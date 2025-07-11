#Requires -Version 2.0
<#
.SYNOPSIS
    Enterprise Windows Server Decommissioning Audit Script
.DESCRIPTION
    Comprehensive PowerShell-based audit solution for enterprise environments to assess 
    Windows server utilization and provide data-driven decommissioning recommendations.
    
    Features:
    - Backward compatible with PowerShell 2.0-5.1
    - Zero external dependencies
    - Comprehensive server role detection
    - Usage scoring algorithm for decommissioning decisions
    - Professional HTML reports with modern dark theme
    - CSV export for batch processing
    - Enterprise-scale error handling
    
.PARAMETER AuditList
    Plain text file containing target hostnames (one per line)
.PARAMETER Credential
    PSCredential object for remote authentication
.PARAMETER MaxEvents
    Maximum event log entries to retrieve per log (default: 100)
.PARAMETER QuickScan
    Bypass time-intensive operations (software inventory, extensive event log queries)
.PARAMETER SkipNetworkConnections
    Skip netstat analysis (auto-enabled for remote targets)
.EXAMPLE
    .\EnterpriseAudit.ps1 -AuditList "servers.txt" -Credential (Get-Credential) -MaxEvents 50
.EXAMPLE
    .\EnterpriseAudit.ps1 -QuickScan
.NOTES
    Version: 1.0 Enterprise Edition
    Author: Enhanced Enterprise Audit Script
    Compatible with PowerShell 2.0-5.1
    Supports Windows Server 2003-2022, Windows 7/8.1/10/11
    
    Usage Scoring Algorithm:
    - User Activity (30 points): Recent login events and unique users
    - Network Utilization (25 points): Connected clients and established connections
    - Application Services (25 points): Critical services detected
    - Database Activity (25 points): Running database instances
    - Web Application Activity (20 points): Active web sites and applications
    - File Share Activity (15 points): Active SMB sessions
    - Scheduled Jobs Activity (15 points): Active scheduled tasks and jobs
    - File System Activity (10 points): Recent file modifications
    - Maintenance Indicators (5 points): Recent reboots and maintenance
    
    Risk Levels:
    - CRITICAL (90-135): DO NOT DECOMMISSION - Active production system
    - MODERATE (55-89): REQUIRES VALIDATION - Verify with stakeholders
    - LOW (30-54): PROCEED WITH CAUTION - Decommission candidate
    - MINIMAL (0-29): SAFE TO PROCEED - Prime for decommission
#>

param(
    [string]$AuditList,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$MaxEvents = 100,
    [switch]$QuickScan,
    [switch]$SkipNetworkConnections
)

# Global Configuration
$ScriptVersion = "1.1 Enterprise Edition Enhanced"
$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"

# PowerShell Version Compatibility Check
$PSVersionTable_PSVersion = if ($PSVersionTable -and $PSVersionTable.PSVersion) { $PSVersionTable.PSVersion } else { [Version]"2.0" }
if ($PSVersionTable_PSVersion.Major -lt 2) {
    Write-Host "This script requires PowerShell 2.0 or later" -ForegroundColor Red
    exit 1
}

# Compatibility functions for older PowerShell versions
if ($PSVersionTable_PSVersion.Major -eq 2) {
    # Add Select-Object -ExpandProperty equivalent for PS 2.0
    function Select-ExpandProperty {
        param($InputObject, $Property)
        if ($InputObject) {
            $InputObject | ForEach-Object { 
                if ($_ -and $_.$Property) {
                    $_.$Property
                }
            }
        }
    }
} else {
    function Select-ExpandProperty {
        param($InputObject, $Property)
        if ($InputObject) {
            $InputObject | ForEach-Object {
                if ($_ -and $_.$Property) {
                    $_.$Property
                }
            }
        }
    }
}

# Windows End-of-Life Database
$WindowsEOLData = @{
    "Windows Server 2003" = @{EOL = "2015-07-14"; ExtendedEOL = "2015-07-14"}
    "Windows Server 2008" = @{EOL = "2020-01-14"; ExtendedEOL = "2020-01-14"}
    "Windows Server 2008 R2" = @{EOL = "2020-01-14"; ExtendedEOL = "2020-01-14"}
    "Windows Server 2012" = @{EOL = "2023-10-10"; ExtendedEOL = "2023-10-10"}
    "Windows Server 2012 R2" = @{EOL = "2023-10-10"; ExtendedEOL = "2023-10-10"}
    "Windows Server 2016" = @{EOL = "2027-01-12"; ExtendedEOL = "2027-01-12"}
    "Windows Server 2019" = @{EOL = "2029-01-09"; ExtendedEOL = "2029-01-09"}
    "Windows Server 2022" = @{EOL = "2031-10-14"; ExtendedEOL = "2031-10-14"}
    "Windows 7" = @{EOL = "2020-01-14"; ExtendedEOL = "2020-01-14"}
    "Windows 8.1" = @{EOL = "2023-01-10"; ExtendedEOL = "2023-01-10"}
    "Windows 10" = @{EOL = "2025-10-14"; ExtendedEOL = "2025-10-14"}
    "Windows 11" = @{EOL = "2031-10-14"; ExtendedEOL = "2031-10-14"}
}

# Well-known ports for service identification
$WellKnownPorts = @{
    21 = "FTP"; 22 = "SSH"; 23 = "Telnet"; 25 = "SMTP"; 53 = "DNS"; 80 = "HTTP"
    110 = "POP3"; 135 = "RPC"; 139 = "NetBIOS"; 143 = "IMAP"; 443 = "HTTPS"
    445 = "SMB"; 993 = "IMAPS"; 995 = "POP3S"; 1433 = "SQL Server"; 1521 = "Oracle"
    3389 = "RDP"; 5432 = "PostgreSQL"; 5985 = "WinRM HTTP"; 5986 = "WinRM HTTPS"
}

# Application detection patterns
$ApplicationPatterns = @{
    "IIS Web Server" = @("w3wp.exe", "inetinfo.exe", "W3SVC")
    "Microsoft SQL Server" = @("sqlservr.exe", "MSSQL")
    "Oracle Database Server" = @("oracle.exe", "tnslsnr.exe", "Oracle")
    "Exchange Server" = @("store.exe", "msexchange", "MSExchange")
    "SharePoint Server" = @("w3wp.exe", "owstimer.exe", "SharePoint")
    "DNS Server" = @("dns.exe", "DNS")
    "DHCP Server" = @("dhcpserver.exe", "DHCP")
    "File Server" = @("lanmanserver", "Server")
    "Print Server" = @("spoolsv.exe", "Spooler")
    "Domain Controller" = @("lsass.exe", "ntds.exe", "NTDS", "ADWS")
    "Hyper-V Server" = @("vmms.exe", "vmwp.exe", "VMMS")
    "Terminal Services" = @("termsrv.exe", "TermService")
    "FTP Server" = @("ftpsvc.exe", "FTPSVC")
    "SMTP Server" = @("smtpsvc.exe", "SMTPSVC")
    "Apache Web Server" = @("apache.exe", "httpd.exe")
    "MySQL Server" = @("mysqld.exe", "MySQL")
    "PostgreSQL Server" = @("postgres.exe", "PostgreSQL")
    "MongoDB Server" = @("mongod.exe", "MongoDB")
    "Redis Server" = @("redis-server.exe", "Redis")
    "Elasticsearch" = @("elasticsearch.exe", "Elasticsearch")
    "RabbitMQ" = @("rabbitmq.exe", "RabbitMQ")
    "Tomcat Server" = @("tomcat.exe", "Tomcat")
    "Jenkins" = @("jenkins.exe", "Jenkins")
    "Docker" = @("docker.exe", "Docker")
    "VMware Tools" = @("vmtoolsd.exe", "VMTools")
    "Backup Software" = @("veeam", "backup", "bacula")
    "Antivirus" = @("mcshield.exe", "symantec", "avast", "kaspersky")
    "Monitoring" = @("nagios", "zabbix", "scom", "prtg")
}

#region Utility Functions

function Write-AuditLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [string]$Color = "White"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $LogMessage -ForegroundColor Red }
        "WARN" { Write-Host $LogMessage -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
        "INFO" { Write-Host $LogMessage -ForegroundColor Cyan }
        default { Write-Host $LogMessage -ForegroundColor $Color }
    }
}

function Test-ServerConnectivity {
    param([string]$ComputerName)
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost" -or $ComputerName -eq "127.0.0.1") {
            return $true
        }
        
        # Test basic connectivity with timeout
        $ping = New-Object System.Net.NetworkInformation.Ping
        $result = $ping.Send($ComputerName, 2000)
        
        if ($result.Status -eq "Success") {
            # Test WMI connectivity
            $wmiParams = @{
                ComputerName = $ComputerName
                Class = "Win32_ComputerSystem"
                ErrorAction = "SilentlyContinue"
            }
            if ($Credential) {
                $wmiParams.Credential = $Credential
            }
            
            $wmi = Get-WmiObject @wmiParams
            return ($wmi -ne $null)
        }
        
        return $false
    } catch {
        return $false
    }
}

function Get-SafeWMIObject {
    param(
        [string]$ComputerName,
        [string]$Class,
        [string]$Query,
        [string]$Filter
    )
    
    $wmiParams = @{
        ErrorAction = "SilentlyContinue"
        ComputerName = $ComputerName
    }
    
    if ($Credential) {
        $wmiParams.Credential = $Credential
    }
    
    try {
        if ($Query) {
            $wmiParams.Query = $Query
            Get-WmiObject @wmiParams
        } elseif ($Filter) {
            $wmiParams.Class = $Class
            $wmiParams.Filter = $Filter
            Get-WmiObject @wmiParams
        } else {
            $wmiParams.Class = $Class
            Get-WmiObject @wmiParams
        }
    } catch {
        Write-AuditLog "WMI query failed on $ComputerName for $Class`: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Get-OSVersionInfo {
    param([object]$OperatingSystem)
    
    $version = $OperatingSystem.Version
    $productType = $OperatingSystem.ProductType
    $caption = $OperatingSystem.Caption
    
    # Determine OS version more accurately
    if ($caption -match "Windows Server") {
        if ($version -like "5.2*") { return "Windows Server 2003" }
        elseif ($version -like "6.0*") { return "Windows Server 2008" }
        elseif ($version -like "6.1*") { return "Windows Server 2008 R2" }
        elseif ($version -like "6.2*") { return "Windows Server 2012" }
        elseif ($version -like "6.3*") { return "Windows Server 2012 R2" }
        elseif ($version -like "10.0*") {
            if ($version -like "10.0.14393*") { return "Windows Server 2016" }
            elseif ($version -like "10.0.17763*") { return "Windows Server 2019" }
            elseif ($version -like "10.0.20348*") { return "Windows Server 2022" }
            else { return "Windows Server 2016+" }
        }
    } else {
        if ($version -like "5.1*") { return "Windows XP" }
        elseif ($version -like "6.0*") { return "Windows Vista" }
        elseif ($version -like "6.1*") { return "Windows 7" }
        elseif ($version -like "6.2*") { return "Windows 8" }
        elseif ($version -like "6.3*") { return "Windows 8.1" }
        elseif ($version -like "10.0*") {
            if ($version -like "10.0.22000*") { return "Windows 11" }
            else { return "Windows 10" }
        }
    }
    
    return $caption
}

function Get-SupportStatus {
    param([string]$OSVersion)
    
    $today = Get-Date
    foreach ($key in $WindowsEOLData.Keys) {
        if ($OSVersion -like "*$key*") {
            $eolDate = [DateTime]$WindowsEOLData[$key].EOL
            if ($today -gt $eolDate) {
                return "END OF LIFE"
            } elseif ($today -gt $eolDate.AddDays(-365)) {
                return "APPROACHING EOL"
            } else {
                return "SUPPORTED"
            }
        }
    }
    return "UNKNOWN"
}

function Get-ServerRoles {
    param([object]$ComputerSystem)
    
    $roles = @()
    
    switch ($ComputerSystem.DomainRole) {
        0 { $roles += "Standalone Workstation" }
        1 { $roles += "Member Workstation" }
        2 { $roles += "Standalone Server" }
        3 { $roles += "Member Server" }
        4 { $roles += "Backup Domain Controller" }
        5 { $roles += "Primary Domain Controller" }
        default { $roles += "Unknown Role" }
    }
    
    return $roles
}

function Get-ApplicationServices {
    param([string]$ComputerName)
    
    $detectedApps = @()
    
    # Get running processes with detailed information
    $processes = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Process"
    
    # Get services with state information
    $services = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service"
    
    # Get installed features/roles (for Windows Server)
    $serverFeatures = @()
    try {
        $features = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_ServerFeature"
        if ($features) {
            $filteredFeatures = $features | Where-Object { $_.InstallState -eq 1 }
            if ($filteredFeatures) {
                $serverFeatures = $filteredFeatures | ForEach-Object { $_.Name }
            } else {
                $serverFeatures = @()
            }
        }
    } catch {
        # Feature detection not available on this system
    }
    
    # Enhanced application detection with priority scoring
    foreach ($appName in $ApplicationPatterns.Keys) {
        $patterns = $ApplicationPatterns[$appName]
        $confidence = 0
        $evidence = @()
        
        # Check running processes (highest confidence)
        if ($processes) {
            foreach ($process in $processes) {
                foreach ($pattern in $patterns) {
                    if ($process.Name -like "*$pattern*") {
                        $confidence += 10
                        $evidence += "Process: $($process.Name)"
                    }
                    if ($process.CommandLine -like "*$pattern*") {
                        $confidence += 8
                        $evidence += "Command: $($process.CommandLine)"
                    }
                }
            }
        }
        
        # Check services (medium-high confidence)
        if ($services) {
            foreach ($service in $services) {
                foreach ($pattern in $patterns) {
                    if ($service.Name -like "*$pattern*") {
                        if ($service.State -eq "Running") {
                            $confidence += 8
                            $evidence += "Running Service: $($service.Name)"
                        } else {
                            $confidence += 4
                            $evidence += "Stopped Service: $($service.Name)"
                        }
                    }
                    if ($service.DisplayName -like "*$pattern*") {
                        if ($service.State -eq "Running") {
                            $confidence += 6
                            $evidence += "Running Service: $($service.DisplayName)"
                        } else {
                            $confidence += 3
                            $evidence += "Stopped Service: $($service.DisplayName)"
                        }
                    }
                }
            }
        }
        
        # Check server features (medium confidence)
        if ($serverFeatures) {
            foreach ($feature in $serverFeatures) {
                foreach ($pattern in $patterns) {
                    if ($feature -like "*$pattern*") {
                        $confidence += 5
                        $evidence += "Server Feature: $feature"
                    }
                }
            }
        }
        
        # Add to detected apps if confidence threshold is met
        if ($confidence -ge 5) {
            $detectedApps += New-Object PSObject -Property @{
                Name = $appName
                Confidence = $confidence
                Evidence = $evidence -join "; "
            }
        }
    }
    
    # Sort by confidence and return app names
    if ($detectedApps.Count -gt 0) {
        $sortedApps = $detectedApps | Sort-Object Confidence -Descending
        return $sortedApps | ForEach-Object { $_.Name }
    } else {
        return @()
    }
}

function Get-NetworkConnections {
    param([string]$ComputerName)
    
    $networkData = @{
        Connections = @()
        UniqueClients = @()
        ListeningPorts = @()
        ClientCount = 0
        EstablishedConnections = 0
        InboundConnections = 0
        OutboundConnections = 0
        DetailedConnections = @()
        ResolvedHostnames = @{}
        NetworkAdapters = @()
        RoutingTable = @()
    }
    
    try {
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
            # Get netstat output with more robust parsing
            $netstatOutput = cmd /c "netstat -an" 2>$null
            $uniqueIPs = @()
            $establishedCount = 0
            $inboundCount = 0
            $outboundCount = 0
            
            foreach ($line in $netstatOutput) {
                if ($line -match "^\s*(TCP|UDP)\s+([\d\.\:]+)\s+([\d\.\:]+|\*\:\*)\s+(\w+)?") {
                    $protocol = $matches[1]
                    $localAddress = $matches[2]
                    $remoteAddress = $matches[3]
                    $state = if ($matches[4]) { $matches[4] } else { "N/A" }
                    
                    $networkData.Connections += @{
                        Protocol = $protocol
                        LocalAddress = $localAddress
                        RemoteAddress = $remoteAddress
                        State = $state
                    }
                    
                    # Count established connections and gather detailed info
                    if ($state -eq "ESTABLISHED") {
                        $establishedCount++
                        
                        # Extract detailed connection information
                        $localIP = ""
                        $localPort = ""
                        $remoteIP = ""
                        $remotePort = ""
                        
                        if ($localAddress -match "^([\d\.]+|\[[\w:]+\]):(\d+)$") {
                            $localIP = $matches[1]
                            $localPort = $matches[2]
                        }
                        
                        if ($remoteAddress -match "^([\d\.]+|\[[\w:]+\]):(\d+)$") {
                            $remoteIP = $matches[1]
                            $remotePort = $matches[2]
                            
                            # Attempt hostname resolution for external IPs
                            $hostname = "Unknown"
                            $fqdn = "Unknown"
                            
                            if ($remoteIP -ne "127.0.0.1" -and $remoteIP -ne "0.0.0.0" -and $remoteIP -notmatch "^169\.254\." -and
                                $remoteIP -notmatch "^224\." -and $remoteIP -notmatch "^239\." -and $remoteIP -ne "::1") {
                                
                                try {
                                    # Resolve hostname
                                    $dnsResult = [System.Net.Dns]::GetHostEntry($remoteIP)
                                    if ($dnsResult) {
                                        $hostname = $dnsResult.HostName.Split('.')[0]
                                        $fqdn = $dnsResult.HostName
                                        $networkData.ResolvedHostnames[$remoteIP] = $fqdn
                                    }
                                } catch {
                                    # DNS resolution failed, try NetBIOS name resolution
                                    try {
                                        $nbResult = nbtstat -A $remoteIP 2>$null | Select-String "<00>" | Select-Object -First 1
                                        if ($nbResult) {
                                            $hostname = ($nbResult.ToString().Split()[0]).Trim()
                                            $fqdn = $hostname
                                        }
                                    } catch {
                                        # Both DNS and NetBIOS failed
                                        $hostname = "Unresolved"
                                        $fqdn = "Unresolved"
                                    }
                                }
                                
                                # Classification of connection type
                                $connectionType = "External"
                                if ($remoteIP -match "^10\." -or $remoteIP -match "^192\.168\." -or 
                                    $remoteIP -match "^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\.") {
                                    $connectionType = "Internal"
                                }
                                
                                # Add to unique clients (external only)
                                if ($connectionType -eq "External" -and $uniqueIPs -notcontains $remoteIP) {
                                    $uniqueIPs += $remoteIP
                                }
                            }
                            
                            # Create detailed connection record
                            $networkData.DetailedConnections += New-Object PSObject -Property @{
                                Protocol = $protocol
                                LocalIP = $localIP
                                LocalPort = $localPort
                                RemoteIP = $remoteIP
                                RemotePort = $remotePort
                                RemoteHostname = $hostname
                                RemoteFQDN = $fqdn
                                State = $state
                                ConnectionType = if ($remoteIP -match "^10\.|^192\.168\.|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-1]\." -or $remoteIP -eq "127.0.0.1") { "Internal" } else { "External" }
                                ServiceName = if ($WellKnownPorts.ContainsKey([int]$localPort)) { $WellKnownPorts[[int]$localPort] } else { "Unknown" }
                                Direction = if ($localAddress -match ":(80|443|21|25|110|143|993|995|1433|1521|3389)$") { "Inbound" } else { "Outbound" }
                            }
                        }
                        
                        # Determine connection direction
                        if ($localAddress -match ":(80|443|21|25|110|143|993|995|1433|1521|3389)$") {
                            $inboundCount++
                        } else {
                            $outboundCount++
                        }
                    }
                    
                    # Collect listening ports
                    if ($state -eq "LISTENING") {
                        if ($localAddress -match ":(\d+)$") {
                            $localPort = $matches[1]
                            $serviceName = if ($WellKnownPorts.ContainsKey([int]$localPort)) { $WellKnownPorts[[int]$localPort] } else { "Unknown" }
                            $networkData.ListeningPorts += @{
                                Port = $localPort
                                Service = $serviceName
                                Protocol = $protocol
                            }
                        }
                    }
                }
            }
            
            $networkData.UniqueClients = $uniqueIPs
            $networkData.ClientCount = $uniqueIPs.Count
            $networkData.EstablishedConnections = $establishedCount
            $networkData.InboundConnections = $inboundCount
            $networkData.OutboundConnections = $outboundCount
            # Get network adapter information
            $adapters = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled=True"
            if ($adapters) {
                foreach ($adapter in $adapters) {
                    $networkData.NetworkAdapters += New-Object PSObject -Property @{
                        Description = $adapter.Description
                        MACAddress = $adapter.MACAddress
                        IPAddress = if ($adapter.IPAddress) { $adapter.IPAddress -join ", " } else { "None" }
                        SubnetMask = if ($adapter.IPSubnet) { $adapter.IPSubnet -join ", " } else { "None" }
                        DefaultGateway = if ($adapter.DefaultIPGateway) { $adapter.DefaultIPGateway -join ", " } else { "None" }
                        DNSServers = if ($adapter.DNSServerSearchOrder) { $adapter.DNSServerSearchOrder -join ", " } else { "None" }
                        DHCPEnabled = $adapter.DHCPEnabled
                        DHCPServer = $adapter.DHCPServer
                        WINSPrimary = $adapter.WINSPrimaryServer
                        WINSSecondary = $adapter.WINSSecondaryServer
                        Index = $adapter.Index
                    }
                }
            }
            
            # Get routing table (local only)
            try {
                $routeOutput = route print 2>$null
                if ($routeOutput) {
                    $inRouteSection = $false
                    foreach ($line in $routeOutput) {
                        if ($line -match "Active Routes:") {
                            $inRouteSection = $true
                            continue
                        }
                        if ($inRouteSection -and $line -match "^\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)") {
                            $networkData.RoutingTable += New-Object PSObject -Property @{
                                Destination = $matches[1]
                                Netmask = $matches[2]
                                Gateway = $matches[3]
                                Interface = $matches[4]
                                Metric = if ($matches[5]) { $matches[5] } else { "Unknown" }
                            }
                        }
                    }
                }
            } catch {
                # Route command failed
            }
        } else {
            # For remote systems, get network adapter info only
            $adapters = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_NetworkAdapterConfiguration" -Filter "IPEnabled=True"
            if ($adapters) {
                foreach ($adapter in $adapters) {
                    $networkData.NetworkAdapters += New-Object PSObject -Property @{
                        Description = $adapter.Description
                        MACAddress = $adapter.MACAddress
                        IPAddress = if ($adapter.IPAddress) { $adapter.IPAddress -join ", " } else { "None" }
                        SubnetMask = if ($adapter.IPSubnet) { $adapter.IPSubnet -join ", " } else { "None" }
                        DefaultGateway = if ($adapter.DefaultIPGateway) { $adapter.DefaultIPGateway -join ", " } else { "None" }
                        DNSServers = if ($adapter.DNSServerSearchOrder) { $adapter.DNSServerSearchOrder -join ", " } else { "None" }
                        DHCPEnabled = $adapter.DHCPEnabled
                        DHCPServer = $adapter.DHCPServer
                        WINSPrimary = $adapter.WINSPrimaryServer
                        WINSSecondary = $adapter.WINSSecondaryServer
                        Index = $adapter.Index
                    }
                    
                    if ($adapter.IPAddress) {
                        $networkData.Connections += @{
                            Protocol = "INFO"
                            LocalAddress = $adapter.IPAddress[0]
                            RemoteAddress = "N/A"
                            State = "CONFIGURED"
                        }
                    }
                }
            }
        }
        
        # Collect routing table for forensic analysis
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
            try {
                $routeOutput = cmd /c "route print" 2>$null
                if ($routeOutput) {
                    $routingTable = @()
                    $foundRoutes = $false
                    
                    foreach ($line in $routeOutput) {
                        if ($line -match "Network Destination.*Netmask.*Gateway.*Interface.*Metric") {
                            $foundRoutes = $true
                            continue
                        }
                        
                        if ($foundRoutes -and $line -match "^\s*(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)") {
                            $routingTable += [PSCustomObject]@{
                                Destination = $matches[1]
                                Netmask = $matches[2]
                                Gateway = $matches[3]
                                Interface = $matches[4]
                                Metric = $matches[5]
                            }
                        }
                    }
                    
                    $networkData.RoutingTable = $routingTable
                }
            } catch {
                Write-AuditLog "Failed to collect routing table: $($_.Exception.Message)" "WARN"
            }
        }
    } catch {
        Write-AuditLog "Failed to get network connections: $($_.Exception.Message)" "WARN"
    }
    
    return $networkData
}

function Get-EventLogSummary {
    param([string]$ComputerName, [int]$MaxEvents)
    
    $eventSummary = @{
        RecentLogins = 0
        SystemErrors = 0
        SystemWarnings = 0
        LastLoginTime = $null
        LastErrorTime = $null
        SecurityEvents = 0
        LoginUsers = @()
        CriticalErrors = 0
        ApplicationErrors = 0
        CriticalEvents = @()
        UserActivity = @()
    }
    
    try {
        # Get recent login events (last 30 days) - Enhanced for better detection
        $startDate = (Get-Date).AddDays(-30)
        $dateFilter = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($startDate)
        
        # Multiple attempts for login detection across different Windows versions
        $loginQueries = @(
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=4624 AND TimeGenerated>='$dateFilter'",
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=528 AND TimeGenerated>='$dateFilter'",
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=540 AND TimeGenerated>='$dateFilter'"
        )
        
        $allLoginEvents = @()
        $uniqueUsers = @()
        
        foreach ($query in $loginQueries) {
            $loginEvents = Get-SafeWMIObject -ComputerName $ComputerName -Query $query
            if ($loginEvents) {
                $allLoginEvents += $loginEvents
            }
        }
        
        if ($allLoginEvents.Count -gt 0) {
            $eventSummary.RecentLogins = $allLoginEvents.Count
            $latestLogin = $allLoginEvents | Sort-Object TimeGenerated -Descending | Select-Object -First 1
            if ($latestLogin) {
                try {
                    $eventSummary.LastLoginTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($latestLogin.TimeGenerated)
                } catch {
                    $eventSummary.LastLoginTime = $null
                }
            }
            
            # Extract unique users from login events
            foreach ($event in $allLoginEvents) {
                if ($event.User -and $event.User -ne "" -and $uniqueUsers -notcontains $event.User) {
                    $uniqueUsers += $event.User
                }
            }
        }
        
        $eventSummary.LoginUsers = $uniqueUsers
        
        # System errors (last 14 days) - Enhanced categorization
        $errorStartDate = (Get-Date).AddDays(-14)
        $errorDateFilter = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($errorStartDate)
        
        # System log errors
        $errorQuery = "SELECT * FROM Win32_NTLogEvent WHERE LogFile='System' AND EventType=1 AND TimeGenerated>='$errorDateFilter'"
        $errorEvents = Get-SafeWMIObject -ComputerName $ComputerName -Query $errorQuery
        
        if ($errorEvents) {
            $eventSummary.SystemErrors = @($errorEvents).Count
            $latestError = $errorEvents | Sort-Object TimeGenerated -Descending | Select-Object -First 1
            if ($latestError) {
                try {
                    $eventSummary.LastErrorTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($latestError.TimeGenerated)
                } catch {
                    $eventSummary.LastErrorTime = $null
                }
            }
            
            # Count critical errors (Event IDs that indicate serious issues)
            $criticalErrorIDs = @(7001, 7023, 7024, 7031, 7032, 7034, 6008, 41, 1001, 1003)
            $criticalErrors = $errorEvents | Where-Object { $criticalErrorIDs -contains $_.EventCode }
            $eventSummary.CriticalErrors = @($criticalErrors).Count
        }
        
        # Application log errors
        $appErrorQuery = "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Application' AND EventType=1 AND TimeGenerated>='$errorDateFilter'"
        $appErrorEvents = Get-SafeWMIObject -ComputerName $ComputerName -Query $appErrorQuery
        
        if ($appErrorEvents) {
            $eventSummary.ApplicationErrors = @($appErrorEvents).Count
        }
        
        # System warnings (last 14 days)
        $warningQuery = "SELECT * FROM Win32_NTLogEvent WHERE LogFile='System' AND EventType=2 AND TimeGenerated>='$errorDateFilter'"
        $warningEvents = Get-SafeWMIObject -ComputerName $ComputerName -Query $warningQuery
        
        if ($warningEvents) {
            $eventSummary.SystemWarnings = @($warningEvents).Count
        }
        
        # Security events count (general)
        $securityQuery = "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND TimeGenerated>='$errorDateFilter'"
        $securityEvents = Get-SafeWMIObject -ComputerName $ComputerName -Query $securityQuery
        
        if ($securityEvents) {
            $eventSummary.SecurityEvents = @($securityEvents).Count
        }
        
        # Collect critical events from last 48 hours for forensic analysis
        $forensicStartDate = (Get-Date).AddDays(-2)
        $forensicDateFilter = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($forensicStartDate)
        
        $criticalEventQueries = @(
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='System' AND EventType=1 AND TimeGenerated>='$forensicDateFilter'",
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Application' AND EventType=1 AND TimeGenerated>='$forensicDateFilter'",
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND (EventCode=4625 OR EventCode=4648 OR EventCode=4656) AND TimeGenerated>='$forensicDateFilter'"
        )
        
        $criticalEvents = @()
        foreach ($query in $criticalEventQueries) {
            $events = Get-SafeWMIObject -ComputerName $ComputerName -Query $query
            if ($events) {
                foreach ($event in (@($events) | Select-Object -First 20)) {
                    # Determine event level
                    $eventLevel = switch ($event.EventType) {
                        1 { "Error" }
                        2 { "Warning" }
                        3 { "Information" }
                        4 { "Success" }
                        5 { "Failure" }
                        default { "Unknown" }
                    }
                    
                    # Format timestamp
                    $timeGenerated = try {
                        [System.Management.ManagementDateTimeConverter]::ToDateTime($event.TimeGenerated).ToString("yyyy-MM-dd HH:mm:ss")
                    } catch {
                        "Unknown"
                    }
                    
                    # Format message
                    $eventMessage = if ($event.Message) { 
                        if ($event.Message.Length -gt 100) { 
                            $event.Message.Substring(0, 100) + "..." 
                        } else { 
                            $event.Message 
                        }
                    } else { 
                        "No message available" 
                    }
                    
                    # Create event object
                    $eventObj = New-Object PSObject
                    $eventObj | Add-Member -MemberType NoteProperty -Name "LogName" -Value $event.LogFile
                    $eventObj | Add-Member -MemberType NoteProperty -Name "EventID" -Value $event.EventCode
                    $eventObj | Add-Member -MemberType NoteProperty -Name "Source" -Value $event.SourceName
                    $eventObj | Add-Member -MemberType NoteProperty -Name "Level" -Value $eventLevel
                    $eventObj | Add-Member -MemberType NoteProperty -Name "TimeGenerated" -Value $timeGenerated
                    $eventObj | Add-Member -MemberType NoteProperty -Name "Message" -Value $eventMessage
                    
                    $criticalEvents += $eventObj
                }
            }
        }
        
        $eventSummary.CriticalEvents = $criticalEvents
        
        # Collect detailed user activity for forensic analysis
        $userActivityData = @()
        $userActivityQueries = @(
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=4624 AND TimeGenerated>='$forensicDateFilter'",
            "SELECT * FROM Win32_NTLogEvent WHERE LogFile='Security' AND EventCode=528 AND TimeGenerated>='$forensicDateFilter'"
        )
        
        $userLoginEvents = @()
        foreach ($query in $userActivityQueries) {
            $events = Get-SafeWMIObject -ComputerName $ComputerName -Query $query
            if ($events) {
                $userLoginEvents += $events
            }
        }
        
        if ($userLoginEvents.Count -gt 0) {
            $userGroups = $userLoginEvents | Group-Object User | Select-Object -First 10
            foreach ($userGroup in $userGroups) {
                if ($userGroup.Name -and $userGroup.Name -ne "") {
                    $latestLogin = $userGroup.Group | Sort-Object TimeGenerated -Descending | Select-Object -First 1
                    
                    # Determine source IP
                    $sourceIP = if ($latestLogin.InsertionStrings -and $latestLogin.InsertionStrings.Count -gt 11) {
                        $latestLogin.InsertionStrings[11]
                    } else {
                        "Local"
                    }
                    
                    # Format last login time
                    $lastLoginTime = try {
                        [System.Management.ManagementDateTimeConverter]::ToDateTime($latestLogin.TimeGenerated).ToString("yyyy-MM-dd HH:mm:ss")
                    } catch {
                        "Unknown"
                    }
                    
                    # Create user activity object
                    $userObj = New-Object PSObject
                    $userObj | Add-Member -MemberType NoteProperty -Name "Username" -Value $userGroup.Name
                    $userObj | Add-Member -MemberType NoteProperty -Name "LoginType" -Value "Interactive"
                    $userObj | Add-Member -MemberType NoteProperty -Name "SourceIP" -Value $sourceIP
                    $userObj | Add-Member -MemberType NoteProperty -Name "LastLogin" -Value $lastLoginTime
                    $userObj | Add-Member -MemberType NoteProperty -Name "LoginCount" -Value $userGroup.Count
                    $userObj | Add-Member -MemberType NoteProperty -Name "AccountStatus" -Value "Active"
                    
                    $userActivityData += $userObj
                }
            }
        }
        
        $eventSummary.UserActivity = $userActivityData
        
    } catch {
        Write-AuditLog "Failed to get event log summary: $($_.Exception.Message)" "WARN"
    }
    
    return $eventSummary
}

function Get-ShareActivity {
    param([string]$ComputerName)
    
    $shareData = @{
        Shares = @()
        ActiveSessions = 0
        UniqueUsers = @()
        OpenFiles = 0
        RecentConnections = 0
        ShareTypes = @{}
    }
    
    try {
        # Get shared folders with enhanced information
        $shares = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Share"
        if ($shares) {
            foreach ($share in $shares) {
                # Filter out administrative shares but include all user shares
                if ($share.Name -ne "IPC$" -and $share.Name -ne "ADMIN$" -and $share.Name -notmatch "^[A-Z]\$$") {
                    $shareType = switch ($share.Type) {
                        0 { "Disk Drive" }
                        1 { "Print Queue" }
                        2 { "Device" }
                        3 { "IPC" }
                        2147483648 { "Administrative" }
                        2147483649 { "Administrative" }
                        2147483650 { "Administrative" }
                        2147483651 { "Administrative" }
                        default { "Unknown" }
                    }
                    
                    $shareData.Shares += @{
                        Name = $share.Name
                        Path = $share.Path
                        Description = $share.Description
                        Type = $shareType
                        AllowMaximum = $share.AllowMaximum
                        MaximumAllowed = $share.MaximumAllowed
                    }
                    
                    # Count share types
                    if ($shareData.ShareTypes.ContainsKey($shareType)) {
                        $shareData.ShareTypes[$shareType]++
                    } else {
                        $shareData.ShareTypes[$shareType] = 1
                    }
                }
            }
        }
        
        # Get active SMB sessions with detailed user information
        $sessions = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_ServerSession"
        if ($sessions) {
            $uniqueUsers = @()
            $recentSessions = 0
            $now = Get-Date
            
            foreach ($session in $sessions) {
                # Count active sessions
                if ($session.UserName -and $session.UserName -ne "" -and $session.UserName -ne $null) {
                    if ($uniqueUsers -notcontains $session.UserName) {
                        $uniqueUsers += $session.UserName
                    }
                }
                
                # Check for recent activity (sessions active in last hour)
                try {
                    if ($session.StartTime) {
                        $sessionStart = [System.Management.ManagementDateTimeConverter]::ToDateTime($session.StartTime)
                        if (($now - $sessionStart).TotalHours -le 1) {
                            $recentSessions++
                        }
                    }
                } catch {
                    # Unable to parse session time
                }
            }
            
            $shareData.ActiveSessions = @($sessions).Count
            $shareData.UniqueUsers = $uniqueUsers
            $shareData.RecentConnections = $recentSessions
        }
        
        # Get open files/connections
        $connections = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_ServerConnection"
        if ($connections) {
            $shareData.OpenFiles = @($connections).Count
        }
        
        # Alternative method for file server detection if WMI fails
        if ($shareData.ActiveSessions -eq 0 -and $shareData.Shares.Count -eq 0) {
            # Check if Server service is running (indicates file sharing capability)
            $serverService = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" -Filter "Name='LanmanServer'"
            if ($serverService -and $serverService.State -eq "Running") {
                # Add a note that file sharing is enabled but no active shares detected
                $shareData.Shares += @{
                    Name = "File Sharing Enabled"
                    Path = "N/A"
                    Description = "Server service running but no user shares detected"
                    Type = "Service"
                    AllowMaximum = $false
                    MaximumAllowed = 0
                }
            }
        }
        
    } catch {
        Write-AuditLog "Failed to get share activity: $($_.Exception.Message)" "WARN"
    }
    
    return $shareData
}

function Get-UpdateStatus {
    param([string]$ComputerName)
    
    $updateData = @{
        LastUpdateDate = $null
        DaysSinceUpdate = 999
        TotalUpdates = 0
        CriticalUpdates = 0
        SecurityUpdates = 0
        UpdateService = "Unknown"
        RecentUpdates = 0
        UpdateHistory = @()
        WSUSServer = "Not Configured"
    }
    
    try {
        # Get installed updates with better date handling
        $updates = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_QuickFixEngineering"
        if ($updates) {
            $updateData.TotalUpdates = @($updates).Count
            $validUpdates = @()
            $securityCount = 0
            $criticalCount = 0
            $recentCount = 0
            $oneMonthAgo = (Get-Date).AddDays(-30)
            
            foreach ($update in $updates) {
                # Handle different date formats and null dates
                $installDate = $null
                if ($update.InstalledOn) {
                    try {
                        if ($update.InstalledOn -is [string]) {
                            # Try parsing various date formats
                            $installDate = [DateTime]::Parse($update.InstalledOn)
                        } else {
                            $installDate = $update.InstalledOn
                        }
                        $validUpdates += @{
                            HotFixID = $update.HotFixID
                            Description = $update.Description
                            InstalledOn = $installDate
                        }
                        
                        # Count recent updates (last 30 days)
                        if ($installDate -gt $oneMonthAgo) {
                            $recentCount++
                        }
                    } catch {
                        # Unable to parse date, skip this update for date calculations
                    }
                }
                
                # Categorize updates by type
                if ($update.Description -like "*Security*" -or $update.HotFixID -match "KB\d+") {
                    $securityCount++
                }
                
                if ($update.Description -like "*Critical*" -or $update.Description -like "*Important*") {
                    $criticalCount++
                }
            }
            
            # Find most recent update from valid dates
            if ($validUpdates.Count -gt 0) {
                $latestUpdate = $validUpdates | Sort-Object InstalledOn -Descending | Select-Object -First 1
                $updateData.LastUpdateDate = $latestUpdate.InstalledOn
                $updateData.DaysSinceUpdate = ((Get-Date) - $latestUpdate.InstalledOn).Days
                
                # Store recent update history
                $updateData.UpdateHistory = $validUpdates | Sort-Object InstalledOn -Descending | Select-Object -First 10
            }
            
            $updateData.SecurityUpdates = $securityCount
            $updateData.CriticalUpdates = $criticalCount
            $updateData.RecentUpdates = $recentCount
        }
        
        # Check Windows Update service status
        $updateService = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" -Filter "Name='wuauserv'"
        if ($updateService) {
            $updateData.UpdateService = "$($updateService.State) ($($updateService.StartMode))"
        } else {
            # Try alternative service names for different Windows versions
            $altService = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" -Filter "Name='UsoSvc'"
            if ($altService) {
                $updateData.UpdateService = "Update Orchestrator: $($altService.State) ($($altService.StartMode))"
            }
        }
        
        # Check for WSUS configuration (if accessible)
        try {
            $wsusRegKey = Get-SafeWMIObject -ComputerName $ComputerName -Class "StdRegProv"
            if ($wsusRegKey) {
                # This would require registry access which may not be available remotely
                $updateData.WSUSServer = "Registry Check Required"
            }
        } catch {
            # WSUS detection not available
        }
        
    } catch {
        Write-AuditLog "Failed to get update status: $($_.Exception.Message)" "WARN"
    }
    
    return $updateData
}

function Calculate-DecommissionScore {
    param([object]$AuditData)
    
    $score = 0
    $scoreDetails = @()
    $maxScore = 135  # Updated for new categories: 30+25+25+15+25+20+15+10+5 = 170, capped at 135
    
    # User Activity (30 points max) - Enhanced calculation
    $userActivity = 0
    if ($AuditData.EventLog.RecentLogins -gt 0) {
        # Scale based on login frequency: 1-10 logins = 10-20 points, 11+ = 30 points
        if ($AuditData.EventLog.RecentLogins -le 10) {
            $userActivity = [Math]::Min(20, $AuditData.EventLog.RecentLogins * 2)
        } else {
            $userActivity = 30
        }
        
        # Bonus for unique users
        if ($AuditData.EventLog.LoginUsers -and $AuditData.EventLog.LoginUsers.Count -gt 1) {
            $userActivity = [Math]::Min(30, $userActivity + ($AuditData.EventLog.LoginUsers.Count * 2))
        }
        
        $scoreDetails += "User Activity: $userActivity points ($($AuditData.EventLog.RecentLogins) logins, $($AuditData.EventLog.LoginUsers.Count) unique users)"
    } else {
        $scoreDetails += "User Activity: 0 points (no recent logins detected)"
    }
    $score += $userActivity
    
    # Network Utilization (25 points max) - Enhanced with connection analysis
    $networkScore = 0
    $connectionBonus = 0
    
    # Base score from unique clients
    if ($AuditData.Network.ClientCount -gt 0) {
        if ($AuditData.Network.ClientCount -le 5) {
            $networkScore = 10
        } elseif ($AuditData.Network.ClientCount -le 15) {
            $networkScore = 20
        } else {
            $networkScore = 25
        }
    }
    
    # Bonus for established connections
    if ($AuditData.Network.EstablishedConnections -gt 10) {
        $connectionBonus = 5
        $networkScore = [Math]::Min(25, $networkScore + $connectionBonus)
    }
    
    if ($networkScore -gt 0) {
        $scoreDetails += "Network Utilization: $networkScore points ($($AuditData.Network.ClientCount) clients, $($AuditData.Network.EstablishedConnections) connections)"
    } else {
        $scoreDetails += "Network Utilization: 0 points (no client connections)"
    }
    $score += $networkScore
    
    # Application Services (25 points max) - Enhanced with service analysis
    $appScore = 0
    if ($AuditData.Applications.Count -gt 0) {
        # Scale based on number and criticality of applications
        if ($AuditData.Applications.Count -eq 1) {
            $appScore = 15
        } elseif ($AuditData.Applications.Count -le 3) {
            $appScore = 20
        } else {
            $appScore = 25
        }
        
        $scoreDetails += "Application Services: $appScore points ($($AuditData.Applications.Count) critical applications)"
    } else {
        $scoreDetails += "Application Services: 0 points (no critical applications detected)"
    }
    $score += $appScore
    
    # File Share Activity (15 points max) - Enhanced with session analysis
    $shareScore = 0
    if ($AuditData.Shares.ActiveSessions -gt 0 -or $AuditData.Shares.Shares.Count -gt 0) {
        $shareScore = 5  # Base for having shares
        
        if ($AuditData.Shares.ActiveSessions -gt 0) {
            $shareScore += [Math]::Min(10, $AuditData.Shares.ActiveSessions * 2)
        }
        
        $shareScore = [Math]::Min(15, $shareScore)
        $scoreDetails += "File Share Activity: $shareScore points ($($AuditData.Shares.ActiveSessions) sessions, $($AuditData.Shares.Shares.Count) shares)"
    } else {
        $scoreDetails += "File Share Activity: 0 points (no file sharing activity)"
    }
    $score += $shareScore
    
    # Database Activity (25 points max) - New enhanced category
    $databaseScore = 0
    if ($AuditData.DatabaseInstances -and $AuditData.DatabaseInstances.Instances.Count -gt 0) {
        $runningDatabases = ($AuditData.DatabaseInstances.Instances | Where-Object { $_.Status -eq "Running" }).Count
        if ($runningDatabases -gt 0) {
            $databaseScore = [Math]::Min(25, $runningDatabases * 8)  # 8 points per running database
            $scoreDetails += "Database Activity: $databaseScore points ($runningDatabases running databases)"
        } else {
            $scoreDetails += "Database Activity: 0 points (databases installed but not running)"
        }
    } else {
        $scoreDetails += "Database Activity: 0 points (no databases detected)"
    }
    $score += $databaseScore
    
    # Web Application Activity (20 points max) - New enhanced category  
    $webScore = 0
    if ($AuditData.WebApplications -and $AuditData.WebApplications.ActiveSites -gt 0) {
        $webScore = [Math]::Min(20, $AuditData.WebApplications.ActiveSites * 7)  # 7 points per active site
        $scoreDetails += "Web Application Activity: $webScore points ($($AuditData.WebApplications.ActiveSites) active sites)"
    } else {
        $scoreDetails += "Web Application Activity: 0 points (no active web applications)"
    }
    $score += $webScore
    
    # Scheduled Jobs Activity (15 points max) - New enhanced category
    $scheduledJobsScore = 0
    if ($AuditData.ScheduledJobs -and $AuditData.ScheduledJobs.ActiveJobs -gt 0) {
        $scheduledJobsScore = [Math]::Min(15, $AuditData.ScheduledJobs.ActiveJobs * 3)  # 3 points per active job
        $scoreDetails += "Scheduled Jobs Activity: $scheduledJobsScore points ($($AuditData.ScheduledJobs.ActiveJobs) active jobs)"
    } else {
        $scoreDetails += "Scheduled Jobs Activity: 0 points (no active scheduled jobs)"
    }
    $score += $scheduledJobsScore
    
    # File System Activity (10 points max) - New enhanced category
    $fileSystemScore = 0
    if ($AuditData.FileSystemActivity -and $AuditData.FileSystemActivity.TotalRecentFiles -gt 0) {
        if ($AuditData.FileSystemActivity.TotalRecentFiles -gt 20) {
            $fileSystemScore = 10
        } elseif ($AuditData.FileSystemActivity.TotalRecentFiles -gt 10) {
            $fileSystemScore = 7
        } elseif ($AuditData.FileSystemActivity.TotalRecentFiles -gt 5) {
            $fileSystemScore = 5
        } else {
            $fileSystemScore = 3
        }
        $scoreDetails += "File System Activity: $fileSystemScore points ($($AuditData.FileSystemActivity.TotalRecentFiles) recent files)"
    } else {
        $scoreDetails += "File System Activity: 0 points (no recent file activity)"
    }
    $score += $fileSystemScore
    
    # Maintenance Indicators (5 points max) - Reduced weight, enhanced logic
    $maintenanceScore = 0
    if ($AuditData.System.UptimeDays -lt 7) {
        $maintenanceScore = 5  # Very recent reboot
    } elseif ($AuditData.System.UptimeDays -lt 30) {
        $maintenanceScore = 3  # Recent reboot
    } elseif ($AuditData.System.UptimeDays -lt 90) {
        $maintenanceScore = 1  # Moderate uptime
    }
    # Very high uptime (>90 days) gets 0 points - might indicate abandonment
    
    if ($maintenanceScore -gt 0) {
        $scoreDetails += "Maintenance Indicators: $maintenanceScore points ($($AuditData.System.UptimeDays) days uptime)"
    } else {
        $scoreDetails += "Maintenance Indicators: 0 points ($($AuditData.System.UptimeDays) days uptime - possible abandonment)"
    }
    $score += $maintenanceScore
    
    # Ensure score doesn't exceed maximum
    $score = [Math]::Min($maxScore, $score)
    
    return @{
        Score = $score
        MaxScore = $maxScore
        Details = $scoreDetails
        Categories = @{
            UserActivity = $userActivity
            NetworkUtilization = $networkScore
            ApplicationServices = $appScore
            FileShareActivity = $shareScore
            DatabaseActivity = $databaseScore
            WebApplicationActivity = $webScore
            ScheduledJobsActivity = $scheduledJobsScore
            FileSystemActivity = $fileSystemScore
            MaintenanceIndicators = $maintenanceScore
        }
    }
}

function Get-RiskAssessment {
    param([int]$Score)
    
    if ($Score -ge 90) {
        return @{
            Level = "CRITICAL"
            Recommendation = "Active Production System"
            Action = "DO NOT DECOMMISSION"
            Color = "red"
            Priority = 1
        }
    } elseif ($Score -ge 55) {
        return @{
            Level = "MODERATE"
            Recommendation = "Verify with Stakeholders"
            Action = "REQUIRES VALIDATION"
            Color = "orange"
            Priority = 2
        }
    } elseif ($Score -ge 30) {
        return @{
            Level = "LOW"
            Recommendation = "Decommission Candidate"
            Action = "PROCEED WITH CAUTION"
            Color = "yellow"
            Priority = 3
        }
    } else {
        return @{
            Level = "MINIMAL"
            Recommendation = "Prime for Decommission"
            Action = "SAFE TO PROCEED"
            Color = "green"
            Priority = 4
        }
    }
}

function Get-DatabaseInstances {
    param([string]$ComputerName)
    
    $databaseData = @{
        Instances = @()
        Databases = @()
        Connections = @()
        TotalInstances = 0
        TotalDatabases = 0
        ActiveConnections = 0
    }
    
    try {
        Write-AuditLog "Discovering database instances on $ComputerName" "INFO"
        
        # SQL Server Instance Discovery
        $sqlInstances = @()
        
        # Method 1: Registry-based SQL Server discovery
        try {
            $sqlRegPath = "SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL"
            $sqlReg = Get-SafeWMIObject -ComputerName $ComputerName -Class "StdRegProv"
            if ($sqlReg) {
                $sqlInstanceNames = $sqlReg.EnumValues(2147483650, $sqlRegPath)
                if ($sqlInstanceNames) {
                    foreach ($instance in $sqlInstanceNames.sNames) {
                        $sqlInstances += @{
                            Type = "SQL Server"
                            Instance = $instance
                            Port = "1433"
                            Status = "Registry"
                        }
                    }
                }
            }
        } catch {
            Write-AuditLog "SQL Server registry discovery failed: $($_.Exception.Message)" "WARN"
        }
        
        # Method 2: Service-based discovery for SQL Server
        $sqlServices = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" | Where-Object { 
            $_.Name -match "MSSQL" -or $_.Name -match "SQLServer"
        }
        
        if ($sqlServices) {
            foreach ($service in $sqlServices) {
                $instanceName = "DEFAULT"
                if ($service.Name -match "MSSQL\$(.+)") {
                    $instanceName = $matches[1]
                }
                
                $sqlInstances += @{
                    Type = "SQL Server"
                    Instance = $instanceName
                    Port = "1433"
                    Status = $service.State
                    ServiceName = $service.Name
                }
            }
        }
        
        # Oracle Discovery
        $oracleInstances = @()
        
        # Oracle TNS discovery
        try {
            $oracleServices = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" | Where-Object {
                $_.Name -match "Oracle" -or $_.DisplayName -match "Oracle"
            }
            
            if ($oracleServices) {
                foreach ($service in $oracleServices) {
                    if ($service.Name -match "OracleService(.+)") {
                        $oracleInstances += @{
                            Type = "Oracle"
                            Instance = $matches[1]
                            Port = "1521"
                            Status = $service.State
                            ServiceName = $service.Name
                        }
                    }
                }
            }
        } catch {
            Write-AuditLog "Oracle discovery failed: $($_.Exception.Message)" "WARN"
        }
        
        # MySQL Discovery
        $mysqlInstances = @()
        $mysqlServices = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" | Where-Object {
            $_.Name -match "MySQL" -or $_.DisplayName -match "MySQL"
        }
        
        if ($mysqlServices) {
            foreach ($service in $mysqlServices) {
                $mysqlInstances += @{
                    Type = "MySQL"
                    Instance = $service.Name
                    Port = "3306"
                    Status = $service.State
                    ServiceName = $service.Name
                }
            }
        }
        
        # PostgreSQL Discovery
        $pgInstances = @()
        $pgServices = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" | Where-Object {
            $_.Name -match "postgresql" -or $_.DisplayName -match "PostgreSQL"
        }
        
        if ($pgServices) {
            foreach ($service in $pgServices) {
                $pgInstances += @{
                    Type = "PostgreSQL"
                    Instance = $service.Name
                    Port = "5432"
                    Status = $service.State
                    ServiceName = $service.Name
                }
            }
        }
        
        # Combine all instances
        $allInstances = $sqlInstances + $oracleInstances + $mysqlInstances + $pgInstances
        
        # Get database connections from network connections
        $dbConnections = @()
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
            $netstatOutput = cmd /c "netstat -an" 2>$null
            if ($netstatOutput) {
                foreach ($line in $netstatOutput) {
                    if ($line -match "TCP\s+[\d\.]+:(\d+)\s+[\d\.]+:\d+\s+ESTABLISHED") {
                        $port = $matches[1]
                        if ($port -in @("1433", "1521", "3306", "5432")) {
                            $dbType = switch ($port) {
                                "1433" { "SQL Server" }
                                "1521" { "Oracle" }
                                "3306" { "MySQL" }
                                "5432" { "PostgreSQL" }
                            }
                            $dbConnections += @{
                                Type = $dbType
                                Port = $port
                                Status = "Active Connection"
                            }
                        }
                    }
                }
            }
        }
        
        # Process discovery - look for database processes
        $dbProcesses = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Process" | Where-Object {
            $_.Name -match "sqlservr|oracle|mysqld|postgres"
        }
        
        if ($dbProcesses) {
            foreach ($proc in $dbProcesses) {
                $dbType = switch -Regex ($proc.Name) {
                    "sqlservr" { "SQL Server" }
                    "oracle" { "Oracle" }
                    "mysqld" { "MySQL" }
                    "postgres" { "PostgreSQL" }
                }
                
                $allInstances += @{
                    Type = $dbType
                    Instance = "Process: $($proc.ProcessId)"
                    Port = "N/A"
                    Status = "Running"
                    ProcessId = $proc.ProcessId
                    Memory = [Math]::Round($proc.WorkingSetSize / 1MB, 2)
                }
            }
        }
        
        # Remove duplicates and create final instance list
        $uniqueInstances = @()
        $instanceKeys = @()
        
        foreach ($instance in $allInstances) {
            $key = "$($instance.Type)_$($instance.Instance)"
            if ($instanceKeys -notcontains $key) {
                $instanceKeys += $key
                $uniqueInstances += $instance
            }
        }
        
        $databaseData.Instances = $uniqueInstances
        $databaseData.Connections = $dbConnections
        $databaseData.TotalInstances = $uniqueInstances.Count
        $databaseData.ActiveConnections = $dbConnections.Count
        
        Write-AuditLog "Found $($uniqueInstances.Count) database instances" "INFO"
        
    } catch {
        Write-AuditLog "Database discovery failed: $($_.Exception.Message)" "WARN"
    }
    
    return $databaseData
}

function Get-ScheduledJobsAnalysis {
    param([string]$ComputerName)
    
    $jobData = @{
        ScheduledTasks = @()
        SqlAgentJobs = @()
        RecentExecutions = @()
        TotalTasks = 0
        ActiveTasks = 0
        FailedTasks = 0
    }
    
    try {
        Write-AuditLog "Analyzing scheduled jobs on $ComputerName" "INFO"
        
        # Windows Scheduled Tasks
        $scheduledTasks = @()
        
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
            # Use schtasks command for local system
            $schtaskOutput = cmd /c "schtasks /query /fo csv /v" 2>$null
            if ($schtaskOutput) {
                $taskLines = $schtaskOutput | Select-Object -Skip 1
                foreach ($line in $taskLines) {
                    if ($line -and $line -match '"([^"]+)","([^"]+)","([^"]+)","([^"]+)"') {
                        $taskName = $matches[1]
                        $nextRunTime = $matches[2]
                        $status = $matches[3]
                        $lastRunTime = $matches[4]
                        
                        if ($taskName -ne "TaskName" -and $taskName -ne "") {
                            $scheduledTasks += @{
                                Name = $taskName
                                Status = $status
                                NextRun = $nextRunTime
                                LastRun = $lastRunTime
                                Type = "Windows Task"
                            }
                        }
                    }
                }
            }
        } else {
            # For remote systems, try WMI (limited in older PS versions)
            try {
                $tasks = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_ScheduledJob"
                if ($tasks) {
                    foreach ($task in $tasks) {
                        $scheduledTasks += @{
                            Name = $task.Name
                            Status = $task.Status
                            NextRun = $task.StartTime
                            LastRun = "Unknown"
                            Type = "Windows Task"
                            JobId = $task.JobId
                        }
                    }
                }
            } catch {
                Write-AuditLog "Remote scheduled task discovery failed: $($_.Exception.Message)" "WARN"
            }
        }
        
        # SQL Agent Jobs (if SQL Server is present)
        $sqlAgentJobs = @()
        try {
            # Look for SQL Agent service
            $sqlAgentService = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" | Where-Object {
                $_.Name -match "SQLAgent" -or $_.DisplayName -match "SQL.*Agent"
            }
            
            if ($sqlAgentService) {
                # SQL Agent is present - note this for investigation
                $sqlAgentJobs += @{
                    Name = "SQL Agent Service Detected"
                    Status = $sqlAgentService.State
                    Type = "SQL Agent"
                    ServiceName = $sqlAgentService.Name
                }
            }
        } catch {
            Write-AuditLog "SQL Agent job discovery failed: $($_.Exception.Message)" "WARN"
        }
        
        # Analyze task execution patterns
        $recentExecutions = @()
        $activeTasks = 0
        $failedTasks = 0
        
        foreach ($task in $scheduledTasks) {
            if ($task.Status -eq "Running") {
                $activeTasks++
            } elseif ($task.Status -match "Failed|Error") {
                $failedTasks++
            }
            
            if ($task.LastRun -and $task.LastRun -ne "Unknown" -and $task.LastRun -ne "N/A") {
                $recentExecutions += @{
                    TaskName = $task.Name
                    LastExecution = $task.LastRun
                    Status = $task.Status
                }
            }
        }
        
        $jobData.ScheduledTasks = $scheduledTasks
        $jobData.SqlAgentJobs = $sqlAgentJobs
        $jobData.RecentExecutions = $recentExecutions
        $jobData.TotalTasks = $scheduledTasks.Count
        $jobData.ActiveTasks = $activeTasks
        $jobData.FailedTasks = $failedTasks
        
        Write-AuditLog "Found $($scheduledTasks.Count) scheduled tasks" "INFO"
        
    } catch {
        Write-AuditLog "Scheduled jobs analysis failed: $($_.Exception.Message)" "WARN"
    }
    
    return $jobData
}

function Get-WebApplications {
    param([string]$ComputerName)
    
    $webData = @{
        IISSites = @()
        VirtualDirectories = @()
        ApplicationPools = @()
        SSLCertificates = @()
        RecentAccess = @()
        TotalSites = 0
        ActiveSites = 0
    }
    
    try {
        Write-AuditLog "Discovering web applications on $ComputerName" "INFO"
        
        # IIS Discovery
        $iisService = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service" | Where-Object {
            $_.Name -eq "W3SVC" -or $_.Name -eq "IISAdmin"
        }
        
        if ($iisService) {
            # IIS is present
            try {
                # Get IIS sites via WMI (limited but works on older systems)
                $iisSites = Get-SafeWMIObject -ComputerName $ComputerName -Class "IISWebServerSetting" -Namespace "root\MicrosoftIISv2"
                
                if ($iisSites) {
                    foreach ($site in $iisSites) {
                        $webData.IISSites += @{
                            Name = $site.ServerComment
                            Bindings = $site.ServerBindings
                            Path = $site.Path
                            Status = "IIS Site"
                        }
                    }
                }
            } catch {
                # Fallback: Look for common IIS indicators
                $webData.IISSites += @{
                    Name = "IIS Detected"
                    Bindings = "Unknown"
                    Path = "C:\inetpub\wwwroot"
                    Status = $iisService.State
                }
            }
        }
        
        # Apache Discovery
        $apacheProcesses = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Process" | Where-Object {
            $_.Name -match "httpd|apache"
        }
        
        if ($apacheProcesses) {
            foreach ($proc in $apacheProcesses) {
                $webData.IISSites += @{
                    Name = "Apache Web Server"
                    Bindings = "Port 80/443"
                    Path = $proc.ExecutablePath
                    Status = "Running"
                    ProcessId = $proc.ProcessId
                }
            }
        }
        
        # Tomcat Discovery
        $tomcatProcesses = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Process" | Where-Object {
            $_.Name -match "tomcat" -or $_.CommandLine -match "catalina"
        }
        
        if ($tomcatProcesses) {
            foreach ($proc in $tomcatProcesses) {
                $webData.IISSites += @{
                    Name = "Apache Tomcat"
                    Bindings = "Port 8080"
                    Path = $proc.ExecutablePath
                    Status = "Running"
                    ProcessId = $proc.ProcessId
                }
            }
        }
        
        # Look for web-related processes
        $webProcesses = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Process" | Where-Object {
            $_.Name -match "w3wp|nginx|node|java" -and $_.CommandLine -match "web|http|server"
        }
        
        if ($webProcesses) {
            foreach ($proc in $webProcesses) {
                $webType = switch -Regex ($proc.Name) {
                    "w3wp" { "IIS Application Pool" }
                    "nginx" { "Nginx Web Server" }
                    "node" { "Node.js Application" }
                    "java" { "Java Web Application" }
                    default { "Web Process" }
                }
                
                $webData.ApplicationPools += @{
                    Name = $webType
                    ProcessId = $proc.ProcessId
                    Status = "Running"
                    Memory = [Math]::Round($proc.WorkingSetSize / 1MB, 2)
                }
            }
        }
        
        # Check for SSL certificates (basic check)
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
            try {
                $certStore = "Cert:\LocalMachine\My"
                $certs = Get-ChildItem $certStore -ErrorAction SilentlyContinue | Where-Object {
                    $_.Subject -match "CN=" -and $_.NotAfter -gt (Get-Date)
                }
                
                if ($certs) {
                    foreach ($cert in ($certs | Select-Object -First 5)) {
                        $webData.SSLCertificates += @{
                            Subject = $cert.Subject
                            Issuer = $cert.Issuer
                            Expiry = $cert.NotAfter
                            Thumbprint = $cert.Thumbprint
                        }
                    }
                }
            } catch {
                Write-AuditLog "SSL certificate discovery failed: $($_.Exception.Message)" "WARN"
            }
        }
        
        $webData.TotalSites = $webData.IISSites.Count
        $webData.ActiveSites = ($webData.IISSites | Where-Object { $_.Status -eq "Running" -or $_.Status -eq "Started" }).Count
        
        Write-AuditLog "Found $($webData.TotalSites) web applications" "INFO"
        
    } catch {
        Write-AuditLog "Web applications discovery failed: $($_.Exception.Message)" "WARN"
    }
    
    return $webData
}

function Get-FileSystemActivity {
    param([string]$ComputerName)
    
    $fileData = @{
        RecentFiles = @()
        LargeFiles = @()
        UserDirectories = @()
        ApplicationData = @()
        TotalRecentFiles = 0
        TotalDataGB = 0
    }
    
    try {
        Write-AuditLog "Analyzing file system activity on $ComputerName" "INFO"
        
        # Get recent files (last 30 days) - focus on key directories
        $recentFiles = @()
        $cutoffDate = (Get-Date).AddDays(-30)
        
        # Key directories to check
        $keyPaths = @(
            "C:\Program Files",
            "C:\Program Files (x86)",
            "C:\Users",
            "C:\inetpub",
            "C:\Windows\System32\config",
            "D:\",
            "E:\"
        )
        
        foreach ($path in $keyPaths) {
            try {
                $files = Get-SafeWMIObject -ComputerName $ComputerName -Class "CIM_DataFile" -Filter "Drive='C:' AND Path LIKE '%Program Files%' AND LastModified > '$(Get-Date $cutoffDate -Format 'yyyyMMddHHmmss').000000+000'"
                
                if ($files) {
                    foreach ($file in ($files | Select-Object -First 10)) {
                        $recentFiles += @{
                            Path = $file.Name
                            Size = [Math]::Round($file.FileSize / 1MB, 2)
                            Modified = $file.LastModified
                            Extension = $file.Extension
                        }
                    }
                }
            } catch {
                # WMI file queries can be resource intensive, continue on error
                continue
            }
        }
        
        # Get large files (>100MB) 
        $largeFiles = @()
        try {
            $files = Get-SafeWMIObject -ComputerName $ComputerName -Class "CIM_DataFile" -Filter "FileSize > 104857600"
            
            if ($files) {
                foreach ($file in ($files | Select-Object -First 20)) {
                    $largeFiles += @{
                        Path = $file.Name
                        SizeMB = [Math]::Round($file.FileSize / 1MB, 2)
                        Modified = $file.LastModified
                        Extension = $file.Extension
                    }
                }
            }
        } catch {
            Write-AuditLog "Large file discovery failed: $($_.Exception.Message)" "WARN"
        }
        
        # Get user directories
        $userDirs = @()
        try {
            $userFolders = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Directory" -Filter "Path='C:\\Users\\%'"
            
            if ($userFolders) {
                foreach ($folder in $userFolders) {
                    $userDirs += @{
                        Path = $folder.Name
                        CreationDate = $folder.CreationDate
                        LastAccessed = $folder.LastAccessed
                    }
                }
            }
        } catch {
            Write-AuditLog "User directory discovery failed: $($_.Exception.Message)" "WARN"
        }
        
        # Calculate totals
        $fileData.RecentFiles = $recentFiles
        $fileData.LargeFiles = $largeFiles
        $fileData.UserDirectories = $userDirs
        $fileData.TotalRecentFiles = $recentFiles.Count
        $fileData.TotalDataGB = [Math]::Round(($largeFiles | Measure-Object -Property SizeMB -Sum).Sum / 1024, 2)
        
        Write-AuditLog "Found $($recentFiles.Count) recent files and $($largeFiles.Count) large files" "INFO"
        
    } catch {
        Write-AuditLog "File system activity analysis failed: $($_.Exception.Message)" "WARN"
    }
    
    return $fileData
}

function Get-DependencyMapping {
    param([string]$ComputerName)
    
    $dependencyData = @{
        OutboundConnections = @()
        ConfiguredConnections = @()
        LinkedServers = @()
        TotalDependencies = 0
    }
    
    try {
        Write-AuditLog "Mapping dependencies for $ComputerName" "INFO"
        
        # Get outbound network connections
        $outboundConnections = @()
        
        if ($ComputerName -eq $env:COMPUTERNAME -or $ComputerName -eq "localhost") {
            $netstatOutput = cmd /c "netstat -an" 2>$null
            if ($netstatOutput) {
                foreach ($line in $netstatOutput) {
                    if ($line -match "TCP\s+([\d\.]+):(\d+)\s+([\d\.]+):(\d+)\s+ESTABLISHED") {
                        $localIP = $matches[1]
                        $localPort = $matches[2]
                        $remoteIP = $matches[3]
                        $remotePort = $matches[4]
                        
                        # Focus on non-local connections
                        if ($remoteIP -ne "127.0.0.1" -and $remoteIP -notmatch "^10\.|^172\.|^192\.168\.") {
                            $outboundConnections += @{
                                RemoteIP = $remoteIP
                                RemotePort = $remotePort
                                LocalPort = $localPort
                                Type = "Outbound"
                            }
                        }
                    }
                }
            }
        }
        
        # Look for configuration-based connections
        $configConnections = @()
        
        # Check for ODBC connections
        try {
            $odbcReg = Get-SafeWMIObject -ComputerName $ComputerName -Class "StdRegProv"
            if ($odbcReg) {
                # This is a simplified approach - in practice, you'd enumerate registry keys
                $configConnections += @{
                    Type = "ODBC DSN"
                    Status = "Registry Present"
                }
            }
        } catch {
            # Continue on error
        }
        
        $dependencyData.OutboundConnections = $outboundConnections
        $dependencyData.ConfiguredConnections = $configConnections
        $dependencyData.TotalDependencies = $outboundConnections.Count + $configConnections.Count
        
        Write-AuditLog "Found $($outboundConnections.Count) outbound connections" "INFO"
        
    } catch {
        Write-AuditLog "Dependency mapping failed: $($_.Exception.Message)" "WARN"
    }
    
    return $dependencyData
}

#endregion

#region HTML Report Generation

function New-EnterpriseHTMLReport {
    param([object]$AuditData)
    
    $computerName = $AuditData.ComputerName
    $timestamp = Get-Date -Format "HHmm_dd-MM-yyyy"
    $fileName = "${computerName}_${timestamp}.htm"
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enterprise Server Audit Report - $computerName</title>
    <style>
        :root {
            --primary-bg: #0d1117;
            --secondary-bg: #161b22;
            --tertiary-bg: #21262d;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --accent-blue: #58a6ff;
            --accent-green: #3fb950;
            --accent-yellow: #d29922;
            --accent-red: #f85149;
            --accent-orange: #ff8c00;
            --hover-bg: #262c36;
            --success: #238636;
            --warning: #9e6a03;
            --error: #da3633;
            --info: #0969da;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--primary-bg);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 14px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-green));
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }
        
        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 10px;
            color: white;
            text-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        
        .header-subtitle {
            font-size: 1.2rem;
            opacity: 0.9;
            color: white;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .summary-card {
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.4);
        }
        
        .summary-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--accent-blue);
        }
        
        .summary-card.critical::before { background: var(--accent-red); }
        .summary-card.warning::before { background: var(--accent-yellow); }
        .summary-card.success::before { background: var(--accent-green); }
        
        .summary-title {
            font-size: 0.9rem;
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 8px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .summary-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 8px;
        }
        
        .summary-description {
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        
        .tabs {
            display: flex;
            background: var(--secondary-bg);
            border-radius: 8px 8px 0 0;
            border: 1px solid var(--border-color);
            border-bottom: none;
            overflow-x: auto;
        }
        
        .tab {
            background: transparent;
            border: none;
            padding: 16px 24px;
            color: var(--text-secondary);
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            white-space: nowrap;
            border-bottom: 3px solid transparent;
        }
        
        .tab:hover {
            background: var(--hover-bg);
            color: var(--text-primary);
        }
        
        .tab.active {
            background: var(--tertiary-bg);
            color: var(--accent-blue);
            border-bottom-color: var(--accent-blue);
        }
        
        .tab-content {
            display: none;
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-top: none;
            border-radius: 0 0 8px 8px;
            padding: 30px;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .section {
            margin-bottom: 30px;
        }
        
        .section-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--accent-blue);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 20px;
        }
        
        .info-panel {
            background: var(--tertiary-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }
        
        .info-panel h4 {
            color: var(--accent-blue);
            margin-bottom: 16px;
            font-size: 1.1rem;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid var(--border-color);
        }
        
        .info-row:last-child {
            border-bottom: none;
        }
        
        .info-label {
            font-weight: 500;
            color: var(--text-secondary);
        }
        
        .info-value {
            color: var(--text-primary);
            font-weight: 600;
            text-align: right;
        }
        
        .status-critical { color: var(--accent-red); }
        .status-warning { color: var(--accent-yellow); }
        .status-success { color: var(--accent-green); }
        .status-info { color: var(--accent-blue); }
        
        .list-section {
            background: var(--tertiary-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .list-title {
            color: var(--accent-blue);
            font-size: 1.1rem;
            margin-bottom: 16px;
        }
        
        .list-item {
            background: var(--secondary-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 12px 16px;
            margin-bottom: 8px;
            border-left: 4px solid var(--accent-blue);
        }
        
        .list-item:last-child {
            margin-bottom: 0;
        }
        
        .metric-bar {
            width: 100%;
            height: 8px;
            background: var(--border-color);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }
        
        .metric-fill {
            height: 100%;
            background: var(--accent-blue);
            transition: width 0.3s ease;
        }
        
        .metric-fill.success { background: var(--accent-green); }
        .metric-fill.warning { background: var(--accent-yellow); }
        .metric-fill.critical { background: var(--accent-red); }
        
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            background: var(--secondary-bg);
            border-radius: 8px;
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge.critical { background: var(--accent-red); color: white; }
        .badge.warning { background: var(--accent-yellow); color: black; }
        .badge.success { background: var(--accent-green); color: white; }
        .badge.info { background: var(--accent-blue); color: white; }
        
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header h1 { font-size: 2rem; }
            .tabs { flex-direction: column; }
            .tab { border-bottom: 1px solid var(--border-color); }
            .tab.active { border-bottom-color: var(--accent-blue); }
            .summary-grid { grid-template-columns: 1fr; }
            .info-grid { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Technical Security Analysis Report</h1>
            <div class="header-subtitle">Target: $computerName | Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | Risk Level: $($AuditData.Risk.Level) | Score: $($AuditData.DecommissionScore.Score)/100</div>
        </div>
        
        <div class="tabs">
            <button class="tab active" onclick="showTab('system')">System Analysis</button>
            <button class="tab" onclick="showTab('network')">Network Intelligence</button>
            <button class="tab" onclick="showTab('processes')">Process Analysis</button>
            <button class="tab" onclick="showTab('services')">Service Enumeration</button>
            <button class="tab" onclick="showTab('security')">Security Assessment</button>
            <button class="tab" onclick="showTab('forensics')">Forensic Details</button>
        </div>
        
        <div id="system" class="tab-content active">
            <div class="section">
                <h2 class="section-title">System Information</h2>
                <div class="info-grid">
                    <div class="info-panel">
                        <h4>General Information</h4>
                        <div class="info-row">
                            <span class="info-label">Computer Name:</span>
                            <span class="info-value">$($AuditData.System.ComputerName)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Operating System:</span>
                            <span class="info-value">$($AuditData.System.OSVersion)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Architecture:</span>
                            <span class="info-value">$($AuditData.System.Architecture)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Service Pack:</span>
                            <span class="info-value">$($AuditData.System.ServicePack)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Domain:</span>
                            <span class="info-value">$($AuditData.System.Domain)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Server Role:</span>
                            <span class="info-value">$($AuditData.System.ServerRole)</span>
                        </div>
                    </div>
                    
                    <div class="info-panel">
                        <h4>Hardware Specifications</h4>
                        <div class="info-row">
                            <span class="info-label">Manufacturer:</span>
                            <span class="info-value">$($AuditData.System.Manufacturer)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Model:</span>
                            <span class="info-value">$($AuditData.System.Model)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Processors:</span>
                            <span class="info-value">$($AuditData.System.ProcessorCount)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Total Memory:</span>
                            <span class="info-value">$($AuditData.System.TotalMemoryGB) GB</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Install Date:</span>
                            <span class="info-value">$(if ($AuditData.System.InstallDate) { $AuditData.System.InstallDate.ToString("yyyy-MM-dd") } else { "Unknown" })</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Last Boot:</span>
                            <span class="info-value">$(if ($AuditData.System.LastBootTime) { $AuditData.System.LastBootTime.ToString("yyyy-MM-dd HH:mm") } else { "Unknown" })</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">System Type:</span>
                            <span class="info-value">$($AuditData.System.SystemType)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Processor:</span>
                            <span class="info-value">$($AuditData.System.ProcessorName)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">BIOS Version:</span>
                            <span class="info-value">$($AuditData.System.BIOSVersion)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="hardware" class="tab-content">
            <div class="section">
                <h2 class="section-title">Storage Information</h2>
                <div class="info-grid">
"@

    # Add storage information
    foreach ($disk in $AuditData.Storage) {
        $statusClass = switch ($disk.Status) {
            "CRITICAL" { "status-critical" }
            "WARNING" { "status-warning" }
            default { "status-success" }
        }
        
        $fillClass = switch ($disk.Status) {
            "CRITICAL" { "critical" }
            "WARNING" { "warning" }
            default { "success" }
        }
        
        $html += @"
                    <div class="info-panel">
                        <h4>Drive $($disk.Drive)</h4>
                        <div class="info-row">
                            <span class="info-label">Total Size:</span>
                            <span class="info-value">$($disk.TotalGB) GB</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Free Space:</span>
                            <span class="info-value $statusClass">$($disk.FreeGB) GB</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Used Space:</span>
                            <span class="info-value">$($disk.UsedGB) GB</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Status:</span>
                            <span class="info-value $statusClass">$($disk.Status)</span>
                        </div>
                        <div class="metric-bar">
                            <div class="metric-fill $fillClass" style="width: $($disk.PercentUsed)%"></div>
                        </div>
                    </div>
"@
    }

    $html += @"
                </div>
            </div>
        </div>
        
        <div id="applications" class="tab-content">
            <div class="section">
                <h2 class="section-title">Detected Applications & Services</h2>
                <div class="list-section">
                    <h3 class="list-title">Critical Applications</h3>
"@

    # Add applications
    if ($AuditData.Applications.Count -gt 0) {
        foreach ($app in $AuditData.Applications) {
            $html += @"
                    <div class="list-item">
                        <strong>$app</strong>
                        <span class="badge info">Critical Service</span>
                    </div>
"@
        }
    } else {
        $html += @"
                    <div class="list-item">
                        <em>No critical applications detected</em>
                    </div>
"@
    }

    $html += @"
                </div>
            </div>
        </div>
        
        <div id="network" class="tab-content">
            <div class="section">
                <h2 class="section-title">Network Intelligence & Connection Analysis</h2>
                
                <div class="list-section">
                    <h3 class="list-title">Active Network Connections with Hostname Resolution</h3>
                    <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                        <tr style="background: #333; color: #4dc9ff;">
                            <th style="padding: 8px; text-align: left;">Protocol</th>
                            <th style="padding: 8px; text-align: left;">Local IP:Port</th>
                            <th style="padding: 8px; text-align: left;">Remote IP:Port</th>
                            <th style="padding: 8px; text-align: left;">Remote Hostname</th>
                            <th style="padding: 8px; text-align: left;">Remote FQDN</th>
                            <th style="padding: 8px; text-align: left;">Connection Type</th>
                            <th style="padding: 8px; text-align: left;">Direction</th>
                            <th style="padding: 8px; text-align: left;">Service</th>
                        </tr>"@

if ($AuditData.Network.DetailedConnections) {
    foreach ($conn in $AuditData.Network.DetailedConnections) {
        $rowColor = if ($conn.ConnectionType -eq "External") { "#2a2a2a" } else { "#1a1a1a" }
        $html += "                        <tr style=""background: $rowColor;"">"
        $html += "                            <td style=""padding: 6px;"">$($conn.Protocol)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($conn.LocalIP):$($conn.LocalPort)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($conn.RemoteIP):$($conn.RemotePort)</td>"
        $html += "                            <td style=""padding: 6px; color: #4dc9ff;"">$($conn.RemoteHostname)</td>"
        $html += "                            <td style=""padding: 6px; color: #3fb950;"">$($conn.RemoteFQDN)</td>"
        $html += "                            <td style=""padding: 6px;"">$($conn.ConnectionType)</td>"
        $html += "                            <td style=""padding: 6px;"">$($conn.Direction)</td>"
        $html += "                            <td style=""padding: 6px;"">$($conn.ServiceName)</td>"
        $html += "                        </tr>"
    }
} else {
    $html += "                        <tr><td colspan=""8"" style=""padding: 10px; text-align: center; color: #888;"">No detailed connection data available</td></tr>"
}

$html += @"
                    </table>
                </div>
                
                <div class="info-grid">
                    <div class="info-panel">
                        <h4>Network Adapter Configuration</h4>"@

if ($AuditData.Network.NetworkAdapters) {
    foreach ($adapter in $AuditData.Network.NetworkAdapters) {
        $html += "                        <div style=""margin-bottom: 15px; padding: 10px; background: #1a1a1a; border-radius: 5px;"">"
        $html += "                            <strong>$($adapter.Description)</strong><br>"
        $html += "                            <small style=""color: #888;"">MAC: $($adapter.MACAddress)</small><br>"
        $html += "                            <strong style=""color: #4dc9ff;"">IP:</strong> $($adapter.IPAddress)<br>"
        $html += "                            <strong style=""color: #4dc9ff;"">Gateway:</strong> $($adapter.DefaultGateway)<br>"
        $html += "                            <strong style=""color: #4dc9ff;"">DNS:</strong> $($adapter.DNSServers)<br>"
        $html += "                            <strong style=""color: #4dc9ff;"">DHCP:</strong> $($adapter.DHCPEnabled)"
        $html += "                        </div>"
    }
}

$html += @"
                    </div>
                    
                    <div class="info-panel">
                        <h4>Listening Services</h4>"@

if ($AuditData.Network.ListeningPorts) {
    foreach ($port in $AuditData.Network.ListeningPorts) {
        $portColor = if ($port.Port -match "^(80|443|21|22|23|25|53|110|143|993|995|1433|1521|3389)$") { "#f85149" } else { "#3fb950" }
        $html += "                        <div style=""margin-bottom: 8px; padding: 8px; background: #1a1a1a; border-left: 3px solid $portColor;"">"
        $html += "                            <strong style=""color: $portColor;"">$($port.Protocol):$($port.Port)</strong> - $($port.Service)"
        $html += "                        </div>"
    }
}

$html += @"
                    </div>
                </div>
            </div>
        </div>
        
        <div id="processes" class="tab-content">
            <div class="section">
                <h2 class="section-title">Process Analysis & Memory Forensics</h2>
                
                <div class="list-section">
                    <h3 class="list-title">Top Memory Consumers (Top 15)</h3>
                    <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                        <tr style="background: #333; color: #4dc9ff;">
                            <th style="padding: 8px; text-align: left;">Process Name</th>
                            <th style="padding: 8px; text-align: left;">PID</th>
                            <th style="padding: 8px; text-align: left;">Parent PID</th>
                            <th style="padding: 8px; text-align: left;">Memory (MB)</th>
                            <th style="padding: 8px; text-align: left;">Category</th>
                            <th style="padding: 8px; text-align: left;">Executable Path</th>
                            <th style="padding: 8px; text-align: left;">Command Line</th>
                        </tr>"@

if ($AuditData.ProcessDetails.TopProcesses) {
    foreach ($proc in $AuditData.ProcessDetails.TopProcesses) {
        $categoryColor = if ($proc.Category -eq "System") { "#3fb950" } else { "#d29922" }
        $suspiciousFlag = if ($proc.IsSuspicious) { "⚠️" } else { "" }
        $html += "                        <tr style=""background: #2a2a2a;"">"
        $html += "                            <td style=""padding: 6px; color: $categoryColor;"">$suspiciousFlag$($proc.Name)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($proc.ProcessId)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($proc.ParentProcessId)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace; text-align: right;"">$($proc.MemoryMB)</td>"
        $html += "                            <td style=""padding: 6px;"">$($proc.Category)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px; max-width: 200px; overflow: hidden;"">$($proc.ExecutablePath)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px; max-width: 250px; overflow: hidden;"">$($proc.CommandLine)</td>"
        $html += "                        </tr>"
    }
}

$html += @"
                    </table>
                </div>"@

if ($AuditData.ProcessDetails.SuspiciousProcesses -and $AuditData.ProcessDetails.SuspiciousProcesses.Count -gt 0) {
    $html += @"
                <div class="list-section">
                    <h3 class="list-title" style="color: #f85149;">⚠️ Suspicious Process Analysis</h3>
                    <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                        <tr style="background: #333; color: #f85149;">
                            <th style="padding: 8px; text-align: left;">Process Name</th>
                            <th style="padding: 8px; text-align: left;">PID</th>
                            <th style="padding: 8px; text-align: left;">Executable Path</th>
                            <th style="padding: 8px; text-align: left;">Command Line</th>
                            <th style="padding: 8px; text-align: left;">Creation Date</th>
                        </tr>"@
    
    foreach ($proc in $AuditData.ProcessDetails.SuspiciousProcesses) {
        $createdDate = if ($proc.CreationDate) { $proc.CreationDate.ToString("yyyy-MM-dd HH:mm") } else { "Unknown" }
        $html += "                        <tr style=""background: #2a1a1a; border-left: 3px solid #f85149;"">"
        $html += "                            <td style=""padding: 6px; color: #f85149;"">$($proc.Name)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($proc.ProcessId)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px;"">$($proc.ExecutablePath)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px;"">$($proc.CommandLine)</td>"
        $html += "                            <td style=""padding: 6px;"">$createdDate</td>"
        $html += "                        </tr>"
    }
    
    $html += @"
                    </table>
                </div>"@
}

$html += @"
                <div class="info-grid">
                    <div class="info-panel">
                        <h4>Process Statistics</h4>
                        <div class="info-row">
                            <span class="info-label">Total Processes:</span>
                            <span class="info-value">$($AuditData.ProcessDetails.TotalProcesses)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">System Processes:</span>
                            <span class="info-value status-success">$($AuditData.ProcessDetails.SystemProcesses)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">User Processes:</span>
                            <span class="info-value">$($AuditData.ProcessDetails.UserProcesses)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Suspicious Processes:</span>
                            <span class="info-value status-critical">$($AuditData.ProcessDetails.SuspiciousProcesses.Count)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Network Processes:</span>
                            <span class="info-value">$($AuditData.ProcessDetails.NetworkProcesses.Count)</span>
                        </div>
                    </div>
                    
                    <div class="info-panel">
                        <h4>Network-Active Processes</h4>"@

if ($AuditData.ProcessDetails.NetworkProcesses) {
    foreach ($proc in ($AuditData.ProcessDetails.NetworkProcesses | Select-Object -First 10)) {
        $html += "                        <div style=""margin-bottom: 8px; padding: 8px; background: #1a1a1a; border-left: 3px solid #4dc9ff;"">"
        $html += "                            <strong style=""color: #4dc9ff;"">$($proc.Name)</strong> (PID: $($proc.ProcessId))<br>"
        $html += "                            <small style=""color: #888;"">Memory: $($proc.MemoryMB) MB</small>"
        $html += "                        </div>"
    }
}

$html += @"
                    </div>
                </div>
            </div>
        </div>
        
        <div id="services" class="tab-content">
            <div class="section">
                <h2 class="section-title">Service Enumeration & Analysis</h2>
                
                <div class="list-section">
                    <h3 class="list-title">Critical System Services</h3>
                    <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                        <tr style="background: #333; color: #4dc9ff;">
                            <th style="padding: 8px; text-align: left;">Service Name</th>
                            <th style="padding: 8px; text-align: left;">Display Name</th>
                            <th style="padding: 8px; text-align: left;">State</th>
                            <th style="padding: 8px; text-align: left;">Start Mode</th>
                            <th style="padding: 8px; text-align: left;">Start Name</th>
                            <th style="padding: 8px; text-align: left;">Executable Path</th>
                        </tr>"@

if ($AuditData.ServiceDetails.CriticalServices) {
    foreach ($svc in $AuditData.ServiceDetails.CriticalServices) {
        $stateColor = if ($svc.State -eq "Running") { "#3fb950" } else { "#f85149" }
        $html += "                        <tr style=""background: #2a2a2a;"">"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($svc.Name)</td>"
        $html += "                            <td style=""padding: 6px;"">$($svc.DisplayName)</td>"
        $html += "                            <td style=""padding: 6px; color: $stateColor;"">$($svc.State)</td>"
        $html += "                            <td style=""padding: 6px;"">$($svc.StartMode)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px;"">$($svc.StartName)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px; max-width: 300px; overflow: hidden;"">$($svc.PathName)</td>"
        $html += "                        </tr>"
    }
}

$html += @"
                    </table>
                </div>"@

if ($AuditData.ServiceDetails.ThirdPartyServices -and $AuditData.ServiceDetails.ThirdPartyServices.Count -gt 0) {
    $html += @"
                <div class="list-section">
                    <h3 class="list-title" style="color: #d29922;">Third-Party Services</h3>
                    <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                        <tr style="background: #333; color: #d29922;">
                            <th style="padding: 8px; text-align: left;">Service Name</th>
                            <th style="padding: 8px; text-align: left;">Display Name</th>
                            <th style="padding: 8px; text-align: left;">State</th>
                            <th style="padding: 8px; text-align: left;">Executable Path</th>
                        </tr>"@
    
    foreach ($svc in ($AuditData.ServiceDetails.ThirdPartyServices | Select-Object -First 20)) {
        $stateColor = if ($svc.State -eq "Running") { "#3fb950" } else { "#888" }
        $html += "                        <tr style=""background: #2a2a2a;"">"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($svc.Name)</td>"
        $html += "                            <td style=""padding: 6px;"">$($svc.DisplayName)</td>"
        $html += "                            <td style=""padding: 6px; color: $stateColor;"">$($svc.State)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px;"">$($svc.PathName)</td>"
        $html += "                        </tr>"
    }
    
    $html += @"
                    </table>
                </div>"@
}

$html += @"
            </div>
        </div>
        
        <div id="security" class="tab-content">
            <div class="section">
                <h2 class="section-title">Security & Compliance</h2>
                <div class="info-grid">
                    <div class="info-panel">
                        <h4>Update Status</h4>
                        <div class="info-row">
                            <span class="info-label">OS Support:</span>
                            <span class="info-value">$($AuditData.System.SupportStatus)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Last Update:</span>
                            <span class="info-value">$(if ($AuditData.Updates.LastUpdateDate) { $AuditData.Updates.LastUpdateDate.ToString("yyyy-MM-dd") } else { "Unknown" })</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Days Since Update:</span>
                            <span class="info-value">$($AuditData.Updates.DaysSinceUpdate)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Total Updates:</span>
                            <span class="info-value">$($AuditData.Updates.TotalUpdates)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Update Service:</span>
                            <span class="info-value">$($AuditData.Updates.UpdateService)</span>
                        </div>
                    </div>
                    
                    <div class="info-panel">
                        <h4>Event Log Summary</h4>
                        <div class="info-row">
                            <span class="info-label">Recent Logins:</span>
                            <span class="info-value">$($AuditData.EventLog.RecentLogins)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">System Errors:</span>
                            <span class="info-value">$($AuditData.EventLog.SystemErrors)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">System Warnings:</span>
                            <span class="info-value">$($AuditData.EventLog.SystemWarnings)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Last Login:</span>
                            <span class="info-value">$(if ($AuditData.EventLog.LastLoginTime) { $AuditData.EventLog.LastLoginTime.ToString("yyyy-MM-dd HH:mm") } else { "Unknown" })</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Unique Users:</span>
                            <span class="info-value">$($AuditData.EventLog.LoginUsers.Count)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Critical Errors:</span>
                            <span class="info-value">$($AuditData.EventLog.CriticalErrors)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Application Errors:</span>
                            <span class="info-value">$($AuditData.EventLog.ApplicationErrors)</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div id="forensics" class="tab-content">
            <div class="section">
                <h2 class="section-title">Forensic Analysis & Event Intelligence</h2>
                
                <div class="list-section">
                    <h3 class="list-title">Event Log Analysis (Last 48 Hours)</h3>
                    <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                        <tr style="background: #333; color: #4dc9ff;">
                            <th style="padding: 8px; text-align: left;">Log Name</th>
                            <th style="padding: 8px; text-align: left;">Event ID</th>
                            <th style="padding: 8px; text-align: left;">Source</th>
                            <th style="padding: 8px; text-align: left;">Level</th>
                            <th style="padding: 8px; text-align: left;">Time Generated</th>
                            <th style="padding: 8px; text-align: left;">Message</th>
                        </tr>"@

if ($AuditData.EventLog.CriticalEvents) {
    foreach ($event in $AuditData.EventLog.CriticalEvents) {
        $levelColor = switch ($event.Level) {
            "Critical" { "#f85149" }
            "Error" { "#ff8c00" }
            "Warning" { "#d29922" }
            "Information" { "#3fb950" }
            default { "#888" }
        }
        $html += "                        <tr style=""background: #2a2a2a;"">"
        $html += "                            <td style=""padding: 6px; color: #4dc9ff;"">$($event.LogName)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace; color: $levelColor;"">$($event.EventID)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px;"">$($event.Source)</td>"
        $html += "                            <td style=""padding: 6px; color: $levelColor;"">$($event.Level)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px;"">$($event.TimeGenerated)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px; max-width: 300px; overflow: hidden;"">$($event.Message)</td>"
        $html += "                        </tr>"
    }
} else {
    $html += "                        <tr><td colspan=""6"" style=""padding: 10px; text-align: center; color: #888;"">No critical events found in the last 48 hours</td></tr>"
}

$html += @"
                    </table>
                </div>

                <div class="list-section">
                    <h3 class="list-title">User Activity Forensics</h3>
                    <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                        <tr style="background: #333; color: #4dc9ff;">
                            <th style="padding: 8px; text-align: left;">User Account</th>
                            <th style="padding: 8px; text-align: left;">Login Type</th>
                            <th style="padding: 8px; text-align: left;">Source IP</th>
                            <th style="padding: 8px; text-align: left;">Last Login</th>
                            <th style="padding: 8px; text-align: left;">Login Count (30 days)</th>
                            <th style="padding: 8px; text-align: left;">Account Status</th>
                        </tr>"@

if ($AuditData.EventLog.UserActivity) {
    foreach ($user in $AuditData.EventLog.UserActivity) {
        $statusColor = if ($user.AccountStatus -eq "Active") { "#3fb950" } else { "#888" }
        $html += "                        <tr style=""background: #2a2a2a;"">"
        $html += "                            <td style=""padding: 6px; color: #4dc9ff;"">$($user.Username)</td>"
        $html += "                            <td style=""padding: 6px;"">$($user.LoginType)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace;"">$($user.SourceIP)</td>"
        $html += "                            <td style=""padding: 6px; font-size: 10px;"">$($user.LastLogin)</td>"
        $html += "                            <td style=""padding: 6px; font-family: monospace; text-align: center;"">$($user.LoginCount)</td>"
        $html += "                            <td style=""padding: 6px; color: $statusColor;"">$($user.AccountStatus)</td>"
        $html += "                        </tr>"
    }
} else {
    $html += "                        <tr><td colspan=""6"" style=""padding: 10px; text-align: center; color: #888;"">No user activity data available</td></tr>"
}

$html += @"
                    </table>
                </div>
                <div class="info-grid">
                    <div class="info-panel">
                        <h4>System Routing Table</h4>"@

if ($AuditData.Network.RoutingTable) {
    $html += "                        <table style=""width: 100%; font-size: 11px; border-collapse: collapse;"">"
    $html += "                            <tr style=""background: #333; color: #4dc9ff;"">"
    $html += "                                <th style=""padding: 4px; text-align: left;"">Destination</th>"
    $html += "                                <th style=""padding: 4px; text-align: left;"">Netmask</th>"
    $html += "                                <th style=""padding: 4px; text-align: left;"">Gateway</th>"
    $html += "                                <th style=""padding: 4px; text-align: left;"">Interface</th>"
    $html += "                                <th style=""padding: 4px; text-align: left;"">Metric</th>"
    $html += "                            </tr>"
    
    foreach ($route in ($AuditData.Network.RoutingTable | Select-Object -First 15)) {
        $html += "                            <tr style=""background: #1a1a1a;"">"
        $html += "                                <td style=""padding: 4px; font-family: monospace; font-size: 9px;"">$($route.Destination)</td>"
        $html += "                                <td style=""padding: 4px; font-family: monospace; font-size: 9px;"">$($route.Netmask)</td>"
        $html += "                                <td style=""padding: 4px; font-family: monospace; font-size: 9px;"">$($route.Gateway)</td>"
        $html += "                                <td style=""padding: 4px; font-family: monospace; font-size: 9px;"">$($route.Interface)</td>"
        $html += "                                <td style=""padding: 4px; font-family: monospace; font-size: 9px;"">$($route.Metric)</td>"
        $html += "                            </tr>"
    }
    
    $html += "                        </table>"
} else {
    $html += "                        <div style=""padding: 10px; text-align: center; color: #888;"">Routing table data not available</div>"
}

$html += @"
                    </div>
                    
                    <div class="info-panel">
                        <h4>Risk Assessment Summary</h4>
                        <div class="info-row">
                            <span class="info-label">Risk Level:</span>
                            <span class="info-value status-$($AuditData.Risk.Color)">$($AuditData.Risk.Level)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Usage Score:</span>
                            <span class="info-value">$($AuditData.DecommissionScore.Score)/100</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Recommendation:</span>
                            <span class="info-value">$($AuditData.Risk.Recommendation)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Action Required:</span>
                            <span class="info-value">$($AuditData.Risk.Action)</span>
                        </div>
                        <div class="metric-bar">
                            <div class="metric-fill $($AuditData.Risk.Color)" style="width: $($AuditData.DecommissionScore.Score)%"></div>
                        </div>
                        
                        <h4 style="margin-top: 20px;">Usage Indicators</h4>
                        <div class="info-row">
                            <span class="info-label">Recent User Activity:</span>
                            <span class="info-value">$($AuditData.EventLog.RecentLogins) logins</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Network Clients:</span>
                            <span class="info-value">$($AuditData.Network.ClientCount) clients</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">File Share Usage:</span>
                            <span class="info-value">$($AuditData.Shares.ActiveSessions) sessions</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Critical Services:</span>
                            <span class="info-value">$($AuditData.Applications.Count) detected</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Total Processes:</span>
                            <span class="info-value">$($AuditData.ProcessDetails.TotalProcesses)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Running Services:</span>
                            <span class="info-value">$($AuditData.ServiceDetails.RunningServices)</span>
                        </div>
                        <div class="info-row">
                            <span class="info-label">Recent Updates:</span>
                            <span class="info-value">$($AuditData.Updates.RecentUpdates)</span>
                        </div>
                    </div>
                </div>
                
                <div class="list-section">
                    <h3 class="list-title">Scoring Details</h3>
"@

    # Add scoring details
    foreach ($detail in $AuditData.DecommissionScore.Details) {
        $html += "                    <div class=""list-item"">$detail</div>"
    }

    $html += @"
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Enterprise Server Audit Report</strong> | Generated by PowerShell Audit Script v$ScriptVersion</p>
            <p>Report generated on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tab contents
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            // Remove active class from all tabs
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
"@

    try {
        $html | Out-File -FilePath $fileName -Encoding UTF8
        Write-AuditLog "Enterprise HTML report saved: $fileName" "SUCCESS"
        return $fileName
    } catch {
        Write-AuditLog "Failed to save HTML report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

#endregion

#region Main Audit Function

function Invoke-EnterpriseAudit {
    param([string]$ComputerName)
    
    Write-AuditLog "Starting enterprise audit for $ComputerName" "INFO"
    
    # Test connectivity
    if (-not (Test-ServerConnectivity -ComputerName $ComputerName)) {
        Write-AuditLog "Unable to connect to $ComputerName" "ERROR"
        return $null
    }
    
    $auditData = @{
        ComputerName = $ComputerName
        AuditDate = Get-Date
        ScriptVersion = $ScriptVersion
    }
    
    try {
        Write-Progress -Activity "Auditing $ComputerName" -Status "Gathering system information" -PercentComplete 10
        
        # Enhanced System Information Collection
        $computerSystem = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_ComputerSystem"
        $operatingSystem = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_OperatingSystem"
        $processor = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Processor" | Select-Object -First 1
        $bios = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_BIOS"
        $timezone = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_TimeZone"
        
        if ($computerSystem -and $operatingSystem) {
            try {
                $bootTime = $operatingSystem.ConvertToDateTime($operatingSystem.LastBootUpTime)
                $installDate = $operatingSystem.ConvertToDateTime($operatingSystem.InstallDate)
            } catch {
                # Fallback for systems where ConvertToDateTime fails
                try {
                    $bootTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($operatingSystem.LastBootUpTime)
                    $installDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($operatingSystem.InstallDate)
                } catch {
                    $bootTime = [DateTime]::Now.AddDays(-1)
                    $installDate = [DateTime]::Now.AddDays(-365)
                }
            }
            
            $uptime = (Get-Date) - $bootTime
            $osVersion = Get-OSVersionInfo -OperatingSystem $operatingSystem
            $supportStatus = Get-SupportStatus -OSVersion $osVersion
            $serverRoles = Get-ServerRoles -ComputerSystem $computerSystem
            
            # Enhanced hardware information
            $processorName = if ($processor) { $processor.Name } else { "Unknown" }
            $processorSpeed = if ($processor) { [Math]::Round($processor.MaxClockSpeed / 1000, 2) } else { 0 }
            $processorCores = if ($processor) { $processor.NumberOfCores } else { $computerSystem.NumberOfProcessors }
            $processorLogical = if ($processor) { $processor.NumberOfLogicalProcessors } else { $computerSystem.NumberOfLogicalProcessors }
            
            # BIOS information
            $biosVersion = if ($bios) { $bios.SMBIOSBIOSVersion } else { "Unknown" }
            $biosDate = if ($bios) {
                try {
                    [DateTime]::ParseExact($bios.ReleaseDate.Substring(0,8), "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                } catch {
                    "Unknown"
                }
            } else { "Unknown" }
            
            # System classification
            $systemType = "Physical"
            if ($computerSystem.Model -like "*Virtual*" -or $computerSystem.Manufacturer -like "*VMware*" -or 
                $computerSystem.Manufacturer -like "*Microsoft Corporation*" -or $computerSystem.Model -like "*Hyper-V*") {
                $systemType = "Virtual Machine"
            }
            
            $auditData.System = @{
                ComputerName = $computerSystem.Name
                OSVersion = $osVersion
                OSBuild = $operatingSystem.BuildNumber
                Architecture = $operatingSystem.OSArchitecture
                ServicePack = $operatingSystem.CSDVersion
                Manufacturer = $computerSystem.Manufacturer
                Model = $computerSystem.Model
                SystemType = $systemType
                ProcessorCount = $computerSystem.NumberOfProcessors
                ProcessorName = $processorName
                ProcessorSpeedGHz = $processorSpeed
                ProcessorCores = $processorCores
                ProcessorLogical = $processorLogical
                TotalMemoryGB = [Math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
                Domain = $computerSystem.Domain
                DomainRole = $computerSystem.DomainRole
                ServerRole = $serverRoles -join ", "
                InstallDate = $installDate
                LastBootTime = $bootTime
                UptimeDays = $uptime.Days
                UptimeHours = $uptime.TotalHours
                SupportStatus = $supportStatus
                TimeZone = if ($timezone) { $timezone.Description } else { "Unknown" }
                BIOSVersion = $biosVersion
                BIOSDate = $biosDate
                OSLanguage = $operatingSystem.OSLanguage
                OSSerialNumber = $operatingSystem.SerialNumber
                WindowsDirectory = $operatingSystem.WindowsDirectory
                SystemDirectory = $operatingSystem.SystemDirectory
                TotalVirtualMemoryGB = [Math]::Round($operatingSystem.TotalVirtualMemorySize / 1MB, 2)
                AvailablePhysicalMemoryGB = [Math]::Round($operatingSystem.FreePhysicalMemory / 1MB, 2)
            }
        } else {
            throw "Unable to retrieve basic system information"
        }
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Gathering storage information" -PercentComplete 20
        
        # Storage Information
        $disks = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_LogicalDisk" -Filter "DriveType=3"
        $auditData.Storage = @()
        
        if ($disks) {
            foreach ($disk in $disks) {
                $totalGB = [Math]::Round($disk.Size / 1GB, 2)
                $freeGB = [Math]::Round($disk.FreeSpace / 1GB, 2)
                $usedGB = $totalGB - $freeGB
                $percentUsed = [Math]::Round((($totalGB - $freeGB) / $totalGB) * 100, 1)
                $percentFree = 100 - $percentUsed
                
                $status = "OK"
                if ($percentFree -lt 10) { $status = "CRITICAL" }
                elseif ($percentFree -lt 20) { $status = "WARNING" }
                
                $auditData.Storage += @{
                    Drive = $disk.DeviceID
                    TotalGB = $totalGB
                    UsedGB = $usedGB
                    FreeGB = $freeGB
                    PercentUsed = $percentUsed
                    PercentFree = $percentFree
                    Status = $status
                }
            }
        }
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Detecting applications" -PercentComplete 30
        
        # Application Detection
        $auditData.Applications = Get-ApplicationServices -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Gathering network information" -PercentComplete 40
        
        # Network Information
        if (-not $SkipNetworkConnections) {
            $auditData.Network = Get-NetworkConnections -ComputerName $ComputerName
        } else {
            $auditData.Network = @{
                Connections = @()
                UniqueClients = @()
                ListeningPorts = @()
                ClientCount = 0
            }
        }
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Gathering file share information" -PercentComplete 50
        
        # Share Information
        $auditData.Shares = Get-ShareActivity -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Analyzing event logs" -PercentComplete 60
        
        # Event Log Analysis
        if (-not $QuickScan) {
            $auditData.EventLog = Get-EventLogSummary -ComputerName $ComputerName -MaxEvents $MaxEvents
        } else {
            $auditData.EventLog = @{
                RecentLogins = 0
                SystemErrors = 0
                SystemWarnings = 0
                LastLoginTime = $null
                LastErrorTime = $null
                SecurityEvents = 0
            }
        }
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Checking update status" -PercentComplete 70
        
        # Update Information
        $auditData.Updates = Get-UpdateStatus -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Gathering enhanced data" -PercentComplete 65
        
        # Enhanced Data Collection
        Write-Progress -Activity "Auditing $ComputerName" -Status "Discovering database instances" -PercentComplete 66
        $auditData.DatabaseInstances = Get-DatabaseInstances -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Analyzing scheduled tasks" -PercentComplete 67
        $auditData.ScheduledJobs = Get-ScheduledJobsAnalysis -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Discovering web applications" -PercentComplete 68
        $auditData.WebApplications = Get-WebApplications -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Analyzing file system activity" -PercentComplete 69
        $auditData.FileSystemActivity = Get-FileSystemActivity -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Mapping dependencies" -PercentComplete 70
        $auditData.DependencyMapping = Get-DependencyMapping -ComputerName $ComputerName
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Calculating decommission score" -PercentComplete 80
        
        # Get additional system details for scoring
        Write-Progress -Activity "Auditing $ComputerName" -Status "Gathering process and service details" -PercentComplete 75
        
        # Get detailed process information
        $processes = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Process"
        $auditData.ProcessDetails = @{
            TotalProcesses = if ($processes) { @($processes).Count } else { 0 }
            TopProcesses = @()
            SystemProcesses = 0
            UserProcesses = 0
            ProcessList = @()
            SuspiciousProcesses = @()
            NetworkProcesses = @()
        }
        
        if ($processes) {
            # Get comprehensive process information
            foreach ($proc in $processes) {
                $memoryMB = if ($proc.WorkingSetSize) { [Math]::Round($proc.WorkingSetSize / 1MB, 2) } else { 0 }
                $creationDate = $null
                try {
                    if ($proc.CreationDate) {
                        $creationDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($proc.CreationDate)
                    }
                } catch {
                    $creationDate = $null
                }
                
                # Determine process category
                $processCategory = "User"
                $isSuspicious = $false
                $hasNetworkActivity = $false
                
                if ($proc.Name -like "*system*" -or $proc.Name -like "*svchost*" -or 
                    $proc.Name -like "*winlogon*" -or $proc.Name -like "*csrss*" -or
                    $proc.Name -like "*smss*" -or $proc.Name -like "*wininit*") {
                    $processCategory = "System"
                    $auditData.ProcessDetails.SystemProcesses++
                } else {
                    $auditData.ProcessDetails.UserProcesses++
                }
                
                # Check for suspicious characteristics
                if ($proc.Name -match "\.(tmp|temp)$" -or 
                    $proc.CommandLine -like "*powershell*-enc*" -or
                    $proc.CommandLine -like "*cmd*ping*" -or
                    ($proc.ParentProcessId -eq 0 -and $processCategory -eq "User") -or
                    $proc.Name -match "^[a-f0-9]{8,}\.(exe|com|scr)$") {
                    $isSuspicious = $true
                }
                
                # Check for network-related processes
                if ($proc.Name -like "*chrome*" -or $proc.Name -like "*firefox*" -or 
                    $proc.Name -like "*iexplore*" -or $proc.Name -like "*outlook*" -or
                    $proc.Name -like "*ftp*" -or $proc.Name -like "*ssh*" -or
                    $proc.Name -like "*rdp*" -or $proc.Name -like "*vnc*") {
                    $hasNetworkActivity = $true
                }
                
                $processInfo = New-Object PSObject -Property @{
                    Name = $proc.Name
                    ProcessId = $proc.ProcessId
                    ParentProcessId = $proc.ParentProcessId
                    MemoryMB = $memoryMB
                    CommandLine = $proc.CommandLine
                    ExecutablePath = $proc.ExecutablePath
                    CreationDate = $creationDate
                    Category = $processCategory
                    IsSuspicious = $isSuspicious
                    HasNetworkActivity = $hasNetworkActivity
                    SessionId = $proc.SessionId
                    ThreadCount = $proc.ThreadCount
                    HandleCount = $proc.HandleCount
                }
                
                $auditData.ProcessDetails.ProcessList += $processInfo
                
                if ($isSuspicious) {
                    $auditData.ProcessDetails.SuspiciousProcesses += $processInfo
                }
                
                if ($hasNetworkActivity) {
                    $auditData.ProcessDetails.NetworkProcesses += $processInfo
                }
            }
            
            # Get top processes by memory usage
            $auditData.ProcessDetails.TopProcesses = $auditData.ProcessDetails.ProcessList | 
                Where-Object { $_.MemoryMB -gt 0 } | 
                Sort-Object MemoryMB -Descending | 
                Select-Object -First 15
        }
        
        # Get detailed service information
        $services = Get-SafeWMIObject -ComputerName $ComputerName -Class "Win32_Service"
        $auditData.ServiceDetails = @{
            TotalServices = if ($services) { @($services).Count } else { 0 }
            RunningServices = 0
            StoppedServices = 0
            AutoStartServices = 0
            CriticalServices = @()
        }
        
        if ($services) {
            foreach ($service in $services) {
                # Count by state
                if ($service.State -eq "Running") {
                    $auditData.ServiceDetails.RunningServices++
                } else {
                    $auditData.ServiceDetails.StoppedServices++
                }
                
                # Count auto-start services
                if ($service.StartMode -eq "Auto") {
                    $auditData.ServiceDetails.AutoStartServices++
                }
                
                # Identify critical services
                $criticalServiceNames = @("BITS", "Browser", "CryptSvc", "DcomLaunch", "Dhcp", "Dnscache", 
                                        "EventSystem", "LanmanServer", "LanmanWorkstation", "LmHosts", 
                                        "Messenger", "PlugPlay", "ProtectedStorage", "RpcSs", "Schedule", 
                                        "Spooler", "TrkWks", "UPS", "W32Time", "WebClient", "Winmgmt", "WZCSVC")
                
                if ($criticalServiceNames -contains $service.Name) {
                    $auditData.ServiceDetails.CriticalServices += @{
                        Name = $service.Name
                        DisplayName = $service.DisplayName
                        State = $service.State
                        StartMode = $service.StartMode
                    }
                }
            }
        }
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Calculating decommission score" -PercentComplete 80
        
        # Calculate Decommission Score with enhanced data
        $auditData.DecommissionScore = Calculate-DecommissionScore -AuditData $auditData
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Performing risk assessment" -PercentComplete 90
        
        # Risk Assessment
        $auditData.Risk = Get-RiskAssessment -Score $auditData.DecommissionScore.Score
        
        Write-Progress -Activity "Auditing $ComputerName" -Status "Complete" -PercentComplete 100
        
        Write-AuditLog "Enterprise audit completed for $ComputerName - Risk: $($auditData.Risk.Level) (Score: $($auditData.DecommissionScore.Score))" "SUCCESS"
        
        return $auditData
        
    } catch {
        Write-AuditLog "Error during enterprise audit of $ComputerName`: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

#endregion

#region CSV Export Function

function Export-EnterpriseCSV {
    param([object[]]$AuditResults)
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HHmm"
    $fileName = "EnterpriseAudit_$timestamp.csv"
    
    $csvData = @()
    
    foreach ($result in $AuditResults) {
        if ($result) {
            $csvData += [PSCustomObject]@{
                Server = $result.ComputerName
                OS = $result.System.OSVersion
                OSBuild = $result.System.OSBuild
                Architecture = $result.System.Architecture
                SupportStatus = $result.System.SupportStatus
                SystemType = $result.System.SystemType
                RiskLevel = $result.Risk.Level
                UsageScore = $result.DecommissionScore.Score
                Recommendation = $result.Risk.Recommendation
                Action = $result.Risk.Action
                ConnectedClients = $result.Network.ClientCount
                EstablishedConnections = $result.Network.EstablishedConnections
                ActiveUsers = $result.EventLog.RecentLogins
                UniqueUsers = $result.EventLog.LoginUsers.Count
                FileShareUsers = $result.Shares.ActiveSessions
                ServerRoles = $result.System.ServerRole
                DetectedApplications = ($result.Applications -join "; ")
                UptimeDays = $result.System.UptimeDays
                LastUpdateDaysAgo = $result.Updates.DaysSinceUpdate
                RecentUpdates = $result.Updates.RecentUpdates
                LastBoot = if ($result.System.LastBootTime) { $result.System.LastBootTime.ToString("yyyy-MM-dd") } else { "Unknown" }
                TotalMemoryGB = $result.System.TotalMemoryGB
                ProcessorName = $result.System.ProcessorName
                ProcessorCores = $result.System.ProcessorCores
                Domain = $result.System.Domain
                Manufacturer = $result.System.Manufacturer
                Model = $result.System.Model
                ProcessorCount = $result.System.ProcessorCount
                TotalProcesses = $result.ProcessDetails.TotalProcesses
                RunningServices = $result.ServiceDetails.RunningServices
                SystemErrors = $result.EventLog.SystemErrors
                SystemWarnings = $result.EventLog.SystemWarnings
                CriticalErrors = $result.EventLog.CriticalErrors
                ApplicationErrors = $result.EventLog.ApplicationErrors
                SharedFolders = $result.Shares.Shares.Count
                OpenFiles = $result.Shares.OpenFiles
                ListeningPorts = $result.Network.ListeningPorts.Count
                TimeZone = $result.System.TimeZone
                BIOSVersion = $result.System.BIOSVersion
                UpdateService = $result.Updates.UpdateService
                AuditDate = $result.AuditDate.ToString("yyyy-MM-dd HH:mm")
                # Enhanced data fields
                DatabaseInstances = if ($result.DatabaseInstances) { $result.DatabaseInstances.Instances.Count } else { 0 }
                RunningDatabases = if ($result.DatabaseInstances) { ($result.DatabaseInstances.Instances | Where-Object { $_.Status -eq "Running" }).Count } else { 0 }
                DatabaseTypes = if ($result.DatabaseInstances) { ($result.DatabaseInstances.Instances | Select-Object -ExpandProperty Type -Unique) -join "; " } else { "None" }
                WebApplications = if ($result.WebApplications) { $result.WebApplications.TotalSites } else { 0 }
                ActiveWebSites = if ($result.WebApplications) { $result.WebApplications.ActiveSites } else { 0 }
                ScheduledJobs = if ($result.ScheduledJobs) { $result.ScheduledJobs.TotalJobs } else { 0 }
                ActiveScheduledJobs = if ($result.ScheduledJobs) { $result.ScheduledJobs.ActiveJobs } else { 0 }
                RecentFiles = if ($result.FileSystemActivity) { $result.FileSystemActivity.TotalRecentFiles } else { 0 }
                LargeFilesGB = if ($result.FileSystemActivity) { $result.FileSystemActivity.TotalDataGB } else { 0 }
                DependencyConnections = if ($result.DependencyMapping) { $result.DependencyMapping.TotalDependencies } else { 0 }
            }
        }
    }
    
    try {
        $csvData | Export-Csv -Path $fileName -NoTypeInformation
        Write-AuditLog "Enterprise CSV report saved: $fileName" "SUCCESS"
        return $fileName
    } catch {
        Write-AuditLog "Failed to save CSV report: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

#endregion

#region Main Script Execution

function Main {
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Enterprise Windows Server Decommissioning Audit" -ForegroundColor Cyan
    Write-Host "Version: $ScriptVersion" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    $auditResults = @()
    $serverList = @()
    
    # Determine servers to audit
    if ($AuditList -and (Test-Path $AuditList)) {
        $serverList = Get-Content $AuditList | Where-Object { $_ -and $_.Trim() -ne "" }
        Write-AuditLog "Loaded $($serverList.Count) servers from $AuditList" "INFO"
    } else {
        $serverList = @($env:COMPUTERNAME)
        Write-AuditLog "No audit list provided, auditing local computer only" "INFO"
    }
    
    # Auto-enable SkipNetworkConnections for remote audits
    if ($serverList.Count -gt 1 -or ($serverList[0] -ne $env:COMPUTERNAME -and $serverList[0] -ne "localhost")) {
        $SkipNetworkConnections = $true
        Write-AuditLog "Remote audit detected, enabling SkipNetworkConnections" "INFO"
    }
    
    # Perform audits
    $totalServers = $serverList.Count
    $currentServer = 0
    
    foreach ($server in $serverList) {
        $currentServer++
        Write-Progress -Activity "Enterprise Server Auditing" -Status "Processing server $currentServer of $totalServers - $server" -PercentComplete (($currentServer / $totalServers) * 100)
        
        $auditResult = Invoke-EnterpriseAudit -ComputerName $server.Trim()
        
        if ($auditResult) {
            $auditResults += $auditResult
            
            # Generate individual HTML report
            $htmlFile = New-EnterpriseHTMLReport -AuditData $auditResult
            
            # Display comprehensive summary
            Write-Host ""
            Write-Host "=== ENTERPRISE AUDIT SUMMARY: $($auditResult.ComputerName) ===" -ForegroundColor Cyan
            Write-Host "Risk Level: " -NoNewline
            switch ($auditResult.Risk.Level) {
                "CRITICAL" { Write-Host $auditResult.Risk.Level -ForegroundColor Red }
                "MODERATE" { Write-Host $auditResult.Risk.Level -ForegroundColor Yellow }
                "LOW" { Write-Host $auditResult.Risk.Level -ForegroundColor Yellow }
                "MINIMAL" { Write-Host $auditResult.Risk.Level -ForegroundColor Green }
            }
            Write-Host "Usage Score: $($auditResult.DecommissionScore.Score)/100" -ForegroundColor White
            Write-Host "OS Support: $($auditResult.System.SupportStatus)" -ForegroundColor White
            Write-Host "Recommendation: $($auditResult.Risk.Recommendation)" -ForegroundColor White
            Write-Host "Action Required: $($auditResult.Risk.Action)" -ForegroundColor White
            Write-Host "Connected Clients: $($auditResult.Network.ClientCount)" -ForegroundColor White
            Write-Host "Critical Applications: $($auditResult.Applications.Count)" -ForegroundColor White
            Write-Host "Uptime: $($auditResult.System.UptimeDays) days" -ForegroundColor White
            Write-Host "System Type: $($auditResult.System.SystemType)" -ForegroundColor White
            Write-Host "Recent Updates: $($auditResult.Updates.RecentUpdates)" -ForegroundColor White
            Write-Host "Running Services: $($auditResult.ServiceDetails.RunningServices)" -ForegroundColor White
            Write-Host "HTML Report: $htmlFile" -ForegroundColor Green
            Write-Host ""
        }
    }
    
    Write-Progress -Activity "Enterprise Server Auditing" -Status "Complete" -PercentComplete 100
    
    # Generate consolidated CSV report
    if ($auditResults.Count -gt 0) {
        $csvFile = Export-EnterpriseCSV -AuditResults $auditResults
        
        Write-Host ""
        Write-Host "=== ENTERPRISE AUDIT COMPLETE ===" -ForegroundColor Green
        Write-Host "Total servers audited: $($auditResults.Count)" -ForegroundColor White
        Write-Host "CSV summary report: $csvFile" -ForegroundColor Green
        Write-Host ""
        
        # Risk level summary with enhanced statistics
        $riskSummary = $auditResults | Group-Object { $_.Risk.Level } | Sort-Object Name
        Write-Host "Risk Level Distribution:" -ForegroundColor Cyan
        foreach ($risk in $riskSummary) {
            $color = switch ($risk.Name) {
                "CRITICAL" { "Red" }
                "MODERATE" { "Yellow" }
                "LOW" { "Yellow" }
                "MINIMAL" { "Green" }
                default { "White" }
            }
            $percentage = [Math]::Round(($risk.Count / $auditResults.Count) * 100, 1)
            Write-Host "  $($risk.Name): $($risk.Count) servers ($percentage%)" -ForegroundColor $color
        }
        
        # Additional statistics
        $criticalServers = $auditResults | Where-Object { $_.Risk.Level -eq "CRITICAL" }
        $candidateServers = $auditResults | Where-Object { $_.Risk.Level -eq "MINIMAL" -or $_.Risk.Level -eq "LOW" }
        $eolServers = $auditResults | Where-Object { $_.System.SupportStatus -eq "END OF LIFE" }
        
        Write-Host ""
        Write-Host "Decommissioning Recommendations:" -ForegroundColor Yellow
        Write-Host "  Safe to decommission: $($candidateServers.Count) servers" -ForegroundColor Green
        Write-Host "  Requires further review: $(($auditResults | Where-Object { $_.Risk.Level -eq "MODERATE" }).Count) servers" -ForegroundColor Yellow
        Write-Host "  Do not decommission: $($criticalServers.Count) servers" -ForegroundColor Red
        Write-Host "  End-of-life systems: $($eolServers.Count) servers" -ForegroundColor Red
        
        # Show top decommission candidates
        if ($candidateServers.Count -gt 0) {
            Write-Host ""
            Write-Host "Top Decommission Candidates:" -ForegroundColor Green
            $topCandidates = $candidateServers | Sort-Object { $_.DecommissionScore.Score } | Select-Object -First 5
            foreach ($candidate in $topCandidates) {
                Write-Host "  $($candidate.ComputerName): Score $($candidate.DecommissionScore.Score)/100 - $($candidate.Risk.Recommendation)" -ForegroundColor Green
            }
        }
        
    } else {
        Write-AuditLog "No successful audits completed" "WARN"
    }
    
    Write-Host ""
    Write-Host "Enterprise audit process completed successfully!" -ForegroundColor Green
    Write-Host "Review the HTML reports for detailed analysis and the CSV file for batch processing." -ForegroundColor Cyan
}

# Execute main function
Main

#endregion