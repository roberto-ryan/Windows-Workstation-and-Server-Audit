#####################################################
#                                                   #
#    Audit script V4 by Alan Renouf - Virtu-Al     #
#    Blog: http://virtu-al.net/                    #
#    Enhanced with improved error handling          #
#                                                   #
#    Usage: Audit.ps1 [-AuditList 'path']          #
#           [-Credential $cred] [-MaxEvents 100]   #
#                                                   #
#    The file is optional and needs to be a        #
#    plain text list of computers to be audited    #
#    one on each line, if no list is specified     #
#    the local machine will be audited.            #
#                                                   #
#####################################################

param( 
    [string]$AuditList,
    [System.Management.Automation.PSCredential]$Credential,
    [int]$MaxEvents = 100,
    [switch]$SkipNetworkConnections,
    [switch]$QuickScan
)

Function Get-CustomHTML ($Header){
$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-frameset.dtd">
<html><head><title>$($Header)</title>
<META http-equiv=Content-Type content='text/html; charset=windows-1252'>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="save" content="history">

<style type="text/css">
:root {
  --bg-color: #1e1e1e;
  --text-color: #e6e6e6;
  --header-bg: #0078d4;
  --header-color: #ffffff;
  --section-bg: #2d2d2d;
  --section-alt-bg: #333333;
  --border-color: #444444;
  --link-color: #4dc9ff;
  --highlight: #0078d4;
  --warning-color: #ff8c00;
  --error-color: #ff5252;
  --success-color: #4caf50;
  --tab-bg: #2a2a2a;
  --tab-active-bg: #333333;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  background-color: var(--bg-color);
  color: var(--text-color);
  font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
  line-height: 1.6;
  margin: 0;
  padding: 20px;
}

.report-container {
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px;
  background-color: #252525;
  border-radius: 8px;
  box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
}

.report-header {
  margin-bottom: 20px;
  border-bottom: 2px solid var(--header-bg);
  padding-bottom: 10px;
}

.report-title {
  font-size: 28px;
  color: var(--header-bg);
  margin-bottom: 5px;
}

.report-meta {
  font-size: 12px;
  color: #b0b0b0;
  margin-bottom: 10px;
}

/* Summary Section */
.summary-section {
  background-color: var(--section-bg);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 20px;
  border: 1px solid var(--border-color);
}

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 15px;
  margin-top: 15px;
}

.summary-item {
  background-color: var(--tab-bg);
  padding: 15px;
  border-radius: 5px;
  text-align: center;
}

.summary-value {
  font-size: 24px;
  font-weight: bold;
  color: var(--link-color);
}

.summary-label {
  font-size: 12px;
  color: #b0b0b0;
  margin-top: 5px;
}

/* Status colors */
.status-ok { color: var(--success-color); }
.status-warning { color: var(--warning-color); }
.status-error { color: var(--error-color); }

/* Tab navigation */
.tab-navigation {
  display: flex;
  flex-wrap: wrap;
  margin-bottom: 20px;
  border-bottom: 2px solid var(--border-color);
}

.tab-button {
  background-color: var(--tab-bg);
  color: var(--text-color);
  border: none;
  padding: 12px 24px;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  transition: all 0.3s ease;
  border-radius: 5px 5px 0 0;
  margin-right: 4px;
  margin-bottom: -2px;
}

.tab-button:hover {
  background-color: var(--tab-active-bg);
}

.tab-button.active {
  background-color: var(--tab-active-bg);
  color: var(--link-color);
  border-bottom: 2px solid var(--highlight);
}

/* Tab content */
.tab-content {
  display: none;
  animation: fadeIn 0.3s ease-in;
}

.tab-content.active {
  display: block;
}

@keyframes fadeIn {
  from { opacity: 0; }
  to { opacity: 1; }
}

.tab-pane {
  padding: 20px;
  background-color: var(--section-bg);
  border-radius: 0 0 8px 8px;
}

.filler {
  display: block;
  height: 8px;
}

.save {
  behavior: url(#default#savehistory);
}

/* Section styling */
.dsphead0 {
  display: none;
}

.section-header {
  font-size: 18px;
  font-weight: bold;
  color: var(--link-color);
  margin-bottom: 15px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border-color);
}

a.dsphead1, a.dsphead2 {
  display: block;
  padding: 10px 15px;
  margin-bottom: 8px;
  background-color: #333333;
  color: var(--text-color);
  font-weight: bold;
  font-size: 16px;
  border-radius: 5px;
  text-decoration: none;
  position: relative;
  border-left: 4px solid var(--highlight);
  transition: background-color 0.2s ease;
}

a.dsphead1:hover, a.dsphead2:hover {
  background-color: #3a3a3a;
}

.expando {
  position: absolute;
  right: 15px;
  color: var(--link-color);
  font-size: 14px;
  text-decoration: none;
}

/* Content styling */
.dspcont {
  display: none;
  padding: 15px;
  margin: 0 0 15px 10px;
  background-color: #2a2a2a;
  border-radius: 5px;
  border-left: 4px solid #444;
}

/* Table styling */
table {
  width: 100%;
  border-collapse: collapse;
  margin-bottom: 20px;
  border-radius: 5px;
  overflow: hidden;
}

th {
  background-color: #333;
  color: var(--link-color);
  text-align: left;
  padding: 12px 15px;
  font-size: 14px;
  font-weight: 600;
  border-bottom: 2px solid #444;
}

td {
  padding: 10px 15px;
  border-bottom: 1px solid #3a3a3a;
  font-size: 14px;
  vertical-align: top;
}

tr:nth-child(even) {
  background-color: #2a2a2a;
}

tr:hover {
  background-color: #303030;
}

/* Detail tables */
table.details {
  margin-bottom: 15px;
}

table.details th {
  width: 25%;
}

/* States */
.warning {
  color: var(--warning-color);
}

.error {
  color: var(--error-color);
}

.ok {
  color: var(--success-color);
}

.error-notice {
  background-color: rgba(255, 82, 82, 0.1);
  border: 1px solid var(--error-color);
  border-radius: 5px;
  padding: 15px;
  margin: 15px 0;
}

.warning-notice {
  background-color: rgba(255, 140, 0, 0.1);
  border: 1px solid var(--warning-color);
  border-radius: 5px;
  padding: 15px;
  margin: 15px 0;
}

@media (max-width: 768px) {
  body {
    padding: 10px;
  }
  
  .report-container {
    padding: 10px;
  }
  
  th, td {
    padding: 8px 10px;
  }
  
  .tab-button {
    padding: 10px 16px;
    font-size: 12px;
  }
  
  .summary-grid {
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  }
}
</style>

<script type="text/javascript">
var tabCounter = 0;
var tabMap = {};

function switchTab(tabName) {
  var i, tabContent, tabButtons;
  
  tabContent = document.getElementsByClassName("tab-content");
  for (i = 0; i < tabContent.length; i++) {
    tabContent[i].className = tabContent[i].className.replace(" active", "");
  }
  
  tabButtons = document.getElementsByClassName("tab-button");
  for (i = 0; i < tabButtons.length; i++) {
    tabButtons[i].className = tabButtons[i].className.replace(" active", "");
  }
  
  document.getElementById(tabName).className += " active";
  document.getElementById(tabName + "-btn").className += " active";
}

function dsp(loc){
   if(document.getElementById){
      var foc=loc.firstChild;
      foc=loc.firstChild.innerHTML?
         loc.firstChild:
         loc.firstChild.nextSibling;
      foc.innerHTML=foc.innerHTML=='hide'?'show':'hide';
      foc=loc.parentNode.nextSibling.style?
         loc.parentNode.nextSibling:
         loc.parentNode.nextSibling.nextSibling;
      foc.style.display=foc.style.display=='block'?'none':'block';}}  

if(!document.getElementById)
   document.write('<style type="text/css">\n'+'.dspcont{display:block;}\n'+ '</style>');
</script>

</head>
<body>
<div class="report-container">
  <div class="report-header">
    <h1 class="report-title">$($Header)</h1>
    <div class="report-meta">
      <p><strong>Windows System Audit Report</strong> | Version 4 Enhanced by Alan Renouf (virtu-al.net)</p>
      <p>Report created on $(Get-Date -Format "dddd, MMMM dd, yyyy HH:mm:ss")</p>
    </div>
  </div>
"@
Return $Report
}

Function Get-CustomSummary {
$Report = @"
  <div class="summary-section">
    <h2>Summary</h2>
    <div class="summary-grid" id="summaryGrid">
    </div>
  </div>
"@
Return $Report
}

Function Add-SummaryItem ($Label, $Value, $Status = "ok") {
$Report = @"
  <script type="text/javascript">
    document.getElementById('summaryGrid').innerHTML += '<div class="summary-item"><div class="summary-value status-$($Status)">$($Value)</div><div class="summary-label">$($Label)</div></div>';
  </script>
"@
Return $Report
}

Function Get-CustomHeader0 ($Title){
$Report = @"
    <script type="text/javascript">
    tabCounter++;
    var tabId = 'tab' + tabCounter;
    tabMap['$($Title)'] = tabId;
    if (!document.getElementById('tabNav')) {
        document.write('<div class="tab-navigation" id="tabNav"></div>');
    }
    document.getElementById('tabNav').innerHTML += '<button class="tab-button' + (tabCounter === 1 ? ' active' : '') + '" id="' + tabId + '-btn" onclick="switchTab(\'' + tabId + '\')">$($Title)</button>';
    document.write('<div id="' + tabId + '" class="tab-content' + (tabCounter === 1 ? ' active' : '') + '"><div class="tab-pane">');
    </script>
"@
Return $Report
}

Function Get-CustomHeader ($Num, $Title){
$Report = @"
    <h2><a href="javascript:void(0)" class="dsphead$($Num)" onclick="dsp(this)">
    <span class="expando">show</span>$($Title)</a></h2>
    <div class="dspcont">
"@
Return $Report
}

Function Get-CustomHeaderClose{
$Report = @"
    </DIV>
    <div class="filler"></div>
"@
Return $Report
}

Function Get-CustomHeader0Close{
$Report = @"
    <script type="text/javascript">
    document.write('</div></div>');
    </script>
"@
Return $Report
}

Function Get-CustomHTMLClose{
$Report = @"
  </div>
</div>
</body>
</html>
"@
Return $Report
}

Function Get-HTMLTable{
	param([array]$Content)
	$HTMLTable = $Content | ConvertTo-Html
	$HTMLTable = $HTMLTable -replace '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">', ""
	$HTMLTable = $HTMLTable -replace '<html xmlns="http://www.w3.org/1999/xhtml">', ""
	$HTMLTable = $HTMLTable -replace '<head>', ""
	$HTMLTable = $HTMLTable -replace '<title>HTML TABLE</title>', ""
	$HTMLTable = $HTMLTable -replace '</head><body>', ""
	$HTMLTable = $HTMLTable -replace '</body></html>', ""
	Return $HTMLTable
}

Function Get-HTMLDetail ($Heading, $Detail){
$Report = @"
<TABLE class="details">
    <tr>
    <th width='25%'><b>$Heading</b></th>
    <td width='75%'>$($Detail)</td>
    </tr>
</TABLE>
"@
Return $Report
}

Function Get-RegistrySoftware {
    param($ComputerName)
    
    $Software = @()
    $RegPaths = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    
    foreach ($Path in $RegPaths) {
        try {
            if ($ComputerName -eq $env:COMPUTERNAME) {
                $RegKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ComputerName)
                $UninstallRef = $RegKey.OpenSubKey($Path)
                if ($UninstallRef) {
                    $SubKeys = $UninstallRef.GetSubKeyNames()
                    foreach ($SubKey in $SubKeys) {
                        $AppKey = $UninstallRef.OpenSubKey($SubKey)
                        $DisplayName = $AppKey.GetValue("DisplayName")
                        if ($DisplayName) {
                            $Software += New-Object PSObject -Property @{
                                Name = $DisplayName
                                Version = $AppKey.GetValue("DisplayVersion")
                                Vendor = $AppKey.GetValue("Publisher")
                                InstallDate = $AppKey.GetValue("InstallDate")
                            }
                        }
                        $AppKey.Close()
                    }
                    $UninstallRef.Close()
                }
            } else {
                # For remote computers, we'll fall back to WMI registry provider
                $WMIRegParams = @{
                    ComputerName = $ComputerName
                    Namespace = "root\default"
                    Class = "StdRegProv"
                    ErrorAction = 'Stop'
                }
                if ($Credential) {
                    $WMIRegParams.Add('Credential', $Credential)
                }
                
                $RegItems = Get-WmiObject @WMIRegParams
                $SubKeys = $RegItems.EnumKey(2147483650, $Path).sNames
                
                foreach ($SubKey in $SubKeys) {
                    $DisplayName = ($RegItems.GetStringValue(2147483650, "$Path\$SubKey", "DisplayName")).sValue
                    $Version = ($RegItems.GetStringValue(2147483650, "$Path\$SubKey", "DisplayVersion")).sValue
                    $Publisher = ($RegItems.GetStringValue(2147483650, "$Path\$SubKey", "Publisher")).sValue
                    $InstallDate = ($RegItems.GetStringValue(2147483650, "$Path\$SubKey", "InstallDate")).sValue
                    
                    if ($DisplayName) {
                        $Software += New-Object PSObject -Property @{
                            Name = $DisplayName
                            Version = $Version
                            Vendor = $Publisher
                            InstallDate = $InstallDate
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to read registry on $ComputerName : $_"
        }
    }
    
    return $Software | Sort-Object Name -Unique
}

Function Test-Connectivity {
    param($ComputerName)
    
    if ($ComputerName -eq $env:COMPUTERNAME) {
        return $true
    }
    
    try {
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        return $ping
    } catch {
        return $false
    }
}

Function Get-SafeWMIObject {
    param(
        [string]$ComputerName,
        [string]$Class,
        [string]$Query
    )
    
    $LocalWMIParams = @{
        ErrorAction = 'Stop'
        ComputerName = $ComputerName
    }
    
    if ($Credential) {
        $LocalWMIParams.Add('Credential', $Credential)
    }
    
    try {
        if ($Query) {
            Get-WmiObject -Query $Query @LocalWMIParams
        } else {
            Get-WmiObject -Class $Class @LocalWMIParams
        }
    } catch {
        Write-Warning "WMI query failed on $ComputerName for $Class : $_"
        return $null
    }
}

# Main script starts here
if ($AuditList -eq ""){
	Write-Host "No list specified, using $env:computername"
	$targets = @($env:computername)
}
else
{
	if ((Test-Path $AuditList) -eq $false)
	{
		Write-Host "Invalid audit path specified: $AuditList"
		exit
	}
	else
	{
		Write-Host "Using Audit list: $AuditList"
		$Targets = Get-Content $AuditList
	}
}

$TotalTargets = $Targets.Count
$CurrentTarget = 0

Foreach ($Target in $Targets){
    $CurrentTarget++
    Write-Progress -Activity "Auditing Systems" -Status "Processing $Target" -PercentComplete (($CurrentTarget/$TotalTargets)*100)
    
    Write-Output "Testing connectivity to $Target"
    if (-not (Test-Connectivity $Target)) {
        Write-Warning "$Target is not reachable. Skipping..."
        continue
    }
    
    # Initialize report
    $MyReport = Get-CustomHTML "$Target Audit"
    
    # Initialize summary variables
    $SummaryData = @{
        TotalErrors = 0
        TotalWarnings = 0
        CriticalServices = 0
        DiskSpaceWarnings = 0
        Success = $true
    }
    
    Write-Output "Collecting basic information for $Target"
    
    try {
        $ComputerSystem = Get-SafeWMIObject -ComputerName $Target -Class "Win32_ComputerSystem"
        
        if ($ComputerSystem) {
            switch ($ComputerSystem.DomainRole){
                0 { $ComputerRole = "Standalone Workstation" }
                1 { $ComputerRole = "Member Workstation" }
                2 { $ComputerRole = "Standalone Server" }
                3 { $ComputerRole = "Member Server" }
                4 { $ComputerRole = "Domain Controller" }
                5 { $ComputerRole = "Domain Controller" }
                default { $ComputerRole = "Information not available" }
            }
            
            $OperatingSystems = Get-SafeWMIObject -ComputerName $Target -Class "Win32_OperatingSystem"
            $TimeZone = Get-SafeWMIObject -ComputerName $Target -Class "Win32_Timezone"
            $Keyboards = Get-SafeWMIObject -ComputerName $Target -Class "Win32_Keyboard"
            $SchedTasks = Get-SafeWMIObject -ComputerName $Target -Class "Win32_ScheduledJob"
            $BootINI = $OperatingSystems.SystemDrive + "boot.ini"
            $RecoveryOptions = Get-SafeWMIObject -ComputerName $Target -Class "Win32_OSRecoveryConfiguration"
            
            switch ($ComputerRole){
                "Member Workstation" { $CompType = "Computer Domain"; break }
                "Domain Controller" { $CompType = "Computer Domain"; break }
                "Member Server" { $CompType = "Computer Domain"; break }
                default { $CompType = "Computer Workgroup"; break }
            }

            # Safely convert LastBootupTime
            try {
                $LBTime = $OperatingSystems.ConvertToDateTime($OperatingSystems.Lastbootuptime)
            } catch {
                $LBTime = "Unable to determine"
            }
            
            # Calculate memory in GB
            $MemoryGB = [math]::Round($ComputerSystem.TotalPhysicalMemory/1GB, 2)
            
            # Add Summary Section
            $MyReport += Get-CustomSummary
            
            # System Information Tab
            $MyReport += Get-CustomHeader0 "System Information"
                $MyReport += "<div class='section-header'>General Information</div>"
                $MyReport += Get-HTMLDetail "Computer Name" ($ComputerSystem.Name)
                $MyReport += Get-HTMLDetail "Computer Role" ($ComputerRole)
                $MyReport += Get-HTMLDetail $CompType ($ComputerSystem.Domain)
                $MyReport += Get-HTMLDetail "Operating System" ($OperatingSystems.Caption)
                $MyReport += Get-HTMLDetail "Service Pack" ($OperatingSystems.CSDVersion)
                $MyReport += Get-HTMLDetail "System Root" ($OperatingSystems.SystemDrive)
                $MyReport += Get-HTMLDetail "Manufacturer" ($ComputerSystem.Manufacturer)
                $MyReport += Get-HTMLDetail "Model" ($ComputerSystem.Model)
                $MyReport += Get-HTMLDetail "Number of Processors" ($ComputerSystem.NumberOfProcessors)
                $MyReport += Get-HTMLDetail "Memory" "$MemoryGB GB"
                $MyReport += Get-HTMLDetail "Registered User" ($ComputerSystem.PrimaryOwnerName)
                $MyReport += Get-HTMLDetail "Registered Organisation" ($OperatingSystems.Organization)
                $MyReport += Get-HTMLDetail "Last System Boot" ($LBTime)
                
                Write-Output "..Regional Options"
                $ObjKeyboards = $Keyboards
                $keyboardmap = @{
                "00000402" = "BG" 
                "00000404" = "CH" 
                "00000405" = "CZ" 
                "00000406" = "DK" 
                "00000407" = "GR" 
                "00000408" = "GK" 
                "00000409" = "US" 
                "0000040A" = "SP" 
                "0000040B" = "SU" 
                "0000040C" = "FR" 
                "0000040E" = "HU" 
                "0000040F" = "IS" 
                "00000410" = "IT" 
                "00000411" = "JP" 
                "00000412" = "KO" 
                "00000413" = "NL" 
                "00000414" = "NO" 
                "00000415" = "PL" 
                "00000416" = "BR" 
                "00000418" = "RO" 
                "00000419" = "RU" 
                "0000041A" = "YU" 
                "0000041B" = "SL" 
                "0000041C" = "US" 
                "0000041D" = "SV" 
                "0000041F" = "TR" 
                "00000422" = "US" 
                "00000423" = "US" 
                "00000424" = "YU" 
                "00000425" = "ET" 
                "00000426" = "US" 
                "00000427" = "US" 
                "00000804" = "CH" 
                "00000809" = "UK" 
                "0000080A" = "LA" 
                "0000080C" = "BE" 
                "00000813" = "BE" 
                "00000816" = "PO" 
                "00000C0C" = "CF" 
                "00000C1A" = "US" 
                "00001009" = "US" 
                "0000100C" = "SF" 
                "00001809" = "US" 
                "00010402" = "US" 
                "00010405" = "CZ" 
                "00010407" = "GR" 
                "00010408" = "GK" 
                "00010409" = "DV" 
                "0001040A" = "SP" 
                "0001040E" = "HU" 
                "00010410" = "IT" 
                "00010415" = "PL" 
                "00010419" = "RU" 
                "0001041B" = "SL" 
                "0001041F" = "TR" 
                "00010426" = "US" 
                "00010C0C" = "CF" 
                "00010C1A" = "US" 
                "00020408" = "GK" 
                "00020409" = "US" 
                "00030409" = "USL" 
                "00040409" = "USR" 
                "00050408" = "GK" 
                }
                
                if ($ObjKeyboards) {
                    $keyb = $keyboardmap.$($ObjKeyboards.Layout)
                    if (!$keyb) { $keyb = "Unknown" }
                } else {
                    $keyb = "Unable to determine"
                }
                
                $MyReport += "<div class='section-header'>Regional Settings</div>"
                $MyReport += Get-HTMLDetail "Time Zone" $(if($TimeZone){$TimeZone.Description}else{"Unable to determine"})
                $MyReport += Get-HTMLDetail "Country Code" ($OperatingSystems.Countrycode)
                $MyReport += Get-HTMLDetail "Locale" ($OperatingSystems.Locale)
                $MyReport += Get-HTMLDetail "Operating System Language" ($OperatingSystems.OSLanguage)
                $MyReport += Get-HTMLDetail "Keyboard Layout" ($keyb)
                
                if (-not $QuickScan) {
                    Write-Output "..Hotfix Information"
                    $colQuickFixes = Get-SafeWMIObject -ComputerName $Target -Class "Win32_QuickFixEngineering"
                    $MyReport += "<div class='section-header'>Installed Hotfixes</div>"
                    if ($colQuickFixes) {
                        $MyReport += Get-HTMLTable ($colQuickFixes | Where {$_.HotFixID -ne "File 1" } | Select HotFixID, Description)
                    } else {
                        $MyReport += "<p>Unable to retrieve hotfix information</p>"
                    }
                }
            $MyReport += Get-CustomHeader0Close
            
            # Hardware Tab
            $MyReport += Get-CustomHeader0 "Hardware"
                Write-Output "..Logical Disks"
                $Disks = Get-SafeWMIObject -ComputerName $Target -Class "Win32_LogicalDisk"
                $MyReport += "<div class='section-header'>Logical Disk Configuration</div>"
                
                if ($Disks) {
                    $LogicalDrives = @()
                    Foreach ($LDrive in ($Disks | Where {$_.DriveType -eq 3})){
                        $Details = "" | Select "Drive Letter", Label, "File System", "Disk Size (GB)", "Disk Free Space (GB)", "% Free Space"
                        $Details."Drive Letter" = $LDrive.DeviceID
                        $Details.Label = $LDrive.VolumeName
                        $Details."File System" = $LDrive.FileSystem
                        $Details."Disk Size (GB)" = [math]::round(($LDrive.size / 1GB), 2)
                        $Details."Disk Free Space (GB)" = [math]::round(($LDrive.FreeSpace / 1GB), 2)
                        $PercentFree = [Math]::Round(($LDrive.FreeSpace / $LDrive.Size) * 100, 2)
                        $Details."% Free Space" = $PercentFree
                        
                        # Check for low disk space
                        if ($PercentFree -lt 10) {
                            $SummaryData.DiskSpaceWarnings++
                            $Details."% Free Space" = "<span class='error'>$PercentFree</span>"
                        } elseif ($PercentFree -lt 20) {
                            $Details."% Free Space" = "<span class='warning'>$PercentFree</span>"
                        }
                        
                        $LogicalDrives += $Details
                    }
                    $MyReport += Get-HTMLTable ($LogicalDrives)
                } else {
                    $MyReport += "<p class='error-notice'>Unable to retrieve disk information</p>"
                }
                
                Write-Output "..Printers"
                $InstalledPrinters = Get-SafeWMIObject -ComputerName $Target -Class "Win32_Printer"
                $MyReport += "<div class='section-header'>Installed Printers</div>"
                if ($InstalledPrinters) {
                    $MyReport += Get-HTMLTable ($InstalledPrinters | Select Name, Location)
                } else {
                    $MyReport += "<p>No printers found or unable to retrieve printer information</p>"
                }
            $MyReport += Get-CustomHeader0Close
            
            # Network Tab
            $MyReport += Get-CustomHeader0 "Network"
                Write-Output "..Network Configuration"
                $Adapters = Get-SafeWMIObject -ComputerName $Target -Class "Win32_NetworkAdapterConfiguration"
                $MyReport += "<div class='section-header'>Network Interface Configuration</div>"
                
                if ($Adapters) {
                    $IPInfo = @()
                    Foreach ($Adapter in ($Adapters | Where {$_.IPEnabled -eq $True})) {
                        $Details = "" | Select Description, "Physical address", "IP Address / Subnet Mask", "Default Gateway", "DHCP Enabled", DNS, WINS
                        $Details.Description = "$($Adapter.Description)"
                        $Details."Physical address" = "$($Adapter.MACaddress)"
                        If ($Adapter.IPAddress -ne $Null) {
                            $Details."IP Address / Subnet Mask" = "$($Adapter.IPAddress)/$($Adapter.IPSubnet)"
                            $Details."Default Gateway" = "$($Adapter.DefaultIPGateway)"
                        }
                        If ($Adapter.DHCPEnabled -eq "True") {
                            $Details."DHCP Enabled" = "Yes"
                        } Else {
                            $Details."DHCP Enabled" = "No"
                        }
                        If ($Adapter.DNSServerSearchOrder -ne $Null) {
                            $Details.DNS = "$($Adapter.DNSServerSearchOrder)"
                        }
                        $Details.WINS = "$($Adapter.WINSPrimaryServer) $($Adapter.WINSSecondaryServer)"
                        $IPInfo += $Details
                    }
                    $MyReport += Get-HTMLTable ($IPInfo)
                } else {
                    $MyReport += "<p class='error-notice'>Unable to retrieve network configuration</p>"
                }
                
                Write-Output "..Local Shares"
                $Shares = Get-SafeWMIObject -ComputerName $Target -Class "Win32_Share"
                $MyReport += "<div class='section-header'>Local Shares</div>"
                if ($Shares) {
                    $MyReport += Get-HTMLTable ($Shares | Select Name, Path, Caption)
                } else {
                    $MyReport += "<p>Unable to retrieve share information</p>"
                }
            $MyReport += Get-CustomHeader0Close
            
            # Software Tab
            $MyReport += Get-CustomHeader0 "Software"
                if (-not $QuickScan) {
                    Write-Output "..Software (Using Registry Method)"
                    $MyReport += "<div class='section-header'>Installed Software</div>"
                    
                    $Software = Get-RegistrySoftware -ComputerName $Target
                    if ($Software -and $Software.Count -gt 0) {
                        $MyReport += Get-HTMLTable ($Software | Select Name, Version, Vendor, InstallDate)
                    } else {
                        # Fallback to Win32_Product if registry method fails
                        Write-Output "..Falling back to WMI method"
                        if ((Get-SafeWMIObject -ComputerName $Target -Query "SELECT * FROM Win32_Product WHERE Name = 'dummy'") -ne $null) {
                            Write-Output "..Software (WMI)"
                            $Products = Get-SafeWMIObject -ComputerName $Target -Class "Win32_Product"
                            if ($Products) {
                                $MyReport += Get-HTMLTable ($Products | Select Name, Version, Vendor, InstallDate)
                            } else {
                                $MyReport += "<p>No software information available</p>"
                            }
                        } else {
                            $MyReport += "<p>Software information not available (WMI class not installed)</p>"
                        }
                    }
                } else {
                    $MyReport += "<div class='section-header'>Installed Software</div>"
                    $MyReport += "<p>Software scan skipped (Quick Scan mode)</p>"
                }
            $MyReport += Get-CustomHeader0Close
            
            # Services Tab
            $MyReport += Get-CustomHeader0 "Services"
                Write-Output "..Services"
                $ListOfServices = Get-SafeWMIObject -ComputerName $Target -Class "Win32_Service"
                $MyReport += "<div class='section-header'>Windows Services</div>"
                
                if ($ListOfServices) {
                    $Services = @()
                    Foreach ($Service in $ListOfServices){
                        $Details = "" | Select Name, Account, "Start Mode", State, "Expected State"
                        $Details.Name = $Service.Caption
                        $Details.Account = $Service.Startname
                        $Details."Start Mode" = $Service.StartMode
                        
                        If ($Service.StartMode -eq "Auto") {
                            if ($Service.State -eq "Stopped") {
                                $Details.State = "<span class='error'>$($Service.State)</span>"
                                $Details."Expected State" = "<span class='error'>Unexpected</span>"
                                $SummaryData.CriticalServices++
                            } else {
                                $Details.State = $Service.State
                                $Details."Expected State" = "<span class='ok'>OK</span>"
                            }
                        } ElseIf ($Service.StartMode -eq "Disabled") {
                            If ($Service.State -eq "Running") {
                                $Details.State = "<span class='warning'>$($Service.State)</span>"
                                $Details."Expected State" = "<span class='warning'>Unexpected</span>"
                            } else {
                                $Details.State = $Service.State
                                $Details."Expected State" = "<span class='ok'>OK</span>"
                            }
                        } Else {
                            $Details.State = $Service.State
                            $Details."Expected State" = "<span class='ok'>OK</span>"
                        }
                        
                        $Services += $Details
                    }
                    $MyReport += Get-HTMLTable ($Services)
                } else {
                    $MyReport += "<p class='error-notice'>Unable to retrieve service information</p>"
                    $SummaryData.Success = $false
                }
            $MyReport += Get-CustomHeader0Close
            
            # Event Logs Tab
            $MyReport += Get-CustomHeader0 "Event Logs"
                Write-Output "..Event Log Settings"
                $LogFiles = Get-SafeWMIObject -ComputerName $Target -Class "Win32_NTEventLogFile"
                $MyReport += "<div class='section-header'>Event Log Settings</div>"
                
                if ($LogFiles) {
                    $LogSettings = @()
                    Foreach ($Log in $LogFiles){
                        $Details = "" | Select "Log Name", "Overwrite Outdated Records", "Maximum Size (KB)", "Current Size (KB)", "% Used"
                        $Details."Log Name" = $Log.LogFileName
                        If ($Log.OverWriteOutdated -lt 0) {
                            $Details."Overwrite Outdated Records" = "Never"
                        } elseif ($Log.OverWriteOutdated -eq 0) {
                            $Details."Overwrite Outdated Records" = "As needed"
                        } Else {
                            $Details."Overwrite Outdated Records" = "After $($Log.OverWriteOutdated) days"
                        }
                        $MaxFileSize = [math]::Round(($Log.MaxFileSize) / 1024, 2)
                        $FileSize = [math]::Round(($Log.FileSize) / 1024, 2)
                        $PercentUsed = [math]::Round(($FileSize / $MaxFileSize) * 100, 2)
                        
                        $Details."Maximum Size (KB)" = $MaxFileSize
                        $Details."Current Size (KB)" = $FileSize
                        
                        if ($PercentUsed -gt 90) {
                            $Details."% Used" = "<span class='error'>$PercentUsed%</span>"
                        } elseif ($PercentUsed -gt 75) {
                            $Details."% Used" = "<span class='warning'>$PercentUsed%</span>"
                        } else {
                            $Details."% Used" = "$PercentUsed%"
                        }
                        
                        $LogSettings += $Details
                    }
                    $MyReport += Get-HTMLTable ($LogSettings)
                } else {
                    $MyReport += "<p class='error-notice'>Unable to retrieve event log settings</p>"
                }
                
                if (-not $QuickScan) {
                    Write-Output "..Event Log Errors (Limited to $MaxEvents entries)"
                    $WmidtQueryDT = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime([DateTime]::Now.AddDays(-14))
                    $ErrorQuery = "Select * from Win32_NTLogEvent Where Type='Error' and TimeWritten >='" + $WmidtQueryDT + "'"
                    $LoggedErrors = Get-SafeWMIObject -ComputerName $Target -Query $ErrorQuery
                    
                    $MyReport += "<div class='section-header'>Error Events (Last 14 Days - Maximum $MaxEvents shown)</div>"
                    if ($LoggedErrors) {
                        $ErrorCount = @($LoggedErrors).Count
                        $SummaryData.TotalErrors = $ErrorCount
                        
                        if ($ErrorCount -gt $MaxEvents) {
                            $MyReport += "<p class='warning-notice'>Found $ErrorCount error events. Showing first $MaxEvents events.</p>"
                            $LoggedErrors = $LoggedErrors | Select -First $MaxEvents
                        }
                        
                        $MyReport += Get-HTMLTable ($LoggedErrors | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
                    } else {
                        $MyReport += "<p>No error events found in the last 14 days</p>"
                    }
                    
                    Write-Output "..Event Log Warnings (Limited to $MaxEvents entries)"
                    $WarningQuery = "Select * from Win32_NTLogEvent Where Type='Warning' and TimeWritten >='" + $WmidtQueryDT + "'"
                    $LoggedWarning = Get-SafeWMIObject -ComputerName $Target -Query $WarningQuery
                    
                    $MyReport += "<div class='section-header'>Warning Events (Last 14 Days - Maximum $MaxEvents shown)</div>"
                    if ($LoggedWarning) {
                        $WarningCount = @($LoggedWarning).Count
                        $SummaryData.TotalWarnings = $WarningCount
                        
                        if ($WarningCount -gt $MaxEvents) {
                            $MyReport += "<p class='warning-notice'>Found $WarningCount warning events. Showing first $MaxEvents events.</p>"
                            $LoggedWarning = $LoggedWarning | Select -First $MaxEvents
                        }
                        
                        $MyReport += Get-HTMLTable ($LoggedWarning | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
                    } else {
                        $MyReport += "<p>No warning events found in the last 14 days</p>"
                    }
                } else {
                    $MyReport += "<p>Event log analysis skipped (Quick Scan mode)</p>"
                }
            $MyReport += Get-CustomHeader0Close
            
            # Network Connections Tab
            if (-not $SkipNetworkConnections) {
                $MyReport += Get-CustomHeader0 "Network Connections"
                Write-Output "..Network Connections"
                
                if ($Target -eq $env:COMPUTERNAME) {
                    # Local computer - can run netstat
                    try {
                        $netstatOutput = & netstat -an 2>&1
                        
                        if ($LASTEXITCODE -eq 0) {
                            # Parse netstat output with improved parsing
                            $Connections = @()
                            $ListeningPorts = @()
                            $isDataSection = $false
                            
                            foreach ($line in $netstatOutput) {
                                if ($line -match "^\s*$") { continue }
                                
                                # Look for the header line to know when data starts
                                if ($line -match "Proto.*Local.*Foreign.*State") {
                                    $isDataSection = $true
                                    continue
                                }
                                
                                if ($isDataSection) {
                                    # Improved regex patterns for different formats
                                    $patterns = @(
                                        '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\S+)\s*(.*)$',
                                        '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+):(\S+)$',
                                        '^\s*(TCP|UDP)\s+(\S+):(\d+)\s+(\S+)$'
                                    )
                                    
                                    $matched = $false
                                    foreach ($pattern in $patterns) {
                                        if ($line -match $pattern) {
                                            $matched = $true
                                            $protocol = $matches[1]
                                            $localAddress = $matches[2]
                                            $localPort = $matches[3]
                                            
                                            if ($matches.Count -ge 5) {
                                                $foreignAddress = $matches[4]
                                                $foreignPort = if ($matches[5] -match '^\d+$') { $matches[5] } else { "*" }
                                                $state = if ($matches.Count -ge 7) { $matches[6].Trim() } else { "N/A" }
                                            } else {
                                                $foreignAddress = "*"
                                                $foreignPort = "*"
                                                $state = if ($matches.Count -ge 5) { $matches[4].Trim() } else { "N/A" }
                                            }
                                            
                                            # Process listening ports
                                            if ($state -eq "LISTENING" -or ($protocol -eq "UDP" -and $foreignAddress -eq "*")) {
                                                $Details = "" | Select Protocol, "Local Address", Port, "Service Name"
                                                $Details.Protocol = $protocol
                                                $Details."Local Address" = $localAddress
                                                $Details.Port = $localPort
                                                
                                                # Map port to service
                                                $serviceName = switch ([int]$localPort) {
                                                    80 { "HTTP" }
                                                    443 { "HTTPS" }
                                                    445 { "SMB/CIFS" }
                                                    135 { "RPC Endpoint Mapper" }
                                                    139 { "NetBIOS Session" }
                                                    3389 { "Remote Desktop" }
                                                    22 { "SSH" }
                                                    21 { "FTP" }
                                                    25 { "SMTP" }
                                                    110 { "POP3" }
                                                    143 { "IMAP" }
                                                    53 { "DNS" }
                                                    88 { "Kerberos" }
                                                    389 { "LDAP" }
                                                    636 { "LDAPS" }
                                                    1433 { "SQL Server" }
                                                    3306 { "MySQL" }
                                                    5985 { "WinRM HTTP" }
                                                    5986 { "WinRM HTTPS" }
                                                    default { 
                                                        if ([int]$localPort -ge 49152 -and [int]$localPort -le 65535) {
                                                            "Dynamic/Private Port"
                                                        } else {
                                                            "Unknown"
                                                        }
                                                    }
                                                }
                                                $Details."Service Name" = $serviceName
                                                
                                                $ListeningPorts += $Details
                                            }
                                            # Process active connections
                                            elseif ($foreignAddress -ne "0.0.0.0" -and $foreignAddress -ne "*" -and $foreignAddress -ne "[::]") {
                                                $Details = "" | Select Protocol, "Local Address", "Local Port", "Remote Address", "Remote Port", State, "Service Name"
                                                $Details.Protocol = $protocol
                                                $Details."Local Address" = $localAddress
                                                $Details."Local Port" = $localPort
                                                $Details."Remote Address" = $foreignAddress
                                                $Details."Remote Port" = $foreignPort
                                                $Details.State = if ($state) { $state } else { "N/A" }
                                                
                                                # Map common ports to services
                                                $serviceName = switch ([int]$foreignPort) {
                                                    80 { "HTTP" }
                                                    443 { "HTTPS" }
                                                    445 { "SMB" }
                                                    135 { "RPC" }
                                                    139 { "NetBIOS" }
                                                    3389 { "RDP" }
                                                    22 { "SSH" }
                                                    default { "Unknown" }
                                                }
                                                $Details."Service Name" = $serviceName
                                                
                                                $Connections += $Details
                                            }
                                            
                                            break
                                        }
                                    }
                                }
                            }
                            
                            $MyReport += "<div class='section-header'>Active Network Connections</div>"
                            if ($Connections.Count -gt 0) {
                                $MyReport += Get-HTMLTable ($Connections | Sort-Object Protocol, "Remote Address", "Remote Port")
                            } else {
                                $MyReport += "<p>No active network connections found</p>"
                            }
                            
                            $MyReport += "<div class='section-header'>Listening Ports</div>"
                            if ($ListeningPorts.Count -gt 0) {
                                $MyReport += Get-HTMLTable ($ListeningPorts | Sort-Object Protocol, {[int]$_.Port} -Unique)
                            } else {
                                $MyReport += "<p>No listening ports found</p>"
                            }
                        } else {
                            $MyReport += "<p class='error-notice'>Failed to run netstat command</p>"
                        }
                    } catch {
                        $MyReport += "<p class='error-notice'>Error retrieving network connections: $_</p>"
                    }
                } else {
                    # Remote computer - cannot run netstat
                    $MyReport += "<div class='section-header'>Network Connections</div>"
                    $MyReport += "<p class='warning-notice'>Network connection details are only available when auditing the local computer</p>"
                }
                
                $MyReport += Get-CustomHeader0Close
            }
            
            # Add summary items at the end
            $MyReport += Add-SummaryItem -Label "System Status" -Value $(if($SummaryData.Success){"OK"}else{"Issues Found"}) -Status $(if($SummaryData.Success){"ok"}else{"error"})
            $MyReport += Add-SummaryItem -Label "Event Errors" -Value $SummaryData.TotalErrors -Status $(if($SummaryData.TotalErrors -gt 100){"error"}elseif($SummaryData.TotalErrors -gt 50){"warning"}else{"ok"})
            $MyReport += Add-SummaryItem -Label "Event Warnings" -Value $SummaryData.TotalWarnings -Status $(if($SummaryData.TotalWarnings -gt 200){"warning"}else{"ok"})
            $MyReport += Add-SummaryItem -Label "Service Issues" -Value $SummaryData.CriticalServices -Status $(if($SummaryData.CriticalServices -gt 0){"error"}else{"ok"})
            $MyReport += Add-SummaryItem -Label "Low Disk Space" -Value $SummaryData.DiskSpaceWarnings -Status $(if($SummaryData.DiskSpaceWarnings -gt 0){"error"}else{"ok"})
            
        } else {
            $MyReport += "<p class='error-notice'>Failed to retrieve basic system information from $Target</p>"
        }
        
    } catch {
        Write-Error "Critical error auditing $Target : $_"
        $MyReport += "<p class='error-notice'>Critical error occurred while auditing this system: $_</p>"
    }
    
    $MyReport += Get-CustomHTMLClose

    $Date = Get-Date
    $Filename = ".\" + $Target + "_" + $date.Hour + $date.Minute + "_" + $Date.Day + "-" + $Date.Month + "-" + $Date.Year + ".htm"
    
    try {
        $MyReport | out-file -encoding ASCII -filepath $Filename
        Write-Host "Audit saved as $Filename" -ForegroundColor Green
    } catch {
        Write-Error "Failed to save report: $_"
    }
}

Write-Progress -Activity "Auditing Systems" -Completed
Write-Host "`nAudit complete!" -ForegroundColor Green