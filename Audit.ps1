#####################################################
#				                    #
#    Audit script V3 by Alan Renouf - Virtu-Al      #
#    Blog: http://virtu-al.net/	                    #
#	     		                            #
#    Usage: Audit.ps1 'pathtolistofservers'         #
# 			                            #
#    The file is optional and needs to be a 	    #
#	 plain text list of computers to be audited #
#	 one on each line, if no list is specified  #
#	 the local machine will be audited.         # 
#                                                   #
#####################################################

param( [string] $auditlist)

Function Get-CustomHTML ($Header){
$Report = @"
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Frameset//EN" "http://www.w3.org/TR/html4/frameset.dtd">
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
  color: #4caf50;
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
      <p><strong>Windows System Audit Report</strong> | Version 3 by Alan Renouf (virtu-al.net)</p>
      <p>Report created on $(Get-Date)</p>
    </div>
  </div>
  <div class="tab-navigation" id="tabNav">
  </div>
  <div class="save">
"@
Return $Report
}

Function Get-CustomHeader0 ($Title){
$Report = @"
    <script type="text/javascript">
    tabCounter++;
    var tabId = 'tab' + tabCounter;
    tabMap['$($Title)'] = tabId;
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

if ($auditlist -eq ""){
	Write-Host "No list specified, using $env:computername"
	$targets = $env:computername
}
else
{
	if ((Test-Path $auditlist) -eq $false)
	{
		Write-Host "Invalid audit path specified: $auditlist"
		exit
	}
	else
	{
		Write-Host "Using Audit list: $auditlist"
		$Targets = Get-Content $auditlist
	}
}

Foreach ($Target in $Targets){

Write-Output "Collating Detail for $Target"
	$ComputerSystem = Get-WmiObject -computername $Target Win32_ComputerSystem
	switch ($ComputerSystem.DomainRole){
		0 { $ComputerRole = "Standalone Workstation" }
		1 { $ComputerRole = "Member Workstation" }
		2 { $ComputerRole = "Standalone Server" }
		3 { $ComputerRole = "Member Server" }
		4 { $ComputerRole = "Domain Controller" }
		5 { $ComputerRole = "Domain Controller" }
		default { $ComputerRole = "Information not available" }
	}
	
	$OperatingSystems = Get-WmiObject -computername $Target Win32_OperatingSystem
	$TimeZone = Get-WmiObject -computername $Target Win32_Timezone
	$Keyboards = Get-WmiObject -computername $Target Win32_Keyboard
	$SchedTasks = Get-WmiObject -computername $Target Win32_ScheduledJob
	$BootINI = $OperatingSystems.SystemDrive + "boot.ini"
	$RecoveryOptions = Get-WmiObject -computername $Target Win32_OSRecoveryConfiguration
	
	switch ($ComputerRole){
		"Member Workstation" { $CompType = "Computer Domain"; break }
		"Domain Controller" { $CompType = "Computer Domain"; break }
		"Member Server" { $CompType = "Computer Domain"; break }
		default { $CompType = "Computer Workgroup"; break }
	}

	$LBTime=$OperatingSystems.ConvertToDateTime($OperatingSystems.Lastbootuptime)
	Write-Output "..Regional Options"
	$ObjKeyboards = Get-WmiObject -ComputerName $Target Win32_Keyboard
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
	$keyb = $keyboardmap.$($ObjKeyboards.Layout)
	if (!$keyb)
	{ $keyb = "Unknown"
	}
	$MyReport = Get-CustomHTML "$Target Audit"
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
		$MyReport += Get-HTMLDetail "Memory" ($ComputerSystem.TotalPhysicalMemory)
		$MyReport += Get-HTMLDetail "Registered User" ($ComputerSystem.PrimaryOwnerName)
		$MyReport += Get-HTMLDetail "Registered Organisation" ($OperatingSystems.Organization)
		$MyReport += Get-HTMLDetail "Last System Boot" ($LBTime)
		
		$MyReport += "<div class='section-header'>Regional Settings</div>"
		$MyReport += Get-HTMLDetail "Time Zone" ($TimeZone.Description)
		$MyReport += Get-HTMLDetail "Country Code" ($OperatingSystems.Countrycode)
		$MyReport += Get-HTMLDetail "Locale" ($OperatingSystems.Locale)
		$MyReport += Get-HTMLDetail "Operating System Language" ($OperatingSystems.OSLanguage)
		$MyReport += Get-HTMLDetail "Keyboard Layout" ($keyb)
		
		Write-Output "..Hotfix Information"
		$colQuickFixes = Get-WmiObject Win32_QuickFixEngineering
		$MyReport += "<div class='section-header'>Installed Hotfixes</div>"
		$MyReport += Get-HTMLTable ($colQuickFixes | Where {$_.HotFixID -ne "File 1" } |Select HotFixID, Description)
	$MyReport += Get-CustomHeader0Close
	# Hardware Tab
	$MyReport += Get-CustomHeader0 "Hardware"
		Write-Output "..Logical Disks"
		$Disks = Get-WmiObject -ComputerName $Target Win32_LogicalDisk
		$MyReport += "<div class='section-header'>Logical Disk Configuration</div>"
		$LogicalDrives = @()
		Foreach ($LDrive in ($Disks | Where {$_.DriveType -eq 3})){
			$Details = "" | Select "Drive Letter", Label, "File System", "Disk Size (MB)", "Disk Free Space", "% Free Space"
			$Details."Drive Letter" = $LDrive.DeviceID
			$Details.Label = $LDrive.VolumeName
			$Details."File System" = $LDrive.FileSystem
			$Details."Disk Size (MB)" = [math]::round(($LDrive.size / 1MB))
			$Details."Disk Free Space" = [math]::round(($LDrive.FreeSpace / 1MB))
			$Details."% Free Space" = [Math]::Round(($LDrive.FreeSpace /1MB) / ($LDrive.Size / 1MB) * 100)
			$LogicalDrives += $Details
		}
		$MyReport += Get-HTMLTable ($LogicalDrives)
		
		Write-Output "..Printers"
		$InstalledPrinters =  Get-WmiObject -ComputerName $Target Win32_Printer
		$MyReport += "<div class='section-header'>Installed Printers</div>"
		$MyReport += Get-HTMLTable ($InstalledPrinters | Select Name, Location)
	$MyReport += Get-CustomHeader0Close
	# Network Tab
	$MyReport += Get-CustomHeader0 "Network"
		Write-Output "..Network Configuration"
		$Adapters = Get-WmiObject -ComputerName $Target Win32_NetworkAdapterConfiguration
		$MyReport += "<div class='section-header'>Network Interface Configuration</div>"
		$IPInfo = @()
		Foreach ($Adapter in ($Adapters | Where {$_.IPEnabled -eq $True})) {
			$Details = "" | Select Description, "Physical address", "IP Address / Subnet Mask", "Default Gateway", "DHCP Enabled", DNS, WINS
			$Details.Description = "$($Adapter.Description)"
			$Details."Physical address" = "$($Adapter.MACaddress)"
			If ($Adapter.IPAddress -ne $Null) {
			$Details."IP Address / Subnet Mask" = "$($Adapter.IPAddress)/$($Adapter.IPSubnet)"
				$Details."Default Gateway" = "$($Adapter.DefaultIPGateway)"
			}
			If ($Adapter.DHCPEnabled -eq "True")	{
				$Details."DHCP Enabled" = "Yes"
			}
			Else {
				$Details."DHCP Enabled" = "No"
			}
			If ($Adapter.DNSServerSearchOrder -ne $Null)	{
				$Details.DNS =  "$($Adapter.DNSServerSearchOrder)"
			}
			$Details.WINS = "$($Adapter.WINSPrimaryServer) $($Adapter.WINSSecondaryServer)"
			$IPInfo += $Details
		}
		$MyReport += Get-HTMLTable ($IPInfo)
		
		Write-Output "..Local Shares"
		$Shares = Get-wmiobject -ComputerName $Target Win32_Share
		$MyReport += "<div class='section-header'>Local Shares</div>"
		$MyReport += Get-HTMLTable ($Shares | Select Name, Path, Caption)
	$MyReport += Get-CustomHeader0Close
	# Software Tab
	$MyReport += Get-CustomHeader0 "Software"
		If ((get-wmiobject -ComputerName $Target -namespace "root/cimv2" -list) | Where-Object {$_.name -match "Win32_Product"})
		{
			Write-Output "..Software"
			$MyReport += "<div class='section-header'>Installed Software</div>"
			$MyReport += Get-HTMLTable (get-wmiobject -ComputerName $Target Win32_Product | select Name,Version,Vendor,InstallDate)
		}
		Else {
			Write-Output "..Software WMI class not installed"
			$MyReport += "<div class='section-header'>Installed Software</div>"
			$MyReport += "<p>Software information not available (WMI class not installed)</p>"
		}
	$MyReport += Get-CustomHeader0Close
	# Services Tab
	$MyReport += Get-CustomHeader0 "Services"
		Write-Output "..Services"
		$ListOfServices = Get-WmiObject -ComputerName $Target Win32_Service
		$MyReport += "<div class='section-header'>Windows Services</div>"
		$Services = @()
		Foreach ($Service in $ListOfServices){
			$Details = "" | Select Name,Account,"Start Mode",State,"Expected State"
			$Details.Name = $Service.Caption
			$Details.Account = $Service.Startname
			$Details."Start Mode" = $Service.StartMode
			If ($Service.StartMode -eq "Auto")
				{
					if ($Service.State -eq "Stopped")
					{
						$Details.State = $Service.State
						$Details."Expected State" = "Unexpected"
					}
				}
				If ($Service.StartMode -eq "Auto")
				{
					if ($Service.State -eq "Running")
					{
						$Details.State = $Service.State
						$Details."Expected State" = "OK"
					}
				}
				If ($Service.StartMode -eq "Disabled")
				{
					If ($Service.State -eq "Running")
					{
						$Details.State = $Service.State
						$Details."Expected State" = "Unexpected"
					}
				}
				If ($Service.StartMode -eq "Disabled")
				{
					if ($Service.State -eq "Stopped")
					{
						$Details.State = $Service.State
						$Details."Expected State" = "OK"
					}
				}
				If ($Service.StartMode -eq "Manual")
				{
					$Details.State = $Service.State
					$Details."Expected State" = "OK"
				}
				If ($Service.State -eq "Paused")
				{
					$Details.State = $Service.State
					$Details."Expected State" = "OK"
				}
			$Services += $Details
		}
		$MyReport += Get-HTMLTable ($Services)
	$MyReport += Get-CustomHeader0Close
	
	# Event Logs Tab
	$MyReport += Get-CustomHeader0 "Event Logs"
		Write-Output "..Event Log Settings"
		$LogFiles = Get-WmiObject -ComputerName $Target Win32_NTEventLogFile
		$MyReport += "<div class='section-header'>Event Log Settings</div>"
		$LogSettings = @()
		Foreach ($Log in $LogFiles){
			$Details = "" | Select "Log Name", "Overwrite Outdated Records", "Maximum Size (KB)", "Current Size (KB)"
			$Details."Log Name" = $Log.LogFileName
			If ($Log.OverWriteOutdated -lt 0)
				{
					$Details."Overwrite Outdated Records" = "Never"
				}
			if ($Log.OverWriteOutdated -eq 0)
			{
				$Details."Overwrite Outdated Records" = "As needed"
			}
			Else
			{
				$Details."Overwrite Outdated Records" = "After $($Log.OverWriteOutdated) days"
			}
			$MaxFileSize = ($Log.MaxFileSize) / 1024
			$FileSize = ($Log.FileSize) / 1024
			
			$Details."Maximum Size (KB)" = $MaxFileSize
			$Details."Current Size (KB)" = $FileSize
			$LogSettings += $Details
		}
		$MyReport += Get-HTMLTable ($LogSettings)
		
		Write-Output "..Event Log Errors"
		$WmidtQueryDT = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime([DateTime]::Now.AddDays(-14))
		$LoggedErrors = Get-WmiObject -computer $Target -query ("Select * from Win32_NTLogEvent Where Type='Error' and TimeWritten >='" + $WmidtQueryDT + "'")
		$MyReport += "<div class='section-header'>Error Events (Last 14 Days)</div>"
		$MyReport += Get-HTMLTable ($LoggedErrors | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
		
		Write-Output "..Event Log Warnings"
		$WmidtQueryDT = [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime([DateTime]::Now.AddDays(-14))
		$LoggedWarning = Get-WmiObject -computer $Target -query ("Select * from Win32_NTLogEvent Where Type='Warning' and TimeWritten >='" + $WmidtQueryDT + "'")
		$MyReport += "<div class='section-header'>Warning Events (Last 14 Days)</div>"
		$MyReport += Get-HTMLTable ($LoggedWarning | Select EventCode, SourceName, @{N="Time";E={$_.ConvertToDateTime($_.TimeWritten)}}, LogFile, Message)
	$MyReport += Get-CustomHeader0Close
	
	$MyReport += Get-CustomHTMLClose

	$Date = Get-Date
	$Filename = ".\" + $Target + "_" + $date.Hour + $date.Minute + "_" + $Date.Day + "-" + $Date.Month + "-" + $Date.Year + ".htm"
	$MyReport | out-file -encoding ASCII -filepath $Filename
	Write "Audit saved as $Filename"
}
