<# 14.12.2022 Eike Doose / INTERNAL USER ONLY / do not distribute
Install-Starke-DMS_00.ps1 basic settings and OS update
=========================================================================================

-FTPserver   # specify the FTP server which will be used for downloading the software / e.g. -FTPserver 'ftp.get--it.de'
-FTPuser     # name the FTP server user for logging into the FTP server / e.g. -FTPuser 'username'
-FTPpass     # password for logging into the FTP server / e.g. -FTPpass 'verysecretpassword'
-customerno  # client customer number which is needed for naming the new server and the database creation / e.g. -customerno '23545'

-FTP         # add with "no" for not installing the FTP feature - mainly for testing / -FTP 'no'
-UPDATE      # add with "no" for not installing Windows update - mainly for testing / -UPDATES 'no'
-ADMINUPDATE # add with "no" for not performing admin user name and password change - mainly for testing / -ADMINUPDATE 'no'
#>

#######################################
## command line parameter definition 
#######################################

param (
	[Parameter(Mandatory=$true)][string]$customerno,

	[string]$FTPbasic = 'yes',
	[string]$UPDATE = 'yes'
)


################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


################################################
## functions for the script
################################################

function PrintJobToDo($PrintJobToDoValue){
Write-Host @("`n`r `n`r
-------------------------------------------------------------------
  ____  _             _              ____  __  __ ____             
 / ___|| |_ __ _ _ __| | _____      |  _ \|  \/  / ___|            
 \___ \| __/ _´ | ´__| |/ / _ \     | | | | |\/| \___ \            
  ___) | || (_| | |  |   <  __/_____| |_| | |  | |___) |           
 |____/ \__\__,_|_|  |_|\_\___|     |____/|_|  |_|____/            
   ____ _                 _   ___           _        _ _           
  / ___| | ___  _   _  __| | |_ _|_ __  ___| |_ __ _| | | ___ _ __ 
 | |   | |/ _ \| | | |/ _´ |  | || ´_ \/ __| __/ _´ | | |/ _ \ ´__|
 | |___| | (_) | |_| | (_| |  | || | | \__ \ || (_| | | |  __/ |   
  \____|_|\___/ \__,_|\__,_| |___|_| |_|___/\__\__,_|_|_|\___|_|   
                                                                   
-------------------------------------------------------------------

==> $PrintJobToDoValue

-------------------------------------------------------------------`n`r `n`r
") -ForegroundColor Yellow
}

function PrintJobDone($PrintJobDoneValue){
Write-Host @("`n`r `n`r
-------------------------------------------------------------------
  ____  _             _              ____  __  __ ____             
 / ___|| |_ __ _ _ __| | _____      |  _ \|  \/  / ___|            
 \___ \| __/ _´ | ´__| |/ / _ \     | | | | |\/| \___ \            
  ___) | || (_| | |  |   <  __/_____| |_| | |  | |___) |           
 |____/ \__\__,_|_|  |_|\_\___|     |____/|_|  |_|____/            
   ____ _                 _   ___           _        _ _           
  / ___| | ___  _   _  __| | |_ _|_ __  ___| |_ __ _| | | ___ _ __ 
 | |   | |/ _ \| | | |/ _´ |  | || ´_ \/ __| __/ _´ | | |/ _ \ ´__|
 | |___| | (_) | |_| | (_| |  | || | | \__ \ || (_| | | |  __/ |   
  \____|_|\___/ \__,_|\__,_| |___|_| |_|___/\__\__,_|_|_|\___|_|   
                                                                   
-------------------------------------------------------------------

==> $PrintJobDoneValue

-------------------------------------------------------------------`n`r `n`r
") -ForegroundColor Green
}

function PrintJobError($PrintJobErrorValue){
Write-Host @("`n`r `n`r
-------------------------------------------------------------------
  ____  _             _              ____  __  __ ____             
 / ___|| |_ __ _ _ __| | _____      |  _ \|  \/  / ___|            
 \___ \| __/ _´ | ´__| |/ / _ \     | | | | |\/| \___ \            
  ___) | || (_| | |  |   <  __/_____| |_| | |  | |___) |           
 |____/ \__\__,_|_|  |_|\_\___|     |____/|_|  |_|____/            
   ____ _                 _   ___           _        _ _           
  / ___| | ___  _   _  __| | |_ _|_ __  ___| |_ __ _| | | ___ _ __ 
 | |   | |/ _ \| | | |/ _´ |  | || ´_ \/ __| __/ _´ | | |/ _ \ ´__|
 | |___| | (_) | |_| | (_| |  | || | | \__ \ || (_| | | |  __/ |   
  \____|_|\___/ \__,_|\__,_| |___|_| |_|___/\__\__,_|_|_|\___|_|   
                                                                   
-------------------------------------------------------------------

==> $PrintJobErrorValue

-------------------------------------------------------------------`n`r `n`r
") -ForegroundColor Red
}


################################################
## intro and countdown
################################################

Clear-Host []
PrintJobToDo "Starke-DMS® unattended install part 1 of 3"
Start-Sleep -s 3
Clear-Host []


#######################################
## generate timestamp
#######################################

$t=(get-date -format "yyyy-MM-dd_HH-mm-ss")
Start-Sleep -s 1


######################################
## Parameter for FTP server install ##
######################################

$FTPsiteFull = "IIS:\Sites\FTP-Site01"
$FTPsiteShort = "FTP-Site01"
$FTPsitePath = "d:\dms-data\file-exchange\FTP-Site01"
$FTPuserName = "SDMSC1-FTP01-"+$customerno
$FTPgroup = "FTPGroup"


################################################
## start logging 
################################################

Start-Transcript -Path "c:\install\_Log-Install-Starke-DMS_00-$t.txt" 
Start-Sleep -s 2

################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


################################################
################################################
## let's beginn
################################################
################################################

PrintJobToDo "set default OS settings"
Start-Sleep -s 1


##################################################
## disable autostart of Windows server-manager
##################################################

Invoke-Command -ComputerName localhost -ScriptBlock { New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value "0x1" –Force} 


##################################################
## basic explorer settings
##################################################

# "file extension on"
Set-ItemProperty -Type DWord -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -value "0"

# "menus always on"
Set-ItemProperty -Type DWord -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "AlwaysShowMenus" -value "1"

# "show status bar"
Set-ItemProperty -Type DWord -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -value "1"

# show full path"
# Set-ItemProperty -Type DWord -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -value "1"

# "show all folder"
Set-ItemProperty -Type DWord -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneShowAllFolders" -value "1"

# "expand path"
Set-ItemProperty -Type DWord -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "NavPaneExpandToCurrentFolder" -value "1"


##################################################
## set language to de-DE
##################################################

Set-WinUILanguageOverride -Language de-DE
Set-Culture de-DE
Set-WinUserLanguageList de-DE -Force


################################################
## rename computer to $customerno
################################################

Rename-Computer -NewName SDMSC1-$customerno


################################################
## terracloud standard server with two hdd+dvd
## dvd is drive d: and second hdd is e: 
## must be second hdd d: and dvd e:
## change DVD drive temporaly letter to O:
################################################

Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' |
  Select-Object -First 1 |
  Set-WmiInstance -Arguments @{DriveLetter='O:'}

$Drive = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'E:'"
$Drive | Set-CimInstance -Property @{DriveLetter ='D:'}

Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' |
  Select-Object -First 1 |
  Set-WmiInstance -Arguments @{DriveLetter='E:'}

# label c: to "OS", d: to "data"
$Drive = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'C:'"
$Drive | Set-CimInstance -Property @{Label='OS'}
Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'C:'" |
  Select-Object -Property SystemName, Label, DriveLetter

$Drive = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'D:'"
$Drive | Set-CimInstance -Property @{Label='DATA'}
Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter = 'D:'" |
  Select-Object -Property SystemName, Label, DriveLetter

PrintJobDone "default OS settings done"


################################################
## create media structure
################################################
PrintJobToDo "creating media structur"

New-Item -Path "d:\" -Name "dms-data" -ItemType "directory"
New-Item -Path "d:\" -Name "dms-config" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "documents" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "mail" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "pdf-converted" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "pool" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "preview" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "backup" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "sql" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "ftp-log" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "file-exchange" -ItemType "directory"
New-Item -Path "d:\dms-data\file-exchange" -Name "_FileImportSuccess" -ItemType "directory"
New-Item -Path "d:\dms-data\file-exchange" -Name "_FileImportError" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "web-logs" -ItemType "directory"
New-Item -Path "d:\dms-data\backup" -Name "sql" -ItemType "directory"
New-Item -Path "d:\" -Name "tools" -ItemType "directory"
New-Item -Path "d:\tools" -Name "ansible" -ItemType "directory"

PrintJobDone "media structur created"


################################################
## install FTP server
################################################

if($FTPbasic -eq "yes"){
	PrintJobToDo "installing FTP server basics"

	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
	Start-Sleep -s 3
	Install-WindowsFeature Web-Ftp-Server -IncludeAllSubFeature -IncludeManagementTools
	Start-Sleep -s 3
	Install-Module -Name IISAdministration -force
	Start-Sleep -s 3
	Import-Module ServerManager
	Start-Sleep -s 2
	Add-WindowsFeature Web-Scripting-Tools
	Start-Sleep -s 2
	import-module WebAdministration

	PrintJobDone "FTP server basics installed "

}else {
	PrintJobError "FTP server basics not installed"
	Start-Sleep -s 3
}


################################################
## install updates
################################################

if($UPDATE -eq "yes"){

	# Install all pending Updates and restart without asking
	PrintJobToDo "Install PSWindowsUpdate modul for PowerShell"
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
	Start-Sleep -s 2
	Install-Module -Name PSWindowsUpdate -Force
	Start-Sleep -s 2
	get-command -module PSWindowsUpdate
	Start-Sleep -s 2
	PrintJobDone "PSWindowsUpdate modul for PowerS installed"
	Start-Sleep -s 2
	Clear-Host []
	PrintJobToDo "Install all pending updates"
	Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot
	#Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
	PrintJobDone "all updates installed"
	Start-Sleep -s 3

}else {
	PrintJobError "Windows updates not installed"
	Start-Sleep -s 5
}


################################################
## restart computer
################################################
Clear-Host []
PrintJobToDo "Restart in 60s - press STRG-C to interrupt - continue with Install-Starke-DMS_01.ps1"
Start-Sleep -s 60

# stop-transcript / Transcript is broken if OS update installs PowerShell engine update - because of this the transcript stops before updating
Clear-Host []

Restart-computer -force