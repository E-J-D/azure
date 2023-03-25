<# 24.03.2023 Eike Doose / INTERNAL USER ONLY / do not distribute
Install-Starke-DMS_00.ps1 basic settings and OS update
========================================================================================= #>

#######################################
## import parameter
#######################################

$configpath = 'c:\install\'
$configfile = 'Install-Starke-DMS_CONFIG.psd1'
$var = Import-LocalizedData -BaseDirectory $configpath -FileName $configfile

$FTPserver = $var.FTPserver
$FTPuser = $var.FTPuser
$FTPpass = $var.FTPpass
$LIZuser = $var.LIZuser
$LIZpass = $var.LIZpass
$LIZserver = $var.LIZserver
$saPass = $var.saPass
$customerno = $var.customerno
$LIZuid = $var.LIZuid
$UPDATE = $var.UPDATE
$FTP = $var.FTP
$FTPbasic = $var.FTP
$SSH = $var.SSH
$POWERSHELL7 = $var.POWERSHELL7
$ADMINUPDATE = $var.ADMINUPDATE
$PassAutoLogon = $var.PassAutoLogon
$MAILPASS = $var.MAILPASS
$ConsultantMailAddress = $var.ConsultantMailAddress
$Resellerclient = $var.Resellerclient

################################################
## delete my own task from task scheduler
################################################

Unregister-ScheduledTask -TaskName "run Install-Starke-DMS_00.ps1 at logon" -Confirm:$false


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

Start-Sleep -s 1


##################################################
## disable autostart of Windows server-manager
##################################################

PrintJobToDo "disable autostart of Windows Server Manager"
Invoke-Command -ComputerName localhost -ScriptBlock { New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value "0x1" –Force} 
PrintJobDone "autostart of Windows Server disabled"


##################################################
## basic explorer settings
##################################################

PrintJobToDo "set basic explorer settings"
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
PrintJobDone "basic explorer settings done"


##################################################
## set language to de-DE
##################################################

PrintJobToDo "set OS Language to GER"
Set-WinUILanguageOverride -Language de-DE
Set-Culture de-DE
Set-WinUserLanguageList de-DE -Force
PrintJobDone "OS language set to GER"


################################################
## rename computer to $customerno
################################################

PrintJobToDo "rename host"
Rename-Computer -NewName SDMSC1-$customerno
PrintJobDone "host renamend"


################################################
## terracloud standard server with two hdd+dvd
## dvd is drive d: and second hdd is e: 
## must be: second hdd d: and dvd e:
## change DVD drive temporaly letter to O:
################################################

PrintJobToDo "set default OS settings"

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
## create emergency admin user for rollout
## this user will be deleted automatically
## when rollout is complete
################################################

	PrintJobToDo "create rollout Admin user"
	New-LocalUser -Name "EmergencyAdmin" `
	-FullName "Emergency Admin" `
	-Description "Starke-DMS Cloud 1.0 Installer Emergency Admin" `
	-Password (ConvertTo-SecureString "3&K>g%4&=k_{N8Lt" -AsPlainText -Force) `
	-PasswordNeverExpires `
	-AccountNeverExpires 
	Add-LocalGroupMember -Group "Administratoren" -Member "EmergencyAdmin"
	PrintJobDone "rollout admin user created"


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

	# 25.12.2022 tried to fix "Install-Module -Name PSWindowsUpdate -Force" error
	# Get-PSRepository
	# [Net.ServicePoint.Manager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
	# [System.Net.WebRequest]::DefaultWebProxy = [System.Net.WebRequest]::GetSystemWebProxy()
	# [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
	# 
	# Install all pending Updates and restart without asking
	PrintJobToDo "Install PSWindowsUpdate modul for PowerShell"
	# https://petri.com/how-to-manage-windows-update-using-powershell/
	#$Updates = Start-WUScan -SearchCriteria "Type='Software' AND IsInstalled=0"
	#Install-WUUpdates -Updates $Updates
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
	Start-Sleep -s 5
	#egister-PSRepository -Default
	#tart-Sleep -s 3
	Install-Module -Name PSWindowsUpdate -Force
	Start-Sleep -s 3
	Get-Command -Module PSWindowsUpdate
	Start-Sleep -s 3
	PrintJobDone "PSWindowsUpdate modul for PowerShell installed"
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


#########################################################################
## create the windows task to run Install-Starke-DMS_01.ps1 at next logon
#########################################################################

	PrintJobToDo  "create task to continue the installation at next logon"

	[string]$TaskName = "run Install-Starke-DMS_01.ps1 at logon"
	[string]$TaskDescription = "This task will run once at startup / task created by Starke-DMS® cloud installer"
	[string]$TaskDir = "\Starke-DMS®"
	$TaskTrigger = New-ScheduledTaskTrigger -AtLogon
	$TaskAction = New-ScheduledTaskAction -WorkingDirectory c:\install -Execute "powershell" -Argument "-command C:\install\Install-Starke-DMS_01.ps1"
	$TaskSettings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
	$TaskUser = New-ScheduledTaskPrincipal -UserId "Administrator" -RunLevel Highest
	if (Get-ScheduledTask $TaskName -ErrorAction SilentlyContinue) {Unregister-ScheduledTask $TaskName}            
	Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskDir -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskUser -Settings $TaskSettings -Description $TaskDescription

	PrintJobDone "task to continue the installation is created"
	Start-Sleep -s 3

<#
################################################
## enable Adminstrator auto logon
################################################

$UserAutoLogon = 'Administrator'
$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$UserAutoLogon" -type String 
Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$PassAutoLogon" -type String
#>
 
################################################
## send e-mail to technical consultant
################################################

$mailpw = ConvertTo-SecureString -String $MAILPASS -AsPlainText -Force
$mailcred = New-Object System.Management.Automation.PSCredential "noreply@starke-dms.cloud", $mailpw
$mailbody = "Install-Starke-DMS_00.ps1 finished"
$mailsubject = "SDMS-C1-CloudInstaller notification / customer $customerno / Install-Starke-DMS_00.ps1 finished"
Send-MailMessage -Credential $mailcred -to $ConsultantMailAddress -from noreply@starke-dms.cloud -SMTPServer 'smtp.strato.com' -Port 587 -usessl -Subject $mailsubject -body $mailbody


################################################
## restart computer
################################################

Clear-Host []
stop-transcript
Clear-Host []

Restart-computer -force