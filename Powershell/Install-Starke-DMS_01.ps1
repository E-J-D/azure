<# 22.11.2022 Eike Doose / INTERNAL USER ONLY / do not distribute
Install-Starke-DMS_01.ps1 install PowerShell 7 which is needed for following installation
=========================================================================================

-FTPserver   # specify the FTP server which will be used for downloading the software / e.g. -FTPserver 'ftp.get--it.de'
-FTPuser     # name the FTP server user for logging into the FTP server / e.g. -FTPuser 'username'
-FTPpass     # password for logging into the FTP server / e.g. -FTPpass 'verysecretpassword'
-customerno  # client customer number which is needed for naming the new server and the database creation / e.g. -customerno '23545'

-POWERSHELL7 # add with "no" for not installing Powershell7 - mainly for testing / -POWERSHELL7 'no'
-FTP         # add with "no" for not installing the FTP feature - mainly for testing / -FTP 'no'
-UPDATE      # add with "no" for not installing Windows update - mainly for testing / -UPDATES 'no'
-ADMINUPDATE # add with "no" for not performing admin user name and password change - mainly for testing / -ADMINUPDATE 'no'


==> NFR environment
.\Install-Starke-DMS_01.ps1 -FTPserver 'ftp.get--it.de' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '50999'  
.\Install-Starke-DMS_01.ps1 -FTPserver 'ftp.get--it.de' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '56999'  
.\Install-Starke-DMS_01.ps1 -FTPserver 'ftp.get--it.de' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '57999'  
.\Install-Starke-DMS_01.ps1 -FTPserver '172.28.0.11' -FTPuser 'AUTOINSTALLER' -FTPpass 'wbutJzGFALFDrtmN' -customerno '57999'  

==> VMware lokal test environment (22.11.2022)
.\Install-Starke-DMS_01.ps1 -FTPserver '192.168.224.188' -FTPuser 'hausmeister' -FTPpass 'hausmeister' -customerno '36100'
#>

#######################################
## command line parameter definition 
#######################################

param (
	[string]$FTPserver = 'ftp.get--it.de',
	[Parameter(Mandatory=$true)][string]$FTPuser,
	[Parameter(Mandatory=$true)][string]$FTPpass,
	[Parameter(Mandatory=$true)][string]$customerno,

	[string]$POWERSHELL7 = 'yes',
	[string]$FTP = 'yes',
	[string]$UPDATE = 'no',
	[string]$ADMINUPDATE = 'yes'
)


<#######################################
## switch install components on/off
#######################################

$POWERSHELL7 = "yes"
$FTP = "yes"
$UPDATE = "no"
$ADMINUPDATE = "yes"

# AM 29.11.22 14:37 nach oben überführt

#>

#######################################
## generate timestamp
#######################################

<#
Function Get-Timestamp
{
$n=Get-Date
#pad values with leading 0 if necessary
$mo=(($n.Month).ToString()).PadLeft(2,"0")
$dy=(($n.Day).ToString()).PadLeft(2,"0")
$yr=($n.Year).ToString()
$hr=(($n.hour).ToString()).PadLeft(2,"0")
$mn=(($n.Minute).ToString()).PadLeft(2,"0")
$sec=(($n.Second).ToString()).PadLeft(2,"0")

$result=$yr+"-"+$mo+"-"+$dy+"_"+$hr+"-"+$mn+"-"+$sec

return $result
}
$t=Get-TimeStamp
#>

$t=(get-date -format "yyyy-MM-dd_HH-mm-ss")

Start-Sleep -s 1
# $tlang1 = (Get-Date)


#######################################
## password generator
#######################################

function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    return [String]$characters[$random]
}

function Scramble-String([string]$inputString){     
    $characterArray = $inputString.ToCharArray()   
    $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
    $outputString = -join $scrambledStringArray
    return $outputString 
}

$password = Get-RandomCharacters -length 5 -characters 'abcdefghiklmnoprstuvwxyz'
$password += Get-RandomCharacters -length 5 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
$password += Get-RandomCharacters -length 4 -characters '1234567890'
$password += Get-RandomCharacters -length 2 -characters '!"§$%&/()=?}][{@#*+'
$ftppassword = Scramble-String $password

######################################
## Parameter for FTP server install ##
######################################

$FTPsiteFull = "IIS:\Sites\SDMSC1-FTPSite01"
$FTPsiteShort = "SDMSC1-FTPSite01"
$FTPsitePath = "d:\dms-data\ftp-root\SDMSC1-FTPSite01"
$FTPuserName = "SDMSC1-FTP01-"+$customerno
$FTPUserPassword = ConvertTo-SecureString $ftppassword -AsPlainText -Force
$FTPgroup = "FTPGroup"
$FTProotFolderpath = "d:\dms-data\ftp-root"


################################################
## start logging 
################################################

Start-Transcript -Path "c:\install\_Log-Install-Starke-DMS_01-$t.txt" 


################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


################################################
################################################
## let's beginn
################################################
################################################

Write-Host 
Write-Host -ForegroundColor Yellow "###############################"
Write-Host -ForegroundColor Yellow "### set default OS settings ###"
Write-Host -ForegroundColor Yellow "###############################"
Write-Host


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

Write-Host
Write-Host
Write-Host -ForegroundColor Green "################################"
Write-Host -ForegroundColor Green "### default OS settings done ###"
Write-Host -ForegroundColor Green "################################"
Write-Host
Write-Host


################################################
## Download section
################################################

Write-Host
Write-Host 
Write-Host -ForegroundColor Yellow "#################################"
Write-Host -ForegroundColor Yellow "###   downloading the stuff   ###"
Write-Host -ForegroundColor Yellow "#################################"
Write-Host
Write-Host

# download the PowerShell7 installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/PowerShell-7.3.0-win-x64.msi" --ssl-reqd -k --output C:\install\StarkeDMS-latest\PowerShell-7.3.0-win-x64.msi --create-dirs

# download the Ansible config script
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/ConfigureRemotingForAnsible.ps1" --output C:\install\ConfigureRemotingForAnsible.ps1 --create-dirs

# download the Notepad++ installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/npp.8.4.7.Installer.x64.exe" --ssl-reqd -k --output C:\install\StarkeDMS-latest\npp.8.4.7.Installer.x64.exe --create-dirs

# download the Micrsoft Edge installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/MicrosoftEdgeEnterpriseX64.msi" --ssl-reqd -k --output C:\install\StarkeDMS-latest\MicrosoftEdgeEnterpriseX64.msi --create-dirs

Write-Host
Write-Host
Write-Host -ForegroundColor Green "######################################"
Write-Host -ForegroundColor Green "###       download finished        ###"
Write-Host -ForegroundColor Green "######################################"
Write-Host
Write-Host


################################################
## install PowerShell 7
################################################
if($POWERSHELL7 -eq "yes"){
	# run the PowerShell7 installer in silent mode
	Write-Host
	Write-Host 
	Write-Host -ForegroundColor Yellow "###############################"
	Write-Host -ForegroundColor Yellow "### installing PowerShell 7 ###"
	Write-Host -ForegroundColor Yellow "###############################"
	Write-Host
	Write-Host
	
	Start-Process -wait -FilePath C:\install\StarkeDMS-latest\PowerShell-7.3.0-win-x64.msi -ArgumentList "/quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1"
	
	# create desktop shortcut for PowerShell 7 and run always as administrator
	$objShell = New-Object -ComObject ("WScript.Shell")
	$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\PowerShell7.lnk")
	$objShortCut.TargetPath="C:\Program Files\PowerShell\7\pwsh.exe"
	$objShortCut.Save()
	
}else {
	Write-Host -ForegroundColor red "###################################"
	Write-Host -ForegroundColor red "### Powershell 7 not installed  ###"
	Write-Host -ForegroundColor red "###################################"
	Start-Sleep -s 5
}


Write-Host
Write-Host 
Write-Host -ForegroundColor Yellow "##################################"
Write-Host -ForegroundColor Yellow "### creating desktop shortcuts ###"
Write-Host -ForegroundColor Yellow "##################################"
Write-Host
Write-Host

$bytes = [System.IO.File]::ReadAllBytes("$Home\Desktop\PowerShell7.lnk")
$bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
[System.IO.File]::WriteAllBytes("$Home\Desktop\PowerShell7.lnk", $bytes)

$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\services.lnk")
$objShortCut.TargetPath="services.msc"
$objShortCut.Save()

$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\Install.lnk")
$objShortCut.TargetPath="C:\Windows\explorer.exe"
$objShortcut.Arguments = "c:\install"
$objShortCut.Save()

$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\DMS-config.lnk")
$objShortCut.TargetPath="C:\Windows\explorer.exe"
$objShortcut.Arguments = "d:\dms-config"
$objShortCut.Save()

$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\DMS-dir.lnk")
$objShortCut.TargetPath="C:\Windows\explorer.exe"
$objShortcut.Arguments = "C:\Program Files (x86)\StarkeDMS"
$objShortCut.Save()

$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\DMS-data.lnk")
$objShortCut.TargetPath="C:\Windows\explorer.exe"
$objShortcut.Arguments = "d:\dms-data"
$objShortCut.Save()


 
################################################
## Powershell 7 Modul sqlserver install
## necessary for sqlcmd cmdlet
################################################
Write-Host
Write-Host 
Write-Host -ForegroundColor Yellow "#######################################"
Write-Host -ForegroundColor Yellow "### installing PS7 module sqlserver ###"
Write-Host -ForegroundColor Yellow "#######################################"
Write-Host
Write-Host
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name SqlServer -force

Write-Host
Write-Host
Write-Host -ForegroundColor Green "########################################"
Write-Host -ForegroundColor Green "###  PS7 module sqlserver installed  ###"
Write-Host -ForegroundColor Green "########################################"
Write-Host
Write-Host


################################################
## Ansible config script
################################################

powershell.exe -File c:\install\ConfigureRemotingForAnsible.ps1
# iex(iwr https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1).Content

Write-Host
Write-Host
Write-Host -ForegroundColor Green "######################################"
Write-Host -ForegroundColor Green "### Ansible config script finished ###"
Write-Host -ForegroundColor Green "######################################"
Write-Host
Write-Host


################################################
## install Notepad++ in silent mode
################################################
Write-Host
Write-Host 
Write-Host -ForegroundColor Yellow "####################################"
Write-Host -ForegroundColor Yellow "###     installing Notepad++     ###"
Write-Host -ForegroundColor Yellow "####################################"
Write-Host
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\npp.8.4.7.Installer.x64.exe' -ArgumentList /S -PassThru
Write-Host
Write-Host -ForegroundColor Green "#######################################"
Write-Host -ForegroundColor Green "###       Notepad++ installed       ###"
Write-Host -ForegroundColor Green "#######################################"
Write-Host
Write-Host


################################################
## install Microsoft Edge in silent mode
################################################
Write-Host
Write-Host 
Write-Host -ForegroundColor Yellow "####################################"
Write-Host -ForegroundColor Yellow "###  installing Microsoft Edge   ###"
Write-Host -ForegroundColor Yellow "####################################"
Write-Host
Write-Host

Start-Process -wait -FilePath C:\install\StarkeDMS-latest\MicrosoftEdgeEnterpriseX64.msi -ArgumentList "/quiet"
Write-Host
Write-Host
Write-Host -ForegroundColor Green "######################################"
Write-Host -ForegroundColor Green "###    Microsoft Edge installed    ###"
Write-Host -ForegroundColor Green "######################################"
Write-Host
Write-Host
Write-Host
Write-Host 
Write-Host -ForegroundColor Yellow "#####################################"
Write-Host -ForegroundColor Yellow "###    remove Internet Explorer   ###"
Write-Host -ForegroundColor Yellow "#####################################"
Write-Host
Write-Host
Write-Host -ForegroundColor Green " Uninstall Internet Explorer 11"
Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart
Write-Host
Write-Host
Write-Host -ForegroundColor Green "######################################"
Write-Host -ForegroundColor Green "###    Internet Explorer removed   ###"
Write-Host -ForegroundColor Green "######################################"
Write-Host
Write-Host


################################################
## create media structure
################################################
Write-Host -ForegroundColor yellow "##########################################"
Write-Host -ForegroundColor yellow "######## creating media structur #########"
Write-Host -ForegroundColor yellow "##########################################"

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
New-Item -Path "d:\dms-data" -Name "ftp-data" -ItemType "directory"
New-Item -Path "d:\dms-data\backup" -Name "sql" -ItemType "directory"
New-Item -Path "d:\" -Name "tools" -ItemType "directory"
New-Item -Path "d:\tools" -Name "ansible" -ItemType "directory"
Write-Host
Write-Host
Write-Host -ForegroundColor Green "#########################################"
Write-Host -ForegroundColor Green "###       media structur created      ###"
Write-Host -ForegroundColor Green "#########################################"
Write-Host
Write-Host

################################################
## install FTP server
################################################

if($FTP -eq "yes"){
	Write-Host -ForegroundColor yellow "##########################################"
	Write-Host -ForegroundColor yellow "########  installing FTP server  #########"
	Write-Host -ForegroundColor yellow "##########################################"

	Install-WindowsFeature Web-Ftp-Server -IncludeAllSubFeature -IncludeManagementTools
	Install-Module -Name IISAdministration -force

	Import-Module ServerManager
	Add-WindowsFeature Web-Scripting-Tools
	import-module WebAdministration

	# https://blog.kmsigma.com/2016/02/25/removing-default-web-site-application-pool/
	Remove-IISSite "Default Web Site" -Confirm:$False
	# Remove-WebAppPool -Name "DefaultAppPool" -Confirm:$false -Verbose

	# https://www.server-world.info/en/note?os=Windows_Server_2019&p=ftp&f=2
	Set-WebConfiguration "/system.ftpServer/firewallSupport" -PSPath "IIS:\" -Value @{lowDataChannelPort="60000";highDataChannelPort="60100";} 
	Restart-Service ftpsvc 

	New-NetFirewallRule `
	-Name "FTP Server Port" `
	-DisplayName "FTP Server Port" `
	-Description 'Allow FTP Server Ports' `
	-Profile Any `
	-Direction Inbound `
	-Action Allow `
	-Protocol TCP `
	-Program Any `
	-LocalAddress Any `
	-LocalPort 21,60000-60100 

	# https://www.server-world.info/en/note?os=Windows_Server_2019&p=initial_conf&f=1
	New-LocalUser -Name $FTPuserName `
	-FullName "Starke-DMS Cloud 1.0 FileXchange user" `
	-Description "FTP user" `
	-Password $FTPUserPassword `
	-PasswordNeverExpires `
	-AccountNeverExpires 

	New-LocalGroup -Name $FTPgroup
	Add-LocalGroupMember -Group $FTPgroup -Member $FTPuserName 

	mkdir $FTPsitePath 
	New-WebFtpSite -Name $FTPsiteShort -IPAddress "*" -Port 21
	Set-ItemProperty $FTPsiteFull -Name physicalPath -Value $FTPsitePath
	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow" 
	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow" 
	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.authentication.basicAuthentication.enabled -Value $true 

	Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $FTPsiteShort -PSPath IIS:\ -Value @{accessType="Allow";roles=$FTPgroup;permissions="Read,Write"} 

	icacls $FTPsitePath /grant "FTPGroup:(OI)(CI)(F)" 

	Restart-WebItem -PSPath $FTPsiteFull 

	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow" 
	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow" 

	# Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslRequire" 
	# Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslRequire" 

	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.serverCertStoreName -Value "My" 
	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.serverCertHash -Value (Get-ChildItem -path cert:\LocalMachine\My | Where-Object -Property Subject -like "CN=*").Thumbprint

	Remove-Item C:\inetpub\ -recurse

	# https://patorjk.com/software/taag/#p=display&f=Ivrit&t=Starke-DMS%0ACloud%20Installer
	# Font Ivrit
	'-------------------------------------------------------------------', `
	'  ____  _             _              ____  __  __ ____             ', `
	' / ___|| |_ __ _ _ __| | _____      |  _ \|  \/  / ___|            ', `
	' \___ \| __/ _` | ´__| |/ / _ \_____| | | | |\/| \___ \            ', `
	'  ___) | || (_| | |  |   <  __/_____| |_| | |  | |___) |           ', `
	' |____/ \__\__,_|_|  |_|\_\___|     |____/|_|  |_|____/            ', `
	'   ____ _                 _   ___           _        _ _           ', `
	'  / ___| | ___  _   _  __| | |_ _|_ __  ___| |_ __ _| | | ___ _ __ ', `
	' | |   | |/ _ \| | | |/ _` |  | || ´_ \/ __| __/ _` | | |/ _ \ ´__|', `
	' | |___| | (_) | |_| | (_| |  | || | | \__ \ || (_| | | |  __/ |   ', `
	'  \____|_|\___/ \__,_|\__,_| |___|_| |_|___/\__\__,_|_|_|\___|_|   ', `
	'                                                                   ', `
	'-------------------------------------------------------------------', `
	'New FTP name and password', `
	'-------------------------------------------------------------------', `
	'Host: '+$ENV:COMPUTERNAME, `
	'-------------------------------------------------------------------', `
	'Date: '+(get-date -format "yyyy-MM-dd HH:mm:ss"), `
	'-------------------------------------------------------------------', `
	'new ftp user:', `
	$FTPuserName, `
	'-------------------------------------------------------------------', `
	'new password:', `
	$ftppassword, `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------', `
	'DELETE THIS FILE IMMEDIATELY AFTER SAVING THE DATA', `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------'  | `
	out-file $env:USERPROFILE\Desktop\ftp_password_username.txt


	Write-Host
	Write-Host
	Write-Host -ForegroundColor Green "###########################################"
	Write-Host -ForegroundColor Green "### FTP server installed and configured ###"
	Write-Host -ForegroundColor Green "###########################################"
	Write-Host
	Write-Host

}else {
	Write-Host 
	Write-Host -ForegroundColor red "################################"
	Write-Host -ForegroundColor red "### FTP server not installed ###"
	Write-Host -ForegroundColor red "################################"
	Write-Host
	Start-Sleep -s 5
}


################################################
## install updates
################################################
# Install PSWindowsUpdate Modul for PowerShell

if($UPDATE -eq "yes"){
	Write-Host 
	Write-Host -ForegroundColor Yellow "################################################"
	Write-Host -ForegroundColor Yellow "# Install PSWindowsUpdate modul for PowerShell #"
	Write-Host -ForegroundColor Yellow "################################################"
	Write-Host

	Install-Module -Name PSWindowsUpdate -Force
	Start-Sleep -s 2
	get-command -module PSWindowsUpdate
	Start-Sleep -s 2

	# Install all pending Updates and restart without asking
	Write-Host 
	Write-Host -ForegroundColor Yellow "###############################################"
	Write-Host -ForegroundColor Yellow "###       Install all pending updates       ###"
	Write-Host -ForegroundColor Yellow "###############################################"
	Write-Host
	Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -IgnoreReboot
	#Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
	Write-Host
	Write-Host -ForegroundColor green "##########################################################"
	Write-Host -ForegroundColor green "###               all updates installed                ###"
	Write-Host -ForegroundColor green "##########################################################"
	Write-Host
	Start-Sleep -s 5

}else {
	Write-Host -ForegroundColor red "##############################"
	Write-Host -ForegroundColor red "### updates not installed  ###"
	Write-Host -ForegroundColor red "##############################"
	Start-Sleep -s 5
}


################################################
## change admin name und password
################################################
if($ADMINUPDATE -eq "yes"){
	$NewAdminPassword = Scramble-String $password
	$NewAdminPassword = convertto-securestring $password -asplaintext -force
	Set-LocalUser -Name Administrator -Password $NewAdminPassword –Verbose

	Rename-LocalUser -Name "Administrator"  -NewName "GottliebKrause"
	wmic useraccount where "Name='GottliebKrause'" set PasswordExpires=false

	'-------------------------------------------------------------------', `
	'  ____  _             _              ____  __  __ ____             ', `
	' / ___|| |_ __ _ _ __| | _____      |  _ \|  \/  / ___|            ', `
	' \___ \| __/ _` | ´__| |/ / _ \_____| | | | |\/| \___ \            ', `
	'  ___) | || (_| | |  |   <  __/_____| |_| | |  | |___) |           ', `
	' |____/ \__\__,_|_|  |_|\_\___|     |____/|_|  |_|____/            ', `
	'   ____ _                 _   ___           _        _ _           ', `
	'  / ___| | ___  _   _  __| | |_ _|_ __  ___| |_ __ _| | | ___ _ __ ', `
	' | |   | |/ _ \| | | |/ _` |  | || ´_ \/ __| __/ _` | | |/ _ \ ´__|', `
	' | |___| | (_) | |_| | (_| |  | || | | \__ \ || (_| | | |  __/ |   ', `
	'  \____|_|\___/ \__,_|\__,_| |___|_| |_|___/\__\__,_|_|_|\___|_|   ', `
	'                                                                   ', `
	'-------------------------------------------------------------------', `
	'New Administrator name and password', `
	'-------------------------------------------------------------------', `
	'Host: '+$ENV:COMPUTERNAME, `
	'-------------------------------------------------------------------', `
	'Date: '+(get-date -format "yyyy-MM-dd HH:mm:ss"), `
	'-------------------------------------------------------------------', `
	'new admin user:', `
	'"GottliebKrause"', `
	'-------------------------------------------------------------------', `
	'new password:', `
	$Password, `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------', `
	'DELETE THIS FILE IMMEDIATELY AFTER SAVING THE DATA', `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------'  | `
	out-file $env:USERPROFILE\Desktop\admin_password_username.txt


}else {
	Write-Host -ForegroundColor red "#########################################"
	Write-Host -ForegroundColor red "### NO admin name and password change ###"
	Write-Host -ForegroundColor red "#########################################"
	Start-Sleep -s 5
}


<#
################################################
## write date and time to file
################################################

$tlang2 = (Get-Date)
'--------------------','time at the end of installation',$tlang2,'--------------------'  | Add-content $env:USERPROFILE\Desktop\ftp_password_username.txt
#>

################################################
## restart the computer
################################################
# [Console]::ReadKey()
# Restart-computer -force


################################################
## we're done
################################################

Write-Host
Write-Host
Write-Host -ForegroundColor green "##############################################"
Write-Host -ForegroundColor green "####   Install-Starke-DMS_01.ps1 finished  ###"
Write-Host -ForegroundColor green "##############################################"
Write-Host
Write-Host


################################################
## open the ftp_password_username.txt file
################################################

Notepad $env:USERPROFILE\Desktop\ftp_password_username.txt 

if($ADMINUPDATE -eq "yes"){
	Notepad $env:USERPROFILE\Desktop\admin_password_username.txt 
}else {
}
