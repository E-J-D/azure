<# 14.12.2022 Eike Doose / INTERNAL USER ONLY / do not distribute
Install-Starke-DMS_01.ps1 installs PowerShell 7 which is needed for following installation
==========================================================================================

-FTPserver   # specify the FTP server which will be used for downloading the software / e.g. -FTPserver 'ftp.get--it.de'
-FTPuser     # name the FTP server user for logging into the FTP server / e.g. -FTPuser 'username'
-FTPpass     # password for logging into the FTP server / e.g. -FTPpass 'verysecretpassword'
-customerno  # client customer number which is needed for naming the new server and the database creation / e.g. -customerno '23545'

-POWERSHELL7 # add with "no" for not installing Powershell7 - mainly for testing / -POWERSHELL7 'no'
-FTP         # add with "no" for not installing the FTP feature - mainly for testing / -FTP 'no'
-SSH         # add with "no" for not installing the SSH feature - mainly for testing / -SSH 'no'
-UPDATE      # add with "no" for not installing Windows update - mainly for testing / -UPDATES 'no'
-ADMINUPDATE # add with "no" for not performing admin user name and password change - mainly for testing / -ADMINUPDATE 'no'
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
	[string]$SSH = 'yes',
	[string]$UPDATE = 'yes',
	[string]$ADMINUPDATE = 'yes'
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
PrintJobToDo "Starke-DMS® unattended install part 2 of 3"
Start-Sleep -s 3
Clear-Host []


#######################################
## generate timestamp
#######################################

$t=(get-date -format "yyyy-MM-dd_HH-mm-ss")
Start-Sleep -s 1


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


######################################
## Parameter for FTP server install ##
######################################

$FTPsiteFull = "IIS:\Sites\FTP-Site01"
$FTPsiteShort = "FTP-Site01"
$FTPsitePath = "d:\dms-data\file-exchange\FTP-Site01"
$FTPuserName = "SDMSC1-FTP01-"+$customerno
$FTPgroup = "FTPGroup"


######################################
## Parameter for SSH server install ##
######################################

$SSHsitePath = "d:\dms-data\file-exchange\SSH-Site01"
$SSHuserName = "SDMSC1-SSH01-"+$customerno
$SSHgroup = "SSHGroup"


################################################
## start logging 
################################################

Start-Transcript -Path "c:\install\_Log-Install-Starke-DMS_01-$t.txt" 
Start-Sleep -s 3

################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


################################################
## Download section
################################################

PrintJobToDo "downloading the stuff"

# define download files
$files_PS		= "PowerShell-7.2.7-win-x64.msi"
$files_NPP		= "npp.8.4.7.Installer.x64.exe"
$files_EDGE		= "MicrosoftEdgeEnterpriseX64.msi"
$files_SSH		= "OpenSSH-Win64-v9.1.0.0.msi"

# Create an array of files
$files = @($files_PS,$files_NPP,$files_EDGE,$files_SSH)

# Perform iteration to download the files to server
foreach ($i in $files) {
	curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/"$i"" --ssl-reqd -k --output C:\install\StarkeDMS-latest\$i --create-dirs
}

# download the Ansible config script manually
# curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/ConfigureRemotingForAnsible.ps1" --output C:\install\ConfigureRemotingForAnsible.ps1 --create-dirs

PrintJobDone "download finished"


################################################
## install PowerShell 7
################################################
if($POWERSHELL7 -eq "yes"){
	# run the PowerShell7 installer in silent mode
	PrintJobToDo "installing PowerShell 7"
	Start-Process -wait -FilePath C:\install\StarkeDMS-latest\$files_PS -ArgumentList "/quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1"
#	Start-Process -wait -FilePath C:\install\StarkeDMS-latest\PowerShell-7.2.7-win-x64.msi -ArgumentList "/quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1"
	
	# create desktop shortcut for PowerShell 7 and run always as administrator
	$objShell = New-Object -ComObject ("WScript.Shell")
	$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\PowerShell7.lnk")
	$objShortCut.TargetPath="C:\Program Files\PowerShell\7\pwsh.exe"
	$objShortCut.Save()
	
}else {
	PrintJobError "Powershell 7 not installed"
	Start-Sleep -s 3
}


################################################
## creating desktop shortcuts
################################################

PrintJobToDo "creating desktop shortcuts"

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

$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\DMS-file-exchange.lnk")
$objShortCut.TargetPath="C:\Windows\explorer.exe"
$objShortcut.Arguments = "d:\dms-data\file-exchange"
$objShortCut.Save()

 
################################################
## Powershell 7 Modul sqlserver install
## necessary for sqlcmd cmdlet
################################################

PrintJobToDo "installing PS7 module sqlserver"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name SqlServer -force
PrintJobDone "PS7 module sqlserver installed"


################################################
## Ansible config script
################################################

#powershell.exe -File c:\install\ConfigureRemotingForAnsible.ps1
## iex(iwr https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1).Content
#PrintJobDone "Ansible config script finished"


################################################
## install Notepad++ in silent mode
################################################
PrintJobToDo "installing Notepad++"
Start-Process -Wait -FilePath C:\install\StarkeDMS-latest\$files_NPP -ArgumentList /S -PassThru
PrintJobDone "Notepad++ installed"


################################################
## install Microsoft Edge in silent mode
################################################
PrintJobToDo "installing Microsoft Edge"
Start-Process -wait -FilePath C:\install\StarkeDMS-latest\$files_EDGE -ArgumentList "/quiet"
PrintJobDone "Microsoft Edge installed"
PrintJobToDo "Remove Internet Explorer"
Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart
PrintJobDone "Internet Explorer removed"


################################################
## install FTP server
################################################

if($FTP -eq "yes"){
	PrintJobToDo "installing FTP server"

	Install-WindowsFeature Web-Ftp-Server -IncludeAllSubFeature -IncludeManagementTools
	Start-Sleep -s 3
	Install-Module -Name IISAdministration -force
	Start-Sleep -s 3
	Import-Module ServerManager
	Start-Sleep -s 2
	Add-WindowsFeature Web-Scripting-Tools
	Start-Sleep -s 2
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
	$ftppassword = Scramble-String $password
	$FTPUserPassword = ConvertTo-SecureString $ftppassword -AsPlainText -Force
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
	Set-ItemProperty $FTPsiteFull -Name ftpServer.logFile.directory -Value D:\dms-data\ftp-log

	Add-WebConfiguration "/system.ftpServer/security/authorization" -Location $FTPsiteShort -PSPath IIS:\ -Value @{accessType="Allow";roles=$FTPgroup;permissions="Read,Write"} 

	icacls $FTPsitePath /grant "FTPGroup:(OI)(CI)(F)" 

	Restart-WebItem -PSPath $FTPsiteFull 

	#create SSL certificate
	$SSLCERTdomain = ".starke-dms.cloud"
	$SSLCERTdns    = $customerno + $SSLCERTdomain
	$SSLCERT=New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname $SSLCERTdns

	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslAllow" 
	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslAllow" 

	# Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.controlChannelPolicy -Value "SslRequire" 
	# Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.dataChannelPolicy -Value "SslRequire" 

	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.serverCertStoreName -Value "My" 
	Set-ItemProperty $FTPsiteFull -Name ftpServer.security.ssl.serverCertHash -Value $SSLCERT.thumbprint
		
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

	PrintJobDone "FTP server installed and configured"

}else {
	PrintJobError "FTP server not installed"
	Start-Sleep -s 3
}


################################################
## install SSH server
################################################
# https://adamtheautomator.com/openssh-windows/
# (http://woshub.com/installing-sftp-ssh-ftp-server-on-windows-server-2012-r2/)

if($SSH -eq "yes"){
	PrintJobToDo "installing SSH server"

	<#
	## Set network connection protocol to TLS 1.2
	## Define the OpenSSH latest release url
	$url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'
	## Create a web request to retrieve the latest release download link
	$request = [System.Net.WebRequest]::Create($url)
	$request.AllowAutoRedirect=$false
	$response=$request.GetResponse()
	$source = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + '/OpenSSH-Win64.zip'
	## Download the latest OpenSSH for Windows package to the current working directory
	$webClient = [System.Net.WebClient]::new()
	$webClient.DownloadFile($source, (Get-Location).Path + '\OpenSSH-Win64.zip')
	# Extract the ZIP to a temporary location
	 Expand-Archive -Path .\OpenSSH-Win64.zip -DestinationPath ($env:temp) -Force
	# Move the extracted ZIP contents from the temporary location to C:\Program Files\OpenSSH\
	Move-Item "$($env:temp)\OpenSSH-Win64" -Destination "C:\Program Files\OpenSSH\" -Force
	# Unblock the files in C:\Program Files\OpenSSH\
	Get-ChildItem -Path "C:\Program Files\OpenSSH\" | Unblock-File
	& 'C:\Program Files\OpenSSH\install-sshd.ps1'
	# Add openSSH to path variable
	[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path",[System.EnvironmentVariableTarget]::Machine) + ';' + ${Env:ProgramFiles} + '\OpenSSH', [System.EnvironmentVariableTarget]::Machine)
	## changes the sshd service's startup type from manual to automatic.
	Set-Service sshd -StartupType Automatic
	## starts the sshd service.
	Start-Service sshd
	New-NetFirewallRule -Name sshd -DisplayName 'Allow SSH' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
	#>

	Start-Sleep -s 3
	Start-Process -wait -FilePath C:\install\StarkeDMS-latest\$files_SSH
		#  Start-Process -wait -FilePath  .\OpenSSH-Win64-v9.1.0.0.msi
	Start-Sleep -s 3

	<#
	Start-Sleep -s 3
	Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
	Start-Sleep -s 3
	Set-Service -Name sshd -StartupType 'Automatic'
	Start-Sleep -s 3
	Start-Service sshd
	Start-Sleep -s 2
	New-NetFirewallRule -Protocol TCP -LocalPort 22 -Direction Inbound -Action Allow -DisplayName SSH
	#>

	# https://www.server-world.info/en/note?os=Windows_Server_2019&p=initial_conf&f=1
	$sshpassword = Scramble-String $password
	$SSHUserPassword = ConvertTo-SecureString $sshpassword -AsPlainText -Force
	New-LocalUser -Name $SSHuserName `
	-FullName "Starke-DMS Cloud 1.0 FileXchange user" `
	-Description "SSH user" `
	-Password $SSHUserPassword `
	-PasswordNeverExpires `
	-AccountNeverExpires

	New-LocalGroup -Name $SSHGroup
	Add-LocalGroupMember -Group $SSHGroup -Member $SSHUserName 

	mkdir $SSHsitePath 

	icacls $SSHsitePath /grant "SSHGroup:(OI)(CI)(F)" 

	Stop-Service sshd
	Remove-Item 'C:\ProgramData\SSH\sshd_config'
	
	$SSHUserNameMatch = "Match User "
	$SSHUserNameString = $SSHUserNameMatch +$SSHUserName
	$SSHsitePathMatch = "   ChrootDirectory "
	$SSHsitePathString = $SSHsitePathMatch +$SSHsitePath
	'# ssh_config file created by SDMS cloud installer', `
	'Port 22', `
	'Subsystem  sftp   sftp-server.exe', `
	'AllowGroups SSHGroup', `
	'AuthenticationMethods password', `
	'ChrootDirectory D:\dms-data\file-exchange', `
	'DenyGroups Administrators', `
	'SyslogFacility LOCAL0', `
	'LogLevel Debug1', `
	$SSHUserNameString, `
	'   AllowTcpForwarding no', `
	    $SSHsitePathString , `
	'   ForceCommand internal-sftp', `
	'   PermitTunnel no', `
	'   AllowAgentForwarding no', `
	'   X11Forwarding no' | `
	out-file C:\ProgramData\SSH\sshd_config -Encoding utf8

	Start-Service sshd

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
	'New SSH name and password', `
	'-------------------------------------------------------------------', `
	'Host: '+$ENV:COMPUTERNAME, `
	'-------------------------------------------------------------------', `
	'Date: '+(get-date -format "yyyy-MM-dd HH:mm:ss"), `
	'-------------------------------------------------------------------', `
	'new SSH user:', `
	$SSHuserName, `
	'-------------------------------------------------------------------', `
	'new password:', `
	$SSHpassword, `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------', `
	'DELETE THIS FILE IMMEDIATELY AFTER SAVING THE DATA', `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------'  | `
	out-file $env:USERPROFILE\Desktop\ssh_password_username.txt

	PrintJobDone "SSH server installed and configured"

}else {
	PrintJobError "SSH server not installed"
	Start-Sleep -s 3
}




################################################
## install updates
################################################

if($UPDATE -eq "yes"){

	# Install all pending Updates and restart without asking
	PrintJobToDo "Install PSWindowsUpdate modul for PowerShell"
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
## change admin name und password
################################################
if($ADMINUPDATE -eq "yes"){
	$newadminpass = Scramble-String $password
	$NewAdminPassword = convertto-securestring $newadminpass -asplaintext -force
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
	$newadminpass, `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------', `
	'DELETE THIS FILE IMMEDIATELY AFTER SAVING THE DATA', `
	'-------------------------------------------------------------------', `
	'-------------------------------------------------------------------'  | `
	out-file $env:USERPROFILE\Desktop\admin_password_username.txt


}else {
	PrintJobError "NO admin name and password change"
	Start-Sleep -s 5
}


################################################
## restart the computer
################################################
# [Console]::ReadKey()
# Restart-computer -force


################################################
## we're done
################################################

stop-transcript
Clear-Host []
PrintJobDone "Install-Starke-DMS_01.ps1 finished"
Start-Sleep -s 5
PrintJobToDo "Restart the Computer and continue with Install-Starke-DMS_02.ps1"


################################################
## open the ftp_password_username.txt file
################################################

Notepad $env:USERPROFILE\Desktop\ftp_password_username.txt 

if($ADMINUPDATE -eq "yes"){
	Notepad $env:USERPROFILE\Desktop\admin_password_username.txt 
}elseif($SSH -eq "yes"){
	Notepad $env:USERPROFILE\Desktop\ssh_password_username.txt 
}
