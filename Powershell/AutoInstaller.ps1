<# 26.03.2023 Eike Doose / INTERNAL USER ONLY / do not distribute
=================================================================
https://www.starke-dms.cloud
AutoInstaller for Starke-DMS® Cloud 1.0 IaaS
#>

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
$DEVRUN = $var.DEVRUN

Clear-Host []


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
    PrintJobToDo "Starke-DMS® Cloud 1.0 AutoInstaller - let's go :-)"
    Start-Sleep -s 3
    Clear-Host []


#######################################
## generate timestamp
#######################################

    $t=(get-date -format "yyyy-MM-dd_HH-mm-ss")
    Start-Sleep -s 1


################################################
## start logging 
################################################

    Start-Transcript -Path "c:\install\_Log-AutoInstaller-$t.txt" 
    Start-Sleep -s 2
    Clear-Host []


################################################
################################################
## let's beginn
################################################
################################################

################################################
## check if sources ftp server is available
################################################

PrintJobToDo "check if FTP server is available"
try
{
    $ftprequest = [System.Net.FtpWebRequest]::Create("ftp://$FTPserver")
    $ftprequest.Credentials = New-Object System.Net.NetworkCredential("str0ng", "r1ch") 
    $ftprequest.Method = [System.Net.WebRequestMethods+Ftp]::PrintWorkingDirectory
    $ftprequest.GetResponse()

    PrintJobDone "Unexpected FTP connectivity success, but OK."
}
catch
{
    if (($_.Exception.InnerException -ne $Null) -and
        ($_.Exception.InnerException.Response -ne $Null) -and
        ($_.Exception.InnerException.Response.StatusCode -eq
             [System.Net.FtpStatusCode]::NotLoggedIn))
    {
        PrintJobDone "FTP server is available"
    }
    else
    {
        ## send e-mail to technical consultant
        $mailpw = ConvertTo-SecureString -String $MAILPASS -AsPlainText -Force
        $mailcred = New-Object System.Management.Automation.PSCredential "noreply@starke-dms.cloud", $mailpw
        $mailbody = "Cloud Installer stopped"
        $mailsubject = "SDMS-C1-CloudInstaller notification / customer $customerno / FTP not available / Installation aborted"
        Send-MailMessage -Credential $mailcred -to $ConsultantMailAddress -from noreply@starke-dms.cloud -SMTPServer 'smtp.strato.com' -Port 587 -usessl -Subject $mailsubject -body $mailbody
        Throw "FTP server not available - Installation aborted"
        PrintJobError "FTP server is NOT available - Installation aborted: $($_.Exception.Message)"
    }
}

##################################################
## disable autostart of Windows server-manager
##################################################

PrintJobToDo "disable autostart of Windows Server Manager"
Invoke-Command -ComputerName localhost -ScriptBlock { New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value "0x1" –Force} 
PrintJobDone "autostart of Windows Server disabled"


################################################
## enable Adminstrator auto logon
################################################

    $UserAutoLogon = 'Administrator'
    $RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    Set-ItemProperty $RegistryPath 'AutoAdminLogon' -Value "1" -Type String 
    Set-ItemProperty $RegistryPath 'DefaultUsername' -Value "$UserAutoLogon" -type String 
    Set-ItemProperty $RegistryPath 'DefaultPassword' -Value "$PassAutoLogon" -type String


#########################################################################
## create the windows task to run Install-Starke-DMS_00.ps1 at next logon
#########################################################################

	PrintJobToDo  "create task to continue the installation at next logon"

	[string]$TaskName = "run Install-Starke-DMS_00.ps1 at logon"
	[string]$TaskDescription = "This task will run once at startup / task created by Starke-DMS® cloud installer"
	[string]$TaskDir = "\Starke-DMS®"
	$TaskTrigger = New-ScheduledTaskTrigger -AtLogon
	$TaskAction = New-ScheduledTaskAction -WorkingDirectory c:\install -Execute "powershell" -Argument "-noexit -command C:\install\Install-Starke-DMS_00.ps1"
	$TaskSettings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
	$TaskUser = New-ScheduledTaskPrincipal -UserId "Administrator" -RunLevel Highest
	if (Get-ScheduledTask $TaskName -ErrorAction SilentlyContinue) {Unregister-ScheduledTask $TaskName}            
	Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskDir -Action $TaskAction -Trigger $TaskTrigger -Principal $TaskUser -Settings $TaskSettings -Description $TaskDescription

	PrintJobDone "task to continue the installation is created"
	Start-Sleep -s 3
    Clear-Host []


################################################
## let's refresh this server with all updates
################################################

    PrintJobToDo "Install PSWindowsUpdate modul for PowerShell"

    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Start-Sleep -s 2
    Register-PSRepository -Default
    Start-Sleep -s 2
    Install-Module -Name PSWindowsUpdate -Force
    Start-Sleep -s 2
    get-command -module PSWindowsUpdate
    Start-Sleep -s 2

    PrintJobDone "PSWindowsUpdate modul for PowerShell installed"

    PrintJobToDo "Install all pending Updates and restart without asking"
    Start-Sleep -s 3
    stop-transcript
    # stop-transcript / Transcript is broken if OS update installs PowerShell engine update - because of this the transcript stops before updating
    Clear-Host []
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
    Start-Sleep -s 3
    Restart-computer -force