<# 21.02.2023 Eike Doose / INTERNAL USER ONLY / do not distribute
============================================================================

-FTPserver 		# specify the FTP server which will be used for downloading the software / e.g. -FTPserver 'ftp.get--it.de'
-FTPuser 		# name the FTP server user for logging into the FTP server / e.g. -FTPuser 'username'
-FTPpass 		# password for logging into the FTP server / e.g. -FTPpass 'verysecretpassword'
-customerno 	# client customer number which is needed for naming the new server and the database creation / e.g. -customerno '23545'
-LIZuser 		# username for using the license server / e.g. -LIZuser 'username'
-LIZpass 		# password for logging into the license server / e.g. -FTPpass 'licenseuserpass'
-LIZserver 		# URL of the license server / e.g. -LIZserver 'license.starke.cloud'
-LIZuid 		# license UID to be downloaded / e.g. -LIZuid '{5C395FDC-6A94-32BE-BAD4-918D9B324AFG}'
-LIZcustomerno 	# license custom number to be downloaded / e.g. -LIZcustomerno '23545'
				  => not needed if LIZuid is given
-LIZtargetdir 	# directory to where the license file will be downloaded / e.g. -LIZtargetdir 'd:\dms-config' 
-saPass 		# sa password for the database / e.g. -saPass 'secretsapassword' 
-UPDATE			# add with "no" for not installing Windows update - mainly for testing / -UPDATES 'no'
#>

param (
	[Parameter(Mandatory=$true)][string]$customerno
)

#######################################
## generate timestamp
#######################################

$t=(get-date -format "yyyy-MM-dd_HH-mm-ss")
Start-Sleep -s 1


################################################
## start logging 
################################################

Start-Transcript -Path "c:\install\_Log-Install-Starke-DMS_31-createTasks-$t.txt" 
Start-Sleep -s 1


################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


################################################
## create the windows task
################################################

[string]$TaskName = "Start Install-Starke-DMS_00.ps1"
[string]$TaskDescription = "This task will run once at startup / task created by Starke-DMS® cloud installer"
[string]$TaskDir = "\Starke-DMS®"
$TaskAusloeser = New-ScheduledTaskTrigger -AtLogon
$TaskAktion = New-ScheduledTaskAction -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe C:\install\Install-Starke-DMS_00.ps1 -customerno '$customerno'"
$TaskEinstellungen = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
$TaskBenutzer = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest            
if (Get-ScheduledTask $TaskName -ErrorAction SilentlyContinue) {Unregister-ScheduledTask $TaskName}            
Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskDir -Action $TaskAktion -Trigger $TaskAusloeser -Principal $TaskBenutzer -Settings $TaskEinstellungen -Description $TaskDescription
