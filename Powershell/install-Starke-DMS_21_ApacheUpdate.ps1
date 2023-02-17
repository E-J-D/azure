<# 17.02.2023 Eike Doose / INTERNAL USER ONLY / do not distribute
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
	[string]$FTPserver = 'ftp.get--it.de',
	[Parameter(Mandatory=$true)][string]$FTPuser,
	[Parameter(Mandatory=$true)][string]$FTPpass,
	[string]$UPDATE = 'yes'

)

#######################################
## generate timestamp
#######################################

$t=(get-date -format "yyyy-MM-dd_HH-mm-ss")
Start-Sleep -s 1


################################################
## start logging 
################################################

Start-Transcript -Path "c:\install\_Log-Install-Starke-DMS_21-ApacheUpdate-$t.txt" 
Start-Sleep -s 3


################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


################################################
## detect Powershell version - minimum 7
################################################
If ($PSVersionTable.PSVersion.Major -lt 7) {
    Throw "PowerShell version 7 or higher is required."
}
Clear-Host []


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
PrintJobToDo "Starke-DMS® Apache Update Script"
Start-Sleep -s 3
Clear-Host []



################################################
## Download section
################################################

PrintJobToDo "downloading the stuff"

# define download files
$files_WebApache	= "WebApache.zip"

# Create an array of files
$files = @($files_WebApache)

# Perform iteration to download the files to server
foreach ($i in $files) {
	curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/"$i"" --ssl-reqd -k --output C:\install\StarkeDMS-latest\$i --create-dirs
}

PrintJobDone "download finished"
Start-Sleep -s 1
Clear-Host []


################################################
## stop the DMS_11_WebApache service
################################################

PrintJobToDo "stopping DMS_11_WebApache service"
Stop-Service -Name "DMS_11_WebApache"
Start-Sleep -s 2
PrintJobDone "DMS_11_WebApache service stopped"
Start-Sleep -s 2
Clear-Host []


################################################
## delete old Apache24
################################################

PrintJobToDo "deleting old version"
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\WebApache.zip -DestinationPath d:\tools
Remove-Item d:\tools\Apache24 -Recurse
PrintJobDone "old version deleted"
Start-Sleep -s 2
Clear-Host []


################################################
## unzip new version
################################################

PrintJobToDo "unzipping archives"
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\WebApache.zip -DestinationPath d:\tools
Remove-Item C:\install\StarkeDMS-latest\WebApache.zip
PrintJobDone "archives unzipped"
Start-Sleep -s 2
Clear-Host []


################################################
## start the DMS_11_WebApache service
################################################

PrintJobToDo "starting DMS_11_WebApache service"
Start-Service -Name "DMS_11_WebApache"
Start-Sleep -s 2
PrintJobDone "DMS_11_WebApache service started"
Start-Sleep -s 2
Clear-Host []


################################################
## finished
################################################
Clear-Host []
PrintJobToDo "Apache update finished - no restart needed"
Start-Sleep -s 10

stop-transcript
Clear-Host []