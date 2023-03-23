<# 22.03.2023 Eike Doose / INTERNAL USER ONLY / do not distribute
============================================================================

https://blog.netwrix.de/2019/12/12/automatisieren-von-powershell-skripts-mit-der-aufgabenplanung/


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
	[Parameter(Mandatory=$true)][string]$customerno,
    $p1,
    $p2
)

#######################################
## generate timestamp
#######################################

$t=(get-date -format "yyyy-MM-dd_HH-mm-ss")
Start-Sleep -s 1


################################################
## start logging 
################################################

Start-Transcript -Path "c:\install\_Log-Install-Starke-DMS_31-dummy-$t.txt" 
Start-Sleep -s 1


################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


<#
################################################
## create link on desktop - dummy action
################################################

'rem this file was created by the Starke-DMS® cloud installer', `
'rem Eike Doose 22.03.2023', '', `
' PS-DUMMY file'
'SQLCMD.exe -S SDMSC1-KDNR\SDMSCLOUD1 -U sa -P saAdmin00! -i "D:\dms-data\backup\sql\backup-SQLExpress.sql" -o "D:\dms-data\backup\sql\backup-SQLExpress.txt"', `
'echo %DATE%', `
'echo %TIME%', `
'set datetimef=%date:~-4%_%date:~3,2%_%date:~0,2%__%time:~0,2%_%time:~3,2%_%time:~6,2%', `
'echo %datetimef%', `
'd:', `
'cd "d:\dms-data\backup\sql"', `
'rename CLOUD1-DB.bak CLOUD1-DB_%datetimef%.bak', `
'forfiles /p "d:\dms-data\backup\sql" /m *.bak /d -14 /c "cmd /c del @path"' | `
out-file d:\ps-dummy.txt -Encoding utf8
(Get-Content -Path 'd:\ps-dummy.txt') -replace 'KDNR',($customerno) | Set-Content -Path d:\ps-dummy.txt


$objShell = New-Object -ComObject ("WScript.Shell")
$objShortCut = $objShell.CreateShortcut($env:USERPROFILE + "\Desktop" + "\ps-dummy.lnk")
$objShortCut.TargetPath="C:\Windows\explorer.exe"
$objShortcut.Arguments = "d:\ps-dummy.txt"
$objShortCut.Save()
#>


($p1 + " " + $p2) | Out-File "d:\ps-dummy.txt" -Append

Unregister-ScheduledTask -TaskName "run Install-Starke-DMS_31_dummy.ps1 at logon" -Confirm:$false

# pause