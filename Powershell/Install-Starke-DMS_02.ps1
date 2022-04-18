# 07.04.2022 Eike Doose / licensed for commerical use only - do not distribute
# ============================================================================
#
# -FTPserver
#  > specify the FTP server which will be used for downloading the software / e.g. -FTPserver 'ftp.get--it.de'
#
# -FTPuser
#  > name the FTP server user for logging into the FTP server / e.g. -FTPuser 'username'
# 
# -FTPpass
#  > password for logging into the FTP server / e.g. -FTPpass 'verysecretpassword'
#
# -customerno
#  > client customer number which is needed for naming the new server and the database creation / e.g. -customerno '23545'
#
# -LIZuser
#  > username for using the license server / e.g. -LIZuser 'username'
#
# -LIZpass
#  > password for logging into the license server / e.g. -FTPpass 'licenseuserpass'
#
# -LIZserver
#  > URL of the license server / e.g. -LIZserver 'license.starke.cloud'
#
# -LIZuid
#  > license UID to be downloaded / e.g. -LIZuid '{5C395FDC-6A94-32BE-BAD4-918D9B324AFG}'
#
# -LIZcustomerno
#  > license custom number to be downloaded / e.g. -LIZcustomerno '23545'
#  > not needed if LIZuid is given
#
# -LIZtargetdir
#  > directory to where the license file will be downloaded / e.g. -LIZtargetdir 'd:\dms-config' 
#
# -saPass
#  > sa password for the database / e.g. -saPass 'secretsapassword' 
#
#
# parameter sample

# 14.04.2022 14:13 get--IT 50999
# .\Install-Starke-DMS_02.ps1 -FTPserver 'ftp.get--it.de' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '50999' -LIZuser 'dockersetup' -LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -LIZserver 'https://starke-dms-license.azurewebsites.net' -LIZuid '{EB706E3D-8948-4C2D-95BF-0A30FB092147}' -LIZtargetdir 'd:\dms-config' -saPass 'saAdmin00!' 

param (
	[string]$FTPserver = 'ftp.get--it.de',
	[Parameter(Mandatory=$true)][string]$FTPuser,
	[Parameter(Mandatory=$true)][string]$FTPpass,
	
	[Parameter(Mandatory=$true)][string]$customerno,

	[Parameter(Mandatory=$true)][string]$LIZuser,
	[Parameter(Mandatory=$true)][string]$LIZpass,
	[string]$LIZserver,
	[string]$LIZuid,
	[string]$LIZtargetdir,
	[string]$LIZcustomerno,

	[Parameter(Mandatory=$true)][string]$saPass
)

# ============================================================================

################################################
## stop script on PowerShell error 
################################################

$ErrorActionPreference = "Stop"


################################################
## detect Powershe version - minimum 7
################################################

# Detect PowerShell version.
If ($PSVersionTable.PSVersion.Major -lt 7) {
    Throw "PowerShell version 7 or higher is required."
}

cls

################################################
## intro and countdown
################################################

Write-Host 
Write-Host  
Write-Host 
Write-Host  
Write-Host -ForegroundColor Yellow "#######################################"
Write-Host -ForegroundColor Yellow "### Starke-DMS® unattended install ####"
Write-Host -ForegroundColor Yellow "#######################################"

#$Start = Get-Date
#$Duration = New-TimeSpan -Seconds 5
#$End = $Start + $Duration
#Do{
#    Start-Sleep -Seconds 1
#    $DisplayTime = New-TimeSpan -Start $(Get-Date) -End $End
#    $Time = "{0:D2}:{1:D2}" -f ($DisplayTime.Minutes),  ($DisplayTime.Seconds)
#    Write-Progress $Time 
#}
#While((Get-date) -lt $End)

cls
#Write-Host -ForegroundColor Red "##########################################"
#Write-Host -ForegroundColor Red "to cancel press STRG+C - otherwise any key"
#Write-Host -ForegroundColor Red "##########################################"
#[Console]::ReadKey()


################################################
## set language and rename computer to customerno
################################################

Set-WinUILanguageOverride -Language de-DE
Set-Culture de-DE
Set-WinUserLanguageList de-DE -Force


################################################
## Download section
################################################

Write-Host -ForegroundColor Green "##########################################"
Write-Host -ForegroundColor Green "######### downloading software ###########"
Write-Host -ForegroundColor Green "##########################################"

# download the license script
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_license.ps1" --output C:\install\Install-Starke-DMS_license.ps1 --create-dirs

# download the DB fix script
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_DBfixLic.ps1" --output C:\install\Install-Starke-DMS_DBfixLic.ps1 --create-dirs

# download predefined installer registry keys
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_setup.reg" --output C:\install\StarkeDMS-latest\StarkeDMS-setup.reg --create-dirs
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-ABBYY_setup.reg" --output C:\install\StarkeDMS-latest\ABBYY-setup.reg --create-dirs

# download the PowerShell7 installer
# curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/PowerShell-7.2.2-win-x64.msi" --ssl-reqd -k --output C:\install\StarkeDMS-latest\PowerShell-7.2.2-win-x64.msi --create-dirs

# download the Notepad++ installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/npp.8.3.3.Installer.x64.exe" --ssl-reqd -k --output C:\install\StarkeDMS-latest\npp.8.3.3.Installer.x64.exe --create-dirs

# download the MC installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/mcwin32-build226-setup.exe" --ssl-reqd -k --output C:\install\StarkeDMS-latest\mcwin32-build226-setup.exe --create-dirs

# download the latest Starke-DMS® installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/StarkeDMSlatest.zip" --ssl-reqd -k --output C:\install\StarkeDMS-latest\StarkeDMSlatest.zip --create-dirs

# download the latest sql express installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/SQLEXPRADV_x64_DEU.exe" --ssl-reqd -k --output C:\install\StarkeDMS-latest\SQLEXPRADV_x64_DEU.exe --create-dirs

# download the latest sql express ini
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/SQLEXPRADV_x64_DEU.ini" --ssl-reqd -k --output C:\install\StarkeDMS-latest\SQLEXPRADV_x64_DEU.ini --create-dirs

# download the latest ssms installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/SSMS-Setup-ENU.exe" --ssl-reqd -k --output C:\install\StarkeDMS-latest\SSMS-Setup-ENU.exe --create-dirs

# download the latest ABBYY installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/ABBYYlatest.zip" --ssl-reqd -k --output C:\install\StarkeDMS-latest\ABBYYlatest.zip --create-dirs

# download the MSOLE DB driver
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/msoledbsql_18.6.3_x64.msi" --ssl-reqd -k --output C:\install\StarkeDMS-latest\msoledbsql_18.6.3_x64.msi --create-dirs

# download the MS ODBC SQL DB driver
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/msodbcsql17.msi" --ssl-reqd -k --output C:\install\StarkeDMS-latest\msodbcsql17.msi --create-dirs

# download the MsSqlCmdLnUtils sqlcmd.exe
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/MsSqlCmdLnUtils.msi" --ssl-reqd -k --output C:\install\StarkeDMS-latest\MsSqlCmdLnUtils.msi --create-dirs

# download the Template DB
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/SQL-DB-CLOUD1MASTER1.bak" --ssl-reqd -k --output C:\install\StarkeDMS-latest\SQL-DB-CLOUD1MASTER1.bak --create-dirs



################################################
## unzip 
################################################

# expand the Starke-DMS ZIP
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\StarkeDMSlatest.zip -DestinationPath C:\install\StarkeDMS-latest

# expand the sql express setup
Start-Process -wait C:\install\StarkeDMS-latest\SQLEXPRADV_x64_DEU.exe -ArgumentList "/q /x:C:\install\StarkeDMS-latest\SQL"

# expand the ABBYY ZIP
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\ABBYYlatest.zip -DestinationPath C:\install\StarkeDMS-latest

# delete the downloaded ZIPs
Remove-Item C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
Remove-Item C:\install\StarkeDMS-latest\ABBYYlatest.zip

# rename the downloaded installer to *latest
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include StarkeDMS*.exe | Rename-Item -NewName StarkeDMS-latest.exe
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include ABBYY*.exe | Rename-Item -NewName ABBYY-latest.exe


################################################
## import predefined registry keys
################################################

reg import C:\install\StarkeDMS-latest\StarkeDMS-setup.reg /reg:64
reg import C:\install\StarkeDMS-latest\ABBYY-setup.reg /reg:64


################################################
## install all the stuff
################################################

# 14.04.22 separate ps1 file
# run the PowerShell7 installer in silent mode
# Start-Process -wait -FilePath C:\install\StarkeDMS-latest\PowerShell-7.2.2-win-x64.msi -ArgumentList "/quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1"
#Write-Host -ForegroundColor Yellow "################################################"
#Write-Host -ForegroundColor Green  "######### PowerShell 7 installed ###############"
#Write-Host -ForegroundColor Yellow "################################################"
#Write-Host 
#Write-Host  

# run the Notepad++ installer in silent mode
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\npp.8.3.3.Installer.x64' -ArgumentList /S -PassThru
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "############ Notepad++ installed ###############"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  

# run the MC installer in silent mode
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\mcwin32-build226-setup.exe' -ArgumentList "/VERYSILENT /NORESTART"
Write-Host -ForegroundColor Yellow "#########################################"
Write-Host -ForegroundColor Green  "############ MC installed ###############"
Write-Host -ForegroundColor Yellow "#########################################"
Write-Host 
Write-Host  

# run the Starke-DMS installer in silent mode and wait 3sec
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\StarkeDMS-latest.exe' -ArgumentList /S -PassThru
Start-Sleep -s 3
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "########### Starke-DMS® installed ##############"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  

# run the ABBYY installer in silent mode and wait 3sec
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\ABBYY-latest.exe' -ArgumentList /S -PassThru
Start-Sleep -s 3
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "######### ABBYY engine installed ###############"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  

# run the sql express installer in silent mode and wait 3sec
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\SQL\setup.exe' -ArgumentList "/ConfigurationFile=C:\install\StarkeDMS-latest\SQLEXPRADV_x64_DEU.ini /SAPWD=$saPass"
Start-Sleep -s 3
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "######### SQL DB engine installed ##############"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host

# install sql powershell util
Install-Module -Name NuGet -force
#Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name SqlServer -force
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "##### SqlServer PowerShell utils installed #####"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host


# install MSOLE DB driver
# not necessary if sql express is already installed 
#Start-Process -wait C:\install\StarkeDMS-latest\msoledbsql_18.6.3_x64.msi -ArgumentList "IACCEPTMSOLEDBSQLLICENSETERMS=YES /qn"
#Write-Host -ForegroundColor Yellow "################################################"
#Write-Host -ForegroundColor Green  "########### MSOLEDBSQL installed ###############"
#Write-Host -ForegroundColor Yellow "################################################"
#Write-Host 
#Write-Host  

# install MS ODBC SQL17 driver
# not necessary if sql express is already installed
#Start-Process -wait C:\install\StarkeDMS-latest\msodbcsql17.msi -ArgumentList "IACCEPTMSODBCSQLLICENSETERMS=YES /qn"
#Write-Host -ForegroundColor Yellow "################################################"
#Write-Host -ForegroundColor Green  "########### MSODBCSQL18 installed ##############"
#Write-Host -ForegroundColor Yellow "################################################"
#Write-Host 
#Write-Host  

# install SSMS
Start-Process -Wait -FilePath c:\install\StarkeDMS-latest\SSMS-Setup-ENU.exe -ArgumentList "/install /quiet /norestart"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "############## SSMS installed ##################"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  


# install MS SQL Utils (SQLCMD.exe) toolset
# ???? not necessary if ssms is already installed
Start-Process -wait C:\install\StarkeDMS-latest\MsSqlCmdLnUtils.msi -ArgumentList "IACCEPTMSSQLCMDLNUTILSLICENSETERMS=YES /qn"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "########### MQOLEDBSQL installed ###############"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  

# message when everything is done
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "############  Installation done  ###############"
Write-Host -ForegroundColor Green  "###  Thank you for using www.Starke-DMS.com  ###"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  

# message continue to customer config
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "###############  press any key #################"
Write-Host -ForegroundColor Green  "###  to continue with customer config, lic++ ###"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  
# press any key to continue
[Console]::ReadKey()


################################################
## create media structure
################################################
Write-Host -ForegroundColor Green "##########################################"
Write-Host -ForegroundColor Green "######## creating media structur #########"
Write-Host -ForegroundColor Green "##########################################"

# press any key to continue
[Console]::ReadKey()


#New-Item -Path "d:\" -Name "dms-data" -ItemType "directory"
New-Item -Path "d:\" -Name "dms-config" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "documents" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "mail" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "pdf-converted" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "pool" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "preview" -ItemType "directory"
#New-Item -Path "d:\dms-data" -Name "backup" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "sql" -ItemType "directory"
#New-Item -Path "d:\dms-data\backup" -Name "sql" -ItemType "directory"


################################################
## Starke-DMS license download
################################################

# message continue to customer config
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "###############  press any key #################"
Write-Host -ForegroundColor Green  "######  to continue with license download ######"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  
# press any key to continue
[Console]::ReadKey()

# Start-Process -wait "C:\Program Files\PowerShell\7\pwsh.exe" -ArgumentList "c:\install\Install-Starke-DMS_license.ps1 -username $LIZuser -password $LIZpass -server https://starke-dms-license.azurewebsites.net -uid $LIZuid -targetdir $LIZtargetdir" 
c:\install\Install-Starke-DMS_license.ps1 -username $LIZuser -password $LIZpass -server https://starke-dms-license.azurewebsites.net -uid $LIZuid -targetdir $LIZtargetdir


################################################
## Starke-DMS SQL DB config
################################################

Write-Host -ForegroundColor Yellow "#####################################"
Write-Host -ForegroundColor Yellow "### SQL database will be installed ##"
Write-Host -ForegroundColor Yellow "#####################################"
Write-Host
Write-Host


Write-Host -ForegroundColor Yellow "#####################################"
Write-Host -ForegroundColor Yellow "### press any key, CRTL-C to stop ###"
Write-Host -ForegroundColor Yellow "#####################################"
Write-Host
Write-Host

# press ENTER to continue
[Console]::ReadKey()

# create DMSServer.ini
'[DB]','ConnectionString=Provider=MSOLEDBSQL;SERVER=localhost\SDMSCLOUD1;DATABASE=CLOUD1MASTER1','[Network]','Port=27244','[Lizenz]','File=APLizenz.liz' | out-file d:\dms-config\DMSServer.ini

# create initial DB
Start-Process -wait -filepath "C:\Program Files (x86)\StarkeDMS\win64\DMSServer.exe"  -ArgumentList "-AdminPwd $saPass -cli -dbupdate -configpath $LIZtargetdir"

Write-Host -ForegroundColor Yellow "#####################################"
Write-Host -ForegroundColor Yellow "### SQL restore press any key, CRTL-C to stop ###"
Write-Host -ForegroundColor Yellow "#####################################"
Write-Host
Write-Host

# press ENTER to continue
[Console]::ReadKey()
# CLOUD1MASTER1 restore

cd "D:\dms-data\sql\Client SDK\ODBC\170\Tools\Binn\"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "RESTORE DATABASE [CLOUD1MASTER1] FROM  DISK = N'C:\install\StarkeDMS-latest\SQL-DB-CLOUD1MASTER1.bak' WITH  FILE = 1,  MOVE N'CLOUD1MASTER1_Pri' TO N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\CLOUD1MASTER1_Pri.mdf',  MOVE N'CLOUD1MASTER1_Dat' TO N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\CLOUD1MASTER1_Dat.ndf',  MOVE N'CLOUD1MASTER1_txt' TO N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\CLOUD1MASTER1_Txt.ndf',  MOVE N'CLOUD1MASTER1_Log' TO N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\CLOUD1MASTER1_Log.ldf',  NOUNLOAD,  REPLACE,  STATS = 5;"

# rename DB to DB$customerno
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "ALTER DATABASE CLOUD1MASTER1 SET SINGLE_USER WITH ROLLBACK IMMEDIATE;"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "ALTER DATABASE CLOUD1MASTER1 MODIFY FILE (NAME=N'CLOUD1MASTER1_Pri', NEWNAME=N'$customerno-pri');"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "ALTER DATABASE CLOUD1MASTER1 MODIFY FILE (NAME=N'CLOUD1MASTER1_Log', NEWNAME=N'$customerno-log');"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "ALTER DATABASE CLOUD1MASTER1 MODIFY FILE (NAME=N'CLOUD1MASTER1_Dat', NEWNAME=N'$customerno-dat');"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "ALTER DATABASE CLOUD1MASTER1 MODIFY FILE (NAME=N'CLOUD1MASTER1_Txt', NEWNAME=N'$customerno-txt');"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "EXEC master.dbo.sp_detach_db @dbname = N'CLOUD1MASTER1'"

# rename DB files 
Get-ChildItem D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\CLOUD1MASTER1* | Rename-Item -NewName { $_.Name -replace '_','-' }
Get-ChildItem D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\CLOUD1MASTER1* | Rename-Item -NewName { $_.Name -replace 'CLOUD1MASTER1',$customerno }

# create renamed DB
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "CREATE DATABASE CLOUD1MASTER1 ON ( FILENAME = N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\$customerno-pri.mdf' ), ( FILENAME = N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\$customerno-log.ldf' ), ( FILENAME = N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\$customerno-dat.ndf' ), ( FILENAME = N'D:\dms-data\sql\MSSQL15.SDMSCLOUD1\MSSQL\DATA\$customerno-txt.ndf' ) FOR ATTACH;"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "ALTER DATABASE CLOUD1MASTER1 SET MULTI_USER;"
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -P $saPass -Q "ALTER DATABASE CLOUD1MASTER1 MODIFY NAME = [$customerno];"

# change DB in DMSServer.ini to new DB name
'[DB]',"ConnectionString=Provider=MSOLEDBSQL;SERVER=localhost\SDMSCLOUD1;DATABASE=$customerno",'[Network]','Port=27244','[Lizenz]','File=APLizenz.liz' | out-file d:\dms-config\DMSServer.ini

# fix DB to new customer
C:\install\Install-Starke-DMS_DBfixLic.ps1 -sqlserver localhost\SDMSCLOUD1 -database $customerno -username 'sa' -password $saPass -configpath $LIZtargetdir

# update system DB user
.\sqlcmd -S localhost\SDMSCLOUD1 -U SA -d $customerno -P $saPass -Q "ALTER USER ArchivPlus WITH LOGIN = ArchivPlus;"


################################################
## Starke-DMS services config
## https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-service?view=powershell-7.2
################################################

# DMS Server service install
# --------------------------
Write-Host -ForegroundColor Yellow "####################################"
Write-Host -ForegroundColor Yellow "DMS Server Service will be installed"
Write-Host -ForegroundColor Yellow "####################################"
Write-Host
Write-Host -ForegroundColor Yellow "#########  press any key  ##########"

# press any key to continue
[Console]::ReadKey()

$params = @{
  Name = "DMS_01_Server"
  BinaryPathName = 'C:\Program Files (x86)\StarkeDMS\win64\DMSServerSvc.exe /name "DMS_01_Server" /ini DMSServer.ini /configpath "d:\dms-config"'
  StartupType = "AutomaticDelayedStart"
  Description = "Starke-DMS Server"
}
New-Service @params



# DMS LicenseManager service install
# ----------------------------------
Write-Host -ForegroundColor Yellow "############################################"
Write-Host -ForegroundColor Yellow "DMS LicenseManager service will be installed"
Write-Host -ForegroundColor Yellow "############################################"
Write-Host
Write-Host -ForegroundColor Yellow "#############  press any key  ##############"

# press any key to continue
[Console]::ReadKey()

#'[DB]','ConnectionString=Provider=MSOLEDBSQL;SERVER=localhost\SDMSCLOUD1;DATABASE=$customerno,'[Network]','Port=27244','[Lizenz]','File=APLizenz.liz' | out-file d:\dms-config\DMSLicenseManager.ini
'[Service]','User=system','Password=system','Server=localhost','Port=27244' | out-file d:\dms-config\DMSLicenseManager.ini


$params = @{
  Name = "DMS_02_LicenseManager"
  BinaryPathName = 'C:\Program Files (x86)\StarkeDMS\win64\DMSLizenzmanagerSvc.exe /name "DMS_02_LicenseManager" /Ini "DMSLicenseManager.ini" /ConfigPath "D:\dms-config"'
  StartupType = "AutomaticDelayedStart"
  Description = "Starke-DMS License Manager"
  DependsOn = "DMS_01_Server"
}
New-Service @params



# DMS xyz service install
# ----------------------------------

Write-Host -ForegroundColor Yellow "############################################"
Write-Host -ForegroundColor Yellow "DMS xyz  service will be installed"
Write-Host -ForegroundColor Yellow "############################################"
Write-Host
Write-Host -ForegroundColor Yellow "######### press ENTER to continue ##########"

# press ENTER to continue
[Console]::ReadKey()


# message continue to customer config
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "###############  press any key #################"
Write-Host -ForegroundColor Green  "###### to continue cleaning up everything ######"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host 
Write-Host  
Write-Host -ForegroundColor Yellow "######### press ENTER to continue ##########"
# press ENTER to continue
[Console]::ReadKey()


################################################
## cleaning up
################################################

# delete DMS setup.exe 
Remove-Item "C:\Program Files (x86)\StarkeDMS\setup\setup.exe"
# Remove-Item C:\install\StarkeDMS-latest\ -Recurse -Force -Confirm:$false
Remove-Item C:\install\ -Recurse -Force -Confirm:$false
Clear-RecycleBin -Force
Start-Sleep -s 2
'[Info]','setup.exe was deleted after autoinstall' | out-file "C:\Program Files (x86)\StarkeDMS\setup\info.txt"
New-Item -Path "c:\" -Name "install" -ItemType "directory"
Start-Sleep -s 2
'[Info]','everything was deleted after autoinstall' | out-file "C:\install\info.txt"

################################################
## restart computer
################################################
Write-Host -ForegroundColor Red "################################################"
Write-Host -ForegroundColor Red "## Computer will be restarted - press any key ##"
Write-Host -ForegroundColor Red "################################################"
Write-Host
Write-Host -ForegroundColor Yellow "#############  press any key  ##############"
[Console]::ReadKey()
Restart-computer -force