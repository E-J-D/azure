# 05.04.2022 Eike Doose / licenced for commerical use only - do not distribute
# ============================================================================

# param (
#	[string]$FTPserver = 'ftp.get--it.de',
#	[Parameter(Mandatory=$true)][string]$FTPusername,
#	[Parameter(Mandatory=$true)][string]$FTPpassword,
#	[string]$uid,
#	[string]$customerno,
#	[Parameter(Mandatory=$true)][string]$targetdir
#)

# ============================================================================

cls

Write-Host -ForegroundColor Yellow "#######################################"
Write-Host -ForegroundColor Yellow "Starke-DMS® and ABBYY will be installed"
Write-Host -ForegroundColor Yellow "#######################################"

for ($i = 100; $i -gt 10; $i-- )
{
    Write-Progress -Activity "Countdown" -Status "$i%" -PercentComplete $i
    Start-Sleep -Milliseconds 25
}
cls
Write-Host -ForegroundColor Red "##########################################"
Write-Host -ForegroundColor Red "to cancel press STRG+C - otherwise any key"
Write-Host -ForegroundColor Red "##########################################"

pause

# download the PowerShell7 installer
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/PowerShell-7.2.2-win-x64.msi" --output C:\install\StarkeDMS-latest\PowerShell-7.2.2-win-x64.msi --create-dirs

# download the Notepad++ installer
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/npp.8.3.3.Installer.x64.exe" --output C:\install\StarkeDMS-latest\Notepad++Installer.exe --create-dirs

# download the latest Starke-DMS® installer
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/StarkeDMSlatest.zip" --output C:\install\StarkeDMS-latest\StarkeDMSlatest.zip --create-dirs

# download the latest ABBYY installer
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/ABBYYlatest.zip" --output C:\install\StarkeDMS-latest\ABBYYlatest.zip --create-dirs

# download the MSOLE DB driver
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/msoledbsql_18.6.3_x64.msi" --output C:\install\StarkeDMS-latest\msoledbsql_18.6.3_x64.msi --create-dirs

# expand the Starke-DMS® ZIP
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\StarkeDMSlatest.zip -DestinationPath C:\install\StarkeDMS-latest

# expand the ABBYY ZIP
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\ABBYYlatest.zip -DestinationPath C:\install\StarkeDMS-latest

# delete the downloaded ZIPs
Remove-Item C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
Remove-Item C:\install\StarkeDMS-latest\ABBYYlatest.zip

# download predefined installer registry keys
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1-azure/main/Powershell/Install-Starke-DMS_setup.reg" --output C:\install\StarkeDMS-latest\StarkeDMS-setup.reg --create-dirs
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1-azure/main/Powershell/Install-ABBYY_setup.reg" --output C:\install\StarkeDMS-latest\ABBYY-setup.reg --create-dirs

# import predefined installer registry keys
reg import C:\install\StarkeDMS-latest\StarkeDMS-setup.reg /reg:64
reg import C:\install\StarkeDMS-latest\ABBYY-setup.reg /reg:64

# rename the downloaded installer to *latest
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include StarkeDMS*.exe | Rename-Item -NewName StarkeDMS-latest.exe
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include ABBYY*.exe | Rename-Item -NewName ABBYY-latest.exe

# run the PowerShell7 installer in silent mode
Start-Process -wait -FilePath C:\install\StarkeDMS-latest\PowerShell-7.2.2-win-x64.msi -ArgumentList "/quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1"

# run the Notepad++ installer in silent mode
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\Notepad++Installer.exe' -ArgumentList /S -PassThru

# wait for the Notepadd++ installer to be finished
# Wait-Process -Name Notepa*
Start-Sleep -s 5

# run the Starke-DMS® installer in silent mode
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\StarkeDMS-latest.exe' -ArgumentList /S -PassThru

# wait for the Starke-DMS® installer to be finished
# Wait-Process -Name Starke*
Start-Sleep -s 5

# run the ABBYY installer in silent mode
Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\ABBYY-latest.exe' -ArgumentList /S -PassThru

# wait for the ABBYY installer to be finished
# Wait-Process -Name ABBYY*
Start-Sleep -s 5

# install MSOLE DB Driver
Start-Process -wait C:\install\StarkeDMS-latest\msoledbsql_18.6.3_x64.msi -ArgumentList "IACCEPTMSOLEDBSQLLICENSETERMS=YES /qn"

# message when everything is done
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Green  "##############  Install done  ##################"
Write-Host -ForegroundColor Green  "###  Thank you for using www.Starke-DMS.com  ###"
Write-Host -ForegroundColor Yellow "################################################"



################################################
## create media structur
################################################
New-Item -Path "d:\" -Name "dms-data" -ItemType "directory"
New-Item -Path "d:\" -Name "dms-config" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "documents" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "mail" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "pdf-converted" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "pool" -ItemType "directory"
New-Item -Path "d:\dms-data" -Name "preview" -ItemType "directory"




################################################
## Starke-DMS licence download
################################################

# docker tickets done in 03/2022
# DMS-2273 Lizenz vom LizenzServer abrufen
# https://starke.atlassian.net/browse/DMS-2273

#c:\install\get-dms-license.ps1 -username 'dockersetup' -password 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -server https://starke-dms-license.azurewebsites.net -uid '{6750BAE7-7E87-4E3A-93B3-874024C5478A}' -targetdir 'd:\dms-config'
#c:\install\get-dms-license.ps1 -username 'dockersetup' -password 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -server https://starke-dms-license.azurewebsites.net -customerno '50999_99' -targetdir 'd:\dms-config'


################################################
## Starke-DMS SQL DB config
################################################

Write-Host -ForegroundColor Yellow "##############################"
Write-Host -ForegroundColor Yellow "SQL database will be installed"
Write-Host -ForegroundColor Yellow "##############################"

for ($i = 100; $i -gt 10; $i-- )
{
    Write-Progress -Activity "Countdown" -Status "$i%" -PercentComplete $i
    Start-Sleep -Milliseconds 25
}

pause

# create the SQL DB
# DMS-2282 DMSServer Datenbankerstellung und Update ohne Oberflächenabfragen alles über Kommandozeilenparameter steuern
# https://starke.atlassian.net/browse/DMS-2282
# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-content?view=powershell-7.2
'[DB]','ConnectionString=Provider=MSOLEDBSQL;SERVER=192.168.224.10;DATABASE=CLOUD1MASTER1','[Network]','Port=27244','[Lizenz]','File=APLizenz.liz' | out-file d:\dms-config\DMSServer.ini
Start-Process -wait -filepath "C:\Program Files (x86)\StarkeDMS\win64\DMSServer.exe"  -ArgumentList '-AdminPwd "Admin00!" -cli -dbupdate -configpath d:\dms-config\'



################################################
## Starke-DMS services config
## https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-service?view=powershell-7.2
################################################

Write-Host -ForegroundColor Yellow "####################################"
Write-Host -ForegroundColor Yellow "DMS Server Service will be installed"
Write-Host -ForegroundColor Yellow "####################################"

# DMS Server
# -----------
pause
$params = @{
  Name = "DMS_Cloud1Master1_01_Server"
  BinaryPathName = 'C:\Program Files (x86)\StarkeDMS\win64\DMSServerSvc.exe /name "DMS_Cloud1Master1_01_Server" /ini DMSServer.ini /configpath "d:\dms-config"'
  StartupType = "AutomaticDelayedStart"
  Description = "Starke-DMS Server"
}
New-Service @params


Write-Host -ForegroundColor Yellow "############################################"
Write-Host -ForegroundColor Yellow "DMS LicenceManager Service will be installed"
Write-Host -ForegroundColor Yellow "############################################"


# DMS LicenceManager
# -----------------
pause
$params = @{
  Name = "DMS_Cloud1Master1_02_LicenceManager"
  BinaryPathName = 'C:\Program Files (x86)\StarkeDMS\win64\DMSLizenzmanagerSvc.exe /name "DMS_Cloud1Master1_02_LicenceManager" /Ini "DMSLicenceManager.ini" /ConfigPath "D:\dms-config"'
  StartupType = "AutomaticDelayedStart"
  Description = "Starke-DMS Licence Manager"
  DependsOn = "DMS_Cloud1Master1_01_Server"
}
New-Service @params


Write-Host -ForegroundColor Yellow "############################################"
Write-Host -ForegroundColor Yellow "DMS xyz Service will be installed"
Write-Host -ForegroundColor Yellow "############################################"


# DMS xyz
# -----------------




# delete DMS setup.exe 
Remove-Item C:\Program Files (x86)\StarkeDMS\setup\setup.exe