# 01.04.2022 Eike Doose / licenced for commerical use only - do not distribute
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

Write-Host -ForegroundColor Yellow "##############################"
Write-Host -ForegroundColor Yellow "####### License missing ######"
Write-Host -ForegroundColor Yellow "##############################"

# create the SQL DB
;'[DB]','ConnectionString=Provider=MSOLEDBSQL;SERVER=192.168.224.10;DATABASE=CLOUD1MASTER1','[Network]','Port=27244','[Lizenz]','File=APlizenz.liz' | out-file d:\dms-config\DMSServer.ini
;Start-Process -wait -filepath "C:\Program Files (x86)\StarkeDMS\win64\DMSServer.exe"  -ArgumentList '-AdminPwd "Admin00!" -cli -dbupdate -configpath d:\dms-config\'


################################################
## Starke-DMS services config
################################################

Write-Host -ForegroundColor Yellow "####################################"
Write-Host -ForegroundColor Yellow "DMS Server Service will be installed"
Write-Host -ForegroundColor Yellow "####################################"

pause
;Start-Process -wait -filepath "C:\Program Files (x86)\StarkeDMS\win64\DMSServerSvc.exe"  -ArgumentList '/install /name DMSServer_CLOUD1MASTER1 /ini DMSServer.ini /configpath "d:\dms-config"'
