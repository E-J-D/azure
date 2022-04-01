# 31.03.2022 Eike Doose / licenced for commerical use only - do not distribute
# ============================================================================
#
# uninstall Starke-DMS® silent
# "c:\program files (x86)\StarkeDMS\uninst.exe" /S

# uninstall ABBYY silent
# "C:\Program Files (x86)\StarkeDMS\uninstabbyy.exe" /S

# create folder .\install\StarkeDMS-latest
# New-Item -Name "install\StarkeDMS-latest" -ItemType Directory -Path "C:\"

# download the latest Starke-DMS® installer
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/StarkeDMSlatest.zip" --output C:\install\StarkeDMS-latest\StarkeDMSlatest.zip --create-dirs

# download the latest ABBYY installer
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/ABBYYlatest.zip" --output C:\install\StarkeDMS-latest\ABBYYlatest.zip --create-dirs

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

# run the Starke-DMS® installer in silend mode
C:\install\StarkeDMS-latest\StarkeDMS-latest.exe /S

# wait for the Starke-DMS® installer to be finished
Wait-Process -Name Starke*
Start-Sleep -s 10

# run the ABBYY installer in silend mode
C:\install\StarkeDMS-latest\ABBYY-latest.exe /S
Wait-Process -Name ABBYY*
Start-Sleep -s 5

# message when everything is done
echo ################################################
echo #############  Everything done  ################
echo ######  Thank you for using Starke-DMS®  #######
echo ################################################