# 24.03.2022 Eike Doose
# AutoInstaller for Starke-DMS®
# The file "setup.reg" definds which component will be installed. Change this file if neccessary.
#
# Use this PowerShell commands to start the installation.
# curl.exe "https://github.com/E-J-D/sdms-cloud1-azure/blob/ace2be38348ed804329a3501c2b6c6e9c8b4844a/Powershell/Install-Starke-DMS.ps1" 

New-Item -Name "install\StarkeDMS-latest" -ItemType Directory -Path "C:\"
curl.exe "ftp://get--it:get--IT2022@ftp.starke-dms.cloud/StarkeDMSlatest.zip" --output C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\StarkeDMSlatest.zip -DestinationPath C:\install\StarkeDMS-latest
Remove-Item C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
curl.exe "https://github.com/E-J-D/sdms-cloud1-azure/blob/main/Powershell/Install-Starke-DMS_setup.reg" --output C:\install\StarkeDMS-latest\setup.reg
reg import C:\install\StarkeDMS-latest\setup.reg /reg:32
# reg import https://github.com/E-J-D/sdms-cloud1-azure/blob/main/Powershell/Install-Starke-DMS_setup.reg /reg:32
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include StarkeDMS*.exe | Rename-Item -NewName StarkeDMS-latest.exe
C:\install\StarkeDMS-latest\StarkeDMS-latest.exe /S