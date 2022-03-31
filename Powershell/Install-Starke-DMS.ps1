# 31.03.2022 Eike Doose / licenced commerical use only - do not distribute
# ========================================================================
New-Item -Name "install\StarkeDMS-latest" -ItemType Directory -Path "C:\"
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/StarkeDMSlatest.zip" --output C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/ABBYYlatest.zip" --output C:\install\StarkeDMS-latest\ABBYYlatest.zip
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\StarkeDMSlatest.zip -DestinationPath C:\install\StarkeDMS-latest
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\ABBYYlatest.zip -DestinationPath C:\install\StarkeDMS-latest
Remove-Item C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
Remove-Item C:\install\StarkeDMS-latest\ABBYYlatest.zip
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1-azure/main/Powershell/Install-Starke-DMS_setup.reg" --output C:\install\StarkeDMS-latest\StarkeDMS-setup.reg
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1-azure/main/Powershell/Install-Starke-DMS_setup.reg" --output C:\install\StarkeDMS-latest\ABBYY-setup.reg
reg import C:\install\StarkeDMS-latest\StarkeDMS-setup.reg /reg:32
reg import C:\install\StarkeDMS-latest\ABBYY-setup.reg /reg:32
# reg import https://github.com/E-J-D/sdms-cloud1-azure/blob/main/Powershell/Install-Starke-DMS_setup.reg /reg:32
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include ABBYY*.exe | Rename-Item -NewName ABBYY-latest.exe
# C:\install\StarkeDMS-latest\ABBYY-latest.exe
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include StarkeDMS*.exe | Rename-Item -NewName StarkeDMS-latest.exe
C:\install\StarkeDMS-latest\StarkeDMS-latest.exe /S
