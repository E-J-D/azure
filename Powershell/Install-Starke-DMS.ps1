New-Item -Name "install\StarkeDMS-latest" -ItemType Directory -Path "C:\"
curl.exe "ftp://get--it:get--IT2022@ftp.starke-dms.cloud/StarkeDMSlatest.zip" --output C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\StarkeDMSlatest.zip -DestinationPath C:\install\StarkeDMS-latest
Remove-Item C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
curl.exe "https://github.com/E-J-D/sdms-cloud1-azure/blob/eded9e56509c304e7216280fc5205c2545982081/Powershell/Install-Starke-DMS_setup.reg" --output C:\install\StarkeDMS-latest\setup.reg
reg import C:\install\StarkeDMS-latest\setup.reg /reg:32
# reg import https://github.com/E-J-D/sdms-cloud1-azure/blob/main/Powershell/Install-Starke-DMS_setup.reg /reg:32
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include StarkeDMS*.exe | Rename-Item -NewName StarkeDMS-latest.exe
C:\install\StarkeDMS-latest\StarkeDMS-latest.exe /S