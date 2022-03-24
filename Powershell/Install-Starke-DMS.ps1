New-Item -Name "install\StarkeDMS-latest" -ItemType Directory -Path "C:\"
curl.exe "ftp://get--it:get--IT2022@ftp.starke-dms.cloud/StarkeDMSlatest.zip" --output C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
Expand-Archive -LiteralPath C:\install\StarkeDMS-latest\StarkeDMSlatest.zip -DestinationPath C:\install\StarkeDMS-latest
Remove-Item C:\install\StarkeDMS-latest\StarkeDMSlatest.zip
curl.exe "ftp://get--it:get--IT2022@ftp.starke-dms.cloud/setup.reg" --output C:\install\StarkeDMS-latest\setup.reg
reg import C:\install\StarkeDMS-latest\setup.reg /reg:32
Get-ChildItem -Path C:\install\StarkeDMS-latest\* -Include StarkeDMS*.exe | Rename-Item -NewName StarkeDMS-latest.exe
C:\install\StarkeDMS-latest\StarkeDMS-latest.exe /S