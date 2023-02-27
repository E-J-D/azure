rem 08.12.2022 Eike Doose

rem c:
rem cd "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn"
SQLCMD.exe -S localhost -U sa -P Admin00! -i "d:\dms-data\backup\sql\backup-SQLExpress.sql" -o "d:\dms-data\backup\sql\backup-SQLExpress.txt"

rem 08.12.2022 Eike Doose
SQLCMD.exe -S SDMSC1-39506\SDMSCLOUD1 -U sa -P saAdmin00! -i "D:\dms-data\backup\sql\backup-SQLExpress.sql" -o "D:\dms-data\backup\sql\backup-SQLExpress.txt"

echo %DATE%
echo %TIME%
set datetimef=%date:~-4%_%date:~3,2%_%date:~0,2%__%time:~0,2%_%time:~3,2%_%time:~6,2%
echo %datetimef%

d:
cd "d:\dms-data\backup\sql"
rename CLOUD1-DB.bak CLOUD1-DB_%datetimef%.bak

forfiles /p "d:\dms-data\backup\sql" /m *.bak /d -14 /c "cmd /c del @path"

rem forfiles /p "D:\_DMSDaten\Backup\bak" /s /m *.* /d -7 /c "cmd /c del @path"
rem pause