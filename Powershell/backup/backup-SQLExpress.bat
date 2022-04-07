rem 07.04.2022 Eike Doose

rem c:
rem cd "C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\130\Tools\Binn"
SQLCMD.exe -S localhost -U sa -P Admin00! -i "d:\dms-data\backup\backup-SQLExpress.sql" -o "d:\dms-data\backup\backup-SQLExpress.txt"

d:
cd "d:\dms-data\backup"
rename CLOUD1-DB.bak CLOUD1-DB_%date%.bak

forfiles /p "d:\dms-data\backup" /m *.bak /d -14 /c "cmd /c del @path"

rem forfiles /p "D:\_DMSDaten\Backup\bak" /s /m *.* /d -7 /c "cmd /c del @path"
rem pause