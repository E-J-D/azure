
param (
	[Parameter(Mandatory=$true)][string]$sqlserver,
	[Parameter(Mandatory=$true)][string]$database,
	[Parameter(Mandatory=$true)][string]$username,
	[Parameter(Mandatory=$true)][string]$password,
	[Parameter(Mandatory=$true)][string]$configpath
)

cd "D:\dms-data\sql\Client SDK\ODBC\170\Tools\Binn\"

$sqlquery = 'SELECT name FROM ArchivPlus.versions WHERE description LIKE ""Datenbank Kundenindividuelle Struktur"";'
$olduid = .\SQLCMD.EXE -S localhost\SDMSCLOUD1 -d $customerno -Q "$sqlquery" -U 'sa' -P $saPass -h -1
$olduid = ($olduid -split '\r\n')[0]
$olduid = $olduid.Trim()
if ($olduid -match '\{.+\}') {
	$olduid = $Matches.0
	Write-Host Alte UID: $olduid
	$file = Get-Childitem –Path "$configpath" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Version(\{.+\})\.dat' }
	if (("$file" -ne '') -And ("$Matches.1" -ne '')) {
		$newuid = $Matches.1
		Write-Host Neue UID: $newuid
		$sqlupdate = "UPDATE ArchivPlus.versions SET name = """"db$newuid"""" WHERE name = """"db$olduid"""";"
		#Write-Host $sqlupdate
#		$updateresult = .\SQLCMD.EXE -S "$sqlserver" -d "$database" -Q "$sqlupdate" -U "$username" -P "$password" -h -1
		$updateresult = .\SQLCMD.EXE -S localhost\SDMSCLOUD1 -d $customerno -Q "$sqlupdate" -U 'sa' -P  $saPass -h -1
		$updateresult = $updateresult.Trim()
		Write-Host $updateresult
	} else {
		Write-Host Neue UID nicht gefunden.
	}
} else {
	Write-Host Alte UID nicht gefunden.
}

PrintJobDone "fix DB to new customer (fixLic) done"
Start-Sleep -s 2
# Clear-Host []
pause