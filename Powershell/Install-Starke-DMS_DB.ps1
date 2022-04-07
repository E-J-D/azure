# 07.04.2022 Boris Brixel
# .\dms-license-dbupdate.ps1 -sqlserver dbserver.starke.intern -database 'DMSDB' -username 'sa' -password 'geheim' -configpath 'C:\entwicklung\DMSDEV\Exe\config50999_3'
# .\Install-Starke-DMS_DB.ps1 -sqlserver localhost -database 'CLOUD1MASTER1' -username 'sa' -password 'Admin00!' -configpath 'd:\dms-config'
param (
	[Parameter(Mandatory=$true)][string]$sqlserver,
	[Parameter(Mandatory=$true)][string]$database,
	[Parameter(Mandatory=$true)][string]$username,
	[Parameter(Mandatory=$true)][string]$password,
	[Parameter(Mandatory=$true)][string]$configpath
)

#Get-Command -ModuleName 'sqlserver'
#Invoke-SqlCmd -ServerInstance $sqlserver -Database $database -Query $sqlquery -Username "$username" -Password "$password" -Verbose

$sqlquery = 'SELECT name FROM ArchivPlus.versions WHERE description LIKE ""Datenbank Kundenindividuelle Struktur"";'
$olduid = SQLCMD.EXE -S "$sqlserver" -d "$database" -Q "$sqlquery" -U "$username" -P "$password" -h -1
$olduid = ($olduid -split '\r\n')[0]
$olduid = $olduid.Trim()
if ($olduid -match '\{.+\}') {
	$olduid = $Matches.0
	Write-Host Alte UID: $olduid
	$file = Get-Childitem –Path "$configpath" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'Version(\{.+\})\.dat' }
	#Write-host $file
	#Write-Host ($Matches.1)
	if (("$file" -ne '') -And ("$Matches.1" -ne '')) {
		$newuid = $Matches.1
		Write-Host Neue UID: $newuid
		$sqlupdate = "UPDATE ArchivPlus.versions SET name = """"db$newuid"""" WHERE name = """"db$olduid"""";"
		#Write-Host $sqlupdate
		$updateresult = SQLCMD.EXE -S "$sqlserver" -d "$database" -Q "$sqlupdate" -U "$username" -P "$password" -h -1
		$updateresult = $updateresult.Trim()
		Write-Host $updateresult
	} else {
		Write-Host Neue UID nicht gefunden.
	}
} else {
	Write-Host Alte UID nicht gefunden.
}