$SQLInstance = "localhost\SDMSCLOUD1"
#$Date = Get-Date -format yyyyMMdd
#Backup-SqlDatabase  -ServerInstance $SQLInstance `
#                    -Database $DBName `
#                    -CopyOnly `
#                    -CompressionOption on `
#                    -BackupFile "$($SharedFolder)\$DBName-$date.bak" `
#                    -BackupAction Database `
#                    -checksum ` 
#                    -verbose

$DBName = "50999"
$Backupfile = "C:\install\StarkeDMS-latest\SQL-DB-CLOUD1MASTER1.bak"
#Restore-SqlDatabase  -ServerInstance $SQLInstance -Database "$DbNAme" -BackupFile "$Backupfile" -verbose -AutoRelocateFile

Restore-SqlDatabase -ServerInstance $SQLInstance `
-Database "$DbNAme" `
-BackupFile "$Backupfile" `
-verbose `
-AutoRelocateFile


#-RestoreAction Database |

#					 -ReplaceDatabase |
					  ;
#					 -RelocateFile |
#					 -SqlCredential |
#					;