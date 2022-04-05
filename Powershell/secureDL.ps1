$SecureUser     = Read-Host -Prompt “Enter your username”
$SecurePassword = Read-Host -Prompt “Enter your password” -AsSecureString
$SecureStringAsPlainText = $SecurePassword | ConvertFrom-SecureString
$SecureString = $SecureStringAsPlainText | ConvertTo-SecureString

curl.exe ftp://'$SecureUser':'$SecureString'@ftp.get--it.de/PowerShell-7.2.2-win-x64.msi --output C:\install\StarkeDMS-latest\PowerShell_TEST.msi --create-dirs


 # "ftp://get--it:get--IT2022@ftp.get--it.de/PowerShell-7.2.2-win-x64.msi"