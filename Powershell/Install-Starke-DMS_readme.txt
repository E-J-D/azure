25.03.2023 Eike Doose
AutoInstaller for Starke-DMS®
The files "Install-Starke-DMS*" does the silent install. Change this file if neccessary.

Use this PowerShell commands to initiate the installation.

curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/AutoInstaller.ps1" --output c:\install\AutoInstaller.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_CONFIG.psd1" --output c:\install\Install-Starke-DMS_CONFIG.psd1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_00.ps1" --output c:\install\Install-Starke-DMS_00.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_01.ps1" --output c:\install\Install-Starke-DMS_01.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_02.ps1" --output c:\install\Install-Starke-DMS_02.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
Set-Location -Path 'c:\install'
dir
notepad c:\install\Install-Starke-DMS_CONFIG.psd1

When the CONFIG is filled with project details, run .\AutoInstaller.ps1

#####################################
#####################################

PART - APACHE UPDATE
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/install-Starke-DMS_21_ApacheUpdate.ps1" --output c:\install\install-Starke-DMS_21_ApacheUpdate.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
Set-Location -Path 'c:\install'
dir
.\Install-Starke-DMS_21_ApacheUpdate.ps1 `
	-FTPserver 'ftp-server-name' `
	-FTPuser 'ftpusername' `
	-FTPpass 'ftppassword' 
