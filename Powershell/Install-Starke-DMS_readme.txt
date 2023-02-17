18.12.2022 Eike Doose
AutoInstaller for Starke-DMS®
The files "Install-Starke-DMS*" does the silent install. Change this file if neccessary.

Use this PowerShell commands to start the installation.

curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/AutoUpdate.ps1" --output c:\install\AutoUpdate.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_00.ps1" --output c:\install\Install-Starke-DMS_00.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_01.ps1" --output c:\install\Install-Starke-DMS_01.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_02.ps1" --output c:\install\Install-Starke-DMS_02.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
Set-Location -Path 'c:\install'
dir

#####################################
#####################################

EXAMPLES FOR INSTALLATION STRINGS

#####################################
#####################################

PART 1 OF 3
Set-Location -Path 'c:\install'
.\Install-Starke-DMS_00.ps1 -customerno '12345'

PART 2 OF 3
# after reboot
Set-Location -Path 'c:\install'
.\Install-Starke-DMS_01.ps1 -FTPserver 'ftp.get--it.de' -FTPuser 'ftpusername' -FTPpass 'ftppassword' -customerno '12345' -UPDATE 'yes'

PART 3 OF 3
# after reboot
Set-Location -Path 'c:\install'
.\Install-Starke-DMS_02.ps1 `
	-FTPserver 'ftp-server-name' `
	-FTPuser 'ftpusername' `
	-FTPpass 'ftppassword' `
	-customerno '12345' `
	-LIZuser 'lizusername' `
	-LIZpass 'lizpassword' `
	-LIZserver 'lizservername' `
	-LIZuid '{lizuid_of_costumerlicence}' `
	-LIZtargetdir 'd:\dms-config' `
	-saPass 'sapassword' `
	-UPDATE 'yes'

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
