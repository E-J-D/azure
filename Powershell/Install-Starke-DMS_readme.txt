30.11.2022 Eike Doose
AutoInstaller for Starke-DMS®
The files "Install-Starke-DMS*" does the silent install. Change this file if neccessary.

Use this PowerShell commands to start the installation.

curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/AutoUpdate.ps1" --output c:\install\AutoUpdate.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_00.ps1" --output c:\install\Install-Starke-DMS_00.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_01.ps1" --output c:\install\Install-Starke-DMS_01.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
curl.exe "https://raw.githubusercontent.com/E-J-D/sdms-cloud1/main/Powershell/Install-Starke-DMS_02.ps1" --output c:\install\Install-Starke-DMS_02.ps1 --create-dirs  -H "Cache-Control: no-cache, no-store"
cd c:\install
dir


#####################################
#####################################
## .\Install-Starke-DMS_00/01.ps1 ##
# NFR environment
=====================================
.\Install-Starke-DMS_01.ps1 -FTPserver '192.168.120.11' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '56999'  
.\Install-Starke-DMS_01.ps1 -FTPserver '192.168.120.11' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '57999'  

# PRODUCTIVE environment (15.11.2022)
=====================================
.\Install-Starke-DMS_01.ps1 -FTPserver '172.28.0.11' -FTPuser 'AUTOINSTALLER' -FTPpass 'wbutJzGFALFDrtmN' -customerno '57999'

# VMware lokal test environment (22.11.2022)
=====================================
.\Install-Starke-DMS_00.ps1 `
	-FTPserver '192.168.224.188' `
	-FTPuser 'hausmeister' `
	-FTPpass 'hausmeister' `
	-customerno '57999'

.\Install-Starke-DMS_01.ps1 `
	-FTPserver '192.168.224.188' `
	-FTPuser 'hausmeister' `
	-FTPpass 'hausmeister' `
	-customerno '57999'


#####################################
#####################################
## .\Install-Starke-DMS_02.ps1 ##
NFR environment
=====================================


=====================================
PRODUCTIVE environment (15.11.2022)
=====================================
.\Install-Starke-DMS_02.ps1 -FTPserver '172.28.0.11' -FTPuser 'AUTOINSTALLER' -FTPpass 'wbutJzGFALFDrtmN' -customerno '57999' -LIZuser 'dockersetup' -LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -LIZserver 'https://starke-dms-license.azurewebsites.net' -LIZuid '{7666BBC5-7C53-4B17-9444-1CB0B707AF5C}' -LIZtargetdir 'd:\dms-config' -saPass 'saAdmin00!' 

=====================================
VMware lokal test environment (22.11.2022)
=====================================
Test Kunde 02 / {7666BBC5-7C53-4B17-9444-1CB0B707AF5C} Test Kunde 02 / KDNR 57999
cd c:\install
dir
.\Install-Starke-DMS_02.ps1 `
	-FTPserver '192.168.224.188' `
	-FTPuser 'hausmeister' `
	-FTPpass 'hausmeister' `
	-customerno '57999' `
	-LIZuser 'dockersetup' `
	-LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' `
	-LIZserver 'https://starke-dms-license.azurewebsites.net' `
	-LIZuid '{7666BBC5-7C53-4B17-9444-1CB0B707AF5C}' `
	-LIZtargetdir 'd:\dms-config' `
	-saPass 'saAdmin00!' `
	-UPDATE 'yes'
