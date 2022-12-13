13.12.2022 Eike Doose
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

EXAMPLES FOR INSTALLATION STRINGS

#####################################
#####################################
## .\Install-Starke-DMS_00/01.ps1 ##
# NFR environment
=====================================
.\Install-Starke-DMS_00.ps1 -FTPserver '192.168.120.11' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '56999'  
.\Install-Starke-DMS_01.ps1 -FTPserver '192.168.120.11' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '57999'  

# PRODUCTIVE environment (15.11.2022)
=====================================
.\Install-Starke-DMS_00.ps1 `
    -FTPserver '172.28.0.11' `
	-FTPuser 'AUTOINSTALLER' `
	-FTPpass 'wbutJzGFALFDrtmN' `
	-customerno '57999'

# after reboot
cd c:\install
dir
.\Install-Starke-DMS_01.ps1 `
    -FTPserver '172.28.0.11' `
	-FTPuser 'AUTOINSTALLER' `
	-FTPpass 'wbutJzGFALFDrtmN' `
	-UPDATE 'yes' `
	-customerno '57999'



# VMware lokal test environment (22.11.2022)
=====================================
.\Install-Starke-DMS_00.ps1 `
	-FTPserver '192.168.224.188' `
	-FTPuser 'hausmeister' `
	-FTPpass 'hausmeister' `
	-customerno '57999'

# after reboot
cd c:\install
dir
.\Install-Starke-DMS_01.ps1 `
	-FTPserver '192.168.224.188' `
	-FTPuser 'hausmeister' `
	-FTPpass 'hausmeister' `
	-UPDATE 'yes' `
	-customerno '57999'

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


parameter sample Install-Starke-DMS_02.ps1
===================================
25.04.2022 Eike Test NFR // CLOUD1MASTER1 50999 {5F900818-7977-4134-A741-2022C8059A5C}
.\Install-Starke-DMS_02.ps1 -FTPserver '192.168.120.11' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '50999' -LIZuser 'dockersetup' -LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -LIZserver 'https://starke-dms-license.azurewebsites.net' -LIZuid '{5F900818-7977-4134-A741-2022C8059A5C}' -LIZtargetdir 'd:\dms-config' -saPass 'saAdmin00!' 

25.04.2022 Eike Test NFR
Test Kunde 01 / {BB2D87B2-812D-4C62-BA40-7944B941B086} Test Kunde 01 / KDNR 56999
.\Install-Starke-DMS_02.ps1 -FTPserver '192.168.120.11' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '56999' -LIZuser 'dockersetup' -LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -LIZserver 'https://starke-dms-license.azurewebsites.net' -LIZuid '{BB2D87B2-812D-4C62-BA40-7944B941B086}' -LIZtargetdir 'd:\dms-config' -saPass 'saAdmin00!' 

25.04.2022 Eike Test NFR
Test Kunde 02 / {7666BBC5-7C53-4B17-9444-1CB0B707AF5C} Test Kunde 02 / KDNR 57999
.\Install-Starke-DMS_02.ps1 -FTPserver '192.168.120.11' -FTPuser 'get--IT' -FTPpass 'get--IT2022' -customerno '57999' -LIZuser 'dockersetup' -LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -LIZserver 'https://starke-dms-license.azurewebsites.net' -LIZuid '{7666BBC5-7C53-4B17-9444-1CB0B707AF5C}' -LIZtargetdir 'd:\dms-config' -saPass 'saAdmin00!' 

15.11.2022 Eike Test PRODUKTIV
Test Kunde 02 / {7666BBC5-7C53-4B17-9444-1CB0B707AF5C} Test Kunde 02 / KDNR 57999
.\Install-Starke-DMS_02.ps1 -FTPserver '172.28.0.11' -FTPuser 'AUTOINSTALLER' -FTPpass 'wbutJzGFALFDrtmN' -customerno '57999' -LIZuser 'dockersetup' -LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -LIZserver 'https://starke-dms-license.azurewebsites.net' -LIZuid '{7666BBC5-7C53-4B17-9444-1CB0B707AF5C}' -LIZtargetdir 'd:\dms-config' -saPass 'saAdmin00!' 

22.11.2022 Eike Test VMware Testumgebung lokal
Test Kunde 02 / {7666BBC5-7C53-4B17-9444-1CB0B707AF5C} Test Kunde 02 / KDNR 57999
.\Install-Starke-DMS_02.ps1 -FTPserver '192.168.224.188' -FTPuser 'hausmeister' -FTPpass 'hausmeister' -customerno '57999' -LIZuser 'dockersetup' -LIZpass 'S3VyendlaWwgUmV2aXZhbCBiZXdlaXNlbiE' -LIZserver 'https://starke-dms-license.azurewebsites.net' -LIZuid '{7666BBC5-7C53-4B17-9444-1CB0B707AF5C}' -LIZtargetdir 'd:\dms-config' -saPass 'saAdmin00!' 
