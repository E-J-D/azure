# 22.11.2022 Eike Doose / INTERNAL USER ONLY / do not distribute
# ============================================================================
# https://www.pdq.com/blog/silently-install-office-2016/


param (
	[string]$FTPserver = '172.28.0.11',
	[Parameter(Mandatory=$true)][string]$FTPuser,
	[Parameter(Mandatory=$true)][string]$FTPpass,
	[Parameter(Mandatory=$true)][string]$customerno,
	[Parameter(Mandatory=$true)][string]$LIZuser,
	[Parameter(Mandatory=$true)][string]$LIZpass,
	[string]$LIZserver = 'https://starke-dms-license.azurewebsites.net',
	[Parameter(Mandatory=$true)][string]$LIZuid,
	[string]$LIZtargetdir = 'd:\dms-config',
	[string]$LIZcustomerno,
	[Parameter(Mandatory=$true)][string]$saPass
)

# ============================================================================

################################################
## stop script on PowerShell error 
################################################
$ErrorActionPreference = "Stop"

################################################
## detect Powershe version - minimum 7
################################################
If ($PSVersionTable.PSVersion.Major -lt 7) {
    Throw "PowerShell version 7 or higher is required."
}
Clear-Host []

################################################
## intro and countdown
################################################

Write-Host -ForegroundColor Yellow "#######################################"
Write-Host -ForegroundColor Yellow "### Starke-DMS® unattended OFFICE install ####"
Write-Host -ForegroundColor Yellow "#######################################"
Start-Sleep -s 2
Clear-Host []



################################################
## Download section
################################################

Write-Host -ForegroundColor Green "##########################################"
Write-Host -ForegroundColor Green "######### downloading software ###########"
Write-Host -ForegroundColor Green "##########################################"


# download the Office installer
curl.exe ftp://""$FTPuser":"$FTPpass"@"$FTPserver"/SW_DVD5_Office_2016_64Bit_German_MLF_X20-42484.ISO" --ssl-reqd -k --output C:\install\StarkeDMS-latest\SW_DVD5_Office_2016_64Bit_German_MLF_X20-42484.ISO --create-dirs


################################################
## ISO mounten
################################################

Write-Host -ForegroundColor Green "##########################################"
Write-Host -ForegroundColor Green "########## mounting office ISO ###########"
Write-Host -ForegroundColor Green "##########################################"

Mount-DiskImage -ImagePath "C:\install\StarkeDMS-latest\SW_DVD5_Office_2016_64Bit_German_MLF_X20-42484.ISO"

Write-Host -ForegroundColor Green "##########################################"
Write-Host -ForegroundColor Green "########### software unzipped ############"
Write-Host -ForegroundColor Green "##########################################"
Start-Sleep -s 2
# Clear-Host []


################################################
## install office
################################################


# run the Microsoft Visual C++ 2015-2019 Redistributable (x64, x86) installer in silent mode
Write-Host -ForegroundColor Green "###################################################"
Write-Host -ForegroundColor Green "# installing Microsoft Visual C++ Redistributable #"
Write-Host -ForegroundColor Green "###################################################"

# Start-Process -Wait -FilePath 'C:\install\StarkeDMS-latest\VC_redist.x64.exe' -ArgumentList "/install /quiet /norestart"

Write-Host -ForegroundColor Yellow "#############################################"
Write-Host -ForegroundColor Green  "#### Microsoft Visual C++ Redistributable ###"
Write-Host -ForegroundColor Yellow "#############################################"
Write-Host 
Write-Host  
# Start-Sleep -s 2
# Clear-Host []
