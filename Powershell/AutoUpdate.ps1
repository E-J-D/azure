# 02.12.2022 Eike Doose
#	Windows Updates with PowerShell
# http://woshub.com/pswindowsupdate-module/
# https://www.itechtics.com/run-windows-update-cmd/

# Install PSWindowsUpdate Modul for PowerShell
Write-Host 
Write-Host -ForegroundColor Yellow "################################################"
Write-Host -ForegroundColor Yellow "# Install PSWindowsUpdate modul for PowerShell #"
Write-Host -ForegroundColor Yellow "################################################"
Write-Host
# pause

Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Start-Sleep -s 2
Register-PSRepository -Default
Start-Sleep -s 2
Install-Module -Name PSWindowsUpdate -Force
Start-Sleep -s 2
get-command -module PSWindowsUpdate
Start-Sleep -s 2

# Install all pending Updates and restart without asking
Write-Host 
Write-Host -ForegroundColor Yellow "##########################################################"
Write-Host -ForegroundColor Yellow "# Install all pending updates and restart without asking #"
Write-Host -ForegroundColor Yellow "##########################################################"
Write-Host
# pause
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
