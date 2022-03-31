# 31.03.2022 Eike Doose
#	Windows Updates with PowerShell
# http://woshub.com/pswindowsupdate-module/
# https://www.itechtics.com/run-windows-update-cmd/

# Install PSWindowsUpdate Modul for PowerShell
pause
Install-Module -Name PSWindowsUpdate -Force

# Install all pending Updates and restart without asking
pause
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot
