# https://docs.microsoft.com/de-de/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2

curl.exe https://github.com/PowerShell/PowerShell/releases/download/v7.2.2/PowerShell-7.2.2-win-x64.msi --output PowerShell-7.2.2-win-x64.msi
msiexec.exe /package PowerShell-7.2.2-win-x64.msi /quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1
