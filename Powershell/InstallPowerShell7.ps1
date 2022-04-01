# 01.04.2022 Eike Doose
# https://docs.microsoft.com/de-de/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.2

curl.exe "ftp://get--it:get--IT2022@ftp.get--it.de/PowerShell-7.2.2-win-x64.msi" --output C:\install\StarkeDMS-latest\PowerShell-7.2.2-win-x64.msi --create-dirs
Start-Process -wait C:\install\StarkeDMS-latest\PowerShell-7.2.2-win-x64.msi -ArgumentList "/quiet ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=1 ENABLE_PSREMOTING=1 REGISTER_MANIFEST=1 USE_MU=1 ENABLE_MU=1"