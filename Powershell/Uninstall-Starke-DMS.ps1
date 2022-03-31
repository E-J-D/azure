# 31.03.2022 Eike Doose / licenced for commerical use only - do not distribute
# ============================================================================
#
cls
echo Starke-DMS® and ABBYY will be uninstalled
echo to cancel press STRG+C

pause

# uninstall ABBYY silent
"C:\Program Files (x86)\StarkeDMS\uninstabbyy.exe" /S

# wait for the Starke-DMS® uninstaller to be finished
Wait-Process -Name un*
Start-Sleep -s 10

# uninstall Starke-DMS® silent
"c:\program files (x86)\StarkeDMS\uninst.exe" /S

# wait for the Starke-DMS® uninstaller to be finished
Wait-Process -Name un*
Start-Sleep -s 10

# message when everything is done
echo ################################################
echo #############  Everything done  ################
echo ######  Thank you for using Starke-DMS®  #######
echo ################################################
