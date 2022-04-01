# 01.04.2022 Eike Doose / licenced for commerical use only - do not distribute
# ============================================================================
#
cls
echo Starke-DMS® and ABBYY will be uninstalled
echo to cancel press STRG+C

pause

# uninstall ABBYY silent
Start-Process -Wait -FilePath 'C:\Program Files (x86)\StarkeDMS\uninstabbyy.exe' -ArgumentList /S -PassThru

# wait for the Starke-DMSÂ® uninstaller to be finished
Wait-Process -Name uninstabbyy*
Start-Sleep -s 10

# uninstall Starke-DMSÂ® silent
Start-Process -Wait -FilePath 'C:\Program Files (x86)\StarkeDMS\uninst.exe' -ArgumentList /S -PassThru

# wait for the Starke-DMSÂ® uninstaller to be finished
Wait-Process -Name un*
Start-Sleep -s 10

# message when everything is done
echo ################################################
echo #############  Everything done  ################
echo ######  Thank you for using Starke-DMSÂ®  #######
echo ################################################
