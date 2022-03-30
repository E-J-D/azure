# 30.03.2022 Eike Doose eike.doose@starke.de

# Use the following command to download this file
# curl.exe https://raw.githubusercontent.com/E-J-D/sdms-cloud1-azure/main/Powershell/Install-EDGE.ps1 --output Install-EDGE.ps1

# Autoinstall Microsoft Edge
md -Path $env:temp\edgeinstall -erroraction SilentlyContinue | Out-Null
$Download = join-path $env:temp\edgeinstall MicrosoftEdgeEnterpriseX64.msi
Invoke-WebRequest 'https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/a2662b5b-97d0-4312-8946-598355851b3b/MicrosoftEdgeEnterpriseX64.msi'  -OutFile $Download
Start-Process "$Download" -ArgumentList "/quiet"

# Uninstall Internet Explorer 11
echo Uninstall Internet Explorer 11
pause
Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online
