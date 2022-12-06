param (
	[Parameter(Mandatory=$true)][string]$customerno
)

#Zertifikat wird erstellt
$SSLCERT= New-SelfSignedCertificate -certstorelocation cert:\localmachine\my -dnsname "'$customerno'.starke-dms.cloud"

#Tumbprint abspeichern
$MeinTumbprint = $MeinCert.thumbprint

#Passwort zum Exportieren hinterlegen
#$MeinPasswort = ConvertTo-SecureString -String 'Admin00!' -Force -AsPlainText

#Zertifikat exportieren
#Export-PfxCertificate -cert cert:\localMachine\my\$MeinTumbprint -FilePath C:\MeinPfad\MeinCert.pfx -Password $MeinPasswort