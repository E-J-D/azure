# 05.04.2022 Boris Brixel
#
#

if (($LIZuid -eq '') -And ($LIZcustomerno -eq '')) {
	"UID oder Kundennummer übergeben"
	Return
}

$licensefile = '.\get-dms-license.zip'
$licensedir = '.\get-dms-license'
if (Test-Path -Path $licensefile -PathType Leaf) {
	Remove-Item -LiteralPath $licensefile
}
if (Test-Path -Path $licensedir) {
	Remove-Item -LiteralPath $licensedir -Force -Recurse
}

$credentials = @{
    username = $LIZuser
    password = $LIZpass
}
$response = Invoke-WebRequest -Uri "$LIZserver/license/login" -Body $credentials -Method Get -SkipHttpErrorCheck -SessionVariable session

if ($response.StatusCode -eq 200) {
	"Anmeldung erfolgreich."

	if ($LIZuid -eq '') {
		# UID anhand von Kundennummer ermitteln
		$parameters = @{
			customerno = $LIZcustomerno # '50999'
		}
		$response = Invoke-WebRequest -Uri "$LIZserver/license/list" -Body $parameters -Method Get -SkipHttpErrorCheck -WebSession $session
		if ($response.StatusCode -eq 200) {
			$json = $response.Content | ConvertFrom-Json
			$count = $json.count
			if ($count -eq 1) {
				$LIZuid = $json[0].uid
				"UID: $LIZuid"
			} elseif ($count -eq 0) {
				"Keine Lizenz gefunden."
			} else {
				"$count Lizenzen gefunden. Geben Sie eine eindeutige Kundennummer oder eine UID an."
			}
		} else {
			"Fehler beim Suchen der Lizenz-UID: $response"
		}
	}
	
	if ($LIZuid -ne '') {
		$parameters = @{
			uid = $LIZuid
		}
		$response = Invoke-WebRequest -Uri "$LIZserver/license/export" -Body $parameters -OutFile $licensefile -PassThru -Method Get -SkipHttpErrorCheck -WebSession $session

		if ($response.StatusCode -eq 200) {
			"Lizenz heruntergeladen."
		} else {
			"Fehler beim Herunterladen der Lizenz: $response"
			if (Test-Path -Path $licensefile -PathType Leaf) {
				Remove-Item -LiteralPath $licensefile
			}
		}
	}

	$response = Invoke-WebRequest -Uri "$LIZserver/license/logout" -Method Get -SkipHttpErrorCheck -WebSession $session
} else {
	"Fehler beim Anmelden: $response"
}
if (Test-Path -Path $licensefile -PathType Leaf) {
	Expand-Archive -LiteralPath $licensefile -DestinationPath $licensedir
	if (Test-Path -Path "$licensedir\APLizenz.liz" -PathType Leaf) {
		"Lizenzdateien entpackt."
		if (-Not (Test-Path -Path $LIZtargetdir)) {
			$dummy = New-Item $LIZtargetdir -ItemType Directory
		}
		Copy-Item -Path "$licensedir\*" -Destination "$LIZtargetdir\" -Recurse
	} else {
		"APLizenz.liz nicht gefunden."
	}
	Remove-Item -LiteralPath $licensefile
	Remove-Item -LiteralPath $licensedir -Force -Recurse
}