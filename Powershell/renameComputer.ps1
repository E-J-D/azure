# https://www.server-world.info/en/note?os=Windows_Server_2019&p=initial_conf&f=3

Rename-Computer -NewName NewNAME -Force -PassThru
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" –Name "NV Domain" –Value "cloud1.local" -PassThru
Restart-Computer -Force
(ipconfig /all)[0..9]
