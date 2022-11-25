# 25.11.2022 Eike Doose / INTERNAL USER ONLY / do not distribute
# Install-Starke-DMS_FTP.ps1 install IIS FTP 
# ===========================================


https://4sysops.com/archives/install-and-configure-an-ftp-server-with-powershell/

# Install the Windows feature for FTP
Install-WindowsFeature Web-Ftp-Server -IncludeAllSubFeature -IncludeManagementTools -Verbose
Install-WindowsFeature Web-Server -IncludeManagementTools -verbose
#Install-Module -Name IISAdministration -force
#Import-Module IISAdministration -UseWindowsPowerShell
# https://blog.kmsigma.com/2016/02/25/removing-default-web-site-application-pool/
Remove-Website "Default Web Site"
Remove-WebAppPool -Name "DefaultAppPool" -Confirm:$false -Verbose




https://techexpert.tips/de/powershell-de/powershell-ersetzen-von-text-in-einer-datei/


Function Get-Timestamp
{
$n=Get-Date
#pad values with leading 0 if necessary
$mo=(($n.Month).ToString()).PadLeft(2,"0")
$dy=(($n.Day).ToString()).PadLeft(2,"0")
$yr=($n.Year).ToString()
$hr=(($n.hour).ToString()).PadLeft(2,"0")
$mn=(($n.Minute).ToString()).PadLeft(2,"0")
$sec=(($n.Second).ToString()).PadLeft(2,"0")

$result=$yr+"-"+$mo+"-"+$dy+"_"+$hr+"-"+$mn+"-"+$sec

return $result
}
$t=Get-TimeStamp

Start-Transcript -Path "c:\install\_Log-Install-Starke-DMS_01-$t.txt" 

################################################################


#Creating new FTP site
$SiteName = "Starke-DMS Cloud 1.0 FileXchange"
$RootFolderpath = "d:\dms-data\ftp-root"
$PortNumber = 21
$FTPUserGroupName = "FTPuserGroup"
$FTPUserName = "FtpUser"
$FTPPassword = ConvertTo-SecureString "p@ssw0rd" -AsPlainText -Force

if (!(Test-Path $RootFolderpath)) {
    # if the folder doesn't exist
    New-Item -Path $RootFolderpath -ItemType Directory # create the folder
}

New-WebFtpSite -Name $SiteName -PhysicalPath $RootFolderpath -Port $PortNumber -Verbose -Force 

#Creating the local Windows group
if (!(Get-LocalGroup $FTPUserGroupName  -ErrorAction SilentlyContinue)) {
    #if the group doesn't exist
    New-LocalGroup -Name $FTPUserGroupName `
        -Description "Members of this group can connect to FTP server" #create the group
}

# Creating an FTP user
If (!(Get-LocalUser $FTPUserName -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $FTPUserName -Password $FTPPassword `
        -Description "User account to access FTP server" `
        -UserMayNotChangePassword
} 

# Add the created FTP user to the group Demo FTP Users Group
Add-LocalGroupMember -Name $FTPUserGroupName -Member $FTPUserName -ErrorAction SilentlyContinue

# Enabling basic authentication on the FTP site
$param = @{
    Path    = 'IIS:\Sites\Demo FTP Site'
    Name    = 'ftpserver.security.authentication.basicauthentication.enabled'
    Value   = $true 
    Verbose = $True
}
Set-ItemProperty @param

# Adding authorization rule to allow FTP users 
# in the FTP group to access the FTP site
$param = @{
    PSPath   = 'IIS:\'
    Location = $SiteName 
    Filter   = '/system.ftpserver/security/authorization'
    Value    = @{ accesstype = 'Allow'; roles = $FTPUserGroupName; permissions = 1 } 
}

Add-WebConfiguration @param

# Changing SSL policy of the FTP site
'ftpServer.security.ssl.controlChannelPolicy', 'ftpServer.security.ssl.dataChannelPolicy' | 
ForEach-Object {
    Set-ItemProperty -Path "IIS:\Sites\Demo FTP Site" -Name $_ -Value $false
}

$ACLObject = Get-Acl -Path $RootFolderpath
$ACLObject.SetAccessRule(
    ( # Access rule object
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            $FTPUserGroupName,
            'ReadAndExecute',
            'ContainerInherit,ObjectInherit',
            'None',
            'Allow'
        )
    )
)
Set-Acl -Path $RootFolderpath -AclObject $ACLObject

# Checking the NTFS permissions on the FTP root folder
Get-Acl -Path $RootFolderpath | ForEach-Object Access

# Test FTP Port and FTP access
Test-NetConnection -ComputerName localhost -Port 21

ftp localhost




Stop-Transcript