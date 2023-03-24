<# 24.03.2023 Eike Doose / INTERNAL USER ONLY / do not distribute
============================================================================

-FTPserver 		# specify the FTP server which will be used for downloading the software / e.g. -FTPserver 'ftp.get--it.de'
-FTPuser 		# name the FTP server user for logging into the FTP server / e.g. -FTPuser 'username'
-FTPpass 		# password for logging into the FTP server / e.g. -FTPpass 'verysecretpassword'
-customerno 	# client customer number which is needed for naming the new server and the database creation / e.g. -customerno '23545'
-LIZuser 		# username for using the license server / e.g. -LIZuser 'username'
-LIZpass 		# password for logging into the license server / e.g. -FTPpass 'licenseuserpass'
-LIZserver 		# URL of the license server / e.g. -LIZserver 'license.starke.cloud'
-LIZuid 		# license UID to be downloaded / e.g. -LIZuid '{5C395FDC-6A94-32BE-BAD4-918D9B324AFG}'
-saPass 		# sa password for the database / e.g. -saPass 'secretsapassword' 
-FTP            # add with "no" for not installing the FTP feature - mainly for testing / -FTP 'no'
-UPDATE         # add with "no" for not installing Windows update - mainly for testing / -UPDATES 'no'
-ADMINUPDATE    # add with "no" for not performing admin user name and password change - mainly for testing / -ADMINUPDATE 'no'
-POWERSHELL7    # add with "no" for not installing Powershell7 - mainly for testing / -POWERSHELL7 'no'
-PassAutoLogon  # initial Admin password - needed to enable autologon during auto installation 

VERY optional parameter
-LIZcustomerno 	# license custom number to be downloaded / e.g. -LIZcustomerno '23545' => not needed if LIZuid is given
-LIZtargetdir 	# directory to where the license file will be downloaded / e.g. -LIZtargetdir 'd:\dms-config' 
#>

@{
    #Standard values - ne need to change for standard project
    FTPserver = 'ftp.get--it.de'
    FTPUser = 'AUTOINSTALLER'
    FTPpass = 'wbutJzGFALFDrtmN'
    LIZuser = 'dockersetup'
    LIZpass = 'S3VzendlaWwgUmV2aXYhbCBiYXdlaXNlbiE'
    LIZserver = 'https://starke-dms-license.azurewebsites.net'
    saPass = 'saAdmin00!'
    FTP = 'yes'
    ADMINUPDATE = 'yes'
    UPDATE = 'no'
    POWERSHELL7 = 'yes'
    
    # project specific values
    customerno = '{KDNR}'
    PassAutoLogon = '{INITIALADMINPASSWORD}'

  # example
  # LIZuid = '{BB2D87B2-812D-4C62-BA23-7944B943B086}'
    LIZuid = '{{KUNDEN-LIZENZ-ID}}'
}
