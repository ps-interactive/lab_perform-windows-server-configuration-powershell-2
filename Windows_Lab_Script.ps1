# Challenge 3 - Setting up shared folders and their permissions

# 3.1.A -Create a new user

# Prompt to enter new user name
$NewUser1 = Read-Host "Enter the username for new user:"

# Set password for new user and convert it in secure string
$Password = Read-Host -AsSecureString "Create a password for $NewUser1"

# Create New User
New-LocalUser "$NewUser1" -Password $Password -FullName "$NewUser1" -Description "Test User"




# 3.2 - Create a folder

# 3.2.A - Create folder
New-Item -ItemType Directory -Path C:\Temp\SharedFolder1




# 3.3 Share a folder and set permssions

# 3.3.A - Create a new SMB share on existing folder
New-SmbShare -Path C:\Temp\SharedFolder1 -Name "Shared Folder 1"    #(Folder needs to be present. Command won't create the folder)

# 3.3.B - Retrieve SMB share
Get-SmbShare




# 3.4 Set SMB share permissions

# 3.4.A - Retrieve SMB share permssions
Get-SmbShareAccess -Name "Shared Folder 1"

# 3.4.B - Set Read Write permissions for test user
Grant-SmbShareAccess -Name "Shared Folder 1" -AccountName "ps-win-1\$NewUser1" -AccessRight Change -Force




# 3.5 Revoke SMB share permissions

# 3.5.A - Revoke SMB share permissions for test user
Revoke-SmbShareAccess -Name "Shared Folder 1" -AccountName "ps-win-1\$NewUser1" -Force


######################################################################################

# Challenge 4 - Manage NTFS permissions

# 4.1.A -Create a new user

# Prompt to enter new user name
$NewUser2 = Read-Host "Enter the username for new user:"

# Set password for new user and convert it in secure string
$Password = Read-Host -AsSecureString "Create a password for $NewUser2"

# Create New User
New-LocalUser "$NewUser2" -Password $Password -FullName "$NewUser2" -Description "Test User 2"




# 4.2 - Create a folder

# 4.2.A - Create folder
New-Item -ItemType Directory -Path C:\Temp\SharedFolder2




# 4.3 - Set permissions on folder

# 4.3.A - List all available NTFS permissions
[System.Enum]::GetNames([System.Security.AccessControl.FileSystemRights]) | Sort-Object

# 4.3.B - Retrieve NTFS permissions of newly created folder
(Get-Acl C:\Temp\SharedFolder2).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize

# 4.3.C - Modify NTFS permissions
$ACL = Get-ACL -Path "C:\Temp\SharedFolder2"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$newuser2","FullControl","Allow")
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl -Path "C:\Temp\SharedFolder2"
(Get-Acl C:\Temp\SharedFolder2).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize

# 4.3.D - Retrieve NTFS permissions of newly created folder
$ACL = Get-ACL -Path "C:\Temp\SharedFolder2"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("$NewUser2","FullControl","Allow")
$ACL.RemoveAccessRule($AccessRule)
$ACL | Set-Acl -Path "C:\Temp\SharedFolder2"
(Get-Acl C:\Temp\SharedFolder2).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize

######################################################################################


# Challenge 5 - Creating and managing Windows registries and values

# 5.1 - List PS Drives

# 5.1.A - List all PS drives
Get-PSDrive

# 5.1.B - List Registry PS drives
Get-PSDrive -PSProvider Registry




# 5.2 - List registry keys, properties and values

# 5.2.A - Enter into local machine PS drive
Set-location HKLM:\

# 5.2.B - Retrieve details of HKLM PS drive
Get-Item HKLM:\ | select *

# 5.2.C - Retrieve child items of HKLM PS drive
Get-childItem HKLM:\

# 5.2.D - Retrieve registry key using absolute path
Get-Item HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine\

# 5.2.E - Retrieve registry value using name paramter
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine -Name ApplicationBase

# 5.2.F - Retrieve all registry values using from a registry key
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine

# 5.2.G - Do a wildcard search with registry key name
Get-ChildItem -Path .\ -Include "PowerShell" -Recurse




# 5.3 - Create registry keys, properties and values

# 5.3.A - Create a new registry key
New-Item .\SOFTWARE\App1

# 5.3.B - Create a new registry property
New-Item .\SOFTWARE\App1 -Name InstallPath -Value "C:\Program Files\App1"

# 5.3.B - Create a new registry property
New-Item .\SOFTWARE\App1 -Name InstallPath -Value "C:\Program Files\App1"

# 5.3.B - Create a new registry property with null value
New-Item .\SOFTWARE\App1 -Name NewInstallPath -Value ""




# 5.4 - Modify registry keys, properties and values

# 5.4.A - Change registry key name
Rename-Item -Path .\SOFTWARE\App1 -NewName App2

# 5.4.B - Change registry property name
Rename-ItemProperty -Path .\SOFTWARE\App2 -Name InstallPath -NewName OldInstallPath

# 5.4.C - Change registry value
Set-ItemProperty -Path App2 -Name OldInstallPath -Value "C:\Temp" 




# 5.5 - Delete registry keys, properties and values

# 5.5.A - Clear registry value
Clear-ItemProperty -Path .\SOFTWARE\App2 -Name OldInstallPath
Get-ItemProperty -Path .\SOFTWARE\App2 -Name OldInstallPath

# 5.5.B - Delete registry property
Remove-ItemProperty -Path .\SOFTWARE\App2 -Name OldInstallPath
Get-ItemProperty -Path .\SOFTWARE\App2 -Name OldInstallPath

# 5.5.C - Delete all registry property
Clear-Item -Path .\SOFTWARE\App2

# 5.5.D - Delete registry key
Remove-Item -Path .\SOFTWARE\App2
Get-Item -Path .\SOFTWARE\App2

######################################################################################


# Challenge 6 - Managing Certificates

# 6.1 - Explore Cert PSDrive and retrieve certificates

# 6.1.A - List Certificate PS drive and enter the drive
Get-PSDrive -Name Cert
Set-location Cert:\

# 6.1.B - List Machine's and User's Cert store path
Get-ChildItem .\

# 6.1.C - Machine's certificate stores
Get-ChildItem .\CurrentUser

# 6.1.D - Retrieve all certificates in Machine's Root store
Get-ChildItem .\CurrentUser\Root

# 6.1.E - Retrieve certificate properties
Get-ChildItem .\CurrentUser\Root | Get-Member

# 6.1.F - Retrieve root certificate from User path
Get-ChildItem .\LocalMachine\Root | Where-Object {$_.Thumbprint -eq "CDD4EEAE6000AC7F40C3802C171E30148030C072"}

# 6.1.G - Retrieve certificates expiring in 30 days
Get-ChildItem .\LocalMachine\Root -ExpiringInDays 30 -Recurse

# 6.1.H - Delete a certificate
$Del=(Get-ChildItem .\LocalMachine\Root -ExpiringInDays 30 -Recurse | select -expandproperty Thumbprint)[-1]
Write-Output "Thumbprint of certificate to be deleted - $Del"
Remove-Item .\LocalMachine\Root\$Del -Force

Get-ChildItem .\LocalMachine\Root -ExpiringInDays 30 -Recurse





# 6.2 - Create a self-signed certificate and install in trusted store

# 6.2.A - Create a self-signed certificate
$Certificate = New-SelfSignedCertificate -Subject "testing.com" -CertStoreLocation Cert:\CurrentUser\My

# 6.2.B - Export the certificate to a file
Export-Certificate -Cert $Certificate -FilePath "C:\TestCertificate.cer"

# 6.2.C - Installing the certificate in trusted root store
Import-Certificate -FilePath "C:\TestCertificate.cer" -CertStoreLocation 'Cert:\CurrentUser\Root'

######################################################################################


# Challenge 7 - Managing Task Schedulers

#7.1 - Create a basic task scheduler

#7.1.A - Register a new basic scheduled task
$TaskName = "Task 1"

$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "C:\Users\Public\Desktop\LAB_FILES\TaskTest.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At 1am

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger




# 7.2 - Run a task scheduler

#7.2.A - Execute a task
Start-ScheduledTask -TaskName "Task 1"




# 7.3 - Create task scheduler with advanced settings

#7.3.A - Register an advanced scheduled task
$TaskName = "Task 2"
$username ="ps-win-1\user2"
$password ="P@ssw0rd"

$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-nologo -file C:\Users\Public\Desktop\LAB_FILES\TaskTest.ps1"
$Trigger = New-ScheduledTaskTrigger -Weekly -WeeksInterval 1 -DaysOfWeek Friday -At 11pm
$RunLevel = "Highest"

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -User $username -Password $Password -RunLevel $RunLevel

# 7.3.B - Execute the task
Start-ScheduledTask -TaskName "Task 2"




# 7.4 - Modify existing task scheduler settings

# 7.4.A - Change run under user for Task 2
Set-ScheduledTask -TaskName "Task 2" -User "pslearner"

# 7.4.B - Execute the task
Start-ScheduledTask -TaskName "Task 2"

