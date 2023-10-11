# 1 - Create local user and group

# 1.1.A - Get list of all local users
Get-LocalUser

# 1.1.B - List all the properties of Admin user
Get-LocalUser -Name Administrator | select-object *

# 1.1.C - Create a new user
#Prompt to enter new user name
$NewUser = Read-Host "New local admin username:"

#