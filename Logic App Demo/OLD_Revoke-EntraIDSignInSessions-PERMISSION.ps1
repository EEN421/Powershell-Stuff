# Your tenant id (in Azure Portal, under Azure Active Directory -> Overview)
$TenantID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Microsoft Graph App ID (DON'T CHANGE)
$GraphAppId = "00000003-0000-0000-c000-000000000000"

# Name of the system managed identity (same as the Logic App name)
$DisplayNameOfMSI = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Check the Microsoft Graph documentation for the permission you need to revoke sign-in sessions
$PermissionName = "User.ReadWrite.All"

# Install the module (You need admin on the machine)
Install-Module AzureAD

Connect-AzureAD -TenantId $TenantID

# Get the MSI
$MSI = (Get-AzureADServicePrincipal -Filter "displayName eq '$DisplayNameOfMSI'")
Start-Sleep -Seconds 10

# Get the Graph API app principal
$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"

# Get the permission object from the Graph API for Application
$AppRole = $GraphServicePrincipal.AppRoles | `
	Where-Object { $_.Value -eq $PermissionName -and $_.AllowedMemberTypes -contains "Application" }

# Add the required permission on the Graph API to the MSI (this also provides "admin consent")
New-AzureAdServiceAppRoleAssignment -ObjectId $MSI.ObjectId -PrincipalId $MSI.ObjectId `
	-ResourceId $GraphServicePrincipal.ObjectId -Id $AppRole.Id
