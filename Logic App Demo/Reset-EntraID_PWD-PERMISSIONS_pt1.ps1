# This is the 1st of 2 scripts required to enable the Reset Microsoft Entra ID User Password - Incident Trigger logic app. 

# Fill out and define these variables:
$MIGuid = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$SubscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$ResourceGroupName = "<Your RG Here>"

# Don't change anything after this line
$MI = Get-AzureADServicePrincipal -ObjectId $MIGuid
$GraphAppId = "00000003-0000-0000-c000-000000000000"

#Roles required to reset EntraID Passwords and Update Incidents:
$roleName = "Password Administrator"
$SentinelRoleName = "Microsoft Sentinel Responder"

$GraphServicePrincipal = Get-AzureADServicePrincipal -Filter "appId eq '$GraphAppId'"
$role = Get-AzureADDirectoryRole | Where {$_.displayName -eq $roleName}
if ($role -eq $null) {
$roleTemplate = Get-AzureADDirectoryRoleTemplate | Where {$_.displayName -eq $roleName}
Enable-AzureADDirectoryRole -RoleTemplateId $roleTemplate.ObjectId
$role = Get-AzureADDirectoryRole | Where {$_.displayName -eq $roleName}
}
Add-AzureADDirectoryRoleMember -ObjectId $role.ObjectId -RefObjectId $MI.ObjectID
New-AzRoleAssignment -ObjectId $MIGuid -RoleDefinitionName $SentinelRoleName -Scope /subscriptions/$SubscriptionId/resourcegroups/$ResourceGroupName
