# This is the 2nd of 2 scripts required to enable the Reset Microsoft Entra ID User Password - Incident Trigger logic app. Update the following 3 parameters:
$directoryRoleName = 'Password Administrator'
$logicAppName = '<Your EntraID PWD Reset Logic App Name Here>'
$resourceGroupName = '<Resource Group Containing your Logic App Here>'

$resourceType = 'Microsoft.Logic/workflows'

# Look up the logic app's managed identity's object ID.
$managedIdentityObjectId = (Get-AzResource -ResourceGroupName $resourceGroupName -Name $logicAppName -ResourceType $resourceType).Identity.PrincipalId
$odataId = 'https://graph.microsoft.com/v1.0/directoryObjects/' + $managedIdentityObjectId

try {
    # Find the specific role by name
    $directoryRoleTemplate = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq $directoryRoleName }
    $directoryRoleTemplateId = $directoryRoleTemplate.Id

    # Attempt to get the directory role
    $role = Get-MgDirectoryRoleByRoleTemplateId -RoleTemplateId $directoryRoleTemplateId -ErrorAction Stop
    Write-Host('The ' + $role.DisplayName + ' role is activated.')
}
catch {
    $errorDetails = $_
    $errorException = $errorDetails.Exception
    $errorMessage = $errorDetails.Exception.Message
    $errorId = $errorDetails.FullyQualifiedErrorId

    # Check for specific status codes and handle accordingly
    if ($errorId -eq 'Request_ResourceNotFound,Microsoft.Graph.PowerShell.Cmdlets.GetMgDirectoryRoleByRoleTemplateId_Get') {
        Write-Host $errorMessage
        Write-Host 'Activating the role ...'
        New-MgDirectoryRole -RoleTemplateId $directoryRoleTemplateId -Confirm
        Write-Host('The ' + $role.DisplayName + ' role is activated.')
    }
    else {
        # Handle other errors
        Write-Host $errorException
    }
}

try {
    # Use the constructed OdataId directly in the cmdlet
    New-MgDirectoryRoleMemberByRef -DirectoryRoleId $role.Id -OdataId $odataId -Confirm -ErrorAction Stop
}
catch {
    $errorDetails = $_
    $errorException = $errorDetails.Exception
    $errorMessage = $errorDetails.Exception.Message
    $errorId = $errorDetails.FullyQualifiedErrorId

    # Check for specific status codes and handle accordingly
    if ($errorId -eq 'Request_BadRequest,Microsoft.Graph.PowerShell.Cmdlets.NewMgDirectoryRoleMemberByRef_CreateExpanded') {
        Write-Host $errorMessage
        Write-Host 'Checking the membership ...'
    }
    else {
        # Handle other errors
        Write-Host $errorException
    }
}

# Retrieve the service principal
$servicePrincipal = Get-MgServicePrincipal -ServicePrincipalId $managedIdentityObjectId

if ($null -eq $servicePrincipal) {
    Write-Host 'Service Principal with ID ' + $managedIdentityObjectId + ' not found.'
} else {
    # Output service principal details
    Write-Host 'Service Principal found:'

    # Retrieve memberOf relationships
    $memberOf = Get-MgServicePrincipalMemberOf -ServicePrincipalId $servicePrincipal.Id
    if ($memberOf) {
        $servicePrincipal.DisplayName
        $memberOf | Format-List
    } else {
        Write-Host('No memberships found for Service Principal with ID' + $($servicePrincipal.Id) + ' .')
    }
}
