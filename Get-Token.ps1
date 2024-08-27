# This script gets the App Context Token and saves it to a file named "Latest-token.txt" in the current directory and prompts the user for Tenant ID, App ID, and App Secret.

# Prompt the user for Tenant ID, App ID, and App Secret
$tenantId = Read-Host -Prompt 'Enter your Tenant ID'
$appId = Read-Host -Prompt 'Enter your Application ID'
$appSecret = Read-Host -Prompt 'Enter your Application Secret'

$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri = "https://login.windows.net/$TenantId/oauth2/token"

$authBody = [Ordered] @{
    resource = "$resourceAppIdUri"
    client_id = "$appId"
    client_secret = "$appSecret"
    grant_type = 'client_credentials'
}

$authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
$token = $authResponse.access_token
Out-File -FilePath "./Latest-token.txt" -InputObject $token
return $token
