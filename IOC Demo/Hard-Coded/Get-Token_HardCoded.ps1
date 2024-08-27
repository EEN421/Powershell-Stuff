# Grabs and saves the App Context Token to file called "Latest-token.txt" under in the current directory
# In this script, the Tenant ID, App ID and App Secret are hardcoded.
# For a variation of this script that prompts for these variables when run, visit https://github.com/EEN421/Powershell-Stuff/blob/Main/IOC%20Demo/Prompt/Get-Token.ps1

# Paste your Tenant ID, App ID and App Secret Value in lines 4-6 below:
$tenantId = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' ### Paste your tenant ID here
$appId = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' ### Paste your app ID here
$appSecret = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' ### Paste your app secret here

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