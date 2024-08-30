# Get-Token.ps1
# This script gets the App Context Token and saves it securely.

# Prompt the user for Tenant ID, App ID, and App Secret (securely)
$tenantId = Read-Host -Prompt 'Enter your Tenant ID'
$appId = Read-Host -Prompt 'Enter your Application ID'
$appSecret = Read-Host -Prompt 'Enter your Application Secret' -AsSecureString

$resourceAppIdUri = 'https://api.securitycenter.windows.com'
$oAuthUri = "https://login.windows.net/$tenantId/oauth2/token"

# Convert the secure string to plain text for the API call (in-memory only)
$appSecretPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($appSecret))

$authBody = @{
    resource      = "$resourceAppIdUri"
    client_id     = "$appId"
    client_secret = "$appSecretPlainText"
    grant_type    = 'client_credentials'
}

# Error handling for token retrieval
try {
    $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    $token = $authResponse.access_token

    # Securely store the token (using Windows DPAPI)
    $secureToken = ConvertTo-SecureString $token -AsPlainText -Force
    $secureToken | ConvertFrom-SecureString | Set-Content -Path "./Latest-token.txt"

    # Clear plain text secret from memory
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($appSecret))

    return $token
} catch {
    Write-Error "Failed to obtain token: $_"
    exit 1
}
