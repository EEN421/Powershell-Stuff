# Submit_Indicator.ps1
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet('FileSha1','FileSha256','IpAddress','DomainName','Url')]
    [string]$indicatorType,

    [Parameter(Mandatory=$true)]
    [string]$indicatorValue,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Alert','AlertAndBlock','Allowed')]
    [string]$action = 'Alert',

    [Parameter(Mandatory=$true)]
    [string]$title,

    [Parameter(Mandatory=$false)]
    [ValidateSet('Informational','Low','Medium','High')]
    [string]$severity = 'Informational',

    [Parameter(Mandatory=$true)]
    [string]$description,

    [Parameter(Mandatory=$true)]
    [string]$recommendedActions
)

# Retrieve the token securely
try {
    $token = .\Get-Token.ps1
} catch {
    Write-Error "Failed to retrieve authorization token: $_"
    exit 1
}

$url = "https://api.securitycenter.windows.com/api/indicators"

$body = @{
    indicatorValue     = $indicatorValue
    indicatorType      = $indicatorType
    action             = $action
    title              = $title
    severity           = $severity
    description        = $description
    recommendedActions = $recommendedActions
}

$headers = @{
    'Content-Type' = 'application/json'
    Accept         = 'application/json'
    Authorization  = "Bearer $token"
}

# Securely send the indicator
try {
    $response = Invoke-WebRequest -Method Post -Uri $url -Body ($body | ConvertTo-Json) -Headers $headers -ErrorAction Stop
    if($response.StatusCode -eq 200) {
        return $true        # Update ended successfully
    } else {
        return $false       # Update failed
    }
} catch {
    Write-Error "Failed to submit indicator: $_"
    return $false
}
