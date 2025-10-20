<#
.SYNOPSIS
    Direct Graph API authentication - bypasses module issues
#>

param(
    [string]$TenantId = "common",  # or your specific tenant ID
    [string]$OutputPath = ".\EndOfSupport_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
)

# Microsoft Graph PowerShell App ID (public client)
$clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
$scope = "https://graph.microsoft.com/.default"

# Get access token using device code flow
function Get-GraphToken {
    $body = @{
        client_id = $clientId
        scope     = $scope
    }
    
    # Initiate device code flow
    $deviceCodeResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" -Body $body
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "AUTHENTICATION REQUIRED" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "1. Open your browser and go to:" -ForegroundColor White
    Write-Host "   https://microsoft.com/devicelogin" -ForegroundColor Green
    Write-Host "`n2. Enter this code:" -ForegroundColor White
    Write-Host "   $($deviceCodeResponse.user_code)" -ForegroundColor Yellow -BackgroundColor Black
    Write-Host "`n3. Complete the sign-in process" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Poll for token
    $tokenBody = @{
        grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
        client_id   = $clientId
        device_code = $deviceCodeResponse.device_code
    }
    
    $timeout = [DateTime]::Now.AddSeconds($deviceCodeResponse.expires_in)
    
    while ([DateTime]::Now -lt $timeout) {
        Start-Sleep -Seconds $deviceCodeResponse.interval
        
        try {
            $tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $tokenBody
            Write-Host "✓ Successfully authenticated!" -ForegroundColor Green
            return $tokenResponse.access_token
        }
        catch {
            $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json
            if ($errorResponse.error -ne "authorization_pending") {
                throw "Authentication failed: $($errorResponse.error_description)"
            }
        }
    }
    
    throw "Authentication timed out. Please try again."
}

# Get token
Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Cyan
$token = Get-GraphToken

# Query for EOL software
$kql = @"
DeviceTvmSoftwareInventory
| where isnotempty(DeviceName)
| where isnotempty(EndOfSupportDate) and EndOfSupportDate <= now()
| project DeviceName, SoftwareName, SoftwareVersion, SoftwareVendor, EndOfSupportDate
| order by DeviceName asc, SoftwareName asc
"@

$body = @{ Query = $kql } | ConvertTo-Json -Depth 5

$headers = @{
    "Authorization" = "Bearer $token"
    "Content-Type"  = "application/json"
}

Write-Host "`nExecuting Advanced Hunting query..." -ForegroundColor Cyan

try {
    $response = Invoke-RestMethod -Method Post -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Headers $headers -Body $body
    
    if (-not $response.results -or $response.results.Count -eq 0) {
        Write-Host "✓ No devices with EOL/EOS software found." -ForegroundColor Green
        return
    }

    # Process results
    $results = $response.results | ForEach-Object {
        [PSCustomObject]@{
            DeviceName       = $_.DeviceName
            SoftwareName     = $_.SoftwareName
            SoftwareVersion  = $_.SoftwareVersion
            SoftwareVendor   = $_.SoftwareVendor
            EndOfSupportDate = $_.EndOfSupportDate
        }
    }

    # Export
    $results | Export-Csv -NoTypeInformation -Path $OutputPath -Encoding UTF8
    
    # Summary
    $deviceCount = ($results | Select-Object -Unique DeviceName).Count
    $softwareCount = ($results | Select-Object -Unique SoftwareName).Count
    $totalInstances = $results.Count

    Write-Host "`n========== Summary ==========" -ForegroundColor Yellow
    Write-Host "Devices with EOL software: $deviceCount" -ForegroundColor Cyan
    Write-Host "Unique EOL software titles: $softwareCount" -ForegroundColor Cyan
    Write-Host "Total EOL instances: $totalInstances" -ForegroundColor Cyan
    Write-Host "=============================" -ForegroundColor Yellow
    Write-Host "`n✓ Results saved: $OutputPath" -ForegroundColor Green

    # Top 10
    Write-Host "`nTop 10 Most Common EOL Software:" -ForegroundColor Yellow
    $results | Group-Object SoftwareName | 
               Sort-Object Count -Descending | 
               Select-Object -First 10 Name, Count | 
               Format-Table -AutoSize

}
catch {
    Write-Error "Query execution failed: $_"
    if ($_.ErrorDetails) {
        Write-Host "Error details: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
}
