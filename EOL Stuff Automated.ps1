#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Summarizes devices with EOL software count per device
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\EndOfSupport_DeviceSummary_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
)

# Verify authentication
try {
    $context = Get-MgContext
    if (-not $context) {
        throw "Not connected to Microsoft Graph. Run: Connect-MgGraph -Scopes 'ThreatHunting.Read.All'"
    }
} catch {
    Write-Error "Authentication check failed: $_"
    return
}

# Query: Count EOL software per device
$kql = @"
DeviceTvmSoftwareInventory
| where isnotempty(DeviceName)
| where isnotempty(EndOfSupportDate) and EndOfSupportDate <= now()
| summarize 
    EOLSoftwareCount = count(),
    EOLSoftwareList = make_set(SoftwareName, 100),
    OldestEOLDate = min(EndOfSupportDate)
  by DeviceName
| order by EOLSoftwareCount desc
"@

$body = @{ Query = $kql } | ConvertTo-Json -Depth 5
$uri = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"

Write-Host "Executing query..." -ForegroundColor Cyan

try {
    $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"
    
    if (-not $response.results) {
        Write-Host "✓ No devices with EOL/EOS software found." -ForegroundColor Green
        return
    }

    # Process results
    $results = $response.results | ForEach-Object {
        [PSCustomObject]@{
            DeviceName       = $_.DeviceName
            EOLSoftwareCount = $_.EOLSoftwareCount
            OldestEOLDate    = $_.OldestEOLDate
            EOLSoftwareList  = ($_.EOLSoftwareList | ConvertFrom-Json) -join "; "
        }
    }

    $results | Export-Csv -NoTypeInformation -Path $OutputPath -Encoding UTF8
    
    Write-Host "`n✓ Found $($results.Count) devices with EOL software" -ForegroundColor Green
    Write-Host "✓ Results saved: $OutputPath" -ForegroundColor Green
    
    # Show top 10 worst offenders
    Write-Host "`nTop 10 Devices by EOL Software Count:" -ForegroundColor Yellow
    $results | Select-Object -First 10 DeviceName, EOLSoftwareCount, OldestEOLDate | 
               Format-Table -AutoSize

} catch {
    Write-Error "Query failed: $_"
}
