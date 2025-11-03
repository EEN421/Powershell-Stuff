#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
  Summarizes devices with End-of-Life (EoL / End-of-Support) software counts per device
  by running a Defender hunting query via Microsoft Graph and exporting results to CSV.

.DESCRIPTION
  - Ensures you're connected to Microsoft Graph with ThreatHunting.Read.All (or App-only).
  - Executes a KQL query against /security/runHuntingQuery.
  - Produces a CSV with DeviceName, EOLSoftwareCount, OldestEOLDate, and EOLSoftwareList.

.PARAMETER OutputPath
  Full path to the CSV output. The folder is created if it doesn't exist.

.PARAMETER TenantId
  Optional. If provided, the script will attempt to connect to Graph for that tenant.

.PARAMETER SkipAutoConnect
  Switch. If set, the script will NOT attempt to connect automatically and will fail if no context exists.

.EXAMPLE
1. Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
2. Install-Module Microsoft.Graph -Scope CurrentUser -AllowClobber
3. Connect-MgGraph -Scopes 'ThreatHunting.Read.All'
4. .\EOLAutomated.ps1 -OutputPath 'C:\Temp\EndOfSupport_DeviceSummary.csv'
#>

[CmdletBinding()]
param(
  [string]$OutputPath = ".\EndOfSupport_DeviceSummary_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv",
  [string]$TenantId,
  [switch]$SkipAutoConnect
)

function Ensure-GraphConnection {
  param(
    [Parameter(Mandatory)][string]$RequiredScope,
    [string]$TenantId
  )

  try {
    $ctx = Get-MgContext -ErrorAction SilentlyContinue
  } catch {
    $ctx = $null
  }

  if (-not $ctx) {
    if ($SkipAutoConnect) {
      throw "Not connected to Microsoft Graph. Re-run after: Connect-MgGraph -Scopes '$RequiredScope'"
    }

    Write-Host "No Graph context detected. Attempting to connect..." -ForegroundColor Cyan
    if ($TenantId) {
      Connect-MgGraph -Scopes $RequiredScope -TenantId $TenantId
    } else {
      Connect-MgGraph -Scopes $RequiredScope
    }

    $ctx = Get-MgContext
    if (-not $ctx) {
      throw "Failed to establish a Microsoft Graph connection."
    }
  }

  # App-only has no Scopes property
  if ($ctx.AuthType -eq 'AppOnly') {
    Write-Host "Connected with App-Only auth. Ensure the application permission 'ThreatHunting.Read.All' has admin consent." -ForegroundColor Yellow
    return
  }

  # Verify requested scope present (best-effort)
  $scopes = @()
  if ($ctx.Scopes) { $scopes = $ctx.Scopes }
  if ($scopes.Count -gt 0) {
    $joined = ($scopes -join ' ')
    if ($joined -notmatch [regex]::Escape($RequiredScope)) {
      throw "Connected, but missing required scope '$RequiredScope'. Current scopes: $joined"
    }
  }
}

function Convert-ToStringList {
  <#
    Converts the EOLSoftwareList field (could be JSON array string, PS array, or string)
    into a human-friendly '; '-joined string.
  #>
  param([object]$Value)

  if ($null -eq $Value) { return '' }

  try {
    $typeName = $Value.GetType().Name
  } catch {
    $typeName = 'Unknown'
  }

  try {
    switch ($typeName) {
      'String' {
        $trim = $Value.Trim()
        if ($trim.StartsWith('[') -and $trim.EndsWith(']')) {
          $arr = $trim | ConvertFrom-Json -ErrorAction Stop
          if ($arr -is [System.Array]) { return ($arr -join '; ') }
        }
        return $trim
      }
      'Object[]' { return ($Value -join '; ') }
      default    { return [string]$Value }
    }
  } catch {
    return [string]$Value
  }
}

# ------------------------------
# Main
# ------------------------------
$ErrorActionPreference = 'Stop'

# 1) Ensure Graph connection & permissions
$requiredScope = 'ThreatHunting.Read.All'
Ensure-GraphConnection -RequiredScope $requiredScope -TenantId $TenantId

# 2) Define the hunting query
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

# 3) Prepare request
$uri  = "https://graph.microsoft.com/v1.0/security/runHuntingQuery"
$body = @{ Query = $kql } | ConvertTo-Json -Depth 5

Write-Host "Executing hunting query against Defender via Microsoft Graph..." -ForegroundColor Cyan

try {
  $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $body -ContentType "application/json"

  # 4) Validate results
  if (-not $response -or -not $response.results) {
    Write-Host "✓ No devices with EOL/EOS software found (no results returned)." -ForegroundColor Green
    return
  }

  $raw = $response.results
  if (-not $raw.Count) {
    Write-Host "✓ No devices with EOL/EOS software found." -ForegroundColor Green
    return
  }

  # 5) Transform rows (pre-calc complex values; no inline try/catch in hashtable)
  $results = foreach ($row in $raw) {
    # OldestEOLDate may come as string; make a best-effort cast
    $oldest = $null
    try {
      $oldest = [datetime]$row.OldestEOLDate
    } catch {
      $oldest = $row.OldestEOLDate
    }

    $list = Convert-ToStringList -Value $row.EOLSoftwareList

    [PSCustomObject]@{
      DeviceName       = $row.DeviceName
      EOLSoftwareCount = [int]$row.EOLSoftwareCount
      OldestEOLDate    = $oldest
      EOLSoftwareList  = $list
    }
  }

  # 6) Ensure destination folder exists
  $dir = Split-Path -Path $OutputPath -Parent
  if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
    Write-Host "Creating folder: $dir" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
  }

  # 7) Export to CSV (compatible with all PowerShell versions)
  $results |
    Sort-Object -Property EOLSoftwareCount -Descending |
    Export-Csv -NoTypeInformation -Encoding UTF8 -Path $OutputPath

  Write-Host "`n✓ Found $($results.Count) devices with EOL software" -ForegroundColor Green
  Write-Host "✓ Results saved: $OutputPath" -ForegroundColor Green

  # 8) Console summary: Top 10 offenders
  Write-Host "`nTop 10 Devices by EOL Software Count:" -ForegroundColor Yellow
  $results |
    Sort-Object -Property EOLSoftwareCount -Descending |
    Select-Object -First 10 DeviceName, EOLSoftwareCount, OldestEOLDate |
    Format-Table -AutoSize

} catch {
  Write-Error "Query failed: $($_.Exception.Message)"
  if ($_.Exception.Response -and $_.Exception.Response.Content) {
    Write-Host "Response content:" -ForegroundColor DarkYellow
    Write-Host $_.Exception.Response.Content
  }
  throw
}
