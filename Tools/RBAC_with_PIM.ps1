# Azure RBAC Privileged Roles Audit Script
# Author: Ian Hanley 
#
# Description:
#
# This script is a purpose-built PowerShell tool that identifies and reports on privileged role assignments within an Azure environment.
# It scans the selected subscription for users, groups, and service principals assigned elevated Azure Role-Based Access Control (RBAC) roles such as Owner,
# Contributor, and Security Admin across all scopes.
#
# This is ideal for security teams, auditors, and Azure administrators seeking to maintain least-privilege access principles, enforce governance, or prepare for
# compliance reviews. It outputs a detailed CSV report and optionally generates an HTML summary for executive-level visibility.
#
# By surfacing privileged role assignments in a clear, actionable format, this tool enhances your ability to monitor, review,
# and remediate access risks in alignment with Zero Trust and Microsoft security best practices.
#
# Notes:
# Ensure you're logged into Azure before running this script
# Run Connect-AzAccount if not already authenticated
# Requires Az.Resources version that includes:
#   Get-AzRoleAssignmentScheduleInstance
#   Get-AzRoleEligibilityScheduleInstance

# Parameters
param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputCSVPath = ".\AzurePrivilegedRolesReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputHTMLPath = ".\AzurePrivilegedRolesReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeResourceGroups = $true,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "HTML", "Both")]
    [string]$OutputFormat = "Both"
)

# Function to display script progress
function Write-ProgressHelper {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

# Set of privileged role names to look for
$privilegedRoles = @(
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Co-Administrator",
    "Service Administrator",
    "Account Administrator",
    "Key Vault Administrator",
    "SQL DB Contributor",
    "SQL Security Manager",
    "Storage Account Contributor",
    "Azure Kubernetes Service Cluster Admin Role",
    "Virtual Machine Administrator Login",
    "Virtual Machine Contributor",
    "Network Contributor",
    "Security Administrator",
    "Azure Service Deploy Release Management Contributor",
    "Automation Contributor",
    "Log Analytics Contributor",
    "Application Administrator",
    "Cloud Application Administrator"
)

# Initialize result collection
$results = @()

Write-Host "Starting Azure RBAC Privileged Roles Audit..." -ForegroundColor Cyan

# Select subscription
if ([string]::IsNullOrEmpty($SubscriptionId)) {
    # No subscription ID provided, use the current context
    try {
        $context = Get-AzContext
        if (-not $context) {
            Write-Host "You're not connected to Azure. Please run Connect-AzAccount first." -ForegroundColor Red
            exit
        }
        $SubscriptionId = $context.Subscription.Id
    }
    catch {
        Write-Host "Error getting Azure context: $_" -ForegroundColor Red
        exit
    }
}
else {
    # Use the provided subscription ID
    try {
        Select-AzSubscription -SubscriptionId $SubscriptionId | Out-Null
    }
    catch {
        Write-Host "Error selecting subscription $SubscriptionId : $_" -ForegroundColor Red
        exit
    }
}

# Get subscription details
try {
    $subscription = Get-AzSubscription -SubscriptionId $SubscriptionId
    Write-Host "Analyzing subscription: $($subscription.Name) ($SubscriptionId)" -ForegroundColor Green
}
catch {
    Write-Host "Error retrieving subscription information: $_" -ForegroundColor Red
    exit
}

# ---------------------------------------------
# PIM lookup: pre-load schedule instances
# ---------------------------------------------
Write-Host "Loading PIM schedule instances for subscription..." -ForegroundColor Yellow

$pimLookupAvailable = $true
$activePimIndex    = @{}
$eligiblePimIndex  = @{}

try {
    # Subscription-level scope (includes children)
    $subscriptionScopePath = "/subscriptions/$SubscriptionId"

    # Active PIM assignment schedule instances
    $activePimInstances = Get-AzRoleAssignmentScheduleInstance -Scope $subscriptionScopePath -ErrorAction Stop
    foreach ($inst in $activePimInstances) {
        # Expect properties: Scope, PrincipalId, RoleDefinitionId, Status
        $key = "$($inst.Scope)|$($inst.PrincipalId)|$($inst.RoleDefinitionId)"
        $activePimIndex[$key] = $inst
    }

    # Eligible PIM schedule instances
    $eligiblePimInstances = Get-AzRoleEligibilityScheduleInstance -Scope $subscriptionScopePath -ErrorAction Stop
    foreach ($inst in $eligiblePimInstances) {
        # Expect properties: Scope, PrincipalId, RoleDefinitionId, Status
        $key = "$($inst.Scope)|$($inst.PrincipalId)|$($inst.RoleDefinitionId)"
        $eligiblePimIndex[$key] = $inst
    }

    Write-Host "PIM lookup loaded: $($activePimIndex.Count) active instances, $($eligiblePimIndex.Count) eligible instances." -ForegroundColor Green
}
catch {
    Write-Warning "PIM lookup failed or PIM not enabled for Azure resources. IsPIM will be reported as 'Unknown'. Error: $_"
    $pimLookupAvailable = $false
}

function Get-PimStatusForAssignment {
    param(
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$PrincipalId,
        [Parameter(Mandatory = $true)][string]$RoleDefinitionId
    )

    if (-not $pimLookupAvailable) {
        return "Unknown"
    }

    if ([string]::IsNullOrEmpty($Scope) -or
        [string]::IsNullOrEmpty($PrincipalId) -or
        [string]::IsNullOrEmpty($RoleDefinitionId)) {
        return "Unknown"
    }

    $key = "$Scope|$PrincipalId|$RoleDefinitionId"

    if ($activePimIndex.ContainsKey($key)) {
        $status = $activePimIndex[$key].Status
        if ([string]::IsNullOrEmpty($status)) { $status = "Active" }
        return "Active (PIM - $status)"
    }

    if ($eligiblePimIndex.ContainsKey($key)) {
        $status = $eligiblePimIndex[$key].Status
        if ([string]::IsNullOrEmpty($status)) { $status = "Eligible" }
        return "Eligible (PIM - $status)"
    }

    # No PIM schedule found for this principal/role/scope
    return "Direct (non-PIM)"
}

# Get subscription-level role assignments
Write-ProgressHelper -Activity "Analyzing Azure RBAC" -Status "Getting subscription-level role assignments" -PercentComplete 20
Write-Host "Getting subscription-level role assignments..." -ForegroundColor Yellow

try {
    $subRoleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId"
    
    # Filter for privileged roles
    $privilegedAssignments = $subRoleAssignments | Where-Object { $privilegedRoles -contains $_.RoleDefinitionName }
    
    foreach ($assignment in $privilegedAssignments) {
        $principalType = $assignment.ObjectType
        $principalName = ""
        
        # Get display name based on principal type
        try {
            if ($principalType -eq "User") {
                $user = Get-AzADUser -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
                if ($user) {
                    $principalName = $user.DisplayName
                }
                else {
                    $principalName = $assignment.DisplayName
                }
            }
            elseif ($principalType -eq "Group") {
                $group = Get-AzADGroup -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
                if ($group) {
                    $principalName = $group.DisplayName
                }
                else {
                    $principalName = $assignment.DisplayName
                }
            }
            elseif ($principalType -eq "ServicePrincipal") {
                $sp = Get-AzADServicePrincipal -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
                if ($sp) {
                    $principalName = $sp.DisplayName
                }
                else {
                    $principalName = $assignment.DisplayName
                }
            }
            else {
                $principalName = $assignment.DisplayName
            }
        }
        catch {
            $principalName = $assignment.DisplayName
            Write-Host "Warning: Could not resolve display name for $($assignment.ObjectId)" -ForegroundColor Yellow
        }

        # Resolve PIM status for this assignment
        $assignmentScope = $assignment.Scope
        $roleDefinitionId = $assignment.RoleDefinitionId
        $pimStatus = Get-PimStatusForAssignment -Scope $assignmentScope `
                                                -PrincipalId $assignment.ObjectId `
                                                -RoleDefinitionId $roleDefinitionId
        
        # Create result object
        $resultObject = [PSCustomObject]@{
            SubscriptionName  = $subscription.Name
            SubscriptionId    = $SubscriptionId
            Scope             = "Subscription"
            ResourceGroupName = "N/A"
            RoleName          = $assignment.RoleDefinitionName
            PrincipalType     = $principalType
            PrincipalId       = $assignment.ObjectId
            PrincipalName     = $principalName
            SignInName        = $assignment.SignInName
            AssignmentId      = $assignment.RoleAssignmentId
            IsPIM             = $pimStatus
        }
        
        $results += $resultObject
    }
    
    Write-Host "Found $($privilegedAssignments.Count) privileged role assignments at subscription level" -ForegroundColor Green
}
catch {
    Write-Host "Error getting subscription role assignments: $_" -ForegroundColor Red
}

# Get resource group-level role assignments if requested
if ($IncludeResourceGroups) {
    Write-ProgressHelper -Activity "Analyzing Azure RBAC" -Status "Getting resource group role assignments" -PercentComplete 50
    Write-Host "Getting resource group-level role assignments..." -ForegroundColor Yellow
    
    try {
        $resourceGroups = Get-AzResourceGroup
        $totalRgs = $resourceGroups.Count
        $currentRg = 0
        
        foreach ($rg in $resourceGroups) {
            $currentRg++
            $percentComplete = [math]::Min(50 + [math]::Floor(($currentRg / $totalRgs) * 40), 90)
            Write-ProgressHelper -Activity "Analyzing Azure RBAC" -Status "Processing resource group $currentRg of $totalRgs" -PercentComplete $percentComplete
            
            $rgScope = "/subscriptions/$SubscriptionId/resourceGroups/$($rg.ResourceGroupName)"
            $rgRoleAssignments = Get-AzRoleAssignment -Scope $rgScope
            
            # Filter for privileged roles
            $rgPrivilegedAssignments = $rgRoleAssignments | Where-Object { $privilegedRoles -contains $_.RoleDefinitionName }
            
            foreach ($assignment in $rgPrivilegedAssignments) {
                $principalType = $assignment.ObjectType
                $principalName = ""
                
                # Get display name based on principal type (same logic as before)
                try {
                    if ($principalType -eq "User") {
                        $user = Get-AzADUser -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
                        if ($user) {
                            $principalName = $user.DisplayName
                        }
                        else {
                            $principalName = $assignment.DisplayName
                        }
                    }
                    elseif ($principalType -eq "Group") {
                        $group = Get-AzADGroup -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
                        if ($group) {
                            $principalName = $group.DisplayName
                        }
                        else {
                            $principalName = $assignment.DisplayName
                        }
                    }
                    elseif ($principalType -eq "ServicePrincipal") {
                        $sp = Get-AzADServicePrincipal -ObjectId $assignment.ObjectId -ErrorAction SilentlyContinue
                        if ($sp) {
                            $principalName = $sp.DisplayName
                        }
                        else {
                            $principalName = $assignment.DisplayName
                        }
                    }
                    else {
                        $principalName = $assignment.DisplayName
                    }
                }
                catch {
                    $principalName = $assignment.DisplayName
                }

                # Resolve PIM status for this assignment
                $assignmentScope = $assignment.Scope
                $roleDefinitionId = $assignment.RoleDefinitionId
                $pimStatus = Get-PimStatusForAssignment -Scope $assignmentScope `
                                                        -PrincipalId $assignment.ObjectId `
                                                        -RoleDefinitionId $roleDefinitionId
                
                # Create result object
                $resultObject = [PSCustomObject]@{
                    SubscriptionName  = $subscription.Name
                    SubscriptionId    = $SubscriptionId
                    Scope             = "Resource Group"
                    ResourceGroupName = $rg.ResourceGroupName
                    RoleName          = $assignment.RoleDefinitionName
                    PrincipalType     = $principalType
                    PrincipalId       = $assignment.ObjectId
                    PrincipalName     = $principalName
                    SignInName        = $assignment.SignInName
                    AssignmentId      = $assignment.RoleAssignmentId
                    IsPIM             = $pimStatus
                }
                
                $results += $resultObject
            }
        }
        
        Write-Host "Processed $totalRgs resource groups" -ForegroundColor Green
    }
    catch {
        Write-Host "Error getting resource group role assignments: $_" -ForegroundColor Red
    }
}

# Generate summary statistics
Write-ProgressHelper -Activity "Analyzing Azure RBAC" -Status "Generating report" -PercentComplete 95
Write-Host "Generating summary report..." -ForegroundColor Yellow

$roleStats = $results | Group-Object -Property RoleName | 
            Select-Object @{N='Role';E={$_.Name}}, @{N='Count';E={$_.Count}} |
            Sort-Object -Property Count -Descending

$principalTypeStats = $results | Group-Object -Property PrincipalType | 
                      Select-Object @{N='PrincipalType';E={$_.Name}}, @{N='Count';E={$_.Count}} |
                      Sort-Object -Property Count -Descending

$scopeStats = $results | Group-Object -Property Scope | 
              Select-Object @{N='Scope';E={$_.Name}}, @{N='Count';E={$_.Count}} |
              Sort-Object -Property Count -Descending

# Display summary statistics
Write-Host "`nPrivileged Role Assignment Summary for Subscription: $($subscription.Name)" -ForegroundColor Cyan
Write-Host "===================================================================" -ForegroundColor Cyan
Write-Host "Total privileged role assignments found: $($results.Count)" -ForegroundColor Green
Write-Host "`nBreakdown by Role:" -ForegroundColor Green
$roleStats | Format-Table -AutoSize

Write-Host "`nBreakdown by Principal Type:" -ForegroundColor Green
$principalTypeStats | Format-Table -AutoSize

Write-Host "`nBreakdown by Scope:" -ForegroundColor Green
$scopeStats | Format-Table -AutoSize

# Export results to file(s)
if ($results.Count -gt 0) {
    # Export to CSV if requested
    if ($OutputFormat -eq "CSV" -or $OutputFormat -eq "Both") {
        try {
            $results | Export-Csv -Path $OutputCSVPath -NoTypeInformation
            Write-Host "`nDetailed CSV report exported to: $OutputCSVPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Error exporting report to CSV: $_" -ForegroundColor Red
        }
    }
    
    # Export to HTML if requested
    if ($OutputFormat -eq "HTML" -or $OutputFormat -eq "Both") {
        try {
            # Create HTML report with styling
            $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure RBAC Privileged Roles Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; }
        h1, h2 { color: #0078D4; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th { background-color: #0078D4; color: white; text-align: left; padding: 8px; }
        td { border: 1px solid #ddd; padding: 8px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        tr:hover { background-color: #ddd; }
        .summary { background-color: #EFF6FC; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .warning { color: #D83B01; }
        .timestamp { color: #777; font-size: 0.9em; }
        .container { max-width: 1200px; margin: 0 auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure RBAC Privileged Roles Audit Report</h1>
        <p class="timestamp">Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
"@

            # Summary section
            $htmlSummary = @"
        <div class="summary">
            <h2>Summary</h2>
            <p><strong>Subscription:</strong> $($subscription.Name) ($SubscriptionId)</p>
            <p><strong>Total privileged role assignments found:</strong> $($results.Count)</p>
        </div>
"@

            # Role statistics
            $roleStatsHtml = @"
        <h2>Breakdown by Role</h2>
        <table>
            <tr>
                <th>Role</th>
                <th>Count</th>
            </tr>
"@
            foreach ($roleStat in $roleStats) {
                $roleStatsHtml += @"
            <tr>
                <td>$($roleStat.Role)</td>
                <td>$($roleStat.Count)</td>
            </tr>
"@
            }
            $roleStatsHtml += "</table>"

            # Principal Type statistics
            $principalTypeStatsHtml = @"
        <h2>Breakdown by Principal Type</h2>
        <table>
            <tr>
                <th>Principal Type</th>
                <th>Count</th>
            </tr>
"@
            foreach ($principalTypeStat in $principalTypeStats) {
                $principalTypeStatsHtml += @"
            <tr>
                <td>$($principalTypeStat.PrincipalType)</td>
                <td>$($principalTypeStat.Count)</td>
            </tr>
"@
            }
            $principalTypeStatsHtml += "</table>"

            # Scope statistics
            $scopeStatsHtml = @"
        <h2>Breakdown by Scope</h2>
        <table>
            <tr>
                <th>Scope</th>
                <th>Count</th>
            </tr>
"@
            foreach ($scopeStat in $scopeStats) {
                $scopeStatsHtml += @"
            <tr>
                <td>$($scopeStat.Scope)</td>
                <td>$($scopeStat.Count)</td>
            </tr>
"@
            }
            $scopeStatsHtml += "</table>"

            # Detailed results table
            $detailedResultsHtml = @"
        <h2>Detailed Privileged Role Assignments</h2>
        <table>
            <tr>
                <th>Scope</th>
                <th>Resource Group</th>
                <th>Role Name</th>
                <th>Principal Type</th>
                <th>Principal Name</th>
                <th>Sign-In Name</th>
                <th>PIM Status</th>
            </tr>
"@
            foreach ($result in $results) {
                $rowColor = ""
                if ($result.RoleName -eq "Owner" -or $result.RoleName -eq "Contributor") {
                    $rowColor = ' style="background-color: #FFF1F0;"'
                }
                
                $detailedResultsHtml += @"
            <tr$rowColor>
                <td>$($result.Scope)</td>
                <td>$($result.ResourceGroupName)</td>
                <td>$($result.RoleName)</td>
                <td>$($result.PrincipalType)</td>
                <td>$($result.PrincipalName)</td>
                <td>$($result.SignInName)</td>
                <td>$($result.IsPIM)</td>
            </tr>
"@
            }
            $detailedResultsHtml += "</table>"

            # Combine all HTML content
            $htmlFooter = @"
        <p class="timestamp">Report generated by Azure RBAC Privileged Roles Audit Script</p>
    </div>
</body>
</html>
"@

            $completeHtml = $htmlHeader + $htmlSummary + $roleStatsHtml + $principalTypeStatsHtml + $scopeStatsHtml + $detailedResultsHtml + $htmlFooter

            # Save HTML file
            $completeHtml | Out-File -FilePath $OutputHTMLPath -Encoding utf8
            Write-Host "Detailed HTML report exported to: $OutputHTMLPath" -ForegroundColor Green
        }
        catch {
            Write-Host "Error generating HTML report: $_" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "`nNo privileged role assignments found to export." -ForegroundColor Yellow
}

Write-ProgressHelper -Activity "Analyzing Azure RBAC" -Status "Completed" -PercentComplete 100
Write-Host "`nAzure RBAC Privileged Roles Audit completed!" -ForegroundColor Cyan

# Return results for pipeline usage
return $results
