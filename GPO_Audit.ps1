$reportFolder = "C:\GPOReports"
if (-not (Test-Path $reportFolder)) {
    New-Item -Path $reportFolder -ItemType Directory | Out-Null
}
 
$GPOs = Get-GPO -All
foreach ($gpo in $GPOs) {
    try {
        $safeName = ($gpo.DisplayName -replace '[\\/:*?"<>|]', '_')
        $reportPath = "$reportFolder\$safeName.html"
        Get-GPOReport -Name $gpo.DisplayName -ReportType Html -Path $reportPath
    } catch {
        Write-Warning "Failed to export report for $($gpo.DisplayName): $_"
    }
}
