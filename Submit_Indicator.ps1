param (   
    [Parameter(Mandatory=$true)]
    [ValidateSet('FileSha1','FileSha256','IpAddress','DomainName','Url')]   #validate that the input contains valid value
    [string]$indicatorType,

    [Parameter(Mandatory=$true)]
    [string]$indicatorValue,     #an input parameter for the alert's ID	    
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('Alert','AlertAndBlock','Allowed')]   #validate that the input contains valid value
    [string]$action = 'Alert',                         #set default action to 'Alert'
    
    [Parameter(Mandatory=$true)]
    [string]$title,     
   
    [Parameter(Mandatory=$false)]
    [ValidateSet('Informational','Low','Medium','High')]   #validate that the input contains valid value
    [string]$severity = 'Informational',                   #set default severity to 'informational'
    
    [Parameter(Mandatory=$true)]
    [string]$description,     

    [Parameter(Mandatory=$true)]
    [string]$recommendedActions     
)

# Prompt the user for the necessary values
$indicatorType = Read-Host -Prompt 'Enter the Indicator Type (FileSha1, FileSha256, IpAddress, DomainName, Url)'
$indicatorValue = Read-Host -Prompt 'Enter the Indicator Value'
$action = Read-Host -Prompt 'Enter the Action (Alert, AlertAndBlock, Allowed)' -Default 'Alert'
$title = Read-Host -Prompt 'Enter the Title'
$severity = Read-Host -Prompt 'Enter the Severity (Informational, Low, Medium, High)' -Default 'Informational'
$description = Read-Host -Prompt 'Enter the Description'
$recommendedActions = Read-Host -Prompt 'Enter the Recommended Actions'

$token = .\Get-Token.ps1                              # Execute Get-Token.ps1 script to get the authorization token

$url = "https://api.securitycenter.windows.com/api/indicators"

$body = 
@{
    indicatorValue = $indicatorValue        
    indicatorType = $indicatorType 
    action = $action
    title = $title 
    severity = $severity	
    description = $description 
    recommendedActions =  $recommendedActions 
}
 
$headers = @{ 
    'Content-Type' = 'application/json'
    Accept = 'application/json'
    Authorization = "Bearer $token"
}

$response = Invoke-WebRequest -Method Post -Uri $url -Body ($body | ConvertTo-Json) -Headers $headers -ErrorAction Stop

if($response.StatusCode -eq 200)   # Check the response status code
{
    return $true        # Update ended successfully
}
else
{
    return $false       # Update failed
}
