# The parameters can be submitted in line with the command to run the script like this...
# Example:
# .\Submit-Indicator.ps1 -indicatorType FileSha1 -indicatorValue  xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -action AlertAndBlock -severity High -title "Ian's Test" -description "This IoC was pushed from a powershell command that leverages an EntraID Registered API for authentication and permissions - Ian Hanley" -recommendedActions "This can be ignored - for testing purposes only"

# For a variation of this script that prompts for the required parameters, visit https://github.com/EEN421/Powershell-Stuff/blob/Main/IOC%20Demo/Prompt/Submit_Indicator.ps1

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

$token = .\Get-Token.ps1                              #Execute Get-Token.ps1 script to get the authorization token

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

if($response.StatusCode -eq 200)   #chcek the response status code
{
    return $true        #update ended successfully
}
else
{
    return $false       #update failed
}
