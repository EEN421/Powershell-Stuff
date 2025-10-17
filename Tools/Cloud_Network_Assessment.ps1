# Azure Network Inventory Script 
# Author: Ian Hanley 
#
# Description:
#
# The Cloud_Network_Assessment.ps1 script is a PowerShell-based network discovery and reporting tool designed for Azure environments.
# It automates the collection of critical network configuration data across an Azure subscription, including Virtual Networks,
# Network Security Groups (NSGs), Route Tables, Virtual Network Gateways, and Peering connections.
#
#This script is especially useful for cloud engineers, security architects, and consultants conducting network assessments, security reviews,
# or documentation efforts. It outputs a set of CSV files for easy analysis and reporting, streamlining the visibility of Azure network topology and security posture.
#
# By running this script, you gain a comprehensive snapshot of your Azure network configuration, enabling better decision-making
# around governance, segmentation, and cloud architecture optimization.

# Notes:
# Ensure you're logged into Azure before running this script
# Run Connect-AzAccount if not already authenticated

$OutputDir = "C:\AzureNetworkReport"
$ZipPath = "$OutputDir\AzureNetworkReport.zip"
$CombinedCsv = "$OutputDir\AzureNetworkInventory.csv"

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# Login if not already
Connect-AzAccount -ErrorAction SilentlyContinue

# Prompt user to pick subscription
$subs = Get-AzSubscription | Sort-Object Name
$selection = $subs | Out-GridView -Title "Select Azure Subscription" -PassThru
if (-not $selection) {
    Write-Warning "No subscription selected. Exiting."
    return
}
Set-AzContext -SubscriptionId $selection.Id
$subName = $selection.Name

# Collect output rows here
$inventory = @()

# Iterate through all resource groups
$resourceGroups = Get-AzResourceGroup
foreach ($rg in $resourceGroups) {
    $rgName = $rg.ResourceGroupName
    Write-Host "Processing RG: $rgName" -ForegroundColor Yellow

    # --- NSGs ---
    $nsgs = Get-AzNetworkSecurityGroup -ResourceGroupName $rgName -ErrorAction SilentlyContinue
    foreach ($nsg in $nsgs) {
        foreach ($rule in $nsg.SecurityRules) {
            $inventory += [PSCustomObject]@{
                Subscription      = $subName
                ResourceGroup     = $rgName
                ResourceType      = "NetworkSecurityRule"
                ResourceName      = "$($nsg.Name) - $($rule.Name)"
                Detail1           = "Direction: $($rule.Direction)"
                Detail2           = "Protocol: $($rule.Protocol)"
                Detail3           = "Src: $($rule.SourceAddressPrefix):$($rule.SourcePortRange)"
                Detail4           = "Dst: $($rule.DestinationAddressPrefix):$($rule.DestinationPortRange)"
                AdditionalDetails = "Access: $($rule.Access); Priority: $($rule.Priority)"
            }
        }
    }

    # --- VNets ---
    $vnets = Get-AzVirtualNetwork -ResourceGroupName $rgName -ErrorAction SilentlyContinue
    foreach ($vnet in $vnets) {
        foreach ($subnet in $vnet.Subnets) {
            $inventory += [PSCustomObject]@{
                Subscription      = $subName
                ResourceGroup     = $rgName
                ResourceType      = "VNetSubnet"
                ResourceName      = "$($vnet.Name)/$($subnet.Name)"
                Detail1           = "Location: $($vnet.Location)"
                Detail2           = "AddressSpace: $($vnet.AddressSpace.AddressPrefixes -join ', ')"
                Detail3           = "SubnetPrefix: $($subnet.AddressPrefix)"
                Detail4           = ""
                AdditionalDetails = ""
            }
        }
    }

    # --- VPN Gateways ---
    $gateways = Get-AzVirtualNetworkGateway -ResourceGroupName $rgName -ErrorAction SilentlyContinue
    foreach ($gw in $gateways) {
        $inventory += [PSCustomObject]@{
            Subscription      = $subName
            ResourceGroup     = $rgName
            ResourceType      = "VirtualNetworkGateway"
            ResourceName      = $gw.Name
            Detail1           = "Type: $($gw.GatewayType)"
            Detail2           = "VPN Type: $($gw.VpnType)"
            Detail3           = "Sku: $($gw.Sku.Name)"
            Detail4           = "Enable BGP: $($gw.EnableBgp)"
            AdditionalDetails = ""
        }
    }

    # --- VPN Connections ---
    $connections = Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $rgName -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        $inventory += [PSCustomObject]@{
            Subscription      = $subName
            ResourceGroup     = $rgName
            ResourceType      = "VPNConnection"
            ResourceName      = $conn.Name
            Detail1           = "Type: $($conn.ConnectionType)"
            Detail2           = "Enable BGP: $($conn.EnableBgp)"
            Detail3           = "Shared Key: $($conn.SharedKey)"
            Detail4           = "VNetGW1: $($conn.VirtualNetworkGateway1.Id)"
            AdditionalDetails = "VNetGW2: $($conn.VirtualNetworkGateway2.Id)"
        }
    }

    # --- Azure Firewalls ---
    $firewalls = Get-AzFirewall -ResourceGroupName $rgName -ErrorAction SilentlyContinue
    foreach ($fw in $firewalls) {
        foreach ($rc in $fw.NetworkRuleCollections) {
            foreach ($rule in $rc.Rules) {
                $inventory += [PSCustomObject]@{
                    Subscription      = $subName
                    ResourceGroup     = $rgName
                    ResourceType      = "AzureFirewallRule"
                    ResourceName      = "$($fw.Name) - $($rule.Name)"
                    Detail1           = "Collection: $($rc.Name)"
                    Detail2           = "Protocols: $($rule.Protocols -join ', ')"
                    Detail3           = "Src: $($rule.SourceAddresses -join ', ')"
                    Detail4           = "Dst: $($rule.DestinationAddresses -join ', '):$($rule.DestinationPorts -join ', ')"
                    AdditionalDetails = ""
                }
            }
        }
    }

    # --- Application Gateways ---
    $appgws = Get-AzApplicationGateway -ResourceGroupName $rgName -ErrorAction SilentlyContinue
    foreach ($ag in $appgws) {
        foreach ($listener in $ag.HttpListeners) {
            $inventory += [PSCustomObject]@{
                Subscription      = $subName
                ResourceGroup     = $rgName
                ResourceType      = "ApplicationGatewayListener"
                ResourceName      = "$($ag.Name)/$($listener.Name)"
                Detail1           = "Protocol: $($listener.Protocol)"
                Detail2           = "HostName: $($listener.HostName)"
                Detail3           = "FrontendPort: $($listener.FrontendPort.Id)"
                Detail4           = ""
                AdditionalDetails = ""
            }
        }
    }

    # --- ExpressRoute Circuits ---
    $circuits = Get-AzExpressRouteCircuit -ResourceGroupName $rgName -ErrorAction SilentlyContinue
    foreach ($circuit in $circuits) {
        $inventory += [PSCustomObject]@{
            Subscription      = $subName
            ResourceGroup     = $rgName
            ResourceType      = "ExpressRouteCircuit"
            ResourceName      = $circuit.Name
            Detail1           = "Sku: $($circuit.Sku.Tier) - $($circuit.Sku.Family)"
            Detail2           = "Provider: $($circuit.ServiceProviderProperties.ServiceProviderName)"
            Detail3           = "Peering: $($circuit.ServiceProviderProperties.PeeringLocation)"
            Detail4           = "Bandwidth: $($circuit.ServiceProviderProperties.BandwidthInMbps) Mbps"
            AdditionalDetails = "State: $($circuit.ProvisioningState)"
        }
    }
}

# Output final CSV
$inventory | Export-Csv -Path $CombinedCsv -NoTypeInformation

# Zip results
if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }
Compress-Archive -Path $CombinedCsv -DestinationPath $ZipPath

Write-Host "`n✅ All results written to: $CombinedCsv"
Write-Host "📦 Zipped as: $ZipPath" -ForegroundColor Green
