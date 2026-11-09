#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Network

<#
.SYNOPSIS
    Finds what is reachable from the Internet: open NSG rules and VMs with a public IP.

.DESCRIPTION
    Read-only. Reports:
      - OpenNsgRule  inbound "Allow" rules whose source is any address
                     (*, 0.0.0.0/0, Internet, Any). Severity is High when the rule
                     covers an administration or database port (see -SensitivePort)
                     or all ports, Medium otherwise.
      - VmPublicIp   public IPs attached directly to a network interface: the VM is
                     exposed without a load balancer, Bastion or firewall in front.

    Each NSG finding says whether the NSG is attached to anything: a rule on a
    detached NSG has no effect today, but becomes live as soon as it is attached.

    Required role: Reader on the subscriptions.

.PARAMETER SubscriptionId
    One or more subscription IDs. Default: every enabled subscription of the current tenant.

.PARAMETER SensitivePort
    Ports that raise the severity to High. Default: SSH, RDP, WinRM, SMB, RPC, Telnet,
    FTP and common database ports.

.PARAMETER OutputPath
    Optional path of a CSV file to write the results to.

.EXAMPLE
    ./Test-AzNetworkExposure.ps1 | Where-Object Severity -EQ 'High' | Format-Table
#>
[CmdletBinding()]
param(
    [string[]] $SubscriptionId,
    [int[]] $SensitivePort = @(20, 21, 22, 23, 135, 445, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 27017),
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AnySource = @('*', '0.0.0.0/0', '0.0.0.0', 'Internet', 'Any', '::/0')

function Get-TargetSubscription {
    param([string[]] $Id)
    $context = Get-AzContext
    if (-not $context) { throw 'Not connected to Azure. Run Connect-AzAccount first.' }
    if ($Id) {
        foreach ($subId in $Id) { Get-AzSubscription -SubscriptionId $subId -TenantId $context.Tenant.Id }
    } else {
        Get-AzSubscription -TenantId $context.Tenant.Id | Where-Object State -EQ 'Enabled'
    }
}

function Test-PortMatch {
    # True if one of the NSG port expressions ("22", "1000-2000", "*") covers a port of the list
    param([string[]] $PortRange, [int[]] $Port)
    foreach ($range in $PortRange) {
        if ($range -eq '*') { return $true }
        if ($range -match '^(\d+)-(\d+)$') {
            $low = [int]$Matches[1]; $high = [int]$Matches[2]
            if ($Port | Where-Object { $_ -ge $low -and $_ -le $high }) { return $true }
        } elseif ($range -match '^\d+$' -and [int]$range -in $Port) {
            return $true
        }
    }
    return $false
}

$originalContext = Get-AzContext
$results = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($sub in Get-TargetSubscription -Id $SubscriptionId) {
        Write-Verbose "Subscription $($sub.Name) ($($sub.Id))"
        $null = Set-AzContext -Subscription $sub.Id

        foreach ($nsg in Get-AzNetworkSecurityGroup) {
            $attached = (@($nsg.NetworkInterfaces).Count + @($nsg.Subnets).Count) -gt 0
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Direction -ne 'Inbound' -or $rule.Access -ne 'Allow') { continue }
                $openSources = @($rule.SourceAddressPrefix | Where-Object { $_ -in $AnySource })
                if ($openSources.Count -eq 0) { continue }

                $ports = @($rule.DestinationPortRange)
                $severity = if (Test-PortMatch -PortRange $ports -Port $SensitivePort) { 'High' } else { 'Medium' }
                $results.Add([pscustomobject]@{
                        SubscriptionName = $sub.Name
                        Category         = 'OpenNsgRule'
                        Severity         = $severity
                        Resource         = ('{0} / {1}' -f $nsg.Name, $rule.Name)
                        ResourceGroup    = $nsg.ResourceGroupName
                        Details          = ('Ports {0} {1} from {2}, priority {3}{4}' -f ($ports -join ','), $rule.Protocol, ($openSources -join ','), $rule.Priority, $(if ($attached) { '' } else { ' (NSG not attached)' }))
                        ResourceId       = $rule.Id
                    })
            }
        }

        foreach ($ip in Get-AzPublicIpAddress) {
            if ($ip.IpConfiguration -and $ip.IpConfiguration.Id -match '/networkInterfaces/([^/]+)/') {
                $results.Add([pscustomobject]@{
                        SubscriptionName = $sub.Name
                        Category         = 'VmPublicIp'
                        Severity         = 'Medium'
                        Resource         = $ip.Name
                        ResourceGroup    = $ip.ResourceGroupName
                        Details          = ('{0} on network interface {1}' -f $ip.IpAddress, $Matches[1])
                        ResourceId       = $ip.Id
                    })
            }
        }
    }
} finally {
    if ($originalContext) { $null = Set-AzContext -Context $originalContext }
}

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8
    Write-Verbose "Written to $OutputPath"
}
$results
