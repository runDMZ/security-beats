#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Storage

<#
.SYNOPSIS
    Checks the security settings of every storage account.

.DESCRIPTION
    Read-only. Returns one object per storage account and per check, with a status
    (Pass, Fail or Warn):
      - HttpsOnly            secure transfer required
      - MinimumTls           TLS 1.2 or above
      - BlobPublicAccess     anonymous blob access disabled on the account
      - SharedKeyAccess      account keys disabled (Entra ID authentication only)
      - NetworkAccess        public network access disabled, or firewall in "Deny" by default

    An unset value (Warn) means Azure applies its default, which depends on the age
    of the account: older accounts default to the permissive value. Set it explicitly.

    Required role: Reader on the subscriptions.

.PARAMETER SubscriptionId
    One or more subscription IDs. Default: every enabled subscription of the current tenant.

.PARAMETER FailedOnly
    Only return checks that did not pass.

.PARAMETER OutputPath
    Optional path of a CSV file to write the results to.

.EXAMPLE
    ./Test-AzStorageAccountSecurity.ps1 -FailedOnly | Format-Table StorageAccount, Check, Status, Value
#>
[CmdletBinding()]
param(
    [string[]] $SubscriptionId,
    [switch] $FailedOnly,
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

function Get-StorageCheck {
    # Returns the list of checks for one storage account
    param($Account)

    $tls = $Account.MinimumTlsVersion
    $defaultAction = if ($Account.NetworkRuleSet) { [string]$Account.NetworkRuleSet.DefaultAction } else { $null }

    @(
        @{ Check = 'HttpsOnly'; Value = $Account.EnableHttpsTrafficOnly
            Status = if ($Account.EnableHttpsTrafficOnly -eq $true) { 'Pass' } elseif ($null -eq $Account.EnableHttpsTrafficOnly) { 'Warn' } else { 'Fail' }
            Fix = 'Enable "Secure transfer required"' }

        @{ Check = 'MinimumTls'; Value = $tls
            Status = if ($tls -in 'TLS1_2', 'TLS1_3') { 'Pass' } elseif (-not $tls) { 'Warn' } else { 'Fail' }
            Fix = 'Set the minimum TLS version to 1.2' }

        @{ Check = 'BlobPublicAccess'; Value = $Account.AllowBlobPublicAccess
            Status = if ($Account.AllowBlobPublicAccess -eq $false) { 'Pass' } elseif ($null -eq $Account.AllowBlobPublicAccess) { 'Warn' } else { 'Fail' }
            Fix = 'Disable "Allow Blob anonymous access"' }

        @{ Check = 'SharedKeyAccess'; Value = $Account.AllowSharedKeyAccess
            Status = if ($Account.AllowSharedKeyAccess -eq $false) { 'Pass' } elseif ($null -eq $Account.AllowSharedKeyAccess) { 'Warn' } else { 'Fail' }
            Fix = 'Disable "Allow storage account key access" once apps use Entra ID' }

        @{ Check = 'NetworkAccess'; Value = 'PublicNetworkAccess={0}; DefaultAction={1}' -f $Account.PublicNetworkAccess, $defaultAction
            Status = if ($Account.PublicNetworkAccess -eq 'Disabled' -or $defaultAction -eq 'Deny') { 'Pass' } else { 'Fail' }
            Fix = 'Disable public network access, or set the firewall default action to Deny' }
    )
}

$originalContext = Get-AzContext
$results = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($sub in Get-TargetSubscription -Id $SubscriptionId) {
        Write-Verbose "Subscription $($sub.Name) ($($sub.Id))"
        $null = Set-AzContext -Subscription $sub.Id

        foreach ($account in Get-AzStorageAccount) {
            foreach ($check in Get-StorageCheck -Account $account) {
                if ($FailedOnly -and $check.Status -eq 'Pass') { continue }
                $results.Add([pscustomobject]@{
                        SubscriptionName = $sub.Name
                        StorageAccount   = $account.StorageAccountName
                        ResourceGroup    = $account.ResourceGroupName
                        Check            = $check.Check
                        Status           = $check.Status
                        Value            = $check.Value
                        Recommendation   = if ($check.Status -eq 'Pass') { '' } else { $check.Fix }
                        ResourceId       = $account.Id
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
