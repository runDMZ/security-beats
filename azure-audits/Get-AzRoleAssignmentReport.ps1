#Requires -Version 7.2
#Requires -Modules Az.Accounts, Az.Resources

<#
.SYNOPSIS
    Audits Azure RBAC role assignments and flags the risky ones.

.DESCRIPTION
    Read-only. Returns every role assignment of the subscriptions (including those
    inherited from management groups) with a list of findings:
      - PrivilegedRole   Owner, Contributor, User Access Administrator or
                         Role Based Access Control Administrator
      - OrphanedPrincipal the principal was not found in Entra ID (deleted user,
                         group or app). May also mean you lack the right to read
                         the directory: confirm before removing.
      - GuestUser        external (#EXT#) account
      - DirectUserAssignment role given to a user instead of a group
      - SubscriptionScope assignment on the whole subscription (or above)

    Required roles: Reader on the subscriptions, plus the right to read users,
    groups and service principals in Entra ID to resolve names.

.PARAMETER SubscriptionId
    One or more subscription IDs. Default: every enabled subscription of the current tenant.

.PARAMETER FindingsOnly
    Only return assignments that have at least one finding.

.PARAMETER OutputPath
    Optional path of a CSV file to write the results to.

.EXAMPLE
    ./Get-AzRoleAssignmentReport.ps1 -FindingsOnly | Format-Table Principal, Role, ScopeLevel, Findings

.EXAMPLE
    ./Get-AzRoleAssignmentReport.ps1 | Where-Object Findings -Match 'OrphanedPrincipal'
#>
[CmdletBinding()]
param(
    [string[]] $SubscriptionId,
    [switch] $FindingsOnly,
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PrivilegedRoles = @(
    'Owner'
    'Contributor'
    'User Access Administrator'
    'Role Based Access Control Administrator'
)

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

function Get-ScopeLevel {
    param([string] $Scope)
    switch -Regex ($Scope) {
        '^/$' { 'Root'; break }
        '^/providers/Microsoft\.Management/managementGroups/' { 'ManagementGroup'; break }
        '^/subscriptions/[^/]+/?$' { 'Subscription'; break }
        '^/subscriptions/[^/]+/resourceGroups/[^/]+/?$' { 'ResourceGroup'; break }
        default { 'Resource' }
    }
}

$originalContext = Get-AzContext
$results = [System.Collections.Generic.List[object]]::new()
try {
    foreach ($sub in Get-TargetSubscription -Id $SubscriptionId) {
        Write-Verbose "Subscription $($sub.Name) ($($sub.Id))"
        $null = Set-AzContext -Subscription $sub.Id

        foreach ($ra in Get-AzRoleAssignment) {
            $level = Get-ScopeLevel $ra.Scope
            $findings = [System.Collections.Generic.List[string]]::new()
            if ($ra.RoleDefinitionName -in $PrivilegedRoles) { $findings.Add('PrivilegedRole') }
            if ($ra.ObjectType -eq 'Unknown') { $findings.Add('OrphanedPrincipal') }
            if ($ra.SignInName -like '*#EXT#*') { $findings.Add('GuestUser') }
            if ($ra.ObjectType -eq 'User') { $findings.Add('DirectUserAssignment') }
            if ($level -in 'Root', 'ManagementGroup', 'Subscription') { $findings.Add('SubscriptionScope') }

            if ($FindingsOnly -and $findings.Count -eq 0) { continue }
            $results.Add([pscustomobject]@{
                    SubscriptionName = $sub.Name
                    Principal        = if ($ra.DisplayName) { $ra.DisplayName } else { $ra.ObjectId }
                    SignInName       = $ra.SignInName
                    ObjectType       = $ra.ObjectType
                    Role             = $ra.RoleDefinitionName
                    ScopeLevel       = $level
                    Scope            = $ra.Scope
                    Findings         = $findings -join '; '
                    RoleAssignmentId = $ra.RoleAssignmentId
                })
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
