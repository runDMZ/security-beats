BeforeAll {
    . (Join-Path $PSScriptRoot 'Common.ps1')
    $script:Path = Get-ScriptPath 'azure-audits/Get-AzRoleAssignmentReport.ps1'
}

Describe 'Get-AzRoleAssignmentReport' {
    BeforeAll {
        Set-AzConnectionMock
        Mock Get-AzRoleAssignment {
            [pscustomobject]@{ DisplayName = 'Alice'; SignInName = 'alice@contoso.com'; ObjectType = 'User'; ObjectId = 'o1'
                RoleDefinitionName = 'Owner'; Scope = '/subscriptions/sub-1'; RoleAssignmentId = 'ra1' }
            [pscustomobject]@{ DisplayName = 'Ops team'; SignInName = $null; ObjectType = 'Group'; ObjectId = 'o2'
                RoleDefinitionName = 'Reader'; Scope = '/subscriptions/sub-1/resourceGroups/rg-a'; RoleAssignmentId = 'ra2' }
            [pscustomobject]@{ DisplayName = $null; SignInName = $null; ObjectType = 'Unknown'; ObjectId = 'deleted-id'
                RoleDefinitionName = 'Reader'; Scope = '/subscriptions/sub-1/resourceGroups/rg-a/providers/Microsoft.Storage/storageAccounts/st1'; RoleAssignmentId = 'ra3' }
            [pscustomobject]@{ DisplayName = 'Bob (guest)'; SignInName = 'bob_fabrikam.com#EXT#@contoso.onmicrosoft.com'; ObjectType = 'User'; ObjectId = 'o4'
                RoleDefinitionName = 'Reader'; Scope = '/providers/Microsoft.Management/managementGroups/root-mg'; RoleAssignmentId = 'ra4' }
        }
        $script:Result = & $script:Path
    }

    It 'flags a privileged role given directly to a user on the subscription' {
        ($Result | Where-Object Principal -EQ 'Alice').Findings |
            Should -Be 'PrivilegedRole; DirectUserAssignment; SubscriptionScope'
    }
    It 'has no finding for a Reader group on a resource group' {
        ($Result | Where-Object Principal -EQ 'Ops team').Findings | Should -BeNullOrEmpty
    }
    It 'flags an orphaned principal and shows its object ID' {
        $orphan = $Result | Where-Object RoleAssignmentId -EQ 'ra3'
        $orphan.Principal | Should -Be 'deleted-id'
        $orphan.Findings | Should -Match 'OrphanedPrincipal'
        $orphan.ScopeLevel | Should -Be 'Resource'
    }
    It 'flags a guest and an assignment inherited from a management group' {
        $guest = $Result | Where-Object Principal -EQ 'Bob (guest)'
        $guest.Findings | Should -Match 'GuestUser'
        $guest.ScopeLevel | Should -Be 'ManagementGroup'
    }
    It 'returns only assignments with findings when -FindingsOnly is used' {
        $filtered = & $script:Path -FindingsOnly
        $filtered.Principal | Should -Not -Contain 'Ops team'
        @($filtered).Count | Should -Be 3
    }
}
