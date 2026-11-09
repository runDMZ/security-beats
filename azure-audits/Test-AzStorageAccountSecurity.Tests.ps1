BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    $script:Path = $PSCommandPath -replace '\.Tests\.ps1$', '.ps1'
}

Describe 'Test-AzStorageAccountSecurity' {
    BeforeAll {
        Initialize-AzConnectionMock
        Mock Get-AzStorageAccount {
            [pscustomobject]@{ StorageAccountName = 'sthardened'; ResourceGroupName = 'rg-a'; Id = 'st1'
                EnableHttpsTrafficOnly = $true; MinimumTlsVersion = 'TLS1_2'; AllowBlobPublicAccess = $false
                AllowSharedKeyAccess = $false; PublicNetworkAccess = 'Enabled'; NetworkRuleSet = [pscustomobject]@{ DefaultAction = 'Deny' } }
            [pscustomobject]@{ StorageAccountName = 'stlegacy'; ResourceGroupName = 'rg-a'; Id = 'st2'
                EnableHttpsTrafficOnly = $false; MinimumTlsVersion = 'TLS1_0'; AllowBlobPublicAccess = $null
                AllowSharedKeyAccess = $true; PublicNetworkAccess = 'Enabled'; NetworkRuleSet = [pscustomobject]@{ DefaultAction = 'Allow' } }
        }
        $script:Result = & $script:Path
    }

    It 'passes every check for a hardened account' {
        ($Result | Where-Object StorageAccount -EQ 'sthardened').Status | Should -Not -Contain 'Fail'
        ($Result | Where-Object StorageAccount -EQ 'sthardened').Status | Should -Not -Contain 'Warn'
    }
    It 'fails HTTPS, TLS, shared key and network checks for a legacy account' {
        $legacy = $Result | Where-Object StorageAccount -EQ 'stlegacy'
        ($legacy | Where-Object Status -EQ 'Fail').Check | Sort-Object |
            Should -Be @('HttpsOnly', 'MinimumTls', 'NetworkAccess', 'SharedKeyAccess')
    }
    It 'warns when anonymous blob access is not set explicitly' {
        ($Result | Where-Object { $_.StorageAccount -eq 'stlegacy' -and $_.Check -eq 'BlobPublicAccess' }).Status | Should -Be 'Warn'
    }
    It 'gives a recommendation only for checks that did not pass' {
        ($Result | Where-Object Status -EQ 'Pass').Recommendation | Should -Not -Contain 'Set the minimum TLS version to 1.2'
        ($Result | Where-Object { $_.StorageAccount -eq 'stlegacy' -and $_.Check -eq 'MinimumTls' }).Recommendation | Should -Not -BeNullOrEmpty
    }
    It 'returns only checks that did not pass with -FailedOnly' {
        (& $script:Path -FailedOnly).Status | Should -Not -Contain 'Pass'
    }
}
