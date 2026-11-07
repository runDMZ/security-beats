BeforeAll {
    . (Join-Path $PSScriptRoot 'Common.ps1')
    $script:Path = Get-ScriptPath 'm365-audits/Test-SharePointOversharing.ps1'

    function New-Permission {
        param($Scope, $GrantedTo, $Roles = @('read'), [switch] $Inherited)
        [pscustomobject]@{
            Roles              = $Roles
            Link               = if ($Scope) { [pscustomobject]@{ Scope = $Scope; Type = 'view' } } else { $null }
            GrantedToV2        = if ($GrantedTo) { [pscustomobject]@{ SiteGroup = [pscustomobject]@{ DisplayName = $GrantedTo } } } else { $null }
            InheritedFrom      = if ($Inherited) { [pscustomobject]@{ Id = 'parent' } } else { $null }
            ExpirationDateTime = $null
        }
    }

    function New-DriveItem {
        param($Id, $Name, [switch] $Folder)
        [pscustomobject]@{ Id = $Id; Name = $Name; WebUrl = "https://example/$Name"
            Folder = if ($Folder) { [pscustomobject]@{ ChildCount = 1 } } else { $null } }
    }

    function Set-SharePointMock {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-1' } }
        Mock Get-MgSite {
            [pscustomobject]@{ Id = 's1'; DisplayName = 'Finance'; WebUrl = 'https://contoso.sharepoint.com/sites/finance' }
            [pscustomobject]@{ Id = 's2'; DisplayName = 'OneDrive'; WebUrl = 'https://contoso-my.sharepoint.com/personal/someone' }
        }
        Mock Get-MgSiteDrive { [pscustomobject]@{ Id = 'd1'; Name = 'Documents'; WebUrl = 'https://example/Documents' } }

        # Documents/
        # ├── Projects/        shared with one user (not a finding)
        # │   └── plan.docx    organisation-wide link
        # └── salaries.xlsx    anonymous link + an inherited "Everyone" right
        Mock Get-MgDriveItemChild { (New-DriveItem 'f1' 'Projects' -Folder), (New-DriveItem 'i1' 'salaries.xlsx') } -ParameterFilter { $DriveItemId -eq 'root' }
        Mock Get-MgDriveItemChild { New-DriveItem 'i2' 'plan.docx' } -ParameterFilter { $DriveItemId -eq 'f1' }

        Mock Get-MgDriveItemPermission { New-Permission -GrantedTo 'Everyone except external users' -Inherited } -ParameterFilter { $DriveItemId -eq 'root' }
        Mock Get-MgDriveItemPermission { New-Permission -GrantedTo 'Alice' -Roles 'write' } -ParameterFilter { $DriveItemId -eq 'f1' }
        Mock Get-MgDriveItemPermission {
            New-Permission -Scope 'anonymous'
            New-Permission -GrantedTo 'Everyone except external users' -Inherited
        } -ParameterFilter { $DriveItemId -eq 'i1' }
        Mock Get-MgDriveItemPermission { New-Permission -Scope 'organization' } -ParameterFilter { $DriveItemId -eq 'i2' }
    }
}

Describe 'Test-SharePointOversharing' {
    BeforeAll {
        Set-SharePointMock
        $script:Result = @(& $script:Path)
    }

    It 'rates an anonymous link High' {
        $finding = $Result | Where-Object Resource -EQ '/salaries.xlsx'
        $finding.Category | Should -Be 'AnonymousLink'
        $finding.Severity | Should -Be 'High'
    }
    It 'rates an organisation-wide link Medium' {
        $finding = $Result | Where-Object Resource -EQ '/Projects/plan.docx'
        $finding.Category | Should -Be 'OrgWideLink'
        $finding.Severity | Should -Be 'Medium'
    }
    It 'reports a site-wide "Everyone" right once, at the library root' {
        $broad = @($Result | Where-Object Category -EQ 'BroadGroupGrant')
        $broad.Count | Should -Be 1
        $broad[0].Resource | Should -Be '/'
        $broad[0].Details | Should -Match 'inherited from the site'
    }
    It 'ignores a share with a named user' {
        $Result.Resource | Should -Not -Contain '/Projects'
    }
    It 'skips OneDrive personal sites' {
        Should -Invoke Get-MgSiteDrive -Times 0 -ParameterFilter { $SiteId -eq 's2' }
        $Result.Site | Should -Not -Contain 'OneDrive'
    }
}

Describe 'Test-SharePointOversharing -MaxDepth' {
    BeforeAll { Set-SharePointMock }

    It 'does not open folders below the requested depth' {
        $result = @(& $script:Path -MaxDepth 1)
        $result.Resource | Should -Not -Contain '/Projects/plan.docx'
        $result.Resource | Should -Contain '/salaries.xlsx'
    }
}

Describe 'Test-SharePointOversharing without a connection' {
    It 'stops with a clear message' {
        Mock Get-MgContext { $null }
        { & $script:Path } | Should -Throw '*Connect-MgGraph*'
    }
}
