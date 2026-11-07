#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Sites, Microsoft.Graph.Files

<#
.SYNOPSIS
    Finds files and folders shared too broadly in SharePoint Online, before a Copilot rollout.

.DESCRIPTION
    Read-only. Microsoft 365 Copilot respects permissions: it can find and summarise anything
    the user can already open. Every overly broad share becomes reachable with a simple prompt.

    Walks the document libraries of each site and returns one object per finding:
      - AnonymousLink     "Anyone with the link" sharing link                  High
      - BroadGroupGrant   access given to "Everyone" or "Everyone except
                          external users"                                      High
      - OrgWideLink       "People in <organisation>" sharing link              Medium

    At the root of each library, inherited permissions are kept: that is where rights given
    at site level show up. Below the root, only unique permissions are reported, so that one
    site-wide grant does not appear once per file.

    Complements sysadmin-mixtape/Export-SharePointInventory.ps1, which works at site level
    (owners, members, sharing setting): this script looks at sharing links item by item.

    Required: an account connected with Connect-MgGraph -Scopes Sites.Read.All, Files.Read.All
    In delegated mode, only what that account can open is scanned. For a full tenant audit,
    use app-only authentication with the same permissions as application permissions.

.PARAMETER SiteSearch
    Search string used to find sites. Default '*': every site the account can see.

.PARAMETER MaxDepth
    Folder depth scanned in each library (1 = items at the root only). Default 3.

.PARAMETER OutputPath
    Optional path of a CSV file to write the results to.

.EXAMPLE
    Connect-MgGraph -Scopes Sites.Read.All, Files.Read.All
    ./m365-audits/Test-SharePointOversharing.ps1 | Sort-Object Severity | Format-Table Severity, Category, Site, Resource

.EXAMPLE
    ./m365-audits/Test-SharePointOversharing.ps1 -SiteSearch 'Finance' -MaxDepth 6 -OutputPath ./oversharing.csv
#>
[CmdletBinding()]
param(
    [string] $SiteSearch = '*',
    [ValidateRange(1, 20)]
    [int] $MaxDepth = 3,
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Get-MgContext)) {
    throw 'Not connected to Microsoft Graph. Run Connect-MgGraph -Scopes Sites.Read.All, Files.Read.All first.'
}

# Built-in groups that mean "the whole organisation" (English and French tenants)
$BroadGroupPattern = '^(Everyone|Everyone except external users|Tout le monde|Tout le monde sauf les utilisateurs externes)$'

function Get-PropertyValue {
    # Reads a property that may be missing or null, whatever the object type
    param($InputObject, [string] $Name)
    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { $property.Value } else { $null }
}

function Get-GrantedName {
    # Display names of every identity a permission is given to
    param($Permission)
    $identities = @(Get-PropertyValue $Permission 'GrantedToV2') + @(Get-PropertyValue $Permission 'GrantedToIdentitiesV2')
    $names = foreach ($identity in $identities | Where-Object { $_ }) {
        foreach ($kind in 'User', 'Group', 'SiteUser', 'SiteGroup') {
            Get-PropertyValue (Get-PropertyValue $identity $kind) 'DisplayName'
        }
    }
    @($names | Where-Object { $_ } | Select-Object -Unique)
}

function Get-PermissionFinding {
    # Returns category and severity when a permission is too broad, nothing otherwise
    param($Permission, [string[]] $GrantedName)
    switch (Get-PropertyValue (Get-PropertyValue $Permission 'Link') 'Scope') {
        'anonymous' { return [pscustomobject]@{ Category = 'AnonymousLink'; Severity = 'High' } }
        'organization' { return [pscustomobject]@{ Category = 'OrgWideLink'; Severity = 'Medium' } }
    }
    if ($GrantedName | Where-Object { $_ -match $BroadGroupPattern }) {
        return [pscustomobject]@{ Category = 'BroadGroupGrant'; Severity = 'High' }
    }
}

function Test-IsInherited {
    param($Permission)
    [bool](Get-PropertyValue (Get-PropertyValue $Permission 'InheritedFrom') 'Id')
}

function Test-IsFolder {
    param($Item)
    $null -ne (Get-PropertyValue (Get-PropertyValue $Item 'Folder') 'ChildCount')
}

function Get-LibraryItem {
    # Every item of a library down to MaxDepth, with its path
    param([string] $DriveId, [string] $ItemId, [string] $ParentPath, [int] $Depth)
    try {
        $children = @(Get-MgDriveItemChild -DriveId $DriveId -DriveItemId $ItemId -All)
    } catch {
        Write-Warning "Cannot list '$ParentPath': $($_.Exception.Message)"
        return
    }
    foreach ($child in $children) {
        $path = "$ParentPath/$($child.Name)"
        [pscustomobject]@{ Item = $child; Path = $path }
        if ((Test-IsFolder $child) -and $Depth -lt $MaxDepth) {
            Get-LibraryItem -DriveId $DriveId -ItemId $child.Id -ParentPath $path -Depth ($Depth + 1)
        }
    }
}

function Get-ItemFinding {
    # Findings for one item; inherited permissions are skipped unless asked
    param($Site, $Drive, [string] $DriveItemId, [string] $Path, [string] $Url, [switch] $IncludeInherited)
    try {
        $permissions = @(Get-MgDriveItemPermission -DriveId $Drive.Id -DriveItemId $DriveItemId -All)
    } catch {
        Write-Warning "Cannot read permissions of '$($Drive.Name)$Path': $($_.Exception.Message)"
        return
    }
    foreach ($permission in $permissions) {
        $inherited = Test-IsInherited $permission
        if ($inherited -and -not $IncludeInherited) { continue }

        $names = Get-GrantedName $permission
        $finding = Get-PermissionFinding -Permission $permission -GrantedName $names
        if (-not $finding) { continue }

        $link = Get-PropertyValue $permission 'Link'
        $expiration = Get-PropertyValue $permission 'ExpirationDateTime'
        $details = @(
            "Roles: $(@(Get-PropertyValue $permission 'Roles') -join ', ')"
            if ($link) { "link type: $(Get-PropertyValue $link 'Type')" }
            if ($names) { "granted to: $($names -join ', ')" }
            if ($expiration) { "expires: $expiration" } elseif ($link) { 'no expiry' }
            if ($inherited) { 'inherited from the site' }
        ) -join '; '

        [pscustomobject]@{
            Site     = $Site.DisplayName
            Library  = $Drive.Name
            Category = $finding.Category
            Severity = $finding.Severity
            Resource = if ($Path) { $Path } else { '/' }
            Details  = $details
            Url      = $Url
            SiteUrl  = $Site.WebUrl
        }
    }
}

$results = [System.Collections.Generic.List[object]]::new()

$sites = @(Get-MgSite -Search $SiteSearch -All | Where-Object { $_.WebUrl -notmatch '-my\.sharepoint\.com' })
Write-Verbose "$($sites.Count) site(s) found (OneDrive excluded)"

foreach ($site in $sites) {
    Write-Verbose "Site $($site.DisplayName) ($($site.WebUrl))"
    try {
        $drives = @(Get-MgSiteDrive -SiteId $site.Id -All)
    } catch {
        Write-Warning "Cannot list the libraries of '$($site.WebUrl)': $($_.Exception.Message)"
        continue
    }

    foreach ($drive in $drives) {
        foreach ($finding in Get-ItemFinding -Site $site -Drive $drive -DriveItemId 'root' -Path '' -Url $drive.WebUrl -IncludeInherited) {
            $results.Add($finding)
        }
        foreach ($entry in Get-LibraryItem -DriveId $drive.Id -ItemId 'root' -ParentPath '' -Depth 1) {
            foreach ($finding in Get-ItemFinding -Site $site -Drive $drive -DriveItemId $entry.Item.Id -Path $entry.Path -Url $entry.Item.WebUrl) {
                $results.Add($finding)
            }
        }
    }
}

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding utf8
    Write-Verbose "Written to $OutputPath"
}
$results
