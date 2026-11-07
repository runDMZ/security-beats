# 🤖 Microsoft 365 audits · Copilot readiness

Read-only PowerShell audits of a Microsoft 365 tenant, starting with what matters before turning on **Microsoft 365 Copilot**.

## Why Copilot is an access problem

Copilot does not bypass permissions: it respects them, and that is the problem. It can find and summarise anything the user can already open. In most tenants, years of "share with everyone, it's quicker" have left sensitive files reachable by far more people than intended. Nobody stumbled on them before; with Copilot, a prompt like *"show me the salary grid"* can surface them in seconds.

So Copilot readiness is first an **access governance** project: find what is overshared, fix it with the content owners, then label and protect what is sensitive.

| Script | Answers | Minimum permissions |
|---|---|---|
| [`Test-SharePointOversharing.ps1`](Test-SharePointOversharing.ps1) | Which files and folders are shared too broadly? (anonymous links, organisation-wide links, "Everyone" rights) | Graph: `Sites.Read.All`, `Files.Read.All` |

Site-level rights (owners, members, external sharing setting of each site) are covered by [`Export-SharePointInventory.ps1`](https://github.com/runDMZ/sysadmin-mixtape/blob/main/powershell/m365/sharepoint/Export-SharePointInventory.ps1), and team visibility by [`Export-TeamsInventory.ps1`](https://github.com/runDMZ/sysadmin-mixtape/blob/main/powershell/m365/teams/Export-TeamsInventory.ps1). This audit goes one level down: sharing links, item by item.

```powershell
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Sites, Microsoft.Graph.Files -Scope CurrentUser
Connect-MgGraph -Scopes Sites.Read.All, Files.Read.All

./m365-audits/Test-SharePointOversharing.ps1 | Sort-Object Severity | Format-Table Severity, Category, Site, Resource
./m365-audits/Test-SharePointOversharing.ps1 -SiteSearch 'Finance' -MaxDepth 6 -OutputPath ./oversharing.csv
```

## Reading the results

| Category | Severity | Meaning |
|---|---|---|
| `AnonymousLink` | High | "Anyone with the link": no sign-in needed, the link can be forwarded anywhere |
| `BroadGroupGrant` | High | Right given to "Everyone" or "Everyone except external users": every account of the tenant, Copilot included |
| `OrgWideLink` | Medium | "People in your organisation" link: anyone who gets the link can open it, and Copilot can surface the file to them |

- **Delegated mode sees what your account can open, nothing more.** Global Administrator does not mean access to every site. For a full tenant audit, use app-only authentication (certificate, no client secret) with the same permissions as application permissions.
- **Library root**: rights inherited from the site are reported there, once. Below the root, only unique permissions are reported, so one site-wide grant does not flood the report.
- **Depth**: `-MaxDepth` (default 3) keeps the scan reasonable on large libraries. Raise it on sensitive sites.
- **OneDrive is excluded**: personal sites need their own audit.
- **Fix with the owners, not alone**: removing a link can break a process nobody told you about. The script changes nothing on purpose.
- **Exports contain tenant data** (site and file names): `*.csv` is ignored by git in this repo.

## Tests

The Pester tests replace every Graph cmdlet with a mock and build a small fake library, so they run without a tenant (the Graph modules must still be installed: Pester can only mock commands that exist).

```powershell
Invoke-Pester ./tests/Test-SharePointOversharing.Tests.ps1 -Output Detailed
```

7 test cases, for example: an anonymous link is rated High, a site-wide "Everyone" right is reported once and not on every file, a share with a named user is not a finding, and `-MaxDepth` really stops the scan.

## Next tracks

- Sensitivity labels and DLP: a checklist of what to set in Purview before Copilot, and why
- OneDrive oversharing
- Restricted Content Discovery: which sites to hide from Copilot while they are being cleaned up
