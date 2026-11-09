# ☁️ Azure audits

Read-only PowerShell audits of an Azure environment: who can touch what, what is reachable from the Internet, whether storage is configured safely. They need **Reader** only and change nothing.

| Script | Answers | Minimum role |
|---|---|---|
| [`Get-AzRoleAssignmentReport.ps1`](Get-AzRoleAssignmentReport.ps1) | Who has which rights, and which assignments are risky? (privileged roles, deleted principals, guests, users instead of groups, broad scopes) | Reader + read access to Entra ID |
| [`Test-AzNetworkExposure.ps1`](Test-AzNetworkExposure.ps1) | What is reachable from the Internet? (NSG rules open to any source, VMs with a public IP) | Reader |
| [`Test-AzStorageAccountSecurity.ps1`](Test-AzStorageAccountSecurity.ps1) | Are storage accounts configured safely? (HTTPS only, TLS 1.2, anonymous access, shared keys, network access) | Reader |

They work across subscriptions: every enabled subscription of the current tenant by default, or the ones passed with `-SubscriptionId`. The original Azure context is restored at the end. Each finding has a severity, so results can be sorted and exported.

```powershell
Install-Module Az.Accounts, Az.Resources, Az.Compute, Az.Network, Az.Storage -Scope CurrentUser
Connect-AzAccount                       # an account with Reader is enough

./azure-audits/Get-AzRoleAssignmentReport.ps1 -FindingsOnly -OutputPath ./rbac-findings.csv
./azure-audits/Test-AzNetworkExposure.ps1 | Sort-Object Severity | Format-Table Severity, Category, Resource, Details
./azure-audits/Test-AzStorageAccountSecurity.ps1 -FailedOnly | Format-Table StorageAccount, Check, Status, Value
```

## Reading the results

- **`OrphanedPrincipal`**: the principal was not found in Entra ID. Usually a deleted user, group or app, but also what you see when your account cannot read the directory.
- **Inherited assignments**: an assignment made on a management group appears once for every subscription below it.
- **Detached NSG**: a rule on an NSG attached to nothing has no effect today, but becomes live the day the NSG is attached.
- **Storage `Warn`**: the setting is not set explicitly, so Azure applies its default, which depends on the age of the account.
- **Exports contain tenant data** (names, principals, IPs): `*.csv` is ignored by git in this repo, keep it that way.

## Tests

Each audit has its test next to it (`Name.Tests.ps1`), to run after changing the script. The tests replace every Az cmdlet with a mock, so they run without an Azure account (the Az modules must still be installed: Pester can only mock commands that exist).

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser
Install-Module PSScriptAnalyzer -Scope CurrentUser

Invoke-Pester ./azure-audits -Output Detailed
Invoke-ScriptAnalyzer -Path ./azure-audits -Settings ./PSScriptAnalyzerSettings.psd1
```

17 test cases, for example: RDP allowed inside a port range is rated High, a public IP on a load balancer is not reported as a VM exposure, and a principal deleted from Entra ID is flagged.
