# 🔊 security-beats

[![tests](https://github.com/runDMZ/security-beats/actions/workflows/tests.yml/badge.svg)](https://github.com/runDMZ/security-beats/actions/workflows/tests.yml)

> *Security is designed in from the start, not bolted on in production.*

The security side of my work: a hardened workstation, cloud audits, system hardening. Every part is tested on a real machine or against a real cloud API, with the problems met on the way and how they were solved.

```
security-beats/
├── qubes/          Qubes OS workstation: hardened template, split-SSH
├── azure-audits/   read-only Azure audits: RBAC, network exposure, storage
└── hardening/      server hardening as code (coming next)
```

Next to a script, a file with the same name ending in `.Tests.ps1` is its **automated test**: it runs the script against fake data and checks the answers. They run at every push on GitHub Actions.

## Tracks

| Part | What it is | Highlights |
|---|---|---|
| [**Qubes · hardened template**](qubes/hardened-template/) | A Debian template hardened once, inherited by every qube based on it. Script + write-up | ANSSI and CIS measures adapted to Qubes: what does not work like on a server (qrexec sessions, `pam_umask`, systemd limits), Debian 13 pitfalls |
| [**Qubes · split-SSH**](qubes/split-ssh/) | SSH private keys kept in an offline qube, used from a networked qube, every use approved in dom0 | qrexec service and dom0 policy, full troubleshooting log |
| [**Azure audits**](azure-audits/) | PowerShell audits that need Reader only | Risky role assignments, what is open to the Internet, storage account settings, findings rated by severity, Pester tests |
| [**Hardening**](hardening/) | Server hardening as code | Coming next |

How the Qubes parts fit together: [qubes/](qubes/).

## Principles

- **Least privilege**: audits are read-only and state the minimum role they need.
- **Explain the why**: each measure says which risk it addresses and which benchmark it comes from.
- **No real data**: no tenant name, ID, key or export in this repo.

Day-to-day admin scripts (inventory, costs, Microsoft 365) live in [sysadmin-mixtape](https://github.com/runDMZ/sysadmin-mixtape).
