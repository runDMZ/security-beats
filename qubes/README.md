# 🧪 Qubes OS lab

> *Compartmentalization, applied to my own workstation.*

How I run and harden my daily machine on **Qubes OS 4.3**: each part is a hands-on guide or a script, tested on the real machine, with the problems met on the way and how they were solved.

## Parts

| Part | What it is | Highlights |
|---|---|---|
| [**Hardened template**](hardened-template/) | A Debian template hardened once, inherited by every qube based on it. Script + write-up | ANSSI and CIS measures adapted to Qubes: what does not work like on a server (qrexec sessions, `pam_umask`, systemd limits), Debian 13 pitfalls |
| [**Split-SSH**](split-ssh/) | SSH private keys kept in an offline qube, used from a networked qube, every use approved in dom0 | qrexec service and dom0 policy, full troubleshooting log |

## How the parts fit together

```
debian-13-xfce          stock template
  └─ system qubes (sys-net, sys-firewall, sys-usb)

debian-13-hardened      hardened template
  ├─ everyday qubes and disposables
  ├─ vault-ssh template (+ socat)     ─ vault-ssh: SSH keys, no network
  └─ dev template (+ socat, git)      ─ dev: code, git, pushes approved in dom0
```

- Templates provide the system; qubes only keep their own `/home`, `/rw` and `/usr/local`. Hardening the template therefore hardens every qube based on it.
- Each specialised template is a clone of the hardened one, with only the tools its role needs.
- The SSH keys never leave `vault-ssh`, which has no network at all.

## Coming next

- Per-qube outbound firewall rules (`qvm-firewall`)
- dom0 confirmation instead of password-less root inside qubes
