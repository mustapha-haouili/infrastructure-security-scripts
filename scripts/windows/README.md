# Windows Scripts

Windows collection is organized by evidence domain. Start with the supported
launchers rather than calling individual scripts unless a script is explicitly
documented as manual-only.

## Supported launchers

```powershell
# Interactive defensive audit launcher
.\scripts\windows\Start-WindowsSecurity.ps1

# Create a structured evidence bundle for local analysis
.\scripts\windows\Start-SecureInfraClientCollection.ps1

# Collect the explicit Group Policy scope
.\scripts\windows\Start-SecureInfraClientCollection.ps1 -Scope GPO
```

Both launchers are audit-first. Any remediation-capable script remains dry-run
by default and requires explicit approval before apply mode.

## Categories

| Folder | Purpose |
|---|---|
| `ad/` | Active Directory identity, computer, SPN, and privileged-access evidence |
| `gpo/` | Group Policy inventory and health evidence |
| `host/` | Cross-host audit, event, local-admin, RDP, and hardening preview tools |
| `network/` | Listening service, firewall, and network-profile evidence |
| `server/` | Server inventory and review-only maintenance helpers |
| `workstation/` | Workstation posture and endpoint inventory |
| `backup/` | Backup-readiness evidence |
| `shared/` | Shared PowerShell helpers; not standalone entrypoints |

## Safe usage

1. Run audit or dry-run mode.
2. Review JSON, CSV, and Markdown outputs under the selected output directory.
3. Confirm owner, dependency, rollback, and maintenance-window requirements.
4. Use apply mode only for a reviewed and approved change.

A finding that is technically important can still be unsafe to remediate
automatically. System-managed and break-glass identities require governance
review, not deletion instructions.

## Reference

- [Script index](../../docs/script-index.md)
- [Detailed script reference](../../docs/script-reference.md)
- [Usage guide](../../docs/usage.md)
- [Roadmap](../../ROADMAP.md)
