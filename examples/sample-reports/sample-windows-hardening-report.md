# Sample Windows Hardening Report

Company: Example GmbH  
Host: `EX-WIN-SRV01`  
Assessment date: 2026-06-07  
Mode: Dry run

All hosts and values in this sample report are fictional.

## Executive Summary

The Windows hardening dry run identified controls that can improve local host
security posture. No changes were applied in this sample. The most important
items relate to legacy SMB exposure, local firewall review, and PowerShell
logging configuration.

## Scope

- Windows Server baseline review.
- Firewall, SMB, RDP, WinRM, audit policy, Defender, and PowerShell logging
  controls.
- Dry-run only.

## Key Findings

| Control | Finding | Risk level | Priority |
|---|---|---|---|
| `WIN-HARDEN-SMB-001` | SMBv1 should be disabled if no legacy dependency exists. | High | P1 |
| `WIN-HARDEN-FW-001` | Firewall state requires review. | High | P1 |
| `WIN-HARDEN-PS-001` | PowerShell logging can be improved. | Medium | P2 |
| `WIN-HARDEN-RDP-001` | RDP exposure requires owner validation. | Medium | P2 |

## Risk Level

Overall risk level: High.

Legacy protocol exposure and weak host firewall posture can increase lateral
movement and attack surface risk.

## Operational Impact

Hardening changes can affect remote administration, legacy applications,
monitoring agents, scripts, and endpoint security tooling. Apply changes only
after testing and approval.

## Suggested Remediation

- Confirm whether SMBv1 is required by any legacy system.
- Review firewall ownership and central policy management.
- Enable PowerShell logging controls where compatible.
- Validate RDP access requirements and restrict where possible.
- Apply only approved controls during a maintenance window.

## Priority

Priority: P1 for SMB and firewall controls. P2 for logging and remote access
improvements.

## Notes for IT Administrators

Use dry-run output first. When applying changes, keep backup files and rollback
notes with the change ticket.
