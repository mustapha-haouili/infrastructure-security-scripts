# Sample Linux Security Report

Company: Example GmbH  
Host: `ex-linux-app01`  
Assessment date: 2026-06-07

All hosts, users, and values in this sample report are fictional.

## Executive Summary

The Linux security review found several baseline hardening opportunities. The
highest-priority items relate to SSH configuration, patch visibility, and
service exposure. No changes were applied in this sample report.

## Scope

- Linux host inventory.
- SSH posture review.
- User and group hygiene.
- Listening service visibility.
- Package and update visibility.
- File permission spot checks.

## Key Findings

| Finding | Evidence | Risk level | Priority |
|---|---|---|---|
| SSH password authentication needs review | `PasswordAuthentication yes` | High | P1 |
| Patch status visibility is incomplete | Package metadata older than 14 days | Medium | P2 |
| Unexpected listening service | TCP `0.0.0.0:8080` | Medium | P2 |
| Local admin group needs owner validation | 4 members in `sudo` group | Medium | P2 |

## Risk Level

Overall risk level: High.

The rating is driven by remote access posture and incomplete patch visibility.

## Operational Impact

SSH changes can lock out administrators if key-based access and console access
are not confirmed first. Service changes can affect application availability.

## Suggested Remediation

- Confirm administrator key-based SSH access.
- Test SSH changes in a maintenance window.
- Refresh package metadata and document patch status.
- Validate listening services with application owners.
- Review `sudo` group membership and document approved administrators.

## Priority

Priority: P1 for SSH access posture. P2 for patch visibility, service exposure,
and privileged local group review.

## Notes for IT Administrators

Keep an active console or out-of-band access path available before changing SSH
settings. Re-run the audit after remediation to confirm the new state.
