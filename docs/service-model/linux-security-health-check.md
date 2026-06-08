# Linux Security Health Check

The Linux security health check reviews host posture, inventory, hardening
readiness, SSH exposure, package and service visibility, and operational
security basics.

## Scope

Potential assessment areas:

- Host inventory and OS metadata.
- SSH and remote administration posture.
- Listening services.
- User and group hygiene.
- File permission checks.
- Package and update visibility.
- Baseline hardening readiness.
- Disk and service monitoring readiness.

## Required Access

Some audit evidence requires `sudo`, but initial checks can often run without
root to produce partial visibility. Hardening should stay in dry-run mode until
`--apply` is explicitly approved.

## Review Questions

- Which services are listening and why?
- Are privileged users and groups expected?
- Are SSH controls aligned with operational requirements?
- Are backups created before configuration changes?
- Are package and patch signals visible enough for follow-up?

## Deliverables

- Linux security audit report.
- JSON summary.
- Host inventory JSON.
- Hardening dry-run report.
- Prioritized remediation notes.

## Safety Notes

Linux hardening can affect SSH access, service startup, authentication, and
automation. Test in a lab, keep console access available when changing remote
access controls, and verify service health after implementation.
