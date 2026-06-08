# Windows Security Health Check

The Windows security health check reviews local host posture, baseline controls,
security services, logging, event evidence, and remediation readiness across
Windows Server and workstation systems.

## Scope

Potential assessment areas:

- Local firewall and remote access exposure.
- SMB, guest access, WinRM, and legacy protocol settings.
- Microsoft Defender and security service status.
- PowerShell and Windows event logging configuration.
- Audit policy visibility.
- Baseline hardening readiness.
- Recent security and system event signals.

## Required Access

Full local evidence usually requires an elevated PowerShell session. Audit-only
scripts should not change host configuration. Hardening scripts should remain in
dry-run mode until `-Apply` is explicitly approved.

## Review Questions

- Which controls are already compliant?
- Which controls are managed by another platform or policy?
- Which settings could affect remote administration or business services?
- Are backups created for configuration changes?
- Is rollback guidance available for each applied control?

## Deliverables

- Windows host audit JSON.
- Baseline hardening plan.
- Event security report.
- Prioritized findings and remediation candidates.
- Administrator notes for exclusions, ownership, and next steps.

## Safety Notes

Windows hardening can affect remote access, authentication, service behavior,
and monitoring. Test changes in a lab or pilot group before production rollout.
Use targeted controls and exclude settings that are owned by other tools.
