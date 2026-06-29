# Monthly Improvement Summary

This fictional sample shows deterministic monthly KPI output from normalized
SecureInfra reports. It does not claim compliance, certification, audit
attestation, or official audit status.

## Executive KPI Snapshot

| KPI | Value |
|---|---:|
| Total findings | 8 |
| Critical | 1 |
| High | 2 |
| Medium | 3 |
| Low | 2 |
| Info | 0 |
| New findings | 2 |
| Persistent findings | 4 |
| Resolved findings | 2 |
| Risk reduction score | 6 |

Simple deterministic trend indicator: resolved Critical/High findings add
points; new Critical/High findings subtract points; persistent Critical/High
findings subtract smaller points. It is not a formal risk score.

## What Improved

- `AD-PGROUP-0001` (Critical, `alex.admin`): Privileged group membership addition was no longer present in the current fictional report.
- `HOST-WIN-WIN-FW-001` (High, `EXAMPLE-SRV01`): Windows Firewall profile exposure was no longer present in the current fictional report.

## What Got Worse

- `AD-SVC-0002` (High, `svc-example-api`): New service account owner evidence gap requires review.

## Persistent Risks

- `AD-PNE-0001` (High, `svc-fixed-password`): PasswordNeverExpires account requires exception review.
- `GPO-HEALTH-0001` (Medium, `EX Workstation Baseline`): AD and SYSVOL GPO versions differ.

## New Findings

- `AD-SVC-0002` (High, `svc-example-api`): New service account owner evidence gap requires review.
- `SERVER-RDP-CACHE-0001` (Low, `EXAMPLE-RDS01`): RDP profile cache cleanup candidates were found.

## Resolved Findings

- `AD-PGROUP-0001` (Critical, `alex.admin`): Privileged group membership addition requires review.
- `HOST-WIN-WIN-FW-001` (High, `EXAMPLE-SRV01`): Windows Firewall profile is disabled.

## Owner Decisions Needed

- `AD-PNE-0001` (High, `svc-fixed-password`): Validate owner, exception status, and rotation plan before any account change.
- `AD-SVC-0002` (High, `svc-example-api`): Confirm service owner and dependency before any change.

## Evidence Gaps / Coverage Limitations

- Missing optional evidence file: `ad-shared/gpo-health.json`
- Coverage gap for `EXAMPLE-SRV02` Server: `server/windows-server-security.json`

Limitations:

- Monthly KPI output is deterministic, local, and based only on supplied normalized reports.
- Risk reduction score is a simple trend indicator, not a formal risk score.
- Findings are matched by stable `finding_id` first, then by a conservative unique fallback fingerprint.

## Recommended Focus For Next Month

- Triage new Critical and High findings and confirm owner decisions.
- Review persistent Critical and High findings for blockers, ownership, and approved next steps.
- Close evidence gaps so next month has comparable coverage.
