# Active Directory Health Check

The SecureInfra AI Active Directory health check layer starts with inactive user
analysis. It converts AD inactive user audit JSON into normalized findings and
Markdown reports.

## Phase 1 Scope

- Enabled inactive user accounts.
- Privileged inactive accounts.
- Stale service account candidates.
- SPN-bearing inactive accounts.
- Password-never-expires risk indicators.
- Built-in Administrator break-glass review.
- Exchange HealthMailbox and system-managed account holds.

## Safety Rules

- Account deletion must never be recommended without owner review.
- Privileged accounts require change approval before any modification.
- Built-in Administrator accounts must not be deleted and require break-glass
  policy review.
- SPN-bearing accounts may represent service dependencies and require
  application owner validation.
- System-managed accounts should be held unless product owners approve action.

## Expected Outputs

- Normalized finding records.
- Executive summary.
- Technical findings report.
- Remediation plan grouped by urgency and safety constraints.
