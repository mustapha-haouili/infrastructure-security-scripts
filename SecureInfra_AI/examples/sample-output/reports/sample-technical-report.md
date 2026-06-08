# Technical Findings

All data in this sample output is fictional.

## AD-INACTIVE-0001 - Enabled inactive privileged account detected

- Severity: Critical
- Affected object: `alex.admin`
- Evidence: Enabled account inactive for 184 days, member of `Domain Admins`.
- Risk factors: Privileged group membership, PasswordNeverExpires.
- Technical impact: Privileged access remains available for an inactive account.
- Recommendation: Validate owner, approval record, and need for privileged access.
- Safety notes: Not safe for auto-remediation. Requires owner review and change approval.

## AD-INACTIVE-0005 - System-managed account on hold

- Severity: Hold
- Affected object: `HealthMailbox-EXAMPLE-01`
- Evidence: Exchange HealthMailbox account category.
- Risk factors: System-managed account.
- Technical impact: Normal inactive account cleanup does not apply.
- Recommendation: Keep on hold unless Exchange administrators approve action.
- Safety notes: Must not be deleted as a normal inactive user.
