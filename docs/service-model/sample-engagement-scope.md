# Sample Engagement Scope

This sample scope is fictional and can be adapted for internal reviews or
authorized customer work. It is written for a defensive infrastructure security
health check, not a penetration test.

## Engagement Name

Example GmbH Infrastructure Security Health Check

## Objective

Review infrastructure security posture across selected Windows, Active
Directory, Group Policy, Linux, DevSecOps, and monitoring areas. Produce
prioritized findings, operational impact notes, and remediation guidance.

## In Scope

- Domain: `example.local`.
- Active Directory user, computer, service account, and privileged group review.
- Group Policy health and link review.
- Windows host audit and hardening dry-run on selected servers.
- Linux host audit and inventory on selected systems.
- Secret scan of selected internal repositories.
- Service and disk monitoring readiness checks.

## Out of Scope

- Exploit development.
- Password attacks.
- Social engineering.
- Internet-wide scanning.
- Customer data extraction.
- Unauthorized changes.
- Production remediation without explicit approval.

## Assumptions

- All work is authorized by the system owner.
- Assessment accounts have read-only access unless a change window is approved.
- Sensitive data will not be collected intentionally.
- Reports will be reviewed before wider distribution.
- Fictional sample data will be used in public examples.

## Deliverables

- Executive summary.
- Technical findings report.
- Evidence files in JSON, CSV, or Markdown format.
- Remediation plan.
- Follow-up recommendations for administrators.

## Safety Controls

- Audit-first execution.
- Dry-run before remediation.
- Explicit approval before `--apply` or `-Apply`.
- Backups where scripts change configuration.
- Verification after implementation.
