# SecureInfra AI Methodology

SecureInfra AI follows a defensive, audit-first methodology. Phase 1 does not
use AI for risk decisions. It normalizes evidence, applies deterministic rules,
and generates Markdown reports that humans can review.

## 1. Discovery

Confirm authorization, scope, systems, owners, and expected report consumers
before processing assessment data. Discovery defines which JSON reports are in
scope and which teams must review the results.

## 2. Audit-Only Data Collection

Source JSON should come from audit-only scripts or dry-run workflows. The
project should not collect passwords, secrets, tokens, private keys, customer
records, or unrelated business data.

## 3. Finding Normalization

Script-specific JSON fields are normalized into a common finding format. This
makes reports easier to compare across Active Directory, Windows, Linux, Group
Policy, DevSecOps, and monitoring checks.

Normalization should preserve evidence and avoid inventing facts. If a source
field is missing, the normalized report should leave the value empty or note
that the information was not provided.

## 4. Risk Classification

Risk classification uses transparent deterministic rules. AI is not required
and does not assign severity in Phase 1.

Rules should explain why a finding is Critical, High, Medium, Low, Info, or
Hold. Human reviewers can adjust final prioritization after validating business
context and operational safety.

## 5. Report Generation

Markdown reports are generated for:

- Executive summary.
- Technical findings.
- Remediation planning.

Reports should separate security risk from operational safety. For example, an
inactive privileged account can be a high security risk while still being unsafe
for automatic remediation.

## 6. Human Review

Human review is mandatory before remediation. Administrators must validate
owner, business purpose, service dependency, change window, rollback, and
monitoring impact.

## 7. Remediation Planning

Remediation plans should group findings by urgency and safety constraints.
Privileged, SPN-bearing, built-in, and system-managed accounts should require
owner review and approved change control.

## 8. Approved Implementation

SecureInfra AI does not implement autonomous remediation. Any future execution
workflow must use explicit dry-run and apply safety controls, and production
changes must require approval.

## 9. Verification

After approved changes, run the original audit scripts again and compare the new
evidence with the normalized report. Verification should confirm both security
improvement and operational stability.

## 10. Follow-Up Reporting

Follow-up reporting should document resolved findings, accepted risks,
deferred items, holds, and next review dates.
