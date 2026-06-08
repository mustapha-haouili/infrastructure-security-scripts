# Security Assessment Methodology

This project follows an audit-first and safety-first methodology for practical
infrastructure security assessment. The goal is to help administrators collect
useful technical evidence, classify risk, plan remediation, and verify outcomes
without introducing unnecessary operational risk.

The toolkit is intended for defensive use in environments that the operator owns
or is explicitly authorized to assess.

## 1. Discovery

Discovery defines what will be reviewed before any script is run. The expected
inputs are environment scope, system ownership, business criticality, maintenance
constraints, and administrator points of contact.

Discovery should answer:

- Which domains, hosts, clusters, or services are in scope?
- Which systems are production, staging, lab, or decommissioning candidates?
- Which accounts or groups are privileged?
- Which teams approve changes?
- Which time windows are safe for data collection and remediation?

## 2. Audit-Only Data Collection

Initial execution should collect only the required technical information needed
to understand posture and risk. Audit scripts should avoid broad data capture and
should not collect passwords, secrets, sensitive customer records, or unrelated
business data.

Preferred audit behavior:

- Use read-only queries where possible.
- Store outputs under `reports/`.
- Use fictional or sanitized values in examples and public documentation.
- Avoid credential material in command-line arguments, config files, and output.
- Review generated files before sharing them outside the operations team.

## 3. Risk Classification

Collected evidence should be classified by operational and security impact. A
finding is more useful when it explains why it matters and what could happen if
it remains unresolved.

Suggested severity levels:

- `Critical`: likely exposure of privileged access, major control failure, or
  urgent business risk.
- `High`: important weakness that should be prioritized soon.
- `Medium`: meaningful risk or hygiene issue that needs planned remediation.
- `Low`: low-risk cleanup or hardening improvement.
- `Informational`: useful evidence that does not require immediate action.

Severity should not be treated as a final decision by itself. Administrators
should validate scope, ownership, compensating controls, and business impact.

## 4. Finding Validation

Findings should be checked before remediation planning. Validation reduces false
positives and prevents unnecessary changes to systems that still have a valid
business purpose.

Validation steps should include:

- Confirm the affected object still exists and is in scope.
- Check whether the configuration is intentionally approved.
- Confirm owner, service dependency, and maintenance constraints.
- Compare the finding with recent change records when available.
- Record any exception, compensating control, or accepted risk.

## 5. Remediation Planning

Remediation should be planned before changes are applied. A remediation plan
should identify the affected object, recommended action, expected operational
impact, rollback approach, verification step, and approval owner.

Remediation planning should prefer:

- Clear owner assignment.
- Small, reversible changes.
- Maintenance windows for production systems.
- Backups or exports before configuration changes.
- Documented exceptions for items that cannot be changed safely.

## 6. Dry-Run Testing

Dry-run mode should be preferred before applying remediation. Dry-run output
helps administrators understand the exact controls or objects that would be
changed and gives stakeholders a chance to review impact.

Dry-run review should confirm:

- The intended systems are targeted.
- No unexpected controls are included.
- Backups will be created when needed.
- Rollback guidance is available.
- The change window and approval are still valid.

## 7. Approved Implementation

Changes should never be applied without explicit approval. Approval should be
specific to the systems, controls, and timing of the change.

Implementation guidance:

- Use `--apply`, `-Apply`, or equivalent switches only after review.
- Prefer targeted control selection for high-impact changes.
- Keep console logs and generated reports for change evidence.
- Stop if the script output differs from the approved plan.
- Avoid applying remediation to production without prior lab or staging testing.

## 8. Verification

After implementation, run the relevant audit again and compare the new result
with the original evidence. Verification should prove that the change achieved
the intended result and did not introduce unacceptable side effects.

Verification should include:

- Re-running the audit or health check.
- Confirming service availability where applicable.
- Reviewing security event logs or monitoring signals.
- Checking that backups and rollback records exist.
- Recording unresolved or deferred findings.

## 9. Follow-Up Reporting

Follow-up reporting should summarize what was reviewed, what was changed, what
remains open, and what needs management or administrator attention.

Recommended report sections:

- Executive summary.
- Scope.
- Findings by severity.
- Remediation status.
- Operational impact.
- Exceptions and accepted risks.
- Recommended next steps.

## Public Repository Boundary

The public repository should remain a defensive, audit-first technical toolkit.
It should not include customer data, real assessment reports, portal code,
pricing, contracts, internal business templates, sensitive remediation
automation, credentials, secrets, private IP inventories, or real domain
information.

Commercial or customer-specific workflows can be maintained separately in a
private layer that includes branded reports, dashboards, customer history,
templates, and client-specific remediation processes.
