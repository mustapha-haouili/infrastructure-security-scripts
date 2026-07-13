# Security Assessment Methodology

This project follows an audit-first and safety-first methodology for authorized
infrastructure security assessment. The public toolkit collects technical
evidence, normalizes it deterministically, and produces reviewable outputs
without autonomous remediation.

## 1. Authorization and scope

Before collection, confirm authorization, in-scope systems, owners, business
criticality, maintenance constraints, and the people who approve changes.
Collection should be limited to the evidence required for the stated review.

## 2. Audit-only data collection

Initial execution should be read-only or dry-run. Collectors should avoid
passwords, secrets, tokens, private keys, unrelated business data, and broad file
content. Public examples and fixtures must use fictional values.

## 3. Evidence preservation

Source evidence must be treated as untrusted data and preserved without
inventing facts:

- missing booleans remain unknown rather than becoming `false`;
- missing numbers remain unknown rather than becoming `0`;
- listening on all interfaces is bind-scope evidence, not proof of reachability;
- Internet exposure requires explicit routing, firewall, segmentation, or
  allowed-source evidence;
- ports come from collected evidence, not from control identifiers.

## 4. Finding normalization

Script-specific output is converted into a common finding contract. Normalized
findings retain stable identifiers, source scripts, affected objects, evidence,
and technical severity. The same normalized contract supports single reports,
collection bundles, fleet analysis, correlations, and history comparison.

Normalization is deterministic. Language-generation systems do not assign
severity or create evidence.

## 5. Technical severity and workflow state

Technical severity uses exactly:

- `Critical`: urgent technical exposure or major control failure;
- `High`: important weakness requiring prioritized review;
- `Medium`: meaningful risk requiring planned remediation;
- `Low`: lower-risk hardening or lifecycle work;
- `Info`: evidence or governance context that does not represent a higher
  technical severity.

Workflow state is separate. For example, a system-managed account can have
`severity: Info` while `status: Hold` and `remediation_priority: Hold`. `Hold`
must never be used as technical severity.

Severity is a triage aid, not a final business decision. Reviewers must validate
ownership, dependencies, compensating controls, and operational impact.

## 6. Correlation and control mapping

Correlation may connect findings that reference the same account, host, group,
GPO, service, port, or other explicit object. Correlation must preserve all raw
finding identifiers and must not over-group unrelated evidence.

Control mappings are broad references only. They do not claim certification,
compliance, or audit attestation.

## 7. Human validation

Before remediation, confirm that the object still exists, is in scope, has a
known owner, and is not protected by an approved dependency or exception.
Privileged, built-in, SPN-bearing, service, and system-managed identities require
explicit owner and change review.

## 8. Remediation planning and dry-run

Plans should identify the affected object, proposed action, operational impact,
rollback approach, verification step, and approval owner. Prefer small,
reversible changes and dry-run output before apply mode.

## 9. Approved implementation

Changes must require explicit approval and an explicit `--apply`, `-Apply`, or
equivalent control. Stop if runtime output differs from the approved plan. Do
not apply high-impact changes to production without appropriate testing and a
rollback path.

## 10. Verification and follow-up

After an approved change, rerun the relevant audit and compare new evidence with
the original result. Record resolved, persistent, deferred, accepted, and held
items. History and monthly KPI summaries are trend aids and do not replace human
review.

## Public repository boundary

This repository contains public defensive collectors, validators, normalizers,
and public-safe technical outputs. Customer data, real assessment reports,
non-public prompts, customer-specific interpretation, branding, pricing, and
delivery workflows are outside the repository.
