# Roadmap

This roadmap describes the planned direction of the public defensive toolkit.
Items are priorities, not contractual commitments.

## 1. Public repository hygiene and release safety

- Complete current-tree sanitization and remove internal handoff material,
  local workstation paths, customer-specific workflow details, and stale
  generated review artifacts.
- Keep leak checks generic and public-safe while maintaining exact
  organization-specific denylist checks outside the repository.
- Validate release archives, tags, documentation, examples, and generated
  assets before publication.
- Prepare a reviewed history-rewrite plan for repositories that were already
  published with sensitive content.

## 2. Windows and Linux end-to-end validation

- Run mixed Windows and Linux bundle analysis using synthetic fixtures.
- Confirm stable finding identifiers, evidence preservation, schema validation,
  network wording, and metadata-only handling of remediation previews.
- Complete remaining safe Windows evidence gaps, including pending-reboot and
  certificate-expiry visibility, only after the current collectors are fully
  tested.
- Design Entra/Microsoft Graph identity checks separately with explicit
  permissions and authentication requirements; do not infer cloud controls from
  on-premises evidence.
- Keep generated examples synchronized with tested fixtures and schemas.

## 3. Normalized contract consistency

- Separate technical severity from workflow and review state consistently.
- Keep unknown evidence explicit instead of converting it to false or zero.
- Strengthen bundle, schema, correlation, and leak validation.
- Add missing standalone normalizers only where source evidence and schemas are
  stable, including monitoring and secret-scan outputs.
- Keep JSON Schemas as the machine-readable source of truth and reduce duplicated
  documentation.

## 4. Reporting and local review

- Keep Markdown reports and the static dashboard local/offline and derived from
  normalized evidence.
- Improve historical comparison, monthly KPI summaries, and saved synthetic
  demonstrations.
- Add language support only after deterministic output and validation are
  stable. Language assistance must remain evidence-grounded and human-reviewed.

## 5. Container coverage

Begin Docker work only after repository hygiene and the Windows/Linux completion
gate are finished.

- Define a read-only collection bundle contract.
- Add safe local inventory and configuration evidence.
- Add deterministic normalizers, schemas, synthetic fixtures, and tests.
- Avoid secret collection and avoid executing container-controlled content.

## 6. Kubernetes coverage

After Docker support is stable:

- define authorized, read-only collection scopes;
- collect configuration and RBAC evidence conservatively;
- add normalization and schema coverage;
- avoid active exploitation, credential collection, and unsupported reachability
  claims.

## 7. Cloud identity and resource coverage

Later phases may add read-only evidence for cloud identity and selected cloud
resources where permissions, data minimization, and evidence contracts are
clear.

## Ongoing priorities

- Signed or verifiable release artifacts.
- Evidence-based benchmark mappings without certification claims.
- Offline dashboard and normalized JSON improvements.
- Clear lab documentation and synthetic examples.
