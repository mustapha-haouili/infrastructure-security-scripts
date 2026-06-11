# SecureInfra AI Roadmap

This roadmap describes planned improvements for the AI-ready reporting layer.

## Phase 1 - Deterministic AD Inactive User Reporting

- Create common finding and normalized report schemas.
- Add Active Directory inactive user JSON normalization.
- Add deterministic risk rules.
- Generate Markdown executive, technical, and remediation reports.
- Add fictional sample input and output.
- Add tests for loading, normalization, risk rules, reports, and sample safety.
- Add AI provider interface and local deterministic stub.

## Phase 2 - Additional Normalizers

- Completed Active Directory privileged group reports.
- Completed Active Directory privileged identity protection reports.
- Completed Group Policy health reports.
- Windows host audit reports.
- Linux host audit reports.
- Secret scan reports.
- Monitoring health reports.

## Phase 1.5 - AD Shared Bundle Support

- Support directory input with `--type ad-shared`.
- Detect known AD report files in a shared report folder.
- Handle Windows PowerShell JSON files with UTF-8 BOM.
- Normalize `inactive-users.json` into detailed findings.
- Normalize `password-never-expires.json`, `service-accounts.json`,
  `spn-exposure.json`, and `stale-computers.json` into detailed findings.
- Normalize `privileged-groups.json`, `privileged-identity-protection.json`,
  and `gpo-health.json` into detailed findings.
- Report missing optional files without stopping analysis.

## Phase 3 - Report Standardization

- Stronger schema validation.
- Cross-source finding correlation.
- Historical comparison.
- Customer-ready report templates.
- Language support for English and German.

## Phase 4 - Private AI Integration

- Local model support where available.
- Private API provider support where approved.
- Prompt versioning and safety checks.
- Evidence-grounded executive language generation.
- Human review workflow before report finalization.

## Future Ideas

- Wazuh alert analysis after core normalizers are stable.
- HTML report output.
- PDF generation in a private commercial layer.
- Customer dashboard integration outside the public repository.
- Signed report artifacts.
