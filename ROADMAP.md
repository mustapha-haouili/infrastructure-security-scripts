# Roadmap

This roadmap describes the planned direction for the infrastructure security
scripts toolkit. Versions are targets, not contractual commitments.

## v1.1.0 - Active Directory and Group Policy Improvements

- Expand Active Directory audit scripts for inactive users, stale computers,
  service accounts, SPN exposure, privileged groups, and privileged identities.
- Improve Group Policy health reporting with link inventory, stale policy
  indicators, version mismatch checks, and administrator action guidance.
- Add methodology, service model documentation, sample reports, and fictional
  sample outputs.
- Keep all public examples defensive, audit-first, and free of customer data.

## v1.2.0 - Report Standardization and JSON Schemas

- Standardize finding and report structures across Windows, AD, GPO, Linux,
  DevSecOps, and monitoring checks.
- Add validation schemas for findings, audit summaries, and remediation plans.
- Improve report generator support for multiple input formats.
- Add historical comparison helpers for repeated assessments.
- Expand SecureInfra AI normalizers beyond AD inactive user reports.
- Add a client-side collection bundle workflow that packages supported safe
  checks for reviewer-side analysis.
- Add beta standalone SecureInfra AI analyzer types for Windows host, server,
  workstation, and network exposure JSON reports.
- Add broad deterministic control-reference metadata to normalized reports
  without claiming compliance, certification, or audit attestation.
- Add deterministic monthly KPI summaries from normalized reports for baseline
  and month-over-month improvement review.
- Add audit-only backup readiness collection and normalization for metadata-only
  Windows and Linux backup evidence.

## v1.3.0 - Windows Security Health Check Enhancements

- Expand Windows host audit coverage for local security policy, event logging,
  remote access, Defender, services, and patch visibility.
- Improve remediation planning and rollback documentation.
- Add more sample host audit outputs and administrator review examples.
- Add optional HTML report generation.

## v1.4.0 - Linux Security Health Check Enhancements

- Expand Linux security audit coverage for SSH, services, packages, users,
  sudoers, kernel posture, and filesystem permissions.
- Improve JSON output consistency.
- Add Linux remediation planning examples.
- Add distro-specific notes where behavior differs.

## v1.5.0 - HTML / Markdown Report Generator

- Generate customer-readable Markdown and HTML reports from JSON audit results.
- Add report templates for executive summary, technical findings, and admin
  remediation planning.
- Add severity grouping, risk scoring, and optional comparison with a previous
  assessment.
- Keep PDF and branded portal workflows in the private commercial layer.

## Future Ideas

- Entra ID and Microsoft Graph read-only privileged identity checks.
- Evidence-based benchmark checks where controls can be validated safely without
  claiming certification or audit attestation.
- Wazuh/SIEM evidence mapping.
- Expanded backup readiness checks for additional platforms and centralized
  backup job-history evidence.
- Dashboard-ready JSON exports and monthly trend visualizations.
- Signed release artifacts.
- Documentation examples for lab environments.
- Private customer portal and branded report templates outside the public repo.
