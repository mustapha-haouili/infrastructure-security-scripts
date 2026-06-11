# Changelog

All notable project changes are documented here.

This project follows semantic versioning after the initial `1.0.0` baseline.

## [Unreleased]

### SecureInfra AI

- Added `ad-shared` directory input support for Active Directory report bundles.
- Added Windows-safe JSON loading for UTF-8 BOM PowerShell output and a BOM-safe CSV loader.
- Added AD shared bundle discovery for known AD and GPO report JSON files.
- Added consolidated AD shared normalized report metadata for detected, loaded, and missing optional files.
- Added AD shared documentation and tests for bundle discovery, BOM loading, missing files, and Markdown output.
- Added SecureInfra AI normalizers for PasswordNeverExpires, service account, SPN exposure, and stale computer reports.
- Added direct analyzer types for `ad-password-never-expires`, `ad-service-accounts`, `ad-spn-exposure`, and `ad-stale-computers`.
- Added SecureInfra AI normalizers for privileged group changes, privileged identity protection findings, and GPO health findings.
- Added direct analyzer types for `ad-privileged-groups`, `ad-privileged-identity`, and `gpo-health`.
- Renamed the privileged identity audit threshold parameter to `-MaxCredentialAgeDays` to avoid PowerShell analyzer credential-parameter false positives.
- Added the `SecureInfra_AI/` layer for deterministic AI-ready infrastructure security analysis and reporting.
- Added SecureInfra AI finding, normalized report, and future AI report schemas.
- Added an Active Directory inactive users normalizer and deterministic risk engine.
- Added a CLI analyzer that reads AD inactive user JSON and generates normalized JSON plus Markdown reports.
- Added optional AI provider interface and local deterministic stub for future private AI integration.
- Added fictional SecureInfra AI sample input, sample output reports, architecture docs, roadmap, methodology, and prompt templates.
- Added tests for sample loading, normalization, risk rules, Markdown report generation, CLI output, and sample data safety.

## [1.1.0] - 2026-06-07

### Documentation And Reporting

- Added `docs/methodology.md` for the audit-first and safety-first assessment workflow.
- Added service model documentation for structured infrastructure security health checks.
- Added fictional sample assessment reports under `examples/sample-reports/`.
- Added fictional sample JSON outputs under `examples/sample-output/`.
- Added JSON schemas under `schemas/` for findings, AD reports, GPO reports, Windows host audits, Linux host audits, and remediation plans.
- Added `scripts/reporting/generate-markdown-report.py` to convert one or more JSON audit result files into a Markdown report.
- Added release notes for `v1.1.0` under `docs/releases/`.
- Added `ROADMAP.md` for future toolkit development.
- Added a script documentation standard for purpose, requirements, permissions, examples, safety notes, limitations, and next steps.

### Windows

- Added Windows expansion roadmap for AD, GPO, server, workstation, and shared helper categories.
- Added scaffold folders for future Windows AD, GPO, server, workstation, and shared helper scripts.
- Added the first 20 planned Windows security tasks with priority, status, target folder, and proposed script names.
- Added `scripts/windows/ad/Get-ADInactiveUserReport.ps1` for audit-only inactive Active Directory user reporting with JSON and CSV output.
- Improved `Get-ADInactiveUserReport.ps1` with `Critical`, `High`, `Medium`, `Low`, and `Hold` review priorities; Exchange HealthMailbox hold detection; account categories; lifecycle stage; deletion-readiness guidance; and explicit no-direct-delete safety fields.
- Added Markdown review output and dependency signals to `Get-ADInactiveUserReport.ps1`, including mail attributes, direct group counts, privileged group matches, and next review steps.
- Fixed `Get-ADInactiveUserReport.ps1` Markdown and CSV helper binding so empty or clean AD result sets write reports instead of failing on empty collections.
- Added `scripts/windows/ad/Get-ADStaleComputerReport.ps1` for audit-only stale Active Directory computer reporting with JSON, CSV, Markdown, priority, category, cleanup-readiness, and no-direct-delete safety guidance.
- Added `scripts/windows/ad/Watch-ADPrivilegedGroupChanges.ps1` for audit-only privileged AD group baseline comparison with added/removed member detection and Markdown review guidance.
- Added `scripts/windows/ad/Get-ADServiceAccountAudit.ps1` for audit-only service account, gMSA/sMSA, SPN, password age, delegation, owner, and privilege review.
- Added `scripts/windows/ad/Get-ADSPNExposureAudit.ps1` for defensive SPN-bearing account exposure reporting without Kerberos ticket requests or password testing.
- Added `scripts/windows/ad/Get-ADPasswordNeverExpiresReport.ps1` for PasswordNeverExpires exception, rotation, service-account, SPN, and privilege review.
- Added `scripts/windows/ad/Get-PrivilegedIdentityProtectionAudit.ps1` for on-prem privileged AD identity protection review, including smartcard, Protected Users, delegation, SPN, stale, password, and owner signals.
- Added `scripts/windows/gpo/Get-ADGPOHealthReport.ps1` for audit-only Group Policy inventory, link mapping, stale policy, filter, version mismatch, and policy health reporting.
- Improved `Get-ADGPOHealthReport.ps1` with an Admin Action Plan, per-finding action priority, admin action, verification guidance, localized default-principal detection, and more specific GPO extension names.
- Replaced root-level Windows compatibility wrappers with `scripts/windows/Start-WindowsSecurity.ps1`, a single menu launcher for AD/GPO, host, server, and workstation scripts with parameter prompts.
- Moved existing Windows implementations into organized `host/` and `server/` folders and made the root Windows entry point the menu launcher.

## [1.0.0] - 2026-06-01

Initial production baseline for the infrastructure security scripts repository.

### Windows

- Added `Invoke-WindowsSecurityAudit.ps1` for Windows security posture audit reports.
- Added structured Windows findings with severity, operational impact, suggested fixes, remediation eligibility, CIS/Wazuh reference fields, and exception guidance.
- Added `New-WindowsRemediationPlan.ps1` to convert audit findings into reviewable JSON, Markdown, and CSV remediation plans.
- Added `Start-WindowsSecurityRemediation.ps1` as the guided IT admin workflow for audit, plan creation, interactive approval, dry-run preview, and final apply confirmation.
- Added resume behavior for `Start-WindowsSecurityRemediation.ps1 -ApplyApproved` so saved decisions are reused instead of asking all questions again.
- Added `Set-WindowsBaselineHardening.ps1` hardening controls for firewall, password policy, SMBv1, SMB guest authentication, UAC, LLMNR, RDP, Guest account, Microsoft Defender, PowerShell logging, security services, WinRM, and audit policy.
- Added plan-aware hardening so only approved runnable remediation plan items are applied.
- Added default exclusion for high-impact controls that require explicit plan approval or `-OnlyControlId`.
- Added selective registry backups and `backup-manifest.json` in apply mode so backup files are tied to the controls that required them.
- Added hardening report fields for backup manifest path, backup summary, plan selection, control results, operational impact, recommendations, and rollback notes.
- Added `Export-WindowsEventSecurityReport.ps1` for readable Windows event investigation summaries, JSON summaries, and CSV evidence.
- Added `Clear-RDPUserProfileCache.ps1` for conservative RDP/Terminal Server profile cache audit and cleanup.

### Linux

- Added `linux-security-audit.sh` for Linux security posture reporting with text and JSON summary output.
- Added `linux-hardening-baseline.sh` for dry-run-first Linux baseline hardening with optional apply mode and backups.
- Added `collect-linux-inventory.sh` for Linux host inventory collection.

### DevSecOps

- Added `secret-scan.py` for dependency-free local and CI secret scanning.
- Added `docker-image-audit.sh` for Docker image metadata and optional runtime checks.
- Added `kubernetes-rbac-audit.sh` for Kubernetes RBAC and workload security review.

### Monitoring

- Added `service-health-check.py` for HTTP and TCP service health checks from JSON configuration.
- Added `disk-space-monitor.sh` for filesystem usage monitoring with warning, critical, exclusion, and JSON modes.

### Documentation And Safety

- Added Windows, Linux, DevSecOps, and monitoring README documentation.
- Added `docs/script-reference.md` with script purpose, safety mode, parameters, outputs, and examples.
- Added `docs/script-index.md`, `docs/usage.md`, and PowerShell execution policy guidance.
- Documented the project safety model: audit or dry-run first, explicit apply flags, reports under `reports/`, and backups under `backups/`.
- Added static checks and unit tests for shell, Python, PowerShell parsing, secret scanning, monitoring, Linux audit report behavior, and argument validation.
