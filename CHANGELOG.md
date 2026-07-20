# Changelog

All notable project changes are documented here.

This project follows semantic versioning after the initial `1.0.0` baseline.

## [Unreleased]

## [1.3.0-beta.6] - 2026-07-20

### Windows runtime compatibility
- Added optional `compatibility-report.json` bundle metadata with a strict
  public schema and defensive validator. The client-bundle normalizer exposes
  runtime readiness and limited-scope counts without converting missing
  capabilities into compliant values.
- The Windows client launcher accepts the verified compatibility profile from
  the portable Enterprise entry point, records it in the archive, skips AD/GPO
  scopes that cannot run, and continues limited local scopes with explicit
  evidence-gap messages.
- Added CIM-to-WMI fallback for base operating-system metadata and tests for
  safe bundle ingestion, invalid compatibility contracts, and launcher
  integration.

### Collector safety
- Added `CollectorSafeMode` to the Windows and Linux unified launchers. In this
  mode, scripts that expose apply or deletion behavior are not invoked, even
  for preview-only output.
- Preserved the existing public dry-run workflow outside portable Enterprise
  collection while enabling the Enterprise distribution to enforce a stricter
  read-only runtime boundary.

### Contract
- Separated technical severity from workflow state across schemas, analyzers,
  reports, monthly KPI output, and the local dashboard. Normalized severity now
  accepts only `Critical`, `High`, `Medium`, `Low`, or `Info`; held items retain
  `status: Hold` and `remediation_priority: Hold`.
- Canonicalized legacy `Informational` source values to `Info` and added a
  negative validation test that rejects `Hold` as technical severity.

### Documentation
- Consolidated duplicate SecureInfra AI architecture, methodology, roadmap,
  Windows category, service-model, and release-note documents into the root
  architecture, methodology, roadmap, script references, and this changelog.
- Removed stale manually maintained Markdown report samples; machine-readable
  fictional fixtures and generated test outputs remain the source of truth.
- Renamed the monthly review document to `docs/monthly-kpi-methodology.md`.

### SecureInfra AI
- Added deterministic public-safe network port context mapping for normalized
  Windows network exposure findings, including common service names, exposure
  type, risk explanation, acceptable-use context, customer validation questions,
  and safe next steps for common listener ports such as RDP, SMB, HTTP, WinRM,
  database, directory, cache, and search services.
- Added explicit UDP service context for NetBIOS Name/Datagram, IKE, and IPsec
  NAT Traversal so Windows listeners on 137, 138, 500, and 4500 are not labeled
  as unknown custom services.

### Fixed
- Made Windows Public-network-profile finding identifiers stable and unique
  per interface/profile object. Multiple active Public profiles no longer
  produce duplicate `finding_id` values in standalone client-bundle analysis.
- Restricted compatibility evidence-gap notes and limited-scope counts to the
  public scopes actually requested by the collection. Complete capability
  inventory remains available without presenting unrequested Enterprise roles
  as report limitations.
- Preserved every deduplicated specific listener address in customer-facing
  network summaries instead of describing only the first interface address.
- Preserved `PasswordRequired` in normalized local-administrator evidence and
  made password-not-required summaries describe that control instead of only
  repeating group membership.
- Changed Windows service-installation summaries to Medium by default, include
  the collection window and first/last observation time, and raise them to High
  only when a bounded suspicious service-image-path heuristic is present.
- Fixed AD account classification precedence so built-in Administrator and
  privileged administrator accounts are treated as governance reviews instead
  of strict service accounts when SPN, AdminCount, privileged membership, or
  PasswordNeverExpires evidence is present.
- Standardized normalized finding evidence across analyzer outputs by adding
  `evidence.summary`, `evidence.details`, `evidence.confidence`, safe
  `evidence.key_fields`, and final-report sanitization for internal bundle
  paths before `normalized-report.json` is written.
- Restored `GPO` as an explicit `Start-SecureInfraClientCollection.ps1`
  scope so existing `-Scope GPO` commands remain valid. The broad `AD` scope
  continues to collect GPO health evidence for compatibility.
- Included Backup readiness in the broad `All` client collection scope so
  default bundles include backup/recovery evidence while keeping `-Scope Backup`
  available for targeted collection.

## [1.3.0-beta.3] - 2026-07-17

### Fixed
- Renamed the Network exposure process lookup key so it cannot overwrite the
  read-only PowerShell `$PID` automatic variable.
- Renamed the sensitive-port accumulator so PowerShell's `$Matches` automatic
  variable cannot replace it while parsing firewall port ranges.
- Materialized collection messages explicitly and removed an `$Args` shadow in
  the quality gate for predictable Windows PowerShell 5.1 behavior.

### Validation
- Added repository-wide static guards against assignments, loop variables, and
  typed declarations that shadow protected PowerShell automatic variables.
- Added guards against known PowerShell 7-only syntax in the Windows runtime.


## [1.3.0-beta.2] - 2026-07-01

### Fixed
- Restored and validated GPO collection scope compatibility.
- Improved normalized evidence summaries and details.
- Improved Active Directory privileged-account classification.
- Removed internal path leakage from report evidence.
- Improved reviewer-facing interpretation while preserving source evidence.

### Safety
- Kept collection and analysis defensive, audit-only, and local by default.
- Excluded customer data and non-public customer-specific workflows from the
  public release.

## [1.3.0-beta.1] - 2026-07-01

### SecureInfra AI
- Improved AD/account evidence classification so account-oriented findings are
  easier to review without adding customer-specific assumptions.
- Improved missing-value handling in defensive reporting paths so absent,
  unknown, and unavailable evidence can be represented more consistently.
- Added deterministic broad control-reference metadata for normalized reports,
  including per-finding references and summary counts under `metadata`.
- Added a public-safe static control mapping catalog and tests without changing
  normalized finding objects or claiming compliance, certification, or audit
  attestation.
- Added deterministic monthly KPI summaries with baseline and month-over-month
  trend output from existing normalized reports.
- Added beta backup readiness normalization for metadata-only Windows and Linux
  backup evidence, including conservative findings for stale evidence, missing
  expected backup paths, restore-test gaps, monitoring gaps, and unverified
  backup service presence.

### Backup Readiness
- Added audit-only Windows and Linux backup readiness collectors.
- Added backup readiness schema, fictional sample output, docs, and unit tests.
- Added explicit client collection `Backup` scope; it is not included in broad
  `All` collection and does not read backup contents or run restores.

### Release Integrity
- Added public release bundle scripts for PowerShell and shell environments.
- Added release manifest and SHA256 checksum documentation for local artifact
  verification.
- Documented optional operator-controlled signing outside the repository,
  without adding signing keys or paid-service requirements.

### Safety
- Reaffirmed the public/private boundary for the public defensive engine:
  defensive and audit-only, no customer data, and no private commercial
  workflows.

## [1.2.0-beta.1] - 2026-06-20

### SecureInfra AI
- Added ad-shared directory input support for Active Directory report bundles.
- Added Windows-safe JSON loading for UTF-8 BOM PowerShell output and a BOM-safe CSV loader.
- Added AD shared bundle discovery for known AD and GPO report JSON files.
- Added consolidated AD shared normalized report metadata for detected, loaded, and missing optional files.
- Added AD shared documentation and tests for bundle discovery, BOM loading, missing files, and Markdown output.
- Added SecureInfra AI normalizers for PasswordNeverExpires, service account, SPN exposure, and stale computer reports.
- Added direct analyzer types for ad-password-never-expires, ad-service-accounts, ad-spn-exposure, and ad-stale-computers.
- Added SecureInfra AI normalizers for privileged group changes, privileged identity protection findings, and GPO health findings.
- Added direct analyzer types for ad-privileged-groups, ad-privileged-identity, and gpo-health.
- Added dependency-free normalized report schema validation before SecureInfra AI writes JSON and Markdown outputs.
- Added a local static SecureInfra Dashboard for JSON report triage, severity metrics, filtering, evidence detail, and related-finding links.
- Added dashboard scope filtering and client-bundle collection coverage status for loaded, missing, failed, and not-collected scope files.
- Added deterministic cross-source correlation groups to normalized reports and dashboard related-finding views.
- Added historical comparison for repeated SecureInfra AI runs, including --previous-normalized-report, history_comparison, Markdown summaries, and dashboard trend display.
- Added client-bundle analyzer support for full SecureInfra client collection folders and zip archives, combining supported AD, host, server, and workstation evidence into one normalized report.
- Added multi-bundle analyzer support for fleet-style review of multiple client bundles.
- Added beta standalone SecureInfra AI analyzer types for windows-host-audit, windows-server-audit, windows-workstation-audit, and windows-network-exposure.
- Added strict dependency-free normalized output schemas and fictional sample inputs for the beta standalone Windows analyzer types.
- Added the SecureInfra_AI/ layer for deterministic AI-ready infrastructure security analysis and reporting.
- Added SecureInfra AI finding, normalized report, and future AI report schemas.
- Added an Active Directory inactive users normalizer and deterministic risk engine.
- Added a CLI analyzer that reads AD inactive user JSON and generates normalized JSON plus Markdown reports.
- Added optional AI provider interface and local deterministic stub for future private AI integration.
- Added fictional SecureInfra AI sample input, sample output reports, architecture docs, roadmap, methodology, and prompt templates.
- Added tests for sample loading, normalization, risk rules, Markdown report generation, CLI output, Windows standalone analyzers, schema validation, and sample data safety.

### Windows
- Added Start-SecureInfraClientCollection.ps1 to run supported safe client-side checks, create manifest and summary files, and package a send-back zip bundle.
- Added Windows local administrator inventory and RDP exposure audit scripts, exposed through server and workstation collection scopes.
- Added Windows server, workstation, and local network exposure evidence collection support.
- Renamed the privileged identity audit threshold parameter to -MaxCredentialAgeDays to avoid PowerShell analyzer credential-parameter false positives.

### Documentation
- Added documentation for AD shared bundle analysis.
- Added documentation for multi-bundle fleet analysis.
- Added SecureInfra AI architecture and roadmap updates.
- Updated README, ROADMAP, script index, and script reference documentation for the beta SecureInfra AI workflow.

### Safety
- Kept the public workflow defensive, audit-first, and local-by-default.
- Kept beta Windows standalone analyzers report-only.
- Kept fictional sample data separate from real customer or production data.

## [1.1.0] - 2026-06-07

### Documentation And Reporting

- Added `docs/methodology.md` for the audit-first and safety-first assessment workflow.
- Added service model documentation for structured infrastructure security health checks.
- Added fictional sample assessment outputs for documentation and testing.
- Added fictional sample JSON outputs under `examples/sample-output/`.
- Added JSON schemas under `schemas/` for findings, AD reports, GPO reports, Windows host audits, Linux host audits, and remediation plans.
- Added `scripts/reporting/generate-markdown-report.py` to convert one or more JSON audit result files into a Markdown report.
- Added release-history documentation for `v1.1.0`.
- Added `ROADMAP.md` for future toolkit development.
- Added consistent script documentation requirements for purpose, permissions, examples, safety notes, limitations, and next steps.

### Windows

- Added an initial Windows expansion plan for AD, GPO, server, workstation, and shared helper categories.
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
