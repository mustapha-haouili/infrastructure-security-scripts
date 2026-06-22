# AI Reporting Architecture

SecureInfra AI is designed as a deterministic reporting pipeline first, with an
optional future AI layer for language assistance.

## Phase 1 Pipeline

```text
JSON audit output
  -> JSON loader
  -> report-type normalizer
  -> deterministic risk engine
  -> normalized report
  -> cross-source correlation
  -> optional historical comparison
  -> schema validation
  -> Markdown report generator
```

AI is not part of the Phase 1 decision path.

## Components

### Loader

The loader reads JSON files and returns structured data. It does not modify
systems or collect new information.

### Normalizer

Normalizers convert script-specific output into common findings. Current
normalizers support Active Directory inactive users, password-never-expires
accounts, service accounts, SPN exposure, stale computers, privileged group
changes, privileged identity protection, and GPO health.

### Risk Engine

The risk engine applies deterministic rules. It is transparent and reviewable.
Examples include:

- Enabled inactive privileged accounts are Critical.
- Enabled inactive accounts with SPNs are High unless a higher rule applies.
- Exchange HealthMailbox and system-managed accounts are Hold.

### Schema Validator

The analyzer validates normalized reports against the local JSON schemas before
writing `normalized-report.json` or Markdown outputs. Validation is
dependency-free and fails closed when a normalizer emits missing required
fields, invalid enums, unexpected fields, or malformed date-time values.

### Correlation Builder

The correlation builder adds deterministic `correlations` to normalized reports.
It groups findings that reference the same account, group, GPO, SPN, SID, or
target path, and marks whether the relationship spans multiple source scripts.
These links are advisory review aids. They do not authorize remediation.

### Historical Comparison

When the analyzer receives `--previous-normalized-report`, it compares the
current and previous normalized reports by `finding_id`. The output adds
`history_comparison` with new, persistent, and resolved finding IDs plus summary
counts. The comparison is an advisory trend aid and does not change remediation
safety requirements.

### Report Generator

The report generator creates Markdown files:

- `executive-summary.md`
- `technical-findings.md`
- `remediation-plan.md`

### AI Provider Interface

The AI provider interface prepares future local or private AI support. Future AI
may summarize findings, generate executive wording, explain remediation in
business language, and translate approved report text.

AI must only use provided evidence. It must not invent facts, decide destructive
remediation, or replace human approval.

## Public And Private Boundary

The public repository should include the safe technical foundation: schemas,
normalizers, deterministic rules, docs, examples, and report generation.

Commercial or customer-specific logic should stay private. This includes
customer portal code, branded PDF workflows, pricing, contracts, customer
history, private dashboards, and sensitive remediation automation.
