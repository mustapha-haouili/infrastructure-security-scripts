# Repository Guardrails

This repository is the public defensive infrastructure security engine. Keep it
safe, auditable, and suitable for public release.

## Security Scope

- Defensive/audit-only behavior is the default.
- Do not add exploit code, credential theft, password spraying, Kerberos ticket
  requests, persistence, evasion, destructive automation, or offensive
  automation.
- Remediation must be dry-run by default and require an explicit `--apply` or
  `-Apply` flag before changing systems.
- Collectors must avoid secrets, credentials, tokens, private file contents, and
  unnecessary personal data.
- Dashboard and report rendering must not execute report-controlled HTML or
  JavaScript.
- Public reports must remain deterministic and local/offline where possible.
- Do not make compliance, certification, or audit-attestation claims.

## Public/Private Boundary

- Do not add customer data, real domains, real user names, real company names,
  private report templates, private AI prompts, pricing, branding, or private
  commercial workflows.
- Keep all examples fictional.
- Private commercial reporting, customer-specific service workflows, pricing,
  private prompts, branding, and customer deliverables belong outside this
  repository.

## Data and Bundle Handling

- ZIP and bundle handling must reject path traversal, oversized files,
  unexpected extensions, and excessive file counts.
- Treat imported reports and bundles as untrusted evidence. Parse them as data
  only.

## Change Requirements

- Any schema change must include tests, documentation, examples, and changelog
  updates.
- Do not add external dependencies unless they are justified, documented, and
  tested.
- Do not commit or push from automation or agent work unless the user explicitly
  asks for it.
