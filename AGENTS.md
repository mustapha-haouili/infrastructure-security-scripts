# Repository Guardrails

This repository contains public defensive infrastructure security collectors,
bundle validation, normalized evidence generation, schema validation, and
public-safe analysis helpers. Keep it safe, auditable, portable, and suitable
for public release.

## Security scope

- Defensive and audit-only behavior is the default.
- Do not add exploit code, credential theft, password spraying, persistence,
  evasion, destructive automation, or offensive automation.
- Remediation must be dry-run by default and require an explicit `--apply` or
  `-Apply` flag before changing systems.
- Collectors must avoid secrets, credentials, tokens, private file contents,
  and unnecessary personal data.
- Treat imported bundles and reports as untrusted data. Do not execute content
  controlled by a report or bundle.
- Do not make compliance, certification, audit-attestation, or unsupported
  Internet-exposure claims.

## Public repository boundary

- Keep customer data, real domains, real user names, real company names,
  customer-specific report templates, pricing, branding, internal workflows,
  local workstation paths, and non-public prompts outside this repository.
- Keep all examples fictional and synthetic.
- This repository ends at public normalized technical output such as
  `normalized-report.json`.
- Customer-specific interpretation, presentation, exceptions, and delivery
  workflows are outside this repository.

## Evidence rules

- Unknown evidence remains unknown.
- Missing booleans and numbers must not be converted to `false` or `0`.
- Listening on all interfaces is bind-scope evidence, not proof of external or
  Internet reachability.
- Network ports must come from explicit evidence, not from control identifiers.
- Preserve source evidence, source scripts, stable finding identifiers, and
  original technical severity.

## Script integration rule

Any new production script must have an explicit caller or a documented
manual-only reason.

Before accepting a new script, verify at least one of the following:

- A tracked platform launcher invokes it.
- The public analyzer or another tracked module invokes it.
- It is a validator or quality tool documented in the testing and release docs.
- It is test-only and covered by automated tests.
- It is intentionally manual-only and its documentation explains when and why
  it should be run.

Do not add orphan production scripts.

## Change requirements

- Read relevant code and tests before changing behavior.
- Reuse existing functions instead of creating duplicate implementations.
- Every schema change must include tests, documentation, examples, and a
  changelog entry.
- Add or update negative tests for unsafe paths, malformed bundles, and
  unsupported values when relevant.
- Do not add external dependencies unless justified, documented, and tested.
- Do not commit generated reports, customer-like artifacts, local paths, or
  private handoff notes.
- Do not use `git add .`.
- Do not commit or push unless explicitly requested.
