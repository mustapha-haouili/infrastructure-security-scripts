# Public Repository Release Checklist

Use this checklist before publishing, tagging, creating a release archive, or
sharing the public repository.

## Repository boundary

- [ ] No customer data, real assessment evidence, or customer-like project
      folders are present.
- [ ] No local workstation paths, user profile paths, internal repository names,
      internal host names, or organization names are present unintentionally.
- [ ] No customer-specific reporting, exception, packaging, pricing, or delivery
      workflow is present.
- [ ] No non-public prompts, private templates, secrets, credentials, tokens,
      passwords, keys, or `.env` files are present.
- [ ] All public examples are fictional and synthetic.

## Leak scan

- [ ] Scan text files for Windows drive paths and user-specific home paths.
- [ ] Scan for generic customer-project, input-bundle, normalized-output, and
      deliverable folder markers.
- [ ] Scan scripts, tests, fixtures, comments, generated documentation, archives,
      and release assets—not Markdown files only.
- [ ] Keep exact organization-specific denylist terms in a private local hook or
      private release gate rather than publishing them in this repository.
- [ ] Review all scan hits manually; allow only intentional generic examples or
      safety-test markers.

## Defensive scope

- [ ] Collectors are read-only or clearly documented as dry-run/preview.
- [ ] No exploitation guidance, credential attacks, persistence, evasion, or
      destructive remediation was added.
- [ ] Network exposure claims are evidence-driven.
- [ ] Unknown evidence remains unknown.
- [ ] Any change-capable workflow requires explicit apply and approval controls.

## Analyzer and contracts

- [ ] `secureinfra_analyzer.py` runs against synthetic fixtures.
- [ ] Bundle helpers load supported formats safely.
- [ ] Finding identifiers remain stable and unique.
- [ ] Normalizers preserve evidence and source references.
- [ ] Risk rules are deterministic and conservative.
- [ ] `normalized-report.json` passes schema and strict-safety validation.
- [ ] Workflow state is not represented as technical severity in new or changed
      contracts.

## Tests and quality gates

- [ ] Python unit tests pass:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

- [ ] Fast quality gate passes during development:

```powershell
.\quality-gate.ps1 -Fast
```

- [ ] Full quality gate passes before release or public handoff:

```powershell
.\quality-gate.ps1
```

- [ ] `git diff --check` passes.
- [ ] Any new production script has an explicit caller or documented manual-only
      reason.

## Release archive

- [ ] Release scripts run on the target platform.
- [ ] Archive contents were listed and reviewed before upload.
- [ ] Generated release bundle excludes local reports, evidence, archives,
      spreadsheets, and customer-like artifacts.
- [ ] Release metadata and checksums are correct.
- [ ] Shell script executable permissions are preserved where required.
- [ ] Old release assets and source archives were reviewed for sensitive content.

## Git safety

- [ ] `git status --short` and `git diff --stat` were reviewed.
- [ ] Staged paths were reviewed explicitly.
- [ ] `git add .` was not used.
- [ ] No commit, tag, force-push, or release publication occurs without explicit
      approval.
