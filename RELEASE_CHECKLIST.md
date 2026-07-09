# Public Repository Release Checklist

Use this checklist before publishing, tagging, or sharing the public SecureInfra defensive repository.

## Boundary checks

- [ ] No customer data is present.
- [ ] No customer projects are present.
- [ ] No approved exceptions for real customers are present.
- [ ] No private commercial report logic is present.
- [ ] No private prompts are present.
- [ ] No private paths are present.
- [ ] No secrets, credentials, tokens, or passwords are present.

## Defensive scope checks

- [ ] Collectors are read-only or clearly documented as dry-run/preview.
- [ ] No exploitation guidance is added.
- [ ] No destructive remediation is added.
- [ ] No automatic fix behavior is added.
- [ ] Network exposure claims are evidence-driven.
- [ ] Unknown evidence remains unknown.

## Analyzer checks

- [ ] `secureinfra_analyzer.py` runs against synthetic fixtures.
- [ ] Bundle helpers load supported input formats.
- [ ] Normalizers produce stable normalized findings.
- [ ] Risk rules are deterministic and conservative.
- [ ] Control mappings are broad and public-safe.
- [ ] `normalized-report.json` matches the public contract.

## Test command

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

## Quality gate

- [ ] Fast quality gate passes during development:

```powershell
.\quality-gate.ps1 -Fast
```

- [ ] Full quality gate passes before release or public handoff:

```powershell
.\quality-gate.ps1
```

- [ ] The quality gate generated a synthetic `normalized-report.json` and validated it with `--strict-safety`.
- [ ] Any new production script has an automatic caller or documented manual-only reason.

## Release bundle checks

- [ ] Release bundle scripts run on the target platform.
- [ ] Generated release bundle excludes private/customer data.
- [ ] Release metadata is correct.
- [ ] Executable permissions are correct for shell scripts where required.

## Git safety

- [ ] `git status --short` reviewed.
- [ ] `git diff --stat` reviewed.
- [ ] Generated local reports are not staged.
- [ ] Customer files are not staged.
- [ ] `git add .` was not used.
- [ ] No commit or push is performed unless explicitly requested.
