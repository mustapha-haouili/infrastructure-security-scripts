# Script Documentation Standard

Every important script should be documented well enough that another system
administrator or security engineer can understand why it exists, how to run it,
what it changes, and what to do after reading the output.

Use this checklist when adding or updating script documentation.

## Required Documentation Fields

| Field | What to document |
|---|---|
| Purpose | What the script does in one or two sentences. |
| Problem solved | The operational or security problem the script helps review. |
| Requirements | Required shell, modules, commands, operating system, or tools. |
| Required permissions | Minimum expected permissions and when elevation is needed. |
| Parameters | Every supported argument, switch, default, and expected value. |
| Usage examples | Copy-ready examples for common audit and dry-run workflows. |
| Example output | Output files, important fields, and the best first file to read. |
| Safety notes | Whether the script is audit-only, dry-run, or applies changes. |
| Limitations | Known blind spots, false-positive areas, or dependency limits. |
| Recommended next steps | How an administrator should validate, remediate, or follow up. |

## Priority Script Families

### Active Directory Audit Scripts

Document the Active Directory module requirement, read-only directory access,
optional domain controller targeting, optional credentials, output directory,
and lifecycle safety guidance. Cleanup guidance must state that accounts and
computer objects should not be deleted until owner, dependency, approval,
quarantine, rollback, and monitoring checks are complete.

### Group Policy Audit Scripts

Document Group Policy module requirements, directory read access, domain
targeting, stale policy thresholds, link inventory behavior, and the difference
between a review finding and a confirmed remediation action. GPO cleanup should
always require backup, owner review, testing, and approval.

### Windows Hardening and Security Audit Scripts

Document elevated PowerShell requirements, execution policy guidance, output
paths, dry-run behavior, `-Apply` behavior, backup locations, exclusions, and
rollback expectations. Explain which controls can affect remote access,
authentication, logging, or endpoint security tooling.

### Linux Security Audit Scripts

Document when `sudo` improves evidence collection, when root is required for
hardening, supported output paths, dry-run behavior, backup behavior, and SSH
access safety. Linux hardening documentation should remind administrators to
test remote access changes before production rollout.

### Secret Scanning Scripts

Document scanned paths, default exclusions, output formats, allowlists,
non-zero exit behavior, and the fact that the scanner is a defensive hygiene
tool. The documentation should avoid publishing real secret examples.

### Monitoring Scripts

Document configuration shape, exit codes, thresholds, output files, timeout
behavior, and how monitoring systems can consume results. Example targets should
use fictional services or reserved documentation addresses.

## Existing Documentation Locations

- `docs/script-reference.md` contains full cross-platform script reference
  material with parameters, outputs, examples, and safety mode.
- `docs/script-index.md` contains a quick inventory of available scripts.
- Script-family README files under `scripts/` provide folder-level guidance.
- Individual scripts should keep built-in help or comment-based help aligned
  with the reference documentation.
