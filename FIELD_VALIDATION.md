# Public Runtime Field Validation Policy

Automated tests and GitHub-hosted runners prove repository contracts; they do
not by themselves prove recurring support for every Windows role, operating
system version, locale, or privilege boundary. A platform support statement
requires an authorized field-validation case with sanitized result metadata.

## Required Windows dimensions

The maintained external field matrix must include, at minimum:

- domain controller, member server, and workstation roles;
- the inbox Windows PowerShell 5.1 path and the PowerShell 7 to Windows
  PowerShell handoff path;
- `en-US` and `de-DE` hosts, so built-in groups and other localized resources
  are not accepted through English-name assumptions;
- elevated and limited-permission collection, preserving unavailable evidence
  as Unknown or a documented limitation;
- the supported packaged launcher, strict bundle validation, manifest/hash
  validation, and normalized schema validation.

Each case begins with preflight, runs only the read-only collector path, and is
reviewed for unexpected mutation or sensitive-data capture. Remediation and
active scanning are outside this protocol.

## Evidence boundary

Do not commit raw field bundles, hostnames, domains, IP addresses, account
names, customer identifiers, or absolute lab paths. Source control may retain
only a fictional case identifier, target dimensions, result state, repository
commit SHAs, artifact hashes, and a sanitized outcome summary.

Allowed result states are `passed`, `passed-with-limitations`, `failed`, and
`blocked`. A planned or scheduled case is a test target, not evidence of
platform support.

Before a release support statement changes, the corresponding external matrix
case must be updated and its metadata validator must pass.
