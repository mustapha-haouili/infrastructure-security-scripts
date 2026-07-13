# Security Policy

## Scope

This repository contains defensive scripts for authorized system
administration, auditing, hardening previews, monitoring, bundle validation, and
normalized evidence analysis.

Use the scripts only on systems and environments where you have authorization.

## Reporting security issues

Report script vulnerabilities, unsafe collection behavior, archive-validation
bypasses, accidental secret collection, or repository information exposure
through a private security advisory or another private maintainer channel.

Include only the minimum information needed:

- affected script or file;
- impact;
- safe reproduction steps;
- suggested fix, when available.

Do not include real secrets, credentials, private keys, tokens, customer data,
raw customer evidence, or unnecessary personal information in a report.

## Repository information exposure

Treat an accidental commit of local workstation paths, internal repository
identifiers, customer-specific workflows, customer data, non-public prompts, or
release assets containing such information as a security and release-hygiene
issue.

Removing the text in a later commit does not remove it from Git history, tags,
release assets, forks, caches, or downloaded source archives. Maintainers should
sanitize the current tree, assess published artifacts, preserve a private backup,
and use a reviewed history-rewrite procedure when necessary.

## Operational safety

Before using scripts in production:

1. Read the script and its documentation.
2. Run in audit or dry-run mode.
3. Test in a lab or staging environment.
4. Confirm authorization, scope, rollback, and backup procedures.
5. Run with least privilege where possible.
6. Review generated evidence before sharing it.
