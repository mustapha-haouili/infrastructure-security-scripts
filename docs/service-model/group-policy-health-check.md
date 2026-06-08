# Group Policy Health Check

The Group Policy health check reviews GPO inventory, links, stale policies,
version mismatches, filtering, legacy references, and administrative cleanup
opportunities.

## Scope

Potential assessment areas:

- Unlinked, disabled, empty, stale, or duplicate-name GPOs.
- Direct link volume on OUs, domains, and sites.
- Enforced or disabled links.
- Security filtering and WMI filtering.
- AD and SYSVOL version mismatches.
- Possible legacy policy references.
- Policy overlap indicators.

## Required Access

The assessment uses read-only Group Policy and Active Directory evidence. Some
inventory details require the Group Policy module and appropriate directory read
access.

## Review Questions

- Which policies are still business-required?
- Which policies have no clear owner?
- Which stale policies can be retired after backup and approval?
- Which legacy settings should be modernized?
- Are there link patterns that make troubleshooting difficult?

## Deliverables

- GPO inventory.
- Link inventory.
- Findings CSV and JSON.
- Administrator-readable Markdown review report.
- Cleanup and modernization recommendations.

## Safety Notes

GPO cleanup should be handled carefully. Back up GPOs, confirm owners, test
changes on pilot OUs, and stage removal before deleting policies. A stale GPO is
not automatically safe to remove.
