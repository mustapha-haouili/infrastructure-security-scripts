# Active Directory Health Check

The Active Directory health check reviews identity hygiene, privileged access
exposure, stale objects, and account lifecycle risks. It is an audit-first
workflow for administrators and infrastructure security teams.

## Scope

Potential assessment areas:

- Inactive user accounts.
- Stale computer accounts.
- Privileged group membership changes.
- Service account and SPN exposure.
- Accounts with `PasswordNeverExpires`.
- Privileged identity protection gaps.
- Missing owner or lifecycle evidence.

## Required Access

The assessment should use the least privileged read access that can collect the
required evidence. Domain administrator access should not be required for normal
read-only reporting unless the environment has unusual delegation constraints.

## Review Questions

- Are privileged groups limited to expected administrators?
- Are service accounts documented and owned?
- Are stale enabled accounts still needed?
- Are disabled accounts ready for quarantine review or cleanup?
- Are SPN-bearing accounts using appropriate protections?
- Are exceptions documented and reviewed periodically?

## Deliverables

- Executive summary of identity hygiene.
- Finding list grouped by severity.
- Inactive and stale object review lists.
- Privileged group membership evidence.
- Service account and SPN exposure notes.
- Remediation plan with owner, priority, and verification steps.

## Safety Notes

Active Directory cleanup can break services, scheduled tasks, delegated access,
and legacy applications. The scripts should be used for review first. Disable,
move, rotate, or delete objects only after ownership, dependencies, approval,
rollback, and monitoring are confirmed.
