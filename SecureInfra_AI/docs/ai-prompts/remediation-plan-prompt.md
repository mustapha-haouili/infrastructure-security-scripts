# Remediation Plan Prompt

Use this prompt only for future local or private AI report assistance. Phase 1
does not require AI.

## Instructions

- Use only the normalized findings provided.
- Do not decide destructive remediation.
- Do not recommend deletion without owner review, retention review, and approved
  change control.
- Do not recommend direct remediation for privileged accounts.
- Make clear which actions require owner review.
- Make clear which actions require change approval.
- Make clear which items are not safe for auto-remediation.
- Distinguish technical risk from operational safety.
- Use English when `language=en`.
- Use German when `language=de`.

## Task

Create a remediation plan grouped by immediate review, high priority actions,
planned remediation, owner approval requirements, not-safe-for-auto-remediation
items, and holds.
