---
name: software-engineering-guardrails
description: Enforce repository software engineering standards for implementation, refactoring, and code review work. Use when writing or modifying code in this repository so work always follows docs/development/common-engineering-rules.md and docs/development/engineering-process.md, plus docs/development/frontend-engineering-rules.md for frontend tasks, docs/development/backend-engineering-rules.md for backend tasks, and docs/development/backend-express-nest-rules.md for Express/Nest tasks. Apply OWASP-aligned secure-by-default practices and require zod schemas for public and untrusted interfaces with z.infer type inference.
---

# Software Engineering Guardrails

Treat these rules as mandatory and unbreakable for all code changes.

## Load required standards first

Read these files before implementing or reviewing code:

- `docs/development/common-engineering-rules.md`
- `docs/development/engineering-process.md`

Read additional files by task type:

- Frontend task: `docs/development/frontend-engineering-rules.md`
- Frontend task with emphasis on UX: `docs/development/web-app-ui-ux-user-experience-rules.md`
- Backend task: `docs/development/backend-engineering-rules.md`
- Express or Nest backend task: `docs/development/backend-express-nest-rules.md`
- Postgress, Prisma or Redis: `docs/development/data-storage-postgres-redis-rules.md`

## Execute with strict order

1. Classify the task as frontend, backend, or mixed.
2. Load mandatory standards for that classification.
3. Extract applicable constraints and banned patterns before editing.
4. Implement changes that satisfy all applicable constraints.
5. Run `references/checklist.md` and complete every applicable check.
5.1. If you are working on UI run `references/ux-checklist.md` and complete every applicable check there as well.
6. Validate security properties and boundary validation before finishing.
7. Verify tests or checks for touched behavior and document any gaps.

## Enforce engineering rules

Always:

- Prefer clear, composable modules over god files.
- Use explicit typed inputs and avoid implicit shared state.
- Avoid boolean traps in public APIs; use named options/enums.
- Parse and validate untrusted input at boundaries before core logic.
- Use structured error handling with stable reason codes.
- Preserve review gates for security-critical flows.

Never:

- Add silent security relaxations or fallback behavior.
- Swallow errors (`catch` and ignore).
- Leak secrets or sensitive payloads in logs or read APIs.
- Introduce broad allowlists without explicit justification and approval notes.

## Enforce OWASP-aligned defaults

For every boundary and data flow, apply secure-by-default controls:

- Input validation and canonicalization.
- Authentication, authorization, and least privilege.
- Output/data handling that avoids sensitive exposure.
- Safe error handling and auditability.
- Dependency and supply-chain hygiene for critical paths.

When uncertain, fail closed and record why.

## Enforce zod-first validation and typing

Use `zod` as both runtime validator and type source, especially at public interfaces:

- Define `zod` schemas for request/query/header/body/env/external payload boundaries.
- Parse with `schema.parse` or `schema.safeParse` before domain logic.
- Use `z.infer<typeof Schema>` for TypeScript types.
- Avoid duplicate hand-written DTO types when they can come from schema inference.
- Reject unexpected fields on untrusted input where appropriate.

## Output requirements for the agent using this skill

When delivering code changes:

- State which standards were applied (common/process + task-specific files).
- Confirm `references/checklist.md` checks are complete (or list explicit exceptions).
- State how OWASP-style safeguards were addressed for touched boundaries.
- State where `zod` schemas were added or updated and where `z.infer` is used.
- Call out any unavoidable compliance gap and the follow-up required.
