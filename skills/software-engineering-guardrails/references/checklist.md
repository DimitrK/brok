# Engineering Compliance Checklist

Use this checklist as a hard gate before finalizing any code change.

## 1) Scope and standards

- [ ] Task classification is explicit: frontend, backend, Express/Nest backend, or mixed.
- [ ] `docs/development/common-engineering-rules.md` was applied.
- [ ] `docs/development/engineering-process.md` was applied.
- [ ] If frontend was touched: `docs/development/frontend-engineering-rules.md` was applied.
- [ ] If backend was touched: `docs/development/backend-engineering-rules.md` was applied.
- [ ] If Express/Nest code was touched: `docs/development/backend-express-nest-rules.md` was applied.

## 2) Architecture and maintainability

- [ ] No god modules/components introduced.
- [ ] Public APIs avoid boolean traps and ambiguous positional arguments.
- [ ] Core logic uses explicit typed inputs and deterministic behavior.
- [ ] No `catch`-and-ignore blocks.
- [ ] Error handling is structured and maps to stable reason codes where applicable.

## 3) Security (OWASP-aligned)

- [ ] Untrusted input boundaries are validated and canonicalized.
- [ ] Authn/Authz and least-privilege constraints are preserved or improved.
- [ ] Sensitive values are not exposed in logs/responses.
- [ ] Security-relevant behavior fails closed on invalid/unexpected input.
- [ ] No silent relaxation of policy, allowlists, or forwarding rules.

## 4) zod validation and typing

- [ ] Public/untrusted interfaces have `zod` schemas.
- [ ] Validation occurs at boundaries before business logic.
- [ ] Types are inferred from schemas using `z.infer<typeof Schema>`.
- [ ] Duplicate hand-written DTO types were avoided when schema inference was possible.
- [ ] Unknown/unexpected fields are rejected where required by interface risk.

## 5) Frontend checks (if applicable)

- [ ] API responses are treated as untrusted and validated before use.
- [ ] Accessibility and keyboard-friendly semantics are preserved.
- [ ] Network logic remains centralized/typed (no ad hoc scattered fetch logic).
- [ ] Unsafe HTML rendering is not introduced.

## 6) Backend checks (if applicable)

- [ ] Trust boundaries are preserved (control-plane vs data-plane concerns).
- [ ] Forwarding/proxy-like behavior remains constrained by explicit policy.
- [ ] Timeouts, limits, and rejection paths remain explicit.
- [ ] Audit semantics for sensitive decisions/rejections remain intact.

## 7) Verification and delivery

- [ ] Tests/checks were run for touched behavior, or a concrete gap is documented.
- [ ] Any compliance exception is explicitly documented with follow-up.
- [ ] Final report states: applied standards, OWASP safeguards, and zod changes.
