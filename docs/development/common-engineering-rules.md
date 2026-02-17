Here are the engineering rules, conventions, and patterns I’d put in place for your codebase. Organized into **Universal**, **Backend**, and **Frontend**. Each rule includes **Do / Avoid** examples.

---

# Common anti-patterns to ban explicitly

## A1. God modules / “utils.ts dumping ground”

**Do**

* domain-specific modules with clear ownership

**Avoid**

* one giant helper file used everywhere

## A2. Tight coupling to upstream APIs

**Do**

* adapters (OpenAIAdapter, GoogleAdapter) that produce normalized internal shapes

**Avoid**

* upstream DTOs leaking into UI and policy engine

## A3. Silent fallbacks in security decisions

**Do**

* fail closed with explicit audit reason codes

**Avoid**

```ts
if (!template) return forwardAnyway();
```

## A4. Catch-and-ignore

**Do**

* handle errors explicitly and emit audit events

**Avoid**

```ts
try { ... } catch (e) {}
```

---

## U1. Prefer pure functions and explicit inputs

**Why**: Predictable behavior, easier testing, fewer side effects.

**Do**

```ts
const computeRiskTier = (score: number) => (score >= 0.8 ? "high" : "low");
```

**Avoid**

```ts
let globalScore = 0.9;
const computeRiskTier = () => (globalScore >= 0.8 ? "high" : "low");
```

---

## U2. Immutability by default

**Why**: Eliminates action-at-a-distance bugs and makes concurrency safer.

**Do**

```ts
const addHeader = (h: Record<string,string>, k: string, v: string) => ({ ...h, [k]: v });
```

**Avoid**

```ts
const addHeader = (h: any, k: string, v: string) => (h[k] = v, h);
```

---

## U3. No boolean traps - use named options or enums

**Why**: Call sites become unreadable and error-prone.

**Do**

```ts
type ApprovalMode = "none" | "required";
const createRule = (opts: { approvalMode: ApprovalMode; riskTier: "low"|"high" }) => opts;
createRule({ approvalMode: "required", riskTier: "high" });
```

**Avoid**

```ts
const createRule = (requiresApproval: boolean, highRisk: boolean) => ({ requiresApproval, highRisk });
createRule(true, false); // nobody knows what this means later
```

---

## U4. Avoid many positional arguments - prefer an options object

**Why**: Easier evolution, fewer call-site mistakes.

**Do**

```ts
const execute = (opts: {
  method: "GET"|"POST"; url: string; headers: Array<{name:string; value:string}>; body?: Uint8Array;
}) => opts;
```

**Avoid**

```ts
const execute = (method: any, url: string, headers: any, body: any, retries: number, timeout: number) => {};
```

---

## U5. “Parse early, validate once, operate on typed data”

**Why**: Prevents inconsistent validation and reduces injection classes.

**Do**

```ts
const parsePort = (n: unknown) => {
  if (typeof n !== "number" || !Number.isInteger(n) || n < 1 || n > 65535) throw new Error("bad port");
  return n;
};
```

**Avoid**

```ts
const port = Number(req.query.port); // implicitly accepts NaN/Infinity/0
```

---

## U6. Model errors explicitly; don’t throw raw strings

**Why**: consistent handling, safe user messaging, reliable audit.

**Do**

```ts
type AppError = { kind: "Validation"|"Auth"|"Policy"|"Upstream"; message: string; code: string };
const err = (kind: AppError["kind"], code: string, message: string): AppError => ({ kind, code, message });
```

**Avoid**

```ts
throw "not allowed"; // unstructured
```

---

## U7. “Return Result” in core logic, throw only at boundaries

**Why**: Keeps decision logic testable; boundaries handle HTTP status mapping.

**Do**

```ts
type Result<T> = { ok: true; value: T } | { ok: false; error: AppError };
```

**Avoid**

```ts
// deeply nested business logic throws and caller guesses what happened
```

---

## U8. Keep functions small and single-purpose

**Why**: Improves review quality and reduces coupling.

**Do**

```ts
const classify = (...) => ...
const decidePolicy = (...) => ...
const forward = (...) => ...
```

**Avoid**

```ts
const executeEverything = (...) => { /* 300 lines */ }
```

---

## U9. Prefer composition pipelines over branching pyramids

**Why**: Makes the “execute pipeline” auditable and deterministic.

**Do**

```ts
const pipe = <A>(a: A, ...fns: Array<(x:any)=>any>) => fns.reduce((x,f)=>f(x), a);
```

**Avoid**

```ts
if (...) { if (...) { if (...) { ... } } }
```

---

## U10. No hidden mutation in “utility” helpers

**Why**: Utility modules become silent bug sources.

**Do**

```ts
const sanitizeHeaders = (h: Header[]) => h.filter(...).map(...);
```

**Avoid**

```ts
const sanitizeHeaders = (h: any[]) => { h.splice(0,1); return h; }
```

---

## U11. Standardize naming and domain language

**Why**: shared mental model.

Conventions

* nouns for data: `ApprovalRequest`, `CanonicalRequestDescriptor`
* verbs for actions: `issueSession`, `evaluatePolicy`, `forwardUpstream`
* suffix functions for intent: `parseX`, `validateX`, `normalizeX`, `toX`, `fromX`

---

## U12. No “magic strings” for domain categories

**Why**: typos become security bugs.

**Do**

```ts
const RiskTier = ["low","medium","high"] as const;
type RiskTier = typeof RiskTier[number];
```

**Avoid**

```ts
if (tier === "hgh") ...
```

---

## U13. Logging is structured and redacted

**Why**: secrets leak most often through logs.

**Do**

```ts
log.info({ correlationId, workloadId, decision, actionGroup }, "execute decision");
```

**Avoid**

```ts
console.log("headers", headers); // may contain auth
```

---

## U14. Determinism over heuristics in enforcement paths

**Why**: policy and approval must be reproducible.

**Do**

* “template match -> canonicalize -> classify -> policy -> approve/deny -> forward”

**Avoid**

* dynamic behavior based on “likely” patterns or fuzzy matching.

---

## U15. Tests: pyramid and golden fixtures

**Why**: security code needs regression suites.

Minimum

* unit tests for canonicalization edge cases
* SSRF denial fixtures
* hop-by-hop header stripping fixtures
* approval dedupe behavior fixtures

---


## U16. Make side effects explicit with “effect boundaries”

**Why**: keeps functional core testable.

**Do**

```ts
// core
const decide = (input: DecisionInput): Result<Decision> => ...

// boundary
const handler = async (req) => {
  const decision = decide(parse(req));
  if (!decision.ok) return respondErr(decision.error);
  return respond(await forward(decision.value));
};
```

**Avoid**

```ts
const decide = async (req) => { await db.save(...); await fetch(...); }
```

---

## U17. Prefer data-first APIs and small algebraic types

**Why**: easier composition.

**Do**

```ts
type Decision = { kind: "allow" } | { kind: "deny"; reason: string };
```

**Avoid**

```ts
class Decision { constructor(public allow: boolean, public reason?: string) {} }
```

---

## U18. Eliminate “temporal coupling”

**Why**: “call A before B” bugs are hard to diagnose.

**Do**

```ts
const createSession = (workload: Workload): Session => ...
```

**Avoid**

```ts
let workloadId;
const setWorkload = (id) => (workloadId = id);
const createSession = () => use(workloadId); // depends on prior call
```

---

## U19. Use `unknown` at boundaries; forbid `any`

**Why**: boundary input is untrusted.

**Do**

```ts
const body: unknown = req.body;
const parsed = ExecuteRequestSchema.parse(body);
```

**Avoid**

```ts
const body: any = req.body; // bypasses all safety
```

---

## U20. “No null unless you mean it”

**Why**: `null` and `undefined` ambiguity creates bugs.

**Do**

* prefer `undefined` for “not provided”
* use explicit union types for “present but empty”

**Avoid**

* mixing null/undefined interchangeably

---

## U21. Prefer explicit units and types for time and bytes

**Why**: brokers depend on correct timeouts and size limits.

**Do**

```ts
type Millis = number & { __brand: "Millis" };
const ms = (n: number) => n as Millis;
```

**Avoid**

```ts
setTimeout(fn, 5); // seconds? ms?
```

---

## U22. No ad-hoc regex in security logic without tests

**Why**: regex mistakes become bypasses.

**Do**

* compile patterns at template publish time
* add fixtures for each new pattern

**Avoid**

* inline new regex in the execute path with no tests

---

## U23. Prefer “total functions” over partial functions

**Why**: avoid runtime throws for expected states.

**Do**

```ts
const toRiskTier = (n: number): RiskTier => n >= 0.8 ? "high" : n >= 0.5 ? "medium" : "low";
```

**Avoid**

```ts
const toRiskTier = (n: number) => { if (n > 0.8) return "high"; } // undefined cases
```

---

## U24. Use consistent module boundaries and import direction

**Why**: prevents cyclic dependency and “spaghetti”.

**Rules**

* `core` packages must not import `infra` packages
* `policy-engine` must not import `forwarder`
* `canonicalizer` must be dependency-free

**Avoid**

* `policy-engine` importing DB directly

---

## U25. Prefer “explicit default deny”

**Why**: security posture.

**Do**

```ts
if (!templateMatch) return deny("no_template_match");
```

**Avoid**

```ts
if (!templateMatch) return allow(); // convenience
```

---

# Cross-cutting patterns you should standardize

## CP1. “Functional core, imperative shell”

* Core packages return `Result<T>`
* Shell converts to HTTP responses and emits audit

## CP2. Options objects for anything public

* Avoid positional args in exported functions
* Use `type` + `satisfies` to keep call sites clean

## CP3. Domain-driven boundaries (lightweight)

* “policy,” “execution,” “audit,” “crypto,” “storage,” “connectors”
* No cross-imports that break layering

## CP4. “Reason codes” everywhere

* Every deny, throttle, approval-required event has a code
* UI renders codes and messages consistently

---

