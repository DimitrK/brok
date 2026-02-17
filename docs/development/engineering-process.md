
# A simple “engineering contract” for PRs

Every PR that touches `execute`, `canonicalizer`, `ssrf-guard`, `forwarder`, `auth`, `policy-engine` must include:

* at least one regression test
* updated fixtures if canonicalization behavior changes
* explicit note on whether this impacts audit or approval semantics

# Enforce concrete “banned list” in code review

* Positional boolean params in exported functions
* `any` in data-plane core packages
* Returning secrets in any control-plane “read” response
* Auto-follow redirects in execute pipeline
* Logging full headers or bodies in execute path
* Broad allowlists (`*`, `.*`, unanchored regex) in templates
* “Catch and ignore” blocks

---



# Review gates and engineering process rules

## G1. Security-critical areas require a reviewer checklist

Any change to:

* execute pipeline
* canonicalizer
* ssrf guard
* forwarder
* auth/session binding
* templates/policy engine

Must include:

* new or updated regression tests
* update to fixtures if canonicalization changes
* explicit note on impact to audit/approval semantics

## G2. “No silent relaxations”

If you broaden allowlists, patterns, or header forwarding:

* require explicit approval + changelog entry

## G3. Performance budgets on hot paths

For `/execute`, define budgets:

* p95 latency target
* max DB queries
* max CPU time for canonicalization/matching

## G4. Coverage gates for security-critical packages

Any PR touching `auth`, `forwarder`, `ssrf-guard`, `canonicalizer`, or policy enforcement code must:

* run `test:coverage` for the touched package(s) and include the summary in the PR description
* add tests for every newly introduced rejection/decision branch
* avoid lowering package coverage without an explicit justification and follow-up task
* ensure changed files in auth/session/DPoP logic have meaningful branch coverage, not only happy-path assertions

## G5. Runtime contract validation at boundaries

For untrusted inputs (HTTP headers, request body/query, env/config payloads, external adapter responses):

* validate at the boundary with explicit schemas (prefer `zod`)
* use `z.infer` types from those schemas instead of duplicating request DTO types
* fail closed with stable reason codes when validation fails
* avoid passing raw `unknown` or unvalidated objects into core auth/policy logic

## G6. Shared DTO ownership in `@broker-interceptor/schemas`

For API/control-plane/data-plane DTOs:

* import DTO types and Zod parsers from `@broker-interceptor/schemas`
* do not locally re-define request/response DTOs in app/package code
* update source schemas/OpenAPI and regenerate schemas package when contracts change
* treat generated schema exports as the single source of truth for cross-package contracts


# Supply chain and dependency governance

## D1. Minimize dependencies in security-critical packages

**Why**: reduces attack surface.

**Do**

* allowlist dependencies for `auth`, `crypto`, `forwarder`, `ssrf-guard`

**Avoid**

* pulling random URL parsing libs when Node provides `URL`.

---

## D2. Lockfile and provenance discipline

**Why**: supply chain issues are common.

**Do**

* lockfile committed
* CI checks for dependency drift
* periodic upgrade cadence

**Avoid**

* “install latest” across packages.

---

# Architecture governance and documentation rules

## A1. ADRs for irreversible decisions

**Why**: keeps architecture consistent as team grows.

**Do**

* short ADRs for:

  * token model
  * approval semantics
  * canonicalization rules
  * redirect policy
  * key rotation format

**Avoid**

* tribal knowledge.

---

## A2. Public APIs are versioned; internal modules are not

**Why**: prevents ecosystem breakage.

**Do**

* `/v1/...` stable
* schemas versioned
* templates versioned and immutable

**Avoid**

* changing request/response shape without version bump.

---
