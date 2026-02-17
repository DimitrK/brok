
# Backend rules (Node/Nest broker + interceptor services)

## B1. Separate control plane from data plane in code and deployment

**Why**: different auth, risk profiles, and scaling.

**Do**

* `broker-api` (mTLS + session + execute + manifest)
* `broker-admin-api` (OIDC/bearer admin)

**Avoid**

* mixing admin endpoints and `/execute` in one router with “if admin then…”

---

## B2. mTLS authenticates workload; session token authorizes actions

**Why**: identity vs scoped authorization.

**Do**

* Require mTLS for data plane.
* Issue short TTL tokens bound to workload identity.

**Avoid**

* long-lived static API keys for workloads.

---

## B2.1 DPoP runs in auth middleware, not business handlers

**Why**: DPoP is an authentication and replay-defense control and must fail closed early.

**Do**

* Verify DPoP at session issuance to bind `dpop_jkt` to session when provided.
* Verify DPoP on protected requests immediately after session validation.
* Enforce middleware order: `requireMtls` -> `requireSession` -> `requireDpopIfBound` -> policy/forwarder.
* Enforce `ath` when proof is bound to presented bearer session token.
* Use a shared `jti` replay store across instances.

**Avoid**

* calling DPoP verification inside execute business logic after policy checks
* per-handler ad hoc DPoP checks with inconsistent error behavior
* local in-memory replay store in multi-instance deployment

---

## B3. `/execute` must never be a general proxy

**Why**: becomes an SSRF cannon.

**Do**

* Require a template match (host allowlist + path group + method)
* Deny redirects in MVP
* DNS resolve and deny internal ranges
* Strict scheme/port rules

**Avoid**

```ts
// "just forward it"
fetch(userProvidedUrl, { headers: userProvidedHeaders });
```

---

## B4. Canonicalize before you match approvals or policies

**Why**: prevents bypass via encoding tricks.

**Do**

* Normalize host, path, query keys ordering
* Reject fragments and userinfo
* Reject weird schemes

**Avoid**

* approval keyed on raw strings

---

## B5. Enforce hop-by-hop header stripping and safe framing

**Why**: prevents request smuggling-style failures and proxy weirdness.

**Do**

* Remove `Connection` and headers it nominates
* Reject conflicting `Content-Length` / `Transfer-Encoding`
* Maintain per-template header allowlist

**Avoid**

```ts
// forward all headers
upstreamHeaders = incomingHeaders;
```

---

## B6. Timeouts and budgets everywhere

**Why**: broker is a choke point.

**Do**

* set connect + request + total timeouts
* cap response size per action group
* cap request body size at ingress

**Avoid**

* default fetch/axios timeouts (often “no timeout”)

---

## B7. Idempotency for approved “execute” classes where possible

**Why**: retries happen, you want controlled behavior.

**Do**

* allow optional `idempotency_key`
* store outcome for a short TTL for high-risk groups

**Avoid**

* blind retry loops on 429/5xx for send actions

---

## B8. Database usage: keep it transactionally correct, not clever

**Why**: approvals, rules, and audits must not drift.

**Do**

* write approval + corresponding rule in a transaction
* append-only audit table, no updates

**Avoid**

* “update audit row later with more info” (breaks IR)

---

## B9. Secrets handling discipline

**Why**: the product’s core promise.

**Do**

* never return secrets in read APIs
* mark secret inputs write-only
* decrypt only in memory, shortest scope possible
* zeroize buffers where feasible (best-effort)

**Avoid**

* storing secrets inside Integration “read” objects
* logging headers/payloads unredacted

---

## B10. Least privilege templates and connector boundaries

**Why**: limit blast radius.

**Do**

* separate templates by action group (read vs send)
* default deny for new endpoints
* explicit allowlist additions require approval

**Avoid**

* `allowed_hosts: ["*"]` or catch-all regex path patterns

---

## B11. Rate limiting is per workload + integration + action group

**Why**: protects upstream quotas and your system stability.

**Do**

* token bucket by action group
* audit throttles

**Avoid**

* only global per-IP limits (doesn’t map to identity)

---

## B12. Dependency hygiene for security-critical packages

**Why**: supply chain risk.

**Do**

* lockfile commits
* regular dependency review for `forwarder`, `auth`, `crypto`

**Avoid**

* pulling small unmaintained libs into the data plane

---


## B13. Every rejection has a reason code and audit event

**Why**: incident response and debugging.

**Do**

```ts
return deny({ code: "ssrf_ip_range", message: "Destination IP denied" });
```

**Avoid**

```ts
return res.status(400).send("bad request");
```

---

## B14. Strict content-type and body limits per action group

**Why**: stops abuse and surprises.

**Do**

* default body limit to 0 unless explicitly allowed
* enforce content-type allowlist

**Avoid**

* accepting arbitrary content-types everywhere

---

## B15. Safe redirect posture

**Why**: redirects are SSRF escalation.

**Do**

* deny redirects in MVP (you already do)
* if ever enabled: re-run allowlist + DNS/IP checks on each hop

**Avoid**

* following redirects automatically

---

## B16. Canonicalization and DNS checks must happen server-side

**Why**: client/interceptor cannot be trusted.

**Do**

* broker canonicalizes and validates regardless of what interceptor did

**Avoid**

* “manifest already matched, skip checks”

---

## B17. Don’t let upstream influence your headers

**Why**: header injection / smuggling / auth confusion.

**Do**

* allowlist response headers you pass back
* strip `set-cookie` unless you have a clear policy

**Avoid**

* “return all upstream headers”

---

## B18. Prefer connection pooling and per-host agents

**Why**: performance and stability.

**Do**

* one pooled client per upstream host / provider
* tune max sockets per host

**Avoid**

* creating new HTTP client per request

---

## B19. Avoid N+1 DB reads on execute path

**Why**: execute path is hot.

**Do**

* load: integration + template + policies in one query path or cached set
* cache templates in memory (versioned)

**Avoid**

* separate DB calls for each stage

---

## B20. Cache with explicit invalidation

**Why**: correctness and security.

**Do**

* cache templates by `template_id@version`
* invalidate on publish, disable, rotation

**Avoid**

* “cache forever” without revocation path

---

## B21. mTLS cert lifecycle and rotation are first-class

**Why**: operational security.

**Do**

* support cert rotation overlap window
* immediate disable = session invalidation

**Avoid**

* long-lived certs with no rotation story

---

## B22. DB schema conventions for security data

**Rules**

* approvals and audit are append-only
* store hashes of tokens, never plaintext
* index by `tenant_id`, `workload_id`, `integration_id`, `timestamp`

**Avoid**

* updating audit rows in place

---

## B23. Secrets handling patterns

**Do**

* “decrypt late, use briefly”
* avoid storing decrypted value in JS objects that get logged or reused
* never put secrets in exception messages

**Avoid**

* attaching secret material to Integration read DTOs (you already flagged this)

---

## B24. SSRF “defense in depth” checklist

**Do**

* allowlist hosts + scheme + port
* DNS resolve at request time
* block private, loopback, link-local, metadata
* deny redirects
* reject IP literal URLs unless explicitly allowed

**Avoid**

* allowlisting based only on string prefix

---


# Security product grade rules

## S1. Default-deny data exposure policy

**Why**: internal tools leak through “helpful debug endpoints.”

**Do**

* Define a data classification list: `public`, `internal`, `sensitive`, `secret`.
* For every API response field, label it (docs or schema annotations).
* Redaction rules enforced server-side.

**Avoid**

* “temporarily returning raw request/headers for debugging.”

---

## S2. “No secrets in exceptions” rule (enforced)

**Why**: exception collectors and logs become exfil channels.

**Do**

```ts
throw new UpstreamError({ code: "upstream_502", message: "Upstream error", correlationId });
```

**Avoid**

```ts
throw new Error(`Failed with headers=${JSON.stringify(headers)}`); // can contain auth
```

---

## S3. Deterministic allowlist evaluation order

**Why**: prevent “rule shadowing” surprises.

**Do**

* Order: `deny exact` -> `deny scoped` -> `allow exact` -> `allow scoped` -> `approval_required` -> default deny
* Make it part of policy engine spec and tests.

**Avoid**

* “first match wins” without defined precedence.

---

## S4. “No dynamic code execution” in broker ecosystem

**Why**: reduces catastrophic exploitability.

**Do**

* ban `eval`, `Function`, dynamic `require` from untrusted input

**Avoid**

* runtime codegen or expression interpreters in policy rules.

---

## S5. Cryptography rules (hard constraints)

**Why**: avoid accidental weak crypto.

**Do**

* Only use established libs, no custom crypto primitives.
* Enforce key sizes and algorithms in config.
* Store only hashes of tokens.

**Avoid**

* homegrown encryption schemes or “simple AES helper” without envelope encryption design.

---

## S6. Replay resistance at the edge

**Why**: stolen session tokens are likely in real incidents.

**Do**

* cert-bound session tokens
* optional DPoP for high-risk actions
* short TTL + sliding window only where needed

**Avoid**

* 24h access tokens for data plane.

---

# Reliability and operability rules

## R1. Every operation has an SLO and an “abort plan”

**Why**: prevents runaway latency and stuck threads.

**Do**

* timeouts + cancellation for upstream requests
* circuit breaker behavior for upstream outages

**Avoid**

* infinite retries or retrying non-idempotent calls.

---

## R2. Idempotency semantics documented per action group

**Why**: prevents accidental duplicate sends.

**Do**

* label action groups as `idempotent` or `non-idempotent`
* only auto-retry idempotent

**Avoid**

* generic retry middleware that retries everything.

---

## R3. Backpressure and queueing rules

**Why**: broker is a choke point.

**Do**

* cap concurrency per upstream host
* use queues for bursts and enforce per-workload fairness

**Avoid**

* unbounded parallelism on `/execute`.

---

## R4. “Audit is non-blocking but never dropped silently”

**Why**: audit must survive outages, but not block execute.

**Do**

* write-ahead queue (DB table or durable queue)
* if audit pipeline degraded, mark events with `delivery_status`

**Avoid**

* execute succeeds but audit disappears with no signal.

---



# Performance rules (practical)

## P1. Avoid allocations in hot path

**Why**: JS GC pauses can spike p95.

**Do**

* reuse objects where safe
* avoid repeatedly parsing URL strings multiple times in pipeline

**Avoid**

* JSON stringify/parse loops in execute path.

---

## P2. Cache immutable reference data aggressively

**Why**: templates and rules are read-heavy.

**Do**

* in-memory cache by version with explicit invalidation
* “warm” caches at startup

**Avoid**

* hitting DB for template/policy on every request.

---

## P3. Use streaming only when you can enforce limits

**Why**: streaming complicates policy enforcement and redaction.

**Do**

* disable streaming in MVP or only allow for known-safe providers with hard caps

**Avoid**

* “stream everything” without size budgets.

---
