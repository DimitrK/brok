
## 1. Purpose and scope

Threat model for the Broker ecosystem focusing on:

* Broker control plane (admin UI/API)
* Broker data plane (execute/proxy for protected services)
* Workload-interceptor interaction model
* Policy, approvals, audit integrity
* SSRF-class risks arising from “execute URL” semantics

This is a living document tied to regression tests and backlog items.

## 2. System context and trust boundaries

### 2.1 Trust zones

* **Zone A: Admin Browser** (untrusted client)
* **Zone B: Admin API** (control plane)
* **Zone C: Broker Data Plane** (execute, forwarder, policy engine)
* **Zone D: Workloads** (semi-trusted; may be compromised)
* **Zone E: Upstream Providers** (OpenAI/Anthropic, Google APIs, SMTP/IMAP, etc.)
* **Zone F: Storage** (DB, audit log, secrets store)

### 2.2 Key trust boundaries

* Browser ↔ Admin API (public internet)
* Workload ↔ Broker Data Plane (private network, authenticated workload identity)
* Broker ↔ Upstream Providers (egress controlled by Broker)

## 3. Assets

High-value assets:

* Encrypted secrets, wrapping keys, secret material references
* Workload session tokens, cert bindings, replay-resistant artifacts (optional DPoP)
* Policy rules, templates, manifests
* Approval state machine records
* Audit logs (integrity and completeness)

## 4. Entry points

* Admin UI routes, OAuth callbacks
* Admin API endpoints (workload management, policy changes)
* Data plane: `/execute` and related endpoints
* Manifest distribution endpoints
* Any webhook ingestion from upstream providers (if present later)

## 5. Attacker profiles

* External attacker with no credentials
* Attacker with stolen admin session cookie
* Attacker with stolen workload token or compromised workload host
* Malicious tenant admin / insider
* Supply-chain attacker (dependency compromise)
* Upstream provider compromise or outage (assume possible, mitigate blast radius)

## 6. Security invariants

1. Broker never returns decrypted secrets to workloads
2. Broker never forwards Broker-issued workload tokens upstream
3. Default deny for all egress; only approved, canonicalized destinations are allowed
4. All policy decisions and executions are auditable and attributable

## 7. Threat categories and mitigations

### 7.1 SSRF (execute URL is inherently SSRF-shaped)

SSRF is explicitly recognized as a top-tier risk when fetching remote resources based on user-controlled URLs. ([OWASP][6])

**Controls**

* Strict allowlist for scheme, host, port, and path patterns
* Resolve DNS and validate resulting IPs against allowed ranges; block private, loopback, link-local and metadata IP ranges
* Deny redirects by default; do not follow 30x automatically
* Enforce canonical URL parsing and normalization
* Rate limits and timeouts for upstream calls

These align with OWASP SSRF prevention guidance. ([OWASP Cheat Sheet Series][7])

### 7.2 OAuth code interception / injection

**Controls**

* Authorization Code + PKCE with S256
* Exact redirect URI matching and strict state verification
  PKCE S256 and no downgrade are normative requirements. ([IETF Datatracker][2])

### 7.3 Session theft and CSRF (admin control plane)

**Controls**

* Secure/HttpOnly/SameSite cookies, short session TTL
* CSRF tokens + Origin/Referer checks for state-changing endpoints
  OWASP documents the mechanics and mitigations. ([OWASP Cheat Sheet Series][4])

### 7.4 Token replay against data plane

**Controls**

* Workload identity via mTLS plus session-bound tokens
* Optionally add DPoP for replay detection on sensitive actions
  DPoP provides sender-constraining and replay detection semantics. ([IETF Datatracker][8])
* For DPoP-bound sessions, verification must enforce both:
  * `expectedJkt` bound to the stored session `dpop_jkt`
  * `ath` bound to the presented bearer session token
* DPoP `htu` normalization must reject non-HTTP(S) schemes and reject URL userinfo
* Replay protection must use a shared store (for example Redis) and a scoped key that includes tenant/session/key thumbprint context

### 7.5 HTTP request smuggling / splitting

Risk: differences in HTTP parsing between proxies and upstream components allow bypass or desync attacks.

**Controls**

* Strict HTTP parsing and normalization
* Disallow ambiguous `Content-Length`/`Transfer-Encoding` combinations
* Disallow hop-by-hop headers and normalize headers
* No request pipelining across trust boundaries
* Regression tests for smuggling vectors
  OWASP WSTG includes smuggling testing guidance. ([OWASP][9])
  (PortSwigger coverage is also a useful reference for severity and common patterns.) ([PortSwigger][10])

### 7.6 Prompt injection as operational risk

Prompt injection does not directly compromise the Broker, but can induce workloads to attempt dangerous actions.

**Controls**

* Workload cannot obtain real secrets; only broker-issued tokens
* Approvals required for new endpoints and sensitive action templates
* Audit and anomaly detection for unusual sequences of actions
* Optional “sandboxed tool simulation” as advisory signal only (never final authorization)

### 7.7 Audit log integrity and non-repudiation

**Controls**

* Append-only audit storage semantics
* Include request ID, decision ID, actor identity, timestamps
* Ensure audit path is non-blocking but never silently dropped (queue + delivery status)

### 7.8 Supply chain and dependency compromise

**Controls**

* Dependency allowlist for security-critical packages
* Locked versions and CI drift checks
* Minimal dependency footprint in execute/policy engine hot path

### 7.9 External CA enrollment dependency failures

Risk: onboarding flows that depend on external CA services can leak sensitive details, hang indefinitely, or return unsafe trust bundles if not validated strictly.

**Controls**

* enforce strict timeouts and cancellation for external CA calls
* fail closed on transport errors, malformed responses, and unknown provider error shapes
* use stable error codes for policy/audit mapping and sanitize client-facing error messages
* reject private key material and oversized trust payloads

### 7.10 Workload source IP uncertainty with allowlists

Risk: if workload IP allowlists are configured but source IP cannot be resolved from the transport/socket, a permissive implementation can silently bypass allowlist enforcement.

**Controls**

* fail closed when source IP is unavailable while an allowlist is present
* treat unknown source IP as `workload_ip_denied` and require operator investigation
* keep this behavior explicit in middleware and regression tests

## 8. Approval and policy decision model

### 8.1 Default deny and one-time approvals

* Unknown canonical destinations generate an approval request
* Approvals are scoped to workload + canonical request descriptor
* Denials persist and generate violation events on repeated attempts

### 8.2 Canonicalization as a security boundary

Canonicalization must be deterministic and stable:

* Normalize scheme/host
* Normalize path and remove dot segments
* Normalize query key ordering, drop irrelevant parameters if policy says so
* Extract “auth-relevant” header fields and normalize casing
* For MVP policy scope, host matching is exact-only; wildcard hosts are forbidden
* Approval constraints and derived policy constraints must validate against shared bounded schema contracts (no ad-hoc free-form objects)

## 9. Residual risks and explicit non-goals

* If a workload host is fully compromised, attacker may cause allowed actions within that workload’s policy envelope
* Broker cannot prevent all malicious actions; goal is to constrain and audit
* Upstream provider outages can cause denial-of-service; Broker should fail closed

## 10. Monitoring and detection signals

* Spike in denied approvals per workload
* Repeated attempts to reach private IP ranges or metadata hosts
* Policy changes by admins outside normal windows
* Unusual execution graph patterns (new hostnames, new paths, new methods)
* Audit delivery failures or gaps

## 11. Test plan and backlog mapping

* SSRF regression suite (DNS rebinding, redirects, scheme confusion)
* Request smuggling suite aligned to WSTG cases ([OWASP][9])
* OAuth flow tests (PKCE S256 required, state/nonce validation) ([openid.net][1])
* CSRF tests for all state-changing admin endpoints ([OWASP Cheat Sheet Series][4])
* Replay tests for workload session tokens and optional DPoP proofs ([IETF Datatracker][8])
* DPoP wiring tests that fail closed when `expectedJkt` or `ath` binding is omitted in DPoP-bound paths

## 12. Checklist alignment

Use ASVS as a verification checklist for architecture, authentication, session management, access control, validation, crypto, logging and data protection. ([OWASP][11])

---


## Implementation checklist

* PKCE

  * Enforce `code_challenge_method=S256` for all browser-based clients. ([IETF Datatracker][2])
  * Reject `plain` and reject missing `code_challenge_method` if you’re mandating S256.

* OIDC token validation

  * Verify ID Token signature using IdP keys and handle rotation correctly. ([openid.net][1])
  * Verify nonce equals the original request nonce when present. ([openid.net][1])
  * Verify issuer and audience are exactly what you expect. ([openid.net][1])

* Sessions

  * Prefer server-side sessions referenced by Secure and HttpOnly cookies, with bounded TTL and revocation semantics. ([OWASP Cheat Sheet Series][3])

* CSRF

  * Use SameSite plus a CSRF token scheme for state-changing endpoints, and validate Origin or Referer where feasible. ([OWASP Cheat Sheet Series][4])

## Common pitfalls to watch for

* Accepting PKCE default behavior where omission implies `plain`, which is weaker than S256. ([IETF Datatracker][2])
* Treating access tokens as identity without ID Token validation rules, especially nonce. ([openid.net][1])
* Relying on SameSite alone as “CSRF solved” for all cases instead of layering token and origin controls. ([OWASP Cheat Sheet Series][4])
* Not planning for key rotation and `kid` changes, leading to brittle deployments. ([openid.net][1])
