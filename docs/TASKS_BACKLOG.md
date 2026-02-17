# Broker MVP Implementation Backlog (Ticket-Ready)

This backlog assumes:

- Broker holds all provider secrets and performs secret injection server-side.
- Workloads authenticate to broker using mutual TLS and obtain short-lived session tokens that are bound to the workload
  certificate.
- Workload interceptor is best-effort and routes only protected-provider calls to the broker.

## Epic 0 - Project Foundations

### Story 0.1 - Repository and CI baseline

**Acceptance criteria**

- Monorepo created with `broker`, `interceptor-node`, and `schemas` packages.
- CI runs: unit tests, lint, SAST, dependency scanning, and build on each PR.
- Artifacts published for broker container image and interceptor package.

### Story 0.2 - Threat model and security requirements

**Acceptance criteria**

- Written threat model includes SSRF, token replay, proxy request smuggling, secret exfil, and prompt injection abuse.
- Security invariants documented and linked in README for all repos.
- Abuse cases enumerated with expected mitigations and tests.

### Story 0.3 - Admin auth model

**Acceptance criteria**

- Admin auth mechanism is selected and documented as OIDC on OAuth 2.0 for the admin UI.
- Admin UI uses Authorization Code + PKCE flow.
- Audit trail records admin subject, IdP, auth method context (amr/acr when available), and session id for control-plane
  actions.

## Epic 1 - Tenancy, Identity, and Sessions

### Story 1.1 - Tenant and user model

**Acceptance criteria**

- Tenants, human users, and roles stored with RBAC enforcement.
- Admin UI can create tenant users and assign roles.
- All data-plane requests are tenant-scoped by workload identity.

### Story 1.2 - Workload enrollment

**Acceptance criteria**

- Admin creates workload and receives one-time enrollment token.
- Workload submits CSR and receives client certificate and CA chain.
- Broker validates CSR contains required identity SAN and EKU clientAuth.
- Workload can be disabled and immediately loses access.

### Story 1.3 - Data-plane mutual TLS enforcement

**Acceptance criteria**

- All data-plane endpoints reject non-mTLS connections.
- Broker extracts workload identity from certificate SAN and maps it to workload record.
- Optional IP allowlist is applied after workload identity is established.

### Story 1.4 - Session token issuance, binding, and validation

**Acceptance criteria**

- `POST /v1/session` issues opaque session tokens with TTL <= configured max.
- Token records store only hash of token plus metadata.
- Token is bound to workload certificate thumbprint or public key hash.
- All data-plane requests require both mTLS and a valid bound session token.
- Optional DPoP proof is supported and replay protection is enforced via `jti` cache.

### Story 1.5 - DPoP proof verification wiring and enforcement

**Acceptance criteria**

- `POST /v1/session` can accept `DPoP` proof and bind `dpop_jkt` to the new session.
- If workload or tenant policy marks DPoP as required, session issuance without valid `DPoP` is rejected.
- Data-plane auth middleware requires `DPoP` proof for sessions with bound `dpop_jkt`.
- DPoP verification on protected calls enforces `expectedJkt=session.dpop_jkt` and `ath` bound to bearer session token.
- Replay detection uses shared `jti` store across instances.
- DPoP failures fail closed before policy evaluation, forwarding, and secret injection.
- Audit events include DPoP failure reason codes (`dpop_missing`, `dpop_signature_invalid`, `dpop_replay`,
  `dpop_jkt_mismatch`, `dpop_ath_mismatch`).

## Epic 2 - Secrets Plane

### Story 2.1 - Encrypted secret storage

**Acceptance criteria**

- Secrets stored encrypted at rest using envelope encryption and KMS abstraction.
- Secrets versioning supported with active version pointer.
- Secrets never appear in logs or error payloads.

### Story 2.2 - Integration management

**Acceptance criteria**

- Admin can create integrations for API-key providers and attach templates.
- For OAuth providers, refresh token storage is supported (OAuth connect flow can be stubbed for MVP if needed).
- Integrations can be disabled and immediately block execution.

## Epic 3 - Templates, Classification, and Policies

### Story 3.1 - Template schema and validator

**Acceptance criteria**

- JSON Schema for templates is implemented and validated on upload.
- Template versions supported and immutable after publish.
- Templates include allowed hosts, path groups, methods, query allowlists, header allowlists, body policies, redirect
  policy.

### Story 3.2 - URL canonicalization and request descriptor

**Acceptance criteria**

- Canonicalization implemented per RFC 3986 style normalization: scheme and host lowercasing, dot segment removal,
  percent-encoding normalization.
- Userinfo and fragment rejected.
- Query normalized by allowlisted keys and stable sorting.
- Canonical request descriptor produced for every execute attempt and written into audit trail.

### Story 3.3 - Classification into action groups

**Acceptance criteria**

- Broker classifies requests into template path groups using host + method + path pattern match.
- If no path group matches, request is rejected with reason `no_matching_group`.

### Story 3.4 - Policy engine v1

**Acceptance criteria**

- Policy rules support: allow, deny, approval_required, and rate limits.
- Policy evaluation is deterministic, logged, and produces a decision object.
- Deny rules override allow rules.
- Default is deny unless explicitly allowed by template and policy.

## Epic 4 - Execute Pipeline and Forwarding

### Story 4.1 - Execute endpoint

**Acceptance criteria**

- `POST /v1/execute` accepts intended URL, method, headers, and body as base64.
- Broker applies mTLS + token validation, template constraints, canonicalization, classification, policy decision.
- Redirects are denied in MVP.
- Broker injects provider credential server-side and forwards upstream.
- Response returned with status code, headers allowlisted, and body base64.

### Story 4.2 - SSRF defenses

**Acceptance criteria**

- DNS resolution performed at request time.
- Destination IPs validated against denylisted ranges (private, loopback, link-local, metadata).
- Requests with resolved internal IPs are rejected.
- Any redirect response from upstream is treated as error in MVP.

### Story 4.3 - Proxy-safe header handling

**Acceptance criteria**

- Hop-by-hop headers stripped and any header listed in `Connection` is removed.
- Ambiguous framing is rejected (conflicting Content-Length and Transfer-Encoding).
- Header forwarding uses per-group allowlist from template.
- Broker never forwards broker session tokens or internal auth headers upstream.

### Story 4.4 - Rate limiting

**Acceptance criteria**

- Rate limits enforced per tenant, per workload, per integration, per action group.
- Limits emit audit events on throttle.

### Story 4.5 - Streaming policy

**Acceptance criteria**

- Broker execute response is buffered and returned as base64 in MVP.
- Requests that require upstream streaming are rejected with a clear error.

## Epic 5 - Approvals and Violations

### Story 5.1 - Approval request creation

**Acceptance criteria**

- When policy requires approval, broker creates ApprovalRequest and returns `approval_required` response.
- ApprovalRequest includes canonical descriptor, action group, risk tier, and a sanitized summary.
- ApprovalRequest has TTL and expires automatically.

### Story 5.2 - Approval decision endpoints

**Acceptance criteria**

- Admin can approve once, approve as rule, or deny.
- Approve-as-rule creates an allow rule scoped to workload + integration + action group + method + host + query keys.
- Deny creates a deny rule and future attempts raise violation events.

### Story 5.3 - Violation events

**Acceptance criteria**

- Repeat attempts that match deny rules generate violation audit events and dashboard counters.
- Violations include correlation IDs and descriptors for incident response.

## Epic 6 - Audit and Incident Response

### Story 6.1 - Audit event pipeline

**Acceptance criteria**

- Every session issuance, execute attempt, policy decision, approval creation, approval decision, and violation emits an
  audit event.
- Audit events are append-only and immutable by API.
- Search API supports filtering by tenant, workload, integration, time range, action group, and decision.

### Story 6.2 - Redaction policy

**Acceptance criteria**

- Audit events never store raw secrets or full sensitive payloads by default.
- Configurable redaction profiles exist per tenant.
- Broker logs are structured and redacted.

## Epic 7 - Manifest and Interceptor v1

### Story 7.1 - Signed manifest distribution

**Acceptance criteria**

- `GET /v1/workloads/{id}/manifest` returns a short-lived manifest with match rules.
- Manifest is signed (JWS) and interceptor verifies signature before use.
- Manifest includes broker execute URL and per-integration match rules (hosts and path groups).

### Story 7.2 - Node interceptor MVP

**Acceptance criteria**

- Interceptor supports Node fetch (undici) and http/https for best-effort capture.
- Requests matching manifest rules are routed to broker execute endpoint.
- Interceptor removes any upstream Authorization header and uses broker session token for broker call.
- Correlation IDs are propagated.

### Story 7.3 - Manifest signing key distribution and rotation

**Acceptance criteria**

- Broker exposes manifest signing keys for interceptor verification.
- Keys are identified by `kid` and support rotation without breaking existing manifests.

### Story 7.5 - Manifest key format and caching

**Acceptance criteria**

- Key format is locked (JWKS or PEM) and documented with supported algorithms.
- Cache headers and max TTL are specified for key distribution.

### Story 7.4 - Base URL override integration mode

**Acceptance criteria**

- SDKs can target broker by setting base URL and broker session token.
- No interception is required for supported SDK base URL mode.

## Epic 8 - Sandbox Analyzer (Optional MVP+)

### Story 8.1 - Response sandbox analysis

**Acceptance criteria**

- `POST /v1/sandbox/analyze` accepts upstream response and runs tool-use simulation with mocked tools.
- Tool attempts are logged and alerts created.
- Output is advisory and does not authorize anything.

## Epic 9 - Security Testing and Hardening

### Story 9.1 - SSRF regression suite

**Acceptance criteria**

- Tests cover DNS rebinding patterns, internal IP ranges, redirects, and malformed URLs.
- Tests cover path traversal and dot-segment normalization.
- Tests cover open proxy attempt patterns.

### Story 9.2 - Proxy and header abuse regression suite

**Acceptance criteria**

- Tests cover hop-by-hop header stripping and Connection header parsing.
- Tests cover TE and CL ambiguity.
- Fuzz tests exist for header parsing and URL parsing.

### Story 9.3 - Redirect handling suite

**Acceptance criteria**

- Tests cover upstream redirects when redirects are denied in MVP.
- Redirect responses are audited consistently with policy decisions.

### Story 9.4 - Token replay suite

**Acceptance criteria**

- Replay attempts with stolen token and different client cert are rejected.
- Optional DPoP replay attempts with reused `jti` are rejected.

### Story 9.5 - Canonicalization test vectors

**Acceptance criteria**

- Tests cover RFC 3986 normalization, dot segment removal, and percent-encoding normalization.
- Tests cover query allowlist filtering and stable sorting.

### Story 9.6 - Header and query multi-value handling

**Acceptance criteria**

- Tests cover duplicate header handling and header canonicalization.
- Tests cover duplicate query keys when not explicitly allowed.
