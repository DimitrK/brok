“secrets firewall for outbound tool calls.” is the moto for this two-parts tool that secures AI agents from prompt
injections which focus on exposing secrets or exploiting 3rd party services. Your revised scope is coherent and
materially more buildable broker is the only place where third-party secrets exist and are usable workloads use
broker-issued opaque tokens only calls that require those secrets are routed through the broker policy, approval,
monitoring, and incident audit apply only to those protected calls.

Below is a concrete MVP spec focused on protecting third-party secrets and controlling only the calls that require those
secrets. It is designed so the broker remains the enforcement point, while the in-app interceptor is a convenience layer
and a routing helper.

This spec assumes you treat prompt injection as a persistent risk and design to minimize impact rather than assume
perfect mitigation. ([NCSC][1])

---

## Product statement and MVP boundary

**Goal**

- Prevent protected-provider credentials from being exposed or misused by AI agents, including under prompt injection
- Centralize secret custody, policy enforcement, approvals, and audit for requests that require those secrets
- Provide a low-friction integration path for workloads via a lightweight interceptor plus optional SDK conveniences

**Non-goals in MVP**

- Full egress control for all outbound traffic
- Preventing data exfiltration to arbitrary attacker endpoints that do not require protected provider credentials
- “Perfect” interception coverage in every language and network stack

---

## Threat model and security invariants

### Security invariants

1. Provider credentials never leave the broker in a usable form
2. A workload token is never forwarded upstream
3. Any protected-provider request that succeeds must have been executed by the broker
4. Broker policy is deterministic and auditable, not LLM-decided
5. The broker never becomes a general-purpose proxy

### Key threat classes and mitigations

- SSRF against broker execute capabilities
  - Strict allowlists, safe URL canonicalization, DNS and IP validation, redirect policy, block internal address ranges
    ([OWASP Cheat Sheet Series][2])

- Replay and token theft
  - mTLS workload identity with certificate-bound sessions, optional DPoP proof-of-possession on top ([IETF
    Datatracker][3])

- Proxy-layer request smuggling and header abuse
  - Hop-by-hop header stripping, strict framing rules, Connection header parsing requirements ([IETF Datatracker][4])

- Prompt injection leading to unintended tool use
  - Policy and approvals at broker, least privilege templates, sandbox tool firewall as a secondary signal not an
    authorizer ([NCSC][1])

---

## High-level architecture

### Components

1. Broker control plane
   - Tenants, integrations, templates, policies, workloads, approvals UI, audit search

2. Broker data plane
   - Auth via mTLS, session issuance, request execution, secret injection, policy engine, audit emission

3. Workload interceptor
   - Runs inside the workload process
   - Downloads a signed manifest of match rules and broker routing
   - For matched requests, rewrites to broker execute API
   - Never injects provider credentials

4. Optional sandbox tool firewall service
   - Runs on broker side
   - Takes upstream responses and simulates tool usage in a sandbox with mocked tools
   - Produces alerts and suggested rules
   - Does not authorize requests

---

## Data model

Minimum entities for MVP

- Tenant
- HumanUser
- Workload
  - mTLS identity, allowed IP ranges optional, enabled status

- WorkloadSession
  - short-lived, bound to workload mTLS identity

- Integration
  - provider type, secret reference, assigned templates

- Secret
  - encrypted provider API key or OAuth refresh token

- Template
  - allowed destinations and path groups for a provider

- PolicyRule
  - allow, deny, approval_required, rate limits, constraints

- ApprovalRequest
  - pending approval for a canonical request descriptor

- AuditEvent
  - immutable structured record

---

## Template schema

### Concept

Templates define what the broker is willing to execute for a given integration type. Templates are not per-endpoint
routes in code. They are declarative allowlists and action groups.

Templates also drive classification, risk tiers, and approval defaults. SSRF controls begin with strong allowlists.
([OWASP Cheat Sheet Series][2])

### JSON schema draft

```json
{
  "template_id": "tpl_google_gmail_v1",
  "version": 1,
  "provider": "google_gmail",
  "description": "Gmail minimal safe template",
  "allowed_schemes": ["https"],
  "allowed_ports": [443],
  "allowed_hosts": ["gmail.googleapis.com"],
  "redirect_policy": {
    "mode": "deny"
  },
  "path_groups": [
    {
      "group_id": "gmail_read",
      "risk_tier": "low",
      "approval_mode": "none",
      "methods": ["GET"],
      "path_patterns": ["^/gmail/v1/users/[^/]+/messages/[^/]+$", "^/gmail/v1/users/[^/]+/messages$"],
      "query_allowlist": ["format", "maxResults", "q", "pageToken"],
      "header_forward_allowlist": ["content-type", "accept", "user-agent"],
      "body_policy": {
        "max_bytes": 0,
        "content_types": []
      }
    },
    {
      "group_id": "gmail_send",
      "risk_tier": "high",
      "approval_mode": "required",
      "methods": ["POST"],
      "path_patterns": ["^/gmail/v1/users/[^/]+/messages/send$"],
      "query_allowlist": [],
      "header_forward_allowlist": ["content-type", "accept", "user-agent"],
      "body_policy": {
        "max_bytes": 1048576,
        "content_types": ["application/json"]
      },
      "constraints": {
        "recipient_domain_allowlist": [],
        "recipient_allowlist": []
      }
    }
  ],
  "network_safety": {
    "deny_private_ip_ranges": true,
    "deny_link_local": true,
    "deny_loopback": true,
    "deny_metadata_ranges": true,
    "dns_resolution_required": true
  }
}
```

### Notes

- `path_patterns` should be anchored regex or a safe glob dialect compiled to regex at publish time
- `network_safety` flags are enforced in broker execute pipeline, not in the interceptor

### Templates you ship in MVP

- OpenAI minimal template for responses or chat endpoints depending on which API compatibility you target
- Anthropic minimal template for messages endpoints
- Google Gmail minimal template
- Google Calendar minimal template

When you build provider templates, keep them narrow and evolve by versioning. The user can override by adding extra
rules through UI, but default remains restrictive.

---

## Canonicalization algorithm

You need canonicalization for two purposes

- rule matching
- deduplication for one-time approval caching

Use RFC 3986 normalization guidance as baseline for syntax-based normalization. ([IETF Datatracker][5])

### Canonical request descriptor

Broker computes a canonical descriptor from the inbound execute request and uses it for

- policy evaluation
- approval matching
- audit
- rate limits

Descriptor fields

- tenant_id
- workload_id
- integration_id
- template_id and version
- method
- canonical_url
- matched_path_group_id
- normalized headers subset
- query keys subset
- body digest for high-risk groups optional

### URL canonicalization steps

1. Parse URL using a strict RFC 3986 parser
2. Enforce scheme allowlist, default to deny for anything not https ([OWASP Cheat Sheet Series][2])
3. Lowercase scheme and host
4. Convert host to ASCII using IDNA, reject invalid labels
5. Remove default port 443 if explicitly specified
6. Normalize path
   - remove dot-segments using RFC 3986 algorithm ([IETF Datatracker][5])
   - percent-encoding normalization, uppercase hex, decode unreserved where safe per RFC 3986 ([IETF Datatracker][5])

7. Normalize query
   - parse into key value pairs
   - keep only keys that are allowlisted for the matched path group
   - sort keys lexicographically
   - preserve duplicate keys only if explicitly allowed

8. Reject userinfo component entirely
9. Fragment is ignored and should be rejected if present

### DNS and IP safety checks

To avoid DNS rebinding and internal network access, validate destination after resolution and block internal ranges.
This is standard SSRF prevention guidance. ([OWASP Cheat Sheet Series][2])

Broker execution pipeline for DNS safety

- resolve hostname at request time
- validate each returned A and AAAA record against denylist ranges
- optionally pin to resolved IPs for a short TTL window and revalidate on redirects
- deny redirects by default, or re-run full checks on each redirect hop if you later enable redirects

---

## Approval state machine

Approvals are created only for protected calls that match a template but are not currently allowed by policy, or are
marked approval_required by risk tier.

### States

| State    | Meaning                                                |
| -------- | ------------------------------------------------------ |
| pending  | waiting for human decision                             |
| approved | allowed under specific scope and constraints           |
| denied   | explicitly blocked, repeat attempts produce violations |
| expired  | not decided before TTL                                 |
| executed | the specific request instance executed after approval  |
| canceled | withdrawn by admin                                     |

### Transitions

- pending -> approved
- pending -> denied
- pending -> expired
- approved -> executed for the specific pending request instance
- approved remains as a rule if user chose “approve future matches”
- denied creates or updates a deny rule
- repeat blocked attempts after denied raise a violation event

### Approval scopes

1. once
   - approves exactly the canonical descriptor once

2. rule
   - converts to an allow rule for the descriptor class
   - class fields must be explicit
     - path_group_id
     - method
     - host
     - optional query key allowlist

3. rule with constraints
   - allow rule plus constraints
   - examples for Gmail send
     - recipient allowlist
     - recipient domain allowlist
     - max recipients
     - max body bytes

---

## Broker APIs

### Authentication model

**mTLS workload identity**

- all data-plane endpoints require mTLS
- map cert SAN URI to workload_id
- session tokens are certificate-bound in the sense that the token record stores a cert thumbprint or public key hash
  and broker checks the presented client cert matches that binding ([IETF Datatracker][3])

**Optional DPoP**

- `POST /v1/session` may include `DPoP` header so the broker can bind session to a DPoP public key thumbprint (`dpop_jkt`)
- protected data-plane calls include `DPoP` proof and are verified against bound `dpop_jkt` when present
- for bearer-bound proofs, broker verifies `ath` against the presented session token
- broker verifies signature and checks replay using `jti` and timestamp
- DPoP is designed to sender-constrain tokens and detect replay. ([RFC Editor][6])

**IP allowlist**

- optional additional check after mTLS identity is established
- used as defense-in-depth only

### Data-plane auth gate order

Use a fixed middleware order and fail closed before policy and forwarding:

1. `requireMtls`
2. `requireSession` (token hash lookup + cert fingerprint binding)
3. `requireDpopIfBound` (proof verification with `expectedJkt` and optional `ath`)
4. policy evaluation, secret injection, forwarding, audit

---

## Control plane endpoints

### Create workload

`POST /v1/tenants/{tenant_id}/workloads`

Request

```json
{
  "name": "prod-agent-1",
  "ip_allowlist": ["203.0.113.0/24"],
  "enrollment_mode": "broker_ca"
}
```

Response

```json
{
  "workload_id": "w_2c71",
  "enrollment_token": "enr_...",
  "mtls_ca_pem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
}
```

### Upload CSR and get client cert

`POST /v1/workloads/{workload_id}/enroll`

Request

```json
{
  "enrollment_token": "enr_...",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...-----END CERTIFICATE REQUEST-----",
  "requested_ttl_seconds": 2592000
}
```

Response

```json
{
  "client_cert_pem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
  "ca_chain_pem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----",
  "expires_at": "2026-03-05T12:00:00Z"
}
```

### Create integration

`POST /v1/tenants/{tenant_id}/integrations`

Request for API key providers

```json
{
  "provider": "openai",
  "name": "openai-prod",
  "secret_material": {
    "type": "api_key",
    "value": "sk-live-..."
  },
  "template_id": "tpl_openai_min_v1"
}
```

Response

```json
{
  "integration_id": "i_openai_01"
}
```

OAuth integrations would store refresh tokens similarly, but with a proper OAuth connect flow.

---

## Data plane endpoints

### Issue session

`POST /v1/session`

mTLS required

Headers

- optional `DPoP: <proof_jwt>` to bind new session to a DPoP key

Request

```json
{
  "requested_ttl_seconds": 900,
  "scopes": ["execute", "manifest.read"]
}
```

Response

```json
{
  "session_token": "bk_sess_v1_...",
  "expires_at": "2026-02-04T12:15:00Z",
  "bound_cert_thumbprint": "sha256:...",
  "dpop_jkt": "base64url-sha256-jwk-thumbprint"
}
```

### Get signed manifest for interceptor

`GET /v1/workloads/{workload_id}/manifest`

Response

```json
{
  "manifest_version": 1,
  "issued_at": "2026-02-04T12:00:00Z",
  "expires_at": "2026-02-04T12:10:00Z",
  "broker_execute_url": "https://broker.example/v1/execute",
  "dpop_required": true,
  "dpop_ath_required": true,
  "match_rules": [
    {
      "integration_id": "i_openai_01",
      "provider": "openai",
      "match": {
        "hosts": ["api.openai.com"],
        "schemes": ["https"],
        "ports": [443],
        "path_groups": ["openai_responses"]
      },
      "rewrite": {
        "mode": "execute",
        "send_intended_url": true
      }
    }
  ],
  "signature": {
    "alg": "EdDSA",
    "kid": "broker-manifest-1",
    "jws": "eyJ..."
  }
}
```

The interceptor must verify the JWS before applying rules.

### Execute protected request

`POST /v1/execute`

Headers

- `Authorization: Bearer <session_token>`
- `DPoP: <proof_jwt>` required when session is DPoP-bound (`dpop_jkt`) or policy mandates DPoP ([RFC Editor][6])

Request

```json
{
  "integration_id": "i_openai_01",
  "request": {
    "method": "POST",
    "url": "https://api.openai.com/v1/responses",
    "headers": {
      "content-type": "application/json",
      "accept": "application/json"
    },
    "body_base64": "eyJtb2RlbCI6ICJn..."
  },
  "client_context": {
    "request_id": "9b5c1f2a-3c43-4c29-8a4a-0d2c1d7d6a91",
    "idempotency_key": "idem_...",
    "source": "interceptor_node_v1"
  }
}
```

Response for allow and execute

```json
{
  "status": "executed",
  "correlation_id": "corr_4f19...",
  "upstream": {
    "status_code": 200,
    "headers": {
      "content-type": "application/json"
    },
    "body_base64": "eyJvdXRwdXQiOiBb..."
  }
}
```

Response for approval required

```json
{
  "status": "approval_required",
  "approval_id": "appr_7d91",
  "expires_at": "2026-02-04T12:05:00Z",
  "correlation_id": "corr_4f19...",
  "summary": {
    "integration_id": "i_google_gmail_01",
    "action_group": "gmail_send",
    "risk_tier": "high",
    "destination_host": "gmail.googleapis.com",
    "method": "POST",
    "path": "/gmail/v1/users/me/messages/send"
  }
}
```

---

## Proxy-safe forwarding rules inside broker

The broker is acting as an intermediary and must implement strict HTTP normalization and forwarding rules.

Minimum requirements

- Parse Connection header and remove hop-by-hop headers before forwarding ([tech-invite.com][7])
- Reject ambiguous framing, conflicting Content-Length and Transfer-Encoding cases
- Prevent hop-by-hop header abuse that can trick proxies into stripping critical framing headers ([Akamai][8])
- Maintain header forward allowlists from templates

---

## Interceptor behavior spec

### Runtime behavior

1. Establish mTLS to broker, fetch session token
2. Fetch manifest and verify signature
3. Intercept outbound requests in supported HTTP stacks
4. For each request
   - canonicalize target enough to match rule host and path group
   - if matched, rewrite into `/v1/execute` call
   - include intended URL and original request components
   - remove any Authorization header meant for upstream and replace with broker session token

5. For non-matched requests
   - no action

### Supported interception for MVP

- Node undici fetch interception via dispatcher hook
- Node http and https agent interception
- Axios interceptor integration
- Explicit wrapper API for cases you cannot safely intercept

The interceptor does not need to be complete. Its job is to route protected requests to the broker when it can. Any
direct call to protected providers using broker-issued tokens must fail at the provider because the provider will not
accept broker tokens.

---

## Sandbox tool firewall

### Purpose

- Detect suspicious tool-like behavior in upstream responses
- Provide alerts and suggested policies
- Never authorize execution

This aligns with treating LLM outputs as potentially hostile and designing mitigations that reduce impact rather than
assuming perfect prevention. ([NCSC][1])

### Minimal API

`POST /v1/sandbox/analyze`

Request

```json
{
  "integration_id": "i_openai_01",
  "correlation_id": "corr_4f19...",
  "upstream_response_base64": "eyJvdXRwdXQiOiBb...",
  "mock_tools": true
}
```

Response

```json
{
  "tool_use_detected": true,
  "attempted_tools": [{"tool": "gmail.send", "arguments_redacted": true}],
  "risk_score": 0.82,
  "recommendations": [{"type": "require_approval", "action_group": "gmail_send", "scope": "workload"}]
}
```

---

## Audit event schema

A single canonical event schema makes incident response feasible.

```json
{
  "event_id": "evt_...",
  "timestamp": "2026-02-04T12:00:01Z",
  "tenant_id": "t_9f3a",
  "workload_id": "w_2c71",
  "integration_id": "i_openai_01",
  "correlation_id": "corr_4f19...",
  "event_type": "execute",
  "decision": "allowed",
  "action_group": "openai_responses",
  "risk_tier": "low",
  "destination": {
    "scheme": "https",
    "host": "api.openai.com",
    "port": 443,
    "path_group": "openai_responses"
  },
  "latency_ms": 842,
  "upstream_status_code": 200
}
```

---

## Milestones and concrete work items

### Milestone 1 - Identity, sessions, secrets

- Workload enrollment and cert issuance
- mTLS enforcement on data-plane
- session token issuance and cert binding ([IETF Datatracker][3])
- secret storage with envelope encryption

### Milestone 2 - Templates, canonicalization, execute pipeline

- template schema and versioning
- canonicalization implementation based on RFC 3986 ([IETF Datatracker][5])
- SSRF defenses, DNS and IP validation, redirect deny policy ([OWASP Cheat Sheet Series][2])
- execute endpoint with injection and proxy-safe forwarding ([tech-invite.com][7])

### Milestone 3 - Approvals and violations

- approval state machine, UI, admin actions
- allow and deny rule persistence
- violation events on repeat denied attempts

### Milestone 4 - Interceptor

- signed manifest distribution
- Node undici and http/https support
- axios integration
- correlation ID propagation

### Milestone 5 - Sandbox analyzer

- offline tool-use simulation with mocked tools
- alerting hooks and rule suggestion
- strict separation from authorization path ([NCSC][1])

---

## Key design decisions to lock now

- Broker execute must be template constrained, not user-provided arbitrary proxying ([OWASP Cheat Sheet Series][2])
- Token binding to workload cert thumbprint as baseline, DPoP optional for higher assurance ([IETF Datatracker][3])
- Redirects denied in MVP
- Approval cache key based on canonical descriptor, never raw strings ([IETF Datatracker][5])

If you want the next artifact to be directly convertible to tickets, I can convert the above into an implementation
backlog with acceptance criteria and a minimal OpenAPI document for the broker endpoints and JSON Schema files for
templates, manifests, and audit events.

[1]:
  https://www.ncsc.gov.uk/blog-post/prompt-injection-is-not-sql-injection?utm_source=chatgpt.com
  'Prompt injection is not SQL injection (it may be worse)'
[2]:
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html?utm_source=chatgpt.com
  'Server-Side Request Forgery Prevention Cheat Sheet'
[3]:
  https://datatracker.ietf.org/doc/html/rfc8705?utm_source=chatgpt.com
  'RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication ...'
[4]:
  https://datatracker.ietf.org/doc/html/rfc7230?utm_source=chatgpt.com
  'RFC 7230 - Hypertext Transfer Protocol (HTTP/1.1)'
[5]:
  https://datatracker.ietf.org/doc/html/rfc3986?utm_source=chatgpt.com
  'RFC 3986 - Uniform Resource Identifier (URI): Generic ...'
[6]:
  https://www.rfc-editor.org/rfc/rfc9449.html?utm_source=chatgpt.com
  'OAuth 2.0 Demonstrating Proof of Possession (DPoP)'
[7]: https://www.tech-invite.com/y70/tinv-ietf-rfc-7230-3.html?utm_source=chatgpt.com 'RFC 7230 (Obsoleted): 3 of 4'
[8]:
  https://www.akamai.com/blog/security/akamai-mitigates-hop-by-hop-header-abuse?utm_source=chatgpt.com
  'Akamai Mitigates Hop-by-Hop Header Abuse Leading to ...'
