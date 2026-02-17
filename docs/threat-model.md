
## 1. Purpose and scope

This document defines the **control-plane admin authentication and authorization model** for the Broker system. It covers:

* Admin identity and login flow for the UI and Admin API
* Session management and CSRF protections
* RBAC and tenancy
* Audit requirements for control-plane actions
* Operational considerations (key rotation, token validation, logout)

**Out of scope**

* Workload identity (mTLS, cert issuance) and data-plane auth (covered elsewhere)
* Upstream provider OAuth (Gmail/Calendar, etc.), except where it intersects with admin UX

## 2. Security goals

* Prevent unauthorized control-plane access
* Provide **strong, reviewable** authentication with standard protocols
* Ensure all sensitive operations are attributable via audit records
* Reduce token leakage impact via short-lived credentials and secure session storage

## 3. Decision

Use **OpenID Connect (OIDC) on OAuth 2.0** for admin authentication with **Authorization Code + PKCE**. ([openid.net][1])

### 3.1 Why OIDC

OIDC standardizes identity assertions via ID Tokens and provides a well-understood security model (issuer, audience, nonce, signature validation). ([openid.net][1])

### 3.2 Why PKCE (and why S256)

PKCE reduces authorization code interception and injection risk. Enforce `code_challenge_method=S256`; clients must not downgrade to `plain`. ([IETF Datatracker][2])

## 4. Architecture overview

### 4.1 Components

* **Admin UI** (browser SPA)
* **Admin API** (Broker control-plane endpoints)
* **OIDC Provider** (enterprise IdP or hosted provider)
* **Session Store** (server-side, Broker-managed)
* **Audit Log Sink** (append-only semantics)

### 4.2 Separation of planes

* Control plane: Admin UI + Admin API (OIDC, sessions)
* Data plane: `/v1/execute` etc. (workload identity, mTLS)

Control-plane credentials must never grant data-plane privileges.

## 5. Authentication flows

### 5.1 Login (Authorization Code + PKCE)

1. Admin UI initiates authorization request with `state`, `nonce`, PKCE `code_challenge` (S256)
2. User authenticates at IdP
3. IdP redirects back with `code` and `state`
4. Broker exchanges `code` for tokens using `code_verifier`
5. Broker validates tokens and creates a **server-side session**

OIDC nonce must be checked if present in the ID Token. ([openid.net][1])

### 5.2 Session representation

Use a **server-side session** referenced by a cookie:

* Cookie name: `broker_admin_session`
* Cookie flags:

  * `HttpOnly=true`
  * `Secure=true`
  * `SameSite=Lax` (or `Strict` if compatible with IdP redirects)
  * Bounded `Max-Age` (short)
    Session cookie guidance aligns with OWASP. ([OWASP Cheat Sheet Series][3])

### 5.3 Logout

* Browser logout calls Broker `/admin/logout`
* Broker invalidates server-side session
* Optionally initiate IdP logout (best-effort, not relied upon)

### 5.4 Step-up authentication (optional, later)

For high-risk control-plane actions (e.g., modifying allowlists, rotating keys), require:

* higher `acr` value, or
* re-authentication within a time window
* explicit confirmation when policy scope host changes (MVP host scope is exact-match only; wildcards are forbidden)

## 6. Token validation requirements (OIDC)

Broker must validate:

* **Issuer (`iss`)** matches configured IdP
* **Audience (`aud`)** includes Broker client ID
* **Signature** using IdP keys
* **Expiration (`exp`)** and “not before” if used
* **Nonce** equals the original request nonce when present ([openid.net][1])
* **Authorized party (`azp`)** checks for multi-audience tokens, if applicable

### 6.1 Key discovery and rotation (JWKS)

* Use IdP JWKS endpoint
* Cache keys with TTL
* Respect `kid` changes and rotate cleanly
* Hard-fail signature validation if key is unknown and refresh is exhausted

## 7. CSRF protection (control plane)

Because admin auth uses cookies, apply OWASP CSRF protections:

* Use **SameSite** cookies as baseline
* For state-changing endpoints, require a CSRF token (double-submit cookie or synchronizer token)
* Verify `Origin` and/or `Referer` on state-changing requests
* Never accept state-changing requests from cross-site contexts ([OWASP Cheat Sheet Series][4])

## 8. Authorization model (RBAC + tenancy)

### 8.1 Tenancy

* Every admin session is bound to `tenantId`
* Every control-plane object belongs to exactly one tenant
* Tenant isolation is enforced in:

  * API authorization middleware
  * DB queries (tenant filter is mandatory)

### 8.2 Roles

Minimum roles:

* `owner`: full control including billing, key rotation, admin management
* `admin`: manage workloads, policies, approvals
* `auditor`: read-only including audit logs
* `operator`: limited execution controls, approve/deny requests

### 8.3 Mapping from IdP claims

Define mapping strategy (one of):

* `roles` claim
* `groups` claim
* custom claim `broker_roles`

Default deny if mapping yields no recognized role.

## 9. Audit requirements (control plane)

Every control-plane action must emit an audit event including:

* `actor.sub` (OIDC subject)
* `actor.issuer`
* `actor.session_id`
* `actor.amr` / `actor.acr` when available
* `tenantId`
* action name and object identifiers
* before/after diffs for policy changes
* client IP, user agent, request ID
* validation outcome details when policy constraints fail shared schema checks

## 10. OAuth security baseline notes

For any OAuth behavior in the control plane (and later integrations), avoid deprecated flows and enforce current best practices from the OAuth Security BCP draft (redirect URI exact matching, PKCE, refresh token rotation, reuse detection). ([IETF Datatracker][5])

## 11. Non-functional requirements

* Rate limit login, token exchange, and admin API endpoints
* Centralized error handling (no token leakage in errors/logs)
* External control-plane dependency calls (for example external CA enrollment) must use bounded timeouts and fail closed
* Control-plane sessions must never be accepted as data-plane credentials; data-plane DPoP-bound flows must enforce `expectedJkt` + `ath` binding with shared replay storage
* Security headers for UI: X-Frame-Options/frame-ancestors, CSP, etc. (documented separately)
* Disaster recovery: ability to revoke admin sessions tenant-wide

## 12. Acceptance criteria

* Admin login uses Authorization Code + PKCE (S256)
* ID Tokens are validated for `iss/aud/exp/signature/nonce`
* Session cookie has Secure/HttpOnly/SameSite and bounded lifetime
* CSRF controls applied on state-changing endpoints
* RBAC enforced and tenant isolation is mandatory
* Audit events record admin identity and auth context for every control-plane mutation
* External dependency failures in enrollment/auth flows produce stable reason codes without leaking provider internals

---
