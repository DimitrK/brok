# Broker terminology

This document defines domain terms used across the Broker Admin UI and APIs. It uses plain language with concrete
examples.

## Core entities

**Tenant** A tenant is a customer account boundary. Everything belongs to one tenant so data does not mix. Example:
"Acme" and "Globex" are two tenants in the same Broker deployment.

**Workload** A workload is a system that makes requests through the Broker. Example: a backend service that calls the
Broker to reach an external AI API.

**Enrollment token** A one-time code used to onboard a workload and get its client certificate. Example: a service gets
an enrollment token, submits a CSR, and receives a cert.

**Broker CA** The Broker's own certificate authority that issues workload certificates. Example: the Broker signs the
workload cert and returns the CA chain.

**External CA** A customer-managed CA. The Broker checks the cert chain instead of issuing it. Example: your company PKI
signs the cert, and the Broker validates it.

**Integration** A named connection to an upstream provider plus its credentials and policy binding. Example: "OpenAI
prod" or "Google Mail" integrations with stored API keys.

**Template** A versioned ruleset for a provider: allowed hosts, paths, methods, and safety rules. Example: a "gmail"
template allows only Gmail API hosts and paths.

**Template version** Templates are immutable once published. Changes create a new version. Example: v2 adds a new Gmail
endpoint; integrations can move from v1 to v2.

**Policy rule** A specific allow/deny/approval/rate-limit rule for a workload and integration. Example: allow POST to
api.openai.com for action group "messages.send".

**Approval request** A request created when a workload tries something that needs human approval. Example: the first
call to a new host creates a pending approval.

**Approval decision mode** The scope of the approval decision. Example: "once" approves a single call; "rule" creates a
reusable policy rule.

**MFA approval** A policy constraint that requires the approver to have recent MFA. Example: approving a high-risk
action requires a fresh MFA prompt.

**Audit event** An immutable record of an action and its decision. Example: "Workload X executed POST /v1/messages and
was allowed".

## Security and identity terms

**mTLS (mutual TLS)** Certificate-based authentication for workloads. Example: the workload presents its client cert
when calling the Broker.

**Session token** A short-lived token used for execute calls after mTLS. Example: a workload gets a token valid for 15
minutes.

**DPoP** Proof a token is held by a specific client key to prevent replay. Example: the request must include a DPoP
proof signed by the workload key.

**Risk tier** A simple label for how risky an action is. Example: "high" for deleting data, "low" for read-only calls.

**Action group** A human-friendly grouping of related provider actions. Example: "files.upload" or "messages.send".

## Manifest and keys

**Manifest** A signed document sent to workloads. It tells them where to send execute traffic and what destinations are
valid. Example: a manifest lists allowed hosts and the Broker execute URL.

Fields in a manifest:

- **manifest_version**: version number for the manifest format.
- **issued_at**: when the manifest was created.
- **expires_at**: when the manifest becomes invalid.
- **broker_execute_url**: the Broker data-plane URL that workloads must call.
- **dpop_required**: whether DPoP is required for execute requests.
- **dpop_ath_required**: whether DPoP must bind the access token hash (ath).
- **match_rules**: allowed destinations per integration (hosts, schemes, ports, path groups).
- **signature**: JWS signature metadata (alg, kid, jws) used to verify the payload.

Example match rule in plain language: "Integration X may call https://api.openai.com on port 443 for path group
'messages' using execute mode."

**Manifest keys (JWKS)** The public keys used by workloads to verify manifest signatures. Example: the Broker publishes
a JWKS with a single Ed25519 key.

```json
{
  "keys": [
    {
      "kid": "manifest_b184d990-e793-4896-8221-f2d66ed588cc",
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "wEF2EZhb1eR7MlLMQ6Jlon2XV1WPbG31DqBBcZUp8VY",
      "alg": "EdDSA",
      "use": "sig"
    }
  ]
}
```

Field meanings:

- **kid**: key identifier referenced by manifest signatures.
- **kty**: key type (OKP for Ed25519, EC for P-256).
- **crv**: curve name when applicable.
- **x**: public key material (for OKP keys).
- **y**: second coordinate (for EC keys).
- **alg**: signing algorithm.
- **use**: key usage (sig = signature verification).

## Specialized UI terms

**Policy constraints** Optional limits attached to approvals or rules. Example: allow only query keys "model" and
"temperature" and require MFA.

**Approval status** Where an approval is in its lifecycle. Example: "pending" means waiting for a decision.

**Enrollment mode** How a workload gets its certificate. Example: broker_ca uses Broker CA, external_ca uses your PKI.

**Template status** Whether a template version can be used. Example: "disabled" means new integrations cannot use it.

**Integration status** Whether the integration can be used for execution. Example: disabling it blocks execute requests
for that integration.

**Audit decision** The outcome stored in audit events. Example: "approval_required" means the call created a pending
approval.

If you want this expanded with screenshots or exact UI labels, tell me which screen set to use (Workloads, Integrations,
Templates, Policies, Approvals, Audit).
