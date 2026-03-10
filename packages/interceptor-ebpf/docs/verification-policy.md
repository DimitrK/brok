# eBPF Compatibility Verifier Policy

## Purpose

Workload-specific eBPF compatibility verifiers are optional package-level tools. They exist to document and validate
local interception assumptions for a named workload or runtime-auth strategy when those assumptions are not already
covered by the core eBPF contracts in this package.

They are not a required dependency for every new `secret_material.type` or `constraints.upstream_auth.type`.

## What stays generic

The following remain the reusable cross-package contract surface:

- `@broker-interceptor/schemas` owns public secret and runtime-auth discriminators.
- Template constraints activate runtime-auth behavior.
- Core eBPF contracts in this package own:
  - dataplane verdict reason-code namespaces
  - control-plane authz reason-code namespaces
  - boundary parsing and log serialization

Compatibility verifiers must not become an implicit prerequisite for adding a new credential type.

## When a verifier is not required

Do not add a workload-specific verifier when all of the following are true:

- the credential change only affects stored secret shape, not socket-interception behavior
- runtime auth remains fully broker-side and does not depend on workload-specific path or query semantics
- interception safety depends only on destination scheme, host, and port already covered by exact template allowlists
- the transport path is fully covered by the existing hook model for the intended protocol
- no wildcard or dynamic-host broadening is introduced

Example:

- a new structured bearer-token secret type that still results in ordinary HTTPS requests to exact template hosts

## When a verifier is required

Add a workload-specific verifier when at least one of the following is true:

- a workload depends on request-shape semantics that could be mistaken for an interception or policy mismatch
  - examples: bucket-root list queries, canonicalized query sets, object-path conventions
- transport coverage depends on hooks beyond the default connect path
  - examples: unconnected UDP, `sendmsg4`, `sendmsg6`
- runtime-auth behavior is sensitive to canonical request structure in ways that operators may misconfigure
- destination selection or host usage is derived from typed workload inputs and needs an explicit compatibility check
- a protocol-specific rollout needs a focused operator-facing validation artifact inside this package

## What a verifier must validate

Every workload-specific verifier must validate only the local assumptions that matter for eBPF compatibility:

- typed secret and typed runtime-auth constraint pairing fail closed on mismatch
- required transport and hook coverage are explicit
- exact host allowlist assumptions remain intact
- request-shape assumptions are named and validated narrowly
- no secret values are logged, returned, or persisted by the helper

If applicable, the verifier should also document:

- whether `connect4` and `connect6` are sufficient
- whether `sendmsg4` and `sendmsg6` are also required
- whether HTTP path/query/header shape affects socket-layer interception
- whether the check is compatibility-only or also guards operator rollout assumptions

## Design constraints

Keep verifier helpers narrow:

- one helper per workload or protocol scenario
- no dynamic plugin system
- no provider-string heuristics
- no hidden dependency from generic auth abstractions to workload-specific verifier logic

Do not use a verifier to replace core contract validation that belongs in:

- `@broker-interceptor/schemas`
- broker data-plane runtime auth translation
- policy engine or canonicalizer packages

## S3 backup example

The S3 backup verifier is appropriate because backup traffic uses both:

- bucket-root `GET /?list-type=2&prefix=...`
- object `GET` and `PUT`

The helper exists to show that these workload-specific request shapes remain compatible with HTTPS/TCP socket
interception. It does not make S3 verification mandatory for every future credential type, and it does not own SigV4
signing, region resolution, or secret persistence.
