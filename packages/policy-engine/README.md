# @broker-interceptor/policy-engine

Deterministic action-group classification and policy decision engine for broker execute requests.

This package is the Epic 3.3 / 3.4 core:

- Classifies canonical requests into template path groups.
- Evaluates `allow`, `deny`, `approval_required`, and `rate_limit` rules with deterministic precedence.
- Produces a stable decision object with reason codes and evaluation trace.

## Source of Truth

All DTOs and runtime contract parsing come from:

- `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/schemas`

Do not re-define policy/template/descriptor DTOs in this package.

## Exposed Interface

Public exports are defined in `/Users/dimitriskyriazopoulos/Development/ui/apps/broker-interceptor/packages/policy-engine/src/index.ts`:

- `classifyPathGroup(input)`
  - Input: `ClassifyPathGroupInput`
  - Output: `PathGroupClassificationResult`
  - Behavior: host + method + path-pattern classification, fail-closed with `no_matching_group` or `invalid_path_pattern`.
- `buildCanonicalDescriptorWithPathGroup(input)`
  - Input: descriptor (without `matched_path_group_id`) + template
  - Output: descriptor with resolved `matched_path_group_id` or classification failure.
- `evaluatePolicyDecision(input)`
  - Input: canonical descriptor, template, policy rules, optional rate limiter.
  - Output: `PolicyDecision` (`allowed | denied | approval_required | throttled`) with reason code and trace.
- `validatePolicyRule(input)`
  - Input: `OpenApiPolicyRule`
  - Output: normalized policy or stable validation error code.
  - Behavior: semantic validation + normalization for host/method/query keys and cross-field `rule_type`/`rate_limit` rules.
  - Security: host scope is exact-match only (wildcards rejected in MVP) and `constraints` must satisfy bounded shared schema contracts from `@broker-interceptor/schemas`.
- `derivePolicyFromApprovalDecision(input)`
  - Input: approval status/mode + canonical descriptor + policy id (+ optional constraints)
  - Output: derived policy rule or `null` for approved-once decisions.
  - Behavior: deterministic approval-to-policy derivation from canonical descriptor scope.
- `createPolicyEngineDbBridge(dependencies)`
  - Input: app-owned clients + repository adapters (no client initialization inside package)
  - Output: DB bridge scope for read/write/invalidation hooks.
  - Behavior: validates DTO boundaries, passes app transaction client through call options, and fails closed when dependency wiring is missing.
- `createPolicyEngineDbBridgeFromDbPackage(input)`
  - Input: app-owned clients plus db-package repository/adapter implementations.
  - Output: ready-to-use policy-engine bridge wired to `@broker-interceptor/db` repositories + Redis adapters.
  - Behavior: no internal client initialization; wiring only.
- Compatibility aliases:
  - Legacy `*_INCOMPLETE` bridge method names are still exported as compatibility wrappers during migration.

Contract exports:

- Decision and reason schemas/types (`DecisionSchema`, `DecisionReasonCodeSchema`, etc.).
- Input/output schemas and inferred types via `z.infer`.
- Rate-limit extension types (`RateLimiter`, `RateLimitCheckInput`, `RateLimitCheckResult`).

## Decision Precedence

Evaluation is deterministic and ordered:

1. `deny` (exact/scoped)
2. `allow` (exact/scoped)
3. `approval_required` rule
4. template approval mode (`required`)
5. default deny

If `allow` is selected and matching `rate_limit` rules exist:

- rate limit rejection => `throttled`
- limiter missing or errors => fail closed (`denied`)

## Usage

```ts
import {
  evaluatePolicyDecision,
  type EvaluatePolicyDecisionInput
} from '@broker-interceptor/policy-engine'

const decision = await evaluatePolicyDecision({
  descriptor,
  template,
  policies,
  rateLimiter: ({key, rule, now}) => {
    // integrate with redis/token-bucket implementation
    return {allowed: true}
  }
} satisfies EvaluatePolicyDecisionInput)

if (decision.decision === 'denied') {
  // map reason_code to API error/audit event
}
```

App-owned storage wiring with shared transaction pass-through:

```ts
import {createPolicyEngineDbBridge} from '@broker-interceptor/policy-engine'

const policyEngineDbBridge = createPolicyEngineDbBridge({
  clients: {
    postgres: processInfrastructure.prisma,
    redis: processInfrastructure.redis
  },
  repositories: {
    policyRuleStore,
    templateStore,
    rateLimitStore,
    auditStore,
    invalidationBus
  }
})

await processInfrastructure.withTransaction(async tx => {
  const policies = await policyEngineDbBridge.listPolicyRulesForDescriptorScope(
    {descriptor},
    {transaction_client: tx}
  )

  return policies
})
```

Direct wiring from `@broker-interceptor/db` implementations:

```ts
import {createPolicyEngineDbBridgeFromDbPackage} from '@broker-interceptor/policy-engine'

const policyEngineDbBridge = createPolicyEngineDbBridgeFromDbPackage({
  clients: {
    postgres: processInfrastructure.prisma,
    redis: processInfrastructure.redis
  },
  db: {
    policy_rule_repository,
    integration_repository,
    audit_event_repository,
    rate_limit_store,
    invalidation_bus
  }
})
```

Design rule:
- Package modules never initialize Postgres/Redis clients.
- Apps own process lifecycle and pass clients/repositories into package factories.
- Cross-package transaction sharing is handled by explicit `transaction_client` pass-through.

Classification-only flow:

```ts
import {classifyPathGroup} from '@broker-interceptor/policy-engine'

const classification = classifyPathGroup({
  template,
  method: descriptor.method,
  canonical_url: descriptor.canonical_url
})
```

## Quality Gate

Run before merging:

```bash
pnpm --filter @broker-interceptor/policy-engine run lint
pnpm --filter @broker-interceptor/policy-engine run test
pnpm --filter @broker-interceptor/policy-engine run test:coverage
pnpm --filter @broker-interceptor/policy-engine run build
```

Current target: coverage above 80%.

## Pending feedback

No open external feedback requests at this time (last liveness check: 2026-02-13).
