## Issue 1:
Found the issue: admin‑api writes templates under the global tenant, but broker‑api only looks for templates under the
workload’s tenant. That makes the manifest builder see zero templates and throw manifest_no_rules.

Evidence in code:

Admin‑api stores templates under GLOBAL_TEMPLATE_TENANT_ID = 'global': repository.ts:180 repository.ts:1608-1649

Broker‑api builds manifest rules from tenant‑scoped templates only: repository.ts:2558-2603

The DB shows your template versions exist, but tenant_id = global, so the tenant‑scoped query returns nothing.

Why you see integrations but no rules: integrations are stored under your tenant, but templates are stored under global,
and broker‑api doesn’t load global templates.

Fix options Update broker‑api to include global templates when building manifest rules (recommended). Change admin‑api
to store templates per tenant instead of global (bigger change). If you want me to implement the broker‑api change, I
can. It should be a small change in repository.ts:2558-2603 to load templates for both {tenantId} and global.

Bottom line: Ability to use global and per-tenant custom templates

## Issue 2:
 Error thrown

```
[Nest] 1  - 02/17/2026, 1:02:31 AM     LOG [NestApplication] Nest application successfully started +2ms
[9e183c3e-9848-4b12-bed1-611b8547c1a2] Unexpected internal error: Error: Unable to rotate manifest signing keys: rotateManifestSigningKeysWithStore: Unique constraint violated; additionally failed to release rotation lock: releaseCryptoRotationLock: "arguments[3]" must be of type "string | Buffer", got function instead.
    at DataPlaneRepository.rotateManifestSigningPrivateKeyShared (file:///app/dist/repository.js:483:23)
    at async BrokerApiController.handleRequest [as requestHandler] (file:///app/dist/server.js:1155:38)
    at async BrokerApiController.handle (file:///app/dist/nest/brokerApiNestModule.js:23:9)
    at async /app/node_modules/.pnpm/@nestjs+core@11.1.13_@nestjs+common@11.1.13_reflect-metadata@0.2.2_rxjs@7.8.2__@nestjs+platfo_wc5csu2smgbknvnoiud7blcgb4/node_modules/@nestjs/core/router/router-execution-context.js:46:28
    at async /app/node_modules/.pnpm/@nestjs+core@11.1.13_@nestjs+common@11.1.13_reflect-metadata@0.2.2_rxjs@7.8.2__@nestjs+platfo_wc5csu2smgbknvnoiud7blcgb4/node_modules/@nestjs/core/router/router-proxy.js:9:17
```

## Issue 3: 
Observability. No logs, nothing to identify failures. An error usually carries `correlation_id` yet there are no
logs to correlate whatsoever.

```
'{"status":500,"body":"{\\"error\\":\\"internal_error\\",\\"message\\":\\"Unexpected internal error\\",\\"correlation_id\\":\\"e313cd75-b702-432b-bd02-e35802e81647\\"}"}'
```

## Issue 4:
Pathgroup id returned in manifest instead of the regexp In the screenshot there is the template I configured.

Here is the actual manifest response I am getting for this template:

```
{"status":200,"body":"{\\"manifest_version\\":1,\\"issued_at\\":\\"2026-02-17T10:55:45.331Z\\",\\"expires_at\\":\\"2026-02-17T11:00:45.331Z\\",\\"broker_execute_url\\":\\"https://localhost:8081/v1/execute\\",\\"dpop_required\\":false,\\"dpop_ath_required\\":false,\\"match_rules\\":[{\\"integration_id\\":\\"int_6dc7ecd8def449bd87cb1354bbdc1ab3\\",\\"provider\\":\\"openai\\",\\"match\\":{\\"hosts\\":[\\"api.openai.com\\"],\\"schemes\\":[\\"https\\"],\\"ports\\":[443],\\"path_groups\\":[\\"responses_create\\"]},\\"rewrite\\":{\\"mode\\":\\"execute\\",\\"send_intended_url\\":true}}],\\"signature\\":{\\"alg\\":\\"EdDSA\\",\\"kid\\":\\"manifest_4b5df09e-d3b8-4bd4-a9bc-f13ea3e77062\\"}}
```

Seems like this is the request i am performing and is not matching

```
curl -X POST http://localhost:3000/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello, what is 2+2?"}'
```

Two issues: broker-api sends group_id instead of path_patterns interceptor-node matcher only supports globs, not regex
(like ^/v1/chat/completions$)


## Issue 5:
 There is no nest service here nor in broker-api. The route paths are matched with regexp and the logic applied per regexp match + Method. This needs to be rewritten using nest + express conventions