# @broker-interceptor/interceptor-ebpf

Linux eBPF interceptor contracts and validation package for strict separation of:

- dataplane packet verdict reason codes
- control-plane socket auth/authz error codes

This package is the contract layer used by an eBPF daemon/controller implementation. It provides stable reason-code
taxonomies, runtime validation, and log/control-protocol parsing to keep observability and security behavior
deterministic.

## What this package does

## 1) Stable reason-code namespaces

- `DataplaneVerdictReasonCode` in
  `brok/packages/interceptor-ebpf/src/contracts/reason-codes.ts`
- `ControlPlaneAuthzErrorCode` in
  `brok/packages/interceptor-ebpf/src/contracts/control-authz-codes.ts`

These enums are intentionally disjoint and enforced via:

- compile-time type guard
- runtime overlap assertion

Native mirror enums are also provided for C/libbpf integrations:

- `brok/packages/interceptor-ebpf/native/include/reason_codes.h`
- `brok/packages/interceptor-ebpf/native/include/control_authz_codes.h`

## 2) Strict boundary parsing (fail closed)

All untrusted payloads are parsed with `zod`:

- dataplane packet events
- control-plane authz events
- control protocol request/response payloads

Unknown or cross-namespace reason codes are rejected.

## 3) Explicit observability namespace

Serialized log records always include one explicit namespace:

- `code_namespace: "dataplane_verdict"`
- `code_namespace: "control_authz"`

This prevents ambiguity in downstream logging and alerting pipelines.

## Security contract

1. Control protocol errors may only use `ControlPlaneAuthzErrorCode`.
2. Dataplane packet events may only use `DataplaneVerdictReasonCode`.
3. Namespace overlap is a build-time and runtime failure.
4. Unknown reason codes are rejected at parse boundaries.

## Install and local usage

From repo root:

```bash
pnpm --filter @broker-interceptor/interceptor-ebpf install
pnpm --filter @broker-interceptor/interceptor-ebpf lint
pnpm --filter @broker-interceptor/interceptor-ebpf test
pnpm --filter @broker-interceptor/interceptor-ebpf build
```

TypeScript usage:

```ts
import {
  parseDataplanePacketEvent,
  parseControlPlaneAuthzEvent,
  parseControlProtocolResponse
} from '@broker-interceptor/interceptor-ebpf';

const dataplaneEvent = parseDataplanePacketEvent(inputFromRingBuffer);
const controlAuthzEvent = parseControlPlaneAuthzEvent(inputFromSocketAuthzPath);
const controlResponse = parseControlProtocolResponse(inputFromControlSocket);
```

## Docker setup (host-level eBPF agent pattern)

Use a privileged host agent container for eBPF program loading/attachment and a separate controller process that uses
this package for parsing/serialization.

Minimum runtime requirements:

- Linux host with eBPF support
- access to host cgroups (`/sys/fs/cgroup`)
- mounted BPF filesystem (`/sys/fs/bpf`)
- Unix control socket directory with restricted permissions

Example `docker-compose.yml` snippet:

```yaml
services:
  interceptor-ebpf-agent:
    image: ghcr.io/your-org/interceptor-ebpf-agent:latest
    container_name: interceptor-ebpf-agent
    network_mode: host
    pid: host
    privileged: true
    cap_add:
      - BPF
      - NET_ADMIN
      - SYS_ADMIN
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf
      - /sys/fs/cgroup:/sys/fs/cgroup:ro
      - /var/run/broker-interceptor-ebpf:/var/run/broker-interceptor-ebpf
    environment:
      - BROKER_EBPF_CONTROL_SOCKET=/var/run/broker-interceptor-ebpf/agentd.sock
      - BROKER_EBPF_SOCKET_MODE=0660
      - BROKER_EBPF_SOCKET_UID=0
      - BROKER_EBPF_SOCKET_GID=2000

  interceptor-ebpf-controller:
    image: ghcr.io/your-org/interceptor-ebpf-controller:latest
    network_mode: host
    volumes:
      - /var/run/broker-interceptor-ebpf:/var/run/broker-interceptor-ebpf
    environment:
      - BROKER_EBPF_CONTROL_SOCKET=/var/run/broker-interceptor-ebpf/agentd.sock
```

### Docker security notes

1. Use a dedicated host group for control-socket access (for example `broker-ebpfctl`).
2. Enforce socket ACLs (`0660`, owned by root + control group).
3. Validate peer credentials (`SO_PEERCRED`) in the daemon before accepting mutating commands.

## Docker test container for interceptor-node test service

This workspace includes a dedicated Dockerfile that runs
`/Users/dimitriskyriazopoulos/Development/brok/packages/interceptor-node/test-service/server.ts`
inside a container while reusing `@broker-interceptor/interceptor-node` package scripts.

Dockerfile:

- `/Users/dimitriskyriazopoulos/Development/brok/packages/interceptor-ebpf/docker/interceptor-node-test.Dockerfile`

Package scripts (in `@broker-interceptor/interceptor-ebpf`):

```bash
# Build image
pnpm --filter @broker-interceptor/interceptor-ebpf run docker:test-service:build

# Run container (maps localhost:3000 -> container:3000)
pnpm --filter @broker-interceptor/interceptor-ebpf run docker:test-service:run

# Build + run
pnpm --filter @broker-interceptor/interceptor-ebpf run docker:test-service
```

The container runs `pnpm test:service:intercepted` from `packages/interceptor-node` and uses the same default env
values as `@broker-interceptor/interceptor-node` `test:service:intercepted`.
For container startup resilience it also defaults `BROKER_FAIL_ON_MANIFEST_ERROR=false` (service stays up even if
broker bootstrap fails).

Health check:

```bash
curl http://localhost:3000/health
```

Equivalent explicit intercepted run in container:

```bash
docker run --rm -p 3000:3000 \
  -e BROKER_URL="${BROKER_URL:-https://localhost:8081}" \
  -e BROKER_WORKLOAD_ID="${BROKER_WORKLOAD_ID:-w_f73d1dc18e9c41bc89c5928d5bc67230}" \
  -e OPENAI_API_KEY="${OPENAI_API_KEY:-int_c7baa65e33244fb8b8bcd51a7072b57f}" \
  -e BROKER_MTLS_CERT_PATH="${BROKER_MTLS_CERT_PATH:-./test-service/certs/workload.crt}" \
  -e BROKER_MTLS_KEY_PATH="${BROKER_MTLS_KEY_PATH:-./test-service/certs/workload.key}" \
  -e BROKER_MTLS_CA_PATH="${BROKER_MTLS_CA_PATH:-./test-service/certs/ca-chain.pem}" \
  -e BROKER_LOG_LEVEL="${BROKER_LOG_LEVEL:-debug}" \
  -e BROKER_FAIL_ON_MANIFEST_ERROR="${BROKER_FAIL_ON_MANIFEST_ERROR:-false}" \
  interceptor-node-test:local \
  pnpm test:service:intercepted
```

Note: intercepted mode requires valid cert/key files to exist in the image or mounted volume.

## macOS one-command eBPF lab (nested Docker)

You can run a full local lab from macOS CLI:

1. Build a privileged Linux host image with eBPF tooling.
2. Start it as a Docker-in-Docker host (`dockerd` inside container).
3. Start a localhost broker tunnel inside the host container (`localhost:8081 -> host.docker.internal:8081`).
4. Build and run `packages/interceptor-node/test-service/server.ts` as a nested container.
5. Expose nested service health and API to your mac at `localhost`.

Files used:

- `/Users/dimitriskyriazopoulos/Development/brok/packages/interceptor-ebpf/docker/ebpf-host.Dockerfile`
- `/Users/dimitriskyriazopoulos/Development/brok/packages/interceptor-ebpf/docker/host-init.sh`
- `/Users/dimitriskyriazopoulos/Development/brok/packages/interceptor-ebpf/scripts/ebpf-lab-up.sh`
- `/Users/dimitriskyriazopoulos/Development/brok/packages/interceptor-ebpf/scripts/ebpf-lab-status.sh`
- `/Users/dimitriskyriazopoulos/Development/brok/packages/interceptor-ebpf/scripts/ebpf-lab-down.sh`

Run from repo root:

```bash
# Prerequisite: Docker Desktop is running and `docker info` succeeds.

# Start full lab (build host image + start nested test-service)
pnpm --filter @broker-interceptor/interceptor-ebpf run docker:ebpf-lab

# Check state
pnpm --filter @broker-interceptor/interceptor-ebpf run docker:ebpf-lab:status

# Stop and clean up
pnpm --filter @broker-interceptor/interceptor-ebpf run docker:ebpf-lab:down
```

After startup:

```bash
curl http://localhost:3000/health
```

Optional environment overrides:

- `EBPF_LAB_PORT` (default `3000`)
- `EBPF_LAB_HOST_IMAGE` (default `interceptor-ebpf-host:local`)
- `EBPF_LAB_HOST_CONTAINER` (default `interceptor-ebpf-host-lab`)
- `EBPF_LAB_NESTED_IMAGE` (default `interceptor-node-test:nested`)
- `EBPF_LAB_NESTED_CONTAINER` (default `nested-interceptor-node-test-service`)
- `EBPF_LAB_BROKER_TUNNEL_PORT` (default `8081`)
- `EBPF_LAB_REQUIRE_HOST_PORT` (default `false`, set `true` to fail if `localhost:${EBPF_LAB_PORT}` is not reachable)
- `BROKER_URL` (default `https://localhost:8081`)
- `BROKER_WORKLOAD_ID` (default `w_f73d1dc18e9c41bc89c5928d5bc67230`)
- `OPENAI_API_KEY` (default `int_c7baa65e33244fb8b8bcd51a7072b57f`)
- `BROKER_MTLS_CERT_PATH` (default `./test-service/certs/workload.crt`)
- `BROKER_MTLS_KEY_PATH` (default `./test-service/certs/workload.key`)
- `BROKER_MTLS_CA_PATH` (default `./test-service/certs/ca-chain.pem`)
- `BROKER_LOG_LEVEL` (default `debug`)
- `BROKER_FAIL_ON_MANIFEST_ERROR` (default `false`)

Important: on macOS, eBPF executes in Docker Desktop's Linux VM kernel, not in the Darwin host kernel.
The nested service runs with `--network host` (inside the eBPF host container namespace) so `BROKER_URL=https://localhost:8081`
matches the broker certificate hostname while still reaching outer `broker-api` through the tunnel.

## Kubernetes setup (DaemonSet host-agent pattern)

Recommended pattern:

1. Run the eBPF agent as a `DaemonSet` on every node.
2. Keep control socket in a `hostPath` directory.
3. Run controller workload with least privilege and access only to the control socket.

Example `DaemonSet` (abbreviated):

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: interceptor-ebpf-agent
  namespace: broker-system
spec:
  selector:
    matchLabels:
      app: interceptor-ebpf-agent
  template:
    metadata:
      labels:
        app: interceptor-ebpf-agent
    spec:
      hostPID: true
      containers:
        - name: agent
          image: ghcr.io/your-org/interceptor-ebpf-agent:latest
          securityContext:
            privileged: true
            capabilities:
              add: ["BPF", "NET_ADMIN", "SYS_ADMIN"]
          volumeMounts:
            - name: bpffs
              mountPath: /sys/fs/bpf
            - name: cgroupfs
              mountPath: /sys/fs/cgroup
              readOnly: true
            - name: control-socket
              mountPath: /var/run/broker-interceptor-ebpf
      volumes:
        - name: bpffs
          hostPath:
            path: /sys/fs/bpf
            type: Directory
        - name: cgroupfs
          hostPath:
            path: /sys/fs/cgroup
            type: Directory
        - name: control-socket
          hostPath:
            path: /var/run/broker-interceptor-ebpf
            type: DirectoryOrCreate
```

### Kubernetes security notes

1. Restrict DaemonSet scheduling using node selectors/taints if needed.
2. Lock down RBAC for any controller that can issue mutating control-socket commands.
3. Keep control socket group ownership aligned with the controller pod identity.

## Reason-code taxonomy

Dataplane:

- `UNMANAGED_ALLOW`
- `OBSERVE_WOULD_ALLOW`
- `OBSERVE_WOULD_DENY_EXPLICIT`
- `OBSERVE_WOULD_DENY_DEFAULT`
- `ALLOW_EXPLICIT`
- `ALLOW_BROKER`
- `ALLOW_DNS`
- `DENY_EXPLICIT`
- `DENY_DEFAULT`
- `DENY_DEGRADED_FAIL_CLOSED`
- `ALLOW_DEGRADED_FAIL_OPEN`

Control-plane auth/authz:

- `CTRL_AUTH_PEERCRED_UNAVAILABLE`
- `CTRL_AUTH_PEERCRED_REJECTED_UID`
- `CTRL_AUTH_PEERCRED_REJECTED_GID`
- `CTRL_AUTH_SOCKET_MODE_INVALID`
- `CTRL_AUTH_SOCKET_OWNER_INVALID`

## Notes on current scope

This package is a contracts/validation layer. It does not itself load eBPF programs or run a daemon process. It is
designed to be consumed by those runtime components while preserving strict interface safety.
