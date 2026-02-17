# Process-level interception (no MITM, no root)

This document explores interception strategies that work at the process level, before TLS encryption, without requiring
root access or CA injection.

## Why this matters

The MITM approach requires:

- Root access for firewall rules
- Custom CA injected into trust stores
- Breaking certificate pinning
- High trust from operators

Process-level interception can achieve similar goals with:

- No root required (just environment variables or CLI flags)
- No custom CA (we intercept before TLS, not after)
- Works with certificate pinning (we don't touch the TLS layer)
- Lower trust requirements

---

## Strategy 1: Node.js module interception (--require / --import)

Node allows preloading modules before any user code runs. We can patch the `http`, `https`, `net`, and `tls` modules at
the earliest possible point.

### How it works

```text
┌────────────────────────────────────────────────────────────────┐
│  Node.js Process                                                │
│                                                                │
│  1. Node starts with --require broker-interceptor/preload      │
│  2. Preload patches http.request, https.request, fetch, etc.  │
│  3. User code runs (AI agent, tools, etc.)                     │
│  4. All HTTP/HTTPS calls go through our patched functions      │
│  5. We see plaintext request BEFORE TLS wrapping               │
│  6. We can rewrite, block, or forward to Broker                │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Implementation

```ts
// packages/interceptor-node/src/preload.ts
// This file is loaded via: node --require @broker-interceptor/interceptor-node/preload

import http from 'node:http';
import https from 'node:https';
import {URL} from 'node:url';

// Store original implementations
const originalHttpRequest = http.request;
const originalHttpsRequest = https.request;

// Manifest and config loaded from env or file
const manifest = loadManifestFromEnv();
const brokerUrl = process.env.BROKER_URL;
const sessionToken = process.env.BROKER_SESSION_TOKEN;

function shouldIntercept(url: URL): boolean {
  return manifest.match_rules.some(
    rule =>
      rule.match.hosts.includes(url.hostname) &&
      rule.match.schemes.includes(url.protocol.replace(':', '')) &&
      rule.match.ports.includes(url.port ? parseInt(url.port) : url.protocol === 'https:' ? 443 : 80)
  );
}

async function forwardToBroker(options: http.RequestOptions, body: Buffer): Promise<http.IncomingMessage> {
  // Build execute request
  const executePayload = {
    integration_id: findIntegrationId(options),
    request: {
      method: options.method || 'GET',
      url: `https://${options.hostname}${options.path}`,
      headers: Object.entries(options.headers || {}).map(([name, value]) => ({name, value: String(value)})),
      body_base64: body.length > 0 ? body.toString('base64') : undefined
    }
  };

  // Call broker
  const brokerResponse = await callBroker(executePayload);

  // Return response as if it came from original host
  return wrapBrokerResponse(brokerResponse);
}

// Patch https.request
https.request = function (url, options, callback) {
  const parsedUrl = typeof url === 'string' ? new URL(url) : url instanceof URL ? url : null;
  const opts = typeof options === 'function' ? {} : options;
  const cb = typeof options === 'function' ? options : callback;

  const targetUrl = parsedUrl || new URL(`https://${opts.hostname || opts.host}${opts.path || '/'}`);

  if (shouldIntercept(targetUrl)) {
    // Return a fake ClientRequest that buffers the body and forwards to broker
    return createInterceptedRequest(targetUrl, opts, cb);
  }

  // Not intercepted, pass through
  return originalHttpsRequest.call(this, url, options, callback);
};

// Similar patch for http.request, fetch, etc.
```

### Usage

```bash
# Option 1: --require flag
node --require @broker-interceptor/interceptor-node/preload app.js

# Option 2: NODE_OPTIONS env var (works even if you don't control the node command)
export NODE_OPTIONS="--require @broker-interceptor/interceptor-node/preload"
node app.js

# Option 3: ESM loader (for ES modules)
node --import @broker-interceptor/interceptor-node/preload.mjs app.js
```

### Pros

- No root required
- No CA injection
- Works with cert pinning (we don't touch TLS at all for broker calls)
- Child Node processes inherit NODE_OPTIONS

### Cons

- Only works for Node.js
- Native addons that call libssl directly bypass this
- Child processes in other languages (Python, curl) are not intercepted

---

## Strategy 2: LD_PRELOAD (Linux, works for any language)

On Linux, we can intercept libc functions like `connect()` and `send()` before they reach the kernel. This works for any
language/runtime that uses libc.

### How it works

```text
┌────────────────────────────────────────────────────────────────┐
│  Any Process (Node, Python, curl, etc.)                        │
│                                                                │
│  1. Process starts with LD_PRELOAD=libbroker-intercept.so     │
│  2. Our library overrides connect(), send(), recv()           │
│  3. When connect() targets a protected host:port              │
│     - We connect to local broker proxy instead                │
│     - We track the mapping                                     │
│  4. When send() is called on that socket:                     │
│     - We wrap the data in execute format                       │
│     - We forward to broker                                     │
│  5. recv() returns the broker's response                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Implementation (C shared library)

```c
// packages/interceptor-native/src/libbroker-intercept.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

// Original function pointers
static int (*original_connect)(int, const struct sockaddr*, socklen_t) = NULL;
static ssize_t (*original_send)(int, const void*, size_t, int) = NULL;

// Protected hosts (loaded from env/file at startup)
static char** protected_hosts = NULL;
static int protected_host_count = 0;

// Socket tracking
typedef struct {
    int fd;
    int is_intercepted;
    char original_host[256];
    int original_port;
} socket_state;

static socket_state sockets[1024] = {0};

__attribute__((constructor))
void init() {
    original_connect = dlsym(RTLD_NEXT, "connect");
    original_send = dlsym(RTLD_NEXT, "send");
    load_protected_hosts_from_env();
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in*)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr_in->sin_addr, ip, INET_ADDRSTRLEN);
        int port = ntohs(addr_in->sin_port);

        if (is_protected_host(ip, port)) {
            // Redirect to local broker proxy
            struct sockaddr_in broker_addr;
            broker_addr.sin_family = AF_INET;
            broker_addr.sin_port = htons(BROKER_PROXY_PORT);
            inet_pton(AF_INET, "127.0.0.1", &broker_addr.sin_addr);

            // Track this socket
            sockets[sockfd].fd = sockfd;
            sockets[sockfd].is_intercepted = 1;
            strncpy(sockets[sockfd].original_host, ip, 255);
            sockets[sockfd].original_port = port;

            return original_connect(sockfd, (struct sockaddr*)&broker_addr, sizeof(broker_addr));
        }
    }

    return original_connect(sockfd, addr, addrlen);
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    if (sockets[sockfd].is_intercepted) {
        // Wrap in broker protocol and send
        return send_to_broker(sockfd, buf, len, &sockets[sockfd]);
    }
    return original_send(sockfd, buf, len, flags);
}
```

### Usage

```bash
# Compile shared library
gcc -shared -fPIC -o libbroker-intercept.so libbroker-intercept.c -ldl

# Run any process with interception
LD_PRELOAD=/path/to/libbroker-intercept.so node app.js
LD_PRELOAD=/path/to/libbroker-intercept.so python agent.py
LD_PRELOAD=/path/to/libbroker-intercept.so curl https://api.openai.com/v1/chat

# Child processes inherit LD_PRELOAD automatically
```

### Pros

- Works for any language/runtime on Linux
- No root required
- Child processes inherit automatically
- Intercepts before TLS (we see plaintext at application layer)

### Cons

- Linux only (macOS has DYLD_INSERT_LIBRARIES but it's restricted)
- Statically linked binaries bypass this
- Go binaries often bypass libc for network calls
- Complex to implement correctly

---

## Strategy 3: eBPF socket interception (Linux, more robust)

eBPF allows attaching programs to kernel events. We can intercept socket operations at the kernel level, scoped to
specific processes or cgroups.

### How it works

```text
┌────────────────────────────────────────────────────────────────┐
│  Kernel                                                         │
│                                                                │
│  eBPF program attached to:                                     │
│  - sock_ops (socket operations)                                │
│  - cgroup/connect4 (connect calls)                             │
│                                                                │
│  When connect() targets protected host:                        │
│  → Redirect to local broker proxy socket                       │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

### Implementation sketch

```c
// eBPF program (loaded via libbpf or bpftrace)
SEC("cgroup/connect4")
int broker_connect4(struct bpf_sock_addr *ctx) {
    __u32 dst_ip = ctx->user_ip4;
    __u16 dst_port = ctx->user_port;

    // Check if this IP:port is protected
    if (is_protected(dst_ip, dst_port)) {
        // Redirect to local broker proxy
        ctx->user_ip4 = BROKER_PROXY_IP;
        ctx->user_port = htons(BROKER_PROXY_PORT);
    }

    return 1; // Allow connection
}
```

### Pros

- Works for any language, including Go and statically linked binaries
- Can be scoped to cgroups (containers)
- Very low overhead
- Kernel-level, no userspace bypass possible

### Cons

- Requires CAP_BPF or root to load eBPF programs
- Linux 4.10+ only
- More complex to develop and debug

---

## Strategy 4: Process tree tracking for child processes

For spawned subprocesses, we need to ensure they also get intercepted.

### Option A: Inherit environment variables

```ts
// When spawning child processes, ensure they inherit interception env vars
import {spawn} from 'node:child_process';

const child = spawn('python', ['tool.py'], {
  env: {
    ...process.env,
    // Node preload
    NODE_OPTIONS: '--require @broker-interceptor/interceptor-node/preload',
    // LD_PRELOAD for native code
    LD_PRELOAD: '/path/to/libbroker-intercept.so',
    // Broker config
    BROKER_URL: process.env.BROKER_URL,
    BROKER_SESSION_TOKEN: process.env.BROKER_SESSION_TOKEN,
    BROKER_MANIFEST_PATH: process.env.BROKER_MANIFEST_PATH
  }
});
```

### Option B: Patch child_process module

```ts
// packages/interceptor-node/src/preload.ts
import child_process from 'node:child_process';

const originalSpawn = child_process.spawn;
const originalExec = child_process.exec;
const originalFork = child_process.fork;

child_process.spawn = function (command, args, options) {
  const interceptedOptions = {
    ...options,
    env: {
      ...process.env,
      ...options?.env,
      LD_PRELOAD: getInterceptorLibPath(),
      NODE_OPTIONS: getNodePreloadOptions()
    }
  };
  return originalSpawn.call(this, command, args, interceptedOptions);
};

// Similar for exec, fork, execFile
```

### Option C: cgroup-based (containers)

In Kubernetes, use a sidecar or init container to set up interception for the entire pod's cgroup:

```yaml
apiVersion: v1
kind: Pod
spec:
  initContainers:
    - name: broker-interceptor-init
      image: broker-interceptor:latest
      command: ['/setup-interception.sh']
      securityContext:
        capabilities:
          add: ['NET_ADMIN', 'BPF'] # Only for eBPF approach
```

---

## Comparison of approaches

| Approach              | Root needed | Languages     | Child processes       | Bypass difficulty        |
| --------------------- | ----------- | ------------- | --------------------- | ------------------------ |
| Node --require        | No          | Node only     | Inherits NODE_OPTIONS | Medium (native addons)   |
| LD_PRELOAD            | No          | Most (not Go) | Inherits env var      | Medium (static binaries) |
| eBPF                  | CAP_BPF     | All           | Automatic (cgroup)    | Hard                     |
| MITM proxy + iptables | Yes         | All           | Automatic             | Hard                     |

---

## Recommended hybrid approach

For Node workloads with possible tool spawning:

```ts
// packages/interceptor-node/src/index.ts

export async function initBrokerInterceptor(config: InterceptorConfig) {
  // 1. Load and verify manifest
  const manifest = await fetchAndVerifyManifest(config);

  // 2. Patch Node modules (http, https, fetch, child_process)
  patchNodeModules(manifest, config);

  // 3. Set up environment for child processes
  setupChildProcessEnvironment(config);

  // 4. If on Linux and LD_PRELOAD library is available, set it up
  if (process.platform === 'linux' && hasNativeInterceptor()) {
    process.env.LD_PRELOAD = getNativeInterceptorPath();
  }

  // 5. Schedule manifest refresh
  scheduleManifestRefresh(manifest, config);

  return {
    manifest,
    refresh: () => fetchAndVerifyManifest(config)
  };
}
```

### Preload entry point

```ts
// packages/interceptor-node/src/preload.ts
// Loaded via NODE_OPTIONS="--require @broker-interceptor/interceptor-node/preload"

import {initBrokerInterceptor} from './index.js';

const config = {
  brokerUrl: process.env.BROKER_URL!,
  manifestPath: process.env.BROKER_MANIFEST_PATH,
  sessionTokenProvider: () => process.env.BROKER_SESSION_TOKEN!,
  mtlsCertPath: process.env.BROKER_MTLS_CERT_PATH,
  mtlsKeyPath: process.env.BROKER_MTLS_KEY_PATH,
  mtlsCaPath: process.env.BROKER_MTLS_CA_PATH
};

// Initialize synchronously at module load time
initBrokerInterceptor(config).catch(err => {
  console.error('[broker-interceptor] Failed to initialize:', err);
  process.exit(1);
});
```

---

## What this doesn't solve

1. **Native code calling OpenSSL directly**: If a native addon calls `SSL_connect()` directly without going through
   Node's `tls` module, this bypasses the Node patches. LD_PRELOAD can catch these on Linux.

2. **Go binaries**: Go has its own network stack that doesn't use libc. Only eBPF or network-level interception catches
   these.

3. **Statically linked binaries**: LD_PRELOAD doesn't work. Only eBPF or network-level interception works.

4. **Malicious code actively evading**: If code specifically tries to detect and bypass interception (checking
   LD_PRELOAD, using raw syscalls), only eBPF provides strong guarantees.

---

## Trust model comparison

| Approach        | What you trust          | What operator trusts        |
| --------------- | ----------------------- | --------------------------- |
| MITM + firewall | Root on host, custom CA | Broker controls all HTTPS   |
| Node preload    | Node runtime            | Only Node calls intercepted |
| LD_PRELOAD      | libc-based calls        | Most calls intercepted      |
| eBPF            | Kernel                  | All calls intercepted       |

The Node preload approach has a much lighter trust requirement: you're just requiring a module before your code runs.
It's similar to how many APM tools (DataDog, New Relic) work.

---

## Next steps

1. Implement Node module patching (http, https, undici, child_process)
2. Test with common AI frameworks (LangChain, OpenAI SDK, etc.)
3. Prototype LD_PRELOAD library for cross-language support
4. Evaluate eBPF for production container deployments
