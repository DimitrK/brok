# OS-level interception (RFC)

This document explores how the interceptor could use OS-level firewall rules and transparent proxying to guarantee
interception even when:

- AI agents are prompt-injected to bypass SDK wrappers
- Tools spawn child processes without the SDK loaded
- Arbitrary code runs without explicit broker-aware HTTP calls

## The bypass problem

Application-level interception (SDK wrappers, base URL override) can be bypassed by:

1. **Prompt injection**: Agent is convinced to call `fetch('https://api.openai.com')` directly instead of using the
   wrapper
2. **Spawned processes**: A tool runs `curl https://api.openai.com` or spawns a Python subprocess that makes HTTP calls
3. **Native extensions**: A native module makes syscalls directly without going through Node's HTTP stack
4. **Malicious code**: Injected code intentionally avoids the SDK

The only way to guarantee interception is to enforce at the OS or network layer.

---

## Approach: transparent proxy + firewall redirect

### Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│ Workload host/container                                         │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────────────────────────┐   │
│  │  AI Agent    │───▶│  OS Firewall (iptables/pf)           │   │
│  │  (any proc)  │    │  - Redirect HTTPS to local proxy     │   │
│  └──────────────┘    │  - Block direct egress to protected  │   │
│                      │    hosts                              │   │
│         │            └──────────────┬───────────────────────┘   │
│         │                           │                           │
│         ▼                           ▼                           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Broker Proxy (local)                                     │   │
│  │  - Terminates TLS (MITM with injected CA)                │   │
│  │  - Matches against manifest                              │   │
│  │  - Rewrites to Broker /v1/execute                        │   │
│  │  - Calls Broker with mTLS + session token                │   │
│  │  - Returns response as if from original host             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                      │                                          │
└──────────────────────┼──────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  Broker Data Plane                                               │
│  - Receives execute request                                      │
│  - Injects real API credentials                                  │
│  - Forwards to OpenAI/Gmail/etc                                  │
│  - Returns response                                              │
└──────────────────────────────────────────────────────────────────┘
```

### How it works

1. **Firewall redirects all HTTPS (port 443) to local proxy**
   - Linux: `iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443`
   - macOS: `pf` rules with `rdr-anchor`

2. **Local proxy terminates TLS**
   - Proxy has a CA certificate injected into the system trust store
   - Proxy generates on-the-fly certs signed by this CA for each destination
   - Application thinks it's talking to real host

3. **Proxy checks manifest**
   - If destination matches manifest rule → rewrite to Broker `/v1/execute`
   - If destination not in manifest → pass through or block (configurable)

4. **Proxy calls Broker with mTLS**
   - Wraps original request in execute format
   - Adds session token
   - Sends over mTLS to Broker

5. **Broker executes and returns**
   - Broker injects real credentials
   - Forwards to upstream
   - Returns response

6. **Proxy returns response to app**
   - Unwraps execute response
   - Returns to app as if it came from real host

---

## Firewall configuration by OS

### Linux (iptables)

```bash
# Redirect all HTTPS to local proxy (port 8443)
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443

# Alternative: only redirect specific hosts (requires ipset or DNS resolution)
ipset create protected_hosts hash:ip
ipset add protected_hosts $(dig +short api.openai.com)
iptables -t nat -A OUTPUT -p tcp --dport 443 -m set --match-set protected_hosts dst -j REDIRECT --to-port 8443

# Allow the proxy process to bypass (by owner)
iptables -t nat -I OUTPUT -p tcp --dport 443 -m owner --uid-owner broker-proxy -j ACCEPT
```

### Linux (nftables, modern)

```bash
nft add table nat
nft add chain nat output { type nat hook output priority -100 \; }
nft add rule nat output tcp dport 443 redirect to :8443
```

### macOS (pf)

```text
# /etc/pf.anchors/broker-proxy
rdr pass on lo0 proto tcp from any to any port 443 -> 127.0.0.1 port 8443

# Enable with:
# pfctl -a broker-proxy -f /etc/pf.anchors/broker-proxy
# pfctl -e
```

### Windows (netsh + WFP)

```powershell
# Windows requires a WFP (Windows Filtering Platform) driver or netsh portproxy
netsh interface portproxy add v4tov4 listenport=443 listenaddress=0.0.0.0 connectport=8443 connectaddress=127.0.0.1
```

---

## Transparent proxy implementation options

### Option A: mitmproxy (Python, scriptable)

```python
# mitmproxy addon for broker rewrite
from mitmproxy import http, ctx

class BrokerRewriter:
    def __init__(self):
        self.manifest = load_manifest()
        self.session_token = get_session_token()

    def request(self, flow: http.HTTPFlow):
        if self.matches_manifest(flow.request.host):
            # Rewrite to broker execute
            flow.request.host = "broker.example.com"
            flow.request.port = 443
            flow.request.path = "/v1/execute"
            flow.request.method = "POST"
            flow.request.content = self.wrap_execute_request(flow)

# Run with:
# mitmproxy -s broker_rewriter.py --mode transparent --listen-port 8443
```

**Pros**: Battle-tested, scriptable, handles TLS well **Cons**: Python dependency, heavier weight

### Option B: Custom Node proxy (lighter, native to interceptor-node)

```ts
// packages/interceptor-node/src/transparentProxy.ts
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import {createSecureContext} from 'node:tls';

export function startTransparentProxy(config: {
  port: number;
  caCert: Buffer;
  caKey: Buffer;
  manifest: Manifest;
  brokerUrl: string;
  sessionTokenProvider: () => Promise<string>;
  mtlsAgent: https.Agent;
}) {
  const server = https.createServer(
    {
      SNICallback: (servername, cb) => {
        // Generate cert for servername on the fly
        const cert = generateCertForHost(servername, config.caCert, config.caKey);
        cb(null, createSecureContext({key: cert.key, cert: cert.cert}));
      }
    },
    async (req, res) => {
      const originalHost = req.headers.host;

      if (matchesManifest(originalHost, config.manifest)) {
        // Rewrite to broker execute
        await forwardToBroker(req, res, config);
      } else {
        // Pass through directly
        await passThrough(req, res, originalHost);
      }
    }
  );

  server.listen(config.port);
}
```

**Pros**: Native to Node, single runtime, lighter **Cons**: More code to maintain, need to handle edge cases

### Option C: Envoy/HAProxy sidecar

Run a dedicated proxy container/process that handles all egress.

**Pros**: Production-grade, well-tested **Cons**: Another process to manage, configuration complexity

---

## CA injection for TLS interception

For transparent proxying of HTTPS to work, the proxy must MITM the TLS connection. This requires:

1. **Generate a CA certificate** (one-time, at interceptor setup)
2. **Inject CA into system trust store** (varies by OS)
3. **Inject CA into Node's trust store** (via `NODE_EXTRA_CA_CERTS` or runtime config)

### Linux (system trust)

```bash
cp broker-ca.crt /usr/local/share/ca-certificates/broker-ca.crt
update-ca-certificates
```

### macOS

```bash
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain broker-ca.crt
```

### Node.js specific

```bash
export NODE_EXTRA_CA_CERTS=/path/to/broker-ca.crt
```

Or programmatically:

```js
import tls from 'node:tls';

const originalCreateSecureContext = tls.createSecureContext;
tls.createSecureContext = function (options) {
  const context = originalCreateSecureContext.call(this, options);
  context.context.addCACert(brokerCaCert);
  return context;
};
```

---

## Dynamic firewall configuration from manifest

The interceptor can read the manifest and configure firewall rules dynamically:

```ts
// packages/interceptor-node/src/firewall.ts
import {execSync} from 'node:child_process';
import os from 'node:os';

export async function configureFirewallFromManifest(manifest: Manifest, proxyPort: number) {
  const protectedHosts = manifest.match_rules.flatMap(rule => rule.match.hosts);

  // Resolve hosts to IPs
  const protectedIps = await Promise.all(protectedHosts.map(host => resolveHostToIps(host))).then(results =>
    results.flat()
  );

  const platform = os.platform();

  if (platform === 'linux') {
    configureIptables(protectedIps, proxyPort);
  } else if (platform === 'darwin') {
    configurePf(protectedIps, proxyPort);
  } else if (platform === 'win32') {
    configureWindowsFirewall(protectedIps, proxyPort);
  }
}

function configureIptables(ips: string[], proxyPort: number) {
  // Clear existing rules
  execSync('iptables -t nat -F BROKER_INTERCEPT 2>/dev/null || true');
  execSync('iptables -t nat -N BROKER_INTERCEPT 2>/dev/null || true');

  // Add redirect rules for protected IPs
  for (const ip of ips) {
    execSync(`iptables -t nat -A BROKER_INTERCEPT -p tcp -d ${ip} --dport 443 -j REDIRECT --to-port ${proxyPort}`);
  }

  // Hook into OUTPUT chain
  execSync('iptables -t nat -A OUTPUT -j BROKER_INTERCEPT');

  // Allow proxy process to bypass (requires knowing proxy PID or running as specific user)
  execSync(`iptables -t nat -I OUTPUT -p tcp --dport 443 -m owner --uid-owner $(id -u) -j ACCEPT`);
}
```

---

## Preventing the proxy itself from being intercepted (loop prevention)

The proxy needs to make outbound HTTPS calls to the Broker. These must not be redirected back to itself.

### Solution 1: UID-based bypass

Run the proxy as a specific user and exempt that user from firewall rules:

```bash
# Create broker-proxy user
useradd -r broker-proxy

# Bypass rule for that user
iptables -t nat -I OUTPUT -m owner --uid-owner broker-proxy -j ACCEPT
```

### Solution 2: Mark packets

Use iptables marks to identify proxy-originated packets:

```bash
# Proxy sets SO_MARK on its sockets
# Bypass rule for marked packets
iptables -t nat -I OUTPUT -m mark --mark 0x1 -j ACCEPT
```

### Solution 3: Destination-based (allow Broker IP)

```bash
BROKER_IP=$(dig +short broker.example.com)
iptables -t nat -I OUTPUT -p tcp -d $BROKER_IP --dport 443 -j ACCEPT
```

---

## Trade-offs and considerations

| Aspect        | Application-level       | OS-level transparent proxy   |
| ------------- | ----------------------- | ---------------------------- |
| Coverage      | Explicit calls only     | All processes, all calls     |
| Bypass risk   | High (prompt injection) | Low (requires root escape)   |
| Complexity    | Low                     | High (firewall, CA, proxy)   |
| TLS handling  | Native                  | MITM required                |
| Performance   | Direct                  | Extra hop through proxy      |
| Debugging     | Easy                    | Harder (opaque interception) |
| Portability   | Cross-platform          | OS-specific rules            |
| Root required | No                      | Yes (firewall config)        |

---

## Recommended architecture for high-security workloads

```text
┌─────────────────────────────────────────────────────────────────┐
│  Container / VM / Pod                                            │
│                                                                 │
│  1. interceptor-node starts transparent proxy on :8443          │
│  2. interceptor-node configures iptables to redirect 443→8443   │
│  3. interceptor-node injects CA into system trust              │
│  4. AI agent runs, makes HTTP calls normally                    │
│  5. All HTTPS to protected hosts goes through proxy            │
│  6. Proxy rewrites to Broker, returns response                  │
│                                                                 │
│  Defense in depth: k8s NetworkPolicy also blocks direct egress  │
└─────────────────────────────────────────────────────────────────┘
```

### Startup sequence

```ts
// packages/interceptor-node/src/index.ts

export async function initBrokerInterceptor(config: InterceptorConfig) {
  // 1. Fetch and verify manifest
  const manifest = await fetchAndVerifyManifest(config);

  // 2. Generate or load CA for MITM
  const ca = await loadOrGenerateCA(config.caPath);

  // 3. Inject CA into system trust
  await injectCaIntoTrustStore(ca.cert);

  // 4. Start transparent proxy
  const proxy = await startTransparentProxy({
    port: 8443,
    caCert: ca.cert,
    caKey: ca.key,
    manifest,
    brokerUrl: config.brokerUrl,
    sessionTokenProvider: config.sessionTokenProvider,
    mtlsAgent: config.mtlsAgent
  });

  // 5. Configure firewall rules
  await configureFirewallFromManifest(manifest, 8443);

  // 6. Schedule manifest refresh
  scheduleManifestRefresh(config, proxy);

  return {
    stop: async () => {
      await removeFirewallRules();
      proxy.close();
    }
  };
}
```

---

## Open questions

1. **Root/admin privileges**: Firewall config requires root. Is the interceptor expected to run as root, or should there
   be a separate privileged helper?

2. **Container vs VM vs bare metal**: In Kubernetes, NetworkPolicy + a sidecar proxy might be cleaner than iptables
   inside the container.

3. **Manifest refresh and firewall updates**: When manifest changes (new hosts added), firewall rules need updating. How
   to handle atomically?

4. **Certificate pinning**: Some SDKs pin certificates. MITM will break them. Need allowlist for pinned hosts?

5. **Performance**: Double TLS termination adds latency. Acceptable for AI API calls?

6. **Audit**: Should the proxy log all intercepted requests for local audit even before they reach Broker?

---

## Next steps

1. Prototype transparent proxy in Node with on-the-fly cert generation
2. Test firewall rules on Linux (iptables) and macOS (pf)
3. Measure latency overhead
4. Design privileged helper for non-root workloads
5. Integrate with Kubernetes NetworkPolicy for container deployments
