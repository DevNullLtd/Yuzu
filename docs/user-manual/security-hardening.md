# Security Hardening Guide

This guide covers hardening Yuzu for production enterprise deployments.

## mTLS Setup

> **Default certificates are convenience, not production.** A fresh install
> generates a per-install CA + server leaves on first boot so it is encrypted
> with zero configuration — but those leaves are 10-year, do not auto-renew, and
> carry SANs for `localhost`/loopback/hostname only. **Replace them before a
> production rollout** with operator-provided or organisation-CA certs (below),
> or root the built-in CA in your enterprise CA (subordinate mode, roadmap). The
> server warns loudly while on default certs (startup banner, audit
> `server.default_certs_in_use`, the `yuzu_server_default_certs_active` gauge).
> Back up `--ca-dir` (esp. `default-ca.key`) and the `ca_store` Postgres
> schema (`pg_dump`/`pg_restore`, ADR-0053) — losing the CA key forces a full
> fleet re-enrollment.

All agent-to-server communication should use mutual TLS. Create a private CA, server certificate, and per-agent certificates.

### 1. Create Certificate Authority

```bash
# Generate CA key and certificate (valid 10 years)
openssl genrsa -out ca.key 4096
openssl req -new -x509 -key ca.key -sha256 -days 3650 \
  -out ca.crt -subj "/CN=Yuzu CA/O=Your Org"
```

### 2. Server Certificate

```bash
# Generate server key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
  -subj "/CN=yuzu-server/O=Your Org"

# Sign with CA (include SAN for gRPC)
cat > server-ext.cnf <<EOF
subjectAltName = DNS:yuzu-server,DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256 \
  -extfile server-ext.cnf
```

### 3. Agent Certificates

```bash
# Per-agent certificate (CN should match agent ID)
AGENT_ID="agent-001"
openssl genrsa -out "${AGENT_ID}.key" 2048
openssl req -new -key "${AGENT_ID}.key" -out "${AGENT_ID}.csr" \
  -subj "/CN=${AGENT_ID}/O=Your Org"
openssl x509 -req -in "${AGENT_ID}.csr" -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out "${AGENT_ID}.crt" -days 365 -sha256
```

### 4. Configure

```bash
# Server
yuzu-server --cert server.crt --key server.key --ca-cert ca.crt

# Agent
yuzu-agent --client-cert agent-001.crt --client-key agent-001.key --ca-cert ca.crt
```

On Windows, agents can use the certificate store instead of PEM files:
```bash
yuzu-agent --cert-store MY --cert-subject "agent-001"
```

## Firewall Rules

| Port | Protocol | Direction | Purpose | Restrict To |
|------|----------|-----------|---------|-------------|
| 8080 | TCP | Inbound | Web dashboard + REST API | Admin network |
| 8443 | TCP | Inbound | HTTPS dashboard | Admin network |
| 50051 | TCP | Inbound | Agent gRPC | Agent network |
| 50052 | TCP | Inbound | Management gRPC | Admin network |
| 50055 | TCP | Inbound | Gateway upstream | Gateway hosts only |
| 9568 | TCP | Inbound | Gateway Prometheus | Monitoring network |

**Recommendations:**
- Bind the web dashboard to an internal interface: `--web-address 10.0.0.1`
- Never expose gRPC ports (50051/50052) to the internet
- Use a reverse proxy (nginx, Caddy) for TLS termination on the dashboard

## Least-Privilege Deployment

The systemd service units include security hardening:

```ini
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyDirectories=/
ReadWritePaths=/var/lib/yuzu /var/log/yuzu /etc/yuzu
```

Run each component under its own system user:
- `yuzu` — server process
- `yuzu-agent` — agent process
- `yuzu-gw` — gateway process

## Gateway TLS (if you deploy the Erlang gateway)

> **⚠ The gateway agent listener (`:50051`) is plaintext in the *shipped* composes.**
> The gateway is the command fan-out plane — a plaintext, untrusted-network-reachable
> agent listener lets an on-path attacker inject commands (fleet RCE).
> **One-way (server-authenticated) TLS now exists for it (PKI PR5c)** — enable it on
> the agent listener (`transport_opts` with `verify => verify_none`,
> `fail_if_no_peer_cert => false`; see `gateway/config/sys.config.prod`) and ship the
> CA to your agents. It is not on by default in the deployed composes until PR5b.

If you deploy the gateway, you **must** protect the agent edge — either enable the
PR5c one-way TLS above (and distribute the CA), **or** at the network layer:
- **Terminate TLS in front** of the gateway (reverse proxy / L7 LB doing TLS on
  `:50051`, forwarding only over loopback or a trusted segment), **or**
- keep `:50051` on a **trusted network** (VPN / private subnet / service mesh) — never
  directly internet-exposed.

The gateway→server **upstream** hop supports mutual TLS (`gateway/config/sys.config.prod`
`{https,...}`), and the gateway **fails closed** if that channel is configured `https`
without `verify_peer`. Direct agent→server connections (no gateway) are already full
mTLS over any network. Full detail + the deployment runbook: `docs/user-manual/gateway.md`
"TLS posture" and `docs/pki-architecture.md` "Gateway TLS".

The gateway **management plane** (`:50063`) — the port the server's command
forwarding dials — is the highest-value gateway surface: whoever it admits can
run commands on every connected agent. Its secure shape is strict mTLS **plus a
peer pin** (#1422): the listener's `auth_fun` accepts only a client cert whose
key matches `{yuzu_gw, mgmt_peer_pins}` (your server's cert) AND carries the
`serverAuth` EKU — a CA-issued cert alone (any agent's leaf, the gateway's own
leaf) is rejected with `UNAUTHENTICATED`. The gateway **refuses to boot** when a
network-reachable mgmt listener lacks this posture; never set
`{allow_insecure_mgmt, true}` outside an isolated lab rig, and never publish
`:50063` from a plaintext stack. See `docs/user-manual/gateway.md` "TLS posture"
for pin configuration and rotation.

## Secret Management

**Never pass secrets via CLI flags** — they are visible in `ps aux`.

Use environment variables instead:

```bash
# systemd EnvironmentFile
echo 'YUZU_OIDC_CLIENT_SECRET=your-secret' > /etc/yuzu/secrets.env
chmod 600 /etc/yuzu/secrets.env

# Add to systemd unit
# [Service]
# EnvironmentFile=/etc/yuzu/secrets.env
```

Sensitive environment variables:
- `YUZU_OIDC_CLIENT_SECRET` — OIDC client secret
- `YUZU_CLICKHOUSE_PASSWORD` — ClickHouse password
- `YUZU_NVD_API_KEY` — NVD API key

For HashiCorp Vault integration, use a wrapper script that fetches secrets at startup:
```bash
#!/bin/bash
export YUZU_OIDC_CLIENT_SECRET=$(vault kv get -field=secret secret/yuzu/oidc)
exec /usr/local/bin/yuzu-server "$@"
```

## Rate Limiting

Configure API and login rate limits:

```bash
yuzu-server --rate-limit 100 --login-rate-limit 10
```

- `--rate-limit` — Maximum API requests per second per IP (default: 100)
- `--login-rate-limit` — Maximum login attempts per second per IP (default: 10)

Clients exceeding the limit receive `429 Too Many Requests` with a `Retry-After: 1` header.

For additional protection, deploy a reverse proxy with rate limiting:
```nginx
limit_req_zone $binary_remote_addr zone=yuzu_api:10m rate=50r/s;
location /api/ {
    limit_req zone=yuzu_api burst=20 nodelay;
    proxy_pass http://127.0.0.1:8080;
}
```

## HTTP Security Response Headers

Yuzu sets six standard security response headers on every HTTP response from the server (dashboard, REST API, MCP, metrics, health probes, error pages). No configuration is required to enable them.

| Header | Value | Purpose |
|---|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'[; upgrade-insecure-requests]` | Restricts which sources can be loaded by the dashboard. Defends against XSS, clickjacking, and content injection. `upgrade-insecure-requests` is appended only when HTTPS is enabled. The CSP is fully `'self'`-only — no external CDN allowance — because the HTMX runtime is embedded in the server binary and served from `/static/htmx.js` (see below). |
| `X-Frame-Options` | `DENY` | Blocks the dashboard from being embedded in any `<iframe>`. Defense-in-depth alongside CSP `frame-ancestors 'none'`. |
| `X-Content-Type-Options` | `nosniff` | Prevents MIME-type sniffing attacks. Browsers must respect the declared `Content-Type`. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Sends only the origin (not the full URL with query strings) when navigating cross-origin. Defends against URL-based secret leakage to third-party sites. |
| `Permissions-Policy` | `accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()` | Deny-all baseline for browser feature APIs the dashboard never uses. `fullscreen=(self)` is permitted for same-origin chart libraries. |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | (HTTPS only) Tells browsers to always use HTTPS for this origin for one year. Defends against TLS downgrade attacks. Only sent when `https_enabled` is true, per RFC 6797 §7.2. |

At server startup, the resolved header bundle is logged at INFO level so operators can confirm activation:

```
[info] Security headers active: CSP=277 bytes, HSTS=on, Referrer-Policy="strict-origin-when-cross-origin", Permissions-Policy=315 bytes
```

### Why `'unsafe-inline'` for scripts and styles

The HTMX dashboard uses inline `<script>` blocks, inline `onclick=` event handlers, and inline `<style>` blocks. Tightening to a strict nonce-based CSP would require refactoring all event handlers to `addEventListener` and threading per-request nonces through every HTML render path. This work is tracked separately. The current CSP is restrictive enough to block external script injection while keeping the dashboard functional.

### Embedded HTMX runtime — no external CDN

The HTMX 2.0.4 runtime and the `htmx-ext-sse` extension are compiled into the server binary as static C++ string literals (`server/core/src/static_js_bundle.cpp`) and served from same-origin paths:

- `GET /static/htmx.js` — HTMX core (~51 KB)
- `GET /static/sse.js` — Server-Sent Events extension (~9 KB)

Both responses set `Cache-Control: public, max-age=86400`. The dashboard's `<head>` references them as `<script src="/static/htmx.js">` and `<script src="/static/sse.js">`, so the CSP `script-src` only needs `'self'` — there is no external CDN allowance and **no internet connectivity required** for the dashboard to load. This makes the server suitable for air-gapped deployments out of the box.

If you need to update HTMX, replace the payloads in `server/core/src/static_js_bundle.cpp` and rebuild. The file is split into 14 KB chunks because MSVC's raw string literal limit is 16380 bytes (error C2026) — keep that constraint in mind when re-vendoring.

### Extending CSP for customer environments

Some deployments need to reach additional origins from the dashboard — a customer-hosted CDN, a monitoring beacon (e.g. New Relic, Sentry), an analytics endpoint, or a custom favicon host. Use `--csp-extra-sources` to append additional source-list entries to the `script-src`, `style-src`, `connect-src`, and `img-src` directives:

```bash
yuzu-server \
  --csp-extra-sources "https://cdn.example.com https://beacon.example.com"
```

The argument is a single space-separated string. Each entry is appended to all four directives. To set this via environment variable:

```bash
export YUZU_CSP_EXTRA_SOURCES="https://cdn.example.com https://beacon.example.com"
yuzu-server
```

#### Validation

The flag is validated at startup. The server will refuse to start with a clear error message if the value contains:

- Control bytes (0x00–0x1F except SP/HTAB, plus 0x7F) — these would cause cpp-httplib's header validation to silently drop the entire CSP header.
- Semicolons (`;`) or commas (`,`) — these would inject additional CSP directives.
- Quoted CSP keywords other than the safe allow-list `'self'`, `'none'`, or `'sha256-...'`/`'sha384-...'`/`'sha512-...'`/`'nonce-...'` hash and nonce expressions. Notably `'unsafe-eval'` and `'strict-dynamic'` are **rejected** — operators who genuinely need them must extend the server build and accept the security trade-off.
- Unquoted tokens with stray single quotes (malformed sources).

For example:

```bash
# Rejected at startup with: csp_extra_sources contains forbidden control byte 0x0d at position 18
yuzu-server --csp-extra-sources $'https://ok.example\rInjected'

# Rejected at startup with: csp_extra_sources token "'unsafe-eval'" is not a valid CSP source expression
yuzu-server --csp-extra-sources "'unsafe-eval'"
```

### Behind a reverse proxy

If you deploy Yuzu behind a reverse proxy (nginx, HAProxy, Caddy, Cloudflare) that **also** sets a `Content-Security-Policy` header, the browser will see two CSP headers and apply the **intersection** of both policies — the strictest combined policy wins. This can be confusing when debugging "why is my extra source blocked?" — check both layers. If your proxy sets its own CSP, either:

- Disable the proxy's CSP and let Yuzu's CSP apply, or
- Disable Yuzu's CSP via the proxy's `proxy_hide_header Content-Security-Policy;` directive, or
- Match both policies so the intersection allows what you need.

The same applies to all other security headers — if both layers set them, browsers honor the strictest.

### Verifying headers

Run the dashboard and inspect the response headers in your browser's developer tools (Network tab → click any request → Response Headers), or with `curl`:

```bash
curl -sk -i https://yuzu.example.com:8443/livez \
  | grep -E '^(Content-Security|X-Frame|X-Content|Referrer-Policy|Permissions-Policy|Strict-Transport)'
```

You should see all six headers present on HTTPS responses (and the first five on HTTP responses).

### Bandwidth note

The six security headers add roughly 700–900 bytes per HTTP response depending on whether `--csp-extra-sources` is set. For a fleet that pulls heavily from the REST API (e.g. an analytics pipeline polling `/api/v1/responses` thousands of times per hour), this is a non-trivial increase in egress on metered connections. Plan capacity accordingly. The headers cannot be disabled.

## Audit Log Forwarding

Configure webhooks to forward audit events to your SIEM:

```bash
# Create a webhook subscription for audit events
curl -X POST http://localhost:8080/api/v1/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"url":"https://splunk-hec.example.com:8088/services/collector",
       "events":["audit.*"],
       "headers":{"Authorization":"Splunk YOUR-HEC-TOKEN"}}'
```

Audit events include: `timestamp`, `principal`, `action`, `target_type`, `target_id`, `detail`, `source_ip`.

## Database Security

- SQLite databases use WAL mode for concurrent access
- The TAR database uses `PRAGMA secure_delete = ON` to zero deleted pages
- Protect database files with filesystem permissions: `chmod 600 *.db`
- For encryption at rest, use filesystem-level encryption:
  - Linux: LUKS on the data partition
  - Windows: BitLocker on the data volume
  - Docker: encrypted volumes

### Current encryption posture (interim, disclosed)

No secret class is now stored plaintext at the column level — the last remaining
exception (offload-target credentials) closes with this migration (ADR-0059).
ADR-0010 (`docs/adr/0010-secrets-at-rest-envelope-encryption.md`) is the completed
roadmap: app-side AES-256-GCM envelope encryption landed with each store's
PostgreSQL migration. Host-level encryption (above) remains defence-in-depth
regardless.

Five classes that used to appear on this list no longer belong on it:

- **MFA TOTP secrets** (`auth.users.mfa_totp_secret`) are `SecretCodec`-encrypted
  as of 2026-07-16 — the first store to land the ADR-0010 seam. This changes the
  *backup* requirement rather than removing one: the wrapped data key travels in
  the row, but the KEK that unwraps it is a file under `--ca-dir`. A Postgres
  dump alone is **not** a complete auth backup — restore one next to a different
  keys directory and every MFA decrypt fails closed. Back the database and the
  keys directory up as a pair; see
  `docs/ops-runbooks/auth-db-recovery.md` § "Backup — the KEK pairing rule".
- **Webhook signing secrets** (`webhook_store.webhooks.secret`) are
  `SecretCodec`-encrypted as of the `WebhookStore` Postgres migration
  (ADR-0057) — same KEK-pairing backup rule as MFA secrets above: back the
  database and the `--ca-dir` keys directory up together.
- **The OIDC client secret** (`runtime_config_store.runtime_config_secrets.sealed_value`)
  is `SecretCodec`-encrypted as of the `RuntimeConfigStore` Postgres migration
  (ADR-0060) — same KEK-pairing backup rule as MFA secrets above: back the
  database and the `--ca-dir` keys directory up together.
- **Session tokens** have no durable storage on any substrate. Sessions are
  in-memory-authoritative (`AuthManager::sessions_`); the Postgres cutover
  dropped the SQLite-era `sessions` table outright rather than migrating it, so
  there is no session-token column to encrypt — or to leak in a dump. A restart
  is itself a fleet-wide session revocation.
- **Offload-target credentials** (`offload_target_store.offload_targets.auth_credential`)
  are `SecretCodec`-encrypted as of 2026-08-25 (ADR-0059). Same backup-pairing
  requirement as MFA TOTP secrets above: a Postgres dump alone cannot recover a
  configured target's credential without the matching keys directory — the
  target survives, but its credential must be re-entered.

## Plugin Allowlist

In production, verify plugin binaries against a SHA-256 allowlist to prevent loading of tampered or unauthorized code:

```bash
# Generate allowlist from verified builds
sha256sum /opt/yuzu/plugins/*.so > /etc/yuzu/plugin-allowlist.txt
chmod 600 /etc/yuzu/plugin-allowlist.txt

# Start agent with allowlist enforcement
yuzu-agent --plugin-allowlist /etc/yuzu/plugin-allowlist.txt
```

Plugins not listed or with a hash mismatch are rejected before any code executes. See [Plugin Allowlist](agent-plugins.md#plugin-allowlist) for details.

## Command Replay Protection

The agent deduplicates commands by `command_id` so a captured or redelivered command cannot re-execute an action. Deduplication is **durable**: it is backed by a small SQLite store (`command_dedup.db`) in the agent's data directory, so protection survives an agent **restart**, not just a reconnect (HA delivery-matrix WS-0, ADR-2002).

- **Terminal-outcome replay.** When a command's outcome has been recorded, a redelivery replays the **original terminal frame** — its real status, exit code, and structured error — instead of a generic rejection. This closes the "effect-once, result-maybe-lost" gap where a dropped acknowledgement of a completed command would otherwise discard its real result. The terminal frame carries the *outcome*, not the command's streamed stdout (that output is sent during execution and is not re-sent on replay). A terminal frame larger than 64 KiB has its output field replaced by a fixed marker in the store, to bound on-disk growth — status, exit code, and (bounded) error are preserved.
- **In-flight duplicate.** A command still executing (or one that was mid-execution when the agent last stopped) is answered with a non-terminal `RUNNING` frame (output `"duplicate command still in flight"`) and is **never re-executed** — re-running a possibly-destructive command is deliberately avoided. This is *effectively-once*, not exactly-once.
- **Guardian control exemption.** Commands to the reserved `__guard__` plugin (real-time Guardian control/reconcile signals, not endpoint command executions) are deliberately **exempt** from deduplication — they are idempotent control messages meant to be re-applied, so they always run.
- **Retention.** The store keeps the most recent commands (a fixed-size, clock-free ring); an outcome older than the retention window is forgotten, after which a redelivery would run again. The server generates a unique `command_id` per invocation, so legitimate commands are never affected.
- **Degraded (fail-open) mode.** If the store cannot be opened or written (e.g. a full disk), the agent continues executing commands **undeduplicated** rather than refusing them (so a single disk fault does not drop the endpoint out of remote-control reach). This is surfaced, not silent: the `yuzu.dedup_degraded` heartbeat tag reports an agent whose store never **opened**, and the `yuzu.dedup_claim_errors` / `dedup_record_errors` / `dedup_release_errors` counters report **post-open write failures** (a full disk after boot) — together an operator can detect an agent running without replay protection. (Fleet-wide `yuzu_fleet_*` gauges and an alert derived from these tags land with the HA observability workstream.)

No configuration is required — replay protection is always active.

> **Changed in this release (automation/SIEM):** older agents rejected a redelivered command with a `REJECTED` response whose reason was `"command replay rejected: duplicate command_id"`. That fixed string **no longer exists** on the terminal path — a duplicate now replays the command's *real* terminal status (or an in-flight `RUNNING`). Any detection rule that keyed on the old rejection string must be updated. See the corresponding entry in `docs/user-manual/upgrading.md`.

## Device Quarantine

The `quarantine` agent plugin isolates compromised or suspicious devices by blocking all network traffic except the Yuzu server connection. This allows continued management while preventing lateral movement.

### Quarantining a Device

Execute the `quarantine` action from the `quarantine` plugin:

```bash
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "quarantine.quarantine",
    "scope": "agent_id == \"compromised-agent-id\""
  }'
```

The plugin blocks all network traffic except communication with the Yuzu server using
platform-native firewalling: `netsh` on Windows, `iptables` **and `ip6tables`** on Linux, and `pfctl` on macOS.

### Whitelisting on a dual-stack host (read this before quarantining one)

Containment covers **both address families**. On Linux the plugin installs the same
`yuzu-quarantine` chain in `iptables` *and* `ip6tables`; each whitelist entry is routed to the
chain matching its own family, so a **v4-only whitelist leaves IPv6 fully contained**.

That is the correct posture — before this, an IPv6-capable host was never contained at all
(#3282) — but it changes what a whitelist has to contain:

- There is no blanket "keep existing connections alive" rule on either family — only a
  whitelisted address's traffic survives, in any connection state (new, reconnecting, or
  already established). The agent automatically whitelists its own configured server address
  (`--server`) for this: an IP literal is used directly, and a hostname is resolved to its
  address(es) **once, at agent startup** — never at quarantine time — covering whichever
  families it resolves to at that point.
- **Trust boundary: startup-time resolution uses the endpoint's own resolver.** This is a
  deliberate improvement over resolving at quarantine time (which would let a host already
  under active compromise steer its own containment exception via a poisoned `/etc/hosts` or
  local resolver, right when quarantine is dispatched in response to that compromise) — but it
  is not a trusted-channel guarantee against a resolver that was already compromised before or
  at agent startup. For endpoints where containment integrity matters most, **configure `--server`
  as an IP literal** rather than a hostname, removing DNS from the equation entirely.
- If the agent's configured server address is a hostname that resolves to an IPv4 address but
  the agent actually reaches the server over IPv6 through some other path (a split-horizon DNS
  setup, a manually pinned route), or if the server's address changes after the agent last
  started, the automatic whitelisting will not cover that path — **add the server's address to
  the whitelist explicitly** in that case. The common case (the configured address resolves to
  the address actually used, and doesn't change between agent restarts) needs no manual
  whitelist entry for the server at all.
- Whitelist entries that are neither valid IPv4 nor valid IPv6 (a hostname, a malformed literal)
  are **skipped, and the skip is reported** — the plugin does not silently drop them and report a
  clean success.
- **On macOS, `whitelist` is a quarantine-time action.** It rebuilds and reloads the whole pf
  ruleset, which includes the `block all` default-deny, and enables pf. Dispatching it at a device
  that is *not* quarantined therefore isolates it. Use it to repair a contained device's
  exceptions, which is what it is for; check `status` first if you are unsure of the device's
  state.
- If `ip6tables` is absent from the host, the v6 leg is reported as unavailable rather than
  counted as applied.

When in doubt, whitelist both families for the management server. An over-broad whitelist keeps
the device manageable; a missing one requires physical or out-of-band access to recover.

### Reading the result honestly

The plugin reports on **two channels, and they carry different things**. `status|`/`state|` in the
output line is the operator-readable detail; the ABI result status is what a generic
success/failure consumer sees. Neither is allowed to say "clean" for a containment that is
partial, unenforced, or unreadable.

**Mutation actions** (`quarantine`, `unquarantine`, `whitelist`) emit `status|<token>`:

| Token | Meaning | What to do |
|---|---|---|
| `quarantined` | Every rule the host's supported families need was applied | Nothing |
| `quarantined_partial` | Some rules applied, some did not — e.g. IPv4 contained, IPv6 not | Treat the device as **not contained**; the `note\|` field names what is missing |
| `failed` | Nothing applied | Not contained |
| `released` | Rules removed | Nothing |
| `release_uncertain` | The release ran but its result could not be confirmed | Verify with `status`; the device may still be contained |
| `updated` | *(`whitelist`)* The exception list was changed | Nothing |
| `update_uncertain` | *(`whitelist`)* The edit ran but its result could not be confirmed | Treat the repair as **not applied**; confirm with `status` before relying on it. This is the outcome to watch for on the stranded-device recovery path above |
| `busy` | Another mutating quarantine action on this device held the serialization gate for longer than the wait budget | Nothing was changed by this call — retry. Waiters are served in arrival order, so a release queued behind a burst of quarantines is not starved |

**`quarantine.status`** emits `state|<token>`:

| Token | Meaning |
|---|---|
| `active` | Containment is in force |
| `partial` | Some of the expected rules are present and some are not — a real containment gap |
| `degraded` | *(macOS)* A blocking pf ruleset is loaded but pf is **disabled** — traffic is not actually being blocked |
| `uncertain` | The firewall state could not be read, so the answer is unknown |
| `inactive` | Not quarantined |

`status` returns a **non-zero exit code** on `degraded` and `uncertain`, and sets the ABI result
status to `UNAVAILABLE`/`PARTIAL`, so automation that only inspects the return code cannot read an
unenforced or unreadable host as a clean status. `partial` returns 0 but is reported `PARTIAL` on
the result-status channel. `active` and `inactive` are genuine answers and return 0.

A quarantine result is a claim about firewall rules, not proof that traffic is blocked — for a
device you believe is actively hostile, confirm with an independent probe.

### Checking Quarantine Status

```bash
# Execute quarantine.status to check if an agent is isolated
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "quarantine.status",
    "scope": "agent_id == \"agent-id\""
  }'
```

### Releasing a Device

Execute the `unquarantine` action to remove quarantine rules and restore normal network access. On
Linux this tears down both the `iptables` and `ip6tables` chains; a release whose teardown does not
fully succeed reports `release_uncertain`, not `released` — treat the device as possibly still
contained and confirm with `status`.

You can also use `whitelist` to add exceptions (IP or CIDR range) to the quarantine rules before
releasing — the usual repair when a device has been contained without a reachable management
address. `whitelist` is exempt from the dispatch gate below precisely so that repair stays possible.

### Checking Quarantine Status

```bash
# Execute quarantine.status to check if an agent is isolated
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "quarantine.status",
    "scope": "agent_id == \"agent-id\""
  }'
```

### Releasing a Device

Execute the `unquarantine` action to remove quarantine rules and restore normal network access. On
Linux this tears down both the `iptables` and `ip6tables` chains; a release whose teardown does not
fully succeed reports `release_uncertain`, not `released` — treat the device as possibly still
contained and confirm with `status`.

You can also use `whitelist` to add exceptions (IP or CIDR range) to the quarantine rules before
releasing — the usual repair when a device has been contained without a reachable management
address. `whitelist` is the repair path for a device whose exceptions are wrong.

### Quarantine now blocks instruction dispatch (#881)

A quarantined device is refused at the **server's dispatch chokepoint**, not only at its own
firewall: any instruction targeting it — by id, by scope, by management group, or by broadcast —
is dropped before it reaches the agent, and the refusal is audited as
`quarantine.dispatch_denied`. Before this, quarantine isolated the network while the control
plane carried on issuing commands to the device.

Two consequences worth planning for:

- **The quarantine plugin's own actions are exempt** — `quarantine`, `unquarantine`, `status` and
  `whitelist` still reach a contained device, so release stays possible. The exemption is keyed on
  the action, not the plugin, so a future fifth action would be gated until it is deliberately
  added.
- **Four server-internal pushes are also exempt, and you should know they exist.** The TAR
  fleet-topology snapshot request (`tar.fleet_snapshot`), the Guardian rule push
  (`__guard__.push_rules`), the asset-tag sync (`asset_tags.sync`) and the on-demand inventory
  sync (`__sync__.now`) continue to reach a contained device. This is deliberate — gating the Guardian push would stop a quarantined device
  receiving the enforcement rules that make containment meaningful — but it means the containment
  boundary is not total, and a security review of the containment surface has to account for
  those four channels. They are a closed set in code (`SystemReservedPush`) and are counted by
  `yuzu_server_system_reserved_push_total{capability,result}`; a new one cannot be added without
  appearing in that set. **They are counted, not audited** — there is no per-event row saying a
  particular push reached a particular contained device, so this is a fleet-level signal rather
  than per-device evidence. **Nothing outside that set and the plugin's own four actions reaches a
  quarantined device.**

  What that means for your threat model, channel by channel:

  | Channel | What it can do on a contained device |
  |---|---|
  | `tar.fleet_snapshot` | Requests a read-only topology/process snapshot. No state change. |
  | `asset_tags.sync` | Writes device tags. No code execution. |
  | `__sync__.now` | Requests an on-demand inventory sync — it arms the agent's existing sync scheduler and nothing else. No code execution beyond the plugin's existing daily-sync path. |
  | `__guard__.push_rules` | Delivers Guardian baseline rules, which the agent may *enforce*. Enforcement is **not arbitrary command execution**: the assertion vocabulary is a closed five-value set — file present/absent, file hash, registry value, service running, service stopped — and dangerous registry keys and service names are refused at the `dangerous_enforce_in_spec` chokepoint before a push is ever built. So an operator with Guardian deploy rights can still change *typed, bounded* state on a contained device while their `execute_instruction` is refused. That is deliberate — enforcing a security baseline on a compromised host is the point — but it is the one exempt channel that mutates the endpoint, so scope it accordingly. |
- **If containment state becomes unreadable, dispatch fails closed** — the server refuses *every*
  target rather than guess who is contained. A short store outage is absorbed by a 60-second
  last-known-good snapshot; past that, instruction dispatch stops fleet-wide until the store
  recovers. Alert on `yuzu_server_quarantine_gate_total{outcome="fail_closed"}` — see
  [Metrics](metrics.md) — because that series is an outage signal, not a quarantine signal.

### Reconnect re-application (#3425)

A device quarantined while **offline** is contained at the control plane immediately (the #881
dispatch gate above refuses it), but its own firewall cannot be touched until a dispatch actually
reaches it — and an offline device cannot be reached. Before #3425, that gap was permanent until
an operator noticed and manually re-issued the quarantine after the device came back.

`QuarantineContainmentReconciler` closes it automatically. For every device with an active
quarantine record whose endpoint containment is not yet confirmed:

- **Trigger.** A heartbeat from the device (the fast path — the reconciler no longer holds a
  reconnecting device to a stale offline-tick's claim window, so the first
  post-reconnect heartbeat is eligible to dispatch immediately) or a periodic ~20-second tick (the
  backstop — catches anything the heartbeat path missed, and everything before the reconciler's
  heartbeat hook was wired). Deliberately **not** agent registration/reconnect itself: the gRPC
  command stream is not yet established at that point, so a dispatch fired from there would be
  silently dropped. Full end-to-end confirmation is **not** one heartbeat interval — it is a real
  state machine (apply, a follow-up `quarantine.status` verify after a short grace window, then
  confirm), so it typically spans a few heartbeat intervals from reconnect to a confirmed record,
  not one; the `#881` gate holds containment at the control plane for the entire span regardless.
- **What it dispatches.** The **stored** `reason`/`whitelist` — the same rule the MCP
  `quarantine_device` retry path (#3127) follows, for the same reason: dispatching anything else
  would silently rewrite a contained device's firewall allow-list with no store update and no
  audit trail.
- **Confirmation.** Dispatch acceptance alone is not proof of containment (a gateway-attached
  agent's `send_to` only queues the frame). The reconciler follows up with a `quarantine.status`
  read and only marks the device confirmed once it answers `state|active`. **This is the target
  agent's own self-report** — cert-bound to the correct agent identity (a different agent cannot
  forge it), but not independently corroborated by any network-side signal. A device whose
  quarantine plugin or execution environment is itself tampered could in principle reply
  `state|active` regardless of its true firewall state; the `#881` dispatch-confinement gate does
  not key off `last_confirmed_at`, so a false confirmation narrows to false operator/audit
  assurance rather than widening what commands can reach that device. This is the same trust
  boundary #3127's MCP `already_active` retry path already relies on, not new to this feature. A
  previously-confirmed device re-verifies on either of two independent signals checked every
  tick: its live agent session changes (a reboot, a service restart — the firewall rules from
  before the restart are gone — re-verifies via `status` first, rather than blindly
  re-applying), or its active `QuarantineStore` record is replaced (released, then
  requarantined — possibly with a different whitelist — while the agent stayed connected the
  whole time, so a session change alone would never have caught it — resets straight to a fresh
  apply instead, since a status check would say nothing about whether the NEW record's whitelist
  was ever applied). A
  confirm is additionally checked against the session that was live when the verifying `status`
  dispatch was actually sent, not just whatever session is live at confirm time, closing a narrow
  reboot window in between that would otherwise attribute a stale session's status read to a new
  one. **Confirmation is point-in-time, not continuous**: once confirmed, a device is not asked
  again unless one of those two signals fires — if something *other* than a session or record
  change clears its firewall rules out-of-band (an OS firewall daemon restart, an unrelated admin
  `iptables -F`/`netsh advfirewall reset`), this component does not notice and does not re-verify.
  Ongoing drift detection outside those cases is Guardian/DEX's domain, not this component's.
- **Concurrency.** The shipped agent-side quarantine plugin's `do_status` answers `active`/`inactive`,
  and a `status|busy` response is possible on all three platforms once a mutating action (`quarantine`/
  `unquarantine`/`whitelist`) is already in flight (#3429's mutation-serialization gate). The
  reconciler parses `busy` defensively (`quarantine_reapply.hpp`) and treats it as "already being
  handled," not a failure. Either way, the reconciler does not retry until its own per-agent backoff
  (starting at 60s, doubling up to a 15-minute cap on repeated non-confirmation, reset on confirm)
  elapses.
- **Audit.** A system-initiated re-application is audited under `quarantine.reapply`
  (`principal: system`), distinct from an operator-initiated `quarantine.enable`/`quarantine.disable`
  — detail carries `record_id=<id> command_id=<id> trigger=tick|heartbeat`, or
  `CONFIRMED record_id=<id> command_id=<id>` once containment is verified. `record_id` is the
  internal `QuarantineRecord::id` the reapply cycle was built from — it keeps a
  release-then-requarantine race for the same device distinguishable across the two quarantine
  episodes in the audit trail, matching the record-identity scoping the store write itself
  already applies.
- **Observability.** `yuzu_server_quarantine_endpoint_unconfirmed{reachability="connected"|"offline"}`
  is a per-replica gauge — never sum it across server instances — counting active records not yet
  confirmed contained. `reachability="offline"` is expected and not alerted on (a device quarantined
  while off is legitimately unconfirmed for its whole offline duration); a sustained
  `reachability="connected"` count is the genuine divergence signal — see
  `YuzuQuarantineEndpointUnconfirmed` in [Metrics](metrics.md). `yuzu_server_quarantine_reapply_total{result}`
  breaks down every outcome (`reapplied`, `confirmed`, `unconfirmed`, `busy`, `offline`,
  `not_reached`, `rate_limited`, `pending`, `degraded`, `validation_failed`, `dispatch_error`).
  `yuzu_server_quarantine_reconciler_tick_healthy` (0/1) distinguishes a genuinely-empty confirm
  queue from a tick that couldn't read at all — check it first when
  `yuzu_server_quarantine_endpoint_unconfirmed` looks suspiciously static, since that gauge
  freezes rather than reflecting an outage.

A manual re-issue of `quarantine_device` (MCP) still works and re-drives the same stored intent —
it is redundant with the automatic reconciler, never required, and never harmful.

**Known limitation.** A device released (`DELETE /api/v1/quarantine/{agent_id}`) at the exact moment
the reconciler is mid-reapply for it can end up re-firewalled just after its record becomes released —
a narrow timing window, not a routine occurrence. If nothing else happens to the device, this is
over-containment, not a containment gap: the device stays isolated a cycle longer than intended, never
less isolated than the record says.

If the device is instead **immediately re-quarantined with a different whitelist** — not just
released — the guarantee weakens: the reconciler already read the OLD record's whitelist and may
dispatch it to the endpoint after the NEW record (a different reason, a different whitelist)
becomes active. The store write is still safe (the id-scoped guarded update refuses to stamp
the stale dispatch onto the new record, and the `quarantine.reapply` audit row now names the OLD
record's `record_id` so the episode is distinguishable after the fact) —
but for up to one reconciler cycle the *endpoint* can be enforcing a whitelist that is looser or
tighter than the one the active record currently states, until the next tick/heartbeat notices the
new record is unconfirmed and re-dispatches its real whitelist. If you release and immediately
re-quarantine the same device with a different whitelist, a follow-up `quarantine.status` check is a
reasonable sanity step until this closes. Tracked for a proper fix (a claim/generation token on the
active record, extended to cover this dispatch-time case as well as the store-write case it was
originally scoped for).

## IOC Checking

The `ioc` plugin supports Indicator of Compromise checking for threat hunting. Execute the `check` action with one or more indicator types to scan an endpoint for signs of compromise.

### Supported Indicator Types

| Type | Description |
|---|---|
| `ip_addresses` | Check active TCP/UDP connections against known-bad IPs |
| `domains` | Check DNS cache and hosts file against known-bad domains |
| `file_hashes` | Scan specified paths for files matching known-bad SHA-256 hashes |
| `file_paths` | Check for the existence of specific suspicious file paths |
| `ports` | Check for processes listening on suspicious ports |

### Running an IOC Check

```bash
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "ioc.check",
    "parameters": {
      "ip_addresses": ["203.0.113.50", "198.51.100.23"],
      "file_hashes": ["e3b0c44298fc1c149afbf4c8996fb924..."],
      "ports": ["4444", "5555"]
    },
    "scope": "tag:env == \"production\""
  }'
```

IOC checks run locally on each endpoint, querying active connections (Windows: `GetExtendedTcpTable`, Linux: `/proc/net/tcp`, macOS: `lsof`), DNS cache, and filesystem state. Results include matched indicators and the source of the match.

## Certificate Inventory

The `certificates` plugin enumerates certificates in system stores for compliance auditing, expiration monitoring, and security review.

### Listing Certificates

Execute the `certificates.list` action to get all certificates with subject, issuer, thumbprint, and expiry date. Use `certificates.details` with a thumbprint parameter for full certificate details including key usage, serial number, and chain information.

### Certificate Deletion

Execute the `certificates.delete` action with a thumbprint parameter to remove a certificate from the system store. This is useful for revoking compromised certificates or cleaning up expired entries.

Platform implementations:
- **Windows:** CryptoAPI (`CertOpenStore`, `CertEnumCertificatesInStore`)
- **Linux:** PEM files in `/etc/ssl/certs/`
- **macOS:** `security find-certificate` CLI

## OIDC Hardening

When using OIDC/Entra ID:
- Set `--oidc-admin-group` to restrict admin access to a specific group
- Use `--session-timeout` to limit session duration
- Configure the OIDC provider to require MFA
- Restrict the app registration to your tenant (single-tenant)
- Rotate the client secret regularly

> **Upgrading: if `oidc_client_secret` was ever set on this install, rotate it.**
> Releases up to and including v0.13.0 emitted the value in the clear to three places - the
> server log (written by the startup override pass on every boot), `GET /api/config` (gated
> only on `Infrastructure:Read`), and the `config.update` audit detail (readable by every
> role seeded `AuditLog:Read`, which includes the seeded `Operator` role). Those paths are
> now closed, and audit rows written before the fix are redacted when read. **The stored
> value itself is unchanged**, so anyone or anything that already read it still holds a
> working credential.
>
> **Remediation lives in one place:** [`upgrading.md`](upgrading.md) → "⚠️ Security: rotate
> `oidc_client_secret` if it was ever set on this install". Follow it there rather than from
> a summary here. Two things that catch people out: adding a second client secret is not a
> rotation, so the old one must be **deleted** at the IdP; and deletion does not reach what was
> already issued under it — access tokens stay valid until they expire, and sessions have to be
> ended separately at the IdP and in Yuzu.
