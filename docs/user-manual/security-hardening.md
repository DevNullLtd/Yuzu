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
| 8080 | TCP | Inbound | HTTP→HTTPS redirect + unauthenticated health probes in cleartext (the dashboard with `--no-https`) | Orchestrator/admin network |
| 8443 | TCP | Inbound | HTTPS dashboard | Admin network |
| 50051 | TCP | Inbound | Agent gRPC | Agent network |
| 50052 | TCP | Inbound | Management gRPC | Admin network |
| 50055 | TCP | Inbound | Gateway upstream (mutual TLS plus an SPKI public-key pin of the gateway's key, or an acknowledged-disabled plaintext rig) | Gateway hosts only |
| 50063 | TCP | Inbound | Gateway management (server to gateway command fan-out; mutual TLS plus a peer pin) | Server hosts only; never publish it |
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

> **⚠ The gateway agent listener (`:50051`) is plaintext in every shipped compose except the reference gateway compose.**
> The gateway is the command fan-out plane — a plaintext, untrusted-network-reachable
> agent listener lets an on-path attacker inject commands (fleet RCE).
> **One-way (server-authenticated) TLS now exists for it (PKI PR5c)** — enable it on
> the agent listener (a `tls` map in its `{yuzu_gw, grpc_listeners}` entry with
> `verify => verify_none`, `fail_if_no_peer_cert => false`; see
> `gateway/config/sys.config.prod`) and ship the
> CA to your agents. `docker-compose.reference-gateway.yml` ships it (#1314); the
> cluster compose boots the image default `sys.config` and the demo and UAT composes use their own UAT/demo `sys.config`; all of those listen in plaintext.

If you deploy the gateway, you **must** protect the agent edge — either enable the
PR5c one-way TLS above (and distribute the CA), **or** at the network layer:
- **Front the gateway at L4 or with TLS passthrough only** (a plain TCP load balancer,
  an L4 virtual IP or a TLS-passthrough proxy that keeps one TCP connection per agent
  end to end), with the gateway agent listener itself running the one-way TLS above.
  A reverse proxy or L7 load balancer that terminates TLS or HTTP/2 in front of
  `:50051` is a supported way to protect this edge only when it keeps each client
  connection on its own backend connection for as long as the client connection lives
  (see [Keeping each agent on one backend connection](gateway.md#keeping-each-agent-on-one-backend-connection)):
  the gateway binds each agent's heartbeats to the connection that opened its session,
  and a proxy that pools backend connections can spread one agent's calls over several
  connections (see [Heartbeat admission](gateway.md#heartbeat-admission)), **or**
- keep `:50051` on a **trusted network** (VPN / private subnet / a mesh policy that does not
  terminate HTTP/2; see [Heartbeat admission](gateway.md#heartbeat-admission)), never
  directly internet-exposed.

The gateway→server **upstream** hop supports mutual TLS (`gateway/config/sys.config.prod`
`{https,...}`). The canonical answer for this hop: mutual TLS with the SPKI pin below is
enforced **by the server**; the gateway's own check is only that it will talk TLS to a server it
has verified. A plaintext upstream (`http`) is a lab/UAT posture and needs the server's explicit
acknowledgement flag (`--insecure-gateway-peer`). The gateway refuses to boot (fails closed) on
the legacy `{grpcbox, [{client, ...}]}` key, on any `https` endpoint without `verify_peer` and a
`cacertfile` / `cacerts` of its own, and on a channel that lists both `http` and `https`
endpoints; a gateway that boots without a client certificate is refused by the server.
Production is `https`, `verify_peer`, a CA-pinned `cacertfile`, and a client certificate and key.
The server's gateway-upstream service additionally requires an
authorized gateway peer: the gateway's client certificate must carry `serverAuth`, be inside
its validity window and have a public key that matches a configured SPKI pin (automatic on
the generated default certificates, explicit with `--gateway-peer-pin` /
`--gateway-peer-pin-file` otherwise), and the server refuses to start without one unless
`--insecure-gateway-peer` acknowledges a plaintext rig. The check wraps the service, which the
server registers on the one gRPC server that also listens for agents and management, so it
applies on every one of those ports; without it, a caller with no certificate could reach the
service on the agent port of a default-certificate install, and any holder of a CA-issued
client certificate (an agent leaf included) could reach it on the strict ports. Keep the
gateway key readable only by the server and gateway processes: the pin authorizes exactly that
key, so anyone who can read it can act as the gateway. See
[Gateway upstream peer authorization](server-admin.md#gateway-upstream-peer-authorization).
Direct agent→server connections (no gateway) use TLS. Full detail + the deployment runbook: `docs/user-manual/gateway.md`
"TLS posture" and `docs/pki-architecture.md` "Gateway TLS".

The agent listener authenticates the gateway to agents, not agents to the gateway.
Requesting a client certificate on this edge is a configuration change that enforces
nothing yet, and enforcing one needs a separate design (see
[Moving the agent edge to mutual TLS](gateway.md#moving-the-agent-edge-to-mutual-tls)).
The address the gateway reports for an agent is the TCP peer unless the listener is told
which proxies to trust, and it discards whatever the agent sent (a forged address passes
through an older gateway that does not: upgrade every gateway; see
[Client addresses behind a proxy](gateway.md#client-addresses-behind-a-proxy)).
The gateway admits an agent `Heartbeat` only on the connection that opened the
session's `Subscribe` stream, and only for a session that gateway node holds
(a rejected heartbeat is answered `NOT_FOUND`, counted, and not forwarded).
`Subscribe` admission is unchanged, and the binding relies on one connection per
agent between the agent and the gateway (see the supported topologies above). The
same change removes the session id from two gateway log lines, which reduces the
disclosure of session ids in logs; some log lines still include session ids.

The gateway **management plane** (`:50063`) — the port the server's command
forwarding dials — is the highest-value gateway surface: whoever it admits can
run commands on every connected agent. Its secure shape is strict mTLS **plus peer
authorization** (#1422, #6016): the listener's `auth_fun` (run by the gateway's gRPC layer before any handler exists) accepts only a client cert that carries the
`serverAuth` EKU AND is admitted by `{yuzu_gw, mgmt_peer_auth_mode}`: its key matches
`{yuzu_gw, mgmt_peer_pins}` (your server's cert), or it carries the server identity URI SAN
`yuzu://<install>/server` that the install CA puts on the server's built-in certificate, or either,
depending on the mode (unset means `pin`, so an upgrade changes nothing; the identity is never implied by a missing key; the shipped reference configs set `identity` with no pin; bring-your-own certificates must set `pin`) — a CA-issued cert alone (any agent's leaf, the gateway's own
leaf) is rejected with `UNAUTHENTICATED`. A pin needs the server's private key; the identity needs only a
certificate the install CA signed with that URI, so a deployment that guards the CA key separately from
the server key should stay in `pin` mode or use `identity` with a pin (which requires both). The identity also trusts the issuing CA's issuance policy: do not enable it where the listener's `cacertfile` is a corporate CA that lets a requester choose a URI SAN with serverAuth (stay in `pin`), and an identity over a `cacertfile` that is not demonstrably exactly one readable certificate (a bundle, or an empty, unreadable or half-written file) refuses to boot unless the mode is `identity` with a pin configured (`identity_over_ca_bundle`). A serial
deny-list, `mgmt_peer_denied`, refuses a withdrawn certificate in every mode and is read at boot (a change
takes effect at the next gateway restart, which disconnects the node's agents; a gateway rolled back to a
pre-#6016 binary does not honour it). Revoking the server certificate in the CA inventory removes its command-plane access only on a gateway that sets `{yuzu_gw, mgmt_crl_source}`: that gateway reads the CA's CRL (verified by signature against the management listener's CA, fetched over verified TLS) and refuses a listed serial with `crl_revoked` within `mgmt_crl_refresh_ms` of the server publishing it, with no restart, and refuses every stream (`revocation_unknown`, `revocation_stale`) when it holds no usable CRL or one past `nextUpdate` plus `mgmt_crl_grace_s`. A gateway with no source reads no CRL, so for it withdrawal is a serial in `mgmt_peer_denied` plus a gateway restart, which disconnects the node's agents, and agents without the #5183 fix stay wedged; the boot logs a WARN for that case. See "Withdrawing a server certificate" in [gateway.md](gateway.md). The gateway **refuses to boot** when a
network-reachable mgmt listener lacks this posture; never set
`{allow_insecure_mgmt, true}` outside an isolated lab rig, and never publish
`:50063` from a plaintext stack. See `docs/user-manual/gateway.md` "TLS posture"
for pin configuration and rotation, and "Authorizing the server by its identity" and
`docs/adr/2004-gateway-mgmt-server-identity.md` for the identity modes.

**Firewall the management port (known, accepted limitation).** The management listener
holds at most 256 connections (`limits.max_connections`), and that is a file-descriptor
bound, not protection. Before the TLS handshake, anyone with layer-4 reach to the port can
hold a slot for up to the 10 s handshake timeout; after the handshake, any holder of a
certificate issued by the install CA (every enrolled agent has one) can hold it for as long
as `PING`s keep the connection busy, because peer authorization (pin and/or identity) runs later, per stream. About
256 held connections would stop the server making **new** connections to the gateway;
connections already established are unaffected. The gateway does not fix this; you must
restrict `:50063` (and any alternative port set by `YUZU_GW_MGMT_PORT`) so that only the
server replicas can reach it, set the management listener's `listen.ip` to the management
interface's address so the port is not bound on the agent-facing interface, and where you can,
multi-home the server so that the interface it uses for gateway management traffic is not
the one that faces agents or the database. The shipped composes do not publish it, and the
gateway cannot verify the firewall or the interface separation. To detect a flood, count
`ss -Htn state established '( sport = :50063 )'` on the gateway host against the number of
server replicas, and watch `yuzu_server_gateway_forward_total{status="unavailable"}` on the
server (commands dropped after three attempts; an alert on its `increase` is recommended and
none ships). To recover, block the source at the firewall; a process restart does not
clear it. The agent listener has the matching
residual risk: its 60000-connection ceiling bounds file descriptors, but a peer that
completes the handshake and keeps sending can hold connections open and fill it, after which
new connections wait in the kernel backlog (agents already connected are unaffected until
they reconnect). Limit connections per source address at the L4 balancer or firewall; see
[Connection ceilings and the unauthenticated ports](gateway.md#grpc-listeners).

**Gateway Erlang distribution is outside the PKI and unencrypted.** Between
gateway nodes of a cluster, commands and results (including plugin parameters)
travel over plain TCP guarded only by the shared cookie handshake; there is no
encryption and no per-message integrity. Keep the cluster network trusted and
firewalled to the gateway nodes only (EPMD 4369 and the distribution range
9100-9105), and give every node a strong cookie. TLS distribution is tracked as
#8158 (decision pending; owner: Fraser Jarvis; review by 2027-02-17). If a node
will not start and you cannot reach the vendor docs, read the
refusal text: the container logs it on stderr (`[gateway-entrypoint] FATAL: ...`)
and the systemd unit in the journal (`yuzu-gateway: ...`); it names the fix and
never prints the cookie. A conforming cookie is 32 to 255 characters from
`[A-Za-z0-9._~+=-]` (`openssl rand -hex 32`), identical on every node. See
[Distribution Cookie](gateway.md#distribution-cookie-required-in-production).

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

For the database connection string and the OIDC client secret, a file is an
alternative to the environment: `--postgres-dsn-file` and
`--oidc-client-secret-file` (or `YUZU_POSTGRES_DSN_FILE` /
`YUZU_OIDC_CLIENT_SECRET_FILE`) read the value from a file you protect, such as
a Docker or Kubernetes secret mount. On Windows, prefer the file: a service's
environment there is readable by local users. A `-file` flag cannot be combined
with its direct option or environment variable. See the flag table in
`server-admin.md`.

Sensitive environment variables:
- `YUZU_POSTGRES_DSN` — PostgreSQL connection string (usually includes a password)
- `YUZU_OIDC_CLIENT_SECRET` — OIDC client secret
- `YUZU_CLICKHOUSE_PASSWORD` — ClickHouse password
- `YUZU_NVD_API_KEY` — NVD API key

For HashiCorp Vault integration, use a wrapper script that fetches secrets at startup:
```bash
#!/bin/bash
export YUZU_OIDC_CLIENT_SECRET=$(vault kv get -field=secret secret/yuzu/oidc)
exec /usr/local/bin/yuzu-server "$@"
```

## Random-number failure during MFA enrolment

If the host's random source fails while the server is generating an MFA TOTP secret, a recovery code or a recovery code's salt, the server refuses the request and issues nothing: no TOTP secret, no recovery codes and no partial enrolment. An enrolment being confirmed at that moment is rolled back and the existing recovery codes stay valid. The operator sees a retryable "Authentication store is temporarily unavailable" message (HTTP `503` at sign-in) and can retry once the host recovers. Stored enrolments and recovery codes are untouched.

These attempts are audited with a `detail` starting `csprng_unavailable: ` and counted in `yuzu_secure_random_failure_total{site="mfa_enroll"|"mfa_recovery"}`, separately from a database outage. The same random source also mints sign-in and session tokens, and those draws are **not** counted or audited: if the source is wholly dead, new sign-ins fail with a bare `500` (already-established sessions keep working, but an action that mints a random identifier, such as dispatching a command from the dashboard, can fail too), and the only signals are the sign-in error rate and the server log. At the enrolment confirm step the session is minted after the enrolment has committed, so a failure there leaves the account enrolled with recovery codes the user never saw; regenerate them from Settings. See [Secret-minting failure metric](metrics.md#secret-minting-csprng-failure-metric) and the [response runbook](../ops-runbooks/auth-db-recovery.md#mfa-enrolment-refused-random-number-failure-503).

## Rate Limiting

Configure API and login rate limits:

```bash
yuzu-server --rate-limit 100 --login-rate-limit 10
```

- `--rate-limit`: Maximum API requests per second per IP (default: 100). It is also the per-source budget for `/health` and `/api/health` requests that carry a credential header; values below 1 are treated as 1
- `--login-rate-limit`: Maximum login attempts per second per IP (default: 10). It covers local login, SAML start and ACS, and OIDC sign-in start (`GET /auth/oidc/start`) and callback (`GET /auth/callback`), because these are unauthenticated entry points that trigger outbound requests. An OIDC sign-in uses two requests from the browser's source address, one for start and one for the callback. The same bucket carries the local MFA step-up (`POST /login/mfa/stepup`), which an approver needs for approve and reject. Behind a reverse proxy or NAT that does not preserve the client address, every user shares one source address, so raise `--login-rate-limit` to roughly twice the peak number of simultaneous sign-ins per second. Raising it loosens the only per-address limit on password guessing at `POST /login` and on TOTP guessing at `POST /login/mfa/stepup`, so keep it as low as the proxied population allows.

Clients exceeding the limit receive `429 Too Many Requests` with a `Retry-After: 1` header.

For additional protection, deploy a reverse proxy with rate limiting:
```nginx
limit_req_zone $binary_remote_addr zone=yuzu_api:10m rate=50r/s;
location /api/ {
    limit_req zone=yuzu_api burst=20 nodelay;
    proxy_set_header Host $http_host;   # repeat in every location that proxies to Yuzu
    proxy_pass http://127.0.0.1:8080;
}
```

Forward the client's `Host` unchanged (`proxy_set_header Host $http_host;`), as above, in every `location` that proxies to Yuzu or at `server` level: nginx otherwise sends `$proxy_host`, and every dashboard write is then refused until the public origin is declared with `--csrf-trusted-origin` (see [CSRF protection](#csrf-protection)). `$host` drops the port, so use `$http_host` unless the public port is 80 or 443.

## CSRF protection

Cookie-session writes require a same-site `Origin` or `Referer`. The server applies one check to every request that is authorised by a session cookie (local, OIDC or SAML) and uses any method other than `GET`, `HEAD` or `OPTIONS`: the request must carry an `Origin` or `Referer` that names the same host as the request's `Host` header or one of the origins declared with `--csrf-trusted-origin` (environment variable `YUZU_CSRF_TRUSTED_ORIGIN`). A request without a usable header, or with one naming another site, is refused `403` `cross-site request refused` after authentication and before step-up evaluation, challenge emission and route-handler effects, and before the body is read. Requests authenticated only by an API, MCP or engine token are exempt, because they do not ride a browser cookie; a request that presents a valid session cookie is treated as a cookie request even if it also carries a token. Evidence: each refusal writes a `csrf.denied` audit row (see [Audit Log](audit-log.md)) and increments `yuzu_server_csrf_denied_total{path_class,reason}` (see [Metrics](metrics.md)). The check fails closed: if it cannot complete, the request is refused and counted with `reason` `gate_error`, and a refusal whose audit row could not be written carries the `Sec-Audit-Failed` response header. The same-host comparison is scheme-aware where the server can know the public scheme. On a server that terminates TLS itself (HTTPS enabled), the `Origin` or `Referer` must be `https://`, and default ports are scheme-aware (`:443` is the default, `:80` is not), so `Host: yuzu.example.com` is matched only by `https://yuzu.example.com` or `https://yuzu.example.com:443`. Behind a TLS-terminating reverse proxy the server listens in plain HTTP and the `Host` header carries no scheme, so the server cannot see the public scheme: declare the public origin WITH its scheme (`--csrf-trusted-origin https://yuzu.example.com`) and a plain-`http://` `Origin` for that host and port is then refused, while a bare-host entry matches either scheme. Stated limits: on a plain-HTTP listener where no `https://` origin is declared for the host, an `http://` `Origin` naming the same host and port as `Host` is still treated as same-site, so a proxied deployment should declare its public `https://` origin; the endpoints that answer before a session exists (sign-in and similar) are outside the check; any origin you declare, including a sibling subdomain, is trusted completely; and the control relies on the browser sending `Origin` or `Referer`, so a proxy that injects or strips either header turns it off or locks every write out. It narrows, and does not eliminate, cross-site request risk, and it complements the other layers rather than replacing them.

Cookie-session requests that dispatch work, persist state or force a refresh of server state (the guarded reads) are held to the same rule, whichever method they use. For those requests the browser's fetch metadata decides, and a `Sec-Fetch-Site` header that is present decides alone: `Origin` and `Referer` are not consulted. A request whose `Sec-Fetch-Site` header is `same-origin`, or `none` (a navigation the user started, such as a typed address or a bookmark), is admitted; any other value (`cross-site`, `same-site` or anything unrecognised) is refused `403` with reason `origin_mismatch`. Only a request without `Sec-Fetch-Site`, such as one from a script, `curl` or an old client, falls back to the `Origin` or `Referer` rule above, with the same trusted origins and the same scheme handling, and is refused with the same three reasons. A repeated `Sec-Fetch-Site` header is treated as a non-matching value and refused with `origin_mismatch`, even when a good `Origin` is also sent; to cure such a refusal send `Sec-Fetch-Site` once with value `same-origin` or `none`, or remove the header and send a same-site `Origin` or `Referer`. Page script cannot set `Sec-Fetch-Site`, and the dashboard's own requests send `same-origin`, so on HTTPS or loopback the dashboard needs no change. Browsers send `Sec-Fetch-*` headers only to potentially trustworthy origins (HTTPS and loopback), and Safari before 16.4 does not send them at all, so on a plain-HTTP listener at a non-loopback address these requests fall back to the `Origin` or `Referer` rule: a same-origin `GET` carries no `Origin`, so the dashboard then depends on the `Referer` the browser sends, which the server's default `Referrer-Policy` (`strict-origin-when-cross-origin`) supplies; a proxy or page policy of `no-referrer` would break those panels on such a deployment. A TLS-terminating proxy is unaffected, because the browser talks to the proxy over HTTPS. Requests authenticated only by a token are exempt, as above. The set of covered requests is an explicit, reviewed list kept as data next to the decision (`kFetchMetadataGuardedPaths` in `same_site_write_policy.hpp`), matched on the exact request path (the path, never a query flag, selects the gate); a best-effort source-text test is meant to fail when a handler that dispatches work or changes state is added without an entry (it is lexical and has stated blind spots), and the live-stack security test exercises one covered request. Refusals use the same `403` body, `csrf.denied` audit row (its `target_id` is `GET <path>` or `HEAD <path>`), counter and alerts as writes. Additional stated limits for these requests: fetch metadata does not tell a browser's own prefetch, prerender or link-preview of an address apart from a user action, so a request the same user's browser issues on its own initiative is admitted; a client that sends neither `Sec-Fetch-Site` nor `Origin`/`Referer` is refused; a request whose path is not on the list is not checked, and cookie-reachable `GET` requests outside the list remain there by decision. The audit `detail` text for a refusal of one of these requests still reads "browser write refused".

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

Cookie-session writes require a same-site `Origin` or `Referer`. Forward the client's `Host` unchanged, port included (nginx: `proxy_set_header Host $http_host;` in every `location` that proxies to Yuzu, or at `server` level; `$host` drops the port) or, if the proxy rewrites `Host`, declare the public origin with `--csrf-trusted-origin` (see [CSRF protection](#csrf-protection) and [Server Administration](server-admin.md)). Declare it with its `https://` scheme (for example `https://yuzu.example.com`) even when `Host` is forwarded: the server behind a TLS-terminating proxy cannot see the public scheme, and the scheme-qualified entry is what makes it refuse a plain-`http://` `Origin` for that host. Do not configure the proxy to inject or rewrite `Origin` or `Referer`, which would turn the control off.

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
- The Echo database uses `PRAGMA secure_delete = ON` to zero deleted pages
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
- **Session tokens** are never stored. Operator sessions are durable rows in the
  `session_store` Postgres schema (`SessionStore`, HA WS-1/1a), keyed by the
  SHA-256 hash of the token, with `AuthManager::sessions_` as a generation-gated
  validate cache, so there is no session-token column to encrypt — or to leak in
  a dump. Sessions survive a server restart, so a restart is **not** a session
  revocation: use `DELETE /api/v1/sessions?username=<name>` (force sign-out of
  one operator) or `DELETE /api/v1/sessions/me` (sign out everywhere). The
  all-operators emergency procedure is in
  [Auth database recovery](../ops-runbooks/auth-db-recovery.md#sessions-are-durable).

  **Deactivated local accounts and sessions.** For accounts held in the Yuzu
  local account store and deactivated through the product, once every server
  replica runs this release, a session of that account is rejected on every
  replica within about one second of the deactivation committing on a healthy
  generation poll, even if the deactivation's session cleanup failed. Limits:

  - Local accounts only. OIDC and SAML sessions are ended by the linked-identity
    revoke of the deprovision, not by this check; API tokens and MCP tokens are
    unchanged.
  - Mixed-version operation and out-of-band SQL changes to `auth.users` are
    outside the guarantee. An out-of-band change bumps no generation, so a
    replica with a warm cache can keep serving the session until the next
    generation change.
  - Up to about 30 seconds while a replica's generation poll fails.
  - Deleting an account and recreating it under the same name is keyed on the
    username only, so a surviving session of the old account is not ended by
    the check.
  - The refusal writes no audit row. The evidence is the deactivation's audit
    row plus the aggregate counter `yuzu_auth_session_account_inactive_total`.
  - A deactivation can now fail with `503`, leaving the account active, when
    its session write-generation write cannot complete (see
    [Auth database recovery](../ops-runbooks/auth-db-recovery.md#scim--dashboard-deprovision-returns-500-sessions_db_error)).

  Details: `docs/auth-architecture.md`, "Account state at session validation".
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
- **In-flight duplicate.** A command still executing (or one that was mid-execution when the agent last stopped) is answered with a non-terminal `RUNNING` frame (output `"duplicate command still in flight"`) and is **never re-executed** (apart from the cases described under Retention and Corrupt store recovery below) — re-running a possibly-destructive command is deliberately avoided. This is *effectively-once*, not exactly-once.
- **Guardian control exemption.** Commands to the reserved `__guard__` plugin (real-time Guardian control/reconcile signals, not endpoint command executions) are deliberately **exempt** from deduplication — they are idempotent control messages meant to be re-applied, so they always run.
- **Retention.** The store keeps the most recent commands (a fixed-size, clock-free ring); an outcome older than the retention window is forgotten, after which a redelivery would run again. The server generates a unique `command_id` per invocation, so legitimate commands are never affected. The server-side source of redelivery that is not otherwise bounded is the scheduled-run command outbox, and it is limited, as an estimate, to half of that window: a retry is refused (the occurrence is marked failed, `redelivery_horizon_exceeded`) once the dispatch count has advanced by 10,000 since its first attempt, half of the agent's 20,000-command ring (#3678; see [Execution semantics](instructions.md#execution-semantics)). That count is an estimate and can err in both directions; that page lists the limits. The gateway also re-sends a command under the same `command_id` a bounded number of times over about 15 minutes, which is not expected to reach the ring size.
- **Degraded (fail-open) mode.** If the store cannot be opened or written (e.g. a full disk; a store that is merely *corrupt* is recovered instead, see the next bullet), the agent continues executing commands **undeduplicated** rather than refusing them (so a single disk fault does not drop the endpoint out of remote-control reach). The agent reports these conditions on its heartbeat: the `yuzu.dedup_degraded` tag reports an agent whose store never **opened**, and the `yuzu.dedup_claim_errors` / `dedup_record_errors` / `dedup_release_errors` counters report **post-open write failures** (a full disk after boot). The server derives fleet gauges from them and a sample alert for the open-failure case; see [Fleet monitoring of the dedup store](#fleet-monitoring-of-the-dedup-store). That is best-effort and partial: the alert covers only a store that failed to open (a store that opened and later failed writes is visible only on the latched `..._claim_erroring` gauge, which has no alert), and the gauges do not see old agents or agents offline for more than 90 s, so they are not evidence that replay protection is in force.
- **Corrupt store recovery.** If `command_dedup.db` is so corrupt that it cannot be opened (for example a file that is not a database after a disk fault or a partial restore), the agent moves it aside and starts a fresh store, instead of staying in degraded mode until someone deletes the file.
  - **What and where.** The corrupt file becomes `command_dedup.db.corrupt-<unix-epoch-seconds>` in the data directory, with `-<n>` appended if that name is taken and any non-empty `-wal`/`-shm`/`-journal` files alongside as `<that name>-wal` and so on. The number is the time of the recovery in Unix seconds: `date -r N` on macOS, `date -d @N` on Linux.
  - **What you lose.** **The command history in the corrupt file is lost**, so a command that already ran and is redelivered afterwards may run again.
  - **How you see it.** The agent logs an error naming the quarantined file, increments the agent-local counter `yuzu_agent_dedup_quarantined_total`, and reports the `yuzu.dedup_quarantined` heartbeat tag. `yuzu.dedup_degraded` stays `0` because protection is active again. The tag is a per-process value, so it returns to 0 when the agent restarts even though the quarantined files remain; the log line and the files themselves are the lasting record.
  - **What is kept.** Only the **newest 3** quarantined files are kept; older ones are removed automatically at the end of each recovery. They hold the same saved command responses as the live store (status, exit code and short error text, not streamed output), so treat them as sensitive as a precaution. Once reviewed they are safe to delete: remove every file matching `<data-dir>/command_dedup.db.corrupt-*`, which includes the `-wal`, `-shm` and `-journal` files that travelled with them. A normal uninstall does not remove them.
  - **What is not replaced.** A file that still opens but has a few damaged pages is deliberately **not** replaced (that would discard commands that are still running); the agent keeps using it and only the commands that hit a damaged page run undeduplicated, counted in `yuzu.dedup_claim_errors`.
  - **If it cannot recover.** If the file cannot be moved aside (for example a read-only directory, or a data directory on a filesystem without hard links, for example exFAT, or a network share whose server does not provide them: the quarantine claims its name with a hard link and never falls back to a plain rename), or the fresh store cannot be created afterwards (for example a full disk), the agent falls back to degraded mode as described above and `yuzu.dedup_degraded` is `1`; in the second case the history is already lost and the error names the kept file. Fix the directory's permissions, move the data directory to a filesystem with hard links (NTFS, ReFS, ext4, xfs or APFS), or free the space, or move the file away by hand, and restart the agent. Repeated `.corrupt-*` files on one endpoint mean the disk is corrupting the file on successive boots; check that disk.
  - **Unsupported.** Running two agent processes against one data directory is not supported; recovery protects the quarantined evidence from being overwritten, not the live store from the other process.

No configuration is required — replay protection is on by default (see Degraded mode and Corrupt store recovery for the cases where it is not in force).

> **Changed in this release (automation/SIEM):** older agents rejected a redelivered command with a `REJECTED` response whose reason was `"command replay rejected: duplicate command_id"`. That fixed string **no longer exists** on the terminal path — a duplicate now replays the command's *real* terminal status (or an in-flight `RUNNING`). Any detection rule that keyed on the old rejection string must be updated. See the corresponding entry in `docs/user-manual/upgrading.md`.

### Fleet monitoring of the dedup store

Because the degraded mode is fail-open, an agent can run for a long time without replay protection and nothing on the endpoint tells the operator. The server therefore derives fleet gauges from the agents' heartbeat tags (full reference: [Agent command-dedup store telemetry](metrics.md#agent-command-dedup-store-telemetry-3663)):

- `yuzu_fleet_agents_dedup_store_degraded` — agents whose store could not be **opened**. This is the one live reading, and it drives the `YuzuDedupStoreDegraded` alert (a degradation spanning more than 10 minutes fires it; severity warning).
- `yuzu_fleet_agents_dedup_claim_erroring`, `..._record_erroring`, `..._release_erroring`, `..._record_terminal_missing`, `..._replaying` — agents whose per-process counter is above zero **since their last restart**. They latch until the agent restarts, so they are for investigation, not paging, and have no alert.
- `yuzu_fleet_dedup_rows_max` — the largest store, in rows, as an approximate hint. A healthy value tops out near 20,500 (the 20,000-row terminal ring plus one prune interval); sustained values above about 25,000 are worth investigating (in-flight rows from crashed commands are never evicted). It can over-read after a burst of released claims, and one agent can forge it.
- `yuzu_fleet_agents_dedup_reporting` / `..._tag_rejected` — how many agents are being measured, and how many sent a malformed value.

**`YuzuDedupStoreDegraded` is a sample rule** in `docs/prometheus/yuzu-alerts.yml`. It is a control only once you load that file into your Prometheus and route `severity=warning` in Alertmanager; neither is done by any compose or Helm file the project ships. Until then the gauges on `/metrics` are the only evidence.

**What this does not tell you:**

1. A store that **opened and later failed writes** (a full disk after boot) leaves `store_degraded` at 0. It shows only on the latched `..._claim_erroring` gauge, which has no alert (tracked in #6932).
2. The population is agents with a heartbeat in the **last 90 seconds**. An offline agent, or one that heartbeats slower than 90 s, drops out of every count; a degraded agent that goes offline leaves the count without having been fixed. Keep `--heartbeat` below 90 s, preferably 60 s or less.
3. Each core replica exports only the agents attached to it: sum the counts across replicas, but take the **max** of `yuzu_fleet_dedup_rows_max`. During a failover one agent can be counted on two replicas for a few minutes, so the alert says "about N".
4. Agents that predate these tags are invisible, and so is an agent whose row count could not be read when its store opened (it reports no `yuzu.dedup_rows`, which looks the same). `yuzu_fleet_agents_dedup_reporting` is the denominator; a 0 elsewhere means nothing until it is close to your fleet size.
5. An agent whose heartbeat carries more than 512 status tags (or an oversized tag) has all of its tags dropped by the gateway and vanishes from every dedup count above. The gateway counts it as `yuzu_gw_heartbeat_buffer_dropped_total{reason="heartbeat_oversize"}`; no shipped alert watches it yet (#6934).
6. A quiet graph is **not** evidence that replay protection is in force.

**When `YuzuDedupStoreDegraded` fires:** *(preview-grade: the fleet count tells you how many agents are affected, not which; locating them is manual until #6931.)*

1. **Find the endpoints.** There is no page or API yet that lists them (tracked in #6931), so the alert's count tells you how many to find. Search the agent logs for `Failed to open command dedup store`, or check the data directory on a suspect host.
2. **Fix the cause:** a full or read-only data directory, or a permissions fault on `command_dedup.db` (see "Corrupt store recovery" above for a corrupt file, which the agent recovers by itself).
3. **Restart the agent.** A restart does not re-send an in-flight operator command to it: an agent that is offline receives no queued commands, so a command running when you restart is lost, not repeated (by code reading; a chaos run to measure it is tracked in #6935). But while an endpoint has no durable dedup record, a command redelivered to it by **any** path is not absorbed: the server tries a gateway forward up to three times with the same command id, and a scheduled command can be re-driven after a fault (the undelivered backlog is visible as `yuzu_server_command_outbox_pending`, but it counts every undelivered occurrence and does not identify re-drives). You cannot see from the product whether a redelivery is in flight, so do not delay the fix for it; restarting after the fix restores protection for later commands.
4. **Expect up to about 45 seconds** between the restart and the count dropping (the agent sends its first heartbeat one interval after it starts, 30 s by default, then the server sweeps every 15 s), and about 5 minutes more for the alert to resolve, so it can still fire for an agent that was just fixed. If the agent stays offline for more than 90 seconds it leaves the count without having been fixed, which looks the same as a fix.
5. **"Resolved"** means the agent is back, counted in `yuzu_fleet_agents_dedup_reporting`, with `store_degraded` at 0.

**Known gap:** an agent that recovered from a *corrupt* store (see "Corrupt store recovery" above) loses its replay history but is not degraded, so none of the gauges above counts it. It reports the per-process `yuzu.dedup_quarantined` heartbeat tag, which the server does not read and which returns to 0 when the agent restarts while the quarantined files stay on the endpoint. A fleet gauge for it needs a restart-surviving marker designed together with its consumer (tracked in #6933).

## Device Quarantine

Device quarantine isolates a compromised or suspicious device by blocking all of its network
traffic except the Yuzu server connection and what you list. The agent side is the `firewall`
plugin's four containment actions; the server side is the quarantine record (`QuarantineStore`),
the dispatch gate below, and a reconciler that keeps the two in step.

| Action | What it does |
|---|---|
| `firewall.quarantine` | Applies the containment: loopback, the agent's own control channel to the server, DHCP, DNS to the host's configured resolvers, IPv6 neighbour discovery and your exceptions stay reachable; everything else is blocked |
| `firewall.release` | Removes the containment and restores the firewall state captured at apply time |
| `firewall.quarantine_status` | Reads the containment from the device's record and its live firewall; never waits behind a mutation |
| `firewall.quarantine_allow` | Adds or removes exceptions on an active containment |

The plugin uses platform-native firewalling: the Windows Firewall API (a rule group plus a
per-profile default-block), an own `nftables` table (an `iptables`/`ip6tables` chain when `nft` is
absent) on Linux, and an own `pf` sub-anchor on macOS. See the plugin's README for the per-OS
mechanism, the reply rows and the limits.

### Quarantining a device

`POST /api/v1/quarantine` writes the record; the server's reconciler then dispatches the stored
whitelist to the device within about one tick of it being connected. The MCP `quarantine_device`
tool writes the record **and** dispatches at once. You can also run `security.firewall.quarantine`
through the execution routes, but a dispatch outside the quarantine routes is not tied to a record
(see "What confirmed means" below).

```bash
curl -s -X POST http://localhost:8080/api/v1/quarantine \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "compromised-agent-id", "reason": "malware", "whitelist": "10.0.0.5"}'
```

### The whitelist (read this before quarantining a dual-stack host)

The whitelist is a comma-separated list of **bare IPv4 or IPv6 addresses, at most 32**. Each address
is sent to the plugin as an outbound and an inbound exception. A port, a prefix length, an
IPv4-mapped form (`::ffff:1.2.3.4`), an IPv4 octet with a leading zero or a host name is refused
with `400`; nothing is silently dropped. Containment covers **both address families**: a v4-only
whitelist leaves IPv6 fully contained.

- There is no blanket "keep existing connections alive" rule on Linux: only an allowed address's
  traffic survives, in any connection state. The agent allows its own control channel: the address it
  is connected through when the quarantine is applied (published by the agent daemon from the
  authenticated stream, never resolved on the contained host) plus every address the configured
  server name resolved to **once, at agent startup**, on the server's port. **Configure `--server` as
  an IP literal** on endpoints where containment integrity matters most, which removes the resolver
  from the trust boundary entirely.
- If the agent reaches the server by a path the startup resolution did not see (a split-horizon
  setup, a pinned route, a server re-addressed after the agent started), **add the server's address
  to the whitelist explicitly**: a contained device whose control channel is blocked needs
  out-of-band recovery.
- On macOS, `quarantine_allow` reloads the plugin's own anchor and flushes pf states once, so
  connections the allow set does not cover are cut and **are not restored by a release**.
- A device that cannot reach the server needs out-of-band recovery. When in doubt, whitelist both
  families for the management server.

### Reading the result honestly

The plugin reports on two channels: the `status|<token>[|<reason>]` row in the output, and the ABI
result status a generic consumer sees. Neither says "clean" for a containment that is partial,
unenforced or unreadable.

| `status\|` token | Meaning | What to do |
|---|---|---|
| `active` | Containment is in force and the block was verified (the control channel answers, a probe target is blocked) | Nothing |
| `active_unproven` | In force, but not proven: no probe target was given, or a verification failed | Treat as contained; supply a `probe_target` to prove it |
| `inactive` | No containment | After a release, nothing; for a record that should be contained, the device is **not** |
| `partial` | Contained but incomplete (a rule that would not disable, a stale rule, a state flush that failed, an operation in progress) | Treat as **not fully contained**; the `note\|` rows name the residue |
| `degraded` | The host no longer enforces what the record says (a reboot, a flushed table, pf switched off, a Group Policy that took over) | The reconciler re-applies it; check the reason |
| `refused`, `rolled_back`, `update_failed` | Nothing was changed, the first apply was undone, or an update failed | Read the reason token |
| `busy` | Another containment change held the serialization gate for 2 seconds | Retry |

Linux on the **packaged systemd unit** (`NoNewPrivileges`, no sudoers grant) refuses every mutating
action `refused|privilege_unavailable`: `sudo` cannot elevate there, so a record on such a host stays
unconfirmed and cannot be released from the server except by a forced end (below).

A result is a claim about firewall rules, not proof that traffic is blocked. For a device you
believe is actively hostile, confirm with an independent probe.

### Checking status

```bash
curl -s -X POST http://localhost:8080/api/v1/commands \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"plugin": "firewall", "action": "quarantine_status", "agent_ids": ["agent-id"]}'
```

### What confirmed means

The server **confirms** a record from `firewall.quarantine_status`: `status|active`, or
`status|active_unproven` when the reply carries no `note|probe_target=` row (the server sends no probe
target, so its own applies always read unproven; where a probe target is stored on the device, only a
verified proof confirms). Confirmed means **the device reports its rules in force and enforcing**:

- it is the target agent's own self-report (bound to its certificate identity, so another agent cannot
  forge it, but not independently corroborated by any network-side signal);
- it is **not a reachability proof**;
- the server does **not compare** the device's allow-list with the stored whitelist: a
  `firewall.quarantine_allow` sent outside the quarantine routes changes the device and not the record,
  and the record still reads confirmed;
- the one difference the device itself reports is on a **new record for a device that is already
  contained**. `firewall.quarantine` to a contained device keeps the exceptions already in force, and
  when the request's exceptions differ from them (as a set, order aside) the reply carries
  `note|allow_set_unchanged_use_quarantine_allow=1`. For a record that has never been confirmed the
  server then does **not** confirm it and does not read status: the device is contained, but not under
  this record's whitelist. The record stays unconfirmed, one `quarantine.reapply` failure row
  (`allow_set_not_applied record_id=<id> command_id=<id>`) is written, and
  `YuzuQuarantineEndpointUnconfirmed` fires after its usual delay. **The new whitelist is still not on
  the device.** To get it there, release the device and quarantine it again (the release ends the record
  once the device confirms, and the new quarantine then applies the whitelist to a device that holds no
  earlier exceptions). A record that was confirmed once keeps the behaviour above: later allow-list
  drift is not detected.

### Releasing a device

`DELETE /api/v1/quarantine/{agent_id}` asks the device to lift its rules and waits up to 5 seconds:
`200` when the device answers `status|inactive`, `202` otherwise. **A record ends only on the device's
word, or by an operator's forced end** (below). Until then it
reads `releasing`, stays listed, and keeps the dispatch refusal, so a device that still holds the
containment is never treated as free. The reconciler reads the device's status first (`inactive` ends
the record), otherwise sends `firewall.release` and reads status again, and no answer to the release
itself ends anything. A record that cannot finish stays listed with commands refused until it is forced,
and `YuzuQuarantineReleasePending` fires after 15 minutes for a connected device.

**The two ways a record ends, and no other:**

1. The device answers `status|inactive` to a release (audit `quarantine.disable`, `confirmed`).
2. An operator forces it with `DELETE ...?force=true` (audit names the operator and `reason=forced`).

A device that reads `inactive` while its record is **active** ends nothing: it is read as drift (one
`quarantine.reapply` failure row, `drift status=inactive`) and containment is re-applied. A time limit
set on the device by a `firewall.quarantine` dispatch outside the quarantine routes (`ttl_seconds`) does
not end the record either; the quarantine routes set no time limit.

**Forced end (`?force=true`, REST only).** Use it for a device that will not return, or one that cannot
finish a release (such as the Linux packaged unit, which refuses mutation). Authority is the release's
own: scoped `Security:Execute`, the same-principal check and the dispatch check for `firewall.release`.
It **does not release the device**: the device may still be contained, the server stops refusing
commands to it, the reconciler sends the release it owes once per reconnect and then parks the device
after one unconfirmed cycle (`yuzu_server_quarantine_forced_release_owed` counts them; no alert fires
on it), and an operator can send `firewall.release` through the generic routes at any time. A device
whose firewall plugin does not load cannot be released from the server at all (#7444).

Until the device confirms that owed release, **the release lifts whatever containment the device holds,
including one applied directly with `firewall.quarantine` after the forced end.** A containment sent
outside the quarantine routes is not recorded, listed, re-applied or protected by the server. To keep
the device contained, quarantine it again through the quarantine routes: the new record stops the owed
release.

### Containment from the Hardware page

> **Hidden in this release.** The Hardware page controls described below (pill, panel, banner and
> Containment tab) are not shown until an approval workflow lands; REST and MCP are unchanged.

- **Quarantined devices** panel on `/hardware` lists the active records you may read (newest first,
  at most 200) with who quarantined the device, when, why, the whitelist and how far containment has
  been shown to reach it: *Recorded*, *Applied, not confirmed*, *Confirmed on device at the last status
  read* (point-in-time) or *Releasing: waiting for the device to confirm*. A read that cannot be
  completed is a banner, never "no device is quarantined".
- A **Quarantined** pill marks rows on the Hardware list; the record header carries a banner while the
  device has an active record. Instructions to a quarantined device are withheld until it is released;
  Sync now still works.
- The record's **Containment** tab offers **Quarantine device** and **Release device**. Both call the
  REST routes and need `Security:Execute` on the device. They run the dispatch approval check for the
  `firewall.quarantine` and `firewall.release` pairs before any record is written or release requested:
  the caller must be an administrator or carry an approved request. REST has no ticket path today, so
  with RBAC on a non-administrator who holds `Security:Execute` on the device is refused `403`
  (`approval_required`), and a caller who holds it only through a management group `403` (`forbidden`).
  A refused request writes no record and the record stays as it was. There is no forced end in the UI
  or on MCP.
- The release dialog says the record ends when the device confirms, and that an offline device is
  released when it next connects.
- An offline device can be quarantined: the record is stored now and applied when the device next
  connects.
- **The Actions lens.** While the containment UI is hidden, the Actions lens does not list the four
  firewall containment actions (they are controls for the quarantine); `firewall.state` and
  `firewall.rules` stay listed.

**Diagnosing an unexpected `403` on quarantine creation or release.** Search the audit log for action
`quarantine.enable` (create) or `quarantine.disable` (release), result `denied`, target type
`Security`, target id the device's agent id; `detail` holds `reason=<label> securable=<name>`. A
`denied` row whose `detail` is `authenticated principal changed during the request now=<account>` is a
session that changed between the route's two look-ups. A refusal by the per-device scoped permission
gate (the caller has no `Security:Execute` on the device) is audited by that gate, not under
`quarantine.enable`. `yuzu_server_dispatch_denied_total{reason}` shows the fleet-wide trend only.

| Reason label | What it means | What to do |
|---|---|---|
| `approval_required` | RBAC is on and the account role is not `admin` (the RBAC `Administrator` role alone does not count) | Use an administrator account |
| `forbidden` | The caller's own `Security:Execute` grant is not global (group-only, or administrator only through a JIT elevation), or the RBAC store could not be read | Grant it globally, or retry if the store was unavailable |
| `unclassified`, `ambiguous` | The containment action could not be matched to one catalogue entry | Report it: this is a defect, not a permission problem |
| (a `500`, no label) | The dispatch check is not wired on this server | Report it; the route fails closed and writes no record |

### Quarantine now blocks instruction dispatch (#881)

A quarantined device is refused at the **server's dispatch chokepoint**, not only at its own
firewall: any instruction targeting it, by id, by scope, by management group or by broadcast, is
dropped before it reaches the agent, and the refusal is audited as `quarantine.dispatch_denied`.

Two consequences worth planning for:

- **The firewall plugin's four containment actions are exempt**: `quarantine`, `release`,
  `quarantine_status` and `quarantine_allow` still reach a contained device, so release stays possible.
  The exemption is keyed on the `(plugin, action)` pair, so `firewall.state`, `firewall.rules` and any
  later action are gated. These four actions, and the Guardian rule push `__guard__.push_rules`, are also
  exempt from the per-plugin/action kill switch, the per-OS kill switch (and its agent-presence read),
  the plugin-presence filter and a degraded plugin-config store, so none of them can strand a contained
  device. **A plugin-level `firewall` kill-switch row never stops those four and still stops `state`
  and `rules`**, so `protective_exempt=partial` on that row means "covers a protective action", not "gates
  nothing". A kill-switch row for one of these pairs is still accepted and displayed, but it is
  informational only. To stop Guardian rule delivery during an incident, disable or remove the rules
  instead; see [Guaranteed State](guaranteed-state.md#baselines--how-guards-reach-agents).
- **Four server-internal pushes are also exempt, and you should know they exist.** The Echo
  fleet-topology snapshot request (`echo.fleet_snapshot`), the Guardian rule push
  (`__guard__.push_rules`), the asset-tag sync (`asset_tags.sync`) and the on-demand inventory sync
  (`__sync__.now`) continue to reach a contained device. This is deliberate (gating the Guardian push
  would stop a quarantined device receiving the enforcement rules that make containment meaningful),
  but it means the containment boundary is not total. They are a closed set in code
  (`SystemReservedPush`) counted by `yuzu_server_system_reserved_push_total{capability,result}`. **They
  are counted, not audited.** **Nothing outside that set and the four containment actions reaches a
  quarantined device.**

  | Channel | What it can do on a contained device |
  |---|---|
  | `echo.fleet_snapshot` | Requests a read-only topology/process snapshot. No state change. |
  | `asset_tags.sync` | Writes device tags. No code execution. |
  | `__sync__.now` | Requests an on-demand inventory sync: it arms the agent's existing sync scheduler and nothing else. |
  | `__sync__.settings` | Delivers the software collection settings that apply to the device: how often installed software is collected, in which window, and which collectors run. It changes only the agent's own collection schedule and collector switches, and the agent refuses any document that is not exactly the expected shape. No code execution. |
  | `__guard__.push_rules` | Delivers Guardian baseline rules, which the agent may *enforce*. Enforcement is **not arbitrary command execution**. |
- **If containment state becomes unreadable, dispatch fails closed**: the server refuses *every* target
  rather than guess who is contained. A short store outage is absorbed by a 60-second last-known-good
  snapshot; past that, instruction dispatch stops fleet-wide until the store recovers. Alert on
  `yuzu_server_quarantine_gate_total{outcome="fail_closed"}` (see [Metrics](metrics.md)): that series is
  an outage signal, not a quarantine signal.

### Reconnect re-application (#3425), re-verify and drift

A device quarantined while **offline** is contained at the control plane immediately (the gate above
refuses it), but its own firewall cannot be touched until a dispatch reaches it. The
`QuarantineContainmentReconciler` closes that automatically. For every record not yet confirmed:

- **Trigger.** A heartbeat from the device (the fast path) or a periodic ~20-second tick (the
  backstop). Deliberately **not** agent registration itself: the command stream does not exist yet
  there. Full confirmation is a state machine (apply, a follow-up `firewall.quarantine_status` after a
  short grace window, confirm), so it spans a few heartbeat intervals from reconnect to a confirmed
  record.
- **What it dispatches.** The **stored** whitelist, mapped to the plugin's `exceptions` (`<ip>/out,<ip>/in`
  per address): the same rule the MCP `quarantine_device` retry path follows, because dispatching
  anything else would silently rewrite a contained device's allow-list with no store update and no
  audit trail. It never dispatches a quarantine for a releasing record. A stored whitelist the mapper
  refuses is not sent: it is audited (`quarantine.reapply` failure, the value never echoed) and counted
  `validation_failed`.
- **Re-verify and drift.** A confirmed record is re-read every 5 minutes while its device is connected,
  and stays confirmed meanwhile (the unconfirmed gauge and its alert do not blink); the CONFIRMED audit
  row is written once per transition. A re-verify that no longer confirms is **drift**: one
  `quarantine.reapply` failure row (`drift status=<name>`), then the next cycle re-applies through the
  same chokepoint. A device whose live session changes (a reboot) re-verifies via status first, and a
  record that is replaced (released and re-quarantined while the agent stayed connected) resets to a
  fresh apply. A confirm is checked against the session that was live when the verifying status was
  sent. A restarted server applies first (its in-memory state starts empty), then reads status.
- **A new record on a contained device.** See "What confirmed means": when the device says it kept
  other exceptions, a record that was never confirmed is left unconfirmed, audited and alerted, and the
  remedy is a release followed by a new quarantine.
- **Release driving.** See "Releasing a device" above.
- **The owed release.** A record ended by force before the device confirmed stays on a list until the
  device does. Per agent session the reconciler reads status (`inactive` clears it, audited
  `forced_release_confirmed`), otherwise sends `firewall.release` once (and only while a fresh read shows
  no active record for the device: a device quarantined again is governed by its new record), reads
  status again, and, if the device still does not read `inactive` after a release it answered, writes one
  `forced_release_unconfirmed` failure row and parks it: a status-only read every 15 minutes and a new
  release only on a new session. A `busy` answer (the device's mutation gate was held, so the release
  did not run) does not spend the session's release: the reconciler waits an escalating backoff, reads
  status and sends the release again, so a gate that stays busy costs at most one release and one
  `forced_release_sent` row per 15 minutes.
- **Audit.** `quarantine.reapply` (`principal: system`): `record_id=<id> command_id=<id>
  trigger=tick|heartbeat` per apply, `CONFIRMED ...`, `drift ...`, `allow_set_not_applied ...`. `quarantine.disable`: the release
  rows described in the audit log reference. `record_id` is the internal `QuarantineRecord::id`, so a
  release-then-requarantine race stays distinguishable.
- **Observability.** `yuzu_server_quarantine_endpoint_unconfirmed{reachability}`,
  `yuzu_server_quarantine_release_pending{reachability}` and
  `yuzu_server_quarantine_forced_release_owed{reachability}` are per-replica gauges, never summed across
  instances; `offline` is expected and not alerted on, a sustained `connected` count is the signal
  (`YuzuQuarantineEndpointUnconfirmed`, `YuzuQuarantineReleasePending` in [Metrics](metrics.md)).
  `yuzu_server_quarantine_reapply_total{result}` breaks down every outcome (`reapplied`, `confirmed`,
  `unconfirmed`, `busy`, `offline`, `not_reached`, `rate_limited`, `pending`, `degraded`,
  `validation_failed`, `dispatch_error`, `release_sent`, `released`).
  `yuzu_server_quarantine_reconciler_tick_healthy` (0/1) distinguishes an empty queue from a tick that
  could not read at all: check it first when a gauge looks suspiciously static.

**Known limitation.** A release request landing at the exact moment the reconciler is mid-apply for the
same device can end with the apply arriving after the release, in one of two ways:

- The apply lands while the record still reads releasing: the release_pending guard and the
  status-first rule make the next cycle correct it, but for up to one cycle the device can be contained
  under a record that reads releasing.
- The release completes first and the apply lands after it: the device is firewalled and **no record
  names it**. Nothing re-reads it, so nothing corrects it. The only trace is a `quarantine.reapply`
  failure row in the audit log, `dispatch accepted record_id=<id> command_id=<id> but the durable stamp
  failed: device is not quarantined`, and the way back is `firewall.release` sent through the generic
  command routes.

The release a `DELETE` sends and the owed release both check the record and then dispatch, so each has the
same narrow window against a new quarantine of the same device (the new record's re-verify corrects it
within 5 minutes). The same outcome follows when a release sent earlier is run by the device after a later
record's apply, because commands are not ordered on the device: the new record can be confirmed and the
device then released, uncontained until the re-verify re-applies it. If you release and immediately re-quarantine the same device with a different
whitelist, a follow-up `firewall.quarantine_status` check is a reasonable sanity step. Tracked for a
proper fix (a claim or generation token on the active record).

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

**Domain checks and the Windows DNS cache.** On Windows a `domains` check reads the resolver cache once per command. If the cache cannot be read (the DNS API is unavailable, or returns failure, which some Windows 11 builds do on every call), the result is marked **constrained / partial** with provenance `windows:ioc:dns_cache_unreadable`, and each domain row says `DNS resolver cache could not be read`. Treat that as **unknown, not clean**: a constrained domain answer says nothing about whether the endpoint resolved the domain. Earlier builds reported `Not in DNS cache` in this case. At most 100 domains are accepted per command; more is refused whole with `error|domains|false|Too many domains (N, max 100)`.

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

When using OIDC (for example with Keycloak or Microsoft Entra ID):
- Set `--oidc-admin-group` to restrict admin access to a specific group
- Use `--session-timeout` to limit session duration
- Configure the OIDC provider to require MFA
- Restrict the app registration to your tenant (single-tenant)
- Rotate the client secret regularly
- **Use an `https` issuer only, and never `--oidc-skip-tls-verify` outside a lab.** The server fetches the issuer's JWKS and trusts it as the signature key for every ID token, and sends the client secret to the token endpoint, both over the issuer's own scheme. With an `http://` issuer, or with TLS verification off, anyone who can sit on the network path (or poison the issuer's DNS name) can substitute the keys and mint a sign-in for any user, up to the administrator group, and can read the client secret. The server logs a warning for an `http://` issuer on a non-loopback host. Plain `http://` to a PUBLIC address is refused outright (no switch; the error is `plain http is not permitted to a public address`), which closes the internet man-in-the-middle case; `http://` to a loopback or private address is allowed only with `--oidc-allow-private-networks` and stays exposed to anyone on that network path (keys, token response and client secret in the clear), so it is a lab setup.
- **Egress control.** The server's OIDC requests (discovery, JWKS, Test Connection, token POST) go to hosts the IdP's discovery document names, and Test Connection goes to whatever issuer an administrator types. Each request is resolved by the server, every resolved address is classified, and the connection is pinned to a permitted address (Windows token POST: pre-checked only, strictly: one refused address in its answer refuses the request; see below). Link-local addresses (the cloud metadata address `169.254.169.254` included), the other listed cloud metadata addresses, multicast and unspecified addresses are always refused (Oracle Cloud's `192.0.0.192` is not listed: it lies in the `192.0.0.0/24` special-purpose block that `--oidc-allow-private-networks` admits). Loopback, RFC 1918, carrier-grade NAT and IPv6 unique-local addresses are refused unless the server operator starts the process with `--oidc-allow-private-networks`, which no dashboard or REST caller can set. Leave it off unless your IdP is on an internal network. Residual: on Windows the token POST resolves its name again inside WinHTTP, so DNS rebinding between the check and the connect is not covered for that one request (that request does not follow redirects and accepts only HTTP status 200, so a 3xx cannot move it to an unchecked host or be taken for a token response; host names must be ASCII, with an internationalized name given as punycode); there is no per-host allow-list and no HTTP proxy on the discovery and JWKS path (the Windows token POST uses the system default proxy). NAT64: an IPv6 address inside a NAT64 prefix is classified by the IPv4 address embedded in it (every RFC 6052 section 2.2 layout), so `Pref64 + 169.254.169.254` is refused as link-local. SIIT (`::ffff:0:0:0/96`) and IPv4-compatible (`::/96`) addresses are classified by the IPv4 address they embed too, never as more open than non-global, and plain http to such a form of a public address is refused by the cleartext rule; a local-use NAT64 address (`64:ff9b:1::/48`) that no configured or learned prefix covers is refused whatever the switch says. The server learns prefixes from RFC 7050 (it resolves `ipv4only.arpa`, only when a request is about to be pinned to an otherwise permitted IPv6 address, and repeats the lookup after 10 minutes, or 1 minute when it learned none; a learned prefix is only ever added to the set and kept until restart, never forgotten by a later answer, and an answer that would take the set past 64 prefixes refuses the fetch instead of being installed partially) and from `--oidc-nat64-prefix`; a failed lookup means "none discovered" and does not fail the request. On Linux and macOS the OIDC name lookups run in a pool of 16 slots (gauge `yuzu_server_oidc_resolver_in_flight`), a lookup the resolver does not finish keeps its slot until the resolver returns, and further lookups fail closed at once while the pool is full, while the name already has 8 lookups outstanding, while lookups for 64 names are outstanding, when the admission check does not complete, and for 3 s after a lookup of the same name was refused or timed out (a refusal is never an allow; the pool, the name limit and the memory are per server process, so under high availability each replica has its own; the `ipv4only.arpa` prefix lookup is exempt from the name limit and the 3 s memory, and the pool's cap is its only bound); a known residual is that a failed or timed-out `ipv4only.arpa` prefix lookup is remembered as failed for 1 minute, during which IPv6 destinations are classified with the prefixes already learned (none on a fresh start; on a DNS64 network set `--oidc-nat64-prefix`); a translated private address inside a prefix the server has not learned is classified as public while the prefix lookup is unanswered, and while the probe is refused (the pool is full or no worker could be started), IPv6 destinations are classified with the prefixes already learned (none on a fresh start) and without a fresh probe, which is tried again on the next fetch. A configured prefix is trusted to describe a translator and may therefore permit a destination its own address class would otherwise gate; only the always-refused tier is never relaxed. Teredo, IPv6 benchmarking and the other non-global parts of `2001::/23` are refused unless the private-network switch is set, except the sub-ranges the IANA registry marks globally reachable. Residual: translators the server cannot see, that is a translator whose prefix is neither discoverable nor configured, a proxy, a VPN, or CLAT/464XLAT outside the host, can still map an address that classifies as public to a private destination; because TLS verification still uses the host name, such a path is limited to a blind TCP connect for `https`, and plain `http` to a public-looking (translated) address is refused by the cleartext rule above. See [Authentication -> Network and trust](authentication.md#network-and-trust). **Operator warning:** a configured prefix asserts that a NAT64 translator lives there and can permit HTTPS connections to ULA addresses even when `--oidc-allow-private-networks` is off; declare only actual translation prefixes (native IPv6 services inside a declared prefix get the same embedded-IPv4 classification; always-refused addresses remain blocked).

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
