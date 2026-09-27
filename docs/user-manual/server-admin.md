# Server Administration Guide

This document covers Yuzu server deployment, configuration, and ongoing administration. It is intended for operators who install, configure, and maintain the Yuzu server.

---

## Table of Contents

1. [Server CLI Flags](#server-cli-flags)
2. [Configuration Files](#configuration-files)
3. [First-Run Setup](#first-run-setup)
4. [Settings Page](#settings-page)
5. [TLS Configuration](#tls-configuration)
6. [User Management](#user-management)
7. [Agent Enrollment](#agent-enrollment)
8. [OTA Agent Updates](#ota-agent-updates)
9. [RBAC Management](#rbac-management)
10. [Tag Compliance](#tag-compliance)
11. [OIDC SSO Configuration](#oidc-sso-configuration)
12. [SAML 2.0 SP Configuration](#saml-20-sp-configuration)
13. [Directory Sync (AD/Entra ID)](#directory-sync-adentra-id)
14. [Data Storage and Encryption](#data-storage-and-encryption)
15. [PostgreSQL Substrate](#postgresql-substrate)
16. [NVD CVE sync](#nvd-cve-sync)
17. [Retention Settings](#retention-settings)
18. [Settings API Reference](#settings-api-reference)
19. [Deployment](#deployment)
20. [Windows Service Installation](#windows-service-installation)
21. [Planned Features](#planned-features)

---

## Server CLI Flags

The Yuzu server binary accepts the following command-line flags. All flags are optional; defaults are shown in the table.

| Flag | Default | Description |
|---|---|---|
| `--config` | *(auto)* | Path to `yuzu-server.cfg`. If omitted, uses the platform default: `/etc/yuzu/yuzu-server.cfg` on Linux (and on macOS as root), `~/Library/Application Support/Yuzu/yuzu-server.cfg` on macOS as a non-root user, `C:\ProgramData\Yuzu\yuzu-server.cfg` on Windows. |
| `--data-dir` | *(config dir)* | Directory for runtime state files (enrollment tokens, pending agents, auto-approve rules) and the NVD CVE cache `nvd_cves.db`, the one remaining server SQLite store, plus the `agent-updates/` (unless `--update-dir` is set) and `upload-blobs/` file directories. All other server data is in PostgreSQL. Defaults to the parent directory of `--config`. Use this in containerized deployments where the config file is on a read-only mount but state files need a writable volume. The path is resolved to its canonical form at startup (symlinks are followed). Env: `YUZU_DATA_DIR`. |
| `--web-port` | `8080` | HTTP listen port for the dashboard and REST API. |
| `--web-address` | `127.0.0.1` | Web UI bind address. |
| `--shutdown-drain-seconds` | `0` | On `SIGTERM`, keep serving for at least this many seconds after `/readyz` turns `503 draining`, so a load balancer stops routing here before the listener closes (HA WS-8). Range 0–60; `0` keeps the listener-closes-at-once behaviour a single server has always had. Set it to at least the load balancer's health-check interval × unhealthy threshold, plus one interval — see "Load balancers and shutdown drain" below. Env: `YUZU_SHUTDOWN_DRAIN_SECONDS`. |
| `--no-https` | off | Disable HTTPS (insecure, for development only). HTTPS is **enabled by default**; provide `--https-cert` and `--https-key`, or pass `--no-https` to disable. Env: `YUZU_NO_HTTPS`. |
| `--no-tls` | off | Disable **all** gRPC TLS (agent listener AND management listener). Plaintext gRPC, no encryption, no peer authentication. **The administrative surface is ungated when this flag is passed.** Intended for local UAT, customer demos, and development. The server emits a multi-line ERROR-level startup banner and a 5-minute recurring reminder when running in this mode. |
| `--cert` | *(none)* | Path to PEM-encoded gRPC server certificate for the **agent listener** (port 50051 by default). Env: `YUZU_CERT`. |
| `--key` | *(none)* | Path to PEM-encoded gRPC server private key for the agent listener. The file must not be world-readable (Unix: `chmod 600`). Env: `YUZU_KEY`. |
| `--no-default-certs` | off | Do **not** auto-generate built-in default certificates on first boot. Restores the legacy refuse-to-start: the server will not start unless `--cert`/`--key` (and `--https-cert`/`--https-key` when HTTPS is enabled) are supplied. Use where operator- or HSM-provided certs are mandatory policy. (Defaults emit a startup banner, the audit actions `server.default_certs_generated` + `server.default_certs_in_use`, and the Prometheus gauge `yuzu_server_default_certs_active`.) Env: `YUZU_NO_DEFAULT_CERTS`. |
| `--ca-dir` | *(platform cert dir)* | Directory for the built-in CA root + default leaf certs (`default-ca.pem`/`.key`, `default-server.pem`, `default-https.pem`, …). Default: `/etc/yuzu/certs` (Linux; macOS running as root — matches the packaged-install convention), `~/Library/Application Support/Yuzu/certs` (macOS running as a non-root user — e.g. a native `scripts/start-UAT.sh` dev run, since `/etc/yuzu` is root-owned and macOS has no packaged server installer), `C:\ProgramData\Yuzu\certs` (Windows). The CA root key is `0600` — back it up (losing it forces a full fleet re-enrollment). Env: `YUZU_CA_DIR`. |
| `--cert-san` | *(none)* | **Repeatable.** Extra Subject Alternative Name to add to *every* auto-generated default leaf (dashboard HTTPS, agent/management gRPC, and gateway), on top of the base `localhost` / `127.0.0.1` / `::1` / `<hostname>`. Forms: `dns:<name>`, `ip:<addr>`, or a bare value (auto-classified as IP vs DNS by shape); a single value may be comma-separated. Use this so the built-in certs validate for a name a client actually dials — e.g. `--cert-san dns:gateway` so an agent reaching the gateway by that service name passes TLS hostname verification, or `--cert-san dns:yuzu.corp.example --cert-san ip:10.0.0.5` for a load-balancer name / VIP. An `ip:` value that is not an IP literal is ignored with a warning. **Ignored** when operator certs are supplied or `--no-default-certs` is set; **changing it does not rotate an existing cert set** — clear `--ca-dir` (or replace the certs) for new SANs to take effect (in a container the cert dir lives in the image layer unless a volume is mounted there, so *recreate* the container — a restart alone won't regenerate). Env: `YUZU_CERT_SAN`. |
| `--ca-cert` | *(none)* | Path to PEM-encoded CA certificate used to verify agent client certificates (full mTLS). Without this, the agent listener has no client-cert verification — `--insecure-skip-client-verify` plus `YUZU_ALLOW_INSECURE_TLS=1` is required to start in that posture. Env: `YUZU_CA_CERT`. |
| `--insecure-skip-client-verify` | off | Allow gRPC TLS without `--ca-cert` (one-way TLS — server cert is presented but client certs are not verified). Applies to BOTH the agent listener and the management listener. **Requires `YUZU_ALLOW_INSECURE_TLS=1` in the environment as a second confirmation** — the server refuses to start without it. Renamed from `--allow-one-way-tls` in v0.12.0; the old name is still accepted with a deprecation warning. |
| `--allow-one-way-tls` | off | **[DEPRECATED]** Renamed to `--insecure-skip-client-verify`. Still accepted for backward compatibility with a startup deprecation warning; will be removed in a future release. |
| `--management-cert` | *(none)* | Optional PEM cert for the **management listener** (port 50052 by default). If unset, the management listener reuses the agent listener's certificate. |
| `--management-key` | *(none)* | Optional PEM key for the management listener. If `--management-cert`/`--management-key` are set without `--management-ca-cert`, the same `--insecure-skip-client-verify` + `YUZU_ALLOW_INSECURE_TLS=1` gate applies. |
| `--management-ca-cert` | *(none)* | Optional CA cert for management client cert verification. Without this (and without `--insecure-skip-client-verify`), the management listener refuses to start. |
| `--trusted-nat-cidr` | *(none)* | Comma-separated (or repeatable) CIDR ranges (IPv4 or IPv6) declaring a trusted NAT boundary for **direct-connect** agents. When an agent's Register and Subscribe source IPs *both* fall within one declared range, a per-session peer-IP mismatch is downgraded from a hard reject to an *advisory* (audit `result="ok" outcome=advisory`; counted on `yuzu_grpc_subscribe_peer_advisory_total`) instead of rejecting the stream. Strict exact-match is the default when absent; mismatches outside every declared range still reject (the stolen-session guard stays intact). Use for fleets behind multi-egress NAT, proxy pools, CG-NAT, or SD-WAN where an agent may egress from different public IPs on its two connections. **Security note:** declaring a range asserts the hosts in it are mutually trusted not to replay each other's sessions; keep ranges as narrow as possible (never `0.0.0.0/0`). Malformed entries are logged and ignored at startup. Env: `YUZU_TRUSTED_NAT_CIDR`. |
| `--nat-trust-mtls-identity` | off | Also downgrade a peer-IP mismatch to advisory when the Subscribe mTLS client identity matches the identity bound at Register (#1128). **SAFE ONLY WITH PER-AGENT CLIENT CERTIFICATES.** With a shared/fleet-wide client cert every identity "matches", turning this into a session-replay bypass (an insider agent could hijack another agent's session from its own IP). Off by default; enable only if each agent presents a unique client certificate. When both `--nat-trust-mtls-identity` and `--trusted-nat-cidr` are configured, mTLS-identity match takes precedence: a session whose mTLS identity matches records `reason=mtls_identity_match` (visible on the audit `detail` and the `yuzu_grpc_subscribe_peer_advisory_total{reason=...}` label), and CIDR containment is not consulted for that session. Enabling the flag emits a `warn`-level startup line — confirm it appears in the boot log so the operator who pulled the lever can sign off on the per-agent-cert posture. Env: `YUZU_NAT_TRUST_MTLS_IDENTITY`. |
| `--https-port` | `8443` | HTTPS listen port. |
| `--https-cert` | *(auto)* | Path to PEM-encoded TLS certificate for the dashboard. **A per-install default cert is auto-generated when omitted** (unless `--no-default-certs`); `--no-https` disables HTTPS entirely. |
| `--https-key` | *(auto)* | Path to PEM-encoded TLS private key. Auto-generated default used when omitted (unless `--no-default-certs`). The file must not be world-readable (Unix: `chmod 600`). |
| `--no-https-redirect` | off | When HTTPS is enabled, do not redirect HTTP requests to HTTPS. By default, HTTP requests are redirected. |
| `--no-cert-reload` | off | Disable automatic certificate hot-reload. By default, the server polls cert/key files and hot-swaps the SSL context when they change. Env: `YUZU_NO_CERT_RELOAD`. |
| `--cert-reload-interval` | `60` | Certificate reload polling interval in seconds. Minimum effective interval is 10 seconds. Env: `YUZU_CERT_RELOAD_INTERVAL`. |
| `--metrics-no-auth` | off | Allow unauthenticated `/metrics` access from any IP. By default, remote clients must authenticate; localhost access is always unauthenticated. **Warning:** enabling this exposes fleet composition data (OS, architecture, version counts) — and, when the cohort metrics export is enabled, **operator tag values** as `cohort` labels — to any network client. See [Metrics Security](metrics.md#security-considerations). Env: `YUZU_METRICS_NO_AUTH`. |
| `--csp-extra-sources` | *(none)* | Extra Content-Security-Policy source-list entries appended to `script-src`, `style-src`, `connect-src`, and `img-src`. Space-separated string of host/scheme expressions or whitelisted CSP keywords (`'self'`, `'none'`, `'sha256-...'`, `'sha384-...'`, `'sha512-...'`, `'nonce-...'`). The server **refuses to start** if the value contains control bytes, semicolons, commas, or unsafe CSP keywords like `'unsafe-eval'`. Use to whitelist customer CDNs, monitoring beacons, or analytics endpoints. See [HTTP Security Response Headers](security-hardening.md#http-security-response-headers). Env: `YUZU_CSP_EXTRA_SOURCES`. |
| `--oidc-issuer` | *(none)* | OIDC identity provider issuer URL (e.g., `https://login.microsoftonline.com/{tenant}/v2.0`). Env: `YUZU_OIDC_ISSUER`. |
| `--oidc-client-id` | *(none)* | OIDC application (client) ID. Env: `YUZU_OIDC_CLIENT_ID`. |
| `--oidc-client-secret` | *(none)* | OIDC client secret. Env: `YUZU_OIDC_CLIENT_SECRET`. |
| `--oidc-redirect-uri` | *(auto)* | OIDC redirect URI. If omitted, auto-computed from the web address and port. Must match the registered redirect in your identity provider. Env: `YUZU_OIDC_REDIRECT_URI`. |
| `--oidc-admin-group` | *(none)* | Entra ID group object ID that maps to the admin role. Users in this group are granted admin access on OIDC login. Env: `YUZU_OIDC_ADMIN_GROUP`. (Value is trimmed automatically, same as `--saml-admin-group` — #1830.) |
| `--oidc-skip-tls-verify` | off | Disable TLS certificate verification for OIDC endpoints. **Insecure — dev only.** Env: `YUZU_OIDC_SKIP_TLS_VERIFY`. |
| `--oidc-scim-link-claim` | `sub` | ADR-2001 (SCIM↔OIDC identity linkage, CC6.8). Which validated ID-token claim is compared against a SCIM resource's `externalId` to form the durable link a SCIM deprovision revokes API/MCP tokens across. Only `sub` and `oid` are accepted — the server **refuses to start** on any other value. Okta: leave as the default `sub`. Microsoft Entra ID: set `oid` — Entra's SCIM `externalId` rides the ID token as the `oid` claim, not `sub`. See `docs/user-manual/scim-provisioning.md` "SCIM ↔ OIDC identity linkage". Env: `YUZU_OIDC_SCIM_LINK_CLAIM`. |
| `--saml-idp-entity-id` | *(none)* | **SAML 2.0 SP.** Entity ID URI of the IdP (must match what the IdP uses in its assertions). Required and validated at startup — omitting it (along with the other four `--saml-*` flags) leaves SAML disabled. Env: `YUZU_SAML_IDP_ENTITY_ID`. |
| `--saml-idp-sso-url` | *(none)* | **SAML 2.0 SP.** IdP's HTTP-Redirect SSO endpoint URL. Env: `YUZU_SAML_IDP_SSO_URL`. |
| `--saml-idp-cert` | *(none)* | **SAML 2.0 SP.** Filesystem path to the IdP's assertion-signing certificate (PEM, max 64 KiB). The cert at this path is the **sole** trusted signing authority — in-document `<KeyInfo>` values are ignored. Env: `YUZU_SAML_IDP_CERT`. |
| `--saml-sp-entity-id` | *(none)* | **SAML 2.0 SP.** Entity ID URI this SP advertises to the IdP in the AuthnRequest. Env: `YUZU_SAML_SP_ENTITY_ID`. |
| `--saml-sp-acs-url` | *(none)* | **SAML 2.0 SP.** Full public URL of the Assertion Consumer Service (`https://<host>/saml/acs`). The IdP must be configured to POST the response to this URL. Env: `YUZU_SAML_SP_ACS_URL`. |
| `--saml-sp-key` | *(none)* | **SAML 2.0 SP.** Filesystem path to the SP AuthnRequest signing private key (PEM, **RSA only** — EC and RSA-PSS keys are rejected). Optional and independent of the five required `--saml-*` flags above. When set, AuthnRequests are signed over the HTTP-Redirect binding with RSA PKCS#1 v1.5 + SHA-256. The key file must pass the same private-key permission check as the HTTPS/gateway TLS keys (not group/other-readable). Fails closed: an unreadable, over-permissioned, oversized (>64 KiB), malformed, or non-RSA key disables SAML entirely at startup — never a silent fall-back to unsigned requests. When unset (the default), AuthnRequests remain unsigned — backward-compatible with IdPs that accept unsigned requests. Env: `YUZU_SAML_SP_KEY`. |
| `--mcp-disable` | off | Disable the MCP (Model Context Protocol) endpoint entirely. When set, all requests to `/mcp/v1/` are rejected with a JSON-RPC error. Use this in air-gapped or high-security environments where AI integration is not desired. Env: `YUZU_MCP_DISABLE`. |
| `--mcp-read-only` | off | Restrict MCP to read-only tools only. Write and execute operations (Phase 2) are rejected even if the MCP token's tier would normally allow them. Env: `YUZU_MCP_READ_ONLY`. |
| `--mcp-no-streaming` | off | Disable the MCP **Streamable HTTP** transport (ADR-1005 Decision 15): no `Mcp-Session-Id` minting, `GET`/`DELETE /mcp/v1/` return `405`, and only plain JSON-RPC POST is served. The spec-required `202` status on notification POSTs still applies. Use where a buffering reverse proxy interferes with streaming. Env: `YUZU_MCP_NO_STREAMING`. |
| `--mcp-enable-streamed-post` / `--no-mcp-streamed-post` | on | Enable **SSE-on-POST** (streamed POST) for `execute_instruction` callers that supply a `progressToken`. **Ships ON** — the transport machinery is complete and reviewed, and the four defects that previously gated the on-by-default flip are fixed: #2739 (the 120 s response cap is now enforced on a busy execution — after it expires the bridge delivers one final drain of already-latched progress and then settles, bounding the response at the cap plus at most two ~3 s pump ticks plus one progress drain), #2740 (a committed-but-undelivered final no longer locks a session out of streaming — admission reclaims the slot and audits it), #2785 (streamed-POST frames now carry the replay-ring event id, so a POST-only client can build a `Last-Event-ID` resume cursor) and #2789 (end-to-end coverage of the per-principal admission reject). Pass `--no-mcp-streamed-post` to opt out. Distinct from `--mcp-no-streaming`, which disables the whole transport including the session lifecycle and GET channel. |
| `--mcp-allowed-origin` | *(none)* | **Repeatable.** An allowed `Origin` header value (`scheme://host:port`, exact match) for `/mcp/v1/` DNS-rebinding defence. An **absent** `Origin` is always allowed (the endpoint requires a credential); an **empty allowlist rejects any *present* Origin** (secure default) — browser-based MCP clients must be listed explicitly, non-browser clients need no configuration. Env: `YUZU_MCP_ALLOWED_ORIGINS`. |
| `--max-sse-streams` | `128` | **Concurrent held-open SSE responses this server is sized for, across EVERY streaming surface** — `GET /mcp/v1/`, MCP streamed POST, `GET /api/v1/events`, the dashboard executions drawer, and the legacy `/events` stream. The HTTP worker pool is derived *from* this number: cpp-httplib is thread-per-connection, so each held-open response pins one worker for its whole life. That thread burns no CPU, and its resident cost is a fraction of a stack reservation that is virtual and platform-dependent (8 MB on Linux/glibc, 1 MB on Windows, 512 KB for macOS secondary threads). The resident fraction itself is **not yet measured** on our platforms (ADR-0034), so treat the default as a starting point rather than a sizing guarantee until a per-platform baseline exists. Utilisation is `yuzu_http_held_open_responses / yuzu_http_held_open_capacity`. The ceiling is thread-count; see ADR-0034. Env: `YUZU_MAX_SSE_STREAMS`. |
| `--mcp-max-streams-per-principal` | `4` | Max concurrent MCP SSE streams for one principal. An **anti-monopoly policy, not a capacity limit** — capacity is `--max-sse-streams`. Stops a single agentic token taking the channel; does not ration the fleet. Env: `YUZU_MCP_MAX_STREAMS_PER_PRINCIPAL`. |
| `--http-worker-threads` | `0` (derive) | Pin the shared HTTP worker pool by hand. `0` derives it from `--max-sse-streams`, which is what you want. If you set it, the stream target is clamped to what your pool can actually carry (the startup log reports the effective figure). Env: `YUZU_HTTP_WORKER_THREADS`. |
| `--viz-disable` | off | Disable the fleet visualization feature. When set, the REST endpoints (`GET /api/v1/viz/fleet/topology`, `GET /fragments/viz/fleet/topology`, and the per-host drill-down routes) **and** the page shells (`GET /viz/fleet`, `GET /viz/host/<id>`) all return `503`. Tier-before-permission ordering: the kill switch takes effect even for callers who would otherwise fail RBAC. Two pieces of durable evidence that the switch took effect: the startup log line `[VIZ] viz endpoint disabled by configuration`, and a `server.viz_disabled` audit event (`target_type = FleetTopology`) written to the audit store at boot — so an auditor can confirm the disabled state from the audit trail even on a deployment with no viz traffic. Env: `YUZU_VIZ_DISABLE`. |
| `--allow-unsigned-packs` | off | **Dangerous.** Accept product packs at install without an Ed25519 signature. Default is to reject unsigned packs with `pack '<name>' is unsigned and signature enforcement is enabled (set --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1 to bypass)` (security-by-default since #802 / W7.4). Setting this flag restores the pre-W7.4 behaviour where any operator with pack-upload permission, or a MITM on pack delivery, could install a pack containing arbitrary `InstructionDefinition` or plugin payloads that would execute fleet-wide. Two pieces of durable evidence that the flag is active: a startup log line `[SECURITY] product pack signature enforcement DISABLED by configuration`, and a `server.unsigned_packs_allowed` audit event (`target_type = ProductPack`) written to the audit store at boot. Use only as a temporary migration aid; sign your packs and remove the flag as soon as feasible. Env: `YUZU_ALLOW_UNSIGNED_PACKS`. |
| `--allow-unsigned-definitions` | off | **Dangerous.** Accept `InstructionDefinition` imports via `POST /api/v1/instructions/import` without an Ed25519 signature. Default is to reject unsigned imports with `instruction-import is unsigned and signature enforcement is enabled (set --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1 to bypass)` (security-by-default since #1073 / W7.4 sibling-gap closure). Closes the equivalent fleet-RCE surface that `--allow-unsigned-packs` covers on the ProductPack side: without enforcement, any operator with `InstructionDefinition:Write` (or a MITM on a content sync) can publish a definition that dispatches a malicious plugin invocation on every targeted agent. Durable evidence: startup log line `[SECURITY] instruction-definition signature enforcement DISABLED by configuration` AND a `server.unsigned_definitions_allowed` audit event (`target_type = InstructionDefinition`). Env: `YUZU_ALLOW_UNSIGNED_DEFINITIONS`. |
| `--mfa-enforcement` | `optional` | MFA enforcement mode: `optional` (users may enroll voluntarily; login never requires it), `admin-only` (an admin without MFA must enroll before login completes), or `required` (every role must enroll). Under `admin-only`/`required` an un-enrolled login is redirected through TOTP enrollment (`POST /login/mfa/enroll`) before a session is minted; the server logs an `INFO` line naming the active mode at startup. **Breaking:** earlier releases accepted `admin-only`/`required` as no-ops — if you staged the flag, read `docs/user-manual/upgrading.md` before upgrading (live enforcement begins immediately, and SSO users require an IdP that asserts `amr`). See `docs/user-manual/authentication.md` § Multi-Factor Authentication and `docs/auth-mfa-design.md`. Env: `YUZU_MFA_ENFORCEMENT`. |
| `--mfa-step-up-window-secs` | `300` | Seconds after a successful TOTP proof during which 24 high-risk REST + Settings endpoints (PR2 of the MFA ladder, since extended) accept the session as "stepped up" without re-prompting. Set to `0` to disable the gate entirely (emits a startup `WARN`). Env: `YUZU_MFA_STEP_UP_WINDOW_SECS`. |
| `--mfa-login-pending-secs` | `120` | Lifetime of the intermediate `mfa_pending_token` between password success and TOTP submission. The pending state is per-process (lost on restart, not shared across HA replicas without sticky sessions). Env: `YUZU_MFA_LOGIN_PENDING_SECS`. |
| `--mfa-reset <username>` | *(none)* | **Break-glass.** Clears the named user's MFA enrollment and exits **without starting the server** — the recovery path from MFA-enforcement lockout. Writes an `mfa.reset.breakglass` audit row (principal = the OS account that ran the CLI). Requires the Postgres auth store (`--postgres-dsn` / `YUZU_POSTGRES_DSN`), and the same `--config` the service uses if it is not at the platform default (`/etc/yuzu/yuzu-server.cfg` on Linux and root macOS; `C:\ProgramData\Yuzu\yuzu-server.cfg` on Windows) — the container images run with `--config /var/lib/yuzu/yuzu-server.cfg`, and without it the binary falls into interactive first-run setup and exits. No TLS flags needed. See `docs/ops-runbooks/auth-db-recovery.md` § Emergency MFA disable. |
| `--auth-lockout-threshold` | `5` | Consecutive failed **local-password** login attempts before an account is temporarily locked (SOC 2 CC6.3). A locked account returns the **same generic 401** as a bad password — no enumeration/lock-state oracle. Counter resets on a successful login or an admin unlock (`POST /api/v1/users/{name}/unlock`). Scope is local-password only — OIDC/SSO sessions and API tokens are unaffected. Setting `0` **disables** lockout (startup `WARN`) and constitutes a deviation from the CC6.3 hardened baseline — record it as a documented exception on your risk register, do not just flip it. NIST 800-63B §5.2.2 suggests allowing ≥10 attempts where network-layer rate-limiting is also present; raise the threshold accordingly if you front Yuzu with an IP throttle. Env: `YUZU_AUTH_LOCKOUT_THRESHOLD`. |
| `--auth-lockout-window-secs` | `900` | How long an account stays locked after the threshold is crossed. The lock **auto-expires** after this window — it is never permanent, so it cannot be weaponised to permanently deny a legitimate principal; a waited-out user regains a full attempt budget. Env: `YUZU_AUTH_LOCKOUT_WINDOW_SECS`. |
| `--jit-max-elevation-secs` | `3600` | **JIT admin elevation** maximum window (SOC 2 CC6.3/CC6.6). Caps the lifetime of a time-boxed admin elevation activated via `POST /api/v1/elevate`; a request asking for longer is clamped. Range 1–86400 (24h). Eligibility is the per-user `users.elevation_eligible` flag (admin-set via `POST /api/v1/users/<name>/elevation-eligibility`), elevation requires a fresh MFA step-up, and for Postgres-backed deployments the grant is **durably persisted** to the cookie session's `SessionStore` row (HA WS-1/1a, ADR-2002 §4), so it **survives a restart** — bounded by this 24h ceiling and the session's own absolute expiry, and auto-reverting on lapse, logout, or explicit revoke (config-file-only deployments keep the old in-memory-per-session behavior a restart drops). API/MCP tokens can never be elevated. Env: `YUZU_JIT_MAX_ELEVATION_SECS`. |
| `--jit-oidc-amr-elevation` / `--no-jit-oidc-amr-elevation` | `true` (enabled) | Whether an OIDC session whose IdP login attested MFA (the `amr` claim, seeding `Session::mfa_verified_at` at `/auth/callback`) can satisfy `POST /api/v1/elevate`'s mandatory second-factor requirement **without** local TOTP enrollment. An OIDC session never consults a local namesake account's TOTP enrollment — a single-factor (no-`amr`) OIDC session is **always** denied regardless of this flag. Pass `--no-jit-oidc-amr-elevation` to disable JIT elevation for OIDC sessions **entirely** — an OIDC session cannot present a local TOTP step-up (its step-up challenge is re-authenticating via SSO, not a TOTP code), so with the flag off an operator must switch to a local-authenticated session with local TOTP to elevate. A one-time INFO log line is emitted at boot when OIDC is configured and this flag is on. ⚠️ **This flag currently has no observable effect** — since the #1837/#1857 identity re-key, an OIDC session is denied JIT elevation at the eligibility gate (its `oidc:<iss>#<sub>` principal has no local `users` row), before the `amr` branch this flag controls is reached; OIDC elevation is restored by #1852. Env: `YUZU_JIT_OIDC_AMR_ELEVATION`. |
| `--session-inactivity-secs` | `0` | **Idle (inactivity) session timeout** (SOC 2 CC6.3). Seconds of inactivity after which an operator **dashboard cookie session** is invalidated server-side — a **sliding** window that resets on each authenticated request, *under* the absolute 8-hour session lifetime. `0` (default) **disables** it (only the absolute lifetime applies — existing deployments are unaffected); a recommended hardened value is `900` (15 min). Scope is cookie sessions only: **API tokens and MCP tokens are never idle-timed-out** (long-lived automation is unaffected); OIDC users simply re-authenticate via SSO. The active window is logged once at boot for evidence; a value ≥ the absolute 8-hour session lifetime (28800s) is accepted but elicits a startup `WARN` (the idle window can never fire before absolute expiry). Env: `YUZU_SESSION_INACTIVITY_SECS`. |
| `--auth-mode` | `standard` | Local-password login policy (SOC 2 CC6.3). `standard` = password login enabled. `sso-only` = **local-password login is disabled fleet-wide** — only an SSO provider mints a session — so the server **refuses to start** unless OIDC (`--oidc-issuer` + `--oidc-client-id`) or, on Linux/macOS with HTTPS enabled, a complete SAML SP config is present. A rejected local login returns the **same generic 401** as a bad password (no oracle) and is counted via the metric `yuzu_auth_local_disabled_total` (metric, not a per-attempt audit row — avoids audit-flood under credential spray). A single `--break-glass-user` is exempt while armed. Env: `YUZU_AUTH_MODE`. |
| `--break-glass-user <username>` | *(none)* | The single local account exempt from `--auth-mode=sso-only`, exempt **only while armed** (see `--break-glass-arm`). Under `sso-only` the server **refuses to start** unless this account exists and has **MFA enrolled** (a break-glass account must carry a second factor). A break-glass login is forced through MFA regardless of `--mfa-enforcement` and writes an `auth.breakglass.login` audit row. Env: `YUZU_BREAK_GLASS_USER`. |
| `--break-glass-window-secs` | `86400` | Seconds the break-glass account stays armed after `--break-glass-arm` (default 24h). The arm **auto-expires** (evaluated lazily at login like the lockout window) — it is never a permanent standing exemption. Env: `YUZU_BREAK_GLASS_WINDOW_SECS`. |
| `--break-glass-arm` | off | **Break-glass.** Arms `--break-glass-user` for the configured window and exits **without starting the server** — the recovery path when the IdP is down under `--auth-mode=sso-only`. Run on the server host as the service account (arming deliberately does **not** require a session). Validates the account (exists + MFA), verifies the audit store is writable **before** arming, and writes an `auth.breakglass.armed` audit row (principal = the OS account that ran the CLI). Requires `--break-glass-user` + the Postgres auth store (`--postgres-dsn` / `YUZU_POSTGRES_DSN`), and the same `--config` caveat as `--mfa-reset` above. Refuses (exit non-zero) if any check fails. |
| `--principal-max-concurrency` | `16` | **Engine principals** (ADR-1005 class, PR 4.4). Maximum in-flight requests for a single engine principal at any instant, checked at the server's single pre-routing chokepoint on both REST and MCP. A streaming/SSE request holds its slot for the stream's lifetime, not just until routing hands off. Exceeding it returns HTTP `429`. Human, device-agent, and anonymous traffic is never gated by this cap. See `docs/user-manual/engine-principals.md` "Per-principal quota cap" for tuning guidance. Env: `YUZU_PRINCIPAL_MAX_CONCURRENCY`. |
| `--principal-rate-limit` | `20.0` | **Engine principals** (ADR-1005 class, PR 4.4). Sustained request rate cap (requests/second, token bucket, burst = 2x the configured rate) for a single engine principal. Exceeding it returns HTTP `429`. Independent of `--principal-max-concurrency` — either dimension alone can reject a request. See `docs/user-manual/engine-principals.md` "Per-principal quota cap" for tuning guidance. Env: `YUZU_PRINCIPAL_RATE_LIMIT`. |
| `--ota-max-concurrent-per-peer` | `2` | **Agent OTA pulls (#913).** Maximum parallel `DownloadUpdate` streams a single peer may hold. This is the PRIMARY bound on the OTA path: the attack it closes is one authenticated agent opening many concurrent streams, each pinning a gRPC thread on blocking disk and network I/O. Exceeding it returns gRPC `RESOURCE_EXHAUSTED` (rejected, never queued). Admission keys on the peer's certificate identity, falling back to peer IP when no client certificate is presented. Env: `YUZU_OTA_MAX_CONCURRENT_PER_PEER`. |
| `--ota-rate-capacity` | `20.0` | **Agent OTA pulls (#913).** Token-bucket burst per peer, a secondary bound that exists only to stop a fast open/close hammer loop. Deliberately loose: a bucket meters *attempts*, so tightening it punishes retries and can lock out honest slow-link or flapping agents rather than the attacker (this is the failure mode recorded on #934 and #941). Tune `--ota-max-concurrent-per-peer` first. Env: `YUZU_OTA_RATE_CAPACITY`. |
| `--ota-rate-refill-per-min` | `1.0` | **Agent OTA pulls (#913).** Tokens restored per minute per peer. At the defaults a peer that reconnects five times spends five tokens and recovers them in five minutes. A transfer that trips a server-imposed deadline refunds its token, so failures the server caused never count against the peer. Env: `YUZU_OTA_RATE_REFILL_PER_MIN`. |
| `--ota-transfer-deadline-secs` | `900` | **Agent OTA pulls (#911).** Whole-transfer bound, and **the knob that binds on a slow link**. Enforced by cancelling the RPC from a watchdog thread — the only thing that unblocks a synchronous `ServerWriter::Write` stalled on a peer whose HTTP/2 receive window has collapsed to zero. Keepalive does NOT catch that case: such a peer keeps answering pings while the stream is stalled. Tripping it returns `DEADLINE_EXCEEDED` and refunds the peer's rate token. **It implies a throughput floor**: the default 900 s over a 100 MiB binary is ~0.93 Mbit/s sustained. A link below `artifact_size / deadline` can never complete an update — there is no resume, so each attempt restarts from offset 0 — and the only signal is `yuzu_ota_download_deadline_exceeded_total{phase="transfer"}` (watch it as a proportion of `{decision="admitted"}`). Raise it for satellite, residential 4G/LTE and congested-WAN fleets. Env: `YUZU_OTA_TRANSFER_DEADLINE_SECS`. |
| `--ota-chunk-write-deadline-secs` | `30` | **Agent OTA pulls (#911).** Per-chunk stall bound, catching a peer whose individual writes hang. Note this is rarely the binding constraint: 64 KiB / 30 s is 2.2 KiB/s, and a peer that slow blows the whole-transfer budget long before 30 chunks. **For slow links tune `--ota-transfer-deadline-secs`, not this** — see its row. Env: `YUZU_OTA_CHUNK_WRITE_DEADLINE_SECS`. |
| `--ota-max-peers-tracked` | `50000` | **Agent OTA pulls (#935).** Cardinality ceiling on the per-peer admission map. Load-bearing because the admission key falls back to peer IP when a peer presents no client certificate, which makes the key space attacker-influenced: a NAT'd peer rotating source ports would otherwise grow the map without bound. At the ceiling a new peer evicts the least-recently-seen entry that holds no in-flight transfer. **Shared-bucket caveat:** where peers present no client certificate, admission keys on source IP, so every agent behind one NAT egress shares a single bucket and therefore a single `--ota-max-concurrent-per-peer` allowance — on a large certless fleet behind one egress this can throttle legitimate updates. Enrolling agents with client certificates moves each onto its own bucket; watch `yuzu_ota_admission_key_mode_total{mode="peer_ip"}` to see how much of the fleet is affected. **Floored at 1024**: a value below that is raised at startup, and every surface (the capacity gauge, the settings page, the alerts that divide by it) then reports 1024, not what you set — a map smaller than that cannot usefully bound anything and would make eviction, not the rate bucket, the operative limit. Env: `YUZU_OTA_MAX_PEERS_TRACKED`. |
| `--ota-max-concurrent-total` | `64` | **Agent OTA pulls (#913).** Server-wide ceiling on concurrent transfers across ALL peers. The per-peer cap bounds one identity; where the identity gate is inert the admission key falls back to source IP, so that bound scales with a caller's address space (a /24 buys 256 independent per-peer budgets). This is the bound that does not. Exceeding it returns `RESOURCE_EXHAUSTED` with a message naming the server capacity, distinct from the per-peer message. Env: `YUZU_OTA_MAX_CONCURRENT_TOTAL`. |
| `--ota-cert-reserve-pct` | `50` | **Agent OTA pulls (#913).** Percent of `--ota-max-concurrent-total` reserved for peers admitted on a **certificate** identity. IP-keyed peers may occupy at most the remainder. Without it the server-wide ceiling is a single shared resource, and on any deployment where the identity gate is inert an unauthenticated caller commanding a range of addresses can hold it entirely, locking the enrolled fleet out of updates — the per-peer cap does not help, because each address is its own peer. The reserve arithmetic is floored at one slot for non-zero ceilings, so a small cap cannot round the IP-keyed share to zero; a ceiling of `0` still admits nobody. Set `0` to disable the split, `100` to admit only certificate-keyed peers. Watch `yuzu_ota_download_admission_total{decision="rejected_total"}` and the rejection log's `cert_keyed=` field. Env: `YUZU_OTA_CERT_RESERVE_PCT`. |
| `--grpc-max-threads` | `8192` | **gRPC server bound (#913).** Thread ceiling for the gRPC sync server, applied via `ResourceQuota::SetMaxThreads`. Without it the per-connection stream cap below bounds nothing globally — connections are uncapped, so N connections yield N x cap concurrent handlers. This is also what bounds the OTA admission map's overshoot. **THIS IS A FLEET-SIZE CEILING, not a tuning dial.** `AgentService` is synchronous and `Subscribe` holds one thread for the entire life of each connected agent's command stream, so this value MUST exceed your concurrently-connected agent count with headroom. Set below it, gRPC answers `RESOURCE_EXHAUSTED` to every RPC on every service sharing the quota — a fleet-wide outage, not back-pressure. Size it as `expected_agents x 1.5`, and raise it before a fleet grows into it. Env: `YUZU_GRPC_MAX_THREADS`. |
| `--grpc-max-concurrent-streams` | `128` | **gRPC server bound (#913).** Maximum concurrent HTTP/2 streams per gRPC connection. Before this setting the server's one `ServerBuilder` carried keepalive/ping arguments and nothing else — no stream cap and no `ResourceQuota` existed anywhere — which is what made an unbounded per-peer OTA path a capacity-monopolisation issue rather than a theoretical one. Env: `YUZU_GRPC_MAX_CONCURRENT_STREAMS`. |
| `--grpc-max-resource-memory-mb` | `512` | **gRPC server bound (#913).** `ResourceQuota` memory ceiling in MiB for the gRPC server. At capacity gRPC rejects rather than queueing. Sized for a typical fleet server; raise it on large deployments if you observe rejections that do not correlate with an actual attack. Env: `YUZU_GRPC_MAX_RESOURCE_MEMORY_MB`. |
| `--log-level` | `info` | Logging verbosity: `trace`, `debug`, `info`, `warn`, `error`. Applies to every log sink (the console and the `--log-file` file). Read once at startup: a `log_level` stored through runtime configuration is re-applied at boot and overrides it, and the same key changes the level without a restart; level names are lowercase and case sensitive, and an unrecognised value given to this flag (including `WARN`) is treated as `off`. The Upgrade note "new `Guardian T_*` diagnostic log lines" lists the restart-free levers and what `warn` also silences (including authentication and session lines). Env: `YUZU_LOG_LEVEL`. |
| `--log-max-size` | `52428800` | Size in bytes at which the `--log-file` file rotates (50 MB). Ignored without `--log-file`. Env: `YUZU_LOG_MAX_SIZE`. |
| `--log-max-files` | `5` | Number of rotated `--log-file` files kept. Ignored without `--log-file`. Env: `YUZU_LOG_MAX_FILES`. |
| `--log-file` | *(none)* | Path for explicit on-disk log output. When set, log lines are written to this file in addition to stdout. The directory must be writable by the server's runtime user; if the file or directory cannot be opened the server logs an ERROR but continues to start. Independent of the default platform log path (see [File Logging](#file-logging)). |
| `--kek-min-rotate-interval` | `3600` | **KEK rotation runaway/abuse guard (#2530) — NOT a rotation-schedule setting.** A floor on how *frequently* `/api/v1/secrets/kek/rotate` may be attempted at all (seconds), read from `secrets.kek_meta.created_at` on the database server's own clock — cluster-wide and restart-persistent (the only authoritative control; a cheap process-local pre-check that used to sit alongside it was removed as a correctness bug, #2530 G7-S9 — see "Key management (secrets KEK)"). A rotate inside the window gets `429` with an honest `retry_after_ms`. The default is sized to stop looping automation, not to express how often you intend to rotate; **most operators should never change it.** Raising it delays *emergency* re-rotation after a suspected KEK compromise with no bypass (`/rewrap` only resumes an in-progress rotation, it never mints a new version) — do not set it to your rotation *cadence* (e.g. a 90-day quarterly policy), that is a routine rotation followed by a compromise the next day leaving you refused for the next three months. The upper bound (365 days) is a fat-finger sanity ceiling, not an endorsement of setting it that high. **A fresh install's first rotate attempt is refused for up to this interval** — KEK v1 is minted at boot with `created_at = now()`, so the durable clock starts counting down from install time, not from your first rotate call. See "Key management (secrets KEK)" for the full contract. Env: `YUZU_KEK_MIN_ROTATE_INTERVAL`. |
| `--kek-max-live-versions` | `32` | **KEK rotation runaway control (#2530).** Backstop ceiling on the number of non-retired KEK versions; a rotate at or above it gets `409` with no retry hint. There is no retire route (#2525), so raising this above the default is the **supported escape hatch** that keeps rotation usable once an install hits it — a deliberate, logged (`spdlog::warn` at boot) and audited (`server.kek_ceiling_raised`) temporary risk acceptance, not a routine tuning knob; every server sharing the database needs the raised value for the ceiling to lift fleet-wide. See "Key management (secrets KEK)". Env: `YUZU_KEK_MAX_LIVE_VERSIONS`. |

### Example

```bash
# HTTP only (development — HTTPS is on by default, must opt out)
./yuzu-server --no-https --web-port 8080

# HTTPS with certificate files (default mode)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key

# HTTPS with custom cert reload interval (30 seconds)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --cert-reload-interval 30

# HTTPS with cert reload disabled
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --no-cert-reload

# MCP disabled (air-gapped environment)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --mcp-disable

# MCP read-only mode (AI can query but not execute)
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --mcp-read-only

# HTTPS with OIDC SSO
./yuzu-server --https-cert /etc/yuzu/server.crt \
  --https-key /etc/yuzu/server.key \
  --oidc-issuer "https://login.microsoftonline.com/YOUR_TENANT/v2.0" \
  --oidc-client-id "YOUR_CLIENT_ID" \
  --oidc-client-secret "YOUR_SECRET" \
  --oidc-redirect-uri "https://yuzu.example.com:8443/auth/callback"
```

---

## Configuration Files

The server's configuration file (`--config`, default `/etc/yuzu/yuzu-server.cfg` on Linux, `C:\ProgramData\Yuzu\yuzu-server.cfg` on Windows) and its runtime state files live on disk; the state files are written to `--data-dir` (default: the directory containing the config file). Apart from those files, the NVD cache and the `agent-updates/`/`upload-blobs/` file directories, everything — users, sessions, MFA/TOTP, SCIM and every other server store — lives in PostgreSQL (see [PostgreSQL Substrate](#postgresql-substrate)). There is no `auth.db`; legacy `*.db` files left in `--data-dir` by older releases are only probed at startup to warn, never read.

| File | Purpose |
|---|---|
| `yuzu-server.cfg` | First-boot seed for the initial admin. Holds the initial admin credential as PBKDF2-SHA256 with a per-user salt, which is seeded into the PostgreSQL `auth` schema on first boot. After that the `auth` schema is authoritative — keep this file as the seed for disaster recovery. |
| `enrollment-tokens.cfg` | Live Tier-2 enrollment-token store. Holds token hashes, never plaintext tokens. |
| `pending-agents.cfg` | Queue of agents awaiting manual approval (Tier 1 enrollment). Contains agent ID, hostname, IP, and registration timestamp. |
| `auto-approve.cfg` | Auto-approve enrollment policy rules and match mode. |
| `nvd_cves.db` | NVD CVE cache. The one remaining server SQLite store — a recorded deferral, not a permanent exemption (`docs/postgres-migration-ladder.md`). |
| `agent-updates/` | Agent OTA package binaries. The package records (`update_registry.update_packages`) are in PostgreSQL; the files they name live here. Relocated by `--update-dir` when that flag is set. |
| `upload-blobs/` | Blob root for completed agent file uploads (ADR-3004). The records (`upload_grant_store.completed_uploads`) are in PostgreSQL; the blobs live here. Always under `--data-dir`; no flag overrides it. |

> **Backup recommendation:** A complete backup is a `pg_dump --format=custom` of the Yuzu database **plus the entire CA/cert directory `--ca-dir`**, captured at the same point in time and restored as a pair — `--ca-dir` holds `default-ca.key` (the per-install CA private key) and the secrets KEK files `secrets-kek-v<N>.key`, without which the secret columns in the dump (TOTP secrets, webhook and plugin-config secrets, runtime-config and offload-target secrets) cannot be decrypted. See [Backup — the KEK pairing rule](../ops-runbooks/auth-db-recovery.md#backup--the-kek-pairing-rule) and [PostgreSQL Substrate](#postgresql-substrate) for the procedure. Retain old KEK versions for as long as the backups that need them. Also back up the `--data-dir` `.cfg` files above, `nvd_cves.db` (use `sqlite3 nvd_cves.db ".backup ..."`, NEVER `cp` against a live DB), and the two blob directories `agent-updates/` (or your `--update-dir`) and `upload-blobs/` — the dump holds only the package and upload records that point into them, so restoring the dump without these directories leaves records with no files behind them. **Losing `default-ca.key` forces a full fleet re-enrollment** (every agent's cert chains to that root, and the server refuses to silently re-root — see below). Losing the Postgres `auth` schema AND `yuzu-server.cfg` requires re-running `--first-run-setup` to create a new admin. Losing authentication state alone is a Postgres restore — see `docs/ops-runbooks/auth-db-recovery.md`. **The internal-CA inventory + CRL history (`ca_store` schema, ADR-0053) is one of the migrated Postgres stores** — back it up with `pg_dump`/`pg_restore`, not as a separate local file.

> **Built-in default certificates — convenience, not production.** With no `--cert`/`--key`/`--https-cert` supplied (and without `--no-default-certs`), the server generates a per-install ECDSA CA + server leaves on first boot so a fresh install is encrypted with zero config. Operational caveats:
> - **10-year, no auto-renewal.** The server leaves do not auto-renew; the `yuzu_server_cert_expiry_timestamp_seconds{cert="default-ca"}` gauge + the `YuzuCertificateExpiringSoon`/`…Critical` alerts (`docs/prometheus/yuzu-alerts.yml`) warn ahead of expiry. **Replace defaults before production rollout** with operator-provided certs (`--cert`/`--key`, `--https-cert`/`--https-key`) or, to rotate the built-in set, clear `--ca-dir` (after backing it up) and restart.
> - **SAN limitation.** Default leaf SANs cover `localhost`, `127.0.0.1`, `::1`, and the boot-time hostname only. Reaching the dashboard/agent listener by a LAN IP or a different FQDN needs operator-provided certs (or DNS that resolves to a covered name). A host rename invalidates the SAN — rotate the certs after renaming.
> - **No silent re-root.** If `ca_store` (the internal-CA Postgres store, ADR-0053) already holds a CA root but the on-disk certs in `--ca-dir` are missing/corrupt (e.g. a wiped cert dir on a persistent data volume, or ordinary later damage to an established install — a bad partial restore, a lost leaf file), the server **refuses to start** rather than mint a new CA that would orphan every enrolled agent — **unless this exact instance can prove it minted the still-incomplete root** (its local CA key file still resolves and cryptographically pairs with the stored root), in which case it resumes automatically and re-mints its own default leaves under the same root (ADR-0053). When that self-heal condition does not hold, restore `default-*.{pem,key}` from backup (matching the `ca_store` root), or perform a deliberate clean re-root by clearing `ca_store.ca_root`/`ca_issued`/`ca_crl_versions` directly against Postgres — see `docs/pki-architecture.md` "Operator runbook" for the full procedure.

> **File permissions (Unix):** `yuzu-server.cfg`, `enrollment-tokens.cfg`, and `pending-agents.cfg` are `0600` after every write, and the KEK files in `--ca-dir` are created `0600`. No manual `chmod` is required.

> **Windows Defender:** No authentication-file exclusion applies — authentication state is in PostgreSQL, not a local database file. See `docs/ops-runbooks/auth-db-recovery.md`.

---

## First-Run Setup

When the server starts for the first time and no `yuzu-server.cfg` exists, it enters **interactive setup mode** on the terminal. The setup prompts for:

1. **Admin username** -- the initial administrator account.
2. **Admin password** -- entered twice for confirmation. Stored as a PBKDF2 hash.

After setup completes, the server writes `yuzu-server.cfg` and starts normally. Subsequent restarts skip the setup prompt.

> **Headless deployment:** For automated or containerized deployments, pre-create `yuzu-server.cfg` with PBKDF2-hashed password entries before starting the server for the first time — first-run setup is interactive and will exit without a TTY.

### Seeded credentials

**No image or installer provisions a default account.** No image `COPY`s a
`yuzu-server.cfg`, and there is no built-in account: a server started without a
config runs interactive first-run setup, which prompts for an administrator
**and** a second user account.

One checked-in file, `deploy/config/uat/yuzu-server.cfg`, does hold a single
`admin` entry — with a **fixed salt and a fixed PBKDF2 digest committed to git**,
for the known password `adminpassword1`. It is orphaned: no script, compose file
or image reads it (the UAT rigs each generate their own config at a temp path
with a fresh random salt per run). Never copy it into a deployment, and do not
read its presence as a supported default — removing it from the tree is tracked
separately.

> **If you seed an account yourself, change its password before exposing the
> server.** For enterprise deployments, integrate OIDC SSO and disable local
> accounts.

---

## Upgrade Notes

### vNEXT — `installed_apps list` rows carry two more fields (breaking)

**What changed.** The `installed_apps` agent plugin's operator `list` action (definition
`crossplatform.software.inventory`) now emits seven `|`-separated fields per row instead of five:
`app|name|version|publisher|install_date|install_location|bundle_id`. `install_location` is the Windows
Uninstall-key `InstallLocation` (unexpanded) or the location macOS reports; `bundle_id` is the macOS
`CFBundleIdentifier`. Either is `-` where the OS has none: every Linux row ends `-|-`, and many Windows rows
have no `InstallLocation` (182 of 241 on the reference developer workstation). The first five fields keep their
position; every field is now escape-aware (`\` folds to `/`, `|` to `\|`, CR/LF to a space, a field over 4 KiB
is cut), a no-op for every value in the three reference captures. Row shape for `query`, `list_per_user` and the
daily-sync inventory (ADR-0016) is unchanged, though on macOS the collector `list`/`query`/`list_per_user` share
now sorts same-named apps by (name, install_location) instead of leaving their order arbitrary.

**Who this affects.** Automation reading `installed_apps list` output from `GET /api/v1/responses/{id}`, its
`/export`, or MCP `query_responses` that (a) unpacks or anchors exactly five fields, or (b) treats the last
field as `install_date`. The dashboard is unaffected: it has always split these rows into `app` plus one
remainder cell, so the new fields appear inside that cell (and the search box matches them) but are not
separate, sortable or filterable columns. A policy or script that substring-matches the raw `output` now also
matches install paths and bundle identifiers.

**Mixed fleets.** Upgrade order is server first, so agents keep answering with five fields until they take the
release carrying `installed_apps` 1.2.0 (the definition's `minAgentVersion` stays `1.0.0`). Agents older than
1.2.0 do not escape `|` in name, version, publisher or install date, so a row from one of them can split into
any count under the escape-aware split: accept a row only when it has exactly 5 or exactly 7 tokens, reject any
other count, and read the sixth/seventh columns only for agents known to be on plugin 1.2.0 or later.

**Existing deployments keep the old definition.** The bundled definition is seeded once and never refreshed
on an existing server (see the InstructionStore note in [`upgrading.md`](upgrading.md); #2555), so
`get_definition` and `discover_instructions` keep listing four columns at version 1.0.0. Row content is
unaffected. Editing the definition (dashboard YAML editor or `PUT /api/instructions/{id}`) to declare the two
new columns is optional and cosmetic.

**Before upgrading, check whether this affects you.** Search your scripts, SIEM parsers and saved exports for
consumers of `installed_apps`/`crossplatform.software.inventory` output and change any fixed five-field
pattern to `app|name|version|publisher|install_date[|install_location|bundle_id]`.

### vNEXT — `re-eval` on a result set now refuses instead of broadcasting when its recorded parent set has been deleted (#4306, breaking)

**What changed.** `POST /api/v1/result-sets/{id}/re-eval` and MCP `reevaluate_result_set`
previously synthesised the sibling's dispatch scope from the original's live, nullable
`parent_id` foreign key. If the original's parent result set was later deleted (`parent_id ...
ON DELETE SET NULL`), the column read as absent, and an absent `parent_id` reaching dispatch
synthesis meant "broadcast to `__all__`" — silently turning "re-ask the same narrow question"
into "ask the whole visible fleet." Both routes now refuse (`400 RESULT_SET_BAD_REQUEST`,
`reason=parent_gone`) when the live parent is gone but the original's persisted `source_payload`
shows it was narrowed at creation, instead of broadcasting.

**Who this affects.** Any caller (REST or MCP) whose automation re-evaluates a result set that
was originally narrowed to a `parent_id`, where that parent set has since been deleted.
Previously such a call silently succeeded with a `202` (REST) or a materialized/pending result
(MCP) dispatched to the entire visible fleet; it now refuses instead -- REST returns `400
RESULT_SET_BAD_REQUEST`, MCP returns a JSON-RPC error (`kInvalidParams`) over HTTP 200, per that
transport's existing error-shape convention. No legitimate caller should have been relying on the
fleet-wide broadcast — this was the target-erasure defect being fixed — but any automation
catching only success responses on this route should add handling for the new `400
reason=parent_gone` case: create a fresh result set from the intended parent instead of
re-evaluating the orphaned one. A genuinely parentless original (no `parent_id` was ever supplied
at creation) still broadcasts on re-eval, unchanged.

### vNEXT — a result-set `parent_id` alias longer than 64 bytes is no longer accepted on `from-tar-query`/`from-instruction-result` (#4734, breaking)

**What changed.** `parent_id` accepts either a canonical `rs_...` id or a per-operator alias
(the set's own `name`, valid up to 256 bytes). `POST /api/v1/result-sets/from-tar-query` and
`/from-instruction-result` now bound `parent_id` to 64 bytes (`kResultSetParentIdMaxLen`) before
attempting alias resolution, closing a gap where an oversized value was copied unbounded into
the persisted `scope_input_id` lineage marker. MCP's equivalent producer tools already enforced
this bound; REST did not — this change brings REST to parity.

**Who this affects.** Any caller referencing a result set by a `name`-based alias longer than 64
bytes as `parent_id` on these two REST routes. Previously such a call resolved the alias and
dispatched normally; it now returns `400` ("parent_id must be at most 64 bytes") before
resolution is attempted. Use the set's canonical `rs_...` id instead (`GET
/api/v1/result-sets` lists both `id` and `name` for every set you own).

### vNEXT — `GET /api/v1/result-sets` can now answer `503`; the async result-set producers' post-dispatch fault code changes from `400` to `500` on REST (#4306, breaking)

**What changed.** `GET /api/v1/result-sets` previously always answered `200`, even when the
underlying store read was degraded — `ResultSetStore::list_by_owner` returned a plain (possibly
empty) container rather than surfacing the failure, so a degraded Postgres read answered `200`
with an empty `result_sets` array indistinguishable from a genuinely-empty owner. It now answers
`503 RESULT_SET_STORE_UNAVAILABLE` (`Retry-After` present) on a genuine store-level read failure.
Separately, on REST, the three async result-set producers (`POST /api/v1/result-sets/from-tar-query`,
`/from-instruction-result`, and `/{id}/re-eval`) previously mapped a post-dispatch store fault —
the pending result-set row failing to persist *after* a real command had already dispatched to
agents — to `400`. That was a client-error status for a server-side fault; it is now
`500 RESULT_SET_STORE_FAULT_AFTER_DISPATCH`, matching MCP's `rs_run_async`, which already used its
`kInternalError` branch for the identical case (the JSON-RPC error type is unchanged). The same
three REST routes also gained a new PRE-dispatch `503 RESULT_SET_STORE_UNAVAILABLE` when the
per-owner quota cannot be verified before dispatch — nothing is sent in that case, and the request
is safe to retry.

**Who this affects.** Any REST caller that treats `GET /api/v1/result-sets` as never-erroring, or
that pattern-matches the old `400` on the three async producers' post-dispatch failure path. A
`503` should be retried (`Retry-After` header present); a `500 RESULT_SET_STORE_FAULT_AFTER_DISPATCH`
means a command already dispatched — do not re-send, poll `GET /api/v1/executions/{id}` for its
outcome instead. MCP's error *type* (`kInternalError`) is unchanged, but the embedded fault-message
token was also renamed to `RESULT_SET_STORE_FAULT_AFTER_DISPATCH` for the same reason as REST — any
MCP caller pattern-matching the old `RESULT_SET_STORE_UNAVAILABLE` token string on this specific
post-dispatch branch should update to the new token (the 3 MCP tool descriptions in `kTools[]`
document both tokens explicitly).

### vNEXT — server TLS listeners now pin a fixed TLS 1.2 cipher allow-list; a previously-set `GRPC_SSL_CIPHER_SUITES` no longer applies (#4722; breaking)

**What changed.** The server now unconditionally overwrites `GRPC_SSL_CIPHER_SUITES` in its own process environment before any gRPC call, and applies the same six-suite ECDHE TLS 1.2 allow-list to the HTTPS dashboard listener and its certificate hot-reload validation. It self-checks the resolved policy at boot and refuses to start if the allow-list resolves to zero usable TLS 1.2 ciphers on the local OpenSSL build. See [TLS policy](tls.md) for the exact list and what CI proves about it.

**Who this affects.** Any deployment that previously set `GRPC_SSL_CIPHER_SUITES` in the server's environment to select or restrict its own cipher suites — that variable is now silently ignored, and the server's fixed allow-list applies instead.

**What to do.** There is no override flag and no config option to restore the previous behavior — this is a deliberate policy floor, not an oversight. If your environment relied on a non-default `GRPC_SSL_CIPHER_SUITES` value, remove it (it no longer does anything) and confirm your TLS clients support at least one suite in the pinned list (`tls.md`); operator-issued RSA certificates remain supported via the pinned ECDHE-RSA suites.

### vNEXT — new `Guardian T_*` diagnostic log lines at `info` level (#4606; NOT breaking)

**What changed.** The server now writes one `info`-level line for every Guardian event it stores for an ordinary rule (ruleless DEX observations are excluded):

```
Guardian T_server event_id=… agent=… rule=… recv_ns=… committed_ns=… agent_ns=… store_ms=…
```

The agent writes `Guardian T_wire event_id=… domain=… sent=… wire_wall_ns=…` for every Guardian event it attempts to send over the Subscribe stream on the legacy detection path (`domain=legacy`; `sent=0` means the link was down or the local write failed, and that event was dropped and is not retried). Ruleless DEX observations are not logged. Only once the Spark path is the live backend (`prefer_spark`, off by default) does it also write `Guardian T_detect …` for each outbox entry an evaluation pass stages (a pass evaluates every rule on the watched key and stages up to two entries for each, so a key shared by several rules can produce several lines, and a pass that stages nothing produces none), plus the same `T_wire` line for the Spark outbox path (there `sent=0` means the local write failed and the entry is retried; a down stream logs nothing). They exist to measure detect-to-deliver latency for the Spark cutover benchmark (#4606); they are plain log lines, not metrics or audit events, and no shipped component consumes them. If you do consume them, join on the agent and `event_id` (the agent-side lines carry no agent field, so take the agent from which log the line came from and from the server line's `agent=`), and never on log-file line order: a `T_wire` line can appear before its own `T_detect` line.

**What the lines contain.** Only identifiers, times and a few flags and counters: the event id, the agent id, the rule id, instants or elapsed times, and fields such as `sent`, `accepted` and `seq`. They contain no event detail, no detected or expected value, no user name, process name or path. Ids are neutralised before they are written: every byte outside printable ASCII, and any space, `=` or `,` (a line break included), becomes `_`, and an id longer than 256 bytes is shortened to 256 by keeping its head and its last 24 bytes (the part that tells two events apart), identically on the agent and the server and on the server's Guardian ingest replay, conflict, error, oversized-detail and parse-failure lines, so an operator-chosen rule id such as `Disk Full` appears as `Disk_Full` and a non-ASCII rule name appears as underscores. The event id printed on the server's replay, conflict and oversized-detail lines is this neutralised form, so to find that event in the store, match on the agent, the rule and the time rather than pasting the id. This covers the lines named here. **#4665 closed the rest of this list**: every other rule-id, Spark-key, path, hive, service-name and unit-name print site across the Guardian/Spark subsystem — the legacy file, registry and service guards, SparkEngine, the Guardian engine's arm/baseline/rule-parsing messages, the Spark runtime's own lines that name only a watched key, the server's Guardian push enforce-downgrade warning, and the event store's own error lines — is now neutralised too. A rule id on any of these lines is wrapped the same way as on the lines above (`log_id_token`: control bytes, DEL, space, `=`, `,` and every non-ASCII byte fold to `_`, then a 256-byte head/tail shorten), so the same `Disk_Full`-style search still finds it. A path, registry hive/key, service or unit name embedded in a `'...'`-quoted fragment is wrapped with the newer, more permissive `log_key_token` (`common/include/yuzu/log_token.hpp`): it preserves spaces and non-ASCII bytes, so a real Windows path or a non-ASCII name still reads naturally, and folds only control bytes, DEL, and three Unicode line-separator sequences (NEL, LINE SEPARATOR, PARAGRAPH SEPARATOR) to `_` — the minimum needed to stop a forged physical log line. A log pipeline may now treat an id or key on any of these lines as forge-resistant. A regression-net test (`tests/test_guardian_spark_log_injection_tripwire.py`) fails the build on a future unwrapped call site in this subsystem — a lexical scanner with one documented, permanent, non-closable blind spot (it cannot trace a value wrapped several lines above its print site through local-variable construction; see the test's own header comment). They are ordinary log output, so how long they are kept is decided by your log pipeline, not by the Guardian event retention period, and they are not an audit record.

**Impact.** Log volume only. There is no API, schema, metric, alert or wire change, and no change to any detection, dispatch or ingest decision. Nothing to do on upgrade.

- **Today, on the legacy path:** up to one server line and one agent line per Guardian event, so it tracks your Guardian event volume. The agent debounces drift events per rule (default 1000 ms, the rule parameter `event_debounce_ms`), which collapses rapid drifts; a rule configured with `event_debounce_ms` of `0` emits every drift, and a return to compliant is never debounced, so a rule that flaps can still log at its flap rate.
- **Once the Spark path is live:** up to two agent lines per event (`T_detect` and `T_wire`) plus the server line. Lifecycle events, replayed events and health events raised by a subscription fault or its recovery log `T_wire` with no `T_detect` (health entries raised by an evaluation pass do get one), a retried send logs `T_wire` again, lifecycle journal replays re-send on every reconnect (with no info-level server line), a rule stuck in an unknown or error state re-emits on the errored-refresh cadence (default 5 minutes, and in practice no faster than the rule type's convergence sweep), and each evaluation pass rejected by a full outbox logs another `accepted=0` `T_detect` line with no rate limit of its own.
- **Where the lines go:** wherever a log file is in use (`--log-file` on the server or the agent; a Windows service agent defaults to `yuzu-agent.log` under its data directory) the file sink rotates at 50 MB and keeps the active file plus up to 5 rotated files by default (up to about 300 MB per sink; `--log-max-size` in bytes, `--log-max-files`), so an event storm shortens how far back your logs reach. Without a log file the lines go to the console and Yuzu applies no rotation: retention and any rate limiting belong to your service manager or container runtime (a journald rate limit can drop lines, including unrelated warnings).
- **They are written synchronously on the server; the agent side is now asynchronous (#4666 PR-2).** On the server, the thread that reads the agent's stream, or the `ForwardGuardianMessage` handler when the agent is behind a gateway, still writes `T_server` inline, and a blocked sink (an undrained pipe, a stalled network mount) still blocks that thread. On the agent, a guard worker (legacy path) or the Spark consumer, convergence and send threads call the same bare `spdlog::` functions as before, but main.cpp now installs the async hand-off logger (see "Agent logging is now asynchronous" under *systemd Units*, further down this page) as the process's spdlog default logger, so every one of those calls, including the Spark runtime's own arm-committed/late-arm/sweep-residue lines, now enqueues and returns rather than blocking on sink I/O, on any platform where the agent image and `libyuzu_agent_core` share one spdlog registry (confirmed on Linux, inferred but not directly measured on Windows from its dynamic spdlog linkage; see "spdlog registry identity across images" in `docs/darwin-compat.md` for the measured macOS exception — two separate registries there). This is the mechanism, not a dedicated per-line change: the `docs/spark-flip-gate.md` section 7 precondition (synchronous benchmark and Spark-runtime log writes) is addressed by this global default-logger swap, not by threading a bounded-wait call through each individual `T_detect`/`T_wire`/arm-committed site.

**If log volume matters.** There is no dedicated switch for these lines. The only lever is the log level, and it is blunt: `warn` also suppresses every other `info` line, including on the server the authentication and session lines (for example `User '…' authenticated`, `Local session created`) and the API-token created/revoked lines, which a SIEM ingesting the server log would then lose, and the Guardian arm/commit messages on an agent. It also silences the agent's own "Received signal, shutting down..." line (an ordinary `info`-level call since #4666 PR-2): at `--log-level warn` or above that line is absent entirely on a clean `SIGINT`/`SIGTERM`/Ctrl-C stop, so if you rely on it to confirm an intentional stop, keep agents at `info` or below, or check the process exit code (0 = clean) instead. The audit log is a separate store and is not affected by the log level. Prefer applying it to agents only, and weigh it before applying it fleet-wide.

- **At startup:** `--log-level warn` (env `YUZU_LOG_LEVEL`) on the server and/or the agent; this needs a restart. Level names are lowercase and matching is case sensitive, so `WARN` is not `warn`: an unrecognised value given this way is treated as `off`, not rejected, so a typo silences everything. On an agent, `--verbose` forces `trace` whatever `--log-level` says.
- **Without a restart:** on the server, the `log_level` runtime-configuration key (`PUT /api/config/log_level`, needs `Infrastructure:Write`, applied immediately and persisted, so it survives a restart; an invalid value is rejected; see [REST API: Runtime Configuration](rest-api.md#when-a-change-takes-effect)); on an agent, the `agent_actions` plugin's `set_log_level` action, which is in-process only and lasts until that agent restarts (see the agent `--log-level` flag in [device-management.md](device-management.md)).
- **Precedence:** a `log_level` stored through runtime configuration is re-applied when the server boots, after the command line and environment, so it overrides `--log-level`. If `--log-level warn` appears to have no effect, check the stored value first; and if you stored `warn` to quieten these lines, remember to store `info` again afterwards.

Retiring or gating these lines once the benchmark concludes is recorded in `docs/spark-flip-gate.md` §7.

### vNEXT — gateway-fronted agents stay dispatchable across circuit-recovery replays (HA WS-4 4.4, `#4246` #6; NOT breaking)

New, non-breaking, purely additive. No operator action required.

Before this change, a gateway that lost and regained its connection to the
server (a core restart, replica failover, or an ordinary network blip) would
replay its held agent registrations — and on EVERY such replay, the server
wiped that agent's placement (`gateway_node`/capabilities) before deciding
whether to reuse or refuse the session, silently making the agent
unreachable via that gateway until it happened to reconnect on its own. This
was reachable on a single, otherwise-healthy replica; no core restart was
required.

**What changes:** the server now decides adopt-vs-refuse for a replayed
session before installing anything, the gateway re-announces the agent's own
connection to converge placement on a successful adopt, and a genuinely
superseded/stale replay is refused outright rather than silently accepted.
New Prometheus counters (`yuzu_gw_upstream_notify_dropped_total`,
`yuzu_server_gateway_route_desync_total{outcome="session_superseded"}`) give
visibility into both the normal drop path and a refused replay. At
fleet-wide reconnect-storm scale a re-announcement can still be dropped
under load; that case is no longer stuck forever — the row now ages out and
is purged within the route's existing lease TTL+grace window instead of
being kept alive indefinitely by ordinary heartbeat renewals. This makes the
stuck row observable (a new drop counter, plus the `shortfall` desync
outcome on the next heartbeat) and eligible for reclaim, but it is not an
instant fix — actual re-convergence still needs the next circuit-recovery
replay or the agent's own reconnect. See
`docs/adr/2002-high-availability-architecture.md` §7c for the full
mechanism and two remaining known limitations: (1) a large fleet recovering
from an outage longer than the lease grace window sees a transient wave of
reclaim activity rather than instant convergence, and (2) a replay refused
because the routing directory itself was degraded at that moment is not
retried within that recovery cycle and can strand an agent server-unknown
until its own next reconnect (`#4634`).

### vNEXT — multi-cluster gateway mode now binds each agent to its own cluster, closing a claim-then-answer hijack (#4669; NOT breaking, gateway-fronted multi-cluster deployments only)

New, non-breaking, purely additive. No operator action required for single-gateway (non-multi-cluster) deployments — read on only if you run `--gateway-cluster-addr` (multi-cluster gateway mode).

Before this change, a rogue or compromised gateway process could re-register an agent identity that was already approved and live on a DIFFERENT cluster (`ProxyRegister` needs no per-agent secret for an already-approved agent), then legitimately answer for it — intercepting command payloads and forging terminal results for that agent, despite each `--gateway-cluster-addr` entry conceptually representing a separate trust zone.

**What changes:** each agent now durably binds to the first cluster that legitimately confirms its connection (trust-on-first-use). A later claim from a DIFFERENT cluster for an already-bound agent is refused — for the ordinary case, before anything is published to the routing directory or the in-memory dispatch path; on a definitive conflict caught only at the durable write (a rare defense-in-depth case — the fast pre-check missed it, e.g. under a transient store hiccup), an in-memory placement already published moments earlier is reverted rather than left live — and the refusal is audited (`gateway.cluster_affinity_violation`, see [audit-log.md](audit-log.md)) and counted (`yuzu_server_gateway_route_desync_total{op="announce_connected",outcome="cluster_affinity_violation"}`, alerted via `YuzuGatewayClusterAffinityViolation`). An agent's affinity re-binds when the previously-bound cluster has been genuinely unreachable for the full stale-route grace window **and no session is currently claiming the row** — a single rogue registration alone (with no completed connection) parks the row instead, preserving its affinity, precisely so a rogue cannot force a re-home just by registering (an operator-forced re-home route is tracked as a follow-up, `#4696` — not available in this release).

**Rollout window — read this if you run multi-cluster gateway mode today.** Every agent that was already connected before you upgrade to this version has NO bound affinity until its NEXT `CONNECTED` notification — until then, that agent is still open to a same-shape claim from any cluster, exactly as before this fix. Long-lived gateway↔agent connections may not reconnect on their own for a long time. **To close this window immediately across your whole fleet, restart your gateway processes (or otherwise force your agents to reconnect) after upgrading** — each forced reconnect binds that agent's affinity right away rather than waiting on an organic reconnect.

This does not provide full trust-zone isolation between clusters — a gateway's claimed `cluster_id` is still not cryptographically bound to its actual identity (mitigation 2, tracked separately, not implemented). Do not present multi-cluster gateway mode as providing that guarantee. Multi-cluster gateway mode has no production deployments as of this release.

### vNEXT — a command forwarded to a gateway-connected agent always resolves instead of getting stuck at RUNNING (#4672; NOT breaking)

New, non-breaking, purely additive. No operator action required.

Before this change, a command dispatched to a gateway-fronted agent (multi-cluster gateway
mode — see [ha-postgres.md](ha-postgres.md) and ADR-2002 §7) could get stuck at `RUNNING`
forever with no terminal signal if the forward itself failed: the gateway's mgmt-plane peer
pin rejecting this server's certificate, the gateway staying unreachable after retries, a
target cluster with no configured `--gateway-cluster-addr`, or a response that could not be
attributed to the intended agent. The executions drawer and any API caller polling that
command's status saw it idle indefinitely.

**What changes:** every one of those cases now resolves the command to a terminal `FAILURE`,
at most once, with `error_detail` (the field the REST/MCP response surfaces — there is no
separate structured `error.code`) prefixed with a specific reason code you can use to
diagnose the cause, e.g. `[gateway_unavailable] Gateway unreachable after 3 attempts —
command not delivered`:

| Reason code prefix | Meaning | What to check |
|---|---|---|
| `gateway_unauthenticated` | The gateway's mgmt-plane peer pin (#1422) rejected this server's certificate | The server's mgmt-plane leaf cert and the gateway's `mgmt_peer_pins` configuration agree |
| `gateway_unknown_cluster` | No `--gateway-cluster-addr` is configured for the agent's cluster | Server startup flags / the compose/env configuration for that cluster |
| `gateway_unavailable` | The gateway was unreachable after 3 retry attempts | Gateway process health, network path between server and gateway |
| `gateway_agent_mismatch` | The gateway answered for a different agent than the one this command targeted | Possible cross-cluster response forgery or a stale cluster resolution — treat as a security-relevant signal, not routine noise |
| `gateway_forward_failed` | Any other gateway `SendCommand` RPC failure | The gateway's own logs for the specific gRPC error |

**Recovery:** there is no automatic re-drive for a gateway-forward failure — re-dispatch the
command once the underlying cause is fixed. Automatic durable retry is tracked as a follow-up
in #4690. One case is not yet covered by this fix: a gateway response stream that closes
cleanly with zero frames still leaves the command stuck at RUNNING (tracked separately, #4691).

### vNEXT — human API-token self-rotation is now reachable under the default config, and covers your own MCP-tiered/scoped tokens (#2963; NOT breaking)

New, non-breaking, purely additive. No operator action required.

Before this change, `POST /api/v1/tokens/{id}/rotate`/`.../confirm` (and the
MCP twins `rotate_api_token`/`confirm_api_token_rotation`) composed the
shipped RBAC-off default with the store's self-service-only ownership check
into something reachable by nobody but an admin out of the box — a plain
non-admin owner of a token got `403` trying to rotate their own credential.
Separately, a dashboard/cookie session could never rotate or confirm its own
MCP-tiered or service-scoped token — only that exact token's own credential
could, which was backwards precisely when the token's secret is under
suspicion.

**What changes:** any authenticated, non-admin owner of a token can now
self-rotate it under the default configuration, and a plain interactive
session can now rotate/confirm any of its own tokens regardless of that
token's own tier/scope. Nothing that previously succeeded now fails — this
only widens which previously-403/400'd callers now get `200`. The minted
successor still always inherits the token's own tier/scope and expiry
verbatim; no caller can mint a credential broader than the one it replaces.
A token within 24 hours of its own expiry still cannot be rotated (mint a
new one instead) — unchanged, by design.

See `docs/user-manual/authentication.md` "Rotating a Token" for the full
operator-facing detail, and
`docs/security-reviews/2963-token-rotation-default-permission-2026-09-17.md`
for the decision record.

### vNEXT — CRL publishing is serialised in Postgres, and a missed CRL now republishes itself (HA WS-6 6.1, #4126; NOT breaking)

Every CRL publish (startup, an operator revoke, a subordinate-CA import, and the
freshness re-publish) now runs as one Postgres transaction under a lock on the
`ca_store.ca_crl_versions` table, instead of behind a lock inside one server
process. The `ca_store` schema migrates to v4: v3 adds a nullable
`revoked_count` column on `ca_crl_versions` (nothing is backfilled), v4 adds a
trigger that refuses to delete or change a revoked `ca_issued` row. A
subordinate-CA import (`POST /api/v1/ca/import-chain`) now waits for any CRL
publish already in progress before it swaps the root; if that takes longer than
the database's lock timeout (10 s by default) the import fails with a
database error and can simply be retried.

What changes on **every** deployment, including single-server:

- **A CRL publish can now fail on lock contention.** A publish that waits more
  than 5 s for the table lock gives up. On `POST /api/v1/ca/revoke` and MCP
  `revoke_certificate` that shows as `crl_republished:false` plus a
  `ca.crl.published` failure audit; every trigger increments
  `yuzu_server_ca_crl_publish_failures_total`. The revocation itself still
  takes effect immediately server-side.
- **A revocation missing from the served CRL is now republished automatically.**
  Previously, if a revoke's own CRL publish failed, the revocation stayed out of
  `GET /api/v1/ca/crl` until the next revoke or until the CRL was within 24 h of
  its `nextUpdate` (up to ~6 days); retrying the revoke returns "already
  revoked" and does not publish. The freshness pass now also republishes, on its
  next 15 s tick, whenever the latest CRL was not built from the current revoked
  set (after a failed attempt it waits 5 minutes before trying again). You may
  occasionally see a redundant CRL version shortly after a revoke.
- **A revoked default server certificate now stays revoked.** Previously,
  regenerating the built-in default certificates (for example after changing
  `--cert-san`) deleted their old inventory rows, including revoked ones, so a
  revoked default leaf was accepted again and dropped from the CRL. Revoked rows
  are now kept, and the database now refuses to delete them (migration v4
  trigger) — during a rolling upgrade an older server's default-cert purge fails
  with "failed to purge prior default-cert inventory rows" instead. **This does not restore a revocation already lost that way:** the
  purged serial is no longer in the inventory, so revoking it again returns
  `404`. This only affects you if you revoked a default server certificate (for
  example because its key may have leaked) **and** the default certificates were
  regenerated **before you upgraded to this release**. Check first: find the
  serial in the audit log (the `ca.cert.revoked` event for that revocation; if
  that event has aged out of audit retention — 365 days by default — and you
  cannot establish the serial another way, you cannot tell whether it was lost:
  treat it as lost), then
  page through `GET /api/v1/ca/issued` (follow `offset` until `has_more` is
  false) or decode the CRL (`curl … /api/v1/ca/crl | openssl crl -inform DER
  -noout -text`). If the serial is still listed as revoked, nothing was lost. If
  it is missing, re-root
  the internal CA with the clean re-root in `docs/pki-architecture.md`
  ("Deliberate clean re-root") — `POST /api/v1/ca/import-chain` is not enough,
  because it keeps the issuing key the leaked certificate chains to. A re-root
  re-enrolls the whole fleet.

Single-server remains the only supported topology. If you nevertheless run two
server versions against one database during an upgrade, a publish from the
**older** binary does not take the lock and can still publish a CRL that omits a
revocation the newer binary just recorded; the newer binary's freshness pass
republishes to cover it (and can do so on every tick for as long as the older
binary keeps publishing).

**Rollback** to the previous release is safe: an older binary boots against the
v4 schema and ignores the new column. It will not self-heal a missed CRL (rolling
forward again republishes once), and its default-cert inventory purge fails
while any revoked default leaf exists (logged, harmless) because the trigger stays
in place — which is the point: it cannot un-revoke anything. Multi-replica PKI also still
needs WS-6 slices 6.2 (enrollment) and 6.3 (CA key and KEK custody): today the
freshness pass runs only on the elected leader, and a leader whose CA directory
lacks the CA key can never publish.

### vNEXT — the server now elects a background-work leader at startup (HA WS-3; NOT breaking)

New, non-breaking, and inert on a single-server deployment. As one step toward
making a second server replica safe, the singleton background loops that
*dispatch* — scheduled instructions, policy remediation, quarantine containment
reconciliation, and the CRL freshness re-publish — now run only on a fenced
leader elected over a dedicated Postgres coordination connection (ADR-2002 §3).
On a single server the sole replica is always the leader, so behaviour is
unchanged.

> **This is the *attempt-gate* half only — do NOT run a second server replica on
> the strength of this change alone.** It ensures only the leader *attempts* the
> dispatching loops; the correctness guarantee that a paused ex-leader cannot
> still commit a dispatch (the epoch fence in the claim write) lands in a
> follow-on slice, and a supported active-active deployment additionally needs
> gateway-fronted routing, shared agent presence, and PKI HA. Running a second
> replica against this slice alone can double-dispatch destructive singleton work
> (quarantine, deployment, policy remediation). Single-server is the only
> supported topology today.

What you will see, on **every** deployment including single-server, are new
startup log lines — these are routine, not a fault:

- `leader_elector: coordination connection established (host=… port=… dbname=…; dedicated, never-recycled)`
- `leader_elector: election loop started (poll=5s)`
- `leader_elector: acquired leadership 'server_background_leader' at epoch N`

If instead you see `[HA] leader_elector could not open its coordination
connection; FencedLeaderOnly background loops are PAUSED …`, the server could not
reach its Postgres coordination connection: it keeps serving and re-tries every
election cycle (so a transient blip self-heals within seconds), but while the
message persists the four dispatching loops above do not run. This is fail-closed
by design — a paused loop never double-dispatches — and a persistent occurrence
is a Postgres-reachability problem to investigate, not a server bug. (The
operator-triggered paths are unaffected: a manual policy remediation or evaluation,
and an operator CRL revoke, run on whichever replica received the request — and a
remediation/evaluation is also *completed* on that same replica, so it still reaches
a terminal verdict even while that replica is not the leader. Only the leader-owned
*scheduling* half — the automatic due-policy dispatch and the periodic CRL freshness
re-publish — pauses.)

### vNEXT — Guardian compliance % and the fleet honesty banner now reflect Linux Service Guards correctly (#4252; NOT breaking)

New, non-breaking, and inert on a fleet with no deployed Service-type Guards.
The `/guardian` dashboard's compliance rollup previously treated every
non-Windows agent as "not implemented" for **every** Guard type — correct for
Registry/File (genuinely Windows-only), but wrong for Service, which arms
(observe-only) on Linux today. A Linux agent with a real compliant/drifted
status row for a deployed Service Guard was folded into that Guard's
"not implemented" bucket a second time, corrupting the "% compliant" headline
and the fleet/by-baseline breakdowns.

**What you will see, if your fleet has Linux endpoints with deployed
Service-type Guards:** the affected Guard(s)' "% compliant" figure will likely
move — typically upward, since the double-count previously inflated the
denominator without inflating the numerator. If some of those Linux Service
Guards never actually arm (see the known limitations below), part of any
upward movement is those pairs going from "counted as not implemented" to
"not counted at all" — also raises the %, but is coverage disappearing, not
new enforcement; don't read the whole jump as pure correctness without
checking D-Bus/systemd reachability on the affected endpoints. The fleet
honesty banner (the
list of agents flagged as running on a platform Guardian doesn't fully cover)
also narrows: it now names an agent only if it owns an *actually*-unenforced
Guard pair, not merely for being on a less-covered platform, so a Linux agent
whose only deployed Guard is a Service Guard may disappear from that banner.
Nothing about how a Guard is authored, deployed, or enforced changes — this is
a dashboard-reporting correctness fix only, with no REST/MCP-visible effect
(the `/api/v1/guaranteed-state/status` endpoint never applied this fold and is
unaffected).

Two known, accepted limitations of this fold — see
[guaranteed-state.md](guaranteed-state.md#compliance-overview) for detail and
[metrics.md](metrics.md)'s `yuzu_server_guardian_platform_matrix_stale_total`
entry for the diagnostic signal: a Service Guard that never actually arms on a
genuinely-supported platform (no system D-Bus — every containerized/compose
Linux agent, a disabled build flag, or an invalid unit name) now silently
drops out of the denominator rather than showing "not implemented"; and a
status row surviving a guard-*type* revision on the same rule id can render a
now-unenforced pair as compliant with no marker on that rule (tracked as
#4263, not yet fixed).

### vNEXT — scheduled instruction fires now go through a durable command outbox (HA WS-3 3.3; breaking for SIEM/audit-count assurance)

Scheduled instruction fires no longer dispatch to agents inline from the
poller. The poller now (a) creates the tracked execution row and (b) commits
a durable `pending` occurrence to a new born-on-PG store, `CommandOutboxStore`
(schema `command_outbox_store`); a leader-gated delivery loop drains that
outbox and performs the actual wire dispatch. No operator action is required
— the store's schema migration runs automatically on upgrade (fresh-start/
no-backfill, since this store never existed before 3.3).

**Behaviour changes you will see:**

- **Added dispatch latency.** A scheduled fire is still enqueued within ~30
  seconds of its due time (the poller cadence is unchanged), but actual
  dispatch to agents now follows within ~5 seconds of enqueue via the
  delivery loop — up to ~35 seconds total, where it was previously inline/
  immediate.
- **The audit trail for one scheduled fire is now two events, not one.**
  `instruction.schedule_fired` (result `queued`) marks the enqueue; a new
  `command.outbox_delivered` (result `success`/`failure`/`denied`) marks the
  actual delivery outcome. **Any SIEM correlation rule or audit-count
  assurance built on "one audit event per scheduled fire" must be updated**
  to expect the pair, or to key off `command.outbox_delivered` for the
  delivery outcome.
- **New metrics.** Eight counters and a backlog gauge —
  `yuzu_server_command_outbox_*` — cover enqueue-side degrade and the
  delivery loop's outcomes (delivered / no-agents / denied / retry / errors /
  decode-failed / degrade) plus `yuzu_server_command_outbox_pending`, the
  primary signal that scheduled dispatch has stalled. Full reference:
  `docs/user-manual/metrics.md` "Command outbox delivery metrics".
- **ADR-1007 per-device concurrency is no longer enforced for scheduled
  fires.** The inline path previously resolved a `concurrency_mode` and
  gated on it; the outbox delivery path dispatches on the plain confined
  path without that claim. This is a deliberate, tracked gap — restoring
  per-device concurrency enforcement for the outbox path is a follow-up, not
  an oversight.

**Rollback note:** a `pending` outbox row committed by a 3.3-or-later binary
is invisible to a pre-3.3 binary, which has no outbox reader. Rolling back
mid-flight leaves that occurrence undelivered until you roll forward again —
a narrow window, and no data corruption (the row stays durable in Postgres
and delivers as soon as a 3.3-or-later binary is running and holds
leadership).

### vNEXT — manual policy remediation is now claimed durably, cross-replica (HA WS-3 3.4; breaking for automation asserting `agents == len(agent_ids)`)

`POST /api/policies/{id}/remediate` now arbitrates its per-target claim
through a durable per-`(policy, agent)` row in `PolicyStore`
(`policy_status.remediation_claim_at`), instead of an in-process-only guard.
This closes the cross-replica gap noted in the ADR-0056 Follow-ups: two
replicas racing a remediate call for the same policy/agent can no longer both
dispatch a fix.

**Scope of the guarantee.** This holds between replicas running the **same
schema version**. A rolling upgrade across the migration boundary can
transiently run an old binary that predates the durable claim alongside a new
one; that mixed-version window is gated today by issue #4014 (which blocks
running a second production replica) pending a durable cluster-capability
admission gate. The exposure is one-directional: a row written by an old
binary carries claim-generation `0`, a value a new binary never mints.
Separately, this is effectively-once, not exactly-once (consistent with
ADR-2002): a replica that pauses for longer than `fixing_stale_seconds`
between winning a claim and actually sending a command over gRPC — the fix,
or the subsequent post-fix verify — can still
dispatch that one send after a sibling has reclaimed the target — the wire
send is not itself transactionally fenced. The durable claim prevents
concurrent or duplicate *claims*; it bounds, but does not make impossible, a
single late duplicate *dispatch* from a long-paused claim-holder.

**Behaviour changes you will see:**

- **A new 409 cause.** `POST /api/policies/{id}/remediate` can now refuse
  with `409` and body message `"remediation already in flight or retry cap
  reached for this policy"` when a target is already claimed for remediation
  (by this replica or a sibling) or has exhausted its fix-retry cap for this
  policy — in addition to the existing no-fix-instruction and
  no-non-compliant-agents 409 causes.
- **`agents` in the `202` response is now the delivered count, not the
  attempted count (breaking).** A claimed-but-undelivered target (offline,
  quarantined, plugin absent) releases its claim without consuming a retry
  attempt and is excluded from `agents`. Automation asserting `agents ==
  len(agent_ids)` (or `== number of non-compliant agents` for an omitted
  `agent_ids`) must be updated to tolerate `agents` being smaller than the
  number of targets requested.

**Migration note:** schema migrations v2–v4 add
`policy_status.remediation_claim_at` (v2), `policy_status.remediation_claim_gen`
(v3, the ABA claim-generation fence), and the `remediation_claim_seq` sequence
(v4) — all `BIGINT NOT NULL DEFAULT 0` columns plus one sequence. They run
automatically on upgrade, are metadata-only, and require no operator action
and no downtime.

**Post-restart note:** after a restart, a durable claim left behind by the
previous process may briefly block re-remediation of the agents it was
mid-flight for. This self-heals once the claim ages past the staleness
window (`fixing_stale_seconds`, default 1800s) — the same window
`claim_due_policies`'s own stranded-`fixing` sweep uses.

### vNEXT — gateway management plane now pins its peer (#1422, breaking for custom gateway configs)

The gateway's `:50063` command plane requires, on any network-reachable
listener, strict mTLS **plus** an SPKI peer pin
(`auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1` and
`{yuzu_gw, mgmt_peer_pins}`) — and the gateway **refuses to boot** without
them. Two upgrade orderings fail, in opposite directions:

- **New gateway image + your old custom mTLS mgmt config** → boot refusal.
  Add the `auth_fun` and `mgmt_peer_pins` entries (copy the shape from
  `gateway/config/sys.config.prod`) before pulling the image. The refusal
  log names every missing piece.
- **New repo-checkout config + an old (pre-pin) gateway image** → the config
  references `yuzu_gw_authz`, which the old image does not ship: every mgmt
  stream dies with `undef` and command forwarding is silently dead. Update
  the image and the mounted config **together** — a dev checkout's
  `reference-gateway-sys.config` is ahead of the pinned release image until
  the next release ships.

BYO-cert installs: point `mgmt_peer_pins` at your server certificate — which
**must carry the `serverAuth` EKU** — or paste its SPKI SHA-256; pin-list
edits take effect on gateway restart. `{allow_insecure_mgmt, true}` is a
lab-rig acknowledgement only; never set it where `:50063` is reachable from
untrusted networks.

### vNEXT — the `wifi` plugin's Linux output changes shape (breaking)

The `wifi` plugin moves to reading NetworkManager directly over D-Bus on Linux
(plugin version 1.1.0). Three operator-visible changes to the records it emits:

- **`connected` field 6 changes meaning on Linux.** It now carries the network
  interface (for example `wlan0`). Earlier agents put the NetworkManager
  *connection profile name* there. Any dashboard query, export or script that
  reads that field as a profile name needs updating.
- **Unsecured networks report `Open`, not `NONE`.** Previously the value
  depended on which acquisition path answered; all paths now agree on `Open`.
- **WPA3 and enhanced-open networks are reported distinctly.** They previously
  appeared as `WPA2`, so a fleet may show WPA3 networks for the first time
  after upgrading. This is a reporting change, not a change on the network.

**During a staged rollout the two shapes are mixed, and the record does not say
which one it is.** An un-upgraded agent reports the profile name in field 6 and
an upgraded agent reports the interface, with no discriminator in the row —
unlike the firewall change, where a `backend|` value distinguished per device.
Until the fleet is fully upgraded, treat field 6 as free text: match on agent
version rather than on the field's content, or defer any query that keys on it.
`SELECT` on the plugin version, not on the value.

A long-standing bug that made the macOS network scan return no results on
macOS 14 and later is fixed in the same release; macOS hosts that reported an
empty scan may begin reporting networks, subject to Location Services.

### vNEXT — `event_logs` acquires natively; Windows message text and `count` semantics change (breaking)

The `event_logs` plugin now reads the event log **in-process** — wevtapi on
Windows, `sd_journal` on Linux (falling back to a bounded `journalctl`
invocation where libsystemd is unavailable) — replacing the previous PowerShell
and shell-out legs. Automation that parses `event_logs` rows needs review before
upgrading; the changes fail **silently** (fewer rows, or a rule that stops
firing), not with an error.

What changes for a row consumer:

- **Windows message column** is now the event's `EventData` parameter values,
  space-joined, instead of the provider-formatted message template. A rule
  regex-matching template prose (for example `"The user account was locked
  out"`) will stop matching; match on event ID and provider instead.
- **Windows timestamps** are the event's UTC `SystemTime` at full precision,
  where the previous leg emitted the PowerShell-rendered local time.
- **Windows `count`** bounds the events **examined**, not the matches returned —
  the filter is applied within the newest `count` events. Linux and macOS return
  up to `count` matches. When the window fills without satisfying the query the
  result now carries a `constrained` status rather than reporting an absence.
- **Linux keyword filtering** is a case-insensitive substring match on both
  rungs, where the shell-out leg used `journalctl --grep` regular expressions.
- **`hours` and `count`** reject trailing or leading non-digits (`"12x"`,
  `" 24"`, `"+8"`) and fall back to their defaults; the previous parse silently
  accepted the leading digits.
- **A failed, denied, or bounded read** now reports a typed status
  (`permission_denied` / `unavailable` / `constrained`) instead of an empty
  result. Consumers that treated "no rows" as "healthy" will now see the
  difference — this is the point of the change, but it is a behaviour change.

**Mixed-fleet blend during rollout.** Upgraded and non-upgraded agents emit
*different message columns for the same Windows event*, and there is no per-row
field identifying which leg produced it. Expect a blended view until the fleet
is fully upgraded, and prefer event ID plus provider for any rule that must hold
across both.

### vNEXT — a duplicate SCIM `externalId` now refuses to boot (ADR-2001, CC6.8) (breaking)

**What changed.** This release adds a partial unique index, `scim_resources_external_id_uniq ON scim_resources (external_id) WHERE external_id IS NOT NULL`, applied by the `ScimStore` migration that runs at construction — **unconditionally, regardless of whether `--scim-enable` is set**. Postgres itself detects any pre-existing duplicate non-empty `external_id` and raises a `unique_violation`, which fails the migration; `ScimStore` then reports `!is_open()` and the server refuses to start, the same fail-closed posture every born-on-PG store uses on a failed migration. This is deliberate, not a bug to work around: a duplicate `externalId` is exactly the mis-link hazard ADR-2001's SCIM↔OIDC token-revoke linkage exists to prevent (a duplicate would let link formation pick a SCIM resource arbitrarily and revoke — or fail to revoke — the wrong principal's tokens), so the index is a **stronger** posture than what shipped before, not a regression to relax.

**Who this affects.** Any deployment with existing SCIM data (has ever run `--scim-enable`, even if it isn't set on this upgrade) where two or more `scim_resources` rows share the same non-empty `external_id` — most likely from an IdP connector bug, a manual data-fix gone wrong, or a resource re-provisioned under a new SCIM `id` without the old row ever being cleaned up.

**Before upgrading, run this against your existing database to check:**

```sql
SELECT external_id, COUNT(*) FROM scim_store.scim_resources
WHERE external_id IS NOT NULL
GROUP BY external_id
HAVING COUNT(*) > 1;
```

**If it returns any rows,** the upgrade will fail to boot until you resolve the duplicates first — deactivate or delete the stale/incorrect row(s) for each `external_id` this query surfaces (keep whichever row is the IdP's actual current resource), then re-run the query until it returns nothing. If it returns no rows, this note does not affect you and the migration applies silently on next boot.

### vNEXT — pre-auth request-body caps now apply to (almost) every route, not just `/mcp/` (#2407) (breaking)

**What changed.** Before this release, only the `/mcp/` ingress was capped ahead of authentication (4 MiB, #2437) — every other route was bounded only by httplib's own 100 MiB server-wide default, so an unauthenticated caller could make the server buffer up to 100 MiB per connection on any route. The server now resolves a per-route-class cap from a single table (`body_cap_policy.hpp`) at the same pre-routing chokepoint, before the body is read at all — including `GET`/`HEAD` requests (a GET declaring a `Content-Length` still buffers a body regardless of method) and the four unauthenticated health-probe paths (`/livez`, `/readyz`, `/health`, `/api/health`), which were previously the last unauthenticated 100 MiB buffer on the server because their early-return sat above the cap; they now hit the cap first and remain exempt only from the on-behalf-of guard and the rate limiter. Separately, a request declaring a compressed (non-`identity`) `Content-Encoding` is now refused outright (`415`) on **every** class, because httplib decompresses transparently and bounds only the decompressed size against its own 100 MiB global limit — a sub-cap compressed body could otherwise expand to ~100 MiB before this cap (or any handler) ever saw it. Full per-class numbers and the error contract: [`docs/user-manual/rest-api.md` "Pre-Auth Request Body Caps"](rest-api.md#pre-auth-request-body-caps-2407).

**What a client sees.**

- **`413`** — the declared `Content-Length` exceeds the resolved class's cap.
- **`411`** — the body cannot be sized in advance **by framing** (chunked, or no `Content-Length`) and this route's class requires one it can size. Today that is `/mcp/` only; every other class still admits an unmeasurable body up to httplib's 100 MiB backstop, unchanged from before this release.
- **`415`** — the request carries a `Content-Encoding` header other than `identity`. Refused on **every** class, unconditionally — this one is new in this release and does not depend on the class opting into anything. No shipped Yuzu route accepts a compressed request body, so this should not affect a conforming client; a client or intermediary that compresses request bodies (`gzip`/`br`/`deflate`) must stop doing so against this server. Send an identity-encoded body by **omitting `Content-Encoding` entirely** — do not send `Content-Encoding: identity` explicitly, which reaches httplib's own decompressor lookup, finds nothing to do, and today gets a bare `415` with none of this section's error-shape guarantees (no A4 envelope, no `yuzu_body_cap_rejected_total` increment); see the `415` row in [`docs/user-manual/rest-api.md`](rest-api.md#pre-auth-request-body-caps-2407) for the mechanism.

**Who this affects.** Any integration that was sending a body larger than its route's new class cap and relying on httplib's 100 MiB backstop to accept it. The most likely surface to notice: a very large `POST /api/v1/guaranteed-state/rules`, `/api/workflows`, or `/api/product-packs` body — those three classes are capped at a generous but explicit 16 MiB (a judgment call, not a measured contract, because no aggregate size limit for that content exists yet) rather than the previous 100 MiB backstop. Most other routes had a smaller handler-level check already (response templates, CA import) — for those, the effect really is just an earlier rejection at the same byte count (before the body is buffered rather than after). Also newly affected: any client or intermediary that sends a **compressed** request body — that is now refused outright with `415` on every class (see "What changed" above); no shipped Yuzu client compresses request bodies, so this is expected to affect only a custom integration or a reverse proxy doing transparent compression. One class is **not** the simple "earlier rejection, same effect" case, and clients should not assume "no behavior change" from it: **TAR queries** (`POST /api/dashboard/tar-execute`, `POST /api/v1/result-sets/from-tar-query`) — these two classes' caps as originally shipped bounded the RAW body at the same byte count their handlers check on a DECODED/PARSED value, which is not the same number; that unit mismatch caused some legitimate queries to be rejected here that the handler would have admitted. Both caps carry a margin now (see [`docs/user-manual/rest-api.md`](rest-api.md#pre-auth-request-body-caps-2407) for the sizing), so this class is now also a clean earlier-rejection-only change going forward. **SCIM is no longer a special case either** (fixed as part of this same change, D7): the pre-routing rejection now publishes SCIM's own RFC 7644 §3.12 `application/scim+json` error shape, matching what a strict SCIM client already expected from the handler's own (now-superseded) check.

**How to raise a cap.** Edit the table in `server/core/src/body_cap_policy.hpp` (with review) and the matching row in `docs/user-manual/rest-api.md`. Do **not** reach for httplib's global `Server::set_payload_max_length` — that knob is shared by every route on the listener, including the ~70 MiB live-query bundle route and the OTA agent-binary upload, so a single global value can't fit every route class at once. Rejections are visible per class via `yuzu_body_cap_rejected_total{path_class,reason}` — see `docs/user-manual/metrics.md`.

### vNEXT — `/auto` deployment execute now enforces per-device `Execution:Execute` confinement (breaking)

**What changed.** `/auto` deployment advance (staging + executing an installer on a pre-flight
run's go-cohort) previously dispatched every `content_dist.stage`/`content_dist.execute_staged`
command under the server's own system authority, bypassing the caller-identity check the
chokepoint performs for every other operator-facing dispatch surface — the check the route's own
permission gate depends on to confine *which devices* an operator's `Execution:Execute` grant
actually reaches. It now dispatches under the triggering operator's real identity and — as of a
second, related fix landing in the same release — is confined to that operator's
`Execution:Execute`-visible device set at the point of dispatch, the same per-device confinement
`RestApiV1`/`WorkflowRoutes`/`BundleOrchestrator`/`McpServer`/`DashboardRoutes` already enforce.

**Who this affects.** Only deployments where a role that can trigger `/auto` deploy
(`Infrastructure:Read` + `SoftwareDeployment:Execute`, per the permissions table in
[`preflight.md`](preflight.md#permissions)) holds a **management-group-scoped** `Execution:Execute`
grant — narrower than the full fleet — rather than a global one. For that role, a deployment whose
go-cohort includes a device outside the role's `Execution:Execute` scope will now correctly skip
that device (visible as `skipped` in the deployment's device list) instead of executing on it.
A role with a global `Execution:Execute` grant sees no change.

**Before upgrading, check for any role combining a scoped `Execution:Execute` grant with
`SoftwareDeployment:Execute`** — that combination is the only one affected. If none of your
deployment-triggering roles hold a scoped (rather than global) `Execution:Execute` grant, this
note does not affect you.

### vNEXT — an authorization-topology floor now applies regardless of RBAC, and engine-principal reads move off `Security:Read` (#2376) (breaking)

This note has **two independent breaking directions** — read both, they
affect different deployments.

**Direction 1 — RBAC-disabled installs lose three non-admin reads.**

**Who this affects.** Any deployment running with `[rbac] enabled = false`
(the shipped default) where a non-admin, authenticated session was relying
on reading one of: the fleet-wide access-review export
(`/api/v1/access-reviews*`), `GET /api/v1/rbac/roles`, or the
engine-principal inventory/roles (`/api/v1/engine-principals*` and the
`list_engine_principals`/`get_engine_principal`/`list_engine_roles` MCP
tools). RBAC-enabled deployments are unaffected by this direction (see
"Why" below).

**Why.** RBAC ships disabled by default. With RBAC disabled, the legacy
authorization fallback previously allowed **every** authenticated
non-engine session to perform **every** `Read` — including reads of the
authorization topology itself. A plain non-admin `user` on a default,
just-installed server could read who holds what role and pull the complete
access-review grant population that exists to be SOC 2 CC6.2 evidence. As
of this release, `AccessReview:Read`, `UserManagement:Read`, and
`EnginePrincipal:Read` (see Direction 2) require the `admin` session role
**regardless of the RBAC toggle**. This is not configurable — there is no
setting that reopens it. Full design rationale:
`docs/security-reviews/authz-topology-floor-2026-08-05.md`.

**What does NOT change.** A live RBAC grant is unaffected — under
RBAC-**enabled** enforcement, a non-admin holding the seeded `Reviewer`
role still reaches the access-review export exactly as before; a non-admin
holding `UserManagement:Read`/`EnginePrincipal:Read` (e.g. the built-in
`Viewer` role holds both) still reaches the other two reads. The floor only
engages inside the RBAC-off legacy fallback.

**What to do.** If a non-admin session needs one of these three reads,
enable RBAC and grant the matching role:

```cfg
[rbac]
enabled = true
```

- Access-review export → assign the built-in `Reviewer` role.
- `/rbac/roles` → the built-in `Viewer` role already holds
  `UserManagement:Read`, or grant it directly.
- Engine-principal reads → the built-in `Viewer` role already holds
  `EnginePrincipal:Read` (see Direction 2), or grant it directly.

See [`rbac.md`](rbac.md) "The authorization topology floor" and "Before
enabling RBAC in production" before flipping the toggle on a live fleet —
turning RBAC on also applies management-group-scoped device visibility
immediately.

**Direction 2 — RBAC-enabled deployments with a custom role granted
`Security:Read` for engine-principal access must re-grant.**

**Who this affects.** Any RBAC-**enabled** deployment with a **custom**
role (not `Administrator`/`Viewer`, which are updated automatically — see
below) that was granted `Security:Read` specifically so its holders could
reach `GET /api/v1/engine-principals*` or the
`list_engine_principals`/`get_engine_principal`/`list_engine_roles` MCP
tools.

**Why.** Those reads moved off `Security:Read` onto a new, narrower
`EnginePrincipal:Read` securable (the same move #2324 made cutting
`AccessReview` away from `AuditLog:*`) — `Security:Read` also gates
unrelated operational reads (quarantine visibility, CA issued-certs,
`/ca/root-csr`, KEK status) that stay on `Security:Read` unchanged and
un-floored.

**What changes automatically.** No schema migration is required — the new
`EnginePrincipal` securable and its `Administrator` (full CRUD) and
`Viewer` (`Read`) grants are seeded idempotently on every server boot
(`RbacStore::seed_defaults()`'s `INSERT OR IGNORE` loops), so the two
built-in roles pick it up on the next boot automatically, with no operator
action, matching exactly the access they held via `Security:Read` before
this change.

**What to do.** A custom role does **not** get this automatic re-seed.
Check whether any custom role was granted `Security:Read` for this
purpose, and if so, grant it `EnginePrincipal:Read` too — via the Settings
UI or `RbacStore::set_permission()` directly. `Security:Read` alone no
longer reaches `/api/v1/engine-principals*` or its MCP twins after this
upgrade.

**Direction 3 — API consumers of `GET /api/v1/discover/permissions` (and the MCP
`discover_permissions` twin) lose the role grid unless they hold
`UserManagement:Read`.**

**Who this affects.** Anything reading the discovery catalogue's
`roles[].permissions[]` under a principal that holds `Infrastructure:Read` but
not `UserManagement:Read`.

**What changes.** The route still returns `200` and the full
`securable_types`/`operations` taxonomy — that half is unchanged and still needs
only `Infrastructure:Read`. The `roles` key is replaced by `"roles_omitted": true`
plus a `roles_omitted_reason`. A consumer that iterates `roles` must handle its
absence; one that checks `roles_omitted` gets an unambiguous answer.

**Why.** That grid is authorization topology, and strictly more of it than
`GET /api/v1/rbac/roles` discloses — which this same change floors. Leaving it on
the unfloored `Infrastructure:Read`, which every authenticated session holds on an
RBAC-off install, left the floor reachable around. Flooring `Infrastructure:Read`
itself was rejected: it gates ordinary operational reads and would have repeated
the too-coarse mistake this change avoided with `Security:Read`.

**What to do.** Grant the consuming principal `UserManagement:Read` if it
legitimately needs the grid, or update it to read `roles_omitted`. Do not treat a
missing `roles` key as "no roles exist" — that is precisely why the omission is
declared.

**Check your automation, not just your operators — this is the failure that
hides.** Neither breaking direction produces a startup warning or a migration
prompt. Both surface only as a `403` at some later moment, and that moment may
be inside a script rather than in front of a person. Audit anything
non-interactive that reads the three floored surfaces
(`/api/v1/access-reviews/export`, `/api/v1/rbac/roles`,
`/api/v1/engine-principals*` and their MCP twins) under a **non-admin** token:

- A **compliance evidence collector** is the dangerous case. If it pulls the
  access-review export on a schedule and treats a non-`2xx` as "no grants to
  report" rather than as a hard failure, it will keep succeeding while
  silently collecting nothing — potentially for a whole audit period. Confirm
  yours fails loudly on `403`, and re-check the first collection after upgrade.
- A **monitoring or inventory job** on a non-admin token will start logging
  `403`s rather than breaking visibly.

Either enable RBAC and grant the job's principal the appropriate role
(`Reviewer` for access reviews, `UserManagement:Read` for `/rbac/roles`,
`EnginePrincipal:Read` for engine-principal reads), or move the job to an admin credential.

**One caveat on revoking a built-in role's grant.** Because the seed loops
above run on *every* boot, a grant you deliberately remove from a built-in
role — for example revoking `Viewer`'s `EnginePrincipal:Read` — is re-inserted
on the next restart, with no audit line distinguishing it from an
operator-set grant. This is long-standing behaviour for every seeded
securable, not new here, but it is worth knowing before you narrow a built-in
role: express the narrowing as a **custom role** or an explicit `deny` row
instead, both of which survive a restart.

### vNEXT — three new securables for directory-sync and enrollment reads; `Viewer` auto-gains `Directory:Read` (#4031) (breaking)

**Who this affects.** RBAC-**enabled** deployments with a **custom** role
that reads AD/Entra directory-synced users, or that previously reached the
directory-sync status / enrollment auto-approve rules / pending-agent list /
OIDC config surfaces before this release added dedicated REST v1 routes for
them.

**What changes automatically.** Three new securables — `Directory`,
`Enrollment`, `OidcConfig` — are seeded idempotently on every boot
(`RbacStore::seed_defaults()`), same mechanism as `EnginePrincipal` above.
Their built-in-role grants are **not symmetric**, unlike `EnginePrincipal`:

- `Directory:Read` is seeded to **both** `Administrator` and `Viewer` —
  matching the precedent set for other identity-adjacent PII reads
  (`UserManagement`). A custom role that previously relied on **not**
  inheriting directory-user PII visibility from a `Viewer`-equivalent grant
  set should check whether that matters for its use — this is a genuine
  **widening** of what `Viewer`-derived roles can see, not a like-for-like
  securable split the way `EnginePrincipal:Read` was. **RBAC-enabled
  deployments get more than a widening here, though:** `Directory` was
  never seeded to *any* role before this release, despite `GET
  /api/directory/users`/`/directory/status`/`/directory/sync` already
  gating on it — under RBAC-**enabled** enforcement this denied **every**
  role, including `Administrator`, not just non-`Viewer` custom roles. If
  your RBAC-enabled deployment could never reach the legacy directory-sync
  routes even as an admin, this release fixes that dead zone; the "Viewer
  gains new PII visibility" framing above only tells the RBAC-**disabled**
  half of the story.
- `Enrollment:Read` and `OidcConfig:Read` are seeded to `Administrator`
  **only** — `Viewer` deliberately does NOT gain either, since these gate
  the fleet's enrollment admission policy and SSO configuration rather than
  identity/inventory data. Both are also added to the authorization
  topology floor (see the #2376 note above), so an RBAC-**disabled**
  install denies them to a non-admin the same way it now denies
  `AccessReview:Read`/`UserManagement:Read`/`EnginePrincipal:Read`.

**What to do.** No action needed for `Administrator`/`Viewer` — the seed
loop picks these up automatically. If a custom role needs
`Enrollment:Read`/`OidcConfig:Read`, grant it directly (no built-in
non-admin role holds either). If a custom role's exposure to directory-user
PII via an inherited `Viewer`-shaped permission set is a concern, review it
explicitly — the auto-grant is intentional but new.

**Also new in this release:** the legacy `GET /api/directory/users` route
(pre-existing, not new in #4031) previously issued **no audit call at all**
despite returning PII; it is now audited as `directory.users.view`, though
via a fire-and-forget path that cannot detect a dropped audit row — see
[`audit-log.md`](audit-log.md)'s `directory.users.view` row for the full
three-way posture (REST v1 fail-closed / MCP set-and-proceed-with-signal /
legacy silent).

### vNEXT — approval tickets outstanding at the upgrade must be re-requested (#2442) (breaking)

**Who this affects.** Any deployment holding an **MCP** approval that was granted but not yet
redeemed at the moment of upgrade — that is, one an agentic worker will present back to an MCP tool
call. This is independent of the `mcp.` prefix entry below: it does not matter whether you author any
`mcp.`-prefixed definitions, and a deployment running only Yuzu-supplied content **is** affected if
it has an MCP approval in flight.

**Scheduled approvals are not affected.** A schedule redeems its own approval by matching the
schedule id, not through the MCP recall, so the origin check never sees it and a scheduled run
outstanding across the upgrade still fires. If nothing is awaiting an MCP recall when you upgrade,
there is nothing to do.

**Rolling BACK across this release re-opens the check, and rolling forward does not close it
again — but as of this same release, it does not stay open either.** The back-fill runs once, as a
schema migration. An older server started against an already-migrated database does not re-run it
and does not refuse to start; approvals it mints while you are rolled back record no minting
surface at all (the column is never set). Rolling forward will not revisit those rows, because the
migration has already run — but the MCP mint in this same release always declares its own surface
(see the "MCP mint now declares its own surface" entry below), so a row with no recorded surface is
no longer the value that grants: it is refused at recall exactly like a declared foreign surface,
not exempted. There is no window in which a rollback-minted ticket is redeemable once you are back
on a current server. Treat a roll-back as a window during which such tickets simply won't work
later — mint fresh ones after rolling forward rather than relying on anything minted during the
roll-back.

**What happens.** This release records which surface minted each approval, and rows that predate the
column carry no surface at all. Rather than assume one they may not have come from, the upgrade
labels them with a sentinel that fails closed — so an approval granted before the upgrade is refused
at recall. It is reported as `approval already used (one-time ticket)` even though it was never
consumed: that message is deliberately identical for every refusal so the recall cannot be used to
probe which surface minted a ticket, and that is why this note exists rather than the error
explaining itself.

**Recover** by calling the tool again without `approval_id` to mint a fresh ticket and have it
re-approved. Nothing is lost but the review. The affected population is only what is outstanding at
upgrade time, it does not grow afterwards, and approvals expire after 7 days regardless. On the
server side the refusal is distinguishable: the audit row records `refused: foreign_origin`, not the
uniform client message.

### vNEXT — the MCP mint now declares its own surface; undeclared tickets stop redeeming (#2442) (breaking)

**Who this affects.** Any deployment holding an **MCP** approval that was granted but not yet
redeemed at the moment of upgrade — the same population as the entry above, widened. The
previous release closed the check for a ticket a REST or scheduled mint declared as its own
surface; an MCP-minted ticket was still exempt, because the MCP gate could not yet declare
`kMcp` itself. This release removes that exemption: the MCP mint now stamps every new ticket
`kMcp` explicitly, and an undeclared ticket (the value an omitted `origin` argument used to
produce) is refused at recall exactly like a declared foreign surface.

**What happens.** Same mechanics as the entry above, same client message
(`approval already used (one-time ticket)`), same audit distinction (`refused: foreign_origin`).
The only difference is which population is now caught: any MCP ticket minted by a
pre-upgrade server — every one of them, since none could declare `kMcp` before this release —
that is still outstanding when you upgrade.

**Recover** the same way: call the tool again without `approval_id`. The affected population
does not grow after the upgrade — every ticket minted by the new server declares its surface
at mint time, so nothing outstanding from this point on can hit this case.

### vNEXT — MCP approval recall is now bound to its submitter (#2442) (intentional compatibility break, no supported flow affected)

**What changes.** An approval ticket's `approval_id` is a bearer capability — presenting it is
what authorizes the recall — and an id can be **disclosed** to a third party: `GET
/api/approvals` returns the full id to any principal holding `Approval:Read`, seeded to the
`Viewer` role. Until this release, a Viewer who also held the target tool's own RBAC permission
could take another operator's approved ticket id from that listing and redeem it themselves. The
MCP recall now refuses a ticket whose recorded submitter does not match the recalling principal,
the same way it already refuses one minted on a foreign surface — same client message, a distinct
audit token (`refused: foreign_submitter`) for the log.

**Who this affects.** No supported flow: the one production redemption path in this codebase
(the MCP recall) has only ever redeemed a ticket as the same principal that minted it, verified
by an exhaustive sweep of every mint and consume call site in the tree, and the non-binding was
documented as this issue's own hazard, never as an intended capability. What this cannot rule
out is an external integration that relied on the old behavior to hand an `approval_id` between
two different authenticated principals deliberately — nothing in this codebase does that, but an
operator's own tooling might have. If something in your deployment presented a ticket as a
different principal than the one that minted it, that now fails; there is no supported
replacement for it today (see #2442 if you need one). Nothing to do at upgrade for the ordinary
case: there is no outstanding-ticket population affected by this specific change, because a
legitimately-outstanding ticket was always going to be recalled by its own submitter.

### vNEXT — the `mcp.` instruction-definition id prefix is reserved (#2442) (breaking)

**Who this affects.** Anyone whose instruction definitions include an id beginning `mcp.`. No
shipped or bundled content uses that prefix, so a deployment running only Yuzu-supplied content
needs no action *for this item* — but the outstanding-approval entry above applies regardless of
what content you run.

**Why.** `mcp.<tool>` names an MCP approval ticket. At the time this shipped, the MCP recall
matched a ticket on its definition id and scope expression alone, so a definition authored under
that prefix could line up with an MCP tool's canonical arguments — a ticket raised on one surface
being redeemable on another. (Two later releases closed the redemption side of this directly, by
binding the recall to the ticket's recorded origin and separately to its submitter — see the two
entries above. This prefix reservation is the narrower, mint-time-adjacent half: it stops a
definition from being authored under `mcp.` at all.) Consuming a confused ticket still required
the schema check, the tier gate, per-handler RBAC and a human approval, so this closes a
namespace confusion rather than an open escalation.

**What changes.** Creating a definition whose id starts `mcp.` is refused with a 400 on every
authoring route that accepts an explicit id — `POST /api/instructions`, `POST
/api/instructions/yaml`, and `POST /api/instructions/import` — and such a definition is skipped
(counted in `defs_errored`) at boot auto-import. The dashboard's YAML validator refuses it too,
so Validate and Save agree on the create path. Product-pack install is unaffected because it
never carries a declared id through at all: the store assigns one, so a pack's own id, reserved
or not, has never been honoured.

**What does NOT change.** The store applies the rule at creation only, so a definition that
already carries such an id keeps executing and can still be saved through `PUT
/api/instructions/{id}` — an update cannot originate an id, so blocking it there would strand
content rather than protect anything. One exception, and it is the reason to rename rather than
live with it: the dashboard's YAML editor runs the same validation on every save, create or
update, so an existing `mcp.`-prefixed definition cannot be edited there if its document
declares `metadata.id` (one that omits it still saves, since the validator only checks a
declared id).

**What to do.** Before upgrading, check for affected content. Query the instruction database
directly rather than the REST list route: `GET /api/v1/definitions` caps its result at 100
definitions, and the shipped content alone exceeds that, so an API-based check can report a
false all-clear. Use a case-sensitive glob-style match — Postgres `LIKE` is case-sensitive by
default, but `~` (POSIX regex) is used below for an explicit anchor — the reservation is
case-sensitive: `MCP.foo` is a different id everywhere else in the system and is not reserved.
(Superseded — `instruction_definitions` moved to PostgreSQL under ADR-0058; this is no longer
a `sqlite3` query against `instructions.db`, see the PostgreSQL Substrate section below.)

```bash
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT id FROM instruction_store.instruction_definitions WHERE id ~ '^mcp\.';"
```

Any id listed keeps executing after the upgrade and can still be edited through
`PUT /api/instructions/{id}`, but re-importing an export of it will fail, and so will saving it
from the dashboard's YAML editor (that path validates the id on every save, not only on
create). Rename those definitions before upgrading — create a replacement under a different id
and delete the original.

### vNEXT — behind a reverse proxy, declare your external origin or CSRF-gated dashboard actions keep failing (#2537)

**Who this affects.** Anyone running the dashboard behind nginx, Envoy, HAProxy, an ALB or
Cloudflare where the proxy **rewrites the `Host` header** rather than passing the client's
value through. Direct access, and proxies configured to preserve `Host`, are unaffected and
need no change.

**The symptom.** Every CSRF-gated dashboard action fails with `403 cross-origin POST refused`
— CA revoke, CA import-chain, the TAR retention-paused re-enable and purge fragments, and the
gated settings POSTs. The dashboard renders fine and reads work; only the destructive actions
fail.

**Why.** The same-site check compares the browser's `Origin` against the server's `Host`. When
the proxy substitutes its own `Host`, those two legitimately differ: the browser says
`https://yuzu.customer.example` while the server sees `yuzu-server:8080`. The check was
correct and the deployment was correct; there was simply no way to tell the server its
external name.

**The fix — declare the external origin:**

```bash
yuzu-server --csrf-trusted-origin https://yuzu.customer.example
# or
YUZU_CSRF_TRUSTED_ORIGIN=https://yuzu.customer.example
```

Repeatable, and a single value may be comma-separated:

```bash
--csrf-trusted-origin https://yuzu.example --csrf-trusted-origin https://yuzu-dr.example
--csrf-trusted-origin "https://yuzu.example,https://yuzu-dr.example"
```

Two accepted forms, and the difference matters:

| Form | Matches |
|---|---|
| `https://yuzu.example` | that host **over https only** — an `http://` Origin for the same host is still refused |
| `yuzu.example` | that host over **either** scheme |

Prefer the scheme-qualified form. It also closes a weaker pre-existing behaviour in the same
check, where `http://h` satisfied a request to `https://h`.

Entries are case-insensitive, may carry a port, and any path is ignored. **Wildcards are not
supported** — `*.example` is accepted by the parser but will never match anything, deliberately.
The reserved token `null` is refused as an entry: it is the serialisation of an *opaque* origin
(sandboxed iframes, redirected cross-origin POSTs, `file://` documents), not a host, so trusting
it would admit all of them at once.

Port handling follows RFC 6454 — a port is dropped only when it is the default **for that entry's
scheme**:

| entry | canonical form | note |
|---|---|---|
| `https://yuzu.example:443` | `https://yuzu.example` | 443 is the https default |
| `http://yuzu.example:80` | `http://yuzu.example` | 80 is the http default |
| `https://yuzu.example:80` | *unchanged* | 80 is **not** the https default, so it is significant |
| `yuzu.example:8443` | *unchanged* | not a default under any scheme |
| `yuzu.example:443` | **rejected** | ambiguous — a bare entry cannot say which scheme's default this is |

The last row is the one to read twice. An earlier version collapsed a bare `yuzu.example:443` to
`yuzu.example`, which then trusted **both** `http://yuzu.example` and `https://yuzu.example` — one
declared origin silently trusting a second, which is the whole defect this canonicalisation exists
to prevent. Guessing `https` would be a guess, and keeping the port would make the entry unmatchable
(the request side canonicalises `https://yuzu.example:443` to `yuzu.example`). So it is refused, and
you write `https://yuzu.example` or `http://yuzu.example` instead.

A bare entry with **no** port is still deliberately loose: `yuzu.example` covers
`https://yuzu.example`, `https://yuzu.example:443`, `http://yuzu.example` and
`http://yuzu.example:80` — but not `https://yuzu.example:80`, which is a different origin.

Entries are also rejected if they are empty, host-less (`:443`), or carry userinfo (`u@host`) — the
last because the request side always fails closed on `@`, so accepting it would put an entry in the
boot log that could never match.

**Rejections are reported.** If any supplied value is refused, the server warns at boot with the
accepted-versus-supplied counts. Before this, an all-invalid config produced boot output identical
to not passing the flag at all, and the first symptom was the same opaque 403 the flag exists to
remove.

**Confirming it took.** The server logs the accepted set once at boot:

```
CSRF same-site gate: accepting 1 operator-declared external origin(s) in addition to the request Host — https://yuzu.customer.example
```

If that line is absent, or lists something other than what your users type into the address
bar, the 403s will continue. It is the fastest diagnosis for a mistyped entry.

**What has NOT changed.** A request whose `Origin` already matches `Host` behaves exactly as
before, so an unproxied deployment sees no difference. Non-browser clients sending neither
`Origin` nor `Referer` (curl, automation) are still admitted by the shared helper, and the two
CA endpoints still treat both-headers-absent as cross-site. Leaving the flag unset is safe: it
means same-host only, which is the previous behaviour.

**Deliberately not implemented: `X-Forwarded-Host` is never consulted.** Reading it would let
anyone able to reach the server's port declare their own external hostname and defeat the CSRF
check outright. Gating it on a trusted-proxy CIDR does not rescue that — on the container
networks the reference composes use, "inside the CIDR" is usually every sibling container, and
the failure mode is silent: the dashboard keeps working while the control is dead. A config
value cannot be set by an attacker, which is why the trust anchor here is a flag and not a
header.

### vNEXT — a device target that was supplied but names nothing is now refused, not widened to the fleet (#2500)

**What changed.** Three REST surfaces treated a targeting argument the caller *supplied* that
resolved to no devices as identical to one they never sent — and "no target named" meant
broadcast. `POST /api/command` with `{"plugin":"service","action":"restart","agent_ids":[1,2,3]}`
restarted the service on **every connected agent** under plain `Execution:Execute`, with no
approval step, and returned a success response. So did `{"agent_ids": []}`, which is what any
device filter that matched nothing produces. Each of these is now `400`.

**What breaks.** Requests that previously succeeded and now fail:

| Endpoint | Shape | Was | Now |
|---|---|---|---|
| `POST /api/command` | `agent_ids` `[]`, non-array, or containing a non-string | broadcast to all | `400` |
| `POST /api/command` | `scope` `""` or non-string | broadcast to all | `400` |
| `POST /api/instructions/{id}/execute` | `agent_ids` `[]`, non-array | broadcast to all | `400` |
| `POST /api/instructions/{id}/execute` | `scope` `""` or non-string | broadcast to all | `400` |
| `POST /api/v1/result-sets/from-*` | `parent_id` empty, non-string, or `null` | searched/dispatched unscoped | `400` |
| `POST /api/policies/{id}/remediate` | `agent_ids` `[]`, non-array, or containing a non-string | remediated **every non-compliant agent** in the policy | `400` |
| `POST /api/policies/{id}/remediate` | `scope` supplied at all | silently ignored, so a narrowing selector remediated every non-compliant agent | `400` — the route selects targets by `agent_ids` only |
| `POST /api/command` | body is not a JSON object | treated as "no target" → broadcast | `400` |
| `POST /api/command` | `plugin`/`action` outside `[A-Za-z0-9_.-]` or over 128 bytes | accepted | `400` |
| `POST /api/instructions/{id}/execute` | body is not a JSON object | treated as "no target" → broadcast | `400` |
| `POST /api/command` | `scope` is `"__all__"` | `400 invalid scope` | dispatches to **all connected agents** |
| `POST /api/v1/result-sets/from-*` | body is not a JSON object | `500` (uncaught type error) | `400` |
| `POST /api/dashboard/execute` | form field `scope=` supplied but EMPTY | broadcast to all | refused, nothing dispatched |
| `POST /api/dashboard/tar-execute` | query param `scope=` supplied but EMPTY | broadcast to all | refused, nothing dispatched |

The two remediation rows matter for the same reason as the rest: on that route an **absent**
`agent_ids` means "every non-compliant agent in this policy", so a supplied selector that named
nothing — or a `scope`, which that route cannot act on — quietly became a fleet-wide *mutating*
remediation. Omitting `agent_ids` entirely still targets every non-compliant agent, unchanged.

The instructions-execute row is the one to read twice: `"scope": "" + empty agent_ids = broadcast`
was **documented** behaviour in `rest-api.md`, so a client written against the published contract
is affected. The `from-*` row covers `from-tar-query`, `from-instruction-result`, `re-eval` and
`from-inventory-query`.

**One thing got LOOSER, not tighter.** `POST /api/command` previously rejected
`"scope": "__all__"` with `400 invalid scope` — the scope parser has no rule for it — while the
sibling instruction-execute route broadcast on the same string. It now broadcasts on both. This
grants no new access: broadcast was already reachable on that route by omitting targeting
entirely, under the same `Execution:Execute`, so `__all__` only gives a name to something a
caller could already do. But if you have a script that sends `__all__` and treats the `400` as a
no-op, it will now dispatch to the fleet.

**What still works, unchanged.** **Omitting both** `agent_ids` and `scope` broadcasts to all
connected agents, on every route. So does an explicit `"scope": "__all__"` — the ground scope kind already
advertised by `/discover/scope-kinds` and by the MCP `execute_instruction` schema. If you have a
client sending `"scope": ""` to mean "everything", change it to omit the field or to send
`"__all__"`; both are supported and neither is deprecated.

**Stored data — narrower than it first looks.** Only requests that **explicitly** send
`"scope": "__all__"` record `scope_expression = "__all__"` on the execution row, and those already
did so before this change. Broadcasting by **omitting both fields** is unchanged and still records
`""` — the execution row is written from the raw request value, before the omitted-means-`__all__`
mapping is applied for dispatch, and the mapped value is never written back. The one practical
change is that the dashboard's "All agents" button now sends `__all__` explicitly, so rows created
that way look different from before. A saved query selecting historical broadcasts by
`scope_expression = ''` still matches everything except dashboard-initiated ones.

**Dashboard users driving the UI in a browser need do nothing** — the Instructions execute
dialog's "All agents" option sends `__all__` instead of an empty string.

**But automation that POSTs the dashboard forms directly does need attention.** As of the
Wave-1 foundations change, `/api/dashboard/execute` and `/api/dashboard/tar-execute`
distinguish an OMITTED `scope` from one SUPPLIED as empty (`scope=`): omitted still means the
whole fleet, but supplied-but-empty is now refused and dispatches to nobody, where it
previously broadcast. If a script builds the form body unconditionally and leaves `scope`
blank when no device is selected, it will stop dispatching — which is the intended outcome,
but a silent one. Send `scope=__all__` to keep the fleet-wide behaviour deliberately.

**Detecting affected clients — and the limit of what is possible.** There is no reliable way to
find them *before* upgrading. The audit trail records the OUTCOME of a dispatch, not the request
shape that produced it: `command.dispatch|success` stores `plugin:action -> N agent(s)` and
`instruction.execute|success` stores `agents=<sent>`, and neither preserves the `agent_ids` or
`scope` the caller actually sent. So a historical broadcast that was deliberate and one that was
an accidentally-widened three-device request are indistinguishable in existing rows. The closest
available pre-upgrade signal is reviewing automation you believe targets a subset for dispatches
whose agent count is suspiciously close to your full fleet size. (The stored detail uses a literal
`\u2192` arrow, not `->`, so match on the agent count rather than the separator.)

After upgrading, refusals are counted by
`yuzu_server_dispatch_target_rejected_total{route,reason}` (all series pre-seeded at boot, so
`absent()` stays meaningful) and audited as `command.dispatch|denied`
(`detail=reason=<reason> <plugin>:<action>`), `instruction.execute|denied`
(`detail=reason=<reason>`) or `result_set.create|denied`
(`detail=reason=<reason> source_kind=<kind>`). The same action's `failure` result (#4496 + follow-up, the
`POST /api/v1/result-sets/from-inventory-query` producer and its MCP twin) carries
`detail=reason=store_degraded|query_truncated|poison_excluded|parse_error_excluded source_kind=inventory_query` - only
the latter three of those four are counted on `yuzu_server_dispatch_target_rejected_total`
(`route="result_set_inventory_query"`); `store_degraded` is a store-availability failure, not a
targeting-shape refusal, so it is not on this series. The
`YuzuDispatchTargetRejected` alert fires when the 15-minute increase exceeds 3 — deliberately not
on every single refusal, because a rule that pages on one malformed request gets silenced. Use the
audit rows, not the alert, to find individual offenders.

**`query_truncated`'s failure mode is structural, not a per-record near-miss - plan its runbook
step separately from `poison_excluded`/`parse_error_excluded`.** `poison_excluded` and
`parse_error_excluded` are both per-record and self-heal once the offending record is fixed or
excluded - they are DIFFERENT causes (over-nested `data_json` vs. `data_json` that fails to parse
as JSON at all), each with its own reason so an operator can tell which guard excluded a record,
but the same "per-record, self-healing" runbook shape applies to both. `query_truncated` fires
whenever the generic-inventory read backing both producer routes exceeds the hard-coded 5,000-row
cap or the 8 MiB aggregate payload cap - there is no pagination on this path today. On a fleet
whose inventory has grown past either cap, EVERY subsequent call to
`POST /api/v1/result-sets/from-inventory-query` or its MCP twin refuses with `query_truncated`,
and the alert never clears on its own. If you need to silence `YuzuDispatchTargetRejected` on such
a fleet before the fix lands, scope the Alertmanager silence to `reason="query_truncated"` AND
`route="result_set_inventory_query"` specifically - never the bare alertname, which would also
hide `poison_excluded`/`parse_error_excluded`, genuine near-miss signals that must stay visible.
Tracked fix: **#2633** (`InventoryStore::query` row cap (5000): keyset pagination +
`limit+1` truncation probe).

### vNEXT - result-set `instruction_id`/`params` fields are now bound-checked (#4373) (intentional compatibility break, no supported flow affected)

**What changed.** `POST /api/v1/result-sets/from-instruction-result` and `POST
/api/v1/result-sets/{id}/re-eval` had no bound on the `instruction_id` or `params` fields feeding
an InstructionDefinition dispatch: an over-keyed/oversized `params` object could reach fleet-wide
dispatch, and an oversized `instruction_id` could reach an unbounded `instruction_store` lookup
(a real registered instruction id is capped at 128 characters, so an oversized id could never
match one and dispatch - it reached the not-found fallback instead). Both routes now enforce the
same caps MCP's `create_result_set_from_instruction_result`/`reevaluate_result_set` tools enforce:
`instruction_id` at 256 bytes, `params` at 32 keys / 256-byte keys / 64 KiB values.

**What breaks.** Requests that previously succeeded and now fail:

| Endpoint | Shape | Was | Now |
|---|---|---|---|
| `POST /api/v1/result-sets/from-instruction-result` | `instruction_id` over 256 bytes | reached an unbounded store lookup, then 404 | `400` |
| `POST /api/v1/result-sets/from-instruction-result` | `params` over 32 keys, a key over 256 bytes, or a value over 64 KiB | dispatched | `400` |
| `POST /api/v1/result-sets/{id}/re-eval` | same, on a set whose stored `instruction_id`/`params` exceed the caps | re-dispatched (params) or reached an unbounded store lookup then 400 (instruction_id) | `400` |
| `POST /api/v1/result-sets/from-instruction-result` or `{id}/re-eval` | `params` present but not a JSON object (a string, array, or number) | dispatched/re-dispatched with an EMPTY params map, silently discarding it | `400` |
| `POST /api/v1/result-sets/from-tar-query` | `sql` present but not a JSON string | uncaught exception, bare `500` | `400` |
| `POST /api/v1/result-sets/from-instruction-result` or `{id}/re-eval` | `instruction_id` present but not a JSON string | uncaught exception, bare `500` | `400` |
| `POST /api/v1/result-sets/from-tar-query` or `from-instruction-result` | `name` present but not a JSON string | uncaught exception, bare `500` | `400` |
| `POST /api/v1/result-sets`, `from-tar-query`, `from-instruction-result`, or `from-inventory-query` | `name` over 256 bytes, or (generic create route only) `source_kind` over 64 bytes | persisted/dispatched unbounded | `400` |
| `POST /api/v1/result-sets` (the generic/synchronous create route) | `name` or `source_kind` present but not a JSON string | uncaught exception, bare `500` | `400` |

**Who this affects.** Callers sending a field past a numeric/count bound (`instruction_id`,
`params` count/key-length/value-length, both at the same values MCP's equivalent tools enforce -
MCP's handler-side bounds landed within days of this fix, in the same unreleased cycle, not a
long-standing MCP/REST gap), AND separately callers sending a wrong-typed `params`, `name`, or
`source_kind` (not a numeric bound at all - a shape/type mismatch, always rejected regardless of
size). No supported flow constructs any of these fields anywhere near the numeric limits or with
the wrong JSON type, so no compliant client is affected either way.

### vNEXT — `POST /mcp/v1/` can now hold its response open as an SSE stream (2f PR 3b)

A `tools/call` for `execute_instruction` that carries `_meta.progressToken` **and**
an SSE-capable `Accept` now receives its progress on the POST response itself
rather than on the session's GET stream. Opt-in and per request: a call that sends
neither, or only one of the two, behaves exactly as before and is byte-identical on
the wire. Plain POST clients (mcp-remote, Claude Desktop) are unaffected.

Three operator-visible consequences:

- **Sizing.** A streamed POST holds an HTTP worker for up to its response cap
  (120 s), enforced on a busy execution too (#2739): after the cap expires the
  bridge delivers one final drain of already-latched progress and then settles,
  so the bound is the cap plus at most two ~3 s pump ticks plus one bounded
  progress drain (a single latest-wins snapshot since #2412) and its
  socket-write time (the server's 30 s write timeout,
  `set_write_timeout` in `server.cpp`) — worst case ~156 s, not the execution's
  duration. It leases from the same held-open budget as the GET channel, so
  total concurrency is unchanged — but `TimeoutStopSec` and any container
  termination grace period should be sized comfortably above that ~156 s bound
  (the shipped systemd unit and every shipped compose file use **210 s**); 30 s
  — which suited GET alone — is the figure to move away from. Under-sizing
  SIGKILLs mid-drain and silently drops in-flight streams on deploy.
  **Update (#3042):** the ~156 s figure above bounds a single streamed-POST
  *call* during ordinary (non-shutdown) operation — it is not how long
  `ServerImpl::stop()` itself waits on one. Since #3042, graceful shutdown
  close-signals every live MCP session up front, so a streamed POST held open
  across an ordinary `stop()` ends within about one pump tick (~3 s), not the
  120 s cap; the underlying execution is unaffected and stays fetchable by
  `execution_id`. What still bounds shutdown is a stream stuck mid-write to a
  blackholed or drip-feeding peer (the 30 s write timeout) — see
  `docs/mcp-server.md`'s Shutdown section for the current mechanism. The 210 s
  `TimeoutStopSec` recommendation above remains a safe, comfortably
  conservative choice; it is no longer the tight bound its original
  derivation implied.
- **Per-principal ceiling.** `--mcp-max-streams-per-principal` governs the GET
  channel. The streamed-POST allowance is a fixed 4 concurrent calls per
  principal — numerically the same as, but counted and enforced separately
  from, any single session's own replay-ring pin-slot count — so the
  steady-state per-principal held-open sum across both channels is
  `--mcp-max-streams-per-principal + 4`. That sum is not a hard ceiling: a
  GET-channel reconnect keeps the superseded connection's count until it
  finishes draining, and `McpStreamState` bounds this to one pending handover
  per *session*, not per principal — a principal with every one of its GET
  sessions mid-handover at once can transiently double the GET component.
  Lowering the flag to contain a noisy principal does not reduce its
  streamed-POST concurrency.
- **Reverse proxies.** The response sets `X-Accel-Buffering: no`, which only nginx
  honours. Envoy, HAProxy, ALB and Cloudflare need their own no-buffering opt-out,
  or the stream is buffered and dead clients are not detected.

`--mcp-no-streaming` remains the kill switch and now also degrades the streamed
POST arm back to plain JSON, not just GET/DELETE.

### vNEXT — streamed POST (`--mcp-enable-streamed-post`) now ships ON by default (breaking)

The feature described in the vNEXT entry above already existed; this entry is
about its **default** changing. Every prerequisite that gated the on-by-default flip
(#2739, #2740, #2785, #2789) is fixed, so a server started with no MCP flags now
serves streamed POST for any `execute_instruction` call that sends
`_meta.progressToken` with an SSE-capable `Accept` — no configuration required.

**What this means for an upgrading operator**, restated from the Sizing and
per-principal bullets above because they are no longer conditional on opting in
— they now apply to every deployment by default:

- **`TimeoutStopSec` (or your container runtime's equivalent termination grace)
  must be sized comfortably above the ~156 s worst-case bound derived in the
  Sizing bullet above** (120 s cap + pump ticks + the 30 s write timeout), not
  the ~30 s that sufficed for the GET channel alone. The shipped systemd unit
  and every shipped compose file that runs `yuzu-server` use **210 s** — use
  that as your own starting point if you're not deploying from one of those. This
  was previously only a concern for operators who had explicitly enabled the
  flag; it is now the default posture for every deployment that takes no
  action.
- **A principal's steady-state held-open sum is `--mcp-max-streams-per-principal
  + 4`** — the streamed-POST allowance is no longer contingent on opting in, it
  applies to every deployment by default. That sum is not a hard ceiling (see
  the Per-principal ceiling bullet above for the GET-reconnect transient).
- **If you're behind a non-nginx reverse proxy (Envoy, HAProxy, ALB,
  Cloudflare) or running an MCP client whose HTTP transport can't consume a
  streamed response body**, verify SSE-on-POST actually reaches your client
  before upgrading (see the Reverse proxies bullet above) — otherwise a call
  that previously answered promptly can appear to hang for up to the ~156 s
  worst-case bound (see the Sizing bullet above), not just the 120 s cap.
  Pass `--no-mcp-streamed-post` if you'd rather verify after upgrading.

**To opt out**, pass `--no-mcp-streamed-post` (or set
`YUZU_MCP_ENABLE_STREAMED_POST=false`) to keep the pre-flip plain-POST-only
behavior. `--mcp-no-streaming` remains the broader kill switch and disables
streamed POST along with the rest of the Streamable HTTP transport.

### vNEXT — MCP stream revalidation rides the tick, and the pin-drift alert moves to a new counter

Two operator-visible changes to held-open MCP `GET` SSE streams. Neither changes a
revocation bound: the documented one-tick single-server figure still holds and is now
pinned by tests.

**Credential re-checks are once per tick, and busy streams stop sending heartbeat
filler.** A stream delivering frames continuously previously re-validated its
credential and slid its session TTL on *every frame*; both now run once per ~3 s tick,
and a pass that delivered real frames skips the redundant heartbeat. If anything on
your side counts `event: heartbeat` frames as a liveness signal, key on *any*
delivered frame instead.

**The admission-drift reading moved counters.** `yuzu_mcp_stream_final_unpinned_total`
used to carry the "replay-ring pin accounting has drifted" reading; that reading now
belongs to the new `yuzu_mcp_stream_pin_displaced_total` (the server now displaces the
oldest pinned terminal instead of committing the newest unprotected, which is strictly
less bad). If you alert on `final_unpinned_total > 0`, keep that rule and add the same
rule for `pin_displaced_total` — reference rules for both ship in
`docs/prometheus/yuzu-alerts.yml`, and the response procedure is
`docs/ops-runbooks/mcp-stream-pin-displacement.md` (diagnostic only — no restart).

### vNEXT — engine-principal streams: liveness re-checks are cached, and the outage grace window is measured differently (#2367)

Two operator-visible changes to held-open MCP/SSE streams authenticated by an
**engine** principal. Nothing changes for human or API-token streams.

**Liveness re-checks are cached for 15 seconds.** Every held-open stream
re-validates its credential on each ~3 s heartbeat tick. For engine principals
that check previously read PostgreSQL every tick, which under a connection-pool
brownout was self-amplifying and could starve ordinary request traffic — not
just streaming. It is now served from a short cache, and a store that cannot be
reached is rate-limited rather than re-asked on every tick.

Fresh authorization is unaffected: creating a session and on-behalf-of target
checks still read through on every call, so revoking an engine principal stops
new sessions immediately. On the server handling the revoke, live streams are
still cut on the next tick — the cache is invalidated as part of that write.
Across replicas, a revoke reaches another replica's stream within the 15 s TTL
plus a tick. If your compliance posture quotes a revocation-latency figure for
engine principals, that is the number.

**A stream may now end sooner during a PostgreSQL outage.** The 60 s
indeterminate grace window is now measured from the stream's last
*authoritative* credential confirmation rather than from the moment the outage
was noticed. Previously a stream could ride cached answers and then collect a
full fresh 60 s window on top of them; total survival past a real confirmation
is now bounded by the window itself. In practice a stream can close with
`auth_unavailable` up to ~15 s earlier than before. Clients reconnect and
resume via `Last-Event-ID` as they already do, and durable results remain
fetchable by `execution_id`.

**New observability.** Four metrics
(`yuzu_server_engine_revalidate_cache_hits_total`, `..._misses_total`,
`..._cache_size`, `..._backoff_suppressed_total` — see
[metrics.md](metrics.md)). The last is the brownout signal: it moves only while
the store is unreachable. The server also emits a startup warning when
effective SSE stream capacity exceeds 16x `--postgres-pool-size`; if you see
it, watch `yuzu_pg_acquire_wait_seconds` and `yuzu_pg_pool_in_use` before
raising either.

No configuration changes are required and no flags were added.

### vNEXT — MCP supervised-tier calls now enforce the published input schema pre-approval (#2405)

Approval-gated MCP `tools/call` arguments are now validated against the tool's
published `inputSchema` BEFORE an approval ticket is minted or consumed. Most
callers only fail earlier (junk args that would have failed after admin
approval now answer `-32602` immediately, with no ticket created or burned).

**Previously-succeeding shapes that now break — supervised-tier
`execute_instruction` / `execute_bundle`, plus any approval-gated tool taking
an `integer` parameter:**

- `execute_instruction` / `execute_bundle` with a `params` object containing a
  non-string value (number/bool/array/object) — previously silently
  stringified by the handler after approval. Stringify client-side.
- `execute_bundle` with `steps: []` or more than 32 steps (the schema's
  `minItems`/`maxItems`, matching the handler's own 1–32 bound).
- `execute_instruction` with more than 10 000 `agent_ids`, or any single
  `agent_ids` element longer than 128 bytes.
- `execute_instruction` with `plugin`/`action` longer than 128 bytes, or
  `scope` / a `params` value longer than 8192 bytes. (`execute_bundle`'s
  per-step `plugin`/`action`/`params` carry no length bound and so are
  unaffected by *these* bounds — the non-string rule above still applies to
  them.)
- Any approval-gated tool given an **integral float** where the schema declares
  `integer` — e.g. `mint_engine_credential {"ttl_days": 90.0}` or
  `rotate_engine_credential {"overlap_days": 7.0}`. These previously
  "succeeded" in the worst way: the server ignored the value and silently
  applied the parameter's default. Send a JSON integer (`90`, not `90.0`) —
  note that Python's `json.dumps` emits `90.0` for a float-typed value.

The bound-based rejections above were already the published schema contract
(added in track 2f) but were client-advisory until this change; they are now
enforced on the approval-gated path. **Operator and readonly callers of these
two tools are unchanged** — schema validation runs where `requires_approval` is
true, which for `Execution:Execute` is the supervised tier only, so those
bounds stay advisory on the other tiers (full every-path enforcement is tracked
in #2437). Note the gate keys on the *operation*, not the tier: `delete_tag` is
approval-gated on **operator** as well, so its arguments are validated there
too — it simply carries no length or count bound today, so nothing breaks. Any approval ticket already minted-and-approved for one of the shapes
above becomes unrecallable fail-closed (it is never consumed) and expires on
the normal 7-day approval TTL; re-submit the corrected call for a fresh ticket.

Also note: a recall whose arguments fail schema validation now answers `-32602`
before the ticket is even looked up — clients that pattern-matched `-32003` for
every recall failure should treat `-32602` as "fix the arguments, ticket
untouched". Full detail: `docs/mcp-server.md` "Pre-approval input-schema
validation".

### vNEXT — MCP tool annotations are now truthful; write tools carry `destructiveHint:true` for the first time

Track 2g PR 2. Every MCP tool now advertises the four standard annotation hints
(`readOnlyHint`/`destructiveHint`/`idempotentHint`/`openWorldHint`), generated
from a single-source classification and enforced truthful by a CI cross-check
test. Operator-visible effect: an agentic worker that renders a confirmation
prompt off `destructiveHint` will, for the first time, prompt on the write tools
that previously carried no annotation (`execute_instruction`, `execute_bundle`,
`set_tag`, `delete_tag`, `quarantine_device`, `revoke_certificate`, and more),
and three previously false-safe hints (`confirm_engine_rotation`,
`close_access_review`) are corrected. The hints are **advisory UX only** — the
tier + maker-checker approval gate is unchanged and remains the enforcement.
Because MCP advertises `tools.listChanged:false`, long-lived clients should
reconnect after this deploy to pick up the corrected hints. Not a breaking change
(no previously-working call is rejected). Full detail: `docs/user-manual/mcp.md`
"Available Tools". *(Since superseded for `confirm_engine_rotation`: #2384 added
a required `token_id` argument that pins the confirm to the exact pending
rotation, so its `idempotentHint` is corrected back to `true` — and the new
required argument IS a breaking change for that one unreleased tool/route.)*

### vNEXT — `confirm_engine_rotation` replay-after-resolution is now a terminal error (#2404)

Direct sequel to the `#2384` entry above. A `confirm` (REST
`POST /api/v1/engine-principals/{id}/credentials/confirm` or MCP
`confirm_engine_rotation`) replayed **after the rotation already resolved** — a
network-dropped `200`, a double-submit, or a client racing the auto-revoke
sweep — now returns a **terminal** `409` / MCP `kInvalidParams` (`rotation
already confirmed` / `no rotation in flight ... already the sole active
credential`), instead of the previous retryable `503`. A confirm that finds
**more than two** active credentials likewise now returns a terminal `400`
(was `503`). Only a genuinely-empty read and an unrecognized two-credential
pair stay `503`.

**Not a breaking change** by this file's convention — no previously-succeeding
call is rejected; the first, real confirm still returns `200` identically. But
**worth a glance for any integration that pattern-matches `503 => retry`**: such
a client will now loop forever against a permanently-`503` call under the old
behavior, which is exactly the livelock this fixes — after the upgrade it gets a
terminal `409`/`400` and should stop and (if it genuinely needs a new
credential) call `rotate`, not replay `confirm`. Agentic MCP clients honouring
`idempotentHint:true` get the correct terminal answer automatically. Full
detail: `docs/user-manual/rest-api.md` (confirm error table) and
`docs/user-manual/engine-principals.md`.

### vNEXT — API-token rotation confirm-identity binding now survives a restart; first schema change to `api_tokens` (#2961)

Migration v3 adds `api_tokens.rotation_initiator` (durable twin of the
confirm-identity binding described in `docs/auth-architecture.md`
"Confirm-identity binding survives a server restart"). This is the FIRST
schema change ever applied to `api_tokens` since it shipped — every
authenticated request validates a Bearer token against this table, so it is
one of the hottest tables on the server.

**Not breaking, but worth knowing before a rolling upgrade.** `ALTER TABLE
... ADD COLUMN ... DEFAULT ''` takes Postgres's briefest possible form (a
metadata-only "fast default" on PG 11+, not a table rewrite) but is still an
`ACCESS EXCLUSIVE` DDL statement: it must wait for every transaction
currently touching `api_tokens` to finish before it can run, and every new
transaction on the table queues behind it in turn while it waits. During a
rolling upgrade, an outgoing replica's still-open request handling can hold
such a transaction open. This is bounded and loud, not silent: the pool's
`lock_timeout` (10s, `pg_pool.hpp`) cancels the migration's `ALTER` if it
queues that long, and `ApiTokenStore` construction fails closed exactly as
it does for any other migration failure — the new binary refuses to start
with a clear log line rather than serving degraded or hanging the table. If
you see this on a rolling upgrade, retry once traffic quiesces (a load
balancer draining the outgoing replica is usually enough); it is not a data
integrity concern either way.

### vNEXT — a device quarantined while offline now re-contains itself automatically on reconnect (#3425) (breaking)

`QuarantineStore` gains schema v2: two columns on `quarantine_records`
(`last_applied_at`, `last_confirmed_at`, both `BIGINT NOT NULL DEFAULT 0`) tracking whether a new
background component, `QuarantineContainmentReconciler`, has re-applied and confirmed a device's
endpoint firewall since it last reconnected. Same `ACCESS EXCLUSIVE` migration-lock note as the
API-token entry above applies here too — negligible in practice, since `quarantine_records` is a
small, manually-curated security-event table, not a hot path.

No operator action needed for the reconciler itself. Previously, a device quarantined while
offline stayed contained at the control plane (the #881 dispatch gate) indefinitely, but its own
firewall was never (re-)applied until someone noticed and manually re-issued the
`quarantine_device` MCP call. On upgrade, every pre-existing active quarantine record starts
unconfirmed, so expect one automatic re-application attempt per connected contained device shortly
after the new binary starts serving — this is idempotent and is the correct, intended behaviour
(those are exactly the devices whose endpoint containment was never independently confirmed). See
`docs/user-manual/security-hardening.md` "Reconnect re-application (#3425)" for the mechanism and
the new `yuzu_server_quarantine_endpoint_unconfirmed{reachability}` /
`yuzu_server_quarantine_reapply_total{result}` / `yuzu_server_quarantine_reconciler_tick_healthy`
metrics.

**BREAKING for callers of `POST /api/v1/quarantine`.** This route now validates `whitelist` at
write time (≤512 chars, `[0-9A-Fa-f.:]` tokens only) and rejects a malformed value with `400`
instead of persisting it — a caller relying on the old permissiveness for a CIDR range or hostname
entry now gets `400` where it previously got `201`. This route only ever creates a NEW record (it
already refuses with `400` if the device is already quarantined), so no *existing* containment is
ever lost by this change — but a caller that fires a quarantine request and ignores a `400`
response now gets zero protection for that device, where before a malformed-but-persisted record
still left it denied at the #881 control-plane dispatch gate (its endpoint firewall was never
actually enforceable either way, since the same malformed value could never be dispatched). Check
the response status; do not assume success.

`QuarantineContainmentReconciler` is **always on, with no configuration surface** — no CLI flag or
env var disables or tunes it (matching the #881 dispatch gate it complements, which is the same
way). Its cadence (20s tick), per-agent timing (60s minimum reapply interval, 15-minute backoff
cap), and per-tick dispatch cap (50 agents) are fixed `constexpr` constants in
`quarantine_containment_reconciler.hpp`, not runtime-configurable.

### vNEXT — the rotation sweep now carries the full clock-guarded-retention shape (#2964)

**What changed.** `ApiTokenStore::sweep_expired_rotations` — the 60-second
background sweep that auto-revokes rotation predecessors for *both*
engine-credential and human API-token overlap pairs — previously issued its
delete on a bare local wall-clock comparison, capped per tick but with no
persisted clock anchor and no anomaly detection. It now reads a
Postgres-authoritative clock, persists a durable anchor in a new
`rotation_retention_meta` table (schema v4), and classifies every tick
through the same guard `audit_store`'s retention pass uses — a clock anomaly
or a not-yet-trustworthy anchor **declines** the tick outright rather than
revoke on an unverified reading, leaving both credentials in every affected
pair active for at least one more tick. Detail:
`docs/user-manual/authentication.md` "Rotating a Token",
`docs/user-manual/engine-principals.md` "Rotate the credential (overlap-pair
model)", and `docs/user-manual/metrics.md` "Rotation-sweep clock guard
metrics".

**HA / multi-replica.** Unlike `audit_store`'s retention pass, this sweep is
single-writer **by construction**: before it will classify anything, it
takes a store-wide PostgreSQL **session** advisory lock in its own key
namespace. This is what makes the per-tick auto-revoke cap (≤200) a
**cluster-wide** cap rather than a per-replica one that would otherwise let
an N-replica deployment auto-revoke up to `N x 200` predecessors in one
tick. A replica that does not win the lock on a given tick records a
`SkippedLock` outcome and does nothing that tick — expected, routine
behaviour on a genuinely multi-replica deployment, where roughly
`(N-1)/N` of ticks land there for any given replica. **On a single-replica
deployment — the default — this is not "routine leader-election
contention" at all: one dedicated sweep thread on a sequential 60-second
loop cannot lose an election against itself, so `SkippedLock` there can only
mean a *second writer* holding the same session lock** — a zombie process
left over from a crashed instance, a botched blue-green cutover overlapping
two live instances briefly, or an unauthorised second server pointed at the
same DSN. If you run single-replica, treat any sustained non-zero
`yuzu_rotation_sweep_lock_skipped_total` as a fault to investigate, not
background noise; see `docs/ops-runbooks/rotation-sweep-clock-guard.md`.

### vNEXT — API-token rotation confirm now requires proof of possession (#3015) (breaking)

**What changed.** `confirm` on a rotation — REST `POST /api/v1/tokens/{id}/confirm` and `POST /api/v1/engine-principals/{id}/credentials/confirm`, plus the MCP twins `confirm_api_token_rotation`/`confirm_engine_rotation` — previously admitted on caller identity plus the successor's `token_id` alone. A caller who recovered an unknown successor's `token_id` out-of-band (a support ticket, a log line) could confirm — and thereby revoke the predecessor for — a rotation whose secret they never received. All four confirm surfaces now additionally require the raw successor secret in the request body/args, verified with a constant-time hash comparison against the successor's stored hash, checked LAST — strictly after ownership, pair-state, the `token_id` pin, tier, scope, and the initiator binding have all already passed — before the predecessor is touched.

**Who this affects.** Any caller confirming with only `token_id`: REST now returns `400` instead of succeeding; MCP returns `kInvalidParams`. A caller confirming with a *wrong* secret gets REST `403` / MCP `kPermissionDenied`. Correctly-installing automation is unaffected — the secret required here is the same raw value the `rotate` response already returns exactly once (REST `data.token`), so automation that installs the successor from that response and passes it straight to `confirm` sees no behavior change.

**If you lose the rotate response before confirming,** you can no longer confirm — the secret cannot be manufactured from the `token_id` alone. Two recovery paths:

1. **Wait for the automatic overlap-window sweep.** Proof of possession gates the immediate, explicit `confirm` call only — the 60-second background sweep is unaffected by this change and still auto-revokes the predecessor on its own schedule with no secret required, provided the successor secret was actually installed and presented (used) at least once.
2. **Revoke the unknown successor and start a new rotation** (`DELETE /api/v1/tokens/{token_id}` or the engine-principal twin) — keeps the predecessor working immediately, at the cost of restarting the rotation.

Full detail: [`authentication.md`](authentication.md#rotating-a-token) "Rotating a Token", [`engine-principals.md`](engine-principals.md) "Rotate the credential", and [`mcp.md`](mcp.md) rows 61/71.

### vNEXT — Guardian status routes gain real data, new denial/failure modes (#2298 item 6d) (breaking)

**What changed.** `GET /api/v1/guaranteed-state/status` and
`/status/{agent_id}` previously returned a hardcoded placeholder
(`errored_rules: 0`, always `200`). `errored_rules` is now real, derived
from the same per-agent compliance census (`guardian_agent_rule_status`)
the dashboard's Unhealthy Guards card reads, intersected against the live
rule catalogue. `compliant_rules`/`drifted_rules` remain placeholder `0`
pending full status ingest, tracked separately.

**What a client sees.**

- **`403`** on the fleet route (`/status`, no `{agent_id}`) — new. A
  service-scoped API token is now refused outright rather than admitted to
  a fleet-wide aggregate outside its own scope: this route aggregates
  across every agent's census, and the underlying permission check does
  not apply a service-scoped token's own service-tag confinement (it only
  checks a role grant), so admitting it here would have let a token scoped
  to one service read a fleet-wide count.
- A **narrower `errored_rules` count** (still `200`) on the fleet route
  for a management-group-**confined** (not global) `GuaranteedState:Read`
  grant — new. This route moved from a bare global permission check (any
  authenticated `GuaranteedState:Read` holder got the unfiltered
  fleet-wide count) to `AuthRoutes::require_list_read` — the route's SOLE
  gate (ADR-0017 admit-then-filter; never stacked with the flat
  `require_permission`, which does not consult management groups and
  cannot compose with a separate confinement check bolted on afterward). An
  earlier, unreleased attempt at this exact fix stacked a direct
  `authorize_list_read` call BEHIND the flat `require_permission` gate
  instead of replacing it — that composition never actually confined
  anyone (a confined caller was denied by the flat gate before the
  confinement check ever ran) and was corrected before shipping; nothing
  described below was ever live under that broken attempt. A
  caller with no `GuaranteedState:Read` grant at all
  (global or via any management group) now gets `403` instead of `200`
  (this is a SEPARATE outcome from the narrower-count case above — a
  confined grant that resolves to at least a scope, even an empty one,
  never gets a `403` from the confinement decision itself; a `403` from
  this route means either a service-scoped token, no usable grant, or,
  rarer, a fail-closed authorization-store fault, which denies even a
  caller who otherwise holds a resolvable confined grant — see
  `rest-api.md` for the full 4xx taxonomy). A caller whose grant is confined to specific management groups now sees
  `errored_rules` scoped to their **visible agents only**, not the whole
  fleet — including `0` if their groups contain no agents at all, which is
  still `200`, not `403` (a real grant that resolves to an empty visible
  set is a legitimate answer, not a denial). `total_rules` is unaffected
  by this change on either route: it counts the rule *catalogue*, which
  has no agent dimension to confine. A global (non-group-confined) grant
  is unaffected on the fleet route too — it still sees the full fleet
  count, same as before.
- **`403`** on the per-agent route (`/status/{agent_id}`) — new. This route
  moved from a bare global permission check (any authenticated
  `GuaranteedState:Read` holder got `200`, even with a management-group
  scope that does not cover the requested device) to the same per-device
  scoped check `GET /guaranteed-state/device-compliance` uses. A caller
  whose `GuaranteedState:Read` grant is confined to management groups that
  do not include the requested `agent_id` now gets `403` instead of a
  `200` carrying placeholder-zero data for a device outside their scope. A
  global (non-group-confined) grant is unaffected — it still passes
  fleet-wide, same as before.
- **`503`** on the per-agent route (`/status/{agent_id}`) — new failure
  mode. This route now performs a **behavioral-PII access audit**
  (`guardian.device.view`, same verb as `GET
  /guaranteed-state/device-compliance` and `GET /dex/devices/{id}`) before
  serving per-device data, and fails **closed**
  (`503` + `Sec-Audit-Failed: true`) if that audit row cannot persist —
  the audit subsystem being unavailable is not itself new, but this route
  could not previously return `503` for it because it served no real
  per-device data before.
- **`503`** on either route if the Guaranteed State store degrades — new;
  previously the route degraded silently to `0` on any store fault.

**Who this affects.** Any integration polling either route that (a) uses a
service-scoped API token against the fleet route — that call now needs
either a non-service-scoped credential or a per-agent call against
`/status/{agent_id}` instead, and the per-agent route is not an
unconditional substitute: `require_scoped_permission` additionally checks
that the *target* `agent_id`'s own `service` tag matches the token's scope
(`tag_store`-backed), so a service-scoped token still gets `403` there for
any device outside its own service, distinct from the fleet route's
simpler "any service-scoped token, unconditionally" denial; (b) holds a
management-group-**confined**
(not global) `GuaranteedState:Read` grant and polls `/status/{agent_id}`
for a device outside that scope — that call now gets `403` where it
previously got `200` with placeholder data, the same confinement
`/guaranteed-state/device-compliance` has always enforced; (c) holds a
management-group-**confined** grant and polls the **fleet** route
(`/status`) — that call still gets `200`, but `errored_rules` now reflects
only the caller's visible agents rather than the whole fleet; a real grant
that resolves to ZERO visible agents (an empty or agent-less management
group) is still `200` with `errored_rules: 0` (ADR-0017 INV-2 — a real
grant that is simply narrow is not a denial), distinct from holding no
`GuaranteedState:Read` grant anywhere, which is `403` on either route; or (d)
treats every response as `200` — both routes can now return `403`/`503`
and a client that does not already retry on `5xx` (standard practice for
every other Guaranteed State route) should add that handling. No change
for a global-permission, non-service-scoped caller on the happy path
beyond `errored_rules` becoming a real, changing number instead of a
constant `0`.

### vNEXT — macOS antivirus posture is now probed, not asserted

The `antivirus` plugin's macOS leg previously hardcoded `av|XProtect|active`
without reading anything, and its third-party checks grepped for the wrong
process name. Visible after upgrading agents:

1. **`av|XProtect|<state>` is now a real probe** of the XProtect definition
   bundle: `active` comes with a new `xprotect_version|<n>` row; `unknown`
   means the bundle was unreadable (never assumed active). Third-party EDR/AV
   detected via endpoint-security system extensions emit an additional
   `edr|<bundle id>|<version>` row each. Integrations keying on the old
   always-present `av|XProtect|active` row should treat `unknown` as a signal
   to investigate, not as product-absent.
2. **The `status` action on macOS returns real XProtect data** (definition
   version, freshness, Remediator/MRT versions) instead of
   `status|not_available`. A new darwin-only definition
   `security.antivirus.xprotect_status` exposes it; being a new id, it seeds
   on upgraded installs at next boot (unlike edited descriptions, which reach
   fresh installs only — the amended `security.antivirus.products` text lands
   there alone).
3. **Mixed-fleet blend during rollout:** agents not yet upgraded keep emitting
   the hardcoded XProtect row and process-grep results. Not a server bug; the
   presence of an `xprotect_version` row identifies an upgraded agent.
### vNEXT — macOS firewall `state` now reports the Application Firewall (backend key changed)

The `firewall` plugin's macOS `state` action previously reported the pf packet
filter — which is off by default and unrelated to the Application Firewall a
Mac admin means — so a Mac with the real firewall on could read `disabled`.
Three things are visible after upgrading agents:

1. **The `backend` row value changes from `pf` to `appfirewall`**, and `state`
   now reflects `socketfilterfw --getglobalstate`. Integrations keying on
   `backend|pf` or treating `state` as pf state must switch to the new rows.
   Two additive rows appear: `mode|block_all` (only when block-all is set) and
   `pf|<state>` (the demoted pf signal; `unknown` on agents not running as
   root). `state|unknown` means the check was unreadable — never assumed safe.
2. **Mixed-fleet blend during rollout:** agents not yet upgraded keep emitting
   `backend|pf` + pf-based `state`. Expect both shapes side by side until the
   fleet is fully upgraded — not a server bug; the `backend` row disambiguates
   per device.
3. **Existing installs keep the old definition description.** Bundled
   definitions seed insert-or-skip by id at boot, so the corrected
   `security.firewall.state` description (v1.1.0) lands on fresh installs
   only; upgraded fleets get the corrected *behavior* regardless. To refresh
   the text, delete `security.firewall.state` and re-import it via
   `POST /api/instructions/import` — do not edit it in the dashboard YAML
   editor, which drops the definition's `spec.visualization` on save.

### vNEXT — Linux firewall `state` may now read `unknown` more often for ufw/iptables hosts (correctness fix)

The `firewall` plugin's Linux ufw/iptables legs previously reported a parsed
`active`/`inactive` `state` as soon as the underlying subprocess exited `0`
— even if the read had actually timed out or been truncated before
finishing, which could report a stale or simply wrong verdict with full
confidence. `state|` is now gated on the same completeness check `ruleset|`
already used (`tool_ran && exit_code==0 && !timed_out && !output_truncated`),
matching the nftables leg's own honest-degrade behavior added alongside it.

1. **Hosts whose `ufw status`/`iptables -S` reads were marginal** (slow,
   near-timeout, or hitting the output cap) will now read `state|unknown`
   more often post-upgrade, for the SAME underlying firewall state as
   before. This is the fix working as intended — a previously
   false-confident `active`/`inactive` becomes an honest "couldn't tell" —
   not a detection regression. `ruleset|unknown` already had this behavior;
   `state|` now matches it.
2. **No row shape changed.** `unknown` was already a valid `state` value on
   every backend (it is the nftables leg's own honest-degrade outcome); this
   only changes which reads reach it. Integrations already handling
   `state|unknown` need no changes.
3. **Mixed-fleet blend during rollout:** agents not yet upgraded keep the
   prior completeness posture for ufw/iptables; a wider spread of
   `state|unknown` across the fleet for these backends specifically
   identifies upgraded agents whose reads were genuinely marginal, not a
   server-side fault.

### vNEXT — KEK rotation is now durably rate-limited (#2530) (breaking)

Before this release, `POST /api/v1/secrets/kek/rotate` was rate-limited only by a 5-minute
**process-local** cooldown — cheap, but per-process and restart-clearable, so an install could
in practice rotate roughly every 5 minutes (or more often across a restart, or across several
servers pointed at the same database). This release replaces that with a **durable,
database-backed** rate limit, `--kek-min-rotate-interval` (default `3600` seconds = 1 hour, env
`YUZU_KEK_MIN_ROTATE_INTERVAL`), read from `secrets.kek_meta.created_at` on the database
server's own clock — it survives a restart and is shared cluster-wide by every server pointed at
the same database. **An install that could previously rotate every ~5 minutes can now be
durably refused (`429`) for up to an hour by default.** If your operational tooling or runbooks
assume a short rotation cadence is always available (smoke tests immediately after install,
scripted rotation drills, etc.), review them against the new default before upgrading — a fresh
install's very first rotate attempt is also refused for up to this interval, because KEK v1 is
minted at boot with `created_at = now()`. Lower `--kek-min-rotate-interval` if your operational
model genuinely needs more frequent rotation, but read the "runaway/abuse guard, not a
rotation-schedule setting" caveat in "Key management (secrets KEK)" first — this flag also
bounds how quickly you can rotate in a genuine emergency. See that section and
`docs/prometheus/yuzu-alerts.yml` (group `yuzu-secrets`) for the full contract, the new
`VersionCeiling`/`QueryCanceled`/`ClockAnomaly` failure modes, and the new observability surface.

### vNEXT — API/MCP bearer tokens invalidated on upgrade (ApiTokenStore → Postgres, ADR-0030) (breaking)

The API/MCP bearer-token store moves from SQLite (`api-tokens.db`) to the PostgreSQL substrate as
a **fresh-start cutover with no data migration** — every pre-upgrade API token and MCP token stops
working the instant the new server starts (interactive cookie-session/SSO login is unaffected).
**Re-mint every API/MCP bearer token** after upgrading (`POST /api/v1/tokens`) and update the
credential wherever it is stored; plan a maintenance window and notify automation owners, since all
bearer-token integrations break at once. A boot-time warning names the legacy file (inert,
removable). Full detail + multi-instance caveat: the `## ⚠️ Breaking` section in
`docs/user-manual/upgrading.md` and ADR-0030.

### vNEXT — `GET /mcp/v1/` is a live SSE channel; ALL streaming surfaces now share one worker budget

Track 2f PR 2, plus ADR-0034. Three things change for an operator:

1. **`GET /mcp/v1/` no longer returns `405`.** It is the MCP session's server→client SSE channel (heartbeats, `Last-Event-ID` resume). Nothing publishes onto it yet — `notifications/progress` arrives in the next rung — so a client that never issues a GET is unaffected. Behind a reverse proxy, note these are held-open responses: the server sets `X-Accel-Buffering: no` (nginx honours it); Envoy, HAProxy, ALB and Cloudflare need their own no-buffering opt-out.

2. **Every held-open SSE response now leases from one shared budget** — MCP's GET channel, MCP streamed POST, `GET /api/v1/events`, the dashboard executions drawer, and the legacy `/events` stream. cpp-httplib is thread-per-connection, so each of those pins a worker for its entire life; previously only MCP was counted, which meant the plain-REST reserve was arithmetic rather than a guarantee. A cap hit returns `429` with `Retry-After`; a live stream is never evicted. **This closes a starvation path that existed before MCP streaming shipped at all**: enough dashboard tabs could exhaust the pool and stall plain REST.

3. **The worker pool is derived from `--max-sse-streams` (default 128), not the other way round.** The old default sized itself from httplib's accidental 32-thread pool and yielded 12 streams — on a platform designed for hundreds of agentic clients. A blocked thread burns no CPU; its resident cost is a fraction of a virtual, platform-dependent stack reservation and has not yet been measured (ADR-0034), so the pool is sized for the workload you declare rather than off a per-thread constant. Watch `yuzu_http_held_open_responses / yuzu_http_held_open_capacity`; the ceiling is thread-count, and the durable fix (moving long-lived connections off the thread-per-connection server) is recorded in ADR-0034.

### vNEXT — MCP notification POSTs now answer `202` (was `204`); Streamable HTTP sessions added

The `/mcp/v1/` endpoint gains the MCP-spec **Streamable HTTP** transport (track
2f, PR 1). Three changes are visible to existing clients:

1. **A JSON-RPC *notification* POST (a request with no `id`, e.g.
   `notifications/initialized`) now returns `HTTP 202 Accepted` instead of
   `204 No Content`.** The body stays empty. This is a spec MUST and applies
   regardless of the kill switch below. **Affected:** only a strict client that
   asserts the status is exactly `204` (or asserts an empty-body status other
   than `202`) — the reference clients (mcp-remote, Claude Desktop) treat any
   2xx-with-empty-body as success and are unaffected. Adjust such assertions to
   accept `202`.
2. **`initialize` responses now carry an additive `Mcp-Session-Id` header.**
   Clients that don't use it can safely ignore it (plain-POST flows are
   otherwise byte-identical). Clients that do may present it on later requests;
   an unknown/expired/foreign id returns `404`, at which point the client
   re-initializes (sessions are in-memory, so a server restart has the same
   effect). `DELETE /mcp/v1/` ends a session.
3. **`initialize` now negotiates the protocol revision** instead of always
   returning `2025-03-26`. A client that sends `params.protocolVersion` of a
   *supported* revision (`2025-03-26` or `2025-06-18`) gets that value echoed;
   anything else (including no `protocolVersion`) still returns `2025-03-26`.
   **Affected:** only a newer client that requests `2025-06-18` — a legacy client
   requesting `2025-03-26` (or nothing) sees no change. Negotiation is independent
   of the `--mcp-no-streaming` kill switch.

New CLI flags (all optional):

- `--mcp-no-streaming` (`YUZU_MCP_NO_STREAMING`) — disable the Streamable HTTP
  transport: no session minting, `GET`/`DELETE /mcp/v1/` → `405`, plain
  JSON-RPC POST only. The `202` notification status still applies. Use this if a
  buffering reverse proxy interferes with streaming.
- `--mcp-allowed-origin <value>` (`YUZU_MCP_ALLOWED_ORIGINS`, repeatable) — an
  allowed `Origin` header value (`scheme://host:port`, exact match) for
  DNS-rebinding defence. **An absent `Origin` is always allowed** (the endpoint
  requires a credential); an **empty allowlist rejects any *present* `Origin`**
  (the secure default) — browser-based MCP clients must be allowlisted
  explicitly. Non-browser clients (which send no `Origin`) need no configuration.

### vNEXT — DEX per-application sampling (`procperf`) is a new opt-in telemetry category

This release adds per-application resource sampling (top-N processes by CPU and
working set, by image name) to the TAR edge warehouse. **It is off by default**
(`procperf_enabled=false`) and collects nothing until an operator opts in — it
is a distinct, usage-class telemetry category subject to works-council / DPA
review, separate from the device-level performance sampling (`perf_enabled`,
on by default, no per-app identity) that shipped in the prior release **on
Windows** — on Linux, device-level sampling starts automatically **on upgrade
to this release** (see the upgrade checklist in the user manual's
[Upgrading](upgrading.md) page and the TAR manual's upgrade note; opt out per
host with `perf_enabled=false`). To
enable per-app sampling, set `procperf_enabled=true` via a TAR `configure`
instruction (fleet-wide or per-device). The data is image names only (no
command lines), 7-day raw / 31-day hourly retention, and is captured in the
Workstream E data inventory in `docs/enterprise-readiness-soc2-first-customer.md`.
TAR warehouse tables are now also created on every database open, so upgraded
agents need no manual table-creation step. New webhook egress: the `dex.signal`
event (operator-routed signals) — see the security questionnaire note in the
assurance package if you answer data-egress questions.

### vNEXT — `POST /login` returns 202 for MFA-enrolled users (breaking)

Programmatic clients (CI pipelines, health checks, `curl` scripts) that call `POST /login` and treat anything other than `HTTP 200 + {"status":"ok"}` as failure will silently break the first time an authenticating user enrolls in TOTP MFA via Settings → Multi-Factor Authentication. The new response is `HTTP 202` with body `{"status":"mfa_required","mfa_pending_token":"<opaque>","expires_in":120}` — handle this branch by posting `mfa_pending_token` + the 6-digit TOTP code (or a `XXXX-XXXX-XXXX-XXXX` recovery code) to `POST /login/mfa` to mint the session cookie. See `docs/user-manual/authentication.md` § Multi-Factor Authentication for the full flow.

MFA CLI flags: `--mfa-enforcement` (default `optional`; `admin-only`/`required` now **enforce** — see the breaking note in `docs/user-manual/upgrading.md`), `--mfa-step-up-window-secs` (default `300`), `--mfa-login-pending-secs` (default `120`), and the break-glass `--mfa-reset <username>` (clears a locked-out user's MFA and exits, writing an `mfa.reset.breakglass` audit row — see `docs/ops-runbooks/auth-db-recovery.md`). Recovery code format changed from `XXXXX-XXXXX` (50 bits) to `XXXX-XXXX-XXXX-XXXX` (80 bits) — codes printed by earlier PR1 commits remain valid until consumed or regenerated. The break-glass procedure for a user who has lost both their authenticator and all recovery codes — and the recovery path for an operator locked out by an enforcement misconfiguration (SSO IdP not asserting `amr`, or a sole admin who could not enroll) — lives at `docs/ops-runbooks/auth-db-recovery.md`.

### vNEXT — service-scoped API tokens can no longer read or mutate the confirmed fleet-wide Guardian/DEX/network/inventory/TAR/Schedule surfaces found as of this release (breaking)

**What changed.** A pre-existing gap let a service-scoped API token read identity-linked, fleet-wide device data — and, for Guardian Baselines, MUTATE what every agent enforces — across every reporting agent, not just its own service's agents. **This note does not claim the underlying class is fully closed** — three tracked issues (#3123 device-discovery, #3124 response/execution data, #3125 inventory data) document further confirmed instances on surfaces this release does not touch, found by an independent adversarial review during this branch's own governance run; see those issues for the current list. The confinement check on these fleet-wide (no single `agent_id`) reads only ever verified the token's role, never its service scope, and several of the affected reads had no per-open audit trail at all. Fixed across REST, the dashboard, and MCP: `GET /api/v1/guaranteed-state/events` (no-`agent_id` shape), `GET /api/v1/dex/signals/{obs_type}`, `GET /api/v1/dex/perf/devices`, `GET /api/v1/network/devices` and their MCP twins now deny a service-scoped token outright and are access-audited (`dex.signal.view` / `dex.perf.device.view` / `network.device.view` — the latter two had no audit coverage at all before this release); the Guardian dashboard's fleet status, guards list, event timeline, per-Guard drilldown, baselines list, and per-Baseline fragments, plus the `/fragments/dex/perf/devices`, `/fragments/network/devices`, `/fragments/dex/overview`, `/fragments/dex/app`, and `/fragments/dex/catalogue/signal` dashboard fragments now deny a service-scoped token the same way. The same confinement-gap class extends beyond `GuaranteedState:Read`: `GET /fragments/devices/list` (`Infrastructure:Read`), `GET /fragments/inventory/devices` (`Inventory:Read` — GDPR-personal-data serial/system_uuid/primary_mac columns), and both TAR frame device pickers (`GET /fragments/tar/process-tree`, `GET /fragments/tar/capture-sources`) now deny a service-scoped token too. It also reached a MUTATING surface: `POST /fragments/auto/run` (the `/auto` Pre-flight dispatch) resolved its device cohort the same unconfined way before dispatching the configured checks — now denied the same way, before any dispatch occurs. A different shape of the same root cause also reached three more `/auto` Pre-flight routes: `GET /fragments/auto` (the saved-runs rail), `GET /fragments/auto/result` (the run result poll), and `POST /fragments/auto/delete` (run delete) scope by `session->username` alone, and a service-scoped API token shares its creating principal's username (`ApiToken::principal_id`) — so a token scoped to e.g. one IT service could read back, poll, or delete a fleet-wide pre-flight run its own principal created interactively. All three now deny a service-scoped token the same way. The same owner-scoping shape reached the `/auto` Deploy stage too: `GET /fragments/auto/deploy` (the deploy config form) and `POST /fragments/auto/deploy/delete` (deployment delete) now deny a service-scoped token for the same reason; `GET /fragments/auto/deploy/result` (the deployment result poll) now denies too, and — because it also re-invokes the deployment engine's mutating advance step on every call — this additionally narrows how far an already-in-flight deployment can progress for a service-scoped caller. The same owner-scoping shape reached the Schedule API too, and worse: `POST /api/schedules` (create) and `POST /api/schedules/{id}/enable` (re-enable) now deny a service-scoped token outright, even one holding both `Schedule:Write` and `Execution:Execute` — a recurring schedule dispatches fleet-wide through `ScheduleRunner` with no per-fire confinement at all, unattended, and reaching it needs no pre-existing state (unlike every route above). `DELETE /api/schedules/{id}` (delete) denies the same way as the ordinary owner-scoping class. Disabling a schedule (`enable=false`) is deliberately **not** denied by this per-file check — the kill switch is intended to stay reachable even for a service-scoped token. **Caveat added 2026-08-21 (#3290 Phase 2 bucket 1a):** that guarantee does not currently hold in practice — `require_permission(Schedule,Write)` denies a service-scoped token unconditionally at the top of this handler, before `enabled` is even parsed, so a disable is denied the same as an enable. Pre-existing, not introduced by this note's own fixes; tracked as #3378. A separate, worse-than-username-scoping gap in the same feature area: `GET /api/schedules` (REST) and the MCP `list_schedules` tool now also deny a service-scoped token, because `ITServiceOwner` grants full CRUD on `Schedule` and the underlying query had no owner/service filter of any kind, so `Schedule:Read` alone let a service-scoped token enumerate every schedule from every other service. `GET /fragments/schedules` (the dashboard twin) is fixed the same way, and separately gains an RBAC gate it never had — this fragment was previously reachable by **any authenticated session, regardless of role or grant**. Independently, `POST /api/schedules/{id}/enable` had a request-parsing bug that silently reinterpreted the standards-compliant JSON boolean `{"enabled": false}` as `enabled=true` — this is now fixed; see "What to do" below for who needs to check their integration. Two more instances were found and fixed during this branch's own governance review, both in files already touched above: the Guardian dashboard's six MUTATING fragments (guard create, guard enable/disable, baseline create/deploy/delete/update) never got the same deny their read-only siblings got in the same earlier commit — worst of all the fixes in this note, since a service-scoped token could deploy a Baseline (a fleet-wide, `full_sync` operation) outside its own service; and `GET /fragments/inventory/find/results`, `GET /api/v1/inventory/software`, and MCP `query_installed_software` (the software-search family) never got the deny their sibling `/fragments/inventory/devices` got. See `docs/user-manual/audit-log.md` for the full list of new/changed audit verbs and `docs/enterprise-readiness-soc2-first-customer.md` "The machine-health audit exemption" for the narrowed CC7.2 scope.

**Who this affects.** Any integration authenticating with a service-scoped API token (a token bound to one service's agents) that currently calls any of the routes/tools/fragments above will start receiving `403` instead of fleet-wide data on this upgrade — this is the intended fix, not a regression. Separately, any integration calling `POST /api/schedules/{id}/enable` with `enabled` as a native JSON boolean will see its `enabled: false` calls actually disable the schedule for the first time — see "What to do" below. Ordinary (non-service-scoped) operator sessions are unaffected by the confinement changes.

**What to do.** An integration that needs this data should use a token scoped appropriately for the surface it reads: a global (non-service-scoped) credential for a fleet-wide aggregate view, or the existing per-device REST/MCP reads (`.../{agent_id}` shapes), which remain available and stay confined to the token's own service. For the `/auto` Pre-flight and Deploy rail/result/config/delete routes there is no per-device equivalent — a service-scoped token cannot manage its own principal's fleet-wide pre-flight runs or deployments at all; use a non-service-scoped credential for pre-flight and deployment workflows. The Schedule API has no per-device equivalent either — a service-scoped token cannot list, create, arm, **or (see the #3378 caveat above) disable** a runaway schedule; use a non-service-scoped credential for schedule management, including as the kill-switch for an incident involving a service-scoped-triggered schedule. Guardian Guard/Baseline mutation and fleet-wide software search have no per-device equivalent either — use a non-service-scoped credential for those too. For the `enabled` parsing fix: if your integration sends `{"enabled": false}` as a real JSON boolean and has been relying on (or working around) it actually re-enabling the schedule, update it — that was always a bug, and the workaround is now unnecessary and will produce the opposite of the intended effect.

### vNEXT — service-scoped API tokens are now denied by default everywhere, not just on the routes named above (guardian-confinement-2298 PR 3 — "the flip") (breaking)

**What changed.** The note immediately above this one (PR 2 of this same series) closed an *enumerated* list of routes/tools/fragments — real fixes, but each one required someone to find and name the affected surface first. This release replaces that approach with a default-flip: `AuthRoutes::require_permission`'s service-scoped branch previously admitted any operation the `ITServiceOwner` role happened to grant, and that role holds broad CRUD across most securables — so a token bound to one IT service's agents could, in practice, reach fleet-wide data anywhere that role's grants reached, whether or not anyone had found and fixed that specific route yet. A `(securable, operation)` pair must now *also* clear a server-side allow-list that ships **empty**, so every route not yet migrated to real per-request confinement denies a service-scoped token outright — including routes nobody has found yet. Mirrored at the MCP `tools/call` dispatch layer via a new per-tool `ServiceScopeClass` classification (`denied` is the default; `confined` and `global_safe` are explicit, reviewed exceptions). This supersedes the PR 2 note's scope: those routes stay fixed the same way, but so does everything else that shares the same `require_permission`/`require_scoped_permission`/MCP `tools/call` gate. See `docs/adr/1006-service-scope-default-deny.md` for the full design.

**Who this affects.** Any integration authenticating with a service-scoped API token that currently reaches fleet-wide data or actions through a route not on the seeded-empty allow-list will start receiving `403` on this upgrade — this is the intended fix, not a regression. This is a strictly larger set than the PR 2 note above: that note's fixes were routes someone had already found; this flip additionally denies routes nobody has found yet, the moment they're reached. Ordinary (non-service-scoped) operator sessions are unaffected.

**What to do.** Same guidance as the PR 2 note above: use a global (non-service-scoped) credential for anything that genuinely needs fleet-wide reach, or the per-device REST/MCP reads that stay confined to the token's own service. There is no per-deployment or per-operator way to widen the allow-list — it is compile-time, and widening it for a specific `(securable, operation)` pair is a security decision requiring `security-guardian` sign-off, not an admin setting. If a service-scoped token's workflow breaks on this upgrade and there is no per-device equivalent for what it was doing, that workflow needs a non-service-scoped credential going forward; there is no config flag to opt back into the old admit-by-default behavior for one route or one deployment.

### vNEXT — `GET /api/v1/inventory/software` and MCP `query_installed_software` diverge from the rest of the service-scoped-deny family: filtered data, not a 403 (#3290 Phase 2) (still in this vNEXT batch)

**What changed.** Both notes immediately above this one (PR 2's enumerated fixes, then "the flip") describe `GET /api/v1/inventory/software` and MCP `query_installed_software` as denying a service-scoped API token outright (`403`). This still-unreleased batch changes that a second time, before either prior note has shipped: both surfaces now migrate onto `AuthRoutes::require_fleet_read`, a real per-request confinement gate — a correctly-confined service-scoped token gets a **filtered `200`** (rows limited to its own service-tagged agents, intersected with any management-group grant), not a `403`. This is a least-privilege improvement, not a widening: no caller sees any *row* it did not already hold a grant for. (A service-scoped caller's `devices_omitted` count can now be nonzero when a name-filtered query matches software outside its own scope — a bounded existence-only signal, reviewed and accepted, see `docs/security-reviews/service-scope-phase2-migrations-2026-08.md`'s UP-2 ruling — not a row-level disclosure.) The two prior notes' own routes/tools are otherwise unaffected — only this one route pair's end-state changes. Because all three notes land in the same unreleased version, an operator reading only the two notes above would be told to expect a permanent `403` from these two surfaces that will not, in fact, occur. Full behavior table (every caller class, not just this one):
`docs/security-reviews/service-scope-phase2-migrations-2026-08.md`.

**Who this affects.** Any integration using a service-scoped API token against these two specific surfaces. If it was built to expect (or work around) the `403` the notes above describe, it will now receive real data instead — code that specifically branches on a `403` here to mean "not available to this token" should be updated; code that simply surfaces the error to an operator needs no change, since the success case is a strict improvement.

**What to do.** Nothing required for the common case. If your integration has error-handling logic keyed specifically on a `403` from these two surfaces, update it to handle the real filtered result instead.

### vNEXT — dashboard `/fragments/results`, the workflow executions drawer, and MCP `get_agent_details` now confine to the caller's management group / service scope (#1712, ADR-0017)

**What changed.** These three surfaces previously gated on a flat permission check with no per-agent filter: a management-group-confined operator holding `Response:Read`/`Execution:Read` saw the **whole fleet's** response data and agent statuses through the dashboard/workflow surfaces (not just their own group), and a service-scoped API token calling MCP `get_agent_details` was denied outright (`403`) rather than shown anything. All three now migrate onto `AuthRoutes::require_fleet_read`, the same admit-then-filter primitive `GET /api/v1/inventory/software`/`query_installed_software` already use (#3290 note above) — a management-group-confined operator now sees a genuinely narrowed, correct result on the two dashboard/workflow surfaces; a correctly-confined service-scoped token now gets a **filtered result** from `get_agent_details` instead of a `403`. `get_agent_details` on an out-of-scope agent returns the identical "not found" response a genuinely nonexistent agent would (closing a related existence-oracle, #3564) — the tool can no longer be used to discover which agents exist outside a caller's scope.

**Who this affects.** Any management-group-confined operator using the dashboard results page or the workflow executions drawer will now see a **narrower** view than before — this is the intended fix, not a regression; an unconfined (global) operator's view is byte-identical to before. A confined operator who newly reaches `/fragments/results` will also not see the "Create Group from N Agents" button that an unconfined operator sees — its downstream flow (`/fragments/create-group-form`, `POST /api/dashboard/group-from-results`) is not yet scope-safe, so the button is withheld entirely for a confined caller rather than risk a confined-N-vs-unscoped-M mismatch (tracked #3489). Any integration authenticating with a service-scoped API token that calls MCP `get_agent_details`: code that specifically branched on a `403` from this tool to mean "not available to this token" should be updated to expect a real (filtered) result instead, mirroring the `query_installed_software` guidance above.

**What to do.** Nothing required for the common case. If a confined operator reports dashboard/workflow results that look "smaller than before," that is the fix working as intended — confirm their management-group membership matches the agents they expect to see. If a service-scoped integration's error handling is keyed on a `403` from `get_agent_details` specifically, update it the same way as the `query_installed_software` note above.

### v0.10.0 — API token revocation is owner-scoped

Starting with v0.10.0, non-admin users can no longer revoke API tokens they do not own. A caller holding the `ApiToken:Delete` permission may revoke only tokens whose `principal_id` matches the session's username; the global `admin` role is the sole bypass. Prior releases allowed any holder of `ApiToken:Delete` to revoke any token, which was an IDOR (tracked in GitHub issue #222).

**If your deployment uses a non-admin service account to rotate tokens for other principals** — for example, a shared `ops` role that recycles service-account tokens on a schedule — those rotations will begin receiving `HTTP 404 token not found` after upgrade. To restore the behavior, either:

1. Assign the rotation account the global `admin` role, or
2. Refactor the rotation so each principal owns and rotates its own token.

Option (2) is the recommended long-term posture because it aligns with least-privilege. The same ownership constraint applies to both the REST path `DELETE /api/v1/tokens/{id}` and the HTMX dashboard path `DELETE /api/settings/api-tokens/{id}`. Denied attempts are recorded in the audit log with `action=api_token.revoke`, `result=denied`, and `detail=owner=<real owner>` so operators can distinguish an enumeration probe from a legitimate self-revoke.

Both paths return `HTTP 404 token not found` on a cross-user revoke attempt — identical to the response for a truly-nonexistent token — to prevent the endpoint from being used as an enumeration oracle.

### v0.12.0 — TAR dashboard page + mixed-version agent caveats

The new `/tar` dashboard page (issue #547) surfaces every device × source pair where a TAR collector has been disabled. The page is reachable from the **TAR** entry in the main navigation bar; viewing requires `Infrastructure:Read` and the per-source Re-enable / Scan-fleet actions require `Execution:Execute`.

**Mixed-version rollout caveat.** Agents running a build older than v0.12.0 do not emit the new per-source `paused_at` / `live_rows` / `oldest_ts` lines on `tar.status`. The dashboard renders an em-dash (`—`) for those columns when a pre-v0.12.0 agent appears in a scan result. This is not a server bug — it is an honest "we don't know when this collector was disabled because the agent reporting it pre-dates the field." Operators upgrading the server before the agent fleet should expect the em-dash for any pre-existing paused sources until the agent at the affected device is upgraded. See `docs/user-manual/tar.md` for the full TAR dashboard workflow.

**Per-operator scan state caveat.** Scan results are held in the server's memory keyed by operator username, with a 30-second per-operator cooldown to defend against retry-storms. Restarting the server clears all scan state; operators will see "No scan data yet — click Scan fleet" after a restart and a fresh scan returns within seconds. Persistence across restarts and multi-server coordination land in Phase 15.G operational hardening.

**Audit log additions.** Two new audit actions emit on operator activity: `tar.status.scan` (every Scan-fleet click; `result=success`/`denied`/`failure` with detail) and `tar.source.reenable` (every Re-enable click; `result=success`/`denied`/`failure`). SIEM rules can distinguish forged form submissions from genuine connectivity failures via the `detail=scope_violation` vs `detail=agent_not_connected` distinction even though the HTTP response body is identical (`Agent not reachable.` 404) for both cases — the body identity is load-bearing for the no-enumeration-oracle property.

### vNEXT — Fleet visualization (3D) (`/viz/fleet`)

The fleet-visualization feature ladder lands across the `feat/viz-engine` branch. PRs 1–12 are shipped: agent collector + server store + REST/fragment routes + page scaffold + camera controls + cube renderer + Sprite labels + hover tooltip + interior process nodes coloured by category + intra-cube localhost edges + per-cube listening-socket spheres + cross-machine connection edges + push-based topology ingestion + **three-tier stacked layout, talking-socket dots, curved tube wires, loopback-bind filter (PR 12)**. Remaining ladder PRs add the vulnerability overlay and final polish (LOD, edge bundling, a11y, perf).

**Operator-visible state today (PRs 1–12).** Navigating to `/viz/fleet` shows one translucent cube per fleet machine, **organized into three architectural tiers** — frontend cubes on the top Y plane, applications in the middle plane, databases on the bottom plane. Within each tier, machines fall onto a deterministic per-tier grid (FNV-1a hash on `agent_id`). Live agents render at opacity `0.18`; stale agents (no `tar.fleet_snapshot` push within the staleness threshold) drop to `0.08`. Per-OS palette: Linux `#f0c674`, macOS/Darwin `#a0a0a0`, Windows `#5294e2`. Hostname `Sprite` labels render below each cube. Inside each cube, one `SphereGeometry` dot per process is laid out deterministically (`hash(pid|ppid)`-mod-bucket inside the cube's interior) and coloured from a six-category palette: system `#6e7681`, browser `#58a6ff`, database `#d29922`, web `#56d364`, runtime `#bc8cff`, other `#8b949e`. Each cube's TOP face carries a ring of cream-coloured listening-socket spheres (one per `listeners[]` row) with `:port` labels; **loopback-only listeners (`127.x`, `::1`) are now hidden from the surface** — they aren't reachable from other instances. Each cube's BOTTOM face carries a ring of cool-blue **talking-socket** dots (one per unique outbound `(proto, dst_ip, dst_port)`). **Cross-machine connections render as thick curved tubes** (`THREE.TubeGeometry` along a `CubicBezierCurve3` with vertical end-tangents) that drop from the source's talking dot down/across to the destination's listener sphere. External (off-fleet) destinations render as short grey stub lines with ring markers. Hover order: listener sockets → talking sockets → process dots → edges → cubes. WASD pans, drag rotates, wheel zooms.

**Tier classification heuristic.** `classifyTier` reads `listeners[]` port hints (`DB_PORTS = {3306, 5432, 6379, 27017, 1521, 1433, 9042, 9200, 5984, 8086, 11211}` / `WEB_PORTS = {80, 443, 8080, 8443, 8088}`) plus process-category strings (`'database'`, `'web'`). Priority is **db > web > app**: a host with any DB signal lands on the database tier regardless of whether it also serves web traffic. A host with no DB or web signal defaults to the application tier. **Known limitations:** (a) databases on non-standard ports (e.g. Postgres on 5431 for a sharded cluster) fall through to the application tier unless one of the host's processes is classified as `database` by `process_category.hpp`; (b) `WEB_PORTS` is intentionally narrow — it covers reverse proxies / load balancers / API gateways on ports 80/443/8080/8443/8088 but **not** dev-server defaults (3000/4200/5173/8000), because in a classic three-tier deployment a nodejs/django/vite server listening on those ports is application work, not the front edge. There is no operator-accessible override today; both limitations are tracked as a follow-up issue on function-aware tier classification.

**Why empty cubes show no lines.** Intra-cube edges appear only for processes with *active* loopback socket pairs (e.g. Prometheus scraping node_exporter, a client connected to a local Redis / Postgres). A fresh agent with no inter-process loopback traffic shows process dots but no lines — this is expected, not a bug. Lines appear as workloads generate loopback flows.

**Browser requirements.** The page uses ES module imports resolved through an `<script type="importmap">` declaration. importmap is supported in Chrome 89+, Firefox 108+, Safari 16.4+, and Edge 89+ (all browsers shipped after early 2023). Older browsers receive a visible error overlay on the page rather than a blank canvas — the page detects via `HTMLScriptElement.supports('importmap')` before attempting the module load. **`MeshPhysicalMaterial` cubes additionally require WebGL 2.0**, which is bundled with all browsers in the import-map support floor but can be disabled by enterprise group policy on locked-down terminals. Browsers without WebGL 2 will see the grid but the cubes will fail to render with a black or missing material; verify WebGL 2 is enabled in browser policy before pilot rollout. Operators on enterprise-locked browser configurations that lag 2+ years should test on a representative deployment. **Page weight:** the `/viz/fleet` route pulls three.js (~685 KB), three-orbit (~32 KB), htmx (~51 KB), the yuzu-viz renderer (~84 KB), plus the design-system CSS. Approximate first-load total is ~1.5 MB of JS (uncompressed). For metered-link or low-bandwidth deployments, consider `--viz-disable` as a default and enabling it selectively for ops staff.

**Reverse-proxy deployment constraint.** The page hard-codes static asset paths (`/static/three.module.min.js`, `/static/three-orbit-controls.js`, `/static/yuzu-viz.js`) and the API path (`/api/v1/viz/fleet/topology`). Sub-path proxy deployments (e.g. nginx `location /yuzu/`) are NOT supported — the absolute paths would 404 against the rewritten origin. Mount Yuzu at the root path of its host or a fronting domain.

**Cache posture.** The `/viz/fleet` page response sets `Cache-Control: no-cache, no-store, must-revalidate` so a server upgrade cannot leave operators with a stale page that references the new vendored assets (which themselves cache for 24 hours via `max-age=86400`). The vendored asset bundles are content-addressed by server binary version — a fresh page revalidation after upgrade picks up any bundle changes immediately.

**Kill switch behaviour.** `--viz-disable` / `YUZU_VIZ_DISABLE` disables the **whole feature**: the REST/fragment endpoints, the per-host drill-down routes, **and** the `/viz/fleet` and `/viz/host/<id>` page shells all return `503` (a plain-text "fleet visualization is disabled by an administrator" body). An operator who sets the flag will not see a half-working page. The static asset routes (`/static/yuzu-viz.js` etc.) are not gated — they are inert without the page — so gating them at a reverse proxy is optional, not required. The kill switch is **boot-time only** (seeded from config at startup); there is no runtime toggle, so disabling viz under a live incident requires a server restart.

**Sizing and capacity.** Push-based ingestion holds one `RawAgentSnapshot` per agent in an in-memory `pushed_` map. Per-agent footprint is bounded by the parser caps (4096 processes + 4096 connections per snapshot, ~1–2 MB worst case, typically 5–20 KB). The map is hard-capped at **100 000 agents** (`kPushedMapHardCap`); at the cap, a new agent's push evicts the least-recently-seen entry (LRU by server receipt time) and emits a `topology.push.evicted_for_cap` audit event. Watch `yuzu_viz_pushed_map_size` and alert before it approaches the cap. The store is **in-memory only** — on server restart it is empty until agents re-push (recovery window ≈ one agent push cycle, ~30–60 s); the pull-based dispatch fetcher serves as the cold-start fallback during that window.

**Permission model.** The page route is auth-gated only (`require_auth`); the data fetch at `GET /api/v1/viz/fleet/topology` enforces `Response:Read`. An operator with a session but without `Response:Read` can land on the page (sees the grid and the "Access denied" overlay when the JS fetch fires) but every JSON fetch returns 403. The `viz.fleet_topology` audit row is emitted on the API path, not the page path — auditors querying "who accessed fleet visualization?" should filter on the `FleetTopology` `target_type` (covered in detail in `audit-log.md`).

**Browser-side errors are not server-logged.** WebGL context loss, module-fetch 503, and importmap-resolution failures surface only in the operator's browser console. A future polish PR will add a client-error beacon; today, support engineers diagnosing "viz is blank" reports should ask for a screenshot of the browser console.

**Per-host drill-down (`/viz/host/<agent_id>`).** Double-clicking a cube
opens a new tab with a 2D bipartite IPC graph (processes + sockets,
Cytoscape `cose` layout) above the existing TAR process tree, with
cross-pane select-to-highlight and a resizable splitter. The page route
is auth-gated only; the data fetch (`GET /api/v1/viz/host/<agent_id>/topology`)
enforces `Response:Read` and honours the `--viz-disable` kill switch.
Audit rows are emitted as `viz.host_topology` (`target_type = HostTopology`).
The `agent_id` path segment is allow-listed to `[A-Za-z0-9._-]` before
templating; any other character returns `400`.

**Connection window — `fleet_snapshot_window_seconds` (TAR plugin config).**
`tar.fleet_snapshot` reports not only the connections ESTABLISHED at the
exact `/proc` sample instant but also connections TAR observed recently
in its `tcp_live` warehouse, so short-lived flows still reach the viz.
The look-back window is operator-tunable via the TAR plugin's KV config
key `fleet_snapshot_window_seconds` (default `3600`). It is a TAR plugin
config key, not a server CLI flag — set it through the TAR plugin's
configuration surface. The 60 s sampler still cannot see sub-interval
connections; that needs kernel eventing (tracked separately).

### vNEXT — Agent interval triggers now functional

`yuzu_register_trigger` / `yuzu_unregister_trigger` were previously no-op
stubs — no `TriggerEngine` was instantiated on the agent, so interval
triggers were silently discarded and never fired. As a result the TAR
warehouse `*_live` tables (`tcp_live` and friends) sat permanently empty
in the field, and any plugin that registered an interval trigger had it
silently dropped.

**Upgrade caveat.** After upgrading the **agent** daemon, registered
interval triggers begin firing for the first time. On the first
`collect_fast` cycle (default 60 s) the TAR `*_live` tables start
populating, and operators may see a small increase in per-agent CPU/IO
proportional to the number of registered triggers. Any plugin that
registered an interval trigger expecting the old no-op behaviour will now
have that trigger fire — this is the fix, not a regression. Server-only
upgrades are unaffected; the change is entirely agent-side.

### vNEXT — OTA update binary signing (#416)

**Endpoints that upgraded via OTA self-update have no trust-anchor directory.**
The installers create it, but agent self-update replaces the binary in place and
runs no installer — so on Windows and macOS, where OTA *is* the normal upgrade
route, neither the directory nor its ACL hardening exists after upgrading. Create
it before you enable signing, or `--update-trust-bundle` points at nothing:

```powershell
# Windows, elevated. All three commands matter, and in this order. Keep each on ONE
# line -- a broken continuation runs the earlier steps and silently skips the rest,
# which is the exact state this block exists to avoid.
mkdir "C:\ProgramData\Yuzu\agent-certs"

# 1. Take ownership. If the directory ALREADY EXISTS, whoever created it owns it and
#    holds WRITE_DAC permanently -- stripping their access without taking ownership
#    lets them put it straight back. takeown also enables the privilege needed to
#    recover a directory whose permissions grant Administrators nothing at all.
takeown /F "C:\ProgramData\Yuzu\agent-certs" /A /R /D Y

# 2. Drop every explicit entry. This is the step that removes a pre-existing grant.
#    Step 3 cannot: /grant:r replaces grants only for the accounts it NAMES, so an
#    entry held by anyone else survives it untouched.
icacls "C:\ProgramData\Yuzu\agent-certs" /reset /T /C /Q

# 3. Break inheritance and grant exactly Administrators and SYSTEM. Without the
#    inheritance break, %ProgramData%'s inherited rights let an unprivileged local
#    user plant the anchor file before you do.
icacls "C:\ProgramData\Yuzu\agent-certs" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" /T /C /Q

# Verify: expect ONLY BUILTIN\Administrators and NT AUTHORITY\SYSTEM, each (OI)(CI)(F),
# and nothing marked (I). Check the OWNER too -- an unexpected owner can restore its own
# access at any time, so "the list looks right" is not on its own sufficient.
icacls "C:\ProgramData\Yuzu\agent-certs"
(Get-Acl "C:\ProgramData\Yuzu\agent-certs").Owner
```

```bash
# macOS, as root.
mkdir -p /etc/yuzu-agent/certs && chown root:wheel /etc/yuzu-agent/certs
chmod 755 /etc/yuzu-agent/certs
```

Linux endpoints upgraded through `.deb`/`.rpm` need nothing here — Debian's
post-install step re-runs on upgrade, and the RPM ships the directory in its
payload. A Linux endpoint that upgraded by OTA self-update, however, is in the
same position as Windows and macOS and needs `install -d -m 0755 -o root -g root
/etc/yuzu-agent/certs`.

**Default behaviour is unchanged.** Agents that pass no `--update-trust-bundle`
behave exactly as before: the downloaded binary is checked against the
server-supplied SHA-256 and applied. Signature verification is entirely opt-in.

**What signing does and does not close — read this before relying on it.** With a
trust bundle configured, a compromised or impersonated update server can no
longer push a binary your signing key never signed. That is the substitution
attack, and it is closed.

It does NOT close ROLLBACK. The signature covers the binary's CONTENT only, while
`latest_version` and the SHA-256 both come from the server. So a hostile server
can still serve a genuinely signed OLD release — one you really did sign — while
labelling it a newer version and quoting a hash computed over those same bytes.
Every agent-side check passes and the endpoint installs a real but outdated,
possibly known-vulnerable build, then reports itself up to date. Closing this
needs the version bound into the signed material (a signed manifest, TUF-style),
which is not in this release. Treat signing as confining an attacker to *binaries
you have signed*, not to *the binary you meant to ship*, and keep retiring the
signing key's authority over withdrawn releases accordingly.

**New on-disk artifact — the trust anchor.** `/etc/yuzu-agent/certs/` on Linux
and macOS, `C:\ProgramData\Yuzu\agent-certs\` on Windows, created by the
installers. It is deliberately NOT the server's `/etc/yuzu/certs` — that path is
the server's own CA directory, which the server owns and re-tightens on boot, so
no single mode serves both. You place the PEM bundle there yourself; nothing is
installed into it.

**Second new artifact — the signature sidecar.** An uploaded signature is stored
as `<binary>.sig` beside the package in the update directory. Like the package
itself it is node-local and not covered by the database backup: it is recreated
by re-uploading the package with its signature, so it needs no separate
backup step.

**Two new agent flags**, both off by default: `--update-trust-bundle`
(`YUZU_UPDATE_TRUST_BUNDLE`) and `--update-require-signature`
(`YUZU_UPDATE_REQUIRE_SIGNATURE`). Setting the second without the first refuses
to start, rather than running with enforcement silently inert.

**Nothing to do on upgrade** unless you want signing. If you do, read *Signing
update binaries* — in particular the two-stage rollout, because a fleet that
enforces before every package is signed stops updating.

### vNEXT — Plugin code signing (#80)

Plugin signature verification ships in two parts: an agent-side CMS verifier and a server-side Settings UI for managing the trust bundle. **Default behaviour is unchanged** — agents that do not pass `--plugin-trust-bundle` and operators that do not upload a bundle through the new Settings card see identical behaviour to prior releases (allowlist-only, sha256 hash check).

**New on-disk artifact.** `plugin-trust-bundle.pem` in the default cert directory (Linux, and macOS as root: `/etc/yuzu/certs/plugin-trust-bundle.pem`; Windows: `C:\ProgramData\Yuzu\certs\plugin-trust-bundle.pem`). The server always writes it there, even when `--ca-dir` points elsewhere. Server-managed via Settings → Plugin Code Signing. **Back up the default cert directory (the path above), paired with the Postgres dump** (see [Configuration Files](#configuration-files)); that directory is `--ca-dir` only when `--ca-dir` is left at its default. A backup that captures the database but not that directory restores `plugin_signing_required=true` (in `runtime_config`) without the trust bundle file — agents fetching the policy will receive a 500 and require-mode agents will reject every plugin until the bundle is restored.

**Cert-dir collision check.** The server now treats this filename as authoritative. If a prior deployment placed an unrelated PEM at this exact path for a different purpose, it will be interpreted as the plugin trust bundle on first read. This is unlikely (the filename was unused before this release) but worth confirming before upgrade. Run `ls <cert-dir>/plugin-trust-bundle.pem` and rename the file if it pre-exists for any other purpose.

**New `runtime_config` key.** `plugin_signing_required` (string `"true"` or `"false"`). Set via the Settings card; reading and writing the key directly via the runtime-config REST surface is supported but not recommended — the Settings UI guarantees the disk-and-DB invariants (two-phase clear, file-presence-equals-enabled).

**New audit actions.** `plugin_signing.bundle.uploaded`, `plugin_signing.bundle.cleared`, `plugin_signing.require.changed` — see `audit-log.md` for the result and detail conventions. SIEM rules already filtering on `success`/`failure`/`denied` will pick these up unchanged; no new vocabulary tokens.

**Operator distribution.** The server hosts the bundle at `GET /api/v2/agent/plugin-policy` (`PluginSigning:Read`, Administrator-only; unreachable by any MCP token at any tier as of #4028). Agents are pointed at a local copy via `--plugin-trust-bundle <path>`; the manual workflow today is `curl` + `jq` + write the JSON's `data.trust_bundle_pem` field to disk on each agent host. The old `GET /api/v1/agent/plugin-policy` (flat top-level body, no `data` envelope) is **deprecated** — see the vNEXT note below for the migration and removal window. Automatic agent-side fetch is a forthcoming change.

**Fleet-suicide caveat.** The Yuzu release pipeline does not yet sign the 44 in-tree plugins under `agents/plugins/`. **Do NOT enable "Require signed plugins" until you have signed every plugin your fleet uses, including the in-tree ones.** Use the transitional mode (bundle uploaded, Require off) during rollout. The Settings card surfaces this warning inline.

### vNEXT — Response templates (#254, Phase 8.2)

**Superseded (ADR-0058).** `instruction_definitions`/`instruction_sets` moved from
per-replica SQLite to the shared PostgreSQL substrate — the `sqlite3 instructions.db`
commands and the SQLite `schema_meta` v1→v3 probe-and-stamp mechanism described below **no
longer apply**; that mechanism doesn't exist in the current codebase. For backup/restore and
schema-version checks on this store today, use the PostgreSQL Substrate section's `pg_dump`/
`pg_restore` procedure against the `instruction_store` schema, not the commands in this
subsection. Left as-written below for historical reference (this is what the Phase 8.2
migration looked like on SQLite, in case an operator is diagnosing an upgrade that predates
the Postgres cutover).

Phase 8.2 ships named response-view configurations attached to each `InstructionDefinition`: a column subset, sort order, and filter presets the dashboard's filter-bar **View** dropdown surfaces. The feature is purely additive — operators who never author a template see a synthesised `__default__` view that is byte-identical in behaviour to the prior "show all columns, sort by Agent" default.

**Schema migration.** `instruction_definitions` gains one column: `response_templates_spec TEXT NOT NULL DEFAULT '[]'`. The migration ledger advances from v2 to v3. `ALTER TABLE ADD COLUMN` with a constant default is O(1) in SQLite (metadata-only, no table rewrite); the migration is non-destructive.

**Pre-upgrade snapshot (recommended).** Take a backup of the InstructionStore database before upgrade:

```bash
cp /var/lib/yuzu/instructions.db /var/lib/yuzu/instructions.db.bak
# or, for a hot-running server, use SQLite's online backup:
sqlite3 /var/lib/yuzu/instructions.db ".backup /var/lib/yuzu/instructions.db.bak"
```

**Post-upgrade validation.**

```bash
sqlite3 /var/lib/yuzu/instructions.db \
  "SELECT version FROM schema_meta WHERE store='instruction_store';"
# expected output: 3
```

If the value is `2` instead of `3`, the migration did not run — check the server logs for `MigrationRunner: instruction_store migrated to v3` (or for a `probe-and-stamp failed` line in the InstructionStore section).

**Boot wedge recovery.** A corrupt schema_meta row or a pre-existing `response_templates_spec` column with a missing schema_meta v3 stamp will trip the probe-and-stamp guard, which fails closed (server logs `InstructionStore: probe-and-stamp failed; closing database`). To recover, restore the snapshot or apply the column manually:

```bash
# Stop the server first.
systemctl stop yuzu-server

sqlite3 /var/lib/yuzu/instructions.db \
  "ALTER TABLE instruction_definitions ADD COLUMN response_templates_spec TEXT NOT NULL DEFAULT '[]';"
sqlite3 /var/lib/yuzu/instructions.db \
  "INSERT OR REPLACE INTO schema_meta (store, version, upgraded_at) VALUES ('instruction_store', 3, strftime('%s','now'));"

systemctl start yuzu-server
```

**New audit actions.** `response_template.create`, `response_template.update`, `response_template.delete` — see `audit-log.md` for the failure-reason vocabulary. SIEM rules already filtering on `success`/`denied` will pick these up unchanged.

**Authoring caveats.** The dashboard YAML editor's lightweight line-scanner does not extract `spec.responseTemplates` into the indexed column; author through `POST /api/v1/definitions/import` (JSON envelope) or the REST template endpoints. Imported templates with the reserved `id: __default__` are silently dropped during normalisation.

### vNEXT — webhook store moves to Postgres; secrets now encrypted at rest (ADR-0057) (breaking)

`WebhookStore` moves from SQLite (`webhooks.db`) to the PostgreSQL substrate, and the webhook
HMAC signing secret is now envelope-encrypted at rest (`SecretCodec`, ADR-0010) instead of a
plaintext column. No production fleet ever ran a pre-Postgres build of this store, so there was
no real legacy data to migrate — the mandatory backfill this originally shipped with was
retired shortly after (#3623, ADR-0057's Update); a legacy `webhooks.db` file is never read
into Postgres, only hardened to 0600 and counted for a diagnostic warning at boot. `POST /api/webhooks` now returns `400`
for an invalid URL, distinct from a `503` for a genuine store/database error; both `POST` and
`DELETE` return `503` (rather than a silently-empty/silently-failed result) on that latter
case, previously ambiguous. A legacy `webhooks.db` file left on disk still holds every
pre-cutover secret in plaintext and is restricted to the file owner where the platform supports
it (POSIX only, see the ADR) — see [`rest-api.md`](rest-api.md#post-apiwebhooks) for guidance
on disposing of it securely. Full
detail: `docs/adr/0057-webhook-store-postgres-migration.md` and the
`## ⚠️ Behaviour change: webhook store moves to Postgres (ADR-0057)` section in
`docs/user-manual/upgrading.md`.

### vNEXT — `initialize` can answer `503` during a graceful shutdown (#3042)

With MCP streaming on, `initialize` now returns `HTTP 503` / JSON-RPC `-32015` ("Server is shutting down") for a narrow, transient window (seconds, not the deploy's whole grace period) if it lands after `ServerImpl::stop()` has begun draining live sessions. **Affected:** any MCP client integration — the reference clients and most SDKs already treat a non-2xx `initialize` as a transient failure and retry/reconnect; a client that specifically asserted "initialize never 503s" needs updating. No `retry_after_ms` is given (this process has no visibility into when a replacement instance will be reachable); reconnect and re-`initialize` once it is. A session that was already live when shutdown began instead receives a clean `notifications/yuzu.stream_closed` close frame (`reason: session_terminated`) rather than a bare connection drop — see [MCP — Troubleshooting](mcp.md#-32015-server-is-shutting-down-http-503) for the full symptom/cause/fix.

### vNEXT — Linux adapter names no longer carry the `@peer` suffix (breaking)

**What changed.** The `network_config` agent plugin's `adapters` and `ip_addresses` actions were rewritten to read Linux interfaces via rtnetlink instead of parsing `ip -o link show` text. The previous parser copied iproute2's *display* form for any interface with a parent link — a veth pair, a VLAN sub-interface, a tunnel device — which renders as `<name>@<parent>`, for example `eth0@if74` or `eth0.100@eth0`. The new leg reads the kernel's own interface name directly (`IFLA_IFNAME`), which never carries that suffix: the same two interfaces now report as `eth0` and `eth0.100`. This is a deliberate choice, not an oversight — `eth0@if74` is iproute2 presentation syntax that no other data source on the host recognises, and it was also silently breaking the adapter's link-speed lookup (`/sys/class/net/eth0@if74/speed` never resolves; the un-suffixed path does), so restoring the old string would also restore that bug.

**Who this affects.** Any deployment with a Linux fleet segment where at least one host has an interface with a parent link — containerised hosts (veth is the default Docker/Kubernetes networking model), VLAN-tagged interfaces, or tunnel devices (WireGuard, OpenVPN, GRE) — **and** has a saved dashboard filter, a report, an external inventory join, or automation keyed on the adapter-name string containing `@`. A plain bare-metal or VM fleet with no such interfaces is unaffected; the field's *value* changes only for interfaces that previously carried the suffix.

**Before upgrading, check whether this affects you.** On a representative Linux host, compare:

```bash
ip -o link show | awk -F': ' '{print $2}' | grep '@'
```

If this returns any interface names, those hosts will report a different (shorter) adapter name for those interfaces after upgrade — update any saved filter, dashboard, or join key that references the old `@`-suffixed string. If it returns nothing, this note does not affect you.

---

### vNEXT — `software_actions.installed_count`'s reported number can change after upgrading (breaking)

**What changed.** The `software_actions` agent plugin's `installed_count` action was migrated off `popen`/a `powershell -Command` shell-out onto native counting, and the counting rule changed on both platforms it touches:

- **Linux.** The dpkg presence filter now counts packages in the `hi` (installed, held) status alongside `ii` (installed), matching the filter `installed_apps` and `vuln_scan` already use. A host with any held packages reports a higher count than before, by exactly the number of held packages.
- **Windows.** `installed_count` now reads a raw subkey count of the registry `Uninstall` key via `RegQueryInfoKeyW`, replacing a `powershell -Command Get-ItemProperty ... | Measure-Object` pipeline. The two are not byte-identical: the registry read counts every subkey, the old script counted only subkeys carrying at least one property — a rare shape, but not one the new count can be relied on to match exactly. Both the old and new implementation read only the default (64-bit) registry view; 32-bit applications registered under `WOW6432Node` were never counted by either one and still are not.

**Who this affects.** Any deployment with automation, a dashboard trend line, or an alert threshold keyed on the literal `count|N` value from `installed_count` — particularly a Linux fleet with `apt-mark hold`ed packages, or any Windows fleet (the registry-count/property-count divergence is rare but not bounded to a specific host shape, so it isn't pre-checkable the way the Linux change is).

**Before upgrading, check whether this affects you.** On a representative Linux host:

```bash
dpkg-query -W -f='${db:Status-Abbrev}\n' | grep -c '^hi'
```

A nonzero result means that host's `installed_count` will report a higher number after upgrading, by exactly that many. If your automation only compares the count to a rough threshold or trend, no action is needed; if it asserts an exact expected value, re-baseline it after upgrading.

### vNEXT — `GET /api/v1/agent/plugin-policy` is DEPRECATED; use `GET /api/v2/agent/plugin-policy` (#4028, #4144)

**What changed, and why there are now two versions.** This route already existed pre-#4028 (documented here as the trust-bundle-PEM distribution path for agent config management) but was off the REST-v1 API-parity ledger. #4028 originally hardened it onto the same conventions every other `/api/v1/*` route in this manual uses — but did so **in place**, reshaping `GET /api/v1/agent/plugin-policy`'s response envelope without a version bump. An external review (#4144) caught that this violates `docs/api-versioning-policy.md`'s own rule ("changing an error envelope's shape" requires a `/api/v2/` sibling and a deprecation cycle). Corrected: the hardened behavior now lives at `GET /api/v2/agent/plugin-policy`; `GET /api/v1/agent/plugin-policy` is restored to its exact pre-#4028 shape and formally deprecated.

**`GET /api/v2/agent/plugin-policy` (the hardened route — migrate to this):**

- **Success body is enveloped, under `data`.** `{"data": {"enabled":..., "required":..., "cert_count":..., "sha256":..., "subjects": [...], "bundle_unreadable": <bool>, "bundle_error"?: <string>, "trust_bundle_pem":...}, "meta": {"api_version": "v1"}}`. `subjects` and `bundle_unreadable`/`bundle_error` are new fields versus the v1 shape below.
- **Error body is the standard A4 envelope** — `error.code`/`error.message`/`error.correlation_id`/`error.retry_after_ms`.
- **Authorization is the `PluginSigning:Read` RBAC permission** (seeded Administrator-only). An MCP-tier token is denied this route regardless, at the tier chokepoint, before the permission check runs.
- **Two `503` (retry) responses** where v1 answers `200` with a value it cannot stand behind: a `runtime_config_store` outage backing the `required` flag (v1 silently reports `required:false`), and a concurrent trust-bundle upload/clear racing this request's PEM re-read (v1 can pair a stale `sha256` with the newly-uploaded `trust_bundle_pem` on this exact race — #4144 also closed this integrity gap by deriving every field from a single read of the bundle).

**`GET /api/v1/agent/plugin-policy` (DEPRECATED — unchanged since before #4028):** flat top-level body (`{"enabled":..., "required":..., "trust_bundle_pem":..., "cert_count":..., "sha256":...}`), `require_admin` gate (not RBAC), the old bespoke error shape, no audit row, and the pre-existing runtime_config_store/PEM-race behavior described above. Kept exactly as it always was — no new hardening is being back-ported to it.

**Deprecation window (per `docs/api-versioning-policy.md`).** Announced 2026-09-08. `GET /api/v1/agent/plugin-policy` keeps working for at least 90 days **and** at least one intervening feature release, whichever is longer (so no earlier than 2026-12-07, and not before the next feature release ships) — removal will carry its own `CHANGELOG.md` **Breaking/Removed** entry per the cycle's Step 3, never a silent drop.

**Who this affects, and what to do.** Any script, admin tool, or manual `curl` pipeline reading this route directly. Point it at `/api/v2/agent/plugin-policy` and read `response["data"]["trust_bundle_pem"]` (was `response["trust_bundle_pem"]`) — no CLI flag or configuration change is needed, this is a URL and response-shape change only. No action is required before the removal window closes, but migrating now also picks up the TOCTOU integrity fix.

### vNEXT - a poisoned inventory record now makes two result-set producer routes refuse instead of silently narrowing (#4496) (breaking)

**What changed.** `POST /api/v1/result-sets/from-inventory-query` and the MCP `create_result_set_from_inventory_query` tool now refuse (`503`/`kInternalError`) when a candidate inventory record's stored `data_json` nests past the JSON depth guard (the #2437-class poisoned/over-nested record). Previously the poisoned record was silently skipped with no signal at all, and the call succeeded, materialising a result set that had quietly excluded that agent.

**Who this affects.** Any deployment with an existing stored inventory record (`inventory_store.inventory_data`) whose `data_json` nests deeper than the JSON depth guard allows - most likely a row predating the #2437-class write-side guard. A call to either route above that previously succeeded despite such a record now refuses outright instead of materialising a result set narrower than the true match set.

**How to identify the affected record(s).** There is no SQL-level detection query or purge endpoint for this today - the only current signal is a server log line at WARN level, `evaluate_inventory: excluding agent=<agent_id> plugin=<plugin> - data_json nests too deeply (#2437-class)`, emitted once per excluded record on every call that reaches the guard. Watch the server log for this line following a `503` from either route above to identify which agent/plugin's record needs re-collection at the source. Restart the affected agent to force a full resync; if the same WARN line (or a subsequent `poison_excluded` refusal) recurs afterward, the source data itself genuinely exceeds the depth guard and re-collection alone will not clear it - the source plugin needs a fix, or an operator can manually run `DELETE FROM inventory_store.inventory_data WHERE agent_id=... AND plugin=...` (the row repopulates on the next sync cycle if the source data is unchanged).

### vNEXT - a malformed (unparseable) inventory record ALSO now makes the same two result-set producer routes refuse (#4496 follow-up) (breaking)

**What changed.** Same two routes as the entry above (`POST /api/v1/result-sets/from-inventory-query` and the MCP `create_result_set_from_inventory_query` tool), a DIFFERENT trigger: a candidate inventory record whose stored `data_json` fails to parse as JSON at all (a syntax defect, not over-nesting) now also refuses (`503`/`kInternalError`, `reason=parse_error_excluded`) rather than being silently skipped. Kept as a separate, distinctly-named cause from `poison_excluded` above so an operator can tell WHICH guard excluded a record.

**Who this affects.** Any deployment with an existing stored inventory record whose `data_json` is not valid JSON - the write-side depth guard (`gateway_service_impl.cpp`'s `json_exceeds_depth`) checks nesting depth only, not general JSON validity, so a malformed-but-shallow blob has always been able to reach storage. A call to either route above that previously succeeded despite such a record now refuses outright instead of materialising a result set narrower than the true match set. The read-only `POST /api/v1/inventory/evaluate` route instead surfaces this as a `results_excluded_by_parse_error` count field alongside `results_excluded_by_poison` (present only when non-zero), the same posture as the depth-guard entry above. `POST /api/inventory/query` is UNAFFECTED by this specific change: it never calls `evaluate_inventory()` (it lists records by agent/plugin/time metadata, not by evaluating conditions against parsed JSON) and already degrades gracefully on a parse failure, returning the record with its `data` field as a raw string rather than dropping it - there is no narrowed-match-set hazard on that route for this cause.

**How to identify the affected record(s).** Same mechanism as the entry above: a server log line at WARN level, `evaluate_inventory: excluding agent=<agent_id> plugin=<plugin> - data_json failed to parse (malformed JSON)`, emitted once per excluded record. Watch the server log for this line following a `503` (`reason=parse_error_excluded`) from either producer route to identify which agent/plugin's record needs re-collection at the source. Same remediation ladder as the entry above: restart the affected agent to force a full resync; if the same WARN line (or a subsequent `parse_error_excluded` refusal) recurs afterward, the source data itself is genuinely malformed and re-collection alone will not clear it - the source plugin needs a fix, or an operator can manually run `DELETE FROM inventory_store.inventory_data WHERE agent_id=... AND plugin=...` (the row repopulates on the next sync cycle if the source data is unchanged).

---

### vNEXT — `certificates` `delete` on Windows fails closed instead of silently switching stores (#4377) (breaking)

**What changed.** The `security.certificates.delete` action on Windows opened the named store under the `LOCAL_MACHINE` hive; if that open failed, it silently retried under `CURRENT_USER` and deleted there if a same-named store existed and matched. `delete` now opens `LOCAL_MACHINE` only — a failure to open there reports `error|<store> store could not be opened; nothing removed` (non-zero exit, `status|not_found` never returned in this case) and removes nothing, rather than falling back. `list`/`details` are unaffected in kind — they keep the `CURRENT_USER` read fallback, and now disclose it more completely (an explicit output row and a `CONSTRAINED`/`PARTIAL` result whenever a store fell back, an earlier store couldn't be opened, or its enumeration was incomplete, not only when the final match itself came from the fallback).

**Who this affects.** Any deployment where a `delete` automation's target `LOCAL_MACHINE` store can become unopenable (a permissions misconfiguration, a corrupted store) **and** a same-named `CURRENT_USER` store exists on the same host. Before this fix, that combination made `delete` silently remove a certificate from a store the caller never named — which is the bug this closes, not a regression. Automation that only checked for a non-zero exit code was already correctly informed on every OTHER failure path; this is the one combination where the old behavior masked a wrong-target delete with an apparent success.

**Before upgrading, check whether this affects you.** If your `delete` automation for Windows hosts does not already treat a non-zero exit / an `error|...` result as a hard failure requiring investigation, add that check now. There is no way to pre-check for the specific `LOCAL_MACHINE`-unopenable-with-a-`CURRENT_USER`-fallback condition from outside the action itself; the fix is unconditional and has no opt-out.

### vNEXT — service-scoped tokens can no longer create a result set from an inventory query (#4980) (breaking)

**What changed.** `POST /api/v1/result-sets/from-inventory-query` now denies a service-scoped API token outright (`403`), matching its 8 non-dispatch sibling result-set routes. Before this fix, the route gated only through the `Inventory:Read` fleet-read chokepoint (`fleet_read_fn`), which admits and confines a service-scoped caller rather than denying it — but the result set this route creates is owner-scoped to the minting principal's identity, not the token's own service tag, so a service-scoped token holding `Inventory:Read` could mint a set that its minting principal's other tokens/session could then read back.

**Who this affects.** Any integration using a service-scoped API token to call this specific route. No legitimate use of a service-scoped token should have depended on this — the other 8 result-set routes have always denied this way, and the MCP twin (`create_result_set_from_inventory_query`) was never affected. There is no opt-out.

**What to do.** Nothing for a correctly-built integration. If a service-scoped workflow did depend on this route, it needs a non-service-scoped credential going forward, same as the flip notes above; there is no per-route or per-deployment allow.

---

### vNEXT - agent logging is now asynchronous, with a new self-exit code 5 (#4666 PR-2) (NOT breaking)

**What changed.** The agent no longer writes log lines synchronously on the thread that produced them; `main.cpp` installs a bounded async hand-off logger as the process's spdlog default (see "Agent logging is now asynchronous", the paragraph immediately before *Stopping a wedged agent* under *systemd Units*, further down this page, for the queue-size/memory-cost/overrun details). Agent shutdown gains one more possible self-exit code, **5**, distinct from the existing 1/3/4, fired from either of two causes at that step: tearing down that logger (flushing its queue, joining its worker thread) does not complete within an internal 2-second watchdog, **or the teardown itself fails outright** (an immediate exit with no wait at all — see *Stopping a wedged agent* under *systemd Units*, further down this page, for both causes in full).

**Impact.** Not a breaking change: no flag, wire format, API, or default behavior changes, and no operator action is required. Log output looks the same (same pattern/JSON formatting, same `--log-file`/rotation behavior) with one exception below. The externally-visible differences are: (1) under sustained log-sink overload, the agent can now silently drop older queued lines (`overrun_oldest`) rather than blocking, so a very bursty logger under a stuck sink may show gaps instead of a stall; (2) a shutdown wedge that used to hang or need `SIGKILL` before this and the related #2233 watchdogs landed can now self-exit with code 5 specifically, in addition to the pre-existing 1/3/4; (3) the "Received signal, shutting down..." line the agent prints on `SIGINT`/`SIGTERM`/Ctrl-C used to be a raw, fixed-format write straight to stderr — it is now routed through the same configured logger as everything else, so it picks up the configured pattern (or JSON structure under `--log-format json`) and now also lands in `--log-file` when one is configured, not stderr alone. A plain substring match against the message text (the default text pattern keeps the original words verbatim) is unaffected; a line-anchored or byte-exact matcher, or one that assumed this specific line was stderr-only, needs updating; (4) that same line is now an ordinary `info`-level call rather than an unconditional raw write, so at `--log-level warn` or above — a configuration this page itself recommends for agents to cut noise, see "If log volume matters" above — the line is silently **absent entirely**, whereas before it always printed regardless of level. If you rely on this line's presence to confirm a clean/intentional stop, either keep `--log-level` at `info` or below, or switch to checking the process exit code (0 = clean) instead.

**Who should check.** Any operator running a supervisor script or monitoring rule that pattern-matches the agent's process exit code against a fixed set (`{0,1,3,4}` or similar) should widen it to include `5`. An unrecognised exit code there should not be interpreted as "impossible" or treated as a different failure class than the documented watchdog exits already are. See *Stopping a wedged agent* under *systemd Units*, further down this page, for what each code means and how they interact.

## Settings Page

The Settings page is the primary administrative interface. It is accessible only to users with the **admin** role and is rendered server-side using HTMX.

**URL:** `/settings` (redirects to `/login` if unauthenticated or non-admin)

The Settings page is organized into sections, each loaded as an HTMX fragment. Changes take effect immediately without a server restart unless otherwise noted.

### Sections

| Section | Fragment Route | Description |
|---|---|---|
| TLS Configuration | `/fragments/settings/tls` | Enable/disable HTTPS, upload PEM certificate and key files. |
| User Management | `/fragments/settings/users` | Create and delete local user accounts. |
| Multi-Factor Authentication | `/fragments/settings/mfa` | Per-operator TOTP enrollment + recovery codes. Admin-only in this release. Self-service for the logged-in admin only; to clear another (locked-out) user's MFA use the audited break-glass CLI `yuzu-server --mfa-reset <username>` — see `docs/ops-runbooks/auth-db-recovery.md` § Emergency MFA disable. |
| Enrollment Tokens | `/fragments/settings/tokens` | Generate and revoke tokens for Tier 2 agent enrollment. |
| Pending Agents | `/fragments/settings/pending` | Approve or deny agents waiting in the Tier 1 approval queue. |
| Auto-Approval Policies | `/fragments/settings/auto-approve` | Define rules for automatically approving agents based on criteria (hostname pattern, IP range, etc.). |
| API Tokens | `/fragments/settings/api-tokens` | Create and revoke bearer tokens for REST API automation. |
| Plugin Code Signing | `/fragments/settings/plugin-signing` | Upload a PEM trust bundle for agent plugin CMS signature verification, toggle the require-signed-plugins flag, and remove the bundle. The trust bundle persists at `<cert-dir>/plugin-trust-bundle.pem`; the require flag persists in `runtime_config` under key `plugin_signing_required`. Distribution to agents is operator-driven today (curl into a local file referenced by `--plugin-trust-bundle`); automatic agent-side fetch is a forthcoming change. See the user-manual *Agent Plugins → Plugin Code Signing* section. |
| OTA Updates | `/fragments/settings/updates` | Upload agent binaries, view available versions, promote a version to production. The upload form also takes an optional detached CMS **Signature** (`.sig`, max 64 KB), stored as a sidecar beside the binary and served to agents on `CheckForUpdate` — see *Signing update binaries*. The server stores but never verifies it. |
| Tag Compliance | `/fragments/settings/tag-compliance` | View compliance summary across the fleet based on tag-driven policies. |
| RBAC Management | *(planned -- no fragment yet)* | Enable or disable RBAC enforcement, create and manage roles. RBAC is enforced via `RbacStore` and the `/api/v1/rbac/*` REST API, but has no Settings page fragment yet. |
| OIDC SSO / Directory | `/fragments/settings/directory` | Configure OIDC single sign-on (issuer, client ID, secret, admin group). Editable form with "Test Connection" button. Changes are applied to the running server AND persisted to runtime config. **This is the only path that applies an OIDC change to the RUNNING server** (the swap is process-local - a restart reverts to the command-line/environment value, so a durable rotation must update that too; see [security hardening](security-hardening.md#oidc-hardening)) - a `PUT /api/config/oidc_*` persists the value but never reaches the live provider, on this boot or a later one (see [REST API -> Runtime Configuration](rest-api.md#when-a-change-takes-effect)). |
| Internal CA | `/fragments/settings/ca` | View the built-in Certificate Authority (algorithm, SHA-256 fingerprint, expiry), download the CA certificate + CRL, browse the issued-certificate inventory, and revoke a certificate. `Security:Read` to view, `Security:Delete` to revoke. |
| DEX Alerts | `/fragments/settings/dex-alerts` | Route individual DEX signal types to operator notifications and the `dex.signal` webhook, tune the fleet blast-radius thresholds (min devices / window / cooldown), and set the per-cohort Prometheus gauge **export tag key**. Admin-only; changes apply live (no restart) and are audit-logged (`settings.dex_alerts.routing`, `settings.dex_alerts.blast`, `settings.dex_alerts.cohort_export`). See the user-manual *DEX → Routing signals to alerts* and *DEX → Fleet performance rollup* sections. |
| Access Reviews | `/fragments/settings/access-reviews` | Periodic access review (SOC 2 CC6.2) convenience panel — pull/download the cross-principal grant export (JSON/CSV), open a new attestation campaign, and record per-grant `attested`/`flagged_revoke` decisions against an open campaign (`/fragments/settings/access-reviews/campaign?id=...`). A view over the same `AuditLog:Read`/`AuditLog:Attest`-gated `/api/v1/access-reviews*` REST API and its MCP twins — not a separate data path. See `docs/auth-architecture.md` "Periodic access reviews". |

### Revoking an agent certificate from the dashboard

When the server runs its built-in CA, **Settings → Internal CA** lists every
issued certificate. To revoke one (e.g. a decommissioned or compromised agent):

1. Find the agent's row in the inventory (match on **Subject** = `agent_id` or
   the **Serial**).
2. Optionally type a **reason** (e.g. `key compromise`, `decommissioned`) — it is
   stored on the revocation record and audited.
3. Click **Revoke** and confirm. The panel refreshes in place showing the cert as
   *Revoked* and the public CRL is republished automatically. If that publish
   fails (the panel does not show this; the REST/MCP revoke response returns
   `crl_republished:false` and a `ca.crl.published` failure is audited), the
   server republishes it on its own: on the next
   15-second freshness tick once the cause clears, or up to about 5 minutes later
   if that attempt fails too. You do not need to revoke again.

Revocation takes effect **immediately server-side**: the agent is refused on its
next connection, and any already-open command stream is torn down by the
revocation sweep within ~15s. A revoked agent cannot re-enroll its way back by
deleting its key (re-issuance is refused while the revocation stands). The same
operation is available over REST (`POST /api/v1/ca/revoke`) for automation. The
dashboard action is CSRF-protected and requires `Security:Delete`.

> **Gateway-proxied agents:** revocation is enforced on direct-connect agents
> only — an agent reaching the server through a gateway presents its cert to the
> gateway, not the server, so also disconnect it at the gateway. See
> `docs/auth-architecture.md` "Gateway-proxied agents: revocation scope".

### Issuing a code-signing certificate (gap-matrix #10)

The internal CA can issue a **code-signing-only** leaf for signing agent
plugins (`agents/plugins/*.so`, see `docs/user-manual/agent-plugins.md`
"Plugin Signing"), so operators don't have to stand up a separate hand-rolled
CA just to get a signer cert. This is **not** a key-minting service — the
operator generates and keeps the private key; the server only sees and signs a
CSR.

**End-to-end workflow:**

1. **Generate a keypair and CSR locally** (never sent to the server):
   ```bash
   openssl ecparam -genkey -name prime256v1 -out signer.key
   openssl req -new -key signer.key -out signer.csr -subj "/CN=Plugin Signer"
   ```
2. **Submit the CSR** to `POST /api/v1/ca/issue-code-signing` (`Security:Write`)
   with a `label` (becomes the leaf's subject CN, `^[A-Za-z0-9._-]{1,64}$`) and
   an optional `validity_days` (default 365, hard ceiling 730):
   ```bash
   curl -s -X POST -H "X-Yuzu-Token: $TOKEN" -H 'Content-Type: application/json' \
     -d "{\"csr_pem\": $(jq -Rs . < signer.csr), \"label\": \"plugin-signer-2026\"}" \
     https://localhost:8443/api/v1/ca/issue-code-signing > issuance.json
   jq -r .certificate_pem < issuance.json > signer.pem
   jq -r .chain_pem       < issuance.json > signer_chain.pem
   ```
   The equivalent MCP tool is `issue_code_signing_cert` (same schema,
   supervised-tier + approval-gated like every other `Security:Write` MCP
   tool). The issuance is also visible afterward in **Settings → Internal CA**'s
   issued-certificate inventory (`purpose: code-signing`).
3. **Sign the plugin** with the returned leaf, including the issuer chain:
   ```bash
   openssl cms -sign -binary \
     -signer signer.pem -inkey signer.key -certfile signer_chain.pem \
     -in chargen.so -outform pem -out chargen.so.sig
   ```
4. **Distribute the trust bundle to agents.** Since the leaf chains to the
   server's own CA, the trust bundle agents need is simply the already-public
   CA root — `GET /api/v1/ca/root` — no separate CA-distribution step. Ship it
   as `/etc/yuzu/plugin-trust-bundle.pem` alongside the `.sig` files, same as
   any other plugin-signing setup.

**Why this route is scoped to code-signing only.** Usage is hard-pinned to
`codeSigning` (never `clientAuth`/`serverAuth`), so a leaf issued here is
rejected outright by the mTLS `SSL_CLIENT` purpose check and can never
impersonate an agent at the #1118 identity gate regardless of its CN — which is
what makes it safe to ship while the **general** `POST /api/v1/ca/issue`
(operator-chosen CN, operator-chosen EKU) stays deferred. See
`docs/pki-architecture.md` "Code-signing certificate issuance" for the full
argument.

**Revocation and expiry — operational caveats.** Revoking a code-signing leaf
(`POST /api/v1/ca/revoke`, same as any other issued cert) republishes the CRL
and marks it revoked in the issued-certificate inventory — but the agent-side
plugin-load verifier (`docs/user-manual/agent-plugins.md` "Plugin Code
Signing") does **not** consult the CRL, so revocation does not yet stop an
agent from loading a plugin already signed with that leaf. Closing this gap is
a tracked follow-up (`#4234`); until then, treat "revoked" as "will not be
reissued/renewed", not "immediately rejected fleet-wide". Separately, the
signer leaf's own **expiry** already matters: once its `not_after` passes,
`CMS_verify` rejects the signature at the agent's *next restart* — track
`not_after` from the issuance response and re-sign/re-issue before it lapses.

---

## TLS Configuration

The Yuzu server has **two independent TLS surfaces**:

1. **HTTPS** — the dashboard and REST API (port 8443 by default). Configured via `--https-cert` / `--https-key` (or runtime via the Settings page). Disabled with `--no-https`.
2. **gRPC TLS** — the agent listener (port 50051) and the management listener (port 50052). Configured via `--cert` / `--key` / `--ca-cert` (and optionally `--management-cert` / `--management-key` / `--management-ca-cert` for a separate management cert). Disabled entirely with `--no-tls`.

The two surfaces are configured separately and can be in different states (e.g., HTTPS enabled but gRPC TLS disabled for a local UAT against a remote dashboard).

Both surfaces pin the same TLS 1.2 cipher allow-list and version floor; see [TLS policy](tls.md) for the exact list, what's proven by CI, and what isn't pinned yet.

### HTTPS via CLI Flags

HTTPS is enabled by default. Pass `--https-cert` and `--https-key` at server startup. Use `--no-https` for development without TLS. See [Server CLI Flags](#server-cli-flags).

### gRPC TLS via CLI Flags

The recommended posture is **mutual TLS (mTLS)** — the server presents a certificate and verifies a client certificate from each connecting agent:

```bash
./yuzu-server \
  --cert /etc/yuzu/grpc-server.crt \
  --key  /etc/yuzu/grpc-server.key \
  --ca-cert /etc/yuzu/agent-clients-ca.crt
```

If you have not yet stood up a CA for issuing agent client certificates, you have two fallback options:

**Option 1 — One-way TLS** (server cert is presented but client certs are not verified):

```bash
export YUZU_ALLOW_INSECURE_TLS=1   # required as a second confirmation
./yuzu-server \
  --cert /etc/yuzu/grpc-server.crt \
  --key  /etc/yuzu/grpc-server.key \
  --insecure-skip-client-verify
```

This applies to **both** the agent listener and the management listener. The server emits an ERROR-level startup banner and a 5-minute recurring reminder log line for the duration the listener runs in this mode. An audit event with action `server.tls_degraded` is also written every 5 minutes for SOC 2 evidence.

**Option 2 — `--no-tls`** (no encryption, no peer authentication, plaintext gRPC):

```bash
./yuzu-server --no-tls
```

This is the supported posture for **local UAT, customer demos, and development**. The administrative surface is ungated — anyone reachable on port 50052 can issue management RPCs. The server emits a multi-line ERROR-level startup banner and a 5-minute recurring reminder. Do not run `--no-tls` against any network you do not control end-to-end.

### Upgrade note (v0.12.0)

The `--allow-one-way-tls` flag was renamed to `--insecure-skip-client-verify` AND now requires `YUZU_ALLOW_INSECURE_TLS=1` in the environment as a second confirmation. **Existing deployments that pass `--allow-one-way-tls` (or the new flag name) will refuse to start after upgrade until the env var is set.** The old flag name remains accepted with a deprecation warning for one release.

For systemd-managed deployments, add the env var via a drop-in:

```bash
sudo systemctl edit yuzu-server   # creates /etc/systemd/system/yuzu-server.service.d/override.conf
```

```ini
[Service]
Environment="YUZU_ALLOW_INSECURE_TLS=1"
```

### Via Settings Page

1. Navigate to **Settings > TLS Configuration**.
2. Toggle **Enable HTTPS**.
3. Upload PEM-encoded certificate and private key files using the **Upload PEM** button, or paste PEM content directly using the **Paste PEM** button.
4. The server begins serving HTTPS on the configured port. By default, HTTP requests are redirected to HTTPS.

### Certificate Requirements

- Format: PEM-encoded.
- The certificate file may contain the full chain (leaf + intermediates).
- The private key must not be password-protected.
- On Unix, the private key file must not be readable by group or others. The server will refuse to start if permissions are too open. Fix with: `chmod 600 /path/to/key.pem`.
- For production, use certificates signed by a trusted CA. Self-signed certificates work but require agents to trust the CA.

### Certificate Hot-Reload

The server automatically detects when HTTPS certificate or key files change on disk and hot-swaps the SSL context **without requiring a restart**. This enables zero-downtime certificate rotation, including automated renewal via ACME/certbot.

**How it works:**

1. The server polls the cert and key file modification times at a configurable interval (default: 60 seconds).
2. When a change is detected, the new files are validated:
   - PEM format is parseable
   - Certificate and private key match
   - Key file permissions are secure (Unix: not group/others-readable)
   - Files are not empty and not larger than 1 MB
3. If validation passes, the SSL context is updated atomically. New connections use the new certificate; existing connections are unaffected.
4. If validation fails, the current certificate is preserved and an error is logged.

**Configuration:**

| Flag | Default | Description |
|---|---|---|
| `--no-cert-reload` | off | Disable automatic hot-reload. Env: `YUZU_NO_CERT_RELOAD`. |
| `--cert-reload-interval` | `60` | Polling interval in seconds. Minimum: 10s. Env: `YUZU_CERT_RELOAD_INTERVAL`. |

**Best practice for atomic file replacement:**

```bash
# Write to temp files first, then move atomically
cp new-cert.pem /etc/yuzu/certs/server.crt.tmp
cp new-key.pem /etc/yuzu/certs/server.key.tmp
chmod 600 /etc/yuzu/certs/server.key.tmp
mv /etc/yuzu/certs/server.crt.tmp /etc/yuzu/certs/server.crt
mv /etc/yuzu/certs/server.key.tmp /etc/yuzu/certs/server.key
```

**Observability:**

- Log messages: `cert-reload: certificate hot-reloaded successfully` or `cert-reload: ... failed`
- Audit events: action `cert.reload` with result `success` or `failure`
- Metrics: `yuzu_server_cert_reloads_total` (counter), `yuzu_server_cert_reload_failures_total` (counter)

**Limitations:**

- **HTTPS only.** gRPC mTLS certificate hot-reload is not supported. Rotating gRPC certificates still requires a server restart.
- The server logs a warning at startup if gRPC TLS is enabled with cert reload: *"gRPC TLS certificate hot-reload is not yet supported."*

---

## User Management

Yuzu supports two built-in roles for local users:

| Role | Permissions |
|---|---|
| `admin` | Full access to all features, including Settings, user management, agent enrollment, and instruction execution. |
| `user` | Read-only access to the dashboard, agent list, and query results. Cannot modify settings or execute instructions. |

### Creating a User

1. Navigate to **Settings > User Management**.
2. Enter a username, password, and select a role.
3. Click **Create User**.

The password is hashed with PBKDF2 before storage. Plaintext passwords are never written to disk.

> **Breaking change in v0.12.0** — the `role` field is **ignored** on
> create. New users are always created as `user`. To grant admin, use
> the **Change Role** button on the user's row, or `POST
> /api/settings/users/{username}/role` programmatically. This is a
> deliberate split (security finding C1): collapsing role assignment
> into the create endpoint allowed a 4xx-on-create + audit-as-success
> pattern that operators couldn't audit cleanly. Each role transition
> now produces a single `user.role_change` audit event with `old_role`
> and `new_role` recorded in the detail field.

### Changing a User's Role

1. Navigate to **Settings > User Management**.
2. Click **Change Role** next to the target user.
3. Pick `admin` or `user` and confirm.

The server emits an audit event on every branch:

| Branch | Audit `result` | Detail |
|---|---|---|
| Role changed | `success` | `old_role=user,new_role=admin` (or vice versa) |
| Same role requested | `no_op` | `same_role=admin` (or `user`) |
| Self-target rejected | `denied` | `self_role_change_blocked` |
| Invalid username | `denied` | `invalid_username` |
| Invalid JSON body | `denied` | `invalid_json` |
| Missing `role` field | `denied` | `missing_role` |
| Invalid role value | `denied` | `invalid_role` |
| User not found | `denied` | `user_not_found` |
| DB write failed | `denied` | `db_failure` |

> **You cannot change your own role.** The endpoint rejects self-target
> with HTTP 403, audited as `denied:self_role_change_blocked`. The same
> motivation as the self-delete guard: prevent an operator from locking
> themselves out via a misclick or scripted demotion.

> **Active sessions are invalidated atomically.** After a successful
> `user.role_change`, every active session for the target user is
> destroyed; the user must re-authenticate to pick up the new role.

### Deleting a User

1. Navigate to **Settings > User Management**.
2. Click **Remove** next to the target user.
3. Confirm the deletion.

> **Note:** You cannot delete your own account. The Users table renders
> the text "Current user" in place of the **Remove** button for the
> currently authenticated operator's row, and the server rejects any
> hand-crafted `DELETE /api/settings/users/<your-username>` request with
> HTTP 403 and a `Cannot delete your own account` toast. This prevents
> a misclick — or a scripted revoke loop — from dropping the only
> credential on the running server and locking every operator out
> until the process is restarted against its on-disk config. To remove
> the account you are signed in as, first create a second admin, log
> out, log in as the second admin, and delete the original.

---

### Force-logging out a user (incident response)

Use this when an account credential is suspected of compromise but the
account itself should remain functional (the user reports a stolen
laptop but still needs to keep working from a clean device, or a
short-lived contractor's badge is being rotated).

1. Navigate to **Settings > User Management**.
2. Click **Revoke sessions** next to the target user.
3. Confirm the blast-radius warning. The user's active dashboard
   sessions end immediately; their account remains intact and they
   can re-authenticate normally.

The audit log records `session.revoke_all` with `target_id=<username>`,
`target_type=User`, and `detail=count=<N>` where N is the number of
in-memory cookie sessions wiped. The action is also surfaced on the
`yuzu_auth_sessions_revoked_total{caller="admin",scope="cookies"}`
Prometheus counter — a sustained spike there is the operator's
automated alert for either a real incident response in progress or
a misbehaving automation script.

> **API tokens are not revoked by this flow.** Use it for a leaked
> session cookie. If the user's API tokens are also implicated, either
> revoke them individually via Settings → API Tokens or instruct the
> user to click **Sign out everywhere** themselves (see below), which
> revokes both cookies and tokens.

> **Verify persistence after a partial failure.** If the response body
> reports `db_persisted: false` (or the audit row shows `result=partial`
> with `db_error=true`), the in-memory wipe succeeded but the durable
> session rows in PostgreSQL (`SessionStore`) survive. A server restart,
> or a cache miss on another replica, will resurrect those sessions.
> Retry the revoke once the database is healthy again.

### Self-service "Sign out everywhere"

Any user — not just admins — can wipe every credential bearing their
identity by clicking the **Sign out everywhere** button on their own
row in Settings → Users. Unlike the admin **Revoke sessions** button,
this revokes BOTH cookie sessions AND every API token the user owns
(the lost-laptop scenario must kill every credential, not just
browser cookies). After the request the page redirects to `/login`
and the response clears the session cookie via `Set-Cookie: Max-Age=0`.

> **MCP-tier and service-scoped tokens cannot self-revoke.** Those
> credential classes have no other write privilege; accepting a
> self-revoke from one would create a novel DoS surface against the
> human owner. The endpoint returns 403 and the audit row records
> `session.revoke_all.self` with `result=denied`. Use the dashboard
> from a password-authenticated session.

---

## Agent Enrollment

Yuzu uses a tiered enrollment model. Each tier provides a different balance of security and convenience.

### Tier 1: Manual Approval

The default enrollment method. No pre-shared token is required.

1. The agent starts and sends a `RegisterRequest` to the server.
2. The server places the agent in the **pending queue**.
3. An admin reviews pending agents in **Settings > Pending Agents**.
4. The admin approves or denies each agent.
5. Approved agents complete registration on their next heartbeat.
6. Denied agents are removed from the queue. They can re-register if restarted.

### Tier 2: Pre-Shared Token

For automated or bulk deployment. Agents present a token at startup for instant enrollment.

**Server side:**
1. Navigate to **Settings > Enrollment Tokens**.
2. Click **Generate Token**.
3. Configure token properties:
   - **Expiry** -- time limit (e.g., 24 hours, 7 days).
   - **Max uses** -- how many agents can use this token (1 for single-device, unlimited for bulk).
4. Copy the generated token string.

**Agent side:**
```bash
./yuzu-agent --enrollment-token "TOKEN_STRING"
```

The agent passes the token in `RegisterRequest.enrollment_token`. If the token is valid and not expired or exhausted, the agent is enrolled immediately.

### Tier 3: Platform Trust (Planned)

Reserved protocol fields (`machine_certificate`, `attestation_signature`, `attestation_provider`) support future integration with:
- Windows certificate store (machine certificates)
- Azure Attestation
- Cloud instance identity documents (AWS, GCP, Azure)

### Auto-Approval Policies

For environments that need something between manual approval and pre-shared tokens, auto-approval policies can automatically approve agents that match defined criteria:

1. Navigate to **Settings > Auto-Approval Policies**.
2. Create a rule with conditions (e.g., hostname matches `prod-web-*`, source IP in `10.0.0.0/8`).
3. Agents matching any active policy are approved automatically at registration time.

---

## OTA Agent Updates

The server can distribute agent binary updates to enrolled endpoints.

### Uploading a New Version

1. Navigate to **Settings > OTA Updates**.
2. Click **Upload** and select the agent binary. Optionally select a detached
   CMS signature in the **Signature** field — see *Signing update binaries*
   below, and do supply one: without it the agent can verify integrity but not
   authenticity.
3. The server stores the binary (and the signature, if given) and assigns a
   version identifier.

**Package filenames may not end in `.sig`** (case-insensitive); the upload is
rejected with a 400. That suffix is reserved for signature sidecars, named
`<binary>.sig`, so a package called `x.sig` would occupy package `x`'s slot.

### Promoting to Production

1. In the OTA Updates list, locate the uploaded version.
2. Click **Promote** to mark it as the current production version.
3. Agents check for updates on their next heartbeat and download the new binary automatically.

### Managing Versions

- View all uploaded versions with their upload date, size, and promotion status.
- Delete old versions to reclaim storage.
- Only one version can be promoted (active) at a time.

---

### Signing update binaries (#416)

**The SHA-256 the agent checks is not an authenticity check.** The server supplies
that hash over the same gRPC channel that delivers the binary, so anything able to
substitute the binary substitutes the hash beside it. It detects corruption and a
truncated download; it does not detect a malicious or impersonated server. Since
the OTA path installs and runs code on every managed endpoint, sign your packages.

A signature is a detached PEM CMS blob over the binary's bytes, produced by a
certificate carrying the **codeSigning** EKU. Yuzu does not sign for you — the
party that chooses the binary is the party that must sign it, and on this path
that is you: packages reach the registry by admin upload.

**The signing certificate's profile is load-bearing, and getting it wrong fails
in a confusing way.** The agent builds its trust store with OpenSSL's codeSigning
*purpose*, which imposes requirements beyond "chains to the bundle":

- the leaf MUST carry `extendedKeyUsage = codeSigning`;
- the leaf's `keyUsage` MUST be marked **critical** (`keyUsage = critical,
  digitalSignature`). A non-critical keyUsage is rejected — this is the single
  most common way to produce a certificate that looks correct and does not work;
- the issuing CA should carry `keyUsage = critical, keyCertSign, cRLSign`. This one is
  good practice rather than enforced — a CA with no `keyUsage` at all still
  verifies — but set it, since a CA that declares its purpose is easier to audit.

A minimal OpenSSL extension file for the leaf:

```ini
[ codesign ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = codeSigning
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
```

Then sign the binary:

```sh
openssl cms -sign -binary -outform PEM \
  -signer code-signing-cert.pem -inkey code-signing-key.pem \
  -in yuzu-agent-0.14.0-x86_64-linux -out yuzu-agent-0.14.0-x86_64-linux.sig
```

**If your signing certificate chains through an intermediate**, add
`-certfile intermediate.pem`. Without it the signature carries only the leaf, the
agent cannot build the chain to your root. Note the agent does NOT log OpenSSL's
familiar `unable to get local issuer certificate` — CMS reports it as `untrusted
chain` with `error:17000064:CMS routines::certificate verify error`, so grepping
for the X509 string finds nothing. Two-tier PKIs are the normal enterprise case,
so this is easy to hit.

**Diagnosing a rejection.** The agent logs either `untrusted chain` or
`invalid signature`. Be aware that a certificate-*profile* problem — a
non-critical keyUsage, a missing codeSigning EKU, a missing intermediate — is
reported as `untrusted chain`, the same as a genuinely wrong CA. Check the
profile above before concluding the trust bundle is wrong. Verify a certificate
locally with:

```sh
openssl verify -purpose codesign -CAfile trust-bundle.pem code-signing-cert.pem
```

**Before you debug the certificate, check the server side.** A stored signature
that cannot possibly cover the binary beside it produces the same `untrusted
chain` string as a genuinely wrong CA, and no amount of `openssl verify` on your
certificate will reveal it. The **Signed** column shows **signature mismatch**
for exactly this case: the signature landed but the binary write that should
have followed it did not, so the two artifacts are from different uploads. The
fix is to re-upload the binary and its signature together; the certificate is
not the problem. If the column says **unsigned** for a package you signed, the
sidecar was rejected or is unreadable — the server log names which.

Upload it alongside the binary: **Settings → OTA Updates** has an optional
**Signature** file input beside the binary input. The server stores it as a
sidecar next to the package and hands it to agents on `CheckForUpdate`; it does
**not** verify it and is deliberately not trusted to. Signatures are capped at
64 KB — a detached CMS signature is a few KB, so a rejection here usually means
the binary was selected into the signature field by mistake.

**Place the trust anchor out of band.** Agents verify against a PEM bundle you
install on the endpoint — never fetched over the update channel, because a trust
anchor delivered by the party being verified anchors nothing. The installers now create the directory for it. It is deliberately separate from
`/etc/yuzu/certs`, which is the SERVER's CA directory — the server owns that path
and re-tightens its mode on every boot, so an anchor placed there would be either
unwritable by the server or unreadable by the agent, with no mode satisfying
both:

| Platform | Path | Ownership |
|---|---|---|
| Linux | `/etc/yuzu-agent/certs/` | `root:root`, mode 0755 |
| macOS | `/etc/yuzu-agent/certs/` | `root:wheel`, mode 0755 |
| Windows | `C:\ProgramData\Yuzu\agent-certs\` | Administrators + SYSTEM, and owned by Administrators. The installer takes ownership, resets the ACL outright, then breaks inheritance and re-grants those two (`takeown` → `icacls /reset` → `icacls /inheritance:r /grant:r`) — breaking inheritance alone is not enough, because it leaves any explicit entry a local user had already set, and leaves them owning the directory. A post-install check verifies the resulting owner and entry set exactly and aborts the install if anything else can write there. |

**How much protection that directory gives you depends on the platform, and it is
worth being precise about it.** On Linux the agent runs as the unprivileged
`yuzu-agent` user and genuinely cannot write the anchor. On macOS and Windows the
agent runs as `root` and `LocalSystem` respectively — it has to, in order to
replace its own binary — so it *can* write the anchor there. On those platforms
the directory permissions protect the anchor from unprivileged local users, not
from the agent process itself.

This is a real limit rather than an oversight: a process privileged enough to
replace the system binary is privileged enough to rewrite the file that
authorises the replacement. Signature verification on those platforms defends
against a malicious or impersonated *server*, which is the threat it was built
for; it is not a defence against an already-compromised root/SYSTEM process on
the endpoint. If you need the stronger property, run the agent as a dedicated
non-privileged service account and grant it only what it needs.

Then point agents at it. On a packaged install the agent is started by the
service manager, not by hand, so set these through the environment rather than by
editing the unit:

| Platform | How |
|---|---|
| Linux (systemd) | `systemctl edit yuzu-agent` and add `[Service]` / `Environment="YUZU_UPDATE_TRUST_BUNDLE=/etc/yuzu-agent/certs/update-trust-bundle.pem"`, then `systemctl restart yuzu-agent`. The shipped unit has a fixed `ExecStart`, so a drop-in is the supported route. |
| macOS (launchd) | Add the variable to `EnvironmentVariables` in `/Library/LaunchDaemons/com.yuzu.agent.plist`, then `launchctl kickstart -k system/com.yuzu.agent`. |
| Windows | Add the flag to the service's **binary path**. **`sc.exe config binPath=` REPLACES THE ENTIRE COMMAND LINE — it does not append.** Capture the current one first with `sc qc YuzuAgent`, then re-issue it in full with the flag added, keeping the escaped inner quotes exactly as shown under **Windows Service Installation → Agent: `--install-service`** below. Passing only the new flag drops `--server`, `--data-dir`, `--plugin-dir` and `--log-file`; the service then reaches RUNNING, fails closed on startup with no server or CA to pin, and the endpoint silently leaves the fleet while you believe you enabled signing. Prefer this over `setx /M`: services inherit their environment from `services.exe`, which caches it at boot, so a machine variable is typically NOT visible to a merely-restarted service — the bundle would stay unset and verification silently OFF while you believed it was on. If you do use `setx /M`, reboot. |

Every flag below has the environment variable shown beside it:

| Agent flag | Env | Default | Meaning |
|---|---|---|---|
| `--update-trust-bundle` | `YUZU_UPDATE_TRUST_BUNDLE` | unset | PEM bundle of CAs permitted to sign update binaries. **Unset disables signature checking entirely.** |
| `--update-require-signature` | `YUZU_UPDATE_REQUIRE_SIGNATURE` | off | Refuse packages that carry no signature. |

Setting `--update-require-signature` **without** a trust bundle refuses to start,
rather than running with enforcement silently inert.

### The verifier's catastrophic invariants

Four properties of `agents/core/src/detached_signature.cpp` are recorded as
catastrophic-if-violated in `.claude/routed-concerns.md`. They are stated here in
full because that table is character-budgeted and carries only a pointer. Anyone
changing that file must preserve all four.

1. **`CMS_verify` must never receive `CMS_NO_SIGNER_CERT_VERIFY` or
   `CMS_NO_CONTENT_VERIFY`.** Each individually disables one half of the check —
   the certificate-chain validation or the content digest — while still returning
   success. The call passes exactly `CMS_BINARY | CMS_DETACHED`.
2. **The `X509_STORE` must keep `X509_PURPOSE_CODE_SIGN`.** Without it, any leaf
   chaining to a trusted root becomes a signing authority — the normal case for an
   internal PKI issuing mTLS and S/MIME from one root, so the consequence is not
   hypothetical.
3. **An unreadable trust bundle must fail CLOSED.** "Cannot check" is never
   "checked out fine". The store load is the first check performed.
4. **OTA verification stays after the SHA-256 compare and before apply**, reading
   the HELD descriptor rather than re-opening the path. Apply is the point of no
   return — the execute bit on POSIX, the live-binary move on Windows. Reading the
   held descriptor is mandatory rather than preferable on Windows: the staged file
   is opened `dwShareMode=0` and cannot be opened twice.

Two further properties are load-bearing without being catastrophic:
`--update-require-signature` governs **only** whether an ABSENT signature is
tolerated — a present-but-invalid one is refused in both modes given a bundle —
and the trust-anchor directory must stay root-owned and non-world-writable.

### Rolling signing out to a live fleet

**Roll it out in two stages, and understand what the first stage does not give
you.** Deploy the bundle with `--update-require-signature` OFF first: an unsigned
package is then accepted with a loud warning, while a package whose signature is
present and does not verify is refused — that rejection is unconditional and does
not depend on this flag. Once every package you serve is signed, turn the flag on.

The permissive stage is a genuine **downgrade oracle** for as long as it lasts.
There is no capability handshake on this RPC, so an agent cannot tell "this server
is too old to sign" from "the signature was stripped in transit"; both look like
an absent signature and both are accepted. Keep the window short.

### Withdrawing a signed release, or responding to a suspected key compromise

**Deleting the package from the server does not withdraw it.** The signature
covers the binary's content and carries no version or expiry, so any copy of a
binary your key has ever signed stays acceptable to every anchored agent forever.
An attacker who kept a copy can replay it (see the rollback limitation above).
Removing it from Settings → OTA Updates only stops *you* serving it.

The only true withdrawal lever is the trust anchor itself, and it is blunt:

1. **Issue a new signing key and certificate**, and re-sign every release you
   still want endpoints to accept.
2. **Re-upload the re-signed packages** to the server. Do this BEFORE the new
   bundle reaches any endpoint: an agent that gets the new anchor while the
   server is still serving old-key signatures refuses everything.
3. **Distribute a bundle containing only the new certificate** — not both.
   Last, because this is the step that actually invalidates the withdrawn
   release, and until it lands the withdrawal has not happened.

For a *suspected key compromise*, do the same but do not wait to batch it, and
invert the ordering caution from *Rotating the signing key* below: there the old
certificate is removed **last** to avoid an outage; here leaving it in place is
the risk you are trying to remove. Plan for a window in which updates stop rather
than a window in which a compromised key is still trusted.

### Rotating the signing key

**If you are enabling signing for the first time, read *Rolling signing out to a
live fleet* above first** — this section is about replacing a key you already
use.

The spec for this feature asked for custody and rotation guidance, and rotation
is worth doing deliberately because the naive sequence strands a fleet.

**The trap.** Agents verify against whatever is in the trust bundle at the moment
they check. If you sign new packages with a new key and have not yet distributed
the new anchor, every agent that has the old anchor refuses them — and refusal
is unconditional for a signature that is present and does not verify, so the
transitional mode does not help.

**The safe order:**

1. **Distribute the new anchor alongside the old one, and wait.** A PEM bundle
   may hold several certificates; append the new one rather than replacing it, so
   an agent trusts both keys at once. Do not sign anything with the new key yet.
   Wait until you are confident every endpoint has the updated bundle — the fleet
   gauge cannot tell you this, so use your configuration-management tooling.
2. **Start signing with the new key.** Both old and new packages verify, because
   every agent trusts both.
3. **Re-sign anything you still serve.** A package uploaded under the old key
   keeps its old signature; it stays valid only while the old anchor is trusted.
4. **Remove the old certificate from the bundle**, last.

**Re-signing an existing package.** Upload it again with the new `.sig`. Do NOT
re-upload the binary without a signature intending to add one afterwards — the
upload replaces the sidecar along with the binary, so the package would be served
unsigned in between, and `--update-require-signature` agents would refuse it for
as long as that window lasts. The **Signed** column in Settings → OTA Updates
shows what agents are actually being served.

**Custody.** The signing key never needs to touch a Yuzu server — the server
stores and forwards the signature but never produces or verifies one. Keep it
wherever you keep your other code-signing material.

**Watch `yuzu_fleet_ota_signature_refusing_agents`.** The server derives this
gauge from the agents' heartbeats: it counts how many endpoints have refused at
least one update **since the agent process last started**. It counts AGENTS
rather than refusals on purpose — one wedged endpoint retrying every six hours
would otherwise dominate a refusal count and hide how much of the fleet is
affected.

**Read it as "has refused", not "is currently failing".** The underlying counter
is cumulative and never resets, so an endpoint that refused once and has since
updated cleanly keeps contributing until it restarts — and conversely, an agent
restart zeroes one that is still failing. A rising number is a real signal and
worth acting on; a flat non-zero number is not proof that those machines are
still stuck. To confirm current state, check whether the affected endpoints'
reported agent version is advancing.

**A refusing agent still cannot tell you WHY.** There is no status-report RPC on
the update path, so the reason appears only in that endpoint's own log — the
gauge tells you how many are affected, not what to fix. The strings to grep for
are `untrusted chain` and `invalid signature`; an unsigned package logs
`update package is unsigned and --update-require-signature is set` (`missing` is
the metric label for that case, not text that appears in the log). Verify on a pilot
group before a fleet-wide flip.

Signature verification runs after the hash check and before anything irreversible
— before the execute bit is set on POSIX and before the live binary is moved
aside on Windows — and reads the already-downloaded file through the descriptor
that was hashed, so the bytes verified are the bytes that were checked.

## RBAC Management

Role-Based Access Control adds granular permissions beyond the built-in admin/user roles.

### Enabling RBAC

1. Navigate to **Settings > RBAC Management**.
2. Toggle **Enable RBAC**.
3. When RBAC is enabled, the system enforces fine-grained permissions based on assigned roles.

### Built-in vs. Custom Roles

| Aspect | Built-in Roles | Custom Roles (RBAC) |
|---|---|---|
| Granularity | Two roles: admin, user | Per-operation permissions on securable types |
| Assignment | Per-user | Per-principal (users, service accounts, API tokens) |
| Management groups | Not scoped | Permissions can be scoped to management groups |

### Creating a Role

1. Navigate to **Settings > RBAC Management**.
2. Click **Create Role**.
3. Name the role and assign permissions for each securable type and operation.

For the full RBAC model, see `docs/user-manual/rbac.md`.

---

## Tag Compliance

The Tag Compliance section provides a fleet-wide view of compliance based on tag-driven policies.

1. Navigate to **Settings > Tag Compliance**.
2. View the compliance summary showing:
   - Total devices, compliant count, non-compliant count.
   - Breakdown by tag category.
   - Devices missing required tags.

Tag compliance data is also available via the REST API (`GET /api/v1/tag-compliance`) for integration with external dashboards and reporting tools.

---

## OIDC SSO Configuration

Yuzu supports OpenID Connect (OIDC) for single sign-on with external identity providers such as Microsoft Entra ID (Azure AD), Okta, or any OIDC-compliant provider.

### Configuration

OIDC can be configured via CLI flags at startup or through the Settings page:

| Parameter | CLI Flag | Description |
|---|---|---|
| Issuer URL | `--oidc-issuer` | The OIDC discovery endpoint base URL. |
| Client ID | `--oidc-client-id` | Application (client) ID from your identity provider. |
| Client Secret | `--oidc-client-secret` | Client secret for the confidential client flow. |
| Redirect URI | `--oidc-redirect-uri` | Callback URL registered with the identity provider. Must point to the Yuzu server's `/auth/callback` path. |
| Admin Group | `--oidc-admin-group` | Entra ID group object ID that maps to the admin role. |
| Skip TLS Verify | `--oidc-skip-tls-verify` | Disable TLS cert verification for OIDC endpoints (insecure, dev only). Env: `YUZU_OIDC_SKIP_TLS_VERIFY`. |
| Link Claim | `--oidc-scim-link-claim` | ADR-2001 (SCIM↔OIDC identity linkage, CC6.8) — which validated ID-token claim (`sub` default, or `oid` for Entra) links a SCIM slug to its OIDC login identity so a SCIM deprovision can also revoke that identity's API/MCP tokens. **Not a Settings-page form field** — this page saves the OIDC config CLI/env already set for this value unchanged rather than resetting it to the struct default. See [SCIM ↔ OIDC identity linkage](scim-provisioning.md#scim--oidc-identity-linkage-federated-token-revocation). Env: `YUZU_OIDC_SCIM_LINK_CLAIM`. |

### Identity Provider Setup

1. Register Yuzu as an application in your identity provider.
2. Set the redirect URI to `https://<yuzu-server>:<port>/auth/callback`.
3. Note the client ID and client secret.
4. Enter these values in the Yuzu Settings page or pass them as CLI flags.

### User Mapping

OIDC-authenticated users are mapped to Yuzu roles based on claims or group membership. The mapping configuration depends on your identity provider and is set in the OIDC section of the Settings page.

---

## SAML 2.0 SP Configuration

Yuzu supports SAML 2.0 SP-initiated single sign-on as an alternative to OIDC for enterprises whose identity infrastructure requires SAML. **Linux and macOS only — SAML is not supported on Windows builds.**

> **HTTPS is required.** The `__Host-yuzu_saml_bind` binding cookie is `Secure`-only and is silently dropped by browsers over plain HTTP. If `--https-cert`/`--https-key` are not configured the server logs an error at startup and leaves SAML disabled (fail-closed).

> **Windows note:** On Windows builds, any SAML flag is logged as an error at startup and SAML is not enabled.

### Configuration

All five flags below must be supplied for correct operation, and all five are validated at startup — a partial set leaves SAML disabled (fail-closed) until every flag is set. The two group→role flags further down are optional and independent of this five-flag gate.

| Flag | Env var | Description |
|---|---|---|
| `--saml-idp-entity-id` | `YUZU_SAML_IDP_ENTITY_ID` | Entity ID URI of the IdP (must match what the IdP uses in assertions). |
| `--saml-idp-sso-url` | `YUZU_SAML_IDP_SSO_URL` | IdP's HTTP-Redirect SSO endpoint URL. |
| `--saml-idp-cert` | `YUZU_SAML_IDP_CERT` | Filesystem path to the IdP's assertion-signing certificate (PEM). The cert at this path is the sole trusted authority; in-document `<KeyInfo>` values are ignored. |
| `--saml-sp-entity-id` | `YUZU_SAML_SP_ENTITY_ID` | Entity ID URI this SP advertises to the IdP in the AuthnRequest. |
| `--saml-sp-acs-url` | `YUZU_SAML_SP_ACS_URL` | Full public URL of the Assertion Consumer Service (`https://<host>/saml/acs`). |

Example startup:

```bash
./yuzu-server \
  --https-cert         /etc/yuzu/server.crt \
  --https-key          /etc/yuzu/server.key \
  --saml-idp-entity-id "https://idp.example.com/saml" \
  --saml-idp-sso-url   "https://idp.example.com/saml/sso" \
  --saml-idp-cert      /etc/yuzu/idp-signing.pem \
  --saml-sp-entity-id  "https://yuzu.example.com" \
  --saml-sp-acs-url    "https://yuzu.example.com/saml/acs"
```

### Role mapping

Two additional, optional flags grant admin access via IdP-attested group
membership — mirroring the OIDC `--oidc-admin-group` mechanism:

| Flag | Env var | Description |
|---|---|---|
| `--saml-group-attribute` | `YUZU_SAML_GROUP_ATTRIBUTE` | `<Attribute Name="...">` in the assertion's `<AttributeStatement>` whose `<AttributeValue>`s are group identifiers. |
| `--saml-admin-group` | `YUZU_SAML_ADMIN_GROUP` | The group value (from `--saml-group-attribute`) that grants `role=admin`. |
| `--saml-name-attribute` | `YUZU_SAML_NAME_ATTRIBUTE` | Optional. `<Attribute Name="...">` whose first value is the user's display name (e.g. Entra's `displayname` claim URI). Empty (default) leaves the session display as the raw NameID. **Display/audit only — never an identity or authz input.** |
| `--saml-email-attribute` | `YUZU_SAML_EMAIL_ATTRIBUTE` | Optional. `<Attribute Name="...">` whose first value is the user's email (e.g. Entra's `emailaddress` claim URI). Used only as a display fallback and logged — **never stored durably or used for identity.** |

A session is `role=admin` only when both flags are set and the assertion's
group list contains an **exact match** for `--saml-admin-group`; otherwise
(including when either flag is left empty, the default) the session is
`role=user`. Group values are read from the same signature-verified assertion
`NameID` is read from, and `NameID`/email/display name are never treated as
group-membership evidence. Changing either flag requires a server restart
(no hot-reload). JIT elevation remains non-functional for SAML users (no
local `users` row in the `auth` schema) regardless of role — a group-mapped
admin gets `role=admin` directly at login, not via the elevation endpoint.

> **Configuring `--saml-admin-group` against a real IdP:** the value must be
> the exact identifier the IdP puts in the assertion, not a display name —
> Entra ID sends group **object ID GUIDs**, not group names, so configure the
> GUID. Matching is case-sensitive. A user in more than ~150 Entra groups hits
> **"groups overage"**: Entra omits the `groups` claim entirely for that
> assertion (substituting a Graph API link), so such users can never resolve
> to admin via `--saml-admin-group` regardless of actual membership — use a
> dedicated low-membership group for the mapping. At most 200 group values
> from the configured attribute are considered.

**Fine-grained RBAC (parity with OIDC).** When RBAC is enabled and
`--saml-group-attribute` is configured, every asserted group value is ALSO
reconciled into the RBAC store as `saml:<value>` group principals (source
`"saml"`) on every login, the same `reconcile_idp_memberships` mechanism
OIDC uses for source `"entra"` — assign roles to `saml:<value>` groups via
the management-group role-delegation API,
`POST /api/v1/management-groups/{id}/roles`, with `"principal_type": "group"`
and `"principal_id": "saml:<value>"` (only the `Operator` and `Viewer` roles can be
delegated this way). Both mechanisms coexist: `--saml-admin-group` still grants
the coarse session role independently of any fine-grained RBAC grants.
Reconciliation runs before the session is minted (fail-closed on error), and
two cases deliberately do NOT fall through to a normal reconcile:

- **More than 200 asserted group values DENIES the login** — the parser has
  already truncated `groups` to 200 entries by then, and reconciling that
  truncated view would silently deprovision every membership past the
  200th, so the login is refused instead (mirrors OIDC's
  `group_count_exceeded`).
- **An empty or absent group attribute SKIPS reconciliation** (never
  deprovisions) — SAML cannot distinguish "attribute absent" from
  "attribute present, zero values", and deprovisioning on that ambiguity
  would be wrong. Existing `saml:` memberships are left untouched; SCIM
  deprovisioning remains the only full deprovisioning path for a
  SAML-linked identity.

See [authentication.md's SAML Fine-Grained RBAC section](authentication.md#saml-fine-grained-rbac)
for the full detail.

### AuthnRequest signing

One additional, optional flag, independent of the five-flag gate, signs
SP-initiated AuthnRequests:

| Flag | Env var | Description |
|---|---|---|
| `--saml-sp-key` | `YUZU_SAML_SP_KEY` | Filesystem path to the SP AuthnRequest signing private key (PEM, **RSA only** — EC and RSA-PSS keys are rejected). |

When set, AuthnRequests are signed over the HTTP-Redirect binding with
RSA PKCS#1 v1.5 + SHA-256 (`SigAlg`
`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`), carried as the
`SigAlg`/`Signature` query parameters. The key file must pass the same
private-key permission check as the HTTPS/gateway TLS keys (not
group/other-readable). Left unset (the default), AuthnRequests remain
**unsigned** — backward-compatible with an IdP that accepts unsigned
requests.

Fails closed: a configured key that is unreadable, over-permissioned,
exceeds 64 KiB, is malformed, encrypted/passphrase-protected, is not RSA, or
has a modulus outside **2048–16384 bits** disables SAML **entirely** at
startup — loudly (an `ERROR` log line), never a silent fall-back to unsigned
requests. A per-request signing failure fails `/auth/saml/start` rather than
emitting an unsigned redirect. The key **must be unencrypted** — a
passphrase-protected key is rejected, not prompted for. The 2048-bit floor
rejects factorable weak keys; the 16384-bit ceiling bounds per-request signing
cost on the unauthenticated start endpoint.

Yuzu does not yet publish an SP metadata endpoint, so you must register the
signing key's **public certificate** with the IdP by hand (as the
AuthnRequest/request-signing verification certificate) — otherwise the IdP
rejects the signature despite a clean Yuzu boot. See the user manual's
[AuthnRequest Signing](authentication.md#authnrequest-signing) section for
the `openssl` keypair-generation and IdP-registration recipe.

### Known limitations in this release

- **MFA step-up:** MFA step-up is not supported for SAML sessions — a SAML session hitting any step-up-gated endpoint receives a 403 regardless of `--mfa-enforcement`. Use `optional` and rely on the IdP to enforce MFA. Avoid `required` for SAML deployments.
- **`--auth-mode=sso-only`:** Requires an SSO provider — OIDC, or (Linux/macOS, HTTPS enabled) a complete SAML SP config. A SAML-only deployment **can** disable local-password login. Note: SAML sessions cannot use JIT elevation (grant admin via `--saml-admin-group` instead), and there is no login-page SAML button — SAML operators go to `/auth/saml/start`.
- **HA / multi-replica:** Pending AuthnRequest state is in-process. Configure load-balancer sticky sessions (session affinity) on `/auth/saml/start` + `/saml/acs`. Without affinity, approximately `(N−1)/N` of logins fail as unsolicited. OIDC shares this limitation.
- **IdP cert rotation:** Update `--saml-idp-cert` and restart the server. There is no hot-reload.
- **No login-page button:** Navigate directly to `GET /auth/saml/start`; there is no "Sign in with SAML" button on the login page.

See `docs/user-manual/authentication.md` "SAML 2.0 SSO" for the full login flow, capability table, and `docs/auth-architecture.md` "SAML 2.0 SP" for the implementation reference.

---

## Directory Sync (AD/Entra ID)

`POST /api/directory/sync` pulls users, groups, and group memberships from
Microsoft Entra ID into `DirectorySync` (schema `directory_sync`, ADR-0063).
See `docs/user-manual/upgrading.md`'s ADR-0063 entry for the Postgres-cutover
migration note.

### Diagnosing a stuck directory sync (ADR-1007)

`sync_entra` holds a single in-process guard (an `std::atomic<bool>`, not a
Postgres advisory lock — this is a single-server-process concern, unlike the
KEK op lock below) for the duration of one sync call, so two overlapping
`POST /api/directory/sync` calls can no longer race and interleave writes.
A call that arrives while another is already in flight is rejected
immediately with `409 Conflict` — no queueing, no blocking, and the caller
gets its response right away rather than waiting for the in-flight sync to
finish; retry once the guard clears (see below for how long that can take).

**If `409` responses persist well past a normal sync's duration** (a normal
sync completes in seconds to low tens of seconds; each individual HTTP call
IS bounded — 15s connect / 30s read+write per Microsoft Graph call, 10s
connect / 15s read+write for the OAuth token exchange — but nothing bounds
the sync AS A WHOLE, which can page through an arbitrarily large tenant
across many such calls), the guard is most likely still
held by a sync that is genuinely slow — a large tenant, or a slow/degraded
Graph API response — not wedged forever, since the guard is released via
RAII on every exit path of `sync_entra`, including error returns. There is
**no operator override to force-clear the guard** — restarting the server
is the only way to reset it, because the guard is in-process state with no
persisted record for an admin surface to reset independently (a Postgres
advisory lock, by contrast, can be inspected and — carefully — cleared
without restarting anything; see "Diagnosing a stuck KEK op lock" below for
what that looks like when the underlying primitive supports it). Before
restarting, check the server log for the sync's own completion or error
line and confirm Microsoft Graph reachability from this host — a restart
discards no synced data (the store itself is unaffected), but it does drop
the in-flight sync attempt.

**HA / multi-replica:** this guard, like the SAML/OIDC login-state
limitation above, is in-process and therefore per-replica — a second
server replica has its own independent guard and would not see a sync
in flight on the first. Coordinating this across replicas is not yet
built (`docs/adr/2002-high-availability-architecture.md`); today's
single-server deployment model is unaffected.

## Data Storage and Encryption

Yuzu stores persistent server data in PostgreSQL (see [PostgreSQL Substrate](#postgresql-substrate)): the response store, audit log, RBAC store, authentication and every other server store. Only the runtime state files, the NVD CVE cache `nvd_cves.db` and the `agent-updates/`/`upload-blobs/` file directories live on disk, in `--data-dir` (or `--update-dir` for agent updates) (see [Configuration Files](#configuration-files)).

> **Important: Yuzu does not encrypt the database at rest.** Secret columns (for example TOTP secrets) are envelope-encrypted by the server (ADR-0010; see [Key management](#key-management-secrets-kek)), but query results, audit logs and agent metadata sit in plaintext in PostgreSQL's data directory, and the `--data-dir` files are plaintext too. Any user or process with read access to those files can read this data.

### Protecting Data at Rest

Operators must use full-disk encryption to protect Yuzu data at rest:

| Platform | Recommended Solution | Notes |
|---|---|---|
| Linux | dm-crypt / LUKS | Encrypt the partition or volume where Yuzu data resides (PostgreSQL's data directory and `--data-dir`). Most distributions support LUKS during OS installation. |
| Windows | BitLocker | Enable BitLocker on the drive containing the Yuzu server directory. Requires TPM or startup key. |
| macOS | FileVault | Enable FileVault in System Settings. Encrypts the entire startup volume. |

For containerized deployments (Docker Compose), ensure the host volumes backing `server-data` and the PostgreSQL data volume are on an encrypted filesystem.

> **Planned:** A future `--encrypt-db` option was scoped as SQLCipher encryption for the server's SQLite files. With the server stores on PostgreSQL it would now cover only the NVD cache; database-level encryption for PostgreSQL is the operator's platform choice today.

---

## PostgreSQL Substrate

The server's storage substrate is **PostgreSQL** (ADR-0006/0007; the agent stays SQLite). As of the cut-over (#1320 PR 3) the server **requires a reachable database at boot and fails closed without one** — it constructs a shared connection pool at startup and, if `--postgres-dsn` / `YUZU_POSTGRES_DSN` is unset or the database is unreachable, **refuses to start and exits non-zero** (no SQLite fallback for the server). There is a distinct `[PG] Refusing to start` log line so the cause is unambiguous in `systemd` / `kubectl` logs.

> **Upgrade action (BREAKING):** before upgrading to this release, provision PostgreSQL and set `YUZU_POSTGRES_DSN`. Docker Compose deployments already bundle the `postgres` service and wire the DSN (no action beyond pulling the new images). Native installs must run the provisioning helper below (or point the DSN at a managed PostgreSQL 16+) **first** — otherwise the upgraded server will not boot. Restore pairing (ADR-0010): a database restore must be paired with the matching `--ca-dir` / key-directory restore.

**Dedicated coordination connection (HA WS-3, ADR-2002 §10).** Beyond the pool, each server holds **one** additional, never-recycled Postgres connection for background-work leader election, **plus one** for the `/readyz` reachability probe (HA WS-8). (The probe's connection runs one plain query per tick and holds no session state, so unlike the leader-election connection it works through a transaction-mode pooler; it reconnects after any failure.) Per §10 it is deliberately outside the pool and must reach the primary directly (an HAProxy-to-primary front is fine; a *transaction-mode* pooler is not, as it breaks the session advisory lock leadership rests on).

**Sizing `max_connections` (#4943).** The server's whole Postgres footprint is static: **`pool_size + 2` per server** — the pool never opens more than `--postgres-pool-size` connections, plus the two dedicated ones above; there is no other connect site. So

`max_connections ≥ N_servers × (pool_size + 2) + superuser_reserved_connections (3) + every other client`

— backup tooling, Grafana's data source, ad-hoc `psql`. Sized this way the servers cannot exhaust the database by themselves; only other clients can. To keep *them* out of the servers' share, the shipped `yuzu-postgres` images (single-node and the HA Patroni profile) set **`reserved_connections`** (PostgreSQL 16+; default **40**, env `YUZU_PG_RESERVED_CONNECTIONS`, `0` disables) and **grant `pg_use_reserved_connections` to the app role** at first boot. Once the free slots fall to `superuser_reserved_connections + reserved_connections`, only the app role (and superusers) can still connect — so a backup job or a stray session can never take the slot the `/readyz` probe needs to reconnect, which would otherwise turn a replica red on a database that still serves (the probe holds its connection in steady state and reconnects only after a failure; at the limit that reconnect was the connection refused first). The reserve covers the pool and the probe alike — the probe connects exactly as a pool connection does, so it is never green while the pool is refused. Set `YUZU_PG_RESERVED_CONNECTIONS` to `N_servers × (pool_size + 2)` (the default fits two servers at the default pool, e.g. 2 × (16 + 2) = 36 ≤ 40). **Never set it to `max_connections` minus `superuser_reserved_connections` or higher** — both scripts refuse to boot on that value (the boot-time check reads the live `max_connections`; the Patroni entrypoint checks against its own literal 200), because it would leave zero connection slots any ordinary (non-privileged) client could ever use, not merely under load. **On the single-node image this refusal happens AFTER the role/database/grant already exist** on the now-initialized data directory (Postgres's initdb-only-runs-once convention means those steps ran before this check) — restarting the SAME container with a corrected value does **not** retroactively apply anything; either start over on a fresh (wiped) data volume, or apply the fix by hand per "Existing databases" just below. The Patroni entrypoint's check runs before ANY of that (at bootstrap, before the cluster exists), so a Patroni refusal is a clean, no-op-safe retry. **This check runs once, at bootstrap.** A later `patronictl edit-config --set postgresql.parameters.max_connections=...` on an already-running Patroni cluster is not re-validated against the `reserved_connections` value already in force — re-check the arithmetic by hand after any live `max_connections` change (tracked for a real runtime check: #4943 fast-follow). **Existing databases:** first-boot init does not re-run; apply it by hand — `ALTER SYSTEM SET reserved_connections = 40;` (restart required; under Patroni, `patronictl edit-config --set postgresql.parameters.reserved_connections=40` then `patronictl restart <scope>` — `edit-config` alone only writes the DCS config and marks the member pending-restart, it does not apply a postmaster-context GUC like this one; the GRANT below is unchanged either way) and `GRANT pg_use_reserved_connections TO yuzu;`. Verify with `SHOW reserved_connections` and `SELECT pg_has_role('yuzu', 'pg_use_reserved_connections', 'MEMBER')`. On PostgreSQL 15 or older the grant is skipped with a notice and only the formula protects you. **Re-run this same verification** after anything that can silently undo it: a first boot interrupted between the `GRANT` and the `ALTER SYSTEM` (the init script never re-runs once the data directory exists, so a kill in that narrow window leaves the grant in place but the GUC at Postgres's own default of 0 — inert, not incorrect, but not protecting anything either), or any role recreation, credential rotation, or disaster-recovery restore that can drop and re-add the app role without this script running again.

**Connection-pool sizing.** The server opens up to `--postgres-pool-size` / `YUZU_POSTGRES_POOL_SIZE` connections (default **16**). Each heartbeat persists last-seen with one short-lived lease (≈33/s at 1 000 agents on a 30 s heartbeat — well within 16), and `/viz/fleet` draws one. Raise the size for large fleets (rule of thumb: +1 per ~1 000 agents beyond 5 000, plus headroom per additional Postgres-backed store as they migrate) or for a slow managed-PG link. Tune against the `yuzu_pg_pool_{in_use,open,size}` gauges, the `yuzu_pg_acquire_wait_seconds` histogram (the leading saturation signal), and the `yuzu_pg_{connect_failed,acquire_timeout,unhealthy_discard}_total` counters (`unhealthy_discard` counts pooled connections dropped on a failed health probe); the bundled alert rules (`YuzuPgPoolSaturated`, `YuzuPgAcquireWaitHigh`, `YuzuPgConnectFailing`, `YuzuServerPostgresUnreachable` in `docs/prometheus/yuzu-alerts.yml`). Pool saturation never affects `/readyz` — a busy but healthy server must stay in rotation — while an unreachable database turns `/readyz` red within seconds, well before those alerts' `for:` windows page. The heartbeat upsert is best-effort with a 250 ms acquire deadline, so a saturated pool degrades the stale-host display, never the live fleet.

**Saturation fast-fail (not operator-configurable).** When the pool is already saturated at the moment of acquire (no idle connection, no spare capacity to open one), every bounded acquire across every Postgres-backed store now gives up after a short, fixed ceiling (~500 ms) instead of running to the caller's own, often much longer, timeout, freeing the calling worker thread for other routes rather than pinning it on a connection unlikely to free up in time. This substantially reduces, but does not eliminate, the risk of a saturated pool cascading into broader worker-thread exhaustion (including on unrelated routes such as auth) under sustained load; the underlying pool-to-worker sizing ratio is unchanged, so a large enough sustained saturation event can still exhaust worker capacity, just at a materially higher load threshold than before this mitigation. This ceiling is a compiled-in default, not exposed via a CLI flag or environment variable; if it proves wrong for your deployment's connection-hold-time distribution, that is a code change, not a config change. The metrics and alert rules named above (particularly `yuzu_pg_acquire_wait_seconds` and `YuzuPgAcquireWaitHigh`) remain the right signals to watch; a rising rate of fast-failed acquires under this ceiling is visible via the same `yuzu_pg_acquire_timeout_total` counter as a genuine full-timeout exhaustion (the counter does not currently distinguish the two).

Held-open SSE streams also lease this pool: each re-validates its credential every ~3 s tick. Those reads are cached (60 s for API tokens, 15 s for the engine-principal liveness check), so steady-state cost is proportional to *distinct credentials* rather than to stream count — but the refreshes still land here alongside ordinary traffic, and a stream capacity far above the pool size is the shape that turns a brief pool blip into a correlated stall. The server warns at startup when effective SSE stream capacity exceeds 16x `--postgres-pool-size`. Treat that as a prompt to watch `yuzu_pg_acquire_wait_seconds` and `yuzu_pg_pool_in_use`, not as an instruction to enlarge the pool reflexively — adding connections against an already-struggling database makes matters worse, and lowering the stream capacity is often the better lever.

**Bootstrap-time floor (default-cert generation, ADR-0053).** First-boot (or self-heal) default-cert generation takes the `yuzu:default_certs_bootstrap` Postgres advisory lock for the duration of its critical section, holding one pool lease for that whole window while the CA-store writes it performs inside the lock each draw their own nested per-call lease from the SAME pool — an N-way race at this one boot-time code path needs roughly N+1 simultaneous connections. At the allowed minimum `--postgres-pool-size=1` this is not merely "can self-contend under a race" — it fails **every** boot that needs to generate certs, deterministically, zero racers required, since the outer lease alone exhausts a pool of size 1. It fails closed and loudly (a nested-acquire timeout surfaces as an ordinary `record_issued` failure → refuse to start), never a hang or silent corruption, but a pool sized at the bare minimum for steady-state heartbeat/SSE traffic above can still be too small for this one-time bootstrap path — size for at least 2 even on the smallest deployments.

**`endpoint_state` is reconstructible.** The `endpoint_state` schema (last-known offline-host display) is pure cache — the server repopulates it from heartbeats within one cycle (~30 s). A targeted restore may safely omit it; only the secret-bearing schemas and live operational data need the paired key-directory restore above.

### Provisioning a native (non-container) install

Docker Compose deployments get PostgreSQL automatically — every tracked compose bundles a `postgres` service (the `ghcr.io/tr3kkr/yuzu-postgres` image: PostgreSQL 18 + pgvector + first-boot role/database init). Native installs use the provisioning helper instead:

| Install method | Helper location | Invocation |
|---|---|---|
| `.deb` / `.rpm` | `/usr/share/yuzu/scripts/install-server-postgres.sh` | Run automatically (non-fatally) by the package post-install hook |
| Release tarball | `scripts/install-server-postgres.sh` inside the archive | Run manually as root after unpacking |
| Git checkout | `scripts/install-server-postgres.sh` | Run manually as root |

Two modes:

```bash
# Mode 1 — external/managed Postgres: writes the DSN to
# /etc/yuzu/yuzu-server.env (0600), which the systemd unit loads
# via EnvironmentFile=. No local Postgres is touched.
sudo bash install-server-postgres.sh --dsn 'postgresql://yuzu:...@db.example.com:5432/yuzu'

# Mode 2 (default) — local Postgres: provisions the app role + database
# on an already-installed local PostgreSQL 16+ and writes the DSN env file.
# Idempotent — never clobbers an existing role, database, or env file.
sudo bash install-server-postgres.sh
```

The helper is **non-fatal when no local cluster is found** (prints install hints and exits 0) — this posture flips to a hard failure when the server starts requiring the DSN. The app role's credential is freshly random and never shared with the `postgres` superuser. Per-store schemas are *not* created by the helper; the server's migration runner owns those at startup (ADR-0008).

### Backing up PostgreSQL state

A complete backup is the Postgres dump below **plus** the whole `--ca-dir`, taken at the same point in time and restored as a pair (see the restore-pairing invariant under [Key management](#key-management-secrets-kek)), together with the `--data-dir` state files, the NVD cache `nvd_cves.db`, and the blob directories `agent-updates/` (or `--update-dir`) and `upload-blobs/` listed in [Configuration Files](#configuration-files). The dump holds only the OTA-package and completed-upload records; restoring it without those two directories leaves records that point at files that no longer exist.

Use `pg_dump` (logical, consistent-by-construction — safe against a live database, unlike filesystem copies).

**Native installs** — the DSN lives only in the root-only systemd environment file (`/etc/yuzu/yuzu-server.env`), **not** in interactive shells, so load it first. Then split the password out so it rides the `PGPASSWORD` environment variable instead of the process argv (`/proc/<pid>/cmdline` is world-readable, and the command lands in shell history):

```bash
# Run as root. Assumes the standard helper-written DSN shape
# scheme://user:password@host:port/db.
. /etc/yuzu/yuzu-server.env
export PGPASSWORD="$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^[a-z]+://[^:/@]*:([^@]*)@.*$!\1!')"
DSN_NOPASS="$(printf '%s\n' "$YUZU_POSTGRES_DSN" | sed -E 's!^([a-z]+://[^:/@]*):[^@]*@!\1@!')"

pg_dump --format=custom --file="yuzu-pg-$(date +%F).dump" "$DSN_NOPASS"
```

**Docker Compose** (reference template — superuser peer auth inside the container; no credential on the host command line):

```bash
docker exec yuzu-postgres pg_dump -U postgres --format=custom yuzu \
  > "yuzu-pg-$(date +%F).dump"
```

Restore with the server stopped, then start the server (the migration runner reconciles schema versions at boot). On a **fresh disaster-recovery target**, the app role and database must exist before `pg_restore` — run `install-server-postgres.sh` (or your managed-DB provisioning) first:

```bash
# Native — same env-file + PGPASSWORD/DSN_NOPASS preamble as the backup recipe
pg_restore --clean --if-exists --no-owner --role=yuzu \
  --dbname="$DSN_NOPASS" "yuzu-pg-YYYY-MM-DD.dump"

# Docker Compose
docker exec -i yuzu-postgres pg_restore --clean --if-exists --no-owner \
  --role=yuzu -U postgres --dbname=yuzu < "yuzu-pg-YYYY-MM-DD.dump"
```

Schedule the dump alongside the `--ca-dir` and `--data-dir` backups (and `--update-dir`, if set outside `--data-dir`); verify restores periodically against a scratch database (`createdb yuzu_restore_test && pg_restore --dbname=... `).

### Key management (secrets KEK)

Secret columns in PostgreSQL are **envelope-encrypted app-side** (ADR-0010): each value is sealed under a fresh data-encryption key (DEK), and the DEK is wrapped by the install's key-encryption key (KEK). The KEK is a 32-byte key file generated on first boot (`secrets-kek-v1.key`, mode 0600, in the same key directory as the CA root key — `--ca-dir`, default `/etc/yuzu/certs` on Linux and on macOS running as root, `~/Library/Application Support/Yuzu/certs` on macOS running non-root, `C:\ProgramData\Yuzu\certs` on Windows) and **never enters the database** — `kek_meta` in the `secrets` schema records only non-secret fingerprints (key-check values), which the server verifies against the key files at every boot.

> Three of the four gated stores now write secret columns through this machinery: `auth` (TOTP secrets, since 2026-07-16), `webhooks` (the outbound HMAC signing secret, ADR-0057), and `runtime_config_store` (the OIDC client secret, ADR-0060). `offload_targets` adopts it once it migrates to Postgres (ADR-0059). Set your backup procedure up for the pairing below **now** — every additional migration widens the blast radius of a KEK/DB backup mismatch, never narrows it.

**The restore-pairing invariant.** `pg_dump` output and volume snapshots contain **ciphertext and wrapped DEKs only** — a database backup alone recovers no secrets, and a database restore is unusable without the matching keys directory. DB backups and keys-dir backups are a *pair*: back them up on the same schedule, restore them **together**, and keep a separate offline copy of the KEK file exactly like the CA root key. The restore-verification drill must restore both halves and confirm a clean boot — the server checks every registered KEK fingerprint at startup and **fails closed** rather than serving with unreadable secrets. The failure classes below are stable error *prefixes* at the start of the fatal startup message (match the prefix in the message text when writing log-scraping alerts; they are not structured log fields):

| Startup error prefix | Meaning | Recovery |
|---|---|---|
| `kek_unresolvable` | A registered KEK version has no key file. Causes: keys dir older than the DB (backup skew), wrong keys directory, a second server instance pointed at the same database (unsupported — one KEK per database), **or, on macOS, a database registered by a server run as root (`/etc/yuzu/certs`) later opened by the same binary run non-root, or vice versa (`~/Library/Application Support/Yuzu/certs`)** — the two euid-dependent defaults do not share key material. | Restore the keys directory from the backup *paired* with this database, or pass `--ca-dir` pointing at whichever directory the original KEK actually lives in. |
| `kek_corrupt` | The key file exists but does not match its registered fingerprint (torn/corrupt file or foreign key material — **not** row tamper). | Same: restore the paired keys directory. |
| `provider_failure` | CSPRNG or key-storage failure during KEK generation or check-value computation (first boot / rotation). | Check the keys directory is writable and system entropy is healthy; if a prior first boot crashed, the message names the torn file to delete. |
| `db_error` | Postgres connection/transaction failure during the `secrets` schema migration or `kek_meta` read/write. | Check the DSN and Postgres service health — triage as "DB down", not key loss. |

**Rotation** mints `secrets-kek-v<N+1>` and re-wraps only the small wrapped-DEK header of each stored blob — payloads are untouched, so rotation is cheap, incremental, and interruptible (a crash resumes by re-running the re-wrap; already-rotated rows are detected by the blob header; a crash *before* the new version's fingerprint registers leaves an orphan key file that the next rotation attempt safely adopts). The operator-facing surface for this — REST + MCP, the half-committed contract, retirement preconditions, and a DR drill — is below.

#### Rotating the KEK

Three operations, mirrored on REST and MCP so both surfaces answer identically for the same failure:

| REST | MCP tool | Permission | Returns |
|---|---|---|---|
| `POST /api/v1/secrets/kek/rotate` | `rotate_kek` | `Security:Write` | `{new_version, rotation_complete}` |
| `POST /api/v1/secrets/kek/rewrap` | `rewrap_secrets` | `Security:Write` | `{rows_rewrapped}` |
| `GET /api/v1/secrets/kek/status` | `get_kek_status` | `Security:Read` | `{active_version, oldest_in_use, rotation_complete, live_versions, lock_held, lock_holder_pid}` |

All three take no request parameters (an empty body or `{}`; any other field is rejected `400`). `rotate`/`rewrap` are `Security:Write` — on the MCP side that means the supervised-tier approval gate applies, same as every other write tool.

`/status`'s `live_versions`, `lock_held`, and `lock_holder_pid` are #2530
diagnostic fields — see "Diagnosing a stuck KEK op lock" below for what they're
for and how to use them. `live_versions` and `lock_held` are `null` (never a
fabricated `0`/`false`) when the underlying query could not be determined; a
`null` `lock_held` means the lock state is **unknown**, not "not held".
`lock_held`/`lock_holder_pid` report the lock **in the server's own
database** — the query is filtered by `current_database()`, not
cluster-wide, so a same-named advisory lock held by an unrelated tenant
database sharing the same Postgres instance never shows up here.

```bash
# 1. Mint a new version and re-wrap every row under it.
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://yuzu.example.com/api/v1/secrets/kek/rotate

# 2. Confirm completion.
curl -H "Authorization: Bearer $TOKEN" \
  https://yuzu.example.com/api/v1/secrets/kek/status
# → {"active_version":2,"oldest_in_use":2,"rotation_complete":true,
#    "live_versions":2,"lock_held":false,"lock_holder_pid":null,...}
```

`/rotate`'s response deliberately omits a row count (`rotation_complete: true` is the honest signal — see below); call `/rewrap` if you want an actual `rows_rewrapped` number.

> **The half-committed contract — read this before you retry anything.**
> `rotate_kek` mints the new version and then re-wraps every row as one
> operation. If it fails, the response tells you which of two states you are
> in:
> - **A plain failure** (`503`/generic `500`) — nothing changed; safe to
>   retry `/rotate`.
> - **Half-committed** (`500`, message *"KEK rotation did not finish
>   re-wrapping every secret"*) — the new KEK version is **already active**;
>   only the row-by-row re-wrap did not finish. **Call `POST
>   /api/v1/secrets/kek/rewrap` (or the `rewrap_secrets` MCP tool) to
>   resume. Do NOT call `/rotate` again** — it would mint a *second*,
>   spurious new version on top of an already-half-rotated state, not fix
>   anything. `/rewrap` is idempotent and safe to call repeatedly, including
>   once there is genuinely nothing left to do (`rows_rewrapped: 0` is a
>   normal, non-error outcome).
>
> A practical consequence: rotation **attempts** are rate-limited, and a
> *failed* attempt consumes that budget too. That is deliberate — it is
> precisely the retry-on-500 loop above that the limit exists to stop, and
> automation that ignores the half-committed message would otherwise mint a
> fresh, never-retirable KEK version on every retry. `/rewrap` is **not**
> rate-limited, so the correct recovery path is never blocked. Treat a `429`
> on `/rotate` as "you are recovering, use `/rewrap`", not as "try again
> shortly".
>
> **One authoritative rate limit, durable and cluster-wide (#2530; #2530
> G7-S9 removed a second, weaker tier).** An earlier cut of this hardening
> pass added a cheap process-local pre-check (5 minutes, in-memory, no DB
> round trip) alongside the durable control below, to short-circuit an
> obviously-too-soon retry before it cost a query. That pre-check was
> **removed**: its hardcoded 5-minute window could not be configured down
> (an operator setting `--kek-min-rotate-interval` below 5 minutes was still
> refused for the full 5 minutes on that path), and it never populated an
> honest `retry_after_ms`, silently falling back to a fixed value on exactly
> the requests it refused. It was also never the correctness guarantee — it
> was per-process, so servers sharing one database each kept their own
> state, and a restart cleared it. The sole authoritative control today is a
> **durable** rate limit read from `secrets.kek_meta.created_at`, compared
> against the database server's own `now()` in a single statement (so it is
> never comparing an app-host clock to a DB clock):
> `--kek-min-rotate-interval` (seconds, default `3600` = 1h,
> `YUZU_KEK_MIN_ROTATE_INTERVAL`). It survives a restart and is shared
> cluster-wide by every server pointed at the same database. A rotate
> refused by this durable check gets `429` with
> an **honest** `retry_after_ms` computed from that same durable timestamp —
> this is the one failure in this whole surface where a numeric retry hint
> is truthful, because waiting genuinely resolves it. (`retry_after_ms` is a
> `uint32` millisecond count; an unreasonably large configured interval
> **saturates** it at its maximum rather than wrapping, so the hint can only
> ever come out over-long, never falsely short.)
>
> **This is a runaway/abuse guard, not a rotation-schedule setting — do NOT
> set it to your rotation cadence.** It exists to stop a looping caller
> (buggy automation, a compromised token) hammering `/rotate`, not to
> express how often you intend to rotate; the default is sized for that job
> and **most operators should never change it.** Raising it has a sharp,
> real cost: it directly delays *emergency* re-rotation after a suspected
> KEK compromise — the single most time-critical thing this surface exists
> to support — with **no bypass** (`/rewrap` only resumes an
> already-in-progress rotation; it never mints a new version). Set this to,
> say, 90 days to "match" a quarterly rotation policy, and a routine
> rotation followed by a compromise the very next day leaves you refused
> with `429` for the next three months, with no escape short of a restart
> at a lower value **in the middle of the incident**. Rotation *cadence*
> (how often you choose to rotate) and this *minimum spacing* (how often
> you permit rotation to be attempted at all) are different concepts — keep
> them separate. The flag's upper bound (365 days) is a sanity ceiling
> against a fat-fingered value, not a recommendation.
>
> Cluster-wide *correctness* (as opposed to rate limiting) still comes from
> the advisory lock, which reports `409` — see Concurrency below. A second,
> unrelated `409` — the live-version ceiling — is covered right after it.
>
> **Week-one gotcha: a fresh install's FIRST rotate is refused too (#2530
> G7-S7).** KEK v1 is minted at boot with `created_at = now()` — it is a
> `kek_meta` row like any other, so the durable clock above starts counting
> down from **install time**, not from whenever you happen to first call
> `/rotate`. If you install the server and immediately try to rotate as a
> smoke test, you get the same `429` cooldown response an abuse-guard trip
> would produce, with `retry_after_ms` counting down from
> `--kek-min-rotate-interval` (default 1h) minus however long the server has
> been up. This is expected, not a bug — treat a `429` in the first hour
> after a fresh install as "working as designed", not as a signal something
> is wrong with the install.

**Verify completion.** `GET /status` (`get_kek_status`) is the source of
truth: `rotation_complete` is `true` when no stored secret blob still
references a version older than `active_version` — equivalently,
`oldest_in_use` (null when there are no secret rows at all) is `>=
active_version`. This is the ADR-0010 §3 completion signal; don't infer
completion from a lack of errors alone — always confirm with `/status`
after a `/rotate` or `/rewrap` call.

**Concurrency.** `/rotate` and `/rewrap` take a cluster-wide Postgres
advisory lock (`secrets_kek_op`), non-blocking. A second concurrent attempt
gets `409` on REST ("another KEK operation is in progress") or a retryable
MCP error with an honest `retry_after_ms` — that is expected behaviour under
contention, not a fault. Wait for the in-flight operation to finish and
retry. **`GET /status` deliberately never takes this lock** — a status poll
during a long-running rotation would otherwise itself be blocked, which is
the opposite of what a diagnostic endpoint is for; see "Diagnosing a stuck
KEK op lock" below for how `/status` observes lock state without taking it.

**The live-version ceiling — a second, different `409` (#2530).**
`--kek-max-live-versions` (default `32`, `YUZU_KEK_MAX_LIVE_VERSIONS`) caps
the number of non-retired KEK versions. `/rotate` at or above the ceiling
also gets `409` — "the live KEK version ceiling has been reached" — which
reads exactly like the lock-conflict `409` above but means something
different and needs a different response: waiting never clears it (there is
no automatic decay, and no `retry_after_ms` is sent for this one), and
because there is no retire route (#2525), the only way past it is deliberate
operator action.

**Raising `--kek-max-live-versions` above the default is the supported
escape hatch** for that — do it deliberately, as a temporary risk acceptance
pending #2525, not as a routine tuning knob. Setting it above the default:

- logs a `spdlog::warn` at boot naming the configured value and the default;
- emits a `server.kek_ceiling_raised` audit event (`principal="system"`,
  `target_type=Secret`, `target_id=kek`, once the audit store is up) —
  worded as an explicit, temporary risk acceptance, the same posture pattern
  as `--allow-unsigned-packs`/`--allow-unsigned-definitions`.

`--kek-max-live-versions` is a per-process CLI flag, not cluster state — it
is not stored anywhere the cluster shares. If several servers point at the
same database, **every one of them needs the raised value** before the
ceiling genuinely lifts fleet-wide: since `secrets_kek_op` serialises rotate
attempts across the whole cluster, a caller can still land on an un-bumped
server's evaluation of the ceiling and get refused, even after you've raised
it on others.

**Clock-anomaly guard (#2530).** The durable rate limit above depends on
comparing `now()` to `secrets.kek_meta.created_at`, both read from the
*same* Postgres statement precisely so the comparison never crosses an
app-host clock against a DB-host clock. If the newest `kek_meta` row's
`created_at` is future-dated relative to that same `now()`, `/rotate`
refuses immediately with a distinct `503` — "the KEK rotation clock is
untrustworthy" — **not** a `429` cooldown, and with no retry hint at all. A
`429` here would carry a `retry_after_ms` computed from the exact timestamp
that has just been proven untrustworthy, which would be a lie rather than a
hint. **What to actually do:** this means the database server's own clock
(or its NTP sync) is wrong — investigate that, not the KEK subsystem.

**The two skew directions behave DIFFERENTLY — read this before assuming
"it'll clear itself" (#2530 G7-B6).** A **backward** clock skew (the
database server's clock jumps or drifts BACKWARD after the row was minted)
is transient and self-clearing: once the clock reads sanely again relative
to the stored row, `/rotate` proceeds normally on the very next attempt,
with nothing to reset by hand. A **forward** skew — the row was minted
*while* the clock was already ahead (bad NTP source, a VM restore, a
failover to a host whose clock is ahead) — is **not** self-clearing: the
stored `created_at` stays in the future relative to `now()`, and therefore
stays `> now()`, for the ENTIRE skew duration, blocking every `/rotate`
attempt for as long as that lasts. Because the anomaly check runs before
the cooldown and ceiling checks, this refusal has **no bypass at all** — no
flag, no restart, no override — making an emergency re-rotation after a
suspected key compromise impossible until real time catches up to the
stored timestamp.

**Diagnosing which direction you're in.** Both the `503` body and the
server log line report the observed skew **magnitude** — how many seconds
into the future the row is dated — specifically so you can tell "a few
seconds of NTP jitter" (self-clears within moments) from "this row is dated
next year" (does not self-clear on any practical timescale) at a glance,
rather than having to query `kek_meta` by hand to find out. If the reported
magnitude is small (seconds), it is almost certainly ordinary clock jitter
around the `now()`/`created_at` boundary — wait a few seconds and retry. If
it is large (hours, days, or more), treat it as a genuine incident:
1. Confirm the database server's actual wall-clock time and NTP sync status
   directly (not through the application).
2. Correct the clock (or complete the VM restore / failover cutover that
   left it skewed).
3. Once `SELECT now()` on the database server reads a sane time again,
   `/rotate` proceeds normally on the next attempt — there is nothing to
   reset in `kek_meta` by hand.

There is deliberately **no** flag to bypass this check even for a confirmed,
large, persistent forward skew — a code-level escape hatch on a security
guard is a separate design decision with its own review, not something this
hardening pass adds. If a persistent forward skew blocks an emergency
rotation for you in practice, file an issue describing the scenario rather
than working around it by hand-editing `kek_meta.created_at`.

**Query-cancellation classification (#2530).** Any KEK rotate/rewrap/status
Postgres query that is canceled or exceeds `statement_timeout` (SQLSTATE
`57014`) returns a distinct `503` — "a KEK query was canceled or exceeded
its statement timeout" — instead of a generic `500`. Read that phrasing
literally: SQLSTATE `57014` is `query_canceled`, which Postgres also raises
for an administrator's `pg_cancel_backend`, so "timed out" alone would
overclaim what actually happened, and this is **not necessarily transient**
— don't just retry blind. Check, in roughly this order: `statement_timeout`
(is it configured too low for current load?), current database load,
whether an administrator issued a cancel, and the size of the
registered-column rewrap scan (`SecretCodec::registered_columns()` — today
just `auth.users.mfa_totp_secret`; a second registered secret column makes
the unbatched full-column scan a real scale risk, deliberately deferred and
out of scope for this hardening pass — see the trip-wire test named in
`tests/unit/server/test_secret_column_registration_tripwire.cpp`). **If a
`query_canceled` arrives after `/rotate` has already advanced the active
version, it is reported as `HalfCommitted`, not `QueryCanceled`** — the
half-committed contract above always wins, because the operator must still
be told to call `/rewrap`, never to retry `/rotate`.

#### Diagnosing a stuck KEK op lock (#2530)

Before this, a backend wedged holding the `secrets_kek_op` advisory lock
made every KEK operation return `409` forever, with no way to see why and no
documented remedy. `GET /status` (`get_kek_status`) now reports four fields
for exactly this:

| Field | Meaning |
|---|---|
| `live_versions` | Count of non-retired KEK versions. `null` if the count query could not be determined — never a fabricated `0`. |
| `lock_held` | `true` iff `secrets_kek_op` currently has a granted holder **in this server's own database** (the query is filtered by `current_database()`, not cluster-wide). `null` if the holder query could not be determined — **never** a fabricated `false`; a `null` here means the lock state is UNKNOWN, not "not held". |
| `lock_holder_pid` | That holder's Postgres backend pid. **THREE possible states, not two — always read `lock_held` first to disambiguate a `null` pid:** (1) `lock_held: false` → `null`, genuinely unheld; (2) `lock_held: true` with a **non-null** pid → a normal held lock, corroborate it in `pg_stat_activity` (step 2 below); (3) `lock_held: true` with a **`null`** pid → HELD, but the holder's backend pid itself could not be read from `pg_locks` at query time — there is no pid to corroborate with, see step 1's third case below. `lock_held: null` (query itself failed) also reports `lock_holder_pid: null`, but that is a fourth, entirely separate "undetermined" case — do not conflate it with case (1) or (3). |
| `lock_holder_captured_at` | ISO-8601 UTC instant (`YYYY-MM-DDTHH:MM:SSZ`) the `lock_held`/`lock_holder_pid` snapshot above was **taken** — `null` in lockstep with them when undetermined (#2530 H1). This exists so a stale reading is visible as stale rather than authoritative: the longer the gap between this timestamp and the moment you are about to act, the less you should trust that `lock_holder_pid` still names the same backend — Postgres **reuses** pids, so an old-enough reading can now point at a completely unrelated connection. Treat a `lock_holder_captured_at` more than a few seconds in the past as a reason to re-read `/status` (or, before anything irreversible, re-query `pg_locks` directly — see step 3) rather than act on the number in front of you. |

**These are lock-free diagnostic snapshots, not one coordinated read.** Each
is its own `SELECT`, taken at a possibly different instant from the others
and from `active_version`/`oldest_in_use` in the same response — `/status`
still never takes the lock itself (see Concurrency above). **Never derive a
"safe to retire" conclusion from any combination of them** — that is
precisely the #2525 hazard this surface has no retire route for; these
fields add observability, not a new safety guarantee.

**A `null` `lock_held` means UNKNOWN, never "not held" (#2530).** If the
holder query itself fails — the exact scenario a wedged Postgres backend or
substrate outage produces — `lock_held` and `live_versions` come back `null`
rather than the confident-sounding `false`/`0` an earlier version of this
surface fabricated. Treat a `null` `lock_held` as "corroborate before
concluding anything": check `pg_stat_activity` directly and check whether the
Postgres substrate itself is degraded (see the `yuzu-postgres` alerts) before
deciding either way.

**The procedure — follow it in order, do not skip a step:**

1. **Identify the holder.** `GET /status`'s `lock_holder_pid` is the
   Postgres backend pid currently holding `secrets_kek_op` **in this
   database**. Three cases, not two:
   - `lock_held: false` — nothing to diagnose here: a `409` you're
     separately seeing is either a genuinely in-flight operation about to
     finish, or the pid you captured earlier has already released and
     moved on.
   - `lock_held: null` — **do not conclude "not held"**; the holder query
     itself failed. Go straight to `pg_stat_activity` (step 2) and check
     Postgres substrate health before drawing any conclusion.
   - `lock_held: true` with `lock_holder_pid: null` — the lock **is** held,
     but the holder's backend pid could not be read from `pg_locks` at
     query time, so there is no pid to plug into step 2's `WHERE pid =
     <lock_holder_pid>`. Instead, query `pg_locks` directly for any granted
     holder of this lock in the current database and read whatever pid it
     reports at that moment:
     ```sql
     SELECT pid FROM pg_locks
      WHERE locktype = 'advisory' AND classid = 2037545589
        AND objid = (hashtext('secrets_kek_op')::bigint & 4294967295)::oid
        AND granted
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database());
     ```
     If that also returns a null/no pid, retry `/status` once (the pid
     column can be transiently unreadable) before escalating to a DBA
     inspection of `pg_stat_activity` for any session in this database
     holding an advisory lock, since the affected session cannot be
     targeted by pid alone.
2. **Corroborate in `pg_stat_activity` — never act on the pid alone.**
   ```sql
   SELECT pid, state, wait_event_type, wait_event, query, query_start, xact_start
     FROM pg_stat_activity
    WHERE pid = <lock_holder_pid>;
   ```
   A **healthy long rewrap** (a large registered-secrets scan) and a
   **genuinely wedged backend** look identical from `lock_held`/
   `lock_holder_pid` alone — the difference is entirely in what
   `pg_stat_activity` shows. An actively-progressing query with a sensible,
   recent `query_start` is a rewrap doing real work. A backend sitting
   `idle` or `idle in transaction` while still holding the lock, or a
   `query_start`/`xact_start` far older than any registered-column table
   could plausibly take to scan, is the wedge.
3. **Only a DBA terminates it, deliberately, and only after step 2 shows a
   genuine wedge.** **Read this in full before running `pg_terminate_backend`
   on anything.**

   > **The holder is very likely one of YOUR OWN Yuzu servers, mid-rotation
   > — not an intruder or a hung process.** The `secrets_kek_op` lock is held
   > for the ENTIRE `/rotate`/`/rewrap` call, and a large re-wrap (every
   > registered secret row, one query) can legitimately take a long time —
   > holding this lock for 30+ minutes on a big table is EXPECTED, not
   > itself evidence of a wedge. Step 2's `pg_stat_activity` check exists
   > precisely because this gauge and these fields cannot tell "healthy and
   > slow" from "wedged" apart on their own.
   >
   > **Terminating the holder mid-rotation produces exactly the
   > half-committed state this whole feature exists to help you avoid.** If
   > you kill a backend that is genuinely a Yuzu server partway through
   > `/rotate`, the new KEK version it already minted stays active — only
   > the row-by-row re-wrap is interrupted. Recovery is `POST
   > /api/v1/secrets/kek/rewrap` (or the `rewrap_secrets` MCP tool). **Do
   > NOT retry `/rotate`** to "fix" this — see the half-committed contract
   > above; a retried `/rotate` mints a second, spurious KEK version on top
   > of the mess and can never be retired (#2525), it does not undo
   > anything. In other words: the wrong call here does not just fail
   > safely, it creates the exact incident this runbook was written to help
   > you diagnose and avoid.
   >
   > **Before doing anything else, check whether the backend belongs to a
   > Yuzu server, and prefer stopping that server cleanly over killing its
   > backend:**
   > ```sql
   > SELECT pid, application_name, client_addr, client_port, backend_start
   >   FROM pg_stat_activity
   >  WHERE pid = <lock_holder_pid>;
   > ```
   > Match `client_addr`/`client_port` against your known Yuzu server hosts
   > (Yuzu's pooled Postgres connections do not set `application_name`, so
   > expect it blank for the lock holder — do not treat a blank
   > `application_name` as evidence the holder is *not* a Yuzu server; only
   > the `/readyz` probe's own connection is tagged, `yuzu-readyz-probe`). If
   > the pid traces to a live Yuzu server process you can reach, stop that
   > **server** cleanly (its own shutdown path releases the advisory lock
   > through the ordinary `KekOpLockGuard` destructor, the same clean-exit
   > path a completed rotation takes) rather than terminating its Postgres
   > backend out from under it mid-statement.

   If, and only if, step 2 has already shown a genuine wedge (an `idle` /
   `idle in transaction` backend still holding the lock, or a `query_start`/
   `xact_start` implausibly old for any registered-secrets scan) **and**
   the check above could not identify a Yuzu server you can stop cleanly:

   - **Re-confirm the pid is still the granted holder, at the moment you are
     about to act — not from the `/status` reading you captured earlier.**
     `lock_holder_captured_at` tells you how old that reading already is,
     and Postgres reuses backend pids, so a pid that was correct when you
     first read it can now belong to an unrelated connection. Re-run the
     `pg_locks` query from step 1's third case (or `/status` again) and only
     proceed if it still names the same pid:
     ```sql
     SELECT pid FROM pg_locks
      WHERE locktype = 'advisory' AND classid = 2037545589
        AND objid = (hashtext('secrets_kek_op')::bigint & 4294967295)::oid
        AND granted
        AND database = (SELECT oid FROM pg_database WHERE datname = current_database());
     ```
   - Only then does a DBA run `SELECT pg_terminate_backend(<pid>);`
     deliberately — session-scoped advisory locks die with their session, so
     terminating the backend releases the lock. If the target turned out to
     be a Yuzu server after all, be ready to call `/rewrap` afterward — never
     `/rotate`.

**Two more staleness caveats, on top of "these are lock-free snapshots":**
the pid you read can **vanish** (the backend has already exited normally
between your `/status` read and your `pg_stat_activity` query — treat "no
such pid" in step 2 as "already resolved, no action needed", not as an
error) and can be **reused** by an unrelated later connection (Postgres
recycles backend pids). Always corroborate against `pg_stat_activity` in the
same narrow window as the `/status` read that produced the pid — never a pid
captured minutes earlier. `lock_holder_captured_at` (#2530 H1) is what makes
"minutes earlier" checkable instead of assumed: it is the wall-clock instant
the `lock_holder_pid` snapshot was taken, so before acting on a pid you can
see for yourself whether it is fresh or something you should re-read before
trusting.

**Retirement preconditions — and why there is no retire endpoint.** An old
KEK version is only safe to destroy when **both** hold: (1) zero stored
blobs reference it (`GET /status`'s `oldest_in_use` has moved past it), and
(2) no backup you intend to be able to restore still contains rows wrapped
under it — a restored backup needs the KEK version its rows reference, so
you must retain every version referenced by any backup inside your
retention window. That second condition is a policy decision only you can
make; this document will not pick a number for you:

> **Operator decision — set your backup-retention window here:**
> `<SET-ME: e.g. "90 days" / "13 monthly backups" — however long you keep a
> backup you intend to be able to restore>`. Retain every KEK file that
> covers that window. Set this **too short** and a restore from an older
> backup can be permanently undecryptable; set it (or "forever") and you
> simply keep more small key files around — annoying, never unsafe.

Given that, Yuzu deliberately ships **no** retire/decommission route or MCP
tool, even though `SecretCodec::retire_kek` exists internally and is
tested. **#2525 documents a write race that makes exposing it unsafe:**
`SecretCodec::encrypt()` snapshots the active KEK version, releases its
lock, and the *caller* persists the resulting blob afterwards — so a
retirement can pass its "zero references" check and delete the key while an
in-flight write is still about to commit a blob wrapped under exactly that
version, permanently bricking that row. This is not an HA-only hazard; it
reproduces on a single server, and no lock this surface could take would
close it, because ordinary secret writers don't participate in the KEK
operation lock. Advertising a version as "safe to retire" without a safe way
to retire it would be worse than saying nothing.

**Consequence for you: old KEK files accumulate, and that is correct and
safe.** They cost a few dozen bytes each and are exactly what you need to
restore an older backup. **Do not delete a KEK file by hand** — there is no
supported path to determine it's truly safe to remove, and doing so risks
exactly the permanent data loss #2525 describes.

**Audit evidence.** A successful rotation produces **two** audit rows by
design, not a duplicate bug: a system-attributed `kek.rotated` (emitted
inside the codec itself, detail `{"kek_version": <N+1>}`) and an
operator-attributed `kek.rotate` (emitted by the REST route / MCP tool that
invoked it, detail `new_version=<N+1>`). The codec-level event genuinely
cannot know which operator called it — attribution rides the caller's
session, which only the surface that received the request has (ADR-0010,
design review "arch-7") — so an auditor correlating the audit log should
expect the pair, not treat it as a double-count. `rewrap`/`rewrap_secrets`
similarly audits `kek.rewrap` with `rows_rewrapped=<n>`; `GET
/status`/`get_kek_status` is read-only and is not audited (matches the
internal-CA read routes).

Decrypt failures are counted per store and failure class as
`yuzu_server_secret_decrypt_failures_total{store, failure_class}` (classes:
`tag_mismatch`, `kek_unresolvable`, `malformed_blob`, `crypto_failure`).
**This is live as of the auth store's Postgres migration** — the auth store
(`auth.users.mfa_totp_secret`, TOTP secrets) was the first secret-bearing
store to ship; `webhook_store` (`webhooks.secret`, ADR-0057) joined it, so
`store` already has more than one live value and gains a new one with each
further secret-gated migration (`offload_targets`, then the OIDC client
secret). Scope any dashboard/alert to the specific `store` you care about
rather than assuming a single fixed value. A sustained
non-zero `kek_unresolvable` rate after a deployment or restore is the
primary backup-skew alert signal; a single-row `tag_mismatch` is the tamper
signal and warrants investigation, not retry. Ready-made alert rules for
both are in `docs/prometheus/yuzu-alerts.yml` (group `yuzu-secrets`).

**KEK rotation-runaway metrics (#2530).** Sampled every 15s on the same
background thread that recomputes fleet health (`health_recompute_thread_`),
never synchronously inside the `/metrics` handler itself — so a slow or
unreachable database degrades a *stale* gauge value on the next scrape
rather than stalling or failing the scrape during exactly the incident an
operator needs it for. **The sampler's reads run inside an explicit
transaction with a 500ms `SET LOCAL statement_timeout` (#2530 G7-B4)** — not
just a bounded pool acquire — because this is a SERIAL thread shared with
the security-relevant agent-revocation teardown sweep (and joined before
`pg_pool_.reset()` in `stop()`); an unbounded statement here previously
could hold that shared thread for a long multiple of a healthy pass.

| Metric | Type | Meaning |
|---|---|---|
| `yuzu_server_kek_op_lock_held` | gauge | `1` if `secrets_kek_op` currently has a granted holder **in this server's own database** (filtered by `current_database()`, not cluster-wide), else `0`. |
| `yuzu_server_kek_live_versions` | gauge | Count of non-retired KEK versions. Compare against `yuzu_server_kek_max_live_versions`. |
| `yuzu_server_kek_active_version` | gauge | The KEK version new secrets are currently encrypted under. |
| `yuzu_server_kek_max_live_versions` | gauge | The configured `--kek-max-live-versions` ceiling (#2530 G8-S12). Unlike the three gauges above, this is a **static config value set once at boot**, not sampled from Postgres on the 15s sweep — it stays published even when the KEK substrate itself is never reachable. `yuzu_server_kek_live_versions / yuzu_server_kek_max_live_versions` is the ceiling-proximity ratio the `YuzuKekCeilingApproaching` alert (`docs/prometheus/yuzu-alerts.yml`) fires on at 0.8 — because there is no retire route (#2525), this ceiling is a lifetime cap, and without this alert the first signal is a `409 VersionCeiling` at the moment rotation is needed. |
| `yuzu_server_kek_operations_total{op,outcome}` | counter | Rotate/rewrap/status attempts. `op` is one of `rotate`\|`rewrap`\|`status`; `outcome` is one of `success`, `conflict`, `cooldown`, `ceiling`, `query_canceled`, `clock_anomaly`, `half_committed`, `unavailable`, `internal`. Pre-seeded to 0 for every `{op,outcome}` combination at boot, so an outcome that has never fired reads as a true zero, not absent. |
| `yuzu_server_kek_metrics_unavailable_total` | counter | KEK cluster-state reads that could not reach Postgres (pool acquire failure, statement_timeout, or the substrate never being wired up at all) — see "Diagnosing a stuck KEK op lock" and the `YuzuKekMetricsUnavailable` alert. Short-circuits after the first failed read within a sweep (#2530 G8-S2), so this is at most one increment per 15s sweep. |

**`yuzu_server_kek_oldest_version_in_use` was RETIRED from this sampler
(#2530 G7-B4)** — it was the one query here that is an UNBATCHED
full-column scan (`SecretCodec::oldest_kek_version_in_use`), whose scale
ceiling #2530 explicitly deferred as out of scope (see the registered-column
trip-wire test). Running that scan every 15s instead of only on operator
demand made the deferred problem worse, not better, so it was dropped from
the periodic sweep and the gauge was deleted. `GET /status`'s
`oldest_in_use` field is unaffected — it still computes this value on
demand, which is where a full-column scan belongs.

On a database-read degrade during a sampling pass, every gauge above **HOLDS
its prior published value** rather than publishing a fabricated `0` — a
metric nobody could read is absent, never a false "no KEK versions" /
"lock free" reading during exactly the outage you'd want this for — and
`yuzu_server_kek_metrics_unavailable_total` (counter) is bumped instead, so
a sustained increase there is itself the "these KEK gauges are stale" signal
(this now also fires when the KEK substrate itself — `auth_secret_codec_`/
`pg_pool_` — is unavailable, not only on a query-level degrade, #2530
G7-M1). A ready-made alert for a persistently-held op lock, and a second for
a sustained metrics-unavailable rate, are in `docs/prometheus/yuzu-alerts.yml`
(group `yuzu-secrets`) — see "Diagnosing a stuck KEK op lock" above before
acting on the first one.

**`yuzu_server_kek_operations_total`'s `{op,outcome}` accumulator is
published even when the KEK substrate is unavailable (#2530 G7-M1).** An
earlier cut of this pass published it only from inside the same guard that
gates the Postgres-backed gauges above — which is the EXACT condition under
which every KEK operation records `outcome="unavailable"`, so the counter
went dark precisely when the outcome it exists to show was firing. It is a
pure in-process accumulator read (no DB access), so it now publishes
unconditionally on every sampling pass.

#### DR restore-pairing drill

Run this periodically against a scratch environment, alongside the
PostgreSQL restore-verification drill in [Backing up PostgreSQL
state](#backing-up-postgresql-state) above.

This section is the source of truth for the **rotation** side of key
management. The **recovery** side — per-symptom boot triage, the paired
backup commands, and the post-restore verification that catches a
wrong-keys restore before users are locked out — lives in
`docs/ops-runbooks/auth-db-recovery.md`. Read both before running the drill;
they are deliberately not duplicated.

- **CH-1 — restore the database without the keys directory.** Restore a
  `pg_dump` to a scratch database but deliberately withhold (or point
  `--ca-dir` elsewhere from) the paired keys directory, then start the
  server against it. Expect a **loud, correctly-diagnosed** failure, not
  silence: the server fails closed at boot with a `kek_unresolvable` startup
  error (see the failure-class table above), and any MFA-enrolled user
  cannot complete TOTP login (the secret can't be decrypted) — but password
  login and recovery-code MFA fallback still work, because neither needs
  the KEK (see blast radius below). If you instead see a clean boot, the
  drill has failed — investigate before trusting production restores.
- **CH-2 — backup skew.** Restore a `pg_dump` paired with a keys directory
  from a *different* rotation generation than the dump (e.g. the dump is
  from after a rotation the keys directory predates, or vice versa).
  Watch `yuzu_server_secret_decrypt_failures_total{failure_class}` closely:
  a skew like this can produce a **flood** of `kek_unresolvable` events that
  buries a genuine, low-volume `tag_mismatch` (tamper) signal in the same
  window — alert on the *sustained rate*, not a raw count, and don't
  dismiss a skew incident just because most of the flagged rows turn out to
  be the benign skew case.
- **Quantified blast radius of KEK loss** (permanent, no paired backup
  exists to recover from): every TOTP-enrolled operator loses their TOTP
  secret and must re-enroll — but they are **not locked out**, because MFA
  recovery codes are PBKDF2 verify-only hashes that need no KEK to redeem
  (this is precisely why KEK loss is not a total lockout); sign in with a
  recovery code, then re-enroll TOTP. Password login is entirely unaffected
  (session tokens and password hashes are not KEK-wrapped). Any future
  secret class gated behind the same codec (webhook signing secrets,
  offload-target credentials, the OIDC client secret, once each store
  migrates) would need re-issuing and its downstream reconfigured — there
  is no way to recover the old value.

**Break-glass (KEK permanently lost).** KEK loss is painful, never a total lockout: admin sign-in survives by design (MFA recovery codes are verify-only hashes and need no KEK — sign in with a recovery code and re-enroll TOTP), and every gated secret class is re-enrollable/re-issuable (webhook secrets re-issued, offload credentials re-issued, OIDC client secret re-pasted). The explicit voided-secrets boot flag described in ADR-0010 ships with the first secret-bearing store migration.

---

## NVD CVE sync

The server maintains a local mirror of the NVD (National Vulnerability Database) CVE
catalog, used by the fleet-topology vulnerability overlay. On first boot it runs a
newest-first **backfill** of the full catalog, then switches to periodic freshness
re-checks. Configuration is via CLI flags at startup (each has an env-var equivalent).

| CLI Flag | Env | Default | Description |
|---|---|---|---|
| `--nvd-api-key` | `YUZU_NVD_API_KEY` | *(none)* | NVD API key. Raises the NVD rate limit substantially — the difference between the initial backfill taking minutes versus hours. |
| `--nvd-proxy` | `YUZU_NVD_PROXY` | *(none)* | HTTP proxy URL for egress to `services.nvd.nist.gov`, for deployments with restricted outbound network access. |
| `--nvd-sync-interval` | `YUZU_NVD_SYNC_INTERVAL` | `4` | Freshness re-check cadence, in hours, once the backfill has completed. |
| `--nvd-backfill-years` | `YUZU_NVD_BACKFILL_YEARS` | `8` | How far back (in years) the newest-first backfill walks. `0` = full history. The floor is clamped to NVD's catalog start (1999-01-01) and to a 200-year effective maximum, so no value reaches before the catalog begins. |
| `--no-nvd-sync` | `YUZU_NO_NVD_SYNC` | off | Disable NVD sync entirely. |

> **Note:** the initial backfill makes sustained HTTPS requests to `services.nvd.nist.gov`
> and grows the local NVD database to hundreds of MB. Without an API key it can take hours.
> The backfill is resumable — after a restart it resumes from where it left off rather than
> starting over. Sync progress is observable via `GET /api/nvd/status`
> (`backfill_complete`, `backfill_oldest_published`, `total_cves`).

**Rate-limit and auth-error handling:** HTTP 429 responses are backed off automatically (honouring `Retry-After`, else exponential to a 30-minute cap) and the same page is retried — expect `NVD HTTP 429 … backing off` warnings during a large backfill without an API key; this is expected, not a failure. HTTP 403 means a bad or revoked `--nvd-api-key`: it is logged distinctly and NOT retried — check/rotate the key. Both surface via `yuzu_nvd_sync_failures_total{reason=...}` (see the [metrics reference](metrics.md#nvd-cve-sync-metrics)).

---

## Retention Settings

The server applies retention policies to stored data to manage disk usage. Retention values are set via CLI flags at startup.

| Data Type | CLI Flag | Default TTL | Description |
|---|---|---|---|
| Instruction responses | `--response-retention-days` | 90 days | Results from executed instructions. Older responses are purged on a daily schedule. |
| Audit log entries | `--audit-retention-days` | 365 days | Records of who did what, when, and on which devices. |
| Guardian (Guaranteed State) events | `--guardian-event-retention-days` | 30 days | Guaranteed State drift events, remediation events, and agent-sync events written by the Guardian engine. See [Guaranteed State](guaranteed-state.md) for the feature context. |

Increasing a TTL preserves more history for compliance. **Reducing one does not
reclaim disk retroactively** -- and that is true of all three stores, not just
the audit log. Each stamps `ttl_expires_at` once, at INSERT, from the retention
setting in force at the time (`AuditStore::log`, `ResponseStore::store`,
`GuaranteedStateStore::compute_ttl_epoch`), and nothing ever rewrites it, so
existing rows always age out on their original TTLs. Only rows written after the
change (and, per the #483 note below, after a restart) get the shorter window.

What is specific to the audit log is *how* the expired rows then leave: see the
note below.

> **Audit retention is a floor, not a ceiling.** A cleanup pass declines once
> when it would expire every datable row, and every accepted pass is capped at
> 25,000 rows, so deletion is paced rather than immediate.
>
> One side effect of the shared insert-stamped-TTL scheme is specific to this
> guard and worth knowing: the guard's "is any datable row still alive?"
> horizon is derived from the CURRENT window, so after a reduction the older
> long-TTL rows fall outside it and stop counting as survivors. That makes a
> single declined pass more likely right after the change. It is self-healing --
> see [The retention clock guard](audit-log.md#the-retention-clock-guard).

> **Note:** All three retention values can also be set via environment variables (`YUZU_RESPONSE_RETENTION_DAYS`, `YUZU_AUDIT_RETENTION_DAYS`, `YUZU_GUARDIAN_EVENT_RETENTION_DAYS`) and can be updated at runtime via `PUT /api/config/<key>` with an `Infrastructure:Write` permission. Runtime updates are persisted via `RuntimeConfigStore` and reflected immediately in the `/api/config` GET response — **but the running store captures its retention value at construction time and does not re-read it, so TTL computation on new inserts continues to use the startup value until the next server restart.** This "takes effect on restart" limitation is shared across all three retention keys and is tracked as issue #483.

---

## Settings API Reference

All Settings page operations are backed by REST API routes. These can be called directly for automation.

### Authentication

All API routes require a valid session cookie (obtained via `POST /login`) or, when available, a bearer token. Admin-role sessions are required for all write operations.

### TLS

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/tls` | Render the TLS configuration fragment (HTMX). |
| `POST` | `/api/settings/tls` | Update TLS settings (enable/disable, port). |
| `POST` | `/api/settings/cert-upload` | Upload PEM certificate and key files (multipart form). |
| `POST` | `/api/settings/cert-paste` | Paste PEM certificate content (form-encoded). |

### OIDC / Directory

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/directory` | Render the OIDC/Directory configuration fragment (HTMX). |
| `POST` | `/api/settings/oidc` | Save OIDC/Entra ID configuration (form-encoded). Persisted to runtime config. |
| `POST` | `/api/settings/oidc/test` | Test OIDC discovery endpoint connectivity. |

### Users

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/users` | Render the user management fragment (HTMX). |
| `POST` | `/api/settings/users` | Create a new user. Body: `{ "username", "password", "role" }`. |
| `DELETE` | `/api/settings/users/{username}` | Delete a user by username. |

### Enrollment Tokens

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/tokens` | Render the enrollment tokens fragment (HTMX). |
| `POST` | `/api/settings/enrollment-tokens` | Generate a new enrollment token. Body: `{ "expiry", "max_uses" }`. |
| `POST` | `/api/settings/enrollment-tokens/batch` | Generate multiple tokens in one call. Body: `{ "label", "count", "max_uses", "ttl_hours" }`. |
| `DELETE` | `/api/settings/enrollment-tokens/{id}` | Revoke a token by ID. |

### Pending Agents

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/pending` | Render the pending agents fragment (HTMX). |
| `POST` | `/api/settings/pending-agents/{id}/approve` | Approve a pending agent. |
| `POST` | `/api/settings/pending-agents/{id}/deny` | Deny a pending agent. |
| `DELETE` | `/api/settings/pending-agents/{id}` | Remove a pending agent from the queue. |

### Auto-Approval Policies

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/auto-approve` | Render the auto-approval policies fragment (HTMX). |
| `POST` | `/api/settings/auto-approve` | Create a new auto-approval rule. |
| `POST` | `/api/settings/auto-approve/mode` | Set the auto-approval mode (manual, policy-based). |
| `POST` | `/api/settings/auto-approve/{index}/toggle` | Toggle an auto-approval rule on or off. |
| `DELETE` | `/api/settings/auto-approve/{index}` | Delete an auto-approval rule. |

### API Tokens

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/api-tokens` | Render the API tokens management fragment (HTMX). |
| `POST` | `/api/settings/api-tokens` | Create a new API bearer token. Body: `{ "name", "role", "scopes" }`. |
| `DELETE` | `/api/settings/api-tokens/{id}` | Revoke an API token by ID. |

### OTA Updates

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/updates` | Render the OTA updates fragment (HTMX). |
| `POST` | `/api/settings/updates/upload` | Upload an agent binary (multipart form). Parts: `file` (the binary, required), `signature` (an optional detached PEM CMS signature, ≤64 KB), `platform`, `arch`, `rollout_pct`, `mandatory`. Returns **400** if the signature is not a PEM CMS block, and **500** if the signature could not be stored, the binary could not be written, or the binary could not be published. **Treat any non-2xx as "retry", never as "uploaded".** How much changed depends on where it failed: a **400**, or a **500 storing the signature**, changes nothing at all. A **500 writing or publishing the binary** leaves the previous binary in place, and — on a *signed* upload — the *new* signature already stored beside it, so agents refuse that package until you retry successfully. The upload order guarantees only that a failure never leaves the served binary UNPROTECTED; it does not guarantee the pair is consistent. After a 500 on a **signed** upload, check the **Signed** column: **signature mismatch** is the expected state, and re-uploading clears it. An unsigned upload that fails on the binary changes nothing, so the column is unchanged. Omitting `signature` on a re-upload **removes** any existing signature for that package. |
| `DELETE` | `/api/settings/updates/{platform}/{arch}/{version}` | Delete an uploaded agent binary **and its signature sidecar**. |
| `POST` | `/api/settings/updates/{platform}/{arch}/{version}/rollout` | Promote a version to production rollout. |

### Tag Compliance

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/tag-compliance` | Render the tag compliance summary fragment (HTMX). |
| `GET` | `/api/v1/tag-compliance` | Tag compliance summary (JSON, via REST API v1). |

### DEX Alerts

| Method | Route | Description |
|---|---|---|
| `GET` | `/fragments/settings/dex-alerts` | Render the DEX alerts configuration fragment (HTMX). Admin-only. |
| `POST` | `/api/settings/dex-alerts/routing` | Update the routed signal types. Body: form-encoded `types=<obs_type>` repeated per checked type; values are allow-listed against the signal catalogue. Persisted to `runtime_config` key `dex_alert_routing` (sorted JSON array). Applied live. Audit: `settings.dex_alerts.routing` (detail records the full routed set). |
| `POST` | `/api/settings/dex-alerts/blast` | Update the blast-radius thresholds. Body: `min_devices`, `window_seconds`, `cooldown_seconds` (clamped server-side to `[2,100000]` / `[60,86400]` / `[0,604800]`). Persisted to the `dex_blast_*` keys. Applied live. Audit: `settings.dex_alerts.blast`. |
| `POST` | `/api/settings/dex-alerts/cohort-export` | Set (or clear) the cohort metrics export tag key. Body: `export_key` (tag-key alphabet `[A-Za-z0-9_.:-]`, max 64; empty disables — the default). When set, the per-cohort `yuzu_fleet_perf_cohort_*` Prometheus gauges are published for that key's cohorts (top 50 by population, 10-device floor, `yuzu_fleet_perf_cohort_clipped` makes capping visible). Persisted to `dex_cohort_export_key`. Applied on the next gauge sweep. Audit: `settings.dex_alerts.cohort_export`. |

**New `runtime_config` keys.** All are runtime-set via the DEX Alerts panel and applied live (and re-applied at boot):

| Key | Type | Default | Description |
|---|---|---|---|
| `dex_alert_routing` | JSON array string | `[]` | DEX `obs_type` strings routed to operator notifications + the `dex.signal` webhook. Empty = nothing routed. |
| `dex_blast_min_devices` | integer string | `5` | Blast-radius minimum distinct-device threshold. Clamped `[2, 100000]`. |
| `dex_blast_window_seconds` | integer string | `900` | Blast-radius detection window (seconds). Clamped `[60, 86400]`. |
| `dex_blast_cooldown_seconds` | integer string | `3600` | Blast-radius per-incident re-alert cooldown (seconds). Clamped `[0, 604800]`. |
| `dex_cohort_export_key` | tag-key string | *(empty)* | Tag key whose cohorts export as `yuzu_fleet_perf_cohort_*` Prometheus gauges. Empty = export disabled. Invalid stored values disable the export (fail closed). |

**New audit actions.**

| Action | Emitted when |
|---|---|
| `settings.dex_alerts.routing` | An admin changes the routed signal-type list. Detail records the full new routed set (the runtime-config store keeps no history, so this row is the change-management evidence). |
| `settings.dex_alerts.blast` | An admin changes the blast-radius thresholds (detail records the new min/window/cooldown). |
| `settings.dex_alerts.cohort_export` | An admin sets or clears the cohort metrics export tag key (detail records the new key, or "export disabled"). |
| `dex.device.perf.query` | An operator loads a device performance sparkline panel (DEX device drill-down). Execute-gated; detail records the target agent and command id. |
| `dex.device.procperf.query` | An operator loads a device's per-application panel (usage-class telemetry — deliberately a separate verb from the machine-health `dex.device.perf.query` so usage reads stay separately countable). Execute-gated; detail records the target agent and command id. |

---

## Agent OTA pull bounds

Runbook for the `yuzu-ota` alert group. The agent OTA path (`DownloadUpdate`) is
bounded on four axes: a per-peer concurrency semaphore, a per-peer token bucket, a
server-wide transfer ceiling, and two deadlines.

**Admission keying, and why it matters operationally.** A peer is bucketed by its
certificate identity where it presents one, and by **source IP** where it does not.
Check `yuzu_ota_admission_key_mode_total` to see which mode your fleet is in. The
IP fallback has two consequences worth planning for:

- **Every certless agent behind one NAT egress shares one bucket** — one
  concurrency allowance and one token stream for the whole site. Enrolling agents
  with client certificates gives each its own.
- The per-peer bound therefore scales with a caller's address space, which is why
  `--ota-max-concurrent-total` exists as a flat ceiling.

**Metrics to watch, and what each one means.** These are the raw signals; the
`yuzu-ota` alert group in `docs/prometheus/yuzu-alerts.yml` pages on them, and
each alert's own annotations record what its threshold was chosen against and
where it is known to be blind. Chart these directly if you want to set thresholds
of your own — the shipped ones are reasoned starting points, not fleet-validated
numbers.

| Metric | What a rising value means | First action |
|---|---|---|
| `yuzu_ota_download_admission_total{decision="rejected_concurrency"}` | A peer is repeatedly refused for holding too many parallel transfers. | Find the peer in the server log — the rejection line carries `key=` and `mode=`. **That line is sampled 1-in-100** (the first always logs, then every hundredth, on a counter shared with the server-wide rejections), so a short burst may leave one line or none; the counter is the complete record. There is deliberately no audit row for admission rejections. |
| `yuzu_ota_download_admission_total{decision="rejected_total"}` | The server-wide ceiling is saturated, so agents are refused regardless of their own per-peer budget. | Two very different causes look identical here; the rejection log's `cert_keyed=` field separates them — but that line is sampled 1-in-100, so correlate with `yuzu_ota_admission_key_mode_total` when the log is thin. All-`true` means a genuine rollout wants more concurrency: raise `--ota-max-concurrent-total`, sizing roughly as `devices x transfer_seconds / rollout_seconds`. `false` concentrated on a few addresses is a denial attempt against the shared ceiling, which `--ota-cert-reserve-pct` exists to bound. |
| `yuzu_grpc_ota_identity_rejected_total{reason}` | A peer presented no usable certificate, one from a foreign CA, or an `agent_id` that does not match it. | Check the `reason` label first — this counter is complete. Then the `session.ota_identity_rejected` audit rows for attribution, bearing in mind **two** reasons they under-count: `no_client_identity` is metric-only and writes none, and the row is rate-limited to ~2/s per (peer, RPC, reason). `yuzu_ota_identity_audit_suppressed_total` counts what was dropped. Never read row volume as rejection volume. |
| `yuzu_ota_download_deadline_exceeded_total{phase}` | Transfers are hitting a deadline. **This is the silent-outage signal**: every aborted transfer refunds its rate token, so no bucket drains and every other dashboard stays green while the fleet stops updating. | Check the `phase` label. `transfer` usually means `--ota-transfer-deadline-secs` is below `artifact_size / link_throughput` for that fleet — raise it. Watch it as a PROPORTION of `{decision="admitted"}`, not as a count: agents check every 6 hours, so a small fleet failing completely produces a low absolute rate. |
| `yuzu_ota_download_peers_evicted_total` | `--ota-max-peers-tracked` is at or below the live key count, which silently disables the rate dimension — an evicted key is re-minted with a full burst. | Raise it above your expected distinct-key count. |
| `yuzu_ota_download_peers_tracked / yuzu_ota_download_peers_capacity` | The admission map is approaching its ceiling. | Same action. Note the map never shrinks in-process, so this stays high until restart. |
| `yuzu_ota_download_refund_total` vs `yuzu_ota_download_deadline_exceeded_total` | Deadline aborts outrunning refunds is a regression in the refund wiring, not a tuning problem. | Check the deadline branches in `agent_service_impl.cpp`. |

**Alert responses.**

| Alert | What it means | First action |
|---|---|---|
| `YuzuOtaConcurrencyRejections` | A peer is repeatedly refused for holding too many parallel transfers. | Find the peer in the server log — the rejection line carries `key=` and `mode=`. **That line is sampled 1-in-100** (the first always logs, then every hundredth, on a counter shared with the server-wide rejections), so a short burst may leave one line or none; the counter is the complete record and the log is for attribution only. There is deliberately no audit row for admission rejections. |
| `YuzuOtaServerCapacityRejections` | The server-wide ceiling is saturated, so agents are refused regardless of their own per-peer budget. | Two very different causes look identical in the metric. The rejection log's `cert_keyed=` field is the discriminator — but **read it carefully: `cert_keyed` means "presented a certificate this listener accepted", not "is an enrolled Yuzu agent"** (see #3828). On a multi-CA trust bundle a peer holding a certificate from any other CA in that bundle also reads as `cert_keyed=true`, so it does not by itself distinguish a rollout from an attack. That line is also sampled 1-in-100, so correlate with `yuzu_ota_admission_key_mode_total` when it is thin. All-`true` on an enrolled-only trust root means a genuine rollout wants more concurrency: raise `--ota-max-concurrent-total`, sizing roughly as `devices x transfer_seconds / rollout_seconds`. `false` concentrated on a few addresses is a denial attempt against the shared ceiling, which `--ota-cert-reserve-pct` exists to bound. |
| `YuzuOtaIdentityRejections` | A peer presented no usable certificate, one from a foreign CA, or an `agent_id` that does not match it. | Check the `reason` label first — this counter is complete. Then the `session.ota_identity_rejected` audit rows for attribution, bearing in mind **two** reasons they under-count: `no_client_identity` is metric-only and writes none, and the row is rate-limited to ~2/s per (peer, RPC, reason). `yuzu_ota_identity_audit_suppressed_total` counts what was dropped. Never read row volume as rejection volume. |
| `YuzuOtaTransfersAborting` | Transfers are hitting a deadline. **This is the silent-outage detector**: every aborted transfer refunds its rate token, so no bucket drains and every other dashboard stays green while the fleet stops updating. | Check the `phase` label. `transfer` usually means `--ota-transfer-deadline-secs` is below `artifact_size / link_throughput` for that fleet — raise it. The rule fires on a PROPORTION of transfers aborting, not a count, because agents check only every six hours and any fixed count goes blind below some fleet size. Its own annotation records the residual blind spot: a fleet where under ~10% of devices fail permanently sits below the bar. |
| `YuzuOtaPeerMapEvicting` | `--ota-max-peers-tracked` is at or below the live key count, which silently disables the rate dimension — an evicted key is re-minted with a full burst. | Raise it above your expected distinct-key count. Note the floor: values below 1024 are raised at startup, so the effective ceiling may not be what you set. |
| `YuzuOtaPeerMapNearCapacity` | The admission map is above 80% of its ceiling. | Same action. The map never shrinks in-process, so this stays firing until restart. |
| `YuzuOtaRefundDivergence` | Deadline aborts are outrunning refunds — a regression in the refund wiring, not a tuning problem. | Check the deadline branches in `agent_service_impl.cpp`. The rule detects a dropped call site, not a refund that fails inside `PrincipalQuota::refund`. |

**Known limitation — keep OTA artifacts on local storage.** The per-chunk read of
the update binary is blocking and cannot be interrupted; the transfer watchdog
cancels the RPC but cannot unpark a thread waiting on the kernel. If the artifact
lives on a network mount that stalls, the handler never returns, and the peer whose
pull wedged holds one of its concurrency slots until the server restarts — so that
peer is refused `RESOURCE_EXHAUSTED` on every later pull. At
`--ota-max-concurrent-per-peer=1` that is permanent for that peer. The blast radius
is bounded to that peer and to one share of `--ota-max-concurrent-total`, but there
is no in-process recovery.

**Known limitation — per-process, not fleet-wide.** All of these bounds live in one
server process's memory. Behind a load balancer with N replicas the effective
ceiling is `configured_cap x N`, and a peer that reconnects to a different replica
gets a fresh allowance.

## File Logging

Yuzu writes logs to stdout by default. File logging is opt-in via `--log-file`, with a best-effort fallback at the platform default path (`/var/log/yuzu/server.log` on Linux, `C:\ProgramData\Yuzu\logs\server.log` on Windows, `~/Library/Logs/Yuzu/server.log` on macOS).

| Path | Behaviour | Failure mode |
|---|---|---|
| `--log-file <path>` (explicit) | Writes to `<path>` in addition to stdout. | If the file/directory cannot be opened, server logs an ERROR and continues without file logging. |
| Platform default path (implicit) | Writes to the platform default path if it exists and is writable. | If the directory cannot be created or the file cannot be opened, server logs a single INFO line and continues without file logging. The default fallback is best-effort observability, not load-bearing. |

The Docker server image pre-creates `/var/log/yuzu` (mode 0750, owned by the `yuzu` user) so the implicit default path works out of the box. When mounting an external host volume at `/var/log/yuzu`, ensure the host directory is owned by the same UID as the in-container `yuzu` user (verify with `docker exec yuzu-server id yuzu`); a wrong-ownership mount silently degrades to stdout-only logging.

## Health Endpoints

Yuzu exposes four HTTP probe endpoints for orchestrators, load balancers, and monitoring integrations. All four are unauthenticated and exempt from the API rate limiter.

| Path | Use case | Body | Draining-aware |
|---|---|---|---|
| `/livez` | Kubernetes liveness probe — fast check that the HTTP listener is up. | `{"status":"ok"}` | No |
| `/readyz` | Readiness probe for load balancers and orchestrators — "stop routing to me". Covers **runtime Postgres reachability** (the `pg_reachable` row), per-store migration completion at startup, AND graceful-shutdown drain. | `{"status":"ready"}` (200), `{"status":"draining"}` (503), or `{"status":"not ready","failed_stores":["pg_reachable", ...],"pg":"unreachable"}` (503). `pg` appears only when `pg_reachable` fails and names the reason: `unreachable`, `stale`, `read_only` (connected to a standby), or `not_yet_probed`. A non-critical store that's on but degraded (currently: `analytics_event_store`, ADR-0049, and the NVD CVE cache `nvd_db`, whose failure leaves vulnerability matching empty) is reported via a non-gating `"degraded":[...]` array alongside either `status` value, rather than flipping the node to not-ready. | **Yes** |
| `/health` | Monitoring dashboards (Prometheus blackbox exporter, Datadog, Nagios). Rich JSON with per-store status, agent counts, execution stats, and version. | Structured JSON — see [REST API: Health](rest-api.md#health). | No |
| `/api/health` | Identical alias of `/health`, provided for monitoring integrations that prefix every REST call with `/api/`. Restored in v0.12.0 (issue #620). | Identical to `/health`. | No |

**Choose the right endpoint for your use case.** Load balancers that should drain in-flight traffic during a rolling deploy MUST use `/readyz` — `/health` and `/api/health` continue returning 200 during shutdown by design (Kubernetes pattern: liveness/health probes are not draining-aware). Aggressive monitoring poll cadences (sub-second) should target `/livez` rather than `/health` to minimise per-probe SQLite touches. Point an orchestrator's **liveness** probe at `/livez`, never `/readyz`: a database outage turns `/readyz` red on every replica, and restarting them all fixes nothing.

### What `/readyz` checks (HA WS-8)

- **`pg_reachable` — the runtime signal.** Each replica runs a small probe on its **own dedicated Postgres connection** (not the pool, tagged `application_name=yuzu-readyz-probe` unless your DSN sets one) every 2 s: `SELECT pg_is_in_recovery() OR current_setting('transaction_read_only')::boolean`, with client-side deadlines of 2 s per query and, to connect, at most 5 s for a single host (less when `connect_timeout` is shorter; a host list: the pool's own `connect_timeout` per host — see below). `/readyz` reports not ready after **two consecutive failed probes** (`unreachable`), **at once** if the probe reached a server that refuses writes (`read_only` — a standby, or a primary with `default_transaction_read_only` on, which some managed Postgres services set when the disk fills; the server writes to Postgres on nearly every request, so it cannot serve there), or when no probe has succeeded for **15 s** (`stale`). One successful probe makes it ready again; your load balancer's own healthy/unhealthy thresholds add any hysteresis you want. Measured end to end: a stopped database turns `/readyz` red in about 3 s, a frozen one (`docker pause`, a black-holed host) in about 11 s, a read-only primary in about 2 s, and recovery takes about 2 s (`scripts/ha/ha-readyz-scenarios.sh`). The body never carries host names, DSNs or error text — the libpq detail goes to the server log as a `[readyz] Postgres not reachable ...` line, written when a completed probe changes the answer and repeated every 60 s while not ready (a probe stuck outside its deadlines, which is what `stale` means, logs when it completes).
- **Multi-host DSNs need `target_session_attrs=read-write`, and the server enforces it.** Without it, libpq — and so the server's pool — takes the *first host that accepts a connection, even a standby*, and writes fail on connections nothing can see. So when `--postgres-dsn` lists several hosts (or the server's environment supplies a `PGHOST`/`PGHOSTADDR` list) and there is no `target_session_attrs`, the server adds `target_session_attrs=read-write` and logs a warning at startup; it rebuilds the DSN from libpq's own parse (the same settings, in keyword form) and checks it option by option rather than editing your text. `primary` is accepted as well; any other explicit value (`any`, `read-only`, `standby`, `prefer-standby`) makes the server **refuse to start** — the message names the value only when it is one of libpq's own, never the DSN. `load_balance_hosts` (other than `disable`, in the DSN or `PGLOADBALANCEHOSTS`) also makes the server refuse to start: with read-write only the primary is acceptable, so shuffling balances nothing, and `/readyz` — one held connection — could not see a host that fails only some of the pool's shuffled connections. An empty DSN is left empty, so the server still refuses to start without one. A `service=` entry or `PGSERVICE` is applied by libpq only when it connects, so the server also checks the settings libpq resolved on its first connection at startup and refuses to start (`Invalid Postgres connection settings: ...`) if they set `load_balance_hosts` or list several hosts without `target_session_attrs=read-write` (or `primary`) — set it in the service file. libpq re-reads the service file on every new connection; the readiness probe repeats the check each time *it* connects, but it keeps a healthy connection open, so a later edit that breaks these rules shows on `/readyz` (red, with the reason in the `[readyz]` log line) only at the probe's next reconnect, while new pool connections already use it — **restart the server after editing the service file**. Not visible to either check — set `target_session_attrs=read-write` yourself: one host *name* that resolves to several servers (DNS round-robin, a Kubernetes headless service). List the Postgres servers themselves, not a pooler per node: a pooler such as pgbouncer can keep reporting a demoted node as writable to libpq.
- **How the probe walks a host list.** libpq walks it for the probe exactly as for the pool — in the DSN's order; it moves on after a refused or failed connect, "cannot connect now" (57P03) or a read-only host, and ends the attempt on anything else (a failed login, too many clients, a missing database, a peer that hangs up), because the pool's connections end there too. The probe connects with exactly the pool's connection settings (the same DSN, environment and default `connect_timeout` of 10 s) and adds one thing: each host address in the list gets its own deadline — the `connect_timeout` in force, timed the way the pool's own connect times it (in whole seconds before libpq 17) — so a frozen host costs one `connect_timeout` instead of holding the probe (a single host is capped at 5 s, so a frozen primary still reads red in about 11 s) (libpq's non-blocking connect never moves past a silent host by itself). That works for a `PGHOST` or `service=` list as well. When the probe's held connection fails and it has to reconnect past a silent host, that reconnect can outlast the 15 s staleness limit (about 1 s over with the default 10 s `connect_timeout`), so `/readyz` briefly reads `stale` — as slow as the pool's own new connections are at that moment. With `connect_timeout=0` (wait for ever) the pool never moves past a silent host, so neither does the probe: it reports `unreachable` instead. One gap: when one *address* of a host name with several addresses is silent, the probe gives up that name's other addresses too, where the pool would try them — `/readyz` can then disagree with the pool either way; list the addresses as separate hosts to avoid it. With `target_session_attrs=read-write`, libpq itself refuses a host that is read-only, so a cluster with no writable host reads `unreachable` rather than `read_only` (the server log says why).
- **What `/readyz` does not see: the pool's existing connections.** The probe holds one connection of its own, re-checks it every 2 s, and reconnects — walking the host list as a new pool connection does — only when that check fails; it answers "can this replica reach a writable primary", not "is every pooled connection healthy". Precisely: `pg_reachable` is red when the probe's most recent connect — made with the pool's own settings — could not establish a session to a server that accepts writes, or when the probe's own session stops answering or turns read-only. Because it keeps a healthy session open, it does not observe the pool's other held connections, nor anything that changed since it last connected. Known gaps: pooled connections to a server demoted in place (below; #4942); anything that changes whether a *new* connection would succeed — a service-file or environment edit, a password rotation or expiry, a `pg_hba.conf` or certificate change — which shows only at the probe's next reconnect (#4956), so restart or re-check after such a change; a host name with several addresses, one of them silent (#4954); `max_connections` exhaustion, where the probe is the connection refused first (#4943); and timing — about ±1 s from the pool's own connect, and a single host capped at 5 s (it can read red while a slower pool connect succeeds, never green). The pool does not re-check the connections it already holds, and never retires them by age, so a connection whose server turns read-only *in place* keeps failing writes until that connection breaks. If that server is the one a new connection reaches, `/readyz` goes red as well; it stays green only when a new connection reaches a different, writable host. Connecting to Postgres directly, a real demotion restarts the old primary and breaks those connections; the gap needs a server that flips read-only while staying up (for example `default_transaction_read_only` set on a running primary), or a pooler in between that keeps its server connections across the demotion.
- **Point the DSN at the primary.** A proxy that load-balances plain `SELECT`s across replicas (pgpool-II `load_balance_mode`, a read-any port) can send the probe's query to a standby and report `read_only` while writes still reach the primary. Use the proxy's read-write endpoint.
- **During a Postgres failover every replica goes red at once**, for roughly the failover time (Patroni: 10–30 s). That is correct — nothing can serve writes until the new primary is up. Many load balancers fail open when every backend is unhealthy and keep forwarding. What the forwarded requests then see depends on the outage: against a stopped or refusing database they fail fast with `503`; against a *frozen* one (a paused VM, a black-holed host) queries on already-open pooled connections can hang for up to ~100 s before failing, so expect slow errors rather than quick ones until the failover completes.
- **Two different causes can both read `/readyz` unreachable, and only the server log tells them apart.** A `max_connections` exhaustion (#4943 — every ordinary slot held by other clients) and a genuine overload (#4944, below) both collapse to the same `pg_reachable=unreachable` verdict and the same alert. Check the `[readyz] Postgres not reachable ...` log line: `remaining connection slots are reserved for roles with privileges of the "pg_use_reserved_connections" role` names the #4943 case specifically (lower `max_connections` pressure from other clients, or verify the reserve per the formula above); anything else reading `unreachable` — a timeout, a refused connection with no such text — points at #4944 or a genuine outage instead.
- **A sustained overload also reds every replica together, and that is deliberate (#4944).** If the probe's one-row, no-table `SELECT` misses its 2 s deadline twice in a row, the database cannot answer real requests within their deadlines either (nearly every request validates a session and writes an audit row), so the replica is truthfully unable to serve — and, from the client side, a hopelessly slow backend and a frozen one look the same. There is **no server-side hysteresis** by decision: the rule stays two failures to go red, one success to recover, and your load balancer's thresholds are the damping — see "Load balancers and shutdown drain" below for the recommended values. A *brief* stall never evicts: one failed probe is a blip (`scripts/ha/ha-readyz-scenarios.sh`, scenario M holds a 3 s pause green; scenario L shows a CPU-starved database going red and recovering within one probe of the limit being lifted).
- **The store rows are startup checks.** Every other row (`response_store`, `session_store`, ...) reports whether that store opened and migrated when the server started. They do not re-check a running store — a runtime problem with one store (a revoked grant, a dropped table) shows up as `503`s on that store's routes and in metrics, not on `/readyz`, because every replica shares the same database and moving traffic elsewhere would not help.
- **Leadership is not readiness.** A replica that is not the background-work leader is fully ready.

### Load balancers and shutdown drain

On `SIGTERM` the server sets `/readyz` to `503 {"status":"draining"}` and then keeps serving every other route for at least **`--shutdown-drain-seconds`** (env `YUZU_SHUTDOWN_DRAIN_SECONDS`, default **0**, range 0–60) before it closes its listener, and for as long as executions are still running (up to 30 s). It logs a countdown every 10 s. The two background roll-ups (app-perf and the software catalogue) do not start new work once draining begins. With the default of 0 and nothing running, the listener closes straight away — fine for a single server, but a load balancer in front of several replicas would then find out from refused connections.

For any deployment behind a load balancer:

1. Set `--shutdown-drain-seconds` to at least the load balancer's **health-check interval × unhealthy threshold, plus one interval** (e.g. 5 s interval × 2 failures + 5 s = 15 s).
1. **Set the health-check thresholds to `interval 5 s`, `unhealthy_threshold 2`, `healthy_threshold 3`** (the names vary: HAProxy `inter 5s fall 2 rise 3`, Kubernetes `periodSeconds: 5`, `failureThreshold: 2`, `successThreshold: 3`, AWS target groups the same three fields). Eviction then needs ≥ 10 s continuously red, so a single database stall never evicts a replica; re-admission needs ≥ 15 s continuously green, so a database hovering at the edge of its capacity does not pull every replica in and out every few seconds — which drops held-open SSE/MCP streams, and their reconnects are what turns a slow database into a slower one. `/readyz` itself adds no hysteresis (#4944): two failed probes red it, one success greens it.
1. **Know what your load balancer does when every backend is unhealthy.** During a Postgres failover or a sustained overload every replica is red at once (above). An AWS ALB/NLB and nginx `upstream` route to all backends anyway (fail open) — requests then fail fast or slowly depending on the outage; a Kubernetes `Service` removes every endpoint and HAProxy answers `503` (fail closed) — an outage of the API plane for the duration. Neither is wrong; make sure the choice is yours.
2. **Raise the orchestrator's stop timeout by the same N.** The drain grace comes *before* the rest of the shutdown, which is unchanged, so it adds to it: the shipped compose `stop_grace_period` and systemd `TimeoutStopSec` of **210 s** become **210 + N**. Kubernetes' default `terminationGracePeriodSeconds` of 30 s is far too short in any case (see `docs/user-manual/upgrading.md`, the stacked-shutdown section).
3. Health-check `/readyz`, not `/health`.

A second `SIGTERM` still exits immediately.

## Deployment

Yuzu provides multiple deployment options: Docker Compose for quick setup, systemd units for bare-metal Linux, and a development stack script for local testing.

### Docker Compose

The default Docker deployment runs the server and agent standalone -- no gateway required. For scaled deployments with a gateway, see `docker-compose.full-uat.yml`.

**Files:**

| File | Description |
|---|---|
| `deploy/docker/Dockerfile.server` | Multi-stage build for the Yuzu server binary |
| `deploy/docker/Dockerfile.gateway` | Erlang/OTP build for the gateway node |
| `deploy/docker/docker-compose.yml` | Build-from-source dev stack (server + agent + monitoring) |
| `deploy/docker/docker-compose.reference.yml` | Copyable deployment template — pulls pinned ghcr.io images, uses a named `server-data` volume, carries inline TLS hardening + backup + rollback commentary. Requires operator hardening (TLS, bind address) before production use. |
| `deploy/docker/docker-compose.full-uat.yml` | Gateway deployment (server + gateway + monitoring) |
| `docker-compose.uat.yml` | Self-contained single-file UAT stack pulled from ghcr.io (server + gateway + Prometheus + Grafana + ClickHouse) |
| `deploy/docker/docker-compose.demo.yml` | Chiselled (FROM scratch) Ubuntu 26.04 sales-demo stack — server + gateway + N agent replicas, release-pinned. Entry point `scripts/start-demo.sh`; see `docs/demo-environment.md`. Not for production (runs `--no-tls` with a baked admin password). |

**Usage:**

```bash
cd deploy/docker
docker compose up -d          # start all services
docker compose logs -f        # follow logs
docker compose down           # stop all services
```

**Pinning a specific release with `docker-compose.uat.yml`:**

The top-level UAT compose file parameterises its `ghcr.io/.../yuzu-server` and `yuzu-gateway` tags through `${YUZU_VERSION:-<default>}`. The default tracks the latest published release, but operators testing an earlier or newer image can override at the command line:

```bash
YUZU_VERSION=0.9.0 docker compose -f docker-compose.uat.yml up -d
```

A GitHub Actions check (`scripts/check-compose-versions.sh`) runs as the first step of the release workflow and blocks asset publication if any tracked compose file carries a hardcoded `X.Y.Z` tag or a `${YUZU_VERSION:-...}` default that does not match the release tag — so the default in the checked-in file is guaranteed to match the latest shipped release.

**Exposed ports:**

| Port | Service | Deployment |
|---|---|---|
| 8080 | Web dashboard + REST API | Always |
| 50051 | gRPC (agent connections) | Always -- server in standalone, gateway in scaled |
| 50052 | gRPC (management) | Always |
| 50055 | gRPC (gateway upstream) | Gateway deployments only |
| 50063 | gRPC (gateway command forwarding) | **Compose-network only — never host-published** (#1422). The privileged fleet-command plane; the server dials `gateway:50063` over the compose network, no shipped compose publishes it, and none should. See `security-hardening.md` "Gateway TLS" |
| 8081 | Gateway health/readiness | Gateway deployments only |
| 9568 | Gateway Prometheus metrics | Gateway deployments only |
| 9090 | Prometheus | Monitoring stack |
| 3000 | Grafana (default login: admin/admin) | Monitoring stack |

**Volumes:** `server-data`, `agent-data`, `prometheus-data`, and `grafana-data` are persisted across container restarts.

### systemd Units

For bare-metal Linux deployments, systemd service files are provided for each component.

**Files:**

| File | Description |
|---|---|
| `deploy/systemd/yuzu-server.service` | Yuzu server unit |
| `deploy/systemd/yuzu-agent.service` | Yuzu agent unit |
| `deploy/systemd/yuzu-gateway.service` | Erlang gateway unit |

**Agent logging is now asynchronous (#4666 PR-2).** `main.cpp` no longer calls
spdlog's sinks directly on the thread that logs; it installs a bounded async
hand-off logger (`agents/core/src/log_handoff.hpp`) as the process's spdlog
default. A producer thread formats the line and enqueues it (`overrun_oldest`
policy); one dedicated worker thread does the actual sink I/O. The queue is a
FIXED-SIZE ring, pre-allocated in full at startup, not proportional to log
volume: 8192 message slots plus one in-flight slot (8193 total), each slot
`sizeof(spdlog::details::async_msg) == 408` bytes on x64: 8193 x 408 =
3,342,744 bytes = 3.34 MB (about 3.19 MiB) of RSS, paid up front the moment
the agent starts, whether or not anything is ever logged. Formatted-text
payload beyond that fixed per-slot cost is additional and not bounded by this
primitive. Under sustained overload (more lines produced than the worker can
write, e.g. a stalled log destination) the queue does not block the
producer and does not grow; `overrun_oldest` silently evicts the oldest
still-queued message to admit the new one, so a busy agent under a stuck sink
can lose log lines rather than pause. There is currently no counter or
heartbeat field surfacing how many lines were dropped this way: an
`overrun_total()` accessor exists on the primitive but nothing in the shipped
binary reads it yet (planned for a later PR's heartbeat poller). A sink-level
write/format failure (as opposed to an overrun) is tracked internally too —
count plus the last 256 bytes of the failing message, in `LogHandoff`'s
private `ErrorState`. Two accessors exist: `log_errors_total()`, exercised
by this PR's own unit test; and `last_log_error_for_test()`, which despite
its name is not currently called by any test or production code. Neither
has a production/heartbeat consumer yet — the same later-PR heartbeat
poller planned for `overrun_total()` above. The only production-visible
signal today is a rate-limited (once per second) fallback line to stderr at
the moment of failure, reproducing what spdlog's own default error handler
always did before #4666 PR-2 installed this one. That fallback line is
unlikely to be visible at all under a genuine Windows-service session
(`--install-service`, no console): the agent attaches no stderr sink at
all in that mode, log-file destination or not. If log lines appear to go
missing under load with no error printed, check disk space and fd limits on
the log destination first: `overrun_oldest` drops are silent in this
release, with no counter or alert to point at them yet. There is no `--log-sync` flag or other escape
hatch back to synchronous logging; this is unconditional for every build. A
`--log-file` that cannot be opened still falls back to console-only logging
exactly as before (`used_log_file_fallback()` prints the same kind of startup
diagnostic), except the console sink is now async too, not synchronous as it
was pre-#4666.

**Stopping a wedged agent (Linux/macOS).** `SIGTERM`/`SIGINT` (`systemctl stop`,
Ctrl-C) triggers a graceful agent stop — plugin shutdown, thread joins, store
close. If that teardown hangs (e.g. the server is unreachable and a drain is
stuck), **send the signal a second time** (`kill -TERM <pid>` again, or a second
Ctrl-C): the agent immediately hard-exits with code 1. This escalation is
deliberate and has **no grace window** — the second signal always force-exits,
even if the first stop was progressing normally — so double-signalling stop
tooling will force-kill healthy agents; send one signal and wait. You no longer
need `SIGKILL` to recover a stuck agent. SQLite state is WAL crash-safe across
the hard exit. Separately (#2233 item 3), a stuck teardown is now also caught
automatically: `AgentImpl::stop()` and the agent's own `run()`-exit teardown
each arm a 20-second internal watchdog, and self hard-exit (**code 4** — new,
distinct from this section's exit 1 and the crash-loop-backstop's exit 3
below) if guardian/spark/DEX teardown or any other blocking step hasn't
returned within it. Separately again (#4666 PR-2), once the rest of shutdown
has already finished (after both watchdogs above have been cancelled and
after the F3 orphan-exit check below has run), the agent tears down its own
async log hand-off logger before the process exits: **code 5** (distinct from
codes 1/3/4) fires from EITHER of two causes at that step — a 2-second
internal watchdog if flushing the queue and joining the logging worker thread
hasn't finished in time, **or an immediate exit (no 2-second wait at all) if
the teardown itself fails outright** (an exception during the flush/join
sequence, or a failure while releasing this image's own reference to the
logger — the exe-image-swap step this exists to protect is unconditional on
every platform, not gated to macOS, even though the underlying hazard it
guards against is real only there: macOS's agent and its shared library run
in separate spdlog registries, so a failed swap there can leave a live
reference past the watchdog; on Linux (confirmed) and Windows (inferred from
dynamic spdlog linkage, not directly measured) the registry is shared and a
later teardown step already nulls it regardless, so a transient failure at
this specific step forces the same hard exit there too even though nothing
was actually left dangling). An operator seeing code 5 land instantly,
with no apparent delay, should not read that as a broken or skipped
watchdog; it means the second cause fired. You do not need to send a second
signal to recover from a code-4 or code-5-class wedge; doing so just makes
the exit happen sooner (code 1) instead of after the relevant internal
deadline. **Codes 3, 4,
and 5 are sequential, non-overlapping checkpoints in the same shutdown, not
independent watchdogs racing each other**: code 4's watchdogs run first
(during `stop()`/`run()`-exit teardown), the F3 orphan check (code 3) runs
after both have been cancelled, and the log-teardown watchdog (code 5) is the
last step before the process exits, so at most one of them can actually fire
for a given shutdown. **Code 1 is different**: because the agent stays
signal-responsive throughout every one of those checkpoints, an operator's
second signal can still preempt whichever one would otherwise have fired, so
code 1 can race with 3, 4, *or* 5 for the same underlying wedge; treat the
exact code reported in that case as a useful hint, not a certain diagnosis,
mirroring the existing code 1-vs-4 framing `main.cpp`'s own comments use. On
Windows, a second Ctrl-C also terminates promptly (via the escalation or the
CRT's default disposition); the service path (`sc stop`) is now also bounded
by the same 20s watchdog, **and by a second, independent 20-second wait**
(`kServiceMainDrainGrace`) that `run_service()` performs after the SCM's
control dispatcher returns, before handing control back to `main()` for its
own log-teardown step: a timeout there also self hard-exits with code 4 (the
same code as the two `stop()`/`run()`-exit watchdogs, reused deliberately
rather than minting a fourth code for "something past its own internal
watchdogs is wedged"; see `shutdown_deadline_guard.hpp`). Because this wait
sits strictly after `service_main` has already reported its final SCM status
(`SERVICE_STOPPED`, clean or with a "specific error" code, see below), a
timeout here changes nothing about what the SCM was already told; it only
means the process takes longer to actually exit. The agent's own
`--install-service` path (see below) does configure automatic service
recovery (3 restarts, 60s apart, resetting after 24h, firing on both a crash
and a clean exit that never reported `SERVICE_STOPPED`, #1822), so a
watchdog fire there behaves similarly to the Linux `Restart=always` unit, not
as a permanent stop. What it does change: `TerminateProcess` bypasses
`report_status`, so none of codes 3/4/5 land in the `sc query`/Event Viewer
"specific error" buckets described further down. A code-4 fired by
`AgentImpl::stop()`'s or `run()`-exit's own watchdog, while `service_main` is
still running and has not yet reported `SERVICE_STOPPED`, surfaces as a
generic unexpected termination. A code-3, a code-5, or a code-4 fired by
`run_service()`'s own drain-grace wait all sit strictly *after*
`service_main` has already reported its final status (`SERVICE_STOPPED`,
clean or with a "specific error" code, see below), so by construction none
of those three changes what the SCM was already told, and none produces an
Event Viewer entry distinguishable from a normal stop; the process simply
takes a little longer to actually exit than the SCM's report suggested.

**Two watchdogs, not one, and their budgets don't share a clock.**
`AgentImpl::stop()` and the agent's own `run()`-exit teardown each arm their
own separate 20s deadline — in the worst case (both phases legitimately slow
but not individually wedged) the two can compose sequentially to as much as
~40 seconds before either one actually fires, exceeding this 30s SCM hint
with **neither** watchdog triggering. That specific case is not a hang and
not a restart: both phases genuinely finish, the agent reports a normal clean
stop (`SERVICE_STOPPED`/success), and per the SCM's own recovery-action rules
a clean stop with a zero exit code does not trigger `SC_ACTION_RESTART`
either — the service simply reports stopped later than the SCM's hint
anticipated, with no automatic action taken either way. Composition-aware
budgeting between the two deadlines (so a slow `stop()` shortens the
remaining budget available to the teardown that follows it) is tracked as a
follow-up (#3756), not implemented today. If
the agent logs `shutdown watcher unavailable` at boot (thread/fd
exhaustion), a hard-exit handler is installed instead: the agent exits promptly
on the FIRST signal, ungracefully — no plugin shutdown, no clean store close.
(A default signal disposition would be discarded by PID 1 in a container, so
the handler is the posture that stays killable.)

**A third, independent watchdog now follows the two above (#4666 PR-2), and
this is a SUM of bounded phases plus genuinely unbounded ones, not a single
derived guarantee.** The log-teardown watchdog (`kLogTeardownGrace`, 2s
default) only arms once the earlier phases have already finished, so its
grace ADDS to theirs rather than overlapping them. On the POSIX/console path
the fully-bounded phases are: `AgentImpl::stop()`'s watchdog (≤20s) plus the
`run()`-exit ScopeExit's watchdog (≤20s) plus the F3 orphan-exit grace
(`kOrphanDrainGrace`, 3s) plus the log-teardown grace (2s), **45 seconds**
total in the worst case where every phase is legitimately slow but none
individually wedged. That figure is bounded-phases-only and does **not**
cover the whole shutdown: the inline plugin-shutdown loop that `run()`'s
reconnect thread runs BETWEEN noticing `stop_requested_` and the `run()`-exit
ScopeExit even arming its own watchdog has no named bound at all (tracked as
#3756 item 5), and neither does `~Agent`'s own destructor work once every
watchdog has already been cancelled; a hang in either of those is caught by
nothing described here. On the Windows service path the arithmetic is
different in shape, not just in number: `run_service()`'s own drain-grace
wait (`kServiceMainDrainGrace`, 20s) sits AFTER the SCM dispatcher returns
and effectively caps whatever is left of `service_main` at that point,
including the F3 orphan grace and `~Agent`, as one bounded 20-second window,
regardless of which specific phase `service_main` is actually in when the
dispatcher returns; the log-teardown grace (2s) then runs separately, in
`main()`, strictly after `run_service()` itself has already returned, adding
to that 20s rather than being covered by it. Neither `deploy/systemd/yuzu-agent.service`
nor `deploy/packaging/macos/com.yuzu.agent.plist` overrides its supervisor's
own stop-timeout default (`TimeoutStopSec=` is absent from the unit;
`ExitTimeOut` is absent from the plist); systemd's and launchd's own
defaults apply on top of everything above, and this document does not assert
what those defaults are. Check `systemd.service(5)`/`launchd.plist(5)` on
your own host if you need the exact figure.

**Stopping a wedged server (Linux/macOS, #3007).** Identical mechanism to the
agent above, applied to the server. If a stop appears to hang: **send the
signal a second time** (`kill -TERM <pid>` again, or a second Ctrl-C) and the
server immediately hard-exits with code 1, no grace window — exactly like the
agent. SQLite/Postgres state is crash-safe across the hard exit. On Windows, a
second Ctrl-C also terminates promptly.

Mechanism: `SIGTERM`/`SIGINT` (`systemctl stop`, `docker stop`, Ctrl-C)
triggers a graceful stop on a dedicated watcher thread — HTTP admission stop,
background thread joins, up to ~115s of stacked waits including webhook/
offload store quiesce (see the stacked-shutdown-bound section in
[Upgrading](upgrading.md); a rare thread-creation-exhaustion fallback path can
push the quiesce portion alone to ~120s, worst case ~175s total), then store
teardown. Those figures leave out two things that can each add to them: a
background roll-up recompute already in flight at SIGTERM (app-perf up to
120 s, catalogue up to 60 s — the 210 s shipped grace was sized for these two,
not for them on top of everything else, so the fallback path plus an in-flight
app-perf recompute can pass 210 s), and a *frozen* primary, against which the
execution-drain query and the background-thread joins block in their own
Postgres calls until it answers. A `--shutdown-drain-seconds` grace of N seconds
runs before all of this and adds to it — raise the stop timeout by N when you
set it.
**A long-seeming wait can
be completely normal, not evidence of a wedge**: each stage logs a
`Shutting down server: waiting up to Ns for ...` line at its start, but
nothing further until it completes or times out — so a silent gap of up to a
minute or so between progress lines is expected, not a hang by itself. If the
server logs `shutdown watcher unavailable` at boot, it falls back to a
hard-exit handler: a `SIGTERM`/`SIGINT` then exits the process promptly on the
FIRST signal, ungracefully (no store flush, no clean close) — the server keeps
running normally until a signal actually arrives, this only changes how it
responds once one does. Separately, a `SIGTERM`/`SIGINT` arriving before the
server has finished starting up (`Server::create()` — TLS cert bootstrap, gRPC
listener setup) also exits promptly with code 1 instead of attempting a
graceful stop — a boot-time signal cannot be handled gracefully, so the server
fails visibly rather than silently continuing to boot (or, before #3007, being
silently ignored).

**Crash-loop backstop (systemd).** The `yuzu-agent` unit sets `Restart=always` +
`RestartSec=10`, but also `StartLimitIntervalSec=300` + `StartLimitBurst=5` (ADR-0021
rung 7.7a). A Guardian I/O worker wedged past its grace period triggers a `hard_exit()`
(exit 3); the shutdown-teardown watchdog above (#2233 item 3) triggers the same
`hard_exit()` mechanism at exit 4; the log hand-off teardown watchdog (#4666 PR-2)
triggers it at exit 5. Either way, against
a *permanently* wedged target (a dead NFS mount, a hung service query) that would
otherwise restart-loop every 10s forever. Instead, after 5 restarts within 300s systemd
puts the unit into `failed` and stops retrying (the device goes dark rather than looping
silently). Recover with `systemctl reset-failed yuzu-agent && systemctl start yuzu-agent`
once the wedged target is resolved. Alert on the `failed` state; the old restart-forever
behaviour hid a crash-looping agent. The unit sets no `SuccessExitStatus=`, so systemd's
default success check (exit code `0` only) applies to every exit the agent makes,
including a `hard_exit()`-driven one. `Restart=always` restarts on any SPONTANEOUS exit the
process makes (0 included; it does not distinguish success from failure for the *restart*
decision), except one thing: systemd suppresses `Restart=` entirely for a process that exits
in response to an explicit `systemctl stop` (`systemd.service(5)`), so a wedge that
self-exits 1/3/4/5 while an operator-initiated stop is in flight does NOT trigger a restart
and does NOT count toward `StartLimitBurst=5`, even though the exit code is still a
"failure" result and can still leave the unit reporting `failed` in `systemctl status`
rather than `inactive`. The `StartLimitBurst=5` ceiling above applies only to the
crash-loop case this paragraph is about: a spontaneous, unrequested exit that systemd
itself decides to restart from. This document does not independently verify the
suppress-on-explicit-stop behaviour against a real systemd instance; it follows from
`systemd.service(5)`'s own documented `Restart=` semantics.

**Persisting deploy-time settings (systemd).** The `yuzu-agent` unit also loads an optional
`EnvironmentFile=-/etc/yuzu-agent/yuzu-agent.env` (`-` = no error when absent, not shipped by
the `.deb`/`.rpm` - operator-created), so `YUZU_AGENT_*` flags such as
`YUZU_AGENT_SPARK_DISABLE` survive restarts and package upgrades instead of only a one-off
command-line override. See [SparkEngine](guaranteed-state.md#sparkengine--the-next-generation-detection-engine-observe-only)
for the specific rollback-lever case, and `docs/spark-flip-gate.md` §6 for the drill
procedure and recovery from a malformed value (it shares the crash-loop backstop above).

**Installation:**

```bash
# Copy binaries
sudo cp build-linux/server/core/yuzu-server /usr/local/bin/
sudo cp build-linux/agents/core/yuzu-agent /usr/local/bin/

# Create service user
sudo useradd --system --no-create-home yuzu

# Install units
sudo cp deploy/systemd/yuzu-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable yuzu-server
sudo systemctl start yuzu-server
```

**Security hardening:** The systemd units include `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=true`, and `PrivateTmp=true` for defense-in-depth.

### Development Stack Script

The `scripts/start-stack.sh` script starts the full development stack locally (without Docker).

**Components started:**

1. `yuzu-server` -- gRPC on :50051, web on :8080
2. Erlang gateway -- agent gRPC on :50051, metrics on :9568
3. `yuzu-agent` -- connects to gateway on :50051
4. Prometheus -- scraper on :9090
5. Grafana -- dashboards on :3000

**Usage:**

```bash
bash scripts/start-stack.sh          # start all components
bash scripts/start-stack.sh stop     # kill all components
bash scripts/start-stack.sh status   # show running processes and ports
```

---

## Windows Service Installation

On Windows, the Yuzu **agent** has a native Windows service wrapper (`yuzu-agent.exe --install-service`); this is what the shipped installer uses, and is the recommended path — see the **Agent: `--install-service`** subsection below. A native wrapper for the Yuzu **server** is still planned for a future release; until then, use `sc.exe` or NSSM (Non-Sucking Service Manager) for the server, as described below.

### Agent: `--install-service` (native, recommended)

```cmd
REM Register the service (binPath is written for you, including the internal
REM --service marker the agent needs to run under the SCM control protocol)
yuzu-agent.exe --install-service

REM Point it at your server / data dir / log file via sc config. binPath= takes a
REM SINGLE value, so the whole "exe + arguments" string must be ONE quoted token,
REM with the quotes around a spaced exe path escaped as \" -- sc.exe does NOT
REM reassemble several quoted segments back into one binPath. Written the other way
REM round (quoting only the exe and leaving the flags bare after it) sc.exe parses
REM --service/--server/... as unknown OPTIONS to sc itself, prints its usage block,
REM and exits 1639 ERROR_INVALID_COMMAND_LINE without touching the service. That is
REM #1468: the shipped installer had exactly that defect, and because Inno ignores
REM [Run] exit codes it failed silently -- the service kept the argument-less binPath
REM --install-service had written, so the agent ran with no --server and fail-closed
REM on TLS. Check your work with `sc qc YuzuAgent`: every flag below must appear.
sc.exe config YuzuAgent binPath= "\"C:\Yuzu\bin\yuzu-agent.exe\" --service --server yuzu.example.com:50051 --data-dir \"C:\ProgramData\Yuzu\" --plugin-dir \"C:\Yuzu\plugins\" --log-file \"C:\Yuzu\logs\yuzu-agent.log\""

sc.exe start YuzuAgent
sc.exe stop YuzuAgent

REM Remove it
yuzu-agent.exe --remove-service
```

The service currently registers to run as **LocalSystem** (unchanged by the #1822 SCM-protocol fix — tracked separately as #1442). Moving it to a least-privilege account requires a manual post-install `sc.exe config obj= "NT SERVICE\YuzuAgent"` plus directory ACLs the installer doesn't set today — see `docs/agent-privilege-model.md` and #1442 for the tracked follow-up, and the [Service Account](#service-account) guidance below (written for the server, but the same `obj=` mechanism applies).

Re-running `--install-service` is idempotent — it updates an existing registration's binPath in place rather than failing with "service already exists", so it's safe to re-run after an upgrade. **It resets binPath to the bare exe + `--service` marker** (the same minimal form shown above), dropping any `--server`/`--data-dir`/`--plugin-dir`/`--log-file` a prior `sc config` had applied — always follow it with `sc.exe config` to restore your runtime args, exactly as the installer's own `[Run]` sequence does (`--install-service` then `sc config` then `sc start`). Recovery actions (3 restarts, 60s apart, resetting after 24h) are configured automatically and fire on both crashes and clean-exit-with-error.

> **Important:** the `--service` flag tells the binary to speak the SCM control protocol (`ServiceMain`/`SetServiceStatus`) instead of running as a console program — it is added automatically by `--install-service` and must be present in any `sc.exe`/manually-crafted binPath for the agent. Omitting it reproduces the pre-fix behavior: `sc start` fails with error 1053. Do **not** add `--service` when wrapping the agent with NSSM (below) — NSSM launches the agent as an ordinary child process, not via the SCM itself, so the agent would try (and fail) to connect to a dispatcher that isn't there.

> **Fleet-upgrade gotcha:** because `--install-service` always resets binPath to the bare minimal form, a silent/unattended re-run of the shipped installer (e.g. an SCCM/Intune package upgrade) that does **not** re-supply the original `/SERVER=`/`/TOKEN=`/`/NOTLS` parameters on that specific invocation will reconfigure the agent back to `localhost:50051` with TLS on — and because the SCM protocol now actually works (post-#1822), the service **starts successfully** against that wrong address instead of failing loudly the way it always did before this fix. The agent goes dark from the fleet with no installer-visible error. Always replay the same install-time parameters on every upgrade run, not just the first install.

**If `sc start YuzuAgent` still fails after this fix:** check the log file first (`{app}\logs\yuzu-agent.log` via the installer; `<data-dir>\yuzu-agent.log` if you configured `--service` manually without `--log-file`), it has the actual reason. `sc query YuzuAgent`/Event Viewer only distinguish which of three generic buckets: **specific error 1** covers three distinct causes that land on the same code: the agent failed to construct (bad `agent.db`, SQLite/config problem), **or** startup completed but the gRPC channel couldn't be built under the fail-closed TLS posture (missing/unreadable CA or client cert/key, #1303), including, notably, the exact misconfiguration the fleet-upgrade gotcha above can introduce by silently flipping TLS back on, **or** a mid-life failure: the dispatch thread pool could not be re-created on a reconnect (host out of threads), which previously ended the service silently as a clean stop; **specific error 2** (the agent stopped on its own without a stop/shutdown request, unexpected, check the log for what `run()` returned early on); **specific error 3** (an unhandled exception reached the service dispatcher, check the log for the exception message). None of these three codes carry more detail on their own; the log file is where the actual cause lives. These SCM "specific error" buckets are a **separate namespace** from the agent's own process exit codes (1/3/4/5) described under *Stopping a wedged agent* above; they cover why `sc start` failed to bring the service up in the first place, not why a running service later stopped. In particular, a code-4 shutdown-watchdog exit (#2233 item 3) fired while `service_main` is still running happens via `TerminateProcess`, which bypasses `report_status` entirely, so it does not land in any of these three buckets; Event Viewer shows it as a generic unexpected termination, not "specific error N". A code-5, a code-4 fired by `run_service()`'s own post-dispatcher drain wait, or a code-3 fired by the EXPLICIT F3 orphan check on `service_main`'s normal path (#4666 PR-2) are stranger still: each fires strictly after `service_main` has already reported one of the buckets above (or a clean `SERVICE_STOPPED`), so it changes none of them and shows up in neither `sc query` nor Event Viewer as anything distinguishable from that already-reported outcome. One exception to that ordering, pre-existing and not introduced by PR-2: `OrphanExitGuard`'s destructor (`hard_exit.hpp`) is ALSO a fail-closed backstop covering an exception that unwinds out of `agent->run()` itself before the explicit F3 check is even reached; on that path a code-3 can fire from the destructor DURING unwind, before any `report_status` call, so this "already reported" property does not hold universally for every possible code-3, only for the ordinary explicit-check case.

### Server: sc.exe (native wrapper not yet available)

```cmd
REM Create the Yuzu server service
sc.exe create YuzuServer binPath= "C:\Yuzu\yuzu-server.exe --https-cert C:\Yuzu\certs\server.crt --https-key C:\Yuzu\certs\server.key" start= auto DisplayName= "Yuzu Server"

REM Set startup type to automatic (delayed start, recommended)
sc.exe config YuzuServer start= delayed-auto

REM Configure recovery: restart on first, second, and subsequent failures
sc.exe failure YuzuServer reset= 86400 actions= restart/5000/restart/10000/restart/30000

REM Start / stop the service
sc.exe start YuzuServer
sc.exe stop YuzuServer
```

> **Note:** With `sc.exe`, spaces after `=` are required (e.g., `start= auto`, not `start=auto`). This is a quirk of the `sc.exe` command parser.

### Using NSSM

[NSSM](https://nssm.cc/) provides a more user-friendly wrapper with a GUI configuration dialog. It remains a valid option for the **server** (no native wrapper yet) and for the **agent** if you prefer NSSM's process-monitoring/log-rotation over the native `--install-service` path — just don't pass `--service` to an NSSM-wrapped agent (see the note above).

```cmd
REM Install services
nssm install YuzuServer "C:\Yuzu\yuzu-server.exe"
nssm install YuzuAgent "C:\Yuzu\yuzu-agent.exe"

REM Set arguments (no --service for the NSSM-wrapped agent)
nssm set YuzuServer AppParameters "--https-cert C:\Yuzu\certs\server.crt --https-key C:\Yuzu\certs\server.key"
nssm set YuzuAgent AppParameters "--server yuzu.example.com:50051"

REM Configure startup and recovery
nssm set YuzuServer Start SERVICE_DELAYED_AUTO_START
nssm set YuzuAgent Start SERVICE_DELAYED_AUTO_START

REM Configure stdout/stderr logging
nssm set YuzuServer AppStdout "C:\Yuzu\logs\server-stdout.log"
nssm set YuzuServer AppStderr "C:\Yuzu\logs\server-stderr.log"
nssm set YuzuAgent AppStdout "C:\Yuzu\logs\agent-stdout.log"
nssm set YuzuAgent AppStderr "C:\Yuzu\logs\agent-stderr.log"

REM Start the services
nssm start YuzuServer
nssm start YuzuAgent
```

### Service Account

For production deployments, create a dedicated service account with minimal permissions rather than running as `LocalSystem`:

1. Create a local user account (e.g., `YuzuSvc`) with no interactive logon rights.
2. Grant the account read/write access to the Yuzu installation directory and data directory only.
3. Assign the "Log on as a service" right via Local Security Policy (`secpol.msc`).
4. Configure the service to run as this account: `sc.exe config YuzuServer obj= ".\YuzuSvc" password= "PASSWORD"`.

> **Planned:** A native Windows service wrapper (`yuzu-server --install-service`) is planned for a future release, which will handle service registration, recovery configuration, and Event Log integration automatically.

---

## Planned Features

The following server administration features are on the roadmap but not yet implemented.

| Feature | Phase | Description |
|---|---|---|
| Runtime Configuration API | Phase 7 (7.3) | Change retention TTLs, connection limits, and other server parameters via REST API. **Not all keys apply live** - retention TTLs are stored and reported immediately but enforced only after a restart, and OIDC keys apply only via Settings -> OIDC. See [REST API -> When a change takes effect](rest-api.md#when-a-change-takes-effect). |
| AD/Entra Integration | Phase 7 (7.5) | Sync users and groups from Active Directory (LDAP) or Microsoft Entra ID. Auto-create Yuzu principals from directory membership. |
| System Health Monitoring | Phase 7 (7.2) | Server-side health dashboard showing memory, CPU, disk, database size, connected agent count, and gRPC stream health. Prometheus metrics for server internals. |
