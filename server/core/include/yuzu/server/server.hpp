#pragma once

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::server::auth {
class AuthManager;
}

namespace yuzu::server {

struct Config {
    std::string listen_address{"0.0.0.0:50051"};     // Agent-facing gRPC
    std::string management_address{"0.0.0.0:50052"}; // Operator-facing gRPC
    std::string web_address{"127.0.0.1"};            // HTMX web UI bind address
    int web_port{8080};                              // HTMX web UI port

    // External origins the dashboard is served on, for the CSRF same-site gate
    // (--csrf-trusted-origin, repeatable, comma-separated permitted; #2537).
    // A reverse proxy that rewrites Host makes the browser's Origin and the
    // server's Host legitimately differ, which 403'd every CSRF-gated dashboard
    // action behind nginx/Envoy/ALB/Cloudflare. Declaring the external origin
    // here lets the gate accept it. Entries are normalised ONCE at boot by
    // web_utils.hpp's normalise_trusted_origins; an entry carrying a scheme
    // ("https://yuzu.example") is matched on scheme AND host, a bare host on
    // host only. No forwarded header is ever consulted — the trust anchor is
    // this config value, which an attacker cannot set. Empty (default) =
    // same-host only, i.e. pre-#2537 behaviour.
    std::vector<std::string> csrf_trusted_origins;

    bool tls_enabled{true};
    std::filesystem::path tls_server_cert; // PEM server certificate
    std::filesystem::path tls_server_key;  // PEM server private key
    std::filesystem::path tls_ca_cert;     // For mTLS agent verification
    bool insecure_skip_client_verify{false}; // Permit TLS without client cert verification

    // PKI default certs (PR2). With no operator cert flags and without
    // --no-default-certs, the server generates a per-install CA + server-side
    // leaves on first boot (default_certs.hpp). `ca_dir` defaults to
    // auth::default_cert_dir() when empty; `using_default_certs` is runtime state
    // the bootstrap sets to drive the notification surfaces + the
    // request-but-don't-require agent-listener posture (per-agent mTLS is PR3).
    bool no_default_certs{false};
    bool using_default_certs{false};       // any surface on default certs — drives notifications
    bool using_default_agent_certs{false}; // agent listener on default certs (don't-require posture)
    std::filesystem::path ca_dir;
    // Extra Subject Alternative Names to inject into the auto-generated default
    // leaves (--cert-san, repeatable). Each value is "dns:<name>", "ip:<addr>",
    // or a bare value auto-classified by IP-literal shape; a single value may be
    // comma-separated. Applied to every default leaf (https/server/gateway) so an
    // operator can make the built-in certs valid for a deployment hostname or IP
    // (e.g. "dns:gateway" so an agent verifying a gateway reached by that name
    // succeeds). Ignored when operator certs are supplied or --no-default-certs.
    std::vector<std::string> cert_sans;
    // Shared POSIX group (name or numeric gid) for the auto-generated cert volume
    // (--cert-group, PKI #1289). When set, the cert dir (0750) and the gateway
    // leaf key (0640) are chgrp'd to it so a gateway/agent running as a DIFFERENT
    // uid in a sibling container can read the shared CA + its leaf out of the
    // shared /etc/yuzu/certs volume. Empty (default) = tight single-host perms
    // (dir 0700, keys 0600). The server/HTTPS private keys stay 0600 regardless.
    std::string cert_group;

    // Optional management listener TLS override.
    // If left empty, management reuses the agent listener credentials.
    std::filesystem::path mgmt_tls_server_cert;
    std::filesystem::path mgmt_tls_server_key;
    std::filesystem::path mgmt_tls_ca_cert;

    // Session management
    std::chrono::seconds session_timeout{
        90}; // Agents disconnected after this many seconds without heartbeat
    std::size_t max_agents{10'000};

    // JIT admin elevation (SOC 2 CC6.3/CC6.6) — `/auth-and-authz` gap P1 #9.
    // Maximum lifetime (seconds) of a time-boxed admin elevation granted via
    // POST /api/v1/elevate; a request asking for longer is clamped to this. The
    // elevation is in-memory per-session and auto-reverts on lapse. Default
    // 3600 (1h). Wired via --jit-max-elevation-secs / YUZU_JIT_MAX_ELEVATION_SECS.
    int jit_max_elevation_secs{3600};

    // JIT elevation via OIDC IdP-MFA assertion (security review
    // docs/security-reviews/jit-elevation-2026-06-30.md follow-up). When true
    // (default), an OIDC session whose IdP login attested MFA via the `amr`
    // claim (a seeded `Session::mfa_verified_at`, set at /auth/callback via
    // amr_asserts_mfa) satisfies the mandatory-second-factor requirement at
    // POST /api/v1/elevate WITHOUT local TOTP enrollment — the existing
    // step-up freshness check still applies. A no-amr (single-factor) OIDC
    // session is still hard-denied regardless of this flag. Set false to
    // disable the OIDC-amr path entirely: OIDC sessions then cannot use JIT
    // elevation at all (an OIDC session can't present a local TOTP step-up —
    // its step-up is re-SSO), so an operator must elevate from a local session
    // with local TOTP — an escape hatch for shops that want an elevation factor
    // distinct from SSO. Wired via --jit-oidc-amr-elevation /
    // YUZU_JIT_OIDC_AMR_ELEVATION.
    bool jit_oidc_amr_elevation{true};

    // Operator dashboard idle (inactivity) session timeout — SOC 2 CC6.3.
    // Seconds of inactivity after which a cookie session is invalidated
    // server-side (a sliding window UNDER the absolute 8h session lifetime).
    // 0 (default) disables it — only the absolute lifetime applies; existing
    // deployments are unaffected. Enabling it (recommended 900 = 15 min)
    // satisfies the CC6.3 inactivity-timeout control. Wired via
    // --session-inactivity-secs / YUZU_SESSION_INACTIVITY_SECS into
    // AuthManager::set_session_inactivity. See docs/auth-architecture.md.
    int session_inactivity_secs{0};

    // Authentication
    std::filesystem::path auth_config_path; // yuzu-server.cfg path

    // Data directory (for all SQLite DBs and runtime state).
    // If empty, defaults to auth_config_path's parent directory.
    std::filesystem::path data_dir;

    /// Returns the directory where DBs and runtime state should be written.
    [[nodiscard]] std::filesystem::path db_dir() const {
        return data_dir.empty() ? auth_config_path.parent_path() : data_dir;
    }

    // PostgreSQL server storage substrate (ADR-0006/0007). libpq conninfo —
    // keyword/value or URI form — for the shared PgPool every Postgres-backed
    // server store uses. Wired via --postgres-dsn / YUZU_POSTGRES_DSN. The
    // server FAILS CLOSED (ADR-0007, no SQLite fallback) when this is empty or
    // the pool cannot reach the database: startup_failed() is set and run()
    // returns non-zero. The agent stays SQLite; this is server-only.
    std::string postgres_dsn;

    // Max concurrent PostgreSQL connections in the shared pool. Default 16.
    // Sizing guidance in docs/user-manual/server-admin.md; tuning signals are
    // yuzu_pg_pool_in_use / yuzu_pg_acquire_wait_seconds. Wired via
    // --postgres-pool-size / YUZU_POSTGRES_POOL_SIZE.
    int postgres_pool_size{16};

    // HA WS-8 (ADR-2002 §12): minimum seconds stop() keeps the listener open
    // after /readyz starts answering 503 `draining`, so a load balancer stops
    // routing here before the socket closes. 0 = no minimum (the single-node
    // default). Range [0, 60] — see shutdown_drain_rules.hpp for why 60. Wired
    // via --shutdown-drain-seconds / YUZU_SHUTDOWN_DRAIN_SECONDS.
    int shutdown_drain_seconds{0};

    // Set by main.cpp iff `AuthDB::seed_admin_if_empty` actually seeded the
    // sole admin user this boot (a genuinely-empty `auth.users` — fresh
    // start / Postgres cutover). Threaded through Config rather than set
    // directly on a metrics registry because the seed happens before
    // `Server::create()` constructs `ServerImpl` (and therefore before
    // `metrics_` exists) — ServerImpl's ctor reads this once to pre-seed
    // `yuzu_auth_fresh_start_reset_total`.
    bool auth_fresh_start_seeded{false};

    // Gateway upstream (Erlang gateway → C++ server control plane)
    std::string gateway_upstream_address; // Empty = disabled; e.g. "0.0.0.0:50053"
    std::string gateway_command_address;  // Gateway ManagementService for command forwarding
    bool gateway_mode{false};             // When true, relax peer-mismatch in Subscribe

    // HA WS-4 4.3: per-cluster ManagementService addresses for cross-cluster
    // command fan-out (`--gateway-cluster-addr cluster_id=host:port`, comma-
    // repeatable). Empty (the default) means single-cluster mode:
    // `gateway_command_address` alone is used regardless of which cluster_id
    // an agent's gateway announces — byte-for-byte the pre-4.3 behavior. Set
    // means multi-cluster mode: see `GatewayMgmtStubPool`
    // (gateway_mgmt_stub_pool.hpp) for the full resolution rule, including
    // the `"default"` auto-alias to `gateway_command_address`.
    std::unordered_map<std::string, std::string> gateway_cluster_addresses;

    // #1128: operator-declared multi-egress NAT/proxy ranges. When a direct-
    // connect agent's Register and Subscribe present different source IPs that
    // BOTH fall inside one of these CIDRs, the per-session peer-IP mismatch is
    // downgraded to advisory (audit + metric) instead of rejected. Empty = the
    // strict exact-match binding (default, no relaxation).
    std::vector<std::string> trusted_nat_cidrs;

    // #1128 / gov UP-2: opt-in to the mTLS-identity NAT accommodation. When
    // true, a peer-IP mismatch is also downgraded to advisory if the Subscribe
    // mTLS identity matches the one bound at Register. SAFE ONLY WITH PER-AGENT
    // CLIENT CERTS — a shared/fleet-wide cert makes every identity "match",
    // which would let an insider replay another agent's session from its own IP
    // (the IP guard is waived). Default false: identity-match never relaxes the
    // IP binding unless the operator affirms per-agent certs via this flag.
    bool nat_trust_mtls_identity{false};

    // NVD CVE feed
    std::string nvd_api_key; // Optional NVD API key for higher rate limits
    std::string nvd_proxy;   // HTTP proxy for NVD API (e.g. "http://proxy:8080")
    std::chrono::seconds nvd_sync_interval{4 * 3600}; // Default: 4 hours
    bool nvd_sync_enabled{true};
    int nvd_backfill_years{8}; // Newest-first backfill depth; <=0 = full history

    // OTA agent updates
    std::filesystem::path
        update_dir;         // Directory for agent binaries (default: <config_dir>/agent-updates/)
    bool ota_enabled{true}; // Master switch for OTA updates

    // HTTPS for web dashboard
    bool https_enabled{true};
    int https_port{8443};
    std::filesystem::path https_cert_path;
    std::filesystem::path https_key_path;
    bool https_redirect{true}; // HTTP→HTTPS 301 redirect

    // Certificate hot-reload
    bool cert_reload_enabled{true};       // Auto-reload when cert/key files change on disk
    int cert_reload_interval_seconds{60}; // Polling interval in seconds

    // OIDC SSO
    std::string oidc_issuer;        // e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
    std::string oidc_client_id;     // App registration client ID
    std::string oidc_client_secret; // Client secret (required for Entra web platform)
    std::string oidc_redirect_uri;  // Callback URL (auto-computed from web port if empty)
    std::string oidc_admin_group;   // Entra group ID that maps to admin role
    bool oidc_skip_tls_verify{
        false}; // Disable TLS cert verification for OIDC (insecure, for dev only)
    // ADR-2001 §1 — which validated ID token claim is used as the
    // SCIM-externalId join key at OIDC login. Allow-list {sub, oid} is
    // enforced at boot (main.cpp, CLI::IsMember) — fail-closed on anything
    // else, never a silent fallback to the default.
    std::string oidc_scim_link_claim{"sub"};

    // SAML 2.0 SSO
    // Enabled when idp_sso_url + idp_cert + sp_entity_id + sp_acs_url are all non-empty
    // (mirrors OIDC's "gated on issuer && client_id" pattern).
    // Not supported on Windows builds — is_enabled() returns false (N4), and a startup
    // ERROR is logged if any flag is set.
    std::string saml_idp_entity_id; // IdP entityID (must match Issuer in assertions)
    std::string saml_idp_sso_url;   // IdP SSO URL (HTTP-Redirect binding endpoint)
    std::string saml_idp_cert;      // Filesystem path to IdP signing cert PEM (pinned key)
    std::string saml_sp_entity_id;  // SP entityID (used as AudienceRestriction)
    std::string saml_sp_acs_url;    // SP Assertion Consumer Service URL (POST binding)
    std::string saml_sp_key;        // Filesystem path to SP AuthnRequest signing key PEM (RSA);
                                     // empty means AuthnRequests are unsigned (backward-compatible)
    std::string saml_group_attribute; // <Attribute Name="..."> carrying group values
    std::string saml_admin_group;     // Group value (from saml_group_attribute) that maps to admin
    std::string saml_name_attribute;  // <Attribute Name="..."> carrying the display name (else NameID)
    std::string saml_email_attribute; // <Attribute Name="..."> carrying the email (display fallback)

    // Response persistence
    int response_retention_days{90};

    // Audit trail
    int audit_retention_days{365};

    // Guardian (Guaranteed State) event retention. Default 30d matches
    // kDefaultEventRetentionDays + the workstream-E data inventory.
    int guardian_event_retention_days{30};

    // Analytics
    bool analytics_enabled{true};
    int analytics_drain_interval_seconds{10};
    int analytics_batch_size{100};
    std::string clickhouse_url; // empty = disabled
    std::string clickhouse_database{"yuzu"};
    std::string clickhouse_table{"yuzu_events"};
    std::string clickhouse_username;
    std::string clickhouse_password;
    std::filesystem::path analytics_jsonl_path; // empty = disabled

    // Metrics
    bool metrics_require_auth{true}; // Require auth for remote /metrics access

    // Security response headers (SOC2-C1)
    // Extra source-list entries appended to script-src, style-src, connect-src,
    // and img-src CSP directives. Space-separated. Use to whitelist customer
    // CDNs, monitoring beacons, or analytics endpoints.
    std::string csp_extra_sources;

    // Rate limiting
    int rate_limit{100};      // Max API requests/second per IP
    int login_rate_limit{10}; // Max login attempts/second per IP

    // Per-principal quota cap (PR 4.4, ADR-1005 class engine principals).
    // Gates only principal_kind=="engine" sessions at the pre-routing
    // chokepoint; human/agent/anonymous traffic is unaffected. See
    // principal_quota.hpp. `burst` is derived as 2x rate at construction.
    int principal_max_concurrency{16};    // per-engine-principal in-flight cap
    double principal_rate_limit{20.0};    // per-engine-principal requests/second

    // Agent OTA pull bounds (issue #913 per-peer limit, #911 deadlines).
    // `DownloadUpdate` was previously unbounded in every dimension: any
    // mTLS-authenticated agent could open unlimited parallel streams, each
    // pinning a gRPC thread on blocking disk reads and network writes.
    //
    // The CONCURRENCY cap is the primary defence; the rate bucket is
    // deliberately loose. The attack is N parallel streams, which a semaphore
    // stops exactly, whereas a tight bucket meters RETRIES and produces the
    // lockout pathologies recorded on #934 and #941. Raise the rate knobs only
    // with that in mind. See agent_service_impl.hpp's OtaBoundConfig.
    int ota_max_concurrent_per_peer{2};   // parallel DownloadUpdate streams per peer
    double ota_rate_capacity{20.0};       // token-bucket burst per peer
    double ota_rate_refill_per_min{1.0};  // tokens restored per minute per peer
    int ota_transfer_deadline_secs{900};  // whole-transfer bound (watchdog TryCancel)
    int ota_chunk_write_deadline_secs{30};// single-chunk stall bound
    // Cardinality ceiling on the per-peer map. The admission key falls back to
    // peer IP when no client certificate is presented, so this key space is
    // attacker-influenced (issue #935) and must be capped.
    int ota_max_peers_tracked{50000};

    // gRPC server-wide resource bounds. Before these, the one ServerBuilder set
    // keepalive/ping args and NOTHING else — no ResourceQuota, no stream cap —
    // which is what made the unbounded OTA path severe rather than theoretical.
    // A repo-wide search found no other gRPC resource bound anywhere on the
    // server; the governance ledger row for #3401 (finding UP-4) records the
    // same absence.
    int grpc_max_concurrent_streams{128};  // per-connection HTTP/2 stream cap
    int grpc_max_resource_memory_mb{512};  // gRPC ResourceQuota ceiling
    // Thread ceiling for the gRPC sync server.
    //
    // THIS IS A FLEET-SIZE CEILING, NOT A WORK CEILING, and it must be set above
    // your concurrently-connected agent count. AgentService is a SYNCHRONOUS
    // service and Subscribe blocks for the life of each agent's command stream, so
    // every connected agent permanently occupies one thread. Once the quota is
    // exhausted gRPC answers ResourceExhausted to EVERY rpc on every service
    // sharing it — agent, management and gateway-upstream alike — so a value below
    // the fleet size is a fleet-wide outage, not back-pressure.
    //
    // The default is therefore generous rather than tight. It exists to stop
    // pathological runaway (and to give the OTA admission map's overshoot a real
    // bound), not to size the fleet.
    int grpc_max_threads{8192};

    // Fraction of ota_max_concurrent_total reserved for peers admitted on a
    // CERTIFICATE identity, expressed as a percentage. The server-wide cap is a
    // shared exhaustible resource, so without a reserve a handful of source
    // addresses holding slow transfers can starve the whole fleet — a cheaper
    // denial than the address-space scaling the cap was added to prevent. Peers
    // keyed on source IP may occupy at most (100 - this)% of the cap; enrolled
    // peers may use all of it.
    int ota_cert_reserve_pct{50};
    // Server-wide ceiling on concurrent DownloadUpdate transfers, across ALL peers.
    // The per-peer cap bounds one identity; on a deployment where the identity gate
    // is inert the admission key falls back to source IP, so the per-peer bound
    // scales with the caller's address space (a /24 buys 256 buckets). This is the
    // bound that does not.
    int ota_max_concurrent_total{64};

    // Account lockout — `/auth-and-authz` skill gap matrix P0 #2, SOC 2
    // CC6.3. After `auth_lockout_threshold` consecutive failed local-password
    // attempts the account is locked for `auth_lockout_window_secs`. The
    // counter resets on a successful login or an admin unlock. Threshold 0
    // disables the feature. The lock is temporary/auto-expiring so it cannot
    // be weaponised to permanently DoS a legitimate principal; OIDC and the
    // MFA code-verification path (which has its own rate-limit) are out of
    // scope. See docs/auth-architecture.md.
    int auth_lockout_threshold{5};     // consecutive failures before lock; 0 disables
    int auth_lockout_window_secs{900}; // lock duration, default 15 min

    // MFA / TOTP — `/auth-and-authz` skill gap matrix P0 #1, SOC 2 CC6.6.
    // See docs/auth-mfa-design.md. PR1 ships enforcement="optional" (self-
    // service enrollment, no enforcement at login). PR3 wires admin-only /
    // required by gating /login against users.mfa_enrolled_at.
    std::string mfa_enforcement{"optional"}; // "optional" | "admin-only" | "required"
    /// How long after a successful MFA proof (login or step-up) high-risk
    /// endpoints accept the session as "stepped up" without re-prompting.
    /// Default 300 s mirrors common bank/SaaS UX. Lowering to <60 s pushes
    /// every privileged click through TOTP; raising to >900 s weakens
    /// the CC6.6 evidence chain.
    int mfa_step_up_window_secs{300};
    /// How long the intermediate "mfa_pending" token is valid (window
    /// between password success and TOTP submission). Default 120 s.
    int mfa_login_pending_secs{120};

    // Hardened authentication mode + break-glass — `/auth-and-authz` skill gap
    // matrix P0 #3, SOC 2 CC6.3 (disable password fallback) + CC6.6
    // (constrained break-glass). See docs/auth-architecture.md "Hardened mode".
    //
    // "standard" (default) leaves local-password login enabled. "sso-only"
    // disables the local-password path fleet-wide — only an SSO provider mints
    // a session — EXCEPT for a single designated break-glass account that is
    // exempt ONLY while armed (an out-of-band host operator ran
    // --break-glass-arm within the window). sso-only refuses to start unless an
    // SSO provider is configured — OIDC, or (Linux/macOS, HTTPS on) SAML — since
    // it would otherwise lock every operator out (gate: sso_boot_guard.hpp).
    std::string auth_mode{"standard"}; // "standard" | "sso-only"
    /// Username of the single local account exempt from sso-only while armed.
    /// Empty = no break-glass account. Must exist and have MFA enrolled
    /// (enforced fail-closed at boot under sso-only).
    std::string break_glass_user;
    /// Seconds the break-glass account stays armed after --break-glass-arm
    /// (default 86400 = 24h). The arm auto-expires (break_glass_armed_until is
    /// a future timestamp evaluated lazily at login, like locked_until) so it
    /// can never be a permanent standing exemption.
    int break_glass_window_secs{86400};

    // SCIM v2 provisioning (`/scim/v2/*`) — enterprise IdP (Okta/Entra)
    // auto-provisioning + auto-deprovisioning of Yuzu operators (Users only).
    // Disabled by default: an unauthenticated provisioning surface would be
    // catastrophic, so the server FAILS CLOSED at boot if --scim-enable is
    // set without --scim-token, and if HTTPS is disabled (the bearer token
    // would cross the wire in plaintext) — see main.cpp. Wired via
    // --scim-enable / YUZU_SCIM_ENABLE.
    bool scim_enable{false};
    /// Bearer credential IdPs present as `Authorization: Bearer <token>` on
    /// every /scim/v2/* request. Stored as a sha256 hash only (ScimStore).
    /// Required (fail-closed) whenever scim_enable is true. Wired via
    /// --scim-token / YUZU_SCIM_TOKEN.
    std::string scim_token;
    /// SCIM Group `displayName` (from ScimStore's scim_groups table) that
    /// maps to admin role — mirrors --saml-admin-group's group-to-role
    /// pattern (#2021, slice 2). Empty (the default) means no SCIM group
    /// grants admin. Wired via --scim-admin-group / YUZU_SCIM_ADMIN_GROUP.
    std::string scim_admin_group;

    // MCP (Model Context Protocol) server
    bool mcp_disable{false};   // Kill switch: reject all MCP requests
    bool mcp_read_only{false}; // Restrict MCP to read-only tools only
    // MCP Streamable HTTP transport (ADR-1005 Decision 15, track 2f)
    bool mcp_streaming_disable{false}; // --mcp-no-streaming: no sessions, GET/DELETE → 405
    /// SSE-on-POST (streamed POST, 2f PR 3b). Ships ON: the machinery is complete and
    /// reviewed, and the four defects that gated the on-by-default flip (#2739, #2740,
    /// #2785, #2789) are fixed. Pass --no-mcp-streamed-post to opt out.
    /// NOT --mcp-no-streaming, which disables the whole transport (sessions +
    /// GET/DELETE) including rungs already shipped.
    bool mcp_streamed_post_enable{true}; // --mcp-enable-streamed-post
    /// Allowed Origin header values for /mcp/v1/ (scheme+host+port, exact match).
    /// Empty ⇒ any PRESENT Origin is rejected (secure default; absent Origin is
    /// allowed because the endpoint requires a credential). Wired via the
    /// repeatable --mcp-allowed-origin / YUZU_MCP_ALLOWED_ORIGINS.
    std::vector<std::string> mcp_allowed_origins;
    /// Concurrently held-open MCP SSE streams, globally and per principal
    /// (Decision 15(d)/(h)). Each stream pins one HTTP worker for its whole life,
    /// so this is a worker-pool budget, not a taste setting: the global cap is
    /// clamped at boot to `pool_max - plain-REST reserve`. Per-principal is
    /// deliberately BELOW the per-principal session cap (8) — a session is a cheap
    /// cursor, a held-open worker is not.
    /// Concurrent held-open SSE responses this server is sized for, across EVERY streaming
    /// surface (MCP GET, MCP streamed POST, /api/v1/events, the dashboard executions
    /// drawer, the legacy /events stream). The worker pool is derived FROM this — not
    /// the other way round (ADR-0034):
    /// a stream costs a blocked thread, which is cheap, so the operator declares the workload
    /// and the pool is sized to honour it. 0 = the default (128).
    std::size_t max_sse_streams{0};
    /// Per-principal MCP stream allowance — a per-surface anti-monopoly policy, NOT a
    /// capacity limit (the pool is protected by the global budget alone).
    std::size_t mcp_max_streams_per_principal{4};
    /// Pin the shared HTTP worker pool by hand. 0 = derive it from `max_sse_streams`, which
    /// is what you want. Setting it overrides the derivation, and the stream target is then
    /// clamped to whatever the pool you chose can actually carry.
    std::size_t http_worker_threads{0};

    // Fleet visualization (PR 3 of feat/viz-engine ladder)
    bool viz_disable{false}; // Kill switch: reject all /viz/fleet requests (DEP-1)

    // Product pack signature enforcement (#802 / W7.4)
    /// When true, install_pack accepts packs WITHOUT a `signature` field
    /// (legacy unsigned packs). Default false — the secure posture rejects
    /// unsigned packs to close the fleet-wide arbitrary-code-execution
    /// surface a MITM or unprivileged-uploader could otherwise exploit.
    /// Wired via --allow-unsigned-packs / YUZU_ALLOW_UNSIGNED_PACKS=1.
    /// Setting true at startup emits the `server.unsigned_packs_allowed`
    /// audit event + a startup spdlog::warn so the relaxed posture is
    /// loud in both audit log and operator-visible logs.
    bool allow_unsigned_packs{false};

    // Instruction-definition signature enforcement (#1073 / W7.4 sibling-gap)
    /// When true, `InstructionStore::import_definition_json` accepts
    /// definitions WITHOUT a `signature` field (legacy unsigned imports).
    /// Default false — the secure posture rejects unsigned imports to close
    /// the equivalent fleet-wide arbitrary-code-execution surface that #802
    /// closed for ProductPack: an operator with `InstructionDefinition:Write`
    /// can otherwise publish an arbitrary definition (carrying a plugin
    /// invocation) that executes on every targeted agent. Wired via
    /// --allow-unsigned-definitions / YUZU_ALLOW_UNSIGNED_DEFINITIONS=1.
    /// Setting true at startup emits the `server.unsigned_definitions_allowed`
    /// audit event + a startup spdlog::warn — exact parity with
    /// `--allow-unsigned-packs`.
    bool allow_unsigned_definitions{false};

    // KEK rotation runaway control (#2530 B5). See kek_routes.hpp and the
    // rotate control-flow comment in server.cpp (secrets_kek_op lock
    // section) for how these two feed the durable checks.
    /// Durable rate limit: a rotate request is refused (`Cooldown`, 429) when
    /// the newest `secrets.kek_meta` row is younger than this, read from the
    /// database server's own clock (not the app host's). This is a
    /// RUNAWAY/ABUSE GUARD against looping automation, NOT a rotation-cadence
    /// setting — default 3600s (1h) is sized for that job and most operators
    /// should never change it. Raising it directly delays EMERGENCY
    /// re-rotation after a suspected key compromise, with no bypass
    /// (`/rewrap` only resumes an already-half-committed rotation; it never
    /// mints a new version) short of a restart with a lower value —
    /// mid-incident. Do not set this to your rotation cadence (e.g. 90d for
    /// "quarterly"): that would leave an operator refused for up to that
    /// long during the one operation this whole surface exists to make fast.
    /// CLI-bounded to [1, 31536000] (365d, main.cpp) as a sanity ceiling
    /// against a fat-fingered value, not an endorsement of setting it that
    /// high. The honest `cooldown_retry_after_ms` this feeds is a uint32
    /// millisecond count; `evaluate_rotate_preconditions`
    /// (kek_rotate_control.hpp) saturates rather than wraps past ~49.7 days,
    /// so the 365d CLI bound is defence-in-depth, not the only thing keeping
    /// the hint honest.
    /// Wired via --kek-min-rotate-interval / YUZU_KEK_MIN_ROTATE_INTERVAL.
    int kek_min_rotate_interval_secs{3600};
    /// Backstop ceiling: a rotate request is refused (`VersionCeiling`, 409)
    /// once the count of non-retired KEK versions reaches this. There is no
    /// retire route (#2525), so raising this above the default is the
    /// supported escape hatch that keeps rotation usable for an install that
    /// has hit the ceiling — an explicit, logged and audited temporary risk
    /// acceptance pending #2525, not a routine tuning knob. Default 32.
    /// Wired via --kek-max-live-versions / YUZU_KEK_MAX_LIVE_VERSIONS.
    int kek_max_live_versions{32};
};

/// Trim leading/trailing ASCII whitespace (space/tab/CR/LF). Used to
/// normalize operator-supplied config values that are compared for EXACT
/// string equality against IdP-attested data — a trailing space from a
/// copy-pasted CLI arg would otherwise silently and permanently prevent any
/// match (currently: SamlConfig's admin-group flag, UP-4). Pure/free so it is
/// directly unit-testable without constructing a Server.
std::string trim_ascii_whitespace(std::string_view s);

/**
 * Server manages inbound agent connections and exposes a management gRPC API.
 */
class Server {
public:
    virtual ~Server() = default;

    [[nodiscard]] static std::unique_ptr<Server> create(Config config, auth::AuthManager& auth_mgr);

    /** Block and serve until stop() is called. */
    virtual void run() = 0;

    /** Graceful shutdown. Thread-safe. */
    virtual void stop() noexcept = 0;

    /** True when run() returned because startup failed (refuse-to-start), so the
     *  caller can exit non-zero — systemd Restart=on-failure / k8s crashloop
     *  detection need a non-zero code, not a silent clean exit. Default false. */
    [[nodiscard]] virtual bool startup_failed() const { return false; }
};

} // namespace yuzu::server
