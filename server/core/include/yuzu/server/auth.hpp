#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}
namespace yuzu::server {
class AuthDB;
class SessionStore;       // HA WS-1/1a — durable operator sessions (Postgres, ADR-2002 §4)
struct SessionRow;        // session_store.hpp — the durable row shape
struct SessionWriteParams; // session_store.hpp — duration-based create params (DB-clock authoring)
} // namespace yuzu::server

namespace yuzu::server::auth {

/// Maximum session token length (64 hex chars = 32 bytes random). Reject longer to prevent DoS.
inline constexpr std::size_t kMaxSessionTokenLength = 64;

/// Maximum API token length (raw token before hashing). Raw tokens can be up to 256 chars.
inline constexpr std::size_t kMaxApiTokenLength = 256;

enum class Role { user, admin };

/// Outcome of re-checking a credential that is already in use — the tri-state a
/// HELD-OPEN connection needs and a request does not.
///
/// Ordinary request auth collapses "definitively gone" and "we cannot reach the
/// store to find out" into one answer, because both mean 401. A long-lived
/// stream cannot: a revocation must cut it immediately, while an unreachable
/// auth store must NOT cut every stream on the fleet at the same instant
/// (ADR-1005 Decision 15(c)/(i), chaos CH-4) — the consumer rides out an
/// indeterminate answer for a bounded grace window instead.
///
/// The underlying type is pinned so this can be opaquely forward-declared by
/// consumers (e.g. `mcp_stream.hpp`) without dragging in this header: a later
/// `: std::uint8_t` here would otherwise silently name a different type in every
/// TU that saw only the forward declaration — an ODR violation with no diagnostic.
enum class CredentialCheck : int {
    kValid,
    kRevoked,       ///< definitive: signed out, expired, revoked, rebound, or absent
    kIndeterminate, ///< the auth store could not answer — NOT evidence of revocation
    /// Valid, but the answer came from a cache — nothing was asked of the
    /// authoritative store on this tick (#2367).
    ///
    /// This exists because "still valid" and "re-confirmed valid" are different
    /// facts to a held-open stream, and conflating them silently extends how
    /// long a stream can outlive its credential. A consumer that treats this as
    /// plain `kValid` and resets its grace clock makes cache residency and the
    /// grace window ADD: the stream rides the cache, and only once the cache
    /// expires does a full FRESH grace window start. The consumer must instead
    /// keep measuring its grace budget from the last AUTHORITATIVE `kValid`, so
    /// total survival past a real confirmation stays bounded by the grace
    /// window however much of it was spent on cached answers.
    ///
    /// Not a denial and not a degradation — the credential IS valid. A consumer
    /// that does not model staleness may safely treat this as `kValid`; it will
    /// simply inherit the additive window described above.
    ///
    /// PRODUCER INVARIANT: every site that returns this must be bounded by a
    /// staleness limit the consumer knows about. `McpStreamPump` clamps its
    /// authoritative floor forward by `Config::revalidate_max_staleness`, which
    /// is wired from the ONE current producer's cache TTL
    /// (`EnginePrincipalStore::kAuthCacheTtl`). A second producer with a longer
    /// window, added without raising that config, would silently over-grant
    /// grace — the clamp would credit a confirmation that never happened.
    kValidStale,
};

struct UserEntry {
    std::string username;
    Role role;
    std::string salt_hex;
    std::string hash_hex;
    /// #1852 — `'local'` for a password-authenticated account (auth.db
    /// migration v6 default; every pre-v6 row and every row created via
    /// `upsert_user` is `'local'`), `'oidc'`/`'saml'`/`'ad'` for a durable
    /// SSO identity auto-provisioned by `AuthDB::upsert_sso_identity`. Not
    /// populated by every list/read path — see the call site's doc comment.
    std::string identity_source{"local"};
    /// Gate 5 chaos-injector CH-1 (#4020 follow-up): a stamp from
    /// `AuthManager::next_role_version_()`'s single PROCESS-WIDE monotonic
    /// counter, taken every time ANY entry (any username) is created or has
    /// `.role` mutated in place - NOT a per-username counter starting at 0.
    ///
    /// #4107 (row-locking rewrite) REMOVED the only code that ever COMPARED
    /// this stamp - `recheck_role_after_credential_check` now serializes via
    /// a real Postgres row lock instead (see that function's header doc),
    /// and no longer reads `pre_check_version` at all. This field is
    /// retained purely as a write-ordering stamp: every writer still bumps
    /// it in lockstep with `.role` (an invariant several reviewers have
    /// checked for and relied on), which is useful for future consumers and
    /// for reasoning about write ordering, but nothing compares it for
    /// correctness today. The history below (why it's process-wide, not
    /// per-username) explains the counter's DESIGN and remains accurate;
    /// just read every "the compare-guard" reference below as "the retired
    /// compare-guard, historical context for why this field is shaped the
    /// way it is."
    ///
    /// Comparing this stamp instead of `.role` itself in the (retired)
    /// recheck compare-guard closed an ABA hole a role-VALUE compare cannot:
    /// a promote-then-demote back to the same role value inside one PBKDF2
    /// window would satisfy a value-equality guard and let a stale read win
    /// over the demote that already landed. A cpp-safety re-review of the
    /// first version of that fix (which used a per-username counter
    /// carried forward across `upsert_user`/reactivate) found that a
    /// PER-USERNAME scheme reopens the identical class through a different
    /// door: `remove_user()` erases the cache entry outright, and
    /// `reactivate_user()`/a fresh cold hydrate then reinstalls a NEW entry
    /// whose counter restarts at a low value (typically 0) - a stale
    /// in-flight call's captured pre-check version could coincidentally
    /// match that reset value. A single process-wide source stamped at
    /// EVERY write (including first creation, not just later mutation) made
    /// any two equal stamps observed by this process mean the exact same
    /// write event, full stop - erase/reinsert included. Only a u64
    /// wraparound (~2^64 writes across every username combined, over one
    /// process's lifetime) could theoretically repeat a stamp, which was
    /// never a realistic concern.
    ///
    /// One creation path is a carve-out, not covered by "every entry is
    /// stamped": `load_config()`'s cfg-file bulk load builds entries directly
    /// and never calls `next_role_version_()`, so a cfg-seeded entry keeps
    /// this field's struct-default `0`. Safe ONLY because
    /// `role_version_epoch_` starts at 1 and can never (re)issue 0 - see that
    /// field's own doc - and because `load_config()` runs boot-only,
    /// single-threaded, strictly before `set_auth_db()` is ever called on the
    /// same `AuthManager` (`main.cpp`), so no in-flight recheck call can exist
    /// yet to capture a stale `pre_check_version` against one of these
    /// entries. A future config-reload feature reusing `load_config()` at
    /// runtime would need to stamp these entries too, or it would reopen
    /// this exact ABA class for cfg-file-seeded accounts.
    std::uint64_t role_version{0};
};

struct Session {
    /// STABLE authorization principal. For local/API-token auth this is the
    /// login username; for OIDC/SSO auth (#1837) this is `"oidc:" + iss +
    /// "#" + sub` — the IdP-issuer-scoped, immutable subject claim — NEVER a
    /// human-readable label. `check_permission`, `reconcile_idp_memberships`,
    /// elevation eligibility, and every audit `principal` field key on THIS
    /// field. Two SSO users who happen to share a display name (or a display
    /// name that later changes, e.g. after a legal name change) must never
    /// collide or resolve to the same principal — see
    /// docs/auth-architecture.md "Stable principal vs. display name".
    std::string username;
    /// Human-readable label for UI/audit-DETAIL rendering only — NEVER used
    /// for authorization or as a map/store key. For local auth this mirrors
    /// `username`; for OIDC/SSO auth this is the IdP `name` claim (falling
    /// back to `email`) at the time of the most recent login, so it tracks
    /// display-name changes without perturbing the stable `username` above.
    std::string display_name;
    Role role;
    /// Absolute session-lifetime ceiling. WALL-CLOCK (`system_clock`) since
    /// HA WS-1/1a (ADR-2002 §4): sessions are durable Postgres rows, so their
    /// lifetime is an absolute wall-clock instant that any replica compares
    /// against, not a per-process monotonic point. The NTP-step resistance the
    /// former `steady_clock` gave is replaced by (a) the DB-primary clock being
    /// a monitored security dependency (WS-11) and (b) the hard wall-clock
    /// ceilings on the elevation/MFA windows below.
    std::chrono::system_clock::time_point expires_at;
    // "local", "oidc", "saml", "api_token", "mcp_token", or "engine_token" (six values —
    // docs/auth-engine-principals-design.md §6; the sixth is minted only by
    // AuthRoutes::synthesize_token_session for a principal_kind="engine" ApiToken).
    std::string auth_source{"local"};
    std::string oidc_sub;             // OIDC subject claim (empty for local auth)
    std::string token_scope_service;  // Non-empty = token scoped to this service
    std::string mcp_tier;             // "readonly", "operator", "supervised", or "" (not MCP)
    /// Discriminator for the session's principal class — "human" (default) or
    /// "engine". In-memory only (no auth.db schema change: token sessions are
    /// synthesized fresh per request, never persisted — see design doc §6).
    /// Set by `synthesize_token_session` from the source `ApiToken::principal_kind`;
    /// every other session-creation site leaves the "human" default. This is the
    /// discriminator the Phase-4/5 self-target destruction guard (§9) keys on —
    /// never infer principal kind from the shape of `username`.
    std::string principal_kind{"human"};

    /// True iff this session authenticates as an ADR-0031 engine principal.
    /// The canonical engine-session discriminator (mirrors the belts in
    /// rest_api_v1.cpp deny_engine_session / mcp_server.cpp
    /// deny_if_engine_session / principal_quota_gate.hpp apply_engine_quota_gate).
    [[nodiscard]] bool is_engine() const {
        return principal_kind == "engine" || auth_source == "engine_token";
    }

    /// Timestamp of the most recent successful MFA proof on this session
    /// (login completion or step-up). Default-constructed sentinel means
    /// "no MFA proof yet". WALL-CLOCK (`system_clock`) since HA WS-1/1a
    /// (durable rows). Compared against
    /// `system_clock::now() - cfg.mfa_step_up_window_secs` by high-risk route
    /// handlers, which fail CLOSED on a backward step (a proof timestamped
    /// AFTER `now` is treated as no proof — see mfa_step_up.cpp). SOC 2 CC6.6 —
    /// see docs/auth-mfa-design.md.
    std::chrono::system_clock::time_point mfa_verified_at{};

    /// JIT admin elevation (SOC 2 CC6.3/CC6.6). When `system_clock::now() <
    /// elevated_until` (AND the window is within the `kMaxElevationWindow` hard
    /// ceiling — see `is_elevated()`), this session's EFFECTIVE role is `admin`
    /// regardless of the base `role` — a time-boxed, justified, MFA-gated
    /// activation set by `POST /api/v1/elevate` (eligibility =
    /// `users.elevation_eligible`). The default-constructed sentinel (epoch)
    /// means "not elevated". WALL-CLOCK since HA WS-1/1a (durable rows); the
    /// former monotonic NTP-step resistance is replaced by the paired
    /// `elevation_issued_at` anchor + `kMaxElevationWindow` ceiling below. See
    /// `effective_role()` and docs/auth-architecture.md "JIT admin elevation".
    std::chrono::system_clock::time_point elevated_until{};

    /// Wall-clock instant the current elevation was GRANTED (the max-delta
    /// anchor, ADR-2002 §4). Paired with `elevated_until`: `is_elevated()`
    /// rejects any elevation whose granted window `elevated_until -
    /// elevation_issued_at` exceeds `kMaxElevationWindow`, so a forward clock
    /// corruption (at grant, or a tampered durable row) cannot push admin
    /// beyond the hard ceiling independent of what `elevated_until` holds. Epoch
    /// sentinel when not elevated; set together with `elevated_until` at every
    /// grant site and cleared together on revoke.
    std::chrono::system_clock::time_point elevation_issued_at{};

    /// Inactivity (idle) timeout support (SOC 2 CC6.3). `last_activity_at` is
    /// bumped toward `system_clock::now()` on authenticated requests when the
    /// idle timeout is enabled (`AuthManager::session_inactivity_ > 0`),
    /// throttled to once per touch-granularity; `validate_session` rejects the
    /// session once `now - last_activity_at` exceeds the window — a sliding
    /// window UNDER the absolute `expires_at`. WALL-CLOCK (`system_clock`) since
    /// HA WS-1/1a: the sliding anchor is a durable row column advanced via
    /// `SessionStore::touch_activity` (which deliberately does NOT bump the
    /// write-generation), so any replica ages the session from the same
    /// absolute instant. `last_activity_persisted_at` throttles the durable
    /// mirror to at most one write per session per kActivityPersistGranularity,
    /// keeping the hot path off a per-request SQL write.
    ///
    /// Both are STAMPED at every session-creation and rehydration site. The `{}`
    /// member-init is the EPOCH, which is fail-closed: an unstamped session
    /// reads as instantly-idle (rejected), never a spurious keep-alive.
    /// **Invariant:** any path that inserts a Session into the validate-cache
    /// (creation OR rehydration from a `SessionRow`) MUST stamp
    /// `last_activity_at`, or the restored session is idle-evicted on its first
    /// validate when the feature is on.
    std::chrono::system_clock::time_point last_activity_at{};
    std::chrono::system_clock::time_point last_activity_persisted_at{};

    // ── Local monotonic adjudication (ADR-2002 §4 DB-clock authority, WS-1/1a) ──
    // Per-request authorization is decided against these steady_clock deadlines,
    // derived ONCE at session mint / cache-populate from the AUTHORITY clock
    // (Postgres `now()` for a durable session, this host's wall clock for the
    // legacy no-store path) by `AuthManager::derive_session_deadlines`. They are
    // immune to local wall-clock skew and steps: a +Nh-skewed replica derives the
    // same REMAINING duration and ages it monotonically. The system_clock fields
    // above stay the AUTHORED ABSOLUTE instants — used for display/audit and as
    // the suspend backstop (a steady_clock deadline is blind to host suspend; a
    // generous wall sanity ceiling on the absolute instant is not — see
    // is_elevated / validate). The `{}` (steady-epoch) sentinel is fail-closed:
    // an underived session reads as instantly-expired / not-elevated / no-proof.
    std::chrono::steady_clock::time_point steady_expires{};        ///< base-lifetime deadline
    std::chrono::steady_clock::time_point steady_elevated_until{}; ///< {} = not (validly) elevated
    std::chrono::steady_clock::time_point steady_last_activity{};  ///< idle slide anchor
    std::chrono::steady_clock::time_point steady_mfa_verified{};   ///< {} = no valid MFA proof
    /// Durable-touch throttle marker — the local MONOTONIC instant this replica
    /// last mirrored `last_activity` to the store (seeded at populate from how
    /// stale the durable row already is). The throttle MUST be steady, not wall:
    /// gating the durable write on `system_clock` vs a DB-authored timestamp
    /// (cross clock domains) lets host skew suppress touches so an actively-used
    /// session idles out on another replica / after failover (adversarial-review
    /// CDX-P1-001) — the very cross-host-skew contract WS-1/1a exists to close.
    std::chrono::steady_clock::time_point steady_last_persisted{};
};

/// Defense-in-depth hard ceiling on any JIT elevation window (ADR-2002 §4).
/// With sessions on wall-clock (durable rows), `is_elevated()` additionally
/// rejects any elevation whose granted window (`elevated_until -
/// elevation_issued_at`) exceeds this bound — so a forward clock corruption at
/// grant time, or a tampered durable row, cannot extend admin beyond it,
/// INDEPENDENT of the per-deployment `--jit-max-elevation-secs` clamp the caller
/// applies at grant. Chosen generously so every legitimate grant (default 1h,
/// config-capped) passes while an implausible far-future value is refused.
inline constexpr auto kMaxElevationWindow = std::chrono::hours(24);

/// Wall-clock sanity tolerance for the suspend backstop (ADR-2002 §4, design-
/// review H5). A steady_clock deadline is blind to host/VM suspend
/// (CLOCK_MONOTONIC pauses), so a cached session could out-live its authored
/// expiry by the suspend duration. The absolute `system_clock` deadline is the
/// backstop, consulted with THIS slack. The tradeoff: a replica whose local wall
/// clock is synced within this slack of the DB primary is never wrongly rejected,
/// and only a gross wall jump past expiry (a long suspend) trips it; but a replica
/// whose wall clock LEADS the DB primary by MORE than this slack WILL fail-CLOSED
/// (spurious 401 / re-auth) on a session in its last (skew − slack). That is
/// deliberate and fail-safe — it requires replicas to be roughly NTP-synced within
/// this slack, which is the operational precondition for the suspend backstop
/// (the steady deadline alone handles arbitrary skew; this only backstops
/// suspend). Bounds suspend over-extension to this slack + the residual, negligible
/// against an 8h session / 24h elevation ceiling.
inline constexpr auto kWallSanitySkew = std::chrono::minutes(5);

/// True iff `s` currently holds an unexpired, in-ceiling JIT admin elevation.
/// Decided against the local MONOTONIC steady deadline derived at populate
/// (ADR-2002 §4 DB-clock authority) — immune to local wall skew/steps — with a
/// generous wall-clock sanity backstop for steady_clock's suspend-blindness. The
/// authored-width ceiling and future-issued rejection are pre-applied when
/// `steady_elevated_until` is derived (derive_session_deadlines); {} means not
/// (validly) elevated.
inline bool is_elevated(const Session& s) {
    if (s.steady_elevated_until.time_since_epoch().count() == 0)
        return false;
    if (std::chrono::steady_clock::now() >= s.steady_elevated_until)
        return false;
    // Suspend backstop: the absolute authored instant, consulted only with the
    // generous slack so a skewed-but-not-suspended replica is unaffected.
    if (s.elevated_until.time_since_epoch().count() != 0 &&
        std::chrono::system_clock::now() > s.elevated_until + kWallSanitySkew)
        return false;
    return true;
}

/// The session's EFFECTIVE legacy role: `admin` while a JIT elevation is active,
/// otherwise the base `role`. THE authorization functions
/// (`require_admin`/`require_permission`/`require_scoped_permission`) must gate
/// on this, never the raw `role`, so an elevated session is treated as admin for
/// the window and auto-reverts when it lapses.
inline Role effective_role(const Session& s) { return is_elevated(s) ? Role::admin : s.role; }

// ── Enrollment tokens (Tier 2) ──────────────────────────────────────────────

struct EnrollmentToken {
    std::string token_id;   // Short display ID (first 8 hex chars)
    std::string token_hash; // SHA-256 hash of the actual token (stored, never raw)
    std::string label;      // Admin-assigned label (e.g. "NYC office rollout")
    int max_uses;           // 0 = unlimited
    int use_count;          // How many times this token has been used
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at; // time_point::max() = never
    bool revoked;
    /// Last agent_id that consumed this token (W1.4 / #827). Populated on
    /// every successful consume so the lost-race audit detail can name the
    /// winner ("already_consumed_by=<agent_id>"). Empty on a freshly-created
    /// token or on a multi-use token before its first consume. Never the
    /// raw token — only the agent_id presented to consume_enrollment_token.
    std::string last_consumed_by_agent_id;
};

/// Typed rejection reason for `AuthManager::consume_enrollment_token`
/// (W1.4 / #827). Naming style matches W1.2's `DeviceTokenValidateError`
/// (snake_case variants) so SIEM filters can grep across both. Variants
/// are operator-facing — they surface in audit `detail` rows and as
/// Prometheus label values; the public wire shape is uniform ("invalid,
/// expired, or exhausted enrollment token") so no token-shape oracle leaks.
enum class EnrollmentTokenError {
    /// Empty / oversize / structurally malformed raw token. Length-bound
    /// enforced at handler entry (W1.1 UP-H2 pattern, > 256 chars → reject).
    invalid_input,
    /// Hash does not match any token in the store.
    not_found,
    /// Token row exists but `revoked = true`.
    revoked,
    /// Token row exists but `now > expires_at`.
    expired,
    /// Token row exists, not revoked, not expired, but `use_count >=
    /// max_uses` at consume time — either it was previously exhausted, or
    /// a concurrent consume won the race for the last available use. The
    /// race-lost case is distinguishable from "stale exhausted" by
    /// comparing `claim_when_consumed.last_consumed_by_agent_id` against
    /// the current presenter; the caller surfaces this in audit detail.
    already_consumed,
    /// Internal error during consume (lock unavailable, persistence
    /// failure). Caller treats as a hard reject and pages SRE.
    internal_error,
};

/// Successful claim returned from `AuthManager::consume_enrollment_token`.
/// Carries enough context for the success-path audit row and for telling
/// "this consume won an actual race" from "this consume was uncontested".
/// `prior_use_count` is the use_count BEFORE this consume — when it's > 0
/// for a max_uses > 1 token, this consume shared the token with prior
/// agents (legitimate multi-use). The token_id is the public-display
/// short ID (8 hex chars), safe to emit in audit detail.
struct EnrollmentClaim {
    std::string token_id;
    int max_uses{0};        // 0 = unlimited
    int use_count_after{0}; // After this consume
    bool single_use{false}; // max_uses == 1 → token is now exhausted
};

/// Maximum raw enrollment token length accepted at handler entry. Raw
/// tokens are 64 hex chars (32-byte CSPRNG output → bytes_to_hex). Tighter
/// than the 256-char W1.1 UP-H2 bound but uses the same `invalid_input_
/// length` audit detail to keep operator filters consistent across the
/// auth surfaces. Rationale: an enrollment token presented over the
/// gRPC Register RPC has no legitimate path that exceeds this bound —
/// anything longer is request-level garbage to be rejected before any
/// SHA-256 / map lookup work.
inline constexpr std::size_t kMaxEnrollmentTokenLength = 256;

/// Maximum agent_id length accepted at handler entry (W1.4 R2 / UP-H1).
/// Caps `RegisterRequest.info.agent_id` at the gRPC Register and gateway
/// ProxyRegister entry, before any audit emission, any auth-mgr lookup,
/// or any SHA-256 work. Without this cap a presenter can supply an
/// arbitrarily long agent_id (the protobuf has no length constraint) and
/// every downstream audit/analytics row carries the full string verbatim,
/// inflating audit-store I/O and SQLite row size into the megabyte range.
/// 256 chars matches `kMaxEnrollmentTokenLength` for parity — any legitimate
/// hostname-derived or UUID-derived agent_id fits in well under 100 chars.
inline constexpr std::size_t kMaxAgentIdLength = 256;

// ── Pending agents (Tier 1) ─────────────────────────────────────────────────

enum class PendingStatus { pending, approved, denied };

struct PendingAgent {
    std::string agent_id;
    std::string hostname;
    std::string os;
    std::string arch;
    std::string agent_version;
    std::chrono::system_clock::time_point requested_at;
    PendingStatus status;
};

class AuthManager {
public:
    static constexpr auto kSessionDuration = std::chrono::hours(8);
    static constexpr int kPbkdf2Iterations = 100'000;
    /// Minimum spacing between best-effort AuthDB `last_activity_at` mirror
    /// writes for one session, so the per-request idle-timeout touch does not
    /// become a per-request SQL write. The in-memory `Session::last_activity_at`
    /// is always fresh; only the durable mirror is throttled. 60 s matches the
    /// AuthDB cleanup-thread cadence.
    static constexpr auto kActivityPersistGranularity = std::chrono::seconds(60);

    /// Load users from config file. Returns false if file missing/corrupt.
    bool load_config(const std::filesystem::path& cfg_path);

    /// Persist current user list to disk.
    bool save_config() const;

    /// Interactive first-run: prompt for admin + user credentials, write config.
    static bool first_run_setup(const std::filesystem::path& cfg_path);

    /// Authenticate; returns session token on success.
    std::optional<std::string> authenticate(const std::string& username,
                                            const std::string& password);

    /// Verify a username+password without creating a session. Returns the
    /// user's legacy role on match, nullopt on failure (unknown user /
    /// bad password / user soft-deleted in AuthDB). Used by the MFA-aware
    /// login flow at AuthRoutes::POST /login to decide between "mint full
    /// session now" (no MFA enrolled) and "issue a pending token, wait
    /// for TOTP" (MFA enrolled). Histogram metrics observed on every call
    /// using the same labels as authenticate().
    std::optional<Role> verify_password(const std::string& username, const std::string& password);

    /// Create a session for a user who has already cleared the password
    /// and any required MFA checks. Mirrors create_oidc_session but with
    /// `auth_source="local"`. If `mfa_verified` is true, stamps
    /// `mfa_verified_at = system_clock::now()` so the step-up window
    /// covers immediate high-risk actions taken right after login.
    ///
    /// Requires the account to already have an AuthDB `users` row when
    /// `auth_db_` is configured: post_mint_role_recheck (see its own doc)
    /// re-reads AuthDB immediately after minting and fails closed - empty
    /// string returned, no session - on ANY read failure, including a
    /// plain UserNotFound (never provisioned, or removed). Every real
    /// production caller (auth_routes.cpp's 3 call sites) is only reached
    /// after a local-auth verify_password() call that already guarantees
    /// the row exists; calling this directly for an account with no row
    /// (e.g. a test synthesizing a session for an OIDC/SCIM-only
    /// principal) will always be denied (#4107 CI finding, 38cc33b88).
    std::string create_local_session(const std::string& username, Role role, bool mfa_verified);

    /// Stamp `mfa_verified_at = system_clock::now()` on the named session.
    /// Returns true if the session existed and was updated. Used by the
    /// /login/mfa/stepup route (PR 2) to mark an already-issued session
    /// as freshly MFA-verified.
    bool mark_session_mfa_verified(const std::string& token);

    /// JIT admin elevation: set `elevated_until = min(now + duration,
    /// session.expires_at)` on the named session, so its effective role is admin
    /// for the window (SOC 2 CC6.3/CC6.6). The window is clamped to the
    /// session's own absolute lifetime — an elevation can never outlive the
    /// cookie session that carries it (residual-risk follow-up B, security
    /// review 2026-06-30). The CALLER is responsible for the eligibility +
    /// MFA-step-up gates; this only mutates the in-memory session. Returns the
    /// absolute (possibly-clamped) expiry `system_clock::time_point` on success
    /// (so the route can report it), nullopt if the session does not exist OR
    /// is already at/past its own `expires_at` (a dead-window guard, governance
    /// hardening round UP-1/UP-4: a session that crosses its absolute lifetime
    /// between validate_session and this call is REJECTED rather than granted a
    /// zero-or-negative-length window — the session is left unmutated, so no
    /// spurious `role.elevation.granted`/`role.elevation.expired` pair). The
    /// caller's nullopt→401 path already covers this. `duration` is assumed
    /// already clamped to the configured `--jit-max-elevation-secs` cap by the
    /// caller; the durable grant additionally stamps `elevation_issued_at` so
    /// the `kMaxElevationWindow` ceiling (auth.hpp) can bound it wall-clock.
    std::optional<std::chrono::system_clock::time_point>
    elevate_session(const std::string& token, std::chrono::seconds duration);

    /// Revoke an active JIT elevation (manual step-down): clear `elevated_until`
    /// on the named session. On success the value is whether the session existed
    /// AND was elevated (so the route can distinguish a real revoke from a
    /// no-op). Returns `unexpected` ONLY when a durable `SessionStore` clear
    /// FAILED — the route MUST fail closed there (the elevation is still live
    /// durably; reporting success would falsely tell an incident responder the
    /// admin was revoked, governance-missed / adversarial C2). Store-less
    /// (legacy) mode never errors.
    [[nodiscard]] std::expected<bool, std::string> revoke_elevation(const std::string& token);

    /// Clear any active JIT elevation on EVERY session of `username` (all
    /// devices). Called when an admin removes a user's elevation eligibility so
    /// an in-flight elevation is terminated immediately — symmetric with the
    /// session wipe on demote/delete (governance UP-1). On success the value is
    /// the number of sessions whose elevation was cleared. Returns `unexpected`
    /// ONLY when the durable `SessionStore` clear FAILED — the route MUST fail
    /// closed (an in-flight elevation may still be live durably; the eligibility
    /// flip alone does not drop it). Store-less (legacy) mode never errors.
    [[nodiscard]] std::expected<int, std::string> revoke_user_elevations(const std::string& username);

    /// Lazily reap a PASSIVELY-lapsed JIT elevation (residual-risk follow-up A,
    /// security review 2026-06-30): if `token`'s session holds an elevation
    /// whose window has elapsed (`elevated_until` set and `now >=
    /// elevated_until`), clears it to the sentinel and returns the session's
    /// username so the caller can emit `role.elevation.expired`. Returns
    /// nullopt when the session does not exist, is oversized, is not elevated,
    /// or its elevation is still live — including when `elevated_until` is
    /// already the sentinel (never-elevated OR already reaped OR manually
    /// revoked via `revoke_elevation`/`revoke_user_elevations`, both of which
    /// also clear to the sentinel — so a manual step-down never ALSO reports a
    /// passive expiry). Clearing on the FIRST observing call makes emission
    /// exactly-once: a second call on the same lapsed window returns nullopt.
    /// Called from `AuthRoutes::resolve_session` (the cookie chokepoint) on
    /// every authenticated request — there is no background reaper thread.
    std::optional<std::string> reap_expired_elevation(const std::string& token);

    /// TEST-ONLY: push `token`'s absolute `expires_at` backward by `offset`
    /// (a positive offset moves it into the past) without sleeping. Governance
    /// hardening round — exercises `elevate_session`'s dead-window guard
    /// (UP-1/UP-4: a session already at/past its own lifetime must be
    /// REJECTED, not granted a zero-or-negative-length elevation). Mirrors
    /// `AgentRegistry::expire_trusted_gateway_for_test`. Production code MUST
    /// NOT call this — no caller in `server/core/src/**` references it. A
    /// no-op if `token` is not a live session.
    void expire_session_for_test(const std::string& token, std::chrono::seconds offset);

    /// TEST-ONLY: installs a callback fired inside
    /// `recheck_role_after_credential_check`, BEFORE it starts its row-locked
    /// AuthDB re-check (`AuthDB::recheck_role_locked`). Originally fired
    /// between an unlocked DB read and a plain `mu_` acquire (Gate 5
    /// chaos-injector's CH-1 window); #4107's row-locking rewrite moved the
    /// firing point earlier, because a hook that synchronously called
    /// `update_role()` at the OLD point would now self-deadlock (this
    /// thread would go on to hold the row lock its own hook is blocked
    /// trying to acquire). A hook that needs to simulate a GENUINE
    /// concurrent write racing the row lock must spawn a separate
    /// `std::thread` to do it (join it before the test ends) - see
    /// `tests/unit/server/test_auth.cpp` for the pattern. Production code
    /// MUST NOT call this - no caller in `server/core/src/**` references it.
    /// A no-op (nullptr) by default.
    void set_role_recheck_race_hook_for_test(std::function<void()> hook);

    /// TEST-ONLY: installs a callback fired INSIDE
    /// `recheck_role_after_credential_check`'s `AuthDB::recheck_role_locked`
    /// callback - i.e. while AuthDB genuinely holds the row lock, immediately
    /// before the in-process cache write. Lets a test spawn a writer thread
    /// here and confirm its `update_role()` call genuinely blocks (proving
    /// the row lock is real, not just documented) before letting this hook
    /// return, which lets the enclosing transaction commit and the writer
    /// unblock. Must NOT synchronously call anything that itself needs this
    /// row's lock (self-deadlock - same reason
    /// `set_role_recheck_race_hook_for_test` moved its own firing point) -
    /// spawn a thread and join it AFTER `recheck_role_after_credential_check`
    /// returns, never inside this callback. Production code MUST NOT call
    /// this - no caller in `server/core/src/**` references it. A no-op
    /// (nullptr) by default.
    void set_role_recheck_inside_lock_hook_for_test(std::function<void()> hook);

    /// TEST-ONLY: installs a callback fired in `authenticate()` (cpp-safety
    /// Gate 8 catch: NOT in `create_local_session()` - that function has no
    /// pre-mint recheck of its own to race against, since its `role`
    /// parameter comes from an EARLIER caller-side check; see the doc on
    /// `test_auth.cpp`'s parameter-based stale-role test for that path's
    /// coverage instead), AFTER the row lock has already been released
    /// (`recheck_role_after_credential_check` has returned) but BEFORE
    /// `persist_new_session` mints the session - i.e. squarely inside the
    /// #4107 check-then-mint window `post_mint_role_recheck` exists to
    /// close. Unlike the two hooks
    /// above, there is no lock held at this firing point, so a hook MAY
    /// safely call `update_role()` (or spawn+join a thread that does)
    /// synchronously and wait for it to fully complete before returning -
    /// this lets a test force a demote to land, fully committed, strictly
    /// inside the gap, with no race/timing dependence at all (deterministic
    /// red/green, unlike the row-lock-blocking test's genuinely-racy
    /// coverage of this same window). Production code MUST NOT call this -
    /// no caller in `server/core/src/**` references it. A no-op (nullptr) by
    /// default.
    void set_post_mint_race_hook_for_test(std::function<void()> hook);

    /// TEST-ONLY: raw `users_` cache peek, bypassing AuthDB entirely (unlike
    /// `get_user_role()`, which is DB-authoritative and so cannot observe
    /// cache staleness at all). Lets a test confirm the version-guard in
    /// `recheck_role_after_credential_check` actually left the cache alone
    /// rather than clobbering it with a stale read (Gate 5 CH-1 regression).
    /// Returns nullopt if the username isn't cached (cold or evicted).
    /// Production code MUST NOT call this - no caller in `server/core/src/**`
    /// references it.
    [[nodiscard]] std::optional<Role> cached_role_for_test(const std::string& username) const;

    /// TEST-ONLY: raw `users_` cache peek of `role_version` - the version-side
    /// twin of `cached_role_for_test`. Returns nullopt if the username isn't
    /// cached. Production code MUST NOT call this - no caller in
    /// `server/core/src/**` references it.
    [[nodiscard]] std::optional<std::uint64_t>
    cached_role_version_for_test(const std::string& username) const;

    /// Derive a cache `Session`'s adjudication deadlines from the DB-authored
    /// timestamps and the AUTHORITY clock `now_ms` (Postgres `now()` for a durable
    /// session; this host's wall clock for the legacy no-store path). Sets the
    /// wall-clock absolutes (display/audit + suspend backstop) and the local
    /// monotonic steady deadlines, CLAMPING every derived remaining so a backward
    /// `now_ms` cannot inflate the lived duration past its authored maximum
    /// (design-review H2). Returns false iff the base lifetime is already past at
    /// `now_ms` (the caller must NOT cache or honor it — H4 underflow guard).
    /// PUBLIC because the clamps are security-critical and unit-tested directly.
    [[nodiscard]] static bool
    derive_session_deadlines(Session& s, std::int64_t created_ms, std::int64_t expires_ms,
                             std::int64_t last_activity_ms, std::int64_t mfa_verified_ms,
                             std::int64_t elevated_until_ms, std::int64_t elevation_issued_ms,
                             std::int64_t now_ms);

    /// Look up a session by cookie token.
    std::optional<Session> validate_session(const std::string& token) const;

private:
    /// Store-backed validate path (HA WS-1/1a): cache-first, then authoritative
    /// `SessionStore::find`, with the same absolute-expiry + idle-timeout gates
    /// as the legacy in-memory path. Only reached when `session_store_` is set;
    /// the store-less deployment keeps the legacy body unchanged. A degraded
    /// authoritative read for an uncached token fails the request (401), never a
    /// silent grant.
    std::optional<Session> validate_session_durable(const std::string& token,
                                                    bool idle_enabled) const;

public:

    /// Destroy a session (logout).
    /// Destroy a session (logout). Returns whether the durable delete
    /// persisted: true when no store is configured OR the durable row was
    /// deleted; FALSE on a durable-delete store error (the local cache is still
    /// erased, but the durable row survives and can rehydrate a valid session on
    /// another replica / from a copied cookie, so the caller MUST NOT report a
    /// clean logout — adversarial-round blocker #3).
    [[nodiscard]] bool invalidate_session(const std::string& token);

    /// Outcome of `invalidate_user_sessions`. The in-memory `count` is the
    /// number of session cookies erased; `db_persisted` is true iff the
    /// AuthDB DELETE returned success (or the deployment is config-file
    /// only and AuthDB is not configured). When `db_persisted=false` the
    /// caller MUST surface the partial outcome in any audit row — a
    /// "success" audit row that hides a DB write failure produces fictional
    /// SOC 2 CC6.3/CC6.6 evidence (Gate 6 COMPL-H1 / authdb-H1 / UP-3).
    struct RevokeResult {
        std::size_t count{0};
        bool db_persisted{true};
    };

    /// Wipe every session for a username, both in-memory and (if AuthDB
    /// is configured) persisted in `auth.db`. The DB DELETE happens
    /// FIRST, outside `mu_`, mirroring the lock-ordering of `remove_user`
    /// and `update_role`. The in-memory wipe runs unconditionally — even
    /// after a DB failure — so the actively-validating session is killed
    /// immediately for the operator's "stop NOW" use case; the caller is
    /// responsible for surfacing `db_persisted=false` so the operator
    /// knows a server restart may resurrect persisted rows.
    ///
    /// Caller is responsible for audit emission; this method does no
    /// logging or event publishing so it can run while the caller holds
    /// unrelated locks.
    [[nodiscard]] RevokeResult invalidate_user_sessions(const std::string& username);

    /// List all configured users (password hashes omitted from caller view).
    std::vector<UserEntry> list_users() const;

    /// Add or overwrite a user.
    bool upsert_user(const std::string& username, const std::string& password, Role role);

    /// Remove a user by name.
    bool remove_user(const std::string& username);

    /// Reactivate a user previously soft-deleted via `remove_user` — the
    /// SCIM v2 PATCH/PUT `active: true` (un-suspend) path (AuthDB::
    /// reactivate_user's the only writer of `is_active = 1` on an existing
    /// row; see its header doc for the full semantics: clears lockout
    /// state, does NOT restore MFA, leaves provisioning_source/role
    /// untouched). Requires AuthDB (config-file-only deployments have no
    /// soft-delete concept to reverse) — returns false without one. On
    /// success, re-reads the row from AuthDB and repopulates the in-memory
    /// `users_` cache (which `remove_user` erased) so `get_user_role` /
    /// `list_users` reflect the reactivated account immediately, without
    /// requiring a fresh login. Returns false if AuthDB reports no such
    /// user (active or not).
    bool reactivate_user(const std::string& username);

    /// Change a user's role. Uses AuthDB if available, otherwise updates in-memory + config.
    /// Returns false if user not found.
    bool update_role(const std::string& username, Role new_role);

    /// Look up a user's legacy role. Returns nullopt if user not found (or,
    /// in AuthDB-backed mode, if the store could not answer - never falls
    /// back to a cached value on a store error). AuthDB-authoritative on
    /// EVERY call when configured (no cache, no cache fallback) - see the
    /// .cpp definition's doc for why (Gate 3 governance BLOCKING finding,
    /// #4020: this is the call auth_routes.cpp's legacy API-token session
    /// synthesis makes on every request, so a stale cached role here was a
    /// live stale-privilege gap after a demotion, independent of
    /// authenticate()/verify_password() entirely). Config-file mode (no
    /// AuthDB) remains cache-only, unchanged.
    std::optional<Role> get_user_role(const std::string& username) const;

    /// Check whether any users are configured.
    bool has_users() const;

    /// Set the AuthDB instance to use for persistence.
    /// If set, user operations go through the DB instead of config file.
    /// If not set, falls back to config file I/O (backwards compatible).
    void set_auth_db(yuzu::server::AuthDB* db) { auth_db_ = db; }

    /// Set the durable session store (HA WS-1/1a, ADR-2002 §4). When set,
    /// operator sessions are written-through to Postgres and validated
    /// against it, with the in-memory `sessions_` map serving as a
    /// generation-gated process-local cache; a session then survives a
    /// core-replica restart/failover and validates on any replica. When
    /// NULL (config-file-only deployments, and unit tests that do not wire
    /// a pool) the legacy in-memory-only behavior is preserved unchanged —
    /// the same optional-backing pattern as `set_auth_db`. Wired at startup
    /// before any request is served.
    void set_session_store(yuzu::server::SessionStore* s) { session_store_ = s; }

    /// True iff a durable SessionStore is set AND reports open. Wired into
    /// /readyz alongside `is_auth_db_ok()`: with sessions durable, a
    /// half-open/failed session store is a readiness failure (the node cannot
    /// mint or validate durable sessions). Returns true in the legacy
    /// in-memory path (no store configured) so the signal only fires on an
    /// actual store failure. Fail-closed like `is_auth_db_ok`.
    bool is_session_store_ok() const noexcept;

    /// Configure the idle (inactivity) session timeout (SOC 2 CC6.3). When > 0,
    /// `validate_session` rejects a cookie session idle longer than `window` and
    /// bumps `last_activity_at` on each authenticated touch. 0 (default)
    /// disables the feature — only the absolute `kSessionDuration` applies.
    /// Wired from Config::session_inactivity_secs at startup.
    void set_session_inactivity(std::chrono::seconds window) { session_inactivity_ = window; }

    /// Non-owning AuthDB pointer (or nullptr if not configured). Exposed
    /// for the MFA-aware login flow at AuthRoutes::POST /login, which
    /// needs to call mfa_status / mfa_verify_login_code without taking
    /// AuthDB as a new constructor parameter. AuthManager remains the
    /// owner of the wiring decision.
    yuzu::server::AuthDB* auth_db_ptr() const noexcept { return auth_db_; }

    /// True iff a configured AuthDB is set AND it reports `is_ready()`.
    /// Wired into /readyz; operators rely on this to detect a corrupt or
    /// half-migrated auth.db without having to scrape spdlog. Returns
    /// true in the legacy config-file-only path (auth_db_ == nullptr is
    /// fine — the deployment isn't using AuthDB) so the readyz signal
    /// only fires on an actual AuthDB integrity failure.
    bool is_auth_db_ok() const noexcept;

    /// Set the metrics registry for emitting login-latency histograms.
    /// Optional; if null, authenticate() emits no metric (used by tests
    /// that don't construct the server's MetricsRegistry).
    void set_metrics_registry(yuzu::MetricsRegistry* m) { metrics_ = m; }

    /// Non-owning MetricsRegistry pointer (or nullptr in test/cli
    /// contexts). Exposed so AuthRoutes can emit MFA-domain counters
    /// without taking MetricsRegistry as another constructor parameter.
    yuzu::MetricsRegistry* metrics_registry() const noexcept { return metrics_; }

    /// Create a session for an externally-authenticated user (OIDC).
    /// Role: admin if user is in the admin group, or email/name matches a local admin.
    ///
    /// `mfa_verified_at` seeds the new session's MFA-proof timestamp. The
    /// caller passes a non-default `system_clock` value only when the IdP
    /// attested a multi-factor login via the `amr` claim (PR3 / SOC 2
    /// CC6.6). A default-constructed value leaves the session un-stepped-up,
    /// so the local step-up gate prompts for a TOTP code on the first
    /// high-risk action. Wall-clock (`system_clock`) since HA WS-1/1a (durable
    /// rows); the step-up window is short and fails CLOSED on a backward clock
    /// step (see mfa_step_up.cpp) — docs/auth-mfa-design.md hard invariant #5.
    ///
    /// #1837 — the session's STABLE `username` (authorization principal) is
    /// derived from `"oidc:" + iss + "#" + oidc_sub`, NOT `display_name`: a
    /// display name is a mutable, IdP-side, human-editable label (two users
    /// can share one, and a rename must not sever an existing user's group
    /// memberships/roles). `iss` is the token issuer that scopes `sub` to a
    /// specific IdP (RFC 7519 — `sub` is only unique per-issuer). `display_name`
    /// is retained on the `Session` purely for human-readable rendering. There
    /// is no persistent principal→display-name directory for rendering a
    /// principal outside a live session (e.g. an admin user list, or audit-row
    /// rendering) — the human name for such a case is recovered from that
    /// specific SSO audit row's `display=`/`email=` detail field instead (see
    /// /auth/callback's `audit_log_for_principal` calls). A durable directory
    /// is tracked in #1852.
    std::string create_oidc_session(const std::string& display_name, const std::string& email,
                                    const std::string& oidc_sub, const std::string& iss,
                                    const std::vector<std::string>& groups = {},
                                    const std::string& admin_group_id = {},
                                    std::chrono::system_clock::time_point mfa_verified_at = {});

    /// Create an ephemeral session for a verified SAML assertion's NameID.
    /// Role: admin if `groups` contains `admin_group` (exact match), user
    /// otherwise — mirrors create_oidc_session's admin_group_id guard exactly.
    /// Both `groups` and `admin_group` default-empty, so an unconfigured
    /// deployment still mints `user` unconditionally (thin-slice-compatible).
    /// The session's `auth_source` is `"saml"`. `last_activity_at` is stamped
    /// per the standing invariant: any new session-creation site MUST stamp it
    /// or the idle-eviction gate will instantly expire the session (auth.hpp §78).
    ///
    /// ADR-2001 PR4a — the session's STABLE `username` (authorization
    /// principal) is `saml::saml_principal_id(entity_id, name_id)`
    /// (`"saml:" + entity_id + "#" + name_id`, saml_principal.hpp), NOT the
    /// raw NameID: mirrors #1837's OIDC split exactly (`oidc_principal_id
    /// (iss, sub)`) — a NameID is only unique per-IdP, so a bare NameID is
    /// unsafe as a durable cross-IdP join key, and the same collision-risk
    /// argument OIDC's split closes applies here. `display_name` stays the
    /// raw `name_id` (human-readable rendering only — dashboard, audit
    /// detail). `entity_id` is the operator-configured, boot-validated IdP
    /// entityID (`Config::saml_idp_entity_id`) — already verified by
    /// `SamlProvider::validate_response` to equal the assertion's signed
    /// `<saml:Issuer>` before this is called (see the ACS handler,
    /// auth_routes.cpp).
    /// `saml_display_name` / `saml_email` are the session-enrichment attribute
    /// values parsed from the same XSW-verified assertion (empty when the
    /// `--saml-name-attribute`/`--saml-email-attribute` flags are unset). They
    /// only derive `Session::display_name` (name -> email -> raw NameID,
    /// mirroring `create_oidc_session`); email is never stored durably, and
    /// neither is ever an identity/authz/SCIM-linkage input.
    std::string create_saml_session(const std::string& name_id, const std::string& entity_id,
                                    const std::vector<std::string>& groups = {},
                                    const std::string& admin_group = {},
                                    const std::string& saml_display_name = {},
                                    const std::string& saml_email = {});

    /// #1852 — auto-provision (or refresh) a durable `users` row for an
    /// OIDC-authenticated principal, so JIT admin elevation (which reads
    /// `auth.db users.elevation_eligible`) has something to key on. Forwards
    /// to `AuthDB::upsert_sso_identity(..., "oidc")` when `auth_db_` is set
    /// (a legacy config-file-only deployment has no durable store — a
    /// silent no-op). `principal` is the stable `"oidc:" + iss + "#" + sub`
    /// form (matches `create_oidc_session`'s construction exactly — pass
    /// the SAME string). Call this AFTER `create_oidc_session` at the route
    /// layer, NOT from inside `create_oidc_session` itself: that method
    /// holds `mu_` for the in-memory session map, and this performs
    /// independent auth.db I/O that must not serialize behind it.
    /// **Fail-soft**: an AuthDB error is logged and swallowed — the
    /// caller's session is already minted and must not be un-minted
    /// because provisioning failed; the principal simply cannot elevate
    /// until a future successful login provisions it. SAML is NOT wired
    /// to this method yet — ADR-2001 PR4a gave SAML a reserved-prefix
    /// stable principal (`saml_principal_id`, see `create_saml_session`),
    /// but no `auth.db` `users` row is ever provisioned for it, so a SAML
    /// session still cannot elevate (JIT elevation's identity-source guard,
    /// auth_routes.cpp, fails closed on the absent row) — that remains a
    /// separate follow-up (docs/auth-architecture.md).
    void provision_sso_identity(const std::string& principal, const std::string& iss,
                                const std::string& sub, const std::string& display_name);

    const std::filesystem::path& config_path() const { return cfg_path_; }

    /// Set an explicit data directory for runtime state files (enrollment
    /// tokens, pending agents). If not set, defaults to cfg_path_ parent.
    void set_data_dir(const std::filesystem::path& dir) { data_dir_ = dir; }

    /// Re-load enrollment tokens and pending agents from the current state_dir().
    /// Call after set_data_dir() to pick up files from the new location.
    void reload_state() {
        load_tokens();
        load_pending();
    }

    // -- Enrollment tokens (Tier 2) ---------------------------------------

    /// Create a new enrollment token. Returns the raw token string (show once).
    std::string create_enrollment_token(const std::string& label, int max_uses,
                                        std::chrono::seconds ttl);

    /// Create multiple enrollment tokens at once for batch deployment.
    /// Returns a vector of raw token strings (each shown once).
    std::vector<std::string> create_enrollment_tokens_batch(const std::string& label_prefix,
                                                            int count, int max_uses_each,
                                                            std::chrono::seconds ttl);

    /// Read-only validity check for a raw enrollment token. Returns true
    /// iff the token exists, is not revoked, is not expired, and still has
    /// at least one use remaining. Does NOT mutate `use_count` and does
    /// NOT update `last_consumed_by_agent_id` — call
    /// `consume_enrollment_token` for the atomic check-and-consume.
    ///
    /// W1.4 R2 / UP-H2 semantic restoration: pre-W1.4 R2 this wrapper
    /// silently delegated to `consume_enrollment_token`, meaning any
    /// "is this token usable" probe would burn a use. That broke the
    /// caller's stated intent (name says "validate") and made
    /// `max_uses=1` tokens unreachable to any caller that wanted to
    /// observe-before-act. Restored to true read-only semantics. The
    /// only callers in-tree are tests; production Register / ProxyRegister
    /// handlers call `consume_enrollment_token` directly so they can
    /// emit the lost-race audit row.
    bool validate_enrollment_token(const std::string& raw_token);

    /// Atomic check-and-consume of an enrollment token (W1.4 / #827).
    ///
    /// **The race the function closes.** The prior `validate_enrollment_
    /// token` returned a bare bool. A second concurrent Register that
    /// presented the same token could pass the validity check before the
    /// first call's `++use_count` landed, allowing a single-use token to
    /// enroll N agents in the race window. This function does the validity
    /// check and the use-count increment under the SAME `unique_lock` so
    /// no second consumer can interleave. The token's `last_consumed_by_
    /// agent_id` is written under the same lock, giving the lost-race
    /// audit row enough context to name the winner.
    ///
    /// **Why an `EnrollmentClaim` on success.** The handler needs the
    /// public token_id (for audit detail), the new use_count (so a
    /// successful multi-use consume can still emit a "M of N uses
    /// remaining" log line), and `single_use` so the response can
    /// summarise the token's lifecycle.
    ///
    /// **Why a typed error on failure.** Audit/metric variant lives in the
    /// typed error; public wire response uniformly says "invalid, expired,
    /// or exhausted enrollment token" so the response shape is the same
    /// regardless of variant. This is the same wire-collapse rule that
    /// W1.3 enforces for `DeviceTokenValidateError` — a presenter cannot
    /// discriminate `not_found` from `already_consumed` (which would tell
    /// them the token existed and someone beat them to it). Operator-
    /// visible variance lives in audit rows + Prometheus counters.
    ///
    /// `consuming_agent_id` is the agent_id presented to Register. It is
    /// written into the token's `last_consumed_by_agent_id` on a winning
    /// consume so a subsequent loser can audit `already_consumed_by=<id>`.
    [[nodiscard]] std::expected<EnrollmentClaim, EnrollmentTokenError>
    consume_enrollment_token(std::string_view raw_token, std::string_view consuming_agent_id);

    /// Look up the most-recent consumer's agent_id for a token (hash-keyed).
    /// Used by the Register handler's lost-race audit emission so the
    /// "already_consumed_by=<X>" detail can name the winning agent without
    /// requiring a second locked traversal in the consume path.
    /// Returns empty string if no record / token not found / never consumed.
    std::string last_consumer_for_token_hash(std::string_view token_hash) const;

    /// List all enrollment tokens (for admin UI).
    std::vector<EnrollmentToken> list_enrollment_tokens() const;

    /// Revoke a token by its token_id.
    bool revoke_enrollment_token(const std::string& token_id);

    // -- Pending agents (Tier 1) ------------------------------------------

    /// Add an agent to the pending approval queue.
    void add_pending_agent(const std::string& agent_id, const std::string& hostname,
                           const std::string& os, const std::string& arch,
                           const std::string& agent_version);

    /// Mark an agent as enrolled (approved). Creates the entry if it doesn't
    /// exist, or sets an existing entry to approved. This ensures reconnecting
    /// agents are recognized without re-enrollment.
    /// Returns false if the agent has been explicitly denied by an admin —
    /// tokens do not override admin denials.
    bool ensure_enrolled(const std::string& agent_id, const std::string& hostname,
                         const std::string& os, const std::string& arch,
                         const std::string& agent_version);

    /// Check if an agent_id is pending, approved, or denied.
    std::optional<PendingStatus> get_pending_status(const std::string& agent_id) const;

    /// List all pending agents (for admin UI).
    std::vector<PendingAgent> list_pending_agents() const;

    /// Approve a pending agent.
    bool approve_pending_agent(const std::string& agent_id);

    /// Deny a pending agent.
    bool deny_pending_agent(const std::string& agent_id);

    /// Remove a pending agent entry (cleanup after enrollment or denial).
    bool remove_pending_agent(const std::string& agent_id);

    // -- Crypto primitives (platform-abstracted) --------------------------

    static std::vector<uint8_t> random_bytes(std::size_t n);
    static std::string bytes_to_hex(const std::vector<uint8_t>& v);
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex);
    static std::string pbkdf2_sha256(const std::string& password, const std::vector<uint8_t>& salt,
                                     int iterations);
    static std::string sha256_hex(const std::string& input);

    /// Constant-time comparison of two hex strings (timing-attack safe).
    static bool constant_time_compare(const std::string& a, const std::string& b);

private:
    static std::string generate_session_token();

    /// Why a `users_` credential lookup produced no entry (#4020): "no such
    /// active row" vs "AuthDB could not answer". Kept distinct so a DB outage
    /// is never logged or counted as a bad username.
    enum class UserLookupMiss { NotFound, DbError };

    /// Look a user up for a credential check, hydrating `users_` from AuthDB on
    /// a cache miss (#4020). `users_` is warmed only by load_config() and by THIS
    /// process's own per-username writes, so a row created anywhere else (a
    /// dashboard `POST /api/settings/users` before a restart, SCIM, another
    /// replica) is invisible to a cache-only lookup - authenticate() and
    /// verify_password() reported "unknown user" for a genuinely active account
    /// until the next cfg-file boot. The AuthDB row is authoritative and the map
    /// is a read-optimisation layered on top (the remove_user / update_role /
    /// reactivate_user contract). PG I/O runs OUTSIDE `mu_`; the insert never
    /// overwrites an entry an in-process write installed while that read was in
    /// flight. Returns a COPY so callers run PBKDF2 without holding `mu_`.
    /// Caller must NOT hold `mu_`.
    [[nodiscard]] std::expected<UserEntry, UserLookupMiss>
    find_user_or_hydrate(const std::string& username);

    /// A fresh, process-wide-unique stamp for `UserEntry::role_version` - see
    /// that field's doc comment. Cheap (single atomic increment), callable
    /// with or without `mu_` held (the counter is independent of it).
    [[nodiscard]] std::uint64_t next_role_version_();

    /// Shared by authenticate()/verify_password(): the post-password-check
    /// re-read of AuthDB (already firing to catch a soft-deleted user) made
    /// authoritative for role too (#4020 Gate 2 adversarial-review/governance
    /// follow-up). Went through several hardening rounds against increasingly
    /// subtle same-process races (compare-by-role-value -> compare-by-version
    /// -> return-value-follows-the-guard -> re-verify-on-divergence -> this
    /// one) - see `git log -p` on this function for the blow-by-blow if the
    /// history matters; this comment describes only the CURRENT mechanism.
    ///
    /// #4107: re-verifies via `AuthDB::recheck_role_locked`, which takes a
    /// `SELECT ... FOR UPDATE` row lock and holds it across the callback
    /// below (where the in-process cache write happens) before committing.
    /// This SERIALIZES against any concurrent `update_role()` write to this
    /// user's row, and against `reactivate_user()` too WHEN the row is
    /// active at read time (authdb Gate 8: `reactivate_user`'s UPDATE has no
    /// `is_active` filter, so it contends for the same lock; but if the row's
    /// last-COMMITTED state is already inactive, its own `is_active = TRUE`
    /// filter excludes it under READ COMMITTED's own snapshot rules,
    /// regardless of whether a `reactivate_user()` happens to be
    /// concurrently uncommitted at that instant - correct fail-closed
    /// denial, not a missed serialization - see `recheck_role_locked`'s own
    /// doc in `auth_db.hpp` for the full asymmetry). This is by construction, not by
    /// detecting a race after the fact - closing the whole class of
    /// same-process divergence residuals every EARLIER version of this
    /// function's version-counter guard could only narrow, never eliminate
    /// (a version counter can tell you something changed since you looked;
    /// it cannot make your look happen atomically with the change). No more
    /// case-2/case-3 split, no more `pre_check_version` comparison - a role
    /// this call observes under the row lock is provably not stale relative
    /// to any OTHER writer's commit, full stop. `pre_check_version` stays in
    /// the signature (now used only by the cfg-file-mode early return above,
    /// which doesn't touch it either) rather than reworking both call sites
    /// in the same round as this rewrite - signature cleanup is a follow-up.
    ///
    /// What this does NOT close: the gap between THIS function returning and
    /// the caller (`authenticate()`/`verify_password()`) actually minting a
    /// session via `persist_new_session` - a separate, later step that is not
    /// itself inside the row lock. A demote committing in that specific
    /// window still mints a stale session, surviving that demote's own sweep
    /// (`update_role`'s `std::erase_if(sessions_, ...)`, which already ran
    /// before the new session existed). External adversarial review
    /// (fjarvis, PR #4076, "C1") named this the "inherent check-then-mint gap
    /// no non-serialized recheck can close" - true of every version of this
    /// function including this one; only serializing all the way through
    /// session creation would close it, which is a materially bigger change
    /// (would need `persist_new_session`, and its own DB write in HA mode, to
    /// run inside the same transaction/lock). This is NOT a same-process-only
    /// gap: Postgres row locks serialize at the DATABASE-ENGINE level, not
    /// per-process or per-connection, so a racing writer from a DIFFERENT
    /// replica sharing the same Postgres primary is serialized against this
    /// function's own row-locked read exactly like a same-process writer
    /// (security-guardian Gate 8 re-review verified this empirically against
    /// a live instance, in both directions - a corrected earlier draft of
    /// this doc wrongly described a separate "cross-replica" residual here;
    /// there isn't one - the check-then-mint window is the one remaining gap,
    /// same mechanism regardless of which process the racing writer runs in).
    /// This is the CURRENT scope of issue #4107 (re-scoped from its original
    /// case-2/case-3 framing, which this commit closes) - `validate_session`
    /// still performs no per-request AuthDB re-verification, so a session
    /// minted via this gap still carries a stale role for its full lifetime,
    /// not one request.
    ///
    /// Returns the current role on success (cfg-file mode, no `auth_db_`,
    /// trivially returns `pre_check_role` unchanged - there's no DB to
    /// re-check against). Returns nullopt if AuthDB reports the user no
    /// longer active (soft-deleted/removed) - in which case the stale cache
    /// entry is ALSO evicted, mirroring remove_user()'s own eviction: a
    /// removal made through a DIFFERENT AuthManager never touches this
    /// process's map, so without this a removed principal stays "active,
    /// role R" forever in any consumer of that stale `users_` entry -
    /// reachable via a still-valid API token, since remove_user() only wipes
    /// sessions, never tokens. (get_user_role() itself is no longer such a
    /// consumer - a later fix made it AuthDB-authoritative on every call,
    /// independent of this eviction entirely.)
    ///
    /// CALLER-SIDE NOTE: every `nullopt` this function returns (store error,
    /// or a genuine `UserNotFound`) is indistinguishable from a genuine bad
    /// password to `verify_password`'s REST caller (`auth_routes.cpp`), which
    /// counts ANY `nullopt` toward the account lockout threshold
    /// (`AuthDB::record_failed_login`). Pre-existing (present since the
    /// original C1 fix), not this round's concern; no new capability for an
    /// attacker (only affects legitimate concurrent operations on the SAME
    /// already-authenticating principal), so LOW availability impact,
    /// disclose-don't-fix is proportionate. Distinguishing "denied by a
    /// detected race, retry" from "wrong password" would need a richer
    /// return type than `std::optional<Role>` threaded through both callers.
    ///
    /// `context` is the log-message prefix ("Auth failed" / "verify_password
    /// failed") so both callers keep their existing distinct wording. Caller
    /// must NOT hold `mu_`.
    [[nodiscard]] std::optional<Role>
    recheck_role_after_credential_check(const std::string& username, Role pre_check_role,
                                        std::uint64_t pre_check_version,
                                        std::string_view context);

    /// Closes the #4107 check-then-mint gap: `recheck_role_after_credential_
    /// check`'s row-locked read (or, for `create_local_session`'s callers, an
    /// even earlier `verify_password()` call) can be stale by the time a
    /// session actually finishes minting - `persist_new_session` is a
    /// separate, later step, not itself inside any row lock. Call this
    /// immediately after a successful `persist_new_session`, passing the
    /// role the just-minted session was stamped with; on divergence (or a
    /// store error) it revokes that session via `invalidate_user_sessions`
    /// and returns `false` - the caller must then treat the mint as denied
    /// (return `nullopt`/`{}` per its own contract), never hand out a token
    /// past this point.
    ///
    /// This is the SAME pattern (mint, then post-mint re-check, then revoke-
    /// and-deny on divergence) `docs/auth-architecture.md` already documents
    /// for the structurally identical OIDC/SAML deprovision-race - chosen
    /// over serializing the mint inside AuthDB's row lock, which that doc's
    /// §3 explicitly rejects for this race class ("never hold one store's
    /// pool lease while calling another" - `SessionStore`'s shared write-
    /// generation row is exactly the cross-store lock that discipline
    /// exists to avoid). See this method's own `.cpp` doc for the ordering
    /// proof that this closes the race rather than merely narrowing it.
    ///
    /// Returns `true` unconditionally in cfg-file mode (`!auth_db_`) - no
    /// separate authority exists to diverge from. Caller must NOT hold `mu_`.
    [[nodiscard]] bool post_mint_role_recheck(const std::string& username, Role minted_role,
                                              std::string_view context);

    /// Backing field for `set_role_recheck_race_hook_for_test` - see that
    /// method's doc. Invoked (if set) from inside
    /// `recheck_role_after_credential_check`.
    std::function<void()> role_recheck_race_hook_for_test_;

    /// Backing field for `set_role_recheck_inside_lock_hook_for_test` - see
    /// that method's doc. Invoked (if set) from inside
    /// `recheck_role_after_credential_check`'s `AuthDB::recheck_role_locked`
    /// callback, i.e. while the row lock is held. Same shape/lifetime/
    /// production-reachability as `role_recheck_race_hook_for_test_` above -
    /// see that field's Resource Ledger entry, which covers this one too.
    std::function<void()> role_recheck_inside_lock_hook_for_test_;

    /// Backing field for `set_post_mint_race_hook_for_test` - see that
    /// method's doc. Invoked (if set) from inside `authenticate()` only
    /// (NOT `create_local_session()` - see the setter's doc), after the row
    /// lock releases but before `persist_new_session`. Same shape/lifetime/
    /// production-reachability
    /// as `role_recheck_race_hook_for_test_` above - see that field's
    /// Resource Ledger entry, which covers this one too.
    std::function<void()> post_mint_race_hook_for_test_;

    /// Backing counter for `next_role_version_()` - see `UserEntry::role_version`'s
    /// doc for why this is process-wide, not per-username. `std::atomic` since
    /// it's drawn from both under `mu_` (most call sites) and without it
    /// (`find_user_or_hydrate`/`reactivate_user` stamp a LOCAL copy before ever
    /// taking `mu_`) - safe either way, since uniqueness comes from `fetch_add`'s
    /// atomicity alone (no two RMWs on one atomic ever observe the same prior
    /// value, independent of memory order) and cross-thread visibility of the
    /// stamped value, once published into `users_`, comes from `mu_` itself, not
    /// from this counter's ordering. Starts at 1, not 0: `load_config()`
    /// (cfg-file bulk load, boot-only, always before `set_auth_db()` - see that
    /// call's doc) seeds entries at the struct default `role_version{0}`
    /// without drawing a stamp at all, and 0 must stay a value this counter can
    /// never (re)issue - historically (pre-#4107) so such an entry's version
    /// could never coincidentally match a stale in-flight caller's
    /// `pre_check_version` in the now-retired recheck compare-guard; kept
    /// unconditionally true today even though nothing compares this value
    /// anymore (see `UserEntry::role_version`'s doc).
    std::atomic<std::uint64_t> role_version_epoch_{1};

    // ── Durable session store integration (HA WS-1/1a) ─────────────────────────
    // These are all no-ops / pure-in-memory when `session_store_ == nullptr`.

    /// SHA-256 (hex) of a raw session token — the SessionStore row key. Secrets
    /// at rest: the store never sees the raw bearer token (session_store.hpp).
    static std::string hash_token(const std::string& raw_token);

    /// Count a degraded durable-session operation on the auth hot path
    /// (yuzu_auth_session_store_degrade_total{op}) so a PG blip/failover is
    /// observable without log-grepping (mirrors the rbac/login degrade
    /// counters). No-op when no MetricsRegistry is wired (tests/CLI).
    void note_session_store_degrade(const char* op) const;

    /// Reconstruct a cache `Session` from a durable `SessionRow` PLUS the DB
    /// clock at read time (`db_now_ms`, from `SessionStore::find`). Sets the
    /// authored wall-clock absolutes AND the local monotonic steady deadlines
    /// (via `derive_session_deadlines`) so is_elevated/idle/MFA read a
    /// fully-formed, DB-clock-adjudicated session (ADR-2002 §4).
    static Session session_from_row(const yuzu::server::SessionRow& row, std::int64_t db_now_ms);

    /// Write-through a newly-created session from DB-clock-authored params: when
    /// a durable store is configured, `create()` FIRST (outside `mu_`, authoring
    /// timestamps from Postgres `now()`) and FAIL CLOSED on a store error — a
    /// login whose session cannot be made durable is not honored (ADR-0007). The
    /// cached `Session` is built from the RETURNED authored times so it matches
    /// the durable row exactly. In the legacy no-store path the timestamps are
    /// authored from this host's wall clock. Returns false on durable-write
    /// failure; always true legacy. Caller must NOT hold `mu_`.
    [[nodiscard]] bool persist_new_session(const std::string& raw_token,
                                           const yuzu::server::SessionWriteParams& params);

    /// Durably delete every session for a username (bumps the generation so all
    /// replicas drop the cached copies). Called from the role-change / demote /
    /// delete paths ALONGSIDE the local-cache wipe, so a stale-role session
    /// cannot survive on another replica or across a restart.
    ///
    /// Returns true when there is nothing durable to fail (no store configured)
    /// OR the durable delete succeeded; FALSE on a durable-delete error. A false
    /// return MUST fail the enclosing role-change/remove operation closed: in
    /// store mode the local `sessions_` erase is only cache eviction — a
    /// cache-missed token is re-served from the authoritative row — so if the
    /// durable delete did not land, the stale-(higher-)role session survives and
    /// the generation was NOT bumped (other replicas keep serving it). Reporting
    /// success there would grant a demoted/removed operator their old privilege
    /// past the change (governance authdb-BLOCKING). `invalidate_user` is
    /// idempotent, so an operator retry after a false return is safe. No-op
    /// (true) without a store. Caller must NOT hold `mu_`.
    [[nodiscard]] bool wipe_user_sessions_durable(const std::string& username);

    /// Poll the durable write-generation on an interval; when it has advanced
    /// (a create/invalidate/elevate/mfa mutation landed, possibly on another
    /// replica), clear the process-local `sessions_` cache so the next lookup
    /// re-reads authoritative state. Interval-gated + single-flight (mirrors
    /// RbacStore::maybe_refresh_generation); a refresh FAILURE keeps serving the
    /// existing cache (the absolute `expires_at` on every session is the
    /// backstop). No-op without a store. Caller must NOT hold `mu_`.
    ///
    /// Coherence does NOT depend on anchoring a locally-committed write: a
    /// mutation bumps the durable generation, so within one refresh interval
    /// this same poll observes the advance and clears the cache, re-reading
    /// authoritative state — write-through to the local cache only covers the
    /// sub-interval window until then.
    void maybe_refresh_session_generation() const;

    /// True when the validate-cache's generation view is too stale to trust — the
    /// generation was never confirmed, OR the last SUCCESSFUL refresh is older
    /// than kSessionGenStaleServeBoundMs (a sustained refresh outage). A cache
    /// hit is served only when this is false; past the bound, validate falls to
    /// the authoritative store and fails closed if it too is degraded (the
    /// rbac_store bounded-stale-serve pattern, ADR-2002 §4). No-op-false without
    /// a store. Takes `session_gen_mtx_`; caller must NOT hold it.
    [[nodiscard]] bool session_generation_view_stale() const;

    /// Persist enrollment tokens to disk.
    bool save_tokens() const;
    /// Load enrollment tokens from disk.
    bool load_tokens();

    /// Persist pending agents to disk.
    bool save_pending() const;
    /// Load pending agents from disk.
    bool load_pending();

    /// Returns the directory for runtime state files.
    std::filesystem::path state_dir() const {
        return data_dir_.empty() ? cfg_path_.parent_path() : data_dir_;
    }

    mutable std::shared_mutex mu_;
    std::filesystem::path cfg_path_;
    std::filesystem::path data_dir_;
    std::unordered_map<std::string, UserEntry> users_;
    // Keyed by the token HASH when a durable store is configured (it is the
    // store row key too), by the raw token in the legacy in-memory-only mode.
    // Serves as the generation-gated validate cache when `session_store_` is set.
    mutable std::unordered_map<std::string, Session> sessions_;

    // Non-owning pointer to AuthDB; if set, persistence goes through DB.
    yuzu::server::AuthDB* auth_db_ = nullptr;

    // Non-owning pointer to the durable SessionStore (HA WS-1/1a). Null =
    // legacy in-memory-only sessions. Set once at startup before serving.
    yuzu::server::SessionStore* session_store_ = nullptr;

    // Validate-cache generation state (guarded by `session_gen_mtx_`, a
    // dedicated mutex so a generation poll never contends on the session-map
    // `mu_`). `cached_session_gen_` is the durable write-generation this
    // replica's `sessions_` cache is coherent with; `session_gen_valid_` is
    // false until the first successful anchor. `last_session_gen_refresh_ms_`
    // interval-gates the poll (single-flight claim, like RbacStore).
    mutable std::mutex session_gen_mtx_;
    mutable std::uint64_t cached_session_gen_ = 0;
    mutable bool session_gen_valid_ = false;
    mutable std::int64_t last_session_gen_refresh_ms_ = 0;
    // steady-ms of the last SUCCESSFUL generation read (bounded stale-serve, the
    // rbac_store pattern). 0 = never succeeded. Read by
    // session_generation_view_stale() to decide when a cache hit is too stale to
    // trust during a refresh outage.
    mutable std::int64_t last_successful_session_gen_refresh_ms_ = 0;

    /// Idle-timeout window (SOC 2 CC6.3). 0 = disabled (absolute expiry only).
    /// Read on the validate_session hot path; set once at startup before any
    /// request is served, so a plain member (no extra lock) is sufficient.
    std::chrono::seconds session_inactivity_{0};

    // Non-owning pointer to MetricsRegistry; null in tests/CLI tools.
    yuzu::MetricsRegistry* metrics_ = nullptr;

    // Enrollment tokens keyed by token_id
    std::unordered_map<std::string, EnrollmentToken> enrollment_tokens_;

    // Pending agents keyed by agent_id
    std::unordered_map<std::string, PendingAgent> pending_agents_;
};

// OS-appropriate default paths.
std::filesystem::path default_config_path();
std::filesystem::path default_cert_dir();

std::string role_to_string(Role r);
Role string_to_role(const std::string& s);

/// Shared group→role resolution for federated (OIDC/SAML) session creation.
/// Security-load-bearing: defaults to `Role::user`; promotes to `Role::admin`
/// ONLY on an EXACT match between `admin_group` and one entry of `groups`.
/// Never matches on NameID/email/display_name — those are attacker-controlled
/// values that ride in the same assertion/claims. `admin_group` empty ⇒
/// always `Role::user` (unconfigured deployment stays thin-slice-compatible).
/// Extracted from create_oidc_session's original guard (byte-equivalent
/// behaviour) and reused verbatim by create_saml_session — do not change
/// this function's semantics without security-guardian review.
Role resolve_role_from_groups(const std::vector<std::string>& groups,
                              const std::string& admin_group);

std::string pending_status_to_string(PendingStatus s);

} // namespace yuzu::server::auth
