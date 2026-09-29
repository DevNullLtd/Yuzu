#pragma once

/// @file device_token_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0052, schema `device_token_store`) for device
/// authorization tokens (capability 18.8) — bearer credentials an operator issues, scoped to a
/// device and/or instruction definition. One table, `device_auth_tokens`.
///
/// **This store is DELIBERATELY DORMANT on `dev`** (ADR-0052 Context): nothing in `server.cpp`
/// constructs a `DeviceTokenStore`, and `rest_api_v1.{hpp,cpp}` registers `/api/v1/device-tokens*`
/// routes only `if (device_token_store)`. History (pickaxe): construction was added by
/// `acc6c481a` ("Add T2 capabilities") and removed by `2fcfb95b5` ("Decompose server.cpp god
/// object") — the same two commits that produced `LicenseStore` (ADR-0048) and
/// `SoftwareDeploymentStore`'s (ADR-0051) dormancy. This store is UNWIRED, not never-wired.
/// Re-wiring construction is out of scope for this migration — this file migrates the
/// persistence layer only.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and runtime. This is an
/// auth-credential store — a silently-empty/false read or a silently-swallowed revoke would be
/// an auth bypass (a stale token treated as still valid, or a revocation an operator issued
/// never taking effect) — so every reader/mutator returns `std::expected<..., std::string>`.
/// `validate_token`'s typed `RejectedToken`/`DeviceTokenValidateError` contract (see below) is
/// preserved EXACTLY — `device_token_rejection.hpp`'s wire-boundary-collapse contract depends on
/// it unchanged. Every genuine DB/lease failure is prefixed `kDeviceTokenDbErrorPrefix`; a PG
/// error reaching `validate_token` always collapses to `DeviceTokenValidateError::internal_error`
/// — never a benign rejection reason (that would misrepresent a store fault as a clean
/// deny-with-reason, polluting the not-found/revoked/expired signal audit/SIEM consumers rely
/// on).
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a `sqlite3*`), runs its
/// schema migration at construction on a pinned lease, and schema-qualifies every runtime
/// statement (`device_token_store.device_auth_tokens`) — pooled connections carry no per-store
/// search_path. Mutate-and-return uses `RETURNING`, never `sqlite3_changes()`.
///
/// Secrets (ADR-0010): `token_hash` is a SHA-256 verify-only hash (checked EVP SHA-256 on every
/// platform since #3351 — a prior Windows BCrypt branch is gone; output bytes unchanged) — the
/// raw token is returned once at creation and never persisted. No `SecretCodec` involvement
/// (hash-only, not envelope-encrypted) — this is why this store sits in Wave 3's "verify/hash"
/// row rather than the SecretCodec-gated rows.
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b, #3623): no
/// production fleet ever ran a pre-Postgres build of this store, and this store additionally had
/// zero production callers at all (UNWIRED, above) — its `sqlite_backfill_source` marker table
/// was never created in any real database, so removal edited migration v1 in place rather than
/// version-bumping (ADR-0009's version-bump requirement protects a schema a live database may
/// already have run; that never happened here).

#include <cstdint>
#include <expected>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `DeviceTokenStore` `unexpected()` that represents a genuine
/// DB/lease failure rather than caller-input validation or a not-found/business-rule error
/// (mirrors `LicenseStore`'s `kLicenseDbErrorPrefix` / `SoftwareDeploymentStore`'s
/// `kSwDeployDbErrorPrefix` idiom — a store-local constant, deliberately not shared, per
/// ADR-0048 "Considered and rejected"). Exported here so `rest_api_v1.cpp`'s classifier and this
/// store's own error sites can never silently drift apart.
inline constexpr const char* kDeviceTokenDbErrorPrefix = "db_error: ";

struct DeviceAuthToken {
    std::string token_id;      // Short display ID (prefix of hash)
    std::string name;          // Human-readable label
    std::string principal_id;  // Username who created it
    std::string device_id;     // Scoped to this device (empty = any device)
    std::string definition_id; // Scoped to this instruction definition (empty = any)
    int64_t created_at{0};
    int64_t expires_at{0}; // 0 = never
    int64_t last_used_at{0};
    bool revoked{false};
};

/// Why validate_token failed. The typed enum lets callers attribute rejections
/// in audit rows and Prometheus counters without re-parsing free-form strings.
/// `binding_mismatch` is the #824 case — token presented by an agent that is
/// not the device the token was bound to. SOC 2 CC6.1 + auth-architecture
/// standing invariant "token presenter MUST equal token subject."
///
/// **Wire-boundary contract (#1052, W1.3).** This typed surface is for SIEM
/// and operator-visible metrics ONLY. Every caller that maps the rejection
/// to an HTTP/gRPC response MUST collapse all five variants to a single
/// status code + envelope (`yuzu::server::DEVICE_TOKEN_REJECTION_PUBLIC_*`).
/// Variant-specific status leaks token-existence and binding context to an
/// attacker holding a stolen valid token. See `device_token_rejection.hpp`.
enum class DeviceTokenValidateError {
    /// Empty / malformed raw token, or store closed. Indistinguishable from
    /// not_found at the wire layer to deny token-shape oracles, but separate
    /// here for SIEM filtering.
    invalid_input,
    /// Hash does not match any row in `device_auth_tokens`.
    not_found,
    /// Row exists but `revoked = true`.
    revoked,
    /// Row exists and `expires_at > 0 && now > expires_at`.
    expired,
    /// Row exists, not revoked, not expired, but the stored `device_id` is
    /// empty — a legacy / pre-#824 row that has no enforceable binding. We
    /// refuse to validate such tokens loudly rather than allow any presenter
    /// to pass the empty-comparison short-circuit (W1.2 R2 HIGH-1/HIGH-2).
    /// Operator must re-issue with explicit binding.
    unbound_legacy,
    /// Row exists, not revoked, not expired, stored `device_id` is non-empty,
    /// but the agent presenting the token does not match `device_id` (#824
    /// stolen-token impersonation).
    binding_mismatch,
    /// A store-internal failure prevented validation from reaching a verdict
    /// (e.g. a lease/query failure). Distinct from `not_found` so an internal
    /// fault does not pollute the not-found signal or mislead forensics into
    /// reading a clean miss (#1056). Collapses to the same 401/UNAUTHENTICATED
    /// wire response as every other variant — an internal fault MUST NOT
    /// surface as a 500 differential an attacker could probe.
    internal_error,
};

/// Rich rejection context returned from `validate_token` on failure
/// (#1053, W1.3 prereq). Combines the typed `error` with whatever
/// row context is available WITHOUT requiring the handler to re-SELECT
/// the row (which would (a) add latency and (b) create a timing oracle
/// distinguishing `binding_mismatch` from `not_found`).
///
/// Field population by variant:
///
/// | variant            | token_id | bound_device_id | bound_principal_id |
/// |--------------------|----------|-----------------|--------------------|
/// | invalid_input      | empty    | empty           | empty              |
/// | not_found          | empty    | empty           | empty              |
/// | internal_error     | empty    | empty           | empty              |
/// | revoked            | set      | set             | set                |
/// | expired            | set      | set             | set                |
/// | unbound_legacy     | set      | empty           | set                |
/// | binding_mismatch   | set      | set             | set                |
///
/// `unbound_legacy` deliberately leaves `bound_device_id` empty because
/// the row has empty `device_id` by construction — propagating "" would
/// mislead audit readers into thinking a binding existed.
struct RejectedToken {
    DeviceTokenValidateError error{DeviceTokenValidateError::invalid_input};
    std::string token_id;
    std::string bound_device_id;
    std::string bound_principal_id;
};

class DeviceTokenStore {
public:
    /// Borrows the shared pool and runs the `device_token_store` schema migration on a pinned
    /// lease. `is_open()` is false if the lease was empty or the migration failed.
    explicit DeviceTokenStore(pg::PgPool& pool);

    DeviceTokenStore(const DeviceTokenStore&) = delete;
    DeviceTokenStore& operator=(const DeviceTokenStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Create a new device authorization token. Returns the raw token string (shown once) on
    /// success. `unexpected(msg)` is either caller-input validation (empty principal_id),
    /// CSPRNG exhaustion (message describes the entropy failure — matches the pre-migration
    /// store's error text so `rest_api_v1.cpp`'s existing CSPRNG-failure classification stays
    /// correct), or a genuine DB/lease failure (prefixed `kDeviceTokenDbErrorPrefix`).
    [[nodiscard]] std::expected<std::string, std::string>
    create_token(const std::string& name, const std::string& principal_id,
                 const std::string& device_id, const std::string& definition_id,
                 int64_t expires_at);

    /// Validate a raw token. Returns the DeviceAuthToken on success, or a
    /// rich `RejectedToken` (typed error + bound context) on rejection.
    /// `presenting_agent_id` is the agent_id the caller has authenticated
    /// by an independent channel (TLS client cert subject, gateway-side
    /// agent identity, etc.) and is matched against the token's `device_id`
    /// (#824 — prevents a stolen token being replayed by a different agent).
    ///
    /// As of W1.2 R2 (HIGH-1/HIGH-2) tokens with empty stored `device_id`
    /// are rejected with `unbound_legacy` rather than treated as any-device,
    /// so a pre-#824 row cannot be replayed from any presenter. Operators
    /// wanting a legitimate any-device token must opt in via a future
    /// explicit API. Callers MUST NOT silently treat an empty
    /// `presenting_agent_id` as "skip the check" — that recreates the #824
    /// vulnerability.
    ///
    /// **#1053 rich-rejection contract (W1.3).** On `binding_mismatch`,
    /// `revoked`, `expired` we populate `bound_device_id` and
    /// `bound_principal_id` so the handler can emit a complete audit row
    /// (`presenter=X bound=Y bound_principal=Z`) WITHOUT a second SELECT.
    /// A second SELECT would (a) add latency and (b) create a timing
    /// oracle distinguishing `binding_mismatch` from `not_found`. See
    /// `RejectedToken` doc for per-variant population.
    ///
    /// Runs the read (row-locked, `SELECT ... FOR UPDATE`) and the accepted-path
    /// `last_used_at` bump in one transaction — the PG equivalent of the pre-migration store's
    /// single-critical-section discipline (avoids a TOCTOU window where a concurrent
    /// `revoke_token` could slip between the read and the write).
    [[nodiscard]] std::expected<DeviceAuthToken, RejectedToken>
    validate_token(const std::string& raw_token, const std::string& presenting_agent_id);

    /// Every token, optionally filtered by principal_id, newest-created first. `unexpected(msg)`
    /// (prefixed `kDeviceTokenDbErrorPrefix`) is a genuine read failure — never treat it as "no
    /// tokens" (ADR-0036: an operator token-management view silently rendering empty on a DB
    /// blip is misleading, not merely degraded).
    [[nodiscard]] std::expected<std::vector<DeviceAuthToken>, std::string>
    list_tokens(const std::string& principal_id = {});

    /// Revoke a token by ID. `unexpected("not_found: ...")` when no token with this id exists;
    /// any other `unexpected(msg)` (prefixed `kDeviceTokenDbErrorPrefix`) is a genuine write
    /// failure — an operator-initiated revoke that silently no-ops on a DB error would leave a
    /// token the operator believes is dead still valid (auth bypass), so this MUST NOT collapse
    /// to a bare `false`.
    [[nodiscard]] std::expected<void, std::string> revoke_token(const std::string& token_id);

    /// Owner-scoped bulk revoke: every still-valid token whose `principal_id` (the operator who
    /// issued it — see `DeviceAuthToken::principal_id`) matches. This is NOT the #823
    /// re-registration defence — that is `revoke_by_device` below, keyed on the column
    /// `validate_token` actually binds a presenter against. `principal_id` and `device_id` are
    /// distinct identities (issuer vs. bearer; #3401): a REST-issued token has `principal_id` =
    /// the operator's username, never an agent_id, so sweeping this method by an agent_id (the
    /// pre-#3401 bug) matches zero rows. No production caller today. Returns the number of rows
    /// newly revoked (0 = no matching tokens or all were already revoked; idempotent) on success.
    /// `unexpected(msg)` (prefixed `kDeviceTokenDbErrorPrefix`) is a genuine write failure.
    /// Empty `principal_id` is a no-op (returns 0) so a forgotten id can't accidentally match the
    /// empty-string default a buggy caller might pass.
    [[nodiscard]] std::expected<int64_t, std::string>
    revoke_by_principal(const std::string& principal_id);

    /// W1.5 / #823, corrected by #3401: revoke every still-valid token bound to `device_id` —
    /// the column `validate_token` actually enforces the presenter against (`presenting_agent_id
    /// != t.device_id`). Called from `AgentRegistry::register_agent` so a re-registration
    /// invalidates any device tokens bound to the previous incarnation of the same agent_id — an
    /// attacker who briefly impersonated the agent (mTLS-disabled flow, #779) could otherwise
    /// replay a previously issued token indefinitely. `revoke_by_principal` above cannot serve
    /// this purpose: REST issuance never writes the agent_id into `principal_id`. Returns the
    /// number of rows newly revoked (0 = no matching tokens or all were already revoked;
    /// idempotent) on success. `unexpected(msg)` (prefixed `kDeviceTokenDbErrorPrefix`) is a
    /// genuine write failure — distinct from a successful "0 revoked" so a caller that gates on
    /// this cannot silently treat "the revoke sweep failed" as "there was nothing to revoke"
    /// (ADR-0036). Empty `device_id` is a no-op (returns 0) — `create_token` permits an empty
    /// `device_id` (unbound token), and this must never sweep the unbound-token population.
    [[nodiscard]] std::expected<int64_t, std::string> revoke_by_device(const std::string& device_id);

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
