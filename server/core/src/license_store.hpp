#pragma once

/// @file license_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0048, schema `license_store`) for product license
/// activations and their derived alerts (capability 22.3). Two tables, no foreign keys —
/// `license_alerts.license_id` is a soft reference, preserved exactly from the pre-migration
/// SQLite schema.
///
/// **This store is DELIBERATELY DORMANT on `dev`** (ADR-0048 Context): nothing in `server.cpp`
/// constructs a `LicenseStore`, and `rest_api_v1.{hpp,cpp}` registers `/api/v1/license*` routes
/// only `if (license_store)`. Re-wiring construction is out of scope for this migration — this
/// file migrates the persistence layer only.
///
/// Posture (ADR-0012 §1): AUTHORITATIVE / fail-hard, both construction and runtime. The
/// database is the source of truth for license entitlement — a silently-empty
/// `get_active_license`/`has_feature` would silently drop licensed features, so every
/// reader/mutator returns `std::expected<..., std::string>` (ADR-0036 type-distinguishability).
/// Every genuine DB/lease failure is prefixed `kLicenseDbErrorPrefix`; `rest_api_v1.cpp`'s
/// `license_error_status` classifies `not_found: ` -> 404, that prefix -> 503, else -> 400.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a `sqlite3*`), runs its
/// schema migration at construction on a pinned lease, and schema-qualifies every runtime
/// statement (`license_store.licenses` / `license_store.license_alerts`) — pooled connections
/// carry no per-store search_path. Mutate-and-return uses `RETURNING`, never
/// `sqlite3_changes()`.
///
/// Secrets (ADR-0010): `license_key_hash` is a SHA-256 verify-only hash — the raw license key is
/// never persisted. No `SecretCodec` involvement (hash-only, not envelope-encrypted).
///
/// `migrate_from_sqlite()` retired (chore/retire-migrate-from-sqlite-batch-b, #3623): no
/// production fleet ever ran a pre-Postgres build of this store, and this store additionally had
/// zero production callers at all (DORMANT, above) — its `sqlite_backfill_source` marker table
/// was never created in any real database, so removal edited migration v1 in place rather than
/// version-bumping (see ADR-0048's Update).

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// Machine-checkable prefix on every `LicenseStore` `unexpected()` that represents a genuine
/// DB/lease failure rather than caller-input validation or a not-found/business-rule error
/// (mirrors `AccessReviewStore`'s `"not_found: "` idiom and `DeploymentStore`'s
/// `kDeploymentDbErrorPrefix` — deliberately a SEPARATE constant, not a shared one: see
/// ADR-0048 "Considered and rejected"). Exported here so `rest_api_v1.cpp`'s classifier and
/// this store's own error sites can never silently drift apart.
inline constexpr const char* kLicenseDbErrorPrefix = "db_error: ";

/// One activated license.
struct License {
    std::string id;
    std::string organization;
    int64_t seat_count{0};
    int64_t seats_used{0}; // computed by the caller at render time; never set by this store
    int64_t issued_at{0};
    int64_t expires_at{0}; // 0 = perpetual
    std::string edition;   // "community", "professional", "enterprise"
    std::string features_json; // JSON array of feature flags
    std::string status;        // "active", "expired", "exceeded", "invalid"
};

/// One license-lifecycle alert (expiry/seat-limit warning, or a terminal expired/exceeded
/// notice). `id` is a Postgres-assigned surrogate — see the header doc's backfill note for why
/// legacy SQLite AUTOINCREMENT values are not preserved across migration.
struct LicenseAlert {
    int64_t id{0};
    std::string license_id; // soft reference — no FK
    std::string alert_type; // "expiry_warning", "seat_limit_warning", "expired", "exceeded"
    std::string message;
    int64_t triggered_at{0};
    bool acknowledged{false};
};

class LicenseStore {
public:
    /// Borrows the shared pool and runs the `license_store` schema migration on a pinned lease.
    /// `is_open()` is false if the lease was empty or the migration failed.
    explicit LicenseStore(pg::PgPool& pool);

    LicenseStore(const LicenseStore&) = delete;
    LicenseStore& operator=(const LicenseStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Validates `license_key`/`license.organization` are non-empty, hashes the key (SHA-256,
    /// never persisted raw), mints an id if `license.id` is empty, and inserts atomically via
    /// `ON CONFLICT (license_key_hash) DO NOTHING RETURNING id` — a duplicate key is detected by
    /// the conflict itself, not a separate check-then-insert race. Returns the license id, or
    /// `unexpected(msg)` on a validation failure, a duplicate key, or a write error (the last
    /// prefixed `kLicenseDbErrorPrefix`).
    [[nodiscard]] std::expected<std::string, std::string>
    activate_license(const License& license, const std::string& license_key);

    /// Every license, newest-activated first. `unexpected(msg)` (prefixed
    /// `kLicenseDbErrorPrefix`) is a genuine read failure; a license-free store still returns
    /// success with an empty vector.
    [[nodiscard]] std::expected<std::vector<License>, std::string> list_licenses();

    /// The most recently activated license with `status = 'active'`, if any. `nullopt` = a
    /// successful read finding none; `unexpected(msg)` = a genuine read failure — never treat
    /// the latter as "no license" (ADR-0036: a silently-empty read here would silently drop
    /// licensed features).
    [[nodiscard]] std::expected<std::optional<License>, std::string> get_active_license();

    /// Deletes the license and its alerts atomically (one transaction — never a partial
    /// delete). `unexpected("not_found: ...")` when no license with this id exists; any other
    /// `unexpected(msg)` (prefixed `kLicenseDbErrorPrefix`) is a genuine write failure.
    [[nodiscard]] std::expected<void, std::string> remove_license(const std::string& id);

    /// Recomputes status (active/expired/exceeded) and emits alerts for every currently-active
    /// license against `current_agent_count`, atomically — one transaction per call, so a
    /// partial failure never leaves some licenses recomputed and others not.
    /// `unexpected(msg)` (prefixed `kLicenseDbErrorPrefix`) is a genuine read/write failure.
    [[nodiscard]] std::expected<void, std::string> validate(int64_t current_agent_count);

    /// The most recently activated license's status, or `"unlicensed"` if none exists (a
    /// genuine, successful answer — not an error). `unexpected(msg)` (prefixed
    /// `kLicenseDbErrorPrefix`) is a genuine read failure.
    [[nodiscard]] std::expected<std::string, std::string> get_status();

    /// Every alert, optionally filtered to unacknowledged-only, newest-triggered first.
    /// `unexpected(msg)` (prefixed `kLicenseDbErrorPrefix`) is a genuine read failure.
    [[nodiscard]] std::expected<std::vector<LicenseAlert>, std::string>
    list_alerts(bool unacknowledged_only = false);

    /// `unexpected("not_found: ...")` when no alert with this id exists; any other
    /// `unexpected(msg)` (prefixed `kLicenseDbErrorPrefix`) is a genuine write failure.
    [[nodiscard]] std::expected<void, std::string> acknowledge_alert(int64_t alert_id);

    /// True iff the most recently activated `active` license's `features_json` array contains
    /// `feature` (exact string match). `unexpected(msg)` (prefixed `kLicenseDbErrorPrefix`) is a
    /// genuine read failure — ADR-0036: a future caller gating a grant/enforce decision on this
    /// must treat that as fail-closed (deny), never fold it into the `false` case.
    [[nodiscard]] std::expected<bool, std::string> has_feature(const std::string& feature);

    /// The most recently activated `active` license's seat count, or 0 if none.
    /// `unexpected(msg)` (prefixed `kLicenseDbErrorPrefix`) is a genuine read failure.
    [[nodiscard]] std::expected<int64_t, std::string> seat_count();

    /// Days remaining on the most recently activated `active` license: 0 for "no active
    /// license", 0 for a perpetual license (`expires_at == 0`), 0 if already expired, else the
    /// whole-day count until `expires_at`. `unexpected(msg)` (prefixed `kLicenseDbErrorPrefix`)
    /// is a genuine read failure.
    [[nodiscard]] std::expected<int64_t, std::string> days_remaining();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
