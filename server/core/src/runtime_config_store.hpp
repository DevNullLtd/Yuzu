#pragma once

/// @file runtime_config_store.hpp
/// Migrated Postgres store (ADR-0006/0009/0060, schema `runtime_config_store`).
/// Persistent runtime configuration overrides — key/value pairs that override
/// startup defaults (CLI/env). Only a fixed allow-list of keys is accepted
/// (`allowed_keys()`); one of them (`oidc_client_secret`) is a credential.
///
/// **Posture: AUTHORITATIVE / fail-closed (ADR-0012 §1).** Runtime config
/// feeds auth/OIDC behaviour (the startup override pass populates
/// `cfg_.oidc_client_secret`) and DEX alerting config — a silently-empty
/// read on a degraded store is a fail-open, not a benign "nothing
/// configured". `get_all()`/`get()` return `std::expected<..., std::string>`
/// (ADR-0036 typed-read policy) so a genuine DB error is never collapsed
/// into "no overrides set". `get_value()` stays a plain `std::string`
/// convenience wrapper — deliberately NOT widened. Every current call site
/// was audited (kickoff review, 2026-08-25): DEX alert-routing knobs are
/// deny-or-benign (a degraded read just means no routes/defaults, not a
/// security decision).
///
/// `plugin_signing_required` migrated OFF `get_value()` onto `get()` as of
/// #4028's fix round: both its readers (`GET /api/v1/agent/plugin-policy`
/// and the Settings dashboard fragment, `settings_routes.cpp`) now fail
/// the READ closed (503 / a distinct "status unknown" state) on a genuine
/// store error, since the flag's value IS what those two surfaces exist to
/// serve (I3: the caller could not tell a degraded read from a healthy
/// "not required"). This is a display-honesty fix, not an
/// enforcement-bypass fix: the flag itself has never gated a live
/// grant/enforce/skip decision, on this store or any other. **Do not cite
/// `ProductPackStore::require_signed_packs_` as this flag's enforcement
/// backstop** — an earlier fix-round draft did, and it is a different
/// artifact class entirely (`ProductPackStore` gates YAML product-pack
/// content: `InstructionDefinition`/`PolicyFragment`/`Workflow`
/// documents, never a compiled plugin binary). Plugin-binary signature
/// verification, where an agent is configured for it, is local to that
/// agent via its own `--plugin-require-signature`/`--plugin-trust-bundle`
/// flags — entirely independent of this store, confirmed by an `agents/`
/// grep showing no agent code reads this key or this route at all. See
/// `docs/user-manual/rest-api.md`'s "When a change takes effect" table,
/// `plugin_signing_required` row, for the authoritative operator-facing
/// statement of this.
///
/// Substrate contract (ADR-0008): the store holds a `pg::PgPool&` (not a
/// `sqlite3*`), runs its schema migration at construction on a pinned,
/// unbounded, construction-only lease, and schema-qualifies every runtime
/// statement (`runtime_config_store.*`) — pooled connections carry no
/// per-store `search_path`. Mutate-and-return uses `RETURNING` (the
/// #1033-banning idiom), never `sqlite3_changes()`.
///
/// **Secrets (ADR-0010): per-KEY, not per-column — `is_secret_config_key()`
/// decides.** Storage discrimination is a TABLE split, not a nullable
/// column: a secret key's non-empty value lives ONLY in
/// `runtime_config_secrets.sealed_value` (SecretCodec envelope, one row per
/// secret key, `key` as the AAD pk_column — mirrors `PluginConfigStore`'s
/// `configs`/`secrets` split, ADR-3005, the closest existing precedent for
/// "some keys in this namespace are secret, most aren't"); every other
/// value — including an EMPTY secret — lives in the plain `runtime_config`
/// table. `get_all()`/`get()`/`read_secret()` ALL read both tables in ONE
/// statement (`UNION ALL`) and let a `runtime_config_secrets` row win when
/// present (see `set()`'s doc comment for the becomes-secret-later story);
/// `read_secret()` — the only accessor that returns a real decrypted value —
/// falls back to a non-empty plain-table row for the SAME transitional state
/// (never decrypting there, since there is nothing encrypted to decrypt).
/// Presence in `runtime_config_secrets` is still a
/// HARD invariant that the row is never empty, so `set()` never encrypts an
/// empty string — it
/// deletes any stale ciphertext row instead and stores `value=''` in the
/// plain table (same table an empty NON-secret value would use), which is
/// what lets an empty secret keep its `updated_by`/`updated_at`
/// attribution (see the redaction test) without ever holding a live DEK
/// over zero bytes. Own `SecretCodec` instance (ADR-0010 per-store model,
/// AuthDB/PluginConfigStore precedent): the caller constructs one over the
/// shared `FileKeyProvider` and passes it in; this store's constructor
/// registers `runtime_config_secrets.sealed_value` immediately after its
/// own schema migration, and the caller runs `SecretCodec::init()` on a
/// pinned lease right after construction returns (register-before-init).
///
/// **Concurrent `set()` on the SAME secret key is serialized by a
/// transaction-scoped advisory lock** (`pg_advisory_xact_lock(hashtextextended(
/// 'runtime_config_store:secret:' || key, 0))`, taken first inside the
/// transaction, mirrors `ResultSetStore::pin`'s per-owner lock convention).
/// Without it, two concurrent `PUT`s on the same secret key — one clearing
/// it, one setting a real value — could interleave across their independent
/// transactions so the clearing caller received `applied:true` while the
/// concurrently-set secret silently survived (governance Gate 4/5 chaos-
/// confirmed finding, derives HIGH/BLOCKING: I3 wrong-result-presented-as-
/// correct). `set()` on a NON-secret key needs no lock — it is already one
/// atomic `INSERT ... ON CONFLICT` statement.
///
/// **Backfill: SKIPPED unconditionally (ADR-0009's 2026-08-25
/// fresh-start-by-default amendment).** No `migrate_from_sqlite()` — the
/// legacy `runtime-config.db` is never COPIED. No production fleet has
/// ever run a pre-Postgres Yuzu build, so the original per-store-ADR
/// "mandatory backfill for config/reference stores" default assumed a
/// live fleet that has never existed. On cutover the server logs a boot
/// warning (`server.cpp`'s construction site) noting the reset, mirroring
/// `ResponseStore`/ADR-0039's reference shape for the skippable class.
///
/// **Detect-and-warn, per `docs/postgres-store-playbook.md`'s Backfill
/// bullet.** Unlike `ResponseStore` (purely TTL'd telemetry — a silent
/// reset is genuinely benign), this store holds real operator-authored
/// config, so a silent reset would be a fail-open if the "no production
/// fleet" premise ever turns out to be locally wrong. `warn_if_legacy_data_present()`
/// opens the legacy file READ-ONLY (never migrates, never mutates, never
/// moves it aside) purely to check whether it exists and holds any rows;
/// the caller logs a loud, count-bearing warning only when it does —
/// silence is the expected, unremarkable case for a genuinely fresh
/// install (no legacy file, or an empty one), not something to warn
/// about on every start. This check only ever inspects the LEGACY
/// SQLite file — it does not, and cannot, tell whether an operator has
/// already reapplied a warned-about override via Settings, so it
/// deliberately re-warns on EVERY boot the legacy file still holds
/// rows, not only the first one after cutover (an operator who has
/// reapplied every override and wants silence must remove or empty the
/// legacy file — see `docs/user-manual/upgrading.md`'s RuntimeConfigStore
/// section).

#include "config_secret_keys.hpp"
#include "secure_buffer.hpp"
#include "store_errors.hpp"

#include <cstdint>
#include <expected>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

namespace yuzu::server::pg {
class PgPool;
class SecretCodec;
}

namespace yuzu::server {

struct RuntimeConfigEntry {
    std::string key;
    std::string value;
    std::string updated_by;
    int64_t updated_at{0};
};

/// Machine-checkable prefix on every `RuntimeConfigStore` `unexpected()` that
/// represents a genuine DB/lease/crypto failure rather than caller-input
/// validation (unknown key, bad value shape, the redaction-placeholder
/// guard). Callers classify: this prefix -> 503, else -> 400. Aliases the
/// shared `kDbErrorPrefix` (`store_errors.hpp`), not a fresh literal — see
/// `ProductPackStore::kProductPackDbErrorPrefix` / `InstructionStore::
/// kInstructionStoreDbErrorPrefix` for the same convention.
inline constexpr std::string_view kRuntimeConfigDbErrorPrefix = kDbErrorPrefix;

class RuntimeConfigStore {
public:
    /// Borrows the shared pool and the CALLER'S OWN `SecretCodec` instance
    /// (ADR-0010 per-store model — see the file header). Runs the
    /// `runtime_config_store` schema migration on a pinned, unbounded,
    /// construction-only lease, then registers
    /// `runtime_config_secrets.sealed_value` as a secret column. `is_open()`
    /// is false if the lease was empty, the migration failed, or column
    /// registration failed.
    RuntimeConfigStore(pg::PgPool& pool, pg::SecretCodec& secret_codec);

    RuntimeConfigStore(const RuntimeConfigStore&) = delete;
    RuntimeConfigStore& operator=(const RuntimeConfigStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Wire a metrics registry for the read accessors' degrade counter
    /// (`yuzu_server_runtime_config_read_degrade_total{reason}`, matching
    /// ProductPackStore/CustomPropertiesStore's #1675 convention). Set ONCE
    /// during single-threaded startup. A null registry (the default, e.g.
    /// in unit tests) disables emission.
    void set_metrics(yuzu::MetricsRegistry* m) noexcept { metrics_ = m; }

    /// THE READ ACCESSORS BELOW NEVER RETURN A SECRET'S REAL VALUE. Redaction
    /// is decided by `is_secret_key()` on the KEY, not by which table a value
    /// happens to live in — usually the same thing (`runtime_config_secrets`
    /// row presence means a real non-empty value, the table-split invariant —
    /// see `set()`), but NOT always: a becomes-secret-later transitional
    /// state (a stale row still sitting in the plain `runtime_config` table
    /// for a key that IS classified secret today) has a real, non-empty
    /// value there too, and it is redacted just the same — never decrypted
    /// to redact it, since redaction only needs to know THAT a real value
    /// exists, not what it is. An EMPTY secret is left empty: there is
    /// nothing to protect, and the emptiness is the only set-vs-unset signal
    /// a caller has (`GET /api/config` derives `is_set` from it).
    ///
    /// `unexpected(msg)` (prefixed `kRuntimeConfigDbErrorPrefix`) is a
    /// genuine read failure (lease timeout or query error) — NEVER treat it
    /// as "nothing configured". A caller feeding a grant/enforce/skip
    /// decision from this store must fail closed on it (ADR-0036); the two
    /// production callers today (the boot override pass, `GET
    /// /api/config`) both do.
    ///
    /// `get_all()`, `get()`, AND `read_secret()` all read the plain and
    /// secrets tables in ONE statement (`UNION ALL`), not two separate round
    /// trips — a single statement is one MVCC snapshot, so a concurrent
    /// `set()` moving a key between tables (the becomes-secret /
    /// empty-secret transitions) can never make that key transiently vanish
    /// from any of the three reads. `get_all()`/`get()`: governance Gate 3/4
    /// architect finding on the prior two-SELECT merge, resolved by this
    /// redesign. `read_secret()`: governance Gate 4/5/6 finding (unhappy-
    /// path, chaos-injector, enterprise-readiness — independently re-derived
    /// three times) on its own prior two-sequential-SELECT shape, same
    /// redesign applied. Neither needs a lock: one statement is one
    /// snapshot, so there is no window left to serialize against.

    /// All entries, secrets redacted. Never decrypts — see above.
    [[nodiscard]] std::expected<std::vector<RuntimeConfigEntry>, std::string> get_all() const;

    /// A single config entry, secret redacted. `nullopt` = read fine,
    /// genuinely no override set for this key (use the default). Never
    /// decrypts — see above.
    [[nodiscard]] std::expected<std::optional<RuntimeConfigEntry>, std::string>
    get(const std::string& key) const;

    /// Convenience string getter, secret redacted. NOT typed: a DB error
    /// collapses to "", the same as "key not set" -- see the file header
    /// for why every current call site accepts that (deny-or-benign;
    /// none feeds a live grant/enforce/skip decision). Prefer `get()` for
    /// anything that does.
    [[nodiscard]] std::string get_value(const std::string& key) const;

    /// THE ONLY store method that returns a secret's REAL value. Returns the
    /// zeroizing `SecureBuffer` type, never `std::string` (ADR-0010 §1
    /// "Zeroization" — a plain-`std::string` return was a governance-
    /// blocking finding on this store's first version; see ADR-0060
    /// "Zeroization fix"). `nullopt` = genuinely nothing for this key (a
    /// non-secret key, an unset secret, or an explicitly-cleared secret) —
    /// logged at info ("no stored override"), distinct from the warn-level
    /// read-degrade log on a genuine query/crypto failure, so an operator can
    /// tell "never configured" from "read anomaly" in the boot log.
    /// For a SECRET key with no `runtime_config_secrets` row, the same
    /// single `UNION ALL` statement also carries the plain table's row (if
    /// any), used as a non-empty becomes-secret-later
    /// transitional value (see the file header) and returns THAT — copied,
    /// not decrypted, since it was never encrypted — with a `spdlog::warn`
    /// naming the key. Skipping this fallback would silently apply nothing
    /// while `get_all()` reports the key as `is_set`, the same wrong-result-
    /// presented-as-correct shape the `set()` advisory-lock fix exists to
    /// prevent, reached a different way. ONE legitimate caller today: the
    /// boot override pass, which must apply the real OIDC client secret into
    /// `Config::oidc_client_secret` — itself a plain `std::string` by
    /// pre-existing design (populated identically from `--oidc-client-secret`),
    /// so the caller's own copy-out is the point where zeroization ends;
    /// keep that copy as tight in scope as `WebhookStore::deliver_one`'s
    /// signing-secret use (decrypt, use immediately, let the buffer's
    /// destructor wipe it — never store the `SecureBuffer` itself past the
    /// copy). Any FUTURE caller needing a real secret uses this, never
    /// `decrypt_sealed_value`'s old `std::string`-returning shape (removed).
    [[nodiscard]] std::expected<std::optional<SecureBuffer>, std::string>
    read_secret(const std::string& key) const;

    /// Set a config value. Returns an error if the key is not in the
    /// allow-list, if validation fails, or if the value is the redaction
    /// placeholder for a secret key. `unexpected(msg)` prefixed
    /// `kRuntimeConfigDbErrorPrefix` is a genuine DB/crypto failure (503 at
    /// the REST seam); anything else is caller-input validation (400).
    ///
    /// For a secret key, this is also the ONLY path that materializes the
    /// becomes-secret-later transform: a non-empty value is encrypted and
    /// written to `runtime_config_secrets`, and any stale plaintext row for
    /// the same key in `runtime_config` (left over from before the key was
    /// classified secret) is deleted in the SAME transaction. An empty value
    /// does the reverse: any `runtime_config_secrets` row is deleted, and
    /// `runtime_config` gets `value=''` (so `updated_by`/`updated_at`
    /// survive an explicit clear).
    ///
    /// [[nodiscard]] deliberately: discarding this used to be harmless
    /// because the only failure was an unknown key, which no in-tree caller
    /// could produce. The placeholder guard made it reachable, and a caller
    /// that ignored it reported "saved" for a write the store refused --
    /// with the live in-memory config already updated, so the two diverged
    /// and a restart silently healed it.
    [[nodiscard]] std::expected<void, std::string> set(const std::string& key,
                                                        const std::string& value,
                                                        const std::string& updated_by);

    /// Delete a config override (revert to default). Removes any row for
    /// `key` from BOTH `runtime_config` and `runtime_config_secrets` --
    /// exactly one is ever populated under normal operation, but a
    /// transitional becomes-secret-later state can have a stale row in
    /// each. Returns true if either delete removed a row.
    bool remove(const std::string& key);

    /// Detect-and-warn obligation (`docs/postgres-store-playbook.md`'s Backfill
    /// bullet, ADR-0009 fresh-start-by-default): does the legacy
    /// `runtime-config.db` at `legacy_db_path` hold real operator overrides
    /// this cutover will NOT carry over? Read-only — never migrates, mutates,
    /// or moves the file; logs the finding itself (the caller has nothing to
    /// branch on). Three outcomes, each logged distinctly: the file does not
    /// exist (silent — a genuine fresh install, the unremarkable case, not
    /// worth a line on every boot); the file exists but cannot be opened or
    /// queried (`spdlog::warn` — corrupt/permission-denied is exactly the
    /// case detection cannot silently wave through, since a real override
    /// could be trapped behind it); the file opens and its `runtime_config`
    /// table has zero rows (silent — genuinely nothing to lose); the table
    /// has N > 0 rows (`spdlog::warn` with the count — the case this
    /// obligation exists for).
    static void warn_if_legacy_data_present(const std::filesystem::path& legacy_db_path);

    /// Check if a key is in the allow-list of safe runtime-configurable keys.
    static bool is_allowed_key(const std::string& key);

    /// True if this key's VALUE is a credential and must never be emitted in
    /// plaintext - not to a log, not to an API response, not to an audit detail, not
    /// to a config dump. Prefer get_all(), which applies this for you; consult the
    /// predicate directly only where the value does not come from the store (the
    /// PUT handler audits a caller-supplied value, which is the path that leaked
    /// past the first version of this fix).
    static bool is_secret_key(const std::string& key);

    /// What to print in place of a secret. Delegates to the shared leaf so there is
    /// exactly one spelling in the tree (see config_secret_keys.hpp).
    static const char* redacted_placeholder() { return kRedactedPlaceholder; }

    /// Returns the list of allowed config keys.
    static const std::vector<std::string>& allowed_keys();

private:
    pg::PgPool& pool_;
    pg::SecretCodec& secret_codec_;
    bool open_{false};
    yuzu::MetricsRegistry* metrics_{nullptr};
};

} // namespace yuzu::server
