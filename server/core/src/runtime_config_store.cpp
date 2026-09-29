#include "runtime_config_store.hpp"
#include "config_secret_keys.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "secure_buffer.hpp"
#include "sqlite_raii.hpp"
#include "utf8_sanitize.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/secure_zero.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <span>

namespace yuzu::server {

// ── Allowed keys (safe for runtime modification) ─────────────────────────────

static const std::vector<std::string> kAllowedKeys = {
    "heartbeat_timeout",             // seconds before marking agent offline
    "response_retention_days",       // days to keep instruction responses
    "audit_retention_days",          // days to keep audit events
    "guardian_event_retention_days", // days to keep guaranteed-state events
    "auto_approve_enabled",          // "true" or "false"
    "log_level",                     // trace|debug|info|warn|error
    "oidc_issuer",                   // OIDC issuer URL
    "oidc_client_id",                // OIDC client ID
    "oidc_client_secret",            // OIDC client secret — SecretCodec-envelope
                                     // encrypted; see runtime_config_secrets (ADR-0060)
    "oidc_redirect_uri",             // OIDC redirect URI
    "oidc_admin_group",              // OIDC admin group ID
    "oidc_skip_tls_verify",          // "true" or "false"
    "plugin_signing_required",       // see plugin_signing::kPluginSigningRequiredKey — must match
    // F1 DEX alerting (Settings → DEX alerts; applied live, no restart)
    "dex_alert_routing",             // JSON array of routed obs_types
    "dex_blast_min_devices",         // blast-radius alert shape (clamped on apply)
    "dex_blast_window_seconds",      //
    "dex_blast_cooldown_seconds",    //
    // F2a PR3 cohort metrics export (Settings → DEX alerts; next gauge sweep)
    "dex_cohort_export_key",         // tag key; "" = export disabled (validated on apply)
};

const std::vector<std::string>& RuntimeConfigStore::allowed_keys() {
    return kAllowedKeys;
}

bool RuntimeConfigStore::is_allowed_key(const std::string& key) {
    return std::find(kAllowedKeys.begin(), kAllowedKeys.end(), key) != kAllowedKeys.end();
}

bool RuntimeConfigStore::is_secret_key(const std::string& key) {
    return is_secret_config_key(key); // the shared leaf; see config_secret_keys.hpp
}

namespace {

constexpr const char* kStoreName = "runtime_config_store";

// Bounded acquires (ADR-0012 §2(a)). Reads/writes here are boot-time and
// admin-Settings-driven — low volume, but never unbounded. Construction is
// the only unbounded acquire.
constexpr std::chrono::milliseconds kAcquireTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{2000};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    //
    // Two tables (ADR-0060): `runtime_config` holds every non-secret value
    // PLUS a secret key's value when it is EMPTY (see the header's "empty
    // secret" note); `runtime_config_secrets` holds a secret key's value
    // ONLY when it is non-empty, envelope-encrypted (ADR-0010) —
    // `sealed_value` is NOT NULL because a row's mere presence there is the
    // "has a real secret" signal, so an empty ciphertext is never written
    // (the store deletes the row instead). No backfill-completion-marker
    // table (ADR-0009's 2026-08-25 fresh-start-by-default amendment): this
    // store skips legacy-SQLite backfill unconditionally, so there is no
    // completion marker to carry.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE runtime_config (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL DEFAULT '',
                updated_by  TEXT NOT NULL DEFAULT '',
                updated_at  BIGINT NOT NULL
            );

            CREATE TABLE runtime_config_secrets (
                key          TEXT PRIMARY KEY,
                sealed_value BYTEA NOT NULL,
                updated_by   TEXT NOT NULL DEFAULT '',
                updated_at   BIGINT NOT NULL
            );
        )"},
    };
    return kMigrations;
}

// ── PG result helpers (file-local — no shared header across stores; mirrors
//    auth_db.cpp / plugin_config_store.cpp / offline_endpoint_store.cpp's own
//    file-local copies) ───────────────────────────────────────────────────

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
std::int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string bytes_to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4) & 0xF]);
        out.push_back(kHex[b & 0xF]);
    }
    return out;
}

std::vector<std::uint8_t> hex_to_bytes(std::string_view hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// Same treatment as TagStore/CustomPropertiesStore/RbacStore (ADR-0041/0045):
// scrub invalid UTF-8 to U+FFFD, then replace any embedded NUL the scrub
// leaves behind — PostgreSQL TEXT can't store NUL and libpq's text-format
// bind C-string-truncates at the first one. Applied to every free-text value.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

RuntimeConfigEntry plain_row(PGresult* r, int i) {
    RuntimeConfigEntry e;
    e.key = col_str(r, i, 0);
    e.value = col_str(r, i, 1);
    e.updated_by = col_str(r, i, 2);
    e.updated_at = to_i64(col(r, i, 3));
    return e;
}

// ── Read-degrade observability (#1675 convention, mirrors ProductPackStore) ──
constexpr const char* kReasonStoreNotOpen = "store_not_open";
constexpr const char* kReasonPoolTimeout = "pool_acquire_timeout";
constexpr const char* kReasonQueryError = "query_error";
constexpr const char* kReasonCryptoError = "crypto_error";
constexpr std::uint64_t kReadDegradeLogSample = 100;
constexpr std::int64_t kDegradeEpisodeGapSecs = 60;

// Per-key advisory lock serializing writers on a single secret key across
// set()/remove(). Shared by both so a clear-vs-set race (governance-found)
// and a concurrent remove-vs-set race can't interleave. Taken unconditionally
// in remove() (cold path, always both tables) but only in set()'s secret-key
// branches (hot path split by key classification) -- same lock id either way.
constexpr const char* kSecretKeyLockSql =
    "SELECT pg_advisory_xact_lock(hashtextextended("
    "'runtime_config_store:secret:' || $1, 0))";

struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};

bool note_read_degrade(yuzu::MetricsRegistry* metrics, const char* reason, DegradeSampler& s) {
    if (metrics)
        metrics->counter("yuzu_server_runtime_config_read_degrade_total", {{"reason", reason}})
            .increment();
    const std::int64_t now = now_secs();
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    const bool new_episode = prev == 0 || (now - prev) > kDegradeEpisodeGapSecs;
    return new_episode || (n % kReadDegradeLogSample) == 0;
}

// One sampler per distinct read call site (a shared sampler would let a hot get_all()
// degrade mask a cold get()/read_secret() one from ever logging).
DegradeSampler g_get_all_sampler;
DegradeSampler g_get_sampler;
DegradeSampler g_read_secret_sampler;

} // namespace

// ── Constructor ───────────────────────────────────────────────────────────

RuntimeConfigStore::RuntimeConfigStore(pg::PgPool& pool, pg::SecretCodec& secret_codec)
    : pool_(pool), secret_codec_(secret_codec) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded. The playbook names this
    // sequence "the open_with_migrations helper", but no such helper exists
    // anywhere in the tree — every store (offline_endpoint_store.cpp,
    // auth_db.cpp, plugin_config_store.cpp, tag_store.cpp) hand-rolls this
    // exact acquire/run/release sequence; this mirrors that precedent.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("RuntimeConfigStore: no database connection at construction ({}) — "
                      "runtime config disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("RuntimeConfigStore: schema migration failed — runtime config disabled");
        return;
    }
    lease.reset(); // release before touching the codec (never hold a lease across other work)

    // ADR-0010 register-before-init sequencing (playbook §3 / AuthDB /
    // PluginConfigStore precedent): this ctor registers the column; the
    // CALLER runs secret_codec.init() immediately after this ctor returns.
    if (!secret_codec_.register_secret_column(
            {kStoreName, "runtime_config_secrets", "sealed_value", "key"})) {
        spdlog::error("RuntimeConfigStore: failed to register runtime_config_secrets.sealed_value "
                      "as a secret column — runtime config disabled");
        return;
    }

    open_ = true;
    spdlog::info("RuntimeConfigStore: opened (schema {})", kStoreName);
}

// ── Queries ──────────────────────────────────────────────────────────────────

namespace {

std::expected<SecureBuffer, std::string>
decrypt_sealed_value(pg::SecretCodec& codec, const std::string& key, const char* hex) {
    const auto bytes = hex_to_bytes(hex);
    auto dec = codec.decrypt(pg::SecretCodec::SecretId{kStoreName, "runtime_config_secrets",
                                                        "sealed_value", key},
                             std::span<const std::uint8_t>{bytes.data(), bytes.size()});
    if (!dec.has_value()) {
        spdlog::error("RuntimeConfigStore: decrypt failed for key '{}' ({})", key,
                      pg::SecretCodec::to_string(dec.error().cls));
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                               "secret decrypt failed for key '" + key + "'");
    }
    return std::move(*dec); // SecureBuffer -- ADR-0010 §1, never collapsed to std::string here
}

// True if the row at `i` in a `runtime_config UNION ALL runtime_config_secrets`-shaped
// result is from the secrets side -- the literal `is_secret_row` column selected below.
// Takes the column index explicitly: get_all()'s query carries `key` (5 columns, index
// 4), get()'s single-key query does not (4 columns, index 3), and read_secret()'s
// single-key query carries neither `key` nor `updated_by`/`updated_at` (3 columns, index
// 2) -- a shared hardcoded index silently read past the end of a narrower shape
// (out-of-range column access, caught by the resulting "column number N is out of
// range" libpq warning on every get() call once this landed the first time).
bool row_is_secret(PGresult* r, int i, int col_idx) {
    return std::string(col(r, i, col_idx)) == "t";
}

} // namespace

std::expected<std::vector<RuntimeConfigEntry>, std::string> RuntimeConfigStore::get_all() const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_get_all_sampler))
            spdlog::warn("RuntimeConfigStore: get_all degraded - store not open");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "store not open");
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_get_all_sampler))
            spdlog::warn("RuntimeConfigStore: get_all degraded - pool acquire timeout");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                               "no database connection in time");
    }

    // ONE statement, ONE MVCC snapshot (governance Gate 3/4 architect finding on the
    // prior two-SELECT merge — resolved, not accepted, by folding both tables into a
    // single UNION ALL). Never touches `sealed_value`: a secret's presence in the
    // secrets table is redaction's entire signal (the table-split invariant — see
    // header), so this never decrypts.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT key, value, updated_by, updated_at, false AS is_secret_row "
        "FROM runtime_config_store.runtime_config "
        "UNION ALL "
        "SELECT key, ''::text, updated_by, updated_at, true "
        "FROM runtime_config_store.runtime_config_secrets "
        "ORDER BY key",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_get_all_sampler))
            spdlog::warn("RuntimeConfigStore: get_all degraded - query error");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "database read failed");
    }

    // Two passes over the ONE fetched result set (no second query): plain rows first,
    // then secret rows overwrite -- secrets-table presence always wins (see header),
    // and this makes that true regardless of which side UNION ALL happened to emit
    // first for a given key.
    std::map<std::string, RuntimeConfigEntry> merged;
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        if (row_is_secret(res.get(), i, 4))
            continue;
        merged[col_str(res.get(), i, 0)] = plain_row(res.get(), i);
    }
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        if (!row_is_secret(res.get(), i, 4))
            continue;
        RuntimeConfigEntry e;
        e.key = col_str(res.get(), i, 0);
        // Presence here means non-empty by construction (the invariant) -- redact
        // directly, never decrypt to find out.
        e.value = redacted_placeholder();
        e.updated_by = col_str(res.get(), i, 2);
        e.updated_at = to_i64(col(res.get(), i, 3));
        merged[e.key] = std::move(e);
    }
    // The becomes-secret-later transitional state (see set()'s doc comment): a stale
    // PLAIN-table row for a key that IS classified secret today, left over from before
    // it was added to kSecretKeys or from an older release. is_secret_key() is the
    // actual authority, not which table a value happens to sit in -- redact it here
    // too, or a transitional secret leaks through get_all()/GET /api/config unredacted.
    // No-op on an already-redacted secrets-table entry (placeholder is non-empty) and
    // on a genuinely-cleared secret (value already empty).
    for (auto& [key, e] : merged) {
        if (is_secret_key(key) && !e.value.empty())
            e.value = redacted_placeholder();
    }

    std::vector<RuntimeConfigEntry> out;
    out.reserve(merged.size());
    for (auto& kv : merged)
        out.push_back(std::move(kv.second));
    return out;
}

std::expected<std::optional<RuntimeConfigEntry>, std::string>
RuntimeConfigStore::get(const std::string& key) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_get_sampler))
            spdlog::warn("RuntimeConfigStore: get degraded - store not open");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "store not open");
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_get_sampler))
            spdlog::warn("RuntimeConfigStore: get degraded - pool acquire timeout");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                               "no database connection in time");
    }

    // Same one-statement shape as get_all(), scoped to one key. Never decrypts.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT value, updated_by, updated_at, false AS is_secret_row "
        "FROM runtime_config_store.runtime_config WHERE key = $1 "
        "UNION ALL "
        "SELECT ''::text, updated_by, updated_at, true "
        "FROM runtime_config_store.runtime_config_secrets WHERE key = $1",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_get_sampler))
            spdlog::warn("RuntimeConfigStore: get degraded - query error");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "database read failed");
    }
    if (PQntuples(res.get()) == 0)
        return std::optional<RuntimeConfigEntry>(std::nullopt);

    // Prefer a secrets-side row if (against the invariant) both somehow appear,
    // rather than trusting row order.
    int row = 0;
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        if (row_is_secret(res.get(), i, 3)) {
            row = i;
            break;
        }
    }
    RuntimeConfigEntry e;
    e.key = key;
    e.updated_by = col_str(res.get(), row, 1);
    e.updated_at = to_i64(col(res.get(), row, 2));
    const bool from_secrets_table = row_is_secret(res.get(), row, 3);
    e.value = from_secrets_table ? redacted_placeholder() : col_str(res.get(), row, 0);
    // Transitional-state redaction (see get_all()'s equivalent pass): a plain-table
    // row for a key classified secret today is still a secret, storage lag aside.
    if (!from_secrets_table && is_secret_key(key) && !e.value.empty())
        e.value = redacted_placeholder();
    return std::optional<RuntimeConfigEntry>(std::move(e));
}

std::string RuntimeConfigStore::get_value(const std::string& key) const {
    auto entry = get(key);
    if (!entry.has_value() || !*entry)
        return {};
    return (*entry)->value;
}

std::expected<std::optional<SecureBuffer>, std::string>
RuntimeConfigStore::read_secret(const std::string& key) const {
    if (!open_) {
        if (note_read_degrade(metrics_, kReasonStoreNotOpen, g_read_secret_sampler))
            spdlog::warn("RuntimeConfigStore: read_secret degraded - store not open");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "store not open");
    }

    auto lease = pool_.try_acquire_for(kAcquireTimeout);
    if (!lease) {
        if (note_read_degrade(metrics_, kReasonPoolTimeout, g_read_secret_sampler))
            spdlog::warn("RuntimeConfigStore: read_secret degraded - pool acquire timeout");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                               "no database connection in time");
    }

    // ONE statement, ONE MVCC snapshot -- same fix as get()/get_all()'s UNION ALL,
    // applied here for the identical reason (governance Gate 4/5/6 finding,
    // independently re-derived three times: unhappy-path, chaos-injector,
    // enterprise-readiness). The prior shape ran two sequential un-transacted
    // SELECTs; a concurrent set() promoting this key to secret could commit
    // entirely between them, so this returned nullopt ("genuinely unset") while a
    // real secret existed -- the same wrong-result-presented-as-correct shape the
    // set()-vs-set() race fix (kSecretKeyLockSql) closed, reached a different way.
    // No lock needed: a single statement cannot observe a torn state.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT encode(sealed_value, 'hex') AS sealed_hex, ''::text AS plain_value, "
        "true AS is_secret_row "
        "FROM runtime_config_store.runtime_config_secrets WHERE key = $1 "
        "UNION ALL "
        "SELECT NULL::text, value, false "
        "FROM runtime_config_store.runtime_config WHERE key = $1",
        std::vector<std::string>{key});
    if (res.status() != PGRES_TUPLES_OK) {
        if (note_read_degrade(metrics_, kReasonQueryError, g_read_secret_sampler))
            spdlog::warn("RuntimeConfigStore: read_secret degraded - query error");
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "database read failed");
    }

    // Prefer the secrets-side row if (against the invariant) both somehow appear --
    // same precedence as get()'s equivalent pass.
    int secret_row = -1;
    int plain_row_idx = -1;
    for (int i = 0; i < PQntuples(res.get()); ++i) {
        if (row_is_secret(res.get(), i, 2))
            secret_row = i;
        else
            plain_row_idx = i;
    }

    if (secret_row >= 0) {
        auto real = decrypt_sealed_value(secret_codec_, key, col(res.get(), secret_row, 0));
        if (!real.has_value()) {
            if (note_read_degrade(metrics_, kReasonCryptoError, g_read_secret_sampler))
                spdlog::warn("RuntimeConfigStore: read_secret degraded - decrypt failed");
            return std::unexpected(real.error());
        }
        return std::optional<SecureBuffer>(std::move(*real));
    }

    // No secrets-table row. For a NON-secret key that's simply "not a secret" --
    // nullopt, no fallback: the plain row fetched above is an ordinary config value,
    // never treated as a secret merely because this function was asked about it.
    if (!is_secret_key(key))
        return std::optional<SecureBuffer>(std::nullopt);

    // Ambiguous by design for a secret-classified key with no secrets-table row:
    // either genuinely unset/cleared, OR the becomes-secret-later transitional state
    // (a stale PLAIN-table row from before this key was classified secret, or from an
    // older release — see set()'s doc comment). Logged at info, distinctly from the
    // warn-level read-degrade calls above: this is "never configured", not a read
    // anomaly, and the two must stay distinguishable in the boot log (compliance-
    // officer, governance Gate 6 rider on this fix).
    std::string value = plain_row_idx < 0 ? std::string{} : col_str(res.get(), plain_row_idx, 1);
    if (value.empty()) {
        spdlog::info("RuntimeConfigStore: read_secret found no stored override for '{}'", key);
        return std::optional<SecureBuffer>(std::nullopt); // genuinely unset or explicitly cleared
    }
    spdlog::warn("RuntimeConfigStore: read_secret for '{}' used a stale PLAINTEXT row "
                "(becomes-secret-later transitional state) -- the next set() envelopes it",
                key);
    SecureBuffer buf{std::span<const std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(value.data()), value.size()}};
    yuzu::secure_zero(value); // this copy already sat in cleartext in the plain
                              // table -- no less protected than before, but don't
                              // leave a second unwiped copy behind here too
    return std::optional<SecureBuffer>(std::move(buf));
}

// ── Mutations ────────────────────────────────────────────────────────────────

std::expected<void, std::string> RuntimeConfigStore::set(const std::string& key,
                                                         const std::string& value,
                                                         const std::string& updated_by) {
    if (!open_)
        return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) + "store not open");

    if (!is_allowed_key(key))
        return std::unexpected("key '" + key + "' is not a configurable runtime setting");

    // The redaction placeholder is not a credential. GET /api/config omits a secret's
    // value precisely so a round-tripping client cannot write this back -- but the
    // startup log prints it, and a human copying that line reaches the same place.
    // Storing it would break SSO and destroy the real secret, so refuse at the sink
    // rather than relying on every caller to notice.
    if (is_secret_key(key) && is_redaction_placeholder(value))
        return std::unexpected("value is the redaction placeholder, not a credential; send the "
                               "real secret, or omit the key to leave it unchanged");

    // Basic validation per key
    if (key == "heartbeat_timeout" || key == "response_retention_days" ||
        key == "audit_retention_days") {
        try {
            int val = std::stoi(value);
            if (val <= 0)
                return std::unexpected("value must be a positive integer");
        } catch (...) {
            return std::unexpected("value must be a valid integer");
        }
    }

    if (key == "auto_approve_enabled" || key == "plugin_signing_required") {
        if (value != "true" && value != "false")
            return std::unexpected("value must be 'true' or 'false'");
    }

    if (key == "log_level") {
        static const std::vector<std::string> valid_levels = {"trace", "debug", "info", "warn",
                                                              "error"};
        if (std::find(valid_levels.begin(), valid_levels.end(), value) == valid_levels.end())
            return std::unexpected("value must be one of: trace, debug, info, warn, error");
    }

    const std::string sanitized_by = sanitize_pg_text(updated_by);
    const auto now = now_secs();

    if (is_secret_key(key)) {
        // Serializes two concurrent set() calls on the SAME secret key (e.g. one
        // clearing it, one setting a real value) across their independent
        // transactions. Without this, the clear branch's DELETE could commit
        // after the set branch's INSERT, leaving the secret intact while the
        // clearing caller was already told `applied:true` (governance Gate 4/5
        // chaos-confirmed finding — see header). Namespaced like
        // ResultSetStore::pin's per-owner lock; released automatically at
        // transaction end, never held past this function.
        if (value.empty()) {
            // Empty-stays-empty (see header): no ciphertext, ever. Clear any
            // stale ciphertext row and record the clear in the plain table so
            // updated_by/updated_at survive.
            const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
                pg::PgResult lk = pg::exec_params(c, kSecretKeyLockSql, std::vector<std::string>{key});
                if (lk.status() != PGRES_TUPLES_OK)
                    return false;
                pg::PgResult del = pg::exec_params(
                    c, "DELETE FROM runtime_config_store.runtime_config_secrets WHERE key = $1",
                    std::vector<std::string>{key});
                if (del.status() != PGRES_COMMAND_OK)
                    return false;
                pg::PgResult up = pg::exec_params(
                    c,
                    "INSERT INTO runtime_config_store.runtime_config (key, value, updated_by, "
                    "updated_at) VALUES ($1, '', $2, $3::bigint) ON CONFLICT (key) DO UPDATE SET "
                    "value = '', updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at",
                    std::vector<std::string>{key, sanitized_by, std::to_string(now)});
                return up.status() == PGRES_COMMAND_OK;
            });
            if (!ok)
                return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                       "database write failed");
        } else {
            // ADR-0010 encrypt-failure semantics: encrypt OUTSIDE any lease,
            // BEFORE any write. A failed encrypt touches nothing. Encrypts
            // the RAW value, never sanitize_pg_text()'d: that helper exists
            // to make free-text safe for a PostgreSQL TEXT column, but
            // `sealed_value` is BYTEA -- there is no storage reason to touch
            // the secret's bytes at all, and doing so silently replaces any
            // embedded NUL byte or invalid-UTF-8 sequence in the credential
            // before it is ever sealed (external adversarial review finding;
            // WebhookStore/PluginConfigStore, this store's own cited
            // precedent for the secrets-table split, both encrypt raw).
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(value.data());
            auto enc = secret_codec_.encrypt(
                pg::SecretCodec::SecretId{kStoreName, "runtime_config_secrets", "sealed_value", key},
                std::span<const std::uint8_t>{bytes, value.size()});
            if (!enc.has_value()) {
                spdlog::error("RuntimeConfigStore::set: encrypt failed for key '{}'", key);
                return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                       "secret encrypt failed");
            }
            const std::string hex = bytes_to_hex(*enc);
            const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
                pg::PgResult lk = pg::exec_params(c, kSecretKeyLockSql, std::vector<std::string>{key});
                if (lk.status() != PGRES_TUPLES_OK)
                    return false;
                pg::PgResult del = pg::exec_params(
                    c, "DELETE FROM runtime_config_store.runtime_config WHERE key = $1",
                    std::vector<std::string>{key});
                if (del.status() != PGRES_COMMAND_OK)
                    return false;
                pg::PgResult up = pg::exec_params(
                    c,
                    "INSERT INTO runtime_config_store.runtime_config_secrets (key, sealed_value, "
                    "updated_by, updated_at) VALUES ($1, decode($2, 'hex'), $3, $4::bigint) "
                    "ON CONFLICT (key) DO UPDATE SET sealed_value = EXCLUDED.sealed_value, "
                    "updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at",
                    std::vector<std::string>{key, hex, sanitized_by, std::to_string(now)});
                return up.status() == PGRES_COMMAND_OK;
            });
            if (!ok)
                return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                       "database write failed");
        }
    } else {
        // Sanitized only here, not up front: the secret-key branches above encrypt
        // the raw value (sealed_value is BYTEA, sanitizing it would silently
        // corrupt an embedded NUL/invalid-UTF-8 byte before sealing -- external
        // adversarial-review finding), so computing this unconditionally would
        // leave a wasted, unwiped near-copy of the credential sitting in the
        // stack frame on every secret set() for no purpose (cpp-expert, governance
        // Gate 3 finding on that fix).
        const std::string sanitized_value = sanitize_pg_text(value);
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease)
            return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                   "no database connection in time");
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "INSERT INTO runtime_config_store.runtime_config (key, value, updated_by, updated_at) "
            "VALUES ($1, $2, $3, $4::bigint) ON CONFLICT (key) DO UPDATE SET "
            "value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, "
            "updated_at = EXCLUDED.updated_at",
            std::vector<std::string>{key, sanitized_value, sanitized_by, std::to_string(now)});
        if (res.status() != PGRES_COMMAND_OK)
            return std::unexpected(std::string(kRuntimeConfigDbErrorPrefix) +
                                   "database write failed");
    }

    // Apply the change immediately
    if (key == "log_level") {
        spdlog::set_level(spdlog::level::from_str(value));
        spdlog::info("Runtime config: log_level changed to '{}'", value);
    }

    return {};
}

bool RuntimeConfigStore::remove(const std::string& key) {
    if (!open_)
        return false;

    bool removed = false;
    const bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* c) -> bool {
        // Unconditional (unlike set()'s secret-key-branch-only lock): remove()
        // always touches both tables regardless of key classification, and is
        // cold-path, so there is no hot-path cost to taking it every time.
        // Same lock id as set()'s secret-key branches -- this is what actually
        // serializes a concurrent remove() against a concurrent set() when
        // `key` classifies as secret. For a NON-secret key, set() never
        // contests this lock (it's a single atomic INSERT ... ON CONFLICT, no
        // lock at all) -- remove() still takes it, but there is nothing on
        // the other side to serialize against for that case. Not a known
        // live race (each side's own statement is independently atomic), but
        // worth its own test as a follow-up rather than assumed safe on this
        // comment's say-so alone.
        pg::PgResult lk = pg::exec_params(c, kSecretKeyLockSql, std::vector<std::string>{key});
        if (lk.status() != PGRES_TUPLES_OK)
            return false;
        pg::PgResult r1 = pg::exec_params(
            c, "DELETE FROM runtime_config_store.runtime_config WHERE key = $1 RETURNING key",
            std::vector<std::string>{key});
        if (r1.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(r1.get()) > 0)
            removed = true;

        pg::PgResult r2 = pg::exec_params(
            c,
            "DELETE FROM runtime_config_store.runtime_config_secrets WHERE key = $1 "
            "RETURNING key",
            std::vector<std::string>{key});
        if (r2.status() != PGRES_TUPLES_OK)
            return false;
        if (PQntuples(r2.get()) > 0)
            removed = true;
        return true;
    });
    return ok && removed;
}

void RuntimeConfigStore::warn_if_legacy_data_present(
    const std::filesystem::path& legacy_db_path) {
    std::error_code ec;
    if (!std::filesystem::exists(legacy_db_path, ec) || ec)
        return; // genuine fresh install -- the unremarkable, silent case

#ifndef _WIN32
    // ADR-0010 §Consequences (a): a legacy file we are about to read may hold a
    // PLAINTEXT oidc_client_secret row -- force 0600 defence-in-depth before
    // touching it, same idiom as WebhookStore::migrate_from_sqlite_impl (external
    // adversarial-review finding: this obligation was applied to WebhookStore for
    // the identical scenario but missed here). POSIX-only: std::filesystem::
    // permissions with owner-only POSIX bits is a silent no-op on Windows -- no
    // compensating Windows ACL exists for this path today, tracked as issue #3593
    // (WebhookStore's own tracked follow-up, same gap).
    //
    // Also force any pre-existing -wal/-shm sidecar, at read time: the
    // pre-migration store ran `PRAGMA journal_mode=WAL` unconditionally, so an
    // unclean prior shutdown can leave the pre-checkpoint plaintext secret
    // pages sitting in the WAL sidecar, not the main file -- exactly as
    // sensitive as the file it belongs to.
    std::filesystem::permissions(legacy_db_path,
                                 std::filesystem::perms::owner_read |
                                     std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    if (ec)
        spdlog::warn("RuntimeConfigStore: could not set 0600 on legacy {}: {}",
                    legacy_db_path.string(), ec.message());
    for (const char* suffix : {"-wal", "-shm"}) {
        auto side = legacy_db_path;
        side += suffix;
        std::error_code side_exists_ec;
        if (!std::filesystem::exists(side, side_exists_ec) || side_exists_ec)
            continue;
        std::error_code side_ec;
        std::filesystem::permissions(side,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace, side_ec);
        if (side_ec)
            spdlog::warn("RuntimeConfigStore: could not set 0600 on legacy sidecar {}: {}",
                        side.string(), side_ec.message());
    }
#endif

    SqliteDb db;
    if (sqlite3_open_v2(legacy_db_path.string().c_str(), db.addr(), SQLITE_OPEN_READONLY,
                        nullptr) != SQLITE_OK) {
        spdlog::warn("RuntimeConfigStore: legacy {} exists but could not be opened ({}) -- "
                    "verify manually whether it holds operator overrides that need reapplying",
                    legacy_db_path.string(), sqlite3_errmsg(db.get()));
        return;
    }

    // sqlite3_open_v2 is lazy -- it succeeds even against a file that is not a valid SQLite
    // database at all; the format is only checked on first real access. Check sqlite_master
    // FIRST, distinctly from the row-count query below, so "this file cannot be read as a
    // SQLite database" (warn -- exactly the corruption case detection exists to catch) is
    // never conflated with "this file IS a SQLite database, just not one holding our table"
    // (silent -- an unfamiliar schema is not this store's data to report on).
    SqliteStmt table_check;
    if (sqlite3_prepare_v2(db.get(),
                           "SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_config'",
                           -1, table_check.addr(), nullptr) != SQLITE_OK) {
        spdlog::warn("RuntimeConfigStore: legacy {} exists but could not be read as a SQLite "
                    "database ({}) -- verify manually whether it holds operator overrides "
                    "that need reapplying",
                    legacy_db_path.string(), sqlite3_errmsg(db.get()));
        return;
    }
    const int table_rc = sqlite3_step(table_check.get());
    if (table_rc == SQLITE_DONE)
        return; // query ran fine, zero rows -- no runtime_config table, silent
    if (table_rc != SQLITE_ROW) {
        // Anything else (SQLITE_BUSY from a concurrent lock-holder, SQLITE_IOERR,
        // SQLITE_CORRUPT, ...) is an execution FAILURE, not "no such table" -- and is
        // exactly the case this obligation must not silently wave through: a locked
        // or failing file could be hiding a real override. Distinguishing this from
        // SQLITE_DONE above is the same open()-is-lazy lesson as the table-existence
        // check itself, one call deeper (prepare succeeded, step failed). NOTE
        // (correction, Gate 8): an earlier revision of this comment claimed a held
        // BEGIN EXCLUSIVE chaos-confirms THIS branch specifically. A governance
        // regression attempt using that exact technique (a fresh connection's cold
        // schema cache needs its own lock just to read sqlite_master) instead landed
        // in the PREPARE-fails branch above, not here -- so that claim was wrong and
        // has been removed rather than repeated. This branch is still real defensive
        // coverage (SQLITE_IOERR/SQLITE_CORRUPT can surface at step rather than
        // prepare depending on where the bad page falls) but is not independently
        // demonstrated to be reachable via an external lock the way the branch above
        // is; see the corrupt-file test's comment in test_runtime_config_store.cpp
        // for the accepted-without-a-test disposition.
        spdlog::warn("RuntimeConfigStore: legacy {} exists but its schema could not be checked "
                    "({}) -- verify manually whether it holds operator overrides that need "
                    "reapplying",
                    legacy_db_path.string(), sqlite3_errmsg(db.get()));
        return;
    }

    SqliteStmt stmt;
    if (sqlite3_prepare_v2(db.get(), "SELECT COUNT(*) FROM runtime_config", -1, stmt.addr(),
                           nullptr) != SQLITE_OK || sqlite3_step(stmt.get()) != SQLITE_ROW) {
        spdlog::warn("RuntimeConfigStore: legacy {} exists but its row count could not be read "
                    "-- verify manually whether it holds operator overrides that need "
                    "reapplying",
                    legacy_db_path.string());
        return;
    }
    const auto count = static_cast<std::size_t>(sqlite3_column_int64(stmt.get(), 0));
    if (count > 0)
        spdlog::warn("RuntimeConfigStore: legacy {} holds {} override(s) that will NOT be "
                    "carried over (ADR-0009 fresh-start-by-default) -- reapply them via "
                    "Settings after this boot",
                    legacy_db_path.string(), count);
}

} // namespace yuzu::server
