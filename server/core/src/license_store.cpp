#include "license_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <nlohmann/json.hpp>

#include <libpq-fe.h>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// clang-format off
#include <windows.h>  // must precede bcrypt.h (defines NTSTATUS)
// clang-format on
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/sha.h>
#endif

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <random>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "license_store";

// Not a hot path — operator-driven (activate/remove/acknowledge) or periodic-background
// (validate), same budget class as DeploymentStore (docs/adr/0043-...md).
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
// validate()'s pool-ACQUIRE-wait budget only (with_txn_for, per pg_pool.hpp) — NOT a bound on
// the transaction body's own execution time, which is governed solely by the pool's
// per-connection statement_timeout GUC (playbook: "Pool connection setup†" quick fact). Set
// generously since validate() is a periodic background pass, not a request/response path.
constexpr std::chrono::milliseconds kValidateTimeout{10000};

// gov UP-5 precedent (every migrated store on this ladder): bounded materialization regardless
// of table growth — an operator convenience list, not a paged feed.
constexpr int kListRowCap = 10000;

// ── Small helpers ────────────────────────────────────────────────────────────

std::int64_t now_epoch() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}

bool to_bool(const char* s) {
    return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1');
}

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

// Applied to every free-text column reaching Postgres (organization/edition/features_json),
// mirroring discovery_store.cpp's sanitize_pg_text — an operator-supplied organization/edition
// string over REST is untrusted.
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

// ── Migration DDL ────────────────────────────────────────────────────────────

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration txn.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE licenses ("
         "  id                TEXT PRIMARY KEY,"
         "  license_key_hash  TEXT NOT NULL UNIQUE,"
         "  organization      TEXT NOT NULL DEFAULT '',"
         "  seat_count        BIGINT NOT NULL DEFAULT 0,"
         "  issued_at         BIGINT NOT NULL DEFAULT 0,"
         "  expires_at        BIGINT NOT NULL DEFAULT 0,"
         "  edition           TEXT NOT NULL DEFAULT 'community',"
         "  features_json     TEXT NOT NULL DEFAULT '[]',"
         "  status            TEXT NOT NULL DEFAULT 'active',"
         "  activated_at      BIGINT NOT NULL DEFAULT 0);"
         "CREATE INDEX idx_license_status ON licenses(status);"
         "CREATE TABLE license_alerts ("
         "  id              BIGSERIAL PRIMARY KEY,"
         "  license_id      TEXT NOT NULL,"
         "  alert_type      TEXT NOT NULL,"
         "  message         TEXT NOT NULL DEFAULT '',"
         "  triggered_at    BIGINT NOT NULL DEFAULT 0,"
         "  acknowledged    BOOLEAN NOT NULL DEFAULT FALSE,"
         // add_alert()'s ON CONFLICT (license_id, alert_type, triggered_at) DO NOTHING relies on
         // this constraint to no-op a same-second race between two concurrent validate() calls
         // (license_alerts.id is always freshly minted by Postgres, so it can never itself be an
         // ON CONFLICT target).
         "  UNIQUE (license_id, alert_type, triggered_at));"
         "CREATE INDEX idx_license_alert_lic ON license_alerts(license_id);"
         "CREATE INDEX idx_license_alert_ack ON license_alerts(acknowledged, triggered_at);"},
    };
    return kMigrations;
}

// ── Row readers ──────────────────────────────────────────────────────────────

constexpr const char* kLicensePublicCols =
    "id, organization, seat_count, issued_at, expires_at, edition, features_json, status";

License read_license_public(PGresult* res, int row) {
    License lic;
    int c = 0;
    lic.id = text_col(res, row, c++);
    lic.organization = text_col(res, row, c++);
    lic.seat_count = to_i64(PQgetvalue(res, row, c++));
    lic.issued_at = to_i64(PQgetvalue(res, row, c++));
    lic.expires_at = to_i64(PQgetvalue(res, row, c++));
    lic.edition = text_col(res, row, c++);
    lic.features_json = text_col(res, row, c++);
    lic.status = text_col(res, row, c++);
    return lic;
}

// ── Alerts ───────────────────────────────────────────────────────────────────

// Caller must already be inside an active transaction (`conn` is a transaction-pinned
// connection — never a plain pool lease; nesting a second acquire here inside validate()'s
// with_txn would deadlock a size-1 pool). Returns false only on a genuine DB error; a skip due
// to the 24h dedup window is success (true), matching the pre-migration store's silent-skip
// semantics exactly.
bool add_alert(PGconn* conn, const std::string& license_id, const std::string& alert_type,
               const std::string& message) {
    const std::int64_t now = now_epoch();

    pg::PgResult chk = pg::exec_params(
        conn,
        "SELECT id FROM license_store.license_alerts "
        "WHERE license_id = $1 AND alert_type = $2 AND triggered_at > $3::bigint LIMIT 1",
        std::vector<std::string>{license_id, alert_type, std::to_string(now - 86400)});
    if (chk.status() != PGRES_TUPLES_OK) {
        spdlog::error("LicenseStore::add_alert: dedup check failed for '{}'/{}: {}", license_id,
                      alert_type, PQerrorMessage(conn));
        return false;
    }
    if (PQntuples(chk.get()) > 0)
        return true; // already alerted recently — same silent-skip as the original

    // ON CONFLICT DO NOTHING: the UNIQUE(license_id, alert_type, triggered_at) constraint
    // exists for backfill dedup (ADR-0048), but a same-second race between two concurrent
    // validate() calls could in principle hit it too — treated as a benign no-op either way.
    pg::PgResult res = pg::exec_params(
        conn,
        "INSERT INTO license_store.license_alerts "
        "(license_id, alert_type, message, triggered_at) VALUES ($1,$2,$3,$4::bigint) "
        "ON CONFLICT (license_id, alert_type, triggered_at) DO NOTHING",
        std::vector<std::string>{license_id, alert_type, sanitize_pg_text(message),
                                 std::to_string(now)});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("LicenseStore::add_alert: insert failed for '{}'/{}: {}", license_id,
                      alert_type, PQerrorMessage(conn));
        return false;
    }
    spdlog::info("LicenseStore: alert [{}] for license '{}': {}", alert_type, license_id,
                 message);
    return true;
}

// ── License-key hashing (kept cross-platform-identical to the pre-migration store) ─────────

std::string hash_key(const std::string& raw) {
    unsigned char hash[32]{};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (alg) {
        BCRYPT_HASH_HANDLE h = nullptr;
        BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
        if (h) {
            BCryptHashData(h, reinterpret_cast<PUCHAR>(const_cast<char*>(raw.data())),
                           static_cast<ULONG>(raw.size()), 0);
            BCryptFinishHash(h, hash, 32, 0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
#else
    SHA256(reinterpret_cast<const unsigned char*>(raw.data()), raw.size(), hash);
#endif

    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (unsigned char c : hash) {
        result += hex[c >> 4];
        result += hex[c & 0x0f];
    }
    return result;
}

// 32 lowercase-hex-char id (16 random bytes via mt19937_64) — the ORIGINAL pre-migration
// format, deliberately kept (not DeploymentStore's 16-hex/8-byte format): ADR-0048 "pre-
// migration ID contracts are kept exactly", which is about preserving THIS store's existing
// format, not converging every migrated store onto the same one.
std::string generate_id() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char hex_chars[] = "0123456789abcdef";
    std::string id;
    id.reserve(32);
    std::uniform_int_distribution<int> dist(0, 15);
    for (int i = 0; i < 32; ++i)
        id += hex_chars[dist(rng)];
    return id;
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

LicenseStore::LicenseStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("LicenseStore: no database connection at construction ({}) — license "
                      "persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("LicenseStore: schema migration failed — license persistence disabled");
        return;
    }
    open_ = true;
}


// ── Operations ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
LicenseStore::activate_license(const License& license, const std::string& license_key) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");
    if (license_key.empty())
        return std::unexpected("license key cannot be empty");
    if (license.organization.empty())
        return std::unexpected("organization cannot be empty");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    const std::string key_hash = hash_key(license_key);
    const std::string id = license.id.empty() ? generate_id() : license.id;
    const std::int64_t now = now_epoch();
    const std::int64_t issued_at = license.issued_at > 0 ? license.issued_at : now;
    const std::string edition = license.edition.empty() ? "community" : license.edition;
    const std::string features = license.features_json.empty() ? "[]" : license.features_json;

    // Atomic upsert (ADR-0048 hardening over the pre-migration check-then-insert): the conflict
    // itself, not a separate SELECT, detects a duplicate key — closes the TOCTOU window a
    // check-then-act pair leaves open.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO license_store.licenses "
        "(id, license_key_hash, organization, seat_count, issued_at, expires_at, edition, "
        " features_json, status, activated_at) "
        "VALUES ($1,$2,$3,$4::bigint,$5::bigint,$6::bigint,$7,$8,'active',$9::bigint) "
        "ON CONFLICT (license_key_hash) DO NOTHING RETURNING id",
        std::vector<std::string>{id, key_hash, sanitize_pg_text(license.organization),
                                 std::to_string(license.seat_count), std::to_string(issued_at),
                                 std::to_string(license.expires_at), sanitize_pg_text(edition),
                                 sanitize_pg_text(features), std::to_string(now)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "activate_license failed: " +
                               PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("license key already activated");

    spdlog::info("LicenseStore: activated license '{}' for org '{}' (edition={}, seats={})", id,
                 license.organization, edition, license.seat_count);
    return id;
}

std::expected<std::vector<License>, std::string> LicenseStore::list_licenses() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kLicensePublicCols +
                      " FROM license_store.licenses ORDER BY activated_at DESC LIMIT $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "list_licenses failed: " +
                               PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<License> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(read_license_public(res.get(), i));
    return out;
}

std::expected<std::optional<License>, std::string> LicenseStore::get_active_license() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = std::string("SELECT ") + kLicensePublicCols +
                      " FROM license_store.licenses WHERE status = 'active' "
                      "ORDER BY activated_at DESC LIMIT 1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "get_active_license failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::optional<License>{std::nullopt};
    return std::optional<License>{read_license_public(res.get(), 0)};
}

std::expected<void, std::string> LicenseStore::remove_license(const std::string& id) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");
    if (id.empty())
        return std::unexpected("id cannot be empty");

    bool deleted = false;
    std::string db_err;
    // One transaction: delete the license's alerts, then the license itself — never a partial
    // delete (the pre-migration version ran these as two independent best-effort statements).
    bool ok = pool_.with_txn_for(kWriteTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult da = pg::exec_params(
            conn, "DELETE FROM license_store.license_alerts WHERE license_id = $1",
            std::vector<std::string>{id});
        if (da.status() != PGRES_COMMAND_OK) {
            db_err = PQerrorMessage(conn);
            return false;
        }
        pg::PgResult dl = pg::exec_params(
            conn, "DELETE FROM license_store.licenses WHERE id = $1 RETURNING id",
            std::vector<std::string>{id});
        if (dl.status() != PGRES_TUPLES_OK) {
            db_err = PQerrorMessage(conn);
            return false;
        }
        deleted = PQntuples(dl.get()) > 0;
        return true;
    });
    if (!ok) {
        // db_err stays empty when with_txn_for fails before the lambda ever runs (lease
        // acquire timeout) or after it returns true (a failed COMMIT) — never leave the
        // message with a dangling "failed: " tail in either case.
        if (db_err.empty())
            db_err = "transaction failed (lease timeout or begin/commit failure)";
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "remove_license failed: " + db_err);
    }
    if (!deleted)
        return std::unexpected("not_found: license '" + id + "'");

    spdlog::info("LicenseStore: removed license '{}'", id);
    return {};
}

std::expected<void, std::string> LicenseStore::validate(std::int64_t current_agent_count) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    std::string db_err;
    // One transaction for the whole pass (ADR-0048 hardening over the pre-migration version,
    // which processed each license independently and ignored write failures): every status
    // transition and the alerts it produces commit atomically, or none do.
    //
    // FOR UPDATE (gov Gate 4 unhappy-path UP-1, HIGH): without a row lock, two overlapping
    // validate() transactions (e.g. two server replicas sharing this Postgres) each read the
    // same pre-transition status under their own snapshot, independently compute a new status,
    // and the later COMMIT silently clobbers the earlier one's write with no error — the
    // UPDATE below has no re-check against what was read. FOR UPDATE makes the second
    // transaction's SELECT block until the first commits, so it re-reads the already-updated
    // row instead of racing against it.
    bool ok = pool_.with_txn_for(kValidateTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "SELECT id, seat_count, expires_at, status FROM license_store.licenses "
            // gov Gate 8 architect (SHOULD): PK order — two overlapping validate() passes
            // locking more than one row now acquire Postgres row locks in the same order,
            // closing the same deadlock class as the backfill loops' ORDER BY above.
            "WHERE status = 'active' ORDER BY id ASC FOR UPDATE",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK) {
            db_err = PQerrorMessage(conn);
            return false;
        }

        const int rows = PQntuples(res.get());
        const std::int64_t now = now_epoch();
        for (int i = 0; i < rows; ++i) {
            const std::string id = text_col(res.get(), i, 0);
            const std::int64_t seats = to_i64(PQgetvalue(res.get(), i, 1));
            const std::int64_t expires_at = to_i64(PQgetvalue(res.get(), i, 2));
            const std::string status = text_col(res.get(), i, 3);

            std::string new_status = "active";

            if (expires_at > 0 && now > expires_at) {
                new_status = "expired";
                if (!add_alert(conn, id, "expired", "License '" + id + "' has expired")) {
                    db_err = "failed to record expiry alert for '" + id + "'";
                    return false;
                }
            } else if (expires_at > 0) {
                const std::int64_t days = (expires_at - now) / 86400;
                if (days <= 30) {
                    if (!add_alert(conn, id, "expiry_warning",
                                   "License '" + id + "' expires in " + std::to_string(days) +
                                       " days")) {
                        db_err = "failed to record expiry warning for '" + id + "'";
                        return false;
                    }
                }
            }

            if (seats > 0 && current_agent_count > seats) {
                new_status = "exceeded";
                if (!add_alert(conn, id, "exceeded",
                               "License '" + id + "' seat limit exceeded (" +
                                   std::to_string(current_agent_count) + "/" +
                                   std::to_string(seats) + ")")) {
                    db_err = "failed to record seat-exceeded alert for '" + id + "'";
                    return false;
                }
            } else if (seats > 0) {
                const double usage =
                    static_cast<double>(current_agent_count) / static_cast<double>(seats);
                if (usage >= 0.9) {
                    if (!add_alert(conn, id, "seat_limit_warning",
                                   "License '" + id + "' at " +
                                       std::to_string(static_cast<int>(usage * 100)) +
                                       "% seat capacity (" +
                                       std::to_string(current_agent_count) + "/" +
                                       std::to_string(seats) + ")")) {
                        db_err = "failed to record seat-warning alert for '" + id + "'";
                        return false;
                    }
                }
            }

            if (new_status != status) {
                pg::PgResult upd = pg::exec_params(
                    conn, "UPDATE license_store.licenses SET status = $1 WHERE id = $2",
                    std::vector<std::string>{new_status, id});
                if (upd.status() != PGRES_COMMAND_OK) {
                    db_err = PQerrorMessage(conn);
                    return false;
                }
                spdlog::warn("LicenseStore: license '{}' status changed to '{}'", id, new_status);
            }
        }
        return true;
    });
    if (!ok) {
        // Same empty-db_err gap as remove_license: with_txn_for can fail before the lambda runs
        // (lease timeout) or after it returns true (a failed COMMIT).
        if (db_err.empty())
            db_err = "transaction failed (lease timeout or begin/commit failure)";
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "validate failed: " + db_err);
    }
    return {};
}

std::expected<std::string, std::string> LicenseStore::get_status() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT status FROM license_store.licenses ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "get_status failed: " + PQerrorMessage(lease.get()));

    if (PQntuples(res.get()) == 0)
        return std::string("unlicensed");
    return text_col(res.get(), 0, 0);
}

std::expected<std::vector<LicenseAlert>, std::string>
LicenseStore::list_alerts(bool unacknowledged_only) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = "SELECT id, license_id, alert_type, message, triggered_at, acknowledged "
                      "FROM license_store.license_alerts";
    if (unacknowledged_only)
        sql += " WHERE acknowledged = false";
    sql += " ORDER BY triggered_at DESC LIMIT $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(),
                                       std::vector<std::string>{std::to_string(kListRowCap)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "list_alerts failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<LicenseAlert> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        LicenseAlert a;
        int c = 0;
        a.id = to_i64(PQgetvalue(res.get(), i, c++));
        a.license_id = text_col(res.get(), i, c++);
        a.alert_type = text_col(res.get(), i, c++);
        a.message = text_col(res.get(), i, c++);
        a.triggered_at = to_i64(PQgetvalue(res.get(), i, c++));
        a.acknowledged = to_bool(PQgetvalue(res.get(), i, c++));
        out.push_back(std::move(a));
    }
    return out;
}

std::expected<void, std::string> LicenseStore::acknowledge_alert(std::int64_t alert_id) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE license_store.license_alerts SET acknowledged = true WHERE id = $1 RETURNING id",
        std::vector<std::string>{std::to_string(alert_id)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "acknowledge_alert failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: alert " + std::to_string(alert_id));
    return {};
}

std::expected<bool, std::string> LicenseStore::has_feature(const std::string& feature) {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");
    if (feature.empty())
        return false;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT features_json FROM license_store.licenses WHERE status = 'active' "
        "ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "has_feature failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return false;

    auto parsed = nlohmann::json::parse(PQgetvalue(res.get(), 0, 0), nullptr, false);
    if (!parsed.is_array())
        return false;
    for (const auto& elem : parsed) {
        if (elem.is_string() && elem.get<std::string>() == feature)
            return true;
    }
    return false;
}

std::expected<std::int64_t, std::string> LicenseStore::seat_count() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT seat_count FROM license_store.licenses WHERE status = 'active' "
        "ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "seat_count failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::int64_t{0};
    return to_i64(PQgetvalue(res.get(), 0, 0));
}

std::expected<std::int64_t, std::string> LicenseStore::days_remaining() {
    if (!open_)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT expires_at FROM license_store.licenses WHERE status = 'active' "
        "ORDER BY activated_at DESC LIMIT 1",
        std::vector<std::string>{});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kLicenseDbErrorPrefix) +
                               "days_remaining failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::int64_t{0};

    const std::int64_t expires = to_i64(PQgetvalue(res.get(), 0, 0));
    if (expires == 0)
        return std::int64_t{0}; // perpetual
    const std::int64_t remaining = expires - now_epoch();
    return remaining > 0 ? remaining / 86400 : std::int64_t{0};
}

} // namespace yuzu::server
