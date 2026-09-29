#include "device_token_store.hpp"

#include "evp_raii.hpp"
#include "pg/pg_array.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "secure_random.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
// #3351: EVP_Digest is the SOLE hashing path now (sha256_hex/hash_token below) — the prior
// _WIN32/BCrypt split is gone, so this include is simply unconditional rather than the
// split-with-a-comment it used to need. `spdlog/spdlog.h` below pulls no transitive `<windows.h>`
// in this build (this project sets `SPDLOG_COMPILED_LIB` project-wide, which dead-codes spdlog's
// header-only Windows.h-including paths) — cpp-expert and cross-platform confirmed by source
// inspection, so this file carries zero `#ifdef _WIN32` branches and needs none.
#include <openssl/evp.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "device_token_store";

// validate_token is a genuine request/response path once wired (a bearer credential presented
// on every scoped API call) — shorter than LicenseStore::validate()'s 10s (a periodic
// background pass). create_token/revoke_token/revoke_by_principal are operator-driven, same
// budget class as list_tokens.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
constexpr std::chrono::milliseconds kValidateTimeout{2000};

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

// Applied to every free-text column reaching Postgres (name/principal_id/device_id/
// definition_id), mirroring license_store.cpp's sanitize_pg_text — an operator-supplied
// name/device_id/definition_id over REST is untrusted (already length-clamped at the route, but
// not UTF-8-validated there).
//
// #3351: single reserve-and-append pass (#2691 precedent, response_store.cpp — Doomgoose finding
// #8), not the naive find+replace loop copied into every OTHER store's sanitize_pg_text (still
// quadratic there; out of scope here — see #3351's follow-up). The prior loop shifted every
// trailing byte on each NUL hit (1 byte -> 3), an O(k*n) rebuild in NUL count x length for a
// NUL-dense string. Count once, reserve the final size, then copy the segments between NULs
// directly — no in-place shifting.
std::string sanitize_pg_text(std::string_view s) {
    std::string scrubbed = sanitize_utf8_strict(s);
    const std::size_t nul_count =
        static_cast<std::size_t>(std::count(scrubbed.begin(), scrubbed.end(), '\0'));
    if (nul_count == 0)
        return scrubbed;
    std::string out;
    out.reserve(scrubbed.size() + nul_count * 2); // each NUL grows 1 byte -> 3
    std::size_t start = 0;
    for (std::size_t i = 0; i < scrubbed.size(); ++i) {
        if (scrubbed[i] == '\0') {
            out.append(scrubbed, start, i - start);
            out.append("\xEF\xBF\xBD");
            start = i + 1;
        }
    }
    out.append(scrubbed, start, scrubbed.size() - start);
    return out;
}

// #3351: store-level bound on every free-text field, matching the REST route's own 256-char
// clamp (rest_api_v1.cpp) for name/device_id/definition_id — principal_id has NO route-level
// clamp (it comes from session->username, itself bounded to 64 by auth_db.cpp) so this is the
// only bound it gets. Applied on RAW byte length, BEFORE sanitize_pg_text (which can only grow a
// string, never shrink it — utf8_sanitize.hpp's ordering contract), so this is the first, not
// last, gate a caller's input passes through. Defence-in-depth for any future non-REST caller
// (e.g. an MCP twin) — unreachable via the REST route today given its own clamp.
constexpr std::size_t kMaxTextFieldLength = 256;

// Shared by sha256_hex() below — feeds EVP's raw digest bytes
// through the identical lowercase-hex encoding, so the encoding step lives once rather than
// twice; the two functions differ only in how they GET those bytes (incremental vs one-shot).
std::string hex_encode(const unsigned char* md, unsigned int len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(static_cast<std::size_t>(len) * 2);
    for (unsigned int i = 0; i < len; ++i) {
        out.push_back(kHex[md[i] >> 4]);
        out.push_back(kHex[md[i] & 0x0f]);
    }
    return out;
}

// #3351: single checked EVP_Digest call for hash_token below (a single raw token). Byte-for-byte
// the same digest OpenSSL always produces (EVP_sha256, lowercase-hex-encoded via hex_encode
// above).
std::string sha256_hex(std::string_view in) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (EVP_Digest(in.data(), in.size(), md, &len, EVP_sha256(), nullptr) != 1)
        return {};
    return hex_encode(md, len);
}

// ── Migration DDL ────────────────────────────────────────────────────────────

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for the migration txn.
    // Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE device_auth_tokens ("
         "  token_id      TEXT PRIMARY KEY,"
         "  token_hash    TEXT NOT NULL UNIQUE,"
         "  name          TEXT NOT NULL DEFAULT '',"
         "  principal_id  TEXT NOT NULL,"
         "  device_id     TEXT NOT NULL DEFAULT '',"
         "  definition_id TEXT NOT NULL DEFAULT '',"
         "  created_at    BIGINT NOT NULL DEFAULT 0,"
         "  expires_at    BIGINT NOT NULL DEFAULT 0,"
         "  last_used_at  BIGINT NOT NULL DEFAULT 0,"
         "  revoked       BOOLEAN NOT NULL DEFAULT FALSE);"
         // token_hash already carries a UNIQUE constraint, which Postgres backs with its own
         // index — no separate idx_device_token_hash (the pre-migration SQLite schema had one,
         // but it was always redundant with the UNIQUE index; not reproduced here).
         "CREATE INDEX idx_device_token_device ON device_auth_tokens(device_id);"},
    };
    return kMigrations;
}

// ── Token hashing (kept cross-platform-identical to the pre-migration store) ───────────────

// #3351: was a hand-rolled _WIN32-BCrypt-vs-OpenSSL-SHA256 split with FOUR unchecked BCrypt
// calls on the Windows branch — a failure anywhere in that chain (alg/hash handle never
// allocated, BCryptHashData/BCryptFinishHash erroring) fell through the zero-initialized
// `hash[32]` and silently returned the hex of 32 zero bytes: a constant hash for every input,
// which is an auth-bypass shape on a bearer-credential path (create_token would persist it,
// validate_token would recompute the same constant for ANY raw token). Now a single checked path
// on every platform via a single checked EVP_Digest call (sha256_hex above) — OpenSSL is
// required on Windows regardless of linkage (CLAUDE.md vcpkg section), so there is no
// cross-platform reason left for a BCrypt branch. Output bytes are identical to the old BCrypt
// branch (both are SHA-256), so no legacy hash is invalidated.
std::expected<std::string, std::string> hash_token(const std::string& raw) {
    auto h = sha256_hex(raw);
    if (h.empty())
        return std::unexpected("internal_error: token hash computation failed");
    return h;
}

// Cryptographic PRNG required — mt19937 is predictable from its outputs (#801).
// random_hex routes through OpenSSL RAND_bytes (POSIX) / BCryptGenRandom (Win).
std::expected<std::string, std::string> generate_raw_device_token() {
    auto bytes = random_hex(32); // 32 bytes -> 64 hex chars
    if (!bytes.has_value())
        return std::unexpected(std::string{"CSPRNG unavailable (entropy exhausted)"});
    return std::string{"ydt_"} + *bytes; // yuzu device token prefix
}

std::expected<std::string, std::string> generate_token_id() {
    auto bytes = random_hex(16); // 16 bytes -> 32 hex chars
    if (!bytes.has_value())
        return std::unexpected(std::string{"CSPRNG unavailable (entropy exhausted)"});
    return std::move(*bytes);
}

} // namespace

// ── Construction ─────────────────────────────────────────────────────────────

DeviceTokenStore::DeviceTokenStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("DeviceTokenStore: no database connection at construction ({}) — device "
                      "token persistence disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("DeviceTokenStore: schema migration failed — device token persistence "
                      "disabled");
        return;
    }
    open_ = true;
}

// ── Operations ───────────────────────────────────────────────────────────────

std::expected<std::string, std::string>
DeviceTokenStore::create_token(const std::string& name, const std::string& principal_id,
                               const std::string& device_id, const std::string& definition_id,
                               int64_t expires_at) {
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");
    if (principal_id.empty())
        return std::unexpected("principal_id cannot be empty");
    // #3351: reject (not clamp) on RAW byte length, before sanitize_pg_text can grow the field —
    // see kMaxTextFieldLength's doc comment.
    if (name.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: name exceeds 256 chars");
    if (principal_id.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: principal_id exceeds 256 chars");
    if (device_id.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: device_id exceeds 256 chars");
    if (definition_id.size() > kMaxTextFieldLength)
        return std::unexpected("invalid_input_length: definition_id exceeds 256 chars");

    auto raw_result = generate_raw_device_token();
    if (!raw_result.has_value())
        return std::unexpected(raw_result.error());
    auto token_id_result = generate_token_id();
    if (!token_id_result.has_value())
        return std::unexpected(token_id_result.error());

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    auto raw = std::move(*raw_result);
    auto hashed_result = hash_token(raw);
    if (!hashed_result)
        return std::unexpected(hashed_result.error());
    auto hashed = std::move(*hashed_result);
    auto token_id = std::move(*token_id_result);
    auto now = now_epoch();

    // ON CONFLICT (token_id) DO NOTHING RETURNING: token_id is 128 bits of CSPRNG entropy, so a
    // collision here is not a realistic retry path, but the atomic-upsert shape is the
    // playbook-endorsed default (docs/postgres-store-playbook.md anti-patterns) over a bare
    // INSERT whose constraint-violation error text would otherwise be the only signal. A
    // token_hash collision (equally implausible) surfaces as a genuine UNIQUE-violation error
    // via the `res.status() != PGRES_TUPLES_OK` branch below.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO device_token_store.device_auth_tokens "
        "(token_id, token_hash, name, principal_id, device_id, definition_id, created_at, "
        " expires_at) "
        "VALUES ($1,$2,$3,$4,$5,$6,$7::bigint,$8::bigint) "
        "ON CONFLICT (token_id) DO NOTHING RETURNING token_id",
        std::vector<std::string>{token_id, hashed, sanitize_pg_text(name),
                                 sanitize_pg_text(principal_id), sanitize_pg_text(device_id),
                                 sanitize_pg_text(definition_id), std::to_string(now),
                                 std::to_string(expires_at)});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "create_token failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "create_token: token_id collision — retry");

    spdlog::info("DeviceTokenStore: created token '{}' for principal '{}' (device='{}', "
                 "def='{}')",
                 name, principal_id, device_id, definition_id);
    return raw; // Return raw token (shown once to user)
}

std::expected<DeviceAuthToken, RejectedToken>
DeviceTokenStore::validate_token(const std::string& raw_token,
                                 const std::string& presenting_agent_id) {
    auto reject_input = []() {
        RejectedToken r;
        r.error = DeviceTokenValidateError::invalid_input;
        return r;
    };
    if (!open_ || raw_token.empty())
        return std::unexpected(reject_input());

    auto hashed_result = hash_token(raw_token);
    if (!hashed_result) {
        // #3351: a hash-computation fault is a store-internal failure, never a benign rejection
        // reason — same posture as the #1056 lookup-failure handling below (internal_fault),
        // which this mirrors before the transaction even starts.
        spdlog::error("DeviceTokenStore::validate_token: {}", hashed_result.error());
        RejectedToken r;
        r.error = DeviceTokenValidateError::internal_error;
        return std::unexpected(r);
    }
    auto hashed = std::move(*hashed_result);

    DeviceAuthToken t;
    RejectedToken rejected;
    bool accepted = false;
    bool internal_fault = false;

    // One transaction for the whole read+update, `SELECT ... FOR UPDATE`: the PG equivalent of
    // the pre-migration store's single-unique_lock discipline — a concurrent revoke_token on
    // this row blocks until this transaction commits, closing the TOCTOU window a
    // read-then-separately-write pair would leave open.
    bool ok = pool_.with_txn_for(kValidateTimeout, [&](PGconn* conn) -> bool {
        pg::PgResult res = pg::exec_params(
            conn,
            "SELECT token_id, name, principal_id, device_id, definition_id, created_at, "
            "expires_at, last_used_at, revoked FROM device_token_store.device_auth_tokens "
            "WHERE token_hash = $1 FOR UPDATE",
            std::vector<std::string>{hashed});
        if (res.status() != PGRES_TUPLES_OK) {
            // #1056: a lookup failure is a store-internal fault, not a clean miss. Labelling it
            // not_found would pollute the not-found signal and mislead forensics.
            internal_fault = true;
            spdlog::error("DeviceTokenStore::validate_token: lookup failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        if (PQntuples(res.get()) == 0) {
            rejected.error = DeviceTokenValidateError::not_found;
            return true;
        }

        t.token_id = text_col(res.get(), 0, 0);
        t.name = text_col(res.get(), 0, 1);
        t.principal_id = text_col(res.get(), 0, 2);
        t.device_id = text_col(res.get(), 0, 3);
        t.definition_id = text_col(res.get(), 0, 4);
        t.created_at = to_i64(PQgetvalue(res.get(), 0, 5));
        t.expires_at = to_i64(PQgetvalue(res.get(), 0, 6));
        t.last_used_at = to_i64(PQgetvalue(res.get(), 0, 7));
        t.revoked = to_bool(PQgetvalue(res.get(), 0, 8));

        // #1053: every rejection from this point on has row context that the W1.3 handler needs
        // to emit a complete audit row WITHOUT a second SELECT.
        auto reject_with_context = [&](DeviceTokenValidateError err, bool include_bound_device) {
            RejectedToken r;
            r.error = err;
            r.token_id = t.token_id;
            r.bound_principal_id = t.principal_id;
            if (include_bound_device)
                r.bound_device_id = t.device_id;
            return r;
        };

        if (t.revoked) {
            rejected = reject_with_context(DeviceTokenValidateError::revoked,
                                           /*include_bound_device=*/true);
            return true;
        }

        const auto now = now_epoch();
        if (t.expires_at > 0 && now > t.expires_at) {
            rejected = reject_with_context(DeviceTokenValidateError::expired,
                                           /*include_bound_device=*/true);
            return true;
        }

        // HIGH-1/HIGH-2 (PR #824 round 2): tokens stored with empty device_id are a back-door —
        // any presenter would pass the empty-comparison short-circuit. Refuse to validate them.
        if (t.device_id.empty()) {
            rejected = reject_with_context(DeviceTokenValidateError::unbound_legacy,
                                           /*include_bound_device=*/false);
            return true;
        }

        // Binding enforcement (#824): an empty presenting_agent_id is also a mismatch — the
        // stored device_id is guaranteed non-empty by the unbound_legacy check above.
        if (presenting_agent_id != t.device_id) {
            rejected = reject_with_context(DeviceTokenValidateError::binding_mismatch,
                                           /*include_bound_device=*/true);
            return true;
        }

        // Accepted. Bump last_used_at monotonically (GREATEST — mirrors touch semantics; never
        // regresses even under an out-of-order concurrent update) inside this same row-locked
        // transaction.
        pg::PgResult upd = pg::exec_params(
            conn,
            "UPDATE device_token_store.device_auth_tokens "
            "SET last_used_at = GREATEST(last_used_at, $1::bigint) WHERE token_hash = $2",
            std::vector<std::string>{std::to_string(now), hashed});
        if (upd.status() != PGRES_COMMAND_OK) {
            internal_fault = true;
            spdlog::error("DeviceTokenStore::validate_token: last_used_at update failed: {}",
                          PQerrorMessage(conn));
            return false;
        }
        t.last_used_at = std::max(t.last_used_at, now);
        accepted = true;
        return true;
    });

    if (!ok || internal_fault) {
        RejectedToken r;
        r.error = DeviceTokenValidateError::internal_error;
        return std::unexpected(r);
    }
    if (accepted)
        return t;
    return std::unexpected(rejected);
}

std::expected<std::vector<DeviceAuthToken>, std::string>
DeviceTokenStore::list_tokens(const std::string& principal_id) {
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    std::string sql = "SELECT token_id, name, principal_id, device_id, definition_id, "
                      "created_at, expires_at, last_used_at, revoked "
                      "FROM device_token_store.device_auth_tokens";
    std::vector<std::string> params;
    if (!principal_id.empty()) {
        sql += " WHERE principal_id = $1";
        params.push_back(principal_id);
    }
    sql += " ORDER BY created_at DESC LIMIT $" + std::to_string(params.size() + 1);
    params.push_back(std::to_string(kListRowCap));

    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "list_tokens failed: " + PQerrorMessage(lease.get()));

    const int rows = PQntuples(res.get());
    std::vector<DeviceAuthToken> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        DeviceAuthToken t;
        t.token_id = text_col(res.get(), i, 0);
        t.name = text_col(res.get(), i, 1);
        t.principal_id = text_col(res.get(), i, 2);
        t.device_id = text_col(res.get(), i, 3);
        t.definition_id = text_col(res.get(), i, 4);
        t.created_at = to_i64(PQgetvalue(res.get(), i, 5));
        t.expires_at = to_i64(PQgetvalue(res.get(), i, 6));
        t.last_used_at = to_i64(PQgetvalue(res.get(), i, 7));
        t.revoked = to_bool(PQgetvalue(res.get(), i, 8));
        out.push_back(std::move(t));
    }
    return out;
}

std::expected<void, std::string> DeviceTokenStore::revoke_token(const std::string& token_id) {
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE device_token_store.device_auth_tokens SET revoked = true "
        "WHERE token_id = $1 RETURNING token_id",
        std::vector<std::string>{token_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "revoke_token failed: " + PQerrorMessage(lease.get()));
    if (PQntuples(res.get()) == 0)
        return std::unexpected("not_found: device token '" + token_id + "'");

    spdlog::info("DeviceTokenStore: revoked token '{}'", token_id);
    return {};
}

std::expected<std::int64_t, std::string>
DeviceTokenStore::revoke_by_principal(const std::string& principal_id) {
    // Empty principal_id is a no-op: a buggy caller passing the empty default must not be able
    // to revoke the entire table or match historical rows that lack a principal binding. See
    // header doc.
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");
    if (principal_id.empty())
        return std::int64_t{0};

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    // RETURNING avoids the FULLMUTEX sqlite3_changes() race (#1033) — moot on Postgres, but
    // RETURNING + PQntuples() is the shared idiom every migrated store's mutate-and-return path
    // uses (docs/postgres-store-playbook.md).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE device_token_store.device_auth_tokens SET revoked = true "
        "WHERE principal_id = $1 AND revoked = false RETURNING token_id",
        std::vector<std::string>{principal_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "revoke_by_principal failed: " + PQerrorMessage(lease.get()));

    const std::int64_t revoked = PQntuples(res.get());
    if (revoked > 0)
        spdlog::info("DeviceTokenStore: revoked {} device token(s) for principal '{}'", revoked,
                     principal_id);
    return revoked;
}

std::expected<std::int64_t, std::string>
DeviceTokenStore::revoke_by_device(const std::string& device_id) {
    // Empty device_id is a no-op: create_token permits an empty device_id (an intentionally
    // unbound token), and a buggy caller passing the empty default must not sweep that
    // population. See header doc.
    if (!open_)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) + "database not open");
    if (device_id.empty())
        return std::int64_t{0};

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "database unavailable — try again");

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "UPDATE device_token_store.device_auth_tokens SET revoked = true "
        "WHERE device_id = $1 AND revoked = false RETURNING token_id",
        std::vector<std::string>{device_id});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(std::string(kDeviceTokenDbErrorPrefix) +
                               "revoke_by_device failed: " + PQerrorMessage(lease.get()));

    const std::int64_t revoked = PQntuples(res.get());
    if (revoked > 0)
        spdlog::info("DeviceTokenStore: revoked {} device token(s) for device '{}'", revoked,
                     device_id);
    return revoked;
}

} // namespace yuzu::server
