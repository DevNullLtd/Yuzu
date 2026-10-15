#include "offload_target_store.hpp"

#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: shared #2437 depth guard
#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "secure_buffer.hpp"

#include <httplib.h>
#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <span>
#include <sstream>
#include <stdexcept>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#pragma comment(lib, "bcrypt.lib")
#else
#include <openssl/evp.h>
#include <openssl/hmac.h>
#endif

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "offload_target_store";
constexpr const char* kTargetCols =
    "id, name, url, auth_type, has_credential, event_types, batch_size, enabled, created_at";

// Bounded acquires (ADR-0012 §2). Reads/writes get the ordinary CRUD budget;
// fire_event's enabled-target scan gets a SHORT one — this store sits on a
// hot dispatch path (perf-S2, the load-bearing partial index below), and a
// degraded/slow pool must never stall the gRPC/dispatch caller thread that
// calls fire_event. Construction is the only unbounded acquire.
constexpr std::chrono::milliseconds kReadTimeout{1500};
constexpr std::chrono::milliseconds kWriteTimeout{2000};
constexpr std::chrono::milliseconds kFireEventAcquireTimeout{300};

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets search_path to the store schema for
    // the migration txn. Runtime statements below schema-qualify explicitly.
    static const std::vector<pg::PgMigration> kMigrations = {
        {1,
         "CREATE TABLE offload_targets ("
         "  id              BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  name            TEXT    NOT NULL UNIQUE,"
         "  url             TEXT    NOT NULL,"
         "  auth_type       TEXT    NOT NULL DEFAULT 'none',"
         // auth_credential is the ADR-0010 secret column: a SecretCodec
         // envelope blob or NULL, never plaintext. has_credential is an
         // INDEPENDENT boolean (never inferred from column emptiness — the
         // anti-downgrade rule) — the CHECK below makes the pairing
         // structural, not just app-level (mirrors WebhookStore/ADR-0057).
         "  auth_credential BYTEA,"
         "  has_credential  BOOLEAN NOT NULL DEFAULT FALSE,"
         "  event_types     TEXT    NOT NULL DEFAULT '*',"
         "  batch_size      INTEGER NOT NULL DEFAULT 1,"
         "  enabled         BOOLEAN NOT NULL DEFAULT TRUE,"
         "  created_at      BIGINT  NOT NULL,"
         "  CHECK ((has_credential AND auth_credential IS NOT NULL) OR "
         "         (NOT has_credential AND auth_credential IS NULL))"
         ");"
         "CREATE TABLE offload_deliveries ("
         "  id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,"
         "  target_id    BIGINT  NOT NULL REFERENCES offload_targets(id) ON DELETE CASCADE,"
         "  event_type   TEXT    NOT NULL,"
         "  event_count  INTEGER NOT NULL DEFAULT 1,"
         "  payload      TEXT    NOT NULL,"
         "  status_code  INTEGER NOT NULL DEFAULT 0,"
         "  delivered_at BIGINT  NOT NULL,"
         "  error        TEXT    NOT NULL DEFAULT ''"
         ");"
         "CREATE INDEX idx_offload_delivery_target_ts "
         "  ON offload_deliveries(target_id, delivered_at);"
         // Partial index on enabled targets: fire_event scans this on every
         // dispatched event, and at N>~50 targets a full scan shows up in
         // profiles (perf-S2, carried across from the SQLite era — see
         // auth_db.cpp's users_active_idx for this codebase's precedent for
         // the exact `WHERE bool_col` shape on the PG substrate).
         "CREATE INDEX idx_offload_targets_enabled ON offload_targets(enabled) WHERE enabled;"},
    };
    return kMigrations;
}

// ── PG result helpers (file-local — no shared header across stores; mirrors
//    plugin_config_store.cpp / auth_db.cpp's own file-local copies) ────────

const char* col(PGresult* res, int row, int c) {
    return PQgetisnull(res, row, c) ? "" : PQgetvalue(res, row, c);
}
std::string col_str(PGresult* res, int row, int c) { return std::string(col(res, row, c)); }
std::int64_t to_i64(const char* s) {
    if (s == nullptr || s[0] == '\0')
        return 0;
    return static_cast<std::int64_t>(std::strtoll(s, nullptr, 10));
}
bool to_bool(const char* s) { return s != nullptr && (s[0] == 't' || s[0] == 'T' || s[0] == '1'); }

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
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nib(hex[i]);
        int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::int64_t epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool event_matches(const std::string& event_types, const std::string& event_type) {
    if (event_types == "*")
        return true;
    std::istringstream stream(event_types);
    std::string token;
    while (std::getline(stream, token, ',')) {
        auto start = token.find_first_not_of(' ');
        auto end = token.find_last_not_of(' ');
        if (start != std::string::npos) {
            auto trimmed = token.substr(start, end - start + 1);
            if (trimmed == event_type || trimmed == "*")
                return true;
        }
    }
    return false;
}

OffloadTarget row_to_target(PGresult* r, int i) {
    OffloadTarget t;
    t.id = to_i64(col(r, i, 0));
    t.name = col_str(r, i, 1);
    t.url = col_str(r, i, 2);
    t.auth_type = offload_auth_type_from_string(col_str(r, i, 3));
    t.has_credential = to_bool(col(r, i, 4));
    t.event_types = col_str(r, i, 5);
    t.batch_size = static_cast<int>(to_i64(col(r, i, 6)));
    t.enabled = to_bool(col(r, i, 7));
    t.created_at = to_i64(col(r, i, 8));
    return t;
}

} // namespace

// ── Auth-type enum bridge ───────────────────────────────────────────────────

std::string offload_auth_type_to_string(OffloadAuthType t) {
    switch (t) {
    case OffloadAuthType::Bearer: return "bearer";
    case OffloadAuthType::Basic:  return "basic";
    case OffloadAuthType::Hmac:   return "hmac";
    case OffloadAuthType::None:   break;
    }
    return "none";
}

OffloadAuthType offload_auth_type_from_string(const std::string& s) {
    if (s == "bearer") return OffloadAuthType::Bearer;
    if (s == "basic")  return OffloadAuthType::Basic;
    if (s == "hmac")   return OffloadAuthType::Hmac;
    return OffloadAuthType::None;
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

std::optional<std::string> OffloadTargetStore::hmac_sha256(std::string_view secret,
                                                            std::string_view data) {
    uint8_t hash[32] = {};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                              BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status))
        return std::nullopt;

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(alg, &hHash, nullptr, 0,
                              reinterpret_cast<PUCHAR>(const_cast<char*>(secret.data())),
                              static_cast<ULONG>(secret.size()), 0);
    bool ok = BCRYPT_SUCCESS(status);
    if (ok) {
        status = BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                                static_cast<ULONG>(data.size()), 0);
        ok = BCRYPT_SUCCESS(status);
    }
    if (ok) {
        status = BCryptFinishHash(hHash, hash, 32, 0);
        ok = BCRYPT_SUCCESS(status);
    }
    // hHash is destroyed whenever it was created, regardless of whether a
    // later step in the chain failed — cleanup must not depend on `ok`.
    if (hHash)
        BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok)
        return std::nullopt;
#else
    unsigned int len = 32;
    if (!HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
              reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash, &len))
        return std::nullopt;
#endif

    return bytes_to_hex(std::span<const std::uint8_t>{hash, 32});
}

// ── Base64 (RFC 4648, standard alphabet, padded) ────────────────────────────

std::string OffloadTargetStore::base64_encode(std::string_view data) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t triplet = (static_cast<uint8_t>(data[i]) << 16) |
                           (static_cast<uint8_t>(data[i + 1]) << 8) |
                           static_cast<uint8_t>(data[i + 2]);
        out.push_back(kAlphabet[(triplet >> 18) & 0x3F]);
        out.push_back(kAlphabet[(triplet >> 12) & 0x3F]);
        out.push_back(kAlphabet[(triplet >> 6) & 0x3F]);
        out.push_back(kAlphabet[triplet & 0x3F]);
        i += 3;
    }
    if (i < data.size()) {
        uint32_t triplet = static_cast<uint8_t>(data[i]) << 16;
        if (i + 1 < data.size())
            triplet |= static_cast<uint8_t>(data[i + 1]) << 8;
        out.push_back(kAlphabet[(triplet >> 18) & 0x3F]);
        out.push_back(kAlphabet[(triplet >> 12) & 0x3F]);
        out.push_back(i + 1 < data.size() ? kAlphabet[(triplet >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

// ── Constructor / Destructor ────────────────────────────────────────────────

OffloadTargetStore::OffloadTargetStore(pg::PgPool& pool, pg::SecretCodec& secret_codec)
    : pool_(pool), secret_codec_(secret_codec) {
    // Construction-only unbounded acquire (ADR-0012 §2) — every runtime
    // acquire elsewhere in this file is bounded.
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("OffloadTargetStore: no database connection at construction ({}) — "
                      "offload target store disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("OffloadTargetStore: schema migration failed — offload target store "
                      "disabled");
        return;
    }
    lease.reset(); // release before touching the codec (never hold a lease across other work)

    // ADR-0010 register-before-init sequencing (playbook §3 / AuthDB
    // precedent, mirrored verbatim by WebhookStore/ADR-0057): this ctor
    // registers the column; the CALLER runs secret_codec.init() immediately
    // after this ctor returns.
    if (!secret_codec_.register_secret_column(
            {kStoreName, "offload_targets", "auth_credential", "id"})) {
        spdlog::error("OffloadTargetStore: failed to register auth_credential as a secret "
                      "column — offload target store disabled");
        return;
    }

    open_ = true;
    // ADR-0009's 2026-08-25 fresh-start-by-default amendment: no
    // migrate_from_sqlite here, unconditionally, no flag — same posture as
    // ResponseStore. No production fleet has ever run a pre-Postgres build
    // of this store, so there is no legacy `offload_targets.db` content to
    // protect; the log line says so explicitly rather than leaving an
    // operator to wonder why an existing legacy file was never read.
    spdlog::info("OffloadTargetStore initialized (schema {}) — fresh start, no legacy backfill",
                 kStoreName);
}

OffloadTargetStore::~OffloadTargetStore() {
    // Intentionally NOT calling flush_all() here - buffered (batch_size>1)
    // events not yet flushed are dropped on destruction; that's a
    // lost-on-shutdown data-completeness tradeoff, not a safety one.
    // Operators needing at-least-once semantics should set batch_size=1
    // (immediate dispatch, no buffer) or call flush_all() on a graceful
    // shutdown path before this destructs.
    //
    // #3261 governance hardening (ported from the SQLite era, extended for
    // the ADR-0010 secrets seam): pool_/secret_codec_ are borrowed
    // references this destructor does not own and cannot itself protect —
    // the caller (ServerImpl::stop()) MUST NOT reset its FileKeyProvider/
    // SecretCodec or PgPool until quiesce() (called explicitly, ahead of
    // destruction) has returned true, exactly as documented on quiesce()'s
    // own doc comment. This destructor's 24h drain is a last-resort
    // backstop for any OTHER caller that destroys this store directly
    // without going through that sequence first — it cannot by itself
    // prevent a UAF against secret_codec_'s KeyProvider if the caller
    // ignores that contract, but it does guarantee no delivery is still
    // touching either borrowed reference once this call returns true.
    if (!delivery_pool_.quiesce(std::chrono::hours(24))) {
        try {
            spdlog::critical("OffloadTargetStore::~OffloadTargetStore: delivery pool did not "
                              "quiesce within 24h - a delivery may still be touching this "
                              "store's borrowed pool/secret codec after destruction");
        } catch (...) {
        }
    }
}

void OffloadTargetStore::set_metrics(yuzu::MetricsRegistry* metrics) { metrics_ = metrics; }

void OffloadTargetStore::log_dropped_delivery(const std::string& target_url) {
    spdlog::warn("OffloadTargetStore: dropped delivery to {} - worker pool queue full or "
                 "server shutting down",
                 target_url);
    if (metrics_)
        metrics_->counter("yuzu_server_offload_delivery_dropped_total").increment();
}

bool OffloadTargetStore::quiesce(std::chrono::milliseconds timeout) {
    return delivery_pool_.quiesce(timeout);
}

// ── CRUD ────────────────────────────────────────────────────────────────────

std::expected<int64_t, OffloadWriteError> OffloadTargetStore::create_target(
    const std::string& name, const std::string& url, OffloadAuthType auth_type,
    const std::string& auth_credential, const std::string& event_types, int batch_size,
    bool enabled) {
    if (!open_)
        return std::unexpected(OffloadWriteError::store_unavailable);
    if (name.empty()) {
        spdlog::warn("OffloadTargetStore: rejected target with empty name");
        return std::unexpected(OffloadWriteError::invalid_input);
    }
    if (!url.starts_with("http://") && !url.starts_with("https://")) {
        spdlog::warn("OffloadTargetStore: rejected target with invalid URL scheme: {}", url);
        return std::unexpected(OffloadWriteError::invalid_input);
    }
    if (batch_size < 1) {
        spdlog::warn("OffloadTargetStore: batch_size must be >= 1, got {}", batch_size);
        return std::unexpected(OffloadWriteError::invalid_input);
    }
    // Reject control characters in operator-supplied free-text fields.
    // - auth_credential: Bearer tokens flow into the
    //   `Authorization: Bearer <credential>` header verbatim — CR/LF
    //   would inject a second header and smuggle a request through any
    //   HTTP-aware proxy. Basic is base64'd, HMAC is hex; the guard
    //   fires for all auth_types as defence-in-depth.
    // - name, url: both are emitted verbatim into the DELETE audit-row
    //   `detail` field as `name=<n> url=<u>`. A control byte (CR/LF/NUL)
    //   in either field would line-split the audit row and forge a
    //   downstream event in any SIEM that parses log lines individually.
    // - event_types: rides a libpq text-format parameter verbatim; a NUL
    //   byte would silently truncate at the C-string boundary rather than
    //   erroring, and CR/LF has the same log/audit-injection shape as name.
    auto has_control_byte = [](const std::string& s) {
        for (char c : s) {
            if (static_cast<unsigned char>(c) < 0x20)
                return true;
        }
        return false;
    };
    if (has_control_byte(auth_credential)) {
        spdlog::warn(
            "OffloadTargetStore: rejected target with control bytes in auth_credential: {}",
            name);
        return std::unexpected(OffloadWriteError::invalid_input);
    }
    if (has_control_byte(name)) {
        spdlog::warn("OffloadTargetStore: rejected target with control bytes in name");
        return std::unexpected(OffloadWriteError::invalid_input);
    }
    if (has_control_byte(url)) {
        spdlog::warn(
            "OffloadTargetStore: rejected target with control bytes in url (target name: {})",
            name);
        return std::unexpected(OffloadWriteError::invalid_input);
    }
    if (has_control_byte(event_types)) {
        spdlog::warn(
            "OffloadTargetStore: rejected target with control bytes in event_types: {}", name);
        return std::unexpected(OffloadWriteError::invalid_input);
    }

    // Serial-PK allocate-before-encrypt (ADR-0010 Amendment): reserve the
    // row id on its own short lease (released before encrypting), encrypt
    // with that id as the AAD row-PK, then INSERT ... OVERRIDING SYSTEM
    // VALUE on a fresh lease — never INSERT-then-UPDATE, which would
    // transiently write a non-blob value to auth_credential.
    int64_t id = -1;
    {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease)
            return std::unexpected(OffloadWriteError::store_unavailable);
        pg::PgResult idres = pg::exec_params(
            lease.get(),
            "SELECT nextval(pg_get_serial_sequence('offload_target_store.offload_targets','id'))",
            std::vector<std::string>{});
        if (idres.status() != PGRES_TUPLES_OK || PQntuples(idres.get()) == 0) {
            spdlog::error("OffloadTargetStore::create_target: id reservation failed: {}",
                          PQresultErrorMessage(idres.get()));
            return std::unexpected(OffloadWriteError::db_error);
        }
        id = to_i64(col(idres.get(), 0, 0));
    }

    const bool has_credential = !auth_credential.empty();
    std::vector<std::uint8_t> encrypted;
    if (has_credential) {
        auto pk = pg::SecretCodec::encode_bigint_pk(id);
        auto enc = secret_codec_.encrypt(
            pg::SecretCodec::SecretId{kStoreName, "offload_targets", "auth_credential", pk},
            std::span<const std::uint8_t>{
                reinterpret_cast<const std::uint8_t*>(auth_credential.data()),
                auth_credential.size()});
        if (!enc.has_value()) {
            // Encrypt failure aborts here — never write plaintext, never
            // write anything at all (ADR-0010 encrypt-failure semantics).
            // No row has been touched yet (only the sequence advanced,
            // which is harmless — a gap in a BIGINT identity sequence is
            // not observable state).
            spdlog::error("OffloadTargetStore::create_target: credential encrypt failed for {}",
                          name);
            return std::unexpected(OffloadWriteError::db_error);
        }
        encrypted = std::move(*enc);
    }

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(OffloadWriteError::store_unavailable);
    auto auth_str = offload_auth_type_to_string(auth_type);
    std::vector<std::optional<std::string>> params = {
        std::to_string(id),
        name,
        url,
        auth_str,
        has_credential ? std::optional<std::string>(bytes_to_hex(encrypted)) : std::nullopt,
        has_credential ? "true" : "false",
        event_types,
        std::to_string(batch_size),
        enabled ? "true" : "false",
        std::to_string(epoch_seconds()),
    };
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO offload_target_store.offload_targets "
        "(id, name, url, auth_type, auth_credential, has_credential, event_types, batch_size, "
        " enabled, created_at) "
        "OVERRIDING SYSTEM VALUE VALUES "
        "($1::bigint, $2, $3, $4, decode($5,'hex'), $6::boolean, $7, $8::integer, $9::boolean, "
        " $10::bigint)",
        params);
    if (res.status() != PGRES_COMMAND_OK) {
        const char* sqlstate_p = PQresultErrorField(res.get(), PG_DIAG_SQLSTATE);
        const std::string sqlstate = sqlstate_p ? sqlstate_p : "";
        if (sqlstate == "23505") {
            const char* constraint_p = PQresultErrorField(res.get(), PG_DIAG_CONSTRAINT_NAME);
            const std::string constraint = constraint_p ? constraint_p : "";
            if (constraint == "offload_targets_pkey") {
                // The id-reservation sequence and the identity column's own
                // backing sequence have diverged (e.g. an operator manually
                // resetting the sequence, or restoring a dump that carried
                // stale sequence state) - this is a real bug/operational
                // error, never a legitimate operator collision, and must
                // never be reported as "duplicate name" (a sequence bug
                // masquerading as operator error).
                spdlog::critical(
                    "OffloadTargetStore::create_target: PRIMARY KEY collision on reserved id "
                    "{} - the offload_targets identity sequence is out of sync (bug, not "
                    "operator error)",
                    id);
                return std::unexpected(OffloadWriteError::db_error);
            }
            spdlog::warn("OffloadTargetStore: rejected duplicate target name: {}", name);
            return std::unexpected(OffloadWriteError::invalid_input);
        }
        spdlog::error("OffloadTargetStore::create_target: insert failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(OffloadWriteError::db_error);
    }
    return id;
}

std::optional<std::vector<OffloadTarget>> OffloadTargetStore::list(int limit, int offset) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return std::nullopt;

    const std::string sql = std::string("SELECT ") + kTargetCols +
                            " FROM offload_target_store.offload_targets "
                            "ORDER BY created_at DESC LIMIT $1 OFFSET $2";
    pg::PgResult res = pg::exec_params(
        lease.get(), sql.c_str(),
        std::vector<std::string>{std::to_string(limit), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("OffloadTargetStore::list: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::nullopt;
    }

    const int rows = PQntuples(res.get());
    std::vector<OffloadTarget> out;
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i)
        out.push_back(row_to_target(res.get(), i));
    return out;
}

std::optional<OffloadTarget> OffloadTargetStore::get(int64_t id, bool* store_ok) const {
    if (store_ok)
        *store_ok = true;
    if (!open_) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kTargetCols +
                            " FROM offload_target_store.offload_targets WHERE id = $1";
    pg::PgResult res =
        pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("OffloadTargetStore::get: query failed: {}",
                      PQresultErrorMessage(res.get()));
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt; // genuinely not found — not a degradation
    return row_to_target(res.get(), 0);
}

std::optional<OffloadTarget> OffloadTargetStore::get_by_name(const std::string& name,
                                                             bool* store_ok) const {
    if (store_ok)
        *store_ok = true;
    if (!open_) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    const std::string sql = std::string("SELECT ") + kTargetCols +
                            " FROM offload_target_store.offload_targets WHERE name = $1";
    pg::PgResult res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{name});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("OffloadTargetStore::get_by_name: query failed: {}",
                      PQresultErrorMessage(res.get()));
        if (store_ok)
            *store_ok = false;
        return std::nullopt;
    }
    if (PQntuples(res.get()) == 0)
        return std::nullopt;
    return row_to_target(res.get(), 0);
}

std::expected<bool, OffloadWriteError> OffloadTargetStore::delete_target(int64_t id) {
    if (!open_)
        return std::unexpected(OffloadWriteError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(OffloadWriteError::store_unavailable);

    // offload_deliveries CASCADEs natively on the FK — no manual pre-delete
    // needed (unlike the SQLite era, Postgres FK enforcement needs no
    // per-connection PRAGMA).
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM offload_target_store.offload_targets WHERE id = $1 RETURNING id",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("OffloadTargetStore::delete_target: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return std::unexpected(OffloadWriteError::db_error);
    }
    const bool deleted = PQntuples(res.get()) > 0;

    // Drop any in-memory buffer for this target (no flush — the operator
    // asked to delete it; pending events go away with it).
    if (deleted) {
        std::lock_guard buf_lock(buf_mu_);
        buffers_.erase(id);
    }
    return deleted;
}

std::vector<OffloadDelivery> OffloadTargetStore::get_deliveries(int64_t target_id,
                                                                int limit) const {
    std::vector<OffloadDelivery> results;
    if (!open_)
        return results;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease)
        return results;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, target_id, event_type, event_count, payload, status_code, delivered_at, "
        "error FROM offload_target_store.offload_deliveries WHERE target_id = $1 "
        "ORDER BY delivered_at DESC LIMIT $2",
        std::vector<std::string>{std::to_string(target_id), std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("OffloadTargetStore::get_deliveries: query failed: {}",
                      PQresultErrorMessage(res.get()));
        return results;
    }

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        OffloadDelivery d;
        d.id = to_i64(col(res.get(), i, 0));
        d.target_id = to_i64(col(res.get(), i, 1));
        d.event_type = col_str(res.get(), i, 2);
        d.event_count = static_cast<int>(to_i64(col(res.get(), i, 3)));
        d.payload = col_str(res.get(), i, 4);
        d.status_code = static_cast<int>(to_i64(col(res.get(), i, 5)));
        d.delivered_at = to_i64(col(res.get(), i, 6));
        d.error = col_str(res.get(), i, 7);
        results.push_back(std::move(d));
    }
    return results;
}

// ── Delivery recording ──────────────────────────────────────────────────────

bool OffloadTargetStore::record_delivery(int64_t target_id, const std::string& event_type,
                                         int event_count, const std::string& payload,
                                         int status_code, const std::string& error) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return false;

    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO offload_target_store.offload_deliveries "
        "(target_id, event_type, event_count, payload, status_code, delivered_at, error) "
        "VALUES ($1::bigint, $2, $3::integer, $4, $5::integer, $6::bigint, $7)",
        std::vector<std::string>{std::to_string(target_id), event_type,
                                 std::to_string(event_count), payload,
                                 std::to_string(status_code), std::to_string(epoch_seconds()),
                                 error});
    if (res.status() != PGRES_COMMAND_OK) {
        spdlog::error("OffloadTargetStore::record_delivery: insert failed: {}",
                      PQresultErrorMessage(res.get()));
        return false;
    }
    return true;
}

// ── Single delivery (runs on a worker pool thread) ──────────────────────────

std::string OffloadTargetStore::build_batch_body(const std::vector<BufferedEvent>& events,
                                                 int64_t target_id) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& e : events) {
        // #2437-class guard: depth-check the raw BUFFERED payload_json
        // BEFORE nlohmann::json::parse ever sees it. Every current caller of
        // fire_event() (agent enrollment, execution.completed, DEX blast-
        // radius/signal alerts) builds a small flat scalar-field object and
        // dumps it immediately, so no live path hands this a too-deep
        // payload today - but fire_event() itself performs no validation on
        // the string it buffers, so a future caller (or a change to one of
        // today's) could reintroduce exactly this crash with no signal.
        // Parsing this into a real tree and then `.dump()`-ing the wrapping
        // `{"events":[…]}` below is unboundedly recursive on `.dump()` (see
        // json_exceeds_depth's doc comment, mcp_jsonrpc.hpp - measured, not
        // assumed), so reject on the raw text before parse ever runs.
        //
        // Routed through the SAME "can't be safely handled, preserve as raw
        // text" fallback the catch(...) below already uses for genuinely
        // malformed JSON - the event is never silently dropped, so an
        // operator inspecting /deliveries can still see and investigate it.
        // This store has no retry/backoff mechanism (delivery is one-shot
        // per flush), so a poisoned event cannot be retried forever either -
        // it is attempted exactly once, like every other buffered event.
        if (mcp::json_exceeds_depth(e.payload_json, mcp::kMcpMaxJsonDepth)) {
            spdlog::warn("OffloadTargetStore::build_batch_body: target {} event '{}' payload "
                         "nested past the depth guard (max {}), preserving as raw text - cannot "
                         "be safely parsed",
                         target_id, e.event_type, mcp::kMcpMaxJsonDepth);
            arr.push_back(e.payload_json);
            continue;
        }
        try {
            arr.push_back(nlohmann::json::parse(e.payload_json));
        } catch (...) {
            // Fallback: treat the unparseable event as a raw string so we
            // never silently drop it. The receiver gets a clear-text
            // record that they can investigate.
            arr.push_back(e.payload_json);
        }
    }
    return nlohmann::json({{"events", arr}}).dump();
}

void OffloadTargetStore::deliver_single(const OffloadDeliveryTarget& tgt,
                                        const std::string& event_type, int event_count,
                                        const std::string& payload_body) {
    // Defence-in-depth scheme re-check: create_target's guard rejects
    // non-http(s) URLs, but a tampered row (manual SQL write, or any other
    // write surface that bypasses create_target) would otherwise be
    // dispatched here verbatim. Record the rejection so the operator sees
    // it in /deliveries.
    if (!tgt.url.starts_with("http://") && !tgt.url.starts_with("https://")) {
        record_delivery(tgt.id, event_type, event_count, payload_body, 0, "invalid_scheme");
        spdlog::warn("OffloadTargetStore: refused dispatch with non-http(s) URL: {}", tgt.url);
        if (metrics_)
            metrics_->counter("yuzu_server_offload_delivery_failed_total").increment();
        return;
    }

    // Defence-in-depth, same class as the URL-scheme re-check above: a
    // stored auth_type value that doesn't round-trip through
    // offload_auth_type_to_string (a tampered row, or a value from a
    // since-retired enum member) resolves to None via the lenient
    // from-string parser used to build `tgt` — never silently dispatch a
    // configured credential with no authentication applied.
    if (tgt.has_credential &&
        offload_auth_type_to_string(tgt.auth_type) != tgt.auth_type_raw) {
        record_delivery(tgt.id, event_type, event_count, payload_body, 0, "invalid_auth_type");
        spdlog::warn("OffloadTargetStore: refused dispatch for target {} - stored auth_type "
                     "({}) is not a recognized value and a credential is configured",
                     tgt.id, tgt.auth_type_raw);
        if (metrics_)
            metrics_->counter("yuzu_server_offload_delivery_failed_total").increment();
        return;
    }

    // Decrypt-on-use at the dispatch site, right before the credential is
    // needed for the auth header/signature — never cached/batched across
    // this target's flush lifetime (ADR-0010 §Consequences permits caching
    // for a whole delivery batch; this store declines that option, same as
    // WebhookStore/ADR-0057). `credential` falls out of scope (and is
    // cleansed) at the end of this function on EVERY exit path, including
    // an exception from the HTTP client below.
    std::optional<SecureBuffer> credential;
    if (tgt.has_credential) {
        auto pk = pg::SecretCodec::encode_bigint_pk(tgt.id);
        auto dec = secret_codec_.decrypt(
            pg::SecretCodec::SecretId{kStoreName, "offload_targets", "auth_credential", pk},
            tgt.credential_blob);
        if (!dec.has_value()) {
            // Fail closed — never fire unsigned/unauthenticated when a
            // credential was configured (ADR-0010 §1). No HTTP call is
            // made at all.
            spdlog::warn("OffloadTargetStore: delivery to {} skipped - credential unavailable "
                         "({})",
                         tgt.url, pg::SecretCodec::to_external_error());
            if (metrics_)
                metrics_->counter("yuzu_server_offload_delivery_credential_unavailable_total")
                    .increment();
            record_delivery(tgt.id, event_type, event_count, payload_body, 0,
                            "credential_unavailable");
            return;
        }
        credential = std::move(*dec);
    }

    int status_code = 0;
    std::string error;

    try {
        std::string url = tgt.url;
        std::string scheme = "http";
        std::string host_port;
        std::string path = "/";

        if (url.starts_with("https://")) {
            scheme = "https";
            url = url.substr(8);
        } else if (url.starts_with("http://")) {
            url = url.substr(7);
        }

        auto path_pos = url.find('/');
        if (path_pos != std::string::npos) {
            host_port = url.substr(0, path_pos);
            path = url.substr(path_pos);
        } else {
            host_port = url;
        }

        httplib::Client cli(scheme + "://" + host_port);
        cli.set_connection_timeout(5);
        cli.set_read_timeout(10);
        cli.set_write_timeout(10);

        httplib::Headers headers;
        headers.emplace("Content-Type", "application/json");
        headers.emplace("X-Yuzu-Event", event_type);
        headers.emplace("X-Yuzu-Event-Count", std::to_string(event_count));

        switch (tgt.auth_type) {
        case OffloadAuthType::Bearer:
            if (credential) {
                auto view = std::string_view(reinterpret_cast<const char*>(credential->data()),
                                             credential->size());
                headers.emplace("Authorization", "Bearer " + std::string(view));
            }
            break;
        case OffloadAuthType::Basic:
            if (credential) {
                auto view = std::string_view(reinterpret_cast<const char*>(credential->data()),
                                             credential->size());
                headers.emplace("Authorization", "Basic " + base64_encode(view));
            }
            break;
        case OffloadAuthType::Hmac:
            if (credential) {
                auto view = std::string_view(reinterpret_cast<const char*>(credential->data()),
                                             credential->size());
                auto sig = hmac_sha256(view, payload_body);
                if (!sig) {
                    // Fail closed — never send a predictable all-zero
                    // signature as if it were real. Throwing here (caught
                    // below, same as a connection failure) skips the POST
                    // entirely.
                    throw std::runtime_error("hmac_failed");
                }
                headers.emplace("X-Yuzu-Signature", "sha256=" + *sig);
            }
            break;
        case OffloadAuthType::None:
            break;
        }

        auto result = cli.Post(path, headers, payload_body, "application/json");
        if (result) {
            status_code = result->status;
        } else {
            error = "connection_failed";
            spdlog::warn("OffloadTargetStore: delivery to {} failed: connection error", tgt.url);
        }
    } catch (const std::exception& ex) {
        error = ex.what();
        spdlog::warn("OffloadTargetStore: delivery to {} failed: {}", tgt.url, error);
    }

    if (metrics_) {
        const bool ok = error.empty() && status_code >= 200 && status_code < 300;
        metrics_->counter(ok ? "yuzu_server_offload_delivery_success_total"
                              : "yuzu_server_offload_delivery_failed_total")
            .increment();
    }
    record_delivery(tgt.id, event_type, event_count, payload_body, status_code, error);
}

// ── Event firing (async — returns immediately) ──────────────────────────────

void OffloadTargetStore::fire_event(const std::string& event_type,
                                    const std::string& payload_json,
                                    const std::vector<std::string>& target_filter) {
    if (!open_)
        return;

    // Gather matching, enabled targets under a SHORT bounded acquire — this
    // runs on the gRPC/dispatch caller's thread, so a degraded pool must
    // skip this tick's firing (logged + counted) rather than stall the
    // caller (ADR-0036 deny-or-benign carve-out for a non-authoritative,
    // best-effort dispatch scan).
    std::vector<OffloadDeliveryTarget> matching;
    {
        auto lease = pool_.try_acquire_for(kFireEventAcquireTimeout);
        if (!lease) {
            spdlog::warn("OffloadTargetStore::fire_event: could not acquire a connection within "
                         "{}ms - this tick's events are not delivered",
                         kFireEventAcquireTimeout.count());
            if (metrics_)
                metrics_->counter("yuzu_server_offload_fire_event_degraded_total").increment();
            return;
        }

        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT id, name, url, auth_type, encode(auth_credential,'hex'), has_credential, "
            "       event_types, batch_size "
            "FROM offload_target_store.offload_targets WHERE enabled",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::error("OffloadTargetStore::fire_event: query failed: {}",
                          PQresultErrorMessage(res.get()));
            if (metrics_)
                metrics_->counter("yuzu_server_offload_fire_event_degraded_total").increment();
            return;
        }

        const int rows = PQntuples(res.get());
        matching.reserve(static_cast<std::size_t>(rows));
        for (int i = 0; i < rows; ++i) {
            OffloadDeliveryTarget t;
            t.id = to_i64(col(res.get(), i, 0));
            t.name = col_str(res.get(), i, 1);
            t.url = col_str(res.get(), i, 2);
            t.auth_type_raw = col_str(res.get(), i, 3);
            t.auth_type = offload_auth_type_from_string(t.auth_type_raw);
            t.has_credential = to_bool(col(res.get(), i, 5));
            if (t.has_credential)
                t.credential_blob = hex_to_bytes(col_str(res.get(), i, 4));
            const std::string event_types = col_str(res.get(), i, 6);
            t.batch_size = static_cast<int>(to_i64(col(res.get(), i, 7)));

            if (!event_matches(event_types, event_type))
                continue;
            if (!target_filter.empty()) {
                auto it = std::find(target_filter.begin(), target_filter.end(), t.name);
                if (it == target_filter.end())
                    continue;
            }
            matching.push_back(std::move(t));
        }
    }

    // Per-target dispatch: batch_size==1 → fire immediately; otherwise
    // append to buffer and flush on threshold. Deliveries run on the
    // bounded pool (#3261 governance hardening). A full queue drops the
    // delivery (logged + counted) rather than spawning an unbounded thread.
    for (auto& tgt : matching) {
        if (tgt.batch_size <= 1) {
            const bool queued = delivery_pool_.submit([this, tgt, event_type, payload_json]() {
                deliver_single(tgt, event_type, /*event_count=*/1, payload_json);
            });
            if (!queued)
                log_dropped_delivery(tgt.url);
            continue;
        }

        std::vector<BufferedEvent> to_flush;
        {
            std::lock_guard buf_lock(buf_mu_);
            auto& buf = buffers_[tgt.id];
            buf.push_back({event_type, payload_json});
            if (static_cast<int>(buf.size()) >= tgt.batch_size) {
                to_flush = std::move(buf);
                buf.clear();
            }
        }

        if (!to_flush.empty()) {
            auto body = build_batch_body(to_flush, tgt.id);
            int count = static_cast<int>(to_flush.size());
            const bool queued = delivery_pool_.submit([this, tgt, event_type, count, body]() {
                deliver_single(tgt, event_type, count, body);
            });
            if (!queued)
                log_dropped_delivery(tgt.url);
        }
    }
}

void OffloadTargetStore::flush_all() {
    // Snapshot non-empty buffers under buf_mu_, then read fresh target
    // configs (including the still-encrypted credential blob) with no lock
    // held, then fire deliveries.
    std::unordered_map<int64_t, std::vector<BufferedEvent>> snapshot;
    {
        std::lock_guard buf_lock(buf_mu_);
        for (auto& [id, evs] : buffers_) {
            if (!evs.empty()) {
                snapshot.emplace(id, std::move(evs));
                evs.clear();
            }
        }
    }
    if (snapshot.empty() || !open_)
        return;

    for (auto& [target_id, events] : snapshot) {
        if (events.empty())
            continue;

        OffloadDeliveryTarget tgt;
        {
            auto lease = pool_.try_acquire_for(kReadTimeout);
            if (!lease)
                continue; // degraded — drop this target's buffered batch
            pg::PgResult res = pg::exec_params(
                lease.get(),
                "SELECT id, name, url, auth_type, encode(auth_credential,'hex'), "
                "       has_credential, batch_size "
                "FROM offload_target_store.offload_targets WHERE id = $1",
                std::vector<std::string>{std::to_string(target_id)});
            if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0)
                continue; // target deleted or the query degraded — drop the batch
            tgt.id = to_i64(col(res.get(), 0, 0));
            tgt.name = col_str(res.get(), 0, 1);
            tgt.url = col_str(res.get(), 0, 2);
            tgt.auth_type_raw = col_str(res.get(), 0, 3);
            tgt.auth_type = offload_auth_type_from_string(tgt.auth_type_raw);
            tgt.has_credential = to_bool(col(res.get(), 0, 5));
            if (tgt.has_credential)
                tgt.credential_blob = hex_to_bytes(col_str(res.get(), 0, 4));
            tgt.batch_size = static_cast<int>(to_i64(col(res.get(), 0, 6)));
        }

        auto event_type = events.front().event_type; // representative
        auto body = build_batch_body(events, target_id);
        int count = static_cast<int>(events.size());
        const bool queued = delivery_pool_.submit([this, tgt, event_type, count, body]() {
            deliver_single(tgt, event_type, count, body);
        });
        if (!queued)
            log_dropped_delivery(tgt.url);
    }
}

} // namespace yuzu::server
