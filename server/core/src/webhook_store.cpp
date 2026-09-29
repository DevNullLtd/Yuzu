#include "webhook_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "pg/secret_codec.hpp"
#include "secure_buffer.hpp"
#include "utf8_sanitize.hpp"

#include <httplib.h>
#include <libpq-fe.h>
#include <spdlog/spdlog.h>
#include <yuzu/metrics.hpp>

// gov Gate 3 cpp-expert (PR #3563 full-PR review): unconditional, not
// `#else`-guarded — OpenSSL is a required dependency on every platform
// including Windows (CLAUDE.md), and this file's EVP_sha256()/HMAC() call
// sites in the non-Windows HMAC path previously relied on these headers
// reaching Windows only via httplib.h's own transitive OpenSSL include chain
// — an accidental dependency, not a contract. Matches notification_store.cpp/
// offload_target_store.cpp's unconditional include. openssl/crypto.h dropped
// (#3623) — its only symbol here, OPENSSL_cleanse(), was the retired legacy
// plaintext-secret wipe in migrate_from_sqlite.
#include <openssl/evp.h>
#include <openssl/hmac.h>

#ifdef _WIN32
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#pragma comment(lib, "bcrypt.lib")
#endif

#include <chrono>
#include <cstdlib>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "webhook_store";

// Authoritative store (ADR-0012 §1) — operator-authored integration config,
// not a hot path (CRUD is operator-driven). fire_event's own scan is
// deliberately fail-soft with a SHORT bound instead — see its own comment.
constexpr std::chrono::milliseconds kReadTimeout{2000};
constexpr std::chrono::milliseconds kWriteTimeout{4000};
// fire_event can be called from a gRPC handler thread (Register/execution-
// completion) — it must never block meaningfully on a saturated pool.
constexpr std::chrono::milliseconds kFireEventAcquireTimeout{300};
// gov UP-5 precedent: bounded materialization regardless of table growth.
constexpr int kListRowCap = 10000;

// ── Small local helpers (each PG store keeps its own copy — not yet
//    promoted to a shared header, docs/postgres-store-playbook.md /
//    ADR-0040 Follow-ups) ──────────────────────────────────────────────────

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

std::string text_col(PGresult* res, int row, int col) {
    if (PQgetisnull(res, row, col))
        return {};
    return std::string(PQgetvalue(res, row, col),
                       static_cast<std::size_t>(PQgetlength(res, row, col)));
}

std::string bytes_to_hex(std::span<const std::uint8_t> b) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(b.size() * 2);
    for (std::uint8_t byte : b) {
        out.push_back(kDigits[byte >> 4]);
        out.push_back(kDigits[byte & 0x0F]);
    }
    return out;
}

std::vector<std::uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<std::uint8_t> out;
    out.reserve(hex.size() / 2);
    const auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            break; // malformed — server-authored hex only, defensive stop
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

// sanitize_utf8_strict scrubs invalid UTF-8 to U+FFFD but keeps embedded
// NUL. PostgreSQL TEXT cannot store a NUL and libpq's text-format bind
// C-string-truncates at the first one, so replace every NUL with U+FFFD
// too. Ported from rbac_store.cpp/management_group_store.cpp (ADR-0041/
// 0042); applied on BOTH the live-write path (url/event_types/payload/
// error, client-supplied) and the backfill path (#1593 class — AuditStore's
// migration corrected an earlier version of this idiom that sanitized only
// the backfill copy, ADR-0040).
std::string sanitize_pg_text(std::string_view s) {
    std::string out = sanitize_utf8_strict(s);
    std::size_t pos = 0;
    while ((pos = out.find('\0', pos)) != std::string::npos) {
        out.replace(pos, 1, "\xEF\xBF\xBD");
        pos += 3;
    }
    return out;
}

/// Check if a comma-separated list of event types contains a specific event.
/// Supports wildcard "*" to match all events.
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

// Unqualified DDL: the runner sets search_path to `webhook_store` for the
// migration transaction. Runtime statements below schema-qualify
// explicitly. `secret` is BYTEA (SecretCodec envelope, ADR-0010 — follows
// AuthDB's `mfa_totp_secret` precedent for type); `has_secret` is the
// INDEPENDENT flag ADR-0010 §Decision-1 requires so "no secret configured"
// is never represented by column emptiness.
const std::vector<pg::PgMigration>& migrations() {
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, R"(
            CREATE TABLE webhooks (
                id          BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                url         TEXT    NOT NULL,
                event_types TEXT    NOT NULL DEFAULT '*',
                secret      BYTEA,
                has_secret  BOOLEAN NOT NULL DEFAULT FALSE,
                enabled     BOOLEAN NOT NULL DEFAULT TRUE,
                created_at  BIGINT  NOT NULL,
                CHECK ((has_secret AND secret IS NOT NULL) OR (NOT has_secret AND secret IS NULL))
            );
            CREATE TABLE webhook_deliveries (
                id           BIGINT  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                webhook_id   BIGINT  NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
                event_type   TEXT    NOT NULL,
                payload      TEXT    NOT NULL,
                status_code  INTEGER NOT NULL DEFAULT 0,
                delivered_at BIGINT  NOT NULL,
                error        TEXT    NOT NULL DEFAULT ''
            );
            CREATE INDEX idx_delivery_webhook_ts ON webhook_deliveries(webhook_id, delivered_at);
            -- ADR-0009 backfill idempotency marker. Marker-only; the sole writer
            -- (migrate_from_sqlite) was retired (#3623, ADR-0057 Update).
            CREATE TABLE sqlite_backfill_source (
                fingerprint  TEXT PRIMARY KEY,
                completed_at BIGINT NOT NULL
            );
        )"},
        // migrate_from_sqlite() retired (#3623, ADR-0057 Update) — sqlite_backfill_source was
        // its sole idempotency marker. Appended at the next free slot, never renumbering v1
        // (PgMigrationRunner applies only version > current — renumbering an already-shipped
        // version re-applies it against a database that already ran it).
        {2, "DROP TABLE IF EXISTS sqlite_backfill_source;"},
    };
    return kMigrations;
}

} // namespace

// ── HMAC-SHA256 ─────────────────────────────────────────────────────────────

std::string WebhookStore::hmac_sha256(std::string_view secret, std::string_view data) {
    std::uint8_t hash[32] = {};

#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    auto status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr,
                                              BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status))
        return {};

    BCRYPT_HASH_HANDLE hHash = nullptr;
    status = BCryptCreateHash(alg, &hHash, nullptr, 0,
                              reinterpret_cast<PUCHAR>(const_cast<char*>(secret.data())),
                              static_cast<ULONG>(secret.size()), 0);
    if (BCRYPT_SUCCESS(status)) {
        BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(data.data())),
                       static_cast<ULONG>(data.size()), 0);
        BCryptFinishHash(hHash, hash, 32, 0);
        BCryptDestroyHash(hHash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
#else
    unsigned int len = 32;
    HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash, &len);
#endif

    return bytes_to_hex(std::span<const std::uint8_t>(hash, 32));
}

// ── Constructor / Destructor ────────────────────────────────────────────────

WebhookStore::WebhookStore(pg::PgPool& pool, pg::SecretCodec& secret_codec)
    : pool_(pool), secret_codec_(secret_codec) {
    // Construction-only unbounded acquire (ADR-0012 §2(a)).
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("WebhookStore: no database connection at construction ({}) — webhook "
                      "store disabled",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("WebhookStore: schema migration failed — webhook store disabled");
        return;
    }
    lease.reset(); // release before touching the codec (never hold a lease across other work)

    // ADR-0010: register the sole secret-bearing column. This ctor never
    // calls secret_codec_.init() — the caller (server.cpp) constructs the
    // codec, then this store (which registers the column), THEN calls
    // init() — mirrors AuthDB's construction contract exactly
    // (docs/postgres-store-playbook.md step 3).
    if (!secret_codec_.register_secret_column({"webhook_store", "webhooks", "secret", "id"})) {
        spdlog::error(
            "WebhookStore: failed to register 'secret' as a secret column — webhook store "
            "disabled");
        return;
    }

    open_ = true;
    spdlog::info("WebhookStore: opened (schema {})", kStoreName);
}

WebhookStore::~WebhookStore() {
    // Ported verbatim from the SQLite era (#3261 governance hardening) — the
    // reasoning is storage-backend-agnostic: a destructor's BODY runs BEFORE
    // its members' destructors, so declaring delivery_pool_ last does not by
    // itself stop a still-running worker from touching pool_/secret_codec_
    // while this body executes. In the intended production flow
    // (ServerImpl::stop() -> quiesce(60s) -> success -> .reset()) this is
    // always instant — the pool is already empty by the time this
    // destructor runs.
    //
    // On a 24h timeout this call does NOT leak or abandon anything (gov
    // Gate 3 cpp-safety, hardening round: an earlier version of this
    // comment/log claimed "leaking", which is inaccurate) — ~StoreWorkerPool
    // (delivery_pool_, this class's last-declared member) runs immediately
    // after this body returns and unconditionally joins every worker
    // thread, so this destructor call BLOCKS the whole process shutdown
    // until the wedged task actually finishes, however long that takes. The
    // critical log below is the operator-facing signal that the process
    // *looks* stuck for that reason, not a report that anything was left
    // behind unsafely — blocking indefinitely is the safe outcome; the
    // unsafe one would be proceeding to destruct pool_/secret_codec_ (and,
    // transitively, the KeyProvider secret_codec_ borrows) while a worker's
    // decrypt-and-sign call could still touch them.
    if (!delivery_pool_.quiesce(std::chrono::hours(24))) {
        try {
            spdlog::critical(
                "WebhookStore::~WebhookStore: delivery pool did not quiesce within 24h - "
                "about to block in ~StoreWorkerPool's unconditional join until the wedged "
                "delivery finishes, however long that takes, rather than risking a "
                "use-after-free against it");
        } catch (...) {
        }
    }
}

void WebhookStore::set_metrics(yuzu::MetricsRegistry* metrics) { metrics_ = metrics; }

bool WebhookStore::quiesce(std::chrono::milliseconds timeout) {
    return delivery_pool_.quiesce(timeout);
}

// ── CRUD ────────────────────────────────────────────────────────────────────

std::expected<int64_t, WebhookWriteError>
WebhookStore::create_webhook(const std::string& url, const std::string& event_types,
                             const std::string& secret, bool enabled) {
    // Validate URL scheme — only http:// and https:// are allowed.
    if (!url.starts_with("http://") && !url.starts_with("https://")) {
        spdlog::warn("WebhookStore: rejected webhook with invalid URL scheme: {}", url);
        return std::unexpected(WebhookWriteError::invalid_url);
    }
    if (!open_)
        return std::unexpected(WebhookWriteError::store_unavailable);

    // ADR-0010 Amendment: a GENERATED-ALWAYS (serial-PK) secret-bearing
    // table must allocate its row id BEFORE encrypting (the AAD binds the
    // row PK) — nextval() first, then INSERT the encrypted blob with that
    // id explicit (OVERRIDING SYSTEM VALUE). Never INSERT-then-UPDATE,
    // which would transiently write a non-blob value to `secret`.
    std::int64_t id = 0;
    {
        auto lease = pool_.try_acquire_for(kWriteTimeout);
        if (!lease)
            return std::unexpected(WebhookWriteError::store_unavailable);
        pg::PgResult seq = pg::exec_params(
            lease.get(), "SELECT nextval(pg_get_serial_sequence('webhook_store.webhooks','id'))",
            std::vector<std::string>{});
        if (seq.status() != PGRES_TUPLES_OK || PQntuples(seq.get()) != 1) {
            spdlog::error("WebhookStore::create_webhook: id allocation failed: {}",
                          PQerrorMessage(lease.get()));
            return std::unexpected(WebhookWriteError::db_error);
        }
        id = to_i64(PQgetvalue(seq.get(), 0, 0));
    } // lease released — never hold one across encryption (ADR-0012 §2(b))

    const bool has_secret = !secret.empty();
    std::vector<std::uint8_t> encrypted;
    if (has_secret) {
        auto pk = pg::SecretCodec::encode_bigint_pk(id);
        auto enc = secret_codec_.encrypt(
            pg::SecretCodec::SecretId{"webhook_store", "webhooks", "secret", pk},
            std::span<const std::uint8_t>{reinterpret_cast<const std::uint8_t*>(secret.data()),
                                          secret.size()});
        if (!enc.has_value()) {
            // Encrypt failure aborts here — never write plaintext, never
            // write anything at all (ADR-0010 encrypt-failure semantics).
            spdlog::error("WebhookStore::create_webhook: secret encrypt failed for {}", url);
            return std::unexpected(WebhookWriteError::db_error);
        }
        encrypted = std::move(*enc);
    }

    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(WebhookWriteError::store_unavailable);
    std::vector<std::optional<std::string>> params = {
        std::to_string(id),
        sanitize_pg_text(url),
        sanitize_pg_text(event_types),
        has_secret ? std::optional<std::string>(bytes_to_hex(encrypted)) : std::nullopt,
        has_secret ? "true" : "false",
        enabled ? "true" : "false",
        std::to_string(now_epoch()),
    };
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO webhook_store.webhooks "
        "(id, url, event_types, secret, has_secret, enabled, created_at) "
        "OVERRIDING SYSTEM VALUE VALUES "
        "($1::bigint, $2, $3, decode($4,'hex'), $5::boolean, $6::boolean, $7::bigint) "
        "RETURNING id",
        params);
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::error("WebhookStore::create_webhook: insert failed for {}: {}", url,
                      PQerrorMessage(lease.get()));
        return std::unexpected(WebhookWriteError::db_error);
    }
    return id;
}

std::optional<std::vector<Webhook>> WebhookStore::list(int limit, int offset) const {
    if (!open_)
        return std::nullopt;
    if (limit <= 0)
        limit = 100;
    limit = std::min(limit, kListRowCap);
    if (offset < 0)
        offset = 0;

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::debug("WebhookStore::list: no connection in time ({})", pool_.last_error());
        return std::nullopt;
    }
    // Never selects `secret` — list() must never expose webhook secrets,
    // encrypted or otherwise; `has_secret` is the non-sensitive signal.
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, url, event_types, has_secret, enabled, created_at "
        "FROM webhook_store.webhooks ORDER BY created_at DESC, id DESC LIMIT $1::bigint OFFSET "
        "$2::bigint",
        std::vector<std::string>{std::to_string(limit), std::to_string(offset)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("WebhookStore::list: query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }

    std::vector<Webhook> out;
    const int rows = PQntuples(res.get());
    out.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        Webhook w;
        w.id = to_i64(PQgetvalue(res.get(), i, 0));
        w.url = text_col(res.get(), i, 1);
        w.event_types = text_col(res.get(), i, 2);
        w.has_secret = text_col(res.get(), i, 3) == "t";
        w.enabled = text_col(res.get(), i, 4) == "t";
        w.created_at = to_i64(PQgetvalue(res.get(), i, 5));
        out.push_back(std::move(w));
    }
    return out;
}

std::optional<Webhook> WebhookStore::get(int64_t id) const {
    if (!open_)
        return std::nullopt;
    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::debug("WebhookStore::get: no connection in time ({})", pool_.last_error());
        return std::nullopt;
    }
    // Never selects `secret` — same rule as list().
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, url, event_types, has_secret, enabled, created_at "
        "FROM webhook_store.webhooks WHERE id=$1::bigint",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        if (res.status() != PGRES_TUPLES_OK)
            spdlog::debug("WebhookStore::get: query failed: {}", PQerrorMessage(lease.get()));
        return std::nullopt;
    }
    Webhook w;
    w.id = to_i64(PQgetvalue(res.get(), 0, 0));
    w.url = text_col(res.get(), 0, 1);
    w.event_types = text_col(res.get(), 0, 2);
    w.has_secret = text_col(res.get(), 0, 3) == "t";
    w.enabled = text_col(res.get(), 0, 4) == "t";
    w.created_at = to_i64(PQgetvalue(res.get(), 0, 5));
    return w;
}

std::expected<bool, WebhookWriteError> WebhookStore::delete_webhook(int64_t id) {
    if (!open_)
        return std::unexpected(WebhookWriteError::store_unavailable);
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease)
        return std::unexpected(WebhookWriteError::store_unavailable);
    // ON DELETE CASCADE removes webhook_deliveries rows. RETURNING proves
    // whether THIS call's row existed — never sqlite3_changes()-style
    // mutate-then-count (#1033).
    pg::PgResult res = pg::exec_params(
        lease.get(), "DELETE FROM webhook_store.webhooks WHERE id = $1::bigint RETURNING id",
        std::vector<std::string>{std::to_string(id)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::error("WebhookStore::delete_webhook: query failed for id={}: {}", id,
                      PQerrorMessage(lease.get()));
        return std::unexpected(WebhookWriteError::db_error);
    }
    return PQntuples(res.get()) > 0;
}

std::vector<WebhookDelivery> WebhookStore::get_deliveries(int64_t webhook_id, int limit) const {
    std::vector<WebhookDelivery> results;
    if (!open_)
        return results;
    if (limit <= 0)
        limit = 50;
    limit = std::min(limit, kListRowCap);

    auto lease = pool_.try_acquire_for(kReadTimeout);
    if (!lease) {
        spdlog::debug("WebhookStore::get_deliveries: no connection in time ({})",
                      pool_.last_error());
        return results;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "SELECT id, webhook_id, event_type, payload, status_code, delivered_at, error "
        "FROM webhook_store.webhook_deliveries WHERE webhook_id = $1::bigint "
        "ORDER BY delivered_at DESC, id DESC LIMIT $2::bigint",
        std::vector<std::string>{std::to_string(webhook_id), std::to_string(limit)});
    if (res.status() != PGRES_TUPLES_OK) {
        spdlog::debug("WebhookStore::get_deliveries: query failed: {}", PQerrorMessage(lease.get()));
        return results;
    }

    const int rows = PQntuples(res.get());
    results.reserve(static_cast<std::size_t>(rows));
    for (int i = 0; i < rows; ++i) {
        WebhookDelivery d;
        d.id = to_i64(PQgetvalue(res.get(), i, 0));
        d.webhook_id = to_i64(PQgetvalue(res.get(), i, 1));
        d.event_type = text_col(res.get(), i, 2);
        d.payload = text_col(res.get(), i, 3);
        d.status_code = static_cast<int>(to_i64(PQgetvalue(res.get(), i, 4)));
        d.delivered_at = to_i64(PQgetvalue(res.get(), i, 5));
        d.error = text_col(res.get(), i, 6);
        results.push_back(std::move(d));
    }
    return results;
}

// ── Delivery recording ──────────────────────────────────────────────────────

bool WebhookStore::record_delivery(int64_t webhook_id, const std::string& event_type,
                                   const std::string& payload, int status_code,
                                   const std::string& error) {
    if (!open_)
        return false;
    auto lease = pool_.try_acquire_for(kWriteTimeout);
    if (!lease) {
        spdlog::warn("WebhookStore::record_delivery: no connection in time for webhook_id={} "
                     "({})",
                     webhook_id, pool_.last_error());
        if (metrics_)
            metrics_->counter("yuzu_server_webhook_delivery_log_failed_total").increment();
        return false;
    }
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "INSERT INTO webhook_store.webhook_deliveries "
        "(webhook_id, event_type, payload, status_code, delivered_at, error) "
        "VALUES ($1::bigint, $2, $3, $4::integer, $5::bigint, $6) RETURNING id",
        std::vector<std::string>{std::to_string(webhook_id), sanitize_pg_text(event_type),
                                 sanitize_pg_text(payload), std::to_string(status_code),
                                 std::to_string(now_epoch()), sanitize_pg_text(error)});
    if (res.status() != PGRES_TUPLES_OK || PQntuples(res.get()) == 0) {
        spdlog::warn("WebhookStore::record_delivery: insert failed for webhook_id={}: {}",
                     webhook_id, PQerrorMessage(lease.get()));
        if (metrics_)
            metrics_->counter("yuzu_server_webhook_delivery_log_failed_total").increment();
        return false;
    }
    return true;
}

// ── Single webhook delivery (runs on a worker pool thread) ─────────────────

void WebhookStore::deliver_single(const WebhookDeliveryTarget& wh, const std::string& event_type,
                                  const std::string& payload_json) {
    int status_code = 0;
    std::string error;

    // Decrypt-on-use, right here, before ANY network work, and reduce to the
    // HMAC hex digest immediately below — the raw secret exists in memory
    // only for the hmac_sha256 call itself, never across the connect/write/
    // read of the outbound POST (file header; ADR-0010 §Consequences'
    // per-delivery-batch cache allowance is deliberately declined here,
    // ADR-0057). A decrypt failure skips the delivery ENTIRELY: it must
    // never fire unsigned and must never fire with an empty secret.
    std::optional<std::string> signature;
    if (wh.has_secret) {
        auto pk = pg::SecretCodec::encode_bigint_pk(wh.id);
        auto dec = secret_codec_.decrypt(
            pg::SecretCodec::SecretId{"webhook_store", "webhooks", "secret", pk}, wh.secret_blob);
        if (!dec.has_value()) {
            spdlog::warn("WebhookStore: delivery to {} skipped - signing secret unavailable "
                         "({})",
                         wh.url, pg::SecretCodec::to_external_error());
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_delivery_secret_unavailable_total")
                    .increment();
            record_delivery(wh.id, event_type, payload_json, 0, "secret_unavailable");
            return;
        }
        // Scoped to this block only: the SecureBuffer is wiped by its own
        // destructor the instant `secret` goes out of scope, before the URL
        // is even parsed — well before any socket is opened.
        const SecureBuffer secret = std::move(*dec);
        auto view = std::string_view(reinterpret_cast<const char*>(secret.data()), secret.size());
        // hmac_sha256/bytes_to_hex sit outside the try/catch below on
        // purpose, same as the decrypt call just above — both are C-API
        // calls (OpenSSL HMAC()/BCrypt) that cannot themselves throw; the
        // only theoretical throw source in this block is bad_alloc from
        // string construction, a class of failure this file already
        // accepts uncaught here (gov Gate 3 cpp-safety/architect,
        // PR #3563: StoreWorkerPool::worker_loop's own try/catch is the
        // accepted backstop for that essentially-unreachable case, not a
        // silent gap).
        signature = hmac_sha256(view, payload_json);
    }

    try {
        // Parse the URL to extract scheme, host, port, path
        std::string url = wh.url;
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

        if (signature) {
            headers.emplace("X-Yuzu-Signature", "sha256=" + *signature);
        }

        auto result = cli.Post(path, headers, payload_json, "application/json");
        if (result) {
            status_code = result->status;
        } else {
            error = "connection_failed";
            spdlog::warn("WebhookStore: delivery to {} failed: connection error", wh.url);
        }
    } catch (const std::exception& ex) {
        error = ex.what();
        spdlog::warn("WebhookStore: delivery to {} failed: {}", wh.url, error);
    }
    // `signature` is a hex digest, not secret material — nothing left to
    // wipe here. The SecureBuffer itself was already destroyed (and wiped)
    // above, before the URL was even parsed.

    const bool ok = error.empty() && status_code >= 200 && status_code < 300;
    if (metrics_) {
        metrics_->counter(ok ? "yuzu_server_webhook_delivery_success_total"
                              : "yuzu_server_webhook_delivery_failed_total")
            .increment();
    }
    record_delivery(wh.id, event_type, payload_json, status_code, error);
}

// ── Event firing (async — returns immediately) ──────────────────────────────

void WebhookStore::fire_event(const std::string& event_type, const std::string& payload_json) {
    if (!open_)
        return;

    std::vector<WebhookDeliveryTarget> matching;
    {
        // Short bound (fire_event can run on a gRPC handler thread) and
        // deliberately fail-soft: this is a "skip this tick's firing"
        // degrade, never an error the caller (Register/execution-completion
        // handlers) has any way to act on. See the file header's posture
        // note.
        auto lease = pool_.try_acquire_for(kFireEventAcquireTimeout);
        if (!lease) {
            spdlog::debug("WebhookStore::fire_event: no connection in time, skipping this "
                         "tick's matching scan ({})",
                         pool_.last_error());
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_fire_event_degraded_total").increment();
            return;
        }
        pg::PgResult res = pg::exec_params(
            lease.get(),
            "SELECT id, url, event_types, encode(secret,'hex'), has_secret "
            "FROM webhook_store.webhooks WHERE enabled = TRUE",
            std::vector<std::string>{});
        if (res.status() != PGRES_TUPLES_OK) {
            spdlog::debug("WebhookStore::fire_event: query failed: {}", PQerrorMessage(lease.get()));
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_fire_event_degraded_total").increment();
            return;
        }

        const int rows = PQntuples(res.get());
        for (int i = 0; i < rows; ++i) {
            std::string event_types = text_col(res.get(), i, 2);
            if (!event_matches(event_types, event_type))
                continue;

            WebhookDeliveryTarget wh;
            wh.id = to_i64(PQgetvalue(res.get(), i, 0));
            wh.url = text_col(res.get(), i, 1);
            wh.event_types = std::move(event_types);
            wh.has_secret = text_col(res.get(), i, 4) == "t";
            if (wh.has_secret)
                wh.secret_blob = hex_to_bytes(text_col(res.get(), i, 3));
            matching.push_back(std::move(wh));
        }
    }

    // Deliver to each matching webhook on the bounded pool (#3261 governance
    // hardening) - `wh` carries only the ENCRYPTED blob + has_secret, never
    // plaintext, so this closure never holds a decrypted secret while
    // queued.
    for (const auto& wh : matching) {
        const bool queued = delivery_pool_.submit(
            [this, wh, event_type, payload_json]() { deliver_single(wh, event_type, payload_json); });
        if (!queued) {
            spdlog::warn("WebhookStore: dropped delivery to {} - worker pool queue full or "
                         "server shutting down",
                         wh.url);
            if (metrics_)
                metrics_->counter("yuzu_server_webhook_delivery_dropped_total").increment();
        }
    }
}

} // namespace yuzu::server
