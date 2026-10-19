#include "crypto_dashboard_layout_store.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_migration_runner.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "utf8_sanitize.hpp"

#include <libpq-fe.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <string_view>

namespace yuzu::server {

namespace {

constexpr const char* kStoreName = "crypto_dashboard_layout_store";

const std::vector<pg::PgMigration>& migrations() {
    // Unqualified DDL: the runner sets `search_path` to the store schema for the migration
    // transaction. Runtime statements below schema-qualify explicitly. `widget_ids` is a JSONB
    // array of strings in display order; `updated_at` is epoch seconds of the last save;
    // `version` is the optimistic-concurrency counter (1 on first write, +1 per replace).
    static const std::vector<pg::PgMigration> kMigrations = {
        {1, "CREATE TABLE layouts ("
            "  username   TEXT PRIMARY KEY,"
            "  widget_ids JSONB NOT NULL,"
            "  updated_at BIGINT NOT NULL,"
            "  CONSTRAINT layouts_widget_ids_array CHECK (jsonb_typeof(widget_ids) = 'array'));"},
        // Appended, never folded into v1 (the runner applies only version > current). Rows
        // written before it read as version 1.
        {2, "ALTER TABLE layouts ADD COLUMN version BIGINT NOT NULL DEFAULT 1 "
            "CONSTRAINT layouts_version_positive CHECK (version >= 1);"},
    };
    return kMigrations;
}

// Strict UTF-8, no NUL: anything else cannot bind as TEXT (SQLSTATE 22021) and would read as a
// store fault rather than the caller's bad argument.
bool bindable(std::string_view v) {
    return v.find('\0') == std::string_view::npos && sanitize_utf8_strict(v) == v;
}

using Kind = CryptoLayoutStoreError::Kind;

// Degrade-log sampling (L1; the DegradeSampler pattern of the other stores): the first warn of
// an episode and every kLogSample-th after it, so a run of failures is visible without one line
// per page load. The 503 to the operator and the seam's degrade counter are unaffected.
constexpr std::uint64_t kLogSample = 100;
constexpr std::int64_t kEpisodeGapSecs = 60;
struct DegradeSampler {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::int64_t> last_ts{0};
};
struct DegradeLog {
    bool should_log;
    std::uint64_t occurrence;
};
DegradeLog sample(DegradeSampler& s) {
    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::steady_clock::now().time_since_epoch())
                                 .count() +
                             1; // never 0, so 0 stays "no previous degrade"
    const std::int64_t prev = s.last_ts.exchange(now, std::memory_order_relaxed);
    const std::uint64_t n = s.count.fetch_add(1, std::memory_order_relaxed) + 1;
    return {prev == 0 || (now - prev) > kEpisodeGapSecs || (n % kLogSample) == 0, n};
}
DegradeSampler g_timeout_sampler;
DegradeSampler g_statement_sampler;

void warn_no_connection(std::string_view op, std::chrono::milliseconds timeout) {
    if (const auto d = sample(g_timeout_sampler); d.should_log)
        spdlog::warn("CryptoDashboardLayoutStore: {} skipped, no connection within {} ms "
                     "(occurrence {})",
                     op, timeout.count(), d.occurrence);
}

// The SQLSTATE only (L1): a libpq error message can quote the failing row, which here is keyed
// by a username.
std::string_view sqlstate(const pg::PgResult& res) {
    const char* code = res.get() ? PQresultErrorField(res.get(), PG_DIAG_SQLSTATE) : nullptr;
    return code ? std::string_view(code) : std::string_view("none");
}

std::unexpected<CryptoLayoutStoreError> fail(Kind kind, std::string message) {
    return std::unexpected(CryptoLayoutStoreError{kind, std::move(message)});
}

// The username check every call shares. An oversized name is logged by its LENGTH only.
std::optional<CryptoLayoutStoreError> username_error(std::string_view op, std::string_view user) {
    if (user.size() > CryptoDashboardLayoutStore::kMaxUsernameBytes) {
        spdlog::warn("CryptoDashboardLayoutStore: {} refused, username of {} bytes exceeds {}", op,
                     user.size(), CryptoDashboardLayoutStore::kMaxUsernameBytes);
        return CryptoLayoutStoreError{Kind::kInvalidInput, "username too long"};
    }
    if (user.empty() || !bindable(user))
        return CryptoLayoutStoreError{Kind::kInvalidInput, "invalid username"};
    return std::nullopt;
}

// A statement that did not answer as expected. A lost connection after a WRITE was sent is
// kOutcomeUnknown — Postgres may have committed it before the link dropped (autocommit, one
// statement) — while any failure on a live connection is a definite rollback (kQueryError).
// A read is never ambiguous: nothing was written either way.
CryptoLayoutStoreError statement_error(std::string_view op, PGconn* conn,
                                       const pg::PgResult& res, bool write) {
    const bool lost = PQstatus(conn) == CONNECTION_BAD;
    if (const auto d = sample(g_statement_sampler); d.should_log)
        spdlog::warn("CryptoDashboardLayoutStore: {} failed{} (SQLSTATE {}, occurrence {})", op,
                     lost ? " (connection lost)" : "", sqlstate(res), d.occurrence);
    if (lost && write)
        return {Kind::kOutcomeUnknown, std::string(op) + ": connection lost, outcome unknown"};
    return {Kind::kQueryError, std::string(op) + ": query failed"};
}

} // namespace

CryptoDashboardLayoutStore::CryptoDashboardLayoutStore(pg::PgPool& pool) : pool_(pool) {
    auto lease = pool_.acquire();
    if (!lease) {
        spdlog::error("CryptoDashboardLayoutStore: no database connection at construction ({})",
                      pool_.last_error());
        return;
    }
    if (!pg::PgMigrationRunner::run(lease.get(), kStoreName, migrations())) {
        spdlog::error("CryptoDashboardLayoutStore: schema migration failed");
        return;
    }
    open_ = true;
}

std::expected<std::optional<StoredCryptoLayout>, CryptoLayoutStoreError>
CryptoDashboardLayoutStore::get(const std::string& username) {
    if (!open_)
        return fail(Kind::kNotOpen, "dashboard layout store is not open");
    if (auto bad = username_error("get", username))
        return std::unexpected(std::move(*bad));
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("get", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    pg::PgResult res = pg::exec_params(lease.get(),
                                       "SELECT widget_ids::text, version FROM "
                                       "crypto_dashboard_layout_store.layouts WHERE username = $1",
                                       std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("get", lease.get(), res, /*write=*/false));
    if (PQntuples(res.get()) == 0)
        return std::optional<StoredCryptoLayout>{std::nullopt};
    const std::int64_t version = std::strtoll(PQgetvalue(res.get(), 0, 1), nullptr, 10);
    const auto j = nlohmann::json::parse(PQgetvalue(res.get(), 0, 0), nullptr,
                                         /*allow_exceptions=*/false);
    // The CHECK constraint keeps a non-array out; a non-string element can still be written by
    // hand or by a future build. Either is reported as corrupt, never served or dropped.
    if (j.is_discarded() || !j.is_array() ||
        !std::ranges::all_of(j, [](const nlohmann::json& v) { return v.is_string(); })) {
        spdlog::warn("CryptoDashboardLayoutStore: get found a stored layout that is not a JSON "
                     "array of strings");
        return std::unexpected(CryptoLayoutStoreError{
            Kind::kCorrupt, "stored layout is not a JSON array of strings", version});
    }
    StoredCryptoLayout out;
    out.version = version;
    out.widget_ids.reserve(j.size());
    for (const auto& v : j)
        out.widget_ids.push_back(v.get<std::string>());
    return std::optional<StoredCryptoLayout>{std::move(out)};
}

std::expected<std::int64_t, CryptoLayoutStoreError>
CryptoDashboardLayoutStore::put(const std::string& username,
                                const std::vector<std::string>& widget_ids,
                                std::optional<std::int64_t> expected_version) {
    if (!open_)
        return fail(Kind::kNotOpen, "dashboard layout store is not open");
    if (auto bad = username_error("put", username))
        return std::unexpected(std::move(*bad));
    if (widget_ids.size() > kMaxIds)
        return fail(Kind::kInvalidInput, "too many widget ids");
    if (expected_version && *expected_version < 1)
        return fail(Kind::kInvalidInput, "expected_version must be at least 1");
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& id : widget_ids) {
        if (id.empty() || id.size() > kMaxIdBytes || !bindable(id))
            return fail(Kind::kInvalidInput, "invalid widget id");
        arr.push_back(id);
    }
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("put", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    std::vector<std::string> params{username, arr.dump(), std::to_string(now)};
    // ONE conditional statement either way, so the version check and the write are atomic.
    // A first write inserts only when no row exists (a concurrent first write waits on the
    // primary key, then does nothing); a replace updates only the expected version. No row
    // returned = the condition failed = kConflict.
    const char* sql =
        "INSERT INTO crypto_dashboard_layout_store.layouts (username, widget_ids, updated_at, "
        "version) VALUES ($1, $2::jsonb, $3::bigint, 1) ON CONFLICT (username) DO NOTHING "
        "RETURNING version";
    if (expected_version) {
        sql = "UPDATE crypto_dashboard_layout_store.layouts SET widget_ids = $2::jsonb, "
              "updated_at = $3::bigint, version = version + 1 WHERE username = $1 AND "
              "version = $4::bigint RETURNING version";
        params.push_back(std::to_string(*expected_version));
    }
    pg::PgResult res = pg::exec_params(lease.get(), sql, params);
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("put", lease.get(), res, /*write=*/true));
    if (PQntuples(res.get()) != 1) {
        spdlog::info("CryptoDashboardLayoutStore: put refused, the stored layout changed since "
                     "it was read");
        return fail(Kind::kConflict, "the stored layout changed since it was read");
    }
    return static_cast<std::int64_t>(std::strtoll(PQgetvalue(res.get(), 0, 0), nullptr, 10));
}

std::expected<bool, CryptoLayoutStoreError>
CryptoDashboardLayoutStore::erase(const std::string& username) {
    if (!open_)
        return fail(Kind::kNotOpen, "dashboard layout store is not open");
    if (auto bad = username_error("erase", username))
        return std::unexpected(std::move(*bad));
    auto lease = pool_.try_acquire_for(timeout_);
    if (!lease) {
        warn_no_connection("erase", timeout_);
        return fail(Kind::kPoolAcquireTimeout, "no database connection in time");
    }
    // RETURNING carries the outcome — never a changes()-style count (#1033 idiom).
    pg::PgResult res = pg::exec_params(
        lease.get(),
        "DELETE FROM crypto_dashboard_layout_store.layouts WHERE username = $1 RETURNING 1",
        std::vector<std::string>{username});
    if (res.status() != PGRES_TUPLES_OK)
        return std::unexpected(statement_error("erase", lease.get(), res, /*write=*/true));
    return PQntuples(res.get()) > 0;
}

} // namespace yuzu::server
