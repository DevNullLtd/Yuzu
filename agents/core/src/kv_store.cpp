/**
 * kv_store.cpp -- Persistent SQLite-backed key-value storage for plugins
 *
 * Table schema:
 *   CREATE TABLE IF NOT EXISTS kv_store (
 *       plugin     TEXT NOT NULL,
 *       key        TEXT NOT NULL,
 *       value      TEXT,
 *       updated_at INTEGER,
 *       PRIMARY KEY(plugin, key)
 *   );
 *
 * All queries use parameterized SQL to prevent injection.
 * A std::mutex guards all sqlite3* access for thread safety (Darwin pitfall).
 */

#include <yuzu/agent/kv_store.hpp>

#include <sqlite3.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <cstddef>
#include <memory>
#include <string>
#include <thread>
#include <utility>

namespace yuzu::agent {

namespace {

int64_t now_epoch_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Build the LIKE operand for a prefix match: escape the wildcards SQLite's LIKE would otherwise
// interpret ('%', '_') and the escape char itself, then append '%'. Every prefix-scanning query
// pairs this with ESCAPE '\'. Extracted so the four call sites (list, list_entries,
// namespace_size, list_keys_sized) cannot drift - an unescaped '_' silently widens the scan to
// keys the caller never asked for.
std::string escape_like_prefix(std::string_view prefix) {
    std::string escaped;
    escaped.reserve(prefix.size() + 1);
    for (char c : prefix) {
        if (c == '%' || c == '_' || c == '\\')
            escaped += '\\';
        escaped += c;
    }
    escaped += '%';
    return escaped;
}

// How long the busy handler sleeps between retries of a locked database, by `count` (the number
// of retries SQLite has already made in this wait): 1, 2, 5, then 10 ms from the fourth retry on.
// SQLite's own sqlite3_busy_timeout() handler sleeps in a similar ladder (1, 2, 5, 10, 15, 20, 25,
// 25, 25, 50, 50, 100 ms); the short head means a lock another process holds for a few
// milliseconds costs milliseconds, not a whole 10 ms sleep, and the 10 ms tail keeps a long wait
// from busy-spinning. A sleep never undershoots, but the platform timer rounds it UP: about
// 15.6 ms on Windows (the default timer tick) and about 15 ms on macOS (a review measured
// 15.03 ms, one run, median), so each of the first retries can cost up to one tick there and a budget is overshot by up to
// one tick. The head of the ladder is therefore a Linux latency gain; elsewhere it is bounded by
// the tick.
constexpr std::array<std::chrono::milliseconds, 4> kBusyRetryLadder{
    std::chrono::milliseconds{1}, std::chrono::milliseconds{2}, std::chrono::milliseconds{5},
    std::chrono::milliseconds{10}};

std::chrono::milliseconds busy_retry_sleep(int count) noexcept {
    const auto idx = count < 0 ? std::size_t{0}
                               : (std::min)(static_cast<std::size_t>(count),
                                            kBusyRetryLadder.size() - 1);
    return kBusyRetryLadder[idx];
}

// A handler call more than this long after the previous call on the same thread cannot be a
// continuation of one wait: a continuing wait calls the handler again after one retry sleep (at
// most about 10 ms, about 16 ms on a coarse-timer platform, plus scheduler delay), so a gap this
// wide means the previous wait ended (its call returned BUSY, or the statement completed) and
// this is a different one whose `count == 0` call this thread never saw.
constexpr std::chrono::milliseconds kBusyWaitRestartGap{250};

struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

} // namespace

// The busy handler's context (see KvBusyState's declaration in kv_store.hpp).
struct KvBusyState {
    std::atomic<std::int64_t> budget_ms{0};
};

namespace {

// sqlite3_busy_handler callback (#5604). Runs on the waiting thread WITH the connection mutex
// held, so it may ONLY read the atomic budget and sleep: no logging, no locks, no allocation.
// `count` is the number of earlier retries within ONE lock wait, so 0 is that wait's first
// retry and the wait's start is captured there (thread_local: the wait runs entirely on the
// calling thread). SQLite resets `count` to 0 at the start of every statement step, prepare
// and checkpoint that has to wait, not once per KV method: a method that takes the lock twice
// (del_keys' rollback-journal fallback) starts two waits. Because the start is only captured on
// `count == 0`, a call with `count > 0` on a thread that never saw the matching `count == 0`
// (a wait begun by a code path this handler did not observe) would read a stale or empty start
// and fail at once. Defence: the start is also re-captured when this thread has no previous
// call, or when the previous call was more than kBusyWaitRestartGap ago (see there); no such
// path has been constructed (the review that raised it could not). Returning 0 makes the pending call fail with SQLITE_BUSY. The budget is re-read on
// every retry, so lowering it from another thread cuts a wait that is already in progress,
// which sqlite3_busy_timeout() cannot do (it would block behind the connection mutex this wait
// holds). A thread descheduled for more than the gap in the middle of a wait restarts that
// wait's clock, so its budget can then be exceeded by up to that gap; the budgets here are
// seconds, not a hard real-time bound.
int kv_busy_handler(void* ctx, int count) noexcept {
    struct WaitClock {
        std::chrono::steady_clock::time_point start{};
        std::chrono::steady_clock::time_point last{};
        bool seen{false};
    };
    thread_local WaitClock wait;
    const auto now = std::chrono::steady_clock::now();
    if (count == 0 || !wait.seen || now - wait.last > kBusyWaitRestartGap)
        wait.start = now;
    wait.seen = true;
    wait.last = now;
    const auto* busy = static_cast<const KvBusyState*>(ctx);
    const auto limit = std::chrono::milliseconds{busy->budget_ms.load(std::memory_order_relaxed)};
    if (now - wait.start >= limit)
        return 0;
    std::this_thread::sleep_for(busy_retry_sleep(count));
    return 1;
}

} // namespace

// Private constructor
KvStore::KvStore(sqlite3* db, std::unique_ptr<KvBusyState> busy) : db_{db}, busy_{std::move(busy)} {}

KvStore::~KvStore() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

KvStore::KvStore(KvStore&& other) noexcept : db_{other.db_}, busy_{std::move(other.busy_)} {
    other.db_ = nullptr;
}

KvStore& KvStore::operator=(KvStore&& other) noexcept {
    if (this != &other) {
        // Close the connection BEFORE releasing the context it points at. Defensive ordering,
        // not a measured need: closing a connection does not run the busy handler (SQLite's
        // close-time checkpoint passes no handler; a review measured 0 handler calls), but nothing here
        // should rely on that staying true across SQLite versions.
        if (db_)
            sqlite3_close(db_);
        db_ = other.db_;
        busy_ = std::move(other.busy_);
        other.db_ = nullptr;
    }
    return *this;
}

std::expected<KvStore, KvStoreError> KvStore::open(const std::filesystem::path& db_path) {
    // Ensure parent directory exists
    std::error_code ec;
    auto parent = db_path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, ec);
        if (ec) {
            return std::unexpected(KvStoreError{
                std::format("failed to create directory {}: {}", parent.string(), ec.message())});
        }
    }

    // The busy handler's context is allocated BEFORE the connection exists, so a failed
    // allocation (bad_alloc) has no sqlite3* to leak, and every later early return frees it
    // through the unique_ptr (#5604).
    auto busy = std::make_unique<KvBusyState>();
    busy->budget_ms.store(kKvStoreBusyTimeout.count(), std::memory_order_relaxed);

    sqlite3* raw_db = nullptr;
    int rc = sqlite3_open_v2(db_path.string().c_str(), &raw_db,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             nullptr);
    if (rc != SQLITE_OK) {
        std::string err = raw_db ? sqlite3_errmsg(raw_db) : "unknown error";
        if (raw_db)
            sqlite3_close(raw_db);
        return std::unexpected(
            KvStoreError{std::format("failed to open kv_store.db: {}", err)});
    }

    // WAL mode for better concurrent read performance
    char* err_msg = nullptr;
    rc = sqlite3_exec(raw_db, "PRAGMA journal_mode=WAL", nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::warn("KvStore: WAL mode failed: {}", err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
    }

    // Busy handling for concurrent access (#5604): a handler reading an atomic budget instead of
    // sqlite3_busy_timeout(), so GuardianEngine::stop() can lower the budget lock-free and cut a
    // wait already in progress. Starts at kKvStoreBusyTimeout, the old behaviour. Installing a
    // handler on an open connection cannot fail (SQLite returns SQLITE_OK; SQLITE_MISUSE is only
    // reachable for a closed or invalid handle), so a non-OK result is unreachable here. It is
    // logged and tolerated rather than cleaned up by hand: the store then fails a locked write at
    // once instead of waiting, and set_busy_timeout() has nothing to lower.
    rc = sqlite3_busy_handler(raw_db, &kv_busy_handler, busy.get());
    if (rc != SQLITE_OK)
        spdlog::error("KvStore: installing the busy handler failed (rc={}); a locked database "
                      "will fail writes at once",
                      rc);

    // Create table.
    //
    // `key` MUST stay BINARY-collated (SQLite's default - do NOT add COLLATE NOCASE or any
    // other collation). Guardian's durable journal mints fixed-width keys whose leading field
    // is a zero-padded timestamp precisely so that `ORDER BY key` IS chronological order, and
    // its retention pass evicts oldest-first off that ordering. A collation change here would
    // silently reorder those scans and evict the wrong audit records - with nothing in that
    // component able to detect it, because it never sees this schema (governance Gate 3
    // architect). The PRIMARY KEY's implicit index is also what makes the prefix scans
    // ordered-by-key for free; see list_keys_sized.
    const char* create_sql = R"(
        CREATE TABLE IF NOT EXISTS kv_store (
            plugin     TEXT NOT NULL,
            key        TEXT NOT NULL,
            value      TEXT,
            updated_at INTEGER,
            PRIMARY KEY(plugin, key)
        )
    )";
    err_msg = nullptr;
    rc = sqlite3_exec(raw_db, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string err = err_msg ? err_msg : "unknown error";
        sqlite3_free(err_msg);
        sqlite3_close(raw_db);
        return std::unexpected(
            KvStoreError{std::format("failed to create kv_store table: {}", err)});
    }

    spdlog::info("KvStore opened: {}", db_path.string());
    return KvStore{raw_db, std::move(busy)};
}

void KvStore::set_busy_timeout(std::chrono::milliseconds budget) noexcept {
    // Deliberately not under mu_: a call waiting on a locked database holds the connection
    // mutex (and mu_) for its whole wait, and the point is to shorten that wait.
    if (busy_) {
        // Clamped so a caller's value can never overflow the handler's millisecond-to-clock
        // conversion (a budget beyond about 9.2e12 ms overflows int64 nanoseconds, which is
        // undefined behaviour): negative and zero both mean "do not wait".
        const auto clamped = (std::clamp)(budget, kKvStoreMinBusyTimeout, kKvStoreMaxBusyTimeout);
        busy_->budget_ms.store(clamped.count(), std::memory_order_relaxed);
    }
}

int KvStore::busy_handler_for_test(int count) noexcept {
    return busy_ ? kv_busy_handler(busy_.get(), count) : 0;
}

std::chrono::milliseconds KvStore::busy_retry_sleep_for_test(int count) noexcept {
    return busy_retry_sleep(count);
}

std::chrono::milliseconds KvStore::busy_timeout_for_test() const noexcept {
    return busy_ ? std::chrono::milliseconds{busy_->budget_ms.load(std::memory_order_relaxed)}
                 : std::chrono::milliseconds{0};
}

bool KvStore::set(std::string_view plugin, std::string_view key, std::string_view value) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    const char* sql = R"(
        INSERT INTO kv_store (plugin, key, value, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(plugin, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    )";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::set prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, value.data(), static_cast<int>(value.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 4, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("KvStore::set step failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

std::optional<std::string> KvStore::get(std::string_view plugin, std::string_view key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::nullopt;

    const char* sql = "SELECT value FROM kv_store WHERE plugin = ? AND key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::get prepare failed: {}", sqlite3_errmsg(db_));
        return std::nullopt;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        return std::string(text ? text : "");
    }
    return std::nullopt;
}

bool KvStore::del(std::string_view plugin, std::string_view key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    const char* sql = "DELETE FROM kv_store WHERE plugin = ? AND key = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::del prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("KvStore::del step failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    return true;
}

bool KvStore::exists(std::string_view plugin, std::string_view key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return false;

    const char* sql = "SELECT 1 FROM kv_store WHERE plugin = ? AND key = ? LIMIT 1";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::exists prepare failed: {}", sqlite3_errmsg(db_));
        return false;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    return rc == SQLITE_ROW;
}

std::vector<std::string> KvStore::list(std::string_view plugin, std::string_view prefix) {
    std::lock_guard lock(mu_);
    std::vector<std::string> result;
    if (!db_)
        return result;

    // L6: Escape LIKE wildcards (%, _, \) in the prefix to prevent unintended matching
    const std::string escaped_prefix = escape_like_prefix(prefix);

    const char* sql = "SELECT key FROM kv_store WHERE plugin = ? AND key LIKE ? ESCAPE '\\' ORDER BY key";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::list prepare failed: {}", sqlite3_errmsg(db_));
        return result;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, escaped_prefix.c_str(), static_cast<int>(escaped_prefix.size()), SQLITE_STATIC);

    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        auto text = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        if (text)
            result.emplace_back(text);
    }
    return result;
}

int KvStore::clear(std::string_view plugin) {
    std::lock_guard lock(mu_);
    if (!db_)
        return 0;

    const char* sql = "DELETE FROM kv_store WHERE plugin = ?";

    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::clear prepare failed: {}", sqlite3_errmsg(db_));
        return 0;
    }
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        spdlog::error("KvStore::clear step failed: {}", sqlite3_errmsg(db_));
        return 0;
    }
    return sqlite3_changes(db_);
}

std::expected<std::vector<KvRow>, KvStoreError>
KvStore::list_entries(std::string_view plugin, std::string_view prefix) {
    std::lock_guard lock(mu_);
    std::vector<KvRow> result;
    if (!db_)
        return std::unexpected(KvStoreError{"kv_store is closed"});

    const std::string escaped_prefix = escape_like_prefix(prefix);

    const char* sql =
        "SELECT key, value FROM kv_store WHERE plugin = ? AND key LIKE ? ESCAPE '\\' ORDER BY key";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected(
            KvStoreError{std::format("list_entries prepare failed: {}", sqlite3_errmsg(db_))});
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, escaped_prefix.c_str(),
                      static_cast<int>(escaped_prefix.size()), SQLITE_STATIC);

    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        const auto* ktext = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        // Read the value as a BLOB so an embedded NUL is preserved (a corrupt
        // value must reach the parser intact to be quarantined, not silently
        // truncated by column_text).
        const auto* vblob = static_cast<const char*>(sqlite3_column_blob(stmt.get(), 1));
        const int vbytes = sqlite3_column_bytes(stmt.get(), 1);
        result.push_back(KvRow{ktext ? std::string(ktext) : std::string{},
                               vblob ? std::string(vblob, static_cast<std::size_t>(vbytes))
                                     : std::string{}});
    }
    // A mid-scan error must NOT be mistaken for end-of-rows (the raw list()
    // while-loop cannot tell the difference - that is the bug this fixes).
    if (rc != SQLITE_DONE)
        return std::unexpected(
            KvStoreError{std::format("list_entries step failed: {}", sqlite3_errmsg(db_))});
    return result;
}

std::expected<KvNamespaceSize, KvStoreError>
KvStore::namespace_size(std::string_view plugin, std::string_view prefix) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected(KvStoreError{"kv_store is closed"});

    const std::string escaped_prefix = escape_like_prefix(prefix);

    // octet_length(value) is the BYTE length of the value's UTF-8 encoding - matching
    // KvRow::value.size() and persist()'s value.size() accounting. It is deliberately NOT bare
    // LENGTH(): LENGTH() on a TEXT column counts CHARACTERS, under-counting a multibyte value so
    // the byte gauge reads low - the one direction that loosens the write ceiling. It is chosen
    // over the equally byte-correct LENGTH(CAST(value AS BLOB)) because octet_length keeps
    // SQLite's header-only length path (no overflow-page reads on spilled values); available
    // since SQLite 3.43 (the vendored build is far newer). COALESCE covers the empty-set SUM
    // (NULL). The aggregate always yields exactly one row.
    const char* sql = "SELECT COUNT(*), COALESCE(SUM(octet_length(value)), 0) "
                      "FROM kv_store WHERE plugin = ? AND key LIKE ? ESCAPE '\\'";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected(
            KvStoreError{std::format("namespace_size prepare failed: {}", sqlite3_errmsg(db_))});
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, escaped_prefix.c_str(),
                      static_cast<int>(escaped_prefix.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_ROW)
        return std::unexpected(
            KvStoreError{std::format("namespace_size step failed: {}", sqlite3_errmsg(db_))});

    // Both columns are non-negative by construction (COUNT, and a SUM of LENGTHs), so the
    // int64 -> uint64 widening cannot wrap; clamp anyway rather than trust a corrupt page.
    const std::int64_t n = sqlite3_column_int64(stmt.get(), 0);
    const std::int64_t b = sqlite3_column_int64(stmt.get(), 1);
    return KvNamespaceSize{n > 0 ? static_cast<std::uint64_t>(n) : 0,
                           b > 0 ? static_cast<std::uint64_t>(b) : 0};
}

std::expected<std::vector<KvKeySize>, KvStoreError>
KvStore::list_keys_sized(std::string_view plugin, std::string_view prefix) {
    std::lock_guard lock(mu_);
    std::vector<KvKeySize> result;
    if (!db_)
        return std::unexpected(KvStoreError{"kv_store is closed"});

    const std::string escaped_prefix = escape_like_prefix(prefix);

    // octet_length(value), not the value itself: the point of this method is that a scan over a
    // namespace at its byte ceiling costs the key column and a header-only length read, never the
    // value pages. See namespace_size() for why octet_length rather than LENGTH().
    const char* sql = "SELECT key, octet_length(value) FROM kv_store "
                      "WHERE plugin = ? AND key LIKE ? ESCAPE '\\' ORDER BY key";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected(
            KvStoreError{std::format("list_keys_sized prepare failed: {}", sqlite3_errmsg(db_))});
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, escaped_prefix.c_str(),
                      static_cast<int>(escaped_prefix.size()), SQLITE_STATIC);

    while ((rc = sqlite3_step(stmt.get())) == SQLITE_ROW) {
        const auto* ktext = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        const std::int64_t b = sqlite3_column_int64(stmt.get(), 1);
        result.push_back(KvKeySize{ktext ? std::string(ktext) : std::string{},
                                   b > 0 ? static_cast<std::uint64_t>(b) : 0});
    }
    // Same mid-scan discipline as list_entries(): an error is not end-of-rows.
    if (rc != SQLITE_DONE)
        return std::unexpected(
            KvStoreError{std::format("list_keys_sized step failed: {}", sqlite3_errmsg(db_))});
    return result;
}

std::expected<std::optional<std::string>, KvStoreError>
KvStore::get_entry(std::string_view plugin, std::string_view key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return std::unexpected(KvStoreError{"kv_store is closed"});

    const char* sql = "SELECT value FROM kv_store WHERE plugin = ? AND key = ?";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK)
        return std::unexpected(
            KvStoreError{std::format("get_entry prepare failed: {}", sqlite3_errmsg(db_))});
    StmtPtr stmt(raw_stmt);

    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        // Blob read: an embedded NUL must survive to the parser (list_entries() rationale).
        const auto* vblob = static_cast<const char*>(sqlite3_column_blob(stmt.get(), 0));
        const int vbytes = sqlite3_column_bytes(stmt.get(), 0);
        return std::optional<std::string>{
            vblob ? std::string(vblob, static_cast<std::size_t>(vbytes)) : std::string{}};
    }
    if (rc == SQLITE_DONE)
        return std::optional<std::string>{}; // absent, definitively
    return std::unexpected(
        KvStoreError{std::format("get_entry step failed: {}", sqlite3_errmsg(db_))});
}

KvInsert KvStore::insert_if_absent(std::string_view plugin, std::string_view key,
                                   std::string_view value) {
    std::lock_guard lock(mu_);
    if (!db_)
        return KvInsert::Error;

    const char* sql = R"(
        INSERT INTO kv_store (plugin, key, value, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(plugin, key) DO NOTHING
        RETURNING 1
    )";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::insert_if_absent prepare failed: {}", sqlite3_errmsg(db_));
        return KvInsert::Error;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, key.data(), static_cast<int>(key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, value.data(), static_cast<int>(value.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 4, now_epoch_seconds());

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        // A RETURNING row means the row was inserted, but the autocommit COMMIT (WAL fsync)
        // only completes at the TERMINAL step. Drain to SQLITE_DONE so a commit failure
        // (SQLITE_FULL / SQLITE_IOERR) after the returned row surfaces here as Error instead
        // of a false Inserted that would let the caller drop a not-yet-durable record.
        rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_DONE)
            return KvInsert::Inserted;
        spdlog::error("KvStore::insert_if_absent commit failed: {}", sqlite3_errmsg(db_));
        return KvInsert::Error;
    }
    if (rc == SQLITE_DONE)
        return KvInsert::Exists; // conflict: nothing inserted (no row), no durable change
    spdlog::error("KvStore::insert_if_absent step failed: {}", sqlite3_errmsg(db_));
    return KvInsert::Error;
}

KvRename KvStore::rename_key(std::string_view plugin, std::string_view from_key,
                             std::string_view to_key) {
    std::lock_guard lock(mu_);
    if (!db_)
        return KvRename::Error;

    const char* sql = "UPDATE kv_store SET key = ? WHERE plugin = ? AND key = ? RETURNING 1";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::rename_key prepare failed: {}", sqlite3_errmsg(db_));
        return KvRename::Error;
    }
    StmtPtr stmt(raw_stmt);
    sqlite3_bind_text(stmt.get(), 1, to_key.data(), static_cast<int>(to_key.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, plugin.data(), static_cast<int>(plugin.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, from_key.data(), static_cast<int>(from_key.size()),
                      SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_ROW) {
        // Drain to the terminal step so a commit failure after the RETURNING row surfaces as
        // Error, not a false Renamed (same durability reason as insert_if_absent).
        rc = sqlite3_step(stmt.get());
        if (rc == SQLITE_DONE)
            return KvRename::Renamed;
        spdlog::error("KvStore::rename_key commit failed: {}", sqlite3_errmsg(db_));
        return KvRename::Error;
    }
    if (rc == SQLITE_DONE)
        return KvRename::NotFound; // from_key matched no row
    // Mask to the PRIMARY result code (#2303 K1). Extended result codes are off on this
    // connection today, so a bare == SQLITE_CONSTRAINT happens to match; the moment anything
    // enables sqlite3_extended_result_codes() the step would return SQLITE_CONSTRAINT_PRIMARYKEY
    // (1555) and a genuine PK conflict would silently misreport as Error. Masking makes the
    // classification independent of that setting.
    if ((rc & 0xFF) == SQLITE_CONSTRAINT)
        return KvRename::Conflict; // to_key already exists (PK), ABORT default
    spdlog::error("KvStore::rename_key step failed: {}", sqlite3_errmsg(db_));
    return KvRename::Error;
}

int KvStore::del_keys(std::string_view plugin, const std::vector<std::string>& keys) {
    std::lock_guard lock(mu_);
    if (!db_ || keys.empty())
        return 0;

    if (sqlite3_exec(db_, "BEGIN", nullptr, nullptr, nullptr) != SQLITE_OK) {
        spdlog::error("KvStore::del_keys BEGIN failed: {}", sqlite3_errmsg(db_));
        return 0;
    }

    // RAII: ROLLBACK on ANY early return between BEGIN and a successful COMMIT unless disarmed,
    // so the hand-rolled transaction stays balanced against a future added early-return
    // (cpp-safety review). Disarmed only after COMMIT succeeds.
    struct TxnGuard {
        sqlite3* db;
        bool committed{false};
        ~TxnGuard() {
            if (!committed)
                sqlite3_exec(db, "ROLLBACK", nullptr, nullptr, nullptr);
        }
    } txn{db_};

    const char* sql = "DELETE FROM kv_store WHERE plugin = ? AND key = ? RETURNING 1";
    sqlite3_stmt* raw_stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &raw_stmt, nullptr);
    if (rc != SQLITE_OK) {
        spdlog::error("KvStore::del_keys prepare failed: {}", sqlite3_errmsg(db_));
        return 0; // TxnGuard rolls back
    }
    StmtPtr stmt(raw_stmt);

    int deleted = 0;
    for (const auto& k : keys) {
        sqlite3_bind_text(stmt.get(), 1, plugin.data(), static_cast<int>(plugin.size()),
                          SQLITE_STATIC);
        sqlite3_bind_text(stmt.get(), 2, k.data(), static_cast<int>(k.size()), SQLITE_STATIC);
        rc = sqlite3_step(stmt.get());
        while (rc == SQLITE_ROW) { // 0 or 1 rows per key (PK), but drain defensively
            ++deleted;
            rc = sqlite3_step(stmt.get());
        }
        if (rc != SQLITE_DONE) {
            spdlog::error("KvStore::del_keys step failed: {}", sqlite3_errmsg(db_));
            return 0; // TxnGuard rolls back
        }
        sqlite3_reset(stmt.get());
        sqlite3_clear_bindings(stmt.get());
    }

    if (sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr) != SQLITE_OK) {
        spdlog::error("KvStore::del_keys COMMIT failed: {}", sqlite3_errmsg(db_));
        return 0; // TxnGuard rolls back
    }
    txn.committed = true;
    return deleted;
}

int KvStore::pragma_synchronous() {
    std::lock_guard lock(mu_);
    if (!db_)
        return -1;
    sqlite3_stmt* raw_stmt = nullptr;
    if (sqlite3_prepare_v2(db_, "PRAGMA synchronous", -1, &raw_stmt, nullptr) != SQLITE_OK)
        return -1;
    StmtPtr stmt(raw_stmt);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW)
        return sqlite3_column_int(stmt.get(), 0);
    return -1;
}

void KvStore::enable_extended_result_codes_for_test() {
    std::lock_guard lock(mu_);
    if (db_)
        sqlite3_extended_result_codes(db_, 1);
}

} // namespace yuzu::agent
