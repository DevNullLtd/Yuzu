/**
 * test_echo_local_dispatcher.cpp -- loads the ACTUAL built echo plugin
 * (echo.dylib/.so/.dll) via PluginHandle::load and drives init() + status
 * through LocalDispatcher / StandalonePluginContext (with a real KvStore, so
 * the plugin's heartbeat.* publish is observable).
 *
 * Covers the #1567 chain the pure-part tests cannot: corrupt echo.db at boot ->
 * quarantine -> db_health status line -> reconcile into the heartbeat KV keys
 * (idempotent replay) -> the #1846 status keys. Unguarded on every OS.
 *
 * Also pins the default-on contract at the plugin seam the unit-test exe cannot
 * reach (echo_plugin.cpp is not linked there): no `<src>_enabled` seed at init, the
 * destructive purge refusing an unreadable enable flag, and `snapshot` reporting partial.
 */
#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#ifdef _WIN32
// Before anything that can pull in <windows.h> (it would drag in the old winsock.h): the
// loopback socket pair in the process-name case below is real Winsock.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <sqlite3.h>

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/process_enum.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <format>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_echo_plugin() {
    const std::string lib_name = std::string{"echo"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "echo" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "echo" / lib_name);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

std::optional<std::string> row_with_prefix(const std::vector<std::string>& rows,
                                           const std::string& p) {
    for (const auto& r : rows)
        if (r.rfind(p, 0) == 0)
            return r;
    return std::nullopt;
}

// Registered capture sources: one `<src>_last_status` health line each. The registry source
// is the 17th (Windows-only, but its health lines are emitted on every OS). Not derived from
// capture_sources(): that table lives in a TU this executable does not link.
constexpr std::size_t kEchoSourceCount = 17;

size_t count_containing(const std::vector<std::string>& rows, const std::string& needle) {
    size_t n = 0;
    for (const auto& r : rows)
        if (r.find(needle) != std::string::npos)
            ++n;
    return n;
}

// Count the `<src>_enabled` rows init left in echo_config (raw read, no plugin code).
int enabled_rows_in(const fs::path& db_path) {
    yuzu::test::SqliteHandleOwner<sqlite3> owner;
    REQUIRE(sqlite3_open_v2(db_path.string().c_str(), &owner.db, SQLITE_OPEN_READONLY, nullptr) ==
            SQLITE_OK);
    // sqlite3_exec with a callback: no statement handle to finalize on a failing REQUIRE.
    int n = -1;
    REQUIRE(sqlite3_exec(
                owner.db,
                "SELECT count(*) FROM echo_config WHERE key LIKE '%\\_enabled' ESCAPE '\\'",
                [](void* out, int, char** vals, char**) {
                    *static_cast<int*>(out) = std::atoi(vals[0]);
                    return 0;
                },
                &n, nullptr) == SQLITE_OK);
    return n;
}

// Make ONLY the read of `echo_config.value` for `key` fail (at step), from a second
// connection to the plugin's open echo.db; every other key still reads. `value`
// becomes a VIRTUAL generated column whose expression overflows for that one key; the
// expression is row-dependent, so a stored value is written first (init stores none).
// (Same technique as make_config_key_unreadable in test_echo_aggregator.cpp.)
void make_config_key_unreadable(const fs::path& db_path, const std::string& key) {
    yuzu::test::SqliteHandleOwner<sqlite3> owner;
    REQUIRE(sqlite3_open(db_path.string().c_str(), &owner.db) == SQLITE_OK);
    sqlite3_busy_timeout(owner.db, 5000);
    const auto sql =
        std::format("INSERT INTO echo_config (key, value) VALUES ('{0}', 'true') "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value; "
                    "ALTER TABLE echo_config RENAME COLUMN value TO value_raw; "
                    "ALTER TABLE echo_config ADD COLUMN value TEXT GENERATED ALWAYS AS "
                    "(CASE WHEN key = '{0}' THEN abs(-9223372036854775808 + 0 * length(key)) "
                    "ELSE value_raw END) VIRTUAL;",
                    key);
    REQUIRE(sqlite3_exec(owner.db, sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

// Run `sql` on a fresh raw connection to the plugin's echo.db (no plugin code) and return the
// rows as text, NULL as "" (empty for a statement that returns none: the seeding writes below
// use it too). A second connection to a WAL database sees what the plugin committed.
std::vector<std::vector<std::string>> raw_sql(const fs::path& db_path, const std::string& sql) {
    yuzu::test::SqliteHandleOwner<sqlite3> owner;
    REQUIRE(sqlite3_open(db_path.string().c_str(), &owner.db) == SQLITE_OK);
    sqlite3_busy_timeout(owner.db, 5000);
    std::vector<std::vector<std::string>> rows;
    REQUIRE(sqlite3_exec(
                owner.db, sql.c_str(),
                [](void* out, int n, char** vals, char**) {
                    std::vector<std::string> row;
                    for (int i = 0; i < n; ++i)
                        row.emplace_back(vals[i] ? vals[i] : "");
                    static_cast<std::vector<std::vector<std::string>>*>(out)->push_back(
                        std::move(row));
                    return 0;
                },
                &rows, nullptr) == SQLITE_OK);
    return rows;
}

// `<key>|<value>` line of the plugin's `status` action.
std::optional<std::string> plugin_status_value(yuzu::agent::LocalDispatcher& d,
                                               const YuzuPluginDescriptor* desc,
                                               const std::string& key) {
    const auto rows = rows_of(d.run(desc, "status").captured);
    const auto line = row_with_prefix(rows, key + "|");
    if (!line)
        return std::nullopt;
    return line->substr(key.size() + 1);
}

} // namespace

TEST_CASE("echo plugin: corrupt boot quarantines, publishes the fleet signal, status reports it",
          "[echo][local_dispatcher][corruption]") {
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_local_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());

    SECTION("corrupt echo.db -> one quarantine file, db_health, KV publish, idempotent replay") {
        {
            std::ofstream bad(dir_guard.path / "echo.db", std::ios::binary);
            bad << std::string(8192, 'X'); // not a SQLite file
        }
        {
            yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            CHECK(desc->init(ctx.get()) == 0);

            size_t quarantined_files = 0;
            std::string quarantine_name;
            for (const auto& e : fs::directory_iterator(dir_guard.path))
                if (e.path().filename().string().rfind("echo.db.corrupt-", 0) == 0) {
                    ++quarantined_files;
                    quarantine_name = e.path().filename().string();
                }
            CHECK(quarantined_files == 1);

            yuzu::agent::LocalDispatcher d;
            const auto rows = rows_of(d.run(desc, "status").captured);
            const auto health = row_with_prefix(rows, "db_health|quarantined|");
            REQUIRE(health.has_value());
            const auto epoch = health->substr(std::string{"db_health|quarantined|"}.size());
            CHECK(row_with_prefix(rows, "config|perf_capture_method|").has_value());
            CHECK(row_with_prefix(rows, "config|procperf_procs_seen|").has_value());
            CHECK(count_containing(rows, "_last_status|") == kEchoSourceCount);
            CHECK(count_containing(rows, "_last_status_at|") == kEchoSourceCount);
            CHECK(count_containing(rows, "_consecutive_failures|") == kEchoSourceCount);

            CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
            const auto last = kv->get("echo", "heartbeat.db_quarantine_last");
            REQUIRE(last.has_value());
            CHECK(last == std::optional<std::string>{epoch + ":" + quarantine_name});
            desc->shutdown(ctx.get());

            // Second init on the same data dir: replay is idempotent.
            yuzu::agent::StandalonePluginContext ctx2("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                      &*kv);
            REQUIRE(desc->init(ctx2.get()) == 0);
            CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
            CHECK(kv->get("echo", "heartbeat.db_quarantine_last") == last);
            desc->shutdown(ctx2.get());
        }
    }

    SECTION("failed `last` publish is not re-counted; counter advances once per quarantine") {
        const auto quarantine_basenames = [&] {
            std::vector<std::string> names;
            for (const auto& e : fs::directory_iterator(dir_guard.path)) {
                const auto n = e.path().filename().string();
                if (n.rfind("echo.db.corrupt-", 0) == 0)
                    names.push_back(n);
            }
            // directory_iterator order is unspecified, not creation order. The
            // `.corrupt-<epoch>[-n]` basenames are fixed-width-epoch and sort
            // lexicographically == chronologically (quarantine_corrupt_db's own
            // disambiguator picks '-1', '-2', ... which also sort after the
            // bare epoch), so a plain sort recovers a deterministic oldest-first
            // order for names[0]/names[1] below.
            std::sort(names.begin(), names.end());
            return names;
        };
        const auto corrupt_db = [&] {
            std::ofstream bad(dir_guard.path / "echo.db", std::ios::binary | std::ios::trunc);
            bad << std::string(8192, 'X');
        };
        const auto init_shutdown = [&] {
            yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            REQUIRE(desc->init(ctx.get()) == 0);
            desc->shutdown(ctx.get());
        };

        // Block only the `last` key on the kv table (INSERT and UPDATE).
        // Owner declared before the open: sqlite3_open populates the handle even on
        // failure, so a failing REQUIRE still unwinds through a live owner.
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open((dir_guard.path / "kv_store.db").string().c_str(), &owner.db) ==
                SQLITE_OK);
        const auto exec = [&](const char* sql) {
            return sqlite3_exec(owner.db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
        };
        REQUIRE(exec("CREATE TRIGGER block_last_ins BEFORE INSERT ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_quarantine_last' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
        REQUIRE(exec("CREATE TRIGGER block_last_upd BEFORE UPDATE ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_quarantine_last' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

        corrupt_db();
        init_shutdown();
        init_shutdown(); // replay with `last` still failing: must not re-increment
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
        CHECK_FALSE(kv->get("echo", "heartbeat.db_quarantine_last").has_value());

        REQUIRE(exec("DROP TRIGGER block_last_ins"));
        REQUIRE(exec("DROP TRIGGER block_last_upd"));
        init_shutdown();
        auto names = quarantine_basenames();
        REQUIRE(names.size() == 1);
        const auto first_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(first_last.has_value());
        CHECK(first_last->ends_with(":" + names[0]));
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});

        // A second quarantine advances the counter exactly once and `last` names the newer file.
        corrupt_db();
        init_shutdown();
        names = quarantine_basenames();
        CHECK(names.size() == 2);
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
        const auto second_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(second_last.has_value());
        CHECK(second_last != first_last);
        bool names_a_listed_file = false;
        for (const auto& n : names)
            if (second_last->ends_with(":" + n) &&
                n != first_last->substr(first_last->find(':') + 1))
                names_a_listed_file = true;
        CHECK(names_a_listed_file);

        // Only the two bridged heartbeat keys exist: the private ledger is not
        // `heartbeat.`-prefixed.
        auto hb = kv->list("echo", "heartbeat.");
        std::sort(hb.begin(), hb.end());
        CHECK(hb == std::vector<std::string>{"heartbeat.db_corruption_total",
                                             "heartbeat.db_quarantine_last"});

        // An unreadable ledger is warn-only: never overwritten, count not reset.
        REQUIRE(kv->set("echo", "db_health.ledger", "garbage"));
        init_shutdown();
        CHECK(kv->get("echo", "db_health.ledger") == std::optional<std::string>{"garbage"});
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
    }

    SECTION("a torn `total` publish withholds the identity: never a stale total with a newer last") {
        const auto quarantine_basenames = [&] {
            std::vector<std::string> names;
            for (const auto& e : fs::directory_iterator(dir_guard.path)) {
                const auto n = e.path().filename().string();
                if (n.rfind("echo.db.corrupt-", 0) == 0)
                    names.push_back(n);
            }
            // directory_iterator order is unspecified, not creation order. The
            // `.corrupt-<epoch>[-n]` basenames are fixed-width-epoch and sort
            // lexicographically == chronologically (quarantine_corrupt_db's own
            // disambiguator picks '-1', '-2', ... which also sort after the
            // bare epoch), so a plain sort recovers a deterministic oldest-first
            // order for names[0]/names[1] below.
            std::sort(names.begin(), names.end());
            return names;
        };
        const auto corrupt_db = [&] {
            std::ofstream bad(dir_guard.path / "echo.db", std::ios::binary | std::ios::trunc);
            bad << std::string(8192, 'X');
        };
        const auto init_shutdown = [&] {
            yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            REQUIRE(desc->init(ctx.get()) == 0);
            desc->shutdown(ctx.get());
        };

        // First quarantine publishes cleanly.
        corrupt_db();
        init_shutdown();
        auto names = quarantine_basenames();
        REQUIRE(names.size() == 1);
        const auto first_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(first_last.has_value());
        CHECK(first_last->ends_with(":" + names[0]));
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});

        // Block only the `total` key on the kv table (INSERT and UPDATE).
        yuzu::test::SqliteHandleOwner<sqlite3> owner;
        REQUIRE(sqlite3_open((dir_guard.path / "kv_store.db").string().c_str(), &owner.db) ==
                SQLITE_OK);
        const auto exec = [&](const char* sql) {
            return sqlite3_exec(owner.db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
        };
        REQUIRE(exec("CREATE TRIGGER block_total_ins BEFORE INSERT ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_corruption_total' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));
        REQUIRE(exec("CREATE TRIGGER block_total_upd BEFORE UPDATE ON kv_store "
                     "WHEN NEW.key = 'heartbeat.db_corruption_total' "
                     "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"));

        // Second quarantine: the ledger advances but `total` cannot publish, so
        // `last` must be withheld too -- never a stale total paired with a
        // newer identity.
        corrupt_db();
        init_shutdown();
        names = quarantine_basenames();
        REQUIRE(names.size() == 2);
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
        CHECK(kv->get("echo", "heartbeat.db_quarantine_last") == first_last); // identity withheld

        REQUIRE(exec("DROP TRIGGER block_total_ins"));
        REQUIRE(exec("DROP TRIGGER block_total_upd"));
        init_shutdown();
        CHECK(kv->get("echo", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
        const auto second_last = kv->get("echo", "heartbeat.db_quarantine_last");
        REQUIRE(second_last.has_value());
        CHECK(second_last->ends_with(":" + names[1]));
    }

    SECTION("clean boot -> db_health|ok|0") {
        yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}}, &*kv);
        REQUIRE(desc->init(ctx.get()) == 0);
        yuzu::agent::LocalDispatcher d;
        const auto rows = rows_of(d.run(desc, "status").captured);
        CHECK(row_with_prefix(rows, "db_health|ok|0").has_value());
        CHECK_FALSE(kv->get("echo", "heartbeat.db_corruption_total").has_value());
        desc->shutdown(ctx.get());
    }
}

TEST_CASE("echo plugin: every source is enabled by default with no stored flag; an unreadable flag "
          "refuses a purge and makes a snapshot partial",
          "[echo][local_dispatcher][default-on]") {
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_local_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    const auto db_path = dir_guard.path / "echo.db";
    yuzu::agent::LocalDispatcher d;

    SECTION("a fresh init seeds no flag; formerly opt-in sources read enabled and run") {
        // init used to write `<src>_enabled=false` for four of these; the registry
        // default now supplies "true", so a fresh data dir stores nothing.
        CHECK(enabled_rows_in(db_path) == 0);

        // `registry` is Windows-only, but status lists every registered source's flag on
        // every OS (unsupported ones record nothing), so it is asserted here everywhere.
        const auto rows = rows_of(d.run(desc, "status").captured);
        for (const char* src :
             {"module", "software", "netconn", "mapdrive", "netqual", "procperf", "registry"}) {
            INFO("source=" << src);
            CHECK(row_with_prefix(rows, std::format("config|{}_enabled|true", src)).has_value());
        }
        CHECK(count_containing(rows, "source_disabled") == 0);

        // The registry source's fifteen health keys are always present, at their "not
        // running" defaults before any tick has written them.
        for (const char* kv : {"registry_capture_method|none", "registry_watch_roots|0",
                               "registry_watch_roots_unarmed|0", "registry_roots_unreadable|0",
                               "registry_roots_capped|0", "registry_etw_events|0",
                               "registry_etw_dropped|0", "registry_etw_lost|0",
                               "registry_attr_attributed|0", "registry_attr_ambiguous|0",
                               "registry_attr_none|0", "registry_offline_roots|0",
                               "registry_offline_roots_unreadable|0",
                               "registry_offline_roots_deferred|0",
                               "registry_offline_discovery_incomplete|0"}) {
            INFO("key=" << kv);
            const auto expected = std::format("config|{}", kv);
            CHECK(row_with_prefix(rows, expected) == std::optional<std::string>{expected});
        }

        // The per-app leg of collect_perf is gated on source_enabled("procperf"):
        // with no stored flag it must run (baseline / unsupported_platform /
        // counters_unavailable by OS), never report source_disabled.
        const auto perf = rows_of(d.run(desc, "collect_perf").captured);
        const auto leg = row_with_prefix(perf, "echo|collect_procperf|");
        REQUIRE(leg.has_value());
        CHECK_FALSE(leg->ends_with("|source_disabled"));
    }

    SECTION("purge_source refuses when the enable flag cannot be read") {
        make_config_key_unreadable(db_path, "module_enabled");

        const YuzuParam module_params[] = {{"source", "module"}};
        const auto refused = d.run(desc, "purge_source", module_params);
        CHECK(refused.rc == 1);
        CHECK(refused.captured.find("error|config_unreadable") != std::string::npos);

        // Control: a source whose flag still reads is refused for the OTHER reason
        // (enabled by default), so the first refusal is the unreadable-flag guard.
        const YuzuParam process_params[] = {{"source", "process"}};
        const auto control = d.run(desc, "purge_source", process_params);
        CHECK(control.rc == 1);
        CHECK(control.captured.find("error|source_not_paused") != std::string::npos);
    }

    SECTION("snapshot reports partial, not complete, when an enable flag cannot be read") {
        // An unreadable flag skips its source through skip_token() and never raises
        // IncompleteCaptureError, so only the flag read in do_snapshot can name it.
        make_config_key_unreadable(db_path, "module_enabled");

        const auto snap = d.run(desc, "snapshot");
        CHECK(snap.rc != 0);
        const auto line = row_with_prefix(rows_of(snap.captured), "echo|snapshot|");
        REQUIRE(line.has_value());
        CHECK(line->starts_with("echo|snapshot|partial|"));
        CHECK(line->find("module") != std::string::npos);
    }

    desc->shutdown(ctx.get());
}

TEST_CASE("echo plugin: db_budget_bytes validates, persists and shows in status with the budget counters",
          "[echo][local_dispatcher][budget]") {
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_local_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    yuzu::agent::LocalDispatcher d;
    // Scope-exit: the loaded plugin is a process singleton, so a failed REQUIRE below must not
    // leave it initialised over a directory the guard is about to remove.
    const yuzu::test::ScopeExit shutdown_on_exit{[&] { desc->shutdown(ctx.get()); }};

    const auto status_value = [&](const std::string& key) {
        return plugin_status_value(d, desc, key);
    };

    SECTION("a fresh database reports the default budget and zeroed counters") {
        CHECK(status_value("db_budget_bytes") == std::optional<std::string>{"262144000"});
        CHECK(status_value("budget_over_bytes") == std::optional<std::string>{"0"});
        CHECK(status_value("budget_evicted_hourly_rows_total") == std::optional<std::string>{"0"});
        // The retired raw-row counter is still printed (one release), at its stored value.
        CHECK(status_value("budget_evicted_raw_rows_total") == std::optional<std::string>{"0"});
        CHECK(status_value("db_auto_vacuum") == std::optional<std::string>{"incremental"});
        CHECK(status_value("module_dedup_overflow_total") == std::optional<std::string>{"0"});
        CHECK(status_value("tcp_closing_dedup_overflow_total") == std::optional<std::string>{"0"});
        // db_size_bytes is now used pages + WAL, never zero for an initialised database.
        const auto size = status_value("db_size_bytes");
        REQUIRE(size.has_value());
        CHECK(std::stoll(*size) > 0);
    }

    SECTION("a value below the minimum or not a whole number is refused and changes nothing") {
        for (const char* bad : {"33554431", "abc", "-1", "1e9", "32MiB", "0"}) {
            INFO("value=" << bad);
            const YuzuParam params[] = {{"db_budget_bytes", bad}};
            const auto r = d.run(desc, "configure", params);
            CHECK(r.rc == 1);
            CHECK(r.captured.find("error|db_budget_bytes must be a whole number of bytes >= 33554432") !=
                  std::string::npos);
            CHECK(status_value("db_budget_bytes") == std::optional<std::string>{"262144000"});
        }
    }

    SECTION("the minimum is accepted, applied and reported") {
        const YuzuParam params[] = {{"db_budget_bytes", "33554432"}};
        const auto r = d.run(desc, "configure", params);
        CHECK(r.rc == 0);
        CHECK(r.captured.find("config|db_budget_bytes|33554432") != std::string::npos);
        CHECK(status_value("db_budget_bytes") == std::optional<std::string>{"33554432"});
    }

    SECTION("an invalid budget in a request with a valid change rejects the whole request") {
        const YuzuParam params[] = {{"retention_days", "30"}, {"db_budget_bytes", "5"}};
        const auto r = d.run(desc, "configure", params);
        CHECK(r.rc == 1);
        CHECK(status_value("retention_days") == std::optional<std::string>{"7"}); // nothing written
    }

    SECTION("a maintenance pass on a small database is a clean no-op for the budget") {
        const auto r = d.run(desc, "rollup");
        CHECK(r.rc == 0);
        CHECK(status_value("budget_over_bytes") == std::optional<std::string>{"0"});
        CHECK(status_value("budget_evicted_hourly_rows_total") == std::optional<std::string>{"0"});
    }

    SECTION("the dictionary sweep is reported and paced by its last-run marker") {
        // The sweep runs inside the maintenance pass, weekly, paced by `dict_gc_last_ts`. The
        // starved bump (the live-set scan outrunning its 2 s deadline) is not driven here: the
        // deadline is a constant inside the plugin with no seam.
        const auto db_path = dir_guard.path / "echo.db";
        const auto now_s = [] {
            return std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::system_clock::now().time_since_epoch())
                .count();
        };
        const auto marker = [&] { return std::stoll(status_value("dict_gc_last_ts").value_or("-1")); };
        const auto set_marker = [&](std::int64_t v) {
            raw_sql(db_path, std::format("INSERT INTO echo_config (key, value) VALUES "
                                         "('dict_gc_last_ts', '{}') ON CONFLICT(key) DO UPDATE SET "
                                         "value = excluded.value",
                                         v));
        };

        // never swept: both keys are reported as 0, the reply keeps its rows_aggregated line
        CHECK(status_value("dict_gc_last_ts") == std::optional<std::string>{"0"});
        CHECK(status_value("dict_gc_starved_total") == std::optional<std::string>{"0"});
        const auto before_first = now_s();
        const auto first = d.run(desc, "rollup");
        CHECK(first.rc == 0);
        CHECK(first.captured.find("echo|rollup|0|rows_aggregated") != std::string::npos);
        CHECK(marker() >= before_first); // an empty dictionary is swept at once

        // swept a day ago: the week has not elapsed, the marker is left alone
        const auto yesterday = now_s() - 86400;
        set_marker(yesterday);
        CHECK(d.run(desc, "rollup").rc == 0);
        CHECK(marker() == yesterday);

        // swept eight days ago: due, so the sweep runs and the marker advances
        const auto before_due = now_s();
        set_marker(before_due - 8 * 86400);
        CHECK(d.run(desc, "rollup").rc == 0);
        CHECK(marker() >= before_due);

        CHECK(status_value("dict_gc_starved_total") == std::optional<std::string>{"0"});
    }

    SECTION("an unreadable budget setting reads as unknown, not as the default, and the pass is "
            "skipped") {
        // An unreadable setting is not "within budget" and not the 250 MiB default: status says
        // `unknown` for both figures it feeds, and a rollup still succeeds without evicting.
        make_config_key_unreadable(dir_guard.path / "echo.db", "db_budget_bytes");
        CHECK(status_value("db_budget_bytes") == std::optional<std::string>{"unknown"});
        CHECK(status_value("budget_over_bytes") == std::optional<std::string>{"unknown"});
        const auto r = d.run(desc, "rollup");
        CHECK(r.rc == 0);
        CHECK(status_value("budget_evicted_hourly_rows_total") == std::optional<std::string>{"0"});
    }
}


TEST_CASE("echo plugin: a rollup pass on an over-budget legacy database evicts to the byte target, "
          "converts it to incremental auto_vacuum and publishes the result",
          "[echo][local_dispatcher][budget]") {
    // The public-path proof of the plugin-owned budget lifecycle (enforce_budget, the conversion
    // gate and the post-pass hygiene that do_rollup runs), which the run_budget cases cannot
    // reach. The loaded plugin is driven through the frozen C ABI, so a test has no seam to shrink
    // the thresholds: this uses the production constants (a 32 MiB budget leaves a 16 MiB data
    // target; the conversion wants a 32 MiB freelist) and pays for it in disk, about 55 MiB in the
    // temp directory. The data is sized past the 32 MiB budget itself (not only its 16 MiB data
    // target) so that `budget_over_bytes` is non-zero before any pass has run. No clock or timing
    // assertion, no process. Measured at 0.54 s with `yuzu_agent_tests --durations=yes` on an
    // Apple M4 (the writes are page-sized zeroblobs on one WAL connection, and three passes run:
    // one that can evict nothing, one the retention clock guard skips, then the evicting one that
    // also runs the conversion VACUUM); at
    // the 3-6x I/O amplification the shared CI runners show under load that is two to three
    // seconds.
    constexpr std::int64_t kMiB = 1024 * 1024;
    constexpr std::int64_t kMinBudget = 32 * kMiB;

    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_budget_rollup_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    const auto db_path = dir_guard.path / "echo.db";

    // A database as an older build left it: auto_vacuum none, and 16 MiB of pages the plugin will
    // find free once the pad rows are deleted below (the evicted rows add to them).
    (void)raw_sql(db_path,
                  "PRAGMA auto_vacuum=0; CREATE TABLE yuzu_test_pad(x BLOB);"
                  "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i < 16) "
                  "INSERT INTO yuzu_test_pad SELECT zeroblob(1048576) FROM n;");

    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    yuzu::agent::LocalDispatcher d;
    const yuzu::test::ScopeExit shutdown_on_exit{[&] { desc->shutdown(ctx.get()); }};

    // Thirty-four ~1 MiB hourly service rows (each carries a 1 MiB last_binary_path), 49 to 82
    // hours old -- past the 48 h floor: 34 MiB of data, over the 32 MiB budget and the 16 MiB
    // target. Plus one small row 47 hours old, which the 48 h floor must keep. Then free the pad,
    // so the file is mostly free pages.
    const auto now = static_cast<std::int64_t>(std::time(nullptr));
    (void)raw_sql(
        db_path,
        std::format("WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 33) "
                    "INSERT INTO service_hourly_r (hour_ts,name_id,last_binary_path) "
                    "SELECT {0} - 49 * 3600 - i * 3600, i, hex(zeroblob(524288)) FROM n;"
                    "INSERT INTO service_hourly_r (hour_ts,name_id) VALUES ({0} - 47 * 3600, 99);"
                    "DELETE FROM yuzu_test_pad;",
                    now));

    const std::string budget_text = std::to_string(kMinBudget);
    const YuzuParam budget_param[] = {{"db_budget_bytes", budget_text.c_str()}};
    REQUIRE(d.run(desc, "configure", budget_param).rc == 0);

    // Before the pass: nothing evicted, the legacy file is not incremental, and it is over target.
    const auto size_before = plugin_status_value(d, desc, "db_size_bytes");
    REQUIRE(size_before.has_value());
    CHECK(std::stoll(*size_before) > kMinBudget - 16 * kMiB);
    CHECK(plugin_status_value(d, desc, "budget_evicted_hourly_rows_total") ==
          std::optional<std::string>{"0"});
    CHECK(plugin_status_value(d, desc, "db_auto_vacuum") == std::optional<std::string>{"none"});
    // The overage is measured when asked, not cached from a pass: this database is over its
    // budget before any pass has ever run (a gauge that starts at 0 would hide it).
    const auto over_before = plugin_status_value(d, desc, "budget_over_bytes");
    REQUIRE(over_before.has_value());
    CHECK(std::stoll(*over_before) > 0);

    // A pass that can take nothing still reports the overage and evicts nothing: pause service
    // (the exemption keeps its rows), so the only over-budget data is exempt.
    const YuzuParam pause_service[] = {{"service_enabled", "false"}};
    REQUIRE(d.run(desc, "configure", pause_service).rc == 0);
    REQUIRE(d.run(desc, "rollup").rc == 0);
    CHECK(plugin_status_value(d, desc, "budget_evicted_hourly_rows_total") ==
          std::optional<std::string>{"0"});
    const auto over_paused = plugin_status_value(d, desc, "budget_over_bytes");
    REQUIRE(over_paused.has_value());
    CHECK(std::stoll(*over_paused) > 0);
    const YuzuParam resume_service[] = {{"service_enabled", "true"}};
    REQUIRE(d.run(desc, "configure", resume_service).rc == 0);

    // A pass whose retention step sees a clock-guard event skips the budget (a clock the guard
    // distrusts must not drive eviction). run_retention writes its anchor `retention_guard_last_pass`
    // on every pass; making that one write fail raises a guard failure with no decline. The WHEN
    // clause leaves the eviction counters' own echo_config writes alone, so a pass that did run
    // the budget would still evict, and the evicting pass below proves the skip was not a disarm.
    // The guard counters live in the plugin singleton and survive init/shutdown, so earlier cases in
    // this process may have moved them: the assertions are on the change this pass makes.
    const auto guard_value = [&](const std::string& line_prefix) -> std::int64_t {
        const auto line = row_with_prefix(rows_of(d.run(desc, "status").captured), line_prefix);
        return line ? std::stoll(line->substr(line_prefix.size())) : 0;
    };
    const auto skips_before = guard_value("retention_guard|__budget__|");
    const auto clock_failures_before = guard_value("retention_guard_failed|__clock_state__|");
    const auto failures_before = guard_value("retention_guard_failures_total|");
    const auto declines_before = guard_value("retention_guard_declines_total|");

    (void)raw_sql(db_path,
                  "CREATE TRIGGER yuzu_test_block_anchor_ins BEFORE INSERT ON echo_config "
                  "WHEN NEW.key = 'retention_guard_last_pass' "
                  "BEGIN SELECT RAISE(ABORT, 'blocked'); END;"
                  "CREATE TRIGGER yuzu_test_block_anchor_upd BEFORE UPDATE ON echo_config "
                  "WHEN NEW.key = 'retention_guard_last_pass' "
                  "BEGIN SELECT RAISE(ABORT, 'blocked'); END;");
    REQUIRE(d.run(desc, "rollup").rc == 0);
    // The skip is its own line and in neither total: one failure (the anchor write), no decline.
    CHECK(guard_value("retention_guard|__budget__|") == skips_before + 1);
    CHECK(guard_value("retention_guard_failed|__clock_state__|") == clock_failures_before + 1);
    CHECK(guard_value("retention_guard_failures_total|") == failures_before + 1);
    CHECK(guard_value("retention_guard_declines_total|") == declines_before);
    CHECK(plugin_status_value(d, desc, "budget_evicted_hourly_rows_total") ==
          std::optional<std::string>{"0"});
    {
        const auto kept = raw_sql(db_path, "SELECT count(*) FROM service_hourly_r");
        REQUIRE(kept.size() == 1);
        CHECK(kept[0][0] == "35");
    }
    (void)raw_sql(db_path, "DROP TRIGGER yuzu_test_block_anchor_ins;"
                           "DROP TRIGGER yuzu_test_block_anchor_upd;");

    const auto pass = d.run(desc, "rollup");
    REQUIRE(pass.rc == 0);

    // The evicting pass ends with a TRUNCATE checkpoint, so the WAL file is empty (or gone); a
    // PASSIVE one would leave the pass's own writes in it.
    std::error_code wal_ec;
    const auto wal_size = fs::file_size(fs::path{db_path.string() + "-wal"}, wal_ec);
    CHECK((wal_ec || wal_size == 0));

    // Eviction ran on the public path and took the hourly rows (enforce_budget in do_rollup); the
    // retired raw-row counter stays at its stored value.
    CHECK(plugin_status_value(d, desc, "budget_evicted_hourly_rows_total") ==
          std::optional<std::string>{"34"});
    CHECK(plugin_status_value(d, desc, "budget_evicted_raw_rows_total") ==
          std::optional<std::string>{"0"});
    // Only the 47 h row is left: the 48 h floor holds.
    const auto left = raw_sql(db_path, "SELECT count(*) FROM service_hourly_r");
    REQUIRE(left.size() == 1);
    CHECK(left[0][0] == "1");

    // The measured size dropped to within the budget and the overage is published as zero.
    const auto size_after = plugin_status_value(d, desc, "db_size_bytes");
    REQUIRE(size_after.has_value());
    CHECK(std::stoll(*size_after) < std::stoll(*size_before));
    CHECK(std::stoll(*size_after) <= kMinBudget);
    CHECK(plugin_status_value(d, desc, "budget_over_bytes") == std::optional<std::string>{"0"});

    // The conversion gate (maybe_vacuum_to_incremental in the same pass): data was under target and
    // the freelist large, so the one-off VACUUM ran, succeeded and cleared its deferral marker.
    CHECK(plugin_status_value(d, desc, "db_auto_vacuum") == std::optional<std::string>{"incremental"});
    const auto deferred =
        raw_sql(db_path, "SELECT value FROM echo_config WHERE key = 'auto_vacuum_deferred_at'");
    REQUIRE(deferred.size() == 1);
    CHECK(deferred[0][0] == "0");
}

namespace {

#ifdef _WIN32
using SockT = SOCKET;
using SockLen = int;
constexpr SockT kNoSock = INVALID_SOCKET;
void close_sock(SockT s) { ::closesocket(s); }
#else
using SockT = int;
using SockLen = socklen_t;
constexpr SockT kNoSock = -1;
void close_sock(SockT s) { ::close(s); }
#endif

std::uint32_t current_pid() {
#ifdef _WIN32
    return static_cast<std::uint32_t>(::GetCurrentProcessId());
#else
    return static_cast<std::uint32_t>(::getpid());
#endif
}

// Two ESTABLISHED loopback sockets owned by this process: a listener on 127.0.0.1 (kernel-chosen
// port, so no fixed port), a client connected to it and the accepted end. All in this thread, no
// process spawned: connect completes in the kernel before accept is called.
struct LoopbackPair {
    SockT listener{kNoSock};
    SockT client{kNoSock};
    SockT server{kNoSock};
    int listener_port{0};
    int client_port{0};

    LoopbackPair() = default;
    LoopbackPair(const LoopbackPair&) = delete;
    LoopbackPair& operator=(const LoopbackPair&) = delete;
    ~LoopbackPair() {
        for (const SockT s : {server, client, listener})
            if (s != kNoSock)
                close_sock(s);
    }

    [[nodiscard]] bool open() {
#ifdef _WIN32
        static const bool winsock_ok = [] {
            WSADATA wsa;
            return ::WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
        }();
        if (!winsock_ok)
            return false;
#endif
        const auto port_of = [](SockT s) {
            sockaddr_in a{};
            SockLen len = sizeof a;
            if (::getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0)
                return 0;
            return static_cast<int>(ntohs(a.sin_port));
        };
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        if (::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1)
            return false;
        listener = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listener == kNoSock ||
            ::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 ||
            ::listen(listener, 1) != 0)
            return false;
        listener_port = port_of(listener);
        addr.sin_port = htons(static_cast<std::uint16_t>(listener_port));
        client = ::socket(AF_INET, SOCK_STREAM, 0);
        if (client == kNoSock ||
            ::connect(client, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0)
            return false;
        server = ::accept(listener, nullptr, nullptr);
        client_port = port_of(client);
        return server != kNoSock && listener_port != 0 && client_port != 0;
    }
};

// Blocks until the peer's FIN arrives (recv returns 0), which leaves this end in CLOSE_WAIT. A
// blocking kernel event, not a poll: nothing is sent on the pair, so 0 can only mean the FIN.
bool wait_for_peer_fin(SockT s) {
    char buf[16];
#ifdef _WIN32
    return ::recv(s, buf, static_cast<int>(sizeof buf), 0) == 0;
#else
    return ::recv(s, buf, sizeof buf, 0) == 0;
#endif
}

} // namespace

TEST_CASE("echo plugin: status counts each source's finest tier and query and export "
          "read the hourly views as buckets",
          "[echo][local_dispatcher][tiers]") {
    // Roll-up is the only store, so there is no raw row to count or list: `status` reports the
    // finest tier's row count and its oldest bucket, and `query` / `export` return hour BUCKETS in
    // the old column shape (ts = the bucket start, action = bucket, snapshot_id = 0).
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_tiers_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    const auto db_path = dir_guard.path / "echo.db";
    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    yuzu::agent::LocalDispatcher d;
    const yuzu::test::ScopeExit shutdown_on_exit{[&] { desc->shutdown(ctx.get()); }};

    // Two process buckets (hours 100 and 101 of the epoch), written the way the fold writes them.
    (void)raw_sql(
        db_path,
        "INSERT INTO echo_dict (text) VALUES ('a.exe'), ('u'), ('p.exe');"
        "INSERT INTO process_hourly_r (hour_ts, name_id, user_id, parent_name_id, start_count, "
        "stop_count) VALUES "
        "(360000, (SELECT id FROM echo_dict WHERE text = 'a.exe'), "
        " (SELECT id FROM echo_dict WHERE text = 'u'), (SELECT id FROM echo_dict WHERE text = 'p.exe'), 2, 1),"
        "(363600, (SELECT id FROM echo_dict WHERE text = 'a.exe'), "
        " (SELECT id FROM echo_dict WHERE text = 'u'), (SELECT id FROM echo_dict WHERE text = 'p.exe'), 1, 0);");

    SECTION("status: rows and oldest bucket of the finest tier, the old name as an alias") {
        CHECK(plugin_status_value(d, desc, "config|process_rows") == std::optional<std::string>{"2"});
        CHECK(plugin_status_value(d, desc, "config|process_live_rows") ==
              std::optional<std::string>{"2"});
        CHECK(plugin_status_value(d, desc, "config|process_oldest_ts") ==
              std::optional<std::string>{"360000"});
        // A source with nothing folded reports 0 / 0, and the plain baseline table has its own key.
        CHECK(plugin_status_value(d, desc, "config|tcp_rows") == std::optional<std::string>{"0"});
        CHECK(plugin_status_value(d, desc, "config|tcp_oldest_ts") == std::optional<std::string>{"0"});
        // The per-boot netqual baseline lives in a plain table: the key is always reported, but
        // whether the collector has already written a row is up to the OS (Windows may have), so
        // only its presence and form are pinned.
        const auto boot_rows = plugin_status_value(d, desc, "config|netqual_boot_rows");
        REQUIRE(boot_rows.has_value());
        CHECK(!boot_rows->empty());
        CHECK(boot_rows->find_first_not_of("0123456789") == std::string::npos);
    }

    SECTION("query: one line per hour bucket, shaped like the old event rows") {
        const YuzuParam params[] = {{"type", "process"}, {"from", "0"}, {"to", "400000"}};
        const auto r = d.run(desc, "query", params);
        REQUIRE(r.rc == 0);
        const auto rows = rows_of(r.captured);
        REQUIRE(rows.size() == 3);
        CHECK(rows[0] == "360000|process|bucket|0|a.exe start=2 stop=1");
        CHECK(rows[1] == "363600|process|bucket|0|a.exe start=1 stop=0");
        CHECK(rows[2] == "total|2");
        // A window after both buckets is empty, and one that starts mid-hour still reaches the
        // bucket that began before it (a bucket is in range when it ends after `from`).
        const YuzuParam late[] = {{"type", "process"}, {"from", "400000"}, {"to", "500000"}};
        CHECK(rows_of(d.run(desc, "query", late).captured) == std::vector<std::string>{"total|0"});
        const YuzuParam mid[] = {{"type", "process"}, {"from", "361000"}, {"to", "400000"}};
        CHECK(rows_of(d.run(desc, "query", mid).captured).size() == 3); // 361000 is inside bucket 360000
        const YuzuParam second[] = {{"type", "process"}, {"from", "364000"}, {"to", "400000"}};
        const auto only_second = rows_of(d.run(desc, "query", second).captured);
        REQUIRE(only_second.size() == 2); // the 363600 bucket and the total
        CHECK(only_second[0].rfind("363600|process|bucket|0|", 0) == 0);
    }

    SECTION("export: JSON rows carry ts, snapshot_id 0 and action bucket beside the tier columns") {
        const YuzuParam params[] = {{"type", "process"}, {"from", "0"}, {"to", "400000"}};
        const auto r = d.run(desc, "export", params);
        REQUIRE(r.rc == 0);
        const auto j = nlohmann::json::parse(r.captured);
        REQUIRE(j.is_array());
        REQUIRE(j.size() == 2);
        CHECK(j[0]["ts"] == "360000");
        CHECK(j[0]["snapshot_id"] == "0");
        CHECK(j[0]["action"] == "bucket");
        CHECK(j[0]["name"] == "a.exe");
        CHECK(j[0]["start_count"] == "2");
        CHECK(j[1]["start_count"] == "1");
    }
}

TEST_CASE("echo plugin: a polled tcp row is named by the process source, and stays unnamed once "
          "that source is paused",
          "[echo][local_dispatcher][pidname]") {
    // The poll legs set a socket's pid but never its process name, so on this host the only thing
    // that names a stored tcp row is the plugin's pid -> name map (filled from the process poll).
    // That map is plugin-private behind the frozen C ABI, hence the public path: a real socket
    // pair owned by this process, one `collect_fast`, and a read of what the hourly tcp tier stored.
    //
    // Why real loopback sockets (the test-efficiency rule asks for the justification): the only
    // input `collect_fast` takes through the frozen ABI is the OS socket table itself. There is no
    // seam to hand the loaded .dylib/.so/.dll a fixture connection list (the collector is a free
    // function the plugin calls directly), so the one way to put a row with THIS pid in front of
    // the poll leg is to own a socket. Loopback is the cheapest such socket: no network, no DNS
    // for its own addresses (the collector skips 127.0.0.1), kernel-chosen ports, torn down with
    // the pair. The remaining host dependence is the collector's reverse-DNS pass over whatever
    // OTHER sockets the host has open, bounded by its 3 s per-snapshot budget (the plugin has no
    // switch to turn it off). The poll leg is the path for an unprivileged macOS user and for
    // Linux and Windows always; as root on macOS the nstat stream becomes the primary tcp source
    // and bypasses the poll leg, so the case is skipped there rather than asserting on a path
    // the host would not take.
#ifdef __APPLE__
    if (::geteuid() == 0) {
        WARN("running as root on macOS: nstat is the primary tcp source and the poll leg under "
             "test is bypassed -- skipping");
        return;
    }
#endif
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_pidname_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    const auto db_path = dir_guard.path / "echo.db";
    yuzu::agent::LocalDispatcher d;

    // The loaded plugin instance outlives init/shutdown in this process and its source-health
    // ledger is not reset by init, so whatever happens below the process source must be left
    // reporting an enabled token (a later case reads `status` and expects no source_disabled in
    // it) and the plugin shut down. Scope-exit, so a failed REQUIRE after the pause cannot leave
    // the singleton paused for the rest of the run. CHECK only: this runs during unwind.
    const YuzuParam resume[] = {{"process_enabled", "true"}};
    const yuzu::test::ScopeExit restore_process_source{[&] {
        CHECK(d.run(desc, "configure", resume).rc == 0);
        (void)d.run(desc, "collect_fast");
        desc->shutdown(ctx.get());
    }};

    // The name the process enumeration reports for this very process: what the poll seeds the map
    // with, so it is the name a correctly named row must carry.
    std::string expected;
    for (const auto& p : yuzu::agent::enumerate_processes())
        if (p.pid == current_pid())
            expected = p.name;
    if (expected.empty()) {
        // A sandbox or container that denies process listing: the poll could not have named
        // this process either, so the case has nothing to check. Same idiom as the root skip.
        WARN("process enumeration cannot name this process -- skipping (restricted environment)");
        return;
    }

    // The client end of a pair: the row whose remote port is the listener's. The listening socket
    // itself folds into the same tier as remote_addr='*', so the wildcard is excluded. The tier
    // keeps no pid or local port: the process name is the key that carries the attribution.
    const auto stored_row = [&](const LoopbackPair& pair) {
        return raw_sql(db_path,
                       std::format("SELECT process_name FROM tcp_hourly WHERE remote_port = {} "
                                   "AND remote_addr <> '*'",
                                   pair.listener_port));
    };

    LoopbackPair first;
    REQUIRE(first.open());
    {
        const auto r = d.run(desc, "collect_fast");
        INFO(r.captured);
        const auto rows = stored_row(first);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0][0] == expected);
    }

    // A confirmed disable forgets the map: a socket opened afterwards is stored unnamed rather
    // than under a name the paused source would no longer have learned.
    const YuzuParam pause[] = {{"process_enabled", "false"}};
    REQUIRE(d.run(desc, "configure", pause).rc == 0);
    LoopbackPair second;
    REQUIRE(second.open());
    {
        const auto r = d.run(desc, "collect_fast");
        INFO(r.captured);
        const auto rows = stored_row(second);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0][0].empty());
    }
}

TEST_CASE("echo plugin: a closing tcp socket whose insert failed is recorded on the next tick, not "
          "lost to the hourly de-duplication",
          "[echo][local_dispatcher][closing_dedup]") {
    // A socket first seen already closing is recorded once per hour per (process, remote). The
    // hour's seen-set must advance only when the rows commit: a tick whose insert fails persists
    // neither the rows nor the baseline, so the next tick re-derives the same first sighting and
    // must still record it. A seen-set committed before the insert would swallow that row for the
    // rest of the hour. The set is plugin-private behind the frozen C ABI, so the case drives the
    // public path: an accepted socket in CLOSE_WAIT, a trigger that fails the first tick's insert,
    // then a second tick.
    //
    // Real loopback sockets, as in the process-name case above: the only input collect_fast takes
    // is the OS socket table, and a socket pair owned by this process is the cheapest way to put a
    // closing socket in front of it. No process, no timing assumption (the CLOSE_WAIT state is
    // reached by a blocking recv for the peer's FIN). As root on macOS the nstat stream is the
    // primary tcp source and bypasses the poll leg under test, so the case is skipped there.
#ifdef __APPLE__
    if (::geteuid() == 0) {
        WARN("running as root on macOS: nstat is the primary tcp source and the poll leg under "
             "test is bypassed -- skipping");
        return;
    }
#endif
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_closing_dedup_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    const auto db_path = dir_guard.path / "echo.db";
    yuzu::agent::LocalDispatcher d;
    const yuzu::test::ScopeExit shutdown_on_exit{[&] { desc->shutdown(ctx.get()); }};

    // A sandbox or container that denies process listing also denies the collector sight of this
    // process's sockets: nothing to check there. Same idiom as the process-name case.
    bool lists_own_process = false;
    for (const auto& p : yuzu::agent::enumerate_processes())
        if (p.pid == current_pid())
            lists_own_process = true;
    if (!lists_own_process) {
        WARN("process enumeration cannot see this process -- skipping (restricted environment)");
        return;
    }

    // The accepted end becomes CLOSE_WAIT once the client closes and its FIN has arrived; that
    // end still has an fd here, so both the macOS fd walk and the Linux inode map keep it.
    LoopbackPair pair;
    REQUIRE(pair.open());
    close_sock(pair.client);
    pair.client = kNoSock;
    REQUIRE(wait_for_peer_fin(pair.server));

    // The accepted end's row: its remote port is the client's. A first sighting already closing
    // is recorded as a connection (connect_count 1).
    const auto closing_rows = [&] {
        return raw_sql(db_path, std::format("SELECT connect_count FROM tcp_hourly WHERE "
                                            "remote_port = {}",
                                            pair.client_port));
    };

    (void)raw_sql(db_path, "CREATE TRIGGER yuzu_test_block_tcp BEFORE INSERT ON tcp_hourly_r "
                           "BEGIN SELECT RAISE(ABORT, 'blocked'); END;");
    {
        const auto r = d.run(desc, "collect_fast");
        INFO(r.captured);
        CHECK(r.rc == 1);
    }
    CHECK(closing_rows().empty());
    (void)raw_sql(db_path, "DROP TRIGGER yuzu_test_block_tcp;");

    {
        const auto r = d.run(desc, "collect_fast");
        INFO(r.captured);
        CHECK(r.rc == 0);
    }
    const auto rows = closing_rows();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0][0] == "1");
}

TEST_CASE("echo plugin: a query over a retired $X_Live name answers no rows and a CONSTRAINED status",
          "[echo][local_dispatcher][sql][shim]") {
    // The empty shim view makes a stored query succeed with `__total__|0`; the typed result status
    // is what tells a schedule, a result-set producer or an operator that the table is retired,
    // not that nothing happened. A query over a tier view carries no such status.
    const auto plugin_path = find_echo_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("echo plugin library not found under meson test");
        WARN("echo plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_echo_shim_sql_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    yuzu::agent::StandalonePluginContext ctx("echo", {{"agent.data_dir", dir_guard.path.string()}},
                                             &*kv);
    REQUIRE(desc->init(ctx.get()) == 0);
    yuzu::agent::LocalDispatcher d;
    const yuzu::test::ScopeExit shutdown_on_exit{[&] { desc->shutdown(ctx.get()); }};

    const YuzuParam retired[] = {{"sql", "SELECT * FROM $Process_Live"}};
    const auto r = d.run(desc, "sql", retired);
    CHECK(r.rc == 0);
    const auto rows = rows_of(r.captured);
    CHECK(row_with_prefix(rows, "__schema__|id|ts|").has_value()); // the old column shape
    CHECK(row_with_prefix(rows, "__total__|0") == std::optional<std::string>{"__total__|0"});
    CHECK(r.result_status == YUZU_RESULT_STATUS_CONSTRAINED);

    const YuzuParam live[] = {{"sql", "SELECT * FROM $Process_Hourly"}};
    const auto ok = d.run(desc, "sql", live);
    CHECK(ok.rc == 0);
    CHECK(ok.result_status != YUZU_RESULT_STATUS_CONSTRAINED);
}
