/**
 * test_tar_local_dispatcher.cpp -- loads the ACTUAL built tar plugin
 * (tar.dylib/.so/.dll) via PluginHandle::load and drives init() + status
 * through LocalDispatcher / StandalonePluginContext (with a real KvStore, so
 * the plugin's heartbeat.* publish is observable).
 *
 * Covers the #1567 chain the pure-part tests cannot: corrupt tar.db at boot ->
 * quarantine -> db_health status line -> reconcile into the heartbeat KV keys
 * (idempotent replay) -> the #1846 status keys. Unguarded on every OS.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
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

fs::path find_tar_plugin() {
    const std::string lib_name = std::string{"tar"} + kPluginExt;
    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT"))
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "tar" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "tar" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "tar" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "tar" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "tar" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "tar" / lib_name);
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

size_t count_containing(const std::vector<std::string>& rows, const std::string& needle) {
    size_t n = 0;
    for (const auto& r : rows)
        if (r.find(needle) != std::string::npos)
            ++n;
    return n;
}

} // namespace

TEST_CASE("tar plugin: corrupt boot quarantines, publishes the fleet signal, status reports it",
          "[tar][local_dispatcher][corruption]") {
    const auto plugin_path = find_tar_plugin();
    if (plugin_path.empty()) {
        if (std::getenv("MESON_BUILD_ROOT") != nullptr)
            FAIL("tar plugin library not found under meson test");
        WARN("tar plugin library not found -- skipping (run from the build root or via meson test)");
        return;
    }
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    REQUIRE(handle.has_value());
    const auto* desc = handle->descriptor();
    REQUIRE(desc != nullptr);
    REQUIRE(desc->init != nullptr);

    yuzu::test::TempDir dir_guard{"yuzu_test_tar_local_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());

    SECTION("corrupt tar.db -> one quarantine file, db_health, KV publish, idempotent replay") {
        {
            std::ofstream bad(dir_guard.path / "tar.db", std::ios::binary);
            bad << std::string(8192, 'X'); // not a SQLite file
        }
        {
            yuzu::agent::StandalonePluginContext ctx("tar", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            CHECK(desc->init(ctx.get()) == 0);

            size_t quarantined_files = 0;
            std::string quarantine_name;
            for (const auto& e : fs::directory_iterator(dir_guard.path))
                if (e.path().filename().string().rfind("tar.db.corrupt-", 0) == 0) {
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
            CHECK(count_containing(rows, "_last_status|") == 16);
            CHECK(count_containing(rows, "_last_status_at|") == 16);
            CHECK(count_containing(rows, "_consecutive_failures|") == 16);

            CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
            const auto last = kv->get("tar", "heartbeat.db_quarantine_last");
            REQUIRE(last.has_value());
            CHECK(last == std::optional<std::string>{epoch + ":" + quarantine_name});
            desc->shutdown(ctx.get());

            // Second init on the same data dir: replay is idempotent.
            yuzu::agent::StandalonePluginContext ctx2("tar", {{"agent.data_dir", dir_guard.path.string()}},
                                                      &*kv);
            REQUIRE(desc->init(ctx2.get()) == 0);
            CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
            CHECK(kv->get("tar", "heartbeat.db_quarantine_last") == last);
            desc->shutdown(ctx2.get());
        }
    }

    SECTION("failed `last` publish is not re-counted; counter advances once per quarantine") {
        const auto quarantine_basenames = [&] {
            std::vector<std::string> names;
            for (const auto& e : fs::directory_iterator(dir_guard.path)) {
                const auto n = e.path().filename().string();
                if (n.rfind("tar.db.corrupt-", 0) == 0)
                    names.push_back(n);
            }
            return names;
        };
        const auto corrupt_db = [&] {
            std::ofstream bad(dir_guard.path / "tar.db", std::ios::binary | std::ios::trunc);
            bad << std::string(8192, 'X');
        };
        const auto init_shutdown = [&] {
            yuzu::agent::StandalonePluginContext ctx("tar", {{"agent.data_dir", dir_guard.path.string()}},
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
        CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
        CHECK_FALSE(kv->get("tar", "heartbeat.db_quarantine_last").has_value());

        REQUIRE(exec("DROP TRIGGER block_last_ins"));
        REQUIRE(exec("DROP TRIGGER block_last_upd"));
        init_shutdown();
        auto names = quarantine_basenames();
        REQUIRE(names.size() == 1);
        const auto first_last = kv->get("tar", "heartbeat.db_quarantine_last");
        REQUIRE(first_last.has_value());
        CHECK(first_last->ends_with(":" + names[0]));
        CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});

        // A second quarantine advances the counter exactly once and `last` names the newer file.
        corrupt_db();
        init_shutdown();
        names = quarantine_basenames();
        CHECK(names.size() == 2);
        CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
        const auto second_last = kv->get("tar", "heartbeat.db_quarantine_last");
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
        auto hb = kv->list("tar", "heartbeat.");
        std::sort(hb.begin(), hb.end());
        CHECK(hb == std::vector<std::string>{"heartbeat.db_corruption_total",
                                             "heartbeat.db_quarantine_last"});

        // An unreadable ledger is warn-only: never overwritten, count not reset.
        REQUIRE(kv->set("tar", "db_health.ledger", "garbage"));
        init_shutdown();
        CHECK(kv->get("tar", "db_health.ledger") == std::optional<std::string>{"garbage"});
        CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
    }

    SECTION("a torn `total` publish withholds the identity: never a stale total with a newer last") {
        const auto quarantine_basenames = [&] {
            std::vector<std::string> names;
            for (const auto& e : fs::directory_iterator(dir_guard.path)) {
                const auto n = e.path().filename().string();
                if (n.rfind("tar.db.corrupt-", 0) == 0)
                    names.push_back(n);
            }
            return names;
        };
        const auto corrupt_db = [&] {
            std::ofstream bad(dir_guard.path / "tar.db", std::ios::binary | std::ios::trunc);
            bad << std::string(8192, 'X');
        };
        const auto init_shutdown = [&] {
            yuzu::agent::StandalonePluginContext ctx("tar", {{"agent.data_dir", dir_guard.path.string()}},
                                                     &*kv);
            REQUIRE(desc->init(ctx.get()) == 0);
            desc->shutdown(ctx.get());
        };

        // First quarantine publishes cleanly.
        corrupt_db();
        init_shutdown();
        auto names = quarantine_basenames();
        REQUIRE(names.size() == 1);
        const auto first_last = kv->get("tar", "heartbeat.db_quarantine_last");
        REQUIRE(first_last.has_value());
        CHECK(first_last->ends_with(":" + names[0]));
        CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});

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
        CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"1"});
        CHECK(kv->get("tar", "heartbeat.db_quarantine_last") == first_last); // identity withheld

        REQUIRE(exec("DROP TRIGGER block_total_ins"));
        REQUIRE(exec("DROP TRIGGER block_total_upd"));
        init_shutdown();
        CHECK(kv->get("tar", "heartbeat.db_corruption_total") == std::optional<std::string>{"2"});
        const auto second_last = kv->get("tar", "heartbeat.db_quarantine_last");
        REQUIRE(second_last.has_value());
        CHECK(second_last->ends_with(":" + names[1]));
    }

    SECTION("clean boot -> db_health|ok|0") {
        yuzu::agent::StandalonePluginContext ctx("tar", {{"agent.data_dir", dir_guard.path.string()}}, &*kv);
        REQUIRE(desc->init(ctx.get()) == 0);
        yuzu::agent::LocalDispatcher d;
        const auto rows = rows_of(d.run(desc, "status").captured);
        CHECK(row_with_prefix(rows, "db_health|ok|0").has_value());
        CHECK_FALSE(kv->get("tar", "heartbeat.db_corruption_total").has_value());
        desc->shutdown(ctx.get());
    }
}
