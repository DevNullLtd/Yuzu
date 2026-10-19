/**
 * test_kv_store.cpp -- Unit tests for KvStore (SQLite-backed plugin KV storage)
 *
 * Covers: basic CRUD, listing, plugin isolation, edge cases, concurrency.
 */

#include <yuzu/agent/kv_store.hpp>

// A SECOND, raw connection to the same file - the only way to make a REAL SQLite call
// fail inside KvStore (drop the table out from under it) rather than testing a
// stand-in. See the fallible-read tests at the bottom of this file.
#include <sqlite3.h>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace yuzu::agent;

// Per-uid suffix so multi-user hosts (e.g. WSL2 with both an interactive
// user and the github-runner CI account) don't collide on /tmp ownership.
// Without this, whichever uid wins the race owns /tmp/yuzu_test_kv 0700
// and locks the other uid out until someone runs `sudo rm`.
static std::string yuzu_test_uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME"))
        return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

// Helper: create a KvStore in a unique temp file. TempDbFile (adopt-a-path
// ctor) owns cleanup of the .db + -wal/-shm companions, exception-safely —
// the old manual dtor was the last of the #482-ported files still doing this
// by hand (#486). Declared FIRST so it destructs LAST: the KvStore closes
// its handle before the file is removed (Windows can't delete an open file).
struct TestKvStore {
    yuzu::test::TempDbFile db;
    KvStore store;
    fs::path path{db.path};

    TestKvStore(fs::path p, KvStore s) : db(std::move(p)), store(std::move(s)) {}
};

static TestKvStore make_test_store() {
    // Previously used `std::hash<std::thread::id>{} ^ steady_clock::now()` for
    // uniqueness — the pattern that flaked on Windows MSVC debug + Defender
    // (#473). Delegate to the shared salt+counter helper so KV tests don't
    // regress even though they haven't flaked in CI yet (#482).
    const auto dir = fs::temp_directory_path() / ("yuzu_test_kv" + yuzu_test_uid_suffix());
    const auto tmp = dir / (yuzu::test::unique_temp_path("kv_").filename().string() + ".db");
    auto result = KvStore::open(tmp);
    REQUIRE(result.has_value());
    return TestKvStore{tmp, std::move(*result)};
}

// ═══════════════════════════════════════════════════════════════════════════════
// Basic CRUD
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: open creates database file", "[kv_store][lifecycle]") {
    auto t = make_test_store();
    CHECK(fs::exists(t.path));
}

TEST_CASE("KvStore: set and get round-trip", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("myplugin", "hostname", "WORKSTATION-01"));

    auto val = t.store.get("myplugin", "hostname");
    REQUIRE(val.has_value());
    CHECK(*val == "WORKSTATION-01");
}

TEST_CASE("KvStore: set overwrites existing value", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "key", "original"));
    REQUIRE(t.store.set("p1", "key", "updated"));

    auto val = t.store.get("p1", "key");
    REQUIRE(val.has_value());
    CHECK(*val == "updated");
}

TEST_CASE("KvStore: get non-existent key returns nullopt", "[kv_store][crud]") {
    auto t = make_test_store();
    auto val = t.store.get("p1", "no-such-key");
    CHECK_FALSE(val.has_value());
}

TEST_CASE("KvStore: delete key then get returns nullopt", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "to-delete", "value"));
    REQUIRE(t.store.del("p1", "to-delete"));

    auto val = t.store.get("p1", "to-delete");
    CHECK_FALSE(val.has_value());
}

TEST_CASE("KvStore: delete non-existent key returns true", "[kv_store][crud]") {
    auto t = make_test_store();
    // del returns true even when key didn't exist
    CHECK(t.store.del("p1", "never-existed"));
}

TEST_CASE("KvStore: exists for present key", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "present", "yes"));
    CHECK(t.store.exists("p1", "present"));
}

TEST_CASE("KvStore: exists for absent key", "[kv_store][crud]") {
    auto t = make_test_store();
    CHECK_FALSE(t.store.exists("p1", "absent"));
}

TEST_CASE("KvStore: exists returns false after delete", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "k", "v"));
    REQUIRE(t.store.del("p1", "k"));
    CHECK_FALSE(t.store.exists("p1", "k"));
}

TEST_CASE("KvStore: clear removes all keys for a plugin", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "a", "1"));
    REQUIRE(t.store.set("p1", "b", "2"));
    REQUIRE(t.store.set("p1", "c", "3"));

    int deleted = t.store.clear("p1");
    CHECK(deleted == 3);
    CHECK_FALSE(t.store.exists("p1", "a"));
    CHECK_FALSE(t.store.exists("p1", "b"));
    CHECK_FALSE(t.store.exists("p1", "c"));
}

TEST_CASE("KvStore: clear on empty plugin returns 0", "[kv_store][crud]") {
    auto t = make_test_store();
    int deleted = t.store.clear("empty-plugin");
    CHECK(deleted == 0);
}

TEST_CASE("KvStore: clear does not affect other plugins", "[kv_store][crud]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "key", "val1"));
    REQUIRE(t.store.set("p2", "key", "val2"));

    t.store.clear("p1");
    CHECK_FALSE(t.store.exists("p1", "key"));
    CHECK(t.store.exists("p2", "key"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Listing
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: list with empty prefix returns all keys", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "alpha", "1"));
    REQUIRE(t.store.set("p1", "beta", "2"));
    REQUIRE(t.store.set("p1", "gamma", "3"));

    auto keys = t.store.list("p1", "");
    REQUIRE(keys.size() == 3);
    // Keys should be ordered alphabetically
    CHECK(keys[0] == "alpha");
    CHECK(keys[1] == "beta");
    CHECK(keys[2] == "gamma");
}

TEST_CASE("KvStore: list with prefix filters keys", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "net.interface.eth0", "up"));
    REQUIRE(t.store.set("p1", "net.interface.eth1", "down"));
    REQUIRE(t.store.set("p1", "net.dns.primary", "8.8.8.8"));
    REQUIRE(t.store.set("p1", "disk.usage", "75%"));

    auto net_iface_keys = t.store.list("p1", "net.interface.");
    REQUIRE(net_iface_keys.size() == 2);
    CHECK(net_iface_keys[0] == "net.interface.eth0");
    CHECK(net_iface_keys[1] == "net.interface.eth1");

    auto net_keys = t.store.list("p1", "net.");
    CHECK(net_keys.size() == 3);

    auto disk_keys = t.store.list("p1", "disk.");
    CHECK(disk_keys.size() == 1);
}

TEST_CASE("KvStore: list for non-existent plugin returns empty", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "key", "val"));

    auto keys = t.store.list("nonexistent-plugin", "");
    CHECK(keys.empty());
}

TEST_CASE("KvStore: list with non-matching prefix returns empty", "[kv_store][list]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "alpha", "1"));
    REQUIRE(t.store.set("p1", "beta", "2"));

    auto keys = t.store.list("p1", "zzz");
    CHECK(keys.empty());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Plugin isolation
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: plugin A cannot see plugin B keys", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "secret", "A-value"));

    auto val = t.store.get("pluginB", "secret");
    CHECK_FALSE(val.has_value());
}

TEST_CASE("KvStore: same key name coexists across plugins", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "count", "10"));
    REQUIRE(t.store.set("pluginB", "count", "20"));

    auto a_val = t.store.get("pluginA", "count");
    auto b_val = t.store.get("pluginB", "count");

    REQUIRE(a_val.has_value());
    REQUIRE(b_val.has_value());
    CHECK(*a_val == "10");
    CHECK(*b_val == "20");
}

TEST_CASE("KvStore: plugin A list only sees own keys", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "a1", "v"));
    REQUIRE(t.store.set("pluginA", "a2", "v"));
    REQUIRE(t.store.set("pluginB", "b1", "v"));

    auto a_keys = t.store.list("pluginA", "");
    auto b_keys = t.store.list("pluginB", "");

    CHECK(a_keys.size() == 2);
    CHECK(b_keys.size() == 1);
}

TEST_CASE("KvStore: deleting plugin A key does not affect plugin B", "[kv_store][isolation]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("pluginA", "shared-name", "A"));
    REQUIRE(t.store.set("pluginB", "shared-name", "B"));

    REQUIRE(t.store.del("pluginA", "shared-name"));

    CHECK_FALSE(t.store.exists("pluginA", "shared-name"));
    CHECK(t.store.exists("pluginB", "shared-name"));
    auto b_val = t.store.get("pluginB", "shared-name");
    REQUIRE(b_val.has_value());
    CHECK(*b_val == "B");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: very long key (1000 chars)", "[kv_store][edge]") {
    auto t = make_test_store();
    std::string long_key(1000, 'k');
    REQUIRE(t.store.set("p1", long_key, "value-for-long-key"));

    auto val = t.store.get("p1", long_key);
    REQUIRE(val.has_value());
    CHECK(*val == "value-for-long-key");
    CHECK(t.store.exists("p1", long_key));
}

TEST_CASE("KvStore: very long value (100KB)", "[kv_store][edge]") {
    auto t = make_test_store();
    std::string long_value(100 * 1024, 'v');
    REQUIRE(t.store.set("p1", "big-blob", long_value));

    auto val = t.store.get("p1", "big-blob");
    REQUIRE(val.has_value());
    CHECK(val->size() == 100 * 1024);
    CHECK(*val == long_value);
}

TEST_CASE("KvStore: key with special characters", "[kv_store][edge]") {
    auto t = make_test_store();

    // Dots, dashes, underscores
    REQUIRE(t.store.set("p1", "net.interface-eth0_stats", "data"));
    auto val = t.store.get("p1", "net.interface-eth0_stats");
    REQUIRE(val.has_value());
    CHECK(*val == "data");

    // Slashes
    REQUIRE(t.store.set("p1", "path/to/resource", "found"));
    val = t.store.get("p1", "path/to/resource");
    REQUIRE(val.has_value());
    CHECK(*val == "found");

    // Colons and equals
    REQUIRE(t.store.set("p1", "key:with=symbols", "ok"));
    val = t.store.get("p1", "key:with=symbols");
    REQUIRE(val.has_value());
    CHECK(*val == "ok");
}

TEST_CASE("KvStore: empty value is stored and retrievable", "[kv_store][edge]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "empty-val", ""));

    auto val = t.store.get("p1", "empty-val");
    REQUIRE(val.has_value());
    CHECK(val->empty());
    CHECK(t.store.exists("p1", "empty-val"));
}

TEST_CASE("KvStore: empty key is stored and retrievable", "[kv_store][edge]") {
    auto t = make_test_store();
    // SQLite allows empty strings as text — the schema has no NOT NULL constraint
    // on the key column value, but the PRIMARY KEY(plugin, key) allows empty strings.
    // The implementation uses parameterized queries so empty key is just an empty TEXT.
    REQUIRE(t.store.set("p1", "", "value-for-empty-key"));

    auto val = t.store.get("p1", "");
    REQUIRE(val.has_value());
    CHECK(*val == "value-for-empty-key");
}

TEST_CASE("KvStore: value with newlines and tabs", "[kv_store][edge]") {
    auto t = make_test_store();
    std::string multiline = "line1\nline2\r\nline3\ttab";
    REQUIRE(t.store.set("p1", "multiline", multiline));

    auto val = t.store.get("p1", "multiline");
    REQUIRE(val.has_value());
    CHECK(*val == multiline);
}

TEST_CASE("KvStore: value with null bytes (binary)", "[kv_store][edge]") {
    auto t = make_test_store();
    // SQLite TEXT columns handle embedded NUL via length-specified binding,
    // but sqlite3_column_text returns a C string (stops at first NUL).
    // This test documents the actual behavior.
    std::string with_nul = std::string("before") + '\0' + "after";
    t.store.set("p1", "binary", with_nul);

    auto val = t.store.get("p1", "binary");
    // The get implementation uses sqlite3_column_text which is NUL-terminated,
    // so we expect truncation at the first NUL.
    REQUIRE(val.has_value());
    CHECK(*val == "before");
}

TEST_CASE("KvStore: multiple sets then clear returns correct count", "[kv_store][edge]") {
    auto t = make_test_store();
    for (int i = 0; i < 50; ++i) {
        REQUIRE(t.store.set("p1", "key-" + std::to_string(i), "val"));
    }
    int deleted = t.store.clear("p1");
    CHECK(deleted == 50);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Move semantics
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: move constructor transfers ownership", "[kv_store][lifecycle]") {
    // Salted per-test path: the old fixed "move_ctor.db" filename lived in a
    // USERNAME/uid-suffixed dir — identical for all 4 runner agents on a
    // shared-identity CI box, so two concurrent jobs shared the exact path
    // and cleaned up each other's live DB (#1883). TempDbFile declared FIRST
    // so removal happens after the stores close.
    yuzu::test::TempDbFile db{"yuzu_test_kv_move_ctor-"};
    auto result = KvStore::open(db.path);
    REQUIRE(result.has_value());

    auto& original = *result;
    REQUIRE(original.set("p1", "k", "v"));

    KvStore moved{std::move(original)};
    auto val = moved.get("p1", "k");
    REQUIRE(val.has_value());
    CHECK(*val == "v");
}

TEST_CASE("KvStore: move assignment transfers ownership", "[kv_store][lifecycle]") {
    yuzu::test::TempDbFile db1{"yuzu_test_kv_move_a1-"};
    yuzu::test::TempDbFile db2{"yuzu_test_kv_move_a2-"};

    auto r1 = KvStore::open(db1.path);
    auto r2 = KvStore::open(db2.path);
    REQUIRE(r1.has_value());
    REQUIRE(r2.has_value());

    r1->set("p1", "from", "store1");
    r2->set("p1", "from", "store2");

    // Move-assign r2 into r1 (r1's old db should be closed)
    *r1 = std::move(*r2);
    auto val = r1->get("p1", "from");
    REQUIRE(val.has_value());
    CHECK(*val == "store2");
}

// ═══════════════════════════════════════════════════════════════════════════════
// Concurrency
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore: concurrent set/get from multiple threads", "[kv_store][concurrency]") {
    auto t = make_test_store();

    constexpr int kThreads = 8;
    constexpr int kOpsPerThread = 100;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    // Catch2 assertion macros are not thread-safe (they write a process-global
    // line-info object), so worker threads record into an atomic and the
    // assertion happens on the main thread after join.
    std::atomic<bool> all_present{true};

    for (int tid = 0; tid < kThreads; ++tid) {
        threads.emplace_back([&store = t.store, &all_present, tid]() {
            std::string plugin = "plugin-" + std::to_string(tid);
            for (int i = 0; i < kOpsPerThread; ++i) {
                std::string key = "key-" + std::to_string(i);
                std::string val = std::to_string(tid * 1000 + i);

                store.set(plugin, key, val);
                auto got = store.get(plugin, key);
                // Value should always be present (we just set it); each thread
                // has its own plugin so there is no cross-thread overwrite.
                if (!got.has_value())
                    all_present.store(false, std::memory_order_relaxed);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    CHECK(all_present.load());

    // Verify each thread's final state is intact
    for (int tid = 0; tid < kThreads; ++tid) {
        std::string plugin = "plugin-" + std::to_string(tid);
        auto keys = t.store.list(plugin, "");
        CHECK(keys.size() == kOpsPerThread);
    }
}

TEST_CASE("KvStore: concurrent set on same key from multiple threads", "[kv_store][concurrency]") {
    auto t = make_test_store();

    constexpr int kThreads = 8;
    constexpr int kOpsPerThread = 50;

    std::vector<std::thread> threads;
    threads.reserve(kThreads);

    for (int tid = 0; tid < kThreads; ++tid) {
        threads.emplace_back([&store = t.store, tid]() {
            for (int i = 0; i < kOpsPerThread; ++i) {
                std::string val = std::to_string(tid) + "-" + std::to_string(i);
                store.set("shared-plugin", "contested-key", val);
            }
        });
    }

    for (auto& th : threads) {
        th.join();
    }

    // Key should exist with some valid value (last writer wins)
    auto val = t.store.get("shared-plugin", "contested-key");
    REQUIRE(val.has_value());
    CHECK_FALSE(val->empty());
}

TEST_CASE("KvStore: concurrent list while writing", "[kv_store][concurrency]") {
    auto t = make_test_store();

    // Pre-populate some keys
    for (int i = 0; i < 20; ++i) {
        t.store.set("p1", "pre-" + std::to_string(i), "v");
    }

    std::atomic<bool> done{false};
    // Catch2 macros are not thread-safe; the reader records into an atomic.
    std::atomic<bool> list_consistent{true};

    // Writer thread
    std::thread writer([&]() {
        for (int i = 0; i < 100 && !done.load(); ++i) {
            t.store.set("p1", "write-" + std::to_string(i), "v");
        }
        done.store(true);
    });

    // Reader thread: list keys concurrently
    std::thread reader([&]() {
        while (!done.load()) {
            auto keys = t.store.list("p1", "");
            // Should always get a consistent snapshot (at least the 20 pre-populated)
            if (keys.size() < 20)
                list_consistent.store(false, std::memory_order_relaxed);
        }
    });

    writer.join();
    done.store(true);
    reader.join();

    CHECK(list_consistent.load());
}

// ═══════════════════════════════════════════════════════════════════════════════
// Journal substrate primitives (item 7 PR-Ag C1)
// ═══════════════════════════════════════════════════════════════════════════════

TEST_CASE("KvStore::list_entries returns key+value, empty is not an error", "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:n:0", "alpha"));
    REQUIRE(t.store.set("p1", "lc:n:1", "beta"));
    REQUIRE(t.store.set("p1", "other", "gamma"));

    auto rows = t.store.list_entries("p1", "lc:");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    CHECK((*rows)[0].key == "lc:n:0");
    CHECK((*rows)[0].value == "alpha");
    CHECK((*rows)[1].key == "lc:n:1");
    CHECK((*rows)[1].value == "beta");

    // A non-matching prefix is an empty result, NOT an error (distinct from list()).
    auto none = t.store.list_entries("p1", "zzz");
    REQUIRE(none.has_value());
    CHECK(none->empty());
}

TEST_CASE("KvStore::list_entries reads values byte-exact (NUL preserved)", "[kv_store][entries]") {
    auto t = make_test_store();
    const std::string with_nul = std::string("before") + '\0' + "after"; // 12 bytes
    REQUIRE(t.store.set("p1", "lc:n:0", with_nul));

    // get() truncates at the NUL (documented elsewhere); list_entries must not.
    auto rows = t.store.list_entries("p1", "lc:");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].value.size() == with_nul.size());
    CHECK((*rows)[0].value == with_nul);
}

TEST_CASE("KvStore::insert_if_absent reports Inserted vs Exists", "[kv_store][entries]") {
    auto t = make_test_store();
    CHECK(t.store.insert_if_absent("p1", "lc:n:0", "first") == KvInsert::Inserted);
    // Second insert on the same key does nothing and reports Exists.
    CHECK(t.store.insert_if_absent("p1", "lc:n:0", "second") == KvInsert::Exists);
    auto v = t.store.get("p1", "lc:n:0");
    REQUIRE(v.has_value());
    CHECK(*v == "first"); // value NOT overwritten
    // A different key is a fresh insert.
    CHECK(t.store.insert_if_absent("p1", "lc:n:1", "other") == KvInsert::Inserted);
}

TEST_CASE("KvStore::rename_key moves atomically, reports Conflict/NotFound", "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:n:0", "payload"));

    CHECK(t.store.rename_key("p1", "lc:n:0", "quarantine:lc:n:0") == KvRename::Renamed);
    CHECK_FALSE(t.store.exists("p1", "lc:n:0"));
    auto moved = t.store.get("p1", "quarantine:lc:n:0");
    REQUIRE(moved.has_value());
    CHECK(*moved == "payload"); // value preserved

    // Renaming a key that no longer exists.
    CHECK(t.store.rename_key("p1", "lc:n:0", "lc:n:9") == KvRename::NotFound);

    // Conflict: to_key already exists - both rows survive untouched.
    REQUIRE(t.store.set("p1", "lc:a", "A"));
    REQUIRE(t.store.set("p1", "lc:b", "B"));
    CHECK(t.store.rename_key("p1", "lc:a", "lc:b") == KvRename::Conflict);
    CHECK(t.store.get("p1", "lc:a").value_or("") == "A");
    CHECK(t.store.get("p1", "lc:b").value_or("") == "B");
}

TEST_CASE("KvStore::del_keys removes only the listed keys, returns count", "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "a", "1"));
    REQUIRE(t.store.set("p1", "b", "2"));
    REQUIRE(t.store.set("p1", "c", "3"));

    CHECK(t.store.del_keys("p1", {"a", "c"}) == 2);
    CHECK_FALSE(t.store.exists("p1", "a"));
    CHECK(t.store.exists("p1", "b"));
    CHECK_FALSE(t.store.exists("p1", "c"));

    CHECK(t.store.del_keys("p1", {}) == 0);            // empty list
    CHECK(t.store.del_keys("p1", {"nope"}) == 0);      // absent key, no error
    CHECK(t.store.del_keys("p1", {"b", "nope"}) == 1); // counts only what existed
    CHECK_FALSE(t.store.exists("p1", "b"));
}

TEST_CASE("KvStore::pragma_synchronous reports a valid level", "[kv_store][entries]") {
    auto t = make_test_store();
    const int level = t.store.pragma_synchronous();
    // 0=OFF 1=NORMAL 2=FULL 3=EXTRA. The journal wants FULL; anything in range is
    // a valid read (the caller soft-warns on < FULL, never aborts).
    CHECK(level >= 0);
    CHECK(level <= 3);
}

// ── namespace_size (#2303 C1): direct coverage of the aggregate size probe ──────

TEST_CASE("KvStore::namespace_size counts rows and sums value bytes", "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:a", "12345"));   // 5 bytes
    REQUIRE(t.store.set("p1", "lc:b", "678"));     // 3 bytes
    REQUIRE(t.store.set("p1", "other:c", "9999")); // different prefix, must NOT count

    auto sz = t.store.namespace_size("p1", "lc:");
    REQUIRE(sz.has_value());
    CHECK(sz->count == 2);
    CHECK(sz->bytes == 8); // 5 + 3, the "other:" row excluded by the prefix

    // Cross-check against list_entries: same rows, and the byte sum equals the sum
    // of KvRow::value.size() - the exact accounting namespace_size must mirror.
    auto rows = t.store.list_entries("p1", "lc:");
    REQUIRE(rows.has_value());
    std::uint64_t byte_sum = 0;
    for (const auto& r : *rows)
        byte_sum += r.value.size();
    CHECK(sz->count == rows->size());
    CHECK(sz->bytes == byte_sum);
}

TEST_CASE("KvStore::namespace_size on an empty namespace is {0,0}, not an error",
          "[kv_store][entries]") {
    auto t = make_test_store();
    // No rows at all, and a non-existent plugin: both must be a clean {0,0}, so a
    // caller can distinguish "nothing there" from a DB error (the fail-closed seed
    // in GuardianLifecycleJournal relies on exactly that distinction).
    auto empty = t.store.namespace_size("p1", "lc:");
    REQUIRE(empty.has_value());
    CHECK(empty->count == 0);
    CHECK(empty->bytes == 0);

    REQUIRE(t.store.set("p1", "lc:a", "x"));
    auto other_plugin = t.store.namespace_size("does-not-exist", "lc:");
    REQUIRE(other_plugin.has_value());
    CHECK(other_plugin->count == 0);
    CHECK(other_plugin->bytes == 0);
}

TEST_CASE("KvStore::namespace_size sizes multibyte values in BYTES, not characters",
          "[kv_store][entries]") {
    auto t = make_test_store();
    const std::string v = "café-日本語"; // > one byte per code point
    REQUIRE(t.store.set("p1", "lc:u", v));
    auto sz = t.store.namespace_size("p1", "lc:");
    REQUIRE(sz.has_value());
    CHECK(sz->count == 1);
    CHECK(sz->bytes == v.size()); // octet_length == std::string byte length, not glyph count
}

// ── LIKE-prefix escaping (#2303 C1): the shared escape_like_prefix helper ────────

TEST_CASE("KvStore prefix scans escape LIKE wildcards in the prefix", "[kv_store][entries]") {
    // list / list_entries / namespace_size all route their prefix through the one
    // escape_like_prefix helper. A literal '_' or '%' in the prefix must match
    // ITSELF, not act as a wildcard - otherwise a scan silently widens to keys the
    // caller never asked for. Guards the extraction that folded three call sites.
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "a_b:1", "match"));   // literal underscore
    REQUIRE(t.store.set("p1", "aXb:1", "wildcard")); // '_' would match this X
    REQUIRE(t.store.set("p1", "a%b:1", "pct"));      // literal percent
    REQUIRE(t.store.set("p1", "azzzb:1", "pctwild")); // '%' would match this run

    // "a_b:" must match only the literal-underscore key, not "aXb:".
    auto under = t.store.list("p1", "a_b:");
    CHECK(under.size() == 1);
    auto under_sz = t.store.namespace_size("p1", "a_b:");
    REQUIRE(under_sz.has_value());
    CHECK(under_sz->count == 1);

    // "a%b:" must match only the literal-percent key, not "azzzb:".
    auto pct = t.store.list_entries("p1", "a%b:");
    REQUIRE(pct.has_value());
    CHECK(pct->size() == 1);
    CHECK(pct->front().value == "pct");

    // list_keys_sized is the fourth call site of the same helper - it must not drift.
    auto sized = t.store.list_keys_sized("p1", "a_b:");
    REQUIRE(sized.has_value());
    CHECK(sized->size() == 1);
    CHECK(sized->front().key == "a_b:1");
}

// ── list_keys_sized / get_entry: the O(work) scan pair (#2299 perf-P-1) ──────────

TEST_CASE("KvStore::list_keys_sized returns keys + value byte lengths in key order",
          "[kv_store][entries]") {
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:b", "678"));     // out of order on purpose
    REQUIRE(t.store.set("p1", "lc:a", "12345"));
    REQUIRE(t.store.set("p1", "other:c", "9999")); // different prefix, excluded

    auto rows = t.store.list_keys_sized("p1", "lc:");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 2);
    // ORDER BY key is the contract a fixed-width key prefix turns into ordering by
    // that field - a caller that drops its own sort depends on it.
    CHECK((*rows)[0].key == "lc:a");
    CHECK((*rows)[1].key == "lc:b");
    CHECK((*rows)[0].bytes == 5);
    CHECK((*rows)[1].bytes == 3);

    // Byte accounting agrees row-for-row with the value-materializing sibling.
    auto entries = t.store.list_entries("p1", "lc:");
    REQUIRE(entries.has_value());
    REQUIRE(entries->size() == rows->size());
    for (std::size_t i = 0; i < rows->size(); ++i) {
        CHECK((*rows)[i].key == (*entries)[i].key);
        CHECK((*rows)[i].bytes == (*entries)[i].value.size());
    }
}

TEST_CASE("KvStore::list_keys_sized sizes multibyte values in BYTES, and empty is not an error",
          "[kv_store][entries]") {
    auto t = make_test_store();
    auto empty = t.store.list_keys_sized("p1", "lc:");
    REQUIRE(empty.has_value()); // empty namespace: a clean empty vector, never an error
    CHECK(empty->empty());

    const std::string v = "café-日本語"; // > one byte per code point
    REQUIRE(t.store.set("p1", "lc:u", v));
    auto rows = t.store.list_keys_sized("p1", "lc:");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK(rows->front().bytes == v.size()); // octet_length, not the glyph count
}

TEST_CASE("KvStore::get_entry distinguishes absent from failed, and reads bytes exactly",
          "[kv_store][entries]") {
    auto t = make_test_store();
    const std::string with_nul = std::string("head\0tail", 9);
    REQUIRE(t.store.set("p1", "lc:n", with_nul));

    auto present = t.store.get_entry("p1", "lc:n");
    REQUIRE(present.has_value());
    REQUIRE(present->has_value());
    // get() truncates at the NUL; the fallible point read must not - a corrupt value
    // has to reach the parser intact to be quarantined rather than silently repaired.
    CHECK(**present == with_nul);
    CHECK(t.store.get("p1", "lc:n").value_or("").size() == 4);

    // ABSENT is a value (nullopt), not an error: only that distinction lets a caller
    // treat "cannot tell" differently from "not there".
    auto missing = t.store.get_entry("p1", "lc:does-not-exist");
    REQUIRE(missing.has_value());
    CHECK(!missing->has_value());
}

// ── rename_key extended-result-code masking (#2303 K1) ──────────────────────────

TEST_CASE("KvStore::rename_key reports Conflict even with extended result codes on",
          "[kv_store][entries]") {
    // K1: rename_key classifies a PK conflict with `(rc & 0xFF) == SQLITE_CONSTRAINT`.
    // With extended result codes enabled, step() returns SQLITE_CONSTRAINT_PRIMARYKEY
    // (1555), whose low byte is SQLITE_CONSTRAINT (19). Without the mask the bare
    // compare would miss and misreport the conflict as Error. This is the only test
    // that turns extended codes on, so it is the one that actually pins the mask.
    auto t = make_test_store();
    t.store.enable_extended_result_codes_for_test();
    REQUIRE(t.store.set("p1", "lc:a", "A"));
    REQUIRE(t.store.set("p1", "lc:b", "B"));

    CHECK(t.store.rename_key("p1", "lc:a", "lc:b") == KvRename::Conflict);
    // Both rows survive untouched, exactly as in the primary-code path.
    CHECK(t.store.get("p1", "lc:a").value_or("") == "A");
    CHECK(t.store.get("p1", "lc:b").value_or("") == "B");
}

// ── The fallible-read contract: "cannot tell" must never read as "not there" ─────
//
// These two methods exist BECAUSE they distinguish a failed read from an absent row -
// `get()`/`list()` collapse both and the journal's eviction classifier would then report a
// transient DB error as audit loss. So the failure branch IS the feature, and every other
// "read failed" test in this area injects at the journal layer, never reaching the real call.

TEST_CASE("KvStore fallible reads report a CLOSED handle rather than an empty result",
          "[kv_store][entries]") {
    // Reached through a documented state transition, not a test-only seam: the move
    // constructor nulls the moved-from handle, and the `!db_` guard exists precisely so
    // that object stays safe to call. An empty vector / nullopt here would be a caller
    // reading "the namespace is empty" out of "the store is gone".
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:a", "v"));
    KvStore moved = std::move(t.store);
    REQUIRE(moved.get("p1", "lc:a").has_value()); // the handle really did transfer

    auto scan = t.store.list_keys_sized("p1", "lc:");
    REQUIRE_FALSE(scan.has_value());
    CHECK(scan.error().message.find("closed") != std::string::npos);

    auto point = t.store.get_entry("p1", "lc:a");
    REQUIRE_FALSE(point.has_value());
    CHECK(point.error().message.find("closed") != std::string::npos);
}

TEST_CASE("KvStore fallible reads surface a REAL SQLite failure as an error, not as absence",
          "[kv_store][entries]") {
    // The branch that matters in production. Dropping the table through a second connection
    // makes prepare_v2 fail for real - no injected stand-in - so a live row does not come
    // back as a clean "absent" once the schema is gone.
    //
    // Scope, stated precisely because it is easy to overclaim: this reaches the PREPARE
    // failure path of both methods, verified by mutation (making either method treat a
    // failed prepare as absence turns this red). It does NOT reach the mid-SCAN failure
    // path - `rc != SQLITE_DONE` after rows have already been returned - which needs a VFS
    // shim or a schema change landing mid-statement. That branch is shared with the
    // pre-existing `list_entries` and is recorded as a deferred gap rather than faked here:
    // a test that appears to cover it but does not is worse than a named hole.
    auto t = make_test_store();
    REQUIRE(t.store.set("p1", "lc:a", "v"));
    REQUIRE(t.store.get_entry("p1", "lc:a").value().has_value()); // present before the drop

    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(t.path.string().c_str(), &raw) == SQLITE_OK);
    char* err = nullptr;
    const int rc = sqlite3_exec(raw, "DROP TABLE kv_store", nullptr, nullptr, &err);
    if (err)
        sqlite3_free(err);
    sqlite3_close(raw);
    REQUIRE(rc == SQLITE_OK);

    auto scan = t.store.list_keys_sized("p1", "lc:");
    REQUIRE_FALSE(scan.has_value()); // NOT an empty vector
    CHECK_FALSE(scan.error().message.empty());

    auto point = t.store.get_entry("p1", "lc:a");
    REQUIRE_FALSE(point.has_value()); // NOT nullopt - the row's absence is unknown, not proven
    CHECK_FALSE(point.error().message.empty());

    // The contrast that motivates the pair: the fail-OPEN siblings cannot tell you any of
    // this. Both report the same thing for a dropped table as for an empty namespace.
    CHECK(t.store.list("p1", "lc:").empty());
    CHECK_FALSE(t.store.get("p1", "lc:a").has_value());
}

// ═══════════════════════════════════════════════════════════════════════════════
// #5604: the busy budget is an atomic read by a busy HANDLER, so lowering it from another
// thread cuts a write that is already waiting on a locked database.
// ═══════════════════════════════════════════════════════════════════════════════

namespace {

/// A second raw connection holding the write lock (BEGIN IMMEDIATE) until released or destroyed.
/// The connection is owned by an RAII member from the moment it is opened, and the constructor
/// asserts nothing (a REQUIRE that threw from here would skip the destructor and leak the
/// handle): a caller checks `locked` with REQUIRE after construction.
struct WriteLockHolder5604 {
    struct Closer {
        void operator()(sqlite3* db) const { sqlite3_close(db); } // rolls back an open transaction
    };
    std::unique_ptr<sqlite3, Closer> raw;
    bool locked{false};
    explicit WriteLockHolder5604(const fs::path& path) {
        sqlite3* db = nullptr;
        const int rc = sqlite3_open(path.string().c_str(), &db);
        raw.reset(db);
        locked = rc == SQLITE_OK &&
                 sqlite3_exec(db, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK;
    }
    void release() {
        if (raw)
            sqlite3_exec(raw.get(), "ROLLBACK", nullptr, nullptr, nullptr);
    }
    WriteLockHolder5604(const WriteLockHolder5604&) = delete;
    WriteLockHolder5604& operator=(const WriteLockHolder5604&) = delete;
};

/// How long `fn` takes, in milliseconds.
template <class Fn> double elapsed_ms_5604(Fn&& fn) {
    const auto t0 = std::chrono::steady_clock::now();
    fn();
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

} // namespace

TEST_CASE("#5604 KvStore: open installs the normal 5 s busy budget; set_busy_timeout is observable",
          "[kv_store][busy]") {
    auto t = make_test_store();
    CHECK(t.store.busy_timeout_for_test() == kKvStoreBusyTimeout);
    t.store.set_busy_timeout(kKvStoreStopBusyTimeout);
    CHECK(t.store.busy_timeout_for_test() == kKvStoreStopBusyTimeout);
}

TEST_CASE("#5604 KvStore: lowering the budget from another thread cuts a write already waiting",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    auto t = make_test_store();
    REQUIRE(t.store.set("p", "seed", "v"));
    WriteLockHolder5604 holder{t.path};
    REQUIRE(holder.locked);

    t.store.set_busy_timeout(2000ms);
    // The writer raises a flag right before its set(); this thread waits for the flag, gives the
    // write a moment to reach the busy handler, then drops the budget to 200 ms. The write
    // already waiting must give up at ~200 ms from its start, not run out the 2000 ms it started
    // under. sqlite3_busy_timeout() from this thread would have blocked behind the waiting
    // call's connection mutex and not shortened it.
    std::atomic<bool> about_to_write{false};
    bool in_flight_ok = true;
    double in_flight = 0.0;
    std::thread writer([&] {
        in_flight = elapsed_ms_5604([&] {
            about_to_write.store(true);
            in_flight_ok = t.store.set("p", "k1", "v");
        });
    });
    REQUIRE(yuzu::test::spin_until([&] { return about_to_write.load(); }));
    std::this_thread::sleep_for(50ms);
    t.store.set_busy_timeout(200ms);
    writer.join();
    CHECK_FALSE(in_flight_ok);
    CHECK(in_flight >= 200.0);
    CHECK(in_flight < 1000.0); // RED if the 2000 ms it started under had run out

    // A fresh write under the lowered budget costs it, and fails.
    bool fresh_ok = true;
    const double fresh = elapsed_ms_5604([&] { fresh_ok = t.store.set("p", "k2", "v"); });
    CHECK_FALSE(fresh_ok);
    CHECK(fresh >= 200.0);
    CHECK(fresh < 1000.0);
    CHECK(t.store.busy_timeout_for_test() == 200ms); // never raised

    // Releasing the lock: the same store writes again at once (nothing latched).
    holder.release();
    CHECK(t.store.set("p", "k3", "v"));
    CHECK(t.store.get("p", "k3").value_or("") == "v");
    CHECK_FALSE(t.store.get("p", "k1").has_value());
}

TEST_CASE("#5604 KvStore: a MOVED store keeps a working busy handler (the context is heap-owned)",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    // The handler's context pointer is registered with SQLite at open() and outlives the
    // KvStore object's address: moving the store must neither dangle it nor lose the budget.
    auto t = make_test_store();
    t.store.set_busy_timeout(100ms);
    KvStore moved{std::move(t.store)};
    CHECK(moved.busy_timeout_for_test() == 100ms);
    CHECK(t.store.busy_timeout_for_test() == 0ms); // moved-from: no context, no budget
    t.store.set_busy_timeout(5000ms);              // a no-op on a moved-from store, not a crash

    {
        WriteLockHolder5604 holder{t.path};
        REQUIRE(holder.locked);
        bool ok = true;
        const double ms = elapsed_ms_5604([&] { ok = moved.set("p", "k", "v"); });
        CHECK_FALSE(ok);
        CHECK(ms >= 100.0);
        CHECK(ms < 1500.0);
    }

    // Move ASSIGNMENT: the destination's old connection and context are released, the source's
    // adopted.
    yuzu::test::TempDbFile other_db{"yuzu_test_kv_5604_"};
    auto other = KvStore::open(other_db.path);
    REQUIRE(other.has_value());
    other->set_busy_timeout(5000ms);
    *other = std::move(moved);
    CHECK(other->busy_timeout_for_test() == 100ms);
    {
        WriteLockHolder5604 holder{t.path};
        REQUIRE(holder.locked);
        bool ok = true;
        const double ms = elapsed_ms_5604([&] { ok = other->set("p", "k2", "v"); });
        CHECK_FALSE(ok);
        CHECK(ms >= 100.0);
        CHECK(ms < 1500.0);
    }
    CHECK(other->set("p", "k3", "v"));
}

TEST_CASE("#5604 KvStore: set_busy_timeout clamps to [0, 1 h]; zero and negative mean do not wait",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    auto t = make_test_store();
    t.store.set_busy_timeout(1234ms);
    CHECK(t.store.busy_timeout_for_test() == 1234ms);
    t.store.set_busy_timeout(0ms);
    CHECK(t.store.busy_timeout_for_test() == 0ms);
    t.store.set_busy_timeout(-5ms);
    CHECK(t.store.busy_timeout_for_test() == kKvStoreMinBusyTimeout);
    t.store.set_busy_timeout((std::chrono::milliseconds::min)());
    CHECK(t.store.busy_timeout_for_test() == kKvStoreMinBusyTimeout);
    t.store.set_busy_timeout(kKvStoreMaxBusyTimeout);
    CHECK(t.store.busy_timeout_for_test() == kKvStoreMaxBusyTimeout);
    t.store.set_busy_timeout(kKvStoreMaxBusyTimeout + 1ms);
    CHECK(t.store.busy_timeout_for_test() == kKvStoreMaxBusyTimeout);
    // The value that overflowed the handler's millisecond-to-nanosecond arithmetic before the
    // clamp.
    t.store.set_busy_timeout((std::chrono::milliseconds::max)());
    CHECK(t.store.busy_timeout_for_test() == kKvStoreMaxBusyTimeout);
    // With the huge value in place the handler still behaves (no overflow): it retries.
    CHECK(t.store.busy_handler_for_test(0) == 1);

    // Zero (and a negative, clamped to zero) means a locked database fails the call at once.
    WriteLockHolder5604 holder{t.path};
    REQUIRE(holder.locked);
    for (const auto budget : {0ms, -5ms}) {
        t.store.set_busy_timeout(budget);
        bool ok = true;
        const double ms = elapsed_ms_5604([&] { ok = t.store.set("p", "k", "v"); });
        CHECK_FALSE(ok);
        CHECK(ms < 1000.0); // the budget is zero: nothing waits
    }
}

TEST_CASE("#5604 KvStore: the busy handler's retry sleep is a short ladder (1, 2, 5, then 10 ms)",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    CHECK(KvStore::busy_retry_sleep_for_test(0) == 1ms);
    CHECK(KvStore::busy_retry_sleep_for_test(1) == 2ms);
    CHECK(KvStore::busy_retry_sleep_for_test(2) == 5ms);
    CHECK(KvStore::busy_retry_sleep_for_test(3) == 10ms);
    CHECK(KvStore::busy_retry_sleep_for_test(4) == 10ms);
    CHECK(KvStore::busy_retry_sleep_for_test(1'000'000) == 10ms);
    CHECK(KvStore::busy_retry_sleep_for_test((std::numeric_limits<int>::max)()) == 10ms);
    CHECK(KvStore::busy_retry_sleep_for_test(-1) == 1ms); // never indexes out of range
    // The point of the ladder: a lock held for a few milliseconds is retried well before a
    // flat 10 ms would have retried it.
    CHECK(KvStore::busy_retry_sleep_for_test(0) < 10ms);
    CHECK(KvStore::busy_retry_sleep_for_test(1) < 10ms);
    CHECK(KvStore::busy_retry_sleep_for_test(2) < 10ms);
}

TEST_CASE("#5604 KvStore: a handler call with count > 0 on a thread that never saw count == 0 "
          "does not fail at once, and a continuing wait is still cut at the budget",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    auto t = make_test_store();
    t.store.set_busy_timeout(150ms);

    // A fresh thread has no wait clock. count > 0 is a call SQLite could make for a wait this
    // thread's handler never began (a reset count after a prepare or checkpoint wait): reading
    // an empty start would see "elapsed since the epoch" and give up immediately. The call
    // restarts the clock instead, and the wait then ends at about the budget from THAT call.
    // Counts 1, 2 and 3 each start a fresh thread: the thread's initial "previous count" must
    // not be a value that continues any of them (an initial 0 would continue count 1, an
    // initial 1 count 2).
    for (const int first_count : {1, 2, 3}) {
        INFO("first count on the fresh thread: " << first_count);
        int rc_fresh = -1;
        double fresh_ms = 0.0;
        double fresh_wait_ms = 0.0;
        std::thread fresh([&] {
            fresh_wait_ms = elapsed_ms_5604([&] {
                fresh_ms = elapsed_ms_5604(
                    [&] { rc_fresh = t.store.busy_handler_for_test(first_count); });
                int rc = rc_fresh;
                for (int count = first_count + 1; rc == 1 && count < 10'000; ++count)
                    rc = t.store.busy_handler_for_test(count);
            });
        });
        fresh.join();
        CHECK(rc_fresh == 1); // RED without the restart: returned 0 at once
        CHECK(fresh_wait_ms >= 150.0);
        CHECK(fresh_wait_ms < 1500.0);
        if (first_count == 3) {
            // The sleep under test is the ladder's 10 ms tail. 5 ms is the loosest lower bound
            // that still tells it from a handler that does not sleep (or sleeps the 1 ms head
            // only); it is a loose bound, and rc_fresh == 1 is the assertion that matters.
            CHECK(fresh_ms >= 5.0);
        }
    }

    // A normal wait: count 0, 1, 2, ... until the handler gives up. It must give up, and only
    // once the budget is spent.
    int calls = 0;
    int rc = 1;
    const double wait_ms = elapsed_ms_5604([&] {
        for (int count = 0; rc == 1 && count < 10'000; ++count, ++calls)
            rc = t.store.busy_handler_for_test(count);
    });
    CHECK(rc == 0);
    CHECK(calls > 3);
    CHECK(wait_ms >= 150.0);
    CHECK(wait_ms < 1500.0);

    // Count 0 always starts a wait: with a zero budget it gives up at once.
    t.store.set_busy_timeout(0ms);
    int rc_zero = -1;
    std::thread zero([&] { rc_zero = t.store.busy_handler_for_test(0); });
    zero.join();
    CHECK(rc_zero == 0);
}

TEST_CASE("#5604 KvStore: the handler's count arithmetic is safe at the ends of the int range",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    auto t = make_test_store();
    t.store.set_busy_timeout(5s);
    constexpr int kMax = (std::numeric_limits<int>::max)();
    constexpr int kMin = (std::numeric_limits<int>::min)();
    // Two calls with INT_MAX in a row: the second compares against a previous count of INT_MAX,
    // so a "previous + 1" would overflow a signed int (undefined behaviour; a UBSan failure).
    // Neither continues the other's wait, so both restart and retry.
    int rc_first = -1;
    int rc_second = -1;
    int rc_min = -1;
    int rc_zero = -1;
    std::thread th([&] {
        rc_first = t.store.busy_handler_for_test(kMax);
        rc_second = t.store.busy_handler_for_test(kMax);
        rc_min = t.store.busy_handler_for_test(kMin); // outside the contract: restarts, no UB
        rc_zero = t.store.busy_handler_for_test(0);
    });
    th.join();
    CHECK(rc_first == 1);
    CHECK(rc_second == 1);
    CHECK(rc_min == 1);
    CHECK(rc_zero == 1);
}

TEST_CASE("#5604 KvStore: every public method starts with a fresh wait chain",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    // SQLite resets its busy count when a step starts, at the end of a prepare, and for a PRAGMA
    // or checkpoint, but never when a step ends. A handler call at the start of one KV call can
    // therefore arrive with the count that follows the LAST call of the previous KV call on the
    // same connection and thread. Without the per-call reset it would continue that wait and
    // inherit its old start. The seam below stands in for SQLite: it leaves the chain at count 2
    // with a start that is already past a 1 ms budget, makes one public call, and then presents
    // count 3.
    auto t = make_test_store();

    // The three calls run under a 5 s budget, so a coarse timer (a Windows sleep rounds up to a
    // tick of about 15.6 ms) or a loaded runner cannot make one of them give up. Only after they
    // return is the budget lowered to 1 ms. The ladder sleeps of calls 0 to 2 (1, 2 and 5 ms)
    // put the start more than 1 ms in the past, so a continuing count 3 gives up, while a
    // restarted one has elapsed 0 and retries. The budget is only ever lowered inside arm(),
    // after the three calls.
    auto arm = [&] {
        t.store.set_busy_timeout(5s);
        const bool chained = t.store.busy_handler_for_test(0) == 1 &&
                             t.store.busy_handler_for_test(1) == 1 &&
                             t.store.busy_handler_for_test(2) == 1;
        t.store.set_busy_timeout(1ms);
        return chained;
    };

    // Control: with no public call in between, count 3 continues the wait and its old start is
    // past the budget, so the handler gives up. This is what the reset has to prevent.
    REQUIRE(arm());
    CHECK(t.store.busy_handler_for_test(3) == 0);

    const std::vector<std::pair<const char*, std::function<void()>>> calls = {
        {"set", [&] { (void)t.store.set("p", "k", "v"); }},
        {"get", [&] { (void)t.store.get("p", "k"); }},
        {"del", [&] { (void)t.store.del("p", "none"); }},
        {"exists", [&] { (void)t.store.exists("p", "k"); }},
        {"list", [&] { (void)t.store.list("p", ""); }},
        {"list_entries", [&] { (void)t.store.list_entries("p", ""); }},
        {"namespace_size", [&] { (void)t.store.namespace_size("p", ""); }},
        {"list_keys_sized", [&] { (void)t.store.list_keys_sized("p", ""); }},
        {"get_entry", [&] { (void)t.store.get_entry("p", "k"); }},
        {"insert_if_absent", [&] { (void)t.store.insert_if_absent("p", "k2", "v"); }},
        {"rename_key", [&] { (void)t.store.rename_key("p", "k2", "k3"); }},
        {"del_keys", [&] { (void)t.store.del_keys("p", {"k3"}); }},
        {"pragma_synchronous", [&] { (void)t.store.pragma_synchronous(); }},
        {"enable_extended_result_codes_for_test",
         [&] { t.store.enable_extended_result_codes_for_test(); }},
        {"clear", [&] { (void)t.store.clear("p"); }},
    };
    for (const auto& [name, call] : calls) {
        INFO("public method: " << name);
        REQUIRE(arm());
        call();
        // RED when the method does not reset the chain: count 3 continues the stale wait and the
        // handler gives up (0) instead of restarting (1).
        CHECK(t.store.busy_handler_for_test(3) == 1);
    }
}

TEST_CASE("#5604 KvStore: a pause inside a continuing wait does not renew its budget",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    auto t = make_test_store();
    t.store.set_busy_timeout(400ms);

    // SQLite calls the handler with consecutive counts while one wait continues. A scheduler
    // stall, or one of SQLite's own sleeps outside the handler, between two such calls is part of
    // the same wait: the 300 ms pause between count 1 and count 2 below must not grant a fresh
    // 400 ms. The wait ends at the budget from the FIRST call (plus one ladder sleep), so it
    // ends well before the end of the pause plus the budget (about 700 ms in total when the
    // pause renews it).
    int rc0 = -1;
    int rc1 = -1;
    int last_rc = 1;
    double total_ms = 0.0;
    double pause_end_ms = 0.0;
    std::thread waiter([&] {
        const auto t0 = std::chrono::steady_clock::now();
        rc0 = t.store.busy_handler_for_test(0);
        rc1 = t.store.busy_handler_for_test(1);
        std::this_thread::sleep_for(300ms);
        pause_end_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
                .count();
        int count = 2;
        while (last_rc == 1 && count < 10'000)
            last_rc = t.store.busy_handler_for_test(count++);
        total_ms =
            std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0)
                .count();
    });
    waiter.join();
    CHECK(last_rc == 0);
    CHECK(total_ms >= 400.0);
    // Measured from the end of the pause, so a slow scheduler that lengthens the pause itself
    // does not move this result: a continuing wait has at most about 100 ms (400 ms minus the
    // 300 ms pause) left when the pause ends, a renewed one a whole 400 ms. 250 ms leaves 150 ms
    // of scheduling delay after the pause before this goes RED on a correct handler, and 150 ms
    // of margin before it stops catching a renewing one. Skipped when calls 0 and 1 did not both
    // retry: a thread starved past the whole budget there gave up before the pause.
    if (rc0 == 1 && rc1 == 1)
        CHECK(total_ms - pause_end_ms < 250.0); // RED if the pause renewed the budget

    // The same property without any upper timing bound: a pause longer than the whole budget
    // between two consecutive counts leaves the wait over budget, so the next call gives up.
    t.store.set_busy_timeout(150ms);
    int rc_first = -1;
    int rc_second = -1;
    int rc_after_pause = -1;
    std::thread paused([&] {
        rc_first = t.store.busy_handler_for_test(0);
        rc_second = t.store.busy_handler_for_test(1);
        std::this_thread::sleep_for(300ms);
        rc_after_pause = t.store.busy_handler_for_test(2);
    });
    paused.join();
    // A thread starved past the 150 ms budget inside the first two calls gave up there and
    // forgot the count, so count 2 would correctly restart: the property needs both to retry.
    if (rc_first == 1 && rc_second == 1)
        CHECK(rc_after_pause == 0); // RED if the 300 ms pause restarted the clock: returned 1
}

TEST_CASE("#5604 KvStore: a handler call that does not continue the previous count restarts the "
          "wait's clock",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    auto t = make_test_store();
    t.store.set_busy_timeout(150ms);

    // Counts 0 and 1, then a pause longer than the budget, then count 5. 5 is not the previous
    // count + 1, so it is a different wait: it must restart the clock and retry, not read the
    // old start (200 ms ago, past the 150 ms budget) and give up at once. Elapsed time cannot
    // tell this from a continuing wait, so only the count can.
    int rc_discontinuous = -1;
    double wait_ms = 0.0;
    std::thread waiter([&] {
        (void)t.store.busy_handler_for_test(0);
        (void)t.store.busy_handler_for_test(1);
        std::this_thread::sleep_for(200ms);
        wait_ms = elapsed_ms_5604([&] {
            rc_discontinuous = t.store.busy_handler_for_test(5);
            int rc = rc_discontinuous;
            for (int count = 6; rc == 1 && count < 10'000; ++count)
                rc = t.store.busy_handler_for_test(count);
        });
    });
    waiter.join();
    CHECK(rc_discontinuous == 1);
    CHECK(wait_ms >= 150.0); // the restarted wait runs its whole budget
    CHECK(wait_ms < 1500.0);

    // After the handler gives up, the next wait restarts even with a count that would otherwise
    // continue the last one (the give-up forgets the count).
    int rc_after_give_up = -1;
    std::thread after([&] {
        int rc = 1;
        int count = 0;
        for (; rc == 1 && count < 10'000; ++count)
            rc = t.store.busy_handler_for_test(count);
        // `count` is now the previous call's count + 1: a call that would continue the wait the
        // handler just gave up on if the give-up had not forgotten it.
        rc_after_give_up = t.store.busy_handler_for_test(count);
    });
    after.join();
    CHECK(rc_after_give_up == 1);
}

TEST_CASE("#5604 KvStore: two stores waited on in turn by one thread are each cut at their own "
          "budget",
          "[kv_store][busy]") {
    using namespace std::chrono_literals;
    // Through real SQLite: the busy handler's wait clock is per thread, shared by every store
    // that thread waits on. Each wait starts at count 0, so a wait on one store never reads the
    // start another store's wait left behind.
    auto a = make_test_store();
    auto b = make_test_store();
    a.store.set_busy_timeout(80ms);
    b.store.set_busy_timeout(160ms);
    WriteLockHolder5604 hold_a{a.path};
    WriteLockHolder5604 hold_b{b.path};
    REQUIRE(hold_a.locked);
    REQUIRE(hold_b.locked);
    for (int round = 0; round < 2; ++round) {
        bool ok_a = true;
        bool ok_b = true;
        const double ms_a = elapsed_ms_5604([&] { ok_a = a.store.set("p", "k", "v"); });
        const double ms_b = elapsed_ms_5604([&] { ok_b = b.store.set("p", "k", "v"); });
        CHECK_FALSE(ok_a);
        CHECK_FALSE(ok_b);
        CHECK(ms_a >= 80.0);
        CHECK(ms_a < 1000.0);
        CHECK(ms_b >= 160.0);
        CHECK(ms_b < 1000.0);
    }
}
