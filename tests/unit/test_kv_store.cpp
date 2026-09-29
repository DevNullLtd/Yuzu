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
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
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
