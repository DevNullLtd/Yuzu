/**
 * test_fake_journal_store.cpp -- contract coverage for FakeJournalStore (#4153).
 *
 * Small and sequential (no threads here - the concurrency checkpoints that
 * consume this fake live in test_guardian_spark_runtime.cpp). This file pins that
 * the fake's behaviour matches KvStore's real SQLite semantics closely enough for
 * GuardianLifecycleJournal to run identically against either: absent reads,
 * duplicate insert, byte counts (including multibyte), delete counts, every
 * rename_key outcome (including the NotFound-before-Conflict ordering SQLite's
 * single UPDATE produces), and prefix-scan ordering.
 */

#include "fake_journal_store.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::agent;
using yuzu::test::FakeJournalStore;

TEST_CASE("FakeJournalStore::get_entry is nullopt for an absent key, in an absent plugin too",
          "[fake_journal_store]") {
    FakeJournalStore store;
    auto v = store.get_entry("p1", "nope");
    REQUIRE(v.has_value()); // fallible contract: absent is a VALUE (nullopt), not unexpected
    CHECK_FALSE(v->has_value());

    // A plugin namespace that has never been written to at all.
    auto v2 = store.get_entry("never-seen", "k");
    REQUIRE(v2.has_value());
    CHECK_FALSE(v2->has_value());
}

TEST_CASE("FakeJournalStore::insert_if_absent reports Inserted vs Exists, never overwrites",
          "[fake_journal_store]") {
    FakeJournalStore store;
    CHECK(store.insert_if_absent("p1", "lc:n:0", "first") == KvInsert::Inserted);
    CHECK(store.insert_if_absent("p1", "lc:n:0", "second") == KvInsert::Exists);

    auto v = store.get_entry("p1", "lc:n:0");
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == "first"); // value NOT overwritten by the second (Exists) call

    CHECK(store.insert_if_absent("p1", "lc:n:1", "other") == KvInsert::Inserted);
}

TEST_CASE("FakeJournalStore::set upserts - first write inserts, second overwrites",
          "[fake_journal_store]") {
    FakeJournalStore store;
    CHECK(store.set("p1", "k", "v1"));
    CHECK(store.set("p1", "k", "v2"));
    auto v = store.get_entry("p1", "k");
    REQUIRE(v.has_value());
    REQUIRE(v->has_value());
    CHECK(**v == "v2");
}

TEST_CASE("FakeJournalStore::namespace_size counts rows and sums value BYTES, incl. multibyte",
          "[fake_journal_store]") {
    FakeJournalStore store;
    REQUIRE(store.set("p1", "lc:a", "12345"));   // 5 bytes
    REQUIRE(store.set("p1", "lc:b", "678"));     // 3 bytes
    REQUIRE(store.set("p1", "other:c", "9999")); // different prefix, must NOT count
    // A 3-byte-per-codepoint UTF-8 string (e.g. U+00e9 encodes as 2 bytes; use a
    // BMP character that is 3 bytes in UTF-8, "中" == "中").
    REQUIRE(store.set("p1", "lc:multibyte", "\xe4\xb8\xad\xe4\xb8\xad")); // 2 * 3 = 6 bytes

    auto sz = store.namespace_size("p1", "lc:");
    REQUIRE(sz.has_value());
    CHECK(sz->count == 3);
    CHECK(sz->bytes == 5 + 3 + 6);
}

TEST_CASE("FakeJournalStore::namespace_size on an empty/absent namespace is {0,0}",
          "[fake_journal_store]") {
    FakeJournalStore store;
    auto empty = store.namespace_size("p1", "lc:");
    REQUIRE(empty.has_value());
    CHECK(empty->count == 0);
    CHECK(empty->bytes == 0);

    auto absent_plugin = store.namespace_size("never-seen", "lc:");
    REQUIRE(absent_plugin.has_value());
    CHECK(absent_plugin->count == 0);
    CHECK(absent_plugin->bytes == 0);
}

TEST_CASE("FakeJournalStore::list_keys_sized returns keys + byte lengths in key order",
          "[fake_journal_store]") {
    FakeJournalStore store;
    // Insert out of order; the fake's std::map<std::string,...> must still report
    // them in ascending byte order, matching KvStore's `ORDER BY key`.
    REQUIRE(store.set("p1", "lc:0000000000003:n:000000000000", "ccc"));
    REQUIRE(store.set("p1", "lc:0000000000001:n:000000000000", "a"));
    REQUIRE(store.set("p1", "lc:0000000000002:n:000000000000", "bb"));
    REQUIRE(store.set("p1", "other:x", "should not appear"));

    auto rows = store.list_keys_sized("p1", "lc:");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 3);
    CHECK(rows->at(0).key == "lc:0000000000001:n:000000000000");
    CHECK(rows->at(0).bytes == 1);
    CHECK(rows->at(1).key == "lc:0000000000002:n:000000000000");
    CHECK(rows->at(1).bytes == 2);
    CHECK(rows->at(2).key == "lc:0000000000003:n:000000000000");
    CHECK(rows->at(2).bytes == 3);
}

TEST_CASE("FakeJournalStore::del_keys removes only the listed keys, returns count",
          "[fake_journal_store]") {
    FakeJournalStore store;
    REQUIRE(store.set("p1", "a", "1"));
    REQUIRE(store.set("p1", "b", "2"));
    REQUIRE(store.set("p1", "c", "3"));

    CHECK(store.del_keys("p1", {"a", "c"}) == 2);
    CHECK_FALSE(store.get_entry("p1", "a")->has_value());
    CHECK(store.get_entry("p1", "b")->has_value());
    CHECK_FALSE(store.get_entry("p1", "c")->has_value());

    CHECK(store.del_keys("p1", {}) == 0);            // empty list
    CHECK(store.del_keys("p1", {"nope"}) == 0);      // absent key, no error
    CHECK(store.del_keys("p1", {"b", "nope"}) == 1); // counts only what existed

    // A plugin namespace that was never written to at all.
    CHECK(store.del_keys("never-seen", {"x"}) == 0);
}

TEST_CASE("FakeJournalStore::rename_key: Renamed, NotFound, Conflict, and self-rename",
          "[fake_journal_store]") {
    FakeJournalStore store;
    REQUIRE(store.set("p1", "lc:n:0", "payload"));

    CHECK(store.rename_key("p1", "lc:n:0", "quarantine:lc:n:0") == KvRename::Renamed);
    CHECK_FALSE(store.get_entry("p1", "lc:n:0")->has_value());
    auto moved = store.get_entry("p1", "quarantine:lc:n:0");
    REQUIRE(moved.has_value());
    REQUIRE(moved->has_value());
    CHECK(**moved == "payload"); // value preserved across the move

    // Renaming a key that no longer exists.
    CHECK(store.rename_key("p1", "lc:n:0", "lc:n:9") == KvRename::NotFound);

    // Conflict: to_key already exists - both rows survive untouched.
    REQUIRE(store.set("p1", "lc:a", "A"));
    REQUIRE(store.set("p1", "lc:b", "B"));
    CHECK(store.rename_key("p1", "lc:a", "lc:b") == KvRename::Conflict);
    CHECK(**store.get_entry("p1", "lc:a") == "A");
    CHECK(**store.get_entry("p1", "lc:b") == "B");

    // Self-rename: the SAME single UPDATE SQLite would run on a row onto itself -
    // no PK conflict, reported Renamed, value unchanged.
    CHECK(store.rename_key("p1", "lc:a", "lc:a") == KvRename::Renamed);
    CHECK(**store.get_entry("p1", "lc:a") == "A");

    // The case a naive "check to_key first" implementation gets wrong: from_key is
    // ABSENT, but to_key already exists. SQLite's single UPDATE matches zero rows on
    // an absent from_key and never reaches the PK-conflict path, so the correct
    // answer is NotFound, not Conflict, no matter what to_key holds.
    CHECK_FALSE(store.get_entry("p1", "ghost")->has_value());
    CHECK(store.rename_key("p1", "ghost", "lc:b") == KvRename::NotFound);
    CHECK(**store.get_entry("p1", "lc:b") == "B"); // untouched
}

TEST_CASE("FakeJournalStore::pragma_synchronous reports FULL", "[fake_journal_store]") {
    FakeJournalStore store;
    CHECK(store.pragma_synchronous() == 2);
}

TEST_CASE("FakeJournalStore isolates plugin namespaces from each other",
          "[fake_journal_store]") {
    FakeJournalStore store;
    REQUIRE(store.set("p1", "k", "p1-value"));
    REQUIRE(store.set("p2", "k", "p2-value"));
    CHECK(**store.get_entry("p1", "k") == "p1-value");
    CHECK(**store.get_entry("p2", "k") == "p2-value");
    CHECK(store.del_keys("p1", {"k"}) == 1);
    CHECK_FALSE(store.get_entry("p1", "k")->has_value());
    CHECK(store.get_entry("p2", "k")->has_value()); // p2 untouched by p1's delete
}
