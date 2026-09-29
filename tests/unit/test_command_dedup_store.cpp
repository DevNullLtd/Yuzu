/**
 * test_command_dedup_store.cpp -- Unit tests for CommandDedupStore (HA WS-0)
 *
 * Covers the claim → record_terminal / release lifecycle, byte-exact outcome
 * replay, and the two properties WS-0 exists to guarantee (its WS-9 scenarios in
 * store form): durability of the terminal outcome across an agent RESTART, and a
 * command claimed-but-not-resolved when the agent crashes being answered
 * INDETERMINATE (in-flight) on redelivery rather than silently re-executed.
 *
 * The store treats the response as an opaque blob, so these tests deliberately
 * use arbitrary bytes (including an embedded NUL) as the "serialized response" —
 * no protobuf dependency needed.
 */

#include <yuzu/agent/command_dedup_store.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace fs = std::filesystem;
using namespace yuzu::agent;

static std::string uid_suffix() {
#ifdef _WIN32
    if (const char* u = std::getenv("USERNAME"))
        return std::string("_") + u;
    return "_unknown";
#else
    return "_" + std::to_string(static_cast<unsigned long>(::geteuid()));
#endif
}

// TempDbFile declared first so it destructs LAST — the store closes its handle
// before the .db/-wal/-shm files are removed (Windows cannot delete an open
// file). Uses the underscore `yuzu_test_` prefix so paths land inside the Wee
// Tam Defender exclusion wildcard.
struct TestDedupStore {
    yuzu::test::TempDbFile db;
    CommandDedupStore store;
    fs::path path{db.path};
    TestDedupStore(fs::path p, CommandDedupStore s) : db(std::move(p)), store(std::move(s)) {}
};

static fs::path fresh_db_path() {
    const auto dir = fs::temp_directory_path() / ("yuzu_test_cmddedup" + uid_suffix());
    return dir / (yuzu::test::unique_temp_path("cmddedup_").filename().string() + ".db");
}

static TestDedupStore make_store() {
    const auto tmp = fresh_db_path();
    auto result = CommandDedupStore::open(tmp);
    REQUIRE(result.has_value());
    return TestDedupStore{tmp, std::move(*result)};
}

// ── Lifecycle basics ──────────────────────────────────────────────────────────

TEST_CASE("CommandDedupStore: open creates the database file", "[command_dedup][lifecycle]") {
    auto t = make_store();
    CHECK(fs::exists(t.path));
}

TEST_CASE("CommandDedupStore: first claim is Claimed, no stored response",
          "[command_dedup][claim]") {
    auto t = make_store();
    auto r = t.store.claim("cmd-1");
    CHECK(r.status == ClaimStatus::Claimed);
    CHECK(r.response.empty());
}

TEST_CASE("CommandDedupStore: a second claim while in flight is Duplicate/InFlight",
          "[command_dedup][claim]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);

    auto again = t.store.claim("cmd-1");
    CHECK(again.status == ClaimStatus::Duplicate);
    CHECK(again.state == DedupState::InFlight);
    CHECK(again.response.empty()); // no terminal outcome to replay yet
}

TEST_CASE("CommandDedupStore: a duplicate after record_terminal replays the exact outcome",
          "[command_dedup][replay]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);

    // Arbitrary bytes with an embedded NUL — must survive as a blob.
    const std::string outcome = std::string("SUCCESS\0exit=0\0payload", 22);
    t.store.record_terminal("cmd-1", outcome);

    auto dup = t.store.claim("cmd-1");
    CHECK(dup.status == ClaimStatus::Duplicate);
    CHECK(dup.state == DedupState::Terminal);
    CHECK(dup.response == outcome); // byte-exact, NUL preserved
}

TEST_CASE("CommandDedupStore: release lets a command be re-claimed (transient path)",
          "[command_dedup][release]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);

    // Simulate a queue-full: the command never executed, so its claim is released.
    t.store.release("cmd-1");

    // A redelivery must be executable again — Claimed, not Duplicate.
    CHECK(t.store.claim("cmd-1").status == ClaimStatus::Claimed);
}

TEST_CASE("CommandDedupStore: release never removes a terminal outcome",
          "[command_dedup][release]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);
    t.store.record_terminal("cmd-1", "SUCCESS");

    t.store.release("cmd-1"); // must be a no-op against a terminal row

    auto dup = t.store.claim("cmd-1");
    CHECK(dup.status == ClaimStatus::Duplicate);
    CHECK(dup.state == DedupState::Terminal);
    CHECK(dup.response == "SUCCESS");
}

TEST_CASE("CommandDedupStore: empty command_id is never deduplicated",
          "[command_dedup][edge]") {
    auto t = make_store();
    CHECK(t.store.claim("").status == ClaimStatus::Error); // proceed without dedup
    // record_terminal / release on an empty id are no-ops (must not throw/insert).
    t.store.record_terminal("", "x");
    t.store.release("");
    auto c = t.store.count();
    REQUIRE(c.has_value());
    CHECK(*c == 0);
}

// ── The WS-0 core properties (WS-9 scenarios, store form) ──────────────────────

TEST_CASE("CommandDedupStore: a terminal outcome survives an agent RESTART",
          "[command_dedup][restart][effectively-once]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path}; // owns cleanup of .db/-wal/-shm

    const std::string outcome = std::string("SUCCESS\0result-blob", 19);
    {
        auto opened = CommandDedupStore::open(path);
        REQUIRE(opened.has_value());
        REQUIRE(opened->claim("cmd-restart").status == ClaimStatus::Claimed);
        opened->record_terminal("cmd-restart", outcome);
    } // store destructs — simulates the agent process exiting

    // Fresh process: reopen the SAME file. A redelivered command replays the
    // ORIGINAL outcome — not a bare REJECTED, and it does NOT re-execute.
    auto reopened = CommandDedupStore::open(path);
    REQUIRE(reopened.has_value());
    auto dup = reopened->claim("cmd-restart");
    CHECK(dup.status == ClaimStatus::Duplicate);
    CHECK(dup.state == DedupState::Terminal);
    CHECK(dup.response == outcome);
}

TEST_CASE("CommandDedupStore: a crashed in-flight command is INDETERMINATE after restart",
          "[command_dedup][restart][effectively-once]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};

    {
        auto opened = CommandDedupStore::open(path);
        REQUIRE(opened.has_value());
        // Claim but never resolve — models a crash mid-execution.
        REQUIRE(opened->claim("cmd-crash").status == ClaimStatus::Claimed);
    }

    // Redelivery after restart: the record is still in-flight, so we answer
    // Duplicate/InFlight (the caller replies RUNNING). We must NEVER re-claim it
    // as fresh — that would re-run a possibly-destructive command.
    auto reopened = CommandDedupStore::open(path);
    REQUIRE(reopened.has_value());
    auto dup = reopened->claim("cmd-crash");
    CHECK(dup.status == ClaimStatus::Duplicate);
    CHECK(dup.state == DedupState::InFlight);
}

// ── record_terminal outcome semantics ──────────────────────────────────────────

TEST_CASE("CommandDedupStore: record_terminal on a never-claimed id is a Miss, no row",
          "[command_dedup][record]") {
    auto t = make_store();
    CHECK(t.store.record_terminal("never-claimed", "SUCCESS") == RecordOutcome::Miss);
    auto c = t.store.count();
    REQUIRE(c.has_value());
    CHECK(*c == 0); // Miss must NOT create a row
    // ...and the id is still claimable fresh (nothing was memoised).
    CHECK(t.store.claim("never-claimed").status == ClaimStatus::Claimed);
}

TEST_CASE("CommandDedupStore: record_terminal is first-write-wins (second is a Miss)",
          "[command_dedup][record]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);
    CHECK(t.store.record_terminal("cmd-1", "FIRST") == RecordOutcome::Recorded);
    // A second terminal (e.g. a spurious post-terminal throw) must NOT overwrite.
    CHECK(t.store.record_terminal("cmd-1", "SECOND") == RecordOutcome::Miss);
    auto dup = t.store.claim("cmd-1");
    CHECK(dup.state == DedupState::Terminal);
    CHECK(dup.response == "FIRST"); // the original outcome is sticky
}

TEST_CASE("CommandDedupStore: a corrupt/non-proto stored blob round-trips byte-exact",
          "[command_dedup][replay]") {
    // The store is proto-agnostic — it must return whatever bytes were stored,
    // even non-parseable ones (the agent then falls back to RUNNING). No
    // cross-command mixup: command_id is the PK.
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-garbage").status == ClaimStatus::Claimed);
    const std::string garbage = std::string("\xff\x00\x01not-a-protobuf\x00", 18);
    REQUIRE(t.store.record_terminal("cmd-garbage", garbage) == RecordOutcome::Recorded);
    auto dup = t.store.claim("cmd-garbage");
    CHECK(dup.state == DedupState::Terminal);
    CHECK(dup.response == garbage);
}

// ── Retention: clock-free rowid ring over TERMINAL rows only ────────────────────

TEST_CASE("CommandDedupStore: retention evicts oldest TERMINAL rows",
          "[command_dedup][retention]") {
    auto t = make_store();
    t.store.set_max_dedup_rows_for_test(50); // exercise the ring without 20k fsyncs

    REQUIRE(t.store.claim("cmd-oldest").status == ClaimStatus::Claimed);
    REQUIRE(t.store.record_terminal("cmd-oldest", "SUCCESS") == RecordOutcome::Recorded);

    // Drive enough claim+terminal PAIRS to overflow the terminal ring and prune.
    const std::int64_t overflow =
        50 + static_cast<std::int64_t>(CommandDedupStore::kPruneInterval) + 100;
    for (std::int64_t i = 0; i < overflow; ++i) {
        auto id = "fill-" + std::to_string(i);
        REQUIRE(t.store.claim(id).status == ClaimStatus::Claimed);
        REQUIRE(t.store.record_terminal(id, "SUCCESS") == RecordOutcome::Recorded);
    }

    // Count stays bounded (50 + at most one prune interval of slack).
    auto c = t.store.count();
    REQUIRE(c.has_value());
    CHECK(*c <= 50 + static_cast<std::int64_t>(CommandDedupStore::kPruneInterval));

    // The oldest TERMINAL row was evicted, so it re-claims fresh.
    CHECK(t.store.claim("cmd-oldest").status == ClaimStatus::Claimed);
}

TEST_CASE("CommandDedupStore: a live in-flight row is NEVER evicted by retention (UP-1)",
          "[command_dedup][retention][effectively-once]") {
    auto t = make_store();
    t.store.set_max_dedup_rows_for_test(50);

    // One long-running command: claimed, not yet resolved.
    REQUIRE(t.store.claim("cmd-live").status == ClaimStatus::Claimed);

    // Churn well past the ring with terminal commands while it "runs".
    const std::int64_t churn =
        50 + static_cast<std::int64_t>(CommandDedupStore::kPruneInterval) + 200;
    for (std::int64_t i = 0; i < churn; ++i) {
        auto id = "churn-" + std::to_string(i);
        REQUIRE(t.store.claim(id).status == ClaimStatus::Claimed);
        REQUIRE(t.store.record_terminal(id, "SUCCESS") == RecordOutcome::Recorded);
    }

    // The live claim MUST survive — evicting it would let its redelivery
    // re-execute a possibly-destructive command (the failure the design forbids).
    auto dup = t.store.claim("cmd-live");
    CHECK(dup.status == ClaimStatus::Duplicate);
    CHECK(dup.state == DedupState::InFlight);
}

// ── release outcome + open() failure branches ──────────────────────────────────

TEST_CASE("CommandDedupStore: release reports Released on a healthy store",
          "[command_dedup][release]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);
    CHECK(t.store.release("cmd-1") == ReleaseOutcome::Released);
    // An empty id / no-op release is Released (nothing to leak), not Error.
    CHECK(t.store.release("") == ReleaseOutcome::Released);
    CHECK(t.store.release("never-claimed") == ReleaseOutcome::Released);
}

TEST_CASE("CommandDedupStore: open fails on an unusable path (a directory)",
          "[command_dedup][lifecycle]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_dir_"};
    std::error_code ec;
    std::filesystem::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);
    // The path is a directory, not a valid database file — open must fail.
    auto result = CommandDedupStore::open(dir.path);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("CommandDedupStore: open fails on a non-database file",
          "[command_dedup][lifecycle]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    // fresh_db_path()'s parent dir may not exist yet if no earlier case in this
    // binary has created it — an unchecked ofstream open into a missing parent
    // fails SILENTLY (no exception, no bytes written), and open() below then
    // creates that same parent itself and succeeds against a fresh empty DB
    // (#3744: misdiagnosed as a Windows/Defender visibility race — it reproduces
    // on any platform once the shared temp dir doesn't already exist).
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    REQUIRE_FALSE(ec);
    {
        std::ofstream f(path, std::ios::binary);
        REQUIRE(f.is_open());
        f << "this is not a sqlite database";
        REQUIRE(f.good());
        f.flush();
        REQUIRE(f.good());
    }
    // f.good() alone doesn't prove the bytes reached disk: the actual flush/
    // write happens in the destructor above, which can't propagate an I/O
    // error — the explicit flush() + re-check makes the failure observable
    // here instead of manifesting as a silent empty file for open() to accept.
    REQUIRE(fs::file_size(path) > 0);
    // journal_mode/synchronous read-back or the schema DDL rejects a garbage file.
    auto result = CommandDedupStore::open(path);
    CHECK_FALSE(result.has_value());
}
