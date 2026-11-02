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

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

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


// ── Corruption recovery (#3665) ──────────────────────────────────────────────

// Quarantined siblings of `db` (`<name>.corrupt-*`, plus their -wal/-shm sidecars).
static std::vector<fs::path> quarantine_siblings(const fs::path& db) {
    std::vector<fs::path> out;
    std::error_code ec;
    const auto prefix = db.filename().string() + ".corrupt-";
    if (!fs::exists(db.parent_path(), ec))
        return out;
    for (const auto& e : fs::directory_iterator(db.parent_path(), ec)) {
        if (e.path().filename().string().starts_with(prefix))
            out.push_back(e.path());
    }
    return out;
}

// Removes every `<db>.corrupt-*` file on scope exit (TempDbFile only knows the live files).
struct QuarantineCleanup {
    fs::path db;
    ~QuarantineCleanup() {
        for (const auto& p : quarantine_siblings(db)) {
            std::error_code ec;
            fs::remove(p, ec);
        }
    }
};

static void write_bytes(const fs::path& p, const std::string& bytes) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    REQUIRE_FALSE(ec);
    {
        std::ofstream f(p, std::ios::binary);
        REQUIRE(f.is_open());
        f << bytes;
        f.flush();
        REQUIRE(f.good());
    }
    REQUIRE(fs::file_size(p) == bytes.size()); // the bytes reached the filesystem
}

static std::string read_bytes(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
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
    // #3665: CANTOPEN is environmental, not corruption — it must NEVER quarantine (that would
    // move a directory / discard good history). The path is left exactly as found.
    CHECK(fs::is_directory(dir.path));
    CHECK(quarantine_siblings(dir.path).empty());
}

TEST_CASE("CommandDedupStore: a non-database file is quarantined and recreated",
          "[command_dedup][lifecycle][corruption]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    const std::string garbage = "this is not a sqlite database";
    write_bytes(path, garbage);

    {
        auto result = CommandDedupStore::open(path);
        REQUIRE(result.has_value());
        REQUIRE(result->quarantined_this_open().has_value());

        const auto q = quarantine_siblings(path);
        REQUIRE(q.size() == 1);
        CHECK(q[0].filename().string() == *result->quarantined_this_open());
        CHECK(read_bytes(q[0]) == garbage); // evidence preserved byte-for-byte

        // The fresh store is fully functional.
        CHECK(result->claim("cmd-after-recovery").status == ClaimStatus::Claimed);
    }

    // A later boot is a normal open: no second quarantine, and the claim persisted.
    auto reopened = CommandDedupStore::open(path);
    REQUIRE(reopened.has_value());
    CHECK_FALSE(reopened->quarantined_this_open().has_value());
    CHECK(quarantine_siblings(path).size() == 1);
    auto dup = reopened->claim("cmd-after-recovery");
    CHECK(dup.status == ClaimStatus::Duplicate);
}

TEST_CASE("CommandDedupStore: a file whose schema step hits corruption is quarantined",
          "[command_dedup][lifecycle][corruption]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    {
        auto opened = CommandDedupStore::open(path);
        REQUIRE(opened.has_value());
        for (int i = 0; i < 50; ++i)
            REQUIRE(opened->claim("cmd-" + std::to_string(i)).status == ClaimStatus::Claimed);
    } // last connection closes -> WAL checkpointed into the main file

    // Keep page 1 (header + schema, so open_v2 and the pragmas succeed) and trash the rest, so the
    // schema step's own read of `meta` fails with SQLITE_CORRUPT: the store cannot be initialised,
    // which is an OPEN failure and the one thing that justifies discarding the file.
    auto bytes = read_bytes(path);
    REQUIRE(bytes.size() > 8192);
    for (std::size_t i = 4096; i < bytes.size(); ++i)
        bytes[i] = static_cast<char>(0xAB);
    write_bytes(path, bytes);

    auto result = CommandDedupStore::open(path);
    REQUIRE(result.has_value());
    CHECK(result->quarantined_this_open().has_value());
    CHECK(quarantine_siblings(path).size() == 1);
    // History in the damaged file is gone (documented); the store itself is healthy again.
    CHECK(result->claim("cmd-0").status == ClaimStatus::Claimed);
}

TEST_CASE("CommandDedupStore: a file that still opens with damaged data pages is NOT quarantined",
          "[command_dedup][lifecycle][corruption]") {
    // Owner ruling (#3665): no whole-file integrity scan. A file that opens keeps serving the ids
    // whose pages are intact; quarantining it would discard in-flight claims too (invariants 4, 5).
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    const std::string blob(2000, 'x');
    constexpr int kRows = 300;
    {
        auto opened = CommandDedupStore::open(path);
        REQUIRE(opened.has_value());
        for (int i = 0; i < kRows; ++i) {
            const auto id = "cmd-" + std::to_string(i);
            REQUIRE(opened->claim(id).status == ClaimStatus::Claimed);
            REQUIRE(opened->record_terminal(id, blob) == RecordOutcome::Recorded);
        }
    }

    auto bytes = read_bytes(path);
    constexpr std::size_t kPage = 4096;
    REQUIRE(bytes.size() > 40 * kPage);
    const std::size_t victim = (bytes.size() / kPage) / 2; // a data page well away from page 1
    for (std::size_t i = victim * kPage; i < (victim + 1) * kPage; ++i)
        bytes[i] = static_cast<char>(0xAB);
    write_bytes(path, bytes);

    auto result = CommandDedupStore::open(path);
    REQUIRE(result.has_value());
    CHECK_FALSE(result->quarantined_this_open().has_value());
    CHECK(quarantine_siblings(path).empty());
    CHECK(fs::exists(path));

    int still_known = 0;
    for (int i = 0; i < kRows; ++i) {
        if (result->claim("cmd-" + std::to_string(i)).status == ClaimStatus::Duplicate)
            ++still_known;
    }
    CHECK(still_known > 0); // history on intact pages survives
}

TEST_CASE("CommandDedupStore: only the newest 3 quarantined stores are kept",
          "[command_dedup][lifecycle][corruption]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    const auto q = [&](const std::string& tail) {
        fs::path f = path;
        f += ".corrupt-" + tail;
        return f;
    };
    for (const char* e : {"1", "2", "3", "4", "5"})
        write_bytes(q(e), std::string("old-") + e);
    write_bytes(q("1-wal"), "old-1-wal"); // a sidecar travels with its group
    write_bytes(q("notanumber"), "not ours"); // does not parse: never touched
    write_bytes(path, "garbage main file");

    auto result = CommandDedupStore::open(path);
    REQUIRE(result.has_value());
    REQUIRE(result->quarantined_this_open().has_value());

    // groups 1..5 + the new one = 6; the 3 oldest (1, 2, 3) go, with group 1's sidecar.
    for (const char* e : {"1", "2", "3", "1-wal"})
        CHECK_FALSE(fs::exists(q(e)));
    for (const char* e : {"4", "5"})
        CHECK(fs::exists(q(e)));
    CHECK(fs::exists(path.parent_path() / *result->quarantined_this_open()));
    CHECK(read_bytes(q("notanumber")) == "not ours");
}

TEST_CASE("CommandDedupStore: pruning never removes the quarantine it just made",
          "[command_dedup][lifecycle][corruption]") {
    // A backward clock step makes the NEW name sort OLDEST. Count-based pruning orders by name, so
    // it must skip the file it just created or it would delete the only fresh evidence.
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    std::vector<fs::path> future;
    for (long long d : {1000LL, 2000LL, 3000LL}) {
        fs::path f = path;
        f += ".corrupt-" + std::to_string(now + d);
        write_bytes(f, "from the future");
        future.push_back(f);
    }
    write_bytes(path, "garbage main file");

    auto result = CommandDedupStore::open(path);
    REQUIRE(result.has_value());
    REQUIRE(result->quarantined_this_open().has_value());
    CHECK(fs::exists(path.parent_path() / *result->quarantined_this_open())); // survived
    CHECK_FALSE(fs::exists(future[0])); // the oldest OTHER group was the one pruned
    CHECK(fs::exists(future[1]));
    CHECK(fs::exists(future[2]));
}

TEST_CASE("CommandDedupStore: a stale -wal beside a corrupt file is never adopted by the fresh store",
          "[command_dedup][lifecycle][corruption]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    const fs::path wal = path.string() + "-wal";
    write_bytes(path, "garbage main file");
    write_bytes(wal, "stale wal bytes");

    {
        auto result = CommandDedupStore::open(path);
        REQUIRE(result.has_value());
        REQUIRE(result->quarantined_this_open().has_value());

        // SQLite may itself discard a garbage WAL when the failed attempt's connection closes, in
        // which case there is nothing to move. Either way the stale bytes must not be live: a
        // surviving `-wal` beside the fresh DB must not be the stale one, and if the quarantine
        // kept a copy it must be intact.
        if (fs::exists(wal))
            CHECK(read_bytes(wal) != "stale wal bytes");
        const fs::path qwal =
            (path.parent_path() / *result->quarantined_this_open()).string() + "-wal";
        if (fs::exists(qwal))
            CHECK(read_bytes(qwal) == "stale wal bytes");

        CHECK(result->claim("cmd-fresh").status == ClaimStatus::Claimed);
    }

    // The fresh store is self-consistent across a restart: no second quarantine, claim kept.
    auto reopened = CommandDedupStore::open(path);
    REQUIRE(reopened.has_value());
    CHECK_FALSE(reopened->quarantined_this_open().has_value());
    CHECK(reopened->claim("cmd-fresh").status == ClaimStatus::Duplicate);
}

TEST_CASE("CommandDedupStore: a second corruption never overwrites an earlier quarantine",
          "[command_dedup][lifecycle][corruption]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};

    // Occupy the `.corrupt-<epoch>` names the open is most likely to pick (the clock is 1 s granular
    // and can step backward), so the collision-safe `-<n>` suffix is used whenever it lands on one.
    // Only two, so the keep-newest-3 rule does not prune them away.
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
                         std::chrono::system_clock::now().time_since_epoch())
                         .count();
    std::vector<fs::path> blockers;
    for (long long e : {now, now + 1}) {
        fs::path b = path;
        b += ".corrupt-" + std::to_string(e);
        write_bytes(b, "earlier quarantine");
        blockers.push_back(b);
    }
    write_bytes(path, "second corruption");

    auto result = CommandDedupStore::open(path);
    REQUIRE(result.has_value());
    REQUIRE(result->quarantined_this_open().has_value());

    for (const auto& b : blockers)
        CHECK(read_bytes(b) == "earlier quarantine"); // untouched
    const auto q = quarantine_siblings(path);
    REQUIRE(q.size() == blockers.size() + 1);
    CHECK(read_bytes(path.parent_path() / *result->quarantined_this_open()) == "second corruption");
}

#ifndef _WIN32
TEST_CASE("CommandDedupStore: a corrupt file that cannot be moved aside fails open, untouched",
          "[command_dedup][lifecycle][corruption]") {
    if (::geteuid() == 0)
        SKIP("root bypasses directory permissions; the unmovable case cannot be built");

    yuzu::test::TempDir dir{"yuzu_test_cmddedup_ro_"};
    std::error_code ec;
    fs::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);
    const auto path = dir.path / "command_dedup.db";
    write_bytes(path, "garbage main file");

    // Read-only parent: the corrupt file opens read-write (its own mode) but cannot be renamed.
    struct RestorePerms {
        fs::path d;
        ~RestorePerms() {
            std::error_code e;
            fs::permissions(d, fs::perms::owner_all, fs::perm_options::replace, e);
        }
    } restore{dir.path};
    fs::permissions(dir.path, fs::perms::owner_read | fs::perms::owner_exec,
                    fs::perm_options::replace, ec);
    REQUIRE_FALSE(ec);

    auto result = CommandDedupStore::open(path);
    REQUIRE_FALSE(result.has_value()); // observable fail-open path, same as any open failure
    // It must be the quarantine-failure branch, not an unrelated CANTOPEN that merely also fails.
    CHECK(result.error().message.find("could not be quarantined") != std::string::npos);
    CHECK(read_bytes(path) == "garbage main file"); // original untouched
    CHECK(quarantine_siblings(path).empty());
}
#endif

TEST_CASE("CommandDedupStore: a healthy open and reopen never quarantine",
          "[command_dedup][lifecycle][corruption]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    {
        auto opened = CommandDedupStore::open(path);
        REQUIRE(opened.has_value());
        CHECK_FALSE(opened->quarantined_this_open().has_value());
        REQUIRE(opened->claim("cmd-keep").status == ClaimStatus::Claimed);
    }
    auto reopened = CommandDedupStore::open(path);
    REQUIRE(reopened.has_value());
    CHECK_FALSE(reopened->quarantined_this_open().has_value());
    CHECK(reopened->claim("cmd-keep").status == ClaimStatus::Duplicate); // history kept
    CHECK(quarantine_siblings(path).empty());
}
