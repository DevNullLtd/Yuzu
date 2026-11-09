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

#include "command_dedup_quarantine.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <csignal>
#include <sys/resource.h>
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

// #3678: the boundary the server's redelivery horizon is sized against. The ring keeps the newest
// `max` TERMINAL rows by rowid and prunes only on every kPruneInterval-th record_terminal. With
// `max == kPruneInterval` the FIRST prune runs while the table holds EXACTLY `max` terminal rows,
// so it pins both sides of the boundary at once:
//   * a command followed by `max - 1` newer terminals is still the oldest of `max` retained rows,
//     and must survive that prune (a bound of `max - 1`, or an off-by-one in the LIMIT, evicts it
//     and fails the first assertion);
//   * after `max` MORE newer terminals the next prune must evict it (a bound that keeps extra rows,
//     or a prune that no longer fires on cadence, fails the second assertion).
// An earlier version used a bound of 600 beside the 512 cadence: its only prune ran with fewer
// than 600 rows, so it passed for ANY bound from 512 to 1500 and proved nothing about the limit.
// Reduced ring (the idiom above): this proves the SHAPE of the boundary, not the 20000 figure.
TEST_CASE("CommandDedupStore: a terminal command survives max-1 newer terminals through a prune "
          "and is evicted by the next prune after max more (#3678)",
          "[command_dedup][retention][3678]") {
    static_assert(CommandDedupStore::kMaxDedupRows == ::yuzu::kAgentDedupRingRows,
                  "the ring bound is single-sourced in command_replay_horizon.hpp");
    constexpr std::int64_t kRing = static_cast<std::int64_t>(CommandDedupStore::kPruneInterval);
    auto t = make_store();
    t.store.set_max_dedup_rows_for_test(kRing);

    REQUIRE(t.store.claim("cmd-x").status == ClaimStatus::Claimed);
    REQUIRE(t.store.record_terminal("cmd-x", "SUCCESS-X") == RecordOutcome::Recorded);

    // kRing - 1 newer terminals => kRing terminal rows in total; the kRing-th record_terminal
    // triggers the first prune with exactly kRing rows held. cmd-x must survive it.
    for (std::int64_t i = 0; i < kRing - 1; ++i) {
        auto id = "newer-" + std::to_string(i);
        REQUIRE(t.store.claim(id).status == ClaimStatus::Claimed);
        REQUIRE(t.store.record_terminal(id, "SUCCESS") == RecordOutcome::Recorded);
    }
    auto inside = t.store.claim("cmd-x");
    CHECK(inside.status == ClaimStatus::Duplicate);
    CHECK(inside.state == DedupState::Terminal);
    CHECK(inside.response == "SUCCESS-X"); // replayed with its ORIGINAL outcome

    // kRing more newer terminals => the next prune (kRing record_terminals later) keeps only the
    // newest kRing rows, and cmd-x is no longer among them: a redelivery is a fresh claim.
    for (std::int64_t i = 0; i < kRing; ++i) {
        auto id = "pushout-" + std::to_string(i);
        REQUIRE(t.store.claim(id).status == ClaimStatus::Claimed);
        REQUIRE(t.store.record_terminal(id, "SUCCESS") == RecordOutcome::Recorded);
    }
    CHECK(t.store.claim("cmd-x").status == ClaimStatus::Claimed);
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

// ── cached_row_count(): the lock-free heartbeat capacity signal (#3663) ─────────

TEST_CASE("CommandDedupStore: cached_row_count is 0 (known) on a fresh store",
          "[command_dedup][row_count]") {
    auto t = make_store();
    const auto cached = t.store.cached_row_count();
    REQUIRE(cached.has_value()); // 0 is a reading; nullopt would mean "unknown"
    CHECK(*cached == 0);
}

TEST_CASE("CommandDedupStore: cached_row_count tracks claims and agrees with count()",
          "[command_dedup][row_count]") {
    auto t = make_store();
    for (int i = 0; i < 5; ++i)
        REQUIRE(t.store.claim("cmd-" + std::to_string(i)).status == ClaimStatus::Claimed);

    // A Duplicate claim inserts nothing, so it must not move the count.
    REQUIRE(t.store.claim("cmd-0").status == ClaimStatus::Duplicate);
    // Flipping in-flight -> terminal is not a new row either.
    REQUIRE(t.store.record_terminal("cmd-1", "SUCCESS") == RecordOutcome::Recorded);

    const auto cached = t.store.cached_row_count();
    const auto real = t.store.count();
    REQUIRE(cached.has_value());
    REQUIRE(real.has_value());
    CHECK(*cached == 5);
    CHECK(*cached == *real);
}

TEST_CASE("CommandDedupStore: cached_row_count is exact again after a restart",
          "[command_dedup][row_count][restart]") {
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    {
        auto opened = CommandDedupStore::open(path);
        REQUIRE(opened.has_value());
        REQUIRE(opened->claim("a").status == ClaimStatus::Claimed);
        REQUIRE(opened->claim("b").status == ClaimStatus::Claimed);
        REQUIRE(opened->record_terminal("a", "SUCCESS") == RecordOutcome::Recorded);
    }
    // The process-local atomic is gone; the reopened store must re-anchor on the file.
    auto reopened = CommandDedupStore::open(path);
    REQUIRE(reopened.has_value());
    const auto cached = reopened->cached_row_count();
    REQUIRE(cached.has_value());
    CHECK(*cached == 2);
}

TEST_CASE("CommandDedupStore: cached_row_count is re-anchored by the prune and stays bounded",
          "[command_dedup][row_count][retention]") {
    auto t = make_store();
    t.store.set_max_dedup_rows_for_test(50);

    const std::int64_t overflow =
        50 + static_cast<std::int64_t>(CommandDedupStore::kPruneInterval) + 100;
    for (std::int64_t i = 0; i < overflow; ++i) {
        auto id = "fill-" + std::to_string(i);
        REQUIRE(t.store.claim(id).status == ClaimStatus::Claimed);
        REQUIRE(t.store.record_terminal(id, "SUCCESS") == RecordOutcome::Recorded);
    }

    const auto cached = t.store.cached_row_count();
    const auto real = t.store.count();
    REQUIRE(cached.has_value());
    REQUIRE(real.has_value());
    // Without a release() the cache must equal the table exactly, not merely be near it.
    CHECK(*cached == *real);
    // ...and the eviction must be visible in it: the ring held the table to the bound
    // plus at most one prune interval, so the cache cannot have kept counting claims.
    CHECK(*cached <= 50 + static_cast<std::int64_t>(CommandDedupStore::kPruneInterval));
    CHECK(*cached < overflow);
}

TEST_CASE("CommandDedupStore: cached_row_count may over-read after a release, never under-read",
          "[command_dedup][row_count][release]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);
    REQUIRE(t.store.release("cmd-1") == ReleaseOutcome::Released);

    const auto cached = t.store.cached_row_count();
    const auto real = t.store.count();
    REQUIRE(cached.has_value());
    REQUIRE(real.has_value());
    CHECK(*real == 0);
    // The documented, accepted drift: release() does not decrement. It is an over-read of a
    // capacity gauge, never an under-read that would hide a store approaching its bound.
    CHECK(*cached >= *real);
}

TEST_CASE("CommandDedupStore: cached_row_count survives a move of the store",
          "[command_dedup][row_count][lifecycle]") {
    auto t = make_store();
    REQUIRE(t.store.claim("cmd-1").status == ClaimStatus::Claimed);
    REQUIRE(t.store.claim("cmd-2").status == ClaimStatus::Claimed);

    CommandDedupStore moved{std::move(t.store)};
    const auto cached = moved.cached_row_count();
    REQUIRE(cached.has_value());
    CHECK(*cached == 2);
    // The moved-from store no longer owns a database: its count is unknown, not stale.
    // NOLINTNEXTLINE(bugprone-use-after-move) -- deliberately probing the moved-from state
    CHECK_FALSE(t.store.cached_row_count().has_value());
}

namespace {
// Joins the thread on EVERY exit path, including the exception a failed REQUIRE throws: a
// std::thread destroyed while joinable calls std::terminate, which would abort the whole test
// binary and hide every other result. (std::jthread would do this, but it is not available in
// every supported libc++, e.g. Apple Clang 15's; the rest of the codebase gates it behind
// __cpp_lib_jthread.)
struct StopAndJoin {
    std::atomic<bool>& stop;
    std::thread& thread;
    ~StopAndJoin() {
        stop.store(true, std::memory_order_release);
        if (thread.joinable())
            thread.join();
    }
};
} // namespace

TEST_CASE("CommandDedupStore: cached_row_count is safe to read while claims and prunes run",
          "[command_dedup][row_count][concurrent]") {
    // The heartbeat thread reads cached_row_count() lock-free while the reader thread claims and
    // a worker thread records/prunes under mu_. This is the one cross-thread read the cache adds,
    // so it is the case TSan (nightly) needs: a data race on cached_rows_ or db_ would be flagged
    // here (verified: with cached_rows_ made a plain int64_t, TSan reports the race; without TSan
    // the same mutant passes, so this case alone is not a race detector). Without TSan it still
    // pins the bounds: never negative once known, never beyond the rows ever inserted, and exact
    // against the table once the writer has stopped.
    auto t = make_store();
    t.store.set_max_dedup_rows_for_test(50);
    constexpr int kCycles = 600; // > kPruneInterval (512), so at least one prune + recount runs

    std::atomic<bool> stop{false};
    std::atomic<int> reads{0};
    std::atomic<std::int64_t> lowest{INT64_MAX};
    std::atomic<std::int64_t> highest{-1};
    std::thread reader([&] {
        // do/while: the reader always reads once before it looks at `stop`, so a reader that is
        // scheduled late still records a value.
        do {
            if (const auto rows = t.store.cached_row_count()) {
                reads.fetch_add(1, std::memory_order_relaxed);
                std::int64_t cur = lowest.load(std::memory_order_relaxed);
                while (*rows < cur && !lowest.compare_exchange_weak(cur, *rows)) {}
                cur = highest.load(std::memory_order_relaxed);
                while (*rows > cur && !highest.compare_exchange_weak(cur, *rows)) {}
            }
            std::this_thread::yield();
        } while (!stop.load(std::memory_order_acquire));
    });
    StopAndJoin guard{stop, reader};

    // Do not start writing until the reader has observed a value, so `reads > 0` below cannot
    // fail on a loaded runner that has not yet scheduled the reader. The count is known (0) after
    // construction; the REQUIRE makes a regression that leaves it unknown fail here instead of
    // spinning until the test runner's timeout.
    REQUIRE(t.store.cached_row_count().has_value());
    while (reads.load(std::memory_order_relaxed) == 0)
        std::this_thread::yield();

    for (int i = 0; i < kCycles; ++i) {
        const auto id = "conc-" + std::to_string(i);
        REQUIRE(t.store.claim(id).status == ClaimStatus::Claimed);
        REQUIRE(t.store.record_terminal(id, "SUCCESS") == RecordOutcome::Recorded);
    }
    stop.store(true, std::memory_order_release);
    reader.join();

    CHECK(reads.load() > 0);
    CHECK(lowest.load() >= 0); // a known count is never negative
    CHECK(highest.load() <= kCycles); // never more rows than were ever inserted
    const auto cached = t.store.cached_row_count();
    const auto real = t.store.count();
    REQUIRE(cached.has_value());
    REQUIRE(real.has_value());
    CHECK(*cached == *real); // no release() ran, so the cache is exact
    CHECK(*cached < kCycles); // the prune evicted, and the recount saw it
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

TEST_CASE("CommandDedupStore: the fresh store after a quarantine reports a known zero row count",
          "[command_dedup][lifecycle][corruption][row_count]") {
    // #3665 recovery builds a NEW store through the same constructor that takes the initial
    // count. The quarantined file's rows are gone, so the cache must read a KNOWN 0 (an unknown
    // would look like an agent that does not report the tag), and must then track claims.
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    write_bytes(path, "this is not a sqlite database");

    auto result = CommandDedupStore::open(path);
    REQUIRE(result.has_value());
    REQUIRE(result->quarantined_this_open().has_value());
    auto fresh = result->cached_row_count();
    REQUIRE(fresh.has_value());
    CHECK(*fresh == 0);

    REQUIRE(result->claim("cmd-after-recovery").status == ClaimStatus::Claimed);
    auto after = result->cached_row_count();
    REQUIRE(after.has_value());
    CHECK(*after == 1);
}

TEST_CASE("CommandDedupStore: a file whose schema page is garbage is quarantined",
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

    // Keep the 100-byte SQLite header (so open_v2 and the pragmas succeed) and trash the rest of
    // page 1, which holds sqlite_schema: the store cannot be initialised. That is an OPEN failure
    // and the one thing that justifies discarding the file.
    auto bytes = read_bytes(path);
    REQUIRE(bytes.size() > 4096);
    for (std::size_t i = 100; i < 4096; ++i)
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
    int silently_reclaimed = 0;
    for (int i = 0; i < kRows; ++i) {
        const auto status = result->claim("cmd-" + std::to_string(i)).status;
        if (status == ClaimStatus::Duplicate)
            ++still_known;
        else if (status == ClaimStatus::Claimed)
            ++silently_reclaimed;
    }
    // History on intact pages survives (a leaf page holds a handful of rows), and an id on the
    // damaged page fails open with Error: it must NEVER read as a fresh Claimed, which would be a
    // silent re-execution.
    CHECK(still_known >= kRows - 10);
    CHECK(silently_reclaimed == 0);
}

TEST_CASE("CommandDedupStore: damage confined to the unused meta table does not quarantine",
          "[command_dedup][lifecycle][corruption]") {
    // The schema_version seed probes the meta table's own pages, which command_outcomes never
    // uses. Damage there must not discard a file whose command table is intact (invariants 4, 5).
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    constexpr int kRows = 100;
    {
        auto opened = CommandDedupStore::open(path);
        REQUIRE(opened.has_value());
        for (int i = 0; i < kRows; ++i)
            REQUIRE(opened->claim("cmd-" + std::to_string(i)).status == ClaimStatus::Claimed);
    }
    // Page layout is fixed by the schema's creation order: 1 = sqlite_schema, 2 = command_outcomes,
    // 3 = its autoindex, 4 = meta, 5 = meta's autoindex.
    auto bytes = read_bytes(path);
    constexpr std::size_t kPage = 4096;
    REQUIRE(bytes.size() >= 5 * kPage);
    for (std::size_t i = 3 * kPage; i < 5 * kPage; ++i)
        bytes[i] = static_cast<char>(0xAB);
    write_bytes(path, bytes);

    auto result = CommandDedupStore::open(path);
    REQUIRE(result.has_value());
    CHECK_FALSE(result->quarantined_this_open().has_value());
    CHECK(quarantine_siblings(path).empty());
    int still_known = 0;
    for (int i = 0; i < kRows; ++i) {
        if (result->claim("cmd-" + std::to_string(i)).status == ClaimStatus::Duplicate)
            ++still_known;
    }
    CHECK(still_known == kRows); // every id survived: nothing was discarded
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

TEST_CASE("CommandDedupStore: a garbage -wal beside a corrupt file does not poison the fresh store",
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
        // SQLite may itself discard a garbage WAL when the failed attempt closes; either way the
        // stale bytes must not be live beside the fresh store. (The sidecar-move branches are
        // driven directly in the dedup_quarantine tests below, where they are not at SQLite's mercy.)
        if (fs::exists(wal))
            CHECK(read_bytes(wal) != "stale wal bytes");
        CHECK(result->claim("cmd-fresh").status == ClaimStatus::Claimed);
    }
    auto reopened = CommandDedupStore::open(path);
    REQUIRE(reopened.has_value());
    CHECK_FALSE(reopened->quarantined_this_open().has_value());
    CHECK(reopened->claim("cmd-fresh").status == ClaimStatus::Duplicate);
}

// ── The filesystem half, driven directly (command_dedup_quarantine.hpp) ──────────────────────

namespace dq = yuzu::agent::dedup_quarantine;

TEST_CASE("dedup_quarantine: non-empty sidecars travel with the main file, empty ones are removed",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    write_bytes(db, "main");
    write_bytes(fs::path(db.string() + "-wal"), "wal bytes");
    write_bytes(fs::path(db.string() + "-journal"), "journal bytes");
    write_bytes(fs::path(db.string() + "-shm"), ""); // empty: holds no evidence

    const auto dest = dq::quarantine_corrupt_db(db, 1234).dest;
    REQUIRE(dest.has_value());
    CHECK(dest->filename().string() == "command_dedup.db.corrupt-1234");
    CHECK(read_bytes(*dest) == "main");
    CHECK(fs::hard_link_count(*dest) == 1); // the original name was dropped after the claim
    CHECK(read_bytes(fs::path(dest->string() + "-wal")) == "wal bytes");
    CHECK(read_bytes(fs::path(dest->string() + "-journal")) == "journal bytes");
    CHECK_FALSE(fs::exists(fs::path(dest->string() + "-shm"))); // removed, not carried
    CHECK_FALSE(fs::exists(db));
    CHECK_FALSE(fs::exists(fs::path(db.string() + "-wal")));
    CHECK_FALSE(fs::exists(fs::path(db.string() + "-shm")));
    CHECK_FALSE(fs::exists(fs::path(db.string() + "-journal")));
}

TEST_CASE("dedup_quarantine: a taken name gets a -n suffix and an earlier quarantine is untouched",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    fs::path taken = db;
    taken += ".corrupt-1234";
    write_bytes(taken, "earlier");
    write_bytes(db, "second");

    const auto dest = dq::quarantine_corrupt_db(db, 1234).dest;
    REQUIRE(dest.has_value());
    CHECK(dest->filename().string() == "command_dedup.db.corrupt-1234-1");
    CHECK(read_bytes(taken) == "earlier");
    CHECK(read_bytes(*dest) == "second");
}

TEST_CASE("dedup_quarantine: create_hard_link onto a taken name reports file_exists",
          "[command_dedup][corruption][quarantine_fs]") {
    // The atomicity of the name claim rests on this: a taken name must be told apart from "hard
    // links are unavailable here", on every platform's error mapping. If this ever fails (say, an
    // MSVC STL that maps ERROR_ALREADY_EXISTS differently), every collision would silently take the
    // non-atomic check-then-rename fallback.
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto a = dir.path / "a";
    const auto b = dir.path / "b";
    write_bytes(a, "a");
    write_bytes(b, "b");
    std::error_code ec;
    fs::create_hard_link(a, b, ec);
    REQUIRE(ec);
    CHECK(ec == std::errc::file_exists);
    CHECK(read_bytes(b) == "b"); // the taken name was not touched
}

TEST_CASE("dedup_quarantine: a clock before 1970 still yields a name the pruner can see",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    write_bytes(db, "main");
    const auto dest = dq::quarantine_corrupt_db(db, -5).dest;
    REQUIRE(dest.has_value());
    CHECK(dest->filename().string() == "command_dedup.db.corrupt-0");
    CHECK(dq::parse_quarantine_name("command_dedup.db.corrupt-", dest->filename().string())
              .has_value());
}

TEST_CASE("dedup_quarantine: parse_quarantine_name accepts only the documented grammar",
          "[command_dedup][corruption][quarantine_fs]") {
    constexpr std::string_view stem = "x.db.corrupt-";
    const auto parse = [&](std::string_view tail) {
        return dq::parse_quarantine_name(stem, std::string{stem} + std::string{tail});
    };
    using Key = std::pair<long long, long long>;
    CHECK(parse("5") == std::optional<Key>{Key{5, 0}});
    CHECK(parse("5-3") == std::optional<Key>{Key{5, 3}});
    CHECK(parse("5-wal") == std::optional<Key>{Key{5, 0}});
    CHECK(parse("5-3-journal") == std::optional<Key>{Key{5, 3}});
    CHECK(parse("007") == std::optional<Key>{Key{7, 0}}); // folds into the canonical key
    for (const char* bad : {"", "-5", "+5", "5-", "-0", "5--0", "5-+3", "5-3-4", "5.5", "5-wal-wal",
                            "abc", "5 ", " 5", "99999999999999999999", "5-99999999999999999999"}) {
        INFO("tail: '" << bad << "'");
        CHECK_FALSE(parse(bad).has_value());
    }
    CHECK_FALSE(dq::parse_quarantine_name(stem, "y.db.corrupt-5").has_value()); // other database
}

TEST_CASE("dedup_quarantine: prune keeps the newest groups and touches only well-formed names",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    const auto named = [&](const std::string& tail) {
        fs::path f = db;
        f += ".corrupt-" + tail;
        return f;
    };
    for (const char* e : {"10", "9", "8", "7", "6"})
        write_bytes(named(e), e);
    write_bytes(named("6-wal"), "wal");
    // Shapes that merely RESEMBLE a quarantine name must be left alone.
    for (const char* odd : {"99999999999999999999", "-0", "5--0", "abc", "6-wal-wal"})
        write_bytes(named(odd), "bystander");
    write_bytes(dir.path / "echo.db.corrupt-1", "someone else's");

    const auto just_created = named("10");
    dq::prune_old_quarantines(db, just_created);

    // Groups 6..10 = 5; the 2 oldest (6, with its -wal, and 7) go.
    for (const char* gone : {"6", "6-wal", "7"})
        CHECK_FALSE(fs::exists(named(gone)));
    for (const char* kept : {"8", "9", "10"})
        CHECK(fs::exists(named(kept)));
    for (const char* odd : {"99999999999999999999", "-0", "5--0", "abc", "6-wal-wal"})
        CHECK(fs::exists(named(odd)));
    CHECK(fs::exists(dir.path / "echo.db.corrupt-1"));
}

namespace sq = yuzu::shared::sqlite_quarantine;

TEST_CASE("dedup_quarantine: a sidecar whose rename fails is copied before the original is removed",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    write_bytes(db, "main");
    write_bytes(fs::path(db.string() + "-wal"), "wal bytes");

    sq::FsOps ops;
    ops.move = [](const fs::path&, const fs::path&, std::error_code& ec) {
        ec = std::make_error_code(std::errc::permission_denied); // the injected rename failure
    };
    const auto r = dq::quarantine_corrupt_db(db, 1234, ops);
    REQUIRE(r.dest.has_value());
    CHECK(read_bytes(*r.dest) == "main");
    CHECK(read_bytes(fs::path(r.dest->string() + "-wal")) == "wal bytes"); // preserved by copy
    CHECK_FALSE(fs::exists(fs::path(db.string() + "-wal")));             // original gone
    // The note replaces the former spdlog::warn: the caller logs it.
    REQUIRE(r.notes.size() == 1);
    CHECK(r.notes[0].find("copied") != std::string::npos);
}

TEST_CASE("dedup_quarantine: a sidecar quarantine name that is taken is never overwritten",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    write_bytes(db, "main");
    write_bytes(fs::path(db.string() + "-wal"), "new wal");
    write_bytes(fs::path(db.string() + ".corrupt-1234-wal"), "stray older wal");

    const auto r = dq::quarantine_corrupt_db(db, 1234);
    REQUIRE(r.dest.has_value());
    CHECK(r.dest->filename().string() == "command_dedup.db.corrupt-1234");
    CHECK(read_bytes(fs::path(r.dest->string() + "-wal")) == "stray older wal"); // not replaced
    CHECK_FALSE(fs::exists(fs::path(db.string() + "-wal"))); // the stale original still goes
    REQUIRE(r.notes.size() == 1);
    CHECK(r.notes[0].find("could not preserve") != std::string::npos);
}

TEST_CASE("sqlite_quarantine: claim_quarantine_name moves one file and no sidecar",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "x.db";
    write_bytes(db, "main");
    write_bytes(fs::path(db.string() + "-wal"), "wal");

    const auto dest = sq::claim_quarantine_name(db, 77, ".planted-");
    REQUIRE(dest.has_value());
    CHECK(dest->filename().string() == "x.db.planted-77");
    CHECK(read_bytes(*dest) == "main");
    CHECK_FALSE(fs::exists(db));
    CHECK(read_bytes(fs::path(db.string() + "-wal")) == "wal"); // the sidecar stays put
    CHECK_FALSE(fs::exists(fs::path(dest->string() + "-wal")));
}

TEST_CASE("sqlite_quarantine: two claims in the same second never overwrite each other",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "x.db";
    write_bytes(db, "first");
    const auto a = sq::claim_quarantine_name(db, 5, ".corrupt-");
    write_bytes(db, "second");
    const auto b = sq::claim_quarantine_name(db, 5, ".corrupt-");
    write_bytes(db, "third");
    const auto c = sq::claim_quarantine_name(db, -9, ".corrupt-"); // clamps to 0
    REQUIRE((a && b && c));
    CHECK(a->filename().string() == "x.db.corrupt-5");
    CHECK(b->filename().string() == "x.db.corrupt-5-1");
    CHECK(c->filename().string() == "x.db.corrupt-0");
    CHECK(read_bytes(*a) == "first");
    CHECK(read_bytes(*b) == "second");
}

TEST_CASE("sqlite_quarantine: a filesystem without hard links fails the claim closed, naming the cause",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "x.db";
    write_bytes(db, "main");
    sq::FsOps ops;
    ops.link = [](const fs::path&, const fs::path&, std::error_code& ec) {
        ec = std::make_error_code(std::errc::operation_not_permitted); // e.g. FAT
    };
    std::vector<std::string> notes;
    CHECK_FALSE(sq::claim_quarantine_name(db, 5, ".corrupt-", &notes, ops).has_value());
    REQUIRE(notes.size() == 1);
    CHECK(notes[0].find("hard links") != std::string::npos);
    CHECK(read_bytes(db) == "main"); // untouched, and no rename fallback ran
    for (const auto& e : fs::directory_iterator(dir.path))
        CHECK(e.path() == db);
}

TEST_CASE("sqlite_quarantine: when every quarantine name is taken the claim gives up and the file stays",
          "[command_dedup][corruption][quarantine_fs]") {
    // The injected link answers "exists" for every name, so the claim must stop after exactly
    // kMaxClaimAttempts tries (no unbounded loop) and refuse rather than overwrite anything.
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "x.db";
    write_bytes(db, "main");
    int calls = 0;
    sq::FsOps ops;
    ops.link = [&calls](const fs::path&, const fs::path&, std::error_code& ec) {
        ++calls;
        ec = std::make_error_code(std::errc::file_exists);
    };
    std::vector<std::string> notes;
    CHECK_FALSE(sq::claim_quarantine_name(db, 5, ".corrupt-", &notes, ops).has_value());
    CHECK(calls == sq::kMaxClaimAttempts);
    REQUIRE(notes.size() == 1);
    CHECK(notes[0].find("every quarantine name") != std::string::npos);
    CHECK(read_bytes(db) == "main"); // the original is untouched
}

#ifndef _WIN32
TEST_CASE("dedup_quarantine: a dangling symlink on the wanted name is not replaced",
          "[command_dedup][corruption][quarantine_fs]") {
    // exists() FOLLOWS a symlink, so the old check-then-rename saw a dangling link as "free" and
    // rename() would have replaced it. The hard-link claim gets EEXIST and takes the next suffix.
    // This passes ONLY on the hard-link path, so it is what distinguishes it from the fallback.
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    fs::path wanted = db;
    wanted += ".corrupt-1234";
    const auto target = dir.path / "nowhere.txt";
    std::error_code ec;
    fs::create_directories(dir.path, ec);
    REQUIRE_FALSE(ec);
    fs::create_symlink(target, wanted, ec);
    REQUIRE_FALSE(ec);
    write_bytes(db, "corrupt");

    const auto dest = dq::quarantine_corrupt_db(db, 1234).dest;
    REQUIRE(dest.has_value());
    CHECK(dest->filename().string() == "command_dedup.db.corrupt-1234-1");
    CHECK(fs::is_symlink(wanted));        // untouched
    CHECK_FALSE(fs::exists(target));      // nothing was created through it
    CHECK(read_bytes(*dest) == "corrupt");
}

TEST_CASE("dedup_quarantine: when the hard link fails the claim fails closed and nothing moves",
          "[command_dedup][corruption][quarantine_fs]") {
    // link(2) on a DIRECTORY fails with EPERM (not EEXIST), which is the "hard links are unavailable
    // here" arm. There is no check-then-rename fallback any more (it could overwrite evidence), so
    // the claim returns nullopt, names the cause, and the original is untouched.
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    std::error_code ec;
    fs::create_directories(db, ec);
    REQUIRE_FALSE(ec);
    write_bytes(db / "inside.txt", "payload");
    fs::path taken = db;
    taken += ".corrupt-1234";
    write_bytes(taken, "earlier");

    const auto r = dq::quarantine_corrupt_db(db, 1234);
    CHECK_FALSE(r.dest.has_value());
    REQUIRE(r.notes.size() == 1);
    CHECK(r.notes[0].find("hard links") != std::string::npos);
    CHECK(read_bytes(db / "inside.txt") == "payload");
    CHECK(read_bytes(taken) == "earlier");
}

namespace {
// Make every regular-file write fail with EFBIG for the lifetime of the object (SIGXFSZ ignored).
struct FileSizeLimit {
    rlimit saved{};
    void (*old_handler)(int) = SIG_DFL;
    FileSizeLimit() {
        ::getrlimit(RLIMIT_FSIZE, &saved);
        old_handler = std::signal(SIGXFSZ, SIG_IGN);
        rlimit zero = saved;
        zero.rlim_cur = 0;
        ::setrlimit(RLIMIT_FSIZE, &zero);
    }
    ~FileSizeLimit() {
        ::setrlimit(RLIMIT_FSIZE, &saved);
        std::signal(SIGXFSZ, old_handler);
    }
};
} // namespace

TEST_CASE("CommandDedupStore: a fresh store that cannot be created after a quarantine fails open "
          "loudly, keeps the evidence intact and still prunes",
          "[command_dedup][lifecycle][corruption]") {
    // The branch "quarantine succeeded, then the retry failed": history is lost AND the agent is
    // degraded. Chaos CH-3 (#3665).
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    const auto named = [&](const std::string& tail) {
        fs::path f = path;
        f += ".corrupt-" + tail;
        return f;
    };
    for (const char* e : {"1", "2", "3", "4"})
        write_bytes(named(e), std::string("old-") + e);
    write_bytes(path, "garbage main file");

    {
        FileSizeLimit no_writes; // reads, link and unlink still work; creating the schema cannot
        auto result = CommandDedupStore::open(path);
        REQUIRE_FALSE(result.has_value());
        const auto& msg = result.error().message;
        CHECK(msg.find("re-initialised after quarantine") != std::string::npos);
        CHECK(msg.find("history is lost") != std::string::npos);
        CHECK(msg.find(".corrupt-") != std::string::npos); // names the kept file
    }

    // Evidence intact: the quarantine holds the original bytes, prune ran (4 old + 1 new = 5 groups
    // -> the 2 oldest go) even though the retry failed.
    const auto q = quarantine_siblings(path);
    int groups_with_bytes = 0;
    for (const auto& f : q) {
        if (read_bytes(f) == "garbage main file")
            ++groups_with_bytes;
    }
    CHECK(groups_with_bytes == 1);
    CHECK_FALSE(fs::exists(named("1")));
    CHECK_FALSE(fs::exists(named("2")));
    CHECK(fs::exists(named("3")));
    CHECK(fs::exists(named("4")));

    // Once writes work again the next boot opens a healthy store.
    auto next = CommandDedupStore::open(path);
    REQUIRE(next.has_value());
    CHECK(next->claim("cmd-after-recovery").status == ClaimStatus::Claimed);
}
#endif

#ifndef _WIN32
TEST_CASE("dedup_quarantine: a symlink named like a quarantine loses the link, never the target",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "command_dedup.db";
    const auto victim = dir.path / "victim.txt";
    write_bytes(victim, "do not delete");
    fs::path link = db;
    link += ".corrupt-1";
    std::error_code ec;
    fs::create_symlink(victim, link, ec);
    REQUIRE_FALSE(ec);
    for (const char* e : {"2", "3", "4"}) {
        fs::path f = db;
        f += std::string(".corrupt-") + e;
        write_bytes(f, e);
    }
    fs::path newest = db;
    newest += ".corrupt-4";

    dq::prune_old_quarantines(db, newest); // 4 groups -> the oldest (the symlink) goes

    CHECK_FALSE(fs::is_symlink(link));
    CHECK(read_bytes(victim) == "do not delete");
}
#endif

TEST_CASE("dedup_quarantine: prune never throws on a missing directory",
          "[command_dedup][corruption][quarantine_fs]") {
    yuzu::test::TempDir dir{"yuzu_test_cmddedup_qfs_"};
    const auto db = dir.path / "does_not_exist" / "command_dedup.db";
    CHECK_NOTHROW(dq::prune_old_quarantines(db, db.string() + ".corrupt-1"));
}

TEST_CASE("CommandDedupStore: move assignment carries the quarantine record and clears the source",
          "[command_dedup][lifecycle][corruption]") {
    const auto bad = fresh_db_path();
    yuzu::test::TempDbFile bad_guard{bad};
    QuarantineCleanup qc{bad};
    write_bytes(bad, "garbage main file");
    auto recovered = CommandDedupStore::open(bad);
    REQUIRE(recovered.has_value());
    REQUIRE(recovered->quarantined_this_open().has_value());

    const auto good = fresh_db_path();
    yuzu::test::TempDbFile good_guard{good};
    auto healthy = CommandDedupStore::open(good);
    REQUIRE(healthy.has_value());

    *healthy = std::move(*recovered);
    CHECK(healthy->quarantined_this_open().has_value());
    CHECK_FALSE(recovered->quarantined_this_open().has_value());
    CHECK(healthy->claim("cmd-after-move").status == ClaimStatus::Claimed);
}

TEST_CASE("CommandDedupStore: a locked rollback-journal file is BUSY, not corruption",
          "[command_dedup][lifecycle][corruption]") {
    // `PRAGMA journal_mode=WAL` needs an exclusive lock on a rollback-journal file; another
    // connection holding one makes it BUSY. That is transient: the file must be left exactly as
    // found, with its history, and opened normally once the lock is released.
    const auto path = fresh_db_path();
    yuzu::test::TempDbFile guard{path};
    QuarantineCleanup qc{path};
    std::error_code ec;
    fs::create_directories(path.parent_path(), ec);
    REQUIRE_FALSE(ec);

    sqlite3* holder = nullptr;
    REQUIRE(sqlite3_open(path.string().c_str(), &holder) == SQLITE_OK);
    REQUIRE(sqlite3_exec(holder,
                         "PRAGMA journal_mode=DELETE;"
                         "CREATE TABLE command_outcomes (command_id TEXT PRIMARY KEY, state "
                         "INTEGER NOT NULL, response BLOB, claimed_at INTEGER NOT NULL);"
                         "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
                         "INSERT INTO command_outcomes VALUES('cmd-keep', 1, x'00', 0);"
                         "BEGIN EXCLUSIVE;",
                         nullptr, nullptr, nullptr) == SQLITE_OK);
    {
        auto blocked = CommandDedupStore::open(path);
        CHECK_FALSE(blocked.has_value());
        CHECK(quarantine_siblings(path).empty());
        CHECK(fs::exists(path));
    }
    REQUIRE(sqlite3_exec(holder, "COMMIT;", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(holder);

    auto opened = CommandDedupStore::open(path);
    REQUIRE(opened.has_value());
    CHECK_FALSE(opened->quarantined_this_open().has_value());
    CHECK(opened->claim("cmd-keep").status == ClaimStatus::Duplicate); // history intact
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
