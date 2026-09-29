/**
 * test_tar_cursor.cpp -- Unit tests for the TAR cursor-model seam
 * (tar_cursor.hpp): CursorSource lifecycle contract, tar_cursor persistence,
 * pending-queue durability, and the frozen power/removable schema rows.
 *
 * A FakeCursorSource plays the role a wave-2 collector will fill (power /
 * removable): it implements CursorSource directly against a real (ephemeral)
 * TarDatabase, so these tests exercise the actual insert_power_events_and_
 * cursor / get_cursor / generate_warehouse_ddl code paths the seam promises,
 * without depending on tar_plugin.cpp (which owns the driver loop and is
 * translation-unit-local -- see test_tar_capture_status.cpp for the same
 * "fixture collector through the shared contract, not through the plugin"
 * pattern this file follows).
 */

#include "tar_cursor.hpp"
#include "tar_db.hpp"
#include "tar_schema_registry.hpp"
#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sqlite3.h>
#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace yuzu::tar;

// ── Test DB harness (mirrors test_tar_store.cpp's TestTarDb) ────────────────

namespace {

struct TestTarDb {
    TarDatabase db;
    fs::path path;

    ~TestTarDb() {
        { TarDatabase discard = std::move(db); }
        std::error_code ec;
        fs::remove(path, ec);
        fs::remove(fs::path{path.string() + "-wal"}, ec);
        fs::remove(fs::path{path.string() + "-shm"}, ec);
    }
};

TestTarDb make_test_db() {
    auto tmp = yuzu::test::unique_temp_path("yuzu_test_tar_cursor_");
    auto result = TarDatabase::open(tmp);
    REQUIRE(result.has_value());
    return TestTarDb{std::move(*result), tmp};
}

// A fake CursorSource driving the real contract against a real TarDatabase.
// Every collect() call persists its own events+cursor atomically via
// insert_power_events_and_cursor, exactly as a real wave-2 source must --
// this class supplies only the DECISION of what to do each tick, not a
// second, parallel persistence path.
class FakePowerCursorSource final : public CursorSource {
public:
    std::string name() const noexcept override { return "power"; }

    void start(TarDatabase& db) override {
        started_ = true;
        db_at_start_ = &db;
    }

    CursorCollectResult collect(TarDatabase& db,
                                const std::optional<std::string>& cursor_json) override {
        if (throw_incomplete)
            throw IncompleteCaptureError("fake transient read failure");

        if (force_lost) {
            // Rule 2: lost/invalid cursor is NOT an exception -- emit a
            // capture_gap, re-baseline at "now" (never replay-from-zero),
            // persist atomically, return CursorLost.
            PowerEvent gap;
            gap.ts = 100;
            gap.snapshot_id = 1;
            gap.action = "capture_gap";
            gap.detail = "cursor lost (fixture)";
            gap.record_key = next_key();
            const std::string new_cursor = R"({"v":1,"pos":"rebaselined"})";
            // Rule 3: a failed persist THROWS. Returning an outcome here would
            // report a clean tick while nothing was written -- the exact shape
            // the contract names. This fake is the only CursorSource in the
            // tree and a consumer author will copy it, so it must obey the
            // contract it demonstrates.
            if (auto r = db.insert_power_events_and_cursor({gap}, new_cursor); !r)
                throw IncompleteCaptureError("fixture: gap persist failed");
            return {new_cursor, std::size_t{1}, CursorOutcome::CursorLost, "lost"};
        }

        PowerEvent ev;
        ev.ts = 200;
        ev.snapshot_id = 1;
        ev.action = "wake";
        ev.record_key = next_key();
        const std::string new_cursor = R"({"v":1,"pos":"advanced"})";
        if (auto r = db.insert_power_events_and_cursor({ev}, new_cursor); !r)
            throw IncompleteCaptureError("fixture: event persist failed");
        const auto outcome = cursor_json.has_value() ? CursorOutcome::Advanced
                                                     : CursorOutcome::Baseline;
        return {new_cursor, std::size_t{1}, outcome, ""};
    }

    void stop() noexcept override {
        stopped_ = true;
        // Lifecycle ordering assertion (P-002): a correct driver calls
        // stop() on every source BEFORE tearing down the database, so the
        // database must still be open right now.
        db_open_at_stop_ = db_at_start_ != nullptr && db_at_start_->is_open();
    }

    void on_enabled_changed(bool enabled) override {
        if (!enabled) {
            // disable: drain-and-DISCARD the paused-window queue.
            pending_.discard_all();
            saw_disable_ = true;
        } else {
            // re-enable: re-baseline forward, never replay the disabled
            // window's own events.
            saw_reenable_ = true;
        }
    }

    bool throw_incomplete{false};
    bool force_lost{false};
    bool started_{false};
    bool stopped_{false};
    bool db_open_at_stop_{false};
    bool saw_disable_{false};
    bool saw_reenable_{false};
    BoundedPendingQueue<PowerEvent> pending_;
    TarDatabase* db_at_start_{nullptr};

private:
    std::string next_key() { return "power-fixture-" + std::to_string(++counter_); }
    int counter_{0};
};

} // namespace

// ── tar_cursor persistence: round trip ───────────────────────────────────────

// get_cursor() is tri-state: a read FAILURE is an error, distinct from "no row"
// (C2). Every assertion below is about a successful read, so this helper
// asserts that much and unwraps -- a test that silently accepted an error as
// "no cursor" would be asserting the exact confusion C2 removed.
static std::optional<std::string> read_cursor(yuzu::tar::TarDatabase& db,
                                              const std::string& source) {
    auto r = db.get_cursor(source);
    REQUIRE(r.has_value());
    return *r;
}

TEST_CASE("TarDatabase: get_cursor returns nullopt before any cursor is persisted",
          "[tar][cursor]") {
    auto t = make_test_db();
    CHECK_FALSE(read_cursor(t.db, "power").has_value());
}

TEST_CASE("TarDatabase: a cursor READ FAILURE is an error, never mistaken for 'never persisted' "
          "(C2)",
          "[tar][cursor][c2]") {
    // The whole point of the tri-state. If a failed read returned nullopt, the
    // driver would hand that to collect(), the source would treat the tick as a
    // first-ever baseline and commit the CURRENT log position -- silently
    // skipping every event between the durable cursor and now, and emitting no
    // capture_gap, because nothing in the chain ever knew a cursor existed.
    auto t = make_test_db();
    REQUIRE(t.db.insert_power_events_and_cursor({}, R"({"v":1,"pos":10})"));
    {
        auto ok = t.db.get_cursor("power");
        REQUIRE(ok.has_value());
        REQUIRE(ok->has_value());
        CHECK(**ok == R"({"v":1,"pos":10})");
    }

    // Break the read out from under it, on a SECOND raw connection to the same
    // file (the test_kv_store.cpp pattern) so the TarDatabase handle is
    // untouched and the failure is a genuine one at prepare time.
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(t.path.string().c_str(), &raw) == SQLITE_OK);
    REQUIRE(sqlite3_exec(raw, "DROP TABLE tar_cursor", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(raw);

    auto broken = t.db.get_cursor("power");
    REQUIRE_FALSE(broken.has_value());          // an ERROR ...
    CHECK_FALSE(broken.error().empty());        // ... that says what went wrong
}

TEST_CASE("TarDatabase: insert_power_events_and_cursor persists the cursor even with zero events",
          "[tar][cursor]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_power_events_and_cursor({}, R"({"v":1,"pos":10})"));
    auto c = read_cursor(t.db, "power");
    REQUIRE(c.has_value());
    CHECK(*c == R"({"v":1,"pos":10})");
}

TEST_CASE("TarDatabase: a record_key COLLISION is refused, while an exact replay still dedupes "
          "(C1)",
          "[tar][cursor][c1]") {
    // INSERT OR IGNORE cannot, by itself, tell a legitimate replay from a
    // collision: both are "a row with this key already exists". Accepting a
    // collision would commit the cursor past an event that was never stored --
    // forensic loss reported as a clean tick. Only an exact payload match is a
    // replay.
    auto t = make_test_db();

    PowerEvent a;
    a.ts = 100;
    a.snapshot_id = 1;
    a.action = "sleep";
    a.detail = "lid";
    a.record_key = "winpower:sw:0";

    REQUIRE(t.db.insert_power_events_and_cursor({a}, R"({"v":1,"pos":1})"));

    // Exact replay: the same OS record re-offered after a failed commit. This
    // MUST still succeed, or every ordinary retry would wedge the source.
    CHECK(t.db.insert_power_events_and_cursor({a}, R"({"v":1,"pos":2})"));

    // Collision: a DIFFERENT event that derived the same key -- exactly what a
    // process-local counter reset produces on an agent restart.
    PowerEvent b = a;
    b.ts = 900;
    b.action = "wake";
    CHECK_FALSE(t.db.insert_power_events_and_cursor({b}, R"({"v":1,"pos":3})"));

    // ... and because the batch failed, the cursor did NOT advance past it.
    auto c = read_cursor(t.db, "power");
    REQUIRE(c.has_value());
    CHECK(*c == R"({"v":1,"pos":2})");
}

TEST_CASE("TarDatabase: a capture_gap retried on a later tick still dedupes, and a real "
          "transition's timestamp still discriminates (CDX-04)",
          "[tar][cursor][c1][cdx04]") {
    // The collision check must not mistake an ordinary RETRY for a collision.
    // snapshot_id is minted fresh every tick, and a capture_gap's ts is only
    // "when we noticed" -- a gap's identity is the window encoded in its
    // record_key. Comparing either would wedge a source that is retrying an
    // unclosed gap: every attempt would collide, the queue would never ack, and
    // the gap could never be closed.
    auto t = make_test_db();

    PowerEvent gap;
    gap.ts = 100;
    gap.snapshot_id = 1;
    gap.action = "capture_gap";
    gap.detail = "power subscription restarted -- window 900..now";
    gap.record_key = "winpower:restart:900";
    REQUIRE(t.db.insert_power_events_and_cursor({gap}, R"({"v":1,"pos":1})"));

    // Tick 2: the same gap, still unclosed. New tick => new snapshot_id, and
    // "now" has moved on. It is the SAME gap and must commit.
    PowerEvent retry = gap;
    retry.ts = 250;
    retry.snapshot_id = 2;
    CHECK(t.db.insert_power_events_and_cursor({retry}, R"({"v":1,"pos":2})"));

    // A REAL transition, by contrast, is identified by its timestamp: two
    // different sleeps sharing a key is the restart-collision class, and it
    // must still be refused.
    PowerEvent sleep1;
    sleep1.ts = 500;
    sleep1.snapshot_id = 3;
    sleep1.action = "sleep";
    sleep1.detail = "lid";
    sleep1.record_key = "winpower:sw:0";
    REQUIRE(t.db.insert_power_events_and_cursor({sleep1}, R"({"v":1,"pos":3})"));

    PowerEvent sleep2 = sleep1;
    sleep2.ts = 9000;      // a DIFFERENT sleep ...
    sleep2.snapshot_id = 4; // ... whose key collided after a restart
    CHECK_FALSE(t.db.insert_power_events_and_cursor({sleep2}, R"({"v":1,"pos":4})"));

    auto c = read_cursor(t.db, "power");
    REQUIRE(c.has_value());
    CHECK(*c == R"({"v":1,"pos":3})");
}

TEST_CASE("TarDatabase: insert_removable_events_and_cursor round-trips events + cursor together",
          "[tar][cursor]") {
    auto t = make_test_db();
    RemovableEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "attached";
    ev.device_key = "usb-0001";
    ev.vendor = "Acme";
    ev.product = "Widget";
    ev.serial = "SN1";
    ev.bus = "usb";
    ev.volume = "E:";
    ev.size_bytes = 1024;
    ev.image_path = "";
    ev.pid = 0;
    ev.evidence = "{}";
    ev.record_key = "rm-1";

    REQUIRE(t.db.insert_removable_events_and_cursor({ev}, R"({"v":1})"));
    auto res = t.db.execute_query("SELECT COUNT(*) FROM removable_live");
    REQUIRE(res.has_value());
    CHECK(res->rows[0][0] == "1");
    CHECK(read_cursor(t.db, "removable") == std::string(R"({"v":1})"));
}

// ── Replay idempotence via UNIQUE record_key ────────────────────────────────

TEST_CASE("power_live: duplicate record_key is a no-op (row count unchanged), cursor still advances",
          "[tar][cursor]") {
    auto t = make_test_db();
    PowerEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "wake";
    ev.record_key = "dup-1";

    REQUIRE(t.db.insert_power_events_and_cursor({ev}, R"({"v":1})"));
    // Replay the SAME event (e.g. a cursor re-read from a slightly earlier
    // position) -- record_key's UNIQUE index makes this a silent no-op, not
    // a duplicate row (tar_cursor.hpp rule 3).
    REQUIRE(t.db.insert_power_events_and_cursor({ev}, R"({"v":2})"));

    auto res = t.db.execute_query("SELECT COUNT(*) FROM power_live");
    REQUIRE(res.has_value());
    CHECK(res->rows[0][0] == "1");
    // The cursor itself is NOT gated by record_key idempotence -- it still
    // advances to whatever the (idempotent) tick reports.
    CHECK(read_cursor(t.db, "power") == std::string(R"({"v":2})"));
}

// ── Atomic commit/rollback ───────────────────────────────────────────────────

TEST_CASE("the lookback privacy control fails CLOSED: unreadable means forward-only, never the "
          "default",
          "[tar][cursor][lookback]") {
    // get_config returns the supplied default for BOTH "unset" and "unreadable",
    // so reading the lookback naively turns a transient SQLite failure into a
    // 7-day retrospective read on a host where the operator set 0 precisely
    // because such a read is not lawful there -- a privacy control failing OPEN.
    auto t = make_test_db();

    // Genuinely absent -> the documented default applies.
    CHECK(lookback_seconds_or_forward_only(t.db, "power", 604800) == 604800);

    // Explicitly stored -> honoured, including the operator's forward-only 0.
    REQUIRE(t.db.set_config("power_lookback_seconds", "0"));
    CHECK(lookback_seconds_or_forward_only(t.db, "power", 604800) == 0);

    REQUIRE(t.db.set_config("power_lookback_seconds", "3600"));
    CHECK(lookback_seconds_or_forward_only(t.db, "power", 604800) == 3600);

    // Unreadable (the config table is gone) -> 0, NOT the 7-day default. This is
    // the assertion that matters: the naive get_config(key, default) shape
    // returns 604800 here.
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open(t.path.string().c_str(), &raw) == SQLITE_OK);
    REQUIRE(sqlite3_exec(raw, "DROP TABLE tar_config", nullptr, nullptr, nullptr) == SQLITE_OK);
    sqlite3_close(raw);
    CHECK(lookback_seconds_or_forward_only(t.db, "power", 604800) == 0);
}

TEST_CASE("an embedded NUL cannot silently truncate a persisted field or collapse two keys",
          "[tar][cursor][nul]") {
    // sqlite3_bind_text with length -1 stops at the first NUL. Two consequences,
    // both silent: a record_key of "\0a" is NON-empty in C++ so it passes the
    // empty-key guard, yet binds as zero-length -- so "\0a" and "\0b" become one
    // row; and a stored-then-truncated `detail` no longer equals the value
    // re-offered on a retry, so the payload compare fails and the source is
    // refused forever. Fixed-width USB string descriptors and EvtRender buffers
    // both produce embedded NULs in practice.
    auto t = make_test_db();

    PowerEvent a;
    a.ts = 1;
    a.snapshot_id = 1;
    a.action = "sleep";
    a.record_key = std::string("\0a", 2);
    CHECK_FALSE(t.db.insert_power_events_and_cursor({a}, R"({"v":1})"));

    // A NUL inside an ordinary payload field must round-trip intact, or the
    // replay comparison refuses the event on every later tick.
    PowerEvent b;
    b.ts = 2;
    b.snapshot_id = 1;
    b.action = "wake";
    b.detail = std::string("head\0tail", 9);
    b.record_key = "nul-detail";
    REQUIRE(t.db.insert_power_events_and_cursor({b}, R"({"v":1,"pos":1})"));

    // Re-offering the identical event is a replay and MUST be accepted; if the
    // stored `detail` had been truncated at the NUL it would now mismatch and
    // be refused as a collision.
    CHECK(t.db.insert_power_events_and_cursor({b}, R"({"v":1,"pos":2})"));
}

TEST_CASE("a mid-batch refusal rolls back the events that ALREADY inserted, not just the cursor "
          "(observes the transaction, not its absence)",
          "[tar][cursor][atomicity]") {
    // The sibling tests below force the FIRST statement to fail by dropping the
    // table, so nothing ever inserts and the cursor write never runs -- they
    // pass with no transaction at all and cannot observe a rollback. This one
    // can: a good event inserts, a colliding one is refused mid-loop, and the
    // good row must be GONE afterwards. Replacing ROLLBACK with COMMIT fails
    // exactly here.
    auto t = make_test_db();

    PowerEvent seed;
    seed.ts = 100;
    seed.snapshot_id = 1;
    seed.action = "sleep";
    seed.detail = "lid";
    seed.record_key = "collide";
    REQUIRE(t.db.insert_power_events_and_cursor({seed}, R"({"v":1,"pos":1})"));

    PowerEvent good;
    good.ts = 200;
    good.snapshot_id = 2;
    good.action = "wake";
    good.record_key = "good-row";

    PowerEvent collides = seed;      // same key ...
    collides.ts = 900;               // ... different payload => refused
    collides.snapshot_id = 2;

    CHECK_FALSE(t.db.insert_power_events_and_cursor({good, collides}, R"({"v":1,"pos":2})"));

    // `good` inserted before the refusal. If the transaction did not roll back
    // it would still be here -- a forensic row from a batch the store told the
    // caller it had REJECTED.
    auto rows = t.db.execute_query("SELECT COUNT(*) FROM power_live WHERE record_key = 'good-row'");
    REQUIRE(rows.has_value());
    CHECK(rows->rows[0][0] == "0");

    // ... and the cursor did not advance either.
    auto c = read_cursor(t.db, "power");
    REQUIRE(c.has_value());
    CHECK(*c == R"({"v":1,"pos":1})");
}

TEST_CASE("insert_power_events_and_cursor rolls back the cursor when the event insert fails",
          "[tar][cursor]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_power_events_and_cursor({}, R"({"v":1})"));

    // Force the event-insert half of the transaction to fail deterministically.
    REQUIRE(t.db.execute_sql("DROP TABLE power_live"));

    PowerEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "sleep";
    ev.record_key = "will-not-land";
    CHECK_FALSE(t.db.insert_power_events_and_cursor({ev}, R"({"v":2})"));

    // Narrow by construction: the table is gone, so the FIRST statement fails
    // and nothing was inserted to roll back. This shows the cursor is not
    // written when the events cannot be -- the rollback itself is observed by
    // the mid-batch-refusal test above.
    CHECK(read_cursor(t.db, "power") == std::string(R"({"v":1})"));
}

TEST_CASE("insert_removable_events_and_cursor rolls back the cursor when the event insert fails",
          "[tar][cursor]") {
    auto t = make_test_db();
    REQUIRE(t.db.insert_removable_events_and_cursor({}, R"({"v":1})"));
    REQUIRE(t.db.execute_sql("DROP TABLE removable_live"));

    RemovableEvent ev;
    ev.ts = 1;
    ev.snapshot_id = 1;
    ev.action = "detached";
    ev.record_key = "will-not-land";
    CHECK_FALSE(t.db.insert_removable_events_and_cursor({ev}, R"({"v":2})"));
    CHECK(read_cursor(t.db, "removable") == std::string(R"({"v":1})"));
}

// ── Generated DDL ─────────────────────────────────────────────────────────────

TEST_CASE("TAR warehouse DDL: power_live and removable_live carry a record_key UNIQUE index",
          "[tar][cursor][warehouse]") {
    auto ddl = generate_warehouse_ddl();
    CHECK(ddl.find("CREATE UNIQUE INDEX IF NOT EXISTS power_live_record_key_uq "
                   "ON power_live(record_key);") != std::string::npos);
    CHECK(ddl.find("CREATE UNIQUE INDEX IF NOT EXISTS removable_live_record_key_uq "
                   "ON removable_live(record_key);") != std::string::npos);
}

// ── Frozen schema-registry rows ─────────────────────────────────────────────

TEST_CASE("TAR schema registry: power and removable default to ENABLED, live-tier-only",
          "[tar][cursor][registry]") {
    bool saw_power = false, saw_removable = false;
    for (const auto& src : capture_sources()) {
        if (src.name != "power" && src.name != "removable")
            continue;
        if (src.name == "power")
            saw_power = true;
        else
            saw_removable = true;

        // ALEX RULING 2026-09-04: the first two default-ON sources.
        CHECK(src.default_enabled);
        CHECK(src.unique_key_column == "record_key");
        REQUIRE(src.granularities.size() == 1);
        CHECK(src.granularities.front().suffix == "live");
    }
    CHECK(saw_power);
    CHECK(saw_removable);
}

// ── Fake CursorSource driver semantics ──────────────────────────────────────

TEST_CASE("CursorSource contract: a successful collect persists events + cursor atomically",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    CHECK(src.started_);

    auto result = src.collect(t.db, std::nullopt);
    CHECK(result.outcome == CursorOutcome::Baseline);
    CHECK(result.events_emitted == 1);
    CHECK(read_cursor(t.db, "power") == result.new_cursor_json);

    // A second tick with a prior cursor present reports Advanced.
    auto result2 = src.collect(t.db, read_cursor(t.db, "power"));
    CHECK(result2.outcome == CursorOutcome::Advanced);
}

TEST_CASE("CursorSource contract: IncompleteCaptureError leaves the persisted cursor untouched",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    auto seed = src.collect(t.db, std::nullopt);
    REQUIRE(read_cursor(t.db, "power") == seed.new_cursor_json);

    // Rule 1: a transient failure throws rather than returning a result --
    // the driver (simulated here directly) must not call any persist path
    // on this branch, so the cursor is exactly what it was before.
    src.throw_incomplete = true;
    const auto cursor_before = read_cursor(t.db, "power");
    REQUIRE_THROWS_AS(src.collect(t.db, cursor_before), IncompleteCaptureError);
    CHECK(read_cursor(t.db, "power") == cursor_before);
}

TEST_CASE("CursorSource contract: CursorLost emits a capture_gap and re-baselines forward",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    src.force_lost = true;

    auto result = src.collect(t.db, R"({"v":1,"pos":"stale-behind-a-wrapped-log"})");
    CHECK(result.outcome == CursorOutcome::CursorLost);

    auto res = t.db.execute_query("SELECT action FROM power_live WHERE action = 'capture_gap'");
    REQUIRE(res.has_value());
    CHECK(res->rows.size() == 1);
    // Re-baselined at "now", never replay-from-zero -- the new cursor is
    // exactly what this tick persisted, not derived from the stale input.
    CHECK(read_cursor(t.db, "power") == result.new_cursor_json);
}

TEST_CASE("CursorSource lifecycle: stop() runs while the database is still open",
          "[tar][cursor][lifecycle]") {
    auto t = make_test_db();
    FakePowerCursorSource src;
    src.start(t.db);
    REQUIRE(t.db.is_open());

    src.stop(); // simulates shutdown()'s ordering: stop() BEFORE db_.reset()
    CHECK(src.stopped_);
    CHECK(src.db_open_at_stop_);
}

TEST_CASE("CursorSource lifecycle: on_enabled_changed(false) discards the paused window",
          "[tar][cursor][lifecycle]") {
    FakePowerCursorSource src;
    PowerEvent buffered;
    buffered.action = "wake";
    buffered.record_key = "buffered-during-pause";
    src.pending_.push(buffered);
    REQUIRE(src.pending_.size() == 1);

    src.on_enabled_changed(false);
    CHECK(src.saw_disable_);
    // Nothing from the paused window survives -- discard, not overflow.
    CHECK(src.pending_.size() == 0);
    CHECK(src.pending_.dropped() == 0);
}

TEST_CASE("CursorSource lifecycle: on_enabled_changed(true) signals a re-baseline, not a replay",
          "[tar][cursor][lifecycle]") {
    FakePowerCursorSource src;
    src.on_enabled_changed(true);
    CHECK(src.saw_reenable_);
}

// ── BoundedPendingQueue (P-003 subscription durability) ─────────────────────

TEST_CASE("BoundedPendingQueue: a failed insert leaves entries unacked; a retry commits them "
          "exactly once",
          "[tar][cursor][queue]") {
    BoundedPendingQueue<int> q;
    q.push(1);
    q.push(2);
    q.push(3);

    auto batch = q.snapshot_batch();
    REQUIRE(batch.items.size() == 3);

    // Simulated failed insert: do NOT ack -- the batch must still be there
    // for the next tick's retry.
    CHECK(q.snapshot_batch().items.size() == 3);

    // Simulated successful insert: ack through the batch's own last sequence.
    q.ack_through(batch.last_seq);
    CHECK(q.snapshot_batch().items.empty());

    // Re-acking the same sequence, with nothing new pushed, is a safe no-op.
    q.ack_through(batch.last_seq);
    CHECK(q.snapshot_batch().items.empty());
}

TEST_CASE("BoundedPendingQueue: an overflow eviction BETWEEN snapshot and ack cannot destroy an "
          "uncommitted entry -- the R-005 regression, deterministic and single-threaded",
          "[tar][cursor][queue][r005]") {
    // The defect this pins: with the queue full, ack-by-COUNT erased N entries
    // from the front. An eviction landing between snapshot_batch() and the ack
    // shifts every index by one, so the Nth erased entry is one the batch never
    // contained -- destroyed without ever being committed, while the drop was
    // charged to an entry that DID commit. Ack-by-sequence cannot do that,
    // because a sequence number identifies an entry rather than a position.
    BoundedPendingQueue<int> q;
    constexpr std::size_t kCap = BoundedPendingQueue<int>::kCap;

    for (std::size_t i = 0; i < kCap; ++i)
        q.push(static_cast<int>(i));
    REQUIRE(q.size() == kCap);

    // The collect() tick snapshots the full queue and begins its transaction.
    const auto batch = q.snapshot_batch();
    REQUIRE(batch.items.size() == kCap);
    REQUIRE(batch.items.front() == 0);

    // While that transaction is in flight, a callback fires. The queue is full,
    // so the push evicts the OLDEST entry -- which is inside the batch, and is
    // about to commit -- and appends an entry the batch does NOT contain.
    const int kUncommitted = 999999;
    q.push(kUncommitted);
    REQUIRE(q.size() == kCap);

    // The transaction commits. Ack through the sequence the batch reported.
    q.ack_through(batch.last_seq);

    // The entry pushed after the snapshot MUST survive: it was never committed,
    // so acking the batch must not have removed it. Under positional ack(kCap)
    // this assertion fails -- the erase would have consumed it.
    const auto after = q.snapshot_batch();
    REQUIRE(after.items.size() == 1);
    CHECK(after.items.front() == kUncommitted);
}

TEST_CASE("BoundedPendingQueue: overflow drops the OLDEST entry and counts it cumulatively",
          "[tar][cursor][queue]") {
    BoundedPendingQueue<int> q;
    constexpr std::size_t kOverBy = 5;
    for (std::size_t i = 0; i < BoundedPendingQueue<int>::kCap + kOverBy; ++i)
        q.push(static_cast<int>(i));

    CHECK(q.size() == BoundedPendingQueue<int>::kCap);
    CHECK(q.dropped() == kOverBy);

    auto batch = q.snapshot_batch();
    REQUIRE_FALSE(batch.items.empty());
    // The oldest kOverBy entries (0..kOverBy-1) were dropped -- the front of
    // the queue is now entry kOverBy, not 0.
    CHECK(batch.items.front() == static_cast<int>(kOverBy));
}

TEST_CASE("BoundedPendingQueue: the dropped count surfaces in the next capture_gap event",
          "[tar][cursor][queue]") {
    auto t = make_test_db();
    BoundedPendingQueue<PowerEvent> q;
    constexpr std::size_t kOverBy = 3;
    for (std::size_t i = 0; i < BoundedPendingQueue<PowerEvent>::kCap + kOverBy; ++i) {
        PowerEvent ev;
        ev.record_key = "q-" + std::to_string(i);
        q.push(ev);
    }
    REQUIRE(q.dropped() == kOverBy);

    PowerEvent gap;
    gap.ts = 1;
    gap.snapshot_id = 1;
    gap.action = "capture_gap";
    gap.detail = "dropped=" + std::to_string(q.dropped());
    gap.record_key = "gap-for-overflow";
    REQUIRE(t.db.insert_power_events_and_cursor({gap}, R"({"v":1})"));

    auto res = t.db.execute_query("SELECT detail FROM power_live WHERE action = 'capture_gap'");
    REQUIRE(res.has_value());
    REQUIRE(res->rows.size() == 1);
    CHECK(res->rows[0][0] == "dropped=3");
}
