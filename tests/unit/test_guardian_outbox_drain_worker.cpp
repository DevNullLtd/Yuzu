// test_guardian_outbox_drain_worker.cpp - the live-drain worker (ADR-0021 rung
// 7, F6). Drives it against a real GuardianSparkRuntime (fake reader/backend,
// matching the runtime's own test style) with a short periodic bound so the
// backstop-poll path is exercisable in test time too.

#include "guardian_outbox_drain_worker.hpp"

#include "guardian_joined_thread_role.hpp"
#include "guardian_lifecycle_journal.hpp"

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/spark.hpp>

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::agent;
using namespace std::chrono_literals;

namespace {

struct FakeReader : IStateReader {
    ReadResult<FileSnapshot> file{read_known(FileSnapshot{.exists = true})};
    ReadResult<FileSnapshot> read_file(const FileSparkParams&, const FileReadPlan&) override {
        return file;
    }
    RegistryRead read_registry(const RegistrySparkParams&, const RegistryReadPlan&) override {
        return {};
    }
    ReadResult<ServiceRunState> read_service(const ServiceSparkParams&) override {
        return read_known(ServiceRunState::Running);
    }
    void request_stop() noexcept override {}
};

struct FakeBackend : ISparkBackend {
    std::atomic<std::uint64_t> next{1};
    std::expected<std::uint64_t, std::string> arm(const SparkSpec&) override {
        return next.fetch_add(1);
    }
    void disarm(std::uint64_t) override {}
};

RuleAssertion file_exists_rule(const std::string& rule_id) {
    RuleAssertion a;
    a.kind = AssertionKind::FileExists;
    a.rule_id = rule_id;
    a.expect_present = true;
    return a;
}

SparkSpec file_spec(const std::string& path) {
    return SparkSpec{SparkType::File, FileSparkParams{path}};
}

// A collecting, always-Sent fake send_fn - the worker's own mechanics are
// under test here, not any real wire serialization (that's rung 7.7's job).
struct CollectingSink {
    std::mutex mu;
    std::vector<OutboxEntry> sent;
    SendResult operator()(const OutboxEntry& e) {
        std::lock_guard<std::mutex> lk{mu};
        sent.push_back(e);
        return SendResult::Sent;
    }
    std::size_t count() {
        std::lock_guard<std::mutex> lk{mu};
        return sent.size();
    }
};

// spin_until / kSpinScale promoted to yuzu::test (test_helpers.hpp) — #2238, CON-S4
// promote-at-second-user. Brought into this anonymous namespace's lookup so every
// unqualified call site below keeps working unchanged.
using yuzu::test::kSpinScale;
using yuzu::test::spin_until;

// A real KvStore + durable journal alongside the runtime, for the C0 (#2298)
// maintenance-on-the-worker cases: prune + page now run HERE, not on the
// heartbeat / reconnect threads.
/// Wall clock in ms, matching the journal's retention basis. Tests that page need a
/// now_ms consistent with the ts_ms the rig persists.
inline std::int64_t journal_now_ms_for_test() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

struct JournalRig {
    yuzu::test::TempDbFile db{"yuzu_test_drainmaint-"};
    std::unique_ptr<KvStore> kv;
    std::shared_ptr<FakeReader> reader; ///< kept so a test can flip verdicts (compliance traffic)
    std::shared_ptr<GuardianSparkRuntime> rt;
    std::shared_ptr<GuardianLifecycleJournal> journal;
    /// `outbox_capacity` 0 = the production default (4096). NOTE: the lifecycle window is
    /// FLOORED at kMaxJournalEntriesPerBatch, so any smaller value is clamped UP to 256 and
    /// logs that it did. Passing a small number therefore does NOT make the headroom branch
    /// reachable - a test that needs headroom to bind must fill the window to near its real
    /// capacity and REQUIRE the headroom it expects. Getting this wrong is not a loud failure:
    /// it silently makes the test vacuous, which is how the head-of-line guard below spent a
    /// round asserting nothing (#2345 Gate 4 consistency).
    explicit JournalRig(std::size_t outbox_capacity = 0) {
        auto r = KvStore::open(db.path);
        REQUIRE(r.has_value());
        kv = std::make_unique<KvStore>(std::move(*r));
        reader = std::make_shared<FakeReader>();
        if (outbox_capacity > 0) {
            GuardianSparkRuntime::Config cfg;
            cfg.outbox_capacity = outbox_capacity;
            rt = std::make_shared<GuardianSparkRuntime>(reader, std::make_shared<FakeBackend>(),
                                                        cfg, RuntimeClock{});
        } else {
            rt = std::make_shared<GuardianSparkRuntime>(reader, std::make_shared<FakeBackend>());
        }
        journal = std::make_shared<GuardianLifecycleJournal>(kv.get());
    }

    /// Persist ONE durable batch containing `n` records - the multi-entry shape the headroom
    /// gate actually keys off (it is all-or-nothing per batch).
    void persist_batch(const std::string& tag, std::size_t n) {
        std::vector<std::shared_ptr<const JournalRecord>> pending;
        pending.reserve(n);
        for (std::size_t i = 0; i < n; ++i)
            pending.push_back(std::make_shared<const JournalRecord>(JournalRecord{
                .rule_id = tag + "-" + std::to_string(i), .generation = 1,
                .event_id = "e-" + tag + "-" + std::to_string(i),
                .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                .guard_type = "file", .rule_name = "n"}));
        REQUIRE(journal->persist(pending, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == n);
    }
    /// Persist one record as its own durable batch (one persist call = one batch key),
    /// WITHOUT going through the runtime - so the only way it can reach the send window
    /// is the worker's paging pass.
    void persist(const std::string& rule) {
        std::vector<std::shared_ptr<const JournalRecord>> pending{
            std::make_shared<const JournalRecord>(
                JournalRecord{.rule_id = rule, .generation = 1, .event_id = "e-" + rule,
                              .enqueued_ns = 1'700'000'000'000'000'000, .kind = "armed",
                              .guard_type = "file", .rule_name = "n"})};
        REQUIRE(journal->persist(pending, nullptr, kJournalPersistUnbounded, kJournalPersistUnbounded) == 1);
    }
};

} // namespace

TEST_CASE("drain_once sends everything currently pending", "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
    worker.drain_once();

    CHECK(sink.count() == 1); // the "armed" lifecycle entry from attach_rule
}

TEST_CASE("worker survives + counts a throwing send (item 4 hardening)",
          "[spark][guardian][drain]") {
    // A send that throws (e.g. a bad_alloc serializing an entry) must NOT terminate the
    // bare worker thread - which would abort the whole agent (#2037 class). drain_log_
    // unlocked catches the send throw (counting send_exception_count, retaining the head);
    // the entry drains once the send stops throwing. (The worker's own drain_exception_
    // count is a further backstop for a throw in the drain MACHINERY - front_copy/
    // pop_front_if bad_alloc - which needs an allocation-fault seam to exercise; covered by
    // review, not this test.)
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);

    std::atomic<int> throws_left{2};
    std::atomic<bool> drained{false};
    auto sink = [&](const OutboxEntry&) -> SendResult {
        if (throws_left.fetch_sub(1) > 0)
            throw std::runtime_error("send boom");
        drained = true;
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rt, sink, /*periodic_bound_ms=*/20); // fast retry
    worker.start();
    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // enqueues "armed"

    // Reaching here at all proves the worker thread did not terminate on the throws.
    REQUIRE(spin_until([&] { return drained.load(); }, 3s));
    CHECK(rt->send_exception_count() >= 1); // the send throws were counted, not silent
    worker.stop();
}

TEST_CASE("start()/stop() wake promptly on a fresh enqueue, not waiting for the periodic bound",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);

    CollectingSink sink;
    // A long periodic bound - if the wake-on-enqueue path is broken, this test
    // times out waiting for the (nonexistent, since we assert well before the
    // bound) backstop poll rather than failing fast.
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink), /*periodic_bound_ms=*/60'000);
    worker.start();

    rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(spin_until([&] { return sink.count() >= 1; }, 2s));

    worker.stop();
}

TEST_CASE("the periodic bound drains even without an explicit enqueue-wake",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink), /*periodic_bound_ms=*/20);
    worker.start();
    // Let the boot cycle (which runs WITHOUT waiting) complete first. Attaching before
    // start() - as this test used to - no longer exercises the backstop at all, because that
    // first cycle drains the entry before any timeout elapses (#2298 Sol review).
    CHECK(spin_until([&] { return worker.drain_exception_count() == 0; }, 1s));
    std::this_thread::sleep_for(60ms); // >= 2 periodic bounds: the boot cycle is long done

    // try_page_batch is the one enqueue path that deliberately does NOT fire the waker, so
    // an entry placed this way can ONLY be shipped by the periodic backstop poll.
    std::vector<OutboxEntry> batch;
    batch.push_back(OutboxEntry::lifecycle("r1", 1, "e-backstop", 1'700'000'000'000'000'000,
                                           "armed", "file", "n"));
    REQUIRE(rt->try_page_batch(std::move(batch)).added == 1);
    CHECK(sink.count() == 0); // nothing woke the worker

    REQUIRE(spin_until([&] { return sink.count() >= 1; }, 2s)); // the backstop did
    worker.stop();
}

TEST_CASE("#3953 item 6: stop() closes both lane executors before publishing sig_->stopping "
          "does not admit a send in the gap",
          "[spark][guardian][drain][chaos]") {
    // Never start()ed: offer()'s one-caller contract holds on THIS test thread, so
    // calling wrapped_send_for_test() directly from inside the hook is deterministic -
    // no real thread scheduling involved, matching the send_executor file's own
    // pre_launch_race_hook_for_test_ pattern.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    std::atomic<int> invocations{0};
    auto sink = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rt, sink);

    auto entry = OutboxEntry::lifecycle("r1", 1, "e1", 1'700'000'000'000'000'000, "armed");
    std::optional<SendResult> observed;
    worker.set_stop_race_hook_for_test(
        [&] { observed = worker.wrapped_send_for_test(entry); });

    worker.stop();

    REQUIRE(observed.has_value());
    CHECK(*observed == SendResult::Retain);
    CHECK(invocations.load() == 0);
    // On TODAY's order this test's own admitted send launches a REAL detached thread
    // (the executor hasn't been told to stop yet when the hook fires) - spin_until,
    // don't assert active_send_workers()==0 synchronously: a real worker is in
    // flight, only its eventual thread-exit decrement makes the count read 0.
    CHECK(spin_until([&] { return worker.active_send_workers() == 0; }, 3s));
}

TEST_CASE("#3953 item 6 follow-up: the gap BETWEEN the two lane executors' own stop() "
          "calls still admits a compliance send after lifecycle already refuses",
          "[spark][guardian][drain][chaos]") {
    // Governance Gate 4 unhappy-path (UP-4): stop() calls lifecycle_send_exec_.stop()
    // THEN compliance_send_exec_.stop() - a real, tolerated (per the orphan-exit
    // contract) admission window exists between the two calls, and nothing previously
    // exercised it in isolation. Never start()ed: offer()'s one-caller contract holds
    // on THIS test thread.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    std::atomic<int> compliance_invocations{0};
    std::atomic<int> lifecycle_invocations{0};
    auto sink = [&](const OutboxEntry& e) -> SendResult {
        // Sent, not Retain: wrapped_send()'s .value_or(Retain) makes Retain ambiguous
        // between "refused" and "sent but retained" - Sent disambiguates admission.
        if (e.domain == OutboxDomain::Lifecycle)
            lifecycle_invocations.fetch_add(1);
        else
            compliance_invocations.fetch_add(1);
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rt, sink);

    auto lifecycle_entry = OutboxEntry::lifecycle("r1", 1, "e-lifecycle",
                                                   1'700'000'000'000'000'000, "armed");
    GuardDrift drift;
    drift.rule_id = "r2";
    auto compliance_entry =
        OutboxEntry::compliance("r2", 1, "e-compliance", 1'700'000'000'000'000'000, drift);

    std::optional<SendResult> compliance_result;
    std::optional<SendResult> lifecycle_result;
    // Fires between lifecycle_send_exec_.stop() and compliance_send_exec_.stop(): at
    // this instant lifecycle's lane already refuses, compliance's does not yet.
    worker.set_between_lane_stops_hook_for_test([&] {
        compliance_result = worker.wrapped_send_for_test(compliance_entry);
        lifecycle_result = worker.wrapped_send_for_test(lifecycle_entry);
    });

    worker.stop();

    REQUIRE(compliance_result.has_value());
    REQUIRE(lifecycle_result.has_value());
    CHECK(*compliance_result == SendResult::Sent);  // compliance's lane not yet stopped
    CHECK(*lifecycle_result == SendResult::Retain); // lifecycle's lane already stopped
    CHECK(compliance_invocations.load() == 1);
    CHECK(lifecycle_invocations.load() == 0);
    CHECK(spin_until([&] { return worker.active_send_workers() == 0; }, 3s));
}

TEST_CASE("stop() is idempotent and joins cleanly with nothing pending",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
    worker.start();
    worker.stop();
    worker.stop(); // idempotent
    SUCCEED("double-stop did not hang or crash");
}

TEST_CASE("destroying the worker while running stops and joins it (dtor calls stop())",
          "[spark][guardian][drain]") {
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    CollectingSink sink;
    {
        GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
        worker.start();
        rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
        // worker destructs here without an explicit stop() call
    }
    SUCCEED("destructor-driven stop joined cleanly");
}

TEST_CASE("a copied waker outliving the worker is a harmless no-op (Signal stays alive)",
          "[spark][guardian][drain]") {
    // Mirrors ConvergenceScheduler's own copied-waker-outlives-scheduler test.
    auto r = std::make_shared<FakeReader>();
    auto b = std::make_shared<FakeBackend>();
    auto rt = std::make_shared<GuardianSparkRuntime>(r, b);
    CollectingSink sink;
    std::function<void()> copied_waker;
    {
        GuardianOutboxDrainWorker worker(*rt, std::ref(sink));
        worker.start();
        copied_waker = rt->outbox_enqueue_waker_for_test();
        worker.stop();
    } // worker destroyed
    REQUIRE(copied_waker);
    copied_waker(); // must not crash / touch a destroyed mutex
    SUCCEED("post-destruction waker invocation was safe");
}

// ---------------------------------------------------------------------------
// C0 (#2298 gate 1): journal maintenance (retention prune + replay paging)
// relocated onto this worker, off the heartbeat and reconnect threads.
// ---------------------------------------------------------------------------

TEST_CASE("maintenance_once is a no-op without a journal (the pre-C0 construction)",
          "[spark][guardian][drain][maint]") {
    auto rt = std::make_shared<GuardianSparkRuntime>(std::make_shared<FakeReader>(),
                                                     std::make_shared<FakeBackend>());
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rt, std::ref(sink)); // journal defaults to null
    CHECK_FALSE(worker.maintenance_once({.prune = true, .page = true}).records_paged > 0);
    CHECK(worker.journal_maint_exception_count() == 0);
}

TEST_CASE("maintenance_once pages a durable batch into the window and reports it",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     {.journal = rig.journal});
    // Nothing is in the window until maintenance pages it: the record was persisted
    // straight to the journal, never through the runtime.
    worker.drain_once();
    CHECK(sink.count() == 0);

    CHECK(worker.maintenance_once({.prune = true, .page = true}).records_paged > 0);
    worker.drain_once();
    REQUIRE(sink.count() == 1);
    CHECK(sink.sent[0].event_id == "e-r1");
    CHECK(rig.journal->pages() >= 1);
}

TEST_CASE("a running worker pages AND ships a durable batch in one wake (no second-wake wait)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");

    CollectingSink sink;
    // A long periodic bound: if the paged entry needed a SECOND wake to ship, this test
    // would time out. try_page_batch does not fire the enqueue waker, so shipping within
    // one wake is exactly the post-page re-drain C0 adds.
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/60'000,
                                     {.journal = rig.journal});
    worker.start();
    worker.notify(); // the reconnect kick
    // 30 s, not the 5 s default: this waits on a real journal scan plus a send, and under a
    // sanitizer build sharing a box with the rest of the suite that overran 5 s in one full
    // TSan run out of two (isolated, it passes 5/5). The deadline is only there to stop a
    // never-shipping worker hanging the suite - what the test asserts is that ONE wake
    // suffices, which a longer deadline does not weaken.
    CHECK(spin_until([&] { return sink.count() == 1; }, 30s));
    worker.stop();
}

TEST_CASE("notify() wakes the worker promptly - the reconnect kick replaces inline paging",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/60'000,
                                     {.journal = rig.journal});
    worker.start();
    worker.notify();
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; })); // the kick, not the bound
    const auto before = rig.journal->pages();
    worker.notify();
    CHECK(spin_until([&] { return rig.journal->pages() > before; })); // NOT a 60 s wait
    worker.stop();
}

TEST_CASE("notify() after stop() is a no-op and never resurrects the worker",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/20,
                                     {.journal = rig.journal});
    worker.start();
    worker.stop();
    const auto after_stop = rig.journal->pages();
    worker.notify();
    std::this_thread::sleep_for(60ms); // > 2 periodic bounds had the thread still been alive
    CHECK(rig.journal->pages() == after_stop);
}

TEST_CASE("the maintenance cadence is TIME-based, not per-wake (an enqueue storm cannot spin it)",
          "[spark][guardian][drain][maint]") {
    // The regression guard for #2298 governance f-1/A1/sec-M1. The earlier version of this
    // test drove maintenance_once() directly against an EMPTY journal and asserted
    // batches_pruned()==0, which is trivially true whether prune ran once or twenty times -
    // it proved nothing (Gate 3 quality-engineer). This one counts ACTUAL journal scans via
    // the pre-scan hook, against a RUNNING worker being hammered with wakes, which is the
    // shape that regresses if anyone reties the cadence to wake count.
    JournalRig rig;
    rig.persist("r1"); // a real journal, so a scan has something to do

    std::atomic<int> prune_scans{0};
    rig.journal->set_pre_scan_hook_for_test([&] { prune_scans.fetch_add(1); });

    CollectingSink sink;
    // Hour-long cadences: NOTHING in this test may legitimately prune or page after the
    // forced boot page, however many times the worker wakes.
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 1h});
    worker.start();
    // Hammer the waker the way a Guardian drift storm would.
    for (int i = 0; i < 200; ++i)
        worker.notify();
    std::this_thread::sleep_for(150ms); // many wakes at a 1 ms periodic bound
    worker.stop();

    // notify() forces a page each time, and a page's boot barrier prunes ONCE (latching
    // boot_pruned_). What must NOT happen is a scan per wake.
    CHECK(prune_scans.load() <= 2);
    CHECK(rig.journal->pages() <= 205); // forced pages only; no cadence pages on top
}

TEST_CASE("an enqueue-driven wake does not page (only the cadence and the kick do)",
          "[spark][guardian][drain][maint]") {
    // sec-M1 stated precisely: paging is a full journal scan, and the token bucket only
    // throttles NET-NEW paging, so the scan itself must be cadence-bound. A wake caused by
    // an ordinary outbox enqueue must therefore ship the entry WITHOUT rescanning.
    JournalRig rig;
    rig.persist("r1");

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/60'000,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 1h});
    worker.start();
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; })); // the seeded boot page
    const auto pages_after_boot = rig.journal->pages();

    // Now drive 50 enqueue wakes through the REAL waker (attach_rule enqueues a lifecycle
    // entry, which fires the runtime's outbox waker).
    for (int i = 0; i < 50; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);
    CHECK(spin_until([&] { return sink.count() >= 50; })); // they shipped...
    CHECK(rig.journal->pages() == pages_after_boot);       // ...with no extra journal scan
    worker.stop();
}

TEST_CASE("a zero prune interval prunes every maintenance pass (retention still runs here)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/2,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 6; ++i)
        rig.persist("r" + std::to_string(i));

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.maintenance_once({.prune = true, .page = true});
    CHECK(rig.journal->batches_pruned() >= 4); // trimmed to the 2-batch cap on the worker
}

TEST_CASE("request_stop() makes a maintenance pass a no-op (bounds the drain-worker join)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");
    rig.journal->request_stop();

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    CHECK_FALSE(worker.maintenance_once({.prune = true, .page = true}).records_paged > 0);
    CHECK(rig.journal->pages() == 0);        // page_into_window bailed before its scan
    CHECK(rig.journal->batches_pruned() == 0); // prune bailed before its scan
    worker.drain_once();
    CHECK(sink.count() == 0); // and nothing reached the window after the stop signal
}

TEST_CASE("a stop landing INSIDE a scan is honoured mid-pass, not just at the entry gate",
          "[spark][guardian][drain][maint]") {
    // The earlier version called request_stop() BEFORE stop(), so every subsequent pass
    // short-circuited at prune's entry guard and the mid-loop gates added by 551e91ac were
    // never executed (Gate 3 quality-engineer). Here the pre-scan hook fires request_stop()
    // from INSIDE a scan already in flight, which is the interleaving those gates exist for.
    JournalRig rig;
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/2,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 40; ++i)
        rig.persist("r" + std::to_string(i));

    std::atomic<bool> stopped_mid_scan{false};
    rig.journal->set_pre_scan_hook_for_test([&] {
        rig.journal->request_stop(); // the scan is already past its entry gate
        stopped_mid_scan.store(true);
    });

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink),
                                     GuardianOutboxDrainWorker::kDefaultPeriodicBoundMs,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.maintenance_once({.prune = true, .page = true});

    CHECK(stopped_mid_scan.load());
    // The mid-scan gates must have aborted the pass: nothing was evicted despite 40 batches
    // against a 2-batch cap, and the label-GC / quarantine-bounding scans never ran.
    CHECK(rig.journal->batches_pruned() == 0);
    CHECK(rig.journal->prune_failures() == 0); // an abort is not a failure
}

TEST_CASE("stop() during a running worker's maintenance joins cleanly",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    for (int i = 0; i < 40; ++i)
        rig.persist("r" + std::to_string(i));

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.start();
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; }));
    // Production teardown order: the journal is signalled FIRST, then the worker joined.
    rig.journal->request_stop();
    worker.stop();
    const auto pages_at_join = rig.journal->pages();
    std::this_thread::sleep_for(20ms);
    CHECK(rig.journal->pages() == pages_at_join); // no maintenance survived the join
    CHECK(worker.journal_maint_exception_count() == 0);
}

TEST_CASE("a throwing maintenance pass is firewalled, counted, and does not stop the loop",
          "[spark][guardian][drain][maint]") {
    // journal_maint_exception_count() was asserted ==0 everywhere but never driven nonzero
    // (Gate 3 quality-engineer). The pre-scan hook throws straight out of prune_locked_
    // uncaught, so no new seam is needed to prove the firewall.
    JournalRig rig;
    rig.persist("r1");
    std::atomic<int> throws{0};
    rig.journal->set_pre_scan_hook_for_test([&] {
        if (throws.fetch_add(1) < 3)
            throw std::runtime_error("scan boom");
    });

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    worker.start();
    CHECK(spin_until([&] { return worker.journal_maint_exception_count() >= 1; }));
    // The loop survived and kept going: once the hook stops throwing, work resumes.
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; }));
    worker.stop();
    CHECK(worker.drain_exception_count() == 0); // the drain firewall was NOT tripped
}

TEST_CASE("item 6 stamps: seeded at start(), advanced by a non-throwing pass",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    // Before start() the stamps are 0 - the reader's "no worker" sentinel, which is what
    // journal_age_stats() keys its nullopt on for the wired-but-not-started window.
    CHECK(worker.last_page_success_steady_ms() == 0);
    CHECK(worker.last_prune_success_steady_ms() == 0);

    worker.start();
    // Seeded synchronously in start(): non-zero from the very first instant, so a worker
    // that starts and then dies reads as a growing age from its first heartbeat (item 14).
    const auto page_seed = worker.last_page_success_steady_ms();
    const auto prune_seed = worker.last_prune_success_steady_ms();
    CHECK(page_seed > 0);
    CHECK(prune_seed > 0);

    // 0ms intervals: passes run continuously and succeed, so both stamps must ADVANCE
    // past their seeds (a success re-stamps with a later steady reading).
    CHECK(spin_until([&] { return worker.last_page_success_steady_ms() > page_seed; }));
    CHECK(spin_until([&] { return worker.last_prune_success_steady_ms() > prune_seed; }));
    worker.stop();
}

TEST_CASE("item 6 stamps: a permanently-throwing pass never advances them",
          "[spark][guardian][drain][maint]") {
    // The cadence locals advance even on a throw (deliberate min-GAP pacing); the SUCCESS
    // stamps must not - a permanently-failing maintenance loop has to read as an
    // ever-growing age, or item 6's gauge cannot distinguish it from a healthy one.
    JournalRig rig;
    rig.persist("r1");
    // Throws on EVERY scan, forever: the prune pass throws directly, and the page pass
    // throws inside its boot-prune barrier - both firewalled, neither ever succeeds.
    rig.journal->set_pre_scan_hook_for_test([] { throw std::runtime_error("scan boom"); });

    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    worker.start();
    const auto page_seed = worker.last_page_success_steady_ms();
    const auto prune_seed = worker.last_prune_success_steady_ms();
    REQUIRE(page_seed > 0);
    REQUIRE(prune_seed > 0);
    // Let several passes throw, then verify neither stamp moved off its seed.
    CHECK(spin_until([&] { return worker.journal_maint_exception_count() >= 4; }));
    CHECK(worker.last_page_success_steady_ms() == page_seed);
    CHECK(worker.last_prune_success_steady_ms() == prune_seed);
    worker.stop();
}

TEST_CASE("progress flag: a token-starved (deferred) pass is NOT verified-idle (flag false)",
          "[spark][guardian][drain][maint]") {
    // A pass that returns on deferred_no_token did no replay and verified nothing, so the flag must
    // be false (the page stamp then reads as a growing age on a permanently token-starved worker).
    // Deterministic and running-worker-free: the burn is synchronous, so no wall-clock token refill
    // can race the assertion (the earlier running-worker form of this test was a documented flake
    // risk under CI contention - governance QE-1). The gate's end-to-end consumption of a false
    // flag is proven by the read-fail / prune-scan / boot-barrier stamp tests above.
    JournalRig rig;
    // Burn the startup token burst: page net-new batches until a pass reports deferred_no_token.
    // Successive synchronous calls advance wall-clock by ~microseconds, far below the 0.1/s refill,
    // so the bucket drains and stays dry within the loop.
    rig.persist_batch("seed", 2);
    REQUIRE(rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test()).records_paged == 2);
    for (int i = 0; i < 12; ++i)
        rig.persist_batch("f" + std::to_string(i), 1);
    JournalPageStats stats;
    bool dry = false;
    for (int i = 0; i < 40 && !dry; ++i) {
        stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
        dry = stats.deferred_no_token;
    }
    REQUIRE(dry); // net-new work still pending, bucket empty
    CHECK(stats.records_paged == 0);
    CHECK_FALSE(stats.progress_or_verified_idle);
}

TEST_CASE("item 6 stamps: a page pass whose read fails does not refresh the age (#2452)",
          "[spark][guardian][drain][maint]") {
    // The other half of the page gate: a candidate/value read failure leaves the pass unable to
    // establish what is replayable, so it must not read as fresh. Inject a long run of page
    // candidate-scan failures - each increments page_read_failures and does no replay - while
    // prune stays healthy and advances (proving the passes ran).
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    // Latch the boot-prune barrier with one clean synchronous page first (a read failure before
    // it latches would merely be retried), then fail every subsequent page candidate scan. A
    // read-failed pass returns before charging a token, so the bucket never drains and every
    // pass reaches (and fails at) the candidate scan.
    REQUIRE(worker.maintenance_once({.page = true}).records_paged == 1);
    rig.journal->inject_page_read_failures_for_test(1'000'000); // outlasts the whole test window

    worker.start();
    const auto page_seed = worker.last_page_success_steady_ms();
    const auto prune_seed = worker.last_prune_success_steady_ms();
    REQUIRE(page_seed > 0);
    REQUIRE(prune_seed > 0);
    REQUIRE(spin_until([&] { return worker.last_prune_success_steady_ms() > prune_seed; }));
    const auto prune_mark = worker.last_prune_success_steady_ms();
    REQUIRE(spin_until([&] { return worker.last_prune_success_steady_ms() > prune_mark; }));
    CHECK(worker.last_page_success_steady_ms() == page_seed); // frozen: every pass read-failed
    CHECK(rig.journal->page_read_failures() > 0);             // ...and the passes really ran
    worker.stop();
}

TEST_CASE("item 6 stamps: a prune whose scan fails does not refresh the age (#2452)",
          "[spark][guardian][drain][maint]") {
    // The prune-side sibling of the page gate. A prune whose scan fails returns read_ok=false
    // WITHOUT throwing (a KvStore read error is fail-safe), so gating the success stamp on "did
    // not throw" alone would read a permanently-unreadable retention loop as fresh. Inject a long
    // run of prune scan failures; prune_failures counts the passes that ran while the stamp must
    // stay at its seed.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 1h, // keep page out of it
                                      .prune_interval = 0ms});
    rig.journal->inject_read_failures_for_test(1'000'000); // every prune scan fails, no throw

    worker.start();
    const auto prune_seed = worker.last_prune_success_steady_ms();
    REQUIRE(prune_seed > 0);
    // Wait for several prune passes to have run and fail-scanned, then confirm the success stamp
    // never advanced. RED before #2452: `if (ok)` advanced it on every read_ok=false pass.
    REQUIRE(spin_until([&] { return rig.journal->prune_failures() >= 4; }));
    CHECK(worker.last_prune_success_steady_ms() == prune_seed);
    worker.stop();
}

TEST_CASE("item 6 stamps: a page pass whose boot-prune barrier scan fails does not refresh the age (#2452)",
          "[spark][guardian][drain][maint]") {
    // The boot-prune barrier inside page_into_window runs a prune scan before the FIRST replay can
    // page anything. If that scan fails, the pass paged nothing and established nothing - but the
    // failure is counted on prune_failures, NOT page_read_failures, and the pass sets no
    // deferred/sent-scan flag. Without JournalPageStats::read_failed the page stamp would advance
    // on this zero-work pass (a residual instance of the same #2452 bug class, found in review).
    // Inject prune scan failures so the barrier never latches; every page pass takes this exit. Do
    // NOT pre-page (that would latch the barrier). prune_failures proves cycles ran - both the
    // maintenance prune and the barrier's own prune increment it - while the page stamp stays put.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    rig.journal->inject_read_failures_for_test(1'000'000); // every prune scan fails; barrier never latches

    worker.start();
    const auto page_seed = worker.last_page_success_steady_ms();
    REQUIRE(page_seed > 0);
    REQUIRE(spin_until([&] { return rig.journal->prune_failures() >= 4; }));
    CHECK(worker.last_page_success_steady_ms() == page_seed); // frozen: every page pass hit the failing barrier
    CHECK(rig.journal->page_read_failures() == 0); // the barrier is counted on prune_failures, not here
    worker.stop();
}

// ── progress_or_verified_idle: the page stamp's positive gate signal (#2452 Gate 7) ──
// These pin the flag DIRECTLY on page_into_window's return (synchronous, deterministic) rather
// than through a running worker: the worker gate's CONSUMPTION of the flag is proven end-to-end by
// the four stamp tests above (each a pass with flag==false leaves the stamp frozen). A page pass is
// healthy iff it placed records OR ran a full scan finding a clean, unblocked, uncorrupted,
// readable idle backlog; every degraded/no-work outcome must leave the flag false.

TEST_CASE("progress flag: a clean idle pass is verified-idle (flag true)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig; // empty journal
    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    CHECK(stats.records_paged == 0);
    CHECK(stats.progress_or_verified_idle); // scan completed, nothing to page, nothing wrong
}

TEST_CASE("progress flag: a pass that places records is progress (flag true)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist_batch("r", 2);
    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    CHECK(stats.records_paged == 2);
    CHECK(stats.progress_or_verified_idle);
}

TEST_CASE("progress flag: a quarantine-only pass is NOT verified-idle (flag false, UP-2)",
          "[spark][guardian][drain][maint]") {
    // A pass that only quarantines corrupt batches placed nothing and verified no clean backlog -
    // it must not read fresh, else a mass-corruption endpoint shows a healthy age while zero
    // records reach the server. Quarantine is a SUCCESSFUL read of a corrupt value (not a read
    // failure), so only the any_quarantine_this_pass term keeps the flag false. RED before Gate 7.
    JournalRig rig;
    const std::int64_t now = journal_now_ms_for_test();
    for (std::uint64_t i = 0; i < 3; ++i)
        REQUIRE(rig.kv->set(kJournalNamespace,
                            journal_batch_key(now, "corrupt" + std::to_string(i), i),
                            "not valid json"));
    const auto stats = rig.journal->page_into_window(*rig.rt, now);
    CHECK(stats.records_paged == 0);
    CHECK(rig.journal->quarantined() == 3); // the pass really did quarantine every candidate
    CHECK_FALSE(stats.progress_or_verified_idle);
}

TEST_CASE("progress flag: a quarantine-RENAME-FAILING pass is NOT verified-idle (flag false, UP-5)",
          "[spark][guardian][drain][maint]") {
    // Even when the corrupt batch's quarantine rename FAILS (a pre-planted quarantine: twin
    // conflicts), the pass placed nothing and left a stuck corrupt batch - not a clean idle
    // backlog. The corrupt signal is set BEFORE the rename, so a rename failure cannot slip past
    // the positive flag (the residual no-work exit the negative enumeration would have missed).
    JournalRig rig;
    const std::int64_t now = journal_now_ms_for_test();
    const auto key = journal_batch_key(now, "corrupt", 0);
    REQUIRE(rig.kv->set(kJournalNamespace, key, "not valid json"));
    // Pre-plant the quarantine twin so the page-side rename conflicts (not Renamed).
    REQUIRE(rig.kv->set(kJournalNamespace, journal_quarantine_key(key), "pre-existing twin"));
    const auto stats = rig.journal->page_into_window(*rig.rt, now);
    CHECK(stats.records_paged == 0);
    CHECK(rig.journal->quarantine_failures() >= 1); // the rename really failed
    CHECK_FALSE(stats.progress_or_verified_idle);
}

TEST_CASE("progress flag: a fully-window-blocked pass is NOT verified-idle (flag false, UP-1)",
          "[spark][guardian][drain][maint]") {
    // records_paged==0 with headroom_blocked=true is a genuine replay-congestion stall behind a
    // saturated send window, not a clean idle - the flag must be false so the age gauge grows.
    JournalRig rig{/*outbox_capacity=*/1}; // clamped up to kMaxJournalEntriesPerBatch
    const std::size_t cap = rig.rt->lifecycle_headroom();
    rig.persist_batch("blocked", 3); // needs 3 slots
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap; ++i) // fill the window completely: nothing fits
        fill.push_back(OutboxEntry::lifecycle("live", 1, "live-" + std::to_string(i),
                                              1'700'000'000'000'000'000, "armed", "file", "n"));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap);
    REQUIRE(rig.rt->lifecycle_headroom() == 0);
    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    CHECK(stats.headroom_blocked);
    CHECK(stats.records_paged == 0);
    CHECK_FALSE(stats.progress_or_verified_idle);
}

TEST_CASE("progress flag: a value-read-failing pass that places nothing is NOT verified-idle (flag false)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist_batch("r", 2);
    rig.journal->inject_value_read_failures_for_test(1); // the one candidate's value read fails
    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    CHECK(stats.records_paged == 0);
    CHECK(stats.read_failed);
    CHECK_FALSE(stats.progress_or_verified_idle);
}

TEST_CASE("progress flag: a sent-scan-failing idle pass is NOT verified-idle (flag false, UP8-2)",
          "[spark][guardian][drain][maint]") {
    // A degraded sent-label scan means the pass could not fully verify what was already delivered,
    // so an otherwise-idle pass is not "verified idle" (parity with the pre-Gate-7 gate, restored
    // after governance Gate 8 found the term dropped). Empty backlog isolates it: the sent-scan
    // still runs (it is unconditional on !replay_sent), fails, and nothing places - so
    // sent_scan_failed is the SOLE false-driver. A pass that re-offers everything and PLACES
    // records still reads fresh via the records_paged>0 override.
    JournalRig rig; // empty backlog
    rig.journal->inject_sent_scan_failures_for_test(1);
    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    CHECK(stats.sent_scan_failed);
    CHECK(stats.records_paged == 0);
    CHECK_FALSE(stats.progress_or_verified_idle);
}

TEST_CASE("progress flag: records placed OVERRIDES a same-pass read failure (flag true, QE-4/#2452)",
          "[spark][guardian][drain][maint]") {
    // The records_paged>0 disjunct: a pass that placed records is progress even if one other
    // candidate read failed - so a persistently flaky single candidate cannot cry wolf while the
    // rest of the backlog drains. Non-vacuous BECAUSE this is a single synchronous pass carrying
    // BOTH signals at once: reverting the `records_paged>0 ||` disjunct reddens this (the pass
    // would then read as stale despite real progress).
    JournalRig rig;
    rig.persist_batch("a", 2); // first-considered candidate; its value read is failed below
    rig.persist_batch("b", 2); // second candidate; pages normally
    rig.journal->inject_value_read_failures_for_test(1); // fails only the FIRST value read
    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    CHECK(stats.read_failed);          // a candidate value read did fail this pass
    CHECK(stats.records_paged > 0);    // ...but another candidate still paged
    CHECK(stats.progress_or_verified_idle); // progress wins: the stamp reads fresh
}

TEST_CASE("item 6 stamps + episode age: lock-free readers race a live worker (TSan checkpoint)",
          "[spark][guardian][drain][maint][tsan]") {
    // The age telemetry's concurrency shape is lock-free readers (the heartbeat)
    // against a mutex-serialized writer (the drain thread). Safe by inspection - this
    // exists so nightly TSan actually DRIVES it (governance Gate 3 cpp-safety): a
    // main-thread polling loop hammers every new accessor while the worker runs
    // continuous maintenance passes.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    worker.start();
    const auto deadline = std::chrono::steady_clock::now() + kSpinScale * 200ms;
    std::uint64_t last_page = 0, last_prune = 0, age = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        last_page = worker.last_page_success_steady_ms();
        last_prune = worker.last_prune_success_steady_ms();
        const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now().time_since_epoch())
                                .count();
        age = rig.journal->headroom_blocked_age_ms(now_ms);
        (void)rig.journal->headroom_blocked_since_for_test();
    }
    worker.stop();
    CHECK(last_page > 0);  // seeded + racing reads observed real values
    CHECK(last_prune > 0);
    CHECK(age == 0); // nothing blocked in this rig
}

TEST_CASE("item 13: a throw in loop()'s tail reaches the top-level catch, is counted, joins clean",
          "[spark][guardian][drain][maint]") {
    // The loop's own tail (the refill re-arm's rt_.lifecycle_headroom() call - std::mutex::lock
    // can throw - and the cadence arithmetic) sits OUTSIDE every inner firewall. Nothing in
    // production can make it throw, so the thread lambda's top-level catch and its
    // journal_maint_exceptions_ increment were unexercised (flip item 13). The seam injects a
    // one-shot throw there and this proves the escape is caught, counted once, and the worker
    // terminates so stop() still joins cleanly.
    //
    // MUTATION EVIDENCE (run at verify time, not asserted here):
    //   (a) remove the thread lambda's top-level catch -> the injected throw escapes a bare
    //       thread -> std::terminate -> the whole suite process dies (the strongest proof the
    //       catch is load-bearing);
    //   (b) remove the catch's journal_maint_exceptions_.fetch_add -> spin_until below never
    //       reaches 1 and times out -> red.
    // In this rig nothing in MAINTENANCE throws, so the only thing that can drive the counter
    // to 1 is the top-level catch - which is what makes (b) a clean pin despite the counter
    // being shared with the inner firewalls.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,
                                      .prune_interval = 0ms});
    // Armed BEFORE start(): thread creation is the happens-before edge, so the worker's first
    // cycle observes it without a data race.
    worker.inject_loop_tail_throw_for_test();
    CHECK(worker.last_page_success_steady_ms() == 0); // not started yet

    worker.start();
    // The first cycle runs maintenance (both 0ms-due passes succeed and stamp), then the tail
    // throws and the loop dies - so the count settles at exactly 1 and never moves again.
    CHECK(spin_until([&] { return worker.journal_maint_exception_count() == 1; }));

    // The worker is dead: its success stamps are seeded/advanced (> 0) and now FROZEN, which is
    // exactly the ever-growing-age liveness contract item 6 reads off a dead worker.
    const auto page_ms = worker.last_page_success_steady_ms();
    const auto prune_ms = worker.last_prune_success_steady_ms();
    CHECK(page_ms > 0);
    CHECK(prune_ms > 0);
    CHECK(worker.drain_exception_count() == 0); // the DRAIN firewall was not tripped

    worker.stop(); // must still join cleanly despite the dead loop
    CHECK(worker.journal_maint_exception_count() == 1);       // one-shot: never a second throw
    CHECK(worker.last_page_success_steady_ms() == page_ms);   // frozen - the loop is gone
    CHECK(worker.last_prune_success_steady_ms() == prune_ms);
}

TEST_CASE("a throwing send does not suppress journal maintenance (independent firewalls)",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    rig.persist("r1");
    // The send throws on every entry (counted + head-retained by the runtime's own drain
    // firewall). Journal maintenance must still run every pass: before C0 these two lived on
    // different threads, and folding them onto one must not let either starve the other.
    auto throwing = [](const OutboxEntry&) -> SendResult { throw std::runtime_error("boom"); };
    GuardianOutboxDrainWorker worker(*rig.rt, throwing, /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal});
    worker.start();
    CHECK(spin_until([&] { return rig.journal->records_paged() >= 1; }));
    CHECK(spin_until([&] { return rig.rt->send_exception_count() >= 1; }));
    worker.stop();
    CHECK(worker.journal_maint_exception_count() == 0); // maintenance itself never threw
}

TEST_CASE("a running worker's maintenance races a persister + reconnect kicks (TSan checkpoint)",
          "[spark][guardian][drain][maint][tsan]") {
    // The exact post-C0 concurrency shape: prune + page on the WORKER thread, persist on a
    // separate thread (the heartbeat's surviving phase-1 retry), and reconnect kicks arriving
    // from a third. Before C0 prune/page and persist were serialised on one heartbeat thread,
    // so this interleaving is the one the relocation introduces.
    JournalRig rig;
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/16,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 16; ++i)
        rig.persist("seed" + std::to_string(i));

    // The send is the PRODUCTION wrapper shape, not a bare sink: mark_batch_sent issues a
    // KvStore WRITE from the worker thread, which must race prune's del_keys on the same
    // store. A CollectingSink would never exercise that (Gate 3 cpp-safety).
    CollectingSink sink;
    auto journaled_send = [&](const OutboxEntry& e) -> SendResult {
        const SendResult r = sink(e);
        if (r == SendResult::Sent && e.journal_last_in_batch && !e.journal_batch_key.empty())
            rig.journal->mark_batch_sent(e.journal_batch_key);
        return r;
    };
    GuardianOutboxDrainWorker worker(*rig.rt, journaled_send, /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal, .prune_interval = 0ms});
    worker.start();

    std::atomic<bool> stop{false};
    // Drives the REAL phase-1 persist path (snapshot_pending -> persist ->
    // erase_persisted_prefix -> backfill_batch_provenance over outbox_mu_/pending_journal_),
    // which is precisely the state C0 newly splits across two threads. Persisting straight
    // into the journal, as this test previously did, bypasses all of it.
    std::thread persister([&] {
        for (int i = 0; !stop.load(std::memory_order_relaxed) && i < 200; ++i) {
            const auto rid = "live" + std::to_string(i);
            rig.rt->attach_rule(rid, file_spec("/" + rid), file_exists_rule(rid), true);
                        auto snap = rig.rt->snapshot_pending();
                auto& pending = snap.records;
            if (pending.empty())
                continue;
            std::vector<PersistedBatch> batches;
            const std::size_t written = rig.journal->persist(pending, &batches, kJournalPersistUnbounded, kJournalPersistUnbounded);
            if (written > 0) {
                rig.rt->erase_persisted_prefix(written, snap.drops_at_snapshot);
                for (const auto& b : batches)
                    if (!b.event_ids.empty())
                        rig.rt->backfill_batch_provenance(b.key, b.event_ids, b.event_ids.back());
            }
        }
    });
    std::thread kicker([&] {
        while (!stop.load(std::memory_order_relaxed))
            worker.notify();
    });

    std::this_thread::sleep_for(200ms);
    stop.store(true, std::memory_order_relaxed);
    persister.join();
    kicker.join();

    // Production teardown order: the journal is signalled FIRST, then the worker is joined.
    rig.journal->request_stop();
    worker.stop();
    SUCCEED("no data race / crash across worker maintenance + persist + reconnect kicks");
}

TEST_CASE("the drain-worker role marker is set on that thread and nowhere else",
          "[spark][guardian][drain][maint]") {
    // This is what GuardianEngine::WorkerHostileMutex consults to abort rather than deadlock
    // if the worker ever takes mtx_ (#2298 A2, reworked after Sol found the earlier
    // pointer-based mechanism was itself a data race and a potential UAF). The abort ITSELF is
    // proven by the forked-child death test in test_guardian_engine_spark_reconcile.cpp; what
    // this covers is the PREDICATE it keys off - true on a joined worker thread, false
    // elsewhere - which that death test cannot isolate.
    JournalRig rig;
    CHECK_FALSE(on_guardian_joined_thread()); // the test thread is not the worker

    // A separate, directly-constructed marker proves the TRUE case (on_guardian_joined_
    // thread() reads true while GuardianJoinedThreadRole is alive on the calling thread),
    // independent of the drain worker - #2233 item 4 moved the injected `send` off the
    // joined thread entirely (see below), so the worker's own loop() no longer has any
    // externally-observable point that is both "marked" and test-injectable.
    std::atomic<bool> marked_true{false};
    std::thread marked_thread([&] {
        GuardianJoinedThreadRole role_marker;
        marked_true.store(on_guardian_joined_thread());
    });
    marked_thread.join();
    CHECK(marked_true.load());

    std::atomic<bool> marker_inside{true}; // default true so a missed callback fails loudly
    std::atomic<bool> observed{false};
    auto observing_send = [&](const OutboxEntry&) -> SendResult {
        // #2233 item 4: `send` now runs on GuardianOutboxSendExecutor's DETACHED worker,
        // not on this class's own joined thread (guardian_outbox_send_executor.hpp) - so
        // it correctly reads false here. That is the point of the fix: stop() no longer
        // joins whatever thread `send` happens to be running on, so send() taking
        // GuardianEngine::mtx_ can no longer deadlock stop() the way it could before -
        // the exposure this marker exists to catch is why an injected `send` was ever the
        // vehicle for this test.
        marker_inside.store(on_guardian_joined_thread());
        observed.store(true);
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rig.rt, observing_send, /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal});
    worker.start();
    rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    CHECK(spin_until([&] { return observed.load(); }));
    CHECK_FALSE(marker_inside.load());
    worker.stop();
    CHECK_FALSE(on_guardian_joined_thread()); // still false here after the join
}

TEST_CASE("a bounded drain truncates, reports it, and later passes finish the backlog",
          "[spark][guardian][drain][maint]") {
    JournalRig rig;
    for (int i = 0; i < 12; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);

    CollectingSink sink;
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 4;
    const auto first = rig.rt->drain_bounded(std::ref(sink), limits);
    CHECK(first.sent == 4);
    CHECK(first.truncated); // entries remain: the caller must re-drain, not sleep
    const auto second = rig.rt->drain_bounded(std::ref(sink), limits);
    CHECK(second.sent == 4);
    rig.rt->drain(std::ref(sink)); // unbounded finish
    CHECK(sink.count() == 12);     // nothing lost, nothing duplicated
}

TEST_CASE("a bounded drain reserves a share so lifecycle cannot starve compliance",
          "[spark][guardian][drain][maint]") {
    // Regression guard for the detection blackout a naive shared budget reintroduced: with
    // lifecycle drained first out of ONE budget, a busy lifecycle log meant compliance/health
    // never ran at all - the exact failure Gate 4 UP-3 removed (#2298 Sol review).
    JournalRig rig;
    for (int i = 0; i < 20; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);
    rig.rt->evaluate_key(spark_key(file_spec("/p0")), EvalReason::Convergence);

    CollectingSink sink;
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 8; // lifecycle alone would consume all 8 without a reserve
    rig.rt->drain_bounded(std::ref(sink), limits);

    bool saw_non_lifecycle = false;
    {
        std::lock_guard<std::mutex> lk{sink.mu};
        for (const auto& e : sink.sent)
            if (e.domain != OutboxDomain::Lifecycle)
                saw_non_lifecycle = true;
    }
    CHECK(saw_non_lifecycle);
}

TEST_CASE("a drain starts no further sends once stop is requested",
          "[spark][guardian][drain][maint]") {
    // A count bound let a whole 512-send pass BEGIN after stop() was already blocked in
    // join(); should_stop is now checked before every send (#2298 Sol review).
    JournalRig rig;
    for (int i = 0; i < 20; ++i)
        rig.rt->attach_rule("r" + std::to_string(i), file_spec("/p" + std::to_string(i)),
                            file_exists_rule("r" + std::to_string(i)), true);

    std::atomic<int> sends{0};
    std::atomic<bool> stopping{false};
    auto counting_send = [&](const OutboxEntry&) -> SendResult {
        if (sends.fetch_add(1) >= 2)
            stopping.store(true); // shutdown lands mid-pass
        return SendResult::Sent;
    };
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 100;
    limits.should_stop = [&] { return stopping.load(); };
    const auto out = rig.rt->drain_bounded(counting_send, limits);
    CHECK(out.truncated);
    CHECK(sends.load() <= 4); // stopped promptly; did not run the whole allowance
}

TEST_CASE("a prune failure does not swallow a forced reconnect page",
          "[spark][guardian][drain][maint]") {
    // prune and page shared one try/catch and both cadence stamps were taken BEFORE the pass,
    // so a prune throw consumed the force flag and lost the reconnect kick for a whole
    // cadence interval (#2298 Sol review).
    JournalRig rig;
    rig.persist("r1");
    std::atomic<int> scans{0};
    rig.journal->set_pre_scan_hook_for_test([&] {
        if (scans.fetch_add(1) < 2)
            throw std::runtime_error("prune boom");
    });

    CollectingSink sink;
    // Page cadence an hour out, so ONLY a forced page can ever run in this test.
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 0ms});
    worker.start();
    CHECK(spin_until([&] { return worker.journal_maint_exception_count() >= 1; }));
    // The prune throws ate the first cycles, but the force was re-armed rather than lost,
    // so the durable record still reaches the wire.
    CHECK(spin_until([&] { return sink.count() >= 1; }));
    worker.stop();
}

// A send shaped like the PRODUCTION one (agent.cpp send_guardian_outbox_entry): writes to a
// stream that may be absent, and reports Retain - not an exception, not a drop - whenever the
// link is down or the write fails. Every other test here uses an always-Sent sink, which never
// exercises head-retention, the backlog it builds, or the drain-stops-at-the-head behaviour
// that Retain triggers (#2298 Sol review).
struct StreamLikeSink {
    std::mutex mu;
    bool stream_up{false};       ///< nullptr guardian_sink_stream_ equivalent
    bool write_fails{false};     ///< Write() returning false equivalent
    std::size_t retained{0};
    std::vector<std::string> sent_ids;

    SendResult operator()(const OutboxEntry& e) {
        std::lock_guard<std::mutex> lk{mu};
        if (!stream_up || write_fails) {
            ++retained;
            return SendResult::Retain; // keep the head and stop this pass
        }
        sent_ids.push_back(e.event_id);
        return SendResult::Sent;
    }
    std::size_t count() {
        std::lock_guard<std::mutex> lk{mu};
        return sent_ids.size();
    }
    std::size_t retain_count() {
        std::lock_guard<std::mutex> lk{mu};
        return retained;
    }
    void set_stream(bool up) {
        std::lock_guard<std::mutex> lk{mu};
        stream_up = up;
    }
};

TEST_CASE("a link-down/reconnect cycle with REAL Retain semantics loses nothing",
          "[spark][guardian][drain][maint]") {
    // The end-to-end shape C0 has to survive at cutover: entries pile up while the link is
    // down (send Retains, journal persists), then the link returns and the reconnect kick has
    // to get the whole backlog moving - including the case Sol raised, where the send window
    // is already full so the kick's page places nothing and only the drain frees room.
    JournalRig rig;
    StreamLikeSink sink; // starts with the stream DOWN

    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/20,
                                     {.journal = rig.journal,
                                      // Small drain budget so the backlog needs several
                                      // truncated passes, exercising the re-drain path.
                                      .drain_budget = 3});
    worker.start();

    // Link DOWN: arm rules, and persist their staged records durably the way the heartbeat's
    // retry-persist would.
    for (int i = 0; i < 12; ++i) {
        const auto rid = "r" + std::to_string(i);
        rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true);
    }
    {
                auto snap = rig.rt->snapshot_pending();
                auto& pending = snap.records;
        if (!pending.empty()) {
            std::vector<PersistedBatch> batches;
            const std::size_t written = rig.journal->persist(pending, &batches, kJournalPersistUnbounded, kJournalPersistUnbounded);
            if (written > 0)
                rig.rt->erase_persisted_prefix(written, snap.drops_at_snapshot);
        }
    }
    std::this_thread::sleep_for(100ms); // several wakes, all Retaining
    CHECK(sink.count() == 0);           // nothing shipped while the link was down

    // Link UP + the reconnect kick.
    sink.set_stream(true);
    worker.notify();

    // Everything must arrive, without needing a second kick.
    CHECK(spin_until([&] { return sink.count() >= 12; }, 10s));
    worker.stop();

    std::lock_guard<std::mutex> lk{sink.mu};
    const std::set<std::string> unique(sink.sent_ids.begin(), sink.sent_ids.end());
    // NO LOSS is the assertion. Deliberately NOT exactly-once: the durable journal is
    // AT-LEAST-ONCE by design - it replays on every reconnect, and an entry that was already
    // sent and popped from the window before the replay pass gets re-sent. The server
    // de-duplicates on the event_id primary key and counts it as
    // yuzu_server_guardian_events_redelivered_total, which docs/user-manual/metrics.md
    // documents as expected after an outage and explicitly NOT a loss signal. An earlier
    // draft of this test asserted exactly-once and failed - the assertion was wrong, not the
    // code, and pinning the real contract here is the point.
    CHECK(unique.size() == 12);          // every distinct event arrived
    CHECK(sink.sent_ids.size() >= 12);   // redelivery is permitted, loss is not
}

TEST_CASE("a mid-drain link drop retains the head and resumes without loss",
          "[spark][guardian][drain][maint]") {
    // Retain is not a failure - it means "keep the head, stop this pass". A link that drops
    // PART WAY through a backlog must therefore leave the remainder intact and resume from
    // exactly where it stopped once the stream returns.
    JournalRig rig;
    StreamLikeSink sink;
    sink.set_stream(true);

    for (int i = 0; i < 10; ++i) {
        const auto rid = "r" + std::to_string(i);
        rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true);
    }

    // Ship a few, then drop the link mid-backlog.
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 4;
    const auto first = rig.rt->drain_bounded(std::ref(sink), limits);
    CHECK(first.sent == 4);

    sink.set_stream(false);
    const auto during_outage = rig.rt->drain_bounded(std::ref(sink), limits);
    CHECK(during_outage.sent == 0);        // the head is retained, not consumed
    CHECK_FALSE(during_outage.truncated);  // Retain is not a limit hit - do NOT hot-loop

    sink.set_stream(true);
    rig.rt->drain(std::ref(sink)); // unbounded catch-up
    CHECK(sink.count() == 10);

    std::lock_guard<std::mutex> lk{sink.mu};
    std::set<std::string> unique(sink.sent_ids.begin(), sink.sent_ids.end());
    CHECK(unique.size() == 10); // nothing lost, nothing duplicated across the outage
}

TEST_CASE("a jammed lifecycle head plus live compliance traffic does not re-arm the page",
          "[spark][guardian][drain][maint]") {
    // Regression guard for #2298 Gate 4 UP-2, caused BY the reconnect-refill fix. The old
    // re-arm keyed on "a page ran and placed nothing, and the drain sent something", and both
    // halves are true in a reachable, benign state that has nothing to do with a full window:
    //
    //   - a lifecycle head that cannot send (Retain) jams the lifecycle log, so the batches
    //     the boot page placed STAY window members and every later page legitimately adds 0;
    //   - compliance/health drains independently (failure isolation, Gate 4 UP-3), so the
    //     drain is non-empty every cycle.
    //
    // That re-armed the force flag on every cycle and restored the per-wake full-journal scan
    // the 30 s cadence exists to prevent. The fix requires headroom_blocked - a candidate the
    // window genuinely could not fit.
    JournalRig rig;
    rig.persist("r1");
    rig.persist("r2");

    // Lifecycle jams; everything else flows.
    std::atomic<int> compliance_sent{0};
    auto split_sink = [&](const OutboxEntry& e) -> SendResult {
        if (e.domain == OutboxDomain::Lifecycle)
            return SendResult::Retain; // head retained: the window never drains
        compliance_sent.fetch_add(1);
        return SendResult::Sent;
    };

    // A 200 ms page cadence against a 2 ms wake bound: cadence alone allows ~5 pages/second,
    // while a per-cycle re-arm allows hundreds. That gap is what makes this load-bearing.
    GuardianOutboxDrainWorker worker(*rig.rt, split_sink, /*periodic_bound_ms=*/2,
                                     {.journal = rig.journal,
                                      .page_interval = 200ms,
                                      .prune_interval = 1h});
    worker.start();
    CHECK(spin_until([&] { return rig.journal->pages() >= 1; })); // boot page places both

    // Real compliance traffic: a rule on /a whose observed state FLIPS every evaluation, so
    // each one is a genuine verdict edge and emits. (Evaluating a key with no rule, or with a
    // stable verdict, emits nothing - and then `drained` is 0 and the buggy condition never
    // fires, which is how an earlier version of this test passed against the bug.)
    REQUIRE(rig.rt->attach_rule("cmp", file_spec("/a"), file_exists_rule("cmp"), true));
    const auto until = std::chrono::steady_clock::now() + 1s;
    int n = 0;
    while (std::chrono::steady_clock::now() < until) {
        // Dense enough that EVERY worker cycle has something to drain. The buggy re-arm
        // required drained > 0 on the very cycle a page ran, so sparse traffic breaks the
        // chain by luck and hides the bug.
        for (int i = 0; i < 8; ++i) {
            rig.reader->file = read_known(FileSnapshot{.exists = (n % 2 == 0)});
            rig.rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Convergence);
            ++n;
        }
        std::this_thread::sleep_for(1ms);
    }
    worker.stop();

    const auto pages = rig.journal->pages();
    INFO("pages=" << pages << " compliance_sent=" << compliance_sent.load() << " evals=" << n);
    // ~1 s at a 200 ms cadence: a handful. Generous ceiling so this fails on the BUG, not on
    // scheduling jitter - the buggy condition produced pages on essentially every cycle.
    // MEASURED, not guessed: with the fix this is a stable 5 (1 s at a 200 ms cadence, plus
    // the boot page); with the buggy condition it was 9-11 across repeated runs, because each
    // cadence page re-armed exactly one extra page whose drain then found nothing, breaking
    // the chain. 7 sits in that gap. Note the amplification is ~2x and self-limiting rather
    // than the unbounded event-rate loop it was first reported as - the extra cycle runs
    // microseconds later, so there is nothing left for it to drain.
    CHECK(pages <= 7);
}

// ---------------------------------------------------------------------------
// Gate 5 chaos scenarios promoted to P0 (in-process; see the chaos design in
// docs/guardian-c0-thread-reloc-design.md).
// ---------------------------------------------------------------------------

TEST_CASE("CH-3: the drain bound holds against a SLOW-but-succeeding send",
          "[spark][guardian][drain][maint][chaos]") {
    // The largest untested surface C0 created. Every existing drain test uses a send that
    // returns instantly, or throws, or Retains - none exercises the case the wall-clock cap
    // exists for: sends that all SUCCEED but are individually slow, making a count-bounded
    // pass arbitrarily long while stop() waits on the join.
    JournalRig rig;
    for (int i = 0; i < 60; ++i) {
        const auto rid = "r" + std::to_string(i);
        rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true);
    }

    std::atomic<int> sends{0};
    auto slow_send = [&](const OutboxEntry&) -> SendResult {
        sends.fetch_add(1);
        std::this_thread::sleep_for(20ms); // slow, but succeeding
        return SendResult::Sent;
    };

    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 1000;  // deliberately NOT the binding constraint
    limits.max_wall = 150ms;    // this is
    const auto t0 = std::chrono::steady_clock::now();
    const auto out = rig.rt->drain_bounded(slow_send, limits);
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CHECK(out.truncated); // the wall clock cut it short, so the caller re-drains
    // Assert the SEND COUNT, not wall time. The property is "the cap bounded the pass"; the
    // discriminator is that far fewer than the 60-rule backlog shipped. A count bound is
    // runner-independent where a wall-clock bound is not: sleep_for(20ms) is a MINIMUM, so on
    // a slow/contended CI runner it sleeps longer, which makes the deadline bite after FEWER
    // sends, never more - so this only gets safer under load, while `elapsed < 270ms` fails
    // (it did, on macOS CI). max_wall 150ms / 20ms-per-send is ~8 sends; 30 is generous margin
    // and still half the backlog.
    INFO("elapsed_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                       << " sends=" << sends.load()); // diagnostics only; NOT asserted
    CHECK(sends.load() < 30); // truncated well short of the 60-rule backlog
}

TEST_CASE("CH-3b: the compliance reserve survives pathological denominators",
          "[spark][guardian][drain][maint][chaos]") {
    // den == 0 is a divide-by-zero if the guard is ever dropped; den > max_entries used to
    // floor the reserve to nothing (Gate 4 UP-8).
    for (const std::size_t den : {std::size_t{0}, std::size_t{1}, std::size_t{8},
                                  std::size_t{1000},
                                  std::numeric_limits<std::size_t>::max()}) {
        JournalRig rig;
        for (int i = 0; i < 6; ++i) {
            const auto rid = "r" + std::to_string(i);
            rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true);
        }
        // Attach a rule to the key BEFORE evaluating it, and flip its observed state so the
        // evaluation is a real verdict edge. Evaluating an unattached key emits nothing, so
        // the compliance entry the reserve is supposed to protect never existed and the
        // assertion below was vacuous (#2345 minor).
        REQUIRE(rig.rt->attach_rule("cmp", file_spec("/cmp"), file_exists_rule("cmp"), true));
        rig.reader->file = read_known(FileSnapshot{.exists = false});
        rig.rt->evaluate_key(spark_key(file_spec("/cmp")), EvalReason::Convergence);

        // SLOW sends, so the WALL is genuinely the binding constraint. With an instant sink the
        // wall never binds and a mis-sliced lifecycle deadline starves nobody - the coverage
        // would be nominal only. (Adding max_wall without making it bind was the first,
        // inadequate version of this fix.)
        CollectingSink sink;
        auto slow = [&](const OutboxEntry& e) -> SendResult {
            std::this_thread::sleep_for(30ms);
            return sink(e);
        };
        GuardianSparkRuntime::DrainLimits limits;
        limits.max_entries = 4;
        // The WALL dimension needs the same pathological-input coverage as the count: round 4
        // added wall slicing derived from this same ratio, and an unclamped cast could make
        // the lifecycle slice LONGER than the whole pass, leaving compliance with an
        // already-expired deadline (#2345 Gate 2 sec-MEDIUM). Without max_wall set, this test
        // exercised only the count path and would not have seen that.
        limits.max_wall = 500ms;
        limits.compliance_reserve_den = den;
        INFO("compliance_reserve_den = " << den);
        const auto out = rig.rt->drain_bounded(slow, limits); // must not crash
        CHECK(out.sent <= 4); // the overall cap holds
        // The DISCRIMINATING observable: with a sane denominator a compliance entry actually
        // ships. `out.sent <= 4` alone was true even when compliance shipped nothing.
        // Only a denominator ABOVE kMaxReserveRatio is clamped to "no reserve"; every sane
        // one still gets at least the floor of 1 slot, so it must still ship compliance. The
        // earlier `den <= 8` gate was stricter than the code's guarantee and left den=1000
        // asserting only "did not crash" (#2345 Gate 3 QE).
        if (den > 0 && den <= 1'000'000) {
            bool saw_compliance = false;
            std::lock_guard<std::mutex> lk{sink.mu};
            for (const auto& e : sink.sent)
                if (e.domain != OutboxDomain::Lifecycle)
                    saw_compliance = true;
            CHECK(saw_compliance);
        }
    }
}

TEST_CASE("CH-1: a slow send does not make stop() additionally run a full maintenance pass",
          "[spark][guardian][drain][maint][chaos]") {
    // #2233 item 4 / #3847 (revised): before that fix, an in-flight send was UNBOUNDED and
    // no mechanism in this class could beat a blocked syscall, so this test deliberately did
    // not assert that stop() beats a blocked send. drain_bounded() now routes send through
    // GuardianOutboxSendExecutor (guardian_outbox_send_executor.hpp), which detaches the
    // call - so stop() no longer waits on it at all. This asserts THAT property directly: the
    // send sleeps 800 ms (well past kGuardianSendOfferWait's 200 ms and past a maintenance
    // pass over 200 batches, so a pass-swallowed-into-the-join failure mode would also fail
    // this bound), yet stop() returns in a small fraction of that.
    JournalRig rig;
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/10'000,
                                               /*max_bytes=*/static_cast<std::size_t>(-1),
                                               /*max_quarantine=*/100);
    for (int i = 0; i < 200; ++i) // a journal big enough that a full pass is measurable
        rig.persist("seed" + std::to_string(i));

    std::atomic<bool> in_send{false};
    auto slow_send = [&](const OutboxEntry&) -> SendResult {
        in_send.store(true);
        std::this_thread::sleep_for(800ms);
        return SendResult::Sent;
    };

    GuardianOutboxDrainWorker worker(*rig.rt, slow_send, /*periodic_bound_ms=*/1,
                                     {.journal = rig.journal,
                                      .page_interval = 0ms,   // maintenance every cycle
                                      .prune_interval = 0ms});
    worker.start();
    CHECK(spin_until([&] { return in_send.load(); }, 10s));

    // Stop while a send is in flight AND maintenance is running every cycle.
    const auto t0 = std::chrono::steady_clock::now();
    rig.journal->request_stop(); // production order: signal the journal, then join
    worker.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CHECK(elapsed < 400ms); // decoupled from the 800 ms send entirely, not merely bounded below it

    // The detached send is still running past stop() (that's the point) - it captures
    // `in_send` by reference into THIS stack frame, so the frame must not unwind while it is
    // still alive. Wait for it to finish before returning (exercises active_send_workers(),
    // the same orphan-exit observable production wires into GuardianEngine::active_io_workers()).
    REQUIRE(spin_until([&] { return worker.active_send_workers() == 0; }, 3s));
}

// ---------------------------------------------------------------------------
// #2233 item 4 / #3847: the drain worker's next tick proceeds while a prior
// send is artificially stalled - the acceptance bar the two tests above only
// partially cover (they prove stop() decouples; these prove the LIVE worker
// keeps making progress, not just that shutdown is prompt).
// ---------------------------------------------------------------------------

TEST_CASE("item 4: journal maintenance keeps advancing while a send is stalled",
          "[spark][guardian][drain][maint][chaos]") {
    JournalRig rig;
    rig.persist("seed"); // a real durable record, so a page pass has something to place
    rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true); // enqueues "armed"

    std::mutex send_mu;
    std::condition_variable send_cv;
    bool release{false};
    std::atomic<int> invocations{0};
    auto stalling_send = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        std::unique_lock<std::mutex> lk{send_mu};
        send_cv.wait(lk, [&] { return release; });
        return SendResult::Sent;
    };

    GuardianOutboxDrainWorker worker(*rig.rt, stalling_send, /*periodic_bound_ms=*/20,
                                     {.journal = rig.journal, .page_interval = 0ms,
                                      .prune_interval = 0ms});
    worker.start();
    REQUIRE(spin_until([&] { return invocations.load() >= 1; }, 3s)); // the send is now stuck

    // Sample the stamps at the moment the send is confirmed stuck, then prove they advance
    // PAST that point - i.e. a LATER pass ran maintenance - while the send is still blocked.
    // Before the fix this worker thread would itself be inside send(), so neither could move.
    const auto page_at_stall = worker.last_page_success_steady_ms();
    const auto prune_at_stall = worker.last_prune_success_steady_ms();
    CHECK(spin_until([&] { return worker.last_page_success_steady_ms() > page_at_stall; }, 3s));
    CHECK(spin_until([&] { return worker.last_prune_success_steady_ms() > prune_at_stall; }, 3s));

    {
        std::lock_guard<std::mutex> lk{send_mu};
        release = true;
    }
    send_cv.notify_all();
    // Wait for the detached send to actually finish before this frame's captures (send_mu,
    // send_cv, release, invocations) unwind - GuardianOutboxSendExecutor does not join it.
    REQUIRE(spin_until([&] { return worker.active_send_workers() == 0; }, 3s));
    worker.stop();
}

TEST_CASE("item 4: a stalled send is single-flight, never resubmitted while in flight",
          "[spark][guardian][drain][chaos]") {
    JournalRig rig;
    rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);

    std::mutex send_mu;
    std::condition_variable send_cv;
    bool release{false};
    std::atomic<int> invocations{0};
    auto stalling_send = [&](const OutboxEntry&) -> SendResult {
        invocations.fetch_add(1);
        std::unique_lock<std::mutex> lk{send_mu};
        send_cv.wait(lk, [&] { return release; });
        return SendResult::Sent;
    };

    // A fast periodic bound forces many worker ticks while the one send stays stuck - if the
    // wrapper ever resubmitted instead of retaining, this would show up as invocations > 1.
    GuardianOutboxDrainWorker worker(*rig.rt, stalling_send, /*periodic_bound_ms=*/5);
    worker.start();
    REQUIRE(spin_until([&] { return invocations.load() >= 1; }, 3s));

    std::this_thread::sleep_for(150ms); // many ticks at a 5ms periodic bound
    CHECK(invocations.load() == 1);

    {
        std::lock_guard<std::mutex> lk{send_mu};
        release = true;
    }
    send_cv.notify_all();
    REQUIRE(spin_until([&] { return worker.active_send_workers() == 0; }, 3s));
    CHECK(invocations.load() == 1); // still exactly one send for the one entry
    worker.stop();
}

TEST_CASE("#3953 item 3: an internal re-check bounds detection latency for a send that "
          "finishes between the per-attempt offer wait and the periodic backstop",
          "[spark][guardian][drain][chaos]") {
    // A 1-hour periodic bound - matching R4's own config - so only the internal
    // re-check (kGuardianSendRecheckInterval) can make progress inside this test's
    // window; without it, the second entry sits behind loop()'s full 1-hour sleep and
    // this test times out. Default GuardianMaintenanceConfig (journal=nullptr) means no
    // maintenance pass runs regardless of interval, so this exercises send cadence only.
    JournalRig rig;
    std::atomic<int> sent_count{0};
    auto sink = [&](const OutboxEntry&) -> SendResult {
        // Only the FIRST send stalls - long enough to exceed kGuardianSendOfferWait
        // (200ms) several times over, so the margin against scheduling jitter is wide
        // (Fable's review: a tighter stall left too little slack against two 200ms
        // offer waits).
        if (sent_count.fetch_add(1) == 0)
            std::this_thread::sleep_for(1s);
        return SendResult::Sent;
    };
    GuardianOutboxDrainWorker worker(*rig.rt, sink, /*periodic_bound_ms=*/3'600'000);
    worker.start();

    rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    rig.rt->attach_rule("r2", file_spec("/b"), file_exists_rule("r2"), true);

    CHECK(spin_until([&] { return sent_count.load() >= 2; }, 5s));
    worker.stop();
}

TEST_CASE("item 4 regression: a stalled lifecycle send does not starve compliance delivery",
          "[spark][guardian][drain][chaos]") {
    // #3847/#2233 item 4, governance Gate 4 unhappy-path finding UP-1 (BLOCKING, found in
    // this fix's first draft): GuardianOutboxDrainWorker used ONE shared
    // GuardianOutboxSendExecutor across BOTH the lifecycle log and the compliance/health
    // log. A slow-but-succeeding lifecycle send made the compliance drain_log_unlocked call
    // hit the SAME executor's mismatch-orphan branch and return Retain WITHOUT EVER
    // invoking the compliance send - silent, repeated starvation of an entire audit lane,
    // not just the stalled entry. Exercises the real GuardianOutboxDrainWorker wiring
    // (unlike test_guardian_outbox_send_executor.cpp's isolated single-lane coverage),
    // since the bug lived in the TWO-CALL structure this class routes through, not in the
    // executor class itself. Fixed by giving each lane its own executor instance.
    //
    // Lifecycle is stalled INDEFINITELY (CV-gated, not a fixed sleep): a bounded stall long
    // enough to exceed kGuardianSendOfferWait once still lets compliance ship as soon as
    // lifecycle's OWN send finally resolves and its single shared slot frees up - both the
    // single-executor and two-executor designs would eventually satisfy that. The property
    // that actually distinguishes them is compliance shipping WHILE lifecycle's send is
    // STILL provably running - which the single-executor design can never do (the shared
    // slot stays occupied for the send's whole duration, however long that is).
    JournalRig rig;

    std::mutex lifecycle_mu;
    std::condition_variable lifecycle_cv;
    bool release_lifecycle{false};
    std::atomic<int> lifecycle_invocations{0};
    std::atomic<int> compliance_invocations{0};
    auto send = [&](const OutboxEntry& e) -> SendResult {
        if (e.domain == OutboxDomain::Lifecycle) {
            lifecycle_invocations.fetch_add(1);
            std::unique_lock<std::mutex> lk{lifecycle_mu};
            lifecycle_cv.wait(lk, [&] { return release_lifecycle; });
            return SendResult::Sent;
        }
        compliance_invocations.fetch_add(1);
        return SendResult::Sent; // instant
    };

    GuardianOutboxDrainWorker worker(*rig.rt, send, /*periodic_bound_ms=*/20);
    worker.start();

    // Lifecycle entry: attach_rule enqueues an "armed" lifecycle entry immediately.
    rig.rt->attach_rule("r1", file_spec("/a"), file_exists_rule("r1"), true);
    REQUIRE(spin_until([&] { return lifecycle_invocations.load() >= 1; }, 3s)); // now stuck

    // Compliance entry: a real drift verdict on a SEPARATE rule, enqueued only AFTER
    // lifecycle is confirmed stuck - a real drain pass has to run the compliance phase
    // while lifecycle's slot is still occupied for this to prove anything.
    REQUIRE(rig.rt->attach_rule("cmp", file_spec("/cmp"), file_exists_rule("cmp"), true));
    rig.reader->file = read_known(FileSnapshot{.exists = false});
    rig.rt->evaluate_key(spark_key(file_spec("/cmp")), EvalReason::Convergence);

    // THE regression: compliance ships WHILE lifecycle is still parked (never released).
    // Pre-fix (one shared executor) this times out - the compliance send is never even
    // attempted while the shared slot is held by lifecycle's still-running worker.
    CHECK(spin_until([&] { return compliance_invocations.load() >= 1; }, 3s));
    CHECK(lifecycle_invocations.load() == 1); // lifecycle's send never resolved during that wait

    {
        std::lock_guard<std::mutex> lk{lifecycle_mu};
        release_lifecycle = true;
    }
    lifecycle_cv.notify_all();
    REQUIRE(spin_until([&] { return worker.active_send_workers() == 0; }, 3s));
    worker.stop();
}

// ---------------------------------------------------------------------------
// Round 4 (#2345 review): lane fairness under the WALL bound, and the
// headroom/refill contract. Each asserts the mechanism's own observable.
// ---------------------------------------------------------------------------

TEST_CASE("R4: a wall-bound lifecycle drain still lets compliance start",
          "[spark][guardian][drain][maint][r4]") {
    // The count reserve added earlier is DEAD under wall pressure: drain_log_unlocked checks
    // the deadline BEFORE the budget, so once lifecycle consumes the shared wall, compliance
    // returns on entry and never spends its reserved slots. That is the Gate-4 UP-3 detection
    // blackout reached through the other limit (#2345 important-1).
    JournalRig rig;
    // A deep lifecycle backlog whose sends are slow enough to eat the whole wall.
    for (int i = 0; i < 40; ++i) {
        const auto rid = "lc" + std::to_string(i);
        rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true);
    }
    // ...and real compliance traffic queued behind it.
    REQUIRE(rig.rt->attach_rule("cmp", file_spec("/a"), file_exists_rule("cmp"), true));
    for (int i = 0; i < 4; ++i) {
        rig.reader->file = read_known(FileSnapshot{.exists = (i % 2 == 0)});
        rig.rt->evaluate_key(spark_key(file_spec("/a")), EvalReason::Convergence);
    }

    std::atomic<int> lifecycle_sent{0}, compliance_sent{0};
    auto slow_split = [&](const OutboxEntry& e) -> SendResult {
        std::this_thread::sleep_for(15ms); // slow but succeeding
        if (e.domain == OutboxDomain::Lifecycle)
            lifecycle_sent.fetch_add(1);
        else
            compliance_sent.fetch_add(1);
        return SendResult::Sent;
    };

    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 1000;  // NOT the binding constraint
    limits.max_wall = 120ms;    // this is: ~8 slow sends fit in the whole pass
    rig.rt->drain_bounded(slow_split, limits);

    INFO("lifecycle_sent=" << lifecycle_sent.load()
                           << " compliance_sent=" << compliance_sent.load());
    // The observable: compliance got at least one attempt. Without a per-lane wall slice
    // lifecycle consumes the entire deadline and this is 0.
    CHECK(compliance_sent.load() >= 1);
}

TEST_CASE("R4: an oversized head batch does not defer smaller newer batches",
          "[spark][guardian][drain][maint][r4]") {
    // The headroom miss `break`s before page_cursor_ advances, so an oversized head batch pins
    // the rotation and newer smaller batches never page - the B2 starvation class the cursor
    // exists to prevent, reintroduced by the headroom precheck (#2345 minor / head-of-line).
    //
    // This test was HOLLOW for a round. It asked for a 16-entry window, but the window is
    // floored at kMaxJournalEntriesPerBatch, so it silently got 256 - nothing was ever
    // headroom-blocked, the branch under test never ran, and `records_paged >= 2` passed
    // because BOTH batches paged. It now fills the window against its real capacity and
    // asserts the blocking itself, not a number both outcomes satisfy.
    JournalRig rig{/*outbox_capacity=*/1}; // clamped UP to the floor: exactly one max batch
    const std::size_t cap = rig.rt->lifecycle_headroom();
    REQUIRE(cap == kMaxJournalEntriesPerBatch); // the floor, not the requested size

    rig.persist_batch("big", 12);  // oldest, large
    rig.persist_batch("small", 2); // newer, would fit

    // Leave room for the SMALL batch but not the big one.
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < cap - 3; ++i)
        fill.push_back(OutboxEntry::lifecycle("live", 1, "live-" + std::to_string(i),
                                              1'700'000'000'000'000'000, "armed", "file", "n"));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap - 3);
    REQUIRE(rig.rt->lifecycle_headroom() == 3); // deterministic: 3 >= 2 but 3 < 12

    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    INFO("records_paged=" << stats.records_paged
                          << " headroom_blocked=" << stats.headroom_blocked
                          << " min_blocked=" << stats.min_blocked_headroom);
    // The branch's OWN observables: the big batch was blocked and said what it needed...
    CHECK(stats.headroom_blocked);
    CHECK(stats.min_blocked_headroom == 12);
    // ...and the cursor advanced past it so the smaller NEWER batch still got through.
    CHECK(stats.records_paged == 2);
}

TEST_CASE("R4: a refill re-arm does not wait out the periodic bound",
          "[spark][guardian][drain][maint][r4]") {
    // The re-arm sets force_page_ but neither skip_wait nor the signal generation, so an
    // untruncated drain sleeps the FULL periodic bound before acting on it. Existing reconnect
    // tests use a 20 ms bound, which masks the production 5 s latency (#2345 / Sol).
    //
    // The arrangement matters: the window must be genuinely too small for the pending BATCH,
    // not merely occupied. A first draft of this test forced a page that was never
    // headroom-blocked and passed for an unrelated reason - the same hollow-test failure this
    // round exists to stop repeating.
    // The window is floored at kMaxJournalEntriesPerBatch, so a maximum-size batch is the only
    // one that can be headroom-blocked by a nearly-empty window - which is what this needs.
    JournalRig rig{/*outbox_capacity=*/1}; // clamped up to the floor
    rig.persist_batch("b", kMaxJournalEntriesPerBatch); // all-or-nothing: needs the whole window

    StreamLikeSink sink;
    sink.set_stream(false); // link DOWN: sends Retain, so the window cannot drain
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/3'600'000,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 1h});
    // Occupy 4 slots BEFORE the worker starts. Attaching after start() races the seeded boot
    // page: if the enqueues land after that pass reads headroom, the whole batch pages,
    // headroom drops, and GuardianLifecycleLog::enqueue silently DROPS the remaining live
    // entries on backpressure - after which this test waits forever for sends that will never
    // happen. A real ordering race, not load-dependent slop (#2345 Gate 3 QE).
    for (int i = 0; i < 4; ++i) {
        const auto rid = "live" + std::to_string(i);
        REQUIRE(rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true));
    }
    // Deterministic precondition: some room, but not enough for the batch.
    REQUIRE(rig.rt->lifecycle_headroom() == kMaxJournalEntriesPerBatch - 4);
    worker.start();
    REQUIRE(spin_until([&] { return rig.journal->pages() >= 1; }));
    // Pin the link-down half of the scenario before reconnecting. Merely observing
    // the page counter is too early: the worker increments it before the following
    // drain. If this thread raises the link during that gap, the boot drain can send
    // the four live entries and its refill re-arm coalesces with notify() into one
    // forced page. That is correct runtime behaviour, but the old assertion then
    // waited for a third page that the scenario no longer required.
    REQUIRE(spin_until([&] { return sink.retain_count() >= 1; }));
    const auto pages_before = rig.journal->pages();

    // Link returns. The NEXT cycle pages (blocked: the REQUIRE above pins headroom at
    // kMaxJournalEntriesPerBatch - 4, short of the batch's full 256), then its drain ships the
    // 4 live entries and frees room - which is precisely when the refill re-arm should fire.
    sink.set_stream(true);
    worker.notify();
    CHECK(spin_until([&] { return sink.count() >= 4; }, 10s)); // the drain freed the room

    // The observable: a FURTHER page happens off the re-arm alone. No second notify() here -
    // if the re-arm does not itself wake the loop, this waits the hour-long bound and fails.
    CHECK(spin_until([&] { return rig.journal->pages() > pages_before + 1; }, 10s));
    worker.stop();
}

TEST_CASE("R4: a pathological reserve ratio cannot make a pass exceed its wall budget",
          "[spark][guardian][drain][maint][r4]") {
    // The lifecycle wall slice is derived from the reserve ratio via a size_t->int64_t cast.
    // Unclamped, a pathological denominator makes (den-num)/den wrap to a POSITIVE multiplier
    // greater than one, so lifecycle receives a deadline LONGER than the whole pass and the
    // pass overruns its own max_wall - and compliance's restored deadline is already expired
    // (#2345 Gate 2 sec-MEDIUM-1).
    //
    // The observable is pass DURATION, not compliance delivery: at a pathological denominator
    // the ratio degrades to "no reserve" by design, so compliance starvation is expected there
    // and cannot discriminate. CH-3b could not catch this - its count bound binds first and its
    // compliance assertion is gated to sane denominators.
    JournalRig rig;
    for (int i = 0; i < 40; ++i) {
        const auto rid = "r" + std::to_string(i);
        rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true);
    }

    auto slow = [](const OutboxEntry&) -> SendResult {
        std::this_thread::sleep_for(20ms);
        return SendResult::Sent;
    };
    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 1000; // deliberately NOT binding: the wall must be the constraint
    limits.max_wall = 200ms;
    limits.compliance_reserve_den = std::numeric_limits<std::size_t>::max();
    limits.compliance_reserve_num = 1;

    const auto t0 = std::chrono::steady_clock::now();
    const auto out = rig.rt->drain_bounded(slow, limits);
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    INFO("elapsed_ms=" << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()
                       << " sent=" << out.sent);
    // Assert the SEND COUNT, not wall time (same reasoning as CH-3). The pathological
    // denominator would give lifecycle a deadline longer than the whole pass, so it drains the
    // ENTIRE 40-rule backlog; the clamped path stops near the 200ms/20ms ~= 10-send budget.
    // `out.sent < 40` discriminates the two on any runner - a slow box yields FEWER sends, not
    // a longer wall time that a fixed ms bound would trip over.
    (void)elapsed;
    CHECK(out.sent < 40); // did NOT overrun to run the whole backlog
}

TEST_CASE("R4: a completely full window blocks the pass without sweeping the cursor",
          "[spark][guardian][drain][maint][r4]") {
    // The headroom == 0 path was untested (#2345 Gate 3 QE). It must BREAK rather than
    // continue: with no room at all, no batch can fit, and continuing would take outbox_mu_
    // once per candidate and sweep page_cursor_ over the whole rotation while paging nothing,
    // destroying oldest-first replay locality on reconnect.
    JournalRig rig{/*outbox_capacity=*/1}; // clamped up to the kMaxJournalEntriesPerBatch floor
    rig.persist_batch("b", 2);

    // Fill the window completely. Paged directly rather than via attach_rule: the point is a
    // zero-headroom window, not how the entries got there, and the floor makes that a few
    // hundred entries.
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i < kMaxJournalEntriesPerBatch; ++i)
        fill.push_back(OutboxEntry::lifecycle("live", 1, "live-" + std::to_string(i),
                                              1'700'000'000'000'000'000, "armed", "file", "n"));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == kMaxJournalEntriesPerBatch);
    REQUIRE(rig.rt->lifecycle_headroom() == 0);

    const auto stats = rig.journal->page_into_window(*rig.rt, journal_now_ms_for_test());
    CHECK(stats.records_paged == 0);
    CHECK(stats.headroom_blocked);          // the caller must learn a backlog is waiting...
    CHECK(stats.min_blocked_headroom == 2); // ...and how much room it needs
}

TEST_CASE("R4: a lifecycle send slower than the whole pass still lets compliance ship",
          "[spark][guardian][drain][maint][r4]") {
    // The wall slice alone guarantees compliance an opportunity to START only if the in-flight
    // lifecycle send returns before the full deadline. A single send slower than max_wall
    // therefore left compliance's restored deadline permanently in the past: zero compliance
    // sends, every pass, forever - a detection blackout that survived the wall fix
    // (#2345 Gate 4 UP-3).
    JournalRig rig;
    for (int i = 0; i < 6; ++i) {
        const auto rid = "lc" + std::to_string(i);
        REQUIRE(rig.rt->attach_rule(rid, file_spec("/p" + rid), file_exists_rule(rid), true));
    }
    // Real compliance traffic behind it.
    REQUIRE(rig.rt->attach_rule("cmp", file_spec("/cmp"), file_exists_rule("cmp"), true));
    rig.reader->file = read_known(FileSnapshot{.exists = false});
    rig.rt->evaluate_key(spark_key(file_spec("/cmp")), EvalReason::Convergence);

    std::atomic<int> lifecycle_sent{0}, compliance_sent{0};
    auto very_slow_lifecycle = [&](const OutboxEntry& e) -> SendResult {
        if (e.domain == OutboxDomain::Lifecycle) {
            lifecycle_sent.fetch_add(1);
            std::this_thread::sleep_for(120ms); // ONE send longer than the entire pass budget
        } else {
            compliance_sent.fetch_add(1);
        }
        return SendResult::Sent;
    };

    GuardianSparkRuntime::DrainLimits limits;
    limits.max_entries = 100;
    limits.max_wall = 60ms; // deliberately shorter than a single lifecycle send
    rig.rt->drain_bounded(very_slow_lifecycle, limits);

    INFO("lifecycle_sent=" << lifecycle_sent.load()
                           << " compliance_sent=" << compliance_sent.load());
    CHECK(lifecycle_sent.load() >= 1);  // lifecycle overran the pass, as designed
    CHECK(compliance_sent.load() >= 1); // and compliance STILL got its guaranteed attempt
}

// ---------------------------------------------------------------------------
// #2345 Gate 5 chaos scenarios. Each targets a LOSS channel - a way an audit
// record that was durably written never reaches the server and is then deleted -
// rather than a latency one. All three were observed RED before their fix.
// ---------------------------------------------------------------------------

TEST_CASE("CH-7: required headroom counts net-new records, not raw batch size",
          "[spark][guardian][journal][chaos]") {
    // A batch most of whose records are ALREADY in the send window needs room only for the
    // rest. Charging the raw batch size made the window's own occupants the reason the batch
    // could not be placed: the worker then re-armed on a headroom figure that could not
    // arrive while those same records held the space, and the batch's one unsent record was
    // eventually pruned. RED before the fix: blocked_for_headroom, added == 0.
    auto reader = std::make_shared<FakeReader>();
    GuardianSparkRuntime rt{reader, std::make_shared<FakeBackend>()};
    const std::size_t cap = rt.lifecycle_headroom();
    REQUIRE(cap >= kMaxJournalEntriesPerBatch);

    auto mk = [](std::size_t i) {
        return OutboxEntry::lifecycle("r", 1, "e" + std::to_string(i), 1'700'000'000'000'000'000,
                                      "armed", "file", "n");
    };
    std::vector<OutboxEntry> fill; // leave exactly ONE slot
    for (std::size_t i = 0; i + 1 < cap; ++i)
        fill.push_back(mk(i));
    REQUIRE(rt.try_page_batch(std::move(fill)).added == cap - 1);
    REQUIRE(rt.lifecycle_headroom() == 1);

    std::vector<OutboxEntry> overlapping; // 3 already windowed + 1 genuinely new
    overlapping.push_back(mk(0));
    overlapping.push_back(mk(1));
    overlapping.push_back(mk(2));
    overlapping.push_back(mk(cap)); // never seen
    const auto out = rt.try_page_batch(std::move(overlapping));
    CHECK_FALSE(out.blocked_for_headroom); // one slot is all it ever needed
    CHECK(out.added == 1);
    CHECK(out.required == 0);
}

TEST_CASE("CH-7b: a fully-windowed batch reports neither work nor a blockage",
          "[spark][guardian][journal][chaos]") {
    // The degenerate end of the same bug: every record already present, zero headroom. Read as
    // "blocked", it manufactured an unsatisfiable re-arm target out of a batch with nothing
    // left to do.
    auto reader = std::make_shared<FakeReader>();
    GuardianSparkRuntime rt{reader, std::make_shared<FakeBackend>()};
    const std::size_t cap = rt.lifecycle_headroom();
    auto mk = [](std::size_t i) {
        return OutboxEntry::lifecycle("r", 1, "e" + std::to_string(i), 1'700'000'000'000'000'000,
                                      "armed", "file", "n");
    };
    std::vector<OutboxEntry> full;
    for (std::size_t i = 0; i < cap; ++i)
        full.push_back(mk(i));
    std::vector<OutboxEntry> again{full.begin(), full.begin() + 2};
    REQUIRE(rt.try_page_batch(std::move(full)).added == cap);
    REQUIRE(rt.lifecycle_headroom() == 0);

    const auto out = rt.try_page_batch(std::move(again));
    CHECK(out.added == 0);
    CHECK_FALSE(out.blocked_for_headroom);
    CHECK(out.required == 0);
}

TEST_CASE("CH-5: a forward clock step does not delete the whole journal in one pass",
          "[spark][guardian][journal][chaos]") {
    // Age eviction is anchored to the wall clock, so ONE forward jump - a VM restored from
    // snapshot, a bad NTP correction - puts every batch past retention simultaneously and
    // retention deletes the entire durable audit trail in a single transaction, before any of
    // it has been replayed. RED before the fix: evicted == 3 and nothing survives.
    JournalRig rig;
    // Anchor on the real clock: persist() stamps each batch with system_clock, so a synthetic
    // baseline would make the batches look like the future and retention would never bite.
    const std::int64_t kT = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    // Latch the boot prune-before-page barrier while the journal is still empty, so the page
    // below is an ordinary steady-state replay rather than a boot pass carrying its own prune.
    REQUIRE(rig.journal->page_into_window(*rig.rt, kT).records_paged == 0);
    rig.persist_batch("a", 2);
    rig.persist_batch("b", 2);
    rig.persist_batch("c", 2);

    REQUIRE(rig.journal->prune(kT).evicted == 0); // establishes the clock baseline
    REQUIRE(rig.journal->clock_jump_skips() == 0);

    constexpr std::int64_t kThirtyDays = 30LL * 86400 * 1000;
    const auto jumped = rig.journal->prune(kT + kThirtyDays);
    CHECK(jumped.read_ok);
    CHECK(jumped.evicted == 0); // declined: the trail survives the anomaly
    CHECK(rig.journal->clock_jump_skips() == 1);

    // The trail is still there to be replayed, which is the whole point.
    const auto paged = rig.journal->page_into_window(*rig.rt, kT + kThirtyDays);
    CHECK(paged.records_paged == 6);

    // The pass right after the jump no longer LOOKS like a step (last_prune_now_ms_ has already
    // re-anchored to the jumped value), but the journal is still fully expired under the new
    // clock - a fact set (wipe, no step) `jumped` never recorded. It must decline again on its
    // own merits (#2573 GJ half) rather than ride `jumped`'s still-set latch into a silent
    // eviction.
    const auto settling = rig.journal->prune(kT + kThirtyDays + 1000);
    CHECK(settling.evicted == 0);
    CHECK(rig.journal->clock_jump_skips() == 2);

    // ...and the guard is not a permanent disabling of retention: the SAME fact shape recurring
    // is a suppressed repeat, so this pass finally proceeds.
    const auto after = rig.journal->prune(kT + kThirtyDays + 2000);
    CHECK(after.evicted == 3);
    CHECK(rig.journal->clock_jump_skips() == 2); // not re-counted a third time
}

TEST_CASE("CH-5b: one retention pass cannot age out the whole journal",
          "[spark][guardian][journal][chaos]") {
    // The pacing half of CH-5. Even once the jump is accepted as the new normal, a single pass
    // must not delete everything: ageing has to be slow enough that replay and an operator
    // alert still overlap it. RED before the cap: evicted == kMaxAgeEvictionsPerPass + 10 on
    // the first accepting pass, i.e. the entire journal.
    JournalRig rig;
    const std::int64_t kT = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    constexpr std::size_t kBatches = kMaxAgeEvictionsPerPass + 10;
    for (std::size_t i = 0; i < kBatches; ++i)
        rig.persist_batch("b" + std::to_string(i), 1);

    constexpr std::int64_t kThirtyDays = 30LL * 86400 * 1000;
    REQUIRE(rig.journal->prune(kT).evicted == 0);                // baseline
    REQUIRE(rig.journal->prune(kT + kThirtyDays).evicted == 0);  // the jump itself: declined
    // As in CH-5: the pass right after the jump presents a DISTINCT fact set (wipe, no step)
    // and declines again on its own merits before the cap-paced drain proceeds (#2573 GJ half).
    REQUIRE(rig.journal->prune(kT + kThirtyDays + 1000).evicted == 0);

    const auto accepted = rig.journal->prune(kT + kThirtyDays + 2000);
    CHECK(accepted.evicted == kMaxAgeEvictionsPerPass); // paced, not wholesale
    const auto rest = rig.journal->prune(kT + kThirtyDays + 3000);
    CHECK(rest.evicted == 10); // and the remainder follows on the next pass
}

TEST_CASE("a fully-windowed batch is never read as blocked by the paging pre-check",
          "[spark][guardian][journal][chaos]") {
    // The journal's own pre-check sized a candidate by its RAW entry count, which is the exact
    // accounting error try_page_batch was fixed for, surviving one layer up. A batch already
    // fully in the send window was then reported blocked on a phantom shortage, which the
    // worker's refill re-arm reads as "a backlog is waiting on drain progress" when there is
    // no backlog at all. RED before the fix: headroom_blocked is true.
    constexpr std::size_t kBig = kMaxJournalEntriesPerBatch;
    JournalRig rig{kBig + 8};
    rig.persist_batch("b", kBig);

    std::int64_t now = 1'700'000'000'000;
    REQUIRE(rig.journal->page_into_window(*rig.rt, now).records_paged == kBig);
    // Now occupy the rest, so headroom is far below the batch's raw size while every one of its
    // records is already windowed - it needs no room at all.
    while (rig.rt->lifecycle_headroom() > 3)
        REQUIRE(rig.rt->try_page_batch({OutboxEntry::lifecycle(
                    "live", 1, "live-" + std::to_string(rig.rt->lifecycle_headroom()),
                    1'700'000'000'000'000'000, "armed", "file", "n")}).added == 1);

    now += 10'000;
    const auto stats = rig.journal->page_into_window(*rig.rt, now);
    CHECK(stats.records_paged == 0);     // nothing to do...
    CHECK_FALSE(stats.headroom_blocked); // ...and emphatically not blocked
}

TEST_CASE("CH-5c: a backward clock step retains evidence and still bounds the journal",
          "[spark][guardian][journal][chaos]") {
    // A backward step is the opposite hazard to a forward one. An earlier round clamped the
    // cutoff upward with the previous reading to stop retention "stalling", on the theory that
    // a stalled retention lets the journal climb to its write ceiling and start REFUSING new
    // records. That premise was wrong, and the clamp cost real evidence: the pass AFTER a
    // correction still evicted against the known-bad reading.
    //
    // What must actually hold is both halves of this test: a backward step RETAINS (the safe
    // direction for an audit trail, and the clock's own correction takes effect immediately),
    // and the journal is still bounded, because the count ceiling is computed with no clock at
    // all. RED before the fix: the first half evicts 2.
    JournalRig rig;
    const std::int64_t kT = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    rig.persist_batch("a", 1);
    rig.persist_batch("b", 1);
    constexpr std::int64_t kThirtyDays = 30LL * 86400 * 1000;

    REQUIRE(rig.journal->prune(kT).evicted == 0);
    REQUIRE(rig.journal->prune(kT + kThirtyDays).evicted == 0); // forward jump: declined once

    // Clock steps BACKWARD, to well before the batches were written.
    const auto back = rig.journal->prune(kT - kThirtyDays);
    CHECK(back.evicted == 0); // nothing is "too old" against the corrected clock: retained

    // ...and the journal is still bounded while the clock is wrong, by a rule that never reads
    // it. This is what makes removing the clamp safe rather than merely kinder: a retention
    // window that cannot bite is not the only thing holding the journal down.
    rig.persist_batch("c", 1); // three batches now
    rig.journal->set_retention_limits_for_test(/*days=*/100000, /*max_batches=*/2,
                                               /*max_bytes=*/std::size_t(-1),
                                               /*max_quarantine=*/100);
    const auto capped = rig.journal->prune(kT - kThirtyDays); // clock still wrong
    CHECK(capped.evicted >= 1);                               // the COUNT ceiling still trims
    CHECK(rig.journal->journal_batch_count() <= 2);
}

TEST_CASE("a page-side read failure is counted separately from retention's",
          "[spark][guardian][journal]") {
    // Retention succeeding while replay is stalled means records are deleted on schedule and
    // shipped never. Without its own counter that state is invisible. RED before the fix:
    // page_read_failures stays 0.
    JournalRig rig;
    rig.persist_batch("a", 1);
    std::int64_t now = 1'700'000'000'000;
    REQUIRE(rig.journal->page_into_window(*rig.rt, now).records_paged == 1); // latch boot prune
    REQUIRE(rig.journal->page_read_failures() == 0);

    rig.journal->inject_page_read_failures_for_test(1);
    now += 10'000;
    const auto stats = rig.journal->page_into_window(*rig.rt, now);
    CHECK(stats.records_paged == 0);
    CHECK(rig.journal->page_read_failures() == 1);
    CHECK(rig.journal->prune_failures() == 0); // retention is fine; only replay is stalled
}

TEST_CASE("a page deferred by an empty rate limiter says so, so the kick is not dropped",
          "[spark][guardian][drain][maint]") {
    // A reconnect kick that lands while the paging token bucket is empty was swallowed: the
    // pass returns clean and does no work, so the worker's "re-arm if the forced page failed"
    // never fired and replay waited out a full cadence interval after the link came back. The
    // pass now reports WHY it did nothing, which is what the re-arm condition
    // `forced_page && (!ok || deferred_no_token)` keys off. RED before the fix: the flag does
    // not exist and a dry pass is indistinguishable from an idle one.
    JournalRig rig;
    rig.persist_batch("b", 2);
    StreamLikeSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/3'600'000,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 1h});
    // Never started: this drives the maintenance seam directly so the assertion is about the
    // pass result, not about racing a running loop.
    const auto first = worker.maintenance_once({.page = true});
    CHECK(first.page_attempted);
    CHECK_FALSE(first.deferred_no_token); // the startup burst had a token
    CHECK(first.records_paged == 2);

    // Burn the burst. A token is charged only for NET-NEW work, so each pass needs something
    // fresh to place - re-paging an already-windowed batch is deliberately free. The bucket
    // refills at kJournalPageRefillPerSec (0.1/s), so within a test it does not come back.
    for (int i = 0; i < 12; ++i)
        rig.persist_batch("f" + std::to_string(i), 1);

    bool went_dry = false;
    for (int i = 0; i < 20 && !went_dry; ++i) {
        const auto r = worker.maintenance_once({.page = true});
        if (r.deferred_no_token) {
            went_dry = true;
            CHECK(r.page_attempted);
            CHECK(r.records_paged == 0); // it did nothing...
        }
    }
    CHECK(went_dry); // ...and said WHY, which is what the re-arm keys off
}

TEST_CASE("a full window reports the SMALLEST pending requirement, not the first seen",
          "[spark][guardian][journal]") {
    // The worker re-arms a page when lifecycle_headroom() reaches min_blocked_headroom, so that
    // figure has to be the smallest thing actually waiting. Reporting the first-encountered
    // batch's requirement made the re-arm wait for room nothing needed - replay stalled a whole
    // cadence interval for a 1-entry batch sitting behind a 256-entry one.
    //
    // The third candidate is the point of this test. It is ALREADY fully windowed, so it needs
    // zero room; an earlier version of the scan folded that zero into the minimum and then
    // discarded the whole result, silently keeping the head's 256. A first draft of this test
    // used only blocked candidates and stayed green against that defect - the fully-windowed
    // one is what makes it real, and it is the common case in production, because live
    // arm/disarm records are both windowed and journal candidates.
    constexpr std::size_t kBig = kMaxJournalEntriesPerBatch;
    JournalRig rig{1}; // clamped up to the floor
    rig.persist_batch("a-big", kBig); // oldest, so it is met first in the rotation
    rig.persist_batch("b-small", 1);  // the smallest thing genuinely pending
    rig.persist_batch("c-windowed", 1); // ...and this one needs no room at all

    std::vector<OutboxEntry> fill; // window full, and it CONTAINS c-windowed's record
    fill.push_back(OutboxEntry::lifecycle("c-windowed-0", 1, "e-c-windowed-0",
                                          1'700'000'000'000'000'000, "armed", "file", "n"));
    for (std::size_t i = 1; i < kBig; ++i)
        fill.push_back(OutboxEntry::lifecycle("live", 1, "live-" + std::to_string(i),
                                              1'700'000'000'000'000'000, "armed", "file", "n"));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == kBig);
    REQUIRE(rig.rt->lifecycle_headroom() == 0);

    const auto stats = rig.journal->page_into_window(*rig.rt, 1'700'000'000'000);
    CHECK(stats.headroom_blocked);
    CHECK(stats.min_blocked_headroom == 1); // b-small, not the head's 256 and not c-windowed's 0
}

TEST_CASE("a batch repeating an event_id is sized by its distinct records",
          "[spark][guardian][journal]") {
    // The paging pre-check sizes a candidate by its NET-NEW records. Counting per entry rather
    // than per distinct event_id let a row that repeats an id overstate its requirement by up
    // to a whole batch, so a batch needing one slot could be deferred as though it needed many.
    // persist() never writes such a row, which is exactly why this needs writing by hand.
    // RED without the de-duplication: the batch is reported blocked and pages nothing.
    JournalRig rig;
    const auto key = journal_batch_key(1'700'000'000'000LL, "dup", 1);
    const std::string row =
        R"({"v":4,"ts_ms":1700000000000,"entries":[)"
        R"({"rule_id":"r","event_id":"dup","kind":"armed","guard_type":"file","rule_name":"n",)"
        R"("generation":1,"enqueued_ns":1700000000000000000},)"
        R"({"rule_id":"r","event_id":"dup","kind":"armed","guard_type":"file","rule_name":"n",)"
        R"("generation":1,"enqueued_ns":1700000000000000000},)"
        R"({"rule_id":"r","event_id":"dup","kind":"armed","guard_type":"file","rule_name":"n",)"
        R"("generation":1,"enqueued_ns":1700000000000000000}]})";
    REQUIRE(rig.kv->set(kJournalNamespace, key, row));

    // Leave exactly ONE free slot: enough for the single distinct record, far short of three.
    const std::size_t cap = rig.rt->lifecycle_headroom();
    std::vector<OutboxEntry> fill;
    for (std::size_t i = 0; i + 1 < cap; ++i)
        fill.push_back(OutboxEntry::lifecycle("live", 1, "live-" + std::to_string(i),
                                              1'700'000'000'000'000'000, "armed", "file", "n"));
    REQUIRE(rig.rt->try_page_batch(std::move(fill)).added == cap - 1);
    REQUIRE(rig.rt->lifecycle_headroom() == 1);

    const auto stats = rig.journal->page_into_window(*rig.rt, 1'700'000'000'000);
    CHECK(stats.records_paged == 1); // one distinct record placed in the one free slot
    CHECK_FALSE(stats.headroom_blocked);
}

TEST_CASE("CH-8: a backward clock step does not freeze replay while retention keeps deleting",
          "[spark][guardian][journal][chaos]") {
    // The paging rate limiter refilled only when now_ms exceeded its last reading, so a
    // backward step - a VM restored from an old snapshot, an NTP correction - parked replay
    // for the whole size of the step. Retention's count and byte ceilings are clock-free and
    // kept deleting throughout. Replay stopped with deletion continuing is the unsent-loss
    // shape this journal exists to prevent, and it was the one case the bucket's own
    // "DELAYS, never skips" comment did not cover.
    // RED before the fix: still deferred_no_token an hour of new-clock time later.
    JournalRig rig;
    constexpr std::int64_t kT = 1'700'000'000'000;
    for (int i = 0; i < 12; ++i)
        rig.persist_batch("b" + std::to_string(i), 1);

    // Spend the startup burst so the bucket, not the burst, governs the next pass.
    bool exhausted = false;
    for (int i = 0; i < 20 && !exhausted; ++i)
        exhausted = rig.journal->page_into_window(*rig.rt, kT).deferred_no_token;
    REQUIRE(exhausted);

    // The clock steps BACK an hour, then advances normally on the new reading. Re-baselining
    // costs the one pass that observes the step - it grants no tokens, so the pacing bound is
    // untouched - and replay must resume immediately after on the new clock. Five passes at
    // 20 s is 100 s of new-clock time; the unfixed code needs the full hour to elapse before
    // it refills at all, so it is still deferred here.
    constexpr std::int64_t kBack = kT - 3'600'000;
    bool resumed = false;
    std::size_t paged = 0;
    for (int i = 1; i <= 5 && !resumed; ++i) {
        const auto st = rig.journal->page_into_window(*rig.rt, kBack + i * 20'000);
        resumed = !st.deferred_no_token;
        paged += st.records_paged;
    }
    CHECK(resumed); // replay resumed on the new baseline, not an hour later
    CHECK(paged > 0);
}

TEST_CASE("CH-9: a failed retention delete does not strand the rows it meant to remove",
          "[spark][guardian][journal][chaos]") {
    // The replay cutoff was published before the delete that justified it. When the delete
    // then failed, the rows were still on disk but replay classified them expired: neither
    // shipped nor removed until some later pass happened to succeed, while a counter
    // documented to mean "this endpoint's clock moved" kept incrementing.
    // RED before the fix: records_paged == 0 - the rows are present and unreachable.
    JournalRig rig;
    const std::int64_t kT = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::system_clock::now().time_since_epoch())
                                .count();
    REQUIRE(rig.journal->page_into_window(*rig.rt, kT).records_paged == 0); // latch the barrier
    for (int i = 0; i < 3; ++i)
        rig.persist_batch("b" + std::to_string(i), 1);

    constexpr std::int64_t kEightDays = 8LL * 86400 * 1000;
    REQUIRE(rig.journal->prune(kT).evicted == 0);                 // baseline the clock
    REQUIRE(rig.journal->prune(kT + kEightDays).evicted == 0);    // the jump itself: declined

    // The accepting pass tries to delete and the store refuses.
    rig.journal->inject_delete_failures_for_test(1);
    const auto failed = rig.journal->prune(kT + kEightDays + 1000);
    CHECK(failed.evicted == 0);

    // The rows survived the failure, so replay must still be able to reach them.
    const auto paged = rig.journal->page_into_window(*rig.rt, kT + kEightDays + 2000);
    CHECK(paged.records_paged == 3);
}

TEST_CASE("CH-10: a delivered batch is not re-offered on the ordinary cadence pass",
          "[spark][guardian][journal][chaos]") {
    // A delivered batch leaves the in-memory window the instant it ships, and window membership
    // was the ONLY test for "already delivered" - so the next cadence pass saw it as net-new,
    // re-paged it and re-sent it, for as long as retention kept the batch. Per agent that spends
    // the entire paging budget re-delivering what the server already has; across a fleet it is a
    // permanent floor of redundant ingest proportional to endpoint count.
    // RED before the fix: records_paged == 2 on the second cadence pass.
    JournalRig rig;
    constexpr std::int64_t kT = 1'700'000'000'000;
    const std::size_t empty_headroom = rig.rt->lifecycle_headroom(); // window empty at rest
    rig.persist_batch("a", 2);

    REQUIRE(rig.journal->page_into_window(*rig.rt, kT).records_paged == 2);
    REQUIRE(rig.rt->lifecycle_headroom() == empty_headroom - 2);

    // Ship it, so the entries leave the window and only the durable sent-label records that
    // delivery happened at all.
    GuardianSparkRuntime::DrainLimits lim;
    lim.compliance_reserve_num = 0;
    lim.compliance_reserve_den = 0;
    rig.rt->drain_bounded([](const OutboxEntry&) { return SendResult::Sent; }, lim);
    // Precondition, not decoration: if the entries were still windowed the pass below would
    // place nothing for the ordinary membership reason and the test would pass vacuously.
    REQUIRE(rig.rt->lifecycle_headroom() == empty_headroom);
    auto rows = rig.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    rig.journal->mark_batch_sent(rows->front().key);

    // The ordinary cadence pass must leave it alone...
    const auto cadence = rig.journal->page_into_window(*rig.rt, kT + 30'000);
    CHECK(cadence.records_paged == 0);
    CHECK(cadence.skipped_already_sent == 1);

    // ...but a FORCED pass - boot replay or a reconnect kick, the events after which an
    // in-flight send may have been lost - must still re-offer it. That is the safety net, kept
    // where it can pay.
    const auto forced =
        rig.journal->page_into_window(*rig.rt, kT + 60'000, /*replay_sent=*/true);
    CHECK(forced.records_paged == 2);
    CHECK(forced.skipped_already_sent == 0);
}

TEST_CASE("CH-11: a failed sent-label scan falls back to re-offering, and says so",
          "[spark][guardian][journal][chaos]") {
    // Skipping delivered batches depends on reading the sent-labels. If that read fails the
    // pass must fall back to re-offering everything - redelivery is free, a wrongly-skipped
    // batch is lost - and it must SAY so, because an agent whose scan fails every pass
    // silently returns to the fleet-wide redelivery floor this change exists to remove.
    // RED before the fallback is counted: sent_scan_failed stays false and the counter is 0.
    JournalRig rig;
    constexpr std::int64_t kT = 1'700'000'000'000;
    rig.persist_batch("a", 2);
    REQUIRE(rig.journal->page_into_window(*rig.rt, kT).records_paged == 2);

    GuardianSparkRuntime::DrainLimits lim;
    lim.compliance_reserve_num = 0;
    lim.compliance_reserve_den = 0;
    rig.rt->drain_bounded([](const OutboxEntry&) { return SendResult::Sent; }, lim);
    auto rows = rig.kv->list_entries(yuzu::agent::kJournalNamespace, yuzu::agent::kBatchKeyPrefix);
    REQUIRE(rows.has_value());
    rig.journal->mark_batch_sent(rows->front().key);
    // Precondition: with a WORKING scan this batch is skipped. Without it the assertions below
    // could not tell the fallback from an ordinary miss.
    REQUIRE(rig.journal->page_into_window(*rig.rt, kT + 30'000).skipped_already_sent == 1);

    rig.journal->inject_sent_scan_failures_for_test(1);
    const auto degraded = rig.journal->page_into_window(*rig.rt, kT + 60'000);
    CHECK(degraded.sent_scan_failed);
    CHECK(rig.journal->sent_scan_failures() == 1);
    CHECK(degraded.skipped_already_sent == 0); // skipped nothing...
    CHECK(degraded.records_paged == 2);        // ...and re-offered, the safe direction
}

// ── Maintenance phase + forced-page jitter (C0 flip-checklist item 12) ─────────

TEST_CASE("guardian_jitter_offset is uniform over [0, upper) and safe at zero",
          "[spark][guardian][drain][maint]") {
    std::mt19937 rng(12345);
    for (int i = 0; i < 500; ++i) {
        const auto off = guardian_jitter_offset(rng, 30'000ms);
        CHECK(off >= 0ms);
        CHECK(off < 30'000ms); // half-open: an offset of a full interval is a whole skipped pass
    }
    // A zero interval means "no cadence", not "divide by zero".
    CHECK(guardian_jitter_offset(rng, 0ms) == 0ms);
    CHECK(guardian_jitter_offset(rng, -5ms) == 0ms);

    // Two agents seeded differently must not draw the same SEQUENCE - the entire point.
    // Compared as a sequence, not a single draw: uniform_int_distribution's mapping is
    // implementation-defined, so "seed 1 and seed 2 differ on their first draw" is a property
    // of one STL and one collision (~1/30000) away from a cross-toolchain failure that no
    // code change would explain.
    std::mt19937 a(1), b(2);
    std::vector<std::chrono::milliseconds> sa, sb;
    for (int i = 0; i < 8; ++i) {
        sa.push_back(guardian_jitter_offset(a, 30'000ms));
        sb.push_back(guardian_jitter_offset(b, 30'000ms));
    }
    CHECK(sa != sb);
}

TEST_CASE("jitter DEFERS a forced page rather than dropping it",
          "[spark][guardian][drain][maint]") {
    // The forced page is the correlated one: a gateway bounce or a mass restart hands every
    // agent a boot/reconnect replay - a full journal scan plus a token burst - in the same
    // second. Jitter must spread that WITHOUT ever losing a kick, so the deadline is observed
    // through the seam rather than by asserting a wall-clock upper bound on the work.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 1h, // only a FORCED page can fire
                                      .prune_interval = 1h,
                                      .jitter = true});
    worker.seed_jitter_rng_for_test(4242);
    worker.start();

    // The boot force is deferred within the (hour-long) page interval, so it is still pending
    // and still carries a deadline well into the future.
    const auto deadline = worker.force_page_not_before_ms_for_test();
    CHECK(deadline > 0);
    std::this_thread::sleep_for(40ms); // many periodic bounds: a DROP would show up here
    CHECK(rig.journal->pages() == 0);
    CHECK(worker.force_page_not_before_ms_for_test() == deadline); // still pending, not consumed

    worker.stop();
}

TEST_CASE("a jittered forced page still runs once its deadline passes",
          "[spark][guardian][drain][maint]") {
    // The other half of the contract: deferral is not suppression. With a tiny page interval
    // the boot force's offset is bounded by that interval, so the pass must happen - and the
    // deadline must be cleared once it is consumed, or a later kick would inherit it.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 10ms, // jitter bound: offset < 10ms
                                      .prune_interval = 1h,
                                      .jitter = true});
    worker.seed_jitter_rng_for_test(99);
    worker.start();
    // Spin on the OBSERVABLE (a page happened), never on a wall-clock upper bound: a slower
    // runner takes longer to get here, it does not make the assertion wrong.
    const auto give_up = std::chrono::steady_clock::now() + 10s;
    while (rig.journal->pages() == 0 && std::chrono::steady_clock::now() < give_up)
        std::this_thread::sleep_for(1ms);
    CHECK(rig.journal->pages() >= 1);
    worker.stop();
}

TEST_CASE("jitter is OFF unless asked for, so every other cadence test is deterministic",
          "[spark][guardian][drain][maint]") {
    // Enablement is explicit (production wiring calls set_maintenance_jitter). Inferring it
    // from some other configured field would silently defer the boot page in tests that
    // depend on it running immediately, turning a real assertion into a hollow pass.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 1h,
                                      .prune_interval = 1h});
    CHECK(worker.force_page_not_before_ms_for_test() == 0);
    worker.start();
    const auto give_up = std::chrono::steady_clock::now() + 10s;
    while (rig.journal->pages() == 0 && std::chrono::steady_clock::now() < give_up)
        std::this_thread::sleep_for(1ms);
    CHECK(rig.journal->pages() >= 1); // the boot force ran immediately, undeferred
    CHECK(worker.force_page_not_before_ms_for_test() == 0);
    worker.stop();
}

TEST_CASE("a kick storm cannot keep postponing an already-deferred forced page",
          "[spark][guardian][drain][maint]") {
    // First kick wins. Re-drawing the deadline on every notify() would let a FLAPPING link
    // postpone the forced replay indefinitely: each reconnect lands a fresh offset, so the
    // pass that re-offers sent-labelled batches (whose in-flight send may have been lost)
    // keeps being pushed back by exactly the event it exists to respond to. One draw is all
    // the fleet spread needs. RED if notify() sets the deadline unconditionally: the observed
    // deadline moves with each kick.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/5,
                                     {.journal = rig.journal,
                                      .page_interval = 1h, // only a forced page can fire
                                      .prune_interval = 1h,
                                      .jitter = true});
    worker.seed_jitter_rng_for_test(7);
    // No start(): the loop must not consume the force while the deadlines are compared, so
    // this exercises notify()'s own state transition rather than racing the worker thread.
    worker.notify();
    const auto first = worker.force_page_not_before_ms_for_test();
    CHECK(first > 0);
    for (int i = 0; i < 20; ++i)
        worker.notify();
    CHECK(worker.force_page_not_before_ms_for_test() == first); // monotone, not re-drawn
}

TEST_CASE("jitter: concurrent notify() against a live jittered loop is race-free",
          "[spark][guardian][drain][maint]") {
    // TSan coverage for the shape the other jitter tests deliberately avoid. The kick-storm
    // test omits start() so it can compare deadlines deterministically, and the deferral test
    // starts the worker but never notifies - so the new sig_->mu critical sections
    // (notify() writing force_page_not_before_ms_ and drawing from jitter_rng_, while the
    // loop reads both to compute its wait deadline and to consume the force) were never
    // executed CONCURRENTLY under the sanitizer (governance Gate 3 cpp-safety).
    //
    // Asserts liveness only. Any timing assertion here would be a wall-clock upper bound,
    // which is the standing flake source on a contended runner.
    JournalRig rig;
    rig.persist("r1");
    CollectingSink sink;
    GuardianOutboxDrainWorker worker(*rig.rt, std::ref(sink), /*periodic_bound_ms=*/2,
                                     {.journal = rig.journal,
                                      .page_interval = 5ms, // tiny, so forces land constantly
                                      .prune_interval = 5ms,
                                      .jitter = true});
    worker.seed_jitter_rng_for_test(31337);
    worker.start();

    std::atomic<bool> stop_kicking{false};
    std::thread kicker([&] {
        while (!stop_kicking.load(std::memory_order_relaxed))
            worker.notify();
    });

    // Spin on the observable rather than sleeping a fixed time: a slower runner takes longer
    // to get here, it does not make the assertion wrong.
    const auto give_up = std::chrono::steady_clock::now() + 10s;
    while (rig.journal->pages() == 0 && std::chrono::steady_clock::now() < give_up)
        std::this_thread::sleep_for(1ms);

    stop_kicking.store(true, std::memory_order_relaxed);
    kicker.join();
    worker.stop();

    CHECK(rig.journal->pages() >= 1); // the loop stayed live under a continuous kick storm
    // A stopped worker leaves no pending deferral that a later observer could misread.
    CHECK(worker.force_page_not_before_ms_for_test() >= 0);
}
