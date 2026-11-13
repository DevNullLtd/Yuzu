// test_pg_collation_recheck.cpp: the repeat of the collation version check (hourly when settled,
// every minute when not; pg_collation_recheck.{hpp,cpp}). The check is injected, so `tick()` is
// driven directly and the loop runs with a tiny interval; nothing waits an hour. One [pg] case
// drives a real database: the recorded version of a throwaway database is overwritten to force a
// mismatch and then put back, and the recheck must follow both.

#include "pg_collation_recheck.hpp"

#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include "../test_helpers.hpp"
#include "../test_log_capture.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using namespace yuzu::server;
using yuzu::server::pg::CollationLast;
using yuzu::server::pg::CollationReport;
using yuzu::server::pg::CollationState;
using yuzu::server::pg::CollationVerdict;

namespace {

CollationReport report_of(CollationVerdict v) {
    CollationReport r;
    r.verdict = v;
    r.database = "yuzu";
    r.recorded = "2.36";
    r.actual = v == CollationVerdict::Mismatch ? "2.39" : "2.36";
    r.failure = v == CollationVerdict::Unreadable ? "scripted failure" : "";
    return r;
}

/// A check that answers from a script (the last answer repeats) and counts its calls.
struct ScriptedCheck {
    std::mutex mu;
    std::deque<CollationVerdict> script;
    CollationVerdict last{CollationVerdict::Ok};
    std::atomic<int> calls{0};
    /// steady_clock time of the first call, in nanoseconds since its epoch; 0 until called.
    std::atomic<std::int64_t> first_call_ns{0};

    PgCollationRecheck::CheckFn fn() {
        return [this] {
            std::int64_t unset = 0;
            first_call_ns.compare_exchange_strong(
                unset, std::chrono::duration_cast<std::chrono::nanoseconds>(
                           std::chrono::steady_clock::now().time_since_epoch())
                           .count());
            calls.fetch_add(1);
            std::lock_guard<std::mutex> lk(mu);
            if (!script.empty()) {
                last = script.front();
                script.pop_front();
            }
            return report_of(last);
        };
    }
};

bool has_sample(yuzu::MetricsRegistry& m) {
    const std::string text = "\n" + m.serialize();
    return text.find(std::string("\n") + pg::kCollationMismatchGauge + " ") != std::string::npos;
}

/// The exposition text of the gauge's sample line ("<name> <value>"), empty when there is none.
/// Unlike `gauge()`, reading it does not create the series, so it can prove a series exists.
std::string sample_line(yuzu::MetricsRegistry& m) {
    const std::string text = "\n" + m.serialize();
    const std::string prefix = std::string("\n") + pg::kCollationMismatchGauge + " ";
    const auto at = text.find(prefix);
    if (at == std::string::npos)
        return {};
    const auto from = at + 1;
    return text.substr(from, text.find('\n', from) - from);
}

/// Counts occurrences of `needle` in captured log text.
std::size_t occurrences(const std::string& logs, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = logs.find(needle); at != std::string::npos; at = logs.find(needle, at + 1))
        ++n;
    return n;
}

double gauge(yuzu::MetricsRegistry& m) {
    return m.gauge(pg::kCollationMismatchGauge).value();
}

double count(yuzu::MetricsRegistry& m, const char* result) {
    return m.counter(pg::kCollationCheckCounter, {{"result", result}}).value();
}

} // namespace

TEST_CASE("PgCollationRecheck: tick follows Mismatch, then Ok, and an unreadable tick leaves the "
          "gauge alone",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    ScriptedCheck check;
    PgCollationRecheck recheck(check.fn(), &m, 1h);

    check.script = {CollationVerdict::Mismatch};
    recheck.tick();
    REQUIRE(has_sample(m));
    CHECK(gauge(m) == 1.0);

    check.script = {CollationVerdict::Unreadable};
    recheck.tick();
    CHECK(gauge(m) == 1.0); // unchanged: the unreadable tick neither cleared nor invented anything
    CHECK(recheck.state() == CollationState{CollationLast::Mismatch, true});

    check.script = {CollationVerdict::Ok};
    recheck.tick();
    CHECK(gauge(m) == 0.0);
    CHECK(recheck.state() == CollationState{CollationLast::Ok, false});

    check.script = {CollationVerdict::Unreadable};
    recheck.tick();
    CHECK(gauge(m) == 0.0);

    check.script = {CollationVerdict::NotApplicable};
    recheck.tick();
    CHECK_FALSE(has_sample(m));

    CHECK(count(m, "mismatch") == 1);
    CHECK(count(m, "unreadable") == 2);
    CHECK(count(m, "ok") == 1);
    CHECK(count(m, "not_applicable") == 1);
    CHECK(recheck.ticks() == 5);
}

TEST_CASE("PgCollationRecheck: the state seeded from the start-time check is respected",
          "[pg_collation][recheck]") {
    // One Mismatch tick, with the given seed; returns the number of ERROR lines it logged. The
    // ERROR is logged on ENTERING a mismatch, so a recheck that was told the start-time check
    // already concluded Mismatch must stay silent, and one that was told nothing must log it.
    const auto errors_logged = [](CollationState seed) {
        yuzu::test::LogCapture cap(spdlog::level::err);
        yuzu::MetricsRegistry m;
        ScriptedCheck check;
        check.last = CollationVerdict::Mismatch;
        PgCollationRecheck recheck(check.fn(), &m, 1h, seed);
        recheck.tick();
        CHECK(recheck.state() == CollationState{CollationLast::Mismatch, false});
        CHECK(gauge(m) == 1.0);
        cap.stop();
        return occurrences(cap.text(), "[error]");
    };
    CHECK(errors_logged(CollationState{CollationLast::Mismatch, false}) == 0);
    CHECK(errors_logged(CollationState{}) == 1);
}

TEST_CASE("PgCollationRecheck: a throwing check is an unreadable tick, never an escape",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    PgCollationRecheck recheck([]() -> CollationReport { throw 42; }, &m, 1h);
    REQUIRE_NOTHROW(recheck.tick());
    CHECK(count(m, "unreadable") == 1);
    CHECK_FALSE(has_sample(m));
}

TEST_CASE("PgCollationRecheck: the first recheck is one interval after start, then it repeats",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    ScriptedCheck check;
    // A whole second: the lower bound below is a floor on the wait, so a late wake-up (an
    // oversleeping thread on a loaded box) can never fail it, and the "no check yet" assertion has
    // a wide margin.
    constexpr auto kInterval = 1000ms;
    PgCollationRecheck recheck(check.fn(), &m, kInterval);
    const auto started = std::chrono::steady_clock::now();
    recheck.start();
    recheck.start(); // idempotent: still one thread
    std::this_thread::sleep_for(50ms);
    CHECK(check.calls.load() == 0); // waits first, then ticks: no check at start
    for (int i = 0; i < 600 && check.calls.load() < 2; ++i)
        std::this_thread::sleep_for(10ms);
    CHECK(check.calls.load() >= 2); // and it repeats
    // The first check came at least one interval after start (measured at the check itself).
    const auto first = std::chrono::steady_clock::time_point(
        std::chrono::nanoseconds(check.first_call_ns.load()));
    REQUIRE(check.first_call_ns.load() != 0);
    CHECK(first - started >= kInterval);

    const auto t = std::chrono::steady_clock::now();
    recheck.stop();
    CHECK(std::chrono::steady_clock::now() - t < 2s);
}

TEST_CASE("PgCollationRecheck: stop is idempotent and sticky", "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    ScriptedCheck check;
    PgCollationRecheck recheck(check.fn(), &m, 20ms);
    recheck.start();
    for (int i = 0; i < 400 && check.calls.load() < 1; ++i)
        std::this_thread::sleep_for(10ms);
    REQUIRE(check.calls.load() >= 1);
    recheck.stop();

    const int after = check.calls.load();
    recheck.start(); // sticky: no restart after stop
    recheck.tick();  // and a direct tick after stop does nothing
    std::this_thread::sleep_for(150ms); // several intervals of the restarted loop, were there one
    CHECK(check.calls.load() == after);
    recheck.stop(); // idempotent
}

TEST_CASE("PgCollationRecheck: stop interrupts the interval wait and the pool is not touched "
          "afterwards",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    ScriptedCheck check;
    // An interval far longer than the test: only the stop flag can end the wait.
    PgCollationRecheck recheck(check.fn(), &m, std::chrono::hours(24));
    recheck.start();
    std::this_thread::sleep_for(50ms);
    const auto t = std::chrono::steady_clock::now();
    recheck.stop();
    CHECK(std::chrono::steady_clock::now() - t < 2s);
    CHECK(check.calls.load() == 0);
    std::this_thread::sleep_for(100ms);
    CHECK(check.calls.load() == 0);
}

TEST_CASE("PgCollationRecheck: stop waits out a check in flight and reports nothing from it",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    std::atomic<bool> in_check{false};
    std::atomic<bool> release{false};
    std::atomic<bool> entered{false};       // the stopper thread is about to call stop()
    std::atomic<bool> stop_returned{false};
    PgCollationRecheck recheck(
        [&]() -> CollationReport {
            in_check.store(true);
            while (!release.load())
                std::this_thread::sleep_for(5ms);
            return report_of(CollationVerdict::Mismatch);
        },
        &m, 10ms);
    std::thread stopper;
    // Declared after the recheck and the stopper, so it runs first on EVERY exit path, a failed
    // REQUIRE included: it lets the check in flight finish and joins the stopper, so the
    // recheck's destructor never joins a loop thread that is still spinning.
    struct Finish {
        std::atomic<bool>& release;
        std::thread& stopper;
        ~Finish() {
            release.store(true);
            if (stopper.joinable())
                stopper.join();
        }
    } finish{release, stopper};

    recheck.start();
    for (int i = 0; i < 400 && !in_check.load(); ++i)
        std::this_thread::sleep_for(5ms);
    REQUIRE(in_check.load());
    stopper = std::thread([&] {
        entered.store(true);
        recheck.stop();
        stop_returned.store(true);
    });
    // Handshake, then a margin: the stopper has certainly reached stop() and had time to request
    // it, so stop() is now waiting for the check in flight rather than not yet called.
    for (int i = 0; i < 400 && !entered.load(); ++i)
        std::this_thread::sleep_for(5ms);
    REQUIRE(entered.load());
    std::this_thread::sleep_for(250ms);
    CHECK_FALSE(stop_returned.load()); // stop() is still waiting for the check
    release.store(true);
    stopper.join();
    CHECK(stop_returned.load());
    // The check finished after stop() was requested: its report is dropped.
    CHECK_FALSE(has_sample(m));
    CHECK(recheck.ticks() == 0);
}

// request_stop(): the signal half of stop(), so ServerImpl::stop() can tell the loop to wind down
// at the start of teardown and join it later (a check in flight can take about 15 s). The wait is
// bounded everywhere, and a failure never leaves a spinning loop thread behind (the Finish guard).

TEST_CASE("PgCollationRecheck: request_stop returns while a check is in flight, drops its report "
          "and ends the loop",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    std::atomic<bool> in_check{false};
    std::atomic<bool> release{false};
    std::atomic<bool> request_returned{false};
    std::atomic<int> calls{0};
    PgCollationRecheck recheck(
        [&]() -> CollationReport {
            calls.fetch_add(1);
            in_check.store(true);
            while (!release.load())
                std::this_thread::sleep_for(5ms);
            return report_of(CollationVerdict::Mismatch);
        },
        &m, 10ms);
    std::thread requester;
    // Runs first on every exit path: lets the check finish and joins the requester.
    struct Finish {
        std::atomic<bool>& release;
        std::thread& requester;
        ~Finish() {
            release.store(true);
            if (requester.joinable())
                requester.join();
        }
    } finish{release, requester};

    recheck.start();
    for (int i = 0; i < 400 && !in_check.load(); ++i)
        std::this_thread::sleep_for(5ms);
    REQUIRE(in_check.load());
    // On its own thread, so a request_stop() that wrongly joined would be a failed assertion below
    // and not a hung test: the check cannot finish until `release`.
    requester = std::thread([&] {
        recheck.request_stop();
        request_returned.store(true);
    });
    for (int i = 0; i < 400 && !request_returned.load(); ++i)
        std::this_thread::sleep_for(5ms);
    CHECK(request_returned.load()); // returned while the check is still running: no join
    release.store(true);
    requester.join();
    // The report of the check that was in flight when stop was requested is dropped, and the loop
    // starts no further check although its interval (10 ms) has long passed.
    std::this_thread::sleep_for(150ms);
    CHECK(calls.load() == 1);
    CHECK_FALSE(has_sample(m));
    CHECK(recheck.ticks() == 0);
    recheck.stop(); // the join, now immediate
    CHECK(calls.load() == 1);
}

// The wake-up of the interval wait is observed through the join: stop() is request_stop() plus a
// join, so the 24 hour interval case above only returns because the wait was woken. A process
// thread count was tried and removed: it is not stable under sanitizers (the runtime can start its
// own background thread) or under load (a joined thread can linger in the task list).

TEST_CASE("PgCollationRecheck: request_stop then stop joins, and every further call is a no-op",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    ScriptedCheck check;
    PgCollationRecheck recheck(check.fn(), &m, 20ms);
    recheck.start();
    for (int i = 0; i < 400 && check.calls.load() < 1; ++i)
        std::this_thread::sleep_for(10ms);
    REQUIRE(check.calls.load() >= 1);
    recheck.request_stop();
    recheck.request_stop(); // idempotent
    const auto t = std::chrono::steady_clock::now();
    recheck.stop();
    CHECK(std::chrono::steady_clock::now() - t < 2s);
    const int after = check.calls.load();
    recheck.stop();         // idempotent
    recheck.request_stop(); // and still fine after the join
    recheck.start();        // sticky: no restart
    recheck.tick();
    std::this_thread::sleep_for(100ms);
    CHECK(check.calls.load() == after);
}

TEST_CASE("PgCollationRecheck: request_stop before start makes start a no-op",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    ScriptedCheck check;
    PgCollationRecheck recheck(check.fn(), &m, 5ms);
    recheck.request_stop();
    recheck.start();
    std::this_thread::sleep_for(100ms); // twenty intervals of a loop that must not exist
    CHECK(check.calls.load() == 0);
    recheck.tick(); // a direct tick after stop was requested does nothing either
    CHECK(check.calls.load() == 0);
    recheck.stop(); // nothing to join
}

TEST_CASE("PgCollationRecheck: request_stop from several threads while the loop runs",
          "[pg_collation][recheck]") {
    yuzu::MetricsRegistry m;
    ScriptedCheck check;
    PgCollationRecheck recheck(check.fn(), &m, 1ms);
    recheck.start();
    for (int i = 0; i < 400 && check.calls.load() < 2; ++i)
        std::this_thread::sleep_for(5ms);
    REQUIRE(check.calls.load() >= 2);

    std::atomic<bool> go{false};
    std::vector<std::thread> requesters;
    struct Finish {
        std::atomic<bool>& go;
        std::vector<std::thread>& threads;
        ~Finish() {
            go.store(true);
            for (auto& t : threads)
                if (t.joinable())
                    t.join();
        }
    } finish{go, requesters};
    for (int i = 0; i < 4; ++i)
        requesters.emplace_back([&] {
            while (!go.load())
                std::this_thread::yield();
            for (int k = 0; k < 200; ++k)
                recheck.request_stop();
        });
    go.store(true);
    for (auto& t : requesters)
        t.join();
    recheck.stop();
    const int after = check.calls.load();
    std::this_thread::sleep_for(50ms);
    CHECK(check.calls.load() == after); // the loop is gone and stays gone
}

TEST_CASE("PgCollationRecheck against a real database: a forced Mismatch, then Ok again",
          "[pg][pg_collation][recheck]") {
    YUZU_REQUIRE_PG_DB(db);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());

    const CollationReport first = pg::check_collation_version(pool);
    INFO("verdict=" << pg::to_string(first.verdict) << " failure=" << first.failure
                    << " recorded=" << first.recorded << " actual=" << first.actual);
    if (first.verdict == CollationVerdict::NotApplicable)
        SKIP("this PostgreSQL has no recorded collation version for the test database (C/POSIX "
             "locale or a server before 15)");
    // Skip only on a genuine mismatch: both versions known and different. A Mismatch verdict with
    // an empty field would be a fetch defect and must fail the REQUIRE below, not hide here.
    if (first.verdict == CollationVerdict::Mismatch && !first.recorded.empty() &&
        !first.actual.empty() && first.recorded != first.actual)
        SKIP("this cluster's template database already has a collation version mismatch; a clean "
             "start is needed");
    REQUIRE(first.verdict == CollationVerdict::Ok);

    const auto set_recorded = [&](const std::string& version) {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(),
                                   "UPDATE pg_database SET datcollversion = $1 "
                                   "WHERE datname = current_database()",
                                   std::vector<std::string>{version});
        if (res.status() != PGRES_COMMAND_OK)
            SKIP("the test role cannot update pg_database (not a superuser): "
                 << PQerrorMessage(lease.get()));
    };

    yuzu::MetricsRegistry m;
    CollationState seeded;
    pg::report_collation_check(first, &m, seeded); // what the constructor-time check does
    // gauge() would create the series, so prove it exists and reads 0 from the exposition text.
    REQUIRE(sample_line(m) == std::string(pg::kCollationMismatchGauge) + " 0");
    PgCollationRecheck recheck([&pool] { return pg::check_collation_version(pool); }, &m, 1h,
                               seeded);

    set_recorded("0.0.bogus");
    recheck.tick();
    CHECK(gauge(m) == 1.0);
    CHECK(count(m, "mismatch") == 1);

    set_recorded(first.actual); // what REFRESH COLLATION VERSION does
    recheck.tick();
    CHECK(gauge(m) == 0.0);
    CHECK(count(m, "ok") == 2); // the start-time check and this recheck
    CHECK(recheck.state() == CollationState{CollationLast::Ok, false});
}

TEST_CASE("PgCollationRecheck: the state follows every report",
          "[pg_collation][recheck]") {
    ScriptedCheck check;
    check.script = {CollationVerdict::Mismatch, CollationVerdict::Unreadable, CollationVerdict::Ok,
                    CollationVerdict::Mismatch};
    PgCollationRecheck recheck(check.fn(), nullptr, 1h, CollationState{});
    recheck.tick();
    CHECK(recheck.state().last == CollationLast::Mismatch); // Mismatch
    recheck.tick();
    CHECK(recheck.state().last == CollationLast::Mismatch); // Unreadable: the last conclusive answer stands
    CHECK(recheck.state().unreadable);
    recheck.tick();
    CHECK(recheck.state().last == CollationLast::Ok); // Ok
    recheck.tick();
    CHECK(recheck.state().last == CollationLast::Mismatch); // Mismatch again
}

TEST_CASE("PgCollationRecheck: an unsettled state is rechecked sooner than the hourly interval",
          "[pg_collation][recheck]") {
    // The long interval is far beyond the test's wait; only the short (unsettled) interval can fire.
    constexpr auto kLong = 1h;
    constexpr auto kShort = 20ms;
    SECTION("seeded Mismatch: the loop uses the short interval until a check clears it") {
        ScriptedCheck check;
        check.script = {CollationVerdict::Mismatch, CollationVerdict::Ok};
        CollationState seed;
        seed.last = CollationLast::Mismatch;
        PgCollationRecheck recheck(check.fn(), nullptr, kLong, seed, kShort);
        recheck.start();
        for (int i = 0; i < 500 && check.calls.load() < 2; ++i)
            std::this_thread::sleep_for(10ms);
        REQUIRE(check.calls.load() >= 2); // Mismatch, then Ok, each after the short interval
        for (int i = 0; i < 200 && recheck.state().last == CollationLast::Mismatch; ++i)
            std::this_thread::sleep_for(10ms);
        CHECK(recheck.state().last == CollationLast::Ok);
        // The Ok put the loop back on the long interval: no further check arrives.
        std::this_thread::sleep_for(100ms);
        const int settled = check.calls.load();
        std::this_thread::sleep_for(150ms);
        CHECK(check.calls.load() == settled);
        CHECK(settled == 2);
        recheck.stop();
    }
    SECTION("seeded Ok: the short interval is never used") {
        ScriptedCheck check;
        check.script = {CollationVerdict::Ok};
        CollationState seed;
        seed.last = CollationLast::Ok;
        PgCollationRecheck recheck(check.fn(), nullptr, kLong, seed, kShort);
        recheck.start();
        std::this_thread::sleep_for(200ms);
        CHECK(check.calls.load() == 0);
        recheck.stop();
    }
    SECTION("seeded NotApplicable: the short interval is never used") {
        ScriptedCheck check;
        check.script = {CollationVerdict::Ok};
        CollationState seed;
        seed.last = CollationLast::NotApplicable;
        PgCollationRecheck recheck(check.fn(), nullptr, kLong, seed, kShort);
        recheck.start();
        std::this_thread::sleep_for(200ms);
        CHECK(check.calls.load() == 0);
        recheck.stop();
    }
    SECTION("a default-constructed state (nothing conclusive, nothing unreadable) is unsettled") {
        ScriptedCheck check;
        check.script = {CollationVerdict::Ok};
        PgCollationRecheck recheck(check.fn(), nullptr, kLong, CollationState{}, kShort);
        recheck.start();
        for (int i = 0; i < 500 && check.calls.load() < 1; ++i)
            std::this_thread::sleep_for(10ms);
        CHECK(check.calls.load() >= 1); // the short interval fired; an hour never would
        recheck.stop();
    }
    SECTION("no conclusive verdict yet (the start-time check was unreadable): short interval "
            "until one arrives, then the long one") {
        // No verdict has concluded in this state, so the first conclusive one must not be an hour
        // away. Unreadable keeps the state unsettled; the Mismatch that follows is seen within one
        // short interval.
        ScriptedCheck check;
        check.script = {CollationVerdict::Unreadable, CollationVerdict::Unreadable,
                        CollationVerdict::Mismatch};
        CollationState seed; // last == None: nothing conclusive yet
        seed.unreadable = true;
        PgCollationRecheck recheck(check.fn(), nullptr, kLong, seed, kShort);
        recheck.start();
        for (int i = 0; i < 500 && check.calls.load() < 3; ++i)
            std::this_thread::sleep_for(10ms);
        REQUIRE(check.calls.load() >= 3);
        for (int i = 0; i < 200 && recheck.state().last != CollationLast::Mismatch; ++i)
            std::this_thread::sleep_for(10ms);
        CHECK(recheck.state().last == CollationLast::Mismatch);
        recheck.stop();
    }
    SECTION("a conclusive Ok after an unreadable spell puts the loop back on the long interval") {
        ScriptedCheck check;
        check.script = {CollationVerdict::Unreadable, CollationVerdict::Ok};
        CollationState seed;
        seed.last = CollationLast::Ok;
        seed.unreadable = true; // the latest check was unreadable
        PgCollationRecheck recheck(check.fn(), nullptr, kLong, seed, kShort);
        recheck.start();
        for (int i = 0; i < 500 && check.calls.load() < 2; ++i)
            std::this_thread::sleep_for(10ms);
        REQUIRE(check.calls.load() >= 2);
        std::this_thread::sleep_for(100ms);
        const int settled = check.calls.load();
        std::this_thread::sleep_for(150ms);
        CHECK(check.calls.load() == settled);
        CHECK(settled == 2);
        recheck.stop();
    }
    SECTION("the faster of the two intervals wins, never a slower mismatch interval") {
        ScriptedCheck check;
        check.script = {CollationVerdict::Mismatch};
        CollationState seed;
        seed.last = CollationLast::Mismatch;
        // The test's own interval (20 ms) is shorter than the default Mismatch interval (60 s).
        PgCollationRecheck recheck(check.fn(), nullptr, 20ms, seed);
        recheck.start();
        for (int i = 0; i < 500 && check.calls.load() < 2; ++i)
            std::this_thread::sleep_for(10ms);
        CHECK(check.calls.load() >= 2);
        recheck.stop();
    }
}

// The documented repair, run for real. A forced mismatch sets the gauge to 1; then the statements
// the runbook gives (REINDEX DATABASE CONCURRENTLY, ALTER DATABASE ... REFRESH COLLATION VERSION)
// run against the throwaway database, and the recheck loop, with nothing faked after the first
// UPDATE, must see the repair and clear the gauge by itself. Kills: a gauge that never clears, a
// loop that stays on the hourly interval while a mismatch stands, and a runbook statement that
// does not do what the docs say.
TEST_CASE("PgCollationRecheck against a real database: the documented reindex clears the gauge "
          "within the Mismatch interval",
          "[pg][pg_collation][recheck]") {
    YUZU_REQUIRE_PG_DB(db);
    pg::PgPool pool{{.conninfo = db.dsn(), .size = 3}};
    REQUIRE(pool.valid());

    const CollationReport first = pg::check_collation_version(pool);
    if (first.verdict == CollationVerdict::NotApplicable)
        SKIP("this PostgreSQL has no recorded collation version for the test database");
    if (first.verdict == CollationVerdict::Mismatch)
        SKIP("this cluster's template database already has a collation version mismatch");
    REQUIRE(first.verdict == CollationVerdict::Ok);

    // The documented cadence while a mismatch stands.
    CHECK(std::chrono::milliseconds(kCollationMismatchRecheckInterval).count() == 60000);

    auto run_sql = [&](const std::string& sql) {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(), sql.c_str(), std::vector<std::string>{});
        INFO(sql << " -> " << PQerrorMessage(lease.get()));
        return res.status() == PGRES_COMMAND_OK;
    };
    std::string name;
    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(), "SELECT current_database()",
                                   std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        name = PQgetvalue(res.get(), 0, 0);
    }
    const std::string quoted = pg::quote_identifier(name);

    // The opt-in run at the production cadence (a minute): YUZU_TEST_REAL_CADENCE=1. The default
    // run uses 200 ms so the suite does not wait a minute.
    const bool real_cadence = std::getenv("YUZU_TEST_REAL_CADENCE") != nullptr;
    const std::chrono::milliseconds production(kCollationMismatchRecheckInterval);
    const auto mismatch_interval = real_cadence ? production : std::chrono::milliseconds(200);

    // A forced mismatch (the one faked step), seen by the start-time check.
    if (!run_sql("UPDATE pg_database SET datcollversion = '0.0.bogus' WHERE datname = "
                 "current_database()"))
        SKIP("the test role cannot update pg_database (not a superuser)");
    yuzu::MetricsRegistry m;
    CollationState state;
    pg::report_collation_check(pg::check_collation_version(pool), &m, state);
    REQUIRE(state.last == CollationLast::Mismatch);
    REQUIRE(gauge(m) == 1.0);

    PgCollationRecheck recheck([&pool] { return pg::check_collation_version(pool); }, &m, 1h,
                               state, mismatch_interval);
    recheck.start();

    // While broken the gauge stays at 1 across several rechecks (it does not flap).
    std::this_thread::sleep_for(real_cadence ? 2s : 700ms);
    CHECK(gauge(m) == 1.0);

    // The documented repair, step 2 and step 3, verbatim from server-admin.md.
    REQUIRE(run_sql("REINDEX DATABASE CONCURRENTLY " + quoted));
    REQUIRE(run_sql("ALTER DATABASE " + quoted + " REFRESH COLLATION VERSION"));
    const auto repaired = std::chrono::steady_clock::now();

    // Nothing else is touched: the recheck loop alone must clear the gauge.
    const auto budget = mismatch_interval + 5s;
    while (recheck.state().last == CollationLast::Mismatch &&
           std::chrono::steady_clock::now() - repaired < budget)
        std::this_thread::sleep_for(20ms);
    const auto cleared_after = std::chrono::steady_clock::now() - repaired;
    INFO("cleared after "
         << std::chrono::duration_cast<std::chrono::milliseconds>(cleared_after).count()
         << " ms (mismatch interval " << mismatch_interval.count() << " ms)");
    CHECK(recheck.state().last == CollationLast::Ok);
    CHECK(cleared_after <= mismatch_interval + 2s);
    CHECK(gauge(m) == 0.0);

    // The refresh really recorded the operating system's version (not a faked UPDATE).
    const CollationReport after = pg::check_collation_version(pool);
    CHECK(after.verdict == CollationVerdict::Ok);
    CHECK(after.recorded == first.actual);

    // And back on the long interval: no further checks while healthy.
    std::this_thread::sleep_for(150ms); // the report that cleared the gauge finishes counting
    const auto ticks = recheck.ticks();
    std::this_thread::sleep_for(mismatch_interval * 3 > 1s ? 1s : mismatch_interval * 3);
    CHECK(recheck.ticks() == ticks);
    recheck.stop();
}

namespace {

/// `dsn` re-pointed at another login role: every key except user and password is kept.
std::string dsn_as_role(const std::string& dsn, const std::string& user,
                        const std::string& password) {
    char* errmsg = nullptr;
    // Owned from the moment it is returned, so nothing between here and the end of the function
    // (the string appends can throw bad_alloc) can leak it.
    const std::unique_ptr<PQconninfoOption, decltype(&PQconninfoFree)> opts{
        PQconninfoParse(dsn.c_str(), &errmsg), &PQconninfoFree};
    const std::unique_ptr<char, decltype(&PQfreemem)> err_owner{errmsg, &PQfreemem};
    if (opts == nullptr)
        return {};
    const auto quoted = [](const char* v) {
        std::string out = "'";
        for (const char* p = v; *p != '\0'; ++p) {
            if (*p == '\\' || *p == '\'')
                out += '\\';
            out += *p;
        }
        return out + "'";
    };
    std::string out;
    for (const PQconninfoOption* o = opts.get(); o->keyword != nullptr; ++o) {
        const std::string_view key = o->keyword;
        if (o->val == nullptr || key == "user" || key == "password")
            continue;
        out += std::string(key) + "=" + quoted(o->val) + " ";
    }
    return out + "user=" + quoted(user.c_str()) + " password=" + quoted(password.c_str());
}

} // namespace

// The check and the documented repair as a login role that is NOT a superuser, which is what a
// managed PostgreSQL gives the application (the provider keeps the superuser). Two roles are
// tried: a plain connect-only role, which must be able to READ the verdict (so the server's
// verdict is reported) but not repair; and the database owner, who must be able to run the repair
// statements and see the gauge clear. Only the forced mismatch needs the superuser; it is done on
// the admin connection. Kills: a check or repair that quietly needs superuser, and a mismatch that
// never clears for the role an operator actually has.
TEST_CASE("PgCollationRecheck as a non-superuser: the verdict is readable and the owner can "
          "repair it",
          "[pg][pg_collation][recheck][nonsuper]") {
    YUZU_REQUIRE_PG_DB(db);
    pg::PgPool admin{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(admin.valid());
    const auto sql = [](pg::PgPool& pool, const std::string& text) {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(), text.c_str(), std::vector<std::string>{});
        INFO(text << " -> " << PQerrorMessage(lease.get()));
        return res.status() == PGRES_COMMAND_OK;
    };
    const auto text_of = [](pg::PgPool& pool, const char* query) {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto res = pg::exec_params(lease.get(), query, std::vector<std::string>{});
        REQUIRE(res.status() == PGRES_TUPLES_OK);
        return std::string(PQgetvalue(res.get(), 0, 0));
    };

    const CollationReport first = pg::check_collation_version(admin);
    if (first.verdict == CollationVerdict::NotApplicable)
        SKIP("this PostgreSQL has no recorded collation version for the test database");
    if (first.verdict == CollationVerdict::Mismatch)
        SKIP("this cluster's template database already has a collation version mismatch");
    REQUIRE(first.verdict == CollationVerdict::Ok);

    const std::string admin_name = text_of(admin, "SELECT current_user");
    const std::string db_name = text_of(admin, "SELECT current_database()");
    constexpr const char* kIsSuper =
        "SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user";
    if (text_of(admin, kIsSuper) != "true")
        SKIP("the test role is not a superuser, so it cannot create the roles or force a mismatch");

    // Roles are cluster-wide, so name them after the throwaway database (itself unique) and drop
    // them on every exit path. Ownership goes back to the admin first: a role that owns a
    // database cannot be dropped.
    const std::string role = "ns_" + db_name.substr(db_name.size() > 40 ? db_name.size() - 40 : 0);
    const std::string quoted_role = pg::quote_identifier(role);
    const std::string quoted_db = pg::quote_identifier(db_name);
    constexpr const char* kPassword = "yuzu_test_pw";
    struct RoleGuard {
        std::function<void()> undo;
        ~RoleGuard() {
            try {
                undo();
            } catch (...) {
            }
        }
    } role_guard{[&] {
        sql(admin, "ALTER DATABASE " + quoted_db + " OWNER TO " + pg::quote_identifier(admin_name));
        sql(admin, "DROP OWNED BY " + quoted_role);
        sql(admin, "DROP ROLE IF EXISTS " + quoted_role);
    }};

    // A table the admin owns and an index on its text key: what the repair has to rebuild.
    REQUIRE(sql(admin, "CREATE TABLE ci_probe (k text PRIMARY KEY)"));
    REQUIRE(sql(admin, "CREATE ROLE " + quoted_role + " LOGIN NOSUPERUSER NOCREATEDB PASSWORD '" +
                           kPassword + "'"));
    REQUIRE(sql(admin, "GRANT CONNECT ON DATABASE " + quoted_db + " TO " + quoted_role));

    pg::PgPool role_pool{{.conninfo = dsn_as_role(db.dsn(), role, kPassword), .size = 3}};
    REQUIRE(role_pool.valid());
    REQUIRE(text_of(role_pool, kIsSuper) == "false");

    // 1. Connect-only role: reads the verdict, both ways.
    const CollationReport as_role = pg::check_collation_version(role_pool);
    INFO("failure=" << as_role.failure);
    REQUIRE(as_role.verdict == CollationVerdict::Ok);
    CHECK(as_role.recorded == first.actual);
    CHECK(as_role.actual == first.actual);

    REQUIRE(sql(admin, "UPDATE pg_database SET datcollversion = '0.0.bogus' WHERE datname = "
                       "current_database()"));
    const CollationReport broken = pg::check_collation_version(role_pool);
    INFO("failure=" << broken.failure);
    REQUIRE(broken.verdict == CollationVerdict::Mismatch);
    CHECK(broken.recorded == "0.0.bogus");
    CHECK(broken.actual == first.actual);

    // It cannot repair (the statements need the database's owner) and cannot fake the version.
    CHECK_FALSE(sql(role_pool, "ALTER DATABASE " + quoted_db + " REFRESH COLLATION VERSION"));
    CHECK_FALSE(sql(role_pool, "REINDEX DATABASE CONCURRENTLY " + quoted_db));
    CHECK_FALSE(sql(role_pool, "UPDATE pg_database SET datcollversion = '1' WHERE datname = "
                               "current_database()"));
    CHECK(pg::check_collation_version(role_pool).verdict == CollationVerdict::Mismatch);

    // 2. The database owner, still not a superuser: the whole runbook, then the gauge clears.
    REQUIRE(sql(admin, "ALTER DATABASE " + quoted_db + " OWNER TO " + quoted_role));
    yuzu::MetricsRegistry m;
    CollationState state;
    pg::report_collation_check(pg::check_collation_version(role_pool), &m, state);
    REQUIRE(state.last == CollationLast::Mismatch);
    PgCollationRecheck recheck([&role_pool] { return pg::check_collation_version(role_pool); }, &m,
                               1h, state, 200ms);
    recheck.start();
    std::this_thread::sleep_for(500ms);
    CHECK(gauge(m) == 1.0);

    REQUIRE(sql(role_pool, "REINDEX DATABASE CONCURRENTLY " + quoted_db));
    REQUIRE(sql(role_pool, "ALTER DATABASE " + quoted_db + " REFRESH COLLATION VERSION"));
    const auto repaired = std::chrono::steady_clock::now();
    while (recheck.state().last == CollationLast::Mismatch &&
           std::chrono::steady_clock::now() - repaired < 5s)
        std::this_thread::sleep_for(20ms);
    CHECK(recheck.state().last == CollationLast::Ok);
    CHECK(gauge(m) == 0.0);
    recheck.stop();

    const CollationReport after = pg::check_collation_version(role_pool);
    CHECK(after.verdict == CollationVerdict::Ok);
    CHECK(after.recorded == first.actual);
}
