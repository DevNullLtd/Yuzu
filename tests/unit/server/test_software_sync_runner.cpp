/**
 * test_software_sync_runner.cpp — the shared fleet-run sequence behind POST /api/v1/hardware/sync
 * and the MCP tool sync_hardware_software: one cooldown and one in-flight lease for both callers,
 * a bounded partition, audit before dispatch. Faked seams only; no process, clock or store.
 */

#include "software_sync_runner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::server;
namespace ss = yuzu::server::software_sync;

namespace {

struct Rig {
    std::int64_t wall = 1'700'000'000;
    std::int64_t mono = 10'000;
    std::vector<std::string> resolved_ids{"d0", "d1", "d2"};
    int version_lookups = 0;
    int dispatch_calls = 0;
    bool persist_ok = true;
    std::vector<std::string> events;
    std::function<void()> during_dispatch;

    ss::Env env() {
        ss::Env e;
        e.resolve = [this](const auth::Session&, const ss::Selector&) {
            ss::Resolved r;
            r.status = ss::Resolved::Status::Ok;
            r.caller_unfiltered = true;
            r.ids = resolved_ids;
            return r;
        };
        e.dispatch = [this](const auth::Session&, const std::vector<std::string>& ids) {
            ++dispatch_calls;
            events.push_back("dispatch");
            // One-shot: take the hook out first so it can re-enter the runner without recursing.
            if (auto hook = std::move(during_dispatch)) {
                during_dispatch = nullptr;
                hook();
            }
            return ss::DispatchResult{ids.size(), "__sync__-test"};
        };
        e.caller_unfiltered = [](const auth::Session&) { return true; };
        e.agent_version = [this](const std::string&) -> std::optional<std::string> {
            ++version_lookups;
            return std::string("0.13.1");
        };
        e.now = [this] { return wall; };
        e.mono_ms = [this] { return mono; };
        return e;
    }
    ss::Audit audit() {
        return {[this](std::string_view r, std::string_view, const std::string&, const std::string&) {
                    events.push_back("note:" + std::string(r));
                },
                [this](std::string_view r, std::string_view, const std::string&, const std::string&) {
                    events.push_back("persist:" + std::string(r));
                    return persist_ok;
                }};
    }
};

auth::Session session_of(std::string name) {
    auth::Session s;
    s.username = std::move(name);
    return s;
}

const ss::Selector kFleet{DispatchArm::Broadcast, ""};

} // namespace

TEST_CASE("sync runner: audit is persisted before the send, then the run is accepted",
          "[server][software_sync][runner]") {
    Rig rig;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), kFleet, rig.audit());
    CHECK(out.status == ss::Status::Accepted);
    CHECK(out.http == 202);
    CHECK(rig.events == std::vector<std::string>{"persist:requested", "dispatch"});
}

TEST_CASE("sync runner: a failed audit write sends nothing", "[server][software_sync][runner][security]") {
    Rig rig;
    rig.persist_ok = false;
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), kFleet, rig.audit());
    CHECK(out.status == ss::Status::AuditUnavailable);
    CHECK(out.http == 503);
    CHECK(rig.dispatch_calls == 0);
}

TEST_CASE("sync runner: the cooldown is per operator and shared by every caller of the runner",
          "[server][software_sync][runner]") {
    Rig rig;
    ss::Runner runner(rig.env()); // REST and MCP hold the same instance
    REQUIRE(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::Accepted);
    const auto again = runner.run(session_of("alice"), kFleet, rig.audit());
    CHECK(again.status == ss::Status::Cooldown);
    CHECK(again.http == 429);
    CHECK(again.retry_after_ms.value_or(0) > 0);
    CHECK(rig.dispatch_calls == 1);
    // Another operator is not held back by alice's stamp.
    CHECK(runner.run(session_of("bob"), kFleet, rig.audit()).status == ss::Status::Accepted);
    // After the cooldown the same operator may run again.
    rig.wall += 61;
    CHECK(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::Accepted);
}

TEST_CASE("sync runner: a second run during a send is 409; a lapsed lease may be taken over",
          "[server][software_sync][runner]") {
    Rig rig;
    ss::Runner runner(rig.env());
    ss::Outcome inner;
    rig.during_dispatch = [&] {
        inner = runner.run(session_of("bob"), kFleet, rig.audit());
    };
    REQUIRE(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::Accepted);
    CHECK(inner.status == ss::Status::InFlight);
    CHECK(inner.http == 409);
    CHECK(inner.retry_after_ms.value_or(0) >= 1000);

    // A holder that never finishes: once its lease lapses another run takes the slot, and the
    // stalled run's late release cannot clear the new holder's lease.
    ss::Outcome taken;
    rig.during_dispatch = [&] {
        rig.mono += ss::kSlotLeaseMs + 1; // the outer run has now held the slot past its lease
        taken = runner.run(session_of("carol"), kFleet, rig.audit());
    };
    rig.wall += 61;
    REQUIRE(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::Accepted);
    CHECK(taken.status == ss::Status::Accepted);
    // Slot is free again afterwards (both released cleanly).
    rig.wall += 61;
    CHECK(runner.run(session_of("dave"), kFleet, rig.audit()).status == ss::Status::Accepted);
}

TEST_CASE("sync runner: a huge fleet costs at most cap+1 session lookups and is 413",
          "[server][software_sync][runner][security]") {
    Rig rig;
    rig.resolved_ids.clear();
    for (int i = 0; i < 50'000; ++i)
        rig.resolved_ids.push_back("d" + std::to_string(i));
    ss::Runner runner(rig.env());
    const auto out = runner.run(session_of("alice"), kFleet, rig.audit());
    CHECK(out.status == ss::Status::TooMany);
    CHECK(out.http == 413);
    CHECK(rig.version_lookups == static_cast<int>(ss::kMaxTargets) + 1);
    CHECK(rig.dispatch_calls == 0);
    // The walk was paid for, so the 413 spends the cooldown; after it the operator may narrow.
    rig.resolved_ids = {"d0"};
    const auto again = runner.run(session_of("alice"), kFleet, rig.audit());
    CHECK(again.status == ss::Status::Cooldown);
    CHECK(rig.version_lookups == static_cast<int>(ss::kMaxTargets) + 1); // the repeat read nothing
    rig.wall += 61;
    CHECK(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::Accepted);
}

TEST_CASE("sync runner: a confined caller naming the whole fleet is refused before any read",
          "[server][software_sync][runner][security]") {
    Rig rig;
    auto env = rig.env();
    env.caller_unfiltered = [](const auth::Session&) { return false; };
    int resolves = 0;
    env.resolve = [&](const auth::Session&, const ss::Selector&) {
        ++resolves;
        return ss::Resolved{};
    };
    ss::Runner runner(std::move(env));
    const auto out = runner.run(session_of("alice"), kFleet, rig.audit());
    CHECK(out.status == ss::Status::FleetWideRequired);
    CHECK(out.http == 403);
    CHECK(resolves == 0);
    CHECK(rig.dispatch_calls == 0);
}

TEST_CASE("sync runner: which refused attempts spend the cooldown", "[server][software_sync][runner]") {
    // No live target: the resolve and the lookups were paid for, so it is spent.
    {
        Rig rig;
        auto env = rig.env();
        env.agent_version = [](const std::string&) { return std::optional<std::string>{}; };
        ss::Runner runner(std::move(env));
        CHECK(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::Accepted);
        CHECK(rig.dispatch_calls == 0);
        CHECK(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::Cooldown);
    }
    // Not spent: a malformed expression, a degraded scope read, an audit that would not persist,
    // and a send every session refused - the retry hint is the cure for each.
    {
        Rig rig;
        auto env = rig.env();
        ss::Resolved::Status next = ss::Resolved::Status::InvalidScope;
        env.resolve = [&](const auth::Session&, const ss::Selector&) {
            ss::Resolved r;
            r.status = next;
            r.caller_unfiltered = true;
            r.ids = {"d0"};
            return r;
        };
        ss::Runner runner(std::move(env));
        const ss::Selector expr{DispatchArm::Scope, "ostype == \"linux\""};
        CHECK(runner.run(session_of("alice"), expr, rig.audit()).status == ss::Status::BadScope);
        next = ss::Resolved::Status::Aborted;
        CHECK(runner.run(session_of("alice"), expr, rig.audit()).status == ss::Status::ScopeUnresolved);
        next = ss::Resolved::Status::Ok;
        rig.persist_ok = false;
        CHECK(runner.run(session_of("alice"), expr, rig.audit()).status == ss::Status::AuditUnavailable);
        rig.persist_ok = true;
        CHECK(runner.run(session_of("alice"), expr, rig.audit()).status == ss::Status::Accepted);
    }
    {
        Rig rig;
        auto env = rig.env();
        env.dispatch = [](const auth::Session&, const std::vector<std::string>&) {
            return ss::DispatchResult{0, "x"};
        };
        ss::Runner runner(std::move(env));
        CHECK(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::NoneReachable);
        CHECK(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::NoneReachable);
    }
}

TEST_CASE("sync runner: an expired holder's late release cannot clear the live successor's lease",
          "[server][software_sync][runner]") {
    Rig rig;
    std::mutex mu;
    std::condition_variable cv;
    int in_dispatch = 0;
    bool release_a = false, release_b = false;
    const auto patience = std::chrono::seconds(20); // a regression fails a CHECK; it never hangs CI
    auto env = rig.env();
    env.dispatch = [&](const auth::Session&, const std::vector<std::string>& ids) {
        std::unique_lock<std::mutex> lk(mu);
        const int me = ++in_dispatch; // 1 = the first (expiring) holder, 2 = its successor
        cv.notify_all();
        if (me <= 2)
            cv.wait_for(lk, patience, [&] { return me == 1 ? release_a : release_b; });
        return ss::DispatchResult{ids.size(), "__sync__-lease"};
    };
    ss::Runner runner(std::move(env));
    const auto wait_for_dispatches = [&](int n) {
        std::unique_lock<std::mutex> lk(mu);
        return cv.wait_for(lk, patience, [&] { return in_dispatch >= n; });
    };
    const auto release = [&](bool& flag) {
        {
            std::lock_guard<std::mutex> lk(mu);
            flag = true;
        }
        cv.notify_all();
    };

    ss::Outcome a_out, b_out;
    std::thread a([&] { a_out = runner.run(session_of("alice"), kFleet, rig.audit()); });
    const bool a_in = wait_for_dispatches(1);
    rig.mono += ss::kSlotLeaseMs + 1; // A has now held the slot past its lease
    std::thread b([&] { b_out = runner.run(session_of("bob"), kFleet, rig.audit()); });
    const bool b_in = wait_for_dispatches(2); // B took the slot over and is in its send
    release(release_a);
    a.join(); // A has unwound; its release must not have cleared B's lease
    const auto c_out = runner.run(session_of("carol"), kFleet, rig.audit());
    release(release_b);
    b.join();
    CHECK(a_in);
    CHECK(b_in);
    CHECK(c_out.status == ss::Status::InFlight);
    CHECK(a_out.status == ss::Status::Accepted);
    CHECK(b_out.status == ss::Status::Accepted);
    CHECK(runner.run(session_of("carol"), kFleet, rig.audit()).status == ss::Status::Accepted);
}

TEST_CASE("sync runner: stacked stalled holders are capped, and a takeover is reported",
          "[server][software_sync][runner]") {
    Rig rig;
    int takeovers = 0;
    int depth = 0;
    std::vector<ss::Status> nested;
    auto env = rig.env();
    int refused = 0;
    env.on_takeover = [&] { ++takeovers; };
    env.on_takeover_refused = [&] { ++refused; };
    ss::Runner* self = nullptr;
    const std::vector<std::string> names = {"u1", "u2", "u3", "u4", "u5"};
    env.dispatch = [&](const auth::Session&, const std::vector<std::string>& ids) {
        // Each run that gets in stalls (still alive) while the lease lapses and the next tries.
        if (depth < static_cast<int>(names.size()) - 1) {
            ++depth;
            rig.mono += ss::kSlotLeaseMs + 1;
            nested.push_back(self->run(session_of(names[static_cast<std::size_t>(depth)]), kFleet, rig.audit()).status);
        }
        return ss::DispatchResult{ids.size(), "__sync__-stack"};
    };
    ss::Runner runner(std::move(env));
    self = &runner;
    CHECK(runner.run(session_of(names[0]), kFleet, rig.audit()).status == ss::Status::Accepted);
    // u1 holds; u2 takes over (2 alive); u3 takes over (3 alive); u4 is refused at kMaxLiveRuns.
    // Completion order is innermost first: u4 refused, then u3 and u2 (which had been admitted) accepted.
    REQUIRE(nested.size() == 3);
    CHECK(nested[0] == ss::Status::InFlight);
    CHECK(nested[1] == ss::Status::Accepted);
    CHECK(nested[2] == ss::Status::Accepted);
    CHECK(takeovers == ss::kMaxLiveRuns - 1);
    // Everything unwound: the live-run count returned to zero, so the slot is usable again.
    rig.mono += ss::kSlotLeaseMs + 1;
    CHECK(runner.run(session_of("fresh"), kFleet, rig.audit()).status == ss::Status::Accepted);
    CHECK(refused == 1);
}

TEST_CASE("sync runner: a dispatch that throws is a retryable 503, with the slot released",
          "[server][software_sync][runner]") {
    Rig rig;
    auto env = rig.env();
    env.dispatch = [](const auth::Session&, const std::vector<std::string>&) -> ss::DispatchResult {
        throw std::runtime_error("boom");
    };
    ss::Runner runner(std::move(env));
    const auto out = runner.run(session_of("alice"), kFleet, rig.audit());
    CHECK(out.status == ss::Status::NoneReachable);
    CHECK(out.http == 503);
    CHECK(out.retry_after_ms.value_or(0) > 0);
    // The slot is free and the cooldown unspent: the retry reaches dispatch again (and throws again).
    CHECK(runner.run(session_of("alice"), kFleet, rig.audit()).status == ss::Status::NoneReachable);
}
