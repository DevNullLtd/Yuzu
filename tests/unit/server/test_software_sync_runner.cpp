/**
 * test_software_sync_runner.cpp — the shared fleet-run sequence behind POST /api/v1/hardware/sync
 * and the MCP tool sync_hardware_software: one cooldown and one in-flight lease for both callers,
 * a bounded partition, audit before dispatch. Faked seams only; no process, clock or store.
 */

#include "software_sync_runner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <optional>
#include <string>
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
    // A 413 is not a run: the operator may retry with a narrower scope at once.
    rig.resolved_ids = {"d0"};
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
