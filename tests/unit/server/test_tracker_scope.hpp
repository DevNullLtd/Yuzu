#pragma once

/**
 * test_tracker_scope.hpp -- a live ExecutionTracker wired into an AgentServiceImpl for one test.
 *
 * Promoted out of test_agent_service_impl.cpp when test_plugin_result_audit.cpp became its second
 * user (docs/testing/unit-test-conventions.md). It stays beside the server tests because it names
 * server types, which the shared tests/unit/test_helpers.hpp (also built into the agent tests)
 * cannot include.
 */

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>

#include "agent_service_impl.hpp"
#include "execution_event_bus.hpp"
#include "execution_tracker.hpp"
#include "pg/pg_pool.hpp"

namespace yuzu::test {

/// MEMBER ORDER LOAD-BEARING: `tracker` is owned outright (against the
/// caller-supplied pool), `svc` borrows `tracker.get()` (via
/// `set_execution_tracker`). The dtor MUST run set_execution_tracker(nullptr)
/// -> tracker.reset(), in that exact order, so the borrowed-pointer chain is
/// unwound from the outside in. Reordering the member declarations or
/// replacing the user-defined dtor with `= default` would silently break the
/// contract -- there is no compile-time guard. Mirrors the production
/// ServerImpl "drain gRPC -> null setter -> reset" shutdown sequence, documented
/// on AgentServiceImpl::set_execution_tracker.
struct TrackerScope {
    std::unique_ptr<yuzu::server::ExecutionTracker> tracker;
    yuzu::server::detail::AgentServiceImpl* svc{nullptr};

    /// `bus`, when given, is attached to the tracker (which publishes `agent-transition` events
    /// on it) and must outlive this scope.
    TrackerScope(yuzu::server::detail::AgentServiceImpl& s, yuzu::server::pg::PgPool& pool,
                 yuzu::server::ExecutionEventBus* bus = nullptr)
        : svc(&s) {
        tracker = std::make_unique<yuzu::server::ExecutionTracker>(pool);
        REQUIRE(tracker->is_open());
        if (bus != nullptr)
            tracker->set_event_bus(bus);
        // The tracker's records are the only record source from here on: a harness's
        // prefix-labelling fake (test_provenance_fake.hpp) is cleared, so a frame whose command id
        // was never recorded is unverified exactly as in production.
        svc->override_command_record_lookup({});
        svc->set_execution_tracker(tracker.get());
    }
    ~TrackerScope() {
        if (svc)
            svc->set_execution_tracker(nullptr);
        tracker.reset();
    }

    TrackerScope(const TrackerScope&) = delete;
    TrackerScope& operator=(const TrackerScope&) = delete;

    /// Create an execution row on the bound tracker, return its id. Matches
    /// the `GatewayResponseHarness::make_response` static-factory pattern --
    /// keeps test bodies focused on the assertion, not boilerplate. Call
    /// sites read `auto exec_id = ts.make_exec();`.
    std::string make_exec(int agents_targeted = 1) {
        yuzu::server::Execution exec;
        exec.definition_id = "def-test";
        exec.scope_expression = "agent_id = 'agent-1'";
        exec.dispatched_by = "tester";
        exec.status = "running";
        exec.agents_targeted = agents_targeted;
        auto id = tracker->create_execution(exec);
        REQUIRE(id.has_value());
        return *id;
    }
};

} // namespace yuzu::test
