/**
 * test_os_kill_switch_dispatch_gate.cpp — #5294: the per-OS kill-switch filter
 * at the dispatch chokepoint. Mirrors test_plugin_presence_dispatch_gate.cpp:
 * `os_killed` is the sibling of `contained` / `plugin_absent`, checked after
 * containment and before plugin absence, in every arm. Also binds
 * `AgentRegistry::ids_with_os` (local sessions, presence-only ids, degraded
 * presence) and the `wire_and_dispatch_confined` threading: claim release for
 * an OS-withheld id and the fail-closed refusal on a degraded presence read.
 */

#include "agent_registry.hpp"
#include "dispatch_confined_arms.hpp"
#include "dispatch_scope_ladder.hpp"
#include "event_bus.hpp"
#include "execution_tracker.hpp"
#include "offline_endpoint_store.hpp"
#include "pg/pg_exec.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "test_execution_tracker_pg_helper.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using yuzu::server::ArmDispatchResult;
using yuzu::server::ConfinedDispatchSink;
using yuzu::server::ConfinedDispatchTargets;
using yuzu::server::ContainmentGate;
using yuzu::server::dispatch_confined_arms;
using yuzu::server::DispatchArm;
using yuzu::server::OfflineEndpointStore;
using yuzu::server::PresenceReadError;
using yuzu::server::authz::VisibleSet;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

using IdSet = std::unordered_set<std::string>;

struct RecordingSink {
    std::vector<std::string> reached;
    bool unfiltered_broadcast_used = false;
    std::vector<std::string> fleet{"dev-A", "dev-B", "dev-C"};

    ConfinedDispatchSink make() {
        return ConfinedDispatchSink{
            [this](const std::string& id) {
                reached.push_back(id);
                return true;
            },
            [this] {
                unfiltered_broadcast_used = true;
                return static_cast<int>(fleet.size());
            },
            [this] { return fleet; },
            /*prepare_route_fallback=*/nullptr,
            [](const std::vector<std::string>&) { return false; }};
    }

    bool reached_exactly(std::vector<std::string> expected) {
        auto got = reached;
        std::sort(got.begin(), got.end());
        std::sort(expected.begin(), expected.end());
        return got == expected;
    }
};

VisibleSet unfiltered() { return std::nullopt; }
const std::vector<std::string> kThree{"dev-A", "dev-B", "dev-C"};
const ContainmentGate kNoContainment = ContainmentGate::exempt_control_plugin();

agent_pb::AgentInfo make_info(const std::string& id, const std::string& os) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname("host.local");
    if (!os.empty())
        a.mutable_platform()->set_os(os);
    return a;
}

yuzu::test::PgTestTemplate os_presence_tpl{"os_kill_switch_presence", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    OfflineEndpointStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("os_kill_switch_presence template: store failed to migrate");
}};

/// Holds ACCESS EXCLUSIVE on the presence table so a presence read with a
/// short lock timeout degrades deterministically (the #4981 PR-1 recipe).
struct PresenceLocker {
    PgConn conn;
    explicit PresenceLocker(const std::string& dsn) : conn{PQconnectdb(dsn.c_str())} {
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        REQUIRE(yuzu::server::pg::exec_params(conn.get(), "BEGIN", std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
        REQUIRE(yuzu::server::pg::exec_params(
                    conn.get(), "LOCK TABLE endpoint_state.endpoints IN ACCESS EXCLUSIVE MODE",
                    std::vector<std::string>{})
                    .status() == PGRES_COMMAND_OK);
    }
    ~PresenceLocker() {
        (void)yuzu::server::pg::exec_params(conn.get(), "ROLLBACK", std::vector<std::string>{});
    }
};

} // namespace

// ------------------------------------------------------------- per-arm ---

TEST_CASE("Ids arm: a single OS-killed id reaches nobody",
          "[server][dispatch][os_kill_switch][security]") {
    RecordingSink sink;
    const std::vector<std::string> one{"dev-A"};
    ConfinedDispatchTargets t;
    t.agent_ids = &one;
    const auto r = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, kNoContainment,
                                          sink.make(), {}, IdSet{"dev-A"});
    CHECK(r.sent == 0);
    CHECK(sink.reached.empty());
    CHECK(r.kill_switched_os == std::vector<std::string>{"dev-A"});
    CHECK(r.kill_switched_os_count == 1);
}

TEST_CASE("Ids/Group/Scope arms: a mixed list reaches only non-killed ids; an out-of-scope "
          "killed id is NOT recorded (#1788 intersection runs first)",
          "[server][dispatch][os_kill_switch][security]") {
    const IdSet killed{"dev-B"};
    for (auto arm : {DispatchArm::Ids, DispatchArm::Group, DispatchArm::Scope}) {
        ConfinedDispatchTargets t;
        if (arm == DispatchArm::Ids)
            t.agent_ids = &kThree;
        else if (arm == DispatchArm::Group)
            t.group_members = &kThree;
        else
            t.scope_matched = &kThree;
        {
            RecordingSink sink;
            const auto r = dispatch_confined_arms(arm, t, unfiltered(), false, kNoContainment,
                                                  sink.make(), {}, killed);
            CHECK(r.sent == 2);
            CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
            CHECK(r.kill_switched_os == std::vector<std::string>{"dev-B"});
        }
        {
            RecordingSink sink;
            const auto r = dispatch_confined_arms(arm, t, VisibleSet{IdSet{"dev-A"}}, false,
                                                  kNoContainment, sink.make(), {}, killed);
            CHECK(r.sent == 1);
            CHECK(r.kill_switched_os.empty());
        }
    }
}

TEST_CASE("priority: quarantined beats OS-killed; OS-killed beats plugin-absent",
          "[server][dispatch][os_kill_switch][security]") {
    {
        RecordingSink sink;
        ConfinedDispatchTargets t;
        t.agent_ids = &kThree;
        auto gate = ContainmentGate::enforcing(/*fail_closed=*/false, {"dev-B"});
        const auto r = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, gate,
                                              sink.make(), {}, IdSet{"dev-B"});
        CHECK(r.denied_quarantined == std::vector<std::string>{"dev-B"});
        CHECK(r.kill_switched_os.empty());
    }
    {
        RecordingSink sink;
        ConfinedDispatchTargets t;
        t.agent_ids = &kThree;
        const auto r = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false,
                                              kNoContainment, sink.make(), IdSet{"dev-B"},
                                              IdSet{"dev-B"});
        CHECK(r.kill_switched_os == std::vector<std::string>{"dev-B"});
        CHECK(r.unknown_plugin.empty());
    }
}

TEST_CASE("Broadcast/None: a non-empty OS set disables the unfiltered fast path; empty keeps it",
          "[server][dispatch][os_kill_switch][security]") {
    {
        RecordingSink sink;
        const auto r = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                              kNoContainment, sink.make(), {}, IdSet{"dev-B"});
        CHECK(r.sent == 2);
        CHECK(sink.reached_exactly({"dev-A", "dev-C"}));
        CHECK_FALSE(sink.unfiltered_broadcast_used);
    }
    {
        RecordingSink sink;
        const auto r = dispatch_confined_arms(DispatchArm::None, {}, unfiltered(),
                                              /*broadcast_on_none=*/true, kNoContainment,
                                              sink.make(), {}, IdSet{"dev-A"});
        CHECK(r.sent == 2);
        CHECK_FALSE(sink.unfiltered_broadcast_used);
    }
    {
        RecordingSink sink;
        const auto r = dispatch_confined_arms(DispatchArm::Broadcast, {}, unfiltered(), false,
                                              kNoContainment, sink.make(), {}, {});
        CHECK(r.sent == 3);
        CHECK(sink.unfiltered_broadcast_used);
    }
}

TEST_CASE("omitting the OS set withholds nothing (defaulted parameter)",
          "[server][dispatch][os_kill_switch][security]") {
    RecordingSink sink;
    ConfinedDispatchTargets t;
    t.agent_ids = &kThree;
    const auto r = dispatch_confined_arms(DispatchArm::Ids, t, unfiltered(), false, kNoContainment,
                                          sink.make());
    CHECK(r.sent == 3);
    CHECK(r.kill_switched_os.empty());
    CHECK(r.kill_switched_os_count == 0);
}

// ------------------------------------------------ AgentRegistry::ids_with_os ---

TEST_CASE("ids_with_os: local sessions match on their reported os; empty os is never withheld; "
          "empty input is empty",
          "[server][dispatch][os_kill_switch][registry]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("win", "windows"));
    registry.register_agent(make_info("lin", "linux"));
    registry.register_agent(make_info("unknown", ""));

    auto got = registry.ids_with_os(IdSet{"windows"});
    REQUIRE(got.has_value());
    CHECK(*got == IdSet{"win"});
    got = registry.ids_with_os(IdSet{"windows", "linux"});
    REQUIRE(got.has_value());
    CHECK(*got == IdSet{"win", "lin"}); // "unknown" is never withheld
    got = registry.ids_with_os({});
    REQUIRE(got.has_value());
    CHECK(got->empty());
}

TEST_CASE("ids_with_os: a presence-only id is matched on its presence os; a local session wins "
          "over a conflicting presence row",
          "[pg][ha][presence][server][dispatch][os_kill_switch][registry]") {
    YUZU_REQUIRE_PG_DB_TPL(db, os_presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));
    registry.register_agent(make_info("local-lin", "linux"));
    REQUIRE(store.upsert("remote-win", "h", "windows", 0, 0, "1.0.0", "x86_64", "s1"));
    REQUIRE(store.upsert("remote-lin", "h", "linux", 0, 0, "1.0.0", "x86_64", "s2"));
    REQUIRE(store.upsert("remote-unknown", "h", "", 0, 0, "1.0.0", "x86_64", "s3"));
    // Stale presence row claiming windows for an id this replica serves as linux.
    REQUIRE(store.upsert("local-lin", "h", "windows", 0, 0, "1.0.0", "x86_64", "s4"));

    const auto got = registry.ids_with_os(IdSet{"windows"});
    REQUIRE(got.has_value());
    CHECK(*got == IdSet{"remote-win"});
}

TEST_CASE("ids_with_os: a degraded presence read with a non-empty set is an error; with an empty "
          "set no read is attempted",
          "[pg][ha][presence][failclosed][server][dispatch][os_kill_switch][registry]") {
    YUZU_REQUIRE_PG_DB_TPL(db, os_presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));
    registry.register_agent(make_info("local-win", "windows"));

    PresenceLocker locker{db.dsn()};
    const auto empty_in = registry.ids_with_os({});
    REQUIRE(empty_in.has_value());
    CHECK(empty_in->empty());
    const auto degraded = registry.ids_with_os(IdSet{"windows"});
    REQUIRE_FALSE(degraded.has_value());
}

// ─────────────── wire_and_dispatch_confined ───────────────

namespace {

yuzu::server::detail::ClassifiedCommand classified_with_os_off(IdSet os_off) {
    constexpr yuzu::server::CommandCapability kCap{
        .plugin = "tar",
        .action = "sql",
        .dispatch_class = yuzu::server::DispatchClass::ReadOnly,
        .mutability = yuzu::server::Mutability::None,
        .securable = "Infrastructure",
        .operation = yuzu::server::authz::Operation::Read,
        .risk_tier = yuzu::server::authz::RiskTier::Low,
        .system_reserved = false,
    };
    yuzu::server::detail::KillSwitchFn fn = [os_off](std::string_view, std::string_view) {
        return std::optional<IdSet>{os_off};
    };
    auto r = yuzu::server::detail::finalize_classified_command(
        kCap, fn, "tar", "sql", "os-cmd", {}, {}, 0, 0, {}, {});
    REQUIRE(r.has_value());
    return std::move(*r);
}

yuzu::server::ConfinedDispatchOutcome wire(AgentRegistry& registry,
                                           yuzu::server::ExecutionTracker* tracker,
                                           const yuzu::server::detail::ClassifiedCommand& cmd,
                                           const std::vector<std::string>& ids,
                                           const std::string& execution_id = "exec-1") {
    auto gate = ContainmentGate::exempt_control_plugin();
    auto noop = [](const std::string&, const std::string&, const std::string&,
                   const std::string&) {};
    return yuzu::server::wire_and_dispatch_confined(
        registry, nullptr, nullptr, nullptr, nullptr, tracker, noop, noop, "os-cmd-" + execution_id, execution_id, "",
        ids, "", unfiltered(), false, gate, cmd, tracker ? "def-1" : "",
        tracker ? "per-device" : "");
}

} // namespace

TEST_CASE("wire_and_dispatch_confined: an OS-withheld id's per-device claim is released, and a "
          "dispatch after the switch is cleared reaches it",
          "[pg][server][dispatch][os_kill_switch][integration]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::execution_tracker_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    yuzu::server::ExecutionTracker tracker{pool};
    REQUIRE(tracker.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.register_agent(make_info("dev-A", "windows"));
    registry.register_agent(make_info("dev-B", "linux"));
    for (const auto& id : {"dev-A", "dev-B"})
        REQUIRE(registry.set_gateway_route(
            id, {}, "test-gateway",
            {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

    const std::vector<std::string> ids{"dev-A", "dev-B"};
    const auto outcome = wire(registry, &tracker, classified_with_os_off({"windows"}), ids);
    CHECK_FALSE(outcome.os_gate_unreadable);
    CHECK(outcome.kill_switched_os == std::vector<std::string>{"dev-A"});
    CHECK(outcome.kill_switched_os_count == 1);
    CHECK(outcome.sent == 1);

    // The claim taken for dev-A before the withhold was released, not leaked.
    auto reclaim = tracker.claim_concurrency_slots("def-1", "exec-2", "os-cmd-2", {"dev-A"},
                                                    /*expires_at_seconds=*/9999999999);
    CHECK(reclaim == std::vector<std::string>{"dev-A"});

    // Switch cleared: the next dispatch reaches dev-A (no leftover exclusion).
    (void)tracker.release_concurrency_claims("def-1", "exec-2", {"dev-A"});
    const auto after = wire(registry, &tracker, classified_with_os_off({}), {"dev-A"}, "exec-3");
    CHECK(after.kill_switched_os.empty());
    CHECK(after.sent == 1);
}

TEST_CASE("wire_and_dispatch_confined: a remote-only (presence) Windows target is withheld, not "
          "attempted",
          "[pg][ha][presence][server][dispatch][os_kill_switch][integration]") {
    YUZU_REQUIRE_PG_DB_TPL(db, os_presence_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));
    REQUIRE(store.upsert("remote-win", "h", "windows", 0, 0, "1.0.0", "x86_64", "s1"));

    const std::vector<std::string> ids{"remote-win"};
    const auto withheld = wire(registry, nullptr, classified_with_os_off({"windows"}), ids);
    CHECK(withheld.kill_switched_os == ids);
    CHECK(withheld.not_sent.empty()); // never attempted, so never a failed send
    CHECK(withheld.sent == 0);

    // Control: with no OS switched off the same id IS attempted (no local
    // session, so the send fails and lands in not_sent).
    const auto attempted = wire(registry, nullptr, classified_with_os_off({}), ids);
    CHECK(attempted.kill_switched_os.empty());
    CHECK(attempted.not_sent == ids);
}

TEST_CASE("wire_and_dispatch_confined: degraded presence with a per-OS switch OFF refuses the "
          "dispatch before targeting and before any claim",
          "[pg][ha][presence][failclosed][server][dispatch][os_kill_switch][integration]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::execution_tracker_pg_template);
    // The execution-tracker template has no endpoint_state schema; build the
    // presence store in the same database.
    PgPool pool{{.conninfo = db.dsn(), .size = 4, .lock_timeout_ms = 100}};
    REQUIRE(pool.valid());
    yuzu::server::ExecutionTracker tracker{pool};
    REQUIRE(tracker.is_open());
    OfflineEndpointStore store{pool};
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    registry.configure_presence(&store, std::chrono::hours(1));
    registry.register_agent(make_info("dev-A", "windows"));
    REQUIRE(registry.set_gateway_route(
        "dev-A", {}, "test-gateway",
        {std::string(yuzu::server::detail::kGatewayWireCapabilityDispatchTagV1)}));

    PresenceLocker locker{db.dsn()};
    const std::vector<std::string> ids{"dev-A"};
    const auto outcome = wire(registry, &tracker, classified_with_os_off({"windows"}), ids);
    CHECK(outcome.os_gate_unreadable);
    CHECK(outcome.sent == 0);
    CHECK(outcome.kill_switched_os.empty());
    // No claim was taken: it is claimable immediately.
    auto claim = tracker.claim_concurrency_slots("def-1", "exec-9", "os-cmd-9", {"dev-A"},
                                                  /*expires_at_seconds=*/9999999999);
    CHECK(claim == std::vector<std::string>{"dev-A"});
}
