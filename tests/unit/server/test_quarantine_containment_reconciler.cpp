/**
 * test_quarantine_containment_reconciler.cpp — #3425: a device quarantined
 * while offline never had its endpoint firewall re-applied on reconnect.
 * `QuarantineContainmentReconciler` closes that gap. Pins the acceptance
 * criteria directly:
 *  - an active record on a REACHABLE (registered) device is re-dispatched;
 *  - no record means no dispatch at all;
 *  - a device with no live session is skipped (no wasted dispatch/audit);
 *  - a `status|busy` response from the agent-side mutation gate does not
 *    spin — the per-agent claim governs the next attempt, not an immediate
 *    retry;
 *  - dispatch acceptance alone never marks a device confirmed — only a
 *    follow-up `state|active` status read does;
 *  - the stored whitelist is what gets dispatched, never anything else —
 *    every dispatch assertion below checks the EXACT argument tuple, never
 *    mere presence in a set (the false-green lesson this repo has already
 *    paid for once).
 *
 * Real `QuarantineStore` + `ResponseStore` (Postgres, PgTestTemplate) and a
 * real `AgentRegistry` — only the dispatch function is mocked, capturing the
 * full call.
 */

#include "quarantine_containment_reconciler.hpp"

#include "agent_registry.hpp"
#include "audit_store.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "quarantine_store.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <catch2/catch_test_macros.hpp>

#include <libpq-fe.h>

#include <yuzu/metrics.hpp>

#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace {

yuzu::test::PgTestTemplate quarantine_recon_tpl{"quarantinestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    QuarantineStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("quarantine_store template: store failed to migrate");
}};

yuzu::test::PgTestTemplate responsestore_recon_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

::yuzu::agent::v1::AgentInfo make_info(const std::string& id) {
    ::yuzu::agent::v1::AgentInfo info;
    info.set_agent_id(id);
    info.set_hostname(id + ".local");
    return info;
}

struct DispatchCall {
    std::string plugin;
    std::string action;
    std::vector<std::string> agent_ids;
    std::unordered_map<std::string, std::string> parameters;
};

// A minimal dispatch fixture: records every call with its FULL argument
// tuple (the exact-send-set discipline) and hands back a scripted
// (command_id, agents_reached) pair per call, defaulting to accepted.
struct MockDispatch {
    std::vector<DispatchCall> calls;
    int next_agents_reached{1};
    bool next_throws{false};
    // Invoked synchronously from inside the dispatch call, AFTER the call is
    // recorded but BEFORE the (command_id, agents_reached) pair is returned
    // — the deterministic, single-threaded way to inject "someone else
    // mutated the store concurrently, between the reconciler's read and its
    // own follow-up write" without a real thread or a store-failure seam.
    std::function<void()> on_dispatch;

    QuarantineContainmentReconciler::CommandDispatchFn fn() {
        return [this](const std::string& plugin, const std::string& action,
                     const std::vector<std::string>& agent_ids, const std::string&,
                     const std::unordered_map<std::string, std::string>& parameters,
                     const std::string&) -> yuzu::server::ConfinedDispatchOutcome {
            calls.push_back({plugin, action, agent_ids, parameters});
            if (on_dispatch)
                on_dispatch();
            if (next_throws)
                throw std::runtime_error("dispatch failed");
            return {.sent = next_agents_reached, .command_id = "cmd-" + std::to_string(calls.size())};
        };
    }
};

void store_status_response(ResponseStore& rs, const std::string& command_id,
                           const std::string& agent_id, const std::string& output) {
    StoredResponse sr;
    sr.instruction_id = command_id;
    sr.agent_id = agent_id;
    sr.status = 1; // SUCCESS
    sr.output = output;
    sr.plugin = "quarantine";
    rs.store(sr);
}

} // namespace

// ── Core acceptance criteria ────────────────────────────────────────────────

TEST_CASE("QuarantineContainmentReconciler: an active record on a reachable device is "
          "re-dispatched with the EXACT stored whitelist, never anything else",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "10.0.0.1,10.0.0.2")
                .has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1")); // reachable

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();

    REQUIRE(dispatch.calls.size() == 1);
    const auto& call = dispatch.calls.front();
    CHECK(call.plugin == "quarantine");
    CHECK(call.action == "quarantine");
    REQUIRE(call.agent_ids.size() == 1);
    CHECK(call.agent_ids[0] == "agent-1");
    REQUIRE(call.parameters.size() == 1);
    CHECK(call.parameters.at("whitelist_ips") == "10.0.0.1,10.0.0.2");

    // agents_reached > 0 marks last_applied_at, NOT last_confirmed_at —
    // dispatch acceptance is not proof of containment.
    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_applied_at > 0);
    CHECK((*status)->last_confirmed_at == 0);
}

TEST_CASE("QuarantineContainmentReconciler: no active record means no dispatch at all",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    // No quarantine_device call — nothing active.

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    reconciler.notify_agent_heartbeat("agent-1");

    CHECK(dispatch.calls.empty());
}

TEST_CASE("QuarantineContainmentReconciler: a device with no live session is skipped, "
          "no dispatch attempted",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-offline", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    // Deliberately NOT registered — no live session.

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();

    CHECK(dispatch.calls.empty());
    // Record stays unconfirmed — nothing marks it applied while offline.
    auto status = qstore.get_status("agent-offline");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_applied_at == 0);

    // The gauge counts it under "offline", not "connected".
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "offline"}})
              .value() == 1);
    CHECK(metrics
              .gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

// #3425 governance Gate 4 (happy-path, 2026-08-24): an offline-tick claim
// must not hold a reconnecting device's FIRST post-reconnect heartbeat to
// the full claim window — that directly undermines the "fast path fires
// promptly on reconnect" design intent for exactly the device class this
// feature exists to fix.
TEST_CASE("QuarantineContainmentReconciler: a device found offline is immediately eligible again "
          "on the next heartbeat, not held to the claim window an offline tick took",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    // Deliberately NOT registered yet — offline at the first tick.

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        // A generous production-scale claim window — if the offline skip
        // held it, a same-millisecond heartbeat would be rate_limited; the
        // fix means it isn't, regardless of how large this is.
        .min_reapply_interval_override = std::chrono::milliseconds(60'000),
    });

    reconciler.tick(); // offline — claims, then immediately releases the claim
    CHECK(dispatch.calls.empty());

    // Reconnect: register the session, then heartbeat right away — no sleep.
    registry.register_agent(make_info("agent-1"));
    reconciler.notify_agent_heartbeat("agent-1");
    REQUIRE(dispatch.calls.size() == 1); // NOT rate_limited despite the 60s window
    CHECK(dispatch.calls[0].plugin == "quarantine");
    CHECK(dispatch.calls[0].action == "quarantine");
}

TEST_CASE("QuarantineContainmentReconciler: a busy mutation-gate response does not spin — "
          "the per-agent claim governs the next attempt",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    // Tick 1: apply dispatched.
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);
    const std::string apply_cmd = "cmd-1";

    // The agent-side mutation gate (open PR #3429) answers busy — seed that
    // as the apply command's response.
    store_status_response(rstore, apply_cmd, "agent-1", "status|busy");

    // Same tick's claim already holds next_eligible_at in the future — a
    // second reconcile attempt right now (e.g. a racing heartbeat) must NOT
    // dispatch again. This is the concrete no-spin mechanism: rate_limited,
    // not another poll-then-dispatch.
    reconciler.notify_agent_heartbeat("agent-1");
    CHECK(dispatch.calls.size() == 1); // still just the one apply call — no spin
}

// The two cases below drive the FULL apply -> poll -> status -> confirm
// state machine deterministically using the millisecond timing overrides
// (Deps' *_override fields) — production leaves these at 0 (meaning "use
// the real 60s/15s/60s constants"); a test setting them to tens of
// milliseconds gets the identical state machine without a multi-minute
// sleep. A response is seeded IMMEDIATELY after learning its command_id
// (before the next reconcile_one call), and a short real sleep bridges the
// overridden claim/grace windows — the assertions are on STATE reached, not
// on timing precision.

TEST_CASE("QuarantineContainmentReconciler: confirmation requires a follow-up status read "
          "reporting state|active — dispatch acceptance alone is not enough",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Step 1: apply dispatched.
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);
    CHECK(dispatch.calls[0].action == "quarantine");
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");

    // Step 2: this call POLLS the apply response and (since it's not
    // "busy") schedules a status verify — it does NOT dispatch status
    // itself in the same call (one dispatch decision per reconcile_one
    // call, by design).
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick();
    CHECK(dispatch.calls.size() == 1); // still just the apply — no dispatch yet

    // Confirmation must NOT have happened from apply acceptance alone.
    auto mid = qstore.get_status("agent-1");
    REQUIRE(mid.has_value());
    REQUIRE(mid->has_value());
    CHECK((*mid)->last_confirmed_at == 0);

    // Step 3: THIS call is the one that actually dispatches the status verify.
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "status");

    // Still not confirmed — the status dispatch's own response hasn't
    // arrived/been polled yet.
    auto after_status_dispatch = qstore.get_status("agent-1");
    REQUIRE(after_status_dispatch.has_value());
    REQUIRE(after_status_dispatch->has_value());
    CHECK((*after_status_dispatch)->last_confirmed_at == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a follow-up status read of state|active marks "
          "the record confirmed",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // 1: apply dispatched
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply response, schedules status verify (no dispatch yet)
    CHECK(dispatch.calls.size() == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches the status verify
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "status");

    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls status response -> confirms

    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_confirmed_at > 0);

    // A further tick dispatches NOTHING for a confirmed, session-unchanged
    // agent — and its sweep (computed at the START of the tick, before that
    // cycle's own reconcile_one work) is also the first one to see the
    // gauge reflect the confirm achieved during tick 4 (the gauge published
    // during tick 4 itself still reflected PRE-confirm state).
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick();
    CHECK(dispatch.calls.size() == 2); // unchanged — confirmed agents are skipped
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0); // no longer counted as unconfirmed
}

TEST_CASE("QuarantineContainmentReconciler: session churn on a confirmed agent re-verifies "
          "via status, not a blind re-apply",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-A", "agent-1");

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive to confirmed under session-A (apply -> poll -> status verify -> confirm).
    reconciler.tick(); // 1: apply
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply, schedules status verify
    CHECK(dispatch.calls.size() == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches status verify
    REQUIRE(dispatch.calls.size() == 2);
    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls status -> confirms
    auto confirmed = qstore.get_status("agent-1");
    REQUIRE(confirmed.has_value());
    REQUIRE(confirmed->has_value());
    REQUIRE((*confirmed)->last_confirmed_at > 0);

    // Simulate a reconnect: a NEW session for the same agent (register_agent
    // replaces the shared_ptr — the immutability contract — then a fresh
    // session_id is mapped, as AgentServiceImpl::Register really does).
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-B", "agent-1");

    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 5: tick's own sweep detects churn and dispatches STATUS
                       // first (verify_first is consumed on the SAME call that
                       // detects it, unlike apply's poll->schedule->dispatch
                       // split, because churn detection happens in tick()'s
                       // sweep loop, before reconcile_one's claim, so the
                       // dispatch decision and the churn flag land in the same
                       // reconcile_one invocation).

    REQUIRE(dispatch.calls.size() == 3);
    CHECK(dispatch.calls[2].action == "status"); // verify-first, never a blind re-apply
}

TEST_CASE("QuarantineContainmentReconciler: record churn on a confirmed, still-connected agent "
          "re-enters via the fresh apply path (governance re-review Finding UP-1)",
          "[pg][quarantine][reconciler]") {
    // UP-1: releasing and re-quarantining the SAME agent_id while its
    // session never changes (a normal whitelist-update workflow) must not
    // leave the reconciler believing the NEW record is already contained
    // just because the OLD one was. Session churn alone (the pre-existing
    // check) never fires here, so this pins the SEPARATE record-identity
    // check tick() now also performs.
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-A", "agent-1"); // stays live through the whole test

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive the first record to confirmed (apply -> poll -> status verify -> confirm).
    reconciler.tick(); // 1: apply
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply, schedules status verify
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches status verify
    REQUIRE(dispatch.calls.size() == 2);
    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls status -> confirms
    auto confirmed = qstore.get_status("agent-1");
    REQUIRE(confirmed.has_value());
    REQUIRE(confirmed->has_value());
    REQUIRE((*confirmed)->last_confirmed_at > 0);
    const auto old_record_id = (*confirmed)->id;

    // A further tick would normally dispatch nothing for a confirmed,
    // session-unchanged agent (pinned by the sibling test above) — confirm
    // that baseline still holds right before the release+requarantine.
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 5
    REQUIRE(dispatch.calls.size() == 2);

    // Release then re-quarantine the SAME agent_id — same session throughout,
    // a different stored whitelist this time. This is the exact operator
    // workflow UP-1 named: updating containment without a reboot in between.
    REQUIRE(qstore.release_device("agent-1").has_value());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "reassessed", "10.0.0.9").has_value());
    auto new_record = qstore.get_status("agent-1");
    REQUIRE(new_record.has_value());
    REQUIRE(new_record->has_value());
    REQUIRE((*new_record)->id != old_record_id);
    REQUIRE((*new_record)->last_confirmed_at == 0); // never verified — the whole point

    // tick()'s own sweep must detect the record churn and re-enter the fresh
    // apply path for the NEW record THIS tick — the same call, not a later
    // one — rather than silently continuing to treat this agent as confirmed.
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 6: record churn detected -> fresh apply dispatched
    REQUIRE(dispatch.calls.size() == 3);
    CHECK(dispatch.calls[2].action == "quarantine"); // fresh APPLY, not a status-only re-verify
    CHECK(dispatch.calls[2].parameters.at("whitelist_ips") == "10.0.0.9");
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 1); // visible again — not silently still "confirmed"
}

TEST_CASE("QuarantineContainmentReconciler: a session churn between the status dispatch and its "
          "confirm does not stamp the new session as confirmed (governance re-review Finding "
          "UP-2)",
          "[pg][quarantine][reconciler]") {
    // UP-2: the status dispatch that will confirm containment is sent while
    // session-A is live; if the device reboots onto session-B before the
    // reconciler processes that response, the response describes session-A's
    // (possibly already-gone) firewall state — stamping it as evidence for
    // session-B would be a false assurance the NEW session was ever verified.
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-A", "agent-1");

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // 1: apply
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply, schedules status verify
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches status verify (session-A live at dispatch time)
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "status");

    // The device reboots BEFORE the reconciler processes the response —
    // session-B replaces session-A in the registry now, but the response
    // still describes session-A's state.
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-B", "agent-1");
    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls status — must NOT confirm against session-B

    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_confirmed_at == 0); // never stamped on stale evidence
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 1); // still counted as unconfirmed, not silently cleared
}

TEST_CASE("QuarantineContainmentReconciler: a sustained response_store outage escalates backoff "
          "on a pending poll instead of retrying at a flat cadence forever "
          "(#3425 gate4-response-store-degradation-freezes-timeout)",
          "[pg][quarantine][reconciler]") {
    // response_store = nullptr from construction (matches this file's own
    // "simulates unavailable" convention) means every poll of the pending
    // apply command hits reconcile_one's `!resp` branch every single time —
    // isolating exactly the branch under test, with no interference from
    // the sibling resp->empty()/timed_out paths.
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr, // degraded for the whole test
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(100),
        .response_wait_override = std::chrono::milliseconds(5000), // large: never let
                                                                    // timed_out fire —
                                                                    // isolates the !resp
                                                                    // branch specifically
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // 1: apply dispatched (doesn't touch response_store)
    REQUIRE(dispatch.calls.size() == 1);

    auto degraded_count = [&] {
        return metrics.counter("yuzu_server_quarantine_reapply_total", {{"result", "degraded"}})
            .value();
    };

    // Margins match this file's own ~3x-over-threshold convention (see the
    // 20ms/60ms pairing used throughout the file) rather than the original,
    // much tighter 20ms/30ms pairing this test shipped with — cpp-safety and
    // cpp-expert independently flagged the original margin as thin enough to
    // risk a false-red (never false-green) under a contended CI runner.
    std::this_thread::sleep_for(std::chrono::milliseconds(300)); // past the 100ms interval
    reconciler.tick(); // 2: polls, response_store null -> degraded, backoff 100ms -> 200ms
    CHECK(degraded_count() == 1);
    CHECK(dispatch.calls.size() == 1); // no new dispatch — still the same pending command

    // 150ms elapsed: past the OLD 100ms window (which the pre-fix code would
    // still be using, since it never touched backoff on this branch) but
    // comfortably short of the NEW 200ms window (50ms slack either side).
    // Under the fix, this call must be rate_limited — no poll attempt, no
    // second "degraded" count.
    std::this_thread::sleep_for(std::chrono::milliseconds(150));
    reconciler.tick(); // 3: rate_limited if backoff escalated; degraded again if it didn't
    CHECK(degraded_count() == 1); // unchanged — proves the wait window actually grew

    // Now past the escalated 200ms window — the next poll attempt fires and
    // escalates again (200ms -> 400ms), continuing the same exponential
    // shape every other repeated-failure path in this state machine already
    // uses.
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    reconciler.tick(); // 4
    CHECK(degraded_count() == 2);
    CHECK(dispatch.calls.size() == 1); // still no new dispatch — command is still pending
}

TEST_CASE("QuarantineContainmentReconciler: heartbeat fast path is a no-op for an agent with "
          "no active record (no store read)",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    // Heartbeat BEFORE any tick() has ever run — the cache is empty, so this
    // must be a pure cache-miss with zero dispatch and zero store I/O
    // (there is nothing to assert the "no store read" half directly, but a
    // dispatch call would prove the fast path failed).
    reconciler.notify_agent_heartbeat("agent-1");
    CHECK(dispatch.calls.empty());
}

TEST_CASE("QuarantineContainmentReconciler: an unsafe stored whitelist is never dispatched",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    // quarantine_device itself validates nothing — this mirrors a row
    // written through the record-only REST twin, which performs no
    // charset/length validation of its own (the #3127 rationale for
    // re-validating a STORED value at the server edge before dispatch).
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "10.0.0.1;rm -rf /")
                .has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();

    CHECK(dispatch.calls.empty());
    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->last_applied_at == 0); // never dispatched, never marked applied
}

TEST_CASE("QuarantineContainmentReconciler: a released record disappears from the next "
          "tick with no dispatch",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);

    REQUIRE(qstore.release_device("agent-1").has_value());
    reconciler.tick(); // GC's the now-released agent out of internal state

    CHECK(dispatch.calls.size() == 1); // no second dispatch to a released device
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a degraded quarantine-store read aborts the tick, "
          "never treated as \"nothing active\"",
          "[quarantine][reconciler]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = nullptr, // simulates "store unavailable"
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    // #3425 review (security-guardian + cpp-expert, gate11 focused re-review):
    // Gauge::value() defaults to 0.0, same as the value this test expects —
    // asserting == 0 without ever setting it first cannot distinguish
    // publish_tick_health(false) actually running from that call being
    // silently removed. Pre-seed to 1 (mirrors the real boot-time seed in
    // server.cpp) so the post-tick assertion below is load-bearing: it can
    // only read 0 if the degraded branch genuinely published it.
    metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").set(1);

    // Must not crash and must not fabricate any dispatch.
    reconciler.tick();
    CHECK(dispatch.calls.empty());

    // #3425 review (Doomgoose, #3567): a degraded tick must NOT leave the
    // freshness gauge silently at whatever it was before — it must publish
    // 0, distinguishing "couldn't check" from "checked, genuinely healthy".
    CHECK(metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").value() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a successful tick publishes tick_healthy=1 "
          "(#3425 review (Doomgoose, #3567))",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    // No active record at all — an empty fleet is still a HEALTHY read, not
    // a degraded one; publish_tick_health must fire on this path too, not
    // only when there's something to reconcile.

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    CHECK(metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").value() == 1);
}

TEST_CASE("QuarantineContainmentReconciler: a degraded list_quarantined() read on an OPEN "
          "store also publishes tick_healthy=0, not only the never-wired branch",
          "[pg][quarantine][reconciler]") {
    // #3425 governance correction round (cpp-expert LOW + security-guardian
    // INFO + quality-engineer MEDIUM, independently converged three ways):
    // the two early returns in tick() publish identical `false`, but only
    // the `!quarantine_store` branch (above) had a dedicated assertion —
    // and that branch is production-UNREACHABLE (server.cpp fails closed at
    // boot, before quarantine_reconciler_ is ever constructed, on a store
    // that fails to open). The branch this gauge actually exists for — a
    // previously-open store whose read degrades mid-flight — had zero
    // coverage. Force a genuine read failure (not a mock) by dropping the
    // table out from under the still-open store.
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());

    {
        PgConn conn{PQconnectdb(qdb.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult drop{PQexec(conn.get(), "DROP TABLE quarantine_store.quarantine_records CASCADE")};
        REQUIRE(drop.ok());
    }

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    // Same pre-seed rationale as the sibling test above: Gauge::value()
    // defaults to 0.0, so asserting == 0 without ever setting it first
    // cannot distinguish the fix running from the fix being silently
    // removed.
    metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").set(1);

    reconciler.tick();
    CHECK(dispatch.calls.empty());
    CHECK(metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").value() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: on_tick_exception publishes tick_healthy=0 and "
          "counts degraded",
          "[quarantine][reconciler]") {
    // Gate 8 re-review (cpp-safety SHOULD + quality-engineer NICE,
    // independently converged): the fourth publish_tick_health(false) call
    // site — server.cpp's tick-thread outer catch, wired to this method —
    // had no direct test; the other three (null store, degraded read,
    // success path) all do. Called directly rather than via a real thrown
    // exception since there is no fault-injection seam on the dispatch/PG
    // path yet (chaos-injector CH-1, deferred).
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = nullptr,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").set(1);
    const double before =
        metrics.counter("yuzu_server_quarantine_reapply_total", {{"result", "degraded"}}).value();

    reconciler.on_tick_exception();

    CHECK(metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").value() == 0);
    CHECK(metrics.counter("yuzu_server_quarantine_reapply_total", {{"result", "degraded"}})
              .value() == before + 1);
}

// ── Adversarial-review regression tests (2026-08-24) ───────────────────────
//
// K1/K2 (Kimi) + CDX-P1-02 (Codex), independently found: mark_endpoint_applied/
// mark_endpoint_confirmed's std::expected result was discarded, so a
// concurrent release racing the reconciler's own read-then-write could leave
// the in-memory state believing "applied"/"confirmed" when the guarded
// UPDATE actually affected zero rows. Both dispatch mocks below release the
// device from INSIDE the dispatch callback — the deterministic, single-
// threaded way to land exactly in that window (reconcile_one calls
// dispatch_fn, then immediately calls mark_endpoint_applied/confirmed on
// return) without a real second thread or a store-failure injection seam.

TEST_CASE("QuarantineContainmentReconciler: a release racing mark_endpoint_applied does not "
          "leave a phantom \"pending apply\" tracked forever",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    // Fires after the apply dispatch is recorded but before reconcile_one's
    // own mark_endpoint_applied call — releasing the device HERE means that
    // guarded UPDATE (WHERE status='active') affects zero rows.
    dispatch.on_dispatch = [&] { REQUIRE(qstore.release_device("agent-1").has_value()); };

    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1); // the dispatch itself still happened — cannot be undone
    // NOTE: this same tick's own gauge publish still counts agent-1 as
    // unconfirmed=1 — it was computed from the list_quarantined() SNAPSHOT
    // taken at the top of tick(), before the release (which happens later,
    // inside this same call's dispatch). The gauge only reflects the release
    // starting with the NEXT tick's snapshot — checked below.

    // A further tick must not attempt to poll a response for a command
    // whose record is gone (the fix erased the per-agent state entirely on
    // "device is not quarantined" rather than setting pending=apply on an
    // unchecked write) — no second dispatch call. And THIS tick's snapshot
    // no longer contains agent-1 at all, so the unconfirmed gauge is 0.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    reconciler.tick();
    CHECK(dispatch.calls.size() == 1);
    CHECK(metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a release racing mark_endpoint_confirmed does not "
          "leave the reconciler falsely believing the device is confirmed",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive to the status-dispatch step normally (apply -> poll(no dispatch) -> status verify).
    reconciler.tick(); // 1: apply dispatched
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|quarantined|rules_applied|1");
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply response, schedules status verify — no new dispatch
    CHECK(dispatch.calls.size() == 1);
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches the status verify
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "status");

    // NOW release the device — racing the eventual mark_endpoint_confirmed
    // call that fires once this status response is polled and parses as
    // state|active.
    store_status_response(rstore, "cmd-2", "agent-1", "state|active");
    REQUIRE(qstore.release_device("agent-1").has_value());
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls cmd-2 -> confirms containment -> mark_endpoint_confirmed hits 0 rows

    // The fix must NOT set confirmed=true on that failed write — verified
    // indirectly: a THIRD tick, if the agent were wrongly marked confirmed,
    // would exclude it from to_reconcile forever with no further activity;
    // since the record is genuinely gone, the correct outcome is simply "no
    // further dispatch, no active record to track" either way. The stronger
    // check is that the store itself was never re-quarantined by this path
    // and stays released.
    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    CHECK_FALSE(status->has_value()); // still released — the reconciler did not resurrect it
}

TEST_CASE("QuarantineContainmentReconciler: backoff doubling takes effect on THIS attempt's "
          "deadline, not only a future one (no premature retry)",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    // A generous claim interval (200ms) but a SHORT response wait (30ms), so
    // a timed-out poll's freshly-doubled backoff is easy to distinguish from
    // "immediately eligible again" in a fast test.
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .min_reapply_interval_override = std::chrono::milliseconds(200),
        .response_wait_override = std::chrono::milliseconds(30),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // apply dispatched; claim deadline ~200ms out (min_reapply_interval)
    REQUIRE(dispatch.calls.size() == 1);
    // Never seed a response — force the response_wait timeout path, which is
    // where the fix adds `next_eligible_at = steady_now + st.backoff`. Must
    // sleep PAST the 200ms claim window itself (a second reconcile_one call
    // cannot even run before then), which is also comfortably past
    // response_wait(30ms), so the poll below sees both "empty" and
    // "timed_out" at once.
    std::this_thread::sleep_for(std::chrono::milliseconds(220));
    reconciler.tick(); // times out, doubles backoff, and (fixed) advances next_eligible_at NOW
    CHECK(dispatch.calls.size() == 1); // no new dispatch on the timeout-processing call itself

    // Immediately after, a heartbeat must NOT be able to claim again — if the
    // bug were present, next_eligible_at would still be the ORIGINAL ~200ms
    // claim (already elapsed by now, since we're well past 40ms), letting
    // this call straight through to a second dispatch. The fix rebases the
    // deadline to now + the NEWLY DOUBLED backoff (400ms), so this must be
    // rate-limited.
    reconciler.notify_agent_heartbeat("agent-1");
    CHECK(dispatch.calls.size() == 1); // still just the one dispatch — no premature retry
}

// #3425 governance Gate 2 (security-guardian, 2026-08-24): the two regression
// tests above both wire `.audit_store = nullptr`, so neither one could ever
// have caught a missing audit row on the mark_endpoint_applied/confirmed
// failure path — the exact gap the fix below closes. This test wires a REAL
// AuditStore and asserts the "dispatch accepted but the durable stamp
// failed" row actually lands with result="failure".
yuzu::test::PgTestTemplate quarantine_recon_audit_tpl{"reconaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("reconaudit template: store failed to migrate");
}};

TEST_CASE("QuarantineContainmentReconciler: a release racing mark_endpoint_applied still leaves "
          "an audit row for the dispatch that already happened",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "").has_value());
    auto pre_status = qstore.get_status("agent-1");
    REQUIRE(pre_status.has_value());
    REQUIRE(pre_status->has_value());
    const std::int64_t record_id = (*pre_status)->id;

    YUZU_REQUIRE_PG_DB_TPL(adb, quarantine_recon_audit_tpl);
    PgPool apool{{.conninfo = adb.dsn(), .size = 4}};
    AuditStore astore{apool};
    REQUIRE(astore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    // Same K1 injection as the test above: release from inside the dispatch
    // callback so mark_endpoint_applied's guarded UPDATE affects zero rows —
    // but this time with a real audit_store wired, so the fix's
    // audit_unstamped call has somewhere real to land.
    dispatch.on_dispatch = [&] { REQUIRE(qstore.release_device("agent-1").has_value()); };

    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = &astore,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1); // the dispatch itself still happened

    AuditQuery aq;
    aq.action = "quarantine.reapply";
    auto events = astore.query(aq);
    REQUIRE(events.has_value());
    REQUIRE(events->size() == 1); // the one "dispatch accepted, stamp failed" row — no crash, no silent drop
    CHECK(events->front().result == "failure"); // the store write failed — must not claim "success"
    CHECK(events->front().target_id == "agent-1");
    CHECK(events->front().detail.find("dispatch accepted") != std::string::npos);
    CHECK(events->front().detail.find("device is not quarantined") != std::string::npos);
    // governance Gate 6 (compliance-officer, Finding 2): the audit detail
    // must carry the same record identity the store-level guarded UPDATE is
    // scoped by, so a release-then-requarantine race leaves an unambiguous
    // audit trail across the two quarantine episodes for this agent_id.
    CHECK(events->front().detail.find("record_id=" + std::to_string(record_id)) !=
          std::string::npos);
}

// #3425 governance Gate 4 (unhappy-path, Finding A, 2026-08-24): a
// release-then-requarantine sequence landing inside a reconcile cycle for
// the OLD record must never have its confirmation/apply stamp land on the
// NEW, unrelated record — that record's whitelist was never actually
// dispatched. Fixed by scoping `mark_endpoint_applied`/`mark_endpoint_confirmed`
// to the specific `QuarantineRecord::id` the dispatch was built from,
// threaded through `AgentState::pending_record_id`. Same deterministic
// on_dispatch injection technique as the K1/K2 regression tests above.
TEST_CASE("QuarantineContainmentReconciler: a release+requarantine race does not misattribute "
          "the apply stamp to the NEW unrelated record, and the new record still gets its own "
          "fresh apply",
          "[pg][quarantine][reconciler][regression]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "10.0.0.1").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    registry.register_agent(make_info("agent-1"));

    MockDispatch dispatch;
    // Fires after the apply dispatch (with the OLD record's whitelist,
    // 10.0.0.1) is recorded but BEFORE reconcile_one's own
    // mark_endpoint_applied call: release the OLD record and immediately
    // re-quarantine with a DIFFERENT whitelist — an operator's
    // release-then-requarantine-for-a-new-reason sequence landing in the
    // window between dispatch and the store stamp.
    dispatch.on_dispatch = [&] {
        REQUIRE(qstore.release_device("agent-1").has_value());
        REQUIRE(qstore.quarantine_device("agent-1", "admin", "NEW-reason", "99.99.99.99")
                    .has_value());
    };

    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);
    // What was ACTUALLY dispatched was the OLD record's whitelist — the
    // stored-whitelist-only invariant holds for the dispatch itself.
    CHECK(dispatch.calls[0].parameters.at("whitelist_ips") == "10.0.0.1");

    // The NEW record (whitelist 99.99.99.99, reason NEW-reason) is now the
    // sole 'active' row for agent-1 — and it must be COMPLETELY untouched by
    // the failed (id-mismatched) mark_endpoint_applied call.
    auto status = qstore.get_status("agent-1");
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    CHECK((*status)->whitelist == "99.99.99.99");
    CHECK((*status)->reason == "NEW-reason");
    CHECK((*status)->last_applied_at == 0); // NOT stamped — this is the fix
    CHECK((*status)->last_confirmed_at == 0);

    // A further tick must dispatch a FRESH apply for the NEW record's own
    // whitelist — proving this isn't just non-corruption but real recovery.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].parameters.at("whitelist_ips") == "99.99.99.99");
}

// #3425 governance Gate 5 (chaos-injector, Finding 4b, 2026-08-24): tick()'s
// reconcile loop had NO interior cancellation check — once started, a single
// tick() call could sequentially work through every eligible agent (up to
// kMaxDispatchesPerTick) with no way to interrupt it before returning,
// compounding with the thread-join step in ServerImpl::stop() that runs
// before it. Deps::should_stop closes this: checked once per loop
// iteration, so a shutdown request bounds how many MORE agents one tick()
// call starts (an already-in-flight reconcile_one still completes cleanly —
// this only stops the NEXT one from starting).
TEST_CASE("QuarantineContainmentReconciler: tick() stops starting further agents once "
          "should_stop() reports true, deferring the rest to the next tick",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    for (int i = 1; i <= 5; ++i) {
        const std::string agent_id = "agent-" + std::to_string(i);
        REQUIRE(qstore.quarantine_device(agent_id, "admin", "malware", "").has_value());
        registry.register_agent(make_info(agent_id));
    }

    MockDispatch dispatch;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        // Stop signals true once 2 of the 5 eligible agents have already
        // been dispatched — proving the loop actually checks should_stop()
        // and exits early rather than pushing through all 5.
        .should_stop = [&dispatch] { return dispatch.calls.size() >= 2; },
    });

    reconciler.tick();

    REQUIRE(dispatch.calls.size() == 2); // NOT 5 — the loop stopped early
    for (const auto& call : dispatch.calls)
        CHECK(call.action == "quarantine"); // the 2 that did go out were real, correct dispatches

    // Exactly 2 of the 5 records were stamped applied — the other 3 are
    // completely untouched (no partial state), proving this is a clean
    // defer, not a lost or corrupted record.
    int applied_count = 0;
    for (int i = 1; i <= 5; ++i) {
        auto status = qstore.get_status("agent-" + std::to_string(i));
        REQUIRE(status.has_value());
        REQUIRE(status->has_value());
        if ((*status)->last_applied_at > 0)
            ++applied_count;
    }
    CHECK(applied_count == 2);
}
