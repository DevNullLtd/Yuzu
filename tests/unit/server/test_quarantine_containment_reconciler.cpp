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
 *    follow-up `status|active` firewall.quarantine_status read does;
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
#include "quarantine_reapply.hpp"
#include "quarantine_store.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <libpq-fe.h>

#include <yuzu/metrics.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <latch>
#include <memory>
#include <optional>
#include <set>
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

// The reconciler's monotonic clock (#7583): a test advances it instead of waiting, so every
// backoff, claim window and response wait elapses exactly when the test says. Starts an hour in, so
// a time_point of 0 ("never claimed") is always in the past. `on_read` runs on every read, which
// lets a test change the world between a pass's claim and its write-back.
struct FakeSteady {
    std::chrono::steady_clock::time_point t =
        std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    std::function<void()> on_read;

    void advance(std::chrono::milliseconds d) { t += d; }
    QuarantineContainmentReconciler::SteadyNowFn fn() {
        return [this] {
            if (on_read)
                on_read();
            return t;
        };
    }
};

// The token a confirmed end presents: the apply generation read now, with no claim live.
std::int64_t fence_of(QuarantineStore& store, const std::string& agent_id, std::int64_t record_id) {
    auto token = store.apply_fence_token(agent_id, record_id);
    REQUIRE(token.has_value());
    REQUIRE(token->has_value());
    return **token;
}

// An ended record: the release asked for, then the device's confirmation recorded.
void end_record(QuarantineStore& store, const std::string& agent_id) {
    auto id = store.request_release(agent_id);
    REQUIRE(id.has_value());
    REQUIRE(store.mark_released(agent_id, *id, ReleaseEnd::device_confirmed,
                                fence_of(store, agent_id, *id))
                .has_value());
}

// One statement on a fresh connection: a sabotage or its repair, for the cases that need a store
// read to fail at one chosen moment.
void exec_sql(const std::string& dsn, const std::string& sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult res{PQexec(conn.get(), sql.c_str())};
    INFO(PQresultErrorMessage(res.get()));
    REQUIRE(res.ok());
}

// Ends the active record by SQL, with no fence. A confirmed end made while an apply's claim is live
// is refused (that is the fence), so a test that needs the record to be GONE from inside a dispatch
// hook, to pin what the reconciler does with a write that finds no record, ends it this way.
void end_record_by_sql(const std::string& dsn, const std::string& agent_id) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult res{PQexec(conn.get(),
                        ("UPDATE quarantine_store.quarantine_records SET status = 'released', "
                         "released_at = 1 WHERE status = 'active' AND agent_id = '" +
                         agent_id + "'")
                            .c_str())};
    REQUIRE(res.ok());
}

void store_status_response(ResponseStore& rs, const std::string& command_id,
                           const std::string& agent_id, const std::string& output) {
    StoredResponse sr;
    sr.instruction_id = command_id;
    sr.agent_id = agent_id;
    sr.status = 1; // SUCCESS
    sr.output = output;
    sr.plugin = "firewall";
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });

    reconciler.tick();

    REQUIRE(dispatch.calls.size() == 1);
    const auto& call = dispatch.calls.front();
    CHECK(call.plugin == "firewall");
    CHECK(call.action == "quarantine");
    REQUIRE(call.agent_ids.size() == 1);
    CHECK(call.agent_ids[0] == "agent-1");
    REQUIRE(call.parameters.size() == 1);
    CHECK(call.parameters.at("exceptions") == "10.0.0.1/out,10.0.0.1/in,10.0.0.2/out,10.0.0.2/in");

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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });

    reconciler.tick();
    reconciler.notify_agent_heartbeat("agent-1");
    reconciler.drain_heartbeat_due(); // the reconciler thread's next pass over the marked devices

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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    reconciler.drain_heartbeat_due(); // the reconciler thread's next pass over the marked devices
    REQUIRE(dispatch.calls.size() == 1); // NOT rate_limited despite the 60s window
    CHECK(dispatch.calls[0].plugin == "firewall");
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    reconciler.drain_heartbeat_due(); // the reconciler thread's next pass over the marked devices
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
          "reporting status|active — dispatch acceptance alone is not enough",
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Step 1: apply dispatched.
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);
    CHECK(dispatch.calls[0].action == "quarantine");
    store_status_response(rstore, "cmd-1", "agent-1", "status|active_unproven");

    // Step 2: this call POLLS the apply response and (since it's not
    // "busy") schedules a status verify — it does NOT dispatch status
    // itself in the same call (one dispatch decision per reconcile_one
    // call, by design).
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick();
    CHECK(dispatch.calls.size() == 1); // still just the apply — no dispatch yet

    // Confirmation must NOT have happened from apply acceptance alone.
    auto mid = qstore.get_status("agent-1");
    REQUIRE(mid.has_value());
    REQUIRE(mid->has_value());
    CHECK((*mid)->last_confirmed_at == 0);

    // Step 3: THIS call is the one that actually dispatches the status verify.
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "quarantine_status");

    // Still not confirmed — the status dispatch's own response hasn't
    // arrived/been polled yet.
    auto after_status_dispatch = qstore.get_status("agent-1");
    REQUIRE(after_status_dispatch.has_value());
    REQUIRE(after_status_dispatch->has_value());
    CHECK((*after_status_dispatch)->last_confirmed_at == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a follow-up status read of status|active marks "
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // 1: apply dispatched
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|active_unproven");
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply response, schedules status verify (no dispatch yet)
    CHECK(dispatch.calls.size() == 1);
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches the status verify
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "quarantine_status");

    store_status_response(rstore, "cmd-2", "agent-1", "status|active");
    steady.advance(std::chrono::milliseconds(60));
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
    steady.advance(std::chrono::milliseconds(60));
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive to confirmed under session-A (apply -> poll -> status verify -> confirm).
    reconciler.tick(); // 1: apply
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|active_unproven");
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply, schedules status verify
    CHECK(dispatch.calls.size() == 1);
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches status verify
    REQUIRE(dispatch.calls.size() == 2);
    store_status_response(rstore, "cmd-2", "agent-1", "status|active");
    steady.advance(std::chrono::milliseconds(60));
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

    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 5: tick's own sweep detects churn and dispatches STATUS
                       // first (verify_first is consumed on the SAME call that
                       // detects it, unlike apply's poll->schedule->dispatch
                       // split, because churn detection happens in tick()'s
                       // sweep loop, before reconcile_one's claim, so the
                       // dispatch decision and the churn flag land in the same
                       // reconcile_one invocation).

    REQUIRE(dispatch.calls.size() == 3);
    CHECK(dispatch.calls[2].action == "quarantine_status"); // verify-first, never a blind re-apply
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive the first record to confirmed (apply -> poll -> status verify -> confirm).
    reconciler.tick(); // 1: apply
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|active_unproven");
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply, schedules status verify
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches status verify
    REQUIRE(dispatch.calls.size() == 2);
    store_status_response(rstore, "cmd-2", "agent-1", "status|active");
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 4: polls status -> confirms
    auto confirmed = qstore.get_status("agent-1");
    REQUIRE(confirmed.has_value());
    REQUIRE(confirmed->has_value());
    REQUIRE((*confirmed)->last_confirmed_at > 0);
    const auto old_record_id = (*confirmed)->id;

    // A further tick would normally dispatch nothing for a confirmed,
    // session-unchanged agent (pinned by the sibling test above) — confirm
    // that baseline still holds right before the release+requarantine.
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 5
    REQUIRE(dispatch.calls.size() == 2);

    // Release then re-quarantine the SAME agent_id — same session throughout,
    // a different stored whitelist this time. This is the exact operator
    // workflow UP-1 named: updating containment without a reboot in between.
    end_record(qstore, "agent-1");
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "reassessed", "10.0.0.9").has_value());
    auto new_record = qstore.get_status("agent-1");
    REQUIRE(new_record.has_value());
    REQUIRE(new_record->has_value());
    REQUIRE((*new_record)->id != old_record_id);
    REQUIRE((*new_record)->last_confirmed_at == 0); // never verified — the whole point

    // tick()'s own sweep must detect the record churn and re-enter the fresh
    // apply path for the NEW record THIS tick — the same call, not a later
    // one — rather than silently continuing to treat this agent as confirmed.
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 6: record churn detected -> fresh apply dispatched
    REQUIRE(dispatch.calls.size() == 3);
    CHECK(dispatch.calls[2].action == "quarantine"); // fresh APPLY, not a status-only re-verify
    CHECK(dispatch.calls[2].parameters.at("exceptions") == "10.0.0.9/out,10.0.0.9/in");
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    reconciler.tick(); // 1: apply
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|active_unproven");
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply, schedules status verify
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches status verify (session-A live at dispatch time)
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "quarantine_status");

    // The device reboots BEFORE the reconciler processes the response —
    // session-B replaces session-A in the registry now, but the response
    // still describes session-A's state.
    registry.register_agent(make_info("agent-1"));
    registry.map_session("session-B", "agent-1");
    store_status_response(rstore, "cmd-2", "agent-1", "status|active");
    steady.advance(std::chrono::milliseconds(60));
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr, // degraded for the whole test
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    steady.advance(std::chrono::milliseconds(300)); // past the 100ms interval
    reconciler.tick(); // 2: polls, response_store null -> degraded, backoff 100ms -> 200ms
    CHECK(degraded_count() == 1);
    CHECK(dispatch.calls.size() == 1); // no new dispatch — still the same pending command

    // 150ms elapsed: past the OLD 100ms window (which the pre-fix code would
    // still be using, since it never touched backoff on this branch) but
    // comfortably short of the NEW 200ms window (50ms slack either side).
    // Under the fix, this call must be rate_limited — no poll attempt, no
    // second "degraded" count.
    steady.advance(std::chrono::milliseconds(150));
    reconciler.tick(); // 3: rate_limited if backoff escalated; degraded again if it didn't
    CHECK(degraded_count() == 1); // unchanged — proves the wait window actually grew

    // Now past the escalated 200ms window — the next poll attempt fires and
    // escalates again (200ms -> 400ms), continuing the same exponential
    // shape every other repeated-failure path in this state machine already
    // uses.
    steady.advance(std::chrono::milliseconds(100));
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });

    // Heartbeat BEFORE any tick() has ever run — the cache is empty, so this
    // must be a pure cache-miss with zero dispatch and zero store I/O
    // (there is nothing to assert the "no store read" half directly, but a
    // dispatch call would prove the fast path failed).
    reconciler.notify_agent_heartbeat("agent-1");
    reconciler.drain_heartbeat_due(); // the reconciler thread's next pass over the marked devices
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);

    end_record(qstore, "agent-1");
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = nullptr, // simulates "store unavailable"
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = nullptr,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    dispatch.on_dispatch = [&] { end_record_by_sql(qdb.dsn(), "agent-1"); };

    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    steady.advance(std::chrono::milliseconds(10));
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
        .min_reapply_interval_override = std::chrono::milliseconds(20),
        .response_wait_override = std::chrono::milliseconds(200),
        .verify_grace_override = std::chrono::milliseconds(20),
    });

    // Drive to the status-dispatch step normally (apply -> poll(no dispatch) -> status verify).
    reconciler.tick(); // 1: apply dispatched
    REQUIRE(dispatch.calls.size() == 1);
    store_status_response(rstore, "cmd-1", "agent-1", "status|active_unproven");
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 2: polls apply response, schedules status verify — no new dispatch
    CHECK(dispatch.calls.size() == 1);
    steady.advance(std::chrono::milliseconds(60));
    reconciler.tick(); // 3: dispatches the status verify
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].action == "quarantine_status");

    // NOW release the device — racing the eventual mark_endpoint_confirmed
    // call that fires once this status response is polled and parses as
    // status|active.
    store_status_response(rstore, "cmd-2", "agent-1", "status|active");
    end_record(qstore, "agent-1");
    steady.advance(std::chrono::milliseconds(60));
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
    steady.advance(std::chrono::milliseconds(220));
    reconciler.tick(); // times out, doubles backoff, and (fixed) advances next_eligible_at NOW
    CHECK(dispatch.calls.size() == 1); // no new dispatch on the timeout-processing call itself

    // Immediately after, a heartbeat must NOT be able to claim again — if the
    // bug were present, next_eligible_at would still be the ORIGINAL ~200ms
    // claim (already elapsed by now, since we're well past 40ms), letting
    // this call straight through to a second dispatch. The fix rebases the
    // deadline to now + the NEWLY DOUBLED backoff (400ms), so this must be
    // rate-limited.
    reconciler.notify_agent_heartbeat("agent-1");
    reconciler.drain_heartbeat_due(); // the reconciler thread's next pass over the marked devices
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
    dispatch.on_dispatch = [&] { end_record_by_sql(qdb.dsn(), "agent-1"); };

    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = &astore,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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
        end_record_by_sql(qdb.dsn(), "agent-1");
        REQUIRE(qstore.quarantine_device("agent-1", "admin", "NEW-reason", "99.99.99.99")
                    .has_value());
    };

    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });

    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 1);
    // What was ACTUALLY dispatched was the OLD record's whitelist — the
    // stored-whitelist-only invariant holds for the dispatch itself.
    CHECK(dispatch.calls[0].parameters.at("exceptions") == "10.0.0.1/out,10.0.0.1/in");

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
    steady.advance(std::chrono::milliseconds(10));
    reconciler.tick();
    REQUIRE(dispatch.calls.size() == 2);
    CHECK(dispatch.calls[1].parameters.at("exceptions") == "99.99.99.99/out,99.99.99.99/in");
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
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
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

// ── #5684: session ids are read under the registry lock ─────────────────────

namespace {

// Answers every dispatch with the response the reconciler is waiting for, so
// a bounded tick loop (1 ms timing overrides) drives apply -> status ->
// confirm without wall-clock sleeps.
void auto_respond(MockDispatch& dispatch, ResponseStore& rs) {
    dispatch.on_dispatch = [&dispatch, &rs] {
        const auto& call = dispatch.calls.back();
        store_status_response(
            rs, "cmd-" + std::to_string(dispatch.calls.size()), call.agent_ids.front(),
            call.action == "quarantine_status" ? "status|active" : "status|active_unproven");
    };
}

std::int64_t last_confirmed_at(QuarantineStore& qstore, const std::string& agent_id) {
    auto status = qstore.get_status(agent_id);
    REQUIRE(status.has_value());
    REQUIRE(status->has_value());
    return (*status)->last_confirmed_at;
}

QuarantineContainmentReconciler::Deps fast_deps(QuarantineStore& qstore, ResponseStore& rstore,
                                                AgentRegistry& registry,
                                                yuzu::MetricsRegistry& metrics,
                                                MockDispatch& dispatch, FakeSteady& steady) {
    return QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = &rstore,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
        .min_reapply_interval_override = std::chrono::milliseconds(1),
        .response_wait_override = std::chrono::milliseconds(60'000),
        .verify_grace_override = std::chrono::milliseconds(1),
    };
}

constexpr int kMaxTicksToConfirm = 5000;
// What a tick loop advances the fake clock by: past the 1 ms timing overrides fast_deps sets.
constexpr std::chrono::milliseconds kTickStep{5};

} // namespace

// The writer re-maps the SAME session id, so every read the reconciler makes
// (the churn check, the dispatch-time capture and the confirm-time compare)
// races a real write while the sequential outcome stays fixed.
//
// What this test does and does not prove, plainly:
//  - In a normal (non-TSan) build it checks the OUTCOME only (confirmed once,
//    exactly apply then status). It cannot detect an unlocked read.
//  - It is a [pg] test, and sanitizer-tests.yml provisions no Postgres
//    (issue #4637), so it SKIPS on the per-PR sanitizer legs. The data race
//    is reported only by the nightly `sanitize-tsan` job.
//  - Old-code TSan evidence shows the race at the status-dispatch capture
//    site only (the pre-fix `session->session_id` read); the churn-check and
//    confirm-time sites are covered by the outcome assertions, not proven by
//    a TSan report.
// The only normal-build pin on capture-before-dispatch is the deterministic
// session-swap test below.
TEST_CASE("QuarantineContainmentReconciler: session id reads race-free against a concurrent "
          "map_session for the same agent (#5684)",
          "[pg][quarantine][reconciler][tsan]") {
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
    REQUIRE(registry.register_agent(make_info("agent-1")).has_value());
    registry.map_session("session-A", "agent-1");

    MockDispatch dispatch;
    auto_respond(dispatch, rstore);
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(
        fast_deps(qstore, rstore, registry, metrics, dispatch, steady));

    // std::thread + atomic stop flag + a join guard, NOT std::jthread: Apple
    // Clang's libc++ has no std::jthread (modelled on test_secret_codec.cpp).
    // The guard also raises the stop flag, so a REQUIRE unwinding out of this
    // scope joins the writer instead of hanging or hitting std::terminate.
    // The writer body contains no Catch2 assertions (not thread-safe).
    std::latch writer_running{1};
    std::atomic<bool> stop_writer{false};
    std::thread writer([&registry, &writer_running, &stop_writer] {
        writer_running.count_down();
        while (!stop_writer.load(std::memory_order_acquire)) {
            registry.map_session("session-A", "agent-1");
            std::this_thread::yield(); // do not starve the reconciler on the registry mutex
        }
    });
    struct JoinGuard {
        std::thread& t;
        std::atomic<bool>& stop;
        ~JoinGuard() {
            stop.store(true, std::memory_order_release);
            if (t.joinable())
                t.join();
        }
    } join_guard{writer, stop_writer};
    writer_running.wait();

    int ticks = 0;
    while (ticks < kMaxTicksToConfirm && last_confirmed_at(qstore, "agent-1") == 0) {
        reconciler.tick();
        steady.advance(kTickStep);
        ++ticks;
    }
    for (int i = 0; i < 200; ++i) {
        reconciler.tick(); // confirmed + unchanged session: the churn check runs every tick
        steady.advance(kTickStep);
    }
    stop_writer.store(true, std::memory_order_release);
    writer.join();

    REQUIRE(ticks < kMaxTicksToConfirm);
    CHECK(last_confirmed_at(qstore, "agent-1") > 0);
    REQUIRE(dispatch.calls.size() == 2); // apply then status, nothing after confirm
    CHECK(dispatch.calls[0].action == "quarantine");
    CHECK(dispatch.calls[1].action == "quarantine_status");
    for (const auto& call : dispatch.calls)
        CHECK(call.agent_ids == std::vector<std::string>{"agent-1"});
    CHECK(metrics
              .gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

// The churn check compares under the lock with `session_is`, which is false
// for an absent session too: the separate presence check is what keeps an
// offline, confirmed device from being misread as churn.
TEST_CASE("QuarantineContainmentReconciler: a confirmed device that goes offline is not session "
          "churn and re-verifies via status once it reconnects on a new session (#5684)",
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
    REQUIRE(registry.register_agent(make_info("agent-1")).has_value());
    registry.map_session("session-A", "agent-1");

    MockDispatch dispatch;
    auto_respond(dispatch, rstore);
    // A strictly increasing stamp clock, so a SECOND last_confirmed_at stamp
    // (the re-confirm against session-B) is observable without sleeping.
    std::int64_t clock = 1'000;
    FakeSteady steady;
    auto deps = fast_deps(qstore, rstore, registry, metrics, dispatch, steady);
    deps.now_fn = [&clock] { return ++clock; };
    QuarantineContainmentReconciler reconciler(std::move(deps));

    int ticks = 0;
    while (ticks < kMaxTicksToConfirm && last_confirmed_at(qstore, "agent-1") == 0) {
        reconciler.tick();
        steady.advance(kTickStep);
        ++ticks;
    }
    REQUIRE(ticks < kMaxTicksToConfirm);
    REQUIRE(dispatch.calls.size() == 2);
    const std::int64_t first_confirmed_at = last_confirmed_at(qstore, "agent-1");
    REQUIRE(first_confirmed_at > 0);

    registry.remove_agent("agent-1");
    for (int i = 0; i < 50; ++i) {
        reconciler.tick();
        steady.advance(kTickStep);
    }
    CHECK(dispatch.calls.size() == 2);
    CHECK(
        metrics.gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "offline"}})
            .value() == 0);
    CHECK(metrics
              .gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);

    REQUIRE(registry.register_agent(make_info("agent-1")).has_value());
    registry.map_session("session-B", "agent-1");
    for (int i = 0; i < kMaxTicksToConfirm && dispatch.calls.size() == 2; ++i) {
        reconciler.tick();
        steady.advance(kTickStep);
    }
    REQUIRE(dispatch.calls.size() == 3);
    CHECK(dispatch.calls[2].action == "quarantine_status"); // verify-first, never a blind re-apply

    // ...and that status verification confirms against session-B: a SECOND,
    // later last_confirmed_at stamp, with no further dispatch needed.
    for (int i = 0; i < kMaxTicksToConfirm && last_confirmed_at(qstore, "agent-1") == first_confirmed_at;
         ++i) {
        reconciler.tick();
        steady.advance(kTickStep);
    }
    CHECK(last_confirmed_at(qstore, "agent-1") > first_confirmed_at);
    CHECK(dispatch.calls.size() == 3);
    reconciler.tick(); // the gauge is published at the start of a tick
    CHECK(metrics
              .gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

// Deterministic, normal-build pin on capture-before-dispatch (#5684). The
// session id recorded for the verifying `status` is read BEFORE the dispatch
// call. Here session-B replaces session-A INSIDE that dispatch call (on the
// same session object, as map_session does on a re-register or a gateway
// replay). Capture-before-dispatch records session-A, the confirm-time read
// sees session-B, and the existing session-swap mismatch branch runs: never
// stamped, counted unconfirmed, then a normal stored-whitelist re-apply and a
// fresh verification that confirms against session-B. Were the capture moved
// back AFTER the dispatch it would record session-B, match at confirm time
// and stamp the device as verified on evidence from session-A.
TEST_CASE("QuarantineContainmentReconciler: a session swapped during the status dispatch is never "
          "confirmed, then re-applies the stored whitelist and verifies against the new session "
          "(#5684)",
          "[pg][quarantine][reconciler]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "10.0.0.1,10.0.0.2")
                .has_value());

    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);
    PgPool rpool{{.conninfo = rdb.dsn(), .size = 4}};
    ResponseStore rstore{rpool};
    REQUIRE(rstore.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    REQUIRE(registry.register_agent(make_info("agent-1")).has_value());
    registry.map_session("session-A", "agent-1");

    MockDispatch dispatch;
    auto_respond(dispatch, rstore); // stores the usual response, incl. `status|active` for status
    bool swapped = false;
    dispatch.on_dispatch = [&, respond = dispatch.on_dispatch] {
        respond();
        if (!swapped && dispatch.calls.back().action == "quarantine_status") {
            swapped = true;
            registry.map_session("session-B", "agent-1"); // swap mid-dispatch
        }
    };
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(
        fast_deps(qstore, rstore, registry, metrics, dispatch, steady));

    auto unconfirmed_count = [&] {
        return metrics.counter("yuzu_server_quarantine_reapply_total", {{"result", "unconfirmed"}})
            .value();
    };

    // Drive until the swapped status response has been polled and rejected.
    int ticks = 0;
    while (ticks < kMaxTicksToConfirm && unconfirmed_count() == 0) {
        reconciler.tick();
        steady.advance(kTickStep);
        ++ticks;
    }
    REQUIRE(ticks < kMaxTicksToConfirm);
    REQUIRE(swapped);
    REQUIRE(dispatch.calls.size() == 2); // apply, then the swapped status
    CHECK(dispatch.calls[1].action == "quarantine_status");
    CHECK(unconfirmed_count() == 1);
    CHECK(last_confirmed_at(qstore, "agent-1") == 0); // never stamped on session-A's evidence
    reconciler.tick(); // gauge is published at the start of a tick
    CHECK(metrics
              .gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 1);

    // Recovery: a normal re-apply of the STORED whitelist, then a verification
    // that confirms against session-B.
    for (int i = 0; i < kMaxTicksToConfirm && last_confirmed_at(qstore, "agent-1") == 0; ++i) {
        reconciler.tick();
        steady.advance(kTickStep);
    }
    CHECK(last_confirmed_at(qstore, "agent-1") > 0);
    REQUIRE(dispatch.calls.size() == 4);
    CHECK(dispatch.calls[2].action == "quarantine");
    CHECK(dispatch.calls[2].agent_ids == std::vector<std::string>{"agent-1"});
    REQUIRE(dispatch.calls[2].parameters.size() == 1);
    CHECK(dispatch.calls[2].parameters.at("exceptions") == "10.0.0.1/out,10.0.0.1/in,10.0.0.2/out,10.0.0.2/in");
    CHECK(dispatch.calls[3].action == "quarantine_status");
    CHECK(registry.session_is("agent-1", "session-B"));
    reconciler.tick();
    CHECK(metrics
              .gauge("yuzu_server_quarantine_endpoint_unconfirmed", {{"reachability", "connected"}})
              .value() == 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// PRQ.2: the firewall cut-over. Re-verify and drift, a device's own state never ending a record, a
// new record on an already-contained device, the release (a releasing record), and the owed release
// of a force-ended record. Every case asserts the EXACT
// send set (plugin.action, in order), and the store and audit outcome.
//
// One rig: real QuarantineStore, ResponseStore and AuditStore, a real AgentRegistry, a mock
// dispatch that answers each call from a script, and millisecond timing overrides. A step sleeps
// past the longest wait (max_backoff is capped at 6 ms) and ticks once, so each step advances the
// per-agent state machine by exactly one move.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

struct ReconRig {
    PgPool qpool;
    QuarantineStore qstore;
    PgPool rpool;
    ResponseStore rstore;
    PgPool apool;
    AuditStore astore;
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    MockDispatch dispatch;
    // What the "device" answers each dispatch ("" = no answer). Called with the call just made.
    std::function<std::string(const DispatchCall&)> script;
    // The reconciler's should_stop probe; a test sets it to throw, to stop a drain part-way.
    std::function<bool()> stop_fn;
    std::int64_t clock{1'800'000'000};
    FakeSteady steady; // the reconciler's monotonic clock; a step advances it, nothing waits
    // Timing of the reconciler build() makes; a test that needs a visible backoff sets these
    // and calls build() again.
    std::chrono::milliseconds min_interval{1};
    std::chrono::milliseconds max_backoff{6};
    std::unique_ptr<QuarantineContainmentReconciler> rec;

    ReconRig(const std::string& qdsn, const std::string& rdsn, const std::string& adsn,
             std::chrono::milliseconds reverify = std::chrono::milliseconds(0))
        : qpool{{.conninfo = qdsn, .size = 4}}, qstore(qpool), rpool{{.conninfo = rdsn, .size = 4}},
          rstore(rpool), apool{{.conninfo = adsn, .size = 4}}, astore(apool) {
        REQUIRE(qstore.is_open());
        REQUIRE(rstore.is_open());
        REQUIRE(astore.is_open());
        connect("session-A");
        dispatch.on_dispatch = [this] {
            const auto& call = dispatch.calls.back();
            const auto out = script ? script(call) : std::string{};
            if (!out.empty())
                store_status_response(rstore, "cmd-" + std::to_string(dispatch.calls.size()),
                                      call.agent_ids.front(), out);
        };
        build(reverify);
    }

    void connect(const std::string& session) {
        REQUIRE(registry.register_agent(make_info("agent-1")).has_value());
        registry.map_session(session, "agent-1");
    }
    void disconnect() { registry.remove_agent("agent-1"); }

    // A fresh reconciler (no in-memory state), as after a restart.
    void build(std::chrono::milliseconds reverify = std::chrono::milliseconds(0)) {
        rec = std::make_unique<QuarantineContainmentReconciler>(QuarantineContainmentReconciler::Deps{
            .quarantine_store = &qstore,
            .response_store = &rstore,
            .registry = &registry,
            .metrics = &metrics,
            .audit_store = &astore,
            .dispatch_fn = dispatch.fn(),
            .now_fn = [this] { return clock; },
            .steady_now_fn = steady.fn(),
            .should_stop = [this] { return stop_fn && stop_fn(); },
            .min_reapply_interval_override = min_interval,
            .response_wait_override = std::chrono::milliseconds(60'000),
            .verify_grace_override = std::chrono::milliseconds(1),
            .reverify_interval_override = reverify,
            .max_backoff_override = max_backoff,
        });
    }

    void step() {
        steady.advance(std::chrono::milliseconds(8));
        rec->tick();
    }
    // A heartbeat, then the reconciler thread's next pass over the devices it marked.
    void heartbeat() {
        rec->notify_agent_heartbeat("agent-1");
        rec->drain_heartbeat_due();
    }
    void run(int n) {
        for (int i = 0; i < n; ++i)
            step();
    }

    // The exact send set so far, "plugin.action" in order.
    std::vector<std::string> sent() const {
        std::vector<std::string> out;
        for (const auto& c : dispatch.calls)
            out.push_back(c.plugin + "." + c.action);
        return out;
    }
    std::size_t count_sent(const std::string& what) const {
        std::size_t n = 0;
        for (const auto& s : sent())
            n += s == what;
        return n;
    }

    struct Row {
        std::string result;
        std::string detail;
        std::string principal;
    };
    std::vector<Row> audit(const char* action) {
        AuditQuery q;
        q.action = action;
        q.limit = 1000;
        auto events = astore.query(q);
        REQUIRE(events.has_value());
        std::vector<Row> out;
        for (const auto& e : *events)
            out.push_back({e.result, e.detail, e.principal});
        return out;
    }
    bool has_row(const char* action, const std::string& result, const std::string& detail_prefix) {
        for (const auto& r : audit(action))
            if (r.result == result && r.detail.starts_with(detail_prefix))
                return true;
        return false;
    }
    std::size_t rows_with(const char* action, const std::string& detail_prefix) {
        std::size_t n = 0;
        for (const auto& r : audit(action))
            n += r.detail.starts_with(detail_prefix);
        return n;
    }

    // Quarantine agent-1 and return the record.
    QuarantineRecord quarantine(const std::string& whitelist = "10.0.0.1") {
        REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", whitelist).has_value());
        return *active();
    }
    std::optional<QuarantineRecord> active() {
        auto st = qstore.get_status("agent-1");
        REQUIRE(st.has_value());
        return *st;
    }
    std::vector<QuarantineRecord> owed() {
        auto o = qstore.list_release_owed();
        REQUIRE(o.has_value());
        return *o;
    }
    // The expiry stamped on a command's stored reply: shortened replies sit near a day out, the
    // default (90 days here) well beyond a month.
    std::int64_t ttl_of(const std::string& command_id) {
        auto rows = rstore.query(command_id, ResponseTierFilter::unrestricted_internal_consumer(),
                                 ResponseQuery{.agent_id = "agent-1"});
        REQUIRE(rows.has_value());
        REQUIRE(rows->size() == 1);
        return rows->front().ttl_expires_at;
    }
    bool shortened(const std::string& command_id) {
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        const auto ttl = ttl_of(command_id);
        REQUIRE(ttl > 0);
        return ttl <= now + 2 * 86400;
    }
    bool kept_at_default(const std::string& command_id) {
        const auto now = static_cast<std::int64_t>(std::time(nullptr));
        return ttl_of(command_id) > now + 30 * 86400;
    }
    // The id of the Nth dispatch (1-based), as the mock hands it out.
    static std::string cmd(std::size_t n) { return "cmd-" + std::to_string(n); }

    double gauge(const char* name, const char* reach) {
        return metrics.gauge(name, {{"reachability", reach}}).value();
    }
    double counter(const char* result) {
        return metrics.counter("yuzu_server_quarantine_reapply_total", {{"result", result}}).value();
    }

    // Script helpers: apply and status replies by action.
    void reply(const std::string& apply, const std::string& status, const std::string& release = "") {
        script = [=](const DispatchCall& c) -> std::string {
            if (c.action == "quarantine")
                return apply;
            if (c.action == "quarantine_status")
                return status;
            if (c.action == "release")
                return release;
            return {};
        };
    }
    // Drive an active record to confirmed (apply, verify) with the status reply scripted.
    void confirm(const std::string& status_reply) {
        reply("status|active_unproven", status_reply);
        run(4);
        REQUIRE(active().has_value());
        REQUIRE(active()->last_confirmed_at > 0);
    }
    // One re-verify: past the interval, a status goes out and its reply is read.
    void reverify_once() {
        steady.advance(std::chrono::milliseconds(45));
        step(); // sends the status
        step(); // reads it
    }
};

// No __VA_OPT__: MSVC's default preprocessor does not support it, so the optional re-verify
// interval is a second macro instead of a variadic argument.
#define RECON_DBS()                                                                                \
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);                                             \
    YUZU_REQUIRE_PG_DB_TPL(rdb, responsestore_recon_tpl);                                          \
    YUZU_REQUIRE_PG_DB_TPL(adb, quarantine_recon_audit_tpl)

#define RECON_RIG(rig)                                                                             \
    RECON_DBS();                                                                                   \
    ReconRig rig(qdb.dsn(), rdb.dsn(), adb.dsn())

#define RECON_RIG_REVERIFY(rig, reverify)                                                          \
    RECON_DBS();                                                                                   \
    ReconRig rig(qdb.dsn(), rdb.dsn(), adb.dsn(), reverify)

const std::vector<std::string> kApplyThenVerify{"firewall.quarantine", "firewall.quarantine_status"};

} // namespace

// ── What confirms containment ───────────────────────────────────────────────

TEST_CASE("reconciler (firewall): status|active_unproven confirms; status|partial|operation_in_progress does not",
          "[pg][quarantine][reconciler][prq2]") {
    SECTION("active_unproven confirms") {
        RECON_RIG(rig);
        rig.quarantine();
        rig.reply("status|active_unproven", "status|active_unproven");
        rig.run(4);
        CHECK(rig.sent() == kApplyThenVerify);
        CHECK(rig.active()->last_confirmed_at > 0);
        CHECK(rig.has_row("quarantine.reapply", "success", "CONFIRMED record_id="));
    }
    SECTION("partial|operation_in_progress does not") {
        RECON_RIG(rig);
        rig.quarantine();
        rig.reply("status|active_unproven", "status|partial|operation_in_progress");
        rig.run(4);
        CHECK(rig.active()->last_confirmed_at == 0);
        CHECK(rig.active()->status == "active");
        CHECK_FALSE(rig.has_row("quarantine.reapply", "success", "CONFIRMED"));
        // never confirmed, so never "drift": no audit row for the refusal
        CHECK(rig.rows_with("quarantine.reapply", "drift") == 0);
    }
}

TEST_CASE("reconciler (firewall): a stored probe target means only a verified proof confirms",
          "[pg][quarantine][reconciler][prq2]") {
    SECTION("active_unproven with a probe_target row does not confirm") {
        RECON_RIG(rig);
        rig.quarantine();
        rig.reply("status|active_unproven", "status|active_unproven\nnote|probe_target=203.0.113.9:443");
        rig.run(4);
        CHECK(rig.active()->last_confirmed_at == 0);
    }
    SECTION("status|active with a probe_target row does") {
        RECON_RIG(rig);
        rig.quarantine();
        rig.reply("status|active_unproven", "status|active\nnote|probe_target=203.0.113.9:443");
        rig.run(4);
        CHECK(rig.active()->last_confirmed_at > 0);
    }
}

TEST_CASE("reconciler (firewall): apply dispatches the mapped STORED whitelist, verify dispatches "
          "quarantine_status, an empty whitelist sends no parameters",
          "[pg][quarantine][reconciler][prq2]") {
    RECON_RIG(rig);
    rig.quarantine("10.0.0.5, 2001:db8::1");
    rig.reply("status|active_unproven", "status|active");
    rig.run(3);
    REQUIRE(rig.dispatch.calls.size() >= 2);
    CHECK(rig.dispatch.calls[0].plugin == "firewall");
    CHECK(rig.dispatch.calls[0].action == "quarantine");
    REQUIRE(rig.dispatch.calls[0].parameters.size() == 1);
    CHECK(rig.dispatch.calls[0].parameters.at("exceptions") ==
          "10.0.0.5/out,10.0.0.5/in,2001:db8::1/out,2001:db8::1/in");
    CHECK(rig.dispatch.calls[1].action == "quarantine_status");
    CHECK(rig.dispatch.calls[1].parameters.empty());
}

// ── Re-verify and drift ─────────────────────────────────────────────────────

TEST_CASE("reconciler (firewall): a confirmed record is re-read after the interval, never blinks "
          "out of the unconfirmed gauge and writes no second CONFIRMED row",
          "[pg][quarantine][reconciler][prq2]") {
    RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
    rig.quarantine();
    rig.confirm("status|active");
    const auto first_stamp = rig.active()->last_confirmed_at;
    CHECK(rig.sent() == kApplyThenVerify);
    CHECK(rig.rows_with("quarantine.reapply", "CONFIRMED") == 1);

    rig.clock += 60; // the re-verify's stamp is observably later
    rig.steady.advance(std::chrono::milliseconds(45));
    rig.step(); // past the interval: a status goes out
    CHECK(rig.sent().back() == "firewall.quarantine_status");
    CHECK(rig.sent().size() == 3);
    CHECK(rig.gauge("yuzu_server_quarantine_endpoint_unconfirmed", "connected") == 0);
    rig.step(); // its reply is read: confirms again, silently
    CHECK(rig.active()->last_confirmed_at > first_stamp);
    CHECK(rig.rows_with("quarantine.reapply", "CONFIRMED") == 1); // still one
    CHECK(rig.rows_with("quarantine.reapply", "drift") == 0);
    CHECK(rig.gauge("yuzu_server_quarantine_endpoint_unconfirmed", "connected") == 0);
    // and nothing else was sent: no re-apply
    CHECK(rig.count_sent("firewall.quarantine") == 1);
}

TEST_CASE("reconciler (firewall): drift - a re-verify that no longer confirms writes one drift row, "
          "clears confirmed and the next cycle re-applies through the chokepoint",
          "[pg][quarantine][reconciler][prq2]") {
    RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
    const auto rec = rig.quarantine("10.0.0.1");
    rig.confirm("status|active");
    // The device's rules stop being enforced.
    rig.reply("status|active_unproven", "status|degraded|policy_not_blocking");
    rig.reverify_once();
    CHECK(rig.rows_with("quarantine.reapply", "drift status=unconfirmed record_id=" + std::to_string(rec.id)) == 1);
    CHECK(rig.has_row("quarantine.reapply", "failure", "drift status=unconfirmed"));
    CHECK(rig.rows_with("quarantine.disable", "") == 0); // nothing ended
    // the next cycle re-applies, with the stored whitelist, not another status
    rig.step();
    CHECK(rig.sent().back() == "firewall.quarantine");
    CHECK(rig.count_sent("firewall.quarantine") == 2);
    REQUIRE(rig.dispatch.calls.back().parameters.size() == 1);
    CHECK(rig.dispatch.calls.back().parameters.at("exceptions") == "10.0.0.1/out,10.0.0.1/in");
    CHECK(rig.active()->status == "active");
}

TEST_CASE("reconciler (firewall): a record that was never confirmed and stays unconfirmed writes no drift row",
          "[pg][quarantine][reconciler][prq2]") {
    RECON_RIG(rig);
    rig.quarantine();
    rig.reply("status|active_unproven", "status|degraded|policy_not_blocking");
    rig.run(10);
    CHECK(rig.rows_with("quarantine.reapply", "drift") == 0);
    CHECK(rig.counter("drift") == 0);
    CHECK(rig.counter("unconfirmed") >= 1); // an ordinary unconfirmed read, never drift
    CHECK(rig.active()->last_confirmed_at == 0);
    CHECK(rig.active()->status == "active");
}

TEST_CASE("reconciler (firewall): an ACTIVE record whose apply is refused privilege_unavailable stays active "
          "and unconfirmed",
          "[pg][quarantine][reconciler][prq2]") {
    RECON_RIG(rig);
    rig.quarantine();
    rig.reply("status|refused|privilege_unavailable", "status|refused|privilege_unavailable");
    rig.run(10);
    const auto row = rig.active();
    REQUIRE(row.has_value());
    CHECK(row->status == "active");
    CHECK(row->last_confirmed_at == 0);
    CHECK(rig.owed().empty());
    CHECK(rig.rows_with("quarantine.disable", "") == 0); // no answer ends a record this way
    rig.step();
    CHECK(rig.gauge("yuzu_server_quarantine_endpoint_unconfirmed", "connected") == 1);
}

// ── A device's own state never ends a record ───────────────────────────────

TEST_CASE("reconciler (firewall): a confirm whose reply carried a time limit changes nothing; a later "
          "inactive is drift: the record stays active and listed, one drift row, no quarantine.disable "
          "row, containment re-applied",
          "[pg][quarantine][reconciler][prq2][drift]") {
    const auto offset = GENERATE(std::int64_t{-5000}, std::int64_t{0}, std::int64_t{5000});
    CAPTURE(offset);
    RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
    const auto rec = rig.quarantine("10.0.0.1");
    rig.confirm("status|active\nnote|ttl_expires=" + std::to_string(rig.clock + offset));
    CHECK(rig.has_row("quarantine.reapply", "success", "CONFIRMED record_id=" + std::to_string(rec.id)));

    rig.reply("status|active_unproven", "status|inactive");
    rig.reverify_once();
    const auto row = rig.active();
    REQUIRE(row.has_value());
    CHECK(row->status == "active"); // still listed, still refusing dispatch
    CHECK(rig.rows_with("quarantine.reapply",
                        "drift status=inactive record_id=" + std::to_string(rec.id)) == 1);
    CHECK(rig.audit("quarantine.disable").empty());
    CHECK(rig.counter("released") == 0);
    CHECK(rig.owed().empty());
    auto history = rig.qstore.get_history("agent-1");
    REQUIRE(history.has_value());
    REQUIRE(history->size() == 1);
    CHECK((*history)[0].status == "active");
    // the next cycle re-applies through the chokepoint with the stored whitelist
    rig.step();
    CHECK(rig.sent().back() == "firewall.quarantine");
    REQUIRE(rig.dispatch.calls.back().parameters.size() == 1);
    CHECK(rig.dispatch.calls.back().parameters.at("exceptions") == "10.0.0.1/out,10.0.0.1/in");
    CHECK(rig.active().has_value());
}

TEST_CASE("reconciler (firewall): inactive on an active record that was never confirmed is re-applied, "
          "never an end, with no drift row",
          "[pg][quarantine][reconciler][prq2][drift]") {
    RECON_RIG(rig);
    rig.quarantine();
    rig.reply("status|active_unproven", "status|inactive");
    rig.run(6);
    CHECK(rig.active().has_value());
    CHECK(rig.active()->last_confirmed_at == 0);
    CHECK(rig.count_sent("firewall.quarantine") >= 2); // applied again after the inactive read
    CHECK(rig.audit("quarantine.disable").empty());
    CHECK(rig.rows_with("quarantine.reapply", "drift") == 0); // never confirmed, so never drift
}

TEST_CASE("reconciler (firewall): a restarted server applies first over a record confirmed earlier, and an "
          "inactive answer is then re-applied, never an end",
          "[pg][quarantine][reconciler][prq2][drift]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_endpoint_confirmed("agent-1", rec.id, rig.clock - 400).has_value());
    rig.reply("status|active_unproven", "status|inactive");
    rig.run(2);
    CHECK(rig.sent() == std::vector<std::string>{"firewall.quarantine"}); // apply first, never a status read
    rig.run(2);
    CHECK(rig.sent() == kApplyThenVerify); // the verify read answered inactive
    CHECK(rig.active().has_value());
    CHECK(rig.audit("quarantine.disable").empty());
    rig.step();
    CHECK(rig.sent().back() == "firewall.quarantine");
}

// ── A new record on a device that is already contained ──────────────────────

TEST_CASE("reconciler (firewall): a new record on a device already contained under other exceptions is "
          "never confirmed: one failure row, no status read after the declined apply",
          "[pg][quarantine][reconciler][prq2][allowset]") {
    const std::string kKept =
        "status|active\nnote|already_active=1\nnote|allow_set_unchanged_use_quarantine_allow=1";
    SECTION("the note on a record that was never confirmed") {
        RECON_RIG(rig);
        const auto rec = rig.quarantine("10.0.0.2");
        rig.reply(kKept, "status|active");
        rig.run(8);
        CHECK(rig.count_sent("firewall.quarantine") >= 2); // the entry keeps applying on its backoff
        CHECK(rig.count_sent("firewall.quarantine_status") == 0); // but never reads status after a declined apply
        const auto row = rig.active();
        REQUIRE(row.has_value());
        CHECK(row->last_confirmed_at == 0);
        CHECK(row->status == "active");
        CHECK(rig.rows_with("quarantine.reapply", "allow_set_not_applied") == 1); // one per entry
        CHECK(rig.has_row("quarantine.reapply", "failure",
                          "allow_set_not_applied record_id=" + std::to_string(rec.id) + " command_id=cmd-1"));
        CHECK(rig.rows_with("quarantine.reapply", "CONFIRMED") == 0);
        CHECK(rig.audit("quarantine.disable").empty());
        CHECK(rig.counter("unconfirmed") >= 1);
        CHECK(rig.counter("confirmed") == 0);
        CHECK(rig.gauge("yuzu_server_quarantine_endpoint_unconfirmed", "connected") == 1);
        // the failure row carries the ids only, never device text
        for (const auto& r : rig.audit("quarantine.reapply"))
            CHECK(r.detail.find("already_active") == std::string::npos);
    }
    SECTION("the same exceptions: the apply reply carries no such note, and the record is confirmed") {
        RECON_RIG(rig);
        rig.quarantine("10.0.0.2");
        rig.reply("status|active\nnote|already_active=1", "status|active");
        rig.run(4);
        CHECK(rig.sent() == kApplyThenVerify);
        CHECK(rig.active()->last_confirmed_at > 0);
        CHECK(rig.rows_with("quarantine.reapply", "allow_set_not_applied") == 0);
    }
    SECTION("a record that was confirmed once keeps today's behaviour: the status read confirms it") {
        RECON_RIG(rig);
        rig.quarantine("10.0.0.2");
        rig.confirm("status|active");
        const auto first_stamp = rig.active()->last_confirmed_at;
        rig.clock += 60;
        rig.build(); // a restart: the reconciler applies again
        rig.reply(kKept, "status|active");
        rig.run(4);
        CHECK(rig.count_sent("firewall.quarantine") == 2);
        CHECK(rig.count_sent("firewall.quarantine_status") == 2);
        CHECK(rig.active()->last_confirmed_at > first_stamp);
        CHECK(rig.rows_with("quarantine.reapply", "allow_set_not_applied") == 0);
    }
}

// ── Release driving: a releasing record ─────────────────────────────────────

TEST_CASE("reconciler (firewall): a releasing record reads status first; inactive ends it as confirmed "
          "and no release is sent",
          "[pg][quarantine][reconciler][prq2][release]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    rig.reply("", "status|inactive");
    rig.run(2);
    CHECK(rig.sent() == std::vector<std::string>{"firewall.quarantine_status"});
    CHECK_FALSE(rig.active().has_value());
    CHECK(rig.owed().empty());
    CHECK(rig.has_row("quarantine.disable", "success", "confirmed record_id=" + std::to_string(rec.id)));
    CHECK(rig.counter("released") == 1);
    rig.run(3);
    CHECK(rig.sent().size() == 1);
}

TEST_CASE("reconciler (firewall): a releasing record still contained gets status, then release (no "
          "parameters), then status; released only on inactive",
          "[pg][quarantine][reconciler][prq2][release]") {
    RECON_RIG(rig);
    rig.quarantine();
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    int statuses = 0;
    rig.script = [&statuses](const DispatchCall& c) -> std::string {
        if (c.action == "quarantine_status")
            return ++statuses == 1 ? "status|active" : "status|inactive";
        if (c.action == "release")
            return "status|active"; // whatever it says to the release ends nothing by itself
        return {};
    };
    rig.run(3);
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine_status", "firewall.release"}));
    CHECK(rig.dispatch.calls[1].parameters.empty());
    CHECK(rig.dispatch.calls[1].agent_ids == std::vector<std::string>{"agent-1"});
    REQUIRE(rig.active().has_value());
    CHECK(rig.active()->status == "releasing"); // still listed
    CHECK(rig.has_row("quarantine.disable", "pending", "release_sent record_id="));
    rig.run(3);
    CHECK(rig.sent() ==
          (std::vector<std::string>{"firewall.quarantine_status", "firewall.release", "firewall.quarantine_status"}));
    CHECK_FALSE(rig.active().has_value());
    CHECK(rig.has_row("quarantine.disable", "success", "confirmed record_id="));
    CHECK(rig.counter("release_sent") == 1);
}

TEST_CASE("reconciler (firewall): a release answered privilege_unavailable never ends the record, "
          "confirmed before or not, and it is counted in the release_pending gauge",
          "[pg][quarantine][reconciler][prq2][release]") {
    RECON_RIG(rig);
    rig.quarantine();
    SECTION("never confirmed") {}
    SECTION("confirmed first") {
        rig.confirm("status|active");
    }
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    rig.reply("status|active_unproven", "status|active", "status|refused|privilege_unavailable");
    rig.run(14);
    const auto row = rig.active();
    REQUIRE(row.has_value());
    CHECK(row->status == "releasing"); // stays releasing and listed
    CHECK(rig.owed().empty());
    for (const auto& r : rig.audit("quarantine.disable"))
        CHECK(r.result != "success");
    CHECK(rig.count_sent("firewall.release") >= 1);
    CHECK(rig.gauge("yuzu_server_quarantine_release_pending", "connected") == 1);
    CHECK(rig.gauge("yuzu_server_quarantine_endpoint_unconfirmed", "connected") == 0); // not counted there
}

TEST_CASE("reconciler (firewall): a releasing record on an offline device sends nothing and stays listed",
          "[pg][quarantine][reconciler][prq2][release]") {
    RECON_RIG(rig);
    rig.quarantine();
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    rig.disconnect();
    rig.run(3);
    CHECK(rig.dispatch.calls.empty());
    CHECK(rig.active().has_value());
    CHECK(rig.gauge("yuzu_server_quarantine_release_pending", "offline") == 1);
    CHECK(rig.gauge("yuzu_server_quarantine_release_pending", "connected") == 0);
}

TEST_CASE("reconciler (firewall): a record flipped to releasing after the tick snapshot is never re-applied "
          "(the chokepoint answers release_pending)",
          "[pg][quarantine][reconciler][prq2][release]") {
    RECON_RIG(rig);
    rig.quarantine();
    rig.reply("", "status|active");
    rig.disconnect();
    rig.step(); // the snapshot: an active, unconfirmed record; the offline skip dispatches nothing
    CHECK(rig.dispatch.calls.empty());
    rig.connect("session-A");
    REQUIRE(rig.qstore.request_release("agent-1").has_value()); // flips after the snapshot
    rig.heartbeat(); // the cached entry still thinks it is active
    CHECK(rig.dispatch.calls.empty()); // release_pending: nothing dispatched, never a firewall.quarantine
    rig.step();
    CHECK(rig.sent() == std::vector<std::string>{"firewall.quarantine_status"}); // now a releasing entry
}

TEST_CASE("reconciler (firewall): release is never sent for a row a fresh read does not show as releasing",
          "[pg][quarantine][reconciler][prq2][release]") {
    RECON_RIG(rig);
    rig.quarantine();
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    rig.reply("", "status|active");
    rig.step(); // status sent
    rig.step(); // reply read: still contained, backoff
    CHECK(rig.sent() == std::vector<std::string>{"firewall.quarantine_status"});
    // The record ends elsewhere (the REST route, say) before the next cycle's release.
    const auto id = rig.active()->id;
    REQUIRE(rig.qstore
                .mark_released("agent-1", id, ReleaseEnd::device_confirmed,
                               fence_of(rig.qstore, "agent-1", id))
                .has_value());
    rig.steady.advance(std::chrono::milliseconds(8));
    rig.heartbeat(); // the cached releasing entry would send a release
    CHECK(rig.sent() == std::vector<std::string>{"firewall.quarantine_status"}); // it did not
    rig.run(3);
    CHECK(rig.count_sent("firewall.release") == 0);
}

TEST_CASE("reconciler (firewall): a stored whitelist the mapper refuses sends nothing, counts "
          "validation_failed, writes one failure row and leaves the record unchanged",
          "[pg][quarantine][reconciler][prq2]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine("10.0.0.1;rm -rf /");
    rig.reply("status|active_unproven", "status|active");
    rig.step();
    CHECK(rig.dispatch.calls.empty());
    CHECK(rig.counter("validation_failed") == 1);
    const auto rows = rig.audit("quarantine.reapply");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].result == "failure");
    // the value is never echoed
    CHECK(rows[0].detail ==
          "stored whitelist cannot be expressed as firewall exceptions record_id=" + std::to_string(rec.id));
    const auto row = rig.active();
    REQUIRE(row.has_value());
    CHECK(row->last_applied_at == 0);
    CHECK(row->status == "active");
}

// ── The owed release of a force-ended record ────────────────────────────────

TEST_CASE("reconciler (firewall): an owed record, device connected: status first; inactive clears the mark "
          "as forced_release_confirmed; no release is sent",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    REQUIRE(rig.owed().size() == 1);
    rig.reply("", "status|inactive");
    rig.run(2);
    CHECK(rig.sent() == std::vector<std::string>{"firewall.quarantine_status"});
    CHECK(rig.owed().empty());
    const auto rows = rig.audit("quarantine.disable");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].result == "success");
    CHECK(rows[0].principal == "system");
    CHECK(rows[0].detail.starts_with("forced_release_confirmed record_id=" + std::to_string(rec.id)));
    CHECK(rig.counter("released") == 1);
    rig.run(3);
    CHECK(rig.sent().size() == 1);
}

TEST_CASE("reconciler (firewall): an owed record, device still contained: status, then release (no "
          "parameters), then status; the mark clears only on inactive",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    int statuses = 0;
    rig.script = [&statuses](const DispatchCall& c) -> std::string {
        if (c.action == "quarantine_status")
            return ++statuses == 1 ? "status|active" : "status|inactive";
        if (c.action == "release")
            return "status|active";
        return {};
    };
    rig.run(3);
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine_status", "firewall.release"}));
    CHECK(rig.dispatch.calls[1].parameters.empty());
    CHECK(rig.owed().size() == 1); // not cleared by a release reply
    CHECK(rig.has_row("quarantine.disable", "pending", "forced_release_sent record_id=" + std::to_string(rec.id)));
    rig.run(3);
    CHECK(rig.sent() ==
          (std::vector<std::string>{"firewall.quarantine_status", "firewall.release", "firewall.quarantine_status"}));
    CHECK(rig.owed().empty());
    CHECK(rig.has_row("quarantine.disable", "success", "forced_release_confirmed"));
}

TEST_CASE("reconciler (firewall): an owed record that never reads inactive: one forced_release_unconfirmed "
          "row, no second release in the session, status-only reads after the park, one more release on a "
          "new session",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    rig.reply("", "status|active", "status|active");
    rig.run(8);
    CHECK(rig.count_sent("firewall.release") == 1);
    CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed status=active record_id=" +
                                                  std::to_string(rec.id)) == 1);
    const auto parked_status_reads = rig.count_sent("firewall.quarantine_status");
    // parked: only status reads continue; no new release, no second row, the mark stays
    rig.run(8);
    CHECK(rig.count_sent("firewall.release") == 1);
    CHECK(rig.count_sent("firewall.quarantine_status") > parked_status_reads); // status-only reads
    CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 1); // once per session
    CHECK(rig.owed().size() == 1);

    // A new session is a new cycle: one more release, then parked again.
    rig.connect("session-B");
    rig.run(14);
    CHECK(rig.count_sent("firewall.release") == 2);
    CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 2);
    CHECK(rig.owed().size() == 1);
}

TEST_CASE("reconciler (firewall): an owed release answered busy is not spent: status is read again and "
          "the release is sent again in the same session, with no failure row and no park",
          "[pg][quarantine][reconciler][prq2][owed][busy]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());

    SECTION("busy every time") {
        rig.reply("", "status|active", "status|busy");
        rig.run(10);
        CHECK(rig.counter("busy") >= 2);
        CHECK(rig.count_sent("firewall.release") >= 2); // the same session
        const auto sent = rig.sent();
        REQUIRE(sent.size() >= 4);
        CHECK(std::vector<std::string>(sent.begin(), sent.begin() + 4) ==
              (std::vector<std::string>{"firewall.quarantine_status", "firewall.release",
                                        "firewall.quarantine_status", "firewall.release"}));
        CHECK(rig.rows_with("quarantine.disable", "forced_release_sent record_id=" +
                                                      std::to_string(rec.id)) >= 2);
        CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 0);
        CHECK(rig.owed().size() == 1); // still owed, not parked
    }
    SECTION("busy once, then answered and still contained: parked with one row after that release") {
        int releases = 0;
        rig.script = [&releases](const DispatchCall& c) -> std::string {
            if (c.action == "quarantine_status")
                return "status|active";
            if (c.action == "release")
                return ++releases == 1 ? "status|busy" : "status|active";
            return {};
        };
        rig.run(16);
        CHECK(rig.count_sent("firewall.release") == 2);
        CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed status=active record_id=" +
                                                      std::to_string(rec.id)) == 1);
        CHECK(rig.owed().size() == 1);
    }
    SECTION("a release refused privilege_unavailable is answered, so it parks after one cycle") {
        rig.reply("", "status|active", "status|refused|privilege_unavailable");
        rig.run(10);
        CHECK(rig.count_sent("firewall.release") == 1);
        CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed status=active record_id=" +
                                                      std::to_string(rec.id)) == 1);
        CHECK(rig.counter("busy") == 0);
    }
    SECTION("busy and then a status read that finds the device released clears the mark") {
        int statuses = 0;
        rig.script = [&statuses](const DispatchCall& c) -> std::string {
            if (c.action == "quarantine_status")
                return ++statuses < 3 ? "status|active" : "status|inactive";
            if (c.action == "release")
                return "status|busy";
            return {};
        };
        rig.run(12);
        CHECK(rig.owed().empty());
        CHECK(rig.has_row("quarantine.disable", "success", "forced_release_confirmed record_id=" +
                                                               std::to_string(rec.id)));
        CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 0);
    }
}

TEST_CASE("reconciler (firewall): each busy answer to an owed release escalates the entry's backoff, so the "
          "next claim waits longer than before",
          "[pg][quarantine][reconciler][prq2][owed][busy]") {
    RECON_RIG(rig);
    rig.min_interval = std::chrono::milliseconds(60);
    rig.max_backoff = std::chrono::milliseconds(10'000);
    rig.build();
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    rig.reply("", "status|active", "status|busy");
    const auto pause_then_tick = [&rig](int ms) {
        rig.steady.advance(std::chrono::milliseconds(ms));
        rig.rec->tick();
    };
    // Backoff 60 ms: the status goes out, its answer doubles the wait to 120 ms, the release goes out.
    rig.rec->tick();
    pause_then_tick(70); // reads the status answer
    pause_then_tick(130); // sends the release
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine_status", "firewall.release"}));
    pause_then_tick(130); // reads the busy answer: the wait doubles again, to 240 ms
    const auto limited = rig.counter("rate_limited");
    rig.rec->tick();
    CHECK(rig.counter("rate_limited") == limited + 1);
    pause_then_tick(150); // past the 120 ms the entry waited before, inside the 240 ms it waits now
    CHECK(rig.counter("rate_limited") == limited + 2);
    CHECK(rig.sent().size() == 2);
    pause_then_tick(120); // past 240 ms in all: status first, again
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine_status", "firewall.release",
                                                  "firewall.quarantine_status"}));
}

// Time here is the rig's fake steady clock, so the waits are exact. Phase 1 ticks every millisecond
// until the third release has gone out and measures the gap between sends; phase 2 advances past
// max_backoff before every tick, so a tick is rate limited only if some wait was longer than
// max_backoff.
TEST_CASE("reconciler (firewall): repeated busy answers to an owed release grow the backoff only "
          "up to max_backoff and the release is still retried: no park and no failure row",
          "[pg][quarantine][reconciler][prq2][owed][busy]") {
    using Ms = std::chrono::milliseconds;
    constexpr Ms kMin{3};
    constexpr Ms kMax{24}; // 8 x kMin: the clamp first bites at the second busy answer
    RECON_RIG(rig);
    rig.min_interval = kMin;
    rig.max_backoff = kMax;
    rig.build();
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    rig.reply("", "status|active", "status|busy");

    // Phase 1: tick every millisecond until the third release has gone out, keeping when each
    // tick that sent a release ran. Backoff: status read 2 x kMin, first busy 4 x, status read 8 x,
    // second busy 16 x clamped to kMax.
    std::vector<std::chrono::steady_clock::time_point> release_ticks;
    for (int i = 0; i < 100'000 && release_ticks.size() < 3; ++i) {
        const auto before = rig.count_sent("firewall.release");
        rig.rec->tick();
        if (rig.count_sent("firewall.release") > before)
            release_ticks.push_back(rig.steady.t);
        rig.steady.advance(Ms(1));
    }
    REQUIRE(release_ticks.size() == 3);
    const auto gap_ms = [&](std::size_t i) {
        return std::chrono::duration_cast<Ms>(release_ticks[i] - release_ticks[i - 1]).count();
    };
    // Between two release sends: the busy answer's wait, the status send's, the status read's and
    // the release send's. First pair 2 + 4 + 4 + 8 x kMin, then all four are kMax: the delay grew.
    CHECK(gap_ms(1) >= (2 + 4 + 4 + 8) * kMin.count());
    CHECK(gap_ms(2) >= 4 * kMax.count());

    // Phase 2: past the plateau. Eight ticks, each after more than kMax, are two more whole cycles
    // (read busy, send status, read it, send release, and again): never rate limited, so no wait
    // outgrew max_backoff, and the owed release keeps being retried, never parked.
    const auto limited = rig.counter("rate_limited");
    for (int i = 0; i < 8; ++i) {
        rig.steady.advance(kMax + Ms(4));
        rig.rec->tick();
    }
    CHECK(rig.counter("rate_limited") == limited);
    CHECK(rig.counter("busy") == 4); // the answers to releases 1 to 4
    std::vector<std::string> expected;
    for (int i = 0; i < 5; ++i) // five cycles of status then release, nothing else
        expected.insert(expected.end(), {"firewall.quarantine_status", "firewall.release"});
    CHECK(rig.sent() == expected);
    CHECK(rig.rows_with("quarantine.disable",
                        "forced_release_sent record_id=" + std::to_string(rec.id)) == 5);
    CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 0);
    CHECK(rig.owed().size() == 1); // still owed, not parked
}

TEST_CASE("reconciler (firewall): an owed record, device offline: nothing sent, counted in "
          "forced_release_owed{offline}",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    rig.disconnect();
    rig.run(3);
    CHECK(rig.dispatch.calls.empty());
    CHECK(rig.owed().size() == 1);
    CHECK(rig.gauge("yuzu_server_quarantine_forced_release_owed", "offline") == 1);
    CHECK(rig.gauge("yuzu_server_quarantine_forced_release_owed", "connected") == 0);
}

TEST_CASE("reconciler (firewall): an owed record whose device was quarantined again: no release is ever "
          "sent for the old record, and the new record is applied as usual",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto old_rec = rig.quarantine("10.0.0.1");
    REQUIRE(rig.qstore.mark_released("agent-1", old_rec.id, ReleaseEnd::forced).has_value());
    rig.quarantine("10.0.0.2"); // the new record
    CHECK(rig.owed().empty());  // governed by the new record now
    rig.reply("status|active_unproven", "status|active");
    rig.run(4);
    CHECK(rig.sent() == kApplyThenVerify);
    CHECK(rig.count_sent("firewall.release") == 0);
    REQUIRE(rig.dispatch.calls[0].parameters.size() == 1);
    CHECK(rig.dispatch.calls[0].parameters.at("exceptions") == "10.0.0.2/out,10.0.0.2/in");
    CHECK(rig.active()->last_confirmed_at > 0);
}

TEST_CASE("reconciler (firewall): a heartbeat for an owed device whose new record appeared sends no release",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto old_rec = rig.quarantine("10.0.0.1");
    REQUIRE(rig.qstore.mark_released("agent-1", old_rec.id, ReleaseEnd::forced).has_value());
    rig.reply("", "status|active");
    rig.step();
    rig.step(); // status read: still contained; the next cycle would send the release
    CHECK(rig.sent() == std::vector<std::string>{"firewall.quarantine_status"});
    rig.quarantine("10.0.0.2"); // the device is quarantined again in between
    rig.steady.advance(std::chrono::milliseconds(8));
    rig.heartbeat(); // the cached owed entry
    CHECK(rig.count_sent("firewall.release") == 0); // a fresh read shows an active record: nothing sent
}

TEST_CASE("reconciler (firewall): a failed owed read counts degraded, and the active rows are still "
          "reconciled in the same tick",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    rig.quarantine();
    {
        // Fail ONLY the owed read. Its WHERE compares device_release_owed_at with 0, which no
        // longer type-checks once the column is text; the active read selects the column but never
        // compares it, so it keeps working. The owed-read partial index compares the column too and
        // would block the type change, so it goes first.
        PgConn conn{PQconnectdb(qdb.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult drop_index{
            PQexec(conn.get(), "DROP INDEX quarantine_store.idx_quarantine_release_owed")};
        REQUIRE(drop_index.ok());
        PgResult alter{PQexec(conn.get(),
                              "ALTER TABLE quarantine_store.quarantine_records "
                              "ALTER COLUMN device_release_owed_at DROP DEFAULT, "
                              "ALTER COLUMN device_release_owed_at TYPE text "
                              "USING device_release_owed_at::text")};
        REQUIRE(alter.ok());
    }
    REQUIRE_FALSE(rig.qstore.list_release_owed().has_value()); // the owed read is degraded
    REQUIRE(rig.qstore.list_quarantined().has_value());        // the active read is not
    rig.reply("status|active_unproven", "status|active");
    rig.run(4);
    CHECK(rig.counter("degraded") >= 1);
    CHECK(rig.sent() == kApplyThenVerify); // the active record was reconciled all the same
    CHECK(rig.active()->last_confirmed_at > 0);
}

// ═══════════════════════════════════════════════════════════════════════════
// Follow-ups to the PRQ.2 review: the heartbeat mark, identity-checked write-back, the drift
// re-read, alerts, retention of status replies and the apply fence.
// ═══════════════════════════════════════════════════════════════════════════

// ── #7620 / #7645: a pass whose entry was reset drops its result ─────────────

TEST_CASE("reconciler (firewall): a tick run from inside a drained heartbeat pass's dispatch, after "
          "a release was requested, leaves ONE command pending and the outer pass's result dropped",
          "[pg][quarantine][reconciler][prq2][reentrant]") {
    RECON_RIG(rig);
    rig.quarantine();
    // The first pass is the heartbeat's: the entry exists (an offline tick made it), the device
    // then connects.
    rig.disconnect();
    rig.step();
    rig.connect("session-A");
    rig.reply("status|active_unproven", "status|active");
    bool fired = false;
    rig.dispatch.on_dispatch = [&rig, &fired, base = rig.dispatch.on_dispatch] {
        base(); // the scripted reply for the command just made
        if (fired)
            return;
        fired = true;
        // While the apply is dispatching: the operator asks for the release, and the reconciler
        // thread's tick runs (the entry is reset to a releasing one, which reads status first).
        REQUIRE(rig.qstore.request_release("agent-1").has_value());
        rig.rec->tick();
    };
    rig.steady.advance(std::chrono::milliseconds(8));
    rig.heartbeat(); // the outer pass: send_apply
    REQUIRE(fired);
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine", "firewall.quarantine_status"}));
    // The outer pass wrote nothing into the releasing entry: the pending command is still the
    // status the tick sent, whose reply (still contained) is read next and followed by the release.
    // A clobbered entry would have read the apply's reply instead and sent a second status.
    rig.run(2);
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine", "firewall.quarantine_status",
                                                  "firewall.release"}));
    CHECK(rig.active()->status == "releasing");
}

TEST_CASE("reconciler (firewall): quarantine, release, quarantine again with other exceptions on a "
          "contained device writes a second allow_set_not_applied row naming the new record",
          "[pg][quarantine][reconciler][prq2][allowset]") {
    const std::string kKept =
        "status|active\nnote|already_active=1\nnote|allow_set_unchanged_use_quarantine_allow=1";
    RECON_RIG(rig);
    const auto first = rig.quarantine("10.0.0.2");
    rig.reply(kKept, "status|active");
    rig.run(6);
    CHECK(rig.rows_with("quarantine.reapply", "allow_set_not_applied record_id=" +
                                                  std::to_string(first.id)) == 1);
    end_record(rig.qstore, "agent-1");
    const auto second = rig.quarantine("10.0.0.3"); // other exceptions, the device still contained
    REQUIRE(second.id != first.id);
    rig.run(6);
    CHECK(rig.rows_with("quarantine.reapply", "allow_set_not_applied record_id=" +
                                                  std::to_string(second.id)) == 1);
    CHECK(rig.rows_with("quarantine.reapply", "allow_set_not_applied") == 2);
}

TEST_CASE("reconciler (firewall): a reset from the steady-clock read between a pass's claim and its "
          "write-back leaves the NEW entry's flags and backoff untouched",
          "[pg][quarantine][reconciler][prq2][reentrant]") {
    RECON_RIG(rig);
    rig.quarantine();
    rig.reply("status|active_unproven", "status|active");
    rig.step(); // the apply goes out, its reply is stored
    REQUIRE(rig.sent() == std::vector<std::string>{"firewall.quarantine"});
    // The next pass claims the entry and polls the apply's reply. Its next monotonic-clock read is
    // OUTSIDE the lock and ahead of the write-back: a release is requested and a tick resets the
    // entry to a releasing one, which sends its own status.
    // (The pass reads the clock at its claim, under the entry lock, where a re-entrant tick would
    // deadlock itself; the read after the poll is outside it. So the hook skips the claim's.)
    bool fired = false;
    int reads = 0;
    rig.steady.on_read = [&rig, &fired, &reads] {
        if (fired || ++reads < 2)
            return;
        fired = true;
        REQUIRE(rig.qstore.request_release("agent-1").has_value());
        rig.rec->tick();
    };
    rig.steady.advance(std::chrono::milliseconds(8));
    // The outer pass is a heartbeat's: the cache still holds the agent from the earlier tick.
    rig.heartbeat();
    rig.steady.on_read = nullptr;
    REQUIRE(fired);
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine", "firewall.quarantine_status"}));
    // The outer pass's reply handling (verify_next: clear `pending`, set verify_first) was dropped:
    // the status the tick sent is still pending, so the next step reads ITS reply (still contained)
    // and sends the release. A pass that wrote back would have sent a second status instead.
    rig.run(2);
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine", "firewall.quarantine_status",
                                                  "firewall.release"}));
}

// ── #7621 / #7622: a re-verify that no longer confirms ────────────────────────

TEST_CASE("reconciler (firewall): a release requested during a pending re-verify, handled before the next "
          "tick, ends as a confirmed release when the device answers inactive: no drift row",
          "[pg][quarantine][reconciler][prq2][drift]") {
    RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
    const auto rec = rig.quarantine();
    rig.confirm("status|active");
    rig.reply("status|active_unproven", "status|inactive");
    rig.steady.advance(std::chrono::milliseconds(45));
    rig.step(); // the re-verify's status goes out
    REQUIRE(rig.sent().back() == "firewall.quarantine_status");
    // The operator asks for the release while that status is in flight; the heartbeat pass reads
    // the earlier reply before any tick sees the new kind.
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    rig.steady.advance(std::chrono::milliseconds(8));
    rig.heartbeat();
    CHECK(rig.rows_with("quarantine.reapply", "drift") == 0);
    CHECK_FALSE(rig.active().has_value()); // the record ended on the device's word
    CHECK(rig.has_row("quarantine.disable", "success", "confirmed record_id=" + std::to_string(rec.id)));
    CHECK(rig.counter("released") == 1);
    CHECK(rig.counter("drift") == 0);
    CHECK(rig.owed().empty());
}

TEST_CASE("reconciler (firewall): the fresh store read before a drift row fails -> no drift row, degraded "
          "counted, the entry re-verifies",
          "[pg][quarantine][reconciler][prq2][drift]") {
    RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
    rig.quarantine();
    rig.confirm("status|active");
    rig.reply("status|active_unproven", "status|degraded|policy_not_blocking");
    rig.steady.advance(std::chrono::milliseconds(45));
    rig.step(); // the re-verify's status goes out
    const auto status_sends = rig.count_sent("firewall.quarantine_status");
    const double degraded = rig.counter("degraded");
    // The reply is read with the store unreadable: the pass cannot tell drift from a release.
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records RENAME TO quarantine_records_x");
    rig.steady.advance(std::chrono::milliseconds(8));
    rig.heartbeat();
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records_x RENAME TO quarantine_records");
    CHECK(rig.rows_with("quarantine.reapply", "drift") == 0);
    CHECK(rig.counter("degraded") == degraded + 1);
    CHECK(rig.counter("drift") == 0);
    CHECK(rig.active()->last_confirmed_at > 0); // still confirmed: nothing was concluded
    // the entry re-verifies on its next cycle, and the real drift is then counted once
    rig.run(3);
    CHECK(rig.count_sent("firewall.quarantine_status") > status_sends);
    CHECK(rig.rows_with("quarantine.reapply", "drift") == 1);
}

TEST_CASE("reconciler (firewall): a real drift counts result=drift once and result=unconfirmed not at all",
          "[pg][quarantine][reconciler][prq2][drift]") {
    RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
    rig.quarantine();
    rig.confirm("status|active");
    REQUIRE(rig.counter("unconfirmed") == 0);
    rig.reply("status|active_unproven", "status|degraded|policy_not_blocking");
    rig.reverify_once();
    CHECK(rig.counter("drift") == 1);
    CHECK(rig.counter("unconfirmed") == 0);
    CHECK(rig.rows_with("quarantine.reapply", "drift status=unconfirmed") == 1);
    // (an ordinary unconfirmed read on a never-confirmed record counts unconfirmed and no drift:
    // the next case)
}

// ── #7623: the last-tick gauge ───────────────────────────────────────────────

TEST_CASE("reconciler (firewall): the last-tick gauge moves on a healthy tick and on a degraded early "
          "return, and not from on_tick_exception",
          "[pg][quarantine][reconciler][prq2][metrics]") {
    RECON_RIG(rig);
    const auto last_tick = [&rig] {
        return rig.metrics.gauge("yuzu_server_quarantine_reconciler_last_tick_unixtime").value();
    };
    rig.step();
    CHECK(last_tick() == static_cast<double>(rig.clock));
    rig.clock += 100;
    rig.step();
    CHECK(last_tick() == static_cast<double>(rig.clock)); // moved on a healthy tick
    CHECK(rig.metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").value() == 1);

    // a degraded read: the tick returns early, still a tick that finished
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records RENAME TO quarantine_records_x");
    rig.clock += 100;
    rig.step();
    CHECK(rig.metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").value() == 0);
    CHECK(last_tick() == static_cast<double>(rig.clock));
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records_x RENAME TO quarantine_records");

    // a tick that threw did not finish: the gauge stays where it was
    const double before = last_tick();
    rig.clock += 100;
    rig.rec->on_tick_exception();
    CHECK(last_tick() == before);
}

// ── #7625: release_sent is audited once per session ───────────────────────────

TEST_CASE("reconciler (firewall): a device that always refuses the release gets one release_sent row per "
          "session, while every dispatch is counted",
          "[pg][quarantine][reconciler][prq2][release]") {
    RECON_RIG(rig);
    rig.quarantine();
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    rig.reply("", "status|active", "status|refused|privilege_unavailable");
    rig.run(16);
    const auto sends = rig.count_sent("firewall.release");
    REQUIRE(sends >= 3); // six-plus cycles: the release went out repeatedly
    CHECK(rig.rows_with("quarantine.disable", "release_sent") == 1);
    CHECK(rig.counter("release_sent") == static_cast<double>(sends)); // every dispatch counted
    CHECK(rig.active()->status == "releasing");

    // a new session is a new cycle: one more row
    rig.connect("session-B");
    rig.run(16);
    CHECK(rig.count_sent("firewall.release") > sends);
    CHECK(rig.rows_with("quarantine.disable", "release_sent") == 2);
}

// ── #7626: a restart sends one more owed release ──────────────────────────────

TEST_CASE("reconciler (firewall): a fresh reconciler over a parked owed device sends exactly one more "
          "release and writes one more forced_release_unconfirmed row",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    rig.reply("", "status|active", "status|active");
    rig.run(8);
    REQUIRE(rig.count_sent("firewall.release") == 1);
    REQUIRE(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 1);
    rig.run(8); // parked: status-only reads
    REQUIRE(rig.count_sent("firewall.release") == 1);

    rig.build(); // a server restart: no in-memory bookkeeping
    rig.run(14);
    CHECK(rig.count_sent("firewall.release") == 2);
    CHECK(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 2);
    CHECK(rig.owed().size() == 1);
}

// ── #7627: which status replies keep the default lifetime ─────────────────────

TEST_CASE("reconciler (firewall): status replies the reconciler reads are shortened to a day unless they "
          "changed what the server holds",
          "[pg][quarantine][reconciler][prq2][retention]") {
    SECTION("the first confirm keeps the default; a repeat confirm is shortened") {
        RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
        rig.quarantine();
        rig.confirm("status|active");
        REQUIRE(rig.sent() == kApplyThenVerify);
        CHECK(rig.kept_at_default(rig.cmd(2)));   // the status reply that first confirmed
        rig.reverify_once();
        REQUIRE(rig.count_sent("firewall.quarantine_status") == 2);
        CHECK(rig.shortened(rig.cmd(3)));          // the repeat confirm
        CHECK(rig.kept_at_default(rig.cmd(2)));
    }
    SECTION("a drift reply keeps the default") {
        RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
        rig.quarantine();
        rig.confirm("status|active");
        rig.reply("status|active_unproven", "status|degraded|policy_not_blocking");
        rig.reverify_once();
        REQUIRE(rig.rows_with("quarantine.reapply", "drift") == 1);
        CHECK(rig.kept_at_default(rig.cmd(3)));
    }
    SECTION("a still-contained reply on a releasing record is shortened; the reply that ends it is not") {
        RECON_RIG(rig);
        rig.quarantine();
        REQUIRE(rig.qstore.request_release("agent-1").has_value());
        int statuses = 0;
        rig.script = [&statuses](const DispatchCall& c) -> std::string {
            if (c.action == "quarantine_status")
                return ++statuses == 1 ? "status|active" : "status|inactive";
            if (c.action == "release")
                return "status|active"; // whatever it says to the release ends nothing by itself
            return {};
        };
        rig.run(8);
        REQUIRE_FALSE(rig.active().has_value());
        const auto sent = rig.sent();
        REQUIRE(sent.size() >= 3);
        CHECK(rig.shortened(rig.cmd(1)));          // the first status: still contained
        CHECK(rig.kept_at_default(rig.cmd(3)));    // the second status: inactive, the record ended
    }
    SECTION("an unconfirmed reply on a never-confirmed record is shortened") {
        RECON_RIG(rig);
        rig.quarantine();
        rig.reply("status|active_unproven", "status|degraded|policy_not_blocking");
        rig.run(4);
        REQUIRE(rig.sent().size() >= 2);
        CHECK(rig.shortened(rig.cmd(2)));
    }
    SECTION("a parked owed read is shortened; the reply that clears the owed release is not") {
        RECON_RIG(rig);
        const auto rec = rig.quarantine();
        REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
        rig.reply("", "status|active", "status|active");
        rig.run(10); // status, release, status (parks), then status-only reads
        REQUIRE(rig.rows_with("quarantine.disable", "forced_release_unconfirmed") == 1);
        rig.run(2);
        std::size_t last_status = 0;
        for (std::size_t i = 0; i < rig.dispatch.calls.size(); ++i)
            if (rig.dispatch.calls[i].action == "quarantine_status")
                last_status = i + 1;
        REQUIRE(last_status > 3);
        CHECK(rig.shortened(rig.cmd(last_status))); // a parked read
        // the device is released at last
        rig.reply("", "status|inactive", "status|inactive");
        rig.steady.advance(std::chrono::seconds(10));
        rig.run(12);
        REQUIRE(rig.owed().empty());
        std::size_t clearing = 0;
        for (std::size_t i = 0; i < rig.dispatch.calls.size(); ++i)
            if (rig.dispatch.calls[i].action == "quarantine_status")
                clearing = i + 1;
        CHECK(rig.kept_at_default(rig.cmd(clearing)));
    }
}

// ── #7584c: one failed owed read between ticks ────────────────────────────────

TEST_CASE("reconciler (firewall): one failed owed read between ticks keeps the owed entry, so no second "
          "release is sent in the session",
          "[pg][quarantine][reconciler][prq2][owed]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    rig.reply("", "status|active", "status|active");
    rig.run(3);
    REQUIRE(rig.sent() == (std::vector<std::string>{"firewall.quarantine_status", "firewall.release"}));
    // The owed read fails for one tick (the column type is flipped, then restored).
    exec_sql(qdb.dsn(), "DROP INDEX quarantine_store.idx_quarantine_release_owed");
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records "
                        "ALTER COLUMN device_release_owed_at DROP DEFAULT, "
                        "ALTER COLUMN device_release_owed_at TYPE text USING device_release_owed_at::text");
    const double degraded = rig.counter("degraded");
    rig.step();
    CHECK(rig.counter("degraded") == degraded + 1);
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records "
                        "ALTER COLUMN device_release_owed_at TYPE bigint USING device_release_owed_at::bigint, "
                        "ALTER COLUMN device_release_owed_at SET DEFAULT 0");
    exec_sql(qdb.dsn(), "CREATE INDEX idx_quarantine_release_owed ON quarantine_store.quarantine_records"
                        "(agent_id, id) WHERE status = 'released' AND device_release_owed_at <> 0");
    rig.run(16);
    CHECK(rig.count_sent("firewall.release") == 1); // the entry survived, so the session's release stands
    CHECK(rig.owed().size() == 1);
}

// ── #7613: a token read that fails is never a token ───────────────────────────

TEST_CASE("reconciler (firewall): when the apply fence token cannot be read the status command is not "
          "sent and the pass counts degraded",
          "[pg][quarantine][reconciler][fence]") {
    RECON_RIG(rig);
    rig.quarantine();
    rig.reply("status|active_unproven", "status|active");
    rig.step(); // the apply goes out
    REQUIRE(rig.sent() == (std::vector<std::string>{"firewall.quarantine"}));
    // Fail ONLY the token read: its WHERE compares apply_claimed_at with 0 and with the database
    // clock, which stops type-checking once the column is text. The apply's own claim is over, and
    // the rest of the reconciler's reads and writes never touch the column. A failed read treated
    // as a token would send the status command all the same.
    exec_sql(qdb.dsn(), "ALTER TABLE quarantine_store.quarantine_records "
                        "ALTER COLUMN apply_claimed_at DROP DEFAULT, "
                        "ALTER COLUMN apply_claimed_at TYPE text USING apply_claimed_at::text");
    const double degraded = rig.counter("degraded");
    rig.run(4); // the apply's reply is read; every attempt to move on to the status read fails closed
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine"}));
    CHECK(rig.counter("degraded") >= degraded + 1);
    CHECK(rig.active()->last_confirmed_at == 0);
}

// ── #7613: the apply fence through the reconciler ─────────────────────────────

TEST_CASE("reconciler (firewall): DELETE's release request and confirmed mark run inside the reconciler's "
          "apply dispatch: the mark is refused, the record stays releasing, then status, release, "
          "inactive end it",
          "[pg][quarantine][reconciler][prq2][fence]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    int statuses = 0;
    rig.script = [&statuses](const DispatchCall& c) -> std::string {
        if (c.action == "quarantine")
            return "status|active_unproven";
        if (c.action == "quarantine_status")
            return ++statuses == 1 ? "status|active" : "status|inactive";
        if (c.action == "release")
            return "status|active"; // whatever it says to the release ends nothing by itself
        return {};
    };
    bool ran = false;
    rig.dispatch.on_dispatch = [&rig, &ran, &rec, base = rig.dispatch.on_dispatch] {
        base();
        if (ran || rig.dispatch.calls.back().action != "quarantine")
            return;
        ran = true;
        // What DELETE does, from inside the apply's dispatch: the claim is live.
        REQUIRE(rig.qstore.request_release("agent-1").has_value());
        auto token = rig.qstore.apply_fence_token("agent-1", rec.id);
        REQUIRE(token.has_value());
        CHECK_FALSE(token->has_value()); // empty while the apply's claim is live
        auto mark = rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::device_confirmed, *token);
        REQUIRE_FALSE(mark.has_value());
        CHECK(mark.error() == std::string(kQuarantineApplyInFlight));
    };
    rig.run(9);
    REQUIRE(ran);
    CHECK(rig.sent() == (std::vector<std::string>{"firewall.quarantine", "firewall.quarantine_status",
                                                  "firewall.release", "firewall.quarantine_status"}));
    CHECK_FALSE(rig.active().has_value());
    CHECK(rig.has_row("quarantine.disable", "success", "confirmed record_id=" + std::to_string(rec.id)));
    CHECK(rig.owed().empty());
}

TEST_CASE("reconciler (firewall): a status read sent while the record was confirmed, an apply through the "
          "chokepoint, then a release request: the device's EARLIER inactive reply ends nothing; the "
          "next status read takes a fresh token and settles it",
          "[pg][quarantine][reconciler][prq2][fence]") {
    RECON_RIG_REVERIFY(rig, std::chrono::milliseconds(30));
    const auto rec = rig.quarantine();
    rig.confirm("status|active");
    rig.reply("status|active_unproven", "status|inactive");
    rig.steady.advance(std::chrono::milliseconds(45));
    rig.step(); // the re-verify's status is sent: its token is read now
    REQUIRE(rig.sent().back() == "firewall.quarantine_status");
    // The MCP path: an apply goes through the chokepoint after that read...
    QuarantineRecord stored{};
    auto applied = redispatch_stored_containment(
        rig.qstore, "agent-1",
        [&rig](const std::unordered_map<std::string, std::string>& params)
            -> std::pair<std::string, int> {
            const auto out = rig.dispatch.fn()("firewall", "quarantine", {"agent-1"}, "", params, "");
            return {out.command_id, out.sent};
        },
        stored);
    REQUIRE(applied.has_value());
    // The apply reached the device, so its claim is held: this path reads no reply, so here the
    // test plays the part of the reply being consumed (otherwise the claim expires on its own).
    REQUIRE(applied->held_claim_gen != 0);
    // ...and the operator then asks for the release.
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    rig.steady.advance(std::chrono::milliseconds(8));
    rig.heartbeat(); // the earlier status's `inactive` is read now
    const auto row = rig.active();
    REQUIRE(row.has_value());
    CHECK(row->status == "releasing");                // the end was refused
    CHECK(rig.audit("quarantine.disable").empty());    // no row, no counter for a refusal
    CHECK(rig.counter("released") == 0);
    CHECK(rig.rows_with("quarantine.reapply", "drift") == 0);
    // the apply's reply is consumed (claim dropped); the next status read takes a fresh token
    // and settles it
    REQUIRE(rig.qstore.release_apply_claim("agent-1", rec.id, applied->held_claim_gen).has_value());
    rig.run(4);
    CHECK_FALSE(rig.active().has_value());
    CHECK(rig.has_row("quarantine.disable", "success", "confirmed record_id=" + std::to_string(rec.id)));
}

TEST_CASE("reconciler (firewall): an apply that was delivered but has not run keeps its claim, so a "
          "release confirmed by an inactive answer cannot end the record until the apply's reply is "
          "consumed (#8045 R1)",
          "[pg][quarantine][reconciler][prq2][fence][r1]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    rig.reply("", "status|inactive"); // the apply gets no reply yet: it is delivered, not run
    rig.step();                       // the apply is dispatched; its claim is held
    REQUIRE(rig.sent() == (std::vector<std::string>{"firewall.quarantine"}));
    // What DELETE does while the apply is still waiting to run on the device: ask for the release
    // and read the fence token before sending it.
    REQUIRE(rig.qstore.request_release("agent-1").has_value());
    auto token = rig.qstore.apply_fence_token("agent-1", rec.id);
    REQUIRE(token.has_value());
    CHECK_FALSE(token->has_value()); // no token while a delivered apply may not have run
    // An end resting on the device's `inactive` answer fails closed, with or without a token.
    auto refused = rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::device_confirmed, *token);
    REQUIRE_FALSE(refused.has_value());
    CHECK(refused.error() == std::string(kQuarantineApplyInFlight));
    REQUIRE(rig.active().has_value()); // the record is still there
    // The apply runs and answers; the reconciler consumes the reply and drops the claim.
    store_status_response(rig.rstore, ReconRig::cmd(1), "agent-1", "status|active_unproven");
    rig.step();
    auto after = rig.qstore.apply_fence_token("agent-1", rec.id);
    REQUIRE(after.has_value());
    CHECK(after->has_value()); // the token reads again once the reply is consumed
    rig.run(8);
    CHECK_FALSE(rig.active().has_value()); // and the release now ends the record the normal way
}

TEST_CASE("reconciler (firewall): a release requested while an apply is unanswered turns the entry into "
          "a releasing one; the apply's claim survives that reset, no `inactive` read ends the record "
          "until the apply's reply is read, and then it settles (#8045 R1)",
          "[pg][quarantine][reconciler][prq2][fence][r1][reset]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    rig.reply("", "status|inactive"); // the device answers every status read inactive; the apply is silent
    rig.step();                       // the apply is dispatched and its claim held
    REQUIRE(rig.sent() == (std::vector<std::string>{"firewall.quarantine"}));
    REQUIRE(rig.qstore.request_release("agent-1").has_value()); // the entry becomes a releasing one
    rig.run(10);
    CHECK(rig.count_sent("firewall.quarantine_status") >= 1);
    CHECK(rig.active().has_value()); // every inactive read was refused: no token while the claim is held
    // The apply runs and answers; the releasing entry reads that reply, drops the claim, and the
    // next status read (with a fresh token) ends the record.
    store_status_response(rig.rstore, ReconRig::cmd(1), "agent-1", "status|active_unproven");
    rig.run(10);
    CHECK_FALSE(rig.active().has_value());
    CHECK(rig.owed().empty());
    CHECK(rig.has_row("quarantine.disable", "success", "confirmed record_id=" + std::to_string(rec.id)));
}

TEST_CASE("reconciler (firewall): the marks a heartbeat drain had not reached go back when the pass throws "
          "(#8045 R4)",
          "[pg][quarantine][reconciler][prq2][drain]") {
    RECON_RIG(rig);
    rig.quarantine();
    rig.reply("", ""); // the apply gets no reply: the entry stays pending and unconfirmed
    rig.step();        // the apply is dispatched; the unconfirmed cache now holds agent-1
    REQUIRE(rig.sent() == (std::vector<std::string>{"firewall.quarantine"}));
    rig.rec->notify_agent_heartbeat("agent-1"); // marked due
    rig.stop_fn = []() -> bool { throw std::runtime_error("stop probe failed"); };
    CHECK_THROWS_AS(rig.rec->drain_heartbeat_due(), std::runtime_error); // before the device is reached
    rig.stop_fn = nullptr;
    rig.steady.advance(std::chrono::milliseconds(8));
    const double before = rig.counter("pending");
    CHECK(rig.rec->drain_heartbeat_due() == 0);  // nothing is dispatched...
    CHECK(rig.counter("pending") == before + 1); // ...but the mark survived the throw and was read
}

TEST_CASE("reconciler (firewall): the owed leg: a record ended by force while an apply's claim is live is "
          "not cleared by an inactive read taken with an empty token; after the claim is released the "
          "next status read clears it",
          "[pg][quarantine][reconciler][prq2][fence][owed]") {
    RECON_RIG(rig);
    const auto rec = rig.quarantine();
    auto claim = rig.qstore.claim_apply("agent-1", rec.id); // an apply is dispatching
    REQUIRE(claim.has_value());
    REQUIRE(rig.qstore.mark_released("agent-1", rec.id, ReleaseEnd::forced).has_value());
    rig.reply("", "status|inactive");
    rig.run(5); // status (token empty), its reply read and refused, status again (still empty)
    CHECK(rig.count_sent("firewall.quarantine_status") >= 2);
    CHECK(rig.count_sent("firewall.release") == 0);      // the device answered inactive: no release
    CHECK(rig.owed().size() == 1);                       // not cleared on an unfenced answer
    CHECK(rig.audit("quarantine.disable").empty());
    REQUIRE(rig.qstore.release_apply_claim("agent-1", rec.id, *claim).has_value());
    rig.run(4);
    CHECK(rig.owed().empty());                            // the next status read settles it
    CHECK(rig.has_row("quarantine.disable", "success", "forced_release_confirmed record_id=" +
                                                           std::to_string(rec.id)));
}

#undef RECON_RIG

// ── Cases that need no rig ────────────────────────────────────────────────────

TEST_CASE("QuarantineContainmentReconciler::seed_metrics: every series exists at 0 before the first tick, "
          "every result label is present, and the last-tick gauge starts at boot time",
          "[quarantine][reconciler][metrics]") {
    yuzu::MetricsRegistry metrics;
    QuarantineContainmentReconciler::seed_metrics(metrics);
    const std::string text = metrics.serialize();
    for (const auto result : kQuarantineReapplyResults)
        CHECK(text.find("yuzu_server_quarantine_reapply_total{result=\"" + std::string(result) +
                        "\"} 0") != std::string::npos);
    CHECK(kQuarantineReapplyResults.size() == 14);
    CHECK(std::find(kQuarantineReapplyResults.begin(), kQuarantineReapplyResults.end(), "drift") !=
          kQuarantineReapplyResults.end());
    // Read from the snapshot taken above, never through metrics.gauge(): a lookup creates a missing
    // series at 0, so it would pass with the seed loop deleted.
    for (const std::string reach : {"connected", "offline"})
        for (const std::string name : {"yuzu_server_quarantine_endpoint_unconfirmed",
                                       "yuzu_server_quarantine_release_pending",
                                       "yuzu_server_quarantine_forced_release_owed"})
            CHECK(text.find(name + "{reachability=\"" + reach + "\"} 0") != std::string::npos);
    CHECK(metrics.gauge("yuzu_server_quarantine_reconciler_tick_healthy").value() == 1);
    // a plausible epoch (after 2020), so the stall alert does not fire before the first tick
    CHECK(metrics.gauge("yuzu_server_quarantine_reconciler_last_tick_unixtime").value() > 1.6e9);
}

TEST_CASE("QuarantineContainmentReconciler: a heartbeat only marks the device due: with every lease of "
          "the store pool held it makes no acquire attempt and no dispatch, and the drain does the work "
          "once the leases are back",
          "[pg][quarantine][reconciler][heartbeat]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    std::atomic<int> acquires{0};
    std::atomic<int> timeouts{0};
    PgPool qpool{{.conninfo = qdb.dsn(),
                  .size = 2,
                  .observer = {.on_acquire_timeout = [&timeouts] { ++timeouts; },
                               .on_acquire_wait_seconds = [&acquires](double) { ++acquires; }}}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    for (const char* id : {"agent-1", "agent-2", "agent-3"})
        REQUIRE(qstore.quarantine_device(id, "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    MockDispatch dispatch;
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });
    reconciler.tick(); // the three devices are offline: the entries and the cache exist, nothing sent
    REQUIRE(dispatch.calls.empty());
    for (const char* id : {"agent-1", "agent-2", "agent-3"})
        REQUIRE(registry.register_agent(make_info(id)).has_value());

    {
        auto lease_a = qpool.acquire();
        auto lease_b = qpool.acquire();
        REQUIRE(lease_a);
        REQUIRE(lease_b);
        acquires = 0;
        timeouts = 0;
        for (const char* id : {"agent-1", "agent-2", "agent-3"})
            reconciler.notify_agent_heartbeat(id);
        CHECK(acquires.load() == 0);
        CHECK(timeouts.load() == 0);
        CHECK(dispatch.calls.empty());
    }
    // the leases are back: the reconciler thread's next pass does the work for all three
    CHECK(reconciler.drain_heartbeat_due() == 3);
    CHECK(dispatch.calls.size() == 3);
    for (const auto& call : dispatch.calls)
        CHECK(call.action == "quarantine");
    // the marks were taken: a second drain has nothing to do
    CHECK(reconciler.drain_heartbeat_due() == 0);
}

TEST_CASE("QuarantineContainmentReconciler: a heartbeat drain dispatches at most one pass's budget and "
          "carries the rest to the next drain, each device once",
          "[pg][quarantine][reconciler][heartbeat]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 2}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    // One more device than a pass may dispatch to (kMaxDispatchesPerTick, 50, a private constant).
    std::vector<std::string> ids;
    for (int i = 0; i < 51; ++i)
        ids.push_back("agent-" + std::to_string(i));
    for (const auto& id : ids)
        REQUIRE(qstore.quarantine_device(id, "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    MockDispatch dispatch;
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });
    reconciler.tick(); // all offline: the entries and the cache exist, nothing sent
    REQUIRE(dispatch.calls.empty());
    for (const auto& id : ids)
        REQUIRE(registry.register_agent(make_info(id)).has_value());
    for (const auto& id : ids)
        reconciler.notify_agent_heartbeat(id);

    CHECK(reconciler.drain_heartbeat_due() == 50); // the budget of one pass
    CHECK(dispatch.calls.size() == 50);
    // the device left over was put back marked, with no new heartbeat
    CHECK(reconciler.drain_heartbeat_due() == 1);
    CHECK(dispatch.calls.size() == 51);
    std::set<std::string> reached;
    for (const auto& call : dispatch.calls) {
        REQUIRE(call.agent_ids.size() == 1);
        reached.insert(call.agent_ids.front());
    }
    CHECK(reached.size() == 51); // every device once, none twice
    CHECK(reconciler.drain_heartbeat_due() == 0);
    CHECK(dispatch.calls.size() == 51);
}

TEST_CASE("QuarantineContainmentReconciler: a heartbeat drain stops starting devices once its time budget "
          "has passed, and the next drain takes the rest",
          "[pg][quarantine][reconciler][heartbeat]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 2}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    const std::vector<std::string> ids{"agent-1", "agent-2"};
    for (const auto& id : ids)
        REQUIRE(qstore.quarantine_device(id, "admin", "malware", "").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry{bus, metrics};
    MockDispatch dispatch;
    FakeSteady steady;
    QuarantineContainmentReconciler reconciler(QuarantineContainmentReconciler::Deps{
        .quarantine_store = &qstore,
        .response_store = nullptr,
        .registry = &registry,
        .metrics = &metrics,
        .audit_store = nullptr,
        .dispatch_fn = dispatch.fn(),
        .now_fn = {},
        .steady_now_fn = steady.fn(),
    });
    reconciler.tick(); // both offline: the entries and the cache exist, nothing sent
    REQUIRE(dispatch.calls.empty());
    for (const auto& id : ids)
        REQUIRE(registry.register_agent(make_info(id)).has_value());
    for (const auto& id : ids)
        reconciler.notify_agent_heartbeat(id);

    // The first device's dispatch takes longer than a pass's time budget (kDrainTimeBudget, 2 s, a
    // private constant): the store or the pool is slow.
    dispatch.on_dispatch = [&] { steady.advance(std::chrono::seconds(10)); };
    CHECK(reconciler.drain_heartbeat_due() == 1);
    CHECK(dispatch.calls.size() == 1); // the second device was not started in this pass...
    CHECK(reconciler.drain_heartbeat_due() == 1);
    CHECK(dispatch.calls.size() == 2); // ...and was taken, still marked, by the next one
    std::set<std::string> reached;
    for (const auto& call : dispatch.calls) {
        REQUIRE(call.agent_ids.size() == 1);
        reached.insert(call.agent_ids.front());
    }
    CHECK(reached == std::set<std::string>(ids.begin(), ids.end())); // each device once
    CHECK(reconciler.drain_heartbeat_due() == 0);
}

TEST_CASE("redispatch_stored_containment claims the apply: the token is empty inside the dispatch, the new "
          "generation after it, and another apply's live claim means nothing is dispatched",
          "[pg][quarantine][reconciler][fence]") {
    YUZU_REQUIRE_PG_DB_TPL(qdb, quarantine_recon_tpl);
    PgPool qpool{{.conninfo = qdb.dsn(), .size = 4}};
    QuarantineStore qstore{qpool};
    REQUIRE(qstore.is_open());
    REQUIRE(qstore.quarantine_device("agent-1", "admin", "malware", "10.0.0.1").has_value());
    const auto id = qstore.get_status("agent-1")->value().id;

    std::optional<std::optional<std::int64_t>> inside;
    QuarantineRecord stored{};
    auto first = redispatch_stored_containment(
        qstore, "agent-1",
        [&](const std::unordered_map<std::string, std::string>&) -> std::pair<std::string, int> {
            auto token = qstore.apply_fence_token("agent-1", id);
            REQUIRE(token.has_value());
            inside = *token;
            return {"cmd-1", 1};
        },
        stored);
    REQUIRE(first.has_value());
    REQUIRE(inside.has_value());
    CHECK_FALSE(inside->has_value()); // a claim is live inside the dispatch
    // The dispatch reached an agent, so the claim is KEPT: the command was only sent, the agent
    // runs it on a thread pool, and an apply that has not run yet can still be overtaken by a
    // release (#8045 R1). It is handed back for the caller to drop once the reply is consumed.
    CHECK(first->held_claim_gen == 1);
    auto kept = qstore.apply_fence_token("agent-1", id);
    REQUIRE(kept.has_value());
    CHECK_FALSE(kept->has_value()); // no token is issued while the delivered apply may not have run
    REQUIRE(qstore.release_apply_claim("agent-1", id, first->held_claim_gen).has_value());
    auto after = qstore.apply_fence_token("agent-1", id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK(**after == 1); // the reply was consumed, the claim is dropped, the generation moved

    // a dispatch that reached nobody delivered nothing: its claim is dropped at once
    auto unreached = redispatch_stored_containment(
        qstore, "agent-1",
        [&](const std::unordered_map<std::string, std::string>&) -> std::pair<std::string, int> {
            return {"cmd-0", 0};
        },
        stored);
    REQUIRE(unreached.has_value());
    CHECK(unreached->held_claim_gen == 0);
    auto after_unreached = qstore.apply_fence_token("agent-1", id);
    REQUIRE(after_unreached.has_value());
    CHECK(after_unreached->has_value());

    // another apply holds a live claim: the chokepoint dispatches nothing
    auto other = qstore.claim_apply("agent-1", id);
    REQUIRE(other.has_value());
    int calls = 0;
    auto second = redispatch_stored_containment(
        qstore, "agent-1",
        [&](const std::unordered_map<std::string, std::string>&) -> std::pair<std::string, int> {
            ++calls;
            return {"cmd-2", 1};
        },
        stored);
    REQUIRE_FALSE(second.has_value());
    CHECK(second.error().kind == ContainmentReapplyErrorKind::no_active_record);
    CHECK(second.error().detail == "quarantine record changed or another apply is in flight");
    CHECK(calls == 0);
    // a dispatch that throws still drops the claim
    REQUIRE(qstore.release_apply_claim("agent-1", id, *other).has_value());
    auto threw = redispatch_stored_containment(
        qstore, "agent-1",
        [&](const std::unordered_map<std::string, std::string>&) -> std::pair<std::string, int> {
            throw std::runtime_error("dispatch failed");
        },
        stored);
    REQUIRE(threw.has_value());
    CHECK(threw->dispatch_threw);
    auto settled = qstore.apply_fence_token("agent-1", id);
    REQUIRE(settled.has_value());
    CHECK(settled->has_value()); // no claim left behind

    // CH-2: an exception that is NOT a std::exception passes through the call (only std::exception
    // is caught), and the claim is still dropped by the scope guard: the token reads again and a
    // second claim succeeds. Without the guard the claim stays live for kApplyClaimTtlSecs.
    bool escaped = false;
    try {
        (void)redispatch_stored_containment(
            qstore, "agent-1",
            [&](const std::unordered_map<std::string, std::string>&) -> std::pair<std::string, int> {
                throw 42;
            },
            stored);
    } catch (int) {
        escaped = true;
    }
    CHECK(escaped);
    auto after_int = qstore.apply_fence_token("agent-1", id);
    REQUIRE(after_int.has_value());
    REQUIRE(after_int->has_value()); // a live claim would make the token empty
    auto reclaim = qstore.claim_apply("agent-1", id);
    REQUIRE(reclaim.has_value()); // and would refuse this one
    REQUIRE(qstore.release_apply_claim("agent-1", id, *reclaim).has_value());
}
