/**
 * test_agent_service_impl.cpp — coverage for AgentServiceImpl response-path
 * helpers. Closes the gap explicitly deferred at
 * test_workflow_routes.cpp:820 ("no AgentServiceImpl in ExecHarness")
 * by constructing a real AgentServiceImpl and driving response receipt
 * end-to-end into a real ResponseStore.
 *
 * Pins three contracts called out in #117 (response-streaming coverage):
 *
 *   1. record_execution_id() registers the command_id → execution_id
 *      mapping consumed at response receipt; passing an empty
 *      execution_id removes the entry (the documented "clear" semantics
 *      from agent_service_impl.cpp:586).
 *
 *   2. process_gateway_response() stamps execution_id onto every
 *      StoredResponse (RUNNING and terminal branches both), so the
 *      executions detail drawer's `query_by_execution` path sees the
 *      stream. A response with no recorded mapping degrades cleanly —
 *      execution_id stays empty rather than crashing or fabricating.
 *
 *   3. The HF-1 multi-agent fan-out invariant: the terminal branch
 *      MUST NOT erase the mapping after the first agent's terminal
 *      response, otherwise agents 2..N stamp empty execution_id and
 *      the drawer drops them. This was a real PR-2 hardening regression
 *      (see agent_service_impl.cpp:672-674); the response-store-level
 *      pin at test_workflow_routes.cpp:814 only proves the store
 *      handles two stamped rows — this test proves the upstream path
 *      actually emits two stamped rows from a single mapping.
 */

#include "agent_service_impl.hpp"

#include <catch2/catch_test_macros.hpp>

#include "agent_registry.hpp"
#include "app_usage_store.hpp"
#include "audit_store.hpp"
#include "event_bus.hpp"
#include "execution_tracker.hpp"
#include "gateway_mgmt_stub_pool.hpp" // #4672: build_gateway_forward_terminal_failure
#include "gateway_service_impl.hpp"
#include "inventory_store.hpp"
#include "notification_store.hpp"
#include "offload_target_store.hpp"
#include "peer_ip.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"
#include "test_offload_target_store_pg_helper.hpp"
#include "test_webhook_store_pg_helper.hpp"
#include "typed_inventory_sources.hpp"
#include "webhook_store.hpp"
#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include "../test_helpers.hpp"

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using yuzu::server::AuditStore;
using yuzu::server::NotificationStore;
using yuzu::server::OffloadAuthType;
using yuzu::server::OffloadTargetStore;
using yuzu::server::ResponseStore;
using yuzu::server::StoredResponse;
using yuzu::server::WebhookStore;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::AgentServiceImpl;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgPool;
namespace pg = yuzu::server::pg;

namespace {

// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

namespace apb = ::yuzu::agent::v1;

// AuditStore migrated to Postgres (ADR-0006) — GatewayResponseHarness below
// clones this pre-migrated template instead of opening a SQLite path.
yuzu::test::PgTestTemplate agent_svc_audit_tpl{"agentaudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("agentaudit template: store failed to migrate");
}};

/// Minimal harness: real AgentServiceImpl wired against in-memory
/// ResponseStore. analytics/notification/webhook stores stay null so
/// the side-effect branches in process_gateway_response short-circuit
/// on their `if (store_)` guards — keeps the test focused on the
/// execution_id stamping invariant.
///
/// MEMBER ORDER LOAD-BEARING: members below are declared in topological
/// order so that every reference captured by `svc` (and by `registry`)
/// points at an already-constructed member, AND so that `responses`
/// destructs AFTER `svc` (it is declared earlier than `svc`, so it
/// destructs later than `svc`). `svc` holds `response_store_` as a raw
/// `ResponseStore*` (set in the body); reordering would create a
/// dangling-pointer hazard at `~svc`. Do not alphabetise.
struct GatewayResponseHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    ResponseStore responses;
    // AuditStore ported to Postgres (ADR-0006): a template-cloned ephemeral
    // database + pool. This harness's ResponseStore is now also PG-backed
    // (ADR-0039), so both share the caller-supplied pool below.
    std::optional<yuzu::test::PostgresTestDb> audit_db;
    std::optional<yuzu::server::pg::PgPool> audit_pool;
    std::unique_ptr<AuditStore> audit;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};

    explicit GatewayResponseHarness(pg::PgPool& pool) : responses(pool) {
        REQUIRE(responses.is_open());

        if (yuzu::test::pg_admin_dsn_env() == nullptr) {
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
        }
        audit_db.emplace(agent_svc_audit_tpl);
        INFO("[GatewayResponseHarness] audit db status (blank == ok): " << audit_db->error());
        REQUIRE(audit_db->available());
        audit_pool.emplace(yuzu::server::pg::PgPool::Options{.conninfo = audit_db->dsn(), .size = 4});
        audit = std::make_unique<AuditStore>(*audit_pool);
        REQUIRE(audit->is_open());
        svc.set_response_store(&responses);
        svc.set_audit_store(audit.get());
    }

    static apb::CommandResponse make_response(const std::string& command_id,
                                              apb::CommandResponse::Status status,
                                              const std::string& output = "", int exit_code = 0) {
        apb::CommandResponse r;
        r.set_command_id(command_id);
        r.set_status(status);
        r.set_output(output);
        r.set_exit_code(exit_code);
        return r;
    }
};

} // namespace

// ── #872 — notify_exec_tracker wiring through to ExecutionTracker ──────────
//
// Bare GatewayResponseHarness leaves execution_tracker_ at nullptr, so the
// entire notify_exec_tracker body (5-status enum mapping, empty-execution_id
// early-return, null-tracker early-return) was dead in test. TrackerScope
// constructs a real in-memory ExecutionTracker and wires it via
// set_execution_tracker; destruction order is managed so the borrowed pointer
// in svc is nulled before the tracker destructs (mirrors the production
// shutdown contract documented at agent_service_impl.hpp:113).

namespace {

/// MEMBER ORDER LOAD-BEARING: `tracker` is owned outright (against the
/// caller-supplied pool), `svc` borrows `tracker.get()` (via
/// `set_execution_tracker`). The dtor MUST run set_execution_tracker(nullptr)
/// → tracker.reset(), in that exact order, so the borrowed-pointer chain is
/// unwound from the outside in. Reordering the member declarations or
/// replacing the user-defined dtor with `= default` would silently break the
/// contract — there is no compile-time guard. Mirrors the production
/// ServerImpl "drain gRPC → null setter → reset" shutdown sequence at
/// agent_service_impl.hpp:113.
struct TrackerScope {
    std::unique_ptr<yuzu::server::ExecutionTracker> tracker;
    AgentServiceImpl* svc{nullptr};

    TrackerScope(AgentServiceImpl& s, yuzu::server::pg::PgPool& pool) : svc(&s) {
        tracker = std::make_unique<yuzu::server::ExecutionTracker>(pool);
        REQUIRE(tracker->is_open());
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
    /// the `GatewayResponseHarness::make_response` static-factory pattern —
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

} // namespace

// ── record_execution_id ────────────────────────────────────────────────────

TEST_CASE("record_execution_id: terminal response stamps mapped execution_id",
          "[pg][agent_service][executions][pr2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    // HA WS-1(1b): record_execution_id now routes through ExecutionTracker
    // (PG-backed), so this test needs one wired — mirrors the #872 tests.
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-A", "exec-42");

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS,
                                                      /*output=*/"", /*exit_code=*/0);
    h.svc.process_gateway_response("agent-1", resp);

    auto rows_opt = h.responses.query_by_execution("exec-42");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].execution_id == "exec-42");
    CHECK(rows[0].agent_id == "agent-1");
    CHECK(rows[0].instruction_id == "cmd-A");
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
}

TEST_CASE("record_execution_id: empty execution_id removes the mapping",
          "[pg][agent_service][executions][pr2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-A", "exec-42");
    h.svc.record_execution_id("cmd-A", ""); // documented clear semantics

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    auto by_exec = h.responses.query_by_execution("exec-42");
    REQUIRE(by_exec.has_value());
    CHECK(by_exec->empty()); // mapping cleared → row not tagged
    auto by_cmd_opt = h.responses.get_by_instruction("cmd-A");
    REQUIRE(by_cmd_opt.has_value());
    const auto& by_cmd = *by_cmd_opt;
    REQUIRE(by_cmd.size() == 1);
    CHECK(by_cmd[0].execution_id.empty());
}

// ── process_gateway_response: per-status branches ──────────────────────────

TEST_CASE("process_gateway_response: RUNNING streaming row carries execution_id",
          "[pg][agent_service][executions][pr2]") {
    // The RUNNING branch lives at agent_service_impl.cpp:597-655 — it both
    // stores a streaming row and stamps execution_id from the same
    // ExecutionTracker-backed correlation lookup (HA WS-1(1b)). Pin both
    // halves: the row exists AND it carries the tag.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-stream", "exec-stream");

    auto running =
        GatewayResponseHarness::make_response("cmd-stream", apb::CommandResponse::RUNNING,
                                              /*output=*/"row-1");
    h.svc.process_gateway_response("agent-1", running);

    auto rows_opt = h.responses.query_by_execution("exec-stream");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::RUNNING));
    CHECK(rows[0].output == "row-1");
}

TEST_CASE("process_gateway_response: FAILURE preserves error_detail and execution_id",
          "[pg][agent_service][executions][pr2]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-fail", "exec-fail");

    auto resp = GatewayResponseHarness::make_response("cmd-fail", apb::CommandResponse::FAILURE,
                                                      /*output=*/"",
                                                      /*exit_code=*/2);
    resp.mutable_error()->set_message("plugin returned non-zero");
    h.svc.process_gateway_response("agent-1", resp);

    auto rows_opt = h.responses.query_by_execution("exec-fail");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].error_detail == "plugin returned non-zero");
    CHECK(rows[0].execution_id == "exec-fail");
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::FAILURE));
}

// ── #4672 — gateway-forward terminal-failure synthesis resolves the
//    command_id exactly like a real gateway response would ────────────────
//
// forward_gateway_pending's four terminal-failure branches (unauthenticated,
// exhausted unavailable, unknown_cluster, a stream with no legitimate
// resolution for the targeted agent) build a synthetic FAILURE CommandResponse
// (build_gateway_forward_terminal_failure, gateway_mgmt_stub_pool.hpp) and
// apply it through THIS SAME process_gateway_response path — never a bespoke
// second mechanism. These tests drive that exact call shape end-to-end so a
// regression that stops calling process_gateway_response on one of those
// branches (or that starts double-resolving) is caught here rather than only
// by reading forward_gateway_pending's un-unit-testable body.

TEST_CASE("process_gateway_response: a #4672 synthetic gateway-forward terminal failure "
          "resolves the command's execution row exactly like a real FAILURE response",
          "[pg][agent_service][executions][4672]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-gwfwd", "exec-gwfwd");

    auto synth = yuzu::server::build_gateway_forward_terminal_failure(
        "cmd-gwfwd", "gateway_unauthenticated",
        "Gateway REJECTED by the gateway's mgmt-plane peer pin (UNAUTHENTICATED) — command "
        "not delivered");
    h.svc.process_gateway_response("agent-1", synth);

    auto rows_opt = h.responses.query_by_execution("exec-gwfwd");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::FAILURE));
    // pr-rev finding (FortitudeEtc/Codex+Kimi, SHOULD, 2026-09-22): the
    // reason code is now prefixed onto the persisted message (see
    // build_gateway_forward_terminal_failure's updated doc comment).
    CHECK(rows[0].error_detail ==
         "[gateway_unauthenticated] Gateway REJECTED by the gateway's mgmt-plane peer pin "
         "(UNAUTHENTICATED) — command not delivered");
    CHECK(rows[0].execution_id == "exec-gwfwd");
    CHECK(rows[0].agent_id == "agent-1");
    CHECK(rows[0].instruction_id == "cmd-gwfwd");
}

TEST_CASE("process_gateway_response: a command left RUNNING then hit by a #4672 synthetic "
          "terminal failure ends up FAILURE, never stuck RUNNING (the bug #4672 closes)",
          "[pg][agent_service][executions][4672]") {
    // Before #4672, forward_gateway_pending's terminal-failure branches
    // logged + counted + dropped: a command that streamed a RUNNING frame
    // and then hit e.g. exhausted UNAVAILABLE retries never got a matching
    // terminal write, so its execution/response row idled at RUNNING
    // forever (only the executions-ladder materialise timeout, a much later
    // and coarser signal, would eventually notice). This pins the fix: the
    // SAME command_id, first a real RUNNING frame, then the synthesized
    // terminal failure — the row must resolve to FAILURE, not stay RUNNING
    // and not produce a second, orphaned row.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-stuck", "exec-stuck");

    auto running = GatewayResponseHarness::make_response(
        "cmd-stuck", apb::CommandResponse::RUNNING, /*output=*/"still going");
    h.svc.process_gateway_response("agent-1", running);

    auto synth = yuzu::server::build_gateway_forward_terminal_failure(
        "cmd-stuck", "gateway_unavailable",
        "Gateway unreachable after 3 attempts — command not delivered");
    h.svc.process_gateway_response("agent-1", synth);

    auto rows_opt = h.responses.query_by_execution("exec-stuck");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 1); // updated in place, not a second orphaned row
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::FAILURE));
    CHECK(rows[0].error_detail ==
         "[gateway_unavailable] Gateway unreachable after 3 attempts — command not delivered");
}

TEST_CASE("process_gateway_response: each of the five #4672 reason codes produces a distinct, "
          "resolved FAILURE row",
          "[pg][agent_service][executions][4672]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};

    struct Case {
        const char* command_id;
        const char* reason;
    };
    // Gate 4 consistency-auditor SHOULD (2026-09-21): this list previously
    // omitted "gateway_forward_failed" (the generic non-UNAVAILABLE
    // grpc-status branch, the 5th of forward_gateway_pending's 5 terminal-
    // failure call sites) — a typo/rename there would have gone uncaught.
    const Case cases[] = {
        {"cmd-unauth", "gateway_unauthenticated"},
        {"cmd-unavail", "gateway_unavailable"},
        {"cmd-unknown-cluster", "gateway_unknown_cluster"},
        {"cmd-mismatch", "gateway_agent_mismatch"},
        {"cmd-forward-failed", "gateway_forward_failed"},
    };
    for (const auto& c : cases) {
        INFO("reason=" << c.reason);
        auto synth =
            yuzu::server::build_gateway_forward_terminal_failure(c.command_id, c.reason, c.reason);
        h.svc.process_gateway_response("agent-1", synth);

        auto by_cmd_opt = h.responses.get_by_instruction(c.command_id);
        REQUIRE(by_cmd_opt.has_value());
        const auto& by_cmd = *by_cmd_opt;
        REQUIRE(by_cmd.size() == 1);
        CHECK(by_cmd[0].status == static_cast<int>(apb::CommandResponse::FAILURE));
        CHECK(by_cmd[0].error_detail == std::string("[") + c.reason + "] " + c.reason);
    }
}

TEST_CASE("process_gateway_response: unmapped command_id stamps empty execution_id",
          "[pg][agent_service][executions][pr2]") {
    // Out-of-band dispatch (CLI / direct gRPC) bypasses the dispatch path
    // that calls record_execution_id. The receipt path must degrade to an
    // empty execution_id rather than crashing or inventing a value.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    // Tracker wired (open, no mapping recorded) so this exercises the real
    // "no row for this command_id" degrade, not a coincidental null-tracker
    // early-return that would pass for the wrong reason.
    TrackerScope ts{h.svc, pool};
    auto resp = GatewayResponseHarness::make_response("cmd-orphan", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    auto by_cmd_opt = h.responses.get_by_instruction("cmd-orphan");
    REQUIRE(by_cmd_opt.has_value());
    const auto& by_cmd = *by_cmd_opt;
    REQUIRE(by_cmd.size() == 1);
    CHECK(by_cmd[0].execution_id.empty());
}

// ── HF-1 multi-agent fan-out invariant ─────────────────────────────────────

TEST_CASE("process_gateway_response: terminal branch does NOT erase mapping "
          "(HF-1 multi-agent fan-out invariant)",
          "[pg][agent_service][executions][pr2][hardening]") {
    // PR-2 ladder regression. Pre-fix, the terminal branch erased the
    // command_id -> execution_id mapping (then an in-process
    // cmd_execution_ids_ map, now HA WS-1(1b)'s PG-backed
    // command_execution table) on the FIRST agent's response, so agents
    // 2..N stamped empty execution_id and the executions drawer dropped
    // them. The fix keeps the mapping live until it ages out via
    // ExecutionTracker::reap_command_execution_mappings. This test drives
    // the path the test_workflow_routes pin couldn't reach (it operated on
    // ResponseStore directly).
    //
    // Fan out across 4 agents and mix terminal statuses (SUCCESS / FAILURE /
    // TIMEOUT) to pin two distinct invariants simultaneously: (a) the
    // mapping survives every terminal-status code path (`else` branch at
    // agent_service_impl.cpp:656 covers all non-RUNNING statuses uniformly,
    // a future split that re-introduces an erase on FAILURE-only or
    // TIMEOUT-only would slip past a SUCCESS-only test); and (b) tail
    // agents (#4) past the smallest fan-out width still stamp correctly,
    // closing the off-by-one window where a regression could erase after
    // exactly N=3 calls.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-fan", "exec-fan");

    struct AgentTerminal {
        const char* agent;
        apb::CommandResponse::Status status;
    };
    const AgentTerminal terminals[] = {
        {"agent-1", apb::CommandResponse::SUCCESS},
        {"agent-2", apb::CommandResponse::FAILURE},
        {"agent-3", apb::CommandResponse::TIMEOUT},
        {"agent-4", apb::CommandResponse::SUCCESS},
    };
    for (const auto& t : terminals) {
        auto r = GatewayResponseHarness::make_response("cmd-fan", t.status);
        h.svc.process_gateway_response(t.agent, r);
    }

    auto rows_opt = h.responses.query_by_execution("exec-fan");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 4);
    for (const auto& row : rows) {
        CHECK(row.execution_id == "exec-fan");
        CHECK(row.error_detail.empty()); // SUCCESS path must not invent error_detail
    }
}

TEST_CASE("process_gateway_response: __timing__ sentinel takes the early-return "
          "branch and does NOT store",
          "[pg][agent_service][executions][pr2]") {
    // The RUNNING branch at agent_service_impl.cpp:599-606 short-circuits
    // for output starting with "__timing__|" — these are out-of-band
    // dashboard-stat payloads, not command output. They must NOT appear
    // in ResponseStore (no execution_id stamp, no instruction row).
    // Without this pin, a refactor that hoists the store block above the
    // sentinel guard would silently start persisting timing rows under the
    // execution_id, which the drawer would then surface as bogus output.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-time", "exec-time");

    auto timing = GatewayResponseHarness::make_response("cmd-time", apb::CommandResponse::RUNNING,
                                                        /*output=*/"__timing__|elapsed=42");
    h.svc.process_gateway_response("agent-1", timing);

    auto time_by_exec = h.responses.query_by_execution("exec-time");
    REQUIRE(time_by_exec.has_value());
    CHECK(time_by_exec->empty());
    auto time_by_cmd = h.responses.get_by_instruction("cmd-time");
    REQUIRE(time_by_cmd.has_value());
    CHECK(time_by_cmd->empty());
}

TEST_CASE("process_gateway_response: terminal SUCCESS folds into existing RUNNING rows",
          "[pg][agent_service][executions][pr2]") {
    // Post-UAT 2026-05-06: an empty-output terminal frame is folded into
    // the existing RUNNING rows in place via
    // ResponseStore::finalize_terminal_status, instead of inserting a
    // separate sentinel row that operators misread as a failed run that
    // happened "before" the data row. Two streaming RUNNING rows + a
    // terminal SUCCESS = 2 rows, both updated to SUCCESS, both still
    // tagged with the same execution_id.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-mix", "exec-mix");

    auto r1 = GatewayResponseHarness::make_response("cmd-mix", apb::CommandResponse::RUNNING,
                                                    /*output=*/"line-1");
    h.svc.process_gateway_response("agent-1", r1);
    auto r2 = GatewayResponseHarness::make_response("cmd-mix", apb::CommandResponse::RUNNING,
                                                    /*output=*/"line-2");
    h.svc.process_gateway_response("agent-1", r2);
    auto r3 = GatewayResponseHarness::make_response("cmd-mix", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", r3);

    auto rows_opt = h.responses.query_by_execution("exec-mix");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 2);
    for (const auto& row : rows) {
        CHECK(row.status == static_cast<int>(apb::CommandResponse::SUCCESS));
        CHECK(row.execution_id == "exec-mix");
    }
}

TEST_CASE("process_gateway_response: terminal frame WITH output still inserts",
          "[pg][agent_service][executions][pr2]") {
    // Edge case: a plugin whose terminal frame carries the result data
    // (rather than streaming via RUNNING + sentinel terminal) should
    // still produce a row, since finalize_terminal_status only fires
    // when the terminal output is empty.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-direct", "exec-direct");
    auto only = GatewayResponseHarness::make_response("cmd-direct", apb::CommandResponse::SUCCESS,
                                                      /*output=*/"final-data");
    h.svc.process_gateway_response("agent-1", only);

    auto rows_opt = h.responses.query_by_execution("exec-direct");
    REQUIRE(rows_opt.has_value());
    const auto& rows = *rows_opt;
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
    CHECK(rows[0].output == "final-data");
}

TEST_CASE("process_gateway_response: re-mapping a command_id updates the stamp",
          "[pg][agent_service][executions][pr2]") {
    // Defensive contract: if the dispatch path overwrites a command_id's
    // mapping (e.g. retry under a new execution row), responses arriving
    // after the overwrite stamp the new execution_id. Old execution_id
    // sees only pre-overwrite responses.
    //
    // Post-UAT 2026-05-06: the terminal-frame finalize path is scoped by
    // execution_id, so a terminal SUCCESS arriving after the re-mapping
    // does NOT fold back onto the old execution's row. With no RUNNING
    // row under exec-new, finalize matches zero rows and falls through
    // to insert (preserving the re-mapping invariant).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    h.svc.record_execution_id("cmd-re", "exec-old");
    auto first = GatewayResponseHarness::make_response("cmd-re", apb::CommandResponse::RUNNING,
                                                       /*output=*/"old");
    h.svc.process_gateway_response("agent-1", first);

    h.svc.record_execution_id("cmd-re", "exec-new");
    auto second = GatewayResponseHarness::make_response("cmd-re", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", second);

    auto old_rows_opt = h.responses.query_by_execution("exec-old");
    REQUIRE(old_rows_opt.has_value());
    const auto& old_rows = *old_rows_opt;
    REQUIRE(old_rows.size() == 1);
    CHECK(old_rows[0].status == static_cast<int>(apb::CommandResponse::RUNNING));

    auto new_rows_opt = h.responses.query_by_execution("exec-new");
    REQUIRE(new_rows_opt.has_value());
    const auto& new_rows = *new_rows_opt;
    REQUIRE(new_rows.size() == 1);
    CHECK(new_rows[0].status == static_cast<int>(apb::CommandResponse::SUCCESS));
}

// ── #826 — Subscribe peer-mismatch IP extraction ───────────────────────────

TEST_CASE("AgentServiceImpl::extract_peer_ip handles ipv4/ipv6/unix peer encodings",
          "[agent_service][peer_mismatch][issue826]") {
    // gRPC peer encoding is documented at
    // src/core/lib/iomgr/parse_address.cc; the parser must round-trip
    // every shape it produces so the Subscribe peer-mismatch check can
    // operate on IPs (ports differ per-RPC, IPs do not).
    using yuzu::server::detail::AgentServiceImpl;

    CHECK(AgentServiceImpl::extract_peer_ip("ipv4:1.2.3.4:5678") == "1.2.3.4");
    CHECK(AgentServiceImpl::extract_peer_ip("ipv4:127.0.0.1:50051") == "127.0.0.1");
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:[::1]:50051") == "::1");
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:[2001:db8::1]:443") == "2001:db8::1");
    // unix-domain sockets have no IP to extract → empty. Caller MUST
    // treat empty as a mismatch (never as a wild match) to avoid #826.
    CHECK(AgentServiceImpl::extract_peer_ip("unix:/tmp/sock").empty());
    CHECK(AgentServiceImpl::extract_peer_ip("").empty());
    // Malformed/unknown scheme → empty
    CHECK(AgentServiceImpl::extract_peer_ip("garbage").empty());
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:no-brackets:8080").empty());
    CHECK(AgentServiceImpl::extract_peer_ip("ipv6:[unclosed").empty());
}

TEST_CASE("extract_peer_ip strict-mode rejects malformed addresses (#1058)",
          "[agent_service][peer_mismatch][issue1058]") {
    using yuzu::server::detail::extract_peer_ip;
    // ipv4 bodies that are not a valid dotted-quad → empty. The previous lax
    // parser returned a half-parsed substring that could slip past the #826
    // binding comparison.
    CHECK(extract_peer_ip("ipv4:not.an.ip:80").empty());
    CHECK(extract_peer_ip("ipv4:1.2.3:80").empty());     // 3 octets
    CHECK(extract_peer_ip("ipv4:1.2.3.4.5:80").empty()); // 5 octets
    CHECK(extract_peer_ip("ipv4:999.1.1.1:80").empty()); // octet > 255
    CHECK(extract_peer_ip("ipv4:1.2.3.4.:80").empty());  // trailing dot
    CHECK(extract_peer_ip("ipv4::80").empty());          // empty address
    CHECK(extract_peer_ip("ipv4:01.02.03.04:80").empty()); // leading-zero octets (non-canonical)
    CHECK(extract_peer_ip("ipv4:1.2.3.04:80").empty());    // single leading-zero octet
    CHECK(extract_peer_ip("ipv4:0.0.0.0:80") == "0.0.0.0"); // bare-zero octets are canonical
    // ipv6 bodies with non-hex junk in the address → empty
    CHECK(extract_peer_ip("ipv6:[xyz]:80").empty());
    CHECK(extract_peer_ip("ipv6:[g::1]:80").empty()); // 'g' not hex
    CHECK(extract_peer_ip("ipv6:[]:80").empty());     // empty address
    CHECK(extract_peer_ip("ipv6:[1234]:80").empty()); // no colon → not v6
    // valid shapes still pass, including a v6 zone id (interface name is
    // non-hex but legitimate after '%').
    CHECK(extract_peer_ip("ipv4:10.0.0.1:443") == "10.0.0.1");
    CHECK(extract_peer_ip("ipv6:[fe80::1%eth0]:443") == "fe80::1%eth0");
}

TEST_CASE("extract_peer_ip canonicalizes IPv6 to lowercase (#1058)",
          "[agent_service][peer_mismatch][issue1058]") {
    using yuzu::server::detail::extract_peer_ip;
    // Register-side vs subscribe-side comparison must not depend on hex
    // casing — both sides route through this function so lowercasing is
    // symmetric. (gRPC emits canonical lowercase today; this defends the
    // comparison if that ever changes.)
    CHECK(extract_peer_ip("ipv6:[2001:DB8::1]:443") == "2001:db8::1");
    CHECK(extract_peer_ip("ipv6:[FE80::AbCd]:443") == "fe80::abcd");
    // IPv4-mapped IPv6 (dual-stack listener accepting an IPv4 client) — '.' is
    // allowed in the v6 body; uppercase folds to lower.
    CHECK(extract_peer_ip("ipv6:[::ffff:1.2.3.4]:80") == "::ffff:1.2.3.4");
    CHECK(extract_peer_ip("ipv6:[::FFFF:1.2.3.4]:80") == "::ffff:1.2.3.4");
    CHECK(extract_peer_ip("ipv4:1.2.3.4:5") == "1.2.3.4"); // ipv4 needs no folding
}

TEST_CASE("extract_peer_ip register/subscribe comparison is casing-symmetric (#1058)",
          "[agent_service][peer_mismatch][issue1058]") {
    using yuzu::server::detail::extract_peer_ip;
    // The #826 binding check compares extract_peer_ip(register) vs
    // extract_peer_ip(subscribe). The same IP in different hex casing / port
    // MUST compare equal after canonicalization, or a legit agent reconnecting
    // via a differently-cased peer string would be locked out.
    CHECK(extract_peer_ip("ipv6:[FE80::1]:443") == extract_peer_ip("ipv6:[fe80::1]:9999"));
    CHECK(extract_peer_ip("ipv6:[2001:DB8::AB]:1") == extract_peer_ip("ipv6:[2001:db8::ab]:2"));
    CHECK(extract_peer_ip("ipv4:1.2.3.4:443") == extract_peer_ip("ipv4:1.2.3.4:55"));
}

TEST_CASE("extract_peer_ip never returns junk on arbitrary input (#1058)",
          "[agent_service][peer_mismatch][issue1058][fuzz]") {
    using yuzu::server::detail::extract_peer_ip;
    using yuzu::server::detail::is_plausible_ipv6;
    using yuzu::server::detail::is_valid_ipv4;
    // Deterministic fuzz: random bytes from a hostile alphabet (colons,
    // brackets, percent, whitespace, non-hex letters) must never throw, and any
    // non-empty result must itself validate as one of the two accepted shapes —
    // the strict-mode guarantee under adversarial input.
    std::mt19937 rng(0xC0FFEE);
    const std::string alphabet = "ipv46:[]%.-_0123456789abcdefABCDEFxyz/ \t";
    std::uniform_int_distribution<std::size_t> len_dist(0, 40);
    std::uniform_int_distribution<std::size_t> ch_dist(0, alphabet.size() - 1);
    for (int iter = 0; iter < 20000; ++iter) {
        std::string s;
        const std::size_t n = len_dist(rng);
        for (std::size_t i = 0; i < n; ++i)
            s.push_back(alphabet[ch_dist(rng)]);
        const auto out = extract_peer_ip(s);
        if (!out.empty()) {
            CHECK((is_valid_ipv4(out) || is_plausible_ipv6(out)));
        }
    }
}

// ── #1064 — normalize_bare_ip (gateway_observed_peer parsing) ───────────────

TEST_CASE("normalize_bare_ip accepts canonical bare IPs, rejects junk (#1064)",
          "[agent_service][peer_mismatch][issue1064]") {
    using yuzu::server::detail::normalize_bare_ip;
    // The gateway fills RegisterRequest.gateway_observed_peer with a BARE IP
    // (no gRPC scheme/port). Valid IPv4 passes through; IPv6 is lowercased so it
    // compares equal to an extract_peer_ip() value from the same address.
    CHECK(normalize_bare_ip("203.0.113.7") == "203.0.113.7");
    CHECK(normalize_bare_ip("10.0.0.1") == "10.0.0.1");
    CHECK(normalize_bare_ip("2001:DB8::1") == "2001:db8::1");
    CHECK(normalize_bare_ip("fe80::1%eth0") == "fe80::1%eth0");

    // Anything not a clean literal → empty, so the caller falls back to the
    // transport (gateway) IP rather than recording attacker-controlled junk.
    CHECK(normalize_bare_ip("").empty());
    CHECK(normalize_bare_ip("not-an-ip").empty());
    CHECK(normalize_bare_ip("999.1.1.1").empty());        // octet > 255
    CHECK(normalize_bare_ip("01.02.03.04").empty());      // leading-zero (non-canonical)
    CHECK(normalize_bare_ip("ipv4:1.2.3.4:80").empty());  // gRPC framing is NOT a bare IP
    CHECK(normalize_bare_ip("1.2.3.4 ; rm -rf").empty()); // no injection round-trips
}

// ── #1128 — NAT-aware peer-binding decision (evaluate_peer_binding) ─────────

TEST_CASE("evaluate_peer_binding: exact match short-circuits to ok (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    // exact_ok=true means the strict check (or trusted-gateway) already passed —
    // no accommodation is consulted.
    CHECK(AgentServiceImpl::evaluate_peer_binding(true, "10.0.0.1", "10.0.0.1", false, {}) ==
          O::exact_ok);
    CHECK(AgentServiceImpl::evaluate_peer_binding(true, "10.0.0.1", "10.0.0.9", false, {}) ==
          O::exact_ok); // exact_ok is authoritative regardless of IP equality
    // gov QA SHOULD-2: a future bug that consulted CIDRs before exact_ok would
    // still pass the two assertions above (cidrs={} would short-circuit
    // ips_share_trusted_cidr to false). Pin the short-circuit with a non-empty
    // wide CIDR so the only way to reach O::exact_ok is the exact_ok=true gate.
    const std::vector<std::string> wide{"0.0.0.0/0"};
    CHECK(AgentServiceImpl::evaluate_peer_binding(true, "10.0.0.1", "8.8.8.8", false, wide) ==
          O::exact_ok);
}

TEST_CASE("evaluate_peer_binding: default (no accommodation) rejects a mismatch (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    // Strict-by-default: no mTLS match, no trusted CIDR → a mismatch is reject.
    // This is the unchanged #826 behaviour and the cross-range replay guard.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "8.8.8.8", false, {}) ==
          O::reject);
    const std::vector<std::string> cidrs{"203.0.113.0/24"};
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "203.0.113.7", "8.8.8.8", false, cidrs) ==
          O::reject); // only one side in range → still reject
    // #1128 acceptance bar "cross-range replay rejected" pinned at the decision
    // layer: each IP sits in a DIFFERENT trusted range, so they share none →
    // reject (a sniffed session replayed from another trusted subnet loses).
    const std::vector<std::string> two{"203.0.113.0/24", "198.51.100.0/24"};
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "203.0.113.7", "198.51.100.7", false,
                                                  two) == O::reject);
}

TEST_CASE("evaluate_peer_binding: empty IP is always reject, accommodation cannot rescue (#1128)",
          "[agent_service][peer_mismatch][issue1128][issue826]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    const std::vector<std::string> cidrs{"0.0.0.0/0"};
    // #826: an empty extracted IP is a mismatch, never a wildcard — even with a
    // matching mTLS identity or an all-encompassing /0 trusted range.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "", "10.0.0.1", true, cidrs) == O::reject);
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "", true, cidrs) == O::reject);
}

TEST_CASE("evaluate_peer_binding: mTLS identity match downgrades to advisory (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    // A verified, matching client identity is the stronger layer (#827/#1118),
    // so a multi-egress IP mismatch becomes advisory rather than reject.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "8.8.8.8",
                                                  /*client_identity_matches=*/true, {}) ==
          O::advisory_mtls);
    // mTLS takes precedence over CIDR when both would apply.
    const std::vector<std::string> cidrs{"0.0.0.0/0"};
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "10.0.0.1", "10.0.0.2", true, cidrs) ==
          O::advisory_mtls);
}

TEST_CASE("evaluate_peer_binding: shared trusted CIDR downgrades to advisory (#1128)",
          "[agent_service][peer_mismatch][issue1128]") {
    using O = AgentServiceImpl::PeerBindingOutcome;
    const std::vector<std::string> cidrs{"203.0.113.0/24", "2001:db8::/32"};
    // Legit multi-egress: both Register and Subscribe IPs in one declared range.
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "203.0.113.7", "203.0.113.200",
                                                  /*client_identity_matches=*/false, cidrs) ==
          O::advisory_nat_cidr);
    CHECK(AgentServiceImpl::evaluate_peer_binding(false, "2001:db8::1", "2001:db8:dead::beef", false,
                                                  cidrs) == O::advisory_nat_cidr);
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer round-trips, refuses empty",
          "[pg][agent_service][peer_mismatch][issue826]") {
    // The trusted-gateway set is the second leg of the #826 fix —
    // gateway-mode Subscribe is allowed if the peer IP was previously
    // noted via ProxyRegister. Empty IP must NEVER round-trip (would
    // recreate the bypass).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.2"));

    // Empty is rejected on insert AND on lookup.
    h.registry.note_trusted_gateway_peer("");
    CHECK_FALSE(h.registry.is_trusted_gateway_peer(""));
    // The original entry survives — the empty insert was a no-op,
    // not an accidental clear.
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
}

TEST_CASE("AgentRegistry::is_trusted_gateway_peer holds multiple gateways",
          "[pg][agent_service][peer_mismatch][issue826]") {
    // A fleet may have multiple gateway nodes (load-balanced cluster).
    // Each gateway noted via ProxyRegister joins the trusted set; none
    // of them displaces another.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    h.registry.note_trusted_gateway_peer("10.0.0.2");
    h.registry.note_trusted_gateway_peer("::1");
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.2"));
    CHECK(h.registry.is_trusted_gateway_peer("::1"));
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.3"));
}

// ── W1.3 R2 — trusted-gateway TTL + cap + gauge ────────────────────────────

TEST_CASE("AgentRegistry::is_trusted_gateway_peer evicts entries past TTL "
          "(W1.3 R2 / UP-3)",
          "[pg][agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // UP-3: a stale entry (TTL elapsed) is no longer trusted. The lookup
    // returns false; the next note_trusted_gateway_peer sweeps it out of
    // the map.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    REQUIRE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    REQUIRE(h.registry.trusted_gateway_peer_count() == 1);

    // Age past the TTL (1 h default) — push entries 2 h into the past.
    h.registry.expire_trusted_gateway_for_test(std::chrono::hours(2));

    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    // Map size unchanged until a new note triggers the sweep — the const
    // lookup path doesn't mutate.
    CHECK(h.registry.trusted_gateway_peer_count() == 1);

    // A fresh note from a DIFFERENT IP triggers the sweep that drops the
    // stale entry, then inserts the new one. Net size: 1 (not 2).
    h.registry.note_trusted_gateway_peer("10.0.0.2");
    CHECK(h.registry.trusted_gateway_peer_count() == 1);
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.1"));
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.2"));
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer refreshes last_seen on repeat "
          "(W1.3 R2)",
          "[pg][agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // A gateway that re-ProxyRegisters before TTL elapses keeps its trust
    // entry alive indefinitely. Test: insert → age to JUST shy of TTL →
    // re-insert → age another half-TTL → still trusted (would have
    // expired without the refresh).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    h.registry.note_trusted_gateway_peer("10.0.0.1");

    // Age to 45 min (still within 1 h TTL).
    h.registry.expire_trusted_gateway_for_test(std::chrono::minutes(45));
    REQUIRE(h.registry.is_trusted_gateway_peer("10.0.0.1"));

    // Refresh.
    h.registry.note_trusted_gateway_peer("10.0.0.1");

    // Age another 45 min — without the refresh, total would be 90 min
    // (past TTL). With the refresh, last_seen reset to ~now, so this is
    // only 45 min from refresh → still trusted.
    h.registry.expire_trusted_gateway_for_test(std::chrono::minutes(45));
    CHECK(h.registry.is_trusted_gateway_peer("10.0.0.1"));
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer caps map at kTrustedGatewayCap, "
          "evicts oldest first (W1.3 R2 / UP-2)",
          "[pg][agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // UP-2: in a churn-heavy NAT environment the trusted set used to
    // grow unboundedly. The cap (1024) prevents memory DoS; oldest-first
    // eviction preserves trust for the most recent gateways.
    using yuzu::server::detail::AgentRegistry;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);

    // Fill to cap. We use distinct IPs to avoid the in-place refresh path.
    // Each insert is one steady_clock tick newer than the previous, so
    // "oldest" = the first IP inserted.
    for (std::size_t i = 0; i < AgentRegistry::kTrustedGatewayCap; ++i) {
        h.registry.note_trusted_gateway_peer("10.0." + std::to_string(i / 256) + "." +
                                             std::to_string(i % 256));
    }
    REQUIRE(h.registry.trusted_gateway_peer_count() == AgentRegistry::kTrustedGatewayCap);
    REQUIRE(h.registry.is_trusted_gateway_peer("10.0.0.0")); // first inserted

    // One more insert pushes the oldest entry out (not the new one, not a
    // middle one). Net size: cap, not cap+1.
    h.registry.note_trusted_gateway_peer("192.168.99.99");
    CHECK(h.registry.trusted_gateway_peer_count() == AgentRegistry::kTrustedGatewayCap);
    CHECK(h.registry.is_trusted_gateway_peer("192.168.99.99"));  // new entry kept
    CHECK_FALSE(h.registry.is_trusted_gateway_peer("10.0.0.0")); // oldest evicted
}

TEST_CASE("AgentRegistry::note_trusted_gateway_peer updates the Prometheus gauge "
          "(W1.3 R2)",
          "[pg][agent_service][peer_mismatch][issue826][w1_3_r2][metrics]") {
    // The yuzu_trusted_gateway_peer_set_size gauge reflects current map
    // size on every note + every sweep, so dashboards see real-time
    // health (rising under churn, falling as entries expire).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);

    auto current_gauge = [&]() {
        return h.metrics.gauge("yuzu_trusted_gateway_peer_set_size").value();
    };

    CHECK(current_gauge() == 0.0); // gauge unset → 0

    h.registry.note_trusted_gateway_peer("10.0.0.1");
    CHECK(current_gauge() == 1.0);

    h.registry.note_trusted_gateway_peer("10.0.0.2");
    h.registry.note_trusted_gateway_peer("10.0.0.3");
    CHECK(current_gauge() == 3.0);

    // Re-insert the same IP — refreshes last_seen, does not change size.
    h.registry.note_trusted_gateway_peer("10.0.0.1");
    CHECK(current_gauge() == 3.0);

    // Age all entries past TTL, then trigger a sweep via a fresh note —
    // gauge drops from 3 to 1 (3 expired + 1 new).
    h.registry.expire_trusted_gateway_for_test(std::chrono::hours(2));
    h.registry.note_trusted_gateway_peer("172.16.0.1");
    CHECK(current_gauge() == 1.0);
}

// ── W1.3 R2 — Fix #1 / UP-7 — trust-after-auth on ProxyRegister ────────────

TEST_CASE("ProxyRegister: failed enrollment (no token, no auto-approve) does NOT "
          "add the peer to the trusted set (W1.3 R2 / UP-7)",
          "[pg][agent_service][peer_mismatch][issue826][w1_3_r2][gateway]") {
    // UP-7 / sec-G MEDIUM-1: the trusted-peer noting used to fire BEFORE
    // the enrollment branches, with the rationale that even denied
    // proxies should contribute to gateway-trust discovery. That inverted
    // the trust model — any peer reaching :50055 with any payload became
    // trusted. The fix moves the noting to the post-`gw_enrolled:`
    // success path. With a fresh AuthManager and no auto-approve rules,
    // ProxyRegister falls into the "pending" branch (Tier 1 queue) and
    // returns without touching the trusted set.
    //
    // Note: context==nullptr in this test means the trust-noting branch
    // would skip even on success — what this test pins is structural:
    // the *pending* return doesn't add anything. The success-path counter-
    // example is the existing test
    // "AgentRegistry::note_trusted_gateway_peer round-trips, refuses empty"
    // which proves the helper itself is wired and reachable.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("agent-pending");
    req.mutable_info()->set_hostname("host-pending");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.mutable_info()->set_agent_version("0.0.0-test");
    // No enrollment_token, no auto-approve rules → Tier 1 pending branch.

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "pending");
    // The invariant under test: pending enrollment did not touch the
    // trusted set. (And the gauge stayed at 0.)
    CHECK(h.registry.trusted_gateway_peer_count() == 0);
    CHECK(h.metrics.gauge("yuzu_trusted_gateway_peer_set_size").value() == 0.0);
}

TEST_CASE("ProxyRegister: invalid enrollment token does NOT add the peer to the "
          "trusted set (W1.3 R2 / UP-7)",
          "[pg][agent_service][peer_mismatch][issue826][w1_3_r2][gateway]") {
    // Companion to the pending-branch test above — the denied-token
    // branch in ProxyRegister also returns early without crossing into
    // the trust-noting code. Pre-fix this branch would have already
    // recorded the peer.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("agent-bad-token");
    req.mutable_info()->set_hostname("host-bad-token");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token("clearly-invalid-token");

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "denied");
    CHECK(h.registry.trusted_gateway_peer_count() == 0);
}

// ── W1.3 R2 — Fix #3 / consistency MEDIUM-1 — shared peer_ip.hpp ───────────

TEST_CASE("peer_ip.hpp::extract_peer_ip matches AgentServiceImpl::extract_peer_ip "
          "byte-for-byte (W1.3 R2 / consistency MEDIUM-1)",
          "[agent_service][peer_mismatch][issue826][w1_3_r2]") {
    // The two former call sites in agent_service_impl.cpp and
    // gateway_service_impl.cpp now route through the shared free function
    // in peer_ip.hpp. The static member AgentServiceImpl::extract_peer_ip
    // is a thin shim retained for the existing test surface. Pin: both
    // entry points produce identical output on every shape gRPC can hand
    // back.
    using yuzu::server::detail::AgentServiceImpl;
    using yuzu::server::detail::extract_peer_ip;

    const std::string_view inputs[] = {
        "ipv4:1.2.3.4:5678", "ipv4:127.0.0.1:50051",
        "ipv6:[::1]:50051",  "ipv6:[2001:db8::1]:443",
        "unix:/tmp/sock",    "",
        "garbage",           "ipv6:no-brackets:8080",
        "ipv6:[unclosed",
    };

    for (auto in : inputs) {
        CHECK(AgentServiceImpl::extract_peer_ip(in) == extract_peer_ip(in));
    }
}

// ── W1.4 R2 / UP-H1 — agent_id length cap at handler entry ─────────────────

TEST_CASE("Register: rejects oversize agent_id with INVALID_ARGUMENT (W1.4 R2 / UP-H1)",
          "[pg][agent_service][register][w1_4_r2][up_h1]") {
    // The protobuf places no length constraint on agent_id and W1.4 PR1
    // audits the value verbatim. Without this cap, a presenter can supply
    // a 1 MiB agent_id and every downstream audit row carries it. Cap is
    // checked BEFORE any audit emission, mTLS check, or auth-mgr lookup
    // so attack traffic costs ~one strlen + counter increment.
    using yuzu::server::auth::kMaxAgentIdLength;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(std::string(kMaxAgentIdLength + 1, 'A'));
    req.mutable_info()->set_hostname("host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");

    apb::RegisterResponse resp;
    auto status = h.svc.Register(/*context=*/nullptr, &req, &resp);

    CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    // Counter ticked with the right label.
    yuzu::Labels labels{{"reason", "length"}};
    CHECK(h.metrics.counter("yuzu_register_invalid_agent_id_total", labels).value() == 1.0);
}

TEST_CASE("Register: rejects empty agent_id with INVALID_ARGUMENT (W1.4 R2 / UP-H1)",
          "[pg][agent_service][register][w1_4_r2][up_h1]") {
    // Empty agent_id is structurally invalid — every downstream code path
    // assumes a non-empty key (registry, audit principal, pending lookup).
    // Same metric / status as the oversize case.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("");
    req.mutable_info()->set_hostname("host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");

    apb::RegisterResponse resp;
    auto status = h.svc.Register(/*context=*/nullptr, &req, &resp);

    CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    yuzu::Labels labels{{"reason", "length"}};
    CHECK(h.metrics.counter("yuzu_register_invalid_agent_id_total", labels).value() == 1.0);
}

TEST_CASE("ProxyRegister: rejects oversize agent_id with INVALID_ARGUMENT (W1.4 R2 / UP-H1)",
          "[pg][agent_service][register][gateway][w1_4_r2][up_h1]") {
    // Mirror of the direct-Register path. ProxyRegister carries the same
    // attack surface — the gateway proxies the agent's RegisterRequest
    // unmodified, so an attacker who controls the agent payload can
    // present an oversize agent_id here too. Source label on the metric
    // discriminates gateway-proxied attacks from direct-connect ones.
    using yuzu::server::auth::kMaxAgentIdLength;
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(std::string(kMaxAgentIdLength + 1, 'B'));
    req.mutable_info()->set_hostname("host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    CHECK(status.error_code() == grpc::StatusCode::INVALID_ARGUMENT);
    yuzu::Labels labels{{"reason", "length"}, {"source", "gateway_proxy"}};
    CHECK(h.metrics.counter("yuzu_register_invalid_agent_id_total", labels).value() == 1.0);
    // Trusted-peer set untouched — the early-reject path never reaches
    // the post-success note_trusted_gateway_peer call.
    CHECK(h.registry.trusted_gateway_peer_count() == 0);
}

// ── PR5d — ProxyRegister issues a per-agent cert through the gateway ────────
//
// The boot-test gap: a gateway-enrolled agent registered fine but never got a
// per-agent client cert (only the direct AgentServiceImpl::Register signed the
// CSR). ProxyRegister now mirrors the direct path — when a CSR is present and a
// signer is wired, it returns issued_certificate/issued_ca_chain on the same
// verbatim-relayed RegisterResponse. These pin the four branches.

namespace {
// Drive a successful gateway enrollment (valid token) so ProxyRegister reaches
// the gw_enrolled issuance block, with `agent_id` carried.
apb::RegisterRequest make_gw_register(yuzu::server::auth::AuthManager& auth_mgr,
                                      const std::string& agent_id, const std::string& csr_pem) {
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id(agent_id);
    req.mutable_info()->set_hostname("gw-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(auth_mgr.create_enrollment_token("test", 0, std::chrono::hours(1)));
    if (!csr_pem.empty())
        req.set_csr_pem(csr_pem);
    return req;
}
} // namespace

TEST_CASE("ProxyRegister: a wired signer issues a per-agent cert for a gateway-enrolled agent",
          "[pg][agent_service][register][gateway][pki][pr5d]") {
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    int calls = 0;
    std::string seen_csr, seen_id;
    auto seen_src = yuzu::server::CertIssuanceSource::Direct; // sentinel ≠ expected
    gateway_svc.set_agent_cert_signer(
        [&](const std::string& csr, const std::string& id,
            yuzu::server::CertIssuanceSource src)
            -> std::optional<std::pair<std::string, std::string>> {
            ++calls;
            seen_csr = csr;
            seen_id = id;
            seen_src = src;
            return std::make_pair("LEAF-PEM-for-" + id, "CHAIN-PEM");
        });

    auto req = make_gw_register(h.auth_mgr, "agent-gw-1", "FAKE-CSR");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK(resp.accepted());
    CHECK(resp.enrollment_status() == "enrolled");
    CHECK(calls == 1);
    CHECK(seen_csr == "FAKE-CSR");          // the agent's CSR reached the signer
    CHECK(seen_id == "agent-gw-1");          // bound to the registering agent_id
    // #1290: the gateway path tags issuance gateway_proxy so the ca.cert.issued
    // audit (minted inside sign_agent_csr) is forensically attributable.
    CHECK(seen_src == yuzu::server::CertIssuanceSource::GatewayProxy);
    CHECK(resp.issued_certificate() == "LEAF-PEM-for-agent-gw-1");
    CHECK(resp.issued_ca_chain() == "CHAIN-PEM");
}

namespace {
// Pre-migrated template (see PgTestTemplate in test_helpers.hpp): the generic
// InventoryStore is the only PG store these two [pg] tests construct.
yuzu::test::PgTestTemplate inventory_h1_tpl{"agent_svc_inventory", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    yuzu::server::InventoryStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("agent_svc_inventory template: store failed to migrate");
}};
} // namespace

TEST_CASE("ProxyInventory: device_ci is NOT double-stored into the generic InventoryStore "
          "(H1 — gateway parity + Inventory:Read boundary)",
          "[pg][agent_service][gateway][inventory][device_ci]") {
    // Regression for the round-2 H1: the gateway generic-blob loop must skip every
    // TYPED source (is_typed_inventory_source) — else device_ci's serial/UUID/MAC
    // lands in the generic InventoryStore, which is read on Infrastructure:Read,
    // bypassing the new Inventory:Read securable (and breaking direct/gateway parity,
    // since the direct path has no generic loop).
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    using yuzu::server::InventoryStore;
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_h1_tpl);
    // Shared pool: both InventoryStore (schema inventory_store, migrated by the
    // template above) and ResponseStore (schema response_store, migrated by its
    // own constructor below — schemas coexist in one Postgres database) reuse
    // this one connection pool rather than standing up a second ephemeral DB.
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    InventoryStore inv{pool}; // the generic blob store (read on Infrastructure:Read)
    REQUIRE(inv.is_open());
    gateway_svc.set_inventory_store(&inv);

    // Register a gateway session so ProxyInventory resolves the agent_id.
    auto reg = make_gw_register(h.auth_mgr, "agent-gw-inv", /*csr_pem=*/"");
    apb::RegisterResponse rresp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &reg, &rresp).ok());
    REQUIRE(rresp.accepted());
    const std::string session_id = rresp.session_id();
    REQUIRE_FALSE(session_id.empty());

    // A report carrying BOTH a typed source (device_ci) and a generic source.
    apb::InventoryReport rpt;
    rpt.set_session_id(session_id);
    (*rpt.mutable_plugin_data())["device_ci"] = "raw-canonical-blob"; // typed → must be skipped
    (*rpt.mutable_plugin_data())["custom_source"] = "{\"k\":1}";      // generic → must be stored
    apb::InventoryAck ack;
    REQUIRE(gateway_svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());

    auto device_ci_row = inv.get("agent-gw-inv", "device_ci");
    REQUIRE(device_ci_row.has_value());      // not degraded
    CHECK_FALSE(device_ci_row->has_value()); // H1: not in the generic store
    auto custom_row = inv.get("agent-gw-inv", "custom_source");
    REQUIRE(custom_row.has_value());
    CHECK(custom_row->has_value()); // generic source still works
}

TEST_CASE("ProxyInventory: software_licensing is NOT double-stored into the generic "
          "InventoryStore (typed-registry same-change rule + SoftwareLicensing boundary)",
          "[pg][agent_service][gateway][inventory][software_licensing]") {
    // Clone of the device_ci H1 parity case for the software_licensing typed key
    // (ADR-0024 Decision 5 / roadmap C-9 pattern): the gateway generic-blob loop
    // must skip every TYPED source (is_typed_inventory_source) — else detected-
    // licence rows (incl. `user_ref`, the ADR-0024 D11 pseudonym) land in the
    // generic InventoryStore, which is read on Infrastructure:Read, bypassing
    // the SoftwareLicensing securable (and breaking direct/gateway parity,
    // since the direct path has no generic loop).
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    using yuzu::server::InventoryStore;
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_h1_tpl);
    // Shared pool: both InventoryStore and ResponseStore reuse this one
    // connection pool (see the H1 device_ci test above for why that's safe).
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    InventoryStore inv{pool}; // the generic blob store (read on Infrastructure:Read)
    REQUIRE(inv.is_open());
    gateway_svc.set_inventory_store(&inv);
    // No SoftwareLicensingStore wired — the skip must hold regardless of the
    // typed store's presence (the registry, not the store hook, is the guard).

    auto reg = make_gw_register(h.auth_mgr, "agent-gw-lic", /*csr_pem=*/"");
    apb::RegisterResponse rresp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &reg, &rresp).ok());
    REQUIRE(rresp.accepted());
    const std::string session_id = rresp.session_id();
    REQUIRE_FALSE(session_id.empty());

    // A report carrying BOTH the typed source and a generic source.
    apb::InventoryReport rpt;
    rpt.set_session_id(session_id);
    (*rpt.mutable_plugin_data())["software_licensing"] =
        "lic\x1fSomeProduct\x1fSomeVendor\x1e";                // typed → must be skipped
    (*rpt.mutable_plugin_data())["custom_source"] = "{\"k\":1}"; // generic → must be stored
    apb::InventoryAck ack;
    REQUIRE(gateway_svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());

    auto lic_row = inv.get("agent-gw-lic", "software_licensing");
    REQUIRE(lic_row.has_value());      // not degraded
    CHECK_FALSE(lic_row->has_value()); // not double-stored
    auto custom_row = inv.get("agent-gw-lic", "custom_source");
    REQUIRE(custom_row.has_value());
    CHECK(custom_row->has_value()); // generic source still works
}

namespace {
// Pre-migrated template covering both stores the app_usage composition tests
// below need: the generic InventoryStore (mixed-version parity check) and
// the typed AppUsageStore (Wave 7 PR7.2).
yuzu::test::PgTestTemplate app_usage_composition_tpl{
    "agent_svc_app_usage", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        yuzu::server::InventoryStore inv_store{pool};
        yuzu::server::AppUsageStore usage_store{pool};
        if (!inv_store.is_open() || !usage_store.is_open())
            throw std::runtime_error("agent_svc_app_usage template: a store failed to migrate");
    }};

// One `lu|`-kind app_usage wire blob (records 0x1E-joined, fields 0x1F-joined,
// kind in field 0) carrying a single executable row — mirrors
// app_usage_ingestion.cpp's parse_app_usage_blob contract exactly.
std::string make_app_usage_blob(const std::string& exe_key) {
    // Adjacent string literals ("\x1f" "1000") deliberately split the hex
    // escape from the following digits — \x consumes every following hex
    // digit greedily, so "\x1f1000" would try to parse "1f1000" as one
    // (out-of-range) hex escape.
    return "lu\x1f" + exe_key + "\x1f" "1000" "\x1f" "2000" "\x1f" "5" "\x1f" "600";
}
} // namespace

TEST_CASE("ReportInventory (direct): reaches ingest_app_usage_report and persists rows",
          "[pg][agent_service][app_usage]") {
    using yuzu::server::AppUsageStore;
    YUZU_REQUIRE_PG_DB_TPL(db, app_usage_composition_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);

    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());
    h.svc.set_app_usage_store(&usage);

    auto raw = h.auth_mgr.create_enrollment_token("t1", /*max_uses=*/1, std::chrono::hours(1));
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("agent-direct-usage");
    req.mutable_info()->set_hostname("host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(raw);
    apb::RegisterResponse resp;
    REQUIRE(h.svc.Register(/*context=*/nullptr, &req, &resp).ok());
    REQUIRE(resp.accepted());

    apb::InventoryReport rpt;
    rpt.set_session_id(resp.session_id());
    (*rpt.mutable_content_hashes())["app_usage"] = "claimed-hash";
    (*rpt.mutable_plugin_data())["app_usage"] = make_app_usage_blob("chrome.exe");
    apb::InventoryAck ack;
    REQUIRE(h.svc.ReportInventory(/*context=*/nullptr, &rpt, &ack).ok());
    CHECK(ack.received());
    // A successful full-replace never nacks.
    CHECK(std::find(ack.need_full().begin(), ack.need_full().end(), "app_usage") ==
          ack.need_full().end());

    auto rows = usage.get_agent_last_used("agent-direct-usage");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].exe_key == "chrome.exe");
}

TEST_CASE("ProxyInventory (gateway): reaches ingest_app_usage_report and persists rows",
          "[pg][agent_service][gateway][app_usage]") {
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    using yuzu::server::AppUsageStore;
    YUZU_REQUIRE_PG_DB_TPL(db, app_usage_composition_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());
    gateway_svc.set_app_usage_store(&usage);

    auto reg = make_gw_register(h.auth_mgr, "agent-gw-usage", /*csr_pem=*/"");
    apb::RegisterResponse rresp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &reg, &rresp).ok());
    REQUIRE(rresp.accepted());

    apb::InventoryReport rpt;
    rpt.set_session_id(rresp.session_id());
    (*rpt.mutable_content_hashes())["app_usage"] = "claimed-hash";
    (*rpt.mutable_plugin_data())["app_usage"] = make_app_usage_blob("notepad.exe");
    apb::InventoryAck ack;
    REQUIRE(gateway_svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
    CHECK(std::find(ack.need_full().begin(), ack.need_full().end(), "app_usage") ==
          ack.need_full().end());

    auto rows = usage.get_agent_last_used("agent-gw-usage");
    REQUIRE(rows.has_value());
    REQUIRE(rows->size() == 1);
    CHECK((*rows)[0].exe_key == "notepad.exe");
}

TEST_CASE("ProxyInventory: app_usage is NOT double-stored into the generic InventoryStore "
          "(mixed-version parity, adjudication P1)",
          "[pg][agent_service][gateway][inventory][app_usage]") {
    // A gateway-proxied report carrying an app_usage blob must leave the
    // generic InventoryStore with NO app_usage row for that agent — the same
    // H1 parity/leak-prevention shape as the device_ci and software_licensing
    // cases above, extended to the newest typed source.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    using yuzu::server::AppUsageStore;
    using yuzu::server::InventoryStore;
    YUZU_REQUIRE_PG_DB_TPL(db, app_usage_composition_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    InventoryStore inv{pool}; // the generic blob store (read on Infrastructure:Read)
    REQUIRE(inv.is_open());
    gateway_svc.set_inventory_store(&inv);
    AppUsageStore usage{pool};
    REQUIRE(usage.is_open());
    gateway_svc.set_app_usage_store(&usage);

    auto reg = make_gw_register(h.auth_mgr, "agent-gw-usage-mixed", /*csr_pem=*/"");
    apb::RegisterResponse rresp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &reg, &rresp).ok());
    REQUIRE(rresp.accepted());

    apb::InventoryReport rpt;
    rpt.set_session_id(rresp.session_id());
    (*rpt.mutable_content_hashes())["app_usage"] = "claimed-hash";
    (*rpt.mutable_plugin_data())["app_usage"] = make_app_usage_blob("firefox.exe"); // typed
    (*rpt.mutable_plugin_data())["custom_source"] = "{\"k\":1}";                    // generic
    apb::InventoryAck ack;
    REQUIRE(gateway_svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());

    // The typed seam WAS reached (the store has the row)...
    auto rows = usage.get_agent_last_used("agent-gw-usage-mixed");
    REQUIRE(rows.has_value());
    CHECK(rows->size() == 1);
    // ...but the generic store never sees it.
    auto usage_row = inv.get("agent-gw-usage-mixed", "app_usage");
    REQUIRE(usage_row.has_value());      // not degraded
    CHECK_FALSE(usage_row->has_value()); // not double-stored
    auto custom_row = inv.get("agent-gw-usage-mixed", "custom_source");
    REQUIRE(custom_row.has_value());
    CHECK(custom_row->has_value()); // generic source still works
}

TEST_CASE("ProxyInventory: over-cap source maps are rejected before generic writes",
          "[pg][agent_service][gateway][inventory][security]") {
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    using yuzu::server::InventoryStore;
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_h1_tpl);
    // Shared pool: both InventoryStore and ResponseStore reuse this one
    // connection pool (see the H1 device_ci test above for why that's safe).
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    InventoryStore inv{pool};
    REQUIRE(inv.is_open());
    gateway_svc.set_inventory_store(&inv);

    auto reg = make_gw_register(h.auth_mgr, "agent-gw-source-cap", /*csr_pem=*/"");
    apb::RegisterResponse rresp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &reg, &rresp).ok());
    REQUIRE(rresp.accepted());

    apb::InventoryReport rpt;
    rpt.set_session_id(rresp.session_id());
    for (int i = 0; i < 65; ++i)
        (*rpt.mutable_plugin_data())["custom-" + std::to_string(i)] = "{}";
    apb::InventoryAck ack;
    REQUIRE(gateway_svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
    CHECK(ack.received());

    auto rows = inv.get_agent_inventory("agent-gw-source-cap");
    REQUIRE(rows.has_value());
    CHECK(rows->empty());
    CHECK(h.metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "__report__"}, {"outcome", "rejected"}})
              .value() == 1.0);
}

TEST_CASE("ProxyInventory: a per-source blob nesting past kMcpMaxJsonDepth is rejected, a "
          "healthy sibling source in the same report still stores (#2437-class write-side guard)",
          "[pg][agent_service][gateway][inventory][security]") {
    // Regression for the #2437-class generic InventoryStore write-side guard:
    // ProxyInventory's generic per-source loop is the ONLY call site of
    // InventoryStore::upsert in the tree, and each blob is raw wire bytes off
    // an agent with no prior validation. A blob nesting past kMcpMaxJsonDepth
    // must be rejected (skipped) BEFORE it ever reaches upsert - dump() on a
    // too-deep stored value is unboundedly recursive and would SIGSEGV the
    // whole process on a later read. A poisoned source must not affect any
    // OTHER healthy source in the same report.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    using yuzu::server::InventoryStore;
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_h1_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    InventoryStore inv{pool};
    REQUIRE(inv.is_open());
    gateway_svc.set_inventory_store(&inv);

    auto reg = make_gw_register(h.auth_mgr, "agent-gw-depth", /*csr_pem=*/"");
    apb::RegisterResponse rresp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &reg, &rresp).ok());
    REQUIRE(rresp.accepted());

    // Reachability-proxy depth (35 > kMcpMaxJsonDepth's 32) - never the real
    // ~100,000-level attack depth in a test.
    const std::string poisoned = std::string(35, '[') + std::string(35, ']');

    apb::InventoryReport rpt;
    rpt.set_session_id(rresp.session_id());
    (*rpt.mutable_plugin_data())["poisoned_source"] = poisoned;
    (*rpt.mutable_plugin_data())["healthy_source"] = R"({"k":1})";
    apb::InventoryAck ack;
    REQUIRE(gateway_svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
    CHECK(ack.received()); // overall report still acked

    auto poisoned_row = inv.get("agent-gw-depth", "poisoned_source");
    REQUIRE(poisoned_row.has_value()); // not degraded
    CHECK_FALSE(poisoned_row->has_value()); // rejected, never stored

    auto healthy_row = inv.get("agent-gw-depth", "healthy_source");
    REQUIRE(healthy_row.has_value());
    REQUIRE(healthy_row->has_value());
    CHECK((*healthy_row)->data_json == R"({"k":1})"); // healthy sibling stored correctly

    // Fixed sentinel, never the raw plugin_name: that name is caller-supplied
    // for the generic source family, so labeling on it would let one agent
    // mint unbounded metric series (see the next TEST_CASE). outcome is its
    // OWN "rejected_depth" value, distinct from the whole-report-cap
    // "rejected" outcome (inventory_ingestion.cpp), so this per-blob
    // rejection does not page the YuzuInventoryReportRejected alert's
    // source-map-cap runbook.
    CHECK(h.metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "__generic__"}, {"outcome", "rejected_depth"}})
              .value() == 1.0);
    // Adversarial-review finding: a per-blob depth rejection must NOT also
    // increment the whole-report-cap outcome, or the YuzuInventoryReportRejected
    // alert (which sums ALL outcome="rejected" series) fires with the wrong
    // runbook for a single over-depth blob that never came close to the
    // report's 64-source cap.
    CHECK(h.metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "__generic__"}, {"outcome", "rejected"}})
              .value() == 0.0);
}

TEST_CASE("ProxyInventory: rejecting over-depth blobs under many distinct caller-chosen source "
          "names stays on ONE bounded metric series, not one per name (#2437-class cardinality)",
          "[pg][agent_service][gateway][inventory][security]") {
    // Gate 8 fix: an earlier version of the write-side guard used the raw,
    // agent-supplied plugin_name as the metric label - an authenticated agent
    // could mint an unbounded number of retained series just by resubmitting
    // an over-depth blob under a different made-up source name each time.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    using yuzu::server::InventoryStore;
    YUZU_REQUIRE_PG_DB_TPL(db, inventory_h1_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    InventoryStore inv{pool};
    REQUIRE(inv.is_open());
    gateway_svc.set_inventory_store(&inv);

    auto reg = make_gw_register(h.auth_mgr, "agent-gw-depth-2", /*csr_pem=*/"");
    apb::RegisterResponse rresp;
    REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &reg, &rresp).ok());
    REQUIRE(rresp.accepted());

    const std::string poisoned = std::string(35, '[') + std::string(35, ']');
    for (int i = 0; i < 5; ++i) {
        apb::InventoryReport rpt;
        rpt.set_session_id(rresp.session_id());
        (*rpt.mutable_plugin_data())["source_" + std::to_string(i)] = poisoned;
        apb::InventoryAck ack;
        REQUIRE(gateway_svc.ProxyInventory(/*context=*/nullptr, &rpt, &ack).ok());
    }

    // Five distinct source names, all rejected: if the fix still labeled on
    // the raw name, each would land in its own series and this would read 1,
    // not 5. Reading 5 is only possible if all five collapsed onto the SAME
    // bounded sentinel series.
    CHECK(h.metrics
              .counter("yuzu_inventory_ingest_total",
                       {{"source", "__generic__"}, {"outcome", "rejected_depth"}})
              .value() == 5.0);
}

TEST_CASE("ProxyRegister: no signer wired → enrolls but issues no cert (graceful degrade)",
          "[pg][agent_service][register][gateway][pki][pr5d]") {
    // The pre-PR5d behavior, now the explicit fallback: a CSR with no signer
    // (CA inactive) must still enroll the agent, just without a cert.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    auto req = make_gw_register(h.auth_mgr, "agent-gw-2", "FAKE-CSR");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK(resp.accepted());
    CHECK(resp.issued_certificate().empty());
    CHECK(resp.issued_ca_chain().empty());
}

TEST_CASE("ProxyRegister: signer wired but no CSR → signer not called, no cert",
          "[pg][agent_service][register][gateway][pki][pr5d]") {
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    int calls = 0;
    gateway_svc.set_agent_cert_signer(
        [&](const std::string&, const std::string&, yuzu::server::CertIssuanceSource)
            -> std::optional<std::pair<std::string, std::string>> {
            ++calls;
            return std::make_pair("X", "Y");
        });

    auto req = make_gw_register(h.auth_mgr, "agent-gw-3", /*csr_pem=*/"");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK(resp.accepted());
    CHECK(calls == 0); // no CSR → signer never invoked
    CHECK(resp.issued_certificate().empty());
}

TEST_CASE("ProxyRegister: signing failure is non-fatal (agent still enrolled)",
          "[pg][agent_service][register][gateway][pki][pr5d]") {
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};

    gateway_svc.set_agent_cert_signer(
        [&](const std::string&, const std::string&, yuzu::server::CertIssuanceSource)
            -> std::optional<std::pair<std::string, std::string>> { return std::nullopt; });

    auto req = make_gw_register(h.auth_mgr, "agent-gw-4", "FAKE-CSR");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK(resp.accepted()); // enrollment succeeds even though signing failed
    CHECK(resp.enrollment_status() == "enrolled");
    CHECK(resp.issued_certificate().empty());
}

TEST_CASE("Register (direct): a wired signer issues a per-agent cert — parity with ProxyRegister",
          "[pg][agent_service][register][pki][pr5d]") {
    // Locks the direct-path issuance block (agent_service_impl.cpp:539) that
    // ProxyRegister mirrors. Without this, a future edit to the direct block
    // would silently break the parity PR5d depends on (consistency Gate-4 SHOULD).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    int calls = 0;
    std::string seen_csr, seen_id;
    auto seen_src = yuzu::server::CertIssuanceSource::GatewayProxy; // sentinel ≠ expected
    h.svc.set_agent_cert_signer(
        [&](const std::string& csr, const std::string& id,
            yuzu::server::CertIssuanceSource src)
            -> std::optional<std::pair<std::string, std::string>> {
            ++calls;
            seen_csr = csr;
            seen_id = id;
            seen_src = src;
            return std::make_pair("LEAF-PEM-for-" + id, "CHAIN-PEM");
        });

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("agent-direct-1");
    req.mutable_info()->set_hostname("h");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(h.auth_mgr.create_enrollment_token("test", 0, std::chrono::hours(1)));
    req.set_csr_pem("FAKE-CSR");

    apb::RegisterResponse resp;
    auto status = h.svc.Register(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK(resp.accepted());
    CHECK(calls == 1);
    CHECK(seen_csr == "FAKE-CSR");
    CHECK(seen_id == "agent-direct-1");
    // #1290: the direct path tags issuance `direct` (vs the gateway's gateway_proxy).
    CHECK(seen_src == yuzu::server::CertIssuanceSource::Direct);
    CHECK(resp.issued_certificate() == "LEAF-PEM-for-agent-direct-1");
    CHECK(resp.issued_ca_chain() == "CHAIN-PEM");
}

TEST_CASE("ProxyRegister: the signer is called with the RELAYED agent_id, never the CSR subject "
          "(confused-deputy identity-binding defense, #1273 B-2)",
          "[pg][agent_service][register][gateway][pki][pr5d][security]") {
    // The confused-deputy defense: identity is set from the authenticated
    // enrollment (`info.agent_id()`), NOT from anything in the attacker-relayed
    // CSR. A CSR whose bytes "claim" a different agent must still cause the signer
    // to be called with the registering agent_id — so the issued leaf binds to the
    // enrolled id, not the CSR's. (X509_REQ_verify proves key-ownership only; this
    // pins that the service layer ignores CSR-asserted identity.)
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    std::string seen_id;
    gateway_svc.set_agent_cert_signer(
        [&](const std::string&, const std::string& id, yuzu::server::CertIssuanceSource)
            -> std::optional<std::pair<std::string, std::string>> {
            seen_id = id;
            return std::make_pair("LEAF-for-" + id, "CHAIN");
        });

    // CSR blob "claims" victim-agent; the enrollment is for attacker-agent.
    auto req = make_gw_register(h.auth_mgr, "attacker-agent",
                                "CSR-with-subject-CN=victim-agent");
    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK(seen_id == "attacker-agent");                         // relayed id, NOT the CSR's
    CHECK(resp.issued_certificate() == "LEAF-for-attacker-agent");
    CHECK(resp.issued_certificate().find("victim") == std::string::npos);
}

TEST_CASE("ProxyRegister: a THROWING signer cannot crash the gateway handler (#1273 B-2)",
          "[pg][agent_service][register][gateway][pki][pr5d][security]") {
    // The signer runs inside the sync gRPC handler; an exception out of it would
    // otherwise propagate and `terminate` the now-gateway-reachable service. The
    // shared signer is wrapped in try/catch — this pins that a throwing signer
    // degrades to "enrolled, no cert" rather than taking the process down.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    gateway_svc.set_agent_cert_signer(
        [&](const std::string&, const std::string&, yuzu::server::CertIssuanceSource)
            -> std::optional<std::pair<std::string, std::string>> {
            throw std::runtime_error("signer blew up (key load glitch / OpenSSL error)");
        });

    auto req = make_gw_register(h.auth_mgr, "agent-gw-throw", "FAKE-CSR");
    apb::RegisterResponse resp;
    grpc::Status status;
    REQUIRE_NOTHROW(status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp));
    REQUIRE(status.ok());
    CHECK(resp.accepted());                       // enrollment still succeeds
    CHECK(resp.issued_certificate().empty());     // no cert, no crash
}

TEST_CASE("Register (direct): a THROWING signer cannot crash the handler either "
          "(parity with ProxyRegister, #1273 B-2)",
          "[pg][agent_service][register][pki][pr5d][security]") {
    // Parity: the direct Register path shares the same try/catch crash-safety as
    // ProxyRegister (both signer sites are now exception-contained).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    h.svc.set_agent_cert_signer(
        [&](const std::string&, const std::string&, yuzu::server::CertIssuanceSource)
            -> std::optional<std::pair<std::string, std::string>> {
            throw std::runtime_error("signer blew up");
        });
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("agent-direct-throw");
    req.mutable_info()->set_hostname("h");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(h.auth_mgr.create_enrollment_token("test", 0, std::chrono::hours(1)));
    req.set_csr_pem("FAKE-CSR");

    apb::RegisterResponse resp;
    grpc::Status status;
    REQUIRE_NOTHROW(status = h.svc.Register(/*context=*/nullptr, &req, &resp));
    REQUIRE(status.ok());
    CHECK(resp.accepted());
    CHECK(resp.issued_certificate().empty());
}

TEST_CASE("notify_exec_tracker: RUNNING maps to status='running' with "
          "completed_at=0",
          "[pg][agent_service][executions][issue872]") {
    // RUNNING is the only non-terminal mapping in the switch — it stamps
    // first_response_at but leaves completed_at zero. A regression that
    // unifies the RUNNING and terminal branches (treating RUNNING as
    // completed) would flip executions to "done" on their first chunk.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::RUNNING,
                                                      /*output=*/"row-1");
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "running");
    CHECK(statuses[0].first_response_at > 0);
    CHECK(statuses[0].completed_at == 0);
}

TEST_CASE("process_gateway_response: the __keepalive__ sentinel renews the concurrency claim "
          "without storing a response row or tagging an SSE output line (CHAOS-TTL-1)",
          "[pg][agent_service][executions][concurrency][adr1007]") {
    // The agent's concurrency-claim keepalive thread (agents/core/src/agent.cpp)
    // sends a bare RUNNING with this exact output sentinel on a fixed interval,
    // independent of any real plugin progress — see the twin intercept in
    // process_agent_response (agent_service_impl.cpp's direct-Subscribe RUNNING
    // branch) and this function's own. It must reach notify_exec_tracker (so
    // ExecutionTracker::renew_concurrency_claim fires) but must NOT be treated
    // as a real output row.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-keepalive", exec_id);

    auto ping = GatewayResponseHarness::make_response("cmd-keepalive", apb::CommandResponse::RUNNING,
                                                       /*output=*/"__keepalive__");
    h.svc.process_gateway_response("agent-1", ping);

    // Reached notify_exec_tracker: the agent_exec_status row was touched
    // exactly as a real 'running' CommandResponse would (same assertion shape
    // as the RUNNING test just above).
    auto ka_statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(ka_statuses.size() == 1);
    CHECK(ka_statuses[0].status == "running");
    CHECK(ka_statuses[0].first_response_at > 0);
    CHECK(ka_statuses[0].completed_at == 0);

    // Did NOT reach ResponseStore::store — no row landed for the drawer/SSE.
    auto rows_opt = h.responses.query_by_execution(exec_id);
    REQUIRE(rows_opt.has_value());
    CHECK(rows_opt->empty());
}

TEST_CASE("notify_exec_tracker: the by-command concurrency-claim fallback fires end-to-end "
          "through process_gateway_response when execution_id cannot be resolved (cpp-safety "
          "Gate 8 reconciliation-review finding, PR #3784)",
          "[pg][agent_service][executions][concurrency][adr1007]") {
    // The ExecutionTracker-level test ("release_concurrency_claim_by_command /
    // renew_concurrency_claim_by_command restore claim release/renewal...",
    // test_execution_tracker.cpp) proves the fallback methods work in
    // isolation. It does NOT prove notify_exec_tracker's own decision logic
    // (the RUNNING-vs-terminal switch, the resolve_execution_id-miss branch
    // condition) actually reaches them correctly when driven through the
    // real AgentServiceImpl entry point a live agent connection uses. This
    // test closes that gap: deliberately never calls record_execution_id
    // (so resolve_execution_id genuinely misses, matching an unresolved
    // workflow-step dispatch or a correlation-table degrade), claims a slot
    // directly on the tracker, then drives real CommandResponses through
    // process_gateway_response and asserts the claim renews then releases.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};

    const int64_t now0 = std::chrono::duration_cast<std::chrono::seconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
    auto claimed = ts.tracker->claim_concurrency_slots(
        "def-fallback-e2e", "exec-unresolved", "cmd-fallback-e2e", {"agent-1"},
        /*expires_at=*/now0 + 2);
    REQUIRE(claimed.size() == 1);

    // A RUNNING response with no recorded execution_id mapping must renew
    // the claim via renew_concurrency_claim_by_command, not silently drop
    // it — proven by advancing past the SHORT original expiry and checking
    // the reconciler does NOT force-release it.
    auto running = GatewayResponseHarness::make_response(
        "cmd-fallback-e2e", apb::CommandResponse::RUNNING, /*output=*/"row-1");
    h.svc.process_gateway_response("agent-1", running);

    REQUIRE(ts.tracker->reconcile_stale_concurrency_claims(now0) == 0); // prime the anchor
    CHECK(ts.tracker->reconcile_stale_concurrency_claims(now0 + 5) == 0); // past ORIGINAL expiry
    CHECK(ts.tracker
              ->claim_concurrency_slots("def-fallback-e2e", "exec-other", "cmd-probe-1",
                                        {"agent-1"}, now0 + 100)
              .empty()); // still held — the RUNNING response renewed it

    // A terminal response with no recorded execution_id mapping must
    // release the claim via release_concurrency_claim_by_command.
    auto done = GatewayResponseHarness::make_response("cmd-fallback-e2e",
                                                       apb::CommandResponse::SUCCESS,
                                                       /*output=*/"", /*exit_code=*/0);
    h.svc.process_gateway_response("agent-1", done);

    CHECK(ts.tracker
              ->claim_concurrency_slots("def-fallback-e2e", "exec-other-2", "cmd-probe-2",
                                        {"agent-1"}, now0 + 100)
              .size() == 1); // released — a fresh claim succeeds

    // Confirms nothing leaked into the normal execution_id-resolved path
    // (no agent_exec_status row, since no execution was ever created/
    // correlated for this command_id).
    CHECK(h.responses.query_by_execution("exec-unresolved")->empty());
}

TEST_CASE("notify_exec_tracker: a __guard__- command_id short-circuits the by-command fallback "
          "before either renew or release fires (Fable adversarial-review finding, PR #3784)",
          "[pg][agent_service][executions][concurrency][adr1007]") {
    // __guard__.* dispatches are system-caller, definition-less, and can
    // never carry a per-device concurrency claim — the skip exists purely
    // to avoid a wasted write-pool lease on every guard push/reconcile
    // response. Prove it actually short-circuits: a claim taken under a
    // DIFFERENT, real command_id must survive a __guard__-prefixed
    // response arriving with no recorded execution_id mapping.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};

    auto claimed = ts.tracker->claim_concurrency_slots("def-guard-skip", "exec-unresolved-2",
                                                        "cmd-real-command", {"agent-1"},
                                                        /*expires_at=*/9999999999);
    REQUIRE(claimed.size() == 1);

    auto guard_ping = GatewayResponseHarness::make_response(
        "__guard__-reconcile-1-abc123", apb::CommandResponse::RUNNING, /*output=*/"");
    h.svc.process_gateway_response("agent-1", guard_ping);
    auto guard_terminal = GatewayResponseHarness::make_response(
        "__guard__-reconcile-1-abc123", apb::CommandResponse::SUCCESS, /*output=*/"");
    h.svc.process_gateway_response("agent-1", guard_terminal);

    // The unrelated real claim must be completely untouched by either
    // __guard__- response.
    CHECK(ts.tracker
              ->claim_concurrency_slots("def-guard-skip", "exec-other", "cmd-probe",
                                        {"agent-1"}, 9999999999)
              .empty());
}

TEST_CASE("notify_exec_tracker: SUCCESS maps to status='success' and stamps "
          "completed_at",
          "[pg][agent_service][executions][issue872]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS,
                                                      /*output=*/"", /*exit_code=*/0);
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "success");
    CHECK(statuses[0].exit_code == 0);
    CHECK(statuses[0].first_response_at > 0);
    CHECK(statuses[0].completed_at > 0);
}

TEST_CASE("notify_exec_tracker: FAILURE preserves error_detail and exit_code",
          "[pg][agent_service][executions][issue872]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::FAILURE,
                                                      /*output=*/"", /*exit_code=*/3);
    resp.mutable_error()->set_message("plugin returned non-zero");
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].status == "failure");
    CHECK(statuses[0].exit_code == 3);
    CHECK(statuses[0].error_detail == "plugin returned non-zero");
    CHECK(statuses[0].completed_at > 0);
}

TEST_CASE("notify_exec_tracker: TIMEOUT maps to status='timeout'",
          "[pg][agent_service][executions][issue872]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::TIMEOUT);
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "timeout");
    CHECK(statuses[0].first_response_at > 0);
    CHECK(statuses[0].completed_at > 0);
    // notify_exec_tracker only populates s.error_detail when resp.has_error().
    // The TIMEOUT response was constructed with no error message, so the
    // resulting column must be empty — pins the has_error()==false arm of
    // the conditional at agent_service_impl.cpp:1157 against a regression
    // that copies the field unconditionally.
    CHECK(statuses[0].error_detail.empty());
}

TEST_CASE("notify_exec_tracker: REJECTED maps to status='rejected'",
          "[pg][agent_service][executions][issue872]") {
    // notify_exec_tracker sets s.first_response_at=0 for REJECTED (the agent
    // rejected the command at dispatch, never began executing — "first
    // response" is conceptually undefined). The DB column still ends up
    // stamped to `now` because the bind layer substitutes
    // `s.first_response_at > 0 ? s.first_response_at : now`
    // (execution_tracker.cpp:363), making the struct-field zero invisible
    // to consumers.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    auto exec_id = ts.make_exec();
    h.svc.record_execution_id("cmd-A", exec_id);

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::REJECTED);
    h.svc.process_gateway_response("agent-1", resp);

    auto statuses = ts.tracker->get_agent_statuses(exec_id);
    REQUIRE(statuses.size() == 1);
    CHECK(statuses[0].agent_id == "agent-1");
    CHECK(statuses[0].status == "rejected");
    CHECK(statuses[0].completed_at > 0);
    // Both first_response_at and completed_at derive from the same
    // `system_clock::now()` snapshot inside update_agent_status — first_response_at
    // via the bind-layer substitution, completed_at via the direct bind. They
    // are written from the same instant, so they cannot legitimately diverge
    // by more than ~1 second. A regression that stops substituting `now` for
    // a zero first_response_at would land first_response_at=0 vs
    // completed_at>1e9, blowing this bound — catches the specific drift the
    // bind-layer comment above warns about, without mocking the clock.
    CHECK(statuses[0].first_response_at >= statuses[0].completed_at - 1);
    CHECK(statuses[0].first_response_at <= statuses[0].completed_at + 1);
}

TEST_CASE("notify_exec_tracker: unmapped command_id is a no-op",
          "[pg][agent_service][executions][issue872]") {
    // Out-of-band dispatch (CLI / direct gRPC) never calls record_execution_id.
    // notify_exec_tracker must early-return on empty execution_id rather than
    // upserting under a fabricated id — those rows would be invisible to every
    // tracker query (all filter by execution_id) but would still bloat the
    // table and break the documented "out-of-band = no tracker side effect"
    // contract referenced in agent_service_impl.cpp:1146.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};
    auto exec_id = ts.make_exec();
    // Deliberately do NOT call record_execution_id — cmd-orphan is unmapped.

    auto resp = GatewayResponseHarness::make_response("cmd-orphan", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    CHECK(ts.tracker->get_agent_statuses(exec_id).empty());
}

TEST_CASE("notify_exec_tracker: non-tracked correlation-id prefixes produce "
          "no tracker row (adversarial review, PR #3780)",
          "[pg][agent_service][executions][issue872]") {
    // The four non-tracked correlation-id prefixes (polchk-/bundle-/
    // preflight-/deployment-) are minted as the execution_id VALUE by
    // PolicyEvaluator/BundleOrchestrator/PreflightRunner/the deployment
    // engine, then explicitly skipped by notify_exec_tracker's
    // starts_with(...) guards (agent_service_impl.cpp) so they never
    // create a phantom agent_exec_status row or publish a phantom
    // agent-transition SSE event. test_execution_tracker.cpp proves the
    // STORE round-trips these values opaquely; THIS test proves the
    // actual DECISION SITE (notify_exec_tracker, reached only through
    // resolve_execution_id -> ExecutionTracker::lookup_execution_id, the
    // PG-backed path this PR migrated) still honours the skip — the
    // property a prior version of this PR's own test claimed to prove
    // but didn't (it looked up an unwritten key, never exercising this
    // decision site at all).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};

    for (const std::string execution_id :
         {"polchk-abc123", "bundle-def456", "preflight-run1-check2", "deployment-xyz-stage"}) {
        CAPTURE(execution_id);
        const std::string command_id = "plugin-cmd-" + execution_id;
        h.svc.record_execution_id(command_id, execution_id);

        auto resp = GatewayResponseHarness::make_response(command_id, apb::CommandResponse::SUCCESS);
        h.svc.process_gateway_response("agent-1", resp);

        CHECK(ts.tracker->get_agent_statuses(execution_id).empty());
    }
}

TEST_CASE("resolve_execution_id bumps yuzu_exec_correlation_read_degrade_total "
          "by reason (adversarial review, PR #3780)",
          "[pg][agent_service][executions]") {
    // The read-degrade counter is the only signal for a sustained lookup
    // failure on this hot path (hit on every CommandResponse) — mirrors
    // test_software_inventory_store.cpp's "read-degrade bumps
    // yuzu_inventory_read_degrade_total by reason (#1675)" precedent.
    // Dropping the command_execution table under the open store forces a
    // genuine query_failed on the next lookup (not a coincidental
    // pool-exhaustion path).
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    TrackerScope ts{h.svc, pool};

    h.svc.record_execution_id("cmd-A", "exec-42"); // a mapping DOES exist...

    {
        auto lease = pool.acquire();
        REQUIRE(lease);
        auto drop = pg::exec_params(lease.get(),
                                    "DROP TABLE execution_tracker.command_execution",
                                    std::vector<std::string>{});
        REQUIRE(drop.status() == PGRES_COMMAND_OK);
    }

    // ...but the lookup can no longer reach it.
    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS);
    h.svc.process_gateway_response("agent-1", resp);

    // A terminal response resolves execution_id from TWO independent call
    // sites (response-store stamping at agent_service_impl.cpp:1577, then
    // again inside notify_exec_tracker at :1606) — both hit the dropped
    // table, so the counter increments twice per response, not once.
    CHECK(h.metrics
              .counter("yuzu_exec_correlation_read_degrade_total", {{"reason", "query_failed"}})
              .value() == 2.0);
}

TEST_CASE("notify_exec_tracker: null tracker pointer is a no-op (shutdown contract)",
          "[pg][agent_service][executions][issue872]") {
    // The atomic-load-acquire in notify_exec_tracker is the read half of the
    // shutdown contract — ServerImpl drains gRPC, calls
    // set_execution_tracker(nullptr) with release ordering, then resets the
    // owning unique_ptr. A refactor that drops the null guard (e.g. assumes
    // tracker stays non-null once set) would crash in the shutdown window.
    // Pinned explicitly via the set→unset path, not just the never-set path
    // every other GatewayResponseHarness test exercises implicitly.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    {
        TrackerScope ts{h.svc, pool};
        // ~TrackerScope calls set_execution_tracker(nullptr) before destroying
        // the tracker, leaving svc.execution_tracker_ at nullptr.
    }
    h.svc.record_execution_id("cmd-A", "exec-42");

    auto resp = GatewayResponseHarness::make_response("cmd-A", apb::CommandResponse::SUCCESS);
    // Must not crash, must not dereference the destroyed tracker.
    h.svc.process_gateway_response("agent-1", resp);
}

// ── #1067 — admin-denied agent must NOT consume an enrollment token ─────────

TEST_CASE("Register: admin-denied agent does not consume the enrollment token (#1067)",
          "[pg][agent_service][register][enrollment][issue1067]") {
    // W1.4 UP-M3: the consume happened BEFORE the admin-deny check, so a denied
    // attacker burned a use of the token on every attempt — depleting a
    // max_uses=1 token until the legitimate agent could no longer enroll. The
    // early PendingStatus::denied check pre-empts the consume.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    auto raw =
        h.auth_mgr.create_enrollment_token("dos-test", /*max_uses=*/1, std::chrono::hours(1));

    // Mark the attacker's agent_id admin-denied.
    h.auth_mgr.add_pending_agent("denied-agent", "evil-host", "linux", "x86_64", "0.0.0-test");
    REQUIRE(h.auth_mgr.deny_pending_agent("denied-agent"));
    REQUIRE(h.auth_mgr.get_pending_status("denied-agent") ==
            yuzu::server::auth::PendingStatus::denied);

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("denied-agent");
    req.mutable_info()->set_hostname("evil-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(raw);

    apb::RegisterResponse resp;
    auto status = h.svc.Register(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "denied");
    // gov #1134: the denied rejection emits the bounded SIEM-routed counter.
    CHECK(h.metrics
              .counter("yuzu_register_denied_total",
                       {{"source", "direct"}, {"event", "security"}})
              .value() == 1.0);

    // Core invariant: the denied attempt did NOT consume the token.
    auto tokens = h.auth_mgr.list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 0);

    // And the single use is still available to a legitimate agent — proving the
    // max_uses=1 token was not depleted by the denied attacker.
    auto claim = h.auth_mgr.consume_enrollment_token(raw, "good-agent");
    CHECK(claim.has_value());
}

// ── #1065 — success-path enrollment audit is emitted (was fire-and-forget) ──

TEST_CASE("Register: successful token enrollment emits a success audit row (#1065)",
          "[pg][agent_service][register][enrollment][audit][issue1065]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    auto raw =
        h.auth_mgr.create_enrollment_token("ok-test", /*max_uses=*/1, std::chrono::hours(1));

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("enroll-ok");
    req.mutable_info()->set_hostname("good-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.mutable_info()->set_agent_version("0.0.0-test");
    req.set_enrollment_token(raw);

    apb::RegisterResponse resp;
    REQUIRE(h.svc.Register(/*context=*/nullptr, &req, &resp).ok());
    CHECK(resp.accepted());

    // The success-path audit row is now captured + persisted (#1065). Find it
    // by its stable fields rather than the action constant.
    auto rows = h.audit->query({});
    REQUIRE(rows.has_value());
    bool found = false;
    for (const auto& ev : *rows) {
        if (ev.action == "enrollment.token_consumed" && ev.result == "success" &&
            ev.principal == "agent:enroll-ok" && ev.target_type == "enrollment_token") {
            found = true;
            break;
        }
    }
    CHECK(found);
}

TEST_CASE("ProxyRegister: admin-denied agent does not consume the enrollment token (#1067)",
          "[pg][agent_service][register][enrollment][gateway][issue1067]") {
    // Sibling of the direct-Register #1067 test. The gateway ProxyRegister path
    // proxies the agent's RegisterRequest unmodified and had the same
    // consume-before-deny ordering — so the token-depletion DoS was equally
    // reachable here until the early PendingStatus::denied check was mirrored.
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    gateway_svc.set_audit_store(h.audit.get());
    auto raw =
        h.auth_mgr.create_enrollment_token("gw-dos-test", /*max_uses=*/1, std::chrono::hours(1));
    h.auth_mgr.add_pending_agent("gw-denied", "evil-host", "linux", "x86_64", "0.0.0-test");
    REQUIRE(h.auth_mgr.deny_pending_agent("gw-denied"));

    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("gw-denied");
    req.mutable_info()->set_hostname("evil-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token(raw);

    apb::RegisterResponse resp;
    auto status = gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp);

    REQUIRE(status.ok());
    CHECK_FALSE(resp.accepted());
    CHECK(resp.enrollment_status() == "denied");
    CHECK(h.metrics
              .counter("yuzu_register_denied_total",
                       {{"source", "gateway_proxy"}, {"event", "security"}})
              .value() == 1.0);
    auto tokens = h.auth_mgr.list_enrollment_tokens();
    REQUIRE(tokens.size() == 1);
    CHECK(tokens[0].use_count == 0); // token not depleted via the gateway path

    // The single use is still available — proving non-depletion via the gateway
    // path too (symmetry with the direct-Register #1067 test).
    auto gw_claim = h.auth_mgr.consume_enrollment_token(raw, "good-gw-agent");
    CHECK(gw_claim.has_value());
}

// ── #1064 — ProxyRegister origin-IP attribution ─────────────────────────────

TEST_CASE("ProxyRegister: audit attributes the agent origin IP, not the gateway IP (#1064)",
          "[pg][agent_service][register][enrollment][gateway][issue1064]") {
    using yuzu::server::detail::GatewayUpstreamServiceImpl;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    GatewayUpstreamServiceImpl gateway_svc{h.registry, h.bus, h.auth_mgr, h.auto_approve,
                                           &h.metrics};
    gateway_svc.set_audit_store(h.audit.get());

    // An INVALID enrollment token drives the denied/failure audit site — where
    // the #1064 attribution records source_ip=agent origin + gateway_ip in
    // detail. context is nullptr (as in every ProxyRegister test) so the gateway
    // transport IP is empty; the attribution then comes ENTIRELY from
    // gateway_observed_peer, making the agent-vs-gateway distinction observable.
    apb::RegisterRequest req;
    req.mutable_info()->set_agent_id("gw-origin-test");
    req.mutable_info()->set_hostname("agent-host");
    req.mutable_info()->mutable_platform()->set_os("linux");
    req.mutable_info()->mutable_platform()->set_arch("x86_64");
    req.set_enrollment_token("no-such-token-xyz");
    apb::RegisterResponse resp;

    auto failure_row = [&]() -> yuzu::server::AuditEvent {
        auto rows = h.audit->query({});
        REQUIRE(rows.has_value());
        for (const auto& ev : *rows) {
            if (ev.result == "failure")
                return ev;
        }
        return {};
    };

    SECTION("origin observed → source_ip is the agent IP, not the gateway") {
        req.set_gateway_observed_peer("203.0.113.7");
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        CHECK_FALSE(resp.accepted());
        const auto row = failure_row();
        CHECK(row.source_ip == "203.0.113.7"); // agent origin — the core attribution proof
        // gateway_ip key is always recorded; its VALUE is empty here only
        // because the test passes context=nullptr (no transport peer). With a
        // real context it would carry the gateway's IP. source_ip above is the
        // assertion that proves agent-origin vs gateway attribution.
        CHECK(row.detail.find("gateway_ip=") != std::string::npos);
        CHECK(row.detail.find("origin_observed=false") == std::string::npos);
    }

    SECTION("origin absent → falls back to gateway IP, flagged origin_observed=false") {
        // No gateway_observed_peer set; null context → gateway IP empty.
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        const auto row = failure_row();
        CHECK(row.source_ip.empty()); // gateway-IP fallback (empty under null ctx)
        CHECK(row.detail.find("origin_observed=false") != std::string::npos);
    }

    SECTION("malformed origin is rejected by the strict parser → fallback") {
        // A non-IP value (incl. an injection attempt) must NOT round-trip into
        // the audit row — normalize_bare_ip returns empty, so we fall back.
        req.set_gateway_observed_peer("1.2.3.4; rm -rf /");
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        const auto row = failure_row();
        CHECK(row.source_ip.empty());
        CHECK(row.detail.find("origin_observed=false") != std::string::npos);
        CHECK(row.detail.find("rm -rf") == std::string::npos); // no junk in evidence
    }

    SECTION("success path also attributes the agent origin (gov QE SHOULD)") {
        // The success audit site (valid token → accepted) shares append_origin_detail.
        auto raw = h.auth_mgr.create_enrollment_token("gw-origin-test", /*max_uses=*/1,
                                                      std::chrono::hours(1));
        req.set_enrollment_token(raw);
        req.set_gateway_observed_peer("203.0.113.9");
        REQUIRE(gateway_svc.ProxyRegister(/*context=*/nullptr, &req, &resp).ok());
        CHECK(resp.accepted());
        yuzu::server::AuditEvent success_row;
        auto success_rows = h.audit->query({});
        REQUIRE(success_rows.has_value());
        for (const auto& ev : *success_rows) {
            if (ev.result == "success")
                success_row = ev;
        }
        CHECK(success_row.source_ip == "203.0.113.9"); // agent origin on the success row too
        CHECK(success_row.detail.find("gateway_ip=") != std::string::npos);
    }
}

// ── PR3 trust gate: Register CSR-signing callback boundary (#1239 B-2) ──────────
//
// These pin the `agent_cert_signer_` callback at the service-layer enforcement
// boundary — that the Register handler invokes the signer ONLY for an approved
// enrollment that carries a CSR, forwards the raw CSR plus the SERVER-chosen
// agent_id (never a CSR-derived identity), and degrades cleanly when signing is
// unavailable. (The revocation gate and `peer_cert_recognizer_` fire only on a
// PRESENTED client leaf, which requires a real TLS auth context that a unit test
// cannot synthesise — those are exercised by the live boot-test and, for the
// revocation predicate itself, by the sweep tests below + the ca_store
// revocation round-trip. The recognizer's crypto core is covered by
// test_x509_ca's verify_chain cases.)

namespace {

apb::RegisterRequest make_register(const std::string& agent_id, const std::string& csr_pem = "") {
    apb::RegisterRequest req;
    auto* info = req.mutable_info();
    info->set_agent_id(agent_id);
    info->set_hostname("host-" + agent_id);
    info->mutable_platform()->set_os("linux");
    info->mutable_platform()->set_arch("x64");
    info->set_agent_version("0.13.0");
    if (!csr_pem.empty())
        req.set_csr_pem(csr_pem);
    return req;
}

// Match-all auto-approve so a token-less Register falls through to the accept
// (and therefore the CSR-signing) path deterministically.
void install_match_all_auto_approve(GatewayResponseHarness& h) {
    h.auto_approve.add_rule({yuzu::server::auth::AutoApproveRuleType::hostname_glob, "*",
                             "match-all (test)", /*enabled=*/true});
}

} // namespace

TEST_CASE("Register: approved CSR reaches the signer with the authenticated agent_id (B-2)",
          "[pg][agent_service][pki][pr3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    install_match_all_auto_approve(h);

    std::string seen_csr, seen_agent_id;
    int signer_calls = 0;
    h.svc.set_agent_cert_signer(
        [&](const std::string& csr, const std::string& agent_id,
            yuzu::server::CertIssuanceSource) -> std::optional<std::pair<std::string, std::string>> {
            ++signer_calls;
            seen_csr = csr;
            seen_agent_id = agent_id;
            return std::make_pair(std::string("LEAF-PEM"), std::string("CHAIN-PEM"));
        });

    grpc::ServerContext ctx;
    // The CSR blob deliberately "claims" a different identity; the service layer
    // must hand the signer the AUTHENTICATED agent_id (the signer is what stamps
    // CN), never anything derived from attacker-controlled CSR bytes.
    auto req = make_register("agent-real", "CSR-claiming-to-be-agent-evil");
    apb::RegisterResponse resp;
    auto st = h.svc.Register(&ctx, &req, &resp);

    REQUIRE(st.ok());
    REQUIRE(resp.accepted());
    REQUIRE(signer_calls == 1);
    REQUIRE(seen_csr == "CSR-claiming-to-be-agent-evil"); // raw CSR forwarded verbatim
    REQUIRE(seen_agent_id == "agent-real");               // server identity, not the CSR's
    REQUIRE(resp.issued_certificate() == "LEAF-PEM");
    REQUIRE(resp.issued_ca_chain() == "CHAIN-PEM");
}

TEST_CASE("Register: signer returning nullopt leaves the agent accepted but cert-less (B-2)",
          "[pg][agent_service][pki][pr3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    install_match_all_auto_approve(h);
    int signer_calls = 0;
    h.svc.set_agent_cert_signer(
        [&](const std::string&, const std::string&,
            yuzu::server::CertIssuanceSource) -> std::optional<std::pair<std::string, std::string>> {
            ++signer_calls;
            return std::nullopt; // signing unavailable / failed
        });

    grpc::ServerContext ctx;
    auto req = make_register("agent-x", "SOME-CSR");
    apb::RegisterResponse resp;
    auto st = h.svc.Register(&ctx, &req, &resp);

    REQUIRE(st.ok());
    REQUIRE(resp.accepted()); // signing failure is non-fatal: agent stays on bootstrap posture
    REQUIRE(signer_calls == 1);
    REQUIRE(resp.issued_certificate().empty());
    REQUIRE(resp.issued_ca_chain().empty());
}

TEST_CASE("Register: a pending (unapproved) enrollment never reaches the CSR signer (B-2)",
          "[pg][agent_service][pki][pr3][security]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    // No auto-approve rule + no token → the agent lands in the pending queue and
    // Register returns BEFORE the signing block. A CSR must NOT be signed for an
    // agent the operator has not approved.
    bool signer_called = false;
    h.svc.set_agent_cert_signer(
        [&](const std::string&, const std::string&,
            yuzu::server::CertIssuanceSource) -> std::optional<std::pair<std::string, std::string>> {
            signer_called = true;
            return std::make_pair(std::string("X"), std::string("Y"));
        });

    grpc::ServerContext ctx;
    auto req = make_register("agent-pending", "A-CSR");
    apb::RegisterResponse resp;
    auto st = h.svc.Register(&ctx, &req, &resp);

    REQUIRE(st.ok());
    REQUIRE_FALSE(resp.accepted());
    REQUIRE(resp.enrollment_status() == "pending");
    REQUIRE_FALSE(signer_called);
    REQUIRE(resp.issued_certificate().empty());
}

TEST_CASE("Register: no CSR → signer is not invoked even when wired (B-2)",
          "[pg][agent_service][pki][pr3]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);
    install_match_all_auto_approve(h);
    bool signer_called = false;
    h.svc.set_agent_cert_signer(
        [&](const std::string&, const std::string&,
            yuzu::server::CertIssuanceSource) -> std::optional<std::pair<std::string, std::string>> {
            signer_called = true;
            return std::make_pair(std::string("X"), std::string("Y"));
        });

    grpc::ServerContext ctx;
    auto req = make_register("agent-nocsr"); // CSR omitted
    apb::RegisterResponse resp;
    auto st = h.svc.Register(&ctx, &req, &resp);

    REQUIRE(st.ok());
    REQUIRE(resp.accepted());
    REQUIRE_FALSE(signer_called);
    REQUIRE(resp.issued_certificate().empty());
}

// ── PR3 H-1: revocation sweep tears down live Subscribe streams (#1239 H-1) ─────
//
// The establishment gate checks revocation once; sweep_revoked() is the
// mechanism that re-evaluates a long-lived stream so a revoked/compromised agent
// stops receiving dispatched commands without waiting for a voluntary reconnect.
// Driving it directly (with a spy predicate standing in for is_peer_cert_revoked)
// exercises the revocation_checker_ decision boundary that the gRPC entry points
// cannot in a unit test.

namespace {

apb::AgentInfo make_agent_info(const std::string& agent_id) {
    apb::AgentInfo info;
    info.set_agent_id(agent_id);
    info.set_hostname("host-" + agent_id);
    info.mutable_platform()->set_os("linux");
    info.mutable_platform()->set_arch("x64");
    info.set_agent_version("0.13.0");
    return info;
}

} // namespace

TEST_CASE("AgentRegistry::sweep_revoked cancels only the revoked, cert-bearing streams (H-1)",
          "[agent_service][pki][pr3][revocation]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};

    (void)registry.register_agent(make_agent_info("agent-good"));
    (void)registry.register_agent(make_agent_info("agent-bad"));
    (void)registry.register_agent(make_agent_info("agent-nocert"));

    // Two contexts stand in for live Subscribe streams; TryCancel on a context
    // with no underlying call is a safe no-op (grpc_call_cancel_with_status
    // returns GRPC_CALL_ERROR on a null call), so the sweep logic is exercised
    // without a real RPC.
    grpc::ServerContext ctx_good, ctx_bad, ctx_nocert;
    registry.set_stream("agent-good", nullptr, &ctx_good, "PEM-GOOD");
    registry.set_stream("agent-bad", nullptr, &ctx_bad, "PEM-BAD");
    // No client cert presented → nothing to evaluate, must be skipped.
    registry.set_stream("agent-nocert", nullptr, &ctx_nocert, /*peer_cert_pem=*/"");

    std::vector<std::string> seen;
    auto is_revoked = [&](const std::string& pem) {
        seen.push_back(pem);
        return pem == "PEM-BAD";
    };

    const auto cancelled = registry.sweep_revoked(is_revoked);
    REQUIRE(cancelled.size() == 1);          // only agent-bad
    REQUIRE(cancelled.front() == "agent-bad"); // and it is reported for auditing

    // The predicate saw exactly the two cert-bearing PEMs (order-independent);
    // the no-cert session was never offered to it.
    REQUIRE(seen.size() == 2);
    REQUIRE(std::find(seen.begin(), seen.end(), "PEM-GOOD") != seen.end());
    REQUIRE(std::find(seen.begin(), seen.end(), "PEM-BAD") != seen.end());
    REQUIRE(std::find(seen.begin(), seen.end(), "") == seen.end());
}

TEST_CASE("AgentRegistry::sweep_revoked is a no-op for a null predicate or no revocations (H-1)",
          "[agent_service][pki][pr3][revocation]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    (void)registry.register_agent(make_agent_info("agent-1"));
    grpc::ServerContext ctx;
    registry.set_stream("agent-1", nullptr, &ctx, "PEM-1");

    REQUIRE(registry.sweep_revoked(nullptr).empty()); // null predicate → no work
    REQUIRE(registry.sweep_revoked([](const std::string&) { return false; }).empty()); // none revoked
}

TEST_CASE("AgentRegistry::sweep_revoked skips a session whose stream has been cleared (H-1)",
          "[agent_service][pki][pr3][revocation]") {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    (void)registry.register_agent(make_agent_info("agent-1"));
    grpc::ServerContext ctx;
    registry.set_stream("agent-1", nullptr, &ctx, "PEM-1");
    registry.clear_stream("agent-1"); // disconnect → context + pem cleared

    int calls = 0;
    const auto cancelled = registry.sweep_revoked([&](const std::string&) {
        ++calls;
        return true;
    });
    REQUIRE(cancelled.empty()); // no live stream to tear down
    REQUIRE(calls == 0);        // a cleared session is never offered to the predicate
}

TEST_CASE("AgentRegistry::sweep_revoked does NOT cancel a stream whose cert changed "
          "during the off-lock check (H-1 re-check race)",
          "[agent_service][pki][pr3][revocation]") {
    // The predicate runs off stream_mu (it reads ca.db); teardown re-acquires the
    // lock and re-verifies the stored PEM is unchanged. Simulate a reconnection
    // that swaps in a FRESH (non-revoked) leaf between capture and teardown by
    // having the predicate itself mutate the session via set_stream. The sweep
    // must then skip the cancel (the cert it judged revoked is no longer mounted).
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    (void)registry.register_agent(make_agent_info("agent-1"));
    grpc::ServerContext ctx_old, ctx_new;
    registry.set_stream("agent-1", nullptr, &ctx_old, "PEM-OLD");

    int calls = 0;
    auto is_revoked = [&](const std::string& pem) {
        ++calls;
        // First (and only) call: the captured PEM is the revoked one. Before we
        // return true, a "reconnection" swaps in a different, non-revoked leaf.
        if (pem == "PEM-OLD")
            registry.set_stream("agent-1", nullptr, &ctx_new, "PEM-NEW");
        return true; // claim everything revoked — only the re-check should save it
    };

    const auto cancelled = registry.sweep_revoked(is_revoked);
    REQUIRE(calls == 1);          // evaluated the originally-captured leaf
    REQUIRE(cancelled.empty());   // but the re-check saw PEM-NEW != PEM-OLD → no cancel
}

// ── #3261: notification/webhook/offload emission with wired stores ────────
//
// #3261 fixed a boot-wiring bug where the three set_notification_store /
// set_webhook_store / set_offload_target_store calls in ServerImpl's
// constructor ran before their stores were constructed, so the guards were
// guaranteed-false and every AgentServiceImpl emission on these three paths
// (Register, Subscribe, process_gateway_response) was silently dead. The
// source-scan regression guard (test_store_wiring_order.cpp) proves the
// ORDERING is now correct; these two tests prove the RECEIVING MACHINERY
// actually works once wired, driving process_gateway_response end-to-end
// into real (SQLite in-memory / PG-templated) stores.

namespace {

/// Minimal harness: a real AgentServiceImpl with no stores wired at
/// construction. process_gateway_response's response_store_/analytics_store_/
/// notification_store_/webhook_store_/offload_target_store_/
/// execution_tracker_ branches are all independently null-guarded
/// (agent_service_impl.cpp), so a bare AgentServiceImpl by itself needs no
/// PG dependency — EventSinkScope below is what actually pulls one in now
/// that WebhookStore is Postgres-backed (ADR-0057); every TEST_CASE that
/// constructs one is tagged [pg].
struct BareServiceHarness {
    yuzu::MetricsRegistry metrics;
    EventBus bus;
    AgentRegistry registry{bus, metrics};
    yuzu::server::auth::AuthManager auth_mgr;
    yuzu::server::auth::AutoApproveEngine auto_approve;
    AgentServiceImpl svc{registry,
                         bus,
                         /*require_client_identity=*/false,
                         auth_mgr,
                         auto_approve,
                         metrics,
                         /*gateway_mode=*/false};
};

/// MEMBER ORDER LOAD-BEARING, same contract as TrackerScope above: the dtor
/// must null both borrowed-pointer setters before the stores it borrowed
/// from destruct. #3261 governance hardening: WebhookStore/OffloadTargetStore
/// now dispatch deliveries through a bounded StoreWorkerPool instead of a
/// raw detached std::thread (store_worker_pool.hpp), so this scope's dtor
/// calls quiesce() before reset() below — a real, bounded guarantee that no
/// delivery thread is still touching the store, not merely an inference
/// from every test polling get_deliveries() to completion first (which was
/// the whole story before the pool existed, and left a narrow gap if a
/// REQUIRE failed mid-poll and unwound straight into this destructor).
struct EventSinkScope {
    // Both self-contained (skip-if-no-PG, own their own ephemeral DB/keys
    // dir) — see test_webhook_store_pg_helper.hpp /
    // test_offload_target_store_pg_helper.hpp. Declared FIRST so they
    // destruct LAST (reverse declaration order): harmless either way since
    // webhooks and offloads share no state, but matches each shared
    // helper's own "declare before what borrows it" convention.
    yuzu::test::WebhookStorePg webhooks;
    yuzu::test::OffloadTargetStorePg offloads;
    AgentServiceImpl* svc{nullptr};

    explicit EventSinkScope(AgentServiceImpl& s) : svc(&s) {
        svc->set_webhook_store(webhooks.get());
        svc->set_offload_target_store(offloads.get());
    }
    ~EventSinkScope() {
        if (svc) {
            svc->set_webhook_store(nullptr);
            svc->set_offload_target_store(nullptr);
        }
        // #3261 governance hardening (cpp-expert SHOULD, Gate 3): the old
        // version of this comment argued destruction was safe because
        // every test using this scope polls get_deliveries() to
        // completion first — true on the success path, but a REQUIRE
        // failure mid-poll unwinds straight into this destructor with a
        // detached delivery thread potentially still in flight. quiesce()
        // makes that argument unconditional instead of relying on test
        // discipline: it blocks (bounded) until every queued/in-flight
        // delivery on the pool has actually finished, so reset() below is
        // always safe regardless of how this scope exits.
        webhooks->quiesce(std::chrono::seconds(5));
        offloads->quiesce(std::chrono::seconds(5));
        // webhooks (WebhookStorePg) and offloads (OffloadTargetStorePg)
        // both destruct after this body returns, via their own member
        // order — no explicit .reset() available/needed (they are value
        // members, not unique_ptr).
    }

    EventSinkScope(const EventSinkScope&) = delete;
    EventSinkScope& operator=(const EventSinkScope&) = delete;
};

/// Poll `get` (a `get_deliveries`-shaped callable) up to 5s for at least
/// `min_count` results — matches the deterministic-without-a-fixed-sleep
/// idiom already established for detached delivery threads in
/// test_offload_target_store.cpp's batch_size test. Default `min_count=1`
/// preserves the original "wait for non-empty" behavior for existing
/// callers; a caller re-polling after a second delivery (e.g. a reconnect
/// firing a second `agent.registered`) passes 2 so it does not observe a
/// stale still-size-1 result and stop waiting too early.
template <typename Get>
auto poll_deliveries(Get get, std::size_t min_count = 1) {
    constexpr auto kPollDeadline = std::chrono::seconds(5);
    auto start = std::chrono::steady_clock::now();
    decltype(get()) rows;
    while (std::chrono::steady_clock::now() - start < kPollDeadline) {
        rows = get();
        if (rows.size() >= min_count)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return rows;
}

} // namespace

TEST_CASE("process_gateway_response: wired webhook + offload sinks receive "
          "execution.completed (#3261)",
          "[pg][agent_service][issue3261]") {
    BareServiceHarness h;
    EventSinkScope sinks(h.svc);

    auto wh_id_result =
        sinks.webhooks->create_webhook("http://127.0.0.1:1/hook", "execution.completed", "s3cret");
    REQUIRE(wh_id_result.has_value());
    auto wh_id = *wh_id_result;
    REQUIRE(wh_id > 0);
    // batch_size=2 so the single event fired below buffers deterministically
    // instead of dispatching immediately (test_offload_target_store.cpp's
    // batch_size>1 idiom) — proves fire_event ran without racing a
    // detached-thread dispatch.
    auto off_result = sinks.offloads->create_target(
        "t1", "http://127.0.0.1:1/off", OffloadAuthType::None, "", "execution.completed",
        /*batch_size=*/2);
    REQUIRE(off_result.has_value());
    auto off_id = *off_result;

    auto resp = GatewayResponseHarness::make_response("cmd-hook-1", apb::CommandResponse::SUCCESS,
                                                        /*output=*/"done", /*exit_code=*/0);
    h.svc.process_gateway_response("agent-1", resp);

    // Buffered, not yet dispatched.
    CHECK(sinks.offloads->get_deliveries(off_id).empty());
    sinks.offloads->flush_all();

    // Neither sink is touched again after this point in this test case, so
    // quiesce() (a real CV-based wait, not a timing assumption) is safe
    // here — PR review finding (important): the sleep_for+poll idiom
    // poll_deliveries() below implements is genuinely necessary at LATER,
    // multi-delivery call sites (e.g. the reauth test), where quiesce()
    // would permanently close the pool before a second delivery could
    // ever fire — but was unnecessary at this first-use site.
    REQUIRE(sinks.offloads->quiesce(std::chrono::seconds(5)));
    REQUIRE(sinks.webhooks->quiesce(std::chrono::seconds(5)));

    auto off_deliveries = sinks.offloads->get_deliveries(off_id);
    REQUIRE(off_deliveries.size() == 1);
    CHECK(off_deliveries[0].event_count == 1);
    CHECK(off_deliveries[0].payload.find("execution.completed") != std::string::npos);
    CHECK(off_deliveries[0].payload.find("cmd-hook-1") != std::string::npos);

    auto wh_deliveries = sinks.webhooks->get_deliveries(wh_id);
    REQUIRE(wh_deliveries.size() == 1);
    CHECK(wh_deliveries[0].event_type == "execution.completed");
    CHECK(wh_deliveries[0].payload.find("cmd-hook-1") != std::string::npos);
    CHECK(wh_deliveries[0].payload.find("agent-1") != std::string::npos);
}

namespace {

// NotificationStore is Postgres-backed (ADR-0006 Wave 2) — shares the
// "notifstore" template key with test_notification_store.cpp (identical
// setup: construct-and-scope-destruct a single NotificationStore).
yuzu::test::PgTestTemplate notif_tpl{"notifstore", [](const std::string& dsn) {
                                         PgPool pool{{.conninfo = dsn, .size = 1}};
                                         NotificationStore store{pool};
                                         if (!store.is_open())
                                             throw std::runtime_error(
                                                 "notification template: store failed to migrate");
                                     }};

/// Same drain -> null -> reset discipline as TrackerScope/EventSinkScope
/// above, for a NotificationStore already cloned from notif_tpl by the
/// caller (mirrors GatewayResponseHarness's own PgPool-by-reference shape).
struct NotificationScope {
    std::unique_ptr<NotificationStore> store;
    AgentServiceImpl* svc{nullptr};

    NotificationScope(AgentServiceImpl& s, pg::PgPool& pool) : svc(&s) {
        store = std::make_unique<NotificationStore>(pool);
        REQUIRE(store->is_open());
        svc->set_notification_store(store.get());
    }
    ~NotificationScope() {
        if (svc)
            svc->set_notification_store(nullptr);
        store.reset();
    }

    NotificationScope(const NotificationScope&) = delete;
    NotificationScope& operator=(const NotificationScope&) = delete;
};

} // namespace

TEST_CASE("process_gateway_response: wired notification store receives an "
          "Execution Failed row on a non-SUCCESS response (#3261)",
          "[pg][agent_service][issue3261]") {
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    GatewayResponseHarness h(pool);

    YUZU_REQUIRE_PG_DB_TPL(ndb, notif_tpl);
    PgPool npool{{.conninfo = ndb.dsn(), .size = 4}};
    NotificationScope nscope(h.svc, npool);

    apb::CommandResponse resp;
    resp.set_command_id("cmd-fail-1");
    resp.set_status(apb::CommandResponse::FAILURE);
    resp.mutable_error()->set_message("boom");
    h.svc.process_gateway_response("agent-9", resp);

    auto rows = nscope.store->list_all();
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].level == "error");
    CHECK(rows[0].title == "Execution Failed");
    CHECK(rows[0].message.find("cmd-fail-1") != std::string::npos);
    CHECK(rows[0].message.find("agent-9") != std::string::npos);
    CHECK(rows[0].message.find("boom") != std::string::npos);
}

// ── #3261 governance hardening (Gate 3 quality-engineer SHOULD) ────────────
//
// The two TEST_CASEs above exercise process_gateway_response's wiring but
// never Register/Subscribe's own notification/webhook/offload logic — which,
// being downstream of the SAME construction-order bug, had never executed
// in any test or production boot until #3261's fix. This closes that gap,
// and doubles as the regression test for the reauth-suppression fix
// (agent_service_impl.cpp Register handler): "Agent Enrolled" must fire
// once, on first enrollment only; `agent.registered` webhook/offload must
// fire on EVERY Register, including a reconnect, per the documented
// contract (docs/user-manual/rest-api.md's webhook/offload sections).

TEST_CASE("Register: notification fires once on first enrollment; webhook/offload "
          "fire again on a reconnect (#3261)",
          "[pg][agent_service][issue3261]") {
    YUZU_REQUIRE_PG_DB_TPL(ndb, notif_tpl);
    PgPool npool{{.conninfo = ndb.dsn(), .size = 4}};

    BareServiceHarness h;
    h.auto_approve.add_rule({yuzu::server::auth::AutoApproveRuleType::hostname_glob, "*",
                             "match-all (test)", /*enabled=*/true});
    EventSinkScope sinks(h.svc);
    NotificationScope nscope(h.svc, npool);

    auto wh_id_result =
        sinks.webhooks->create_webhook("http://127.0.0.1:1/hook", "agent.registered", "");
    REQUIRE(wh_id_result.has_value());
    auto wh_id = *wh_id_result;
    REQUIRE(wh_id > 0);
    auto off_result = sinks.offloads->create_target("t1", "http://127.0.0.1:1/off",
                                                    OffloadAuthType::None, "", "agent.registered",
                                                    /*batch_size=*/1);
    REQUIRE(off_result.has_value());
    auto off_id = *off_result;

    auto req = make_register("reauth-test-agent");

    // First Register: genuinely new agent.
    apb::RegisterResponse resp1;
    REQUIRE(h.svc.Register(/*context=*/nullptr, &req, &resp1).ok());
    REQUIRE(resp1.accepted());

    auto notifs = nscope.store->list_all();
    REQUIRE(notifs.size() == 1);
    CHECK(notifs[0].title == "Agent Enrolled");
    CHECK(notifs[0].message.find("reauth-test-agent") != std::string::npos);

    auto wh_after_first = poll_deliveries([&] { return sinks.webhooks->get_deliveries(wh_id); });
    REQUIRE(wh_after_first.size() == 1);
    auto off_after_first =
        poll_deliveries([&] { return sinks.offloads->get_deliveries(off_id); });
    REQUIRE(off_after_first.size() == 1);

    // Second Register with the SAME agent_id: a reconnect.
    // auth_mgr_.get_pending_status() now returns approved, so is_reauth
    // becomes true inside Register.
    apb::RegisterResponse resp2;
    REQUIRE(h.svc.Register(/*context=*/nullptr, &req, &resp2).ok());

    // Notification: unchanged. A regression here (the pre-#3261-fix shape,
    // just newly visible) would flood the unreaper'd notification feed on
    // every fleet-wide restart (Gate 4 happy-path/unhappy-path UP-3).
    auto notifs_after_reauth = nscope.store->list_all();
    CHECK(notifs_after_reauth.size() == 1);

    // Webhook/offload: DO fire again, matching the documented contract.
    auto wh_after_reauth =
        poll_deliveries([&] { return sinks.webhooks->get_deliveries(wh_id); }, /*min_count=*/2);
    CHECK(wh_after_reauth.size() == 2);
    auto off_after_reauth =
        poll_deliveries([&] { return sinks.offloads->get_deliveries(off_id); }, /*min_count=*/2);
    CHECK(off_after_reauth.size() == 2);
}

// ── Metric: all 6 webhook/offload delivery counters pre-seeded to 0 ────────
//
// Mirrors server.cpp's ServerImpl constructor pre-seed block (the six
// metrics_.counter(name) calls right after the six describe() calls,
// server.cpp:~1614-1633) — same pattern as
// test_principal_quota_chokepoint.cpp's preseed_quota_metric() helper.
// Regression guard for the adversarial-review round-2 fix (bf5582461):
// describe() alone only writes HELP/TYPE metadata, it does not materialize
// a series, so before that fix a fresh server exposed none of these six
// series until the first delivery incremented one - breaking absent()-based
// alerting. This test does not construct a real ServerImpl (too heavyweight
// for a unit test); it exercises the exact same describe()+counter() calls
// against a bare MetricsRegistry.
TEST_CASE("Webhook/offload delivery counters: all 6 pre-seeded to 0 at boot",
          "[agent_service][issue3261][metrics]") {
    yuzu::MetricsRegistry reg;
    const char* names[] = {"yuzu_server_webhook_delivery_success_total",
                           "yuzu_server_webhook_delivery_failed_total",
                           "yuzu_server_webhook_delivery_dropped_total",
                           "yuzu_server_offload_delivery_success_total",
                           "yuzu_server_offload_delivery_failed_total",
                           "yuzu_server_offload_delivery_dropped_total"};
    for (const char* name : names) {
        reg.describe(name, "test", "counter");
        reg.counter(name);
    }
    for (const char* name : names) {
        CHECK(reg.counter(name).value() == 0.0);
    }
}

TEST_CASE("typed_inventory_sources: app_usage is a typed source (PR7b.3 guard)",
          "[server][inventory][typed]") {
    // Pins the byte-identical hunk this package and ws-7b2's p2.2 both add to
    // typed_inventory_sources.hpp — a distinct TEST_CASE name from ws-7b2's
    // own gateway-composition case so both survive the trivial merge when
    // the second of the two lands.
    CHECK(yuzu::server::is_typed_inventory_source("app_usage"));
    CHECK(yuzu::server::is_typed_inventory_source("installed_software"));
    CHECK(yuzu::server::is_typed_inventory_source("app_perf"));
    CHECK(yuzu::server::is_typed_inventory_source("device_ci"));
    CHECK(yuzu::server::is_typed_inventory_source("software_licensing"));
}
