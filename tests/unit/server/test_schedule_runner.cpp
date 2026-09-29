/**
 * test_schedule_runner.cpp — Unit tests for the recurring-schedule poller
 * (ScheduleRunner, #1191).
 *
 * Strategy: real ScheduleEngine/ExecutionTracker/ApprovalManager (Postgres,
 * ADR-0065, schema-per-store on one shared ephemeral database — the
 * production shape now that InstructionDbPool is deleted and all three
 * are independent Postgres stores), a real InstructionStore on the same
 * database, and a FAKE `enqueue_fn` (WS-3 3.3) that records each
 * OutboxEnqueueRequest and returns a controllable OutboxEnqueueOutcome —
 * replacing the former inline dispatch_fn now that ScheduleRunner commits a
 * durable outbox occurrence instead of dispatching to agents directly.
 * Due-ness is driven by creating schedules with next_execution_at in the
 * past (create_schedule honors an explicit value), so no clock injection is
 * needed.
 */

#include "approval_manager.hpp"
#include "audit_store.hpp"
#include "execution_tracker.hpp"
#include "instruction_store.hpp"
#include "schedule_engine.hpp"
#include "schedule_params_parsers.hpp"
#include "schedule_runner.hpp"

#include "../test_helpers.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>

#include <chrono>
#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

// WS-3 3.3: what the fake `enqueue_fn` records for each fire — the shape of
// OutboxEnqueueRequest that matters to these tests, not the whole struct.
struct EnqueueRecord {
    std::string occurrence_id;
    std::string plugin;
    std::string action;
    std::string scope;
    std::string execution_id;
    std::string principal;
    std::string approval_id; // non-empty iff this occurrence cleared an approval gate
    std::string params;      // raw OutboxEnqueueRequest::parameters (canonical JSON)
};

// InstructionStore is now a migrated Postgres store (ADR-0058). ADR-0065
// migration-programme PR 5 grew this same template/database (ADR-0008
// schema-per-store-on-one-connection) across all 3 commits — this key has
// exactly one caller in the whole test tree (this file), so growing its
// setup function was safe under the PgTestTemplate replay-fingerprint rule
// (no other TU shares this key, so there's no divergent setup to conflict
// with). Now covers all 4 stores.
yuzu::test::PgTestTemplate schedrunner_instr_tpl{
    "schedrunnerinstr", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        InstructionStore store{pool};
        if (!store.is_open())
            throw std::runtime_error("schedrunner instruction template: store failed to migrate");
        ScheduleEngine engine{pool};
        if (!engine.is_open())
            throw std::runtime_error("schedrunner schedule engine template: store failed to migrate");
        ApprovalManager approvals{pool};
        if (!approvals.is_open())
            throw std::runtime_error("schedrunner approval manager template: store failed to migrate");
        ExecutionTracker tracker{pool};
        if (!tracker.is_open())
            throw std::runtime_error("schedrunner execution tracker template: store failed to migrate");
    }};

// A trivial first-declared Harness member whose sole purpose is running the
// YUZU_REQUIRE_PG_DB_TPL skip-check BEFORE the non-movable PostgresTestDb/
// PgPool members below it construct (both delete their move ctor, so they
// cannot be built elsewhere and relocated in). SKIP() works correctly here
// because we're still within the dynamic extent of the TEST_CASE that
// constructs Harness — Catch2's macros don't care about call depth, only
// about running inside a live test case (Harness's own constructor body
// already relies on this same fact for its REQUIRE calls, below). Keeping
// every one of the 19 existing `Harness h;` / `Harness h(...)` call sites
// unchanged is the whole point of gating this way instead of threading a
// pg::PgPool& through the constructor.
struct PgSkipGate {
    PgSkipGate() {
        if (yuzu::test::pg_admin_dsn_env() == nullptr)
            SKIP("YUZU_TEST_POSTGRES_DSN not set - Postgres test skipped");
    }
};

struct Harness {
    PgSkipGate pg_gate_; // MUST stay the first declared member — see its own doc comment.
    yuzu::test::PostgresTestDb instr_db{schedrunner_instr_tpl};
    yuzu::server::pg::PgPool instr_pool{{.conninfo = instr_db.dsn(), .size = 2}};

    // ADR-0065 (migration-programme PR 5): all four stores built on
    // instr_pool (one ephemeral Postgres database, schema-per-store) — the
    // production shape now that InstructionDbPool is deleted.
    ScheduleEngine engine{instr_pool};
    ExecutionTracker tracker{instr_pool};
    ApprovalManager approvals{instr_pool};
    InstructionStore is{instr_pool};

    std::vector<EnqueueRecord> enqueues;
    // WS-3 3.3: the outcome the fake enqueue_fn returns — controls whether
    // fire()/fire_with_approval() advance the schedule (Enqueued/
    // AlreadyEnqueued) or leave it due for retry (FencedOut/Degraded).
    OutboxEnqueueOutcome enqueue_result{OutboxEnqueueOutcome::Enqueued};
    // qa-1 regression coverage: when set, the fake enqueue_fn throws (models a
    // create_execution/entropy failure) so the exec-row-cancel-on-throw path is
    // exercised.
    bool throw_on_enqueue{false};
    // #3495: settable AFTER construction (mirrors enqueue_result above) so
    // existing call sites are unaffected — Deps::should_stop wraps a lambda
    // that reads this field live rather than the field's value at
    // construction time, since Deps is copied into the runner once and
    // there's no other way to change should_stop's behavior per-test.
    std::function<bool()> should_stop_hook;

    ScheduleRunner runner;

    // D7 (PLAN-003): default arming_check allows every fire, matching every
    // pre-D7 test's assumption that the schedule fires whenever nothing else
    // blocks it. D7-specific test cases pass `false` or an explicitly empty
    // ScheduleRunner::ArmingCheckFn{} to prove the deny/unset paths.
    explicit Harness(ScheduleRunner::ArmingCheckFn arming =
                          [](const std::string&, const std::string&, const std::string&) {
                              return true;
                          },
                      AuditStore* audit = nullptr, yuzu::MetricsRegistry* metrics_reg = nullptr,
                      InstructionStore* instruction_store_override = nullptr)
        : runner(ScheduleRunner::Deps{
              .schedule_engine = &engine,
              .instruction_store = instruction_store_override ? instruction_store_override : &is,
              .execution_tracker = &tracker,
              .approval_manager = &approvals,
              .audit_store = audit,
              .metrics = metrics_reg,
              // WS-3 3.3: records the durable-occurrence request instead of
              // dispatching inline, and returns the test-controlled outcome.
              .enqueue_fn =
                  [this](const yuzu::server::OutboxEnqueueRequest& req)
                      -> yuzu::server::OutboxEnqueueOutcome {
                  enqueues.push_back({req.occurrence_id, req.plugin, req.action, req.scope_expr,
                                     req.execution_id, req.principal, req.approval_id,
                                     req.parameters});
                  if (throw_on_enqueue)
                      throw std::runtime_error("enqueue boom");
                  return enqueue_result;
              },
              .arming_check = std::move(arming),
              .should_stop = [this] { return should_stop_hook && should_stop_hook(); },
          }) {
        INFO("[schedrunner instr] fixture status (blank == database came up OK): "
             << instr_db.error());
        REQUIRE(instr_db.available());
        tracker.create_tables();
        approvals.create_tables();

        InstructionDefinition d;
        d.id = "test.def";
        d.name = "test.def";
        d.version = "1.0.0";
        d.type = "question";
        d.plugin = "procs";
        d.action = "list";
        d.enabled = true;
        REQUIRE(is.create_definition(d).has_value());

        InstructionDefinition gated = d;
        gated.id = "test.gated";
        gated.name = "test.gated";
        gated.approval_mode = "always";
        REQUIRE(is.create_definition(gated).has_value());
    }

    // A schedule that is due NOW (next_execution_at forced into the past).
    std::string make_due(const std::string& def_id, const std::string& freq,
                         bool requires_approval = false,
                         const std::string& parameters_json = "") {
        InstructionSchedule s;
        s.name = "sched-" + def_id + "-" + freq;
        s.definition_id = def_id;
        s.frequency_type = freq;
        s.interval_minutes = 60;
        s.scope_expression = "";
        s.requires_approval = requires_approval;
        s.enabled = true;
        s.created_by = "admin";
        s.next_execution_at = 1; // long past — due immediately
        s.parameter_values = parameters_json;
        auto id = engine.create_schedule(s);
        REQUIRE(id.has_value());
        return *id;
    }

    InstructionSchedule get(const std::string& id) {
        for (const auto& s : engine.query_schedules())
            if (s.id == id)
                return s;
        FAIL("schedule not found: " + id);
        return {};
    }

    // Force an already-advanced schedule due again (a "next occurrence").
    // ScheduleEngine now lives in Postgres (instr_pool) — poke it via a
    // second raw connection, same as the interval-floor test below.
    void force_due(const std::string& id) {
        yuzu::server::pg::PgConn conn{PQconnectdb(instr_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto sql =
            "UPDATE schedule_engine.schedules SET next_execution_at = 1 WHERE id = '" + id + "'";
        yuzu::server::pg::PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }
};

} // namespace

TEST_CASE("ScheduleRunner: due interval schedule fires once and advances", "[schedule][runner][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1);
    CHECK(h.enqueues[0].plugin == "procs");
    CHECK(h.enqueues[0].action == "list");
    REQUIRE_FALSE(h.enqueues[0].execution_id.empty());
    // #2500: a schedule carries no agent_ids, so an empty scope_expression is
    // how this path has always meant "the whole fleet" — by falling into the
    // dispatch sink's empty-means-everybody default, which that issue INVERTED
    // to reach nobody. The runner now names the broadcast explicitly. Without
    // this assertion the inversion would silently turn every scope-less
    // schedule into a no-op that still advances and still logs a fire, which is
    // the worst shape a regression here could take: unattended and quiet.
    CHECK(h.enqueues[0].scope == "__all__");
    // The enqueued request's principal must be the schedule's creator — never
    // a system/service identity. The delivery loop re-resolves the live
    // caller/authority from this at send time.
    CHECK(h.enqueues[0].principal == "admin");
    // #1398: a direct auto-mode fire carries no approval provenance — the
    // gate at the dispatch chokepoint relies on principal_is_admin alone for
    // a role-gated pair reached this way, never a fabricated ticket. An
    // empty approval_id is the WS-3 3.3 equivalent of the old
    // caller.approval_provenance == ApprovalProvenance::None check.
    CHECK(h.enqueues[0].approval_id.empty());

    // Tracked execution row is created at enqueue time (create-before-dispatch),
    // so it exists immediately and shows in the Executions history. WS-3 3.3:
    // the targeted count is set later, by the DELIVERY loop after the actual
    // send — this schedule-only test does not run delivery, so agents_targeted is
    // still 0 and the row is 'running' (queued, not yet delivered).
    auto exec = h.tracker.get_execution(h.enqueues[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->definition_id == "test.def");
    CHECK(exec->dispatched_by == "admin");
    CHECK(exec->agents_targeted == 0);
    CHECK(exec->status == "running");

    // Advanced: next in the future, occurrence counted.
    auto s = h.get(id);
    CHECK(s.execution_count == 1);
    CHECK(s.next_execution_at > 1);

    // Not due any more — nothing else fires.
    h.runner.tick();
    CHECK(h.enqueues.size() == 1);
}

TEST_CASE("ScheduleRunner: 'once' schedule fires exactly once then disables",
          "[schedule][runner][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "once");

    h.runner.tick();
    h.runner.tick();

    CHECK(h.enqueues.size() == 1);
    CHECK(h.get(id).next_execution_at == 0); // disabled-after-fire sentinel
}

TEST_CASE("ScheduleRunner: unknown definition skips the occurrence but advances",
          "[schedule][runner][pg]") {
    Harness h;
    auto id = h.make_due("no.such.def", "interval");

    h.runner.tick();

    CHECK(h.enqueues.empty());
    auto s = h.get(id);
    CHECK(s.next_execution_at > 1); // advanced — must not re-fire every tick
}

TEST_CASE("ScheduleRunner: InstructionStore DB error skips the occurrence WITHOUT advancing "
          "(retries next tick)",
          "[schedule][runner][pg]") {
    // Regression pin (gov Gate 3/6 sibling finding): a genuine InstructionStore DB error used
    // to advance_schedule() unconditionally, permanently consuming that occurrence on a
    // transient Postgres blip — the same class of bug PolicyEvaluator::dispatch_due's
    // throttle-restore fix closed, not originally applied here.
    yuzu::server::pg::PgPool broken_pool{{.conninfo = "=quohth4eeQu5 garbage =", .size = 1}};
    REQUIRE_FALSE(broken_pool.valid());
    InstructionStore broken_is{broken_pool};
    REQUIRE_FALSE(broken_is.is_open());

    Harness h(
        [](const std::string&, const std::string&, const std::string&) { return true; }, nullptr,
        nullptr, &broken_is);
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    CHECK(h.enqueues.empty());
    // NOT advanced — still due, so the next tick retries rather than losing the occurrence.
    CHECK(h.get(id).next_execution_at == 1);
}

TEST_CASE("ScheduleRunner: disabled definition skips the occurrence but advances",
          "[schedule][runner][pg]") {
    Harness h;
    InstructionDefinition d;
    d.id = "test.off";
    d.name = "test.off";
    d.version = "1.0.0";
    d.type = "question";
    d.plugin = "p";
    d.action = "a";
    d.enabled = false;
    REQUIRE(h.is.create_definition(d).has_value());
    auto id = h.make_due("test.off", "interval");

    h.runner.tick();

    CHECK(h.enqueues.empty());
    CHECK(h.get(id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: a Degraded enqueue cancels the speculative execution row and leaves "
          "the schedule due (retries next tick)",
          "[schedule][runner][pg]") {
    // WS-3 3.3: replaces the former "zero agents reached" inline-dispatch
    // case — reach-counting no longer lives at this layer (the delivery
    // loop dispatches later). A Degraded enqueue is this layer's own
    // analogous failure: enqueue_occurrence() fails closed, so unlike the
    // old inline path (which still advanced on zero reach) the schedule
    // stays due and retries — the stable occurrence key keeps the retry
    // idempotent.
    Harness h;
    h.enqueue_result = OutboxEnqueueOutcome::Degraded;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1);
    auto exec = h.tracker.get_execution(h.enqueues[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");
    CHECK(h.get(id).next_execution_at == 1); // NOT advanced — stays due
}

TEST_CASE("ScheduleRunner: AlreadyEnqueued (idempotent re-fire) cancels the duplicate exec row "
          "and advances",
          "[schedule][runner][pg]") {
    // qa-2: the idempotent-re-fire branch (a crash-before-advance re-fire whose
    // occurrence already exists). The speculative exec row this fire created is a
    // duplicate the outbox discarded, so it must be cancelled, and the schedule
    // advances exactly as the first fire would have.
    Harness h;
    h.enqueue_result = OutboxEnqueueOutcome::AlreadyEnqueued;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1);
    auto exec = h.tracker.get_execution(h.enqueues[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");           // duplicate row cancelled
    CHECK(h.get(id).next_execution_at > 1);       // advanced (idempotent success)
}

TEST_CASE("ScheduleRunner: FencedOut (leadership lost) cancels the exec row and leaves the "
          "schedule due",
          "[schedule][runner][pg]") {
    // qa-2: the leadership-lost branch. The occurrence is left for the true
    // leader (no advance), and the speculative exec row is cancelled.
    Harness h;
    h.enqueue_result = OutboxEnqueueOutcome::FencedOut;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1);
    auto exec = h.tracker.get_execution(h.enqueues[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");
    CHECK(h.get(id).next_execution_at == 1); // NOT advanced — deferred to the true leader
}

TEST_CASE("ScheduleRunner: a throw from enqueue cancels the speculative exec row (qa-1 regression)",
          "[schedule][runner][pg]") {
    // qa-1: the former inline dispatch_tracked cancelled the exec row on a dispatch
    // throw; the enqueue rewrite must preserve that. tick()'s own catch advances
    // the schedule (fire-and-advance); enqueue_occurrence cancels the row first.
    Harness h;
    h.throw_on_enqueue = true;
    auto id = h.make_due("test.def", "interval");

    h.runner.tick(); // must not propagate — tick() contains per-schedule throws

    REQUIRE(h.enqueues.size() == 1);
    auto exec = h.tracker.get_execution(h.enqueues[0].execution_id);
    REQUIRE(exec.has_value());
    CHECK(exec->status == "cancelled");     // row cancelled, not orphaned at 'running'
    CHECK(h.get(id).next_execution_at > 1); // advanced by tick()'s catch (fire-and-advance)
}

TEST_CASE("ScheduleRunner: requires_approval submits one ticket and holds the occurrence",
          "[schedule][runner][approval][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick();
    h.runner.tick(); // second tick must NOT stack a duplicate ask

    CHECK(h.enqueues.empty());
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    CHECK(pending[0].definition_id == "test.def");
    CHECK(pending[0].submitted_by == "admin");

    // Occurrence held: not advanced, still due.
    auto s = h.get(id);
    CHECK(s.execution_count == 0);
    CHECK(s.next_execution_at == 1);
}

TEST_CASE("ScheduleRunner: approving the ticket fires the held occurrence exactly once",
          "[schedule][runner][approval][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick(); // submits
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());

    h.runner.tick(); // fires

    REQUIRE(h.enqueues.size() == 1);
    CHECK(h.get(id).execution_count == 1);
    // #1398: firing on an approved ticket carries the ticket id as
    // approval_id (never empty) — the delivery loop stamps Ticket
    // provenance from it. This is the WS-3 3.3 equivalent of the old
    // caller.approval_provenance == ApprovalProvenance::Ticket check.
    CHECK(h.enqueues[0].approval_id == pending[0].id);

    // One-approval == one-run: force the next occurrence due — the spent
    // (still 'approved') ticket must be stale under the occurrence anchor,
    // so the runner submits a FRESH ask instead of re-firing.
    h.force_due(id);
    h.runner.tick();

    CHECK(h.enqueues.size() == 1); // no second fire
    CHECK(h.approvals.query({.status = "pending"}).size() == 1);
}

// #1398 hardening (governance Gate 4 unhappy-path CRITICAL finding): a
// ticket is minted for the definition's CONTENT at submit time, but
// `fire()` re-fetches the definition fresh every tick and previously
// matched a ticket by `(definition_id, scope_expression, schedule_id)`
// alone — so a definition mutated between ticket-approval and the next
// tick would fire under review that was never given for the NEW content.
// Concrete exploit this closes: a seeded non-admin role (e.g. Operator,
// which holds InstructionDefinition:Write + Schedule:Write + Execution:
// Execute) gets a benign action approved, then mutates the SAME
// definition to point at `script_exec.bash` (also `Execution:Execute`,
// also gated) before the next tick — without this fix, the stale ticket
// would silently cover the swapped, unreviewed action.
TEST_CASE("ScheduleRunner: a definition mutated AFTER ticket approval does not fire under "
          "the stale ticket (#1398 content-swap hardening)",
          "[schedule][runner][approval][1398]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick(); // submits a ticket for procs.list (test.def's content)
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());

    // Mutate the definition's plugin/action AFTER approval, BEFORE the next
    // tick — exactly the PUT /api/instructions/{id} write an operator with
    // only InstructionDefinition:Write can perform.
    auto def_result = h.is.get_definition("test.def");
    REQUIRE(def_result.has_value());
    REQUIRE(def_result->has_value());
    InstructionDefinition mutated = **def_result;
    mutated.plugin = "script_exec";
    mutated.action = "bash";
    REQUIRE(h.is.update_definition(mutated).has_value());

    h.runner.tick(); // must NOT fire the swapped action under the old ticket

    CHECK(h.enqueues.empty()); // no enqueue happened at all — the swap was refused
    // A fresh ticket for the NEW content is submitted and held, distinct
    // from the original (now permanently stale — target mismatched) approved
    // one. Two separate fields (not a concatenated string, #1398
    // security-guardian re-review) so a definition whose plugin/action
    // happen to concatenate to the same string as another pair still can't
    // collide here — asserted independently.
    auto still_pending = h.approvals.query({.status = "pending"});
    REQUIRE(still_pending.size() == 1);
    CHECK(still_pending[0].target_plugin == "script_exec");
    CHECK(still_pending[0].target_action == "bash");
    auto approved_now = h.approvals.query({.status = "approved"});
    REQUIRE(approved_now.size() == 1);
    CHECK(approved_now[0].target_plugin == "procs"); // the stale, never-consumed ticket
    CHECK(approved_now[0].target_action == "list");
    CHECK(approved_now[0].consumed_at == 0); // never redeemed
}

TEST_CASE("ScheduleRunner: rejecting the ticket skips the occurrence and re-asks next time",
          "[schedule][runner][approval][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick(); // submits
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.reject(pending[0].id, "boss", "no").has_value());

    h.runner.tick(); // occurrence skipped + advanced

    CHECK(h.enqueues.empty());
    CHECK(h.get(id).next_execution_at > 1);

    // Next occurrence: the rejected ticket is stale — a fresh ask goes out.
    h.force_due(id);
    h.runner.tick();
    CHECK(h.enqueues.empty());
    CHECK(h.approvals.query({.status = "pending"}).size() == 1);
}

TEST_CASE("ScheduleRunner: definition approval_mode gates even without the schedule flag",
          "[schedule][runner][approval][pg]") {
    Harness h;
    h.make_due("test.gated", "interval", /*requires_approval=*/false);

    h.runner.tick();

    // approval_mode="always" must not be bypassed by a scheduled fire.
    CHECK(h.enqueues.empty());
    CHECK(h.approvals.query({.status = "pending"}).size() == 1);
}

TEST_CASE("ScheduleRunner: two schedules sharing (creator,definition,scope) get independent "
          "approval tickets — one approval fires only its own schedule (M-02, #1806)",
          "[schedule][runner][approval][m02][pg]") {
    Harness h;
    // Both due, both reference the same gated definition, both default to
    // the same scope_expression ("") and created_by ("admin") — exactly the
    // (submitted_by, definition_id, scope_expression) tuple M-02 found was
    // used to match an approval BEFORE schedule_id existed.
    auto id_a = h.make_due("test.gated", "interval");
    auto id_b = h.make_due("test.gated", "interval");

    h.runner.tick(); // both hold; each submits its OWN ticket, no dedup collapse

    CHECK(h.enqueues.empty());
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 2); // two tickets, not one shared ticket

    std::string pending_a_id, pending_b_id;
    for (const auto& a : pending) {
        if (a.schedule_id == id_a)
            pending_a_id = a.id;
        else if (a.schedule_id == id_b)
            pending_b_id = a.id;
    }
    REQUIRE_FALSE(pending_a_id.empty());
    REQUIRE_FALSE(pending_b_id.empty());

    // Approve ONLY schedule A's ticket.
    REQUIRE(h.approvals.approve(pending_a_id, "boss", "ok").has_value());

    h.runner.tick();

    // Exactly one fire, and it is A's — B must not be swept along just
    // because it shares (creator, definition, scope) with A.
    REQUIRE(h.enqueues.size() == 1);
    CHECK(h.get(id_a).execution_count == 1);
    CHECK(h.get(id_b).execution_count == 0);

    // B still holds its OWN untouched pending ticket — proves no cross-talk
    // (not merely "no double-fire"): B was never suppressed by A's ticket
    // and never had its own ticket consumed by A's approval.
    auto still_pending = h.approvals.query({.status = "pending"});
    REQUIRE(still_pending.size() == 1);
    CHECK(still_pending[0].id == pending_b_id);
    CHECK(still_pending[0].schedule_id == id_b);
}

TEST_CASE("ScheduleEngine: interval floor rejected at create, clamped on legacy advance",
          "[schedule][runner][pg]") {
    Harness h;

    // Create-time floor.
    InstructionSchedule bad;
    bad.name = "bad";
    bad.definition_id = "test.def";
    bad.frequency_type = "interval";
    bad.interval_minutes = 0;
    auto rejected = h.engine.create_schedule(bad);
    REQUIRE_FALSE(rejected.has_value());

    // Legacy row (predates the floor): clamp on advance so it cannot land
    // next_execution_at <= now and re-fire every tick. ScheduleEngine now
    // lives in Postgres (instr_pool) — poke it via a second raw connection.
    auto id = h.make_due("test.def", "interval");
    {
        yuzu::server::pg::PgConn conn{PQconnectdb(h.instr_db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        auto sql = "UPDATE schedule_engine.schedules SET interval_minutes = 0 WHERE id = '" +
                  id + "'";
        yuzu::server::pg::PgResult res{PQexec(conn.get(), sql.c_str())};
        REQUIRE(res.status() == PGRES_COMMAND_OK);
    }

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1);
    auto s = h.get(id);
    auto now = std::chrono::duration_cast<std::chrono::seconds>(
                   std::chrono::system_clock::now().time_since_epoch())
                   .count();
    CHECK(s.next_execution_at > now); // clamped forward, not re-armed at now
}

// ── PR1.5a: typed schedule parameters ───────────────────────────────────────

TEST_CASE("ScheduleRunner: a schedule's parameters round-trip to the enqueued request and "
          "exec.parameter_values",
          "[schedule][runner][params][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/false,
                         R"({"target":"prod","retries":3})");

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1);
    // Canonical (sorted-key) form reaches the enqueue request's parameters —
    // never empty, never the raw caller order.
    auto params = schedule_params_to_map(h.enqueues[0].params);
    CHECK(params.at("target") == "prod");
    CHECK(params.at("retries") == "3");

    auto exec = h.tracker.get_execution(h.enqueues[0].execution_id);
    REQUIRE(exec.has_value());
    // exec.parameter_values equals the stored canonical JSON — never the
    // literal "{}" that used to be hardcoded before this package.
    CHECK(exec->parameter_values == h.get(id).parameter_values);
    CHECK(exec->parameter_values != "{}");
    // The enqueued request carries the same canonical blob straight through.
    CHECK(h.enqueues[0].params == h.get(id).parameter_values);
}

TEST_CASE("ScheduleRunner: a schedule created with no parameters defaults to the canonical "
          "empty object and enqueues an empty parameter map",
          "[schedule][runner][params][pg]") {
    Harness h;
    auto id = h.make_due("test.def", "interval");

    CHECK(h.get(id).parameter_values == "{}");

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1);
    CHECK(h.enqueues[0].params == "{}");
    CHECK(schedule_params_to_map(h.enqueues[0].params).empty());
}

// ── D7 (PLAN-003): arming re-check on EVERY fire path ───────────────────────

TEST_CASE("ScheduleRunner: D7 a false arming_check blocks the auto (no-approval) fire path",
          "[schedule][runner][d7][pg]") {
    Harness h([](const std::string&, const std::string&, const std::string&) { return false; });
    auto id = h.make_due("test.def", "interval");

    h.runner.tick();

    CHECK(h.enqueues.empty()); // enqueue_fn never reached
    CHECK(h.get(id).next_execution_at > 1); // advanced — must not spin
}

TEST_CASE("ScheduleRunner: D7 a false arming_check blocks the approval-gated fire path",
          "[schedule][runner][d7][approval][pg]") {
    Harness h([](const std::string&, const std::string&, const std::string&) { return false; });
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick();

    // Denied BEFORE the approval branch — no ticket is even submitted, so
    // this proves arming_check gates IN FRONT OF fire_with_approval rather
    // than duplicating one of its checks.
    CHECK(h.enqueues.empty());
    CHECK(h.approvals.query({.status = "pending"}).empty());
    CHECK(h.get(id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: D7 an UNSET arming_check denies both the auto and approval-gated "
          "paths",
          "[schedule][runner][d7][pg]") {
    Harness h(ScheduleRunner::ArmingCheckFn{}); // deliberately empty — p14 not wired
    auto auto_id = h.make_due("test.def", "interval");
    auto gated_id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick();

    CHECK(h.enqueues.empty());
    CHECK(h.approvals.query({.status = "pending"}).empty());
    CHECK(h.get(auto_id).next_execution_at > 1);
    CHECK(h.get(gated_id).next_execution_at > 1);
}

TEST_CASE("ScheduleRunner: D7 true arming_check still lets the auto and approved-ticket paths "
          "fire (existing approval behaviour unchanged)",
          "[schedule][runner][d7][approval][pg]") {
    Harness h([](const std::string&, const std::string&, const std::string&) { return true; });

    auto auto_id = h.make_due("test.def", "interval");
    h.runner.tick();
    REQUIRE(h.enqueues.size() == 1);
    CHECK(h.get(auto_id).execution_count == 1);

    auto gated_id = h.make_due("test.def", "interval", /*requires_approval=*/true);
    h.runner.tick(); // submits
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());
    h.runner.tick(); // fires

    REQUIRE(h.enqueues.size() == 2);
    CHECK(h.get(gated_id).execution_count == 1);
}

namespace {
// AuditStore is Postgres-backed now — pre-migrated template for the single
// audit-consuming case below (everything else in this file stays hermetic
// SQLite via the runner's own stores).
yuzu::test::PgTestTemplate schedrunner_audit_tpl{"schedrunneraudit", [](const std::string& dsn) {
    yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
    AuditStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("schedrunner audit template: store failed to migrate");
}};
} // namespace

TEST_CASE("ScheduleRunner: D7 a denied arming check audits the principal + target and counts "
          "the deny",
          "[schedule][runner][d7][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, schedrunner_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AuditStore audit{pool};
    REQUIRE(audit.is_open());
    yuzu::MetricsRegistry metrics;
    Harness h([](const std::string&, const std::string&, const std::string&) { return false; },
             &audit, &metrics);
    h.make_due("test.def", "interval");

    h.runner.tick();

    CHECK(metrics.counter("yuzu_schedule_arming_denied_total").value() == 1.0);

    auto rows = audit.query({.action = "instruction.schedule_fired"});
    REQUIRE(rows.has_value()); // PG store: query reports availability, not just rows
    bool found = false;
    for (const auto& e : *rows) {
        if (e.result == "denied" && e.principal == "admin" &&
            e.detail.find("plugin=procs") != std::string::npos &&
            e.detail.find("action=list") != std::string::npos) {
            found = true;
        }
    }
    CHECK(found);
}

// #1398 (compliance-officer + sre governance findings): the
// approval_content_mismatch audit event added alongside the content-swap
// hardening test (above, in the SQLite-only harness section) had no test
// verifying the audit row is actually written (compliance-officer) — a
// future refactor of fire_with_approval could silently drop the audit()
// call and nothing would catch it. This test wires a real AuditStore
// (mirroring the D7 audit test just above) and checks two things: (1) the
// row exists with the expected detail fields, and (2) it fires exactly
// ONCE across two ticks that both re-detect the same stale mismatch — not
// once per tick (sre finding: the stale approved ticket never changes
// status, so an un-deduplicated audit call would re-fire on every tick for
// as long as the fresh replacement ticket stays pending).
TEST_CASE("ScheduleRunner: a content mismatch audits once, with the approved vs. current "
          "target in the detail, not once per tick (#1398)",
          "[schedule][runner][approval][1398][pg]") {
    YUZU_REQUIRE_PG_DB_TPL(db, schedrunner_audit_tpl);
    yuzu::server::pg::PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    AuditStore audit{pool};
    REQUIRE(audit.is_open());
    Harness h(
        [](const std::string&, const std::string&, const std::string&) { return true; }, &audit);
    auto id = h.make_due("test.def", "interval", /*requires_approval=*/true);

    h.runner.tick(); // submits a ticket for procs.list
    auto pending = h.approvals.query({.status = "pending"});
    REQUIRE(pending.size() == 1);
    REQUIRE(h.approvals.approve(pending[0].id, "boss", "ok").has_value());

    auto def_result = h.is.get_definition("test.def");
    REQUIRE(def_result.has_value());
    REQUIRE(def_result->has_value());
    InstructionDefinition mutated = **def_result;
    mutated.plugin = "script_exec";
    mutated.action = "bash";
    REQUIRE(h.is.update_definition(mutated).has_value());

    h.runner.tick(); // detects the mismatch, audits once, submits a fresh ticket
    h.runner.tick(); // re-detects the SAME stale mismatch — must NOT audit again

    auto mismatch_rows_res = audit.query({.action = "instruction.schedule_fired"});
    REQUIRE(mismatch_rows_res.has_value());
    int mismatch_rows = 0;
    for (const auto& e : *mismatch_rows_res) {
        if (e.result == "denied" &&
            e.detail.find("approval_content_mismatch") != std::string::npos) {
            ++mismatch_rows;
            CHECK(e.detail.find("approved_target=procs.list") != std::string::npos);
            CHECK(e.detail.find("current_target=script_exec.bash") != std::string::npos);
            CHECK(e.detail.find("schedule_id=" + id) != std::string::npos);
        }
    }
    CHECK(mismatch_rows == 1);
}

// #3495 governance (chaos-injector HIGH + codex external tie-break,
// 2026-08-24): tick()'s per-schedule loop had NO interior cancellation
// check — once started, a single tick() call could fire every due schedule
// with no way to interrupt it, compounding with ServerImpl::stop()'s
// schedule_tick_thread_.join() ahead of it. Deps::should_stop closes this,
// ported from QuarantineContainmentReconciler::Deps: checked once per
// schedule, before fire() runs, so a schedule already firing still
// completes cleanly — this only stops the NEXT one from starting.
TEST_CASE("ScheduleRunner: tick() stops firing further schedules once should_stop() "
          "reports true, deferring the rest to the next tick",
          "[schedule][runner]") {
    Harness h;
    auto id_a = h.make_due("test.def", "interval");
    auto id_b = h.make_due("test.def", "daily");

    // Stop signals true once the first schedule has fired — proving the
    // loop actually checks should_stop() before the SECOND schedule and
    // exits early rather than pushing through both.
    h.should_stop_hook = [&h] { return h.enqueues.size() >= 1; };

    h.runner.tick();

    REQUIRE(h.enqueues.size() == 1); // NOT 2 — the loop stopped before the second schedule

    const auto sa = h.get(id_a);
    const auto sb = h.get(id_b);
    // Exactly one of the two fired (advanced past next_execution_at == 1);
    // the other is untouched and stays due for the next tick — a clean
    // defer, not a partial or lost fire.
    const bool a_fired = sa.next_execution_at != 1;
    const bool b_fired = sb.next_execution_at != 1;
    CHECK(a_fired != b_fired);
}

// #3495 companion (governance happy-path, 2026-08-30): Harness::runner always
// wires a non-empty `.should_stop` lambda (`[this]{ return should_stop_hook &&
// should_stop_hook(); }`, itself false unless a test sets should_stop_hook) —
// so no existing ScheduleRunner test ever exercises `d_.should_stop` as a
// literal default-constructed empty std::function, the exact production
// shape every unwired Deps carries. PreflightRunner and PolicyEvaluator each
// got a dedicated unset-should_stop control test at Gate 3; this is
// ScheduleRunner's. Constructs a second, raw ScheduleRunner sharing the
// Harness's already-built engine/tracker/approvals/instruction-store rather
// than going through Harness's own runner (which cannot leave should_stop
// unset).
TEST_CASE("ScheduleRunner: an unset should_stop fires every due schedule, "
          "not just the first",
          "[schedule][runner]") {
    Harness h;
    auto id_a = h.make_due("test.def", "interval");
    auto id_b = h.make_due("test.def", "daily");

    std::vector<EnqueueRecord> enqueues;
    ScheduleRunner raw_runner(ScheduleRunner::Deps{
        .schedule_engine = &h.engine,
        .instruction_store = &h.is,
        .execution_tracker = &h.tracker,
        .approval_manager = &h.approvals,
        .enqueue_fn =
            [&](const yuzu::server::OutboxEnqueueRequest& req)
                -> yuzu::server::OutboxEnqueueOutcome {
            enqueues.push_back({req.occurrence_id, req.plugin, req.action, req.scope_expr,
                               req.execution_id, req.principal, req.approval_id,
                               req.parameters});
            return yuzu::server::OutboxEnqueueOutcome::Enqueued;
        },
        .arming_check = [](const std::string&, const std::string&, const std::string&) {
            return true;
        },
        // .should_stop left unset (default std::function<bool()>{}).
    });

    raw_runner.tick();

    CHECK(enqueues.size() == 2); // both fired — an unset should_stop never breaks the loop
    const auto sa = h.get(id_a);
    const auto sb = h.get(id_b);
    CHECK(sa.next_execution_at != 1);
    CHECK(sb.next_execution_at != 1);
}
