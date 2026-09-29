/**
 * test_bundle_orchestrator.cpp — server-side bundle dispatch/collate orchestration
 * (ADR-0011). Exercises the transport-agnostic core with an injected fake
 * DispatchFn + a :memory: ResponseStore + a fixed IdMinter, so no live agent or
 * server is needed. The REST/MCP wrappers are thin over this object.
 */

#include "bundle_orchestrator.hpp"
#include "bundle_service.hpp"
#include "pg/pg_pool.hpp"
#include "response_store.hpp"

#include "../test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using yuzu::server::pg::PgPool;

namespace {

// ResponseStore is now a migrated Postgres store (ADR-0039) — shares the
// "responsestore" template key with test_response_store.cpp (identical setup).
yuzu::test::PgTestTemplate responsestore_tpl{"responsestore", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResponseStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("responsestore template: store failed to migrate");
}};

// Fake per-command dispatcher: records calls, returns a deterministic
// command_id per (plugin,action) and a configurable agents_reached.
struct FakeDispatch {
    struct Call {
        std::string plugin, action, correlation;
        std::vector<std::string> agent_ids;
        yuzu::server::authz::VisibleSet exec_visible; // governance UP-8: what the caller threaded
        std::string principal; // M11: the IDENTITY half — see the test below
        // #1398 (adversarial-review finding): the two fields dispatch()'s own
        // per-step DispatchCaller reconstruction used to silently drop.
        bool principal_is_admin = false;
        yuzu::server::ApprovalProvenance approval_provenance =
            yuzu::server::ApprovalProvenance::None;
    };
    std::vector<Call> calls;
    int sent = 1; // agents_reached returned for every step

    BundleOrchestrator::DispatchFn fn() {
        return [this](const std::string& plugin, const std::string& action,
                      const std::vector<std::string>& agent_ids, const std::string& /*scope*/,
                      const std::unordered_map<std::string, std::string>& /*params*/,
                      const std::string& correlation,
                      const yuzu::server::DispatchCaller& caller)
            -> yuzu::server::ConfinedDispatchOutcome {
            calls.push_back(Call{plugin, action, correlation, agent_ids, caller.exec_visible,
                                 caller.principal, caller.principal_is_admin,
                                 caller.approval_provenance});
            return {.sent = sent, .command_id = "cmd-" + plugin + "-" + action};
        };
    }
};

BundleOrchestrator::IdMinter fixed_id(std::string id) {
    return [id = std::move(id)]() { return id; };
}

// no-op audit
BundleOrchestrator::AuditSink null_audit() {
    return [](const std::string&, const std::string&, const std::string&, const std::string&,
              const std::string&) {};
}

void put_response(ResponseStore& store, const std::string& correlation,
                  const std::string& command_id, int status, const std::string& output) {
    StoredResponse r;
    r.execution_id = correlation;  // stamped with the bundle correlation id
    r.instruction_id = command_id; // == the dispatched command_id
    r.agent_id = "agent-1";
    r.status = status;
    r.output = output;
    r.timestamp = 100;
    store.store(r);
}

std::vector<BundleStepSpec> two_steps() {
    auto v = validate_bundle_steps(
        R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"}])");
    REQUIRE(v.has_value());
    return *v;
}

} // namespace

TEST_CASE("orchestrator dispatch fans each step under one bundle- correlation id",
          "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    int audited = 0;
    auto audit = [&](const std::string& verb, const std::string& result, const std::string& type,
                     const std::string& id, const std::string&) {
        ++audited;
        CHECK(verb.rfind("bundle.os_info.", 0) == 0); // per-step verb, transport-agnostic
        CHECK(result == "dispatched");
        CHECK(type == "Agent"); // device-access audit lens (governance F1)
        CHECK(id == "agent-1");
    };

    auto res = orch.dispatch("agent-1", two_steps(), "alice", audit);
    CHECK(res.correlation_id == "bundle-abc"); // bundle- prefix → notify_exec_tracker skips it
    CHECK(res.expected == 2);
    REQUIRE(fd.calls.size() == 2);
    CHECK(fd.calls[0].correlation == "bundle-abc");
    CHECK(fd.calls[0].agent_ids == std::vector<std::string>{"agent-1"});
    CHECK(audited == 2);
}

TEST_CASE("orchestrator threads the caller's exec_visible into DispatchFn unchanged "
          "(governance UP-8)",
          "[pg][bundle][orchestrator][scope]") {
    // Before this fix `dispatch()` hardcoded an unfiltered VisibleSet{} into
    // every step regardless of what the caller (REST/MCP) had already derived
    // — a drift hazard: a future dispatch_fn that started consulting this set
    // for its own confinement would silently see "unfiltered" no matter what
    // the wrapper actually authorized. This proves the caller's set survives
    // unchanged, per step.
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("vis"));

    std::unordered_set<std::string> caller_visible{"agent-1"};
    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit(),
                             yuzu::server::authz::VisibleSet{caller_visible});
    CHECK(res.expected == 2);
    REQUIRE(fd.calls.size() == 2);
    for (const auto& call : fd.calls) {
        REQUIRE(call.exec_visible.has_value()); // NOT nullopt/unfiltered
        CHECK(call.exec_visible->size() == 1);
        CHECK(call.exec_visible->count("agent-1") == 1);
        // M11 (review finding, post-merge round): this suite proved the
        // VISIBILITY half of DispatchCaller reaches dispatch_fn but ignored
        // the IDENTITY half — the same asymmetry the original CRITICAL fix
        // was about. `dispatch()`'s third positional argument ("alice"
        // above) is exactly `caller.principal`.
        CHECK(call.principal == "alice");
    }
}

TEST_CASE("orchestrator threads principal_is_admin and approval_provenance into DispatchFn "
          "unchanged (#1398, adversarial-review finding)",
          "[pg][bundle][orchestrator][1398]") {
    // Before this fix `dispatch()` reconstructed a per-step DispatchCaller
    // carrying only `.principal`/`.exec_visible` — `principal_is_admin` and
    // `approval_provenance` silently defaulted to false/None regardless of
    // the real caller, so an admin's (or a ticket-holding supervised MCP
    // caller's) bundle step on an AdminOrApproval/AlwaysApproval pair was
    // refused ApprovalRequired unconditionally at the dispatch chokepoint,
    // with no way to satisfy the gate via this surface at all. Both
    // independent adversarial-review reviewers (Kimi + Codex, 2026-08-28)
    // found this; this test is the falsifier they both asked for.
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("admin"));

    SECTION("admin caller, no ticket") {
        auto res = orch.dispatch("agent-1", two_steps(), "boss", null_audit(), std::nullopt,
                                 /*principal_is_admin=*/true);
        CHECK(res.expected == 2);
        REQUIRE(fd.calls.size() == 2);
        for (const auto& call : fd.calls) {
            CHECK(call.principal_is_admin);
            CHECK(call.approval_provenance == yuzu::server::ApprovalProvenance::None);
        }
    }
    SECTION("non-admin caller with a consumed ticket") {
        auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit(), std::nullopt,
                                 /*principal_is_admin=*/false,
                                 yuzu::server::ApprovalProvenance::Ticket);
        CHECK(res.expected == 2);
        REQUIRE(fd.calls.size() == 2);
        for (const auto& call : fd.calls) {
            CHECK_FALSE(call.principal_is_admin);
            CHECK(call.approval_provenance == yuzu::server::ApprovalProvenance::Ticket);
        }
    }
    SECTION("neither admin nor ticket — defaults preserved, matching pre-#1398 behavior for an "
            "ungated pair") {
        auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
        CHECK(res.expected == 2);
        REQUIRE(fd.calls.size() == 2);
        for (const auto& call : fd.calls) {
            CHECK_FALSE(call.principal_is_admin);
            CHECK(call.approval_provenance == yuzu::server::ApprovalProvenance::None);
        }
    }
}

TEST_CASE("orchestrator defaults to unfiltered exec_visible when the caller supplies none",
          "[pg][bundle][orchestrator][scope]") {
    // REST's confinement model authorizes agent_id via scoped_perm_fn BEFORE
    // calling dispatch() (never derives a VisibleSet), so omitting the
    // argument must preserve that — nullopt, not a present-empty deny-all.
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("def"));

    orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    REQUIRE(fd.calls.size() == 2);
    CHECK_FALSE(fd.calls[0].exec_visible.has_value());
}

TEST_CASE("orchestrator collate groups responses in request order", "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());

    // Before any response: not complete.
    auto a0 = orch.collate(res.correlation_id, "alice", /*is_admin=*/false);
    REQUIRE(a0.has_value());
    CHECK_FALSE(a0->complete);
    CHECK(a0->received == 0);

    // Responses land (out of order) under the correlation id.
    put_response(store, "bundle-abc", "cmd-os_info-os_name", 1, "os_name|Win");
    put_response(store, "bundle-abc", "cmd-os_info-uptime", 1, "up 3d");

    auto a1 = orch.collate(res.correlation_id, "alice", false);
    REQUIRE(a1.has_value());
    CHECK(a1->complete);
    CHECK(a1->received == 2);
    REQUIRE(a1->steps.size() == 2);
    CHECK(a1->steps[0].action == "uptime"); // request order, not arrival
    CHECK(a1->steps[0].output == "up 3d");
    CHECK(a1->steps[1].action == "os_name");
}

TEST_CASE("orchestrator: a step that reached no agent is dispatch-failed (terminal)",
          "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    fd.sent = 0; // every step reaches 0 agents
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto a = orch.collate(res.correlation_id, "alice", false);
    REQUIRE(a.has_value());
    CHECK(a->complete); // dispatch-failed steps are terminal, don't hold it open
    CHECK(a->received == 0);
    for (const auto& s : a->steps)
        CHECK(s.state == BundleStepState::DispatchFailed);
}

TEST_CASE("orchestrator collate enforces ownership (IDOR guard)", "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));

    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());

    // Wrong principal, not admin → nullopt (indistinguishable from not-found).
    CHECK_FALSE(orch.collate(res.correlation_id, "mallory", /*is_admin=*/false).has_value());
    // Admin override is allowed.
    CHECK(orch.collate(res.correlation_id, "mallory", /*is_admin=*/true).has_value());
    // Owner is allowed.
    CHECK(orch.collate(res.correlation_id, "alice", false).has_value());
}

TEST_CASE("orchestrator collate of an unknown correlation id is nullopt", "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));
    auto agg = orch.collate("bundle-nope", "alice", false);
    CHECK_FALSE(agg.has_value());
    CHECK(agg.error() == CollateError::kNotFoundOrDenied);
}

// #2691 (Doomgoose finding #3): a manifest that IS found and owned, but whose
// ResponseStore read fails, must return a DISTINCT error from the same-shaped
// "not found / not owned" case above — the caller maps kDegraded to a
// retryable 503/kInternalError, never the terminal 404 a genuinely-absent or
// denied bundle gets. A not-open store (bad pool) forces query_by_execution()
// to fail without needing to break a healthy connection mid-test.
TEST_CASE("orchestrator collate distinguishes a degraded store read from not-found/denied",
          "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    PgPool bad_pool{{.conninfo = "host=192.0.2.1 port=1 connect_timeout=1", .size = 1}};
    ResponseStore bad_store(bad_pool);
    REQUIRE_FALSE(bad_store.is_open());
    BundleOrchestrator orch(fd.fn(), &bad_store, fixed_id("abc"));

    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto agg = orch.collate(res.correlation_id, "alice", /*is_admin=*/false);
    CHECK_FALSE(agg.has_value());
    CHECK(agg.error() == CollateError::kDegraded); // NOT kNotFoundOrDenied
}

// The `!response_store_` (never-wired) branch is the SAME degrade signal,
// not a third state — a caller must not be able to tell "substrate never
// wired" apart from "substrate read failed" (#2691).
TEST_CASE("orchestrator collate with an unwired response store is a degrade not a not-found",
          "[bundle][orchestrator]") {
    FakeDispatch fd;
    BundleOrchestrator orch(fd.fn(), /*response_store=*/nullptr, fixed_id("abc"));
    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto agg = orch.collate(res.correlation_id, "alice", /*is_admin=*/false);
    CHECK_FALSE(agg.has_value());
    CHECK(agg.error() == CollateError::kDegraded);
}

// ── Gate-7 governance hardening regressions ─────────────────────────────────

TEST_CASE("orchestrator: a throwing dispatch step is isolated, manifest still stored (UP-1)",
          "[pg][bundle][orchestrator]") {
    // A throw from dispatch_ on step 2 must NOT propagate and must NOT orphan the
    // already-sent commands: the manifest is stored regardless, so collate finds
    // it; the throwing step reads dispatch-failed.
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    int n = 0;
    BundleOrchestrator::DispatchFn throwing =
        [&n](const std::string& plugin, const std::string& action, const std::vector<std::string>&,
             const std::string&, const std::unordered_map<std::string, std::string>&,
             const std::string&, const yuzu::server::DispatchCaller&)
            -> yuzu::server::ConfinedDispatchOutcome {
        if (++n == 2)
            throw std::runtime_error("gRPC write failed");
        return {.sent = 1, .command_id = "cmd-" + plugin + "-" + action};
    };
    BundleOrchestrator orch(throwing, &store, fixed_id("abc"));
    auto specs = validate_bundle_steps(
        R"([{"plugin":"os_info","action":"uptime"},{"plugin":"os_info","action":"os_name"},{"plugin":"os_info","action":"os_arch"}])");
    REQUIRE(specs.has_value());

    BundleOrchestrator::DispatchResult res;
    REQUIRE_NOTHROW(res = orch.dispatch("agent-1", *specs, "alice", null_audit()));

    auto agg = orch.collate(res.correlation_id, "alice", /*is_admin=*/false);
    REQUIRE(agg.has_value()); // not orphaned
    REQUIRE(agg->steps.size() == 3);
    CHECK(agg->steps[1].state == BundleStepState::DispatchFailed); // the throwing step
    CHECK(agg->steps[0].state == BundleStepState::Pending);        // dispatched, awaiting response
    CHECK(agg->steps[2].state == BundleStepState::Pending);
}

TEST_CASE("orchestrator: a single boundary poll does not self-evict; polling slides the TTL",
          "[pg][bundle][orchestrator]") {
    // governance UP-3/UP-4 / CH-3/CH-4.
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    std::int64_t clock = 1000;
    BundleOrchestrator::ClockFn now = [&clock]() { return clock; };
    const std::int64_t ttl = 10000;
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"), /*metrics=*/nullptr,
                            /*surface=*/"test", now, ttl, /*max_manifests=*/4096);
    auto res = orch.dispatch("agent-1", two_steps(), "alice", null_audit());

    // CH-3: first/only poll exactly at created_at + ttl + 1 still serves it
    // (collate finds BEFORE sweeping).
    clock = 1000 + ttl + 1;
    CHECK(orch.collate(res.correlation_id, "alice", false).has_value());

    // CH-4: that poll slid the window — a poll within ttl of the LAST poll works,
    // even though it is far past the original created_at.
    clock += ttl;
    CHECK(orch.collate(res.correlation_id, "alice", false).has_value());
}

TEST_CASE("orchestrator: an abandoned (un-polled) bundle is eventually swept",
          "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    std::int64_t clock = 0;
    int idctr = 0;
    BundleOrchestrator::ClockFn now = [&clock]() { return clock; };
    BundleOrchestrator::IdMinter mint = [&idctr]() { return std::to_string(idctr++); };
    const std::int64_t ttl = 10000;
    BundleOrchestrator orch(fd.fn(), &store, mint, nullptr, "test", now, ttl, 4096);

    clock = 1000;
    auto abandoned = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    // Never poll `abandoned`. Jump past ttl AND past the 30s sweep interval, then
    // a fresh dispatch triggers the sweep that drops it.
    clock = 1000 + ttl + 31000;
    orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    CHECK_FALSE(orch.collate(abandoned.correlation_id, "alice", false).has_value());
}

TEST_CASE("orchestrator: an empty principal can never collate (sec-M2/CH-7)",
          "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    BundleOrchestrator orch(fd.fn(), &store, fixed_id("abc"));
    auto res = orch.dispatch("agent-1", two_steps(), /*principal=*/"", null_audit());
    // Even the (empty) dispatcher cannot collate — empty principal never owns.
    CHECK_FALSE(orch.collate(res.correlation_id, "", /*is_admin=*/false).has_value());
    // Admin break-glass still works.
    CHECK(orch.collate(res.correlation_id, "", /*is_admin=*/true).has_value());
}

TEST_CASE("orchestrator: cap eviction drops the oldest manifest (QE-S3)",
          "[pg][bundle][orchestrator]") {
    FakeDispatch fd;
    YUZU_REQUIRE_PG_DB_TPL(db, responsestore_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    ResponseStore store(pool);
    REQUIRE(store.is_open());
    std::int64_t clock = 0;
    int idctr = 0;
    BundleOrchestrator::ClockFn now = [&clock]() { return ++clock; }; // distinct, monotonic
    BundleOrchestrator::IdMinter mint = [&idctr]() { return std::to_string(idctr++); };
    // High TTL so only the CAP evicts; max=2.
    BundleOrchestrator orch(fd.fn(), &store, mint, nullptr, "test", now, /*ttl=*/1'000'000'000,
                            /*max_manifests=*/2);
    auto a = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto b = orch.dispatch("agent-1", two_steps(), "alice", null_audit());
    auto c = orch.dispatch("agent-1", two_steps(), "alice", null_audit()); // cap → evict oldest (a)
    CHECK_FALSE(orch.collate(a.correlation_id, "alice", false).has_value());
    CHECK(orch.collate(b.correlation_id, "alice", false).has_value());
    CHECK(orch.collate(c.correlation_id, "alice", false).has_value());
}
