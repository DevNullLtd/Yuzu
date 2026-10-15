/**
 * test_scope_walking_authz.cpp — cross-operator authorization for the
 * `from_result_set:` scope kind (scope-walking review finding B1).
 *
 * AgentRegistry::evaluate_scope must resolve `from_result_set:<id>` ONLY for a
 * dispatching principal that owns the set. An operator who learns another
 * operator's rs_ id and embeds it in a scope expression must target ZERO of
 * that set's devices (the IDOR the review blocked merge on). The owner check
 * lives in the preload step (ResultSetStore::member_set_owned), scoped to the
 * principal threaded into evaluate_scope; an empty principal (the untracked
 * raw-dispatch path with no operator) resolves nothing.
 */

#include "agent_registry.hpp"
#include "custom_properties_store.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "result_set_store.hpp"
#include "scope_engine.hpp"
#include "scope_yaml.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"

#include "agent.pb.h"

#include <libpq-fe.h>

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::server;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;
namespace agent_pb = ::yuzu::agent::v1;

namespace {

agent_pb::AgentInfo info(const std::string& id) {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(id + ".local");
    return a;
}

bool has(const std::vector<std::string>& v, const std::string& id) {
    return std::find(v.begin(), v.end(), id) != v.end();
}

// ResultSetStore is now a migrated Postgres store (ADR-0036) — shares the
// "resultset" template key with test_result_set_store.cpp (identical setup).
yuzu::test::PgTestTemplate result_set_tpl{"resultset", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResultSetStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}};

} // namespace

TEST_CASE("evaluate_scope: from_result_set is owner-scoped (no cross-operator targeting)",
          "[pg][scope][result_set][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    // Alice curates a set containing only one of the two connected agents.
    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.name = "alice-suspects";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());

    auto expr = yuzu::scope::parse("from_result_set:" + set->id);
    REQUIRE(expr.has_value());

    SECTION("owner resolves exactly the set's members") {
        auto matched = registry.evaluate_scope(*expr, /*tag_store=*/nullptr,
                                               /*props_store=*/nullptr, &store, "alice");
        REQUIRE(matched.has_value()); // no preload degrade (ADR-0036)
        REQUIRE(matched->size() == 1);
        CHECK(has(*matched, "agent-win"));
        CHECK_FALSE(has(*matched, "agent-lin")); // not a broadcast
    }

    SECTION("a non-owner ABORTS the whole evaluation — IDOR blocked (review B1, "
            "#4981 PR-1 A3: no longer a silent empty match)") {
        // Pre-#4981 this resolved to a SUCCESSFUL empty match (member_set_owned's
        // plain owner-filtered JOIN produced zero rows for a foreign id,
        // indistinguishable from "owned, zero members") — which under a NOT
        // combinator elsewhere would invert to "matches every agent" with no DB
        // error required (the same TOCTOU-adjacent fail-open Finding A closes).
        // A3 collapses NotOwner into ScopeEvalError::Kind::OwnerCheckFailed so a
        // caller can never distinguish "doesn't exist" from "exists but isn't
        // yours" — the SAME oracle-safety contract this test's old empty-match
        // behavior was trying (imperfectly) to preserve.
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "bob");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::OwnerCheckFailed);
        CHECK(matched.error().detail == set->id);
    }

    SECTION("empty principal (untracked raw-dispatch path) ABORTS, never silently "
            "no-matches (B2, 2026-07-26 hardening round)") {
        // Pre-B2 this resolved to an empty (but present) match — which under a
        // NOT combinator elsewhere would invert to "matches every agent" purely
        // from a missing principal, no DB error required. A real rs_store is
        // wired here but there is no principal to owner-resolve against, so
        // evaluate_scope must abort, not degrade to "0 matched".
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::PrincipalUnresolved);
    }

    SECTION("an unknown result-set id ABORTS — fail-closed, not match-all (UP-14, "
            "#4981 PR-1 A3: no longer a silent empty match)") {
        auto e2 = yuzu::scope::parse("from_result_set:rs_does_not_exist");
        REQUIRE(e2.has_value());
        auto matched = registry.evaluate_scope(*e2, nullptr, nullptr, &store, "alice");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::OwnerCheckFailed);
        CHECK(matched.error().detail == "rs_does_not_exist");
    }
}

// ── Dispatch-time alias resolution (PR-E) ────────────────────────────────────

TEST_CASE("resolve_scope_aliases: rewrites owner aliases, leaves ids/non-owners",
          "[pg][scope][result_set][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.name = "alice-suspects"; // per-operator alias
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());
    const std::string canonical = "from_result_set:" + set->id;

    SECTION("owner alias is rewritten to the canonical id") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects", "alice", &store) == canonical);
    }
    SECTION("composition: only the ref atom is rewritten") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects AND ostype == \"windows\"",
                                    "alice", &store) == canonical + " AND ostype == \"windows\"");
    }
    SECTION("two refs: the alias resolves, a canonical rs_ id passes through") {
        CHECK(resolve_scope_aliases(
                  "from_result_set:alice-suspects AND from_result_set:" + set->id, "alice",
                  &store) == canonical + " AND " + canonical);
    }
    SECTION("a canonical rs_ id passes through untouched") {
        CHECK(resolve_scope_aliases(canonical, "alice", &store) == canonical);
    }
    SECTION("a non-owner's alias does not resolve (left as-is, no-matches downstream)") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects", "bob", &store) ==
              "from_result_set:alice-suspects");
    }
    SECTION("empty owner is a no-op") {
        CHECK(resolve_scope_aliases("from_result_set:alice-suspects", "", &store) ==
              "from_result_set:alice-suspects");
    }
    SECTION("an alias inside a quoted literal is never rewritten") {
        const std::string e = "hostname == \"from_result_set:alice-suspects\"";
        CHECK(resolve_scope_aliases(e, "alice", &store) == e);
    }
}

TEST_CASE("scope_refs_failing_owner_check: flags absent/unowned, not empty-but-owned",
          "[pg][scope][result_set][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto owned = store.create_materialized(cr, {"agent-win"});
    REQUIRE(owned.has_value());
    auto empty_owned = store.create_materialized(cr, {}); // owned, zero members
    REQUIRE(empty_owned.has_value());

    SECTION("an owned, non-empty set is not flagged") {
        auto f = scope_refs_failing_owner_check("from_result_set:" + owned->id, "alice", &store);
        REQUIRE(f.has_value());
        CHECK(f->empty());
    }
    SECTION("an owned but legitimately empty set is not flagged") {
        auto f =
            scope_refs_failing_owner_check("from_result_set:" + empty_owned->id, "alice", &store);
        REQUIRE(f.has_value());
        CHECK(f->empty());
    }
    SECTION("an absent id is flagged") {
        auto f = scope_refs_failing_owner_check("from_result_set:rs_does_not_exist", "alice", &store);
        REQUIRE(f.has_value());
        REQUIRE(f->size() == 1);
        CHECK((*f)[0] == "rs_does_not_exist");
    }
    SECTION("another operator's id is flagged (not owned)") {
        auto f = scope_refs_failing_owner_check("from_result_set:" + owned->id, "bob", &store);
        REQUIRE(f.has_value());
        REQUIRE(f->size() == 1);
        CHECK((*f)[0] == owned->id);
    }
    SECTION("mixed owned + absent: only the absent ref is flagged") {
        auto f = scope_refs_failing_owner_check(
            "from_result_set:" + owned->id + " AND from_result_set:rs_ghost", "alice", &store);
        REQUIRE(f.has_value());
        REQUIRE(f->size() == 1);
        CHECK((*f)[0] == "rs_ghost");
    }
    SECTION("empty owner yields no findings (no owner context)") {
        auto f = scope_refs_failing_owner_check("from_result_set:" + owned->id, "", &store);
        REQUIRE(f.has_value());
        CHECK(f->empty());
    }
}

// ── ADR-0036 fail-closed regression: a degraded store must ABORT, never ─────
// ── silently expand a NOT-inverted scope to the whole fleet.             ────
//
// The concrete vulnerability this guards: a `NOT from_result_set:<id>` scope
// resolves the atom to "" (no match) for every agent NOT in the (possibly
// empty/degraded) preloaded membership set, and NOT inverts "no match" to
// "match" — so a membership preload that silently came back empty because of
// a transient Postgres error (not because the set is genuinely empty) used to
// make every connected agent match. `evaluate_scope` must instead return
// `std::nullopt` the instant the preload can't be trusted, so the dispatch
// layer aborts (503) rather than sending to "everyone".
TEST_CASE("evaluate_scope: a degraded result-set store ABORTS — never expands a "
          "NOT-inverted scope to the whole fleet",
          "[pg][scope][result_set][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());

    // Simulate a Postgres-side degrade: drop the table `member_set_owned`
    // queries out from under the live store — a reproducible stand-in for a
    // transient connection loss / botched migration, without needing to kill
    // the whole pool (which would also fail is_open()-style checks upstream
    // and hide the specific regression this test targets: a QUERY failure
    // once the store believes it is open).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE result_set_store.result_set_members CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("NOT from_result_set:<id> aborts rather than matching every agent") {
        auto expr = yuzu::scope::parse("NOT from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        // The regression this test exists to catch: pre-fix, a degraded
        // preload silently produced an EMPTY (but present) membership map,
        // so `matched` would come back holding EVERY registered agent under
        // the NOT combinator. Post-fix, degrade is type-distinguishable — an
        // error, never an empty vector — so a caller can never mistake this
        // for "0 matches" or, worse, silently dispatch to `*matched` at all.
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::StoreDegraded);
    }

    SECTION("the plain (non-NOT) form also aborts, never a false empty match") {
        auto expr = yuzu::scope::parse("from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::StoreDegraded);
    }
}

// ── B2 fail-closed regression (2026-07-26 hardening round): an EMPTY ────────
// ── principal must ABORT, never silently expand a NOT-inverted scope to ────
// ── the whole fleet — no DB error required, purely structural.           ────
//
// The concrete vulnerability: `evaluate_scope`'s preload guard used to be
// `if (rs_store && !principal.empty())` — with a real rs_store wired but an
// empty principal (e.g. the tracked/MCP dispatch paths recovering `principal`
// from an execution row's `dispatched_by`, which can miss/be empty), the
// preload loop never ran at all. A `from_result_set:<id>` atom then resolved
// "" (no match) for every agent, and `NOT` inverted that to "matches every
// agent" — a fleet-wide command dispatch reachable with a perfectly healthy
// database, purely from a missing principal.
TEST_CASE("evaluate_scope: an empty principal ABORTS — never expands a NOT-inverted "
          "scope to the whole fleet (B2, no DB degrade needed)",
          "[pg][scope][result_set][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());

    SECTION("NOT from_result_set:<id> with empty principal aborts rather than matching "
            "every agent") {
        auto expr = yuzu::scope::parse("NOT from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        // rs_store IS wired (real store, healthy DB) — only `principal` is
        // empty. Pre-B2 this would have silently matched BOTH agents.
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::PrincipalUnresolved);
    }

    SECTION("the plain (non-NOT) form also aborts, never a false empty match") {
        auto expr = yuzu::scope::parse("from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::PrincipalUnresolved);
    }

    SECTION("a scope WITHOUT a from_result_set: atom is completely unaffected by an "
            "empty principal (narrowness check)") {
        auto expr = yuzu::scope::parse(R"(ostype == "windows")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "");
        REQUIRE(matched.has_value()); // no from_result_set: atom -> never aborts
    }
}

// ── H1 fail-closed regression (2026-07-29 governance round): a NULL store ──
// ── must ABORT a from_result_set: scope, never silently evaluate it false. ──
//
// The concrete vulnerability: the B2 guard above was written INSIDE
// `if (rs_store)`, so the callers that pass NO store at all (the Guardian
// push paths — server.cpp threads neither store nor principal there) skipped
// every guard. A `from_result_set:<id>` atom then resolved "no match" for
// every agent, and `NOT` inverted that to "matches every agent" — for a
// Guardian rule arming an enforcing guard, a fleet-wide arm, reachable with
// no DB and no error anywhere. The header contract even asserted the
// null/null combination "can never degrade". Post-H1 the guard runs for the
// null-store case too: an atom nobody can resolve aborts.
//
// Deliberately NOT [pg]-tagged: no store is constructed — this is the
// null-store arm, and it must hold with no database in the picture at all.
TEST_CASE("evaluate_scope: a NULL result-set store ABORTS a from_result_set scope — "
          "never a silent false-match (H1, no store at all)",
          "[scope][result_set][authz][failclosed]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    SECTION("NOT from_result_set:<id> with a null store aborts rather than matching "
            "every agent") {
        auto expr = yuzu::scope::parse("NOT from_result_set:rs_anything");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, nullptr, "");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::Unresolvable);
    }

    SECTION("the plain (non-NOT) form also aborts") {
        auto expr = yuzu::scope::parse("from_result_set:rs_anything");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, nullptr, "");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::Unresolvable);
    }

    SECTION("an atom buried under a combinator still aborts (the collector walks "
            "the whole AST, not just the root)") {
        auto expr = yuzu::scope::parse("hostname == \"agent-win.local\" AND NOT from_result_set:rs_x");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, nullptr, "");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::Unresolvable);
    }

    SECTION("null store with a NON-empty principal still aborts (branch-message combo)") {
        auto expr = yuzu::scope::parse("from_result_set:rs_anything");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, nullptr, "alice");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::Unresolvable);
    }

    SECTION("a scope with NO from_result_set atom is unaffected — null store stays "
            "legal for plain scopes") {
        auto expr = yuzu::scope::parse("hostname == \"agent-win.local\"");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, nullptr, "");
        REQUIRE(matched.has_value());
        CHECK(matched->size() == 1); // agent-win only
    }
}

// ── M1 regression net (governance round 2, 2026-07-29): the dispatch GATE ──
// ── itself. The pre-M1 bug was each dispatch site auditing the failing    ──
// ── refs and then dispatching anyway; the rule now lives in ONE function  ──
// ── (gate_scope_dispatch) consumed by all three sites, so pinning it here ──
// ── pins the behavior a future edit could silently revert per-site.       ──
TEST_CASE("gate_scope_dispatch: absent/foreign refs ABORT, owned refs proceed",
          "[pg][scope][result_set][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto owned = store.create_materialized(cr, {"agent-win"});
    REQUIRE(owned.has_value());

    std::vector<std::string> failing;

    SECTION("owned ref proceeds") {
        CHECK(gate_scope_dispatch("from_result_set:" + owned->id, "alice", &store, failing) ==
              ScopeDispatchGate::Proceed);
        CHECK(failing.empty());
    }
    SECTION("absent ref aborts with the ref reported") {
        CHECK(gate_scope_dispatch("from_result_set:rs_does_not_exist", "alice", &store, failing) ==
              ScopeDispatchGate::AbortOwnerCheck);
        REQUIRE(failing.size() == 1);
        CHECK(failing[0] == "rs_does_not_exist");
    }
    SECTION("foreign (unowned) ref aborts — indistinguishable from absent by design") {
        CHECK(gate_scope_dispatch("from_result_set:" + owned->id, "bob", &store, failing) ==
              ScopeDispatchGate::AbortOwnerCheck);
        REQUIRE(failing.size() == 1);
    }
    SECTION("NOT over an absent ref still aborts — the inversion the pre-M1 "
            "audit-then-proceed behavior turned into a fleet-wide match") {
        CHECK(gate_scope_dispatch("NOT from_result_set:rs_ghost", "alice", &store, failing) ==
              ScopeDispatchGate::AbortOwnerCheck);
    }
    SECTION("NOT over a foreign ref aborts") {
        CHECK(gate_scope_dispatch("NOT from_result_set:" + owned->id, "bob", &store, failing) ==
              ScopeDispatchGate::AbortOwnerCheck);
    }
    SECTION("a mixed expression with one bad ref aborts the WHOLE gate — no "
            "partial-dispatch semantics") {
        CHECK(gate_scope_dispatch("from_result_set:" + owned->id +
                                      " AND NOT from_result_set:rs_ghost",
                                  "alice", &store, failing) ==
              ScopeDispatchGate::AbortOwnerCheck);
    }
    SECTION("owned-but-EMPTY set proceeds — empty membership is a valid, owned answer") {
        auto empty_owned = store.create_materialized(cr, {});
        REQUIRE(empty_owned.has_value());
        CHECK(gate_scope_dispatch("from_result_set:" + empty_owned->id, "alice", &store,
                                  failing) == ScopeDispatchGate::Proceed);
    }
    SECTION("degraded store aborts as AbortDbDegraded, never OwnerCheck or Proceed") {
        // The owner check probes the result_sets table itself (ownership
        // rows), so THAT is the table to break — dropping only the members
        // table degrades the membership preload (covered by the
        // evaluate_scope degrade test above), not this gate.
        {
            PgConn conn{PQconnectdb(db.dsn().c_str())};
            REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
            PgResult r{PQexec(conn.get(), "DROP TABLE result_set_store.result_sets CASCADE")};
            REQUIRE(r.ok());
        }
        CHECK(gate_scope_dispatch("from_result_set:" + owned->id, "alice", &store, failing) ==
              ScopeDispatchGate::AbortDbDegraded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// #4981 PR-1 Finding A: the TOCTOU race this whole file's "gate_scope_dispatch:
// absent/foreign refs ABORT" test above does NOT cover — the gate is an EARLY
// forensic pass (scope_yaml.hpp's A2 doc comment); the BINDING check is
// evaluate_scope's own member_set_owned preload, which can observe a
// DIFFERENT, later database state. A set that PASSES gate_scope_dispatch can
// still be deleted (explicit delete_set, OR a raw DELETE standing in for a
// gc_sweep pass) before evaluate_scope's own read runs.
// ═══════════════════════════════════════════════════════════════════════════
TEST_CASE("evaluate_scope: a result set deleted AFTER gate_scope_dispatch already returned "
          "Proceed still ABORTS OwnerCheckFailed at evaluate_scope, NEVER a fleet-wide "
          "match (#4981 PR-1 Finding A TOCTOU regression)",
          "[pg][scope][result_set][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";

    SECTION("deleted via the real delete_set path, bare form") {
        auto set = store.create_materialized(cr, {"agent-win"});
        REQUIRE(set.has_value());
        std::vector<std::string> failing;
        REQUIRE(gate_scope_dispatch("from_result_set:" + set->id, "alice", &store, failing) ==
                ScopeDispatchGate::Proceed);
        REQUIRE(store.delete_set(set->id).has_value());

        auto expr = yuzu::scope::parse("from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::OwnerCheckFailed);
        CHECK(matched.error().detail == set->id);
    }

    SECTION("deleted via the real delete_set path, NOT combinator — the concrete "
            "fleet-wide fail-open shape this fix closes") {
        auto set = store.create_materialized(cr, {"agent-win"});
        REQUIRE(set.has_value());
        std::vector<std::string> failing;
        REQUIRE(gate_scope_dispatch("from_result_set:" + set->id, "alice", &store, failing) ==
                ScopeDispatchGate::Proceed);
        REQUIRE(store.delete_set(set->id).has_value());

        auto expr = yuzu::scope::parse("NOT from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        // The regression: pre-#4981, member_set_owned's plain owner-filtered
        // JOIN against the now-gone row produced a SUCCESSFUL empty
        // membership, and NOT inverted that to "matches every agent" —
        // BOTH agent-win and agent-lin. Post-fix this is an ABORT, matching
        // neither.
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::OwnerCheckFailed);
    }

    SECTION("deleted via a raw DELETE (standing in for a gc_sweep pass), bare form") {
        auto set = store.create_materialized(cr, {"agent-win"});
        REQUIRE(set.has_value());
        std::vector<std::string> failing;
        REQUIRE(gate_scope_dispatch("from_result_set:" + set->id, "alice", &store, failing) ==
                ScopeDispatchGate::Proceed);
        {
            PgConn conn{PQconnectdb(db.dsn().c_str())};
            REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
            std::string sql = "DELETE FROM result_set_store.result_sets WHERE id = '" + set->id +
                              "'";
            PgResult r{PQexec(conn.get(), sql.c_str())};
            REQUIRE(r.ok());
        }

        auto expr = yuzu::scope::parse("from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::OwnerCheckFailed);
    }

    SECTION("deleted via a raw DELETE (gc_sweep stand-in), NOT combinator") {
        auto set = store.create_materialized(cr, {"agent-win"});
        REQUIRE(set.has_value());
        std::vector<std::string> failing;
        REQUIRE(gate_scope_dispatch("from_result_set:" + set->id, "alice", &store, failing) ==
                ScopeDispatchGate::Proceed);
        {
            PgConn conn{PQconnectdb(db.dsn().c_str())};
            REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
            std::string sql = "DELETE FROM result_set_store.result_sets WHERE id = '" + set->id +
                              "'";
            PgResult r{PQexec(conn.get(), sql.c_str())};
            REQUIRE(r.ok());
        }

        auto expr = yuzu::scope::parse("NOT from_result_set:" + set->id);
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::OwnerCheckFailed);
    }

    SECTION("compound expression — a deleted result-set atom ANDed with a resolvable "
            "props.<key> atom still aborts OwnerCheckFailed as a whole, never a "
            "partial or fleet-wide match (#4981 PR-1 Finding A, compound-atom coverage)") {
        auto set = store.create_materialized(cr, {"agent-win"});
        REQUIRE(set.has_value());
        std::vector<std::string> failing;
        REQUIRE(gate_scope_dispatch("from_result_set:" + set->id, "alice", &store, failing) ==
                ScopeDispatchGate::Proceed);
        REQUIRE(store.delete_set(set->id).has_value());

        // Shares the pool/db with `store` above; CustomPropertiesStore migrates
        // its own schema on construction regardless of which store's template
        // built this database (see test_props_scope_authz.cpp's identical use).
        CustomPropertiesStore props_store(pool);
        REQUIRE(props_store.is_open());
        REQUIRE(props_store.set_property("agent-win", "role", "web").has_value());

        auto expr = yuzu::scope::parse(R"(props.role == "web" AND from_result_set:)" + set->id);
        REQUIRE(expr.has_value());
        auto matched =
            registry.evaluate_scope(*expr, /*tag_store=*/nullptr, &props_store, &store, "alice");
        // The props.<key> atom resolves cleanly on its own (agent-win has
        // role=web) — only the from_result_set: atom is broken by the TOCTOU
        // delete. A resolver that evaluates atoms independently and merges by
        // AND could produce a PARTIAL match (agent-win, from the props half)
        // instead of aborting the whole expression; that is still a fail-open
        // relative to the "never a fleet/partial match on a broken ref" contract.
        REQUIRE_FALSE(matched.has_value());
        CHECK(matched.error().kind == ScopeEvalError::Kind::OwnerCheckFailed);
        CHECK(matched.error().detail == set->id);
    }
}

// #4981 PR-1 (Finding A/A4): evaluate_scope now touches (extends the TTL of)
// ANY owned result-set reference, empty or not — the pre-#4981 code only
// touched a non-empty owned membership, because an owned-but-empty result was
// indistinguishable from not-owned (touching it risked extending an id that
// might actually belong to someone else). A1 makes owned-empty a real,
// distinguishable success, so it now gets the same "keep alive while actively
// used as scope" treatment (review finding I) a non-empty owned set already
// got.
TEST_CASE("evaluate_scope: touches an owned-but-EMPTY result set used as scope "
          "(#4981 PR-1 A4 — was previously NOT touched)",
          "[pg][scope][result_set][ttl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, result_set_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    ResultSetStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));

    CreateRequest cr;
    cr.owner_principal = "alice";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto empty_owned = store.create_materialized(cr, {}); // owned, ZERO members
    REQUIRE(empty_owned.has_value());
    const int64_t orig_ttl = empty_owned->ttl_at;

    // Force a real observable delta so a touch is detectable even if the
    // whole test runs inside one wall-clock second (touch extends to
    // max(ttl_at, now + kDefaultTtlSeconds) — see ResultSetStore::touch's own
    // doc comment): backdate ttl_at via a raw UPDATE, staying above
    // created_at so the schema's `CHECK (ttl_at >= created_at)` still holds
    // (ttl_at starts at created_at + kDefaultTtlSeconds == +3600; back off by
    // less than that).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        std::string sql = "UPDATE result_set_store.result_sets SET ttl_at = ttl_at - 1000 "
                          "WHERE id = '" +
                          empty_owned->id + "'";
        PgResult r{PQexec(conn.get(), sql.c_str())};
        REQUIRE(r.ok());
    }

    auto expr = yuzu::scope::parse("from_result_set:" + empty_owned->id);
    REQUIRE(expr.has_value());
    auto matched = registry.evaluate_scope(*expr, nullptr, nullptr, &store, "alice");
    REQUIRE(matched.has_value()); // owned-empty is a real success (A1)
    CHECK(matched->empty());

    auto after = store.get(empty_owned->id);
    REQUIRE(after.has_value());
    REQUIRE(after->has_value());
    CHECK((*after)->ttl_at > orig_ttl - 1000); // touched: TTL extended back up
}
