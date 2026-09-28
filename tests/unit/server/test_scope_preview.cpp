/**
 * test_scope_preview.cpp — #4981 PR-2: `scope_preview.hpp`'s rewrite onto the
 * real `resolve_scope_targets` ladder (dispatch_scope_ladder.hpp), the same
 * ladder a real dispatch uses.
 *
 * Root cause this file guards against (#4981): the pre-PR-2 preview builder
 * evaluated a scope expression against a bespoke per-agent attribute resolver
 * that only ever populated `ostype`/`arch`/`hostname`/`agent_version`/
 * `tag:<key>` — a `from_result_set:<id>` or `props.<key>` atom always
 * resolved "" (unset), so the atom's comparison was always false, and
 * `NOT from_result_set:<id>` inverted that to match EVERY agent regardless of
 * the set's real membership. This is the concrete fleet-wide over-disclosure
 * regression test (see the "NOT from_result_set" TEST_CASE below).
 */

#include "scope_preview.hpp"

#include "agent_registry.hpp"
#include "authz_model.hpp"
#include "custom_properties_store.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "result_set_store.hpp"
#include "scope_engine.hpp"

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

agent_pb::AgentInfo info(const std::string& id, const std::string& os = "linux",
                        const std::string& arch = "x64") {
    agent_pb::AgentInfo a;
    a.set_agent_id(id);
    a.set_hostname(id + ".local");
    a.mutable_platform()->set_os(os);
    a.mutable_platform()->set_arch(arch);
    return a;
}

/// A canned ScopeEvaluateFn stub for tests that don't need a real registry —
/// the ladder's OWN alias-resolution/owner-check-gate steps still run for
/// real (both are no-ops with a null ResultSetStore* and/or no
/// from_result_set: atom in the expression, per scope_yaml.hpp's documented
/// contract), so a plain attribute expression reaches this stub unchanged.
ScopeEvaluateFn stub_fn(std::expected<std::vector<std::string>, ScopeEvalError> result) {
    return [result](const yuzu::scope::Expression&, const std::string&) { return result; };
}

// Shares the "resultset"/"customprops" template keys with
// test_scope_walking_authz.cpp / test_props_scope_authz.cpp (identical
// setup, cached template DB reused across test binaries in the same run).
yuzu::test::PgTestTemplate result_set_tpl{"resultset", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    ResultSetStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("resultset template: store failed to migrate");
}};

yuzu::test::PgTestTemplate props_tpl{"customprops", [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    CustomPropertiesStore store{pool};
    if (!store.is_open())
        throw std::runtime_error("customprops template: store failed to migrate");
}};

} // namespace

// ── Invalid expression ───────────────────────────────────────────────────

TEST_CASE("preview_scope_targets: invalid expression syntax reports kInvalidExpression",
          "[scope][preview]") {
    auto outcome = preview_scope_targets("tag:env ==", "alice", std::nullopt, nullptr,
                                         stub_fn(std::vector<std::string>{}));
    CHECK(outcome.kind == ScopePreviewOutcome::Kind::kInvalidExpression);
    CHECK(outcome.detail.starts_with("Invalid scope:"));
}

TEST_CASE("preview_scope_targets: an empty expression string still reports kInvalidExpression",
          "[scope][preview]") {
    auto outcome =
        preview_scope_targets("", "alice", std::nullopt, nullptr, stub_fn(std::vector<std::string>{}));
    CHECK(outcome.kind == ScopePreviewOutcome::Kind::kInvalidExpression);
}

// ── evaluate_scope_fn abort surface — every ScopeEvalError::Kind ────────────

TEST_CASE("preview_scope_targets: evaluate_scope_fn aborting surfaces kEvaluationAborted with "
          "the correct reason string, never a silent 0-match",
          "[scope][preview]") {
    SECTION("Unresolvable") {
        auto outcome = preview_scope_targets(
            R"(ostype == "linux")", "alice", std::nullopt, nullptr,
            stub_fn(std::unexpected(ScopeEvalError{ScopeEvalError::Kind::Unresolvable, ""})));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "unresolvable");
        CHECK(outcome.failing_refs.empty());
    }
    SECTION("PrincipalUnresolved") {
        auto outcome = preview_scope_targets(
            R"(ostype == "linux")", "", std::nullopt, nullptr,
            stub_fn(std::unexpected(ScopeEvalError{ScopeEvalError::Kind::PrincipalUnresolved, ""})));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "principal_unresolved");
        CHECK(outcome.failing_refs.empty());
    }
    SECTION("StoreDegraded") {
        auto outcome = preview_scope_targets(
            R"(ostype == "linux")", "alice", std::nullopt, nullptr,
            stub_fn(std::unexpected(ScopeEvalError{ScopeEvalError::Kind::StoreDegraded, ""})));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "db_degraded");
        CHECK(outcome.failing_refs.empty());
    }
    SECTION("PresenceDegraded") {
        auto outcome = preview_scope_targets(
            R"(ostype == "linux")", "alice", std::nullopt, nullptr,
            stub_fn(std::unexpected(ScopeEvalError{ScopeEvalError::Kind::PresenceDegraded, ""})));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "presence_degraded");
        CHECK(outcome.failing_refs.empty());
    }
    SECTION("OwnerCheckFailed carries the failing ref for the caller's own audit row") {
        auto outcome = preview_scope_targets(
            R"(ostype == "linux")", "alice", std::nullopt, nullptr,
            stub_fn(std::unexpected(
                ScopeEvalError{ScopeEvalError::Kind::OwnerCheckFailed, "rs_ghost"})));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "owner_check_failed");
        REQUIRE(outcome.failing_refs.size() == 1);
        CHECK(outcome.failing_refs[0] == "rs_ghost");
    }
}

// ── Blast-radius warning ─────────────────────────────────────────────────

TEST_CASE("preview_scope_targets: warns above the 50-agent threshold", "[scope][preview]") {
    std::vector<std::string> many;
    for (int i = 0; i < 51; ++i)
        many.push_back("agent-" + std::to_string(i));

    auto outcome = preview_scope_targets(R"(ostype == "linux")", "alice", std::nullopt, nullptr,
                                         stub_fn(many));
    REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
    CHECK(outcome.payload["matched_count"] == 51);
    REQUIRE(outcome.payload.contains("warning"));
}

TEST_CASE("preview_scope_targets: no warning at or below the 50-agent threshold",
          "[scope][preview]") {
    std::vector<std::string> exactly_fifty;
    for (int i = 0; i < 50; ++i)
        exactly_fifty.push_back("agent-" + std::to_string(i));

    auto outcome = preview_scope_targets(R"(ostype == "linux")", "alice", std::nullopt, nullptr,
                                         stub_fn(exactly_fifty));
    REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
    CHECK(outcome.payload["matched_count"] == 50);
    CHECK_FALSE(outcome.payload.contains("warning"));
}

// ── Confinement (`visible`) — applied AFTER the (unfiltered) ladder match ──

TEST_CASE("preview_scope_targets: confinement via the visible set", "[scope][preview]") {
    const std::vector<std::string> fleet_match{"agent-1", "agent-2", "agent-3"};

    SECTION("nullopt == unfiltered: every ladder match survives") {
        auto outcome = preview_scope_targets(R"(ostype == "linux")", "alice", std::nullopt,
                                             nullptr, stub_fn(fleet_match));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
        CHECK(outcome.payload["matched_count"] == 3);
    }
    SECTION("present-empty == deny-all: every ladder match is filtered out") {
        auto outcome = preview_scope_targets(R"(ostype == "linux")", "alice", authz::deny_all(),
                                             nullptr, stub_fn(fleet_match));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
        CHECK(outcome.payload["matched_count"] == 0);
        CHECK(outcome.payload["matched_agents"].empty());
    }
    SECTION("a real subset narrows the ladder's fleet-wide match to the caller's own visible "
            "devices, never the whole fleet") {
        authz::VisibleSet visible{std::unordered_set<std::string>{"agent-2"}};
        auto outcome =
            preview_scope_targets(R"(ostype == "linux")", "alice", visible, nullptr, stub_fn(fleet_match));
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
        CHECK(outcome.payload["matched_count"] == 1);
        REQUIRE(outcome.payload["matched_agents"].size() == 1);
        CHECK(outcome.payload["matched_agents"][0] == "agent-2");
    }
}

// ── Null ResultSetStore* aborts a from_result_set:/props. atom (mirrors ────
// ── PR-1's H1 null-store fail-closed pattern) — no Postgres needed: a real ──
// ── in-memory AgentRegistry, evaluate_scope bound with every store null. ────

TEST_CASE("preview_scope_targets: a null ResultSetStore* aborts a from_result_set: atom, "
          "never a silent 0-match (H1 fail-closed pattern)",
          "[scope][preview][failclosed]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    auto evaluate_scope_fn = [&](const yuzu::scope::Expression& expr, const std::string& principal) {
        return registry.evaluate_scope(expr, nullptr, nullptr, nullptr, principal);
    };

    SECTION("bare form") {
        auto outcome = preview_scope_targets("from_result_set:rs_anything", "alice", std::nullopt,
                                             /*result_set_store=*/nullptr, evaluate_scope_fn);
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "unresolvable");
    }
    SECTION("NOT form — the fail-open shape #4981 closes") {
        auto outcome = preview_scope_targets("NOT from_result_set:rs_anything", "alice",
                                             std::nullopt, /*result_set_store=*/nullptr,
                                             evaluate_scope_fn);
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "unresolvable");
    }
}

TEST_CASE("preview_scope_targets: a null CustomPropertiesStore* aborts a props.<key> atom",
          "[scope][preview][failclosed]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));

    auto evaluate_scope_fn = [&](const yuzu::scope::Expression& expr, const std::string& principal) {
        return registry.evaluate_scope(expr, nullptr, nullptr, nullptr, principal);
    };
    auto outcome = preview_scope_targets(R"(props.role == "web")", "alice", std::nullopt, nullptr,
                                         evaluate_scope_fn);
    REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
    CHECK(outcome.detail == "unresolvable");
}

// ── #4981 regression: the real bug — NOT from_result_set: with an owned, ──
// ── valid set now correctly EXCLUDES that agent, never "matches everyone" ──

TEST_CASE("preview_scope_targets: NOT from_result_set:<id> over an owned, valid set correctly "
          "excludes that set's members instead of matching the whole fleet (#4981)",
          "[pg][scope][preview]") {
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
    cr.name = "alice-suspects";
    cr.source_kind = std::string(source_kind::kManualCurate);
    cr.source_payload = "{}";
    auto set = store.create_materialized(cr, {"agent-win"});
    REQUIRE(set.has_value());

    auto evaluate_scope_fn = [&](const yuzu::scope::Expression& expr, const std::string& principal) {
        return registry.evaluate_scope(expr, nullptr, nullptr, &store, principal);
    };

    SECTION("bare form matches exactly the set's member") {
        auto outcome = preview_scope_targets("from_result_set:" + set->id, "alice", std::nullopt,
                                             &store, evaluate_scope_fn);
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
        CHECK(outcome.payload["matched_count"] == 1);
        CHECK(outcome.payload["matched_agents"][0] == "agent-win");
    }
    SECTION("NOT form correctly excludes agent-win — the pre-#4981 bug matched BOTH agents "
            "(the resolver never populated from_result_set: at all, so the atom always "
            "resolved unset, and NOT inverted that to match everyone)") {
        auto outcome = preview_scope_targets("NOT from_result_set:" + set->id, "alice",
                                             std::nullopt, &store, evaluate_scope_fn);
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
        CHECK(outcome.payload["matched_count"] == 1);
        CHECK(outcome.payload["matched_agents"][0] == "agent-lin");
    }
    SECTION("a foreign (unowned) reference ABORTS — never a silent fleet-wide match") {
        auto outcome = preview_scope_targets("NOT from_result_set:" + set->id, "bob", std::nullopt,
                                             &store, evaluate_scope_fn);
        REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kEvaluationAborted);
        CHECK(outcome.detail == "owner_check_failed");
        REQUIRE(outcome.failing_refs.size() == 1);
        CHECK(outcome.failing_refs[0] == set->id);
    }
}

// ── props.<key> resolves correctly against a real CustomPropertiesStore ────

TEST_CASE("preview_scope_targets: props.<key> resolves against a real CustomPropertiesStore",
          "[pg][scope][preview]") {
    YUZU_REQUIRE_PG_DB_TPL(db, props_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    CustomPropertiesStore store(pool);
    REQUIRE(store.is_open());
    REQUIRE(store.set_property("agent-web", "role", "web").has_value());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-web"));
    (void)registry.register_agent(info("agent-db"));

    auto evaluate_scope_fn = [&](const yuzu::scope::Expression& expr, const std::string& principal) {
        return registry.evaluate_scope(expr, nullptr, &store, nullptr, principal);
    };

    auto outcome = preview_scope_targets(R"(props.role == "web")", "alice", std::nullopt, nullptr,
                                         evaluate_scope_fn);
    REQUIRE(outcome.kind == ScopePreviewOutcome::Kind::kOk);
    CHECK(outcome.payload["matched_count"] == 1);
    CHECK(outcome.payload["matched_agents"][0] == "agent-web");
}
