/**
 * test_tag_scope_authz.cpp — the ADR-0050 fail-closed contract for
 * `tag:<key>` scope-DSL resolution (AgentRegistry::evaluate_scope).
 *
 * Mirrors test_props_scope_authz.cpp's `props.<key>` degrade coverage: the
 * TagStore migration to Postgres introduced a real runtime failure mode (a
 * pool-acquire timeout, a dropped connection) where SQLite's synchronous
 * read had none, and the pre-migration resolver collapsed "no such tag" and
 * "the read failed" to the same empty string — under `NOT tag:<key>` (or
 * `!=`) a silently-empty resolution is a match, so a transient Postgres blip
 * would invert to "every agent matches" (#2500 family).
 *
 * One deliberate asymmetry vs the props contract (the resolver comment in
 * agent_registry.cpp records it): a NULL tag_store with a tag: atom does NOT
 * abort, because session->scopable_tags is an in-memory FALLBACK source
 * that legitimately answers tag: atoms without any store. A DEGRADED
 * (non-null, failing) store still aborts.
 *
 * #3295: the tag: resolver is STORE-FIRST — a TagStore row (any source)
 * wins over a connected agent's in-memory scopable_tags claim for the same
 * key; scopable_tags answers only when the store has no row for that
 * (agent, key) at all (gateway-proxied agents, or a tag not yet synced).
 * 'service' is dropped from scopable_tags entirely at session ingest
 * (register_agent) and never answers via the fallback.
 */

#include "agent_registry.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "custom_properties_store.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include <yuzu/metrics.hpp>

#include <catch2/catch_test_macros.hpp>

#include "../test_helpers.hpp"
#include "test_tag_store_pg_helper.hpp"

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

// Combined-store template for the mixed tag:+props. case (governance qa-4).
// Its OWN key — a template's setup must construct the same store set as
// every other registrant of that key, so it cannot share "tagstore".
yuzu::test::PgTestTemplate tag_props_tpl{
    "tagprops", [](const std::string& dsn) {
        yuzu::server::pg::PgPool pool{{.conninfo = dsn, .size = 1}};
        TagStore tags{pool};
        CustomPropertiesStore props{pool};
        if (!tags.is_open() || !props.is_open())
            throw std::runtime_error("tagprops template: a store failed to migrate");
    }};

} // namespace

TEST_CASE("evaluate_scope: tag:<key> resolves preloaded store values",
          "[pg][scope][tag_store][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::tag_store_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    REQUIRE(store.set_tag("agent-win", "env", "prod").has_value());
    REQUIRE(store.set_tag("agent-lin", "env", "staging").has_value());

    SECTION("matches only the agent with the tag value") {
        auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, /*props_store=*/nullptr);
        REQUIRE(matched.has_value());
        REQUIRE(matched->size() == 1);
        CHECK(has(*matched, "agent-win"));
        CHECK_FALSE(has(*matched, "agent-lin"));
    }

    SECTION("an operator store row wins over a conflicting in-memory self-report (#3295)") {
        auto shadowed = info("agent-shadow");
        (*shadowed.mutable_scopable_tags())["env"] = "prod";
        (void)registry.register_agent(shadowed);
        REQUIRE(store.set_tag("agent-shadow", "env", "staging").has_value());

        auto matches_env = [&](const char* value) {
            auto expr = yuzu::scope::parse(std::string(R"(tag:env == ")") + value + "\"");
            REQUIRE(expr.has_value());
            auto matched = registry.evaluate_scope(*expr, &store, nullptr);
            REQUIRE(matched.has_value());
            return has(*matched, "agent-shadow");
        };
        CHECK_FALSE(matches_env("prod"));    // in-memory claim no longer wins
        CHECK(matches_env("staging"));       // store row is authoritative
    }

    SECTION("in-memory fallback still answers when the store has no row (gateway-proxied "
            "agents never sync_agent_tags — #3295)") {
        auto gw = info("agent-gw");
        (*gw.mutable_scopable_tags())["env"] = "prod";
        (void)registry.register_agent(gw); // no store.set_tag() for agent-gw at all

        auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
        CHECK(has(*matched, "agent-gw"));
        CHECK(has(*matched, "agent-win")); // the pre-existing store row still matches too
    }

    SECTION("an agent-claimed 'service' tag never answers via the in-memory fallback "
            "(#3295 — dropped at register_agent ingest)") {
        auto claimant = info("agent-claim");
        (*claimant.mutable_scopable_tags())["service"] = "printers";
        (void)registry.register_agent(claimant); // no store row for "service" on agent-claim

        auto eq_expr = yuzu::scope::parse(R"(tag:service == "printers")");
        REQUIRE(eq_expr.has_value());
        auto eq_matched = registry.evaluate_scope(*eq_expr, &store, nullptr);
        REQUIRE(eq_matched.has_value());
        CHECK_FALSE(has(*eq_matched, "agent-claim"));

        auto exists_expr = yuzu::scope::parse(R"(EXISTS tag:service)");
        REQUIRE(exists_expr.has_value());
        auto exists_matched = registry.evaluate_scope(*exists_expr, &store, nullptr);
        REQUIRE(exists_matched.has_value());
        CHECK_FALSE(has(*exists_matched, "agent-claim"));

        // An operator-set store row for the same key still resolves normally —
        // only the agent's OWN self-report is suppressed.
        REQUIRE(store.set_tag("agent-claim", "service", "vending").has_value());
        auto after_store = yuzu::scope::parse(R"(tag:service == "vending")");
        REQUIRE(after_store.has_value());
        auto after_matched = registry.evaluate_scope(*after_store, &store, nullptr);
        REQUIRE(after_matched.has_value());
        CHECK(has(*after_matched, "agent-claim"));
    }

    SECTION("an empty in-memory value cannot mask a non-empty store row (#3295)") {
        auto empty_claim = info("agent-empty");
        (*empty_claim.mutable_scopable_tags())["env"] = "";
        (void)registry.register_agent(empty_claim);
        REQUIRE(store.set_tag("agent-empty", "env", "prod").has_value());

        auto exists_expr = yuzu::scope::parse(R"(EXISTS tag:env)");
        REQUIRE(exists_expr.has_value());
        auto exists_matched = registry.evaluate_scope(*exists_expr, &store, nullptr);
        REQUIRE(exists_matched.has_value());
        CHECK(has(*exists_matched, "agent-empty"));

        auto eq_expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(eq_expr.has_value());
        auto eq_matched = registry.evaluate_scope(*eq_expr, &store, nullptr);
        REQUIRE(eq_matched.has_value());
        CHECK(has(*eq_matched, "agent-empty"));
    }

    SECTION("an empty STORE value is never masked by a non-empty in-memory claim (#3295, "
            "the inverse of the empty-in-memory case above)") {
        auto claim = info("agent-empty-store");
        (*claim.mutable_scopable_tags())["env"] = "prod";
        (void)registry.register_agent(claim);
        REQUIRE(store.set_tag("agent-empty-store", "env", "").has_value());

        // The store row (even empty) is found first and short-circuits before
        // the in-memory fallback is even consulted — the empty store value
        // must win, not the agent's own non-empty claim.
        auto exists_expr = yuzu::scope::parse(R"(EXISTS tag:env)");
        REQUIRE(exists_expr.has_value());
        auto exists_matched = registry.evaluate_scope(*exists_expr, &store, nullptr);
        REQUIRE(exists_matched.has_value());
        CHECK_FALSE(has(*exists_matched, "agent-empty-store"));

        auto eq_expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(eq_expr.has_value());
        auto eq_matched = registry.evaluate_scope(*eq_expr, &store, nullptr);
        REQUIRE(eq_matched.has_value());
        CHECK_FALSE(has(*eq_matched, "agent-empty-store"));
    }

    SECTION("an agent-authored store row from a failed re-sync still beats a fresher "
            "in-memory claim — store stays authoritative, self-heals on next sync (#3295)") {
        auto stale = info("agent-stale-sync");
        (*stale.mutable_scopable_tags())["env"] = "fresh-claim";
        (void)registry.register_agent(stale);
        REQUIRE(store.set_tag("agent-stale-sync", "env", "stale-agent-row", "agent")
                    .has_value());

        auto expr = yuzu::scope::parse(R"(tag:env == "stale-agent-row")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
        CHECK(has(*matched, "agent-stale-sync"));
    }

    SECTION("a scope with no tag: atom triggers no preload") {
        auto expr = yuzu::scope::parse(R"(ostype == "")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
    }
}

// The concrete vulnerability this guards: a `NOT tag:<key>` scope resolves
// the atom to "" (no match) for every agent whose tag couldn't be read
// because of a transient Postgres error, and NOT inverts "no match" to
// "match" — so a degraded preload would make every connected agent match.
// evaluate_scope must instead return std::nullopt the instant the preload
// can't be trusted (mirrors the props.<key>/from_result_set: contract).
TEST_CASE("evaluate_scope: a degraded TagStore ABORTS — never expands a NOT-inverted tag: "
          "scope to the whole fleet",
          "[pg][scope][tag_store][authz][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::tag_store_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-win"));
    (void)registry.register_agent(info("agent-lin"));

    REQUIRE(store.set_tag("agent-win", "env", "prod").has_value());

    // Simulate a Postgres-side degrade: drop the table the preload queries
    // out from under the live store (same mechanism as
    // test_props_scope_authz.cpp — a QUERY failure once the store believes
    // it is open).
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
        REQUIRE(r.ok());
    }

    SECTION("NOT tag:<key> aborts rather than matching every agent") {
        auto expr = yuzu::scope::parse(R"(NOT tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        // Pre-fix (per-agent get_tag collapsing degrade to ""), `matched`
        // would come back holding EVERY registered agent under NOT.
        REQUIRE_FALSE(matched.has_value());
    }

    SECTION("the plain (non-NOT) form also aborts, never a false empty match") {
        auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE_FALSE(matched.has_value());
    }
}

// The deliberate asymmetry vs props.<key>: no store at all is NOT a degrade —
// tags have a first-class in-memory source (scopable_tags) that answers tag:
// atoms without one. In production the store cannot be null post-migration
// (fatal at boot); this is the test/embedded configuration.
TEST_CASE("evaluate_scope: tag:<key> with a NULL TagStore resolves from in-memory "
          "scopable_tags alone (no abort — deliberate asymmetry vs props.<key>)",
          "[scope][tag_store][authz]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    auto tagged = info("agent-mem");
    (*tagged.mutable_scopable_tags())["env"] = "prod";
    (void)registry.register_agent(tagged);
    (void)registry.register_agent(info("agent-bare"));

    auto expr = yuzu::scope::parse(R"(tag:env == "prod")");
    REQUIRE(expr.has_value());
    auto matched = registry.evaluate_scope(*expr, /*tag_store=*/nullptr, nullptr);
    REQUIRE(matched.has_value());
    REQUIRE(matched->size() == 1);
    CHECK(has(*matched, "agent-mem"));

    // NOT form still evaluates (in-memory answers are trustworthy — there is
    // no store whose failure could be hiding).
    auto not_expr = yuzu::scope::parse(R"(NOT tag:env == "prod")");
    REQUIRE(not_expr.has_value());
    auto not_matched = registry.evaluate_scope(*not_expr, nullptr, nullptr);
    REQUIRE(not_matched.has_value());
    CHECK(has(*not_matched, "agent-bare"));
    CHECK_FALSE(has(*not_matched, "agent-mem"));
}

// register_agent's ingest filter (#3295): a 'service' claim and any
// key/value failing TagStore::validate_key/validate_value are dropped
// before session->scopable_tags is populated, so neither can ever answer a
// tag: atom via the in-memory fallback — not just when the store shadows
// them, but unconditionally (e.g. a gateway-proxied agent, where the store
// never has a row at all).
TEST_CASE("register_agent: ingest filter drops invalid/service scopable_tags",
          "[scope][tag_store][authz]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);

    auto claimant = info("agent-ingest");
    auto* tags = claimant.mutable_scopable_tags();
    (*tags)["env"] = "prod";            // valid — survives
    (*tags)["empty"] = "";              // valid (empty VALUE allowed) — survives
    (*tags)["service"] = "printers";    // dropped — is_service_tag_key
    (*tags)["Service"] = "printers";    // dropped — case-insensitive match
    (*tags)[""] = "no-key";             // dropped — validate_key rejects empty key
    (*tags)[std::string(65, 'a')] = "too-long-key";      // dropped — validate_key: max 64
    (*tags)["bad key!"] = "invalid-chars";               // dropped — validate_key: charset
    (*tags)["oversized"] = std::string(449, 'x');         // dropped — validate_value: max 448
    (void)registry.register_agent(claimant);

    auto session = registry.get_session("agent-ingest");
    REQUIRE(session != nullptr);
    CHECK(session->scopable_tags.size() == 2);
    CHECK(session->scopable_tags.at("env") == "prod");
    CHECK(session->scopable_tags.at("empty") == "");
    CHECK(session->scopable_tags.find("service") == session->scopable_tags.end());
    CHECK(session->scopable_tags.find("Service") == session->scopable_tags.end());
    CHECK(session->scopable_tags.find("") == session->scopable_tags.end());
    CHECK(session->scopable_tags.find(std::string(65, 'a')) == session->scopable_tags.end());
    CHECK(session->scopable_tags.find("bad key!") == session->scopable_tags.end());
    CHECK(session->scopable_tags.find("oversized") == session->scopable_tags.end());
    // Two service-key drops ("service" + "Service") — the ONLY signal for a
    // gateway-proxied agent, which never reaches TagStore::sync_agent_tags's
    // own counter (#3295 Gate 6 hardening).
    CHECK(metrics.counter("yuzu_server_agent_registry_service_tag_dropped_total").value() ==
          2.0);
}

// ── collect_attribute_suffixes: synthetic-attribute decoding (governance
// DSL-1/DSL-2). LEN(tag:x) parses to attribute `__len:tag:x` and
// STARTSWITH(tag:x, p) to `__startswith:tag:x`; the collector must decode
// them through the ONE shared classifier (classify_synthetic) or the
// preload silently drops the key — the verified pre-fix defect: store-only
// tags unresolved for those forms, and the degrade abort bypassed for
// synthetic-only expressions. Pure parse+collect — no store, no [pg].

TEST_CASE("collect_attribute_suffixes decodes synthetic __len:/__startswith: forms",
          "[scope][tag_store][dsl]") {
    auto collect = [](const char* text, std::string_view prefix) {
        auto expr = yuzu::scope::parse(text);
        REQUIRE(expr.has_value());
        std::vector<std::string> out;
        yuzu::scope::collect_attribute_suffixes(*expr, prefix, out);
        return out;
    };

    CHECK(collect(R"(tag:env == "prod")", "tag:") == std::vector<std::string>{"env"});
    CHECK(collect(R"(EXISTS tag:env)", "tag:") == std::vector<std::string>{"env"});
    CHECK(collect(R"(LEN(tag:env) > 3)", "tag:") == std::vector<std::string>{"env"});
    CHECK(collect(R"(STARTSWITH(tag:env, "pr"))", "tag:") == std::vector<std::string>{"env"});
    CHECK(collect(R"(NOT STARTSWITH(tag:env, "pr"))", "tag:") ==
          std::vector<std::string>{"env"});
    // Nesting + duplicates preserved (callers dedupe via the map they build).
    CHECK(collect(R"(tag:env == "prod" AND (LEN(tag:env) > 3 OR tag:ring == "fast"))",
                  "tag:") == std::vector<std::string>({"env", "env", "ring"}));
    // The props.<key> prefix decodes the same way (the shared walker fixed
    // the identical pre-existing miss for LEN(props.x) — governance DSL-3).
    CHECK(collect(R"(LEN(props.role) > 2)", "props.") == std::vector<std::string>{"role"});
    // Non-matching prefixes stay out.
    CHECK(collect(R"(LEN(hostname) > 3)", "tag:").empty());
}

TEST_CASE("evaluate_scope: LEN/STARTSWITH over a store-persisted tag resolve through the "
          "preload (governance DSL-1 regression)",
          "[pg][scope][tag_store][authz][dsl]") {
    YUZU_REQUIRE_PG_DB_TPL(db, yuzu::test::tag_store_pg_template);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore store(pool);
    REQUIRE(store.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-tagged"));
    (void)registry.register_agent(info("agent-bare"));

    // Store-only tag: NOT in any session's in-memory scopable_tags — the
    // pre-fix collector missed synthetic forms, so these resolved "" and
    // under-targeted (and their NOT forms dispatched to excluded agents).
    REQUIRE(store.set_tag("agent-tagged", "env", "prod").has_value());

    SECTION("STARTSWITH matches the store-tagged agent only") {
        auto expr = yuzu::scope::parse(R"(STARTSWITH(tag:env, "pr"))");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
        REQUIRE(matched->size() == 1);
        CHECK(has(*matched, "agent-tagged"));
    }

    SECTION("NOT STARTSWITH excludes the tagged agent (the over-target killer)") {
        auto expr = yuzu::scope::parse(R"(NOT STARTSWITH(tag:env, "pr"))");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
        CHECK_FALSE(has(*matched, "agent-tagged"));
        CHECK(has(*matched, "agent-bare"));
    }

    SECTION("LEN over the store tag") {
        auto expr = yuzu::scope::parse(R"(LEN(tag:env) >= 4)");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE(matched.has_value());
        REQUIRE(matched->size() == 1);
        CHECK(has(*matched, "agent-tagged"));
    }

    SECTION("a degraded store aborts a synthetic-only expression (degrade-bypass killer)") {
        {
            PgConn conn{PQconnectdb(db.dsn().c_str())};
            REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
            PgResult r{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
            REQUIRE(r.ok());
        }
        auto expr = yuzu::scope::parse(R"(STARTSWITH(tag:env, "pr"))");
        REQUIRE(expr.has_value());
        auto matched = registry.evaluate_scope(*expr, &store, nullptr);
        REQUIRE_FALSE(matched.has_value()); // abort, never a silent no-match
    }
}

TEST_CASE("evaluate_scope: a single expression mixing tag: and props. atoms runs both "
          "preloads (governance qa-4)",
          "[pg][scope][tag_store][custom_props][authz]") {
    YUZU_REQUIRE_PG_DB_TPL(db, tag_props_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore tags(pool);
    REQUIRE(tags.is_open());
    CustomPropertiesStore props(pool);
    REQUIRE(props.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(info("agent-both"));
    (void)registry.register_agent(info("agent-tag-only"));
    (void)registry.register_agent(info("agent-neither"));

    REQUIRE(tags.set_tag("agent-both", "env", "prod").has_value());
    REQUIRE(tags.set_tag("agent-tag-only", "env", "prod").has_value());
    REQUIRE(props.set_property("agent-both", "role", "web").has_value());

    auto expr = yuzu::scope::parse(R"(tag:env == "prod" AND props.role == "web")");
    REQUIRE(expr.has_value());
    auto matched = registry.evaluate_scope(*expr, &tags, &props);
    REQUIRE(matched.has_value());
    REQUIRE(matched->size() == 1);
    CHECK(has(*matched, "agent-both"));

    // Degrading the shared substrate aborts the evaluation through EITHER
    // preload — never a partial result from whichever preload ran first.
    {
        PgConn conn{PQconnectdb(db.dsn().c_str())};
        REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
        PgResult r{PQexec(conn.get(), "DROP TABLE tag_store.tags CASCADE")};
        REQUIRE(r.ok());
    }
    auto degraded = registry.evaluate_scope(*expr, &tags, &props);
    REQUIRE_FALSE(degraded.has_value());
}
