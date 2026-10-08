// AgentRegistry::evaluate_scope_for_agent -- the single-agent scope evaluator
// the Guardian heartbeat reconcile uses so it does not build the whole fleet's
// matching-id vector (#5513).
//
// The contract under test is EQUIVALENCE with the fleet path: for every agent,
//     evaluate_scope_for_agent(id, expr) == (id is in evaluate_scope_local(expr))
// for every scope kind in scope_kind_catalog() and the combinators (NOT being
// the dangerous one: a swallowed read failure inverts to "member").
//
// The TagStore and CustomPropertiesStore are Postgres-only in this tree (no
// in-memory double exists), so the cases that need store rows are tagged [pg]
// and SKIP without YUZU_TEST_POSTGRES_DSN. The cases that need none (session
// identity kinds, the scopable_tags fallback, Unresolvable, unknown agent) run
// everywhere.

#include <catch2/catch_test_macros.hpp>

#include "agent_registry.hpp"
#include "custom_properties_store.hpp"
#include "event_bus.hpp"
#include "pg/pg_pool.hpp"
#include "pg/pg_raii.hpp"
#include "scope_engine.hpp"
#include "tag_store.hpp"

#include "../test_helpers.hpp"

#include <yuzu/metrics.hpp>

#include <libpq-fe.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using yuzu::server::CustomPropertiesStore;
using yuzu::server::ScopeEvalError;
using yuzu::server::TagStore;
using yuzu::server::detail::AgentRegistry;
using yuzu::server::detail::EventBus;
using yuzu::server::detail::scope_kind_catalog;
using yuzu::server::pg::PgConn;
using yuzu::server::pg::PgPool;
using yuzu::server::pg::PgResult;

namespace agent_pb = ::yuzu::agent::v1;

namespace {

constexpr int kAgents = 240;

std::string agent_name(int i) {
    std::string n = std::to_string(i);
    while (n.size() < 3)
        n.insert(n.begin(), '0');
    return "agent-" + n;
}

const char* os_of(int i) {
    static constexpr const char* kOs[] = {"linux", "windows", "darwin"};
    return kOs[i % 3];
}

std::string hostname_of(int i) {
    static constexpr const char* kPrefix[] = {"lnx-", "WIN-", "mac-"};
    return std::string(kPrefix[i % 3]) + std::to_string(i % 23);
}

const char* arch_of(int i) {
    return i % 4 == 0 ? "arm64" : "x86_64";
}

const char* version_of(int i) {
    static constexpr const char* kVer[] = {"0.12.0", "0.13.0", "0.14.0-rc1"};
    return kVer[(i / 3) % 3];
}

// Self-reported scopable tags (the in-memory FALLBACK source of tag:<key>).
// env=prod for i%5==0, env=dev for i%5==1, none otherwise; tier=gold for i%7==0.
agent_pb::AgentInfo make_info(int i) {
    agent_pb::AgentInfo a;
    a.set_agent_id(agent_name(i));
    a.set_hostname(hostname_of(i));
    a.mutable_platform()->set_os(os_of(i));
    a.mutable_platform()->set_arch(arch_of(i));
    a.set_agent_version(version_of(i));
    if (i % 5 == 0)
        (*a.mutable_scopable_tags())["env"] = "prod";
    else if (i % 5 == 1)
        (*a.mutable_scopable_tags())["env"] = "dev";
    if (i % 7 == 0)
        (*a.mutable_scopable_tags())["tier"] = "gold";
    return a;
}

// Registers the synthetic fleet. No store content.
void register_fleet(AgentRegistry& registry) {
    for (int i = 0; i < kAgents; ++i)
        (void)registry.register_agent(make_info(i));
}

std::vector<std::string> registered_ids() {
    std::vector<std::string> ids;
    ids.reserve(kAgents);
    for (int i = 0; i < kAgents; ++i)
        ids.push_back(agent_name(i));
    return ids;
}

// Ids that are NOT registered (no session on this replica) but DO carry store
// rows, so a regression that consults the stores before the session lookup, or
// that treats a store row as membership, shows up as a wrong "true".
std::vector<std::string> ghost_ids() {
    return {"ghost-001", "ghost-002", "ghost-003", "no-such-agent"};
}

// Store rows chosen to collide with the scopable_tags above:
//   i%10==0 : store env="staging"  (overrides scopable env=prod: STORE WINS)
//   i%10==1 : store env=""         (an engaged EMPTY store value still wins
//                                   over scopable env=dev -- #3295)
//   i%10==3 : store env="prod"     (no scopable env for i%5==3)
//   i%4==1  : region="eu";  i%4==2 : region="us"
// Properties: i%2==0 -> owner (alice when i%4==0 else bob); i%3==0 -> tier "1",
// i%3==1 -> tier "22".
void populate_stores(TagStore& tags, CustomPropertiesStore& props) {
    for (int i = 0; i < kAgents; ++i) {
        const std::string id = agent_name(i);
        if (i % 10 == 0)
            REQUIRE(tags.set_tag(id, "env", "staging").has_value());
        else if (i % 10 == 1)
            REQUIRE(tags.set_tag(id, "env", "").has_value());
        else if (i % 10 == 3)
            REQUIRE(tags.set_tag(id, "env", "prod").has_value());
        if (i % 4 == 1)
            REQUIRE(tags.set_tag(id, "region", "eu").has_value());
        else if (i % 4 == 2)
            REQUIRE(tags.set_tag(id, "region", "us").has_value());
        if (i % 2 == 0)
            REQUIRE(props.set_property(id, "owner", i % 4 == 0 ? "alice" : "bob").has_value());
        if (i % 3 == 0)
            REQUIRE(props.set_property(id, "tier", "1").has_value());
        else if (i % 3 == 1)
            REQUIRE(props.set_property(id, "tier", "22").has_value());
    }
    for (const auto& g : ghost_ids()) {
        REQUIRE(tags.set_tag(g, "env", "prod").has_value());
        REQUIRE(tags.set_tag(g, "region", "eu").has_value());
        REQUIRE(props.set_property(g, "owner", "alice").has_value());
        REQUIRE(props.set_property(g, "tier", "1").has_value());
    }
}

// One entry per scope_kind_catalog() kind (keyed by ScopeKindInfo::kind), so a
// kind added to the catalog without a row here fails the coverage check below.
// from_result_set:<id> has no row: it cannot resolve on either path (no
// ResultSetStore) and is covered by its own Unresolvable test.
struct KindExprs {
    std::string kind;
    std::vector<std::string> exprs;
};

const std::vector<KindExprs>& kind_exprs() {
    static const std::vector<KindExprs> table = {
        {"ostype",
         {R"X(ostype == "linux")X", R"X(ostype != "linux")X",
          R"X(ostype IN ("windows", "darwin"))X", R"X(NOT (ostype == "darwin"))X"}},
        {"hostname",
         {R"X(hostname LIKE "WIN-*")X", R"X(hostname MATCHES "^lnx-1[0-9]$")X",
          R"X(STARTSWITH(hostname, "mac-"))X", R"X(hostname CONTAINS "-2")X",
          R"X(NOT (hostname LIKE "lnx-*"))X"}},
        {"arch", {R"X(arch == "arm64")X", R"X(NOT (arch == "arm64"))X", R"X(arch != "arm64")X"}},
        {"agent_version",
         {R"X(agent_version == "0.13.0")X", R"X(agent_version LIKE "0.14*")X",
          R"X(LEN(agent_version) > 5)X", R"X(NOT (agent_version == "0.12.0"))X"}},
        {"tag:<key>",
         {R"X(tag:env == "prod")X", R"X(tag:env != "prod")X", R"X(NOT (tag:env == "prod"))X",
          R"X(EXISTS tag:env)X", R"X(tag:env == "")X", R"X(tag:env == "staging")X",
          R"X(tag:region == "eu")X",
          R"X(NOT (tag:region == "eu" OR tag:env == "dev"))X", R"X(LEN(tag:env) > 3)X",
          R"X(STARTSWITH(tag:env, "pr"))X", R"X(tag:tier == "gold")X",
          R"X(NOT (NOT (tag:env == "dev")))X"}},
        {"props.<key>",
         {R"X(props.owner == "alice")X", R"X(props.owner != "alice")X",
          R"X(NOT (props.owner == "bob"))X", R"X(EXISTS props.tier)X",
          R"X(LEN(props.tier) > 1)X", R"X(props.tier IN ("1", "22"))X"}},
    };
    return table;
}

// Combinators across kinds; NOT over a store-sourced atom is the dangerous
// shape (an unresolved atom resolving "" would invert to "member").
const std::vector<std::string>& combinator_exprs() {
    static const std::vector<std::string> v = {
        R"X(ostype == "linux" AND tag:env == "prod")X",
        R"X((ostype == "windows" OR arch == "arm64") AND NOT (props.owner == "alice"))X",
        R"X(NOT (ostype == "linux" AND tag:region == "us") OR props.tier == "1")X",
        R"X(NOT (tag:env == "prod" OR props.owner == "alice" OR hostname LIKE "mac-*"))X",
        R"X(tag:region == "eu" AND props.tier == "22" AND agent_version != "0.12.0")X",
    };
    return v;
}

yuzu::scope::Expression parse_ok(const std::string& text) {
    auto parsed = yuzu::scope::parse(text);
    INFO("scope expression: " << text);
    REQUIRE(parsed.has_value());
    return std::move(*parsed);
}

struct EquivalenceStats {
    std::size_t exprs{0};
    std::size_t selective{0}; // 0 < matched < fleet: the case actually discriminates
};

// The property under test. For one expression: the single-agent verdict for
// every registered id AND every ghost id equals membership in the fleet path's
// matching-id vector.
void check_equivalent(const AgentRegistry& registry, const std::string& text, const TagStore* tags,
                      const CustomPropertiesStore* props, EquivalenceStats& stats) {
    INFO("scope expression: " << text);
    const auto expr = parse_ok(text);
    auto fleet = registry.evaluate_scope_local(expr, tags, props);
    REQUIRE(fleet.has_value());
    const std::set<std::string> members(fleet->begin(), fleet->end());
    REQUIRE(members.size() == fleet->size()); // the fleet path never repeats an id

    auto ids = registered_ids();
    for (const auto& g : ghost_ids())
        ids.push_back(g);
    for (const auto& id : ids) {
        auto single = registry.evaluate_scope_for_agent(id, expr, tags, props);
        INFO("agent: " << id);
        REQUIRE(single.has_value());
        CHECK(*single == members.contains(id));
    }
    ++stats.exprs;
    if (!members.empty() && members.size() < static_cast<std::size_t>(kAgents))
        ++stats.selective;
}

void check_catalog_covered() {
    std::set<std::string> covered{"from_result_set:<id>"};
    for (const auto& k : kind_exprs())
        covered.insert(k.kind);
    for (const auto& info : scope_kind_catalog()) {
        INFO("scope_kind_catalog() kind has no equivalence row: " << info.kind);
        CHECK(covered.contains(info.kind));
    }
}

yuzu::test::PgTestTemplate scope_for_agent_tpl{"agent_scope_one",
                                               [](const std::string& dsn) {
    PgPool pool{{.conninfo = dsn, .size = 1}};
    TagStore tags{pool};
    CustomPropertiesStore props{pool};
    if (!tags.is_open() || !props.is_open())
        throw std::runtime_error("agent_scope_one template: store failed to migrate");
}};

void drop_table(const std::string& dsn, const char* sql) {
    PgConn conn{PQconnectdb(dsn.c_str())};
    REQUIRE(PQstatus(conn.get()) == CONNECTION_OK);
    PgResult r{PQexec(conn.get(), sql)};
    REQUIRE(r.ok());
}

} // namespace

// -- No-store cases (run everywhere) ------------------------------------------

TEST_CASE("evaluate_scope_for_agent: equals fleet membership for the session-identity kinds and "
          "the scopable_tags fallback, with no store wired",
          "[server][agent_registry][scope]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    register_fleet(registry);

    EquivalenceStats stats;
    // Only kinds that need no store: tag:<key> resolves from scopable_tags here.
    for (const auto& k : kind_exprs()) {
        if (k.kind == "props.<key>")
            continue; // a props atom with no store is Unresolvable (own test below)
        for (const auto& text : k.exprs)
            check_equivalent(registry, text, nullptr, nullptr, stats);
    }
    CHECK(stats.exprs >= 25);
    // Most expressions must actually split the fleet, or the equivalence above
    // is vacuous (all-false == all-false).
    CHECK(stats.selective * 10 >= stats.exprs * 7);
}

TEST_CASE("evaluate_scope_for_agent: an agent with no session on this replica is not a member, "
          "even under NOT",
          "[server][agent_registry][scope]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_info(0));

    for (const char* text : {R"X(ostype == "linux")X", R"X(NOT (ostype == "linux"))X",
                             R"X(NOT (tag:env == "prod"))X", R"X(tag:env != "prod")X"}) {
        INFO("scope expression: " << text);
        const auto expr = parse_ok(text);
        auto single = registry.evaluate_scope_for_agent("never-registered", expr, nullptr);
        REQUIRE(single.has_value());
        CHECK_FALSE(*single);
        // Same answer the fleet path gives: the id is simply not in the vector.
        auto fleet = registry.evaluate_scope_local(expr, nullptr);
        REQUIRE(fleet.has_value());
        CHECK(std::find(fleet->begin(), fleet->end(), "never-registered") == fleet->end());
    }
}

TEST_CASE("evaluate_scope_for_agent: Unresolvable for from_result_set: and for props.<key> with no "
          "store, for ANY agent id, same Kind as the fleet path",
          "[server][agent_registry][scope][failclosed]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_info(0));

    for (const char* text :
         {R"X(from_result_set:rs_abc)X", R"X(NOT (from_result_set:rs_abc))X",
          R"X(ostype == "linux" AND from_result_set:rs_abc)X", R"X(props.owner == "alice")X",
          R"X(NOT (props.owner == "alice"))X", R"X(EXISTS props.tier)X",
          R"X(LEN(props.tier) > 1)X"}) {
        INFO("scope expression: " << text);
        const auto expr = parse_ok(text);
        auto fleet = registry.evaluate_scope_local(expr, nullptr, nullptr);
        REQUIRE_FALSE(fleet.has_value());
        CHECK(fleet.error().kind == ScopeEvalError::Kind::Unresolvable);
        // A registered id AND an unknown id: the structural abort is returned
        // before the session lookup, exactly as the fleet path returns it for
        // any fleet.
        for (const char* id : {"agent-000", "never-registered"}) {
            INFO("agent: " << id);
            auto single = registry.evaluate_scope_for_agent(id, expr, nullptr, nullptr);
            REQUIRE_FALSE(single.has_value());
            CHECK(single.error().kind == ScopeEvalError::Kind::Unresolvable);
        }
    }
}

TEST_CASE("evaluate_scope_for_agent: a null tag_store with a tag: atom does NOT abort; "
          "scopable_tags answers",
          "[server][agent_registry][scope]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_info(0)); // scopable env=prod
    (void)registry.register_agent(make_info(1)); // scopable env=dev

    const auto expr = parse_ok(R"X(tag:env == "prod")X");
    auto a0 = registry.evaluate_scope_for_agent("agent-000", expr, nullptr);
    REQUIRE(a0.has_value());
    CHECK(*a0);
    auto a1 = registry.evaluate_scope_for_agent("agent-001", expr, nullptr);
    REQUIRE(a1.has_value());
    CHECK_FALSE(*a1);
}

TEST_CASE("evaluate_scope_for_agent: reads the CURRENT session, so a re-registration is "
          "reflected on the next call (nothing is memoised)",
          "[server][agent_registry][scope]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    auto info = make_info(0); // linux
    (void)registry.register_agent(info);

    const auto expr = parse_ok(R"X(ostype == "windows")X");
    auto before = registry.evaluate_scope_for_agent("agent-000", expr, nullptr);
    REQUIRE(before.has_value());
    CHECK_FALSE(*before);

    info.mutable_platform()->set_os("windows");
    (void)registry.register_agent(info);
    auto after = registry.evaluate_scope_for_agent("agent-000", expr, nullptr);
    REQUIRE(after.has_value());
    CHECK(*after);
}

// -- Store-backed cases ([pg]) ------------------------------------------------

TEST_CASE("evaluate_scope_for_agent: equals fleet membership for EVERY scope kind and the "
          "combinators, with real TagStore and CustomPropertiesStore rows",
          "[pg][server][agent_registry][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scope_for_agent_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 4}};
    REQUIRE(pool.valid());
    TagStore tags{pool};
    CustomPropertiesStore props{pool};
    REQUIRE(tags.is_open());
    REQUIRE(props.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    register_fleet(registry);
    populate_stores(tags, props);

    check_catalog_covered();

    EquivalenceStats stats;
    for (const auto& k : kind_exprs())
        for (const auto& text : k.exprs)
            check_equivalent(registry, text, &tags, &props, stats);
    for (const auto& text : combinator_exprs())
        check_equivalent(registry, text, &tags, &props, stats);

    CHECK(stats.exprs >= 35);
    CHECK(stats.selective * 10 >= stats.exprs * 7);
}

TEST_CASE("evaluate_scope_for_agent: store-first tag precedence (#3295), including an engaged "
          "EMPTY store value, matches the fleet path",
          "[pg][server][agent_registry][scope]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scope_for_agent_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    TagStore tags{pool};
    CustomPropertiesStore props{pool};
    REQUIRE(tags.is_open());
    REQUIRE(props.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_info(0)); // scopable env=prod
    (void)registry.register_agent(make_info(1)); // scopable env=dev
    REQUIRE(tags.set_tag("agent-000", "env", "staging").has_value()); // store overrides scopable
    REQUIRE(tags.set_tag("agent-001", "env", "").has_value());        // empty store value wins

    auto prod = registry.evaluate_scope_for_agent("agent-000", parse_ok(R"X(tag:env == "prod")X"),
                                                  &tags);
    REQUIRE(prod.has_value());
    CHECK_FALSE(*prod); // the self-reported "prod" must NOT win over the store
    auto staging = registry.evaluate_scope_for_agent(
        "agent-000", parse_ok(R"X(tag:env == "staging")X"), &tags);
    REQUIRE(staging.has_value());
    CHECK(*staging);
    auto dev = registry.evaluate_scope_for_agent("agent-001", parse_ok(R"X(tag:env == "dev")X"),
                                                 &tags);
    REQUIRE(dev.has_value());
    CHECK_FALSE(*dev); // the empty store row hides the scopable fallback
}

TEST_CASE("evaluate_scope_for_agent: a degraded TagStore read returns StoreDegraded, never false "
          "and never true, even under NOT",
          "[pg][server][agent_registry][scope][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scope_for_agent_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    TagStore tags{pool};
    CustomPropertiesStore props{pool};
    REQUIRE(tags.is_open());
    REQUIRE(props.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_info(0));

    drop_table(db.dsn(), "DROP TABLE tag_store.tags CASCADE");

    for (const char* text : {R"X(tag:env == "prod")X", R"X(NOT (tag:env == "prod"))X",
                             R"X(tag:env != "prod")X", R"X(ostype == "linux" OR tag:env == "x")X"}) {
        INFO("scope expression: " << text);
        const auto expr = parse_ok(text);
        // The fleet path aborts the same way (its bulk preload degrades).
        auto fleet = registry.evaluate_scope_local(expr, &tags, &props);
        REQUIRE_FALSE(fleet.has_value());
        CHECK(fleet.error().kind == ScopeEvalError::Kind::StoreDegraded);
        auto single = registry.evaluate_scope_for_agent("agent-000", expr, &tags, &props);
        REQUIRE_FALSE(single.has_value());
        CHECK(single.error().kind == ScopeEvalError::Kind::StoreDegraded);
    }

    // An expression that never references tag:<key> performs no tag read and is
    // unaffected by the broken table (same as the fleet path: no preload).
    auto unaffected = registry.evaluate_scope_for_agent(
        "agent-000", parse_ok(R"X(ostype == "linux")X"), &tags, &props);
    REQUIRE(unaffected.has_value());
    CHECK(*unaffected);

    // Documented difference: an agent with no session returns false WITHOUT a
    // store read, so a degraded store is not surfaced for it.
    auto ghost = registry.evaluate_scope_for_agent(
        "never-registered", parse_ok(R"X(NOT (tag:env == "prod"))X"), &tags, &props);
    REQUIRE(ghost.has_value());
    CHECK_FALSE(*ghost);
}

TEST_CASE("evaluate_scope_for_agent: a degraded CustomPropertiesStore read returns StoreDegraded, "
          "never false and never true, even under NOT",
          "[pg][server][agent_registry][scope][failclosed]") {
    YUZU_REQUIRE_PG_DB_TPL(db, scope_for_agent_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    TagStore tags{pool};
    CustomPropertiesStore props{pool};
    REQUIRE(tags.is_open());
    REQUIRE(props.is_open());

    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    (void)registry.register_agent(make_info(0));

    drop_table(db.dsn(), "DROP TABLE custom_properties_store.custom_properties CASCADE");

    for (const char* text :
         {R"X(props.owner == "alice")X", R"X(NOT (props.owner == "alice"))X",
          R"X(props.owner != "alice")X", R"X(EXISTS props.tier)X",
          R"X(ostype == "linux" AND NOT (props.owner == "bob"))X"}) {
        INFO("scope expression: " << text);
        const auto expr = parse_ok(text);
        auto fleet = registry.evaluate_scope_local(expr, &tags, &props);
        REQUIRE_FALSE(fleet.has_value());
        CHECK(fleet.error().kind == ScopeEvalError::Kind::StoreDegraded);
        auto single = registry.evaluate_scope_for_agent("agent-000", expr, &tags, &props);
        REQUIRE_FALSE(single.has_value());
        CHECK(single.error().kind == ScopeEvalError::Kind::StoreDegraded);
    }
}
