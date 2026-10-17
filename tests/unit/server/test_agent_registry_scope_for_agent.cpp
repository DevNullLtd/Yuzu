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

// An INDEPENDENT oracle for the shared resolver. check_equivalent compares the single-agent
// path with evaluate_scope_local, which resolve every atom through the same function, so a
// resolver bug moves both together. This checks both against a hard-coded id list derived by
// hand from the fixture arithmetic (make_info / populate_stores), not from the evaluator.
void check_exact(const AgentRegistry& registry, const std::string& text, const TagStore* tags,
                 const CustomPropertiesStore* props, const std::set<std::string>& expected) {
    INFO("scope expression: " << text);
    const auto expr = parse_ok(text);
    auto fleet = registry.evaluate_scope_local(expr, tags, props);
    REQUIRE(fleet.has_value());
    CHECK(std::set<std::string>(fleet->begin(), fleet->end()) == expected);
    CHECK(fleet->size() == expected.size());
    auto ids = registered_ids();
    for (const auto& g : ghost_ids())
        ids.push_back(g);
    for (const auto& id : ids) {
        auto single = registry.evaluate_scope_for_agent(id, expr, tags, props);
        INFO("agent: " << id);
        REQUIRE(single.has_value());
        CHECK(*single == expected.contains(id));
    }
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

TEST_CASE("evaluate_scope_for_agent: matches hard-coded expected ids (independent oracle) "
          "with no store wired",
          "[server][agent_registry][scope]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    register_fleet(registry);

    // linux is i%3==0, prod (scopable) is i%5==0, arm64 is i%4==0: i%60==0.
    check_exact(registry, R"X(ostype == "linux" AND tag:env == "prod" AND arch == "arm64")X",
                nullptr, nullptr, {"agent-000", "agent-060", "agent-120", "agent-180"});
    // gold (scopable) is i%7==0, darwin is i%3==2: i%21==14.
    check_exact(registry, R"X(tag:tier == "gold" AND ostype == "darwin")X", nullptr, nullptr,
                {"agent-014", "agent-035", "agent-056", "agent-077", "agent-098", "agent-119",
                 "agent-140", "agent-161", "agent-182", "agent-203", "agent-224"});
    // env=dev is i%5==1, version 0.14.0-rc1 is (i/3)%3==2.
    check_exact(registry, R"X(tag:env == "dev" AND agent_version == "0.14.0-rc1")X", nullptr,
                nullptr,
                {"agent-006", "agent-016", "agent-026", "agent-051", "agent-061", "agent-071",
                 "agent-096", "agent-106", "agent-116", "agent-141", "agent-151", "agent-161",
                 "agent-186", "agent-196", "agent-206", "agent-231"});
    // linux hostnames are "lnx-<i%23>"; 10..19 match the regex; arm64 (i%4==0) is excluded.
    check_exact(registry, R"X(hostname MATCHES "^lnx-1[0-9]$" AND arch != "arm64")X", nullptr,
                nullptr,
                {"agent-015", "agent-018", "agent-033", "agent-039", "agent-042", "agent-057",
                 "agent-063", "agent-081", "agent-087", "agent-102", "agent-105", "agent-111",
                 "agent-126", "agent-129", "agent-150", "agent-153", "agent-171", "agent-174",
                 "agent-177", "agent-195", "agent-198", "agent-201", "agent-219", "agent-222",
                 "agent-225"});
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
          R"X(LEN(props.tier) > 1)X",
          // Synthetic forms (`__len:` / `__startswith:` encodings) of a result-set atom must
          // abort exactly like the bare atom: a collector that matched the raw attribute
          // skipped the abort, resolved the atom empty, and NOT turned that into membership.
          R"X(LEN(from_result_set:rs_abc) > 0)X", R"X(STARTSWITH(from_result_set:rs_abc, "t"))X",
          R"X(NOT (LEN(from_result_set:rs_abc) > 0))X",
          R"X(NOT STARTSWITH(from_result_set:rs_abc, "t"))X"}) {
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

TEST_CASE("evaluate_scope_for_agent: matches hard-coded expected ids (independent oracle) with "
          "real TagStore and CustomPropertiesStore rows",
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

    // Store env=staging is i%10==0 (it overrides the scopable prod), owner alice is i%4==0:
    // i%20==0. The ghost ids carry rows too but have no session, so they are never members.
    check_exact(registry, R"X(tag:env == "staging" AND props.owner == "alice")X", &tags, &props,
                {"agent-000", "agent-020", "agent-040", "agent-060", "agent-080", "agent-100",
                 "agent-120", "agent-140", "agent-160", "agent-180", "agent-200", "agent-220"});
    // Owner bob is i%4==2, tier "22" is i%3==1: i%12==10.
    check_exact(registry, R"X(props.owner == "bob" AND props.tier == "22")X", &tags, &props,
                {"agent-010", "agent-022", "agent-034", "agent-046", "agent-058", "agent-070",
                 "agent-082", "agent-094", "agent-106", "agent-118", "agent-130", "agent-142",
                 "agent-154", "agent-166", "agent-178", "agent-190", "agent-202", "agent-214",
                 "agent-226", "agent-238"});
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

// -- Malformed agent ids (NUL / empty / oversized) ----------------------------

TEST_CASE("evaluate_scope_for_agent: an empty, oversized or NUL-bearing id is never a member, "
          "even under NOT, and takes no session lookup",
          "[server][agent_registry][scope][failclosed]") {
    EventBus bus;
    yuzu::MetricsRegistry metrics;
    AgentRegistry registry(bus, metrics);
    register_fleet(registry);

    const std::string with_nul("agent-000\0x", 11);
    const std::string oversized(257, 'a');
    // Give each malformed id a REAL linux session. Without one, get_session() is null and the
    // result is false for the wrong reason, so deleting the id guard would stay green.
    for (const std::string& id : {std::string{}, oversized, with_nul}) {
        auto info = make_info(0);
        info.set_agent_id(id);
        (void)registry.register_agent(info);
        const auto sess = registry.get_session(id);
        REQUIRE(sess != nullptr);
        REQUIRE(sess->os == "linux");
    }
    for (const char* text :
         {R"X(ostype == "linux")X", R"X(NOT (ostype == "linux"))X", R"X(NOT (tag:env == "x"))X"}) {
        INFO("scope expression: " << text);
        const auto expr = parse_ok(text);
        for (const std::string& id : {std::string{}, oversized, with_nul}) {
            auto single = registry.evaluate_scope_for_agent(id, expr, nullptr);
            REQUIRE(single.has_value());
            CHECK_FALSE(*single);
        }
    }
    // A 256-byte id is the largest legal one: the cap is exclusive of 257 only.
    auto info = make_info(0);
    info.set_agent_id(std::string(256, 'b'));
    (void)registry.register_agent(info);
    auto at_cap = registry.evaluate_scope_for_agent(std::string(256, 'b'),
                                                    parse_ok(R"X(ostype == "linux")X"), nullptr);
    REQUIRE(at_cap.has_value());
    CHECK(*at_cap);
}

TEST_CASE("a NUL-bearing agent id is rejected before any store read",
          "[pg][server][agent_registry][scope][failclosed]") {
    // Defence in depth: libpq text binds take the id as a NUL-terminated string, so an id
    // containing a NUL byte is rejected by the evaluator before any store read.
    YUZU_REQUIRE_PG_DB_TPL(db, scope_for_agent_tpl);
    PgPool pool{{.conninfo = db.dsn(), .size = 2}};
    REQUIRE(pool.valid());
    TagStore tags{pool};
    CustomPropertiesStore props{pool};
    REQUIRE(tags.is_open());
    REQUIRE(props.is_open());

    REQUIRE(tags.set_tag("agent-a", "env", "prod").has_value());
    REQUIRE(props.set_property("agent-a", "owner", "alice").has_value());
    const std::string nul_id("agent-a\0x", 9);

    SECTION("the tag store answers empty for the malformed id") {
        // This section asserts only what the tag store guarantees on its own; it makes no
        // claim about how the custom-properties store answers a malformed id. The evaluator
        // section below never reaches either store for the malformed id.
        auto tm = tags.get_tag_map(nul_id);
        REQUIRE(tm.has_value());
        CHECK(tm->empty());
        // The real id still reads normally.
        auto real = tags.get_tag_map("agent-a");
        REQUIRE(real.has_value());
        CHECK(real->size() == 1);
    }

    SECTION("the evaluator rejects the id before any store read") {
        EventBus bus;
        yuzu::MetricsRegistry metrics;
        AgentRegistry registry(bus, metrics);
        auto info = make_info(1);
        info.set_agent_id(nul_id);  // a session exists for the NUL id
        (void)registry.register_agent(info);

        // Positive atoms: rows stored under agent-a would make these true.
        for (const char* text : {R"X(props.owner == "alice")X", R"X(tag:env == "prod")X"}) {
            INFO("scope expression: " << text);
            auto r = registry.evaluate_scope_for_agent(nul_id, parse_ok(text), &tags, &props);
            REQUIRE(r.has_value());
            CHECK_FALSE(*r);
        }
        // Under NOT a store that merely answered empty would turn the result into "member";
        // the evaluator's own guard keeps it out.
        for (const char* text :
             {R"X(NOT (props.owner == "alice"))X", R"X(NOT (tag:env == "prod"))X"}) {
            INFO("scope expression: " << text);
            auto r = registry.evaluate_scope_for_agent(nul_id, parse_ok(text), &tags, &props);
            REQUIRE(r.has_value());
            CHECK_FALSE(*r);
        }
    }
}

// -- Value-shape and edge-case equivalence (gap tests) ------------------------

namespace {

// Seven agents whose `note` tag AND property carry LIKE/MATCHES/escape-significant text.
const std::vector<std::string>& odd_values() {
    static const std::vector<std::string> v = {
        "a*b", "a?b", "50%", "a_b", R"(c:\dir)", R"(say "hi")", "axb"};
    return v;
}

void populate_odd(AgentRegistry& registry, TagStore& tags, CustomPropertiesStore& props) {
    for (int i = 0; i < static_cast<int>(odd_values().size()); ++i) {
        (void)registry.register_agent(make_info(i));
        REQUIRE(tags.set_tag(agent_name(i), "note", odd_values()[static_cast<std::size_t>(i)])
                    .has_value());
        REQUIRE(props.set_property(agent_name(i), "note", odd_values()[static_cast<std::size_t>(i)])
                    .has_value());
    }
}

} // namespace

TEST_CASE("evaluate_scope_for_agent: values with * ? % _ backslash and quotes behave as the fleet "
          "path does under ==, LIKE and MATCHES (no SQL LIKE semantics leak in)",
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
    populate_odd(registry, tags, props);

    EquivalenceStats stats;
    for (const char* attr : {"tag:note", "props.note"}) {
        const std::string a = attr;
        for (const std::string& text : std::vector<std::string>{
                 a + R"( LIKE "a*b")", a + R"( LIKE "a?b")", a + R"( LIKE "a_b")",
                 a + R"( LIKE "50%")", a + R"( == "50%")", a + R"( == "a*b")",
                 a + R"( == "c:\\dir")", a + R"( == "say \"hi\"")",
                 a + R"( MATCHES "^a.b$")", a + R"( MATCHES "^a_b$")", a + R"( MATCHES "^50%$")",
                 a + R"( CONTAINS "%")", "NOT (" + a + R"( LIKE "a_b"))"})
            check_equivalent(registry, text, &tags, &props, stats);
    }
    CHECK(stats.exprs == 26);

    // Pin the semantics, not only the equivalence: `_` is a literal in LIKE here (a glob, not
    // SQL LIKE), so only the agent whose value is literally "a_b" matches.
    auto underscore = registry.evaluate_scope_local(parse_ok(R"X(tag:note LIKE "a_b")X"), &tags,
                                                    &props);
    REQUIRE(underscore.has_value());
    CHECK(*underscore == std::vector<std::string>{"agent-003"});
}

TEST_CASE("evaluate_scope_for_agent: tag key case, NOT over an absent key and an empty property "
          "value match the fleet path",
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
    for (int i = 0; i < 6; ++i)
        (void)registry.register_agent(make_info(i));
    REQUIRE(tags.set_tag("agent-000", "env", "prod").has_value());
    REQUIRE(tags.set_tag("agent-002", "env", "prod").has_value());
    REQUIRE(props.set_property("agent-001", "owner", "").has_value()); // empty value row
    REQUIRE(props.set_property("agent-003", "owner", "alice").has_value());

    EquivalenceStats stats;
    for (const char* text : {
             R"X(tag:Env == "prod")X",            // key case differs from the stored "env"
             R"X(NOT (tag:Env == "prod"))X",
             R"X(NOT (tag:nokey == "x"))X",       // key present on no agent anywhere
             R"X(tag:nokey != "x")X",
             R"X(NOT (props.nokey == "x"))X",
             R"X(props.owner == "")X",            // the empty-value row
             R"X(EXISTS props.owner)X",
             R"X(NOT (props.owner == ""))X",
             R"X(props.owner != "alice")X",
         })
        check_equivalent(registry, text, &tags, &props, stats);

    // The key-absent NOT is a member for EVERY registered agent on the fleet path; the
    // single-agent path must agree for each, not merely for the ones sampled above.
    auto all_absent = registry.evaluate_scope_local(parse_ok(R"X(NOT (tag:nokey == "x"))X"), &tags,
                                                    &props);
    REQUIRE(all_absent.has_value());
    CHECK(all_absent->size() == 6);
}

TEST_CASE("evaluate_scope_for_agent: a tag-only expression is unaffected by a null or broken "
          "props store; a mixed expression degrades when only props is down",
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
    REQUIRE(tags.set_tag("agent-000", "env", "prod").has_value());

    const auto tag_only = parse_ok(R"X(tag:env == "prod")X");
    const auto mixed = parse_ok(R"X(tag:env == "prod" AND NOT (props.owner == "alice"))X");

    auto with_null = registry.evaluate_scope_for_agent("agent-000", tag_only, &tags, nullptr);
    REQUIRE(with_null.has_value());
    CHECK(*with_null);

    drop_table(db.dsn(), "DROP TABLE custom_properties_store.custom_properties CASCADE");

    auto with_broken = registry.evaluate_scope_for_agent("agent-000", tag_only, &tags, &props);
    REQUIRE(with_broken.has_value()); // no props atom, so no props read
    CHECK(*with_broken);

    auto degraded = registry.evaluate_scope_for_agent("agent-000", mixed, &tags, &props);
    REQUIRE_FALSE(degraded.has_value()); // tags fine, props down: abort, never "member"
    CHECK(degraded.error().kind == ScopeEvalError::Kind::StoreDegraded);
    // And the mixed expression with a null props store is Unresolvable, not degraded.
    auto unresolvable = registry.evaluate_scope_for_agent("agent-000", mixed, &tags, nullptr);
    REQUIRE_FALSE(unresolvable.has_value());
    CHECK(unresolvable.error().kind == ScopeEvalError::Kind::Unresolvable);
}
