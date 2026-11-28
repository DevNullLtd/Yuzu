/**
 * test_execution_owner_key.cpp -- #5557: ExecutionOwnerKey / execution_owner_key().
 *
 * Pure unit tests, no I/O and no PG. The key is the ONLY identity an ownership-based execution
 * admission may compare against `Execution::dispatched_by`; a service-scoped session's
 * `username` is its MINTING account, so its key must be empty. These tests pin the derivation
 * per session class and the type-level properties that keep a bare string out of the compare.
 * The behaviour tests for the call sites that use the key sit beside their routes
 * (test_execution_owner_{rest_v1,legacy,dashboard}.cpp, test_mcp_server.cpp,
 * test_execution_mutation_owner_key.cpp).
 */

#include "execution_scope_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <concepts>
#include <initializer_list>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

auth::Session make_session(const std::string& username) {
    auth::Session s;
    s.username = username;
    return s;
}

Execution dispatched_by(const std::string& who) {
    Execution e;
    e.dispatched_by = who;
    return e;
}

} // namespace

// The key cannot be built from a string, which is what stops a call site passing the minting
// account (or any other raw identity) into an ownership compare.
static_assert(!std::is_convertible_v<std::string, ExecutionOwnerKey>);
static_assert(!std::is_constructible_v<ExecutionOwnerKey, std::string>);
static_assert(!std::is_constructible_v<ExecutionOwnerKey, const char*>);
static_assert(std::is_default_constructible_v<ExecutionOwnerKey>);
static_assert(std::is_nothrow_default_constructible_v<ExecutionOwnerKey>);

TEST_CASE("execution_owner_key: a plain human session keys on its own username",
          "[execution][owner_key][5557]") {
    const auto key = execution_owner_key(make_session("mina"));
    CHECK_FALSE(key.empty());
    CHECK(key.owns(dispatched_by("mina")));
    CHECK_FALSE(key.owns(dispatched_by("carol")));
}

TEST_CASE("execution_owner_key: a service-scoped session owns nothing, tiered or not",
          "[execution][owner_key][5557]") {
    auto s = make_session("mina");
    s.token_scope_service = "A";
    auto key = execution_owner_key(s);
    CHECK(key.empty());
    // The leak this change closes: the minting account's own dispatch must not be owned.
    CHECK_FALSE(key.owns(dispatched_by("mina")));

    s.mcp_tier = "readonly";
    s.auth_source = "mcp_token";
    key = execution_owner_key(s);
    CHECK(key.empty());
    CHECK_FALSE(key.owns(dispatched_by("mina")));
}

TEST_CASE("execution_owner_key: an MCP tier without a service scope keeps the username",
          "[execution][owner_key][5557]") {
    // A tier caps operations, not data scope (the header comment says so; do not "fix" it).
    for (const char* tier : {"readonly", "operator", "supervised"}) {
        auto s = make_session("bob");
        s.mcp_tier = tier;
        s.auth_source = "mcp_token";
        const auto key = execution_owner_key(s);
        CHECK_FALSE(key.empty());
        CHECK(key.owns(dispatched_by("bob")));
        CHECK_FALSE(key.owns(dispatched_by("mina")));
    }
}

TEST_CASE("execution_owner_key: an engine session keeps its principal; a corrupted service "
          "scope on an engine row empties the key",
          "[execution][owner_key][5557]") {
    auto s = make_session("engine:inventory");
    s.principal_kind = "engine";
    s.auth_source = "engine_token";
    auto key = execution_owner_key(s);
    CHECK_FALSE(key.empty());
    CHECK(key.owns(dispatched_by("engine:inventory")));

    // Minting refuses this combination; a corrupted row still gets the empty key because the
    // service scope is tested before the principal kind.
    s.token_scope_service = "A";
    key = execution_owner_key(s);
    CHECK(key.empty());
    CHECK_FALSE(key.owns(dispatched_by("engine:inventory")));
}

TEST_CASE("execution_owner_key: an empty username owns nothing, even an empty dispatched_by",
          "[execution][owner_key][5557]") {
    // The detail, events, SSE and get_execution_status ownership compares used to carry an
    // unguarded "empty username owns an empty dispatched_by" admit; every one of them now goes
    // through this key, which owns nothing. Unreachable in production (session creation rejects
    // an empty username), pinned here so the compare cannot quietly come back.
    const auto key = execution_owner_key(make_session(""));
    CHECK(key.empty());
    CHECK_FALSE(key.owns(dispatched_by("")));
    CHECK_FALSE(key.owns(dispatched_by("mina")));

    auto scoped = make_session("");
    scoped.token_scope_service = "A";
    CHECK(execution_owner_key(scoped).empty());
}

TEST_CASE("ExecutionOwnerKey: a default-constructed key owns nothing",
          "[execution][owner_key][5557]") {
    const ExecutionOwnerKey key;
    CHECK(key.empty());
    CHECK_FALSE(key.owns(dispatched_by("")));
    CHECK_FALSE(key.owns(dispatched_by("mina")));
}

namespace {

auth::Session service_scoped(const std::string& minter, const std::string& service) {
    auto s = make_session(minter);
    s.token_scope_service = service;
    return s;
}

AgentExecStatus status_row(const std::string& agent, const std::string& st = "success") {
    AgentExecStatus a;
    a.agent_id = agent;
    a.status = st;
    return a;
}

authz::VisibleSet agents(std::initializer_list<const char*> ids) {
    std::unordered_set<std::string> set;
    for (const char* id : ids)
        set.emplace(id);
    return authz::VisibleSet{std::move(set)};
}

} // namespace

// A plain string argument must not compile against the visibility/admission predicates: the
// typed key is the only overload (#5557), so the minting account cannot be passed by habit.
template <class Owner>
concept VisibleWith = requires(const Execution& e, const std::vector<AgentExecStatus>& st,
                               const authz::VisibleSet& sc, const Owner& o) {
    { execution_visible(e, st, sc, o) } -> std::same_as<bool>;
};
template <class Owner>
concept AdmitsWith = requires(const Execution& e, const std::vector<AgentExecStatus>& st,
                              const authz::VisibleSet& sc, const Owner& o) {
    { admit_confined_mutation(e, st, sc, o) } -> std::same_as<bool>;
};
static_assert(VisibleWith<ExecutionOwnerKey> && AdmitsWith<ExecutionOwnerKey>);
static_assert(!VisibleWith<std::string> && !AdmitsWith<std::string>);
static_assert(!VisibleWith<const char*> && !AdmitsWith<const char*>);

TEST_CASE("owner_only_filter: carries the key's principal, empty for the empty key",
          "[execution][owner_key][5557]") {
    CHECK(owner_only_filter(execution_owner_key(make_session("bob"))) == "bob");
    // A service-scoped session's key is empty: the filter is then ExecutionQuery's "no filter"
    // sentinel, which is why the one consumer routes that class through confined_list_scope.
    CHECK(owner_only_filter(execution_owner_key(service_scoped("mina", "A"))).empty());
    CHECK(owner_only_filter(ExecutionOwnerKey{}).empty());
}

TEST_CASE("confined_list_scope: unrestricted scope is nullopt whatever the key is",
          "[execution][owner_key][5557]") {
    CHECK_FALSE(confined_list_scope(execution_owner_key(make_session("mina")), std::nullopt)
                    .has_value());
    CHECK_FALSE(
        confined_list_scope(execution_owner_key(service_scoped("mina", "A")), std::nullopt)
            .has_value());
}

TEST_CASE("confined_list_scope: an engaged scope carries the key and the visible agents",
          "[execution][owner_key][5557]") {
    auto human = confined_list_scope(execution_owner_key(make_session("bob")), agents({"a1"}));
    REQUIRE(human.has_value());
    CHECK(human->owner == "bob");
    CHECK(human->visible_agents == std::vector<std::string>{"a1"});

    // A service-scoped session: the minting account is NOT carried; agents are.
    auto svc = confined_list_scope(execution_owner_key(service_scoped("mina", "A")),
                                   agents({"a1"}));
    REQUIRE(svc.has_value());
    CHECK(svc->owner.empty());
    CHECK(svc->visible_agents == std::vector<std::string>{"a1"});
}

TEST_CASE("confined_list_scope: an empty key over an empty engaged scope is visible-to-nobody, "
          "not no-filter",
          "[execution][owner_key][5557]") {
    auto none = confined_list_scope(execution_owner_key(service_scoped("mina", "C")),
                                    authz::deny_all());
    REQUIRE(none.has_value()); // engaged, not nullopt (nullopt would mean unrestricted)
    CHECK(none->owner.empty());
    CHECK(none->visible_agents.empty());
}

TEST_CASE("execution_visible (typed): the key never constrains an unrestricted scope",
          "[execution][owner_key][5557]") {
    // Documents the boundary: an owner key is not a gate. Refusing unrestricted authority to a
    // service-scoped session is the fleet-read gate's job.
    const auto empty_key = execution_owner_key(service_scoped("mina", "A"));
    CHECK(execution_visible(dispatched_by("carol"), {}, std::nullopt, empty_key));
}

TEST_CASE("execution_visible (typed): an engaged scope admits on agent evidence or ownership",
          "[execution][owner_key][5557]") {
    const auto bob = execution_owner_key(make_session("bob"));
    const auto svc = execution_owner_key(service_scoped("mina", "A"));
    const auto scope = agents({"a1", "a2"});

    // Agent evidence admits regardless of the key.
    CHECK(execution_visible(dispatched_by("carol"), {status_row("a2")}, scope, bob));
    CHECK(execution_visible(dispatched_by("carol"), {status_row("a2")}, scope, svc));
    // An out-of-scope agent row does not.
    CHECK_FALSE(execution_visible(dispatched_by("carol"), {status_row("z1")}, scope, svc));
    // Ownership admits a non-service caller with zero rows...
    CHECK(execution_visible(dispatched_by("bob"), {}, scope, bob));
    // ...and NEVER a service-scoped one: its minter's own pending execution stays hidden.
    CHECK_FALSE(execution_visible(dispatched_by("mina"), {}, scope, svc));
    CHECK_FALSE(execution_visible(dispatched_by("mina"), {status_row("z1")}, scope, svc));
    // Engaged-empty scope with an empty key: visible to nobody.
    CHECK_FALSE(execution_visible(dispatched_by("mina"), {}, authz::deny_all(), svc));
}

TEST_CASE("admit_confined_mutation (typed): the zero-row window admits the dispatcher only, "
          "never an empty key",
          "[execution][owner_key][5557]") {
    const auto mina = execution_owner_key(make_session("mina"));
    const auto svc = execution_owner_key(service_scoped("mina", "A"));
    const auto scope = agents({"a1"});
    Execution exec = dispatched_by("mina");
    exec.agents_targeted = 1;

    CHECK(admit_confined_mutation(exec, {}, scope, mina));
    CHECK_FALSE(admit_confined_mutation(exec, {}, scope, svc));
    CHECK_FALSE(admit_confined_mutation(exec, {}, scope, ExecutionOwnerKey{}));

    // With rows the cohort proof decides, not ownership: a complete in-scope cohort admits an
    // empty key; an incomplete or out-of-scope cohort refuses even the dispatcher.
    CHECK(admit_confined_mutation(exec, {status_row("a1")}, scope, svc));
    CHECK_FALSE(admit_confined_mutation(exec, {status_row("z1")}, scope, mina));
    exec.agents_targeted = 2;
    CHECK_FALSE(admit_confined_mutation(exec, {status_row("a1")}, scope, mina));
}
