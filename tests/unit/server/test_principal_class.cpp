// principal_class presentation classifier (ADR-1005, execution-plan PR 1.2)
// and the resolved-session classifier (execution-plan PR 4.5). Pins the
// closed value set {human, agent, none, engine}, the machine-signal-wins
// precedence, and the anchored cookie-name match for principal_class_of;
// pins the hybrid-basis contract (engine=resolved, else presentation) for
// principal_class_resolved.

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

#include <httplib.h>

#include "principal_class.hpp"

using yuzu::server::principal_class_of;
using yuzu::server::principal_class_resolved;

namespace {
httplib::Request req_with(std::initializer_list<std::pair<std::string, std::string>> headers) {
    httplib::Request req;
    for (const auto& [k, v] : headers) req.headers.emplace(k, v);
    return req;
}

// RAII guard: sets the tls_engine_principal() stash for the scope of a test
// case and always resets it to false on scope exit, so a failing assertion
// (or forgotten manual reset) can't leak state into a later test case —
// the thread_local persists across TEST_CASEs run on the same worker thread.
struct EnginePrincipalStash {
    explicit EnginePrincipalStash(bool value) {
        yuzu::server::detail::tls_engine_principal() = value;
    }
    ~EnginePrincipalStash() { yuzu::server::detail::tls_engine_principal() = false; }
    EnginePrincipalStash(const EnginePrincipalStash&) = delete;
    EnginePrincipalStash& operator=(const EnginePrincipalStash&) = delete;
};
}  // namespace

TEST_CASE("bearer token classifies as agent", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Authorization", "Bearer abc"}})) == "agent");
    CHECK(principal_class_of(req_with({{"X-Yuzu-Token", "abc"}})) == "agent");
}

TEST_CASE("session cookie classifies as human", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Cookie", "yuzu_session=s1"}})) == "human");
    CHECK(principal_class_of(req_with({{"Cookie", "theme=dark; yuzu_session=s1"}})) == "human");
}

TEST_CASE("cookie-name match is anchored, not substring", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Cookie", "not_yuzu_session=s1"}})) == "none");
    CHECK(principal_class_of(req_with({{"Cookie", "a=b; xyuzu_session=s1"}})) == "none");
    // A cookie VALUE containing the literal must not classify either.
    CHECK(principal_class_of(req_with({{"Cookie", "other=yuzu_session=x"}})) == "none");
}

TEST_CASE("no credential classifies as none", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({})) == "none");
    CHECK(principal_class_of(req_with({{"Cookie", "theme=dark"}})) == "none");
}

TEST_CASE("machine signal wins over ambient cookie", "[principal-class][adr1005]") {
    CHECK(principal_class_of(req_with({{"Cookie", "yuzu_session=s1"},
                                       {"Authorization", "Bearer abc"}})) == "agent");
}

// -- principal_class_resolved (PR 4.5) — hybrid basis contract --------------

TEST_CASE("resolved engine stash wins regardless of presentation",
          "[principal-class][adr1005][pr4.5]") {
    EnginePrincipalStash stash{true};
    // Bearer header present — presentation alone would say "agent".
    CHECK(principal_class_resolved(req_with({{"Authorization", "Bearer abc"}})) == "engine");
    // Session cookie present — presentation alone would say "human".
    CHECK(principal_class_resolved(req_with({{"Cookie", "yuzu_session=s1"}})) == "engine");
    // No credential at all — presentation alone would say "none".
    CHECK(principal_class_resolved(req_with({})) == "engine");
    // Both a cookie AND a bearer header present — presentation alone would
    // say "agent" (machine signal wins over ambient cookie); the resolved
    // stash still wins.
    CHECK(principal_class_resolved(req_with({{"Cookie", "yuzu_session=s1"},
                                             {"Authorization", "Bearer abc"}})) == "engine");
}

TEST_CASE("resolved classifier falls back to presentation when not an engine session",
          "[principal-class][adr1005][pr4.5]") {
    EnginePrincipalStash stash{false};
    CHECK(principal_class_resolved(req_with({{"Authorization", "Bearer abc"}})) == "agent");
    CHECK(principal_class_resolved(req_with({{"Cookie", "yuzu_session=s1"}})) == "human");
    CHECK(principal_class_resolved(req_with({})) == "none");
}
