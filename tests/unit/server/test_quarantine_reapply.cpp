/**
 * test_quarantine_reapply.cpp — Layer A (pure) of quarantine_reapply.hpp:
 * the whitelist validator, the params builder, the agent-status-response
 * parser, and the confirms-containment predicate. No I/O, no store, no
 * dispatch — see quarantine_reapply.hpp for why the shared re-dispatch
 * recipe is split this way (mirrors quarantine_dispatch_decision.hpp).
 */

#include "quarantine_reapply.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

using yuzu::server::build_quarantine_reapply_params;
using yuzu::server::endpoint_state_confirms_containment;
using yuzu::server::kQuarantineWhitelistParam;
using yuzu::server::parse_quarantine_endpoint_state;
using yuzu::server::quarantine_whitelist_tokens_safe;
using yuzu::server::QuarantineEndpointState;

// ── quarantine_whitelist_tokens_safe ───────────────────────────────────────

TEST_CASE("quarantine_whitelist_tokens_safe: empty and well-formed inputs",
          "[server][quarantine][reapply]") {
    CHECK(quarantine_whitelist_tokens_safe(""));
    CHECK(quarantine_whitelist_tokens_safe("10.0.0.1"));
    CHECK(quarantine_whitelist_tokens_safe("10.0.0.1,10.0.0.2"));
    CHECK(quarantine_whitelist_tokens_safe("10.0.0.1, 10.0.0.2")); // trims spaces
    CHECK(quarantine_whitelist_tokens_safe("fe80::1"));
    CHECK(quarantine_whitelist_tokens_safe("fe80::1,10.0.0.1"));
    CHECK(quarantine_whitelist_tokens_safe(",")); // both tokens trim to empty, skipped
}

TEST_CASE("quarantine_whitelist_tokens_safe: rejects unsafe tokens",
          "[server][quarantine][reapply]") {
    CHECK_FALSE(quarantine_whitelist_tokens_safe("10.0.0.1;rm -rf /"));
    CHECK_FALSE(quarantine_whitelist_tokens_safe("$(whoami)"));
    CHECK_FALSE(quarantine_whitelist_tokens_safe("10.0.0.1,evil`cmd`"));
    CHECK_FALSE(quarantine_whitelist_tokens_safe("10.0.0.1 10.0.0.2")); // space, not comma
}

TEST_CASE("quarantine_whitelist_tokens_safe: per-token length cap", "[server][quarantine][reapply]") {
    const std::string too_long(46, 'a');
    CHECK_FALSE(quarantine_whitelist_tokens_safe(too_long));
    const std::string exactly_max(45, 'a'); // hex-digit chars, arbitrary but charset-valid
    CHECK(quarantine_whitelist_tokens_safe(exactly_max));
}

// ── build_quarantine_reapply_params ────────────────────────────────────────

TEST_CASE("build_quarantine_reapply_params: empty whitelist yields empty params, not nullopt",
          "[server][quarantine][reapply]") {
    auto params = build_quarantine_reapply_params("");
    REQUIRE(params.has_value());
    CHECK(params->empty());
}

TEST_CASE("build_quarantine_reapply_params: non-empty whitelist sets whitelist_ips only",
          "[server][quarantine][reapply]") {
    auto params = build_quarantine_reapply_params("10.0.0.1,10.0.0.2");
    REQUIRE(params.has_value());
    REQUIRE(params->size() == 1);
    CHECK(params->at(std::string(kQuarantineWhitelistParam)) == "10.0.0.1,10.0.0.2");
    // The stored reason is never dispatched — the plugin takes no reason param.
    CHECK(params->find("reason") == params->end());
}

TEST_CASE("build_quarantine_reapply_params: oversized whitelist is nullopt",
          "[server][quarantine][reapply]") {
    const std::string oversized(513, '1');
    CHECK_FALSE(build_quarantine_reapply_params(oversized).has_value());
}

TEST_CASE("build_quarantine_reapply_params: unsafe whitelist is nullopt",
          "[server][quarantine][reapply]") {
    CHECK_FALSE(build_quarantine_reapply_params("10.0.0.1;evil").has_value());
}

// ── parse_quarantine_endpoint_state ────────────────────────────────────────

TEST_CASE("parse_quarantine_endpoint_state: current (pre-#3429) vocabulary",
          "[server][quarantine][reapply]") {
    CHECK(parse_quarantine_endpoint_state("state|active") == QuarantineEndpointState::active);
    CHECK(parse_quarantine_endpoint_state("state|inactive") == QuarantineEndpointState::inactive);
}

TEST_CASE("parse_quarantine_endpoint_state: #3429 vocabulary — note suffix tolerated",
          "[server][quarantine][reapply]") {
    CHECK(parse_quarantine_endpoint_state("state|active|note|all good") ==
          QuarantineEndpointState::active);
    CHECK(parse_quarantine_endpoint_state("state|partial|note|ipv6 ruleset incomplete") ==
          QuarantineEndpointState::partial);
    CHECK(parse_quarantine_endpoint_state("state|uncertain|note|host unreadable") ==
          QuarantineEndpointState::uncertain);
    CHECK(parse_quarantine_endpoint_state("state|degraded") == QuarantineEndpointState::degraded);
}

TEST_CASE("parse_quarantine_endpoint_state: mutation-gate busy response",
          "[server][quarantine][reapply]") {
    CHECK(parse_quarantine_endpoint_state("status|busy") == QuarantineEndpointState::busy);
}

TEST_CASE("parse_quarantine_endpoint_state: CRLF-terminated lines still match "
          "(#3425 adversarial review K3)",
          "[server][quarantine][reapply][regression]") {
    // A Windows agent (or any wrapped tool) emitting \r\n must not silently
    // stall confirmation forever — a bare \n split alone would leave a
    // trailing \r on the token and "active\r" != "active".
    CHECK(parse_quarantine_endpoint_state("state|active\r\n") == QuarantineEndpointState::active);
    CHECK(parse_quarantine_endpoint_state("state|active\r") == QuarantineEndpointState::active);
    CHECK(parse_quarantine_endpoint_state("state|partial|note|x\r\n") ==
          QuarantineEndpointState::partial);
    CHECK(parse_quarantine_endpoint_state("status|busy\r\n") == QuarantineEndpointState::busy);
    CHECK(parse_quarantine_endpoint_state("preamble\r\nstate|active\r\n") ==
          QuarantineEndpointState::active);
}

TEST_CASE("parse_quarantine_endpoint_state: multi-line payload, state line not first",
          "[server][quarantine][reapply]") {
    CHECK(parse_quarantine_endpoint_state("some runner preamble line\nstate|active") ==
          QuarantineEndpointState::active);
    CHECK(parse_quarantine_endpoint_state("rc=0\nnote: ok\nstate|partial|note|x") ==
          QuarantineEndpointState::partial);
}

TEST_CASE("parse_quarantine_endpoint_state: garbage and empty payloads are unknown, never active",
          "[server][quarantine][reapply]") {
    CHECK(parse_quarantine_endpoint_state("") == QuarantineEndpointState::unknown);
    CHECK(parse_quarantine_endpoint_state("garbage") == QuarantineEndpointState::unknown);
    CHECK(parse_quarantine_endpoint_state("status|quarantined|rules_applied|4") ==
          QuarantineEndpointState::unknown);
    CHECK(parse_quarantine_endpoint_state("state|") == QuarantineEndpointState::unknown);
    CHECK(parse_quarantine_endpoint_state("state|weird_token") == QuarantineEndpointState::unknown);
}

// ── endpoint_state_confirms_containment ────────────────────────────────────

TEST_CASE("endpoint_state_confirms_containment: only active confirms",
          "[server][quarantine][reapply]") {
    CHECK(endpoint_state_confirms_containment(QuarantineEndpointState::active));
    CHECK_FALSE(endpoint_state_confirms_containment(QuarantineEndpointState::partial));
    CHECK_FALSE(endpoint_state_confirms_containment(QuarantineEndpointState::inactive));
    CHECK_FALSE(endpoint_state_confirms_containment(QuarantineEndpointState::uncertain));
    CHECK_FALSE(endpoint_state_confirms_containment(QuarantineEndpointState::degraded));
    CHECK_FALSE(endpoint_state_confirms_containment(QuarantineEndpointState::busy));
    CHECK_FALSE(endpoint_state_confirms_containment(QuarantineEndpointState::unknown));
}

TEST_CASE("endpoint_state_confirms_containment: compile-time exhaustiveness",
          "[server][quarantine][reapply]") {
    static_assert(endpoint_state_confirms_containment(QuarantineEndpointState::active));
    static_assert(!endpoint_state_confirms_containment(QuarantineEndpointState::inactive));
    static_assert(!endpoint_state_confirms_containment(QuarantineEndpointState::busy));
}
