/**
 * test_quarantine_reapply.cpp — Layer A (pure) of quarantine_reapply.hpp:
 * the whitelist-to-exceptions mapper, the params builder, the firewall
 * status-reply parser and the confirms-containment predicate. No I/O, no
 * store, no dispatch — see quarantine_reapply.hpp
 * for why the shared re-dispatch recipe is split this way (mirrors
 * quarantine_dispatch_decision.hpp).
 */

#include "quarantine_reapply.hpp"

// The agent's own grammar, included by relative path so the server's mapper is tested against the
// code the device runs (#7585a). Header-only, standard library only.
#include "../../../agents/plugins/firewall/src/firewall_quarantine_parsers.hpp"

#include <yuzu/protective_actions.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using yuzu::server::build_quarantine_reapply_params;
using yuzu::server::kContainmentApplyAction;
using yuzu::server::kContainmentPlugin;
using yuzu::server::kContainmentReleaseAction;
using yuzu::server::kContainmentStatusAction;
using yuzu::server::kWhitelistInvalidMessage;
using yuzu::server::kWhitelistTooLongMessage;
using yuzu::server::ContainmentReply;
using yuzu::server::endpoint_state_name;
using yuzu::server::kContainmentExceptionsParam;
using yuzu::server::kContainmentMaxAddresses;
using yuzu::server::kAllowSetUnchangedNote;
using yuzu::server::kQuarantineWhitelistMaxLen;
using yuzu::server::map_whitelist_to_exceptions;
using yuzu::server::parse_containment_reply;
using yuzu::server::QuarantineEndpointState;
using yuzu::server::reply_confirms_containment;

namespace {

std::string n_addresses(std::size_t n) {
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        if (!out.empty())
            out += ',';
        out += "10.0." + std::to_string(i / 250) + "." + std::to_string(1 + i % 250);
    }
    return out;
}

} // namespace

// ── map_whitelist_to_exceptions ────────────────────────────────────────────

TEST_CASE("map_whitelist_to_exceptions: an empty or all-blank whitelist maps to the empty string",
          "[server][quarantine][reapply]") {
    CHECK(map_whitelist_to_exceptions("") == std::string{});
    CHECK(map_whitelist_to_exceptions(" , ,") == std::string{});
    CHECK(map_whitelist_to_exceptions(",") == std::string{});
}

TEST_CASE("map_whitelist_to_exceptions: each address becomes an /out and an /in exception, order kept",
          "[server][quarantine][reapply]") {
    CHECK(map_whitelist_to_exceptions("10.0.0.5") == "10.0.0.5/out,10.0.0.5/in");
    CHECK(map_whitelist_to_exceptions("2001:db8::1") == "2001:db8::1/out,2001:db8::1/in");
    CHECK(map_whitelist_to_exceptions("fe80::1,10.0.0.1") ==
          "fe80::1/out,fe80::1/in,10.0.0.1/out,10.0.0.1/in");
    // spaces trimmed, empty tokens skipped, no de-duplication (the agent de-duplicates)
    CHECK(map_whitelist_to_exceptions(" 10.0.0.1 ,, 10.0.0.1 ") ==
          "10.0.0.1/out,10.0.0.1/in,10.0.0.1/out,10.0.0.1/in");
}

TEST_CASE("map_whitelist_to_exceptions: refuses anything the agent's exception grammar cannot express",
          "[server][quarantine][reapply]") {
    CHECK_FALSE(map_whitelist_to_exceptions("10.0.0.5:443").has_value()); // a port
    CHECK_FALSE(map_whitelist_to_exceptions("10.0.0.0/8").has_value());   // a prefix (charset)
    CHECK_FALSE(map_whitelist_to_exceptions("010.0.0.1").has_value());    // leading-zero octet
    CHECK_FALSE(map_whitelist_to_exceptions("10.00.0.1").has_value());
    CHECK_FALSE(map_whitelist_to_exceptions("1.2.3").has_value());         // not four octets
    CHECK_FALSE(map_whitelist_to_exceptions("::ffff:1.2.3.4").has_value()); // IPv4-mapped
    CHECK_FALSE(map_whitelist_to_exceptions("abc:def").has_value());        // not a valid IPv6
    CHECK_FALSE(map_whitelist_to_exceptions("10.0.0.1;rm -rf /").has_value());
    CHECK_FALSE(map_whitelist_to_exceptions("$(whoami)").has_value());
    CHECK_FALSE(map_whitelist_to_exceptions("10.0.0.1,evil`cmd`").has_value());
    CHECK_FALSE(map_whitelist_to_exceptions("10.0.0.1 10.0.0.2").has_value()); // space, not comma
    CHECK_FALSE(map_whitelist_to_exceptions(std::string(46, '1')).has_value()); // 46 characters
    // one refused token refuses the whole list: nothing is silently dropped
    CHECK_FALSE(map_whitelist_to_exceptions("10.0.0.1,10.0.0.5:443").has_value());
}

TEST_CASE("map_whitelist_to_exceptions: size bounds", "[server][quarantine][reapply]") {
    // 32 addresses pass, 33 do not
    CHECK(map_whitelist_to_exceptions(n_addresses(kContainmentMaxAddresses)).has_value());
    CHECK_FALSE(map_whitelist_to_exceptions(n_addresses(kContainmentMaxAddresses + 1)).has_value());
    // a list over the length cap is refused whatever it holds
    const std::string over(kQuarantineWhitelistMaxLen + 1, ',');
    CHECK_FALSE(map_whitelist_to_exceptions(over).has_value());
    CHECK(map_whitelist_to_exceptions(std::string(kQuarantineWhitelistMaxLen, ',')) == std::string{});
}

// ── build_quarantine_reapply_params ────────────────────────────────────────

TEST_CASE("build_quarantine_reapply_params: empty whitelist yields empty params, not nullopt",
          "[server][quarantine][reapply]") {
    auto params = build_quarantine_reapply_params("");
    REQUIRE(params.has_value());
    CHECK(params->empty());
}

TEST_CASE("build_quarantine_reapply_params: a whitelist is sent as the mapped `exceptions` only",
          "[server][quarantine][reapply]") {
    auto params = build_quarantine_reapply_params("10.0.0.1,10.0.0.2");
    REQUIRE(params.has_value());
    REQUIRE(params->size() == 1);
    CHECK(params->at(std::string(kContainmentExceptionsParam)) ==
          "10.0.0.1/out,10.0.0.1/in,10.0.0.2/out,10.0.0.2/in");
}

TEST_CASE("build_quarantine_reapply_params: a whitelist the mapper refuses is nullopt",
          "[server][quarantine][reapply]") {
    CHECK_FALSE(build_quarantine_reapply_params("10.0.0.1;evil").has_value());
    CHECK_FALSE(build_quarantine_reapply_params(std::string(600, '1')).has_value());
    CHECK_FALSE(build_quarantine_reapply_params(n_addresses(33)).has_value());
}

// ── parse_containment_reply ────────────────────────────────────────────────

TEST_CASE("parse_containment_reply: the four known status tokens", "[server][quarantine][reapply]") {
    CHECK(parse_containment_reply("status|active").state == QuarantineEndpointState::active);
    CHECK(parse_containment_reply("status|active_unproven").state ==
          QuarantineEndpointState::active_unproven);
    CHECK(parse_containment_reply("status|inactive").state == QuarantineEndpointState::inactive);
    CHECK(parse_containment_reply("status|busy").state == QuarantineEndpointState::busy);
    CHECK(parse_containment_reply("status|active").status_seen);
}

TEST_CASE("parse_containment_reply: every refusal, partial or degraded status, an unknown token and no "
          "status line are unconfirmed",
          "[server][quarantine][reapply]") {
    for (const char* payload : {"status|refused|privilege_unavailable",
                                "status|refused|unsupported_platform",
                                "status|refused",
                                "status|partial|release_incomplete",
                                "status|partial|operation_in_progress",
                                "status|degraded|policy_not_blocking",
                                "status|weird_token",
                                "status|",
                                "garbage",
                                ""}) {
        INFO(payload);
        CHECK(parse_containment_reply(payload).state == QuarantineEndpointState::unconfirmed);
    }
    // a refusal is still an answer; no status line is not
    CHECK(parse_containment_reply("status|refused|privilege_unavailable").status_seen);
    CHECK_FALSE(parse_containment_reply("garbage").status_seen);
    CHECK_FALSE(parse_containment_reply("").status_seen);
}

TEST_CASE("parse_containment_reply: CRLF is tolerated and the first status line wins",
          "[server][quarantine][reapply]") {
    CHECK(parse_containment_reply("status|active\r\n").state == QuarantineEndpointState::active);
    CHECK(parse_containment_reply("status|inactive\r").state == QuarantineEndpointState::inactive);
    CHECK(parse_containment_reply("preamble\r\nstatus|active\r\nnote|x\r\n").state ==
          QuarantineEndpointState::active);
    CHECK(parse_containment_reply("status|inactive\nstatus|active").state ==
          QuarantineEndpointState::inactive);
    CHECK(parse_containment_reply("status|refused|x\nstatus|active").state ==
          QuarantineEndpointState::unconfirmed);
}

TEST_CASE("parse_containment_reply: the probe target row", "[server][quarantine][reapply]") {
    auto p = parse_containment_reply("status|active_unproven\nnote|probe_target=203.0.113.5:443\n");
    CHECK(p.probe_configured);
    CHECK(p.state == QuarantineEndpointState::active_unproven);
    CHECK_FALSE(parse_containment_reply("status|active\n").probe_configured);
}

TEST_CASE("parse_containment_reply: a time limit row is read as nothing: it changes neither the state nor "
          "any flag",
          "[server][quarantine][reapply]") {
    const auto r = parse_containment_reply("status|active\nnote|ttl_expires=1767225600\n");
    CHECK(r.state == QuarantineEndpointState::active);
    CHECK_FALSE(r.probe_configured);
    CHECK_FALSE(r.allow_set_unchanged);
    CHECK(reply_confirms_containment(r));
}

TEST_CASE("parse_containment_reply: the allow-set note is the exact line only",
          "[server][quarantine][reapply]") {
    static_assert(kAllowSetUnchangedNote == "note|allow_set_unchanged_use_quarantine_allow=1");
    const std::string note(kAllowSetUnchangedNote);
    const std::vector<std::string> carrying{
        "status|active\n" + note,
        "status|active\n" + note + "\n",
        "status|active_unproven\r\nnote|already_active=1\r\n" + note + "\r\n",
        note + "\nstatus|active",
    };
    for (const auto& payload : carrying) {
        INFO(payload);
        CHECK(parse_containment_reply(payload).allow_set_unchanged);
    }
    // the note says nothing about the state: it rides with whatever the device reported
    CHECK(parse_containment_reply("status|active\n" + note).state == QuarantineEndpointState::active);
    CHECK(parse_containment_reply("status|degraded|policy_not_blocking\n" + note).state ==
          QuarantineEndpointState::unconfirmed);
    const std::vector<std::string> not_carrying{
        "status|active",
        "",
        "status|active\nnote|already_active=1",
        "status|active\n" + note + "0",
        "status|active\n" + note + " ",
        "status|active\n " + note,
        "status|active\nnote|allow_set_unchanged_use_quarantine_allow=",
        "status|active\nnote|allow_set_unchanged_use_quarantine_allow=2",
        "status|active\nxnote|allow_set_unchanged_use_quarantine_allow=1",
        "status|active\nnote|detail=" + note,
    };
    for (const auto& payload : not_carrying) {
        INFO(payload);
        CHECK_FALSE(parse_containment_reply(payload).allow_set_unchanged);
    }
}

// ── reply_confirms_containment ─────────────────────────────────────────────

TEST_CASE("reply_confirms_containment: true only for active, and for active_unproven with no probe target",
          "[server][quarantine][reapply]") {
    for (const bool probe : {false, true}) {
        INFO("probe_configured=" << probe);
        const auto reply = [probe](QuarantineEndpointState s) {
            return ContainmentReply{.state = s, .probe_configured = probe};
        };
        CHECK(reply_confirms_containment(reply(QuarantineEndpointState::active)));
        CHECK(reply_confirms_containment(reply(QuarantineEndpointState::active_unproven)) == !probe);
        CHECK_FALSE(reply_confirms_containment(reply(QuarantineEndpointState::inactive)));
        CHECK_FALSE(reply_confirms_containment(reply(QuarantineEndpointState::busy)));
        CHECK_FALSE(reply_confirms_containment(reply(QuarantineEndpointState::unconfirmed)));
    }
}

TEST_CASE("reply_confirms_containment: compile-time exhaustiveness", "[server][quarantine][reapply]") {
    static_assert(reply_confirms_containment(ContainmentReply{QuarantineEndpointState::active}));
    static_assert(reply_confirms_containment(ContainmentReply{QuarantineEndpointState::active_unproven}));
    static_assert(!reply_confirms_containment(
        ContainmentReply{QuarantineEndpointState::active_unproven, true}));
    static_assert(!reply_confirms_containment(ContainmentReply{QuarantineEndpointState::inactive}));
    static_assert(!reply_confirms_containment(ContainmentReply{QuarantineEndpointState::busy}));
}

TEST_CASE("endpoint_state_name: the enumerator's name, never device text", "[server][quarantine][reapply]") {
    CHECK(std::string(endpoint_state_name(QuarantineEndpointState::active)) == "active");
    CHECK(std::string(endpoint_state_name(QuarantineEndpointState::active_unproven)) == "active_unproven");
    CHECK(std::string(endpoint_state_name(QuarantineEndpointState::inactive)) == "inactive");
    CHECK(std::string(endpoint_state_name(QuarantineEndpointState::busy)) == "busy");
    CHECK(std::string(endpoint_state_name(QuarantineEndpointState::unconfirmed)) == "unconfirmed");
}

// ── The mapper against the agent's grammar (#7585a) ───────────────────────────

// Each address is sent twice (/out and /in), and the agent refuses more than kMaxExceptions
// entries, so the server's address cap is exactly half of it. The two caps must move together:
// changing either number alone fails the build here instead of failing on a device (or leaving a
// cap the other side never reaches).
static_assert(2 * yuzu::server::kContainmentMaxAddresses ==
                  yuzu::firewall::quarantine::kMaxExceptions,
              "the server's address cap and the agent's exception cap must be changed together: "
              "each address is sent as two entries");

TEST_CASE("map_whitelist_to_exceptions: what the mapper emits is accepted by the agent's own parser, "
          "with twice as many endpoints as addresses",
          "[server][quarantine][reapply][differential]") {
    const std::vector<std::pair<std::string, std::size_t>> accepted{
        {"10.0.0.5", 1},
        {"2001:db8::1", 1},
        {"10.0.0.1,2001:db8::1, fe80::1", 3},
        {" 10.0.0.1 , 10.0.0.2 ", 2},
        {n_addresses(32), 32},
    };
    for (const auto& [whitelist, addresses] : accepted) {
        CAPTURE(whitelist.size());
        const auto mapped = map_whitelist_to_exceptions(whitelist);
        REQUIRE(mapped.has_value());
        const auto agent = yuzu::firewall::quarantine::parse_exceptions_csv(*mapped);
        REQUIRE(agent.has_value());
        CHECK(agent->size() == 2 * addresses); // one /out and one /in per address
    }
    // The empty list maps to nothing, and the agent reads nothing as an empty set.
    const auto empty = map_whitelist_to_exceptions("");
    REQUIRE(empty.has_value());
    const auto agent_empty = yuzu::firewall::quarantine::parse_exceptions_csv(*empty);
    REQUIRE(agent_empty.has_value());
    CHECK(agent_empty->empty());
}

TEST_CASE("map_whitelist_to_exceptions: forms the agent would misread are refused before they reach it",
          "[server][quarantine][reapply][differential]") {
    for (const char* refused : {"010.0.0.1",                                  // a leading-zero octet
                                "::ffff:10.0.0.1",                            // IPv4-mapped
                                "10.0.0.1:443",                               // a port
                                "10.0.0.0/8",                                 // a prefix length
                                "10.0.0.1;rm"}) {                             // outside the charset
        CAPTURE(refused);
        CHECK_FALSE(map_whitelist_to_exceptions(refused).has_value());
    }
    // 46 characters of address charset: one past the token limit.
    CHECK_FALSE(map_whitelist_to_exceptions(std::string(46, 'a')).has_value());
    CHECK_FALSE(map_whitelist_to_exceptions(n_addresses(33)).has_value());
}

// ── The containment constants and the protective set (#7644) ─────────────────

TEST_CASE("the containment action constants are exactly the closed protective set, and nothing else "
          "on the firewall plugin is",
          "[server][quarantine][reapply]") {
    using yuzu::protective::is_protective_action;
    using yuzu::protective::is_firewall_control_plugin;
    for (const auto action : {kContainmentApplyAction, kContainmentStatusAction,
                              kContainmentReleaseAction, std::string_view{"quarantine_allow"}}) {
        CAPTURE(action);
        CHECK(is_firewall_control_plugin(kContainmentPlugin, action));
        CHECK(is_protective_action(kContainmentPlugin, action));
    }
    // A renamed constant would be refused here instead of in production, and an action added to the
    // firewall plugin later does not inherit the exemption.
    CHECK_FALSE(is_firewall_control_plugin(kContainmentPlugin, "state"));
    CHECK_FALSE(is_firewall_control_plugin(kContainmentPlugin, "rules"));
    CHECK_FALSE(is_firewall_control_plugin("os_info", kContainmentApplyAction));
}

TEST_CASE("the whitelist refusal texts name the limits the constants set", "[server][quarantine][reapply]") {
    CHECK(std::string(kWhitelistTooLongMessage).find(std::to_string(kQuarantineWhitelistMaxLen)) !=
          std::string::npos);
    const std::string invalid{kWhitelistInvalidMessage};
    CHECK(invalid.find(std::to_string(kContainmentMaxAddresses)) != std::string::npos);
    CHECK(invalid.find(std::to_string(kQuarantineWhitelistMaxLen)) != std::string::npos);
}
