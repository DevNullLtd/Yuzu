/**
 * test_wol_check_plan.cpp — pure mechanism-selection logic for wol's
 * `check` action (wol_check_plan.hpp, ADR-3002 rung-1 ICMP + TCP-connect
 * fallback migration).
 *
 * classify_check() is header-pure (no I/O, no context), so every branch of
 * the ICMP-primary/TCP-fallback/honest-degrade decision is pinned here
 * without a live network hop — the netprobe_stats.hpp / test_icmp_probe.cpp
 * pattern.
 */
#include "wol_check_plan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

using namespace yuzu::wol;

TEST_CASE("classify_check: an ICMP echo reply is reachable via icmp",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = true;
    o.icmp_session_ok = true;
    o.icmp_replied = true;
    // TCP facts are irrelevant once ICMP has replied -- left at their
    // default (unattempted) to prove classify_check doesn't need them.
    const auto v = classify_check(o);
    CHECK(v.reachable);
    CHECK(v.mechanism == CheckMechanism::icmp);
}

TEST_CASE("classify_check: ICMP session unusable (denied/unavailable), TCP fallback connects "
          "-> reachable via tcp_fallback",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = true;
    o.icmp_session_ok = false; // e.g. Linux net.ipv4.ping_group_range denied it
    o.icmp_replied = false;
    o.tcp_resolved = true;
    o.tcp_connected = true;
    const auto v = classify_check(o);
    CHECK(v.reachable);
    CHECK(v.mechanism == CheckMechanism::tcp_fallback);
}

TEST_CASE("classify_check: ICMP usable but no reply, TCP fallback connects -> reachable via "
          "tcp_fallback",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = true;
    o.icmp_session_ok = true;
    o.icmp_replied = false; // sent, no reply within budget
    o.tcp_resolved = true;
    o.tcp_connected = true;
    const auto v = classify_check(o);
    CHECK(v.reachable);
    CHECK(v.mechanism == CheckMechanism::tcp_fallback);
}

TEST_CASE("classify_check: ICMP unusable, TCP connect refused (RST) -> reachable via "
          "tcp_refused, distinct from a successful connect",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = true;
    o.icmp_session_ok = false; // e.g. Linux net.ipv4.ping_group_range denied it
    o.icmp_replied = false;
    o.tcp_resolved = true;
    o.tcp_connected = false;
    o.tcp_refused = true; // RST -- the host's network stack answered
    const auto v = classify_check(o);
    CHECK(v.reachable);
    CHECK(v.mechanism == CheckMechanism::tcp_refused);
}

TEST_CASE("classify_check: TCP refused takes precedence over a plain no-reply (refused is "
          "stronger evidence than 'no signal at all')",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = true;
    o.icmp_session_ok = true;
    o.icmp_replied = false;
    o.tcp_resolved = true;
    o.tcp_connected = false;
    o.tcp_refused = true;
    const auto v = classify_check(o);
    CHECK(v.reachable);
    CHECK(v.mechanism == CheckMechanism::tcp_refused);
}

TEST_CASE("classify_check: both mechanisms genuinely attempted, neither succeeds -> an honest "
          "negative (checked_no_reply), not unavailable",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = true;
    o.icmp_session_ok = true;
    o.icmp_replied = false;
    o.tcp_resolved = true;
    o.tcp_connected = false; // connect refused/timed out -- still a real attempt
    const auto v = classify_check(o);
    CHECK_FALSE(v.reachable);
    CHECK(v.mechanism == CheckMechanism::checked_no_reply);
}

TEST_CASE("classify_check: ICMP unusable AND no TCP destination resolvable -> unavailable, "
          "never a fabricated unreachable",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = false;
    o.icmp_session_ok = false;
    o.icmp_replied = false;
    o.tcp_resolved = false; // e.g. the host doesn't resolve at all
    o.tcp_connected = false;
    const auto v = classify_check(o);
    CHECK_FALSE(v.reachable);
    CHECK(v.mechanism == CheckMechanism::unavailable);
}

TEST_CASE("classify_check: ICMP session usable but the destination didn't resolve, no TCP "
          "destination either -> still unavailable (icmp_attemptable requires BOTH facts)",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = false; // no AF_INET address for this host
    o.icmp_session_ok = true; // the session itself constructed fine
    o.icmp_replied = false;
    o.tcp_resolved = false;
    o.tcp_connected = false;
    const auto v = classify_check(o);
    CHECK_FALSE(v.reachable);
    CHECK(v.mechanism == CheckMechanism::unavailable);
}

TEST_CASE("classify_check: ICMP unusable but a destination resolved (e.g. IPv6-only host, ICMP "
          "is IPv4-only) and TCP was genuinely attempted -> checked_no_reply, not unavailable",
          "[wol][wol_check_plan]") {
    ProbeOutcome o;
    o.icmp_resolved = false; // no AF_INET result for an IPv6-only host
    o.icmp_session_ok = true;
    o.icmp_replied = false;
    o.tcp_resolved = true; // AF_UNSPEC resolved the IPv6 address
    o.tcp_connected = false;
    const auto v = classify_check(o);
    CHECK_FALSE(v.reachable);
    CHECK(v.mechanism == CheckMechanism::checked_no_reply);
}

TEST_CASE("check_mechanism_label: every enumerator renders a distinct, stable token",
          "[wol][wol_check_plan]") {
    CHECK(std::string_view{check_mechanism_label(CheckMechanism::icmp)} == "icmp");
    CHECK(std::string_view{check_mechanism_label(CheckMechanism::tcp_fallback)} ==
          "tcp-fallback");
    CHECK(std::string_view{check_mechanism_label(CheckMechanism::tcp_refused)} == "tcp-refused");
    CHECK(std::string_view{check_mechanism_label(CheckMechanism::checked_no_reply)} ==
          "icmp+tcp-fallback");
    CHECK(std::string_view{check_mechanism_label(CheckMechanism::unavailable)} == "unavailable");
}
