// network_actions_parsers.hpp's resolver_flush_flag() picks the correct
// flush-cache verb spelling for whichever Linux DNS resolver tool
// probe_tool_path found: resolvectl's modern CLI takes a bare subcommand,
// while the older systemd-resolve CLI takes a long option instead. Pure
// string-suffix logic — no subprocess, no filesystem probe.
#include <catch2/catch_test_macros.hpp>

#include "../../agents/plugins/network_actions/src/network_actions_parsers.hpp"

#include <string>
#include <vector>

using yuzu::network_actions::decide_dns_flush;
using yuzu::network_actions::DnsFlushAttemptOutcome;
using yuzu::network_actions::resolver_flush_flag;

TEST_CASE("resolver_flush_flag: resolvectl takes the bare subcommand",
         "[network_actions]") {
    CHECK(resolver_flush_flag("/usr/bin/resolvectl") == "flush-caches");
}

TEST_CASE("resolver_flush_flag: systemd-resolve takes the long option",
         "[network_actions]") {
    CHECK(resolver_flush_flag("/usr/bin/systemd-resolve") == "--flush-caches");
}

TEST_CASE("resolver_flush_flag: matches on the tool basename, not just an exact path",
         "[network_actions]") {
    // A distro that ships the older CLI at a different prefix still gets the
    // long-option form, because the match is a path suffix, not full equality.
    CHECK(resolver_flush_flag("/bin/systemd-resolve") == "--flush-caches");
}

TEST_CASE("resolver_flush_flag: empty / unrecognised path defaults to the bare subcommand",
         "[network_actions]") {
    // probe_tool_path only ever returns an absolute resolvectl/systemd-resolve
    // path or empty; an empty path never reaches run_bounded_subprocess (the
    // caller leaves argv empty instead), but the pure function itself has no
    // way to signal "no tool" and must still return something well-defined.
    CHECK(resolver_flush_flag("") == "flush-caches");
    CHECK(resolver_flush_flag("/usr/bin/resolvectl-wrapper") == "flush-caches");
}

// ── decide_dns_flush ─────────────────────────────────────────────────────
//
// Pins the Linux flush_dns retry loop's semantics: retry on ANY failure of
// a found candidate (spawn error OR nonzero exit), not just retry-on-
// absence, and stop trying further candidates the moment one succeeds.

TEST_CASE("decide_dns_flush: candidate 1 not found, candidate 2 found and succeeds",
         "[network_actions]") {
    std::vector<DnsFlushAttemptOutcome> attempts{
        {/*found=*/false, /*succeeded=*/false},
        {/*found=*/true, /*succeeded=*/true},
    };
    const auto decision = decide_dns_flush(attempts);
    CHECK(decision.attempted);
    CHECK(decision.ok);
    CHECK(decision.winning_index == 1);
}

TEST_CASE("decide_dns_flush: candidate 1 found but fails at runtime (spawn error) -> "
         "candidate 2 is still tried, not just retry-on-absence",
         "[network_actions]") {
    // found=true, succeeded=false stands for BOTH a spawn error and a
    // nonzero exit -- the retry loop's decision doesn't distinguish how a
    // found candidate failed, only that it did. This case pins the specific
    // regression a presence-only probe would silently narrow away: a
    // candidate that EXISTS but fails at runtime must still fall through to
    // the next one.
    std::vector<DnsFlushAttemptOutcome> attempts{
        {/*found=*/true, /*succeeded=*/false},
        {/*found=*/true, /*succeeded=*/true},
    };
    const auto decision = decide_dns_flush(attempts);
    CHECK(decision.attempted);
    CHECK(decision.ok);
    CHECK(decision.winning_index == 1);
}

TEST_CASE("decide_dns_flush: candidate 1 found but exits nonzero -> candidate 2 is still tried",
         "[network_actions]") {
    std::vector<DnsFlushAttemptOutcome> attempts{
        {/*found=*/true, /*succeeded=*/false}, // e.g. resolvectl present, service masked
        {/*found=*/true, /*succeeded=*/true},
    };
    const auto decision = decide_dns_flush(attempts);
    CHECK(decision.attempted);
    CHECK(decision.ok);
    CHECK(decision.winning_index == 1);
}

TEST_CASE("decide_dns_flush: candidate 1 succeeds -> candidate 2 is never tried",
         "[network_actions]") {
    // The vector below still HOLDS a (poisoned) entry for candidate 2 --
    // decide_dns_flush must return before ever consulting it, proving the
    // real loop's early break is what this decision function reproduces,
    // not merely "picks the first success it happens to see".
    std::vector<DnsFlushAttemptOutcome> attempts{
        {/*found=*/true, /*succeeded=*/true},
        {/*found=*/true, /*succeeded=*/false},
    };
    const auto decision = decide_dns_flush(attempts);
    CHECK(decision.attempted);
    CHECK(decision.ok);
    CHECK(decision.winning_index == 0);
}

TEST_CASE("decide_dns_flush: neither candidate found -> not attempted, never reported ok",
         "[network_actions]") {
    std::vector<DnsFlushAttemptOutcome> attempts{
        {/*found=*/false, /*succeeded=*/false},
        {/*found=*/false, /*succeeded=*/false},
    };
    const auto decision = decide_dns_flush(attempts);
    CHECK_FALSE(decision.attempted);
    CHECK_FALSE(decision.ok);
}

TEST_CASE("decide_dns_flush: both candidates found but both fail -> attempted, not ok, "
         "winning_index is the LAST one tried",
         "[network_actions]") {
    std::vector<DnsFlushAttemptOutcome> attempts{
        {/*found=*/true, /*succeeded=*/false},
        {/*found=*/true, /*succeeded=*/false},
    };
    const auto decision = decide_dns_flush(attempts);
    CHECK(decision.attempted);
    CHECK_FALSE(decision.ok);
    CHECK(decision.winning_index == 1);
}
