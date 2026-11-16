/**
 * test_revocation_source_degrade_wiring_lexical.cpp -- a LEXICAL check of how the CRL source
 * `dns_busy` degrade reason reaches `yuzu_server_revocation_source_degrade_total`, the series the
 * sample alert `YuzuCrlSourceResolverBusy` selects on (#7153).
 *
 * WHAT THIS IS, AND IS NOT. A source-text scan (the test_delivery_pool_metrics_wiring_lexical.cpp
 * style), NOT a behavioural test: ServerImpl is not unit-constructible, so nothing here runs the
 * registration route. The service's own counting of each reason is covered by the surface cases in
 * test_revocation_source_surface.cpp; what those cannot see is whether server.cpp pre-seeds the
 * `dns_busy` series and wires `note_degrade` to the counter. A rule that parses but whose series
 * never exists, or is incremented under another name, is invisible to every other gate, so this
 * reads the comment-stripped sources at test run time (YUZU_SERVER_SRC_DIR) and checks:
 *   1. server.cpp pre-seeds all six reasons, `dns_busy` among them, on the counter;
 *   2. server.cpp's `note_degrade` increments that counter with a `reason` label taken from the
 *      reason it is handed, and the counter's name is written exactly three times (describe,
 *      pre-seed, increment);
 *   3. the service spells the reason `"dns_busy"` exactly twice: the URL-host lookup refusal and
 *      the listen-host lookup refusal.
 * It matches with whitespace removed, so a reformat does not turn it red; a rename or a
 * restructuring does, and the fix is to update the needles here. Limits: it cannot tell that the
 * branch is reachable.
 */

#include "source_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace {

using yuzu::test::source_scan::comment_free_source;
using yuzu::test::source_scan::count_occurrences;

std::string squeeze(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (const char c : text)
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            out.push_back(c);
    return out;
}

} // namespace

TEST_CASE("CRL source degrade wiring (LEXICAL check, not behaviour): server.cpp pre-seeds every "
          "reason, dns_busy included, on the one counter",
          "[revocation_source_degrade][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("server.cpp"));

    CHECK(count_occurrences(flat, "for(constchar*reason:{\"own_addresses_unavailable\","
                                  "\"dns_unavailable\",\"dns_timeout\",\"dns_busy\","
                                  "\"dns_budget_exhausted\",\"validation_busy\"})"
                                  "metrics_.counter(\"yuzu_server_revocation_source_degrade_total\","
                                  "{{\"reason\",reason}});") == 1);
}

TEST_CASE("CRL source degrade wiring (LEXICAL check, not behaviour): note_degrade increments the "
          "counter under the reason it is handed",
          "[revocation_source_degrade][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("server.cpp"));

    CHECK(count_occurrences(flat, "egress_env.note_degrade=[this](std::string_viewreason){"
                                  "metrics_.counter(\"yuzu_server_revocation_source_degrade_total\","
                                  "{{\"reason\",std::string(reason)}}).increment();};") == 1);
    // describe + pre-seed + increment: a fourth would be a second definition or a second path.
    CHECK(count_occurrences(flat, "\"yuzu_server_revocation_source_degrade_total\"") == 3);
}

TEST_CASE("CRL source degrade wiring (LEXICAL check, not behaviour): the service spells dns_busy for "
          "both lookup refusals",
          "[revocation_source_degrade][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("revocation_source_service.cpp"));

    // The URL-host lookup (host_classes) and the listen-host lookup (load_own).
    CHECK(count_occurrences(flat, "\"dns_busy\"") == 2);
    CHECK(count_occurrences(flat, "r.status==EgressEnv::ResolveStatus::kBusy?\"dns_busy\"") == 1);
    CHECK(count_occurrences(flat, "addrs.error()==EgressEnv::OwnAddressesError::kBusy?\"dns_busy\":"
                                  "\"own_addresses_unavailable\"") == 1);
}
