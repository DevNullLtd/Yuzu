/**
 * test_delivery_pool_metrics_wiring_lexical.cpp -- a LEXICAL pin of how server.cpp wires the
 * webhook and offload delivery pool metrics (#7153).
 *
 * WHAT THIS IS, AND IS NOT. A source-text scan (the test_hw_ci_detail_wiring_lexical.cpp style),
 * NOT a behavioural test: ServerImpl is not unit-constructible, so nothing here runs the 15 s
 * tick. The behaviour of `register_delivery_pool_metrics` and `publish_delivery_pool` is covered
 * by the "Delivery pool metrics" cases in test_agent_service_impl.cpp; what those cannot see is
 * whether server.cpp CALLS them, with the right store label and the right store's accessors. A
 * rule such as `YuzuDeliveryPoolBacklogHigh` that parses but whose gauge is never published (or is
 * published under the wrong `store`) is invisible to every other gate, so this reads the
 * comment-stripped server.cpp at test run time (YUZU_SERVER_SRC_DIR) and pins:
 *   1. the registration helper is called exactly once, and the two drop-counter names appear
 *      nowhere in server.cpp as literals (no second describe or a bare pre-seed that would
 *      re-create the unlabelled series);
 *   2. `publish_delivery_pool` is called exactly twice, once with "webhook" and once with
 *      "offload", each fed from its own store's `is_open()`, `delivery_pool_pending()` and
 *      `delivery_pool_capacity()` and reading 0 when the store is not open;
 *   3. both publishes sit inside the 15 s tick: after the OIDC resolver gauge it sets and before
 *      the workflow table-size refresh that follows.
 * It matches with whitespace removed, so a reformat does not turn it red; a rename or a
 * restructuring does, and the fix is to update the needles here. Limits: it cannot tell that the
 * tick runs or that the branch is reachable.
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

TEST_CASE("delivery pool metrics wiring (LEXICAL pin, not behaviour): registered once, with no "
          "second definition of the drop counters",
          "[delivery_pool_metrics][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("server.cpp"));

    CHECK(count_occurrences(flat, "yuzu::server::register_delivery_pool_metrics(metrics_);") == 1);
    // The counters' names live in delivery_pool_metrics.hpp; a literal here would be a second
    // describe or a bare pre-seed of the unlabelled series.
    CHECK(count_occurrences(flat, "\"yuzu_server_webhook_delivery_dropped_total\"") == 0);
    CHECK(count_occurrences(flat, "\"yuzu_server_offload_delivery_dropped_total\"") == 0);
}

TEST_CASE("delivery pool metrics wiring (LEXICAL pin, not behaviour): each store is published "
          "under its own label from its own accessors, after the OIDC resolver gauge",
          "[delivery_pool_metrics][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("server.cpp"));

    REQUIRE(count_occurrences(flat, "yuzu::server::publish_delivery_pool(") == 2);

    // Webhook.
    CHECK(count_occurrences(flat, "constboolwebhook_open=webhook_store_&&webhook_store_->is_open();") ==
          1);
    CHECK(count_occurrences(flat, "yuzu::server::publish_delivery_pool(metrics_,\"webhook\","
                                  "webhook_open,webhook_open?webhook_store_->delivery_pool_pending():0,"
                                  "webhook_open?webhook_store_->delivery_pool_capacity():0);") == 1);
    // Offload.
    CHECK(count_occurrences(flat, "constbooloffload_open=offload_target_store_&&"
                                  "offload_target_store_->is_open();") == 1);
    CHECK(count_occurrences(flat, "yuzu::server::publish_delivery_pool(metrics_,\"offload\","
                                  "offload_open,offload_open?offload_target_store_->"
                                  "delivery_pool_pending():0,offload_open?offload_target_store_->"
                                  "delivery_pool_capacity():0);") == 1);

    // Both publishes sit inside the 15 s tick: after the OIDC resolver gauge it sets (anchored on
    // the `.set(...)` call, which appears once; the metric NAME also appears in the boot-time
    // describe, so the name alone would not pin the tick) and before the workflow table-size
    // refresh that follows them.
    const std::string tick_start =
        ".set(static_cast<double>(::yuzu::server::oidc::oidc_resolver_in_flight()));";
    const std::string tick_next = "workflow_engine_->refresh_table_size_metrics();";
    REQUIRE(count_occurrences(flat, tick_start) == 1);
    REQUIRE(count_occurrences(flat, tick_next) == 1);
    const auto start = flat.find(tick_start);
    const auto next = flat.find(tick_next);
    const auto first = flat.find("yuzu::server::publish_delivery_pool(");
    const auto last = flat.rfind("yuzu::server::publish_delivery_pool(");
    CHECK(first > start);
    CHECK(last < next);
}
