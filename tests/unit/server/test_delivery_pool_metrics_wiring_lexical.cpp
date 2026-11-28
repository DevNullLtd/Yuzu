/**
 * test_delivery_pool_metrics_wiring_lexical.cpp -- a LEXICAL pin of how server.cpp wires the
 * webhook and offload delivery pool metrics, and of the OIDC resolver pool publisher that shares
 * the same 15 s tick (#7153). The file keeps its delivery-pool name: the resolver cases live here
 * because they pin the same tick, and a CRL-source twin has its own file.
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
 *   3. both publishes sit inside the 15 s tick: after the OIDC resolver publish and before
 *      the workflow table-size refresh that follows;
 *   4. the OIDC resolver pool's publisher is registered once, published once on that tick, and its
 *      metric names are not literals in server.cpp; `bounded_resolve` counts through
 *      `note_outcome` once for each lookup it runs (the OIDC adapter makes the one increment for
 *      a lookup it refuses before the pool; the "OIDC resolver pool metrics" cases below).
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
    // the `publish(...)` call, which appears once; the metric NAME is not a literal in server.cpp
    // at all, so the name alone would not identify the tick) and before the workflow table-size
    // refresh that follows them.
    const std::string tick_start =
        "oidc_resolver_publisher_.publish(metrics_,::yuzu::server::oidc::oidc_resolver_in_flight(),"
        "::yuzu::server::oidc::oidc_resolver_pool_capacity(),"
        "::yuzu::server::oidc::oidc_resolver_outcome_counts());";
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

TEST_CASE("OIDC resolver pool metrics wiring (LEXICAL check, not behaviour): registered once from the "
          "pool's own accessors, published once on the tick, never named by a literal",
          "[resolver_pool_metrics][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("server.cpp"));

    // One member, one registration, one publish: a second of any would double a series or race the
    // delta the publisher keeps.
    CHECK(count_occurrences(flat, "yuzu::server::ResolverPoolPublisheroidc_resolver_publisher_{"
                                  "yuzu::server::kOidcResolverMetrics};") == 1);
    CHECK(count_occurrences(flat, "oidc_resolver_publisher_.register_metrics(metrics_,"
                                  "::yuzu::server::oidc::oidc_resolver_pool_capacity(),"
                                  "::yuzu::server::oidc::oidc_resolver_outcome_counts());") == 1);
    CHECK(count_occurrences(flat, "oidc_resolver_publisher_.") == 2);
    CHECK(count_occurrences(flat, "oidc_resolver_publisher_.publish(") == 1);
    // The names live in resolver_pool_metrics.hpp; a literal here would be a second describe or a
    // bare pre-seed of the series the publisher owns.
    CHECK(count_occurrences(flat, "\"yuzu_server_oidc_resolver_in_flight\"") == 0);
    CHECK(count_occurrences(flat, "\"yuzu_server_oidc_resolver_pool_capacity\"") == 0);
    CHECK(count_occurrences(flat, "\"yuzu_server_oidc_resolver_lookups_total\"") == 0);
    // The publish is fed by the OIDC pool's own accessors (the CRL pool has its own gauge).
    CHECK(count_occurrences(flat, "oidc_resolver_in_flight()") == 1);
}

TEST_CASE("resolver pool outcome counting (LEXICAL check, not behaviour): bounded_resolve counts "
          "through note_outcome exactly once",
          "[resolver_pool_metrics][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("bounded_resolver.hpp"));

    // One definition and ONE call site, in the public wrapper that every caller goes through: a
    // second increment would count a call twice, and an early return that bypassed the wrapper
    // would not be counted at all.
    CHECK(count_occurrences(flat, "voidnote_outcome(ResolveStatuss)noexcept{") == 1);
    CHECK(count_occurrences(flat, "note_outcome(") == 2);
    CHECK(count_occurrences(flat, "pool->note_outcome(result.status);") == 1);
    // The wrapper counts what the implementation returned, after choosing the pool.
    const auto pick = flat.find("pool=detail::process_pool();");
    const auto impl = flat.find("detail::bounded_resolve_impl(host,timeout,std::move(lookup),pool);");
    const auto note = flat.find("pool->note_outcome(result.status);");
    REQUIRE(pick != std::string::npos);
    REQUIRE(impl != std::string::npos);
    REQUIRE(note != std::string::npos);
    CHECK(pick < impl);
    CHECK(impl < note);
}
