// Unit tests for the resolver pool metrics publisher (resolver_pool_metrics.hpp): the registration
// pre-seeds every series, the publish mirrors the pool's outcome counts as deltas, a baseline hides
// earlier history, and a count that goes backwards never moves a counter down.
//
// This does not construct a ServerImpl; that server.cpp calls the two functions on its 15 s tick
// is checked by test_delivery_pool_metrics_wiring_lexical.cpp.

#include "resolver_pool_metrics.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>

namespace {

namespace srv = yuzu::server;

constexpr const char* kOutcomes[] = {"ok", "not_found", "temporary", "timeout", "busy"};

double lookups(yuzu::MetricsRegistry& reg, const srv::ResolverPoolMetricNames& names,
               const char* outcome) {
    return reg.counter(names.lookups, {{"outcome", outcome}}).value();
}

// A second set of names: the publisher is parameterised, so another pool can reuse it.
constexpr srv::ResolverPoolMetricNames kOtherNames{
    "yuzu_test_other_resolver_in_flight", "yuzu_test_other_resolver_pool_capacity",
    "yuzu_test_other_resolver_lookups_total", "other in flight", "other capacity", "other lookups"};

} // namespace

TEST_CASE("Resolver pool metrics: registration pre-seeds both gauges and all five outcomes",
          "[resolver_pool_metrics][metrics]") {
    yuzu::MetricsRegistry reg;
    srv::ResolverPoolPublisher pub{srv::kOidcResolverMetrics};
    pub.register_metrics(reg, 16, srv::ResolverOutcomeCounts{});
    const std::string text = reg.serialize();

    CHECK(text.find("yuzu_server_oidc_resolver_in_flight 0") != std::string::npos);
    CHECK(text.find("yuzu_server_oidc_resolver_pool_capacity 16") != std::string::npos);
    for (const char* outcome : kOutcomes)
        CHECK(text.find(std::string("yuzu_server_oidc_resolver_lookups_total{outcome=\"") +
                        outcome + "\"} 0") != std::string::npos);
    // The closed set: exactly the five outcomes, and no bare counter series.
    CHECK(("\n" + text).find("\nyuzu_server_oidc_resolver_lookups_total ") == std::string::npos);
    CHECK(text.find("# HELP yuzu_server_oidc_resolver_lookups_total") != std::string::npos);
    CHECK(text.find("# TYPE yuzu_server_oidc_resolver_lookups_total counter") != std::string::npos);
    CHECK(text.find("# TYPE yuzu_server_oidc_resolver_in_flight gauge") != std::string::npos);
    CHECK(text.find("# TYPE yuzu_server_oidc_resolver_pool_capacity gauge") != std::string::npos);
}

TEST_CASE("Resolver pool metrics: publish sets the gauges and adds only the change in each count",
          "[resolver_pool_metrics][metrics]") {
    yuzu::MetricsRegistry reg;
    srv::ResolverPoolPublisher pub{srv::kOidcResolverMetrics};
    const auto& n = srv::kOidcResolverMetrics;
    pub.register_metrics(reg, 16, srv::ResolverOutcomeCounts{});

    pub.publish(reg, 3, 16, srv::ResolverOutcomeCounts{5, 0, 0, 2, 1});
    CHECK(reg.gauge(n.in_flight).value() == 3.0);
    CHECK(reg.gauge(n.capacity).value() == 16.0);
    CHECK(lookups(reg, n, "ok") == 5.0);
    CHECK(lookups(reg, n, "not_found") == 0.0);
    CHECK(lookups(reg, n, "timeout") == 2.0);
    CHECK(lookups(reg, n, "busy") == 1.0);

    // The same counts again add nothing; a later count adds only the difference.
    pub.publish(reg, 0, 16, srv::ResolverOutcomeCounts{5, 0, 0, 2, 1});
    CHECK(reg.gauge(n.in_flight).value() == 0.0);
    CHECK(lookups(reg, n, "ok") == 5.0);
    CHECK(lookups(reg, n, "busy") == 1.0);
    pub.publish(reg, 16, 16, srv::ResolverOutcomeCounts{9, 1, 0, 2, 4});
    CHECK(reg.gauge(n.in_flight).value() == 16.0);
    CHECK(lookups(reg, n, "ok") == 9.0);
    CHECK(lookups(reg, n, "not_found") == 1.0);
    CHECK(lookups(reg, n, "temporary") == 0.0);
    CHECK(lookups(reg, n, "timeout") == 2.0);
    CHECK(lookups(reg, n, "busy") == 4.0);
}

TEST_CASE("Resolver pool metrics: the baseline at registration hides the pool's earlier history",
          "[resolver_pool_metrics][metrics]") {
    yuzu::MetricsRegistry reg;
    srv::ResolverPoolPublisher pub{srv::kOidcResolverMetrics};
    const auto& n = srv::kOidcResolverMetrics;
    // The pool already counted 7 ok and 3 busy before this registry existed.
    pub.register_metrics(reg, 16, srv::ResolverOutcomeCounts{7, 0, 0, 0, 3});
    CHECK(lookups(reg, n, "ok") == 0.0);
    CHECK(lookups(reg, n, "busy") == 0.0);

    pub.publish(reg, 0, 16, srv::ResolverOutcomeCounts{7, 0, 0, 0, 3});
    CHECK(lookups(reg, n, "ok") == 0.0);
    CHECK(lookups(reg, n, "busy") == 0.0);

    pub.publish(reg, 0, 16, srv::ResolverOutcomeCounts{8, 0, 0, 0, 5});
    CHECK(lookups(reg, n, "ok") == 1.0);
    CHECK(lookups(reg, n, "busy") == 2.0);
}

TEST_CASE("Resolver pool metrics: a count that goes backwards adds nothing and becomes the new base",
          "[resolver_pool_metrics][metrics]") {
    yuzu::MetricsRegistry reg;
    srv::ResolverPoolPublisher pub{srv::kOidcResolverMetrics};
    const auto& n = srv::kOidcResolverMetrics;
    pub.register_metrics(reg, 16, srv::ResolverOutcomeCounts{});
    pub.publish(reg, 0, 16, srv::ResolverOutcomeCounts{10, 0, 0, 0, 0});
    CHECK(lookups(reg, n, "ok") == 10.0);

    // A replaced pool starts again from 0: the counter never goes down and never double counts.
    pub.publish(reg, 0, 16, srv::ResolverOutcomeCounts{2, 0, 0, 0, 0});
    CHECK(lookups(reg, n, "ok") == 10.0);
    pub.publish(reg, 0, 16, srv::ResolverOutcomeCounts{5, 0, 0, 0, 0});
    CHECK(lookups(reg, n, "ok") == 13.0);
}

TEST_CASE("Resolver pool metrics: the publisher is parameterised by the metric names",
          "[resolver_pool_metrics][metrics]") {
    yuzu::MetricsRegistry reg;
    srv::ResolverPoolPublisher pub{kOtherNames};
    pub.register_metrics(reg, 16, srv::ResolverOutcomeCounts{});
    pub.publish(reg, 4, 16, srv::ResolverOutcomeCounts{0, 0, 0, 0, 2});
    const std::string text = reg.serialize();

    CHECK(text.find("yuzu_test_other_resolver_in_flight 4") != std::string::npos);
    CHECK(text.find("yuzu_test_other_resolver_pool_capacity 16") != std::string::npos);
    CHECK(text.find("yuzu_test_other_resolver_lookups_total{outcome=\"busy\"} 2") !=
          std::string::npos);
    CHECK(text.find("# HELP yuzu_test_other_resolver_lookups_total other lookups") !=
          std::string::npos);
    // None of the OIDC names were touched.
    CHECK(text.find("yuzu_server_oidc_resolver") == std::string::npos);
}
