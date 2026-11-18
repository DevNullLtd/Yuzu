/**
 * test_outbound_destination_guard.cpp -- WP10 (#4816, #3870): the destination-ADDRESS guard
 * for webhook and offload-target delivery (outbound_destination_guard.hpp). Pure: the resolver is
 * injected, nothing touches the network.
 *
 * Scope under test (owner ruling): unspecified, link-local / metadata, multicast and reserved are
 * refused; loopback and private ranges are NOT; a name is resolved once and the vetted answer is
 * the connect target.
 */
#include "outbound_destination_guard.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>

using namespace yuzu::server;

namespace {
net::ResolveResult answer(std::vector<std::string> a) {
    net::ResolveResult r;
    r.status = a.empty() ? net::ResolveStatus::kNotFound : net::ResolveStatus::kOk;
    r.addresses = std::move(a);
    return r;
}
} // namespace

TEST_CASE("destination guard: literal create-time refusal covers the never-allowed tier",
          "[outbound_destination_guard][security]") {
    for (const char* u : {"http://169.254.169.254/latest/meta-data/", "https://169.254.0.1/x",
                          "http://0.0.0.0:22/", "http://0.1.2.3/", "http://[fe80::1]/",
                          "http://[::]/", "http://224.0.0.1/", "http://255.255.255.255/",
                          "http://240.0.0.1/", "http://[::ffff:169.254.169.254]/",
                          "http://169.254.169.254:80/p?q=1", "http://169.254.169.254"}) {
        INFO(u);
        CHECK(url_literal_destination_refused(u));
    }
}

TEST_CASE("destination guard: loopback, private and public literals and ordinary names pass create",
          "[outbound_destination_guard][security]") {
    // Loopback and RFC 1918 receivers are not refused by this guard (owner decision; #4816).
    for (const char* u : {"http://127.0.0.1:1/h", "http://localhost:8080/h", "http://10.1.2.3/h",
                          "https://192.168.1.5:8443/h", "http://172.16.0.9/h", "http://[::1]/h",
                          "https://hooks.example.com/h", "https://8.8.8.8/h", "http://[fd00::1]/h"}) {
        INFO(u);
        CHECK_FALSE(url_literal_destination_refused(u));
    }
}

TEST_CASE("destination guard: a refused literal is refused at delivery without any lookup",
          "[outbound_destination_guard][security]") {
    int lookups = 0;
    auto lookup = [&](const std::string&) { ++lookups; return answer({"8.8.8.8"}); };
    const auto v = vet_delivery_destination("http://169.254.169.254/x", std::chrono::seconds(1), lookup);
    CHECK(v.verdict == DestinationVerdict::Refused);
    CHECK(std::string{v.refused_class} == "link-local");
    CHECK(lookups == 0);
}

TEST_CASE("destination guard: a literal loopback or private host is allowed and needs no pin",
          "[outbound_destination_guard][security]") {
    const auto lo = vet_delivery_destination("http://127.0.0.1:1/h");
    CHECK(lo.verdict == DestinationVerdict::Allow);
    CHECK(lo.pinned_ips.empty());
    CHECK(vet_delivery_destination("http://10.0.0.5/h").verdict == DestinationVerdict::Allow);
}

TEST_CASE("destination guard: a name resolving to a never-allowed address is refused",
          "[outbound_destination_guard][security]") {
    for (const char* bad : {"169.254.169.254", "0.0.0.0", "fe80::1", "224.0.0.251", "240.0.0.1",
                            "::ffff:169.254.169.254"}) {
        INFO(bad);
        auto lookup = [&](const std::string&) { return answer({bad}); };
        const auto v = vet_delivery_destination("https://hooks.example.com/x",
                                                std::chrono::seconds(1), lookup);
        CHECK(v.verdict == DestinationVerdict::Refused);
        CHECK(v.pinned_ips.empty());
    }
}

TEST_CASE("destination guard: ANY refused answer refuses the whole name",
          "[outbound_destination_guard][security]") {
    auto lookup = [](const std::string&) { return answer({"93.184.216.34", "169.254.169.254"}); };
    CHECK(vet_delivery_destination("http://mixed.example/x", std::chrono::seconds(1), lookup).verdict ==
          DestinationVerdict::Refused);
    auto reversed = [](const std::string&) { return answer({"169.254.169.254", "93.184.216.34"}); };
    CHECK(vet_delivery_destination("http://mixed.example/x", std::chrono::seconds(1), reversed).verdict ==
          DestinationVerdict::Refused);
}

TEST_CASE("destination guard: a vetted name is resolved ONCE and pinned to the vetted address",
          "[outbound_destination_guard][security]") {
    // DNS rebinding: first answer public, every later answer link-local. The connect target is the
    // answer that was judged; the name is never looked up a second time.
    int lookups = 0;
    auto rebinding = [&](const std::string&) {
        return ++lookups == 1 ? answer({"93.184.216.34"}) : answer({"169.254.169.254"});
    };
    const auto v = vet_delivery_destination("https://hooks.example.com:8443/x?y=1",
                                            std::chrono::seconds(1), rebinding);
    CHECK(v.verdict == DestinationVerdict::Allow);
    REQUIRE(v.pinned_ips.size() == 1);
    CHECK(v.pinned_ips[0] == "93.184.216.34");
    CHECK(v.host == "hooks.example.com"); // the addr-map key: no port, no path
    CHECK(lookups == 1);
}

TEST_CASE("destination guard: a private answer for a name is allowed (loopback and RFC 1918 are not refused)",
          "[outbound_destination_guard][security]") {
    auto lookup = [](const std::string&) { return answer({"10.0.0.7"}); };
    const auto v = vet_delivery_destination("http://siem.internal/x", std::chrono::seconds(1), lookup);
    CHECK(v.verdict == DestinationVerdict::Allow);
    REQUIRE(v.pinned_ips.size() == 1);
    CHECK(v.pinned_ips[0] == "10.0.0.7");
}

TEST_CASE("destination guard: an unresolvable name fails closed", "[outbound_destination_guard][security]") {
    auto none = [](const std::string&) { return answer({}); };
    CHECK(vet_delivery_destination("http://nope.example/x", std::chrono::seconds(1), none).verdict ==
          DestinationVerdict::Unresolved);
    auto garbage = [](const std::string&) { return answer({"not-an-address"}); };
    CHECK(vet_delivery_destination("http://x.example/x", std::chrono::seconds(1), garbage).verdict ==
          DestinationVerdict::Unresolved);
    CHECK(vet_delivery_destination("http:///x").verdict == DestinationVerdict::Unresolved);
}

TEST_CASE("destination guard: numeric spellings the resolver accepts are refused at create",
          "[outbound_destination_guard][security]") {
    // Each of these is 169.254.169.254 (or 0.0.0.0) to the OS resolver but not a canonical dotted
    // quad: accepting one at create would store a target delivery can only decline.
    for (const char* u : {"http://2852039166/", "http://0xa9fea9fe/", "http://0251.0376.0251.0376/",
                          "http://0/", "http://0.0/", "http://0x0/", "http://2852039166:8080/x",
                          "https://0xA9.0xFE.0xA9.0xFE/p", "http://169.254.43518/"}) {
        INFO(u);
        CHECK(url_literal_destination_refused(u));
    }
    // Real names and canonical public/private/loopback literals are untouched.
    for (const char* u : {"http://hooks.example.com/x", "http://localhost/x", "http://127.0.0.1:1/h",
                          "http://10.0.0.5/h", "http://[::1]/h", "http://a1b2.internal/h"})
        CHECK_FALSE(url_literal_destination_refused(u));
}

TEST_CASE("destination guard: a dual-stack name keeps every vetted address, IPv4 first",
          "[outbound_destination_guard][security]") {
    auto lookup = [](const std::string&) {
        return answer({"2606:4700::1111", "93.184.216.34", "2606:4700::1112", "1.1.1.1"});
    };
    const auto v = vet_delivery_destination("https://dual.example/x", std::chrono::seconds(1), lookup);
    REQUIRE(v.verdict == DestinationVerdict::Allow);
    REQUIRE(v.pinned_ips.size() == 4);
    CHECK(v.pinned_ips[0] == "93.184.216.34");
    CHECK(v.pinned_ips[1] == "1.1.1.1");
    CHECK(v.pinned_ips[2] == "2606:4700::1111");
    CHECK(v.pinned_ips[3] == "2606:4700::1112");
    // The same answer with a refused member anywhere is refused whole.
    auto mixed = [](const std::string&) {
        return answer({"2606:4700::1111", "93.184.216.34", "fe80::1"});
    };
    CHECK(vet_delivery_destination("https://dual.example/x", std::chrono::seconds(1), mixed).verdict ==
          DestinationVerdict::Refused);
}

TEST_CASE("destination guard: delivery resolves through a pool of its own",
          "[outbound_destination_guard][security]") {
    // The process pool is the one CRL source registration uses; delivery must never share its 16
    // slots (slow webhook DNS would make CRL registration answer busy, and the reverse).
    CHECK(delivery_resolver_pool().get() != net::detail::process_pool().get());
    const auto before = delivery_resolver_outcome_counts();
    const auto process_before = net::detail::process_pool()->outcome_counts();
    auto lookup = [](const std::string&) { return answer({"93.184.216.34"}); };
    (void)vet_delivery_destination("http://pool.example/x", std::chrono::seconds(1), lookup);
    const auto after = delivery_resolver_outcome_counts();
    const auto process_after = net::detail::process_pool()->outcome_counts();
    CHECK(after[static_cast<std::size_t>(net::ResolveStatus::kOk)] ==
          before[static_cast<std::size_t>(net::ResolveStatus::kOk)] + 1);
    CHECK(process_after == process_before); // the process pool saw nothing
    CHECK(delivery_resolver_pool_capacity() == net::kMaxInFlightLookups);

    // An injected, saturated pool declines (Unresolved) without touching any other pool.
    auto tiny = std::make_shared<net::ResolverPool>(0);
    const auto v = vet_delivery_destination("http://busy.example/x", std::chrono::seconds(1), lookup, tiny);
    CHECK(v.verdict == DestinationVerdict::ResolverBusy); // not "the name does not resolve"
    CHECK(std::string{destination_cause(v.verdict)} == "destination_resolver_busy");
}

TEST_CASE("destination guard: refusal log and audit are throttled per target",
          "[outbound_destination_guard][security]") {
    RefusalThrottle t{std::chrono::seconds(300)};
    const auto t0 = std::chrono::steady_clock::now();
    CHECK(t.admit(7, t0));
    CHECK_FALSE(t.admit(7, t0 + std::chrono::seconds(10)));
    CHECK(t.admit(8, t0 + std::chrono::seconds(10))); // another target has its own window
    CHECK(t.admit(7, t0 + std::chrono::seconds(301))); // the window elapses
}

TEST_CASE("destination guard: the cause labels are the closed pair", "[outbound_destination_guard]") {
    CHECK(std::string{destination_cause(DestinationVerdict::Refused)} == "destination_refused");
    CHECK(std::string{destination_cause(DestinationVerdict::Unresolved)} == "destination_unresolved");
    CHECK(std::string{destination_cause(DestinationVerdict::ResolverBusy)} == "destination_resolver_busy");
}

TEST_CASE("destination guard: an empty resolver answer fails closed and a malformed authority is not judged",
          "[outbound_destination_guard][security]") {
    CHECK(vet_resolved_addresses("h.example", {}).verdict == DestinationVerdict::Unresolved);
    CHECK(vet_resolved_addresses("h.example", {"93.184.216.34"}).verdict == DestinationVerdict::Allow);
    CHECK(detail::bare_host("[]").empty());
    CHECK(detail::bare_host("[::1]:8080") == "::1");
    CHECK(detail::bare_host("host.example:8080") == "host.example");
    CHECK(detail::bare_host("host.example") == "host.example");
}

// At capacity the table evicts (expired first, else the oldest), never clears wholesale: a target that
// is still inside its window stays throttled, so one flood of new ids cannot make every throttled target
// log and audit again at once.
TEST_CASE("RefusalThrottle: at capacity a recent target stays throttled (eviction, not clear)",
          "[destination_guard][throttle]") {
    using yuzu::server::RefusalThrottle;
    RefusalThrottle t{std::chrono::seconds(300)};
    const auto t0 = std::chrono::steady_clock::now();
    REQUIRE(t.admit(1, t0));
    for (std::int64_t id = 2; id <= static_cast<std::int64_t>(RefusalThrottle::kMaxTracked); ++id)
        REQUIRE(t.admit(id, t0 + std::chrono::seconds(1)));
    // The table is full. A NEW id evicts the oldest (id 1), not everything.
    REQUIRE(t.admit(100000, t0 + std::chrono::seconds(2)));
    CHECK_FALSE(t.admit(2, t0 + std::chrono::seconds(3)));  // still inside its window: throttled
    CHECK_FALSE(t.admit(100000, t0 + std::chrono::seconds(3)));
    CHECK(t.admit(1, t0 + std::chrono::seconds(3)));         // the evicted one is a first sighting again
}
