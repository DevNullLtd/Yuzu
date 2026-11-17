/**
 * test_outbound_destination_guard.cpp -- WP10 / F43 (#4816, #3870): the destination-ADDRESS guard
 * for webhook and offload-target delivery (outbound_destination_guard.hpp). Pure: the resolver is
 * injected, nothing touches the network.
 *
 * Scope under test (owner ruling): unspecified, link-local / metadata, multicast and reserved are
 * refused; loopback and private ranges are NOT; a name is resolved once and the vetted answer is
 * the connect target.
 */
#include "outbound_destination_guard.hpp"

#include <catch2/catch_test_macros.hpp>

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
    // Existing deployments (and tests) post to loopback and RFC 1918 receivers: not refused here.
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
    CHECK(lo.pinned_ip.empty());
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
        CHECK(v.pinned_ip.empty());
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
    CHECK(v.pinned_ip == "93.184.216.34");
    CHECK(v.host == "hooks.example.com"); // the addr-map key: no port, no path
    CHECK(lookups == 1);
}

TEST_CASE("destination guard: a private answer for a name is allowed (loopback and RFC 1918 are not refused)",
          "[outbound_destination_guard][security]") {
    auto lookup = [](const std::string&) { return answer({"10.0.0.7"}); };
    const auto v = vet_delivery_destination("http://siem.internal/x", std::chrono::seconds(1), lookup);
    CHECK(v.verdict == DestinationVerdict::Allow);
    CHECK(v.pinned_ip == "10.0.0.7");
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
