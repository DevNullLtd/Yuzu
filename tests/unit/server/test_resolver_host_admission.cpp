/**
 * test_resolver_host_admission.cpp -- the refusal memory in front of the OIDC name lookup
 * (resolver_host_admission.hpp). Deterministic: an injected clock, no DNS, no sleeping for time.
 * Only the concurrency case starts threads, and it asserts after the joins (Catch2 assertions are
 * not thread-safe).
 *
 * The wiring through the OIDC adapter is in test_oidc_egress.cpp ([oidc_resolver]).
 */

// bounded_resolver.hpp first: on Windows it must see winsock2.h before windows.h.
#include "bounded_resolver.hpp"
#include "resolver_host_admission.hpp"
#include "source_scan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

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

using yuzu::server::net::HostLookupAdmission;
using yuzu::server::net::ResolveStatus;
using Verdict = HostLookupAdmission::Verdict;
using Clock = HostLookupAdmission::Clock;
using std::chrono::seconds;

/// A clock the test moves by hand.
struct FakeClock {
    std::atomic<Clock::rep> ticks{Clock::now().time_since_epoch().count()};
    Clock::time_point now() const { return Clock::time_point(Clock::duration(ticks.load())); }
    void advance(Clock::duration d) { ticks.fetch_add(d.count()); }
    HostLookupAdmission::NowFn fn() {
        return [this] { return now(); };
    }
};

std::shared_ptr<HostLookupAdmission> make(FakeClock& clock, std::size_t max_entries = 32) {
    HostLookupAdmission::Limits limits;
    limits.max_refusal_entries = max_entries;
    return HostLookupAdmission::create(limits, clock.fn());
}

} // namespace

TEST_CASE("HostLookupAdmission: the defaults are the documented limits",
          "[resolver_host_admission]") {
    const HostLookupAdmission::Limits limits;
    CHECK(limits.refusal_ttl == seconds(3));
    CHECK(limits.max_refusal_entries == 32);
    CHECK(yuzu::server::net::kLookupRefusalTtl == seconds(3));
    CHECK(yuzu::server::net::kLookupRefusalMaxNames == 32);
}

TEST_CASE("HostLookupAdmission: a name is admitted until a lookup for it was refused or timed out",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    CHECK(adm->admit("idp.example") == Verdict::kAdmitted);
    CHECK(adm->refusal_entries() == 0); // admitting arms nothing

    adm->note_outcome("idp.example", ResolveStatus::kBusy);
    CHECK(adm->admit("idp.example") == Verdict::kRefusedRecent);
    CHECK(adm->admit("other.example") == Verdict::kAdmitted); // another name is unaffected
}

TEST_CASE("HostLookupAdmission: names that differ only by case or one trailing dot share an entry",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("Idp.Example.", ResolveStatus::kTimeout);
    CHECK(adm->refusal_entries() == 1);
    CHECK(adm->admit("idp.example") == Verdict::kRefusedRecent);
    CHECK(adm->admit("IDP.EXAMPLE") == Verdict::kRefusedRecent);
    CHECK(adm->admit("idp.example.") == Verdict::kRefusedRecent);
    CHECK(adm->admit("idp.example2") == Verdict::kAdmitted);

    // Exactly one trailing dot is removed: "a.." and "a" are different names.
    adm->note_outcome("a..", ResolveStatus::kBusy);
    CHECK(adm->admit("a..") == Verdict::kRefusedRecent);
    CHECK(adm->admit("a") == Verdict::kAdmitted);
}

TEST_CASE("HostLookupAdmission: a name that cannot be keyed is never remembered and never refused",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    const std::vector<std::string> unkeyable = {"",
                                                ".",
                                                std::string(254, 'a'),
                                                std::string("a\x01" "b"),
                                                "a b",
                                                std::string("a\x7f" "b"),
                                                std::string("a\0b", 3)};
    for (const auto& host : unkeyable) {
        adm->note_outcome(host, ResolveStatus::kBusy);
        adm->note_outcome(host, ResolveStatus::kTimeout);
        CHECK(adm->refusal_entries() == 0);
        CHECK(adm->admit(host) == Verdict::kAdmitted);
    }
    // 253 bytes is the longest name that is keyed.
    const std::string longest(253, 'a');
    adm->note_outcome(longest, ResolveStatus::kBusy);
    CHECK(adm->admit(longest) == Verdict::kRefusedRecent);
}

TEST_CASE("HostLookupAdmission: the refusal ends at the TTL and its entry is dropped",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("idp.example", ResolveStatus::kBusy);
    clock.advance(seconds(3) - std::chrono::nanoseconds(1));
    CHECK(adm->admit("idp.example") == Verdict::kRefusedRecent);
    clock.advance(std::chrono::nanoseconds(1)); // exactly the TTL
    CHECK(adm->admit("idp.example") == Verdict::kAdmitted);
    CHECK(adm->refusal_entries() == 0);
}

TEST_CASE("HostLookupAdmission: a refusal served from memory does not extend the block",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("idp.example", ResolveStatus::kBusy);
    for (int i = 0; i < 5; ++i) {
        clock.advance(std::chrono::milliseconds(500));
        CHECK(adm->admit("idp.example") == Verdict::kRefusedRecent); // t0 + 0.5 s ... 2.5 s
    }
    clock.advance(std::chrono::milliseconds(500)); // t0 + 3 s
    CHECK(adm->admit("idp.example") == Verdict::kAdmitted);
}

TEST_CASE("HostLookupAdmission: only a busy or timed out lookup arms a name; an answer never does",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);

    adm->note_outcome("a.example", ResolveStatus::kNotFound);
    adm->note_outcome("a.example", ResolveStatus::kTemporary);
    adm->note_outcome("a.example", ResolveStatus::kOk);
    adm->note_outcome("a.example", ResolveStatus::kCount);
    CHECK(adm->refusal_entries() == 0);
    CHECK(adm->admit("a.example") == Verdict::kAdmitted);

    adm->note_outcome("b.example", ResolveStatus::kTimeout);
    CHECK(adm->admit("b.example") == Verdict::kRefusedRecent);
    adm->note_outcome("c.example", ResolveStatus::kBusy);
    CHECK(adm->admit("c.example") == Verdict::kRefusedRecent);

    // Not found and temporary leave an armed name as it is; ok removes it.
    adm->note_outcome("b.example", ResolveStatus::kNotFound);
    adm->note_outcome("b.example", ResolveStatus::kTemporary);
    CHECK(adm->admit("b.example") == Verdict::kRefusedRecent);
    adm->note_outcome("b.example", ResolveStatus::kOk);
    CHECK(adm->admit("b.example") == Verdict::kAdmitted);
    CHECK(adm->refusal_entries() == 1); // c.example only
}

TEST_CASE("HostLookupAdmission: a lookup that ran and ended busy again re-arms the name to a new TTL",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("idp.example", ResolveStatus::kBusy);
    clock.advance(seconds(2));
    adm->note_outcome("idp.example", ResolveStatus::kTimeout); // a lookup that bypassed the memory
    clock.advance(seconds(2));                                 // t0 + 4 s: past the first expiry
    CHECK(adm->admit("idp.example") == Verdict::kRefusedRecent);
    clock.advance(seconds(1)); // t0 + 5 s: the second expiry
    CHECK(adm->admit("idp.example") == Verdict::kAdmitted);
}

TEST_CASE("HostLookupAdmission: a lookup that bypasses the memory is admitted for an armed name",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("ipv4only.arpa", ResolveStatus::kBusy);
    CHECK(adm->admit("ipv4only.arpa", /*consult_refusal_memory=*/true) == Verdict::kRefusedRecent);
    CHECK(adm->admit("ipv4only.arpa", /*consult_refusal_memory=*/false) == Verdict::kAdmitted);
    CHECK(adm->refusal_entries() == 1); // bypassing neither reads nor changes the entry
}

TEST_CASE("HostLookupAdmission: the memory is bounded; expired entries go before a live one",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock, /*max_entries=*/3);

    SECTION("all live: the entry that expires first is evicted") {
        for (const char* name : {"n1.example", "n2.example", "n3.example", "n4.example",
                                 "n5.example"}) {
            adm->note_outcome(name, ResolveStatus::kBusy);
            clock.advance(std::chrono::milliseconds(100));
            CHECK(adm->refusal_entries() <= 3);
        }
        CHECK(adm->refusal_entries() == 3);
        CHECK(adm->admit("n1.example") == Verdict::kAdmitted); // the two earliest are gone
        CHECK(adm->admit("n2.example") == Verdict::kAdmitted);
        CHECK(adm->admit("n3.example") == Verdict::kRefusedRecent);
        CHECK(adm->admit("n4.example") == Verdict::kRefusedRecent);
        CHECK(adm->admit("n5.example") == Verdict::kRefusedRecent);
    }
    SECTION("every expired entry is dropped before a live one is evicted") {
        adm->note_outcome("old.example", ResolveStatus::kBusy);
        clock.advance(std::chrono::milliseconds(300));
        adm->note_outcome("mid.example", ResolveStatus::kBusy);
        clock.advance(std::chrono::milliseconds(2800)); // t0 + 3.1 s
        adm->note_outcome("new.example", ResolveStatus::kBusy);
        CHECK(adm->refusal_entries() == 3);
        clock.advance(std::chrono::milliseconds(400)); // t0 + 3.5 s: old and mid have expired
        adm->note_outcome("fourth.example", ResolveStatus::kBusy); // the table is at its cap
        CHECK(adm->refusal_entries() == 2);                        // new and fourth only
        CHECK(adm->admit("old.example") == Verdict::kAdmitted);
        CHECK(adm->admit("mid.example") == Verdict::kAdmitted);
        CHECK(adm->admit("new.example") == Verdict::kRefusedRecent);
        CHECK(adm->admit("fourth.example") == Verdict::kRefusedRecent);
    }
    SECTION("re-arming a name already in the table needs no room") {
        for (const char* name : {"a.example", "b.example", "c.example"})
            adm->note_outcome(name, ResolveStatus::kBusy);
        adm->note_outcome("a.example", ResolveStatus::kTimeout);
        CHECK(adm->refusal_entries() == 3);
        CHECK(adm->admit("b.example") == Verdict::kRefusedRecent);
        CHECK(adm->admit("c.example") == Verdict::kRefusedRecent);
    }
}

TEST_CASE("HostLookupAdmission: concurrent arming and admission keeps the table within its cap",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock, /*max_entries=*/8);
    std::atomic<bool> go{false};
    std::atomic<std::size_t> max_seen{0};

    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
        threads.emplace_back([&, t] {
            while (!go.load()) {
            }
            for (int i = 0; i < 2000; ++i) {
                const std::string name = "n" + std::to_string((t * 7 + i) % 40) + ".example";
                adm->note_outcome(name, i % 3 == 0 ? ResolveStatus::kBusy : ResolveStatus::kOk);
                (void)adm->admit(name);
                const auto seen = adm->refusal_entries();
                auto prev = max_seen.load();
                while (seen > prev && !max_seen.compare_exchange_weak(prev, seen)) {
                }
            }
        });
    go.store(true);
    for (auto& th : threads)
        th.join();
    CHECK(max_seen.load() <= 8);
    CHECK(adm->refusal_entries() <= 8);
}

TEST_CASE("OIDC lookup admission wiring (LEXICAL pin, not behaviour): the check runs before the "
          "lookup, only a lookup that ran feeds the memory, and a refusal is counted once",
          "[resolver_host_admission][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("oidc_provider.cpp"));

    const auto admit = flat.find("admission->admit(host,memory==LookupMemory::kUse)");
    const auto resolve = flat.find("net::bounded_resolve(host,std::chrono::seconds(timeout_sec),");
    const auto feed = flat.find("admission->note_outcome(host,resolved.status);");
    REQUIRE(admit != std::string::npos);
    REQUIRE(resolve != std::string::npos);
    REQUIRE(feed != std::string::npos);
    CHECK(admit < resolve);
    CHECK(resolve < feed);
    CHECK(count_occurrences(flat, "admission->admit(") == 1);
    CHECK(count_occurrences(flat, "admission->note_outcome(") == 1);
    // The memory is fed only for a call that consults it.
    CHECK(count_occurrences(flat, "if(admission&&memory==LookupMemory::kUse)admission->note_outcome(") == 1);
    // A refusal made before the pool is counted once, as busy, by the adapter (the pool counts
    // only the lookups it ran).
    CHECK(count_occurrences(flat, "pool->note_outcome(net::ResolveStatus::kBusy);") == 1);
    // Only the NAT64 probe bypasses the memory.
    CHECK(count_occurrences(flat, "LookupMemory::kBypass") == 1);
    CHECK(count_occurrences(flat, "resolve_host_addresses_status(") == 3); // definition + two callers
    // The warnings share one throttle with a small key budget.
    CHECK(count_occurrences(flat, "RefusalLogThrottle(std::chrono::seconds(60),4)") == 1);
    CHECK(count_occurrences(flat, "should_warn(") <= 4);
}

namespace {

std::string read_repo_file(const std::string& relative) {
    // YUZU_SERVER_SRC_DIR is <repo>/server/core/src.
    const std::filesystem::path root =
        std::filesystem::path(YUZU_SERVER_SRC_DIR).parent_path().parent_path().parent_path();
    std::ifstream in(root / relative, std::ios::binary);
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

} // namespace

TEST_CASE("OIDC lookup admission limits (LEXICAL pin, not behaviour): the documented figures are "
          "the constants",
          "[resolver_host_admission][wiring][lexical]") {
    const std::string ttl = std::to_string(yuzu::server::net::kLookupRefusalTtl.count()) + " s";
    const std::string names =
        std::to_string(yuzu::server::net::kLookupRefusalMaxNames) + " names";
    const std::string window = "refused or timed out in the last " + ttl;

    for (const char* doc : {"docs/user-manual/authentication.md", "docs/user-manual/metrics.md",
                            "docs/user-manual/upgrading.md"}) {
        CAPTURE(doc);
        const std::string text = read_repo_file(doc);
        REQUIRE_FALSE(text.empty());
        CHECK(text.find(names) != std::string::npos);
        CHECK(text.find(ttl) != std::string::npos);
    }
    for (const char* doc : {"docs/user-manual/authentication.md", "docs/user-manual/metrics.md",
                            "server/core/src/oidc_provider.cpp"}) {
        CAPTURE(doc);
        const std::string text = read_repo_file(doc);
        REQUIRE_FALSE(text.empty());
        CHECK(text.find(window) != std::string::npos);
    }
    // These two wrap or spell the interval differently.
    const std::string help = read_repo_file("server/core/src/resolver_pool_metrics.hpp");
    CHECK(help.find("the last " + ttl) != std::string::npos);
    const std::string alerts = read_repo_file("docs/prometheus/yuzu-alerts.yml");
    CHECK(alerts.find("in the last " +
                      std::to_string(yuzu::server::net::kLookupRefusalTtl.count()) + " seconds") !=
          std::string::npos);
}
