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
#include <stdexcept>
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

std::shared_ptr<HostLookupAdmission> make_limited(FakeClock& clock, std::size_t per_name,
                                                  std::size_t max_names = 64) {
    HostLookupAdmission::Limits limits;
    limits.per_name_in_flight = per_name;
    limits.max_names_in_flight = max_names;
    return HostLookupAdmission::create(limits, clock.fn());
}

/// Admits `host` and requires it to be admitted, returning the lease.
HostLookupAdmission::Lease take(HostLookupAdmission& adm, std::string_view host) {
    auto admitted = adm.admit(host);
    REQUIRE(admitted.verdict == Verdict::kAdmitted);
    REQUIRE(static_cast<bool>(admitted.lease));
    return std::move(admitted.lease);
}

} // namespace

TEST_CASE("HostLookupAdmission: the defaults are the documented limits",
          "[resolver_host_admission]") {
    const HostLookupAdmission::Limits limits;
    CHECK(limits.refusal_ttl == seconds(3));
    CHECK(limits.max_refusal_entries == 32);
    CHECK(limits.per_name_in_flight == 8);
    CHECK(limits.max_names_in_flight == 64);
    CHECK(yuzu::server::net::kLookupRefusalTtl == seconds(3));
    CHECK(yuzu::server::net::kLookupRefusalMaxNames == 32);
    CHECK(yuzu::server::net::kLookupPerNameLimit == 8);
    CHECK(yuzu::server::net::kLookupMaxNames == 64);
}

TEST_CASE("HostLookupAdmission: a name is admitted until a lookup for it was refused or timed out",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    CHECK(adm->admit("idp.example").verdict == Verdict::kAdmitted);
    CHECK(adm->refusal_entries() == 0); // admitting arms nothing

    adm->note_outcome("idp.example", ResolveStatus::kBusy);
    CHECK(adm->admit("idp.example").verdict == Verdict::kRefusedRecent);
    CHECK(adm->admit("other.example").verdict == Verdict::kAdmitted); // another name is unaffected
}

TEST_CASE("HostLookupAdmission: names that differ only by case or one trailing dot share an entry",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("Idp.Example.", ResolveStatus::kTimeout);
    CHECK(adm->refusal_entries() == 1);
    CHECK(adm->admit("idp.example").verdict == Verdict::kRefusedRecent);
    CHECK(adm->admit("IDP.EXAMPLE").verdict == Verdict::kRefusedRecent);
    CHECK(adm->admit("idp.example.").verdict == Verdict::kRefusedRecent);
    CHECK(adm->admit("idp.example2").verdict == Verdict::kAdmitted);

    // Exactly one trailing dot is removed: "a.." and "a" are different names.
    adm->note_outcome("a..", ResolveStatus::kBusy);
    CHECK(adm->admit("a..").verdict == Verdict::kRefusedRecent);
    CHECK(adm->admit("a").verdict == Verdict::kAdmitted);
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
        CHECK(adm->admit(host).verdict == Verdict::kAdmitted);
    }
    // 253 bytes is the longest name that is keyed.
    const std::string longest(253, 'a');
    adm->note_outcome(longest, ResolveStatus::kBusy);
    CHECK(adm->admit(longest).verdict == Verdict::kRefusedRecent);
}

TEST_CASE("HostLookupAdmission: the refusal ends at the TTL and its entry is dropped",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("idp.example", ResolveStatus::kBusy);
    clock.advance(seconds(3) - std::chrono::nanoseconds(1));
    CHECK(adm->admit("idp.example").verdict == Verdict::kRefusedRecent);
    clock.advance(std::chrono::nanoseconds(1)); // exactly the TTL
    CHECK(adm->admit("idp.example").verdict == Verdict::kAdmitted);
    CHECK(adm->refusal_entries() == 0);
}

TEST_CASE("HostLookupAdmission: a refusal served from memory does not extend the block",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make(clock);
    adm->note_outcome("idp.example", ResolveStatus::kBusy);
    for (int i = 0; i < 5; ++i) {
        clock.advance(std::chrono::milliseconds(500));
        CHECK(adm->admit("idp.example").verdict == Verdict::kRefusedRecent); // t0 + 0.5 s ... 2.5 s
    }
    clock.advance(std::chrono::milliseconds(500)); // t0 + 3 s
    CHECK(adm->admit("idp.example").verdict == Verdict::kAdmitted);
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
    CHECK(adm->admit("a.example").verdict == Verdict::kAdmitted);

    adm->note_outcome("b.example", ResolveStatus::kTimeout);
    CHECK(adm->admit("b.example").verdict == Verdict::kRefusedRecent);
    adm->note_outcome("c.example", ResolveStatus::kBusy);
    CHECK(adm->admit("c.example").verdict == Verdict::kRefusedRecent);

    // Not found and temporary leave an armed name as it is; ok removes it.
    adm->note_outcome("b.example", ResolveStatus::kNotFound);
    adm->note_outcome("b.example", ResolveStatus::kTemporary);
    CHECK(adm->admit("b.example").verdict == Verdict::kRefusedRecent);
    adm->note_outcome("b.example", ResolveStatus::kOk);
    CHECK(adm->admit("b.example").verdict == Verdict::kAdmitted);
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
    CHECK(adm->admit("idp.example").verdict == Verdict::kRefusedRecent);
    clock.advance(seconds(1)); // t0 + 5 s: the second expiry
    CHECK(adm->admit("idp.example").verdict == Verdict::kAdmitted);
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
        CHECK(adm->admit("n1.example").verdict == Verdict::kAdmitted); // the two earliest are gone
        CHECK(adm->admit("n2.example").verdict == Verdict::kAdmitted);
        CHECK(adm->admit("n3.example").verdict == Verdict::kRefusedRecent);
        CHECK(adm->admit("n4.example").verdict == Verdict::kRefusedRecent);
        CHECK(adm->admit("n5.example").verdict == Verdict::kRefusedRecent);
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
        CHECK(adm->admit("old.example").verdict == Verdict::kAdmitted);
        CHECK(adm->admit("mid.example").verdict == Verdict::kAdmitted);
        CHECK(adm->admit("new.example").verdict == Verdict::kRefusedRecent);
        CHECK(adm->admit("fourth.example").verdict == Verdict::kRefusedRecent);
    }
    SECTION("re-arming a name already in the table needs no room") {
        for (const char* name : {"a.example", "b.example", "c.example"})
            adm->note_outcome(name, ResolveStatus::kBusy);
        adm->note_outcome("a.example", ResolveStatus::kTimeout);
        CHECK(adm->refusal_entries() == 3);
        CHECK(adm->admit("b.example").verdict == Verdict::kRefusedRecent);
        CHECK(adm->admit("c.example").verdict == Verdict::kRefusedRecent);
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

TEST_CASE("HostLookupAdmission: at most 8 lookups for one name are outstanding at once",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = HostLookupAdmission::create({}, clock.fn());
    std::vector<HostLookupAdmission::Lease> leases;
    for (std::size_t i = 0; i < 8; ++i)
        leases.push_back(take(*adm, "idp.example"));
    CHECK(adm->in_flight_for("idp.example") == 8);

    auto refused = adm->admit("idp.example");
    CHECK(refused.verdict == Verdict::kRefusedNameLimit);
    CHECK_FALSE(static_cast<bool>(refused.lease));
    CHECK(adm->in_flight_for("idp.example") == 8); // a refusal takes no count
    CHECK(adm->refusal_entries() == 0);            // and is not remembered
}

TEST_CASE("HostLookupAdmission: the per-name limit counts per name, frees on release and erases "
          "the entry at zero",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, /*per_name=*/4);
    std::vector<HostLookupAdmission::Lease> leases;
    for (int i = 0; i < 4; ++i)
        leases.push_back(take(*adm, "a.example"));
    CHECK(adm->admit("a.example").verdict == Verdict::kRefusedNameLimit);
    CHECK(adm->admit("b.example").verdict == Verdict::kAdmitted); // another name is unaffected
    CHECK(adm->hosts_in_flight() == 1); // that admission's temporary lease is already released

    leases.pop_back(); // one lookup returned
    CHECK(adm->in_flight_for("a.example") == 3);
    leases.push_back(take(*adm, "a.example")); // so one more is admitted
    CHECK(adm->admit("a.example").verdict == Verdict::kRefusedNameLimit);

    leases.clear();
    CHECK(adm->in_flight_for("a.example") == 0);
    CHECK(adm->hosts_in_flight() == 0); // the table holds only names with a lookup outstanding
}

TEST_CASE("HostLookupAdmission: names that differ only by case or one trailing dot share a limit",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, 3);
    auto one = take(*adm, "Idp.Example.");
    auto two = take(*adm, "idp.example");
    auto three = take(*adm, "IDP.EXAMPLE");
    CHECK(adm->in_flight_for("idp.example.") == 3);
    CHECK(adm->admit("idp.example").verdict == Verdict::kRefusedNameLimit);
    CHECK(adm->hosts_in_flight() == 1);
}

TEST_CASE("HostLookupAdmission: names that cannot be keyed share ONE limit and cannot bypass it",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, 3);
    const std::vector<std::string> unkeyable = {"",
                                                std::string(254, 'a'),
                                                std::string("a\x01" "b"),
                                                "a b",
                                                std::string("a\0b", 3),
                                                "."};
    std::vector<HostLookupAdmission::Lease> leases;
    for (std::size_t i = 0; i < 3; ++i)
        leases.push_back(take(*adm, unkeyable[i]));
    // Every other spelling that cannot be keyed is on the same count.
    for (const auto& host : unkeyable) {
        CAPTURE(host.size());
        CHECK(adm->admit(host).verdict == Verdict::kRefusedNameLimit);
    }
    CHECK(adm->hosts_in_flight() == 1);
    CHECK(adm->in_flight_for("") == 3);
    // A real name is a different key.
    CHECK(adm->admit("real.example").verdict == Verdict::kAdmitted);
    // Never remembered, so never refused from memory either.
    adm->note_outcome("", ResolveStatus::kBusy);
    CHECK(adm->refusal_entries() == 0);
}

TEST_CASE("HostLookupAdmission: at most 64 names have a lookup outstanding; a new name beyond is "
          "refused, never untracked",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, /*per_name=*/2, /*max_names=*/2);
    auto a = take(*adm, "a.example");
    auto b = take(*adm, "b.example");
    auto third = adm->admit("c.example");
    CHECK(third.verdict == Verdict::kRefusedTableFull);
    CHECK_FALSE(static_cast<bool>(third.lease));
    CHECK(adm->hosts_in_flight() == 2);
    // A name already in the table still admits up to its own limit.
    auto a2 = take(*adm, "a.example");
    CHECK(adm->admit("a.example").verdict == Verdict::kRefusedNameLimit);
    // Freeing every lookup of one name admits the new one.
    b.release();
    auto c = take(*adm, "c.example");
    CHECK(adm->hosts_in_flight() == 2);
    // The unkeyable sentinel needs a table slot too, and is refused when none is free.
    CHECK(adm->admit("").verdict == Verdict::kRefusedTableFull);
}

TEST_CASE("HostLookupAdmission: a refusal from memory takes no count, and a refusal by the limit "
          "is not remembered",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, 1);
    adm->note_outcome("armed.example", ResolveStatus::kBusy);
    auto recent = adm->admit("armed.example");
    CHECK(recent.verdict == Verdict::kRefusedRecent);
    CHECK(adm->in_flight_for("armed.example") == 0);
    CHECK(adm->hosts_in_flight() == 0);

    auto held = take(*adm, "full.example");
    CHECK(adm->admit("full.example").verdict == Verdict::kRefusedNameLimit);
    held.release();
    CHECK(adm->admit("full.example").verdict == Verdict::kAdmitted); // not Recent: nothing armed
    CHECK(adm->refusal_entries() == 1);                             // armed.example only
}

TEST_CASE("HostLookupAdmission::Lease: one release per admission, whatever is done to it",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, 4);

    SECTION("a default lease does nothing") {
        HostLookupAdmission::Lease none;
        CHECK_FALSE(static_cast<bool>(none));
        none.release();
        CHECK(adm->hosts_in_flight() == 0);
    }
    SECTION("release is idempotent") {
        auto lease = take(*adm, "a.example");
        CHECK(adm->in_flight_for("a.example") == 1);
        lease.release();
        lease.release();
        CHECK(adm->in_flight_for("a.example") == 0);
        // A second lease on the same name is not reduced by the first one's repeated release.
        auto other = take(*adm, "a.example");
        auto again = take(*adm, "a.example");
        again.release();
        again.release();
        CHECK(adm->in_flight_for("a.example") == 1);
    }
    SECTION("a moved lease leaves exactly one release") {
        auto lease = take(*adm, "a.example");
        HostLookupAdmission::Lease moved(std::move(lease));
        CHECK_FALSE(static_cast<bool>(lease)); // NOLINT(bugprone-use-after-move)
        lease.release();
        CHECK(adm->in_flight_for("a.example") == 1);
        moved.release();
        CHECK(adm->in_flight_for("a.example") == 0);
    }
    SECTION("move assignment releases the count the target held") {
        auto first = take(*adm, "a.example");
        auto second = take(*adm, "b.example");
        first = std::move(second);
        CHECK(adm->in_flight_for("a.example") == 0);
        CHECK(adm->in_flight_for("b.example") == 1);
    }
    SECTION("the destructor releases") {
        {
            auto lease = take(*adm, "a.example");
            CHECK(adm->in_flight_for("a.example") == 1);
        }
        CHECK(adm->in_flight_for("a.example") == 0);
    }
}

TEST_CASE("HostLookupAdmission::Lease: a lease keeps the admission alive and can outlive its "
          "handle",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, 2);
    auto lease = take(*adm, "a.example");
    adm.reset(); // the lease is the only owner now
    lease.release();
    SUCCEED("released after the last external handle was dropped");
}

TEST_CASE("hold_lease_during: the worker releases when the lookup returns, throws, or never runs",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, 4);
    const auto ok = [](const std::string&) {
        return yuzu::server::net::ResolveResult{ResolveStatus::kOk, {"93.184.216.34"}};
    };

    SECTION("returns: held during the lookup, released before the call returns") {
        std::size_t seen_inside = 99;
        auto fn = yuzu::server::net::hold_lease_during(
            [&](const std::string& host) {
                seen_inside = adm->in_flight_for(host);
                return ok(host);
            },
            take(*adm, "a.example"));
        CHECK(adm->in_flight_for("a.example") == 1); // admitted, lookup not yet called
        const auto result = fn("a.example");
        CHECK(result.status == ResolveStatus::kOk);
        CHECK(seen_inside == 1);
        CHECK(adm->in_flight_for("a.example") == 0); // fn is still alive: released by the call
    }
    SECTION("throws: the exception propagates and the count is released") {
        auto fn = yuzu::server::net::hold_lease_during(
            [](const std::string&) -> yuzu::server::net::ResolveResult {
                throw std::runtime_error("resolver failed");
            },
            take(*adm, "a.example"));
        CHECK_THROWS_AS(fn("a.example"), std::runtime_error);
        CHECK(adm->in_flight_for("a.example") == 0);
    }
    SECTION("never run: destroying the wrapper releases the count") {
        {
            auto fn = yuzu::server::net::hold_lease_during(ok, take(*adm, "a.example"));
            CHECK(adm->in_flight_for("a.example") == 1);
        }
        CHECK(adm->in_flight_for("a.example") == 0);
    }
    SECTION("copies: the count stays until the last copy is gone") {
        auto fn = yuzu::server::net::hold_lease_during(ok, take(*adm, "a.example"));
        auto copy = fn;
        fn = nullptr;
        CHECK(adm->in_flight_for("a.example") == 1);
        copy = nullptr;
        CHECK(adm->in_flight_for("a.example") == 0);
    }
    SECTION("running one copy releases once; a second run does not release again") {
        auto first = take(*adm, "a.example");
        auto second = take(*adm, "a.example");
        auto fn = yuzu::server::net::hold_lease_during(ok, std::move(first));
        (void)fn("a.example");
        (void)fn("a.example");
        CHECK(adm->in_flight_for("a.example") == 1); // only `second` remains
    }
}

TEST_CASE("HostLookupAdmission: concurrent admission never holds more than the limit and ends "
          "empty",
          "[resolver_host_admission]") {
    FakeClock clock;
    auto adm = make_limited(clock, /*per_name=*/3, /*max_names=*/8);
    constexpr int kNames = 3;
    std::atomic<int> held[kNames]{};
    std::atomic<int> max_held[kNames]{};
    std::atomic<bool> go{false};

    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
        threads.emplace_back([&, t] {
            while (!go.load()) {
            }
            for (int i = 0; i < 2000; ++i) {
                const int n = (t + i) % kNames;
                auto admitted = adm->admit("n" + std::to_string(n) + ".example");
                if (admitted.verdict != Verdict::kAdmitted)
                    continue;
                const int now_held = held[n].fetch_add(1) + 1;
                int prev = max_held[n].load();
                while (now_held > prev && !max_held[n].compare_exchange_weak(prev, now_held)) {
                }
                held[n].fetch_sub(1);
                admitted.lease.release();
            }
        });
    go.store(true);
    for (auto& th : threads)
        th.join();
    for (int n = 0; n < kNames; ++n) {
        CAPTURE(n);
        CHECK(max_held[n].load() <= 3);
        CHECK(max_held[n].load() >= 1);
    }
    CHECK(adm->hosts_in_flight() == 0);
}

TEST_CASE("OIDC lookup admission wiring (LEXICAL pin, not behaviour): the check runs before the "
          "lookup, only a lookup that ran feeds the memory, and a refusal is counted once",
          "[resolver_host_admission][wiring][lexical]") {
    const std::string flat = squeeze(comment_free_source("oidc_provider.cpp"));

    const auto exempt = flat.find("if(mode==LookupAdmission::kExempt)admission.reset();");
    const auto admit = flat.find("admission->admit(host)");
    const auto resolve = flat.find("net::bounded_resolve(host,std::chrono::seconds(timeout_sec),");
    const auto feed = flat.find("admission->note_outcome(host,resolved.status);");
    REQUIRE(exempt != std::string::npos);
    REQUIRE(admit != std::string::npos);
    REQUIRE(resolve != std::string::npos);
    REQUIRE(feed != std::string::npos);
    // The lease wrapper is installed between the check and the lookup.
    const auto wrap = flat.find("net::hold_lease_during(std::move(lookup),std::move(admitted.lease))");
    REQUIRE(wrap != std::string::npos);
    CHECK(count_occurrences(flat, "hold_lease_during(") == 1);
    // The exemption is decided before the admission is consulted.
    CHECK(exempt < admit);
    CHECK(admit < wrap);
    CHECK(wrap < resolve);
    CHECK(resolve < feed);
    CHECK(count_occurrences(flat, "admission->admit(") == 1);
    CHECK(count_occurrences(flat, "admission->note_outcome(") == 1);
    // The memory is fed only through the admission, which an exempt call does not have.
    CHECK(count_occurrences(flat, "if(admission)admission->note_outcome(") == 1);
    // A refusal made before the pool is counted once, as busy, by the adapter (the pool counts
    // only the lookups it ran).
    CHECK(count_occurrences(flat, "pool->note_outcome(net::ResolveStatus::kBusy);") == 2);
    // Only the NAT64 probe is exempt: one reset of the admission and one exempt caller.
    CHECK(count_occurrences(flat, "LookupAdmission::kExempt") == 2);
    CHECK(count_occurrences(flat, "admission.reset();") == 1);
    CHECK(count_occurrences(flat, "resolve_host_addresses_status(") == 3); // definition + two callers
    // The warnings share one throttle with a small key budget.
    CHECK(count_occurrences(flat, "RefusalLogThrottle(std::chrono::seconds(60),4)") == 1);
    CHECK(count_occurrences(flat, "should_warn(") <= 4);
    // Four fixed keys in all: the two pool warnings and the two refusals before the pool.
    CHECK(count_occurrences(flat, "\"oidc_lookup_busy\"") == 1);
    CHECK(count_occurrences(flat, "\"oidc_nat64_probe_busy\"") == 1);
    CHECK(count_occurrences(flat, "\"oidc_lookup_refused_recent\"") == 1);
    CHECK(count_occurrences(flat, "\"oidc_lookup_refused_name_limit\"") == 2);
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
    const std::string per_name =
        std::to_string(yuzu::server::net::kLookupPerNameLimit) + " lookups for the same name";
    const std::string max_names = std::to_string(yuzu::server::net::kLookupMaxNames) + " names";

    for (const char* doc : {"docs/user-manual/authentication.md", "docs/user-manual/metrics.md",
                            "docs/user-manual/upgrading.md"}) {
        CAPTURE(doc);
        const std::string text = read_repo_file(doc);
        REQUIRE_FALSE(text.empty());
        CHECK(text.find(names) != std::string::npos);
        CHECK(text.find(ttl) != std::string::npos);
        CHECK(text.find(per_name) != std::string::npos);
        CHECK(text.find(max_names) != std::string::npos);
    }
    for (const char* doc : {"docs/user-manual/authentication.md", "docs/user-manual/metrics.md",
                            }) {
        CAPTURE(doc);
        const std::string text = read_repo_file(doc);
        REQUIRE_FALSE(text.empty());
        CHECK(text.find(window) != std::string::npos);
    }
    // These two wrap or spell the interval differently.
    const std::string help = read_repo_file("server/core/src/resolver_pool_metrics.hpp");
    CHECK(help.find("the last " + ttl) != std::string::npos);
    const std::string alerts = read_repo_file("docs/prometheus/yuzu-alerts.yml");
    CHECK(alerts.find("the last " +
                      std::to_string(yuzu::server::net::kLookupRefusalTtl.count()) + " seconds") !=
          std::string::npos);
}
