/**
 * test_guardian_rule_bundle.cpp: GuardianRuleBundleCache and make_bundle (#5513,
 * Fable opinion section B last paragraph and section F). Injected loaders; concurrency
 * tests synchronise on events, never on sleeps.
 */

#include "guardian_rule_bundle.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

using namespace yuzu::server;
using namespace yuzu::server::guardian;

namespace {

class Event {
public:
    void set() {
        {
            std::lock_guard lk(m_);
            set_ = true;
        }
        cv_.notify_all();
    }
    void wait() {
        std::unique_lock lk(m_);
        cv_.wait(lk, [&] { return set_; });
    }

private:
    std::mutex m_;
    std::condition_variable cv_;
    bool set_{false};
};

GuaranteedStateRuleRow rule(std::string id, std::string scope, bool enabled = true) {
    GuaranteedStateRuleRow r;
    r.rule_id = id;
    r.name = std::move(id);
    r.scope_expr = std::move(scope);
    r.enabled = enabled;
    return r;
}

// A loader that builds a one-rule bundle tagged by `marker` and counts calls.
GuardianRuleBundleCache::LoaderFn counting_loader(std::atomic<int>& calls, std::string marker,
                                                  std::uint64_t bogus_generation = 999) {
    return [&calls, marker = std::move(marker), bogus_generation] {
        calls.fetch_add(1);
        Bundle b = make_bundle({rule(marker, "tag:env == \"prod\"")}, {marker});
        b.generation = bogus_generation;  // the cache must overwrite this
        return std::expected<Bundle, BundleLoadError>(std::move(b));
    };
}

}  // namespace

TEST_CASE("make_bundle: parses each distinct scope of enabled rules once",
          "[guardian][rule_bundle]") {
    std::vector<GuaranteedStateRuleRow> rows;
    rows.push_back(rule("a", "tag:env == \"prod\""));
    rows.push_back(rule("b", "tag:env == \"prod\""));          // duplicate scope
    rows.push_back(rule("c", ""));                              // fleet-wide, nothing to parse
    rows.push_back(rule("d", "tag:tier == \"gold\"", false));   // disabled: not parsed
    rows.push_back(rule("e", "== == =="));                      // does not parse
    rows.push_back(rule("f", "ostype == \"windows\""));
    auto b = make_bundle(rows, {"a", "b", "c", "d", "e", "f"});

    CHECK(b.rules.size() == 6);  // rows pass through untouched, order preserved
    CHECK(b.rules[0].rule_id == "a");
    CHECK(b.deployed_rule_ids.size() == 6);
    CHECK(b.scopes.size() == 3);  // prod, the unparseable one, ostype
    CHECK(b.find_scope("tag:tier == \"gold\"") == nullptr);  // disabled rule: absent
    CHECK(b.find_scope("") == nullptr);
    CHECK(b.find_scope("never seen") == nullptr);
    CHECK(b.find_scope("== == ==") == nullptr);  // parse failure means "not a member"
    REQUIRE(b.scopes.contains("== == =="));
    CHECK_FALSE(b.scopes.at("== == ==").parse_error.empty());

    const auto* expr = b.find_scope("tag:env == \"prod\"");
    REQUIRE(expr != nullptr);
    CHECK(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("prod"); }));
    CHECK_FALSE(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("dev"); }));
    // The same parsed tree evaluates differently per agent: it holds no membership.
    CHECK(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("prod"); }));
}

TEST_CASE("GuardianRuleBundleCache: same generation hits the cache",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    const auto loader = counting_loader(calls, "r1");
    auto a = cache.get(7, loader);
    auto b = cache.get(7, loader);
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    CHECK(calls.load() == 1);
    CHECK(cache.loads() == 1);
    CHECK(a->get() == b->get());  // the very same bundle object
    CHECK((*a)->generation == 7);  // stamped by the cache, not the loader's 999
    CHECK(cache.held_generation() == 7);
}

TEST_CASE("GuardianRuleBundleCache: a different generation reloads and replaces",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    auto g1 = cache.get(1, counting_loader(calls, "one"));
    auto g2 = cache.get(2, counting_loader(calls, "two"));
    REQUIRE(g1.has_value());
    REQUIRE(g2.has_value());
    CHECK(calls.load() == 2);
    CHECK((*g1)->generation == 1);
    CHECK((*g2)->generation == 2);
    CHECK((*g2)->rules[0].rule_id == "two");
    CHECK(cache.held_generation() == 2);
}

TEST_CASE("GuardianRuleBundleCache: never serves a bundle for a different generation",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    REQUIRE(cache.get(5, counting_loader(calls, "five")).has_value());
    // Going to a higher generation and back down must reload each time: only ONE
    // bundle is held and it is returned only for its own generation.
    auto up = cache.get(6, counting_loader(calls, "six"));
    REQUIRE(up.has_value());
    CHECK((*up)->generation == 6);
    CHECK((*up)->rules[0].rule_id == "six");
    auto back = cache.get(5, counting_loader(calls, "five-again"));  // a store reset
    REQUIRE(back.has_value());
    CHECK((*back)->generation == 5);
    CHECK((*back)->rules[0].rule_id == "five-again");  // a fresh load, not the old five
    CHECK(calls.load() == 3);
}

TEST_CASE("GuardianRuleBundleCache: a failed load is not cached", "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn failing = [&calls] {
        calls.fetch_add(1);
        return std::expected<Bundle, BundleLoadError>(std::unexpected(
            BundleLoadError{BundleLoadError::Source::deployed, "baseline store down"}));
    };
    auto r = cache.get(3, failing);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().source == BundleLoadError::Source::deployed);  // source preserved
    CHECK(r.error().detail == "baseline store down");
    CHECK_FALSE(cache.held_generation().has_value());
    auto again = cache.get(3, failing);
    CHECK_FALSE(again.has_value());
    CHECK(calls.load() == 2);  // retried, not served from a negative cache

    std::atomic<int> ok_calls{0};
    auto ok = cache.get(3, counting_loader(ok_calls, "ok"));
    REQUIRE(ok.has_value());
    CHECK(cache.held_generation() == 3);
}

TEST_CASE("GuardianRuleBundleCache: a failed load keeps the previously held bundle",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    REQUIRE(cache.get(1, counting_loader(calls, "one")).has_value());
    auto bad = cache.get(2, [] {
        return std::expected<Bundle, BundleLoadError>(
            std::unexpected(BundleLoadError{BundleLoadError::Source::rules, "rules down"}));
    });
    CHECK_FALSE(bad.has_value());
    CHECK(cache.held_generation() == 1);  // still valid for generation 1
    auto one = cache.get(1, counting_loader(calls, "unused"));
    REQUIRE(one.has_value());
    CHECK(calls.load() == 1);  // generation 1 still served from the cache
}

TEST_CASE("GuardianRuleBundleCache: a throwing or missing loader becomes an error",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    auto r = cache.get(1, []() -> std::expected<Bundle, BundleLoadError> {
        throw std::runtime_error("kaboom");
    });
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().source == BundleLoadError::Source::other);
    CHECK(r.error().detail.find("kaboom") != std::string::npos);
    auto r2 = cache.get(1, []() -> std::expected<Bundle, BundleLoadError> { throw 7; });
    CHECK_FALSE(r2.has_value());
    auto r3 = cache.get(1, GuardianRuleBundleCache::LoaderFn{});
    CHECK_FALSE(r3.has_value());
    // The in-flight state was cleared each time: a good load now succeeds.
    std::atomic<int> calls{0};
    CHECK(cache.get(1, counting_loader(calls, "ok")).has_value());
}

TEST_CASE("GuardianRuleBundleCache: concurrent callers for one generation share one load",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    Event entered, release;
    std::atomic<int> calls{0};
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        calls.fetch_add(1);
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("x", "")}, {"x"}));
    };

    std::vector<std::shared_ptr<const Bundle>> got(8);
    std::vector<std::thread> ts;
    ts.emplace_back([&] { got[0] = cache.get(4, slow).value(); });
    entered.wait();  // the flight is registered before the loader body runs
    for (std::size_t i = 1; i < got.size(); ++i)
        ts.emplace_back([&, i] { got[i] = cache.get(4, slow).value(); });
    release.set();
    for (auto& t : ts)
        t.join();
    CHECK(calls.load() == 1);
    CHECK(cache.loads() == 1);
    for (const auto& p : got) {
        REQUIRE(p != nullptr);
        CHECK(p.get() == got[0].get());
        CHECK(p->generation == 4);
    }
}

TEST_CASE("GuardianRuleBundleCache: a request for another generation does not wait on a running load",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    Event entered, release;
    const GuardianRuleBundleCache::LoaderFn slow = [&] {
        entered.set();
        release.wait();
        return std::expected<Bundle, BundleLoadError>(make_bundle({rule("slow", "")}, {"slow"}));
    };
    std::shared_ptr<const Bundle> slow_result;
    std::thread t([&] { slow_result = cache.get(1, slow).value(); });
    entered.wait();

    std::atomic<int> calls{0};
    auto quick = cache.get(2, counting_loader(calls, "quick"));  // returns while gen 1 is blocked
    REQUIRE(quick.has_value());
    CHECK((*quick)->generation == 2);

    release.set();
    t.join();
    REQUIRE(slow_result != nullptr);
    CHECK(slow_result->generation == 1);  // each caller got the bundle for ITS generation
    CHECK(slow_result->rules[0].rule_id == "slow");
    // Whichever finished last is held; a request for the other generation reloads.
    const auto held = cache.held_generation();
    REQUIRE(held.has_value());
    const std::uint64_t other = (*held == 1) ? 2 : 1;
    std::atomic<int> c2{0};
    auto r = cache.get(other, counting_loader(c2, "reload"));
    REQUIRE(r.has_value());
    CHECK((*r)->generation == other);
    CHECK(c2.load() == 1);
}

TEST_CASE("GuardianRuleBundleCache: a held shared_ptr survives a reload",
          "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    auto in_flight_push = cache.get(1, counting_loader(calls, "old"));
    REQUIRE(in_flight_push.has_value());
    const std::shared_ptr<const Bundle> mine = *in_flight_push;
    const auto* expr = mine->find_scope("tag:env == \"prod\"");
    REQUIRE(expr != nullptr);

    REQUIRE(cache.get(2, counting_loader(calls, "new")).has_value());  // reload replaces
    CHECK(cache.held_generation() == 2);
    // The old bundle, and the parsed expression pointer taken from it, are still valid.
    CHECK(mine->generation == 1);
    CHECK(mine->rules[0].rule_id == "old");
    CHECK(yuzu::scope::evaluate(*expr, [](std::string_view) { return std::string("prod"); }));
    CHECK(mine.use_count() >= 1);
}

TEST_CASE("GuardianRuleBundleCache: invalidate drops the held bundle", "[guardian][rule_bundle]") {
    GuardianRuleBundleCache cache;
    std::atomic<int> calls{0};
    REQUIRE(cache.get(1, counting_loader(calls, "a")).has_value());
    cache.invalidate();
    CHECK_FALSE(cache.held_generation().has_value());
    REQUIRE(cache.get(1, counting_loader(calls, "b")).has_value());
    CHECK(calls.load() == 2);
}
