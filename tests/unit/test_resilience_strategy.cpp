/**
 * test_resilience_strategy.cpp — Persist/Backoff/Bounded decision logic (design §8.5).
 *
 * The strategy takes an injected millisecond clock, so every mode is proven here
 * deterministically with NO sleeps and on EVERY platform (the guard wiring that
 * consumes it is Windows-only; the policy is not). decide() gates only the
 * remediation write/create — detection/emit is the guard's job and is never gated.
 */

#include <yuzu/agent/resilience_strategy.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <map>
#include <string>
#include <string_view>

using namespace yuzu::agent;

namespace {
ResilienceConfig cfg(ResilienceMode m) {
    ResilienceConfig c;
    c.mode = m;
    return c;
}
} // namespace

TEST_CASE("ResilienceStrategy Persist: always remediate now, no scheduled wake (hot path)",
          "[guardian][resilience][strategy][persist]") {
    ResilienceStrategy s{cfg(ResilienceMode::Persist)};
    for (std::uint64_t t : {0ull, 1ull, 2ull, 1'000'000ull}) {
        auto d = s.decide(t);
        CHECK(d.remediate);
        CHECK_FALSE(d.next_wake_ms.has_value()); // never adds latency to the sub-ms path
        CHECK_FALSE(d.gave_up);
    }
}

TEST_CASE("ResilienceStrategy Bounded: fixes up to the cap, then gives up and stays given up",
          "[guardian][resilience][strategy][bounded]") {
    ResilienceConfig c = cfg(ResilienceMode::Bounded);
    c.max_attempts = 3;
    c.quiet_reset_ms = 60'000;
    c.resume_after_ms = 0; // no auto-resume
    ResilienceStrategy s{c};

    CHECK(s.decide(0).remediate);  // cycle 1
    CHECK(s.decide(1).remediate);  // cycle 2
    CHECK(s.decide(2).remediate);  // cycle 3
    auto giveup = s.decide(3);     // cycle 4 > 3 → give up
    CHECK_FALSE(giveup.remediate);
    CHECK(giveup.gave_up);
    CHECK_FALSE(giveup.next_wake_ms.has_value()); // resume_after=0 → no scheduled wake

    auto still = s.decide(4);
    CHECK_FALSE(still.remediate);
    CHECK(still.gave_up);
}

TEST_CASE("ResilienceStrategy Bounded: a quiet gap resets the counter before give-up",
          "[guardian][resilience][strategy][bounded][quiet]") {
    ResilienceConfig c = cfg(ResilienceMode::Bounded);
    c.max_attempts = 3;
    c.quiet_reset_ms = 1'000;
    ResilienceStrategy s{c};

    CHECK(s.decide(0).remediate);   // cycle 1
    CHECK(s.decide(100).remediate); // cycle 2 (gap 100 < 1000, no reset)
    auto after_quiet = s.decide(2'000); // gap 1900 >= 1000 → reset → cycle 1 again
    CHECK(after_quiet.remediate);
    CHECK_FALSE(after_quiet.gave_up);
}

TEST_CASE("ResilienceStrategy Bounded: sustained compliance does NOT un-give-up",
          "[guardian][resilience][strategy][bounded][quiet]") {
    ResilienceConfig c = cfg(ResilienceMode::Bounded);
    c.max_attempts = 1;
    c.quiet_reset_ms = 1'000;
    c.resume_after_ms = 0; // human must re-push
    ResilienceStrategy s{c};

    CHECK(s.decide(0).remediate);        // cycle 1
    CHECK(s.decide(1).gave_up);          // cycle 2 > 1 → give up
    auto long_quiet = s.decide(50'000);  // huge gap, but resume_after=0
    CHECK(long_quiet.gave_up);           // still given up — quiet must not revive it
    CHECK_FALSE(long_quiet.remediate);
}

TEST_CASE("ResilienceStrategy Bounded: resume_after auto-retries after the cooldown",
          "[guardian][resilience][strategy][bounded][resume]") {
    ResilienceConfig c = cfg(ResilienceMode::Bounded);
    c.max_attempts = 1;
    c.resume_after_ms = 1'000;
    c.quiet_reset_ms = 60'000;
    ResilienceStrategy s{c};

    CHECK(s.decide(0).remediate);     // cycle 1
    auto giveup = s.decide(1);        // give up; schedule a resume wake
    CHECK(giveup.gave_up);
    REQUIRE(giveup.next_wake_ms.has_value());
    CHECK(*giveup.next_wake_ms == 1'000);

    auto cooldown = s.decide(500);    // still inside cooldown
    CHECK_FALSE(cooldown.remediate);
    CHECK(cooldown.gave_up);
    REQUIRE(cooldown.next_wake_ms.has_value());

    auto resumed = s.decide(1'001);   // cooldown elapsed → fresh fight
    CHECK(resumed.remediate);
    CHECK_FALSE(resumed.gave_up);
}

TEST_CASE("ResilienceStrategy Backoff: exponential delay between writes, never gives up",
          "[guardian][resilience][strategy][backoff]") {
    ResilienceConfig c = cfg(ResilienceMode::Backoff);
    c.backoff_initial_ms = 1'000;
    c.backoff_max_ms = 8'000;
    c.quiet_reset_ms = 60'000;
    ResilienceStrategy s{c};

    auto d0 = s.decide(0); // first drift → fix now, window becomes 1000
    CHECK(d0.remediate);
    CHECK_FALSE(d0.next_wake_ms.has_value());

    auto skip = s.decide(500); // inside the 1000ms window → skip, wake at the boundary
    CHECK_FALSE(skip.remediate);
    REQUIRE(skip.next_wake_ms.has_value());
    CHECK(*skip.next_wake_ms == 500);
    CHECK_FALSE(skip.gave_up); // Backoff NEVER gives up

    auto d1 = s.decide(1'000); // window elapsed → fix, window doubles to 2000
    CHECK(d1.remediate);

    auto skip2 = s.decide(1'500); // inside the 2000ms window
    CHECK_FALSE(skip2.remediate);
    REQUIRE(skip2.next_wake_ms.has_value());
    CHECK(*skip2.next_wake_ms == 1'500); // 2000 - (1500-1000)
}

TEST_CASE("ResilienceStrategy Backoff: a quiet gap resets the exponent to initial",
          "[guardian][resilience][strategy][backoff][quiet]") {
    ResilienceConfig c = cfg(ResilienceMode::Backoff);
    c.backoff_initial_ms = 1'000;
    c.backoff_max_ms = 8'000;
    c.quiet_reset_ms = 5'000;
    ResilienceStrategy s{c};

    CHECK(s.decide(0).remediate);     // window → 1000
    CHECK(s.decide(1'000).remediate); // window → 2000
    CHECK(s.decide(100'000).remediate); // quiet gap → exponent reset, fix now, window → 1000
    auto skip = s.decide(100'500);    // inside the reset 1000ms window again
    CHECK_FALSE(skip.remediate);
    REQUIRE(skip.next_wake_ms.has_value());
    CHECK(*skip.next_wake_ms == 500);
}

TEST_CASE("parse_resilience_mode: names, case-insensitive, unknown -> Persist",
          "[guardian][resilience][strategy][parse]") {
    CHECK(parse_resilience_mode("persist") == ResilienceMode::Persist);
    CHECK(parse_resilience_mode("Backoff") == ResilienceMode::Backoff);
    CHECK(parse_resilience_mode("BOUNDED") == ResilienceMode::Bounded);
    CHECK(parse_resilience_mode("") == ResilienceMode::Persist);
    CHECK(parse_resilience_mode("nonsense") == ResilienceMode::Persist);
}

TEST_CASE("parse_resilience_params: canonical keys, seconds->ms, defaults",
          "[guardian][resilience][strategy][parse][params]") {
    std::map<std::string, std::string> p;
    auto get = [&p](std::string_view k) -> std::string {
        auto it = p.find(std::string(k));
        return it != p.end() ? it->second : std::string{};
    };
    std::uint64_t debounce = 0;

    SECTION("empty params -> defaults (Persist + 1s)") {
        auto c = parse_resilience_params(get, debounce);
        CHECK(c.mode == ResilienceMode::Persist);
        CHECK(c.max_attempts == 5);
        CHECK(c.quiet_reset_ms == 60'000);
        CHECK(c.resume_after_ms == 0);
        CHECK(c.backoff_initial_ms == 1'000);
        CHECK(c.backoff_max_ms == 60'000);
        CHECK(debounce == 1'000);
    }

    SECTION("explicit values, with seconds -> ms conversions") {
        p = {{"mode", "bounded"},          {"max_attempts", "3"},
             {"quiet_reset_s", "30"},      {"resume_after_s", "120"},
             {"backoff_initial_ms", "500"}, {"backoff_max_ms", "8000"},
             {"event_debounce_ms", "250"}};
        auto c = parse_resilience_params(get, debounce);
        CHECK(c.mode == ResilienceMode::Bounded);
        CHECK(c.max_attempts == 3);
        CHECK(c.quiet_reset_ms == 30'000);   // 30s -> ms (catches a key typo or missing *1000)
        CHECK(c.resume_after_ms == 120'000); // 120s -> ms
        CHECK(c.backoff_initial_ms == 500);
        CHECK(c.backoff_max_ms == 8'000);
        CHECK(debounce == 250);
    }

    SECTION("garbage / empty values fall back to defaults") {
        p = {{"max_attempts", "abc"}, {"quiet_reset_s", ""}, {"event_debounce_ms", "x"}};
        auto c = parse_resilience_params(get, debounce);
        CHECK(c.max_attempts == 5);
        CHECK(c.quiet_reset_ms == 60'000);
        CHECK(debounce == 1'000);
    }

    SECTION("a caller-supplied default_event_debounce_ms overrides the implicit 1000ms "
            "fallback (#3388) - every existing 2-arg call site above is unaffected") {
        (void)parse_resilience_params(get, debounce, 72'000);
        CHECK(debounce == 72'000);
    }

    SECTION("a caller-supplied default is still overridden by an explicit "
            "event_debounce_ms param") {
        p = {{"event_debounce_ms", "250"}};
        (void)parse_resilience_params(get, debounce, 72'000);
        CHECK(debounce == 250); // the author's value wins over EITHER default
    }

    SECTION("garbage event_debounce_ms falls back to the caller-supplied default, not 1000") {
        p = {{"event_debounce_ms", "x"}};
        (void)parse_resilience_params(get, debounce, 72'000);
        CHECK(debounce == 72'000);
    }
}
