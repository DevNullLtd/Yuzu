// test_tar_module_stream.cpp — M1 of the $Module capture source
// (docs/tar-module-loads.md). Pins three things the rest of the ladder relies on:
//   1. EventRing<T> (refactored from ProcEventRing) carries ModuleEvent with the
//      SAME backpressure contract — push/drain/overflow-drop/zero-clamp;
//   2. the module action / signed-state warehouse tokens are the stable SQL
//      vocabulary the rollup SQL and dashboard filter on;
//   3. the $Module schema is registered and self-consistent — every tier
//      translates, is queryable, carries module_dir + signing, and has rollup SQL.

#include "tar_module_stream.hpp"
#include "tar_schema_registry.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

using namespace yuzu::tar;

TEST_CASE("EventRing<ModuleEvent> buffers and drains in order", "[tar][module]") {
    ModuleEventRing ring(4);
    ModuleEvent a;
    a.module_name = "a.dll";
    a.pid = 1;
    ModuleEvent b;
    b.module_name = "b.dll";
    b.pid = 2;
    CHECK(ring.push(a));
    CHECK(ring.push(b));
    auto out = ring.drain();
    REQUIRE(out.size() == 2);
    CHECK(out[0].module_name == "a.dll");
    CHECK(out[1].module_name == "b.dll");
    CHECK(ring.drain().empty()); // drain emptied the buffer
}

TEST_CASE("EventRing<ModuleEvent> drops on overflow and counts the drops", "[tar][module]") {
    ModuleEventRing ring(2);
    CHECK(ring.push(ModuleEvent{}));
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{})); // full → dropped
    CHECK(ring.dropped() == 1);
}

TEST_CASE("EventRing<ModuleEvent> drop counter accumulates across drain cycles", "[tar][module]") {
    ModuleEventRing ring(2);
    CHECK(ring.push(ModuleEvent{}));
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{})); // dropped #1
    ring.drain();                          // empties the buffer, NOT the drop counter
    CHECK(ring.push(ModuleEvent{}));
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{})); // dropped #2
    CHECK(ring.dropped() == 2);
}

TEST_CASE("EventRing<ModuleEvent> clamps a zero capacity to one", "[tar][module]") {
    ModuleEventRing ring(0);
    CHECK(ring.capacity() == 1);
    CHECK(ring.push(ModuleEvent{}));
    CHECK_FALSE(ring.push(ModuleEvent{}));
}

TEST_CASE("module action/signed tokens are the stable warehouse vocabulary", "[tar][module]") {
    CHECK(module_action_token(ModuleAction::kLoaded) == "loaded");
    CHECK(module_action_token(ModuleAction::kUnloaded) == "unloaded");
    CHECK(module_action_token(ModuleAction::kSeed) == "seed");
    CHECK(module_action_token(ModuleAction::kBlocked) == "blocked");

    CHECK(module_signed_token(ModuleSignedState::kUnknown) == "unknown");
    CHECK(module_signed_token(ModuleSignedState::kSigned) == "signed");
    CHECK(module_signed_token(ModuleSignedState::kUnsigned) == "unsigned");
    CHECK(module_signed_token(ModuleSignedState::kInvalid) == "invalid");
    CHECK(module_signed_token(ModuleSignedState::kRevoked) == "revoked");
}

TEST_CASE("$Module schema is registered and queryable across all tiers", "[tar][module][schema]") {
    for (const auto* dn : {"$Module_Live", "$Module_Hourly", "$Module_Daily", "$Module_Monthly"}) {
        INFO("dollar=" << dn);
        auto real = translate_dollar_name(dn);
        REQUIRE(real.has_value());
        CHECK(is_queryable_table(*real));
    }
}

TEST_CASE("module_live carries the M1 columns including module_dir + signing",
          "[tar][module][schema]") {
    auto cols = columns_for_table("module_live");
    auto has = [&](const std::string& c) {
        return std::find(cols.begin(), cols.end(), c) != cols.end();
    };
    CHECK(has("module_name"));
    CHECK(has("module_dir")); // the deliberate divergence from names-only
    CHECK(has("signed_state"));
    CHECK(has("signer"));
    CHECK(has("is_kernel"));
}

TEST_CASE("$Module rollup SQL is defined for every aggregate tier", "[tar][module][schema]") {
    for (const auto* tier : {"hourly", "daily", "monthly"}) {
        INFO("tier=" << tier);
        auto sql = rollup_sql("module", tier);
        REQUIRE_FALSE(sql.empty());
        CHECK(sql.find("module_" + std::string(tier)) != std::string::npos);
        CHECK(sql.find("load_count") != std::string::npos);
    }
}

TEST_CASE("$Module hourly rollup counts the 'loaded' action token", "[tar][module][schema]") {
    // Tie the rollup SQL's literal action predicate to the C++ token vocabulary,
    // so renaming module_action_token(kLoaded) can't silently desync the count.
    auto sql = rollup_sql("module", "hourly");
    REQUIRE_FALSE(sql.empty());
    CHECK(sql.find(std::string{"action = '"} +
                   std::string{module_action_token(ModuleAction::kLoaded)} + "'") != std::string::npos);
}

TEST_CASE("module capture methods are pre-stageable while kPlanned", "[tar][module][schema]") {
    // The collectors are kPlanned in M1; accepted_capture_methods still returns
    // them so an operator can pre-stage `module_capture_method` before M2/M4/M6.
    auto methods = accepted_capture_methods("module");
    REQUIRE_FALSE(methods.empty());
    auto has = [&](const std::string& m) {
        return std::find(methods.begin(), methods.end(), m) != methods.end();
    };
    CHECK(has("etw"));
    CHECK(has("auditd"));
    CHECK(has("endpoint_security"));
}

// ── redact_module_dir (the governance-BLOCKING privacy scrub, review S9) ────
// The shared post-drain sanitiser every collector applies to module_dir before
// insert. Pure + cross-platform, so it is exercised on every host (the live
// collectors are not). Backported into M1 from the M2 collector so the
// structural enforcement lands with the contract.

TEST_CASE("redact_module_dir scrubs the user-profile segment", "[tar][module][redact]") {
    CHECK(redact_module_dir(R"(C:\Users\alice\AppData\Local)") ==
          R"(C:\Users\<redacted>\AppData\Local)");
    CHECK(redact_module_dir("/home/bob/.config") == "/home/<redacted>/.config");
    CHECK(redact_module_dir("/Users/carol/Library") == "/Users/<redacted>/Library");
    CHECK(redact_module_dir(R"(\Device\HarddiskVolume3\Users\dave\app)") ==
          R"(\Device\HarddiskVolume3\Users\<redacted>\app)");
}

TEST_CASE("redact_module_dir leaves non-profile paths unchanged", "[tar][module][redact]") {
    CHECK(redact_module_dir(R"(C:\Windows\System32)") == R"(C:\Windows\System32)");
    CHECK(redact_module_dir("/usr/lib/x86_64-linux-gnu") == "/usr/lib/x86_64-linux-gnu");
    CHECK(redact_module_dir("").empty());
    // "Users"/"home" with no following segment → nothing to scrub.
    CHECK(redact_module_dir(R"(C:\Users)") == R"(C:\Users)");
    CHECK(redact_module_dir("/home") == "/home");
}

TEST_CASE("redact_module_dir is case-insensitive on the profile root", "[tar][module][redact]") {
    CHECK(redact_module_dir(R"(C:\USERS\alice\x)") == R"(C:\USERS\<redacted>\x)");
    CHECK(redact_module_dir("/HOME/bob/.config") == "/HOME/<redacted>/.config");
}

TEST_CASE("redact_module_dir scrubs the legacy 'Documents and Settings' root",
          "[tar][module][redact]") {
    CHECK(redact_module_dir(R"(C:\Documents and Settings\carol\Local Settings)") ==
          R"(C:\Documents and Settings\<redacted>\Local Settings)");
    CHECK(redact_module_dir(R"(C:\DOCUMENTS AND SETTINGS\dave\App)") ==
          R"(C:\DOCUMENTS AND SETTINGS\<redacted>\App)");
}

TEST_CASE("redact_module_dir scrubs removable-media mount points (PR #4023 review round 2, "
          "blocker #4 -- shared with the removable exec-from-removable path)",
          "[tar][module][redact][removable]") {
    CHECK(redact_module_dir("/media/alice/USB") == "/media/<redacted>/USB");
    CHECK(redact_module_dir("/run/media/bob/STICK") == "/run/media/<redacted>/STICK");
    CHECK(redact_module_dir("/Volumes/carol") == "/Volumes/<redacted>");
    CHECK(redact_module_dir("/Volumes/UNTITLED/tools") == "/Volumes/<redacted>/tools");
}

// ── EventRing::drain() exception-safety post-condition (review S2) ───────────

TEST_CASE("EventRing<ModuleEvent> retains capacity across drain", "[tar][module]") {
    // The S2 fix swaps in a freshly cap_-reserved buffer at every drain, so the
    // ring's capacity must never shrink below cap_ — otherwise the next push()
    // (in production, the kernel-serial ETW/ES callback) could reallocate, and a
    // bad_alloc across that C frame is UB. This pins the no-shrink post-condition
    // (the actual bad_alloc path can't be injected portably, but the invariant
    // it protects is observable as capacity()).
    ModuleEventRing ring(8);
    REQUIRE(ring.capacity() == 8);
    for (int round = 0; round < 3; ++round) {
        for (int i = 0; i < 5; ++i)
            CHECK(ring.push(ModuleEvent{}));
        auto out = ring.drain();
        CHECK(out.size() == 5);
        CHECK(ring.capacity() == 8); // never shrinks
    }
}

TEST_CASE("EventRing<ModuleEvent> is safe under concurrent push/drain",
          "[tar][module][concurrency]") {
    // Exercises the push/drain mutual exclusion and the drain() reserve-outside-
    // lock change under contention (the ProcEvent ring shares the same template,
    // fed by the kernel-serial ETW/ES callbacks). Conservation: every push that
    // returns true is eventually drained exactly once; every push that returns
    // false is counted as a drop. Run under TSan (nightly) this also asserts the
    // ring is data-race-free. Capacity is deliberately small so overflow drops
    // are exercised too.
    constexpr int kProducers = 4;
    constexpr int kPerProducer = 2000;
    ModuleEventRing ring(64);

    std::atomic<std::uint64_t> accepted{0};
    std::atomic<bool> producers_done{false};
    std::atomic<std::uint64_t> drained{0};

    std::vector<std::thread> producers;
    for (int p = 0; p < kProducers; ++p) {
        producers.emplace_back([&ring, &accepted] {
            for (int i = 0; i < kPerProducer; ++i) {
                if (ring.push(ModuleEvent{}))
                    accepted.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    std::thread consumer([&ring, &drained, &producers_done] {
        for (;;) {
            auto batch = ring.drain();
            drained.fetch_add(batch.size(), std::memory_order_relaxed);
            if (producers_done.load(std::memory_order_acquire) && batch.empty()) {
                // One final drain to catch anything pushed between the last drain
                // and the producers_done flag becoming visible.
                drained.fetch_add(ring.drain().size(), std::memory_order_relaxed);
                return;
            }
        }
    });

    for (auto& t : producers)
        t.join();
    producers_done.store(true, std::memory_order_release);
    consumer.join();

    const std::uint64_t total = kProducers * kPerProducer;
    CHECK(accepted.load() + ring.dropped() == total);     // every push accounted for
    CHECK(drained.load() == accepted.load());             // every accepted event drained once
    CHECK(ring.capacity() == 64);                         // capacity intact after the storm
}
