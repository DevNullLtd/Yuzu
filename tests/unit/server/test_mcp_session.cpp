/**
 * test_mcp_session.cpp — McpSessionRegistry (ADR-1005 Decision 15, track 2f).
 *
 * Covers the security-critical session invariants: 128-bit CSPRNG ids, the
 * principal-bound / no-cross-principal-oracle rule (CH-8), reject-not-evict cap
 * semantics (15(j)), idle-TTL expiry via an injected clock, and DELETE reuse.
 * Session fixation (a client-supplied id is never adopted) is a wiring property
 * verified in test_mcp_server.cpp — the registry exposes no id-ingest API.
 */

#include "mcp_session.hpp"
#include "mcp_test_binding.hpp"

#include <yuzu/metrics.hpp>
#include <yuzu/server/auth.hpp>

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using yuzu::server::mcp::McpSessionRegistry;
using yuzu::server::mcp::McpSessionBinding;
using Validate = McpSessionRegistry::ValidateResult;

// The principal-only fixture (an empty credential class); see mcp_test_binding.hpp.
using yuzu::test::mcp_session::bound;

TEST_CASE("MCP session: mint yields unique 128-bit lowercase-hex ids", "[mcp][session]") {
    McpSessionRegistry reg({.per_principal_cap = 100, .global_cap = 1000});
    std::set<std::string> ids;
    for (int i = 0; i < 50; ++i) {
        auto r = reg.mint(bound("alice"));
        REQUIRE(r.ok);
        CHECK(r.session_id.size() == 32); // 16 bytes → 32 hex chars = 128-bit
        CHECK(ids.insert(r.session_id).second == true); // never a duplicate
        for (char c : r.session_id) {
            CHECK(((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')));
        }
    }
    CHECK(reg.active_count() == 50);
}

TEST_CASE("MCP session: validate is principal-bound, no cross-principal oracle (CH-8)",
          "[mcp][session]") {
    McpSessionRegistry reg;
    auto a = reg.mint(bound("alice"));
    REQUIRE(a.ok);

    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kValid);
    // alice's valid id under bob's identity ≡ a never-existed id (no oracle)
    CHECK(reg.validate_and_touch(a.session_id, bound("bob")) == Validate::kUnknown);
    CHECK(reg.validate_and_touch(std::string(32, 'a'), bound("bob")) == Validate::kUnknown);
    // bob's probe neither consumed nor leaked alice's session
    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kValid);
}

TEST_CASE("MCP session: idle TTL expires; touch slides the window", "[mcp][session]") {
    std::chrono::steady_clock::time_point clk{};
    McpSessionRegistry reg(
        {.per_principal_cap = 8, .global_cap = 64, .idle_ttl = std::chrono::seconds{30}},
        [&clk]() { return clk; });

    auto a = reg.mint(bound("alice"));
    REQUIRE(a.ok);

    clk += std::chrono::seconds{20};
    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kValid); // touch → last_seen=20
    clk += std::chrono::seconds{20};                                          // 20s < 30s idle
    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kValid);
    clk += std::chrono::seconds{31}; // now idle > 30s
    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kUnknown);
    CHECK(reg.active_count() == 0); // gc'd on the failing validate
}

TEST_CASE("MCP session: per-principal cap REJECTS, never evicts a live session (15(j))",
          "[mcp][session]") {
    McpSessionRegistry reg(
        {.per_principal_cap = 2, .global_cap = 64, .idle_ttl = std::chrono::hours{1}});
    auto a1 = reg.mint(bound("alice"));
    auto a2 = reg.mint(bound("alice"));
    REQUIRE(a1.ok);
    REQUIRE(a2.ok);

    auto a3 = reg.mint(bound("alice"));
    CHECK_FALSE(a3.ok);
    CHECK(a3.reject_reason == "per_principal_cap");
    CHECK(a3.session_id.empty());

    // The two live sessions SURVIVE — the cap did not evict to make room.
    CHECK(reg.validate_and_touch(a1.session_id, bound("alice")) == Validate::kValid);
    CHECK(reg.validate_and_touch(a2.session_id, bound("alice")) == Validate::kValid);
    // A different principal is unaffected by alice's cap.
    CHECK(reg.mint(bound("bob")).ok);
}

TEST_CASE("MCP session: global cap rejects", "[mcp][session]") {
    McpSessionRegistry reg(
        {.per_principal_cap = 10, .global_cap = 2, .idle_ttl = std::chrono::hours{1}});
    CHECK(reg.mint(bound("alice")).ok);
    CHECK(reg.mint(bound("bob")).ok);
    auto third = reg.mint(bound("carol"));
    CHECK_FALSE(third.ok);
    CHECK(third.reject_reason == "global_cap");
}

TEST_CASE("MCP session: terminate is principal-bound; reuse 404s", "[mcp][session]") {
    McpSessionRegistry reg;
    auto a = reg.mint(bound("alice"));
    REQUIRE(a.ok);

    CHECK(reg.terminate(a.session_id, bound("bob")) == Validate::kUnknown); // foreign cannot delete
    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kValid); // still alive

    CHECK(reg.terminate(a.session_id, bound("alice")) == Validate::kValid); // owner deletes
    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kUnknown); // gone
    CHECK(reg.terminate(a.session_id, bound("alice")) == Validate::kUnknown); // double-delete no-op
    CHECK(reg.active_count() == 0);
}

TEST_CASE("MCP session: concurrent access is race-free (TSan regression net)", "[mcp][session]") {
    // The registry claims thread-safety (httplib dispatches across workers). This
    // hammers mint/validate_and_touch/terminate/gc from many threads so TSan/ASan
    // catch a future method that forgets the lock (governance cpp-safety-SHOULD).
    // No socket/httplib → no #438 TSan-acceptor hazard.
    McpSessionRegistry reg({.per_principal_cap = 1000, .global_cap = 100000});
    constexpr int kThreads = 8;
    constexpr int kOpsPerThread = 400;
    // Catch2 assertion macros are NOT multithread-safe, so worker threads only
    // accumulate into atomics; every CHECK runs after join (cpp-safety SAFE-RE-S2).
    std::atomic<int> minted{0};
    std::atomic<int> own_invalid{0}; // a thread's own just-minted session read back != kValid
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&reg, &minted, &own_invalid, t] {
            const std::string principal = "p" + std::to_string(t);
            std::vector<std::string> mine;
            for (int i = 0; i < kOpsPerThread; ++i) {
                auto m = reg.mint(bound(principal));
                if (m.ok) {
                    ++minted;
                    if (reg.validate_and_touch(m.session_id, bound(principal)) != Validate::kValid) {
                        ++own_invalid; // must stay 0 — asserted after join
                    }
                    mine.push_back(m.session_id);
                }
                if (!mine.empty() && (i % 3 == 0)) {
                    (void)reg.terminate(mine.back(), bound(principal));
                    mine.pop_back();
                }
                // foreign / unknown probes must never crash or leak across threads
                (void)reg.validate_and_touch(std::string(32, 'e'), bound("intruder"));
                if (i % 7 == 0) {
                    reg.gc();
                }
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }
    CHECK(minted.load() > 0);
    CHECK(own_invalid.load() == 0); // no thread ever failed to read back its own session
    CHECK(reg.active_count() <= static_cast<std::size_t>(kThreads * kOpsPerThread));
}

namespace {
// A supervised MCP token and a weaker credential of the SAME principal.
McpSessionBinding supervised_token(std::string principal = "alice") {
    return McpSessionBinding{.principal = std::move(principal),
                             .auth_source = "mcp_token",
                             .principal_kind = "human",
                             .mcp_tier = "supervised",
                             .token_scope_service = {}};
}
McpSessionBinding readonly_token(std::string principal = "alice") {
    auto b = supervised_token(std::move(principal));
    b.mcp_tier = "readonly";
    return b;
}
} // namespace

// #4754 CH-4: the class-mismatch paths racing the owner's own calls. Every worker records
// into atomics only (Catch2 assertion macros are not thread-safe); all CHECKs run after
// join. The registry is the unit under test, so no socket and no sleep is involved: the
// default idle ttl is far longer than the run and the real clock never expires anything.
TEST_CASE("MCP session: class-mismatch calls racing the owner never end or leak its sessions "
          "(#4754)",
          "[mcp][session][4754]") {
    McpSessionRegistry reg({.per_principal_cap = 1000, .global_cap = 100000});
    constexpr int kOwnerThreads = 2;
    constexpr int kMismatchThreads = 3;
    constexpr int kMinterThreads = 2;
    constexpr int kSessions = 48;
    constexpr int kRounds = 200;
    const auto owner = supervised_token("owner");
    const auto weaker = readonly_token("owner");

    std::vector<std::string> ids;
    for (int i = 0; i < kSessions; ++i) {
        auto m = reg.mint(owner);
        REQUIRE(m.ok);
        ids.push_back(m.session_id);
    }
    // The owner terminates every third session half way through; the rest must survive.
    const auto owner_terminates = [](int idx) { return idx % 3 == 0; };
    int expected_survivors = 0;
    for (int i = 0; i < kSessions; ++i) {
        expected_survivors += owner_terminates(i) ? 0 : 1;
    }

    std::atomic<int> owner_anomalies{0};     // the owner's own call returned the wrong answer
    std::atomic<int> mismatch_leaks{0};      // a weaker-class call saw/ended an owner session
    std::atomic<int> minter_anomalies{0};    // a foreign principal's own session misbehaved
    std::atomic<int> weaker_probes{0};       // positive control: the mismatch threads ran
    std::vector<std::thread> threads;

    for (int t = 0; t < kOwnerThreads; ++t) {
        threads.emplace_back([&, t] {
            std::vector<bool> terminated(kSessions, false);
            for (int r = 0; r < kRounds; ++r) {
                for (int i = t; i < kSessions; i += kOwnerThreads) {
                    const auto idx = static_cast<std::size_t>(i);
                    if (terminated[idx]) {
                        if (reg.validate_and_touch(ids[idx], owner) != Validate::kUnknown) {
                            ++owner_anomalies;
                        }
                        continue;
                    }
                    if (reg.validate_and_touch(ids[idx], owner) != Validate::kValid) {
                        ++owner_anomalies;
                    }
                    if (reg.stream_for(ids[idx], owner) == nullptr) {
                        ++owner_anomalies;
                    }
                    if (r == kRounds / 2 && owner_terminates(i)) {
                        if (reg.terminate(ids[idx], owner) != Validate::kValid) {
                            ++owner_anomalies;
                        }
                        terminated[idx] = true;
                    }
                }
            }
        });
    }
    for (int t = 0; t < kMismatchThreads; ++t) {
        threads.emplace_back([&] {
            for (int r = 0; r < kRounds; ++r) {
                for (const auto& id : ids) {
                    // Allowed answers: a mismatch while the owner's session lives, unknown
                    // once the owner ended it. Never kValid, never a stream, never removal.
                    if (reg.validate_and_touch(id, weaker) == Validate::kValid) {
                        ++mismatch_leaks;
                    }
                    if (reg.stream_for(id, weaker) != nullptr) {
                        ++mismatch_leaks;
                    }
                    if (reg.exists(id, weaker)) {
                        ++mismatch_leaks;
                    }
                    if (reg.terminate(id, weaker) == Validate::kValid) {
                        ++mismatch_leaks;
                    }
                    ++weaker_probes;
                }
            }
        });
    }
    for (int t = 0; t < kMinterThreads; ++t) {
        threads.emplace_back([&, t] {
            const std::string principal = "minter" + std::to_string(t);
            for (int r = 0; r < kRounds; ++r) {
                auto m = reg.mint(supervised_token(principal));
                if (!m.ok) {
                    ++minter_anomalies;
                    continue;
                }
                if (reg.validate_and_touch(m.session_id, supervised_token(principal)) !=
                    Validate::kValid) {
                    ++minter_anomalies;
                }
                if (reg.terminate(m.session_id, supervised_token(principal)) != Validate::kValid) {
                    ++minter_anomalies;
                }
            }
        });
    }
    for (auto& th : threads) {
        th.join();
    }

    CHECK(weaker_probes.load() == kMismatchThreads * kRounds * kSessions);
    CHECK(owner_anomalies.load() == 0);
    CHECK(mismatch_leaks.load() == 0);
    CHECK(minter_anomalies.load() == 0);
    // A mismatch never closed an owner session: exactly the ones the owner kept are left.
    CHECK(reg.active_count() == static_cast<std::size_t>(expected_survivors));
    for (int i = 0; i < kSessions; ++i) {
        const auto idx = static_cast<std::size_t>(i);
        if (!owner_terminates(i)) {
            CHECK(reg.terminate(ids[idx], owner) == Validate::kValid);
        }
    }
    CHECK(reg.active_count() == 0);
}

TEST_CASE("MCP session: idle GC reclaims cap room on mint", "[mcp][session]") {
    std::chrono::steady_clock::time_point clk{};
    McpSessionRegistry reg(
        {.per_principal_cap = 1, .global_cap = 8, .idle_ttl = std::chrono::seconds{30}},
        [&clk]() { return clk; });

    auto a1 = reg.mint(bound("alice"));
    REQUIRE(a1.ok);
    CHECK_FALSE(reg.mint(bound("alice")).ok); // cap 1 hit while a1 is live

    clk += std::chrono::seconds{31};   // a1 idles out
    auto a2 = reg.mint(bound("alice"));        // mint's opportunistic GC frees a1's slot
    CHECK(a2.ok);
    CHECK(reg.active_count() == 1);
}

// #3042: ServerImpl::stop()'s close-signal for every live MCP session.
TEST_CASE("MCP session: shutdown closes every live session and refuses new mints",
          "[mcp][session]") {
    McpSessionRegistry reg;
    auto a = reg.mint(bound("alice"));
    auto b = reg.mint(bound("bob"));
    REQUIRE(a.ok);
    REQUIRE(b.ok);
    REQUIRE(reg.active_count() == 2);

    CHECK(reg.shutdown() == 2);
    CHECK(reg.active_count() == 0);

    // Sticky: every read/write API sees a drained, closed registry afterward.
    auto rejected = reg.mint(bound("carol"));
    CHECK_FALSE(rejected.ok);
    CHECK(rejected.reject_reason == "shutdown");
    CHECK(reg.validate_and_touch(a.session_id, bound("alice")) == Validate::kUnknown);
    CHECK(reg.stream_for(a.session_id, bound("alice")) == nullptr);
    CHECK(reg.terminate(a.session_id, bound("alice")) == Validate::kUnknown);
    CHECK_FALSE(reg.exists(a.session_id, bound("alice")));
    reg.gc(); // no-op on an already-empty map; must not crash or resurrect anything
    CHECK(reg.active_count() == 0);
}

TEST_CASE("MCP session: shutdown is idempotent — a second call closes nothing",
          "[mcp][session]") {
    McpSessionRegistry reg;
    REQUIRE(reg.mint(bound("alice")).ok);
    CHECK(reg.shutdown() == 1);
    CHECK(reg.shutdown() == 0); // already-empty, already-closing: no double-close, no crash
    CHECK(reg.shutdown() == 0);
}

TEST_CASE("MCP session: two threads calling shutdown() simultaneously — exactly one closes",
          "[mcp][session]") {
    // Not reachable via the real call site today: ServerImpl::stop() has its own
    // completion barrier serializing a second concurrent stop() before it ever
    // reaches mcp_sessions_->shutdown() (governance quality-engineer finding,
    // #3042) — but shutdown()'s own doc comment publishes idempotency as a
    // contract independent of caller count, so pin it directly against the
    // registry rather than relying on that external guarantee.
    McpSessionRegistry reg;
    for (int i = 0; i < 5; ++i) {
        REQUIRE(reg.mint(bound("p" + std::to_string(i))).ok);
    }
    std::atomic<int> total_closed{0};
    std::thread a([&] { total_closed += reg.shutdown(); });
    std::thread b([&] { total_closed += reg.shutdown(); });
    a.join();
    b.join();
    CHECK(total_closed.load() == 5); // exactly one caller saw the live set
    CHECK(reg.active_count() == 0);
}

TEST_CASE("MCP session: shutdown with no live sessions closes zero and still latches",
          "[mcp][session]") {
    McpSessionRegistry reg;
    CHECK(reg.shutdown() == 0);
    auto rejected = reg.mint(bound("alice"));
    CHECK_FALSE(rejected.ok);
    CHECK(rejected.reject_reason == "shutdown");
}

TEST_CASE("MCP session: shutdown publishes the active-sessions gauge at zero",
          "[mcp][session]") {
    yuzu::MetricsRegistry metrics;
    McpSessionRegistry reg({.per_principal_cap = 8, .global_cap = 64}, {}, &metrics);
    REQUIRE(reg.mint(bound("alice")).ok);
    REQUIRE(reg.mint(bound("bob")).ok);
    CHECK(metrics.gauge("yuzu_mcp_sessions_active").value() == 2.0);

    reg.shutdown();
    CHECK(metrics.gauge("yuzu_mcp_sessions_active").value() == 0.0);
}

TEST_CASE("MCP session: shutdown races mint/validate/terminate cleanly (TSan regression net)",
          "[mcp][session]") {
    // Same hammer shape as the concurrent-access test above, plus one thread that
    // calls shutdown() partway through. Every mint that lands AFTER shutdown() takes
    // effect must be refused; the registry must end up fully drained regardless of
    // how the hammer and the shutdown call interleave.
    McpSessionRegistry reg({.per_principal_cap = 1000, .global_cap = 100000});
    constexpr int kThreads = 8;
    constexpr int kOpsPerThread = 400;
    std::atomic<bool> shutdown_done{false};
    std::atomic<int> minted_after_shutdown{0}; // must stay 0
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&reg, &shutdown_done, &minted_after_shutdown, t] {
            const std::string principal = "p" + std::to_string(t);
            std::vector<std::string> mine;
            for (int i = 0; i < kOpsPerThread; ++i) {
                const bool done_before = shutdown_done.load(std::memory_order_acquire);
                auto m = reg.mint(bound(principal));
                if (m.ok) {
                    if (done_before) {
                        ++minted_after_shutdown; // a mint must never succeed once shutdown fired
                    }
                    mine.push_back(m.session_id);
                }
                (void)reg.validate_and_touch(std::string(32, 'e'), bound("intruder"));
                if (!mine.empty() && (i % 3 == 0)) {
                    (void)reg.terminate(mine.back(), bound(principal));
                    mine.pop_back();
                }
                if (i % 7 == 0) {
                    reg.gc();
                }
            }
        });
    }
    threads.emplace_back([&reg, &shutdown_done] {
        std::this_thread::sleep_for(std::chrono::microseconds{200});
        reg.shutdown();
        shutdown_done.store(true, std::memory_order_release);
    });
    for (auto& th : threads) {
        th.join();
    }
    CHECK(minted_after_shutdown.load() == 0);
    CHECK(reg.active_count() == 0);
    CHECK_FALSE(reg.mint(bound("late")).ok); // registry stays refused post-join
}

// ── #4754: sessions are bound to the principal AND the credential class ────────────────


TEST_CASE("MCP session: a weaker credential class of the same principal is refused and "
          "leaves the owner's session untouched",
          "[mcp][session]") {
    std::chrono::steady_clock::time_point clk{};
    McpSessionRegistry reg(
        {.per_principal_cap = 8, .global_cap = 64, .idle_ttl = std::chrono::seconds{30}},
        [&clk]() { return clk; });
    const auto owner = supervised_token();
    const auto weaker = readonly_token();
    auto a = reg.mint(owner);
    REQUIRE(a.ok);

    clk += std::chrono::seconds{20};
    // Every registry entry point refuses the weaker class...
    CHECK(reg.validate_and_touch(a.session_id, weaker) == Validate::kCredentialMismatch);
    CHECK(reg.stream_for(a.session_id, weaker) == nullptr);
    CHECK(reg.terminate(a.session_id, weaker) == Validate::kCredentialMismatch);
    CHECK_FALSE(reg.exists(a.session_id, weaker));
    // ...and none of them terminated the owner's session.
    CHECK(reg.active_count() == 1);
    CHECK(reg.exists(a.session_id, owner));

    // Exact-effect: no refused call slid last_seen. At t=40 the session is 40s idle (> 30s
    // ttl) from its mint; had any refused call at t=20 touched it, it would be 20s idle
    // and still valid.
    clk += std::chrono::seconds{20};
    CHECK_FALSE(reg.exists(a.session_id, owner));
    CHECK(reg.validate_and_touch(a.session_id, owner) == Validate::kUnknown);
}

TEST_CASE("MCP session: the same class on a second credential instance is accepted",
          "[mcp][session]") {
    McpSessionRegistry reg;
    auto a = reg.mint(supervised_token());
    REQUIRE(a.ok);

    // A rotated token / a re-login yields a distinct credential of the SAME class: the
    // bindings compare equal, so every entry point accepts it (the residual the header
    // comment states).
    const auto successor = supervised_token();
    CHECK(successor == supervised_token());
    CHECK(reg.validate_and_touch(a.session_id, successor) == Validate::kValid);
    CHECK(reg.stream_for(a.session_id, successor) != nullptr);
    CHECK(reg.exists(a.session_id, successor));
    CHECK(reg.terminate(a.session_id, successor) == Validate::kValid);
    CHECK(reg.active_count() == 0);
}

TEST_CASE("MCP session: a foreign principal is still kUnknown, never kCredentialMismatch",
          "[mcp][session]") {
    McpSessionRegistry reg;
    auto a = reg.mint(supervised_token("alice"));
    REQUIRE(a.ok);

    // Same class, different principal, and a different class for a different principal:
    // both read exactly like a never-existed id (no new existence oracle).
    CHECK(reg.validate_and_touch(a.session_id, supervised_token("bob")) == Validate::kUnknown);
    CHECK(reg.validate_and_touch(a.session_id, readonly_token("bob")) == Validate::kUnknown);
    CHECK(reg.validate_and_touch(std::string(32, 'a'), readonly_token("alice")) ==
          Validate::kUnknown);
    CHECK(reg.terminate(a.session_id, readonly_token("bob")) == Validate::kUnknown);
    CHECK(reg.stream_for(a.session_id, supervised_token("bob")) == nullptr);
    CHECK(reg.validate_and_touch(a.session_id, supervised_token("alice")) == Validate::kValid);
}

TEST_CASE("MCP session: every class field is compared, field by field", "[mcp][session]") {
    McpSessionRegistry reg;
    const auto owner = McpSessionBinding{.principal = "alice",
                                         .auth_source = "mcp_token",
                                         .principal_kind = "human",
                                         .mcp_tier = "operator",
                                         .token_scope_service = {}};
    auto a = reg.mint(owner);
    REQUIRE(a.ok);

    auto auth_source = owner;
    auth_source.auth_source = "api_token";
    auto principal_kind = owner;
    principal_kind.principal_kind = "engine";
    auto mcp_tier = owner;
    mcp_tier.mcp_tier = "supervised";
    auto scope = owner;
    scope.token_scope_service = "printers";
    for (const auto& other : {auth_source, principal_kind, mcp_tier, scope}) {
        CHECK(reg.validate_and_touch(a.session_id, other) == Validate::kCredentialMismatch);
    }

    // No joined string, so a separator inside one field cannot alias a neighbour: these
    // two bindings would collide under "a|b" + "c" versus "a" + "b|c".
    auto left = owner;
    left.auth_source = "a|b";
    left.principal_kind = "c";
    auto right = owner;
    right.auth_source = "a";
    right.principal_kind = "b|c";
    CHECK_FALSE(left == right);
    auto b = reg.mint(left);
    REQUIRE(b.ok);
    CHECK(reg.validate_and_touch(b.session_id, right) == Validate::kCredentialMismatch);
    CHECK(reg.validate_and_touch(b.session_id, left) == Validate::kValid);
}

TEST_CASE("MCP session: the per-principal cap counts by principal, not by credential class",
          "[mcp][session]") {
    McpSessionRegistry reg(
        {.per_principal_cap = 2, .global_cap = 64, .idle_ttl = std::chrono::hours{1}});
    REQUIRE(reg.mint(supervised_token()).ok);
    REQUIRE(reg.mint(readonly_token()).ok);
    // A third class of the same principal does not get a fresh allowance.
    auto third = reg.mint(McpSessionBinding{.principal = "alice", .auth_source = "local"});
    CHECK_FALSE(third.ok);
    CHECK(third.reject_reason == "per_principal_cap");
}

// #4754 CH-2 + CH-3: the per-principal cap is per principal, not per class, so a weaker
// class that fills it locks the owner's stronger class out until the weaker sessions idle
// out. This is characterization of ACCEPTED behaviour (a live session is never evicted to
// make room, Decision 15(j)); it pins the shape so a change to it is deliberate.
TEST_CASE("MCP session: one class holding the per-principal cap blocks the owner's other class "
          "until it idles out (#4754 characterization)",
          "[mcp][session][4754]") {
    const auto t0 = std::chrono::steady_clock::now();
    std::chrono::seconds elapsed{0};
    const auto make_registry = [&] {
        return McpSessionRegistry(
            {.per_principal_cap = 8, .global_cap = 64, .idle_ttl = std::chrono::seconds{30}},
            [&] { return t0 + elapsed; });
    };
    auto reg = make_registry();
    const auto weak = readonly_token();      // class A: fills the cap
    const auto strong = supervised_token();  // class B: the same user's stronger credential

    std::vector<std::string> weak_ids;
    for (int i = 0; i < 8; ++i) {
        auto m = reg.mint(weak);
        REQUIRE(m.ok);
        weak_ids.push_back(m.session_id);
    }
    // Keep every class A session alive: touch them at t=20 so none is near its ttl at t=40.
    elapsed = std::chrono::seconds{20};
    for (const auto& id : weak_ids) {
        REQUIRE(reg.validate_and_touch(id, weak) == Validate::kValid);
    }
    elapsed = std::chrono::seconds{40};

    // The owner's class B mint is refused by the per-principal cap, with the fixed reason.
    auto blocked = reg.mint(strong);
    CHECK_FALSE(blocked.ok);
    CHECK(blocked.reject_reason == "per_principal_cap");
    CHECK(blocked.session_id.empty());
    CHECK(reg.active_count() == 8);

    // Class B cannot reap class A: terminate reports the mismatch and removes nothing.
    CHECK(reg.terminate(weak_ids.front(), strong) == Validate::kCredentialMismatch);
    CHECK(reg.active_count() == 8);

    // A foreign principal is unaffected by alice's cap.
    CHECK(reg.mint(supervised_token("bob")).ok);

    // Switching back to class A resumes every old session (and slides last_seen to t=40).
    for (const auto& id : weak_ids) {
        CHECK(reg.validate_and_touch(id, weak) == Validate::kValid);
    }
    CHECK_FALSE(reg.mint(strong).ok);

    // Class A untouched past the idle ttl: its sessions expire and class B mints.
    elapsed = std::chrono::seconds{40 + 31};
    auto reclaimed = reg.mint(strong);
    CHECK(reclaimed.ok);
    for (const auto& id : weak_ids) {
        CHECK(reg.validate_and_touch(id, weak) == Validate::kUnknown);
    }

    // A restart is a fresh registry: the old ids are unknown under either class, and both
    // classes mint again.
    auto restarted = make_registry();
    CHECK(restarted.validate_and_touch(weak_ids.front(), weak) == Validate::kUnknown);
    CHECK(restarted.validate_and_touch(reclaimed.session_id, strong) == Validate::kUnknown);
    CHECK(restarted.mint(weak).ok);
    CHECK(restarted.mint(strong).ok);
}

// #4754 CH-8: DOCUMENTS the accepted residual, and is expected to FLIP when #4309 lands.
// JIT admin elevation is per-request state, not part of the credential class, so an
// elevated and a non-elevated session of one user bind to the SAME class today. #4309
// refuses tierless (cookie) sessions at /mcp/v1/, the only sessions that can be elevated;
// once it lands this equality no longer describes a reachable state and this test should
// be rewritten or removed with it.
TEST_CASE("MCP session: an elevated and a non-elevated session of one user bind equal "
          "(documents the accepted #4754 residual; flips with #4309)",
          "[mcp][session][4754]") {
    yuzu::server::auth::Session plain;
    plain.username = "alice";
    plain.auth_source = "local";
    plain.principal_kind = "human";
    yuzu::server::auth::Session elevated = plain;
    elevated.elevated_until = std::chrono::system_clock::now() + std::chrono::minutes{10};
    elevated.steady_elevated_until = std::chrono::steady_clock::now() + std::chrono::minutes{10};
    REQUIRE(elevated.elevated_until != plain.elevated_until); // the sessions differ only by it

    CHECK(yuzu::server::mcp::binding_for(plain) == yuzu::server::mcp::binding_for(elevated));

    // Consequence: a registry session minted by one is served to the other.
    McpSessionRegistry reg;
    auto m = reg.mint(yuzu::server::mcp::binding_for(elevated));
    REQUIRE(m.ok);
    CHECK(reg.validate_and_touch(m.session_id, yuzu::server::mcp::binding_for(plain)) ==
          Validate::kValid);
}
