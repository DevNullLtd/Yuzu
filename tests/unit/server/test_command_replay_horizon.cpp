// #3678 (HA WS-0 / WS-3): the cross-component pin between the AGENT's durable dedup ring and the
// SERVER's command-redelivery horizon.
//
// The agent (`CommandDedupStore`) forgets a terminal command after `kMaxDedupRows` newer ones, and
// the WS-3 command outbox re-sends a stable command_id. A redelivery older than the ring is a
// fresh claim and RE-EXECUTES. The relationship is enforced at COMPILE time by the
// `static_assert`s in `common/include/yuzu/command_replay_horizon.hpp`; this file adds the ones
// that need BOTH sides in one translation unit -- the agent's real constant against the server's
// -- which the common header cannot see (it must not include an agent header: #2549 firewall).
//
// Honest limit: this proves the two constants are consistent, not that a real agent absorbs a
// redrive at the production ring size (see the upper-bound argument in the common header).

#include <yuzu/agent/command_dedup_store.hpp>
#include <yuzu/command_replay_horizon.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

namespace {
// Compile-time, so a violation is a BUILD failure rather than a test that has to be run.
static_assert(::yuzu::kMaxOutboxRedeliveryHorizonCommands <
                  ::yuzu::agent::CommandDedupStore::kMaxDedupRows,
              "#3678: the outbox redelivery horizon must be strictly below the agent dedup ring");
static_assert(::yuzu::agent::CommandDedupStore::kMaxDedupRows == ::yuzu::kAgentDedupRingRows,
              "#3678: the agent's ring bound must be the single-sourced shared constant");
} // namespace

TEST_CASE("command replay horizon: the outbox horizon leaves headroom under the agent ring (#3678)",
          "[command_outbox][3678]") {
    // Copied into locals first: CommandDedupStore is YUZU_EXPORT, and binding a class static to
    // a reference parameter (what REQUIRE does) ODR-uses it, which a dllexport class on the
    // Windows leg can turn into an unresolved external.
    constexpr std::int64_t ring = ::yuzu::agent::CommandDedupStore::kMaxDedupRows;
    constexpr std::int64_t horizon = ::yuzu::kMaxOutboxRedeliveryHorizonCommands;
    constexpr std::int64_t prune = static_cast<std::int64_t>(::yuzu::agent::CommandDedupStore::kPruneInterval);

    CHECK(horizon > 0);
    CHECK(horizon < ring);
    // The 2x margin covers failed/skipped dispatch records and the check-vs-claim race; the ring
    // itself may hold up to one prune interval more than `ring`, which is extra slack only and is
    // deliberately NOT counted on.
    CHECK(2 * horizon <= ring);
    CHECK(prune > 0);
}
