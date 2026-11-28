#pragma once

/// @file collation_gate_types.hpp
/// The collation gate as a store-free LEAF: the enum a text-key keyset reader or writer consults,
/// its fixed text, the value it holds before any check has concluded, and the recheck cadence
/// that the readers' retry hint must equal.
///
/// WHY THIS LIVES OUTSIDE `pg/`. The device_ci read gate (`device_ci_read_gate.hpp`) is reached
/// from the MCP registry lane's include closure (`mcp_tool_deps.hpp` ->
/// `hardware_ci_page_model.hpp`), and `scripts/ci/check-seam-closure.py` forbids every `pg/*.hpp`
/// there: a header under `pg/` is the one that hands out a pool and raw SQL. This file holds only
/// a value type and constants, no pool, no SQL and no I/O, so it is enrolled in that lane's
/// store-free types headers (`MCP_REGISTRY_TYPES_HEADERS`). Everything that depends on the check's
/// state machine (`CollationLast`, `gate_for`, the report and the check itself) stays in
/// `pg/pg_collation_check.hpp`, which includes this file. The C++ namespace stays
/// `yuzu::server::pg` so that no use of `pg::CollationGate` had to change.
///
/// What each value means, and how it is derived and published, is in `pg/pg_collation_check.hpp`
/// ("WHAT A REPEAT REPORTS", `gate_for`, `report_collation_check`).

#include <atomic>
#include <chrono>

namespace yuzu::server::pg {

/// What a text-key keyset reader or writer may rely on, as a lock-free value. Derived from
/// `CollationState.last` AFTER `next_collation_state` (the state that survives an Unreadable),
/// never from the latest verdict: a verdict-derived gate would reopen on one failed check during a
/// standing mismatch.
///   - Trusted: the last conclusive finding was Ok or NotApplicable.
///   - Mismatch: the last conclusive finding was Mismatch (stays so through Unreadable checks).
///   - Unproven: no conclusive finding yet (a boot whose checks have all been unreadable).
enum class CollationGate { Trusted, Mismatch, Unproven };

// The gate is published through `std::atomic<CollationGate>` and read on request paths: it must
// never fall back to a lock.
static_assert(std::atomic<CollationGate>::is_always_lock_free,
              "the published collation gate must be a lock-free atomic");

/// Fixed text for logs and tests: "trusted", "mismatch", "unproven".
[[nodiscard]] constexpr const char* to_string(CollationGate g) noexcept {
    switch (g) {
    case CollationGate::Trusted:
        return "trusted";
    case CollationGate::Mismatch:
        return "mismatch";
    case CollationGate::Unproven:
        return "unproven";
    }
    return "unproven";
}

/// The value a published gate holds before any check has concluded: never Trusted.
inline constexpr CollationGate kInitialCollationGate = CollationGate::Unproven;

} // namespace yuzu::server::pg

namespace yuzu::server {

/// How often the collation check is repeated while the picture is UNSETTLED: the last conclusive
/// verdict is Mismatch (after a repair the gauge must not outlast it by up to an hour), or there
/// is no conclusive verdict yet (the start-time check was unreadable), or the latest check was
/// unreadable. One cheap read a minute (the same bounded transaction as the hourly one) is the
/// price, paid only while unsettled. The rule is `PgCollationRecheck::next_wait`
/// (`pg_collation_recheck.hpp`); the readers' refusal hint (`device_ci_read_gate.hpp`) is pinned
/// to this value.
inline constexpr std::chrono::seconds kCollationUnsettledRecheckInterval{60};

} // namespace yuzu::server
