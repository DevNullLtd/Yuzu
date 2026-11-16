#pragma once

/// @file device_ci_read_gate.hpp
/// The ONE mapping from the collation gate to "may a device_ci read answer?" (#7730).
///
/// WHY. While the database collation version differs from the one the text indexes were built
/// under (`pg::CollationGate::Mismatch`), or the check has not yet concluded (`Unproven`), a read
/// that finds a device by its text primary key can answer wrongly: it misses a stored device, or
/// the table holds duplicate and ghost rows (docs/security-reviews/
/// hardware-ci-bulk-read-collation-drift-2026-11-15.md). The reads are not served as if they were
/// right:
///   - the bulk read (`GET /api/v1/hardware-ci`, MCP `list_hardware_ci_records`) is REFUSED with a
///     retryable 503, through `hardware_ci_page::ReadError::kOrderingUnverified`;
///   - the per-id record (`GET /api/v1/hardware/{id}` CI block, MCP `get_hardware_ci`, the
///     dashboard) and the roster-keyed CI columns (`GET /api/v1/hardware`, `list_hardware_ci`)
///     DEGRADE through their existing states (`CiReadError::kDegraded`, `ci_degraded`).
/// Every one of those callers asks `decide` / `refuses` below; there is no second copy of the
/// mapping, so a new read of the CI table must call it too (extend, never fork).
///
/// WHAT THIS DOES NOT DO. It does not change the keyset SQL or its index (they read
/// `agent_id COLLATE "C"` and are correct under drift), and it does not gate any write (the write
/// pause is `DeviceInventoryStore::set_write_gate`). Unproven refuses a READ but does not pause a
/// write: a check that could not run cannot vouch for the data, but pausing every device's CI
/// because a facts read failed would be a self-inflicted outage.
///
/// NULL MEANS NO GATE. A null gate pointer means "no gate was wired" and every read is served.
/// That exists for unit tests that build a deps object by hand or model no gate on purpose;
/// `hardware_ci_page::read_page` has no default for it, so a caller must write the `nullptr`.
/// Production wiring in server.cpp must always pass `&collation_gate_` (a lexical test pins it):
/// a closure that silently defaulted to no gate would serve wrong answers with no signal.
///
/// Pure and header-only: one acquire load of a lock-free atomic, no I/O, no lock.

#include "pg/pg_collation_check.hpp"
#include "pg_collation_recheck.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>

namespace yuzu::server::device_ci_read_gate {

enum class Decision { kServe, kRefuse };

/// Pure. Trusted serves; Mismatch and Unproven refuse. An out-of-range value refuses.
[[nodiscard]] constexpr Decision decide(pg::CollationGate g) noexcept {
    switch (g) {
    case pg::CollationGate::Trusted:
        return Decision::kServe;
    case pg::CollationGate::Mismatch:
    case pg::CollationGate::Unproven:
        return Decision::kRefuse;
    }
    return Decision::kRefuse;
}

/// The published gate, or "no gate wired" (null serves). One acquire load.
[[nodiscard]] inline Decision decide(const std::atomic<pg::CollationGate>* gate) noexcept {
    if (gate == nullptr)
        return Decision::kServe;
    return decide(gate->load(std::memory_order_acquire));
}

/// True when a read must not answer. The spelling every caller outside the page model uses.
[[nodiscard]] inline bool refuses(const std::atomic<pg::CollationGate>* gate) noexcept {
    return decide(gate) == Decision::kRefuse;
}

/// The `retry_after_ms` of a refused bulk read, on REST and MCP alike. The refusal clears when the
/// recheck next concludes Trusted, and while the gate is not Trusted the recheck runs at its
/// unsettled interval, so a shorter hint would only draw a second refusal for the same cause.
inline constexpr std::int64_t kOrderingRetryAfterMs = 60000;
static_assert(kOrderingRetryAfterMs ==
                  std::chrono::duration_cast<std::chrono::milliseconds>(
                      kCollationUnsettledRecheckInterval)
                      .count(),
              "the refusal's retry hint must equal the recheck's unsettled interval");

} // namespace yuzu::server::device_ci_read_gate
