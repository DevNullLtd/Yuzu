#pragma once

/// @file rbac_generation_rules.hpp
/// The F3 stale-beyond-bound decision (#2703, fjarvis), as a pure function.
///
/// Split out of `RbacStore::maybe_refresh_generation` deliberately, following
/// the convention the other server stores use for exactly this problem
/// (`audit_retention_rules.hpp`, `network_perf_rules.hpp`, `preflight_parse.hpp`,
/// `deployment_parse.hpp`, `compliance_eval.hpp`): a pure decision function
/// lives in its own header so it can be pinned by a table test with no
/// database, no real clock, and no fixture.
///
/// This covers only the READ-SIDE decision — whether an already-gated caller
/// should count a `stale_beyond_accepted_bound` degrade. It deliberately does
/// NOT cover the STAMP-SITE invariant (that `last_successful_refresh_ms_` is
/// bumped only on a genuine completed refresh, never pre-emptively) — that
/// half needs a real clock seam or concurrency to exercise meaningfully, which
/// `now_ms()` (`std::chrono::steady_clock`, no seam) doesn't have. This
/// codebase's two sibling degrade paths (`pool_acquire_timeout`, `query_error`
/// on the same metric) have the identical gap for the same reason — deferring
/// that half here is consistent with the existing precedent, not a shortcut
/// unique to this fix.

#include <cstdint>

namespace yuzu::server::rbac_generation {

/// True when a caller that missed the stampede gate (a refresh recently
/// started, possibly still in flight) finds the cache ALREADY past the
/// accepted staleness bound as of `now_ms` — i.e. the refresh that would
/// deliver fresh data has not landed within the interval it was supposed to.
/// The caller still serves the existing cache either way (there is nothing
/// else to serve); this only decides whether to COUNT that as a degrade.
[[nodiscard]] inline bool is_stale_beyond_bound(std::int64_t now_ms,
                                                std::int64_t last_successful_refresh_ms,
                                                std::int64_t bound_ms) {
    return (now_ms - last_successful_refresh_ms) >= bound_ms;
}

} // namespace yuzu::server::rbac_generation
