#pragma once

/// @file verify_api.hpp
/// The SECOND per-family in-process API seam for the presentation/core/engine
/// split (ADR-0031, WS-A4 #4250), copying the merged `network_api.hpp`
/// template verbatim in shape. Abstract, ZERO store-shaped dependencies —
/// only the pure `app_perf_compare.hpp` types + std headers, so this header
/// can be included by a future presentation-side client without dragging the
/// server's store/registry/pg:: layer along.
///
/// The one method == the public `/auto` VERIFY compare resource it stands in
/// front of (`GET /api/v1/dex/perf/compare` + its MCP twin
/// `compare_app_perf_versions`) so a presentation/MCP caller consumes only
/// what the public, versioned core API serves (ADR-0031 B3, INV-31-4 "no
/// private core API") — a local in-process implementation today
/// (`LocalVerifyApi`, verify_api.cpp), a core HTTP client after the WS-B2
/// cutover. Adding a method here without a corresponding public REST/MCP
/// resource would reintroduce a private core API and defeat the point of the
/// seam.
///
/// The store-backed factory (`make_local_verify_api`) lives in the core-only
/// `verify_api_local.hpp` — this header names no store type at all, not even
/// by forward declaration, so a presentation TU including it cannot reach
/// one.
///
/// ── PII policy split (READ BEFORE ADDING A CONSUMER OF `.comparison.pairs`) ──
/// `VerifyCompareResult::comparison` is the full `PairedComparison`, which
/// carries `.pairs` — the per-machine before/after deltas keyed by
/// `agent_id`. That is the SAME behavioural-PII the dashboard's `/auto`
/// VERIFY drill fragment (`GET /fragments/auto/verify/drill`) exists to gate
/// separately from the aggregate: the drill is its OWN audited action
/// (`dex.app_perf.compare.drill`), distinct from the aggregate's
/// `dex.app_perf.compare` (see `verify_routes.cpp`). This is a DELIBERATE
/// policy split, not an oversight — the dashboard drill serves `.pairs`, but
/// REST (`GET /api/v1/dex/perf/compare`) and MCP (`compare_app_perf_versions`)
/// serve the AGGREGATE fields ONLY and MUST NOT serialize `.pairs`.
/// `compare()` returns the FULL comparison because the aggregate fields alone
/// don't determine which caller needs the pairs — WHICH fields each consumer
/// serializes is the calling handler's policy, not this API's. Do not "fix"
/// this by having REST/MCP start emitting `.pairs` to match the dashboard,
/// and do not narrow the return type to drop `.pairs` either — the drill
/// still needs them from the exact same call.

#include <cstdint>
#include <optional>
#include <string>

#include "app_perf_compare.hpp"

namespace yuzu::server {

/// Ceiling for `VerifyCompareQuery::window_days` — same value as
/// `AppPerfDailyStore::kRetentionDays` (a caller cannot usefully ask for more
/// days than the B1 store retains). Named HERE, not there, so this header
/// stays store-free (see the file banner above) — a presentation-side caller
/// (or verify_routes.cpp's own request-parsing clamp) can reference this
/// constant without reaching a store header. `verify_api.cpp`'s own
/// static_assert keeps the two constants from drifting apart; `compare()`
/// ALSO re-clamps internally (defense-in-depth against a future caller that
/// forgets to), so this is not the only place the ceiling is enforced.
inline constexpr int kMaxWindowDays = 31;

/// Parameters for the ONE compare — mirrors GET /api/v1/dex/perf/compare's
/// (and the MCP `compare_app_perf_versions` tool's) query params 1:1, so a
/// REST/MCP/dashboard caller can build one of these directly from its own
/// parsed request with no reshaping. `baseline_version`/`candidate_version`
/// are passed RAW (not caller-canonicalized) — canonicalization happens
/// inside the implementation, exactly once per version, matching the stored
/// key.
struct VerifyCompareQuery {
    std::string group_id;
    std::string app;
    std::string baseline_version;
    std::string candidate_version;
    int window_days{7};
};

/// The compare resource's result: the resolved cohort's member count (so a
/// caller can report cohort_size vs paired vs no-data — `cohort_no_data`
/// derives the last from these two, same as today), whether the underlying
/// row read was truncated by the hard row cap (the comparison counts become
/// UNRELIABLE when true — every caller must surface this loudly, never
/// silently), and the full paired comparison itself.
struct VerifyCompareResult {
    std::int64_t member_count{0};
    bool truncated{false};
    PairedComparison comparison;
};

/// The in-process public verify API. The one method == the public REST/MCP
/// compare resource, so presentation/MCP consume only what the public,
/// versioned core API serves (ADR-0031 B3, INV-31-4) — a local in-process
/// client today, a core HTTP client after the WS-B2 cutover.
class VerifyApi {
public:
    virtual ~VerifyApi() = default;

    /// The cohort-paired before/after app-perf comparison behind `/auto`
    /// VERIFY — the shape `GET /api/v1/dex/perf/compare` serves. `nullopt` is
    /// the AUTHORITATIVE degrade (member resolution or the B1 row read
    /// failed, or the app-perf store has not finished initialising) — every
    /// caller (REST 503, MCP internal-error, the dashboard's "still warming
    /// up"/"retry shortly" notes) treats it as such, never as "nothing to
    /// compare" (that is `member_count == 0` or `comparison.insufficient`,
    /// both a normal PRESENT value).
    [[nodiscard]] virtual std::optional<VerifyCompareResult>
    compare(const VerifyCompareQuery& q) const = 0;
};

} // namespace yuzu::server
