#pragma once

/// @file schedule_api.hpp
/// The SEVENTH per-family in-process API seam for the presentation/core/
/// engine split (ADR-0031, WS-A4), covering the recurring-schedule READ
/// surface — the Postgres-backed `ScheduleEngine`'s `GET /api/v1/schedules`
/// resource (and its dashboard-fragment/MCP twins). Abstract, ZERO
/// store-shaped dependencies — it includes only the pure `schedule_types.hpp`
/// + std headers, so this header can be included by a future
/// presentation-side client without dragging the server's `ScheduleEngine`
/// (a Postgres-backed store, `schedule_engine.hpp`) along.
///
/// The one method == the public `GET /api/v1/schedules` resource it stands in
/// front of (plus its dashboard fragment `GET /fragments/schedules` and MCP
/// twin `list_schedules`), so a presentation/MCP caller consumes only what
/// the public, versioned core API serves (ADR-0031 B3, INV-31-4 "no private
/// core API") — a local in-process implementation today (`LocalScheduleApi`,
/// `schedule_api.cpp`), a core HTTP client after the WS-B2 cutover. Adding a
/// method here without a corresponding public REST/MCP resource would
/// reintroduce a private core API and defeat the point of the seam.
///
/// The store-backed factory (`make_local_schedule_api`) lives in the
/// core-only `schedule_api_local.hpp` — this header names no store type at
/// all, not even by forward declaration, so a presentation TU including it
/// cannot reach one.
///
/// Deliberately NOT in this seam: the unversioned legacy `POST`/`DELETE`/
/// `POST .../enable /api/schedules` routes (`schedule_routes.cpp`) — a
/// SEPARATE, deliberately untouched capability with no public REST v1/MCP
/// twin (confirmed by `GET /api/v1/schedules`'s own OpenAPI description).
/// Unlike the `compliance` family's WS-A3 mutator gap (#4334), there is
/// nothing to carve out here: those mutators were never in the same
/// enforced TU as this seam's reads to begin with.

#include "schedule_types.hpp"

#include <expected>
#include <string>

namespace yuzu::server {

/// The in-process public schedule-read API. The one method == the public
/// REST/MCP/fragment list resource, so presentation/MCP consume only what
/// the public, versioned core API serves (ADR-0031 B3, INV-31-4) — a local
/// in-process client today, a core HTTP client after the WS-B2 cutover.
class ScheduleApi {
public:
    virtual ~ScheduleApi() = default;

    /// The schedule list behind `GET /fragments/schedules` /
    /// `GET /api/v1/schedules` / MCP `list_schedules`. `std::unexpected`
    /// distinguishes a real store failure from a genuinely empty table
    /// (every caller must surface this as a degrade, never as "no
    /// schedules") — the error string is INTERNAL (a store/pool diagnostic,
    /// not sanitized for display); a caller rendering it to an operator or
    /// returning it over REST/MCP MUST run it through
    /// `genericize_db_error(...)` first, exactly as the REST v1 and MCP
    /// callers already do, and MUST NOT echo it into dashboard HTML
    /// unsanitized. `ScheduleListResult::truncated` is set when the
    /// underlying store's hard row cap dropped rows — every caller (REST,
    /// MCP, and the fragment) must surface this, never present the capped
    /// count as the fleet's true total.
    [[nodiscard]] virtual std::expected<ScheduleListResult, std::string>
    list_schedules(const ScheduleQuery& q) const = 0;
};

} // namespace yuzu::server
