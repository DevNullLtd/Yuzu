#pragma once

/// @file schedule_types.hpp
/// Pure POD types for the recurring-schedule read surface (ADR-0031 WS-A4,
/// the SEVENTH family through the seam — `ScheduleApi`, `schedule_api.hpp`).
/// Relocated out of `schedule_engine.hpp` (which `#include`s this back, so
/// every existing includer keeps seeing these types transitively — an
/// ODR-safe relocation, not a duplication, mirroring `compliance_types.hpp`'s
/// split out of `policy_store.hpp` and `dex_types.hpp`'s out of
/// `guaranteed_state_store.hpp`) so the abstract `schedule_api.hpp` can
/// depend on them without ever reaching the Postgres-backed `ScheduleEngine`
/// class or its `pg::PgPool&` constructor dependency.
///
/// No I/O, no store type, std-only — safe for a future presentation-side
/// client to include directly.

#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server {

struct InstructionSchedule {
    std::string id;
    std::string name;
    std::string definition_id;
    std::string frequency_type;
    int interval_minutes{60};
    std::string time_of_day;
    int day_of_week{0};
    int day_of_month{1};
    std::string scope_expression;
    bool requires_approval{false};
    bool enabled{true};
    int64_t next_execution_at{0};
    int64_t last_executed_at{0};
    int execution_count{0};
    std::string created_by;
    int64_t created_at{0};
    // Canonical JSON object (PR1.5a, schedule_params_parsers.hpp), sorted
    // keys, scalar values only. create_schedule() defaults an empty value to
    // "{}" and re-canonicalizes whatever is supplied, so a row read back
    // from storage always carries a validated canonical blob — never the raw
    // caller-supplied text and never truly empty.
    std::string parameter_values;
};

struct ScheduleQuery {
    std::string definition_id;
    bool enabled_only{false};
};

/// Honest counterpart to the older `ScheduleEngine::query_schedules()` (kept
/// as-is for the one remaining direct caller, the legacy unversioned
/// `GET /api/schedules` route — see that method's own doc comment):
/// `std::unexpected` distinguishes a real store failure (engine not open /
/// pool exhausted / query error) from a genuinely empty table, which the
/// older method collapses into the same empty vector either way. #4030
/// review finding: REST v1 `GET /api/v1/schedules` and MCP `list_schedules`
/// were built on the older method and could not tell their caller "the store
/// failed" from "there are no schedules" — see
/// docs/user-manual/rest-api.md's schedules section. The ADR-0031 WS-A4
/// seam (`ScheduleApi::list_schedules`) now also fronts the dashboard
/// fragment (`GET /fragments/schedules`) with this same honest shape — a
/// deliberate, disclosed behaviour delta from the fragment's pre-seam
/// unchecked read (matrix doc, `schedule` family row).
///
/// `truncated` is a second, independent #4030 review finding: the query is
/// hard-capped at `kScheduleListCap` rows (schedule_engine.cpp) with no
/// caller-visible limit/cursor, so a fleet with more schedules than the cap
/// silently loses the alphabetical tail. `truncated` tells REST/MCP/fragment
/// callers when that happened so they can say so (precedent: MCP
/// `query_responses`'s `result_truncated_by_cap`) instead of presenting the
/// capped count as the true total.
struct ScheduleListResult {
    std::vector<InstructionSchedule> schedules;
    bool truncated{false};
};

} // namespace yuzu::server
