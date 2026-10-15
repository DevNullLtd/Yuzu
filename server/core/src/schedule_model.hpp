#pragma once

/// @file schedule_model.hpp
/// Shared, pure JSON row builder for the recurring-schedule read surface
/// (ADR-0031 WS-A4, the SEVENTH family — `ScheduleApi`, `schedule_api.hpp`).
/// Split out of `workflow_model.hpp` (which previously bundled this builder
/// with the WORKFLOW builders and `#include`d both `schedule_engine.hpp` AND
/// `workflow_engine.hpp` — the store headers — despite its own doc comment
/// claiming "pure, I/O-free"). That entanglement is exactly the anti-pattern
/// the `dex_perf` seam's own design note (PR #4582) calls out: a shared
/// model header bundling pure structs with store-coupled declarations. This
/// header includes ONLY `schedule_types.hpp` — no store type, no I/O — so the
/// abstract `schedule_api.hpp` can depend on it without transitively naming
/// `ScheduleEngine`.
///
/// `schedule_row_json` is called by the dashboard fragment
/// (`GET /fragments/schedules`), REST v1 (`GET /api/v1/schedules`), and MCP
/// (`list_schedules`) — all three route through the SAME `ScheduleApi::
/// list_schedules` seam call and the SAME builder here, so their JSON shapes
/// cannot drift from each other by construction (`docs/api-twin-recipe.md`
/// Rule 1).

#include "schedule_types.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// Row shape for `GET /fragments/schedules` (JSON fields only — the fragment
/// renders these into HTML itself) / `GET /api/v1/schedules` / MCP
/// `list_schedules`.
nlohmann::json schedule_row_json(const InstructionSchedule& s);

} // namespace yuzu::server
