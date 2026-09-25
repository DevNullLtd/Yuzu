- Internal: added the in-process `ScheduleApi` seam for the recurring-schedule read surface
  (ADR-0031 WS-A4, the seventh per-family seam) — a store-type-free abstract `schedule_api.hpp`
  covering `GET /fragments/schedules`, `GET /api/v1/schedules`, and MCP `list_schedules`, all three
  routed through the same `list_schedules()` call so their JSON shapes cannot drift, a core-only
  `make_local_schedule_api` factory, and a `LocalScheduleApi` implementation wrapping
  `ScheduleEngine::query_schedules_checked`. `InstructionSchedule`/`ScheduleQuery`/`ScheduleListResult`
  relocated out of `schedule_engine.hpp` into a pure `schedule_types.hpp`; the JSON row builder
  `schedule_row_json` split out of `workflow_model.hpp` (which previously bundled it with the
  unseamed `workflow` family's builders while claiming "pure, I/O-free" — a false claim, now
  corrected) into a genuinely pure `schedule_model.{hpp,cpp}`. The unversioned legacy
  `POST`/`DELETE`/`enable` `/api/schedules` mutators (`schedule_routes.cpp`) are a separate,
  deliberately untouched capability with no public REST v1/MCP twin — unaffected.
- **The dashboard's Schedules tab (`GET /fragments/schedules`) now surfaces a store failure as a
  distinct degraded message** ("Schedule list temporarily unavailable — retry shortly") instead of
  the previously-indistinguishable "No schedules configured". This is a side effect of routing the
  fragment through the same checked `query_schedules_checked` call `GET /api/v1/schedules` and MCP
  `list_schedules` already used — the fragment previously called the unchecked `query_schedules()`,
  which silently swallowed a store failure as an empty result.
- **The Schedules tab now shows a partial-list notice when the store's 100-row cap truncates the
  result**, matching the honesty contract `schedule_api.hpp` states for all three callers (the REST
  v1 and MCP twins already surfaced this via `result_truncated_by_cap`). Previously the fragment
  silently rendered a capped list as complete.
