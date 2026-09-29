#pragma once

/// @file instruction_definition_model.hpp
///
/// #4029 (api-parity Batch A, content/catalog half): the ONE shared pure
/// builder family for `InstructionDefinition` JSON, so `GET /api/instructions`
/// (legacy), `GET /api/v1/instructions*` (new), and MCP's `list_definitions` /
/// `get_definition` / `export_definition` cannot drift from each other by
/// construction (docs/api-twin-recipe.md §1 — the `discover_routes.hpp`
/// pattern). No `httplib.h`, no MCP-specific includes: every function here
/// takes only an already-fetched `InstructionDefinition` and returns a plain
/// `nlohmann::json` object — each surface serializes/wraps it however that
/// surface's envelope requires (`ok_json`/`list_json` for REST v1, `JObj::raw`/
/// `JArr::add_raw` for MCP, a bare `nlohmann::json::array().push_back(...)`
/// for the legacy route).
///
/// THREE reconciled shapes, per the issue's evidence of drift between the
/// pre-existing REST fragment and the pre-existing MCP tools:
///   - `instruction_definition_row_json`    — the LIST row. Was two different
///     shapes: the legacy REST fragment's 11 fields vs. MCP `list_definitions`'
///     narrower 8 (missing `instruction_set_id`/`created_at`/`updated_at`).
///     This is the REST fragment's superset field set — MCP `list_definitions`
///     now calls this too, closing that drift.
///   - `instruction_definition_detail_json` — the SINGLE-definition detail.
///     Was two different shapes: the legacy REST fragment's
///     `gather_ttl_seconds`/`response_ttl_days`/`created_by`/timestamps vs. MCP
///     `get_definition`'s `approval_mode`/`parameter_schema`/`result_schema`/
///     `yaml_source`. This is the RECONCILED SUPERSET of both — `GET
///     /api/v1/instructions/{id}` and MCP `get_definition` both call this now.
///   - `instruction_definition_export_json` — the full export document (every
///     field on the struct). `InstructionStore::export_definition_json` itself
///     delegates here (see instruction_store.cpp) so the store's own export
///     format, `GET /api/v1/instructions/{id}/export`, and MCP
///     `export_definition` are the same shape by construction too.

#include "instruction_store.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// List-row shape (11 fields) — id/name/version/type/plugin/action/
/// description/enabled/instruction_set_id/created_at/updated_at. Used by
/// `GET /api/instructions` (legacy), `GET /api/v1/instructions`, and MCP
/// `list_definitions`.
nlohmann::json instruction_definition_row_json(const InstructionDefinition& d);

/// Single-definition detail shape (18 fields) — `instruction_definition_row_json`'s
/// 11 fields plus `gather_ttl_seconds`/`response_ttl_days`/`created_by` (the
/// legacy REST fragment's extra fields) plus `approval_mode`/`parameter_schema`/
/// `result_schema`/`yaml_source` (MCP `get_definition`'s extra fields). Used by
/// `GET /api/v1/instructions/{id}` and MCP `get_definition`. NOTE: the legacy
/// (non-v1) `GET /api/instructions/{id}` route is deliberately left on its own
/// narrower 14-field shape (no `approval_mode`/`parameter_schema`/
/// `result_schema`/`yaml_source`) rather than migrated onto this superset —
/// widening an already-shipped response body is a live judgment call, not a
/// zero-risk refactor like the list row above, and is out of this issue's
/// scope.
nlohmann::json instruction_definition_detail_json(const InstructionDefinition& d);

/// Full export document (every field on `InstructionDefinition`) — the same
/// shape `InstructionStore::export_definition_json` has always produced.
/// `export_definition_json` now delegates to this pure builder (see
/// instruction_store.cpp) instead of carrying its own independent field list,
/// so the store's export format, `GET /api/v1/instructions/{id}/export`, and
/// MCP `export_definition` cannot drift from each other. Takes an
/// already-fetched struct so a caller that already holds one (MCP
/// `export_definition`, which fetches via `get_definition` to distinguish
/// 404-vs-503 itself) does not need a second store round-trip.
nlohmann::json instruction_definition_export_json(const InstructionDefinition& d);

} // namespace yuzu::server
