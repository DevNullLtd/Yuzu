#pragma once

/// @file approval_model.hpp
/// Shared, pure JSON row builder for the ApprovalManager read surface (the
/// legacy `GET /api/approvals` field set) — REST v1 (`rest_api_v1.cpp`) and
/// MCP (`mcp_server.cpp`) call this SAME function so their JSON shapes
/// cannot drift from each other by construction (`docs/api-twin-recipe.md`
/// Rule 1). Mirrors `workflow_model.hpp`'s shape for the #4030 read-twin
/// programme.
///
/// No `httplib.h`, no MCP-specific include — pure, I/O-free.
///
/// #2146 A2-R4: approval-review REST v1/MCP parity.

#include "approval_manager.hpp"

#include <nlohmann/json.hpp>

namespace yuzu::server {

/// Full field set for `GET /api/approvals` (legacy) / `GET /api/v1/approvals`
/// / `GET /api/v1/approvals/{id}` / MCP `list_pending_approvals` — id,
/// definition_id, status, submitted_by, submitted_at, reviewed_by,
/// reviewed_at, review_comment, scope_expression. Deliberately does NOT
/// include consumed_at/consumed_by/schedule_id/origin/target_plugin/
/// target_action — none of the legacy route's callers have ever seen those
/// (submitted_by/reviewed_by/scope_expression are the fields that already
/// carry operator-facing meaning here); widening this shape is a separate,
/// deliberate decision this PR does not make.
nlohmann::json approval_row_json(const Approval& a);

} // namespace yuzu::server
