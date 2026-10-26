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
/// / `GET /api/v1/approvals/{id}` / MCP `list_pending_approvals` - id,
/// definition_id, status, submitted_by, submitted_at, reviewed_by,
/// reviewed_at, review_comment, scope_expression. Deliberately does NOT
/// include consumed_at/consumed_by/schedule_id/origin/target_plugin/
/// target_action - none of the callers have ever seen those.
///
/// A BOUND ticket (#6062, ADR-1005: the dashboard's frozen-request display needs an
/// API twin) additionally carries, under the SAME gate as the row itself (a bare
/// Approval:Read on every surface; this builder widens WHAT a reader sees of a row, never
/// WHO may read it):
///   request                    the frozen request as a JSON object; null when there is no
///                              readable one (see request_unreadable); the stored document
///                              parsed, not the stored bytes
///   request_digest             lowercase hex SHA-256 of the exact stored bytes
///   excluded_roots             array of human roots barred from approving
///   request_unreadable         true only when a request is stored but cannot be read; a
///                              row holding a digest and NO request has `request: null`
///                              without it
///   excluded_roots_unreadable  true only when the stored roots list could not be read
/// An UNBOUND row (all three columns empty - every MCP, interactive-instruction and
/// scheduled-fire ticket) emits none of them and is byte-identical to the shape above.
nlohmann::json approval_row_json(const Approval& a);

} // namespace yuzu::server
