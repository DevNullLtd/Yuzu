#pragma once

/// @file hardware_ci_page_model.hpp
/// The ONE pure model behind the bulk device-CI read: `GET /api/v1/hardware/ci` and its MCP twin.
/// One keyset page of the stored `device_ci` rows (scalar fields only, no sections), ordered by
/// `agent_id`, with the caller's scope pushed into SQL. Parameter parsing, the cursor codec, the
/// scope decision, the audit text and the JSON shapes live here so REST and MCP cannot drift.
/// No httplib, no MCP, no libpq, no store type: the store is reached through a `Reader` closure.
///
/// It reuses the software catalogue's shared pieces rather than re-deriving them: the parameter
/// and cursor-payload helpers (`model_param_helpers.hpp`) and the strict base64url codec
/// (`list_keyset.hpp`). The keyset itself is different (one unique key, `agent_id`), so the page
/// walk below is this surface's own.
///
/// Scope: the caller's `authz::VisibleSet` is the SOLE filter and it is always applied in SQL.
/// TOP (nullopt) reads everything, in any number of pages; an engaged-empty set reads nothing and
/// runs no SQL; a set of at most `kMaxPushdownScopeIds` ids is pushed into the query as
/// `agent_ids`, so every page is exact. A larger set is NOT read: without an `agent_id` the read
/// is refused (`ReadError::kScopeTooWide`, no SQL), because a post-filter over a wider set would
/// make a short page, or a cursor that skips past hidden rows, tell the caller how many devices
/// lie outside its scope. With an `agent_id` the one device is read by key and served only when
/// `authz::in_scope` admits it. A confined caller therefore never receives an out-of-scope row,
/// id or count, in the body, the cursor or the audit detail.
///
/// Cursors are OPAQUE and not authenticated (the same posture as the software catalogue's): a
/// hand-made well-formed cursor is accepted, which is harmless because the scope is applied to
/// every page and every served page is audited. A cursor carries the last served `agent_id` and
/// nothing else, and is bound to the `agent_id` filter, never to the scope or the limit.

#include "authz_model.hpp"
#include "device_inventory_types.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::hardware_ci_page {

inline constexpr std::int64_t kDefaultLimit = 100;
inline constexpr std::int64_t kPageMax = 1000;
/// Longest cursor accepted; a longer one is refused before it is decoded.
inline constexpr std::size_t kCursorMaxBytes = 2048;
/// The most scope ids pushed into SQL as one `agent_ids` array. Above it a read without an
/// `agent_id` is refused (see the file comment).
inline constexpr std::size_t kMaxPushdownScopeIds = 10000;

using Params = std::multimap<std::string, std::string>;

struct Request {
    std::string agent_id; ///< empty = every device in scope
    std::string cursor;   ///< empty = the first page
    int limit{static_cast<int>(kDefaultLimit)};
};

/// REST parsing. Keys: `limit`, `cursor`, `agent_id`. A repeated key keeps its FIRST value and an
/// unknown key is ignored (the software devices parser's rule). A `limit` that is not a plain
/// decimal integer (an optional leading `-` and digits) is refused; any such integer outside
/// [1, kPageMax], including one too large for 64 bits, is clamped. A cursor over
/// kCursorMaxBytes, and an `agent_id` that is over `auth::kMaxAgentIdLength` bytes or carries a
/// byte below 0x20, are refused. Text must be strict UTF-8 without NUL. An empty `agent_id` or
/// `cursor` means "not given". The error is the 400 message.
[[nodiscard]] std::expected<Request, std::string> parse_params(const Params& p);

/// MCP's STRICT argument read (REST clamps, MCP refuses): a wrong JSON type, a `limit` outside
/// [1, kPageMax], an empty or unsafe `agent_id`, an over-long cursor or text that cannot be bound
/// is refused. Unknown names are ignored. The error is the kInvalidParams message.
[[nodiscard]] std::expected<Request, std::string> request_from_args(const nlohmann::json& args);

// ── Cursors ──────────────────────────────────────────────────────────────────

enum class CursorError { kMalformed, kFilterMismatch };

/// Wire message for a refused cursor (an HTTP 400 on REST).
[[nodiscard]] std::string_view cursor_error_message(CursorError e);

/// A continuation position: the last `agent_id` the caller was served (empty = the head). Every
/// served row is in scope, so the token carries no byte of an out-of-scope row.
struct Position {
    std::string after;
};

/// Binds a cursor to the `agent_id` filter (16 lowercase hex digits).
[[nodiscard]] std::string filter_fingerprint(const Request& rq);

/// `h1:<fp16>:<b64url(length-prefixed {after})>`. A payload with any other field count is refused.
[[nodiscard]] std::string encode_cursor(const Position& at, std::string_view fp);
/// Refusal order: malformed (including a spelling `encode_cursor` would not produce) -> filter
/// mismatch.
[[nodiscard]] std::expected<Position, CursorError> decode_cursor(std::string_view token,
                                                                 std::string_view fp);

// ── One page ─────────────────────────────────────────────────────────────────

using Reader =
    std::function<std::optional<std::vector<DeviceCiRecord>>(const DeviceCiKeysetQuery&)>;

struct Page {
    std::vector<DeviceCiRecord> rows;
    /// Non-empty iff more rows exist: one row beyond the page was seen, so a final page carries
    /// no cursor.
    std::string next_cursor;
    /// The request named an `agent_id` outside the caller's scope. Nothing is read then.
    bool target_denied{false};
};

/// Why a page could not be produced.
///  - `kDegraded`: a store read returned nullopt (a 503 with a retry hint, never an empty page).
///  - `kCursorMalformed`, `kCursorFilterMismatch`: the cursor was refused (a 400 / -32602).
///  - `kScopeTooWide`: TERMINAL (a 400 / -32602, no retry hint). The caller's scope exceeds
///    `kMaxPushdownScopeIds` ids and the request names no `agent_id`. Decided from the scope size
///    and the request alone, before any read, and its text carries no count.
enum class ReadError { kDegraded, kCursorMalformed, kCursorFilterMismatch, kScopeTooWide };

/// Wire message for a refused request: the cursor messages above, and for `kScopeTooWide` the
/// same text on REST and MCP. `kDegraded` has no caller-input message (it is a 503); it yields
/// the generic unavailable text.
[[nodiscard]] std::string_view read_error_message(ReadError e);

/// One page: decode the cursor, apply the scope as described in the file comment, read.
[[nodiscard]] std::expected<Page, ReadError>
read_page(const Reader& read, const Request& rq, const authz::VisibleSet& scope);

/// The production binding of `Reader` is a one-line lambda in server.cpp over
/// `DeviceInventoryStore::list_device_ci_after`; there is no binder here so this header stays
/// store-free.

// ── JSON ─────────────────────────────────────────────────────────────────────

/// One device: `agent_id`; `hostname` (the CI record's, null when empty or the literal
/// "unknown"; it is the last daily-sync value, not the live roster's); `ci` (the scalar block
/// of `GET /api/v1/hardware/{id}`, byte for byte, without `sections`); `content_hash` (the stored
/// hash, null when empty, so a caller can diff client-side); `blob_version`.
[[nodiscard]] nlohmann::json row_json(const DeviceCiRecord& rec);

/// `{"devices": [...], "next_cursor": "<cursor or empty>"}`.
[[nodiscard]] nlohmann::json page_json(const Page& page);

/// The status for a CONFINED caller (the gate's VisibleSet was a present set), applied to a
/// `page_json` body by REST and MCP alike: `scope_basis` "authority_scoped" is added, whether or
/// not any device lies outside the scope. No count of hidden devices exists anywhere in the body
/// (the read is exact), so there is nothing to remove. An unconfined caller's body is left as it
/// is.
void apply_scope_disclosure(nlohmann::json& body, bool confined);

// ── Audit text ───────────────────────────────────────────────────────────────

/// The audit row's target: the requested device when an `agent_id` filter is set, else the fleet.
[[nodiscard]] std::string audit_target_type(const Request& rq);
[[nodiscard]] std::string audit_target_id(const Request& rq);

/// `hardware CI records (<surface>): rows=<n>[ page=continuation] scope=<fleet|authority_scoped>`
/// (the requested device, when there is one, is the row's target, not repeated here). `surface` is
/// "REST" or "MCP". `confined` is whether the gate's VisibleSet was a present set. The detail
/// never lists device ids and never carries a count of devices outside the caller's scope.
[[nodiscard]] std::string audit_detail(const Page& page, const Request& rq, std::string_view surface,
                                       bool confined);

/// `hardware CI records (<surface>): state=scope too wide`: the detail of the `denied` row written
/// when a read is refused with `ReadError::kScopeTooWide`. No count.
[[nodiscard]] std::string audit_detail_scope_too_wide(std::string_view surface);

/// `hardware CI records (<surface>): state=agent_id outside the caller's scope`: the detail of the `denied` row
/// written when the request named an `agent_id` outside the caller's scope (`Page::target_denied`).
/// The response itself is the same empty page a device with no record gets.
[[nodiscard]] std::string audit_detail_target_denied(std::string_view surface);

} // namespace yuzu::server::hardware_ci_page
