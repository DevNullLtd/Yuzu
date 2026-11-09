#pragma once

/// @file hardware_ci_page_model.hpp
/// The ONE pure model behind the bulk device-CI read: `GET /api/v1/hardware/ci` and its MCP twin.
/// One keyset page of the stored `device_ci` rows (scalar fields only, no sections), ordered by
/// `agent_id`, with the caller's scope pushed into SQL. Parameter parsing, the cursor codec, the
/// scope decision, the audit text and the JSON shapes live here so REST and MCP cannot drift.
/// No httplib, no MCP, no libpq, no store type: the store is reached through a `Reader` closure.
///
/// It reuses the software catalogue's shared pieces rather than re-deriving them: the parameter
/// and cursor-payload helpers (`model_param_helpers.hpp`), the strict base64url codec
/// (`list_keyset.hpp`), the scope push-down ceiling and the wide-scope read bound
/// (`software_catalogue_model.hpp`). The keyset itself is different (one unique key, `agent_id`),
/// so the page walk below is this surface's own.
///
/// Scope: the caller's `authz::VisibleSet` is the SOLE filter. TOP (nullopt) reads everything; an
/// engaged-empty set reads nothing and runs no SQL; a set of at most `kScopePushdownMaxIds` ids
/// is pushed into the query (complete pages, nothing hidden); a larger one is post-filtered with
/// `authz::in_scope`. A cursor never carries the key of a device that was dropped.
///
/// Cursors are OPAQUE and not authenticated (the same posture as the software catalogue's): a
/// hand-made well-formed cursor is accepted, which is harmless because the scope is applied to
/// every page and every served page is audited. A cursor is bound to the `agent_id` filter, never
/// to the scope or the limit.

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

using Params = std::multimap<std::string, std::string>;

struct Request {
    std::string agent_id; ///< empty = every device in scope
    std::string cursor;   ///< empty = the first page
    int limit{static_cast<int>(kDefaultLimit)};
};

/// REST parsing. Keys: `limit`, `cursor`, `agent_id`. A repeated key keeps its FIRST value and an
/// unknown key is ignored (the software devices parser's rule). A `limit` that is not a plain
/// decimal integer is refused; an integer outside [1, kPageMax] is clamped. A cursor over
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

/// A continuation position: the last IN-SCOPE `agent_id` the caller was served (empty = the head)
/// plus `skip`, the rows scanned and dropped since it. `skip` is non-zero only on the wide-scope
/// path; it is a count, never a key, so the token carries no byte of an out-of-scope row.
struct Position {
    std::string after;
    std::int64_t skip{0};
};

/// Binds a cursor to the `agent_id` filter (16 lowercase hex digits).
[[nodiscard]] std::string filter_fingerprint(const Request& rq);

/// `h1:<fp16>:<b64url(length-prefixed {after, skip})>`.
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
    /// Non-empty iff more rows may exist. Under push-down it is exact (a row beyond the page was
    /// seen); on the wide-scope path the page can be empty with a non-empty cursor.
    std::string next_cursor;
    /// DISTINCT devices dropped by the post-filter within the scanned window (0 under push-down).
    std::int64_t devices_omitted{0};
    /// The request named an `agent_id` outside the caller's scope. Nothing is read then.
    bool target_denied{false};
};

/// One page: decode the cursor, push the scope, read, post-filter if the scope is wider than
/// kScopePushdownMaxIds. Error: nullopt = degraded (a read returned nullopt: a 503, never an
/// empty page); a CursorError = the cursor was refused (a 400).
[[nodiscard]] std::expected<Page, std::optional<CursorError>>
read_page(const Reader& read, const Request& rq, const authz::VisibleSet& scope);

/// The production binding of `Reader` is a one-line lambda in server.cpp over
/// `DeviceInventoryStore::list_device_ci_after`; there is no binder here so this header stays
/// store-free.

// ── JSON ─────────────────────────────────────────────────────────────────────

/// One device: `agent_id`; `hostname` (the CI record's, null when blank); `ci` (the scalar block
/// of `GET /api/v1/hardware/{id}`, byte for byte, without `sections`); `content_hash` (the stored
/// hash, null when empty, so a caller can diff client-side); `blob_version`.
[[nodiscard]] nlohmann::json row_json(const DeviceCiRecord& rec);

/// `{"devices": [...], "next_cursor": "<cursor or empty>", "devices_omitted": N}`.
[[nodiscard]] nlohmann::json page_json(const Page& page);

/// The disclosure rule for a CONFINED caller (the gate's VisibleSet was a present set), applied to
/// a `page_json` body by REST and MCP alike: `devices_omitted` is removed and `scope_basis`
/// ("authority_scoped", a status set whether or not any device was hidden) is added, because how
/// many devices lie outside a caller's scope is an existence oracle. An unconfined caller's body
/// is left as it is.
void apply_scope_disclosure(nlohmann::json& body, bool confined);

// ── Audit text ───────────────────────────────────────────────────────────────

/// The audit row's target: the requested device when an `agent_id` filter is set, else the fleet.
[[nodiscard]] std::string audit_target_type(const Request& rq);
[[nodiscard]] std::string audit_target_id(const Request& rq);

/// `hardware CI records (<surface>): rows=<n>[ omitted=<n>][ page=continuation] scope=<fleet|confined>`
/// (the requested device, when there is one, is the row's target, not repeated here). `surface` is
/// "REST" or "MCP". `confined` is whether the gate's VisibleSet was a present set; for a confined
/// caller the `omitted` count is left out, as `apply_scope_disclosure` leaves it out of the body.
[[nodiscard]] std::string audit_detail(const Page& page, const Request& rq, std::string_view surface,
                                       bool confined);

} // namespace yuzu::server::hardware_ci_page
