#pragma once

/// @file hardware_ci_page_model.hpp
/// The ONE pure model behind the bulk device-CI read: `GET /api/v1/hardware-ci` and its MCP twin.
/// One keyset page of the stored `device_ci` rows (scalar fields only, no sections), ordered by
/// the BYTE value of `agent_id` (the store reads `agent_id COLLATE "C"`, so the walk does not depend
/// on the database collation), with the caller's scope pushed into SQL. Parameter parsing, the cursor codec, the
/// scope decision, the audit text and the JSON shapes live here so REST and MCP cannot drift.
/// No httplib, no MCP, no libpq, no store type: the store is reached through a `Reader` closure.
///
/// It reuses the software catalogue's shared pieces rather than re-deriving them: the parameter
/// and cursor-payload helpers (`model_param_helpers.hpp`) and the strict base64url codec
/// (`list_keyset.hpp`). The keyset itself is different (one unique key, `agent_id`), so the page
/// walk below is this surface's own.
///
/// Scope: the caller's `authz::VisibleSet` is the SOLE filter. TOP (nullopt) reads everything, in
/// any number of pages; an engaged-empty set reads nothing and runs no SQL; a set of at most
/// `kMaxPushdownScopeIds` ids is applied in SQL as `agent_ids`, so no page is filtered after the
/// read. A walk is still NOT a snapshot: a device registered, removed or newly in scope while it
/// runs can be missed or can vanish, so a client confirms a device with `agent_id` before retiring
/// it. A larger
/// set is NOT applied in SQL and no page of rows is ever filtered after the read: without an
/// `agent_id` the read is refused (`ReadError::kScopeTooWide`, no SQL), because a post-filter over
/// a wider set would make a short page, or a cursor that skips past hidden rows, tell the caller
/// how many devices lie outside its scope. With an `agent_id` the one device is read by key (SQL
/// `agent_id = X`) and served only when `authz::in_scope` admits it, which is the C++ check that
/// stands in for the id array. A confined caller therefore never receives an out-of-scope row, id
/// or count, in the body, the cursor or the audit detail.
///
/// Cursors are OPAQUE and not authenticated (the same posture as the software catalogue's): a
/// hand-made well-formed cursor is accepted, which is harmless because the scope is applied to
/// every page and every served page is audited. A cursor carries the last served `agent_id` and
/// nothing else, and is bound to the `agent_id` filter, never to the scope or the limit.

#include "authz_model.hpp"
#include "bulk_read_slots.hpp"
#include "device_ci_read_gate.hpp"
#include "device_inventory_types.hpp"

#include <nlohmann/json.hpp>

#include <atomic>
#include <cstddef>
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
/// `read_error_message`, the MCP tool description and the user manual all spell this number.
static_assert(kMaxPushdownScopeIds == 10000,
               "update read_error_message, the MCP description and the docs");
/// The MCP default page size, smaller than the REST default: each page lands in an agentic
/// worker's context. The input schema's `default` and `request_from_args` both read this.
inline constexpr std::int64_t kMcpDefaultLimit = 20;

/// The byte budget of one page's ROWS, per surface (compile-time constants, not flags). The sum of
/// `row_wire_bytes` over the rows a page serves stays within it, except that a page ALWAYS serves its
/// first row (one row is at most about 180 KB with worst-case JSON control-byte escaping, so the
/// first row of a page cannot wedge a walk, and a row is never truncated). REST serves the rows
/// once; the MCP `tool_result` emits the payload twice (as `content[0].text`, escaped, and as
/// `structuredContent`), so its budget is smaller. The whole response body is the budget plus the
/// array separators and the envelope, and on MCP the escaping of the text copy; the documented
/// per-surface maximum is in the user manual. This bounds the RESPONSE only: the store still reads
/// `limit + 1` rows, and only `BulkReadSlots` bounds that read.
inline constexpr std::size_t kRestRowBudgetBytes = std::size_t{4} * 1024 * 1024;
inline constexpr std::size_t kMcpRowBudgetBytes = std::size_t{1} * 1024 * 1024;

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
/// byte below 0x20, are refused. Text must be strict UTF-8 without NUL (a cursor that is not
/// valid text gets the same message as every other refused cursor). An empty `cursor` means the
/// first page; an `agent_id` that is present but empty is refused (it would otherwise read the
/// whole fleet where the caller meant one device), the same refusal MCP makes. The error is the 400 message.
[[nodiscard]] std::expected<Request, std::string> parse_params(const Params& p);

/// Which refusal an MCP argument error is, where the caller's remedy differs. `kCursorRefused` is
/// a cursor refused before it is decoded (over-long, or not valid text): the same remedy as a
/// cursor that fails to decode (omit it).
enum class ArgFault { kOther, kCursorRefused };

/// The kInvalidParams message of a refused MCP request, and what kind of refusal it was.
struct ArgError {
    std::string message;
    ArgFault fault{ArgFault::kOther};
};

/// Remediation and audit detail for EVERY refused cursor on the MCP channel: an over-long one
/// (`ArgFault::kCursorRefused`) and one that fails to decode (`ReadError::kCursorMalformed` or
/// `kCursorFilterMismatch`). One spelling each, so the two refusals read the same to a caller and
/// in the audit trail. The detail carries no part of the cursor.
inline constexpr std::string_view kCursorRefusedRemediation = "omit cursor to restart from the first page";
inline constexpr std::string_view kCursorRefusedAuditDetail = "invalid arguments: cursor";

/// MCP's STRICT argument read (REST clamps, MCP refuses): `args` that is neither null nor an
/// object, a wrong JSON type, a `limit` outside [1, kPageMax], an empty or unsafe `agent_id`, an
/// over-long cursor or text that cannot be bound is refused. An absent `limit` is
/// `kMcpDefaultLimit`. Unknown names are ignored. The error carries the kInvalidParams message and, for
/// a cursor refused before decoding, `ArgFault::kCursorRefused`.
[[nodiscard]] std::expected<Request, ArgError> request_from_args(const nlohmann::json& args);

// ── Cursors ──────────────────────────────────────────────────────────────────

enum class CursorError { kMalformed, kFilterMismatch };

/// Wire message for a refused cursor (an HTTP 400 on REST): the same text for both causes, so the
/// answer does not say which of a malformed token and a filter mismatch it was.
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
    /// The byte budget (not the row count) ended the page: rows that fit the count were left for the
    /// next page, so `next_cursor` is non-empty and a page can be shorter than `limit`. Served as
    /// `page_bytes_capped: true` and `byte_capped=1` in the audit detail, only when set.
    bool byte_capped{false};
    /// The bulk-read slot (`bulk_read_slots.hpp`), still HELD when `read_page` returns a served
    /// bulk page. Empty for a point read, a refused page, a failed read and a null cap. The
    /// transport keeps it through the access-audit writes of this page and calls `release_slot()`
    /// right after them, so the cap bounds the pool connections the read AND the audit write of a
    /// served bulk page hold (#7951), not the read alone. Dropping the `Page` releases it too, on
    /// every exit path. Move-only for that reason. The slot borrows its `BulkReadSlots`: a `Page`
    /// must not outlive `ServerImpl::hardware_ci_read_slots_` and is request-local by design.
    std::optional<BulkReadSlots::Slot> hold;
    void release_slot() noexcept { hold.reset(); }
};

/// Why a page could not be produced.
///  - `kDegraded`: a store read returned nullopt (a 503 with a retry hint, never an empty page).
///  - `kCursorMalformed`, `kCursorFilterMismatch`: the cursor was refused (a 400 / -32602).
///  - `kScopeTooWide`: TERMINAL (a 400 / -32602, no retry hint). The caller's scope exceeds
///    `kMaxPushdownScopeIds` ids and the request names no `agent_id`. Decided from the scope size
///    and the request alone, before any read, and its text carries no count.
///  - `kOrderingUnverified`: the collation gate is not Trusted (`device_ci_read_gate.hpp`: the
///    database collation version changed under the stored CI keys, or the check has not yet
///    concluded). A 503 with `retry_after_ms` `device_ci_read_gate::kOrderingRetryAfterMs`, never
///    an empty page and not `kDegraded` (that one says the store is unavailable). Decided after
///    every refusal that needs no read and BEFORE the store is asked, so no read is made.
///  - `kBusy`: every bulk-read slot (`bulk_read_slots.hpp`) was taken for the whole bounded wait.
///    A 503 with `retry_after_ms` `kBusyRetryAfterMs` and a `Retry-After` header, never an empty
///    page and not `kDegraded` (the store is fine, this replica is at its read cap). Nothing was
///    read or served, so it writes NO audit row on either transport (a refusal holds no slot, so a
///    row would be an audit writer outside the cap, #7951). The
///    `yuzu_hardware_ci_read_busy_total` counter is the record of every refusal.
///  - `kCount`: NOT an error. A sentinel one past the last real enumerator, so a test can walk
///    every value and a `static_assert` can tie a table to the enumerator count; it is answered
///    like any out-of-range value. A new enumerator MUST be inserted BEFORE it: the
///    every-enumerator test and the table's `static_assert` count up to `kCount`.
enum class ReadError {
    kDegraded,
    kCursorMalformed,
    kCursorFilterMismatch,
    kScopeTooWide,
    kOrderingUnverified,
    kBusy,
    kCount
};

/// The REST `retry_after_ms` (and, rounded to seconds, `Retry-After`) and the MCP hint of `kBusy`.
/// Derivation: the 500 ms slot wait plus one typical page read. A slot can be held up to the store
/// call's own bounds, so 2 s is a typical-contention hint, not a guarantee.
inline constexpr std::int64_t kBusyRetryAfterMs = 2000;

/// Wire message for a refused request: the cursor messages above, and for `kScopeTooWide` the
/// same text on REST and MCP (it names the global-read way out and carries no count).
/// `kDegraded` has no caller-input message (it is a 503); it yields the generic unavailable
/// text.
[[nodiscard]] std::string_view read_error_message(ReadError e);

/// The A4 `remediation` hint for a `kScopeTooWide` refusal, the same text on REST and MCP: a
/// global-read credential first (it has no such limit), then a named device, then a narrower scope.
inline constexpr std::string_view kScopeTooWideRemediation =
    "use a credential with global read, pass agent_id, or ask an administrator to narrow the "
    "caller's scope";

/// The A4 `remediation` hint for a `kBusy` refusal, the same text on REST and MCP.
inline constexpr std::string_view kBusyRemediation =
    "wait retry_after_ms, then retry the same cursor with some jitter and back off on repeats "
    "(one retry usually succeeds; give up after about 5 minutes of continuous refusals); read one "
    "page at a time, never several in parallel";

/// The A4 `remediation` hint for a `kOrderingUnverified` refusal, the same text on REST and MCP.
inline constexpr std::string_view kOrderingUnverifiedRemediation =
    "wait retry_after_ms and call once more, then restart the walk from the first page (do not "
    "resume the old cursor); if it persists, ask an administrator to check the database collation "
    "state (see PostgreSQL collation version in server-admin.md)";

/// Which transport is answering: it picks the wording of the audit detail and the audit rows the
/// transport writes (`REST` / `MCP` in the text), nothing else.
enum class Surface { kRest, kMcp };

/// Everything a transport needs to answer a failed `read_page`, decided in ONE place so REST and
/// MCP cannot drift (a new `ReadError` enumerator is a `-Wswitch` warning in
/// `describe_read_error` and fails the every-enumerator test, instead of silently becoming a
/// cursor refusal in one transport).
///  - `unavailable`: a store read failed (REST 503 with `retry_after_ms`, MCP store-unreadable
///    answer). Otherwise the request is refused (REST 400, MCP -32602) and never retried.
///  - `remediation`: the A4 hint, empty = none. REST sends none for a refused cursor; MCP sends
///    `kCursorRefusedRemediation`.
///  - `domain_audit_row`: the transport writes an `inventory.devices.ci` row (`audit_outcome`,
///    `audit_detail`). A refused cursor writes none. MCP also writes its generic row
///    (`audit_outcome`, `audit_detail`) on EVERY failure it answers, whatever `audit_detail`
///    holds; REST writes only the domain row, and none when `domain_audit_row` is false.
///    `kBusy` is the one answer that is `unavailable` with `domain_audit_row` false and it writes
///    NO row on either transport (its `audit_outcome` and `audit_detail` are empty).
///  - `retry_after_header`: REST also sends `Retry-After` (whole seconds, `retry_after_ms`
///    rounded up), so the header agrees with the body hint.
///  The `string_view` members (`message`, `remediation`, `audit_outcome`) point at string
///  literals or `inline constexpr` views, so they stay valid for the life of the program; only
///  `audit_detail` owns its text.
struct ReadFailure {
    bool unavailable{false};
    std::string_view message;
    std::string_view remediation;
    std::int64_t retry_after_ms{-1}; ///< REST 503 hint; -1 = none
    bool retry_after_header{false};
    bool domain_audit_row{false};
    std::string_view audit_outcome;
    std::string audit_detail;
};

/// The answer to a failed read. One `switch` over `ReadError` with no `default`.
[[nodiscard]] ReadFailure describe_read_error(ReadError e, Surface surface);

/// The byte length of `row_json(rec)` exactly as both surfaces serve it (compact dump with
/// `error_handler_t::replace`). The ONE measure the byte budget is applied in: the sum over a page's
/// rows plus one comma between neighbours plus the two array brackets is the byte length of the
/// served `devices` array.
[[nodiscard]] std::size_t row_wire_bytes(const DeviceCiRecord& rec);

/// One page: decode the cursor, apply the scope as described in the file comment, check the
/// collation gate, take a read slot, read, then cut to the count and to `row_budget_bytes`. A `rq.limit` outside [1, kPageMax] is clamped into it (the parsers never
/// produce one). `gate` is `device_ci_read_gate`'s input and has NO default: every caller states
/// it. Null means "no gate" and the read is served (a unit test that deliberately models no gate
/// passes an explicit `nullptr`; production passes `&collation_gate_`, pinned by a lexical test).
/// The gate is checked after the cursor and scope refusals, which need no read and keep
/// their own answers, and before the one store call.
/// `slots` is the bulk-read concurrency cap (`bulk_read_slots.hpp`) and, like `gate`, has NO
/// default: every caller states it. A slot is taken after every refusal above (they take none)
/// and held across the one `read(rq)` call. On a served bulk page it is handed to the caller in
/// `Page::hold` and must stay held through the caller's access-audit writes (`release_slot()`
/// afterwards): a pool connection is then held by a served bulk page either for the read or for
/// its audit write, never more than `cap` at once, so an audit write that stalls on a locked audit
/// table cannot pile up (#7951). That bound covers the audit write of a served bulk page ONLY: a
/// point read, the failure row of a failed read and the refusal rows hold no slot. On every
/// refusal and on a failed read the slot is released before this returns. A request that names
/// an `agent_id` (a point read) takes none. When no slot frees within `kBulkReadSlotWait` the answer is
/// `ReadError::kBusy` and nothing is read. Null means "no cap" and the read is served (a unit test
/// that deliberately models no cap passes an explicit `nullptr`; production passes the one
/// `hardware_ci_read_slots_` through `Deps::ci_read_slots` / `ToolDeps::ci_read_slots`, pinned by
/// a lexical test).
/// `row_budget_bytes` is the surface's byte budget (`kRestRowBudgetBytes` / `kMcpRowBudgetBytes`) and
/// has NO default. Rows are kept while the running sum of `row_wire_bytes` stays within it; the first
/// row is always kept and a row is never truncated. When the budget (not the count) left rows over,
/// `Page::byte_capped` is set. `next_cursor` is minted from the last KEPT row whenever any row was
/// left over, by the count or by the budget, including when fewer than `limit + 1` rows were read
/// (the `agent_id > last` resume and the `h1` cursor are unchanged).
[[nodiscard]] std::expected<Page, ReadError>
read_page(const Reader& read, const Request& rq, const authz::VisibleSet& scope,
          const std::atomic<pg::CollationGate>* gate, BulkReadSlots* slots,
          std::size_t row_budget_bytes);

/// The production binding of `Reader` is a one-line lambda in server.cpp over
/// `DeviceInventoryStore::list_device_ci_after`; there is no binder here so this header stays
/// store-free.

// ── JSON ─────────────────────────────────────────────────────────────────────

/// One device: `agent_id`; `hostname` (the CI record's, null when empty or the literal
/// "unknown"; it is the last daily-sync value, not the live roster's); `ci` (the scalar block
/// of `GET /api/v1/hardware/{id}`, byte for byte, without `sections`); `content_hash` (the stored
/// hash, null when empty, so a caller can diff client-side); `blob_version`.
[[nodiscard]] nlohmann::json row_json(const DeviceCiRecord& rec);

/// `{"devices": [...], "next_cursor": "<cursor or empty>"}`, plus `"page_bytes_capped": true` only
/// when the byte budget ended the page (an absent key means it did not).
[[nodiscard]] nlohmann::json page_json(const Page& page);

/// The status for a CONFINED caller (the gate's VisibleSet was a present set), applied to a
/// `page_json` body by REST and MCP alike: `scope_basis` "authority_scoped" is added, whether or
/// not any device lies outside the scope. No count of hidden devices exists anywhere in the body
/// (no row is filtered after the read), so there is nothing to remove. An unconfined caller's body
/// is left as it is.
void apply_scope_disclosure(nlohmann::json& body, bool confined);

// ── Audit text ───────────────────────────────────────────────────────────────

/// The audit row's target: the requested device when an `agent_id` filter is set, else the fleet.
[[nodiscard]] std::string audit_target_type(const Request& rq);
[[nodiscard]] std::string audit_target_id(const Request& rq);

/// `hardware CI records (<surface>): rows=<n>[ page=continuation] scope=<fleet|authority_scoped>[ byte_capped=1]`
/// (the requested device, when there is one, is the row's target, not repeated here). `surface` is
/// "REST" or "MCP". `confined` is whether the gate's VisibleSet was a present set. The detail
/// never lists device ids and never carries a count of devices outside the caller's scope.
[[nodiscard]] std::string audit_detail(const Page& page, const Request& rq, std::string_view surface,
                                       bool confined);

/// `hardware CI records (<surface>) state=scope too wide`: the detail of the `denied` row written
/// when a read is refused with `ReadError::kScopeTooWide`. No count.
[[nodiscard]] std::string audit_detail_scope_too_wide(std::string_view surface);

/// `hardware CI records (<surface>) state=agent_id outside the caller's scope`: the detail of the
/// `denied` row written when the request named an `agent_id` outside the caller's scope
/// (`Page::target_denied`). The response itself is the same empty page a device with no record gets.
[[nodiscard]] std::string audit_detail_target_denied(std::string_view surface);

} // namespace yuzu::server::hardware_ci_page
