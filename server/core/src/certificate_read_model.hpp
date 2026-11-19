#pragma once

/// @file certificate_read_model.hpp
/// The ONE pure model behind the fleet certificate READ surface (slice-2 PR 2a-2b, ADR-0070
/// D10/D12): query-parameter validation, filter-bound keyset cursors, the truncation OR rule,
/// the audit detail and the JSON shapers. Shared by REST, MCP and the dashboard fragments so the
/// wire shapes and the refusals cannot drift (a closed enum in OpenAPI beside "not refused" on
/// the server is the #6122 item 2 defect). No httplib, no MCP, no libpq, no store types.
///
/// FACTS ONLY (ADR-0070 D10): nothing here labels a certificate good, bad, weak or at risk, and
/// no field name is verdict-shaped (the lint in test_certificate_read_model.cpp walks every key
/// this model can emit). The model states its blind spots honestly (`not_read`).
///
/// ONE VALIDATOR FOR BOTH TWINS. REST feeds `parse_list_params` the query string; MCP converts its
/// JSON arguments with `params_from_args` (after the type checks in `strict_args_error`) and feeds
/// the SAME parser. `subject_dn_contains` is accepted only together with `is_ca=true`, on both.
///
/// PERSONAL DATA. Subjects and SANs appear only on the per-certificate read. They are never a
/// summary grouping key, a metric label or an audit detail: the audit detail records the NAMES and
/// OPERATORS of the filters applied, never their values (`audit_detail`).

#include "certificate_read_types.hpp"
#include "crypto_types.hpp"

#include <nlohmann/json.hpp>

#include <expected>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server::cert_read {

using Params = std::multimap<std::string, std::string>;

/// The permission every certificate surface requires (the denial text names it).
inline constexpr std::string_view kSecurable = "CertificateInventory";
inline constexpr std::string_view kOperation = "Read";
inline constexpr std::string_view kPermission = "CertificateInventory:Read";

/// D10's sentence, carried by every certificate REST and MCP description.
inline constexpr std::string_view kFactsOnlySentence =
    "facts only; the only built-in checks are D13's named rules and windows, each shown with "
    "its criterion";

/// The 200-note a dashboard fragment answers a caller who lacks the permission with.
inline constexpr std::string_view kDeniedMessage =
    "Fleet certificate data is not available to this account (CertificateInventory:Read is "
    "required; while RBAC enforcement is off, only an administrator holds it). Ask an "
    "administrator.";

/// D10's honesty list: what the collector does not read and what is not checked. Carried on every
/// per-certificate response; an empty result is never proof of absence.
[[nodiscard]] std::span<const std::string_view> not_read();

// ── Parameters ───────────────────────────────────────────────────────────────

inline constexpr std::string_view kArgumentsNotObject = "arguments must be a JSON object";

/// Keys: every filter, `cursor`, `limit`. REST and MCP refuse (never clamp) a value out of range,
/// an unknown key, a repeated key with differing values, invalid UTF-8 and an over-long value.
/// The error is the 400 / kInvalidParams message and names the parameter.
[[nodiscard]] std::expected<CertQuery, std::string> parse_list_params(const Params& p);
/// Keys: every filter and `not_after_edges` (a comma-separated list of 1..32 ascending RFC 3339
/// UTC instants).
[[nodiscard]] std::expected<CertSummaryQuery, std::string> parse_summary_params(const Params& p);

/// MCP's JSON-type checks (a string where a string is meant, an integer, a boolean, an array of
/// strings for the edges; no unknown property). nullopt = acceptable; otherwise the message.
[[nodiscard]] std::optional<std::string> strict_list_args_error(const nlohmann::json& args);
[[nodiscard]] std::optional<std::string> strict_summary_args_error(const nlohmann::json& args);

/// MCP arguments as the REST parameter bag (strings, integers and booleans stringified; the
/// edges array comma-joined). Call only after the strict check.
[[nodiscard]] Params params_from_args(const nlohmann::json& args);

/// RFC 3339 UTC to the second (`YYYY-MM-DDTHH:MM:SSZ`, calendar-valid, year 1..9999), or nullopt.
[[nodiscard]] std::optional<std::string> parse_instant(std::string_view s);

// ── Cursors ──────────────────────────────────────────────────────────────────

enum class CursorError { kMalformed, kFilterMismatch };
[[nodiscard]] std::string_view cursor_error_message(CursorError e);

/// A fingerprint of every filter (presence and value), so a cursor is bound to the filter set -
/// never to the scope or the limit.
[[nodiscard]] std::string filter_fingerprint(const CertReadFilter& f);
[[nodiscard]] std::string encode_cursor(const CertReadAfter& at, std::string_view fp);
[[nodiscard]] std::expected<CertReadAfter, CursorError> decode_cursor(std::string_view token,
                                                                      std::string_view fp);

// ── Truncation ───────────────────────────────────────────────────────────────

/// Finish a page the store filled: stop at a whole certificate within the byte budget (a cut sets
/// `byte_budget` and the cursor continues after the last row kept), set the cursor from the
/// store's `has_more`, and compute `truncated_parts` / `result_truncated` as the OR of EVERY cut
/// in the response (design "Truncation"): page_limit, byte_budget, locations_cap, sans_cap,
/// constrained_store, constrained_certificate. `fp` is the filter fingerprint the cursor binds.
void finish_page(CertPage& page, std::string_view fp,
                 std::size_t byte_budget = kCertPageByteBudget);

/// A summary's `result_truncated` is true exactly when it names a cut part.
void finish_summary(CertSummary& s);

// ── Audit ────────────────────────────────────────────────────────────────────

/// The audit target of both verbs: the resource, never a filter value.
inline constexpr std::string_view kAuditTarget = "fleet_certificates";

/// `[cid=<cid> ]scope=<fleet|confined> rows=<n> truncated=<bool> filters=<names=op,...|none>
/// [page=continuation]`. `filters` records the NAMES and OPERATORS of the filters applied (for
/// example `issuer_dn=eq,not_after_before=lt`), never their values: a DN filter is free text that
/// can carry personal data.
[[nodiscard]] std::string audit_detail(std::string_view cid, const CertReadFilter& f,
                                       std::size_t rows, bool truncated, bool continuation,
                                       bool confined);
/// The failure-row twin: `[cid=<cid> ]scope=... filters=... store degraded|capacity in use`.
[[nodiscard]] std::string audit_detail_degraded(std::string_view cid, const CertReadFilter& f,
                                                CryptoReadCause cause, bool confined);
/// The filter names/operators alone (`none` when no filter is present).
[[nodiscard]] std::string filter_names(const CertReadFilter& f);
/// The 503 message of a degraded read, one wording for REST and MCP.
[[nodiscard]] std::string_view degraded_message(CryptoReadCause cause);

// ── Fleet gauge ──────────────────────────────────────────────────────────────

/// The fleet gauge's OS label for a device's reported OS: windows/linux/darwin pass through, any
/// other value is `other` (a device absent from the registry snapshot is `unknown`, assigned in
/// SQL). The label set is bounded whatever an agent reports.
[[nodiscard]] std::string fleet_os_bucket(std::string_view reported_os);

// ── JSON ─────────────────────────────────────────────────────────────────────

[[nodiscard]] nlohmann::json row_json(const CertReadRow& r);
[[nodiscard]] nlohmann::json list_json(const CertPage& p);
[[nodiscard]] nlohmann::json summary_json(const CertSummary& s);

/// Serialise without ever throwing on a stray invalid-UTF-8 byte (replaced with U+FFFD).
[[nodiscard]] std::string dump_safe(const nlohmann::json& j);

/// D10's mechanical guard: the verdict-shaped tokens a key may not carry (ADR-0070 D10).
[[nodiscard]] std::span<const std::string_view> verdict_tokens();
/// Every verdict-shaped key in `j` (recursively; object keys only), as `path.key`. Empty = clean.
[[nodiscard]] std::vector<std::string> verdict_shaped_keys(const nlohmann::json& j);

} // namespace yuzu::server::cert_read
