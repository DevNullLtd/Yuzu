#pragma once

/// @file access_audit_render.hpp
/// Pure HTML renderers for the Audit log, Authentication sample and Retention panels of
/// `/access/audit` (Phase 2 UI). No I/O, no logging, no store handles: the route reads the
/// store and hands a finished value in.
///
/// Field set. A row shows only what the REST twin `GET /api/v1/audit` returns (`id`,
/// `timestamp`, `principal`, `action`, `result`, `target_type`, `target_id`, `detail`). The
/// legacy dashboard route also returns `principal_role` and `source_ip`; those are
/// deliberately NOT rendered, so this page never reveals more than the twin to the same
/// `AuditLog:Read` holder.
///
/// States are kept distinct on purpose:
///   * a populated value,
///   * an empty page - the store answered with zero rows ("No events match"),
///   * `access::Unavailable` - the store did NOT answer. A red box, never an empty table, so
///     a degraded audit store cannot read as "no activity",
///   * `BadFilter` - the request itself was not understood (fixed sentence, nothing read).
///
/// Every stored string reaches the output through `html_escape` (attributes included) and
/// every filter value placed in a paging URL through `access::url_q`.

#include "access_render.hpp"
#include "audit_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yuzu::server::access_audit {

/// Rows per page. The route reads kPageSize + 1 rows to learn whether an Older page exists.
inline constexpr int kPageSize = 50;
/// Sample size bounds (the REST twin clamps to the same 1..1000).
inline constexpr int kSampleMin = 1;
inline constexpr int kSampleMax = 1000;
inline constexpr int kSampleDefault = 100;

enum class Range { Hour, Day, Week };

/// "1h" | "24h" | "7d" -> Range; anything else -> nullopt (the route refuses it).
[[nodiscard]] std::optional<Range> parse_range(std::string_view token);
[[nodiscard]] std::string_view range_token(Range r);
[[nodiscard]] std::int64_t range_seconds(Range r);

/// A request the page did not understand. The text is one of the constants below.
struct BadFilter {
    std::string_view reason;
};
inline constexpr std::string_view kBadRange = "The time range must be 1 hour, 24 hours or 7 days.";
inline constexpr std::string_view kBadText = "Filters cannot contain a NUL byte.";
inline constexpr std::string_view kBadOffset =
    "That page is outside the 10,000 rows this view can page through. Narrow the time range or "
    "add a filter.";
inline constexpr std::string_view kBadSample = "Sample size must be a whole number from 1 to 1000.";

/// The sentences the page template carries as `data-denied` / `data-unavailable`; a test pins
/// byte equality with the template so the two copies cannot drift.
inline constexpr std::string_view kLogDenied =
    "Reading the audit log needs the AuditLog:Read permission. While RBAC is off that is the "
    "Administrator account role.";
inline constexpr std::string_view kLogUnavailable =
    "The audit store did not answer, so the log is unknown right now. This is not no activity.";
inline constexpr std::string_view kSampleUnavailable =
    "The audit store did not answer, so no sample could be drawn.";
inline constexpr std::string_view kRetentionDenied =
    "Reading the retention setting needs the ServerConfig:Read permission. While RBAC is off that "
    "is the Administrator account role.";
inline constexpr std::string_view kRetentionUnavailable = "The retention setting could not be read.";

struct LogView {
    Range range = Range::Day;
    std::string principal; ///< exact-match filters as applied; echoed (escaped) into paging URLs
    std::string action;
    int offset = 0;                ///< already validated by the route (0..kAuditMaxOffset)
    std::vector<AuditEvent> rows;  ///< at most kPageSize
    bool has_more = false;         ///< the (kPageSize + 1)th row existed
};

/// The audit-log panel body (replaces `#audit-log`'s innerHTML).
std::string render_audit_log(const std::variant<LogView, access::Unavailable, BadFilter>& state);

struct SampleView {
    std::vector<AuditEvent> rows;
    std::size_t candidates = 0; ///< pool the sample was drawn from
    bool recency_capped = false;
    int limit = kSampleDefault;
    bool audit_failed = false; ///< the draw's own audit row could not be written
};

/// The sample panel result (replaces `#audit-sample`'s innerHTML).
std::string render_auth_sample(const std::variant<SampleView, access::Unavailable, BadFilter>& state);

/// The retention panel body. `days` is the figure the audit store enforces; zero or negative
/// means nothing is ever cleaned up and renders as "Never". The setting is process configuration, so there is no
/// unavailable state; a refusal is the gate's (data-denied note).
std::string render_retention(int days);

/// "13 Oct 09:41:12" (UTC). "-" for epoch <= 0 or a time gmtime cannot represent.
std::string format_utc_short(std::int64_t epoch_seconds);
/// "2026-10-13T09:41:12Z"; "-" under the same rule as format_utc_short.
std::string format_utc_iso(std::int64_t epoch_seconds);

} // namespace yuzu::server::access_audit
