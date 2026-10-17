#pragma once

/// @file enrolment_render.hpp
/// Pure HTML renderers for the three enrolment fragments that `/groups` and the Settings page
/// both host: enrolment tokens, agents waiting for approval, and auto-approve rules.
///
/// No I/O, no logging, no store handles, no clock: the route reads the store and hands a
/// finished value in (and `now`, so "Expired" is decidable in a test). The mutation routes,
/// element ids (`#token-section`, `#pending-section`, `#auto-approve-section`) and form field
/// names are unchanged; the markup is re-classed onto `yuzu.css`. Audit rows keep their action
/// names; a few detail strings gained fields (see the routes).
///
/// Three states stay distinct: populated, genuinely empty, and "the store did not answer"
/// (a failbox, never an empty table).
///
/// Every operator- or agent-supplied string reaches the output through `html_escape`,
/// attribute values included.

#include <yuzu/server/auth.hpp>
#include <yuzu/server/auto_approve.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::enrolment {

/// Rows rendered per list. The store has no LIMIT; the cap keeps one fragment bounded.
inline constexpr std::size_t kRenderCap = 200;
/// Hostnames named in a bulk confirm.
inline constexpr std::size_t kBulkHostnamesListed = 10;

/// `YYYY-MM-DD HH:MM UTC` for a count of seconds since the Unix epoch; the fixed sentence
/// `out of range` for a value before 1970 or after 9999-12-31 23:59:59 (never a bogus date).
/// Pure std::chrono: no CRT time call, and the range is checked before any chrono value is
/// built, so every int64 is safe. Callers holding an epoch (the API-token and engine-principal
/// tables, the access-review table) use this directly.
std::string utc_stamp_epoch_secs(std::int64_t secs);

/// The same for a clock value. Cannot overflow: it floors to seconds, which divides.
std::string utc_stamp(std::chrono::system_clock::time_point tp);

/// True when an auto-approve rule value matches every agent: a `hostname_glob` made only of
/// `*` and `?` that contains a `*`, or an `ip_subnet` that is a valid IPv4 literal with prefix 0.
/// A bare `/0` (no valid address) matches nothing and does not warn; IPv6 is not matched.
bool rule_matches_everything(auth::AutoApproveRuleType type, std::string_view value);

/// Enrolment tokens panel body. `tokens == nullptr`: the store did not answer.
/// `new_raw_token`: a freshly minted secret, shown once above the list (empty: none).
std::string render_tokens(const std::vector<auth::EnrollmentToken>* tokens,
                          std::string_view new_raw_token,
                          std::chrono::system_clock::time_point now);

/// Agents-waiting panel body. `agents == nullptr`: the store did not answer. Approved rows
/// are never shown (they are enrolled).
std::string render_pending(const std::vector<auth::PendingAgent>* agents);

/// Auto-approve rules panel body (mode control, table, add-rule form).
std::string render_auto_approve(const std::vector<auth::AutoApproveRule>& rules, bool require_all);

} // namespace yuzu::server::enrolment
