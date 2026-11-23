#pragma once

/// @file live_result_json.hpp
/// The ONE JSON builder for a per-device live read's `data` object, shared by the REST route
/// (`GET /api/v1/devices/{id}/live/{kind}`) and the MCP tool `get_device_live`, so the two
/// surfaces cannot drift.
///
/// Only the kinds flagged `rest_v1` in live_model.hpp's table are rendered, and today those are
/// `uptime` and `processes`. Any other kind returns `std::nullopt` instead of being rendered as
/// the processes shape (the previous TU-local function did exactly that for every
/// non-`uptime` kind).
///
/// Wire-format parsing stays in live_model.hpp; this unit only maps the parsed fields to JSON.
/// Pure: no store, httplib or HTML. Enrolled in the `device` seam-closure family.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::server::live {

struct LiveResultJson {
    /// The `data` object, serialised. `{"kind":"uptime", ...}` or
    /// `{"kind":"processes","processes":[...]}`; no envelope fields.
    std::string body;
    /// True iff `max_rows` cut the rows. Always false for `uptime` and when `max_rows` is 0.
    bool truncated = false;
    /// Process rows emitted into `body` (0 for `uptime`).
    std::size_t count = 0;
};

/// Render `output` (the device's plugin output) for `kind`.
///
/// `max_rows` bounds the process rows emitted; 0 means no bound (REST). When the parsed rows
/// exceed it, only the first `max_rows` are emitted and `truncated` is set (MCP passes 1000).
/// Strings are serialised with invalid UTF-8 replaced, so the body is always valid JSON.
///
/// Returns `std::nullopt` for a kind other than `uptime` / `processes`.
[[nodiscard]] std::optional<LiveResultJson> live_result_json(std::string_view kind,
                                                             const std::string& output,
                                                             std::size_t max_rows = 0);

} // namespace yuzu::server::live
