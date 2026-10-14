#pragma once

/// @file integrations_sync_render.hpp
/// Pure HTML renderers for the Integrations page's webhook, offload-target and
/// directory-sync panels (System pages, SYS-5). No I/O, no clocks, no httplib:
/// the route module (`integrations_sync_routes.cpp`) does the checked reads and
/// hands these functions plain values, so every state is unit-testable.
///
/// Rules every renderer follows:
///   - every dynamic string goes through `html_escape`; ids are numeric or
///     escaped before they reach an attribute;
///   - a failed read renders as a failure box, never as an empty list;
///   - secret fields never carry a `value` attribute;
///   - destination URLs show scheme+host only; the full URL (userinfo
///     stripped) is inside a `<details>`;
///   - no `hx-on`, no inline `on*=` handler. Writes are driven by
///     `static/yuzu-integrations-sync.js` through `data-int-action` hooks.

#include "directory_sync.hpp"
#include "offload_target_store.hpp"
#include "webhook_store.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::integrations {

/// Why a panel's data could not be read. Both render as a failure box that
/// says it is not an empty list; they differ only in the wording.
enum class ReadError {
    unavailable, ///< the store is absent, closed, or had no connection in time
    failed,      ///< a query against an open store failed
};

/// Rows shown in a list and the "first N" sentinel (routes request N+1).
inline constexpr std::size_t kListShown = 100;
inline constexpr std::size_t kUsersShown = 200;
inline constexpr std::size_t kGroupsShown = 200;
inline constexpr std::size_t kDeliveriesShown = 50;
/// Bytes of `last_error` / delivery error text shown before truncation.
inline constexpr std::size_t kErrorShown = 300;

/// One event type the server actually fires into webhooks and offload targets
/// (`agent_service_impl.cpp`, `server.cpp`), with the data it carries.
struct EventClass {
    std::string_view id;
    std::string_view label;
    std::string_view data_class;
};
[[nodiscard]] const std::array<EventClass, 4>& event_catalogue() noexcept;

// ── view models ──────────────────────────────────────────────────────────────

/// Newest delivery for a list row. `unknown` = the read failed (not "none").
struct LastDelivery {
    enum class Kind { none, unknown, known } kind{Kind::none};
    int status_code{0};
    std::int64_t at{0};
    std::string error;
};

struct WebhookRow {
    Webhook webhook;
    LastDelivery last;
};
struct OffloadRow {
    OffloadTarget target;
    LastDelivery last;
};

/// Everything the directory panel needs. Each read keeps its own error so one
/// failed read degrades only the rows that depend on it.
struct DirectoryView {
    std::expected<SyncStatus, ReadError> status;
    std::expected<std::int64_t, ReadError> user_count;
    std::expected<std::vector<DirectoryGroup>, ReadError> groups;
    /// RBAC role names for the mapping selects. An error disables the mapping
    /// form (a select with no options would silently drop every mapping).
    std::expected<std::vector<std::string>, ReadError> roles;
};

// ── panels ───────────────────────────────────────────────────────────────────

[[nodiscard]] std::string
render_webhooks(const std::expected<std::vector<WebhookRow>, ReadError>& rows);

/// `nullopt` webhook id lookup result is the caller's job (404 note); this only
/// renders the delivery list for a webhook that exists.
[[nodiscard]] std::string
render_webhook_deliveries(const std::expected<std::vector<WebhookDelivery>, ReadError>& rows);

[[nodiscard]] std::string
render_offload_targets(const std::expected<std::vector<OffloadRow>, ReadError>& rows);

[[nodiscard]] std::string
render_offload_deliveries(const std::expected<std::vector<OffloadDelivery>, ReadError>& rows);

[[nodiscard]] std::string render_directory_panel(const DirectoryView& view);

[[nodiscard]] std::string
render_directory_users(const std::expected<std::vector<DirectoryUser>, ReadError>& users,
                       std::int64_t total);

/// The "withheld because the audit row could not be written" box for the
/// directory-users fragment (PII is never shown without durable evidence).
[[nodiscard]] std::string render_audit_withheld_note();

/// "Webhook/target not found" body for a deliveries fragment of a missing id.
[[nodiscard]] std::string render_not_found_note(std::string_view what);

// ── small pure helpers (exposed for tests) ───────────────────────────────────

/// "2026-10-14 05:40 UTC"; "Never" for t <= 0.
[[nodiscard]] std::string format_utc(std::int64_t epoch_seconds);

/// First `max_bytes` bytes of `s` cut on a UTF-8 boundary, with a trailing
/// ellipsis when anything was dropped.
[[nodiscard]] std::string clip_text(const std::string& s, std::size_t max_bytes);

} // namespace yuzu::server::integrations
