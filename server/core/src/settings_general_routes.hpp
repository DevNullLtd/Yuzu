#pragma once

/// @file settings_general_routes.hpp
/// The System "General and appearance" page: `GET /settings/general` plus two
/// UI-only fragments, `GET /fragments/settings/general-runtime` (the runtime
/// form) and `GET /fragments/settings/analytics-events` (recent events and
/// counts). The page also hosts two fragments that already exist
/// (`/fragments/settings/server-config`, `/fragments/settings/analytics`) and
/// writes through the existing `PUT /api/config/{key}`; no REST route and no
/// MCP tool is added here.
///
/// Pure core, thin shell. The two renderers take plain value structs, so a unit
/// test feeds fixtures and never needs a store, a logger or a socket. The route
/// registration takes closures that produce those structs (server.cpp binds
/// them to `Config`, `RuntimeConfigStore` and `AnalyticsEventStore`).
///
/// Every route here is `admin_fn_` (`AuthRoutes::require_admin`): the page
/// redirects a non-admin to `/` exactly as `/settings` does, and the fragments
/// answer the gate's own 403. Never wider than the REST twins they compose.

#include "http_route_sink.hpp"

#include <httplib.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::server::settings_general {

/// How many recent events the table shows. Fixed: the JSON route has no cap, this
/// fragment does (a page of operational events, not an export).
inline constexpr int kRecentEventsLimit = 20;

/// What the runtime form shows. `log_level` is the logger's own name for the level
/// (`warning`, `critical` and `off` are all possible); the renderer maps it.
struct RuntimeView {
    std::int64_t heartbeat_seconds{0};
    std::string log_level;
    /// False when the runtime config store is null or closed (a PUT would 503).
    bool store_available{true};
};

struct EventRow {
    std::string event_type;
    std::string source;
    std::string severity;
    std::int64_t event_time_ms{0};
};

/// Everything the events fragment needs, with the degraded cases kept distinct.
struct EventsView {
    /// `Config::analytics_enabled`; false means the store was never constructed.
    bool collection_enabled{false};
    /// The store object exists (it stays constructed when its migration failed).
    bool store_present{false};
    bool store_open{false};
    /// A ClickHouse URL or a JSONL path is configured.
    bool sink_configured{false};
    /// `nullopt` = the read failed (not "no events").
    std::optional<std::vector<EventRow>> recent;
    /// `nullopt` = the read failed.
    std::optional<std::size_t> pending;
    /// In-process counter: events this server process emitted since it started.
    std::size_t emitted_by_this_server{0};
};

/// The runtime form body. Never emits a `value` the caller did not supply.
std::string render_general_runtime(const RuntimeView& v);

/// The recent-events body: one distinct sentence per state, never an empty table
/// for a failure.
std::string render_analytics_events(const EventsView& v);

/// `YYYY-MM-DD HH:MM:SS` in UTC from epoch milliseconds, locale-independent.
/// `-` for a non-positive value.
std::string format_utc_ms(std::int64_t epoch_ms);

struct Deps {
    using AdminFn = std::function<bool(const httplib::Request&, httplib::Response&)>;
    AdminFn admin_fn;
    std::function<RuntimeView()> runtime_fn;
    std::function<EventsView()> events_fn;
};

/// Registers the page and the two fragments.
void register_settings_general_routes(HttpRouteSink& sink, Deps deps);

} // namespace yuzu::server::settings_general
