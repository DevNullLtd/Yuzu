#pragma once

/// @file device_data_render.hpp
/// PURE renderers (no I/O, no httplib) for the per-device data panels of the Hardware
/// record: custom properties and property schemas (this file), with the application
/// usage, detected licence and readout panels added beside them. Every value that came
/// from an agent or an operator goes through `html_escape`; every control is a
/// `data-act` attribute handled by one delegated listener in `static/yuzu-device-data.js`
/// (no inline handler, no `hx-on`).
///
/// A degraded read renders its own banner and is never drawn as an empty list
/// (ADR-0016 section 7); a permission the caller lacks renders a note naming the
/// permission, never a control that can only 403.

#include <cstddef>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace yuzu::server::device_data {

/// A read that failed (store down or degraded). Distinct from an empty result.
struct Unavailable {};
/// A read the caller is not permitted to make (rendered as a note naming the grant).
struct Denied {};

struct PropertyRow {
    std::string key;
    std::string value;
    std::string type; // "string", "int", "bool", "datetime"
    std::int64_t updated_at{0};
};

struct SchemaRow {
    std::string key;
    std::string display_name;
    std::string type;
    std::string description;
    std::string validation_regex;
};

struct PropertiesView {
    std::string agent_id;
    std::variant<std::vector<PropertyRow>, Unavailable, Denied> properties;
    std::variant<std::vector<SchemaRow>, Unavailable, Denied> schemas;
    bool can_write_properties{false}; // scoped Infrastructure:Write for this device
    bool can_write_schemas{false};    // global Infrastructure:Write
};

/// The Properties and Schemas panels of the "Tags and properties" lens.
std::string render_properties_panels(const PropertiesView& v);

/// The access-audit row for a behavioural read could not persist, so the data is not
/// shown (the REST twins answer 503 + Sec-Audit-Failed; a fragment answers 200 with
/// this note and the same header, because htmx drops a non-2xx body).
struct Withheld {};

/// Display cap on the app-usage table. The store itself is bounded at 20000 rows.
inline constexpr std::size_t kAppUsageDisplayCap = 200;
inline constexpr std::size_t kAppUsageStoreCap = 20000;

struct AppUsageRow {
    std::string exe_key;
    std::int64_t first_seen{0};
    std::int64_t last_seen{0};
    std::int64_t run_count_30d{0};
    std::int64_t total_seconds_30d{0};
};

struct AppUsageData {
    std::vector<AppUsageRow> rows; // any order; the renderer sorts and caps
    std::int64_t collected_at{0};
};

struct AppUsageView {
    std::string agent_id;
    std::variant<AppUsageData, Unavailable, Denied, Withheld> body;
};

/// Per-application usage for one device. `user_ref` and every other per-user value is
/// absent from the input type, so nothing here can render it.
std::string render_app_usage_panel(const AppUsageView& v);

/// A detected licence. Deliberately has no user_scope / user_ref / key_hint field.
struct LicenceRow {
    std::string product;
    std::string vendor;
    std::string version;
    std::string license_type;
    std::string state;
    std::string channel;
    std::string confidence;
    std::string key_hint; // OS-provided partial only, never key material
    std::string detector;
    std::int64_t expiry_at{0}; // 0 = none
};

struct LicencesView {
    std::string agent_id;
    std::variant<std::vector<LicenceRow>, Unavailable, Denied, Withheld> body;
};

std::string render_licences_panel(const LicencesView& v);

/// The two click-to-load hosts shown under the installed-software table. Nothing is
/// fetched (and nothing is audited) until an operator clicks.
std::string render_usage_load_hosts(const std::string& agent_id);

} // namespace yuzu::server::device_data
