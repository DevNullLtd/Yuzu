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

} // namespace yuzu::server::device_data
