#pragma once

/// @file device_estate_render.hpp
/// PURE renderers for the "Stored data" panel at the bottom of a device record's Overview
/// lens (stored-data removal = the SLE decommission cascade). No I/O, no gate: the route
/// (device_estate_routes.cpp) probes `Decommission:Delete` and hands the view in. The copy
/// says exactly what the cascade erases and what it does not; the danger action itself is
/// the page JS calling `DELETE /api/v1/sle/agents/{id}` (static/yuzu-estate.js).

#include <string>

namespace yuzu::server {

struct StoredDataView {
    enum class Gate { Allowed, Denied, Unchecked } gate{Gate::Allowed};
    std::string agent_id;
    std::string hostname; ///< "" -> the agent id is the confirmation value
};

/// The `#hw-stored-data` panel (self-contained root element).
[[nodiscard]] std::string render_stored_data_panel(const StoredDataView& v);

/// The click-to-load placeholder embedded at the bottom of the Overview lens. Loading is
/// on click so a viewer who never opens it does not pay a denied-probe audit row.
[[nodiscard]] std::string stored_data_placeholder(const std::string& agent_id);

} // namespace yuzu::server
