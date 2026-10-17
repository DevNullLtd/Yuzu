#pragma once

/// @file plugin_page_model.hpp
///
/// Pure view models and renderers for the three read panels of System > Plugins and
/// updates: Plugin configuration, Kill switch (lookup) and Product packs. The route TU
/// reads the stores and fills these structs; nothing here touches a store, a clock or
/// httplib, so every state (ready, empty, degraded, denied, truncated) is a unit-test
/// fixture and no test opens Postgres.
///
/// Rules every renderer keeps:
///  - degraded is never rendered as empty, and denied is never an endless "Loading...";
///  - every operator-, agent- or YAML-derived string goes through html_escape;
///  - a secret value never appears (the store has no read path for one);
///  - wording stays mechanical: the kill switch makes the server refuse to SEND.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yuzu::server::plugin_page {

enum class PanelState {
    Ready,    ///< rows (possibly none) were read
    Degraded, ///< the store could not be read: never shown as "none"
    Denied,   ///< the principal lacks the twin's read securable
};

// ── Plugin configuration ──────────────────────────────────────────────────

struct ConfigRow {
    std::string plugin;
    std::string key;
    std::string value;
    std::int64_t updated_at_ms{0};
    std::string updated_by;
};

struct ConfigPanel {
    PanelState state{PanelState::Ready};
    std::vector<ConfigRow> rows;
    bool truncated{false};     ///< the store's row cap was hit
    std::size_t row_cap{5000}; ///< what "First N shown" names
};

std::string render_config_panel(const ConfigPanel& p);

// ── Kill switch (four-layer lookup) ───────────────────────────────────────

enum class SwitchState { Enabled, Disabled, Unknown };

struct SwitchLayer {
    std::string os;     ///< "" = all operating systems; windows | linux | darwin
    SwitchState state{SwitchState::Unknown};
    std::string reason;
    std::string set_by;
    std::int64_t updated_at_ms{0};
    std::string source; ///< scope key of the row that decided this layer ("" = no row)
};

struct KillSwitchPanel {
    PanelState state{PanelState::Ready};
    std::string plugin; ///< as entered; empty renders only the lookup form
    std::string action; ///< optional
    std::string input_error;               ///< non-empty: the entered names are not valid
    std::vector<std::string> known_plugins; ///< fleet-observed plugin names for the datalist
    bool catalogue_available{false};        ///< false: do not claim a name is unknown
    bool plugin_known{true};
    bool action_known{true};                ///< only meaningful when `action` is non-empty
    bool protective{false};                 ///< the entered scope covers protective actions
    std::vector<SwitchLayer> layers;        ///< all-OS, windows, linux, darwin
};

std::string render_kill_switch_panel(const KillSwitchPanel& p);

// ── Product packs ─────────────────────────────────────────────────────────

struct PackItem {
    std::string kind;
    std::string name;
    std::string item_id;
};

struct PackRow {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::vector<PackItem> items;
    std::int64_t installed_at{0}; ///< epoch seconds
    bool verified{false};         ///< valid for the key carried INSIDE the pack
};

struct PacksPanel {
    PanelState state{PanelState::Ready};
    std::vector<PackRow> rows;
    std::size_t shown_limit{100};
    bool more{false}; ///< N+1 were available: "First N shown"
};

std::string render_packs_panel(const PacksPanel& p);

// ── Shared helpers (exposed for tests) ────────────────────────────────────

/// Fixed sentence for a denied panel naming the missing grant.
std::string denied_note(const char* permission);

/// "Windows", "Linux", "macOS" for a layer's os value; "All operating systems" for "".
std::string layer_label(const std::string& os);

/// Value text capped for display (full value stays in the cell's title). Never cuts a
/// UTF-8 sequence.
std::string clip_for_display(const std::string& s, std::size_t max_bytes = 160);

} // namespace yuzu::server::plugin_page
