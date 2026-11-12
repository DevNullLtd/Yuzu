#pragma once

// Protective actions: the closed set of (plugin, action) pairs that plugin
// enablement (per-plugin/action kill switch, per-OS withhold and its presence
// read, plugin-presence filter, degraded plugin-config store) must NEVER
// refuse, because refusing one strands a contained device or a containment
// rule push.
//
// The set is the firewall plugin's four containment actions (quarantine,
// release, quarantine_status, quarantine_allow) plus the Guardian rule push
// (`__guard__.push_rules`). It is CLOSED: widening it is a security decision
// (see the quarantine row of .claude/routed-concerns.md; the four-action set is
// Alex's ruling, 2026-11-11), never a drive-by edit. Lives in common/include so
// agent code can include the same list the server dispatch chokepoint uses.
//
// Pure: no I/O, no store or wire types, so it stays inside the
// common/include firewall and tests bind it directly.

#include <cstddef>
#include <string_view>

namespace yuzu::protective {

namespace detail {
/// Explicit A-Z fold, never `std::tolower`: that depends on the process C
/// locale, and this list is an identifier check where under-exempting is the
/// dangerous direction.
[[nodiscard]] constexpr char to_lower_ascii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

/// Case-insensitive (ASCII-fold) equality. The one comparison both predicates
/// below share.
[[nodiscard]] inline bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (to_lower_ascii(a[i]) != to_lower_ascii(b[i]))
            return false;
    }
    return true;
}
} // namespace detail

/// #881: case-insensitive predicate for the containment control-channel
/// exemption. Pure — no store access — so a test can bind it directly without
/// a live `QuarantineStore`. Normalises to lowercase itself
/// (`ServerImpl::dispatch_confined` already lowercases the ACTION at its own
/// call site, never the plugin) so `"Firewall"`/`"FIREWALL"` exempt exactly like
/// `"firewall"`.
///
/// Keyed on the `(plugin, ACTION)` pair against a CLOSED set — not on the
/// plugin name alone. `firewall` also registers `state` and `rules`, which are
/// ordinary actions and stay gated: exempting the whole plugin would let them,
/// and any action added later, inherit the bypass silently with nothing in
/// review to notice. All four containment actions are exempt, deliberately:
/// narrowing it to `release` alone would break re-isolation (a fresh `quarantine`
/// against an already-contained device), allow-list repair of a contained
/// device's exceptions, and the reconciler's re-apply and status reads — all of
/// which are the plugin managing its OWN containment state, not an operator
/// reaching a quarantined agent through some other plugin.
[[nodiscard]] inline bool is_quarantine_control_plugin(std::string_view plugin,
                                                       std::string_view action) {
    using detail::iequals;
    constexpr std::string_view kContainmentPlugin{"firewall"};
    if (!iequals(plugin, kContainmentPlugin))
        return false;

    // Keyed on the (plugin, ACTION) pair, not the plugin alone; closed against the
    // plugin's four containment actions (`acts[]` in firewall_plugin.cpp). Anything
    // else, `state` and `rules` included, is gated.
    //
    // Why all four rather than release alone: `release` IS the release path;
    // `quarantine_status` is read-only and answering it for a contained host is the
    // point (it is also how the server confirms a release); `quarantine_allow` is
    // how a management path is repaired, and gating it would make a host whose
    // allow-list is wrong unrecoverable remotely — the stranding this control
    // exists to avoid; and `quarantine` on an already-contained host is the
    // re-dispatch #3127 relies on. An action NOT on this list gets no exemption
    // even on this plugin.
    for (const auto allowed :
         {std::string_view{"quarantine"}, std::string_view{"release"},
          std::string_view{"quarantine_status"}, std::string_view{"quarantine_allow"}}) {
        if (iequals(action, allowed))
            return true;
    }
    return false;
}

/// The full protective set: the firewall containment actions plus the Guardian
/// rule push `__guard__.push_rules` (a contained device must keep receiving
/// the rules that make containment meaningful). Case-insensitive.
[[nodiscard]] inline bool is_protective_action(std::string_view plugin, std::string_view action) {
    if (is_quarantine_control_plugin(plugin, action))
        return true;
    using detail::iequals;
    return iequals(plugin, "__guard__") && iequals(action, "push_rules");
}

/// True iff `plugin` declares at least one protective action, so a plugin-level
/// kill-switch row for it covers the protective set. For `firewall` that is true
/// although it also has ordinary actions (`state`, `rules`): the row still stops
/// those and never stops the four. Kept beside
/// `is_protective_action` so the plugin names are never spelled a second time;
/// the exhaustive table in tests/unit/test_protective_actions.cpp fails if the
/// two drift.
[[nodiscard]] inline bool plugin_owns_protective_actions(std::string_view plugin) {
    using detail::iequals;
    return iequals(plugin, "firewall") || iequals(plugin, "__guard__");
}

} // namespace yuzu::protective
