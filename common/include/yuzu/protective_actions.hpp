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

/// The firewall plugin's containment actions: a CLOSED four-action set, keyed on the
/// (plugin, ACTION) pair, never on the plugin alone (the plugin declares exactly these
/// four containment actions in its action table in
/// `agents/plugins/firewall/src/firewall_plugin.cpp`; `state` and `rules` are ordinary
/// actions and stay gated, and a fifth action gets no exemption). Case-insensitive,
/// normalising the plugin name itself (`ServerImpl::dispatch_confined` already
/// lowercases the ACTION at its own call site, never the plugin).
///
/// This is the ONE predicate for two decisions, never two lists: the #881 containment
/// gate's control-channel exemption (`dispatch_confined_arms.hpp`) and, with
/// `__guard__.push_rules`, the protective set below. All four are exempt, deliberately:
/// `release` IS the way out of a containment; `quarantine_status` is read-only and
/// answering it for a contained host is the point (it is also how the server confirms a
/// release); `quarantine_allow` repairs a contained host's exceptions, and gating it would
/// make a host whose allow-list is wrong unrecoverable remotely; and `quarantine` on an
/// already-contained host is the re-dispatch #3127 relies on. Narrowing it to `release`
/// alone would break re-isolation, allow-list repair and the reconciler's re-apply and
/// status reads, all of which are the plugin managing its OWN containment state, not an
/// operator reaching a quarantined agent through some other plugin.
[[nodiscard]] inline bool is_firewall_control_plugin(std::string_view plugin,
                                                     std::string_view action) {
    using detail::iequals;
    if (!iequals(plugin, "firewall"))
        return false;
    for (const auto allowed : {std::string_view{"quarantine"}, std::string_view{"release"},
                               std::string_view{"quarantine_status"},
                               std::string_view{"quarantine_allow"}}) {
        if (iequals(action, allowed))
            return true;
    }
    return false;
}

/// The full protective set: the firewall containment actions plus the Guardian
/// rule push `__guard__.push_rules` (a contained device must keep receiving
/// the rules that make containment meaningful). Case-insensitive.
[[nodiscard]] inline bool is_protective_action(std::string_view plugin, std::string_view action) {
    if (is_firewall_control_plugin(plugin, action))
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

/// True iff `plugin` owns protective actions AND declares ordinary ones beside them (today only
/// `firewall`: `state`, `rules`), so a plugin-level kill-switch row for it exempts the protective
/// actions yet still gates the rest. `__guard__` declares only protective actions.
/// Kept beside `plugin_owns_protective_actions` so the plugin names are spelled in this header
/// only. It feeds the kill-switch AUDIT LABEL only (`protective_exempt=partial`); no enablement,
/// presence, zero-reach or dispatch decision consults it.
[[nodiscard]] inline bool plugin_mixes_protective_and_ordinary_actions(std::string_view plugin) {
    return detail::iequals(plugin, "firewall");
}

} // namespace yuzu::protective
