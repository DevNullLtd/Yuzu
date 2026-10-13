#pragma once

// Protective actions: the closed set of (plugin, action) pairs that plugin
// enablement (per-plugin/action kill switch, per-OS withhold and its presence
// read, plugin-presence filter, degraded plugin-config store) must NEVER
// refuse, because refusing one strands a contained device or a containment
// rule push.
//
// The set is the quarantine plugin's own four actions plus the Guardian rule
// push (`__guard__.push_rules`). It is CLOSED: widening it is a security
// decision (see the quarantine row of .claude/routed-concerns.md), never a
// drive-by edit. Lives in common/include so agent code can include the same
// list the server dispatch chokepoint uses.
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

/// #881: case-insensitive predicate for the quarantine control-channel
/// exemption. Pure — no store access — so a test can bind it directly without
/// a live `QuarantineStore`. Normalises to lowercase itself
/// (`ServerImpl::dispatch_confined` already lowercases the ACTION at its own
/// call site, never the plugin) so `"Quarantine"`/`"QUARANTINE"` exempt
/// exactly like `"quarantine"`.
///
/// Keyed on the `(plugin, ACTION)` pair against a CLOSED set — not on the
/// plugin name alone. All four actions the plugin registers today
/// (quarantine, unquarantine, status, whitelist) are exempt, deliberately:
/// narrowing it to `unquarantine` alone would break re-isolation (a fresh
/// `quarantine` action against an already-contained device), whitelist repair
/// of a contained device's exceptions, and #3127's retry path — all of which
/// are the plugin managing its OWN containment state, not an operator
/// reaching a quarantined agent through some other plugin. Keying on the
/// plugin alone would have let a FIFTH action added later inherit the bypass
/// silently, with nothing in review to notice; see the closed-set comment in
/// the body.
[[nodiscard]] inline bool is_quarantine_control_plugin(std::string_view plugin,
                                                       std::string_view action) {
    using detail::iequals;
    constexpr std::string_view kQuarantinePlugin{"quarantine"};
    if (!iequals(plugin, kQuarantinePlugin))
        return false;

    // Keyed on the (plugin, ACTION) pair, not the plugin alone.
    //
    // Exempting a whole plugin means a FUTURE action inherits the exemption
    // silently — the plugin declares exactly four today, and a fifth would
    // arrive already able to bypass containment with nothing in review to
    // notice. This set is closed against the plugin's declared actions
    // (`acts[]` in quarantine_plugin.cpp); anything else is gated.
    //
    // Why all four are here rather than release alone: `unquarantine` IS the
    // release path; `status` is read-only and answering it for a contained host
    // is the point; `whitelist` is how a management path is repaired, and
    // gating it would make a host whose whitelist is wrong unrecoverable
    // remotely — the stranding this control exists to avoid; and `quarantine`
    // on an already-contained host is the re-dispatch #3127 relies on. An
    // action NOT on this list gets no exemption even on this plugin.
    for (const auto allowed : {std::string_view{"quarantine"}, std::string_view{"unquarantine"},
                               std::string_view{"status"}, std::string_view{"whitelist"}}) {
        if (iequals(action, allowed))
            return true;
    }
    return false;
}

/// The full protective set: the quarantine control actions plus the Guardian
/// rule push `__guard__.push_rules` (a contained device must keep receiving
/// the rules that make containment meaningful). Case-insensitive.
[[nodiscard]] inline bool is_protective_action(std::string_view plugin, std::string_view action) {
    if (is_quarantine_control_plugin(plugin, action))
        return true;
    using detail::iequals;
    return iequals(plugin, "__guard__") && iequals(action, "push_rules");
}

/// True iff `plugin` declares at least one protective action, so a plugin-level
/// kill-switch row for it covers the protective set. Kept beside
/// `is_protective_action` so the plugin names are never spelled a second time;
/// the exhaustive table in tests/unit/test_protective_actions.cpp fails if the
/// two drift.
[[nodiscard]] inline bool plugin_owns_protective_actions(std::string_view plugin) {
    using detail::iequals;
    return iequals(plugin, "quarantine") || iequals(plugin, "__guard__");
}

} // namespace yuzu::protective
