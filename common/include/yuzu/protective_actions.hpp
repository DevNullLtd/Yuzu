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
// drive-by edit. Consumed by the server dispatch chokepoint today and by the
// agent dispatch gate next, so both sides share ONE list.
//
// Pure: no I/O, no store or wire types, so it stays inside the
// common/include firewall and tests bind it directly.

#include <cctype>
#include <cstddef>
#include <string_view>

namespace yuzu::protective {

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
    constexpr std::string_view kQuarantinePlugin{"quarantine"};
    auto iequals = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) != b[i])
                return false;
        }
        return true;
    };
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
    auto iequals = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size())
            return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) != b[i])
                return false;
        }
        return true;
    };
    return iequals(plugin, "__guard__") && iequals(action, "push_rules");
}

} // namespace yuzu::protective
