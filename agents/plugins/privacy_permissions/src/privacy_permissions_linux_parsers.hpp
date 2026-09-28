/**
 * privacy_permissions_linux_parsers.hpp -- Linux-only PURE layer: the session-bus open
 * classifier, the xdg-desktop-portal PermissionStore table map, the per-table permission-list
 * decode, the `Lookup` error/reply-shape decisions and the all-vs-some ServiceUnknown rule. No
 * sd-bus header, no syscall: privacy_permissions_linux.cpp performs the real sd_bus calls and
 * hands this file plain values (an errno, a D-Bus error name, the decoded a{sas} entries), same
 * split as privacy_permissions_macos_parsers.hpp / privacy_permissions_win_parsers.hpp.
 *
 * REAL SHAPES (xdg-desktop-portal 1.20.3, Debian 13 container, 2026-09-23): `Lookup(s table,
 * s id) -> (a{sas} permissions, v data)`. The `devices` table (ids `camera`, `microphone`)
 * stores ONE string per app -- `yes`, `no` or `ask` -- e.g. `({'org.example.CamApp': ['yes']},
 * <byte 0x00>)`. The `location` table (id `location`) stores TWO strings per app, `[accuracy,
 * timestamp]` -- e.g. `({'org.example.MapApp': ['EXACT', '0']}, <byte 0x00>)`. The accuracy
 * vocabulary is the portal binary's own literal set (`strings /usr/libexec/xdg-desktop-portal`):
 * NONE, COUNTRY, CITY, NEIGHBORHOOD, STREET, EXACT -- `NONE` is the portal's refusal, every other
 * level is a grant at that accuracy.
 */
#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "privacy_permissions_parsers.hpp"

namespace yuzu::privacy_permissions::portal {

// ── session-bus open (errno values are portable <cerrno> constants) ────

enum class BusOpenOutcome { unavailable, denied, failed };

/// Classifies sd_bus_open_user's NEGATED return (pass the positive errno). No session bus to
/// reach (no XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS, no socket, nobody listening) is the
/// honest UNAVAILABLE case; a refused socket is `denied`, never folded into "no session";
/// anything else is a real failure.
[[nodiscard]] constexpr BusOpenOutcome classify_session_bus_open(int err) noexcept {
    switch (err) {
    case ENOENT:
    case ENOTDIR:
    case ECONNREFUSED:
    case ENXIO:
#if defined(ENOMEDIUM)
    case ENOMEDIUM: // systemd's "no XDG_RUNTIME_DIR" answer (Linux-only errno)
#endif
        return BusOpenOutcome::unavailable;
    case EACCES:
    case EPERM:
        return BusOpenOutcome::denied;
    default:
        return BusOpenOutcome::failed;
    }
}

// ── the table map ───────────────────────────────────────────────────────

enum class TableKind { devices, location };

struct PortalTable {
    std::string_view table;
    std::string_view id;
    std::string_view category;
    TableKind kind;
};

// `full_disk_access` is deliberately absent -- Flatpak's `filesystem` permission is a
// per-directory grant, not one boolean, so the leg declares it `unsupported` instead.
inline constexpr std::array<PortalTable, 3> kPortalLookups{{
    {"devices", "camera", "camera", TableKind::devices},
    {"devices", "microphone", "microphone", TableKind::devices},
    {"location", "location", "location", TableKind::location},
}};

/// Location accuracy levels that are a GRANT (the portal's own literals; `NONE` is its refusal).
inline constexpr std::array<std::string_view, 5> kGrantedAccuracy{"COUNTRY", "CITY", "NEIGHBORHOOD",
                                                                  "STREET", "EXACT"};

// ── one app's permission list ───────────────────────────────────────────

/// A decoded list. `cause` is non-empty exactly when the list could not be decoded at all
/// (state `unreadable`); an unmodelled but well-formed value is `prompt_undetermined` with no
/// cause -- visible, raw kept, never guessed (the decode_auth_value/decode_consent_value rule).
struct PortalDecision {
    PermissionState state;
    std::string_view cause;
};

/// Table-aware decode. `devices`: exactly one of yes/no/ask. `location`: exactly
/// [accuracy, timestamp] -- NONE is denied, a known accuracy is allowed. An EMPTY list is not a
/// refusal: it names no decision at all, so it is `unreadable` with cause `empty_permissions`,
/// never `denied`.
[[nodiscard]] inline PortalDecision decode_portal_permissions(TableKind kind,
                                                              std::span<const std::string> perms) {
    if (perms.empty()) return {PermissionState::unreadable, "empty_permissions"};
    const std::string_view first = perms.front();
    if (kind == TableKind::devices) {
        if (perms.size() != 1) return {PermissionState::prompt_undetermined, {}};
        if (first == "yes") return {PermissionState::allowed, {}};
        if (first == "no") return {PermissionState::denied, {}};
        if (first == "ask") return {PermissionState::prompt_undetermined, {}};
        return {PermissionState::prompt_undetermined, {}};
    }
    if (perms.size() != 2) return {PermissionState::prompt_undetermined, {}};
    if (first == "NONE") return {PermissionState::denied, {}};
    for (const auto level : kGrantedAccuracy)
        if (first == level) return {PermissionState::allowed, {}};
    return {PermissionState::prompt_undetermined, {}};
}

/// The row's `raw`: the list comma-joined exactly as the portal returned it ("-" when empty).
[[nodiscard]] inline std::string join_permissions(std::span<const std::string> perms) {
    std::string out;
    for (const auto& p : perms) {
        if (!out.empty()) out += ',';
        out += p;
    }
    return out.empty() ? std::string{"-"} : out;
}

// ── one Lookup call ─────────────────────────────────────────────────────

enum class LookupError { service_unknown, not_found, access_denied, timeout, failed };

// ── one total deadline across every Lookup ─────────────────────────────

/// The whole collection's D-Bus budget: each Lookup gets only what is left of it as its own
/// method-call timeout, so a portal that accepts the call but never answers holds the dispatch
/// thread for at most this long in total, never once per lookup. Same 5 s as firewall's budget.
inline constexpr std::uint64_t kPortalTotalBudgetUs = 5'000'000;

/// Microseconds left of `total_us` after `elapsed_us`; 0 = exhausted. The leg never issues a
/// Lookup with 0 (sd-bus reads a 0 timeout as "the default") -- that category gets a
/// `<category>:timeout` row instead.
[[nodiscard]] constexpr std::uint64_t remaining_budget_us(std::uint64_t total_us,
                                                          std::uint64_t elapsed_us) noexcept {
    return elapsed_us >= total_us ? 0 : total_us - elapsed_us;
}

/// A failed Lookup, by its D-Bus error name, or by its positive errno: ETIMEDOUT (the call ran out
/// of the remaining budget) is `timeout` whatever name sd-bus attached.
[[nodiscard]] constexpr LookupError classify_lookup_error(std::string_view dbus_error_name,
                                                          int err = 0) noexcept {
    if (err == ETIMEDOUT || dbus_error_name == "org.freedesktop.DBus.Error.Timeout")
        return LookupError::timeout;
    if (dbus_error_name == "org.freedesktop.DBus.Error.ServiceUnknown")
        return LookupError::service_unknown;
    if (dbus_error_name == "org.freedesktop.portal.Error.NotFound") return LookupError::not_found;
    if (dbus_error_name == "org.freedesktop.DBus.Error.AccessDenied")
        return LookupError::access_denied;
    return LookupError::failed;
}

/// Appends a failed Lookup's row. Returns true for ServiceUnknown, which adds NO row: the caller
/// decides between whole-mechanism unavailability and a per-category failure
/// (finish_portal_rows). NotFound is the portal answering "nothing recorded" -- `absent`.
inline bool append_lookup_error_rows(const PortalTable& t, LookupError e,
                                     std::vector<PermissionRow>& rows,
                                     yuzu::shared::ConstraintAccumulator& acc) {
    const std::string cat{t.category};
    switch (e) {
    case LookupError::service_unknown:
        return true;
    case LookupError::not_found:
        rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
        return false;
    case LookupError::access_denied:
        rows.push_back(failure_row("linux", "-", t.category, true, cat + ":access_denied", acc));
        return false;
    case LookupError::timeout:
        rows.push_back(failure_row("linux", "-", t.category, false, cat + ":timeout", acc));
        return false;
    case LookupError::failed:
        break;
    }
    rows.push_back(failure_row("linux", "-", t.category, false, cat + ":lookup_failed", acc));
    return false;
}

struct PortalEntry {
    std::string app_id;
    std::vector<std::string> permissions;
};

/// A successful Lookup's reply as the leg walked it. `array_entered` = the outer a{sas} was
/// entered; `entry_failed` = a dict entry's key or inner array did not match; `walk_failed` =
/// the dict-entry iteration itself returned an error part-way.
struct PortalReply {
    bool array_entered = false;
    std::vector<PortalEntry> entries;
    bool entry_failed = false;
    bool walk_failed = false;
};

/// Appends one successful Lookup's rows: one per decoded entry (an undecodable list is an
/// `unreadable` row with token `<app_id>:<category>:<cause>`), a `<category>:shape` /
/// `<category>:entry_shape` failure row for a reply that was not fully read, and `absent` only
/// for a table the portal returned cleanly empty -- a partly-read reply is never `absent`.
inline void append_lookup_reply_rows(const PortalTable& t, const PortalReply& reply,
                                     std::vector<PermissionRow>& rows,
                                     yuzu::shared::ConstraintAccumulator& acc) {
    const std::string cat{t.category};
    if (!reply.array_entered) {
        rows.push_back(failure_row("linux", "-", t.category, false, cat + ":shape", acc));
        return;
    }
    std::vector<const PortalEntry*> ordered; // the portal's dict order is not stable
    for (const auto& e : reply.entries) ordered.push_back(&e);
    std::stable_sort(ordered.begin(), ordered.end(),
                     [](const auto* a, const auto* b) { return a->app_id < b->app_id; });
    for (const auto* e : ordered) {
        const auto d = decode_portal_permissions(t.kind, e->permissions);
        if (!d.cause.empty()) {
            rows.push_back(failure_row("linux", e->app_id, t.category, false,
                                       e->app_id + ":" + cat + ":" + std::string{d.cause}, acc));
            continue;
        }
        rows.push_back({"linux", e->app_id, t.category, d.state, join_permissions(e->permissions),
                        "-", "-", false});
    }
    if (reply.walk_failed)
        rows.push_back(failure_row("linux", "-", t.category, false, cat + ":shape", acc));
    if (reply.entry_failed)
        rows.push_back(failure_row("linux", "-", t.category, false, cat + ":entry_shape", acc));
    if (reply.entries.empty() && !reply.walk_failed && !reply.entry_failed)
        rows.push_back({"linux", "-", t.category, PermissionState::absent, "-", "-", "-", false});
}

/// After every Lookup: if EVERY one hit ServiceUnknown the portal backend itself is not on the
/// bus -- the same whole-mechanism-unavailable shape as no session bus, so `rows` becomes the one
/// `unsupported` whole-source row and this returns true (UNAVAILABLE). If only SOME did, the
/// backend answered the others, so each missing category is an `unreadable` failure row
/// (`<category>:service_unknown`), never absence. Either way `full_disk_access` gets its own
/// explicit `unsupported` row on a reachable collection.
inline bool finish_portal_rows(std::span<const std::string_view> service_unknown,
                               std::vector<PermissionRow>& rows,
                               yuzu::shared::ConstraintAccumulator& acc) {
    if (service_unknown.size() == kPortalLookups.size()) {
        rows.clear();
        rows.push_back({"linux", "-", "-", PermissionState::unsupported, "-", "-", "-", false});
        return true;
    }
    for (const auto cat : service_unknown)
        rows.push_back(
            failure_row("linux", "-", cat, false, std::string{cat} + ":service_unknown", acc));
    rows.push_back(
        {"linux", "-", "full_disk_access", PermissionState::unsupported, "-", "-", "-", false});
    return false;
}

} // namespace yuzu::privacy_permissions::portal
