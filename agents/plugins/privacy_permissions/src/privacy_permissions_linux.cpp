/**
 * privacy_permissions_linux.cpp -- Linux leg: xdg-desktop-portal's PermissionStore over the
 * SESSION bus (sd_bus_open_user) -- NOT the system bus firmware_posture_linux.cpp's fwupd leg
 * uses. Zero in-tree precedent for a session-bus call anywhere in this repo (confirmed by
 * grep); this is genuinely new ground, same RAII shape (BusGuard/SdBusErrorGuard/
 * SdBusMessageGuard, hand-rolled per file, no shared sd-bus header exists) as
 * firmware_posture_linux.cpp / firewall_plugin.cpp.
 *
 * PROBED (xdg-desktop-portal 1.20.3, Debian 13 container, 2026-09-23 -- see
 * privacy_permissions_linux_parsers.hpp's banner for the real reply shapes): `Lookup(in s table,
 * in s id) -> (out a{sas} permissions, out v data)`; `devices`/`camera`, `devices`/`microphone`
 * and `location`/`location` are the real table/id pairs; the `location` table stores
 * [accuracy, timestamp], not a yes/no. Every decision (the list decode, the error-name and
 * reply-shape classification, the all-vs-some ServiceUnknown rule) lives in that pure header;
 * this file only performs the sd_bus calls. Still unmeasured: a GNOME/KDE desktop session's
 * real grants (the probe seeded its own records into a fresh store). full_disk_access has no
 * single-boolean portal equivalent (Flatpak's `filesystem` permission is per-directory), so it
 * ships `unsupported`.
 *
 * SCOPE -- THE AGENT'S OWN SESSION BUS ONLY: sd_bus_open_user connects to the session bus of
 * the account the agent process runs as. It never reaches another user's session, and each
 * user's portal permission store lives in that user's own session -- so this leg reports, at
 * most, the grants of the agent's own account. The agent normally runs as a system service
 * with no session bus at all, so the honest result there is UNAVAILABLE, and UNAVAILABLE says
 * nothing about any interactive user's grants.
 *
 * No daemon / no session bus (no XDG_RUNTIME_DIR/DBUS_SESSION_BUS_ADDRESS, no socket, nobody
 * listening) is the EXPECTED common case -- `unsupported` + UNAVAILABLE, no failure token. A
 * refused session-bus socket is `denied` and any other open failure `unreadable`
 * (classify_session_bus_open), never folded into "no session". Once the bus is up, every
 * mapped category gets a row: its decoded app rows, `absent` (the portal answered NotFound or
 * an empty table), or a `denied`/`unreadable` row carrying its own `<category>:<cause>` token.
 * The three Lookups share ONE total deadline (portal::kPortalTotalBudgetUs, re-armed per call
 * with the time left -- the firewall_plugin.cpp precedent); a lookup that runs out of it, or is
 * reached after it is spent, is `<category>:timeout`.
 */
#include "privacy_permissions_legs.hpp"
#include "privacy_permissions_linux_parsers.hpp"

#if defined(__linux__)

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#if defined(YUZU_HAVE_LIBSYSTEMD)
#include <systemd/sd-bus.h>
#endif

namespace yuzu::privacy_permissions {

namespace {

#if defined(YUZU_HAVE_LIBSYSTEMD)

constexpr const char* kPortalDest = "org.freedesktop.impl.portal.PermissionStore";
constexpr const char* kPortalPath = "/org/freedesktop/impl/portal/PermissionStore";
constexpr const char* kPortalIface = "org.freedesktop.impl.portal.PermissionStore";

struct BusGuard {
    sd_bus* bus = nullptr;
    ~BusGuard() {
        if (bus) sd_bus_flush_close_unref(bus);
    }
    BusGuard() = default;
    BusGuard(const BusGuard&) = delete;
    BusGuard& operator=(const BusGuard&) = delete;
};
struct SdBusErrorGuard {
    sd_bus_error err = SD_BUS_ERROR_NULL;
    ~SdBusErrorGuard() { sd_bus_error_free(&err); }
    SdBusErrorGuard() = default;
    SdBusErrorGuard(const SdBusErrorGuard&) = delete;
    SdBusErrorGuard& operator=(const SdBusErrorGuard&) = delete;
};
struct SdBusMessageGuard {
    sd_bus_message* m = nullptr;
    ~SdBusMessageGuard() {
        if (m) sd_bus_message_unref(m);
    }
    SdBusMessageGuard() = default;
    SdBusMessageGuard(const SdBusMessageGuard&) = delete;
    SdBusMessageGuard& operator=(const SdBusMessageGuard&) = delete;
};

/// One Lookup(table, id) call: performs the sd_bus call and walks the a{sas} reply into plain
/// values; every decision about them is portal::append_lookup_error_rows /
/// portal::append_lookup_reply_rows. Returns true for ServiceUnknown (no row -- the caller
/// decides, portal::finish_portal_rows).
bool do_lookup(sd_bus* bus, const portal::PortalTable& t, std::vector<PermissionRow>& rows,
               yuzu::shared::ConstraintAccumulator& acc) {
    SdBusErrorGuard err;
    SdBusMessageGuard reply;
    const int rc = sd_bus_call_method(bus, kPortalDest, kPortalPath, kPortalIface, "Lookup",
                                      &err.err, &reply.m, "ss", std::string{t.table}.c_str(),
                                      std::string{t.id}.c_str());
    if (rc < 0)
        return portal::append_lookup_error_rows(
            t, portal::classify_lookup_error(err.err.name ? err.err.name : "", -rc), rows, acc);

    portal::PortalReply walked;
    // sd_bus_message_enter_container returns >0 entered, 0 a genuine type MISMATCH
    // at the current position (NOT entered), <0 an error -- only >0 is success.
    walked.array_entered = sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "{sas}") > 0;
    if (walked.array_entered) {
        int r;
        while ((r = sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_DICT_ENTRY, "sas")) > 0) {
            const char* app_id = nullptr;
            bool ok = sd_bus_message_read(reply.m, "s", &app_id) > 0 &&
                      sd_bus_message_enter_container(reply.m, SD_BUS_TYPE_ARRAY, "s") > 0;
            if (ok) {
                portal::PortalEntry entry{app_id ? app_id : "-", {}};
                const char* perm = nullptr;
                int pr;
                while ((pr = sd_bus_message_read(reply.m, "s", &perm)) > 0)
                    entry.permissions.emplace_back(perm ? perm : "");
                if (pr < 0) ok = false; // a string that failed to read is never a shorter list
                sd_bus_message_exit_container(reply.m);
                if (ok) walked.entries.push_back(std::move(entry));
            }
            if (!ok) walked.entry_failed = true;
            sd_bus_message_exit_container(reply.m);
        }
        walked.walk_failed = (r < 0);
        sd_bus_message_exit_container(reply.m);
    }
    portal::append_lookup_reply_rows(t, walked, rows, acc);
    return false;
}

#endif // YUZU_HAVE_LIBSYSTEMD

} // namespace

int collect_linux_permissions(yuzu::CommandContext& ctx) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;

#if defined(YUZU_HAVE_LIBSYSTEMD)
    BusGuard bus;
    const int open_rc = sd_bus_open_user(&bus.bus);
    if (open_rc < 0 || !bus.bus) {
        const int err = open_rc < 0 ? -open_rc : 0;
        const auto outcome = portal::classify_session_bus_open(err);
        if (outcome == portal::BusOpenOutcome::unavailable) {
            // No session bus for the agent's own account (headless, system service) -- the
            // expected common case. Honest unavailable, no token.
            rows.push_back({"linux", "-", "-", PermissionState::unsupported, "-", "-", "-", false});
            return emit_rows(ctx, rows, acc, true);
        }
        rows.push_back(outcome == portal::BusOpenOutcome::denied
                           ? failure_row("linux", "-", "-", true, "session_bus:access_denied", acc)
                           : failure_row("linux", "-", "-", false,
                                         "session_bus:open_errno_" + std::to_string(err), acc));
        return emit_rows(ctx, rows, acc, false);
    }
    // One total deadline across the lookups (portal::kPortalTotalBudgetUs): each call is armed
    // with only the time left, and a category reached after it ran out is `<category>:timeout`.
    const auto t_start = std::chrono::steady_clock::now();
    std::vector<std::string_view> service_unknown;
    for (const auto& t : portal::kPortalLookups) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - t_start);
        const std::uint64_t left = portal::remaining_budget_us(
            portal::kPortalTotalBudgetUs, static_cast<std::uint64_t>(elapsed.count()));
        if (left == 0) {
            portal::append_lookup_error_rows(t, portal::LookupError::timeout, rows, acc);
            continue;
        }
        sd_bus_set_method_call_timeout(bus.bus, left);
        if (do_lookup(bus.bus, t, rows, acc)) service_unknown.push_back(t.category);
    }
    if (portal::finish_portal_rows(service_unknown, rows, acc))
        return emit_rows(ctx, rows, acc, true);
#else
    // Built without libsystemd (-Dsystemd_guard=auto|disabled): a build-time absence, not an
    // OS statement -- this plugin cannot know whether a portal daemon exists on this host.
    rows.push_back(failure_row("linux", "-", "-", false, "portal:not_built", acc));
#endif

    return emit_rows(ctx, rows, acc, false);
}

} // namespace yuzu::privacy_permissions

#endif // defined(__linux__)
