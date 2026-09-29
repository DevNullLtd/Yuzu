/**
 * autoruns_catalog.hpp — the versioned, cross-platform source catalog for the
 * autoruns plugin.
 *
 * This header is the single source of truth for "what persistence sources
 * does autoruns know about, and what does each OS declare for it". It is
 * PURE data: no OS call, no file read, nothing platform-conditional in the
 * logic itself. `kSourceCatalog` lists every source this plugin will ever
 * enumerate, on every OS, so `catalog` can describe the complete shape
 * regardless of which OS built the plugin — the same append-only, no-OS-guard
 * discipline `YuzuActionDescriptor` follows (plugin.h).
 *
 * `kAutorunSourceCatalogVersion` is bumped whenever a `SourceId` is added,
 * renamed, or removed, so a consumer keying on `catalog_version` (carried in
 * every `Row`, see autoruns_parsers.hpp) can tell "this row was produced
 * against a catalog shape I don't recognise" from "this row is simply new
 * data".
 */
#pragma once

#include <yuzu/plugin.h> // YuzuSupportLevel

#include <array>
#include <string_view>

namespace yuzu::autoruns {

inline constexpr int kAutorunSourceCatalogVersion = 1;

/// Stable string ids. NEVER renumber or reuse a spelling — `source_id_string`
/// is what every `autorun|` / `source|` row and every content definition
/// keys on, and a downstream consumer stores it as an opaque string.
enum class SourceId {
    // Windows
    win_run_hklm,
    win_runonce_hklm,
    win_runonceex_hklm,
    win_run_hku,
    win_runonce_hku,
    win_startup_approved,
    win_winlogon_shell,
    win_winlogon_userinit,
    win_appinit_dlls,
    win_ifeo_debugger,
    win_startup_folder_common,
    win_startup_folder_user,
    win_scheduled_tasks,
    win_wmi_subscriptions,
    // Linux
    lnx_etc_crontab,
    lnx_cron_d,
    lnx_cron_periodic,
    lnx_user_crontabs,
    lnx_anacrontab,
    lnx_at_spool,
    lnx_systemd_timers_system,
    lnx_systemd_timers_user,
    lnx_xdg_autostart_system,
    lnx_xdg_autostart_user,
    lnx_rc_local,
    lnx_init_d,
    // macOS
    mac_launchdaemons,
    mac_launchagents,
    mac_system_launchdaemons,
    mac_system_launchagents,
    mac_user_launchagents,
    mac_login_items,
    mac_periodic,
    mac_emond,
};

/// The stable wire spelling for a SourceId. Every branch is a literal --
/// never derived from the enumerator name by macro or reflection -- so a
/// future enum rename cannot silently change the string a fleet has already
/// persisted rows against.
constexpr std::string_view source_id_string(SourceId id) noexcept {
    switch (id) {
    case SourceId::win_run_hklm:              return "win_run_hklm";
    case SourceId::win_runonce_hklm:          return "win_runonce_hklm";
    case SourceId::win_runonceex_hklm:        return "win_runonceex_hklm";
    case SourceId::win_run_hku:               return "win_run_hku";
    case SourceId::win_runonce_hku:           return "win_runonce_hku";
    case SourceId::win_startup_approved:      return "win_startup_approved";
    case SourceId::win_winlogon_shell:        return "win_winlogon_shell";
    case SourceId::win_winlogon_userinit:     return "win_winlogon_userinit";
    case SourceId::win_appinit_dlls:          return "win_appinit_dlls";
    case SourceId::win_ifeo_debugger:         return "win_ifeo_debugger";
    case SourceId::win_startup_folder_common: return "win_startup_folder_common";
    case SourceId::win_startup_folder_user:   return "win_startup_folder_user";
    case SourceId::win_scheduled_tasks:       return "win_scheduled_tasks";
    case SourceId::win_wmi_subscriptions:     return "win_wmi_subscriptions";
    case SourceId::lnx_etc_crontab:           return "lnx_etc_crontab";
    case SourceId::lnx_cron_d:                return "lnx_cron_d";
    case SourceId::lnx_cron_periodic:         return "lnx_cron_periodic";
    case SourceId::lnx_user_crontabs:         return "lnx_user_crontabs";
    case SourceId::lnx_anacrontab:            return "lnx_anacrontab";
    case SourceId::lnx_at_spool:              return "lnx_at_spool";
    case SourceId::lnx_systemd_timers_system: return "lnx_systemd_timers_system";
    case SourceId::lnx_systemd_timers_user:   return "lnx_systemd_timers_user";
    case SourceId::lnx_xdg_autostart_system:  return "lnx_xdg_autostart_system";
    case SourceId::lnx_xdg_autostart_user:    return "lnx_xdg_autostart_user";
    case SourceId::lnx_rc_local:              return "lnx_rc_local";
    case SourceId::lnx_init_d:                return "lnx_init_d";
    case SourceId::mac_launchdaemons:         return "mac_launchdaemons";
    case SourceId::mac_launchagents:          return "mac_launchagents";
    case SourceId::mac_system_launchdaemons:  return "mac_system_launchdaemons";
    case SourceId::mac_system_launchagents:   return "mac_system_launchagents";
    case SourceId::mac_user_launchagents:     return "mac_user_launchagents";
    case SourceId::mac_login_items:           return "mac_login_items";
    case SourceId::mac_periodic:              return "mac_periodic";
    case SourceId::mac_emond:                 return "mac_emond";
    }
    return "unknown_source";
}

/// One catalog row: a source's identity plus what EVERY OS declares for it.
/// A source native to one OS still carries all three fields -- the other two
/// are YUZU_SUPPORT_UNSUPPORTED -- so `catalog` and the foreign-OS stubs in
/// autoruns_legs.hpp can read any of the three uniformly, with no per-OS
/// special case at the call site.
struct SourceDecl {
    SourceId id;
    const char* name;
    YuzuSupportLevel linux;
    YuzuSupportLevel macos;
    YuzuSupportLevel windows;
};

/// The full 34-source catalog. Declared support is SUPPORTED on a source's
/// own OS except the three documented exceptions:
///   - mac_login_items: the login-items list lives in a private BTM database
///     with no public read API; the only route is `osascript` driving System
///     Events, which is a rung-3 governed-shell acquisition under Decision 5
///     -- CONSTRAINED, not SUPPORTED.
///   - lnx_init_d: /etc/init.d scripts are a legacy SysV mechanism this
///     plugin lists (script names + metadata) but does not interpret --
///     whether a listed script is actually wired into the current runlevel
///     needs update-rc.d/systemctl state this leg does not read -- CONSTRAINED.
///   - lnx_systemd_timers_user: the scanned search-path set omits several
///     standard `systemd --user` unit-search roots (`~/.local/share/systemd/
///     user`, `/run/systemd/user`, `/usr/local/{lib,share}/systemd/user`,
///     `/usr/share/systemd/user`) -- a permanent, documented coverage gap,
///     not a transient failure -- CONSTRAINED.
inline constexpr std::array<SourceDecl, 34> kSourceCatalog{{
    // Windows
    {SourceId::win_run_hklm, "HKLM Run", YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_runonce_hklm, "HKLM RunOnce", YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_runonceex_hklm, "HKLM RunOnceEx", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_run_hku, "HKU Run (every loaded/mountable hive)", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_runonce_hku, "HKU RunOnce (every loaded/mountable hive)",
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_startup_approved, "Explorer StartupApproved\\Run", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_winlogon_shell, "Winlogon Shell", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_winlogon_userinit, "Winlogon Userinit", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_appinit_dlls, "AppInit_DLLs", YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_ifeo_debugger, "Image File Execution Options Debugger",
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_startup_folder_common, "Startup folder (All Users)", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_startup_folder_user, "Startup folder (current user)",
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_scheduled_tasks, "Scheduled Tasks", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    {SourceId::win_wmi_subscriptions, "WMI permanent event subscriptions",
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED},
    // Linux
    {SourceId::lnx_etc_crontab, "/etc/crontab", YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_cron_d, "/etc/cron.d/*", YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_cron_periodic, "/etc/cron.{hourly,daily,weekly,monthly}",
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_user_crontabs, "/var/spool/cron crontabs (per user)", YUZU_SUPPORT_SUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_anacrontab, "/etc/anacrontab", YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_at_spool, "/var/spool/at (at(1) jobs)", YUZU_SUPPORT_SUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_systemd_timers_system, "systemd system timer units", YUZU_SUPPORT_SUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_systemd_timers_user, "systemd user timer units", YUZU_SUPPORT_CONSTRAINED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_xdg_autostart_system, "XDG autostart (/etc/xdg/autostart)",
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_xdg_autostart_user, "XDG autostart (~/.config/autostart)",
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_rc_local, "/etc/rc.local", YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::lnx_init_d, "/etc/init.d/* (SysV, listing only)", YUZU_SUPPORT_CONSTRAINED,
     YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    // macOS
    {SourceId::mac_launchdaemons, "/Library/LaunchDaemons", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::mac_launchagents, "/Library/LaunchAgents", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::mac_system_launchdaemons, "/System/Library/LaunchDaemons", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::mac_system_launchagents, "/System/Library/LaunchAgents", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::mac_user_launchagents, "~/Library/LaunchAgents", YUZU_SUPPORT_UNSUPPORTED,
     YUZU_SUPPORT_SUPPORTED, YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::mac_login_items, "Login Items (private BTM database, no public API; "
     "osascript is rung 3 under Decision 5)", YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_CONSTRAINED,
     YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::mac_periodic, "/etc/periodic", YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED},
    {SourceId::mac_emond, "/etc/emond.d/rules", YUZU_SUPPORT_UNSUPPORTED, YUZU_SUPPORT_SUPPORTED,
     YUZU_SUPPORT_UNSUPPORTED},
}};

/// The declared support level for `decl` ON THE OS THIS TU WAS BUILT FOR.
/// Used by `catalog` (autoruns_plugin.cpp), which reports "what does THIS
/// build declare", not the other two legs' declarations.
constexpr YuzuSupportLevel declared_support_for_host(const SourceDecl& decl) noexcept {
#if defined(_WIN32)
    return decl.windows;
#elif defined(__APPLE__)
    return decl.macos;
#else
    return decl.linux;
#endif
}

} // namespace yuzu::autoruns
