/**
 * autoruns_plugin.cpp — persistence-source enumeration ("what starts
 * automatically") across Windows, Linux and macOS.
 *
 * Actions:
 *   "catalog" — lists every SourceId this plugin knows about (the full
 *               34-source catalog, every OS), with the DECLARED support level
 *               this BUILD carries for it. No OS call: a pure reflection of
 *               autoruns_catalog.hpp.
 *   "list"    — runs every per-OS leg (collect_windows / collect_linux /
 *               collect_macos, autoruns_legs.hpp) and emits a `source|`
 *               status line per source plus zero or more `autorun|` rows for
 *               each source that produced data. `sources=` filters to a
 *               comma-separated SourceId allow-list; leg-internal.
 *
 * This TU is fully portable -- no target-OS #if of any kind. All three legs
 * are declared unconditionally so a single-OS build always links (see
 * autoruns_legs.hpp's foreign-OS stub) and the capability matrix generator
 * (#2204) sees a complete, stable three-OS shape regardless of which OS
 * built this plugin.
 *
 * Read-only: no action here mutates host state, spawns a process, or writes
 * to the registry/filesystem/launchd.
 */

#include <yuzu/plugin.hpp>

#include "autoruns_catalog.hpp"
#include "autoruns_legs.hpp"
#include "autoruns_parsers.hpp"

#include <yuzu/string_utils.hpp>

#include <exception>
#include <optional>
#include <string>
#include <string_view>

namespace {

// Both actions declare the SAME three mechanism strings: `catalog` and
// `list` describe the identical underlying acquisition capability at
// different fidelities (declared-only vs actually-executed), so there is no
// separate "how catalog works" mechanism to name -- it is a pure read of
// this TU's own static data, on every OS.
//
// Notes below are the reviewed, spike-verified text (PR11.5/P15) -- verbatim
// probe results (A1's the-rig LocalSystem run), real captures on this Mac
// and a real ubuntu:24.04 Docker container, and the leg's own code, not
// aspirational text. See docs/user-manual/autoruns.md for the full
// per-source breakdown these notes summarise at the leg level.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "list",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers "
         "argv fallback only when no unit dir is readable",
         "Every acquisition is a bounded local file read or directory listing "
         "(read_file_bounded, O_NOFOLLOW on the leaf) except one declared exception: systemd "
         "timer enumeration is a tri-state on /run/systemd/system -- absent reports UNSUPPORTED "
         "(no_systemd), a stat() error other than ENOENT reports CONSTRAINED "
         "(systemd_state_undetermined), and present reads /etc/systemd/system, "
         "/usr/lib/systemd/system and /lib/systemd/system directly. Only when systemd is present "
         "but all three dirs are unreadable does it fall back to `systemctl list-timers --all "
         "--no-pager --no-legend` (rung 2, autoruns/collect_linux#1, docs/agent-spawn-sink-"
         "manifest.md), whose rows carry enabled=unknown -- that text has no wants-symlink "
         "evidence. A rung-1-scanned timer row can ALSO carry enabled=unknown, even with a "
         "real wants-symlink read attempted: if a wants directory consulted for it hit a real "
         "I/O error partway through, or hit its entry cap, the matching symlink could be among "
         "what wasn't read (#4182); or, with no failed read among the wants directories it "
         "actually checked, when /home itself couldn't be fully enumerated, the very set of "
         "user wants directories to search is itself incomplete. Real captures (2026-09-07): "
         "this Mac reports the Linux source through the "
         "foreign-OS stub as lnx_systemd_timers_system|unsupported|0|foreign_os (this build "
         "cannot exercise the leg at all); a real ubuntu:24.04 Docker container read "
         "lnx_systemd_timers_system|unsupported|0|no_systemd -- the container has no init "
         "system at all, so this confirms the absent branch; the rung-2 fallback itself needs a "
         "host with systemd present but its unit dirs unreadable, not exercised here. `absent` "
         "(ENOENT) on /etc/crontab and /etc/anacrontab reports "
         "CONSTRAINED (their absence is itself a real constraint, classify_read_error's "
         "required_by_catalog=true); the same ENOENT on every other file/dir source reports "
         "SUPPORTED (nothing there is a valid, fully-read answer) -- a genuine read failure "
         "(permission_denied or any other errno) always reports CONSTRAINED with that token, "
         "never folded into `absent`. lnx_init_d lists /etc/init.d script names only (no "
         "runlevel/systemctl wiring cross-check) -- CONSTRAINED by design, per-user reads report "
         "owning uid numerically (no NSS/getpwuid_r lookup, no directory-service deadline risk "
         "on this read-only path). lnx_systemd_timers_user is likewise always CONSTRAINED "
         "(narrow_search_path_coverage) when reportable -- the scanned search-path set omits "
         "several standard `systemd --user` unit roots (~/.local/share/systemd/user, "
         "/run/systemd/user, /usr/local/{lib,share}/systemd/user, /usr/share/systemd/user), a "
         "permanent gap, not a transient failure."},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, "
         "/etc/emond.d",
         "File-truth only, rung 1: CFPropertyListCreateWithData over launchd plists (system + "
         "per-user LaunchDaemons/LaunchAgents), /etc/periodic directory listings, and "
         "/etc/emond.d/rules plists. Login Items is CONSTRAINED -- the list lives in a private "
         "per-user BTM database with no public read API; this leg never shells out to "
         "osascript, launchctl, or sfltool. A plist's own Disabled key is read, but launchctl "
         "print-disabled's separate override database is NOT consulted -- this is file truth, "
         "not launchd's live runtime state, a deliberate divergence from a services-style plugin "
         "that does read launchctl state. Real capture on this Mac (2026-09-07): "
         "mac_system_launchdaemons|supported|422, mac_system_launchagents|supported|456, "
         "mac_launchdaemons|supported|2, mac_user_launchagents|supported|1, "
         "mac_launchagents|supported|0, mac_periodic|supported|0, mac_emond|supported|0, "
         "mac_login_items|constrained|0|btm_private_database_no_public_api -- login items "
         "always emits that one constrained status line and zero rows, never a real read "
         "attempt (docs/user-manual/autoruns.md has the full `source|` capture)."},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI "
         "root\\subscription bounded query",
         "Reg*W over HKLM plus every reachable HKU hive via win_profiles.hpp's with_user_hive "
         "ladder (live hive first; offline RegLoadKeyW under SeBackup/SeRestore -- enabled on "
         "the process token for the offline arm only, serialised process-wide by "
         "offline_hive_mutex() -- when the profile is not logged in; unload_failed is surfaced "
         "as a warning line, never dropped, when RegUnLoadKeyW fails on the way out). "
         "ITaskService COM (yuzu::shared::win::ComInit, COINIT_MULTITHREADED, no dedicated STA "
         "thread) and a bounded WMI root\\subscription query, one row per "
         "__FilterToConsumerBinding joined on the ref Name -- a dangling ref still emits its "
         "row, tagged constrained|unresolved_ref, never dropped or collapsed into another "
         "binding's row. A1's the-rig probe (tests/unit/fixtures/wave7/probes/the-rig-probe-"
         "findings.md, 2026-09-06), Probe 3, quoted verbatim for the LocalSystem session: "
         "CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively enumerated "
         "(COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical HRESULTs and counts "
         "-- MTA is not a problem for ITaskService here, including as LocalSystem); WMI "
         "root\\subscription ConnectServer/ExecQuery HRESULT 0x00000000, Next() 0x00000001 "
         "(WBEM_S_FALSE) after exactly 1 binding -- the same stock 'SCM Event Log Filter'/'SCM "
         "Event Log Consumer' binding the admin session saw, confirming LocalSystem reaches "
         "both APIs with no apartment-model or session-identity gap. CoInitializeEx itself "
         "failing is the one COM failure this leg cannot render as a real hr_<hex> token "
         "(ComInit::ok() exposes no HRESULT) -- reported as the fixed sentinel "
         "hr_cominit_failed; every other COM/WMI failure carries the real HRESULT or "
         "wmi_bounded.hpp's error token. Zero spawn primitives: schtasks.exe, wmic.exe and "
         "PowerShell are never invoked. Real-hardware verification: docs/wave7/rig-checklist-"
         "autoruns-win.md's 10-step checklist."},
    },
    {
        /* .action      = */ "catalog",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "file reads of cron/anacron/at/systemd unit dirs/XDG autostart; systemctl list-timers "
         "argv fallback only when no unit dir is readable",
         "Pure reflection of this build's static kSourceCatalog declarations for the Linux "
         "sources above -- no OS call. See the `list` descriptor's note for what those "
         "declarations mean once `list` actually runs each mechanism."},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "CFPropertyListCreateWithData over launchd plists; file reads of /etc/periodic, "
         "/etc/emond.d",
         "Pure reflection of this build's static kSourceCatalog declarations for the macOS "
         "sources above -- no OS call. See the `list` descriptor's note for what those "
         "declarations mean once `list` actually runs each mechanism."},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "Reg*W over HKLM + every HKU via win_profiles with_user_hive; ITaskService COM; WMI "
         "root\\subscription bounded query",
         "Pure reflection of this build's static kSourceCatalog declarations for the Windows "
         "sources above -- no OS call itself, but the same LocalSystem session this build's "
         "ITaskService/WMI mechanism relies on is A1's the-rig probe (tests/unit/fixtures/"
         "wave7/probes/the-rig-probe-findings.md, 2026-09-06), Probe 3, quoted verbatim: "
         "CoInitializeEx/Connect/GetFolder HRESULT 0x00000000, 322 tasks recursively "
         "enumerated (COINIT_MULTITHREADED and COINIT_APARTMENTTHREADED gave identical "
         "HRESULTs and counts); WMI root\\subscription ConnectServer/ExecQuery HRESULT "
         "0x00000000, Next() 0x00000001 (WBEM_S_FALSE) after exactly 1 binding. See the `list` "
         "descriptor's note for the full per-source `list` behaviour this catalog entry "
         "declares support for."},
    },
};

} // namespace

class AutorunsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "autoruns"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Enumerates persistence sources (what starts automatically) across Windows, "
               "Linux and macOS";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "catalog", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        // No exception may escape this function: every leg below eventually
        // calls into untrusted-input parsers and third-party OS APIs, and an
        // uncaught exception crossing the extern "C" plugin-ABI boundary is
        // undefined behaviour, not a clean failure. The int return reflects
        // whether THIS COMMAND completed (0) or aborted (1 -- an exception,
        // or an unknown action); it is NOT the same axis as set_result_status
        // below, which carries whether the DATA this command produced is
        // fully trustworthy. A `list` run that genuinely completes but had
        // one or more sources report CONSTRAINED still returns 0 here --
        // that degradation is set_result_status's job (do_list), not rc's.
        // Only the exception paths below tie the two together (rc=1 always
        // pairs with UNAVAILABLE there).
        try {
            if (action == "catalog") {
                do_catalog(ctx);
                return 0;
            }
            if (action == "list") {
                return do_list(ctx, params.get("sources"));
            }

            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        } catch (const std::exception& e) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "autoruns:exception");
            ctx.write_output(std::string{"error: "} + yuzu::util::safe_output_field(e.what()));
            return 1;
        } catch (...) {
            ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "autoruns:exception");
            ctx.write_output("error: unknown exception");
            return 1;
        }
    }

private:
    static void do_catalog(yuzu::CommandContext& ctx) {
        ctx.write_output(std::string{"catalog|"} +
                         std::to_string(yuzu::autoruns::kAutorunSourceCatalogVersion));
        for (const auto& decl : yuzu::autoruns::kSourceCatalog) {
            ctx.write_output(yuzu::autoruns::format_source_status(
                decl.id, yuzu::autoruns::declared_support_for_host(decl), std::nullopt,
                "declared"));
        }
    }

    static int do_list(yuzu::CommandContext& ctx, std::string_view filter) {
        // All three run unconditionally on every build -- the two that are
        // not this build's own OS resolve to autoruns_legs.hpp's foreign-OS
        // stub, so a `list` capture always names every source in the
        // catalog, the same completeness guarantee `catalog` gives.
        //
        // Each collect_* leg's own return value is non-zero iff it emitted
        // at least one CONSTRAINED `source|` status (never for UNSUPPORTED
        // -- a foreign-OS stub's normal, expected outcome -- and never for
        // plain SUPPORTED); see each leg's own banner. ORing the three
        // together and folding a true result into the typed CC-07 result
        // status is what makes a real per-source acquisition failure
        // visible to a fleet-scale consumer reading only that typed field,
        // not just this leg's many individual `source|` text lines --
        // previously the ONLY set_result_status call this plugin ever made
        // was on the exception path, so a degraded-but-completed `list` run
        // always left the typed result at UNDECLARED.
        const int windows_rc = yuzu::autoruns::collect_windows(ctx, filter);
        const int linux_rc = yuzu::autoruns::collect_linux(ctx, filter);
        const int macos_rc = yuzu::autoruns::collect_macos(ctx, filter);
        if (windows_rc != 0 || linux_rc != 0 || macos_rc != 0) {
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "autoruns:degraded");
        }
        // The list command itself always completes here -- a genuinely
        // degraded-but-completed read is reported via set_result_status
        // above, never by this rc (distinct from execute()'s exception
        // path, the only case that reports autoruns:UNAVAILABLE/rc=1).
        return 0;
    }
};

YUZU_PLUGIN_EXPORT(AutorunsPlugin)
