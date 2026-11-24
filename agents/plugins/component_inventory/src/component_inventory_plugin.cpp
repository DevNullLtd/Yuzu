/**
 * component_inventory_plugin.cpp -- installed software components found by reading application
 * trees: Java archives (.jar/.war/.ear) and the libraries nested inside them, the versioned
 * shared libraries (ELF .so, Mach-O .dylib, PE .dll) shipped inside applications, and the Python
 * distributions and Node packages installed outside a package manager. A software-inventory fact read
 * from the files themselves, so it sees components no package manager owns.
 *
 * Actions (none takes a parameter; the roots come from the OS leg and from nothing a request can
 * supply):
 *   "scan"   -- Java archives. Roots: scan_targets(); on Windows the WindowsApps tree under each root is
 *               excluded and counted.
 *   "native" -- shared libraries (ELF .so, Mach-O .dylib, PE .dll), capped at 5,000 rows. Roots:
 *               scan_native_targets(); package-owned trees are excluded and counted. The server
 *               refuses it until an operator switches it on (an action-level kill-switch row seeded
 *               off at boot). Publishes no heartbeat keys: scan already uses 6 of the 8 a plugin may
 *               publish.
 *   "python" -- Python distributions: the METADATA of a `.dist-info`, the PKG-INFO of an `.egg-info`,
 *               first 16 KiB only. Roots: scan_python_targets(). Package source trees are pruned by
 *               design (component_pkg_scan.hpp); the count is logged, never a status token. Not on
 *               Windows: planned there.
 *   "node"   -- Node packages: the package.json of each package under node_modules, 64 KiB cap. Roots:
 *               scan_node_targets(). Pruned the same way. Neither publishes heartbeat keys. Not on
 *               Windows: planned there.
 *
 * Wire rows (component_scan.hpp): exactly one leading `status|<action>|<level>|<tokens or ->` row,
 * then `comp|<java|native|python|node>|name|version|version_source|path|size|mtime|anchor_app` rows.
 *
 * COMPLETENESS. Level supported and typed result OK/FULL only when the scan finished: no bound was
 * reached and every directory and archive it opened was read in full (a link or network mount it
 * passed over on purpose is named by an informational token on the status row). Any budget,
 * unreadable or truncated directory, archive that could not be enumerated or
 * archive that changed while read answers constrained and CONSTRAINED/PARTIAL with the cause as a
 * `<os>:component_inventory:<cause>` token. The rows that were reachable are written at both levels.
 *
 * SHIPPED LEGS. Linux and macOS (machine roots only), and Windows for `scan` and `native` (the two Program
 * Files trees on fixed drives, through a filesystem binding that follows no reparse point;
 * component_fs_win.cpp). The Windows leg is declared SUPPORTED on the measured scope (one
 * host, Windows 11 build 26200, elevated administrator session; docs/samples/windows.txt) and answers
 * constrained when a directory is refused or a bound is reached; the Windows leg of `python` and `node` is a later change and answers through the
 * shared planned-leg reporter. All three descriptor legs are declared unconditionally so
 * the capability-matrix generator sees a complete, stable shape.
 *
 * ZERO SUBPROCESS, READ-ONLY. Nothing here mutates the host; the only write is the plugin's own
 * heartbeat KV keys (the cost of the last `scan`).
 */

#include <yuzu/plugin.hpp>

#include <planned_leg.hpp> // yuzu::shared::report_planned (agents/shared)

#include <yuzu/string_utils.hpp>

#include "component_native_scan.hpp" // portable: the native answer
#include "component_pkg_scan.hpp"    // portable: the python and node answers
#include "component_scan.hpp"        // portable: the answer, its emission and the catch-all's answer

#if defined(_WIN32)
#include "component_legs_win.hpp"
#else
#include "component_legs.hpp"
#endif

#include <spdlog/spdlog.h>

#include <algorithm>
#include <functional>
#include <string>
#include <string_view>

namespace {

// The internal_error token is a literal per OS: the catch-all must answer without allocating
// outside its own guarded calls.
#if defined(_WIN32)
constexpr std::string_view kOs = "windows";
constexpr std::string_view kInternalError = "windows:component_inventory:internal_error";
#elif defined(__linux__)
constexpr std::string_view kOs = "linux";
constexpr std::string_view kInternalError = "linux:component_inventory:internal_error";
#elif defined(__APPLE__)
constexpr std::string_view kOs = "macos";
constexpr std::string_view kInternalError = "macos:component_inventory:internal_error";
#else
#error "component_inventory_plugin.cpp: unsupported host OS"
#endif

// The literal above is hand-typed per OS: it must be exactly <os>:component_inventory:internal_error.
static_assert(kInternalError.starts_with(kOs) &&
              kInternalError.substr(kOs.size()) == ":component_inventory:internal_error");

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "scan",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of /opt, /usr/share/java, /usr/lib/jvm, /usr/local/lib, "
         "/usr/local/share and /usr/share/maven; no link followed at any path component; archive "
         "central directory, pom.properties and MANIFEST.MF read in-process; network mounts skipped "
         "via /proc/<pid>/mountinfo",
         "Java archives only; machine roots only (per-user installs are not read); any budget, "
         "unreadable directory or unenumerable archive answers constrained"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of /Applications, /Library/Java, /usr/local and /opt/homebrew; no "
         "link followed at any path component; archive central directory, pom.properties and "
         "MANIFEST.MF read in-process; network mounts skipped via getmntinfo_r_np",
         "Java archives only; machine roots only (per-user installs are not read); any budget, "
         "unreadable directory or unenumerable archive answers constrained"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of the Program Files and Program Files (x86) directories (the shell's "
         "known-folder paths, fixed drives only); every directory and file opened relative to its volume "
         "root with no reparse point followed at any path component (NtCreateFile, OBJ_DONT_REPARSE); "
         "archive central directory, pom.properties and MANIFEST.MF read in-process; WindowsApps under "
         "each root excluded and counted",
         "measured on one host (Windows 11 build 26200, elevated administrator session), where a "
         "system directory whose access list excludes Administrators was refused and the action "
         "answered constrained (dir_unreadable); Java archives only; machine roots only (per-user "
         "installs are not read); a reparse point is counted and never read; any budget, unreadable "
         "directory or unenumerable archive answers constrained"},
    },
    {
        /* .action      = */ "native",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of /opt and /usr/local/lib for .so and .so.<version> files, at most "
         "5,000 rows; no link followed at any path component; the ELF program headers, dynamic "
         "section and SONAME read in-process within fixed bounds; network mounts skipped via "
         "/proc/<pid>/mountinfo",
         "versioned shared libraries inside applications only: package-owned trees (/usr/lib and "
         "friends) are not walked; machine roots only; the server refuses it until an operator "
         "switches it on; any budget, unreadable directory or changed file answers constrained"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of /Applications, /usr/local and /opt/homebrew for .dylib files, at "
         "most 5,000 rows; no link followed at any path component; the Mach-O header, load commands "
         "and LC_ID_DYLIB (thin, fat or fat64) read in-process within fixed bounds; /usr/local/Cellar "
         "and /opt/homebrew/Cellar excluded and counted; network mounts skipped via getmntinfo_r_np",
         "versioned dynamic libraries inside applications only: extension-less framework binaries "
         "are not read; machine roots only; the server refuses it until an operator switches it on; "
         "any budget, unreadable directory or changed file answers constrained"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of the Program Files and Program Files (x86) directories for .dll files, "
         "at most 5,000 rows; every directory and file opened relative to its volume root with no reparse "
         "point followed at any path component (NtCreateFile, OBJ_DONT_REPARSE); the PE fixed file "
         "version read in-process within fixed bounds; WindowsApps under each root excluded and counted",
         "measured on one host (Windows 11 build 26200, elevated administrator session), where a "
         "system directory whose access list excludes Administrators was refused and the 5,000-row cap "
         "was reached, so the action answered constrained; libraries inside applications only; machine "
         "roots only; the server refuses it until an operator switches it on; a reparse point is counted "
         "and never read; any budget, unreadable directory or changed file answers constrained"},
    },
    {
        /* .action      = */ "python",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of the python3 and python3.<digits> directories under /usr/local/lib "
         "and of /opt for METADATA, PKG-INFO and .egg-info files, the first 16 KiB of each read "
         "in-process; package source trees inside site-packages are not listed; no link followed at "
         "any path component; network mounts skipped via /proc/<pid>/mountinfo",
         "Python distributions installed outside the package manager only (/usr/lib is not walked); "
         "machine roots only (per-user installs are not read); any budget, unreadable directory or "
         "changed file answers constrained"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of /Library/Frameworks/Python.framework/Versions and of the "
         "python3.<digits> directories under /opt/homebrew/lib and /usr/local/lib for METADATA, "
         "PKG-INFO and .egg-info files, the first 16 KiB of each read in-process; package source "
         "trees inside site-packages are not listed; no link followed at any path component; network "
         "mounts skipped via getmntinfo_r_np",
         "Python distributions in those library directories only; machine roots only (per-user "
         "installs are not read); any budget, unreadable directory or changed file answers "
         "constrained"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1, "bounded walk of the Python install roots with the same metadata reads",
         "not read yet: one unsupported status row, windows:planned"},
    },
    {
        /* .action      = */ "node",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of /usr/lib/node_modules, /usr/local/lib/node_modules and /opt for "
         "the package.json of each package under node_modules, at most 64 KiB read in-process; a "
         "package's own source tree is not listed; no link followed at any path component; network "
         "mounts skipped via /proc/<pid>/mountinfo",
         "Node packages under those roots only; machine roots only (per-user installs are not read); "
         "a package.json that is too large or not a JSON object is a row with an unreadable version; "
         "any budget, unreadable directory or changed file answers constrained"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "bounded read-only walk of /opt/homebrew/lib/node_modules, /usr/local/lib/node_modules and "
         "/Applications for the package.json of each package under node_modules, at most 64 KiB read "
         "in-process; a package's own source tree is not listed; no link followed at any path "
         "component; network mounts skipped via getmntinfo_r_np",
         "Node packages under those roots only; machine roots only (per-user installs are not read); "
         "a package.json that is too large or not a JSON object is a row with an unreadable version; "
         "any budget, unreadable directory or changed file answers constrained"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1, "bounded walk of the Node install roots with the same package.json reads",
         "not read yet: one unsupported status row, windows:planned"},
    },
};

// The native action's per-OS parts: which names are candidates, how a file is read, which trees are
// the package manager's. Chosen at compile time, like kOs.
#if defined(_WIN32)
constexpr auto kNativeCandidate = &yuzu::component_inventory::is_windows_native_candidate;
const yuzu::component_inventory::NativeParse kNativeParse = yuzu::component_inventory::describe_windows_file;
#elif defined(__APPLE__)
constexpr auto kNativeCandidate = &yuzu::component_inventory::is_macos_native_candidate;
const yuzu::component_inventory::NativeParse kNativeParse = yuzu::component_inventory::describe_macos_file;
#else
constexpr auto kNativeCandidate = &yuzu::component_inventory::is_linux_native_candidate;
const yuzu::component_inventory::NativeParse kNativeParse = yuzu::component_inventory::describe_linux_file;
#endif

// The scan's walk reads Java archives (the default candidate test). Only the Windows scan excludes a
// tree today; the Linux and macOS scan walk excludes nothing, as before.
yuzu::component_inventory::WalkPolicy scan_policy([[maybe_unused]] const yuzu::component_inventory::Targets& t) {
    yuzu::component_inventory::WalkPolicy p;
#if defined(_WIN32)
    p = yuzu::component_inventory::windows_walk_policy(t); // WindowsApps kept out and counted
#endif
    return p;
}

yuzu::component_inventory::WalkPolicy native_policy([[maybe_unused]] const yuzu::component_inventory::Targets& t) {
#if defined(_WIN32)
    yuzu::component_inventory::WalkPolicy p = yuzu::component_inventory::windows_walk_policy(t);
#else
    yuzu::component_inventory::WalkPolicy p;
    p.skip_dir = [excluded = yuzu::component_inventory::native_excluded_dirs()](const std::string& dir) {
        return std::ranges::find(excluded, dir) != excluded.end();
    };
#endif
    p.is_candidate = kNativeCandidate;
    return p;
}

} // namespace

class ComponentInventoryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "component_inventory"; }
    std::string_view version() const noexcept override { return "1.2.0"; }
    std::string_view description() const noexcept override {
        return "Installed software components found in application trees (Java archives, native libraries, "
               "Python distributions, Node packages)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan", "native", "python", "node", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        plugin_ctx_ = ctx.raw();
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override { plugin_ctx_ = nullptr; }

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        // No exception may cross the plugin ABI: the whole body runs inside the try.
        namespace ci = yuzu::component_inventory;
        bool wrote = false;
        // The action the catch-all answers for; a constant, never the request-supplied text.
        const std::string_view answered = action == ci::kNativeAction   ? ci::kNativeAction
                                          : action == ci::kPythonAction ? ci::kPythonAction
                                          : action == ci::kNodeAction   ? ci::kNodeAction
                                                                        : ci::kScanAction;
        try {
            if (action != ci::kScanAction && action != ci::kNativeAction && action != ci::kPythonAction &&
                action != ci::kNodeAction) {
                // `action` is request-supplied and lands in a pipe-delimited stream, so it goes
                // through the shared escaper. Deliberately NOT a row.
                ctx.write_output(std::string{"unknown action: "} + yuzu::util::safe_output_field(action));
                return 1;
            }
            const auto make_fs = [](const ci::Targets& x) { return ci::make_fs_ops(x); };
#if defined(_WIN32)
            // The Windows leg of python and node is a later change (#8440): the planned row, never a walk.
            if (action == ci::kPythonAction || action == ci::kNodeAction)
                return yuzu::shared::report_planned(ctx, answered);
#else
            // Pruning package source trees is the design of python and node, not a gap: the count is
            // logged once per dispatch and never reaches the status row.
            const auto log_pruned = [](std::string_view act, std::size_t pruned) {
                spdlog::info("component_inventory: {} pruned {} package-internal directories by design", act, pruned);
            };
            if (action == ci::kPythonAction || action == ci::kNodeAction) {
                // No heartbeat keys, as for native.
                const bool py = action == ci::kPythonAction;
                const ci::Answer a = py ? ci::answer_python(kOs, ci::scan_python_targets(), make_fs, log_pruned)
                                        : ci::answer_node(kOs, ci::scan_node_targets(), make_fs, log_pruned);
                ci::emit_answer(ctx, static_cast<yuzu::PluginContext*>(nullptr), a, wrote);
                return 0;
            }
#endif
            if (action == ci::kNativeAction) {
                // No heartbeat keys: scan already uses 6 of the 8 a plugin may publish.
                const ci::Targets nt = ci::scan_native_targets();
                const ci::Answer a = ci::answer_native(kOs, nt, make_fs, ci::native_limits(), native_policy(nt),
                                                       kNativeParse);
                ci::emit_answer(ctx, static_cast<yuzu::PluginContext*>(nullptr), a, wrote);
                return 0;
            }
            const ci::Targets t = ci::scan_targets();
            const ci::Answer a = ci::answer_scan(kOs, t, make_fs, ci::WalkLimits{}, scan_policy(t));
            // The cost of this scan, published by the agent as yuzu.plugin.component_inventory.* tags.
            yuzu::PluginContext pctx{plugin_ctx_};
            ci::emit_answer(ctx, plugin_ctx_ != nullptr ? &pctx : nullptr, a, wrote);
            return 0; // a degraded read is never a failed command
        } catch (...) {
            ci::answer_internal_error(ctx, kInternalError, wrote, answered);
            return 1; // a genuine internal failure is a failed command
        }
    }

private:
    YuzuPluginContext* plugin_ctx_{nullptr};
};

YUZU_PLUGIN_EXPORT(ComponentInventoryPlugin)
