/**
 * component_inventory_plugin.cpp -- installed software components found by reading application
 * trees: Java archives (.jar/.war/.ear) and the libraries nested inside them, and the versioned
 * shared libraries (ELF .so, Mach-O .dylib) shipped inside applications. A software-inventory fact
 * read from the files themselves, so it sees components no package manager owns.
 *
 * Actions (neither takes a parameter; the roots come from the OS leg and from nothing a request can
 * supply):
 *   "scan"   -- Java archives. Roots: scan_targets().
 *   "native" -- shared libraries, capped at 5,000 rows. Roots: scan_native_targets(); package-owned
 *               trees are excluded and counted. The server refuses it until an operator switches it
 *               on (an action-level kill-switch row seeded off at boot). Publishes no heartbeat keys:
 *               scan already uses 6 of the 8 a plugin may publish.
 *
 * Wire rows (component_scan.hpp): exactly one leading `status|<action>|<level>|<tokens or ->` row,
 * then `comp|<java|native>|name|version|version_source|path|size|mtime|anchor_app` rows.
 *
 * COMPLETENESS. Level supported and typed result OK/FULL only when the scan finished: no bound was
 * reached and every directory and archive it opened was read in full (a link or network mount it
 * passed over on purpose is named by an informational token on the status row). Any budget,
 * unreadable or truncated directory, archive that could not be enumerated or
 * archive that changed while read answers constrained and CONSTRAINED/PARTIAL with the cause as a
 * `<os>:component_inventory:<cause>` token. The rows that were reachable are written at both levels.
 *
 * SHIPPED LEGS. Linux and macOS (machine roots only). The Windows leg of both actions is a later change
 * and answers through the shared planned-leg reporter. All three descriptor legs are declared unconditionally so
 * the capability-matrix generator sees a complete, stable shape.
 *
 * ZERO SUBPROCESS, READ-ONLY. Nothing here mutates the host; the only write is the plugin's own
 * heartbeat KV keys (the cost of the last `scan`).
 */

#include <yuzu/plugin.hpp>

#include <planned_leg.hpp> // yuzu::shared::report_planned (agents/shared)

#include <yuzu/string_utils.hpp>

#include "component_native_scan.hpp" // portable: the native answer
#include "component_scan.hpp"        // portable: the answer, its emission and the catch-all's answer

#if !defined(_WIN32)
#include "component_legs.hpp"
#endif

#include <algorithm>
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
        {YUZU_SUPPORT_PLANNED, 1, "bounded Program Files walk with the same archive reads",
         "not read yet: one unsupported status row, windows:planned"},
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
        {YUZU_SUPPORT_PLANNED, 1, "bounded Program Files walk with the same library reads",
         "not read yet: one unsupported status row, windows:planned"},
    },
};

#if !defined(_WIN32)
// The native action's per-OS parts: which names are candidates, how a file is read, which trees are
// the package manager's. Chosen at compile time, like kOs.
#if defined(__APPLE__)
constexpr auto kNativeCandidate = &yuzu::component_inventory::is_macos_native_candidate;
const yuzu::component_inventory::NativeParse kNativeParse = yuzu::component_inventory::describe_macos_file;
#else
constexpr auto kNativeCandidate = &yuzu::component_inventory::is_linux_native_candidate;
const yuzu::component_inventory::NativeParse kNativeParse = yuzu::component_inventory::describe_linux_file;
#endif

yuzu::component_inventory::WalkPolicy native_policy() {
    yuzu::component_inventory::WalkPolicy p;
    p.is_candidate = kNativeCandidate;
    p.skip_dir = [excluded = yuzu::component_inventory::native_excluded_dirs()](const std::string& dir) {
        return std::ranges::find(excluded, dir) != excluded.end();
    };
    return p;
}
#endif

} // namespace

class ComponentInventoryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "component_inventory"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Installed software components found in application trees (Java archives, native libraries)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan", "native", nullptr};
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
        const std::string_view answered = action == ci::kNativeAction ? ci::kNativeAction : ci::kScanAction;
        try {
            if (action != ci::kScanAction && action != ci::kNativeAction) {
                // `action` is request-supplied and lands in a pipe-delimited stream, so it goes
                // through the shared escaper. Deliberately NOT a row.
                ctx.write_output(std::string{"unknown action: "} + yuzu::util::safe_output_field(action));
                return 1;
            }
#if defined(_WIN32)
            return yuzu::shared::report_planned(ctx, answered);
#else
            const auto make_fs = [](const ci::Targets& x) { return ci::make_fs_ops(x); };
            if (action == ci::kNativeAction) {
                // No heartbeat keys: scan already uses 6 of the 8 a plugin may publish.
                const ci::Answer a = ci::answer_native(kOs, ci::scan_native_targets(), make_fs, ci::native_limits(),
                                                       native_policy(), kNativeParse);
                ci::emit_answer(ctx, static_cast<yuzu::PluginContext*>(nullptr), a, wrote);
                return 0;
            }
            const ci::Targets t = ci::scan_targets();
            const ci::Answer a = ci::answer_scan(kOs, t, make_fs, ci::WalkLimits{});
            // The cost of this scan, published by the agent as yuzu.plugin.component_inventory.* tags.
            yuzu::PluginContext pctx{plugin_ctx_};
            ci::emit_answer(ctx, plugin_ctx_ != nullptr ? &pctx : nullptr, a, wrote);
            return 0; // a degraded read is never a failed command
#endif
        } catch (...) {
            ci::answer_internal_error(ctx, kInternalError, wrote, answered);
            return 1; // a genuine internal failure is a failed command
        }
    }

private:
    YuzuPluginContext* plugin_ctx_{nullptr};
};

YUZU_PLUGIN_EXPORT(ComponentInventoryPlugin)
