/**
 * component_inventory_plugin.cpp -- installed software components found by reading application
 * trees: Java archives (.jar/.war/.ear) and the libraries nested inside them. A software-inventory
 * fact read from the files themselves, so it sees components no package manager owns.
 *
 * Action:
 *   "scan" -- no parameters. The roots come from the OS leg (scan_targets) and from nothing a
 *             request can supply.
 *
 * Wire rows (component_scan.hpp): exactly one leading `status|scan|<level>|<tokens or ->` row, then
 * `comp|java|name|version|version_source|path|size|mtime|anchor_app` rows.
 *
 * COMPLETENESS. Level supported and typed result OK/FULL only when the scan finished: no bound was
 * reached and every directory and archive it opened was read in full (a link or network mount it
 * passed over on purpose is named by an informational token on the status row). Any budget,
 * unreadable or truncated directory, archive that could not be enumerated or
 * archive that changed while read answers constrained and CONSTRAINED/PARTIAL with the cause as a
 * `<os>:component_inventory:<cause>` token. The rows that were reachable are written at both levels.
 *
 * SHIPPED LEGS. Linux and macOS (machine roots only). The Windows leg is a later change and answers
 * through the shared planned-leg reporter. All three descriptor legs are declared unconditionally so
 * the capability-matrix generator sees a complete, stable shape.
 *
 * ZERO SUBPROCESS, READ-ONLY. Nothing here mutates the host; the only write is the plugin's own
 * heartbeat KV keys (the cost of the last scan).
 */

#include <yuzu/plugin.hpp>

#include <planned_leg.hpp> // yuzu::shared::report_planned (agents/shared)

#include <yuzu/string_utils.hpp>

#include "component_scan.hpp" // portable: the answer, its emission and the catch-all's answer

#if !defined(_WIN32)
#include "component_legs.hpp"
#endif

#include <string>
#include <string_view>

namespace {

// The internal_error token is a literal per OS: the catch-all must answer without allocating
// outside its own guarded calls.
#if defined(_WIN32)
[[maybe_unused]] constexpr std::string_view kOs = "windows"; // the planned leg names no os token itself
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

constexpr std::string_view kAction = yuzu::component_inventory::kScanAction;

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
};

} // namespace

class ComponentInventoryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "component_inventory"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Installed software components found in application trees (Java archives)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"scan", nullptr};
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
        bool wrote = false;
        try {
            if (action != kAction) {
                // `action` is request-supplied and lands in a pipe-delimited stream, so it goes
                // through the shared escaper. Deliberately NOT a row.
                ctx.write_output(std::string{"unknown action: "} + yuzu::util::safe_output_field(action));
                return 1;
            }
#if defined(_WIN32)
            return yuzu::shared::report_planned(ctx, kAction);
#else
            namespace ci = yuzu::component_inventory;
            const ci::Targets t = ci::scan_targets();
            const ci::Answer a = ci::answer_scan(
                kOs, t, [](const ci::Targets& x) { return ci::make_fs_ops(x); }, ci::WalkLimits{});
            // The cost of this scan, published by the agent as yuzu.plugin.component_inventory.* tags.
            yuzu::PluginContext pctx{plugin_ctx_};
            ci::emit_answer(ctx, plugin_ctx_ != nullptr ? &pctx : nullptr, a, wrote);
            return 0; // a degraded read is never a failed command
#endif
        } catch (...) {
            yuzu::component_inventory::answer_internal_error(ctx, kInternalError, wrote);
            return 1; // a genuine internal failure is a failed command
        }
    }

private:
    YuzuPluginContext* plugin_ctx_{nullptr};
};

YUZU_PLUGIN_EXPORT(ComponentInventoryPlugin)
