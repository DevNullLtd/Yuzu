/**
 * runtimes_plugin.cpp -- installed language-runtime inventory for Yuzu:
 * .NET and JVM. A software-inventory fact read from the runtime's own install
 * tree, so under its roots it also sees runtimes no package manager owns; installed_apps
 * lists the packaged-application view.
 *
 * Actions:
 *   "dotnet" -- installed .NET (Core/5+) runtimes and SDKs.
 *   "jvm"    -- installed JVMs: version, JDK/JRE image type, vendor
 *               (e.g. Eclipse Adoptium vs Debian OpenJDK vs Oracle).
 *
 * Wire rows (runtimes_parsers.hpp): a `status|<action>|...` row first, then
 * `<action>|<flavour>|<version>|<install_path>|<vendor or ->` data rows.
 *
 * ZERO SUBPROCESS. Every fact is a directory name or a metadata file read
 * (rung 1); no `java` or `dotnet` process is ever started.
 *
 * SHIPPED LEGS. Linux only. The macOS and Windows legs are declared PLANNED
 * in the table below (the mechanism string names the planned read); until
 * they ship they report `status|<action>|unsupported|<macos|windows>:planned`.
 *
 * This TU is portable except for its single dispatch #if, which selects the
 * one host leg to call -- so a single-OS build never links the other two
 * legs' symbols. All six descriptor legs are declared unconditionally so
 * the capability-matrix generator (#2204) sees a complete, stable shape.
 *
 * Read-only: no action here mutates host state.
 */

#include <yuzu/plugin.hpp>

#include "runtimes_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The six per-action per-OS legs (two actions x three OSes) are FIXED and
// never wrapped in a preprocessor conditional.
constexpr const char* kPlannedNote = "planned; the action answers a single unsupported status row on this OS";

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "dotnet",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "/usr/share/dotnet, /usr/lib/dotnet, /usr/lib64/dotnet shared/<framework>/<version> "
         "and sdk/<version> directory walk; network mounts skipped via /proc/self/mountinfo",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1, "/usr/local/share/dotnet/shared walk", kPlannedNote},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1,
         "NDP release-key table + dotnet InstalledVersions + Program Files walk", kPlannedNote},
    },
    {
        /* .action      = */ "jvm",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "<home>/release file reads under /usr/lib/jvm, /opt/java, /usr/lib64/jvm, /var/opt/java "
         "(bin/java probe when a home has no release); network mounts skipped via "
         "/proc/self/mountinfo",
         nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1,
         "/Library/Java/JavaVirtualMachines/*/Contents/Info.plist JavaVM dict + "
         "Contents/Home/release",
         kPlannedNote},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1, "JavaSoft keys + Program Files\\Java walk", kPlannedNote},
    },
};

} // namespace

class RuntimesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "runtimes"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Installed .NET and JVM runtime inventory";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"dotnet", "jvm", nullptr};
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

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        const auto a = yuzu::runtimes::parse_action(action);
        // No exception may cross the plugin ABI on any leg: the whole body, the
        // unknown-action diagnostic included, runs inside the try.
        try {
            if (!a) {
                // `action` is request-supplied and lands in a pipe-delimited stream, so
                // it goes through the shared escaper. Deliberately NOT a row.
                ctx.write_output(std::string{"unknown action: "} +
                                 yuzu::util::safe_output_field(action));
                return 1;
            }
            // Leg failure tokens match ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$;
            // the catch-all's `internal_error` is the one OS-neutral token. Yuzu targets
            // exactly these three OSes, so there is deliberately no fourth branch.
#if defined(_WIN32)
            return yuzu::runtimes::run_windows(ctx, *a);
#elif defined(__linux__)
            return yuzu::runtimes::run_linux(ctx, *a);
#elif defined(__APPLE__)
            return yuzu::runtimes::run_macos(ctx, *a);
#endif
        } catch (...) {
            if (!a) return 1; // the refusal diagnostic itself failed; rc 1 still reports it
            ctx.write_output(yuzu::runtimes::format_status_row(
                yuzu::runtimes::action_name(*a), yuzu::runtimes::StatusLevel::constrained,
                "internal_error"));
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "internal_error");
            return 1; // a genuine internal failure is a failed command (siblings; agent.cpp maps rc != 0 to FAILURE)
        }
        return 1; // unreachable on a supported build; avoids falling off a non-void function.
    }
};

YUZU_PLUGIN_EXPORT(RuntimesPlugin)
