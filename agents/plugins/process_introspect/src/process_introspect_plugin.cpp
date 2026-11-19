/**
 * process_introspect_plugin.cpp -- read-only introspection of ONE process.
 *
 * "inspect" -- one numeric pid and one closed-enum facet per dispatch: resource_limits,
 * sigmasks, caps, seccomp, oom, sched (Linux; macOS and Windows are PLANNED). Numbers, masks and
 * fixed tokens only: never file or memory contents, environment values, socket payloads or
 * command-line arguments. One action covers every facet; data above that tier is a NEW action,
 * never a new facet.
 *
 * Portable except the single dispatch #if selecting the leg (`kLeg`, `kLegExceptionToken`);
 * all three descriptor legs are declared unconditionally for the capability-matrix generator.
 */

#include <yuzu/plugin.hpp>

#include "process_introspect_legs.hpp"

#include <planned_leg.hpp>

#include <string_view>

namespace {

const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "inspect",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "bounded reads of /proc/<pid>/{stat,status,limits,oom_score,oom_score_adj} through one "
         "directory descriptor opened once per dispatch",
         "constrained: six facets (resource_limits, sigmasks, caps, seccomp, oom, sched), one "
         "facet per dispatch; numbers, masks and fixed tokens only; a supplied start_time that "
         "no longer matches is refused as pid_reused and a process that changed during the read "
         "as torn_read; on a /proc mounted with hidepid 2 or above another account's process "
         "answers no_such_process_or_hidden (the mount table is read only when the pid is not "
         "found); a thread id reads that thread; an exec during the read is not detected"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_PLANNED, 1, "libproc proc_pidinfo, no task port",
         "not read yet: one unsupported status row, macos:planned"},
        /* .windows_leg = */
        {YUZU_SUPPORT_PLANNED, 1, "NtQueryInformationProcess and toolhelp snapshots",
         "not read yet: one unsupported status row, windows:planned"},
    },
};

// This build's leg and its exception token, defined together. macOS and Windows answer
// `planned` through the shared reporter.
#if defined(__linux__)
constexpr yuzu::process_introspect::LegFn kLeg = &yuzu::process_introspect::run_linux;
constexpr const char* kLegExceptionToken = "linux:leg:exception";
#elif defined(_WIN32) || defined(__APPLE__)
int run_planned(yuzu::CommandContext& ctx, const yuzu::process_introspect::Request&) {
    return yuzu::shared::report_planned(ctx, "inspect");
}
constexpr yuzu::process_introspect::LegFn kLeg = &run_planned;
#if defined(_WIN32)
constexpr const char* kLegExceptionToken = "windows:leg:exception";
#else
constexpr const char* kLegExceptionToken = "macos:leg:exception";
#endif
#else
#error "process_introspect: unsupported platform"
#endif

} // namespace

class ProcessIntrospectPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "process_introspect"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Per-process introspection of one pid, one facet per request: resource limits, "
               "signal masks, capabilities, seccomp, OOM and scheduling; numbers and masks only";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"inspect", nullptr};
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
        return yuzu::process_introspect::execute_inspect(ctx, action, params.get("pid"),
                                                         params.get("facet"),
                                                         params.get("start_time"), kLeg,
                                                         kLegExceptionToken);
    }
};

YUZU_PLUGIN_EXPORT(ProcessIntrospectPlugin)
