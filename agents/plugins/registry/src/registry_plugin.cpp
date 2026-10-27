/**
 * registry_plugin.cpp -- Windows Registry plugin for Yuzu (dispatch and capability declarations).
 *
 * The twelve actions are listed in actions() below and documented in README.md. The logic lives in
 * registry_parsers.hpp and registry_plan.hpp (pure) and registry_core.hpp (over an injected registry); registry_win.cpp is the
 * Windows shell. Windows-only: the other platforms answer every action with the honest
 * registry|unsupported|... sentinel below (the macOS plist and Linux dconf legs are PLANNED, not built).
 */

#include <yuzu/plugin.hpp>

#ifndef _WIN32
#include <spdlog/spdlog.h> // the off-Windows catch logs; the Windows leg logs from registry_win.cpp
#endif

#include <algorithm>
#include <iterator>
#include <string>
#include <string_view>
#if defined(YUZU_REGISTRY_UNIT_TEST_INTERNALS_ONLY)
#include <stdexcept>
#endif

#include "registry_core.hpp"

namespace {

// ── ABI4 capability declarations (#2204) ─────────────────────────────────
//
// One row per entry in actions() below, same names/order. The Windows legs are native in-process Win32
// Reg*W (rung 1; the per-user actions add RegLoadKeyW for an offline NTUSER.DAT). macOS and Linux have an
// equivalent store (CFPreferences / dconf) that this plugin does not read or write yet, so those legs
// are PLANNED and every action there answers with the registry|unsupported|... sentinel.
constexpr const char* kPlannedNote = "planned stub: not implemented, the action answers registry|unsupported|...";
constexpr YuzuOsLeg kLinuxPlanned{YUZU_SUPPORT_PLANNED, 2, "dconf/gsettings", kPlannedNote};
constexpr YuzuOsLeg kMacosPlanned{YUZU_SUPPORT_PLANNED, 1, "defaults/CFPreferences (per-domain plist)", kPlannedNote};

const YuzuActionDescriptor kActionDescriptors[] = {
    {"get_value", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"set_value", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"delete_value", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"delete_key", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"key_exists", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"enumerate_keys", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"enumerate_values", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"get_user_value", kLinuxPlanned, kMacosPlanned,
     {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry+hive_mount", nullptr}},
    {"list_profiles", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
    {"set_user_value", kLinuxPlanned, kMacosPlanned,
     {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry+hive_mount", nullptr}},
    {"delete_user_value", kLinuxPlanned, kMacosPlanned,
     {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry+hive_mount", nullptr}},
    {"apply", kLinuxPlanned, kMacosPlanned, {YUZU_SUPPORT_SUPPORTED, 1, "win32_registry", nullptr}},
};

} // namespace

class RegistryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "registry"; }
    std::string_view version() const noexcept override { return "2.1.0"; }
    std::string_view description() const noexcept override {
        return "Windows Registry -- get, set (six types, verified), delete value, delete key (optionally "
               "recursive), enumerate, per-user reads and writes, bulk apply with an undo manifest";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"get_value",       "set_value",        "delete_value",
                                     "delete_key",      "key_exists",       "enumerate_keys",
                                     "enumerate_values", "get_user_value",  "list_profiles",
                                     "set_user_value",  "delete_user_value", "apply", nullptr};
        return acts;
    }

    [[nodiscard]] const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }

    [[nodiscard]] size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext&) override { return {}; }
    void shutdown(yuzu::PluginContext&) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
#ifndef _WIN32
        (void)params;
        // ONE try/catch(...) at the ABI seam, as execute_guarded is on the Windows leg: nothing thrown here (the
        // only throw sites are string allocations) crosses the plugin boundary.
        try {
#if defined(YUZU_REGISTRY_UNIT_TEST_INTERNALS_ONLY)
            // Test-only (the macro is defined by test_registry_write_local_dispatcher.cpp alone): any action whose
            // `name` parameter says so throws, so the catch below is pinned for a mutator (its audit line) and for a
            // read. The real build has no such parameter handling.
            if (params.get("name") == "__throw_std") throw std::runtime_error("registry test: std::exception");
            if (params.get("name") == "__throw_other") throw 42;
#endif
            // Unknown actions are refused BEFORE the platform answer, so a misspelled one is never terminal SUCCESS.
            bool known = false;
            for (const char* const* a = actions(); *a != nullptr; ++a) {
                if (action == *a) { known = true; break; }
            }
            if (!known) {
                ctx.write_output("error|unknown action: " + yuzu::profiles::sanitize_field(action));
                return 1;
            }
            static constexpr std::string_view kMutatingActions[] = {
                "set_value", "delete_value", "delete_key", "set_user_value", "delete_user_value", "apply"};
            const bool is_mutator = std::ranges::find(kMutatingActions, action) != std::end(kMutatingActions);

#if defined(__APPLE__)
            // macOS-specific honest sentinel (points at the real macOS alternative).
            ctx.write_output("registry|unsupported|Windows registry has no macOS equivalent; use defaults/plists");
#else
            // Linux/other: platform-neutral honest sentinel -- do NOT name macOS tools on a Linux agent.
            ctx.write_output("registry|unsupported|Windows registry is not available on this platform");
#endif
            // BR-03: a mutator that touched nothing must never report SUCCESS (rc 1); a read honestly
            // reporting "unsupported" is itself a successful read (rc 0).
            return is_mutator ? 1 : 0;
        } catch (...) {
            yuzu::registry::report_exception(ctx, action); // a mutating action's fixed audit line, then error|exception
            try {
                spdlog::error("registry: {} raised an exception", yuzu::profiles::sanitize_field(action));
            } catch (...) {
            }
            return 1;
        }
#else
        return yuzu::registry::execute_windows(ctx, action, params);
#endif
    }
};

// The guard macro is defined only by tests/unit/test_registry_write_local_dispatcher.cpp, which includes this file
// to drive execute() directly; the test executable carries no C plugin entry point. The real build never defines it.
#if !defined(YUZU_REGISTRY_UNIT_TEST_INTERNALS_ONLY)
YUZU_PLUGIN_EXPORT(RegistryPlugin)
#endif
