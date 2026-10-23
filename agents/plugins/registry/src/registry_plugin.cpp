/**
 * registry_plugin.cpp -- Windows Registry plugin for Yuzu (dispatch and capability declarations).
 *
 * The nine actions are listed in actions() below and documented in README.md. The logic lives in
 * registry_parsers.hpp (pure) and registry_core.hpp (over an injected registry); registry_win.cpp is the
 * Windows shell. Windows-only: the other platforms answer every action with the honest
 * registry|unsupported|... sentinel below (the macOS plist and Linux dconf legs are PLANNED, not built).
 */

#include <yuzu/plugin.hpp>

#include <algorithm>
#include <iterator>
#include <string>
#include <string_view>

#include "registry_core.hpp"

namespace {

// ── ABI4 capability declarations (#2204) ─────────────────────────────────
//
// One row per entry in actions() below, same names/order. The Windows legs are native in-process Win32
// Reg*W (rung 1; get_user_value adds RegLoadKeyW for an offline NTUSER.DAT). macOS and Linux have an
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
};

} // namespace

class RegistryPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "registry"; }
    std::string_view version() const noexcept override { return "2.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows Registry -- get, set (six types, verified), delete value, delete key, "
               "enumerate, per-user reads";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"get_value",       "set_value",      "delete_value",
                                     "delete_key",      "key_exists",     "enumerate_keys",
                                     "enumerate_values", "get_user_value", "list_profiles", nullptr};
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
            // Unknown actions are refused BEFORE the platform answer, so a misspelled one is never terminal SUCCESS.
            bool known = false;
            for (const char* const* a = actions(); *a != nullptr; ++a) {
                if (action == *a) { known = true; break; }
            }
            if (!known) {
                ctx.write_output("error|unknown action: " + yuzu::profiles::sanitize_field(action));
                return 1;
            }
            static constexpr std::string_view kMutatingActions[] = {"set_value", "delete_value", "delete_key"};
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
            try {
                ctx.write_output("error|exception");
            } catch (...) {
            }
            return 1;
        }
#else
        return yuzu::registry::execute_windows(ctx, action, params);
#endif
    }
};

YUZU_PLUGIN_EXPORT(RegistryPlugin)
