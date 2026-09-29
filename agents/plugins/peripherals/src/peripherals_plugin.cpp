/**
 * peripherals_plugin.cpp — USB, PCI and Thunderbolt/USB4 bus inventory for
 * Yuzu.
 *
 * Actions:
 *   "usb"         — USB device tree: bus path, VID/PID, class/subclass,
 *                   vendor/product strings, serial, negotiated speed, and
 *                   whether the node is itself a hub.
 *   "pci"         — PCI/PCIe device tree: bus path, VID/DID, class code,
 *                   subsystem VID/DID, bound driver, description.
 *   "thunderbolt" — the bus_inventory fold: one row per Thunderbolt/USB4
 *                   node, host controller or attached device, with
 *                   authorization state where the platform exposes one.
 *
 * SCOPE, decided at Wave 1 planning (P91-1 spec). Three bus-inventory kinds
 * only. displays/bluetooth/audio/camera are PR9.1c, deferred until after
 * this PR merges -- no EDID parser, no .mm, no CoreAudio/AVFoundation here.
 *
 * Wave 2 (P91-4/5/6) replaced every leg's placeholder body with a real
 * SetupAPI/sysfs/IOKit walk (peripherals_{win,linux,macos}.cpp) -- this TU
 * was fully wired from Wave 1 (actions, descriptors, dispatch), so the
 * plugin shape, the capability catalogue and the dispatcher tests were real
 * from the first revision; only the OS reads themselves landed in Wave 2.
 *
 * This TU is portable except for its single dispatch #if, which selects the
 * one host leg to call -- the same shape disk_actions_plugin.cpp's sibling
 * multi-TU plugins use, so a single-OS build never needs to link the other
 * two legs' symbols. All three descriptor legs are declared unconditionally
 * so the capability-matrix generator (#2204) sees a complete, stable shape
 * regardless of which OS built the plugin.
 *
 * Read-only: no action here mutates host state.
 */

#include <yuzu/plugin.hpp>

#include "peripherals_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <string>
#include <string_view>

namespace {

// The nine per-action per-OS legs (three actions x three OSes) are FIXED
// and never wrapped in a preprocessor conditional -- a single-OS build still
// declares the full per-OS shape.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "usb",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/sys/bus/usb/devices sysfs attribute reads", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IOKit IOServiceMatching(IOUSBHostDevice)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "SetupAPI SetupDiGetClassDevsW(USB enumerator) + SPDRP_HARDWAREID/COMPATIBLEIDS",
         nullptr},
    },
    {
        /* .action      = */ "pci",
        /* .linux_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "/sys/bus/pci/devices sysfs attribute reads", nullptr},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IOKit IOServiceMatching(IOPCIDevice)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1, "SetupAPI (PCI enumerator)", nullptr},
    },
    {
        /* .action      = */ "thunderbolt",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1, "/sys/bus/thunderbolt/devices sysfs reads",
         "walk verified against a sysfs fixture tree only; no live Linux venue with a "
         "Thunderbolt bus in this run"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_SUPPORTED, 1, "IOKit IOServiceMatching(IOThunderboltSwitch)", nullptr},
        /* .windows_leg = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "SetupAPI PCI enumerator, DEVICEDESC contains Thunderbolt/USB4",
         "string-heuristic identification; no Thunderbolt device class in SetupAPI"},
    },
};

} // namespace

class PeripheralsPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "peripherals"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "USB, PCI and Thunderbolt/USB4 device inventory";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"usb", "pci", "thunderbolt", nullptr};
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
        const auto kind = yuzu::peripherals::parse_kind(action);
        if (!kind) {
            // `action` is request-supplied and lands in a pipe-delimited stream, so
            // it goes through the shared escaper like any other untrusted field.
            // This is deliberately NOT a row (no leading kind token), which is why
            // it does not use the legs.hpp formatters.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }

        // Every failure-token literal this plugin dir emits matches
        // ^(windows|macos|linux):[a-z0-9_]+(:[a-z0-9_]+)*$ -- Yuzu targets
        // exactly these three OSes (CLAUDE.md "Target architecture"), so
        // there is deliberately no fourth branch here.
#if defined(_WIN32)
        return yuzu::peripherals::run_windows(ctx, *kind);
#elif defined(__linux__)
        return yuzu::peripherals::run_linux(ctx, *kind);
#elif defined(__APPLE__)
        return yuzu::peripherals::run_macos(ctx, *kind);
#endif
        return 1; // unreachable on a supported build (see the comment above); avoids
                  // falling off the end of a non-void function if one ever isn't.
    }
};

YUZU_PLUGIN_EXPORT(PeripheralsPlugin)
