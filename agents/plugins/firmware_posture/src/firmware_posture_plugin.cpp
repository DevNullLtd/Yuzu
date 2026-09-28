/**
 * firmware_posture_plugin.cpp -- firmware/BIOS vendor, version and update-pending posture.
 *
 * Action "firmware": rows `firmware|<field>|<value>|<source>` (source: smbios wmi dmi fwupd iokit
 * sysctl). Read-only. Portable except for the single dispatch #if selecting the host leg
 * (firmware_posture_{win,linux,macos}.cpp); every descriptor leg is declared on every build. The
 * one try/catch in execute() contains any exception from any leg (frozen-seam rule).
 *
 * WHY caveat (roadmap PR8.4): there is no standalone documented driver for this plugin; it shares
 * only the roadmap Issue 18.6 "Hardware Attestation" sourcing, whose own justification is a
 * generic "commonly demanded" line. It reports a device-inventory / patch-compliance fact, not
 * boot integrity.
 */

#include <yuzu/plugin.hpp>

#include "firmware_posture_legs.hpp"

#include <yuzu/string_utils.hpp>

#include <exception>
#include <string>
#include <string_view>

namespace {

// Descriptor legs are FIXED, never preprocessor-conditional; support is declared from evidence.
const YuzuActionDescriptor kActionDescriptors[] = {
    {
        /* .action      = */ "firmware",
        /* .linux_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "/sys/class/dmi/id/{bios_vendor,bios_version,bios_date,bios_release} + fwupd "
         "org.freedesktop.fwupd GetDevices/GetUpgrades over the sd-bus system bus",
         "the fwupd leg needs libsystemd at build time (a system dependency, never vcpkg); "
         "without it update_pending reads unreadable with the fwupd:not_built token and the sysfs "
         "rows remain. Hosts without "
         "DMI (containers, some VMs) report the DMI fields absent and a reachable system bus "
         "with no fwupd daemon reports update_pending unavailable: neither is a failure. A "
         "system bus that cannot be opened (a container without the bus socket) reads "
         "update_pending unreadable with fwupd:bus_open:<errno> and the action CONSTRAINED (or "
         "PERMISSION_DENIED when the connect is refused). The populated-DMI shape is not "
         "captured from a physical Linux host"},
        /* .macos_leg   = */
        {YUZU_SUPPORT_CONSTRAINED, 1,
         "IOKit IORegistryEntryFromPath IODeviceTree:/rom then IODeviceTree:/chosen, "
         "IORegistryEntryCreateCFProperty under ScopedIOObject/ScopedCFRef, plus sysctlbyname "
         "hw.model",
         "verified on Apple Silicon only (Mac16,10, macOS 26.6.2): there IODeviceTree:/rom "
         "does not exist and the version is IODeviceTree:/chosen system-firmware-version "
         "(an iBoot tag such as mBoot-18000.161.10, not a BIOS date); the Intel /rom "
         "version/release-date/vendor keys are UNVERIFIED on hardware. release_date reads "
         "absent on Apple Silicon and update_pending is not reported"},
        /* .windows_leg = */
        {YUZU_SUPPORT_SUPPORTED, 1,
         "WMI Win32_BIOS via wmi_bounded run_bounded_wmi_query + GetSystemFirmwareTable('RSMB') "
         "SMBIOS type 0",
         nullptr},
    },
};

} // namespace

class FirmwarePosturePlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "firmware_posture"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Reports firmware/BIOS vendor, version, release date and update-pending posture";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"firmware", nullptr};
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

    // No exception may escape (the ABI trampoline has no catch): ONE handler covers every leg.
    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params /*params*/) override {
        try {
            if (action == "firmware") {
#if defined(_WIN32)
                return yuzu::firmware_posture::collect_firmware_win(ctx);
#elif defined(__linux__)
                return yuzu::firmware_posture::collect_firmware_linux(ctx);
#elif defined(__APPLE__)
                return yuzu::firmware_posture::collect_firmware_macos(ctx);
#else
                return 1;
#endif
            }
            // `action` is request-supplied and lands in a pipe-delimited stream.
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        } catch (...) {
            ctx.write_output(yuzu::firmware_posture::format_internal_error_row());
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "internal_error");
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(FirmwarePosturePlugin)
