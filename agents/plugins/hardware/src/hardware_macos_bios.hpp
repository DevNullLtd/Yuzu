#pragma once

// hardware_macos_bios.hpp — pure parser for macOS `system_profiler
// SPHardwareDataType` plain-text output, extracting the Boot ROM / System
// Firmware Version line for the "bios" action's macOS leg (do_bios() in
// hardware_plugin.cpp).
//
// Apple's own field label differs by Mac generation: Intel Macs (and older
// firmware) report "Boot ROM Version:"; Apple Silicon reports "System
// Firmware Version:" instead — the label was never kept consistent across
// the transition. The pre-Wave-3 implementation grepped only "Boot ROM" and
// silently emitted "unknown" on every Apple Silicon Mac; this parser checks
// both labels (Boot ROM Version first, to match legacy output byte-for-byte
// wherever it's still present).
//
// Platform-agnostic and header-only so it compiles and its unit tests run on
// every host, matching the hardware_disks_macos.hpp / dex_macos_*.hpp
// precedent, even though it is only ever invoked from the __APPLE__ branch
// of the plugin.

#include <string>
#include <string_view>

namespace yuzu::hardware::macos {

// Extracts the value after "Boot ROM Version:" or "System Firmware Version:"
// from `system_profiler SPHardwareDataType` plain-text output. Returns "" if
// neither label is present.
inline std::string parse_boot_rom_version(std::string_view text) {
    static constexpr std::string_view kLabels[] = {
        "Boot ROM Version:",
        "System Firmware Version:",
    };
    for (auto label : kLabels) {
        auto pos = text.find(label);
        if (pos == std::string_view::npos)
            continue;
        auto val_start = text.find_first_not_of(" \t", pos + label.size());
        if (val_start == std::string_view::npos)
            continue;
        auto val_end = text.find_first_of("\r\n", val_start);
        auto val = text.substr(val_start, val_end == std::string_view::npos
                                               ? std::string_view::npos
                                               : val_end - val_start);
        if (!val.empty())
            return std::string(val);
    }
    return {};
}

} // namespace yuzu::hardware::macos
