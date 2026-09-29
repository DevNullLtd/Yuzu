/**
 * power_health_macos.mm — Objective-C++ macOS boundary for power_health's
 * battery and thermal legs. Second Objective-C++ (`.mm`) translation unit in
 * the tree, following wifi_corewlan.mm's shape (docs/native-objcpp-
 * conventions.md) — Foundation (NSProcessInfo) and IOKit (IOPSCopyPower-
 * SourcesInfo/IOPSCopyPowerSourcesList, IOPMGetThermalWarningLevel) are both
 * public frameworks in the base macOS SDK, present with the Command Line
 * Tools SDK. Built with `-fobjc-arc`.
 *
 * Battery: IOPSCopyPowerSourcesInfo/IOPSCopyPowerSourcesList — deliberately
 * NEVER the AppleSmartBattery IORegistry node (Alex ruling). Every value
 * read comes from the public IOPSKeys.h vocabulary.
 *
 * Thermal: NSProcessInfo.thermalState is the primary (4-level, never
 * degrees) signal; IOPMGetThermalWarningLevel supplements it, with
 * kIOReturnNotFound (measured: `pmset -g therm` → "No thermal warning level
 * has been recorded" on an idle host, 2026-09-04) mapped to "not found",
 * never an error.
 *
 * The dictionary/array types (CFDictionaryRef, CFArrayRef) returned by the
 * IOPS calls are CoreFoundation, not ARC-managed — ScopedCFRef
 * (agents/core/include/yuzu/agent/scoped_cfref.hpp) owns their release
 * exactly once, exception-safely, per docs/native-objcpp-conventions.md.
 */

#import <Foundation/Foundation.h>
#import <IOKit/ps/IOPSKeys.h>
#import <IOKit/ps/IOPowerSources.h>
#import <IOKit/pwr_mgt/IOPMLib.h>

#include <yuzu/agent/scoped_cfref.hpp>

#include "power_health_parsers.hpp"

namespace yuzu::power_health::macos_native {

namespace {

std::optional<int> cf_number_to_int(CFTypeRef ref) {
    if (ref == nullptr || CFGetTypeID(ref) != CFNumberGetTypeID())
        return std::nullopt;
    int value = 0;
    if (!CFNumberGetValue(static_cast<CFNumberRef>(ref), kCFNumberIntType, &value))
        return std::nullopt;
    return value;
}

std::optional<bool> cf_bool_to_bool(CFTypeRef ref) {
    if (ref == nullptr || CFGetTypeID(ref) != CFBooleanGetTypeID())
        return std::nullopt;
    return CFBooleanGetValue(static_cast<CFBooleanRef>(ref)) != false;
}

std::optional<std::string> cf_string_to_std(CFTypeRef ref) {
    if (ref == nullptr || CFGetTypeID(ref) != CFStringGetTypeID())
        return std::nullopt;
    auto* s = static_cast<CFStringRef>(ref);
    const char* fast = CFStringGetCStringPtr(s, kCFStringEncodingUTF8);
    if (fast != nullptr)
        return std::string(fast);
    const CFIndex len = CFStringGetLength(s);
    const CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::vector<char> buf(static_cast<std::size_t>(max_size));
    if (!CFStringGetCString(s, buf.data(), max_size, kCFStringEncodingUTF8))
        return std::nullopt;
    return std::string(buf.data());
}

} // namespace

std::vector<IopsSourceView> query_battery_sources() {
    std::vector<IopsSourceView> out;

    yuzu::agent::ScopedCFRef<CFTypeRef> blob(IOPSCopyPowerSourcesInfo());
    if (!blob)
        return out; // honest empty — no fabricated source

    yuzu::agent::ScopedCFRef<CFArrayRef> list(IOPSCopyPowerSourcesList(blob.get()));
    if (!list)
        return out;

    const CFIndex count = CFArrayGetCount(list.get());
    for (CFIndex i = 0; i < count; ++i) {
        CFTypeRef source = CFArrayGetValueAtIndex(list.get(), i);
        // IOPSGetPowerSourceDescription returns a dictionary NOT owned by
        // the caller (it's a reference into `blob`) — no release here.
        CFDictionaryRef desc = IOPSGetPowerSourceDescription(blob.get(), source);
        if (desc == nullptr)
            continue;

        IopsSourceView v;
        v.present = cf_bool_to_bool(CFDictionaryGetValue(desc, CFSTR(kIOPSIsPresentKey))).value_or(false);
        v.is_charging =
            cf_bool_to_bool(CFDictionaryGetValue(desc, CFSTR(kIOPSIsChargingKey))).value_or(false);

        // kIOPSACPowerValue is itself a CFSTR("AC Power") macro, not a C
        // string, so compare against the literal it expands to rather than
        // trying to compare a std::string against a CFStringRef directly.
        const auto state = cf_string_to_std(CFDictionaryGetValue(desc, CFSTR(kIOPSPowerSourceStateKey)));
        v.is_ac_power = state.has_value() && *state == "AC Power";

        v.current_capacity =
            cf_number_to_int(CFDictionaryGetValue(desc, CFSTR(kIOPSCurrentCapacityKey))).value_or(-1);
        v.max_capacity =
            cf_number_to_int(CFDictionaryGetValue(desc, CFSTR(kIOPSMaxCapacityKey))).value_or(-1);

        auto tte = cf_number_to_int(CFDictionaryGetValue(desc, CFSTR(kIOPSTimeToEmptyKey)));
        // kIOPSTimeRemainingUnknown is -1.0 (a double sentinel); the int
        // read above already lands on -1 for that case, so no extra
        // translation is needed.
        v.time_to_empty_min = tte.value_or(-1);

        out.push_back(v);
    }
    return out;
}

void query_thermal(long& ns_thermal_state, bool& iopm_found, int32_t& iopm_warning_level) {
    @autoreleasepool {
        ns_thermal_state = static_cast<long>([[NSProcessInfo processInfo] thermalState]);
    }

    UInt32 level = 0;
    const IOReturn ret = IOPMGetThermalWarningLevel(&level);
    if (ret == kIOReturnNotFound) {
        // Measured normal case (no thermal event ever recorded) — honest
        // "not found", never treated as an error.
        iopm_found = false;
        iopm_warning_level = 0;
        return;
    }
    if (ret != kIOReturnSuccess) {
        iopm_found = false;
        iopm_warning_level = 0;
        return;
    }
    iopm_found = true;
    iopm_warning_level = static_cast<int32_t>(level);
}

} // namespace yuzu::power_health::macos_native
