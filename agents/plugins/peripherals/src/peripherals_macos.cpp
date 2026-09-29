/**
 * peripherals_macos.cpp — macOS leg entry point.
 *
 * WAVE 2 (P91-6). Walks the real IOKit registry via
 * IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(cls),
 * &it) for the three bus-inventory kinds: IOUSBHostDevice, IOPCIDevice,
 * IOThunderboltSwitch. Every io_object_t (the matching iterator itself and
 * each entry/child it yields) is owned by yuzu::agent::ScopedIOObject
 * (agents/core/include/yuzu/agent/scoped_ioobject.hpp) from the moment
 * IOKit hands it back — no bare IOObjectRelease anywhere in this file.
 * IOServiceOpen is never called: every read here is a property fetch off
 * the matched service, not a user-client connection, so ScopedIOObject's
 * IOObjectRelease deleter is the correct owner (see that header's own
 * banner on why an io_connect_t needs a different owner and this file
 * never creates one).
 *
 * Every IORegistryEntryCreateCFProperty result is likewise owned by
 * yuzu::agent::ScopedCFRef (scoped_cfref.hpp) before its type is even
 * checked, so a type-mismatch/early-return path still releases the +1
 * Create-Rule reference. `io_registry_cf_string` below is copied from
 * hardware_plugin.cpp:123 — the ONLY existing precedent for this shape in
 * the repo (grounding-verified 2026-09-08). `cf_number` and
 * `cf_data_bytes` do NOT exist anywhere in that file (or elsewhere in the
 * repo) — they are NEW local helpers defined here in the same
 * size-then-copy / ScopedCFRef style, needed because IOUSBHostDevice's
 * numeric properties (idVendor, Device Speed, ...) and IOThunderboltSwitch's
 * (UID, Route String, ...) are CFNumber-typed, and IOPCIDevice's vendor-id/
 * device-id/class-code/subsystem-* are raw little-endian CFData blobs
 * peripherals_macos_parsers.hpp's decode_le_u32 decodes.
 *
 * A matching-service call that itself fails (kr != KERN_SUCCESS from
 * IOServiceGetMatchingServices) is a leg-level failure — this Mac's IOKit
 * main port is unreachable, not merely "no devices of this class" — and is
 * reported through mark_result_read's failure_token path as
 * "macos:iokit:matching_failed" (CONSTRAINED/PARTIAL), never as an empty OK.
 * An empty-but-successful iteration (zero matched services) is instead a
 * clean, complete `rows == 0` result — mark_result_read's own `<kind>|none`
 * branch handles that, no failure token involved.
 */
#include "peripherals_legs.hpp"

#if defined(__APPLE__)

#include "peripherals_macos_parsers.hpp"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::peripherals {

namespace {

namespace pmac = yuzu::peripherals::macos;

// ── CF property readers ─────────────────────────────────────────────────
//
// Every reader owns the IORegistryEntryCreateCFProperty +1 Create-Rule
// reference via ScopedCFRef before checking its type, so a type-mismatch or
// early return still releases it.

// Copied from hardware_plugin.cpp:123 (the ONLY existing precedent for this
// shape) — reads a CFStringRef-typed IORegistry property and converts it to
// UTF-8 via the size-then-copy CFStringGetCString idiom.
std::string io_registry_cf_string(io_object_t entry, CFStringRef key) {
    yuzu::agent::ScopedCFRef<CFTypeRef> prop(
        IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0));
    if (!prop || CFGetTypeID(prop.get()) != CFStringGetTypeID())
        return {};
    auto str = static_cast<CFStringRef>(prop.get());
    CFIndex len = CFStringGetLength(str);
    if (len <= 0)
        return {};
    CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string buf(static_cast<std::size_t>(max_size), '\0');
    if (!CFStringGetCString(str, buf.data(), max_size, kCFStringEncodingUTF8))
        return {};
    return std::string(buf.c_str());
}

// NEW (not in hardware_plugin.cpp): reads a CFNumberRef-typed IORegistry
// property as a signed 64-bit value. nullopt when absent or not a number --
// idVendor/idProduct/bDeviceClass/bDeviceSubClass/Device Speed/locationID/
// Route String/UID/Thunderbolt Generation are all CFNumber on every node
// this leg has seen (REAL CAPTURE, tests/unit/fixtures/wave9/peripherals/
// macos/), but a future kext revision omitting one must degrade to "-" /0,
// not crash.
std::optional<std::int64_t> cf_number(io_object_t entry, CFStringRef key) {
    yuzu::agent::ScopedCFRef<CFTypeRef> prop(
        IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0));
    if (!prop || CFGetTypeID(prop.get()) != CFNumberGetTypeID())
        return std::nullopt;
    std::int64_t value = 0;
    if (!CFNumberGetValue(static_cast<CFNumberRef>(prop.get()), kCFNumberSInt64Type, &value))
        return std::nullopt;
    return value;
}

// NEW (not in hardware_plugin.cpp): reads a CFDataRef-typed IORegistry
// property as its raw bytes. IOPCIDevice's vendor-id/device-id/class-code/
// subsystem-vendor-id/subsystem-id are OSData (CFData once bridged through
// IORegistryEntryCreateCFProperty) — decode_le_u32 (peripherals_macos_
// parsers.hpp) turns the result into the u32 the row schema carries.
std::string cf_data_bytes(io_object_t entry, CFStringRef key) {
    yuzu::agent::ScopedCFRef<CFTypeRef> prop(
        IORegistryEntryCreateCFProperty(entry, key, kCFAllocatorDefault, 0));
    if (!prop || CFGetTypeID(prop.get()) != CFDataGetTypeID())
        return {};
    auto data = static_cast<CFDataRef>(prop.get());
    CFIndex len = CFDataGetLength(data);
    if (len <= 0)
        return {};
    std::string out(static_cast<std::size_t>(len), '\0');
    CFDataGetBytes(data, CFRangeMake(0, len), reinterpret_cast<UInt8*>(out.data()));
    return out;
}

// ── matching-service walk ───────────────────────────────────────────────
//
// Owns both the iterator (a ScopedIOObject the whole walk lives inside) and
// every entry it yields (a fresh ScopedIOObject per iteration, released at
// the end of each loop body regardless of what `fn` does). Returns false
// only on a genuine matching-call failure (kr != KERN_SUCCESS) -- an
// empty-but-successful iteration still returns true and simply invokes `fn`
// zero times.
template <typename Fn> bool for_each_service(const char* cls, Fn&& fn) {
    io_iterator_t raw_it = IO_OBJECT_NULL;
    kern_return_t kr =
        IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(cls), &raw_it);
    if (!pmac::matching_succeeded(kr))
        return false;
    yuzu::agent::ScopedIOObject it(raw_it);
    for (io_object_t raw_entry = IOIteratorNext(it.get()); raw_entry != IO_OBJECT_NULL;
         raw_entry = IOIteratorNext(it.get())) {
        yuzu::agent::ScopedIOObject entry(raw_entry);
        fn(entry.get());
    }
    return true;
}

// The child entry's IOObjectClass in the service plane, or "-" when this
// node has no child (a leaf device) or the lookup fails. `pci`'s `driver`
// row field.
std::string child_class_name(io_object_t entry) {
    io_registry_entry_t raw_child = IO_OBJECT_NULL;
    if (IORegistryEntryGetChildEntry(entry, kIOServicePlane, &raw_child) != KERN_SUCCESS)
        return "-";
    yuzu::agent::ScopedIOObject child(raw_child);
    io_name_t name{};
    if (IOObjectGetClass(child.get(), name) != KERN_SUCCESS || name[0] == '\0')
        return "-";
    return std::string(name);
}

// ── per-kind walks ───────────────────────────────────────────────────────

// IOUSBHostDevice: the modern class name (see peripherals_plugin.cpp's own
// descriptor comment) -- binds Apple's current USB host stack, not the
// legacy IOUSBDevice family.
bool walk_usb(std::vector<std::string>& rows) {
    return for_each_service("IOUSBHostDevice", [&](io_object_t entry) {
        const auto vendor_id = cf_number(entry, CFSTR("idVendor")).value_or(0);
        const auto product_id = cf_number(entry, CFSTR("idProduct")).value_or(0);
        const auto usb_class = cf_number(entry, CFSTR("bDeviceClass")).value_or(0);
        const auto subclass = cf_number(entry, CFSTR("bDeviceSubClass")).value_or(0);
        const auto location = cf_number(entry, CFSTR("locationID")).value_or(0);
        const auto speed = cf_number(entry, CFSTR("Device Speed"));
        const auto vendor = io_registry_cf_string(entry, CFSTR("USB Vendor Name"));
        const auto product = io_registry_cf_string(entry, CFSTR("USB Product Name"));
        const auto serial = io_registry_cf_string(entry, CFSTR("USB Serial Number"));
        const auto bus_path = std::format("{:08x}", static_cast<std::uint32_t>(location));
        // Keep the optional end-to-end: an absent property is the row schema's
        // "-" unread sentinel, not the out-of-range numeric text usb_speed_name
        // renders for a present-but-unrecognized value (those are two distinct
        // cases -- see that function's own doc comment).
        const std::string speed_text = speed.has_value() ? pmac::usb_speed_name(*speed) : "-";
        rows.push_back(format_usb_row(
            bus_path, static_cast<std::uint16_t>(vendor_id), static_cast<std::uint16_t>(product_id),
            static_cast<std::uint8_t>(usb_class), static_cast<std::uint8_t>(subclass), vendor,
            product, serial, speed_text, usb_class == 9));
    });
}

bool walk_pci(std::vector<std::string>& rows) {
    return for_each_service("IOPCIDevice", [&](io_object_t entry) {
        const auto vendor_id = pmac::decode_le_u32(cf_data_bytes(entry, CFSTR("vendor-id")));
        const auto device_id = pmac::decode_le_u32(cf_data_bytes(entry, CFSTR("device-id")));
        const auto class_code = pmac::decode_le_u32(cf_data_bytes(entry, CFSTR("class-code")));
        const auto subsystem_vendor =
            pmac::decode_le_u32(cf_data_bytes(entry, CFSTR("subsystem-vendor-id")));
        const auto subsystem_device =
            pmac::decode_le_u32(cf_data_bytes(entry, CFSTR("subsystem-id")));
        const auto io_name = io_registry_cf_string(entry, CFSTR("IOName"));
        const auto pcidebug = io_registry_cf_string(entry, CFSTR("pcidebug"));
        const std::string bus_path = pcidebug.empty() ? "-" : pcidebug;
        rows.push_back(format_pci_row(bus_path, static_cast<std::uint16_t>(vendor_id),
                                      static_cast<std::uint16_t>(device_id), class_code,
                                      static_cast<std::uint16_t>(subsystem_vendor),
                                      static_cast<std::uint16_t>(subsystem_device),
                                      child_class_name(entry), io_name));
    });
}

bool walk_thunderbolt(std::vector<std::string>& rows) {
    return for_each_service("IOThunderboltSwitch", [&](io_object_t entry) {
        const auto vendor = io_registry_cf_string(entry, CFSTR("Device Vendor Name"));
        const auto model = io_registry_cf_string(entry, CFSTR("Device Model Name"));
        const auto uid = cf_number(entry, CFSTR("UID"));
        const auto route = cf_number(entry, CFSTR("Route String")).value_or(0);
        const auto generation = cf_number(entry, CFSTR("Thunderbolt Generation"));
        const auto role =
            route == 0 ? ThunderboltRole::HostController : ThunderboltRole::Device;
        const std::string path = std::format("{:x}", static_cast<std::uint64_t>(route));
        const std::string unique_id =
            uid.has_value() ? pmac::uid_to_hex16(static_cast<std::uint64_t>(*uid)) : "-";
        const std::string gen = generation.has_value() ? std::to_string(*generation) : "-";
        rows.push_back(format_thunderbolt_row(path, role, vendor, model, unique_id, gen, "-"));
    });
}

} // namespace

int run_macos(yuzu::CommandContext& ctx, Kind k) {
    std::vector<std::string> rows;
    bool matched = false;
    switch (k) {
    case Kind::usb:         matched = walk_usb(rows); break;
    case Kind::pci:         matched = walk_pci(rows); break;
    case Kind::thunderbolt: matched = walk_thunderbolt(rows); break;
    }
    if (!matched) {
        mark_result_read(ctx, k, 0, "macos:iokit:matching_failed");
        return 0;
    }
    for (const auto& row : rows)
        ctx.write_output(row);
    mark_result_read(ctx, k, rows.size(), std::nullopt);
    return 0;
}

} // namespace yuzu::peripherals

#endif // defined(__APPLE__)
