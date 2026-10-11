/**
 * firmware_posture_macos.cpp -- macOS leg: firmware version/vendor from the IODeviceTree plane.
 * Native IOKit (rung 1), no `ioreg`/`system_profiler` shell-out; the node/key selection and the
 * absent-vs-unreadable decisions are pure functions in firmware_posture_parsers.hpp.
 *
 * REAL-HOST PROBE, this Mac 2026-09-21 (Mac16,10 Apple Silicon, macOS 26.6.2), unprivileged
 * uid 501 (`sudo` needs a password in this session, so no root run is recorded; the plane is
 * world-readable and no read here needed a privilege):
 *   IORegistryEntryFromPath("IODeviceTree:/rom")    -> 0: no such node (`ioreg -p IODeviceTree
 *       -n rom` also has no match). The Intel /rom keys are UNVERIFIED on hardware.
 *   IORegistryEntryFromPath("IODeviceTree:/chosen") -> entry. The firmware version is carried by
 *       node IODeviceTree:/chosen, key `system-firmware-version` = "mBoot-18000.161.10" (CFData,
 *       19 bytes incl. NUL); `firmware-version` there is the same text in a 256-byte buffer.
 *   IORegistryEntryFromPath("IODeviceTree:/")       -> entry, `manufacturer` = "Apple Inc.".
 *   sysctlbyname("hw.model") = "Mac16,10"; sysctlbyname("hw.optional.arm64") = 1 (Intel Macs have
 *       no such key: ENOENT).
 * The version is an iBoot tag, not a BIOS date; Apple Silicon has no release date.
 *
 * Every io_object_t is adopted by ScopedIOObject and every property (+1 Create Rule) by
 * ScopedCFRef: no raw IOObjectRelease / CFRelease. IORegistryEntryFromPath has no other in-tree
 * call site (hardware_plugin.cpp uses IOServiceGetMatchingService).
 */

#if defined(__APPLE__)

#include "firmware_posture_legs.hpp"

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <sys/sysctl.h>

#include <cerrno>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>

namespace yuzu::firmware_posture {
namespace {

// Converts one CFData property to text through the pure decoder; false = it exists but is not
// text (wrong CF type or embedded binary).
bool property_text(CFTypeRef v, std::string& out) {
    if (CFGetTypeID(v) == CFDataGetTypeID()) {
        auto d = static_cast<CFDataRef>(v);
        const auto* p = CFDataGetBytePtr(d);
        const auto n = static_cast<std::size_t>(CFDataGetLength(d));
        auto s = decode_dt_string(std::span<const std::uint8_t>(p, n));
        if (!s) return false;
        out = std::move(*s);
        return true;
    }
    return false;
}

DtNode read_node(const char* path, std::initializer_list<const char*> keys) {
    DtNode node;
    yuzu::agent::ScopedIOObject entry(IORegistryEntryFromPath(kIOMainPortDefault, path));
    // Apple's own IOKitLib.h documents IORegistryEntryFromPath's contract as "a handle to the
    // entry ... or MACH_PORT_NULL on failure" -- one return value, no distinct error code, so a
    // node genuinely absent and a transient IOKit-level failure (sandboxing, mach-port
    // exhaustion) are indistinguishable AT THIS CALL. Unlike WMI/SMBIOS, this API surface
    // exposes nothing else to check here -- so this shell only records the raw fact
    // (lookup_failed) and leaves the absent-vs-unreadable decision to select_macos_firmware(),
    // one layer up in the pure core, which resolves it with hw.optional.arm64 as a second signal (only
    // /rom failing on an Apple Silicon Mac is architecturally expected absence; the same
    // absent-vs-unreadable class was fixed as FV-CODEX-01 on the Windows leg).
    if (!entry) {
        node.lookup_failed = true;
        return node;
    }
    for (const char* key : keys) {
        yuzu::agent::ScopedCFRef<CFStringRef> k(
            CFStringCreateWithCString(kCFAllocatorDefault, key, kCFStringEncodingUTF8));
        if (!k) {
            node.undecodable.emplace_back(key);
            continue;
        }
        yuzu::agent::ScopedCFRef<CFTypeRef> prop(
            IORegistryEntryCreateCFProperty(entry.get(), k.get(), kCFAllocatorDefault, 0));
        if (!prop) continue; // key absent on this node
        std::string text;
        if (property_text(prop.get(), text)) node.props.emplace(key, std::move(text));
        else node.undecodable.emplace_back(key);
    }
    return node;
}

Field sysctl_hw_model() {
    Field f;
    std::string buf;
    std::size_t len = 0;
    if (sysctlbyname("hw.model", nullptr, &len, nullptr, 0) == 0 && len > 0) {
        buf.assign(len, '\0');
        if (sysctlbyname("hw.model", buf.data(), &len, nullptr, 0) != 0) buf.clear();
    }
    while (!buf.empty() && buf.back() == '\0') buf.pop_back();
    if (buf.empty()) f.unreadable = true;
    else f.value = std::move(buf);
    return f;
}

// hw.optional.arm64 is an int32 present only on Apple Silicon (Intel Macs have no such key:
// ENOENT = false). Any other failure is nullopt, which select_macos_firmware reads as Intel so
// an unexplained failure is never an expected absence.
std::optional<bool> sysctl_hw_optional_arm64() {
    std::int32_t v = 0;
    std::size_t len = sizeof v;
    if (sysctlbyname("hw.optional.arm64", &v, &len, nullptr, 0) == 0) return v != 0;
    if (errno == ENOENT) return false;
    return std::nullopt;
}

} // namespace

int collect_firmware_macos(yuzu::CommandContext& ctx) {
    FirmwareReport report;
    // Intel Macs: /rom {version, release-date, vendor}. Apple Silicon: no /rom; /chosen
    // {system-firmware-version, firmware-version}; vendor from the device-tree root.
    const DtNode rom = read_node(kDtRom.data(), {"version", "release-date", "vendor"});
    const DtNode chosen =
        read_node(kDtChosen.data(), {"system-firmware-version", "firmware-version"});
    const DtNode root = read_node(kDtRoot.data(), {"manufacturer"});
    const Field model = sysctl_hw_model();
    const std::optional<bool> arm64 = sysctl_hw_optional_arm64();

    report.add_all(macos_rows(select_macos_firmware(rom, chosen, root, arm64), model));
    for (const DtNode* n : {&rom, &chosen, &root})
        for (const auto& k : n->undecodable)
            report.note_failure("iokit:" + k + ":undecodable");
    // A node whose own IORegistryEntryFromPath lookup failed gets its own failure token here,
    // UNLESS that specific node's absence is architecturally expected (only /rom on Apple
    // Silicon) -- same architecture gate select_macos_firmware() uses for the row's `unreadable`
    // flag, so the token and the row state never disagree.
    const bool apple_silicon = arm64.value_or(false);
    struct NodeRef {
        const DtNode* n;
        std::string_view path;
    };
    for (const NodeRef& r :
         {NodeRef{&rom, kDtRom}, NodeRef{&chosen, kDtChosen}, NodeRef{&root, kDtRoot}})
        if (r.n->lookup_failed && !node_absence_is_expected(r.path, apple_silicon))
            report.note_failure("iokit:" + std::string(r.path) + ":lookup_failed");
    if (model.unreadable) report.note_failure("sysctl:hw_model:unreadable");
    if (!arm64) report.note_failure("sysctl:hw_optional_arm64:unreadable");
    return finish_report(ctx, report);
}

} // namespace yuzu::firmware_posture

#endif // __APPLE__
