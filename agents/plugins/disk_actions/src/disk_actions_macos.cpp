/**
 * disk_actions_macos.cpp — macOS leg entry points.
 *
 * MECHANISM, bound by spike on 2026-09-03 against this host's real hardware
 * (Apple Silicon, APPLE SSD AP0512Z): IOKit `IOBlockStorageDevice` matching,
 * reading `kIOPropertyDeviceCharacteristicsKey` for identity and the
 * `NVMe SMART Capable` property for capability. Rung 1, no subprocess, and it
 * works UNPRIVILEGED (measured at euid 501).
 *
 * WHY HEALTH IS NOT REPORTED HERE, and why that is CONSTRAINED rather than a
 * gap to be quietly filled later. The wear, available-spare and
 * critical-warning attributes live behind Apple's `IONVMeSMARTUserClient`,
 * whose selector interface is PRIVATE and undocumented. The spike confirmed
 * `IOServiceOpen` on the block device succeeds unprivileged (kr=0) and that a
 * selector exists (one returns kIOReturnNotPrivileged, others
 * kIOReturnBadArgument) -- so the door is there, but reaching the data means
 * reverse-engineering a call convention that Apple may change in any release.
 * ALEX RULING: not adopted. Building a shipped capability on an undocumented
 * interface is the same class of dependency as the dead
 * FSCTL_SRV_ENUMERATE_SNAPSHOTS this plugin's sibling had to be rescued from.
 * Health therefore reports `unknown` -- which is a true statement about what
 * this leg read -- and never `ok`, which would be a guess.
 *
 * OWNERSHIP. Every CF and IOKit object goes through ScopedCFRef / ScopedIOObject.
 * Note the documented trap those wrappers carry: ScopedIOObject must NOT wrap an
 * io_connect_t from IOServiceOpen (that needs IOServiceClose, and
 * IOObjectRelease leaves the user client instantiated in the kernel). This file
 * opens no user client at all, so the trap is not reachable here -- stated so a
 * future edit that adds one does not rediscover it.
 */

#if defined(__APPLE__)

#include "disk_actions_legs.hpp"
#include "disk_actions_parsers.hpp" // the shared degradation-precedence decision

#include <yuzu/agent/scoped_cfref.hpp>
#include <yuzu/agent/scoped_ioobject.hpp>

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOBSD.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDevice.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/storage/IOStorageDeviceCharacteristics.h>

#include <sys/mount.h>

#include <cstdlib> // std::free — owns getmntinfo_r_np's caller-owned allocation
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::disk_actions {

namespace {

using yuzu::agent::ScopedCFRef;
using yuzu::agent::ScopedIOObject;

/// Bounds the provider walk. The measured chain is 7 hops; this is generous
/// headroom without trusting an unbounded registry to terminate.
constexpr int kMaxProviderDepth = 16;

/// CFString -> UTF-8. Returns empty on any non-string or conversion failure;
/// the caller decides what an absent value means, since "" and "-" are
/// different facts at the row layer.
std::string cf_string(CFTypeRef v) {
    if (!v || CFGetTypeID(v) != CFStringGetTypeID()) return {};
    CFStringRef s = static_cast<CFStringRef>(v);
    // CFStringGetLength is in UTF-16 units; ask for the real UTF-8 bound.
    const CFIndex max =
        CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
    if (max <= 0) return {};
    std::string out(static_cast<std::size_t>(max), '\0');
    if (!CFStringGetCString(s, out.data(), max, kCFStringEncodingUTF8)) return {};
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
}

bool cf_bool_true(CFTypeRef v) {
    return v && CFGetTypeID(v) == CFBooleanGetTypeID() && CFBooleanGetValue(static_cast<CFBooleanRef>(v));
}

/// Trim the trailing padding IOKit product strings carry (the spike observed
/// "Virtual Disk    " shapes on other platforms and Apple pads similarly).
std::string trim_right(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    return s;
}

/// Media type from the device-characteristics dictionary. Absent is `unknown`,
/// never a guess -- a spinning-vs-solid claim drives capacity decisions.
Media media_from_characteristics(CFDictionaryRef dc) {
    if (!dc) return Media::Unknown;
    const std::string medium =
        cf_string(CFDictionaryGetValue(dc, CFSTR(kIOPropertyMediumTypeKey)));
    if (medium == kIOPropertyMediumTypeSolidStateKey) return Media::Ssd;
    if (medium == kIOPropertyMediumTypeRotationalKey) return Media::Hdd;
    return Media::Unknown;
}

/// Transport, derived from the IOKit class name rather than parsed text. The
/// spike saw IOEmbeddedNVMeBlockDevice for the internal SSD and
/// IODiskImageBlockStorageDeviceOutKernel for a mounted disk image; the latter
/// is `virtual`, which matters because reporting a disk image as a real drive
/// would put a phantom device in a fleet health view.
Bus bus_from_class(std::string_view cls) {
    if (cls.find("NVMe") != std::string_view::npos) return Bus::Nvme;
    if (cls.find("DiskImage") != std::string_view::npos) return Bus::Virtual;
    if (cls.find("USB") != std::string_view::npos) return Bus::Usb;
    if (cls.find("SAS") != std::string_view::npos) return Bus::Sas;
    if (cls.find("ATA") != std::string_view::npos) return Bus::Sata;
    return Bus::Unknown;
}

/// Mount points reachable today, keyed by BSD device name (e.g. "disk0s2").
/// MNT_NOWAIT for the same reason filesystem_posture uses it: a synchronous
/// enumeration can block on an unreachable network mount, and this runs on a
/// bounded dispatch-pool worker.
///
/// THIS USES getmntinfo_r_np, NOT getmntinfo, AND THE DIFFERENCE IS A BUG FIX.
/// Adversarial review (2026-09-04, both external reviewers independently) found
/// the original `getmntinfo` call here racing on a concurrent worker:
///
///   * `getmntinfo(3)` returns a PROCESS-OWNED STATIC buffer, and `man 3
///     getmntinfo` states a later call may OVERWRITE OR FREE it. It is not
///     thread-safe. This function held that pointer across its whole parse
///     loop.
///   * Plugin actions genuinely run concurrently: `execute()` is invoked from
///     inside the dispatch-pool submit lambda (agent.cpp:3480) on a pool sized
///     std::thread::hardware_concurrency() (agent.cpp:1139), and plugin_loader
///     holds no execution mutex. So `disk_actions.volumes` can overlap
///     `filesystem_posture.mounts` — another getmntinfo caller in ANOTHER dylib.
///   * Consequence: torn statfs records corrupt the physical-to-logical join
///     this action exists to produce, and a realloc between the two calls turns
///     the loop below into a freed-heap read.
///
/// COPYING THE SIBLING'S MUTEX WOULD NOT HAVE FIXED IT. filesystem_posture
/// guards its own calls with a function-local `static std::mutex`
/// (filesystem_posture_macos.cpp:65-93), but that mutex is private to THAT
/// dylib — a second copy here would serialize disk_actions against itself and
/// still race filesystem_posture. `getmntinfo_r_np` (macOS 10.13+) sidesteps
/// the shared buffer entirely by handing the CALLER its own allocation, so the
/// race closes one-sidedly with no cross-dylib coordination to maintain.
struct MountInfo {
    std::vector<std::string> mount_points;
    std::string fstype; ///< F6: a declared column that no leg used to fill
};

std::map<std::string, MountInfo> mount_points_by_bsd_name(bool& ok) {
    std::map<std::string, MountInfo> out;
    struct statfs* mnts = nullptr;
    const int n = ::getmntinfo_r_np(&mnts, MNT_NOWAIT);
    // The allocation is OURS. Adopt it before anything can return, so no exit
    // path leaks it; free(nullptr) is a no-op, so the failure case is safe too.
    const std::unique_ptr<struct statfs, decltype(&std::free)> owned{mnts, &std::free};
    ok = n > 0;
    if (!ok) return out;
    for (int i = 0; i < n; ++i) {
        std::string from = mnts[i].f_mntfromname;
        // "/dev/disk0s2" -> "disk0s2"; anything not under /dev/ is not a
        // block device we can join on (network mounts, synthetic roots).
        constexpr std::string_view kDev = "/dev/";
        if (from.rfind(kDev, 0) != 0) continue;
        auto& info = out[from.substr(kDev.size())];
        info.mount_points.push_back(mnts[i].f_mntonname);
        if (info.fstype.empty()) info.fstype = mnts[i].f_fstypename;
    }
    return out;
}

/// The PHYSICAL whole disk backing an IOMedia object, resolved by walking the
/// IOKit provider chain rather than by trimming the BSD name.
///
/// The string shortcut ("disk3s1" -> "disk3") is WRONG on APFS and was caught
/// by running the leg rather than reading it: on this Mac `/` lives on
/// disk3s1s1, whose "Part of Whole" is disk3 -- but disk3 is a SYNTHESIZED
/// AppleAPFSMedia container whose physical store is disk0s2, on the real drive
/// disk0. Trimming the name therefore stops at a virtual container and never
/// reaches the physical device, which is the one thing this action exists to
/// report: a failing drive must be nameable in terms of the volumes it serves.
///
/// The provider chain resolves it exactly (measured):
///   AppleAPFSVolume disk3s1 -> AppleAPFSContainer -> AppleAPFSMedia disk3
///     -> AppleAPFSContainerScheme -> IOMedia disk0s2 -> IOGUIDPartitionScheme
///     -> IOMedia disk0 (Whole=YES)   <-- the answer
///
/// So: walk providers to the first entry that is an IOMedia AND is marked
/// whole. The class test is load-bearing -- AppleAPFSMedia also reports
/// Whole=YES, and accepting it would return the synthesized container again.
std::string physical_whole_disk_of(io_registry_entry_t media) {
    io_registry_entry_t node = media;
    ScopedIOObject owned; // owns only the nodes WE step onto, never the caller's
    for (int depth = 0; depth < kMaxProviderDepth && node; ++depth) {
        io_name_t cls{};
        IOObjectGetClass(node, cls);
        ScopedCFRef<CFTypeRef> whole{
            IORegistryEntryCreateCFProperty(node, CFSTR(kIOMediaWholeKey), kCFAllocatorDefault, 0)};
        if (std::string_view(cls) == kIOMediaClass && cf_bool_true(whole.get())) {
            ScopedCFRef<CFTypeRef> bsd{IORegistryEntryCreateCFProperty(node, CFSTR(kIOBSDNameKey),
                                                                      kCFAllocatorDefault, 0)};
            return cf_string(bsd.get());
        }
        io_registry_entry_t parent = 0;
        if (IORegistryEntryGetParentEntry(node, kIOServicePlane, &parent) != KERN_SUCCESS) break;
        owned.reset(parent); // releases the previous step, adopts this one
        node = parent;
    }
    return {};
}

} // namespace

int emit_smart(yuzu::CommandContext& ctx) {
    io_iterator_t raw_it{};
    if (IOServiceGetMatchingServices(kIOMainPortDefault,
                                     IOServiceMatching(kIOBlockStorageDeviceClass),
                                     &raw_it) != KERN_SUCCESS) {
        write_smart_row(ctx, "-", "-", Bus::Unknown, Media::Unknown, Health::Unknown, std::nullopt,
                        std::nullopt, "IOServiceGetMatchingServices failed");
        mark_result_partial(ctx, "macos:iokit", "IOServiceGetMatchingServices failed");
        return 0;
    }
    ScopedIOObject it{raw_it};

    bool any_row = false;
    bool any_device_unresolved = false;
    for (io_object_t raw_obj; (raw_obj = IOIteratorNext(it.get()));) {
        ScopedIOObject obj{raw_obj};

        io_name_t cls{};
        IOObjectGetClass(obj.get(), cls);

        ScopedCFRef<CFTypeRef> dc{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR(kIOPropertyDeviceCharacteristicsKey), kCFAllocatorDefault, 0)};
        CFDictionaryRef dict = (dc.get() && CFGetTypeID(dc.get()) == CFDictionaryGetTypeID())
                                   ? static_cast<CFDictionaryRef>(dc.get())
                                   : nullptr;

        const std::string model =
            dict ? trim_right(cf_string(CFDictionaryGetValue(dict, CFSTR(kIOPropertyProductNameKey))))
                 : std::string{};

        // IORegistryEntrySearchCFProperty, NOT IORegistryEntryCreateCFProperty.
        // The BSD name lives on the CHILD IOMedia, not on the
        // IOBlockStorageDevice itself, so the lookup has to search the plane.
        // Create's fourth parameter is `IOOptionBits options`, documented as
        // having no options defined -- passing kIORegistryIterateRecursively
        // there is silently ignored, and the earlier revision of this line did
        // exactly that. Measured on this Mac: every smart row's device column
        // came back "-". Caught by the standards reviewer reading the API
        // contract; the runtime dump that would have shown it had only been
        // taken for the volumes action.
        ScopedCFRef<CFTypeRef> bsd{IORegistryEntrySearchCFProperty(
            obj.get(), kIOServicePlane, CFSTR(kIOBSDNameKey), kCFAllocatorDefault,
            kIORegistryIterateRecursively)};
        const std::string device = cf_string(bsd.get());

        ScopedCFRef<CFTypeRef> nvme_smart{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR("NVMe SMART Capable"), kCFAllocatorDefault, 0)};
        ScopedCFRef<CFTypeRef> ata_smart{IORegistryEntryCreateCFProperty(
            obj.get(), CFSTR("SMART Capable"), kCFAllocatorDefault, 0)};
        const bool smart_capable = cf_bool_true(nvme_smart.get()) || cf_bool_true(ata_smart.get());

        // Health is deliberately Unknown on every device: see the file banner.
        // The detail column is where the honest explanation goes, and it
        // distinguishes "the device advertises SMART but we do not read it"
        // from "the device advertises nothing".
        const char* detail =
            smart_capable
                ? "device advertises SMART; health attributes are not read on macOS (they require "
                  "Apple's private IONVMeSMARTUserClient interface)"
                : "device does not advertise SMART capability";

        // An IOBlockStorageDevice with no IOMedia child (an empty card reader or
        // optical bay) resolves no BSD name. That is a device we could not
        // identify, not a device named "-", and it needs the seam like any
        // other unresolved read.
        if (device.empty()) any_device_unresolved = true;

        write_smart_row(ctx, device.empty() ? "-" : device, model.empty() ? "-" : model,
                        bus_from_class(cls), media_from_characteristics(dict), Health::Unknown,
                        std::nullopt, std::nullopt, detail);
        any_row = true;
    }

    if (!any_row)
        // `unsupported`, not `unknown`, so the placeholder is not schema-
        // identical to a real device row.
        write_smart_row(ctx, "-", "-", Bus::Unknown, Media::Unknown, Health::Unsupported,
                        std::nullopt, std::nullopt, "no block storage devices found");

    // PRECEDENCE comes from the pure layer. This leg previously hand-ordered
    // its marks, which contradicted the header's own "and NOWHERE ELSE" claim
    // and left the last hand-ordered chain in the plugin -- exactly the drift
    // that produced the earlier defect.
    //
    // The health constraint is TRUE ON EVERY RUN, so it is the weakest cause
    // here: mapping it to ItemDetailUnread lets any real degradation outrank it
    // rather than being overwritten by a constant.
    DegradationFlags flags;
    flags.item_detail_unread = true; // health is never read on this platform
    flags.identity_unread = any_device_unresolved;
    flags.empty_result = !any_row;

    if (const auto cause = summarise_degradation(flags)) {
        switch (*cause) {
        case DegradationKind::EmptyResult:
            mark_result_unavailable(ctx, "macos:iokit",
                                    "no IOBlockStorageDevice was found on this host");
            break;
        case DegradationKind::IdentityUnread:
            mark_result_partial(ctx, "macos:iokit:no_bsd_name",
                                "at least one block storage device resolved no BSD name and is "
                                "reported with \"-\" as its device");
            break;
        case DegradationKind::ItemDetailUnread:
            // The token is qualified, not bare `macos:iokit`: sharing it with
            // the hard IOServiceGetMatchingServices failure gave that alert key
            // a 100% firing rate on healthy hosts.
            mark_result_partial(ctx, "macos:iokit:health_unread",
                                "health attributes are not read on macOS; identity and capability "
                                "only");
            break;
        case DegradationKind::Denied:
        case DegradationKind::EnumerationIncomplete:
        case DegradationKind::ListUnread:
        case DegradationKind::ListTruncated:
        case DegradationKind::MountsUnread:
        case DegradationKind::FstypeUnread:
            break; // not produced by this leg
        }
    }
    return 0;
}

int emit_volumes(yuzu::CommandContext& ctx) {
    bool mounts_ok = false;
    const auto mounts = mount_points_by_bsd_name(mounts_ok);

    io_iterator_t raw_it{};
    if (IOServiceGetMatchingServices(kIOMainPortDefault, IOServiceMatching(kIOMediaClass),
                                     &raw_it) != KERN_SUCCESS) {
        write_volume_row(ctx, "-", "-", "-", "-", std::nullopt,
                         "IOServiceGetMatchingServices failed");
        mark_result_partial(ctx, "macos:iomedia", "IOServiceGetMatchingServices failed");
        return 0;
    }
    ScopedIOObject it{raw_it};

    bool any_row = false;
    bool any_media_skipped = false;
    bool any_physical_unresolved = false;
    for (io_object_t raw_obj; (raw_obj = IOIteratorNext(it.get()));) {
        ScopedIOObject obj{raw_obj};

        ScopedCFRef<CFTypeRef> bsd{
            IORegistryEntryCreateCFProperty(obj.get(), CFSTR(kIOBSDNameKey), kCFAllocatorDefault, 0)};
        const std::string name = cf_string(bsd.get());
        if (name.empty()) {
            // An IOMedia object we cannot key on is silently absent from the
            // output; record it rather than let a short list read as complete.
            any_media_skipped = true;
            continue;
        }

        ScopedCFRef<CFTypeRef> size{
            IORegistryEntryCreateCFProperty(obj.get(), CFSTR(kIOMediaSizeKey), kCFAllocatorDefault, 0)};
        std::optional<std::uint64_t> total;
        if (size.get() && CFGetTypeID(size.get()) == CFNumberGetTypeID()) {
            long long v = 0;
            if (CFNumberGetValue(static_cast<CFNumberRef>(size.get()), kCFNumberLongLongType, &v) &&
                v >= 0)
                total = static_cast<std::uint64_t>(v);
        }

        // THE JOIN this action exists for: partition -> whole disk, and
        // partition -> mount points.
        std::string joined = "-";
        std::string fstype = "-";
        if (const auto found = mounts.find(name); found != mounts.end()) {
            joined.clear();
            for (const auto& mp : found->second.mount_points) {
                if (!joined.empty()) joined += ',';
                joined += mp;
            }
            if (!found->second.fstype.empty()) fstype = found->second.fstype;
        }

        // An empty answer means the provider walk failed or hit its depth cap,
        // NOT that this media has no backing disk. Collapsing both to "-" left
        // the command reporting a clean OK while the physical column -- the
        // whole point of the action -- was unresolved.
        std::string physical = physical_whole_disk_of(obj.get());
        if (physical.empty()) {
            any_physical_unresolved = true;
            physical = "-";
        }

        // F3 (spec axis): this action is the physical-to-logical JOIN, not a
        // third media inventory -- `hardware.disks` already enumerates physical
        // devices. A row for a whole disk that serves no mount point carries no
        // join at all (its device column is itself), so emitting it would be
        // the scope creep the operator ruling explicitly excluded. Every row
        // that maps SOMETHING -- a partition to its drive, or any media to a
        // mount point -- is kept.
        if (joined == "-" && physical == name) continue;

        write_volume_row(ctx, name, joined, physical, fstype, total,
                         mounts_ok ? "-" : "mount-point enumeration failed; the mapping column is "
                                           "incomplete");
        any_row = true;
    }

    // PRECEDENCE comes from the pure layer, NOT from the order of these blocks.
    // This leg had inverted its own ordering -- it reported a skipped media
    // object (a short listing) first and an unread mount table last, so under
    // last-writer-wins the WEAKEST cause won. Driving the shared decision makes
    // that class of drift impossible rather than merely fixed once.
    if (!any_row)
        // Word this for what actually happened. IOMedia objects may well have
        // been FOUND and then dropped by the join filter above, so "no IOMedia
        // objects found" would be a falsehood in exactly the case that produces
        // it most often.
        write_volume_row(ctx, "-", "-", "-", "-", std::nullopt,
                         "no IOMedia object carried a physical-to-logical mapping to report");

    DegradationFlags flags;
    flags.list_truncated = any_media_skipped;
    flags.item_detail_unread = any_physical_unresolved;
    flags.mounts_unread = !mounts_ok;
    flags.empty_result = !any_row;

    if (const auto cause = summarise_degradation(flags)) {
        switch (*cause) {
        case DegradationKind::ListTruncated:
            mark_result_partial(ctx, "macos:iomedia:no_bsd_name",
                                "at least one IOMedia object reported no BSD name and is absent "
                                "from this listing");
            break;
        case DegradationKind::ItemDetailUnread:
            mark_result_partial(ctx, "macos:provider_walk",
                                "the backing physical disk could not be resolved for at least one "
                                "volume; those rows show \"-\" without meaning none exists");
            break;
        case DegradationKind::MountsUnread:
            // The token names the API the code CALLS. getmntinfo(3) was
            // replaced by getmntinfo_r_np for the static-buffer race documented
            // above, and a provenance token naming the removed call is exactly
            // the drift that invites someone to "restore consistency" by
            // putting it back.
            mark_result_partial(ctx, "macos:getmntinfo_r_np",
                                "getmntinfo_r_np returned no entries; volumes are listed without "
                                "their mount points");
            break;
        case DegradationKind::EmptyResult:
            mark_result_unavailable(ctx, "macos:iomedia",
                                    "no volume mapping could be produced on this host");
            break;
        case DegradationKind::Denied:
        case DegradationKind::EnumerationIncomplete:
        case DegradationKind::ListUnread:
        case DegradationKind::IdentityUnread:
        case DegradationKind::FstypeUnread:
            break; // not produced by this leg
        }
    }
    return 0;
}

} // namespace yuzu::disk_actions

#endif // defined(__APPLE__)
