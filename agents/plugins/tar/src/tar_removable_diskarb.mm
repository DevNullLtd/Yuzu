/**
 * tar_removable_diskarb.mm — Objective-C++ DiskArbitration backing for the
 * macOS leg of the `removable` cursor-model TAR source. Implements the
 * framework-free interface declared in tar_removable_parsers.hpp
 * (RemovableDiskArbSession) so tar_removable_collector.cpp never includes an
 * Objective-C header. Structure copied from wifi_corewlan.mm (first .mm in
 * the tree): built with `-fobjc-arc`; ARC manages only Objective-C object
 * pointers (dispatch_queue_t, since libdispatch objects are ARC-bridged), so
 * every CFTypeRef (DASessionRef, DADiskRef, CFDictionaryRef, ...) is owned
 * through yuzu::agent::ScopedCFRef<T> (docs/native-objcpp-conventions.md) —
 * no hand-rolled CFRelease.
 *
 * MACOS (CONSTRAINED — live-only, no fixture path): DiskArbitration has no
 * documented log/history API, so this leg is subscription-only. start()
 * arms DARegisterDiskAppeared/DisappearedCallback on a private dispatch
 * queue; stop() unregisters, unschedules the queue, and blocks (dispatch_sync
 * of a no-op block) until any in-flight callback has returned, so nothing
 * DiskArbitration-owned survives stop() (tar_cursor.hpp's stop() contract —
 * the seam driver calls this before TarDatabase teardown).
 */

#import <CoreFoundation/CoreFoundation.h>
#import <DiskArbitration/DiskArbitration.h>
#import <Foundation/Foundation.h>

#include "tar_removable_parsers.hpp"

#include <yuzu/agent/scoped_cfref.hpp>

#include <optional>

#include <spdlog/spdlog.h>

#include <sys/mount.h> // getfsstat / struct statfs — tar_mapdrive_collector.cpp precedent

#include <atomic>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

struct RemovableDiskArbSession::Impl {
    // S2: owned through the shared ScopedCFRef like every other CFTypeRef in
    // this file. It was the one exception -- a raw ref with a hand-rolled
    // CFRelease in stop() -- which meant an exception or an early return added
    // between DASessionCreate() and that release would have leaked the
    // session, and it contradicted this file's own header contract.
    yuzu::agent::ScopedCFRef<DASessionRef> session;
    dispatch_queue_t queue{nullptr};
    std::function<void(RemovableDiskArbEvent)> on_event;
    std::atomic<bool> running{false};
    // BSD name -> the identity captured at appear time. Read/written only on
    // the DA private dispatch queue (appeared and disappeared are both
    // registered on the SAME serial queue, so they never run concurrently
    // with each other) -- no lock needed. R-010: a disappeared disk's own
    // description commonly no longer carries the removable/ejectable flags,
    // the media UUID, or even vendor/product once the media is actually
    // gone, so the detached row's identity must come from what was admitted
    // at appear time, never a fresh (possibly-degraded) re-read; and a BSD
    // name that was never admitted here (an internal, non-removable disk's
    // disappearance) must never be forwarded to the collector at all.
    std::unordered_map<std::string, RemovableDiskArbEvent> admitted;
};

namespace {

std::string cfstring_to_std(CFStringRef s) {
    if (s == nullptr)
        return {};
    const CFIndex len = CFStringGetLength(s);
    const CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
    std::string out(static_cast<std::size_t>(max_size), '\0');
    if (!CFStringGetCString(s, out.data(), max_size, kCFStringEncodingUTF8))
        return {};
    out.resize(std::strlen(out.c_str()));
    return out;
}

// True iff the disk's description carries kDADiskDescriptionMediaRemovableKey
// OR kDADiskDescriptionMediaEjectableKey set true — the pair the spec names
// as the removable-media filter (an internal fixed disk has neither).
bool is_removable_or_ejectable(DADiskRef disk) {
    yuzu::agent::ScopedCFRef<CFDictionaryRef> desc(DADiskCopyDescription(disk));
    if (!desc)
        return false;
    bool result = false;
    auto* removable = static_cast<CFBooleanRef>(
       CFDictionaryGetValue(desc.get(), kDADiskDescriptionMediaRemovableKey));
    auto* ejectable = static_cast<CFBooleanRef>(
       CFDictionaryGetValue(desc.get(), kDADiskDescriptionMediaEjectableKey));
    if (removable != nullptr && CFBooleanGetValue(removable))
        result = true;
    if (!result && ejectable != nullptr && CFBooleanGetValue(ejectable))
        result = true;
    return result;
}

RemovableDiskArbEvent build_event(DADiskRef disk, const char* action) {
    RemovableDiskArbEvent ev;
    ev.action = action;
    const char* bsd = DADiskGetBSDName(disk);
    ev.bsd_name = bsd != nullptr ? bsd : "";

    yuzu::agent::ScopedCFRef<CFDictionaryRef> desc(DADiskCopyDescription(disk));
    if (desc) {
        auto* vendor = static_cast<CFStringRef>(
           CFDictionaryGetValue(desc.get(), kDADiskDescriptionDeviceVendorKey));
        auto* model = static_cast<CFStringRef>(
           CFDictionaryGetValue(desc.get(), kDADiskDescriptionDeviceModelKey));
        auto* uuid = static_cast<CFUUIDRef>(
           CFDictionaryGetValue(desc.get(), kDADiskDescriptionMediaUUIDKey));
        auto* vol_url = static_cast<CFURLRef>(
           CFDictionaryGetValue(desc.get(), kDADiskDescriptionVolumePathKey));
        auto* size_num = static_cast<CFNumberRef>(
           CFDictionaryGetValue(desc.get(), kDADiskDescriptionMediaSizeKey));

        ev.vendor = cfstring_to_std(vendor);
        ev.product = cfstring_to_std(model);

        if (uuid != nullptr) {
            yuzu::agent::ScopedCFRef<CFStringRef> uuid_str(CFUUIDCreateString(kCFAllocatorDefault, uuid));
            ev.media_uuid = cfstring_to_std(uuid_str.get());
        }
        if (vol_url != nullptr) {
            UInt8 buf[1024];
            if (CFURLGetFileSystemRepresentation(vol_url, true, buf, sizeof(buf)))
                ev.volume_path = std::string(reinterpret_cast<char*>(buf));
        }
        if (size_num != nullptr) {
            long long v = 0;
            CFNumberGetValue(size_num, kCFNumberLongLongType, &v);
            ev.size_bytes = v;
        }
    }
    return ev;
}

// R-011: DARegisterDisk{Appeared,Disappeared}Callback registers these as raw
// C function pointers -- DiskArbitration invokes them directly with no
// exception boundary of its own. build_event/is_removable_or_ejectable and
// the std::function invocation below are ordinary C++ (std::string
// allocation, std::unordered_map insertion, an arbitrary caller-supplied
// on_event), any of which can in principle throw (allocation failure at
// minimum). An exception unwinding out through a C callback into
// DiskArbitration's dispatch machinery is undefined behaviour and can
// terminate the agent -- contained here exactly like wifi_corewlan.mm
// contains an ObjC exception at its own callback boundary, except the risk
// here is a plain C++ exception, so a standard try/catch is the correct
// guard (DiskArbitration's C API does not raise NSException).

void on_disk_appeared(DADiskRef disk, void* context) {
    try {
        auto* impl = static_cast<RemovableDiskArbSession::Impl*>(context);
        if (impl == nullptr || !impl->on_event)
            return;
        if (!is_removable_or_ejectable(disk))
            return; // internal fixed disk — never reaches the seam
        RemovableDiskArbEvent ev = build_event(disk, "attached");
        // ADMIT ONLY WHAT THE SNAPSHOT CAN ALSO EXPRESS.
        //
        // DiskArbitration reports WHOLE media as well as its partitions: a
        // single stick delivers a callback for disk4 (whole, no mount, no
        // MediaUUID -> its device_key falls back to the BSD name) and another
        // for disk4s1. snapshot_attached() enumerates getfsstat MOUNTS, so it
        // can only ever see disk4s1. Admitting both gave one physical device
        // TWO device_keys: two `attached` rows, and then the reconciler emitted
        // a `detached` for the whole-disk key -- evidenced as a missed
        // callback -- while the stick was still plugged in. The BSD name is not
        // stable across reconnects either, so the split key changed on every
        // replug.
        //
        // Requiring a volume path makes the callback and the snapshot agree by
        // construction, which is the same property that made the Windows
        // serial-keyed guard correct. RESIDUAL, accepted and documented: a
        // removable device that is inserted but never mounts is not reported on
        // macOS. That is a missing row rather than a fabricated one, and the
        // per-tick reconciliation still picks the device up the moment it
        // mounts.
        if (ev.volume_path.empty())
            return;
        impl->admitted[ev.bsd_name] = ev; // remember identity for a future disappear (R-010)
        impl->on_event(ev);
    } catch (...) {
        spdlog::warn("TAR removable: exception contained in DiskArbitration appeared callback "
                    "(R-011) — no event forwarded this callback");
    }
}

void on_disk_disappeared(DADiskRef disk, void* context) {
    try {
        auto* impl = static_cast<RemovableDiskArbSession::Impl*>(context);
        if (impl == nullptr || !impl->on_event)
            return;
        const char* bsd = DADiskGetBSDName(disk);
        const std::string bsd_name = bsd != nullptr ? bsd : "";
        // R-010: only a BSD name previously admitted (removable/ejectable at
        // appear time) is ever forwarded — an internal disk's disappearance
        // is a harmless no-op here, never a fabricated detach row. The
        // forwarded identity is the one captured AT APPEAR TIME, not a fresh
        // DADiskCopyDescription read: a disappearing disk's own description
        // commonly no longer carries the media UUID/vendor/product fields,
        // which would otherwise silently change the row's device_key at the
        // exact moment identity matters most.
        const auto it = impl->admitted.find(bsd_name);
        if (it == impl->admitted.end())
            return;
        RemovableDiskArbEvent ev = it->second;
        ev.action = "detached";
        impl->admitted.erase(it);
        impl->on_event(std::move(ev));
    } catch (...) {
        spdlog::warn("TAR removable: exception contained in DiskArbitration disappeared callback "
                    "(R-011) — no event forwarded this callback");
    }
}

} // namespace

RemovableDiskArbSession::RemovableDiskArbSession() : impl_(std::make_unique<Impl>()) {}

RemovableDiskArbSession::~RemovableDiskArbSession() { stop(); }

void RemovableDiskArbSession::start(std::function<void(RemovableDiskArbEvent)> on_event) {
    if (impl_->running.exchange(true))
        return; // already started — start() must be idempotent (P-002)
    impl_->on_event = std::move(on_event);
    impl_->session.reset(DASessionCreate(kCFAllocatorDefault));
    if (!impl_->session) {
        impl_->running = false;
        return;
    }
    impl_->queue = dispatch_queue_create("com.yuzu.tar.removable.diskarb", DISPATCH_QUEUE_SERIAL);
    DASessionSetDispatchQueue(impl_->session.get(), impl_->queue);
    DARegisterDiskAppearedCallback(impl_->session.get(), nullptr, &on_disk_appeared, impl_.get());
    DARegisterDiskDisappearedCallback(impl_->session.get(), nullptr, &on_disk_disappeared,
                                      impl_.get());
}

void RemovableDiskArbSession::stop() noexcept {
    if (!impl_->running.exchange(false))
        return; // never started, or already stopped
    if (impl_->session) {
        DAUnregisterCallback(impl_->session.get(), reinterpret_cast<void*>(&on_disk_appeared),
                             impl_.get());
        DAUnregisterCallback(impl_->session.get(), reinterpret_cast<void*>(&on_disk_disappeared),
                             impl_.get());
        DASessionSetDispatchQueue(impl_->session.get(), nullptr); // unschedule
    }
    if (impl_->queue != nullptr) {
        // Block until any callback already dispatched onto the queue has
        // finished running — the drain half of "nothing survives stop()".
        dispatch_sync(impl_->queue, ^{
        });
    }
    // Released here, AFTER the queue drain above -- the ordering is the
    // contract, so the owner is reset explicitly rather than left to Impl's
    // destructor.
    impl_->session.reset();
    impl_->queue = nullptr; // ARC-managed (libdispatch objects are toll-free bridged)
    impl_->on_event = nullptr;
    impl_->admitted.clear(); // a future restart begins from a clean admitted-device slate
}

std::optional<std::vector<RemovableDiskArbEvent>> RemovableDiskArbSession::snapshot_attached() const {
    std::vector<RemovableDiskArbEvent> out;

    // Size-then-fill getfsstat(2), MNT_NOWAIT (tar_mapdrive_collector.cpp
    // precedent) — a live snapshot of the current mount table, nothing
    // historical.
    const int n = getfsstat(nullptr, 0, MNT_NOWAIT);
    if (n < 0)
        return std::nullopt; // C6: a FAILED sizing call, not an empty mount table
    if (n == 0)
        return out;          // genuinely nothing mounted
    std::vector<struct statfs> bufs(static_cast<std::size_t>(n));
    const int filled =
        getfsstat(bufs.data(), static_cast<int>(bufs.size() * sizeof(struct statfs)), MNT_NOWAIT);
    if (filled < 0)
        return std::nullopt; // C6: the fill call failed
    if (filled == 0)
        return out;

    yuzu::agent::ScopedCFRef<DASessionRef> local_session(DASessionCreate(kCFAllocatorDefault));
    if (!local_session)
        return std::nullopt; // C6: no session means we learned nothing, not that nothing is attached

    for (int i = 0; i < filled; ++i) {
        const std::string from(bufs[static_cast<std::size_t>(i)].f_mntfromname);
        if (from.rfind("/dev/", 0) != 0)
            continue; // network/synthetic mount — no BSD disk behind it
        const std::string bsd = from.substr(5);
        yuzu::agent::ScopedCFRef<DADiskRef> disk(
           DADiskCreateFromBSDName(kCFAllocatorDefault, local_session.get(), bsd.c_str()));
        if (!disk)
            continue;
        if (is_removable_or_ejectable(disk.get()))
            out.push_back(build_event(disk.get(), "present_at_baseline"));
    }
    return out;
}

} // namespace yuzu::tar
