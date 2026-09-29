/**
 * disk_actions_win.cpp — Windows leg entry points.
 *
 * MECHANISMS, every one bound by spike against real hardware on 2026-09-03
 * (the-rig, live Samsung SSD 970 EVO Plus over NVMe) before a line of this was
 * written. The full record is at ~/.claude/roadmaps/wave6-smart-spike.md.
 *
 *   smart    IOCTL_STORAGE_QUERY_PROPERTY with StorageDeviceProperty (identity,
 *            bus type), StorageDeviceSeekPenaltyProperty (SSD vs HDD) and
 *            StorageDeviceProtocolSpecificProperty + ProtocolTypeNvme +
 *            NVMeDataTypeLogPage page 0x02 (the SMART/Health log).
 *   volumes  FindFirstVolumeW/FindNextVolumeW +
 *            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS (which physical drives back
 *            this volume) + GetVolumePathNamesForVolumeNameW (which mount
 *            points it serves).
 *
 * HOST-VERIFIED 2026-09-04 on that same host: this TU compiles under real MSVC
 * with zero errors, the agent suite passes there (76,268 assertions / 2,553
 * cases), and both actions were exercised against two live NVMe drives,
 * emitting distinct per-device wear figures rather than a constant:
 *
 *   smart|PhysicalDrive0|Samsung SSD 970 EVO Plus 250GB|nvme|ssd|ok|5|100|-
 *   smart|PhysicalDrive1|Samsung SSD 970 EVO Plus 1TB|nvme|ssd|ok|1|100|-
 *   volume|...{c9a5f911}/|C:/|PhysicalDrive0|-|248158093312|-
 *   volume|...{785383ef}/|D:/|PhysicalDrive1|-|1000187363328|-
 *
 * The last two lines are the join this plugin exists for: C: resolves to
 * PhysicalDrive0 and D: to PhysicalDrive1, so a failing drive can be named in
 * terms of the drive letters it serves.
 *
 * TWO SPIKE NEGATIVES, both load-bearing, both the kind of mistake that ships
 * a leg which silently never works:
 *
 *   1. THE DEVICE HANDLE IS OPENED WITH ZERO ACCESS RIGHTS, deliberately, and
 *      this is not a typo for GENERIC_READ. Measured: as NT AUTHORITY\LOCAL
 *      SERVICE, CreateFileW with GENERIC_READ fails ERROR_ACCESS_DENIED, while
 *      a 0-access handle succeeds and serves BOTH IOCTLs (they are
 *      FILE_ANY_ACCESS controls). That single detail is why this leg keeps
 *      working when #1442 moves the agent off LocalSystem — unlike the VSS
 *      snapshots leg in filesystem_posture, which genuinely requires admin.
 *      Do not "fix" this to GENERIC_READ.
 *
 *   2. IOCTL_STORAGE_PREDICT_FAILURE — the obvious "documented health bit" —
 *      FAILS with ERROR_INVALID_FUNCTION (1) on NVMe. It is the ATA-era API.
 *      This file does not use it, and a future edit that reaches for it should
 *      re-measure first rather than assume the docs describe modern drives.
 *
 * Every OS call here is read-only: no write, format or delete right is ever
 * requested on a drive or volume handle.
 *
 * BOUNDING, and an honest statement of what is NOT bounded. Every
 * DeviceIoControl below is synchronous on a handle opened without
 * FILE_FLAG_OVERLAPPED, and there is no deadline on any of them. A wedged
 * device -- a failing USB drive, a disconnected SAN LUN, a removable in a
 * not-ready state -- therefore parks the dispatch-pool worker that called us,
 * and enough of them would exhaust the pool. Two things bound the ordinary
 * case: the probe stops at kMaxPhysicalDrives, and ThreadErrorModeGuard
 * suppresses the session-0 hard-error dialog that would otherwise block on a
 * not-ready volume. Neither bounds a driver that never returns.
 *
 * This is a PLATFORM GAP, not an omission here: agents/shared/bounded_wait.hpp
 * bounds waits on futures and processes, and there is no in-tree precedent for
 * bounding an ioctl/DeviceIoControl/IOKit call. Inventing a one-off here --
 * abandoning a detached thread mid-ioctl on a device handle -- is materially
 * riskier than the wedge it would paper over. Filed rather than improvised.
 */

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <winioctl.h>
// nvme.h supplies STORAGE_PROTOCOL_SPECIFIC_DATA / ProtocolTypeNvme /
// NVMeDataTypeLogPage. Soft-guarded: an SDK without it still builds and
// reports identity, losing only the health figures.
#if __has_include(<nvme.h>)
#define YUZU_DISKACTIONS_HAVE_NVME 1
#include <nvme.h>
#endif

#include <win_str.hpp>

#include "disk_actions_legs.hpp"
#include "disk_actions_parsers.hpp"

#include <array>
#include <cstddef>
#include <cstring>
#include <format>
#include <optional>
#include <string>
#include <vector>

namespace yuzu::disk_actions {

namespace {

/// RAII guard: set the thread error mode on construction, restore on scope
/// exit. Local copy of the same guard in disk_space_plugin.cpp and
/// filesystem_posture_win.cpp — promoting it into agents/shared/ is a
/// follow-up outside this change, noted so the third copy is a recorded
/// decision rather than an oversight.
///
/// It suppresses the session-0 hard-error dialog around a query against a
/// not-ready removable or BitLocker-locked volume, which would otherwise block
/// a bounded dispatch-pool worker. Thread-scoped, never the process-wide
/// SetErrorMode, which would race other workers in the same pool.
class ThreadErrorModeGuard {
public:
    explicit ThreadErrorModeGuard(DWORD mode) noexcept { ::SetThreadErrorMode(mode, &prev_); }
    ~ThreadErrorModeGuard() { ::SetThreadErrorMode(prev_, nullptr); }
    ThreadErrorModeGuard(const ThreadErrorModeGuard&) = delete;
    ThreadErrorModeGuard& operator=(const ThreadErrorModeGuard&) = delete;

private:
    DWORD prev_ = 0;
};

/// RAII owner for a device/volume HANDLE.
///
/// MOVABLE, not copyable, and the move operations are DECLARED rather than
/// defaulted for a reason: declaring the copy constructor (even as deleted)
/// suppresses the implicit move constructor, so a factory returning one of
/// these by value fails to compile with "attempting to reference a deleted
/// function". That is exactly what happened -- `open_physical_drive` was
/// changed to return by value and the whole TU is `#if defined(_WIN32)`, so no
/// macOS build compiled a line of it and only the Windows CI leg caught it.
///
/// A HANDLE is a VALUE, not a refcount: the moved-from object must be left
/// holding INVALID_HANDLE_VALUE so exactly one owner ever closes it. This is
/// the same reasoning that makes ScopedFd's same-identity early return correct
/// while ScopedCFRef's would be a leak -- do not "harmonise" them.
class ScopedFileHandle {
public:
    explicit ScopedFileHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedFileHandle() {
        if (valid()) ::CloseHandle(h_);
    }
    ScopedFileHandle(const ScopedFileHandle&) = delete;
    ScopedFileHandle& operator=(const ScopedFileHandle&) = delete;
    ScopedFileHandle(ScopedFileHandle&& other) noexcept : h_(other.h_) {
        other.h_ = INVALID_HANDLE_VALUE; // sole ownership transfers
    }
    ScopedFileHandle& operator=(ScopedFileHandle&& other) noexcept {
        if (this != &other) {
            if (valid()) ::CloseHandle(h_);
            h_ = other.h_;
            other.h_ = INVALID_HANDLE_VALUE;
        }
        return *this;
    }
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept {
        return h_ != nullptr && h_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

/// RAII owner for a FindFirstVolumeW search handle (FindVolumeClose, a
/// different API from CloseHandle).
class ScopedVolumeFindHandle {
public:
    explicit ScopedVolumeFindHandle(HANDLE h) noexcept : h_(h) {}
    ~ScopedVolumeFindHandle() {
        if (valid()) ::FindVolumeClose(h_);
    }
    ScopedVolumeFindHandle(const ScopedVolumeFindHandle&) = delete;
    ScopedVolumeFindHandle& operator=(const ScopedVolumeFindHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    [[nodiscard]] bool valid() const noexcept {
        return h_ != nullptr && h_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE h_ = INVALID_HANDLE_VALUE;
};

constexpr int kMaxPhysicalDrives = 64; // bounds the probe walk; see emit_smart

/// Open \\.\PhysicalDriveN with ZERO access rights. See negative (1) in the
/// file banner: this is what an unprivileged service account may do, and it is
/// sufficient for every IOCTL this file issues.
///
/// `err` receives the failing GetLastError() and is meaningful only when the
/// returned handle is invalid. It is captured HERE, immediately after
/// CreateFileW, because this function destroys a heap-allocated std::wstring
/// on the way out; that free can overwrite the thread's last error before the
/// caller ever reads it. The caller's classification depends on the exact code
/// -- ERROR_FILE_NOT_FOUND is the normal terminator on roughly 62 of 64
/// iterations, so a clobbered value would misclassify a HEALTHY host as a
/// degraded one.
ScopedFileHandle open_physical_drive(int index, DWORD& err) {
    err = 0;
    const std::wstring path = L"\\\\.\\PhysicalDrive" + std::to_wstring(index);
    ScopedFileHandle h{::CreateFileW(path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                     nullptr, OPEN_EXISTING, 0, nullptr)};
    if (!h.valid()) err = ::GetLastError();
    return h;
}

Bus bus_from_storage_type(STORAGE_BUS_TYPE t) {
    switch (t) {
    case BusTypeNvme:  return Bus::Nvme;
    case BusTypeSata:
    case BusTypeAta:   return Bus::Sata;
    case BusTypeUsb:   return Bus::Usb;
    case BusTypeSas:   return Bus::Sas;
    case BusTypeVirtual:
    case BusTypeFileBackedVirtual: return Bus::Virtual;
    default: return Bus::Unknown;
    }
}

/// A counted, offset-based field from STORAGE_DEVICE_DESCRIPTOR. The offsets
/// are device-supplied, so every one is bounds-checked against the returned
/// byte count before it is dereferenced -- this is untrusted data shaped by
/// firmware, not by us.
std::string descriptor_field(const BYTE* buf, DWORD returned, DWORD offset) {
    if (offset == 0 || offset >= returned) return {};
    const char* p = reinterpret_cast<const char*>(buf) + offset;
    const std::size_t max = static_cast<std::size_t>(returned - offset);
    const std::size_t len = ::strnlen(p, max); // never runs past the reply
    std::string out(p, len);
    while (!out.empty() && (out.back() == ' ' || out.back() == '\t')) out.pop_back();
    return out;
}

struct DriveIdentity {
    std::string model;
    Bus bus{Bus::Unknown};
    Media media{Media::Unknown};
};

/// `err` receives the failing GetLastError() and is meaningful only when this
/// returns nullopt. It is captured HERE, at the syscall, because by the time
/// the caller formats its row the thread's last-error has already been
/// overwritten by the intervening calls -- the row used to print a stale code.
std::optional<DriveIdentity> query_identity(HANDLE h, DWORD& err) {
    err = 0;
    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;
    // alignas: this byte array is read back through a STORAGE_DEVICE_DESCRIPTOR*
    // below. std::array<BYTE,N> carries only BYTE alignment, so the cast would
    // otherwise rest on incidental placement rather than a stated precondition
    // (adversarial review 2026-09-04; a MinGW probe found the buffers aligned in
    // practice, which is exactly the kind of accident that stops being true on
    // another supported compiler).
    alignas(STORAGE_DEVICE_DESCRIPTOR) std::array<BYTE, 1024> buf{};
    DWORD returned = 0;
    if (!::DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &q, sizeof q, buf.data(),
                           static_cast<DWORD>(buf.size()), &returned, nullptr)) {
        err = ::GetLastError();
        return std::nullopt;
    }
    if (returned < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        err = ERROR_INVALID_DATA; // answered, but with less than the descriptor
        return std::nullopt;
    }

    const auto* d = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf.data());
    DriveIdentity id;
    id.bus = bus_from_storage_type(d->BusType);
    std::string product = descriptor_field(buf.data(), returned, d->ProductIdOffset);
    std::string vendor = descriptor_field(buf.data(), returned, d->VendorIdOffset);
    // NVMe puts the whole name in ProductId and leaves VendorId empty; SATA
    // often splits it. Join only when both are present, so a model never gains
    // a stray leading space.
    id.model = vendor.empty() ? product : (product.empty() ? vendor : vendor + " " + product);

    // Seek penalty is a separate query and its absence is not a failure -- a
    // device that will not answer is `unknown`, never guessed as either.
    STORAGE_PROPERTY_QUERY sq{};
    sq.PropertyId = StorageDeviceSeekPenaltyProperty;
    sq.QueryType = PropertyStandardQuery;
    DEVICE_SEEK_PENALTY_DESCRIPTOR sp{};
    DWORD sr = 0;
    if (::DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &sq, sizeof sq, &sp, sizeof sp, &sr,
                          nullptr) &&
        sr >= sizeof sp)
        id.media = sp.IncursSeekPenalty ? Media::Hdd : Media::Ssd;
    return id;
}

#if defined(YUZU_DISKACTIONS_HAVE_NVME)
/// NVMe SMART / Health Information log page 0x02. Byte offsets are from the
/// NVMe specification: [0] critical warning, [3] available spare %,
/// [5] percentage used.
std::optional<NvmeHealth> query_nvme_health(HANDLE h) {
    // LAYOUT PROOF, and a deliberate absence of named members.
    //
    // The Windows protocol query is a single flat buffer: a STORAGE_PROPERTY_QUERY
    // whose trailing `AdditionalParameters` (declared `BYTE[1]`) is where a
    // STORAGE_PROTOCOL_SPECIFIC_DATA actually begins, with the payload after it.
    // Writing through that member is the documented wire contract, not a hack.
    //
    // An earlier revision declared `STORAGE_PROTOCOL_SPECIFIC_DATA protocol;` and
    // `BYTE data[512];` as named members here. They were a TRAP: the cast below
    // establishes the real object at offsetof(AdditionalParameters) == 8, while
    // the named `protocol` sat at 12 and `data` at 52 — so neither named member
    // was ever the object the driver reads. Setting `req.protocol.ProtocolType`
    // (the obvious maintenance edit) would have configured nothing, the driver
    // would have seen ProtocolTypeUnknown, and NVMe health would have gone
    // silently unread on every drive. The members are gone so that edit cannot
    // be written; the buffer is a flat array sized and aligned for the query.
    // The NVMe SMART / Health Information log page is 512 bytes. Named once so
    // the request size, the declared ProtocolDataLength and the reply buffer
    // cannot drift apart.
    static constexpr std::size_t kNvmeLogPageBytes = 512;
    static constexpr std::size_t kProtoQueryBytes =
        offsetof(STORAGE_PROPERTY_QUERY, AdditionalParameters) +
        sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + kNvmeLogPageBytes;
    struct Request {
        alignas(STORAGE_PROPERTY_QUERY) BYTE bytes[kProtoQueryBytes];
    } req{};
    // These constrain the LAYOUT the casts below depend on. The previous pair
    // were tautologies -- `sizeof(Request) >= kProtoQueryBytes` is true by
    // construction -- and neither said anything about the alignment they were
    // written to defend.
    static_assert(alignof(STORAGE_PROTOCOL_SPECIFIC_DATA) <= alignof(STORAGE_PROPERTY_QUERY),
                  "the buffer is aligned for STORAGE_PROPERTY_QUERY, so the protocol descriptor "
                  "written inside it must not need stricter alignment");
    static_assert(offsetof(STORAGE_PROPERTY_QUERY, AdditionalParameters) %
                          alignof(STORAGE_PROTOCOL_SPECIFIC_DATA) == 0,
                  "AdditionalParameters must itself be aligned for the protocol descriptor "
                  "written through it");
    static_assert(offsetof(STORAGE_PROPERTY_QUERY, AdditionalParameters) +
                          sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA) + kNvmeLogPageBytes <=
                      kProtoQueryBytes,
                  "the descriptor plus the full log page must fit inside the request buffer");

    auto* q = reinterpret_cast<STORAGE_PROPERTY_QUERY*>(req.bytes);
    q->PropertyId = StorageDeviceProtocolSpecificProperty;
    q->QueryType = PropertyStandardQuery;

    auto* psd = reinterpret_cast<STORAGE_PROTOCOL_SPECIFIC_DATA*>(q->AdditionalParameters);
    psd->ProtocolType = ProtocolTypeNvme;
    psd->DataType = NVMeDataTypeLogPage;
    psd->ProtocolDataRequestValue = 2; // SMART / Health Information
    psd->ProtocolDataRequestSubValue = 0;
    psd->ProtocolDataOffset = sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA);
    psd->ProtocolDataLength = kNvmeLogPageBytes;

    // alignas: same reason as query_identity's buffer -- this is read back
    // through a STORAGE_PROTOCOL_DATA_DESCRIPTOR*.
    alignas(STORAGE_PROTOCOL_DATA_DESCRIPTOR)
        std::array<BYTE, sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) + kNvmeLogPageBytes> out{};
    DWORD returned = 0;
    if (!::DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &req, sizeof req, out.data(),
                           static_cast<DWORD>(out.size()), &returned, nullptr))
        return std::nullopt;
    if (returned < sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR)) return std::nullopt;

    const auto* pd = reinterpret_cast<const STORAGE_PROTOCOL_DATA_DESCRIPTOR*>(out.data());

    // The descriptor HEADER is device-supplied too, and bounding the payload
    // span is not enough on its own. Adversarial review (2026-09-04) found that
    // a driver returning success with ProtocolDataOffset = 0 makes the span
    // below start at the STORAGE_PROTOCOL_SPECIFIC_DATA header itself -- whose
    // bytes would then be decoded as a SMART reading and reported as a health
    // verdict and wear figures that never came from log page 0x02. Every check
    // here is one Microsoft's own protocol-query sample performs:
    //
    //   * Version and Size must be exactly the descriptor's size. This fails
    //     CLOSED (health `unknown`, and the caller marks the read degraded)
    //     rather than trusting a header we do not recognise.
    //   * ProtocolDataOffset must clear the STORAGE_PROTOCOL_SPECIFIC_DATA
    //     header -- the same lower bound the REQUEST uses at the top of this
    //     function, so an answer that violates it is self-inconsistent.
    if (pd->Version != sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR) ||
        pd->Size != sizeof(STORAGE_PROTOCOL_DATA_DESCRIPTOR))
        return std::nullopt;
    if (pd->ProtocolSpecificData.ProtocolDataOffset < sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA))
        return std::nullopt;

    // Both offset and length are device-supplied. Bound the whole span against
    // what was actually returned before touching a byte of it.
    const std::size_t base = offsetof(STORAGE_PROTOCOL_DATA_DESCRIPTOR, ProtocolSpecificData) +
                             pd->ProtocolSpecificData.ProtocolDataOffset;
    const std::size_t len = pd->ProtocolSpecificData.ProtocolDataLength;
    if (len < kNvmeHealthMinBytes || base > returned || base + len > returned)
        return std::nullopt;

    // The field extraction and its bounds check are pure and shared, so a
    // change to the NVMe offsets fails a unit test rather than silently
    // reading the wrong byte on a live drive.
    return decode_nvme_health(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(out.data() + base), len));
}
#endif // YUZU_DISKACTIONS_HAVE_NVME

#if defined(YUZU_DISKACTIONS_HAVE_NVME)
/// Adapt the pure verdict (disk_actions_parsers.hpp) to the row-layer token
/// enum. The DECISION lives in the parsers header so every platform's unit
/// suite can exercise it against fixtures; this is only the mapping.
///
/// Guarded because its only caller is the NVMe health path: on an SDK without
/// <nvme.h> an unguarded definition is an unused function (C4505 / -Wunused-function).
Health health_from_verdict(NvmeVerdict v) {
    switch (v) {
    case NvmeVerdict::Ok:      return Health::Ok;
    case NvmeVerdict::Warning: return Health::Warning;
    case NvmeVerdict::Failing: return Health::Failing;
    }
    return Health::Unknown;
}
#endif // YUZU_DISKACTIONS_HAVE_NVME

} // namespace

int emit_smart(yuzu::CommandContext& ctx) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};

    bool any_row = false;
    bool any_denied = false;
    bool any_open_failure = false;
    bool any_health_unread = false;
    bool any_identity_failure = false;
    bool probe_cap_reached = false;
    DWORD first_open_err = 0;
    DWORD first_identity_err = 0;

    // Windows exposes no enumeration of PhysicalDriveN, so probe a bounded
    // range. ERROR_FILE_NOT_FOUND simply means that index does not exist and is
    // the normal terminator; ACCESS_DENIED is a different fact and is reported.
    // Truncation detection: the probe is a bounded walk over a SPARSE namespace.
    // PhysicalDriveN numbering has holes after a hot-remove, so "index 63 was
    // open" is NOT the condition -- a host with more than 64 drives and nothing
    // at 63 would truncate silently. What proves the range was exhausted is a
    // clean not-found TAIL: a run of absent indices at the end of the walk. Any
    // other exit means the cap may have cut the list short.
    int trailing_absent = 0;
    for (int i = 0; i < kMaxPhysicalDrives; ++i) {
        DWORD open_err = 0;
        auto h = open_physical_drive(i, open_err);
        if (!h.valid()) {
            if (open_err == ERROR_FILE_NOT_FOUND || open_err == ERROR_PATH_NOT_FOUND) {
                ++trailing_absent;
                continue;
            }
            trailing_absent = 0;
            if (open_err == ERROR_ACCESS_DENIED) {
                any_denied = true;
            } else {
                any_open_failure = true;
                if (first_open_err == 0) first_open_err = open_err;
            }
            continue;
        }
        trailing_absent = 0;

        const std::string device = "PhysicalDrive" + std::to_string(i);
        DWORD identity_err = 0;
        const auto id = query_identity(h.get(), identity_err);
        if (!id) {
            // The row alone is not enough: leaving the typed seam UNDECLARED
            // here reports a clean OK while a drive's identity is missing --
            // the same defect already fixed for the NVMe health path below.
            any_identity_failure = true;
            if (first_identity_err == 0) first_identity_err = identity_err;
            write_smart_row(ctx, device, "-", Bus::Unknown, Media::Unknown, Health::Unknown,
                            std::nullopt, std::nullopt,
                            std::format("StorageDeviceProperty query failed: {}", identity_err));
            any_row = true;
            continue;
        }

        Health health = Health::Unknown;
        std::optional<std::uint8_t> pct_used;
        std::optional<std::uint8_t> spare;
        std::string detail = "-";

#if defined(YUZU_DISKACTIONS_HAVE_NVME)
        if (id->bus == Bus::Nvme) {
            if (const auto nh = query_nvme_health(h.get())) {
                health = health_from_verdict(nvme_verdict(nh->critical_warning));
                pct_used = nh->percentage_used;
                spare = nh->available_spare;
            } else {
                // F2: recording the cause only in the row's detail left the
                // command reporting a clean OK. An NVMe drive whose health we
                // could not read is a DEGRADED read, and must say so through
                // the typed seam a status-keyed consumer reads.
                any_health_unread = true;
                detail = "NVMe SMART log page 0x02 was not returned by this device";
            }
        } else {
            // Deliberate and declared: wear figures come from the NVMe health
            // log, so a SATA or USB drive reports identity and media type with
            // health `unknown` rather than a guess. IOCTL_STORAGE_PREDICT_FAILURE
            // is NOT a substitute -- see negative (2) in the file banner.
            detail = "wear and spare figures are read from the NVMe health log; this device is "
                     "not NVMe, so its health is not reported";
        }
#else
        // F1: this build has no NVMe header, so NO drive can report health on
        // it. The descriptor advertises SUPPORTED with wear figures, so a
        // silent OK here would be the sibling plugin's exact failure mode --
        // a leg whose real path was compiled out while its descriptor claimed
        // otherwise. Degrade explicitly and let the row say why.
        any_health_unread = true;
        detail = "built without the NVMe SDK header; health is not read";
#endif

        write_smart_row(ctx, device, id->model.empty() ? "-" : id->model, id->bus, id->media,
                        health, pct_used, spare, detail);
        any_row = true;
    }

    // TRUNCATION IS A HEURISTIC, AND SAYING SO IS THE POINT.
    //
    // No probe of 0..63 can PROVE the namespace is exhausted: PhysicalDriveN
    // numbering is sparse after a hot-remove, so drives can exist past the cap
    // with a hole below it. A previous revision claimed a "clean not-found
    // tail" solved this, but only ever tested `trailing_absent == 0` — which is
    // true exactly when index 63 was present, i.e. the single-index test it
    // claimed to replace. Governance caught the comment asserting the opposite
    // of the code.
    //
    // What a run of absent indices at the end IS: evidence, not proof. A short
    // run is weak evidence, so require a real one; and because the bound itself
    // can hide drives regardless, that limitation is declared in the descriptor
    // rather than papered over here.
    constexpr int kExhaustionTailRun = 8;
    if (trailing_absent < kExhaustionTailRun) probe_cap_reached = true;

    // PRECEDENCE comes from the pure layer; this switch only names the cause.
    // The placeholder ROW is written before the status decision: a consumer
    // must never read zero rows and infer "no drives". Its STATUS, though, goes
    // through the shared precedence like every other cause -- emitting it after
    // the switch overwrote a co-occurring denial, reporting a host that refused
    // every device as one that simply has none.
    if (!any_row)
        write_smart_row(ctx, "-", "-", Bus::Unknown, Media::Unknown, Health::Unsupported,
                        std::nullopt, std::nullopt, "no physical drives could be opened");

    DegradationFlags flags;
    flags.item_detail_unread = any_health_unread;
    flags.identity_unread = any_identity_failure;
    flags.list_truncated = probe_cap_reached;
    flags.list_unread = any_open_failure;
    flags.empty_result = !any_row;
    flags.denied = any_denied;

    if (const auto cause = summarise_degradation(flags)) {
        switch (*cause) {
        case DegradationKind::Denied:
            mark_result_denied(ctx, "windows:physicaldrive:denied",
                               "at least one physical drive refused a zero-access open; this "
                               "agent account cannot enumerate it");
            break;
        case DegradationKind::ListUnread:
            mark_result_partial(ctx, "windows:physicaldrive",
                                std::format("at least one drive could not be opened: {}",
                                            first_open_err));
            break;
        case DegradationKind::ListTruncated:
            mark_result_partial(ctx, "windows:physicaldrive_cap",
                                std::format("the drive probe stops at PhysicalDrive{}, and this "
                                            "walk did not end in a run of absent indices, so a "
                                            "host with more drives may be reported short",
                                            kMaxPhysicalDrives - 1));
            break;
        case DegradationKind::IdentityUnread:
            mark_result_partial(ctx, "windows:storage_device_property",
                                std::format("at least one drive did not answer the identity "
                                            "query: {}", first_identity_err));
            break;
        case DegradationKind::ItemDetailUnread:
            mark_result_partial(ctx, "windows:nvme_health",
                                "health could not be read for at least one drive; see the row "
                                "detail");
            break;
        case DegradationKind::EmptyResult:
            mark_result_unavailable(ctx, "windows:physicaldrive",
                                    "no physical drive could be opened on this host");
            break;
        case DegradationKind::EnumerationIncomplete:
        case DegradationKind::MountsUnread:
        case DegradationKind::FstypeUnread:
            break; // not produced by this leg
        }
    }
    return 0;
}

int emit_volumes(yuzu::CommandContext& ctx) {
    ThreadErrorModeGuard err_guard{SEM_FAILCRITICALERRORS};

    wchar_t volume[MAX_PATH] = {};
    const ScopedVolumeFindHandle find{::FindFirstVolumeW(volume, MAX_PATH)};
    if (!find.valid()) {
        // ONE read, used twice. Reading GetLastError() a second time after
        // write_volume_row has run std::format, safe_output_field, several
        // allocations and a cross-ABI write_output returns whatever THOSE left
        // behind -- the row and the status would then disagree, both claiming
        // to name the cause.
        const DWORD err = ::GetLastError();
        write_volume_row(ctx, "-", "-", "-", "-", std::nullopt,
                         std::format("FindFirstVolumeW failed: {}", err));
        // Qualified tokens, matching the summary block: a consumer alerting on
        // windows:volume_enum:denied must see the TOTAL refusal too, which is
        // the most severe case of all.
        if (err == ERROR_ACCESS_DENIED)
            mark_result_denied(ctx, "windows:volume_enum:denied",
                               "volume enumeration was refused; this agent account cannot "
                               "enumerate volumes");
        else
            mark_result_partial(ctx, "windows:volume_enum",
                                std::format("FindFirstVolumeW failed: {}", err));
        return 0;
    }

    bool any_extent_failure = false;
    bool any_extent_truncated = false;
    bool any_mounts_failure = false;
    bool any_fstype_failure = false;
    bool any_denied = false;
    bool any_enum_failure = false;
    DWORD first_enum_err = 0;
    for (;;) {
        std::wstring vol = volume;
        const std::string vol_utf8 = yuzu::win::from_wide(vol.c_str());

        // PER-ROW causes. The typed seam transmits only the short provenance
        // token -- the `reason` text goes to spdlog on the endpoint and never
        // reaches the server -- so an aggregate mark tells a consumer that
        // SOMETHING degraded but never WHICH row's "-" is a failure rather than
        // a genuine "none". On the mount-points column that is the join this
        // action exists for, so the cause travels in the row as well.
        std::vector<std::string> row_causes;

        // Mount points served by this volume. A volume with no letter and no
        // mount point is reported with "-" rather than omitted -- it still
        // occupies a physical drive, which is what this action is about.
        // Both failure arms below must reach the typed seam. "-" legitimately
        // means "this volume serves no mount point", so a FAILED enumeration
        // that silently produces the same "-" is indistinguishable from a
        // genuinely unmounted volume -- and the mount-point column is the join
        // this action exists for. The sibling filesystem_posture_win.cpp:275
        // already draws exactly this distinction.
        std::string mounts = "-";
        DWORD needed = 0;
        // Key the sizing outcome off the RETURN VALUE, not GetLastError: this
        // call SUCCEEDS on a volume with no mount points (needed == 1, just the
        // list terminator), and GetLastError is not set on success -- reading it
        // there would surface a stale code from an earlier call and mark every
        // healthy unmounted volume degraded.
        ::SetLastError(ERROR_SUCCESS);
        const BOOL sized = ::GetVolumePathNamesForVolumeNameW(vol.c_str(), nullptr, 0, &needed);
        const DWORD size_err = sized ? ERROR_SUCCESS : ::GetLastError();
        if (needed > 1) {
            std::vector<wchar_t> buf(needed, L'\0');
            if (::GetVolumePathNamesForVolumeNameW(vol.c_str(), buf.data(), needed, &needed)) {
                std::string joined;
                for (const wchar_t* p = buf.data(); *p; p += ::wcslen(p) + 1) {
                    if (!joined.empty()) joined += ',';
                    joined += yuzu::win::from_wide(p);
                }
                if (!joined.empty()) mounts = joined;
            } else {
                any_mounts_failure = true;
                const DWORD e = ::GetLastError();
                if (e == ERROR_ACCESS_DENIED) any_denied = true;
                row_causes.push_back(std::format("mount-point enumeration failed: {}", e));
            }
        } else if (!sized && size_err != ERROR_MORE_DATA) {
            // A FAILED sizing call, as distinct from a successful one reporting
            // an empty mount list.
            any_mounts_failure = true;
            if (size_err == ERROR_ACCESS_DENIED) any_denied = true;
            row_causes.push_back(std::format("mount-point enumeration failed: {}", size_err));
        }

        // THE JOIN: which physical drives back this volume. CreateFileW wants
        // the volume path WITHOUT its trailing backslash.
        // F6: fstype is a declared result column that no leg used to fill.
        // GetVolumeInformationW answers it for a volume that is mounted and
        // ready; one that is not simply keeps "-", which is the honest answer
        // rather than a blank the consumer must interpret.
        std::string fstype = "-";
        {
            wchar_t fs_name[MAX_PATH] = {};
            ::SetLastError(ERROR_SUCCESS);
            if (::GetVolumeInformationW(vol.c_str(), nullptr, 0, nullptr, nullptr, nullptr,
                                        fs_name, MAX_PATH)) {
                if (fs_name[0] != L'\0') fstype = yuzu::win::from_wide(fs_name);
            } else {
                // A REFUSED query, not a volume without a filesystem. Both
                // produce "-", so without this the two are indistinguishable and
                // a host where every volume is BitLocker-locked or not-ready
                // still reports a clean, complete run.
                const DWORD e = ::GetLastError();
                // ERROR_NOT_READY is an empty optical or card slot and
                // ERROR_UNRECOGNIZED_VOLUME an unformatted one: both are normal
                // steady states, not refusals. Counting them would fire this
                // token on every run on such a host, which is the 100%-firing-
                // rate defect the macOS leg split its tokens to avoid. The row
                // still carries the cause.
                if (e != ERROR_NOT_READY && e != ERROR_UNRECOGNIZED_VOLUME) {
                    any_fstype_failure = true;
                    if (e == ERROR_ACCESS_DENIED) any_denied = true;
                }
                row_causes.push_back(std::format("filesystem type query failed: {}", e));
            }
        }

        std::string devices = "-";
        std::optional<std::uint64_t> total;
        std::wstring root = vol;
        if (!root.empty() && root.back() == L'\\') root.pop_back();
        ScopedFileHandle vh{::CreateFileW(root.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                          nullptr, OPEN_EXISTING, 0, nullptr)};
        if (vh.valid()) {
            // A spanned or striped volume touches several drives, so the reply
            // is variable-length; size it for a generous extent count rather
            // than assuming one.
            constexpr DWORD kMaxExtents = 32;
            std::vector<BYTE> buf(sizeof(VOLUME_DISK_EXTENTS) +
                                  (kMaxExtents - 1) * sizeof(DISK_EXTENT));
            DWORD returned = 0;
            ::SetLastError(ERROR_SUCCESS);
            const BOOL ok = ::DeviceIoControl(vh.get(), IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                                              nullptr, 0, buf.data(),
                                              static_cast<DWORD>(buf.size()), &returned, nullptr);
            const DWORD ext_err = ok ? ERROR_SUCCESS : ::GetLastError();
            if (ok && returned >= sizeof(VOLUME_DISK_EXTENTS)) {
                const auto* ext = reinterpret_cast<const VOLUME_DISK_EXTENTS*>(buf.data());
                const DWORD n = ext->NumberOfDiskExtents;
                // NumberOfDiskExtents is device-supplied; bound it against what
                // was actually returned before indexing.
                const std::size_t max_fit =
                    (returned - offsetof(VOLUME_DISK_EXTENTS, Extents)) / sizeof(DISK_EXTENT);
                // The device claimed more extents than the reply could carry, so
                // this volume's drive list is INCOMPLETE -- a spanned volume
                // would name only some of the drives backing it, which is a
                // wrong answer to this action's only question, not a slow one.
                if (n > max_fit) any_extent_truncated = true;
                std::string joined;
                std::uint64_t bytes = 0;
                for (DWORD e = 0; e < n && e < max_fit; ++e) {
                    if (!joined.empty()) joined += ',';
                    joined += "PhysicalDrive" + std::to_string(ext->Extents[e].DiskNumber);
                    bytes += static_cast<std::uint64_t>(ext->Extents[e].ExtentLength.QuadPart);
                }
                if (!joined.empty()) {
                    devices = joined;
                    total = bytes;
                }
                if (n > max_fit)
                    row_causes.push_back(std::format(
                        "the device reported {} extents but only {} fit the reply; this drive "
                        "list is incomplete",
                        n, max_fit));
            } else if (!ok) {
                // The call FAILED: the error is meaningful.
                any_extent_failure = true;
                if (ext_err == ERROR_ACCESS_DENIED) any_denied = true;
                row_causes.push_back(std::format("disk-extent query failed: {}", ext_err));
            } else {
                // The call SUCCEEDED but answered with less than its own header.
                // Reading GetLastError here would report whatever an unrelated
                // call left behind -- and worse, could escalate the whole
                // command to PERMISSION_DENIED off a stale ACCESS_DENIED.
                any_extent_failure = true;
                row_causes.emplace_back("the disk-extent reply was shorter than its own header");
            }
        } else {
            // U1: a REFUSED volume handle is a privilege fact, not a device
            // fact. The file banner's zero-access-rights measurement covered
            // \\.\PhysicalDriveN only -- the VOLUME handle was never measured
            // under an unprivileged account, so if #1442 moves the agent off
            // LocalSystem this is the arm that fires, and it must not be
            // reported as "the device did not answer".
            const DWORD e = ::GetLastError();
            any_extent_failure = true;
            if (e == ERROR_ACCESS_DENIED) any_denied = true;
            row_causes.push_back(std::format("volume handle could not be opened: {}", e));
        }

        std::string detail = "-";
        for (const auto& c : row_causes) {
            if (detail == "-") detail.clear(); else detail += "; ";
            detail += c;
        }
        write_volume_row(ctx, vol_utf8, mounts, devices, fstype, total, detail);

        if (!::FindNextVolumeW(find.get(), volume, MAX_PATH)) {
            const DWORD err = ::GetLastError();
            if (err != ERROR_NO_MORE_FILES) {
                // Recorded, NOT marked here. set_result_status assigns, so a
                // mark emitted inside the loop is unconditionally overwritten by
                // the summary block below -- and a truncated enumeration is the
                // MOST material cause (the listing is incomplete), so it must be
                // reported last, not first.
                any_enum_failure = true;
                first_enum_err = err;
                if (err == ERROR_ACCESS_DENIED) any_denied = true;
            }
            break;
        }
    }

    // PRECEDENCE IS NOT DECIDED HERE. The flags go to the pure
    // summarise_degradation (disk_actions_parsers.hpp), which returns the ONE
    // cause that must be reported; this switch only maps that cause to a token
    // and a sentence. set_result_status assigns, so emitting a sequence of
    // marks and relying on the last to win made every earlier one invisible
    // and let the order drift silently — which is exactly what happened.
    DegradationFlags flags;
    flags.fstype_unread = any_fstype_failure;
    flags.mounts_unread = any_mounts_failure;
    flags.list_truncated = any_extent_truncated;
    flags.list_unread = any_extent_failure;
    flags.enumeration_incomplete = any_enum_failure;
    flags.denied = any_denied;

    if (const auto cause = summarise_degradation(flags)) {
        switch (*cause) {
        case DegradationKind::Denied:
            mark_result_denied(ctx, "windows:volume_enum:denied",
                               "at least one volume refused a zero-access open or query; this "
                               "agent account cannot fully enumerate volumes");
            break;
        case DegradationKind::EnumerationIncomplete:
            mark_result_partial(ctx, "windows:volume_enum",
                                std::format("volume enumeration stopped early ({}); this listing "
                                            "is incomplete", first_enum_err));
            break;
        case DegradationKind::ListUnread:
            mark_result_partial(ctx, "windows:volume_extents:unread",
                                "at least one volume did not report its disk extents; those rows "
                                "name no backing drive");
            break;
        case DegradationKind::ListTruncated:
            mark_result_partial(ctx, "windows:volume_extents:truncated",
                                "at least one volume reported more disk extents than its reply "
                                "could carry; those rows name only some of the drives backing "
                                "them");
            break;
        case DegradationKind::MountsUnread:
            mark_result_partial(ctx, "windows:volume_mount_paths",
                                "at least one volume's mount-point enumeration failed; those rows "
                                "show \"-\" for mount points without meaning the volume has none");
            break;
        case DegradationKind::FstypeUnread:
            mark_result_partial(ctx, "windows:volume_information",
                                "at least one volume refused its filesystem-type query; those "
                                "rows show \"-\" for fstype without meaning the volume has no "
                                "filesystem");
            break;
        case DegradationKind::EmptyResult:
        case DegradationKind::IdentityUnread:
        case DegradationKind::ItemDetailUnread:
            break; // not produced by this leg
        }
    }
    return 0;
}

} // namespace yuzu::disk_actions

#endif // defined(_WIN32)
