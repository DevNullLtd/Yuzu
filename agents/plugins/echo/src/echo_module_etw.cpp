/**
 * echo_module_etw.cpp — ETW Kernel-Process IMAGE-keyword consumer (see header).
 *
 * Cross-platform section (top): the pure ETW-sample → ModuleEvent mapping and
 * the signing-verdict cache — compiled and unit-tested on every platform.
 *
 * Windows section (#ifdef _WIN32): a real-time ETW session on
 * Microsoft-Windows-Kernel-Process with the IMAGE keyword, ProcessTrace on a
 * dedicated thread, TDH decode of image load (5) / unload (6) by property name,
 * signing resolved at drain through a no-reparse handle (NtCreateFile +
 * WinVerifyTrust(hFile) + the provider-chain signer). Mirrors echo_proc_etw.cpp.
 *
 * Off-Windows: every method is a no-op; start() returns false.
 */

#include "echo_module_etw.hpp"

namespace yuzu::echo {

// ── Pure, cross-platform (compiled + unit-tested on every platform) ──────────

ModuleEvent etw_image_sample_to_module_event(const EtwImageSample& s) {
    ModuleEvent e;
    e.ts_unix = s.ts_unix;
    e.action = s.is_load ? ModuleAction::kLoaded : ModuleAction::kUnloaded;
    e.pid = s.pid;
    // System (4) and Idle (0) own kernel-mode / driver image loads.
    e.is_kernel = (s.pid <= 4);
    const std::string& p = s.image_path;
    const auto pos = p.find_last_of("\\/");
    if (pos == std::string::npos) {
        e.module_name = p; // no separator → whole string is the basename
    } else {
        e.module_name = p.substr(pos + 1);
        e.module_dir = p.substr(0, pos);
    }
    // signed_state / signer / process_name are resolved by the collector at
    // drain (off the ETW callback thread), left default here.
    return e;
}

ModuleSignVerdict SigningCache::get(const std::string& full_path, std::int64_t mtime,
                                    const ModuleVerifier& verify) {
    auto it = entries_.find(full_path);
    if (it != entries_.end() && it->second.mtime == mtime) {
        return it->second.verdict; // hit: same file, same version
    }
    // Miss or stale (file changed on disk) → (re)verify. A null verifier yields
    // kUnknown — we never fabricate a verdict.
    ModuleSignVerdict v = verify ? verify(full_path) : ModuleSignVerdict{};
    if (it == entries_.end() && entries_.size() >= cap_) {
        entries_.clear(); // bounded flush; `it` was end() so this is safe
    }
    entries_[full_path] = Entry{mtime, v};
    return v;
}

} // namespace yuzu::echo

#ifdef _WIN32

// windows.h and the ETW/TDH/WinTrust headers are confined to this TU (mirrors
// echo_proc_etw.cpp). NOTE: the small TDH/time/RAII helpers below are kept
// self-contained here rather than shared with echo_proc_etw.cpp — extracting a
// common echo_etw_util would mean a blind refactor of the shipped process
// collector on a host that cannot compile MSVC. Consolidation is a tracked
// follow-up for a Windows-capable session (different TUs → internal linkage, no
// ODR conflict in the meantime). The one exception is the pid → process-name
// helper, shared with the registry source via echo_win_process_name.hpp.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// NtCreateFile's UNICODE_STRING / OBJECT_ATTRIBUTES / IO_STATUS_BLOCK / NTSTATUS; must
// follow windows.h. The function itself is resolved from ntdll at run time (no import lib).
#include <winternl.h>
// <evntcons.h>/<evntrace.h> must follow windows.h; <tdh.h> follows those.
#include <evntcons.h>
#include <evntrace.h>
#include <tdh.h>
// Signing: WinVerifyTrust (softpub action GUID) + the provider-chain signer walk
// (WTHelper*) and CertGetNameStringW.
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)

#include <spdlog/spdlog.h>

#include <atomic>
#include <cstring> // std::memset (stale-session props reset)
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "echo_local_image_path.hpp" // refuse network-path images (see image_path_is_local)
#include "echo_win_process_name.hpp"  // process_basename_for_pid (shared with the registry source)

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace yuzu::echo {

static_assert(kDriveTypeFixed == DRIVE_FIXED);
static_assert(kFileAttributeReparsePoint == FILE_ATTRIBUTE_REPARSE_POINT);
static_assert(kReparseTagNameSurrogateBit == IsReparseTagNameSurrogate(0xFFFFFFFFU));

namespace {

// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
// (same provider as the process collector; we enable a different keyword on our
// own session — see the header's divergence note).
constexpr GUID kKernelProcessGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

// WINEVENT_KEYWORD_IMAGE — image load/unload only (not process/thread/cpu).
constexpr ULONGLONG kKeywordImage = 0x40;

// Image/Load and Image/Unload event ids on the Kernel-Process manifest. These,
// the keyword, and the property names below MUST be confirmed against the live
// provider manifest on a real Windows box (`wevtutil gp
// Microsoft-Windows-Kernel-Process`) — TDH decodes by NAME so a layout change
// across builds is tolerated, but a wrong id/name yields no rows (never a bad
// row: a failed decode drops the event).
constexpr USHORT kEventImageLoad = 5;
constexpr USHORT kEventImageUnload = 6;

// FILETIME (100 ns since 1601) → unix seconds. Wnode.ClientContext = 2 makes
// EVENT_HEADER.TimeStamp a system-time FILETIME, so this is a plain rebase.
std::int64_t filetime_to_unix(LARGE_INTEGER ft) {
    constexpr std::int64_t kEpochDelta = 116444736000000000LL; // 1601→1970 in 100ns
    if (ft.QuadPart < kEpochDelta) {
        return 0; // corrupt/torn/pre-1970 — reject rather than persist a bogus date
    }
    return (ft.QuadPart - kEpochDelta) / 10000000LL;
}

// Delegating shims onto the shared win_str.hpp helper (#1681) -- removes the
// duplicated WideCharToMultiByte boilerplate while keeping these echo-local
// signatures (std::string / std::wstring) and call sites unchanged. Both the old
// local copies and the shared helper treat the input as NUL-terminated, so the
// conversion is behaviour-identical for the (NUL-free) paths this collector handles.
std::wstring utf8_to_wide(const std::string& s) { return yuzu::win::to_wide(s); }

std::string wide_to_utf8(const std::wstring& w) { return yuzu::win::from_wide(w.c_str()); }

// True when `p` (UTF-8, as delivered) is a local path (an NT volume path, or a drive
// letter on a fixed drive) and so safe to open; see echo_local_image_path.hpp. The only
// Windows API here is GetDriveTypeW on the 3-char drive root (drive-letter forms only).
bool image_path_is_local(const std::string& p) {
    const std::string root = drive_root_of(p);
    const unsigned drive_type = root.empty() ? 0U : GetDriveTypeW(utf8_to_wide(root).c_str());
    return is_local_image_path(p, drive_type);
}

// Read a named UInt32 property from a decoded event. Returns false if absent.
bool prop_u32(EVENT_RECORD* rec, const wchar_t* name, std::uint32_t& out) {
    PROPERTY_DATA_DESCRIPTOR pdd{};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(name);
    pdd.ArrayIndex = ULONG_MAX;
    ULONG val = 0;
    if (TdhGetProperty(rec, 0, nullptr, 1, &pdd, sizeof(val),
                       reinterpret_cast<PBYTE>(&val)) != ERROR_SUCCESS) {
        return false;
    }
    out = static_cast<std::uint32_t>(val);
    return true;
}

// Read a named Unicode-string property and return the FULL path as UTF-8 (unlike
// the process collector's basename-only reader — $Module needs the directory).
std::string prop_image_path(EVENT_RECORD* rec, const wchar_t* name) {
    PROPERTY_DATA_DESCRIPTOR pdd{};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(name);
    pdd.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, nullptr, 1, &pdd, &size) != ERROR_SUCCESS || size == 0) {
        return {};
    }
    std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
    if (TdhGetProperty(rec, 0, nullptr, 1, &pdd, size,
                       reinterpret_cast<PBYTE>(buf.data())) != ERROR_SUCCESS) {
        return {};
    }
    return wide_to_utf8(std::wstring(buf.data()));
}

// ── No-reparse image open (NtCreateFile) ─────────────────────────────────────
// The drain opens each classified-local image ONCE, by the NT path as the IMAGE event
// delivers it, and derives mtime, verdict and signer from that handle; nothing is re-resolved
// by name, so a symbolic link or junction planted after the event cannot redirect any step.

using NtCreateFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                         PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG,
                                         ULONG, PVOID, ULONG);

// Resolved once from the loaded ntdll (as confined_fs_win.cpp does; no import library). A null
// result makes every open fail closed -- there is no by-name fallback.
NtCreateFileFn resolve_ntcreatefile() {
    static const NtCreateFileFn resolved = []() -> NtCreateFileFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return nullptr;
        return reinterpret_cast<NtCreateFileFn>(
            reinterpret_cast<void*>(GetProcAddress(ntdll, "NtCreateFile")));
    }();
    return resolved;
}

// Local NT values (<winternl.h> does not export them reliably; a k-name cannot hit a macro).
constexpr ULONG kObjCaseInsensitive = 0x00000040UL;       // OBJ_CASE_INSENSITIVE
constexpr ULONG kObjDontReparse = 0x00001000UL;           // OBJ_DONT_REPARSE (ntifs.h/wdm.h)
constexpr ULONG kFileOpen = 0x00000001UL;                 // FILE_OPEN
constexpr ULONG kFileNonDirectoryFile = 0x00000040UL;     // FILE_NON_DIRECTORY_FILE
constexpr ULONG kFileSynchronousIoNonalert = 0x00000020UL; // FILE_SYNCHRONOUS_IO_NONALERT
constexpr NTSTATUS kStatusInvalidParameter = static_cast<NTSTATUS>(0xC000000DL);

// Simple display name (the CN where one exists) of a provider-chain certificate; "" on failure.
std::string cert_simple_display_name(PCCERT_CONTEXT cert) {
    const DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, nullptr, 0);
    if (n <= 1)
        return {};
    std::wstring name(n - 1, L'\0');
    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(), n);
    return wide_to_utf8(name);
}

} // namespace

// The three seams below are declared in the header and linked by the Windows tests, so they
// sit OUTSIDE the anonymous namespace.

void ImageHandleCloser::operator()(void* h) const noexcept {
    if (h != nullptr)
        CloseHandle(static_cast<HANDLE>(h));
}

ImageHandle open_local_image_no_reparse(const std::string& nt_path) {
    const NtCreateFileFn nt_create_file = resolve_ntcreatefile();
    if (nt_create_file == nullptr)
        return {};
    const std::wstring wide = utf8_to_wide(nt_path);
    // UNICODE_STRING::Length is a USHORT byte count: even, and at most 0xFFFE.
    const std::size_t bytes = wide.size() * sizeof(wchar_t);
    if (bytes == 0 || bytes > 0xFFFEU)
        return {};

    UNICODE_STRING name{};
    name.Length = static_cast<USHORT>(bytes);
    name.MaximumLength = name.Length;
    // const_cast proof: as OBJECT_ATTRIBUTES::ObjectName the Buffer is an INPUT NtCreateFile
    // never writes through (confined_fs_win.cpp make_unicode_string); `wide` outlives the call.
    name.Buffer = const_cast<PWSTR>(wide.c_str());

    OBJECT_ATTRIBUTES attrs{};
    attrs.Length = sizeof(attrs);
    attrs.ObjectName = &name;
    // OBJ_DONT_REPARSE: the open FAILS on a name-surrogate reparse point (symlink, junction)
    // instead of following it. A build that rejects the flag returns STATUS_INVALID_PARAMETER,
    // handled the same way: no handle, the row keeps an unknown verdict.
    attrs.Attributes = kObjCaseInsensitive | kObjDontReparse;

    HANDLE raw = nullptr;
    IO_STATUS_BLOCK iosb{};
    const NTSTATUS status = nt_create_file(
        &raw, FILE_GENERIC_READ, &attrs, &iosb, /*AllocationSize=*/nullptr, /*FileAttributes=*/0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, kFileOpen,
        kFileNonDirectoryFile | kFileSynchronousIoNonalert, /*EaBuffer=*/nullptr, /*EaLength=*/0);
    if (status < 0) {
        static std::atomic_flag warned;
        if (status == kStatusInvalidParameter && !warned.test_and_set()) {
            spdlog::warn("ECHO: module image open returned STATUS_INVALID_PARAMETER -- "
                         "OBJ_DONT_REPARSE unsupported on this Windows build? every module "
                         "signing verdict stays unknown (not counted risky)");
        }
        return {};
    }
    ImageHandle image{raw}; // own it immediately: no raw HANDLE survives this statement

    // Also refuse a name surrogate at the LEAF, from the open handle -- but only that:
    // filter-handled tags (WOF/CompactOS, dedup, cloud files) are ordinary images (precedent:
    // agents/shared/win_hive_file_probe.hpp leaf_facts).
    FILE_ATTRIBUTE_TAG_INFO tag{};
    if (!GetFileInformationByHandleEx(raw, FileAttributeTagInfo, &tag, sizeof(tag)))
        return {};
    if (reparse_leaf_refused(tag.FileAttributes, tag.ReparseTag))
        return {};
    return image;
}

std::int64_t image_mtime_unix(void* image) noexcept {
    BY_HANDLE_FILE_INFORMATION info{};
    if (image == nullptr || !GetFileInformationByHandle(static_cast<HANDLE>(image), &info))
        return 0;
    LARGE_INTEGER li;
    li.LowPart = info.ftLastWriteTime.dwLowDateTime;
    li.HighPart = static_cast<LONG>(info.ftLastWriteTime.dwHighDateTime);
    return filetime_to_unix(li);
}

// The real Windows verifier the drain injects. Verifies the OPEN handle (no name is
// re-resolved), maps the WinVerifyTrust verdict explicitly and NEVER fabricates kSigned: any
// unrecognised status is kUnknown. Signer is best-effort, only when signed.
ModuleSignVerdict verify_image_signature_win(void* image, const std::string& nt_path) {
    ModuleSignVerdict out; // {kUnknown, ""}
    // The path field is required. Authenticode on a PE reads the handle (the native parity case
    // passes a bogus name with a real handle and still gets kSigned); the path is a label, the
    // raw NT path kept alive across both calls.
    const std::wstring wpath = utf8_to_wide(nt_path);
    if (image == nullptr || wpath.empty()) {
        return out;
    }
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = wpath.c_str();
    fi.hFile = static_cast<HANDLE>(image);
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    // No per-load network CRL/OCSP fetch — revocation checking would do network
    // I/O on every image load, unacceptable for a high-volume source. Consequence:
    // WinVerifyTrust will not return CERT_E_REVOKED here, so the kRevoked verdict is
    // effectively unreachable via THIS path — the authoritative revoked/blocked
    // verdict comes from the M3 CodeIntegrity/Operational overlay (events 3033/3034).
    // Documented in docs/echo-module-loads.md §6.
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    const LONG st = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
    // WinVerifyTrust allocates the trust state even when the verdict is bad; free it on every
    // exit, including a throw from the signer read below (an allocation can throw).
    struct TrustStateCloser {
        TrustStateCloser(GUID& a, WINTRUST_DATA& d) noexcept : action_(a), data_(d) {}
        TrustStateCloser(const TrustStateCloser&) = delete;
        TrustStateCloser& operator=(const TrustStateCloser&) = delete;
        ~TrustStateCloser() {
            data_.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action_, &data_);
        }
        GUID& action_;
        WINTRUST_DATA& data_;
    } closer{action, wd};
    switch (st) {
    case ERROR_SUCCESS:
        out.state = ModuleSignedState::kSigned;
        break;
    case TRUST_E_NOSIGNATURE:
        out.state = ModuleSignedState::kUnsigned;
        break;
    case static_cast<LONG>(CERT_E_REVOKED):
        out.state = ModuleSignedState::kRevoked;
        break;
    case static_cast<LONG>(TRUST_E_BAD_DIGEST):
    case static_cast<LONG>(CERT_E_EXPIRED):
    case static_cast<LONG>(CERT_E_UNTRUSTEDROOT):
    case static_cast<LONG>(CERT_E_CHAINING):
    case static_cast<LONG>(TRUST_E_EXPLICIT_DISTRUST):
    case static_cast<LONG>(TRUST_E_SUBJECT_NOT_TRUSTED):
        out.state = ModuleSignedState::kInvalid;
        break;
    default:
        out.state = ModuleSignedState::kUnknown; // unrecognised — never assume signed
        break;
    }
    if (out.state == ModuleSignedState::kSigned) {
        // Signer = chain index 0 (the signing certificate) of the first signer, read BEFORE the
        // state is closed. A null at any step leaves "".
        if (CRYPT_PROVIDER_DATA* pd = WTHelperProvDataFromStateData(wd.hWVTStateData)) {
            if (CRYPT_PROVIDER_SGNR* sg = WTHelperGetProvSignerFromChain(pd, 0, FALSE, 0)) {
                if (CRYPT_PROVIDER_CERT* pc = WTHelperGetProvCertFromChain(sg, 0)) {
                    if (pc->pCert != nullptr)
                        out.signer = cert_simple_display_name(pc->pCert);
                }
            }
        }
    }
    return out;
}

struct ModuleEtwCollector::Impl {
    TRACEHANDLE session = 0;
    TRACEHANDLE consumer = INVALID_PROCESSTRACE_HANDLE;
    std::thread worker;
    std::wstring session_name;
    std::vector<BYTE> props_buf;
    ModuleEventRing* ring = nullptr;
    std::atomic<bool> running{false};

    // pid → owning-process basename, captured at load time (process usually
    // alive) so the row carries the loader even if it exits before drain.
    // Touched ONLY on the ProcessTrace consumer thread (callbacks are serial) —
    // no lock. Capped against unbounded growth.
    std::unordered_map<std::uint32_t, std::string> pid_name;
    static constexpr std::size_t kPidNameCap = 65536;

    // Idempotent RAII teardown (same shape + rationale as ProcEtwCollector::Impl):
    // unblock ProcessTrace, join the worker, stop the session — keyed on handle
    // validity so it is correct whether stop() was called or the session died.
    ~Impl() {
        running.store(false, std::memory_order_relaxed);
        if (consumer != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(consumer);
            consumer = INVALID_PROCESSTRACE_HANDLE;
        }
        if (worker.joinable()) {
            worker.join();
        }
        if (session != 0) {
            auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(props_buf.data());
            ControlTraceW(session, nullptr, props, EVENT_TRACE_CONTROL_STOP);
            session = 0;
        }
    }
    Impl() = default;
    Impl(const Impl&) = delete;
    Impl& operator=(const Impl&) = delete;

    // noexcept: runs across the ETW (C) ProcessTrace frame — an escaping C++
    // exception is UB. Catch-and-drop: a decode/alloc failure costs one event.
    static void WINAPI on_event(EVENT_RECORD* rec) noexcept {
        try {
            auto* self = static_cast<Impl*>(rec->UserContext);
            if (self == nullptr || self->ring == nullptr) {
                return;
            }
            if (!IsEqualGUID(rec->EventHeader.ProviderId, kKernelProcessGuid)) {
                return;
            }
            const USHORT id = rec->EventHeader.EventDescriptor.Id;
            if (id != kEventImageLoad && id != kEventImageUnload) {
                return;
            }
            EtwImageSample s;
            s.ts_unix = filetime_to_unix(rec->EventHeader.TimeStamp);
            if (s.ts_unix <= 0) {
                return; // corrupt/torn timestamp — never emit a bogus-dated row
            }
            s.is_load = (id == kEventImageLoad);
            // pid: prefer the decoded property, fall back to the event header.
            std::uint32_t pid = 0;
            if (!prop_u32(rec, L"ProcessID", pid)) {
                pid = rec->EventHeader.ProcessId;
            }
            s.pid = pid;
            // path: the image-load event names it "ImageName" (some builds
            // "FileName") — plural fallback, mirroring the process stop event's
            // ExitCode/ExitStatus pattern.
            s.image_path = prop_image_path(rec, L"ImageName");
            if (s.image_path.empty()) {
                s.image_path = prop_image_path(rec, L"FileName");
            }
            if (s.image_path.empty()) {
                return; // failed/torn decode — never an empty-path row
            }
            ModuleEvent ev = etw_image_sample_to_module_event(s);
            // Best-effort owning-process name (cached). Kernel loads (pid<=4)
            // have no user process to name.
            if (ev.pid != 0 && !ev.is_kernel) {
                auto it = self->pid_name.find(ev.pid);
                if (it == self->pid_name.end()) {
                    // The IMAGE session sees NO process-stop event to evict on, so
                    // bound the cache by flushing wholesale at the cap — this kills
                    // the past-cap naming blackout (a stop-inserting cap would leave
                    // every new pid unnamed once full). PID reuse can yield a brief
                    // stale name within a fill cycle: best-effort — $Process_Live is
                    // the authoritative pid→process record (cross-reference by pid+ts).
                    if (self->pid_name.size() >= kPidNameCap) {
                        self->pid_name.clear();
                    }
                    it = self->pid_name.emplace(ev.pid, process_basename_for_pid(ev.pid)).first;
                }
                ev.process_name = it->second;
            }
            // signed_state / signer + module_dir redaction happen at DRAIN, off
            // this thread (signing reads the file — too slow for the callback).
            self->ring->push(std::move(ev));
        } catch (...) {
            // Never let an exception unwind across the ETW C frame.
        }
    }
};

ModuleEtwCollector::ModuleEtwCollector(std::size_t ring_capacity) : ring_(ring_capacity) {}

ModuleEtwCollector::~ModuleEtwCollector() { stop(); }

bool ModuleEtwCollector::start() {
    if (impl_ && impl_->running.load()) {
        return false;
    }
    auto impl = std::make_unique<Impl>();
    impl->ring = &ring_;
    // Distinct session name (own session — see header). Keyed on pid so
    // concurrent agents / restarts don't collide; suffix distinguishes it from
    // the process collector's YuzuEchoProcEtw session on the same provider.
    impl->session_name = L"YuzuEchoModuleEtw-" + std::to_wstring(::GetCurrentProcessId());

    const size_t name_bytes = (impl->session_name.size() + 1) * sizeof(wchar_t);
    impl->props_buf.assign(sizeof(EVENT_TRACE_PROPERTIES) + name_bytes, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(impl->props_buf.data());
    props->Wnode.BufferSize = static_cast<ULONG>(impl->props_buf.size());
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 2; // system-time timestamps (FILETIME)
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer = 1;
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG rc = StartTraceW(&impl->session, impl->session_name.c_str(), props);
    if (rc == ERROR_ALREADY_EXISTS) {
        ControlTraceW(0, impl->session_name.c_str(),
                      reinterpret_cast<EVENT_TRACE_PROPERTIES*>(impl->props_buf.data()),
                      EVENT_TRACE_CONTROL_STOP);
        std::memset(impl->props_buf.data() + sizeof(EVENT_TRACE_PROPERTIES), 0, name_bytes);
        props->Wnode.BufferSize = static_cast<ULONG>(impl->props_buf.size());
        props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props->Wnode.ClientContext = 2;
        props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props->FlushTimer = 1;
        props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        rc = StartTraceW(&impl->session, impl->session_name.c_str(), props);
    }
    if (rc != ERROR_SUCCESS) {
        return false;
    }

    ENABLE_TRACE_PARAMETERS params{};
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    rc = EnableTraceEx2(impl->session, &kKernelProcessGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION, kKeywordImage, 0, 0, &params);
    if (rc != ERROR_SUCCESS) {
        return false; // ~Impl stops the session as `impl` unwinds
    }

    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(impl->session_name.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = &Impl::on_event;
    logfile.Context = impl.get();

    impl->consumer = OpenTraceW(&logfile);
    if (impl->consumer == INVALID_PROCESSTRACE_HANDLE) {
        return false; // ~Impl stops the session
    }

    Impl* raw = impl.get();
    raw->running.store(true);
    raw->worker = std::thread([raw]() {
        ProcessTrace(&raw->consumer, 1, nullptr, nullptr);
        raw->running.store(false, std::memory_order_relaxed);
    });

    impl_ = std::move(impl);
    return true;
}

void ModuleEtwCollector::stop() { impl_.reset(); }

bool ModuleEtwCollector::running() const noexcept { return impl_ && impl_->running.load(); }

std::vector<ModuleEvent> ModuleEtwCollector::drain() {
    auto evs = ring_.drain();
    for (auto& e : evs) {
        // Reconstruct the real full path for signing — module_dir is still the
        // UNREDACTED directory here (the mapping split it; we redact below,
        // AFTER verifying, so the cache key and WinVerifyTrust see the real file).
        std::string full = e.module_dir;
        if (!full.empty() && full.back() != '\\' && full.back() != '/') {
            full.push_back('\\');
        }
        full += e.module_name;
        // Not a local path (UNC / \Device\Mup / a network drive): the agent runs as LocalSystem,
        // so opening it would authenticate the machine account to that host and could stall this
        // drain (it runs under collect_mu_). Open NOTHING. For a local path: ONE open, following
        // no reparse point, by the NT path as delivered; mtime (cache key), verdict and signer
        // all come from this handle. No open (network path, vanished file, planted link,
        // unsupported flag) keeps the row with the unknown verdict the mapped event already
        // carries, which module_is_risky does not count.
        try {
            const ImageHandle img =
                image_path_is_local(full) ? open_local_image_no_reparse(full) : ImageHandle{};
            if (img) {
                const std::int64_t mtime = image_mtime_unix(img.get());
                const ModuleSignVerdict v = sign_cache_.get(full, mtime, [&](const std::string&) {
                    return verify_image_signature_win(img.get(), full);
                });
                e.signed_state = v.state;
                e.signer = v.signer;
            }
        } catch (...) {
            // An allocation failure while signing must not unwind drain() after ring_.drain()
            // emptied the ring, which would lose the whole batch: the verdict stays unknown and
            // the row is kept (the ETW callback drops the same way).
        }
        // Privacy edge-drop AFTER signing (governance BLOCKING): the stored dir
        // must never carry a username.
        e.module_dir = redact_module_dir(e.module_dir);
    }
    return evs;
}

std::uint64_t ModuleEtwCollector::dropped() const noexcept { return ring_.dropped(); }

} // namespace yuzu::echo

#else // !_WIN32 — no-op collector

namespace yuzu::echo {

struct ModuleEtwCollector::Impl {};

ModuleEtwCollector::ModuleEtwCollector(std::size_t ring_capacity) : ring_(ring_capacity) {}
ModuleEtwCollector::~ModuleEtwCollector() = default;

bool ModuleEtwCollector::start() { return false; }
void ModuleEtwCollector::stop() {}
bool ModuleEtwCollector::running() const noexcept { return false; }
std::vector<ModuleEvent> ModuleEtwCollector::drain() { return ring_.drain(); }
std::uint64_t ModuleEtwCollector::dropped() const noexcept { return ring_.dropped(); }

} // namespace yuzu::echo

#endif // _WIN32
