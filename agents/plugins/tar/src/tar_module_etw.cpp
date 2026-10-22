/**
 * tar_module_etw.cpp — ETW Kernel-Process IMAGE-keyword consumer (see header).
 *
 * Cross-platform section (top): the pure ETW-sample → ModuleEvent mapping and
 * the signing-verdict cache — compiled and unit-tested on every platform.
 *
 * Windows section (#ifdef _WIN32): a real-time ETW session on
 * Microsoft-Windows-Kernel-Process with the IMAGE keyword, ProcessTrace on a
 * dedicated thread, TDH decode of image load (5) / unload (6) by property name,
 * signing resolved at drain via WinVerifyTrust + CryptQueryObject. Mirrors
 * tar_proc_etw.cpp.
 *
 * Off-Windows: every method is a no-op; start() returns false.
 */

#include "tar_module_etw.hpp"

namespace yuzu::tar {

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

} // namespace yuzu::tar

#ifdef _WIN32

// windows.h and the ETW/TDH/WinTrust headers are confined to this TU (mirrors
// tar_proc_etw.cpp). NOTE: the small TDH/time/RAII helpers below are kept
// self-contained here rather than shared with tar_proc_etw.cpp — extracting a
// common tar_etw_util would mean a blind refactor of the shipped process
// collector on a host that cannot compile MSVC. Consolidation is a tracked
// follow-up for a Windows-capable session (different TUs → internal linkage, no
// ODR conflict in the meantime).
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// <evntcons.h>/<evntrace.h> must follow windows.h; <tdh.h> follows those.
#include <evntcons.h>
#include <evntrace.h>
#include <tdh.h>
// Signing: WinVerifyTrust (softpub action GUID) + CryptQueryObject signer walk.
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)

#include <atomic>
#include <cstring> // std::memset (stale-session props reset)
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "tar_local_image_path.hpp" // refuse network-path images (see image_path_is_local)

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace yuzu::tar {

static_assert(kDriveTypeFixed == DRIVE_FIXED);

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
// duplicated WideCharToMultiByte boilerplate while keeping these tar-local
// signatures (std::string / std::wstring) and call sites unchanged. Both the old
// local copies and the shared helper treat the input as NUL-terminated, so the
// conversion is behaviour-identical for the (NUL-free) paths this collector handles.
std::wstring utf8_to_wide(const std::string& s) { return yuzu::win::to_wide(s); }

// The Kernel-Process IMAGE event delivers ImageName as an NT object-manager
// device path (\Device\HarddiskVolumeN\...). WinVerifyTrust and GetFileAttributesExW
// both REJECT NT paths, so without this conversion every signing verdict would be
// kUnknown (governance HIGH). \\?\GLOBALROOT exposes the NT object namespace to the
// Win32 file APIs: \\?\GLOBALROOT\Device\HarddiskVolumeN\... is accepted by
// CreateFile and the trust/crypt file readers. Drive-letter and already-\\?\-prefixed
// paths pass through unchanged. UTF-8 in/out (the verifier widens). Runbook-verified.
std::string nt_path_to_win32(const std::string& p) {
    if (p.rfind("\\Device\\", 0) == 0) {
        return "\\\\?\\GLOBALROOT" + p;
    }
    return p;
}

std::string wide_to_utf8(const std::wstring& w) { return yuzu::win::from_wide(w.c_str()); }

// True when `p` (UTF-8, as delivered, BEFORE nt_path_to_win32) is a local path (an NT
// volume path, or a drive letter on a fixed drive) and so safe to hand to the file/trust
// APIs; see tar_local_image_path.hpp. The only Windows API here is GetDriveTypeW on the
// 3-char drive root (drive-letter forms only).
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

// RAII for a Win32 HANDLE.
struct HandleGuard {
    HANDLE h{nullptr};
    explicit HandleGuard(HANDLE handle) noexcept : h(handle) {}
    ~HandleGuard() {
        if (h != nullptr && h != INVALID_HANDLE_VALUE) {
            CloseHandle(h);
        }
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
};

// Best-effort owning-process basename for a (usually still-alive) pid. Cached by
// the caller so QueryFullProcessImageName runs ~once per pid. "" for
// protected/exited processes (mirrors the process collector's capture_sid).
std::string process_basename_for_pid(std::uint32_t pid) {
    HandleGuard proc{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (proc.h == nullptr) {
        return {};
    }
    wchar_t buf[MAX_PATH];
    DWORD len = MAX_PATH;
    if (!QueryFullProcessImageNameW(proc.h, 0, buf, &len) || len == 0) {
        return {};
    }
    std::wstring path(buf, len);
    auto pos = path.find_last_of(L"\\/");
    std::wstring base = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    return wide_to_utf8(base);
}

// Last-write time of a file as unix seconds, for the SigningCache key. 0 if the
// path can't be stat'd (e.g. an NT \Device\... path WinVerifyTrust also rejects).
std::int64_t file_mtime_unix(const std::wstring& wpath) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(wpath.c_str(), GetFileExInfoStandard, &fad)) {
        return 0;
    }
    LARGE_INTEGER li;
    li.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    li.HighPart = static_cast<LONG>(fad.ftLastWriteTime.dwHighDateTime);
    return filetime_to_unix(li);
}

// Best-effort Authenticode publisher CN for an embedded-signed image. "" on any
// failure — never throws, never blocks the verdict. All Crypt* handles are freed
// on every path.
std::string extract_signer_cn(const std::wstring& wpath) {
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    DWORD enc = 0, ctype = 0, fmt = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &ctype, &fmt, &store, &msg,
                          nullptr)) {
        return {};
    }
    std::string out;
    DWORD si_size = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, nullptr, &si_size) && si_size > 0) {
        std::vector<BYTE> si_buf(si_size);
        if (CryptMsgGetParam(msg, CMSG_SIGNER_CERT_INFO_PARAM, 0, si_buf.data(), &si_size)) {
            auto* signer = reinterpret_cast<CERT_INFO*>(si_buf.data());
            PCCERT_CONTEXT cert =
                CertFindCertificateInStore(store, enc, 0, CERT_FIND_SUBJECT_CERT, signer, nullptr);
            if (cert != nullptr) {
                DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                             nullptr, 0);
                if (n > 1) {
                    std::wstring name(n - 1, L'\0');
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name.data(),
                                       n);
                    out = wide_to_utf8(name);
                }
                CertFreeCertificateContext(cert);
            }
        }
    }
    if (msg != nullptr)
        CryptMsgClose(msg);
    if (store != nullptr)
        CertCloseStore(store, 0);
    return out;
}

// The real Windows verifier (the ModuleVerifier the drain injects). Maps the
// WinVerifyTrust verdict explicitly and NEVER fabricates kSigned: any
// unrecognised status is kUnknown. Signer is best-effort, only when signed.
ModuleSignVerdict verify_image_signature_win(const std::string& full_path_utf8) {
    ModuleSignVerdict out; // {kUnknown, ""}
    std::wstring wpath = utf8_to_wide(full_path_utf8);
    if (wpath.empty()) {
        return out;
    }
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = wpath.c_str();
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    // No per-load network CRL/OCSP fetch — revocation checking would do network
    // I/O on every image load, unacceptable for a high-volume source. Consequence:
    // WinVerifyTrust will not return CERT_E_REVOKED here, so the kRevoked verdict is
    // effectively unreachable via THIS path — the authoritative revoked/blocked
    // verdict comes from the M3 CodeIntegrity/Operational overlay (events 3033/3034).
    // Documented in docs/tar-module-loads.md §6.
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    const LONG st = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);
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
    wd.dwStateAction = WTD_STATEACTION_CLOSE; // free the trust state
    WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &action, &wd);

    if (out.state == ModuleSignedState::kSigned) {
        out.signer = extract_signer_cn(wpath);
    }
    return out;
}

} // namespace

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
    // the process collector's YuzuTarProcEtw session on the same provider.
    impl->session_name = L"YuzuTarModuleEtw-" + std::to_wstring(::GetCurrentProcessId());

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
        if (!image_path_is_local(full)) {
            // Not a local path (UNC / \Device\Mup / a network drive): the agent runs
            // as LocalSystem, so opening it would authenticate the machine account to that
            // host and could stall this drain (it runs under collect_mu_). Open NOTHING (not
            // even GetFileAttributesExW): keep the row with an unknown verdict.
            e.signed_state = ModuleSignedState::kUnknown;
            e.signer.clear();
        } else {
            // Convert the NT device path to a Win32 path the file/trust APIs accept
            // (governance HIGH) — used for stat, verify, AND the cache key (so the
            // key is the path actually verified).
            const std::string vpath = nt_path_to_win32(full);
            const std::wstring wvpath = utf8_to_wide(vpath);
            const std::int64_t mtime = wvpath.empty() ? 0 : file_mtime_unix(wvpath);
            const ModuleSignVerdict v = sign_cache_.get(vpath, mtime, &verify_image_signature_win);
            e.signed_state = v.state;
            e.signer = v.signer;
        }
        // Privacy edge-drop AFTER signing (governance BLOCKING): the stored dir
        // must never carry a username.
        e.module_dir = redact_module_dir(e.module_dir);
    }
    return evs;
}

std::uint64_t ModuleEtwCollector::dropped() const noexcept { return ring_.dropped(); }

} // namespace yuzu::tar

#else // !_WIN32 — no-op collector

namespace yuzu::tar {

struct ModuleEtwCollector::Impl {};

ModuleEtwCollector::ModuleEtwCollector(std::size_t ring_capacity) : ring_(ring_capacity) {}
ModuleEtwCollector::~ModuleEtwCollector() = default;

bool ModuleEtwCollector::start() { return false; }
void ModuleEtwCollector::stop() {}
bool ModuleEtwCollector::running() const noexcept { return false; }
std::vector<ModuleEvent> ModuleEtwCollector::drain() { return ring_.drain(); }
std::uint64_t ModuleEtwCollector::dropped() const noexcept { return ring_.dropped(); }

} // namespace yuzu::tar

#endif // _WIN32
