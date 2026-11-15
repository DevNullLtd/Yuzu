/**
 * echo_proc_etw.cpp — ETW Kernel-Process consumer (see echo_proc_etw.hpp).
 *
 * Windows: opens a real-time ETW session on Microsoft-Windows-Kernel-Process,
 * runs ProcessTrace on a dedicated thread, decodes start (1) / stop (2) events
 * via TDH (by property name, so it survives manifest layout differences across
 * Windows builds), and pushes ProcEvents into the bounded ring.
 *
 * Off-Windows: every method is a no-op; start() returns false.
 */

#include "echo_proc_etw.hpp"

// ProcEventRing / ProcEvent live in echo_proc_stream.{hpp,cpp}, shared with the
// macOS Endpoint Security collector.

#ifdef _WIN32

// windows.h and the ETW/TDH headers are confined to this translation unit.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// <evntrace.h>/<evntcons.h> must follow windows.h; <tdh.h> follows those.
#include <evntcons.h>
#include <evntrace.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <sddl.h> // ConvertSidToStringSidA / ConvertStringSidToSidA
#include <tdh.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>
#include <unordered_map>
#include <utility> // std::move (used below; no longer pulled in via echo_proc_stream)
#include <vector>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

namespace yuzu::echo {
namespace {

// Microsoft-Windows-Kernel-Process: {22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}
constexpr GUID kKernelProcessGuid = {
    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

// WINEVENT_KEYWORD_PROCESS — start/stop events only (not thread/image/CPU).
constexpr ULONGLONG kKeywordProcess = 0x10;

constexpr USHORT kEventProcessStart = 1;
constexpr USHORT kEventProcessStop = 2;

// FILETIME (100 ns since 1601) → unix seconds. Wnode.ClientContext = 2 makes
// EVENT_HEADER.TimeStamp a system-time FILETIME, so this is a plain rebase.
std::int64_t filetime_to_unix(LARGE_INTEGER ft) {
    constexpr std::int64_t kEpochDelta = 116444736000000000LL; // 1601→1970 in 100ns
    // A corrupt/torn .etl record (or a pre-1970 FILETIME) underflows the rebase to
    // a bogus ancient/negative timestamp; return 0 so callers can reject ts <= 0
    // rather than persist a row dated to 1601 (or worse, slip one past a
    // `ts < cutoff` filter).
    if (ft.QuadPart < kEpochDelta) {
        return 0;
    }
    return (ft.QuadPart - kEpochDelta) / 10000000LL;
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

// Read a named Unicode-string property and return its basename, UTF-8.
std::string prop_image_basename(EVENT_RECORD* rec, const wchar_t* name) {
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
    std::wstring path(buf.data());
    // Basename: strip everything through the last separator (handles both the
    // \Device\HarddiskVolumeN\... NT form and normal drive paths).
    auto pos = path.find_last_of(L"\\/");
    std::wstring base = (pos == std::wstring::npos) ? path : path.substr(pos + 1);
    if (base.empty()) {
        return {};
    }
    return yuzu::win::from_wide(base.c_str()); // (#1681) -1 convert, trailing NUL dropped
}

// RAII for a Win32 HANDLE: closes on scope exit. Keeps capture_sid exception-
// safe — an allocation (std::vector / std::string) between OpenProcess and a
// manual CloseHandle would otherwise leak the handle if it threw.
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

// RAII for a LocalAlloc'd buffer (ConvertSidToStringSid / ConvertStringSidToSid
// hand back LocalAlloc memory freed with LocalFree).
struct LocalMemGuard {
    void* p{nullptr};
    explicit LocalMemGuard(void* ptr) noexcept : p(ptr) {}
    ~LocalMemGuard() {
        if (p != nullptr) {
            LocalFree(p);
        }
    }
    LocalMemGuard(const LocalMemGuard&) = delete;
    LocalMemGuard& operator=(const LocalMemGuard&) = delete;
};

// Capture the owning user's SID (string form) for a just-started, still-alive
// process. All-local/fast (OpenProcess + token query + SID→string) — no domain
// round-trip; that costly step is deferred to drain. "" for protected/system
// processes or a pid that already exited (best-effort, mirrors the poll).
std::string capture_sid(std::uint32_t pid) {
    HandleGuard proc{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (proc.h == nullptr) {
        return {};
    }
    HANDLE token_raw = nullptr;
    if (!OpenProcessToken(proc.h, TOKEN_QUERY, &token_raw)) {
        return {};
    }
    HandleGuard token{token_raw};
    std::string sid;
    DWORD need = 0;
    GetTokenInformation(token.h, TokenUser, nullptr, 0, &need);
    if (need > 0) {
        std::vector<BYTE> buf(need);
        if (GetTokenInformation(token.h, TokenUser, buf.data(), need, &need)) {
            auto* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
            LPSTR str = nullptr;
            if (ConvertSidToStringSidA(tu->User.Sid, &str) && str != nullptr) {
                LocalMemGuard g{str};
                sid.assign(str);
            }
        }
    }
    return sid;
}

// Resolve a SID string to "DOMAIN\\account". The one possibly-networked call
// (LookupAccountSid); callers cache by SID so it runs ~once per distinct user.
std::string sid_to_account(const std::string& sid_str) {
    if (sid_str.empty()) {
        return {};
    }
    PSID sid = nullptr;
    if (!ConvertStringSidToSidA(sid_str.c_str(), &sid) || sid == nullptr) {
        return {};
    }
    LocalMemGuard g{sid};
    char name[256] = {0};
    char domain[256] = {0};
    DWORD name_len = sizeof(name);
    DWORD domain_len = sizeof(domain);
    SID_NAME_USE use{};
    std::string out;
    if (LookupAccountSidA(nullptr, sid, name, &name_len, domain, &domain_len, &use)) {
        out = (domain[0] != '\0') ? (std::string(domain) + "\\" + name) : std::string(name);
    }
    return out;
}

} // namespace

struct ProcEtwCollector::Impl {
    TRACEHANDLE session = 0;                              // from StartTrace
    TRACEHANDLE consumer = INVALID_PROCESSTRACE_HANDLE;   // from OpenTrace
    std::thread worker;                                   // runs ProcessTrace
    std::wstring session_name;
    std::vector<BYTE> props_buf;                          // EVENT_TRACE_PROPERTIES + name
    ProcEventRing* ring = nullptr;
    std::atomic<bool> running{false};

    // pid → {SID, name}, captured at start so the stop event (process already
    // dead, and its own name field is unreliably encoded) can carry the same
    // user AND name. Touched ONLY on the ProcessTrace consumer thread (callbacks
    // are serial) — no lock needed. Best-effort + capped against orphaned
    // entries from missed stops.
    struct ProcIdent {
        std::string sid;
        std::string name;
        std::uint32_t ppid{0};
    };
    std::unordered_map<std::uint32_t, ProcIdent> pid_info;
    static constexpr std::size_t kPidSidCap = 65536;

    // Idempotent RAII teardown: unblock ProcessTrace, join the worker, stop the
    // session. Keyed on handle/thread VALIDITY (not `running`, which the worker
    // clears on session death) so it runs correctly whether stop() was called or
    // the session died on its own. This is also the cleanup path if start()
    // throws between acquiring the session/consumer and publishing impl_ (e.g. a
    // std::thread ctor OOM) — without it the PID-named session + consumer would
    // leak and the slot would never be reclaimed (ETW slot exhaustion).
    ~Impl() {
        running.store(false, std::memory_order_relaxed);
        if (consumer != INVALID_PROCESSTRACE_HANDLE) {
            CloseTrace(consumer); // unblocks ProcessTrace if still running
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

    // SID → "DOMAIN\\account" cache. Touched ONLY on the drain thread
    // (resolve_users, under the plugin's collect mutex) — no lock needed. Keeps
    // the costly LookupAccountSid to ~once per distinct user.
    std::unordered_map<std::string, std::string> sid_name;

    // Drain-thread: fill each event's `user` from its `sid` via the cache.
    void resolve_users(std::vector<ProcEvent>& evs) {
        for (auto& e : evs) {
            if (e.sid.empty()) {
                continue;
            }
            auto it = sid_name.find(e.sid);
            if (it == sid_name.end()) {
                it = sid_name.emplace(e.sid, sid_to_account(e.sid)).first;
            }
            e.user = it->second;
        }
    }

    // noexcept: invoked across the ETW (C) ProcessTrace frame, where an escaping
    // C++ exception is undefined behaviour. Catch-and-drop — an allocation
    // failure (decode buffers, map insert) costs one event, never the agent.
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
            if (id != kEventProcessStart && id != kEventProcessStop) {
                return;
            }
            ProcEvent ev;
            ev.ts_unix = filetime_to_unix(rec->EventHeader.TimeStamp);
            if (ev.ts_unix <= 0) {
                return; // corrupt/torn timestamp — never emit a bogus-dated row
            }
            ev.is_start = (id == kEventProcessStart);
            prop_u32(rec, L"ProcessID", ev.pid);
            if (ev.pid == 0) {
                return; // failed/torn TDH decode — pid 0 is never a real process
            }
            if (ev.is_start) {
                // Decode the name from the start event (Unicode here). Capture
                // the SID while the process is (usually) still alive. Remember
                // pid→{sid,name,ppid} so the matching stop — process gone, and
                // its own name field unreliably encoded — reuses all three.
                ev.image_name = prop_image_basename(rec, L"ImageName");
                prop_u32(rec, L"ParentProcessID", ev.ppid);
                ev.sid = capture_sid(ev.pid);
                if (self->pid_info.size() < kPidSidCap) {
                    self->pid_info[ev.pid] = {ev.sid, ev.image_name, ev.ppid};
                }
            } else {
                std::uint32_t code = 0;
                // Manifest names the field "ExitCode"; fall back to "ExitStatus".
                if (prop_u32(rec, L"ExitCode", code) || prop_u32(rec, L"ExitStatus", code)) {
                    ev.exit_code = static_cast<std::int32_t>(code);
                }
                // Recover name + SID + ppid from the cached start. Empty/0 for a
                // process that started before our session (boot-gap → thread 1b
                // AutoLogger).
                auto it = self->pid_info.find(ev.pid);
                if (it != self->pid_info.end()) {
                    ev.image_name = it->second.name;
                    ev.sid = it->second.sid;
                    ev.ppid = it->second.ppid;
                    self->pid_info.erase(it);
                }
            }
            // user (SID→name) is resolved at drain, off this thread (keeps the
            // callback cheap and the costly lookup cached).
            self->ring->push(std::move(ev));
        } catch (...) {
            // Never let an exception unwind across the ETW C frame.
        }
    }
};

ProcEtwCollector::ProcEtwCollector(std::size_t ring_capacity) : ring_(ring_capacity) {}

ProcEtwCollector::~ProcEtwCollector() { stop(); }

bool ProcEtwCollector::start() {
    if (impl_ && impl_->running.load()) {
        return false;
    }
    auto impl = std::make_unique<Impl>();
    impl->ring = &ring_;
    // Unique-ish session name so concurrent agents / restarts don't collide.
    impl->session_name = L"YuzuEchoProcEtw-" + std::to_wstring(::GetCurrentProcessId());

    const size_t name_bytes = (impl->session_name.size() + 1) * sizeof(wchar_t);
    impl->props_buf.assign(sizeof(EVENT_TRACE_PROPERTIES) + name_bytes, 0);
    auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(impl->props_buf.data());
    props->Wnode.BufferSize = static_cast<ULONG>(impl->props_buf.size());
    props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    props->Wnode.ClientContext = 2; // system-time timestamps (FILETIME)
    props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    props->FlushTimer = 1; // flush every 1s so low-volume events deliver promptly
    props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG rc = StartTraceW(&impl->session, impl->session_name.c_str(), props);
    if (rc == ERROR_ALREADY_EXISTS) {
        // Stale session from a crashed predecessor — stop and retry once.
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
    rc = EnableTraceEx2(impl->session, &kKernelProcessGuid,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                        kKeywordProcess, 0, 0, &params);
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
        return false; // ~Impl stops the session as `impl` unwinds
    }

    Impl* raw = impl.get();
    raw->running.store(true);
    // If the std::thread ctor throws here (OOM / EAGAIN), `impl` unwinds and
    // ~Impl stops the session + closes the consumer — no leak.
    raw->worker = std::thread([raw]() {
        // Blocks until CloseTrace() is called from stop()/~Impl — or returns on
        // its own if the session dies (another tool stops it, buffer loss, …).
        // Either way, mark not-running so the plugin can detect a dead session
        // and fall back to the poll instead of going silently blind.
        ProcessTrace(&raw->consumer, 1, nullptr, nullptr);
        raw->running.store(false, std::memory_order_relaxed);
    });

    impl_ = std::move(impl);
    return true;
}

void ProcEtwCollector::stop() {
    // ~Impl performs the idempotent teardown (CloseTrace + join the worker +
    // ControlTrace STOP), keyed on handle validity so it is correct whether we
    // are stopping a live session or one that already died on its own (in which
    // case the worker has cleared `running` and exited). Safe if never started.
    impl_.reset();
}

bool ProcEtwCollector::running() const noexcept {
    return impl_ && impl_->running.load();
}

std::vector<ProcEvent> ProcEtwCollector::drain() {
    auto evs = ring_.drain();
    if (impl_) {
        impl_->resolve_users(evs); // SID→name (cached) off the ETW thread
    }
    return evs;
}

std::uint64_t ProcEtwCollector::dropped() const noexcept { return ring_.dropped(); }

namespace {

// Consumer state for a one-shot file replay (the boot AutoLogger's .etl).
struct BackfillCtx {
    std::vector<ProcEvent>* out{nullptr};
    std::int64_t before_ts{0};
    std::unordered_map<std::uint32_t, std::string> pid_name; // start→stop name recovery
};

// Bound replay memory (output vector + name-recovery map) against an oversized or
// crafted .etl — the agent data dir is writable by the service account, so a
// replaced/huge file must not grow memory without limit during init(). Mirrors
// the live ring's kPidSidCap posture; silently truncates past the cap.
constexpr std::size_t kBackfillCap = 65536;

// noexcept: invoked across the ETW (C) ProcessTrace frame during file replay,
// same UB-on-throw constraint as on_event. Catch-and-drop.
void WINAPI backfill_cb(EVENT_RECORD* rec) noexcept {
    try {
        auto* ctx = static_cast<BackfillCtx*>(rec->UserContext);
        if (ctx == nullptr || ctx->out == nullptr) {
            return;
        }
        if (!IsEqualGUID(rec->EventHeader.ProviderId, kKernelProcessGuid)) {
            return;
        }
        const USHORT id = rec->EventHeader.EventDescriptor.Id;
        if (id != kEventProcessStart && id != kEventProcessStop) {
            return;
        }
        ProcEvent ev;
        ev.ts_unix = filetime_to_unix(rec->EventHeader.TimeStamp);
        if (ev.ts_unix <= 0 || ev.ts_unix >= ctx->before_ts) {
            return; // <=0: corrupt/torn timestamp; >=before_ts: the live session owns it
        }
        ev.is_start = (id == kEventProcessStart);
        prop_u32(rec, L"ProcessID", ev.pid);
        if (ev.pid == 0) {
            return; // failed/torn TDH decode (corrupt .etl record) — drop it
        }
        if (ctx->out->size() >= kBackfillCap) {
            return; // replay output bounded — silently truncate an oversized .etl
        }
        if (ev.is_start) {
            ev.image_name = prop_image_basename(rec, L"ImageName");
            prop_u32(rec, L"ParentProcessID", ev.ppid);
            if (ctx->pid_name.size() < kBackfillCap) {
                ctx->pid_name[ev.pid] = ev.image_name;
            }
        } else {
            std::uint32_t code = 0;
            if (prop_u32(rec, L"ExitCode", code) || prop_u32(rec, L"ExitStatus", code)) {
                ev.exit_code = static_cast<std::int32_t>(code);
            }
            auto it = ctx->pid_name.find(ev.pid);
            if (it != ctx->pid_name.end()) {
                ev.image_name = it->second;
                ctx->pid_name.erase(it);
            }
        }
        // No user for boot-backfill — the process is gone by replay time.
        ctx->out->push_back(std::move(ev));
    } catch (...) {
        // Never let an exception unwind across the ETW C frame.
    }
}

} // namespace

std::vector<ProcEvent> backfill_proc_events_from_etl(const std::string& etl_path,
                                                     std::int64_t before_ts_unix) {
    std::vector<ProcEvent> out;
    if (etl_path.empty()) {
        return out;
    }
    // (#1681) etl_path is non-empty (guarded above); only wpath.c_str() is consumed.
    const std::wstring wpath = yuzu::win::to_wide(etl_path);
    if (wpath.empty()) {
        return out;
    }

    // The AutoLogger may still be running and holding this .etl open — that is
    // fine: OpenTrace reads an actively-written file as long as the logger
    // flushes its buffers to disk (the AutoLogger MUST be configured with a
    // FlushTimer; without it the buffers never reach the file and this replay
    // sees nothing). No session stop / no elevation required — the narrow agent
    // account only needs read access to its own data dir.

    BackfillCtx ctx;
    ctx.out = &out;
    ctx.before_ts = before_ts_unix;

    EVENT_TRACE_LOGFILEW lf{};
    lf.LogFileName = const_cast<LPWSTR>(wpath.c_str());
    lf.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD; // file mode (no real-time)
    lf.EventRecordCallback = &backfill_cb;
    lf.Context = &ctx;

    TRACEHANDLE h = OpenTraceW(&lf);
    if (h == INVALID_PROCESSTRACE_HANDLE) {
        return out; // missing / unreadable / wrong format
    }
    ProcessTrace(&h, 1, nullptr, nullptr); // replays the whole file, returns at EOF
    CloseTrace(h);
    return out;
}

std::int64_t boot_time_unix() {
    // boot ≈ now - uptime. GetTickCount64 is ms of uptime; floor the result to
    // the minute so sub-second measurement jitter doesn't change the key across
    // restarts within a boot, while the prior boot's uptime (>> 60s) keeps boots
    // distinct. (Sleep is excluded from uptime — see the header note on the
    // bounded re-backfill edge.)
    const std::int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
    const std::int64_t uptime_s = static_cast<std::int64_t>(GetTickCount64() / 1000ULL);
    const std::int64_t boot = now - uptime_s;
    return (boot / 60) * 60;
}

} // namespace yuzu::echo

#else // !_WIN32 — no-op collector

namespace yuzu::echo {

struct ProcEtwCollector::Impl {};

ProcEtwCollector::ProcEtwCollector(std::size_t ring_capacity) : ring_(ring_capacity) {}
ProcEtwCollector::~ProcEtwCollector() = default;

bool ProcEtwCollector::start() { return false; }
void ProcEtwCollector::stop() {}
bool ProcEtwCollector::running() const noexcept { return false; }
std::vector<ProcEvent> ProcEtwCollector::drain() { return ring_.drain(); }
std::uint64_t ProcEtwCollector::dropped() const noexcept { return ring_.dropped(); }

std::vector<ProcEvent> backfill_proc_events_from_etl(const std::string&, std::int64_t) {
    return {}; // no ETW off-Windows
}

std::int64_t boot_time_unix() { return 0; } // backfill is a no-op off-Windows

} // namespace yuzu::echo

#endif // _WIN32
