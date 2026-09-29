// Spark rung-2 resource gate - external, PID-targeted sampler.
//
// Committed 2026-08-18 (F11, #2298; D1 ruling 2026-08-05: port-lite) - previously a
// local-only spike on the DGRHP rig, same posture as tpwait_spike.cpp. Not meson-wired:
// Windows-only (Win32/PDH), no Linux path, rebuilt via the one-line cl.exe command below
// as needed - see stage11-resource-gate-runbook.md alongside this file.
//
// Grill session 2026-07-13 (memory project-spark-rung2-plan.md) settled the
// rung-2 resource gate: legacy vs spark, back-to-back on ONE Windows rig,
// fixed armed load N=20 registry + 20 file + 20 service guards, sampling
// thread count + handle/fd count + RSS + wakeups/sec + idle CPU%. No harness
// existed for this - docs/spark-rebuild-baselines/stage0-resource-baseline.md
// scoped the metrics and gotchas but the tool was never built. This is that
// tool.
//
// Deliberately generic: takes a target PID and samples it from the outside.
// No link against any Yuzu source - works against a legacy agent, a spark
// agent, or anything else, on any branch. The load itself (arming 20/20/20
// guards) is a separate concern, driven through the real product surface
// (a Guardian Baseline push) - see the runbook doc alongside this file.
//
// Metric notes (methodology per stage0-resource-baseline.md):
//   - thread count: CreateToolhelp32Snapshot/Thread32First/Next, same
//     technique as tpwait_spike.cpp's current_process_thread_count(), just
//     generalized to an arbitrary PID instead of GetCurrentProcessId().
//   - handle count: GetProcessHandleCount(). REQUIRED, not optional - a
//     naive spark port could collapse threads while leaving one bus
//     connection + eventfd/handle per unit, a partial win thread count alone
//     would hide (this is exactly the systemd-guard risk flagged in the
//     baseline doc; the Windows analogue is SCM notification handles).
//   - RSS: GetProcessMemoryInfo().WorkingSetSize.
//   - idle CPU%: GetProcessTimes() kernel+user delta over the wall-clock
//     delta, UNBOUNDED per-process (100% = one full core busy, 200% = two
//     full cores, etc. - never divided by core count), matching how the
//     Linux side (ps/top convention) would report it.
//   - wakeups/sec: PDH \Thread(*)\Context Switches/sec, summed across every
//     thread instance whose \Thread(*)\ID Process matches the target PID.
//     Chosen over an internal TP-callback counter (spark_engine.cpp has one)
//     because the legacy side has no equivalent internal counter to compare
//     against - an OS-level count is the only thing measurable on BOTH
//     configurations without instrumenting legacy code. This is the direct
//     Windows analogue of the Linux proxy the baseline doc names
//     (voluntary_ctxt_switches + nonvoluntary_ctxt_switches delta).
//
// Gotcha carried over from the baseline doc: a live agent's gRPC reconnect
// backoff loop adds wakeup noise if it can't reach a server. Sample against
// the SAME connectivity state (both reachable, or both consistently
// unreachable) for legacy and spark runs - never one connected and the other
// not, or the delta is contaminated.
//
// Build (MSVC Developer environment, per docs/windows-build.md /
// project-dgrhp-windows-rig memory):
//   cl /EHsc /std:c++20 /W4 resource_sampler.cpp Advapi32.lib Psapi.lib Pdh.lib /Fe:resource_sampler.exe
//
// Usage:
//   resource_sampler.exe <pid> [duration_sec=120] [interval_sec=5] [out.csv]
// With no output path, CSV goes to stdout. Ctrl+C stops early and still
// prints the steady-state summary over whatever samples were collected.
//
// Steady-state summary drops the first 2 samples (warm-up: process/query
// startup transients, first PDH collect has no rate yet) and averages the
// rest - paste straight into the 2b PR gate-evidence table.

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <pdh.h>
#include <pdhmsg.h>

#include <atomic>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Pdh.lib")

namespace {

std::atomic<bool> g_stop{false};

// RAII owner for a nullptr-sentinel owning HANDLE (target-process HANDLE,
// privilege token) - CloseHandle on every exit path, never leaving a future
// early return to remember it manually (governance Gate 3 finding,
// 2026-08-18: manual cleanup here already leaked once before this file was
// even committed, per the adversarial-review fix earlier the same day -
// reordering acquire-after-fallible-open fixed that ONE path; this closes
// the underlying pattern-fragility rather than the one instance).
class UniqueProcessHandle {
public:
    explicit UniqueProcessHandle(HANDLE h = nullptr) noexcept : h_(h) {}
    ~UniqueProcessHandle() { if (h_) CloseHandle(h_); }
    UniqueProcessHandle(const UniqueProcessHandle&) = delete;
    UniqueProcessHandle& operator=(const UniqueProcessHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ != nullptr; }

private:
    HANDLE h_;
};

// RAII owner for the output FILE* - fclose on every exit path, EXCEPT when
// aliased to stdout (never owned, never closed - matches the pre-existing
// `out != stdout` guard this replaces).
class UniqueOutFile {
public:
    explicit UniqueOutFile(FILE* f) noexcept : f_(f) {}
    ~UniqueOutFile() { if (f_ && f_ != stdout) fclose(f_); }
    UniqueOutFile(const UniqueOutFile&) = delete;
    UniqueOutFile& operator=(const UniqueOutFile&) = delete;
    [[nodiscard]] FILE* get() const noexcept { return f_; }

private:
    FILE* f_;
};

// RAII owner for a HANDLE whose failure sentinel is INVALID_HANDLE_VALUE, not
// nullptr - CreateToolhelp32Snapshot's convention, distinct from
// UniqueProcessHandle's OpenProcess/OpenProcessToken nullptr convention above
// (PR #3267 review, fjarvis: the RAII floor landed on hproc/out but stopped
// short of the token and snapshot handles below).
class UniqueSnapshotHandle {
public:
    explicit UniqueSnapshotHandle(HANDLE h = INVALID_HANDLE_VALUE) noexcept : h_(h) {}
    ~UniqueSnapshotHandle() { if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_); }
    UniqueSnapshotHandle(const UniqueSnapshotHandle&) = delete;
    UniqueSnapshotHandle& operator=(const UniqueSnapshotHandle&) = delete;
    [[nodiscard]] HANDLE get() const noexcept { return h_; }
    explicit operator bool() const noexcept { return h_ != INVALID_HANDLE_VALUE; }

private:
    HANDLE h_;
};

BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT) {
        g_stop.store(true, std::memory_order_relaxed);
        return TRUE;
    }
    return FALSE;
}

// Best-effort: the target may run under a different account (the agent runs
// as a service - docs/agent-privilege-model.md). SeDebugPrivilege lets an
// elevated admin token open/query a process it doesn't own. If this fails,
// OpenProcess below will too, with a clear error.
void try_enable_debug_privilege() {
    HANDLE token_raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_raw)) {
        return;
    }
    UniqueProcessHandle token(token_raw);
    LUID luid{};
    if (LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token.get(), FALSE, &tp, sizeof(tp), nullptr, nullptr);
    }
}

uint32_t thread_count_for_pid(DWORD pid) {
    UniqueSnapshotHandle snap(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
    if (!snap) return 0;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    uint32_t count = 0;
    if (Thread32First(snap.get(), &te)) {
        do {
            if (te.th32OwnerProcessID == pid) ++count;
        } while (Thread32Next(snap.get(), &te));
    }
    return count;
}

uint32_t handle_count_for(HANDLE hproc) {
    DWORD count = 0;
    if (!GetProcessHandleCount(hproc, &count)) return 0;
    return count;
}

size_t rss_bytes_for(HANDLE hproc) {
    PROCESS_MEMORY_COUNTERS pmc{};
    if (GetProcessMemoryInfo(hproc, &pmc, sizeof(pmc))) {
        return pmc.WorkingSetSize;
    }
    return 0;
}

uint64_t filetime_to_u64(const FILETIME& ft) {
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

// PDH-based context-switch aggregator. Opens a query once, adds the two
// wildcard Thread-object counters, and on each collect() sums
// "Context Switches/sec" across every thread instance whose "ID Process"
// matches the target PID.
class CtxSwitchSampler {
public:
    CtxSwitchSampler() = default;
    ~CtxSwitchSampler() {
        if (query_) PdhCloseQuery(query_);
    }
    // Owns a PDH query handle; a copy would double-close it. Unused today (never
    // copied/stored/returned by value anywhere in this file) - deleted so a future
    // edit can't introduce that silently (governance Gate 3 finding, 2026-08-18).
    CtxSwitchSampler(const CtxSwitchSampler&) = delete;
    CtxSwitchSampler& operator=(const CtxSwitchSampler&) = delete;

    bool init() {
        if (PdhOpenQueryW(nullptr, 0, &query_) != ERROR_SUCCESS) return false;
        if (PdhAddEnglishCounterW(query_, L"\\Thread(*)\\ID Process", 0, &id_proc_counter_) != ERROR_SUCCESS) {
            return false;
        }
        if (PdhAddEnglishCounterW(query_, L"\\Thread(*)\\Context Switches/sec", 0, &ctxsw_counter_) != ERROR_SUCCESS) {
            return false;
        }
        return true;
    }

    // Returns -1.0 on the first call (PDH rate counters need two collects to
    // establish a delta) or on a hard PDH failure. Caller should treat a
    // negative value as "no data yet", not an error to report.
    double collect_matching(DWORD target_pid) {
        if (PdhCollectQueryData(query_) != ERROR_SUCCESS) return -1.0;
        if (!have_prior_collect_) {
            have_prior_collect_ = true;
            return -1.0;
        }

        auto id_items = format_array_long(id_proc_counter_);
        auto ctxsw_items = format_array_double(ctxsw_counter_);
        if (id_items.empty() || ctxsw_items.empty()) return -1.0;

        double total = 0.0;
        for (const auto& idi : id_items) {
            if (static_cast<DWORD>(idi.value) != target_pid) continue;
            for (const auto& ci : ctxsw_items) {
                if (ci.name == idi.name) {
                    total += ci.value;
                    break;
                }
            }
        }
        return total;
    }

private:
    struct LongItem { std::wstring name; LONG value; };
    struct DoubleItem { std::wstring name; double value; };

    std::vector<LongItem> format_array_long(PDH_HCOUNTER counter) {
        std::vector<LongItem> out;
        DWORD buf_size = 0, item_count = 0;
        PDH_STATUS st = PdhGetFormattedCounterArrayW(counter, PDH_FMT_LONG, &buf_size, &item_count, nullptr);
        if (st != PDH_MORE_DATA || buf_size == 0) return out;
        std::vector<BYTE> buf(buf_size);
        auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buf.data());
        st = PdhGetFormattedCounterArrayW(counter, PDH_FMT_LONG, &buf_size, &item_count, items);
        if (st != ERROR_SUCCESS) return out;
        out.reserve(item_count);
        for (DWORD i = 0; i < item_count; ++i) {
            if (items[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA) continue;
            out.push_back({items[i].szName, items[i].FmtValue.longValue});
        }
        return out;
    }

    std::vector<DoubleItem> format_array_double(PDH_HCOUNTER counter) {
        std::vector<DoubleItem> out;
        DWORD buf_size = 0, item_count = 0;
        PDH_STATUS st = PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &buf_size, &item_count, nullptr);
        if (st != PDH_MORE_DATA || buf_size == 0) return out;
        std::vector<BYTE> buf(buf_size);
        auto* items = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(buf.data());
        st = PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &buf_size, &item_count, items);
        if (st != ERROR_SUCCESS) return out;
        out.reserve(item_count);
        for (DWORD i = 0; i < item_count; ++i) {
            if (items[i].FmtValue.CStatus != PDH_CSTATUS_VALID_DATA) continue;
            out.push_back({items[i].szName, items[i].FmtValue.doubleValue});
        }
        return out;
    }

    PDH_HQUERY query_ = nullptr;
    PDH_HCOUNTER id_proc_counter_ = nullptr;
    PDH_HCOUNTER ctxsw_counter_ = nullptr;
    bool have_prior_collect_ = false;
};

struct Sample {
    double elapsed_s;
    uint32_t threads;
    uint32_t handles;
    size_t rss_bytes;
    double cpu_pct;
    double ctxsw_per_sec;  // negative = not yet available
};

}  // namespace

int wmain(int argc, wchar_t** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);

    if (argc < 2) {
        fwprintf(stderr, L"usage: resource_sampler.exe <pid> [duration_sec=120] [interval_sec=5] [out.csv]\n");
        return 1;
    }
    DWORD target_pid = static_cast<DWORD>(_wtoi(argv[1]));
    int duration_sec = argc >= 3 ? _wtoi(argv[2]) : 120;
    int interval_sec = argc >= 4 ? _wtoi(argv[3]) : 5;
    const wchar_t* out_path = argc >= 5 ? argv[4] : nullptr;

    // Output file opened BEFORE OpenProcess (adversarial review finding, 2026-08-18)
    // so the OpenProcess-failure path never held a HANDLE to release, and NOW
    // RAII-owned (governance Gate 3 finding, same day) so no future edit that adds
    // an early return needs to remember to release either resource by hand.
    FILE* out_raw = stdout;
    if (out_path) {
        if (_wfopen_s(&out_raw, out_path, L"w") != 0 || !out_raw) {
            fwprintf(stderr, L"[resource_sampler] failed to open %ls for write\n", out_path);
            return 1;
        }
    }
    UniqueOutFile out_owner(out_raw);
    FILE* out = out_owner.get();

    try_enable_debug_privilege();

    UniqueProcessHandle hproc_owner(
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, target_pid));
    if (!hproc_owner) {
        fwprintf(stderr, L"[resource_sampler] OpenProcess(%lu) failed, gle=%lu - target may run as a "
                          L"different account; needs an elevated (Administrator) console even with "
                          L"SeDebugPrivilege, and the target must actually exist\n",
                  target_pid, GetLastError());
        return 1; // out_owner's destructor releases `out` on this path too
    }
    HANDLE hproc = hproc_owner.get();

    CtxSwitchSampler ctxsw;
    bool have_pdh = ctxsw.init();
    if (!have_pdh) {
        fwprintf(stderr, L"[resource_sampler] PDH init failed - continuing without wakeups/sec\n");
    }

    fwprintf(out, L"elapsed_s,threads,handles,rss_bytes,cpu_pct,ctxsw_per_sec\n");

    FILETIME ft_create{}, ft_exit{}, ft_kernel_prev{}, ft_user_prev{};
    GetProcessTimes(hproc, &ft_create, &ft_exit, &ft_kernel_prev, &ft_user_prev);
    uint64_t kernel_prev = filetime_to_u64(ft_kernel_prev);
    uint64_t user_prev = filetime_to_u64(ft_user_prev);
    uint64_t wall_prev_ms = GetTickCount64();

    std::vector<Sample> samples;
    const uint64_t start_ms = GetTickCount64();

    while (!g_stop.load(std::memory_order_relaxed)) {
        Sleep(static_cast<DWORD>(interval_sec) * 1000);
        if (g_stop.load(std::memory_order_relaxed)) break;

        // Re-check liveness: a dead PID reuses cheap, keep it explicit.
        DWORD wait_rc = WaitForSingleObject(hproc, 0);
        if (wait_rc == WAIT_OBJECT_0) {
            fwprintf(stderr, L"[resource_sampler] target pid %lu exited - stopping\n", target_pid);
            break;
        }

        uint64_t wall_now_ms = GetTickCount64();
        double wall_delta_s = static_cast<double>(wall_now_ms - wall_prev_ms) / 1000.0;
        wall_prev_ms = wall_now_ms;

        FILETIME ft_k{}, ft_u{};
        GetProcessTimes(hproc, &ft_create, &ft_exit, &ft_k, &ft_u);
        uint64_t kernel_now = filetime_to_u64(ft_k);
        uint64_t user_now = filetime_to_u64(ft_u);
        double cpu_100ns_delta = static_cast<double>((kernel_now - kernel_prev) + (user_now - user_prev));
        kernel_prev = kernel_now;
        user_prev = user_now;
        // 100% = one full core busy, unbounded above that (matches ps/top's
        // per-process convention on Linux, and this file's own header comment's
        // stated intent) - NOT divided by core count. An earlier version divided
        // by ncores, which silently contradicted that comment (a fully-busy
        // single-core process would have read 100/ncores%, not 100%); fixed
        // 2026-08-18 (governance Gate 3, cross-platform finding).
        double cpu_pct = wall_delta_s > 0.0
            ? (cpu_100ns_delta / 10000000.0) / wall_delta_s * 100.0
            : 0.0;

        double ctxsw_val = have_pdh ? ctxsw.collect_matching(target_pid) : -1.0;

        Sample s{};
        s.elapsed_s = static_cast<double>(wall_now_ms - start_ms) / 1000.0;
        s.threads = thread_count_for_pid(target_pid);
        s.handles = handle_count_for(hproc);
        s.rss_bytes = rss_bytes_for(hproc);
        s.cpu_pct = cpu_pct;
        s.ctxsw_per_sec = ctxsw_val;
        samples.push_back(s);

        if (ctxsw_val >= 0.0) {
            fwprintf(out, L"%.1f,%u,%u,%zu,%.2f,%.1f\n", s.elapsed_s, s.threads, s.handles, s.rss_bytes,
                      s.cpu_pct, s.ctxsw_per_sec);
        } else {
            fwprintf(out, L"%.1f,%u,%u,%zu,%.2f,\n", s.elapsed_s, s.threads, s.handles, s.rss_bytes, s.cpu_pct);
        }
        fflush(out);

        if (duration_sec > 0 && s.elapsed_s >= static_cast<double>(duration_sec)) break;
    }

    // hproc_owner/out_owner release HANDLE/FILE* automatically at function exit
    // (RAII) - nothing further reads or writes either after this point.

    // Steady-state summary: drop first 2 samples (startup / first-PDH-collect
    // warm-up), average the rest.
    size_t warmup = samples.size() > 2 ? 2 : 0;
    if (samples.size() <= warmup) {
        fwprintf(stderr, L"[resource_sampler] not enough samples for a steady-state summary (%zu collected)\n",
                  samples.size());
        return 0;
    }
    double sum_threads = 0, sum_handles = 0, sum_rss = 0, sum_cpu = 0, sum_ctxsw = 0;
    size_t ctxsw_n = 0;
    for (size_t i = warmup; i < samples.size(); ++i) {
        sum_threads += samples[i].threads;
        sum_handles += samples[i].handles;
        sum_rss += static_cast<double>(samples[i].rss_bytes);
        sum_cpu += samples[i].cpu_pct;
        if (samples[i].ctxsw_per_sec >= 0.0) {
            sum_ctxsw += samples[i].ctxsw_per_sec;
            ++ctxsw_n;
        }
    }
    size_t n = samples.size() - warmup;
    fwprintf(stderr,
              L"\n[resource_sampler] steady-state (n=%zu, warmup=%zu dropped): "
              L"threads=%.1f handles=%.1f rss_bytes=%.0f cpu_pct=%.2f wakeups_per_sec=%ls\n",
              n, warmup, sum_threads / n, sum_handles / n, sum_rss / n, sum_cpu / n,
              ctxsw_n > 0 ? std::to_wstring(sum_ctxsw / ctxsw_n).c_str() : L"n/a");

    return 0;
}
