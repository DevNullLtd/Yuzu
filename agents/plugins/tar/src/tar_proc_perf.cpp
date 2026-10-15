#include "tar_proc_perf.hpp"

#include "tar_collectors.hpp" // should_redact

#include <yuzu/version_string.hpp> // shared format_file_version / normalize_ffi_version

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstddef>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace yuzu::tar {

namespace {

// Saturating delta for cumulative counters (the tar_perf idiom).
std::uint64_t delta(std::uint64_t prev, std::uint64_t cur) {
    return cur >= prev ? cur - prev : 0;
}

// PF_KTHREAD ("I am a kernel thread"), <linux/sched.h> — hardcoded rather
// than including the kernel header (userspace has no business pulling that
// in; the bit is stable ABI). Checked against the raw kernel `flags` word
// (proc(5) field 9), never the attacker/process-settable `comm` name — see
// tar_proc_perf.hpp's "Kernel-thread marker" banner note.
constexpr std::uint64_t kPfKthreadFlag = 0x00200000;

// Saturating add/multiply — a hostile /proc mount can put 2^64-scale integers
// in a stat field; the products below would wrap (defined, but garbage). We
// saturate to UINT64_MAX so a forged value yields a pinned reading rather than
// a wrapped one (the module's "tolerate untrusted /proc" contract). Physically
// real kernels never approach these bounds.
std::uint64_t sat_add(std::uint64_t a, std::uint64_t b) {
    return a > std::numeric_limits<std::uint64_t>::max() - b
               ? std::numeric_limits<std::uint64_t>::max()
               : a + b;
}
std::uint64_t sat_mul(std::uint64_t a, std::uint64_t b) {
    return (b != 0 && a > std::numeric_limits<std::uint64_t>::max() / b)
               ? std::numeric_limits<std::uint64_t>::max()
               : a * b;
}

// (pid, create_time) identity key — PID alone is reused by the OS.
std::uint64_t proc_key(const ProcCounter& p) {
    return proc_identity(p.pid, p.create_time_100ns);
}

// Canonicalize a raw kernel `comm` for storage AND for redaction-pattern
// matching. Both MUST use the IDENTICAL transform: procperf stores the
// sanitized name, so an operator pattern has to be matched in the same space
// or a name the sanitizer rewrote (`evil|app` → `evil_app`) would silently
// escape a pattern that targets its raw form (`*evil|app*`). Transform:
//   - `\` and `\n` are escaped exactly as the kernel escapes /proc status
//     Name: (preserving the procperf↔process_live name join);
//   - `|`, other control bytes (< 0x20), and DEL (0x7f) become `_` (comm is
//     attacker-settable and would otherwise inject separators into the
//     pipe-delimited sql/export/app_perf wire formats);
//   - a well-formed multi-byte UTF-8 sequence passes through (legitimate
//     non-ASCII app names survive), but an ILL-FORMED byte (a stray/overlong
//     lead byte, a broken continuation, or a sequence truncated by the 15-byte
//     comm cap mid-character) becomes `_`, so the stored name is always valid
//     UTF-8 and can never fail the server's app_perf Postgres text insert.
std::string sanitize_comm(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    std::size_t i = 0;
    while (i < raw.size()) {
        const auto c0 = static_cast<unsigned char>(raw[i]);
        if (raw[i] == '\\') {
            out += "\\\\";
            ++i;
        } else if (raw[i] == '\n') {
            out += "\\n";
            ++i;
        } else if (c0 == '|' || c0 < 0x20 || c0 == 0x7f) {
            out += '_';
            ++i;
        } else if (c0 < 0x80) {
            out += static_cast<char>(c0);
            ++i;
        } else {
            // Multi-byte UTF-8. Validate the whole sequence (length from the
            // lead byte, well-formed continuations, no overlong/surrogate/
            // out-of-range codepoint); emit it intact iff valid, else one `_`
            // and resync one byte.
            int len = c0 >= 0xF0 ? 4 : c0 >= 0xE0 ? 3 : c0 >= 0xC0 ? 2 : 0;
            bool ok = len >= 2 && i + static_cast<std::size_t>(len) <= raw.size();
            std::uint32_t cp = ok ? (c0 & (0x7fu >> len)) : 0;
            for (int k = 1; ok && k < len; ++k) {
                const auto cc = static_cast<unsigned char>(raw[i + static_cast<std::size_t>(k)]);
                if ((cc & 0xC0) != 0x80) {
                    ok = false;
                } else {
                    cp = (cp << 6) | (cc & 0x3fu);
                }
            }
            const std::uint32_t min_cp = len == 2 ? 0x80 : len == 3 ? 0x800 : 0x10000;
            if (ok && (cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)))
                ok = false; // overlong, surrogate, or out of range
            if (ok) {
                out.append(raw.substr(i, static_cast<std::size_t>(len)));
                i += static_cast<std::size_t>(len);
            } else {
                out += '_';
                ++i;
            }
        }
    }
    return out;
}

} // namespace

std::uint64_t proc_identity(std::uint32_t pid, std::int64_t create_time_100ns) {
    // PID in the high 32 bits XOR'd with the FULL 64-bit create_time; a
    // collision needs two procs whose create_time high-dword aligns with a
    // reused PID — astronomically rare, and at worst costs one interval of CPU
    // mis-attribution for one app row.
    return (static_cast<std::uint64_t>(pid) << 32) ^
           static_cast<std::uint64_t>(create_time_100ns);
}

std::vector<ProcPerfSample> derive_proc_samples(const ProcSnapshot& prev,
                                                const ProcSnapshot& cur,
                                                const std::vector<std::string>& redaction) {
    std::vector<ProcPerfSample> out;
    if (!prev.valid || !cur.valid || cur.ncores <= 0)
        return out;
    const std::int64_t elapsed = cur.ts_epoch - prev.ts_epoch;
    if (elapsed <= 0)
        return out;

    // prev lookup by identity key. create_time must MATCH — a reused PID with
    // a different create_time finds no baseline and contributes 0 CPU this
    // interval rather than a garbage delta.
    std::unordered_map<std::uint64_t, std::uint64_t> prev_cpu;
    prev_cpu.reserve(prev.procs.size());
    for (const auto& p : prev.procs)
        prev_cpu[proc_key(p)] = p.cpu_100ns;

    // Build the redaction match set in the SANITIZED comm space. procperf
    // stores each name via sanitize_comm, so a pattern must be matched against
    // that same transform or a name the sanitizer rewrote (`evil|app` →
    // `evil_app`) would escape a pattern that targets its raw form. `*` passes
    // through sanitize_comm unchanged, so should_redact's star-stripping still
    // works on the sanitized pattern.
    //
    // BEST-EFFORT on the 15-byte comm (TASK_COMM_LEN). The kernel truncates the
    // name to 15 raw bytes, so a pattern whose sensitive substring is not a
    // ≤15-byte prefix-aligned slice of comm cannot match — the bytes are gone.
    // As a partial mitigation, any core LONGER than the comm width also matches
    // by its comm-width prefix (only ever ADDS redaction — the privacy-safe
    // direction; it can also over-suppress an unrelated same-prefix app). This
    // does NOT make redaction complete on Linux; see docs/user-manual/tar.md.
    std::vector<std::string> match_patterns;   // sanitized, full cores
    std::vector<std::string> comm_fallback;    // sanitized, comm-width prefixes
    match_patterns.reserve(redaction.size());
    for (const auto& pat : redaction) {
        std::string s = sanitize_comm(pat);
        std::string_view core = s;
        while (!core.empty() && core.front() == '*')
            core.remove_prefix(1);
        while (!core.empty() && core.back() == '*')
            core.remove_suffix(1);
        if (core.empty())
            continue;
        if (core.size() > kLinuxCommWidth)
            comm_fallback.emplace_back(core.substr(0, kLinuxCommWidth));
        match_patterns.push_back(std::move(s));
    }

    // Aggregate by image name (app-level, the BRD row-22 unit). `rep_*` track
    // the largest-working-set instance — the representative whose on-disk image
    // version stands in for the app this tick (resolved later, off the lock).
    struct Agg {
        int instances{0};
        std::uint64_t cpu_delta{0};
        std::uint64_t ws{0};
        std::uint32_t rep_pid{0};
        std::int64_t rep_create_time{0};
        std::uint64_t rep_ws{0};
        bool is_kthread{false}; // OR'd across instances — see ProcPerfSample::is_kthread
    };
    std::unordered_map<std::string, Agg> by_name;
    for (const auto& p : cur.procs) {
        if (p.name.empty())
            continue; // Idle / unnameable kernel entries — never a row
        // p.name is already sanitized; match_patterns/comm_fallback are in the
        // same space, so a name the sanitizer rewrote can no longer dodge a
        // pattern that targets its raw form.
        if (!match_patterns.empty() && (should_redact(p.name, match_patterns) ||
                                        (!comm_fallback.empty() &&
                                         should_redact(p.name, comm_fallback))))
            continue; // operator-redacted apps never appear in the warehouse
        auto& a = by_name[p.name];
        ++a.instances;
        a.ws += p.ws_bytes;
        a.is_kthread = a.is_kthread || p.is_kthread;
        if (auto it = prev_cpu.find(proc_key(p)); it != prev_cpu.end())
            a.cpu_delta += delta(it->second, p.cpu_100ns);
        if (a.rep_pid == 0 || p.ws_bytes > a.rep_ws) {
            a.rep_ws = p.ws_bytes;
            a.rep_pid = p.pid;
            a.rep_create_time = p.create_time_100ns;
        }
    }
    if (by_name.empty())
        return out;

    // Total machine capacity over the interval, in 100 ns units.
    const double capacity = static_cast<double>(elapsed) * 1.0e7 * cur.ncores;
    std::vector<ProcPerfSample> all;
    all.reserve(by_name.size());
    for (auto& [name, a] : by_name) {
        ProcPerfSample s;
        s.name = name;
        s.instances = a.instances;
        s.cpu_pct = std::clamp(static_cast<double>(a.cpu_delta) * 100.0 / capacity, 0.0, 100.0);
        s.ws_bytes = static_cast<std::int64_t>(a.ws);
        s.rep_pid = a.rep_pid;
        s.rep_create_time_100ns = a.rep_create_time;
        s.is_kthread = a.is_kthread;
        all.push_back(std::move(s));
    }

    // Union of top-N by CPU and top-N by working set.
    const auto n = static_cast<std::size_t>(kProcTopN);
    std::vector<std::size_t> idx(all.size());
    for (std::size_t i = 0; i < idx.size(); ++i)
        idx[i] = i;
    std::unordered_set<std::size_t> chosen;
    auto take_top = [&](auto cmp) {
        std::sort(idx.begin(), idx.end(), cmp);
        for (std::size_t i = 0; i < (std::min)(n, idx.size()); ++i)
            chosen.insert(idx[i]);
    };
    take_top([&](std::size_t a, std::size_t b) { return all[a].cpu_pct > all[b].cpu_pct; });
    take_top([&](std::size_t a, std::size_t b) { return all[a].ws_bytes > all[b].ws_bytes; });

    out.reserve(chosen.size());
    for (std::size_t i : chosen)
        out.push_back(std::move(all[i]));
    // Stable presentation order: CPU-heaviest first.
    std::sort(out.begin(), out.end(),
              [](const ProcPerfSample& a, const ProcPerfSample& b) {
                  return a.cpu_pct != b.cpu_pct ? a.cpu_pct > b.cpu_pct
                                                : a.ws_bytes > b.ws_bytes;
              });
    return out;
}

std::optional<ProcCounter> parse_linux_pid_stat(std::uint32_t pid, std::string_view stat_content,
                                                long clk_tck, long page_size) {
    if (clk_tck <= 0 || page_size <= 0)
        return std::nullopt;

    // comm sits between the first '(' and the LAST ')' — it may itself contain
    // spaces and parens (prctl(PR_SET_NAME)), so the last-')' rule is the only
    // correct parse and the content must never be line-split first.
    const auto open = stat_content.find('(');
    const auto close = stat_content.rfind(')');
    if (open == std::string_view::npos || close == std::string_view::npos || close <= open)
        return std::nullopt;

    // Tokens after the ')' are stat fields 3+, so 0-indexed: field N → N−3.
    //   flags=6  utime=11  stime=12  starttime=19  rss=21
    //   (proc(5), fields 9/14/15/22/24)
    constexpr std::size_t kFlags = 6, kUtime = 11, kStime = 12, kStartTime = 19, kRss = 21;
    constexpr std::size_t kNeed = kRss + 1;
    const auto is_field_ws = [](char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    };
    std::string_view rest = stat_content.substr(close + 1);
    std::string_view tok[kNeed];
    std::size_t count = 0, i = 0;
    while (i < rest.size() && count < kNeed) {
        while (i < rest.size() && is_field_ws(rest[i]))
            ++i;
        const std::size_t start = i;
        while (i < rest.size() && !is_field_ws(rest[i]))
            ++i;
        if (i > start)
            tok[count++] = rest.substr(start, i - start);
    }
    if (count < kNeed)
        return std::nullopt;

    // Exception-free full-consumption parse (the dex_linux_proc rule —
    // malformed content must never unwind out of the collect tick, and a
    // corrupt token rejects the row rather than being half-accepted). rss is
    // signed in the kernel's format string; a negative reading clamps to 0.
    const auto parse_num = []<typename T>(std::string_view t, T) -> std::optional<T> {
        T v = 0;
        const auto [p, ec] = std::from_chars(t.data(), t.data() + t.size(), v);
        return (ec == std::errc{} && p == t.data() + t.size()) ? std::optional{v} : std::nullopt;
    };
    const auto flags = parse_num(tok[kFlags], std::uint64_t{});
    const auto utime = parse_num(tok[kUtime], std::uint64_t{});
    const auto stime = parse_num(tok[kStime], std::uint64_t{});
    const auto starttime = parse_num(tok[kStartTime], std::uint64_t{});
    const auto rss = parse_num(tok[kRss], std::int64_t{});
    if (!flags || !utime || !stime || !starttime || !rss)
        return std::nullopt;

    ProcCounter p;
    p.pid = pid;
    // comm is attacker-settable RAW bytes (prctl(PR_SET_NAME)); sanitize_comm
    // neutralizes wire-format separators, escapes '\'/'\n' for the
    // process_live name join, and scrubs ill-formed UTF-8. derive_proc_samples
    // matches operator redaction patterns in this SAME sanitized space.
    p.name = sanitize_comm(stat_content.substr(open + 1, close - open - 1));
    // Flag-derived, not name-derived — see tar_proc_perf.hpp's "Kernel-thread
    // marker" note on why a name pattern is trivially spoofable in either
    // direction (prctl(PR_SET_NAME)) and this bit is not.
    p.is_kthread = (*flags & kPfKthreadFlag) != 0;
    // Ticks → 100 ns: ×1e7/clk_tck, multiply first (a real kernel needs ~570
    // CPU-years of jiffies to overflow; a forged /proc value is caught by the
    // saturating multiply). Keeps derive_proc_samples' capacity denominator
    // (elapsed·1e7·ncores) working unchanged.
    const auto clk = static_cast<std::uint64_t>(clk_tck);
    p.cpu_100ns = sat_mul(sat_add(*utime, *stime), 10'000'000u) / clk;
    p.create_time_100ns = static_cast<std::int64_t>(sat_mul(*starttime, 10'000'000u) / clk);
    p.ws_bytes = *rss > 0
                     ? sat_mul(static_cast<std::uint64_t>(*rss),
                               static_cast<std::uint64_t>(page_size))
                     : 0;
    return p;
}

} // namespace yuzu::tar

// ── Impure shell: platform process-counter snapshot ──────────────────────────

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <win_str.hpp> // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <winternl.h> // SYSTEM_PROCESS_INFORMATION (public/partial), NTSTATUS
#include <winver.h>   // GetFileVersionInfoW / VerQueryValueW / VS_FIXEDFILEINFO

#include <cstddef>
#include <ctime>
#include <vector>

namespace yuzu::tar {

namespace {

// The REAL SystemProcessInformation entry layout. winternl.h's public struct
// hides CreateTime/UserTime/KernelTime inside Reserved1[48]; this is the
// stable documented-in-practice layout (phnt / ntdoc — unchanged since
// Vista). The static_asserts below pin our offsets to the fields winternl.h
// DOES expose, so any SDK divergence fails the build, not the fleet.
struct SysProcEntry {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    // trailing fields exist; NextEntryOffset walks past them safely
};
// These asserts pin only the fields winternl.h PUBLICLY exposes — all of which
// sit AFTER the `Reserved1[48]` block. CreateTime/UserTime/KernelTime (the CPU
// fields we read) live INSIDE that reserved region, so they CANNOT be
// offsetof-checked; their offsets rely on the documented, Vista-stable layout
// of the reserved bytes (gov cross-platform S1). Pinning ImageName's absolute
// offset (56 on x64) transitively anchors the tail, and walking by
// NextEntryOffset insulates against trailing-field growth across Win10/11/Server
// SKUs — so any layout drift that would matter trips one of these.
static_assert(offsetof(SysProcEntry, ImageName) ==
              offsetof(SYSTEM_PROCESS_INFORMATION, ImageName));
static_assert(offsetof(SysProcEntry, UniqueProcessId) ==
              offsetof(SYSTEM_PROCESS_INFORMATION, UniqueProcessId));
static_assert(offsetof(SysProcEntry, WorkingSetSize) ==
              offsetof(SYSTEM_PROCESS_INFORMATION, WorkingSetSize));

using NtQsiFn = NTSTATUS(WINAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

// UTF-16 → UTF-8 for a counted (possibly unterminated) UNICODE_STRING.
// Delegates to the shared helper (#1681). UNICODE_STRING is COUNTED and not
// NUL-terminated, so yuzu::win::from_wide's trailing-NUL pop never fires here (a
// real image name carries no trailing NUL); null buffer / zero length -> {}.
std::string ucs_to_utf8(const UNICODE_STRING& u) {
    return yuzu::win::from_wide(u.Buffer, static_cast<int>(u.Length / sizeof(WCHAR)));
}

// RAII for a process HANDLE — CloseHandle on every exit path (the OpenProcess
// in resolve_one_version has several early returns; a manual close would leak).
struct HandleGuard {
    HANDLE h{nullptr};
    explicit HandleGuard(HANDLE handle) : h{handle} {}
    ~HandleGuard() {
        if (h && h != INVALID_HANDLE_VALUE)
            ::CloseHandle(h);
    }
    HandleGuard(const HandleGuard&) = delete;
    HandleGuard& operator=(const HandleGuard&) = delete;
    explicit operator bool() const { return h && h != INVALID_HANDLE_VALUE; }
};

// Resolve ONE process's on-disk file version, or "" on any failure. The path is
// read only to feed GetFileVersionInfo and is discarded immediately (it can
// carry a user-profile dir — privacy). `create_time_100ns` is the snapshot's
// CreateTime; it MUST match the live process before any path/version read, or a
// reused PID would get another process's version attributed.
std::string resolve_one_version(std::uint32_t pid, std::int64_t create_time_100ns) {
    HandleGuard proc{::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)};
    if (!proc)
        return {}; // protected/system process or gone — version stays ""

    // PID-reuse guard FIRST: FILETIME-to-FILETIME (100 ns since 1601), never
    // against the Unix-seconds ts_epoch.
    FILETIME ft_create{}, ft_exit{}, ft_kernel{}, ft_user{};
    if (!::GetProcessTimes(proc.h, &ft_create, &ft_exit, &ft_kernel, &ft_user))
        return {};
    ULARGE_INTEGER created{};
    created.LowPart = ft_create.dwLowDateTime;
    created.HighPart = ft_create.dwHighDateTime;
    if (static_cast<std::int64_t>(created.QuadPart) != create_time_100ns)
        return {}; // PID was reused since the snapshot — refuse before reading

    WCHAR path[MAX_PATH * 2];
    DWORD path_len = static_cast<DWORD>(std::size(path));
    if (!::QueryFullProcessImageNameW(proc.h, 0, path, &path_len))
        return {};

    DWORD ignored = 0;
    const DWORD info_size = ::GetFileVersionInfoSizeW(path, &ignored);
    if (info_size == 0)
        return {}; // no version resource (common for many non-vendor exes)
    std::vector<unsigned char> info(info_size); // RAII buffer
    if (!::GetFileVersionInfoW(path, 0, info_size, info.data()))
        return {};
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT ffi_len = 0;
    if (!::VerQueryValueW(info.data(), L"\\", reinterpret_cast<LPVOID*>(&ffi), &ffi_len) ||
        !ffi || ffi_len < sizeof(VS_FIXEDFILEINFO))
        return {};
    // Shared normalization: an all-zero fixed version maps to "" so it shares the
    // single unknown-version bucket with the crash side's canon_version, keeping
    // the (name, version) join consistent across perf and stability.
    return yuzu::util::normalize_ffi_version(ffi->dwFileVersionMS, ffi->dwFileVersionLS);
}

} // namespace

ProcSnapshot read_proc_counters() {
    ProcSnapshot snap;
    snap.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));

    static const NtQsiFn nt_qsi = []() -> NtQsiFn {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<NtQsiFn>(
                           ::GetProcAddress(ntdll, "NtQuerySystemInformation"))
                     : nullptr;
    }();
    if (!nt_qsi)
        return snap; // valid stays false

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    snap.ncores = static_cast<int>(si.dwNumberOfProcessors);

    // Buffer-growth loop: the process list changes between the size probe and
    // the fill, so re-ask with headroom until it fits (bounded attempts).
    // `ok` is load-bearing: only a successful (st==0) fill is walkable. If all
    // attempts return STATUS_INFO_LENGTH_MISMATCH, the buffer holds partial
    // kernel writes AND each resize() moved storage, so every kernel-written
    // ImageName.Buffer (an absolute pointer INTO the pre-resize allocation) now
    // dangles — walking it would be a use-after-free heap read (gov cpp-safety
    // BLOCKING). Bail with valid=false instead.
    std::vector<unsigned char> buf(1 << 18); // 256 KiB start
    bool ok = false;
    for (int attempt = 0; attempt < 6; ++attempt) {
        ULONG needed = 0;
        const NTSTATUS st =
            nt_qsi(SystemProcessInformation, buf.data(), static_cast<ULONG>(buf.size()), &needed);
        if (st == kStatusInfoLengthMismatch) {
            buf.resize(static_cast<std::size_t>(needed) + (1 << 16));
            continue;
        }
        if (st != 0)
            return snap; // any other failure: valid stays false
        ok = true;
        break;
    }
    if (!ok)
        return snap; // never successfully filled — buffer contents are undefined

    const unsigned char* base = buf.data();
    const unsigned char* end = base + buf.size();
    std::size_t off = 0;
    while (off + sizeof(SysProcEntry) <= buf.size()) {
        const auto* e = reinterpret_cast<const SysProcEntry*>(base + off);
        const auto pid =
            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(e->UniqueProcessId));
        if (pid != 0) { // skip Idle — its "CPU" is the absence of work
            ProcCounter p;
            p.pid = pid;
            p.create_time_100ns = e->CreateTime.QuadPart;
            p.cpu_100ns = static_cast<std::uint64_t>(e->KernelTime.QuadPart) +
                          static_cast<std::uint64_t>(e->UserTime.QuadPart);
            p.ws_bytes = static_cast<std::uint64_t>(e->WorkingSetSize);
            // Defence-in-depth: only read ImageName if its (Buffer, Length)
            // span lies wholly within the buffer. The kernel writes Buffer as
            // an absolute pointer into `buf`; a corrupt/forged length must never
            // make ucs_to_utf8 read out of bounds.
            const auto* nb = reinterpret_cast<const unsigned char*>(e->ImageName.Buffer);
            if (nb && e->ImageName.Length > 0 && nb >= base && nb + e->ImageName.Length <= end)
                // sanitize_comm is a no-op on well-formed NTFS image names, but
                // applying it keeps every platform's names in the SAME space as
                // the sanitized redaction patterns derive_proc_samples matches
                // against (and scrubs any ill-formed UTF-8 from the UTF-16
                // conversion). See the pure-section sanitize_comm.
                p.name = sanitize_comm(ucs_to_utf8(e->ImageName));
            if (p.name.empty() && pid == 4)
                p.name = "System"; // the kernel: real working set, no image name
            if (pid == 4)
                // Windows' kernel-process analog — see tar_proc_perf.hpp's
                // "Kernel-thread marker" note. Set independent of the name
                // branch above (pid is the authoritative identity either way).
                p.is_kthread = true;
            snap.procs.push_back(std::move(p));
        }
        if (e->NextEntryOffset == 0)
            break;
        off += e->NextEntryOffset;
    }
    snap.valid = true;
    return snap;
}

void resolve_proc_versions(std::vector<ProcPerfSample>& samples,
                           std::unordered_map<std::uint64_t, std::string>& cache) {
    // Rewrite the cache to this tick's live top-N: a process keeps its version
    // (resolved once at first sighting) while it stays in the set, and the cache
    // can never grow past <= 2N entries. A failed resolve is cached as "" too,
    // so a protected process is not re-OpenProcess'd every tick it survives.
    std::unordered_map<std::uint64_t, std::string> next;
    next.reserve(samples.size());
    for (auto& s : samples) {
        if (s.rep_pid == 0)
            continue; // no representative instance — leave version ""
        const auto key = proc_identity(s.rep_pid, s.rep_create_time_100ns);
        if (auto it = cache.find(key); it != cache.end())
            s.version = it->second;
        else
            s.version = resolve_one_version(s.rep_pid, s.rep_create_time_100ns);
        next.emplace(key, s.version);
    }
    cache.swap(next);
}

} // namespace yuzu::tar

#elif defined(__linux__)

#include <dirent.h>
#include <unistd.h>

#include <cstring>
#include <ctime>
#include <fstream>
#include <memory>
#include <string>

namespace yuzu::tar {

ProcSnapshot read_proc_counters() {
    ProcSnapshot snap;
    snap.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));
    // Process-lifetime constants — thread-safe magic statics, fetched once.
    static const long clk = ::sysconf(_SC_CLK_TCK);
    static const long page = ::sysconf(_SC_PAGESIZE);
    // RAII owner (the HandleGuard rationale): allocations inside the walk can
    // throw bad_alloc, and a manual closedir after the loop would leak the fd
    // on every such unwind — a repeatable per-tick leak, since the trigger
    // engine catches and re-ticks.
    const std::unique_ptr<DIR, int (*)(DIR*)> dir{::opendir("/proc"), &::closedir};
    if (!dir || clk <= 0 || page <= 0)
        return snap; // valid stays false
    // One /proc/<pid>/stat read per numeric entry. Kernel threads are
    // deliberately INCLUDED (parity with Windows recording pid 4 `System`):
    // rss 0 keeps them out of the working-set top-N, and a genuinely hot
    // kworker surfacing in the CPU top-N is signal, not noise. A hidepid
    // mount just yields fewer rows — never an invalid snapshot. The path and
    // content buffers are hoisted and refilled via chunked read() so the
    // ~hundreds-of-PIDs walk reuses their capacity instead of churning the
    // heap every 30 s tick.
    snap.procs.reserve(256);
    std::string path;
    std::string content;
    content.reserve(1024); // a pid stat payload is well under 1 KB
    while (const dirent* de = ::readdir(dir.get())) {
        std::uint32_t pid = 0;
        const char* name = de->d_name;
        const char* end = name + std::strlen(name);
        const auto [p, ec] = std::from_chars(name, end, pid);
        if (ec != std::errc{} || p != end || pid == 0)
            continue; // not a numeric pid entry
        path.assign("/proc/").append(name).append("/stat");
        std::ifstream f(path);
        if (!f)
            continue; // pid exited between readdir and open — expected churn
        char buf[1024];
        content.clear();
        while (f.read(buf, sizeof buf))
            content.append(buf, static_cast<std::size_t>(f.gcount()));
        content.append(buf, static_cast<std::size_t>(f.gcount()));
        if (f.bad())
            continue; // mid-read I/O error — fail closed rather than tokenize a
                      // truncated tail (parity with read_proc in tar_perf.cpp)
        if (auto pc = parse_linux_pid_stat(pid, content, clk, page))
            snap.procs.push_back(std::move(*pc));
    }
    snap.ncores = static_cast<int>(::sysconf(_SC_NPROCESSORS_ONLN));
    snap.valid = snap.ncores > 0 && !snap.procs.empty();
    return snap;
}

// Linux emits version="" — there is no handle-free on-disk version source
// wired yet (ELF .note.package is the documented follow-up; see the
// os-capability-matrix per-app file-version row). Leave the cache untouched.
void resolve_proc_versions(std::vector<ProcPerfSample>& /*samples*/,
                           std::unordered_map<std::uint64_t, std::string>& /*cache*/) {}

} // namespace yuzu::tar

#else // !_WIN32 && !__linux__ — macOS (proc_pid_rusage) is kPlanned

#include <ctime>

namespace yuzu::tar {

ProcSnapshot read_proc_counters() {
    ProcSnapshot snap;
    snap.ts_epoch = static_cast<std::int64_t>(std::time(nullptr));
    return snap; // valid=false — collect_perf records nothing on this platform yet
}

// No per-process version source yet (the macOS per-app collector is
// kPlanned). Leave every version "" without touching the cache.
void resolve_proc_versions(std::vector<ProcPerfSample>& /*samples*/,
                           std::unordered_map<std::uint64_t, std::string>& /*cache*/) {}

} // namespace yuzu::tar

#endif
