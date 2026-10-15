#pragma once

/**
 * tar_proc_perf.hpp — top-N per-process resource sampling for the TAR edge
 * warehouse (BRD A2, docs/dex-brd-coverage.md rows 22/27).
 *
 * Rides the same 30 s collect_perf tick as the A1 device sampler (no new
 * thread, no new trigger): one system-wide process snapshot in, the top-N
 * APPLICATIONS by CPU and by working set out, aggregated by image name
 * (12 chrome.exe processes = one "chrome.exe" row with instances=12 — the
 * BRD asks for app-specific consumption, not per-PID noise; per-PID detail
 * stays on the process_live event trail). Raw rows stay ON-DEVICE
 * (ADR-0004); the hourly tier carries per-app avg/max for trend queries.
 *
 * Windows source — deliberately NOT PDH, NOT WMI: ONE
 * NtQuerySystemInformation(SystemProcessInformation) call returns every
 * process's image name, PID, create time, kernel+user CPU time, and working
 * set, with no per-process handles. CPU% needs two snapshots; the previous
 * one is held in plugin memory keyed by (pid, create_time) so PID reuse never
 * miscounts. Linux source — one /proc/[pid]/stat read per process per tick
 * (comm, utime+stime, rss, starttime, flags; no ptrace, no per-process
 * handles). macOS (proc_pid_rusage) is kPlanned.
 *
 * Kernel-thread marker (`is_kthread`): Linux processes are flagged via the
 * kernel `flags` word (/proc/[pid]/stat field 9, bit 0x00200000 = PF_KTHREAD,
 * <linux/sched.h>) rather than a name pattern — `comm` is attacker/process-
 * settable (prctl(PR_SET_NAME)) and TASK_COMM_LEN-truncated, so a name match
 * is trivially spoofable in either direction. Windows marks pid 4 ("System",
 * the kernel-process analog) the same way. This tier's own top-N sampling and
 * storage NEVER filter on it (kernel threads are deliberately included here —
 * parity with Windows pid 4, see read_proc_counters()); it exists so the
 * separate DAILY app-perf-over-time rollup (agents/core/src/
 * sync_source_app_perf.cpp) can exclude kernel/system noise from the
 * historical "application" view without touching this live tier.
 *
 * Version (DEX app-perf-over-time): the per-app `version` is the BOUNDED,
 * deliberate exception to the handle-free posture. SystemProcessInformation
 * carries the image NAME but not its full path, and a file version lives in
 * the on-disk image — so after top-N selection ONLY (<= 2N apps/tick) we
 * OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) the representative instance,
 * resolve its path, and read the version resource. Per-process failure
 * (ACCESS_DENIED on a protected process, no version resource, PID reuse)
 * isolates to version="" and never aborts the tick; a (pid, create_time)
 * cache resolves each process once at first sighting (the version nearest
 * launch — least disk-staleness, ~zero steady-state handle cost). Off-Windows
 * the resolver is a no-op (version stays "").
 *
 * Privacy: only image NAMES + the on-disk file VERSION are recorded — never
 * command lines (the stronger default; cmdlines can carry secrets) and never
 * the image PATH (it can carry a user profile dir). The operator's TAR
 * redaction patterns are additionally applied to the name, so a process an
 * operator redacted from the event trail never appears here either. The
 * whole source sits behind its own `procperf_enabled` toggle
 * (works-council: per-app visibility can be disabled while device-level
 * sampling stays on).
 *
 * The derivation + top-N selection is PURE (derive_proc_samples), as is the
 * shared version normalization (yuzu::util::format_file_version /
 * normalize_ffi_version in <yuzu/version_string.hpp>) — both unit-tested on
 * every host; read_proc_counters() and resolve_proc_versions() are the impure
 * Windows shells.
 */

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace yuzu::tar {

/// One process's raw counters at an instant. `cpu_100ns` is CUMULATIVE
/// kernel+user time since process start; `ws_bytes` is instantaneous.
/// (pid, create_time_100ns) is the identity key — PID alone is reused.
/// `create_time_100ns` is IDENTITY-ONLY and platform-relative: FILETIME
/// (epoch 1601) on Windows, boot-relative on Linux — nothing interprets the
/// unit; a reused PID gets a different value, which is all it must guarantee.
struct ProcCounter {
    std::uint32_t pid{0};
    std::int64_t create_time_100ns{0};
    std::uint64_t cpu_100ns{0};
    std::uint64_t ws_bytes{0};
    std::string name; ///< image name, UTF-8 (no path, no cmdline)
    /// True for a Linux kernel thread (PF_KTHREAD, stat field 9) or the
    /// Windows "System" process (pid 4). Metadata only — see the header
    /// banner's "Kernel-thread marker" note for why this is flag-derived,
    /// not name-matched, and what consumes it.
    bool is_kthread{false};
};

/// One system-wide snapshot.
struct ProcSnapshot {
    bool valid{false};
    std::int64_t ts_epoch{0};
    int ncores{0}; ///< logical processors — the CPU%% denominator
    std::vector<ProcCounter> procs;
};

/// One derived per-APPLICATION sample (aggregated across same-name
/// processes). `cpu_pct` is the app's share of TOTAL machine capacity
/// (all cores — one saturated core on an 8-core box reads 12.5, matching
/// the device sampler's denominator and Task Manager).
struct ProcPerfSample {
    std::string name;
    std::string version; ///< on-disk file version "a.b.c.d"; "" until resolved / off-Windows
    int instances{0};
    double cpu_pct{0.0};
    std::int64_t ws_bytes{0}; ///< summed working set across instances
    /// The largest-working-set instance, used as the representative for version
    /// resolution. create_time guards against PID reuse between snapshot and
    /// resolution. Set by derive_proc_samples; read by resolve_proc_versions.
    std::uint32_t rep_pid{0};
    std::int64_t rep_create_time_100ns{0};
    /// True iff ANY aggregated instance is a kernel thread / Windows System
    /// process (ProcCounter::is_kthread, OR'd across instances — a name
    /// group sharing an exact kernel-thread comm is, in practice, only ever
    /// kernel threads). Recorded into procperf_live/_hourly unfiltered (this
    /// tier keeps kernel threads, see the header banner); the daily app-perf
    /// rollup filters on it.
    bool is_kthread{false};
};

/// Top-N size per dimension. The recorded set is the UNION of the top N by
/// CPU and the top N by working set (<= 2N rows per tick) — a memory hog
/// that's CPU-idle stays visible and vice versa.
inline constexpr int kProcTopN = 10;

/// Kernel comm width on Linux (TASK_COMM_LEN − 1): names from the Linux
/// collector are at most this many bytes. derive_proc_samples keys its
/// comm-width redaction fallback to this — a pattern core longer than a comm
/// could otherwise never substring-match, silently defeating an operator's
/// redaction of a long-named app on Linux fleets.
inline constexpr std::size_t kLinuxCommWidth = 15;

/// PURE: derive the per-app top-N from two snapshots. Empty when either
/// snapshot is invalid, elapsed <= 0, or ncores <= 0. A process absent from
/// `prev` (new, or PID reused — different create_time) contributes 0 CPU
/// this interval (it baselines; its working set still counts). A CPU
/// counter regression saturates to 0, never wraps. Names matching a
/// redaction pattern are skipped entirely.
std::vector<ProcPerfSample> derive_proc_samples(const ProcSnapshot& prev,
                                                const ProcSnapshot& cur,
                                                const std::vector<std::string>& redaction);

/// Impure shell: snapshot the current per-process counters. Windows
/// (NtQuerySystemInformation) and Linux (/proc/[pid]/stat walk) are wired;
/// valid=false on macOS until its collector lands (registry: kPlanned).
ProcSnapshot read_proc_counters();

/// PURE: parse one /proc/[pid]/stat payload into a ProcCounter. clk_tck
/// (sysconf(_SC_CLK_TCK)) and page_size (sysconf(_SC_PAGESIZE)) are injected
/// so the field handling is deterministic and unit-tested on every host.
/// comm is taken between the first '(' and the LAST ')' of the whole content
/// (comm may contain spaces and parens; never line-split first) — the
/// kernel's 15-char comm. The stored name is SANITIZED: '\' and '\n' are
/// escaped exactly as the kernel escapes /proc/[pid]/status Name: (which the
/// Linux process source records), so procperf rows join process_live rows by
/// name; every other control byte and '|' becomes '_' (comm is
/// attacker-settable raw bytes via prctl(PR_SET_NAME) — a '|' would inject
/// separators into the pipe-delimited sql/export/app_perf wire formats).
/// cpu_100ns = (utime+stime)·1e7/clk_tck; ws_bytes = rss·page_size;
/// create_time_100ns = starttime·1e7/clk_tck (boot-relative, identity-only).
/// is_kthread = (flags & PF_KTHREAD) != 0, from the field-9 kernel flags word
/// (proc(5)) — see the header banner's "Kernel-thread marker" note.
/// nullopt on malformed content or non-positive clk_tck/page_size.
std::optional<ProcCounter> parse_linux_pid_stat(std::uint32_t pid, std::string_view stat_content,
                                                long clk_tck, long page_size);

/// PURE: the (pid, create_time) identity key — PID alone is reused by the OS.
/// Shared by the CPU-baseline lookup and the version cache so both agree.
std::uint64_t proc_identity(std::uint32_t pid, std::int64_t create_time_100ns);

// Version formatting/normalization is shared with the crash-side extractor and
// the server projection — see <yuzu/version_string.hpp> (format_file_version /
// normalize_ffi_version / canon_version), so all three producers of the
// (name, version) identity emit byte-identical canonical strings.

/// Impure shell: annotate each sample's `version` from its representative
/// process (Windows OpenProcess + file-version resource read). `cache` maps a
/// (pid, create_time) identity → version so a process resolves once while it
/// stays in the top-N; the cache is rewritten to this tick's live set on each
/// call (bounded to <= 2N entries). Per-process failure isolates to
/// version="". No-op off Windows (versions stay "").
void resolve_proc_versions(std::vector<ProcPerfSample>& samples,
                           std::unordered_map<std::uint64_t, std::string>& cache);

} // namespace yuzu::tar
