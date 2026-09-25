/**
 * spark_file.cpp — the File spark mechanism (ADR-0021 Stage 1 PR 1b; watch
 * establishment moved off the engine's per-type lock in #2012/#3840 PR-B2).
 *
 * Windows: one IOCP + one worker thread multiplexing ReadDirectoryChangesW
 * across every watched PARENT DIRECTORY — O(mechanism), never O(rules). Two
 * file sparks in the same directory share one ReadDirectoryChangesW
 * registration; a raw directory notification is routed back to the matching
 * spark key(s) by changed filename. IOCP (not WaitForMultipleObjects) is
 * deliberate: the 64-handle MAXIMUM_WAIT_OBJECTS cap is exactly the O(rules)
 * ceiling the SparkEngine exists to remove (the trigger_engine registry-poll
 * mistake).
 *
 * This mechanism PORTS THE WATCH, NOT THE ASSERTION. Unlike guard_file.cpp it
 * does NO expected-value compare, NO hashing, NO write-back — a fired spark is
 * a raw "this path changed" fact (the old TriggerEngine FileChange trigger
 * shape). The compare + enforce move to Guardian as an inline consumer in
 * Stage 2. It DOES port guard_file's watch-resilience: the nearest-existing-
 * ancestor watch that survives a deleted+recreated parent, and arm-before-check
 * ordering (ReadDirectoryChangesW issued before anything reads state).
 *
 * WHY THE PR-B2 SHAPE (issues #2012/#3840). Before this PR, watch() ran
 * blocking OS calls (fs::is_directory / CreateFileW, and on absence an
 * unbounded nearest-ancestor walk) directly under mu_ — and since the engine
 * serialises every watch()/unwatch() of one SparkType under
 * SparkEngine::mech_ops_mu_by_type_[type] for the FULL duration of that call,
 * a single slow/dead filesystem path (a hung network share) stalled every
 * other File arm/disarm for as long as the OS call took. spark_registry.cpp
 * (PR-B1, merged #4225) established the shared shape this PR ports to File's
 * own resource model:
 *   - watch(): reserve under mu_ -> release -> launch the discovery probe on
 *     a detached, F3-counted worker (`probe_lane_`) -> wait at most
 *     kFileCallerWaitBudget -> relock, re-validate, commit; a probe still
 *     outstanding is PUBLISHED to the worker's own sweep and watch() returns
 *     success-with-pending. Per-type lock hold is <= budget + microseconds,
 *     never an OS-call duration.
 *   - run()'s own IOCP loop is now ALSO the sweeper: after every
 *     GetQueuedCompletionStatus return (a real completion, a control wake, or
 *     a scheduled timeout), it sweeps outstanding probes, due retries, and
 *     health grace — File has ONE mechanism-owned thread already (unlike
 *     Registry, which needed a second `sweeper_` thread because a TP_WAIT
 *     callback is not an owner loop), so sweeping is folded into the existing
 *     loop rather than adding a second thread. A completion that ITSELF needs
 *     re-discovery (the dir vanished, an ancestor died) now STAGES a probe
 *     reservation instead of blocking run() with a synchronous open/walk.
 *   - Unlike Registry, File does NOT need a second "disposal lane": a
 *     discovery probe carries an UNASSOCIATED DirHandle (CreateFileW only —
 *     no ReadDirectoryChangesW is ever issued on it), so closing a discarded
 *     probe result's handle (CancelIo on a handle with nothing queued +
 *     CloseHandle) is always fast/non-blocking, unlike Registry's TP_WAIT
 *     drain (WaitForThreadpoolWaitCallbacks can genuinely block on a running
 *     callback). Only an ESTABLISHED, IOCP-associated, read-issued DirWatch
 *     needs the (pre-existing, unchanged) retiring_/push_retiring/drop_watch
 *     discipline that defers its destruction until the aborted completion
 *     drains — a probe result never reaches that state before commit.
 *
 * OWNERSHIP / DISPATCH PROTOCOL (same rules PR-B1 established for Registry):
 *   1. Reserve the obligation under mu_ (probe state + a mechanism-global
 *      generation stamped on the watch), release, launch off-lock.
 *   2. Only the initiating control-path caller (watch()) performs a bounded
 *      wait; run()'s own sweep only polls (try_take), never blocks for D.
 *   3. Reacquire mu_, re-validate the DirWatch by POINTER IDENTITY (found at
 *      the same dirkey) + generation + not-removing, then commit, hand off
 *      (publish as Pending) or discard.
 *   4. Neither watch() nor unwatch() calls emit()/fault() synchronously on ANY
 *      path, immediate success included.
 *   5. `needs_resync` carries an epoch, mirroring Registry's; File's is
 *      scoped PER DIRECTORY (not per spark key) and fans a synthetic fire out
 *      to every key currently in that directory's `keys` map — the shared
 *      obligation is ALWAYS retried as one batch on a submit failure (Dave's
 *      decision #4: accept a bounded number of duplicate invalidations to
 *      already-succeeded keys rather than track per-key debt).
 *   6. Unlike Registry, a DEFINITE establishment failure resolved while the
 *      caller is still inside watch() (the common case for a fast, doomed
 *      probe — e.g. #1927's nonexistent-drive-root walk, where the ancestor
 *      walk reaches a fixed point in microseconds) is NEVER rejected: Dave's
 *      decision #3 accepts a valid-path obligation into observable retry
 *      state, exactly like every OTHER establishment failure this mechanism
 *      can hit (a still-outstanding probe, an admission refusal, a later
 *      async resolution). watch() cannot stage a health-fault notice for
 *      this specific case the way fail_backend_locked normally would — its
 *      own local `discards` never reaches run_off_lock (rule 4 above), so a
 *      notice staged there would be lost, not merely delayed — it defers
 *      instead to the health-grace timer already running from `accepted_at`,
 *      and calls nudge_locked() so that timer's very next sweep pass
 *      actually happens promptly rather than waiting on an unrelated
 *      completion (this mechanism's only timer is run()'s own
 *      GetQueuedCompletionStatus wait).
 *
 * D (50 ms) is the #2012/#3840 series' chosen initial policy value for every
 * one of File's five named constants, including the discovery-probe traversal
 * budget (a deliberate change from the OLD 500 ms ancestor-walk-abandon
 * threshold: since a failed walk is now ALWAYS retried on a schedule — it
 * never was before — a short internal circuit-breaker plus automatic retry is
 * a better trade than a long internal wait with no retry at all). Not a
 * proven statistical bound; see spark_registry.cpp's own header comment for
 * the measured-inputs caveat, which applies here too.
 *
 * Off Windows the factory returns nullptr → SparkEngine rejects arm(File).
 */

#include "spark_mechanism.hpp"

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "guard_win_handle.hpp" // detail::DirHandle, detail::EventHandle
#include "spark_detached_call.hpp"
#include <yuzu/log_token.hpp>

#include <spdlog/spdlog.h>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <filesystem>
#include <functional> // #2839 retire fault hook
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace yuzu::agent {
namespace {

namespace fs = std::filesystem;

using detail::DirHandle;
using Clock = std::chrono::steady_clock;

constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                          FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                          FILE_NOTIFY_CHANGE_CREATION;

// Completion-key sentinels distinguish a directory completion (key == the
// DirWatch pointer) from a control wake (watch/unwatch/stop posted the queue).
constexpr ULONG_PTR kControlKey = 0;

// ── D and its five meanings (PR-B2 initial policy: all 50 ms, tuned apart) ──
/// How long watch() waits for its own discovery probe before publishing it to
/// run()'s own sweep and returning success-with-pending. The per-type lock
/// hold bound (#2012/#3840's whole reason to exist).
constexpr std::chrono::milliseconds kFileCallerWaitBudget{50};
/// How long an accepted obligation (initial establishment or re-discovery)
/// may stay unestablished before the watch is reported Faulted and
/// slow_op_total bumps.
constexpr std::chrono::milliseconds kFileHealthGrace{50};
/// Ceiling on how long a completed probe waits to be committed while nothing
/// else wakes run()'s loop sooner — every launch/state-change already causes
/// a real IOCP event soon in the common case, so this is a worst-case poll
/// cadence, not an added latency for the typical path.
constexpr std::chrono::milliseconds kFileSweepCadence{50};
/// First delay after an admission refusal (probe lane cap / launch failure):
/// D, 2D, 4D, ... capped at kFileAdmissionBackoffCap, never counted as a
/// backend attempt. Also the schedule a submit-failed resync obligation is
/// re-staged on.
constexpr std::chrono::milliseconds kFileAdmissionBackoffSeed{50};
/// Elapsed budget for one discovery probe's ancestor walk once the target
/// itself is confirmed absent: a dead/unresponsive filesystem path costs
/// ~one OS timeout plus this, not depth × per-probe timeout.
constexpr std::chrono::milliseconds kFileProbeTraversalBudget{50};

/// Cap on the admission-refusal backoff above; also the cap on the worker's
/// pass-failure retry backoff (#4658), exactly as spark_registry.cpp reuses its
/// own admission cap for its sweeper.
constexpr std::chrono::milliseconds kFileAdmissionBackoffCap{30'000};
/// Genuine backend failure (open/associate/read refused, probe threw): 30 s
/// doubling to a 300 s cap, attempts reset on a successful establishment.
constexpr std::chrono::milliseconds kFileBackendRetryBase{30'000};
constexpr std::chrono::milliseconds kFileBackendRetryCap{300'000};
/// Consecutive failed worker passes after which the mechanism reports itself
/// inert on the heartbeat (the existing capability-gap signal, see
/// SparkMechanismStats::inert). Mirrors spark_registry.cpp's
/// kSweeperInertAfterFailures (an anonymous-namespace constant there, so it
/// cannot be shared). The intent (#4658; governance sre6-1's rule for
/// Registry, applied to File): a worker whose passes keep failing must not
/// read as a healthy idle one. Only a pass that THROWS counts: a worker wedged
/// inside a callback still reads healthy (#2084's armed-but-deaf liveness), and
/// a failure a pass catches itself becomes state and counts as a success.
constexpr unsigned kFileWorkerInertAfterFailures = 3;

constexpr std::size_t kProbeLaneCap = 16; ///< concurrent detached discovery-probe workers

// The caller wait budget is the only one of the five that a Guardian control-path
// caller can be made to wait through under the per-type lock; it must sit inside
// Guardian's backend_op deadline. Mirrors spark_registry.cpp's identical check.
static_assert(spark_deadline_below_guardian_backend_op(kFileCallerWaitBudget),
              "kFileCallerWaitBudget must be strictly below Guardian's backend_op deadline");

// Locale-INDEPENDENT case fold for directory + filename matching (sec-M1).
// NTFS is case-insensitive via an upcase table; guard_file.cpp matches changed
// names with CompareStringOrdinal(...,TRUE). A per-wchar ::towlower is
// C-locale (ASCII-only), so a non-ASCII filename differing only in case between
// the spark's watched name and the FILE_NOTIFY_INFORMATION name would MISS — a
// silently dropped spark (fail-open detection, worse than a crash for a Stage-2
// enforce consumer). LCMapStringEx with the INVARIANT locale folds the full
// Unicode range deterministically, matching NTFS case-insensitive semantics.
std::wstring fold_ci(std::wstring_view s) {
    if (s.empty())
        return {};
    const int n = ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(),
                                  static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr, 0);
    if (n <= 0)
        return std::wstring(s); // fold unavailable → exact match (safe; only over-strict on case)
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, s.data(), static_cast<int>(s.size()),
                    out.data(), n, nullptr, nullptr, 0);
    return out;
}

std::wstring parent_of(const std::wstring& p) {
    // fs::path::parent_path() of a root (drive root, UNC share root) returns
    // itself — a fixed point, not empty (#1927 review finding, unchanged from
    // the pre-PR-B2 ancestor walk).
    return fs::path(p).parent_path().wstring();
}

[[nodiscard]] std::chrono::milliseconds doubled(std::chrono::milliseconds base, unsigned attempts,
                                                 std::chrono::milliseconds cap) {
    // base * 2^(attempts-1), saturating at cap (attempts >= 1).
    std::chrono::milliseconds d = base;
    for (unsigned i = 1; i < attempts && d < cap; ++i)
        d *= 2;
    return std::min(d, cap);
}

/// Pending-operation state of one real-directory watch — INDEPENDENT of its
/// health (a watch can be Faulted with a retry in flight, or healthy/sheltered
/// with nothing outstanding). Ancestor-map entries never use this field (see
/// this file's header comment: an ancestor slot is bootstrapped directly from
/// a dependent's own probe result and torn down on death — it never runs an
/// independent probe of its own).
enum class ProbeState : std::uint8_t {
    Idle,     ///< nothing outstanding
    Pending,  ///< a probe is reserved or in flight (call engaged once published)
    Deferred, ///< a probe will be relaunched at next_retry_at
};

enum class WatchMode : std::uint8_t { Target, Ancestor };

/// What one detached discovery probe produced. Every OS resource it opened is
/// owned here (RAII) so a discarded result closes itself on whichever thread
/// drops it — never under mu_ by construction of the call sites. The handle is
/// UNASSOCIATED (no CreateIoCompletionPort, no ReadDirectoryChangesW issued):
/// only the owner thread, inside commit_probe_locked()/attach_*_locked(),
/// associates it and issues the first read, using the stable DirWatch (or
/// fresh ancestor slot) address as the IOCP completion key. nothrow-move by
/// construction (launch() static_asserts it).
struct FileProbeResult {
    DirHandle handle;          ///< unassociated; engaged iff ok
    std::wstring resolved_dir; ///< the directory actually opened — the ORIGINAL (non-folded) casing
                               ///< of the target (Target mode) or the found candidate
                               ///< (Ancestor mode), matching what CreateFileW/GetFileAttributesW
                               ///< were called with
    WatchMode mode{WatchMode::Target};
    bool ok{false};
    DWORD err{0};
    const char* stage{""}; ///< which step failed, for the log / fault reason
};
static_assert(std::is_nothrow_move_constructible_v<FileProbeResult>);

/// The detached discovery probe: try to open `dir` as a directory; on genuine
/// absence, walk up for the nearest existing, openable ancestor. Run on a
/// counted worker off every lock — nothing that can block, and no IOCP
/// association or read issue (those need the owner-stable DirWatch address),
/// happens on the control path.
struct FileProbeJob {
    std::wstring dir; ///< the base path to try (a real dir's fixed target — reserve_probe_locked()
                      ///< always starts from the ORIGINAL target, never the current shelter)
    std::shared_ptr<const std::function<void(std::wstring_view)>> hook; ///< test seam; may be null
    std::chrono::milliseconds traversal_budget{kFileProbeTraversalBudget};

    static bool open_dir(const std::wstring& path, DirHandle& out, DWORD& err) {
        DirHandle h(::CreateFileW(
            path.c_str(), FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
        if (!h) {
            err = ::GetLastError();
            return false;
        }
        out = std::move(h);
        return true;
    }

    /// Existence classification for one candidate path:
    ///   1  - confirmed existing directory
    ///   0  - confirmed absent (FILE_NOT_FOUND / PATH_NOT_FOUND)
    ///  -1  - exists but is not a directory, or the attributes call failed for
    ///        any OTHER reason (access denied, a network error, ...) — an
    ///        access-or-backend condition, never treated as absence (Open
    ///        Decision #2: an inaccessible EXISTING target must not be
    ///        silently certified via ancestor shelter — the same rule
    ///        spark_registry.cpp already applies to RegOpenKeyExW's
    ///        non-NOT_FOUND errors).
    static int classify(const std::wstring& path, DWORD& err) {
        const DWORD attrs = ::GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) {
            err = ::GetLastError();
            return (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) ? 0 : -1;
        }
        if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            err = ERROR_DIRECTORY;
            return -1;
        }
        return 1;
    }

    FileProbeResult operator()() {
        FileProbeResult r;
        if (hook && *hook)
            (*hook)(dir); // test seam: may park (a hung/unresponsive path) or throw

        DWORD err = 0;
        const int cls = classify(dir, err);
        if (cls == 1) {
            DirHandle h;
            if (open_dir(dir, h, err)) {
                r.handle = std::move(h);
                r.resolved_dir = dir;
                r.mode = WatchMode::Target;
                r.ok = true;
                return r;
            }
            if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
                r.err = err;
                r.stage = "CreateFileW(target)";
                r.mode = WatchMode::Target;
                return r;
            }
            // else: deleted between the attributes check and the open (a
            // narrow TOCTOU) — fall through to the ancestor walk exactly like
            // a genuine absence.
        } else if (cls == -1) {
            r.err = err;
            r.stage = "GetFileAttributesW(target)";
            r.mode = WatchMode::Target;
            return r;
        }

        // Target absent (or just-deleted): walk up for the nearest existing,
        // openable ancestor. Fixed-point AND deadline guarded — checked
        // before EACH additional potentially-blocking operation (the
        // candidate's own attributes check, then again before its open), not
        // once per iteration after the fact (#1927 review: the pre-PR-B2 walk
        // only checked its elapsed budget after fs::is_directory, leaving the
        // final candidate's is_directory call AND the CreateFileW open that
        // follows it completely unguarded).
        const auto t0 = Clock::now();
        std::wstring anc = dir;
        for (;;) {
            const std::wstring parent = parent_of(anc);
            if (parent == anc) {
                r.err = err; // last classify() error seen, if any
                r.stage = "ancestor walk reached a fixed point with nothing openable";
                r.mode = WatchMode::Ancestor;
                return r;
            }
            anc = parent;
            if (Clock::now() - t0 > traversal_budget) {
                r.err = ERROR_TIMEOUT;
                r.stage = "ancestor walk exceeded its traversal budget";
                r.mode = WatchMode::Ancestor;
                return r;
            }
            const int acls = classify(anc, err);
            if (acls != 1)
                continue; // not found / not usable here — keep walking up
            if (Clock::now() - t0 > traversal_budget) {
                r.err = ERROR_TIMEOUT;
                r.stage = "ancestor walk exceeded its traversal budget (found, before open)";
                r.mode = WatchMode::Ancestor;
                return r;
            }
            DirHandle h;
            if (open_dir(anc, h, err)) {
                r.handle = std::move(h);
                r.resolved_dir = anc;
                r.mode = WatchMode::Ancestor;
                r.ok = true;
                return r;
            }
            // Found a real, existing directory but couldn't open it (a race /
            // permissions): a backend failure for THIS attempt, retried from
            // scratch (a fresh walk) on the next scheduled probe — never a
            // silent give-up (the pre-PR-B2 arm_ancestor() used to erase the
            // candidate slot and return false here with no further recovery).
            r.err = err;
            r.stage = "CreateFileW(ancestor)";
            r.mode = WatchMode::Ancestor;
            return r;
        }
    }
};
static_assert(std::is_nothrow_move_constructible_v<FileProbeJob>);

/// key_index_'s value: which (dirkey, fname) a spark key currently maps to,
/// plus the registration generation it was stamped with (#2012/#3840 review
/// finding 8 — see key_gen_'s own doc comment on WindowsFileMechanism).
struct KeyBinding {
    std::wstring dirkey;
    std::wstring fname;
    std::uint64_t gen{0};
    /// Establishment-signal identity for THIS key (rung 9c PR-6 item 1) — per
    /// key, not per directory, since several keys can share one DirWatch.
    /// Forward-only rebind everywhere it is written (never decreases); see
    /// watch_incarnation()'s two `key_index_[key] = {...}` sites for why the
    /// prior value must be read BEFORE that whole-struct aggregate assignment.
    SparkIncarnation incarnation{kNoSparkIncarnation};
    [[nodiscard]] bool same_target(const std::wstring& d, const std::wstring& f) const {
        return dirkey == d && fname == f;
    }
};

/// One watched directory: its overlapped read, its buffer, and (for a real
/// dir) the set of spark keys interested in each (lower-cased) filename
/// inside it. Heap-owned and kept alive until its outstanding I/O drains —
/// the IOCP teardown contract. Every field is guarded by the mechanism's mu_
/// EXCEPT that a retired watch (removing=true, moved into retiring_) is owned
/// by whichever code eventually reaps it (run()'s own drop_watch(), or
/// stop()'s reap loop) — touched only for its OS handles from that point on.
struct DirWatch {
    DirHandle handle;               ///< CreateFileW(FILE_LIST_DIRECTORY, OVERLAPPED), IOCP-associated
    OVERLAPPED ov{};                ///< distinct per dir — the IOCP key back to this struct
    alignas(DWORD) std::byte buf[32 * 1024]; ///< FILE_NOTIFY_INFORMATION landing buffer
    std::wstring dir;               ///< original-casing path this watch is FOR
    std::wstring map_key;           ///< the fold_ci'd key this entry is stored under (dirs_ or
                                    ///< ancestors_) — stored directly (mirrors spark_registry.cpp's
                                    ///< RegWatch::spark_key) so a completion callback holding only a
                                    ///< DirWatch* can re-find its own map entry without a linear scan
    bool io_pending{false};         ///< a ReadDirectoryChangesW is outstanding
    bool removing{false};           ///< unwatch/teardown drained this dir; free once the last I/O returns

    // Fan-out (real dirs only).
    std::unordered_map<std::wstring, std::unordered_set<std::string>> keys; ///< fname → spark keys

    // Ancestor bookkeeping (real dirs only, when currently absent/sheltered).
    int refcount{0};             ///< ancestor entries only: # of dependents relying on this slot
    std::wstring ancestor_key;   ///< real dirs only: which ancestor currently shelters this dir
    /// Ancestor entries only: this slot's own read is known dead (handle
    /// already reset) but invalidate_ancestor_locked() — which reassigns
    /// every dependent and allocates to do it — could not run at the point
    /// this was discovered (unwind_pass_locked's noexcept recovery path;
    /// #2012/#3840 review finding 2). A pure scalar write, so it can always
    /// be stamped even when nothing may allocate; sweep_probes_locked()
    /// finishes the invalidation on the mechanism's next normal (allocating)
    /// pass. Never set on a real-dir (dirs_) entry.
    bool dead_pending_invalidate{false};

    // Health (real dirs only — ancestor entries never fault to any key
    // directly; a dependent's own health tracks whether IT is sheltered, not
    // whether the shelter itself is "healthy").
    bool health_desired_faulted{false};
    bool health_reported_faulted{false};
    const char* fault_reason{""};

    // Discovery-probe state (real dirs only — see this file's header comment
    // on why ancestor entries never run their own probe).
    ProbeState probe{ProbeState::Idle};
    std::uint64_t probe_gen{0}; ///< mechanism-global gen stamped at reservation
    std::optional<DetachedCall<FileProbeResult>> call; ///< engaged once a launch is PUBLISHED
    /// Obligation acceptance — grace runs from here and a retry never resets it.
    Clock::time_point accepted_at{};
    Clock::time_point next_retry_at{};
    unsigned backend_attempts{0};
    unsigned admission_attempts{0};
    bool grace_counted{false};

    // Resync / synthetic fire (real dirs only). Scoped per DIRECTORY, not per
    // key: an observation gap fans a synthetic fire out to every key
    // currently in `keys`, and a submit failure restores the WHOLE batch
    // (Dave's decision #4 — never per-key debt).
    bool needs_resync{false};
    std::uint64_t resync_epoch{0};
    unsigned resync_attempts{0};
    Clock::time_point resync_retry_at{};
    /// True from the moment stage_resync_emit_locked() stages a batch (which
    /// clears needs_resync as part of staging) until that batch's outcome is
    /// reconciled (Submitted, Failed, or restored-Unattempted) — the window
    /// during which `needs_resync == false` does NOT mean "nothing
    /// outstanding" (#2012/#3840 review round-3, CDEX-P1-3): a key that
    /// joins during this off-lock dispatch window is absent from the
    /// already-staged notices (staging snapshotted the OLD w.keys) and, if
    /// that batch simply succeeds, would otherwise never get its own
    /// obligation. watch()'s join path checks this alongside needs_resync.
    /// Benign known gap (Kimi, round-3 closure-pass scoped review): cleared
    /// on Submitted/Failed/Unattempted but not on Stale (the registration
    /// this batch was staged for no longer exists by dispatch time). If an
    /// entire epoch's batch goes Stale while the DIRECTORY survives, this
    /// stays true until the next batch stages — a later join just takes the
    /// conservative fresh-epoch branch above rather than the fast path, not
    /// a coverage loss (the re-watch that made the batch Stale already
    /// bumped its own epoch while this was in flight).
    bool resync_dispatch_in_flight{false};

    /// The outstanding probe was launched WHILE this dir was absent (a
    /// reresolve_absent_locked() reappearance attempt, triggered by an
    /// ancestor's own fire) — if it commits in Target mode, the target
    /// APPEARED, which needs a synthetic fire (mirrors
    /// spark_registry.cpp's rearm_from_ancestor). Survives a failed probe
    /// attempt; cleared only by a successful Target-mode commit.
    bool probe_is_reappearance{false};

    /// Sheltered by an ancestor and still owed one confirmation re-probe (the
    /// discover/attach race: an intermediate directory may have appeared
    /// between the walk and this shelter's own establishment) — cleared once
    /// that confirmation lands, whatever its outcome, so this never becomes a
    /// permanent poll loop.
    bool confirmation_due{false};

    /// Establishment-signal coverage (rung 9c PR-6 item 1), per DIRECTORY —
    /// real dirs only, like the health fields above; never set on an
    /// ancestors_ entry (a dependent's own coverage reflects whether IT is
    /// sheltered, None while sheltered, not whether the shelter itself is
    /// healthy). Written by every coverage-transition site via
    /// mark_coverage_locked() — three scalar writes, unconditional, never
    /// gated on the prior value. `coverage_report_due` is drained at the
    /// sweep visit, staging one PendingEstablished entry per key currently in
    /// `keys` (each carrying that key's own KeyBinding::incarnation).
    SparkCoverage coverage{SparkCoverage::None};
    Clock::time_point coverage_at{};
    bool coverage_report_due{false};
};

/// Everything one pass wants to do OUTSIDE mu_: launches, dispatch, and the
/// disposal of anything whose destructor closes an OS handle or abandons a
/// call. Destroyed only with mu_ released.
struct FilePassWork {
    struct ProbeLaunch {
        std::wstring dirkey;
        std::uint64_t gen{0};
        std::optional<FileProbeJob> job;
        DetachedLaunch status{DetachedLaunch::LaunchFailed};
        std::optional<DetachedCall<FileProbeResult>> call;
    };
    struct Notice {
        enum class Kind : std::uint8_t { Emit, Fault } kind{Kind::Emit};
        std::string key;
        bool faulted{false};
        const char* reason{""};
        std::uint64_t resync_epoch{0}; ///< Emit notices only, when is_resync
        std::wstring dirkey;           ///< the watch this notice was staged FOR, re-found by key at
                                       ///< dispatch time — never dereference `watch` without this
        DirWatch* watch{nullptr};      ///< identity check only, never dereferenced without a fresh
                                       ///< dirs_.find(dirkey) confirming it is still the SAME object
                                       ///< (UP-1: a Fault staged for W1 must not land on a re-created
                                       ///< W1' at the same key)
        bool is_resync{false};
        /// `key`'s key_index_ registration generation at STAGING time
        /// (#2012/#3840 review finding 8) — revalidated against key_index_'s
        /// CURRENT generation for `key` at dispatch (notice_still_current),
        /// same short mu_ acquisition as the existing identity check. Closes
        /// the gap directory-identity-alone cannot: unwatch(key); watch(key)
        /// racing the off-lock dispatch window, for a directory kept alive
        /// by a still-live sibling key, must not deliver a notice staged for
        /// the OLD registration to the REPLACEMENT one.
        std::uint64_t key_gen{0};
        /// Per-notice dispatch outcome (#2012/#3840 review finding 3):
        /// replaces three separately-allocated copied-key vectors
        /// (succeeded_resync/failed_resync/failed_ordinary_emit) with one
        /// allocation-free enum written IN PLACE on the already-reserved
        /// `work.notices` element itself — run_off_lock() never needs its
        /// own reserve() calls for outcome bookkeeping (there's nothing left
        /// to reserve), which is what closed the control-wake branch's
        /// missing-reserve half of this finding along with the
        /// allocating-outcome-tuple half. Deliberately the LAST member: this
        /// type is aggregate-initialized by positional brace-init at every
        /// staging call site (check_health_edge_locked/stage_fire_locked/
        /// stage_resync_emit_locked), none of which name `outcome` — putting
        /// it last lets every one of those keep working unchanged, filled by
        /// its own default member initializer. `Stale` (notice_still_
        /// current() returned false — the registration this notice was
        /// staged for no longer exists) is a DISTINCT terminal state from
        /// `Unattempted` (round-3 table opine): unwind_pass_locked must
        /// restore every still-Unattempted notice regardless of
        /// `dispatched` (a throw INSIDE run_off_lock, e.g. its own test
        /// hook, after `dispatched` is already true but before the dispatch
        /// loop reached a given notice, must not silently drop it) — Stale
        /// notices are correctly dropped either way, so they must not be
        /// reconciled as if lost.
        enum class Outcome : std::uint8_t { Unattempted, Submitted, Failed, Stale } outcome{
            Outcome::Unattempted};
    };
    /// A staged establishment-signal report (rung 9c PR-6 item 1) — one per
    /// spark KEY currently in the staging watch's `keys` map (not one per
    /// directory: several keys can share a DirWatch, and each carries its own
    /// KeyBinding::incarnation). `dirkey` is used only by unwind_pass_locked
    /// to re-find the watch and re-mark `coverage_report_due`; dispatch itself
    /// needs no staleness re-check (the staged incarnation IS the identity —
    /// SparkEngine::report_established drops a report whose incarnation no
    /// longer names the key's current watch), unlike Notice above.
    struct PendingEstablished {
        std::string key;
        SparkIncarnation incarnation{kNoSparkIncarnation};
        Clock::time_point at{};
        SparkCoverage coverage{SparkCoverage::None};
        std::wstring dirkey;
    };
    std::vector<ProbeLaunch> probe_launches;
    std::vector<Notice> notices; ///< in recorded order — per-key ordering matters
    std::vector<PendingEstablished> established; ///< staged coverage reports, dispatch-first order
    // discards (destroyed off-lock)
    std::vector<DirHandle> old_handles;
    std::vector<FileProbeResult> dead_results;
    std::vector<DetachedCall<FileProbeResult>> stale_calls;
    std::vector<std::unique_ptr<DirWatch>> dead_watches;

    /// Consumed-completion recovery (#2012/#3840 gap-1 fix): `consumed`, if
    /// non-null, is the DirWatch whose IOCP completion run() just dequeued
    /// for THIS pass — already gone from the queue and never redelivered,
    /// whatever process_completion_locked/sweep_probes_locked does or fails
    /// to do with it. Stamped by run() itself, under mu_, BEFORE entering the
    /// try block that may throw anywhere inside — three preallocated scalars
    /// (a raw, non-owning pointer + two bools), so unwind_pass_locked can
    /// always recover from them with no allocation, regardless of exactly
    /// where inside that try the throw landed (the "consumed completion" File
    /// has that Registry doesn't — see this file's header comment rule 6 and
    /// the PR-B2 plan's function-split item 8).
    DirWatch* consumed{nullptr};
    bool consumed_ok{false};
    bool consumed_is_anc{false};
};
/// stage_probe_locked() relies on this: with capacity pre-reserved by every
/// caller (the existing discipline every work.probe_launches.reserve() call
/// site already follows), its own push_back is non-throwing only if this
/// holds (#2012/#3840 review, round-3 table opine — "prove insertion
/// capacity and moves are non-throwing, or placement belongs before the
/// stamp").
static_assert(std::is_nothrow_move_constructible_v<FilePassWork::ProbeLaunch>);

/// Windows file-change mechanism. Thread-safe: watch/unwatch (engine threads)
/// and the worker all take `mu_`. Discovery (CreateFileW / GetFileAttributesW,
/// and the ancestor walk) runs on a detached, F3-counted worker off every
/// lock (#2012/#3840 PR-B2); only IOCP association and the first
/// ReadDirectoryChangesW happen under mu_, on the owner thread, and neither
/// can block.
class WindowsFileMechanism final : public ISparkMechanism {
public:
    /// Bounds retiring_ growth under re-arm churn faster than the single
    /// worker thread can drain (#1979). ~256 * sizeof(DirWatch) (dominated by
    /// the 32 KiB notify buffer) is worst-case ~8.5 MiB pinned — generous
    /// against real churn, small against unbounded growth. UNCHANGED by
    /// PR-B2 — this gate is about I/O TEARDOWN backlog, orthogonal to the new
    /// discovery-probe machinery below.
    static constexpr std::size_t kRetiringCap = 256;

    explicit WindowsFileMechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter)
        : probe_lane_(std::move(f3_counter), kProbeLaneCap) {}

    ~WindowsFileMechanism() override { stop(); }

    void start(SparkEmitFn emit, SparkFaultFn fault) override {
        std::lock_guard lk(mu_);
        // One-way seal (rung 9c PR-6 item 1): start() being CALLED is what seals
        // the establishment sink, whether or not this call does anything else —
        // set first, before the idempotent early-return, so a repeat start()
        // can never re-open the window (mirrors spark_service.cpp /
        // spark_registry.cpp). Never cleared by stop(): SparkEngine is
        // single-shot, so no production caller ever re-arms the sink after a
        // stop().
        sink_sealed_ = true;
        if (iocp_)
            return; // idempotent
        emit_ = std::move(emit);
        fault_ = std::move(fault);
        iocp_.reset(::CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, kControlKey, 1));
        if (!iocp_) {
            spdlog::error("spark_file: CreateIoCompletionPort failed (err={}) — file sparks inert",
                          ::GetLastError());
            inert_.store(true, std::memory_order_release);
            return;
        }
        inert_.store(false, std::memory_order_release);
        stop_.store(false, std::memory_order_release);
        try {
            worker_ = std::thread([this] { run(); });
        } catch (...) {
            // No worker => no dispatch, no sweep, no completions ever drained:
            // refuse to run half-alive, and leave iocp_ reset so a RETRIED
            // start() is a real retry rather than the silent `if (iocp_)
            // return` no-op the pre-PR-B2 code would have hit here (mirrors
            // spark_registry.cpp start()'s identical fix).
            iocp_.reset();
            inert_.store(true, std::memory_order_release);
            throw;
        }
    }

    std::expected<void, std::string> watch(const std::string& key,
                                           const SparkParams& params) override {
        // The engine never calls this overload in production (it always calls
        // watch_incarnation() below) — kept for direct/test callers that predate
        // the establishment signal. kNoSparkIncarnation is a valid, harmless
        // identity: nothing rejects it, it simply never matches a real engine
        // incarnation.
        return watch_incarnation(key, params, kNoSparkIncarnation);
    }

    std::expected<void, std::string> watch_incarnation(const std::string& key,
                                                        const SparkParams& params,
                                                        SparkIncarnation incarnation) override {
        const auto* fp = std::get_if<FileSparkParams>(&params);
        if (!fp)
            return std::unexpected("file mechanism: params are not FileSparkParams");
        fs::path target = fs::path(fp->path);
        fs::path parent = target.has_parent_path() ? target.parent_path() : fs::current_path();
        const std::wstring fname = fold_ci(target.filename().wstring());
        const std::wstring dirkey = fold_ci(parent.wstring());

        std::unique_lock lk(mu_);
        if (!iocp_)
            return std::unexpected("file mechanism not started");
        // #1979: refuse NEW work while too many cancelled watches are still
        // awaiting their drained IOCP completion. UNCHANGED by PR-B2 — this
        // is about I/O teardown backlog, orthogonal to the new probe lane
        // (whose own admission refusal defers+retries rather than rejecting
        // watch() outright — see reserve_probe_locked()'s callers below,
        // matching spark_registry.cpp's identical choice for its own lane).
        if (retiring_.size() >= retiring_cap()) {
            watch_rejected_.fetch_add(1, std::memory_order_relaxed);
            return std::unexpected(
                std::string("file mechanism: ") + std::to_string(retiring_.size()) +
                " watch(es) awaiting IOCP teardown (cap " + std::to_string(retiring_cap()) +
                ") — arm refused");
        }
        // #1981: a re-arm of THIS key against a DIFFERENT (dirkey, fname) —
        // implicitly clear the stale registration first, exactly as if the
        // caller had unwatch()'d it. UNCHANGED in intent from the pre-PR-B2
        // code; unwatch_locked() now takes a disposal sink.
        if (auto ki = key_index_.find(key);
            ki != key_index_.end() && !ki->second.same_target(dirkey, fname)) {
            FilePassWork discards;
            reserve_discard_capacity(discards);
            unwatch_locked(key, discards);
            // `discards` destructs here, with mu_ still held. This is SAFE
            // for File specifically (a discarded, not-yet-established
            // DetachedCall<FileProbeResult>/FileProbeResult never carries a
            // live, IOCP-associated I/O — see this file's header comment),
            // but kept off-lock anyway below is not possible here since this
            // whole re-arm must complete before `slot` is (re)created a few
            // lines down — accepted as a narrow, documented exception to the
            // "always dispose off-lock" discipline used everywhere else in
            // this file, matching the bounded, always-fast cost argued above.
        }
        auto& slot = dirs_[dirkey];
        if (slot && slot->removing)
            push_retiring(slot);
        const bool fresh = !slot;
        if (fresh) {
            // Transactional registration (#2012/#3840 review finding 4): if
            // ANYTHING below throws, erase the just-inserted `dirkey` entry
            // before propagating, so a LATER watch() call for the same
            // directory sees `fresh == true` again and gets a clean retry —
            // never a permanently-deaf slot a defensive unwatch() can't
            // reach (key_index_ was never populated for THIS key, since
            // nothing below has committed yet). watch_guarded()
            // (spark_engine.cpp) already converts an escaping throw from
            // watch() into a returned failure and defensively unwatch()es
            // this key, so rethrowing (rather than hand-building a
            // std::unexpected here — itself an allocation on this same
            // failure path) is safe and matches this mechanism's existing
            // contract.
            try {
                // Implementation trap (rung 9c PR-6 item 1): the aggregate
                // assignment below is a WHOLE-STRUCT
                // overwrite. Read the prior incarnation (if any) BEFORE it, or
                // this registration would silently reset a key that somehow
                // already had one back to kNoSparkIncarnation.
                SparkIncarnation prior_inc = kNoSparkIncarnation;
                if (auto pi = key_index_.find(key); pi != key_index_.end())
                    prior_inc = pi->second.incarnation;
                if (watch_register_fail_hook_)
                    watch_register_fail_hook_(dirkey); // test seam: may throw to model an
                                                        // allocation failing anywhere below
                slot = std::make_unique<DirWatch>();
                slot->dir = parent.wstring();
                slot->map_key = dirkey;
                slot->keys[fname].insert(key);
                key_index_[key] = {dirkey, fname, ++key_gen_}; // #2012/#3840 review finding 8:
                                                               // gen bumped on every registration
                                                               // - see key_gen_'s doc comment
                key_index_[key].incarnation = std::max(prior_inc, incarnation); // forward-only rebind
            } catch (...) {
                dirs_.erase(dirkey); // nothing was ever armed/probed — safe to discard whole
                throw;
            }
        } else {
            try {
                // See the `fresh` branch's identical comment above.
                SparkIncarnation prior_inc = kNoSparkIncarnation;
                if (auto pi = key_index_.find(key); pi != key_index_.end())
                    prior_inc = pi->second.incarnation;
                slot->keys[fname].insert(key);
                key_index_[key] = {dirkey, fname, ++key_gen_};
                key_index_[key].incarnation = std::max(prior_inc, incarnation); // forward-only rebind
            } catch (...) {
                // Existing, already-armed dir: roll back a partial key-
                // membership add so a later watch()/unwatch() for this key
                // is never split between w.keys and key_index_ (a narrower
                // leak than the fresh-dir case above, since the underlying
                // directory watch is already healthy regardless of this one
                // key — closed here for the same "never ride along on a
                // broken half-state" reason).
                auto fi = slot->keys.find(fname);
                if (fi != slot->keys.end()) {
                    fi->second.erase(key);
                    if (fi->second.empty())
                        slot->keys.erase(fi);
                }
                key_index_.erase(key);
                throw;
            }
        }

        if (!fresh) {
            // #2012/#3840 review finding 9: a key joining an EXISTING watch
            // that is CURRENTLY faulted, with that fault already reported to
            // every OTHER member (desired == reported == true), is otherwise
            // invisible to every future health-edge check — those are all
            // "did anything CHANGE" guards, not "does every CURRENT member
            // already know" guards, so the new key would be reported healthy
            // for the entire remaining fault duration. Force a fresh
            // mismatch so the (now-unconditional, finding 5) health-edge
            // check re-fans-out to every CURRENT member, including the one
            // that just joined.
            //
            // Deliberately NOT bumping needs_resync for the ordinary
            // (healthy, settled, nothing in flight) case: a resync fire
            // covers an EXISTING member's own observation gap, and a
            // brand-new (or rejoining) key never had a gap to begin with —
            // its coverage starts now, live, under this same mu_ hold. An
            // unconditional bump on every ordinary join was tried and
            // reverted (round-3 DGRHP): it fired a spurious synthetic
            // resync to every sibling key on every join, breaking existing
            // behavior for the common case. An ALREADY-outstanding resync
            // (needs_resync already true — not yet staged) still correctly
            // covers the new member once it stages, since staging always
            // snapshots the CURRENT w.keys. A batch already STAGED and
            // currently off-lock mid-dispatch (resync_dispatch_in_flight)
            // is DIFFERENT — its notices were built from the OLD w.keys
            // before this join, so a join landing in that exact window
            // needs its own fresh epoch (#2012/#3840 review round-3,
            // CDEX-P1-3) — an earlier version of this comment claimed
            // that window was already covered; it was not.
            bool needs_prompt_sweep = false;
            if (slot->health_desired_faulted && slot->health_reported_faulted) {
                slot->health_reported_faulted = false;
                needs_prompt_sweep = true;
            }
            if (slot->resync_dispatch_in_flight) {
                // NOT an invariant that needs_resync is false here (Astra,
                // round-3 opine): a second join landing in the same
                // in-flight window can find it already true (e.g. a prior
                // join already bumped it, or an unrelated outstanding
                // resync predates the flight). Either way this branch's
                // job is the same — unconditionally force a fresh epoch so
                // the just-joined key is covered by the NEXT batch, not the
                // one already off-lock with stale w.keys.
                slot->needs_resync = true;
                slot->resync_epoch = ++resync_epoch_;
                needs_prompt_sweep = true;
            }
            if (needs_prompt_sweep)
                nudge_locked();
            // Establishment-signal join / adoption / coalesce report (rung 9c
            // PR-6 item 1): the engine
            // skips unwatch() on a renewed SAME key (SparkEngine::disarm() /
            // unregister_consumer()), and a genuinely NEW key joining an
            // already-established directory (coalesce) also needs its own
            // report — its own KeyBinding::incarnation was just stamped
            // above. Mark the directory's CURRENT coverage (whatever it is)
            // due, re-stamped `now()` so a first-wins established_at can
            // never predate the joining/adopting incarnation's own armed_at.
            // The sweep stages ONE entry per key currently in `keys`
            // (stage_established_locked), so every sibling key gets a
            // redundant identical report too — the engine assigns coverage
            // unconditionally and latches established_at first-wins, so a
            // repeat is harmless. The whole directory's coverage_at is
            // re-stamped, so a sibling not yet latched takes the later time.
            slot->coverage_at = Clock::now();
            slot->coverage_report_due = true;
            nudge_locked(); // unconditional: needs_prompt_sweep above is conditional on
                            // unrelated health/resync state and must not gate this report
            return {}; // rides along with whatever obligation this dir already has
        }

        // Brand-new DirWatch: reserve + launch its FIRST discovery probe,
        // with a bounded caller wait (the whole reason this PR exists).
        auto job = reserve_probe_locked(*slot);
        if (!job)
            return {}; // cannot happen for a fresh watch (starts Idle); defensive

        DirWatch* w = slot.get();
        const std::uint64_t gen = w->probe_gen;

        // Launch off-lock and wait AT MOST the caller budget — the ENTIRE
        // reason this PR exists (#2012/#3840): mu_ (and, at the engine layer,
        // SparkEngine::mech_ops_mu_by_type_[File]) must be RELEASED for this
        // whole section, or every other same-type arm/disarm queues behind
        // this call for up to kFileCallerWaitBudget regardless of how the
        // probe itself is bounded. The deadline is computed BEFORE unlocking
        // so lock-release/launch overhead cannot silently extend the wait.
        const auto deadline = Clock::now() + caller_wait_budget();
        lk.unlock();
        auto lr = probe_lane_.launch(std::move(*job));
        std::optional<DetachedCall<FileProbeResult>> call;
        std::optional<DetachedResult<FileProbeResult>> taken;
        if (lr.status == DetachedLaunch::Launched) {
            probe_launched_.fetch_add(1, std::memory_order_relaxed);
            call = std::move(lr.call);
            taken = call->wait_take(deadline); // the ONE bounded wait — control-path caller only
        }
        lk.lock();

        FilePassWork discards;
        reserve_discard_capacity(discards);
        {
            auto it = dirs_.find(dirkey);
            const bool live = it != dirs_.end() && it->second.get() == w && w->probe_gen == gen &&
                              !w->removing;
            if (!live) {
                if (call)
                    discards.stale_calls.push_back(std::move(*call));
                if (taken && taken->has_value())
                    discards.dead_results.push_back(std::move(**taken));
                probe_discarded_.fetch_add(1, std::memory_order_relaxed);
                // The DirWatch was already retired from under us (a
                // concurrent unwatch()/#1981 re-arm/stop() raced this call) —
                // its own teardown path already handled disposal.
            } else if (lr.status != DetachedLaunch::Launched) {
                // Admission refused for this watch's very first probe: the
                // obligation is kept and retried on the admission schedule,
                // but coverage never even started — cover the gap with a
                // resync fire once it eventually establishes (#2012/#3840
                // gap-2 trigger: admission refusal; mirrors
                // spark_registry.cpp watch()'s identical site).
                defer_admission_locked(*w, lr.status);
                w->needs_resync = true;
                w->resync_epoch = ++resync_epoch_;
            } else if (taken) {
                // Decision #3 (Dave, PR-B2 plan): a definite establishment
                // failure resolved this fast — including "no discoverable
                // ancestor anywhere" (#1927's nonexistent-drive-root case,
                // where the walk reaches its fixed point in microseconds) —
                // is accepted into observable retry state, never rejected;
                // this is File's OWN historical behavior, deliberately NOT
                // Registry's immediate-rejection policy (spark_registry.cpp's
                // watch() erases + returns unexpected here — do not copy
                // that shape onto File). report_health=false: see this
                // file's header comment, OWNERSHIP/DISPATCH PROTOCOL rule 6.
                resolve_probe_locked(*w, std::move(*taken), discards, /*report_health=*/false);
                if (w->probe == ProbeState::Deferred) {
                    // The fast resolution was a failure, not a success: this
                    // obligation was accepted but has never observed
                    // anything yet — cover the eventual establishment with a
                    // resync fire (#2012/#3840 gap-2 trigger). Registry has
                    // no analogous site: it rejects on this path instead of
                    // accepting into retry (see Decision #3 above).
                    w->needs_resync = true;
                    w->resync_epoch = ++resync_epoch_;
                }
            } else {
                // Still outstanding past the caller budget: publish to
                // run()'s own sweep, success-with-pending. From here the
                // watch is armed-from-the-caller's-view but not yet
                // watching — a change in this window is caught by the
                // synthetic fire the sweep emits on commit (#2012/#3840
                // gap-2 trigger: published-pending establishment; mirrors
                // spark_registry.cpp watch()'s identical site).
                //
                // Establishment signal: this obligation is accepted but not yet watching, so it has
                // NO coverage yet — report None explicitly, exactly as
                // spark_registry.cpp's identical branch does. The engine's
                // armed-entry cache already defaults to None, so the pull
                // query alone cannot tell this mark from its absence; a
                // direct mechanism-level sink observer can. Under mu_, so the
                // mark lands in the same lock hold that publishes w->call: the
                // first sweep visit that sees the pending call also sees the
                // due marker. The shared nudge_locked() below (this branch is
                // `live`) wakes the sweeper — no second nudge here.
                mark_coverage_locked(*w, SparkCoverage::None);
                w->call = std::move(call);
                w->needs_resync = true;
                w->resync_epoch = ++resync_epoch_;
            }
            if (live)
                nudge_locked(); // this mechanism's only timer is run()'s own
                                // GetQueuedCompletionStatus wait — whatever this
                                // call just staged (Deferred retry, admission
                                // backoff, still-outstanding grace, or an
                                // Ancestor-mode confirmation_due) needs a prompt
                                // sweep pass, not a wait for an unrelated dir's
                                // completion to happen to wake the loop.
        }
        return {};
    }

    bool set_established_sink(SparkEstablishedFn sink) override {
        std::lock_guard lk(mu_);
        if (sink_sealed_)
            return false;
        established_ = std::move(sink);
        return true;
    }

    void unwatch(const std::string& key) override {
        std::lock_guard lk(mu_);
        // Deliberately NOT reported: the engine has
        // already erased armed_[key] before calling unwatch() (or skipped the
        // call entirely on adoption — watch_incarnation()'s join branch
        // above), so a report from here would be dropped by
        // SparkEngine::report_established's identity check by construction.
        // unwatch() also must not call established_() synchronously
        // (spark_mechanism.hpp's mechanism contract, the same reentrancy
        // prohibition as emit()/fault()). A remaining sibling key's own
        // coverage is unchanged — the directory's watch itself is untouched
        // unless `keys` becomes empty, in which case there is no DirWatch
        // left to report against.
        FilePassWork discards;
        reserve_discard_capacity(discards);
        unwatch_locked(key, discards);
        // `discards` destructs here, mu_ still held — see watch()'s #1981
        // path for why this is an accepted, bounded exception for File.
    }

    void stop() override {
        {
            std::lock_guard lk(mu_);
            if (!iocp_)
                return;
        }
        stop_.store(true, std::memory_order_release);
        ::PostQueuedCompletionStatus(iocp_.get(), 0, kControlKey, nullptr);
        if (worker_.joinable())
            worker_.join();

        std::lock_guard lk(mu_);
        // Abandon every independent (not-yet-reconciled) discovery probe:
        // never let a late result commit into a DirWatch after stop().
        for (auto& [dirkey, slot] : dirs_) {
            if (slot && slot->call) {
                if (!slot->call->done())
                    quarantined_.fetch_add(1, std::memory_order_relaxed); // sg-6 parity
                slot->call.reset(); // destructs here, under mu_ — see note below
                probe_discarded_.fetch_add(1, std::memory_order_relaxed);
            }
        }
        // NOTE: destroying an abandoned DetachedCall<FileProbeResult> under
        // mu_ here (rather than staging it off-lock like every other path in
        // this file) is a deliberate, narrow exception at shutdown only: a
        // FileProbeResult never carries a live, IOCP-associated I/O (this
        // file's header comment), so its disposal is always fast/non-blocking
        // regardless of lock context, and stop() is not a hot/contended path.

        // F2: the worker is joined, but a ReadDirectoryChangesW may still be
        // outstanding — the kernel writes into buf/ov until it completes, so a
        // bare CloseHandle+free races that write (UAF). Cancel every
        // outstanding read across ALL three containers (dirs_, ancestors_,
        // retiring_) and then REAP the cancelled completions from the IOCP
        // before freeing. UNCHANGED from the pre-PR-B2 shutdown drain.
        std::size_t pending = 0;
        auto cancel = [&](const std::unique_ptr<DirWatch>& w) {
            if (!w)
                return;
            if (w->handle && w->io_pending) {
                ::CancelIoEx(w->handle.get(), &w->ov);
                ++pending;
            }
        };
        for (auto& [k, w] : dirs_)
            cancel(w);
        for (auto& [k, w] : ancestors_)
            cancel(w);
        for (auto& w : retiring_)
            cancel(w);
        bool lost_completion = false;
        while (pending > 0) {
            DWORD bytes = 0;
            ULONG_PTR ckey = 0;
            LPOVERLAPPED ov = nullptr;
            const BOOL ok = ::GetQueuedCompletionStatus(iocp_.get(), &bytes, &ckey, &ov, 2000);
            if (!ok && ov == nullptr) {
                lost_completion = true;
                break;
            }
            if (ckey == kControlKey)
                continue;
            --pending;
        }
        if (lost_completion) {
            static std::vector<std::unique_ptr<DirWatch>> s_quarantine;
            std::size_t leaked = 0;
            for (auto it = dirs_.begin(); it != dirs_.end();) {
                if (it->second && it->second->io_pending) {
                    s_quarantine.push_back(std::move(it->second));
                    it = dirs_.erase(it);
                    ++leaked;
                } else {
                    ++it;
                }
            }
            for (auto it = ancestors_.begin(); it != ancestors_.end();) {
                if (it->second && it->second->io_pending) {
                    s_quarantine.push_back(std::move(it->second));
                    it = ancestors_.erase(it);
                    ++leaked;
                } else {
                    ++it;
                }
            }
            for (auto& w : retiring_)
                if (w && w->io_pending) {
                    s_quarantine.push_back(std::move(w));
                    ++leaked;
                }
            spdlog::error("spark_file: shutdown drain lost a completion — quarantined {} "
                          "outstanding watch(es) to process lifetime to avoid a UAF",
                          leaked);
            quarantined_.fetch_add(leaked, std::memory_order_relaxed);
        }
        dirs_.clear();
        ancestors_.clear();
        retiring_gauge_.fetch_sub(retiring_.size(), std::memory_order_relaxed);
        retiring_.clear();
        key_index_.clear();
        iocp_.reset();
        emit_ = nullptr;
        fault_ = nullptr;
        established_ = nullptr; // after the worker is joined, like emit_/fault_ above
    }

    /// Lock-free — callable from any thread without coordinating with mu_.
    [[nodiscard]] SparkMechanismStats stats() const override {
        return {
            .retiring = retiring_gauge_.load(std::memory_order_relaxed),
            .retiring_cap = kRetiringCap,
            .watch_rejected_total = watch_rejected_.load(std::memory_order_relaxed),
            .quarantined_total = quarantined_.load(std::memory_order_relaxed),
            .slow_op_total = slow_op_.load(std::memory_order_relaxed),
            .inert = inert_.load(std::memory_order_acquire),
        };
    }

    // ── test seams ────────────────────────────────────────────────────────
    void apply_test_controls(FileMechanismTestControls c) {
        std::lock_guard lk(mu_);
        if (c.probe_hook)
            probe_hook_ = std::make_shared<const std::function<void(std::wstring_view)>>(
                std::move(c.probe_hook));
        else
            probe_hook_.reset();
        if (c.emit_bookkeeping_hook)
            test_emit_bookkeeping_hook_ =
                std::make_shared<const std::function<void()>>(std::move(c.emit_bookkeeping_hook));
        else
            test_emit_bookkeeping_hook_.reset();
        // Both of the following are read only under mu_ (route_noop_rearm /
        // process_completion_locked run exclusively on run()'s owner thread,
        // which always holds mu_) and only ever written here, also under
        // mu_ - unlike probe_hook_/test_emit_bookkeeping_hook_ above, which
        // must be readable from a DETACHED worker thread with no lock of its
        // own, a plain std::function member (no shared_ptr indirection) is
        // sufficient and simpler.
        ancestor_rearm_fail_hook_ = std::move(c.ancestor_rearm_fail_hook);
        notify_fail_hook_ = std::move(c.notify_fail_hook);
        ancestor_invalidate_fail_hook_ = std::move(c.ancestor_invalidate_fail_hook);
        real_rearm_fail_hook_ = std::move(c.real_rearm_fail_hook);
        completion_hook_ = std::move(c.completion_hook);
        reserve_probe_fail_hook_ = std::move(c.reserve_probe_fail_hook);
        resolve_log_fail_hook_ = std::move(c.resolve_log_fail_hook);
        ancestor_insert_fail_hook_ = std::move(c.ancestor_insert_fail_hook);
        watch_register_fail_hook_ = std::move(c.watch_register_fail_hook);
        attach_fail_hook_ = std::move(c.attach_fail_hook);
        commit_attach_fail_hook_ = std::move(c.commit_attach_fail_hook);
        pass_fail_hook_ = std::move(c.pass_fail_hook);
        if (c.probe_lane_cap)
            probe_lane_.set_cap_for_test(c.probe_lane_cap);
        if (c.retiring_cap)
            retiring_cap_override_.store(c.retiring_cap, std::memory_order_relaxed);
        if (c.caller_wait_budget.count() > 0)
            caller_wait_ms_.store(c.caller_wait_budget.count(), std::memory_order_relaxed);
        if (c.health_grace.count() > 0)
            health_grace_ms_.store(c.health_grace.count(), std::memory_order_relaxed);
        if (c.sweep_cadence.count() > 0)
            sweep_cadence_ms_.store(c.sweep_cadence.count(), std::memory_order_relaxed);
        if (c.backend_retry_base.count() > 0)
            backend_retry_base_ms_.store(c.backend_retry_base.count(), std::memory_order_relaxed);
        if (c.admission_backoff_seed.count() > 0)
            admission_seed_ms_.store(c.admission_backoff_seed.count(), std::memory_order_relaxed);
        if (c.traversal_budget.count() > 0)
            traversal_budget_ms_.store(c.traversal_budget.count(), std::memory_order_relaxed);
        if (iocp_)
            ::PostQueuedCompletionStatus(iocp_.get(), 0, kControlKey, nullptr); // nudge — control changed
    }

    [[nodiscard]] FileMechanismDebugCounters debug_counters() const {
        FileMechanismDebugCounters d;
        d.probe_launched = probe_launched_.load(std::memory_order_relaxed);
        d.probe_admission_rejected = probe_admission_rejected_.load(std::memory_order_relaxed);
        d.probe_launch_failed = probe_launch_failed_.load(std::memory_order_relaxed);
        d.probe_backend_failed = probe_backend_failed_.load(std::memory_order_relaxed);
        d.probe_discarded = probe_discarded_.load(std::memory_order_relaxed);
        d.synthetic_fires = synthetic_fires_.load(std::memory_order_relaxed);
        d.health_edges = health_edges_.load(std::memory_order_relaxed);
        d.emit_failed = emit_failed_.load(std::memory_order_relaxed);
        d.fault_failed = fault_failed_.load(std::memory_order_relaxed);
        d.resync_retries = resync_retries_.load(std::memory_order_relaxed);
        d.established_failed = established_failed_.load(std::memory_order_relaxed);
        d.pass_failed = pass_failed_.load(std::memory_order_relaxed);
        d.probe_workers_active = probe_lane_.active_workers();
        std::lock_guard lk(mu_);
        d.pass_failures_consecutive = pass_failures_;
        d.pass_backoff_ms = pass_backoff_.count();
        d.live_dirs = dirs_.size();
        d.live_ancestors = ancestors_.size();
        d.retiring = retiring_.size();
        return d;
    }

    /// #2839: install the retire fault hook (unchanged from pre-PR-B2 — the
    /// hazard it targets, push_retiring()'s own allocating statement, is
    /// untouched by this PR).
    void set_retire_fault_hook_for_test(std::function<void()> hook) {
        std::lock_guard lk(mu_);
        retire_fault_hook_for_test_ = std::move(hook);
    }

private:
    // ── tunables (atomics so the test seam can override without a rebuild) ──
    [[nodiscard]] std::chrono::milliseconds caller_wait_budget() const {
        return std::chrono::milliseconds(caller_wait_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds health_grace() const {
        return std::chrono::milliseconds(health_grace_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds sweep_cadence() const {
        return std::chrono::milliseconds(sweep_cadence_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds backend_retry_base() const {
        return std::chrono::milliseconds(backend_retry_base_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds admission_seed() const {
        return std::chrono::milliseconds(admission_seed_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::chrono::milliseconds traversal_budget() const {
        return std::chrono::milliseconds(traversal_budget_ms_.load(std::memory_order_relaxed));
    }
    [[nodiscard]] std::size_t retiring_cap() const {
        const auto ov = retiring_cap_override_.load(std::memory_order_relaxed);
        return ov ? ov : kRetiringCap;
    }

    static void reserve_discard_capacity(FilePassWork& w) {
        // A local, inline commit (watch()'s own first-probe path, or a plain
        // unwatch()) touches at most a small, fixed number of entries — cheap
        // headroom, not a derived bound (mirrors spark_registry.cpp watch()'s
        // own local `discards` reservation).
        w.stale_calls.reserve(2);
        w.dead_results.reserve(2);
        w.dead_watches.reserve(2);
        w.old_handles.reserve(2);
        w.notices.reserve(8);
        w.probe_launches.reserve(2);
    }

    /// Wake run()'s loop so its very next GetQueuedCompletionStatus wait is
    /// recomputed against wait_timeout_locked() — this mechanism's only
    /// timer. Needed after watch() stages any obligation that has no live
    /// I/O of its own to eventually produce a completion (a Deferred retry,
    /// an admission backoff, or a first-ever probe that found nothing at all
    /// to arm — #1927's nonexistent-drive-root case): without a nudge,
    /// run() could otherwise sit blocked — up to INFINITE, if dirs_/
    /// ancestors_ was previously empty — until some UNRELATED watch's
    /// completion happens to wake it. A no-op before start()/after stop()
    /// (iocp_ unengaged). Under mu_.
    void nudge_locked() {
        if (iocp_)
            ::PostQueuedCompletionStatus(iocp_.get(), 0, kControlKey, nullptr);
    }

    /// Coverage-transition marker (rung 9c PR-6 item 1):
    /// every coverage-transition site calls this and nothing else — three
    /// scalar writes, unconditional, never gated on the watch's prior
    /// coverage (there is no "edge" logic anywhere in this mechanism).
    /// Staging into FilePassWork::established happens exactly once, later, at
    /// the sweep visit (sweep_probes_locked() via stage_established_locked());
    /// dispatch happens exactly once, later still, in run_off_lock() with mu_
    /// released (established_ is never called from here, or from any of this
    /// function's callers). noexcept: reached from noexcept call sites
    /// (defer_admission_locked() via reconcile_probe_launches_locked()) where
    /// an escaping exception is process death; std::chrono::steady_clock::now()
    /// is itself noexcept, so three scalar writes is all this may ever be.
    static void mark_coverage_locked(DirWatch& w, SparkCoverage c) noexcept {
        w.coverage = c;
        w.coverage_at = Clock::now();
        w.coverage_report_due = true;
    }

    /// Reserve a discovery/establishment obligation for real dir `w`: no I/O,
    /// single-flight (a no-op if `w.probe == Pending` already). Promotes
    /// Idle -> Pending or a due Deferred -> Pending. `reappearance` marks this
    /// specific obligation as triggered by an ancestor's own fire (an absent
    /// target that might now exist) — consumed at commit to decide whether a
    /// Target-mode result needs a synthetic resync fire.
    std::optional<FileProbeJob> reserve_probe_locked(DirWatch& w, bool reappearance = false) {
        if (w.probe == ProbeState::Pending)
            return std::nullopt;
        const bool fresh = (w.probe == ProbeState::Idle);
        // Build the job FIRST (#2012/#3840 review finding 5): `job.dir = w.dir`
        // is the one allocating statement in this function. Stamp NO state on
        // `w` until `job` is fully, non-throwingly constructed - a throw here
        // (six run()-thread call sites feed this function) must leave `w`
        // exactly as it was (Idle, or a due Deferred still due), never
        // Pending with no call and no launch record; sweep_probes_locked's
        // Pending case is a no-op without a call, so that state is otherwise
        // unrescuable.
        if (reserve_probe_fail_hook_)
            reserve_probe_fail_hook_(w.dir); // test seam: may throw to model job.dir's
                                             // own allocation failing
        FileProbeJob job;
        job.dir = w.dir;
        job.hook = probe_hook_;
        job.traversal_budget = traversal_budget();
        // Non-throwing tail: scalar/generation writes only.
        w.probe = ProbeState::Pending;
        w.probe_gen = ++gen_;
        if (fresh) {
            w.accepted_at = Clock::now();
            w.grace_counted = false;
        }
        if (reappearance)
            w.probe_is_reappearance = true;
        return job;
    }

    /// Reserve `w`'s obligation AND stage a complete FilePassWork::ProbeLaunch
    /// for it, as one operation (#2012/#3840 review finding 2). Every caller
    /// that used to do `if (auto job = reserve_probe_locked(w))
    /// work.probe_launches.push_back({w.map_key, w.probe_gen, std::move(job),
    /// ...})` copied `w.map_key` into ProbeLaunch::dirkey AFTER
    /// reserve_probe_locked() had already stamped Pending — a throw during
    /// that copy left Pending with no call and no launch record, at five
    /// separate call sites (a sixth, inside invalidate_ancestor_locked, is
    /// closed instead by removing the reservation call there entirely — see
    /// its own doc comment). Copying `dirkey` HERE, before calling
    /// reserve_probe_locked at all, means a throw during the copy leaves `w`
    /// completely untouched; a throw inside reserve_probe_locked itself is
    /// already safe per its own doc comment. Caller must have pre-reserved
    /// work.probe_launches' capacity (same discipline every call site
    /// already follows). Returns false (no-op, `w` untouched) if `w` is
    /// already Pending — single-flight, watch()'s own dedicated
    /// reserve_probe_locked() caller is unaffected by this wrapper.
    bool stage_probe_locked(DirWatch& w, FilePassWork& work, bool reappearance = false) {
        if (w.probe == ProbeState::Pending)
            return false;
        std::wstring dirkey_copy = w.map_key; // the throwing copy — now strictly before any
                                              // Pending stamp, not after
        auto job = reserve_probe_locked(w, reappearance);
        if (!job)
            return false; // defensive only — w.probe cannot have raced to Pending under mu_
        work.probe_launches.push_back({std::move(dirkey_copy), w.probe_gen, std::move(*job),
                                       DetachedLaunch::LaunchFailed, std::nullopt});
        return true;
    }

    /// Admission refused (probe lane cap / launch failure): keep the
    /// obligation, retry on the admission schedule. Never counts as a backend
    /// attempt. Under mu_. noexcept-safe (scalar/atomic only).
    void defer_admission_locked(DirWatch& w, DetachedLaunch status) {
        if (status == DetachedLaunch::Rejected)
            probe_admission_rejected_.fetch_add(1, std::memory_order_relaxed);
        else
            probe_launch_failed_.fetch_add(1, std::memory_order_relaxed);
        w.probe = ProbeState::Deferred;
        w.call.reset();
        ++w.admission_attempts;
        w.next_retry_at =
            Clock::now() + doubled(admission_seed(), w.admission_attempts, kFileAdmissionBackoffCap);
        // No coverage established on this path, in every calling context
        // (watch_incarnation's admission-refused branch, reconcile_probe_
        // launches_locked's noexcept recovery, unwind_pass_locked's consumed-
        // completion recovery) - mark unconditionally.
        mark_coverage_locked(w, SparkCoverage::None);
    }

    /// key_index_'s CURRENT registration generation for `k` (0 if `k` is
    /// somehow not registered — cannot legitimately happen for a key drawn
    /// from a live DirWatch's own `keys` map, but a lookup miss must never
    /// crash a staging pass). Under mu_.
    [[nodiscard]] std::uint64_t key_gen_for(const std::string& k) const {
        auto it = key_index_.find(k);
        return it != key_index_.end() ? it->second.gen : 0;
    }

    /// key_index_'s CURRENT SparkIncarnation for `k` (rung 9c PR-6 item 1) —
    /// kNoSparkIncarnation if `k` is somehow not registered, same defensive
    /// shape as key_gen_for() above. Under mu_.
    [[nodiscard]] SparkIncarnation key_incarnation_for(const std::string& k) const {
        auto it = key_index_.find(k);
        return it != key_index_.end() ? it->second.incarnation : kNoSparkIncarnation;
    }

    /// Fan a Fault (or recovered) edge out to every key currently in `w.keys`
    /// — only if `health_desired_faulted != health_reported_faulted` (an
    /// actual edge, never every completion). Under mu_.
    void check_health_edge_locked(DirWatch& w, FilePassWork& work) {
        if (w.health_desired_faulted == w.health_reported_faulted)
            return;
        std::size_t n = 0;
        for (auto& [fname, keys] : w.keys)
            n += keys.size();
        // Reserve BEFORE staging (governance sg-7/cs-3 shape): a throw
        // mid-fan-out must not leave a PARTIAL edge staged that this
        // function's own diff-check would then never re-attempt
        // (health_reported_faulted is only stamped AFTER the loop below).
        work.notices.reserve(work.notices.size() + n);
        for (auto& [fname, keys] : w.keys)
            for (const auto& k : keys)
                work.notices.push_back({FilePassWork::Notice::Kind::Fault, k,
                                        w.health_desired_faulted, w.fault_reason, 0, w.map_key, &w,
                                        false, key_gen_for(k)});
        w.health_reported_faulted = w.health_desired_faulted;
        health_edges_.fetch_add(1, std::memory_order_relaxed);
    }

    /// Drain `w`'s coverage marker into `work.established` — one entry per
    /// spark key currently in `w.keys`, each carrying that key's OWN KeyBinding::
    /// incarnation, not a shared per-directory value. Mirrors check_health_
    /// edge_locked's shape: reserve BEFORE staging (a throw mid-fan-out must
    /// not leave a partial batch staged that this function's own `due` check
    /// would then never re-attempt — `coverage_report_due` is cleared only
    /// AFTER the loop below, same "push before flip" ordering rule 2 as
    /// Fault-edge staging). No-op if nothing is due. Under mu_.
    void stage_established_locked(DirWatch& w, FilePassWork& work) {
        if (!w.coverage_report_due)
            return;
        std::size_t n = 0;
        for (auto& [fname, keys] : w.keys)
            n += keys.size();
        work.established.reserve(work.established.size() + n);
        for (auto& [fname, keys] : w.keys)
            for (const auto& k : keys)
                work.established.push_back(
                    {k, key_incarnation_for(k), w.coverage_at, w.coverage, w.map_key});
        w.coverage_report_due = false;
    }

    /// Bookkeeping-only half of a genuine backend failure: transitions the
    /// probe to Deferred and schedules a retry on the 30 s doubling
    /// schedule. Deliberately does NOT touch health state or stage any
    /// notice — fail_backend_locked (below) adds that for every call site
    /// that runs inside a pass an owner thread will actually flush through
    /// run_off_lock. watch()'s own immediate-result branch (Decision #3,
    /// this file's header comment rule 6) calls this directly instead: its
    /// local `discards` never reaches run_off_lock, so a notice staged there
    /// would be staged and then silently LOST, not merely delayed — the
    /// health-grace timer (already running from `accepted_at`) reports the
    /// same edge correctly, through run()'s own dispatch, if establishment
    /// is still unhealthy by its next sweep pass. State changes are ordered
    /// BEFORE the log line so a throwing spdlog::warn can never leave the
    /// watch un-deferred. Under mu_.
    void defer_backend_retry_locked(DirWatch& w, const char* reason, DWORD err) {
        probe_backend_failed_.fetch_add(1, std::memory_order_relaxed);
        w.probe = ProbeState::Deferred;
        w.call.reset();
        ++w.backend_attempts;
        w.next_retry_at =
            Clock::now() + doubled(backend_retry_base(), w.backend_attempts, kFileBackendRetryCap);
        // Genuine backend failure - no coverage, in every calling context
        // (fail_backend_locked, commit_probe_locked's/attach_*_locked's catch
        // and failure branches, watch()'s Decision #3 fast-resolve path) -
        // mark unconditionally.
        mark_coverage_locked(w, SparkCoverage::None);
        spdlog::warn("spark_file: establishing '{}' failed ({}, err={}) - watch is deaf until the "
                     "retry",
                     ::yuzu::log_key_token(fs::path(w.dir).string()), reason, err);
    }

    /// Genuine backend failure with a dispatch pass behind it: the
    /// bookkeeping above, plus the health-edge report. Under mu_.
    void fail_backend_locked(DirWatch& w, const char* reason, DWORD err, FilePassWork& work) {
        defer_backend_retry_locked(w, reason, err);
        w.health_desired_faulted = true;
        w.fault_reason = reason;
        check_health_edge_locked(w, work);
    }

    void grace_check_locked(DirWatch& w, Clock::time_point now, FilePassWork& work) {
        if (w.grace_counted || now - w.accepted_at <= health_grace())
            return;
        w.grace_counted = true;
        slow_op_.fetch_add(1, std::memory_order_relaxed);
        w.health_desired_faulted = true;
        w.fault_reason = "file watch establishment pending past grace";
        check_health_edge_locked(w, work);
    }

    /// Walk the FILE_NOTIFY_INFORMATION records in `bytes` and stage an Emit
    /// notice for each spark key whose filename changed. `bytes == 0` =
    /// buffer overflow: fire EVERY key in the dir (never miss one). Under mu_.
    void stage_fire_locked(DirWatch& w, DWORD bytes, FilePassWork& work) {
        std::size_t n = 0;
        for (auto& [fname, keys] : w.keys)
            n += keys.size();
        work.notices.reserve(work.notices.size() + n);
        if (bytes == 0) {
            for (auto& [fname, keys] : w.keys)
                for (const auto& k : keys)
                    work.notices.push_back({FilePassWork::Notice::Kind::Emit, k, false, "", 0,
                                            w.map_key, &w, false, key_gen_for(k)});
            return;
        }
        std::size_t off = 0;
        for (;;) {
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) > bytes)
                break;
            const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(w.buf + off);
            const std::size_t name_bytes = info->FileNameLength;
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) + name_bytes > bytes)
                break;
            const std::wstring fname =
                fold_ci(std::wstring_view(info->FileName, name_bytes / sizeof(WCHAR)));
            auto fi = w.keys.find(fname);
            if (fi != w.keys.end())
                for (const auto& k : fi->second)
                    work.notices.push_back({FilePassWork::Notice::Kind::Emit, k, false, "", 0,
                                            w.map_key, &w, false, key_gen_for(k)});
            if (info->NextEntryOffset == 0)
                break;
            off += info->NextEntryOffset;
        }
    }

    /// Stage a synthetic (resync) Emit for every key currently in `w.keys`,
    /// clearing needs_resync (restored later, on the same epoch, only if the
    /// submit itself throws — see publish_pass_locked()). Under mu_.
    void stage_resync_emit_locked(DirWatch& w, FilePassWork& work) {
        std::size_t n = 0;
        for (auto& [fname, keys] : w.keys)
            n += keys.size();
        work.notices.reserve(work.notices.size() + n);
        for (auto& [fname, keys] : w.keys)
            for (const auto& k : keys)
                work.notices.push_back({FilePassWork::Notice::Kind::Emit, k, false, "",
                                        w.resync_epoch, w.map_key, &w, true, key_gen_for(k)});
        w.needs_resync = false;
        w.resync_dispatch_in_flight = true; // cleared by reconcile_notice_outcomes_locked/
                                            // restore_unattempted_notices_locked once this
                                            // batch's outcome is known
        synthetic_fires_.fetch_add(1, std::memory_order_relaxed);
    }

    /// Drop `dependent`'s dependency on its current ancestor shelter (if
    /// any); tear the ancestor down when no absent dir still needs it (S1).
    /// Unchanged in SHAPE from the pre-PR-B2 release_ancestor() — every
    /// ancestor slot this mechanism creates always has a live read issued at
    /// creation, so the `handle && io_pending` guard below is the ordinary
    /// case, not defensive dead code. Under mu_.
    void release_ancestor_locked(DirWatch& dependent) {
        if (dependent.ancestor_key.empty())
            return;
        auto it = ancestors_.find(dependent.ancestor_key);
        dependent.ancestor_key.clear();
        if (it == ancestors_.end())
            return;
        if (--it->second->refcount > 0)
            return;
        if (it->second->handle && it->second->io_pending) {
            it->second->removing = true;
            ::CancelIoEx(it->second->handle.get(), &it->second->ov);
            try {
                push_retiring(it->second);
            } catch (...) {
                return; // left whole in ancestors_ (already removing+cancelled) for
                       // drop_watch() to reclaim when the aborted completion drains
            }
        }
        ancestors_.erase(it);
    }

    /// `w` (a real dir) probed to Target mode. Install the new handle only
    /// AFTER both the IOCP association and the first read succeed — every
    /// risky OS call runs against a LOCAL handle first; nothing that can
    /// throw runs between a successfully-issued read and this dir taking
    /// ownership of it (so a throw can never leave a live, kernel-owned read
    /// pointing at storage this function is about to abandon). Returns false
    /// if it degraded into a scheduled retry instead (already routed through
    /// fail_backend_locked/defer_backend_retry_locked, per `report_health` —
    /// the caller must not also touch backend_attempts/grace on that path).
    /// `report_health` (default true): false for exactly one caller — watch()'s
    /// own fast-resolve-inside-the-caller-window branch (Decision #3), whose
    /// local FilePassWork is never flushed through run_off_lock, so a Fault
    /// notice staged here would be silently lost, not merely delayed, AND
    /// would wrongly pre-stamp health_reported_faulted == health_desired_
    /// faulted, permanently suppressing the real edge once a dispatched pass
    /// finally does observe it (#2012/#3840 review finding 7). Under mu_.
    [[nodiscard]] bool attach_dir_locked(DirWatch& w, FileProbeResult& res, FilePassWork& work,
                                         bool report_health = true) {
        if (attach_fail_hook_ && attach_fail_hook_(w.dir)) {
            // Test seam: model the real CreateIoCompletionPort/
            // ReadDirectoryChangesW calls failing without making them, with
            // no handle ever associated — leaves exactly the state the
            // first `if` below would on a genuine failure. `res` still holds
            // a real, valid (if now-unwanted) unassociated handle — stage it
            // through work.dead_results like every other failure branch
            // below, rather than relying on implicit stack-unwind timing.
            work.dead_results.push_back(std::move(res));
            if (report_health)
                fail_backend_locked(w, "IOCP associate failed (test)", 0, work);
            else
                defer_backend_retry_locked(w, "IOCP associate failed (test)", 0);
            return false;
        }
        DirHandle new_handle = std::move(res.handle);
        if (!::CreateIoCompletionPort(new_handle.get(), iocp_.get(), reinterpret_cast<ULONG_PTR>(&w),
                                      0)) {
            const DWORD err = ::GetLastError();
            work.dead_results.push_back(std::move(res));
            if (report_health)
                fail_backend_locked(w, "IOCP associate failed", err, work);
            else
                defer_backend_retry_locked(w, "IOCP associate failed", err);
            return false; // new_handle destructs here — never associated, safe
        }
        const bool queued = ::ReadDirectoryChangesW(new_handle.get(), w.buf, sizeof(w.buf), FALSE,
                                                    kFilter, nullptr, &w.ov, nullptr) != 0;
        if (!queued) {
            const DWORD err = ::GetLastError();
            work.dead_results.push_back(std::move(res));
            if (report_health)
                fail_backend_locked(w, "ReadDirectoryChangesW failed", err, work);
            else
                defer_backend_retry_locked(w, "ReadDirectoryChangesW failed", err);
            return false; // associated but no I/O was ever queued — safe
        }
        // Live I/O now outstanding against w.ov/w.buf under new_handle's
        // value — nothing below may throw before ownership transfers to `w`
        // (capacity pre-reserved by the per-pass top-of-loop reserve() calls;
        // see run()'s own comment).
        if (w.handle)
            work.old_handles.push_back(std::move(w.handle)); // nothrow given the reservation
        w.handle = std::move(new_handle);
        w.io_pending = true;
        release_ancestor_locked(w); // drop the (no longer needed) shelter dependency, if any —
                                    // never touches w.handle/w.ov/w.buf, so safe to run after
        w.confirmation_due = false;
        return true;
    }

    /// `w` (a real dir) probed to Ancestor mode: `res` carries an
    /// already-opened, unassociated handle for `res.resolved_dir`. Reuse a
    /// live ancestor slot for that exact path if one exists; otherwise
    /// associate + arm `res.handle` as a new slot. `report_health`: threaded
    /// through to create_ancestor_from_probe_locked — see attach_dir_locked's
    /// doc comment for the one caller that passes false. Under mu_.
    [[nodiscard]] bool attach_ancestor_locked(DirWatch& w, FileProbeResult& res, FilePassWork& work,
                                              bool report_health = true) {
        if (w.handle)
            work.old_handles.push_back(std::move(w.handle)); // defensive; shouldn't normally be
                                                              // engaged here
        std::wstring akey = fold_ci(res.resolved_dir);
        // Captured BEFORE any reassignment below (Gap-3 fix): true iff `w`
        // was ALREADY sheltered by this exact ancestor before this commit —
        // the STABLE case. invalidate_ancestor_locked/release_ancestor_locked
        // always clear a dependent's ancestor_key on teardown, so a stale key
        // surviving a real slot recreation is not reachable here — plain
        // string identity is sufficient.
        const bool same_shelter = (w.ancestor_key == akey);
        if (w.ancestor_key != akey)
            release_ancestor_locked(w);
        if (w.ancestor_key == akey) {
            work.dead_results.push_back(std::move(res)); // duplicate handle — already sheltered here
        } else {
            auto ait = ancestors_.find(akey);
            if (ait != ancestors_.end() && ait->second && !ait->second->removing &&
                ait->second->io_pending) {
                work.dead_results.push_back(std::move(res));
                // Move-assign (nothrow — `akey` is a local, owned value) BEFORE
                // bumping refcount: a copy-assign here could throw and leave the
                // refcount incremented with no dependent actually pointing at it
                // (the same trap-table line-626 hazard create_ancestor_from_
                // probe_locked's own ordering closes — this reuse path had it
                // open).
                w.ancestor_key = std::move(akey);
                ait->second->refcount++;
            } else {
                if (ait != ancestors_.end() && ait->second) {
                    if (ait->second->dead_pending_invalidate) {
                        // This ancestor is marked dead (unwind_pass_locked's
                        // allocation-free recovery marker, #2012/#3840
                        // review finding 2) but hasn't been swept yet.
                        // Invalidate it NOW instead of bare-erasing below: a
                        // bare erase would leave every OTHER dependent still
                        // pointing at `akey` (not just `w`, which is about
                        // to get a fresh slot below) aliasing whatever fresh
                        // ancestor create_ancestor_from_probe_locked creates
                        // at the same key string, silently corrupting ITS
                        // refcount the next time one of them calls
                        // release_ancestor_locked/invalidate_ancestor_locked
                        // (review finding 2's race-window addendum).
                        // invalidate_ancestor_locked erases `ait` itself
                        // (dead_pending_invalidate implies no live I/O, so
                        // its own torn_down path erases unconditionally).
                        invalidate_ancestor_locked(*ait->second);
                    } else {
                        // A zombie, or an unexpected live-but-idle slot: drain it
                        // via the same path any other cancelled watch uses, free
                        // the key, and create a fresh one below.
                        bool erase_now = true;
                        if (ait->second->removing || ait->second->io_pending) {
                            try {
                                push_retiring(ait->second);
                            } catch (...) {
                                // MUST NOT erase below on this path: push_retiring's
                                // own contract leaves `ait->second` UNTOUCHED on a
                                // throw (still owning a possibly-live-I/O DirWatch) —
                                // erasing it here would be exactly the
                                // destroy-while-the-kernel-may-still-write-into-it
                                // hazard #2839 exists to prevent. Leave it whole,
                                // already removing+cancelled if it was live, for
                                // drop_watch() to reclaim when the completion drains.
                                erase_now = false;
                            }
                        }
                        if (erase_now)
                            ancestors_.erase(ait);
                    }
                }
                if (!create_ancestor_from_probe_locked(w, akey, res, work, report_health))
                    return false; // already routed through fail_backend_locked/
                                  // defer_backend_retry_locked, per report_health
            }
        }
        if (!same_shelter)
            w.confirmation_due = true; // re-probe the target once more shortly, independent
                                       // of health — the shelter-confirmation loop
                                       // (sweep_probes_locked) clears this flag right before
                                       // staging that one probe; a NEW or CHANGED shelter
                                       // (same_shelter == false) re-arms it here, a STABLE one
                                       // (same_shelter == true — this commit IS the owed
                                       // confirmation landing, or a routine re-attach with
                                       // nothing new) leaves it cleared, so a stable
                                       // relationship confirms once and stops rather than
                                       // re-arming every pass (#2012/#3840 gap-3 fix — this
                                       // used to be unconditional).
        return true;
    }

    /// Bootstrap a brand-new ancestor slot directly from a dependent's own
    /// probe result. Insert-then-arm (#2012/#3840 review finding 1): `akey`
    /// is reserved a STABLE map slot in `ancestors_` FIRST — before ANY OS
    /// call — so `slot` below is a reference into the map from the moment it
    /// exists, address-stable regardless of a LATER rehash. This restores
    /// the pre-PR-B2 shape (`auto& slot = ancestors_[akey];`, armed in
    /// place) and matches attach_dir_locked()'s reasoning: nothing that can
    /// throw ever runs between a successfully-issued read and the object it
    /// was issued against taking stable ownership. The OLD shape (build
    /// `slot` fully off-map, `ancestors_.emplace()` it LAST, after the read
    /// was already live) relied on the standard's unordered-map "insertion
    /// has no effect on failure" guarantee to mean "slot is safely
    /// reclaimable on a throw" — that guarantee actually means the opposite:
    /// a failed emplace destroys the moved-from node, including a DirWatch
    /// the kernel may still be writing into (the exact #2839 UAF class).
    /// `report_health`: see attach_dir_locked's doc comment for the one
    /// caller that passes false. Under mu_.
    [[nodiscard]] bool create_ancestor_from_probe_locked(DirWatch& w, const std::wstring& akey,
                                                         FileProbeResult& res, FilePassWork& work,
                                                         bool report_health = true) {
        auto fail = [&](const char* reason, DWORD err) {
            work.dead_results.push_back(std::move(res));
            if (report_health)
                fail_backend_locked(w, reason, err, work);
            else
                defer_backend_retry_locked(w, reason, err);
            return false;
        };
        std::wstring akey_for_dependent;
        try {
            akey_for_dependent = akey; // throwing string work — nothing committed yet
        } catch (...) {
            return fail("ancestor bookkeeping allocation failed", 0);
        }
        // Reserve the map slot BEFORE any OS call — see this function's own
        // doc comment above.
        std::unique_ptr<DirWatch>* slot_ptr = nullptr;
        try {
            if (ancestor_insert_fail_hook_)
                ancestor_insert_fail_hook_(res.resolved_dir); // test seam: models try_emplace's
                                                               // own bad_alloc/rehash failure
            auto [it, inserted] = ancestors_.try_emplace(akey);
            if (!inserted && it->second) {
                // Caller contract defense: attach_ancestor_locked() must
                // already have invalidated/erased any stale entry for
                // `akey` (including a dead_pending_invalidate-marked one —
                // see its own doc comment) before calling here. A live slot
                // surviving to this point means something upstream didn't —
                // refuse rather than silently clobber a possibly-live
                // registration.
                return fail("ancestor bookkeeping: unexpected live slot", 0);
            }
            slot_ptr = &it->second;
        } catch (...) {
            return fail("ancestor bookkeeping allocation failed", 0);
        }
        auto& slot = *slot_ptr; // reference into the map; address-stable across rehash
        try {
            slot = std::make_unique<DirWatch>();
            slot->dir = res.resolved_dir;
            slot->map_key = akey;
        } catch (...) {
            ancestors_.erase(akey); // nothing armed yet — safe to discard whole
            return fail("ancestor bookkeeping allocation failed", 0);
        }
        DirHandle new_handle = std::move(res.handle);
        if (!::CreateIoCompletionPort(new_handle.get(), iocp_.get(),
                                      reinterpret_cast<ULONG_PTR>(slot.get()), 0)) {
            const DWORD err = ::GetLastError();
            ancestors_.erase(akey); // handle never associated — nothing live; safe
            return fail("ancestor IOCP associate failed", err);
        }
        const bool queued = ::ReadDirectoryChangesW(new_handle.get(), slot->buf, sizeof(slot->buf),
                                                    FALSE, kFilter, nullptr, &slot->ov, nullptr) != 0;
        if (!queued) {
            const DWORD err = ::GetLastError();
            ancestors_.erase(akey); // associated but no I/O was ever queued — safe
            return fail("ancestor ReadDirectoryChangesW failed", err);
        }
        // Live I/O now outstanding against slot->ov/slot->buf — `slot` is
        // already map-owned and address-stable, so nothing below can destroy
        // it out from under the kernel.
        slot->handle = std::move(new_handle);
        slot->io_pending = true;
        slot->refcount = 1;
        w.ancestor_key = std::move(akey_for_dependent);
        return true;
    }

    /// A probe result for a LIVE real dir `w` (already matched by pointer
    /// identity + generation by the caller). Routes to attach_dir_locked()
    /// (Target) or attach_ancestor_locked() (Ancestor). `report_health`
    /// (default true): false for exactly one caller — see attach_dir_locked's
    /// doc comment (#2012/#3840 review finding 7). Under mu_.
    void commit_probe_locked(DirWatch& w, FileProbeResult res, FilePassWork& work,
                             bool report_health = true) {
        w.probe = ProbeState::Idle;
        w.call.reset();
        const bool was_reappearance = w.probe_is_reappearance;
        bool committed = false;
        try {
            if (commit_attach_fail_hook_)
                commit_attach_fail_hook_(w.dir); // test seam: may throw to model an allocation
                                                  // failing inside attach_*_locked's own early,
                                                  // pre-OS-call work
            committed = res.mode == WatchMode::Target
                           ? attach_dir_locked(w, res, work, report_health)
                           : attach_ancestor_locked(w, res, work, report_health);
        } catch (...) {
            // w.probe/w.call were already reset to Idle/empty above, before
            // attach_*_locked's OWN fallible work (e.g. attach_ancestor_
            // locked's fold_ci(res.resolved_dir)) had a chance to run — a
            // throw here would otherwise leave the watch looking fully at
            // rest with the just-consumed discovery result silently
            // dropped and no owner left for establishment (#2012/#3840
            // review, round-3 table opine). Route it through the same
            // graceful-degrade path attach_*_locked's own internal
            // OS-failure branches already use, so establishment keeps a
            // scheduled retry instead of vanishing. `res` is disposed
            // off-lock like every other discard in this file, not
            // destroyed here under mu_.
            work.dead_results.push_back(std::move(res));
            if (report_health)
                fail_backend_locked(w, "commit allocation failed", 0, work);
            else
                defer_backend_retry_locked(w, "commit allocation failed", 0);
            return;
        }
        if (!committed)
            return; // attach_*_locked already routed this through fail_backend_locked
        w.backend_attempts = 0;
        w.admission_attempts = 0;
        w.grace_counted = false;
        // The one positive coverage site: Target mode has live OS-level
        // notification coverage, Ancestor mode does not (it watches an
        // ancestor for the target's appearance, not the target itself) -
        // unconditional gate on res.mode alone, never special-cased
        // away for Ancestor: a Target -> Ancestor transition (the target was
        // deleted; the re-probe resolved to a shelter) is a real coverage
        // loss that must overwrite whatever Notification the engine has
        // cached. Also covers the "already sheltered here" duplicate-handle
        // branch inside attach_ancestor_locked (still Ancestor mode, still
        // correctly None) and an Ancestor -> Ancestor shelter CHANGE.
        mark_coverage_locked(w, res.mode == WatchMode::Target ? SparkCoverage::Notification
                                                               : SparkCoverage::None);
        if (res.mode == WatchMode::Target) {
            w.probe_is_reappearance = false;
            if (was_reappearance) {
                w.needs_resync = true;
                w.resync_epoch = ++resync_epoch_;
            }
        }
        if (w.health_desired_faulted) {
            w.health_desired_faulted = false;
            w.fault_reason = "recovered";
            check_health_edge_locked(w, work);
        }
        if (w.needs_resync)
            stage_resync_emit_locked(w, work);
    }

    /// Classify a resolved probe result and commit/defer accordingly.
    /// `report_health` (default true): whether a failure here also stages +
    /// reports a health-fault edge via fail_backend_locked. false is used
    /// exactly once — by watch()'s own immediate-result branch (Decision #3,
    /// this file's header comment rule 6) — whose local FilePassWork is
    /// never flushed through run_off_lock, so a notice staged there would be
    /// silently lost rather than merely delayed; the health-grace timer
    /// (already running from `accepted_at`) reports the same edge correctly,
    /// through run()'s own dispatch, if establishment is still unhealthy by
    /// its next sweep pass. Under mu_.
    void resolve_probe_locked(DirWatch& w, DetachedResult<FileProbeResult> r, FilePassWork& work,
                              bool report_health = true) {
        if (r.has_value() && r->ok) {
            commit_probe_locked(w, std::move(*r), work, report_health);
            return;
        }
        const char* reason = "file establishment failed";
        DWORD err = 0;
        const bool has_result = r.has_value();
        const char* stage_for_log = "";
        if (!has_result) {
            reason = r.error() == DetachedCallError::WorkerThrew ? "file discovery probe threw"
                                                                 : "file probe result could not be "
                                                                   "boxed";
        } else {
            // `r->stage` is always a string literal (see every `.stage = "..."`
            // assignment in FileProbeJob::open_dir/walk above) - copying the
            // pointer, not the string, survives moving `*r` below regardless.
            reason = (r->stage && r->stage[0]) ? r->stage : "file establishment failed";
            err = r->err;
            stage_for_log = r->stage;
        }
        // State transition BEFORE any logging (#2012/#3840 review finding 6 -
        // this file's own rule, stated at defer_backend_retry_locked's doc
        // comment: "so a throwing spdlog::warn can never leave the watch
        // un-deferred" - resolve_probe_locked used to violate that rule
        // itself, via its OWN separate log line below). `dead_results.
        // push_back` is an allocation too, not just the log call - both run
        // strictly after the Deferred stamp, which is the first scalar write
        // inside fail_backend_locked/defer_backend_retry_locked.
        if (report_health)
            fail_backend_locked(w, reason, err, work);
        else
            defer_backend_retry_locked(w, reason, err);
        if (has_result) {
            work.dead_results.push_back(std::move(*r));
            if (resolve_log_fail_hook_)
                resolve_log_fail_hook_(w.dir); // test seam: may throw to model the log
                                               // call's own allocation failing
            spdlog::warn("spark_file: probe for '{}' failed at {} (err={})",
                         ::yuzu::log_key_token(fs::path(w.dir).string()), stage_for_log, err);
        }
    }

    /// The ancestor `anc` (found by completion key or by its own reissue
    /// failing) can no longer be trusted. Mark it unusable, tear it down via
    /// the same retiring_ path any other cancelled watch uses, and reassign
    /// every dependent to redo its own probe from scratch — never rely on
    /// another notification arriving from the now-dead ancestor.
    ///
    /// The dependents loop is scalar-only (#2012/#3840 review finding 1): it
    /// used to reserve+launch a fresh probe for each non-Pending dependent
    /// directly, via a throwing ProbeLaunch construction that ran AFTER this
    /// ancestor's own map entry was already erased — a mid-loop throw left
    /// the tail dependents with a stale ancestor_key pointing at a
    /// now-nonexistent entry, and no marker anywhere for a later sweep to
    /// rediscover them (the erase itself wasn't the bug — moving it after
    /// the loop still leaves the CURRENT dependent's ancestor_key cleared
    /// with no reservation attempted). Instead, every dependent's release is
    /// now pure scalar/atomic writes that cannot throw, so this loop always
    /// completes for every dependent regardless of allocation pressure: a
    /// non-Pending dependent is marked confirmation_due, which
    /// sweep_probes_locked's Idle branch picks up and turns into an actual
    /// probe reservation — that pass runs immediately after this function
    /// returns in every calling context except watch()'s own immediate-
    /// result branch, which instead relies on the nudge_locked() call it
    /// already makes right after to wake run()'s loop promptly. A Pending
    /// dependent is left alone: single-flight, its own in-flight probe
    /// revalidates shelter at its own commit (attach_ancestor_locked's
    /// same_shelter gate). Under mu_.
    void invalidate_ancestor_locked(DirWatch& anc) {
        if (ancestor_invalidate_fail_hook_)
            ancestor_invalidate_fail_hook_(anc.dir); // test seam: may throw to model
                                                      // dependents.reserve()'s own
                                                      // allocation failing — see
                                                      // FileMechanismTestControls::
                                                      // ancestor_invalidate_fail_hook's
                                                      // doc comment
        const std::wstring dead_key = anc.map_key;
        // Collect dependents FIRST (a pure read, no allocation risk beyond
        // the vector's own growth, reserved against an upper bound) so the
        // reassignment loop below cannot be left half-done by a later throw.
        std::vector<DirWatch*> dependents;
        dependents.reserve(dirs_.size());
        for (auto& [dirkey, slot] : dirs_)
            if (slot && slot->ancestor_key == dead_key)
                dependents.push_back(slot.get());

        bool torn_down = true;
        auto ait = ancestors_.find(dead_key);
        if (ait != ancestors_.end() && ait->second.get() == &anc) {
            if (anc.handle && anc.io_pending) {
                // Defensive: every current call site already has io_pending
                // == false by the time this runs (the completion that
                // triggered invalidation WAS the outstanding read, or a
                // failed reissue never queued one) — this branch exists so a
                // FUTURE caller that invalidates a still-armed ancestor
                // doesn't UAF the kernel-owned buf/ov, not because it fires
                // today.
                anc.removing = true;
                ::CancelIoEx(anc.handle.get(), &anc.ov);
                try {
                    push_retiring(ait->second);
                } catch (...) {
                    torn_down = false; // left whole (already removing+cancelled) for
                                       // drop_watch() to reclaim when the completion drains
                }
            }
            if (torn_down)
                ancestors_.erase(ait);
        }

        for (DirWatch* dep : dependents) {
            dep->ancestor_key.clear();
            // Loss of shelter: every current dependent just lost whatever
            // coverage this ancestor provided (its own watch for the
            // target's reappearance) — independent of whether ITS OWN probe
            // happens to already be in flight for some unrelated reason.
            // Cover the gap with a resync fire once shelter (or the target
            // itself) is re-established (#2012/#3840 gap-2 trigger:
            // loss/change of shelter creating a coverage gap).
            dep->needs_resync = true;
            dep->resync_epoch = ++resync_epoch_;
            if (dep->probe != ProbeState::Pending)
                dep->confirmation_due = true; // picked up by sweep_probes_locked's Idle
                                              // branch — see this function's own doc comment
        }
    }

    /// Reissue the read on an ancestor watch (they carry no spark keys —
    /// nothing to fire, just stay armed). Returns false if the reissue itself
    /// failed: the caller must then invalidate this ancestor (#829's
    /// pre-existing bug — the old code discarded this exact signal, leaving
    /// no future ancestor event to ever trigger recovery for its dependents).
    [[nodiscard]] bool route_noop_rearm(DirWatch& w) {
        if (ancestor_rearm_fail_hook_ && ancestor_rearm_fail_hook_(w.dir)) {
            // Test seam: model a synchronous ReadDirectoryChangesW reissue
            // failure without making the real OS call, leaving exactly the
            // state a genuine failure would (see FileMechanismTestControls::
            // ancestor_rearm_fail_hook's doc comment).
            w.io_pending = false;
            w.handle.reset();
            return false;
        }
        w.io_pending = ::ReadDirectoryChangesW(w.handle.get(), w.buf, sizeof(w.buf), FALSE, kFilter,
                                               nullptr, &w.ov, nullptr) != 0;
        if (!w.io_pending)
            w.handle.reset(); // reissue failed synchronously — no I/O outstanding, safe to drop
        return w.io_pending;
    }

    /// An ancestor fired (something changed under it) — a previously-absent
    /// target may now exist. Stage a fresh discovery probe for every real dir
    /// currently depending on THIS ancestor and not already mid-probe
    /// (single-flight, Idle case). A dependent that IS already mid-probe
    /// (Pending) cannot be raced with a second probe, but its in-flight one
    /// was necessarily launched BEFORE this event and may have already read
    /// the target's absence stale — dropping the event here would silently
    /// strand it under the wrong shelter with no future trigger, since a
    /// stable same-shelter commit (attach_ancestor_locked's gap-3 gate)
    /// never re-arms confirmation_due on its own (#2012/#3840 gap-4: this
    /// used to just skip a Pending dependent outright). Queue the
    /// confirmation it owes instead: confirmation_due=true survives that
    /// stale commit untouched (the gap-3 gate only ever SETS it, on a
    /// changed shelter, never clears it), so the very next Idle sweep
    /// re-probes with fresh disk state — wait_timeout_locked() already wakes
    /// promptly for a due-immediately confirmation, so this is not a poll.
    /// probe_is_reappearance is set for the same reason: it is a one-way
    /// latch (reserve_probe_locked only ever sets it true, commit_probe_
    /// locked only clears it on a Target-mode commit) so it survives the
    /// same stale intermediate commit and still earns the eventual Target
    /// commit its resync fire, even though the probe that actually observes
    /// the change was not the one this function launched. Bounded: at most
    /// one extra owed re-probe per ancestor event, never a self-perpetuating
    /// loop — a re-probe that finds nothing new lands back on the same
    /// shelter and stops, exactly like the ordinary confirmation case. Under
    /// mu_.
    void reresolve_absent_locked(const std::wstring& akey, FilePassWork& work) {
        std::vector<DirWatch*> candidates;
        candidates.reserve(dirs_.size());
        for (auto& [dirkey, slot] : dirs_) {
            if (!slot || slot->ancestor_key != akey)
                continue;
            if (slot->probe == ProbeState::Idle) {
                candidates.push_back(slot.get());
            } else if (slot->probe == ProbeState::Pending) {
                slot->confirmation_due = true;
                slot->probe_is_reappearance = true;
            } else {
                // Deferred (#2012/#3840 review finding 4): this dependent's
                // own scheduled retry will eventually re-probe and usually
                // find the target, but without this latch it would commit
                // Target-mode with probe_is_reappearance == false, silently
                // dropping the ancestor-to-target appearance signal for
                // whatever changed during the gap window. Scalar-only:
                // survives untouched until that eventual commit consumes it.
                slot->probe_is_reappearance = true;
            }
        }
        work.probe_launches.reserve(work.probe_launches.size() + candidates.size());
        for (DirWatch* dep : candidates)
            stage_probe_locked(*dep, work, /*reappearance=*/true);
    }

    /// Allocation-free mirror of reresolve_absent_locked's dependent-marking
    /// half, for use inside noexcept recovery (unwind_pass_locked) where a
    /// throwing reserve/stage call cannot run. Marks every live dependent of
    /// `akey` for a fresh probe attempt — Idle/Deferred get confirmation_due
    /// (picked up by the next sweep_probes_locked pass, same allocation-free
    /// recovery path finding 1's fix uses), Pending gets nothing extra (its
    /// own eventual commit revalidates) — plus probe_is_reappearance on
    /// every one of them, so a Target-mode commit reporting the ancestor's
    /// fire still earns its resync fire (#2012/#3840 review finding 8: the
    /// successful-rearm half of the consumed-ancestor-completion recovery,
    /// which unlike the normal process_completion_locked path cannot call
    /// reserve_probe_locked/stage_probe_locked directly). Under mu_.
    void mark_reappearance_locked(const std::wstring& akey) noexcept {
        for (auto& [dirkey, slot] : dirs_) {
            if (!slot || slot->ancestor_key != akey)
                continue;
            slot->probe_is_reappearance = true;
            if (slot->probe != ProbeState::Pending)
                slot->confirmation_due = true;
        }
    }

    /// Handle one dequeued IOCP completion for `w` (a real dir or an ancestor
    /// entry, found by completion key). Never blocks: every discovery/open
    /// call is now staged as a probe reservation instead of run synchronously.
    /// Under mu_.
    void process_completion_locked(DirWatch& w, BOOL ok, DWORD bytes, FilePassWork& work) {
        if (completion_hook_)
            completion_hook_(w.dir); // test seam: may throw to model an allocation failure
                                     // landing immediately after this completion was dequeued,
                                     // before anything (reissue, probe reservation, fire notice)
                                     // has happened for it — see FileMechanismTestControls::
                                     // completion_hook's doc comment.
        const bool is_anc = is_ancestor_watch(&w);
        if (w.removing) {
            drop_watch(&w); // its aborted completion drained — free it now; do NOT touch w after
            return;
        }
        if (!ok) {
            w.handle.reset();
            if (!is_anc) {
                // Loss of target coverage: the previously-armed read itself
                // failed — this watch stops observing until it
                // re-establishes. Cover the gap with a resync fire on commit
                // (#2012/#3840 gap-2 trigger: loss of target coverage).
                w.needs_resync = true;
                w.resync_epoch = ++resync_epoch_;
                // Genuine coverage loss, unconditional, regardless of
                // whether staging the retry probe below succeeds or falls
                // back to defer_backend_retry_locked's own (redundant) mark
                // in its catch.
                mark_coverage_locked(w, SparkCoverage::None);
                try {
                    stage_probe_locked(w, work);
                } catch (...) {
                    // #2012/#3840 review round-3: w.handle was ALREADY reset
                    // above — if this throws, unwind_pass_locked's
                    // consumed-completion guard (which requires
                    // found->handle) cannot help, since the handle is
                    // already gone. A bare propagating throw would leave
                    // this watch Idle with no probe, no confirmation, no
                    // grace check (sweep_probes_locked's Idle case
                    // `continue`s past grace) — permanently deaf while
                    // needs_resync's own one-shot fire falsely reports
                    // coverage restored. Fall back to the SAME scalar,
                    // non-throwing Deferred transition the ordinary OS-call
                    // failure path already uses, matching this file's own
                    // "never strand, always Deferred-with-schedule"
                    // discipline (Kimi/Codex round-3, independently
                    // converged).
                    defer_backend_retry_locked(w, "coverage-loss probe staging failed", 0);
                }
            } else {
                try {
                    invalidate_ancestor_locked(w);
                } catch (...) {
                    // Same reasoning as above, ancestor side: w.handle was
                    // already reset by the caller (the !ok branch, above);
                    // invalidate_ancestor_locked's own dependents.reserve()
                    // is the modeled throw point. Stamp the existing
                    // allocation-free recovery marker directly rather than
                    // relying on unwind's consumed-completion guard, which
                    // excludes a handle-less entry.
                    w.dead_pending_invalidate = true;
                }
            }
            return;
        }
        if (is_anc) {
            if (!route_noop_rearm(w)) {
                try {
                    invalidate_ancestor_locked(w);
                } catch (...) {
                    w.dead_pending_invalidate = true; // see the !ok branch's identical catch, above
                }
            } else {
                try {
                    reresolve_absent_locked(w.map_key, work);
                } catch (...) {
                    // #2012/#3840 review finding 8's own incompleteness note
                    // (round-2 synthesis, confirmed by round-3 opine): a
                    // throw here lands with w.io_pending already true
                    // (route_noop_rearm already succeeded) — unwind_pass_
                    // locked's consumed-completion guard requires
                    // !io_pending, so it cannot recover this. Fall back to
                    // the same allocation-free marker the noexcept recovery
                    // path uses: every dependent still gets its
                    // reappearance latch, just deferred to the next sweep
                    // pass instead of reresolve_absent_locked's immediate
                    // launch.
                    mark_reappearance_locked(w.map_key);
                }
            }
            return;
        }
        // Ordinary real-dir notification: fire first (arm-before-check for
        // THIS read already happened when it was issued), then reissue.
        // stage_fire_locked allocates (notices.reserve, a string copy per
        // changed key) and can throw; reissuing into the same buffer before
        // its content is extracted would let the kernel overwrite w.buf out
        // from under an in-progress parse — a different race than the one
        // below — so the reissue must still happen regardless of whether
        // staging succeeded. On a throw, fall back to a coarse resync
        // covering every key in this directory (scalar-only, cannot itself
        // throw) instead of the lost per-file notice — the "preserve first,
        // still reissue" discipline this file's PR-B2 plan documents for
        // rearm (#2012/#3840 gap-1 fix). A throw landing BEFORE this call is
        // reached at all (e.g. completion_hook_'s own test seam, which fires
        // as process_completion_locked's very first statement) is a broader
        // case this local catch cannot help with — see unwind_pass_locked's
        // own consumed-completion recovery, which covers it; this catch only
        // closes the narrower, more common window where staging itself is
        // what throws, so that common case stays cheap (no full-pass
        // unwind).
        try {
            stage_fire_locked(w, bytes, work);
        } catch (...) {
            w.needs_resync = true;
            w.resync_epoch = ++resync_epoch_;
        }
        if (real_rearm_fail_hook_ && real_rearm_fail_hook_(w.dir)) {
            // Test seam: model a synchronous ReadDirectoryChangesW reissue failure without
            // making the real OS call — see FileMechanismTestControls::real_rearm_fail_hook's
            // doc comment. Leaves exactly the state the real call's failure branch below would.
            w.io_pending = false;
        } else {
            w.io_pending = ::ReadDirectoryChangesW(w.handle.get(), w.buf, sizeof(w.buf), FALSE,
                                                   kFilter, nullptr, &w.ov, nullptr) != 0;
        }
        if (!w.io_pending) {
            w.handle.reset();
            // Loss of target coverage: the reissue itself failed — cover the
            // gap the same way the !ok branch above does (#2012/#3840 gap-2
            // trigger: loss of target coverage).
            w.needs_resync = true;
            w.resync_epoch = ++resync_epoch_;
            // Genuine coverage loss, unconditional — see the !ok branch's
            // identical mark, above.
            mark_coverage_locked(w, SparkCoverage::None);
            try {
                stage_probe_locked(w, work);
            } catch (...) {
                // See the !ok branch's identical catch, above — w.handle is
                // already reset by this point, so a bare propagating throw
                // would be unrecoverable via unwind_pass_locked's
                // consumed-completion guard.
                defer_backend_retry_locked(w, "coverage-loss probe staging failed", 0);
            }
        }
    }

    /// One pass' worth of sweep work under mu_: poll outstanding probes,
    /// promote due Deferred retries, check health grace, re-stage due resync
    /// debt. Runs after EVERY run() loop iteration, regardless of what woke
    /// it (a packet, a control wake, or a scheduled timeout) — plain
    /// full-map iteration, no bounded cursor/time-budget rotation (File's
    /// typical directory count is far below Registry's typical key count; a
    /// future scale concern, not addressed by this PR — see this file's
    /// final status notes).
    void sweep_probes_locked(FilePassWork& work, Clock::time_point now) {
        // Finish any ancestor invalidation unwind_pass_locked's noexcept
        // recovery path could only MARK, not perform (DirWatch::
        // dead_pending_invalidate's doc comment; #2012/#3840 review finding
        // 2) — invalidate_ancestor_locked allocates (its dependents vector),
        // which is why the noexcept unwind path can only stamp the marker.
        // This runs from the normal (non-noexcept) pass, where allocation is
        // fine; a throw here just means this entry retries on the NEXT
        // sweep pass (the marker is only cleared by invalidate_ancestor_
        // locked's own successful erase of the entry, so nothing is lost).
        // Ahead of the dirs_ loop below: an invalidated ancestor's
        // dependents may themselves need a fresh probe reserved this same
        // pass.
        for (auto it = ancestors_.begin(); it != ancestors_.end();) {
            if (it->second && it->second->dead_pending_invalidate) {
                DirWatch& anc = *it->second;
                ++it; // advance past this entry FIRST — invalidate_ancestor_locked may erase it,
                     // and unordered_map only invalidates iterators to the ERASED element
                invalidate_ancestor_locked(anc);
            } else {
                ++it;
            }
        }
        for (auto& [dirkey, slot] : dirs_) {
            if (!slot)
                continue;
            DirWatch& w = *slot;
            // Unconditional health-edge reconciliation on every visit
            // (#2012/#3840 review finding 5), matching spark_registry.cpp's
            // own per-watch pattern — closes the gap where a fault-staging
            // throw upstream (grace_check_locked/fail_backend_locked's own
            // check_health_edge_locked call) could otherwise leave a hung
            // probe permanently reported healthy (the dangerous direction),
            // or a recovery-edge unwind leave a healthy watch permanently
            // reported faulted. No-ops when desired already equals
            // reported — see check_health_edge_locked's own guard.
            check_health_edge_locked(w, work);
            // Drain the coverage marker BEFORE the switch: if the switch
            // below commits Notification in this SAME visit (the Pending
            // case's resolve_probe_locked -> commit_probe_locked path),
            // draining after would overwrite the just-staged None and it would
            // never be reported. The commit re-marks `due`, and
            // wait_timeout_locked's own `due -> now` clause lands the
            // Notification on the very next pass.
            stage_established_locked(w, work);
            switch (w.probe) {
            case ProbeState::Pending:
                if (w.call) {
                    if (auto r = w.call->try_take()) {
                        w.call.reset();
                        resolve_probe_locked(w, std::move(*r), work);
                    } else {
                        grace_check_locked(w, now, work);
                    }
                }
                break;
            case ProbeState::Deferred:
                if (now >= w.next_retry_at) {
                    stage_probe_locked(w, work);
                } else {
                    grace_check_locked(w, now, work);
                }
                break;
            case ProbeState::Idle:
                if (w.confirmation_due) {
                    // Shelter confirmation (discover/attach race): an
                    // intermediate directory may have appeared between the
                    // walk that found this shelter and the shelter's own
                    // establishment. This IS the one confirmation attempt
                    // owed; a later Ancestor-mode commit
                    // (attach_ancestor_locked) re-arms it only if the
                    // shelter itself changes, so a STABLE relationship
                    // confirms once and stops (never a permanent poll
                    // loop). A commit landing on THIS same watch earlier in
                    // this very pass (the Pending case, above) cannot also
                    // reach this branch in the same switch dispatch —
                    // wait_timeout_locked() schedules a prompt next wake
                    // for exactly that case. Cleared only AFTER a
                    // successful stage (#2012/#3840 review finding 10): the
                    // old code cleared it FIRST, so a throw during staging
                    // lost the owed confirmation with no future trigger —
                    // now a failed attempt leaves it set, and this same
                    // Idle branch retries it on the very next sweep pass.
                    //
                    // Handled BEFORE the resync check below (round-3 table
                    // opine): finding 1's redesign can hand a freshly
                    // shelterless dependent BOTH needs_resync and
                    // confirmation_due in the same scalar pass. Firing the
                    // resync notice first would report the gap covered
                    // before this watch has actually re-established
                    // anything — the same "resync retired before coverage
                    // resumed" hole the original immediate-reservation
                    // design avoided by making the watch Pending in the
                    // SAME step it recorded the debt. Staging the probe
                    // first (and re-checking w.probe below) restores that
                    // ordering without reintroducing a throwing call inside
                    // invalidate_ancestor_locked itself.
                    if (stage_probe_locked(w, work))
                        w.confirmation_due = false;
                }
                if (w.probe == ProbeState::Idle && w.needs_resync && now >= w.resync_retry_at) {
                    stage_resync_emit_locked(w, work);
                    resync_retries_.fetch_add(1, std::memory_order_relaxed);
                }
                break;
            }
        }
    }

    /// Earliest deadline across every outstanding obligation, as a GQCS
    /// timeout in milliseconds (INFINITE if nothing is scheduled — block
    /// purely on real completions/control wakes).
    [[nodiscard]] DWORD wait_timeout_locked(Clock::time_point now) const {
        auto wake = now + std::chrono::hours(1);
        bool any = false;
        const auto cadence = sweep_cadence();
        const auto grace = health_grace();
        for (const auto& [dirkey, slot] : dirs_) {
            if (!slot)
                continue;
            const DirWatch& w = *slot;
            // A stranded health-edge mismatch (#2012/#3840 review finding 5's
            // own wake half, round-3 table opine): sweep_probes_locked's
            // unconditional check_health_edge_locked call can only fire if
            // something actually wakes the loop to run it. An Idle watch
            // whose desired/reported health disagree (e.g. a health-notice
            // allocation that threw right after a recovery commit) has no
            // other outstanding obligation to schedule that wake — without
            // this, `any` could stay false and the loop block INFINITE with
            // the mismatch never reconciled.
            if (w.health_desired_faulted != w.health_reported_faulted) {
                wake = std::min(wake, now);
                any = true;
            }
            // A marked-but-not-yet-dispatched coverage report — same
            // stranded-wake reasoning as the health-edge
            // mismatch clause above: a watch already Idle with nothing else
            // outstanding would otherwise leave this report parked for up to
            // an hour.
            if (w.coverage_report_due) {
                wake = std::min(wake, now);
                any = true;
            }
            switch (w.probe) {
            case ProbeState::Pending:
                wake = std::min(wake, now + cadence);
                any = true;
                break;
            case ProbeState::Deferred:
                wake = std::min(wake, w.next_retry_at);
                any = true;
                break;
            case ProbeState::Idle:
                if (w.needs_resync) {
                    wake = std::min(wake, w.resync_retry_at);
                    any = true;
                }
                if (w.confirmation_due) {
                    // Due immediately - sweep_probes_locked's own Idle branch
                    // stages the confirmation probe on the very next pass
                    // (never this one: a commit that just set this flag ran
                    // from the Pending case earlier in the SAME switch
                    // dispatch, which cannot also reach Idle this pass).
                    wake = std::min(wake, now);
                    any = true;
                }
                continue; // no grace check for a fully Idle watch
            }
            if (!w.grace_counted) {
                wake = std::min(wake, w.accepted_at + grace);
                any = true;
            }
        }
        // A dead-marked ancestor (#2012/#3840 review finding 2) needs a
        // prompt sweep too — sweep_probes_locked's own ancestor loop is what
        // actually invalidates it; without this, the marker could sit unseen
        // for up to an hour (or forever, if dirs_ is empty and nothing else
        // ever wakes the loop).
        for (const auto& [akey, aslot] : ancestors_) {
            if (aslot && aslot->dead_pending_invalidate) {
                wake = std::min(wake, now);
                any = true;
            }
        }
        // Pass-failure backoff (#4658): an open failure episode always has a
        // retry scheduled, and the wake IS that retry, so `any` is set: an
        // otherwise idle worker still retries and `inert` can clear with no
        // external wake. The retry is scheduled for the backoff deadline, even
        // when every other obligation is later (a Deferred watch's 30 s backend
        // retry, say), or immediately when that deadline has already passed: the
        // deadline is stamped in note_pass_outcome_locked(), before the failed
        // pass's off-lock tail (the log line, FilePassWork destruction), which
        // can outlast a 50 ms backoff, and run() samples the clock twice (its
        // absorb check, then here). The retry cannot busy-loop: run()'s absorb
        // check only holds a pass back while the deadline is still in the future,
        // every failed pass stamps a fresh future deadline and every successful
        // pass ends the episode. The only polling left is under 1 ms per retry,
        // from the millisecond truncation of the timeout (a wake that lands just
        // before the deadline is absorbed and re-waits). Due-now producers above
        // (health edge, coverage marker, confirmation, dead ancestor, a past
        // Deferred/resync/grace deadline) are therefore deferred to the deadline,
        // and obligations later than it are recomputed by the first wait after
        // the retry pass. One assignment on the FINAL value, never per clause.
        if (pass_failures_ != 0) {
            wake = std::max(pass_backoff_until_, now);
            any = true;
        }
        if (!any)
            return INFINITE;
        const auto delta = wake - now;
        if (delta <= Clock::duration::zero())
            return 0;
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(delta).count();
        constexpr auto kMax = static_cast<std::int64_t>((std::numeric_limits<DWORD>::max)() - 1);
        return ms > kMax ? (std::numeric_limits<DWORD>::max)() - 1 : static_cast<DWORD>(ms);
    }

    /// Resolve every staged probe launch, under mu_. Shared by the
    /// normal-pass path (publish_pass_locked, where run_off_lock() ran its
    /// launch loop to completion so every entry's `pl.job` is already reset)
    /// and the threw-mid-pass recovery path (unwind_pass_locked, where the
    /// launch loop may have been aborted partway through). noexcept: every
    /// operation here is scalar/atomic or a noexcept optional move, and
    /// `work.stale_calls`' capacity is guaranteed sufficient by the per-pass
    /// top-of-loop reserve() in run() — see its own comment.
    void reconcile_probe_launches_locked(FilePassWork& work) noexcept {
        for (auto& pl : work.probe_launches) {
            if (pl.job) {
                // Never reached run_off_lock's launch call for this entry.
                auto it = dirs_.find(pl.dirkey);
                if (it != dirs_.end() && it->second->probe == ProbeState::Pending &&
                    it->second->probe_gen == pl.gen && !it->second->call)
                    defer_admission_locked(*it->second, DetachedLaunch::LaunchFailed);
                continue;
            }
            auto it = dirs_.find(pl.dirkey);
            DirWatch* w = it != dirs_.end() ? it->second.get() : nullptr;
            const bool live =
                w && w->probe == ProbeState::Pending && w->probe_gen == pl.gen && !w->call;
            if (!live) {
                if (pl.call)
                    work.stale_calls.push_back(std::move(*pl.call));
                probe_discarded_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (pl.status == DetachedLaunch::Launched) {
                probe_launched_.fetch_add(1, std::memory_order_relaxed);
                w->call = std::move(pl.call);
            } else {
                defer_admission_locked(*w, pl.status);
            }
        }
        work.probe_launches.clear();
    }

    /// Off-lock half of a pass: launches, then dispatch in recorded order.
    void run_off_lock(FilePassWork& work) {
        const bool had_probe_launches = !work.probe_launches.empty();
        for (auto& pl : work.probe_launches) {
            auto lr = probe_lane_.launch(std::move(*pl.job));
            pl.job.reset();
            pl.status = lr.status;
            pl.call = std::move(lr.call);
        }
        if (had_probe_launches && test_emit_bookkeeping_hook_ && *test_emit_bookkeeping_hook_)
            (*test_emit_bookkeeping_hook_)(); // test seam (mirrors PR #4225's fix): models an
                                              // allocation failure landing right after a probe in
                                              // this same pass already launched

        // Dispatch establishment reports before this pass's notices (rung 9c
        // PR-6 item 1; same order as spark_service.cpp and
        // spark_registry.cpp). What that order guarantees: within ONE dispatch
        // pass, `work.established` is delivered before that pass's own
        // notices. It does NOT cover a commit's own Notification: the commit
        // stages its notice in this visit but re-marks coverage after the
        // visit's drain, so the Notification is staged one pass AFTER that
        // notice. established_ is read by
        // reference, no copy, no mu_ - the write happens-before this thread
        // exists (set_established_sink(), pre-seal, under mu_) and the only
        // later write is stop()'s null-out, after this thread has been
        // joined. A throw on one report is counted (established_failed_; the
        // first one is also logged) and the report is dropped, NOT re-staged:
        // the engine's cache keeps the last delivered value until the next
        // transition of that key, and a persistent throw would otherwise spin
        // the worker. This DIVERGES
        // from spark_service.cpp by design: Service has no per-call catch, so
        // a throw there reaches its run() catch, which invalidates every key
        // to None; here the worker never exits on an exception, so no such
        // invalidation exists. (A throw elsewhere in the pass is different:
        // unwind_pass_locked re-marks every staged report.) No key_gen/
        // staleness re-check is needed here (unlike Notice's
        // notice_still_current): the staged incarnation IS the identity, and
        // SparkEngine::report_established drops any report whose incarnation
        // no longer names the key's current watch.
        if (established_) {
            for (const auto& e : work.established) {
                try {
                    established_(e.key, e.incarnation, e.at, e.coverage);
                } catch (...) {
                    // Log only the FIRST drop; the rest are counted. The log
                    // itself must never throw out of this handler.
                    if (established_failed_.fetch_add(1, std::memory_order_relaxed) == 0) {
                        try {
                            spdlog::warn("spark_file: an establishment report for '{}' was "
                                         "dropped (sink threw); further drops are not logged",
                                         ::yuzu::log_key_token(e.key));
                        } catch (...) {
                        }
                    }
                }
            }
        }

        for (auto& n : work.notices) {
            try {
                // #2012/#3840 review finding 8: revalidate EVERY notice
                // (Emit included — see notice_still_current's own doc
                // comment for why the "Emit has no idempotent state to
                // corrupt" argument no longer holds) before dispatch. A
                // dropped notice here — Emit or Fault — is marked Stale, not
                // Unattempted (#2012/#3840 review finding 3's Notice::
                // Outcome, round-3 opine): the registration it was staged
                // for no longer exists, so neither "restore this epoch's
                // debt" nor "clear it" means anything for whatever replaced
                // it, and publish_pass_locked/unwind_pass_locked must be
                // able to tell this apart from a notice that never got a
                // chance to try at all.
                if (!notice_still_current(n)) {
                    n.outcome = FilePassWork::Notice::Outcome::Stale;
                    continue;
                }
                if (n.kind == FilePassWork::Notice::Kind::Fault) {
                    if (fault_)
                        fault_(n.key, n.faulted, n.reason);
                } else if (emit_) {
                    emit_(n.key, SparkData{std::monostate{}});
                }
                n.outcome = FilePassWork::Notice::Outcome::Submitted;
            } catch (...) {
                n.outcome = FilePassWork::Notice::Outcome::Failed;
                if (n.kind == FilePassWork::Notice::Kind::Emit)
                    emit_failed_.fetch_add(1, std::memory_order_relaxed);
                else
                    fault_failed_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    /// A staged notice is dispatched only if (1) its key is STILL registered
    /// to the very watch it was recorded for, at the SAME registration
    /// generation (#2012/#3840 review finding 8 — key_gen_'s own doc
    /// comment: directory identity alone cannot distinguish a key that was
    /// unwatch()'d then watch()'d again, sharing that directory with a
    /// still-live sibling key, from its own earlier registration), and (2)
    /// for a Fault, the watch still wants that health state reported (UP-1:
    /// a re-arm between staging and dispatch must not inherit the old
    /// edge). A short mu_ acquisition off the caller's own lock; never
    /// blocks. Applied to Emit notices too as of finding 8 — the previous
    /// "Emit has no idempotent state to corrupt" argument (matching
    /// spark_registry.cpp's fault_action_still_current precedent, which has
    /// no directory-sharing/key-reuse hazard to begin with) is disproven by
    /// the key-reuse case: a stale Emit landing on a replacement
    /// registration misattributes a change under the OLD target to whatever
    /// the key is now watching. The extra mu_ acquisition per Emit is the
    /// accepted cost — see this PR's own review for the trade.
    [[nodiscard]] bool notice_still_current(const FilePassWork::Notice& n) {
        std::lock_guard lk(mu_);
        auto ki = key_index_.find(n.key);
        if (ki == key_index_.end() || ki->second.gen != n.key_gen)
            return false;
        auto it = dirs_.find(n.dirkey);
        if (it == dirs_.end() || it->second.get() != n.watch)
            return false;
        if (n.kind != FilePassWork::Notice::Kind::Fault)
            return true;
        return it->second->health_reported_faulted == n.faulted &&
              it->second->health_desired_faulted == n.faulted;
    }

    /// Relock half: publish launched probes with re-validation; reconcile
    /// every notice's dispatch outcome (#2012/#3840 review finding 3,
    /// structural change: replaces three copied-key outcome vectors with an
    /// allocation-free per-Notice Outcome enum, iterated here in two passes
    /// over the already-stable work.notices — Submitted first, then Failed —
    /// rather than dispatch-recorded order. This preserves the pre-existing
    /// "a failure always wins over a sibling success in the same resync
    /// batch" guarantee the original two-separate-loops code produced as a
    /// side effect of loop order; a single dispatch-order pass would let a
    /// LATER Submitted sibling reset resync_attempts back to 0 after an
    /// EARLIER Failed sibling had already re-armed it. Only reached when
    /// run_off_lock() completed normally — every notice already has a
    /// determinate Submitted/Failed/Stale outcome, never Unattempted (an
    /// exception escaping run_off_lock itself routes to unwind_pass_locked
    /// instead, which handles Unattempted notices on its own).
    void publish_pass_locked(FilePassWork& work) {
        reconcile_probe_launches_locked(work);
        reconcile_notice_outcomes_locked(work);
    }

    /// Reconcile every notice with a DETERMINATE dispatch outcome
    /// (Submitted or Failed) against current watch state — Submitted pass
    /// first, then Failed pass, preserving the pre-existing "a failure
    /// always wins over a sibling success in the same resync batch"
    /// guarantee the original two-separate-vectors code produced as a side
    /// effect of loop order (a single dispatch-order pass would let a LATER
    /// Submitted sibling reset resync_attempts back to 0 after an EARLIER
    /// Failed sibling had already re-armed it). Notices still Outcome::
    /// Unattempted (never dispatched at all) or Outcome::Stale (dropped by
    /// notice_still_current) are untouched here — see
    /// restore_unattempted_notices_locked for the former. Shared by
    /// publish_pass_locked (the normal path, where every notice is already
    /// determinate) and unwind_pass_locked (#2012/#3840 review, round-3
    /// table opine: one unconditional reconciliation function on both
    /// paths, matching every other recovery surface in this file).
    /// noexcept: every op is scalar/lookup/clock-read, and the one
    /// known-throwing diagnostic (spdlog::warn/fs::path::string(),
    /// #2012/#3840 review finding 6) is locally caught.
    void reconcile_notice_outcomes_locked(FilePassWork& work) noexcept {
        using Outcome = FilePassWork::Notice::Outcome;
        for (auto& n : work.notices) {
            if (n.kind != FilePassWork::Notice::Kind::Emit || !n.is_resync ||
                n.outcome != Outcome::Submitted)
                continue;
            auto it = dirs_.find(n.dirkey);
            if (it != dirs_.end() && it->second.get() == n.watch &&
                it->second->resync_epoch == n.resync_epoch) {
                it->second->resync_attempts = 0;
                it->second->resync_dispatch_in_flight = false; // this epoch's flight is over
                                                                // (#2012/#3840 review round-3,
                                                                // CDEX-P1-3)
            }
        }
        for (auto& n : work.notices) {
            if (n.kind != FilePassWork::Notice::Kind::Emit) {
                // A Failed Fault (#2012/#3840 review round-3, K-R3-2): staging already
                // optimistically stamped health_reported_faulted before dispatch; force it back
                // to a mismatch on a submit failure, same as an Unattempted Fault already does
                // in restore_unattempted_notices_locked, so the next sweep's unconditional
                // health-edge check re-attempts it rather than silently accepting the drop.
                // Defensive depth only — SparkEngine::report_fault() swallows every failure mode
                // before it reaches this callback (round-2 finding-7 correction), so this path
                // is not known to be reachable in production.
                if (n.kind == FilePassWork::Notice::Kind::Fault && n.outcome == Outcome::Failed) {
                    auto it = dirs_.find(n.dirkey);
                    if (it != dirs_.end() && it->second.get() == n.watch)
                        it->second->health_reported_faulted = !it->second->health_desired_faulted;
                }
                continue;
            }
            if (n.outcome != Outcome::Failed)
                continue;
            auto it = dirs_.find(n.dirkey);
            if (it == dirs_.end() || it->second.get() != n.watch)
                continue;
            DirWatch& w = *it->second;
            if (n.is_resync) {
                if (w.resync_epoch != n.resync_epoch)
                    continue;
                w.needs_resync = true;
                w.resync_dispatch_in_flight = false; // this epoch's flight is over, restored to
                                                      // a fresh (still-outstanding) obligation
                ++w.resync_attempts;
                w.resync_retry_at = Clock::now() +
                                    doubled(admission_seed(), w.resync_attempts,
                                            kFileAdmissionBackoffCap);
                try {
                    spdlog::warn("spark_file: synthetic fire for '{}' threw on submit (attempt "
                                 "{}) - retrying",
                                 ::yuzu::log_key_token(fs::path(w.dir).string()), w.resync_attempts);
                } catch (...) {
                    // Diagnostic only — every state write above already
                    // landed; losing this log line must never abort the
                    // remaining notices' reconciliation in this pass
                    // (#2012/#3840 review finding 6).
                }
            } else {
                // Failed ordinary-emit submission: the change this notice carried is gone
                // (SparkEmitFn returns void — no redelivery) — cover it with a fresh resync
                // obligation, no epoch to match (an ordinary notice never carried one).
                w.needs_resync = true;
                w.resync_epoch = ++resync_epoch_;
            }
        }
    }

    /// Restore every notice this pass never got a chance to attempt
    /// (Outcome::Unattempted — either the whole pass aborted before
    /// run_off_lock(), or run_off_lock() itself threw before reaching this
    /// notice) as if it had never been staged: an is_resync Emit notice's
    /// debt is put back (matching epoch only); an ORDINARY Emit notice gets
    /// a fresh resync obligation (#2012/#3840 review round-3 closure pass —
    /// this notice carried a real, now-lost SparkEmitFn call with no
    /// redelivery path, the exact same loss reconcile_notice_outcomes_locked
    /// already covers for a Failed ordinary Emit; leaving Unattempted
    /// uncovered here was the gap the original round-3 test for this exact
    /// scenario failed to actually exercise — see that test's own history).
    /// A Fault notice's health_reported_faulted is forced back to a
    /// mismatch so the next sweep's unconditional health-edge check
    /// (finding 5) re-attempts it. Stale and determinate (Submitted/Failed)
    /// outcomes are untouched — see reconcile_notice_outcomes_locked for
    /// those. noexcept, called only from unwind_pass_locked.
    void restore_unattempted_notices_locked(FilePassWork& work) noexcept {
        for (const auto& n : work.notices) {
            if (n.outcome != FilePassWork::Notice::Outcome::Unattempted)
                continue;
            auto it = dirs_.find(n.dirkey);
            if (it == dirs_.end() || it->second.get() != n.watch)
                continue;
            DirWatch& w = *it->second;
            if (n.kind == FilePassWork::Notice::Kind::Emit) {
                if (n.is_resync) {
                    if (w.resync_epoch == n.resync_epoch) {
                        w.needs_resync = true;
                        w.resync_dispatch_in_flight = false; // this epoch's flight never even
                                                              // started (#2012/#3840 review round-3)
                    }
                } else {
                    w.needs_resync = true;
                    w.resync_epoch = ++resync_epoch_;
                }
            } else {
                w.health_reported_faulted = !w.health_desired_faulted; // re-stage next pass
            }
        }
    }

    /// Test seam (#4658): top of EVERY worker pass, under mu_, after the pass
    /// reserved its FilePassWork containers and before
    /// process_completion_locked()/sweep_probes_locked(). In the completion
    /// branch the dequeue bookkeeping (io_pending cleared, work.consumed
    /// stamped) precedes it: that is what unwind_pass_locked() recovers when
    /// this throws. A throw here models an allocation failure at that point.
    /// The hook runs under mu_, so it must not call any member that takes mu_
    /// (watch(), watch_incarnation(), unwatch(), stop(), apply_test_controls(),
    /// debug_counters(): self-deadlock). One helper, two call sites (both run()
    /// branches) so they cannot drift.
    void run_pass_hook_locked() {
        if (pass_fail_hook_)
            pass_fail_hook_();
    }

    /// What the caller logs once mu_ is released (never log under mu_ from the
    /// worker: the log I/O would extend the per-type-lock hold watch() sees).
    struct PassOutcome {
        unsigned failures{0};
        std::int64_t delay_ms{0};
        bool flipped_inert{false};
        bool recovered{false};
    };

    /// Per-pass outcome bookkeeping (#4658), under mu_, noexcept. Mirrors
    /// spark_registry.cpp's sweeper_main() success/failure arms (N = 3, backoff
    /// doubling from sweep_cadence capped at 30 s, the 1/2/4/8 log gate, cleared
    /// by the next success). Differences from it:
    ///  - the retry deadline is the wake wait_timeout_locked() returns (this
    ///    mechanism's only timer), not a separate stop-only wait, because run()
    ///    is also the IOCP consumer;
    ///  - the deadline is stamped HERE, before the pass's off-lock tail (the
    ///    log line, FilePassWork destruction), where Registry stamps after its
    ///    tail; wait_timeout_locked() therefore treats a deadline that has
    ///    already passed as "retry due now";
    ///  - logging happens off-lock, after this returns;
    ///  - a real completion's pass counts toward the three like any other pass;
    ///  - clearing inert_ has no `if (core_)` guard: run() is the only writer
    ///    while it executes (see the pass-failure member comment).
    [[nodiscard]] PassOutcome note_pass_outcome_locked(bool ok) noexcept {
        PassOutcome out;
        if (ok) {
            if (pass_failures_ != 0) {
                out.recovered = true;
                out.failures = pass_failures_;
                pass_failures_ = 0;
                // MUST reset the deadline: a stale one would pin the next wake and
                // absorb the next nudge.
                pass_backoff_until_ = {};
                pass_backoff_ = {};
                inert_.store(false, std::memory_order_release);
            }
            return out;
        }
        pass_failed_.fetch_add(1, std::memory_order_relaxed);
        if (pass_failures_ != (std::numeric_limits<unsigned>::max)())
            ++pass_failures_;
        pass_backoff_ = doubled(sweep_cadence(), pass_failures_, kFileAdmissionBackoffCap);
        pass_backoff_until_ = Clock::now() + pass_backoff_;
        out.failures = pass_failures_;
        out.delay_ms = pass_backoff_.count();
        if (pass_failures_ >= kFileWorkerInertAfterFailures &&
            !inert_.load(std::memory_order_acquire)) {
            inert_.store(true, std::memory_order_release);
            out.flipped_inert = true;
        }
        return out;
    }

    /// Off-lock, noexcept: run() has NO outer catch, so a throw from a log call
    /// here would be worker death, the very thing the pass catch exists to
    /// prevent. Same wrapping rule as every other diagnostic in a recovery path
    /// in this file.
    static void log_pass_outcome(const PassOutcome& o) noexcept {
        try {
            if (o.recovered) {
                spdlog::info("spark_file: worker pass recovered after {} failure(s)", o.failures);
                return;
            }
            if (o.failures != 0 && (o.failures & (o.failures - 1)) == 0) // 1, 2, 4, 8, ...
                spdlog::error(
                    "spark_file: worker pass failed (consecutive #{}) - retrying in {} ms",
                    o.failures, o.delay_ms);
            if (o.flipped_inert)
                spdlog::error("spark_file: worker failing persistently - file sparks reported "
                              "inert until a pass succeeds");
        } catch (...) {
        }
    }

    /// Undo a pass that threw, under mu_, noexcept: retirements/launches this
    /// pass staged are reconciled the same way publish_pass_locked() would
    /// have (reconcile_probe_launches_locked is unconditional on both paths —
    /// this is the exact PR #4225 defect class spark_registry.cpp's own
    /// review found and fixed: skipping an already-launched entry here on the
    /// assumption the success path will handle it permanently strands that
    /// watch, since nothing else ever relaunches from Pending). If nothing
    /// was dispatched at all (the pass never reached run_off_lock), staged
    /// notices are unwound too so the next pass re-attempts them, and the
    /// completion run() dequeued for this pass (if any) is recovered from
    /// FilePassWork's own preallocated scalars — see their doc comment
    /// (#2012/#3840 gap-1 fix, the "consumed completion" recovery surface
    /// this file's header comment/the PR-B2 plan's item 8 call out as a
    /// File-specific extra Registry didn't need).
    void unwind_pass_locked(FilePassWork& work, bool dispatched) noexcept {
        reconcile_probe_launches_locked(work);
        // Notice-outcome reconciliation runs UNCONDITIONALLY, keyed off each
        // notice's own Outcome rather than the pass-wide `dispatched` flag
        // (#2012/#3840 review, round-3 table opine): `dispatched == true`
        // only means mu_ was released and run_off_lock() was ENTERED, not
        // that every notice inside it was reached — the per-pass test hook
        // (or, in principle, the probe-launch loop) can throw between
        // entering run_off_lock() and the notices loop, leaving every
        // notice still Outcome::Unattempted even though dispatched is
        // already true. reconcile_notice_outcomes_locked handles whatever
        // DID reach a determinate Submitted/Failed outcome (shared with
        // publish_pass_locked — one unconditional reconciliation function
        // on both paths, matching every other recovery surface in this
        // file); restore_unattempted_notices_locked handles whatever never
        // got a chance, exactly as the old `if (!dispatched)` block used to
        // for every notice, since every notice was Unattempted in that case
        // too. Stale notices (a registration that no longer exists) are
        // untouched by both — nothing to reconcile.
        reconcile_notice_outcomes_locked(work);
        restore_unattempted_notices_locked(work);
        work.notices.clear();
        // Re-mark every staged establishment report REGARDLESS of
        // `dispatched` (same reasoning as the notice
        // reconciliation above: `dispatched == true` only means run_off_lock()
        // was ENTERED, not that its established-dispatch loop was reached
        // before the throw that brought us here). Do NOT restore the staged
        // value: the next pass re-stages the watch's CURRENT coverage, which
        // is at least as fresh as what was lost here. dirs_.find on a const
        // std::wstring& does not allocate, so this stays safe for the
        // noexcept contract.
        for (const auto& e : work.established) {
            auto it = dirs_.find(e.dirkey);
            if (it != dirs_.end() && it->second)
                it->second->coverage_report_due = true;
        }
        work.established.clear();
        if (!dispatched) {
            // Consumed-completion recovery: `dispatched == false` here means mu_ was NEVER
            // released between run()'s dequeue (which already cleared consumed->io_pending) and
            // this catch — no other thread could have touched dirs_/ancestors_ in between, so a
            // plain pointer-identity re-scan is exact, not merely defensive. Re-validate anyway
            // (never trust a stored raw pointer without it), matching every other reconciliation
            // site in this file. Only acts if the completion's aftermath was never reached at all
            // (handle still set, io_pending still false, not mid-teardown) — idempotent-safe
            // against a throw landing AFTER process_completion_locked already finished its own
            // handling (reissued, or reset the handle and staged its own retry) for this exact
            // watch, since that leaves nothing matching the guard below.
            if (work.consumed) {
                DirWatch* found = nullptr;
                if (work.consumed_is_anc) {
                    for (auto& [k, slot] : ancestors_)
                        if (slot.get() == work.consumed) {
                            found = slot.get();
                            break;
                        }
                } else {
                    for (auto& [k, slot] : dirs_)
                        if (slot.get() == work.consumed) {
                            found = slot.get();
                            break;
                        }
                }
                if (found && !found->removing && found->handle && !found->io_pending) {
                    DirWatch& w = *found;
                    if (!work.consumed_ok) {
                        // The completion itself was a FAILURE (ok == false) — the read the OS
                        // just reported broken must never be reissued (matches
                        // process_completion_locked's own !ok branch, which resets the handle
                        // before doing anything else). Real dir: cover the gap with a resync
                        // fire, same as that branch, and fall back to the existing, already-
                        // noexcept-proven admission-deferral bookkeeping (no fresh probe
                        // reservation here — that allocates — the next normal pass relaunches it
                        // from Deferred). Ancestor: defer_admission_locked's Deferred/probe-retry
                        // bookkeeping is meaningless for an ancestor entry (never swept for its
                        // own probe) — stamp the allocation-free dead marker instead
                        // (#2012/#3840 review finding 2) so sweep_probes_locked's own ancestor
                        // loop finishes the (allocating) invalidation on the next normal pass,
                        // reassigning every dependent rather than leaving them permanently
                        // sheltered behind a handle-less, un-invalidated ancestor.
                        w.handle.reset();
                        if (work.consumed_is_anc) {
                            w.dead_pending_invalidate = true;
                        } else {
                            w.needs_resync = true;
                            w.resync_epoch = ++resync_epoch_;
                            defer_admission_locked(w, DetachedLaunch::LaunchFailed);
                        }
                    } else if (work.consumed_is_anc) {
                        // Ancestors carry no keys/resync — best effort is keeping it armed.
                        // route_noop_rearm() is the existing, allocation-free reissue path (a
                        // syscall + two scalar writes). A failure here has no allocation-free
                        // invalidation available (invalidate_ancestor_locked() allocates) —
                        // stamp the dead marker instead (#2012/#3840 review finding 2), same as
                        // the !consumed_ok branch above; route_noop_rearm() itself already reset
                        // the handle on failure, matching every other dead_pending_invalidate
                        // site's precondition.
                        if (!route_noop_rearm(w))
                            w.dead_pending_invalidate = true;
                        else
                            // Successful rearm still means this ancestor
                            // fired (#2012/#3840 review finding 8): every
                            // dependent owes a fresh discovery attempt for
                            // the possible appearance the consumed
                            // completion represented. reresolve_absent_
                            // locked() allocates (a candidates vector +
                            // stage_probe_locked's own job) and cannot run
                            // from this noexcept recovery function directly
                            // — mark_reappearance_locked is its
                            // allocation-free equivalent, deferring the
                            // actual probe to sweep_probes_locked's Idle
                            // branch on the next pass instead of launching
                            // it immediately.
                            mark_reappearance_locked(w.map_key);
                    } else {
                        // Real dir, and the completion itself succeeded: whatever notification it
                        // carried is unrecoverable (never parsed) — cover it with a coarse resync,
                        // scalar-only, matching the local catch in process_completion_locked's
                        // real-dir branch. Try to keep the watch armed by reissuing directly — the
                        // IDENTICAL ReadDirectoryChangesW call process_completion_locked's own
                        // real-dir branch makes, NOT route_noop_rearm() (documented as the
                        // ancestor-only reissue path, and it additionally consults
                        // ancestor_rearm_fail_hook_ — a test seam scoped to ancestor watches that
                        // must not be able to interfere with a real-dir reissue). On failure, fall
                        // back to the existing, already-noexcept-proven admission-deferral
                        // bookkeeping (no fresh probe reservation here — that allocates — the next
                        // normal pass relaunches it from Deferred).
                        w.needs_resync = true;
                        w.resync_epoch = ++resync_epoch_;
                        w.io_pending = ::ReadDirectoryChangesW(w.handle.get(), w.buf, sizeof(w.buf),
                                                               FALSE, kFilter, nullptr, &w.ov,
                                                               nullptr) != 0;
                        if (!w.io_pending) {
                            w.handle.reset();
                            defer_admission_locked(w, DetachedLaunch::LaunchFailed);
                        }
                    }
                }
            }
        }
        // Everything else this pass staged for off-lock disposal
        // (dead_watches/old_handles/dead_results/stale_calls) was already
        // FULLY removed from dirs_/ancestors_ (or never inserted at all)
        // before being staged — see attach_*_locked's/create_ancestor_from_
        // probe_locked's own comments — so there is nothing to "put back"
        // for them; they simply finish disposing, off-lock, when `work` is
        // destroyed by the caller after this function returns.
    }

    void unwatch_locked(const std::string& key, FilePassWork& work) {
        auto ki = key_index_.find(key);
        if (ki == key_index_.end())
            return;
        const std::wstring dirkey = ki->second.dirkey;
        const std::wstring fname = ki->second.fname;
        key_index_.erase(ki);
        auto di = dirs_.find(dirkey);
        if (di == dirs_.end())
            return;
        DirWatch& w = *di->second;
        auto fi = w.keys.find(fname);
        if (fi != w.keys.end()) {
            fi->second.erase(key);
            if (fi->second.empty())
                w.keys.erase(fi);
        }
        if (!w.keys.empty())
            return;
        // No spark cares about this dir any more: cancel any outstanding
        // discovery obligation first (never let a late probe commit into a
        // DirWatch nobody references), then tear it down.
        if (w.call) {
            work.stale_calls.push_back(std::move(*w.call));
            w.call.reset();
            probe_discarded_.fetch_add(1, std::memory_order_relaxed);
        }
        w.probe = ProbeState::Idle; // no further retry is meaningful once retired
        release_ancestor_locked(w);
        if (w.io_pending && w.handle) {
            w.removing = true;
            ::CancelIoEx(w.handle.get(), &w.ov);
            push_retiring(di->second); // may throw — see push_retiring's own contract; on a throw
                                       // di->second stays whole (already removing+cancelled) for
                                       // drop_watch() to reclaim, matching every other call site
            dirs_.erase(di);
        } else {
            work.dead_watches.push_back(std::move(di->second));
            dirs_.erase(di);
        }
    }

    /// If `t0` (a caller's entry time, unused as of PR-B2 — kept only as the
    /// note_if_slow name is gone) ... [removed; slow_op_total is now produced
    /// exclusively by grace_check_locked(), mirroring spark_registry.cpp — no
    /// blocking OS call ever runs under mu_ any more, so the pre-PR-B2
    /// "wall-clock a call held under the lock" meaning no longer applies].

    /// Move a cancelled-but-still-io_pending DirWatch into retiring_, bumping
    /// the gauge and warning once per cap/2 crossing (#1979). UNCHANGED from
    /// the pre-PR-B2 code (#2839's own hardening) — the exact-order contract
    /// this function documents is untouched by this PR.
    void push_retiring(std::unique_ptr<DirWatch>& w) {
        if (retire_fault_hook_for_test_) {
            auto hook = std::move(retire_fault_hook_for_test_);
            retire_fault_hook_for_test_ = nullptr;
            hook();
        }
        retiring_.emplace_back();        // MAY THROW — `w` untouched, caller keeps ownership
        retiring_.back() = std::move(w); // noexcept: unique_ptr move-assign
        const auto prev = retiring_gauge_.fetch_add(1, std::memory_order_relaxed);
        if (prev + 1 == retiring_cap() / 2) {
            try {
                spdlog::warn("spark_file: retiring_ crossed {} of {} pending IOCP teardowns",
                             retiring_cap() / 2, retiring_cap());
            } catch (...) {
            }
        }
    }

    bool is_ancestor_watch(DirWatch* w) const {
        for (const auto& [k, slot] : ancestors_)
            if (slot.get() == w)
                return true;
        return false;
    }

    void drop_watch(DirWatch* w) {
        for (auto it = dirs_.begin(); it != dirs_.end(); ++it)
            if (it->second.get() == w) {
                dirs_.erase(it);
                return;
            }
        for (auto it = ancestors_.begin(); it != ancestors_.end(); ++it)
            if (it->second.get() == w) {
                ancestors_.erase(it);
                return;
            }
        for (auto it = retiring_.begin(); it != retiring_.end(); ++it)
            if (it->get() == w) {
                retiring_.erase(it);
                retiring_gauge_.fetch_sub(1, std::memory_order_relaxed);
                return;
            }
    }

    void run() {
        std::unique_lock lk(mu_);
        while (!stop_.load(std::memory_order_acquire)) {
            const DWORD timeout_ms = wait_timeout_locked(Clock::now());
            lk.unlock();
            DWORD bytes = 0;
            ULONG_PTR ckey = 0;
            LPOVERLAPPED ov = nullptr;
            BOOL gqcs_ok =
                ::GetQueuedCompletionStatus(iocp_.get(), &bytes, &ckey, &ov, timeout_ms);
            lk.lock();

            const bool real_completion = (ov != nullptr);
            if (real_completion) {
                // Consume it BEFORE checking stop_, regardless of whether we
                // are about to stop: a packet dequeued right before stop() is
                // observed must have its DirWatch's io_pending cleared here,
                // or stop()'s own cancel/reap loop would wait for a
                // completion that can never arrive again (the pre-PR-B2
                // file.cpp:750 trap).
                auto* w = reinterpret_cast<DirWatch*>(ckey);
                w->io_pending = false;
                if (notify_fail_hook_ && notify_fail_hook_(w->dir))
                    gqcs_ok = FALSE; // test seam: override the kernel's own result; see
                                     // FileMechanismTestControls::notify_fail_hook's doc comment
                if (stop_.load(std::memory_order_acquire)) {
                    if (w->removing)
                        drop_watch(w);
                    break;
                }
                if (w->removing) {
                    // A cancelled watch's completion drained (#2012/#3840
                    // review, round-3 table opine): free it immediately,
                    // before this pass's own scratch reserve() calls below
                    // get a chance to throw. Without this, a reserve()
                    // failure landing here would leave `w` permanently
                    // orphaned — unwind_pass_locked's consumed-completion
                    // recovery explicitly excludes a `removing` watch (never
                    // reissues a cancelled read), and nothing else will ever
                    // call drop_watch() for it again (no more I/O can
                    // complete once io_pending is false and removing is
                    // true). Matches process_completion_locked's own
                    // (now-redundant for this exact path, still needed for
                    // its other callers) removing check.
                    drop_watch(w);
                    continue;
                }
                FilePassWork work;
                // Consumed-completion recovery scalars (#2012/#3840 gap-1 fix): stamped FIRST,
                // unconditionally, BEFORE this pass's own scratch reserve() calls below — this
                // dequeue can never be redelivered regardless of what happens next, so these
                // three preallocated scalars must already be correct before ANY fallible
                // operation in this pass, not merely before process_completion_locked. See
                // FilePassWork's own doc comment.
                work.consumed = w;
                work.consumed_ok = static_cast<bool>(gqcs_ok);
                work.consumed_is_anc = is_ancestor_watch(w);
                bool dispatched = false;
                bool ok = true;
                try {
                    // Reserves moved inside the try (#2012/#3840 review,
                    // round-3 table opine): they used to run BEFORE this
                    // block, so an escaping bad_alloc was uncaught —
                    // std::terminate, not a contained failed pass. work.
                    // consumed is already valid above regardless of where a
                    // throw lands from here on, so unwind_pass_locked's
                    // consumed-completion recovery still applies correctly
                    // even if the very first reserve() call is what throws.
                    const std::size_t cap = dirs_.size() + ancestors_.size() + 1;
                    work.probe_launches.reserve(cap);
                    work.stale_calls.reserve(cap);
                    work.dead_results.reserve(cap);
                    work.dead_watches.reserve(cap);
                    work.old_handles.reserve(cap);
                    run_pass_hook_locked();
                    process_completion_locked(*w, gqcs_ok, bytes, work);
                    sweep_probes_locked(work, Clock::now());
                    lk.unlock();
                    dispatched = true;
                    run_off_lock(work);
                    lk.lock();
                    publish_pass_locked(work);
                } catch (...) {
                    if (!lk.owns_lock())
                        lk.lock();
                    ok = false;
                    unwind_pass_locked(work, dispatched);
                }
                const PassOutcome po = note_pass_outcome_locked(ok);
                // FilePassWork's own doc comment: "Destroyed only with mu_
                // released" (#2012/#3840 review finding 3) — publish_pass_
                // locked()/unwind_pass_locked() both need mu_ HELD while
                // they run (they touch dirs_/ancestors_), but `work` itself
                // (old_handles/dead_results/stale_calls/dead_watches — every
                // one of which can call CloseHandle/CancelIo on destruction,
                // with no proven Win32 latency bound for a handle to an
                // unresponsive remote share) must not destruct until AFTER
                // mu_ is released, on EITHER path — matches spark_registry.
                // cpp's `dead = std::move(work)` pattern.
                lk.unlock();
                log_pass_outcome(po);
                { FilePassWork dead = std::move(work); }
                lk.lock();
                continue;
            }
            if (stop_.load(std::memory_order_acquire))
                break;
            // Pass-failure backoff (#4658): a control wake (watch()/unwatch()/
            // apply_test_controls() nudge, or a timeout that landed a tick
            // early) while the retry deadline is still in the future is ABSORBED, as
            // spark_registry.cpp's stop-only backoff predicate absorbs
            // nudged_: what the nudge announced is durable state in dirs_/
            // ancestors_ and is served by the retry pass at the deadline. Sits
            // after the stop_ check above, so stop() never waits on a backoff.
            // A real completion (the branch above) is never absorbed: its
            // io_pending bookkeeping was consumed at dequeue.
            if (pass_backoff_until_ > Clock::now())
                continue;
            // Control wake (ckey == kControlKey, posted by watch()/unwatch()/
            // apply_test_controls()/stop() — though stop() already checked
            // above) or a scheduled timeout (WAIT_TIMEOUT) — either way,
            // sweep: something new may be due, or this IS the nudge telling
            // us to look now.
            FilePassWork work;
            bool dispatched = false;
            bool ok = true;
            try {
                // Reserves moved inside the try (#2012/#3840 review,
                // round-3 table opine) — same reasoning as the
                // real_completion branch above; `work.consumed` stays
                // nullptr here regardless (no completion to recover on
                // this branch), so no ordering concern.
                const std::size_t cap = dirs_.size() + 1;
                work.probe_launches.reserve(cap);
                work.stale_calls.reserve(cap);
                work.dead_results.reserve(cap);
                work.dead_watches.reserve(cap);
                work.old_handles.reserve(cap);
                run_pass_hook_locked();
                sweep_probes_locked(work, Clock::now());
                lk.unlock();
                dispatched = true;
                run_off_lock(work);
                lk.lock();
                publish_pass_locked(work);
            } catch (...) {
                if (!lk.owns_lock())
                    lk.lock();
                ok = false;
                unwind_pass_locked(work, dispatched);
            }
            const PassOutcome po = note_pass_outcome_locked(ok);
            // See the identical comment on the real_completion branch above
            // (#2012/#3840 review finding 3).
            lk.unlock();
            log_pass_outcome(po);
            { FilePassWork dead = std::move(work); }
            lk.lock();
        }
    }

    mutable std::mutex mu_;
    detail::EventHandle iocp_; ///< IOCP handle (closed via CloseHandle)
    SparkEmitFn emit_;
    SparkFaultFn fault_;
    /// Establishment-signal sink (rung 9c PR-6 item 1) - written once by
    /// set_established_sink() before start(), read only by run_off_lock() on
    /// the worker thread with mu_ released (same happens-before argument as
    /// emit_/fault_ above: the write happens-before the worker thread spawns
    /// in start(), and stop() nulls it only after the worker has been
    /// joined).
    SparkEstablishedFn established_;
    /// One-way latch (rung 9c PR-6 item 1): set as the FIRST statement of
    /// start(), never cleared by stop() - SparkEngine itself is single-shot,
    /// so no production caller ever needs to re-arm the sink after a stop().
    bool sink_sealed_{false};
    std::thread worker_;
    std::atomic<bool> stop_{true};
    std::unordered_map<std::wstring, std::unique_ptr<DirWatch>> dirs_;      ///< real watched dirs
    std::unordered_map<std::wstring, std::unique_ptr<DirWatch>> ancestors_; ///< recreate-recovery
    std::vector<std::unique_ptr<DirWatch>> retiring_; ///< watches awaiting a drained completion
    std::unordered_map<std::string, KeyBinding> key_index_; ///< key→(dir,fname,gen,incarnation)
    /// Mechanism-global: bumped every time a key is (re-)registered via
    /// watch() (#2012/#3840 review finding 8) — a Notice staged for one
    /// registration of a key must not land on a REPLACEMENT registration of
    /// the SAME key string (unwatch(K); watch(K) racing run()'s off-lock
    /// dispatch window, for a directory kept alive by a still-live sibling
    /// key) — directory identity alone cannot distinguish the two.
    std::uint64_t key_gen_{0};
    /// Mechanism-global (never per-watch, so a stale pointer cannot alias a
    /// fresh watch): bumped at every probe reservation.
    std::uint64_t gen_{0};
    /// Mechanism-global: bumped whenever an observation gap is recorded.
    std::uint64_t resync_epoch_{0};

    SparkDetachedLane probe_lane_;

    /// Pass-failure episode (#4658). Written only by run() (the sole worker),
    /// under mu_; read under mu_ by wait_timeout_locked() and debug_counters().
    /// pass_backoff_until_ is the retry deadline of the open episode
    /// (pass_failures_ != 0; epoch = no episode): while it is in the future no
    /// timer-driven pass runs, and wait_timeout_locked() returns it as the wake
    /// (or "now" once it has passed). Not atomic: every reader holds mu_. inert_
    /// (below) gains a runtime writer from this state: while run() executes it is
    /// the ONLY writer (start()'s two `true` stores sit on paths where the worker
    /// never runs, its `false` store precedes the spawn), so no start-time/runtime
    /// distinction is needed and a recovery can never clear a start-time inert. A
    /// runtime-flipped inert_ survives stop() until the next start() clears it;
    /// SparkEngine is single-shot, so nothing reads it.
    unsigned pass_failures_{0};                 ///< consecutive failed passes; 0 = last pass ok
    Clock::time_point pass_backoff_until_{};    ///< epoch = no active backoff
    std::chrono::milliseconds pass_backoff_{0}; ///< last computed delay; 0 outside an episode
    std::atomic<std::uint64_t> pass_failed_{0}; ///< all-time failed passes (mirrors Registry's
                                                ///< sweep_pass_failed_)

    std::atomic<bool> inert_{false};
    std::atomic<std::uint64_t> retiring_gauge_{0};
    std::atomic<std::uint64_t> watch_rejected_{0};
    std::atomic<std::uint64_t> quarantined_{0};
    std::atomic<std::uint64_t> slow_op_{0}; ///< an accepted obligation missed its health grace
                                            ///< (PR-B2: no longer "a blocking call held mu_ too
                                            ///< long" — nothing blocks under mu_ any more)
    std::atomic<std::uint64_t> probe_launched_{0};
    std::atomic<std::uint64_t> probe_admission_rejected_{0};
    std::atomic<std::uint64_t> probe_launch_failed_{0};
    std::atomic<std::uint64_t> probe_backend_failed_{0};
    std::atomic<std::uint64_t> probe_discarded_{0};
    std::atomic<std::uint64_t> synthetic_fires_{0};
    std::atomic<std::uint64_t> health_edges_{0};
    std::atomic<std::uint64_t> emit_failed_{0};
    std::atomic<std::uint64_t> fault_failed_{0};
    std::atomic<std::uint64_t> resync_retries_{0};
    std::atomic<std::uint64_t> established_failed_{0}; ///< established() threw when invoked

    std::atomic<std::size_t> retiring_cap_override_{0}; ///< 0 = use kRetiringCap
    std::atomic<std::int64_t> caller_wait_ms_{kFileCallerWaitBudget.count()};
    std::atomic<std::int64_t> health_grace_ms_{kFileHealthGrace.count()};
    std::atomic<std::int64_t> sweep_cadence_ms_{kFileSweepCadence.count()};
    std::atomic<std::int64_t> backend_retry_base_ms_{kFileBackendRetryBase.count()};
    std::atomic<std::int64_t> admission_seed_ms_{kFileAdmissionBackoffSeed.count()};
    std::atomic<std::int64_t> traversal_budget_ms_{kFileProbeTraversalBudget.count()};

    std::shared_ptr<const std::function<void(std::wstring_view)>> probe_hook_; ///< test seam
    std::shared_ptr<const std::function<void()>> test_emit_bookkeeping_hook_;  ///< test seam
    /// test seam; read/written only under mu_ (see apply_test_controls's comment).
    std::function<bool(std::wstring_view)> ancestor_rearm_fail_hook_;
    std::function<void(std::wstring_view)> completion_hook_; ///< test seam; only under mu_
    std::function<void()> pass_fail_hook_; ///< test seam (#4658); only under mu_
    /// Test seams added for #2012/#3840 PR-B2 review findings 1/4/5/6/7 - all
    /// read/written only under mu_, same contract as ancestor_rearm_fail_hook_/
    /// completion_hook_ above (every call site they fire from runs under mu_).
    std::function<void(std::wstring_view)> reserve_probe_fail_hook_;
    std::function<void(std::wstring_view)> resolve_log_fail_hook_;
    std::function<void(std::wstring_view)> ancestor_insert_fail_hook_;
    std::function<void(std::wstring_view)> watch_register_fail_hook_;
    std::function<bool(std::wstring_view)> attach_fail_hook_;
    std::function<void(std::wstring_view)> commit_attach_fail_hook_; ///< round-3 table opine
    std::function<bool(std::wstring_view)> notify_fail_hook_;        ///< round-3 closure pass
    std::function<void(std::wstring_view)> ancestor_invalidate_fail_hook_; ///< round-3 closure pass
    std::function<bool(std::wstring_view)> real_rearm_fail_hook_;    ///< round-3 closure pass

    /// #2839 test seam; null = no-op. Set-then-use, single-shot: push_retiring
    /// consumes it.
    std::function<void()> retire_fault_hook_for_test_;
};

} // namespace

std::unique_ptr<ISparkMechanism> make_file_mechanism() {
    return std::make_unique<WindowsFileMechanism>(nullptr); // no shared F3 counter (tests)
}

std::unique_ptr<ISparkMechanism>
make_file_mechanism(std::shared_ptr<std::atomic<std::size_t>> f3_counter) {
    return std::make_unique<WindowsFileMechanism>(std::move(f3_counter));
}

bool set_file_retire_fault_hook_for_test(ISparkMechanism& mech, std::function<void()> hook) {
    auto* file = dynamic_cast<WindowsFileMechanism*>(&mech);
    if (file == nullptr)
        return false;
    file->set_retire_fault_hook_for_test(std::move(hook));
    return true;
}

bool set_file_test_controls_for_test(ISparkMechanism& mech, FileMechanismTestControls controls) {
    auto* real = dynamic_cast<WindowsFileMechanism*>(&mech);
    if (!real)
        return false;
    real->apply_test_controls(std::move(controls));
    return true;
}

std::optional<FileMechanismDebugCounters> file_debug_counters_for_test(const ISparkMechanism& mech) {
    const auto* real = dynamic_cast<const WindowsFileMechanism*>(&mech);
    if (!real)
        return std::nullopt;
    return real->debug_counters();
}

} // namespace yuzu::agent

#else // ── Non-Windows: file-change spark is Windows-only for the MVP ──────────

namespace yuzu::agent {

std::unique_ptr<ISparkMechanism> make_file_mechanism() {
    return nullptr; // no mechanism → SparkEngine rejects arm(File) off Windows
}

std::unique_ptr<ISparkMechanism>
make_file_mechanism(std::shared_ptr<std::atomic<std::size_t>> /*f3_counter*/) {
    return nullptr; // same platform contract as the zero-argument form
}

bool set_file_retire_fault_hook_for_test(ISparkMechanism&, std::function<void()>) {
    // #2839: nothing to hook. make_file_mechanism() returns nullptr here, so no file
    // mechanism can exist on this platform. Defined rather than omitted so the
    // declaration links everywhere and a cross-platform test can call it and branch on
    // the result, instead of every caller needing its own #ifdef.
    return false;
}

bool set_file_test_controls_for_test(ISparkMechanism&, FileMechanismTestControls) {
    return false; // nothing to control off Windows
}

std::optional<FileMechanismDebugCounters> file_debug_counters_for_test(const ISparkMechanism&) {
    return std::nullopt;
}

} // namespace yuzu::agent

#endif // _WIN32
