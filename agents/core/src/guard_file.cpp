/**
 * guard_file.cpp — see guard_file.hpp.
 *
 * Windows: one watch thread holds a wait set of {dir-change, ancestor-change,
 * parent-change, stop} and runs reconcile() on every wakeup. reconcile() re-resolves from
 * scratch — if the parent directory exists, arm ReadDirectoryChangesW on it and
 * re-check the target's presence; else walk up to the nearest existing ancestor
 * and watch it for the parent's (re)creation. Arming happens BEFORE the presence
 * check so a change in the arm→check gap re-fires. This makes the guard resilient
 * (design §24): it survives the parent dir — and its whole ancestor chain — being
 * deleted and recreated, and keeps detecting until stop().
 *
 * Only changes to OUR filename (parsed from the FILE_NOTIFY_INFORMATION records)
 * trigger a reconcile, so a busy sibling-heavy directory does not wake us
 * needlessly (network-kindness / NFR). A buffer overflow (bytesReturned == 0)
 * reconciles unconditionally — we can't know what changed.
 *
 * The armed directory X (the target's parent, or the nearest existing ancestor) is
 * opened with FILE_SHARE_DELETE, so renaming or moving X gives no completion on X's
 * own handle: the handle follows X to its new name. A second, non-recursive
 * directory-name-only read on X's parent P reports that rename; a record naming X (or
 * carrying X's file id) or an overflow re-runs the same reconcile. P is bound to X's
 * resolved path and RETAINED across ordinary re-arms (run()'s `bind()`, the three-arm
 * rule in its own comment) — it is rebuilt only when X's identity actually changes, and
 * a rebuild is still armed before X is reopened, so a rename in that gap is not lost.
 * Matching is by path-string identity (plus X's FileId, when the extended notify API is
 * available) captured at the last rebuild — not re-validated on the retain path, and NOT
 * re-derived when X is deleted and recreated at the same path (a narrower instance of
 * the "identified by path" trade-off already present elsewhere in this file). P watches
 * only ONE level above X: P's own handle is opened the same FILE_SHARE_DELETE way as
 * X's, so a rename of P itself (or of anything above it) is just as invisible to P's
 * handle as X's own rename is to X's — nothing here watches P's parent for P being a
 * renamed/moved child entry. That case surfaces the same way any undetected-in-real-
 * time rename does: X's content next changes and triggers a bind() retry, not a
 * dedicated watch. Best effort, two DIFFERENT failure shapes: (1) TRANSIENT — if P
 * cannot be armed on a given attempt (open/read failure, and no ancestor watch is
 * active because X's own handle succeeded), no arm_retry is scheduled; it is simply
 * retried, fresh, on the next ordinary bind() call — a rename of X goes undetected
 * until X's content next changes and triggers that retry. (2) TERMINAL — if a
 * teardown's cancel-drain repeatedly fails to confirm (see ParentIoRelease/
 * kParentIoAbandonLimit below), P is PERMANENTLY disabled for the rest of this
 * guard's lifetime (logged once, at error level) — no further retry of any kind,
 * until the rule is next re-armed (a policy re-push or an agent restart). On that
 * transition this guard reports itself "guard.unhealthy" (once at the edge, then
 * re-sent every parent_unhealthy_refresh_ms for as long as this guard's OWN worker
 * thread keeps running — a lost-edge backstop against the legacy sink dropping an
 * event on disconnect with no retry, not a guarantee against the thread itself
 * dying: a WAIT_FAILED/WAIT_ABANDONED break or an unhandled exception silently ends
 * run(), and this guard then sends nothing further until the next reconcile
 * replaces it) and
 * withholds every further compliant publication until the rule is re-armed, so the
 * operator-facing census cannot show 100% compliant while rename detection is dead
 * (see report_compliant() below). Either way, X's own detection (presence/content,
 * evaluated on every wake) is unaffected and keeps reporting drift/compliant
 * normally; only P's rename-of-X detection is lost, and only P's loss changes what
 * gets published.
 *
 * Detection-only: a FileGuard never writes (file-content remediation needs
 * Content Distribution; deferred). Proto-free + windows.h-free header. On
 * non-Windows the guard is a no-op (start() returns false).
 */

#include <yuzu/agent/guard_file.hpp>

#include <yuzu/agent/plugin_loader.hpp> // sha256_file (bounded)

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp>

#include <chrono>
#include <filesystem>
#include <optional>
#include <system_error>

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "guard_win_handle.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <utility>

namespace yuzu::agent {
namespace {

// Degraded re-arm cadence used ONLY when no watch (dir or ancestor) could be armed
// — a rare failure. Without it the INFINITE wait would block forever, silently
// breaking live-until-disabled (mirrors RegistryGuard's kArmFailRetryMs). The
// healthy path never uses this — it stays fully event-driven (no poll).
constexpr DWORD kArmFailRetryMs = 30000;

// Health-report detail text for the parent-watch permanent-disable transition (see
// ParentIoRelease/kParentIoAbandonLimit). Rendered VERBATIM on the device page's
// event detail column (device_ui.cpp), so it is written for an operator, not an
// engineer — plain language, no internal terms ("cancel drain", "abandon limit").
// The engineering detail (drain-failure count, mechanism) stays in the accompanying
// spdlog::error line instead, which is not customer-facing. No path in the string —
// keeps the text identical across different watched paths (a future test pinning it
// can rely on that).
constexpr std::string_view kParentDisabledDetail =
    "Rename/move detection for this rule is disabled after repeated failures to "
    "reset its file-system watch (often caused by a slow or unreliable network "
    "share). This rule's file presence/content checks are unaffected. To restore "
    "rename detection: re-push this rule's policy, or restart the agent.";

// (A dead, uncalled local to_wide copy was removed here in the #1681 win_str
// de-dup — guard_file does no wide<->UTF-8 conversion of its own.)

// Case-insensitive wide compare (Windows filenames are case-insensitive). Ordinal
// (not locale) — a filename match is a byte/codepoint identity check, not a
// linguistic one.
bool iequals_w(std::wstring_view a, std::wstring_view b) {
    return a.size() == b.size() &&
           CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(),
                                static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
}

// ReadDirectoryChangesExW (Windows 10 1709+) is resolved at run time; without it the
// parent watch uses plain records and matches by leaf name only. The last argument is
// READ_DIRECTORY_NOTIFY_INFORMATION_CLASS; 2 = ReadDirectoryNotifyExtendedInformation.
using ReadDirChangesExFn = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED,
                                         LPOVERLAPPED_COMPLETION_ROUTINE, int);
constexpr int kNotifyExtended = 2;

ReadDirChangesExFn resolve_read_dir_changes_ex() {
    static const ReadDirChangesExFn fn = reinterpret_cast<ReadDirChangesExFn>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ReadDirectoryChangesExW"));
    return fn;
}

// FILE_NOTIFY_EXTENDED_INFORMATION layout (fixed; the type is missing from older SDKs):
// FileId is 64-bit, FileNameLength and FileName follow the fixed 84-byte header.
constexpr std::size_t kExFileIdOff = 64;
constexpr std::size_t kExNameLenOff = 80;
constexpr std::size_t kExNameOff = 84;

// Bounded wait for a cancelled parent read to complete before its OVERLAPPED and buffer are reused.
constexpr DWORD kCancelDrainMs = 1000;

// Consecutive failed parent-read completions tolerated before falling back to the
// degraded re-arm cadence (no rebuild loop against a watch that fails at once).
constexpr int kParentFailureLimit = 3;

// Parent-block cancel-drain failures tolerated, over this run() invocation's whole
// lifetime, before permanently disabling the parent-directory watch for this guard
// instance (sec-1): an unconfirmed drain abandons the heap block rather than freeing
// it (see ParentIoRelease below). Deliberately NOT reset on an intervening confirmed
// drain (unlike kParentFailureLimit/p_failures, which does reset on success) — a
// driver that stalls every other rebuild would never trip a reset-on-success cap,
// leaking one abandoned block per stall indefinitely, which is exactly the unbounded
// leak this cap exists to prevent. NOTE: "this run() invocation" is per guard
// INSTANTIATION, not per agent-process lifetime — GuardianEngine tears down and
// reconstructs a fresh FileGuard (and therefore a fresh count/disabled-flag) on
// every reconcile that touches this rule_id, so the leak bound is 3 blocks per
// wedged-drain episode PER RECONCILE, not 3 for the process's whole uptime; the
// realistic total stays small only because reconcile frequency for a converged
// rule is low (policy-generation-gated, not a periodic heartbeat re-arm).
constexpr int kParentIoAbandonLimit = 3;

// Low 64 bits of a directory handle's FileId (what the extended notify record carries);
// nullopt when the query fails or the id is wider than 64 bits (e.g. ReFS): name match only.
std::optional<std::uint64_t> dir_file_id(HANDLE h) {
    FILE_ID_INFO fi{};
    if (!GetFileInformationByHandleEx(h, FileIdInfo, &fi, sizeof fi))
        return std::nullopt;
    std::uint64_t lo = 0, hi = 0;
    std::memcpy(&lo, fi.FileId.Identifier, sizeof lo);
    std::memcpy(&hi, fi.FileId.Identifier + sizeof lo, sizeof hi);
    if (hi != 0)
        return std::nullopt;
    return lo;
}

} // namespace

FileGuard::FileGuard(Config cfg, GuardSink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}

FileGuard::~FileGuard() { stop(); }

bool FileGuard::start() {
    if (cfg_.path.empty())
        return false;

    // Canonicalise so the parent-dir watch tracks the real location: resolves
    // `..`, mixed separators, and symlinks/junctions in the EXISTING prefix.
    // weakly_canonical (not canonical) so a not-yet-existing target is still
    // accepted — file-exists legitimately watches a path that may not exist yet
    // (expect absent), and we want to detect its creation.
    namespace fs = std::filesystem;
    std::error_code ec;
    fs::path canon = fs::weakly_canonical(fs::path(cfg_.path), ec);
    if (!ec && !canon.empty())
        cfg_.path = canon.string();

    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr); // manual-reset stop
    if (!stop_event_)
        return false;
    stop_.store(false, std::memory_order_release);
    thread_ = std::thread([this] { run(); });
    return true;
}

void FileGuard::stop() {
    stop_.store(true, std::memory_order_release);
    if (stop_event_)
        SetEvent(static_cast<HANDLE>(stop_event_));
    if (thread_.joinable())
        thread_.join();
    if (stop_event_) {
        CloseHandle(static_cast<HANDLE>(stop_event_));
        stop_event_ = nullptr;
    }
}

void FileGuard::run() try {
    using detail::ChangeNotifyHandle;
    using detail::DirHandle;
    using detail::EventHandle;
    namespace fs = std::filesystem;
    const fs::path target(cfg_.path);
    const fs::path parent = target.parent_path();
    const std::wstring fname = target.filename().wstring();
    const bool hash_mode = (cfg_.assertion == Assertion::HashEquals);

    // ReadDirectoryChangesW notification buffer (DWORD-aligned). 32 KiB holds many
    // records; on overflow we reconcile unconditionally, so the size is a perf knob
    // not a correctness one.
    alignas(DWORD) std::byte notify_buf[32 * 1024];

    // RAII owners — released on EVERY exit, including an exception unwind (the sink
    // does a network write and can throw); a leaked HANDLE + std::terminate is what
    // the manual-cleanup version risked.
    EventHandle dir_event(CreateEventW(nullptr, FALSE, FALSE, nullptr)); // auto-reset OVERLAPPED hEvent
    if (!dir_event) {
        spdlog::error("Guardian FileGuard[{}]: CreateEventW failed — watch not started",
                      log_id_token(cfg_.rule_id));
        return;
    }
    // Waitable timer for the disabled-parent-watch unhealthy refresh (lost-edge backstop).
    // Created lazily, only at the disable transition (on_parent_disabled, below) — most
    // guards never disable P and never pay for this handle. CloseHandle (EventHandle's
    // deleter) is the correct release for a waitable timer, same as any other handle.
    EventHandle p_refresh_timer;
    OVERLAPPED ov{};
    ov.hEvent = dir_event.get();
    DirHandle h_dir;                   // parent dir, open for ReadDirectoryChangesW
    ChangeNotifyHandle ancestor_event; // FindFirstChangeNotificationW (normalises -1 → empty)
    bool read_pending = false;

    // Parent-of-armed-directory watch. X = the directory armed below; P = X's parent, read for
    // X's own rename/move. One heap block per "generation" bound to a resolved X path (bind()'s
    // three-arm rule below); ParentIoRelease — this block's unique_ptr deleter — is the single
    // drain-or-abandon chokepoint invoked whenever a generation ends, whether by a mid-run
    // rebind to a different X (bind()'s rebuild arm) or by run() itself exiting (normal, the
    // WAIT_FAILED/WAIT_ABANDONED break below, or exception unwind) — one code path for both,
    // never two separate teardown routines (sec-1).
    struct ParentIo {
        alignas(8) std::byte buf[32 * 1024];
        OVERLAPPED ov{};
        EventHandle ev;
        DirHandle dir;
        bool pending = false;
        bool p_ex = false; // extended (FileId-bearing) records in use for this handle/volume
        fs::path bound_x;  // X this block is armed for (bind()'s three-arm key)
    };

    // A genuinely in-flight read is cancelled and drained (bounded, one extension); if the
    // drain does not confirm, the handles are closed but the block itself is deliberately NOT
    // freed — abandoned, so a delayed kernel completion writes into still-allocated,
    // never-reused memory instead of a freed/reused heap block. Never dispatches, re-arms, or
    // evaluates from here: doing so would reenter bind() through the very unique_ptr being torn
    // down. Logging is wrapped in try/catch — this can run during exception unwind through
    // run()'s own frame, and an exception escaping a destructor-adjacent path there is
    // std::terminate, uncatchable by run()'s own outer catch blocks.
    struct ParentIoRelease {
        int* abandon_count;
        bool* disabled;
        const std::string* rule_id;
        const std::string* path;
        // Test-only (see FileGuard::set_parent_drain_fail_hook_for_test's doc). Checked ONLY
        // when the real drain just confirmed true — never used to fabricate a confirmation out
        // of a real false, so this can only route execution down the SAME abandon branch a
        // genuinely wedged driver would take, never invent a new one.
        const std::function<bool()>* drain_fail_hook;

        void operator()(ParentIo* p) const noexcept {
            if (!p)
                return;
            if (p->pending) {
                CancelIoEx(p->dir.get(), &p->ov);
                bool drained = WaitForSingleObject(p->ev.get(), kCancelDrainMs) == WAIT_OBJECT_0;
                if (!drained) // one bounded extension, matches this file's existing drain convention
                    drained = WaitForSingleObject(p->ev.get(), kCancelDrainMs) == WAIT_OBJECT_0;
                if (drained && drain_fail_hook && *drain_fail_hook && (*drain_fail_hook)())
                    drained = false; // test-forced: model a drain that never confirmed
                if (drained) {
                    DWORD bytes = 0;
                    // Consume the completion so the kernel's bookkeeping settles; the content
                    // itself is discarded — safe because every arm_watch()/bind() call in this
                    // file arms before its presence re-check (see the header comment), so
                    // whatever this read would have found is re-observed by the next re-check.
                    GetOverlappedResult(p->dir.get(), &p->ov, &bytes, FALSE);
                } else {
                    // Not confirmed drained: close the handles (safe — the kernel keeps the
                    // underlying objects alive for as long as an outstanding I/O references
                    // them, independent of the user-mode handle) but do NOT delete p.
                    p->dir.reset();
                    p->ev.reset();
                    ++*abandon_count;
                    if (*abandon_count >= kParentIoAbandonLimit) {
                        *disabled = true;
                        try {
                            spdlog::error(
                                "Guardian FileGuard[{}]: parent-directory watch for {} "
                                "permanently disabled after {} drain failures - directory "
                                "rename detection unavailable for this rule until it is next "
                                "re-armed (a policy re-push or an agent restart)",
                                log_id_token(*rule_id), log_key_token(*path),
                                kParentIoAbandonLimit);
                        } catch (...) {
                        }
                    } else {
                        try {
                            spdlog::warn(
                                "Guardian FileGuard[{}]: parent-directory watch cancel for {} "
                                "did not drain within {}ms - block abandoned ({}/{})",
                                log_id_token(*rule_id), log_key_token(*path), kCancelDrainMs * 2,
                                *abandon_count, kParentIoAbandonLimit);
                        } catch (...) {
                        }
                    }
                    return; // deliberately does not delete p
                }
            }
            delete p;
        }
    };

    // abandon_count/disabled are declared BEFORE `pio` so `pio`'s destructor (which reads/writes
    // them via ParentIoRelease) runs BEFORE they are destroyed, on every exit from run() —
    // normal, the WAIT_FAILED/WAIT_ABANDONED break, or exception unwind (mandatory ordering).
    int p_abandon_count = 0; // parent-block cancel-drain failures this run() (sec-1); does
                             // NOT reset on a confirmed drain — see kParentIoAbandonLimit
    bool p_disabled = false; // permanently disabled once p_abandon_count reaches the limit;
        // drives report_parent_unhealthy()/on_parent_disabled() below and gates
        // report_compliant() — the operator-facing "guard.unhealthy" census signal for
        // this state. GuardianEngine::get_status() (a SEPARATE, still-placeholder surface
        // that stamps every rule "errored" unconditionally) is untouched by this and
        // remains its own named follow-up — this field's real consumer is the event path,
        // not get_status().
    std::unique_ptr<ParentIo, ParentIoRelease> pio(
        nullptr, ParentIoRelease{&p_abandon_count, &p_disabled, &cfg_.rule_id, &cfg_.path,
                                  &parent_drain_fail_hook_for_test_});
    bool p_logged = false; // the "no parent watch" note is logged once per guard
    int p_failures = 0;    // consecutive failed P completions (handle_p_wake's degraded-cadence
                           // trigger — distinct from p_abandon_count, which counts teardown
                           // drain failures on ParentIoRelease)
    std::wstring x_leaf;   // leaf name of X
    std::optional<std::uint64_t> x_id; // low 64 bits of X's FileId, when known
    const ReadDirChangesExFn read_ex = resolve_read_dir_changes_ex();

    // Collapse-with-count debounce (shared convention with RegistryGuard, H3/#1209).
    std::optional<std::chrono::steady_clock::time_point> last_emit;
    std::uint64_t suppressed = 0;

    // Compliance-edge state (Slice B, shared convention with RegistryGuard). nullopt
    // until the first eval, then a guard.compliant event fires ONCE on the edge into
    // compliant; steady compliant state stays silent (NFR). Only this thread touches it.
    std::optional<bool> last_compliant;

    // file-hash-equals state.
    std::string baseline;      // captured-on-arm hash when expected_hash is empty
    bool baseline_set = false;
    bool hash_pending = false; // a change is settling before we (re)hash
    std::chrono::steady_clock::time_point settle_first{}; // when the current settle window began
    bool arm_retry = false;    // no watch could be armed → degraded bounded re-arm scheduled
    std::optional<std::chrono::steady_clock::time_point> retry_at; // absolute degraded-retry deadline;
        // set once on entry, not extended by intervening activity while still degraded (see below)

    // KNOWN RESIDUAL (pre-existing, unchanged by the parent-watch redesign above): h_dir's
    // RAII release (cancel_and_close_ in guard_win_handle.hpp — CancelIo+CloseHandle, no
    // wait) does not drain a genuinely in-flight read before notify_buf/ov are reused or
    // the stack frame is torn down — the same shape as sec-1, which THIS diff fixed for
    // the parent watch (pio/ParentIoRelease) but deliberately left h_dir alone (X's own
    // content channel is out of scope for this branch). A dedicated follow-up, tracked
    // alongside the disclosure decision for this branch's other pre-existing residuals.
    auto reset_dir = [&](HANDLE h = nullptr) {
        h_dir.reset(h);
        read_pending = false;
    };

    // (Re)issue ReadDirectoryChangesW on the already-open parent handle.
    auto arm_dir_read = [&]() -> bool {
        if (!h_dir)
            return false;
        constexpr DWORD kFilter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                  FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                                  FILE_NOTIFY_CHANGE_CREATION;
        read_pending = ReadDirectoryChangesW(h_dir.get(), notify_buf, sizeof(notify_buf), FALSE,
                                             kFilter, nullptr, &ov, nullptr) != 0;
        return read_pending;
    };

    // Health report for the parent-watch permanent-disable state (NOT a compliance
    // verdict — see guard.hpp's GuardDrift::Health doc). Called once at the disable
    // edge (on_parent_disabled, below) and again on every refresh-timer tick, and
    // substituted for a compliant publication by report_compliant()'s gate (below).
    // Best-effort: never let a sink failure end the worker over a health report —
    // run()'s outer catch would tear down the whole guard on an escaping exception,
    // and a health report is strictly less important than the drift/compliance
    // detection this guard exists to provide.
    auto report_parent_unhealthy = [&]() {
        GuardDrift d;
        d.guard_type = "file";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.health = GuardDrift::Health::Unhealthy;
        d.health_detail = std::string(kParentDisabledDetail);
        try {
            if (sink_)
                sink_(d);
        } catch (const std::exception& e) {
            spdlog::warn("Guardian FileGuard[{}]: health-report sink threw: {} — continuing",
                         log_id_token(cfg_.rule_id), e.what());
        } catch (...) {
            spdlog::warn("Guardian FileGuard[{}]: health-report sink threw (unknown) — continuing",
                         log_id_token(cfg_.rule_id));
        }
    };

    // Fired exactly once, at the p_disabled transition. The SOLE call site is bind()'s
    // rebuild arm (below), immediately after pio.reset() trips the abandon limit —
    // never from inside ParentIoRelease itself, which stays free of event dispatch,
    // evaluation, and re-arming (sec-1's own invariant). Arms the lost-edge refresh
    // timer (if configured) and sends the first unhealthy report. No filesystem work:
    // this never touches X or P.
    auto on_parent_disabled = [&]() {
        if (cfg_.parent_unhealthy_refresh_ms > 0) {
            p_refresh_timer.reset(CreateWaitableTimerW(nullptr, FALSE, nullptr));
            if (p_refresh_timer) {
                LARGE_INTEGER due{};
                due.QuadPart = -static_cast<LONGLONG>(cfg_.parent_unhealthy_refresh_ms) * 10'000;
                if (!SetWaitableTimer(p_refresh_timer.get(), &due,
                                      static_cast<LONG>(cfg_.parent_unhealthy_refresh_ms), nullptr,
                                      nullptr, FALSE)) {
                    spdlog::warn("Guardian FileGuard[{}]: SetWaitableTimer failed (err={}) — "
                                 "unhealthy refresh disabled, edge report only",
                                 log_id_token(cfg_.rule_id), GetLastError());
                    p_refresh_timer.reset();
                }
            } else {
                spdlog::warn("Guardian FileGuard[{}]: CreateWaitableTimerW failed (err={}) — "
                             "unhealthy refresh disabled, edge report only",
                             log_id_token(cfg_.rule_id), GetLastError());
            }
        }
        report_parent_unhealthy();
    };

    // (Re)issue the directory-name-only read on the given (already-open) P block. Note for the
    // retain path (bind()'s arm 2, below): if an extended-record reissue fails here, p.p_ex
    // flips to false and the fallback plain-record read is issued on the SAME generation — the
    // block stays bound to the same x, x_leaf/x_id are untouched and still valid, but
    // parent_change_is_ours now matches by leaf name only for the rest of this generation
    // (mirrors the one-time extended-to-plain fallback bind()'s rebuild arm already has on a
    // fresh open; this is that same fallback reachable mid-generation via a reissue instead).
    auto issue_p_read = [&](ParentIo& p) -> bool {
        if (!p.dir)
            return false;
        ResetEvent(p.ev.get());
        if (p.p_ex && read_ex(p.dir.get(), p.buf, sizeof(p.buf), FALSE, FILE_NOTIFY_CHANGE_DIR_NAME,
                              nullptr, &p.ov, nullptr, kNotifyExtended) != 0) {
            p.pending = true;
            return true;
        }
        p.p_ex = false; // extended read unavailable: plain records, leaf-name match only
        p.pending = ReadDirectoryChangesW(p.dir.get(), p.buf, sizeof(p.buf), FALSE,
                                          FILE_NOTIFY_CHANGE_DIR_NAME, nullptr, &p.ov, nullptr) != 0;
        return p.pending;
    };

    // Watch X's parent P for X's own rename or move. Bound to X's resolved path and RETAINED
    // across ordinary re-arms — rebuilt only when X's identity actually changes. Called BEFORE
    // X's reopen (arm_watch_once, below), exactly as before, so a rename between the two arms is
    // still reported. Returns true iff P was actually (re)built this call: the caller uses this
    // to decide whether x_id needs re-deriving (bind() itself owns x_leaf, but x_id needs X's own
    // handle, which is not yet open at this point — see arm_watch_once). Best effort throughout:
    // on any failure the guard runs without P (logged once) and never fails to arm X.
    //
    // Three arms, keyed on whether the currently-held block (if any) is bound to THIS x:
    //   1. bound to x, pending      — no-op; leave the block alone entirely.
    //   2. bound to x, not pending  — reissue a fresh read on the SAME retained handle (mirrors
    //      the reissue handle_p_wake already does after a non-matching completion); x_leaf/x_id
    //      are untouched since the binding has not changed.
    //   3. unbound, bound to a different x, or a same-x reissue that just failed — rebuild: drop
    //      the old block (drains-or-abandons via ParentIoRelease), open a fresh handle on
    //      x.parent_path(), and re-derive x_leaf (x_id is re-derived by the caller, once X's own
    //      handle is available).
    auto bind = [&](const fs::path& x) -> bool {
        if (p_disabled)
            return false; // permanently disabled (sec-1 abandon limit reached): no rebuild loop
        if (pio && pio->bound_x == x) {
            if (pio->pending)
                return false; // arm 1
            if (issue_p_read(*pio))
                return false; // arm 2
            // Reissue failed: do not leave a stale, bound-but-broken block — fall through to
            // the rebuild arm below, exactly as an unbound/different-x call would.
        }
        // arm 3: rebuild.
        pio.reset(); // invokes ParentIoRelease: drains (or abandons) any previous block
        if (p_disabled) {
            on_parent_disabled(); // the reset above just tripped the abandon limit: report once
            return false;
        }
        x_leaf.clear();
        x_id.reset();
        if (!x.has_relative_path() || x.filename().empty()) { // no parent above a root
            if (!p_logged) {
                p_logged = true;
                spdlog::debug("Guardian FileGuard[{}]: no parent directory to watch above {}",
                              log_id_token(cfg_.rule_id), log_key_token(cfg_.path));
            }
            return false;
        }
        // Owned by a unique_ptr from the moment of allocation (sharing pio's own deleter, so
        // both instances read/write the SAME abandon_count/disabled/hook state) rather than a
        // bare `new`/manual `delete` — a throwing fs::path/wstring operation anywhere in this
        // sequence (bad_alloc; low-probability but real, and NOT "trivial" the way a Win32 call
        // is) then unwinds through ParentIoRelease exactly like any other exit, draining-or-
        // abandoning correctly instead of silently leaking a possibly-already-pending read.
        std::unique_ptr<ParentIo, ParentIoRelease> fresh(new ParentIo(), pio.get_deleter());
        fresh->ev.reset(CreateEventW(nullptr, FALSE, FALSE, nullptr));
        fresh->ov.hEvent = fresh->ev.get();
        if (!fresh->ev) {
            if (!p_logged) {
                p_logged = true;
                spdlog::warn("Guardian FileGuard[{}]: parent-directory watch for {} not armed "
                             "(event creation failed)",
                             log_id_token(cfg_.rule_id), log_key_token(cfg_.path));
            }
            return false; // fresh destructs here: pending==false, freed directly; P stays
                          // unbound, no arm_retry (finding 4) — retried on the next bind()
        }
        fresh->dir.reset(CreateFileW(x.parent_path().wstring().c_str(), FILE_LIST_DIRECTORY,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                     OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                     nullptr));
        DWORD err = fresh->dir ? ERROR_SUCCESS : GetLastError();
        fresh->p_ex = (read_ex != nullptr);
        if (fresh->dir && !issue_p_read(*fresh))
            err = GetLastError();
        if (!fresh->pending) {
            if (!p_logged) {
                p_logged = true;
                spdlog::warn("Guardian FileGuard[{}]: parent-directory watch for {} not armed "
                             "(err={})",
                             log_id_token(cfg_.rule_id), log_key_token(cfg_.path), err);
            }
            return false; // fresh destructs here: pending==false, freed directly; P stays
                          // unbound, no arm_retry (finding 4) — retried on the next bind()
        }
        fresh->bound_x = x;
        x_leaf = x.filename().wstring();
        pio = std::move(fresh); // transfers ownership; fresh is now null, no double-teardown
        return true;
    };

    auto report = [&](const std::string& detected, const std::string& expected) {
        last_compliant = false; // drifted / can't-verify (reported, possibly collapsed)
        const auto now = std::chrono::steady_clock::now();
        if (last_emit && (now - *last_emit) < std::chrono::milliseconds(cfg_.event_debounce_ms)) {
            ++suppressed; // fold into the next post-window emission
            return;
        }
        GuardDrift d;
        d.guard_type = "file";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = detected;
        d.expected_value = expected;
        d.collapsed_count = suppressed;
        suppressed = 0;
        last_emit = now;
        if (sink_)
            sink_(d);
    };

    // Compliant edge (Slice B): emit guard.compliant ONCE on the transition into
    // compliant (incl. the first eval / baseline-on-arm, last_compliant == nullopt).
    // Steady compliant state is silent; bypasses the drift-debounce collapse.
    auto report_compliant = [&]() {
        if (last_compliant == true)
            return;
        last_compliant = true;
        if (p_disabled) {
            // The primary channel IS at its expected state — last_compliant still
            // records that — but the PUBLICATION is replaced: never show green while
            // P's rename-of-X detection is permanently dead. This is the sole
            // compliant emitter (report() below is the drift arm), so no other eval
            // site can bypass this gate.
            report_parent_unhealthy();
            return;
        }
        GuardDrift d;
        d.guard_type = "file";
        d.rule_id = cfg_.rule_id;
        d.rule_name = cfg_.rule_name;
        d.detected_value = "<compliant>";
        d.expected_value = "<compliant>";
        d.compliant = true;
        if (sink_)
            sink_(d);
    };

    // file-exists: drift when presence != expected.
    auto eval_exists = [&] {
        std::error_code ec;
        const bool present = fs::exists(target, ec);
        if (present != cfg_.expect_present) {
            spdlog::info("Guardian FileGuard[{}]: {} (expected {}) for {}",
                         log_id_token(cfg_.rule_id), present ? "present" : "absent",
                         cfg_.expect_present ? "present" : "absent", log_key_token(cfg_.path));
            report(present ? "<present>" : "<absent>",
                   cfg_.expect_present ? "<present>" : "<absent>");
        } else {
            report_compliant();
        }
    };

    // file-hash-equals: drift when content (bounded SHA-256) differs from the
    // baseline / expected hash. Reads the PATH (independent of the dir handle) so it
    // is correct regardless of watch state. Fail-loud on absent / oversize /
    // unreadable — never a silent "compliant" (G11/N3).
    auto eval_hash = [&] {
        std::error_code ec;
        const std::string expected_disp =
            cfg_.expected_hash.empty() ? (baseline_set ? baseline : std::string{"<baseline>"})
                                       : cfg_.expected_hash;
        if (!fs::exists(target, ec)) {
            report("<absent>", expected_disp);
            return;
        }
        const auto sz = fs::file_size(target, ec);
        if (ec) {
            report("<unreadable>", expected_disp);
            return;
        }
        if (sz > cfg_.max_hash_bytes) {
            // Too large to verify within the DoS cap — report rather than skip, so
            // the operator sees "can't verify", not a false compliant.
            report("<oversize>", expected_disp);
            return;
        }
        // Hash on each settled change — once per quiescence window, so cheap, and it
        // puts the actual digest in every drift report. Bounded by max_hash_bytes (a
        // TOCTOU-grow / DoS defence). NB: a size-delta pre-filter to skip hashing was
        // considered and dropped — the per-event cost is negligible and unconditional
        // hashing keeps the forensic digest (a size-only signal would lose it).
        const std::string cur =
            sha256_file(target, static_cast<std::size_t>(cfg_.max_hash_bytes));
        if (cur.empty()) {
            // Grew past the cap mid-read (TOCTOU) or read error → can't verify.
            report("<unreadable>", expected_disp);
            return;
        }
        if (cfg_.expected_hash.empty() && !baseline_set) {
            baseline = cur; // baseline-on-arm: first present read establishes the good state
            baseline_set = true;
            spdlog::info("Guardian FileGuard[{}]: baselined {} = {}", log_id_token(cfg_.rule_id),
                         log_key_token(cfg_.path), cur);
            if (cfg_.on_baseline) // #4021: persist so a later full_sync/restart re-seeds this
                cfg_.on_baseline(cur);
            report_compliant(); // armed at the known-good baseline → compliant edge
            return;             // no drift — we just captured the baseline
        }
        const std::string& effective = cfg_.expected_hash.empty() ? baseline : cfg_.expected_hash;
        if (cur != effective) {
            spdlog::info("Guardian FileGuard[{}]: content drift on {} ({} != {})",
                         log_id_token(cfg_.rule_id), log_key_token(cfg_.path), cur, effective);
            report(cur, effective);
        } else {
            report_compliant();
        }
    };

    // The armed directory X: the parent if it exists, else the nearest existing ancestor
    // (empty if none, or if the chain ends at a root that is not a directory).
    auto nearest_existing_dir = [&]() -> fs::path {
        fs::path x = parent;
        std::error_code ec;
        while (!x.empty() && !fs::is_directory(x, ec)) {
            fs::path up = x.parent_path();
            if (up == x)
                return {};
            x = std::move(up);
        }
        return x;
    };

    // One pass of the re-arm; returns the X the parent watch was armed for.
    auto arm_watch_once = [&]() -> fs::path {
        reset_dir();
        ancestor_event.reset();
        arm_retry = false;
        const fs::path x = nearest_existing_dir();
        const bool p_rebuilt = bind(x); // BEFORE arming X, so a rename between the two arms
                                         // is reported (bind()'s three-arm rule, above)
        std::error_code ec;
        if (!parent.empty() && fs::is_directory(parent, ec)) {
            reset_dir(CreateFileW(parent.wstring().c_str(), FILE_LIST_DIRECTORY,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                  OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                                  nullptr));
            if (h_dir && !arm_dir_read())
                reset_dir();
        }
        if (!h_dir) {
            const fs::path anc = nearest_existing_dir();
            if (!anc.empty())
                ancestor_event.reset(FindFirstChangeNotificationW(
                    anc.wstring().c_str(), TRUE,
                    FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_FILE_NAME));
            if (!h_dir && !ancestor_event) {
                arm_retry = true; // both arms failed → bounded degraded re-arm (no deaf-forever)
                spdlog::warn("Guardian FileGuard[{}]: no watch armed for {} — degraded re-arm in {}ms",
                             log_id_token(cfg_.rule_id), log_key_token(cfg_.path), kArmFailRetryMs);
            }
        }
        if (p_rebuilt && pio->p_ex) { // X's FileId, from its own handle (a transient one in
                                       // ancestor mode) — only re-derived on an actual P
                                       // rebuild (bind()'s three-arm rule); left stale on a
                                       // no-op/reissue arm is the accepted trade-off (header)
            if (h_dir) {
                x_id = dir_file_id(h_dir.get());
            } else {
                // OPEN_REPARSE_POINT: for a mount-point or junction X the id must be the
                // directory entry's own, which is what P's record carries.
                DirHandle xh(CreateFileW(x.wstring().c_str(), FILE_READ_ATTRIBUTES,
                                         FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                         nullptr, OPEN_EXISTING,
                                         FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                                         nullptr));
                if (xh)
                    x_id = dir_file_id(xh.get());
            }
        }
        return x;
    };

    // Re-resolve the watch from scratch (no eval): arm the parent-dir watch if the
    // parent exists, else the nearest-ancestor watch for its (re)creation, plus the watch
    // on X's parent. Sets arm_retry when NEITHER could be armed so the wait loop self-heals.
    // X can change between resolving it and arming (a rename in that window): re-check, bounded;
    // if it keeps changing, the parent watch may be armed for a stale X, so schedule a re-arm.
    auto arm_watch = [&] {
        for (int attempt = 0; attempt < 3; ++attempt) {
            const fs::path armed_for = arm_watch_once(); // arm first: the re-check must see the state after it
            if (armed_for == nearest_existing_dir())
                return;
        }
        spdlog::warn("Guardian FileGuard[{}]: watched directory kept changing while arming {} - "
                     "degraded re-arm in {}ms",
                     log_id_token(cfg_.rule_id), log_key_token(cfg_.path), kArmFailRetryMs);
        arm_retry = true;
    };

    auto eval_now = [&] {
        if (hash_mode)
            eval_hash();
        else
            eval_exists();
    };

    auto begin_settle = [&] {
        if (!hash_pending) {
            hash_pending = true;
            settle_first = std::chrono::steady_clock::now();
        }
    };

    // True iff the completed read in `buf` mentions `leaf` (or overflowed). The
    // record walk is bounded by `bytes` so a malformed/truncated buffer cannot run
    // past the data the kernel actually returned.
    auto change_is_ours = [&](const std::byte* buf, DWORD bytes, std::wstring_view leaf) -> bool {
        if (bytes == 0)
            return true; // buffer overflow — can't tell, reconcile
        std::size_t off = 0;
        while (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) <= bytes) {
            auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buf + off);
            const std::size_t name_bytes = info->FileNameLength;
            if (off + offsetof(FILE_NOTIFY_INFORMATION, FileName) + name_bytes > bytes)
                break; // truncated record — stop
            const std::wstring_view name(info->FileName, name_bytes / sizeof(WCHAR));
            if (iequals_w(name, leaf))
                return true;
            if (info->NextEntryOffset == 0)
                break;
            off += info->NextEntryOffset;
        }
        return false;
    };

    // Same for the parent read: ANY record naming X or carrying X's FileId (whatever its
    // action) means re-check; overflow means re-check. Extended records are walked here.
    auto parent_change_is_ours = [&](DWORD bytes) -> bool {
        if (!pio->p_ex)
            return change_is_ours(pio->buf, bytes, x_leaf);
        if (bytes == 0)
            return true; // overflow
        std::size_t off = 0;
        while (off + kExNameOff <= bytes) {
            const std::byte* rec = pio->buf + off;
            DWORD next = 0, name_bytes = 0;
            std::uint64_t id = 0;
            std::memcpy(&next, rec, sizeof next);
            std::memcpy(&id, rec + kExFileIdOff, sizeof id);
            std::memcpy(&name_bytes, rec + kExNameLenOff, sizeof name_bytes);
            if (off + kExNameOff + name_bytes > bytes)
                break; // truncated record: stop
            const std::wstring_view name(reinterpret_cast<const WCHAR*>(rec + kExNameOff),
                                         name_bytes / sizeof(WCHAR));
            if (iequals_w(name, x_leaf) || (x_id && id == *x_id))
                return true;
            if (next == 0)
                break;
            off += next;
        }
        return false;
    };

    // A completed P read: named so the D branch below can also service an already-signalled P
    // without waiting for a later wait call (D is always the lowest-indexed handle). Only
    // called while pio is bound and pending (see both call sites below), so pio is never null
    // here.
    auto handle_p_wake = [&] {
        DWORD bytes = 0;
        const BOOL got = GetOverlappedResult(pio->dir.get(), &pio->ov, &bytes, FALSE);
        const DWORD p_err = got ? ERROR_SUCCESS : GetLastError();
        if (got == FALSE && p_err == ERROR_IO_INCOMPLETE)
            return; // spurious signal: the read is still in flight
        pio->pending = false; // no read in flight now: a reset()/rebuild below frees without draining
        p_failures = got ? 0 : p_failures + 1;
        if (p_failures > kParentFailureLimit) {
            if (p_failures == kParentFailureLimit + 1) // once per entry into this state
                spdlog::warn("Guardian FileGuard[{}]: parent-directory watch for {} failing "
                             "repeatedly (err={}) - degraded re-arm in {}ms",
                             log_id_token(cfg_.rule_id), log_key_token(cfg_.path), p_err,
                             kArmFailRetryMs);
            pio.reset(); // pending==false: freed immediately by ParentIoRelease, no drain needed
            // A previously-working watch degrading (unlike bind()'s fresh-open failure, which
            // never sets arm_retry — see finding 4): bounded degraded re-arm, not a rebuild loop.
            arm_retry = true;
        } else if (got == FALSE || parent_change_is_ours(bytes)) {
            arm_watch(); // X named / overflow / failed read: re-resolve X, then evaluate
            if (hash_mode)
                begin_settle(); // NOT an immediate hash: an overflow flood must not cost one each
            else
                eval_exists();
        } else if (!issue_p_read(*pio)) {
            // Reissue on the retained handle failed: again a previously-working watch degrading,
            // not a fresh open (finding 4) — one bounded degraded re-arm, no spin.
            arm_retry = true;
        }
    };

    spdlog::info("Guardian FileGuard[{}]: watching {} ({}) [resilient]", log_id_token(cfg_.rule_id),
                 log_key_token(cfg_.path),
                 hash_mode ? "hash-equals"
                           : (cfg_.expect_present ? "expect present" : "expect absent"));
    arm_watch();
    eval_now(); // initial compare (hash: baseline-on-arm or compare to expected)

    while (!stop_.load(std::memory_order_acquire)) {
        HANDLE handles[5];
        DWORD n = 0;
        const DWORD idx_dir = read_pending ? n : 0xFFFFFFFF;
        if (idx_dir != 0xFFFFFFFF)
            handles[n++] = dir_event.get();
        const DWORD idx_anc = ancestor_event ? n : 0xFFFFFFFF;
        if (idx_anc != 0xFFFFFFFF)
            handles[n++] = ancestor_event.get();
        const DWORD idx_p = (pio && pio->pending) ? n : 0xFFFFFFFF;
        if (idx_p != 0xFFFFFFFF)
            handles[n++] = pio->ev.get();
        // Lost-edge backstop for the disabled-parent-watch health report (see
        // on_parent_disabled): only live once P has been permanently disabled AND a
        // timer was successfully armed. Its own wait-set branch, below — never
        // touches the timeout/deadline computation for settle/arm_retry.
        const DWORD idx_refresh = p_refresh_timer ? n : 0xFFFFFFFF;
        if (idx_refresh != 0xFFFFFFFF)
            handles[n++] = p_refresh_timer.get();
        const DWORD idx_stop = n;
        handles[n++] = static_cast<HANDLE>(stop_event_);

        // Timeout selection (no busy-poll): a settling hash change uses the settle
        // window, but bounded by max_settle_defer so a continuous write storm cannot
        // starve the hash forever (UP-1); a failed-to-arm watch uses a degraded retry;
        // otherwise block on OS events.
        DWORD timeout = INFINITE;
        if (hash_mode && hash_pending) {
            const auto deferred = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now() - settle_first)
                                      .count();
            const std::uint64_t cap_left =
                deferred >= static_cast<long long>(cfg_.max_settle_defer_ms)
                    ? 0
                    : cfg_.max_settle_defer_ms - static_cast<std::uint64_t>(deferred);
            timeout = static_cast<DWORD>(std::min<std::uint64_t>(cfg_.settle_ms, cap_left));
        } else if (arm_retry) {
            // An absolute deadline, not a fresh kArmFailRetryMs every pass: unrelated activity while
            // still degraded (a D/P wake that does not clear arm_retry) must not keep pushing the
            // real retry back. A deadline already in the past (the retry attempt it triggered ran and
            // is still degraded) starts a fresh window rather than spinning at timeout=0.
            const auto now = std::chrono::steady_clock::now();
            if (!retry_at || *retry_at <= now)
                retry_at = now + std::chrono::milliseconds(kArmFailRetryMs);
            timeout = static_cast<DWORD>(
                std::chrono::duration_cast<std::chrono::milliseconds>(*retry_at - now).count());
        } else {
            retry_at.reset(); // not degraded: no deadline to track
        }

        const DWORD r = WaitForMultipleObjects(n, handles, FALSE, timeout);
        if (r == WAIT_OBJECT_0 + idx_stop)
            break;
        if (r == WAIT_TIMEOUT) {
            if (hash_mode && hash_pending) {
                // Settle quiesced (or the max-defer cap fired) → re-resolve the watch first
                // (handles a parent deleted during the write), then hash — matching every
                // other arm-before-eval call site in this file.
                hash_pending = false;
                arm_watch();
                eval_hash();
            } else if (arm_retry) {
                arm_watch(); // degraded re-arm
                eval_now();
            }
            continue;
        }
        if (idx_dir != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_dir) {
            DWORD bytes = 0;
            const BOOL got = GetOverlappedResult(h_dir.get(), &ov, &bytes, FALSE);
            if (got == FALSE && GetLastError() == ERROR_IO_INCOMPLETE)
                continue; // spurious signal: the read is still in flight
            read_pending = false;
            // On a GetOverlappedResult failure we can't trust the buffer → reconcile.
            const bool ours = (got == FALSE) || change_is_ours(notify_buf, bytes, fname);
            if (!ours) {
                // Fast path: a reissue on the same handle needs no eval at all (not our
                // filename, watch still armed). Only the rebuild sub-branch evaluates — an
                // unconditional eval here would turn every "not our filename" completion in a
                // busy sibling-heavy directory into a full rebuild+eval, reintroducing the
                // noise the header's network-kindness NFR exists to avoid.
                if (!arm_dir_read()) {
                    arm_watch(); // re-arm failed (dir gone) → rebuild
                    if (hash_mode)
                        begin_settle();
                    else
                        eval_exists();
                }
            } else if (hash_mode) {
                // Defer the (expensive, mid-write-prone) hash to the settle timeout;
                // keep the read armed and (re)start the bounded settle countdown.
                if (!arm_dir_read())
                    arm_watch();
                begin_settle();
            } else {
                arm_watch(); // existence: re-resolve + evaluate now
                eval_exists();
            }
            // D is always the lowest-indexed handle, so sustained D activity must not starve an
            // already-signalled P completion until a later wait call: check it non-blockingly now.
            // pio->pending (not the idx_p computed at loop entry) is read here: the D branch above
            // may itself have re-armed or reset P, and only a currently live read is safe to check.
            if (pio && pio->pending && WaitForSingleObject(pio->ev.get(), 0) == WAIT_OBJECT_0)
                handle_p_wake();
        } else if (idx_anc != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_anc) {
            arm_watch();
            if (hash_mode)
                begin_settle(); // settle, then hash the (re)created file
            else
                eval_exists();
        } else if (idx_p != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_p) {
            handle_p_wake();
        } else if (idx_refresh != 0xFFFFFFFF && r == WAIT_OBJECT_0 + idx_refresh) {
            // Lost-edge backstop tick: re-send, no re-arm, no filesystem access. idx_stop is
            // always the highest index (see handles[] population above), so a stop() racing a
            // coincident timer tick can have WaitForMultipleObjects report THIS (lower) index
            // even though a stop was also signalled — check stop_ explicitly rather than issue
            // one more (potentially blocking) send on the way out.
            if (!stop_.load(std::memory_order_acquire))
                report_parent_unhealthy();
        } else {
            spdlog::error("Guardian FileGuard[{}]: WaitForMultipleObjects failed (r={}, err={}) — "
                          "watch stopping",
                          log_id_token(cfg_.rule_id), r, GetLastError());
            break; // WAIT_FAILED / WAIT_ABANDONED — unrecoverable
        }
    }
    // RAII: dir_event / h_dir / ancestor_event released by their destructors; pio's destructor
    // invokes ParentIoRelease, which drains-or-abandons any in-flight P read (sec-1) as part of
    // that same release.
} catch (const std::exception& e) {
    spdlog::error("Guardian FileGuard[{}]: watch thread exception: {} — watch stopping",
                  log_id_token(cfg_.rule_id), e.what());
} catch (...) {
    spdlog::error("Guardian FileGuard[{}]: watch thread unknown exception — watch stopping",
                  log_id_token(cfg_.rule_id));
}

} // namespace yuzu::agent

#else // !_WIN32

namespace yuzu::agent {

FileGuard::FileGuard(Config cfg, GuardSink sink) : cfg_(std::move(cfg)), sink_(std::move(sink)) {}
FileGuard::~FileGuard() = default;
bool FileGuard::start() { return false; } // file-change Spark is Windows-only for the MVP
void FileGuard::stop() {}
void FileGuard::run() {}

} // namespace yuzu::agent

#endif // _WIN32
