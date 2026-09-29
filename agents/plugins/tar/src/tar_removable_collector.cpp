/**
 * tar_removable_collector.cpp — the `removable` cursor-model TAR source
 * (tar_cursor.hpp): hybrid snapshot + per-channel event-log backfill capture
 * of removable-media attach/detach, plus exec-from-removable correlation.
 * Implements make_removable_cursor_source() against the FROZEN wave-1 seam.
 *
 * ONE translation unit carries every platform (P-006/P-014: no compiling-out
 * a whole platform's leg into a file nothing loads) — Windows and Linux legs
 * live here behind `#if defined(_WIN32)` / `#if defined(__linux__)`; the
 * macOS leg is a thin driver over RemovableDiskArbSession
 * (tar_removable_diskarb.mm — the only place DiskArbitration/CoreFoundation
 * symbols appear). All raw-XML/sysfs/DA-description parsing is delegated to
 * the pure functions in tar_removable_parsers.hpp; this file's own job is
 * OS I/O, cursor-state orchestration, and the RemovableEvent shape.
 *
 * Every platform leg shares three review-driven correctness contracts (fix
 * round, 2026-09-04):
 *  - a per-tick RECONCILIATION diff between the live/backfilled device state
 *    and the persisted attach_set, so a missed OS callback/event never
 *    permanently desyncs the two (R-001);
 *  - transient per-tick state (a pending re-enable gap, an overflow-drop
 *    delta) is only cleared/advanced AFTER the DB commit that reports it
 *    succeeds, so a failed commit's retry on the next tick re-derives and
 *    re-reports it rather than silently losing it (R-002/R-003/R-004);
 *  - a persisted cursor that fails to parse, or (Windows) a channel that
 *    wrapped, is reported via CursorOutcome::CursorLost + a capture_gap
 *    event exactly as tar_cursor.hpp rule 2 specifies — never silently
 *    folded into an ordinary Baseline/Advanced tick (R-005).
 *
 * WINDOWS bindings are MEASURED (the-rig, 2026-09-04 — see runDir/fixtures/
 * README.md), and deliberately override the original roadmap row:
 * Microsoft-Windows-DriverFrameworks-UserMode/Operational is NOT read
 * (measured IsEnabled=False — an implementation on it ships green and
 * captures nothing forever). The three LIVE channels are
 * Partition/Diagnostic (identity authority — attach AND detach share
 * EventID 1006, told apart only by payload collapse), Kernel-PnP/
 * Configuration and Storsvc/Diagnostic (corroboration — cursor tracked,
 * no RemovableEvent rows of their own). setupapi.dev.log is OUT (follow-up
 * noted in docs/user-manual/tar-removable.md).
 */

#include "tar_removable_parsers.hpp"

#include "tar_capture_status.hpp" // IncompleteCaptureError
#include "tar_cursor.hpp"
#include "tar_db.hpp"
#include "tar_module_stream.hpp" // redact_module_dir -- shared sanitiser, tar_cursor.hpp rule 4b

#include <yuzu/agent/process_enum.hpp>
#include <yuzu/agent/scoped_fd.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winevt.h>
#include <winioctl.h>
#include <win_str.hpp> // yuzu::win wide<->UTF-8 helpers (#1681)

#include "tar_win_raii_guards.hpp" // yuzu::tar::win_raii::ScopedWinHandle

#include <cstring> // std::memchr — R-017 bounds-checked descriptor string reads

#pragma comment(lib, "wevtapi.lib") // EvtQuery / EvtNext / EvtRender / EvtClose

#elif defined(__linux__)

#include <cerrno>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <linux/netlink.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

#endif

namespace yuzu::tar {

namespace {

std::int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch())
       .count();
}

// R-008: macOS/Linux live-event record_keys are minted as
// "<prefix>:<device_key>:<seq>" from a PROCESS-LOCAL counter. Seeding that
// counter at 0 on every construction means the first live event after any
// two separate agent starts mints the IDENTICAL record_key for the same
// device — the second (legitimate, different) event is silently swallowed
// by the DB's unique-index replay-idempotence guard (tar_cursor.hpp rule 3),
// which exists to protect against RE-emission of the SAME event, not to
// deduplicate two genuinely different ones. Seeding from a nanosecond wall
// clock reading instead makes every agent start's counter begin at a value
// no other start (barring an astronomically unlikely same-nanosecond
// collision) will ever reach, while still incrementing by exactly 1 per
// event within one run — no persisted state, no new dependency, matching
// the "collision-resistant per-start identity" the finding asks for.
std::uint64_t seed_process_local_seq() {
    return static_cast<std::uint64_t>(
       std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

// Linux and Windows only: the macOS leg drives decide_baseline_and_reconcile()
// (tar_removable_parsers.hpp), which already does exactly this via its
// begin_session/forget_execs lambdas — guarded out here so it is not also
// compiled, and warned-as-unused, on the platform that never calls it.
#if defined(__linux__) || defined(_WIN32)

// Begin (or continue) `key`'s attach session: attach_epoch stamps the FIRST
// tick a device is seen, so exec_from_removable can mint a stable
// "exec:<device_key>:<epoch>:<image>" record_key for it (K1); a device
// already tracked keeps its existing epoch so the key stays stable while it
// remains plugged (try_emplace is a no-op when the key already exists).
//
// PR #4023 review blocker: decide_baseline_and_reconcile() already does
// exactly this (its `begin_session` lambda), but only the macOS leg drives
// that function. The Linux and Windows legs do their own inline attach_set
// bookkeeping and never wrote attach_epoch through any path — confirmed by
// grepping every attach_epoch reference in this file and
// tar_removable_parsers.hpp before this fix — so append_exec_from_removable's
// `st.attach_epoch.find(m.device_key)` always missed on those two platforms
// and exec_from_removable was silently dead code on both. Reproduced on real
// Windows hardware: a process launched from an attached, still-mounted stick
// produced zero exec_from_removable rows across two consecutive collect()
// calls.
//
// Mirroring the bookkeeping at each Linux/Windows attach_set mutation site
// (rather than restructuring either leg to route through
// decide_baseline_and_reconcile(), which assumes a live-callback +
// current-keys shape neither leg's poll/backfill architecture has) is the fix
// the review's own falsifier names as acceptable: "or otherwise populate
// attach_epoch on attach for those legs."
void begin_attach_session(RemovableCursorState& st, const std::string& key) {
    st.attach_epoch.try_emplace(key, now_seconds());
}

// End `key`'s attach session: the session ends with the device (K1), so its
// recorded executions must be forgotten too — matching
// decide_baseline_and_reconcile()'s `forget_execs` lambda exactly — or a
// replug-and-rerun of the SAME binary is silently never reported again (a
// stale exec_seen entry surviving with no corresponding attach_epoch).
void end_attach_session(RemovableCursorState& st, const std::string& key) {
    st.attach_epoch.erase(key);
    const std::string prefix = key + "\x1f";
    for (auto it = st.exec_seen.begin(); it != st.exec_seen.end();)
        it = it->starts_with(prefix) ? st.exec_seen.erase(it) : std::next(it);
}

#endif // defined(__linux__) || defined(_WIN32)

} // namespace

#if defined(__linux__)
namespace {

// R-019: the netlink uevent socket is owned across the source's whole
// lifetime (a class member, not a function-local), so a bare `int` with a
// matching ::close() in stop() only protects the NORMAL path -- an exception
// thrown between open and the next stop() would leak the fd. The owner is
// `yuzu::agent::ScopedFd` (agents/core/include/yuzu/agent/scoped_fd.hpp), the
// shared primitive, NOT a local copy: an earlier revision hand-rolled one here
// whose reset() lacked the shared type's self-reset guard, which is exactly
// the kind of silent divergence a second copy of an ownership primitive
// produces.
using yuzu::agent::ScopedFd;

} // namespace
#endif

/// The full CursorSource lifecycle for the `removable` source. Owns:
///  - a BoundedPendingQueue for the two subscription legs (macOS DA
///    callbacks, Linux netlink reads) so ack-after-commit (P-003) is uniform
///    across both;
///  - a monotonic sequence counter for record_keys the live legs mint
///    themselves (attach/detach/exec are not, unlike Windows backfill,
///    keyed by an OS-provided sequence number);
///  - the enable/disable-window bookkeeping (forensic-pause parity,
///    tar_cursor.hpp's on_enabled_changed contract).
class RemovableCursorSource : public CursorSource {
public:
    [[nodiscard]] std::string name() const noexcept override { return "removable"; }

    void start(TarDatabase& db) override;
    CursorCollectResult collect(TarDatabase& db,
                               const std::optional<std::string>& cursor_json) override;
    void stop() noexcept override;
    void on_enabled_changed(bool enabled) override;

private:
    BoundedPendingQueue<RemovableEvent> queue_;
    std::atomic<std::uint64_t> seq_{seed_process_local_seq()};
    bool was_disabled_{false};
    // Both unobservable windows a live leg can owe: a configured pause, and the
    // agent simply not running. They are reported the same way -- one gap,
    // emitted once, cleared only after the commit succeeds -- but an analyst
    // must be able to tell them apart, so the evidence text names which it was.
    enum class GapCause { Disabled, Restart };

    bool pending_reenable_gap_{false};
    // Which window the pending gap describes -- set beside the flag.
    GapCause pending_gap_cause_{GapCause::Disabled};
    // R-002: serializes on_enabled_changed against the macOS DA callback,
    // which runs on DiskArbitration's own dispatch-queue thread — entirely
    // independent of whatever thread calls on_enabled_changed. Holding the
    // SAME mutex on both sides means a callback either completes its push
    // entirely before a disable's discard_all() runs (and is then removed by
    // it) or observes capturing_enabled_==false and returns before pushing
    // at all — no window where a paused-window event survives both checks.
    std::mutex disable_mu_;
    std::atomic<bool> capturing_enabled_{true};
    // R-004: how much of queue_.dropped()'s cumulative overflow count has
    // already been reported as a capture_gap. Advanced only after the tick
    // that reported the delta actually commits (mirrors pending_reenable_gap_
    // — see R-003), so a failed commit's delta is re-derived and re-reported
    // next tick instead of being silently absorbed.
    std::size_t last_reported_dropped_{0};
#if defined(__linux__)
    // C8: kernel-side loss, reported on the same commit-gated cadence as the
    // userspace queue overflow -- counted here, advanced only after commit.
    std::size_t netlink_dropped_bursts_{0};
    std::size_t netlink_recv_errors_{0};
    std::size_t last_reported_netlink_bursts_{0};
    std::size_t last_reported_netlink_errors_{0};
#endif

    std::string next_seq_record_key(std::string_view prefix, std::string_view device_key) {
        return std::string(prefix) + ":" + std::string(device_key) + ":" +
              std::to_string(seq_.fetch_add(1, std::memory_order_relaxed));
    }

    // Runs process_enum.hpp and emits exec_from_removable for every
    // currently-running process whose ProcessInfo::exec_path (P-004 — NEVER
    // cmdline) resolves under one of `attached_roots`. Shared across every
    // platform leg. The actual matching DECISION -- including the
    // exec_path-not-cmdline FIELD SELECTION itself -- lives in the pure
    // select_exec_from_removable_processes (tar_removable_parsers.hpp,
    // R-013 fix round) — kept out of this method so BOTH the matching
    // decision and the field-selection line are testable without a live
    // process_enum() call; this method's only remaining job is calling
    // enumerate_processes() and picking the platform's path-comparison
    // case-sensitivity (R-016).
    // `st` is the tick's working cursor state: `exec_seen` gates the emission
    // so each (device_key, image_path) is reported ONCE per attach session
    // (K1), and the same set is what makes the stable exec record_key safe.
    // Only a committed tick persists `st`, so a failed commit re-derives and
    // re-reports rather than losing the observation.
    void append_exec_from_removable(
       std::vector<RemovableEvent>& out, RemovableCursorState& st,
       const std::vector<std::pair<std::string, std::string>>& attached_roots) const {
        if (attached_roots.empty())
            return;
#if defined(_WIN32) || defined(__APPLE__)
        constexpr bool kCaseInsensitivePaths = true; // NTFS / APFS default mode
#else
        constexpr bool kCaseInsensitivePaths = false; // ext4 et al.
#endif
        const auto procs = yuzu::agent::enumerate_processes();
        for (auto& m : select_exec_from_removable_processes(procs, attached_roots,
                                                            kCaseInsensitivePaths)) {
            // tar_cursor.hpp rule 4b (PR #4023 review round 2, blocker #4):
            // a removable-media exec path can carry a username
            // (`/media/<user>/...`, `/run/media/<user>/...`,
            // `/Volumes/<name>/...`) and this table is default-ON and
            // works-council-class, so it goes through the same sanitiser the
            // module stream uses -- redacted ONCE, here, before it touches
            // the event, the durable exec_seen dedupe key, or the record_key,
            // so nothing downstream ever sees the raw path. Redaction is a
            // pure function of the input, so a retry re-derives the identical
            // redacted string -- the DB's replay-dedupe (tar_db.cpp) stays
            // self-consistent across commits.
            const std::string redacted_image_path = redact_module_dir(m.image_path);
            RemovableEvent ev;
            ev.ts = now_seconds();
            ev.action = "exec_from_removable";
            ev.device_key = m.device_key;
            ev.image_path = redacted_image_path;
            ev.pid = m.pid;
            ev.evidence = "process_enum:exec_path";
            const auto ep = st.attach_epoch.find(m.device_key);
            if (ep == st.attach_epoch.end())
                continue; // not in a known attach session -- no honest key to mint
            ev.record_key =
               removable_exec_record_key(m.device_key, ep->second, redacted_image_path);
            const std::string seen_key = m.device_key + "\x1f" + redacted_image_path;
            if (!st.exec_seen.insert(seen_key).second)
                continue; // already reported for this attach session
            out.push_back(std::move(ev));
        }
    }

    RemovableEvent make_reenable_gap_event(GapCause cause = GapCause::Disabled) {
        RemovableEvent ev;
        ev.ts = now_seconds();
        ev.action = "capture_gap";
        ev.evidence =
           cause == GapCause::Restart
              ? "removable source resumed after the agent was not running; this leg is "
                "live-only (no OS history API), so attach/detach activity during that "
                "window was never captured and cannot be backfilled"
              : "removable source re-enabled after a disabled window; the disabled "
                "window's own attach/detach activity was never captured (P-002 "
                "forensic-pause contract)";
        ev.record_key = next_seq_record_key(
           cause == GapCause::Restart ? "restart_gap" : "reenable_gap", "removable");
        return ev;
    }

    // R-005: tar_cursor.hpp rule 2 names "the cursor JSON fails to parse" as
    // an explicit CursorLost case, on equal footing with a wrapped log —
    // decode_removable_cursor's malformed=true is exactly that case.
    RemovableEvent make_cursor_lost_gap_event() {
        RemovableEvent ev;
        ev.ts = now_seconds();
        ev.action = "capture_gap";
        ev.evidence = "removable source's persisted cursor failed to parse; re-baselined at "
                     "the current state (tar_cursor.hpp rule 2 CursorLost)";
        ev.record_key = next_seq_record_key("cursor_lost_gap", "removable");
        return ev;
    }

    // R-004: one queue-overflow capture_gap naming the cumulative dropped
    // delta since the last one that actually committed.
    RemovableEvent make_overflow_gap_event(std::size_t dropped_delta) {
        RemovableEvent ev;
        ev.ts = now_seconds();
        ev.action = "capture_gap";
        ev.evidence =
           std::format("removable capture queue overflowed — {} event(s) evicted before they "
                      "could be committed (P-003 bounded-queue overflow, cumulative dropped)",
                      dropped_delta);
        ev.record_key = next_seq_record_key("overflow_gap", "removable");
        return ev;
    }

    // C8: the kernel-side twin of the queue overflow above. A netlink socket
    // whose receive buffer fills DROPS uevents and reports ENOBUFS -- the
    // kernel's view and ours have diverged, and a device that attached and
    // detached inside the lost burst is gone: the /sys/block reconciliation
    // repairs final STATE, so it recovers a device still present, but it can
    // never see one that came and went.
    RemovableEvent make_netlink_loss_gap_event(std::size_t dropped_bursts,
                                               std::size_t recv_errors) {
        RemovableEvent ev;
        ev.ts = now_seconds();
        ev.action = "capture_gap";
        ev.evidence = std::format(
           "removable netlink receive lost messages — {} ENOBUFS drop(s) and {} receive "
           "error(s) since the last report; uevents dropped by the kernel socket buffer are "
           "unrecoverable, so a device that attached and detached within that window left no "
           "row (per-tick /sys/block reconciliation recovers only devices still attached)",
           dropped_bursts, recv_errors);
        ev.record_key = next_seq_record_key("netlink_loss_gap", "removable");
        return ev;
    }

#if defined(__APPLE__)
    std::unique_ptr<RemovableDiskArbSession> da_session_;
    // Guarded by disable_mu_, which the DA callback already takes.
    std::set<std::string> replay_suppress_;
#endif

#if defined(__linux__)
    ScopedFd netlink_fd_;
    // devname -> device_key, populated from BOTH the live netlink drain and
    // the per-tick /sys/block reconciliation scan (R-001) so a later
    // "remove" (whose /sys/block/<dev> entry is already gone) can still be
    // reported with the identity captured while the device was live.
    std::unordered_map<std::string, std::string> linux_known_devices_;
    // (device_key, mount_root) pairs — a vector, not a map, because one
    // device can be mounted at more than one point (R-015); collapsing to a
    // single value per device_key silently drops exec-from-removable
    // coverage for every mount past the first.
    std::vector<std::pair<std::string, std::string>> linux_device_roots_;
#endif
};

// ═══════════════════════════════════════════════════════════════════════
// macOS leg
// ═══════════════════════════════════════════════════════════════════════
#if defined(__APPLE__)

namespace {

std::string macos_platform_instance_id(const RemovableDiskArbEvent& ev) {
    return !ev.media_uuid.empty() ? ev.media_uuid : ev.bsd_name;
}

} // namespace

// C5/K2: the live legs cannot observe anything while the agent process is
// stopped, and a restart is otherwise indistinguishable from an ordinary tick
// -- the persisted cursor carries baseline_done=true, so the first collect
// reports Advanced. Worse, the reconcile step then attributes whatever changed
// during the downtime to "missed-appeared/disappeared-callback", which is
// fabricated evidence: no callback was missed, the process was not running.
// docs/user-manual/tar-removable.md promises a capture_gap for exactly this
// window. So: if a cursor was already persisted, this process did not write
// it, and the window between it and now is unobservable. Arm the same
// pending-gap machinery the re-enable path uses -- it is emitted exactly once
// and cleared only after the commit succeeds. Windows needs none of this: its
// event log retains records written while the agent was down, so that leg has
// real history to replay rather than a hole to declare.
void RemovableCursorSource::start(TarDatabase& db) {
    if (da_session_)
        return; // P-002: start() must be idempotent
    if (auto existing = db.get_cursor("removable"); existing && existing->has_value()) {
        pending_reenable_gap_ = true;
        pending_gap_cause_ = GapCause::Restart;
        // REGISTRATION REPLAY SUPPRESSION.
        //
        // DARegisterDiskAppearedCallback does not only report FUTURE arrivals:
        // it immediately replays an appeared callback for every matching disk
        // already present. Measured on this host, registering with no hardware
        // change at all delivered 22 of them. The callback stamps ts = now, so
        // without this every agent restart writes a fresh `attached` row, dated
        // at restart, for a stick that has been plugged in for days -- a
        // fabricated arrival in a forensic table, on every restart.
        //
        // The callback cannot read the database (rule 6: it runs on DA's
        // dispatch queue), so the set of already-known devices is loaded HERE,
        // once, from the cursor we have just read. A key is dropped from the
        // set the first time it suppresses, so a genuine detach-and-reattach
        // later in the same process is still reported.
        const auto st = decode_removable_cursor(**existing);
        std::lock_guard lock(disable_mu_);
        for (const auto& [key, present] : st.attach_set)
            if (present)
                replay_suppress_.insert(key);
    }
    da_session_ = std::make_unique<RemovableDiskArbSession>();
    da_session_->start([this](RemovableDiskArbEvent ev) {
        // Runs on the DA private dispatch queue — must not block or touch
        // the DB (rule 6). Reduce to a RemovableEvent and push; collect()
        // drains and acks after commit.
        std::lock_guard lock(disable_mu_); // R-002 — see disable_mu_'s doc comment
        if (!capturing_enabled_.load(std::memory_order_acquire))
            return; // paused window (P-002 forensic-pause) — never queue it
        RemovableEvent re;
        re.ts = now_seconds();
        re.action = ev.action; // "attached" | "detached"
        re.vendor = ev.vendor;
        re.product = ev.product;
        re.volume = ev.volume_path;
        re.size_bytes = ev.size_bytes;
        const std::string instance_id = macos_platform_instance_id(ev);
        // macOS never has a USB serial in the DA description dictionary —
        // always the platform-instance fallback (P-011).
        const auto key = compute_device_key(ev.vendor, ev.product, std::string_view{}, instance_id);
        re.device_key = key.device_key;
        re.bus = "diskarb";
        re.evidence = "macos:diskarbitration:" + std::string(ev.bsd_name) +
                     ":anonymous-serial-fallback";
        // Registration replay: this device was already in the persisted
        // attach_set, so DA is telling us about an arrival we already know
        // about, not a new one.
        if (re.action == "attached") {
            const auto it = replay_suppress_.find(re.device_key);
            if (it != replay_suppress_.end()) {
                replay_suppress_.erase(it); // once only -- a real re-attach still reports
                return;
            }
        }
        re.record_key = next_seq_record_key("diskarb", re.device_key);
        queue_.push(std::move(re));
    });
}

void RemovableCursorSource::stop() noexcept {
    if (da_session_)
        da_session_->stop();
    queue_.discard_all(); // R-002: nothing owned survives stop() — see tar_cursor.hpp's contract
}

CursorCollectResult RemovableCursorSource::collect(TarDatabase& db,
                                                   const std::optional<std::string>& cursor_json) {
    RemovableCursorState st = decode_removable_cursor(cursor_json);
    std::vector<RemovableEvent> events;

    // R-005: a persisted-but-unparseable cursor is CursorLost, never a
    // silently-fresh Baseline.
    const bool cursor_was_lost = st.malformed;
    if (cursor_was_lost)
        events.push_back(make_cursor_lost_gap_event());

    const bool reenable_gap_pending = pending_reenable_gap_;
    if (reenable_gap_pending)
        events.push_back(make_reenable_gap_event(pending_gap_cause_));

    if (!da_session_)
        throw IncompleteCaptureError("TAR removable: macOS DiskArbitration session not started");

    // The attach_set as it stood BEFORE this tick's mutations — the baseline
    // both R-003's retry-safe replay and R-001's reconciliation diff below
    // need, since the loop below is about to start changing st.attach_set.
    const std::unordered_map<std::string, bool> prev_attach_set(st.attach_set.begin(),
                                                                 st.attach_set.end());
    const bool baseline_already_done = st.baseline_done;

    // Live-only leg (no history API) — snapshot_attached() is both the
    // baseline source AND the per-tick "what's live now" source for
    // exec-from-removable root correlation AND (R-001) the reconciliation
    // source that recovers from a DA callback that was never delivered.
    const auto snapshot = da_session_->snapshot_attached();
    if (!snapshot) {
        // C6: rule 1. The snapshot is BOTH the exec-root correlation source and
        // the reconciliation source, so a failed one is a failed tick -- not an
        // empty device set. Diffing an empty set against the persisted
        // attach_set would commit a detach for every device and clear the
        // durable state, and the next healthy scan would commit a false
        // re-attach for each. Throwing retains the cursor untouched.
        throw IncompleteCaptureError(
           "TAR removable: macOS getfsstat/DiskArbitration snapshot failed -- retaining cursor");
    }
    const auto& attached_now = *snapshot;
    std::vector<std::pair<std::string, std::string>> attached_roots;
    std::unordered_set<std::string> current_keys;
    std::unordered_map<std::string, const RemovableDiskArbEvent*> seen_by_key;
    attached_roots.reserve(attached_now.size());
    current_keys.reserve(attached_now.size());
    for (const auto& ev : attached_now) {
        const auto key =
           compute_device_key(ev.vendor, ev.product, std::string_view{}, macos_platform_instance_id(ev));
        if (!ev.volume_path.empty())
            attached_roots.emplace_back(key.device_key, ev.volume_path);
        current_keys.insert(key.device_key);

        // Device metadata for whichever keys the decision below names.
        seen_by_key.emplace(key.device_key, &ev);
    }
    st.baseline_done = true;

    // Identity-based ack (R-005): ack_through removes only entries with
    // sequence <= the snapshot's last_seq, so an overflow eviction between
    // snapshot and ack can never mis-target an unacked entry.
    const auto batch = queue_.snapshot_batch();
    const auto& pending = batch.items;

    // The baseline seeding, the retained-queue replay (R-003) and the R-001
    // reconciliation are ONE decision over the same attach_set, and it is pure
    // -- decide_baseline_and_reconcile() in tar_removable_parsers.hpp owns it
    // so the unit suites can drive it without a DiskArbitration session. This
    // leg supplies only the OS reads and the device metadata.
    BaselineReconcileInputs bri;
    bri.baseline_already_done = baseline_already_done;
    bri.current_keys = current_keys;
    bri.prev_attach_set = prev_attach_set;
    bri.exec_seen = st.exec_seen;
    bri.attach_epoch = st.attach_epoch;
    bri.now = now_seconds();
    bri.pending.reserve(pending.size());
    for (const auto& ev : pending)
        bri.pending.emplace_back(ev.action, ev.device_key);
    const auto decided = decide_baseline_and_reconcile(bri);
    st.attach_set.clear();
    st.attach_set.insert(decided.attach_set.begin(), decided.attach_set.end());
    st.exec_seen = decided.exec_seen;
    st.attach_epoch = decided.attach_epoch;

    for (const auto& key : decided.baseline_keys) {
        const auto it = seen_by_key.find(key);
        if (it == seen_by_key.end())
            continue;
        const auto& ev = *it->second;
        RemovableEvent re;
        re.ts = now_seconds();
        re.action = "present_at_baseline";
        re.device_key = key;
        re.vendor = ev.vendor;
        re.product = ev.product;
        re.volume = ev.volume_path;
        re.size_bytes = ev.size_bytes;
        re.bus = "diskarb";
        re.evidence = "macos:getfsstat+diskarbitration:baseline:anonymous-serial-fallback";
        re.record_key = removable_baseline_record_key(key);
        events.push_back(std::move(re));
    }

    events.insert(events.end(), pending.begin(), pending.end());

    for (const auto& key : decided.reconcile_added) {
        RemovableEvent re;
        re.ts = now_seconds();
        re.action = "attached";
        re.device_key = key;
        re.bus = "diskarb";
        re.evidence = "macos:diskarbitration:reconcile:missed-appeared-callback";
        re.record_key = next_seq_record_key("reconcile_add", key);
        events.push_back(std::move(re));
    }
    for (const auto& key : decided.reconcile_removed) {
        RemovableEvent re;
        re.ts = now_seconds();
        re.action = "detached";
        re.device_key = key;
        re.bus = "diskarb";
        re.evidence = "macos:diskarbitration:reconcile:missed-disappeared-callback";
        re.record_key = next_seq_record_key("reconcile_rm", key);
        events.push_back(std::move(re));
    }

    append_exec_from_removable(events, st, attached_roots);

    // R-004: overflow-drop delta, reported (not yet advanced — see below).
    const auto dropped_now = queue_.dropped();
    const auto dropped_delta = dropped_now > last_reported_dropped_
                                  ? dropped_now - last_reported_dropped_
                                  : std::size_t{0};
    if (dropped_delta > 0)
        events.push_back(make_overflow_gap_event(dropped_delta));

    CursorCollectResult result;
    result.new_cursor_json = encode_removable_cursor(st);
    result.events_emitted = events.size();
    result.outcome = (cursor_was_lost || reenable_gap_pending)
                        ? CursorOutcome::CursorLost
                        : (cursor_json.has_value() ? CursorOutcome::Advanced : CursorOutcome::Baseline);

    if (auto ins = db.insert_removable_events_and_cursor(events, result.new_cursor_json); !ins) {
        // A KeyCollision is PERMANENT (tar_db.hpp): this source re-derives the
        // same batch every tick and the store refuses it every tick, so retrying
        // is a silent stall, not recovery. It also means rule 3(a) was violated
        // -- a persisted field is not deterministically re-derivable -- which is
        // a bug here rather than a condition to wait out.
        if (ins.error() == TarDatabase::CursorInsertError::KeyCollision)
            spdlog::critical("TAR removable: record_key COLLISION on the macOS leg -- a persisted "
                             "field is not deterministically re-derivable (rule 3a). Capture is "
                             "STUCK and retrying cannot clear it.");
        throw IncompleteCaptureError("TAR removable: macOS event/cursor commit failed");
    }
    // Only clear/advance transient state AFTER the commit above succeeds
    // (R-003/R-004) — a thrown IncompleteCaptureError above never reaches
    // here, so a failed commit leaves pending_reenable_gap_ and
    // last_reported_dropped_ untouched for a correct retry next tick.
    queue_.ack_through(batch.last_seq);
    pending_reenable_gap_ = false;
    last_reported_dropped_ = dropped_now;
    return result;
}

void RemovableCursorSource::on_enabled_changed(bool enabled) {
    std::lock_guard lock(disable_mu_); // R-002 — serializes against the DA callback
    if (!enabled) {
        // Keep the DA session warm (ETW process-stream precedent,
        // tar_plugin.cpp:1157) — gate the callback via capturing_enabled_
        // FIRST so nothing new can be queued, then discard whatever it
        // already queued so nothing from the paused window is ever stored.
        capturing_enabled_.store(false, std::memory_order_release);
        queue_.discard_all();
        was_disabled_ = true;
    } else if (was_disabled_) {
        // Discard again before re-arming: anything that raced into the
        // queue between the disable-time discard above and now (e.g. a
        // callback that had already passed the capturing_enabled_ check on a
        // prior disable/enable cycle) must never survive re-enable either.
        queue_.discard_all();
        capturing_enabled_.store(true, std::memory_order_release);
        pending_reenable_gap_ = true;
        pending_gap_cause_ = GapCause::Disabled;
        was_disabled_ = false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Linux leg (CONSTRAINED)
// ═══════════════════════════════════════════════════════════════════════
#elif defined(__linux__)

namespace {

std::optional<std::string> read_sysfs_trimmed(const std::string& path) {
    std::ifstream f(path);
    if (!f)
        return std::nullopt;
    std::string line;
    std::getline(f, line);
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    return line;
}

struct SysfsBlockIdentity {
    std::string vendor, product, serial, instance_id;
    bool removable{false};
    std::int64_t size_bytes{0};
};

/// Best-effort /sys/block/<dev> read — CONSTRAINED per the spec (no wwid on
/// every controller, no serial on many USB mass-storage bridges). Absence of
/// any one field is not an error; it degrades identity, never throws.
SysfsBlockIdentity read_sysfs_block_identity(const std::string& devname) {
    SysfsBlockIdentity id;
    const std::string base = "/sys/block/" + devname;
    if (auto v = read_sysfs_trimmed(base + "/removable"))
        id.removable = (*v == "1");
    if (auto v = read_sysfs_trimmed(base + "/device/vendor"))
        id.vendor = *v;
    if (auto v = read_sysfs_trimmed(base + "/device/model"))
        id.product = *v;
    if (auto v = read_sysfs_trimmed(base + "/device/serial"))
        id.serial = *v;
    if (auto v = read_sysfs_trimmed(base + "/size")) {
        try {
            id.size_bytes = std::stoll(*v) * 512;
        } catch (...) {
        }
    }
    // Platform-stable instance id (P-011 fallback): the sysfs device symlink
    // target (stable per physical port/topology) plus wwid where present.
    char link_buf[1024]{};
    const ssize_t n =
       ::readlink((base + "/device").c_str(), link_buf, sizeof(link_buf) - 1);
    if (n > 0)
        id.instance_id.assign(link_buf, static_cast<std::size_t>(n));
    if (auto wwid = read_sysfs_trimmed(base + "/device/wwid"); wwid && !wwid->empty())
        id.instance_id += "|" + *wwid;
    if (id.instance_id.empty())
        id.instance_id = devname; // last resort — still stable within one boot
    return id;
}

int open_uevent_netlink_socket() {
    // Own the descriptor BEFORE the first decision that can leave this
    // function, so no exit path -- present or later added -- can leak it. The
    // caller takes it by release() only once bind() has succeeded.
    ScopedFd fd{::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                         NETLINK_KOBJECT_UEVENT)};
    if (!fd.valid()) {
        spdlog::warn("TAR removable: netlink socket() failed (errno {})", errno);
        return -1;
    }
    struct sockaddr_nl addr {};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = 0;
    addr.nl_groups = 1; // the kernel's single kobject-uevent multicast group
    if (::bind(fd.get(), reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        spdlog::warn("TAR removable: netlink bind() failed (errno {})", errno);
        return -1; // ScopedFd closes it
    }
    return fd.release();
}

/// R-019: RAII owner for a `DIR*` — a local raw opendir/closedir pair only
/// protects the normal exit path; an exception thrown mid-scan (e.g. a
/// std::string allocation) would leak the handle without this.
class ScopedDir {
public:
    explicit ScopedDir(DIR* d) noexcept : d_(d) {}
    ~ScopedDir() {
        if (d_ != nullptr)
            ::closedir(d_);
    }
    ScopedDir(const ScopedDir&) = delete;
    ScopedDir& operator=(const ScopedDir&) = delete;
    explicit operator bool() const noexcept { return d_ != nullptr; }
    [[nodiscard]] DIR* get() const noexcept { return d_; }

private:
    DIR* d_;
};

} // namespace

// C5/K2: the live legs cannot observe anything while the agent process is
// stopped, and a restart is otherwise indistinguishable from an ordinary tick
// -- the persisted cursor carries baseline_done=true, so the first collect
// reports Advanced. Worse, the reconcile step then attributes whatever changed
// during the downtime to "missed-appeared/disappeared-callback", which is
// fabricated evidence: no callback was missed, the process was not running.
// docs/user-manual/tar-removable.md promises a capture_gap for exactly this
// window. So: if a cursor was already persisted, this process did not write
// it, and the window between it and now is unobservable. Arm the same
// pending-gap machinery the re-enable path uses -- it is emitted exactly once
// and cleared only after the commit succeeds. Windows needs none of this: its
// event log retains records written while the agent was down, so that leg has
// real history to replay rather than a hole to declare.
void RemovableCursorSource::start(TarDatabase& db) {
    if (netlink_fd_.valid())
        return; // P-002: idempotent
    if (auto existing = db.get_cursor("removable"); existing && existing->has_value()) {
        pending_reenable_gap_ = true;
        pending_gap_cause_ = GapCause::Restart;
    }
    netlink_fd_.reset(open_uevent_netlink_socket());
}

void RemovableCursorSource::stop() noexcept {
    netlink_fd_.reset();
    linux_known_devices_.clear();
    linux_device_roots_.clear();
    queue_.discard_all(); // R-002: nothing owned survives stop()
}

CursorCollectResult RemovableCursorSource::collect(TarDatabase& db,
                                                   const std::optional<std::string>& cursor_json) {
    RemovableCursorState st = decode_removable_cursor(cursor_json);
    std::vector<RemovableEvent> events;

    // R-005: a persisted-but-unparseable cursor is CursorLost, never a
    // silently-fresh Baseline.
    const bool cursor_was_lost = st.malformed;
    if (cursor_was_lost)
        events.push_back(make_cursor_lost_gap_event());

    const bool reenable_gap_pending = pending_reenable_gap_;
    if (reenable_gap_pending)
        events.push_back(make_reenable_gap_event(pending_gap_cause_));

    // Drain the netlink socket non-blocking (spec: "drained non-blocking per
    // tick") — no persistent reader thread, so a batch read here IS the
    // subscription queue's producer side; push into queue_ so overflow/
    // ack-after-commit stays uniform with the macOS leg (P-003).
    if (netlink_fd_.valid()) {
        char buf[8192];
        for (;;) {
            const ssize_t n = ::recv(netlink_fd_.get(), buf, sizeof(buf), MSG_DONTWAIT);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break; // drained — the ordinary exit
            if (n <= 0) {
                // C8: NOT the same thing. A netlink socket whose receive buffer
                // fills DROPS messages and reports ENOBUFS; the kernel's view
                // and ours have diverged and the lost uevents are gone. The
                // per-tick /sys/block reconciliation repairs final STATE, so a
                // device still attached is recovered -- but a device that
                // attached and detached inside the lost burst is invisible to
                // it, which is precisely the evidence this source exists to
                // capture. Treating that as "nothing more pending" reported a
                // complete tick over known-incomplete data. Count it and let
                // the gap below report it, commit-gated like the userspace
                // queue overflow it is the kernel-side twin of.
                if (n < 0)
                    ++netlink_recv_errors_;
                if (n < 0 && errno == ENOBUFS)
                    ++netlink_dropped_bursts_;
                break;
            }
            const auto rec = parse_uevent_message(std::string_view(buf, static_cast<std::size_t>(n)));
            if (!rec || !is_block_disk_uevent(*rec))
                continue;
            const auto devname_it = rec->kv.find("DEVNAME");
            std::string devname = devname_it != rec->kv.end() ? devname_it->second : rec->devpath;
            const auto slash = devname.find_last_of('/');
            if (slash != std::string::npos)
                devname = devname.substr(slash + 1);

            RemovableEvent re;
            re.ts = now_seconds();
            re.bus = "block";
            if (rec->action == "add") {
                const auto id = read_sysfs_block_identity(devname);
                if (!id.removable)
                    continue; // R-009: never record a non-removable block device as removable media
                const auto key = compute_device_key(id.vendor, id.product, id.serial, id.instance_id);
                re.action = "attached";
                re.device_key = key.device_key;
                re.vendor = id.vendor;
                re.product = id.product;
                re.serial = key.used_serial ? id.serial : "";
                re.size_bytes = id.size_bytes;
                re.evidence = std::string("linux:netlink:add:/sys/block/") + devname +
                             (key.used_serial ? "" : ":anonymous-serial-fallback");
                linux_known_devices_[devname] = key.device_key;
                // NOTE: st.attach_set is intentionally NOT mutated here — it
                // is derived from the retained `pending` batch below (R-003)
                // so a retry after a failed commit replays this mutation
                // correctly instead of silently losing it.
            } else { // "remove"
                const auto known = linux_known_devices_.find(devname);
                if (known == linux_known_devices_.end())
                    continue; // R-009: never fabricate a detach for a device we never admitted
                re.action = "detached";
                re.device_key = known->second;
                re.evidence = "linux:netlink:remove:" + devname;
                linux_known_devices_.erase(known);
                linux_device_roots_.erase(
                   std::remove_if(linux_device_roots_.begin(), linux_device_roots_.end(),
                                  [&](const auto& p) { return p.first == re.device_key; }),
                   linux_device_roots_.end());
            }
            re.record_key = next_seq_record_key("udev", re.device_key);
            queue_.push(std::move(re));
        }
    }

    // Identity-based ack (R-005): ack_through removes only entries with
    // sequence <= the snapshot's last_seq, so an overflow eviction between
    // snapshot and ack can never mis-target an unacked entry.
    const auto batch = queue_.snapshot_batch();
    const auto& pending = batch.items;
    // R-003: derive attach_set mutations from the RETAINED snapshot so a
    // prior tick's failed commit replays correctly here too.
    for (const auto& ev : pending) {
        if (ev.action == "attached") {
            st.attach_set[ev.device_key] = true;
            begin_attach_session(st, ev.device_key); // PR #4023 review blocker
        } else if (ev.action == "detached") {
            st.attach_set.erase(ev.device_key);
            end_attach_session(st, ev.device_key); // PR #4023 review blocker
        }
    }
    events.insert(events.end(), pending.begin(), pending.end());

    // R-001 reconciliation: a fresh /sys/block scan every tick (not just the
    // very first) recovers from a lost netlink datagram the drain above
    // never saw. Runs AFTER the netlink drain and pending-batch application,
    // so a device this tick's netlink events already accounted for is
    // already in linux_known_devices_/st.attach_set and is never re-reported
    // here — only genuine drift (a device neither a live event nor a prior
    // tick ever recorded) triggers a recovery row. On the very first-ever
    // tick (baseline_done still false coming in), every currently-removable
    // device is by definition "new", so this loop doubles as the baseline
    // scan the previous round gated behind `if (!st.baseline_done)`.
    const bool baseline_already_done = st.baseline_done;
    std::unordered_map<std::string, std::string> current_scan; // devname -> device_key
    ScopedDir dir{::opendir("/sys/block")};
    if (!dir) {
        // C6: rule 1. An unopenable /sys/block is a FAILED scan, not an empty
        // one. Falling through with an empty current_scan makes the
        // reconciliation below emit `detached` for every known device and clear
        // the durable state, and the next healthy scan re-attaches them all --
        // fabricated evidence in both directions from one transient error.
        throw IncompleteCaptureError(
           "TAR removable: Linux /sys/block scan failed -- retaining cursor");
    }
    {
        while (struct dirent* entry = ::readdir(dir.get())) {
            const std::string name = entry->d_name;
            if (name == "." || name == "..")
                continue;
            const auto id = read_sysfs_block_identity(name);
            if (!id.removable)
                continue;
            const auto key = compute_device_key(id.vendor, id.product, id.serial, id.instance_id);
            current_scan[name] = key.device_key;
            if (linux_known_devices_.count(name))
                continue; // already tracked (baseline, a live event, or a prior reconciliation)
            if (st.attach_set.count(key.device_key)) {
                // PR #4023 review round 2, blocker #3: this device is
                // already persisted as attached -- it survived an agent
                // restart (stop() clears linux_known_devices_, but the
                // durable attach_set is untouched). No uevent was missed;
                // the process simply was not running. Track it for THIS
                // life without fabricating an "attached"/"missed-uevent-add"
                // row for a device that never left.
                linux_known_devices_[name] = key.device_key;
                continue;
            }

            RemovableEvent re;
            re.ts = now_seconds();
            re.device_key = key.device_key;
            re.vendor = id.vendor;
            re.product = id.product;
            re.serial = key.used_serial ? id.serial : "";
            re.bus = "block";
            re.size_bytes = id.size_bytes;
            const std::string anon = key.used_serial ? "" : ":anonymous-serial-fallback";
            if (!baseline_already_done) {
                re.action = "present_at_baseline";
                re.evidence = std::string("linux:/sys/block/") + name + anon;
                re.record_key = removable_baseline_record_key(key.device_key);
            } else {
                re.action = "attached";
                re.evidence = std::string("linux:/sys/block/") + name +
                             ":reconcile:missed-uevent-add" + anon;
                re.record_key = next_seq_record_key("reconcile_add", key.device_key);
            }
            events.push_back(std::move(re));
            st.attach_set[key.device_key] = true;
            begin_attach_session(st, key.device_key); // PR #4023 review blocker
            linux_known_devices_[name] = key.device_key;
        }
    }
    st.baseline_done = true;
    // Anything still in linux_known_devices_ that the fresh scan no longer
    // sees is a device that physically disappeared without a "remove"
    // uevent ever reaching the drain above (a lost datagram) — recover it.
    for (auto it = linux_known_devices_.begin(); it != linux_known_devices_.end();) {
        if (current_scan.count(it->first)) {
            ++it;
            continue;
        }
        RemovableEvent re;
        re.ts = now_seconds();
        re.action = "detached";
        re.device_key = it->second;
        re.bus = "block";
        re.evidence = "linux:reconcile:missing-from-sysfs-scan";
        re.record_key = next_seq_record_key("reconcile_rm", it->second);
        events.push_back(std::move(re));
        st.attach_set.erase(it->second);
        end_attach_session(st, it->second); // PR #4023 review blocker
        linux_device_roots_.erase(
           std::remove_if(linux_device_roots_.begin(), linux_device_roots_.end(),
                          [&](const auto& p) { return p.first == it->second; }),
           linux_device_roots_.end());
        it = linux_known_devices_.erase(it);
    }

    // A device persisted as attached that never appears in linux_known_devices_
    // THIS life at all is invisible to the loop above -- it happens when the
    // device was physically removed WHILE THE AGENT WAS STOPPED, so it was
    // never scanned into linux_known_devices_ this life to begin with (the
    // reconcile-add loop above only iterates devices the /sys/block scan
    // currently sees). Without this, such a device is a PERMANENT ghost in
    // st.attach_set: no future tick can ever correct it, since it can never
    // appear in linux_known_devices_ either (PR #4023 review round 2,
    // blocker #3). Diff directly against the PERSISTED attach_set, checked
    // AFTER the loop above so a device that loop already resolved (the
    // ordinary "known this life, vanished this tick" case) is not
    // double-reported here.
    {
        std::unordered_set<std::string> current_scan_device_keys;
        for (const auto& [name, device_key] : current_scan)
            current_scan_device_keys.insert(device_key);
        std::vector<std::string> ghosted_keys;
        for (const auto& [device_key, present] : st.attach_set)
            if (present && !current_scan_device_keys.count(device_key))
                ghosted_keys.push_back(device_key);
        for (const auto& device_key : ghosted_keys) {
            RemovableEvent re;
            re.ts = now_seconds();
            re.action = "detached";
            re.device_key = device_key;
            re.bus = "block";
            re.evidence = "linux:reconcile:missing-after-restart";
            re.record_key = next_seq_record_key("reconcile_rm", device_key);
            events.push_back(std::move(re));
            st.attach_set.erase(device_key);
            end_attach_session(st, device_key); // PR #4023 review blocker
            linux_device_roots_.erase(
               std::remove_if(linux_device_roots_.begin(), linux_device_roots_.end(),
                              [&](const auto& p) { return p.first == device_key; }),
               linux_device_roots_.end());
        }
    }

    // exec-from-removable root correlation (respec 2026-09-04 amendment):
    // /proc/mounts (the kernel symlink to /proc/self/mounts, same source
    // tar_mapdrive_collector.cpp reads) is read behind the same injectable-
    // read-then-pure-parse split the sysfs identity reads above use;
    // correlate_removable_mounts is pure. A read failure degrades to EMPTY
    // roots for THIS TICK ONLY -- attach/detach/baseline capture is
    // unaffected, and the exec:<device_key>:<image_path> dedupe key
    // recovers the emission on the next successful tick, so this is never
    // an IncompleteCaptureError (unlike mapdrive's BR4-004: an empty roots
    // list here only suppresses supplementary exec evidence, it never
    // fabricates a removed/absent claim).
    std::string mounts_note;
    {
        std::ifstream mounts_f("/proc/mounts");
        if (!mounts_f) {
            mounts_note = "linux: /proc/mounts unreadable — exec_from_removable suppressed "
                         "this tick";
        } else {
            std::ostringstream ss;
            ss << mounts_f.rdbuf();
            if (mounts_f.bad()) {
                mounts_note = "linux: /proc/mounts read error mid-stream — "
                             "exec_from_removable suppressed this tick";
            } else {
                const auto correlation = correlate_removable_mounts(ss.str(), linux_known_devices_);
                // Refresh (not merge) each tick so an unmount without a
                // matching detach uevent also drops its root; the
                // detach-time erase above still fires for the device-gone
                // case, this covers the device-still-attached-but-unmounted
                // case. R-015: keep every (device_key, root) pair — one
                // device mounted at multiple points must not collapse.
                linux_device_roots_ = correlation.pairs;
                // R-024: surface a short/malformed /proc/mounts row rather
                // than silently discarding the parser's own flag -- the
                // rows that DID parse are still used above (a malformed row
                // never invalidates its neighbours), this is diagnostic
                // only.
                if (correlation.malformed) {
                    mounts_note = "linux: /proc/mounts contained a malformed row (skipped) — "
                                 "exec_from_removable roots may be incomplete this tick";
                }
            }
        }
    }
    append_exec_from_removable(events, st, linux_device_roots_);

    // R-004: overflow-drop delta, reported (not yet advanced — see below).
    const auto dropped_now = queue_.dropped();
    const auto dropped_delta = dropped_now > last_reported_dropped_
                                  ? dropped_now - last_reported_dropped_
                                  : std::size_t{0};
    if (dropped_delta > 0)
        events.push_back(make_overflow_gap_event(dropped_delta));

    // C8: same shape as the overflow above -- reported now, advanced only once
    // the commit that carries it has succeeded.
    const auto bursts_delta = netlink_dropped_bursts_ - last_reported_netlink_bursts_;
    const auto errors_delta = netlink_recv_errors_ - last_reported_netlink_errors_;
    if (bursts_delta > 0 || errors_delta > 0)
        events.push_back(make_netlink_loss_gap_event(bursts_delta, errors_delta));

    CursorCollectResult result;
    result.new_cursor_json = encode_removable_cursor(st);
    result.events_emitted = events.size();
    result.outcome = (cursor_was_lost || reenable_gap_pending || bursts_delta > 0)
                        ? CursorOutcome::CursorLost
                        : (cursor_json.has_value() ? CursorOutcome::Advanced : CursorOutcome::Baseline);
    if (!mounts_note.empty())
        result.detail = mounts_note;

    if (auto ins = db.insert_removable_events_and_cursor(events, result.new_cursor_json); !ins) {
        // A KeyCollision is PERMANENT (tar_db.hpp): this source re-derives the
        // same batch every tick and the store refuses it every tick, so retrying
        // is a silent stall, not recovery. It also means rule 3(a) was violated
        // -- a persisted field is not deterministically re-derivable -- which is
        // a bug here rather than a condition to wait out.
        if (ins.error() == TarDatabase::CursorInsertError::KeyCollision)
            spdlog::critical("TAR removable: record_key COLLISION on the Linux leg -- a persisted "
                             "field is not deterministically re-derivable (rule 3a). Capture is "
                             "STUCK and retrying cannot clear it.");
        throw IncompleteCaptureError("TAR removable: Linux event/cursor commit failed");
    }
    // Only clear/advance transient state AFTER the commit above succeeds
    // (R-003/R-004) — see the identical comment in the macOS leg.
    queue_.ack_through(batch.last_seq);
    pending_reenable_gap_ = false;
    last_reported_dropped_ = dropped_now;
    last_reported_netlink_bursts_ = netlink_dropped_bursts_;
    last_reported_netlink_errors_ = netlink_recv_errors_;
    return result;
}

void RemovableCursorSource::on_enabled_changed(bool enabled) {
    if (!enabled) {
        // R-002: unlike macOS's application-level callback (gateable via a
        // flag), a netlink socket's kernel receive buffer keeps accumulating
        // multicast uevents regardless of whether our code is "paused" —
        // there is no way to pause receipt without actually closing the
        // socket. Closing it here (not merely discarding queue_) is what
        // stops paused-window uevents from being re-ingested wholesale the
        // next time collect() drains a still-open, still-buffering socket.
        netlink_fd_.reset();
        queue_.discard_all();
        was_disabled_ = true;
    } else if (was_disabled_) {
        queue_.discard_all(); // anything queued in the instant before the socket closed above
        netlink_fd_.reset(open_uevent_netlink_socket()); // fresh socket — the disabled window's
                                                          // kernel-buffered datagrams are gone
                                                          // with the old one
        pending_reenable_gap_ = true;
        pending_gap_cause_ = GapCause::Disabled;
        was_disabled_ = false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Windows leg (MEASURED — the-rig, 2026-09-04)
// ═══════════════════════════════════════════════════════════════════════
#elif defined(_WIN32)

namespace {

// The three MEASURED live channels (README.md). "partition" is identity
// authority and the only channel that emits RemovableEvent rows; "pnp" and
// "storsvc" are corroboration-only — their per-channel cursor still advances
// independently (tar_cursor.hpp rule 4/per-channel isolation) but they never
// themselves produce a row.
constexpr const char* kChannelPartition = "partition";
constexpr const char* kChannelPnp = "pnp";
constexpr const char* kChannelStorsvc = "storsvc";

struct WinChannelSpec {
    const wchar_t* path;
    const char* key;
};

constexpr WinChannelSpec kWinChannels[] = {
    {L"Microsoft-Windows-Partition/Diagnostic", kChannelPartition},
    {L"Microsoft-Windows-Kernel-PnP/Configuration", kChannelPnp},
    {L"Microsoft-Windows-Storsvc/Diagnostic", kChannelStorsvc},
};

std::string render_event_xml(EVT_HANDLE event) {
    DWORD used = 0, props = 0;
    ::EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &props);
    if (used == 0)
        return {};
    std::wstring buf(used / sizeof(wchar_t) + 1, L'\0');
    if (!::EvtRender(nullptr, event, EvtRenderEventXml, used, buf.data(), &used, &props))
        return {};
    return yuzu::win::from_wide(buf.c_str());
}

/// One EVT_HANDLE, closed with EvtClose (not CloseHandle) — local guard,
/// same shape as tar_netconn_win.cpp's EvtGuard (that one is file-local
/// there too; not shared via a header, so re-declared here rather than
/// reaching into a file this package doesn't own).
struct EvtGuard {
    EVT_HANDLE h{nullptr};
    explicit EvtGuard(EVT_HANDLE handle) : h{handle} {}
    ~EvtGuard() {
        if (h)
            ::EvtClose(h);
    }
    EvtGuard(const EvtGuard&) = delete;
    EvtGuard& operator=(const EvtGuard&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

/// EvtQuery `path` for a single record in `direction`; returns its
/// EventRecordID, or nullopt if the channel is empty/missing/denied.
std::optional<std::int64_t> query_single_record_id(const wchar_t* path, DWORD direction) {
    EvtGuard q{::EvtQuery(nullptr, path, nullptr, EvtQueryChannelPath | direction)};
    if (!q)
        return std::nullopt;
    EVT_HANDLE raw = nullptr;
    DWORD got = 0;
    if (!::EvtNext(q.h, 1, &raw, INFINITE, 0, &got) || got == 0)
        return std::nullopt;
    EvtGuard ev{raw};
    const auto xml = render_event_xml(ev.h);
    return extract_event_record_id(xml);
}

/// Read every record with EventRecordID > `after`, ascending, up to `cap`.
/// Returns the rendered XML of each — Partition/Diagnostic records are then
/// classified by the caller; other channels only need the count/last id.
struct ChannelReadOutcome {
    std::vector<std::string> xml_records; // ascending
    std::int64_t last_record_id{0};
    bool query_failed{false};
};

ChannelReadOutcome read_channel_forward(const wchar_t* path, std::int64_t after, std::size_t cap) {
    ChannelReadOutcome out;
    out.last_record_id = after;
    const std::wstring xpath = L"*[System[EventRecordID > " + std::to_wstring(after) + L"]]";
    EvtGuard q{::EvtQuery(nullptr, path, xpath.c_str(), EvtQueryChannelPath)};
    if (!q) {
        out.query_failed = true;
        return out;
    }
    std::size_t taken = 0;
    while (taken < cap) {
        EVT_HANDLE raw[32]{};
        DWORD got = 0;
        if (!::EvtNext(q.h, static_cast<DWORD>(std::size(raw)), raw, INFINITE, 0, &got))
            break;
        for (DWORD i = 0; i < got; ++i) {
            EvtGuard ev{raw[i]};
            if (taken >= cap)
                continue;
            auto xml = render_event_xml(ev.h);
            if (xml.empty())
                continue;
            if (auto id = extract_event_record_id(xml))
                out.last_record_id = std::max(out.last_record_id, *id);
            out.xml_records.push_back(std::move(xml));
            ++taken;
        }
    }
    if (taken >= cap)
        spdlog::warn("TAR removable: {} channel backfill hit the per-tick cap ({}) — remaining "
                    "records are picked up next tick",
                    yuzu::win::from_wide(path), cap);
    return out;
}

struct WindowsVolumeIdentity {
    std::string drive_letter;
    std::string vendor, product, serial, instance_id;
    std::int64_t size_bytes{0};
};

/// R-017: DeviceIoControl's own return only says the call succeeded, not
/// that every offset the descriptor claims actually lies within the bytes
/// it wrote — a malformed/short driver response could otherwise have this
/// read arbitrarily far past `buf`. Bounds every offset against `ret` (what
/// the ioctl actually returned) before ever dereferencing it, and NUL-scans
/// only within that returned range.
std::string safe_descriptor_cstr(const BYTE* buf, DWORD ret, DWORD offset) {
    if (offset == 0 || offset >= ret)
        return {};
    const char* start = reinterpret_cast<const char*>(buf) + offset;
    const char* end = reinterpret_cast<const char*>(buf) + ret;
    const void* nul = std::memchr(start, '\0', static_cast<std::size_t>(end - start));
    return nul != nullptr ? std::string(start, static_cast<const char*>(nul))
                          : std::string(start, end);
}

std::vector<WindowsVolumeIdentity> windows_snapshot_removable_volumes() {
    std::vector<WindowsVolumeIdentity> out;
    const DWORD mask = ::GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (!(mask & (1u << i)))
            continue;
        const wchar_t letter = static_cast<wchar_t>(L'A' + i);
        const wchar_t root[] = {letter, L':', L'\\', 0};
        if (::GetDriveTypeW(root) != DRIVE_REMOVABLE)
            continue;
        const wchar_t vol_path[] = {L'\\', L'\\', L'.', L'\\', letter, L':', 0};

        // RAII ownership BEFORE any validity check (spec requirement).
        win_raii::ScopedWinHandle<HANDLE> guard(
           ::CreateFileW(vol_path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                        0, nullptr),
           [](HANDLE h) { ::CloseHandle(h); }, INVALID_HANDLE_VALUE);
        if (!guard)
            continue;

        BYTE buf[1024]{};
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        DWORD ret = 0;
        if (!::DeviceIoControl(guard.get(), IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                               buf, sizeof(buf), &ret, nullptr))
            continue;
        // R-017: don't trust the descriptor at all unless the ioctl actually
        // returned enough bytes for its own fixed header, and the header's
        // own claimed Size fits both what we asked for and what we got.
        if (ret < sizeof(STORAGE_DEVICE_DESCRIPTOR))
            continue;
        const auto* desc = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buf);
        if (desc->Size > sizeof(buf) || desc->Size > ret)
            continue;

        WindowsVolumeIdentity v;
        v.drive_letter = std::string(1, static_cast<char>('A' + i)) + ":";
        // trim_trailing_scsi_padding (PR #4023 review, should-fix): these are
        // SCSI-INQUIRY fixed-width fields, space-padded to their declared
        // width -- measured on real hardware reporting
        // product="STORE N GO      " (6 trailing spaces) where the event-log
        // leg's XML-sourced field for the SAME device carried none, splitting
        // one physical device across two device_keys despite a matching
        // trusted serial.
        v.vendor = trim_trailing_scsi_padding(safe_descriptor_cstr(buf, ret, desc->VendorIdOffset));
        v.product = trim_trailing_scsi_padding(safe_descriptor_cstr(buf, ret, desc->ProductIdOffset));
        v.serial = trim_trailing_scsi_padding(safe_descriptor_cstr(buf, ret, desc->SerialNumberOffset));

        // R-014: prefer the volume's own GUID path — durable per-volume
        // identity that survives a drive-letter or physical-drive-number
        // reassignment (both of which can change across a reboot, or when
        // other removable media attach/detach in between) — over the
        // physical-drive-number fallback the previous round used alone; the
        // drive letter remains the last resort. Still documented as a
        // residual, evidence-marked limitation for the anonymous-serial
        // case (docs/user-manual/tar-removable.md) — this narrows, but does
        // not claim to eliminate, that collision window.
        wchar_t vol_guid[64]{};
        if (::GetVolumeNameForVolumeMountPointW(root, vol_guid, static_cast<DWORD>(std::size(vol_guid))))
            v.instance_id = yuzu::win::from_wide(vol_guid);

        STORAGE_DEVICE_NUMBER devnum{};
        DWORD ret2 = 0;
        if (v.instance_id.empty() &&
            ::DeviceIoControl(guard.get(), IOCTL_STORAGE_GET_DEVICE_NUMBER, nullptr, 0, &devnum,
                              sizeof(devnum), &ret2, nullptr))
            v.instance_id = "PHYSICALDRIVE" + std::to_string(devnum.DeviceNumber);
        if (v.instance_id.empty())
            v.instance_id = v.drive_letter; // last-resort platform-stable-enough fallback

        GET_LENGTH_INFORMATION len_info{};
        DWORD ret3 = 0;
        if (::DeviceIoControl(guard.get(), IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0, &len_info,
                              sizeof(len_info), &ret3, nullptr))
            v.size_bytes = len_info.Length.QuadPart;

        out.push_back(std::move(v));
    }
    return out;
}

} // namespace

void RemovableCursorSource::start(TarDatabase&) {
    // Pure poll/backfill leg (EvtQuery per tick, no persistent subscription
    // handle) — nothing to arm.
}

void RemovableCursorSource::stop() noexcept {
    // No live handle owned between ticks — nothing to release.
}

CursorCollectResult RemovableCursorSource::collect(TarDatabase& db,
                                                   const std::optional<std::string>& cursor_json) {
    RemovableCursorState st = decode_removable_cursor(cursor_json);
    std::vector<RemovableEvent> events;
    std::vector<std::string> failing_channels;
    // C4: a channel that was REQUIRED to jump to its head but could not read it.
    // The head jump is the whole mechanism that stops a re-enable or a wrap from
    // replaying history it must not replay, so a tick where one failed cannot be
    // allowed to commit and clear the state that says the jump is still owed.
    bool head_jump_unfulfilled = false;
    bool any_wrap = false;

    // R-005: a persisted-but-unparseable cursor is CursorLost. decode already
    // hands back a fresh (empty channels/attach_set) state for this case, so
    // it naturally takes the same "every channel never_initialized" path a
    // re-enable does below.
    const bool cursor_was_lost = st.malformed;
    if (cursor_was_lost)
        events.push_back(make_cursor_lost_gap_event());

    const bool is_reenable = pending_reenable_gap_;
    if (pending_reenable_gap_) {
        events.push_back(make_reenable_gap_event(pending_gap_cause_));
        st.channels.clear(); // force every channel to head-jump, no backfill scan
    }
    // Rule 2 ("never replay-from-zero"): a lost cursor re-baselines at the
    // current log end exactly like a re-enable, never a from-zero backfill.
    const bool force_head_jump = is_reenable || cursor_was_lost;

    // tar_cursor.hpp rule 5 (PR #4023 review round 2, blocker #1): a source
    // that cannot READ its lookback treats it as 0 (forward-only), never as
    // the default -- db.get_config() returns the caller's default on ANY
    // read failure, so the previous lambda turned a transient SQLite failure
    // into a 7-day retrospective backfill on a host where the operator set 0
    // precisely because that is not lawful. lookback_seconds_or_forward_only()
    // is the mandated helper for exactly this (already used by the sibling
    // `power` source's fix for the identical defect).
    const std::int64_t lookback_s =
        lookback_seconds_or_forward_only(db, "removable", kDefaultRemovableLookbackSeconds);
    const bool first_run = !cursor_json.has_value();
    // R-006: computed ONCE and applied to EVERY Partition/Diagnostic
    // classification below, not just a first-run batch — a backlog longer
    // than one tick's 500-record cap must stay bounded by
    // removable_lookback_seconds across every continuation tick, not just
    // the very first. Once genuinely caught up to the live channel, current
    // records are always >= cutoff anyway, so this is a no-op then.
    const std::int64_t cutoff = now_seconds() - lookback_s;

    const std::unordered_map<std::string, bool> prev_attach_set(st.attach_set.begin(),
                                                                 st.attach_set.end());

    // Both the initial-backfill and continuation branches below classify a
    // batch of Partition/Diagnostic XML identically -- extracted to ONE
    // lambda so two review-driven fixes (PR #4023) cannot silently diverge
    // between what were previously two hand-duplicated copies of this loop:
    //  - shared_serials_in_batch() downgrades a serial two DIFFERENT PnP
    //    ParentIds both reported in this same batch to the anonymous-fallback
    //    key, instead of letting compute_device_key collapse two physically
    //    distinct USBSTOR LUNs (a multi-format card reader, real hardware)
    //    onto one device_key;
    //  - begin_attach_session()/end_attach_session() stamp/clear
    //    attach_epoch (and forget exec_seen on detach) at the point this leg
    //    actually decides attach_set -- attach_epoch was written on NO
    //    Windows code path before this fix, so exec_from_removable was
    //    silently dead here (the blocker).
    // Two passes over the batch (parse-and-filter, THEN classify) rather than
    // one: shared_serials_in_batch needs to see every record's parent_id
    // before ANY of them can be classified, since the untrustworthy-serial
    // decision depends on the WHOLE batch, not one record in isolation.
    auto classify_partition_batch = [&](const std::vector<std::string>& xml_records,
                                        const char* channel_key) {
        std::vector<PartitionDiagnosticRecord> records;
        records.reserve(xml_records.size());
        for (const auto& xml : xml_records) {
            auto rec = parse_partition_diagnostic_xml(xml);
            // R-006: same cutoff applied universally, not only on a first-run
            // batch — a backlog longer than one tick's cap must stay bounded
            // by removable_lookback_seconds across every continuation tick.
            if (rec && rec->ts >= cutoff && is_removable_bus_type(rec->bus_type))
                records.push_back(std::move(*rec));
        }
        const auto shared_serials = shared_serials_in_batch(records);
        for (const auto& rec : records) {
            const bool serial_shared_this_batch =
               !rec.serial_number.empty() &&
               shared_serials.count(rec.manufacturer + "\x1f" + rec.model + "\x1f" +
                                    rec.serial_number) != 0;
            const auto key = compute_device_key(
               rec.manufacturer, rec.model,
               serial_shared_this_batch ? std::string_view{} : std::string_view(rec.serial_number),
               rec.parent_id);
            RemovableEvent re;
            re.ts = rec.ts;
            re.device_key = key.device_key;
            re.vendor = rec.manufacturer;
            re.product = rec.model;
            re.serial = key.used_serial ? rec.serial_number : "";
            re.bus = rec.bus_type;
            const bool is_attach =
               classify_partition_transition(rec) == PartitionTransition::kAttach;
            re.action = is_attach ? "attached" : "detached";
            re.size_bytes = rec.capacity;
            re.evidence = "win:Microsoft-Windows-Partition/Diagnostic:EventRecordID=" +
                         std::to_string(rec.event_record_id) +
                         (key.used_serial ? "" : ":anonymous-serial-fallback");
            re.record_key = removable_channel_record_key(channel_key, rec.event_record_id);
            if (is_attach) {
                st.attach_set[key.device_key] = true;
                begin_attach_session(st, key.device_key);
            } else {
                st.attach_set.erase(key.device_key);
                end_attach_session(st, key.device_key);
            }
            events.push_back(std::move(re));
        }
    };

    for (const auto& ch : kWinChannels) {
        const bool never_initialized = !st.channels.count(ch.key);

        if (never_initialized) {
            // Re-enable, a lost cursor, or a genuinely first run with
            // forward-only lookback (0): jump straight to the channel's
            // current head, no scan.
            if (force_head_jump || (first_run && lookback_s == 0)) {
                if (auto head = query_single_record_id(ch.path, EvtQueryReverseDirection)) {
                    st.channels[ch.key].record_id = *head;
                } else if (force_head_jump) {
                    // C4: NOT a silent skip. Committing this tick would clear
                    // pending_reenable_gap_, so the next tick would see
                    // force_head_jump false, take the retrospective backfill
                    // branch, and read forward THROUGH the disabled window --
                    // replaying exactly the events the pause promised were never
                    // captured.
                    failing_channels.push_back(ch.key);
                    head_jump_unfulfilled = true;
                } else {
                    // First run with lookback 0: no history is owed either way,
                    // so an unreadable head is an ordinary channel failure.
                    failing_channels.push_back(ch.key);
                }
                continue;
            }
            // Genuine retrospective backfill, bounded by
            // removable_lookback_seconds (tar_cursor.hpp rule 5). R-007:
            // this branch is reached whenever a channel has never
            // successfully initialized — including a channel whose FIRST
            // attempt failed on an earlier tick (never_initialized stays
            // true forever until this succeeds, since st.channels[ch.key]
            // is only set once a read actually completes) — so a failed
            // channel safely retries its own bounded backfill here instead
            // of falling through to the wrap-detection path below with a
            // phantom stored=0 cursor that would misclassify it as wrapped
            // and permanently skip its lookback window.
            const auto outcome = read_channel_forward(ch.path, 0, 500);
            if (outcome.query_failed) {
                failing_channels.push_back(ch.key);
                continue;
            }
            if (std::string_view(ch.key) == kChannelPartition)
                classify_partition_batch(outcome.xml_records, ch.key);
            st.channels[ch.key].record_id = outcome.last_record_id;
            continue;
        }

        const std::int64_t stored = st.channels.at(ch.key).record_id;
        const auto oldest = query_single_record_id(ch.path, 0);
        if (!oldest) {
            failing_channels.push_back(ch.key);
            continue; // transient/ACL-denied — keep this channel's cursor, others advance
        }
        if (channel_cursor_wrapped(stored, *oldest)) {
            any_wrap = true;
            RemovableEvent gap;
            gap.ts = now_seconds();
            gap.action = "capture_gap";
            gap.evidence = std::string(ch.key) + " channel wrapped past the stored cursor "
                                                 "(oldest retained record id " +
                          std::to_string(*oldest) + " > stored " + std::to_string(stored) + ")";
            gap.record_key = next_seq_record_key("wrap", ch.key);
            events.push_back(std::move(gap));
            if (auto head = query_single_record_id(ch.path, EvtQueryReverseDirection)) {
                st.channels[ch.key].record_id = *head; // re-baseline forward, never replay-from-zero
            } else {
                // C4: the wrap gap and the re-baseline are one decision. Emitting
                // the gap without moving the cursor would commit a report of loss
                // while leaving the cursor behind the retained window, so the same
                // wrap is re-detected and re-reported on every subsequent tick.
                failing_channels.push_back(ch.key);
                head_jump_unfulfilled = true;
            }
            continue;
        }

        const auto outcome = read_channel_forward(ch.path, stored, 500);
        if (outcome.query_failed) {
            failing_channels.push_back(ch.key);
            continue;
        }
        if (std::string_view(ch.key) == kChannelPartition)
            classify_partition_batch(outcome.xml_records, ch.key);
        st.channels[ch.key].record_id = outcome.last_record_id;
    }

    if (failing_channels.size() == std::size(kWinChannels))
        throw IncompleteCaptureError("TAR removable: every Windows channel failed this tick");

    // Snapshot leg: present_at_baseline once, R-001 reconciliation
    // thereafter, plus the live roots exec-from-removable needs. USBSTOR/
    // history absence is "no history", never surfaced as an error — this
    // function only reads currently-attached volumes, never the registry.
    const bool baseline_already_done = st.baseline_done;
    const auto volumes = windows_snapshot_removable_volumes();
    std::vector<std::pair<std::string, std::string>> attached_roots;
    std::unordered_set<std::string> current_keys;
    attached_roots.reserve(volumes.size());
    current_keys.reserve(volumes.size());
    // C7: the two Windows legs do NOT share an identity authority for an
    // ANONYMOUS device. The event leg keys on the PnP ParentId; this snapshot
    // keys on a volume GUID / PHYSICALDRIVE<n> / drive letter. Those are not
    // alternative spellings of one identifier, so one physical device gets two
    // device_keys: the snapshot's key looks like a brand-new attach, and the
    // event leg's key looks like a device that has vanished, producing a
    // fabricated attach/detach pair every tick.
    //
    // compute_device_key ignores platform_instance_id whenever a trusted serial
    // is present, so the legs agree BY CONSTRUCTION exactly when used_serial is
    // true. Reconciliation is therefore restricted to those devices. An
    // anonymous device is still fully reported by the event leg -- which is the
    // authoritative history source on Windows -- it just no longer has a second,
    // incompatible identity inventing transitions for it here. The residual is
    // that an anonymous device attached before the agent started and older than
    // the event-log lookback gets no baseline row; that is a missing row, not a
    // fabricated one, and it is the strictly safer failure for forensic
    // evidence.
    for (const auto& v : volumes) {
        const auto key = compute_device_key(v.vendor, v.product, v.serial, v.instance_id);
        attached_roots.emplace_back(key.device_key, v.drive_letter + "\\");
        if (!key.used_serial)
            continue; // identity not comparable with the event leg's — see above
        current_keys.insert(key.device_key);
        st.snapshot_keyed.insert(key.device_key);
        if (!st.attach_set.count(key.device_key)) {
            RemovableEvent re;
            re.ts = now_seconds();
            re.device_key = key.device_key;
            re.vendor = v.vendor;
            re.product = v.product;
            re.serial = key.used_serial ? v.serial : "";
            re.volume = v.drive_letter;
            re.size_bytes = v.size_bytes;
            const std::string anon = key.used_serial ? "" : ":anonymous-serial-fallback";
            if (!baseline_already_done) {
                re.action = "present_at_baseline";
                re.evidence = "win:snapshot:IOCTL_STORAGE_QUERY_PROPERTY:baseline" + anon;
                re.record_key = removable_baseline_record_key(key.device_key);
            } else {
                // R-001: the live snapshot sees a device no channel event
                // reported arriving (a missed/wrapped Partition/Diagnostic
                // record) — recover with an explicit row instead of
                // silently absorbing it into attach_set with no evidence.
                re.action = "attached";
                re.evidence = "win:snapshot:reconcile:missed-channel-attach" + anon;
                re.record_key = next_seq_record_key("reconcile_add", key.device_key);
            }
            events.push_back(std::move(re));
        }
        st.attach_set[key.device_key] = true;
        begin_attach_session(st, key.device_key); // PR #4023 review blocker
    }
    st.baseline_done = true;
    // R-001: a device the channels never reported disappearing, but the
    // live snapshot no longer sees at all — recover with a detach.
    for (const auto& [key, present] : prev_attach_set) {
        if (!present || current_keys.count(key) || !st.attach_set.count(key))
            continue;
        if (!st.snapshot_keyed.count(key))
            continue; // C7: never detach a key this snapshot cannot even express
        RemovableEvent re;
        re.ts = now_seconds();
        re.action = "detached";
        re.device_key = key;
        re.evidence = "win:snapshot:reconcile:missing-from-live-snapshot";
        re.record_key = next_seq_record_key("reconcile_rm", key);
        events.push_back(std::move(re));
        st.attach_set.erase(key);
        end_attach_session(st, key); // PR #4023 review blocker
    }

    append_exec_from_removable(events, st, attached_roots);

    CursorCollectResult result;
    result.new_cursor_json = encode_removable_cursor(st);
    result.events_emitted = events.size();
    // R-005: a lost cursor or a wrapped channel is CursorLost, not an
    // ordinary Baseline/Advanced tick — both already emitted their own
    // capture_gap above; this only fixes the reported outcome to match.
    result.outcome = (cursor_was_lost || is_reenable || any_wrap)
                        ? CursorOutcome::CursorLost
                        : (first_run ? CursorOutcome::Baseline : CursorOutcome::Advanced);
    if (!failing_channels.empty()) {
        result.detail = "channel(s) unusable this tick, cursor retained: ";
        for (const auto& c : failing_channels)
            result.detail += c + " ";
    }

    if (head_jump_unfulfilled) {
        // Rule 1: nothing is persisted, so pending_reenable_gap_ and the stored
        // cursors survive untouched and the whole tick is retried. One
        // temporarily unreadable channel costs a tick; letting it through costs
        // the integrity of the pause contract.
        throw IncompleteCaptureError(
           "TAR removable: a Windows channel owed a head jump but its head could not be read -- "
           "retaining cursor and re-enable state");
    }
    if (auto ins = db.insert_removable_events_and_cursor(events, result.new_cursor_json); !ins) {
        // A KeyCollision is PERMANENT (tar_db.hpp): this source re-derives the
        // same batch every tick and the store refuses it every tick, so retrying
        // is a silent stall, not recovery. It also means rule 3(a) was violated
        // -- a persisted field is not deterministically re-derivable -- which is
        // a bug here rather than a condition to wait out.
        if (ins.error() == TarDatabase::CursorInsertError::KeyCollision)
            spdlog::critical("TAR removable: record_key COLLISION on the Windows leg -- a persisted "
                             "field is not deterministically re-derivable (rule 3a). Capture is "
                             "STUCK and retrying cannot clear it.");
        throw IncompleteCaptureError("TAR removable: Windows event/cursor commit failed");
    }
    pending_reenable_gap_ = false; // only clear after the commit above succeeds (R-003)
    return result;
}

void RemovableCursorSource::on_enabled_changed(bool enabled) {
    if (!enabled) {
        was_disabled_ = true;
    } else if (was_disabled_) {
        pending_reenable_gap_ = true;
        pending_gap_cause_ = GapCause::Disabled;
        was_disabled_ = false;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Unsupported platform — honest empty leg, never a silent success claim
// ═══════════════════════════════════════════════════════════════════════
#else

void RemovableCursorSource::start(TarDatabase&) {}
void RemovableCursorSource::stop() noexcept {}
void RemovableCursorSource::on_enabled_changed(bool) {}

CursorCollectResult RemovableCursorSource::collect(TarDatabase&,
                                                   const std::optional<std::string>& cursor_json) {
    RemovableCursorState st = decode_removable_cursor(cursor_json);
    CursorCollectResult result;
    result.new_cursor_json = encode_removable_cursor(st);
    result.outcome = cursor_json.has_value() ? CursorOutcome::Advanced : CursorOutcome::Baseline;
    result.detail = "removable capture not implemented on this platform";
    return result;
}

#endif

std::unique_ptr<CursorSource> make_removable_cursor_source() {
    return std::make_unique<RemovableCursorSource>();
}

} // namespace yuzu::tar
