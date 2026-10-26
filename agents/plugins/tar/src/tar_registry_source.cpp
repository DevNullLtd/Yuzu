/**
 * tar_registry_source.cpp -- the `registry` cursor-model TAR source.
 *
 * Cross-platform section: the collect() state machine over an injected
 * RegistryReader (unit-tested on every platform). Windows section (#ifdef
 * _WIN32): the Kernel-Registry ETW session, the RegNotifyChangeKeyValue watcher
 * thread and the budgeted subtree reader, wired into a RegistryReader by
 * make_registry_cursor_source(). Off-Windows the production factory is nullptr.
 *
 * Design and the exact meaning of the attribution: tar_registry_parsers.hpp.
 */

#include "tar_registry_source.hpp"

#include "tar_capture_status.hpp" // IncompleteCaptureError
#include "tar_collectors.hpp"
#include "tar_db.hpp"

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp> // yuzu::log_key_token: a denied key name is user-chosen (CWE-117)

#include <algorithm>
#include <format>
#include <set>
#include <string>

namespace yuzu::tar {

namespace {

constexpr const char* kEmptyBaselineJson = R"({"v":1,"keys":{}})";

std::string baseline_collector(const std::string& root) { return "registry:" + root; }

// The gap row text for child keys that denied read access: names the first few. The names
// are key names a local user chose under their own hive, so each goes through log_key_token
// (control bytes and line separators folded) before it lands in the stored row.
std::string denied_children_detail(const std::string& root, const std::vector<std::string>& denied) {
    constexpr std::size_t kShown = 3;
    std::string d = std::format("gap:unreadable:{} ({} child key(s) denied read access; their values "
                                "and anything beneath them are not read, and deletions beneath them "
                                "are not derived, until they can be): ",
                                root, denied.size());
    for (std::size_t i = 0; i < denied.size() && i < kShown; ++i)
        d += (i == 0 ? "" : "; ") + yuzu::log_key_token(denied[i]);
    if (denied.size() > kShown)
        d += std::format("; +{} more", denied.size() - kShown);
    return d;
}

// Restores the dirty flags a tick took if the tick does not commit (R7): the next
// tick must re-read those roots and re-diff against the committed baseline.
struct DirtyRollback {
    RegistryDirtyTable& table;
    std::vector<std::pair<std::string, RegistryDirtyTable::Snap>> taken;
    bool hku_taken{false};
    bool active{true};
    ~DirtyRollback() {
        if (!active)
            return;
        for (const auto& [root, snap] : taken)
            table.restore(root, snap);
        table.restore_hku(hku_taken);
    }
};

} // namespace

RegistryCursorSource::RegistryCursorSource(RegistryScope scope, RegistryReader reader)
    : scope_(std::move(scope)), reader_(std::move(reader)) {}

void RegistryCursorSource::ensure_watch(const std::vector<std::string>& roots) {
    if (roots == armed_roots_)
        return;
    reader_.watch_roots(roots);
    armed_roots_ = roots;
}

void RegistryCursorSource::start(TarDatabase& db) {
    // A persisted cursor means a previous run: whatever was written while the agent
    // was down is found by the baseline diff, but the events that would name its
    // writer were never seen. An unreadable cursor is treated the same way.
    const auto cursor = db.get_cursor("registry");
    if (!cursor || cursor->has_value()) {
        pending_gap_ = true;
        gap_cause_ = GapCause::Restart;
        force_all_ = true;
    }
    reader_.start(); // a session that cannot open degrades to the key watch (rows attr:off)
    // Nothing before this instant is in the buffer: every candidate read earlier (the held
    // ones, and the force_all_ reconcile reads) finalises as lost-restart.
    events_since_ = reader_.now_ts();
    last_query_ts_ = events_since_;
    ensure_watch(scope_.roots_for(reader_.loaded_sids()));
}

void RegistryCursorSource::stop() noexcept {
    try {
        reader_.stop();
    } catch (...) {
        // stop() must not throw (tar_cursor.hpp); nothing left to release.
    }
}

void RegistryCursorSource::on_enabled_changed(bool enabled) {
    if (!enabled) {
        // The watcher and the session stay warm. Gate the buffer FIRST so nothing new is
        // queued, and discard what it holds, so no event from the paused window can ever
        // be matched. The first tick after re-enable re-baselines every root
        // (forensic-pause contract), so the paused window's changes are never stored.
        reader_.buffer->pause();
        was_disabled_ = true;
    } else if (was_disabled_) {
        reader_.buffer->resume();
        pending_gap_ = true;
        gap_cause_ = GapCause::Disabled;
        was_disabled_ = false;
        // Nothing before this instant is in the buffer: held candidates read earlier
        // finalise as lost-restart rather than as a clean attribution.
        events_since_ = reader_.now_ts();
    }
}

CursorCollectResult RegistryCursorSource::collect(TarDatabase& db,
                                                  const std::optional<std::string>& cursor_json) {
    DirtyRollback rb{*reader_.dirty, {}, false, true};
    try {
        const std::int64_t now = reader_.now_ts();
        RegistryCursor cur = decode_registry_cursor(cursor_json);
        const bool cursor_lost = cur.malformed;
        if (cursor_lost)
            cur = RegistryCursor{};
        const bool fresh = !cur.present; // first-ever tick, or a lost cursor re-baselining
        const std::int64_t snapshot_id = cur.tick + 1;

        std::vector<RegistryEvent> rows;
        if (cursor_lost)
            rows.push_back(registry_gap_row(
               "cursorlost", std::to_string(now),
               "gap:cursorlost: the persisted registry cursor failed to parse; every root was "
               "re-baselined at its current state (tar_cursor.hpp rule 2)",
               now, snapshot_id));
        const bool gap_pending = pending_gap_;
        const GapCause cause = gap_cause_;
        if (gap_pending)
            rows.push_back(registry_gap_row(
               cause == GapCause::Restart ? "restart" : "disabled", std::to_string(now),
               cause == GapCause::Restart
                  ? "gap:restart: the agent was not running; registry changes made meanwhile are "
                    "found by the baseline diff but their writers were never observed"
                  : "gap:disabled: the registry source was disabled; the disabled window's "
                    "changes were never captured and every root was re-baselined (forensic-pause "
                    "contract)",
               now, snapshot_id));
        const bool rebaseline_all = fresh || (gap_pending && cause == GapCause::Disabled);
        const bool reconcile = (cur.tick % kReconcileEveryTicks == 0) || force_all_;

        // The loaded user hives: re-enumerated on a name-watch signal, a reconcile
        // tick or a re-baseline, otherwise the cursor's list stands.
        const bool hku_changed = reader_.dirty->take_hku();
        rb.hku_taken = hku_changed;
        std::vector<std::string> sids = cur.hku;
        if (hku_changed || reconcile || rebaseline_all || sids.empty())
            sids = reader_.loaded_sids();
        const std::vector<std::string> roots = scope_.roots_for(sids);
        ensure_watch(roots);

        // Roots that left scope (a logged-off user): drop their state and shrink the
        // baseline row, so a logon later re-baselines from scratch, never as a mass
        // removal of what the unloaded hive "lost".
        std::vector<StateWrite> state_writes;
        for (auto it = cur.roots.begin(); it != cur.roots.end();) {
            if (std::find(roots.begin(), roots.end(), it->first) == roots.end()) {
                if (it->second.baselined)
                    state_writes.push_back({baseline_collector(it->first), kEmptyBaselineJson});
                it = cur.roots.erase(it);
            } else {
                ++it;
            }
        }

        // A numbered control set that is no longer the current one would make every
        // key under CurrentControlSet read as removed and re-added: re-baseline them.
        // An unreadable Select\Current (0) keeps the stored value: a transient read failure
        // must not look like a control-set switch and re-baseline the Services subtree.
        const int cs = reader_.current_control_set();
        const std::string ccs_now = cs > 0 ? std::format("ControlSet{:03}", cs) : cur.ccs;
        const bool ccs_switched = !cur.ccs.empty() && cur.ccs != ccs_now;
        cur.ccs = ccs_now;

        std::vector<RegistryCandidate> fresh_candidates;
        const std::int64_t deadline = now + kSnapshotBudget100ns;
        const std::size_t n = roots.size();
        const std::size_t start_idx = n == 0 ? 0 : static_cast<std::size_t>(cur.tick) % n;
        bool read_any = false;
        for (std::size_t i = 0; i < n; ++i) {
            const std::string& root = roots[(start_idx + i) % n];
            RegistryRootState& st = cur.roots[root];
            if (rebaseline_all) {
                st.baselined = false;
            } else if (ccs_switched && st.baselined &&
                       root.find("\\CurrentControlSet\\") != std::string::npos) {
                rows.push_back(registry_gap_row(
                   "baselinelost", root + ":" + std::to_string(now),
                   "gap:baselinelost:" + root + " (the current control set changed)", now,
                   snapshot_id));
                st.baselined = false;
            }
            bool armed = reader_.root_armed(root);
            if (!armed)
                armed = reader_.rearm(root);
            st.armed = armed;

            const bool unsettled = st.status.empty() || st.status == "unreadable" ||
                                   st.status == "capped" || st.status == "due";
            const bool due = !st.baselined || reconcile || reader_.dirty->peek_dirty(root) ||
                             !st.armed || unsettled;
            if (!due)
                continue;
            if (read_any && reader_.now_ts() >= deadline) {
                // Not reached this tick; first in line next time. An already-unsettled
                // status is kept: it is what tells a root that STAYS unreadable from one
                // that just became so.
                if (!unsettled)
                    st.status = "due";
                continue;
            }
            read_any = true;

            // first_dirty is exchanged with the dirty flag BEFORE the read, so a notify
            // arriving during the read re-marks the root for the next tick.
            const auto snap = reader_.dirty->take(root);
            rb.taken.emplace_back(root, snap);
            const std::int64_t read_start = reader_.now_ts();
            SubtreeRead rd = reader_.read_subtree(root, deadline);
            const std::int64_t read_end = reader_.now_ts();
            const std::int64_t last_dirty = reader_.dirty->last(root);

            RegistryBaseline base;
            bool fresh_root = !st.baselined;
            if (st.baselined && rd.status != RegistryReadStatus::Unreadable) {
                const auto stored = db.try_get_state(baseline_collector(root));
                if (!stored)
                    throw IncompleteCaptureError("TAR registry: baseline read failed: " +
                                                 stored.error());
                const auto decoded = decode_registry_baseline(*stored);
                if (!stored->has_value() || decoded.malformed) {
                    // The cursor says this root was baselined and the baseline is gone
                    // or unusable: say so and start it over, rather than diff against
                    // nothing (which would report the whole subtree as added).
                    rows.push_back(registry_gap_row(
                       "baselinelost", root + ":" + std::to_string(now),
                       "gap:baselinelost:" + root, now, snapshot_id));
                    fresh_root = true;
                } else {
                    base = decoded.baseline;
                }
            }
            // The window the writes behind these candidates fall in; st.window_base (this
            // root's last COMPLETE read start) is advanced only below, after the diff.
            const RegistryWindow window = candidate_window(st.window_base, read_end, snap.first,
                                                           last_dirty, kEtwWindowSlack100ns);
            DiffResult diff = diff_registry_snapshot(base, rd, root,
                                                     snap.first != 0 ? "notify" : "reconcile",
                                                     window, read_end, fresh_root);
            for (auto& c : diff.candidates)
                fresh_candidates.push_back(std::move(c));
            if (rd.status != RegistryReadStatus::Unreadable && (fresh_root || diff.changed))
                state_writes.push_back({baseline_collector(root),
                                        encode_registry_baseline(diff.baseline)});

            // A root that could not be read, or child keys that deny access, are a blind
            // spot the operator must be able to see: one gap row when the root becomes
            // unreadable or a child key is newly denied, none while it holds steady, shrinks
            // or clears. The cursor commits with the row, so a replay cannot lose or
            // duplicate it.
            if (rd.status == RegistryReadStatus::Unreadable) {
                if (st.status != "unreadable")
                    rows.push_back(registry_gap_row(
                       "unreadable", root + ":" + std::to_string(read_end),
                       "gap:unreadable:" + root +
                          " (the root could not be read; its baseline is kept and nothing is "
                          "derived for it until it can be)",
                       now, snapshot_id));
            } else {
                std::sort(rd.skipped.begin(), rd.skipped.end());
                rd.skipped.erase(std::unique(rd.skipped.begin(), rd.skipped.end()), rd.skipped.end());
                // A gap is a GAIN: a denied child the stored set does not hold. A Capped read
                // stops its walk early, so its list is partial -- it may add to the stored set
                // but never shrinks it, else the next Complete read would look like a change
                // and report an unchanged set again. (The diff above was given the read's own
                // list: its Capped handling already keeps the unvisited keys.)
                std::set<std::string> known(st.skipped.begin(), st.skipped.end());
                bool gained = false;
                for (const auto& s : rd.skipped)
                    if (known.insert(s).second)
                        gained = true;
                if (rd.status == RegistryReadStatus::Capped) {
                    // Bounded: each Capped read can add up to kSkippedCap fresh names, so a root
                    // that stays Capped would grow the persisted cursor row without limit. Past
                    // the cap the sorted prefix is kept (`gained` was decided above, so a new name
                    // still writes its one gap row); a name clamped away can raise one more gap
                    // row when a later read sees it again -- at most one a tick, and 33 denied
                    // children under one root is already the Capped anomaly the manual documents.
                    st.skipped.assign(known.begin(), known.end());
                    if (st.skipped.size() > kSkippedCap)
                        st.skipped.resize(kSkippedCap);
                } else {
                    st.skipped = std::move(rd.skipped);
                }
                if (gained)
                    rows.push_back(registry_gap_row("unreadable",
                                                    root + ":" + std::to_string(read_end),
                                                    denied_children_detail(root, st.skipped), now,
                                                    snapshot_id));
            }

            st.read_start = read_start;
            st.read_end = read_end;
            st.status = std::string(to_string(rd.status));
            if (rd.status != RegistryReadStatus::Unreadable)
                st.baselined = true; // a Capped first read is a partial baseline, by design
            if (rd.status == RegistryReadStatus::Complete || rd.status == RegistryReadStatus::Absent)
                st.window_base = read_start; // the NEXT window starts here
        }

        // Loss accounting. The drop range and the session counters are cumulative; what is
        // new since the last COMMITTED tick becomes one gap row and a loss epoch. A failed
        // loss query is itself loss: the session's counters are then unknown.
        const auto drops = reader_.buffer->drop_info();
        const SessionLoss sl = reader_.session_loss();
        const std::uint64_t fail_now = sl.query_ok ? 0 : 1;
        const std::uint64_t kernel_total =
           sl.events_lost + sl.rt_buffers_lost + sl.decode_failed + query_failures_ + fail_now;
        const std::uint64_t drop_delta =
           drops.count > last_reported_drops_ ? drops.count - last_reported_drops_ : 0;
        const std::uint64_t kernel_delta =
           kernel_total > last_reported_kernel_ ? kernel_total - last_reported_kernel_ : 0;
        std::vector<LossEpoch> epochs = cur.loss;
        if (drop_delta > 0)
            append_loss_epoch(epochs, {drops.ts_lo, drops.ts_hi});
        if (kernel_delta > 0) // where inside the interval since the last query the loss lies is unknown
            append_loss_epoch(epochs, {last_query_ts_, now});
        if (drop_delta + kernel_delta > 0)
            rows.push_back(registry_gap_row("loss", std::to_string(now),
                                            std::format("gap:loss:{}", drop_delta + kernel_delta),
                                            now, snapshot_id));

        // Held candidates (from earlier ticks) and this tick's fresh ones, against the buffer.
        const auto batch = reader_.buffer->snapshot();
        std::vector<RegistryCandidate> candidates = std::move(cur.held);
        for (auto& c : fresh_candidates)
            candidates.push_back(std::move(c));
        const StitchFlags flags{reader_.etw_running(), events_since_};
        StitchResult stitched =
           stitch_registry_tick(candidates, batch.items, epochs, flags, now, snapshot_id);
        for (auto& r : stitched.rows)
            rows.push_back(std::move(r));

        cur.tick += 1;
        cur.held = std::move(stitched.held_next);
        cur.hku = sids;
        // No future window starts before the minimum window_base, nor does any held one
        // start before its own lo: an epoch ending before both can never intersect again.
        const std::int64_t watermark = retention_watermark(cur.roots);
        std::int64_t floor = watermark;
        for (const auto& h : cur.held)
            floor = std::min(floor, h.window_lo);
        age_loss_epochs(epochs, floor);
        cur.loss = std::move(epochs);

        const std::string new_cursor = encode_registry_cursor(cur);
        if (auto ins = db.insert_registry_events_and_cursor(rows, new_cursor, state_writes); !ins) {
            if (ins.error() == TarDatabase::CursorInsertError::KeyCollision)
                spdlog::critical("TAR registry: record_key COLLISION -- a persisted field is "
                                 "not deterministically re-derivable (tar_cursor.hpp rule 3a). "
                                 "Capture is STUCK and retrying cannot clear it.");
            throw IncompleteCaptureError("TAR registry: event/cursor commit failed");
        }
        rb.active = false; // committed: the dirty flags stay consumed

        // Only now may the transient state move (a failed commit re-derives all of it: the
        // dirty flags above, the buffer, the loss counters and the totals stay untouched).
        reader_.buffer->retire(batch.last_seq, [&](const RegistryEtwEvent& e) {
            return release_event(e, watermark, cur.held);
        });
        reader_.buffer->reset_drop_range(drops.count);
        last_reported_drops_ = drops.count;
        last_reported_kernel_ = kernel_total;
        query_failures_ += fail_now;
        last_query_ts_ = now;
        pending_gap_ = false;
        force_all_ = false;
        totals_.attributed += stitched.counters.attributed;
        totals_.ambiguous += stitched.counters.ambiguous;
        totals_.none += stitched.counters.none;

        // Status keys (always written, skipped when unchanged).
        std::size_t unarmed = 0, unreadable = 0, capped = 0;
        for (const auto& [_, st] : cur.roots) {
            unarmed += st.armed ? 0 : 1;
            unreadable += st.status == "unreadable" ? 1 : 0;
            capped += st.status == "capped" ? 1 : 0;
        }
        const std::pair<const char*, std::string> keys[] = {
           // The key watch is always what detects; the session only names the writer.
           {"registry_capture_method", reader_.etw_running() ? "notify+etw" : "notify"},
           {"registry_etw_events", std::to_string(reader_.buffer->pushed())},
           {"registry_etw_dropped", std::to_string(drops.count)},
           {"registry_etw_lost", std::to_string(kernel_total)},
           {"registry_attr_attributed", std::to_string(totals_.attributed)},
           {"registry_attr_ambiguous", std::to_string(totals_.ambiguous)},
           {"registry_attr_none", std::to_string(totals_.none)},
           {"registry_watch_roots", std::to_string(roots.size())},
           {"registry_watch_roots_unarmed", std::to_string(unarmed)},
           {"registry_roots_unreadable", std::to_string(unreadable)},
           {"registry_roots_capped", std::to_string(capped)},
        };
        for (const auto& [k, v] : keys) {
            auto& last = last_status_written_[k];
            if (last != v && db.set_config(k, v))
                last = v;
        }

        CursorCollectResult result;
        result.new_cursor_json = new_cursor;
        result.events_emitted = rows.size();
        result.outcome = (cursor_lost || (gap_pending && cause == GapCause::Disabled))
                            ? CursorOutcome::CursorLost
                            : (fresh ? CursorOutcome::Baseline : CursorOutcome::Advanced);
        return result;
    } catch (const IncompleteCaptureError&) {
        throw; // rb restores the dirty flags
    } catch (const std::exception& e) {
        // The CursorSource contract: collect() throws only IncompleteCaptureError.
        throw IncompleteCaptureError(std::string("TAR registry: collect failed: ") + e.what());
    }
}

std::unique_ptr<RegistryCursorSource> make_registry_cursor_source(RegistryScope scope,
                                                                  RegistryReader reader) {
    return std::make_unique<RegistryCursorSource>(std::move(scope), std::move(reader));
}

} // namespace yuzu::tar

// ═══════════════════════════════════════════════════════════════════════════
// Windows: Kernel-Registry ETW session + key-watch thread + budgeted reader
// ═══════════════════════════════════════════════════════════════════════════
#ifdef _WIN32

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

#include <guard_win_handle.hpp> // yuzu::agent::detail::EventHandle (agents/core/src)
#include <win_reg_handle.hpp>   // yuzu::win::RegKey
#include <win_str.hpp>          // yuzu::win wide<->UTF-8

#include "tar_win_process_name.hpp" // process_basename_for_pid

#include <atomic>
#include <thread>
#include <unordered_map>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef REG_NOTIFY_THREAD_AGNOSTIC
#define REG_NOTIFY_THREAD_AGNOSTIC 0x10000000L // Windows 8+; older SDK headers omit it
#endif

namespace yuzu::tar {

namespace {

using yuzu::agent::detail::EventHandle;

// run()'s handles[] -> slot index map: these two stand for the control events.
constexpr std::size_t kStopIdx = static_cast<std::size_t>(-1);
constexpr std::size_t kHkuIdx = static_cast<std::size_t>(-2);

// The registry's maximum value-name length, in characters (the buffer adds the NUL).
constexpr std::size_t kMaxValueNameChars = 16383;

// Microsoft-Windows-Kernel-Registry: {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
constexpr GUID kKernelRegistryGuid = {
    0x70eb4f03, 0xc1de, 0x4f73, {0xa0, 0x51, 0x33, 0xd1, 0x3d, 0x54, 0x13, 0xbd}};
constexpr USHORT kEvDeleteKey = 3;
constexpr USHORT kEvSetValueKey = 5;
constexpr USHORT kEvDeleteValueKey = 6;

std::int64_t filetime_now() {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return static_cast<std::int64_t>((static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) |
                                     ft.dwLowDateTime);
}

// ── The Kernel-Registry ETW half ────────────────────────────────────────────

// Named-property readers (TDH decodes by NAME so a layout change across builds is
// tolerated). false = absent or torn: the caller counts a decode failure.
bool prop_u32(EVENT_RECORD* rec, const wchar_t* name, std::uint32_t& out) {
    PROPERTY_DATA_DESCRIPTOR pdd{};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(name);
    pdd.ArrayIndex = ULONG_MAX;
    ULONG val = 0;
    if (TdhGetProperty(rec, 0, nullptr, 1, &pdd, sizeof(val), reinterpret_cast<PBYTE>(&val)) !=
        ERROR_SUCCESS)
        return false;
    out = static_cast<std::uint32_t>(val);
    return true;
}

// ValueName; the default value ("") is a legitimate 2-byte (NUL only) property.
bool prop_string(EVENT_RECORD* rec, const wchar_t* name, std::string& out) {
    PROPERTY_DATA_DESCRIPTOR pdd{};
    pdd.PropertyName = reinterpret_cast<ULONGLONG>(name);
    pdd.ArrayIndex = ULONG_MAX;
    ULONG size = 0;
    if (TdhGetPropertySize(rec, 0, nullptr, 1, &pdd, &size) != ERROR_SUCCESS)
        return false;
    if (size <= sizeof(wchar_t)) {
        out.clear();
        return true;
    }
    std::vector<wchar_t> buf(size / sizeof(wchar_t) + 1, L'\0');
    if (TdhGetProperty(rec, 0, nullptr, 1, &pdd, size, reinterpret_cast<PBYTE>(buf.data())) !=
        ERROR_SUCCESS)
        return false;
    out = yuzu::win::from_wide(buf.data());
    return true;
}

// Owns a started trace session: its handle and the EVENT_TRACE_PROPERTIES block (with
// the session name behind it) every ControlTrace call needs. reset() stops the session
// by handle. The destructor is the safety net, WinEtw::stop() orders teardown.
struct TraceSession {
    TRACEHANDLE h = 0;
    std::vector<BYTE> buf; // EVENT_TRACE_PROPERTIES + the session name

    TraceSession() = default;
    TraceSession(const TraceSession&) = delete;
    TraceSession& operator=(const TraceSession&) = delete;
    ~TraceSession() { reset(); }

    EVENT_TRACE_PROPERTIES* props() { return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data()); }

    // (Re)initialise the properties block for `name_bytes` of session name.
    void init(std::size_t name_bytes) {
        buf.assign(sizeof(EVENT_TRACE_PROPERTIES) + name_bytes, 0);
        props()->Wnode.BufferSize = static_cast<ULONG>(buf.size());
        props()->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props()->Wnode.ClientContext = 2; // system-time timestamps: FILETIME, now_ts's clock
        props()->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props()->FlushTimer = 1; // flush every 1 s so low-volume events deliver promptly
        props()->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    }

    void reset() noexcept {
        if (h == 0)
            return;
        ControlTraceW(h, nullptr, props(), EVENT_TRACE_CONTROL_STOP);
        h = 0;
    }
};

// Owns the OpenTrace consumer handle; reset() is CloseTrace, which is also what
// unblocks a ProcessTrace running on another thread.
struct TraceConsumer {
    TRACEHANDLE h = INVALID_PROCESSTRACE_HANDLE;

    TraceConsumer() = default;
    TraceConsumer(const TraceConsumer&) = delete;
    TraceConsumer& operator=(const TraceConsumer&) = delete;
    ~TraceConsumer() { reset(); }

    void reset() noexcept {
        if (h == INVALID_PROCESSTRACE_HANDLE)
            return;
        CloseTrace(h);
        h = INVALID_PROCESSTRACE_HANDLE;
    }
};

// One real-time session, write-only mask, decoded by name into the shared buffer.
// The ProcessTrace callback is serial, so the pid-name cache needs no lock.
struct WinEtw {
    std::mutex mu; // serialises start / stop / loss (they share the session block)
    TraceSession session;
    TraceConsumer consumer;
    std::thread worker;
    std::wstring session_name;
    std::shared_ptr<RegistryEtwBuffer> buffer;
    std::atomic<bool> running{false};
    std::atomic<std::uint64_t> decode_failed{0};
    std::unordered_map<std::uint32_t, std::string> pid_name; // ProcessTrace thread only
    std::int64_t pid_name_flushed{0};                        // ProcessTrace thread only
    static constexpr std::size_t kPidNameCap = 65536;
    // A pid can be reused, so a cached name goes stale. Flushed this often (FILETIME), which
    // is the default slow tick (tar.yaml slow_interval): a reused pid names stale for at
    // most one tick at the default cadence.
    static constexpr std::int64_t kPidNameFlush100ns = 300LL * 10'000'000;

    ~WinEtw() { stop(); }

    // Idempotent, and the ONLY place that orders teardown: CloseTrace first (it is what
    // unblocks ProcessTrace), then join the worker, then stop the session. The members'
    // destructors repeat this as a safety net but cannot order it across the join.
    void stop() noexcept {
        std::lock_guard lock(mu);
        teardown_locked();
    }

    // noexcept: runs across the ETW (C) frame, where an escaping C++ exception is
    // undefined behaviour. A failed decode costs one event and is COUNTED (it breaks the
    // "every write produced an event" invariant the attribution rests on), never silent.
    static void WINAPI on_event(EVENT_RECORD* rec) noexcept {
        auto* self = static_cast<WinEtw*>(rec->UserContext);
        try {
            if (self == nullptr || !IsEqualGUID(rec->EventHeader.ProviderId, kKernelRegistryGuid))
                return;
            const USHORT id = rec->EventHeader.EventDescriptor.Id;
            if (id != kEvSetValueKey && id != kEvDeleteValueKey && id != kEvDeleteKey)
                return;
            RegistryEtwEvent ev;
            std::uint32_t status = 0;
            if (!prop_u32(rec, L"Status", status)) {
                self->decode_failed.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (status != 0)
                return; // the operation failed: nothing changed
            ev.ts100ns = rec->EventHeader.TimeStamp.QuadPart;
            ev.pid = rec->EventHeader.ProcessId;
            if (id == kEvDeleteKey) {
                ev.op = RegistryEtwOp::DeleteKey;
            } else {
                ev.op = id == kEvSetValueKey ? RegistryEtwOp::Set : RegistryEtwOp::DeleteValue;
                bool ok = prop_string(rec, L"ValueName", ev.value);
                if (ok && id == kEvSetValueKey)
                    ok = prop_u32(rec, L"Type", ev.type) && prop_u32(rec, L"DataSize", ev.size);
                if (!ok) {
                    self->decode_failed.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
            }
            if (ev.ts100ns - self->pid_name_flushed > kPidNameFlush100ns) {
                self->pid_name.clear();
                self->pid_name_flushed = ev.ts100ns;
            }
            auto it = self->pid_name.find(ev.pid);
            if (it == self->pid_name.end()) {
                if (self->pid_name.size() >= kPidNameCap)
                    self->pid_name.clear(); // wholesale flush: no past-cap naming blackout
                it = self->pid_name.emplace(ev.pid, process_basename_for_pid(ev.pid)).first;
            }
            ev.image = it->second;
            self->buffer->push(std::move(ev));
        } catch (...) {
            if (self != nullptr)
                self->decode_failed.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // false = the session could not be opened (not elevated, or the provider is refused):
    // the key watch still runs and rows carry attr:off.
    bool start() noexcept {
        try {
            std::lock_guard lock(mu);
            if (running.load())
                return true;
            session_name = registry_etw_session_name();
            const std::size_t name_bytes = (session_name.size() + 1) * sizeof(wchar_t);
            session.init(name_bytes);
            ULONG rc = StartTraceW(&session.h, session_name.c_str(), session.props());
            // Pid reuse after a crash: a session is a kernel object that outlives its process,
            // so the predecessor's carries this pid's name. Stop it and retry once, else this
            // run is attr:off and the leaked session runs until reboot.
            if (rc == ERROR_ALREADY_EXISTS) {
                ControlTraceW(0, session_name.c_str(), session.props(), EVENT_TRACE_CONTROL_STOP);
                session.init(name_bytes);
                rc = StartTraceW(&session.h, session_name.c_str(), session.props());
            }
            if (rc != ERROR_SUCCESS) {
                session.h = 0; // nothing was started: nothing for reset() to stop
                return false;
            }
            ENABLE_TRACE_PARAMETERS params{};
            params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            rc = EnableTraceEx2(session.h, &kKernelRegistryGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, kEtwKeywordMask, 0, 0, &params);
            if (rc != ERROR_SUCCESS) {
                teardown_locked();
                return false;
            }
            EVENT_TRACE_LOGFILEW logfile{};
            logfile.LoggerName = const_cast<LPWSTR>(session_name.c_str());
            logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.EventRecordCallback = &WinEtw::on_event;
            logfile.Context = this;
            consumer.h = OpenTraceW(&logfile);
            if (consumer.h == INVALID_PROCESSTRACE_HANDLE) {
                teardown_locked();
                return false;
            }
            running.store(true);
            // The worker takes its own copy of the handle: nothing is shared with the thread
            // that later resets `consumer`.
            worker = std::thread([this, handle = consumer.h]() mutable {
                try {
                    // Blocks until CloseTrace() (stop()) -- or returns on its own if the
                    // session dies. Either way, mark not-running so a dead session reads as
                    // attr:off rather than as a quiet registry.
                    ProcessTrace(&handle, 1, nullptr, nullptr);
                } catch (...) {
                    // nothing to release; fall through to the not-running mark
                }
                running.store(false, std::memory_order_relaxed);
            });
            return true;
        } catch (...) {
            // bad_alloc / system_error (the thread): tear down whatever was opened.
            stop();
            return false;
        }
    }

    // The session's own loss counters (ControlTraceW QUERY by name).
    SessionLoss loss() noexcept {
        SessionLoss out;
        out.decode_failed = decode_failed.load(std::memory_order_relaxed);
        std::lock_guard lock(mu);
        if (!running.load() || session.h == 0)
            return out; // no live session: etw_running() says so, and attr:off marks the rows
        session.props()->Wnode.BufferSize = static_cast<ULONG>(session.buf.size());
        session.props()->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        session.props()->LogFileNameOffset = 0;
        if (ControlTraceW(0, session_name.c_str(), session.props(), EVENT_TRACE_CONTROL_QUERY) !=
            ERROR_SUCCESS) {
            out.query_ok = false;
            return out;
        }
        out.events_lost = session.props()->EventsLost;
        out.rt_buffers_lost = session.props()->RealTimeBuffersLost;
        return out;
    }

private:
    void teardown_locked() noexcept {
        running.store(false, std::memory_order_relaxed);
        consumer.reset(); // CloseTrace: unblocks ProcessTrace
        if (worker.joinable())
            worker.join();
        session.reset(); // ControlTrace STOP
    }
};

HKEY hive_of(std::string_view token) {
    return token == "HKU" ? HKEY_USERS : HKEY_LOCAL_MACHINE;
}

// Opens the root's key for the given access. REG_OPTION_OPEN_LINK: a root that is itself a
// symbolic-link key is opened as the link and never followed, so a link a user plants can
// not point this agent's SYSTEM token at a protected key. Defence in depth -- the kernel's
// untrusted-hive link check is the primary control and is not relied on. The flag covers
// the final path component only; an intermediate link (CurrentControlSet is one, by design)
// is the kernel's to resolve.
LONG open_root(const std::string& root, REGSAM access, yuzu::win::RegKey& out) {
    auto [hive, rest] = split_hive(root);
    return RegOpenKeyExW(hive_of(hive), yuzu::win::to_wide(rest).c_str(), REG_OPTION_OPEN_LINK,
                         access | KEY_WOW64_64KEY, out.put());
}

// The key-watch half: one thread waiting on (stop, HKEY_USERS name watch, up to
// kWatchHandleCap root events). On a signal it marks the root dirty with a precise
// timestamp and RE-ARMS at once; a re-arm failure leaves the root unarmed, which the
// collect tick reports and retries (it reads an unarmed root every tick meanwhile).
struct WinWatcher {
    struct Slot {
        std::string root;
        EventHandle event;
        yuzu::win::RegKey key;
        bool armed{false};
    };

    std::shared_ptr<RegistryDirtyTable> dirty;
    std::mutex mu; // guards slots (key + armed) and `live` between the thread and the collect tick
    std::vector<Slot> slots;
    EventHandle stop_event;
    EventHandle hku_event;
    yuzu::win::RegKey hku_key;
    std::thread thread;
    bool live{false}; // a watcher thread is running; arming is only trusted while it is

    ~WinWatcher() { shutdown(); }

    static bool arm(Slot& s) {
        s.key.reset();
        if (open_root(s.root, KEY_NOTIFY, s.key) != ERROR_SUCCESS) {
            s.armed = false;
            return false;
        }
        ResetEvent(s.event.get());
        s.armed = RegNotifyChangeKeyValue(s.key.get(), TRUE,
                                          REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET |
                                             REG_NOTIFY_THREAD_AGNOSTIC,
                                          s.event.get(), TRUE) == ERROR_SUCCESS;
        if (!s.armed)
            s.key.reset();
        return s.armed;
    }

    // No live watcher: every root is unarmed, so the collect tick reads each one every
    // tick (reconcile-only coverage) instead of trusting a watch that is not there.
    // noexcept: the catch handlers below call this, and its one throwing operation is the
    // lock -- whose failure means the mutex is unusable and the agent cannot continue safely
    // either way. noexcept makes that terminate explicit here, not implicit in the call sites.
    void unarm_all() noexcept {
        std::lock_guard lock(mu);
        live = false;
        for (auto& s : slots)
            s.armed = false;
    }

    void shutdown() {
        if (stop_event)
            SetEvent(stop_event.get());
        if (thread.joinable())
            thread.join();
        std::lock_guard lock(mu);
        live = false;
        slots.clear(); // closes each slot's key, then its event
        hku_key.reset();
        hku_event.reset();
        stop_event.reset();
    }

    // Replaces the watch with one over `roots`. Roots past the handle cap get no
    // event: they stay unarmed and are covered by the reconcile read.
    void watch(const std::vector<std::string>& roots) {
        shutdown();
        try {
            stop_event.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
            hku_event.reset(CreateEventW(nullptr, FALSE, FALSE, nullptr));
            // Without both control events the wait would fail at once and the thread exit
            // while every slot still claimed to be armed: report the truth, no watch.
            const bool can_watch = stop_event && hku_event;
            std::lock_guard lock(mu);
            for (std::size_t i = 0; i < roots.size(); ++i) {
                Slot s;
                s.root = roots[i];
                if (can_watch && i < kWatchHandleCap) {
                    s.event.reset(CreateEventW(nullptr, FALSE, FALSE, nullptr));
                    if (s.event)
                        arm(s);
                }
                slots.push_back(std::move(s));
            }
            if (!can_watch)
                return;
            if (RegOpenKeyExW(HKEY_USERS, L"", 0, KEY_NOTIFY, hku_key.put()) == ERROR_SUCCESS)
                RegNotifyChangeKeyValue(hku_key.get(), FALSE, REG_NOTIFY_CHANGE_NAME |
                                                                  REG_NOTIFY_THREAD_AGNOSTIC,
                                        hku_event.get(), TRUE);
            live = true; // before the thread can run: it re-arms through the same lock
            thread = std::thread([this] { run(); });
        } catch (...) {
            // bad_alloc / system_error while building the watch.
            unarm_all();
        }
    }

    void run() {
        bool stopped = false;
        try {
            stopped = wait_loop();
        } catch (...) {
            // bad_alloc / system_error on this thread would be std::terminate and take the
            // agent with it: end the watch instead and say so, below.
        }
        if (!stopped)
            unarm_all();
    }

    // True when stopped on purpose; false when the wait itself failed.
    bool wait_loop() {
        std::vector<HANDLE> handles;
        std::vector<std::size_t> slot_of; // handles[i] -> slot index (kStopIdx/kHkuIdx for the controls)
        {
            std::lock_guard lock(mu);
            handles.push_back(stop_event.get());
            slot_of.push_back(kStopIdx);
            handles.push_back(hku_event.get());
            slot_of.push_back(kHkuIdx);
            for (std::size_t i = 0; i < slots.size(); ++i)
                if (slots[i].event) {
                    handles.push_back(slots[i].event.get());
                    slot_of.push_back(i);
                }
        }
        for (;;) {
            const DWORD w = WaitForMultipleObjects(static_cast<DWORD>(handles.size()),
                                                   handles.data(), FALSE, INFINITE);
            if (w == WAIT_OBJECT_0)
                return true;
            if (w >= WAIT_OBJECT_0 + handles.size())
                return false; // a wait failure (never spin on one)
            const std::size_t which = slot_of[w - WAIT_OBJECT_0];
            if (which == kHkuIdx) {
                dirty->mark_hku();
                std::lock_guard lock(mu);
                if (hku_key)
                    RegNotifyChangeKeyValue(hku_key.get(), FALSE,
                                            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC,
                                            hku_event.get(), TRUE);
                continue;
            }
            std::lock_guard lock(mu);
            auto& s = slots[which];
            dirty->mark(s.root, filetime_now());
            arm(s); // re-arm immediately; a failure leaves it unarmed for the collect tick
        }
    }

    bool armed(const std::string& root) {
        std::lock_guard lock(mu);
        for (const auto& s : slots)
            if (s.root == root)
                return s.armed;
        return false;
    }

    bool rearm(const std::string& root) {
        std::lock_guard lock(mu);
        if (!live)
            return false; // nothing is waiting on the events: arming would only look armed
        for (auto& s : slots)
            if (s.root == root)
                return s.event && arm(s);
        return false;
    }
};

// ── The budgeted four-status subtree reader ─────────────────────────────────

struct ReadCtx {
    SubtreeRead* out;
    RegistryReadBudget budget;
    std::int64_t deadline;
    bool capped{false};
    bool unreadable{false};
    std::vector<BYTE> data;
    // Sized once per root to the registry's maximum name, so an ERROR_MORE_DATA from
    // RegEnumValueW can only mean the DATA buffer.
    std::vector<wchar_t> name = std::vector<wchar_t>(kMaxValueNameChars + 1);
};

// What RegQueryInfoKeyW says about one key, taken before and after its enumeration so a write
// that landed during the walk is detectable (see read_key).
struct KeyInfo {
    DWORD n_sub{0}, max_sub{0}, n_val{0}, max_data{0};
    FILETIME written{};

    bool operator==(const KeyInfo& o) const {
        return n_sub == o.n_sub && n_val == o.n_val && CompareFileTime(&written, &o.written) == 0;
    }
};

LONG query_key(HKEY key, KeyInfo& out) {
    return RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &out.n_sub, &out.max_sub, nullptr,
                            &out.n_val, nullptr, &out.max_data, nullptr, &out.written);
}

void read_key(ReadCtx& ctx, HKEY key, const std::string& full, std::size_t depth) {
    if (ctx.capped || ctx.unreadable)
        return;
    if (!RegistryReadBudget::depth_ok(depth) || !ctx.budget.admit_key() ||
        filetime_now() >= ctx.deadline) {
        ctx.capped = true;
        return;
    }
    KeyInfo before;
    if (query_key(key, before) != ERROR_SUCCESS) {
        ctx.unreadable = true;
        return;
    }
    const DWORD max_sub = before.max_sub, max_data = before.max_data;
    auto& values = ctx.out->keys[full]; // present even when empty: a vanished key is detectable
    // lpData is never null: with a null buffer RegEnumValueW answers ERROR_SUCCESS and only
    // reports the size, so a value that grew since QueryInfoKey would be copied from nullptr.
    const std::size_t buf_len =
       std::max<std::size_t>(std::min<std::size_t>(max_data, kBaselineValueReadCap), 1);
    if (ctx.data.size() < buf_len)
        ctx.data.resize(buf_len);
    for (DWORD i = 0;; ++i) {
        DWORD nlen = static_cast<DWORD>(ctx.name.size());
        DWORD type = 0, dlen = static_cast<DWORD>(ctx.data.size());
        LONG rc = RegEnumValueW(key, i, ctx.name.data(), &nlen, nullptr, &type, ctx.data.data(), &dlen);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc == ERROR_MORE_DATA && nlen >= ctx.name.size()) {
            // The NAME did not fit (not expected at the registry maximum): nothing may be
            // recorded under a partial name. Mark the read partial so the next one revisits.
            // (Only for MORE_DATA: on any other error nlen is unset and the else branch below
            // ends the key, so this `continue` always advances toward ERROR_NO_MORE_ITEMS.)
            ctx.capped = true;
            continue;
        }
        RegistryValueRead v;
        v.type = type;
        if (rc == ERROR_MORE_DATA || (rc == ERROR_SUCCESS && dlen > ctx.data.size())) {
            // Larger than the read cap (or grew since QueryInfo): the API gives no
            // partial read, so keep the size and let the hash cover nothing.
            v.full_size = dlen;
            v.truncated = true;
        } else if (rc == ERROR_SUCCESS) {
            v.full_size = dlen;
            v.bytes.assign(reinterpret_cast<const char*>(ctx.data.data()), dlen);
        } else {
            ctx.unreadable = true;
            return;
        }
        if (!ctx.budget.admit_value(v.bytes.size())) {
            ctx.capped = true;
            return;
        }
        values[yuzu::win::from_wide(ctx.name.data(), static_cast<int>(nlen))] = std::move(v);
    }
    if (ctx.capped)
        return; // a value was left unread: the read is partial, do not walk on

    std::vector<wchar_t> sub(static_cast<std::size_t>(max_sub) + 2);
    for (DWORD i = 0;; ++i) {
        DWORD slen = static_cast<DWORD>(sub.size());
        const LONG rc = RegEnumKeyExW(key, i, sub.data(), &slen, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        if (rc != ERROR_SUCCESS) {
            ctx.unreadable = true;
            return;
        }
        const std::string child_path =
           full + "\\" + yuzu::win::from_wide(sub.data(), static_cast<int>(slen));
        yuzu::win::RegKey child;
        // OPEN_LINK: a child that is a symbolic-link key is read as the link (its own
        // SymbolicLinkValue), never followed into whatever it points at.
        const LONG orc = RegOpenKeyExW(key, sub.data(), REG_OPTION_OPEN_LINK, KEY_READ | KEY_WOW64_64KEY,
                                       child.put());
        if (orc == ERROR_FILE_NOT_FOUND || orc == ERROR_KEY_DELETED)
            continue; // deleted between enumerate and open: the next read sees it gone
        if (orc == ERROR_ACCESS_DENIED) {
            // A child this agent may not read hides only itself: record it and read on. The
            // diff keeps what the baseline holds beneath it, and collect() reports the gap.
            if (ctx.out->skipped.size() >= kSkippedCap) {
                ctx.capped = true; // too many to track: a partial read, so no removals
                return;
            }
            ctx.out->skipped.push_back(child_path);
            continue;
        }
        if (orc != ERROR_SUCCESS) {
            ctx.unreadable = true; // any other failure: a partial read proves nothing
            return;
        }
        read_key(ctx, child.get(), child_path, depth + 1);
        if (ctx.capped || ctx.unreadable)
            return;
    }

    // Both enumerations above are index-driven: an entry deleted at an index already passed
    // shifts the next one into it, so that one is never visited -- yet the read would end
    // Complete and a surviving value or key would be derived as removed. Counts and last-write
    // time are compared with the first query (the time catches a delete and a create that net
    // to the same count); any difference means this key was written to during the walk, so the
    // read is partial (Capped: no removals, and the root is read again next tick). A key that
    // can no longer be queried was deleted mid-walk, which is the same answer. Control flow
    // reaches here only when neither `capped` nor `unreadable` is set.
    KeyInfo after;
    if (query_key(key, after) != ERROR_SUCCESS || !(after == before))
        ctx.capped = true;
}

SubtreeRead read_root(const std::string& root, std::int64_t deadline) noexcept {
    SubtreeRead out;
    try {
        yuzu::win::RegKey key;
        const LONG rc = open_root(root, KEY_READ, key);
        if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND) {
            out.status = RegistryReadStatus::Absent;
            return out;
        }
        if (rc != ERROR_SUCCESS) {
            out.status = RegistryReadStatus::Unreadable;
            return out;
        }
        ReadCtx ctx{&out, {}, deadline, false, false, {}};
        read_key(ctx, key.get(), root, 0);
        if (ctx.unreadable) {
            out.keys.clear();
            out.skipped.clear();
            out.status = RegistryReadStatus::Unreadable;
        } else {
            out.status = ctx.capped ? RegistryReadStatus::Capped : RegistryReadStatus::Complete;
        }
    } catch (...) {
        out.keys.clear();
        out.skipped.clear();
        out.status = RegistryReadStatus::Unreadable;
    }
    return out;
}

int read_current_control_set() {
    yuzu::win::RegKey k;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\Select", 0, KEY_READ, k.put()) != ERROR_SUCCESS)
        return 0;
    DWORD v = 0, len = sizeof(v), type = 0;
    if (RegQueryValueExW(k.get(), L"Current", nullptr, &type, reinterpret_cast<BYTE*>(&v), &len) !=
            ERROR_SUCCESS ||
        type != REG_DWORD)
        return 0;
    return static_cast<int>(v);
}

std::vector<std::string> enumerate_hku() {
    std::vector<std::string> out;
    wchar_t buf[256];
    for (DWORD i = 0;; ++i) {
        DWORD len = 256;
        if (RegEnumKeyExW(HKEY_USERS, i, buf, &len, nullptr, nullptr, nullptr, nullptr) !=
            ERROR_SUCCESS)
            break;
        out.push_back(yuzu::win::from_wide(buf, static_cast<int>(len)));
    }
    return out;
}

} // namespace

std::wstring registry_etw_session_name() {
    // Salted per process: the CI pools run several agents as one OS identity, and a
    // fixed session name is a cross-job shared resource.
    return L"YuzuTarRegistryEtw-" + std::to_wstring(::GetCurrentProcessId());
}

RegistryReader make_windows_registry_reader() {
    auto dirty = std::make_shared<RegistryDirtyTable>();
    auto buffer = std::make_shared<RegistryEtwBuffer>();
    auto etw = std::make_shared<WinEtw>();
    etw->buffer = buffer;
    auto watcher = std::make_shared<WinWatcher>();
    watcher->dirty = dirty;

    RegistryReader r;
    r.dirty = dirty;
    r.buffer = buffer;
    r.read_subtree = [](const std::string& root, std::int64_t deadline) {
        return read_root(normalise_registry_path(root, read_current_control_set()), deadline);
    };
    r.loaded_sids = [] { return enumerate_hku(); };
    r.now_ts = [] { return filetime_now(); };
    r.etw_running = [etw] { return etw->running.load(); };
    r.session_loss = [etw] { return etw->loss(); };
    r.current_control_set = [] { return read_current_control_set(); };
    r.watch_roots = [watcher](const std::vector<std::string>& roots) { watcher->watch(roots); };
    r.root_armed = [watcher](const std::string& root) { return watcher->armed(root); };
    r.rearm = [watcher](const std::string& root) { return watcher->rearm(root); };
    // ponytail: a session that dies after start is not restarted -- capture_method flips to
    // notify and rows say attr:off; add a restart if that is ever seen in the field.
    r.start = [etw] {
        if (!etw->start())
            spdlog::warn("TAR registry: Kernel-Registry ETW session unavailable (not elevated?) "
                         "-- the key watch still runs, rows will carry attr:off");
    };
    // The session first: it is a system-wide kernel object that outlives a leaked handle,
    // where the watcher's resources die with the process.
    r.stop = [etw, watcher] {
        etw->stop();
        watcher->shutdown();
    };
    return r;
}

std::unique_ptr<CursorSource> make_registry_cursor_source() {
    return std::make_unique<RegistryCursorSource>(default_registry_scope(),
                                                  make_windows_registry_reader());
}

} // namespace yuzu::tar

#else // !_WIN32

namespace yuzu::tar {

std::unique_ptr<CursorSource> make_registry_cursor_source() { return nullptr; }

} // namespace yuzu::tar

#endif
