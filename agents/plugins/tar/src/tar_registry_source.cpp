/**
 * tar_registry_source.cpp -- the `registry` cursor-model TAR source.
 *
 * Cross-platform section: the collect() state machine over an injected
 * RegistryReader (unit-tested on every platform). Windows section (#ifdef
 * _WIN32): the RegNotifyChangeKeyValue watcher thread and the budgeted subtree
 * reader, wired into a RegistryReader by make_registry_cursor_source().
 * Off-Windows the production factory is nullptr.
 *
 * Design: tar_registry_parsers.hpp.
 */

#include "tar_registry_source.hpp"

#include "tar_capture_status.hpp" // IncompleteCaptureError
#include "tar_collectors.hpp"
#include "tar_db.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <format>
#include <set>
#include <string>

namespace yuzu::tar {

namespace {

constexpr const char* kEmptyBaselineJson = R"({"v":1,"keys":{}})";

std::string baseline_collector(const std::string& root) { return "registry:" + root; }

// The gap row text for child keys that denied read access: names the first few.
std::string denied_children_detail(const std::string& root, const std::vector<std::string>& denied) {
    constexpr std::size_t kShown = 3;
    std::string d = std::format("gap:unreadable:{} ({} child key(s) denied read access; their values "
                                "and anything beneath them are not read, and deletions beneath them "
                                "are not derived, until they can be): ",
                                root, denied.size());
    for (std::size_t i = 0; i < denied.size() && i < kShown; ++i)
        d += (i == 0 ? "" : "; ") + denied[i];
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
    // was down is found by the baseline diff. An unreadable cursor is treated the
    // same way.
    const auto cursor = db.get_cursor("registry");
    if (!cursor || cursor->has_value()) {
        pending_gap_ = true;
        gap_cause_ = GapCause::Restart;
        force_all_ = true;
    }
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
        // The watcher stays warm. The first tick after re-enable re-baselines every
        // root (forensic-pause contract), so the paused window's changes are never stored.
        was_disabled_ = true;
    } else if (was_disabled_) {
        pending_gap_ = true;
        gap_cause_ = GapCause::Disabled;
        was_disabled_ = false;
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
                    "found by the baseline diff"
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
            DiffResult diff = diff_registry_snapshot(
               base, rd, snap.first != 0 ? "notify" : "reconcile", read_end, fresh_root);
            for (const auto& c : diff.candidates)
                rows.push_back(registry_row_from_candidate(c, snapshot_id));
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
                if (rd.status == RegistryReadStatus::Capped)
                    st.skipped.assign(known.begin(), known.end());
                else
                    st.skipped = std::move(rd.skipped);
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
        }

        cur.tick += 1;
        cur.hku = sids;

        const std::string new_cursor = encode_registry_cursor(cur);
        if (auto ins = db.insert_registry_events_and_cursor(rows, new_cursor, state_writes); !ins) {
            if (ins.error() == TarDatabase::CursorInsertError::KeyCollision)
                spdlog::critical("TAR registry: record_key COLLISION -- a persisted field is "
                                 "not deterministically re-derivable (tar_cursor.hpp rule 3a). "
                                 "Capture is STUCK and retrying cannot clear it.");
            throw IncompleteCaptureError("TAR registry: event/cursor commit failed");
        }
        rb.active = false; // committed: the dirty flags stay consumed

        // Only now may the transient state move (a failed commit re-derives all of it).
        pending_gap_ = false;
        force_all_ = false;

        // Status keys (always written, skipped when unchanged).
        std::size_t unarmed = 0, unreadable = 0, capped = 0;
        for (const auto& [_, st] : cur.roots) {
            unarmed += st.armed ? 0 : 1;
            unreadable += st.status == "unreadable" ? 1 : 0;
            capped += st.status == "capped" ? 1 : 0;
        }
        const std::pair<const char*, std::string> keys[] = {
           {"registry_capture_method", "notify"},
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
// Windows: key-watch thread + budgeted reader
// ═══════════════════════════════════════════════════════════════════════════
#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <guard_win_handle.hpp> // yuzu::agent::detail::EventHandle (agents/core/src)
#include <win_reg_handle.hpp>   // yuzu::win::RegKey
#include <win_str.hpp>          // yuzu::win wide<->UTF-8

#include <thread>

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

std::int64_t filetime_now() {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return static_cast<std::int64_t>((static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) |
                                     ft.dwLowDateTime);
}

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
    void unarm_all() {
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

void read_key(ReadCtx& ctx, HKEY key, const std::string& full, std::size_t depth) {
    if (ctx.capped || ctx.unreadable)
        return;
    if (!RegistryReadBudget::depth_ok(depth) || !ctx.budget.admit_key() ||
        filetime_now() >= ctx.deadline) {
        ctx.capped = true;
        return;
    }
    DWORD n_sub = 0, max_sub = 0, n_val = 0, max_data = 0;
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &n_sub, &max_sub, nullptr, &n_val,
                         nullptr, &max_data, nullptr, nullptr) != ERROR_SUCCESS) {
        ctx.unreadable = true;
        return;
    }
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

RegistryReader make_windows_registry_reader() {
    auto dirty = std::make_shared<RegistryDirtyTable>();
    auto watcher = std::make_shared<WinWatcher>();
    watcher->dirty = dirty;

    RegistryReader r;
    r.dirty = dirty;
    r.read_subtree = [](const std::string& root, std::int64_t deadline) {
        return read_root(normalise_registry_path(root, read_current_control_set()), deadline);
    };
    r.loaded_sids = [] { return enumerate_hku(); };
    r.now_ts = [] { return filetime_now(); };
    r.current_control_set = [] { return read_current_control_set(); };
    r.watch_roots = [watcher](const std::vector<std::string>& roots) { watcher->watch(roots); };
    r.root_armed = [watcher](const std::string& root) { return watcher->armed(root); };
    r.rearm = [watcher](const std::string& root) { return watcher->rearm(root); };
    r.stop = [watcher] { watcher->shutdown(); };
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
