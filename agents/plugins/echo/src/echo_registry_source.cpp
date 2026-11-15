/**
 * echo_registry_source.cpp -- the `registry` cursor-model Echo source.
 *
 * Cross-platform section: the collect() state machine over an injected
 * RegistryReader (unit-tested on every platform). Windows section (#ifdef
 * _WIN32): the Kernel-Registry ETW session, the RegNotifyChangeKeyValue watcher
 * thread and the budgeted subtree reader, wired into a RegistryReader by
 * make_registry_cursor_source(). Off-Windows the production factory is nullptr.
 *
 * Design and the exact meaning of the attribution: echo_registry_parsers.hpp.
 */

#include "echo_registry_source.hpp"

#include "echo_capture_status.hpp" // IncompleteCaptureError
#include "echo_collectors.hpp"
#include "echo_db.hpp"

#include <spdlog/spdlog.h>
#include <yuzu/log_token.hpp> // yuzu::log_key_token: a denied key name is user-chosen (CWE-117)

#include <algorithm>
#include <format>
#include <limits>
#include <set>
#include <string>

namespace yuzu::echo {

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

void RegistryCursorSource::start(EchoDatabase& db) {
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
    try {
        ensure_watch(scope_.roots_for(reader_.loaded_sids()));
    } catch (const IncompleteCaptureError& e) {
        // A partial list would arm a partial watch: arm nothing here. The first collect()
        // enumerates again (a restart's force_all_, a fresh baseline or the empty list all
        // force it) and, if that also fails, keeps the cursor and retries.
        spdlog::warn("Echo registry: the loaded user hives could not be listed at start-up ({}); "
                     "their watches arm on the first tick that can list them",
                     e.what());
    }
}

void RegistryCursorSource::stop() noexcept {
    try {
        reader_.stop();
    } catch (...) {
        // stop() must not throw (echo_cursor.hpp); nothing left to release.
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

CursorCollectResult RegistryCursorSource::collect(EchoDatabase& db,
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
               "re-baselined at its current state (echo_cursor.hpp rule 2)",
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
        const bool hourly = cur.tick % kReconcileEveryTicks == 0;
        const bool reconcile = hourly || force_all_;

        // The loaded user hives: re-enumerated on a name-watch signal, a reconcile
        // tick or a re-baseline, otherwise the cursor's list stands.
        const bool hku_changed = reader_.dirty->take_hku();
        rb.hku_taken = hku_changed;
        std::vector<std::string> sids = cur.hku;
        if (hku_changed || reconcile || rebaseline_all || sids.empty())
            sids = reader_.loaded_sids();
        // The unloaded profiles, asked for when the loaded list is re-enumerated for a reason
        // other than being empty (a name-watch mark, the reconcile, a re-baseline), while the
        // known list is empty, and again while the last walk was incomplete or a known profile
        // has no path yet (a user who just logged off during an incomplete walk). Re-enumerating
        // an empty loaded list does not walk by itself. The walk is classified against
        // THIS tick's `sids`, the one HKU snapshot every decision below uses, so a profile is
        // offline exactly when it is not in `sids`. An incomplete walk keeps the known list, and
        // a sid loaded last tick that is not now joins it (reconcile_offline): scope is removed
        // only when a complete walk shows the profile gone, never because a walk failed.
        const std::vector<std::string> prev_hku = cur.hku;
        const std::vector<OfflineProfile> prev_offline = cur.offline;
        std::vector<OfflineProfile> offline = cur.offline;
        bool discovery_incomplete = offline_incomplete_;
        const bool offline_unresolved =
           offline_incomplete_ ||
           std::any_of(offline.begin(), offline.end(),
                       [](const OfflineProfile& o) { return o.path.empty(); });
        if (hku_changed || reconcile || rebaseline_all || offline.empty() || offline_unresolved) {
            OfflineDiscovery d = reader_.offline_profiles(sids);
            offline = reconcile_offline(cur.offline, prev_hku, sids, d);
            // The ProfileList walk is index-driven: a profile deleted or renamed (X -> X.bak) while
            // it runs can be skipped though it is healthy, or its `.bak` sibling can be skipped so a
            // temporary profile's folder is listed alone. A change to a KNOWN profile's scope is
            // therefore taken only when two walks of this tick agree: a profile is removed only
            // when two complete walks both omit it (a user who has just logged off included), and
            // a path first learned or changed for it is adopted only when both walks list the SAME
            // path, otherwise its previous entry stands (pathless stays pathless and deferred) and
            // the next tick walks again. An incomplete second walk removes nothing.
            // `owed` is every profile a walk must still name (reconcile_offline's own `known`, so a
            // virtual service or system SID that unloaded is not one of them).
            const auto owed =
               reconcile_offline(cur.offline, prev_hku, sids, OfflineDiscovery{false, {}, {}});
            const auto find_sid = [](auto& v, const std::string& sid) {
                return std::find_if(v.begin(), v.end(),
                                    [&](const OfflineProfile& o) { return o.sid == sid; });
            };
            const auto changed = [&](const OfflineProfile& k) {
                const auto it = find_sid(offline, k.sid);
                return it == offline.end() || it->path != k.path; // dropped, filled or changed
            };
            if (std::any_of(owed.begin(), owed.end(), changed)) {
                d = reader_.offline_profiles(sids);
                const auto second = reconcile_offline(cur.offline, prev_hku, sids, d);
                for (const auto& k : owed) {
                    const auto p1 = find_sid(offline, k.sid);
                    const auto p2 = find_sid(second, k.sid);
                    if ((p1 == offline.end()) == (p2 == second.end()) &&
                        (p1 == offline.end() || p1->path == p2->path))
                        continue; // the walks agree: what walk 1 decided stands
                    if (p1 != offline.end())
                        *p1 = k; // the walks disagree: the previous entry stands
                    else
                        offline.push_back(k);
                }
                for (const auto& p : second) // a sid no earlier walk knew: adopt as before
                    if (find_sid(offline, p.sid) == offline.end())
                        offline.push_back(p);
            }
            discovery_incomplete = !d.complete;
        } else {
            std::erase_if(offline, [&](const OfflineProfile& o) {
                return std::find(sids.begin(), sids.end(), o.sid) != sids.end();
            });
        }
        const std::vector<std::string> live_roots = scope_.roots_for(sids);
        const std::vector<std::string> roots = scope_.roots_for(sids, offline);
        // Offline roots are never armed: there is no watch on an unloaded hive.
        ensure_watch(live_roots);
        std::set<std::string> offline_sids;
        for (const auto& o : offline)
            offline_sids.insert(o.sid);

        // Roots that left scope -- a profile two COMPLETE walks show gone from the profile list, or
        // a name that is no longer a profile hive (a logged-off user stays in scope as an offline
        // root, and a logon diffs against its baseline): drop their state and shrink the baseline
        // row, so a profile that reappears re-baselines from scratch, never as a mass removal of
        // what the unloaded hive "lost".
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

        // Live <-> offline transitions. A root that was loaded and is offline now drops its
        // loaded window_base and consumes its stale notify, so nothing from its loaded life
        // pins the ETW retention floor (the take is restored on a failed commit, like every
        // other). A root that was offline and is loaded now is due at once: its first loaded
        // read diffs against the offline baseline this tick.
        for (const auto& root : roots) {
            const std::string sid = hku_sid_of(root);
            if (sid.empty())
                continue;
            const auto sit = cur.roots.find(root);
            if (is_offline_root(root, offline_sids)) {
                if (std::find(prev_hku.begin(), prev_hku.end(), sid) != prev_hku.end()) {
                    if (sit != cur.roots.end())
                        sit->second.window_base = 0;
                    rb.taken.emplace_back(root, reader_.dirty->take(root));
                }
            } else if (sit != cur.roots.end() &&
                       std::any_of(prev_offline.begin(), prev_offline.end(),
                                   [&](const OfflineProfile& o) { return o.sid == sid; }) &&
                       (sit->second.status == "complete" || sit->second.status == "absent")) {
                sit->second.status = "due";
            }
        }

        // Per-root state reset for a re-baseline or a control-set switch.
        const auto init_state = [&](const std::string& root, RegistryRootState& st) {
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
        };

        // Everything that follows a read of one root: diff against its baseline, baseline
        // write, the unreadable / denied-child gap rows, and the root's state. `snap` is the
        // dirty state consumed before a live read (empty for an offline one); an offline root's
        // window_base never advances.
        const auto apply_read = [&](const std::string& root, RegistryRootState& st, SubtreeRead rd,
                                    std::int64_t read_start, std::int64_t read_end,
                                    const RegistryDirtyTable::Snap& snap, bool offline_root) {
            const std::int64_t last_dirty = reader_.dirty->last(root);

            RegistryBaseline base;
            bool fresh_root = !st.baselined;
            if (st.baselined && rd.status != RegistryReadStatus::Unreadable) {
                const auto stored = db.try_get_state(baseline_collector(root));
                if (!stored)
                    throw IncompleteCaptureError("Echo registry: baseline read failed: " +
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
            DiffResult diff = diff_registry_snapshot(
               base, rd, root, offline_root ? "offline" : (snap.first != 0 ? "notify" : "reconcile"),
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
                if (st.status != "unreadable") {
                    std::string detail = "gap:unreadable:" + root +
                                         " (the root could not be read; its baseline is kept and "
                                         "nothing is derived for it until it can be)";
                    if (!rd.reason.empty())
                        detail += " (" + rd.reason + ")";
                    rows.push_back(registry_gap_row("unreadable",
                                                    root + ":" + std::to_string(read_end),
                                                    std::move(detail), now, snapshot_id));
                }
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
                for (const auto& sk : rd.skipped)
                    if (known.insert(sk).second)
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
            if (!offline_root)
                st.deferred = false; // an owed offline read is moot once the hive is read as a loaded root
            st.status = std::string(to_string(rd.status));
            if (rd.status != RegistryReadStatus::Unreadable)
                st.baselined = true; // a Capped first read is a partial baseline, by design
            if (offline_root && fresh_root && rd.status == RegistryReadStatus::Capped)
                st.baselined = false; // ... but an offline one is retried (next tick) as a fresh root
            if (!offline_root &&
                (rd.status == RegistryReadStatus::Complete || rd.status == RegistryReadStatus::Absent))
                st.window_base = read_start; // the NEXT window starts here
        };

        // The loaded roots first (HKLM and the loaded hives), rotated so a tick that runs out of
        // budget resumes where it stopped. Offline hives come after them: a queue of logged-off
        // profiles can only ever take what the loaded roots left, never the budget a notified
        // loaded root was owed.
        const std::size_t n = live_roots.size();
        const std::size_t start_idx = n == 0 ? 0 : static_cast<std::size_t>(cur.tick) % n;
        bool read_any = false;
        for (std::size_t i = 0; i < n; ++i) {
            const std::string& root = live_roots[(start_idx + i) % n];
            RegistryRootState& st = cur.roots[root];
            init_state(root, st);

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
            apply_read(root, st, std::move(rd), read_start, read_end, snap, false);
        }

        // The offline hives, one mount each, deferred hives first, then the one read longest ago
        // (read_end is persisted per root), the sid breaking ties. Due on the HOURLY tick -- not on
        // a restart's force_all_, which exists for a lost notify or ETW buffer an unloaded hive
        // never had -- or when never read, re-baselined, Capped last time, or a retry; never on
        // a notify.
        struct HiveGroup {
            std::string sid, path;
            std::vector<std::string> roots;
            bool deferred{false};
            std::int64_t oldest_read{std::numeric_limits<std::int64_t>::max()};
        };
        std::map<std::string, std::vector<std::string>> roots_of_sid; // one pass, not one per hive
        for (const auto& r : roots)
            if (const std::string sid = hku_sid_of(r); !sid.empty())
                roots_of_sid[sid].push_back(r);
        std::vector<HiveGroup> groups;
        for (const auto& o : offline) {
            const auto found = roots_of_sid.find(o.sid);
            if (found == roots_of_sid.end())
                continue; // not a profile hive name: nothing to read
            HiveGroup g{o.sid, o.path, found->second};
            for (const auto& r : g.roots) {
                RegistryRootState& st = cur.roots[r];
                init_state(r, st);
                st.armed = true; // nothing to arm on an unloaded hive: that is not a defect
                g.deferred = g.deferred || st.deferred;
                g.oldest_read = std::min(g.oldest_read, st.read_end);
            }
            groups.push_back(std::move(g));
        }
        std::sort(groups.begin(), groups.end(), [](const HiveGroup& a, const HiveGroup& b) {
            if (a.deferred != b.deferred)
                return a.deferred;
            if (a.oldest_read != b.oldest_read)
                return a.oldest_read < b.oldest_read;
            return a.sid < b.sid;
        });
        for (const auto& g : groups) {
            const auto defer = [&] {
                for (const auto& r : g.roots)
                    cur.roots[r].deferred = true; // status untouched: a refused hive keeps its one gap row
            };
            // A profile whose path is not known yet (it logged off while the walk was incomplete)
            // cannot be mounted: it is never passed to the reader, keeps its baseline and status,
            // and is marked deferred so the first tick a complete walk supplies the path reads it,
            // not the next hour.
            if (g.path.empty()) {
                defer();
                continue;
            }
            const bool offline_due = std::any_of(g.roots.begin(), g.roots.end(), [&](const std::string& r) {
                const RegistryRootState& st = cur.roots[r];
                return hourly || st.deferred || st.status.empty() || st.status == "due" ||
                       st.status == "capped" || (!st.baselined && st.status != "unreadable");
            });
            if (!offline_due)
                continue;
            if (read_any && reader_.now_ts() >= deadline) {
                defer();
                continue;
            }
            read_any = true;

            const std::int64_t read_start = reader_.now_ts();
            OfflineHiveRead hv = reader_.read_offline_hive(g.sid, g.path, g.roots, deadline);
            const std::int64_t read_end = reader_.now_ts();
            if (!hv.attempted) {
                defer(); // not tried: retried next tick, no row
                continue;
            }
            for (const auto& r : g.roots) {
                RegistryRootState& gs = cur.roots[r];
                gs.deferred = false;
                SubtreeRead rd;
                if (const auto it = hv.roots.find(r); it != hv.roots.end()) {
                    rd = std::move(it->second);
                } else {
                    rd.status = RegistryReadStatus::Unreadable; // the mount answered nothing for it
                }
                if (rd.reason.empty() && rd.status == RegistryReadStatus::Unreadable)
                    rd.reason = hv.reason;
                apply_read(r, gs, std::move(rd), read_start, read_end, {}, true);
            }
        }

        // The buffer is read BEFORE the loss counters: an eviction between the two would
        // otherwise be in neither this tick's epochs nor the snapshot, and a candidate whose
        // true event was evicted could be correlated to one unrelated writer. Read in this
        // order every eviction the snapshot missed is counted, and a later one only adds
        // loss.
        const auto batch = reader_.buffer->snapshot();

        // Loss accounting. The drop range and the session counters are cumulative; what is
        // new since the last COMMITTED tick becomes one gap row and a loss epoch. A failed
        // loss query is itself loss: the session's counters are then unknown.
        const auto drops = reader_.buffer->drop_info();
        const SessionLoss sl = reader_.session_loss();
        // `now` was taken before the reads, which can run to the snapshot deadline, so the
        // counters above describe an instant later than it. A kernel loss in (now, here]
        // would lie in no epoch, and a window ending there could be correlated to a
        // bystander: the epoch ends at a stamp taken after the query, which is at or after
        // the instant the counter was read.
        const std::int64_t qnow = reader_.now_ts();
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
            append_loss_epoch(epochs, {last_query_ts_, qnow});
        if (drop_delta + kernel_delta > 0)
            rows.push_back(registry_gap_row("loss", std::to_string(now),
                                            std::format("gap:loss:{}", drop_delta + kernel_delta),
                                            now, snapshot_id));

        // Held candidates (from earlier ticks) and this tick's fresh ones, against the buffer.
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
        cur.offline = offline;
        // No future window starts before the minimum window_base, nor does any held one
        // start before its own lo: an epoch ending before both can never intersect again.
        // A root whose notify is still unread (the read budget deferred it, or it was marked
        // again during its own read) has no candidate yet, so its pending window is counted
        // here too: the event floor and the loss-epoch floor are one value.
        std::map<std::string, std::int64_t> pending_first;
        for (const auto& root : live_roots) // an offline root never holds the floor
            if (const auto first = reader_.dirty->first(root); first != 0)
                pending_first.emplace(root, first);
        const std::int64_t watermark = retention_watermark(cur.roots, pending_first);
        std::int64_t floor = watermark;
        for (const auto& h : cur.held)
            floor = std::min(floor, h.window_lo);
        age_loss_epochs(epochs, floor);
        cur.loss = std::move(epochs);

        const std::string new_cursor = encode_registry_cursor(cur);
        if (auto ins = db.insert_registry_events_and_cursor(rows, new_cursor, state_writes); !ins) {
            if (ins.error() == EchoDatabase::CursorInsertError::KeyCollision)
                spdlog::critical("Echo registry: record_key COLLISION -- a persisted field is "
                                 "not deterministically re-derivable (echo_cursor.hpp rule 3a). "
                                 "Capture is STUCK and retrying cannot clear it.");
            throw IncompleteCaptureError("Echo registry: event/cursor commit failed");
        }
        rb.active = false; // committed: the dirty flags stay consumed
        if (reader_.committed)
            reader_.committed(rows);

        // Only now may the transient state move (a failed commit re-derives all of it: the
        // dirty flags above, the buffer, the loss counters and the totals stay untouched).
        reader_.buffer->retire(batch.last_seq, [&](const RegistryEtwEvent& e) {
            return release_event(e, watermark, cur.held);
        });
        reader_.buffer->reset_drop_range(drops.count);
        last_reported_drops_ = drops.count;
        last_reported_kernel_ = kernel_total;
        query_failures_ += fail_now;
        // The next epoch starts at this tick's `now`, not at `qnow`: it overlaps these reads
        // on purpose, so a loss the next query reports still reaches a window that closed
        // while they ran (its events may have been dropped after this query).
        last_query_ts_ = now;
        pending_gap_ = false;
        force_all_ = false;
        totals_.attributed += stitched.counters.attributed;
        totals_.ambiguous += stitched.counters.ambiguous;
        totals_.none += stitched.counters.none;

        // Status keys (always written, skipped when unchanged).
        // watch_roots / unarmed describe the LIVE roots (an offline root has nothing to arm);
        // unreadable / capped stay aggregate over every root, so a capped offline read is visible.
        std::size_t unarmed = 0, unreadable = 0, capped = 0;
        std::size_t offline_roots = 0, offline_unreadable = 0, offline_deferred = 0;
        for (const auto& [name, st] : cur.roots) {
            const bool off = is_offline_root(name, offline_sids);
            unarmed += (!off && !st.armed) ? 1 : 0;
            unreadable += st.status == "unreadable" ? 1 : 0;
            capped += st.status == "capped" ? 1 : 0;
            offline_roots += off ? 1 : 0;
            offline_unreadable += (off && st.status == "unreadable") ? 1 : 0;
            offline_deferred += (off && st.deferred) ? 1 : 0;
        }
        if (discovery_incomplete && !offline_incomplete_)
            spdlog::warn("Echo registry: the profile list could not be read completely; the known "
                         "logged-off profiles stay in scope until a complete walk says otherwise");
        offline_incomplete_ = discovery_incomplete;
        const std::pair<const char*, std::string> keys[] = {
           // The key watch is always what detects; the session only names the writer.
           {"registry_capture_method", reader_.etw_running() ? "notify+etw" : "notify"},
           {"registry_etw_events", std::to_string(reader_.buffer->pushed())},
           {"registry_etw_dropped", std::to_string(drops.count)},
           {"registry_etw_lost", std::to_string(kernel_total)},
           {"registry_attr_attributed", std::to_string(totals_.attributed)},
           {"registry_attr_ambiguous", std::to_string(totals_.ambiguous)},
           {"registry_attr_none", std::to_string(totals_.none)},
           {"registry_watch_roots", std::to_string(live_roots.size())},
           {"registry_watch_roots_unarmed", std::to_string(unarmed)},
           {"registry_roots_unreadable", std::to_string(unreadable)},
           {"registry_roots_capped", std::to_string(capped)},
           {"registry_offline_roots", std::to_string(offline_roots)},
           {"registry_offline_roots_unreadable", std::to_string(offline_unreadable)},
           {"registry_offline_roots_deferred", std::to_string(offline_deferred)},
           {"registry_offline_discovery_incomplete", discovery_incomplete ? "1" : "0"},
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
        throw IncompleteCaptureError(std::string("Echo registry: collect failed: ") + e.what());
    }
}

std::unique_ptr<RegistryCursorSource> make_registry_cursor_source(RegistryScope scope,
                                                                  RegistryReader reader) {
    return std::make_unique<RegistryCursorSource>(std::move(scope), std::move(reader));
}

} // namespace yuzu::echo

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

#include <win_profiles.hpp> // with_user_hive, enumerate_profile_list (the shared guarded offline-hive ladder)

#include "bounded_wait.hpp"           // yuzu::shared::bounded_call_ex
#include "echo_hive_mount_gate.hpp"  // g_mount_workers_in_flight, MountWorkerGuard, kHiveMountBoundMs, pin_plugin_module
#include "echo_mapdrive_backfill.hpp" // decide_walk_gate, decide_mount_call, profile_list_complete
#include "echo_win_process_name.hpp" // process_basename_for_pid

#include <atomic>
#include <thread>
#include <unordered_map>

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef REG_NOTIFY_THREAD_AGNOSTIC
#define REG_NOTIFY_THREAD_AGNOSTIC 0x10000000L // Windows 8+; older SDK headers omit it
#endif

namespace yuzu::echo {

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
    // A size beyond the registry's longest value name is a torn property: refuse it before
    // allocating for it.
    if (size > (kMaxValueNameChars + 1) * sizeof(wchar_t))
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
    // ControlTrace needs room behind the properties for BOTH names it may write back (the
    // logger name and the log file name), each up to this many characters.
    static constexpr std::size_t kNameChars = 1024;

    TRACEHANDLE h = 0;
    std::vector<BYTE> buf; // EVENT_TRACE_PROPERTIES + room for the two names

    TraceSession() = default;
    TraceSession(const TraceSession&) = delete;
    TraceSession& operator=(const TraceSession&) = delete;
    ~TraceSession() { reset(); }

    EVENT_TRACE_PROPERTIES* props() { return reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buf.data()); }

    // (Re)initialise the properties block.
    void init() {
        buf.assign(sizeof(EVENT_TRACE_PROPERTIES) + 2 * kNameChars * sizeof(wchar_t), 0);
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
        props()->LogFileNameOffset = 0; // a QUERY may have set it: this is a real-time session
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
    // A pid can be reused, so a cached name goes stale. Flushed every 5 minutes
    // (FILETIME), so a reused pid names stale for at most that long.
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
                std::string name;
                bool ok = prop_string(rec, L"ValueName", name);
                if (ok && id == kEvSetValueKey)
                    ok = prop_u32(rec, L"Type", ev.type) && prop_u32(rec, L"DataSize", ev.size);
                if (!ok) {
                    self->decode_failed.fetch_add(1, std::memory_order_relaxed);
                    return;
                }
                ev.value_key = value_name_key(name); // the name itself is not kept
            }
            if (ev.ts100ns - self->pid_name_flushed > kPidNameFlush100ns) {
                self->pid_name.clear();
                self->pid_name_flushed = ev.ts100ns;
            }
            if (const auto it = self->pid_name.find(ev.pid); it != self->pid_name.end()) {
                ev.image = it->second;
            } else {
                // Looked up at delivery, and refused when a newer process already holds the pid
                // (created after this event), so the new holder is named at its own first event.
                // Only a name is cached: an empty result is retried at the next event.
                ev.image = process_basename_for_pid(ev.pid, ev.ts100ns);
                if (!ev.image.empty()) {
                    if (self->pid_name.size() >= kPidNameCap)
                        self->pid_name.clear(); // wholesale flush: no past-cap naming blackout
                    self->pid_name.emplace(ev.pid, ev.image);
                }
            }
            self->buffer->push(std::move(ev));
        } catch (...) {
            if (self != nullptr)
                self->decode_failed.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // ERROR_SUCCESS, or the Win32 error that stopped the session opening (access denied when
    // the agent is not elevated, no free logger slot, a refused provider): the key watch
    // still runs and rows carry attr:off.
    ULONG start() noexcept {
        try {
            std::lock_guard lock(mu);
            if (running.load())
                return ERROR_SUCCESS;
            // A session that ended on its own left a joinable worker and live handles: release
            // them before the members are assigned again.
            teardown_locked();
            session_name = registry_etw_session_name();
            session.init();
            ULONG rc = StartTraceW(&session.h, session_name.c_str(), session.props());
            // Pid reuse after a crash: a session is a kernel object that outlives its process,
            // so the predecessor's carries this pid's name. Stop it and retry once, else this
            // run is attr:off and the leaked session runs until reboot.
            if (rc == ERROR_ALREADY_EXISTS) {
                ControlTraceW(0, session_name.c_str(), session.props(), EVENT_TRACE_CONTROL_STOP);
                session.init();
                rc = StartTraceW(&session.h, session_name.c_str(), session.props());
            }
            if (rc != ERROR_SUCCESS) {
                session.h = 0; // nothing was started: nothing for reset() to stop
                return rc;
            }
            ENABLE_TRACE_PARAMETERS params{};
            params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
            rc = EnableTraceEx2(session.h, &kKernelRegistryGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                TRACE_LEVEL_INFORMATION, kEtwKeywordMask, 0, 0, &params);
            if (rc != ERROR_SUCCESS) {
                teardown_locked();
                return rc;
            }
            EVENT_TRACE_LOGFILEW logfile{};
            logfile.LoggerName = const_cast<LPWSTR>(session_name.c_str());
            logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.EventRecordCallback = &WinEtw::on_event;
            logfile.Context = this;
            consumer.h = OpenTraceW(&logfile);
            if (consumer.h == INVALID_PROCESSTRACE_HANDLE) {
                const ULONG err = GetLastError();
                teardown_locked();
                return err != ERROR_SUCCESS ? err : ERROR_INTERNAL_ERROR;
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
                // teardown_locked() clears `running` before CloseTrace, so finding it still
                // set means the session ended on its own: say so once.
                if (running.exchange(false)) {
                    try {
                        spdlog::warn("Echo registry: Kernel-Registry ETW session ended on its own; "
                                     "attribution reads attr:off until the agent restarts");
                    } catch (...) {
                        // a log failure must not terminate the agent from this thread
                    }
                }
            });
            return ERROR_SUCCESS;
        } catch (...) {
            // bad_alloc / system_error (the thread): tear down whatever was opened.
            stop();
            return ERROR_OUTOFMEMORY;
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
        // Not configuration (see registry_path_excluded): never opened, so its constant writes
        // cannot disturb the read of the rest of the root.
        if (registry_path_excluded(child_path))
            continue;
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
    if (query_key(key, after) != ERROR_SUCCESS || !(after == before)) {
        ctx.capped = true;
        return;
    }
    // The key's write time, published only now that the two queries agree: a row takes it as
    // its time. A key written during the walk, or one the walk left early (capped, unreadable),
    // gets no stamp, and its candidates fall back to the end of the read.
    ctx.out->written[full] = static_cast<std::int64_t>(
        (static_cast<std::uint64_t>(before.written.dwHighDateTime) << 32) |
        before.written.dwLowDateTime);
}

// Reads the subtree under an already-open `key`, labelling its key paths from `label` (never from
// the HKEY: an offline hive is mounted under a salted name the rows must not carry).
SubtreeRead read_root_at(HKEY key, const std::string& label, std::int64_t deadline) noexcept {
    SubtreeRead out;
    try {
        ReadCtx ctx{&out, {}, deadline, false, false, {}};
        read_key(ctx, key, label, 0);
        if (ctx.unreadable) {
            out.keys.clear();
            out.written.clear();
            out.skipped.clear();
            out.status = RegistryReadStatus::Unreadable;
        } else {
            out.status = ctx.capped ? RegistryReadStatus::Capped : RegistryReadStatus::Complete;
        }
    } catch (...) {
        out.keys.clear();
        out.written.clear();
        out.skipped.clear();
        out.status = RegistryReadStatus::Unreadable;
    }
    return out;
}

// Is `sid`'s hive gone from HKEY_USERS? A loaded profile's hive is HKU\<sid>; once the user logs
// off it is unloaded and the key no longer exists.
bool hku_hive_unloaded(const std::string& sid) {
    yuzu::win::RegKey key;
    const LONG rc =
       RegOpenKeyExW(HKEY_USERS, yuzu::win::to_wide(sid).c_str(), 0, KEY_READ, key.put());
    return rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND;
}

SubtreeRead read_root(const std::string& root, std::int64_t deadline) noexcept {
    SubtreeRead out;
    try {
        yuzu::win::RegKey key;
        const LONG rc = open_root(root, KEY_READ, key);
        if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND) {
            // The root is not there -- or its whole hive is not: a user who logged off after
            // collect() took its HKU snapshot (or before a missed name-watch mark refreshed it)
            // answers the same way. Absent would be read as "every value was deleted" and blank
            // the baseline; Unreadable keeps it, and the next HKU refresh moves the root offline,
            // where it stays Unreadable (counted in registry_offline_roots_unreadable) until the
            // hourly tick reads the hive and diffs it against that baseline. A key missing under
            // a hive that is still loaded stays Absent.
            const std::string sid = hku_sid_of(root);
            if (!sid.empty() && hku_hive_unloaded(sid)) {
                out.status = RegistryReadStatus::Unreadable;
                out.reason = "hive_unloaded";
                return out;
            }
            out.status = RegistryReadStatus::Absent;
            return out;
        }
        if (rc != ERROR_SUCCESS) {
            out.status = RegistryReadStatus::Unreadable;
            return out;
        }
        return read_root_at(key.get(), root, deadline);
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

// The loaded-user list is the one HKU snapshot collect() classifies profiles against, so a
// walk that ends on anything but ERROR_NO_MORE_ITEMS is a failed read: it throws
// IncompleteCaptureError (the cursor-source rule: a transient read failure keeps the cursor)
// instead of returning the names found so far, because a partial list would read a loaded
// user as logged off and drop that user's watch and dirty state. The end-of-list decision is
// walk_enumeration (echo_registry_parsers.hpp), which the unit suite runs on every platform.
std::vector<std::string> enumerate_hku() {
    wchar_t buf[256];
    auto walk = walk_enumeration([&](unsigned i, std::string& name, std::string& err) {
        DWORD len = 256;
        const LONG rc =
            RegEnumKeyExW(HKEY_USERS, i, buf, &len, nullptr, nullptr, nullptr, nullptr);
        if (rc == ERROR_SUCCESS) {
            name = yuzu::win::from_wide(buf, static_cast<int>(len));
            return ListStep::Item;
        }
        if (rc == ERROR_NO_MORE_ITEMS)
            return ListStep::End;
        err = "error " + std::to_string(rc);
        return ListStep::Error;
    });
    if (!walk.error.empty())
        throw IncompleteCaptureError("Echo registry: HKEY_USERS enumeration failed at " +
                                     walk.error);
    return std::move(walk.names);
}

// ── Offline (unloaded) per-user hives ───────────────────────────────────────

// The profiles whose hive is not loaded, from one ProfileList walk. This shell only gathers
// the facts (the walk's Win32 codes, the merged profile list, the sids whose record failed);
// classify_offline_discovery (echo_registry_parsers.hpp, unit-tested on every OS) decides.
// `loaded` is collect()'s own HKU snapshot for this tick, not a second enumeration: a profile
// is offline exactly when collect() does not hold it as loaded, so none can fall between two
// snapshots. `complete` is mapdrive's own rule (profile_list_complete, plus "not truncated"): a
// walk that was cut short, that hit an unreadable ProfileList or that stopped at the profile
// cap proves nothing about what is absent, so the core keeps the scope it knew.
OfflineDiscovery discover_offline_profiles(const std::vector<std::string>& loaded) noexcept {
    try {
        const auto disc = yuzu::win::enumerate_profile_list();
        if (disc.truncated) {
            static std::atomic<bool> s_warned{false};
            if (!s_warned.exchange(true))
                spdlog::warn("Echo registry: profile list truncated at {} entries -- logged-off "
                             "profiles beyond that are not discovered (repeats suppressed)",
                             yuzu::win::kMaxProfiles);
        }
        const auto profiles = yuzu::profiles::build_profile_list(disc.records, loaded);
        std::vector<std::string> failed;
        for (const auto& f : disc.record_failures)
            failed.push_back(f.sid);
        return classify_offline_discovery(
           profile_list_complete(disc.root_rc, disc.last_rc, disc.probe_rc),
           disc.root_rc != ERROR_SUCCESS, disc.truncated, profiles, failed);
    } catch (...) {
        return OfflineDiscovery{false, {}, {}};
    }
}

// One tick's mount bookkeeping: the first mount to time out (or be refused) stops every later
// mount this tick -- each would only queue behind the stuck worker's offline-hive mutex. A tick
// is identified by its absolute deadline, so a new deadline clears the halt. start() touches it
// once on the starting thread before the first tick; collect() then owns it on one thread --
// sequenced, so no lock.
struct OfflineMountTick {
    std::int64_t deadline{0};
    bool halted{false};
    const char* halted_token{"skipped_after_timeout"};
    // The closed gate was warned of; the next mount attempt that finds it open clears this.
    bool gate_warned{false};
    // The start-up sweep of leftover YUZU_HIVE_* mounts has not completed (see
    // run_pending_hive_sweep). Cleared only when its worker returned.
    bool sweep_pending{true};
};

// Runs the start-up sweep of leftover `YUZU_HIVE_*` mounts once, through the same gate and bounded
// worker as a mount (the sweep needs the same process-wide offline-hive lock, and
// ScopedOfflineHiveLock has no try-lock, so a bare call at start would wait forever behind a
// worker a sibling source abandoned). `sweep_pending` is cleared only when the worker returned.
// A closed gate, a rejected call or a timeout leaves it pending: the next read_offline_hive_bounded
// runs it again before its mount, so a sweep that could not run at start is not lost. A rejected
// or timed-out call halts the tick, as a mount's would.
// ponytail: Echo-only. The effect is process-wide, so a sibling plugin's leftover mount is swept
// too; move this to the shared ladder if a non-Echo consumer ever wants its own trigger.
void run_pending_hive_sweep(OfflineMountTick& tick) {
    if (!tick.sweep_pending || tick.halted)
        return;
    if (yuzu::echo::decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load()) !=
        yuzu::echo::WalkGate::open)
        return;
    const auto bounded = yuzu::shared::bounded_call_ex(kHiveMountBoundMs, [] {
        const MountWorkerGuard in_flight; // counted until this closure really returns
        return yuzu::echo::sweep_leftover_hive_mounts();
    });
    if (bounded.status == yuzu::shared::BoundedCallStatus::Completed) {
        tick.sweep_pending = false;
        return;
    }
    const auto decision = yuzu::echo::decide_mount_call(
       bounded.status == yuzu::shared::BoundedCallStatus::TimedOut
          ? yuzu::echo::MountCallResult::timed_out
          : yuzu::echo::MountCallResult::rejected);
    tick.halted = decision.halt_walk;
    tick.halted_token = decision.attempted ? "skipped_after_timeout" : "skipped_after_rejection";
    spdlog::warn("Echo registry: sweep of leftover hive mounts did not complete ({}); retried "
                 "before the next offline mount",
                 decision.attempted ? "timeout" : "mount_rejected");
}

// One warning per open -> closed transition of the shared mount gate (a failed module pin, or a
// worker abandoned on a timeout that is still running): while it stays closed every hive is
// answered not-attempted and retried next tick, which would otherwise be silent -- the gate
// closing is the one thing that stops ALL offline reads, so it is worth one line, not one per tick.
void note_mount_gate(OfflineMountTick& tick, yuzu::echo::WalkGate gate) {
    if (gate == yuzu::echo::WalkGate::open) {
        tick.gate_warned = false;
        return;
    }
    if (!tick.gate_warned) {
        tick.gate_warned = true;
        spdlog::warn("Echo registry: no offline hive mounts ({}); logged-off profiles are retried on "
                     "the next tick (this repeats only after the gate has reopened)",
                     yuzu::echo::walk_gate_token(gate));
    }
}

OfflineHiveRead unreadable_hive(const std::vector<std::string>& roots, bool attempted,
                                const std::string& reason) {
    OfflineHiveRead r;
    r.attempted = attempted;
    r.reason = reason;
    for (const auto& root : roots) {
        SubtreeRead u;
        u.status = RegistryReadStatus::Unreadable;
        u.reason = reason;
        r.roots.emplace(root, std::move(u));
    }
    return r;
}

// Mounts `sid`'s hive once through the shared guarded ladder (default-on hive-file guard,
// process-wide offline-hive lock, SeBackup/SeRestore scope, live arm wins if the user logged in
// meanwhile) and reads every requested root from that one mount. The wait is bounded by
// bounded_call_ex; the worker is detached on a timeout, which the module pin and the shared
// in-flight gate make safe (see echo_mapdrive_collector.cpp). Everything the worker uses is
// copied into the closure.
OfflineHiveRead read_offline_hive_bounded(const std::string& sid, const std::string& path,
                                          const std::vector<std::string>& roots,
                                          std::int64_t deadline, OfflineMountTick& tick) {
    if (tick.deadline != deadline) {
        tick.deadline = deadline;
        tick.halted = false;
    }
    // A sweep that could not run at start runs before the first mount that finds the gate open;
    // if it halts the tick, the check below answers not-attempted.
    run_pending_hive_sweep(tick);
    if (tick.halted)
        return unreadable_hive(roots, false, std::string("offline:") + tick.halted_token);
    const auto gate = yuzu::echo::decide_walk_gate(pin_plugin_module(), g_mount_workers_in_flight.load());
    note_mount_gate(tick, gate);
    if (gate != yuzu::echo::WalkGate::open)
        return unreadable_hive(roots, false,
                               std::string("offline:") + yuzu::echo::walk_gate_token(gate));

    auto bounded = yuzu::shared::bounded_call_ex(
       kHiveMountBoundMs, [sid, path, roots, deadline]() -> OfflineHiveRead {
           const MountWorkerGuard in_flight; // counted until this closure really returns
           OfflineHiveRead r;
           // Built before the try so the handler allocates nothing (a bad_alloc there would
           // leave the closure and the caller blocked for the whole bound); it only moves this in.
           // Building it can itself throw, before any mount: the closure then unwinds, the guard
           // above releases the count and the caller reports a timeout at the bound.
           OfflineHiveRead failed = unreadable_hive(roots, true, "offline:exception");
           yuzu::win::HiveAccessReport report;
           try {
               const auto status = yuzu::win::with_user_hive(
                  sid, path,
                  [&](HKEY root) {
                      const std::string prefix = "HKU\\" + sid + "\\";
                      for (const auto& logical : roots) {
                          SubtreeRead out;
                          if (!logical.starts_with(prefix)) {
                              out.status = RegistryReadStatus::Unreadable;
                          } else {
                              yuzu::win::RegKey key;
                              const LONG rc = RegOpenKeyExW(
                                 root, yuzu::win::to_wide(logical.substr(prefix.size())).c_str(),
                                 REG_OPTION_OPEN_LINK, KEY_READ | KEY_WOW64_64KEY, key.put());
                              if (rc == ERROR_FILE_NOT_FOUND || rc == ERROR_PATH_NOT_FOUND)
                                  out.status = RegistryReadStatus::Absent;
                              else if (rc != ERROR_SUCCESS)
                                  out.status = RegistryReadStatus::Unreadable;
                              else
                                  out = read_root_at(key.get(), logical, deadline);
                          }
                          r.roots[logical] = std::move(out);
                      }
                  },
                  &report);
               if (status != yuzu::win::HiveAccessStatus::ok)
                   r = unreadable_hive(
                      roots, true,
                      "offline:" + yuzu::profiles::hive_access_token(status, report.refusal));
           } catch (...) {
               r = std::move(failed);
           }
           // The second statement outside the try (building `failed` above is the first). A
           // leaked mount is system-wide and keeps NTUSER.DAT locked until something releases it.
           if (report.unload_failed) {
               // Every failure is recorded (which hive, which mount); the alert is raised once.
               spdlog::info("Echo registry: hive unload failed for {} (mount HKU\\{})", sid,
                            report.mount_name);
               static std::atomic<bool> s_unload_warned{false};
               if (!s_unload_warned.exchange(true))
                   spdlog::warn("Echo registry: hive unload failed for HKU\\{} -- the profile's "
                                "NTUSER.DAT stays locked until a holder releases it; retry "
                                "`reg unload HKU\\{}` (repeats suppressed)",
                                report.mount_name, report.mount_name);
           }
           return r;
       });

    if (bounded.status != yuzu::shared::BoundedCallStatus::Completed) {
        // TimedOut: a real, failed attempt whose worker is still running. Rejected: the shared
        // outstanding-call ceiling was full and no mount ran, so it is not an attempt. Either
        // way no further mount is tried this tick.
        const auto decision = yuzu::echo::decide_mount_call(
           bounded.status == yuzu::shared::BoundedCallStatus::TimedOut
              ? yuzu::echo::MountCallResult::timed_out
              : yuzu::echo::MountCallResult::rejected);
        tick.halted = decision.halt_walk;
        tick.halted_token =
           decision.attempted ? "skipped_after_timeout" : "skipped_after_rejection";
        spdlog::warn("Echo registry: offline hive mount for {} ({}); no further mounts this tick",
                     sid, decision.attempted ? "timeout" : "mount_rejected");
        return unreadable_hive(roots, decision.attempted,
                               decision.attempted ? "offline:timeout" : "offline:mount_rejected");
    }
    return std::move(*bounded.value);
}

} // namespace

HiveSweepResult sweep_leftover_hive_mounts(std::string_view prefix) {
    std::vector<std::string> stale;
    HiveSweepResult r;
    bool privilege_missing = false;
    try {
        // Held for the whole sweep, and taken BEFORE the names are listed. Every mount this process
        // makes holds this lock from RegLoadKeyW to the unload (with_user_hive), so while we hold it
        // no `YUZU_HIVE_*` name is an in-process mount in use -- the name carries no process
        // identity to tell a live mount from a stale one (unique_hive_mount_name salts it per
        // process but never publishes the salt). A mount owned by ANOTHER process that has a handle
        // open fails the non-forced unload below and is retained. Residual: a second Yuzu process's
        // mount in its handle-less window (before it opens the root, or after it closes it and
        // before it unloads) can be unloaded here; an out-of-process mount is unguarded
        // (win_reg_handle.hpp), and that is the default shape on the shared CI pools.
        const yuzu::agent::ScopedOfflineHiveLock offline_lock("echo_registry_sweep");
        stale = select_stale_hive_mounts(yuzu::win::enumerate_hku_subkeys(), prefix);
        if (stale.empty())
            return r;
        // RegUnLoadKeyW needs SeRestorePrivilege, which the agent account already holds
        // (docs/agent-privilege-model.md); with_user_hive enables it the same way per mount.
        const yuzu::win::PrivilegeScope restore_priv(L"SeRestorePrivilege");
        if (restore_priv.ok()) {
            r = sweep_hive_mounts(stale, [](const std::string& name) {
                // Never RegUnLoadKey with force: a holder with an open handle is a live user of the hive.
                return RegUnLoadKeyW(HKEY_USERS, yuzu::win::to_wide(name).c_str()) == ERROR_SUCCESS;
            });
        } else {
            // A hardened install may strip it (a documented degraded mode, as in with_user_hive).
            // Every unload would fail ERROR_PRIVILEGE_NOT_HELD and read as a holder keeping the hive
            // open, so none is attempted. The sweep still completes: the privilege will not appear on
            // a retry, and one warning per start is all this needs.
            r.retained = std::move(stale);
            privilege_missing = true;
        }
    } catch (...) {
        // The lock and the privilege scope were released by unwinding. Returning normally makes the
        // sweep complete: one attempt per start, the same rule privilege_missing follows.
        spdlog::warn("Echo registry: sweep of leftover hive mounts failed (exception); retried at "
                     "the next start");
    }
    // Logged after the lock is released, so logging never extends another caller's wait.
    if (privilege_missing) {
        std::string names;
        for (const auto& n : r.retained)
            names += (names.empty() ? "HKU\\" : ", HKU\\") + n;
        spdlog::warn("Echo registry: privilege_missing -- SeRestorePrivilege is not held, so the "
                     "leftover hive mount(s) {} cannot be unloaded and the profile's NTUSER.DAT "
                     "stays locked; unload each with `reg unload` from an elevated prompt",
                     names);
        return r;
    }
    for (const auto& n : r.released)
        spdlog::info("Echo registry: unloaded leftover hive mount HKU\\{}", n);
    for (const auto& n : r.retained)
        spdlog::warn("Echo registry: leftover hive mount HKU\\{} could not be unloaded (the unload "
                     "was refused or failed) -- the profile's NTUSER.DAT stays locked until it is "
                     "released; retry `reg unload HKU\\{}` from an elevated prompt",
                     n, n);
    return r;
}

std::wstring registry_etw_session_name() {
    // Salted per process: the CI pools run several agents as one OS identity, and a
    // fixed session name is a cross-job shared resource. The name is per process, so it
    // assumes one source per process (one Echo plugin instance); a second in-process source
    // would stop the first one's session by name. The live tests stop each source before
    // the next one starts.
    return L"YuzuEchoRegistryEtw-" + std::to_wstring(::GetCurrentProcessId());
}

RegistryReader make_windows_registry_reader() {
    auto dirty = std::make_shared<RegistryDirtyTable>();
    auto buffer = std::make_shared<RegistryEtwBuffer>();
    auto etw = std::make_shared<WinEtw>();
    etw->buffer = buffer;
    auto watcher = std::make_shared<WinWatcher>();
    watcher->dirty = dirty;
    // Shared by the offline-read hook and start(): the mount halt, the gate-warning latch and the
    // pending start-up sweep are one source's state.
    auto tick = std::make_shared<OfflineMountTick>();

    RegistryReader r;
    r.dirty = dirty;
    r.buffer = buffer;
    r.read_subtree = [](const std::string& root, std::int64_t deadline) {
        return read_root(normalise_registry_path(root, read_current_control_set()), deadline);
    };
    r.loaded_sids = [] { return enumerate_hku(); };
    r.offline_profiles = [](const std::vector<std::string>& loaded) {
        return discover_offline_profiles(loaded);
    };
    r.read_offline_hive = [tick](const std::string& sid, const std::string& path,
                                 const std::vector<std::string>& roots, std::int64_t deadline) {
        return read_offline_hive_bounded(sid, path, roots, deadline, *tick);
    };
    r.now_ts = [] { return filetime_now(); };
    r.etw_running = [etw] { return etw->running.load(); };
    r.session_loss = [etw] { return etw->loss(); };
    r.current_control_set = [] { return read_current_control_set(); };
    r.watch_roots = [watcher](const std::vector<std::string>& roots) { watcher->watch(roots); };
    r.root_armed = [watcher](const std::string& root) { return watcher->armed(root); };
    r.rearm = [watcher](const std::string& root) { return watcher->rearm(root); };
    // ponytail: a session that dies after start is not restarted -- capture_method flips to
    // notify and rows say attr:off; add a restart if that is ever seen in the field.
    r.start = [etw, tick] {
        // Before the session and before any offline mount: a mount a previous run leaked keeps its
        // profile's NTUSER.DAT locked, so it must not outlive the restart that could release it.
        // Bounded and gated like a mount; a sweep it cannot run here waits for the first offline read.
        run_pending_hive_sweep(*tick);
        if (const ULONG rc = etw->start(); rc != ERROR_SUCCESS)
            spdlog::warn("Echo registry: Kernel-Registry ETW session unavailable (Win32 error {}; "
                         "5 = the agent is not elevated) -- the key watch still runs, rows will "
                         "carry attr:off",
                         rc);
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

} // namespace yuzu::echo

#else // !_WIN32

namespace yuzu::echo {

std::unique_ptr<CursorSource> make_registry_cursor_source() { return nullptr; }

} // namespace yuzu::echo

#endif
