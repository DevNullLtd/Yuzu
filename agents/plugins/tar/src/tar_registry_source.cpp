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
#include <string>

namespace yuzu::tar {

namespace {

constexpr const char* kEmptyBaselineJson = R"({"v":1,"keys":{}})";

std::string baseline_collector(const std::string& root) { return "registry:" + root; }

std::vector<std::string> unique_in_order(std::vector<std::string> v) {
    std::vector<std::string> out;
    for (auto& s : v)
        if (std::find(out.begin(), out.end(), s) == out.end())
            out.push_back(std::move(s));
    return out;
}

// Fills every optional hook so the state machine never null-checks.
void fill_defaults(RegistryReader& r) {
    if (!r.read_subtree)
        r.read_subtree = [](const std::string&, std::int64_t) { return SubtreeRead{}; };
    if (!r.loaded_sids)
        r.loaded_sids = [] { return std::vector<std::string>{}; };
    if (!r.now_ts)
        r.now_ts = [] { return std::int64_t{0}; };
    if (!r.current_control_set)
        r.current_control_set = [] { return 1; };
    if (!r.watch_roots)
        r.watch_roots = [](const std::vector<std::string>&) {};
    if (!r.root_armed)
        r.root_armed = [](const std::string&) { return true; };
    if (!r.rearm)
        r.rearm = [](const std::string&) { return true; };
    if (!r.stop)
        r.stop = [] {};
    if (!r.dirty)
        r.dirty = std::make_shared<RegistryDirtyTable>();
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
    : scope_(std::move(scope)), reader_(std::move(reader)) {
    fill_defaults(reader_);
}

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
    ensure_watch(unique_in_order(scope_.roots_for(reader_.loaded_sids())));
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
        const std::vector<std::string> roots = unique_in_order(scope_.roots_for(sids));
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
                st.status = "due"; // not reached this tick; first in line next time
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
                rows.push_back(registry_row_from_candidate(c, 0, {}, {}, snapshot_id));
            if (rd.status != RegistryReadStatus::Unreadable && (fresh_root || diff.changed))
                state_writes.push_back({baseline_collector(root),
                                        encode_registry_baseline(diff.baseline)});

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

#include <win_reg_handle.hpp> // yuzu::win::RegKey
#include <win_str.hpp>        // yuzu::win wide<->UTF-8

#include <thread>

#pragma comment(lib, "advapi32.lib")

#ifndef REG_NOTIFY_THREAD_AGNOSTIC
#define REG_NOTIFY_THREAD_AGNOSTIC 0x10000000L // Windows 8+; older SDK headers omit it
#endif

namespace yuzu::tar {

namespace {

std::int64_t filetime_now() {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    return static_cast<std::int64_t>((static_cast<std::uint64_t>(ft.dwHighDateTime) << 32) |
                                     ft.dwLowDateTime);
}

HKEY hive_of(std::string_view token) {
    return token == "HKU" ? HKEY_USERS : HKEY_LOCAL_MACHINE;
}

// Opens the root's key for the given access. nullopt-style via rc.
LONG open_root(const std::string& root, REGSAM access, yuzu::win::RegKey& out) {
    auto [hive, rest] = split_hive(root);
    return RegOpenKeyExW(hive_of(hive), yuzu::win::to_wide(rest).c_str(), 0,
                         access | KEY_WOW64_64KEY, out.put());
}

// The key-watch half: one thread waiting on (stop, HKEY_USERS name watch, up to
// kWatchHandleCap root events). On a signal it marks the root dirty with a precise
// timestamp and RE-ARMS at once; a re-arm failure leaves the root unarmed, which the
// collect tick reports and retries (it reads an unarmed root every tick meanwhile).
struct WinWatcher {
    struct Slot {
        std::string root;
        HANDLE event{nullptr};
        yuzu::win::RegKey key;
        bool armed{false};
    };

    std::shared_ptr<RegistryDirtyTable> dirty;
    std::mutex mu; // guards slots (key + armed) between the thread and the collect tick
    std::vector<Slot> slots;
    HANDLE stop_event{nullptr};
    HANDLE hku_event{nullptr};
    yuzu::win::RegKey hku_key;
    std::thread thread;

    ~WinWatcher() { shutdown(); }

    static bool arm(Slot& s) {
        s.key.reset();
        if (open_root(s.root, KEY_NOTIFY, s.key) != ERROR_SUCCESS) {
            s.armed = false;
            return false;
        }
        ResetEvent(s.event);
        s.armed = RegNotifyChangeKeyValue(s.key.get(), TRUE,
                                          REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET |
                                             REG_NOTIFY_THREAD_AGNOSTIC,
                                          s.event, TRUE) == ERROR_SUCCESS;
        if (!s.armed)
            s.key.reset();
        return s.armed;
    }

    void shutdown() {
        if (stop_event != nullptr)
            SetEvent(stop_event);
        if (thread.joinable())
            thread.join();
        std::lock_guard lock(mu);
        for (auto& s : slots) {
            s.key.reset();
            if (s.event != nullptr)
                CloseHandle(s.event);
        }
        slots.clear();
        hku_key.reset();
        if (hku_event != nullptr)
            CloseHandle(hku_event);
        if (stop_event != nullptr)
            CloseHandle(stop_event);
        hku_event = stop_event = nullptr;
    }

    // Replaces the watch with one over `roots`. Roots past the handle cap get no
    // event: they stay unarmed and are covered by the reconcile read.
    void watch(const std::vector<std::string>& roots) {
        shutdown();
        stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        hku_event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        {
            std::lock_guard lock(mu);
            for (std::size_t i = 0; i < roots.size(); ++i) {
                Slot s;
                s.root = roots[i];
                if (i < kWatchHandleCap) {
                    s.event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
                    if (s.event != nullptr)
                        arm(s);
                }
                slots.push_back(std::move(s));
            }
            if (RegOpenKeyExW(HKEY_USERS, L"", 0, KEY_NOTIFY, hku_key.put()) == ERROR_SUCCESS)
                RegNotifyChangeKeyValue(hku_key.get(), FALSE, REG_NOTIFY_CHANGE_NAME |
                                                                  REG_NOTIFY_THREAD_AGNOSTIC,
                                        hku_event, TRUE);
        }
        thread = std::thread([this] { run(); });
    }

    void run() {
        std::vector<HANDLE> handles;
        std::vector<std::size_t> slot_of; // handles[i] -> slot index (npos for stop/hku)
        {
            std::lock_guard lock(mu);
            handles.push_back(stop_event);
            slot_of.push_back(static_cast<std::size_t>(-1));
            handles.push_back(hku_event);
            slot_of.push_back(static_cast<std::size_t>(-2));
            for (std::size_t i = 0; i < slots.size(); ++i)
                if (slots[i].event != nullptr) {
                    handles.push_back(slots[i].event);
                    slot_of.push_back(i);
                }
        }
        for (;;) {
            const DWORD w = WaitForMultipleObjects(static_cast<DWORD>(handles.size()),
                                                   handles.data(), FALSE, INFINITE);
            if (w == WAIT_OBJECT_0 || w >= WAIT_OBJECT_0 + handles.size())
                return; // stop, or a wait failure (never spin on one)
            const std::size_t which = slot_of[w - WAIT_OBJECT_0];
            if (which == static_cast<std::size_t>(-2)) {
                dirty->mark_hku();
                std::lock_guard lock(mu);
                if (hku_key)
                    RegNotifyChangeKeyValue(hku_key.get(), FALSE,
                                            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_THREAD_AGNOSTIC,
                                            hku_event, TRUE);
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
        for (auto& s : slots)
            if (s.root == root)
                return s.event != nullptr && arm(s);
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
};

void read_key(ReadCtx& ctx, HKEY key, const std::string& full, std::size_t depth) {
    if (ctx.capped || ctx.unreadable)
        return;
    if (!RegistryReadBudget::depth_ok(depth) || !ctx.budget.admit_key() ||
        filetime_now() >= ctx.deadline) {
        ctx.capped = true;
        return;
    }
    DWORD n_sub = 0, max_sub = 0, n_val = 0, max_name = 0, max_data = 0;
    if (RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &n_sub, &max_sub, nullptr, &n_val,
                         &max_name, &max_data, nullptr, nullptr) != ERROR_SUCCESS) {
        ctx.unreadable = true;
        return;
    }
    auto& values = ctx.out->keys[full]; // present even when empty: a vanished key is detectable
    std::vector<wchar_t> name(static_cast<std::size_t>(max_name) + 2);
    const DWORD buf_len = std::min<DWORD>(max_data, static_cast<DWORD>(kBaselineValueReadCap));
    if (ctx.data.size() < buf_len)
        ctx.data.resize(buf_len);
    for (DWORD i = 0;; ++i) {
        DWORD nlen = static_cast<DWORD>(name.size());
        DWORD type = 0, dlen = static_cast<DWORD>(ctx.data.size());
        LONG rc = RegEnumValueW(key, i, name.data(), &nlen, nullptr, &type, ctx.data.data(), &dlen);
        if (rc == ERROR_NO_MORE_ITEMS)
            break;
        RegistryValueRead v;
        v.type = type;
        if (rc == ERROR_MORE_DATA) {
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
        values[yuzu::win::from_wide(name.data(), static_cast<int>(nlen))] = std::move(v);
    }

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
        yuzu::win::RegKey child;
        const LONG orc = RegOpenKeyExW(key, sub.data(), 0, KEY_READ | KEY_WOW64_64KEY, child.put());
        if (orc == ERROR_FILE_NOT_FOUND || orc == ERROR_KEY_DELETED)
            continue; // deleted between enumerate and open: the next read sees it gone
        if (orc != ERROR_SUCCESS) {
            ctx.unreadable = true; // e.g. access denied: a partial read proves nothing
            return;
        }
        read_key(ctx, child.get(),
                 full + "\\" + yuzu::win::from_wide(sub.data(), static_cast<int>(slen)), depth + 1);
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
            out.status = RegistryReadStatus::Unreadable;
        } else {
            out.status = ctx.capped ? RegistryReadStatus::Capped : RegistryReadStatus::Complete;
        }
    } catch (...) {
        out.keys.clear();
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
