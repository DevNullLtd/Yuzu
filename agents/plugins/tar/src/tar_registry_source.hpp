#pragma once

// tar_registry_source.hpp -- the `registry` cursor-model TAR source (see
// tar_registry_parsers.hpp for the mechanism and exactly what the attribution
// establishes). windows.h-free: RegistryCursorSource compiles on every platform
// over an injected RegistryReader, so the whole collect() state machine is
// unit-tested without a registry, a thread or an ETW session. The Windows reader
// (key-watch thread, ETW session, budgeted subtree reader) lives in
// tar_registry_source.cpp behind _WIN32; off-Windows the production factory
// returns nullptr and the plugin drops it.

#include "tar_cursor.hpp"
#include "tar_registry_parsers.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::tar {

/// Per-root "something changed" state, written by the key-watch thread and read
/// by the collect tick. `first` is the FIRST notify since the root was last read
/// (the start of the burst; non-zero is what makes a read source=notify rather
/// than reconcile). It is stamped at notify time: that moment cannot be
/// recovered after the fact. `last` is the most recent notify and only moves
/// forward: take() leaves it alone, so a notify that lands DURING a read still
/// extends the window of the candidates that read produced.
class RegistryDirtyTable {
public:
    struct Snap {
        bool dirty{false};
        std::int64_t first{0};
    };

    /// Watcher side: a notify at `ts`.
    void mark(const std::string& root, std::int64_t ts) {
        {
            std::lock_guard lock(mu_);
            auto& e = m_[root];
            if (!e.dirty || e.first == 0)
                e.first = ts;
            e.dirty = true;
            e.last = std::max(e.last, ts);
        }
        cv_.notify_all();
    }

    /// Exchange: returns the old state and leaves the root clean (BEFORE the read).
    Snap take(const std::string& root) {
        std::lock_guard lock(mu_);
        auto& e = m_[root];
        Snap s{e.dirty, e.first};
        e.dirty = false;
        e.first = 0;
        return s;
    }

    /// Undo a take() after a failed commit: the root is dirty again and its burst
    /// starts at the earlier of the saved and any newer first-notify.
    void restore(const std::string& root, const Snap& s) {
        std::lock_guard lock(mu_);
        auto& e = m_[root];
        if (s.dirty)
            e.dirty = true;
        if (s.first != 0 && (e.first == 0 || s.first < e.first))
            e.first = s.first;
    }

    [[nodiscard]] bool peek_dirty(const std::string& root) const {
        std::lock_guard lock(mu_);
        const auto it = m_.find(root);
        return it != m_.end() && it->second.dirty;
    }

    /// The most recent notify for `root` (0 = none yet).
    [[nodiscard]] std::int64_t last(const std::string& root) const {
        std::lock_guard lock(mu_);
        const auto it = m_.find(root);
        return it == m_.end() ? 0 : it->second.last;
    }

    /// Bounded wait (condition variable, never sleep+poll) until `root` is dirty.
    /// For tests that drive the live key watch.
    [[nodiscard]] bool wait_dirty_for_test(const std::string& root,
                                           std::chrono::steady_clock::time_point deadline) {
        std::unique_lock lock(mu_);
        return cv_.wait_until(lock, deadline, [&] {
            const auto it = m_.find(root);
            return it != m_.end() && it->second.dirty;
        });
    }

    void mark_hku() {
        std::lock_guard lock(mu_);
        hku_ = true;
    }
    [[nodiscard]] bool take_hku() {
        std::lock_guard lock(mu_);
        return std::exchange(hku_, false);
    }
    void restore_hku(bool was) {
        std::lock_guard lock(mu_);
        hku_ = hku_ || was;
    }

private:
    struct Entry {
        bool dirty{false};
        std::int64_t first{0}, last{0};
    };
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::map<std::string, Entry> m_;
    bool hku_{false};
};

/// The in-memory ETW event buffer. Not persisted: a restart loses at most the held
/// candidates' attribution, and says so (attr:lost-restart).
///
/// retire() erases by SEQUENCE IDENTITY, never position -- the shape of
/// BoundedPendingQueue::ack_through (tar_cursor.hpp, R-005): an entry pushed after
/// the snapshot has a larger seq and is untouched whatever overflowed in between.
/// It is not BoundedPendingQueue itself because that releases a seq PREFIX, and
/// the events a held candidate still needs are interleaved with ones it does not.
class RegistryEtwBuffer {
public:
    struct Batch {
        std::vector<RegistryEtwEvent> items;
        std::uint64_t last_seq{0};
    };
    struct DropInfo {
        std::uint64_t count{0};
        std::int64_t ts_lo{0}, ts_hi{0}; // timestamps of the evicted events since the last reset
    };

    explicit RegistryEtwBuffer(std::size_t cap = kRegistryEtwBufferCap) : cap_(cap) {}

    /// Callback-thread safe. At the cap the OLDEST entry is evicted and its
    /// timestamp widens the drop range -- a loss is counted and bounded, never silent.
    void push(RegistryEtwEvent e) {
        {
            std::lock_guard lock(mu_);
            if (!accepting_)
                return; // a paused window is never stored
            e.seq = ++next_seq_;
            if (q_.size() >= cap_ && !q_.empty()) {
                const auto ts = q_.front().ts100ns;
                if (dropped_ == 0 || drop_ts_hi_ == 0) {
                    drop_ts_lo_ = ts;
                    drop_ts_hi_ = ts;
                } else {
                    drop_ts_lo_ = std::min(drop_ts_lo_, ts);
                    drop_ts_hi_ = std::max(drop_ts_hi_, ts);
                }
                q_.pop_front();
                ++dropped_;
            }
            q_.push_back(std::move(e));
            ++pushed_;
        }
        cv_.notify_all();
    }

    [[nodiscard]] Batch snapshot() const {
        std::lock_guard lock(mu_);
        Batch b;
        b.items.assign(q_.begin(), q_.end());
        if (!b.items.empty())
            b.last_seq = b.items.back().seq;
        return b;
    }

    /// After the commit: erase entries with seq <= last_seq for which `release`
    /// says no one can need them again.
    template <class Release> void retire(std::uint64_t last_seq, Release&& release) {
        std::lock_guard lock(mu_);
        std::erase_if(q_, [&](const RegistryEtwEvent& e) { return e.seq <= last_seq && release(e); });
    }

    [[nodiscard]] DropInfo drop_info() const {
        std::lock_guard lock(mu_);
        return {dropped_, drop_ts_lo_, drop_ts_hi_};
    }

    /// Forget the drop range once it is persisted as a loss epoch. Only if nothing
    /// was evicted since `seen_count`, else the newer evictions keep their range.
    void reset_drop_range(std::uint64_t seen_count) {
        std::lock_guard lock(mu_);
        if (dropped_ == seen_count)
            drop_ts_lo_ = drop_ts_hi_ = 0;
    }

    /// Forensic pause: stop accepting and discard (policy, not counted as loss).
    void pause() {
        std::lock_guard lock(mu_);
        accepting_ = false;
        q_.clear();
    }
    void resume() {
        std::lock_guard lock(mu_);
        q_.clear();
        accepting_ = true;
    }
    void clear() {
        std::lock_guard lock(mu_);
        q_.clear();
    }

    [[nodiscard]] std::size_t size() const {
        std::lock_guard lock(mu_);
        return q_.size();
    }
    [[nodiscard]] std::uint64_t pushed() const {
        std::lock_guard lock(mu_);
        return pushed_;
    }

    /// Bounded wait (condition variable, never sleep+poll) until a buffered event
    /// satisfies `pred`. For tests that drive a live session: the session is
    /// system-wide, so "some event arrived" proves nothing about THIS write.
    template <class Pred>
    [[nodiscard]] bool wait_for_event(Pred&& pred, std::chrono::steady_clock::time_point deadline) {
        std::unique_lock lock(mu_);
        return cv_.wait_until(lock, deadline, [&] { return std::any_of(q_.begin(), q_.end(), pred); });
    }

private:
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<RegistryEtwEvent> q_;
    std::size_t cap_;
    std::uint64_t next_seq_{0}, dropped_{0}, pushed_{0};
    std::int64_t drop_ts_lo_{0}, drop_ts_hi_{0};
    bool accepting_{true};
};

/// What the ETW session reports about its own losses (cumulative per session).
struct SessionLoss {
    std::uint64_t events_lost{0};     // EVENT_TRACE_PROPERTIES::EventsLost
    std::uint64_t rt_buffers_lost{0}; // ::RealTimeBuffersLost
    std::uint64_t decode_failed{0};   // callback decode failures
    bool query_ok{true};              // the loss query itself succeeded
};

/// The injected boundary. Every member is required; the source never touches the
/// OS directly.
struct RegistryReader {
    /// One bounded read of `root`. Must not throw. `deadline` is an absolute now_ts() value.
    std::function<SubtreeRead(const std::string& root, std::int64_t deadline)> read_subtree;
    std::function<std::vector<std::string>()> loaded_sids; // subkey names under HKEY_USERS
    std::function<std::int64_t()> now_ts;                  // FILETIME, the ETW header's clock
    std::function<bool()> etw_running;         // the write-event session is delivering
    std::function<SessionLoss()> session_loss; // the session's own loss counters
    std::function<int()> current_control_set; // HKLM\SYSTEM\Select\Current, 0 unknown
    std::function<void(const std::vector<std::string>&)> watch_roots; // (re)arm the key watch
    std::function<bool(const std::string&)> root_armed;
    std::function<bool(const std::string&)> rearm;
    std::function<void()> start;           // open the ETW session; failure is degrade, not error
    std::function<void()> stop;            // idempotent
    std::function<void()> tick_committed;  // per-tick housekeeping after a COMMITTED tick
    std::shared_ptr<RegistryDirtyTable> dirty; // shared with the watcher
    std::shared_ptr<RegistryEtwBuffer> buffer; // shared with the ETW callback
};

class RegistryCursorSource final : public CursorSource {
public:
    RegistryCursorSource(RegistryScope scope, RegistryReader reader);
    ~RegistryCursorSource() override { stop(); }

    [[nodiscard]] std::string name() const noexcept override { return "registry"; }
    void start(TarDatabase& db) override;
    CursorCollectResult collect(TarDatabase& db,
                                const std::optional<std::string>& cursor_json) override;
    void stop() noexcept override;
    void on_enabled_changed(bool enabled) override;

    // Test seams -- never called in production.
    void push_event_for_test(RegistryEtwEvent e) { reader_.buffer->push(std::move(e)); }
    [[nodiscard]] RegistryEtwBuffer& buffer_for_test() { return *reader_.buffer; }

private:
    enum class GapCause { Disabled, Restart };

    void ensure_watch(const std::vector<std::string>& roots);

    RegistryScope scope_;
    RegistryReader reader_;

    // Pending "owed" gap, cleared only after the commit that reports it (R-003).
    bool pending_gap_{false};
    GapCause gap_cause_{GapCause::Disabled};
    bool restarted_{false};   // the buffer was lost across a restart; finalised rows say so
    bool force_all_{false};   // first tick after a restart reads every root
    std::int64_t events_since_{0}; // the buffer holds nothing from before this instant (0 = n/a)
    bool was_disabled_{false};

    std::vector<std::string> armed_roots_;

    // Loss accounting; advanced only after a successful commit, so a failed commit
    // re-derives and re-reports the same loss on the next tick.
    std::uint64_t last_reported_drops_{0};
    std::uint64_t last_reported_kernel_{0};
    std::uint64_t query_failures_{0};
    std::int64_t last_query_ts_{0};

    StitchCounters totals_; // cumulative attribution quality (status keys)
    std::map<std::string, std::string> last_status_written_;
};

/// Production factory: the Windows key-watch + Kernel-Registry ETW source over the
/// curated default scope. nullptr off-Windows (the plugin drops null sources).
std::unique_ptr<CursorSource> make_registry_cursor_source();

#ifdef _WIN32
/// The production Windows reader (key watch + Kernel-Registry ETW + budgeted reader),
/// exposed so the live tests can run the real mechanism over a test scope and a
/// clock they offset. Production code goes through make_registry_cursor_source().
RegistryReader make_windows_registry_reader();

/// The name of the ETW session this process opens (the live tests look it up to prove
/// stop() leaves none behind).
std::wstring registry_etw_session_name();
#endif

/// Test factory: any scope over any reader.
std::unique_ptr<RegistryCursorSource> make_registry_cursor_source(RegistryScope scope,
                                                                  RegistryReader reader);

} // namespace yuzu::tar
