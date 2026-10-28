#pragma once

// echo_registry_source.hpp -- the `registry` cursor-model Echo source (see
// echo_registry_parsers.hpp for the mechanism). windows.h-free: RegistryCursorSource
// compiles on every platform over an injected RegistryReader, so the whole
// collect() state machine is unit-tested without a registry or a thread. The
// Windows reader (key-watch thread, budgeted subtree reader) lives in
// echo_registry_source.cpp behind _WIN32; off-Windows the production factory
// returns nullptr and the plugin drops it.

#include "echo_cursor.hpp"
#include "echo_registry_parsers.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::echo {

/// Per-root "something changed" state, written by the key-watch thread and read
/// by the collect tick. `first` is the FIRST notify since the root was last read
/// (the start of the burst; non-zero is what makes a read source=notify rather
/// than reconcile). It is stamped at notify time: that moment cannot be
/// recovered after the fact.
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
        std::int64_t first{0};
    };
    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::map<std::string, Entry> m_;
    bool hku_{false};
};

/// The injected boundary. Every member is required; the source never touches
/// the OS directly.
struct RegistryReader {
    /// One bounded read of `root`. Must not throw. `deadline` is an absolute now_ts() value.
    std::function<SubtreeRead(const std::string& root, std::int64_t deadline)> read_subtree;
    std::function<std::vector<std::string>()> loaded_sids; // subkey names under HKEY_USERS
    std::function<std::int64_t()> now_ts;                  // FILETIME
    std::function<int()> current_control_set; // HKLM\SYSTEM\Select\Current, 0 unknown
    std::function<void(const std::vector<std::string>&)> watch_roots; // (re)arm the key watch
    std::function<bool(const std::string&)> root_armed;
    std::function<bool(const std::string&)> rearm;
    std::function<void()> stop; // idempotent
    std::shared_ptr<RegistryDirtyTable> dirty; // shared with the watcher
};

class RegistryCursorSource final : public CursorSource {
public:
    RegistryCursorSource(RegistryScope scope, RegistryReader reader);
    ~RegistryCursorSource() override { stop(); }

    [[nodiscard]] std::string name() const noexcept override { return "registry"; }
    void start(EchoDatabase& db) override;
    CursorCollectResult collect(EchoDatabase& db,
                                const std::optional<std::string>& cursor_json) override;
    void stop() noexcept override;
    void on_enabled_changed(bool enabled) override;

private:
    enum class GapCause { Disabled, Restart };

    void ensure_watch(const std::vector<std::string>& roots);

    RegistryScope scope_;
    RegistryReader reader_;

    // Pending "owed" gap, cleared only after the commit that reports it (R-003).
    bool pending_gap_{false};
    GapCause gap_cause_{GapCause::Disabled};
    bool force_all_{false}; // first tick after a restart reads every root
    bool was_disabled_{false};

    std::vector<std::string> armed_roots_;
    std::map<std::string, std::string> last_status_written_;
};

/// Production factory: the Windows key-watch source over the curated default
/// scope. nullptr off-Windows (the plugin drops null sources).
std::unique_ptr<CursorSource> make_registry_cursor_source();

#ifdef _WIN32
/// The production Windows reader (key watch + budgeted reader), exposed so the
/// live tests can run the real mechanism over a test scope. Production code goes through make_registry_cursor_source().
RegistryReader make_windows_registry_reader();
#endif

/// Test factory: any scope over any reader.
std::unique_ptr<RegistryCursorSource> make_registry_cursor_source(RegistryScope scope,
                                                                  RegistryReader reader);

} // namespace yuzu::echo
