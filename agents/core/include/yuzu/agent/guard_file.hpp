#pragma once

/**
 * guard_file.hpp — Windows file-change Spark for Yuzu Guardian (Change B).
 *
 * Watches a target file in REAL TIME via ReadDirectoryChangesW on its parent
 * directory (kernel-notified, NO polling — unlike the Trigger Engine's mtime
 * poll). Resilient like RegistryGuard (C1/C2): the watch is live from arm until
 * the rule is disabled, and reconciles the target's state from scratch on every
 * wake. It survives the armed directory (the target's parent, or its nearest
 * existing ancestor) being deleted and recreated anywhere in that ancestor
 * chain (a nearest-existing-ancestor watch catches the recreation). A rename
 * or move of the armed directory ITSELF is caught separately, via a watch on
 * its own parent — one level up only: a rename or move of that parent, or of
 * anything above it, is not itself detected in real time (picked up once the
 * target's content next changes).
 *
 * B1 implements the `file-exists` assertion: drift when the file's presence
 * (exists / absent) differs from the rule's expected state — i.e. realtime
 * detection of a file being deleted (or created). `file-hash-equals`
 * (content-change detection) is B2.
 *
 * Detection-only: a FileGuard never writes. File-content remediation (restore a
 * known-good copy) needs the Content Distribution subsystem and is deferred.
 *
 * Deliberately proto-free and windows.h-free (stop_event_ is a void* HANDLE).
 * On non-Windows the guard is a no-op (start() returns false) so the engine and
 * tests build everywhere; the watch is Windows-only for the MVP (Linux inotify /
 * macOS FSEvents are later platform work).
 */

#include <yuzu/plugin.h>          // YUZU_EXPORT
#include <yuzu/agent/guard.hpp>   // IGuard, GuardDrift, GuardSink

#include <atomic>
#include <cassert>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

namespace yuzu::agent {

/// One file-existence watch. start() canonicalises the path, arms the parent-dir
/// watch on a dedicated thread, runs an initial compare, and reports drift via
/// the sink. Detection-only.
class YUZU_EXPORT FileGuard : public IGuard {
public:
    /// Which desired-state check the guard evaluates on a change.
    enum class Assertion {
        Exists,    ///< file-exists (B1): presence vs expect_present
        HashEquals ///< file-hash-equals (B2): content (size + SHA-256) vs a baseline
    };

    struct Config {
        std::string rule_id;
        std::string rule_name;
        std::string path; ///< target file (canonicalised at start)
        Assertion assertion{Assertion::Exists};
        // file-exists:
        bool expect_present{true}; ///< desired presence (drift when actual != this)
        // file-hash-equals:
        std::string expected_hash;                       ///< lowercase hex SHA-256; empty = baseline-on-arm
        std::uint64_t max_hash_bytes{64ull * 1024 * 1024}; ///< hashing-DoS cap; over → "<oversize>" drift
        std::uint64_t settle_ms{750};                    ///< coalesce window before hashing (writes are not atomic)
        /// Upper bound on how long a continuous write storm may defer the hash. The
        /// settle window restarts on every notification, so without this cap a writer
        /// touching the file faster than settle_ms would starve the hash forever
        /// (drift invisible). Once this much has elapsed since the first un-hashed
        /// change, hash anyway. Default 5s.
        std::uint64_t max_settle_defer_ms{5000};
        /// Event/sink debounce window (ms) — collapses rapid drift events into a
        /// count (shared convention with RegistryGuard). 0 = emit every drift.
        std::uint64_t event_debounce_ms{1000};
        /// Cadence at which the disabled-parent-watch "guard.unhealthy" report is
        /// re-sent while the guard stays disabled — a lost-edge backstop mirroring
        /// the Spark runtime's `errored_refresh_ms` (default 300s; see
        /// docs/spark-legacy-delta-registry.md D1). The legacy sink drops events on
        /// disconnect with no retry (agent.cpp), so a single edge-only report can be
        /// silently lost; the refresh corrects a stale-green census on the next tick
        /// without depending on that one report's delivery. 0 = edge-only, no
        /// refresh. No filesystem work happens on a refresh tick.
        std::uint64_t parent_unhealthy_refresh_ms{300'000};
        /// #4021: fired EXACTLY ONCE, on the run() worker thread, the moment
        /// `expected_hash.empty() && !baseline_set` captures a fresh baseline (never
        /// again for this FileGuard instance — mirrors the source guard above's own
        /// `!baseline_set` gate; a seeded, non-empty `expected_hash` never enters
        /// that branch at all). Optional — null is a no-op. The callback runs on
        /// THIS worker thread: it must not block meaningfully and must not reach
        /// back into anything owned by the engine that constructed this guard
        /// (GuardianEngine's own contract for every guard-worker callback — see
        /// emit_guard_event's doc — applies here too); the production wiring
        /// (guardian_engine.cpp) captures only a raw KvStore* by value, never
        /// `this`/GuardianEngine&.
        ///
        /// Resource Ledger (Gate 3 governance, cpp-safety — recorded here since
        /// this branch has no PR body yet): new callback context, a movable
        /// value member (RAII, no manual cleanup). Owner: whichever
        /// `FileGuard::Config` holds it, moved into the `FileGuard` ctor at
        /// construction (guardian_engine.cpp's start_guard_for_rule_locked).
        /// Acquired: assignment of the lambda at arm time. Released: `~FileGuard()`
        /// -> `stop()` -> worker thread join (the callback, if mid-execution, has
        /// always fully returned by the time the join completes, since it runs
        /// synchronously inside the same worker's call stack — see run()).
        /// Transfer: none beyond the initial move into the guard; no ownership
        /// hand-off elsewhere. Captured resource: a BORROWED, non-owning
        /// `KvStore*` (owner: `AgentImpl::kv_store_`, agent.cpp — declared before
        /// `guardian_`, so it destructs AFTER every guard thread is joined via
        /// `GuardianEngine::stop()`'s `stop_all_guards_locked()`, which runs
        /// before either unique_ptr tears down). Failure cleanup: none needed —
        /// nothing owned by the callback itself requires it.
        std::function<void(const std::string& hash)> on_baseline;
    };

    FileGuard(Config cfg, GuardSink sink);
    ~FileGuard() override;
    FileGuard(const FileGuard&) = delete;
    FileGuard& operator=(const FileGuard&) = delete;

    /// Canonicalise the path, arm the watch, run an initial compare, and start the
    /// watch thread. Returns false if the guard could not be started (empty path,
    /// or non-Windows build).
    bool start() override;
    void stop() override;

    const std::string& rule_id() const override { return cfg_.rule_id; }

    /// Test-only. When set, forces the parent-directory watch's teardown (whether a
    /// mid-run rebuild or run()'s own exit) to treat an otherwise-confirmed cancel
    /// drain as UNCONFIRMED — i.e. deterministically exercises the abandon-rather-
    /// than-free path (sec-1) without depending on a real, timing-dependent delayed
    /// kernel completion, which cannot be forced on local NTFS from user mode. Never
    /// overrides a genuinely-unconfirmed drain the other way. No-op when unset
    /// (default; production is unaffected). Set before start(). CONTRACT: invoked
    /// inside a noexcept teardown path with no try/catch around the call — the hook
    /// must not throw, or the process terminates.
    void set_parent_drain_fail_hook_for_test(std::function<bool()> hook) {
        assert((!hook || !thread_.joinable()) &&
               "set_parent_drain_fail_hook_for_test: arm before start()");
        parent_drain_fail_hook_for_test_ = std::move(hook);
    }

private:
    void run();

    Config cfg_;
    GuardSink sink_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    void* stop_event_{nullptr}; ///< HANDLE (void* keeps windows.h out of this header)
    std::function<bool()> parent_drain_fail_hook_for_test_; ///< test seam; see setter doc
};

} // namespace yuzu::agent
