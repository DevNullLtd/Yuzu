#pragma once

/**
 * @file dex_score_policy_provider.hpp
 * Read-through cache of the score policy in force, over an injected store read
 * and an injected millisecond clock.
 *
 * Every server instance reads the same stored document through its own
 * provider, so a change typically reaches all of them within kDexPolicyRefreshMs
 * without any process-local push (an instance refreshes at most once per interval,
 * and only while it serves requests; the policy in use is up to kDexPolicyStaleCapMs
 * old while the store is unreadable). The provider owns the failure direction:
 *   - a good read (including "nothing stored", which is the shipped defaults)
 *     is cached for kDexPolicyRefreshMs, counted from the moment the read
 *     COMPLETED (the clock is sampled after the read: a slow good read is
 *     stamped when it finishes, and a slow failed read counts against the cap);
 *   - a stored document that fails to parse or validate is still a GOOD read:
 *     the policy in force is the shipped defaults with `fault` set;
 *   - a failed read serves the last good policy while it is no older than
 *     kDexPolicyStaleCapMs, and past that returns an error, so the caller
 *     degrades instead of scoring under a guess;
 *   - a failed read before any good read is an error at once;
 *   - the store is read by one caller at a time, and the stored text is parsed
 *     and validated, both outside the lock: a caller arriving mid-refresh is
 *     served the last good policy while it is within the cap, or an error when
 *     there is none within the cap, and never waits on the read (the Apps read
 *     answers its typed 503 with retry_after_ms 2000);
 *   - the single-flight flag is released by a scope guard on every exit from
 *     current(), an exception included, so no failure can leave the refresh
 *     wedged.
 *
 * Writes (write(), the only way a policy is installed on the writing instance):
 *   - a write is commit-then-install under ONE process-local writer lock, so on the
 *     writing instance commit order equals install order and two overlapping writers
 *     cannot leave the cache on the older document; other instances still converge
 *     within kDexPolicyRefreshMs through the store;
 *   - the writer lock is held across the caller's commit (database I/O) -- the ONLY lock
 *     in this file held across I/O -- bounded by the commit's own deadline (the store's
 *     lease wait and statement timeout). A waiting writer gives up after kDexPolicyWriterWait
 *     with the typed WriterBusy, so a stalled commit delays other writers, never wedges them;
 *   - readers never take the writer lock: current() is unaffected by a parked writer, and the
 *     install under mu_ is pure state;
 *   - an install serves at once and restarts the refresh window; a successful read that was in
 *     flight across an install is discarded, a failed one is still capped as above. The
 *     5 s / 60 s bounds are unchanged.
 *
 * No clock or store is touched except through the injected functions, so the
 * behaviour is testable without sleeping.
 */

#include "dex_read_model.hpp"
#include "dex_score_policy_json.hpp"

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::server {

/// How long a good read is served before the store is read again.
inline constexpr std::int64_t kDexPolicyRefreshMs = 5000;
/// How long the last good policy is served while the store cannot be read.
inline constexpr std::int64_t kDexPolicyStaleCapMs = 60000;
/// How long a second writer in this process waits for the writer lock before it is told to
/// retry. Equals the store's own lease wait and the Apps read's retry_after_ms.
inline constexpr std::chrono::milliseconds kDexPolicyWriterWait{2000};

/// Why write() installed nothing.
enum class DexPolicyWriteError {
    WriterBusy,   ///< the writer-lock wait expired; the commit was NEVER invoked; retryable
    Stale,        ///< the commit reported the stored text was not the one expected
    CommitFailed, ///< the commit returned an error or threw
};

struct DexPolicyWriteFailure {
    DexPolicyWriteError kind;
    /// WriterBusy: ours. CommitFailed: the commit's own error string, unchanged (so a caller
    /// can still classify it by kRuntimeConfigDbErrorPrefix), or "commit threw: ...".
    std::string detail;
};

class DexScorePolicyProvider {
public:
    /// The stored document text: nullopt = nothing stored, error = unreadable.
    using ReadFn = std::function<std::expected<std::optional<std::string>, std::string>()>;
    /// Monotonic milliseconds.
    using ClockFn = std::function<std::int64_t()>;

    /// The store commit of a write: true = committed, false = stale (nothing changed), error =
    /// failed. Runs under the writer lock, so it must be bounded by its own deadlines.
    using CommitFn = std::function<std::expected<bool, std::string>()>;

    DexScorePolicyProvider(ReadFn read, ClockFn clock,
                           std::chrono::milliseconds writer_wait = kDexPolicyWriterWait)
        : read_(std::move(read)), clock_(std::move(clock)), writer_wait_(writer_wait) {}

    DexScorePolicyProvider(const DexScorePolicyProvider&) = delete;
    DexScorePolicyProvider& operator=(const DexScorePolicyProvider&) = delete;

    /// The policy in force, from cache while fresh. See the file banner for the
    /// failure direction.
    [[nodiscard]] std::expected<DexPolicyInForce, std::string> current() {
        std::unique_lock lk(mu_);
        const std::int64_t now = clock_();
        if (have_ && now - last_ok_ms_ < kDexPolicyRefreshMs)
            return cached_;
        if (refreshing_) {
            if (have_ && now - last_ok_ms_ <= kDexPolicyStaleCapMs)
                return cached_;
            return std::unexpected(
                std::string("score policy refresh in progress, no usable policy"));
        }
        refreshing_ = true;
        // The flag is released on EVERY exit from here, an exception included (a handler
        // building its message, the clock): it is the only owner, so nothing can leave it set.
        // A mutex that cannot be re-taken terminates the process: a crash, never a wedge.
        struct ClearRefreshing {
            std::unique_lock<std::mutex>& lk;
            bool& flag;
            ~ClearRefreshing() {
                if (!lk.owns_lock())
                    lk.lock();
                flag = false;
            }
        } clear{lk, refreshing_};
        const std::uint64_t gen = generation_;
        lk.unlock(); // the store read and the parse run unlocked: no caller queues behind them
        auto r = read_and_resolve();
        lk.lock();
        // A SUCCESSFUL read that began before an install may predate it: serve the installed
        // policy. A FAILED one is not discarded -- apply_locked still enforces the stale cap.
        if (r && generation_ != gen)
            return cached_;
        return apply_locked(std::move(r), clock_());
    }

    /// Commit a new stored text and install it, as one step the other writers in this process
    /// are serialised behind. `text` is the EXACT text `commit` stores (nullopt = the key is
    /// removed, i.e. the shipped defaults); `commit` is the store compare-and-set / -remove
    /// and nothing slower (no audit write, no second store call): it runs under the writer
    /// lock. Call this on the WRITING instance and never write this key to the store outside
    /// it, or the install order can reverse. The text is resolved (parsed, validated, hashed)
    /// before any lock; an invalid document installs the shipped defaults with `fault`, as a
    /// read of it would. Canonical text is unchanged by the store's scrub, so no re-read is
    /// needed before installing.
    ///
    /// Errors, for the caller to map: WriterBusy -> retryable 503 with retry_after_ms =
    /// kDexPolicyWriterWait; Stale -> the If-Match outcome (409); CommitFailed -> by the
    /// store's kRuntimeConfigDbErrorPrefix (503 prefixed, 400 otherwise). Nothing is
    /// installed on any error.
    [[nodiscard]] std::expected<DexPolicyInForce, DexPolicyWriteFailure>
    write(const std::optional<std::string>& text, const CommitFn& commit) {
        auto r = dex_policy_in_force_from_stored(text);
        std::unique_lock wl(writer_mu_, std::defer_lock);
        if (!wl.try_lock_for(writer_wait_))
            return std::unexpected(DexPolicyWriteFailure{
                DexPolicyWriteError::WriterBusy,
                "another score policy write in this process is still running after " +
                    std::to_string(writer_wait_.count()) + " ms"});
        std::expected<bool, std::string> c;
        try {
            c = commit();
        } catch (const std::exception& e) {
            return std::unexpected(DexPolicyWriteFailure{DexPolicyWriteError::CommitFailed,
                                                         std::string("commit threw: ") + e.what()});
        } catch (...) {
            return std::unexpected(DexPolicyWriteFailure{DexPolicyWriteError::CommitFailed,
                                                         "commit threw"});
        }
        if (!c)
            return std::unexpected(
                DexPolicyWriteFailure{DexPolicyWriteError::CommitFailed, std::move(c.error())});
        if (!*c)
            return std::unexpected(DexPolicyWriteFailure{
                DexPolicyWriteError::Stale, "the stored policy is not the one expected"});
        // The install completes BEFORE the writer lock is released: commit order == install
        // order. A resolved value is always a good read, so apply_locked cannot fail here.
        std::lock_guard lk(mu_);
        ++generation_;
        return *apply_locked(std::move(r), clock_());
    }

private:
    // The read and the resolve of the stored text (parse, validate, hash) run outside the
    // lock. A throw from either is a failed read. An exception that escapes this function
    // (the handlers allocate) leaves current() through the guard above, which releases the
    // single-flight flag.
    std::expected<DexPolicyInForce, std::string> read_and_resolve() {
        try {
            auto r = read_();
            if (!r)
                return std::unexpected(std::move(r.error()));
            return dex_policy_in_force_from_stored(*r);
        } catch (const std::exception& e) {
            return std::unexpected(std::string("read threw: ") + e.what());
        } catch (...) {
            return std::unexpected(std::string("read threw"));
        }
    }

    // `now` is sampled AFTER the read: a slow failed read counts against the cap, and a
    // slow good read is stamped at its completion, not its start. Only state, stamps and
    // log lines are touched under the lock.
    std::expected<DexPolicyInForce, std::string>
    apply_locked(std::expected<DexPolicyInForce, std::string> r, std::int64_t now) {
        if (r) {
            if (!r->fault.empty() && r->fault != logged_fault_)
                spdlog::warn("DEX score policy refused, shipped defaults in force: {}", r->fault);
            logged_fault_ = r->fault;
            if (have_ && cached_.revision != r->revision)
                spdlog::info("DEX score policy changed: revision {} -> {} (source {})",
                             cached_.revision, r->revision, r->source);
            if (outage_logged_)
                spdlog::info("DEX score policy store readable again");
            cached_ = std::move(*r);
            last_ok_ms_ = now;
            have_ = true;
            outage_logged_ = false;
            return cached_;
        }
        if (have_ && now - last_ok_ms_ <= kDexPolicyStaleCapMs) {
            if (!outage_logged_)
                spdlog::warn("DEX score policy store unreadable, serving the last good policy: {}",
                             r.error());
            outage_logged_ = true;
            return cached_;
        }
        return std::unexpected("score policy unreadable: " + r.error());
    }

    ReadFn read_;
    ClockFn clock_;
    std::chrono::milliseconds writer_wait_;

    // Serialises commit+install across writers. Held across the caller's commit I/O, bounded by
    // that call's own deadline; never taken by current().
    std::timed_mutex writer_mu_;
    std::mutex mu_; // guards the state below only; never held across the store read
    std::uint64_t generation_{0}; // bumped by each install
    bool refreshing_{false};
    bool have_{false};
    bool outage_logged_{false};
    std::int64_t last_ok_ms_{0};
    DexPolicyInForce cached_;
    std::string logged_fault_;
};

} // namespace yuzu::server
