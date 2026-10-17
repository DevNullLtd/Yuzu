#pragma once

/// @file guardian_generation_cache.hpp
/// Short-TTL, single-flight cache for the Guardian policy generation read (#5513).
///
/// WHY IT EXISTS. The heartbeat reconcile compares the agent's reported generation
/// with `GuaranteedStateStore::current_policy_generation()`, a synchronous Postgres
/// point read taken on every tagged heartbeat. At fleet scale that is one store read per
/// heartbeat for a value that changes only on a rule-set mutation. The result is cached
/// for a short TTL, and a failed read is cached for a shorter negative TTL so a degraded
/// store is not hammered by every heartbeat during an outage. Same shape as
/// `AgentRegistry::live_presence()` / `kPresenceCacheTtl` (agent_registry.hpp), which
/// also caches the `std::expected` itself.
///
/// CONTRACT.
///   - `get()` returns the cached result while it is fresh: `ttl` for a success,
///     `negative_ttl` for an error. Assuming a monotonic store, a value up to `ttl` old is
///     LOWER than or equal to the store's, never higher, so it is safe for a "has anything changed" decision (admit,
///     rate-limit, shed, converged) but it is NOT safe to LABEL a push with: the push
///     content is read after the label, and a fan-out that already delivered a newer
///     generation would then be answered with older content under an older label. A caller
///     that is about to send must use `get_fresh()`.
///   - `get_fresh()` ignores the TTL and any in-flight fetch and reads the store. A SUCCESS
///     is installed as the cached outcome (unless an `invalidate()` raced it); an ERROR is
///     returned to the caller only and never installed, so one transient lease timeout on an
///     admitted push cannot make every `get()` report degraded for `negative_ttl`. It is
///     bounded by the caller's own admission control, not by single flight.
///   - MONOTONIC INSTALL. A result is installed only if its read STARTED no earlier than the
///     currently held entry's, so a read that started long ago and finishes last cannot
///     overwrite a newer one (two `get_fresh()` calls, or a `get_fresh()` racing a `get()`).
///     "Earlier" is decided by a sequence number taken under the mutex when the read starts,
///     NOT by the clock: two reads that start within one clock tick compare equal by time,
///     and the older one finishing last would then overwrite the newer.
///   - SINGLE FLIGHT. At most one thread runs the fetch at a time. While one is in
///     flight, a concurrent caller returns the previously cached SUCCESS if the last
///     outcome was a success. That value is stale by `ttl` plus the idle gap (nothing
///     starts a refresh at expiry: the fetch begins when the first caller arrives after
///     the entry expired, so an entry nobody asked for stays cached however old it is)
///     plus the fetch time, not by `ttl` plus the fetch time alone. NOTHING BOUNDS that
///     while the owner's fetch stays blocked (a blackholed store): an expired held success
///     keeps being served for as long as the fetch runs, because `max_wait` bounds only
///     the waiters that have no success to serve. A caller that needs a bound on staleness uses
///     `get_fresh()` (which blocks for the duration of its own fetch) or a store-side
///     timeout on the fetch function. If there is no
///     value, or the last outcome was an error, the caller waits on the in-flight fetch
///     through a `std::shared_future` for at most `max_wait` and receives its result, or
///     an error naming the timeout (the loader thread is unaffected; a blackholed store
///     must not hold every heartbeat thread for the connect timeout). An expired error is
///     never served in place of a fresh attempt, and a stale success is never served after
///     an error (that would hide a degraded store behind an old value).
///   - A lower fetched value REPLACES a higher cached one. That is a store reset and is
///     not hidden: `regressions()` counts it. Nothing here pins the generation upward.
///   - `invalidate()` drops the cached outcome (called when the generation was just bumped
///     locally, by the store's post-mutation rule hook after every rule create/update/delete
///     on this replica even when the bump failed, and by tests). A fetch already in flight when `invalidate()` runs still
///     returns its result to its own callers but does NOT repopulate the cache, so an
///     invalidation can never be undone by an older read. It also ends single-flight
///     for that fetch: the next `get()` starts its own fetch rather than waiting on the
///     older one.
///   - A fetch that throws is converted to an error result. The in-flight state is cleared
///     and the promise fulfilled on EVERY path out of the flight owner (a scope guard, with
///     the bookkeeping inside try/catch), so an allocation failure between registering the
///     flight and clearing it cannot wedge the cache with a flight nobody will complete.
///   - The fetch function runs WITHOUT the cache mutex held.
///
/// CLOCK INJECTION. `ClockFn` is `std::function<std::chrono::steady_clock::time_point()>`;
/// null selects the real steady clock. Tests inject a manual clock and a fetch function
/// that blocks on an event, so nothing sleeps. A clock that moves backwards leaves the
/// cached entry fresh rather than re-fetching. The clock is called under the internal
/// mutex and must not call back into the cache. A success's TTL is measured from when the
/// fetch STARTED, which is the conservative end of the read's age; an error's `negative_ttl`
/// is measured from when the fetch FINISHED, so a slow failing read still suppresses the
/// next attempts for the full window.
///
/// Thread-safe.

#include <chrono>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace yuzu::server {

/// Cache TTLs (namespace scope so it can be a default argument).
struct GuardianGenerationCacheConfig {
    std::chrono::milliseconds ttl{2000};
    std::chrono::milliseconds negative_ttl{1000};
    /// Longest a waiter blocks on another thread's in-flight fetch.
    std::chrono::milliseconds max_wait{5000};
};

class GuardianGenerationCache {
public:
    using Clock = std::chrono::steady_clock;
    using ClockFn = std::function<Clock::time_point()>;
    using Result = std::expected<std::uint64_t, std::string>;
    using FetchFn = std::function<Result()>;

    using Config = GuardianGenerationCacheConfig;

    explicit GuardianGenerationCache(FetchFn fetch, Config cfg = {}, ClockFn clock = {})
        : fetch_(std::move(fetch)), cfg_(cfg), clock_(clock ? std::move(clock) : ClockFn{[] { return Clock::now(); }}) {}

    GuardianGenerationCache(const GuardianGenerationCache&) = delete;
    GuardianGenerationCache& operator=(const GuardianGenerationCache&) = delete;

    [[nodiscard]] Result get() {
        std::shared_future<Result> waiting;
        std::shared_ptr<std::promise<Result>> promise;
        Clock::time_point started;
        std::uint64_t seq = 0;
        std::uint64_t epoch = 0;
        {
            std::lock_guard lk(mu_);
            const auto now = clock_();
            if (entry_ && fresh_locked(*entry_, now))
                return entry_->result;
            if (inflight_.valid()) {
                if (entry_ && entry_->result.has_value())
                    return entry_->result;  // stale success while a refresh is running
                waiting = inflight_;
            } else {
                promise = std::make_shared<std::promise<Result>>();
                inflight_ = promise->get_future().share();
                started = now;
                seq = ++read_seq_;
                epoch = epoch_;
            }
        }
        if (waiting.valid())
            return wait_for_flight(waiting);

        // From here until `flight` is destroyed the cache has a registered flight that only
        // this thread can complete. The guard makes completion unconditional.
        FlightGuard flight{*this, epoch};
        Result r = run_fetch();
        install(r, started, seq, epoch);
        flight.fulfil(*promise, r);
        return r;
    }

    /// Read the store now, ignoring the TTL and any flight in progress, and install the
    /// result as the cached outcome. Use before LABELLING a push (see the contract).
    [[nodiscard]] Result get_fresh() {
        Clock::time_point started;
        std::uint64_t seq = 0;
        std::uint64_t epoch = 0;
        {
            std::lock_guard lk(mu_);
            started = clock_();
            seq = ++read_seq_;
            epoch = epoch_;
        }
        Result r = run_fetch();
        install(r, started, seq, epoch, /*install_errors=*/false);
        return r;
    }

    /// Drop the cached outcome. See the contract for the in-flight case.
    void invalidate() {
        std::lock_guard lk(mu_);
        entry_.reset();
        inflight_ = {};  // detach a running flight: the next get() starts a fresh fetch
        ++epoch_;
    }

    /// Number of times the fetch function was started.
    [[nodiscard]] std::uint64_t fetches() const {
        std::lock_guard lk(mu_);
        return fetches_;
    }

    /// Number of successful fetches that returned a LOWER generation than the previously
    /// served one (a store reset). Informational: the lower value was served.
    [[nodiscard]] std::uint64_t regressions() const {
        std::lock_guard lk(mu_);
        return regressions_;
    }

private:
    struct Entry {
        Result result;
        Clock::time_point at;       // freshness reference (see install())
        Clock::time_point started;  // when the read began (freshness reference of a success)
        std::uint64_t seq{0};       // read-start order under mu_; orders competing installs
    };

    bool fresh_locked(const Entry& e, Clock::time_point now) const {
        if (now <= e.at)
            return true;  // clock did not advance (or went backwards)
        const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - e.at);
        return age < (e.result.has_value() ? cfg_.ttl : cfg_.negative_ttl);
    }

    // Error text short enough for the small-string buffer of every supported standard
    // library, so building it cannot allocate (it is the last-resort arm).
    static Result nothrow_error() { return std::unexpected(std::string("fetch failed")); }

    // Never throws.
    Result run_fetch() noexcept {
        try {
            {
                std::lock_guard lk(mu_);
                ++fetches_;
            }
            if (!fetch_)
                return std::unexpected(std::string("generation fetch function not configured"));
            try {
                return fetch_();
            } catch (const std::exception& e) {
                return std::unexpected(std::string("generation fetch threw: ") + e.what());
            } catch (...) {
                return std::unexpected(
                    std::string("generation fetch threw a non-standard exception"));
            }
        } catch (...) {
            return nothrow_error();  // building the message (or taking mu_) failed
        }
    }

    // Record `r` as the cached outcome unless an invalidate() ran since `epoch`, or the held
    // entry came from a read that started later than this one (monotonic install, by `seq`),
    // or `r` is an error and `install_errors` is false. Never throws: a failure here only
    // means the next get() fetches again.
    void install(const Result& r, Clock::time_point started, std::uint64_t seq,
                 std::uint64_t epoch, bool install_errors = true) noexcept {
        try {
            std::lock_guard lk(mu_);
            if (epoch != epoch_)
                return;
            if (!r.has_value() && !install_errors)
                return;
            if (entry_ && seq < entry_->seq)
                return;  // an older read finishing last must not overwrite a newer one
            if (r.has_value()) {
                if (last_served_ && *r < *last_served_)
                    ++regressions_;
                last_served_ = *r;
            }
            // A success ages from when its read STARTED (conservative). An error ages from
            // when the read FINISHED: a slow failing read (a 2 s lease timeout) would
            // otherwise be stored already past `negative_ttl` and every heartbeat would
            // re-run it, defeating the negative cache. `seq` alone orders installs.
            entry_ = Entry{r, r.has_value() ? started : clock_(), started, seq};
        } catch (...) {
            try {
                std::lock_guard lk(mu_);
                if (epoch == epoch_)
                    entry_.reset();  // do not keep an entry that may be half-assigned
            } catch (...) {
            }
        }
    }

    Result wait_for_flight(const std::shared_future<Result>& f) const noexcept {
        try {
            if (f.wait_for(cfg_.max_wait) != std::future_status::ready)
                return std::unexpected(
                    std::string("timed out waiting for in-flight generation fetch"));
            return f.get();
        } catch (...) {
            return nothrow_error();  // broken promise, or the copy of the result threw
        }
    }

    // Owns one registered flight. The destructor ALWAYS clears `inflight_` (when it is still
    // this flight). The clear happens at most once: a second one could remove a NEWER flight
    // registered by another thread after the first. A promise that is never fulfilled is
    // broken by its own destructor, which wakes every waiter (wait_for_flight maps that to
    // an error).
    struct FlightGuard {
        GuardianGenerationCache& c;
        std::uint64_t epoch;
        bool cleared{false};

        ~FlightGuard() { clear(); }

        void clear() noexcept {
            if (cleared)
                return;
            try {
                std::lock_guard lk(c.mu_);
                if (epoch == c.epoch_)
                    c.inflight_ = {};  // an invalidate() already detached a stale flight
                cleared = true;
            } catch (...) {
                // mu_ could not be taken: the destructor retries once more.
            }
        }

        // Clear the flight BEFORE publishing the value, as the original ordering did, so a
        // waiter that wakes and calls get() again does not see this flight still registered.
        void fulfil(std::promise<Result>& p, const Result& r) noexcept {
            clear();
            try {
                p.set_value(r);
            } catch (...) {
                try {
                    p.set_exception(std::current_exception());
                } catch (...) {
                }
            }
        }
    };

    const FetchFn fetch_;
    const Config cfg_;
    const ClockFn clock_;
    mutable std::mutex mu_;
    std::optional<Entry> entry_;
    std::shared_future<Result> inflight_;  // valid() iff a fetch is running
    std::optional<std::uint64_t> last_served_;
    std::uint64_t epoch_{0};
    std::uint64_t read_seq_{0};  // last read-start sequence handed out (under mu_)
    std::uint64_t fetches_{0};
    std::uint64_t regressions_{0};
};

}  // namespace yuzu::server
