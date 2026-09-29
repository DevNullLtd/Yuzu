#pragma once

/// @file stream_budget.hpp
/// Shared admission budget for held-open SSE responses (ADR-1005 Decision 15(h)).
///
/// Every held-open SSE response pins one httplib worker thread for the whole
/// life of the stream (the content provider blocks in `cv.wait_for`). The
/// worker pool is shared by EVERY surface on the web server, so the cap on
/// concurrent streams must be computed ONCE across all of them — not
/// per-route. This budget is that single instance: MCP's `GET /mcp/v1/` takes
/// leases from it today; the streamed-POST channel (track 2f PR 3) and
/// `GET /api/v1/events` (issue #2056) adopt the SAME instance rather than
/// minting a parallel counter, or the shared pool can still be starved by the
/// surfaces that opted out.
///
/// Header-only, sibling of `event_bus.hpp` (whose sink primitives it pairs
/// with) — small enough that a separate TU adds no value, and directly
/// unit-testable.

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <functional>
#include <unordered_map>
#include <utility>

namespace yuzu::server::detail {

/// Plain-REST reserve: worker threads held back from streams, so held-open connections
/// can never starve ordinary request/response traffic (ADR-0034 Decision 1; ADR-1005
/// execution plan Decision 15(h); chaos CH-6).
///
/// This is a real reserve, not an aspiration: EVERY surface that holds a response open
/// leases from the one budget below — MCP's GET channel, MCP streamed POST, `GET
/// /api/v1/events`, the dashboard executions drawer, and the legacy `/events` stream.
/// A surface that held a worker without a lease would make the arithmetic here a
/// fiction.
inline constexpr std::size_t kPlainRestReserveDefault = 8;

/// Workers a single permitted stream can pin at once. A stream is normally one provider on
/// one worker — but a takeover leaves the superseded provider draining (still pinning its
/// worker) while the replacement runs, and `McpStreamState` allows at most ONE pending
/// handover per session. So the pool must afford two workers for every stream admitted, or
/// a fleet of reconnecting clients oversubscribes it by the number of handovers in flight.
inline constexpr std::size_t kMaxProvidersPerStream = 2;

/// Concurrent held-open responses the server is sized for, across ALL surfaces.
///
/// This is the number an operator reasons about, and the pool is derived FROM it — not the
/// other way round (ADR-0034 Decision 2). The previous arrow pointed the wrong way: the pool
/// was httplib's accidental default (32 on an 8-core box) and the stream cap fell out of it
/// at 12 — while this platform's own design notes size it for "hundreds of agentic clients
/// per server" (`event_bus.hpp`). A cap two orders of magnitude below the workload is not a
/// safety feature, it is a self-inflicted scarcity.
///
/// A stream costs a BLOCKED thread: ~8-16 KB resident (the 8 MB stack is virtual), zero CPU,
/// and one wakeup per heartbeat. 128 streams is a few MB and a few tens of wakeups a second.
inline constexpr std::size_t kTargetHeldOpenStreamsDefault = 128;

/// Workers needed to honour a stream target, with the plain-REST reserve intact.
/// The inverse of the old `derive_stream_budget`, and the direction the arrow should have
/// pointed from the start.
inline constexpr std::size_t derive_worker_pool(std::size_t target_streams,
                                                std::size_t plain_rest_reserve) {
    return kMaxProvidersPerStream * target_streams + plain_rest_reserve;
}

/// Held-open responses a given pool can afford once the reserve is held back. Retained as
/// the safety clamp for an operator who pins `--http-worker-threads` by hand: the target is
/// honoured only if the pool they chose can actually carry it.
inline constexpr std::size_t derive_stream_budget(std::size_t pool_max,
                                                  std::size_t plain_rest_reserve,
                                                  std::size_t requested_global_cap) {
    const std::size_t spare = pool_max > plain_rest_reserve ? pool_max - plain_rest_reserve : 0;
    const std::size_t affordable = spare / kMaxProvidersPerStream;
    return requested_global_cap < affordable ? requested_global_cap : affordable;
}

/// Ceiling on the DERIVED worker pool, and therefore on threads created at boot.
///
/// The pool is created eagerly and in full (see the note in server.cpp): that is the
/// safe direction, because a host that cannot afford the threads fails at startup and
/// never serves. The hazard it leaves is asking for an absurd number in the first
/// place — `--max-sse-streams 4096` derives 8200 threads — so the fix is to bound the
/// ask, not to defer it. 2048 threads still affords 1020 concurrent streams, an order
/// of magnitude above the 128 default; a target beyond that is clamped by
/// `derive_stream_budget` and warned about at boot, exactly like any other pool the
/// operator's target outruns.
inline constexpr std::size_t kMaxHttpWorkerThreads = 2048;

/// Floor for an explicit `--http-worker-threads`: the smallest pool that can still carry
/// ONE stream with the reserve intact.
///
/// This MUST be derived, not picked. It was previously a hand-written 8, which equals
/// `kPlainRestReserveDefault` — so `derive_stream_budget(8, 8, N)` computed `(8-8)/2 == 0`
/// and the floor sat inside its own dead zone: any `--http-worker-threads` in [1,9] clamped
/// the budget to 0, and a 0 cap rejects unconditionally (`total_ >= global_cap` is
/// `0 >= 0`). That silently 429'd EVERY streaming surface server-wide as they stood at
/// the time — MCP GET, /api/v1/events, the dashboard drawer and legacy /events — from
/// behind a knob that reads like a tuning parameter, which is the exact failure this
/// constant exists to prevent.
inline constexpr std::size_t kMinHttpWorkerThreads =
    derive_worker_pool(1, kPlainRestReserveDefault);

/// The floor must afford at least one stream, or it is not a floor. Compiler-checked so the
/// two constants above can never drift back into the dead zone.
static_assert(derive_stream_budget(kMinHttpWorkerThreads, kPlainRestReserveDefault, 1) >= 1,
              "kMinHttpWorkerThreads must afford at least one held-open stream");

/// Per-surface per-principal policies. These are ANTI-MONOPOLY limits, not capacity limits —
/// capacity is the global cap alone. They differ per surface because the questions differ: an
/// agentic token holding MCP streams is not the same actor as an operator with nine dashboard
/// tabs open, and one number cannot answer both without locking somebody out of the product.
inline constexpr std::size_t kPerPrincipalApiEvents = 16;
inline constexpr std::size_t kPerPrincipalDashboard = 16;
/// Fallback bucket for a caller whose principal could not be resolved. No shipped surface
/// reaches it today — the legacy `/events` stream is session-gated by the pre-routing
/// chokepoint (see the `/events` handler in server.cpp) — so it exists as defence-in-depth
/// against a future exempt-list change, deliberately small enough that an unauthenticated
/// caller could not pin the pool if one ever arrived.
inline constexpr std::size_t kPerPrincipalAnonymous = 4;

/// Max concurrent STREAMED-POST responses one principal may hold on POST /mcp/v1/ (2f PR 3b,
/// SSE-on-POST). The budget-side per-principal anti-monopoly cap for the streamed-POST surface.
/// It is deliberately the twin of `kMaxStreamedPostsPerSession` (mcp_stream.hpp): the same
/// number bounds the eviction-exempt pinned final-frame slots the ring reserves per session, so
/// admission here can never let in more streamed POSTs than the ring can pin finals for. The
/// equality is enforced by a `static_assert` in mcp_stream.hpp (both constants are visible there;
/// stream_budget.hpp cannot include mcp_stream.hpp without a cycle, so the assert lives on that
/// side of the one-way include edge).
inline constexpr std::size_t kPerPrincipalMcpPost = 4;

/// The surfaces that hold a response open. A CLOSED set — it is the metric label, and it is
/// the list ADR-0034 says must be exhaustive. Adding a new streaming route means adding a
/// value here and taking a lease; there is no third option.
enum class SseSurface {
    kMcpGet,          ///< GET /mcp/v1/          — token, principal-bound session
    kMcpPost,         ///< POST /mcp/v1/ (streamed, SSE-on-POST — 2f PR 3b) — token, principal-bound session
    kApiEvents,       ///< GET /api/v1/events    — token, Execution:Read
    kDashboardExec,   ///< GET /sse/executions/{id} — cookie, the executions drawer
    kLegacyEvents,    ///< GET /events           — the legacy dashboard stream
};

inline const char* to_string(SseSurface s) {
    switch (s) {
    case SseSurface::kMcpGet:
        return "mcp_get";
    case SseSurface::kMcpPost:
        return "mcp_post";
    case SseSurface::kApiEvents:
        return "api_events";
    case SseSurface::kDashboardExec:
        return "dashboard_exec";
    case SseSurface::kLegacyEvents:
        return "legacy_events";
    }
    return "unknown";
}

/// THE admission budget for held-open responses — one instance, every surface.
///
/// The global cap is the only thing protecting the shared worker pool, so it is the
/// budget's own business. The PER-PRINCIPAL cap is a per-surface POLICY and is therefore
/// supplied by the caller: an agentic token holding 4 MCP streams is a different question
/// from an operator with 9 dashboard tabs open, and a single number cannot answer both
/// without locking somebody out of their own product.
///
/// REJECT-not-evict (Decision 15(j)): a cap hit denies the NEW stream; a live stream is
/// never torn down to make room for a newcomer, so one noisy principal cannot cut another's.
///
/// Thread-safe: httplib dispatches attach/release across worker threads.
class StreamBudget {
public:
    struct Config {
        /// Held-open responses allowed across ALL surfaces. Derived from the worker pool,
        /// which is in turn derived from the operator's declared stream target (ADR-0034).
        std::size_t global_cap = kTargetHeldOpenStreamsDefault;
    };

    explicit StreamBudget(Config cfg) : cfg_(cfg) {}

    StreamBudget(const StreamBudget&) = delete;
    StreamBudget& operator=(const StreamBudget&) = delete;

    /// Per-principal counting is keyed by SURFACE too: a principal's dashboard tabs and
    /// their MCP streams are different allowances answering different questions.
    struct Key {
        SseSurface surface = SseSurface::kMcpGet;
        std::string principal;

        bool operator==(const Key& o) const noexcept {
            return surface == o.surface && principal == o.principal;
        }
    };

    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return std::hash<std::string>{}(k.principal) ^
                   (static_cast<std::size_t>(k.surface) * 0x9e3779b97f4a7c15ULL);
        }
    };

    /// Move-only RAII slot. Releasing is idempotent and never throws, so a
    /// stream's slot is returned exactly once no matter which path
    /// (client disconnect, revocation, shutdown, exception) tears it down.
    class Lease {
    public:
        Lease() = default;

        Lease(Lease&& other) noexcept
            : budget_(other.budget_), key_(std::move(other.key_)) {
            other.budget_ = nullptr;
        }

        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                release();
                budget_ = other.budget_;
                key_ = std::move(other.key_);
                other.budget_ = nullptr;
            }
            return *this;
        }

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        ~Lease() { release(); }

        explicit operator bool() const { return budget_ != nullptr; }

        /// Return the slot early. Idempotent — a second call is a no-op, so the
        /// destructor after an explicit release does nothing.
        ///
        /// `noexcept` is structural, not decorative: this runs from ~Lease (itself
        /// implicitly noexcept) on a provider-teardown path, so a throwing
        /// `lock_guard` here would terminate anyway. Making it explicit means the
        /// "a slot is always returned" claim cannot be quietly broken by a future
        /// throwing member.
        void release() noexcept {
            if (budget_ != nullptr) {
                budget_->release_slot(key_);
                budget_ = nullptr;
            }
        }

    private:
        friend class StreamBudget;
        Lease(StreamBudget* budget, Key key) : budget_(budget), key_(std::move(key)) {}

        StreamBudget* budget_ = nullptr;
        Key key_;
    };

    struct AcquireResult {
        Lease lease;                          ///< engaged iff admitted
        const char* reject_reason = nullptr;  ///< set iff rejected; a static literal, safe to
                                              ///< use as a bounded metric label value
    };

    /// Reject reasons — a CLOSED set (bounded `yuzu_mcp_stream_rejects_total{reason}`
    /// cardinality; never derive a label from caller-controlled input).
    static constexpr const char* kRejectPerPrincipal = "per_principal_stream_cap";
    static constexpr const char* kRejectGlobal = "global_stream_cap";

    enum class Admission {
        kEnforceCaps,  ///< a NEW stream: subject to both caps
        kTakeover,     ///< replaces a stream this principal already holds
    };

    /// A takeover is admitted without a cap check but STILL TAKES A LEASE. It is not
    /// a new stream — it replaces one the principal already has — and refusing it
    /// would lock a reconnecting client out behind its own not-yet-reaped zombie
    /// stream. It must still be counted, because the superseded provider goes on
    /// pinning its worker until it drains; an uncounted pinned worker is precisely
    /// the hole this budget exists to close. The resulting overshoot is bounded by
    /// `kMaxProvidersPerStream`, which `derive_stream_budget` reserves for.
    /// `per_principal_cap` is the CALLER's policy for its surface (0 = no per-principal
    /// limit — the global cap still applies, and it is the only thing the worker pool
    /// actually needs). Counting is keyed by (surface, principal), so an operator's
    /// dashboard tabs and their MCP streams do not compete for the same allowance.
    AcquireResult try_acquire(SseSurface surface, const std::string& principal,
                              std::size_t per_principal_cap,
                              Admission mode = Admission::kEnforceCaps) {
        const Key key{surface, principal};
        std::lock_guard<std::mutex> lk(mu_);
        auto it = per_principal_.find(key);
        const std::size_t held = it == per_principal_.end() ? 0 : it->second;
        if (mode == Admission::kEnforceCaps) {
            if (total_ >= cfg_.global_cap) {
                return {Lease{}, kRejectGlobal};
            }
            if (per_principal_cap > 0 && held >= per_principal_cap) {
                return {Lease{}, kRejectPerPrincipal};
            }
        }
        // Every ALLOCATING step happens before any counter moves; every step after the
        // first counter moves is noexcept. Get this order wrong in either direction and
        // you get one of two bugs:
        //
        //   * counters first, then allocate — a throw leaks a slot for the life of the
        //     process (a cap that silently tightens under memory pressure), with no lease
        //     in existence to give it back;
        //   * construct the Lease first — a throw from the map insert then unwinds
        //     ~Lease, which calls release_slot(), which re-locks THIS mutex while we still
        //     hold it. Self-deadlock on a non-recursive mutex.
        //
        // So: make the string copy and reserve the map node (both may throw, nothing has
        // moved), then move the counters (cannot throw), then hand the already-owned
        // string to the Lease by move (cannot throw).
        Key owner = key;
        auto [entry, inserted] = per_principal_.try_emplace(key, held);
        entry->second = held + 1;
        ++total_;
        return {Lease{this, std::move(owner)}, nullptr};
    }

    /// Held-open responses right now, across every surface. THE number: this is what the
    /// worker pool is actually spending, and `active() / capacity()` is the utilisation an
    /// operator needs (ADR-0034 Decision 3) — no per-surface gauge can express it.
    std::size_t active() const {
        std::lock_guard<std::mutex> lk(mu_);
        return total_;
    }

    std::size_t capacity() const { return cfg_.global_cap; }

    std::size_t active_for(SseSurface surface, const std::string& principal) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = per_principal_.find(Key{surface, principal});
        return it == per_principal_.end() ? 0 : it->second;
    }

    Config config() const { return cfg_; }

    /// #2703 Gate 7 merge-slice item 2: server shutdown's close-signal for
    /// every held-open stream that shares this budget. Every SSE content
    /// provider on the simpler surfaces (`/events`, `/api/v1/events`, the
    /// dashboard executions drawer) already re-checks its wait predicate at
    /// least every 3s (the keep-alive tick) — adding this to that SAME
    /// predicate closes an idle stream within one tick, with no new
    /// cv-plumbing. NOT wired into the MCP GET/streamed-POST surfaces
    /// (`McpStreamPump`'s teardown is driven by `session_alive_`/session-
    /// registry revalidation, a materially different mechanism) — those are
    /// instead close-signalled via `McpSessionRegistry::shutdown()`, called
    /// from `ServerImpl::stop()` alongside this flag (#3042): a GET pump has
    /// its own sink in the closed session's state, so it gets a genuine wake;
    /// a streamed-POST pump's sink is separate and untouched by that close
    /// call, so it only notices on its own next `session_alive_()` tick. A
    /// stream stuck mid-write (neither a wake nor a poll reaches a pump that
    /// isn't waiting) still falls back on the bounded web-thread join +
    /// `_Exit` escalation in `ServerImpl::stop()`.
    void begin_closing() { closing_.store(true, std::memory_order_release); }
    bool closing() const { return closing_.load(std::memory_order_acquire); }

private:
    /// CONTAINED AT THE SOURCE, and it has to be here rather than at any call site:
    /// this is reached from ~Lease -> an httplib content-provider releaser ->
    /// ~Response, and a destructor is implicitly noexcept, so a throwing lock_guard
    /// would std::terminate INSIDE the destructor, before unwinding could reach any
    /// caller's try/catch. A guard at the call site is decorative (#2037 class).
    /// `PrincipalQuota::release` states the same reasoning for the same shape, and
    /// `sse_resource_release`'s header comment already ASSERTED this function
    /// behaved this way - it did not until now.
    ///
    /// Leaking one slot beats aborting the process, and a mutex that cannot be
    /// locked means the accounting is already unreliable.
    void release_slot(const Key& key) noexcept {
        try {
            release_slot_locked(key);
        } catch (...) { // NOLINT(bugprone-empty-catch)
        }
    }

    void release_slot_locked(const Key& key) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = per_principal_.find(key);
        if (it == per_principal_.end()) {
            return;  // defensive: a lease is only minted through try_acquire
        }
        if (--it->second == 0) {
            // Erase at zero so the map is bounded by LIVE principals, not by every
            // principal that ever streamed (Decision 15(d): all in-memory state bounded).
            per_principal_.erase(it);
        }
        if (total_ > 0) {
            --total_;
        }
    }

    mutable std::mutex mu_;
    Config cfg_;
    std::size_t total_ = 0;
    std::unordered_map<Key, std::size_t, KeyHash> per_principal_;
    std::atomic<bool> closing_{false};
};

}  // namespace yuzu::server::detail
