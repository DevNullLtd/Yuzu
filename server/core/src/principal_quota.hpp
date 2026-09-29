#pragma once

/// @file principal_quota.hpp
///
/// In-memory, thread-safe per-principal quota primitive (PR 4.4, ADR-1005
/// class engine principals — per-principal quota cap). Mirrors the token-
/// bucket idiom of `rate_limiter.hpp` (per-IP) and the already-shipped
/// per-principal cap in `mcp_session.hpp` (`per_principal_cap`), but folds
/// TWO dimensions — concurrency (in-flight reservation) and rate (token
/// bucket) — behind one `try_acquire()` call so callers get a single
/// admit/reject decision instead of composing two primitives by hand.
///
/// CAVEAT — per-instance only: this cap lives in one process's memory. A
/// multi-instance deployment (N server replicas behind a load balancer)
/// gives each principal N × the configured cap, not a fleet-wide cap.
/// Durable, cross-instance quota (a shared store keyed by principal) is
/// deferred to Phase 8 and tracked there — do not treat this class as a
/// global enforcement point until that lands.
///
/// SSE / streaming note: a streaming response DOES take a concurrency slot
/// (every engine request does — see `apply_engine_quota_gate`), but the
/// naive post-routing release fires as soon as routing hands off to the
/// chunked/SSE body — long before the stream finishes. So a streaming
/// route must instead **adopt** the acquired slot into its content-provider
/// resource-releaser via `detail::adopt_quota_slot_into_stream`
/// (`principal_quota_gate.hpp`), which holds the reservation for the
/// stream's real lifetime and releases it on disconnect/completion. Do NOT
/// route streaming through `try_rate_only()` — that leaves the stream
/// concurrency-unbounded and reintroduces the UP-1 cross-principal
/// worker-pool DoS. `try_rate_only()` has no production caller today and is
/// retained only for the primitive's own tests. The single source of truth
/// for the streaming-route contract is `principal_quota_gate.hpp`
/// (`is_streaming_path` registry + `adopt_quota_slot_into_stream`).

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yuzu::server {

/// Which side of a request is being debited. Phase 5: operator-side debit
/// under delegation (§5 step 6); dormant in 4.4 — every 4.4 caller passes
/// kEngine. The enum exists now so the wire/metric shape (QuotaDecision::side)
/// doesn't need to change again when Phase 5 lands.
enum class QuotaSide { kEngine, kOperator };

/// Which dimension a rejection came from (kNone when admitted).
enum class QuotaLimit { kNone, kConcurrency, kRate };

struct QuotaDecision {
    bool admitted{true};
    QuotaLimit limit{QuotaLimit::kNone};   // which dimension rejected (kNone if admitted)
    QuotaSide side{QuotaSide::kEngine};
    std::int64_t retry_after_ms{0};        // honest: rate -> bucket refill time; concurrency -> kConcurrencyRetryMs
};

class PrincipalQuota;

/// Move-only RAII reservation. On admit, holds one concurrency slot for the
/// principal that requested it and releases it on destruction (or on an
/// explicit `reset()`). On reject, holds nothing — `decision().admitted` is
/// false and the destructor is a no-op.
class QuotaSlot {
  public:
    QuotaSlot() = default;  // empty (holds nothing)

    QuotaSlot(QuotaSlot&& other) noexcept;
    QuotaSlot& operator=(QuotaSlot&& other) noexcept;

    QuotaSlot(const QuotaSlot&) = delete;
    QuotaSlot& operator=(const QuotaSlot&) = delete;

    /// Implicitly noexcept already (all subobjects have non-throwing dtors); spelled
    /// out so the guarantee is visible where callers reason about it.
    ~QuotaSlot() noexcept;

    bool admitted() const { return decision_.admitted; }
    const QuotaDecision& decision() const { return decision_; }

    /// Release the held concurrency slot early (if any). Idempotent — safe
    /// to call multiple times, and safe on an empty/rejected slot (no-op).
    ///
    /// `noexcept` is STRUCTURAL, not decorative (same rule as
    /// StreamBudget::Lease::release). This runs from ~QuotaSlot, which is itself
    /// noexcept, and ~QuotaSlot runs from an httplib content-provider releaser
    /// invoked by ~Response — so a throw escaping here is std::terminate and NO
    /// caller-side try/catch can intercept it: the terminate happens inside the
    /// destructor, before unwinding reaches any handler. The containment therefore
    /// has to live here, at the source, which is what makes it real.
    void reset() noexcept;

  private:
    friend class PrincipalQuota;

    QuotaSlot(PrincipalQuota* owner, std::string principal_id, QuotaDecision decision)
        : owner_(owner), principal_id_(std::move(principal_id)), decision_(decision) {}

    // Borrowed, non-owning back-pointer to the PrincipalQuota that minted this
    // slot; non-null iff this slot holds a concurrency reservation. Lifetime
    // safety: `PrincipalQuota` is a `ServerImpl` member and `~ServerImpl()` runs
    // `stop()` — whose `web_thread_.join()` waits for httplib's `listen()` to
    // return, which only happens after `ThreadPool::shutdown()` has JOINED every
    // worker thread. A streaming slot adopted into a content-provider releaser
    // therefore always releases (on its worker thread) before `principal_quota_`
    // is destroyed. Never dereference `owner_` outside `release()` (which takes
    // `mu_`); a slot must not outlive its PrincipalQuota by construction.
    PrincipalQuota* owner_{nullptr};
    std::string principal_id_;
    QuotaDecision decision_{};
};

struct PrincipalQuotaConfig {
    int max_concurrency{16};               // per-principal in-flight cap
    double rate_per_second{20.0};          // per-principal token-bucket refill
    double burst{40.0};                    // bucket capacity
    std::int64_t idle_evict_seconds{300};  // purge_stale threshold

    /// Hard ceiling on tracked keys; 0 = unlimited, which is the historical
    /// behaviour and stays correct for the engine-principal path (its keys are an
    /// operator-provisioned set that no unauthenticated caller can inflate — see
    /// purge_stale's comment).
    ///
    /// A caller whose key space is ATTACKER-INFLUENCED must set this. The OTA
    /// admission gate is the motivating case: it keys on the peer's certificate
    /// identity when one is presented and falls back to peer IP when none is, and
    /// the agent listener does not always require a client certificate, so a NAT'd
    /// peer rotating source ports would otherwise grow the map without bound
    /// (issue #935). At the ceiling a new key evicts the least-recently-seen entry
    /// that holds no in-flight reservation.
    std::size_t max_tracked{0};
};

/// Floor for an attacker-influenced key space. Below this, every insert evicts and
/// `locate_locked` mints a fresh FULL burst for the re-inserted key, so the rate
/// dimension stops limiting anything — a cap that disables the limiter it protects.
/// Callers that set `max_tracked` at all should clamp up to this.
inline constexpr std::size_t kMinPeersTracked = 1024;

/// Thread-safe per-principal quota tracker. One mutex guards a
/// `principal_id -> PerPrincipal` map; a `QuotaSlot`'s destructor re-locks
/// and decrements `in_flight` for the principal it was minted against.
class PrincipalQuota {
  public:
    explicit PrincipalQuota(PrincipalQuotaConfig cfg = {});

    /// Named, documented retry hint for a concurrency rejection — there is
    /// no natural "when will a slot free up" estimate the way a token
    /// bucket has a refill time, so this is a fixed short backoff rather
    /// than a magic literal scattered at call sites.
    static constexpr std::int64_t kConcurrencyRetryMs = 250;

    /// Acquire covers BOTH dimensions in one call: debits the token bucket
    /// (rate) AND reserves a concurrency slot. Returns an admitted
    /// QuotaSlot (holding the concurrency reservation) or a rejected
    /// QuotaSlot carrying the QuotaDecision (limit=kRate or kConcurrency).
    ///
    /// Ordering (deliberate, so a reject never leaks state): concurrency is
    /// checked FIRST without mutating anything; only if there is headroom
    /// does the call debit the rate bucket; only if that succeeds does it
    /// reserve the concurrency slot. A rate reject therefore never reserves
    /// concurrency, and a concurrency-at-capacity reject never touches the
    /// rate bucket — every rejected call leaves per-principal state exactly
    /// as it was before the call.
    QuotaSlot try_acquire(const std::string& principal_id, QuotaSide side);

    /// Rate-only debit for streaming/long-poll paths that must NOT hold a
    /// concurrency slot (see the SSE note in the file header). Returns a
    /// QuotaDecision — never reserves or releases a concurrency slot.
    QuotaDecision try_rate_only(const std::string& principal_id, QuotaSide side);

    /// Replace the configuration IN PLACE, without destroying this object.
    ///
    /// This exists so a caller that needs to reconfigure a quota never has to
    /// replace the PrincipalQuota itself. Replacing it is a use-after-free: every
    /// live `QuotaSlot` holds a raw back-pointer here (see `QuotaSlot::owner_`,
    /// whose own comment states "a slot must not outlive its PrincipalQuota by
    /// construction"), so destroying the object while any reservation is
    /// outstanding orphans that pointer and `~QuotaSlot` then writes through it.
    /// Reconfiguring in place keeps every outstanding slot valid.
    ///
    /// A lowered `burst` clamps existing buckets down to the new ceiling rather
    /// than leaving them holding more credit than the configuration now allows.
    /// `in_flight` counts are untouched — they belong to live reservations, and
    /// lowering `max_concurrency` below the current in-flight count simply admits
    /// nobody new until those drain.
    void set_config(const PrincipalQuotaConfig& cfg);

    /// Injectable steady clock — the token-bucket refill clock ONLY (`last_seen`,
    /// purge_stale's idle-eviction clock, stays wall-clock; see UP-4 in the .cpp).
    /// Defaults to `std::chrono::steady_clock::now`. Mirrors the ClockFn idiom in
    /// `engine_principal_store.hpp` so a test can step time arithmetically instead
    /// of sleeping: this class's own test previously observed refill by waiting on
    /// a real `std::this_thread::sleep_for(30ms)`, which is both slow and racy on a
    /// loaded shared runner.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    /// TEST ONLY. An empty fn restores the real steady clock (same contract as
    /// `EnginePrincipalStore::set_clock_for_test`). Not synchronised against
    /// concurrent `try_acquire`/`refund` calls — the clock is read before `mu_` is
    /// taken, deliberately (see try_acquire), so a test must install the fn before
    /// putting the quota under load, not while it is serving.
    void set_clock_for_test(ClockFn fn);

    /// Return one token to `principal_id`'s bucket, capped at `burst`.
    ///
    /// For a caller that charges up-front but then fails for a reason that is the
    /// SERVER's fault rather than the peer's: a server-imposed deadline, an
    /// unavailable backend, or a failure before any real work was done. Charging
    /// those meters failures instead of usage, and lets a genuinely slow-but-honest
    /// client spend itself into a lockout — the pathology recorded on issues #934
    /// (7.5h) and #941 (75min). Refunding keeps the bucket a measure of work done.
    ///
    /// Deliberately does NOT create an entry: refunding an untracked principal (one
    /// the sweeper or the `max_tracked` ceiling already reclaimed) is a no-op, so a
    /// late refund can never resurrect state that was just evicted, nor mint a
    /// full-burst entry for a key that is no longer tracked.
    ///
    /// Refunds the RATE dimension only. Concurrency is released by ~QuotaSlot and
    /// must not be double-released here.
    void refund(const std::string& principal_id);

    /// Keys evicted by the `max_tracked` ceiling since construction. Always 0 when
    /// `max_tracked == 0`. Surfaced so an operator can see the cap biting rather
    /// than inferring it from a flat `principal_count()`.
    std::uint64_t evicted_count() const;

    /// Optional hook fired once per eviction, so a caller can drive a real
    /// Prometheus counter at the moment the cap bites rather than sampling
    /// `evicted_count()` and differencing it (which loses evictions between
    /// samples and cannot be expressed as a counter at all).
    ///
    /// CONTRACT: invoked while `mu_` is HELD. It must not call back into this
    /// PrincipalQuota — that would self-deadlock on a non-recursive mutex — and
    /// must be cheap and non-throwing in practice. Incrementing a metrics counter
    /// satisfies all three; anything more belongs outside.
    void set_on_evict(std::function<void()> fn);

    /// Purge principals idle for longer than `idle_evict_seconds`, as of
    /// `now_epoch_seconds`. A principal with a live in-flight reservation
    /// (in_flight > 0) is never purged, even if idle past the threshold —
    /// purging it would orphan the eventual QuotaSlot::release() into a
    /// freshly re-inserted entry.
    ///
    /// NO PRODUCTION CALLER as of the governance hardening round — parity
    /// with the also-unwired `RateLimiter::purge_stale()`. Deliberate, not
    /// an oversight: the map is bounded by the count of distinct
    /// authenticated engine principals (a small, operator-provisioned set —
    /// nothing an unauthenticated caller can inflate), so unbounded growth
    /// isn't the exposure an IP-keyed limiter would have. Wiring this to a
    /// periodic sweep is a reasonable follow-up once engine-principal counts
    /// are large enough for the map's steady-state memory to matter; when
    /// that lands, do NOT add it to `health_recompute_thread_` casually —
    /// that thread's sweep body is a shared serial budget with the
    /// security-relevant revocation sweep also on it (see the comment at
    /// its call site in server.cpp), so extending it needs SRE sign-off,
    /// not just a trivial call-site addition.
    void purge_stale(std::int64_t now_epoch_seconds);

    /// Number of tracked principals (for monitoring / tests).
    std::size_t principal_count() const;

    /// Test-only introspection: current in-flight count for a principal
    /// (0 if untracked).
    int in_flight(const std::string& principal_id) const;

  private:
    friend class QuotaSlot;

    struct PerPrincipal {
        int in_flight{0};
        double tokens{0.0};
        // UP-4: the token-bucket refill clock is std::chrono::steady_clock
        // (monotonic, immune to NTP steps/wall-clock adjustment) — NOT
        // system_clock. A wall-clock backward step would snap every
        // principal's bucket to `cfg_.burst` (rate-limit bypass window); a
        // forward step would silently stall refill for however long the
        // step was. last_seen (idle-eviction bookkeeping for purge_stale)
        // deliberately stays wall-clock — see purge_stale's doc comment.
        std::chrono::steady_clock::time_point last_refill{};
        double last_seen{0.0};  // epoch seconds (purge_stale's clock, unchanged)
    };

    // Caller holds mu_. Inserts a fresh, full-bucket entry on first sight.
    PerPrincipal& locate_locked(const std::string& principal_id,
                                std::chrono::steady_clock::time_point now);

    // Caller holds mu_. Refills `pp`'s bucket up to `cfg_.burst` for the
    // elapsed time since its last refill, then stamps last_refill := now.
    void refill_locked(PerPrincipal& pp, std::chrono::steady_clock::time_point now) const;

    // Called by QuotaSlot::reset()/~QuotaSlot(). Decrements in_flight for
    // `principal_id` if the principal is still tracked; a no-op if it has
    // since been purged (defensive — purge_stale already guards against
    // purging a live in-flight principal, so this should not happen in
    // practice).
    /// noexcept: called from QuotaSlot::reset(), which runs in destructors on
    /// httplib's response-teardown path. See QuotaSlot::reset's comment.
    void release(const std::string& principal_id) noexcept;

    // Caller holds mu_. Enforces cfg_.max_tracked BEFORE an insert, so the map is
    // never transiently over the ceiling: evicts the least-recently-seen entry that
    // holds no in-flight reservation.
    //
    // If every tracked entry is in-flight, the insert is allowed through rather
    // than denied. That is a deliberate fail-open on CARDINALITY, and the overshoot
    // is bounded by the number of handlers that can be executing at once.
    //
    // THAT BOUND IS THE gRPC THREAD CEILING, not the stream cap. An earlier version
    // of this comment cited GRPC_ARG_MAX_CONCURRENT_STREAMS, which is PER
    // CONNECTION with connections uncapped — it bounds nothing globally, so the
    // justification was false and the map could in principle grow without limit.
    // `Config::grpc_max_threads` (applied via ResourceQuota::SetMaxThreads) is the
    // real ceiling; the OTA caller additionally holds a server-wide transfer cap.
    // Denying instead would turn a memory-shape concern into a refusal to serve
    // legitimate callers, which is the worse trade.
    void enforce_cap_locked();

    PrincipalQuotaConfig cfg_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, PerPrincipal> principals_;
    ClockFn clock_{[] { return std::chrono::steady_clock::now(); }};
    std::uint64_t evicted_{0};
    std::function<void()> on_evict_{};
};

}  // namespace yuzu::server
