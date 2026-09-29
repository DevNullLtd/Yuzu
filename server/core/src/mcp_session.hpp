#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace yuzu {
class MetricsRegistry;
}

// MCP Streamable HTTP session registry (ADR-1005 Decision 15, track 2f).
namespace yuzu::server::mcp {

class McpStreamState;

// In-memory registry of `Mcp-Session-Id` sessions.
//
// A session is transport affinity + (from PR 2) a replay cursor — it is NEVER
// an auth credential: per-request token auth stands on every method
// (Decision 15(a)). State is bounded and non-durable: a server restart drops
// every session, the client gets a 404 on its next call and re-initializes,
// exactly as the MCP spec prescribes (no Postgres, no new store).
//
// Thread-safe. httplib dispatches requests across worker threads; every public
// method takes the internal mutex.
class McpSessionRegistry {
public:
    struct Config {
        std::size_t per_principal_cap = 8;      // Decision 15(d): bounded per-principal
        std::size_t global_cap = 1024;          // Decision 15(d): bounded globally
        std::chrono::seconds idle_ttl{1800};    // 30 min; slides on every use
        // Per-session replay ring, bounded on BOTH axes (see mcp_stream.hpp; the frame
        // count alone is not a memory bound). The frame cap must not exceed the sink's
        // own queue cap or a full-ring replay would trip the sink's drop-oldest guard
        // and gap a resume the ring could have served — static_assert'd in mcp_stream.cpp.
        std::size_t ring_cap = 500;
        std::size_t ring_bytes_cap = 64 * 1024;
    };

    // Injectable monotonic clock for deterministic tests (defaults to
    // steady_clock::now). Only the *difference* between calls is meaningful.
    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;

    // Default ctor delegates in the .cpp (Config's default member initializers
    // cannot be consumed by a `= {}` default argument before this enclosing class
    // is complete — GCC rejects it; the delegation resolves Config{} where the
    // class is complete).
    McpSessionRegistry();
    explicit McpSessionRegistry(Config cfg, ClockFn clock = {},
                                yuzu::MetricsRegistry* metrics = nullptr);
    ~McpSessionRegistry();

    struct MintResult {
        bool ok = false;
        std::string session_id;     // set iff ok
        // set iff !ok: "per_principal_cap" | "global_cap" | "id_generation" | "shutdown"
        std::string reject_reason;
    };

    // Mint a fresh, principal-bound session id (≥128-bit CSPRNG, lowercase hex).
    // The id is ALWAYS server-generated; a client-supplied id is never adopted
    // (the caller never passes one — no session fixation, Decision 15(a)/CH-8).
    // On a cap hit this REJECTS (ok=false, reason set); a live session is NEVER
    // evicted to make room (Decision 15(j)).
    MintResult mint(const std::string& principal);

    enum class ValidateResult {
        kValid,    // id exists AND is bound to `principal`
        kUnknown,  // id absent, expired, OR bound to a different principal
    };

    // Principal-bound validate. A valid id presented under any *other* principal
    // returns kUnknown — the same result a never-existed id yields, so there is
    // no cross-principal existence oracle (Decision 15(a) / CH-8). On kValid the
    // session's last-seen is refreshed so the idle TTL slides.
    ValidateResult validate_and_touch(const std::string& id, const std::string& principal);

    // The session's GET SSE stream state (replay ring + live sink), minted with
    // the session. Principal-bound exactly like validate_and_touch: an unknown id
    // OR a foreign principal yields nullptr (no existence oracle). Touches
    // last_seen on a hit.
    std::shared_ptr<McpStreamState> stream_for(const std::string& id,
                                               const std::string& principal);

    // DELETE /mcp/v1/. Removes the session iff it exists AND is bound to
    // `principal`; returns true on removal, false otherwise (same no-oracle
    // posture as validate). A live GET stream on that session is closed
    // (kSessionTerminated) — the client learns why rather than seeing a bare EOF.
    bool terminate(const std::string& id, const std::string& principal);

    // Evict idle-expired sessions (closing any live stream). Invoked
    // opportunistically on mint/validate; exposed for tests.
    void gc();

    std::size_t active_count() const;

    // True iff `id` is present, bound to `principal`, AND not idle-expired at the
    // time of the call. PURE READ - track 2f bridge-sweep support: it does NOT
    // slide last_seen (a parked bridge record must never extend session life),
    // runs no gc, and erases nothing (an expired entry is left for the next
    // touching call to reap). The liveness predicate is the exact negation of
    // gc_locked's expiry test (`now() - last_seen > idle_ttl`) so the two can
    // never disagree. Same no-oracle posture as validate_and_touch: a foreign
    // principal reads as absent.
    bool exists(const std::string& id, const std::string& principal) const;

    // Server shutdown close-signal (#3042): stickily refuse every future mint()
    // (reject_reason "shutdown") and close every currently-live stream
    // (kSessionTerminated). A GET pump has its sink IN the closed McpStreamState,
    // so this wakes it immediately; a streamed-POST pump's sink is separate and
    // untouched by the close, so it instead drains by riding its own next tick
    // check (session_alive_) to discover the registry is gone — both land well
    // inside the shutdown grace bound, just via different mechanisms.
    // Idempotent — a second call closes nothing and returns 0. NOT a full
    // close-all guarantee: a caller that already holds a
    // `stream_for()` result and attaches a fresh sink after this returns will
    // still get a stream, but one now emptied from the registry — its pump's
    // first `session_alive_` re-check (one tick, ~3s) finds the session gone and
    // closes it. That residual window is accepted rather than made sticky on
    // McpStreamState itself (larger diff, no bound improvement — see #3042).
    // noexcept: called from ServerImpl::stop(), itself noexcept — every step
    // that can throw (McpStreamState::close(), gauge publish) is internally
    // contained so no exception escapes this call.
    std::size_t shutdown() noexcept;

private:
    struct Entry {
        std::string principal;
        std::chrono::steady_clock::time_point created;
        std::chrono::steady_clock::time_point last_seen;
        std::shared_ptr<McpStreamState> stream;  // never null; shared with a live provider
    };

    std::chrono::steady_clock::time_point now() const;
    // Erase idle-expired entries and RETURN their stream states — the caller closes
    // them AFTER releasing mu_. Lock order is McpStreamState::mu_ → SseSinkState::mu,
    // and a publisher already holds McpStreamState::mu_ when it touches a sink, so
    // the registry must never call into a stream while holding its own mutex.
    std::vector<std::shared_ptr<McpStreamState>> gc_locked();  // caller holds mu_
    std::size_t principal_count_locked(const std::string& p) const;  // caller holds mu_
    // Caller must NOT hold mu_ — this takes the process-global metrics mutex, and
    // /metrics holds that one for a whole exposition build.
    void publish_active_gauge(std::size_t active) const;

    Config cfg_;
    ClockFn clock_;
    yuzu::MetricsRegistry* metrics_ = nullptr;
    mutable std::mutex mu_;
    std::unordered_map<std::string, Entry> sessions_;  // session id → entry
    bool closing_ = false;  // sticky; set once by shutdown(), guarded by mu_
};

}  // namespace yuzu::server::mcp
