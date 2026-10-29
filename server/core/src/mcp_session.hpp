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
namespace yuzu::server::auth {
struct Session;
}

// MCP Streamable HTTP session registry (ADR-1005 Decision 15, track 2f).
namespace yuzu::server::mcp {

class McpStreamState;

// What a session is bound to: the principal AND the credential class that minted it.
//
// The class is four fields of the authenticated auth::Session that together decide what
// a caller may do on /mcp/v1/: how it authenticated (auth_source), what kind of
// principal it is (principal_kind), the MCP tier it carries (mcp_tier) and the service
// scope it is confined to (token_scope_service). The principal and the four class
// fields are compared field by field (defaulted operator==, no joined string, so a
// value containing a separator cannot alias another). A foreign principal never matches; the same principal presenting a
// different class does not match either (ValidateResult::kCredentialMismatch).
//
// Server-derived. The class fields are never sent to a client, logged or audited; a
// mismatch is reported only as the fixed reason token `credential_mismatch`. No
// implicit conversion from a string: a caller that has only a username must say so explicitly, which keeps a
// class-blind call site from compiling by accident.
struct McpSessionBinding {
    std::string principal;            // auth::Session::username
    std::string auth_source;
    std::string principal_kind;
    std::string mcp_tier;
    std::string token_scope_service;

    bool operator==(const McpSessionBinding&) const = default;
};

// The binding an authenticated session presents. Defined in mcp_session.cpp (which
// includes auth.hpp); this header keeps its forward-declaration posture.
[[nodiscard]] McpSessionBinding binding_for(const auth::Session& session);

// In-memory registry of `Mcp-Session-Id` sessions.
//
// A session is transport affinity plus a replay cursor (the per-session ring that GET
// resume reads). It is NOT an auth credential: every request still authenticates, and
// that per-request credential must still be valid on every method (Decision 15(a)).
// What the session adds is a binding to the principal AND the credential class that
// minted it (McpSessionBinding): a request that presents the id is served only if its
// authenticated binding equals the one the session was minted under. That check runs on
// GET attach and resume, on a POST that presents the id, on the streamed-POST and GET
// per-tick liveness check, and on DELETE; ring content is released only past it.
//
// Residuals, stated so nobody reads more into the binding than it gives:
//  - Two distinct credentials of the SAME principal and SAME class (say a token and its
//    rotated successor, or two re-logins) are interchangeable here; they carry identical
//    authority, so nothing is gained by telling them apart.
//  - The per-tick credential revalidation of an open stream is principal-only; the class
//    is compared at attach (and on every later request that presents the id), not
//    re-derived on each tick.
//
// State is bounded and non-durable: a server restart drops every session, the client
// gets a 404 on its next call and re-initializes, exactly as the MCP spec prescribes
// (no Postgres, no new store).
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

    // Mint a fresh session id (≥128-bit CSPRNG, lowercase hex) bound to `binding`.
    // The id is ALWAYS server-generated; a client-supplied id is never adopted
    // (the caller never passes one — no session fixation, Decision 15(a)/CH-8).
    // On a cap hit this REJECTS (ok=false, reason set); a live session is NEVER
    // evicted to make room (Decision 15(j)). The per-principal cap counts by
    // `binding.principal` alone, never the whole binding, so it does not fragment by class.
    MintResult mint(const McpSessionBinding& binding);

    enum class ValidateResult {
        kValid,               // id exists AND is bound to exactly `binding`
        kUnknown,             // id absent, expired, OR bound to a different principal
        kCredentialMismatch,  // id exists for this principal, minted under another class
    };

    // Binding-bound validate. A valid id presented under any *other* principal
    // returns kUnknown — the same result a never-existed id yields, so there is
    // no cross-principal existence oracle (Decision 15(a) / CH-8). The same
    // principal under a different credential class returns kCredentialMismatch, which a
    // caller may AUDIT distinctly but must answer on the wire exactly as kUnknown (the
    // audit trail carries the distinction, the client does not). Only kValid refreshes
    // last-seen, so the idle TTL slides; a mismatch never touches the entry and never
    // terminates the owner's session.
    ValidateResult validate_and_touch(const std::string& id, const McpSessionBinding& binding);

    // The session's GET SSE stream state (replay ring + live sink), minted with
    // the session. Bound exactly like validate_and_touch: an unknown id, a foreign
    // principal OR a different credential class yields nullptr (no existence oracle).
    // Touches last_seen on a hit only.
    std::shared_ptr<McpStreamState> stream_for(const std::string& id,
                                               const McpSessionBinding& binding);

    // DELETE /mcp/v1/. Removes the session iff it exists AND is bound to exactly
    // `binding`; returns true on removal, false otherwise (same no-oracle posture as
    // validate; a class mismatch removes nothing). A live GET stream on that session is
    // closed (kSessionTerminated) — the client learns why rather than seeing a bare EOF.
    // When `refusal` is given it is set to what refused a false return (kUnknown or
    // kCredentialMismatch) so the caller can audit the cause; untouched on success.
    bool terminate(const std::string& id, const McpSessionBinding& binding,
                   ValidateResult* refusal = nullptr);

    // Evict idle-expired sessions (closing any live stream). Invoked
    // opportunistically on mint/validate; exposed for tests.
    void gc();

    std::size_t active_count() const;

    // True iff `id` is present, bound to `binding`, AND not idle-expired at the
    // time of the call. PURE READ - track 2f bridge-sweep support: it does NOT
    // slide last_seen (a parked bridge record must never extend session life),
    // runs no gc, and erases nothing (an expired entry is left for the next
    // touching call to reap). The liveness predicate is the exact negation of
    // gc_locked's expiry test (`now() - last_seen > idle_ttl`) so the two can
    // never disagree. Same no-oracle posture as validate_and_touch: a foreign
    // principal or a different credential class reads as absent.
    bool exists(const std::string& id, const McpSessionBinding& binding) const;

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
        McpSessionBinding binding;
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
