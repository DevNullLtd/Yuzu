#pragma once

/// @file mcp_stream.hpp
/// MCP Streamable HTTP GET SSE channel (ADR-1005 Decision 15, track 2f PR 2).
///
/// The `GET /mcp/v1/` channel a client attaches to a session it minted on
/// `initialize`. It carries the server→client half of that session: heartbeats,
/// a bounded per-session replay ring for `Last-Event-ID` resume, and (from
/// track 2f PR 3) the `notifications/progress` frames the streamed-POST bridge
/// publishes. In PR 2 nothing produces frames yet — `publish()` is the seam PR 3
/// and the tests write through.
///
/// Invariants this module owns (governance: security-guardian / cpp-safety):
///   * Event ids are PER-SESSION, monotonic from 1, never global (Decision
///     15(j) / CH-3). A restart or re-initialize gets a fresh namespace.
///   * The replay ring is BOUNDED (Decision 15(d)). A cursor whose frames have
///     been evicted is never silently gapped: the caller 404s and the client
///     re-initializes, refetching durable state by `execution_id`.
///   * A live stream re-validates its credential once per tick (~3 s), independent
///     of whether a heartbeat frame is emitted that tick, and dies
///     within one tick of a revocation (Decision 15(c)); an INDETERMINATE auth
///     backend (a blip, not a revocation) gets a bounded grace window instead of
///     a mass kill (Decision 15(i)).
///   * Concurrency is admission-controlled through the shared
///     `sse_bus::StreamBudget` — one budget across every held-open SSE response
///     on the shared httplib worker pool (Decision 15(h)).
///
/// LOCK ORDER (both classes): `McpStreamState::mu_` → `SseSinkState::mu`.
/// Never the reverse. The pump therefore releases the sink mutex before calling
/// back into `McpStreamState`, and no socket write ever happens under either
/// mutex (a stalled peer must not block a publisher).

#include "event_bus.hpp"
// McpPostPump's tick is expressed in McpStreamBridge::PostBatch. The dependency
// runs presentation -> core, which is the sanctioned direction (G1); the bridge
// header forward-declares McpStreamState rather than including this one, so
// there is no cycle.
#include "mcp_stream_bridge.hpp"
#include "stream_budget.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

#include <httplib.h>

namespace yuzu {
class MetricsRegistry;
class Gauge;
}

namespace yuzu::server::auth {
struct Session;
// Defined in <yuzu/server/auth.hpp>. Opaquely forward-declared (the underlying
// type is pinned there, so this is well-formed) to keep the MCP stream header off
// the auth header's include cost.
enum class CredentialCheck : int;
}  // namespace yuzu::server::auth

namespace yuzu::server::mcp {

// `yuzu::server::mcp::detail` already exists (mcp_jsonrpc.hpp), so an unqualified
// `detail::` inside this namespace resolves to THAT one and never finds the SSE
// primitives in `yuzu::server::detail`. Alias the outer namespace explicitly —
// and not as `sse`, which is already a member name on McpStreamSink.
namespace sse_bus = ::yuzu::server::detail;

class McpSessionRegistry;

/// Replay-ring capacity per session. Matches `sse_bus::kPerConnectionQueueCapDefault`
/// so a full-ring replay fits the sink queue exactly and cannot trip the sink's
/// own drop-oldest guard (which would gap a resume that the ring could satisfy).
inline constexpr std::size_t kMcpRingCapDefault = sse_bus::kPerConnectionQueueCapDefault;

/// Heartbeat / re-validation tick. Matches the `/api/v1/events` cadence — short
/// enough to keep intermediaries from idling the connection out, and it is the
/// bound on "a revoked stream dies within one tick" (CH-4).
inline constexpr std::chrono::milliseconds kMcpStreamTickDefault{3000};

/// Grace window for an INDETERMINATE re-validation (auth backend unreachable —
/// NOT a revocation). Equal to `ApiTokenStore::kTokenCacheTtl` (60 s): a blip
/// shorter than the token cache's own TTL can never kill a stream, because a
/// cached token would not have re-hit the backend within that window anyway
/// (Decision 15(i) — no mass kill on a blip).
inline constexpr std::chrono::milliseconds kMcpRevalidateGraceDefault{60000};

/// Decision 15: how long a streamed-POST response stays open before it is closed
/// with `kCapExpired`. The execution is NOT cancelled - it continues server-side
/// and its result stays collectable by GET resume or by `execution_id` - so this
/// bounds a held connection, never the work.
inline constexpr std::chrono::milliseconds kMcpStreamedPostCapDefault{120000};

/// `retry_after_ms` on a stream-cap 429. Honest, not aspirational: a slot frees
/// only when a live stream ends, and a dead peer is detected within one tick
/// (3 s) plus its socket write failure — so a retry sooner than this cannot
/// succeed for a capacity reason.
inline constexpr std::int64_t kMcpStreamCapRetryAfterMs = 5000;

/// `retry_after_ms` when a session's previous stream is still draining.
///
/// The common case clears in microseconds: the superseded provider is woken under its
/// own mutex and returns without writing. But if it was caught mid-write to a peer that
/// has stopped reading — the exact case a takeover exists to rescue — it does not
/// re-enter until httplib's `wait_writable` gives up, bounded by the 30 s write timeout.
/// So this hint is deliberately the same as the capacity hint rather than an optimistic
/// half-second that would have a flaky client 429-storming us sixty times while it
/// dutifully obeyed our own advice.
inline constexpr std::int64_t kMcpHandoverRetryAfterMs = 5000;

/// `retry_after_ms` for a streamed-POST admission denial. Deliberately NOT the GET
/// figure above: a GET slot frees when a dead peer is detected (one tick plus a
/// write failure), but a streamed-POST slot is held until the WORK finishes or cap
/// settlement completes (#2739: the cap, then one drain pass, then the settle
/// pass - not the bare cap instant). Advising 5 s there has a conforming client
/// burn ~24 full auth + rate-limit + routing passes before a slot could possibly
/// free - retry amplification on exactly the surface agentic workers hammer. A
/// quarter of the cap is a floor that can actually be true.
inline constexpr std::int64_t kMcpStreamedPostRetryAfterMs = 30000;

/// Ring / sink frames are the shared `detail::SseEvent` (whose `id` field carries
/// the per-session event id). Deliberately NOT a bespoke type: the id used to be
/// packed into `data` as a `"<id>\n<payload>"` string and re-parsed in the provider,
/// which put a throwing `stoull` inside a content-provider callback — and httplib
/// runs those on an unguarded worker task, where an escaped exception is
/// `std::terminate`, not a 500.
using McpStreamEvent = sse_bus::SseEvent;

/// Byte cap on a session's replay ring, enforced alongside the frame cap. The frame
/// count alone is not a memory bound: 1024 sessions × 500 frames is only a bound if
/// you also know what a frame weighs. 64 KiB/session keeps the fleet-wide worst case
/// at ~64 MiB rather than the ~250 MiB an unbounded-size 500-frame ring would allow
/// at PR-3 progress-frame sizes (Decision 15(d): ALL in-memory state bounded).
inline constexpr std::size_t kMcpRingBytesCapDefault = 64 * 1024;

/// Floor for the ring byte cap. Below the size of the `frame_too_large` notice, every
/// publish would count as oversized and the ring would collapse to a single frame —
/// turning every resume into a gap.
inline constexpr std::size_t kMinRingBytesCap = 256;

/// Per-principal MCP stream allowance. A per-SURFACE policy, not a pool limit — the pool is
/// protected by the budget's global cap alone. This one exists to stop a single agentic
/// token monopolising the channel, not to ration capacity.
inline constexpr std::size_t kMcpStreamsPerPrincipalDefault = 4;

/// Max concurrent STREAMED-POST requests per session, and therefore the max eviction-exempt
/// (pinned) final-response frames the ring can hold at once (Decision 15(f): "one pending
/// response per streamed request"). The 2f progress bridge caps streamed records per session
/// at this number at ADMISSION, so publish_final never runs short of a pin slot; the
/// fixed-size pin array here is the ring-side enforcement of the same bound.
inline constexpr std::size_t kMaxStreamedPostsPerSession = 4;

/// The streamed-POST admission cap (StreamBudget, per principal) and this ring-side per-session
/// pin-slot cap are the SAME bound seen from two sides (2f PR 3b): admission must never let in
/// more streamed POSTs than the ring can pin finals for. `sse_bus` aliases the detail namespace
/// where the budget constant lives (stream_budget.hpp is included above; the reverse include
/// would be a cycle, which is why the assert lives here, not there).
static_assert(kMaxStreamedPostsPerSession == sse_bus::kPerPrincipalMcpPost,
              "streamed-POST per-principal budget cap must equal the ring's per-session pin-slot "
              "cap — else admission could admit a streamed POST the ring cannot pin a final for");

/// Why a stream ended. Wire-visible (the JSON-RPC-wrapped `notifications/yuzu.stream_closed`
/// notification, 2f PR 3b), audited (`mcp.stream.close` `reason=`), and distinct per CH-4 — a
/// client must be able to tell "your credential was revoked" from "our auth backend is down".
enum class McpStreamClose {
    kNone,               ///< still open
    kClientGone,         ///< peer disconnected / write failed
    kSuperseded,         ///< a newer GET took the session's stream over
    kSessionTerminated,  ///< DELETE, idle GC, replay-window termination, or server shutdown
    kCredentialRevoked,  ///< re-validation said the credential is definitively gone
    kAuthUnavailable,    ///< re-validation was indeterminate past the grace window
    kInternalError,      ///< the pump caught an exception — OUR fault, not the client's
    // The next four are produced ONLY by the streamed-POST surface (2f PR 3b); the GET pump
    // never emits them. Declared here so to_string / close_remediation / the metric seed cover
    // the whole closed reason set from C4. Their producer code shipped in 3b and runs whenever
    // --mcp-enable-streamed-post is set, which is now the default: the POST pump emits all four
    // unless an operator has opted out with --no-mcp-streamed-post.
    kCancelled,          ///< the client sent notifications/cancelled; the execution continues
    kCapExpired,         ///< the streamed-POST response time cap elapsed; the execution continues
    kRecordGone,         ///< the bridge can no longer serve this key (erased, or shutting down)
    kCompleted,          ///< the final was delivered then EOF — no close frame is written for this
};
const char* to_string(McpStreamClose reason);

/// Build the JSON-RPC-wrapped stream-close notification body (2f PR 3b, PENDING 2):
///   {"jsonrpc":"2.0","method":"notifications/yuzu.stream_closed","params":{ A4 body ... }}
/// carried under the DEFAULT `message` SSE event type (NOT a bespoke `event: stream-closed`, which
/// a spec MCP client parsing JSON-RPC messages off the stream would never see). `params` is the
/// same A4-shaped body every denial on this route uses (reason / correlation_id / retry_after_ms /
/// remediation). `extra_params_json` is an optional RAW fragment appended inside `params` — the
/// caller includes the leading comma, e.g. `,"execution_id":"exec-1","partial":true` (C6c/C7) — or
/// empty. CONTRACT (Gate 2 security/architect): the fragment is concatenated VERBATIM, so any
/// STRING value in it MUST be `detail::json_quoted`-escaped by the caller — an unescaped `"` / `\`
/// / newline in a value would corrupt the JSON envelope on a live stream (a JSON-injection sink).
/// Server-minted ids (`exec-*` etc.) are format-safe, but a future producer passing any
/// agent/execution-derived string must quote it and add a test that a `"`-bearing value cannot
/// break the envelope. The frame is off-ring, id-less and non-replayable: a close is a
/// point-in-time terminal signal, not a resumable frame. Shared by the GET pump and the
/// streamed-POST pump.
std::string make_stream_closed_frame(McpStreamClose reason, std::string_view correlation_id,
                                     std::string_view extra_params_json = {});

/// Tri-state credential re-validation (Decision 15(c)+(i)). The distinction is
/// load-bearing: kRevoked kills the stream NOW, kIndeterminate starts a bounded
/// grace window so an auth-backend blip does not cut every live stream at once.
///
/// This is an ALIAS of the auth layer's own type, not an MCP-specific one: the
/// answer is produced by auth and merely consumed here, and the next held-open
/// surface to want per-tick re-validation (`/api/v1/events`, #2056) must not have
/// to name an MCP type to get it.
using StreamRevalidate = auth::CredentialCheck;

/// Re-validate the credential that opened a stream, against the principal the
/// stream is bound to. Takes the ORIGINAL request (the handler keeps a copy —
/// the pump runs long after httplib's stack frame is gone).
using StreamRevalidateFn = std::function<StreamRevalidate(const httplib::Request& original_req,
                                                          const std::string& expected_principal)>;

/// Audit sink, shape-identical to `McpServer::AuditFn` (declared here so this
/// module does not depend on mcp_server.hpp — the dependency runs the other way).
using StreamAuditFn = std::function<bool(const httplib::Request&, const std::string& action,
                                         const std::string& result, const std::string& target_type,
                                         const std::string& target_id, const std::string& detail)>;

/// Audit sink that STAMPS the principal explicitly instead of re-deriving it from the
/// request. Required for `mcp.stream.close`, and only for it.
///
/// The generic sink resolves the actor by calling `resolve_session(req)` when the row is
/// written. That is correct for a request-time audit, and wrong for a stream close: the
/// close audit runs at teardown against the ORIGINAL attach request, so on a
/// `credential_revoked` close the credential no longer resolves BY DEFINITION and the row
/// lands with an empty `principal`/`principal_role`. The rows that prove the revocation
/// control are exactly the rows that lose their actor (SOC 2 CC6.2/CC7.2).
///
/// The principal is known at attach time, so it is captured then and stamped here.
/// Empty = fall back to the generic sink (test seams; production wires it).
/// The actor, captured at attach. A struct rather than three more `const std::string&`
/// parameters on purpose: adjacent same-typed positional arguments can be transposed and
/// still compile, which no `is_invocable_r_v` static_assert can detect — it checks arity
/// and return type only. Named fields make a transposition a compile error.
struct StreamAuditPrincipal {
    std::string id;    ///< session->username — the stable authorization principal
    std::string role;  ///< role_to_string(effective_role(session)) AS OF ATTACH
    std::string cls;   ///< principal_class: "engine" for an engine principal, else by credential
};

using StreamPrincipalAuditFn = std::function<bool(
    const httplib::Request&, const std::string& action, const std::string& result,
    const StreamAuditPrincipal& principal, const std::string& target_type,
    const std::string& target_id, const std::string& detail)>;

/// One live GET attachment: the reusable SSE sink, the close-reason channel the
/// generic sink lacks, and THE BUDGET LEASE FOR THE WORKER THIS ATTACHMENT PINS.
///
/// The lease lives here, not on the session: an httplib worker is pinned per
/// held-open RESPONSE, and a superseded response keeps pinning its worker until it
/// drains. Charging the lease to the session instead would leave those workers
/// uncounted — which is how a single client hammering GET on one session could
/// exhaust the pool while the cap still read 1.
///
/// Heap-owned; shared by the provider, the release callback, and (while live or
/// draining) the session's stream state.
struct McpStreamSink {
    std::shared_ptr<sse_bus::SseSinkState> sse = std::make_shared<sse_bus::SseSinkState>();
    std::atomic<McpStreamClose> close_reason{McpStreamClose::kNone};
    sse_bus::StreamBudget::Lease lease;  ///< released exactly once, in McpStreamState::detach

    /// First reason wins — a revocation already recorded must not be overwritten
    /// by the client-gone the teardown then observes.
    void set_close_reason(McpStreamClose reason) {
        McpStreamClose expected = McpStreamClose::kNone;
        close_reason.compare_exchange_strong(expected, reason);
    }
};

/// Per-session stream state: bounded replay ring + at-most-one live sink + the
/// budget lease held while a sink is live.
///
/// Owned by `shared_ptr` from BOTH the session registry entry and the provider
/// closures, so a DELETE/GC that erases the session never races the live
/// provider's teardown — the state outlives the registry entry until the last
/// closure drops it.
class McpStreamState {
public:
    explicit McpStreamState(std::size_t ring_cap = kMcpRingCapDefault,
                            yuzu::MetricsRegistry* metrics = nullptr,
                            std::size_t ring_bytes_cap = kMcpRingBytesCapDefault);

    McpStreamState(const McpStreamState&) = delete;
    McpStreamState& operator=(const McpStreamState&) = delete;
    // Holds a mutex, so it is already non-movable — say so, and a future member
    // reorder cannot silently make it movable while providers hold raw references.
    McpStreamState(McpStreamState&&) = delete;
    McpStreamState& operator=(McpStreamState&&) = delete;

    /// Append a frame to the ring and hand it to the live sink, if any. The
    /// producer seam for track 2f PR 3 (progress bridge) and for tests.
    ///
    /// HARD exception boundary (#2366). PR 3's progress bridge invokes this from an
    /// ExecutionEventBus listener running on a worker with no routing try/catch, so an
    /// escaped throw here is std::terminate (the #2037 class). `noexcept` is structural,
    /// not decorative (the stream_budget.hpp precedent): the boundary cannot be quietly
    /// dropped by a future edit without this signature failing loudly.
    ///
    /// Parameters are `string_view`, NOT `std::string` by value: a by-value parameter is
    /// copy-constructed in the CALLER's frame for an lvalue argument (the realistic PR 3
    /// call `publish(event.event_type, event.data)`), and a std::bad_alloc from that copy
    /// would escape to the unguarded listener BEFORE this function's body — bypassing the
    /// boundary entirely. `string_view` makes the caller-side conversion non-throwing; the
    /// owned copies happen inside publish_impl's try, where a bad_alloc is a clean
    /// pre-commit 0. The caller MUST keep the referenced storage alive across the call
    /// (publish copies synchronously before returning; it captures no view).
    ///
    /// Return contract:
    ///  - > 0: the frame is COMMITTED to the in-memory ring under this per-session id.
    ///    A post-commit failure (live-sink enqueue allocation, metrics) never un-commits:
    ///    the id is still returned, the frame stays replayable via Last-Event-ID, and a
    ///    sink-enqueue failure is made visible by bumping the sink's `dropped_total`
    ///    (the pump's existing `events-dropped` synthetic) — never a silent gap.
    ///  - == 0: pre-commit failure. Ring AND `next_id_` are untouched — no id hole, the
    ///    next publish assigns the id this call would have. 0 is never a valid frame id
    ///    (ids start at 1).
    ///
    /// CALLER OBLIGATION (asymmetric — a `0` is client-INVISIBLE): a pre-commit `0` bumps
    /// no `dropped_total`, so no `events-dropped` synthetic fires and no replay recovers
    /// the frame — it simply never existed. That is correct for a fire-and-forget progress
    /// delta. It is NOT sufficient for a TERMINAL/completion frame: a producer of one MUST
    /// NOT treat `publish()` as the delivery guarantee, because a `0` there leaves the
    /// client with no terminal and no gap signal. The durable `execution_id` fetch
    /// (Decision 15(f)) is the backstop, and track 2f PR 3 must wire it to a `0` return
    /// explicitly, not rely on general stream-death recovery.
    ///
    /// CONTRACT (Decision 15(b) — LOAD-BEARING): a published frame MUST be a message
    /// arising from THIS session's own requests. The GET channel is exempt from
    /// per-tool tier/RBAC gating precisely because it carries nothing else; a
    /// server-initiated or cross-session frame published here would reopen that
    /// question and the exemption would no longer hold.
    ///
    /// Drop-oldest at the frame AND byte caps; every eviction is counted (a client
    /// whose cursor falls behind the ring is 404'd on resume, never silently gapped).
    std::uint64_t publish(std::string_view event_type, std::string_view data) noexcept;

    /// Commit a frame to the ring for RESUME replay WITHOUT handing it to the live GET sink.
    ///
    /// Track 2f PR 3, Decision 15 + the MCP Streamable HTTP spec ("MUST NOT broadcast the
    /// same message across multiple streams"): a streamed POST delivers its frames on the
    /// POST stream, so publishing them onto a concurrently-live GET sink too would be a
    /// broadcast violation. The ring commit is purely so a GET resume (Last-Event-ID) can
    /// replay them - never a second live copy. Same return contract and boundary as publish().
    std::uint64_t publish_ring_only(std::string_view event_type, std::string_view data) noexcept;

    /// Commit a streamed request's FINAL response frame: ring-only (as publish_ring_only)
    /// AND eviction-EXEMPT (pinned), so a resume recovers the terminal even after the ring
    /// wraps (Decision 15(f), bounded one pending per streamed request by
    /// kMaxStreamedPostsPerSession).
    ///
    /// The exemption holds for the **kMaxStreamedPostsPerSession most recent** pinned
    /// terminals, not unconditionally: see the degraded case below.
    ///
    /// The pin is written only AFTER the frame commits, so a pre-commit failure leaves no
    /// ghost pin and consumes no id.
    ///
    /// ### What a FULL PIN-SLOT SET means  <a name="full-slot-set"></a>
    ///
    /// **This block owns the DERIVATION.** The operator-facing surfaces - the runbook,
    /// `/metrics` HELP, the alert annotations, the user manual - each carry their own
    /// short, self-contained statement, because an SRE holding a shipped container image
    /// does not have this file. They are NOT citations-in-place-of-content and this block
    /// does not claim they are: an earlier revision asserted "none of them restate it",
    /// which was false at all five sites it named.
    ///
    /// What this block is for: the arithmetic below is a proof obligation over
    /// `McpStreamBridge::reserve`'s admission expression and `publish_impl`'s slot scan.
    /// Change either and re-prove it HERE first, then propagate. The reason to keep one
    /// authoritative derivation is that when #2740 falsified the old claim, successive
    /// review rounds each found and fixed a different subset of its paraphrases - and the
    /// round that introduced this block still got the arithmetic wrong in two places and
    /// shipped one of them into an alert expression.
    ///
    /// Before #2740: a committed final with no free pin slot was unreachable - the bridge
    /// admits streamed records against `pinned_count() + unpinned` and this array is sized
    /// to exactly that cap - so reaching it MEANT admission accounting had drifted.
    ///
    /// Since #2740 that inference no longer holds on its own. TWO paths reach a full slot
    /// set without drift. A third - the admission reclaim - is listed with them because it
    /// is the mechanism whose two failure arms produce them, but the reclaim itself neither
    /// over-admits nor displaces. The distinction is load-bearing: an earlier revision called
    /// all three over-cap paths, and that error was compiled straight into an alert
    /// expression that then subtracted a non-cause.
    ///
    ///   1. the admission reclaim releases a pin DELIBERATELY, to admit a new streamed
    ///      call in place of a final no wire took delivery of. This does **NOT** put the
    ///      session over cap and CANNOT by itself cause a displacement: it releases one
    ///      pin and adds one charge, so the sum is unchanged, the session stays AT cap,
    ///      and `publish_impl` always finds a free slot. Note a full set was reachable
    ///      BEFORE #2740 too - that is the lockout this fix exists to end - so the reclaim
    ///      is why a session at a full set can now be ADMITTED, never why the set is
    ///      reachable;
    ///   2. #2795 - the release returns without having cleared the slot, because another
    ///      route got there first. AT MOST one over cap, not certainly: the slot may
    ///      genuinely have opened, in which case there is no over-admission at all. Client-reachable (racing a GET resume against a POST
    ///      admission on the same session). Counted as
    ///      `yuzu_mcp_bridge_pin_release_raced_total`;
    ///   3. #2805 - the release throws and is contained. Needs a broken platform mutex,
    ///      so not client-reachable. Counted as `yuzu_mcp_bridge_pin_release_failed_total`.
    ///
    /// (#2794 is NOT one of these. It is a separate class - a torn-down record shielding
    /// its pin from the orphan scan - and does not put a session over cap.)
    ///
    /// THE BOUND IS EXACTLY ONE, and it cannot compound: admission requires
    /// `effective_pinned + unpinned < kMaxStreamedPostsPerSession` (note the strict `<`,
    /// and that `effective_pinned` already subtracts the at-most-one reclaim) and adds
    /// exactly one charge, and
    /// `reclaimed` is capped at 1 per pass, so the post-state is at most cap + 1. The next
    /// `reserve` re-reads both figures under the same `bridge_mu_` and rejects.
    ///
    /// "Transiently" is held for the LIFETIME OF THE OVER-ADMITTED CALL. It ends when the
    /// last outstanding charge settles into the full array and displaces, or when the extra
    /// pin clears by another route. It does NOT end when the next admission rejects: a
    /// rejection mutates nothing, so it bounds GROWTH, not duration. The bound is the #2739
    /// streamed-POST response cap, or the teardown reaper if the execution never settles.
    /// Idleness is not the variable.
    ///
    /// AND THE NETTING MUST NEVER COME BACK, at any scope. Not a tuning judgement: this
    /// counter is per-SESSION state, while both residual counters are UNLABELLED
    /// PROCESS-WIDE totals. Any subtraction nets session A's residual against session B's
    /// displacement, and a session label is ruled out by the bounded-label convention, so
    /// the join can never exist. A residual also explains a displacement up to a response
    /// cap later, straddling any window. If automation is ever wanted it is a RECORDING
    /// rule producing a named "unexplained" series ALONGSIDE a retained raw `> 0` alert -
    /// never a subtraction inside the alerting expression.
    ///
    /// So a full slot set is a SIGNAL TO CORROBORATE, not a verdict. Drift is what remains
    /// after the two OVER-CAP paths above (2 and 3) are ruled out against their counters -
    /// path 1 explains nothing, because it never puts the session over cap - and note that
    /// ruling out is only possible at all because (2) got its own counter; it previously
    /// moved none, which is precisely how a runbook came to instruct on-call to rule it out
    /// using two counters that both read flat in that exact case.
    ///
    /// In the degraded state the slots behave as an LRU: the OLDEST pin yields to the
    /// newest, because the newest terminal is the one a client is likeliest still waiting to
    /// resume while the oldest has almost certainly been consumed. The displaced final stays
    /// committed and remains in the ring until ordinary eviction reaches it - it loses its
    /// eviction EXEMPTION, nothing more.
    ///
    /// NOT "delivered". These frames are ring-only; nothing delivers one except a resume,
    /// so "almost certainly been consumed" is a likelihood, not a fact. Saying otherwise
    /// matters because the sweep cannot tell a displaced pin from a cursor-acknowledged
    /// one and records both as terminal_delivered - a wrong audit fact rather than a
    /// wrong comment. STILL OPEN, and #2740's admission reclaim widened it by adding a
    /// third way for a pin to vanish without a client having seen anything. It is
    /// mitigated, not closed: a reclaim emits `mcp.bridge.pin_displaced_for_admission`
    /// immediately before the reap, so the trail distinguishes the two causes even
    /// though the reap's own row does not. A tri-state pin status would close it
    /// properly; this comment used to promise that as "the follow-up PR", which is the
    /// PR that wrote this sentence, so the promise was withdrawn rather than re-dated -
    /// and is now tracked as #2801, because a withdrawn promise with no issue behind it
    /// is just a lost commitment.
    ///
    /// The pin is released by FOUR routes, and they do NOT all mean the client got the
    /// frame: unpin() when the final was written on the POST wire (it did), attach_and_replay
    /// when a cursor proves consumption (it did), ring LRU displacement as above (it did
    /// not — a full slot set; see "What a FULL PIN-SLOT SET means" above), and the
    /// bridge's admission reclaim (#2740; it did not — the
    /// session needed the slot for a new streamed call). A pin also dies with the whole
    /// object. Anything that treats a missing pin as proof of delivery must consult the
    /// audit trail, not the pin alone. Same return contract and boundary as publish().
    std::uint64_t publish_final(std::string_view event_type, std::string_view data) noexcept;

    /// Deterministic fault injection for publish() — TEST SEAM ONLY. The throw sites
    /// inside publish_impl are internal string/deque allocations with no callback to
    /// throw through (the repo's usual injection idiom), so the THREE failure phases the
    /// #2366 boundary distinguishes get explicit trip points instead. One-shot: the
    /// fault fires on the next publish and resets to kNone.
    enum class PublishFault {
        kNone,
        kPreCommit,    ///< models the ring push_back allocation failing (nothing committed)
        kSinkEnqueue,  ///< models the live-sink enqueue copy failing (frame already committed)
        /// Models the POST-COMMIT observability block (metric increment / WARN format)
        /// throwing after the frame is committed. Exercises publish_impl's innermost
        /// `catch(...)` - the guarantee that a metrics/log allocation fault never turns a
        /// committed publish into a 0 return. Fires inside that try, so it never reaches
        /// publish()'s outer boundary: publish returns the committed id.
        kPostCommitObservability,
    };
    /// `times` arms the same fault for the next N publishes (default 1 = the historical
    /// one-shot). Needed by the bridge's double-terminal-failure -> poison test: both the
    /// real-final and fallback-final publishes happen inside ONE projector pass, so the
    /// seam cannot be re-armed between them from the test thread.
    void inject_publish_fault_for_test(PublishFault fault, int times = 1);

    /// Deterministic fault injection for unpin() — TEST SEAM ONLY, mirroring the publish
    /// seam above. It exists because the two accepted residuals of #2740's admission
    /// reclaim are otherwise unreachable from a single-threaded test: both need the
    /// release to fail, and one of them needs it to fail by LOSING A RACE, which a test
    /// cannot stage without the concurrency window tracked as #2791.
    ///
    /// Not a convenience. Before this seam the residuals were untestable AND (for the
    /// raced arm) uncounted, and a runbook was shipped instructing operators to rule the
    /// raced case out via counters that could not move for it.
    enum class UnpinFault {
        kNone,
        /// Models another route (a resume ack, or a final reaching the wire) having
        /// cleared the slot between selection and release: unpin returns false WITHOUT
        /// throwing and without clearing anything (#2795).
        kRaceLost,
        /// Models a broken platform mutex: the lock throws (#2805). The bridge contains
        /// it, because the admission it belongs to has already committed by then.
        kThrow,
    };
    /// `times` arms the same fault for the next N unpins (default 1 = one-shot). A THROWN
    /// fault still consumes its charge - the counter is decremented before the throw - so
    /// `times=2` means two throws and then normal service, not a permanently armed seam.
    void inject_unpin_fault_for_test(UnpinFault fault, int times = 1);

    /// The NEXT `times` close attempts on the poison path throw, modelling close_sink's one
    /// throw site (the sink's own mutex acquisition) - the fault close_sink itself has no
    /// seam for. Shared by BOTH poison-path close sites: poison_terminal()'s original close
    /// and attach_and_replay's poison-branch retry, so `times=2` covers one throw at each.
    /// One-shot per attempt, consumed under mu_ before the close runs. TEST SEAM ONLY (#2531).
    void inject_poison_close_fault_for_test(int times = 1);

    /// Set a short human-readable log prefix (e.g. the session id) included in publish()'s
    /// rare WARN lines so an operator can attribute a dropped/anomalous frame to a session.
    ///
    /// Threading: WRITE-ONCE, called at mint BEFORE the stream is shared with any other
    /// thread (McpSessionRegistry::mint, before the Entry is emplaced). Effectively
    /// immutable thereafter, so publish()'s reads need no lock - the registry mutex + the
    /// shared_ptr handoff at emplace are the happens-before edge to every later reader.
    /// Do NOT call it after the stream is live.
    void set_log_context(std::string context);

    enum class AttachStatus {
        kAttached,
        kGap,              ///< cursor outside the ring window → caller 404s, client re-initializes
        kStreamCapHit,     ///< budget rejected → caller 429s
        kHandoverPending,  ///< a superseded provider has not drained yet → caller 429s
        kPoisoned,         ///< terminal delivery failed twice → caller 410s, fetch by execution_id
    };

    struct AttachResult {
        AttachStatus status = AttachStatus::kGap;
        std::shared_ptr<McpStreamSink> sink;  ///< engaged iff kAttached
        std::uint64_t generation = 0;         ///< this attachment's generation (takeover fence)
        const char* reject_reason = nullptr;  ///< static literal iff kStreamCapHit
    };

    /// Resume-check + admission + replay + attach, ATOMICALLY under one mutex.
    ///
    /// Doing all four under a single lock closes the replay→subscribe race the
    /// `/api/v1/events` sibling documents (a frame published between its replay
    /// and its subscribe is lost): here nothing can be published into the gap,
    /// because a publisher needs the same mutex.
    ///
    /// Takeover, not reject-second: if the session already has a live sink, the
    /// newcomer supersedes it (generation bumped, old sink closed kSuperseded) and is
    /// admitted WITHOUT a cap check — the common second GET is a client reconnecting
    /// across a zombie TCP the server has not noticed yet, and making it wait for its
    /// own zombie to time out would turn the cap into a self-inflicted lockout.
    ///
    /// It still takes its OWN lease (the superseded provider keeps pinning its worker
    /// until it drains, and an uncounted pinned worker is exactly the hole this budget
    /// exists to close). The pool is bounded structurally instead: a session holds at
    /// most one draining sink, so at most two providers — a second takeover while a
    /// handover is still pending returns kHandoverPending, and `derive_stream_budget`
    /// reserves `kMaxProvidersPerStream` workers for every permitted stream.
    ///
    /// `budget == nullptr` disables admission control (test seams only —
    /// production always wires the shared budget).
    AttachResult attach_and_replay(std::uint64_t last_event_id, sse_bus::StreamBudget* budget,
                                   const std::string& principal,
                                   std::size_t per_principal_cap = kMcpStreamsPerPrincipalDefault);

    /// Close the live sink, if any (idempotent). Wakes the provider, which writes the
    /// final `stream-closed` frame and returns false. Never blocks on socket I/O —
    /// safe to call from the registry under a DELETE/GC.
    void close(McpStreamClose reason);

    /// Provider-release path: clears the sink (live OR draining) and returns the lease
    /// for the worker THAT sink was pinning. Idempotent.
    void detach(const std::shared_ptr<McpStreamSink>& sink);

    /// Release the eviction-exemption on a pinned final frame (unpin rule (a): the final was
    /// written on the POST wire). Idempotent - an unknown/already-cleared id is a no-op.
    ///
    /// Returns TRUE only if THIS call cleared the slot. The bridge's admission reclaim
    /// (#2740) needs that distinction: it selects a pin, then releases it after the
    /// admission commits, and in between a resume ack or a delivered final can release the
    /// same id without holding `bridge_mu_`. Crediting the freed slot on a no-op would admit
    /// one call over the per-session cap, and reporting one would audit an exemption loss
    /// that never happened. `[[nodiscard]]` precisely BECAUSE one caller deliberately
    /// ignores it: the rule-(a) release in `on_final_written` is best-effort and writes
    /// `(void)`, which makes that choice explicit and stops a future reclaim-shaped caller
    /// dropping the result silently.
    [[nodiscard]] bool unpin(std::uint64_t id);

    /// True while `id` is a pinned (eviction-exempt) final frame. The 2f bridge sweep polls
    /// this: a parked (ring-only) record whose pin has gone - consumed via a GET resume that
    /// acked past it - can be torn down. Const, cheap (scans the fixed pin array under mu_).
    bool is_pinned(std::uint64_t id) const;

    /// The whole pin array in ONE `mu_` acquisition (0 = empty slot). Two callers
    /// need the SET, not a membership test: the bridge's admission reclaim has to
    /// find a pin no record references (an ORPHAN — the sweep's teardown erases a
    /// record without unpinning, so orphans are reachable and are the one lockout
    /// shape a record scan can never see), and polling `is_pinned` per candidate
    /// would take this mutex once per record while the global admission lock is
    /// held. Returned by value: the caller must not hold `mu_` while it reasons.
    std::array<std::uint64_t, kMaxStreamedPostsPerSession> pinned_ids_snapshot() const;

    /// Poison the session stream: no terminal frame could be delivered (publish_final failed
    /// twice) and the durable result must be fetched by execution_id instead. Sets a sticky
    /// flag so every FUTURE attach fast-fails (AttachStatus::kPoisoned → 410 + remediation)
    /// rather than a client re-attaching and heart-beating forever for a terminal that will
    /// never arrive, and closes any currently-live sink with kInternalError. Idempotent.
    ///
    /// The flag write is unconditional and durable; the close is best-effort. Its one throw
    /// site (close_sink's sink mutex acquisition, modelling a broken platform mutex) is
    /// contained and counted rather than escaping - a client left heart-beating on a failed
    /// close is not silent, and gets a second close attempt the next time it attaches
    /// (attach_and_replay's poison branch retries against any still-live stale sink) (#2531).
    void poison_terminal() noexcept;

    std::size_t pinned_count() const;  ///< eviction-exempt frames currently held (observability/tests)

    std::uint64_t current_generation() const;
    std::uint64_t next_event_id() const;    ///< id the next publish will assign
    std::uint64_t evictions_total() const;  ///< frames dropped from the ring (observability/tests)
    bool has_live_sink() const;
    bool has_draining_sink() const;         ///< a superseded provider has not torn down yet

private:
    /// Close a sink, setting `closed` UNDER its mutex (it is the pump's wait
    /// predicate — an atomic store outside the lock races the pump's
    /// release-and-block and the wakeup is lost). Never blocks on I/O; never called
    /// while holding mu_.
    static void close_sink(const std::shared_ptr<McpStreamSink>& sink, McpStreamClose reason);
    static std::size_t frame_bytes(const McpStreamEvent& ev);

    /// The shared noexcept boundary for publish() / publish_ring_only() / publish_final().
    /// `deliver_live` hands the frame to the live GET sink (false = ring-only, for streamed
    /// POST frames); `pinned` marks a committed final eviction-exempt. One implementation of
    /// the #2366 hard boundary so the three public seams cannot drift.
    std::uint64_t publish_guarded(std::string_view event_type, std::string_view data,
                                  bool deliver_live, bool pinned) noexcept;

    /// The throwing body publish_guarded() guards. Owns the payload from the caller's views
    /// up front (those copies may throw - pre-commit, so a bad_alloc there is a clean 0).
    /// After the ring push + next_id_ advance, every step is either noexcept or locally
    /// contained, so a throw reaching the guard's catch proves nothing was committed and
    /// 0 is the honest return.
    std::uint64_t publish_impl(std::string_view event_type, std::string_view data,
                               bool deliver_live, bool pinned);

    /// True if `id` is a pinned final. Assumes mu_ is held (the eviction path and the public
    /// is_pinned() both funnel through it). Scans the fixed pin array - O(pin count).
    bool is_pinned_locked(std::uint64_t id) const;

    /// True (and consumes one) iff a poison-close fault is armed. Assumes mu_ is held -
    /// the counter is a plain int, not an atomic, because both callers already hold mu_ at
    /// the point they need to decide. Test seam only (#2531).
    bool take_poison_close_fault_locked();

    /// The shared contained-close for the poison path: poison_terminal()'s own close and
    /// attach_and_replay's poison-branch retry both funnel here, so the containment, the
    /// counter and the log line cannot drift between the two call sites (#2531). Never
    /// called while mu_ is held - close_sink's lock order (sink->sse->mu, taken outside
    /// mu_) forbids it, same as close(). `inject_fault` is pre-decided by the caller under
    /// mu_ (see take_poison_close_fault_locked) since the seam counter is not atomic.
    void poison_close_contained(const std::shared_ptr<McpStreamSink>& sink,
                                bool inject_fault) noexcept;

    mutable std::mutex mu_;
    std::deque<McpStreamEvent> ring_;
    std::size_t ring_cap_;
    std::size_t ring_bytes_cap_;
    std::size_t ring_bytes_ = 0;
    std::uint64_t next_id_ = 1;  ///< CH-3: per-session, starts at 1
    std::uint64_t evictions_ = 0;
    std::uint64_t generation_ = 0;
    PublishFault publish_fault_ = PublishFault::kNone;  ///< test seam; guarded by mu_
    UnpinFault unpin_fault_ = UnpinFault::kNone;       ///< test seam; guarded by mu_
    int unpin_fault_remaining_ = 0;                    ///< unpins left that consume it
    int publish_fault_remaining_ = 0;  ///< publishes left that consume publish_fault_; guarded by mu_
    int poison_close_fault_remaining_ = 0;  ///< test seam; guarded by mu_ (#2531)
    // Write-once at mint before the stream is shared (set_log_context contract); read
    // unlocked in publish()'s WARN paths. Never mutated after the stream goes live.
    std::string log_context_;
    // Eviction-exempt (pinned) final-frame ids; 0 = empty slot. Fixed size = the per-session
    // streamed-request bound. All access under mu_. Decision 15(f).
    std::array<std::uint64_t, kMaxStreamedPostsPerSession> pinned_ids_{};
    bool terminal_poisoned_ = false;  ///< sticky; every future attach 410s (guarded by mu_)
    std::shared_ptr<McpStreamSink> live_;
    std::shared_ptr<McpStreamSink> draining_;  ///< superseded, still pinning its worker
    yuzu::MetricsRegistry* metrics_ = nullptr;
    // Resolved ONCE at construction. MetricsRegistry::gauge(name) allocates (a string
    // temporary for the name, plus a map node on first use) and takes the process-global
    // registry lock — neither is acceptable on a path that runs under mu_, and a throw
    // there would strand a sink that already holds a lease. The families live in
    // node-based maps, so these references are stable for the registry's life; a
    // Gauge::increment through them takes only that gauge's own mutex.
    /// Non-owning views into MetricsRegistry's node-based families: valid for the
    /// registry's life, and invalidated ONLY by `clear_gauge_family()` (which is never
    /// called on the `yuzu_mcp_streams_*` families — if that ever changes, these dangle).
    yuzu::Gauge* gauge_streams_active_ = nullptr;
    yuzu::Gauge* gauge_streams_handover_ = nullptr;
};

/// The per-tick credential re-validation grace state machine, extracted from McpStreamPump
/// (2f PR 3b) so the streamed-POST pump (McpPostPump) can share it byte-for-byte. Fed one
/// StreamRevalidate verdict per tick, it owns ALL of the grace/jitter/staleness state and
/// decides whether the stream continues or must close — and with which reason — WITHOUT touching
/// the wire: the pump owns `stream_->close` and the close frame, this owns only the policy.
///
/// The distinctions are load-bearing (Decision 15(c)/(i), CH-4, #2367):
///   * kRevoked       — authoritative revocation, an IMMEDIATE kill (no grace).
///   * kIndeterminate — the auth backend is unreachable (NOT a revocation): ride a bounded,
///                      per-stream-jittered grace window rather than cut every live stream at the
///                      same instant (the correlated-brownout mass-kill, ADR-0006).
///   * kValid         — the store was asked and answered: an authoritative confirmation.
///   * kValidStale    — a positive answer served from a cache of known max age (#2367): clamp the
///                      grace floor forward by at most one window so cache residency and the grace
///                      window can never ADD.
class RevalidateGrace {
public:
    struct Config {
        std::chrono::milliseconds grace = kMcpRevalidateGraceDefault;
        std::chrono::milliseconds jitter_max{0};    ///< max extra per-stream grace, chosen once
        std::chrono::milliseconds max_staleness{0};  ///< #2367; 0 = answers always authoritative
    };

    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    /// What the pump must do after feeding a verdict.
    enum class Outcome {
        kContinue,               ///< stream lives (healthy, or riding a bounded grace window)
        kCloseCredentialRevoked, ///< authoritative revocation — kill now
        kCloseAuthUnavailable,   ///< grace window expired, or an unknown verdict (fail closed)
    };

    /// `last_authoritative_ok_` seeds to now(): attach performed a fresh authoritative
    /// authentication before this exists, and seeding to the epoch would make the very first
    /// indeterminate tick compute an instantly-expired deadline.
    RevalidateGrace(Config cfg, Clock clock)
        : cfg_(std::move(cfg)), clock_(std::move(clock)), last_authoritative_ok_(now()) {}

    /// Feed one tick's verdict; updates grace state and returns the wire outcome.
    Outcome on_verdict(StreamRevalidate verdict);

private:
    std::chrono::steady_clock::time_point now() const {
        return clock_ ? clock_() : std::chrono::steady_clock::now();
    }
    /// Drop the current indeterminate-grace spell. Called from BOTH the kValid and kValidStale
    /// arms — a cache hit is as much a confirmation as a read-through (#2367); round-1's BLOCKING
    /// bug was exactly one arm clearing the deadline while the other left it armed.
    void clear_grace_deadline_() {
        grace_start_.reset();
        grace_deadline_.reset();
    }

    Config cfg_;
    Clock clock_;
    // When the credential was last confirmed AUTHORITATIVELY (store asked and answered), as
    // opposed to served from cache (#2367). The indeterminate grace deadline is measured from
    // HERE, so a stream cannot extend its life by riding cached answers then collecting a full
    // fresh window once they expire.
    std::chrono::steady_clock::time_point last_authoritative_ok_;
    // Where the current indeterminate spell's budget is measured from (the last authoritative
    // confirmation, NOT the moment the store first failed to answer).
    std::optional<std::chrono::steady_clock::time_point> grace_start_;
    // = grace_start_ + grace + a per-stream jitter chosen once when grace_start_ is set. Because
    // grace_start_ is backdated it can already be in the past when armed, so the expiry test runs
    // on the arming tick too.
    std::optional<std::chrono::steady_clock::time_point> grace_deadline_;
};

/// The content-provider body of one live GET stream.
///
/// `pump_once` is the test seam: it takes a `WriteFn` rather than an
/// `httplib::DataSink`, so the whole stream lifecycle (heartbeats, revocation,
/// grace window, replay drain, close frames) is unit-testable without standing
/// up an httplib server — which the server suite must not do (TSan acceptor
/// crash, #438).
class McpStreamPump {
public:
    struct Config {
        std::chrono::milliseconds tick = kMcpStreamTickDefault;
        std::chrono::milliseconds revalidate_grace = kMcpRevalidateGraceDefault;
        // Maximum extra grace ADDED per-stream, chosen once uniformly in
        // [0, revalidate_grace_jitter_max] when a stream first enters the indeterminate
        // grace window. Its whole purpose is to DE-SYNCHRONISE the mass kill: without it,
        // every stream's grace equals the token-cache TTL (60 s), so a PG brownout drives
        // every stream into grace within one tick of onset and they all die at onset+60 s
        // together — a simultaneous fleet-wide reconnect storm that re-floods the very
        // pool that is trying to recover (the substrate has NO SQLite fallback, ADR-0006).
        // Spreading the deadlines turns a cliff into a ramp. Grace only ever applies to
        // kIndeterminate (auth store unreachable), NEVER to a real revocation (which is an
        // immediate kill), so a longer grace can never keep a revoked credential alive —
        // this is a pure availability knob with no security cost.
        //
        // Defaults to 0 so the pump is DETERMINISTIC in unit tests; production wires a real
        // spread (half the grace). A stream picks its own offset once, so the spread is
        // stable for the life of that stream.
        std::chrono::milliseconds revalidate_grace_jitter_max{0};

        // #2367. Maximum age of a `kValidStale` answer — i.e. how stale the
        // revalidate callback's cache is allowed to be. The pump uses it to
        // clamp `last_authoritative_ok_` forward on a cached answer, so a
        // stream that keeps getting cache hits (because a SIBLING stream on the
        // same principal is the one refreshing the shared entry) still has a
        // bounded, non-zero grace budget when the store finally blips.
        //
        // 0 = "answers are always authoritative": the pump then never advances
        // the floor on kValidStale. That is the correct default for any surface
        // whose revalidate callback has no cache, and it is the conservative
        // direction (less life, never more). Wired from
        // EnginePrincipalStore::kAuthCacheTtl for the MCP GET surface.
        std::chrono::milliseconds revalidate_max_staleness{0};
    };

    using ClockFn = std::function<std::chrono::steady_clock::time_point()>;
    using WriteFn = std::function<bool(const char*, std::size_t)>;

    // Two ctors rather than a `Config cfg = {}` default argument: Config's default
    // member initializers cannot be consumed by `= {}` while the enclosing class is
    // still incomplete (GCC rejects it — the same shape documented on
    // McpSessionRegistry). The short form delegates where Config is complete.
    McpStreamPump(std::shared_ptr<McpStreamSink> sink, std::shared_ptr<McpStreamState> stream,
                  std::uint64_t generation, std::function<StreamRevalidate()> revalidate,
                  std::function<bool()> session_alive);
    McpStreamPump(std::shared_ptr<McpStreamSink> sink, std::shared_ptr<McpStreamState> stream,
                  std::uint64_t generation, std::function<StreamRevalidate()> revalidate,
                  std::function<bool()> session_alive, Config cfg, ClockFn clock = {},
                  yuzu::MetricsRegistry* metrics = nullptr);

    /// One provider pass: wait up to a tick, re-validate, drain, heartbeat.
    /// Returns false when the stream is over (httplib then runs the release
    /// callback, which detaches the sink and audits the close reason).
    ///
    /// NEVER THROWS. httplib runs a chunked content provider from a bare ThreadPool
    /// task — outside the try/catch that wraps `routing()` — so an escaped exception
    /// here is `std::terminate`, not a 500 (the #2037 failure class). The body is
    /// wrapped; do not unwrap it. Re-validation alone reaches SQLite and the auth
    /// manager, both of which can throw.
    bool pump_once(const WriteFn& write);

private:
    bool pump_once_impl(const WriteFn& write); ///< the throwing body pump_once() guards
    bool finish(const WriteFn& write, McpStreamClose reason);

    std::shared_ptr<McpStreamSink> sink_;
    std::shared_ptr<McpStreamState> stream_;
    std::uint64_t generation_;
    std::function<StreamRevalidate()> revalidate_;
    std::function<bool()> session_alive_;
    Config cfg_;
    yuzu::MetricsRegistry* metrics_ = nullptr;
    ClockFn clock_; ///< copy of the injected clock; `grace_` owns the other one
    /// When the next credential re-check falls due. SEEDED IN THE CTOR to
    /// `now + cfg_.tick`, never left default-constructed: a default `time_point` is the
    /// steady_clock EPOCH, which would make the first pass's wait budget zero and turn it
    /// into an instant no-op pass. That is not hypothetical - it shipped on an earlier
    /// attempt at this fix and silently invalidated the test that certified the wake path.
    ///
    /// This drives the GATE only. The DRAIN still runs on every wake, so progress reaches
    /// the wire as it happens; only the two store round trips (credential re-validation and
    /// the session TTL slide) ride the tick.
    std::chrono::steady_clock::time_point next_check_{};
    // The credential re-validation grace policy (revoke/indeterminate/valid/stale, jitter,
    // #2367 staleness clamp). Owns all of the grace state + the injected clock; this pump keeps
    // only the wire action taken on its verdict. Constructed from cfg_ + the ClockFn.
    RevalidateGrace grace_;
};

/// The streamed-POST response pump (2f PR 3b): progress frames, then the
/// JSON-RPC result LAST, then EOF. A SIBLING of McpStreamPump, not a subclass -
/// that class has no virtuals and no protected state - and it lives in this
/// header for one hard reason: `write_all` and `count_stream_close` are in
/// mcp_stream.cpp's anonymous namespace, so a pump defined anywhere else could
/// not reuse them.
///
/// Differences from the GET pump, all of them load-bearing:
///  - Its frames come from the BRIDGE, not from its sink queue. A streamed
///    record publishes ring-only (deliver_live=false), so the sink is a pure
///    WAKE CHANNEL: the projector pokes it, and the pump then asks the bridge
///    what to write. Nothing ever enqueues onto that queue.
///  - It has a response CAP. The GET channel is open-ended; a POST response is
///    a request/response exchange, so it is MEANT to be bounded (#2739, fixed: the cap
///    now fires on a busy execution, via the drain-then-settle state in
///    McpStreamBridge::project_record) and the execution continues
///    server-side past the close. That needs a clock of its own, because
///    RevalidateGrace privately owns the one injected into it.
///  - It NEVER closes the session's stream state. The GET pump owns that stream;
///    closing it here would kill a concurrent GET channel that this request has
///    no authority over.
class McpPostPump {
public:
    struct Config {
        std::chrono::milliseconds tick = kMcpStreamTickDefault;
        /// Decision 15: the streamed-POST response is bounded, then closed with
        /// kCapExpired while the execution continues; the client collects the
        /// result by GET resume or by execution_id. A documented SHOULD
        /// deviation ("SHOULD NOT close before sending the response") taken as a
        /// resource bound with a resumable escape.
        std::chrono::milliseconds cap = kMcpStreamedPostCapDefault;
        std::chrono::milliseconds revalidate_grace = kMcpRevalidateGraceDefault;
        std::chrono::milliseconds revalidate_grace_jitter_max{0};
        std::chrono::milliseconds revalidate_max_staleness{0};
    };

    /// Aliased, NOT redeclared: `write_all` is typed to McpStreamPump::WriteFn,
    /// and a fresh std::function typedef is a distinct type that would not bind.
    using WriteFn = McpStreamPump::WriteFn;
    using ClockFn = McpStreamPump::ClockFn;
    /// What the bridge hands back for one tick. Injected as a callable rather
    /// than a bridge pointer so this half stays testable without a live bridge,
    /// matching how the GET pump takes `revalidate` / `session_alive`.
    using TakeBatchFn = std::function<McpStreamBridge::PostBatch(bool cap_expired)>;
    using FinalWrittenFn = std::function<void()>;

    McpPostPump(std::shared_ptr<sse_bus::SseSinkState> sink, TakeBatchFn take_batch,
                FinalWrittenFn on_final_written, std::function<StreamRevalidate()> revalidate,
                std::function<bool()> session_alive);
    // Two ctors rather than `Config cfg = {}` for the same reason as
    // McpStreamPump: GCC rejects a defaulted brace-init of an incomplete
    // enclosing class.
    McpPostPump(std::shared_ptr<sse_bus::SseSinkState> sink, TakeBatchFn take_batch,
                FinalWrittenFn on_final_written, std::function<StreamRevalidate()> revalidate,
                std::function<bool()> session_alive, Config cfg, ClockFn clock = {},
                yuzu::MetricsRegistry* metrics = nullptr,
                std::string correlation_id = {}, std::string execution_id = {});

    /// true = keep the response open, false = the provider is done. Hard
    /// noexcept boundary: httplib runs providers on a bare ThreadPool task.
    bool pump_once(const WriteFn& write);

    /// Why this response closed, for the releaser's `mcp.stream.close` audit.
    /// FIRST reason wins (the first is the cause; later ones are its
    /// consequences), and every close path records BEFORE its observability, so
    /// the audit can never disagree with yuzu_mcp_stream_closes_total. kNone =
    /// the pump never closed it, which the releaser reads as the client going
    /// away - the modal case, since httplib checks liveness before each tick.
    [[nodiscard]] McpStreamClose close_reason() const noexcept;

private:
    void note_close_reason(McpStreamClose reason) noexcept;
    /// Publishes "this response is over" into the sink flag the bridge's cancel
    /// interlock reads, on every path that ends the response. See the definition.
    void mark_sink_closed() noexcept;
    bool pump_once_impl(const WriteFn& write);
    /// Writes the close frame (except for kCompleted, which EOFs after a real
    /// final) and always returns false.
    bool finish(const WriteFn& write, McpStreamClose reason);

    std::shared_ptr<sse_bus::SseSinkState> sink_;
    TakeBatchFn take_batch_;
    FinalWrittenFn on_final_written_;
    std::function<StreamRevalidate()> revalidate_;
    std::function<bool()> session_alive_;
    Config cfg_;
    yuzu::MetricsRegistry* metrics_ = nullptr;
    std::string correlation_id_;
    std::string execution_id_;
    ClockFn clock_;
    std::chrono::steady_clock::time_point deadline_;
    /// Next credential re-validation / session-touch. Separate from the wait
    /// timeout: the poke wakes this pump per publication, but the store round trips
    /// stay on the tick.
    std::chrono::steady_clock::time_point next_check_{};
    RevalidateGrace grace_;
    std::atomic<McpStreamClose> close_reason_{McpStreamClose::kNone};
};

/// The `GET /mcp/v1/` tail, called by `McpServer::build_get_handler` after its
/// PR-1 pre-checks (kill switch → streaming gate → Origin → auth). Owns every
/// denial (400/404/406/429), the attach audit, the response headers, and the
/// chunked provider wiring.
///
/// `budget` / `revalidate` may be null/empty in test seams; production wires
/// both (the registration path warns when they are missing).
///
/// `per_principal_cap` is the operator's `--mcp-max-streams-per-principal`. It is a
/// PARAMETER, not a constant read at the call site: threading it from Config is what
/// makes the flag do anything. It was previously hardcoded to the default here, so the
/// flag and its env var parsed, validated, logged and documented as a working control
/// while having no effect at all.
void handle_get_tail(const httplib::Request& req, httplib::Response& res,
                     const std::string& principal, McpSessionRegistry& sessions,
                     sse_bus::StreamBudget* budget, const StreamRevalidateFn& revalidate,
                     yuzu::MetricsRegistry* metrics, const StreamAuditFn& audit_fn,
                     std::size_t per_principal_cap = kMcpStreamsPerPrincipalDefault,
                     StreamAuditPrincipal audit_principal = {},
                     const StreamPrincipalAuditFn& principal_audit_fn = {});

}  // namespace yuzu::server::mcp
