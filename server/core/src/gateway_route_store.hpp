#pragma once

/// @file gateway_route_store.hpp
/// HA WS-4 slice 4.1: the fenced agent→cluster **routing directory**. Records
/// which gateway cluster/node currently holds each agent's live gRPC stream,
/// so a future dispatch surface (NOT this slice — see below) can route a
/// command to the gateway actually holding the connection instead of relying
/// on the single-process `AgentRegistry` that active-active replicas cannot
/// share.
///
/// INERT IN 4.1: this store is written on connect/disconnect but nothing
/// reads it for dispatch decisions yet — that wiring is a later WS-4 slice.
/// Getting the writer path (and its anti-replay fence) right FIRST, before any
/// reader depends on it, is deliberate.
///
/// THE FENCE (why `connection_epoch` exists) — and what it does NOT do.
/// `register_fresh` mints a fresh epoch (`gateway_route_store.connection_epoch_seq`)
/// at ProxyRegister PROCESSING time and the guarded UPSERT only accepts an epoch
/// numerically GREATER than the row's current one (`WHERE EXCLUDED.connection_epoch
/// > agent_routes.connection_epoch`). Its job is to order CONCURRENT fresh
/// registrations for one agent: when two race, the later committer wins and the
/// earlier one is told `won=false` — mirroring the `LeaderElector`/
/// `CommandOutboxStore` epoch-fence shape (per-agent, not per-lock). It does NOT
/// fence a STALE/delayed replay: because the epoch is minted at processing time,
/// a replay handled later mints a HIGHER epoch and WINS the fresh branch (see the
/// 4.2 OBLIGATIONS note below). Stale-connection protection comes entirely from
/// the re-announce branch (reusing a still-known session) + the SESSION GUARDS
/// below — NOT from the epoch.
///
/// SESSION GUARDS (`announce_connected` / `deregister`). Once a connection has
/// won the epoch race and is recorded, its FOLLOW-UP notifications
/// (`announce_connected` filling in cluster/node once the gateway has fully
/// established the session, and the eventual `deregister` on disconnect) are
/// guarded by `session_id`, not by epoch — they only touch the row if it still
/// belongs to THIS session. A stale CONNECTED/DISCONNECTED from a DIFFERENT,
/// already-superseded session therefore cannot overwrite or tear down a
/// newer re-home IN THIS STORE: `announce_connected` no-ops (falls through to
/// an `ON CONFLICT DO NOTHING` insert) if the session doesn't match, and
/// `deregister` tombstones zero rows.
///
/// This guarantee was DURABLE-STORE-ONLY through HA WS-4 4.4's initial push
/// (PR #4636 FortitudeEtc post-build review, BLOCKER 2): the IN-MEMORY
/// `AgentRegistry::set_gateway_route` (agent_registry.cpp) had NO session
/// check at all — a delayed CONNECTED for a session already superseded by a
/// genuine newer registration could still clobber the newer session's
/// `gateway_node`/capabilities/`stream_home_id` in memory even though this
/// store's own row stayed correct, a real end-to-end gap this file's own
/// prose read as already closed. Fixed in the same PR:
/// `AgentRegistry::set_gateway_route` now takes and checks `session_id`
/// against the currently-installed session (mirroring
/// `gateway_stream_home_id`'s own pre-existing guard) and returns `false`
/// (nothing written) on a mismatch; `NotifyStreamStatus`'s CONNECTED handler
/// rejects the RPC outright on `false` rather than falling through to this
/// store's own (already-correct) `announce_connected` write. The claim below
/// is therefore now genuinely end-to-end — memory AND store both refuse a
/// stale session — not store-only as it was when first written.
/// LIMIT (as of 4.2a) — a SAME-session late notification was NOT fenced by
/// `session_id` alone: the re-announce path deliberately REUSES the session
/// id, so `session_id` equality cannot distinguish an old home's teardown
/// from a newer re-home under the same id. This was unreachable under the
/// shipped gateway (at most one `CONNECTED(S)` and one `DISCONNECTED(S)` per
/// session — see the #4246 #4 bullet in ADR-2002 §7). SLICE #4324 below adds
/// the per-home generation (`stream_home_id`) that closes this gap
/// end-to-end (store predicate below AND the RPC-handler wiring in
/// `gateway_service_impl.cpp` — CLOSED, both halves, as of #4324 task 3/3).
/// Invariant to preserve: `session_id` ≡ exactly one gateway stream
/// placement.
///
/// SLICE #4324 (HA WS-4, store layer) — `stream_home_id` is an opaque,
/// per-connection-instance id (minted once per gateway process instance,
/// task 1 of #4324) stamped on both the CONNECTED and DISCONNECTED
/// notification a given stream instance ever sends. `announce_connected`
/// writes it into the row on every winning placement write, exactly like
/// `cluster_id`/`gateway_node` (it IS placement, not a session property —
/// `announce_connected` stays the sole writer of it); `register_fresh` NULLs
/// it on a winning re-register for the same reason it NULLs `cluster_id`/
/// `gateway_node` (4.2b Task A). `deregister`'s tombstone predicate is
/// `stream_home_id IS NULL OR stream_home_id = $3` — an EMPTY/NULL stored
/// home ADMITS ANY incoming `$3` (stamped or not); a STAMPED stored home
/// requires an EXACT match. This closes the SESSION GUARDS LIMIT above for a
/// rolling gateway upgrade (mixed-version cluster is the NORMAL state of
/// one): an old-build gateway node's late DISCONNECTED — unstamped — must
/// not tombstone a new-build node's stamped re-home reusing the same session
/// id (a stamped `$3` never satisfies `stream_home_id IS NULL` against a
/// stamped stored value, and `stream_home_id = $3` needs an exact match), but
/// a genuinely-matching stamped DISCONNECTED must still tear down its own
/// stamped row, and a legacy DISCONNECTED against a legacy (never-stamped,
/// stored-NULL) row must still behave exactly as before. The naive symmetric
/// predicate (`$3 = '' OR stream_home_id = $3`) would let ANY unstamped
/// DISCONNECTED tear down ANY row regardless of its stamped home id,
/// re-opening exactly this race — do not "fix" this predicate back to that
/// shape. `reap_stale_routes`'s tombstone sweep NULLs `stream_home_id`
/// alongside `session_id`/`lease_until`/`cluster_id`/`gateway_node` for the
/// same reason: a tombstoned row must have a fully cleared placement. CLOSED
/// under today's shipped-gateway producer invariant (#4324 task 3/3): the
/// RPC handler (`gateway_service_impl.cpp`'s `NotifyStreamStatus`) threads
/// the caller's REAL `stream_home_id` into both `announce_connected` and
/// `deregister`, AND resolves an identical fence against `AgentRegistry`'s
/// in-memory `gateway_stream_home_id` — resolved ONCE, at the top of the
/// DISCONNECTED branch, before ANY of the registry-clear/store-deregister/
/// session-map-erase effects run (all-or-nothing; see that handler's own
/// comment for why splitting them is a correctness bug, not a style choice).
/// A gateway build predating #4324 (empty `stream_home_id` on every call) is
/// unaffected — a stored-NULL row always admits an empty incoming value too.
///
/// PREDICATE FIX (PR #4492 review, HIGH, fixed pre-merge): the ORIGINAL form
/// of this predicate was `stream_home_id = $3 OR (stream_home_id IS NULL AND
/// $3 = '')` — requiring the INCOMING value to ALSO be empty before a
/// stored-NULL row would admit it. That was wrong: a stored-NULL home does
/// NOT only mean "legacy, never stamped" — under the single-producer
/// invariant it can equally mean "this session's own `announce_connected`
/// (called from the CONNECTED branch) simply hasn't run yet." The gateway
/// dispatches CONNECTED and DISCONNECTED as two independently
/// `spawn_monitor`'d RPC workers with NO ordering guarantee between them
/// (`yuzu_gw_upstream.erl`), so an ORDINARY connect/disconnect — no re-home,
/// no second CONNECTED/DISCONNECTED pair, just the FIRST and ONLY one for a
/// brand-new session — can have its DISCONNECTED reach this server before
/// its own paired CONNECTED. The original predicate rejected that stamped,
/// entirely legitimate DISCONNECTED (stored NULL, incoming non-empty), so
/// the deregister/fence silently no-opped, and the delayed CONNECTED then
/// published a route for an already-dead stream — a regression vs. the
/// pre-#4324 unfenced behavior, where the same reordering self-corrected.
/// This is DIFFERENT FROM, and reachable WITHOUT, the FORWARD NOTE gaps
/// below (which all require a producer of a SECOND CONNECTED/DISCONNECTED
/// pair for the same session — live re-home, not shipped until 4.3/4.4); it
/// needed only the ordinary FIRST pair, reordered, which is reachable today
/// under ordinary operational churn. The identical gap existed in the
/// in-memory fence (`gateway_service_impl.cpp`'s `home_matches`) and is
/// fixed there the same way — the two predicates must never diverge.
///
/// SCOPE OF "CLOSED" (adversarial review, 2026-09-17): the fence is a
/// check-then-act, not a single atomic operation — `gateway_stream_home_id()`
/// reads and releases `stream_mu` before the three DISCONNECTED effects run
/// under their own separate lock acquisitions. Under the CURRENT shipped
/// gateway this remains safe with the predicate fix above, because at most
/// one `CONNECTED(S)` and one `DISCONNECTED(S)` are ever emitted per session
/// id (see the SESSION GUARDS LIMIT above) — there is no producer of a
/// second, genuinely concurrent `CONNECTED(S, home2)` for the fence's
/// read-then-act window to race against. "CLOSED end-to-end" means closed
/// against every interleaving that invariant permits (which, after the
/// predicate fix, now correctly includes an out-of-order first pair), NOT
/// atomic against arbitrary concurrent RPC execution for a SECOND pair. See
/// the FORWARD NOTE immediately below for what 4.3/4.4 must add before
/// same-session re-home makes that second-pair producer real.
///
/// FORWARD NOTE for #4324's 4.3/4.4, RESOLVED (enterprise-architect
/// adjudication, 2026-09-18, confidence HIGH, spot-checked against the cited
/// call sites): all three directions below share ONE precondition — a
/// same-session, different-home CONNECTED (`CONNECTED(S, home2)` published
/// for a session `S` already at `home1`) — and NO producer of that
/// precondition exists today, nor is one planned for 4.3/4.4. The agent
/// reconnect loop always re-`Register`s on a new connection (a new
/// `session_id`, `agent.cpp`'s Register-retry loop), and the gateway's
/// `Subscribe` REFUSES any presented session with no pending registration
/// (`yuzu_gw_agent_service.erl`, `NOT_FOUND` on a `take_pending` miss) — a
/// gRPC stream cannot migrate BEAM nodes, so a physical stream move is
/// ALWAYS agent-reconnect-shaped: new session, new `stream_home_id`. The
/// EARLIER draft of this note proposed "the gateway mints a fresh session on
/// re-home" as a design choice; that was WRONG — a gateway-synthesized
/// session the agent does not hold starves on the next heartbeat (heartbeats
/// carry the agent's OWN `session_id_`; `BatchHeartbeat` excludes an unknown
/// session from `renew_leases`), reproducing the `#4246` #6 S′-vs-S desync
/// deliberately. The invariant is agent-driven reconnect, never a
/// server/gateway-synthesized session substitution.
///
/// (a) STORE-SIDE ordering: unreachable — `home2` never gets a CONNECTED
/// under a `session_id` that already published `home1`; a genuine re-home
/// arrives as `register_fresh(S_new)`, not `CONNECTED(S, home2)`.
///
/// (b) IN-MEMORY check-then-act: unreachable, and closed WITHOUT a new CAS
/// primitive — the check-then-act window only matters when ONE `session_id`
/// key is shared across two homes. With a distinct `session_id` per
/// placement, every DISCONNECTED-branch effect is already an individually
/// atomic, session-guarded conditional (`remove_agent_if_session`,
/// `clear_stream_if_session`, `gateway_stream_home_id`'s nullopt-on-mismatch,
/// the store's session-guarded `deregister` UPDATE, `gateway_sessions_`
/// erase-by-key) — a stale `DISCONNECTED(S_old, home1)` interleaved anywhere
/// around `register_agent(S_new)`/`CONNECTED(S_new, home2)` either no-ops
/// per effect or tears down only `S_old` state, never `S_new`'s.
///
/// (c) CONNECTED-reorder: unreachable for the same reason as (a) — there is
/// no second CONNECTED for the same session to reorder against.
///
/// STANDING INVARIANT (load-bearing going forward, not just historical
/// analysis): 4.3/4.4 MUST NOT introduce ANY path that emits
/// `CONNECTED(S, home2)` for a session `S` already published at `home1` —
/// every physical placement change is agent-originated re-`Register`. This
/// replaces the former "atomic home-CAS primitive" acceptance criterion
/// (`#4490`) with a server-side TRIPWIRE instead: a CONNECTED for a known
/// `(agent_id, session_id)` whose stored `stream_home_id` is non-empty and
/// differs from the incoming one must be REJECTED (not published) and
/// counted (folds into `#4464`'s `duplicate_connected` tripwire), backed by
/// a deterministic interleaving test (the existing
/// `register_agent_interleave_hook_for_test_` seam) proving a stale
/// `DISCONNECTED(S_old, home1)` interleaved at every point of
/// `register_agent(S_new)`/`map_session`/`CONNECTED(S_new, home2)` leaves
/// `S_new` live in registry, store, and `gateway_sessions_`. `4.4`'s `#4246`
/// #6 fix (SHIPPED) follows this rule: `ProxyRegister` ADOPTS a presented
/// session into `gateway_sessions_`/registry only if the directory
/// `renew_leases` call matched >= 1 row (a store-side CAS proving the row
/// still belongs to that session) OR the new guarded CAS
/// `reclaim_tombstoned_session` re-arms a row this session's row was
/// TOMBSTONED under (never a row a DIFFERENT, live session holds) —
/// NEVER writing back a server-minted session to a gateway whose agent
/// still holds the original. An ADOPT is followed by the gateway's own
/// still-live `yuzu_gw_agent` process re-sending its OWN, already-stamped
/// CONNECTED (`yuzu_gw_agent:reannounce/2`) — a SAME-session, SAME-home
/// re-publish, never a `CONNECTED(S, home2)` for a different home, so this
/// does not reopen the tripwire above.
///
/// WOULD REOPEN THIS: a 4.3 design where the logical home (the
/// `yuzu_gw_agent` process / `stream_home_id`) moves or is re-spawned
/// WITHOUT the agent reconnecting — e.g. a node-A-holds-socket/
/// node-B-owns-agent proxy hop. That would create a same-session
/// different-home producer this analysis assumes does not exist, and the
/// full atomic home-CAS primitive + store-side re-arm this note originally
/// proposed would become necessary again. Treat "no such producer" as a
/// design CONSTRAINT on 4.3, not an assumption to re-verify only after the
/// fact.
///
/// `renew_leases` is a single batched statement, correlated on BOTH
/// `agent_id` AND `session_id` (a parallel-array unnest() join — #4246 #10) —
/// at fleet scale a per-row renew would be one write per agent every lease
/// interval; batching keeps the steady-state write rate flat regardless of
/// fleet size. The agent_id correlation is a defense-in-depth hardening: a
/// caller that knows only a session token can no longer renew a route
/// belonging to a DIFFERENT agent.
///
/// Posture (ADR-0012 §1): as of 4.2b this store is read for dispatch as a
/// FALLBACK (only on a local-registry miss; it changes no routing outcome on a
/// single-replica deployment, where every agent is locally known). Integrity
/// lives at the reader's `routable` trust predicate, so most writes stay
/// fail-open (a degraded write is logged and returned to the caller, never
/// silently dropped); register_fresh — the row-CREATING write whose loss has no
/// other writer to repair it — is the one fail-CLOSED exception (4.2b Task B,
/// returns UNAVAILABLE).
///
/// 4.2 OBLIGATIONS (latent while INERT, load-bearing once a dispatch reader
/// exists — full list in ADR-2002 §7 "4.2 design obligations"): the "cannot
/// overwrite a newer re-home" property above is precise only for OVERWRITE, and
/// only intra-replica with a live session. The epoch orders by server PROCESSING
/// time, so a stale replay whose session has left `gateway_sessions_` takes the
/// fresh branch and wins; the re-announce reuses the session id (a late
/// DISCONNECTED would otherwise tombstone — logically tear down — the
/// re-homed route, #4/#4324 — CLOSED under today's single-producer
/// invariant by SLICE #4324 below: both the store's asymmetric predicate AND
/// the RPC-handler's `stream_home_id` wiring + `AgentRegistry` in-memory
/// fence — see the SCOPE OF "CLOSED" note above for the check-then-act
/// residual 4.3/4.4 must still close) and its known-session check is
/// per-replica in-memory; re-announce refreshes the lease, not cluster/node; and
/// a stale-lease reaper plus the fail-open->fail-closed flip must land before 4.2
/// trusts this directory for routing.
///
/// SLICE 4.2a — `deregister` TOMBSTONES instead of deleting. This closes the
/// late-CONNECTED RESURRECTION direction (#5 in the 4.2 design doc): a late
/// CONNECTED for a now-gone session no-ops against the tombstone instead of
/// reviving a dead route. It did NOT close #4 (a same-session late
/// DISCONNECTED tombstoning a newer re-home) on its own — that needed the
/// per-home generation fence SLICE #4324 below adds, now closed under
/// today's single-producer invariant (see the SESSION GUARDS LIMIT above,
/// its SCOPE OF "CLOSED" note, and ADR-2002 §7 #4246 #4). A
/// tombstone is `session_id IS NULL
/// AND lease_until IS NULL`; `connection_epoch` is retained. Rationale: a bare
/// DELETE lets `announce_connected`'s fallback `ON CONFLICT DO NOTHING`
/// INSERT resurrect a dead route if a late/reordered CONNECTED notification
/// for the just-torn-down session arrives after the DISCONNECTED that
/// deleted it — the INSERT sees no row and recreates one carrying a session
/// nobody holds. With a tombstone, that late CONNECTED's session-guarded
/// UPDATE still misses (no row has that `session_id` — NULL never equals a
/// bound parameter) and its fallback INSERT is now an `ON CONFLICT DO
/// NOTHING` against an EXISTING row (the tombstone), so it no-ops instead of
/// resurrecting. A genuine later `register_fresh` still reuses the row: its
/// freshly-minted epoch is always higher than whatever the tombstoned row
/// retained, so the guarded UPSERT wins unconditionally.
///
/// `reap_stale_routes()` is the durable-directory-hygiene reaper (#7 in the
/// 4.2 design doc) for two row shapes this store accumulates over time: (a)
/// a route whose lease has been expired for longer than a grace window (a
/// gateway that stopped renewing — crashed, network-partitioned, or the
/// agent disconnected without a clean DISCONNECTED notification), and (b) a
/// tombstoned/never-announced row (`lease_until IS NULL`) old enough that it
/// is definitely not mid-handshake. See the header comment on
/// `reap_stale_routes` for the clock-guarded-retention adoption record.
/// #4669: sweep (a)'s tombstone UPDATE now ALSO NULLs `home_cluster_id`
/// (alongside cluster_id/gateway_node/stream_home_id/session_id/lease_until)
/// — this is the "row expired" legitimate re-home trigger from the file
/// header's "AGENT<->CLUSTER AFFINITY" note: an agent genuinely unreachable
/// from its home cluster for the full grace window (>= 1 lease TTL) is
/// eligible to bind a new affinity on its next `announce_connected`, from
/// ANY cluster. Sweep (b)'s hard DELETE already achieves the same by removing
/// the row (and therefore the affinity) entirely.
///
/// SLICE 4.2b — TASK A: `announce_connected` is the SOLE writer of
/// placement. `register_fresh`'s guarded UPSERT used to COALESCE-preserve a
/// winning row's existing `cluster_id`/`gateway_node` across a fresh
/// registration; it now NULLs both unconditionally. Without this, a
/// `register_fresh(S2)` immediately followed by a bare `renew_leases`
/// (no intervening CONNECTED) left the row reading `{session=S2, live
/// lease, cluster=S1's old placement}` — a stale-placement trap for a
/// dispatch reader that must never route to a placement its own session
/// never confirmed. `lookup_routes` (also 4.2b Task A) exposes a
/// `routable` bit computed from exactly this shape (`session_id IS NOT
/// NULL AND lease_until >= now() AND cluster_id IS NOT NULL`), so a
/// dispatch reader built against it never needs to reason about the trap
/// directly.
///
/// Born-on-Postgres (ADR-0009 fresh-start): no legacy SQLite file, no
/// backfill — this store never existed before WS-4.
///
/// AGENT<->CLUSTER AFFINITY (#4669, migration v4's `home_cluster_id` column).
/// `announce_connected` is the sole writer of `cluster_id` (the EPHEMERAL,
/// per-connection placement, NULLed on every `register_fresh`); `home_cluster_id`
/// is a SEPARATE, STICKY column `register_fresh`/`deregister` never touch —
/// it survives a fresh registration/session churn on purpose, because that
/// churn is exactly the mechanism a rogue gateway abuses (#4669's finding:
/// `ProxyRegister` re-registers any already-approved agent_id with no
/// per-agent secret, and `register_fresh`'s newer-epoch-wins rule lets that
/// registration unconditionally claim the row). Semantics:
///   - `home_cluster_id IS NULL` (never bound, or explicitly cleared — see
///     below) admits ANY `cluster_id` and BINDS it (TOFU: trust the first
///     cluster to legitimately confirm this agent's connection).
///   - `home_cluster_id IS NOT NULL` admits ONLY a matching `cluster_id`. A
///     session-matched `announce_connected` presenting a DIFFERENT
///     `cluster_id` is refused — see that method's doc comment for the exact
///     guarded-UPDATE shape (WHERE-clause enforced, atomic, no read-then-write
///     TOCTOU) — and `AnnounceResult::cluster_affinity_violation` reports it
///     distinctly from an ordinary session mismatch so the caller
///     (`gateway_service_impl.cpp`'s `NotifyStreamStatus`) can refuse the
///     whole CONNECTED outright (fail-closed) rather than publish an
///     unconfirmed cross-cluster claim into the in-memory registry too.
///   - This is a NARROWER guarantee than "the row can never move clusters":
///     it prevents an INSTANT claim-then-answer hijack of an agent already
///     bound to a cluster. Two LEGITIMATE re-home paths exist, matching the
///     issue's own design: (1) genuine staleness — `reap_stale_routes`' sweep
///     (a) (expired-lease tombstone, >= grace window past the lease TTL) NOW
///     ALSO NULLs `home_cluster_id` alongside the rest of the tombstoned
///     placement, and sweep (b)'s hard DELETE removes the row (and therefore
///     the affinity) entirely — either way this requires the REAL cluster to
///     have been genuinely unreachable for the full grace window, not
///     something a rogue can force instantaneously; (2) `clear_cluster_affinity`,
///     an explicit, separately-callable operator action (the caller is
///     responsible for auditing it — this store only performs the write).
///   - Deliberately NOT gated on multi-cluster mode: `gateway_route_store_` is
///     wired whenever a gateway upstream is configured AT ALL (server.cpp),
///     single-cluster included, and single-cluster gateways announce a
///     STABLE `cluster_id` (`YUZU_GW_CLUSTER_ID`, defaulting to the literal
///     "default") on every connection — so TOFU-bind-then-match costs
///     single-cluster deployments nothing and changes no observable behavior
///     there, while still hardening the (already-shared) store/write path.
///   - Does NOT (on its own) prevent `register_fresh` itself from letting a
///     rogue claim a NEW session_id for an already-approved agent — that
///     churn is a pre-existing, accepted DoS-shaped weakness (ADR-2002 §7d:
///     "at worst a DoS" pre-4.3). What this closes is the FOLLOW-ON step that
///     made post-4.3 multi-cluster fan-out upgrade that DoS into real
///     command-payload interception: a rogue's own claimed session can no
///     longer make `cluster_id` (and therefore `GatewayMgmtStubPool::resolve()`'s
///     dispatch target) move to the rogue's cluster. The genuine agent's own
///     later reconnect (its own fresh `register_fresh`, strictly-higher epoch,
///     eventually wins per the anti-replay fence) still announces the
///     matching `cluster_id` and self-heals the row.

#include "pg/pg_migration_runner.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::pg {
class PgPool;
}

namespace yuzu::server {

/// The lease TTL agents/gateways renew against — DUPLICATED from (never
/// included from) `gateway_service_impl.cpp::kGatewayRouteLeaseTtlSecs`; see
/// `gateway_route_store.cpp`'s `reap_stale_routes()` constants comment for
/// why the duplication is deliberate. Declared here, rather than staying an
/// anonymous-namespace literal in the .cpp, so `gateway_service_impl.cpp`
/// (which already transitively includes this header) can `static_assert`
/// the two constants stay equal — see that file's `static_assert` next to
/// its own `kGatewayRouteLeaseTtlSecs` (PR #4299 review, MINOR).
inline constexpr int kKnownLeaseTtlSecs = 90;

/// Grace before an expired lease is treated as truly dead by `reap_stale_routes`
/// (sweep (a)): 2x the lease TTL tolerates a FULL missed renewal cycle, not just
/// the last heartbeat's worth of jitter. HOISTED into the header (PR #4299 round
/// 4) from `gateway_route_store.cpp`'s anonymous namespace so the reap recovery
/// FLOOR below can be computed from it here; the reap-sweep cutoff in the .cpp
/// still reads this same constant.
inline constexpr int kStaleLeaseGraceSecs = 2 * kKnownLeaseTtlSecs; // 180s

/// Reap-recovery persistence window (PR #4299 round 4). A skew anomaly's
/// decline-once/drain-on-repeat recovery fires only when the SAME (anchor,
/// direction) anomaly has PERSISTED for `delta = now_ms - first_now_ms` within
/// `[kMinReapRecoveryGapMs, kMaxReapRecoveryGapMs]` (see decide_reap).
///
/// FLOOR = the liveness horizon `(grace + lease TTL) * 1000` = 270'000ms: below
/// this, a spurious forward jump's exposed routes (those whose last renewal
/// predates the jump) are not yet reap-eligible, so recovering can't tombstone a
/// still-live route. It is load-bearing for the multi-replica future — an
/// ε-later second-replica pass must NOT recover with no persistence evidence.
/// CEILING = 1h (cadence-derived with slack): past it, the anomaly is a NEW,
/// discontinuous jump rather than the same one persisting.
inline constexpr std::int64_t kMinReapRecoveryGapMs =
    static_cast<std::int64_t>(kStaleLeaseGraceSecs + kKnownLeaseTtlSecs) * 1000; // 270'000
inline constexpr std::int64_t kMaxReapRecoveryGapMs = 3'600'000; // 1h

/// Typed store failure.
enum class GatewayRouteStoreError {
    store_unavailable, ///< not open / lease timeout — the store cannot answer
    db_error,          ///< a query against an open store failed
};

/// Outcome of `register_fresh`.
struct RegisterFreshResult {
    std::int64_t epoch{0}; ///< the freshly-minted epoch for this connection attempt
    bool won{false};       ///< true iff this epoch's row is the one now stored
};

/// Outcome of `announce_connected`.
struct AnnounceResult {
    bool matched{false}; ///< true iff the UPDATE hit a row owned by this session
    /// #4669: true iff the write was refused SPECIFICALLY because the row is
    /// owned by this session but its durable `home_cluster_id` differs from
    /// the `cluster_id` this call presented — a same-session, different-
    /// cluster claim. Distinct from an ordinary `matched == false` session
    /// mismatch (a benign, expected race/desync — see
    /// `record_directory_desync`'s header comment in gateway_service_impl.cpp):
    /// this is a SECURITY-relevant refusal the caller must treat as
    /// fail-closed (refuse to publish the claimed placement anywhere, incl.
    /// the in-memory registry), never merely logged as a desync. Mutually
    /// exclusive with `matched` (a violation never also matches).
    bool cluster_affinity_violation{false};
};

/// Outcome of `deregister`.
struct DeregisterResult {
    bool removed{false}; ///< true iff a row owned by this session was tombstoned
};

/// Outcome of `reap_stale_routes`. `clock_anomaly` mirrors
/// `SessionStore::ReapOutcome` (session_store.hpp): true iff the pass was
/// DECLINED because a clock-guard-critical reading (DB `now()` or the
/// persisted `route_meta` anchor) was unusable — implausibly ahead of, or
/// behind, the anchor, or unparseable/negative. A declined pass always reaps
/// nothing. A skew (implausibly-ahead/-behind) decline leaves the anchor
/// UNCHANGED; an unparseable/negative PERSISTED anchor instead SELF-HEALS —
/// this method is the anchor's sole writer, so a bad reading there can only
/// be corruption/tampering, and the anchor is rewritten to this pass's own
/// now_ms (never drained) so the next pass proceeds normally rather than
/// wedging forever (PR #4299 round-3 review; see
/// gateway_route_store.cpp's persisted-anchor guard and
/// docs/clock-guarded-retention.md).
///
/// MARKER OBLIGATION (PR #4299 round-3, the defect class the decide/apply
/// split in gateway_route_reap_rules.hpp closes): every lock-holding pass that
/// COMMITS writes `reap_declined_anchor_ms` exactly once — ARM or CLEAR.
/// LEAVE exists ONLY for passes that never read `now()` (the advisory-lock
/// skip) or that roll back. Any DISTINCT anomaly — a skew/direction mismatch,
/// a bad `now()` reading, OR a corrupt persisted anchor — CLEARs or re-ARMs
/// the marker; none of them LEAVES a stale recovery identity a later
/// same-direction skew could free-ride on. The bad-`now()` path in particular
/// CLEARs (it used to LEAVE — that was the round-3 defect). Because
/// `ReapDecision::marker` has no default-constructible `MarkerAction`, a
/// future reap branch that forgets this decision is a COMPILE error, not a
/// silent fourth round of the same bug. `recovered` is true iff this
/// pass was NOT declined but DID run via the decline-once/drain-on-repeat
/// recovery branch (an anomaly persisted across a full decline pass — see
/// the reap_stale_routes() header below and docs/clock-guarded-retention.md)
/// — distinct from an ordinary accepted pass, since a recovery can drain a
/// large backlog in one go and is worth its own metric outcome
/// (`yuzu_server_gateway_route_reap_total{outcome="recovered"}`, PR #4299
/// round-2 review). `clock_anomaly` and `recovered` are mutually exclusive.
/// `skipped` (PR #4299 round-2 external review) is true iff another replica
/// already holds the `gateway_route_store:reap` advisory lock this tick — the
/// ReplicaSafe contract (background_jobs.hpp) is "all but the holder skip",
/// matching every sibling single-sweeper store's `pg_try_advisory_xact_lock`
/// idiom; `skipped` implies every other field stays at its default (the
/// lambda returns before reading now()/the anchor).
///
/// `cap_bound` (PR #4299 round 4, observability-only — NOT acceleration) is true
/// iff an accepted pass hit `kReapCap` on a sweep AND a same-txn `EXISTS` probe
/// (audit_store.cpp shape) confirmed a matching remainder still exists — i.e. a
/// real backlog outlives this pass. It surfaces as a distinct
/// `yuzu_server_gateway_route_reap_total{outcome="ok_capped"}` so a chronically
/// cap-bound reaper is visible WITHOUT changing cadence. Deliberately NOT wired
/// to a faster re-arm: see docs/clock-guarded-retention.md's GatewayRouteStore
/// adoption register for why acceleration is declined here.
struct ReapRoutesResult {
    int expired_leases_reaped{0}; ///< predicate (a): lease_until past the grace window
    int tombstones_reaped{0};     ///< predicate (b): NULL-lease, NULL-affinity rows past the
                                  ///< purge age, hard-deleted
    /// pr-rev finding (FortitudeEtc/Codex+Kimi, BLOCKER, 2026-09-22, empirically
    /// confirmed): predicate (b)'s ORIGINAL scope (any NULL-lease row past the purge
    /// age, hard-deleted regardless of session_id/home_cluster_id) let a single rogue
    /// `register_fresh` -- which sets `lease_until = NULL` but leaves `home_cluster_id`
    /// untouched -- manufacture this exact predicate on a row whose STICKY affinity was
    /// never actually stale, turning "the real cluster must be unreachable that long"
    /// into "a rogue registers once and waits kTombstonePurgeAgeSecs" (a Kimi-authored
    /// store-level repro against real Postgres confirmed the full sequence: rogue
    /// register_fresh -> purge -> rogue TOFU-rebind, home_cluster_id ends AT the
    /// rogue's cluster). Predicate (b) now hard-deletes ONLY a row with NO sticky
    /// affinity to protect (`home_cluster_id IS NULL`); a session-bearing,
    /// never-announced row whose affinity is STILL bound is soft-tombstoned instead
    /// (session_id/cluster_id/gateway_node/stream_home_id cleared, home_cluster_id
    /// preserved) and counted here, never hard-deleted by this predicate again on any
    /// LATER pass (home_cluster_id staying non-null permanently excludes it). This is a
    /// deliberate tradeoff, not an oversight: such a row's ONLY remaining clears are a
    /// genuine register_fresh+announce_connected re-establishing it, or an explicit
    /// `clear_cluster_affinity` call (no caller until #4696) -- a rogue registering
    /// again does not restart this timer against the row's affinity, since the
    /// preserved home_cluster_id already excludes it from predicate (b) regardless of
    /// how many more times session_id churns. A row that reaches `session_id IS NULL`
    /// via an ORDINARY `deregister()` (not this soft-tombstone) rather than via a rogue's
    /// abandoned claim is likewise excluded from predicate (b) by its own preserved
    /// `home_cluster_id` -- and is NOT counted here either, since predicate (b') itself
    /// requires `session_id IS NOT NULL` and never touches it. Such a row is simply left
    /// untouched by both predicates on every pass (it was already tombstoned by the
    /// `deregister()` call itself) -- not a gap, since nothing further needs clearing.
    int affinity_preserved_soft_tombstones{0};
    bool clock_anomaly{false};
    bool recovered{false};
    bool skipped{false};
    bool cap_bound{false}; ///< an accepted sweep hit kReapCap and a remainder still exists
};

/// A durable agent→cluster route, as read by `lookup_route`. Timestamps are
/// epoch-milliseconds authored by Postgres `now()` — never the process clock.
struct RouteRow {
    std::string agent_id;
    std::optional<std::string> cluster_id;
    std::optional<std::string> gateway_node;
    std::int64_t connection_epoch{0};
    std::optional<std::string> session_id;
    std::optional<std::int64_t> lease_until_ms; ///< epoch-ms, or nullopt if unset
    bool is_stale{false}; ///< computed IN-SQL: lease_until IS NOT NULL AND lease_until < now()
    /// #4669: the STICKY agent<->cluster affinity anchor — distinct from
    /// `cluster_id` above (which is the EPHEMERAL current placement, NULLed
    /// on every `register_fresh`). `nullopt` means "never bound" (a brand-new
    /// agent, or a row whose affinity was cleared by staleness/an explicit
    /// operator re-home) — the NEXT `announce_connected` binds it (TOFU). See
    /// the file header "AGENT<->CLUSTER AFFINITY" note.
    std::optional<std::string> home_cluster_id;
};

/// A route paired with the `routable` verdict computed by `lookup_routes`.
/// `routable` is IN-SQL, DB-clock-authoritative (never a replica clock, per
/// the #3715 rule): `session_id IS NOT NULL AND lease_until >= now() AND
/// cluster_id IS NOT NULL`. A tombstone (`session_id IS NULL AND lease_until
/// IS NULL`), an expired lease, or a null-placement row (a winning
/// `register_fresh` not yet followed by `announce_connected` — see the file
/// header "SLICE 4.2b") are all `routable == false`.
struct RoutableRoute {
    RouteRow route;
    bool routable{false};
};

class GatewayRouteStore {
public:
    /// Borrows the shared pool; runs the `gateway_route_store` schema
    /// migration on a pinned construction lease. `is_open()` is false if the
    /// lease was empty or the migration failed (ADR-0012 fail-closed —
    /// the caller/wiring site decides what "not open" means for boot).
    explicit GatewayRouteStore(pg::PgPool& pool);

    GatewayRouteStore(const GatewayRouteStore&) = delete;
    GatewayRouteStore& operator=(const GatewayRouteStore&) = delete;

    [[nodiscard]] bool is_open() const noexcept { return open_; }

    /// Mint a fresh epoch for a new connection attempt and guarded-upsert the
    /// agent's route row. `won` is true iff this epoch beat whatever epoch was
    /// previously stored (the CAS in the file header) — a caller whose
    /// `register_fresh` reports `won == false` lost to a newer connection
    /// and MUST NOT proceed to `announce_connected` with this epoch/session.
    /// `cluster_id`/`gateway_node`/`stream_home_id` are NULLed (4.2b; #4324
    /// for the last) on a winning re-register — `announce_connected` is the
    /// SOLE writer of placement, so a fresh registration never carries
    /// forward a superseded connection's cluster/node/home-id until its own
    /// CONNECTED confirms them.
    [[nodiscard]] std::expected<RegisterFreshResult, GatewayRouteStoreError>
    register_fresh(std::string_view agent_id, std::string_view session_id);

    /// Record that `session_id`'s connection is fully established on
    /// `cluster_id`/`gateway_node`, with a lease valid for `lease_ttl_secs`.
    /// Session-guarded (see file header): a no-op against a row now held by a
    /// DIFFERENT session. If no row exists yet for `agent_id` at all, inserts
    /// one (`ON CONFLICT DO NOTHING`) rather than overwriting a differently-
    /// sessioned row. `stream_home_id` (SLICE #4324, file header) is this
    /// connection instance's opaque per-home generation id — written into the
    /// row exactly like `cluster_id`/`gateway_node`, since it IS placement;
    /// an empty string (the default — a gateway build predating #4324, or a
    /// caller not yet threading it through) means "unknown", same convention
    /// as `cluster_id`.
    ///
    /// #4669 AFFINITY GUARD (see file header "AGENT<->CLUSTER AFFINITY"): the
    /// session-guarded UPDATE additionally requires `home_cluster_id IS NULL
    /// OR home_cluster_id = cluster_id` — a SAME-session claim presenting a
    /// DIFFERENT cluster than the durable home is refused ATOMICALLY (the
    /// affinity check is part of the guarded UPDATE's WHERE clause, not a
    /// separate read-then-write — no TOCTOU window). On a genuine mismatch
    /// the row is left COMPLETELY UNTOUCHED (no lease/placement write at
    /// all, unlike an ordinary session mismatch which is otherwise
    /// indistinguishable at the SQL level) and the returned
    /// `AnnounceResult::cluster_affinity_violation` is set so the caller can
    /// tell "session doesn't match" apart from "session matches, but this
    /// is a cross-cluster claim" — the caller (`gateway_service_impl.cpp`)
    /// treats the latter as fail-closed. A `home_cluster_id IS NULL` row
    /// (never bound, or cleared by staleness/an operator re-home) BINDS on
    /// this call (`home_cluster_id = COALESCE(home_cluster_id, cluster_id)`,
    /// TOFU) — this never regresses single-cluster deployments, which
    /// present a stable `cluster_id` on every connection (file header).
    [[nodiscard]] std::expected<AnnounceResult, GatewayRouteStoreError>
    announce_connected(std::string_view agent_id, std::string_view session_id,
                       std::string_view cluster_id, std::string_view gateway_node,
                       int lease_ttl_secs, std::string_view stream_home_id = {});

    /// #4669: the explicit-operator-action re-home path (file header "AGENT
    /// <->CLUSTER AFFINITY", trigger 2). Clears `home_cluster_id` for
    /// `agent_id` UNCONDITIONALLY (no session/epoch guard — this is a
    /// deliberate operator override, not a connection-lifecycle event), so
    /// the NEXT `announce_connected` for this agent — from ANY cluster —
    /// binds a fresh affinity via TOFU. Does NOT touch `cluster_id`/
    /// `gateway_node`/`session_id`/`lease_until`: an in-progress connection's
    /// CURRENT placement is left alone; only the sticky trust anchor is
    /// reset. Returns `true` iff a row existed for `agent_id` (`false` is not
    /// an error — clearing affinity for an agent with no row yet is a no-op,
    /// since a future first `announce_connected` already binds via TOFU
    /// regardless). AUDITING this action is the CALLER's responsibility
    /// (this store performs the write only, like every other method here) —
    /// a caller wiring this into an operator-facing surface MUST emit an
    /// audit event, per the issue's "an explicit operator re-home action is
    /// recorded" requirement.
    [[nodiscard]] std::expected<bool, GatewayRouteStoreError>
    clear_cluster_affinity(std::string_view agent_id);

    /// #4669: a lightweight, READ-ONLY pre-check — true iff `agent_id`'s row
    /// is CURRENTLY owned by `session_id` (a match), OR its durable
    /// `session_id` is NULL (session-orphaned — pr-rev round 2 fix below),
    /// AND its durable `home_cluster_id` is bound to a DIFFERENT, non-null
    /// cluster than `cluster_id` (an empty `cluster_id` never conflicts —
    /// same "unknown" convention as `announce_connected`). The `session_id
    /// IS NULL` disjunct (FortitudeEtc/Codex+Kimi, CRITICAL, pr-rev round 2,
    /// 2026-09-22, empirically reproduced twice independently) closes a
    /// second hijack the round-1 fix's soft-tombstone sweep (b') itself
    /// opened: once (b') clears a session-bearing affinity-bound row's
    /// durable `session_id` while preserving `home_cluster_id`, the ORIGINAL
    /// rogue's still-live in-memory gateway session can resend CONNECTED
    /// under that same session id — `session_id=$2` alone can never match a
    /// durable NULL, so without this disjunct the resend was invisible to
    /// this pre-check and fell through to the ordinary, unaudited
    /// `session_mismatch` bucket. Safe for a genuine first-ever TOFU contact
    /// — that row has `home_cluster_id IS NULL`, already excluded by this
    /// predicate's own `IS NOT NULL` clause regardless of session_id, so an
    /// ordinary slow first CONNECTED is unaffected. Lets a caller refuse EARLY,
    /// before publishing anything to its OWN non-durable state (e.g. an
    /// in-memory registry), without paying for a write. NOT the security
    /// boundary by itself — `announce_connected`'s own guarded UPDATE
    /// enforces the SAME affinity atomically at write time regardless of
    /// whether a caller uses this pre-check first: this read and the
    /// eventual write can never let a mismatched cluster_id persist
    /// DURABLY, only let a caller's own transient state briefly disagree
    /// with the store — exactly the pre-#4669 fail-open posture, never the
    /// reverse. Gate 2 security-guardian correction (2026-09-21): the
    /// CALLER's own transient state (e.g. an in-memory registry) CAN diverge
    /// from the store for longer than a microsecond race if this pre-check
    /// degrades. pr-rev fix (FortitudeEtc/Codex+Kimi, BLOCKER, 2026-09-22):
    /// the caller (`gateway_service_impl.cpp`'s `NotifyStreamStatus`) now
    /// reverts that transient publish on a definitive write-time refusal, so
    /// "briefly" is accurate again for the ORDINARY case (this read degrades,
    /// the later write still succeeds and correctly refuses). It stays
    /// open-ended only if THIS read and the later write BOTH degrade in the
    /// same window — see the caller's own comment for the concrete
    /// consequence and the alert that measures that compound case.
    [[nodiscard]] std::expected<bool, GatewayRouteStoreError>
    has_cluster_affinity_conflict(std::string_view agent_id, std::string_view session_id,
                                  std::string_view cluster_id);

    /// TOMBSTONE the agent's route row (session_id/lease_until/cluster_id/
    /// gateway_node/stream_home_id -> NULL; `connection_epoch` retained), but
    /// ONLY if the row still belongs to `session_id` AND the incoming
    /// `stream_home_id` clears the fence (file header SLICE #4324):
    /// `stream_home_id IS NULL OR stream_home_id = $3` — a NULL/empty
    /// STORED home admits ANY incoming value (it never represents a live
    /// placement worth protecting — see the file header's PREDICATE FIX
    /// note); a STAMPED stored home requires an EXACT match against `$3`, so
    /// it can never be torn down by an unstamped or differently-stamped
    /// incoming value from a superseded home. See the file header "SLICE
    /// 4.2a" note for why this is an UPDATE, not a DELETE.
    [[nodiscard]] std::expected<DeregisterResult, GatewayRouteStoreError>
    deregister(std::string_view agent_id, std::string_view session_id,
              std::string_view stream_home_id = {});

    /// HA WS-4 4.4 (`#4246` #6, gateway-side session-writeback fix): re-arm a
    /// TOMBSTONED (or entirely absent) row under `session_id`, for a gateway
    /// circuit-recovery replay whose presented session this replica no longer
    /// recognizes in memory (a core restart / replica failover / post-
    /// DISCONNECT eviction) but which was never superseded by a genuinely
    /// newer connection. Returns `true` (won) iff the row was tombstoned
    /// (`session_id IS NULL`) or absent; `false` (lost) iff a DIFFERENT,
    /// LIVE (non-NULL) session already holds the row — that is a genuine
    /// stale/zombie replay and the caller MUST NOT install anything.
    ///
    /// Deliberately does NOT mint a fresh `connection_epoch` (unlike
    /// `register_fresh`): this is not a new connection racing for the row,
    /// it is the exact same session being resurrected, so there is no
    /// concurrent-fresh-registration ordering to fence. `connection_epoch`
    /// is `0` on a brand-new row (no prior row existed at all); on a
    /// re-armed EXISTING tombstone it is left UNTOUCHED (retains whatever
    /// `register_fresh` last minted for that row) — either way it is safe:
    /// `register_fresh`'s `nextval` sequence starts above `0` and is
    /// strictly monotonic, so it always exceeds a brand-new row's `0`, and
    /// a tombstone's retained epoch is exactly what `register_fresh`
    /// already tolerated overwriting before this method existed. ANY later
    /// genuine `register_fresh` for this agent still wins the guarded
    /// upsert regardless of ordering, exactly as if this reclaim had never
    /// run. `cluster_id`/`gateway_node`/`stream_home_id` are left NULL (they
    /// are already NULL on a tombstone, and a never-existed row has nothing
    /// to carry forward) — `announce_connected` remains the sole writer of
    /// placement; this slice's gateway-side fix (re-sending the process's
    /// own CONNECTED after a successful reclaim) is what converges them,
    /// not this call.
    [[nodiscard]] std::expected<bool, GatewayRouteStoreError>
    reclaim_tombstoned_session(std::string_view agent_id, std::string_view session_id,
                               int lease_ttl_secs);

    /// Batched lease renewal: bumps `lease_until` for every row whose
    /// `(agent_id, session_id)` matches a pair in the two PARALLEL arrays
    /// `agent_ids`/`session_ids` (index i is one pair), in ONE statement.
    /// #4246 #10 — correlating on BOTH columns (not `session_id` alone) closes
    /// a defense-in-depth gap: a caller that only ever knows a session token
    /// can no longer renew a DIFFERENT agent's route by presenting that token
    /// against the wrong `agent_id`; such a call matches zero rows. A length
    /// mismatch between the two arrays is refused (`db_error`) rather than
    /// guessed at. Returns the number of rows renewed.
    [[nodiscard]] std::expected<int, GatewayRouteStoreError>
    renew_leases(std::span<const std::string> agent_ids, std::span<const std::string> session_ids,
                int lease_ttl_secs);

    /// The current route for `agent_id`, or `nullopt` if no row exists.
    /// `RouteRow::is_stale` is computed in-SQL from `lease_until` vs. `now()`.
    [[nodiscard]] std::expected<std::optional<RouteRow>, GatewayRouteStoreError>
    lookup_route(std::string_view agent_id);

    /// Batched routable-aware read (4.2b Task A): the current route for every
    /// agent in `agent_ids` that has a row, in ONE query (`WHERE agent_id =
    /// ANY($1)`, mirroring `renew_leases`' array-param idiom) bounded by a
    /// SINGLE `kReadTimeout` — never N times that. An agent with no row is
    /// simply absent from the result (no error, no placeholder entry). See
    /// `RoutableRoute` for the `routable` computation.
    [[nodiscard]] std::expected<std::vector<RoutableRoute>, GatewayRouteStoreError>
    lookup_routes(std::span<const std::string> agent_ids);

    /// Directory-hygiene reaper (4.2a, #7 in the ADR-2002 §7 "4.2 design
    /// obligations" list). CLOCK-GUARDED-RETENTION ADOPTION RECORD (routed
    /// concern, CLAUDE.md; the full seven parts are in
    /// docs/clock-guarded-retention.md) — mirrors `SessionStore::reap_expired`
    /// (session_store.cpp):
    ///  - Part 2/3 (persisted, sanitised clock reading): a `route_meta`
    ///    anchor (migration v2) + Postgres `now()` read ONCE in-SQL under a
    ///    dedicated advisory lock (`gateway_route_store:reap`) — the SAME
    ///    clock domain that authors `lease_until`/`updated_at`.
    ///  - Part 5 (unconditional cap): every accepted pass caps each of the
    ///    two sweeps independently.
    ///  - Part 6 (missing-anchor decision): **PROCEED** on the first pass —
    ///    `ResultSetStore`'s answer. A route is regenerable by the agent's
    ///    next heartbeat/`ProxyRegister`, so a from-boot skewed clock
    ///    reaping a batch of already-stale rows on the very first pass is an
    ///    acceptable worst case, never non-reproducible evidence loss.
    ///  - Part 1 (would-wipe probe) is DELIBERATELY CARVED OUT, the
    ///    `api_token_store`/`SessionStore` precedent: this table drains
    ///    toward "everything reapable" as ROUTINE behaviour (a fleet going
    ///    offline overnight legitimately expires every lease), so a
    ///    would-wipe verdict cannot separate a true positive from that
    ///    routine case.
    ///  - Part 4 (fact-set anomaly dedup) is ADOPTED, keyed on the TRIPLE
    ///    (declined `route_meta.reap_anchor_ms` value, anomaly DIRECTION,
    ///    `first_now_ms` — the reading the anomaly was first observed at)
    ///    (PR #4299 review, BLOCKER 1; direction-keyed since round-2 external
    ///    review; the `first_now_ms` reading-continuity window added round 4).
    ///    A forward- or backward-skew anomaly declines ONCE (persisting
    ///    `reap_declined_anchor_ms = "<reap_anchor_ms>:<direction>:<first_now_ms>"`)
    ///    and RECOVERS only when the SAME (anchor, direction) anomaly has
    ///    PERSISTED a real-time-plausible interval — `delta = now_ms -
    ///    first_now_ms` in `[kMinReapRecoveryGapMs, kMaxReapRecoveryGapMs]`
    ///    (270s..1h). Below the floor it re-declines PRESERVING the original
    ///    `first_now_ms` (an ε-later repeat, e.g. a second replica ticking a
    ///    few seconds offset, must NOT recover with no persistence evidence —
    ///    the FLOOR is load-bearing for the multi-replica future). Above the
    ///    ceiling, or on a negative delta (a further-backward step), it is a
    ///    NEW distinct anomaly — re-declined once against the CURRENT reading,
    ///    never a free recovery on a stale marker. A DIFFERENT-direction
    ///    anomaly at the SAME frozen anchor is likewise not the same anomaly
    ///    repeating — it re-declines and re-arms against the new direction,
    ///    since recovering it would run the sweeps against a mis-classified
    ///    `now_ms`. Without the decline-once/drain-on-repeat mechanism at all,
    ///    a routine >24h gap (weekend shutdown, DR failover, extended
    ///    maintenance) wedged the guard PERMANENTLY — `now - anchor` only grows
    ///    while declined, so every later pass declined forever with no recovery
    ///    path. Note the floor/ceiling correction to the old "oscillates every
    ///    other pass" narrative: a clock stepping backward every pass, or
    ///    forward by more than the ceiling every pass, now DECLINES every pass
    ///    and never recovers until it stops — stricter and correct, observable
    ///    via `outcome="declined"`. An OPERATOR can force recovery early by
    ///    resetting `route_meta.reap_anchor_ms` (see the operator re-anchor
    ///    comment at the anomaly-detection site in `gateway_route_store.cpp`).
    ///    Every decline is `spdlog::warn`'d AND counted —
    ///    `yuzu_server_gateway_route_reap_total{outcome="declined"}`
    ///    (incremented at the server.cpp reap call site). A failed pass
    ///    (store/query error, distinct from a declined one) is counted the
    ///    same way under `outcome="error"`; a clean, ordinary accepted pass
    ///    is `outcome="ok"` (or `outcome="ok_capped"` when it hit `kReapCap`
    ///    and a same-txn `EXISTS` probe confirmed a remaining backlog —
    ///    `ReapRoutesResult::cap_bound`, PR #4299 round 4, observability-only,
    ///    NOT acceleration); a pass that ran via this recovery branch (this
    ///    method's `ReapRoutesResult::recovered`) is its own
    ///    `outcome="recovered"` (PR #4299 round-2 review) — worth
    ///    distinguishing since a recovery pass can drain a large backlog in
    ///    one go, unlike a routine `ok` pass.
    /// SINGLE-WRITER today (advisory lock scoped to one dedicated key); becomes
    /// PG-shared-state under the same ADR-0012 lock when a 2nd replica lands
    /// (matches every other reaper in the register).
    [[nodiscard]] std::expected<ReapRoutesResult, GatewayRouteStoreError>
    reap_stale_routes();

    /// The schema migrations for this store (version 4: v1 the `agent_routes`
    /// table, v2 the `route_meta` reaper-anchor table, v3 the nullable
    /// `stream_home_id` column — SLICE #4324, v4 the nullable
    /// `home_cluster_id` column — #4669). Exposed for tests and the migration
    /// ladder.
    static const std::vector<pg::PgMigration>& migrations();

private:
    pg::PgPool& pool_;
    bool open_{false};
};

} // namespace yuzu::server
