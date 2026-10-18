%%%-------------------------------------------------------------------
%%% @doc gRPC client to the C++ yuzu-server (control plane).
%%%
%%% Proxies Register, Inventory, and stream status notifications
%%% to the upstream server.
%%%
%%% Proxied calls (ProxyRegister, ProxyInventory; #5695):
%%%   They do not run in this process. proxy_register/2 and proxy_inventory/2
%%%   run the RPC in the CALLING process (the gRPC request's own runner), after
%%%   a permit from yuzu_gw_upstream_regulator (bounded pools, a bounded wait
%%%   queue, each waiter with its own deadline; see that module for the numbers
%%%   and why), so one slow call no longer holds up every other one and a
%%%   caller that gave up makes no call. The caller reads the breaker state from
%%%   the lock-free cell before it asks and again after it is granted, sends the
%%%   upstream deadline as grpc-timeout (what is left of its own deadline, at
%%%   most upstream_rpc_timeout_ms), and hands the result to this process by
%%%   cast ({rpc_result, Gen, Result}), tagged with the breaker generation it
%%%   read: this process owns the breaker and moves it only for a result of the
%%%   current generation, never while open. In half_open every proxied call may
%%%   go (as before); the first result decides.
%%%   A call gun refuses locally with too_many_streams (the connection is at
%%%   the server's SETTINGS_MAX_CONCURRENT_STREAMS, RFC 9113 5.1.2; nothing was
%%%   sent) is local backpressure, not a failure of the upstream: the result is
%%%   not cast, the permit is handed back, and after a short pause (10 ms,
%%%   doubling to 100 ms) the caller asks for a permit again, waiting in the
%%%   regulator's queue, until its deadline (answered `deadline', so
%%%   UNAVAILABLE). Registration replays do the same. The regulator sizes the
%%%   permits from the limit the server declared (see
%%%   yuzu_gw_upstream_regulator), so this happens only when a lowered limit
%%%   races a grant, or when the other lanes need more than the server allows.
%%%   The other lanes (stream-status notifications, Guardian forwards, the
%%%   heartbeat flush) have no permit queue to wait in: for them it is a failed
%%%   send like any other, and a notification's counts against the breaker
%%%   (which is what stops its retries). Their 61 streams are kept out of the
%%%   permits (reserved_streams/0), so they meet the limit only when the server
%%%   allows fewer than that, which the regulator logs as a warning.
%%%
%%% Stream status notifications are held, not dropped (#4632):
%%%   A notification is stored in a bounded pending store
%%%   (yuzu_gw_notify_queue) and a drain step sends held entries first in first
%%%   out, at most ?MAX_NOTIFY_INFLIGHT (10) at a time, each on its own
%%%   monitored worker so the gen_server never blocks on one. Entries are held,
%%%   not dropped, while the in-flight limit is reached and while the circuit
%%%   breaker is open or half_open. The store key is {AgentId, SessionId,
%%%   StreamHomeId}: a newer event for a held key replaces the held one (it
%%%   keeps its place in the queue; counted as notify_coalesced; the one
%%%   exception is the key of a half_open probe in flight, which is no longer
%%%   held: a newer event for it is held at the tail of the queue), so a
%%%   CONNECTED followed by a DISCONNECTED for one session sends only the
%%%   DISCONNECTED, while two sessions of one agent are both kept. The cap
%%%   notify_pending_max counts keys, not agents (default: three per connection
%%%   the agent listeners admit, at least 15,000; see
%%%   default_notify_pending_max/0), and every send in flight still counts
%%%   toward it (its event comes back if the send fails; a new key is admitted
%%%   only while the held keys plus the sends in flight stay below the cap). When
%%%   full (#5695): a DISCONNECTED evicts the oldest held CONNECTED (counted
%%%   notify_lost{connected,evicted}), and a lost CONNECTED (evicted, or refused
%%%   at a full store) arms a full registration replay that runs once the breaker
%%%   is closed and the store has drained below half, so every agent re-sends
%%%   its CONNECTED (the heartbeat verdict does NOT put a lost CONNECTED right:
%%%   the server already knows the session, so it never lists it as unknown); a
%%%   DISCONNECTED over a store full of DISCONNECTED is lost (the server keeps
%%%   that session until the agent registers again), counted as
%%%   notify_lost{disconnected,at_capacity} and in notify_dropped. A send that
%%%   fails is held again at the head and retried (notify_requeued), in any
%%%   breaker state; while closed each failure counts against the breaker, so a
%%%   failing server gets at most the threshold of retries before it opens. A
%%%   request fault or encode failure is retired (notify_lost rejected), a
%%%   worker that dies without a result is lost (crashed). An event whose key
%%%   has a send in flight waits for it (head of line), so two events of one key
%%%   never reach the server out of order.
%%%   The store is volatile: it is lost when this process stops or restarts.
%%%   The cap bounds the retained keys only; it is not a memory ceiling.
%%%   The half_open probe has a deadline owned by this process,
%%%   notify_probe_timeout_ms (default 15000, valid 100 to 300000): a probe worker
%%%   that has not reported by then is killed and the probe fails like any failed
%%%   probe (the event is given back, the breaker reopens with the longer backoff,
%%%   the next half_open cycle sends a new probe). The vendored client's own
%%%   bounds (connect, handshake, response) are library defaults an endpoint
%%%   setting can remove; this deadline does not depend on them. It covers the
%%%   probe only; a proxied call is bounded by its caller's deadline and a
%%%   replay by upstream_rpc_timeout_ms.
%%%
%%% Standing invariant (#4632): the head held notification is the breaker probe.
%%%   A notification that fails deterministically for its own payload would block
%%%   the whole queue: it fails every probe, the breaker reopens with a longer
%%%   backoff, and it goes back to the head. So every payload field an agent
%%%   controls must be made safe at admission (yuzu_gw_peer_addr, applied in the
%%%   notify_stream_status cast handler and where the Register call reads the
%%%   :authority header). The peer address is the only such field the gateway
%%%   sanitises: the agent id is bounded (1 to 256 bytes) at the gateway edge by
%%%   yuzu_gw_agent_service:register/2 with the same condition the server applies,
%%%   the session id is minted by the server, the rest is gateway
%%%   configuration (cluster_id is converted to UTF-8 at boot).
%%%   The general rule behind it: a LOCAL encode exception (the request could not
%%%   be encoded, so it never left the gateway) says nothing about the upstream,
%%%   so it never feeds the circuit breaker, as neither a success nor a failure.
%%%   do_rpc returns it as {local_error, {Class, Why}}, a shape no server answer
%%%   can take. A held notification that is the probe and fails that way can
%%%   never encode, so it is evicted with a warning (not requeued) and the next
%%%   head is probed at once; every other failure still requeues it.
%%%   The same rule covers a server ANSWER that is about the request, not about
%%%   the upstream (INVALID_ARGUMENT, NOT_FOUND, ALREADY_EXISTS,
%%%   FAILED_PRECONDITION, OUT_OF_RANGE: the gRPC statuses for a wrong request;
%%%   the server returns the first and the fourth on these RPCs today): on a
%%%   live call it neither fails nor recovers the breaker, because counting it
%%%   as a failure would open the breaker on a request that says nothing about
%%%   the upstream, and counting it as a recovery would reset real failures. A
%%%   probe answered that way is retired, not requeued (requeueing would be
%%%   answered the same way by every probe, for ever). The one exception is a registration REPLAY answered
%%%   FAILED_PRECONDITION: that is the server's authoritative answer that the
%%%   presented session was superseded, and do_replay_one counts it as a breaker
%%%   SUCCESS (record_result({ok, superseded}, State)), so a run of
%%%   stale replays after a reconnect storm cannot trip the breaker. A replay
%%%   answered with any other request-fault status stays neutral.
%%%   Every other status still counts as a failure: UNAVAILABLE, INTERNAL,
%%%   DEADLINE_EXCEEDED, UNKNOWN, PERMISSION_DENIED, UNAUTHENTICATED,
%%%   RESOURCE_EXHAUSTED (a server out of memory answers it), CANCELLED,
%%%   UNIMPLEMENTED, ABORTED and DATA_LOSS, and so does every transport error,
%%%   HTTP-level error and exception out of the client. A request over the
%%%   server's 4 MiB receive limit is refused here as a local encode failure
%%%   (never sent), instead of being answered RESOURCE_EXHAUSTED by the server.
%%%
%%% The half_open probe (#4632):
%%%   Held entries are not sent while the breaker is open. When it goes half_open
%%%   (and when work first arrives while it is half_open) the HEAD held entry is
%%%   sent as the probe (when nothing is held, a due resend of a notice the
%%%   server refused, see NOTIFY-ACK below), and the breaker is driven by its
%%%   result. Without it a
%%%   held entry could wait forever after the server recovered: a disconnected
%%%   session sends no heartbeat, and a known session needs no verdict. Only one
%%%   probe is out at a time, it counts in the ten worker budget, and while the
%%%   breaker is half_open nothing else drains while it is out (if a call path RPC
%%%   closes the breaker meanwhile, the closed drain runs as usual). The probe
%%%   worker sends its result to this process before it exits; the result
%%%   carries the breaker generation (cb_gen, bumped on every entry into
%%%   half_open) it was sent under.
%%%     - The event is retired on ok. On error it goes back to the head of the
%%%       store, unless a newer event for the same key was held meanwhile: that
%%%       one wins and the old one is dropped (counted as notify_coalesced). One
%%%       slot is held back from the cap while a probe is out, so that the
%%%       give-back always fits. On a local encode exception the event is evicted instead (a
%%%       warning names the agent and the reason), it is neither retired as sent
%%%       nor given back, and the breaker is not touched.
%%%     - The breaker is moved only when it is still half_open under the SAME
%%%       generation: ok closes it (nothing is replayed), error reopens it with
%%%       doubled backoff (a local encode exception does neither). In any other
%%%       state or generation the result does not
%%%       touch the breaker (a call path RPC may have closed or reopened it
%%%       meanwhile; a breaker that is open has no on_success or on_failure).
%%%     - A probe worker that dies without a result is an error (worker_down),
%%%       once: the record is cleared by whichever of result or 'DOWN' comes
%%%       first, and a result is always delivered before the 'DOWN' of its
%%%       sender.
%%%   Ordinary workers report too (notify_result): a result counts only
%%%   while the breaker is closed and in the generation the worker started
%%%   in; see the held-notice section above.
%%%
%%% Notices the server did not acknowledge (#5695, NOTIFY-ACK):
%%%   The server answers NotifyStreamStatus with gRPC OK and a StreamStatusAck;
%%%   `acknowledged = false' means it did NOT record the notice. The gateway
%%%   used to take every OK as delivered: a server that refused CONNECTED for a
%%%   minute left every agent that connected in that minute unknown to it for
%%%   good (the heartbeat verdict lists only sessions the server does not know,
%%%   and it knew these). Read from server/core/src/gateway_service_impl.cpp
%%%   (NotifyStreamStatus), every `false' answer and what it means (each logs a
%%%   WARN line on the server, quoted, and counts in
%%%   yuzu_server_gateway_route_desync_total under the reason named):
%%%     - CONNECTED, the route directory read failed and this replica holds no
%%%       matching local session ("CONNECTED for session ... refused -- the
%%%       directory read degraded and this replica holds no matching local
%%%       session", connected_unverified): TRANSIENT, the route store is
%%%       degraded; the same notice is accepted once it reads again.
%%%     - CONNECTED or DISCONNECTED, the session is in neither the directory nor
%%%       this replica's session map ("unknown session ... for agent ...",
%%%       unknown_session): DEFINITIVE for that session (a server that lost its
%%%       state, or never saw the registration). For a live CONNECTED the
%%%       heartbeat verdict names the session and the targeted replay
%%%       re-registers it, which re-announces under the same key.
%%%     - CONNECTED, the directory names another session ("... but the directory
%%%       names a different session -- rejecting") or the registry holds a newer
%%%       one ("... is no longer the currently-installed session -- rejecting the
%%%       publish"), stale_connected_session: DEFINITIVE, a newer registration
%%%       owns the agent, and this session normally ends at the gateway soon.
%%%     - CONNECTED, the session is bound to another cluster ("... claims
%%%       cluster_id ..., which differs from this agent's already-bound cluster
%%%       affinity -- REFUSING ...", cluster_affinity_violation): DEFINITIVE
%%%       until the configuration changes.
%%%     - an event that is neither (never sent by this gateway).
%%%   A failed directory WRITE (announce_connected) is answered true today
%%%   (fail-open); a server change in review (#5961) answers it UNAVAILABLE,
%%%   which this gateway retries as a failed send, and keeps `false' for a
%%%   definitive refusal of a session that is not placed. The answer carries no
%%%   reason, so every `false' is handled the same way: not delivered.
%%%   - The attempt settles as not delivered and the notice is kept, under its
%%%     key, in a retry set beside the pending store, to be sent again after a
%%%     backoff: decorrelated jitter, delay = min(Max, uniform(Base, 3 x the
%%%     previous delay)), Base notify_unacked_retry_base_ms (1000), Max
%%%     notify_unacked_retry_max_ms (60000). The first resend comes 1 to 3 s
%%%     after the refusal; the delay averages about 34 s at steady state
%%%     (simulated), so 5,000 refused keys cost about 150 resends a second.
%%%   - Neither a failure nor a success for the breaker (record_result/2): the
%%%     server answered, so it is not failing, and it recorded nothing, so this
%%%     is no proof of recovery. A refused half_open probe leaves the breaker
%%%     half_open and the next entry is probed. The generation fence on a
%%%     worker's result (Gate 8 #4) is unchanged.
%%%   - Latest wins: a newer event for the key cancels the resend (a
%%%     DISCONNECTED after a refused CONNECTED is sent, the CONNECTED never
%%%     again). A resend in flight is waited for (per-key order), and its
%%%     result is dropped.
%%%   - A restarted agent owner's notify_settled/4 waits for a resend of its key
%%%     in flight and cancels one still waiting (superseded) before it answers:
%%%     the owner presents the session to the server again next, and a resend
%%%     of the predecessor's refused DISCONNECTED must not follow that.
%%%   - A CONNECTED is resent only while this node still holds its session
%%%     (yuzu_gw_registry:lookup_local_session/1, read when the backoff ends;
%%%     a registry that is not running does not stop it). It has no time limit:
%%%     a live session the server does not record is the failure this exists
%%%     for, and the alert names it.
%%%   - Slow phase (a stopgap until the answer carries a refusal reason, #6059):
%%%     a refusal the server will repeat for as long as the session lives
%%%     (stale_connected_session, cluster_affinity_violation) looks the same as
%%%     a transient one. So once a CONNECTED has been refused
%%%     notify_unacked_slow_after (10) times in a row, each next resend comes
%%%     0.8 to 1 x notify_unacked_slow_max_ms (600000) later: a fixed interval
%%%     jittered down by up to 20%, not decorrelated jitter: its floor stays the
%%%     base (1 s), so even with a 600 s cap a third of its draws fall below the
%%%     cap, anywhere down to 1 s, and it needs several more refusals to climb
%%%     from the ~34 s it was at. At the defaults 5,000 slowed keys cost about 9
%%%     resends a second instead of 150. The count lives in the entry: an
%%%     acknowledgement, a newer event for the key or the end of the session
%%%     removes the entry, and with it the count. A DISCONNECTED is never
%%%     slowed: its window bounds it already, and a slow delay would push its
%%%     last resend past the window. Counted in
%%%     yuzu_gw_upstream_notify_unacked_slow_keys (entries in the slow phase).
%%%   - A DISCONNECTED is resent for at most notify_unacked_disconnected_window_ms
%%%     (120000) after its first refusal, then counted lost (unacknowledged).
%%%     The only `false' a DISCONNECTED gets is unknown_session: harmless when
%%%     the server never knew the session or already removed it; otherwise (a
%%%     replica that could not read the directory) the route row it would have
%%%     removed stops being routable when its 90 s lease runs out, so a resend
%%%     after that changes nothing.
%%%   - Bounded: resends take at most ?MAX_UNACKED_INFLIGHT (5) of the ten
%%%     notify slots, and the pending store is drained first on every pass, so
%%%     a fresh CONNECTED or DISCONNECTED always has at least five slots and
%%%     the first one free. One entry per key; at most notify_pending_max
%%%     entries (a refusal past that is lost, unacknowledged). When nothing is
%%%     held, a due resend is the half_open probe. A resend that fails (a
%%%     transport error) is given back to the pending store like any failed send.
%%%   - Planned stop: when the last gasp begins, a refused CONNECTED still
%%%     waiting is dropped (lost, shutdown: the session ends with the stop) and
%%%     a refused DISCONNECTED still waiting goes to the head of the pending
%%%     store and is sent; a refusal during the last gasp is not resent (lost,
%%%     unacknowledged).
%%%   - Counted in yuzu_gw_upstream_notify_unacknowledged_total{event} (every
%%%     `false'), yuzu_gw_upstream_notify_unacked_keys (entries waiting) and
%%%     yuzu_gw_upstream_notify_unacked_ended_total{outcome}; a WARN (at most one
%%%     a second, warn_limited notify_unacknowledged) names the agent. The retry
%%%     set is volatile, like the pending store.
%%%
%%% Includes a circuit breaker to prevent cascading failures when the
%%% upstream server is unreachable. States:
%%%   closed    — RPCs pass through; consecutive failures tracked
%%%   open      — RPCs fail immediately with {error, circuit_open}
%%%   half_open — one probe RPC allowed; success closes, failure reopens
%%%               (a call path RPC, or one held notification as the probe)
%%%
%%% A lost connection is one failure (#5695):
%%%   The proxied calls, notification sends and replays run with the client's
%%%   `report_conn' option, so a call that ended because its CONNECTION closed or
%%%   went away comes back as {error, {connection_lost, Conn}} (see
%%%   yuzu_grpc_client). The breaker counts the first such result for a
%%%   connection as one failure and ignores the rest (cb_lost_conns): one dropped
%%%   connection with 50 calls on it used to be 50 failures, which opened the
%%%   breaker against a server that was up and answering on the next connection.
%%%   A server that keeps dropping connections still opens it: every connection
%%%   it drops is a failure, and while the channel backs off between redials the
%%%   calls that find no connection fail one by one.
%%%
%%% Registration replay: what the server says it does not know (#5695):
%%%   A breaker recovery replays nothing by itself. It used to: on the
%%%   half_open -> closed transition, and on any success after a failure while
%%%   closed, every agent the registry held was re-proxied, in case the server
%%%   was a fresh instance with an empty registry. That replayed the whole fleet
%%%   to a server that had lost nothing whenever one connection dropped (5,000
%%%   agents and 5,000 repeated CONNECTED notices for one reset connection), and
%%%   a failure during that replay opened the breaker again and started over.
%%%   The server tells the gateway what it does not know: every BatchHeartbeat
%%%   answer lists the sessions of the batch it does not hold
%%%   (unknown_session_ids, typically right after a server restart), and those
%%%   are replayed (the targeted replay below). A full replay of every agent this
%%%   node holds runs only on evidence that the server lost its state:
%%%     - a heartbeat verdict that lists at least half of its batch as unknown,
%%%       and at least the evidence floor (verdict_floor/1: one session per 64
%%%       this node holds, at least 1, at most 16), or that the server marked
%%%       truncated (more than 4096 unknown);
%%%     - and no full replay ended in the last ?FULL_REPLAY_COOLDOWN_MS (60 s),
%%%       so a server that keeps answering "unknown" costs at most one full
%%%       replay a minute on top of the targeted replays;
%%%   counted as registration_replay_triggered{trigger="server_lost_state"}. A
%%%   lost CONNECTED notification also starts one (notify_loss, below), and so
%%%   does the replay_registrations cast (trigger="manual"; nothing in the
%%%   gateway sends it). The full replay:
%%%     - after a start jitter (registration_replay_start_jitter_ms), the
%%%       registry's agents table is walked in chunks of ?REPLAY_CHUNK
%%%       {AgentId, SessionId} pairs (ets:select/3, the table safe_fixtable'd
%%%       while walking): no copy of the fleet's requests in this process;
%%%     - each entry is replayed by its own monitored worker, which waits for
%%%       a `replay' permit (at most upstream_replay_concurrency of the register
%%%       pool, so live registrations keep the rest and are served first),
%%%       re-verifies the agent and reads its stored request when it runs;
%%%     - at most replay_limit workers at once (one while half_open: the
%%%       probe), and only while the held notifications plus the replays in
%%%       flight stay under half of notify_pending_max (every adopted replay
%%%       makes the agent re-send its CONNECTED);
%%%     - the breaker opening aborts the rest; the next verdict that shows
%%%       the server still does not know the sessions starts again.
%%%   Rate = replay_limit / server latency: 5,000 agents at 24 in flight and
%%%   50 ms per call take about 10 s.
%%%
%%% Targeted replay on a heartbeat verdict (#1197):
%%%   The server answers every BatchHeartbeat with the sessions it does not
%%%   know. yuzu_gw_heartbeat_buffer casts those ids to replay_sessions/1,
%%%   which queues exactly the ones this node still holds onto the same replay
%%%   (ahead of a full walk's remaining chunks).
%%%   One pending entry per agent, a guard window against replaying a session
%%%   again right after it was replayed, and a queue cap bound the work a
%%%   verdict can create. A verdict that arrives while the breaker is open is
%%%   dropped and counted (a later heartbeat lists the sessions again); one
%%%   that arrives half_open is queued, and its first replay RPC is the probe.
%%%   After a server restart every agent is listed within one heartbeat
%%%   interval (each agent's next heartbeat), and the first verdict already
%%%   shows the evidence that starts a full replay, so everyone is replayed
%%%   within about a second of the first flush that reaches the new server.
%%%
%%% Configuration (sys.config / application env):
%%%   circuit_breaker_failure_threshold   - consecutive failures to trip
%%%                                          (default 5, valid 1..1000)
%%%   circuit_breaker_reset_timeout_ms    - initial open duration
%%%                                          (default 10000, valid 100..3600000)
%%%   circuit_breaker_max_reset_timeout_ms - max backoff cap
%%%                                          (default 30000, valid 100..3600000;
%%%                                          raised to the initial duration when
%%%                                          it is below it, with a warning)
%%%   registration_replay_start_jitter_ms - most random delay before a full
%%%                                          replay starts (default 1000, valid
%%%                                          0..60000). registration_replay_spacing_ms
%%%                                          is no longer read (the drip it paced
%%%                                          is gone)
%%%   upstream_call_timeout_ms            - a proxied call's budget when its
%%%                                          caller gives no deadline (default
%%%                                          30000, valid 100..300000)
%%%   upstream_rpc_timeout_ms             - longest one proxied call or replay
%%%                                          may take (default 5000, valid
%%%                                          100..60000)
%%%   upstream_{register,replay,inventory}_concurrency,
%%%   upstream_{register,inventory}_queue_max - permits and wait queues, see
%%%                                          yuzu_gw_upstream_regulator
%%%   registration_replay_session_guard_ms - how long a replayed session is not
%%%                                          queued again by a verdict
%%%                                          (default 10000, valid 0..3600000)
%%%   registration_replay_queue_max       - most agents the replay queue holds
%%%                                          (default 10000, valid 1..1000000)
%%%   notify_pending_max                  - most stream-status notification keys
%%%                                          held while they cannot be sent
%%%                                          (default 10000, valid 1..1000000)
%%%   notify_unacked_retry_base_ms        - first backoff of a notice the server
%%%                                          refused (default 1000, valid 10..60000)
%%%   notify_unacked_retry_max_ms         - longest backoff (default 60000, valid
%%%                                          100..3600000, raised to the base)
%%%   notify_unacked_disconnected_window_ms - how long a refused DISCONNECTED is
%%%                                          resent (default 120000, valid 0..3600000)
%%%   notify_unacked_slow_after           - consecutive refusals of a CONNECTED
%%%                                          after which it is resent at the slow
%%%                                          interval (default 10, valid 1..10000)
%%%   notify_unacked_slow_max_ms          - the slow interval: each slowed resend
%%%                                          comes 0.8 to 1 x this later (default
%%%                                          600000, valid 100..3600000, raised to
%%%                                          notify_unacked_retry_max_ms)
%%   cluster_id                         — this gateway's trust-zone/region id,
%%                                          stamped on every StreamStatusNotification
%%                                          (default <<"default">>; ADR-2002 §7)
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream).
-behaviour(gen_server).

-include("yuzu_grpc_client.hrl").

%% API
-export([start_link/0,
         proxy_register/1,
         proxy_register/2,
         proxy_inventory/1,
         proxy_inventory/2,
         notify_stream_status/5,
         notify_settled/4,
         reregister_session/3,
         forward_guardian_message/2,
         replay_sessions/1,
         replay_sessions/2,
         circuit_state/0]).
%% Planned stop (yuzu_gw_app:prep_stop/1, #5695).
-export([begin_stop/0, last_gasp/1]).
%% Read without a call into this process, so they answer while it is inside a
%% slow RPC: the breaker state for /readyz (yuzu_gw_health), the lane counts for
%% the pressure sampler (yuzu_gw_upstream_pressure).
-export([circuit_state_now/0, lane_snapshot/0]).
-export([classify_tls_error/1]).  %% for testing (R-3 TLS-error classifier)
-export([call_timeout/0]).        %% for testing (upstream_call_timeout_ms validation)
%% The streams the lanes other than the permit pools can hold open on the
%% upstream connections (read by yuzu_gw_upstream_regulator).
-export([reserved_streams/0]).
%% The reason/stacktrace redaction format_status/1 applies, shared with the
%% crash-report filter (yuzu_gw_crash_redact), which applies it to the parts of
%% a report OTP prints outside format_status.
-export([redact_reason/1, redact_why/1, redact_stack/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3,
         format_status/1]).

-define(SERVER, ?MODULE).
-define(MAX_NOTIFY_INFLIGHT, 10).
%% Dedicated in-flight cap for Guardian drift-event forwards, separate from
%% MAX_NOTIFY_INFLIGHT so a drift storm can't starve stream-status notifies
%% and vice-versa. Larger than notify because drift events carry enforcement
%% evidence; still bounded (NFR — no unbounded process spawn under a slow
%% upstream). Overflow is dropped best-effort; durable buffering is Guardian A3.
-define(MAX_GUARDIAN_INFLIGHT, 50).
%% yuzu_gw_heartbeat_buffer sends its BatchHeartbeat chunks one after another.
-define(HEARTBEAT_FLUSH_STREAMS, 1).
%% A proxied call gun refused locally (too_many_streams: the connection is at
%% the server's concurrent-stream limit) waits this long before it asks for a
%% permit again, doubling to the maximum: long enough for the channel to tell
%% the regulator of a lowered limit, short against a call's deadline.
-define(STREAM_LIMIT_PAUSE_MS, 10).
-define(STREAM_LIMIT_PAUSE_MAX_MS, 100).
-define(DEFAULT_CALL_TIMEOUT_MS, 30000).
-define(MIN_CALL_TIMEOUT_MS, 100).
-define(MAX_CALL_TIMEOUT_MS, 300000).
-define(DEFAULT_RPC_TIMEOUT_MS, 5000).
-define(MAX_RPC_TIMEOUT_MS, 60000).
%% Kept back from a caller's deadline for its answer to travel back to the agent,
%% so the upstream RPC always ends before the agent stops waiting.
-define(DEADLINE_MARGIN_MS, 200).
%% A proxied call with less than this left is not started (the server would
%% hardly answer in time, and the caller is about to give up).
-define(MIN_USEFUL_MS, 250).
-define(DEFAULT_CB_THRESHOLD, 5).
%% The valid range of circuit_breaker_failure_threshold: 0 would trip the breaker
%% on the first failure, and a value past 1000 is not a threshold.
-define(MIN_CB_THRESHOLD, 1).
-define(MAX_CB_THRESHOLD, 1000).
-define(DEFAULT_CB_RESET_MS, 10000).
%% The longest the breaker stays open before it probes again (#5695: was
%% 300000). The backoff doubles 10 s, 20 s, then stays at 30 s, so a server that
%% returns is used again within about 30 s, and a down server is probed twice a
%% minute: one held notification or proxied call each time, nothing a server
%% cannot absorb. YuzuGatewayUpstreamCircuitOpened relies on reopens at least
%% this often (its 5-minute window).
-define(DEFAULT_CB_MAX_RESET_MS, 30000).
%% The valid range of both circuit_breaker_*reset_timeout_ms keys (100 ms to 1 h).
%% The floor keeps the half_open probe from becoming a ~1 kHz loop (a 1 ms base
%% or cap reopens and re-probes every millisecond).
-define(MIN_CB_TIMEOUT_MS, 100).
-define(MAX_CB_TIMEOUT_MS, 3600000).
%% A full replay (after the upstream recovered) starts after a uniform random
%% delay of 0 to registration_replay_start_jitter_ms, so the gateways that saw
%% the same server come back do not all start their replays in the same
%% instant. 1 s spreads ten gateways' first permits (10 x 24 ProxyRegister) over
%% a second; it is small next to the replay itself (5,000 agents at 24 in
%% flight and 50 ms per call is about 10 s). Valid 0 to 60000.
-define(DEFAULT_REPLAY_JITTER_MS, 1000).
-define(MAX_REPLAY_JITTER_MS, 60000).
%% Rows read from the registry's agents table per step of a full walk: the
%% upstream's heap holds at most this many {AgentId, SessionId} pairs at once.
-define(REPLAY_CHUNK, 500).
%% The registry's agents table (yuzu_gw_registry ?TABLE, named, public). A full
%% replay walks it in chunks with ets:select/3; see walk_chunk/1 for the two
%% columns it reads.
-define(AGENTS_TABLE, yuzu_gw_agents).
%% The longest a replay worker waits for a permit. Live registrations are
%% served first, so a replay can wait while a storm of them holds the pool.
-define(REPLAY_PERMIT_WAIT_MS, 60000).
-define(DEFAULT_REPLAY_SESSION_GUARD_MS, 10000).
-define(MAX_REPLAY_SESSION_GUARD_MS, 3600000).
-define(DEFAULT_REPLAY_QUEUE_MAX, 10000).
-define(MAX_REPLAY_QUEUE_MAX, 1000000).
%% The floor of the derived default (default_notify_pending_max/0).
-define(MIN_DEFAULT_NOTIFY_PENDING_MAX, 15000).
%% How often the held-notification high-water mark is rotated.
-define(NOTIFY_HWM_TICK_MS, 60000).
%% Notify sends in flight during a planned stop's last gasp. Proxied calls are
%% refused by then, so the 56 permit streams are free: 64 notify + 50 Guardian
%% + 1 heartbeat flush = 115 stay under 128 streams per connection, the C++
%% server's DEFAULT (its --grpc-max-concurrent-streams; see
%% yuzu_gw_upstream_regulator). A server run with a lower limit declares it in
%% its HTTP/2 SETTINGS, and gun then refuses the last-gasp sends past it
%% locally (too_many_streams): the last gasp does not retry, so each such
%% notification is counted lost (notify_lost{reason="shutdown"}), like any
%% other failed last-gasp send.
-define(STOP_NOTIFY_INFLIGHT, 64).
-define(MAX_NOTIFY_PENDING_MAX, 1000000).
%% The deadline the gateway itself puts on a half_open notify probe (#4632): after
%% this long without a result the probe worker is killed and the probe fails like
%% any other failed probe. The default is of the order of the vendored client's own
%% bounds for one call (connect 5 s, handshake 4.5 s, response 5 s, which the
%% gateway does not control); 100 ms to 5 min is the range of the sibling
%% upstream_call_timeout_ms.
-define(DEFAULT_NOTIFY_PROBE_TIMEOUT_MS, 15000).
-define(MIN_NOTIFY_PROBE_TIMEOUT_MS, 100).
-define(MAX_NOTIFY_PROBE_TIMEOUT_MS, 300000).
%% Most session ids one replay_sessions cast may name. The same bound as
%% ?MAX_VERDICT_IDS in yuzu_gw_heartbeat_buffer, which applies it before the
%% cast; keep the two equal.
-define(MAX_REPLAY_SESSION_IDS, 4096).
%% After a full replay ends, a verdict does not start another one for this long
%% (the targeted replay still runs): a server that keeps listing sessions as
%% unknown after they were replayed costs at most one full replay a minute.
-define(FULL_REPLAY_COOLDOWN_MS, 60000).
%% The connections the breaker has counted as lost (one failure each), newest
%% first. A lost connection's calls all end within one RPC timeout of the loss,
%% and the channel has a handful of connections, so a short list is enough.
-define(MAX_LOST_CONNS, 16).
%% NOTIFY-ACK (#5695): notices the server answered acknowledged=false (see
%% "Notices the server did not acknowledge" in the module doc). The backoff is
%% decorrelated jitter, delay = min(Max, uniform(Base, 3 x the previous delay)):
%% Base 1 s, so the first resend comes 1 to 3 s after the refusal (a degraded
%% route store usually recovers within seconds); Max 60 s, so a server that
%% starts accepting again has every refused notice within about a minute, and
%% 5,000 refused keys cost about 150 resends a second at steady state (the mean
%% delay is about 34 s, simulated). Base 10 ms to 60 s, Max 100 ms to 1 h
%% (raised to Base when below it).
-define(DEFAULT_UNACKED_BASE_MS, 1000).
-define(MIN_UNACKED_BASE_MS, 10).
-define(MAX_UNACKED_BASE_MS, 60000).
-define(DEFAULT_UNACKED_MAX_MS, 60000).
-define(MIN_UNACKED_MAX_MS, 100).
-define(MAX_UNACKED_MAX_MS, 3600000).
%% How long a refused DISCONNECTED is resent after its first refusal: past the
%% server's 90 s route lease (kGatewayRouteLeaseTtlSecs) the row a missed
%% DISCONNECTED would have removed is no longer routable anyway, so a resend
%% changes nothing. 0 (never resent) to 1 h.
-define(DEFAULT_UNACKED_DISC_WINDOW_MS, 120000).
-define(MAX_UNACKED_DISC_WINDOW_MS, 3600000).
%% The slow phase (stopgap until the refusal carries a reason, #6059): after
%% this many consecutive refusals a CONNECTED is resent every 0.8 to 1 x the
%% slow max. 10 refusals take about 2 minutes at the default backoff (median
%% 100 s, 33 s to 260 s for 80% of keys, simulated): longer than a degraded route
%% store usually lasts, at the cost that one unreadable for longer leaves its
%% sessions waiting up to the slow max after it recovers. 1 to 10000 refusals
%% (10000 is several days of resends at the normal backoff: in effect never).
%% The slow max is 100 ms to 1 h like the max, and raised to the max when below
%% it.
-define(DEFAULT_UNACKED_SLOW_AFTER, 10).
-define(MAX_UNACKED_SLOW_AFTER, 10000).
-define(DEFAULT_UNACKED_SLOW_MAX_MS, 600000).
-define(MIN_UNACKED_SLOW_MAX_MS, 100).
-define(MAX_UNACKED_SLOW_MAX_MS, 3600000).
%% The most resends in flight at once: half the notify lane, so fresh notices
%% always have the other half (and are drained first on every pass).
-define(MAX_UNACKED_INFLIGHT, (?MAX_NOTIFY_INFLIGHT div 2)).

%% The lock-free cell: an `atomics' array behind a persistent_term, written only
%% by this process and read by anyone. It exists because everything else this
%% process knows is behind its mailbox, and a mailbox read waits for the RPC in
%% progress; the two readers (the readiness probe and the pressure sampler) must
%% answer exactly when that RPC is slow.
%%   (slot 1) unused: it was IN_RPC, when this process made RPCs itself. It
%%             makes none now (proxied calls run in the caller, replays and
%%             notifications in workers); kept so the slot numbers stay.
%%   NOTIFY    stream-status notifications in flight (of MAX_NOTIFY_INFLIGHT)
%%   GUARDIAN  Guardian forwards in flight (of MAX_GUARDIAN_INFLIGHT)
%%   CB        the breaker state (CB_CLOSED, CB_OPEN, CB_HALF_OPEN), published by
%%             publish_breaker/1 wherever cb_state is assigned: init/1, the
%%             circuit_half_open timer, on_success/1 from half_open and
%%             trip_circuit/1. A new assignment of cb_state must publish too.
%%   NOTIFY_LIMIT  the notify slots drain/1 may fill now: MAX_NOTIFY_INFLIGHT
%%             (a replay no longer holds one back: it does not wait on notify
%%             slots).
%%   CB_GEN    cb_gen, the breaker generation (bumped on every entry into
%%             half_open), published with it by publish_breaker/2. A proxied
%%             call reads it before its RPC and hands it back with the result,
%%             so a result from before the breaker last moved is ignored.
%%   STOPPING  1 from begin_stop/0 on (a planned stop): proxied calls are
%%             refused with `stopping' instead of asking for a permit.
-define(CELL, {?MODULE, cell}).
-define(CELL_SLOTS, 7).
-define(CELL_IN_RPC, 1).
-define(CELL_NOTIFY, 2).
-define(CELL_GUARDIAN, 3).
-define(CELL_CB, 4).
-define(CELL_NOTIFY_LIMIT, 5).
-define(CELL_CB_GEN, 6).
-define(CELL_STOPPING, 7).
-define(CB_CLOSED, 0).
-define(CB_OPEN, 1).
-define(CB_HALF_OPEN, 2).

%% CC-03 wire-capability handshake (proto/yuzu/gateway/v1/gateway.proto,
%% StreamStatusNotification.wire_capabilities): the literal this gateway
%% build advertises to prove its vendored agent.proto carries
%% CommandRequest.dispatch_tag = 9 and forwards it untouched. See
%% encode_command_request/1 in yuzu_gw_proto.erl for the forwarding half.
-define(WIRE_CAP_DISPATCH_TAG_V1, <<"command_dispatch_tag_v1">>).

%% The tag of the exception encode_request/2 raises: the request could not be
%% encoded in this process (see do_rpc/4).
-define(LOCAL_ENCODE_FAILED, yuzu_gw_local_encode_failed).

%% The largest request the server accepts: the receive limit of a stock gRPC
%% server (4 MiB; no SetMaxReceiveMessageSize override exists on the server). A
%% request over that bound can still arrive at this module, and the server would
%% answer RESOURCE_EXHAUSTED before its handler runs. That is a fact about the
%% request, so encode_request/2 refuses it here as a local encode failure, and
%% RESOURCE_EXHAUSTED stays a status that counts against the upstream (a server
%% out of memory or threads answers it too).
-define(MAX_REQUEST_BYTES, 4194304).

%% The statuses that say the request was wrong, not that the upstream is
%% unhealthy: INVALID_ARGUMENT (the server's agent id and enrollment field
%% checks) and FAILED_PRECONDITION (a superseded replay) are the two the server
%% returns on these RPCs today; NOT_FOUND, ALREADY_EXISTS and OUT_OF_RANGE are
%% the same class by the gRPC definition (the server never returns them here).
%% Such an answer proves nothing about the upstream, so on a live call it neither
%% fails nor recovers the breaker (see record_result/2); the one exception, a
%% replay answered FAILED_PRECONDITION, is a breaker success (do_replay_one).
%% Every other status counts.
-define(IS_REQUEST_FAULT(Status), (Status =:= ?GRPC_STATUS_BIN_INVALID_ARGUMENT orelse
                                   Status =:= ?GRPC_STATUS_BIN_NOT_FOUND orelse
                                   Status =:= ?GRPC_STATUS_BIN_ALREADY_EXISTS orelse
                                   Status =:= ?GRPC_STATUS_BIN_FAILED_PRECONDITION orelse
                                   Status =:= ?GRPC_STATUS_BIN_OUT_OF_RANGE)).

%% What do_rpc returns. A local_error is an exception raised by the request
%% encoder in this process: the request never left the gateway.
-type rpc_result() :: {ok, term()} | {error, term()} | {local_error, {atom(), term()}}.
%% What a notification worker reports: an rpc_result, with an OK answer of
%% acknowledged=false told apart as `unacknowledged' (ack_result/1): the
%% server answered but did not record the notice.
-type notify_result() :: rpc_result() | unacknowledged.

%% A notice the server answered acknowledged=false, held for a resend (NOTIFY-ACK).
%%   status  {waiting, TimerRef}  the backoff runs ({timeout, TimerRef,
%%                                {notify_unacked_due, Key}} ends it);
%%           ready                due, queued in notify_unacked_ready;
%%           inflight             a resend (or a send from the pending store) is
%%                                out, and its result decides;
%%           held                 a resend failed (a transport error) and was
%%                                given back to the pending store, which sends it.
%%   delay   the last backoff delay (ms), the next one is derived from it.
%%   first   when the server first refused this event (monotonic ms).
%%   refusals how many times in a row the server refused this event; a
%%           CONNECTED at notify_unacked_slow_after or more is in the slow phase.
-type unacked() :: #{event  := yuzu_gw_notify_queue:event(),
                     class  := connected | disconnected,
                     delay  := pos_integer(),
                     first  := integer(),
                     refusals := pos_integer(),
                     status := {waiting, reference()} | ready | inflight | held}.

%% {AgentId, SessionId, stored RegisterRequest | walk}. A verdict entry carries
%% the request it was resolved with; a walk entry carries `walk' and its worker
%% reads the request from the registry when it runs.
-type replay_entry() :: {binary(), binary() | undefined, map() | walk}.

-type notify_probe() :: #{pid   := pid(),
                          mref  := reference(),
                          %% The deadline timer: a {notify_probe_timeout, Pid, Gen}
                          %% message to this process, cancelled when the probe resolves.
                          timer := reference(),
                          gen   := non_neg_integer(),
                          key   := yuzu_gw_notify_queue:key(),
                          event := yuzu_gw_notify_queue:event()}.

-record(state, {
    %% Notify workers in flight: pid => the key, class and event it is sending
    %% (so a failure can give the event back) and the breaker generation it was
    %% started under (so its result counts toward the breaker only if the
    %% breaker has not moved since, Gate 8 #4), or `resolved' once its result
    %% is in (its slot is freed by its 'DOWN').
    notify_pids     :: #{pid() => {yuzu_gw_notify_queue:key(), connected | disconnected,
                                   yuzu_gw_notify_queue:event(), non_neg_integer()}
                                  | resolved},
    %% Stream-status notifications held until a worker slot is free and the
    %% breaker is closed. Volatile: it does not outlive this process.
    notify_pending  :: yuzu_gw_notify_queue:t(),
    notify_pending_max :: pos_integer(),
    %% The most keys held at once in the current and the previous minute
    %% (rotated by notify_hwm_tick), so the reported high-water mark covers any
    %% scrape interval up to a minute.
    notify_hwm_cur  = 0 :: non_neg_integer(),
    notify_hwm_prev = 0 :: non_neg_integer(),
    %% A CONNECTED notification was lost (evicted or refused at a full store):
    %% run a full registration replay once the breaker is closed and the store
    %% has drained below half, so every agent re-sends its CONNECTED.
    heal_replay     = false :: boolean(),
    %% Planned stop (#5695): running; stopping (begin_stop/0: proxied calls
    %% refused, no replay, the cap raised); flushing (last_gasp/1: every held
    %% notification is sent whatever the breaker, up to STOP_NOTIFY_INFLIGHT at
    %% once, until flush_deadline); flushed (what was left is counted, later
    %% notifications are counted, not sent).
    mode            = running :: running | stopping | flushing | flushed,
    flush_from      = undefined :: undefined | gen_server:from(),
    flush_deadline  = undefined :: undefined | integer(),
    flush_timer     = undefined :: undefined | reference(),
    flush_sent      = 0 :: non_neg_integer(),
    %% How long a half_open notify probe may run before it is killed (ms).
    notify_probe_timeout_ms :: pos_integer(),
    %% Circuit breaker state
    cb_state        :: closed | open | half_open,
    cb_failures     :: non_neg_integer(),
    cb_threshold    :: non_neg_integer(),
    cb_base_timeout :: non_neg_integer(),
    cb_max_timeout  :: non_neg_integer(),
    cb_cur_timeout  :: non_neg_integer(),
    cb_timer        :: reference() | undefined,
    %% The connections whose loss the breaker has counted (one failure each,
    %% however many calls ended with them), newest first, at most ?MAX_LOST_CONNS.
    cb_lost_conns   = [] :: [pid()],
    %% The number of times the breaker entered half_open, and the held
    %% notification currently sent as the half_open probe (its worker, monitor,
    %% the generation it was started under, and the store key and event it
    %% took out of the store so a failure can give it back). The event stays
    %% out of format_status.
    cb_gen          = 0 :: non_neg_integer(),
    notify_probe    = undefined :: undefined | notify_probe(),
    %% Registration replay. replay_queue holds the entries still to re-proxy:
    %% the ones a heartbeat verdict named (with their stored request) and the
    %% current chunk of a full walk of the registry (request `walk', read by
    %% the worker). replay_len is its length, kept as a counter so nothing on
    %% the path is O(n) per step.
    replay_queue    :: [replay_entry()],
    replay_len = 0  :: non_neg_integer(),
    %% The full walk of the registry's agents table a recovery starts: idle,
    %% pending (the start jitter timer runs), or walking (an ets:select/3
    %% continuation, `start' before the first chunk, and the rows still to
    %% walk as an estimate for the depth gauge). The table is safe_fixtable'd
    %% by this process while walking.
    replay_walk = idle :: idle | {pending, reference(), server_lost_state | notify_loss | manual} |
                          {walking, start | '$end_of_table' | term(), non_neg_integer()},
    %% Replay workers in flight: pid => {AgentId, SessionId}. At most
    %% replay_limit (one while the breaker is half_open: the probe).
    replay_pids = #{} :: #{pid() => {binary(), binary() | undefined}},
    replay_limit    :: pos_integer(),
    replay_jitter_ms :: non_neg_integer(),
    %% When the replay now running started (monotonic ms), for its duration.
    replay_started = undefined :: undefined | integer(),
    %% When the last full walk ended (monotonic ms): a verdict starts no other
    %% one within ?FULL_REPLAY_COOLDOWN_MS of it.
    full_replay_ended = undefined :: undefined | integer(),
    %% Sessions replayed within the last session_guard_ms (monotonic ms of the
    %% pop that replayed them). Stamped when a replay worker is started for the
    %% session and removed again if that worker sent nothing (never stamped when
    %% an entry is queued or skipped here), and pruned on every verdict and when
    %% a replay ends, so it is bounded by the sessions replayed within one
    %% guard window.
    recent_replays   = #{} :: #{binary() => integer()},
    session_guard_ms :: non_neg_integer(),
    replay_queue_max :: pos_integer(),
    %% Guardian drift-event forwards in flight (bounded by MAX_GUARDIAN_INFLIGHT)
    guardian_pids   :: #{pid() => true},
    %% HA WS-4 4.1 — the trust-zone/region cluster id this gateway belongs to
    %% (agents are pinned to one cluster, ADR-2002 §7). Stamped onto every
    %% StreamStatusNotification so the server's routing directory can record
    %% which cluster owns an agent's live stream. Read once at init; a
    %% pre-WS-4 build has no such config and the env default (<<"default">>)
    %% keeps a single-cluster deployment's id stable and non-empty.
    cluster_id      :: binary(),
    %% OWNER-RESTART (#5695): who waits for a key to settle, i.e. to have no
    %% event held and no send in flight (notify_settled/4). A restarted agent
    %% owner registers here after casting its predecessor's DISCONNECTED, and
    %% presents the session to the server again only once that notice is done,
    %% so the server never sees the DISCONNECTED after the re-registration.
    settle_waiters = #{} :: #{yuzu_gw_notify_queue:key() => [reference() | pid()]},
    %% NOTIFY-ACK (#5695): the retry set of notices the server answered
    %% acknowledged=false, by store key (at most one entry per key, at most
    %% notify_pending_max entries); the keys whose backoff ended, in order (an
    %% entry no longer `ready' is skipped when popped); the resend workers in
    %% flight (at most ?MAX_UNACKED_INFLIGHT); the keys whose resend in flight a
    %% newer event superseded (its result is dropped); the size last reported
    %% on the gauge; and the backoff settings.
    notify_unacked = #{} :: #{yuzu_gw_notify_queue:key() => unacked()},
    notify_unacked_ready = queue:new() :: queue:queue(yuzu_gw_notify_queue:key()),
    notify_unacked_pids = #{} :: #{pid() => yuzu_gw_notify_queue:key()},
    notify_unacked_cancelled = #{} :: #{yuzu_gw_notify_queue:key() => true},
    notify_unacked_reported = 0 :: non_neg_integer(),
    unacked_base_ms = ?DEFAULT_UNACKED_BASE_MS :: pos_integer(),
    unacked_max_ms = ?DEFAULT_UNACKED_MAX_MS :: pos_integer(),
    unacked_disc_window_ms = ?DEFAULT_UNACKED_DISC_WINDOW_MS :: non_neg_integer(),
    %% The slow phase (#6059 stopgap): its two settings, the entries in it
    %% (kept by slow_in/2 and slow_out/2 as entries enter and leave the retry
    %% set) and the last count reported.
    unacked_slow_after = ?DEFAULT_UNACKED_SLOW_AFTER :: pos_integer(),
    unacked_slow_max_ms = ?DEFAULT_UNACKED_SLOW_MAX_MS :: pos_integer(),
    notify_unacked_slow = 0 :: non_neg_integer(),
    notify_unacked_slow_reported = 0 :: non_neg_integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Forward a RegisterRequest to the C++ server, with the default caller
%% budget (upstream_call_timeout_ms). See proxy_register/2.
-spec proxy_register(map()) -> {ok, term()} | {error, term()}.
proxy_register(RegisterReq) ->
    proxy_register(RegisterReq, #{}).

%% @doc Forward a RegisterRequest to the C++ server. The `ok' payload is
%% whatever the gRPC client handed back: a RegisterResponse map, but a caller
%% must not assume it (an OK with no DATA frame is not a map).
%%
%% The RPC runs in the CALLING process (the gRPC request's own runner), never
%% inside this gen_server, under a `register' permit from
%% yuzu_gw_upstream_regulator; see "Proxied calls" in the module doc. Opts:
%%   deadline  monotonic ms by which the caller needs the answer (the agent's
%%             grpc-timeout); default now + upstream_call_timeout_ms.
%% Errors, besides the server's own answer:
%%   circuit_open          the breaker is open (no permit asked for)
%%   overloaded            the register wait queue is full
%%   deadline              the deadline passed while waiting for a permit, or
%%                         too little of it was left to make the call
%%   stopping              a planned stop is in progress
%%   upstream_unavailable  this process or the regulator is not running
%% Never exits the caller and never puts the request in an exit reason.
-spec proxy_register(map(), map()) -> {ok, term()} | {error, term()}.
proxy_register(RegisterReq, Opts) ->
    proxied_call('ProxyRegister', register, RegisterReq, Opts).

%% @doc Forward an InventoryReport to the C++ server; see proxy_inventory/2.
-spec proxy_inventory(map()) -> {ok, map()} | {error, term()}.
proxy_inventory(InventoryReport) ->
    proxy_inventory(InventoryReport, #{}).

%% @doc Forward an InventoryReport to the C++ server, under an `inventory'
%% permit, like proxy_register/2 (same options, same errors).
-spec proxy_inventory(map(), map()) -> {ok, map()} | {error, term()}.
proxy_inventory(InventoryReport, Opts) ->
    proxied_call('ProxyInventory', inventory, InventoryReport, Opts).

%% @doc Notify C++ server about agent stream connect/disconnect.
-spec notify_stream_status(binary(), binary() | undefined, connected | disconnected, binary(),
                            binary()) -> ok.
notify_stream_status(AgentId, SessionId, Event, PeerAddr, StreamHomeId) ->
    gen_server:cast(?SERVER, {notify_stream_status, AgentId, SessionId, Event, PeerAddr,
                               StreamHomeId}).

%% @doc Tell `Ack' (an alias or a pid) once the stream-status key {AgentId,
%% SessionId, StreamHomeId} has no event held and no send in flight: the
%% message is `{Ack, notify_settled}'. Cast after a notify_stream_status/5 from
%% the same process, it answers once that notice is retired (sent, or counted
%% lost); for a key with nothing pending it answers at once. A resend of a
%% refused notice (NOTIFY-ACK) in flight keeps the key unsettled; a refused
%% notice still waiting for its resend is cancelled (superseded) when it
%% answers, so nothing of the key is sent after it but what the caller sends
%% next (see release_settled/1). Nothing answers if
%% this process stops first: the caller bounds its own wait (OWNER-RESTART,
%% #5695; see yuzu_gw_agent's recovering state).
-spec notify_settled(binary(), binary() | undefined, binary(), reference() | pid()) -> ok.
notify_settled(AgentId, SessionId, StreamHomeId, Ack) ->
    gen_server:cast(?SERVER, {notify_settled,
                              {AgentId, ensure_binary(SessionId), StreamHomeId}, Ack}).

%% @doc Present an existing session to the server again: a ProxyRegister of the
%% stored RegisterRequest carrying SessionId as `x-yuzu-session-id', the same
%% request a registration replay makes (HA WS-4 4.4: the server adopts the
%% session if its directory still owns it or can reclaim it, and answers
%% FAILED_PRECONDITION when a different live session holds the agent). Used by
%% a restarted agent owner to re-establish its predecessor's session
%% (OWNER-RESTART, #5695). Runs in the calling process under a `register'
%% permit, with the options and errors of proxy_register/2.
-spec reregister_session(map(), binary(), map()) -> {ok, term()} | {error, term()}.
reregister_session(RegisterReq, SessionId, Opts) when is_binary(SessionId), SessionId =/= <<>> ->
    proxied_call('ProxyRegister', register, RegisterReq,
                 Opts#{metadata => #{<<"x-yuzu-session-id">> => SessionId}}).

%% @doc Forward an unsolicited Guardian side-channel CommandResponse
%% (plugin="__guard__") upstream to the C++ control plane via the
%% GatewayUpstream.ForwardGuardianMessage RPC.
%%
%% Fire-and-forget (cast): this is invoked from the agent gen_statem's
%% stream_data handler and MUST NOT block it. Best-effort delivery — the
%% message is dropped (with a counter) if the circuit is open or the dedicated
%% in-flight budget is exhausted; durable buffering is Guardian A3. AgentId is
%% gateway-asserted by the caller (the agent's bound stream identity) and is
%% NEVER taken from the forwarded frame.
-spec forward_guardian_message(binary(), map()) -> ok.
forward_guardian_message(AgentId, ResponseFrame) ->
    gen_server:cast(?SERVER, {forward_guardian_message, AgentId, ResponseFrame}).

%% @doc Replay the registrations of the sessions the server reported as
%% unknown in a BatchHeartbeat response (#1197).
%%
%% Fire-and-forget (cast), called by yuzu_gw_heartbeat_buffer once per flush
%% and so never blocking it. `ok' means handed over, not replayed: the ids are
%% dropped when the circuit is open, when this node does not hold the session,
%% when the agent is already queued, when the session was replayed within the
%% guard window, and when the queue is full. The heartbeat buffer already
%% bounds the list (at most 4096 binaries of 1 to 64 bytes); the cast handler
%% bounds it again: a non-list is ignored and only the first 4096 ids are used.
-spec replay_sessions([binary()]) -> ok.
replay_sessions(SessionIds) ->
    replay_sessions(SessionIds, #{}).

%% @doc As replay_sessions/1, with what the verdict was an answer to: `batch',
%% the number of heartbeats in the BatchHeartbeat request, and `truncated', the
%% server's unknown_session_ids_truncated. They are the evidence that decides
%% whether the server lost its state and every agent is replayed (see the
%% module doc); without them only the listed sessions are.
-spec replay_sessions([binary()], #{batch => non_neg_integer(), truncated => boolean()}) -> ok.
replay_sessions(SessionIds, Verdict) when is_map(Verdict) ->
    gen_server:cast(?SERVER, {replay_sessions, SessionIds, Verdict}).

%% @doc Planned stop, step one (#5695): stop taking work. From here proxied
%% calls are refused (`stopping', answered UNAVAILABLE so agents go to another
%% gateway), queued permit waiters are refused, no registration replay runs,
%% and the held-notification cap is raised by twice the sessions this node
%% holds, so the DISCONNECTED notices the stop produces are never refused.
-spec begin_stop() -> ok.
begin_stop() ->
    gen_server:call(?SERVER, begin_stop, 5000).

%% @doc Planned stop, step two (#5695): send every held notification, whatever
%% the breaker state, up to ?STOP_NOTIFY_INFLIGHT at once, until there is none
%% held or in flight, or Deadline (monotonic ms) passes. Returns the number
%% sent and the number left; what is left is counted as lost (reason
%% shutdown) and named in one log line. A failed send is not retried here.
%% Afterwards every notification is counted, not sent.
-spec last_gasp(integer()) -> #{sent := non_neg_integer(), left := non_neg_integer()}.
last_gasp(Deadline) ->
    Wait = max(0, Deadline - erlang:monotonic_time(millisecond)) + 2000,
    gen_server:call(?SERVER, {last_gasp, Deadline}, Wait).

%% @doc Query the current circuit breaker state by a call into this process.
%% The call queues behind whatever RPC the process is making, so against a slow
%% server it waits (it gives up after 5 s); /readyz reads circuit_state_now/0.
-spec circuit_state() -> closed | open | half_open.
circuit_state() ->
    gen_server:call(?SERVER, circuit_state, 5000).

%% @doc The circuit breaker state as last published by this process, read
%% without a call into it, so it answers while the process is inside a slow RPC.
%% Exits with `noproc' when this process is not running, as a call would.
-spec circuit_state_now() -> closed | open | half_open.
circuit_state_now() ->
    case {whereis(?SERVER), persistent_term:get(?CELL, undefined)} of
        {Pid, Cell} when is_pid(Pid), Cell =/= undefined ->
            case atomics:get(Cell, ?CELL_CB) of
                ?CB_OPEN      -> open;
                ?CB_HALF_OPEN -> half_open;
                _             -> closed
            end;
        _ ->
            exit({noproc, {?MODULE, circuit_state_now, []}})
    end.

%% @doc What the pressure sampler needs, read without a call into this process:
%% how many live Register and inventory callers wait for a permit (the
%% regulator's published counts; replays are not counted), how many messages
%% wait in this process's mailbox, and the in-flight count and limit of each
%% worker lane. `undefined' when the process is not running. See
%% yuzu_gw_upstream_pressure for what is made of it.
-spec lane_snapshot() -> undefined | #{permit_waiting := non_neg_integer(),
                                       mailbox_len := non_neg_integer(),
                                       notify_inflight := non_neg_integer(),
                                       notify_limit := pos_integer(),
                                       guardian_inflight := non_neg_integer(),
                                       guardian_limit := pos_integer()}.
lane_snapshot() ->
    case {whereis(?SERVER), persistent_term:get(?CELL, undefined)} of
        {Pid, Cell} when is_pid(Pid), Cell =/= undefined ->
            case erlang:process_info(Pid, message_queue_len) of
                {message_queue_len, Len} ->
                    #{register := #{waiting := RW}, inventory := #{waiting := IW}} =
                        yuzu_gw_upstream_regulator:snapshot(),
                    #{permit_waiting    => RW + IW,
                      mailbox_len       => Len,
                      notify_inflight   => atomics:get(Cell, ?CELL_NOTIFY),
                      notify_limit      => notify_limit(Cell),
                      guardian_inflight => atomics:get(Cell, ?CELL_GUARDIAN),
                      guardian_limit    => ?MAX_GUARDIAN_INFLIGHT};
                undefined ->
                    undefined
            end;
        _ ->
            undefined
    end.

%% Create the cell on first use and zero the lane slots on every start, so a
%% restarted process never inherits the previous one's `in an RPC'. The breaker
%% slot is not zeroed here: init/1 publishes its initial state. The term is put
%% once and kept: replacing a persistent_term makes the VM scan every process.
%% A cell with fewer slots than this module uses (one put by an older version of
%% it, still loaded in this VM) is replaced, once.
init_cell() ->
    Cell = case persistent_term:get(?CELL, undefined) of
               undefined ->
                   new_cell();
               Existing ->
                   case atomics:info(Existing) of
                       #{size := Size} when Size >= ?CELL_SLOTS -> Existing;
                       _                                        -> new_cell()
                   end
           end,
    [atomics:put(Cell, Slot, 0) || Slot <- [?CELL_IN_RPC, ?CELL_NOTIFY, ?CELL_GUARDIAN,
                                            ?CELL_CB_GEN, ?CELL_STOPPING]],
    atomics:put(Cell, ?CELL_NOTIFY_LIMIT, ?MAX_NOTIFY_INFLIGHT),
    ok.

grow_cell() ->
    case persistent_term:get(?CELL, undefined) of
        undefined ->
            ok;
        Old ->
            case atomics:info(Old) of
                #{size := Size} when Size >= ?CELL_SLOTS ->
                    ok;
                #{size := Size} ->
                    New = atomics:new(?CELL_SLOTS, [{signed, false}]),
                    [atomics:put(New, I, atomics:get(Old, I)) || I <- lists:seq(1, Size)],
                    persistent_term:put(?CELL, New),
                    ok
            end
    end.

new_cell() ->
    Cell = atomics:new(?CELL_SLOTS, [{signed, false}]),
    persistent_term:put(?CELL, Cell),
    Cell.

cell_put(Slot, Value) ->
    case persistent_term:get(?CELL, undefined) of
        undefined -> ok;
        Cell      -> atomics:put(Cell, Slot, Value)
    end.

%% The notify budget the pressure sampler compares the in-flight count with: the
%% one drain/1 applies, so "every slot drain/1 may fill is held" is what
%% saturates the lane (one slot is reserved while a replay is queued). A cell
%% that has not been written (0) reads as the full budget.
%% A cell put by an older version of this module (fewer slots) has no limit to
%% read until code_change/3 or the next start replaces it: also the full budget.
notify_limit(Cell) ->
    case atomics:info(Cell) of
        #{size := Size} when Size >= ?CELL_NOTIFY_LIMIT ->
            case atomics:get(Cell, ?CELL_NOTIFY_LIMIT) of
                0     -> ?MAX_NOTIFY_INFLIGHT;
                Limit -> Limit
            end;
        _ ->
            ?MAX_NOTIFY_INFLIGHT
    end.

%% Assign replay_queue and its length counter together.
-spec set_replay_queue(#state{}, [replay_entry()], non_neg_integer()) -> #state{}.
set_replay_queue(State, Queue, Len) ->
    State#state{replay_queue = Queue, replay_len = Len}.

publish_breaker(closed)    -> cell_put(?CELL_CB, ?CB_CLOSED);
publish_breaker(open)      -> cell_put(?CELL_CB, ?CB_OPEN);
publish_breaker(half_open) -> cell_put(?CELL_CB, ?CB_HALF_OPEN).

%% The generation goes out first: a caller that reads half_open must not then
%% read the generation of the previous half_open.
publish_breaker(CbState, Gen) ->
    cell_put(?CELL_CB_GEN, Gen),
    publish_breaker(CbState).

%% The budget of a proxied call whose caller gave no deadline: the application
%% env key upstream_call_timeout_ms (ms, valid 100..300000, default 30000, the
%% agent's own Register deadline). Anything else logs a warning that names the
%% key and takes the default. Read on every such call.
call_timeout() ->
    yuzu_gw_env:env_int(upstream_call_timeout_ms, ?DEFAULT_CALL_TIMEOUT_MS,
                        ?MIN_CALL_TIMEOUT_MS, ?MAX_CALL_TIMEOUT_MS).

%% The longest one proxied RPC may take, whatever the caller's budget:
%% upstream_rpc_timeout_ms (default 5000, the client's own default and what
%% every proxied call had before it was configurable; valid 100..60000). A
%% caller with less time left gets what it has left (less DEADLINE_MARGIN_MS).
rpc_timeout() ->
    yuzu_gw_env:env_int(upstream_rpc_timeout_ms, ?DEFAULT_RPC_TIMEOUT_MS,
                        ?MIN_CALL_TIMEOUT_MS, ?MAX_RPC_TIMEOUT_MS).

%%%===================================================================
%%% Proxied calls (ProxyRegister, ProxyInventory) - run in the caller
%%%===================================================================

%% The caller's deadline, less the margin its answer needs to get back to the
%% agent before the agent's own deadline passes.
caller_deadline(Opts) ->
    case maps:get(deadline, Opts, undefined) of
        D when is_integer(D) -> D - ?DEADLINE_MARGIN_MS;
        _ -> erlang:monotonic_time(millisecond) + call_timeout() - ?DEADLINE_MARGIN_MS
    end.

%% Breaker state and stop flag, read from the cell without a call. `undefined'
%% when this process is not running.
proxy_gate() ->
    case {whereis(?SERVER), persistent_term:get(?CELL, undefined)} of
        {Pid, Cell} when is_pid(Pid), Cell =/= undefined ->
            case atomics:get(Cell, ?CELL_STOPPING) of
                1 -> stopping;
                _ ->
                    case atomics:get(Cell, ?CELL_CB) of
                        ?CB_OPEN -> open;
                        _        -> {pass, atomics:get(Cell, ?CELL_CB_GEN)}
                    end
            end;
        _ ->
            undefined
    end.

proxied_call(Method, Class, Request, Opts) ->
    proxied_attempt(Method, Class, Request, caller_deadline(Opts), ?STREAM_LIMIT_PAUSE_MS,
                    maps:get(metadata, Opts, #{})).

proxied_attempt(Method, Class, Request, Deadline, Pause, Metadata) ->
    case proxy_gate() of
        undefined -> {error, upstream_unavailable};
        stopping  -> {error, stopping};
        open      -> {error, circuit_open};
        {pass, _} ->
            %% Stop waiting for a permit while there is still time for a useful
            %% call; a caller with less than that left is not worth a permit.
            case yuzu_gw_upstream_regulator:ask(Class, Deadline - ?MIN_USEFUL_MS) of
                {ok, Permit} ->
                    Result = try permitted_call(Method, Class, Request, Deadline, Metadata)
                             after yuzu_gw_upstream_regulator:done(Permit)
                             end,
                    case Result of
                        stream_limit ->
                            stream_limit_pause(Class, Deadline, Pause,
                                               fun(Next) ->
                                                       proxied_attempt(Method, Class, Request,
                                                                       Deadline, Next, Metadata)
                                               end);
                        _ ->
                            Result
                    end;
                {error, deadline} ->
                    drop_call(Class),
                    {error, deadline};
                {error, unavailable} ->
                    {error, upstream_unavailable};
                {error, Reason} ->
                    {error, Reason}
            end
    end.

%% gun refused the call locally (too_many_streams): the connection is at the
%% server's concurrent-stream limit, nothing was sent, and that is not a fact
%% about the upstream's health. The permit has been handed back; after a short
%% pause (so the regulator can take a lowered limit the channel just learned)
%% the caller asks for one again and waits in the regulator's queue like any
%% caller, until its deadline, which is answered `deadline' (UNAVAILABLE).
stream_limit_pause(Class, Deadline, Pause, Retry) ->
    case Deadline - ?MIN_USEFUL_MS - erlang:monotonic_time(millisecond) of
        Left when Left > Pause ->
            timer:sleep(Pause),
            Retry(min(?STREAM_LIMIT_PAUSE_MAX_MS, 2 * Pause));
        _ ->
            drop_call(Class),
            {error, deadline}
    end.

%% Holding a permit. The breaker is read again (it may have opened while the
%% caller waited), and so is the clock: a caller that has run out of time makes
%% no RPC. The result goes to this process by cast, with the breaker generation
%% read before the call, and is returned to the caller without waiting for it.
%% A call gun refused locally for the server's stream limit is `stream_limit':
%% it is not cast (the breaker does not see it) and proxied_attempt/5 retries it.
permitted_call(Method, Class, Request, Deadline, Metadata) ->
    case proxy_gate() of
        undefined -> {error, upstream_unavailable};
        stopping  -> {error, stopping};
        open      -> {error, circuit_open};
        {pass, Gen} ->
            Left = Deadline - erlang:monotonic_time(millisecond),
            case Left >= ?MIN_USEFUL_MS of
                false ->
                    drop_call(Class),
                    {error, deadline};
                true ->
                    case do_rpc(Method, Request, Class, Metadata, min(rpc_timeout(), Left)) of
                        {error, too_many_streams} ->
                            stream_limit;
                        Result ->
                            gen_server:cast(?SERVER, {rpc_result, Gen, Result}),
                            public_result(Result)
                    end
            end
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    %% cluster_id is stamped on every notification as a protobuf string, so it is
    %% converted with the unicode conversion, not list_to_binary/1 (which would
    %% truncate a code point above 127 to latin-1, not valid UTF-8). The boot
    %% check in yuzu_gw_app refuses an unrepresentable value first; this is the
    %% second line (the reason names the cause, never the value).
    case yuzu_gw_env:utf8_binary(application:get_env(yuzu_gw, cluster_id, <<"default">>)) of
        {ok, ClusterId} -> init_state(ClusterId);
        error           -> {stop, {invalid_cluster_id, app_env}}
    end.

init_state(ClusterId) ->
    %% The threshold and both timeouts are validated. A threshold of 0 would trip
    %% the breaker on the first failure; a reset timeout under the floor would make
    %% the half_open probe a near hot loop (trip_circuit doubles a tiny base).
    %% Anything outside the range warns naming the key and takes the default.
    Threshold   = yuzu_gw_env:env_int(circuit_breaker_failure_threshold, ?DEFAULT_CB_THRESHOLD,
                                      ?MIN_CB_THRESHOLD, ?MAX_CB_THRESHOLD),
    BaseTimeout = yuzu_gw_env:env_int(circuit_breaker_reset_timeout_ms, ?DEFAULT_CB_RESET_MS,
                                      ?MIN_CB_TIMEOUT_MS, ?MAX_CB_TIMEOUT_MS),
    MaxTimeout0 = yuzu_gw_env:env_int(circuit_breaker_max_reset_timeout_ms,
                                      ?DEFAULT_CB_MAX_RESET_MS,
                                      ?MIN_CB_TIMEOUT_MS, ?MAX_CB_TIMEOUT_MS),
    %% Whether the operator set a usable cap: an unset or rejected key left the
    %% default in force, and the clamp warning must not present that default as a
    %% value the operator configured.
    MaxConfigured = case application:get_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms) of
                        {ok, V} when is_integer(V), V >= ?MIN_CB_TIMEOUT_MS,
                                     V =< ?MAX_CB_TIMEOUT_MS -> true;
                        _                                   -> false
                    end,
    %% The cap is never below the initial duration: trip_circuit takes the first
    %% open period from the base but caps the NEXT one, so a base above the cap
    %% would open for the base and then shorten (the default cap is 30000).
    MaxTimeout  = clamp_max_timeout(BaseTimeout, MaxTimeout0, MaxConfigured),
    ReplayJitter = yuzu_gw_env:env_int(registration_replay_start_jitter_ms,
                                       ?DEFAULT_REPLAY_JITTER_MS, 0, ?MAX_REPLAY_JITTER_MS),
    SessionGuard = yuzu_gw_env:env_int(registration_replay_session_guard_ms,
                                   ?DEFAULT_REPLAY_SESSION_GUARD_MS, 0,
                                   ?MAX_REPLAY_SESSION_GUARD_MS),
    QueueMax = yuzu_gw_env:env_int(registration_replay_queue_max,
                               ?DEFAULT_REPLAY_QUEUE_MAX, 1, ?MAX_REPLAY_QUEUE_MAX),
    NotifyPendingMax = yuzu_gw_env:env_int(notify_pending_max,
                                           default_notify_pending_max(), 1,
                                           ?MAX_NOTIFY_PENDING_MAX),
    ProbeTimeout = yuzu_gw_env:env_int(notify_probe_timeout_ms,
                                       ?DEFAULT_NOTIFY_PROBE_TIMEOUT_MS,
                                       ?MIN_NOTIFY_PROBE_TIMEOUT_MS,
                                       ?MAX_NOTIFY_PROBE_TIMEOUT_MS),
    UnackedBase = yuzu_gw_env:env_int(notify_unacked_retry_base_ms, ?DEFAULT_UNACKED_BASE_MS,
                                      ?MIN_UNACKED_BASE_MS, ?MAX_UNACKED_BASE_MS),
    UnackedMax = max(UnackedBase,
                     yuzu_gw_env:env_int(notify_unacked_retry_max_ms, ?DEFAULT_UNACKED_MAX_MS,
                                         ?MIN_UNACKED_MAX_MS, ?MAX_UNACKED_MAX_MS)),
    UnackedWindow = yuzu_gw_env:env_int(notify_unacked_disconnected_window_ms,
                                        ?DEFAULT_UNACKED_DISC_WINDOW_MS, 0,
                                        ?MAX_UNACKED_DISC_WINDOW_MS),
    SlowAfter = yuzu_gw_env:env_int(notify_unacked_slow_after, ?DEFAULT_UNACKED_SLOW_AFTER,
                                    1, ?MAX_UNACKED_SLOW_AFTER),
    SlowMax = max(UnackedMax,
                  yuzu_gw_env:env_int(notify_unacked_slow_max_ms, ?DEFAULT_UNACKED_SLOW_MAX_MS,
                                      ?MIN_UNACKED_SLOW_MAX_MS, ?MAX_UNACKED_SLOW_MAX_MS)),

    logger:info("Upstream client started (circuit breaker: threshold=~b, base_timeout=~bms, "
                "replay_start_jitter=~bms, replay_session_guard=~bms, replay_queue_max=~b, "
                "notify_pending_max=~b, notify_probe_timeout=~bms, cluster_id=~ts, "
                "unacknowledged notice resend=~b..~bms, disconnected window=~bms, "
                "slowed after ~b refusals to ~bms)",
                [Threshold, BaseTimeout, ReplayJitter, SessionGuard, QueueMax,
                 NotifyPendingMax, ProbeTimeout, ClusterId, UnackedBase, UnackedMax,
                 UnackedWindow, SlowAfter, SlowMax]),

    %% A restarted instance counts only its own workers, so the gauges start
    %% from zero here (workers of an earlier instance are unlinked and uncounted).
    emit_notify_queue(0, 0),

    ok = init_cell(),
    %% Trap exits: terminate/2 then runs on a supervisor shutdown, and counts
    %% the notifications this process still holds (a planned stop has flushed
    %% them already; anything else loses them). The permit regulator is linked:
    %% its exit stops this process (handle_info 'EXIT').
    process_flag(trap_exit, true),
    ok = start_regulator(),

    State = #state{
        notify_pids     = #{},
        notify_pending  = yuzu_gw_notify_queue:new(NotifyPendingMax),
        notify_pending_max = NotifyPendingMax,
        notify_probe_timeout_ms = ProbeTimeout,
        cb_state        = closed,
        cb_failures     = 0,
        cb_threshold    = Threshold,
        cb_base_timeout = BaseTimeout,
        cb_max_timeout  = MaxTimeout,
        cb_cur_timeout  = BaseTimeout,
        cb_timer        = undefined,
        replay_queue    = [],
        replay_limit    = maps:get(replay, yuzu_gw_upstream_regulator:limits()),
        replay_jitter_ms = ReplayJitter,
        recent_replays  = #{},
        session_guard_ms = SessionGuard,
        replay_queue_max = QueueMax,
        guardian_pids   = #{},
        cluster_id      = ClusterId,
        unacked_base_ms = UnackedBase,
        unacked_max_ms  = UnackedMax,
        unacked_disc_window_ms = UnackedWindow,
        unacked_slow_after = SlowAfter,
        unacked_slow_max_ms = SlowMax
    },
    publish_breaker(State#state.cb_state, State#state.cb_gen),
    emit_notify_held(State),
    emit_unacked_keys(0, 0),
    erlang:send_after(?NOTIFY_HWM_TICK_MS, self(), notify_hwm_tick),
    {ok, State}.

%% The effective cap: the configured one, or the initial duration when the cap is
%% below it. The warning names the configuration that did not take effect: the
%% configured cap when the operator set one, otherwise the default cap, said to
%% be the default (the operator never wrote that number).
clamp_max_timeout(Base, Max, _Configured) when Max >= Base ->
    Max;
clamp_max_timeout(Base, Max, true) ->
    logger:warning("circuit_breaker_max_reset_timeout_ms (~b) is below "
                   "circuit_breaker_reset_timeout_ms (~b); using ~b for both",
                   [Max, Base, Base]),
    Base;
clamp_max_timeout(Base, Max, false) ->
    logger:warning("circuit_breaker_reset_timeout_ms (~b) is above the default "
                   "circuit_breaker_max_reset_timeout_ms (~b, not set or rejected); the maximum "
                   "backoff is raised to ~b. Set circuit_breaker_max_reset_timeout_ms "
                   "to choose it.",
                   [Base, Max, Base]),
    Base.

%% The calls this process answers: circuit_state (a state read), and anything
%% else with {error, unknown_call}. ProxyRegister and ProxyInventory are not
%% calls into this process: they run in the caller (proxied_call/4), and only
%% their result comes here, by cast ({rpc_result, Gen, Result}).
handle_call(circuit_state, _From, #state{cb_state = CbState} = State) ->
    {reply, CbState, State};

handle_call(begin_stop, _From, #state{mode = running, notify_pending = Pending} = State) ->
    cell_put(?CELL_STOPPING, 1),
    _ = (catch yuzu_gw_upstream_regulator:refuse_all()),
    Sessions = yuzu_gw_registry:agent_count(),
    Cap = yuzu_gw_notify_queue:cap(Pending) + 2 * Sessions,
    logger:info("Planned stop: proxied calls refused, replay stopped, ~b session(s) held; "
                "held-notification cap raised to ~b", [Sessions, Cap]),
    State1 = case replay_active(State) of
                 true  -> abort_replay("planned stop", State);
                 false -> State
             end,
    {reply, ok, State1#state{mode = stopping, heal_replay = false,
                             notify_pending = yuzu_gw_notify_queue:set_cap(Cap, Pending),
                             notify_pending_max = Cap}};
handle_call(begin_stop, _From, State) ->
    {reply, ok, State};

handle_call({last_gasp, Deadline}, From, #state{mode = Mode} = State)
  when Mode =:= running; Mode =:= stopping ->
    Before = notify_counts(State),
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    Timer = erlang:send_after(Left, self(), last_gasp_deadline),
    cell_put(?CELL_STOPPING, 1),
    cell_put(?CELL_NOTIFY_LIMIT, ?STOP_NOTIFY_INFLIGHT),
    State1 = State#state{mode = flushing, flush_from = From, flush_deadline = Deadline,
                         flush_timer = Timer, flush_sent = 0},
    {noreply, report_notify_counts(Before, settle(flush_unacked(State1)))};
handle_call({last_gasp, _Deadline}, _From, State) ->
    {reply, #{sent => 0, left => 0}, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({notify_stream_status, AgentId, _SessionId, Event, _PeerAddr, _Home},
            #state{mode = flushed} = State) ->
    %% After a planned stop's last gasp: nothing more is sent.
    logger:debug("Stream status notification for ~s after the planned-stop flush; "
                 "not sent", [yuzu_gw_env:log_text(AgentId)]),
    emit_notify_lost(Event, shutdown, 1),
    {noreply, State};
handle_cast({notify_stream_status, AgentId, SessionId, Event, PeerAddr0, StreamHomeId},
            #state{cluster_id = ClusterId} = State0) ->
    Before = notify_counts(State0),
    %% The peer address is the one the gateway decided when the agent registered
    %% (yuzu_gw_agent_service:register_checked/2: the TCP peer, or the address a
    %% trusted proxy vouched for, formatted by yuzu_grpc_origin; `unknown' when
    %% there is none), never a value the agent sent. It is still made encodable
    %% and bounded here, whoever the caller, before anything is built from it, so
    %% the held notification can never fail the same way on every send (see the
    %% standing invariant in the module header).
    PeerAddr = sanitize_peer_addr(AgentId, PeerAddr0),
    Notification = #{
        agent_id     => AgentId,
        session_id   => ensure_binary(SessionId),
        event        => case Event of connected -> 'CONNECTED'; disconnected -> 'DISCONNECTED' end,
        peer_addr    => PeerAddr,
        gateway_node => atom_to_binary(node(), utf8),
        %% HA WS-4 4.1 — this gateway's configured cluster id
        %% (yuzu_gw env `cluster_id` / YUZU_GW_CLUSTER_ID), so
        %% the server's routing directory can record which
        %% cluster owns this agent's live stream.
        cluster_id   => ClusterId,
        %% CC-03: advertised on every notification (connect and
        %% disconnect alike) — the server only needs to observe
        %% it once per gateway build, and sending it unconditionally
        %% avoids a connect-only special case here.
        wire_capabilities => [?WIRE_CAP_DISPATCH_TAG_V1],
        %% HA WS-4 (#4324) — opaque id minted once per
        %% session placement (by its first yuzu_gw_agent owner;
        %% a restarted owner reuses it, #5695) and passed through
        %% verbatim here on both CONNECTED and DISCONNECTED,
        %% so the server can match a DISCONNECTED to the
        %% stream home it tears down. Owners of one session are
        %% sequential, never concurrent, so this is a matching
        %% key, not a guard against a second home.
        stream_home_id => StreamHomeId
    },
    %% #4632: hold the notification instead of dropping it when no slot is free
    %% or the breaker is not closed. Latest event wins within a key (so a
    %% CONNECTED followed by a DISCONNECTED for one session sends only the
    %% DISCONNECTED); two sessions of one agent are two keys.
    Key = {AgentId, maps:get(session_id, Notification), StreamHomeId},
    %% NOTIFY-ACK: a newer event for the key supersedes a notice the server
    %% refused and that waits for a resend (a resend in flight is waited for, by
    %% per-key order, and its result is then dropped).
    #state{notify_pending = Pending} = State = cancel_unacked(Key, State0),
    %% Every send in flight (the half_open probe included) may come back to be
    %% held again (a failure is requeued), so each holds a slot back, except one
    %% for this very key: a newer event for it replaces what comes back
    %% (push_front supersedes) and must not be charged a second slot. The store
    %% therefore never exceeds notify_pending_max, given-back events included.
    Reserved = reserved_slots(Key, State),
    State1 =
        case yuzu_gw_notify_queue:put(Key, {AgentId, Notification}, Event, Reserved, Pending) of
            {new, Pending1} ->
                note_held(State#state{notify_pending = Pending1});
            {replaced, Pending1} ->
                telemetry:execute([yuzu, gw, upstream, notify_coalesced],
                                  #{count => 1}, #{}),
                State#state{notify_pending = Pending1};
            {{evicted, {EvAgent, _, _} = EvKey, _EvEvent}, Pending1} ->
                %% #5695 drop policy: the store is full and this is a
                %% DISCONNECTED, so the oldest held CONNECTED made room. A lost
                %% CONNECTED is put right by a full registration replay, armed
                %% here and run once the store has drained (heal_replay).
                logger:debug("Held CONNECTED for ~s evicted to hold a DISCONNECTED "
                             "(pending store full)", [yuzu_gw_env:log_text(EvAgent)]),
                emit_notify_lost(connected, evicted, 1),
                note_held(drop_held_unacked(EvKey, State#state{notify_pending = Pending1,
                                                               heal_replay = true}));
            {full, _Unchanged} ->
                %% HA WS-4 4.4 review fix (F2): a drop is never invisible.
                %% Admission loss: admitting the key would bring the held keys
                %% plus the sends in flight to notify_pending_max, and (for a
                %% DISCONNECTED) no CONNECTED was held to evict. A lost CONNECTED
                %% arms the healing replay; a lost DISCONNECTED cannot be put
                %% right from here (the server keeps the session until the agent
                %% registers again), which is why the cap is sized well above the
                %% fleet (see default_notify_pending_max/0).
                logger:debug("Dropping stream status notification for ~s (pending store full)",
                             [yuzu_gw_env:log_text(AgentId)]),
                telemetry:execute([yuzu, gw, upstream, notify_dropped],
                                  #{count => 1}, #{reason => <<"at_capacity">>}),
                emit_notify_lost(Event, at_capacity, 1),
                case Event of
                    connected    -> State#state{heal_replay = true};
                    disconnected -> State
                end
        end,
    {noreply, report_notify_counts(Before, settle(State1))};

%% The result of a proxied call, made in the caller's process. It counts
%% against the breaker like any call, but only under the generation the caller
%% read before its RPC and never while the breaker is open: a result from before
%% the breaker last moved says nothing about the upstream now (and on_success/
%% on_failure have no clause for an open breaker).
handle_cast({rpc_result, Gen, Result}, #state{cb_state = CbState, cb_gen = CbGen} = State)
  when CbState =/= open, Gen =:= CbGen ->
    Before = notify_counts(State),
    {noreply, report_notify_counts(Before, settle(record_result(Result, State)))};
handle_cast({rpc_result, _Gen, _Result}, State) ->
    {noreply, State};

handle_cast({forward_guardian_message, AgentId, ResponseFrame},
            #state{guardian_pids = GPids, cb_state = CbState} = State) ->
    %% Best-effort, like notify_stream_status: skip if the circuit is open
    %% (upstream known-down) or the dedicated in-flight budget is full. Each
    %% accepted message is sent on its own monitored process so a slow upstream
    %% can't block the gen_server, and the count is bounded.
    case CbState of
        open ->
            logger:debug("Dropping guardian message for ~s (circuit open)",
                         [yuzu_gw_env:log_text(AgentId)]),
            telemetry:execute([yuzu, gw, guardian, forward_dropped],
                              #{count => 1}, #{reason => <<"circuit_open">>}),
            {noreply, State};
        _ ->
            case map_size(GPids) >= ?MAX_GUARDIAN_INFLIGHT of
                true ->
                    logger:debug("Dropping guardian message for ~s (at capacity)",
                                 [yuzu_gw_env:log_text(AgentId)]),
                    telemetry:execute([yuzu, gw, guardian, forward_dropped],
                                      #{count => 1}, #{reason => <<"at_capacity">>}),
                    {noreply, State};
                false ->
                    %% Accepted for delivery — count it so the drop counters
                    %% have a denominator (drop-rate SLO). See yuzu_gw_telemetry.
                    telemetry:execute([yuzu, gw, guardian, forward_accepted],
                                      #{count => 1}, #{}),
                    Request = #{agent_id => AgentId, response => ResponseFrame},
                    {Pid, _MonRef} = spawn_monitor(fun() ->
                        case public_result(do_rpc('ForwardGuardianMessage', Request,
                                                  guardian)) of
                            {ok, _} -> ok;
                            {error, Reason} ->
                                logger:warning("Failed to forward guardian message for ~s: ~p",
                                               [yuzu_gw_env:log_text(AgentId), Reason])
                        end
                    end),
                    NewGPids = GPids#{Pid => true},
                    cell_put(?CELL_GUARDIAN, map_size(NewGPids)),
                    {noreply, State#state{guardian_pids = NewGPids}}
            end
    end;

handle_cast({replay_sessions, SessionIds}, State) ->
    handle_cast({replay_sessions, SessionIds, #{}}, State);
handle_cast({replay_sessions, _SessionIds, _Verdict}, #state{mode = Mode} = State)
  when Mode =/= running ->
    {noreply, State};
handle_cast({replay_sessions, SessionIds0, Verdict}, State) ->
    Before = notify_counts(State),
    %% replay_sessions/1,2 are exported, so this boundary bounds its own input
    %% (the heartbeat buffer's cap is not the only caller's guarantee): a
    %% non-list is ignored, a list is cut to ?MAX_REPLAY_SESSION_IDS before it
    %% is counted, dropped or queued; the verdict facts are read with defaults.
    case bound_session_ids(SessionIds0) of
        invalid ->
            logger:debug("Registration replay: ignoring a verdict that is not a list"),
            {noreply, State};
        SessionIds ->
            State1 = replay_verdict(SessionIds, verdict_facts(Verdict), State),
            {noreply, report_notify_counts(Before, settle(State1))}
    end;

handle_cast(replay_registrations, #state{mode = Mode} = State) when Mode =/= running ->
    {noreply, State};
handle_cast(replay_registrations, #state{replay_walk = Walk} = State) when Walk =/= idle ->
    %% Gate 7 UP-5: a full replay is already pending or walking. Reseeding it on
    %% every trigger restarted it from zero each time, and at fleet scale it
    %% never finished. The running walk completes; if the upstream went away
    %% again, the walk is aborted when the breaker opens.
    logger:debug("Registration replay: a full replay is already running; ignoring the trigger"),
    {noreply, State};
handle_cast(replay_registrations, State) ->
    %% A full replay asked for by hand (nothing in the gateway sends this since
    %% a breaker recovery stopped replaying; an operator can, from a remote
    %% shell). Idle: start a full walk of the registry after the start jitter.
    %% The walk reads the table when it runs, so an agent that disconnected
    %% meanwhile is already gone and is not replayed. A targeted replay already
    %% queued (a verdict) keeps running; the walk is pumped after it.
    {noreply, start_full_replay(manual, State)};

handle_cast({notify_settled, Key, Ack}, #state{settle_waiters = W} = State) ->
    Before = notify_counts(State),
    %% release_settled/1 can cancel a retry-set entry: report the gauge.
    {noreply, report_notify_counts(
                Before,
                release_settled(State#state{settle_waiters = W#{Key => [Ack | maps:get(Key, W, [])]}}))};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% The start jitter of a full replay has passed: fix the agents table (so the
%% chunked walk is a safe traversal while agents come and go) and start
%% pumping. An absent table (the registry is restarting) is no replay.
handle_info(replay_start, #state{replay_walk = {pending, _, Trigger}} = State) ->
    Before = notify_counts(State),
    State1 =
        try
            true = ets:safe_fixtable(?AGENTS_TABLE, true),
            Rows = ets:info(?AGENTS_TABLE, size),
            case Rows of
                0 ->
                    ets:safe_fixtable(?AGENTS_TABLE, false),
                    logger:info("Registration replay: no agents to re-proxy"),
                    State#state{replay_walk = idle};
                _ ->
                    logger:info("Registration replay: re-proxying ~b agent(s) upstream", [Rows]),
                    telemetry:execute([yuzu, gw, upstream, registration_replay_triggered],
                                      #{count => 1}, #{trigger => Trigger}),
                    start_replay_clock(State#state{replay_walk = {walking, start, Rows}})
            end
        catch error:badarg ->
            logger:warning("Registration replay: registry unavailable; not replayed"),
            State#state{replay_walk = idle}
        end,
    {noreply, report_notify_counts(Before, settle(State1))};
handle_info(replay_start, State) ->
    {noreply, State};

%% What a replay worker did. Only a worker this process still tracks counts;
%% the breaker is moved only under the generation it was spawned with and
%% never while open (see the rpc_result cast).
handle_info({replay_done, Pid, Gen, Outcome}, #state{replay_pids = RPids} = State)
  when is_map_key(Pid, RPids) ->
    Before = notify_counts(State),
    {{_AgentId, SessionId}, RPids1} = maps:take(Pid, RPids),
    State1 = replay_outcome(Outcome, SessionId, Gen, State#state{replay_pids = RPids1}),
    {noreply, report_notify_counts(Before, settle(State1))};
handle_info({replay_done, _Pid, _Gen, _Outcome}, State) ->
    {noreply, State};

%% The last gasp's deadline: whatever is left is counted and the stop goes on.
handle_info(last_gasp_deadline, #state{mode = flushing} = State) ->
    {noreply, end_flush(State)};
handle_info(last_gasp_deadline, State) ->
    {noreply, State};

%% Exits are trapped (see init/1) only so terminate/2 runs; an exit signal is
%% otherwise obeyed as if it were not trapped. The regulator is this process's
%% own: if it goes, this process goes, and the supervisor restarts both. A
%% parent's exit is handled by gen_server itself.
handle_info({'EXIT', _Pid, normal}, State) ->
    {noreply, State};
handle_info({'EXIT', Pid, Reason}, State) ->
    case whereis(yuzu_gw_upstream_regulator) of
        Pid -> {stop, {regulator_exit, redact_reason(Reason)}, State};
        _   -> {stop, Reason, State}
    end;

%% Rotate the high-water mark: the previous minute's peak is kept for one more
%% minute, so a scrape anywhere in that window sees it.
handle_info(notify_hwm_tick, #state{notify_pending = Pending, notify_hwm_cur = Cur} = State) ->
    erlang:send_after(?NOTIFY_HWM_TICK_MS, self(), notify_hwm_tick),
    State1 = State#state{notify_hwm_prev = Cur,
                         notify_hwm_cur = yuzu_gw_notify_queue:size(Pending)},
    emit_notify_held(State1),
    {noreply, State1};

handle_info(circuit_half_open, #state{cb_gen = Gen} = State) ->
    logger:info("Circuit breaker: open -> half_open (allowing probe RPC)"),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"half_open">>}),
    %% The only entry into half_open, so the only place the generation moves. A
    %% held notification is sent as the probe (drain/1).
    Before = notify_counts(State),
    publish_breaker(half_open, Gen + 1),
    State1 = State#state{cb_state = half_open, cb_timer = undefined, cb_gen = Gen + 1},
    {noreply, report_notify_counts(Before, settle(State1))};

%% The result of the half_open probe worker. A result from any pid but the
%% recorded probe (a duplicate, or one that was already resolved) is ignored.
handle_info({notify_probe_result, Pid, Gen, Result},
            #state{notify_probe = #{pid := Pid}} = State) ->
    Before = notify_counts(State),
    State1 = resolve_probe(Gen, Result, State),
    {noreply, report_notify_counts(Before, settle(State1))};
handle_info({notify_probe_result, _Pid, _Gen, _Result}, State) ->
    {noreply, State};

%% The probe worker ended with no result (killed): the same as an error, once.
handle_info({'DOWN', MonRef, process, Pid, Reason},
            #state{notify_probe = #{pid := Pid, mref := MonRef, gen := Gen,
                                    event := {AgentId, _Notification}}} = State) ->
    %% Without this line the only trace of a killed probe is the half_open -> open
    %% warning. The reason is redacted (a crash reason can carry the payload).
    logger:warning("Notify probe worker for ~s exited without a result: ~p",
                   [yuzu_gw_env:log_text(AgentId), redact_reason(Reason)]),
    Before = notify_counts(State),
    State1 = resolve_probe(Gen, {error, worker_down}, State),
    {noreply, report_notify_counts(Before, settle(State1))};

%% The probe's deadline (notify_probe_timeout_ms), the gateway's own bound on how
%% long a half_open probe can hold the held store: the worker is killed and the
%% probe fails as any failed probe does (the event is given back, the breaker
%% reopens with the longer backoff, the next half_open cycle sends a new probe).
%% Only the probe currently recorded, under its own generation, is acted on: the
%% timer is cancelled when the probe resolves, but a message already delivered by
%% then (or one for an earlier probe) is ignored. A result that is already in the
%% mailbox wins over the deadline, so a probe that answered just in time is not
%% requeued; a result sent after this check is ignored like any result of a
%% probe that is no longer recorded (the event is then sent a second time).
handle_info({notify_probe_timeout, Pid, Gen},
            #state{notify_probe = #{pid := Pid, gen := Gen, event := {AgentId, _}},
                   notify_probe_timeout_ms = Timeout} = State) ->
    receive
        {notify_probe_result, Pid, _ResultGen, _Result} = Reported ->
            handle_info(Reported, State)
    after 0 ->
        exit(Pid, kill),
        logger:warning("Notify probe worker for ~s did not answer within ~bms and was "
                       "killed; the notification is held again",
                       [yuzu_gw_env:log_text(AgentId), Timeout]),
        Before = notify_counts(State),
        State1 = resolve_probe(Gen, {error, probe_timeout}, State),
        {noreply, report_notify_counts(Before, settle(State1))}
    end;
handle_info({notify_probe_timeout, _Pid, _Gen}, State) ->
    {noreply, State};

%% What a stream-status notification worker got from the server.
%%
%% The event: ok retires it; a request fault (the server says the notification
%% itself is wrong) or a local encode exception retires it as lost (`rejected':
%% sending it again would be answered the same way); any other failure gives it
%% back at the head of the store, whatever the breaker state (#5695: a failed
%% send used to be neither requeued nor counted), unless a newer event for the
%% key is held meanwhile (then that one wins, counted as coalesced). An OK
%% answer with acknowledged=false (`unacknowledged') is not delivered: the
%% notice goes to the retry set (settle_unacked/5). The slot is freed by the
%% worker's 'DOWN'.
%%
%% The breaker: it counts like a call made from this process, but only while
%% closed AND under the generation the worker was started in (as a proxied
%% call is fenced by the generation its caller read, rpc_result): the workers
%% in flight when it opened or half-opened answer into a circuit they no longer
%% belong to, even once it has closed again (Gate 8 #4: a slow notice from
%% before an open/half_open/closed cycle must not count against the recovered
%% circuit), and the half_open probe (notify_probe_result, resolved by
%% generation), not a late answer, decides when it closes. record_result/2 has
%% no clause for an open breaker, and leaves the breaker as it is for an
%% `unacknowledged' answer. The notice itself is settled the same way whatever
%% its generation.
handle_info({notify_result, Pid, Result}, #state{notify_pids = Pids} = State) ->
    Before = notify_counts(State),
    case maps:find(Pid, Pids) of
        {ok, {Key, Class, Event, Gen}} ->
            State1 = settle_notify(Key, Class, Event, Result,
                                   State#state{notify_pids = Pids#{Pid := resolved}}),
            State2 = case {State1#state.mode, State1#state.cb_state, State1#state.cb_gen} of
                         {flushing, _, _}   -> count_flushed(Result, State1);
                         {_, closed, Gen}   -> record_result(Result, State1);
                         _                  -> State1
                     end,
            {noreply, report_notify_counts(Before, settle(State2))};
        _ ->
            {noreply, State}
    end;

handle_info({'DOWN', _MonRef, process, Pid, Reason},
            #state{replay_pids = RPids} = State) when is_map_key(Pid, RPids) ->
    %% A replay worker that ended without reporting (it crashed or was killed):
    %% nothing is known about the upstream, so the breaker is not touched.
    Before = notify_counts(State),
    {{AgentId, SessionId}, RPids1} = maps:take(Pid, RPids),
    logger:warning("Registration replay worker for ~s exited without a result: ~p",
                   [yuzu_gw_env:log_text(AgentId), redact_reason(Reason)]),
    emit_replay_outcome(failed, 1),
    State1 = State#state{replay_pids = RPids1,
                         recent_replays = maps:remove(SessionId, State#state.recent_replays)},
    {noreply, report_notify_counts(Before, settle(State1))};
handle_info({'DOWN', _MonRef, process, Pid, _Reason},
            #state{notify_pids = Pids, guardian_pids = GPids} = State) ->
    %% A finished notify OR guardian-forward worker. Remove from whichever set
    %% holds it (maps:remove on an absent key is a no-op, so both are safe). A
    %% notify worker that died before reporting crashed (or was killed): its
    %% event is lost and counted (`crashed'), not given back, because a payload
    %% that crashes the worker would crash every retry. A freed notify slot is
    %% refilled from the pending store at once, and a replay held back for notify
    %% headroom may continue.
    Before = notify_counts(State),
    State0 = case maps:find(Pid, Pids) of
                 {ok, {Key, Class, _Event, _Gen}} ->
                     emit_notify_lost(Class, crashed, 1),
                     {Retry, S} = take_unacked_attempt(Key, State),
                     retry_ended(Retry, lost),
                     S;
                 _ ->
                     State
             end,
    State1 = forget_unacked_pid(Pid, State0#state{notify_pids = maps:remove(Pid, Pids),
                                                  guardian_pids = maps:remove(Pid, GPids)}),
    {noreply, report_notify_counts(Before, settle(State1))};

%% NOTIFY-ACK: the backoff of a refused notice ended. Only the timer the entry
%% still waits on counts (a cancelled or re-armed entry ignores an old one).
handle_info({timeout, TRef, {notify_unacked_due, Key}}, #state{notify_unacked = U} = State) ->
    case maps:find(Key, U) of
        {ok, #{status := {waiting, TRef}} = Entry} ->
            Before = notify_counts(State),
            State1 = unacked_due(Key, Entry, State),
            {noreply, report_notify_counts(Before, settle(State1))};
        _ ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

%%%===================================================================
%%% Registration replay workers
%%%===================================================================

%% One replay, in its own monitored process: wait for a `replay' permit (live
%% registrations are served first), then re-verify that the agent is still
%% here under the queued session, read its stored request, re-proxy it, and act
%% on the answer. The breaker part of the result goes back to this process in
%% {replay_done, Pid, Gen, Outcome}, sent before the worker exits, so it is in
%% the mailbox before the 'DOWN'.
%%   Outcome: skipped (gone, re-registered, no stored request, or no permit),
%%            registry_unavailable, or {sent, Kind, BreakerResult}.
spawn_replay({AgentId, SessionId, Req0}, #state{cb_gen = Gen, replay_pids = RPids} = State) ->
    Server = self(),
    {Pid, _Mon} = spawn_monitor(fun() ->
        Outcome = replay_one(AgentId, SessionId, Req0),
        Server ! {replay_done, self(), Gen, Outcome}
    end),
    State#state{replay_pids = RPids#{Pid => {AgentId, SessionId}}}.

replay_one(AgentId, SessionId, Req0) ->
    Deadline = erlang:monotonic_time(millisecond) + ?REPLAY_PERMIT_WAIT_MS,
    replay_attempt(AgentId, SessionId, Req0, Deadline, ?STREAM_LIMIT_PAUSE_MS).

%% A replay gun refused locally for the server's stream limit (too_many_streams)
%% asks for a permit again after a pause, as a proxied call does
%% (stream_limit_pause/4); the breaker does not see it.
replay_attempt(AgentId, SessionId, Req0, Deadline, Pause) ->
    case yuzu_gw_upstream_regulator:ask(replay, Deadline) of
        {ok, Permit} ->
            Outcome = try replay_permitted(AgentId, SessionId, Req0)
                      after yuzu_gw_upstream_regulator:done(Permit)
                      end,
            case Outcome of
                stream_limit ->
                    case Deadline - erlang:monotonic_time(millisecond) > Pause of
                        true ->
                            timer:sleep(Pause),
                            replay_attempt(AgentId, SessionId, Req0, Deadline,
                                           min(?STREAM_LIMIT_PAUSE_MAX_MS, 2 * Pause));
                        false ->
                            skipped
                    end;
                _ ->
                    Outcome
            end;
        {error, _} ->
            skipped
    end.

%% HA WS-4 4.4 (#4246 #6): re-verify liveness right before replaying. By the
%% time an entry's turn comes the agent may have disconnected, or reconnected
%% under a brand-new session (register_agent/6 overwrites its row); replaying
%% the queued session in either case would present an orphaned session the
%% server must not adopt. The `{ok, {Pid, SessionId}}' clause matches only when
%% the CURRENT local session still equals the queued one.
replay_permitted(AgentId, SessionId, Req0) ->
    case yuzu_gw_registry:lookup_local_session(AgentId) of
        {ok, {Pid, SessionId}} ->
            case stored_request(SessionId, Req0) of
                {ok, Req} ->
                    replay_send(AgentId, Pid, SessionId, Req);
                none ->
                    logger:debug("Registration replay: skipping ~s (no stored request)",
                                 [yuzu_gw_env:log_text(AgentId)]),
                    skipped
            end;
        {error, unavailable} ->
            %% The registry's tables are gone (its process died; it is a sibling
            %% under one_for_one): nothing queued can be re-verified.
            registry_unavailable;
        _ ->
            logger:debug("Registration replay: skipping ~s (no longer live locally, or "
                         "reconnected under a different session, since it was queued)",
                         [yuzu_gw_env:log_text(AgentId)]),
            skipped
    end.

%% The request to replay: the one a verdict entry carries, or for a walk entry
%% the one the registry holds for the session now. An empty request (an agent
%% registered without one) is nothing to send.
stored_request(_SessionId, Req) when is_map(Req), map_size(Req) > 0 ->
    {ok, Req};
stored_request(SessionId, walk) when is_binary(SessionId) ->
    case yuzu_gw_registry:entries_for_sessions([SessionId]) of
        [{_AgentId, SessionId, Req}] when is_map(Req), map_size(Req) > 0 -> {ok, Req};
        _ -> none
    end;
stored_request(_SessionId, _Req) ->
    none.

%% Re-proxy one stored request and classify the answer (the three-way branch
%% of HA WS-4 4.4: an adopt, the stale/zombie refusal, any other failure).
%% Carries the agent's EXISTING session id as `x-yuzu-session-id' (HA WS-4
%% 4.1), so the server treats it as a re-announce of that session instead of
%% minting a new one on every upstream reconnect.
replay_send(AgentId, Pid, SessionId, RegisterReq) ->
    Result = do_rpc_replay('ProxyRegister', RegisterReq, register, SessionId),
    case Result of
        {error, too_many_streams} ->
            %% Not sent: the connection is at the server's stream limit
            %% (replay_attempt/5 waits and asks again).
            stream_limit;
        {local_error, {Class, Why}} ->
            %% The stored request could not be encoded here, so nothing was
            %% sent: no verdict about the upstream (record_result/2
            %% ignores it).
            logger:warning("Registration replay: ~s could not be encoded (~p:~p); "
                           "skipped without touching the circuit breaker",
                           [yuzu_gw_env:log_text(AgentId), Class, Why]),
            {sent, failed, Result};
        {ok, #{accepted := false} = Response} ->
            %% The server answered OK but did not install the session (a rejected
            %% enrollment). Re-announcing a session the server never installed
            %% would be rejected again, and the next verdict would replay it
            %% again, so tear down this agent's stream: the agent registers again
            %% by itself and follows its own outcome. An authoritative answer, so
            %% a breaker SUCCESS. A MISSING `accepted' key still means accepted.
            %% The reason is the server's text, cut before it is logged.
            logger:warning("Registration replay: ~s was not accepted by the server (~s); "
                           "disconnecting so the agent follows its own registration path",
                           [yuzu_gw_env:log_text(AgentId), reject_reason_for_log(Response)]),
            yuzu_gw_agent:disconnect(Pid),
            {sent, rejected, {ok, Response}};
        {ok, Response} when is_map(Response) ->
            %% HA WS-4 4.4: the server adopts the presented session on success;
            %% read it from the response rather than assume.
            AdoptedSession = maps:get(session_id, Response,
                                      maps:get(<<"session_id">>, Response, SessionId)),
            logger:debug("Registration replay: re-proxied ~s (adopted session ~s)",
                         [yuzu_gw_env:log_text(AgentId), yuzu_gw_env:log_text(AdoptedSession)]),
            %% The agent re-sends its own CONNECTED: this converges the server's
            %% freshly installed AgentSession (ProxyRegister always wipes its
            %% gateway_node / wire_capabilities / stream_home_id).
            yuzu_gw_agent:reannounce(Pid, AdoptedSession),
            {sent, adopted, {ok, Response}};
        {ok, _NotAMap} ->
            %% An OK with no decoded response: the server never answered the
            %% registration, a replay FAILURE. Neither body nor session logged.
            logger:warning("Registration replay: ~s got an upstream answer that is "
                           "not a response message", [yuzu_gw_env:log_text(AgentId)]),
            {sent, failed, {error, malformed_response}};
        {error, {Status, _Message}} when Status =:= ?GRPC_STATUS_BIN_FAILED_PRECONDITION ->
            %% The presented session was superseded by a DIFFERENT, LIVE session
            %% server-side: a stale replay, not an outage. Authoritative, so a
            %% breaker SUCCESS (a run of stale replays after a reconnect storm
            %% must not trip it). The sanctioned recovery is an agent-driven
            %% reconnect: tear down this agent's stream.
            logger:warning("Registration replay: ~s's presented session was superseded - "
                           "forcing a fresh reconnect", [yuzu_gw_env:log_text(AgentId)]),
            yuzu_gw_agent:disconnect(Pid),
            {sent, superseded, {ok, superseded}};
        {error, Reason} ->
            logger:warning("Registration replay: ~s failed: ~p",
                           [yuzu_gw_env:log_text(AgentId), Reason]),
            {sent, failed, Result}
    end.

%% Account for one finished replay worker.
replay_outcome({sent, Kind, BreakerResult}, SessionId, Gen,
               #state{cb_state = CbState, cb_gen = CbGen} = State) ->
    emit_replay_outcome(Kind, 1),
    %% Gate 7 sre OBS-4: `replayed' counts this re-proxy attempt (any outcome),
    %% queue_depth lets an operator see a replay that never drains.
    telemetry:execute([yuzu, gw, upstream, registration_replay],
                      #{replayed => 1, queue_depth => replay_depth(State)}, #{}),
    _ = SessionId,
    case CbState =/= open andalso Gen =:= CbGen of
        true  -> record_result(BreakerResult, State);
        false -> State
    end;
replay_outcome(skipped, SessionId, _Gen, #state{recent_replays = Recent} = State) ->
    %% Nothing was sent, so the session is not "recently replayed".
    emit_replay_outcome(skipped, 1),
    emit_queue_depth(replay_depth(State)),
    State#state{recent_replays = maps:remove(SessionId, Recent)};
replay_outcome(registry_unavailable, SessionId, _Gen, #state{recent_replays = Recent} = State) ->
    State1 = State#state{recent_replays = maps:remove(SessionId, Recent)},
    abort_replay("registry unavailable", State1).

terminate(_Reason, #state{notify_pending = Pending, notify_pids = Pids} = State) ->
    %% Whatever is still held, in flight or waiting for a resend goes with this
    %% process. A planned stop has flushed it already (last_gasp/1); a crash or a
    %% shutdown without one loses it: counted, and named in one line, never sent
    %% from here (the supervisor gives this callback 5 s, no place for RPCs).
    Held = held_by_class(Pending),
    InFlight = [C || {_K, C, _E, _G} <- maps:values(Pids)],
    [emit_notify_lost(C, shutdown, N) || {C, N} <- Held],
    [emit_notify_lost(C, shutdown, 1) || C <- InFlight],
    Unacked = drop_unacked(State),
    case lists:sum([N || {_, N} <- Held]) + length(InFlight) + Unacked of
        0 -> ok;
        Lost -> logger:warning("Upstream client stopping with ~b stream-status notification(s) "
                               "not sent", [Lost])
    end,
    stop_regulator(),
    ok;
terminate(_Reason, _State) ->
    stop_regulator(),
    ok.

%% The permit regulator belongs to this process: started (linked) by init/1 and
%% stopped by terminate/2, so a restart of this process restarts it, and a crash
%% of either takes the other with it. A regulator still registered from an
%% earlier instance that is going down (the link signal is on its way) is waited
%% for briefly, then stopped: this instance owns the name.
start_regulator() ->
    case yuzu_gw_upstream_regulator:start_link() of
        {ok, _Pid} ->
            ok;
        {error, {already_started, Old}} ->
            Mon = erlang:monitor(process, Old),
            receive
                {'DOWN', Mon, process, Old, _} -> ok
            after 1000 ->
                logger:warning("Upstream permit regulator of an earlier instance still "
                               "running; stopping it"),
                exit(Old, kill),
                receive {'DOWN', Mon, process, Old, _} -> ok end
            end,
            {ok, _} = yuzu_gw_upstream_regulator:start_link(),
            ok
    end.

stop_regulator() ->
    case whereis(yuzu_gw_upstream_regulator) of
        undefined -> ok;
        Pid       -> unlink(Pid),
                     catch gen_server:stop(Pid, shutdown, 5000),
                     ok
    end.

code_change(_OldVsn, State, _Extra) ->
    %% A cell put by an older version has fewer slots than this one writes:
    %% replace it with one that keeps the old slots.
    ok = grow_cell(),
    {ok, add_trailing_fields(State)}.

%% A state from before OWNER-RESTART and NOTIFY-ACK (#5695) lacks the fields
%% they appended to the record, in this order: settle_waiters, then the retry
%% set (notify_unacked .. unacked_disc_window_ms), then its slow phase
%% (unacked_slow_after .. notify_unacked_slow_reported; an entry of an older
%% state without `refusals' counts as refused once). Each missing one is appended
%% at its default (the retry settings at the built-in defaults, not the app
%% env: init/1 reads that on the next start). Any other shape is returned as it
%% is. This only keeps the upgraded process from crashing on a field it cannot
%% find; the gateway ships no relup.
add_trailing_fields(State) when is_tuple(State), element(1, State) =:= state ->
    Defaults = [#{},                                %% settle_waiters
                #{}, queue:new(), #{}, #{}, 0,      %% notify_unacked .. _reported
                ?DEFAULT_UNACKED_BASE_MS, ?DEFAULT_UNACKED_MAX_MS,
                ?DEFAULT_UNACKED_DISC_WINDOW_MS,
                ?DEFAULT_UNACKED_SLOW_AFTER, ?DEFAULT_UNACKED_SLOW_MAX_MS, 0, 0],
    Missing = record_info(size, state) - tuple_size(State),
    case Missing > 0 andalso Missing =< length(Defaults) of
        true  -> list_to_tuple(tuple_to_list(State) ++
                               lists:nthtail(length(Defaults) - Missing, Defaults));
        false -> State
    end;
add_trailing_fields(State) ->
    State.

%% @doc What a crash report and sys:get_status/1 show of this process.
%%
%% The replay queue holds every queued agent's stored RegisterRequest
%% verbatim (enrollment_token, machine_certificate, csr_pem), and the state
%% printed whole would put those credentials in the log, once per queued
%% agent. So this callback shows:
%%   - the state as a map of its scalar fields, with replay_queue,
%%     recent_replays, replay_pids and notify_pids replaced by their sizes
%%     (replay_queue_len, recent_replays_size, replay_inflight,
%%     notify_inflight: notify_pids holds the events in flight), the held
%%     store by its length and the walk by its phase; a state that is not the
%%     record, or a queue or
%%     stamp field of the wrong type, shows as '$redacted', so this callback
%%     cannot itself crash (OTP would then print the raw message);
%%   - the last message without the request it carries. A call arrives as
%%     {'$gen_call', From, Msg} and a cast as {'$gen_cast', Msg}; both
%%     wrappers are handled, as is the bare Msg;
%%   - the reason with every term inside it replaced by '$redacted' (only
%%     atoms survive), and any stacktrace in it with each frame's argument
%%     list cut to its length;
%%   - the debug log (sys:log) as its length, kept a list (the OTP report
%%     callback iterates it).
%% Only the reports are affected: sys:get_state/1 still returns the real record.
%%
%% NOT covered by this callback, because OTP prints them from raw data outside
%% it: the process mailbox (the `messages:' line of the proc_lib crash report),
%% the exception line of that report, the stacktrace gen_server appends to its
%% own terminate report after calling this callback, and the `reason' of the
%% supervisor report. Those are redacted by yuzu_gw_crash_redact, a logger
%% primary filter that yuzu_gw_app installs on start and removes on stop; it
%% reuses redact_reason/1, redact_why/1 and redact_stack/1 below. It is NOT in
%% place when this module is used without the application (a test, a shell):
%% there a crash report of yuzu_gw_upstream is sensitive, treat it as such.
%% do_rpc/4 keeps the request out of exceptions raised by the RPC itself.
-spec format_status(map()) -> map().
format_status(Status) ->
    maps:map(fun(state, State)   -> redact_state(State);
                (message, Msg)   -> redact_message(Msg);
                (reason, Reason) -> redact_reason(Reason);
                (log, Log)       -> redact_log(Log);
                (_Key, Value)    -> Value
             end, Status).

redact_state(#state{replay_queue = Queue, recent_replays = Recent,
                    notify_pending = Pending, notify_probe = Probe, notify_pids = NPids,
                    replay_pids = RPids, replay_walk = Walk,
                    notify_unacked = U, notify_unacked_ready = UReady,
                    notify_unacked_pids = UPids, notify_unacked_cancelled = UCancelled} = State)
  when is_list(Queue), is_map(Recent), is_map(RPids), is_map(NPids),
       is_map(U), is_map(UPids), is_map(UCancelled) ->
    Fields = maps:from_list(lists:zip(record_info(fields, state),
                                      tl(tuple_to_list(State)))),
    %% The retry set holds held events (session ids, peer addresses) and keys:
    %% sizes only, like the pending store.
    (maps:without([replay_queue, recent_replays, notify_pending, notify_probe,
                   replay_pids, replay_walk, notify_pids, settle_waiters, notify_unacked,
                   notify_unacked_ready, notify_unacked_pids, notify_unacked_cancelled],
                  Fields))#{
        settle_waiters => case Fields of
                              #{settle_waiters := W} when is_map(W) -> map_size(W);
                              _ -> '$redacted'
                          end,
        notify_unacked_len => map_size(U),
        notify_unacked_ready_len => queue_len(UReady),
        notify_unacked_inflight => map_size(UPids),
        notify_unacked_cancelled_len => map_size(UCancelled),
        notify_inflight => map_size(NPids),
        replay_queue_len => length(Queue),
        replay_inflight => map_size(RPids),
        replay_walk => case Walk of idle -> idle; _ -> element(1, Walk) end,
        recent_replays_size => map_size(Recent),
        notify_pending_len => notify_pending_len(Pending),
        notify_probe_held => Probe =/= undefined};
redact_state(_Other) ->
    '$redacted'.

%% The pending store is shown as a count; the held events carry session ids and
%% peer addresses. A value that is not the store shows as '$redacted', so this
%% callback stays total.
notify_pending_len(Pending) ->
    try yuzu_gw_notify_queue:size(Pending)
    catch error:_ -> '$redacted'
    end.

%% The length of a queue, or '$redacted' for a value that is not one.
queue_len(Q) ->
    try queue:len(Q)
    catch error:_ -> '$redacted'
    end.

%% The messages that carry a request, an inventory report, session ids, a peer
%% address or a guardian frame; anything else is shown as is.
redact_message({proxy_register, _Req})            -> {proxy_register, '$redacted'};
redact_message({proxy_inventory, _Report})        -> {proxy_inventory, '$redacted'};
redact_message({replay_sessions, _Ids})           -> {replay_sessions, '$redacted'};
redact_message({replay_sessions, _Ids, Verdict})  -> {replay_sessions, '$redacted', Verdict};
redact_message({forward_guardian_message, AgentId, _Frame}) ->
    {forward_guardian_message, AgentId, '$redacted'};
redact_message({notify_settled, _Key, _Ack})      -> {notify_settled, '$redacted', '$redacted'};
redact_message({notify_stream_status, AgentId, _SessionId, Event, _PeerAddr, _Home}) ->
    {notify_stream_status, AgentId, '$redacted', Event, '$redacted', '$redacted'};
redact_message({'$gen_call', From, Msg})          -> {'$gen_call', From, redact_message(Msg)};
redact_message({'$gen_cast', Msg})                -> {'$gen_cast', redact_message(Msg)};
redact_message(Msg)                               -> Msg.

%% An exit reason is an atom, or {Why, Stack} for an error. Why is kept only
%% when it is an atom, or a tuple whose first element is an atom (shown as
%% {Atom, '$redacted'}: {badmatch, Value} carries the value); any other
%% term becomes '$redacted'.
-spec redact_reason(term()) -> term().
redact_reason(Reason) when is_atom(Reason) -> Reason;
redact_reason({Why, Stack})                -> {redact_why(Why), redact_stack(Stack)};
redact_reason(_Other)                      -> '$redacted'.

-spec redact_why(term()) -> term().
redact_why(Why) when is_atom(Why) -> Why;
redact_why(Why) when is_tuple(Why), tuple_size(Why) > 0, is_atom(element(1, Why)) ->
    {element(1, Why), '$redacted'};
redact_why(_Other) -> '$redacted'.

%% A stacktrace frame prints its ARGUMENT LIST when the error was raised with
%% one (function_clause, undef, error(Reason, Args)); keep the arity only. A
%% frame that is not one of the two stacktrace shapes becomes '$redacted'.
-spec redact_stack(term()) -> term().
redact_stack(Stack) when is_list(Stack) ->
    [redact_frame(Frame) || Frame <- Stack];
redact_stack(_Other) ->
    '$redacted'.

redact_frame({M, F, Args, Loc}) when is_list(Args) -> {M, F, length(Args), redact_loc(Loc)};
redact_frame({M, F, Arity, Loc}) when is_integer(Arity) -> {M, F, Arity, redact_loc(Loc)};
redact_frame({Fun, Args, Loc}) when is_function(Fun), is_list(Args) ->
    {Fun, length(Args), redact_loc(Loc)};
redact_frame({Fun, Arity, Loc}) when is_function(Fun), is_integer(Arity) ->
    {Fun, Arity, redact_loc(Loc)};
redact_frame(_Other) ->
    '$redacted'.

%% Only file and line survive: an error_info entry can carry the offending term.
redact_loc(Loc) when is_list(Loc) ->
    [Item || {Key, _} = Item <- Loc, Key =:= file orelse Key =:= line];
redact_loc(Loc) when is_atom(Loc) ->
    Loc;
redact_loc(_Other) ->
    '$redacted'.

%% The report callback iterates the log, so it stays a list: one marker
%% entry carrying the count (an empty list if the value is not a list).
redact_log(Log) when is_list(Log) -> [{log_entries_redacted, length(Log)}];
redact_log(_Other)                 -> [].

%%%===================================================================
%%% Proxied calls dropped for their deadline
%%%===================================================================

%% A proxied call that was not sent because its caller's deadline passed while
%% it waited for a permit, or left too little time to make it. Counted in the
%% caller's process. The event feeds
%% yuzu_gw_upstream_calls_dropped_total{rpc_name} in yuzu_gw_telemetry.
drop_call(Rpc) ->
    telemetry:execute([yuzu, gw, upstream, call_dropped],
                      #{count => 1}, #{rpc_name => atom_to_binary(Rpc, utf8)}).

%%%===================================================================
%%% Circuit breaker logic
%%%===================================================================

%% @doc Record the result of an RPC and update circuit breaker state.
%%
%% A success never starts a registration replay (#5695): a recovery says the
%% upstream answers again, not that it lost what it knew. The server's heartbeat
%% verdict says that (replay_verdict/3).
%%
%% A call that ended because its connection was lost counts once per connection
%% (see the module doc): the first result naming a connection is a failure, any
%% later one naming the same connection is ignored.
record_result({ok, _}, State) ->
    on_success(State);
record_result({error, {connection_lost, Conn}}, #state{cb_lost_conns = Lost} = State)
  when is_pid(Conn) ->
    case lists:member(Conn, Lost) of
        true  -> State;
        false -> on_failure(State#state{cb_lost_conns =
                                            lists:sublist([Conn | Lost], ?MAX_LOST_CONNS)})
    end;
record_result({error, {Status, _Message}}, State) when ?IS_REQUEST_FAULT(Status) ->
    %% The server answered that the request itself was wrong: a fact about the
    %% request, not about the upstream. Neither a failure (it would open the
    %% breaker on a request that says nothing about the upstream) nor a success (it would
    %% reset real failures, and a closed breaker's success after failures
    %% triggers a replay): the state is untouched.
    State;
record_result({error, _}, State) ->
    on_failure(State);
record_result({local_error, _}, State) ->
    %% The request could not be encoded here and never left the gateway: not a
    %% fact about the upstream, so neither a success nor a failure.
    State;
record_result(unacknowledged, State) ->
    %% NOTIFY-ACK: the server answered a notification acknowledged=false. It
    %% answered, so it is not failing; it did not record the notice, so this is
    %% no proof of recovery either (it must not wipe out real failures, nor
    %% close a half_open breaker): the state is untouched.
    State.

%% @doc A success: the consecutive failures are over. Nothing is replayed (see
%% record_result/2): if the server came back without its state, its heartbeat
%% verdicts list the sessions it does not know.
on_success(#state{cb_state = closed, cb_failures = 0} = State) ->
    %% Steady state — nothing recovered.
    State;
on_success(#state{cb_state = closed} = State) ->
    %% Closed but cb_failures > 0: the upstream had failing RPCs and answers
    %% again, without enough consecutive failures to trip the breaker.
    logger:info("Upstream recovered (closed, ~b prior failures)",
                [State#state.cb_failures]),
    State#state{cb_failures = 0};
on_success(#state{cb_state = half_open, cb_base_timeout = BaseTimeout} = State) ->
    %% Probe succeeded — close the circuit, reset backoff.
    logger:info("Circuit breaker: half_open -> closed (probe succeeded)"),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"closed">>}),
    publish_breaker(closed),
    State#state{
        cb_state      = closed,
        cb_failures   = 0,
        cb_cur_timeout = BaseTimeout
    }.

on_failure(#state{cb_state = closed, cb_failures = F, cb_threshold = T} = State) ->
    NewF = F + 1,
    case NewF >= T of
        true  -> trip_circuit(State#state{cb_failures = NewF});
        false -> State#state{cb_failures = NewF}
    end;
on_failure(#state{cb_state = half_open} = State) ->
    %% Probe failed — reopen with doubled timeout
    logger:warning("Circuit breaker: half_open -> open (probe failed, increasing backoff)"),
    trip_circuit(State).

trip_circuit(#state{cb_cur_timeout = CurTimeout, cb_max_timeout = MaxTimeout} = State) ->
    %% Cancel any existing timer
    cancel_timer(State#state.cb_timer),

    %% Exponential backoff: double the timeout, capped at max
    NewTimeout = min(CurTimeout * 2, MaxTimeout),
    TRef = erlang:send_after(CurTimeout, self(), circuit_half_open),

    logger:warning("Circuit breaker: OPEN (will probe in ~bms)", [CurTimeout]),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"open">>}),

    publish_breaker(open),
    State#state{
        cb_state      = open,
        cb_cur_timeout = NewTimeout,
        cb_timer      = TRef
    }.

cancel_timer(undefined) -> ok;
cancel_timer(TRef) -> erlang:cancel_timer(TRef).

%%%===================================================================
%%% Pending stream-status notifications (#4632)
%%%===================================================================

%% @doc The peer address of a notification, made safe by yuzu_gw_peer_addr. A
%% change is logged at debug level with the agent id and the original size only,
%% never the value itself.
-spec sanitize_peer_addr(binary(), term()) -> binary().
sanitize_peer_addr(AgentId, PeerAddr0) ->
    %% The result is always the sanitiser's copy, also when the value is equal to
    %% the input: the input may be a sub-binary that pins a large parent.
    PeerAddr = yuzu_gw_peer_addr:sanitize(PeerAddr0),
    case PeerAddr =:= PeerAddr0 of
        true ->
            ok;
        false ->
            logger:debug("Stream status notification for ~s: peer address replaced "
                         "(original size ~b bytes)",
                         [yuzu_gw_env:log_text(AgentId), peer_addr_size(PeerAddr0)])
    end,
    PeerAddr.

peer_addr_size(Addr) when is_binary(Addr) -> byte_size(Addr);
peer_addr_size(_Addr) -> 0.

%% @doc Send held notifications, first in first out, subject to the breaker.
%% Closed: drain up to the notify budget, the pending store first, then the
%% resends of refused notices into the slots left (at most
%% ?MAX_UNACKED_INFLIGHT of them). Open: nothing is sent, every entry stays
%% held. Half_open: only the single generation-aware probe is sent (the head
%% held entry, or a due resend when nothing is held, one at a time) and every
%% other entry stays held until the probe resolves. Called at the end of every
%% handler that can free a slot, close the breaker or add an entry, so there is
%% one send path and a new arrival never overtakes a held one.
-spec drain(#state{}) -> #state{}.
drain(#state{mode = flushed} = State) ->
    State;
drain(#state{mode = flushing, cb_state = CbState} = State) when CbState =/= closed ->
    %% The last gasp sends whatever the breaker says: it is the only chance.
    %% The breaker is not consulted or moved (count_flushed/2).
    Drained = drain(State#state{cb_state = closed}),
    Drained#state{cb_state = CbState};
drain(#state{cb_state = closed} = State) ->
    drain_unacked(drain_fresh(State));
drain(#state{cb_state = half_open, notify_probe = undefined, notify_pids = Pids,
             notify_pending = Pending} = State)
        when map_size(Pids) < ?MAX_NOTIFY_INFLIGHT ->
    case yuzu_gw_notify_queue:take(Pending) of
        empty ->
            %% Nothing held: a due resend is the probe, so a breaker that
            %% half-opened with only refused notices waiting is still decided.
            case take_ready_unacked(State) of
                {none, State1}            -> State1;
                {Key, Event, State1} -> start_probe(Key, Event, true, State1)
            end;
        {Key, Event, Pending1} ->
            start_probe(Key, Event, false,
                        mark_unacked_taken(Key, State#state{notify_pending = Pending1}))
    end;
drain(State) ->
    State.

%% The closed drain of the pending store, up to the notify budget.
drain_fresh(#state{notify_pids = Pids, notify_pending = Pending} = State) ->
    case map_size(Pids) < notify_limit_now(State) of
        false ->
            State;
        true ->
            %% Per-key order: the head waits while an earlier event for the same
            %% key is still in flight, so a CONNECTED and the DISCONNECTED after
            %% it can never reach the server the other way round.
            case yuzu_gw_notify_queue:peek_key(Pending) of
                {empty, Pending0} ->
                    State#state{notify_pending = Pending0};
                {ok, HeadKey, Pending0} ->
                    case key_in_flight(HeadKey, Pids) of
                        true ->
                            State#state{notify_pending = Pending0};
                        false ->
                            {Key, Ev, Pending1} = yuzu_gw_notify_queue:take(Pending0),
                            State1 = mark_unacked_taken(Key, State#state{notify_pending = Pending1}),
                            {_Pid, State2} = spawn_notify(Key, Ev, State1),
                            drain_fresh(State2)
                    end
            end
    end.

%% NOTIFY-ACK: the due resends, into the slots the pending store left, at most
%% ?MAX_UNACKED_INFLIGHT in flight. Not during a planned stop's last gasp
%% (flush_unacked/1 has dealt with the retry set by then).
drain_unacked(#state{mode = flushing} = State) ->
    State;
drain_unacked(#state{notify_pids = Pids, notify_unacked_pids = UPids} = State) ->
    case map_size(Pids) < notify_limit_now(State) andalso
         map_size(UPids) < ?MAX_UNACKED_INFLIGHT of
        false ->
            State;
        true ->
            case take_ready_unacked(State) of
                {none, State1} ->
                    State1;
                {Key, Ev, State1} ->
                    {Pid, State2} = spawn_notify(Key, Ev, State1),
                    drain_unacked(State2#state{notify_unacked_pids = UPids#{Pid => Key}})
            end
    end.

%% One notification send on its own monitored worker. The result goes to this
%% process before the worker exits, so it is in the mailbox ahead of the 'DOWN'
%% that frees the slot.
spawn_notify(Key, {AgentId, Notification} = Ev, #state{notify_pids = Pids, cb_gen = Gen} = State) ->
    Server = self(),
    Timeout = notify_rpc_timeout(State),
    {Pid, _MonRef} = spawn_monitor(fun() ->
        Result = ack_result(do_rpc('NotifyStreamStatus', Notification, notify_stream, #{},
                                   Timeout)),
        log_notify_result(AgentId, Result),
        Server ! {notify_result, self(), Result}
    end),
    {Pid, State#state{notify_pids = Pids#{Pid => {Key, class_of(Notification), Ev, Gen}}}}.

%% The half_open probe: the head held entry (or a due resend), sent on a
%% monitored worker like any other, but it reports its result to this process
%% (send before exit, so the result reaches the mailbox before the 'DOWN'). The
%% message carries the result only, never the event.
start_probe(Key, {AgentId, Notification} = Event, IsResend,
            #state{notify_pids = Pids, notify_unacked_pids = UPids, cb_gen = Gen,
                   notify_probe_timeout_ms = ProbeTimeout} = State) ->
    Server = self(),
    {Pid, MonRef} = spawn_monitor(fun() ->
        Result = ack_result(do_rpc('NotifyStreamStatus', Notification, notify_stream)),
        case Result of
            {local_error, _} ->
                %% Logged once, by resolve_probe/3, when it evicts the event.
                ok;
            _ ->
                log_notify_result(AgentId, Result)
        end,
        Server ! {notify_probe_result, self(), Gen, Result}
    end),
    %% The gateway's own deadline for the probe (the client's bounds are
    %% library defaults an endpoint setting can remove): resolved or
    %% cancelled with the probe, see handle_info({notify_probe_timeout, ...}).
    Timer = erlang:send_after(ProbeTimeout, Server, {notify_probe_timeout, Pid, Gen}),
    UPids1 = case IsResend of
                 true  -> UPids#{Pid => Key};
                 false -> UPids
             end,
    State#state{notify_pids = Pids#{Pid => {Key, class_of(Notification), Event, Gen}},
                notify_unacked_pids = UPids1,
                notify_probe = #{pid => Pid, mref => MonRef, timer => Timer,
                                 gen => Gen, key => Key, event => Event}}.

%% The warning a failed notification worker logs (a refusal is logged by this
%% process, rate limited, see settle_unacked/5).
log_notify_result(_AgentId, unacknowledged) ->
    ok;
log_notify_result(AgentId, Result) ->
    case public_result(Result) of
        {ok, _} -> ok;
        {error, Reason} ->
            logger:warning("Failed to notify stream status for ~s: ~p",
                           [yuzu_gw_env:log_text(AgentId), Reason])
    end.

%% @doc Retire the probe attempt: clear the record and free its slot, decide the
%% event, then (separately) decide the breaker. Called once per probe, by the
%% first of its result, its 'DOWN' and its deadline (which kills the worker).
%%
%% The event: ok retires it; an error gives it back at the head of the store
%% (the reserved slot guarantees it fits; a newer event for the same key wins and
%% the old one is dropped and counted); an acknowledged=false answer sends it to
%% the retry set (NOTIFY-ACK), like any refused send.
%%
%% A local encode exception ({local_error, _}) evicts the event instead and
%% leaves the breaker untouched (the first clause).
%%
%% The breaker: moved only when it is still half_open AND Gen is the generation
%% now current. In any other state the result is stale (a call path RPC closed or
%% reopened the breaker meanwhile, or it went half_open again): the breaker is
%% not touched, and on_success/on_failure have no clause for an open breaker. A
%% refusal does not move it either (record_result/2): the breaker stays
%% half_open, and the next held entry (or due resend) is probed at once.
-spec resolve_probe(non_neg_integer(), notify_result(), #state{}) -> #state{}.
resolve_probe(_Gen, {local_error, {Class, Why}},
              #state{notify_probe = #{pid := Pid, mref := MonRef, timer := Timer,
                                      key := Key, event := {AgentId, Notification}},
                     notify_pids = Pids} = State) ->
    %% The head held entry could not be encoded here, and the same payload fails
    %% the same way on every probe: requeueing it would reopen the breaker for
    %% ever. Evict it, once, and leave the breaker alone (it is not a fact about
    %% the upstream); the caller's drain/1 then probes the next head at once. The
    %% failure is already counted by rpc_errors_total{code="encode"}.
    retire_probe(MonRef, Timer),
    emit_notify_lost(class_of(Notification), rejected, 1),
    logger:warning("Evicted held stream status notification for ~s: it cannot be "
                   "encoded (~p:~p); the circuit breaker is not affected",
                   [yuzu_gw_env:log_text(AgentId), Class, Why]),
    retire_probe_event(Pid, Key, lost, State#state{notify_probe = undefined,
                                                    notify_pids = maps:remove(Pid, Pids)});
resolve_probe(_Gen, {error, {Status, _Message}},
              #state{notify_probe = #{pid := Pid, mref := MonRef, timer := Timer,
                                      key := Key, event := {_AgentId, Notification}},
                     notify_pids = Pids} = State) when ?IS_REQUEST_FAULT(Status) ->
    %% The server answered that this notification itself was wrong. Requeueing it
    %% would be answered the same way by every probe, for ever (the breaker is
    %% not touched by such an answer, so nothing would slow the loop), so it is
    %% retired like an answered event. The worker already logged the failure; the
    %% breaker is left as it is, as for a local encode exception.
    retire_probe(MonRef, Timer),
    emit_notify_lost(class_of(Notification), rejected, 1),
    retire_probe_event(Pid, Key, lost, State#state{notify_probe = undefined,
                                                    notify_pids = maps:remove(Pid, Pids)});
resolve_probe(Gen, Result,
              #state{notify_probe = #{pid := Pid, mref := MonRef, timer := Timer,
                                      key := Key, event := Event},
                     notify_pids = Pids} = State) ->
    retire_probe(MonRef, Timer),
    State0 = forget_unacked_pid(Pid, State#state{notify_probe = undefined,
                                                 notify_pids = maps:remove(Pid, Pids)}),
    {Retry, State1} = take_unacked_attempt(Key, State0),
    Class = class_of(element(2, Event)),
    State2 =
        case Result of
            {ok, _} ->
                retry_ended(Retry, acknowledged),
                State1;
            unacknowledged ->
                settle_unacked(Retry, Key, Class, Event, State1);
            {error, _} ->
                #state{notify_pending = Pending} = State1,
                case yuzu_gw_notify_queue:push_front(Key, Event, Class, Pending) of
                    {inserted, Q} ->
                        hold_unacked(Retry, Key, State1#state{notify_pending = Q});
                    {superseded, Q} ->
                        telemetry:execute([yuzu, gw, upstream, notify_coalesced],
                                          #{count => 1}, #{}),
                        State1#state{notify_pending = Q}
                end
        end,
    #state{cb_state = CbState, cb_gen = CbGen} = State2,
    case CbState =:= half_open andalso Gen =:= CbGen of
        true  -> record_result(Result, State2);
        false -> State2
    end.

%% A retired probe's event: its resend slot and retry-set entry go too.
retire_probe_event(Pid, Key, Outcome, State) ->
    {Retry, State1} = take_unacked_attempt(Key, forget_unacked_pid(Pid, State)),
    retry_ended(Retry, Outcome),
    State1.

%% @doc The probe is over: drop its monitor (and any 'DOWN' already delivered)
%% and its deadline timer. A timeout message that was already delivered is
%% harmless: it names a probe that is no longer recorded.
-spec retire_probe(reference(), reference()) -> ok.
retire_probe(MonRef, Timer) ->
    erlang:demonitor(MonRef, [flush]),
    _ = erlang:cancel_timer(Timer),
    ok.

%% @doc Decide a finished send's event (see the notify_result clause). A send
%% that was a resend of a refused notice (or one the retry set gave back to the
%% pending store) settles its retry-set entry too.
-spec settle_notify(yuzu_gw_notify_queue:key(), connected | disconnected,
                    yuzu_gw_notify_queue:event(), notify_result(), #state{}) -> #state{}.
settle_notify(Key, Class, Event, Result, State0) ->
    {Retry, State} = take_unacked_attempt(Key, State0),
    settle_notify(Retry, Key, Class, Event, Result, State).

settle_notify(Retry, _Key, _Class, _Event, {ok, _}, State) ->
    retry_ended(Retry, acknowledged),
    State;
settle_notify(Retry, Key, Class, Event, unacknowledged, State) ->
    settle_unacked(Retry, Key, Class, Event, State);
settle_notify(Retry, _Key, Class, _Event, {local_error, _}, State) ->
    emit_notify_lost(Class, rejected, 1),
    retry_ended(Retry, lost),
    State;
settle_notify(Retry, _Key, Class, _Event, {error, {Status, _Message}}, State)
  when ?IS_REQUEST_FAULT(Status) ->
    emit_notify_lost(Class, rejected, 1),
    retry_ended(Retry, lost),
    State;
settle_notify(Retry, _Key, Class, _Event, {error, _}, #state{mode = flushing} = State) ->
    %% The last gasp does not retry: a failure is a notice the server will not
    %% get from this gateway.
    emit_notify_lost(Class, shutdown, 1),
    retry_ended(Retry, lost),
    State;
settle_notify(Retry, Key, Class, Event, {error, _}, #state{notify_pending = Pending} = State) ->
    case yuzu_gw_notify_queue:push_front(Key, Event, Class, Pending) of
        {inserted, Pending1} ->
            telemetry:execute([yuzu, gw, upstream, notify_requeued], #{count => 1}, #{}),
            hold_unacked(Retry, Key, note_held(State#state{notify_pending = Pending1}));
        {superseded, Pending1} ->
            telemetry:execute([yuzu, gw, upstream, notify_coalesced], #{count => 1}, #{}),
            retry_ended(Retry, superseded),
            State#state{notify_pending = Pending1}
    end.

%%%===================================================================
%%% Notices the server did not acknowledge (NOTIFY-ACK, #5695)
%%%===================================================================

%% @doc A worker's result, with an OK answer of acknowledged=false told apart:
%% the server answered, but did not record the notice. Only an explicit `false'
%% counts (a decoded StreamStatusAck always carries the field; an OK without a
%% decoded map is not a refusal).
-spec ack_result(rpc_result()) -> notify_result().
ack_result({ok, #{acknowledged := false}}) -> unacknowledged;
ack_result(Result) -> Result.

%% @doc A fresh event for Key supersedes its retry-set entry: a waiting or due
%% resend is cancelled, one given back to the pending store is replaced there by
%% the caller's put, and one in flight is remembered as cancelled, so its result
%% is dropped (per-key order keeps the fresh event behind it).
-spec cancel_unacked(yuzu_gw_notify_queue:key(), #state{}) -> #state{}.
cancel_unacked(Key, #state{notify_unacked = U, notify_unacked_cancelled = C} = State) ->
    case maps:take(Key, U) of
        error ->
            State;
        {#{status := inflight} = Entry, U1} ->
            emit_unacked_ended(superseded),
            slow_out(Entry, State#state{notify_unacked = U1,
                                        notify_unacked_cancelled = C#{Key => true}});
        {#{status := Status} = Entry, U1} ->
            cancel_unacked_timer(Status),
            emit_unacked_ended(superseded),
            slow_out(Entry, State#state{notify_unacked = U1})
    end.

cancel_unacked_timer({waiting, TRef}) ->
    _ = erlang:cancel_timer(TRef),
    ok;
cancel_unacked_timer(_Status) ->
    ok.

%% @doc The pending store evicted Key's event: an entry that had given it back
%% to the store has nothing left to send.
-spec drop_held_unacked(yuzu_gw_notify_queue:key(), #state{}) -> #state{}.
drop_held_unacked(Key, #state{notify_unacked = U} = State) ->
    case maps:find(Key, U) of
        {ok, #{status := held} = Entry} ->
            emit_unacked_ended(lost),
            slow_out(Entry, State#state{notify_unacked = maps:remove(Key, U)});
        _ ->
            State
    end.

%% @doc Key's event was taken from the pending store to be sent: an entry that
%% had given it back there is in flight again.
-spec mark_unacked_taken(yuzu_gw_notify_queue:key(), #state{}) -> #state{}.
mark_unacked_taken(Key, #state{notify_unacked = U} = State) ->
    case maps:find(Key, U) of
        {ok, #{status := held} = Entry} ->
            State#state{notify_unacked = U#{Key := Entry#{status := inflight}}};
        _ ->
            State
    end.

%% @doc A send for Key resolved (a result, or its worker died): what the retry
%% set knew of it. `none': a first send; `cancelled': a resend a newer event
%% superseded; `{retry, Entry}': a resend, its entry removed (the caller puts
%% it back if it is still owed).
-spec take_unacked_attempt(yuzu_gw_notify_queue:key(), #state{}) ->
          {none | cancelled | {retry, unacked()}, #state{}}.
take_unacked_attempt(Key, #state{notify_unacked = U, notify_unacked_cancelled = C} = State) ->
    case maps:take(Key, C) of
        {true, C1} ->
            {cancelled, State#state{notify_unacked_cancelled = C1}};
        error ->
            case maps:find(Key, U) of
                {ok, #{status := inflight} = Entry} ->
                    {{retry, Entry},
                     slow_out(Entry, State#state{notify_unacked = maps:remove(Key, U)})};
                _ ->
                    {none, State}
            end
    end.

%% How a resend's entry ended, counted once per entry (a cancelled one was
%% counted when it was cancelled).
retry_ended({retry, _Entry}, Outcome) -> emit_unacked_ended(Outcome);
retry_ended(_NoneOrCancelled, _Outcome) -> ok.

%% A failed resend was given back to the pending store: its entry is kept (as
%% `held'), so the backoff goes on from where it was if it is refused again.
hold_unacked({retry, Entry}, Key, #state{notify_unacked = U} = State) ->
    slow_in(Entry, State#state{notify_unacked = U#{Key => Entry#{status := held}}});
hold_unacked(_NoneOrCancelled, _Key, State) ->
    State.

%% A notify worker is done: its resend slot is free.
forget_unacked_pid(Pid, #state{notify_unacked_pids = UPids} = State) ->
    State#state{notify_unacked_pids = maps:remove(Pid, UPids)}.

%% @doc The server answered acknowledged=false: the notice was not delivered.
%% Counted, then held for a resend after a backoff, unless
%%   - a newer event for the key superseded it (dropped);
%%   - a planned stop's last gasp is running (lost, `unacknowledged');
%%   - it is a DISCONNECTED first refused more than the window ago (lost);
%%   - the retry set is full (notify_pending_max entries; lost).
%% A CONNECTED has no window: it is resent while this node holds its session
%% (unacked_due/3). The breaker is not touched (record_result/2).
-spec settle_unacked(none | cancelled | {retry, unacked()}, yuzu_gw_notify_queue:key(),
                     connected | disconnected, yuzu_gw_notify_queue:event(), #state{}) ->
          #state{}.
settle_unacked(Retry, Key, Class, Event, State) ->
    telemetry:execute([yuzu, gw, upstream, notify_unacknowledged], #{count => 1},
                      #{event => Class}),
    settle_unacked1(Retry, Key, Class, Event, State).

settle_unacked1(cancelled, _Key, _Class, _Event, State) ->
    State;
settle_unacked1(Retry, _Key, Class, {AgentId, _}, #state{mode = flushing} = State) ->
    yuzu_gw_safe_call:warn_limited(notify_unacknowledged,
                                   "Server did not record the ~s stream status notice for ~s "
                                   "(acknowledged=false) during the planned-stop flush; not "
                                   "sent again", [Class, yuzu_gw_env:log_text(AgentId)]),
    emit_notify_lost(Class, unacknowledged, 1),
    retry_ended(Retry, lost),
    State;
settle_unacked1(Retry, Key, Class, {AgentId, _} = Event,
                #state{notify_pending = Pending, notify_unacked = U,
                       notify_pending_max = Cap, unacked_base_ms = Base, unacked_max_ms = Max,
                       unacked_disc_window_ms = Window, unacked_slow_after = SlowAfter,
                       unacked_slow_max_ms = SlowMax} = State) ->
    Now = erlang:monotonic_time(millisecond),
    {First, Prev, Refusals} = case Retry of
                                  {retry, #{first := F, delay := D} = E} ->
                                      {F, D, maps:get(refusals, E, 1) + 1};
                                  none ->
                                      {Now, undefined, 1}
                              end,
    Over = Class =:= disconnected andalso Now - First >= Window,
    Full = Retry =:= none andalso map_size(U) >= Cap,
    case yuzu_gw_notify_queue:is_held(Key, Pending) of
        true ->
            %% A newer event for the key is held already (it would have cancelled
            %% this entry; kept for safety): it wins.
            retry_ended(Retry, superseded),
            State;
        false when Over; Full ->
            yuzu_gw_safe_call:warn_limited(notify_unacknowledged,
                                           "Server did not record the ~s stream status notice for "
                                           "~s (acknowledged=false); giving up after ~b ms (~s)",
                                           [Class, yuzu_gw_env:log_text(AgentId), Now - First,
                                            case Over of
                                                true -> "the disconnected window passed";
                                                false -> "the retry set is full"
                                            end]),
            emit_notify_lost(Class, unacknowledged, 1),
            retry_ended(Retry, lost),
            State;
        false ->
            Entry0 = #{event => Event, class => Class, first => First, refusals => Refusals},
            Delay = case is_slow(Entry0, SlowAfter) of
                        true  -> slow_unacked_delay(SlowMax);
                        false -> next_unacked_delay(Prev, Base, Max)
                    end,
            TRef = erlang:start_timer(Delay, self(), {notify_unacked_due, Key}),
            yuzu_gw_safe_call:warn_limited(notify_unacknowledged,
                                           "Server did not record the ~s stream status notice for "
                                           "~s (acknowledged=false); sending it again in ~b ms",
                                           [Class, yuzu_gw_env:log_text(AgentId), Delay]),
            Entry = Entry0#{delay => Delay, status => {waiting, TRef}},
            slow_in(Entry, State#state{notify_unacked = U#{Key => Entry}})
    end.

%% @doc The slow phase's delay (#6059 stopgap): uniform in 0.8 x SlowMax ..
%% SlowMax. A fixed interval jittered by up to 20% (down, so SlowMax stays the
%% longest delay) rather than decorrelated jitter: that one's floor stays the
%% base, so a third of its draws at the cap fall below it, anywhere down to the
%% base. The band holds every slowed key to at most one resend per 0.8 x
%% SlowMax, and still spreads keys that were slowed together over a fifth of
%% the interval.
-spec slow_unacked_delay(pos_integer()) -> pos_integer().
slow_unacked_delay(SlowMax) ->
    Lo = max(1, SlowMax - SlowMax div 5),
    Lo + rand:uniform(SlowMax - Lo + 1) - 1.

%% @doc Whether an entry is in the slow phase: a CONNECTED refused SlowAfter
%% times in a row or more. A DISCONNECTED never is (its window bounds it).
-spec is_slow(map(), pos_integer()) -> boolean().
is_slow(#{class := connected} = Entry, SlowAfter) ->
    maps:get(refusals, Entry, 1) >= SlowAfter;
is_slow(_Entry, _SlowAfter) ->
    false.

%% The count of entries in the slow phase follows every entry put into the
%% retry set (slow_in/2) and every entry taken out of it (slow_out/2); an entry
%% whose status changes in place keeps its count.
slow_in(Entry, #state{unacked_slow_after = SlowAfter, notify_unacked_slow = N} = State) ->
    case is_slow(Entry, SlowAfter) of
        true  -> State#state{notify_unacked_slow = N + 1};
        false -> State
    end.

slow_out(Entry, #state{unacked_slow_after = SlowAfter, notify_unacked_slow = N} = State) ->
    case is_slow(Entry, SlowAfter) of
        true  -> State#state{notify_unacked_slow = max(0, N - 1)};
        false -> State
    end.

%% @doc The next backoff delay: decorrelated jitter, min(Max, uniform(Base,
%% 3 x Prev)), from Base for the first refusal.
-spec next_unacked_delay(undefined | pos_integer(), pos_integer(), pos_integer()) ->
          pos_integer().
next_unacked_delay(undefined, Base, Max) ->
    next_unacked_delay(Base, Base, Max);
next_unacked_delay(Prev, Base, Max) ->
    Hi = max(Base, 3 * Prev),
    min(Max, Base + rand:uniform(Hi - Base + 1) - 1).

%% @doc A backoff ended. A CONNECTED is resent only while this node still holds
%% its session (a session that ended or was replaced has nothing to announce;
%% its DISCONNECTED normally cancelled the entry already). A registry that is
%% not running does not stop it: that is not evidence the session is gone.
%%
%% While a crashed agent owner is restarted (OWNER-RESTART) its registry row is
%% briefly absent: the predecessor's DOWN removed it and the successor has not
%% recovered it yet. A CONNECTED that becomes due then ends as session_gone.
%% That is harmless: the successor sends the session's DISCONNECTED, and on
%% recovery a fresh CONNECTED of its own (yuzu_gw_agent:try_recover/2), so the
%% dropped resend would have been superseded anyway; if recovery fails the
%% session has ended and there is nothing to announce.
-spec unacked_due(yuzu_gw_notify_queue:key(), unacked(), #state{}) -> #state{}.
unacked_due({AgentId, SessionId, _Home} = Key, #{class := Class} = Entry,
            #state{notify_unacked = U, notify_unacked_ready = Q} = State) ->
    Held = Class =:= disconnected orelse
           case yuzu_gw_registry:lookup_local_session(AgentId) of
               {ok, {_Pid, S}} -> ensure_binary(S) =:= SessionId;
               error -> false;
               {error, unavailable} -> true
           end,
    case Held of
        true ->
            Q1 = queue:in(Key, Q),
            Q2 = case queue:len(Q1) > 2 * map_size(U) + 64 of
                     true  -> queue:filter(fun(K) -> is_ready_unacked(K, U) end, Q1);
                     false -> Q1
                 end,
            State#state{notify_unacked = U#{Key := Entry#{status := ready}},
                        notify_unacked_ready = Q2};
        false ->
            emit_unacked_ended(session_gone),
            slow_out(Entry, State#state{notify_unacked = maps:remove(Key, U)})
    end.

is_ready_unacked(Key, U) ->
    case maps:find(Key, U) of
        {ok, #{status := ready}} -> true;
        _ -> false
    end.

%% @doc The next due resend, marked in flight, or `none'. Keys that are no
%% longer due (cancelled or re-armed since they were queued) are skipped. A key
%% with a send in flight cannot be due (its entry would be `inflight'); one is
%% left queued, for safety.
-spec take_ready_unacked(#state{}) ->
          {none, #state{}} | {yuzu_gw_notify_queue:key(), yuzu_gw_notify_queue:event(), #state{}}.
take_ready_unacked(#state{notify_unacked = U, notify_unacked_ready = Q,
                          notify_pids = Pids} = State) ->
    case queue:out(Q) of
        {empty, _} ->
            {none, State};
        {{value, Key}, Q1} ->
            case maps:find(Key, U) of
                {ok, #{status := ready, event := Event} = Entry} ->
                    case key_in_flight(Key, Pids) of
                        false ->
                            {Key, Event,
                             State#state{notify_unacked = U#{Key := Entry#{status := inflight}},
                                         notify_unacked_ready = Q1}};
                        true ->
                            {none, State}
                    end;
                _ ->
                    take_ready_unacked(State#state{notify_unacked_ready = Q1})
            end
    end.

%% @doc A planned stop's last gasp begins. A refused CONNECTED that waits for a
%% resend is dropped (the session ends with the stop; counted lost, shutdown).
%% A refused DISCONNECTED that waits is put at the head of the pending store and
%% sent with the rest (a stale CONNECTED left at the server is the worse
%% outcome). Entries in flight or given back to the store stay: their results
%% settle them, and nothing is resent from here on.
-spec flush_unacked(#state{}) -> #state{}.
flush_unacked(#state{notify_unacked = U} = State) ->
    State1 = maps:fold(fun flush_unacked_entry/3, State, U),
    State1#state{notify_unacked_ready = queue:new()}.

flush_unacked_entry(_Key, #{status := Status}, State) when Status =:= inflight;
                                                           Status =:= held ->
    State;
flush_unacked_entry(Key, #{status := Status, class := connected} = Entry,
                    #state{notify_unacked = U} = State) ->
    cancel_unacked_timer(Status),
    emit_notify_lost(connected, shutdown, 1),
    emit_unacked_ended(lost),
    slow_out(Entry, State#state{notify_unacked = maps:remove(Key, U)});
flush_unacked_entry(Key, #{status := Status, class := disconnected, event := Event} = Entry,
                    #state{notify_unacked = U, notify_pending = Pending} = State) ->
    cancel_unacked_timer(Status),
    case yuzu_gw_notify_queue:push_front(Key, Event, disconnected, Pending) of
        {inserted, Pending1} ->
            note_held(State#state{notify_unacked = U#{Key := Entry#{status := held}},
                                  notify_pending = Pending1});
        {superseded, Pending1} ->
            emit_unacked_ended(superseded),
            slow_out(Entry, State#state{notify_unacked = maps:remove(Key, U),
                                        notify_pending = Pending1})
    end.

%% @doc The retry set is dropped with the process or the end of a flush. What
%% only it holds (entries waiting or due) is counted lost (shutdown) here, by
%% class; entries in flight or given back to the store are counted with those.
-spec drop_unacked(#state{}) -> non_neg_integer().
drop_unacked(#state{notify_unacked = U}) ->
    maps:fold(fun(_Key, #{status := Status, class := Class}, N) ->
                      emit_unacked_ended(lost),
                      case Status of
                          S when S =:= inflight; S =:= held ->
                              N;
                          _ ->
                              cancel_unacked_timer(Status),
                              emit_notify_lost(Class, shutdown, 1),
                              N + 1
                      end
              end, 0, U).

emit_unacked_keys(N, Slow) ->
    telemetry:execute([yuzu, gw, upstream, notify_unacked], #{keys => N, slow_keys => Slow},
                      #{}).

emit_unacked_ended(Outcome) ->
    telemetry:execute([yuzu, gw, upstream, notify_unacked_ended], #{count => 1},
                      #{outcome => Outcome}).

%% The slots held back for Key's admission: one per send in flight whose event
%% may come back (not yet resolved), except one for Key itself.
reserved_slots(Key, #state{notify_pids = Pids}) ->
    maps:fold(fun(_Pid, {K, _, _, _}, N) when K =/= Key -> N + 1;
                 (_Pid, _Other, N) -> N
              end, 0, Pids).

key_in_flight(Key, Pids) ->
    lists:any(fun({K, _, _, _}) -> K =:= Key; (_) -> false end, maps:values(Pids)).

class_of(#{event := 'CONNECTED'}) -> connected;
class_of(_Notification)           -> disconnected.

%% The notify sends drain/1 may have in flight now.
notify_limit_now(#state{mode = flushing}) -> ?STOP_NOTIFY_INFLIGHT;
notify_limit_now(_State)                   -> ?MAX_NOTIFY_INFLIGHT.

%% A send during the last gasp gets what is left of the flush, at most the usual.
notify_rpc_timeout(#state{mode = flushing, flush_deadline = Deadline}) ->
    max(1, min(?DEFAULT_RPC_TIMEOUT_MS, Deadline - erlang:monotonic_time(millisecond)));
notify_rpc_timeout(_State) ->
    ?DEFAULT_RPC_TIMEOUT_MS.

%% A result of a last-gasp send: counted, the breaker untouched.
count_flushed({ok, _}, #state{flush_sent = N} = State) -> State#state{flush_sent = N + 1};
count_flushed(_Result, State) -> State.

%% The last gasp is over when nothing is held and nothing is in flight.
maybe_end_flush(#state{mode = flushing, notify_pending = Pending, notify_pids = Pids} = State) ->
    case yuzu_gw_notify_queue:size(Pending) =:= 0 andalso
         not lists:any(fun(V) -> V =/= resolved end, maps:values(Pids)) of
        true  -> end_flush(State);
        false -> State
    end;
maybe_end_flush(State) ->
    State.

%% End the last gasp: count what is left (held, and sends still in flight) as
%% lost, reply to the caller, and refuse everything from now on.
end_flush(#state{flush_from = From, flush_timer = Timer, flush_sent = Sent,
                 notify_pending = Pending, notify_pids = Pids} = State) ->
    _ = erlang:cancel_timer(Timer),
    Held = held_by_class(Pending),
    InFlight = [C || {_K, C, _E, _G} <- maps:values(Pids)],
    Left = lists:sum([N || {_, N} <- Held]) + length(InFlight) + drop_unacked(State),
    [emit_notify_lost(C, shutdown, N) || {C, N} <- Held],
    [emit_notify_lost(C, shutdown, 1) || C <- InFlight],
    case Left of
        0 -> logger:info("Planned stop: ~b stream-status notification(s) sent, none left", [Sent]);
        _ -> logger:warning("Planned stop: ~b stream-status notification(s) sent, ~b not sent "
                            "by the flush deadline (counted in "
                            "yuzu_gw_upstream_notify_lost_total{reason=\"shutdown\"})",
                            [Sent, Left])
    end,
    gen_server:reply(From, #{sent => Sent, left => Left}),
    %% Counted now, so neither their late results nor terminate/2 count them again.
    Resolved = maps:map(fun(_Pid, _V) -> resolved end, Pids),
    State#state{mode = flushed, flush_from = undefined, flush_timer = undefined,
                notify_pids = Resolved,
                notify_pending = yuzu_gw_notify_queue:new(yuzu_gw_notify_queue:cap(Pending)),
                notify_unacked = #{}, notify_unacked_ready = queue:new(),
                notify_unacked_pids = #{}, notify_unacked_cancelled = #{},
                notify_unacked_slow = 0}.

%% Held events by class, read once at the end of a flush or in terminate/2.
held_by_class(Pending) ->
    Classes = [class_of(N) || {_Key, {_Agent, N}} <- yuzu_gw_notify_queue:to_list(Pending)],
    [{C, length([x || C1 <- Classes, C1 =:= C])} || C <- [connected, disconnected]].

%% Track the high-water mark after the store grew.
note_held(#state{notify_pending = Pending, notify_hwm_cur = Cur} = State) ->
    case yuzu_gw_notify_queue:size(Pending) of
        N when N > Cur ->
            State1 = State#state{notify_hwm_cur = N},
            emit_notify_held(State1),
            State1;
        _ ->
            State
    end.

emit_notify_held(#state{notify_hwm_cur = Cur, notify_hwm_prev = Prev,
                        notify_pending_max = Max}) ->
    telemetry:execute([yuzu, gw, upstream, notify_held],
                      #{hwm => max(Cur, Prev), max => Max}, #{}).

emit_notify_lost(_Class, _Reason, 0) ->
    ok;
emit_notify_lost(Class, Reason, N) ->
    telemetry:execute([yuzu, gw, upstream, notify_lost], #{count => N},
                      #{event => Class, reason => Reason}).

%% The held-notification cap when notify_pending_max is not set (#5695): three
%% keys per agent connection the agent listeners admit (the sum of their
%% limits.max_connections), and at least 15,000. Why three: the store holds one
%% key per agent session and stream home touched while notices cannot be sent.
%% A server that is down lets no agent get a new session (ProxyRegister fails),
%% so an outage holds at most one DISCONNECTED per agent; a server that is up
%% but slow lets an agent that flaps register again, which holds its old
%% session's DISCONNECTED and its new session's CONNECTED: two per agent for
%% one flap of the whole fleet. Three leaves a third of the fleet room for a
%% second flap. 15,000 is three times the 5,000-agent target of a gateway, for a
%% listener with no connection ceiling. At the shipped ceiling of 60,000 that is
%% 180,000 keys (about 1 KB each held, see docs/user-manual/gateway.md), which
%% is a ceiling, not an allocation.
-spec default_notify_pending_max() -> pos_integer().
default_notify_pending_max() ->
    Listeners = case application:get_env(yuzu_gw, grpc_listeners, []) of
                    L when is_list(L) -> L;
                    _ -> []
                end,
    Conns = lists:sum([N || E <- Listeners, is_map(E), yuzu_grpc_listener:routes_agent(E),
                            N <- [maps:get(max_connections, maps:get(limits, E, #{}), infinity)],
                            is_integer(N), N > 0]),
    min(?MAX_NOTIFY_PENDING_MAX, max(?MIN_DEFAULT_NOTIFY_PENDING_MAX, 3 * Conns)).

%% @doc The two numbers the notify_queue gauges report: held keys and workers.
-spec notify_counts(#state{}) -> {non_neg_integer(), non_neg_integer()}.
notify_counts(#state{notify_pending = Pending, notify_pids = Pids}) ->
    {yuzu_gw_notify_queue:size(Pending), map_size(Pids)}.

%% @doc Report the gauges once per handler, and only when the handler changed
%% either number. Before is notify_counts/1 taken at the top of the handler.
-spec report_notify_counts({non_neg_integer(), non_neg_integer()}, #state{}) -> #state{}.
report_notify_counts(Before, #state{notify_pids = Pids, guardian_pids = GPids,
                                    notify_unacked = U, notify_unacked_slow = Slow,
                                    notify_unacked_reported = Reported,
                                    notify_unacked_slow_reported = SlowReported} = State) ->
    %% The lane figures the pressure sampler reads (lane_snapshot/0) follow the
    %% worker sets, which only the handlers that end here change.
    cell_put(?CELL_NOTIFY, map_size(Pids)),
    cell_put(?CELL_GUARDIAN, map_size(GPids)),
    case notify_counts(State) of
        Before                  -> ok;
        {Pending, Inflight}     -> emit_notify_queue(Pending, Inflight)
    end,
    %% NOTIFY-ACK: the keys awaiting a resend and those of them in the slow
    %% phase, reported when either changed.
    case map_size(U) of
        Reported when Slow =:= SlowReported ->
            State;
        Keys ->
            emit_unacked_keys(Keys, Slow),
            State#state{notify_unacked_reported = Keys, notify_unacked_slow_reported = Slow}
    end.

emit_notify_queue(Pending, Inflight) ->
    telemetry:execute([yuzu, gw, upstream, notify_queue],
                      #{pending => Pending, inflight => Inflight}, #{}).

%%%===================================================================
%%% Registration replay: the pump
%%%===================================================================

%% End of every handler that can change what the replay may do: drain the held
%% notifications, then pump the replay. The caller reports the notify gauges
%% (report_notify_counts/2 with the counts taken at the top of its handler).
settle(State) ->
    release_settled(maybe_end_flush(pump_replay(drain(State)))).

%% Answer every notify_settled/4 waiter whose key has no event held and no send
%% in flight (the half_open probe and every NOTIFY-ACK resend are in notify_pids
%% too). O(waiters x sends in flight); there are waiters only while restarted
%% agent owners recover.
%%
%% A settled key may still have a retry-set entry: a refused notice waiting for
%% its backoff, or due and queued (an entry given back to the pending store is
%% held, one being resent is in flight, so neither settles). It is cancelled
%% here, counted superseded, before the waiter is answered: the waiter's next
%% step presents the session to the server again (yuzu_gw_agent:try_recover/2),
%% and a resend of the predecessor's refused DISCONNECTED landing after that
%% would remove the session just recovered. A refused CONNECTED of the
%% predecessor is normally superseded already by the DISCONNECTED the successor
%% sent before it asked; either way none of the predecessor's notices is sent
%% after the successor's own. If the recovery then fails, what is lost is the
%% resend of a DISCONNECTED the server answered unknown_session: its route row,
%% if any, stops being routable when its lease runs out, as when the resend
%% window ends.
release_settled(#state{settle_waiters = W} = State) when map_size(W) =:= 0 ->
    State;
release_settled(#state{settle_waiters = W, notify_pending = Pending, notify_pids = Pids} = State) ->
    Settled = [K || K <- maps:keys(W), not yuzu_gw_notify_queue:is_held(K, Pending),
                    not key_in_flight(K, Pids)],
    State1 = lists:foldl(fun cancel_unacked/2, State, Settled),
    [[Ack ! {Ack, notify_settled} || Ack <- maps:get(K, W)] || K <- Settled],
    State1#state{settle_waiters = maps:without(Settled, W)}.

%% Start replay workers while there is work and room:
%%   - fewer workers than the replay cap (upstream_replay_concurrency, the
%%     regulator's replay sub-cap), or than one while the breaker is half_open:
%%     that one replay is the probe that decides whether it closes;
%%   - notify headroom: every adopted replay makes the agent re-send its
%%     CONNECTED, so the held notifications plus the replays in flight must
%%     stay under half of notify_pending_max (the rest is for real connects
%%     and disconnects). A replay held back by this resumes when a notify
%%     worker finishes.
%% An open breaker aborts the replay: the upstream went away again, and the
%% verdicts after it closes start a new one. Each worker is told the breaker generation,
%% so its result counts only if the breaker has not moved since.
pump_replay(#state{mode = Mode} = State) when Mode =/= running ->
    State;
pump_replay(#state{cb_state = open} = State) ->
    case replay_active(State) of
        true  -> abort_replay("circuit open", State);
        false -> State
    end;
pump_replay(#state{heal_replay = true, cb_state = closed, replay_walk = idle,
                   notify_pending = Pending, notify_pending_max = Max} = State) ->
    case yuzu_gw_notify_queue:size(Pending) < max(1, Max div 2) of
        true ->
            logger:info("A held CONNECTED notification was lost; replaying the "
                        "registrations so every agent re-sends its own"),
            pump_replay(start_full_replay(notify_loss, State#state{heal_replay = false}));
        false ->
            pump_replay_(State)
    end;
pump_replay(State) ->
    pump_replay_(State).

pump_replay_(State) ->
    case can_spawn_replay(State) of
        false ->
            maybe_finish_replay(State);
        true ->
            case next_replay_entry(State) of
                {none, State1} ->
                    maybe_finish_replay(State1);
                {error, unavailable, State1} ->
                    abort_replay("registry unavailable", State1);
                {Entry, State1} ->
                    pump_replay(start_replay_entry(Entry, State1))
            end
    end.

can_spawn_replay(#state{replay_pids = RPids, replay_limit = Limit, cb_state = CbState,
                        notify_pending = Pending, notify_pending_max = Max}) ->
    Cap = case CbState of half_open -> 1; _ -> Limit end,
    map_size(RPids) < Cap andalso
        yuzu_gw_notify_queue:size(Pending) + map_size(RPids) < max(1, Max div 2).

%% Pop the next entry: the queue first (verdict entries, then the current walk
%% chunk), then the next chunk of the walk.
next_replay_entry(#state{replay_queue = [Entry | Rest], replay_len = Len} = State) ->
    {Entry, set_replay_queue(State, Rest, Len - 1)};
next_replay_entry(#state{replay_queue = [], replay_walk = {walking, Cont, Left}} = State) ->
    case walk_chunk(Cont) of
        {[], '$end_of_table'} ->
            {none, end_walk(State)};
        {Rows, Next} ->
            Chunk = [{AgentId, SessionId, walk} || {AgentId, SessionId} <- Rows],
            N = length(Chunk),
            next_replay_entry(set_replay_queue(
                                State#state{replay_walk = {walking, Next, max(0, Left - N)}},
                                Chunk, N));
        unavailable ->
            {error, unavailable, end_walk(State)}
    end;
next_replay_entry(State) ->
    {none, State}.

%% One chunk of the walk: {AgentId, SessionId} of up to ?REPLAY_CHUNK rows. The
%% two columns are positions 1 and 4 of yuzu_gw_registry's row ({AgentId, Pid,
%% Node, SessionId, Plugins, ConnectedAt, Hostname, RegisterReq}); the stored
%% request (position 8) is NOT read here, the worker reads it through
%% yuzu_gw_registry:entries_for_sessions/1, so this process never holds more
%% than a chunk of small pairs. `unavailable' when the table is gone.
walk_chunk(start) ->
    MS = [{'$1', [{'>=', {size, '$1'}, 4}], [{{{element, 1, '$1'}, {element, 4, '$1'}}}]}],
    try ets:select(?AGENTS_TABLE, MS, ?REPLAY_CHUNK) of
        '$end_of_table' -> {[], '$end_of_table'};
        {Rows, Cont}    -> {Rows, Cont}
    catch error:badarg -> unavailable
    end;
walk_chunk('$end_of_table') ->
    {[], '$end_of_table'};
walk_chunk(Cont) ->
    try ets:select(Cont) of
        '$end_of_table' -> {[], '$end_of_table'};
        {Rows, Cont1}   -> {Rows, Cont1}
    catch error:badarg -> unavailable
    end.

end_walk(#state{replay_walk = {walking, _, _}} = State) ->
    _ = (catch ets:safe_fixtable(?AGENTS_TABLE, false)),
    State#state{replay_walk = idle,
                full_replay_ended = erlang:monotonic_time(millisecond)};
end_walk(#state{replay_walk = {pending, TRef, _}} = State) ->
    _ = erlang:cancel_timer(TRef),
    State#state{replay_walk = idle};
end_walk(State) ->
    State.

%% Spawn a worker for Entry, or skip it here when nothing can come of it: an
%% entry with an empty stored request, or a session replayed within the guard
%% window (a verdict and a walk can both name a session). The session is
%% stamped when its worker starts; a worker that sends nothing unstamps it.
start_replay_entry({AgentId, SessionId, Req} = Entry, #state{recent_replays = Recent} = State) ->
    case is_map(Req) andalso map_size(Req) =:= 0 of
        true ->
            logger:debug("Registration replay: skipping ~s (no stored request)",
                         [yuzu_gw_env:log_text(AgentId)]),
            emit_replay_outcome(skipped, 1),
            emit_queue_depth(replay_depth(State)),
            State;
        false ->
            case is_binary(SessionId) andalso maps:is_key(SessionId, Recent) of
                true ->
                    emit_replay_outcome(skipped, 1),
                    emit_queue_depth(replay_depth(State)),
                    State;
                false ->
                    spawn_replay(Entry, stamp_replayed(SessionId, State))
            end
    end.

%% Arm a full walk after the start jitter (a no-op when one is pending or
%% walking: see the replay_registrations cast).
start_full_replay(_Trigger, #state{replay_walk = Walk} = State) when Walk =/= idle ->
    State;
start_full_replay(Trigger, #state{replay_jitter_ms = Jitter} = State) ->
    Delay = case Jitter of 0 -> 0; _ -> rand:uniform(Jitter + 1) - 1 end,
    TRef = erlang:send_after(Delay, self(), replay_start),
    State#state{replay_walk = {pending, TRef, Trigger}}.

replay_active(#state{replay_queue = Q, replay_walk = Walk, replay_pids = RPids}) ->
    Q =/= [] orelse Walk =/= idle orelse map_size(RPids) > 0.

%% Drop everything still queued (and stop the walk). Workers in flight finish;
%% their results count only if the breaker generation has not moved.
abort_replay(Why, #state{replay_len = Len, replay_walk = Walk} = State) ->
    Left = Len + case Walk of {walking, _, W} -> W; _ -> 0 end,
    logger:warning("Registration replay aborted: ~s (~b agent(s) not yet re-proxied)",
                   [Why, Left]),
    emit_replay_outcome(aborted, Left),
    State1 = end_walk(set_replay_queue(State, [], 0)),
    emit_queue_depth(0),
    maybe_finish_replay(prune_recent_replays(State1)).

%% The replay is over when nothing is queued, the walk is done and no worker is
%% in flight: report its duration once, and forget stale guard stamps.
maybe_finish_replay(#state{replay_started = undefined} = State) ->
    State;
maybe_finish_replay(#state{replay_started = T0} = State) ->
    case replay_active(State) of
        true ->
            State;
        false ->
            Seconds = (erlang:monotonic_time(millisecond) - T0) / 1000,
            telemetry:execute([yuzu, gw, upstream, registration_replay_done],
                              #{seconds => Seconds}, #{}),
            prune_recent_replays(State#state{replay_started = undefined})
    end.

start_replay_clock(#state{replay_started = undefined} = State) ->
    State#state{replay_started = erlang:monotonic_time(millisecond)};
start_replay_clock(State) ->
    State.

%% Entries still to replay: queued, plus the rest of the walk (an estimate:
%% the table size when the walk started, less what was read since).
replay_depth(#state{replay_len = Len, replay_walk = {walking, _, Left}}) -> Len + Left;
replay_depth(#state{replay_len = Len}) -> Len.

emit_replay_outcome(_Outcome, 0) ->
    ok;
emit_replay_outcome(Outcome, Count) ->
    telemetry:execute([yuzu, gw, upstream, registration_replay_outcome],
                      #{count => Count}, #{outcome => Outcome}).

%% @doc A verdict's ids, cut to ?MAX_REPLAY_SESSION_IDS; `invalid' for anything
%% that is not a list (an improper list included).
bound_session_ids(Ids) when is_list(Ids) ->
    try lists:sublist(Ids, ?MAX_REPLAY_SESSION_IDS)
    catch error:_ -> invalid
    end;
bound_session_ids(_) ->
    invalid.

%% @doc The verdict of a bounded list: dropped while the circuit is open,
%% queued otherwise; and when it shows the server lost its state, a full replay
%% (maybe_full_replay/3).
replay_verdict(SessionIds, _Facts, #state{cb_state = open} = State) ->
    %% Drop, do not queue: the upstream is known to be down, so every replay
    %% RPC would fail fast anyway. The server lists these sessions again on a
    %% later heartbeat once it answers, so nothing is lost but time.
    Count = length(SessionIds),
    emit_verdict_dropped(circuit_open, Count),
    logger:debug("Registration replay: heartbeat verdict named ~b session(s) "
                 "while the circuit is open; dropped", [Count]),
    State;
replay_verdict(SessionIds, Facts, State) ->
    %% closed or half_open. half_open queues on purpose: the first replay
    %% RPC is the probe that decides whether the breaker closes. The listed
    %% sessions go first; a full walk started here skips them (they are stamped
    %% replayed when their workers start).
    maybe_full_replay(length(SessionIds), Facts, enqueue_sessions(SessionIds, State)).

%% @doc The verdict facts replay_sessions/2 passes, read with defaults: a batch
%% size that is not a non-negative integer is unknown (no ratio evidence), and
%% only `true' is truncated.
verdict_facts(Verdict) when is_map(Verdict) ->
    #{batch => case maps:get(batch, Verdict, undefined) of
                   B when is_integer(B), B >= 0 -> B;
                   _ -> undefined
               end,
      truncated => maps:get(truncated, Verdict, false) =:= true};
verdict_facts(_) ->
    #{batch => undefined, truncated => false}.

%% @doc Start a full replay when the verdict is evidence that the server lost
%% its state (see the module doc): the server truncated its list, or it listed
%% at least half of the batch and at least verdict_floor/1 sessions; and no full
%% replay ended within ?FULL_REPLAY_COOLDOWN_MS. In a large fleet one unknown
%% session says that agent is unknown, not that the server forgot everyone, so
%% the evidence needed grows with the fleet; in a small one a full replay costs
%% little more than the targeted one, and it spares the rest of the fleet a wait
%% of up to one heartbeat interval for their own heartbeats to be listed.
maybe_full_replay(Unknown, #{batch := Batch, truncated := Truncated}, State) ->
    Evidence = Truncated orelse
        (is_integer(Batch) andalso Batch > 0 andalso Unknown * 2 >= Batch
         andalso Unknown >= verdict_floor(agents_held())),
    case Evidence andalso cooled_down(State) of
        true ->
            logger:info("Registration replay: the server does not know ~b of the ~s "
                        "session(s) of a heartbeat batch~s; replaying every agent",
                        [Unknown, case Batch of undefined -> "?"; _ -> integer_to_list(Batch) end,
                         case Truncated of true -> " (list truncated)"; false -> "" end]),
            start_full_replay(server_lost_state, State);
        false ->
            State
    end.

%% @doc The fewest unknown sessions in one verdict that count as evidence the
%% server lost its state: one per 64 agents this node holds, at least 1 and at
%% most 16. At 5,000 agents a 1 s batch carries about 170 heartbeats (agents
%% heartbeat every 30 s), so a restarted server lists far more than 16; a
%% session the server dropped on its own is one or two.
-spec verdict_floor(non_neg_integer()) -> pos_integer().
verdict_floor(Agents) ->
    max(1, min(16, Agents div 64)).

agents_held() ->
    case ets:info(?AGENTS_TABLE, size) of
        N when is_integer(N) -> N;
        undefined -> 0
    end.

cooled_down(#state{full_replay_ended = undefined}) ->
    true;
cooled_down(#state{full_replay_ended = Ended}) ->
    erlang:monotonic_time(millisecond) - Ended >= ?FULL_REPLAY_COOLDOWN_MS.

%% @doc Queue the entries for the sessions a heartbeat verdict named (#1197).
%% Ids are resolved to entries by session (yuzu_gw_registry:
%% entries_for_sessions/1), and each pop is re-verified by agent
%% (lookup_local_session/1): two decisions, two keys.
%%
%% Per entry, in the order of the ids given (a heartbeat verdict arrives sorted
%% by session id: the buffer sorts it, so the queue order is by session id, not
%% the order the server listed), the first rule that applies wins:
%%   - the agent is already queued: skipped. One pending entry per agent, so
%%     a second session for the same agent is not queued; the earlier entry
%%     is skipped as stale at its pop and the new session is listed again by
%%     the agent's next heartbeat.
%%   - the session was replayed within the guard window: skipped. The verdict
%%     was computed before that replay landed.
%%   - the queue is at its cap: dropped and counted (queue_full; the heartbeat
%%     buffer also counts queue_full when it skips the cast because this
%%     process's mailbox is long).
%%   - otherwise appended.
%% The first two are deduplication, not loss, and are not counted as drops.
%% Ids this node does not hold are counted as not_local. Membership is
%% checked against a map built once from the queue, so a verdict costs O(k)
%% for the queue and the k ids, never O(k) per id.
%%
%% When anything was appended: one registration_replay_triggered event, the
%% queue depth is reported (so the gauge is not stale until the first pop),
%% and the caller's settle/1 pumps the new entries into replay workers. The
%% log line carries counts only, never ids.
-spec enqueue_sessions([binary()], #state{}) -> #state{}.
enqueue_sessions(SessionIds, State0) ->
    #state{replay_queue = Queue, replay_len = QueueLen, recent_replays = Recent,
           replay_queue_max = Max} = State = prune_recent_replays(State0),
    Entries = yuzu_gw_registry:entries_for_sessions(SessionIds),
    NotLocal = length(SessionIds) - length(Entries),
    QueuedAgents = maps:from_keys([AgentId || {AgentId, _, _} <- Queue], true),
    {RevAppended, _, Size, AlreadyQueued, WithinGuard, QueueFull} =
        lists:foldl(
          fun({AgentId, SessionId, _} = Entry, {Rev, Agents, Len, Dup, Guarded, Full}) ->
              case {maps:is_key(AgentId, Agents), maps:find(SessionId, Recent), Len >= Max} of
                  {true, _, _} ->
                      {Rev, Agents, Len, Dup + 1, Guarded, Full};
                  {false, {ok, _}, _} ->
                      {Rev, Agents, Len, Dup, Guarded + 1, Full};
                  {false, error, true} ->
                      {Rev, Agents, Len, Dup, Guarded, Full + 1};
                  {false, error, false} ->
                      {[Entry | Rev], Agents#{AgentId => true}, Len + 1, Dup, Guarded, Full}
              end
          end,
          {[], QueuedAgents, QueueLen, 0, 0, 0}, Entries),
    emit_verdict_dropped(not_local, NotLocal),
    emit_verdict_dropped(queue_full, QueueFull),
    Appended = Size - QueueLen,
    Level = case Appended of 0 -> debug; _ -> info end,
    logger:log(Level, "Registration replay: heartbeat verdict named ~b session(s); "
                      "queued ~b, not local ~b, already queued ~b, within guard ~b, "
                      "queue full ~b",
               [length(SessionIds), Appended, NotLocal, AlreadyQueued, WithinGuard, QueueFull]),
    case RevAppended of
        [] ->
            State;
        _ ->
            telemetry:execute([yuzu, gw, upstream, registration_replay_triggered],
                              #{count => 1}, #{trigger => heartbeat}),
            State1 = set_replay_queue(State, Queue ++ lists:reverse(RevAppended), Size),
            emit_queue_depth(replay_depth(State1)),
            %% The caller (the cast handler) settles: the pump starts the new
            %% entries at once if a worker slot is free.
            start_replay_clock(State1)
    end.

%% @doc Record that SessionId is being replayed now. An entry seeded with no
%% session (the register_agent/5 back-compat path) has nothing a verdict could
%% name, so it is not stamped.
stamp_replayed(SessionId, #state{recent_replays = Recent} = State) when is_binary(SessionId) ->
    State#state{recent_replays = Recent#{SessionId => erlang:monotonic_time(millisecond)}};
stamp_replayed(_SessionId, State) ->
    State.

%% @doc Forget guard stamps older than the guard window.
prune_recent_replays(#state{recent_replays = Recent, session_guard_ms = Guard} = State) ->
    Cutoff = erlang:monotonic_time(millisecond) - Guard,
    State#state{recent_replays = maps:filter(fun(_, Stamp) -> Stamp > Cutoff end, Recent)}.

%% @doc Report the replay queue depth without counting a replay: a
%% registration_replay event with replayed = 0 sets the gauge and adds
%% nothing to the replay counter. Called on append, skip and abort, so the
%% gauge is not stale between replay RPCs (do_replay_one/6 reports its own).
emit_queue_depth(Depth) ->
    telemetry:execute([yuzu, gw, upstream, registration_replay],
                      #{replayed => 0, queue_depth => Depth}, #{}).

%% @doc Count session ids from a verdict that were not queued, by reason
%% (not_local | circuit_open | queue_full). A zero count emits nothing.
emit_verdict_dropped(_Reason, 0) ->
    ok;
emit_verdict_dropped(Reason, Count) ->
    telemetry:execute([yuzu, gw, heartbeat, verdict_dropped],
                      #{count => Count}, #{reason => Reason}).

%% @doc The server's reject_reason, as log text.
reject_reason_for_log(Response) ->
    yuzu_gw_env:log_text(maps:get(reject_reason, Response, <<>>)).

%%%===================================================================
%%% Internal — RPC execution
%%%===================================================================

%% Map each GatewayUpstream RPC to its protobuf input/output message types.
rpc_types('ProxyRegister')      -> {'yuzu.agent.v1.RegisterRequest',
                                    'yuzu.agent.v1.RegisterResponse'};
rpc_types('ProxyInventory')     -> {'yuzu.agent.v1.InventoryReport',
                                    'yuzu.agent.v1.InventoryAck'};
rpc_types('NotifyStreamStatus') -> {'yuzu.gateway.v1.StreamStatusNotification',
                                    'yuzu.gateway.v1.StreamStatusAck'};
rpc_types('ForwardGuardianMessage') -> {'yuzu.gateway.v1.ForwardGuardianRequest',
                                        'yuzu.gateway.v1.ForwardGuardianAck'}.

-spec do_rpc(atom(), map(), atom()) -> rpc_result().
do_rpc(Method, Request, Tag) ->
    do_rpc(Method, Request, Tag, #{}).

-spec do_rpc(atom(), map(), atom(), map()) -> rpc_result().
do_rpc(Method, Request, Tag, Metadata) ->
    do_rpc(Method, Request, Tag, Metadata, ?DEFAULT_RPC_TIMEOUT_MS).

%% @doc Like do_rpc/3 but for the registration-replay path (HA WS-4 4.1):
%% attaches the agent's EXISTING session id as the `x-yuzu-session-id' request
%% header, through the client's metadata argument (yuzu_grpc_client:unary/5).
%% Undefined/empty SessionId (the register_agent/5 back-compat path) sends the
%% request with no such header, same as before this change.
do_rpc_replay(Method, Request, Tag, SessionId) when is_binary(SessionId), SessionId =/= <<>> ->
    do_rpc(Method, Request, Tag, #{<<"x-yuzu-session-id">> => SessionId});
do_rpc_replay(Method, Request, Tag, _SessionId) ->
    do_rpc(Method, Request, Tag, #{}).

%% Timeout is the whole call in ms (the client also sends it upstream as
%% grpc-timeout, so the server can stop working on a call nobody waits for).
-spec do_rpc(atom(), map(), atom(), map(), pos_integer()) -> rpc_result().
do_rpc(Method, Request, Tag, Metadata, Timeout) ->
    {InputType, OutputType} = rpc_types(Method),
    Def = #{marshal   => fun(Msg) -> encode_request(Msg, InputType) end,
            unmarshal => fun(Bin) -> gateway_pb:decode_msg(Bin, OutputType) end},
    Path = <<"/yuzu.gateway.v1.GatewayUpstream/", (atom_to_binary(Method, utf8))/binary>>,
    StartTime = erlang:monotonic_time(millisecond),
    Result = try yuzu_grpc_client:unary(Metadata, Path, Request, Def,
                                        #{channel => default_channel, timeout => Timeout,
                                          report_conn => true})
             catch
                 %% The stacktrace is dropped on purpose: a frame prints its
                 %% argument list (the request, with its credentials) in the
                 %% crash report if this exception reaches the gen_server.
                 %% Only the class and the redacted reason are kept.
                 error:{?LOCAL_ENCODE_FAILED, Class, Why} ->
                     %% Raised by encode_request/2 below, with the reason already
                     %% redacted: the request never left this process.
                     {rpc_exception, local, Class, Why};
                 Class:Why ->
                     {rpc_exception, remote, Class, redact_why(Why)}
             end,
    Duration = erlang:monotonic_time(millisecond) - StartTime,
    case Result of
        {rpc_exception, Origin, Class1, Why1} ->
            %% A local encode failure is counted under its own code, so a
            %% systematic encoder fault (every Register answered INTERNAL while the
            %% breaker stays closed) can be told from an exception out of the
            %% client or the transport, which keeps `exception' and does open the
            %% breaker.
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => case Origin of
                                            local  -> <<"encode">>;
                                            remote -> <<"exception">>
                                        end}),
            yuzu_gw_safe_call:warn_limited(rpc_raised, "Upstream RPC ~s raised ~p:~p",
                                           [Method, Class1, Why1]),
            case Origin of
                %% Never reaches the breaker (record_result/2 ignores it).
                local  -> {local_error, {Class1, Why1}};
                remote -> {error, exception_reason(Class1, Why1)}
            end;
        {ok, Response, _Headers} ->
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => atom_to_binary(Tag, utf8)}),
            {ok, Response};
        {error, {Status, Message}, _Trailers} ->
            %% HA WS-4 4.4 fix: yuzu_grpc_client:unary/5's error shape for
            %% a genuine (non-transport) grpc status is a 3-element tuple —
            %% `error`, the `{Status, Message}` pair, and the trailers map
            %% (the shape its predecessor grpcbox_client defined, kept so
            %% these clauses did not change; yuzu_grpc_client:status/4) —
            %% not the 2-element `{error, {Status, Message, Trailers}}` this
            %% clause used to match. That mismatch meant this clause could
            %% NEVER fire: any real upstream grpc-status error (anything
            %% other than a transport-level `{error, Reason}`) fell through
            %% to neither clause and crashed this gen_server with a
            %% case_clause exception. Unreachable before this slice — every
            %% pre-4.4 ProxyRegister/NotifyStreamStatus/etc. failure the
            %% gateway could receive was either OK or a transport-level
            %% error (connection refused, TLS failure, timeout) — but HA
            %% WS-4 4.4 is the first caller to make the server return a
            %% real, deliberate non-OK grpc status (FAILED_PRECONDITION) on
            %% this RPC, so this had to be fixed to ship that feature at
            %% all. `Status` is the raw `grpc-status` trailer value, a
            %% binary digit string (`?GRPC_STATUS_BIN_*` in yuzu_grpc_client.hrl), e.g.
            %% `<<"9">>` for FAILED_PRECONDITION — never an atom.
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => Status}),
            case is_request_fault(Status) of
                true ->
                    %% Provoked by the request, so by whoever sent it: limited.
                    yuzu_gw_safe_call:warn_limited(rpc_answered_error,
                                                   "Upstream RPC ~s failed: ~p ~s",
                                                   [Method, Status, yuzu_gw_env:log_text(Message)]);
                false ->
                    logger:warning("Upstream RPC ~s failed: ~p ~s",
                                   [Method, Status, yuzu_gw_env:log_text(Message)])
            end,
            {error, {Status, Message}};
        {http_error, {Status, _}, _Trailers} ->
            %% HA WS-4 4.4 round-2 review fix (consistency-auditor c-1 /
            %% chaos-injector CH-2): a FOURTH real unary/5
            %% return shape (the `{http_error, Status, Meta}` result of
            %% yuzu_grpc_client, as grpcbox_client's was) for a non-grpc-layer HTTP error
            %% (e.g. a stripped/mangled response from something in front of
            %% the actual gRPC service) — same crash-class gap as the
            %% `{error, {Status, Message}, Trailers}` fix above, and left
            %% unclosed by that fix despite sharing its root cause. Never
            %% observed in practice (the gateway talks to the C++ server
            %% directly, no intermediary), but cheap to close now rather
            %% than chase a `case_clause` crash in production later.
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => Status}),
            logger:warning("Upstream RPC ~s failed with HTTP-level error: ~p", [Method, Status]),
            {error, {internal, iolist_to_binary(io_lib:format("http_error ~p", [Status]))}};
        {error, too_many_streams} ->
            %% gun refused to open the stream: the connection is at the server's
            %% SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 5.1.2). Nothing was
            %% sent. Counted under its own code; the proxied calls and replays
            %% wait and try again without telling the breaker, and the other
            %% lanes count it like any failed send (see the module doc).
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => <<"too_many_streams">>}),
            {error, too_many_streams};
        {error, {connection_lost, Conn}} when is_pid(Conn) ->
            %% The connection the call ran on closed or went away: the breaker
            %% counts this connection once (record_result/2), and the caller sees
            %% the same internal error as for any transport failure.
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => connection_lost}),
            {error, {connection_lost, Conn}};
        {error, Reason} ->
            %% R-3 (#1243): emit a DISTINCT metric for a TLS handshake failure
            %% (cert expiry / CA rotation / wrong-SAN / unreadable cert) so it is
            %% not lost in the generic rpc_error → circuit-open noise. The generic
            %% rpc_error still fires too (the circuit breaker keys off it).
            case classify_tls_error(Reason) of
                {true, Kind} ->
                    telemetry:execute([yuzu, gw, upstream, tls_handshake_failure],
                                      #{count => 1},
                                      #{rpc_name => atom_to_binary(Tag, utf8), kind => Kind}),
                    logger:warning("Upstream RPC ~s TLS handshake failure (~s): ~p",
                                   [Method, Kind, Reason]);
                {false, _} ->
                    ok
            end,
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => Reason}),
            {error, {internal, iolist_to_binary(io_lib:format("~p", [Reason]))}}
    end.

%% The request encoder handed to the gRPC client. grpcbox runs it in the calling
%% process, after a connection was obtained and before anything is sent, so an
%% exception from it is local: it is re-raised under a tag only this module
%% raises (a server answer cannot carry it), with the reason redacted, so do_rpc
%% can tell it from an exception of the client or the transport.
encode_request(Msg, InputType) ->
    try gateway_pb:encode_msg(Msg, InputType) of
        Bin when byte_size(Bin) > ?MAX_REQUEST_BYTES ->
            %% Raised from the `of' branch, so the catch below does not see it.
            erlang:error({?LOCAL_ENCODE_FAILED, error, request_too_large});
        Bin ->
            Bin
    catch Class:Why ->
        erlang:error({?LOCAL_ENCODE_FAILED, Class, redact_why(Why)})
    end.

%% @doc The streams the gateway's lanes other than the permit pools can hold
%% open upstream at once: stream-status notifications, Guardian forwards and the
%% heartbeat flush. yuzu_gw_upstream_regulator keeps them out of the server's
%% capacity before it sizes the register and inventory pools. (A planned stop's
%% last gasp sends up to STOP_NOTIFY_INFLIGHT notifications, but by then every
%% permit is refused.)
-spec reserved_streams() -> pos_integer().
reserved_streams() ->
    ?MAX_NOTIFY_INFLIGHT + ?MAX_GUARDIAN_INFLIGHT + ?HEARTBEAT_FLUSH_STREAMS.

%% @doc The result as the callers of proxy_register/1 and proxy_inventory/1 and
%% the log lines of the workers see it: a local encode exception reads as the
%% same `{error, {internal, <<"rpc exception ...">>}}' as before. Only the breaker
%% bookkeeping tells them apart.
-spec public_result(rpc_result()) -> {ok, term()} | {error, term()}.
public_result({local_error, {Class, Why}}) ->
    {error, exception_reason(Class, Why)};
public_result({error, {connection_lost, _Conn}}) ->
    {error, {internal, <<"connection_lost">>}};
public_result(Result) ->
    Result.

is_request_fault(Status) when ?IS_REQUEST_FAULT(Status) -> true;
is_request_fault(_Status) -> false.

exception_reason(Class, Why) ->
    {internal, iolist_to_binary(io_lib:format("rpc exception ~p:~p", [Class, Why]))}.

%% @private Classify whether an upstream transport error is a TLS handshake
%% failure, returning {true, KindBin} (the alert/cause, for the metric label) or
%% {false, _}. gun/ssl surface these as nested {tls_alert, {Alert,_}} or
%% {options,_} terms (e.g. {shutdown,{tls_alert,{unknown_ca,_}}}); search a
%% bounded depth so an arbitrary error term can't loop. R-3 (#1243).
-spec classify_tls_error(term()) -> {boolean(), binary()}.
classify_tls_error(Term) ->
    classify_tls_error(Term, 4).

classify_tls_error(_Term, 0) ->
    {false, <<>>};
classify_tls_error({tls_alert, {Alert, _}}, _D) when is_atom(Alert) ->
    {true, atom_to_binary(Alert, utf8)};
classify_tls_error({tls_alert, Alert}, _D) when is_atom(Alert) ->
    {true, atom_to_binary(Alert, utf8)};
classify_tls_error({options, _}, _D) ->
    {true, <<"bad_tls_options">>};
classify_tls_error(T, D) when is_tuple(T) ->
    classify_tls_error_list(tuple_to_list(T), D);
classify_tls_error(L, D) when is_list(L) ->
    classify_tls_error_list(L, D);
classify_tls_error(_Other, _D) ->
    {false, <<>>}.

classify_tls_error_list([], _D) ->
    {false, <<>>};
classify_tls_error_list([H | Rest], D) ->
    case classify_tls_error(H, D - 1) of
        {true, _} = R -> R;
        {false, _}    -> classify_tls_error_list(Rest, D)
    end.

ensure_binary(undefined) -> <<>>;
ensure_binary(B) when is_binary(B) -> B;
ensure_binary(L) when is_list(L) -> list_to_binary(L).
