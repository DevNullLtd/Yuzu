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
%%%   notify_pending_max counts keys, not agents, and the key of a half_open probe
%%%   in flight still counts toward it (a new key is admitted only while the held
%%%   keys plus the probe's key stay below the cap); a notification for a new key
%%%   over the cap is dropped and counted (notify_dropped, reason at_capacity).
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
%%%   SUCCESS (record_result_no_replay({ok, superseded}, State)), so a run of
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
%%%   sent as the probe, and the breaker is driven by its result. Without it a
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
%%%       generation: ok closes it (and casts the replay), error reopens it with
%%%       doubled backoff (a local encode exception does neither). In any other
%%%       state or generation the result does not
%%%       touch the breaker (a call path RPC may have closed or reopened it
%%%       meanwhile; a breaker that is open has no on_success or on_failure).
%%%     - A probe worker that dies without a result is an error (worker_down),
%%%       once: the record is cleared by whichever of result or 'DOWN' comes
%%%       first, and a result is always delivered before the 'DOWN' of its
%%%       sender.
%%%   Ordinary workers never report to the breaker.
%%%
%%% Includes a circuit breaker to prevent cascading failures when the
%%% upstream server is unreachable. States:
%%%   closed    — RPCs pass through; consecutive failures tracked
%%%   open      — RPCs fail immediately with {error, circuit_open}
%%%   half_open — one probe RPC allowed; success closes, failure reopens
%%%               (a call path RPC, or one held notification as the probe)
%%%
%%% Registration replay on reconnect:
%%%   When the upstream connection re-establishes after a failure, the
%%%   C++ server may be a fresh instance with an empty agent registry —
%%%   but the gateway still holds the agent connections. Without a
%%%   replay, those agents are silently stranded (invisible to the
%%%   server) until they happen to reconnect. So on any RPC success
%%%   that follows a period of failures (the half_open -> closed
%%%   transition, or a closed-state success with a non-zero failure
%%%   counter), we re-proxy a ProxyRegister for every agent the
%%%   registry currently holds (#5695):
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
%%%     - the breaker opening aborts the rest; the next recovery starts again.
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
%%%
%%% Configuration (sys.config / application env):
%%%   circuit_breaker_failure_threshold   - consecutive failures to trip
%%%                                          (default 5, valid 1..1000)
%%%   circuit_breaker_reset_timeout_ms    - initial open duration
%%%                                          (default 10000, valid 100..3600000)
%%%   circuit_breaker_max_reset_timeout_ms - max backoff cap
%%%                                          (default 300000, valid 100..3600000;
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
%%   cluster_id                          — this gateway's trust-zone/region id,
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
         forward_guardian_message/2,
         replay_sessions/1,
         circuit_state/0]).
%% Read without a call into this process, so they answer while it is inside a
%% slow RPC: the breaker state for /readyz (yuzu_gw_health), the lane counts for
%% the pressure sampler (yuzu_gw_upstream_pressure).
-export([circuit_state_now/0, lane_snapshot/0]).
-export([classify_tls_error/1]).  %% for testing (R-3 TLS-error classifier)
-export([call_timeout/0]).        %% for testing (upstream_call_timeout_ms validation)
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
-define(DEFAULT_CB_MAX_RESET_MS, 300000).
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
-define(DEFAULT_NOTIFY_PENDING_MAX, 10000).
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
    notify_pids     :: #{pid() => true},
    %% Stream-status notifications held until a worker slot is free and the
    %% breaker is closed. Volatile: it does not outlive this process.
    notify_pending  :: yuzu_gw_notify_queue:t(),
    notify_pending_max :: pos_integer(),
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
    replay_walk = idle :: idle | {pending, reference()} |
                          {walking, start | '$end_of_table' | term(), non_neg_integer()},
    %% Replay workers in flight: pid => {AgentId, SessionId}. At most
    %% replay_limit (one while the breaker is half_open: the probe).
    replay_pids = #{} :: #{pid() => {binary(), binary() | undefined}},
    replay_limit    :: pos_integer(),
    replay_jitter_ms :: non_neg_integer(),
    %% When the replay now running started (monotonic ms), for its duration.
    replay_started = undefined :: undefined | integer(),
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
    cluster_id      :: binary()
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
    gen_server:cast(?SERVER, {replay_sessions, SessionIds}).

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
    Deadline = caller_deadline(Opts),
    case proxy_gate() of
        undefined -> {error, upstream_unavailable};
        stopping  -> {error, stopping};
        open      -> {error, circuit_open};
        {pass, _} ->
            %% Stop waiting for a permit while there is still time for a useful
            %% call; a caller with less than that left is not worth a permit.
            case yuzu_gw_upstream_regulator:ask(Class, Deadline - ?MIN_USEFUL_MS) of
                {ok, Permit} ->
                    try permitted_call(Method, Class, Request, Deadline)
                    after yuzu_gw_upstream_regulator:done(Permit)
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

%% Holding a permit. The breaker is read again (it may have opened while the
%% caller waited), and so is the clock: a caller that has run out of time makes
%% no RPC. The result goes to this process by cast, with the breaker generation
%% read before the call, and is returned to the caller without waiting for it.
permitted_call(Method, Class, Request, Deadline) ->
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
                    Result = do_rpc(Method, Request, Class, #{}, min(rpc_timeout(), Left)),
                    gen_server:cast(?SERVER, {rpc_result, Gen, Result}),
                    public_result(Result)
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
    %% would open for the base and then shorten (the default cap is 300000).
    MaxTimeout  = clamp_max_timeout(BaseTimeout, MaxTimeout0, MaxConfigured),
    ReplayJitter = yuzu_gw_env:env_int(registration_replay_start_jitter_ms,
                                       ?DEFAULT_REPLAY_JITTER_MS, 0, ?MAX_REPLAY_JITTER_MS),
    SessionGuard = yuzu_gw_env:env_int(registration_replay_session_guard_ms,
                                   ?DEFAULT_REPLAY_SESSION_GUARD_MS, 0,
                                   ?MAX_REPLAY_SESSION_GUARD_MS),
    QueueMax = yuzu_gw_env:env_int(registration_replay_queue_max,
                               ?DEFAULT_REPLAY_QUEUE_MAX, 1, ?MAX_REPLAY_QUEUE_MAX),
    NotifyPendingMax = yuzu_gw_env:env_int(notify_pending_max,
                                           ?DEFAULT_NOTIFY_PENDING_MAX, 1,
                                           ?MAX_NOTIFY_PENDING_MAX),
    ProbeTimeout = yuzu_gw_env:env_int(notify_probe_timeout_ms,
                                       ?DEFAULT_NOTIFY_PROBE_TIMEOUT_MS,
                                       ?MIN_NOTIFY_PROBE_TIMEOUT_MS,
                                       ?MAX_NOTIFY_PROBE_TIMEOUT_MS),

    logger:info("Upstream client started (circuit breaker: threshold=~b, base_timeout=~bms, "
                "replay_start_jitter=~bms, replay_session_guard=~bms, replay_queue_max=~b, "
                "notify_pending_max=~b, notify_probe_timeout=~bms, cluster_id=~ts)",
                [Threshold, BaseTimeout, ReplayJitter, SessionGuard, QueueMax,
                 NotifyPendingMax, ProbeTimeout, ClusterId]),

    %% A restarted instance counts only its own workers, so the gauges start
    %% from zero here (workers of an earlier instance are unlinked and uncounted).
    emit_notify_queue(0, 0),

    ok = init_cell(),
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
        cluster_id      = ClusterId
    },
    publish_breaker(State#state.cb_state, State#state.cb_gen),
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

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({notify_stream_status, AgentId, SessionId, Event, PeerAddr0, StreamHomeId},
            #state{notify_pending = Pending, notify_probe = Probe,
                   cluster_id = ClusterId} = State) ->
    Before = notify_counts(State),
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
        %% yuzu_gw_agent process instance and passed through
        %% verbatim here on both CONNECTED and DISCONNECTED,
        %% so the server can match a DISCONNECTED to the
        %% stream home it tears down. One process owns a
        %% session for its whole life today, so this is a
        %% matching key, not a guard against a second home.
        stream_home_id => StreamHomeId
    },
    %% #4632: hold the notification instead of dropping it when no slot is free
    %% or the breaker is not closed. Latest event wins within a key (so a
    %% CONNECTED followed by a DISCONNECTED for one session sends only the
    %% DISCONNECTED); two sessions of one agent are two keys. While a half_open
    %% probe is out one slot is held back, so the probe's event always fits back
    %% if the probe fails.
    Key = {AgentId, maps:get(session_id, Notification), StreamHomeId},
    %% The probe's own key is the exception: take/1 removed it from the store,
    %% but its slot is already the one reserved above, so a newer event for that
    %% key is a replacement of a held key and must not be charged a second slot
    %% (else at a full store the newer event is dropped and the stale probe event
    %% is requeued). If the probe fails, push_front/3 finds the newer event still
    %% held (if a call path RPC closed the breaker meanwhile, the drain may
    %% already have sent it, and the old event is then given back and sent after
    %% it) and supersedes the old one; if the probe succeeds, the newer one is
    %% sent later. Either way the store stays within notify_pending_max.
    Reserved = case Probe of
                   undefined         -> 0;
                   #{key := Key}     -> 0;
                   #{}               -> 1
               end,
    State1 =
        case yuzu_gw_notify_queue:put(Key, {AgentId, Notification}, Reserved, Pending) of
            {new, Pending1} ->
                State#state{notify_pending = Pending1};
            {replaced, Pending1} ->
                telemetry:execute([yuzu, gw, upstream, notify_coalesced],
                                  #{count => 1}, #{}),
                State#state{notify_pending = Pending1};
            {full, _Unchanged} ->
                %% HA WS-4 4.4 review fix (F2): a drop is never invisible. A
                %% dropped CONNECTED for an ADOPTED replay session (the
                %% reannounce mechanism) leaves the server's placement wiped
                %% with no other signal, so it is counted. This is admission
                %% loss only: admitting the key would bring the held keys (plus the
                %% key of a half_open probe in flight, which still counts) up to
                %% notify_pending_max.
                logger:debug("Dropping stream status notification for ~s (pending store full)",
                             [yuzu_gw_env:log_text(AgentId)]),
                telemetry:execute([yuzu, gw, upstream, notify_dropped],
                                  #{count => 1}, #{reason => <<"at_capacity">>}),
                State
        end,
    {noreply, report_notify_counts(Before, drain(State1))};

%% The result of a proxied call, made in the caller's process. It counts
%% against the breaker like any call, but only under the generation the caller
%% read before its RPC and never while the breaker is open: a result from before
%% the breaker last moved says nothing about the upstream now (and on_success/
%% on_failure have no clause for an open breaker).
handle_cast({rpc_result, Gen, Result}, #state{cb_state = CbState, cb_gen = CbGen} = State)
  when CbState =/= open, Gen =:= CbGen ->
    Before = notify_counts(State),
    {noreply, report_notify_counts(Before, drain(record_result(Result, State)))};
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

handle_cast({replay_sessions, SessionIds0}, State) ->
    %% replay_sessions/1 is exported, so this boundary bounds its own input
    %% (the heartbeat buffer's cap is not the only caller's guarantee): a
    %% non-list is ignored, a list is cut to ?MAX_REPLAY_SESSION_IDS before it
    %% is counted, dropped or queued.
    case bound_session_ids(SessionIds0) of
        invalid ->
            logger:debug("Registration replay: ignoring a verdict that is not a list"),
            {noreply, State};
        SessionIds ->
            {noreply, settle(replay_verdict(SessionIds, State))}
    end;

handle_cast(replay_registrations, #state{replay_walk = Walk} = State) when Walk =/= idle ->
    %% Gate 7 UP-5: a full replay is already pending or walking. Reseeding it on
    %% every trigger restarted it from zero each time a flapping server came
    %% back, and at fleet scale it never finished. The running walk completes;
    %% if the upstream went away again, the walk is aborted when the breaker
    %% opens and the next real recovery starts a new one.
    logger:debug("Registration replay: a full replay is already running; ignoring the trigger"),
    {noreply, State};
handle_cast(replay_registrations, #state{replay_jitter_ms = Jitter} = State) ->
    %% Idle: start a full walk of the registry after the start jitter. The walk
    %% reads the table when it runs, so an agent that disconnected during the
    %% outage is already gone and is not replayed. A targeted replay already
    %% queued (a verdict) keeps running; the walk is pumped after it.
    Delay = case Jitter of 0 -> 0; _ -> rand:uniform(Jitter + 1) - 1 end,
    TRef = erlang:send_after(Delay, self(), replay_start),
    {noreply, State#state{replay_walk = {pending, TRef}}};

handle_cast(_Msg, State) ->
    {noreply, State}.

%% The start jitter of a full replay has passed: fix the agents table (so the
%% chunked walk is a safe traversal while agents come and go) and start
%% pumping. An absent table (the registry is restarting) is no replay.
handle_info(replay_start, #state{replay_walk = {pending, _}} = State) ->
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
                                      #{count => 1}, #{trigger => breaker}),
                    start_replay_clock(State#state{replay_walk = {walking, start, Rows}})
            end
        catch error:badarg ->
            logger:warning("Registration replay: registry unavailable; not replayed"),
            State#state{replay_walk = idle}
        end,
    {noreply, settle(State1)};
handle_info(replay_start, State) ->
    {noreply, State};

%% What a replay worker did. Only a worker this process still tracks counts;
%% the breaker is moved only under the generation it was spawned with and
%% never while open (see the rpc_result cast).
handle_info({replay_done, Pid, Gen, Outcome}, #state{replay_pids = RPids} = State)
  when is_map_key(Pid, RPids) ->
    {{_AgentId, SessionId}, RPids1} = maps:take(Pid, RPids),
    State1 = replay_outcome(Outcome, SessionId, Gen, State#state{replay_pids = RPids1}),
    {noreply, settle(State1)};
handle_info({replay_done, _Pid, _Gen, _Outcome}, State) ->
    {noreply, State};

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
    {noreply, report_notify_counts(Before, drain(State1))};

%% The result of the half_open probe worker. A result from any pid but the
%% recorded probe (a duplicate, or one that was already resolved) is ignored.
handle_info({notify_probe_result, Pid, Gen, Result},
            #state{notify_probe = #{pid := Pid}} = State) ->
    Before = notify_counts(State),
    State1 = resolve_probe(Gen, Result, State),
    {noreply, report_notify_counts(Before, drain(State1))};
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
    {noreply, report_notify_counts(Before, drain(State1))};

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
        {noreply, report_notify_counts(Before, drain(State1))}
    end;
handle_info({notify_probe_timeout, _Pid, _Gen}, State) ->
    {noreply, State};

%% What a stream-status notification worker got from the server. It counts
%% against the breaker like a call made from this process: a notification
%% that failed is an upstream that failed, and a success after failures is
%% the upstream coming back, which replays the registrations (a CONNECTED
%% lost to a server that bounced is put right by that replay).
%%
%% Only from a worker this process started and still tracks, and only while the
%% circuit is closed: the workers in flight when it opened or half-opened answer
%% into a circuit they no longer belong to, and the half-open probe
%% (notify_probe_result, resolved by generation), not a late answer, decides when
%% it closes. record_result/2 has no clause for a state that is not closed
%% here, which on_failure/on_success would crash on while open.
handle_info({notify_result, Pid, Result},
            #state{notify_pids = Pids, cb_state = closed} = State)
  when is_map_key(Pid, Pids) ->
    Before = notify_counts(State),
    {noreply, report_notify_counts(Before, drain(record_result(Result, State)))};
handle_info({notify_result, _Pid, _Result}, State) ->
    {noreply, State};

handle_info({'DOWN', _MonRef, process, Pid, Reason},
            #state{replay_pids = RPids} = State) when is_map_key(Pid, RPids) ->
    %% A replay worker that ended without reporting (it crashed or was killed):
    %% nothing is known about the upstream, so the breaker is not touched.
    {{AgentId, SessionId}, RPids1} = maps:take(Pid, RPids),
    logger:warning("Registration replay worker for ~s exited without a result: ~p",
                   [yuzu_gw_env:log_text(AgentId), redact_reason(Reason)]),
    emit_replay_outcome(failed, 1),
    State1 = State#state{replay_pids = RPids1,
                         recent_replays = maps:remove(SessionId, State#state.recent_replays)},
    {noreply, settle(State1)};
handle_info({'DOWN', _MonRef, process, Pid, _Reason},
            #state{notify_pids = Pids, guardian_pids = GPids} = State) ->
    %% A finished notify OR guardian-forward worker. Remove from whichever set
    %% holds it (maps:remove on an absent key is a no-op, so both are safe). A
    %% freed notify slot is refilled from the pending store at once, and a
    %% replay held back for notify headroom may continue.
    Before = notify_counts(State),
    State1 = State#state{notify_pids = maps:remove(Pid, Pids),
                         guardian_pids = maps:remove(Pid, GPids)},
    {noreply, pump_replay(report_notify_counts(Before, drain(State1)))};

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
    case yuzu_gw_upstream_regulator:ask(replay, Deadline) of
        {ok, Permit} ->
            try replay_permitted(AgentId, SessionId, Req0)
            after yuzu_gw_upstream_regulator:done(Permit)
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
        {local_error, {Class, Why}} ->
            %% The stored request could not be encoded here, so nothing was
            %% sent: no verdict about the upstream (record_result_no_replay/2
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
        true  -> record_result_no_replay(BreakerResult, State);
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
    {ok, State}.

%% @doc What a crash report and sys:get_status/1 show of this process.
%%
%% The replay queue holds every queued agent's stored RegisterRequest
%% verbatim (enrollment_token, machine_certificate, csr_pem), and the state
%% printed whole would put those credentials in the log, once per queued
%% agent. So this callback shows:
%%   - the state as a map of its scalar fields, with replay_queue and
%%     recent_replays replaced by their sizes (replay_queue_len,
%%     recent_replays_size); a state that is not the record, or a queue or
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
                    notify_pending = Pending, notify_probe = Probe,
                    replay_pids = RPids, replay_walk = Walk} = State)
  when is_list(Queue), is_map(Recent), is_map(RPids) ->
    Fields = maps:from_list(lists:zip(record_info(fields, state),
                                      tl(tuple_to_list(State)))),
    (maps:without([replay_queue, recent_replays, notify_pending, notify_probe,
                   replay_pids, replay_walk], Fields))#{
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

%% The messages that carry a request, an inventory report, session ids, a peer
%% address or a guardian frame; anything else is shown as is.
redact_message({proxy_register, _Req})            -> {proxy_register, '$redacted'};
redact_message({proxy_inventory, _Report})        -> {proxy_inventory, '$redacted'};
redact_message({replay_sessions, _Ids})           -> {replay_sessions, '$redacted'};
redact_message({forward_guardian_message, AgentId, _Frame}) ->
    {forward_guardian_message, AgentId, '$redacted'};
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
%% An RPC success that follows a period of failures means the upstream
%% connection has re-established — possibly against a fresh server with
%% an empty registry. on_success/1 flags that case; record_result/2
%% then casts replay_registrations to self so the agents the gateway
%% already holds get re-proxied. The cast (not an inline call) keeps
%% the replay off the hot path of whatever RPC just succeeded.
record_result({ok, _}, State) ->
    case on_success(State) of
        {State1, replay} ->
            gen_server:cast(self(), replay_registrations),
            State1;
        {State1, noop} ->
            State1
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
    State.

%% @doc Like record_result/2 but never triggers a registration replay.
%% Used by the replay itself: a replay RPC must still advance the
%% circuit breaker (so a mid-replay outage trips it), but it must not
%% kick off a second, nested replay cascade.
record_result_no_replay({ok, _}, State) ->
    {State1, _Trigger} = on_success(State),
    State1;
record_result_no_replay({error, {Status, _Message}}, State) when ?IS_REQUEST_FAULT(Status) ->
    State;
record_result_no_replay({error, _}, State) ->
    on_failure(State);
record_result_no_replay({local_error, _}, State) ->
    State.

%% @doc Returns {NewState, replay | noop}. `replay' means an RPC just
%% succeeded after one or more failures — treat it as a reconnect.
on_success(#state{cb_state = closed, cb_failures = 0} = State) ->
    %% Steady state — nothing recovered.
    {State, noop};
on_success(#state{cb_state = closed} = State) ->
    %% Closed but cb_failures > 0: the upstream had failing RPCs and is
    %% now answering again, yet never accumulated enough consecutive
    %% failures to trip the breaker. This is the common server-bounce
    %% case (few/idle agents, short outage) — replay so the freshly
    %% restarted server relearns every agent.
    %%
    %% Gate 7 UP-5 — this trigger fires readily (a single failed RPC
    %% then a success is routine under packet loss), but that is now
    %% safe: the replay_registrations handler below NO LONGER restarts
    %% an in-flight replay from scratch. Each outage event arms at most
    %% one full-fleet replay that runs to completion; redundant
    %% triggers while it drains are dropped. The storm was the
    %% restart-from-zero, not the trigger.
    logger:info("Upstream recovered (closed, ~b prior failures)",
                [State#state.cb_failures]),
    {State#state{cb_failures = 0}, replay};
on_success(#state{cb_state = half_open, cb_base_timeout = BaseTimeout} = State) ->
    %% Probe succeeded — close the circuit, reset backoff. The breaker
    %% fully tripped, so the upstream was definitely down; replay.
    logger:info("Circuit breaker: half_open -> closed (probe succeeded)"),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"closed">>}),
    publish_breaker(closed),
    {State#state{
        cb_state      = closed,
        cb_failures   = 0,
        cb_cur_timeout = BaseTimeout
    }, replay}.

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
%% Closed: drain up to the notify budget. Open: nothing is sent, every entry
%% stays held. Half_open: only the single generation-aware probe is sent (the
%% head held entry, one at a time) and every other entry stays held until the
%% probe resolves. Called at the end of every handler that can free a slot,
%% close the breaker or add an entry, so there is one send path and a new
%% arrival never overtakes a held one.
-spec drain(#state{}) -> #state{}.
drain(#state{cb_state = closed, notify_pids = Pids, notify_pending = Pending} = State) ->
    case map_size(Pids) < ?MAX_NOTIFY_INFLIGHT of
        false ->
            State;
        true ->
            case yuzu_gw_notify_queue:take(Pending) of
                empty ->
                    State;
                {_Key, {AgentId, Notification}, Pending1} ->
                    Server = self(),
                    {Pid, _MonRef} = spawn_monitor(fun() ->
                        Result = do_rpc('NotifyStreamStatus', Notification, notify_stream),
                        case public_result(Result) of
                            {ok, _} -> ok;
                            {error, Reason} ->
                                logger:warning("Failed to notify stream status for ~s: ~p",
                                               [yuzu_gw_env:log_text(AgentId), Reason])
                        end,
                        %% Sent before the worker exits, so it reaches this process
                        %% ahead of the 'DOWN' that frees the slot (see the
                        %% notify_result clause of handle_info/2).
                        Server ! {notify_result, self(), Result}
                    end),
                    drain(State#state{notify_pending = Pending1,
                                      notify_pids = Pids#{Pid => true}})
            end
    end;
drain(#state{cb_state = half_open, notify_probe = undefined, notify_pids = Pids,
             notify_pending = Pending, cb_gen = Gen,
             notify_probe_timeout_ms = ProbeTimeout} = State)
        when map_size(Pids) < ?MAX_NOTIFY_INFLIGHT ->
    case yuzu_gw_notify_queue:take(Pending) of
        empty ->
            State;
        {Key, {AgentId, Notification} = Event, Pending1} ->
            %% The probe: the head held entry, sent on a monitored worker like
            %% any other, but it reports its result to this process (send before
            %% exit, so the result reaches the mailbox before the 'DOWN'). The
            %% message carries the result only, never the event.
            Server = self(),
            {Pid, MonRef} = spawn_monitor(fun() ->
                Result = do_rpc('NotifyStreamStatus', Notification, notify_stream),
                case Result of
                    {ok, _} -> ok;
                    {error, Reason} ->
                        logger:warning("Failed to notify stream status for ~s: ~p",
                                       [yuzu_gw_env:log_text(AgentId), Reason]);
                    {local_error, _} ->
                        %% Logged once, by resolve_probe/3, when it evicts the event.
                        ok
                end,
                Server ! {notify_probe_result, self(), Gen, Result}
            end),
            %% The gateway's own deadline for the probe (the client's bounds are
            %% library defaults an endpoint setting can remove): resolved or
            %% cancelled with the probe, see handle_info({notify_probe_timeout, ...}).
            Timer = erlang:send_after(ProbeTimeout, Server, {notify_probe_timeout, Pid, Gen}),
            State#state{notify_pending = Pending1,
                        notify_pids = Pids#{Pid => true},
                        notify_probe = #{pid => Pid, mref => MonRef, timer => Timer,
                                         gen => Gen, key => Key, event => Event}}
    end;
drain(State) ->
    State.

%% @doc Retire the probe attempt: clear the record and free its slot, decide the
%% event, then (separately) decide the breaker. Called once per probe, by the
%% first of its result, its 'DOWN' and its deadline (which kills the worker).
%%
%% The event: ok retires it; an error gives it back at the head of the store
%% (the reserved slot guarantees it fits; a newer event for the same key wins and
%% the old one is dropped and counted).
%%
%% A local encode exception ({local_error, _}) evicts the event instead and
%% leaves the breaker untouched (the first clause).
%%
%% The breaker: moved only when it is still half_open AND Gen is the generation
%% now current. In any other state the result is stale (a call path RPC closed or
%% reopened the breaker meanwhile, or it went half_open again): the breaker is
%% not touched, and on_success/on_failure have no clause for an open breaker.
-spec resolve_probe(non_neg_integer(), rpc_result(), #state{}) -> #state{}.
resolve_probe(_Gen, {local_error, {Class, Why}},
              #state{notify_probe = #{pid := Pid, mref := MonRef, timer := Timer,
                                      event := {AgentId, _}},
                     notify_pids = Pids} = State) ->
    %% The head held entry could not be encoded here, and the same payload fails
    %% the same way on every probe: requeueing it would reopen the breaker for
    %% ever. Evict it, once, and leave the breaker alone (it is not a fact about
    %% the upstream); the caller's drain/1 then probes the next head at once. The
    %% failure is already counted by rpc_errors_total{code="encode"}.
    retire_probe(MonRef, Timer),
    logger:warning("Evicted held stream status notification for ~s: it cannot be "
                   "encoded (~p:~p); the circuit breaker is not affected",
                   [yuzu_gw_env:log_text(AgentId), Class, Why]),
    State#state{notify_probe = undefined,
                notify_pids = maps:remove(Pid, Pids)};
resolve_probe(_Gen, {error, {Status, _Message}},
              #state{notify_probe = #{pid := Pid, mref := MonRef, timer := Timer},
                     notify_pids = Pids} = State) when ?IS_REQUEST_FAULT(Status) ->
    %% The server answered that this notification itself was wrong. Requeueing it
    %% would be answered the same way by every probe, for ever (the breaker is
    %% not touched by such an answer, so nothing would slow the loop), so it is
    %% retired like an answered event. The worker already logged the failure; the
    %% breaker is left as it is, as for a local encode exception.
    retire_probe(MonRef, Timer),
    State#state{notify_probe = undefined,
                notify_pids = maps:remove(Pid, Pids)};
resolve_probe(Gen, Result,
              #state{notify_probe = #{pid := Pid, mref := MonRef, timer := Timer,
                                      key := Key, event := Event},
                     notify_pids = Pids, notify_pending = Pending,
                     cb_state = CbState, cb_gen = CbGen} = State) ->
    retire_probe(MonRef, Timer),
    Pending1 =
        case Result of
            {ok, _} ->
                Pending;
            {error, _} ->
                case yuzu_gw_notify_queue:push_front(Key, Event, Pending) of
                    {inserted, Q} ->
                        Q;
                    {superseded, Q} ->
                        telemetry:execute([yuzu, gw, upstream, notify_coalesced],
                                          #{count => 1}, #{}),
                        Q
                end
        end,
    State1 = State#state{notify_probe = undefined,
                         notify_pids = maps:remove(Pid, Pids),
                         notify_pending = Pending1},
    case CbState =:= half_open andalso Gen =:= CbGen of
        true  -> record_result(Result, State1);
        false -> State1
    end.

%% @doc The probe is over: drop its monitor (and any 'DOWN' already delivered)
%% and its deadline timer. A timeout message that was already delivered is
%% harmless: it names a probe that is no longer recorded.
-spec retire_probe(reference(), reference()) -> ok.
retire_probe(MonRef, Timer) ->
    erlang:demonitor(MonRef, [flush]),
    _ = erlang:cancel_timer(Timer),
    ok.

%% @doc The two numbers the notify_queue gauges report: held keys and workers.
-spec notify_counts(#state{}) -> {non_neg_integer(), non_neg_integer()}.
notify_counts(#state{notify_pending = Pending, notify_pids = Pids}) ->
    {yuzu_gw_notify_queue:size(Pending), map_size(Pids)}.

%% @doc Report the gauges once per handler, and only when the handler changed
%% either number. Before is notify_counts/1 taken at the top of the handler.
-spec report_notify_counts({non_neg_integer(), non_neg_integer()}, #state{}) -> #state{}.
report_notify_counts(Before, #state{notify_pids = Pids, guardian_pids = GPids} = State) ->
    %% The lane figures the pressure sampler reads (lane_snapshot/0) follow the
    %% worker sets, which only the handlers that end here change.
    cell_put(?CELL_NOTIFY, map_size(Pids)),
    cell_put(?CELL_GUARDIAN, map_size(GPids)),
    case notify_counts(State) of
        Before                  -> ok;
        {Pending, Inflight}     -> emit_notify_queue(Pending, Inflight)
    end,
    State.

emit_notify_queue(Pending, Inflight) ->
    telemetry:execute([yuzu, gw, upstream, notify_queue],
                      #{pending => Pending, inflight => Inflight}, #{}).

%%%===================================================================
%%% Registration replay: the pump
%%%===================================================================

%% End of every handler that can change what the replay may do: drain the held
%% notifications, then pump the replay.
settle(State) ->
    Before = notify_counts(State),
    report_notify_counts(Before, pump_replay(drain(State))).

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
%% next recovery starts a new one. Each worker is told the breaker generation,
%% so its result counts only if the breaker has not moved since.
pump_replay(#state{cb_state = open} = State) ->
    case replay_active(State) of
        true  -> abort_replay("circuit open", State);
        false -> State
    end;
pump_replay(State) ->
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
    State#state{replay_walk = idle};
end_walk(#state{replay_walk = {pending, TRef}} = State) ->
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
%% queued otherwise.
replay_verdict(SessionIds, #state{cb_state = open} = State) ->
    %% Drop, do not queue: the upstream is known to be down, so every replay
    %% RPC would fail fast anyway. The server lists these sessions again on a
    %% later heartbeat once it answers, so nothing is lost but time.
    Count = length(SessionIds),
    emit_verdict_dropped(circuit_open, Count),
    logger:debug("Registration replay: heartbeat verdict named ~b session(s) "
                 "while the circuit is open; dropped", [Count]),
    State;
replay_verdict(SessionIds, State) ->
    %% closed or half_open. half_open queues on purpose: the first replay
    %% RPC is the probe that decides whether the breaker closes.
    enqueue_sessions(SessionIds, State).

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
                                        #{channel => default_channel, timeout => Timeout})
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

%% @doc The result as the callers of proxy_register/1 and proxy_inventory/1 and
%% the log lines of the workers see it: a local encode exception reads as the
%% same `{error, {internal, <<"rpc exception ...">>}}' as before. Only the breaker
%% bookkeeping tells them apart.
-spec public_result(rpc_result()) -> {ok, term()} | {error, term()}.
public_result({local_error, {Class, Why}}) ->
    {error, exception_reason(Class, Why)};
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
