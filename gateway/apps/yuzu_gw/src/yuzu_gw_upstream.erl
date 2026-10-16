%%%-------------------------------------------------------------------
%%% @doc gRPC client to the C++ yuzu-server (control plane).
%%%
%%% Proxies Register, Inventory, and stream status notifications
%%% to the upstream server.
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
%%%   The cap bounds the retained keys only; it is not a memory ceiling, and
%%%   casts still queue in the mailbox while a ProxyRegister, ProxyInventory or
%%%   replay RPC runs inside this process. While a registration replay is active
%%%   one of the ten slots is held back, so a backlog that refills every freed
%%%   slot cannot keep the replay drip waiting until the backlog is empty.
%%%   The half_open probe has a deadline owned by this process,
%%%   notify_probe_timeout_ms (default 15000, valid 100 to 300000): a probe worker
%%%   that has not reported by then is killed and the probe fails like any failed
%%%   probe (the event is given back, the breaker reopens with the longer backoff,
%%%   the next half_open cycle sends a new probe). The vendored client's own
%%%   bounds (connect, handshake, response) are library defaults an endpoint
%%%   setting can remove; this deadline does not depend on them. It covers the
%%%   probe only: a ProxyRegister, ProxyInventory or replay RPC runs inside this
%%%   process and is bounded by the client alone.
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
%%%   registry currently holds. The replay is a self-paced drip — one
%%%   agent per scheduled message, spaced by replay_spacing_ms — so a
%%%   fleet of N agents cannot block the gen_server or re-trip the
%%%   circuit breaker. Replay RPCs still pass through the breaker, so a
%%%   server that disappears again mid-replay fails fast and the drip
%%%   stops; the next genuine recovery restarts it.
%%%
%%% Targeted replay on a heartbeat verdict (#1197):
%%%   The server answers every BatchHeartbeat with the sessions it does not
%%%   know. yuzu_gw_heartbeat_buffer casts those ids to replay_sessions/1,
%%%   which queues exactly the ones this node still holds onto the same drip.
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
%%%   registration_replay_spacing_ms      - gap between replay RPCs
%%%                                          (default 20, valid 0..60000)
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
         proxy_inventory/1,
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
-define(DEFAULT_REPLAY_SPACING_MS, 20).
-define(MAX_REPLAY_SPACING_MS, 60000).
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
%%   IN_RPC    1 while this process is inside an RPC it makes itself (a proxied
%%             Register or Inventory, a replay step), 0 otherwise. The notify and
%%             Guardian workers run their RPCs in their own processes and do not
%%             set it.
%%   NOTIFY    stream-status notifications in flight (of MAX_NOTIFY_INFLIGHT)
%%   GUARDIAN  Guardian forwards in flight (of MAX_GUARDIAN_INFLIGHT)
%%   CB        the breaker state (CB_CLOSED, CB_OPEN, CB_HALF_OPEN), published by
%%             publish_breaker/1 wherever cb_state is assigned: init/1, the
%%             circuit_half_open timer, on_success/1 from half_open and
%%             trip_circuit/1. A new assignment of cb_state must publish too.
%%   NOTIFY_LIMIT  the notify slots drain/1 may fill now, notify_budget/1 of the
%%             replay queue: MAX_NOTIFY_INFLIGHT, one fewer while a registration
%%             replay is queued. Published by set_replay_queue/2, the one place
%%             replay_queue is assigned after init/1 (init_cell/0 publishes the
%%             empty queue's budget). A new assignment must go through it.
-define(CELL, {?MODULE, cell}).
-define(CELL_SLOTS, 5).
-define(CELL_IN_RPC, 1).
-define(CELL_NOTIFY, 2).
-define(CELL_GUARDIAN, 3).
-define(CELL_CB, 4).
-define(CELL_NOTIFY_LIMIT, 5).
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
    %% Registration replay on upstream reconnect
    replay_spacing  :: non_neg_integer(),
    replay_queue    :: [{binary(), binary() | undefined, map()}],  %% agents still to re-proxy ([] = idle)
    %% Sessions replayed within the last session_guard_ms (monotonic ms of the
    %% pop that replayed them). Stamped only when the drip actually sends the
    %% ProxyRegister, never when an entry is queued or skipped, and pruned on
    %% every verdict and when the queue empties, so it is bounded by the
    %% sessions replayed within one guard window.
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

%% @doc Forward a RegisterRequest to the C++ server. The `ok' payload is
%% whatever the gRPC client handed back: a RegisterResponse map, but a caller
%% must not assume it (an OK with no DATA frame is not a map).
%%
%% Never exits the caller: an upstream that is not running, stalls past the call
%% timeout or dies serving the call gives `{error, upstream_unavailable}'. The
%% exit of a gen_server:call carries the request, which here holds the
%% enrollment token, certificate and CSR, and the caller's own crash handling
%% (the gRPC runner logs it) would print it. See yuzu_gw_safe_call.
-spec proxy_register(map()) -> {ok, term()} | {error, term()}.
proxy_register(RegisterReq) ->
    yuzu_gw_safe_call:call(?SERVER, {proxy_register, RegisterReq}, call_timeout(),
                           upstream_unavailable).

%% @doc Forward an InventoryReport to the C++ server. Like proxy_register/1,
%% never exits the caller: `{error, upstream_unavailable}' instead.
-spec proxy_inventory(map()) -> {ok, map()} | {error, term()}.
proxy_inventory(InventoryReport) ->
    yuzu_gw_safe_call:call(?SERVER, {proxy_inventory, InventoryReport}, call_timeout(),
                           upstream_unavailable).

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
%% whether it is inside an RPC of its own, how many messages wait in its mailbox,
%% and the in-flight count and limit of each worker lane. `undefined' when the
%% process is not running. See yuzu_gw_upstream_pressure for what is made of it.
-spec lane_snapshot() -> undefined | #{in_rpc := boolean(),
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
                    #{in_rpc            => atomics:get(Cell, ?CELL_IN_RPC) =:= 1,
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
    [atomics:put(Cell, Slot, 0) || Slot <- [?CELL_IN_RPC, ?CELL_NOTIFY, ?CELL_GUARDIAN]],
    atomics:put(Cell, ?CELL_NOTIFY_LIMIT, notify_budget([])),
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

%% Assign replay_queue and publish the notify budget it implies.
-spec set_replay_queue(#state{}, list()) -> #state{}.
set_replay_queue(State, Queue) ->
    cell_put(?CELL_NOTIFY_LIMIT, notify_budget(Queue)),
    State#state{replay_queue = Queue}.

publish_breaker(closed)    -> cell_put(?CELL_CB, ?CB_CLOSED);
publish_breaker(open)      -> cell_put(?CELL_CB, ?CB_OPEN);
publish_breaker(half_open) -> cell_put(?CELL_CB, ?CB_HALF_OPEN).

%% Run an RPC this process makes itself, one at a time, with the lane marked busy
%% for as long as it lasts.
serial(Fun) ->
    cell_put(?CELL_IN_RPC, 1),
    try Fun()
    after cell_put(?CELL_IN_RPC, 0)
    end.

%% How long proxy_register/1 and proxy_inventory/1 wait for the upstream
%% process. The application env key upstream_call_timeout_ms (ms, valid
%% 100..300000, default 30000) overrides the default; it exists so a test can
%% exercise the timeout without waiting 30 s. Anything else logs a warning that
%% names the key and takes the default. Read on every call, so a bad value warns
%% on every call.
call_timeout() ->
    yuzu_gw_env:env_int(upstream_call_timeout_ms, ?DEFAULT_CALL_TIMEOUT_MS,
                        ?MIN_CALL_TIMEOUT_MS, ?MAX_CALL_TIMEOUT_MS).

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
    ReplaySpacing = yuzu_gw_env:env_int(registration_replay_spacing_ms,
                                    ?DEFAULT_REPLAY_SPACING_MS, 0, ?MAX_REPLAY_SPACING_MS),
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
                "replay_spacing=~bms, replay_session_guard=~bms, replay_queue_max=~b, "
                "notify_pending_max=~b, notify_probe_timeout=~bms, cluster_id=~ts)",
                [Threshold, BaseTimeout, ReplaySpacing, SessionGuard, QueueMax,
                 NotifyPendingMax, ProbeTimeout, ClusterId]),

    %% A restarted instance counts only its own workers, so the gauges start
    %% from zero here (workers of an earlier instance are unlinked and uncounted).
    emit_notify_queue(0, 0),

    ok = init_cell(),

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
        replay_spacing  = ReplaySpacing,
        replay_queue    = [],
        recent_replays  = #{},
        session_guard_ms = SessionGuard,
        replay_queue_max = QueueMax,
        guardian_pids   = #{},
        cluster_id      = ClusterId
    },
    publish_breaker(State#state.cb_state),
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

%% Every handle_call clause and what it does with a caller that has died:
%%
%%   circuit_state    a state read: answered whatever the caller is.
%%   proxy_register   skipped when the caller is gone (see caller_gone/1).
%%   proxy_inventory  skipped when the caller is gone.
%%   anything else    answered with {error, unknown_call}.
%%
%% This process runs one RPC at a time, so a call queued behind a slow one waits
%% in the mailbox. The caller of a proxy call is the process of one gRPC request
%% (yuzu_grpc_runner); the stream handler stops it when the client resets the
%% stream, the deadline passes or the connection closes, and by then the answer
%% is wanted by nobody. Running the RPC anyway would register the agent with the
%% server (a session nothing will ever use) or send an inventory nobody waits
%% for, and a burst of abandoned requests would be worked off one after the
%% other while live ones queue behind them. Only these two calls are skipped:
%% each is a request whose whole purpose is its answer to the caller. Everything
%% whose effect must happen whatever the sender does is a cast (stream status,
%% Guardian forward, registration replay) and never reaches handle_call.
%% A skipped call is not counted as a failure of the upstream (the breaker is
%% not touched) and not answered: nobody is listening.
handle_call(circuit_state, _From, #state{cb_state = CbState} = State) ->
    {reply, CbState, State};

handle_call({proxy_register, RegisterReq}, From, State) ->
    case caller_gone(From) of
        true ->
            {noreply, drop_call(register, State)};
        false ->
            case check_circuit(State) of
                {reject, State1} ->
                    {reply, {error, circuit_open}, State1};
                {allow, State1} ->
                    Before = notify_counts(State1),
                    Result = serial(fun() -> do_rpc('ProxyRegister', RegisterReq, register) end),
                    State2 = drain(record_result(Result, State1)),
                    {reply, public_result(Result), report_notify_counts(Before, State2)}
            end
    end;

handle_call({proxy_inventory, InventoryReport}, From, State) ->
    case caller_gone(From) of
        true ->
            {noreply, drop_call(inventory, State)};
        false ->
            case check_circuit(State) of
                {reject, State1} ->
                    {reply, {error, circuit_open}, State1};
                {allow, State1} ->
                    Before = notify_counts(State1),
                    Result = serial(fun() -> do_rpc('ProxyInventory', InventoryReport, inventory) end),
                    State2 = drain(record_result(Result, State1)),
                    {reply, public_result(Result), report_notify_counts(Before, State2)}
            end
    end;

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
            {noreply, replay_verdict(SessionIds, State)}
    end;

handle_cast(replay_registrations, #state{replay_queue = [_ | _]} = State) ->
    %% Gate 7 UP-5 — a drip is already in flight. The OLD behaviour
    %% reseeded `replay_queue` with a fresh full-fleet snapshot on every
    %% cast, so a server that flapped (fail→recover→fail→recover under
    %% packet loss) restarted the replay from zero each time and, at
    %% fleet scale, never drained. Drop the cast: the running drip will
    %% complete. Since #1197 the running queue may be a TARGETED one
    %% (the sessions a heartbeat verdict named), not a snapshot of every
    %% agent, so an agent that is not in it is not replayed by this
    %% recovery; it relies on a later verdict, which lists it within one
    %% heartbeat interval plus one flush. If the upstream genuinely went
    %% away again, check_circuit aborts the drip and the next true
    %% half_open->closed recovery reseeds from scratch.
    logger:debug("Registration replay: drip already in flight "
                 "(~b queued) — ignoring redundant trigger",
                 [length(State#state.replay_queue)]),
    {noreply, State};
handle_cast(replay_registrations, State) ->
    %% Idle — snapshot the agents the registry currently holds and seed
    %% the replay queue. Reading the registry here (not at recovery-detect
    %% time) means an agent that disconnected during the outage is already
    %% gone from ETS and will not be replayed.
    Agents = yuzu_gw_registry:all_register_reqs(),
    case Agents of
        [] ->
            logger:info("Registration replay: no agents to re-proxy"),
            {noreply, set_replay_queue(State, [])};
        _ ->
            logger:info("Registration replay: re-proxying ~b agent(s) upstream",
                        [length(Agents)]),
            telemetry:execute([yuzu, gw, upstream, registration_replay_triggered],
                              #{count => 1}, #{trigger => breaker}),
            self() ! replay_next,
            {noreply, set_replay_queue(State, Agents)}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

%% Drip one agent off the replay queue per message. Each step re-proxies
%% exactly one ProxyRegister (through the circuit breaker) then schedules
%% the next after replay_spacing ms — so a fleet of N agents never blocks
%% the gen_server and a server that vanishes again mid-replay fails fast.
handle_info(replay_next, #state{replay_queue = []} = State) ->
    %% Queue drained — replay complete.
    {noreply, prune_recent_replays(State)};
handle_info(replay_next, #state{replay_queue = [{AgentId, SessionId, RegisterReq} | Rest],
                                replay_spacing = Spacing} = State) ->
    Before = notify_counts(State),
    State2 =
        case check_circuit(State) of
            {reject, State1} ->
                %% Circuit reopened during replay — the upstream went
                %% away again. Abandon the drip; the next genuine
                %% recovery (half_open -> closed) will reseed and
                %% restart it from a fresh registry snapshot.
                logger:warning("Registration replay aborted: circuit open "
                               "(~b agent(s) not yet re-proxied)", [length(Rest) + 1]),
                emit_queue_depth(0),
                prune_recent_replays(set_replay_queue(State1, []));
            {allow, #state{notify_pids = Pids} = State1}
                    when map_size(Pids) >= ?MAX_NOTIFY_INFLIGHT ->
                %% Back-pressure, not drop avoidance (#4632). A replay-ADOPTED
                %% session triggers a reannounce-driven CONNECTED
                %% (yuzu_gw_agent:reannounce/2 -> notify_stream_status). That
                %% cast is now HELD in the pending store when every notify
                %% slot is busy, so it can no longer be dropped at capacity;
                %% it only waits its turn behind the held entries. This
                %% check still paces the drip to the notify budget so a
                %% fleet-scale replay does not pile thousands of
                %% reannounce CONNECTEDs into the pending store at once.
                %% drain/1 keeps one slot free while replay_queue is
                %% non-empty, so this clause normally fires only when the slots
                %% were already full before the replay armed. It can also fire
                %% when a half_open notify probe takes the tenth slot after a
                %% verdict armed the replay (drain/1's half_open clause checks
                %% ?MAX_NOTIFY_INFLIGHT directly, not notify_budget/1); the
                %% same-head retry bounds the effect to one spacing tick or
                %% until the probe resolves, and nothing is lost. Retry the
                %% SAME head entry later (replay_queue is NOT advanced). replay_queue
                %% is untouched (still `[{AgentId, SessionId, RegisterReq} |
                %% Rest]`), so the same head retries on the next tick.
                schedule_replay_next(State1#state.replay_queue, Spacing),
                State1;
            {allow, State1} ->
                %% Step is {done, State} when this head entry is finished
                %% (replayed or skipped), or `abort' to drop the whole queue.
                Step =
                    case map_size(RegisterReq) of
                        0 ->
                            %% Agent registered without a stashed request
                            %% (older caller / test). Nothing to send — skip
                            %% it without disturbing the breaker.
                            logger:debug("Registration replay: skipping ~s (no stored request)",
                                        [yuzu_gw_env:log_text(AgentId)]),
                            emit_queue_depth(length(Rest)),
                            {done, State1};
                        _ ->
                            %% HA WS-4 4.4 (`#4246` #6): re-verify liveness
                            %% right before replaying — the drip is
                            %% self-paced (replay_spacing_ms apart), so by
                            %% the time this queued entry's turn comes up
                            %% the agent may have disconnected, or
                            %% reconnected under a BRAND-NEW session
                            %% (register_agent/6 overwrites its ETS row
                            %% wholesale). Replaying a stale snapshot's
                            %% session in either case would present an
                            %% orphaned session id the server should not
                            %% (and, post-4.4, will not) adopt — skip it
                            %% without touching the breaker, same as the
                            %% empty-RegisterReq case above. Re-using the
                            %% already-bound `SessionId` (the QUEUED value,
                            %% from this function's head) as the match
                            %% pattern here means the `{ok, {Pid, SessionId}}`
                            %% clause only fires when the CURRENT local
                            %% session still equals it — a mismatch (or no
                            %% row at all) falls to the catch-all clause.
                            case yuzu_gw_registry:lookup_local_session(AgentId) of
                                {ok, {Pid, SessionId}} ->
                                    %% Stamp here, and only here: the session
                                    %% is stamped when this drip really sends
                                    %% it (a breaker-seeded entry too), never
                                    %% when it was queued or skipped.
                                    {done, do_replay_one(AgentId, Pid, SessionId, RegisterReq,
                                                         length(Rest),
                                                         stamp_replayed(SessionId, State1))};
                                {error, unavailable} ->
                                    %% The registry's tables are gone (its process
                                    %% died; it is a sibling under one_for_one).
                                    %% Nothing queued can be re-verified, so drop
                                    %% the queue instead of crashing this process.
                                    %% A registry that died has lost its tables, so a
                                    %% later verdict finds no local session for these
                                    %% agents: they are not listed again into the replay.
                                    logger:warning("Registration replay aborted: registry unavailable "
                                                   "(~b queued entries dropped)", [length(Rest) + 1]),
                                    emit_queue_depth(0),
                                    abort;
                                _ ->
                                    logger:debug(
                                        "Registration replay: skipping ~s (no longer live "
                                        "locally, or reconnected under a different session, "
                                        "since this drip was queued)",
                                        [yuzu_gw_env:log_text(AgentId)]),
                                    emit_queue_depth(length(Rest)),
                                    {done, State1}
                            end
                    end,
                case Step of
                    {done, NextState} ->
                        schedule_replay_next(Rest, Spacing),
                        advance_queue(NextState, Rest);
                    abort ->
                        prune_recent_replays(set_replay_queue(State1, []))
                end
        end,
    %% The reserved slot is spent again as soon as the replay is over, and the
    %% skip and abort paths above do not drain on their own.
    {noreply, report_notify_counts(Before, drain(State2))};

handle_info(circuit_half_open, #state{cb_gen = Gen} = State) ->
    logger:info("Circuit breaker: open -> half_open (allowing probe RPC)"),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"half_open">>}),
    %% The only entry into half_open, so the only place the generation moves. A
    %% held notification is sent as the probe (drain/1).
    Before = notify_counts(State),
    publish_breaker(half_open),
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

handle_info({'DOWN', _MonRef, process, Pid, _Reason},
            #state{notify_pids = Pids, guardian_pids = GPids} = State) ->
    %% A finished notify OR guardian-forward worker. Remove from whichever set
    %% holds it (maps:remove on an absent key is a no-op, so both are safe). A
    %% freed notify slot is refilled from the pending store at once.
    Before = notify_counts(State),
    State1 = State#state{notify_pids = maps:remove(Pid, Pids),
                         guardian_pids = maps:remove(Pid, GPids)},
    {noreply, report_notify_counts(Before, drain(State1))};

handle_info(_Info, State) ->
    {noreply, State}.

%% @doc Fire one registration-replay ProxyRegister and classify the result.
%% Split out of handle_info(replay_next, ...) for the three-way branch HA
%% WS-4 4.4 (`#4246` #6) added: an ordinary adopt-success, the NEW
%% stale/zombie-replay refusal, and every other (transport-level) failure.
do_replay_one(AgentId, Pid, SessionId, RegisterReq, QueueDepth, State) ->
    %% HA WS-4 4.1 — carry the agent's EXISTING session id as
    %% `x-yuzu-session-id` outgoing metadata (the same header key Subscribe
    %% reads, yuzu_gw_agent_service.erl) on the replay ProxyRegister ONLY.
    %% This is a re-proxy of an agent connection the gateway already holds,
    %% not a new agent — the metadata lets the server treat it as a
    %% re-announce of the existing session rather than minting a new one on
    %% every upstream reconnect (which would otherwise let a zombie replay
    %% clobber a live agent's route once the routing directory is
    %% dispatch-authoritative, WS-4 4.2).
    Result = serial(fun() ->
                        do_rpc_replay('ProxyRegister', RegisterReq, register, SessionId)
                    end),
    NewState =
        case Result of
            {local_error, {Class, Why}} ->
                %% The stored request could not be encoded here, so nothing was
                %% sent: no verdict about the upstream, the breaker is not
                %% touched (record_result_no_replay/2 ignores it).
                logger:warning("Registration replay: ~s could not be encoded (~p:~p); "
                               "skipped without touching the circuit breaker",
                               [yuzu_gw_env:log_text(AgentId), Class, Why]),
                record_result_no_replay(Result, State);
            {ok, #{accepted := false} = Response} ->
                %% The server answered OK but did not install the session
                %% (RegisterResponse.accepted = false, e.g. a rejected
                %% enrollment). Re-announcing a session the server never
                %% installed would only be rejected again, and the next
                %% verdict would replay it again, so tear down this
                %% process's stream: the agent then registers again by
                %% itself through the gateway and follows its own outcome.
                %% The answer is authoritative, so it is a breaker SUCCESS
                %% (as for the superseded case below), and the attempt is
                %% stamped like any other replay. A MISSING `accepted' key
                %% still means accepted (the decoder always sets it on the
                %% wire; only test doubles omit it). The reason is the
                %% server's text, so it is cut before it is logged; no
                %% session id is logged.
                logger:warning("Registration replay: ~s was not accepted by the server (~s); "
                               "disconnecting so the agent follows its own registration path",
                               [yuzu_gw_env:log_text(AgentId), reject_reason_for_log(Response)]),
                yuzu_gw_agent:disconnect(Pid),
                record_result_no_replay({ok, Response}, State);
            {ok, Response} when is_map(Response) ->
                %% HA WS-4 4.4: the server now ALWAYS adopts the presented
                %% session on success (never a throwaway fresh mint, see
                %% gateway_route_store.hpp's FORWARD NOTE) — so
                %% AdoptedSession is expected to equal SessionId, but read
                %% it from the response rather than assume, mirroring
                %% yuzu_gw_agent_service:register/2's own defensive
                %% atom-or-binary-key lookup.
                AdoptedSession = maps:get(session_id, Response,
                                          maps:get(<<"session_id">>, Response, SessionId)),
                logger:debug("Registration replay: re-proxied ~s (adopted session ~s)",
                            [yuzu_gw_env:log_text(AgentId), yuzu_gw_env:log_text(AdoptedSession)]),
                %% Tell the process (confirmed live and holding SessionId by
                %% the caller's lookup_local_session/1 check) to re-send its
                %% own CONNECTED — this is what converges the server's
                %% freshly-installed AgentSession's gateway_node/
                %% wire_capabilities/stream_home_id (register_agent always
                %% wipes that trio, see gateway_service_impl.cpp's
                %% ProxyRegister), rather than leaving this agent
                %% dispatch-unreachable until its next real reconnect.
                yuzu_gw_agent:reannounce(Pid, AdoptedSession),
                record_result_no_replay({ok, Response}, State);
            {ok, _NotAMap} ->
                %% An OK whose message is not a decoded response (for example
                %% an OK with trailers and no DATA frame): the server never
                %% answered the registration, so this is a replay FAILURE like
                %% an RPC error. Neither the body nor the session id is logged.
                logger:warning("Registration replay: ~s got an upstream answer that is "
                               "not a response message", [yuzu_gw_env:log_text(AgentId)]),
                record_result_no_replay({error, malformed_response}, State);
            {error, {Status, _Message}} when Status =:= ?GRPC_STATUS_BIN_FAILED_PRECONDITION ->
                %% The presented session was superseded by a DIFFERENT, LIVE
                %% session server-side — a genuine stale/zombie replay, not
                %% an outage. The server answered authoritatively, so this
                %% is fed to the breaker as a SUCCESS (record_result_no_replay
                %% on a bare {error, _} would count it as a failure and could
                %% spuriously trip the breaker on a run of legitimately-stale
                %% replays after a fleet-wide reconnect storm). The sanctioned
                %% recovery is an AGENT-DRIVEN reconnect
                %% (gateway_route_store.hpp's FORWARD NOTE) — force it by
                %% tearing down this process's stream; the agent's own
                %% subsequent fresh Register carries no stale metadata.
                logger:warning("Registration replay: ~s's presented session was superseded — "
                              "forcing a fresh reconnect", [yuzu_gw_env:log_text(AgentId)]),
                yuzu_gw_agent:disconnect(Pid),
                record_result_no_replay({ok, superseded}, State);
            {error, Reason} ->
                logger:warning("Registration replay: ~s failed: ~p",
                               [yuzu_gw_env:log_text(AgentId), Reason]),
                record_result_no_replay(Result, State)
        end,
    %% Gate 7 sre OBS-4 — registration-replay observability. `replayed`
    %% counts this re-proxy attempt (any outcome); `queue_depth` lets an
    %% operator alert on a drip that never drains (UP-5 storm).
    telemetry:execute([yuzu, gw, upstream, registration_replay],
                      #{replayed => 1, queue_depth => QueueDepth}, #{}),
    drain(NewState).

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, #state{replay_queue = Queue} = State, _Extra) ->
    %% A cell put by an older version has fewer slots than this one writes:
    %% replace it with one that keeps the old slots, then publish the budget.
    ok = grow_cell(),
    {ok, set_replay_queue(State, Queue)}.

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
                    notify_pending = Pending, notify_probe = Probe} = State)
  when is_list(Queue), is_map(Recent) ->
    Fields = maps:from_list(lists:zip(record_info(fields, state),
                                      tl(tuple_to_list(State)))),
    (maps:without([replay_queue, recent_replays, notify_pending, notify_probe], Fields))#{
        replay_queue_len => length(Queue),
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
%%% Calls whose caller has died
%%%===================================================================

%% True when the process that made a call is a local process that has exited.
%% From is {Pid, Tag}. A caller on another node, or any form this does not
%% recognise, counts as alive: only a death that can be seen is acted on, and a
%% call that is wrongly run costs what it always cost. A caller that is alive
%% but stopped waiting (its call timed out) is not detected; its reply goes
%% nowhere and the RPC runs.
caller_gone({Pid, _Tag}) when is_pid(Pid), node(Pid) =:= node() ->
    not is_process_alive(Pid);
caller_gone(_From) ->
    false.

%% A queued proxy call whose caller is gone is dropped without an RPC. The
%% event feeds yuzu_gw_upstream_calls_dropped_total{rpc_name} in yuzu_gw_telemetry.
drop_call(Rpc, State) ->
    telemetry:execute([yuzu, gw, upstream, call_dropped],
                      #{count => 1}, #{rpc_name => atom_to_binary(Rpc, utf8)}),
    State.

%%%===================================================================
%%% Circuit breaker logic
%%%===================================================================

%% @doc Check if the circuit allows an RPC to proceed.
check_circuit(#state{cb_state = closed} = State) ->
    {allow, State};
check_circuit(#state{cb_state = half_open} = State) ->
    %% Allows any call-path or replay RPC while half_open; this clause does not
    %% count probes. The single-probe discipline for notifications lives in
    %% drain/1 (one held entry at a time), and resolve_probe/3 guards the result
    %% with the generation and state checks, because a call-path RPC can overlap
    %% the notify probe and move the breaker first.
    {allow, State};
check_circuit(#state{cb_state = open} = State) ->
    {reject, State}.

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
%% Used by the replay drip itself: a replay RPC must still advance the
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
    %% an in-flight drip from scratch. Each outage event arms at most
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
drain(#state{cb_state = closed, notify_pids = Pids, notify_pending = Pending,
             replay_queue = Replay} = State) ->
    case map_size(Pids) < notify_budget(Replay) of
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

%% @doc How many notify workers drain/1 may have in flight. While a registration
%% replay is active one slot is held back: the replay drip waits for fewer than
%% ?MAX_NOTIFY_INFLIGHT workers, and a backlog that refills every freed slot at
%% once would keep it waiting until the backlog is empty (#4632).
-spec notify_budget([term()]) -> pos_integer().
notify_budget([]) -> ?MAX_NOTIFY_INFLIGHT;
notify_budget(_ReplayQueue) -> ?MAX_NOTIFY_INFLIGHT - 1.

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

%% @doc Schedule the next replay step, unless the queue is now empty.
%% Spacing the steps keeps each handle_info short and rate-limits the
%% ProxyRegister fan-out so a fleet of N agents can't trip the breaker.
schedule_replay_next([], _Spacing) ->
    ok;
schedule_replay_next(_Rest, Spacing) ->
    erlang:send_after(Spacing, self(), replay_next),
    ok.

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
%% and the drip is started if the queue was empty. A running drip picks the
%% new entries up on its own. The log line carries counts only, never ids.
-spec enqueue_sessions([binary()], #state{}) -> #state{}.
enqueue_sessions(SessionIds, State0) ->
    #state{replay_queue = Queue, recent_replays = Recent,
           replay_queue_max = Max} = State = prune_recent_replays(State0),
    Entries = yuzu_gw_registry:entries_for_sessions(SessionIds),
    NotLocal = length(SessionIds) - length(Entries),
    QueueLen = length(Queue),
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
            emit_queue_depth(Size),
            case Queue of
                [] -> self() ! replay_next;
                _  -> ok
            end,
            set_replay_queue(State, Queue ++ lists:reverse(RevAppended))
    end.

%% @doc The head entry is finished: keep the rest of the queue. When that
%% empties the queue the replay is complete, so stale guard stamps are pruned
%% here (the `replay_next' clause for an empty queue is not reached after the
%% last pop).
advance_queue(State, []) ->
    prune_recent_replays(set_replay_queue(State, []));
advance_queue(State, Rest) ->
    set_replay_queue(State, Rest).

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

%% @doc Like do_rpc/3 but for the registration-replay path (HA WS-4 4.1):
%% attaches the agent's EXISTING session id as the `x-yuzu-session-id' request
%% header, through the client's metadata argument (yuzu_grpc_client:unary/5).
%% Undefined/empty SessionId (the register_agent/5 back-compat path) sends the
%% request with no such header, same as before this change.
do_rpc_replay(Method, Request, Tag, SessionId) when is_binary(SessionId), SessionId =/= <<>> ->
    do_rpc(Method, Request, Tag, #{<<"x-yuzu-session-id">> => SessionId});
do_rpc_replay(Method, Request, Tag, _SessionId) ->
    do_rpc(Method, Request, Tag, #{}).

-spec do_rpc(atom(), map(), atom(), map()) -> rpc_result().
do_rpc(Method, Request, Tag, Metadata) ->
    {InputType, OutputType} = rpc_types(Method),
    Def = #{marshal   => fun(Msg) -> encode_request(Msg, InputType) end,
            unmarshal => fun(Bin) -> gateway_pb:decode_msg(Bin, OutputType) end},
    Path = <<"/yuzu.gateway.v1.GatewayUpstream/", (atom_to_binary(Method, utf8))/binary>>,
    StartTime = erlang:monotonic_time(millisecond),
    Result = try yuzu_grpc_client:unary(Metadata, Path, Request, Def,
                                        #{channel => default_channel})
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
