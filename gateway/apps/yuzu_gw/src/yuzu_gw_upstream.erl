%%%-------------------------------------------------------------------
%%% @doc gRPC client to the C++ yuzu-server (control plane).
%%%
%%% Proxies Register, Inventory, and stream status notifications
%%% to the upstream server.
%%%
%%% Includes a circuit breaker to prevent cascading failures when the
%%% upstream server is unreachable. States:
%%%   closed    — RPCs pass through; consecutive failures tracked
%%%   open      — RPCs fail immediately with {error, circuit_open}
%%%   half_open — one probe RPC allowed; success closes, failure reopens
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
%%% Targeted replay on a heartbeat verdict (#1197 PR-C):
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
%%%   circuit_breaker_failure_threshold   — consecutive failures to trip (default 5)
%%%   circuit_breaker_reset_timeout_ms    — initial open duration (default 10000)
%%%   circuit_breaker_max_reset_timeout_ms — max backoff cap (default 300000)
%%%   registration_replay_spacing_ms      — gap between replay RPCs (default 20)
%%%   registration_replay_session_guard_ms - how long a replayed session is not
%%%                                          queued again by a verdict
%%%                                          (default 10000, valid 0..3600000)
%%%   registration_replay_queue_max       - most agents the replay queue holds
%%%                                          (default 10000, valid 1..1000000)
%%   cluster_id                          — this gateway's trust-zone/region id,
%%                                          stamped on every StreamStatusNotification
%%                                          (default <<"default">>; ADR-2002 §7)
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream).
-behaviour(gen_server).

-include_lib("grpcbox/include/grpcbox.hrl").

%% API
-export([start_link/0,
         proxy_register/1,
         proxy_inventory/1,
         notify_stream_status/5,
         forward_guardian_message/2,
         replay_sessions/1,
         circuit_state/0]).
-export([classify_tls_error/1]).  %% for testing (R-3 TLS-error classifier)

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
-define(DEFAULT_CB_THRESHOLD, 5).
-define(DEFAULT_CB_RESET_MS, 10000).
-define(DEFAULT_CB_MAX_RESET_MS, 300000).
-define(DEFAULT_REPLAY_SPACING_MS, 20).
-define(DEFAULT_REPLAY_SESSION_GUARD_MS, 10000).
-define(MAX_REPLAY_SESSION_GUARD_MS, 3600000).
-define(DEFAULT_REPLAY_QUEUE_MAX, 10000).
-define(MAX_REPLAY_QUEUE_MAX, 1000000).
%% Most session ids one replay_sessions cast may name. The same bound as
%% ?MAX_VERDICT_IDS in yuzu_gw_heartbeat_buffer, which applies it before the
%% cast; keep the two equal.
-define(MAX_REPLAY_SESSION_IDS, 4096).

%% CC-03 wire-capability handshake (proto/yuzu/gateway/v1/gateway.proto,
%% StreamStatusNotification.wire_capabilities): the literal this gateway
%% build advertises to prove its vendored agent.proto carries
%% CommandRequest.dispatch_tag = 9 and forwards it untouched. See
%% encode_command_request/1 in yuzu_gw_proto.erl for the forwarding half.
-define(WIRE_CAP_DISPATCH_TAG_V1, <<"command_dispatch_tag_v1">>).

-record(state, {
    notify_pids     :: #{pid() => true},
    %% Circuit breaker state
    cb_state        :: closed | open | half_open,
    cb_failures     :: non_neg_integer(),
    cb_threshold    :: non_neg_integer(),
    cb_base_timeout :: non_neg_integer(),
    cb_max_timeout  :: non_neg_integer(),
    cb_cur_timeout  :: non_neg_integer(),
    cb_timer        :: reference() | undefined,
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

%% @doc Forward a RegisterRequest to the C++ server.
-spec proxy_register(map()) -> {ok, map()} | {error, term()}.
proxy_register(RegisterReq) ->
    gen_server:call(?SERVER, {proxy_register, RegisterReq}, 30000).

%% @doc Forward an InventoryReport to the C++ server.
-spec proxy_inventory(map()) -> {ok, map()} | {error, term()}.
proxy_inventory(InventoryReport) ->
    gen_server:call(?SERVER, {proxy_inventory, InventoryReport}, 30000).

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
%% unknown in a BatchHeartbeat response (#1197 PR-C).
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

%% @doc Query the current circuit breaker state (for health checks).
-spec circuit_state() -> closed | open | half_open.
circuit_state() ->
    gen_server:call(?SERVER, circuit_state, 5000).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Threshold  = application:get_env(yuzu_gw, circuit_breaker_failure_threshold, ?DEFAULT_CB_THRESHOLD),
    BaseTimeout = application:get_env(yuzu_gw, circuit_breaker_reset_timeout_ms, ?DEFAULT_CB_RESET_MS),
    MaxTimeout  = application:get_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, ?DEFAULT_CB_MAX_RESET_MS),
    ReplaySpacing = application:get_env(yuzu_gw, registration_replay_spacing_ms, ?DEFAULT_REPLAY_SPACING_MS),
    SessionGuard = env_int(registration_replay_session_guard_ms,
                           ?DEFAULT_REPLAY_SESSION_GUARD_MS, 0, ?MAX_REPLAY_SESSION_GUARD_MS),
    QueueMax = env_int(registration_replay_queue_max,
                       ?DEFAULT_REPLAY_QUEUE_MAX, 1, ?MAX_REPLAY_QUEUE_MAX),
    ClusterId = ensure_binary(application:get_env(yuzu_gw, cluster_id, <<"default">>)),

    logger:info("Upstream client started (circuit breaker: threshold=~b, base_timeout=~bms, "
                "replay_spacing=~bms, replay_session_guard=~bms, replay_queue_max=~b, "
                "cluster_id=~s)",
                [Threshold, BaseTimeout, ReplaySpacing, SessionGuard, QueueMax, ClusterId]),

    {ok, #state{
        notify_pids     = #{},
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
    }}.

handle_call(circuit_state, _From, #state{cb_state = CbState} = State) ->
    {reply, CbState, State};

handle_call({proxy_register, RegisterReq}, _From, State) ->
    case check_circuit(State) of
        {reject, State1} ->
            {reply, {error, circuit_open}, State1};
        {allow, State1} ->
            Result = do_rpc('ProxyRegister', RegisterReq, register),
            State2 = record_result(Result, State1),
            {reply, Result, State2}
    end;

handle_call({proxy_inventory, InventoryReport}, _From, State) ->
    case check_circuit(State) of
        {reject, State1} ->
            {reply, {error, circuit_open}, State1};
        {allow, State1} ->
            Result = do_rpc('ProxyInventory', InventoryReport, inventory),
            State2 = record_result(Result, State1),
            {reply, Result, State2}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({notify_stream_status, AgentId, SessionId, Event, PeerAddr, StreamHomeId},
            #state{notify_pids = Pids, cb_state = CbState, cluster_id = ClusterId} = State) ->
    %% Don't spawn notifications if circuit is open
    case CbState of
        open ->
            logger:debug("Dropping stream status notification for ~s (circuit open)", [AgentId]),
            %% HA WS-4 4.4 review fix (F2): this drop was previously
            %% invisible — no telemetry, only a debug log line, matching
            %% the guardian-forward path's own forward_dropped counter
            %% (yuzu_gw_guardian_forward_tests.erl). A dropped CONNECTED for
            %% an ADOPTED replay session (the reannounce mechanism this
            %% slice added) means the server's placement stays wiped with
            %% NO observable signal — an I6a false-assurance risk.
            telemetry:execute([yuzu, gw, upstream, notify_dropped],
                              #{count => 1}, #{reason => <<"circuit_open">>}),
            {noreply, State};
        _ ->
            case map_size(Pids) >= ?MAX_NOTIFY_INFLIGHT of
                true ->
                    logger:debug("Dropping stream status notification for ~s (at capacity)", [AgentId]),
                    telemetry:execute([yuzu, gw, upstream, notify_dropped],
                                      #{count => 1}, #{reason => <<"at_capacity">>}),
                    {noreply, State};
                false ->
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
                        %% so the server can fence a stale DISCONNECTED from
                        %% tearing down a newer re-home under the same
                        %% reused session id.
                        stream_home_id => StreamHomeId
                    },
                    {Pid, _MonRef} = spawn_monitor(fun() ->
                        case do_rpc('NotifyStreamStatus', Notification, notify_stream) of
                            {ok, _} -> ok;
                            {error, Reason} ->
                                logger:warning("Failed to notify stream status for ~s: ~p",
                                               [AgentId, Reason])
                        end
                    end),
                    {noreply, State#state{notify_pids = Pids#{Pid => true}}}
            end
    end;

handle_cast({forward_guardian_message, AgentId, ResponseFrame},
            #state{guardian_pids = GPids, cb_state = CbState} = State) ->
    %% Best-effort, like notify_stream_status: skip if the circuit is open
    %% (upstream known-down) or the dedicated in-flight budget is full. Each
    %% accepted message is sent on its own monitored process so a slow upstream
    %% can't block the gen_server, and the count is bounded.
    case CbState of
        open ->
            logger:debug("Dropping guardian message for ~s (circuit open)", [AgentId]),
            telemetry:execute([yuzu, gw, guardian, forward_dropped],
                              #{count => 1}, #{reason => <<"circuit_open">>}),
            {noreply, State};
        _ ->
            case map_size(GPids) >= ?MAX_GUARDIAN_INFLIGHT of
                true ->
                    logger:debug("Dropping guardian message for ~s (at capacity)", [AgentId]),
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
                        case do_rpc('ForwardGuardianMessage', Request, guardian) of
                            {ok, _} -> ok;
                            {error, Reason} ->
                                logger:warning("Failed to forward guardian message for ~s: ~p",
                                               [AgentId, Reason])
                        end
                    end),
                    {noreply, State#state{guardian_pids = GPids#{Pid => true}}}
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
    %% complete. Since #1197 PR-C the running queue may be a TARGETED one
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
            {noreply, State#state{replay_queue = []}};
        _ ->
            logger:info("Registration replay: re-proxying ~b agent(s) upstream",
                        [length(Agents)]),
            telemetry:execute([yuzu, gw, upstream, registration_replay_triggered],
                              #{count => 1}, #{trigger => breaker}),
            self() ! replay_next,
            {noreply, State#state{replay_queue = Agents}}
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
                prune_recent_replays(State1#state{replay_queue = []});
            {allow, #state{notify_pids = Pids} = State1}
                    when map_size(Pids) >= ?MAX_NOTIFY_INFLIGHT ->
                %% HA WS-4 4.4 review fix (F2): a replay-ADOPTED session
                %% triggers a reannounce-driven CONNECTED
                %% (yuzu_gw_agent:reannounce/2 -> notify_stream_status),
                %% which shares the SAME ?MAX_NOTIFY_INFLIGHT budget as
                %% every other stream-status notify. Driving the drip at a
                %% fixed spacing regardless of that budget risks the
                %% notify being silently DROPPED at capacity (see
                %% handle_cast({notify_stream_status,...}) above) right
                %% when 4.4's convergence mechanism needs it most — a
                %% fleet-scale recovery replay is exactly when
                %% notify_pids is busiest. Retry the SAME head entry
                %% later (replay_queue is NOT advanced) rather than
                %% popping it and risking a dropped reannounce. replay_queue
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
                                        [AgentId]),
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
                                    %% the queue instead of crashing this process:
                                    %% each agent comes back on a later verdict.
                                    logger:warning("Registration replay aborted: registry unavailable "
                                                   "(~b queued entries dropped); they return on "
                                                   "their next heartbeat", [length(Rest) + 1]),
                                    emit_queue_depth(0),
                                    abort;
                                _ ->
                                    logger:debug(
                                        "Registration replay: skipping ~s (no longer live "
                                        "locally, or reconnected under a different session, "
                                        "since this drip was queued)", [AgentId]),
                                    emit_queue_depth(length(Rest)),
                                    {done, State1}
                            end
                    end,
                case Step of
                    {done, NextState} ->
                        schedule_replay_next(Rest, Spacing),
                        advance_queue(NextState, Rest);
                    abort ->
                        prune_recent_replays(State1#state{replay_queue = []})
                end
        end,
    {noreply, State2};

handle_info(circuit_half_open, State) ->
    logger:info("Circuit breaker: open -> half_open (allowing probe RPC)"),
    telemetry:execute([yuzu, gw, upstream, circuit_state],
                      #{count => 1},
                      #{state => <<"half_open">>}),
    {noreply, State#state{cb_state = half_open, cb_timer = undefined}};

handle_info({'DOWN', _MonRef, process, Pid, _Reason},
            #state{notify_pids = Pids, guardian_pids = GPids} = State) ->
    %% A finished notify OR guardian-forward worker. Remove from whichever set
    %% holds it (maps:remove on an absent key is a no-op, so both are safe).
    {noreply, State#state{notify_pids = maps:remove(Pid, Pids),
                          guardian_pids = maps:remove(Pid, GPids)}};

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
    Result = do_rpc_replay('ProxyRegister', RegisterReq, register, SessionId),
    NewState =
        case Result of
            {ok, #{accepted := false} = Response} ->
                %% The server answered OK but did not install the session
                %% (RegisterResponse.accepted = false, e.g. a rejected
                %% enrollment). Re-announcing a session the server never
                %% installed would only be rejected again, and the next
                %% verdict would replay it again, so tear down this process's
                %% stream: the agent then registers directly and follows its
                %% own outcome. The answer is authoritative, so it is a breaker
                %% SUCCESS (as for the superseded case below), and the attempt
                %% is stamped like any other replay. A MISSING `accepted' key
                %% still means accepted. The reason is the server's text, so
                %% it is cut before it is logged; no session id is logged.
                logger:warning("Registration replay: ~s was not accepted by the server (~s); "
                               "disconnecting so the agent follows its own registration path",
                               [AgentId, reject_reason_for_log(Response)]),
                yuzu_gw_agent:disconnect(Pid),
                record_result_no_replay({ok, Response}, State);
            {ok, Response} ->
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
                            [AgentId, AdoptedSession]),
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
            {error, {Status, _Message}} when Status =:= ?GRPC_STATUS_FAILED_PRECONDITION ->
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
                              "forcing a fresh reconnect", [AgentId]),
                yuzu_gw_agent:disconnect(Pid),
                record_result_no_replay({ok, superseded}, State);
            {error, Reason} ->
                logger:warning("Registration replay: ~s failed: ~p", [AgentId, Reason]),
                record_result_no_replay(Result, State)
        end,
    %% Gate 7 sre OBS-4 — registration-replay observability. `replayed`
    %% counts this re-proxy attempt (any outcome); `queue_depth` lets an
    %% operator alert on a drip that never drains (UP-5 storm).
    telemetry:execute([yuzu, gw, upstream, registration_replay],
                      #{replayed => 1, queue_depth => QueueDepth}, #{}),
    NewState.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% @doc What a crash report and sys:get_status/1 show of this process.
%%
%% The replay queue holds every queued agent's stored RegisterRequest
%% verbatim (enrollment_token, machine_certificate, csr_pem), and a crash
%% report prints the whole state: with a full queue that is credentials in
%% the log and, measured, 28 s and 179 MB of log for 10000 entries. So the
%% state is shown as a map of its scalar fields with replay_queue and
%% recent_replays replaced by their sizes (replay_queue_len,
%% recent_replays_size), and the last message is shown without the
%% request it carries. Only the report is affected: sys:get_state/1 still
%% returns the real record.
-spec format_status(map()) -> map().
format_status(Status) ->
    maps:map(fun(state, State)   -> redact_state(State);
                (message, Msg)   -> redact_message(Msg);
                (_Key, Value)    -> Value
             end, Status).

redact_state(#state{replay_queue = Queue, recent_replays = Recent} = State) ->
    Fields = maps:from_list(lists:zip(record_info(fields, state),
                                      tl(tuple_to_list(State)))),
    (maps:without([replay_queue, recent_replays], Fields))#{
        replay_queue_len => length(Queue),
        recent_replays_size => map_size(Recent)};
redact_state(_Other) ->
    '$redacted'.

%% The messages that carry a request, an inventory report, session ids or a
%% guardian frame; anything else is shown as is. gen_server hands the bare message to
%% the report, the wrappers are handled for sys:get_status/1 style callers.
redact_message({proxy_register, _Req})            -> {proxy_register, '$redacted'};
redact_message({proxy_inventory, _Report})        -> {proxy_inventory, '$redacted'};
redact_message({replay_sessions, _Ids})           -> {replay_sessions, '$redacted'};
redact_message({forward_guardian_message, AgentId, _Frame}) ->
    {forward_guardian_message, AgentId, '$redacted'};
redact_message({'$gen_call', From, Msg})          -> {'$gen_call', From, redact_message(Msg)};
redact_message({'$gen_cast', Msg})                -> {'$gen_cast', redact_message(Msg)};
redact_message(Msg)                               -> Msg.

%%%===================================================================
%%% Circuit breaker logic
%%%===================================================================

%% @doc Check if the circuit allows an RPC to proceed.
check_circuit(#state{cb_state = closed} = State) ->
    {allow, State};
check_circuit(#state{cb_state = half_open} = State) ->
    %% Allow exactly one probe RPC
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
record_result({error, _}, State) ->
    on_failure(State).

%% @doc Like record_result/2 but never triggers a registration replay.
%% Used by the replay drip itself: a replay RPC must still advance the
%% circuit breaker (so a mid-replay outage trips it), but it must not
%% kick off a second, nested replay cascade.
record_result_no_replay({ok, _}, State) ->
    {State1, _Trigger} = on_success(State),
    State1;
record_result_no_replay({error, _}, State) ->
    on_failure(State).

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

    State#state{
        cb_state      = open,
        cb_cur_timeout = NewTimeout,
        cb_timer      = TRef
    }.

cancel_timer(undefined) -> ok;
cancel_timer(TRef) -> erlang:cancel_timer(TRef).

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

%% @doc Queue the entries for the sessions a heartbeat verdict named (#1197
%% PR-C). Ids are resolved to entries by session (yuzu_gw_registry:
%% entries_for_sessions/1), and each pop is re-verified by agent
%% (lookup_local_session/1): two decisions, two keys.
%%
%% Per entry, in verdict order, the first rule that applies wins:
%%   - the agent is already queued: skipped. One pending entry per agent, so
%%     a second session for the same agent is not queued; the earlier entry
%%     is skipped as stale at its pop and the new session is listed again by
%%     the agent's next heartbeat.
%%   - the session was replayed within the guard window: skipped. The verdict
%%     was computed before that replay landed.
%%   - the queue is at its cap: dropped and counted (queue_full).
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
            State#state{replay_queue = Queue ++ lists:reverse(RevAppended)}
    end.

%% @doc The head entry is finished: keep the rest of the queue. When that
%% empties the queue the replay is complete, so stale guard stamps are pruned
%% here (the `replay_next' clause for an empty queue is not reached after the
%% last pop).
advance_queue(State, []) ->
    prune_recent_replays(State#state{replay_queue = []});
advance_queue(State, Rest) ->
    State#state{replay_queue = Rest}.

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

%% @doc The server's reject_reason, cut to 128 bytes for the log. Bytes, not
%% graphemes: the text is untrusted and need not be valid UTF-8.
reject_reason_for_log(Response) ->
    case maps:get(reject_reason, Response, <<>>) of
        Reason when is_binary(Reason) -> binary:part(Reason, 0, min(byte_size(Reason), 128));
        _                             -> <<>>
    end.

%% @doc Read an integer application env key that must lie in Min..Max; an
%% invalid value is logged (naming the key) and replaced by the default.
-spec env_int(atom(), integer(), integer(), integer()) -> integer().
env_int(Key, Default, Min, Max) ->
    case application:get_env(yuzu_gw, Key, Default) of
        Value when is_integer(Value), Value >= Min, Value =< Max ->
            Value;
        Bad ->
            logger:warning("Invalid ~s value ~p (expected an integer in ~b..~b); using ~b",
                           [Key, Bad, Min, Max, Default]),
            Default
    end.

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

do_rpc(Method, Request, Tag) ->
    do_rpc(Method, Request, Tag, ctx:background()).

%% @doc Like do_rpc/3 but for the registration-replay path (HA WS-4 4.1):
%% attaches the agent's EXISTING session id as `x-yuzu-session-id` outgoing
%% gRPC metadata, via grpcbox's ctx-carried metadata (grpcbox_metadata:
%% append_to_outgoing_ctx/2 + grpcbox_client_stream's metadata_headers/1,
%% which turns it into real request headers — this is the standard grpcbox
%% client mechanism, not a new wire path). Undefined/empty SessionId (the
%% register_agent/5 back-compat path) sends the request with no such header,
%% same as before this change.
do_rpc_replay(Method, Request, Tag, SessionId) when is_binary(SessionId), SessionId =/= <<>> ->
    Ctx = grpcbox_metadata:append_to_outgoing_ctx(
            ctx:background(), #{<<"x-yuzu-session-id">> => SessionId}),
    do_rpc(Method, Request, Tag, Ctx);
do_rpc_replay(Method, Request, Tag, _SessionId) ->
    do_rpc(Method, Request, Tag, ctx:background()).

do_rpc(Method, Request, Tag, Ctx) ->
    {InputType, OutputType} = rpc_types(Method),
    Def = #grpcbox_def{
        service       = 'yuzu.gateway.v1.GatewayUpstream',
        message_type  = atom_to_binary(InputType, utf8),
        marshal_fun   = fun(Msg) -> gateway_pb:encode_msg(Msg, InputType) end,
        unmarshal_fun = fun(Bin) -> gateway_pb:decode_msg(Bin, OutputType) end
    },
    Path = <<"/yuzu.gateway.v1.GatewayUpstream/", (atom_to_binary(Method, utf8))/binary>>,
    StartTime = erlang:monotonic_time(millisecond),
    Result = grpcbox_client:unary(Ctx, Path, Request, Def,
                                  #{channel => default_channel}),
    Duration = erlang:monotonic_time(millisecond) - StartTime,
    case Result of
        {ok, Response, _Headers} ->
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => atom_to_binary(Tag, utf8)}),
            {ok, Response};
        {error, {Status, Message}, _Trailers} ->
            %% HA WS-4 4.4 fix: grpcbox_client:unary/5's REAL error shape for
            %% a genuine (non-transport) grpc status is a 3-element tuple —
            %% `error`, the `{Status, Message}` pair, and the trailers map
            %% (grpcbox_client.erl's unary_handler, via recv_trailers/1) —
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
            %% binary digit string (`?GRPC_STATUS_*` in grpcbox.hrl), e.g.
            %% `<<"9">>` for FAILED_PRECONDITION — never an atom.
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => atom_to_binary(Tag, utf8),
                                code => Status}),
            logger:warning("Upstream RPC ~s failed: ~p ~s", [Method, Status, Message]),
            {error, {Status, Message}};
        {http_error, {Status, _}, _Trailers} ->
            %% HA WS-4 4.4 round-2 review fix (consistency-auditor c-1 /
            %% chaos-injector CH-2): a FOURTH real grpcbox_client:unary/5
            %% return shape (unary_handler's `{http_error, Status, Headers}`
            %% branch, grpcbox_client.erl) for a non-grpc-layer HTTP error
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
