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
%%% Configuration (sys.config / application env):
%%%   circuit_breaker_failure_threshold   — consecutive failures to trip (default 5)
%%%   circuit_breaker_reset_timeout_ms    — initial open duration (default 10000)
%%%   circuit_breaker_max_reset_timeout_ms — max backoff cap (default 300000)
%%%   registration_replay_spacing_ms      — gap between replay RPCs (default 20)
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
         circuit_state/0]).
-export([classify_tls_error/1]).  %% for testing (R-3 TLS-error classifier)

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

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
    ClusterId = ensure_binary(application:get_env(yuzu_gw, cluster_id, <<"default">>)),

    logger:info("Upstream client started (circuit breaker: threshold=~b, base_timeout=~bms, "
                "replay_spacing=~bms, cluster_id=~s)",
                [Threshold, BaseTimeout, ReplaySpacing, ClusterId]),

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

handle_cast(replay_registrations, #state{replay_queue = [_ | _]} = State) ->
    %% Gate 7 UP-5 — a drip is already in flight. The OLD behaviour
    %% reseeded `replay_queue` with a fresh full-fleet snapshot on every
    %% cast, so a server that flapped (fail→recover→fail→recover under
    %% packet loss) restarted the replay from zero each time and, at
    %% fleet scale, never drained. Drop the cast: the running drip
    %% already holds a registry snapshot and will complete. If the
    %% upstream genuinely went away again, check_circuit aborts the drip
    %% and the next true half_open->closed recovery reseeds from scratch.
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
    {noreply, State};
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
                State1#state{replay_queue = []};
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
                NextState =
                    case map_size(RegisterReq) of
                        0 ->
                            %% Agent registered without a stashed request
                            %% (older caller / test). Nothing to send — skip
                            %% it without disturbing the breaker.
                            logger:debug("Registration replay: skipping ~s (no stored request)",
                                        [AgentId]),
                            State1;
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
                            %% row at all) falls to the catch-all.
                            case yuzu_gw_registry:lookup_local_session(AgentId) of
                                {ok, {Pid, SessionId}} ->
                                    do_replay_one(AgentId, Pid, SessionId, RegisterReq,
                                                 length(Rest), State1);
                                _ ->
                                    logger:debug(
                                        "Registration replay: skipping ~s (no longer live "
                                        "locally, or reconnected under a different session, "
                                        "since this drip was queued)", [AgentId]),
                                    State1
                            end
                    end,
                schedule_replay_next(Rest, Spacing),
                NextState#state{replay_queue = Rest}
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
    logger:info("Upstream recovered (closed, ~b prior failures) — "
                "scheduling registration replay", [State#state.cb_failures]),
    {State#state{cb_failures = 0}, replay};
on_success(#state{cb_state = half_open, cb_base_timeout = BaseTimeout} = State) ->
    %% Probe succeeded — close the circuit, reset backoff. The breaker
    %% fully tripped, so the upstream was definitely down; replay.
    logger:info("Circuit breaker: half_open -> closed (probe succeeded) — "
                "scheduling registration replay"),
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
