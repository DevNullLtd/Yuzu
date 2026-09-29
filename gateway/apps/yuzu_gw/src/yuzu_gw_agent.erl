%%%-------------------------------------------------------------------
%%% @doc gen_statem: one Erlang process per connected agent.
%%%
%%% States:
%%%   connecting   → waiting for the subscribe handler to supply its pid
%%%   streaming    → bidi stream active; commands routed via stream_pid
%%%   disconnected → cleanup, deregister, terminate
%%%
%%% The subscribe handler process (yuzu_gw_agent_service:stream_loop/3)
%%% owns the grpcbox server stream and forwards data here as messages:
%%%   {stream_data, Frame}  — CommandResponse from agent
%%%   stream_closed         — agent disconnected (stream ended)
%%%   stream_error          — stream error (treated as disconnect)
%%%
%%% To send a command to the agent, we send {send_command, Cmd} to the
%%% stream_pid (the subscribe handler process), which calls
%%% grpcbox_stream:send(Cmd, State) to write it to the HTTP/2 stream.
%%%
%%% The agent process monitors stream_pid so that if the stream handler
%%% crashes without sending stream_closed, we still transition to
%%% disconnected and clean up.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent).
-behaviour(gen_statem).

%% API
-export([start_link/1,
         dispatch/3,
         get_info/1,
         disconnect/1,
         reannounce/2]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3, code_change/4]).
-export([connecting/3, streaming/3, disconnected/3]).

-record(data, {
    agent_id    :: binary(),
    session_id  :: binary() | undefined,
    stream_pid  :: pid() | undefined,     %% subscribe handler process
    stream_mon  :: reference() | undefined, %% monitor ref for stream_pid
    agent_info  :: map(),
    register_req :: map(),                %% verbatim RegisterRequest (for upstream-reconnect replay)
    plugins     :: [binary()],
    pending     :: #{binary() => {pid(), reference(), integer()}},  %% command_id => {reply_to, fanout_ref, dispatched_at}
    connected_at :: integer() | undefined,
    peer_addr   :: binary(),
    %% Opaque random id minted ONCE per process instance (HA WS-4, #4324) —
    %% stamped on both the CONNECTED (init/1) and DISCONNECTED (do_cleanup)
    %% StreamStatusNotification this process ever sends, so the server can
    %% fence a stale DISCONNECTED from a torn-down placement against a
    %% newer re-home reusing the same session id. NOT a counter — must stay
    %% collision-safe across gateway nodes and mixed-version clusters.
    stream_home_id :: binary()
}).

%%%===================================================================
%%% API
%%%===================================================================

-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

%% @doc Dispatch a command to this agent. Called by the router.
-spec dispatch(pid(), map(), {pid(), reference()}) -> ok.
dispatch(Pid, CommandReq, ReplyTo) ->
    gen_statem:cast(Pid, {dispatch, CommandReq, ReplyTo}).

%% @doc Get agent info (synchronous, for dashboard queries).
-spec get_info(pid()) -> {ok, map()} | {error, term()}.
get_info(Pid) ->
    gen_statem:call(Pid, get_info, 5000).

%% @doc Request graceful disconnect.
-spec disconnect(pid()) -> ok.
disconnect(Pid) ->
    gen_statem:cast(Pid, disconnect).

%% @doc HA WS-4 4.4 (`#4246` #6): tell this agent process its upstream
%% `ProxyRegister` replay was ADOPTED under `SessionId` (the server
%% published S, never a fresh mint) — so this process should RE-SEND its
%% own CONNECTED notification, republishing `gateway_node`/
%% `wire_capabilities`/`stream_home_id` through the existing, session-
%% guarded `NotifyStreamStatus` -> `set_gateway_route` path. This is the
%% mechanism that converges the server's in-memory placement after
%% `ProxyRegister` (which always installs a brand-new `AgentSession`,
%% wiping that trio — see gateway_service_impl.cpp's ProxyRegister) —
%% NOT a new state or a second `CONNECTED` for a DIFFERENT home; the
%% `streaming` clause below only acts when `SessionId` still matches this
%% process's OWN session, so a superseded/dead process ignores it (a cast
%% to a dead pid is silently dropped by the runtime; a cast to a pid that
%% has since moved on to a DIFFERENT session is dropped by the match
%% guard below), and it always resends the SAME `stream_home_id` this
%% process already holds — never a new one — so the standing invariant
%% against a same-session `CONNECTED(S, home2)` (gateway_route_store.hpp's
%% FORWARD NOTE) is not violated.
-spec reannounce(pid(), binary()) -> ok.
reannounce(Pid, SessionId) ->
    gen_statem:cast(Pid, {upstream_reannounced, SessionId}).

%%%===================================================================
%%% gen_statem callbacks
%%%===================================================================

callback_mode() -> [state_functions, state_enter].

init(#{agent_id := AgentId, agent_info := AgentInfo,
       stream_pid := StreamPid, peer_addr := PeerAddr} = Args) ->
    SessionId = maps:get(session_id, Args, undefined),
    Plugins = extract_plugin_names(AgentInfo),
    %% Verbatim RegisterRequest, threaded from the subscribe handler.
    %% Defaulted so an agent started without it (older callers, tests)
    %% still works — replay just skips agents whose req is empty.
    RegisterReq = maps:get(register_req, Args, #{}),

    %% Opaque per-process-instance id (HA WS-4, #4324): minted once here,
    %% never regenerated, and reused verbatim on the DISCONNECTED
    %% notification in do_cleanup/1. A CSPRNG value, not a counter —
    %% erlang:unique_integer/1 was rejected as per-BEAM-node and therefore
    %% collision-prone across gateway cluster nodes.
    StreamHomeId = string:lowercase(binary:encode_hex(crypto:strong_rand_bytes(16))),

    %% Monitor the stream handler process.
    StreamMon = case StreamPid of
        undefined -> undefined;
        _         -> monitor(process, StreamPid)
    end,

    Data = #data{
        agent_id    = AgentId,
        session_id  = SessionId,
        stream_pid  = StreamPid,
        stream_mon  = StreamMon,
        agent_info  = AgentInfo,
        register_req = RegisterReq,
        plugins     = Plugins,
        pending     = #{},
        connected_at = erlang:system_time(millisecond),
        peer_addr   = PeerAddr,
        stream_home_id = StreamHomeId
    },

    %% Register in routing table and join pg groups. The RegisterRequest
    %% is stashed in the registry so yuzu_gw_upstream can re-proxy it
    %% when the upstream connection re-establishes.
    Hostname = maps:get(<<"hostname">>, AgentInfo,
                        maps:get(hostname, AgentInfo, <<>>)),
    yuzu_gw_registry:register_agent(AgentId, self(), SessionId, Plugins,
                                    Hostname, RegisterReq),

    %% Notify WatchEvents subscribers.
    notify_watchers(#{agent_id    => AgentId,
                      occurred_at => #{millis_epoch => erlang:system_time(millisecond)},
                      event       => {connected, #{session_id => ensure_binary(SessionId)}}}),

    telemetry:execute([yuzu, gw, agent, connected],
                      #{count => 1},
                      #{agent_id => AgentId, node => node(),
                        session_id => SessionId}),

    logger:info("Agent ~s connected from ~s (session=~s)",
                [AgentId, PeerAddr, SessionId]),

    %% Notify C++ server about the stream connection.
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr,
                                           StreamHomeId),

    case StreamPid of
        undefined -> {ok, connecting, Data};
        _         -> {ok, streaming, Data}
    end.

%%--------------------------------------------------------------------
%% State: connecting — waiting for subscribe handler pid
%%--------------------------------------------------------------------

connecting(enter, _OldState, _Data) ->
    keep_state_and_data;

connecting(cast, {stream_ready, StreamPid}, Data) ->
    Mon = monitor(process, StreamPid),
    {next_state, streaming, Data#data{stream_pid = StreamPid,
                                       stream_mon = Mon,
                                       connected_at = erlang:system_time(millisecond)}};

connecting(cast, {dispatch, _CommandReq, {ReplyTo, FanoutRef}}, Data) ->
    %% Cannot dispatch while still connecting — reject immediately.
    ReplyTo ! {command_error, FanoutRef, Data#data.agent_id, not_connected},
    keep_state_and_data;

connecting({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, format_info(Data, connecting)}}]};

connecting({call, From}, pending_count, _Data) ->
    {keep_state_and_data, [{reply, From, 0}]};

connecting(info, stream_closed, Data) ->
    {next_state, disconnected, Data};

connecting(info, {'DOWN', MonRef, process, _Pid, _Reason},
           #data{stream_mon = MonRef} = Data) ->
    {next_state, disconnected, Data};

connecting(cast, disconnect, Data) ->
    {next_state, disconnected, Data};

connecting(cast, {upstream_reannounced, SessionId},
           #data{session_id = SessionId, agent_id = AgentId, peer_addr = PeerAddr,
                stream_home_id = StreamHomeId}) ->
    %% HA WS-4 4.4 review fix (N1): init/1 sends this process's ONLY
    %% CONNECTED before the state machine ever reaches `connecting`
    %% (neither `connecting` nor `stream_ready`'s transition to
    %% `streaming` sends a second one) — so an ADOPT landing in this
    %% narrow window, before Subscribe's stream_pid arrives, must still
    %% re-announce here, or the server's placement (wiped by
    %% `register_agent`) stays unrecovered until this session eventually
    %% disconnects and reconnects. Same payload, same mechanism as the
    %% `streaming` clause below — only the state differs.
    logger:debug("Agent ~s: upstream adopted replay under session ~s — re-announcing "
                "CONNECTED (still connecting) to converge server-side placement",
                [AgentId, SessionId]),
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr,
                                          StreamHomeId),
    keep_state_and_data;

connecting(cast, {upstream_reannounced, _OtherSessionId}, _Data) ->
    %% A superseded session — same rationale as streaming's own mismatch
    %% clause below.
    keep_state_and_data.

%%--------------------------------------------------------------------
%% State: streaming — the hot path
%%--------------------------------------------------------------------

streaming(enter, _OldState, _Data) ->
    keep_state_and_data;

streaming(cast, {dispatch, CommandReq, {ReplyTo, FanoutRef}}, Data) ->
    #data{stream_pid = StreamPid, agent_id = AgentId, pending = Pending} = Data,
    CmdId = maps:get(<<"command_id">>, CommandReq, maps:get(command_id, CommandReq, undefined)),
    Plugin = maps:get(<<"plugin">>, CommandReq,
                      maps:get(plugin, CommandReq, <<"unknown">>)),

    %% Send command to the subscribe handler, which writes it to the HTTP/2 stream.
    %% CommandReq is forwarded whole — `dispatch_tag` (field 9) rides through
    %% untouched here exactly like `payload` (field 8) does: neither is read
    %% or rebuilt on this path, so the stream handler's gpb re-encode is the
    %% only place either field could be lost, and both are mirrored into the
    %% gateway's vendored agent.proto for that reason.
    StreamPid ! {send_command, CommandReq},

    telemetry:execute([yuzu, gw, command, dispatched],
                      #{count => 1},
                      #{agent_id => AgentId, plugin => Plugin,
                        command_id => CmdId}),

    Pending2 = Pending#{CmdId => {ReplyTo, FanoutRef, erlang:monotonic_time(millisecond)}},
    {keep_state, Data#data{pending = Pending2}};

streaming(info, {stream_data, ResponseFrame}, #data{agent_id = AgentId} = Data) ->
    %% Guardian side-channel ("__guard__") frames are unsolicited (no
    %% command_id in `pending`) and carry a drift event for the control plane,
    %% not a reply to a dispatched command. Intercept and forward them upstream
    %% BEFORE the command-correlation path — otherwise they would hit the
    %% orphan-drop in handle_stream_response/2. AgentId is the gateway-asserted
    %% bound identity (never read from the frame).
    case yuzu_gw_guardian:intercept(AgentId, ResponseFrame) of
        forwarded   -> keep_state_and_data;
        passthrough -> handle_stream_response(ResponseFrame, Data)
    end;

streaming(info, stream_closed, Data) ->
    {next_state, disconnected, Data};

streaming(info, {stream_error, Reason}, Data) ->
    logger:warning("Stream error for agent ~s: ~p", [Data#data.agent_id, Reason]),
    {next_state, disconnected, Data};

streaming(info, {'DOWN', MonRef, process, _Pid, _Reason},
          #data{stream_mon = MonRef} = Data) ->
    logger:warning("Stream handler died for agent ~s", [Data#data.agent_id]),
    {next_state, disconnected, Data};

streaming({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, format_info(Data, streaming)}}]};

streaming({call, From}, pending_count, #data{pending = Pending}) ->
    {keep_state_and_data, [{reply, From, maps:size(Pending)}]};

streaming(cast, disconnect, Data) ->
    #data{stream_pid = StreamPid} = Data,
    %% Signal the subscribe handler to close the stream.
    case StreamPid of
        undefined -> ok;
        _         -> StreamPid ! close_stream
    end,
    {next_state, disconnected, Data};

streaming(cast, {upstream_reannounced, SessionId},
          #data{session_id = SessionId, agent_id = AgentId, peer_addr = PeerAddr,
               stream_home_id = StreamHomeId}) ->
    %% HA WS-4 4.4 (`#4246` #6, reannounce/2's doc comment): SessionId still
    %% matches this process's own session (the equality is enforced by the
    %% pattern match, not a guard) — re-send the SAME CONNECTED payload this
    %% process already advertised at init/1, republishing gateway_node/
    %% wire_capabilities/stream_home_id through the ordinary session-guarded
    %% path. Does not change `Data` (nothing about THIS process's own state
    %% changed — only the server's independently-installed placement did).
    logger:debug("Agent ~s: upstream adopted replay under session ~s — re-announcing "
                "CONNECTED to converge server-side placement", [AgentId, SessionId]),
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr,
                                          StreamHomeId),
    keep_state_and_data;

streaming(cast, {upstream_reannounced, _OtherSessionId}, Data) ->
    %% This process has since moved on to a DIFFERENT session than the one
    %% the (now-stale) replay drip entry adopted — a benign race between the
    %% drip and a genuine agent reconnect. Ignore; the reconnect's own
    %% CONNECTED already carries the correct, current placement.
    logger:debug("Agent ~s: ignoring stale upstream_reannounced for a superseded session",
                [Data#data.agent_id]),
    keep_state_and_data.

%%--------------------------------------------------------------------
%% State: disconnected — cleanup and terminate
%%--------------------------------------------------------------------

disconnected(enter, _OldState, Data) ->
    do_cleanup(Data),
    {stop, normal, Data};

disconnected(_EventType, _Event, _Data) ->
    keep_state_and_data.

%%--------------------------------------------------------------------
%% terminate
%%--------------------------------------------------------------------

terminate(normal, _State, _Data) ->
    %% Already cleaned up in disconnected(enter, ...).
    ok;
terminate(_Reason, _State, Data) ->
    do_cleanup(Data),
    ok.

code_change(_OldVsn, State, Data, _Extra) ->
    {ok, State, Data}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% Correlate a non-Guardian response frame to a pending command and forward it
%% to the waiting caller, or drop it as orphaned. Guardian side-channel frames
%% ("__guard__") are intercepted in streaming/3 before reaching here.
handle_stream_response(ResponseFrame, #data{agent_id = AgentId, pending = Pending} = Data) ->
    CmdId = maps:get(<<"command_id">>, ResponseFrame,
                     maps:get(command_id, ResponseFrame, undefined)),
    Status = maps:get(<<"status">>, ResponseFrame,
                      maps:get(status, ResponseFrame, undefined)),

    case maps:find(CmdId, Pending) of
        {ok, {ReplyTo, FanoutRef, DispatchedAt}} ->
            ReplyTo ! {command_response, FanoutRef, AgentId, ResponseFrame},

            Pending2 = case Status of
                'RUNNING'          -> Pending;
                <<"RUNNING">>      -> Pending;
                0                  -> Pending;  %% proto enum value
                _FinalStatus       ->
                    Duration = erlang:monotonic_time(millisecond) - DispatchedAt,
                    Plugin = maps:get(<<"plugin">>, ResponseFrame,
                                      maps:get(plugin, ResponseFrame, <<"unknown">>)),
                    telemetry:execute([yuzu, gw, command, completed],
                                      #{duration_ms => Duration},
                                      #{agent_id => AgentId, plugin => Plugin, status => Status}),
                    %% Notify the router that is actually TRACKING this
                    %% fanout. HA WS-4 4.3a fix: that router lives on the
                    %% DISPATCHING node, which — once cross-node routing
                    %% exists (`yuzu_gw_registry:lookup/1`'s `pg` fallback)
                    %% — is not necessarily THIS (the agent process's) node.
                    %% `ReplyTo` is the fanout's `CallerPid` (mgmt-service
                    %% handler process, `yuzu_gw_router.erl`'s `#fanout.from`),
                    %% always co-located with its own node's `yuzu_gw_router`
                    %% (`yuzu_gw_router.erl`'s `?SERVER` is a LOCAL-only
                    %% `gen_server:start_link({local, ...})`) — so
                    %% `node(ReplyTo)` names the right node. The prior local
                    %% `whereis(yuzu_gw_router)` silently no-oped on a
                    %% cross-node dispatch (this agent's OWN node's router,
                    %% which was never tracking a fanout it didn't originate),
                    %% stranding the fanout until the 300s `fanout_timeout`
                    %% fallback — invisible until cross-node routing made this
                    %% reachable. `{Name, Node} ! Msg` is fire-and-forget: an
                    %% unreachable node or unregistered name is silently
                    %% dropped, matching the previous local `undefined -> ok`
                    %% no-op semantics exactly.
                    {yuzu_gw_router, node(ReplyTo)} ! {fanout_terminal, FanoutRef, AgentId},
                    maps:remove(CmdId, Pending)
            end,
            {keep_state, Data#data{pending = Pending2}};

        error ->
            logger:debug("Orphaned response from ~s for cmd ~s", [AgentId, CmdId]),
            keep_state_and_data
    end.

do_cleanup(#data{agent_id = AgentId, session_id = SessionId,
                  connected_at = ConnectedAt, pending = Pending,
                  peer_addr = PeerAddr, stream_home_id = StreamHomeId}) ->
    %% Deregister from routing table and pg groups.
    yuzu_gw_registry:deregister_agent(AgentId),

    %% Notify pending command waiters that the agent disconnected,
    %% and notify router so it can complete fanout tracking.
    maps:foreach(fun(_CmdId, {ReplyTo, FanoutRef, _DispatchedAt}) ->
        ReplyTo ! {command_error, FanoutRef, AgentId, agent_disconnected},
        %% HA WS-4 4.3a fix: route to the DISPATCHING node's router, same
        %% reasoning as handle_stream_response/2 above.
        {yuzu_gw_router, node(ReplyTo)} ! {fanout_terminal, FanoutRef, AgentId}
    end, Pending),

    Duration = case ConnectedAt of
        undefined -> 0;
        T         -> erlang:system_time(millisecond) - T
    end,

    telemetry:execute([yuzu, gw, agent, disconnected],
                      #{count => 1, duration_ms => Duration},
                      #{agent_id => AgentId, reason => normal}),

    %% Notify C++ server. Same StreamHomeId minted at CONNECTED (init/1) —
    %% never a freshly-minted value — so the server can match this
    %% DISCONNECTED to the placement it actually tears down (HA WS-4).
    yuzu_gw_upstream:notify_stream_status(AgentId,
                                           SessionId,
                                           disconnected,
                                           PeerAddr,
                                           StreamHomeId),

    %% Notify WatchEvents subscribers.
    notify_watchers(#{agent_id    => AgentId,
                      occurred_at => #{millis_epoch => erlang:system_time(millisecond)},
                      event       => {disconnected, #{reason => <<"normal">>}}}),

    logger:info("Agent ~s disconnected (was connected ~bms)", [AgentId, Duration]),
    ok.

notify_watchers(Event) ->
    Watchers = pg:get_members(yuzu_gw, event_watchers),
    lists:foreach(fun(W) -> W ! {agent_event, Event} end, Watchers).

ensure_binary(undefined) -> <<>>;
ensure_binary(B) when is_binary(B) -> B.

extract_plugin_names(AgentInfo) ->
    Plugins = maps:get(<<"plugins">>, AgentInfo,
                       maps:get(plugins, AgentInfo, [])),
    [maps:get(<<"name">>, P, maps:get(name, P, <<"unknown">>)) || P <- Plugins].

format_info(#data{agent_id = AgentId, session_id = SessionId,
                   plugins = Plugins, connected_at = ConnectedAt,
                   agent_info = AgentInfo, peer_addr = PeerAddr,
                   pending = Pending}, State) ->
    Hostname = maps:get(<<"hostname">>, AgentInfo,
                        maps:get(hostname, AgentInfo, <<>>)),
    #{agent_id     => AgentId,
      session_id   => SessionId,
      state        => State,
      plugins      => Plugins,
      hostname     => Hostname,
      connected_at => ConnectedAt,
      peer_addr    => PeerAddr,
      agent_info   => AgentInfo,
      pending_cmds => maps:size(Pending)}.
