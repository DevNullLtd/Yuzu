%%%-------------------------------------------------------------------
%%% @doc gen_statem: one Erlang process per connected agent.
%%%
%%% States:
%%%   registering  → the first event after init/1: the registry call
%%%   recovering   → the first event of a RESTARTED owner (see below)
%%%   connecting   → waiting for the subscribe handler to supply its pid
%%%   streaming    → bidi stream active; commands routed via stream_pid
%%%   disconnected → cleanup, deregister, terminate
%%%
%%% Registration runs after init/1 has returned, never inside it. There is one
%%% agent supervisor per gateway and `supervisor:start_child' returns only when
%%% init/1 does, so a registry call (30 s timeout) made in init/1 held every
%%% other agent's start_child, and the supervisor's handling of child exits,
%%% for as long as the registry took: in a reconnect storm the storm was
%%% serialised through the supervisor. start_link_async/1 (the supervisor's
%%% start function) returns as soon as the process exists. A caller that needs
%%% the outcome (the Subscribe handler, through yuzu_gw_agent_sup:start_agent/1,
%%% and start_link/1) passes an alias in `registered_ack' and waits for it in
%%% await_registration/2, in its OWN process.
%%%
%%% A refused registration (session_limit, registry_unavailable) is answered on
%%% the alias and the process stops with reason `normal': it has done nothing
%%% that needs undoing, and a storm of refusals must not write a crash report
%%% each, nor count against the agent supervisor's restart intensity (its
%%% children are `transient': only an abnormal exit is restarted).
%%%
%%% == A restarted owner (OWNER-RESTART, #5695) ==
%%%
%%% An owner started by yuzu_gw_agent_sup has a row in the owner table (see
%%% that module) holding its session, its stream, its RegisterRequest, the
%%% stream_home_id it minted and the last stream-status notice it sent. When it
%%% dies abnormally (an exception, a kill) the supervisor restarts it with the
%%% same row key, and the new process starts in `recovering':
%%%   1. If the predecessor's last notice was CONNECTED, it sends the
%%%      DISCONNECTED for that session with the predecessor's stream_home_id
%%%      (the server matches a DISCONNECTED to the placement by it), unless an
%%%      earlier restart already did. An exception also runs the dying owner's
%%%      terminate/3, which only answers its pending commands' waiters: one
%%%      process sends the notice, never two. A kill runs nothing, which is why
%%%      the notice is the successor's job.
%%%   2. Budget: at most ?MAX_RESTARTS restarts in ?RESTART_WINDOW_MS. Past it
%%%      the owner gives up: it closes the agent's stream (the agent reconnects
%%%      by itself) and ends `normal', which the supervisor does not restart.
%%%   3. Recovery, each step a condition of the next; any failure closes the
%%%      stream and ends `normal' after the DISCONNECTED (outcome
%%%      disconnected_only):
%%%      - the agent is not routed to another live process (a newer
%%%        registration of the agent superseded the session);
%%%      - the Subscribe stream re-attaches: the stream process monitors its
%%%        owner and, after an abnormal owner exit, waits a few seconds for a
%%%        re-attach naming the dead owner (yuzu_gw_agent_service);
%%%      - the DISCONNECTED is settled upstream (yuzu_gw_upstream:
%%%        notify_settled/4): the next step presents the same session to the
%%%        server again, which must not see the DISCONNECTED after it;
%%%      - the registry takes the session again, refusing if a live process
%%%        holds the agent (yuzu_gw_registry:recover_agent/7);
%%%      - the server adopts the session again (yuzu_gw_upstream:
%%%        reregister_session/3, a ProxyRegister presenting the session id, as
%%%        a registration replay does).
%%%      Then it announces CONNECTED for the same session with the SAME
%%%      stream_home_id (never a new one: the server rejects a CONNECTED for a
%%%      known session at a different home, gateway_route_store.hpp's standing
%%%      invariant) and streams as before. Commands in flight at the crash are
%%%      lost with the predecessor: an exception answers their waiters
%%%      agent_disconnected; after a kill the router's fan-out timeout ends
%%%      them.
%%% Supervised owners trap exits, so a supervisor shutdown (planned stop, or
%%% the agent supervisor escalating) runs terminate/3 and sends each session's
%%% DISCONNECTED. An owner started directly (start_link/1, tests) has no row,
%%% does not trap exits and is never restarted: an abnormal exit cleans up in
%%% terminate/3 as before.
%%%
%%% The subscribe handler process (yuzu_gw_agent_service:stream_loop/3)
%%% owns the gRPC server stream and forwards data here as messages:
%%%   {stream_data, Frame}  — CommandResponse from agent
%%%   stream_closed         — agent disconnected (stream ended)
%%%   stream_error          — stream error (treated as disconnect)
%%%
%%% To send a command to the agent, we send {send_command, Cmd} to the
%%% stream_pid (the subscribe handler process), which calls
%%% yuzu_grpc_stream:send(State, Cmd) to write it to the HTTP/2 stream.
%%%
%%% The agent process monitors stream_pid so that if the stream handler
%%% crashes without sending stream_closed, we still transition to
%%% disconnected and clean up.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent).
-behaviour(gen_statem).

-include("yuzu_grpc_client.hrl").

%% API
-export([start_link/1,
         start_link_async/1,
         await_registration/2,
         dispatch/3,
         get_info/1,
         disconnect/1,
         reannounce/2]).

%% gen_statem callbacks
-export([callback_mode/0, init/1, terminate/3, code_change/4, format_status/1]).
-export([registering/3, recovering/3, connecting/3, streaming/3, disconnected/3]).

%% How long a caller of await_registration/2 waits. The agent's registry call
%% gives up after 30 s (yuzu_gw_registry:register_agent/7) and the agent then
%% answers, so this is only reached by an agent that cannot run at all.
-define(REGISTRATION_WAIT_MS, 35000).

%% OWNER-RESTART (#5695). The restart budget of one owner: a restarted owner
%% that finds this many restarts already inside the window gives up.
-define(MAX_RESTARTS, 3).
-define(RESTART_WINDOW_MS, 60000).
%% How long a restarted owner waits for its stream to answer the re-attach (the
%% stream waits 5 s for one, see yuzu_gw_agent_service), for the predecessor's
%% DISCONNECTED to be settled upstream, and for the server to adopt the session.
-define(REATTACH_WAIT_MS, 2000).
-define(SETTLE_WAIT_MS, 10000).
-define(REREGISTER_MS, 10000).

-record(data, {
    agent_id    :: binary(),
    session_id  :: binary() | undefined,
    stream_pid  :: pid() | undefined,     %% subscribe handler process
    stream_mon  :: reference() | undefined, %% monitor ref for stream_pid
    agent_info  :: map(),
    register_req :: map(),                %% verbatim RegisterRequest (for upstream-reconnect replay)
    plugins     :: [binary()],
    %% command_id => {reply_to, fanout_ref, dispatched_at, plugin}. The plugin
    %% is the one the command was dispatched for: a CommandResponse carries
    %% `plugin' only on the Guardian side channel, so a reply cannot label the
    %% duration histogram itself (it decodes as <<>>).
    pending     :: #{binary() => {pid(), reference(), integer(), term()}},
    connected_at :: integer() | undefined,
    peer_addr   :: binary(),
    %% Opaque random id minted ONCE per session placement (HA WS-4, #4324) by
    %% the session's first owner, and reused unchanged by an owner restarted
    %% after a crash (OWNER-RESTART: the server rejects a CONNECTED for a known
    %% session at a different home) — stamped on every CONNECTED and
    %% DISCONNECTED StreamStatusNotification for the session, so the server can
    %% fence a stale DISCONNECTED from a torn-down placement against a newer
    %% re-home reusing the same session id. NOT a counter — must stay
    %% collision-safe across gateway nodes and mixed-version clusters.
    stream_home_id :: binary(),
    %% The key of this owner's row in the owner table (yuzu_gw_agent_sup), or
    %% undefined for an owner started without the supervisor (start_link/1).
    owner_key = undefined :: reference() | undefined
}).

%%%===================================================================
%%% API
%%%===================================================================

%% @doc Start an agent process and return once its registration is decided:
%% `{ok, Pid}' with the agent in the routing table, or `{error, Reason}' for a
%% refused one (session_limit, registry_unavailable), the process then gone.
%% The wait is in the caller; for direct callers and tests. The supervisor uses
%% start_link_async/1.
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Args) ->
    Alias = alias([reply]),
    case start_link_async(Args#{registered_ack => Alias}) of
        {ok, Pid} ->
            await_registration(Pid, Alias);
        Error ->
            unalias(Alias),
            Error
    end.

%% @doc Start an agent process and return as soon as it exists; the
%% registration is its first event. The agent supervisor's start function.
%% With `registered_ack => Alias' in Args the outcome is sent to Alias (see
%% await_registration/2).
-spec start_link_async(map()) -> {ok, pid()} | {error, term()}.
start_link_async(Args) ->
    gen_statem:start_link(?MODULE, Args, []).

%% @doc Wait, in the calling process, for the registration outcome of Pid,
%% started with `registered_ack => Alias' (an alias the caller made with
%% `alias([reply])'). `{error, session_limit | registry_unavailable}' as the
%% registry answered; `{error, registry_unavailable}' too when the agent does
%% not answer in time (it is then told to disconnect, which it does once its
%% registry call returns) or dies first. Fixed reasons only: a crash reason
%% could carry the stored RegisterRequest.
-spec await_registration(pid(), reference()) -> {ok, pid()} | {error, term()}.
await_registration(Pid, Alias) ->
    MRef = monitor(process, Pid),
    receive
        {Alias, registered} ->
            demonitor(MRef, [flush]),
            {ok, Pid};
        {Alias, {refused, Reason}} ->
            %% The process stops right after answering; return once it is gone.
            receive {'DOWN', MRef, process, Pid, _} -> ok
            after 5000 -> demonitor(MRef, [flush])
            end,
            {error, Reason};
        {'DOWN', MRef, process, Pid, _} ->
            unalias(Alias),
            {error, registry_unavailable}
    after ?REGISTRATION_WAIT_MS ->
        unalias(Alias),
        demonitor(MRef, [flush]),
        disconnect(Pid),
        {error, registry_unavailable}
    end.

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

init(#{owner_key := Key} = Start) ->
    %% Started by yuzu_gw_agent_sup: the arguments are in the owner table. A
    %% first start mints the stream home; a row that has one belongs to a
    %% predecessor that died, and this process recovers it. Never fails: a
    %% restart whose start failed would count against the supervisor again.
    process_flag(trap_exit, true),
    case yuzu_gw_agent_sup:owner_row(Key) of
        {ok, #{home := undefined, args := Args}} ->
            Home = mint_stream_home(),
            ok = yuzu_gw_agent_sup:owner_set(Key, [{home, Home}, {pid, self()}]),
            init_owner(Args#{registered_ack => maps:get(registered_ack, Start, undefined)},
                       Key, Home);
        {ok, #{pid := Predecessor}} ->
            ok = yuzu_gw_agent_sup:owner_set(Key, [{pid, self()}]),
            {ok, recovering, {recover, Key, Predecessor}, [{next_event, internal, recover}]};
        none ->
            {ok, recovering, {recover, Key, undefined}, [{next_event, internal, recover}]}
    end;
init(Args) ->
    init_owner(Args, undefined, mint_stream_home()).

%% Opaque per-process-instance id (HA WS-4, #4324): minted once per session's
%% first owner, never regenerated (a restarted owner reuses it), and stamped on
%% the CONNECTED and DISCONNECTED notifications. A CSPRNG value, not a counter
%% — erlang:unique_integer/1 was rejected as per-BEAM-node and therefore
%% collision-prone across gateway cluster nodes.
mint_stream_home() ->
    string:lowercase(binary:encode_hex(crypto:strong_rand_bytes(16))).

init_owner(#{agent_id := AgentId, agent_info := AgentInfo,
             stream_pid := StreamPid, peer_addr := PeerAddr} = Args, OwnerKey, StreamHomeId) ->
    SessionId = maps:get(session_id, Args, undefined),
    Plugins = extract_plugin_names(AgentInfo),
    %% Verbatim RegisterRequest, threaded from the subscribe handler.
    %% Defaulted so an agent started without it (older callers, tests)
    %% still works — replay just skips agents whose req is empty.
    RegisterReq = maps:get(register_req, Args, #{}),
    %% Connection key of the Subscribe stream that created this session
    %% (yuzu_gw_conn). Defaulted so a caller without one still starts; such
    %% a session is held but admits no heartbeat.
    ConnKey = maps:get(conn_key, Args, undefined),

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
        stream_home_id = StreamHomeId,
        owner_key   = OwnerKey
    },

    %% Registration is the first event, run once init/1 has returned and the
    %% supervisor is free (see the module doc). The connection key and the
    %% caller's alias ride in the event, not in the data.
    Ack = maps:get(registered_ack, Args, undefined),
    {ok, registering, Data, [{next_event, internal, {register, ConnKey, Ack}}]}.

%%--------------------------------------------------------------------
%% State: registering — the registry call, then connecting or streaming
%%--------------------------------------------------------------------

registering(enter, _OldState, _Data) ->
    keep_state_and_data;

registering(internal, {register, ConnKey, Ack},
            #data{agent_id = AgentId, session_id = SessionId, agent_info = AgentInfo,
                  plugins = Plugins, register_req = RegisterReq} = Data) ->
    %% Register in the routing table. The RegisterRequest is stashed in the
    %% registry so yuzu_gw_upstream can re-proxy it when the upstream
    %% connection re-establishes.
    Hostname = maps:get(<<"hostname">>, AgentInfo,
                        maps:get(hostname, AgentInfo, <<>>)),
    case yuzu_gw_registry:register_agent(AgentId, self(), SessionId, Plugins,
                                         Hostname, RegisterReq, ConnKey) of
        ok ->
            %% The cross-node lookup group, joined here and not by the registry
            %% (yuzu_gw_registry's module doc).
            ok = yuzu_gw_registry:join_agent_group(AgentId),
            %% Recorded before the notice is cast: a successor of an owner
            %% killed in between sends a DISCONNECTED, never leaves a session
            %% the server thinks is connected.
            ok = yuzu_gw_agent_sup:owner_set(Data#data.owner_key,
                                             [{announced, connected},
                                              {connected_at, Data#data.connected_at}]),
            Next = announce_connected(Data),
            ack(Ack, registered),
            {next_state, Next, drop_request(Data)};
        {error, Reason} when Reason =:= registry_unavailable; Reason =:= session_limit ->
            %% session_limit: the connection holds its quota of other agents'
            %% sessions (the registry counted and logged it). A fixed reason
            %% either way: it is printed by the Subscribe handler and must not
            %% carry the request. Nothing was registered, so nothing to undo:
            %% stop `normal', which writes no crash report.
            ack(Ack, {refused, Reason}),
            {stop, normal}
    end;

registering(_EventType, _Event, _Data) ->
    %% Unreachable in practice (the registration is the first event, and the
    %% registry call runs inside it); anything else waits for its outcome.
    {keep_state_and_data, [postpone]}.

ack(undefined, _Result) -> ok;
ack(Alias, Result)      -> Alias ! {Alias, Result}, ok.

%% Once the agent is in the routing table: tell watchers, telemetry and the
%% server, and name the state to enter.
announce_connected(#data{agent_id = AgentId, session_id = SessionId, peer_addr = PeerAddr,
                         stream_pid = StreamPid, stream_home_id = StreamHomeId}) ->
    %% Notify WatchEvents subscribers.
    notify_watchers(#{agent_id    => AgentId,
                      occurred_at => #{millis_epoch => erlang:system_time(millisecond)},
                      event       => {connected, #{session_id => ensure_binary(SessionId)}}}),

    telemetry:execute([yuzu, gw, agent, connected],
                      #{count => 1},
                      #{agent_id => AgentId, node => node(),
                        session_id => SessionId}),

    logger:info("Agent ~s connected from ~s",
                [yuzu_gw_env:log_text(AgentId), yuzu_gw_env:log_text(PeerAddr)]),

    %% Notify C++ server about the stream connection.
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr,
                                           StreamHomeId),

    case StreamPid of
        undefined -> connecting;
        _         -> streaming
    end.

%%--------------------------------------------------------------------
%% State: recovering — a restarted owner (OWNER-RESTART, see the module doc)
%%--------------------------------------------------------------------

recovering(enter, _OldState, _Data) ->
    keep_state_and_data;

recovering(internal, recover, {recover, Key, Predecessor}) ->
    case yuzu_gw_agent_sup:owner_row(Key) of
        {ok, Row} -> recover(Key, Predecessor, Row);
        none      -> {stop, normal}
    end;

recovering(_EventType, _Event, _Data) ->
    %% Unreachable in practice (recover is the first event and decides the
    %% next state); anything else waits for it.
    {keep_state_and_data, [postpone]}.

recover(Key, Predecessor, #{args := Args, home := Home, announced := Announced,
                            restarts := Restarts0, connected_at := ConnectedAt}) ->
    Now = erlang:monotonic_time(millisecond),
    Restarts = [T || T <- Restarts0, Now - T < ?RESTART_WINDOW_MS] ++ [Now],
    ok = yuzu_gw_agent_sup:owner_set(Key, [{restarts, Restarts}]),
    Data = restored_data(Args, Key, Home, ConnectedAt),
    case Announced of
        A when A =:= connected; A =:= ending ->
            ok = yuzu_gw_agent_sup:owner_set(Key, [{announced, disconnected}]),
            announce_disconnected(Data, owner_crashed);
        _ ->
            ok
    end,
    if
        Announced =:= none; Announced =:= ending ->
            %% Never announced (it died registering; its caller has answered the
            %% agent), or it was ending the session anyway.
            give_up(Data, disconnected_only, not_announced);
        length(Restarts) > ?MAX_RESTARTS ->
            give_up(Data, gave_up, restart_budget);
        true ->
            try_recover(Predecessor, Data)
    end.

try_recover(Predecessor, #data{agent_id = AgentId, stream_pid = StreamPid} = Data) ->
    maybe
        ok ?= not_superseded(AgentId),
        {ok, Mon} ?= reattach(StreamPid, Predecessor),
        ok ?= await_settled(Data),
        ok ?= register_again(Data),
        ok ?= present_again(Data),
        Recovered = drop_request(Data#data{stream_mon = Mon,
                                           connected_at = erlang:system_time(millisecond)}),
        ok = yuzu_gw_agent_sup:owner_set(Recovered#data.owner_key,
                                         [{announced, connected},
                                          {connected_at, Recovered#data.connected_at}]),
        Next = announce_connected(Recovered),
        emit_owner_restart(recovered),
        logger:info("Agent ~s: owner process restarted; session recovered on the same stream",
                    [yuzu_gw_env:log_text(AgentId)]),
        {next_state, Next, Recovered}
    else
        {error, reattach_refused} ->
            give_up(Data#data{stream_pid = undefined}, disconnected_only, reattach_refused);
        {error, Why} ->
            give_up(Data, disconnected_only, Why)
    end.

%% A supervised owner's RegisterRequest is kept by the registry (replay) and the
%% owner table (restart): the process does not keep a third copy (it is 10-20 KB
%% for an agent with 70 plugins). An owner started directly keeps it.
drop_request(#data{owner_key = undefined} = Data) -> Data;
drop_request(Data)                                -> Data#data{register_req = #{}}.

%% End a restarted owner for good: undo what recovery did (the registry row,
%% the group), close the stream (the agent reconnects by itself) and stop
%% `normal' (not restarted; terminate/3 removes the row).
give_up(#data{agent_id = AgentId, session_id = SessionId, stream_pid = StreamPid},
        Outcome, Why) ->
    _ = yuzu_gw_registry:leave_agent_group(AgentId),
    yuzu_gw_registry:deregister_agent(AgentId, self(), SessionId),
    case StreamPid of
        undefined -> ok;
        _         -> StreamPid ! close_stream
    end,
    emit_owner_restart(Outcome),
    case Outcome of
        gave_up ->
            logger:warning("Agent ~s: owner process restarted more than ~b times in ~b s; "
                           "giving up (session ended, the agent reconnects)",
                           [yuzu_gw_env:log_text(AgentId), ?MAX_RESTARTS,
                            ?RESTART_WINDOW_MS div 1000]);
        _ ->
            logger:info("Agent ~s: owner process restarted; session ended (~p)",
                        [yuzu_gw_env:log_text(AgentId), Why])
    end,
    {stop, normal}.

not_superseded(AgentId) ->
    Self = self(),
    case yuzu_gw_registry:lookup_local_session(AgentId) of
        {ok, {Pid, _}} when Pid =/= Self -> {error, superseded};
        _                                -> ok
    end.

%% Ask the stream to deliver to this process from now on. It accepts only a
%% re-attach naming the owner it last delivered to (the dead predecessor).
reattach(undefined, _Predecessor) ->
    {error, stream_gone};
reattach(StreamPid, Predecessor) ->
    Mon = monitor(process, StreamPid),
    Alias = alias([reply]),
    StreamPid ! {yuzu_gw_owner_reattach, Predecessor, self(), Alias},
    receive
        {Alias, reattached} ->
            {ok, Mon};
        {Alias, refused} ->
            demonitor(Mon, [flush]),
            {error, reattach_refused};
        {'DOWN', Mon, process, StreamPid, _} ->
            unalias(Alias),
            {error, stream_gone};
        {'EXIT', _Parent, Reason} ->
            exit(Reason)
    after ?REATTACH_WAIT_MS ->
        unalias(Alias),
        demonitor(Mon, [flush]),
        {error, stream_gone}
    end.

%% Wait until nothing is held or in flight upstream for this session's key:
%% the server must have the DISCONNECTED (or it must be counted lost) before
%% the session is presented again.
await_settled(#data{agent_id = AgentId, session_id = SessionId, stream_home_id = Home}) ->
    Alias = alias([reply]),
    yuzu_gw_upstream:notify_settled(AgentId, SessionId, Home, Alias),
    receive
        {Alias, notify_settled} -> ok;
        {'EXIT', _Parent, Reason} -> exit(Reason)
    after ?SETTLE_WAIT_MS ->
        unalias(Alias),
        {error, notice_pending}
    end.

register_again(#data{agent_id = AgentId, session_id = SessionId, plugins = Plugins,
                     agent_info = AgentInfo, register_req = RegisterReq} = Data) ->
    Hostname = maps:get(<<"hostname">>, AgentInfo, maps:get(hostname, AgentInfo, <<>>)),
    case yuzu_gw_registry:recover_agent(AgentId, self(), SessionId, Plugins, Hostname,
                                        RegisterReq, conn_key(Data)) of
        ok ->
            ok = yuzu_gw_registry:join_agent_group(AgentId);
        {error, _} = Refused ->
            Refused
    end.

present_again(#data{session_id = SessionId}) when not is_binary(SessionId);
                                                  SessionId =:= <<>> ->
    {error, no_session};
present_again(#data{register_req = Req}) when map_size(Req) =:= 0 ->
    {error, no_stored_request};
present_again(#data{session_id = SessionId, register_req = Req}) ->
    Deadline = erlang:monotonic_time(millisecond) + ?REREGISTER_MS,
    case yuzu_gw_upstream:reregister_session(Req, SessionId, #{deadline => Deadline}) of
        {ok, #{accepted := false}} ->
            {error, server_rejected};
        {ok, Response} when is_map(Response) ->
            case maps:get(session_id, Response, maps:get(<<"session_id">>, Response, SessionId)) of
                SessionId -> ok;
                _Other    -> {error, server_other_session}
            end;
        {ok, _NotAMap} ->
            {error, malformed_response};
        {error, {?GRPC_STATUS_BIN_FAILED_PRECONDITION, _}} ->
            {error, superseded};
        {error, Reason} when is_atom(Reason) ->
            {error, Reason};
        {error, _} ->
            {error, server_failed}
    end.

%% The connection key the session was bound to, kept in the owner table's
%% start arguments.
conn_key(#data{owner_key = Key}) ->
    case yuzu_gw_agent_sup:owner_row(Key) of
        {ok, #{args := Args}} -> maps:get(conn_key, Args, undefined);
        none                  -> undefined
    end.

restored_data(#{agent_id := AgentId, agent_info := AgentInfo, peer_addr := PeerAddr} = Args,
              Key, Home, ConnectedAt) ->
    #data{agent_id     = AgentId,
          session_id   = maps:get(session_id, Args, undefined),
          stream_pid   = maps:get(stream_pid, Args, undefined),
          stream_mon   = undefined,
          agent_info   = AgentInfo,
          register_req = maps:get(register_req, Args, #{}),
          plugins      = extract_plugin_names(AgentInfo),
          pending      = #{},
          connected_at = ConnectedAt,
          peer_addr    = PeerAddr,
          stream_home_id = Home,
          owner_key    = Key}.

emit_owner_restart(Outcome) ->
    telemetry:execute([yuzu, gw, agent, owner_restart], #{count => 1}, #{outcome => Outcome}).

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

connecting(info, {yuzu_gw_registry, unrouted, Id}, Data) ->
    leave_if_own(Id, Data);

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
                [yuzu_gw_env:log_text(AgentId), yuzu_gw_env:log_text(SessionId)]),
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

    Pending2 = Pending#{CmdId => {ReplyTo, FanoutRef, erlang:monotonic_time(millisecond),
                                  Plugin}},
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
    logger:warning("Stream error for agent ~s: ~p",
                   [yuzu_gw_env:log_text(Data#data.agent_id), Reason]),
    {next_state, disconnected, Data};

streaming(info, {'DOWN', MonRef, process, _Pid, _Reason},
          #data{stream_mon = MonRef} = Data) ->
    logger:warning("Stream handler died for agent ~s",
                   [yuzu_gw_env:log_text(Data#data.agent_id)]),
    {next_state, disconnected, Data};

streaming({call, From}, get_info, Data) ->
    {keep_state_and_data, [{reply, From, {ok, format_info(Data, streaming)}}]};

streaming({call, From}, pending_count, #data{pending = Pending}) ->
    {keep_state_and_data, [{reply, From, maps:size(Pending)}]};

streaming(info, {yuzu_gw_registry, unrouted, Id}, Data) ->
    leave_if_own(Id, Data);

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
                "CONNECTED to converge server-side placement",
                [yuzu_gw_env:log_text(AgentId), yuzu_gw_env:log_text(SessionId)]),
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr,
                                          StreamHomeId),
    keep_state_and_data;

streaming(cast, {upstream_reannounced, _OtherSessionId}, Data) ->
    %% This process has since moved on to a DIFFERENT session than the one
    %% the (now-stale) replay drip entry adopted — a benign race between the
    %% drip and a genuine agent reconnect. Ignore; the reconnect's own
    %% CONNECTED already carries the correct, current placement.
    logger:debug("Agent ~s: ignoring stale upstream_reannounced for a superseded session",
                [yuzu_gw_env:log_text(Data#data.agent_id)]),
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

terminate(normal, _State, Data) ->
    %% Already cleaned up in disconnected(enter, ...), a refused registration
    %% that registered nothing, or a restarted owner that ended the session.
    %% Not restarted: the row goes.
    yuzu_gw_agent_sup:owner_delete(owner_key_of(Data));
terminate(Reason, State, Data) when Reason =:= shutdown;
                                    is_tuple(Reason), element(1, Reason) =:= shutdown ->
    %% A supervisor shutdown (planned stop, the agent supervisor escalating)
    %% or a stop asked for: not restarted, so this process ends the session.
    shutdown_cleanup(State, Data),
    yuzu_gw_agent_sup:owner_delete(owner_key_of(Data));
terminate(_Reason, registering, _Data) ->
    %% Not registered, not announced: nothing to undo (a restart finds nothing
    %% announced and ends).
    ok;
terminate(_Reason, recovering, _Data) ->
    %% The row stays for the next restart.
    ok;
terminate(_Reason, _State, #data{owner_key = Key} = Data) when Key =/= undefined ->
    %% Restarted next: the successor sends the DISCONNECTED (one sender, see the
    %% module doc). Only this process knows its pending commands' waiters.
    fail_pending(Data);
terminate(_Reason, _State, Data) ->
    %% Not supervised, so never restarted: clean up here.
    do_cleanup(Data),
    ok.

shutdown_cleanup(registering, _Data) ->
    ok;
shutdown_cleanup(disconnected, _Data) ->
    ok;
shutdown_cleanup(recovering, {recover, Key, _Predecessor}) ->
    %% A restarted owner sends its predecessor's DISCONNECTED first thing; a row
    %% still announcing CONNECTED means it was stopped before that.
    case yuzu_gw_agent_sup:owner_row(Key) of
        {ok, #{announced := A, args := Args, home := Home, connected_at := At}}
          when A =:= connected; A =:= ending ->
            announce_disconnected(restored_data(Args, Key, Home, At), normal);
        _ ->
            ok
    end;
shutdown_cleanup(_State, #data{} = Data) ->
    do_cleanup(Data);
shutdown_cleanup(_State, _Data) ->
    ok.

owner_key_of(#data{owner_key = Key})  -> Key;
owner_key_of({recover, Key, _})        -> Key;
owner_key_of(_Data)                    -> undefined.

code_change(_OldVsn, State, Data0, Extra) when is_tuple(Data0), element(1, Data0) =:= data,
                                                tuple_size(Data0) =:= tuple_size(#data{}) - 1 ->
    %% A record from before OWNER-RESTART: no owner_key (never restarted).
    code_change(_OldVsn, State, erlang:append_element(Data0, undefined), Extra);
code_change(_OldVsn, State, #data{pending = Pending} = Data, _Extra) ->
    %% A pending entry from a version that did not keep the dispatched plugin
    %% is a 3-tuple; it completes with the plugin unknown.
    Pending2 = maps:map(fun(_CmdId, {ReplyTo, FanoutRef, DispatchedAt}) ->
                                {ReplyTo, FanoutRef, DispatchedAt, <<"unknown">>};
                           (_CmdId, Entry) ->
                                Entry
                        end, Pending),
    {ok, State, Data#data{pending = Pending2}}.

%% What OTP prints for this process in a terminate or crash report and in
%% sys:get_status/1: the data without the stored RegisterRequest, which holds
%% the enrollment token, machine certificate and CSR (and is only the replay
%% copy the registry also keeps). Only the reports are affected:
%% sys:get_state/1 still returns the real record.
%%
%% NOT covered here, because OTP prints it from raw data outside this callback
%% (the `reason' stacktrace, whose frames carry the argument list of a failing
%% call and so the whole data record; the mailbox; the init arguments in the
%% supervisor report): yuzu_gw_crash_redact, the logger primary filter
%% yuzu_gw_app installs, rewrites those for the processes of this module. It is
%% NOT in place when this module is used without the application.
%%
%% The queued events (`queue', whose head is the "Last event" of a terminate
%% report) and the postponed ones are reduced to their type: an event can carry
%% a request. No production sender delivers one to this process; this is the
%% belt to that braces.
-spec format_status(map()) -> map().
format_status(Status) ->
    maps:map(fun(data, Data)         -> redact_data(Data);
                (queue, Events)      -> redact_events(Events);
                (postponed, Events)  -> redact_events(Events);
                (_Key, Value)        -> Value
             end, Status).

%% A gen_statem event is {Type, Content}; only the type is kept.
redact_events(Events) when is_list(Events) ->
    [redact_event(E) || E <- Events];
redact_events(_Other) ->
    '$redacted'.

redact_event({Type, _Content}) -> {Type, '$redacted'};
redact_event(_Other)           -> '$redacted'.

%% Shown as a map of the fields (a record with register_req replaced would
%% violate the field's declared type), the way yuzu_gw_upstream shows its state.
redact_data(#data{} = Data) ->
    Fields = maps:from_list(lists:zip(record_info(fields, data), tl(tuple_to_list(Data)))),
    Fields#{register_req := '$redacted'};
redact_data(_Other) ->
    '$redacted'.

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
        {ok, {ReplyTo, FanoutRef, DispatchedAt, Plugin}} ->
            ReplyTo ! {command_response, FanoutRef, AgentId, ResponseFrame},

            Pending2 = case Status of
                'RUNNING'          -> Pending;
                <<"RUNNING">>      -> Pending;
                0                  -> Pending;  %% proto enum value
                _FinalStatus       ->
                    Duration = erlang:monotonic_time(millisecond) - DispatchedAt,
                    %% The dispatched plugin, the label commands_dispatched_total
                    %% carries, never the response's own (empty) field.
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
            logger:debug("Orphaned response from ~s for cmd ~s",
                         [yuzu_gw_env:log_text(AgentId), yuzu_gw_env:log_text(CmdId)]),
            keep_state_and_data
    end.

%% The registry no longer routes AgentId to this process (a newer registration
%% replaced it): leave `{agent, AgentId}' so the cross-node lookup fallback
%% cannot pick this process. The process keeps running until its stream ends.
leave_if_own(AgentId, #data{agent_id = AgentId}) ->
    _ = yuzu_gw_registry:leave_agent_group(AgentId),
    keep_state_and_data;
leave_if_own(_OtherId, _Data) ->
    keep_state_and_data.

do_cleanup(#data{agent_id = AgentId, session_id = SessionId, owner_key = Key} = Data) ->
    %% The session is ending on purpose: a successor (if this process is killed
    %% from here on) re-sends the DISCONNECTED but does not recover it.
    ok = yuzu_gw_agent_sup:owner_set(Key, [{announced, ending}]),
    %% Leave the cross-node lookup group first (pg would also drop this
    %% process when it exits), then deregister from the routing table. Fenced
    %% on this process and its own session: if the agent already reconnected
    %% under a newer session, only this session's index entry goes.
    _ = yuzu_gw_registry:leave_agent_group(AgentId),
    yuzu_gw_registry:deregister_agent(AgentId, self(), SessionId),
    fail_pending(Data),
    announce_disconnected(Data, normal).

%% Notify pending command waiters that the agent disconnected, and notify the
%% router so it can complete fanout tracking.
fail_pending(#data{agent_id = AgentId, pending = Pending}) ->
    maps:foreach(fun(_CmdId, {ReplyTo, FanoutRef, _DispatchedAt, _Plugin}) ->
        ReplyTo ! {command_error, FanoutRef, AgentId, agent_disconnected},
        %% HA WS-4 4.3a fix: route to the DISPATCHING node's router, same
        %% reasoning as handle_stream_response/2 above.
        {yuzu_gw_router, node(ReplyTo)} ! {fanout_terminal, FanoutRef, AgentId}
    end, Pending).

%% Tell telemetry, the server and watchers that the session ended. Reason:
%% normal (this owner ended it) or owner_crashed (a restarted owner ends its
%% predecessor's session).
announce_disconnected(#data{agent_id = AgentId, session_id = SessionId,
                            connected_at = ConnectedAt, peer_addr = PeerAddr,
                            stream_home_id = StreamHomeId}, Reason) ->
    Duration = case ConnectedAt of
        undefined -> 0;
        T         -> max(0, erlang:system_time(millisecond) - T)
    end,

    telemetry:execute([yuzu, gw, agent, disconnected],
                      #{count => 1, duration_ms => Duration},
                      #{agent_id => AgentId, reason => Reason}),

    %% Notify C++ server. The session's own StreamHomeId, the one its CONNECTED
    %% carried (minted by the session's first owner) — never a freshly-minted
    %% value — so the server can match this
    %% DISCONNECTED to the placement it actually tears down (HA WS-4).
    yuzu_gw_upstream:notify_stream_status(AgentId,
                                           SessionId,
                                           disconnected,
                                           PeerAddr,
                                           StreamHomeId),

    %% Notify WatchEvents subscribers.
    notify_watchers(#{agent_id    => AgentId,
                      occurred_at => #{millis_epoch => erlang:system_time(millisecond)},
                      event       => {disconnected, #{reason => atom_to_binary(Reason)}}}),

    logger:info("Agent ~s disconnected (was connected ~bms)",
                [yuzu_gw_env:log_text(AgentId), Duration]),
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
