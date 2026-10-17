%%%-------------------------------------------------------------------
%%% @doc A fake yuzu-server for the gateway scale suite (yuzu_gw_scale_SUITE):
%%% the GatewayUpstream service on a REAL gRPC listener (the gateway's own
%%% Cowboy-based yuzu_grpc_listener serving gateway_pb), so the gateway under
%%% test reaches it with its production upstream client (gun channel, circuit
%%% breaker, replay drip), not through a mock.
%%%
%%% It runs in its own peer node (the suite starts one per scenario), so a
%%% "server crash" is a kill -9 of that node and a restart is a fresh node with
%%% an empty state, as a restarted server has.
%%%
%%% Behaviour is set at start and can be changed while it runs (set_config/1):
%%%   register_latency_ms {Min, Max}  ProxyRegister answers after a uniform
%%%                                   delay in [Min, Max] (default {0, 0})
%%%   notify_latency_ms   {Min, Max}  the same for NotifyStreamStatus
%%%   register_fail       none | {Status, Message}  answer every ProxyRegister
%%%                                   with that gRPC status instead
%%%
%%% What it records, for the suite to read (stats/0, registers/0, notices/0):
%%%   - every ProxyRegister: agent id, receive and answer time (ms, OS clock:
%%%     every node of the suite runs on one host), whether it was a replay (the
%%%     gateway sends the agent's existing session id as x-yuzu-session-id
%%%     metadata on a replay only) and the session it answered;
%%%   - the peak number of ProxyRegister calls in flight at once, overall and
%%%     for replays only (the gateway runs them one at a time today);
%%%   - every NotifyStreamStatus (agent, session, event, time);
%%%   - BatchHeartbeat totals; the answer names the sessions this server does
%%%     not know (the verdict the gateway replays from, #1197), as the real
%%%     server does.
%%%
%%% Not a test module: no *_test function, no eunit.hrl.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_scale_upstream).
-behaviour(gen_server).

%% Control API (called in the upstream peer through peer:call).
-export([start/1, port/0, set_config/1, stats/0, registers/0, notices/0, sessions/0]).
%% GatewayUpstream handlers (yuzu_grpc_runner unary convention).
-export([proxy_register/2, batch_heartbeat/2, proxy_inventory/2,
         notify_stream_status/2, forward_guardian_message/2]).
%% gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(CFG, yuzu_gw_scale_upstream_cfg).
-define(REGS, yuzu_gw_scale_upstream_regs).
-define(NOTICES, yuzu_gw_scale_upstream_notices).
-define(SESSIONS, yuzu_gw_scale_upstream_sessions).
-define(SVC, 'yuzu.gateway.v1.GatewayUpstream').
%% atomics slots
-define(A_INFLIGHT, 1).
-define(A_INFLIGHT_MAX, 2).
-define(A_REPLAY_INFLIGHT, 3).
-define(A_REPLAY_INFLIGHT_MAX, 4).
-define(A_REGISTERS, 5).
-define(A_REPLAYS, 6).
-define(A_CONNECTED, 7).
-define(A_DISCONNECTED, 8).
-define(A_HB_BATCHES, 9).
-define(A_HEARTBEATS, 10).
-define(A_UNKNOWN, 11).
-define(A_SEQ, 12).
-define(A_SLOTS, 12).
%% The most unknown session ids one verdict names (the gateway reads at most
%% 4096, yuzu_gw_upstream ?MAX_REPLAY_SESSION_IDS).
-define(MAX_UNKNOWN, 4096).

%%--------------------------------------------------------------------
%% Control API
%%--------------------------------------------------------------------

%% @doc Start the fake server on Port (0 = any free port) with the given
%% behaviour. Returns the bound port. The listener and the state live in a
%% gen_server that is not linked to the caller (peer:call runs each call in a
%% short-lived process).
-spec start(#{port := inet:port_number(), atom() => term()}) -> {ok, inet:port_number()} | {error, term()}.
start(Opts) ->
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    case gen_server:start({local, ?SERVER}, ?MODULE, Opts, []) of
        {ok, _Pid} -> {ok, port()};
        {error, _} = Error -> Error
    end.

-spec port() -> inet:port_number().
port() ->
    gen_server:call(?SERVER, port).

-spec set_config(map()) -> ok.
set_config(Cfg) ->
    ets:insert(?CFG, maps:to_list(Cfg)),
    ok.

%% @doc Counters and peaks.
-spec stats() -> map().
stats() ->
    A = persistent_term:get({?MODULE, atomics}),
    #{register_rpcs => atomics:get(A, ?A_REGISTERS),
      replay_rpcs => atomics:get(A, ?A_REPLAYS),
      register_peak_inflight => atomics:get(A, ?A_INFLIGHT_MAX),
      replay_peak_inflight => atomics:get(A, ?A_REPLAY_INFLIGHT_MAX),
      register_inflight => atomics:get(A, ?A_INFLIGHT),
      connected_notices => atomics:get(A, ?A_CONNECTED),
      disconnected_notices => atomics:get(A, ?A_DISCONNECTED),
      heartbeat_batches => atomics:get(A, ?A_HB_BATCHES),
      heartbeats => atomics:get(A, ?A_HEARTBEATS),
      unknown_sessions_reported => atomics:get(A, ?A_UNKNOWN)}.

%% @doc Every ProxyRegister answered OK: {AgentId, Kind, RecvMs, DoneMs,
%% SessionId, Attempt}, Kind = fresh | replay, Attempt = the load generator's
%% attempt number carried in the request (0 when absent).
-spec registers() -> [{binary(), fresh | replay, integer(), integer(), binary(), integer()}].
registers() ->
    [{Id, Kind, Recv, Done, Sess, Att} || {_Seq, Id, Kind, Recv, Done, Sess, Att} <- ets:tab2list(?REGS)].

%% @doc Every NotifyStreamStatus: {AgentId, SessionId, Event, RecvMs}.
-spec notices() -> [{binary(), binary(), connected | disconnected, integer()}].
notices() ->
    [{Id, Sess, Ev, T} || {_Seq, Id, Sess, Ev, T} <- ets:tab2list(?NOTICES)].

%% @doc The sessions this server knows: {SessionId, AgentId, LastEvent}.
%% LastEvent = registered (ProxyRegister only) | connected | disconnected.
-spec sessions() -> [{binary(), binary(), atom()}].
sessions() ->
    ets:tab2list(?SESSIONS).

%%--------------------------------------------------------------------
%% gen_server: owns the tables and the listener
%%--------------------------------------------------------------------

init(Opts) ->
    ets:new(?CFG, [named_table, public, set, {read_concurrency, true}]),
    ets:new(?REGS, [named_table, public, set, {write_concurrency, true}]),
    ets:new(?NOTICES, [named_table, public, set, {write_concurrency, true}]),
    ets:new(?SESSIONS, [named_table, public, set, {write_concurrency, true}]),
    persistent_term:put({?MODULE, atomics}, atomics:new(?A_SLOTS, [{signed, true}])),
    set_config(maps:merge(#{register_latency_ms => {0, 0},
                            notify_latency_ms => {0, 0},
                            register_fail => none},
                          maps:without([port], Opts))),
    Entry = #{name => {yuzu_gw_scale_upstream, erlang:unique_integer([positive])},
              service_protos => [gateway_pb],
              services => #{?SVC => ?MODULE},
              listen => #{ip => {127, 0, 0, 1}, port => maps:get(port, Opts, 0)},
              acceptors => 8,
              %% The C++ server's gRPC default is 100 concurrent streams per
              %% connection; the gateway opens a small pool. Cowboy's default
              %% (100) matches it, said explicitly here.
              http2 => #{max_concurrent_streams => 100, idle_timeout => 600000}},
    case start_listener(Entry, 50) of
        {ok, L} -> {ok, #{listener => L}};
        {error, Reason} -> {stop, Reason}
    end.

%% A restart reuses the port the gateway dials, which the killed node held a
%% moment ago: retry the bind for a few seconds.
start_listener(Entry, 0) ->
    yuzu_grpc_listener:start(Entry);
start_listener(Entry, N) ->
    case yuzu_grpc_listener:start(Entry) of
        {ok, _} = Ok -> Ok;
        {error, _} -> receive after 100 -> ok end, start_listener(Entry, N - 1)
    end.

handle_call(port, _From, #{listener := L} = S) ->
    {reply, yuzu_grpc_listener:port(L), S}.

handle_cast(_Msg, S) -> {noreply, S}.
handle_info(_Msg, S) -> {noreply, S}.

%%--------------------------------------------------------------------
%% GatewayUpstream
%%--------------------------------------------------------------------

proxy_register(Ctx, Req) ->
    Recv = now_ms(),
    A = persistent_term:get({?MODULE, atomics}),
    Headers = yuzu_grpc:headers(Ctx),
    Info = maps:get(info, Req, #{}),
    AgentId = maps:get(agent_id, Info, <<>>),
    Attempt = case maps:get(<<"scale_attempt">>, maps:get(scopable_tags, Info, #{}), undefined) of
                  undefined -> 0;
                  N -> binary_to_integer(N)
              end,
    {Kind, Presented} = case maps:get(<<"x-yuzu-session-id">>, Headers, undefined) of
                            undefined -> {fresh, undefined};
                            S -> {replay, S}
                        end,
    atomics:add(A, ?A_REGISTERS, 1),
    peak(A, ?A_INFLIGHT, ?A_INFLIGHT_MAX),
    Kind =:= replay andalso begin
                               atomics:add(A, ?A_REPLAYS, 1),
                               peak(A, ?A_REPLAY_INFLIGHT, ?A_REPLAY_INFLIGHT_MAX)
                           end,
    try
        sleep(cfg(register_latency_ms)),
        case cfg(register_fail) of
            {Status, Message} ->
                {grpc_error, {Status, Message}};
            none ->
                %% A replay adopts the presented session (the server's HA WS-4
                %% 4.4 behaviour); a fresh registration gets a new one.
                Session = case Presented of
                              undefined ->
                                  <<"s-", AgentId/binary, "-",
                                    (integer_to_binary(atomics:add_get(A, ?A_SEQ, 1)))/binary>>;
                              P -> P
                          end,
                ets:insert(?SESSIONS, {Session, AgentId, registered}),
                ets:insert(?REGS, {atomics:add_get(A, ?A_SEQ, 1), AgentId, Kind, Recv, now_ms(),
                                   Session, Attempt}),
                {ok, #{session_id => Session, accepted => true,
                       enrollment_status => <<"enrolled">>}, Ctx}
        end
    after
        atomics:sub(A, ?A_INFLIGHT, 1),
        Kind =:= replay andalso atomics:sub(A, ?A_REPLAY_INFLIGHT, 1)
    end.

notify_stream_status(Ctx, Req) ->
    A = persistent_term:get({?MODULE, atomics}),
    sleep(cfg(notify_latency_ms)),
    AgentId = maps:get(agent_id, Req, <<>>),
    Session = maps:get(session_id, Req, <<>>),
    Event = case maps:get(event, Req, 'CONNECTED') of
                'DISCONNECTED' -> disconnected;
                1 -> disconnected;
                _ -> connected
            end,
    atomics:add(A, case Event of connected -> ?A_CONNECTED; disconnected -> ?A_DISCONNECTED end, 1),
    ets:insert(?NOTICES, {atomics:add_get(A, ?A_SEQ, 1), AgentId, Session, Event, now_ms()}),
    ets:insert(?SESSIONS, {Session, AgentId, Event}),
    {ok, #{acknowledged => true}, Ctx}.

batch_heartbeat(Ctx, Req) ->
    A = persistent_term:get({?MODULE, atomics}),
    Beats = maps:get(heartbeats, Req, []),
    atomics:add(A, ?A_HB_BATCHES, 1),
    atomics:add(A, ?A_HEARTBEATS, length(Beats)),
    Unknown = [S || #{session_id := S} <- Beats, not known(S)],
    {Named, Truncated} = case length(Unknown) > ?MAX_UNKNOWN of
                             true -> {lists:sublist(Unknown, ?MAX_UNKNOWN), true};
                             false -> {Unknown, false}
                         end,
    atomics:add(A, ?A_UNKNOWN, length(Named)),
    {ok, #{acknowledged_count => length(Beats),
           unknown_session_ids => Named,
           unknown_session_ids_truncated => Truncated}, Ctx}.

proxy_inventory(Ctx, _Req) ->
    {ok, #{}, Ctx}.

forward_guardian_message(Ctx, _Req) ->
    {ok, #{acknowledged => true}, Ctx}.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

known(Session) ->
    case ets:lookup(?SESSIONS, Session) of
        [{_, _, disconnected}] -> false;
        [_] -> true;
        [] -> false
    end.

cfg(Key) ->
    [{Key, V}] = ets:lookup(?CFG, Key),
    V.

sleep({0, 0}) -> ok;
sleep({Min, Max}) when Max > Min -> timer:sleep(Min + rand:uniform(Max - Min + 1) - 1);
sleep({Min, _}) -> timer:sleep(Min).

%% Raise the in-flight counter and keep its peak.
peak(A, Slot, MaxSlot) ->
    Now = atomics:add_get(A, Slot, 1),
    raise(A, MaxSlot, Now).

raise(A, MaxSlot, Now) ->
    case atomics:get(A, MaxSlot) of
        Old when Old >= Now -> ok;
        Old ->
            case atomics:compare_exchange(A, MaxSlot, Old, Now) of
                ok -> ok;
                _ -> raise(A, MaxSlot, Now)
            end
    end.

now_ms() -> erlang:system_time(millisecond).
