%%%-------------------------------------------------------------------
%%% @doc The load generator of the gateway scale suite (yuzu_gw_scale_SUITE):
%%% simulated agents and the server's management client, run in their own peer
%%% node so they do not share schedulers with the gateway they measure.
%%%
%%% A simulated agent is one process and one gun HTTP/2 connection (as a real
%%% agent has one channel), speaking the real AgentService wire protocol:
%%%
%%%   1. Register (unary, grpc-timeout 30 s, the agent's kRegisterTimeout) with
%%%      a RegisterRequest shaped like a real agent's: hostname, platform,
%%%      version, scopable tags and one PluginInfo per plugin under
%%%      agents/plugins (name, version, description, actions), about 10 KB;
%%%   2. Subscribe (bidirectional) with the session id it was given, held open;
%%%      every CommandRequest that arrives is answered with a CommandResponse
%%%      SUCCESS after a random delay in reply_delay_ms;
%%%   3. Heartbeat (unary) every hb_interval_ms on the same connection, the first
%%%      at a random offset; a NOT_FOUND answer (the gateway no longer knows the
%%%      session) makes it register again, as the C++ agent does.
%%%
%%% Retries follow agents/core/src/agent.cpp: after a failed Register, a lost
%%% connection or an ended Subscribe the agent waits 2^n seconds (n = failures
%%% in a row, from 1; capped at 300 s; no jitter), then connects and registers
%%% again; a successful Register resets n. backoff_unit_ms scales the second.
%%%
%%% Every agent writes its own row and its attempts into public ETS tables, so
%%% the state of 25,000 agents is never funnelled through one process. The
%%% management client (fanout/1) is the server's GatewayMgmtStubPool shape: one
%%% HTTP/2 connection, one SendCommand call per target agent, at most `window'
%%% calls open at once (the gateway's management listener advertises
%%% max_concurrent_streams 4096; gun refuses a stream over the peer's limit
%%% where gRPC C++ queues it, so the client queues).
%%%
%%% All times are this node's erlang:system_time(millisecond). They are for
%%% durations measured HERE (an attempt's latency, time since this node's
%%% mark/0) and never compare with a time taken on another node: each node's
%%% system time is the OS clock through its own time correction, and two nodes
%%% of one host disagree by up to milliseconds (#5695 Gate 8). Which attempts
%%% started after a marker is decided by sequence number instead: every attempt
%%% takes the next number of one counter as it starts, mark/0 returns the
%%% counter, and attempts/1 returns the attempts started after it.
%%%
%%% Not a test module: no *_test function, no eunit.hrl.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_scale_fleet).
-behaviour(gen_server).

%% Control API (called in the load-generator node through peer:call).
-export([start/1, stop_all/0, spawn_agents/1, set_config/1, status/0, mark/0, attempts/0,
         attempts/1, truth/0, disconnect/1, fanout/1, counters/0, ended/1]).
%% Agent process entry
-export([agent_init/2]).
%% gen_server
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(CFG, yuzu_gw_scale_fleet_cfg).
-define(AGENTS, yuzu_gw_scale_fleet_agents).
-define(ATTEMPTS, yuzu_gw_scale_fleet_attempts).
-define(COUNTERS, yuzu_gw_scale_fleet_counters).
%% Every session end, {AgentId, Why, SystemTimeMs} (owner_kill names them).
-define(ENDED, yuzu_gw_scale_fleet_ended).

-define(REGISTER, <<"/yuzu.agent.v1.AgentService/Register">>).
-define(SUBSCRIBE, <<"/yuzu.agent.v1.AgentService/Subscribe">>).
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(SEND_COMMAND, <<"/yuzu.server.v1.ManagementService/SendCommand">>).
-define(MAX_MSG, 16 * 1024 * 1024).
-define(MAX_BACKOFF_S, 300).

%% Agent row: {Id, Pid, State, Session, Attempts, FirstOutcome, FirstLatencyMs,
%%             RegisteredAtMs, Registrations, Disconnects}
-define(F_PID, 2).
-define(F_STATE, 3).
-define(F_SESSION, 4).
-define(F_ATTEMPTS, 5).
-define(F_FIRST, 6).
-define(F_FIRST_MS, 7).
-define(F_REG_AT, 8).
-define(F_REGS, 9).
-define(F_DISC, 10).

-record(a, {id, idx, req, conn, mref, session, sub, buf = <<>>, hb, hb_timer,
            failures = 0, attempt = 0, gen = 0}).

%%--------------------------------------------------------------------
%% Control API
%%--------------------------------------------------------------------

%% @doc Start the fleet owner (tables). Cfg keys:
%%   targets         [{Ip, Port}] agent listeners; agent I uses element I rem len
%%   prefix          binary, agent ids are <<Prefix/binary, "-", Index:6>>
%%   plugins         [PluginInfo map] for the RegisterRequest
%%   hb_interval_ms  0 = no heartbeats
%%   reply_delay_ms  {Min, Max}
%%   output_bytes    size of each CommandResponse.output
%%   backoff_unit_ms the length of one backoff "second" (1000 = the agent's)
%%   register_timeout_ms  the Register deadline (30000 = the agent's)
%%   reconnect       whether an agent reconnects after losing its session
-spec start(map()) -> ok.
start(Cfg) ->
    {ok, _} = application:ensure_all_started(gun),
    case whereis(?SERVER) of
        undefined -> ok;
        _ -> stop_all(), gen_server:stop(?SERVER)
    end,
    {ok, _} = gen_server:start({local, ?SERVER}, ?MODULE, Cfg, []),
    ok.

-spec set_config(map()) -> ok.
set_config(Cfg) ->
    ets:insert(?CFG, maps:to_list(Cfg)),
    ok.

%% @doc Start agents From..From+Count-1. Mode: storm (all at once) or
%% {ramp, PerSecond} (started at that fixed rate). Returns at once.
-spec spawn_agents(#{from := pos_integer(), count := pos_integer(),
                     mode := storm | {ramp, pos_integer()}}) -> ok.
spawn_agents(Spec) ->
    gen_server:call(?SERVER, {spawn, Spec}, infinity).

%% @doc Kill every agent (no goodbye: the sockets are closed with linger 0, a
%% reset, so no TIME_WAIT is left on the load generator's ephemeral ports).
-spec stop_all() -> ok.
stop_all() ->
    Pids = [P || {_, P, _, _, _, _, _, _, _, _} <- ets:tab2list(?AGENTS), is_pid(P)],
    [exit(P, kill) || P <- Pids],
    ok.

%% @doc The fleet summary.
-spec status() -> map().
status() ->
    Init = #{total => 0, live => 0, by_state => #{}, first_ok => 0, first_failed => 0,
             first_pending => 0, ever_registered => 0, registrations => 0, disconnects => 0},
    ets:foldl(fun({_Id, _P, State, _S, _A, First, _FMs, _RegAt, Regs, Disc}, Acc) ->
                      #{total := T, live := L, by_state := B, first_ok := FO,
                        first_failed := FF, first_pending := FP, ever_registered := E,
                        registrations := R, disconnects := D} = Acc,
                      Acc#{total := T + 1,
                           live := L + bool(State =:= live),
                           by_state := maps:update_with(State, fun(X) -> X + 1 end, 1, B),
                           first_ok := FO + bool(First =:= ok),
                           first_failed := FF + bool(First =/= ok andalso First =/= undefined),
                           first_pending := FP + bool(First =:= undefined),
                           ever_registered := E + bool(Regs > 0),
                           registrations := R + Regs,
                           disconnects := D + Disc}
              end, Init, ?AGENTS).

%% @doc Where this node's record is now: the sequence number of the last
%% Register attempt started, and this node's clock (for durations measured
%% against attempt times). Every attempt that starts after this returns has a
%% larger sequence number.
-spec mark() -> #{seq := non_neg_integer(), ms := integer()}.
mark() ->
    #{seq => atomics:get(persistent_term:get({?MODULE, seq}), 1), ms => now_ms()}.

%% @doc Every Register attempt: {Id, N, StartMs, EndMs, Outcome}.
-spec attempts() -> [tuple()].
attempts() ->
    [{Id, N, S, E, O} || {Id, N, S, E, O, _Seq} <- ets:tab2list(?ATTEMPTS)].

%% @doc The Register attempts that STARTED after mark/0 returned Since (and have
%% ended): {Id, N, StartMs, EndMs, Outcome}.
-spec attempts(non_neg_integer()) -> [tuple()].
attempts(Since) ->
    [{Id, N, S, E, O} || {Id, N, S, E, O, Seq} <- ets:tab2list(?ATTEMPTS), Seq > Since].

%% @doc The agents that hold a session now: [{Id, Session, RegisteredAtMs}].
-spec truth() -> [{binary(), binary(), integer()}].
truth() ->
    [{Id, S, At} || {Id, _P, live, S, _, _, _, At, _, _} <- ets:tab2list(?AGENTS)].

-spec counters() -> map().
counters() ->
    maps:from_list(ets:tab2list(?COUNTERS)).

%% @doc Make these agents drop their connection (a flap). They come back by
%% their own retry rule when `reconnect' is true.
%% @doc Each session end of these agents: {AgentId, Why, SystemTimeMs}, Why one
%% of subscribe_ended, heartbeat_not_found, connection_lost, dropped.
-spec ended([binary()]) -> [{binary(), atom(), integer()}].
ended(Ids) ->
    lists:append([ets:lookup(?ENDED, Id) || Id <- Ids]).

-spec disconnect([binary()]) -> ok.
disconnect(Ids) ->
    [P ! drop || Id <- Ids, {_, P, _, _, _, _, _, _, _, _} <- ets:lookup(?AGENTS, Id), is_pid(P)],
    ok.

%%--------------------------------------------------------------------
%% gen_server: owns the tables, spawns agents
%%--------------------------------------------------------------------

init(Cfg) ->
    ets:new(?CFG, [named_table, public, set, {read_concurrency, true}]),
    ets:new(?AGENTS, [named_table, public, set, {write_concurrency, true},
                      {read_concurrency, true}]),
    ets:new(?ATTEMPTS, [named_table, public, duplicate_bag, {write_concurrency, true}]),
    ets:new(?COUNTERS, [named_table, public, set, {write_concurrency, true}]),
    ets:new(?ENDED, [named_table, public, duplicate_bag, {write_concurrency, true}]),
    %% The attempt sequence (mark/0, attempts/1); a fresh one per start/1.
    persistent_term:put({?MODULE, seq}, atomics:new(1, [{signed, false}])),
    ets:insert(?COUNTERS, [{K, 0} || K <- [commands_received, responses_sent, heartbeats_sent,
                                           heartbeats_not_found, heartbeats_failed,
                                           connections_lost, subscribe_ended]]),
    set_config(maps:merge(#{hb_interval_ms => 0, reply_delay_ms => {0, 0}, output_bytes => 1024,
                            backoff_unit_ms => 1000, register_timeout_ms => 30000,
                            reconnect => true, prefix => <<"scale">>}, Cfg)),
    {ok, #{}}.

handle_call({spawn, #{from := From, count := Count, mode := Mode}}, _From, S) ->
    Idxs = lists:seq(From, From + Count - 1),
    case Mode of
        storm ->
            [spawn_agent(I) || I <- Idxs];
        {ramp, PerSec} ->
            proc_lib:spawn(fun() -> ramp(Idxs, PerSec, erlang:monotonic_time(millisecond), 0) end)
    end,
    {reply, ok, S}.

handle_cast(_Msg, S) -> {noreply, S}.
handle_info(_Msg, S) -> {noreply, S}.

%% Start agent K of a ramp at Start + K * 1000 / PerSec ms (no drift).
ramp([], _PerSec, _Start, _K) -> ok;
ramp([I | Rest], PerSec, Start, K) ->
    Due = Start + (K * 1000) div PerSec,
    Wait = Due - erlang:monotonic_time(millisecond),
    Wait > 0 andalso timer:sleep(Wait),
    spawn_agent(I),
    ramp(Rest, PerSec, Start, K + 1).

spawn_agent(Idx) ->
    Id = agent_id(Idx),
    ets:insert(?AGENTS, {Id, undefined, starting, undefined, 0, undefined, undefined,
                         undefined, 0, 0}),
    Pid = proc_lib:spawn(?MODULE, agent_init, [Id, Idx]),
    ets:update_element(?AGENTS, Id, {?F_PID, Pid}).

agent_id(Idx) ->
    Prefix = cfg(prefix),
    iolist_to_binary([Prefix, $-, io_lib:format("~6..0B", [Idx])]).

%%--------------------------------------------------------------------
%% The simulated agent
%%--------------------------------------------------------------------

agent_init(Id, Idx) ->
    process_flag(trap_exit, false),
    connect(#a{id = Id, idx = Idx, req = register_request(Id)}).

%% The request of attempt N: the agent's request with the attempt number in one
%% more scopable tag. The gateway forwards the RegisterRequest as it came, so the
%% fake server can tell which attempt each ProxyRegister belongs to (and so
%% whether it arrived after that attempt had already given up).
encode_attempt(Req = #{info := #{scopable_tags := Tags} = Info}, N) ->
    Tagged = Req#{info := Info#{scopable_tags := Tags#{<<"scale_attempt">> => integer_to_binary(N)}}},
    iolist_to_binary(yuzu_grpc_frame:encode(
                       agent_pb:encode_msg(Tagged, 'yuzu.agent.v1.RegisterRequest'))).

register_request(Id) ->
    #{info => #{agent_id => Id,
                hostname => <<"scale-host-", Id/binary>>,
                agent_version => <<"0.14.0">>,
                platform => #{os => <<"linux">>, arch => <<"x86_64">>,
                              version => <<"6.8.0-45-generic">>},
                plugins => cfg(plugins),
                scopable_tags => #{<<"env">> => <<"scale-test">>,
                                   <<"site">> => <<"lab-1">>,
                                   <<"role">> => <<"workstation">>}},
      enrollment_token => <<"scale-test-enrollment-token-0123456789abcdef">>}.

connect(#a{idx = Idx} = A) ->
    set_state(A, connecting),
    Targets = cfg(targets),
    {Ip, Port} = lists:nth(1 + (Idx rem length(Targets)), Targets),
    Inet = case tuple_size(Ip) of 8 -> [inet6]; _ -> [] end,
    {ok, Conn} = gun:open(Ip, Port, #{protocols => [http2], retry => 0,
                                      connect_timeout => 10000,
                                      tcp_opts => [{linger, {true, 0}}, {nodelay, true} | Inet],
                                      http2_opts => #{keepalive => infinity}}),
    MRef = monitor(process, Conn),
    case gun:await_up(Conn, 15000, MRef) of
        {ok, http2} ->
            register(A#a{conn = Conn, mref = MRef});
        {error, Reason} ->
            close(Conn, MRef),
            A1 = A#a{attempt = A#a.attempt + 1, conn = undefined, mref = undefined},
            record_attempt(A1, attempt_start(), {connect_failed, short(Reason)}),
            backoff(A1)
    end.

register(#a{conn = Conn, mref = MRef, req = Req} = A0) ->
    A = A0#a{attempt = A0#a.attempt + 1},
    set_state(A, registering),
    Timeout = cfg(register_timeout_ms),
    Request = encode_attempt(Req, A#a.attempt),
    {StartMs, _} = Start = attempt_start(),
    Ref = gun:post(Conn, ?REGISTER, grpc_headers(Timeout), Request),
    case await_unary(Conn, MRef, Ref, StartMs + Timeout + 1000) of
        {ok, <<"0">>, Body} ->
            case decode_one(Body, 'yuzu.agent.v1.RegisterResponse') of
                #{session_id := Session} when Session =/= <<>> ->
                    record_attempt(A, Start, ok),
                    subscribe(A#a{session = Session, failures = 0});
                _ ->
                    record_attempt(A, Start, bad_response),
                    backoff(A)
            end;
        {ok, Status, _} ->
            record_attempt(A, Start, {grpc, Status}),
            backoff(A);
        {error, conn_down} ->
            record_attempt(A, Start, conn_down),
            backoff(A#a{conn = undefined});
        {error, Reason} ->
            record_attempt(A, Start, short(Reason)),
            backoff(A)
    end.

subscribe(#a{conn = Conn, session = Session, id = Id} = A) ->
    Sub = gun:headers(Conn, <<"POST">>, ?SUBSCRIBE,
                      [{<<"x-yuzu-session-id">>, Session} | grpc_headers(infinity)]),
    Now = now_ms(),
    case ets:lookup(?AGENTS, Id) of
        [{_, _, _, _, _, _, _, _, Regs, _}] ->
            ets:update_element(?AGENTS, Id, [{?F_STATE, live}, {?F_SESSION, Session},
                                             {?F_REG_AT, Now}, {?F_REGS, Regs + 1}])
    end,
    Gen = A#a.gen + 1,
    live(arm_heartbeat(A#a{sub = Sub, buf = <<>>, hb = undefined, gen = Gen}, first)).

live(#a{conn = Conn, mref = MRef, sub = Sub, hb = Hb, gen = Gen} = A) ->
    receive
        {gun_response, Conn, Sub, nofin, _Status, _Headers} ->
            live(A);
        {gun_data, Conn, Sub, IsFin, Data} ->
            A1 = commands(A#a{buf = <<(A#a.buf)/binary, Data/binary>>}),
            case IsFin of
                fin -> session_ended(A1, subscribe_ended);
                nofin -> live(A1)
            end;
        {gun_response, Conn, Sub, fin, _Status, _Headers} ->
            session_ended(A, subscribe_ended);
        {gun_trailers, Conn, Sub, _Trailers} ->
            session_ended(A, subscribe_ended);
        {gun_error, Conn, Sub, _Reason} ->
            session_ended(A, subscribe_ended);
        {reply, Gen, CmdId} ->
            Resp = #{command_id => CmdId, status => 'SUCCESS', exit_code => 0,
                     output => output()},
            Frame = yuzu_grpc_frame:encode(
                      agent_pb:encode_msg(Resp, 'yuzu.agent.v1.CommandResponse')),
            ok = gun:data(Conn, Sub, nofin, Frame),
            bump(responses_sent),
            live(A);
        {reply, _OldGen, _CmdId} ->
            live(A);
        {heartbeat, Gen} ->
            Ref = gun:post(Conn, ?HEARTBEAT, grpc_headers(10000),
                           yuzu_grpc_frame:encode(
                             agent_pb:encode_msg(#{session_id => A#a.session},
                                                 'yuzu.agent.v1.HeartbeatRequest'))),
            bump(heartbeats_sent),
            live(arm_heartbeat(A#a{hb = {Ref, <<>>}}, next));
        {heartbeat, _OldGen} ->
            live(A);
        {gun_response, Conn, HbRef, fin, _Status, Headers} when element(1, Hb) =:= HbRef ->
            heartbeat_done(A, status_of(Headers));
        {gun_response, Conn, HbRef, nofin, _Status, _Headers} when element(1, Hb) =:= HbRef ->
            live(A);
        {gun_data, Conn, HbRef, _IsFin, _Data} when element(1, Hb) =:= HbRef ->
            live(A);
        {gun_trailers, Conn, HbRef, Trailers} when element(1, Hb) =:= HbRef ->
            heartbeat_done(A, status_of(Trailers));
        {gun_error, Conn, HbRef, _Reason} when element(1, Hb) =:= HbRef ->
            bump(heartbeats_failed),
            live(A#a{hb = undefined});
        {'DOWN', MRef, process, Conn, _Reason} ->
            bump(connections_lost),
            session_ended(A#a{conn = undefined}, connection_lost);
        {gun_down, Conn, _Proto, _Reason, _Killed} ->
            %% gun with retry => 0 exits right after this; the 'DOWN' follows.
            live(A);
        drop ->
            session_ended(A, dropped);
        _Other ->
            live(A)
    end.

heartbeat_done(A, <<"0">>) ->
    live(A#a{hb = undefined});
heartbeat_done(A, <<"5">>) ->
    %% The gateway no longer knows the session: register again (agent.cpp's
    %% NOT_FOUND handling cancels the Subscribe stream to force a reconnect).
    bump(heartbeats_not_found),
    session_ended(A#a{hb = undefined}, heartbeat_not_found);
heartbeat_done(A, _Other) ->
    bump(heartbeats_failed),
    live(A#a{hb = undefined}).

%% The session is over: count it, then reconnect by the retry rule (or stop).
session_ended(#a{id = Id} = A, Why) ->
    Why =:= subscribe_ended andalso bump(subscribe_ended),
    ets:insert(?ENDED, {Id, Why, erlang:system_time(millisecond)}),
    case ets:lookup(?AGENTS, Id) of
        [{_, _, _, _, _, _, _, _, _, Disc}] ->
            ets:update_element(?AGENTS, Id, [{?F_STATE, down}, {?F_DISC, Disc + 1}])
    end,
    cancel_heartbeat(A),
    close(A#a.conn, A#a.mref),
    backoff(A#a{conn = undefined, mref = undefined, sub = undefined, session = undefined,
                gen = A#a.gen + 1}).

backoff(#a{failures = F} = A) ->
    case cfg(reconnect) of
        false ->
            close(A#a.conn, A#a.mref),
            set_state(A, gone);
        true ->
            N = F + 1,
            set_state(A, backoff),
            Delay = min(1 bsl min(N, 8), ?MAX_BACKOFF_S) * cfg(backoff_unit_ms),
            receive
                stop -> close(A#a.conn, A#a.mref), set_state(A, gone)
            after Delay ->
                A1 = A#a{failures = N},
                case A1#a.conn of
                    undefined -> connect(A1);
                    Conn ->
                        case is_process_alive(Conn) of
                            true -> register(A1);
                            false -> close(Conn, A1#a.mref),
                                     connect(A1#a{conn = undefined, mref = undefined})
                        end
                end
            end
    end.

commands(#a{buf = Buf, gen = Gen} = A) ->
    case yuzu_grpc_frame:decode(Buf, ?MAX_MSG) of
        {ok, Msg, Rest} ->
            Cmd = agent_pb:decode_msg(Msg, 'yuzu.agent.v1.CommandRequest'),
            bump(commands_received),
            CmdId = maps:get(command_id, Cmd, <<>>),
            erlang:send_after(delay(cfg(reply_delay_ms)), self(), {reply, Gen, CmdId}),
            commands(A#a{buf = Rest});
        {more, Rest} ->
            A#a{buf = Rest};
        {error, _} ->
            A#a{buf = <<>>}
    end.

arm_heartbeat(A, When) ->
    case cfg(hb_interval_ms) of
        0 -> A;
        Hb ->
            Delay = case When of first -> rand:uniform(Hb); next -> Hb end,
            A#a{hb_timer = erlang:send_after(Delay, self(), {heartbeat, A#a.gen})}
    end.

cancel_heartbeat(#a{hb_timer = undefined}) -> ok;
cancel_heartbeat(#a{hb_timer = T}) -> erlang:cancel_timer(T), ok.

set_state(#a{id = Id}, State) ->
    ets:update_element(?AGENTS, Id, {?F_STATE, State}).

%% An attempt starts: its time and its place in the attempt sequence.
attempt_start() ->
    {now_ms(), atomics:add_get(persistent_term:get({?MODULE, seq}), 1, 1)}.

record_attempt(#a{id = Id, attempt = N}, {Start, Seq}, Outcome) ->
    End = now_ms(),
    ets:insert(?ATTEMPTS, {Id, N, Start, End, Outcome, Seq}),
    case ets:lookup(?AGENTS, Id) of
        [{_, _, _, _, Attempts, undefined, _, _, _, _}] ->
            ets:update_element(?AGENTS, Id, [{?F_ATTEMPTS, Attempts + 1},
                                             {?F_FIRST, Outcome}, {?F_FIRST_MS, End - Start}]);
        [{_, _, _, _, Attempts, _, _, _, _, _}] ->
            ets:update_element(?AGENTS, Id, {?F_ATTEMPTS, Attempts + 1})
    end.

%%--------------------------------------------------------------------
%% The management client: the server's fan-out
%%--------------------------------------------------------------------

%% @doc One command to each of Ids over ONE management connection, one
%% SendCommand call per agent, at most Window calls open. Blocks until every
%% call has ended or Budget ms have passed. Returns the summary and the
%% per-call latencies.
-spec fanout(#{target := {inet:ip_address(), inet:port_number()}, ids := [binary()],
               window := pos_integer(), budget_ms := pos_integer(),
               timeout_s := pos_integer()}) -> map().
fanout(#{target := {Ip, Port}, ids := Ids, window := Window, budget_ms := Budget,
         timeout_s := TimeoutS}) ->
    {ok, _} = application:ensure_all_started(gun),
    Start = now_ms(),
    {Conn, MRef} = mgmt_open(Ip, Port),
    St0 = #{conn => Conn, mref => MRef, ip => Ip, port => Port, queue => Ids,
            inflight => #{}, done => [], drops => 0, refused => 0, window => Window,
            timeout_s => TimeoutS, deadline => Start + Budget, seq => 0,
            target_count => length(Ids)},
    St = fan_loop(fill(St0)),
    #{done := Done, drops := Drops, refused := Refused, inflight := Left, queue := Queue} = St,
    Ok = [L || {_Id, ok, L} <- Done],
    Failed = [{Id, Why} || {Id, Why, _} <- Done, Why =/= ok],
    #{targets => length(Ids),
      answered => length(Ok),
      failed => length(Failed),
      failure_reasons => count_reasons(Failed),
      unfinished => map_size(Left) + length(Queue),
      connection_drops => Drops,
      stream_refusals => Refused,
      completion_ms => now_ms() - Start,
      latencies_ms => Ok}.

mgmt_open(Ip, Port) ->
    Inet = case tuple_size(Ip) of 8 -> [inet6]; _ -> [] end,
    {ok, Conn} = gun:open(Ip, Port, #{protocols => [http2], retry => 0,
                                      tcp_opts => [{nodelay, true} | Inet],
                                      http2_opts => #{keepalive => infinity}}),
    MRef = monitor(process, Conn),
    {ok, http2} = gun:await_up(Conn, 15000, MRef),
    {Conn, MRef}.

fill(#{queue := []} = St) -> St;
fill(#{inflight := In, window := W} = St) when map_size(In) >= W -> St;
fill(#{queue := [Id | Rest], conn := Conn, inflight := In, seq := Seq,
       timeout_s := TimeoutS} = St) ->
    CmdId = <<"scale-cmd-", (integer_to_binary(Seq))/binary>>,
    Req = #{agent_ids => [Id],
            command => #{command_id => CmdId, plugin => <<"os_info">>, action => <<"os_name">>},
            timeout_seconds => TimeoutS},
    Body = yuzu_grpc_frame:encode(
             management_pb:encode_msg(Req, 'yuzu.server.v1.SendCommandRequest')),
    Ref = gun:post(Conn, ?SEND_COMMAND, grpc_headers(TimeoutS * 1000), Body),
    fill(St#{queue := Rest, seq := Seq + 1,
             inflight := In#{Ref => #{id => Id, start => now_ms(), buf => <<>>, ok => false}}}).

fan_loop(#{queue := [], inflight := In} = St) when map_size(In) =:= 0 -> St;
fan_loop(#{conn := Conn, mref := MRef, inflight := In, deadline := Deadline} = St) ->
    Timeout = max(0, Deadline - now_ms()),
    receive
        {gun_response, Conn, Ref, nofin, _, _} when is_map_key(Ref, In) ->
            fan_loop(St);
        {gun_response, Conn, Ref, fin, _, Headers} when is_map_key(Ref, In) ->
            fan_loop(fill(finish_call(Ref, status_of(Headers), St)));
        {gun_data, Conn, Ref, IsFin, Data} when is_map_key(Ref, In) ->
            #{buf := Buf} = Call = maps:get(Ref, In),
            Call1 = responses(Call#{buf := <<Buf/binary, Data/binary>>}),
            St1 = St#{inflight := In#{Ref := Call1}},
            case IsFin of
                fin -> fan_loop(fill(finish_call(Ref, <<"0">>, St1)));
                nofin -> fan_loop(St1)
            end;
        {gun_trailers, Conn, Ref, Trailers} when is_map_key(Ref, In) ->
            fan_loop(fill(finish_call(Ref, status_of(Trailers), St)));
        {gun_error, Conn, Ref, {stream_error, too_many_streams, _}} when is_map_key(Ref, In) ->
            %% Over the listener's stream limit: queue it again (gRPC C++ waits
            %% for a free stream instead of failing the call).
            #{id := Id} = maps:get(Ref, In),
            St1 = St#{inflight := maps:remove(Ref, In),
                      queue := maps:get(queue, St) ++ [Id],
                      refused := maps:get(refused, St) + 1,
                      window := max(1, map_size(In) - 1)},
            fan_loop(St1);
        {gun_error, Conn, Ref, Reason} when is_map_key(Ref, In) ->
            fan_loop(fill(finish_call(Ref, {error, short(Reason)}, St)));
        {'DOWN', MRef, process, Conn, _} ->
            %% The management connection is gone: every call on it failed (the
            %% server sees UNAVAILABLE); dial again for the rest of the queue.
            Done = [{Id, connection_lost, now_ms() - S} || #{id := Id, start := S} <- maps:values(In)],
            {Conn1, MRef1} = mgmt_open(maps:get(ip, St), maps:get(port, St)),
            fan_loop(fill(St#{conn := Conn1, mref := MRef1, inflight := #{},
                              done := Done ++ maps:get(done, St),
                              drops := maps:get(drops, St) + 1}));
        _Other ->
            fan_loop(St)
    after Timeout ->
        St
    end.

finish_call(Ref, Status, #{inflight := In, done := Done} = St) ->
    #{id := Id, start := S, ok := Ok} = maps:get(Ref, In),
    Outcome = case {Status, Ok} of
                  {<<"0">>, true} -> ok;
                  {<<"0">>, false} -> no_success_response;
                  {{error, R}, _} -> {error, R};
                  {Other, _} -> {grpc, Other}
              end,
    St#{inflight := maps:remove(Ref, In), done := [{Id, Outcome, now_ms() - S} | Done]}.

%% Decode the SendCommandResponse frames buffered on a call; a SUCCESS for the
%% call's agent marks it answered.
responses(#{buf := Buf, id := Id} = Call) ->
    case yuzu_grpc_frame:decode(Buf, ?MAX_MSG) of
        {ok, Msg, Rest} ->
            R = management_pb:decode_msg(Msg, 'yuzu.server.v1.SendCommandResponse'),
            Ok = case R of
                     #{agent_id := Id, response := #{status := 'SUCCESS'}} -> true;
                     _ -> maps:get(ok, Call)
                 end,
            responses(Call#{buf := Rest, ok := Ok});
        {more, Rest} -> Call#{buf := Rest};
        {error, _} -> Call#{buf := <<>>}
    end.

count_reasons(Failed) ->
    lists:foldl(fun({_Id, Why}, Acc) ->
                        Key = iolist_to_binary(io_lib:format("~0p", [Why])),
                        maps:update_with(Key, fun(X) -> X + 1 end, 1, Acc)
                end, #{}, Failed).

%%--------------------------------------------------------------------
%% gRPC over gun
%%--------------------------------------------------------------------

grpc_headers(infinity) ->
    [{<<"content-type">>, <<"application/grpc">>}, {<<"te">>, <<"trailers">>}];
grpc_headers(TimeoutMs) ->
    [{<<"grpc-timeout">>, <<(integer_to_binary(TimeoutMs))/binary, "m">>} | grpc_headers(infinity)].

%% Wait for a unary answer: {ok, GrpcStatus, Body} | {error, Reason}.
await_unary(Conn, MRef, Ref, Deadline) ->
    await_unary(Conn, MRef, Ref, Deadline, <<>>).

await_unary(Conn, MRef, Ref, Deadline, Acc) ->
    Timeout = max(0, Deadline - now_ms()),
    receive
        {gun_response, Conn, Ref, fin, _Status, Headers} ->
            {ok, status_of(Headers), Acc};
        {gun_response, Conn, Ref, nofin, _Status, _Headers} ->
            await_unary(Conn, MRef, Ref, Deadline, Acc);
        {gun_data, Conn, Ref, nofin, Data} ->
            await_unary(Conn, MRef, Ref, Deadline, <<Acc/binary, Data/binary>>);
        {gun_data, Conn, Ref, fin, Data} ->
            {ok, <<"missing">>, <<Acc/binary, Data/binary>>};
        {gun_trailers, Conn, Ref, Trailers} ->
            {ok, status_of(Trailers), Acc};
        {gun_error, Conn, Ref, Reason} ->
            {error, Reason};
        {'DOWN', MRef, process, Conn, _Reason} ->
            {error, conn_down}
    after Timeout ->
        gun:cancel(Conn, Ref),
        {error, timeout}
    end.

status_of(Fields) ->
    case lists:keyfind(<<"grpc-status">>, 1, Fields) of
        {_, S} -> S;
        false -> <<"missing">>
    end.

decode_one(Body, Type) ->
    case yuzu_grpc_frame:decode(Body, ?MAX_MSG) of
        {ok, Msg, _} -> agent_pb:decode_msg(Msg, Type);
        _ -> undefined
    end.

close(undefined, _) -> ok;
close(Conn, MRef) ->
    is_reference(MRef) andalso demonitor(MRef, [flush]),
    catch gun:close(Conn),
    catch gun:flush(Conn),
    ok.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

output() ->
    case get(output) of
        undefined ->
            O = binary:copy(<<"x">>, cfg(output_bytes)),
            put(output, O),
            O;
        O -> O
    end.

delay({Min, Max}) when Max > Min -> Min + rand:uniform(Max - Min + 1) - 1;
delay({Min, _}) -> Min.

cfg(Key) ->
    [{Key, V}] = ets:lookup(?CFG, Key),
    V.

bump(Key) ->
    ets:update_counter(?COUNTERS, Key, 1),
    ok.

bool(true) -> 1;
bool(false) -> 0.

short({shutdown, R}) -> short(R);
short({down, R}) -> short(R);
short(R) when is_atom(R) -> R;
short({R, _}) when is_atom(R) -> R;
short(_) -> other.

now_ms() -> erlang:system_time(millisecond).
