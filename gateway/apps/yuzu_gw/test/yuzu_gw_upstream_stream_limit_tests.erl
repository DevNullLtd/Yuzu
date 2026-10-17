%%%-------------------------------------------------------------------
%%% @doc The gateway sizes its upstream calls from the stream limit the server
%%% declares (Gate 8 owner decision B).
%%%
%%% RFC 9113 6.5.2: SETTINGS_MAX_CONCURRENT_STREAMS is declared in the SETTINGS
%%% frame that starts the connection and may change at any time (6.5); 5.1.2:
%%% the client must not open more streams than that. gun refuses a request past
%%% the limit locally (too_many_streams).
%%%
%%% What is held here:
%%%   - the rule (pure): effective permit ceilings from the configured pool
%%%     sizes, the server's capacity and the streams the gateway's other lanes
%%%     reserve;
%%%   - the channel learns each connection's limit from a real gun connection
%%%     to a real Cowboy listener that declares one, follows a change (gun's
%%%     settings_changed notification, simulated: Cowboy fixes its SETTINGS for
%%%     the life of a connection), and forgets a connection that goes down;
%%%   - the regulator applies it: the ceilings follow the learned capacity, a
%%%     lower ceiling never revokes a held permit but stops new grants until the
%%%     held count is below it, and it is published as
%%%     yuzu_gw_upstream_server_max_streams;
%%%   - a call gun refuses locally with too_many_streams is local backpressure:
%%%     the caller waits again for a permit and retries, until its deadline
%%%     (then UNAVAILABLE, `deadline'), and the circuit breaker does not move.
%%%
%%% Ports are probed; every process, mock, handler and channel a case starts is
%%% stopped in its cleanup.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_stream_limit_tests).
-include_lib("eunit/include/eunit.hrl").

-export([forward/4]).

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(CHANNEL, default_channel).
-define(HANDLER, {?MODULE, server_max_streams}).
-define(WAIT_MS, 5000).
-define(CONFIGURED, #{register => 48, replay => 24, inventory => 8}).
-define(RESERVED, 61).

%%%===================================================================
%%% The rule
%%%===================================================================

effective_limits_test_() ->
    E = fun(Cap) -> yuzu_gw_upstream_regulator:effective_limits(?CONFIGURED, Cap, ?RESERVED) end,
    [{"no learned limit: the configured sizes",
      ?_assertEqual(?CONFIGURED, E(none))},
     {"the C++ default of 128 leaves 67 streams, room for 48 + 8: the configured sizes",
      ?_assertEqual(?CONFIGURED, E(128))},
     {"exactly enough (61 + 56): the configured sizes",
      ?_assertEqual(?CONFIGURED, E(117))},
     {"100: 39 left, split 48:8 -> register 33, inventory 6, replay half of register",
      ?_assertEqual(#{register => 33, replay => 16, inventory => 6}, E(100))},
     {"80: 19 left -> register 16, inventory 3, replay 8",
      ?_assertEqual(#{register => 16, replay => 8, inventory => 3}, E(80))},
     {"16, below what the other lanes reserve: one permit each, never zero",
      ?_assertEqual(#{register => 1, replay => 1, inventory => 1}, E(16))},
     {"0: still one permit each",
      ?_assertEqual(#{register => 1, replay => 1, inventory => 1}, E(0))},
     {"the effective ceiling never exceeds the configured one",
      ?_assertEqual(#{register => 4, replay => 2, inventory => 1},
                    yuzu_gw_upstream_regulator:effective_limits(
                      #{register => 4, replay => 2, inventory => 1}, 100, ?RESERVED))},
     {"the reserved streams are the notify lane (10), the Guardian lane (50) and the "
      "heartbeat flush (1)",
      ?_assertEqual(?RESERVED, yuzu_gw_upstream:reserved_streams())}].

%%%===================================================================
%%% The channel learns the limit
%%%===================================================================

channel_test_() ->
    {foreach,
     fun setup_channel/0,
     fun cleanup_channel/1,
     [fun(S) -> {"each connection's declared limit is learned, summed, follows a change, and is "
                 "forgotten when the connection goes down",
                 {timeout, 60, fun() -> channel_learns_the_limit(S) end}} end,
      fun(S) -> {"gun refuses a call past the declared limit as too_many_streams",
                 {timeout, 60, fun() -> gun_refusal_is_too_many_streams(S) end}} end]}.

setup_channel() ->
    start_apps(),
    yuzu_grpc_stub_svc:init_state(),
    #{name => list_to_atom("yuzu_stream_limit_" ++ integer_to_list(erlang:unique_integer([positive]))),
      listeners => ets:new(?MODULE, [public, bag])}.

cleanup_channel(#{name := Name, listeners := Tab}) ->
    [S ! release || S <- yuzu_grpc_stub_svc:sleepers()],
    ok = yuzu_gw_test_listener:stop_channel(Name),
    [catch yuzu_grpc_listener:stop(P) || {listener, P} <- ets:tab2list(Tab)],
    ets:delete(Tab),
    ok.

channel_learns_the_limit(#{name := Name} = S) ->
    {Port, Listener} = listener(S, 100),
    _ = yuzu_gw_test_listener:client_channel(Name, #{port => Port, pool_size => 2}),
    ok = wait(fun() -> yuzu_grpc_client_channel:server_capacity(Name) =:= 200 end),
    [C1, _C2] = up_conns(Name),
    %% the server lowers one connection's limit (RFC 9113 6.5)
    Name ! {gun_notify, C1, settings_changed, #{max_concurrent_streams => 80}},
    ok = wait(fun() -> yuzu_grpc_client_channel:server_capacity(Name) =:= 180 end),
    %% a connection that declares no limit makes the channel unlimited
    Name ! {gun_notify, C1, settings_changed, #{max_concurrent_streams => infinity}},
    ok = wait(fun() -> yuzu_grpc_client_channel:server_capacity(Name) =:= none end),
    Name ! {gun_notify, C1, settings_changed, #{max_concurrent_streams => 80}},
    ok = wait(fun() -> yuzu_grpc_client_channel:server_capacity(Name) =:= 180 end),
    %% a notification from a connection the channel does not own is ignored
    Name ! {gun_notify, self(), settings_changed, #{max_concurrent_streams => 1}},
    _ = sys:get_state(Name),
    ?assertEqual(180, yuzu_grpc_client_channel:server_capacity(Name)),
    %% the connections go down: nothing learned
    ok = yuzu_grpc_listener:stop(Listener),
    ok = wait(fun() -> yuzu_grpc_client_channel:server_capacity(Name) =:= none end).

gun_refusal_is_too_many_streams(#{name := Name} = S) ->
    {Port, _Listener} = listener(S, 1),
    _ = yuzu_gw_test_listener:client_channel(Name, #{port => Port}),
    ok = wait(fun() -> yuzu_grpc_client_channel:server_capacity(Name) =:= 1 end),
    yuzu_grpc_stub_svc:notify(self()),
    Self = self(),
    Sleeper = spawn(fun() ->
                            R = yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"sleep">>},
                                                       hb_def(), #{channel => Name, timeout => 10000}),
                            Self ! {sleeper, R}
                    end),
    receive {stub, sleeping, _} -> ok after ?WAIT_MS -> error(handler_never_slept) end,
    ?assertEqual({error, too_many_streams},
                 yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>}, hb_def(),
                                        #{channel => Name, timeout => 2000})),
    [H ! release || H <- yuzu_grpc_stub_svc:sleepers()],
    receive {sleeper, R} -> ?assertMatch({ok, _, _}, R) after ?WAIT_MS -> error(sleeper_silent) end,
    %% the stream is free again
    ?assertMatch({ok, _, _}, yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>},
                                                    hb_def(), #{channel => Name, timeout => 2000})),
    _ = Sleeper.

%%%===================================================================
%%% The regulator applies it
%%%===================================================================

regulator_test_() ->
    {foreach,
     fun setup_regulator/0,
     fun cleanup_regulator/1,
     [fun(S) -> {"the ceilings follow the server's declared limit; a lower one revokes nothing "
                 "and holds new grants until the held count is below it",
                 {timeout, 60, fun() -> regulator_follows_the_server(S) end}} end]}.

setup_regulator() ->
    start_apps(),
    yuzu_gw_test_upstream:stop_upstream(),
    stop_regulator(),
    ok = yuzu_gw_test_listener:stop_channel(?CHANNEL),
    catch telemetry:detach(?HANDLER),
    Saved = yuzu_gw_test_upstream:save_env([upstream_register_concurrency,
                                            upstream_replay_concurrency,
                                            upstream_inventory_concurrency]),
    [application:unset_env(yuzu_gw, K) || {K, _} <- Saved],
    #{listeners => ets:new(?MODULE, [public, bag]), saved => Saved}.

cleanup_regulator(#{listeners := Tab, saved := Saved} = S) ->
    catch telemetry:detach(?HANDLER),
    [Pid ! stop || Pid <- maps:get(holders, S, [])],
    stop_regulator(),
    ok = yuzu_gw_test_listener:stop_channel(?CHANNEL),
    [catch yuzu_grpc_listener:stop(P) || {listener, P} <- ets:tab2list(Tab)],
    ets:delete(Tab),
    yuzu_gw_test_upstream:restore_env(Saved),
    flush(),
    ok.

regulator_follows_the_server(S) ->
    ok = telemetry:attach(?HANDLER, [yuzu, gw, upstream, server_max_streams],
                          fun ?MODULE:forward/4, self()),
    {Port, Listener} = listener(S, 100),
    _ = yuzu_gw_test_listener:client_channel(?CHANNEL, #{port => Port}),
    ok = wait(fun() -> yuzu_grpc_client_channel:server_capacity(?CHANNEL) =:= 100 end),
    {ok, Reg} = yuzu_gw_upstream_regulator:start_link(),
    unlink(Reg),
    %% 100 - 61 = 39 left: register 33, replay 16, inventory 6
    ?assertEqual({33, 16, 6}, limits()),
    ?assertEqual(100, last_server_max_streams()),
    %% 30 register permits held
    Holders = [holder(register) || _ <- lists:seq(1, 30)],
    ok = wait(fun() -> held(register) =:= 30 end),
    %% the server lowers its limit to 80: register 16, and nothing is revoked
    [Conn] = up_conns(?CHANNEL),
    ?CHANNEL ! {gun_notify, Conn, settings_changed, #{max_concurrent_streams => 80}},
    ok = wait(fun() -> limits() =:= {16, 8, 3} end),
    ?assertEqual(80, last_server_max_streams()),
    ?assertEqual(30, held(register)),
    %% a new caller waits
    Waiter = asker(register),
    ok = wait(fun() -> waiting(register) =:= 1 end),
    {Release, Keep} = lists:split(14, Holders),
    [H ! stop || H <- Release],
    ok = wait(fun() -> held(register) =:= 16 end),
    ?assertEqual(1, waiting(register)),
    ?assertEqual(nothing, granted(Waiter, 100)),
    %% one more frees: 15 is below 16, so the waiter is served
    [Last | Keep1] = Keep,
    Last ! stop,
    ?assertEqual(ok, granted(Waiter, ?WAIT_MS)),
    ?assertEqual(16, held(register)),
    %% a limit below what the other lanes reserve: the floor of one each
    ?CHANNEL ! {gun_notify, Conn, settings_changed, #{max_concurrent_streams => 16}},
    ok = wait(fun() -> limits() =:= {1, 1, 1} end),
    %% the connection goes down: nothing learned, the configured sizes again
    ok = yuzu_grpc_listener:stop(Listener),
    ok = wait(fun() -> limits() =:= {48, 24, 8} end),
    ok = wait(fun() -> last_server_max_streams() =:= 0 end),
    [P ! stop || P <- [Waiter | Keep1]],
    ok.

%%%===================================================================
%%% too_many_streams is local backpressure
%%%===================================================================

backpressure_test_() ->
    {foreach,
     fun setup_upstream/0,
     fun cleanup_upstream/1,
     [fun(_) -> {"a call refused too_many_streams waits for a permit again and is retried; "
                 "the breaker does not move",
                 {timeout, 30, fun refused_call_is_retried/0}} end,
      fun(_) -> {"a call refused until its deadline is answered deadline (UNAVAILABLE); "
                 "the breaker does not move",
                 {timeout, 30, fun refused_until_deadline/0}} end]}.

setup_upstream() ->
    yuzu_gw_test_registry:ensure(),
    yuzu_gw_test_upstream:stop_upstream(),
    stop_regulator(),
    catch meck:unload(yuzu_grpc_client),
    Saved = yuzu_gw_test_upstream:save_env([circuit_breaker_failure_threshold,
                                            circuit_breaker_reset_timeout_ms,
                                            circuit_breaker_max_reset_timeout_ms]),
    ok = yuzu_gw_test_upstream:set_breaker_env(2),
    meck:new(yuzu_grpc_client, [non_strict, no_link]),
    Pid = yuzu_gw_test_upstream:start_upstream(),
    #{pid => Pid, saved => Saved}.

cleanup_upstream(#{saved := Saved}) ->
    yuzu_gw_test_upstream:stop_upstream(),
    stop_regulator(),
    catch meck:unload(yuzu_grpc_client),
    yuzu_gw_test_upstream:restore_env(Saved),
    ok.

refused_call_is_retried() ->
    Refusals = atomics:new(1, []),
    atomics:put(Refusals, 1, 3),
    meck:expect(yuzu_grpc_client, unary,
                fun(_Meta, _Path, _Req, _Def, _Opts) ->
                        case atomics:sub_get(Refusals, 1, 1) >= 0 of
                            true  -> {error, too_many_streams};
                            false -> {ok, #{accepted => true, session_id => <<"s">>}, #{}}
                        end
                end),
    Deadline = erlang:monotonic_time(millisecond) + 5000,
    ?assertMatch({ok, #{accepted := true}},
                 yuzu_gw_upstream:proxy_register(request(), #{deadline => Deadline})),
    ?assertEqual(4, meck:num_calls(yuzu_grpc_client, unary, '_')),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, up_field(cb_failures)),
    %% the permit was handed back each time
    ok = wait(fun() -> held(register) =:= 0 end).

refused_until_deadline() ->
    meck:expect(yuzu_grpc_client, unary,
                fun(_Meta, _Path, _Req, _Def, _Opts) -> {error, too_many_streams} end),
    Deadline = erlang:monotonic_time(millisecond) + 1000,
    ?assertEqual({error, deadline},
                 yuzu_gw_upstream:proxy_register(request(), #{deadline => Deadline})),
    %% more refusals than the breaker's threshold of 2, and it did not move
    ?assert(meck:num_calls(yuzu_grpc_client, unary, '_') > 2),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, up_field(cb_failures)),
    ok = wait(fun() -> held(register) =:= 0 end).

%%%===================================================================
%%% Helpers
%%%===================================================================

start_apps() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    ok.

%% A stub AgentService listener that declares max_concurrent_streams Max.
listener(#{listeners := Tab}, Max) ->
    {Port, Pid} = yuzu_gw_test_listener:start(
                    #{service_protos => [agent_pb],
                      services => #{?SVC => yuzu_grpc_stub_svc},
                      http2 => #{max_concurrent_streams => Max}}),
    ets:insert(Tab, {listener, Pid}),
    {Port, Pid}.

up_conns(Name) ->
    lists:sort(ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}])).

stop_regulator() ->
    case whereis(yuzu_gw_upstream_regulator) of
        undefined -> ok;
        Pid -> catch unlink(Pid),
               catch gen_server:stop(Pid, shutdown, 5000),
               ok
    end.

limits() ->
    #{register := #{limit := R}, replay := #{limit := P}, inventory := #{limit := I}} =
        yuzu_gw_upstream_regulator:snapshot(),
    {R, P, I}.

held(Class) -> maps:get(held, maps:get(Class, yuzu_gw_upstream_regulator:snapshot())).
waiting(Class) -> maps:get(waiting, maps:get(Class, yuzu_gw_upstream_regulator:snapshot())).

%% A process that takes a permit of Class and holds it until told `stop'.
holder(Class) ->
    Self = self(),
    Pid = spawn(fun() ->
                        {ok, _} = yuzu_gw_upstream_regulator:ask(
                                    Class, erlang:monotonic_time(millisecond) + 30000),
                        Self ! {holding, self()},
                        receive stop -> ok after 60000 -> ok end
                end),
    receive {holding, Pid} -> Pid after ?WAIT_MS -> error(no_permit) end.

%% A process that asks for a permit, reports when it has one, and holds it.
asker(Class) ->
    Self = self(),
    spawn(fun() ->
                  case yuzu_gw_upstream_regulator:ask(
                         Class, erlang:monotonic_time(millisecond) + 30000) of
                      {ok, _} -> Self ! {granted, self()};
                      Other   -> Self ! {refused, self(), Other}
                  end,
                  receive stop -> ok after 60000 -> ok end
          end).

granted(Pid, Timeout) ->
    receive
        {granted, Pid} -> ok;
        {refused, Pid, Why} -> {refused, Why}
    after Timeout -> nothing
    end.

forward(_Event, #{streams := N}, _Meta, Pid) ->
    Pid ! {server_max_streams, N},
    ok.

last_server_max_streams() ->
    last_server_max_streams(none).
last_server_max_streams(Last) ->
    receive {server_max_streams, N} -> last_server_max_streams(N)
    after 0 -> Last
    end.

flush() ->
    receive {server_max_streams, _} -> flush()
    after 0 -> ok
    end.

request() ->
    #{info => #{agent_id => <<"stream-limit-agent">>, hostname => <<"h">>},
      enrollment_token => <<"t">>}.

hb_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

%% A field of the upstream process's #state{}, by name.
up_field(Name) ->
    Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_upstream.erl"]),
    {ok, Forms} = epp:parse_file(Src, []),
    [Fs] = [Fs0 || {attribute, _, record, {state, Fs0}} <- Forms],
    Names = [case F of
                 {typed_record_field, {record_field, _, {atom, _, N}}, _} -> N;
                 {typed_record_field, {record_field, _, {atom, _, N}, _}, _} -> N;
                 {record_field, _, {atom, _, N}} -> N;
                 {record_field, _, {atom, _, N}, _} -> N
             end || F <- Fs],
    [I] = [I || {I, N} <- lists:zip(lists:seq(2, length(Names) + 1), Names), N =:= Name],
    element(I, sys:get_state(yuzu_gw_upstream)).

wait(Pred) -> wait(Pred, ?WAIT_MS).

wait(Pred, Left) when Left =< 0 ->
    case Pred() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait(Pred, Left) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(10), wait(Pred, Left - 10)
    end.
