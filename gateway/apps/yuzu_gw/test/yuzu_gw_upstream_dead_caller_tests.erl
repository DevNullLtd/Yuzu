%%%-------------------------------------------------------------------
%%% @doc What yuzu_gw_upstream does with a proxy call whose caller has died.
%%%
%%% The upstream process runs one RPC at a time, so calls queue in its mailbox.
%%% The caller of a Register or an Inventory is the process of one gRPC request,
%%% which the stream handler stops when the client resets the stream, the
%%% deadline passes or the connection closes. The call it left in the queue must
%%% not be made: it would create a server session nobody will use and delay the
%%% calls of live requests behind it.
%%%
%%% The upstream is suspended (sys:suspend/1) while the calls are queued, so
%%% that "queued" is a fact the test waits for, not a timing it hopes for; the
%%% RPC itself is a mocked grpcbox_client:unary/5 that records which request it
%%% was made for.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_dead_caller_tests).
-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 3000).
-define(SINK, yuzu_gw_dead_caller_sink).
-define(DROPPED, [yuzu, gw, upstream, call_dropped]).

dead_caller_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{"queued Registers and Inventories of dead callers make no RPC; a live caller's does",
       fun dead_callers_make_no_rpc/0},
      {"a dead caller between two live ones is skipped and the live ones are served in order",
       fun dead_caller_between_live_ones/0},
      {"a live caller that waits a long time is still served",
       fun slow_live_caller_is_served/0},
      {"dead Register callers do not touch the circuit breaker",
       fun() -> dead_caller_leaves_breaker(register) end},
      {"dead Inventory callers do not touch the circuit breaker",
       fun() -> dead_caller_leaves_breaker(inventory) end},
      {"the state read and an unknown request are answered",
       fun other_calls_are_answered/0},
      {"a caller on another node is treated as alive",
       fun remote_caller_is_alive/0}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    stop_named(yuzu_gw_upstream),
    catch meck:unload(grpcbox_client),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, Path, Req, _Def, _Opts) ->
                         Id = maps:get(token, maps:get(enrollment, Req, Req), undefined),
                         sink() ! {rpc, Path, Id, self()},
                         case Id of
                             <<"hold">> -> receive go -> ok end;
                             _ -> ok
                         end,
                         {ok, #{session_id => <<"sess-", (id_bin(Id))/binary>>}, #{}}
                     end),
    HandlerId = {?MODULE, self()},
    ok = telemetry:attach(HandlerId, ?DROPPED,
                          fun(_E, M, Meta, _) -> sink() ! {dropped, M, Meta} end, none),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 2),
    {ok, Up} = gen_server:start({local, yuzu_gw_upstream}, yuzu_gw_upstream, [], []),
    #{upstream => Up, handler => HandlerId}.

cleanup(#{upstream := Up, handler := HandlerId}) ->
    telemetry:detach(HandlerId),
    application:unset_env(yuzu_gw, circuit_breaker_failure_threshold),
    catch gen_server:stop(Up, shutdown, ?WAIT_MS),
    catch meck:unload(grpcbox_client),
    ok.

%%--------------------------------------------------------------------

dead_callers_make_no_rpc() ->
    bind(),
    Up = whereis(yuzu_gw_upstream),
    ok = sys:suspend(Up),
    Dead = [spawn_caller(register, <<"dead-r1">>), spawn_caller(register, <<"dead-r2">>),
            spawn_caller(inventory, <<"dead-i1">>), spawn_caller(register, <<"dead-r3">>)],
    Live = spawn_caller(register, <<"live">>),
    await_queued(Up, 5),
    [kill(P) || P <- Dead],
    ok = sys:resume(Up),
    ?assertMatch({reply, {ok, #{session_id := <<"sess-live">>}}}, await_reply(Live)),
    %% every skipped call was reported, with the RPC it was for
    Events = [receive {dropped, #{count := 1}, #{rpc_name := N}} -> N after ?WAIT_MS ->
                  error(missing_drop_event) end || _ <- Dead],
    ?assertEqual([<<"inventory">>, <<"register">>, <<"register">>, <<"register">>],
                 lists:sort(Events)),
    %% the live call was the only one made upstream
    ?assertEqual([<<"live">>], rpc_ids()).

dead_caller_between_live_ones() ->
    bind(),
    Up = whereis(yuzu_gw_upstream),
    First = spawn_caller(register, <<"hold">>),
    {_Path, Worker} = receive {rpc, P, <<"hold">>, W} -> {P, W} after ?WAIT_MS -> error(no_rpc) end,
    %% the first RPC is in flight; two more calls queue behind it
    Doomed = spawn_caller(register, <<"doomed">>),
    Last = spawn_caller(register, <<"last">>),
    await_queued(Up, 2),
    kill(Doomed),
    Worker ! go,
    ?assertMatch({reply, {ok, _}}, await_reply(First)),
    ?assertMatch({reply, {ok, #{session_id := <<"sess-last">>}}}, await_reply(Last)),
    ?assertEqual([<<"hold">>, <<"last">>], rpc_ids()).

%% The other side of "dead": a caller that has not died is never skipped, however
%% long its call waits behind another one.
slow_live_caller_is_served() ->
    bind(),
    Up = whereis(yuzu_gw_upstream),
    First = spawn_caller(register, <<"hold">>),
    {_, Worker} = receive {rpc, P, <<"hold">>, W} -> {P, W} after ?WAIT_MS -> error(no_rpc) end,
    Slow = spawn_caller(inventory, <<"slow">>),
    await_queued(Up, 1),
    ?assertEqual(true, is_process_alive(Slow)),
    Worker ! go,
    ?assertMatch({reply, {ok, _}}, await_reply(First)),
    ?assertMatch({reply, {ok, #{session_id := <<"sess-slow">>}}}, await_reply(Slow)),
    ?assertEqual([<<"hold">>, <<"slow">>], rpc_ids()).

%% A skipped call is no failure of the upstream: the breaker here opens at two
%% failures, and ten skipped calls (of either RPC) must leave it closed so the
%% live call is made.
dead_caller_leaves_breaker(Rpc) ->
    bind(),
    Up = whereis(yuzu_gw_upstream),
    ok = sys:suspend(Up),
    Dead = [spawn_caller(Rpc, <<"dead">>) || _ <- lists:seq(1, 10)],
    Live = spawn_caller(Rpc, <<"live">>),
    await_queued(Up, 11),
    [kill(P) || P <- Dead],
    ok = sys:resume(Up),
    ?assertMatch({reply, {ok, _}}, await_reply(Live)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual([<<"live">>], rpc_ids()).

other_calls_are_answered() ->
    bind(),
    Up = whereis(yuzu_gw_upstream),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual({error, unknown_call}, gen_server:call(Up, no_such_request, ?WAIT_MS)).

%% From of a call made from another node names a pid that is not local; it is
%% not probed (is_process_alive/1 would raise) and the call is made.
remote_caller_is_alive() ->
    bind(),
    Up = whereis(yuzu_gw_upstream),
    RemotePid = remote_pid(),
    Tag = make_ref(),
    Req = #{enrollment => #{token => <<"remote">>}},
    Up ! {'$gen_call', {RemotePid, Tag}, {proxy_register, Req}},
    receive {rpc, _, <<"remote">>, _} -> ok after ?WAIT_MS -> error(remote_call_dropped) end,
    ?assert(is_process_alive(Up)).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

%% The mocked RPC and the telemetry handler run in other processes: they send what
%% they see to whichever test process is registered as the sink.
bind() ->
    catch unregister(?SINK),
    true = register(?SINK, self()),
    flush(),
    ok.

sink() ->
    whereis(?SINK).

%% A caller process: makes the call and hands the reply to the test.
spawn_caller(Rpc, Id) ->
    Test = self(),
    Pid = spawn(fun() ->
                    Req = #{enrollment => #{token => Id}},
                    Reply = case Rpc of
                        register -> yuzu_gw_upstream:proxy_register(Req);
                        inventory -> yuzu_gw_upstream:proxy_inventory(Req)
                    end,
                    Test ! {reply, self(), Reply}
                end),
    Pid.

await_reply(Pid) ->
    receive {reply, Pid, Reply} -> {reply, Reply}
    after ?WAIT_MS -> error({no_reply, Pid})
    end.

%% Wait until N calls are in the mailbox of the upstream: the process is either
%% suspended or busy with another call, so the length only grows.
await_queued(Up, N) ->
    Deadline = erlang:monotonic_time(millisecond) + ?WAIT_MS,
    await_queued(Up, N, Deadline).

await_queued(Up, N, Deadline) ->
    {message_queue_len, Len} = process_info(Up, message_queue_len),
    if
        Len >= N -> ok;
        true ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> error({not_queued, N, Len});
                false -> receive after 5 -> await_queued(Up, N, Deadline) end
            end
    end.

kill(Pid) ->
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Mon, process, Pid, _} -> ok after ?WAIT_MS -> error(not_dead) end.

%% The enrollment tokens the mocked RPC was made for, in call order.
rpc_ids() ->
    [Id || {_, {grpcbox_client, unary, [_, _, Req, _, _]}, _} <- meck:history(grpcbox_client),
           Id <- [maps:get(token, maps:get(enrollment, Req))]].

id_bin(Id) when is_binary(Id) -> Id;
id_bin(_) -> <<"none">>.

stop_named(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            catch unlink(Pid),
            Mon = monitor(process, Pid),
            exit(Pid, shutdown),
            receive {'DOWN', Mon, process, Pid, _} -> ok after ?WAIT_MS -> error({stuck, Name}) end
    end.

flush() ->
    receive _ -> flush() after 0 -> ok end.

%% A pid that belongs to another node, built from an external pid term.
remote_pid() ->
    binary_to_term(<<131, 88, 100, 0, 13, "other@nowhere", 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 1>>).
