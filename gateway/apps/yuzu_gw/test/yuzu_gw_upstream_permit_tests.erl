%%%-------------------------------------------------------------------
%%% @doc ProxyRegister and ProxyInventory run in the caller, under a permit.
%%%
%%% yuzu_gw_upstream:proxy_register/1,2 and proxy_inventory/1,2 make the RPC in
%%% the calling process (the gRPC request's own runner) after a permit from
%%% yuzu_gw_upstream_regulator; the upstream gen_server only owns the breaker.
%%% These tests pin what that buys, through the public API only:
%%%
%%%   - a burst far above the permit count is served in parallel, every call
%%%     inside its deadline, none refused (the bounded wait queue absorbs it);
%%%   - a caller whose deadline passes while it waits for a permit makes no
%%%     RPC (it has given up; the server must not see a registration for it);
%%%   - a permit holder that is killed mid-RPC frees its permit;
%%%   - a full wait queue refuses at once with `overloaded'.
%%%
%%% The mocked yuzu_grpc_client:unary/5 records the in-flight count in an ETS
%%% table this module creates and deletes, so peak concurrency is measured, not
%%% inferred.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_permit_tests).
-include_lib("eunit/include/eunit.hrl").

-define(TAB, yuzu_gw_upstream_permit_tests_tab).
-define(ENV_KEYS, [upstream_call_timeout_ms, upstream_register_concurrency,
                   upstream_register_queue_max, upstream_inventory_concurrency,
                   upstream_inventory_queue_max, circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms, circuit_breaker_max_reset_timeout_ms]).

permit_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{timeout, 60, {"a burst of 600 Registers against 48 permits: all served, in parallel, "
                     "inside the deadline", fun burst_is_served_in_parallel/0}},
      {timeout, 30, {"a caller whose deadline passes while it waits for a permit makes no RPC",
                     fun expired_waiter_makes_no_rpc/0}},
      {timeout, 30, {"a permit holder killed mid-RPC frees its permit",
                     fun killed_holder_frees_permit/0}},
      {timeout, 30, {"a full wait queue refuses at once with overloaded",
                     fun full_queue_refuses/0}},
      {timeout, 30, {"inventory has its own pool: a held Register pool does not block it",
                     fun inventory_pool_is_separate/0}},
      {timeout, 30, {"the RPC deadline handed to the client is below the caller's",
                     fun rpc_timeout_is_below_caller_deadline/0}}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    ?TAB = ets:new(?TAB, [named_table, public, set]),
    ets:insert(?TAB, [{inflight, 0}, {peak, 0}]),
    %% Failures never trip the breaker in these tests.
    yuzu_gw_test_upstream:set_breaker_env(1000),
    Prev.

cleanup(Prev) ->
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    catch ets:delete(?TAB),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

%%--------------------------------------------------------------------

burst_is_served_in_parallel() ->
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 5000),
    mock_latency(50),
    _ = yuzu_gw_test_upstream:start_upstream(),
    N = 600,
    T0 = erlang:monotonic_time(millisecond),
    Results = run_callers(N, fun(I) -> yuzu_gw_upstream:proxy_register(req(I)) end, 20000),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    Refused = [R || R <- Results, element(1, R) =/= ok],
    Peak = ets:lookup_element(?TAB, peak, 2),
    ?debugFmt("burst: ~b callers, ~b refused, peak ~b in flight, ~b ms", [N, length(Refused), Peak, Elapsed]),
    ?assertEqual([], lists:usort(Refused)),
    ?assert(Peak > 1),
    ?assert(Peak =< 48),
    ?assert(Elapsed < 5000).

expired_waiter_makes_no_rpc() ->
    application:set_env(yuzu_gw, upstream_register_concurrency, 1),
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 600),
    mock_hold_first(),
    _ = yuzu_gw_test_upstream:start_upstream(),
    Test = self(),
    Holder = spawn(fun() -> Test ! {done, self(), yuzu_gw_upstream:proxy_register(req(<<"hold">>))} end),
    {held, Rpc} = receive {held, _} = H -> H after 5000 -> error(no_hold) end,
    %% The waiter reports its answer and then stays alive: a caller that has
    %% given up is not a dead one, so nothing may rely on it having exited.
    Waiter = spawn(fun() ->
                       Test ! {done, self(), yuzu_gw_upstream:proxy_register(req(<<"late">>))},
                       receive stop -> ok after 10000 -> ok end
                   end),
    WaiterResult = receive {done, Waiter, R} -> R after 5000 -> error(waiter_hung) end,
    ?assertMatch({error, _}, WaiterResult),
    ?assert(is_process_alive(Waiter)),
    %% Free the holder and give the upstream every chance to run the stale request.
    Rpc ! go,
    receive {done, Holder, _} -> ok after 5000 -> error(holder_hung) end,
    timer:sleep(200),
    Waiter ! stop,
    ?assertEqual([<<"hold">>], rpc_tokens()).

killed_holder_frees_permit() ->
    application:set_env(yuzu_gw, upstream_register_concurrency, 1),
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 3000),
    mock_hold_first(),
    _ = yuzu_gw_test_upstream:start_upstream(),
    Holder = spawn(fun() -> yuzu_gw_upstream:proxy_register(req(<<"hold">>)) end),
    {held, _Rpc} = receive {held, _} = H -> H after 5000 -> error(no_hold) end,
    Mon = monitor(process, Holder),
    exit(Holder, kill),
    receive {'DOWN', Mon, process, Holder, _} -> ok after 5000 -> error(not_dead) end,
    ?assertMatch({ok, _}, yuzu_gw_upstream:proxy_register(req(<<"next">>))),
    %% done/1 is a cast: wait for the regulator to have taken it.
    await_register(fun(#{held := H, waiting := W}) -> H =:= 0 andalso W =:= 0 end).

full_queue_refuses() ->
    application:set_env(yuzu_gw, upstream_register_concurrency, 1),
    application:set_env(yuzu_gw, upstream_register_queue_max, 2),
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 3000),
    mock_hold_first(),
    _ = yuzu_gw_test_upstream:start_upstream(),
    Test = self(),
    _Holder = spawn(fun() -> Test ! {done, hold, yuzu_gw_upstream:proxy_register(req(<<"hold">>))} end),
    {held, Rpc} = receive {held, _} = H -> H after 5000 -> error(no_hold) end,
    Q1 = spawn(fun() -> Test ! {done, q1, yuzu_gw_upstream:proxy_register(req(<<"q1">>))} end),
    Q2 = spawn(fun() -> Test ! {done, q2, yuzu_gw_upstream:proxy_register(req(<<"q2">>))} end),
    await_waiting(2),
    ?assertEqual({error, overloaded}, yuzu_gw_upstream:proxy_register(req(<<"over">>))),
    Rpc ! go,
    [receive {done, Who, R} -> ?assertMatch({ok, _}, R) after 5000 -> error({hung, Who}) end
     || Who <- [hold, q1, q2]],
    _ = {Q1, Q2},
    ?assertEqual([<<"hold">>, <<"q1">>, <<"q2">>], lists:sort(rpc_tokens())).

inventory_pool_is_separate() ->
    application:set_env(yuzu_gw, upstream_register_concurrency, 1),
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 3000),
    mock_hold_first(),
    _ = yuzu_gw_test_upstream:start_upstream(),
    _Holder = spawn(fun() -> yuzu_gw_upstream:proxy_register(req(<<"hold">>)) end),
    {held, Rpc} = receive {held, _} = H -> H after 5000 -> error(no_hold) end,
    ?assertMatch({ok, _}, yuzu_gw_upstream:proxy_inventory(#{agent_id => <<"inv">>})),
    Rpc ! go.

rpc_timeout_is_below_caller_deadline() ->
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 3000),
    Test = self(),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, _Path, _Req, _Def, Opts) ->
                         Test ! {opts, Opts},
                         {ok, #{session_id => <<"s">>}, #{}}
                     end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    Deadline = erlang:monotonic_time(millisecond) + 2000,
    ?assertMatch({ok, _}, yuzu_gw_upstream:proxy_register(req(<<"d">>), #{deadline => Deadline})),
    Opts = receive {opts, O} -> O after 1000 -> error(no_rpc) end,
    Timeout = maps:get(timeout, Opts),
    ?assert(Timeout > 0),
    ?assert(Timeout < 2000).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

req(I) when is_integer(I) -> req(integer_to_binary(I));
req(Token) -> #{enrollment => #{token => Token}, info => #{agent_id => Token}}.

token(Req) -> maps:get(token, maps:get(enrollment, Req, #{}), undefined).

%% Every call takes Ms, and the in-flight count and its peak are recorded.
mock_latency(Ms) ->
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, _Path, _Req, _Def, _Opts) ->
                         In = ets:update_counter(?TAB, inflight, 1),
                         bump_peak(In),
                         timer:sleep(Ms),
                         ets:update_counter(?TAB, inflight, -1),
                         {ok, #{session_id => <<"s">>}, #{}}
                     end).

bump_peak(In) ->
    [{peak, P}] = ets:lookup(?TAB, peak),
    case In > P of
        true -> ets:insert(?TAB, {peak, In});
        false -> ok
    end.

%% The call for the token <<"hold">> blocks until the test sends `go' to the
%% process it reports; every other call answers at once.
mock_hold_first() ->
    Test = self(),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, _Path, Req, _Def, _Opts) ->
                         case token(Req) of
                             <<"hold">> -> Test ! {held, self()},
                                           receive go -> ok after 10000 -> ok end;
                             _ -> ok
                         end,
                         {ok, #{session_id => <<"s">>}, #{}}
                     end).

rpc_tokens() ->
    [token(Req) || {_, {yuzu_grpc_client, unary, [_, _, Req, _, _]}, _}
                       <- meck:history(yuzu_grpc_client)].

run_callers(N, Fun, Timeout) ->
    Test = self(),
    Pids = [spawn(fun() -> Test ! {result, self(), Fun(I)} end) || I <- lists:seq(1, N)],
    [receive {result, P, R} -> R after Timeout -> {timeout, P} end || P <- Pids].

await_waiting(N) ->
    await_register(fun(#{waiting := W}) -> W >= N end).

%% Wait until the register class of the regulator's snapshot satisfies Pred.
await_register(Pred) ->
    await_register(Pred, erlang:monotonic_time(millisecond) + 5000).

await_register(Pred, Deadline) ->
    #{register := Reg} = yuzu_gw_upstream_regulator:snapshot(),
    case Pred(Reg) of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> error({register_snapshot, Reg});
                false -> timer:sleep(5), await_register(Pred, Deadline)
            end
    end.
