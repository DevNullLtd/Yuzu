%%%-------------------------------------------------------------------
%%% @doc What happens to a proxied Register or Inventory whose caller dies or
%%% gives up.
%%%
%%% The RPC runs in the caller (the process of one gRPC request), after a permit
%%% from yuzu_gw_upstream_regulator. A caller the stream handler kills while it
%%% waits for a permit is gone with its request: nothing is sent for it, its
%%% place in the queue is freed by its 'DOWN', and the breaker is not touched.
%%% A result that comes back after the breaker moved on is ignored.
%%%
%%% The pool is set to one permit and held by a call the mocked
%%% yuzu_grpc_client:unary/5 blocks, so "waiting" is a fact the test reads from
%%% the regulator's snapshot, not a timing it hopes for.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_dead_caller_tests).
-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 3000).
-define(ENV_KEYS, [upstream_register_concurrency, upstream_inventory_concurrency,
                   circuit_breaker_failure_threshold, upstream_call_timeout_ms]).

dead_caller_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{"waiters killed before their permit make no RPC; a live waiter's is made",
       fun killed_waiters_make_no_rpc/0},
      {"killed Register waiters leave the breaker closed and free their places",
       fun() -> killed_waiters_leave_breaker(register) end},
      {"killed Inventory waiters leave the breaker closed and free their places",
       fun() -> killed_waiters_leave_breaker(inventory) end},
      {"a result from before the breaker moved does not count",
       fun stale_result_is_ignored/0},
      {"the state read and an unknown request are answered",
       fun other_calls_are_answered/0}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, _Path, Req, _Def, _Opts) ->
                         {ok, #{session_id => <<"sess-", (token(Req))/binary>>}, #{}}
                     end),
    application:set_env(yuzu_gw, upstream_register_concurrency, 1),
    application:set_env(yuzu_gw, upstream_inventory_concurrency, 1),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 2),
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 10000),
    _ = yuzu_gw_test_upstream:start_upstream(),
    Prev.

cleanup(Prev) ->
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

%%--------------------------------------------------------------------

killed_waiters_make_no_rpc() ->
    Rpc = hold(register),
    Dead = [spawn_caller(register, <<"dead-", (integer_to_binary(I))/binary>>)
            || I <- lists:seq(1, 4)],
    await(register, fun(#{waiting := W}) -> W =:= 4 end),
    Live = spawn_caller(register, <<"live">>),
    await(register, fun(#{waiting := W}) -> W =:= 5 end),
    [kill(P) || P <- Dead],
    await(register, fun(#{waiting := W}) -> W =:= 1 end),
    Rpc ! go,
    ?assertMatch({reply, {ok, #{session_id := <<"sess-live">>}}}, await_reply(Live)),
    ?assertEqual([<<"hold">>, <<"live">>], rpc_tokens()).

killed_waiters_leave_breaker(Class) ->
    Rpc = hold(Class),
    Dead = [spawn_caller(Class, <<"dead">>) || _ <- lists:seq(1, 10)],
    await(Class, fun(#{waiting := W}) -> W =:= 10 end),
    [kill(P) || P <- Dead],
    await(Class, fun(#{waiting := W}) -> W =:= 0 end),
    Rpc ! go,
    await(Class, fun(#{held := H}) -> H =:= 0 end),
    Live = spawn_caller(Class, <<"live">>),
    ?assertMatch({reply, {ok, _}}, await_reply(Live)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual([<<"hold">>, <<"live">>], rpc_tokens()).

%% The breaker counts a result only under the generation it was read with: two
%% failures with a generation the breaker no longer has leave it closed (the
%% threshold here is 2), two with the current one open it.
stale_result_is_ignored() ->
    Up = whereis(yuzu_gw_upstream),
    Stale = 99,
    [gen_server:cast(Up, {rpc_result, Stale, {error, econnrefused}}) || _ <- [1, 2]],
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    [gen_server:cast(Up, {rpc_result, 0, {error, econnrefused}}) || _ <- [1, 2]],
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

other_calls_are_answered() ->
    Up = whereis(yuzu_gw_upstream),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual({error, unknown_call}, gen_server:call(Up, no_such_request, ?WAIT_MS)).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

token(Req) -> maps:get(token, maps:get(enrollment, Req, #{}), <<"none">>).

req(Id) -> #{enrollment => #{token => Id}}.

%% Take the one permit of Class with a call the mock holds; returns the process
%% to send `go' to.
hold(Class) ->
    %% Installed here, in the test's own process: the fixture's setup runs in
    %% another one, and the mock reports to whoever installed it.
    Test = self(),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, _Path, Req, _Def, _Opts) ->
                         case token(Req) of
                             <<"hold">> -> Test ! {held, self()},
                                           receive go -> ok after 10000 -> ok end;
                             _ -> ok
                         end,
                         {ok, #{session_id => <<"sess-", (token(Req))/binary>>}, #{}}
                     end),
    _ = spawn_caller(Class, <<"hold">>),
    receive {held, P} -> P after ?WAIT_MS -> error(no_hold) end.

spawn_caller(Class, Id) ->
    Test = self(),
    spawn(fun() ->
              Reply = case Class of
                  register  -> yuzu_gw_upstream:proxy_register(req(Id));
                  inventory -> yuzu_gw_upstream:proxy_inventory(req(Id))
              end,
              Test ! {reply, self(), Reply}
          end).

await_reply(Pid) ->
    receive {reply, Pid, Reply} -> {reply, Reply}
    after ?WAIT_MS -> error({no_reply, Pid})
    end.

await(Class, Pred) ->
    await(Class, Pred, erlang:monotonic_time(millisecond) + ?WAIT_MS).

await(Class, Pred, Deadline) ->
    Snap = maps:get(Class, yuzu_gw_upstream_regulator:snapshot()),
    case Pred(Snap) of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> error({snapshot, Class, Snap});
                false -> timer:sleep(5), await(Class, Pred, Deadline)
            end
    end.

kill(Pid) ->
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Mon, process, Pid, _} -> ok after ?WAIT_MS -> error(not_dead) end.

rpc_tokens() ->
    [token(Req) || {_, {yuzu_grpc_client, unary, [_, _, Req, _, _]}, _}
                       <- meck:history(yuzu_grpc_client)].
