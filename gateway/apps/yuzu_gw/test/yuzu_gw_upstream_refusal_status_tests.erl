%%%-------------------------------------------------------------------
%%% @doc What the agent is told when the gateway refuses a Register or an
%%% inventory report itself, and the deadline it hands upstream.
%%%
%%% A refusal that says "try again" (the breaker is open, the permit queue is
%%% full, the caller ran out of time waiting, the gateway is stopping) is
%%% UNAVAILABLE, the retryable gRPC status the agent backs off on; and the
%%% agent's own grpc-timeout bounds the upstream call.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_refusal_status_tests).
-include_lib("eunit/include/eunit.hrl").
-include("../src/yuzu_grpc.hrl").

-define(ENV_KEYS, [upstream_register_concurrency, upstream_register_queue_max,
                   circuit_breaker_failure_threshold, circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms, upstream_call_timeout_ms]).

refusal_status_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{timeout, 30, {"Register with the breaker open is UNAVAILABLE",
                     fun register_circuit_open_is_unavailable/0}},
      {timeout, 30, {"inventory with the breaker open is UNAVAILABLE",
                     fun inventory_circuit_open_is_unavailable/0}},
      {timeout, 30, {"Register refused by a full permit queue is UNAVAILABLE",
                     fun register_overloaded_is_unavailable/0}},
      {timeout, 30, {"the agent's grpc-timeout bounds the upstream Register",
                     fun register_carries_the_agent_deadline/0}}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_registry:ensure(),
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    Prev.

cleanup(Prev) ->
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

register_circuit_open_is_unavailable() ->
    trip(),
    ?assertMatch({grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}},
                 yuzu_gw_agent_service:register(ctx(#{}), req(<<"a1">>))).

inventory_circuit_open_is_unavailable() ->
    trip(),
    ?assertMatch({grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}},
                 yuzu_gw_agent_service:report_inventory(ctx(#{}), #{agent_id => <<"a1">>})).

register_overloaded_is_unavailable() ->
    application:set_env(yuzu_gw, upstream_register_concurrency, 1),
    application:set_env(yuzu_gw, upstream_register_queue_max, 0),
    Test = self(),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_, _, _, _, _) ->
                         Test ! {held, self()},
                         receive go -> ok after 10000 -> ok end,
                         {ok, #{session_id => <<"s">>}, #{}}
                     end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    _ = spawn(fun() -> yuzu_gw_upstream:proxy_register(req(<<"hold">>)) end),
    Rpc = receive {held, P} -> P after 5000 -> error(no_hold) end,
    ?assertMatch({grpc_error, {?GRPC_STATUS_UNAVAILABLE, _}},
                 yuzu_gw_agent_service:register(ctx(#{}), req(<<"a2">>))),
    Rpc ! go.

register_carries_the_agent_deadline() ->
    Test = self(),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_, _, _, _, Opts) ->
                         Test ! {opts, Opts},
                         {ok, #{session_id => <<"s-deadline">>}, #{}}
                     end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    _ = yuzu_gw_agent_service:register(ctx(#{<<"grpc-timeout">> => <<"900m">>}), req(<<"a3">>)),
    Opts = receive {opts, O} -> O after 5000 -> error(no_rpc) end,
    ?assert(maps:get(timeout, Opts) < 900).

%%--------------------------------------------------------------------

trip() ->
    yuzu_gw_test_upstream:set_breaker_env(1),
    ok = meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, econnrefused} end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    yuzu_gw_test_upstream:trip_breaker(req(<<"trip">>), 1).

req(Id) -> #{info => #{agent_id => Id}}.

ctx(Headers) ->
    yuzu_grpc:new_ctx(Headers, self(), {{127, 0, 0, 1}, 1}, {{127, 0, 0, 1}, transport}, undefined).
