%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the Guardian drift-event forward DROP path in
%%% yuzu_gw_upstream (M3, PR #1220 review).
%%%
%%% forward_guardian_message/2 is best-effort: it drops the message — and emits
%%% drop telemetry — when the circuit is open (upstream known-down) or the
%%% dedicated in-flight budget (MAX_GUARDIAN_INFLIGHT) is full. A dropped push
%%% silently leaves an endpoint's guard un-updated, so the drop counters are the
%%% only signal an operator has; they must actually move. The existing gateway
%%% tests cover classification + wire round-trip but not these branches.
%%%
%%% Asserts the accepted/dropped telemetry deltas via meck history:
%%%   - circuit open  -> forward_dropped{reason=circuit_open}, no forward_accepted
%%%   - circuit closed -> forward_accepted, no forward_dropped
%%%   - in-flight full -> forward_dropped{reason=at_capacity}
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_guardian_forward_tests).
-include_lib("eunit/include/eunit.hrl").

%% Mirror of the source's dedicated cap (yuzu_gw_upstream.erl ?MAX_GUARDIAN_INFLIGHT).
-define(MAX_GUARDIAN_INFLIGHT, 50).

guardian_forward_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"circuit open drops with reason=circuit_open", fun drop_circuit_open/0},
      {"closed circuit accepts and counts", fun accept_when_closed/0},
      {"full in-flight budget drops with reason=at_capacity", fun drop_at_capacity/0}
     ]}.

setup() ->
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(telemetry),
    meck:new(yuzu_grpc_client, [non_strict, no_link]),
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {ok, #{}, #{}} end),
    %% passthrough + a recording stub so meck:history captures every execute/3.
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 200),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Old -> catch unlink(Old), catch gen_server:stop(Old, shutdown, 1000)
    end,
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    Pid.

cleanup(Pid) ->
    catch unlink(Pid),
    catch gen_server:stop(Pid, shutdown, 5000),
    meck:unload([yuzu_grpc_client, telemetry]),
    ok.

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Count guardian forward telemetry calls of a given event suffix and (optional)
%% reason from meck history. `Reason = any` ignores the reason metadata.
count_forward(EventSuffix, Reason) ->
    Event = [yuzu, gw, guardian, EventSuffix],
    length([1 || {_Pid, {telemetry, execute, [E, _Meas, Meta]}, _Ret}
                     <- meck:history(telemetry),
                 E =:= Event,
                 Reason =:= any orelse maps:get(reason, Meta, undefined) =:= Reason]).

%% A barrier: a synchronous call flushes the gen_server's mailbox, so any cast
%% issued before it has been fully handled (and its synchronous telemetry emitted)
%% by the time the call returns.
barrier() -> _ = yuzu_gw_upstream:circuit_state().

trip_circuit_open() ->
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, connection_refused} end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%%%===================================================================
%%% Tests
%%%===================================================================

drop_circuit_open() ->
    trip_circuit_open(),
    meck:reset(telemetry), % discard the circuit-breaker telemetry from tripping
    yuzu_gw_upstream:forward_guardian_message(<<"agent-1">>, #{}),
    barrier(),
    ?assertEqual(1, count_forward(forward_dropped, <<"circuit_open">>)),
    ?assertEqual(0, count_forward(forward_accepted, any)).

accept_when_closed() ->
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    meck:reset(telemetry),
    yuzu_gw_upstream:forward_guardian_message(<<"agent-1">>, #{}),
    barrier(),
    ?assertEqual(1, count_forward(forward_accepted, any)),
    ?assertEqual(0, count_forward(forward_dropped, any)),
    %% Let the spawned forward complete before cleanup unloads the mocks (avoids
    %% the #336 cross-module mock-pollution class).
    timer:sleep(50).

drop_at_capacity() ->
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    %% Make every accepted forward's RPC linger briefly so its monitored process
    %% stays in guardian_pids — fills the in-flight budget without tripping the
    %% circuit. The sleep is short enough that all MAX+1 casts are issued while the
    %% earlier ones are still in flight.
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
        timer:sleep(300),
        {ok, #{}, #{}}
    end),
    meck:reset(telemetry),
    [yuzu_gw_upstream:forward_guardian_message(<<"agent">>, #{})
     || _ <- lists:seq(1, ?MAX_GUARDIAN_INFLIGHT)],
    barrier(),
    %% All MAX should have been accepted; none dropped yet.
    ?assertEqual(?MAX_GUARDIAN_INFLIGHT, count_forward(forward_accepted, any)),
    ?assertEqual(0, count_forward(forward_dropped, any)),
    %% One more while the budget is full -> dropped with reason=at_capacity.
    yuzu_gw_upstream:forward_guardian_message(<<"agent-over">>, #{}),
    barrier(),
    ?assertEqual(1, count_forward(forward_dropped, <<"at_capacity">>)),
    %% Drain the lingering forwards before cleanup unloads the mocks.
    timer:sleep(400).
