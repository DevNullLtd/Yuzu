%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the upstream circuit breaker.
%%%
%%% Tests the closed -> open -> half_open -> closed state machine,
%%% exponential backoff, and immediate rejection when open.
%%%
%%% Each test gets a fresh upstream process to ensure isolation.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_circuit_breaker_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — foreach restarts upstream between tests
%%%===================================================================

circuit_breaker_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"starts in closed state", fun starts_closed/0},
      {"stays closed on success", fun stays_closed_on_success/0},
      {"opens after threshold failures", fun opens_after_threshold/0},
      {"rejects immediately when open", fun rejects_when_open/0},
      {"transitions to half_open after timeout", fun transitions_to_half_open/0},
      {"closes on successful probe", fun closes_on_probe_success/0},
      {"reopens on failed probe", fun reopens_on_probe_failure/0}
     ]}.

setup() ->
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    %% Low threshold for fast testing
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
    %% Synchronous stop — see issue #336 for the race exit/sleep replaces.
    catch unlink(Pid),
    catch gen_server:stop(Pid, shutdown, 5000),
    meck:unload([grpcbox_client, telemetry]),
    ok.

%%%===================================================================
%%% Helper — trip the circuit to open state
%%%===================================================================

trip_circuit() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%% The open -> half_open transition is driven by an erlang:send_after timer in
%% yuzu_gw_upstream (the 200ms reset timeout set in setup), so on a loaded
%% runner the timer can fire late, or its message can queue behind this test's
%% circuit_state call. A fixed `timer:sleep(350)` then `half_open` check is an
%% UPPER-bound race of the kind that flaked on the first macOS CI runs (#4841,
%% #4851; BigMags shares its CPU between two agents, and macOS coalesces
%% background timers). Poll every 10ms up to a 2s deadline instead. These tests
%% only claim the transition happens, not when, so the deadline changes
%% nothing they assert (the backoff AMOUNTS are pinned in
%% yuzu_gw_circuit_breaker_nf_tests).
await_state(Want) ->
    poll_state(Want, erlang:monotonic_time(millisecond) + 2000).

poll_state(Want, Deadline) ->
    case yuzu_gw_upstream:circuit_state() of
        Want -> Want;
        Other ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> Other;
                false -> timer:sleep(10), poll_state(Want, Deadline)
            end
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

starts_closed() ->
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

stays_closed_on_success() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"s1">>}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

opens_after_threshold() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    %% Failures 1 and 2 — still closed
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    %% Failure 3 — trips to open
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

rejects_when_open() ->
    trip_circuit(),
    %% Now calls should be rejected immediately without hitting grpcbox
    meck:reset(grpcbox_client),
    Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual({error, circuit_open}, Result),
    %% Verify grpcbox was NOT called
    ?assertEqual(0, meck:num_calls(grpcbox_client, unary, '_')).

transitions_to_half_open() ->
    trip_circuit(),
    %% Wait for the timer-driven half_open (200ms reset timeout).
    ?assertEqual(half_open, await_state(half_open)).

closes_on_probe_success() ->
    trip_circuit(),
    %% Wait for the timer-driven half_open.
    ?assertEqual(half_open, await_state(half_open)),
    %% Make the probe succeed
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"recovered">>}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

reopens_on_probe_failure() ->
    trip_circuit(),
    %% Wait for the timer-driven half_open.
    ?assertEqual(half_open, await_state(half_open)),
    %% Probe fails — should reopen
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).
