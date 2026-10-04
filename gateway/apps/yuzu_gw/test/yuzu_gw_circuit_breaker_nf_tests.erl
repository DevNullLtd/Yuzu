%%%-------------------------------------------------------------------
%%% @doc Non-functional EUnit tests for C3: circuit breaker
%%% exponential backoff, concurrency, throughput, and telemetry.
%%%
%%% Covers:
%%%   - Backoff timeout doubles on each reopen
%%%   - Backoff is capped at max_reset_timeout
%%%   - Concurrent RPCs during state transitions are safe
%%%   - Rejection throughput when circuit is open
%%%   - Telemetry events emitted on state transitions
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_circuit_breaker_nf_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — foreach restarts upstream between tests
%%%===================================================================

circuit_breaker_nf_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"backoff doubles on each reopen cycle",
       {timeout, 10, fun backoff_doubles/0}},
      {"backoff is capped at max_reset_timeout",
       {timeout, 10, fun backoff_capped/0}},
      {"concurrent RPCs during open state are all rejected",
       {timeout, 10, fun concurrent_rejection/0}},
      {"concurrent RPCs during half_open allow exactly one probe",
       {timeout, 10, fun concurrent_half_open_probe/0}},
      {"open circuit rejection throughput",
       {timeout, 10, fun rejection_throughput/0}},
      {"telemetry emitted on open transition",
       fun telemetry_on_open/0},
      {"telemetry emitted on half_open transition",
       {timeout, 5, fun telemetry_on_half_open/0}},
      {"telemetry emitted on close after probe",
       {timeout, 5, fun telemetry_on_close/0}},
      {"failure counter resets on success",
       fun failure_counter_resets/0}
     ]}.

setup() ->
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    %% Capture telemetry calls for later inspection via meck:history.
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_EventName, _Measurements, _Metadata) ->
        ok
    end),
    %% Low thresholds and short timeouts for fast testing.
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 100),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 500),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Old -> catch unlink(Old), catch gen_server:stop(Old, shutdown, 1000)
    end,
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    Pid.

cleanup(Pid) ->
    %% Synchronous stop. exit(Pid, shutdown) + sleep(50) was racy on busy
    %% boxes (WSL2 in particular) and leaked the upstream into the next
    %% test module's setup — see issue #336.
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
%% yuzu_gw_upstream. On a loaded runner the timer can fire late, its message can
%% queue behind this test's circuit_state call, or the test process itself can
%% be descheduled for 100ms+ (BigMags shares one box's CPU between two agents,
%% and macOS coalesces background timers). On macOS CI (#4841) that broke fixed
%% sleeps in BOTH directions: "half_open by now" (an upper bound; run
%% 35879401664) and "still open at N ms" (a lower bound; run 35894938773).
%% So these tests do not time the backoff at all. They:
%%   - read the backoff AMOUNT from the breaker's own state (check_backoff/2).
%%     trip_circuit/1 schedules send_after(CurTimeout) and stores
%%     min(2 * CurTimeout, MaxTimeout) as the next one, which is exactly the
%%     doubling-and-cap behaviour under test, and it is deterministic;
%%   - check the timer was scheduled with (at most) the expected delay:
%%     erlang:read_timer/1 on the breaker's timer must be `false` (already
%%     fired) or =< the expected ms. A late test process can only LOWER the
%%     remaining time, so this upper bound cannot flake. It rejects scheduling
%%     the next value (or an uncapped 800ms), but NOT a too-SHORT delay (e.g.
%%     always the base 100ms). Proving that would need a lower bound, which is
%%     the wall-clock race this rewrite removes. That residual gap is accepted;
%%   - prove the timer actually drives open -> half_open by polling for it with
%%     a generous deadline (await_state/1). That wait checks "it happens", not
%%     how long it took.
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

%% Right after a trip: the breaker scheduled `ScheduledMs` and stores `NextMs`
%% as the backoff the NEXT trip will use (#state.cb_cur_timeout). The record is
%% private to yuzu_gw_upstream, so it is read by position. The size, the tag,
%% and the base/max fields pinned to setup/0's 100/500 make a record change fail
%% loudly as "record changed" rather than as an apparent backoff bug.
check_backoff(ScheduledMs, NextMs) ->
    S = sys:get_state(yuzu_gw_upstream),
    %% #state{} = {state, notify_pids, cb_state, cb_failures, cb_threshold,
    %%   cb_base_timeout, cb_max_timeout, cb_cur_timeout, cb_timer,
    %%   replay_spacing, replay_queue, guardian_pids, cluster_id}
    ?assertMatch({13, state, 100, 500},
                 {tuple_size(S), element(1, S), element(6, S), element(7, S)}),
    ?assert(lists:member(element(3, S), [closed, open, half_open])),
    ?assertEqual(NextMs, element(8, S)),
    case element(9, S) of
        TRef when is_reference(TRef) ->
            case erlang:read_timer(TRef) of
                false -> ok;   % already fired
                Remaining -> ?assert(Remaining =< ScheduledMs)
            end;
        undefined ->
            ok                 % already fired and handled (half_open)
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

backoff_doubles() ->
    %% Cycle 1: trip. It schedules the 100ms base and stores 200ms as the next.
    trip_circuit(),
    check_backoff(100, 200),
    ?assertEqual(half_open, await_state(half_open)),

    %% Probe fails -> reopens with 200ms, next doubles to 400ms.
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    check_backoff(200, 400),
    ?assertEqual(half_open, await_state(half_open)),

    %% Probe fails again -> reopens with 400ms; the next doubling (800ms) is
    %% capped at max_reset_timeout (500ms in setup/0).
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    check_backoff(400, 500),
    ?assertEqual(half_open, await_state(half_open)).

backoff_capped() ->
    %% Max timeout is 500ms (setup/0). The stored next backoff must go
    %% 200 -> 400 -> 500 (capped, not 800) -> 500 (stays capped).

    %% Cycle 1: trip (schedules 100ms).
    trip_circuit(),
    check_backoff(100, 200),
    ?assertEqual(half_open, await_state(half_open)),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),

    %% Cycle 2: reopened with 200ms.
    check_backoff(200, 400),
    ?assertEqual(half_open, await_state(half_open)),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),

    %% Cycle 3: reopened with 400ms; the next is capped at 500, not 800.
    check_backoff(400, 500),
    ?assertEqual(half_open, await_state(half_open)),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),

    %% Cycle 4: reopened with the capped 500ms; the next stays 500.
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    check_backoff(500, 500),
    ?assertEqual(half_open, await_state(half_open)).

concurrent_rejection() ->
    trip_circuit(),
    meck:reset(grpcbox_client),

    %% Fire 100 concurrent RPCs. All should be rejected.
    Self = self(),
    N = 100,
    _Workers = [spawn_link(fun() ->
        Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
        Self ! {rpc_result, I, Result}
    end) || I <- lists:seq(1, N)],

    Results = [receive
        {rpc_result, I, R} -> R
    after 5000 ->
        {error, timeout}
    end || I <- lists:seq(1, N)],

    %% All should be circuit_open.
    CircuitOpenCount = length([R || R <- Results, R =:= {error, circuit_open}]),
    ?assertEqual(N, CircuitOpenCount),

    %% grpcbox should NOT have been called at all.
    ?assertEqual(0, meck:num_calls(grpcbox_client, unary, '_')).

concurrent_half_open_probe() ->
    trip_circuit(),
    ?assertEqual(half_open, await_state(half_open)),

    %% Make grpcbox succeed but add a small delay to simulate real RPC.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        timer:sleep(10),
        {ok, #{session_id => <<"probe">>}, #{}}
    end),

    %% Fire 10 concurrent RPCs. In half_open, only the probe is allowed
    %% through; any RPCs that arrive after the first succeeds should
    %% pass through in the now-closed state.
    Self = self(),
    N = 10,
    _Workers = [spawn_link(fun() ->
        Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
        Self ! {probe_result, I, Result}
    end) || I <- lists:seq(1, N)],

    Results = [receive
        {probe_result, I, R} -> R
    after 5000 ->
        {error, timeout}
    end || I <- lists:seq(1, N)],

    %% No errors should remain — the first probe closes the circuit,
    %% then subsequent RPCs pass through in closed state.
    %% (gen_server serialises calls, so they go one at a time.)
    Successes = length([R || {ok, _} = R <- Results]),
    ?assertEqual(N, Successes).

rejection_throughput() ->
    trip_circuit(),
    meck:reset(grpcbox_client),

    %% Measure how fast we can reject 10,000 RPCs.
    N = 10000,
    {TimeUs, _} = timer:tc(fun() ->
        lists:foreach(fun(_) ->
            {error, circuit_open} = yuzu_gw_upstream:proxy_register(#{info => #{}})
        end, lists:seq(1, N))
    end),

    TimeMs = TimeUs / 1000,
    %% 10K gen_server call roundtrips should complete in < 5 seconds.
    ?assert(TimeMs < 5000),

    %% grpcbox should not have been called.
    ?assertEqual(0, meck:num_calls(grpcbox_client, unary, '_')).

telemetry_on_open() ->
    meck:reset(telemetry),
    trip_circuit(),
    %% Check meck history for a circuit_state event with state=open.
    ?assert(has_telemetry_state(<<"open">>)).

telemetry_on_half_open() ->
    meck:reset(telemetry),
    trip_circuit(),
    %% Wait for the half_open timer to fire.
    ?assertEqual(half_open, await_state(half_open)),
    ?assert(has_telemetry_state(<<"half_open">>)).

telemetry_on_close() ->
    meck:reset(telemetry),
    trip_circuit(),
    ?assertEqual(half_open, await_state(half_open)),
    %% Probe succeeds -> close.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"ok">>}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assert(has_telemetry_state(<<"closed">>)).

failure_counter_resets() ->
    %% 2 failures, then a success, then 2 more failures.
    %% Should NOT trip because the success reset the counter.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),

    %% Success resets counter.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),

    %% 2 more failures — still closed (threshold is 3).
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

%%%===================================================================
%%% Telemetry helpers
%%%===================================================================

%% @doc Check meck:history(telemetry) for a circuit_state event with
%% the given state label.
has_telemetry_state(ExpectedState) ->
    History = meck:history(telemetry),
    lists:any(fun
        ({_Pid, {telemetry, execute,
                 [[yuzu, gw, upstream, circuit_state],
                  #{count := 1},
                  #{state := State}]}, ok}) ->
            State =:= ExpectedState;
        (_) ->
            false
    end, History).
