%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_gauge — scheduler utilization and
%%% periodic gauge emission.
%%%
%%% Tests the pure computation functions and verifies the gen_server
%%% emits telemetry events on tick.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_gauge_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Scheduler utilization computation tests
%%%===================================================================

scheduler_util_basic_test() ->
    %% Two schedulers, each 20% busy.
    Prev = [{1, 100, 1000}, {2, 200, 1000}],
    Curr = [{1, 300, 2000}, {2, 400, 2000}],
    %% Delta: Sched1: Active=200, Total=1000; Sched2: Active=200, Total=1000
    %% Aggregate: Active=400, Total=2000 → 0.2
    Util = yuzu_gw_gauge:compute_scheduler_util(Prev, Curr),
    ?assert(abs(Util - 0.2) < 0.001).

scheduler_util_full_load_test() ->
    Prev = [{1, 0, 0}],
    Curr = [{1, 1000, 1000}],
    Util = yuzu_gw_gauge:compute_scheduler_util(Prev, Curr),
    ?assert(abs(Util - 1.0) < 0.001).

scheduler_util_zero_delta_test() ->
    %% No change between snapshots → 0.0.
    Prev = [{1, 100, 1000}],
    Curr = [{1, 100, 1000}],
    Util = yuzu_gw_gauge:compute_scheduler_util(Prev, Curr),
    ?assertEqual(0.0, Util).

scheduler_util_new_id_ignored_test() ->
    %% A new scheduler appears in Curr that wasn't in Prev.
    %% It should be ignored (no delta computable).
    Prev = [{1, 100, 1000}],
    Curr = [{1, 300, 2000}, {2, 100, 1000}],
    %% Only scheduler 1 is compared: Active=200, Total=1000 → 0.2
    Util = yuzu_gw_gauge:compute_scheduler_util(Prev, Curr),
    ?assert(abs(Util - 0.2) < 0.001).

scheduler_util_mixed_load_test() ->
    %% Different utilization per scheduler.
    Prev = [{1, 0, 0}, {2, 0, 0}],
    Curr = [{1, 500, 1000}, {2, 100, 1000}],
    %% Total: Active=600, Total=2000 → 0.3
    Util = yuzu_gw_gauge:compute_scheduler_util(Prev, Curr),
    ?assert(abs(Util - 0.3) < 0.001).

scheduler_util_empty_test() ->
    Util = yuzu_gw_gauge:compute_scheduler_util([], []),
    ?assertEqual(0.0, Util).

%%%===================================================================
%%% gen_server tick test (with mocked telemetry + registry)
%%%===================================================================

gauge_tick_test_() ->
    {setup,
     fun tick_setup/0,
     fun tick_cleanup/1,
     [{"tick emits agent count event", fun tick_emits_agent_count/0},
      {"tick emits vm process count event", fun tick_emits_process_count/0}]}.

tick_setup() ->
    %% pg + a real registry, race-safe across modules (#1403 / #336).
    yuzu_gw_test_registry:ensure(),
    %% Use ETS to collect telemetry events (EUnit runs setup and tests
    %% in different processes, so mailbox messaging won't work).
    catch ets:delete(gauge_test_events),
    ets:new(gauge_test_events, [named_table, bag, public]),
    catch meck:unload(telemetry),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(EventName, Measurements, Meta) ->
        ets:insert(gauge_test_events, {EventName, Measurements, Meta}),
        ok
    end),
    %% Set a short gauge interval.
    application:set_env(yuzu_gw, telemetry_gauge_interval_ms, 50),
    {ok, Pid} = yuzu_gw_gauge:start_link(),
    Pid.

tick_cleanup(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    timer:sleep(50),
    meck:unload(telemetry),
    ets:delete(gauge_test_events).

tick_emits_agent_count() ->
    %% Wait for at least one tick.
    Found = await_event([yuzu, gw, agent, count]),
    ?assert(length(Found) > 0),
    [{_, #{count := Count}, _} | _] = Found,
    ?assert(is_integer(Count)).

tick_emits_process_count() ->
    Found = await_event([yuzu, gw, vm, process_count]),
    ?assert(length(Found) > 0),
    [{_, #{count := Count}, _} | _] = Found,
    ?assert(Count > 0).

%% Poll for a telemetry event the gauge's tick records, instead of sleeping a
%% fixed 150ms and checking once. The tick is an erlang:send_after (50ms here),
%% and its first act is a synchronous yuzu_gw_registry:agent_count/0 call. Its
%% telemetry:execute also goes through the meck proxy. On a loaded runner, any
%% of these can push the first event past 150ms: that failed on macOS CI
%% (#4841; BigMags shares its CPU between two agents). These tests only claim
%% "a tick emitted the event", so a generous deadline changes nothing they
%% assert.
await_event(Name) ->
    await_event(Name, erlang:monotonic_time(millisecond) + 2000).

await_event(Name, Deadline) ->
    case ets:lookup(gauge_test_events, Name) of
        [] ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> [];
                false -> timer:sleep(10), await_event(Name, Deadline)
            end;
        Found ->
            Found
    end.
