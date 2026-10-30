%%%-------------------------------------------------------------------
%%% @doc yuzu_gw_mem_reclaim: when a pass runs (the drop rule, min_gap_ms,
%%% the follow-up pass, enabled => false), what a pass does (collects the
%%% large processes; trims or reports why not), and that a failing count
%%% function or a bad configuration value never crashes the server.
%%%
%%% Every test starts its own server with interval_ms and trim_interval_ms
%%% out of reach and drives it by sending `tick' itself, then synchronises on
%%% sys:get_state/1, so nothing waits on a timer except the follow-up test,
%%% which waits (bounded) for the one timer it is about.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mem_reclaim_tests).
-include_lib("eunit/include/eunit.hrl").

-define(NAME, yuzu_gw_mem_reclaim).
-define(OPTS, #{drop_fraction => 0.25, min_drop => 1000}).

%%%===================================================================
%%% decide/3 and validate/1: pure
%%%===================================================================

decide_test_() ->
    D = fun(N, Peak) -> yuzu_gw_mem_reclaim:decide(N, Peak, ?OPTS) end,
    [?_assertEqual(wait, D(0, 0)),
     ?_assertEqual(wait, D(100000, 100000)),
     %% a quarter of the peak but under min_drop
     ?_assertEqual(wait, D(1500, 2000)),
     %% min_drop but under a quarter
     ?_assertEqual(wait, D(95000, 100000)),
     ?_assertEqual(reclaim, D(70000, 100000)),
     ?_assertEqual(reclaim, D(0, 4000))].

validate_test_() ->
    V = fun yuzu_gw_mem_reclaim:validate/1,
    Defaults = V(#{}),
    [?_assertEqual(10000, maps:get(interval_ms, Defaults)),
     ?_assertEqual(30000, maps:get(followup_ms, Defaults)),
     ?_assertEqual(true, maps:get(enabled, Defaults)),
     ?_assertEqual(5000, maps:get(interval_ms, V(#{interval_ms => 5000}))),
     %% invalid values keep the default
     ?_assertEqual(10000, maps:get(interval_ms, V(#{interval_ms => 0}))),
     ?_assertEqual(10000, maps:get(interval_ms, V(#{interval_ms => "10"}))),
     ?_assertEqual(0.25, maps:get(drop_fraction, V(#{drop_fraction => 1.5}))),
     ?_assertEqual(1000, maps:get(min_drop, V(#{min_drop => -1}))),
     ?_assertEqual(true, maps:get(trim, V(#{trim => yes}))),
     ?_assert(is_function(maps:get(count_fun, V(#{count_fun => fun(_) -> 0 end})), 0)),
     %% an unknown key is dropped, a non-map gives the defaults
     ?_assertNot(is_map_key(bogus, V(#{bogus => 1}))),
     ?_assertEqual(maps:keys(Defaults), maps:keys(V(not_a_map)))].

%%%===================================================================
%%% The server
%%%===================================================================

server_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun drop_runs_a_pass_and_a_followup/1,
      fun min_gap_holds_back_a_second_pass/1,
      fun ordinary_churn_runs_no_pass/1,
      fun raising_count_fun_keeps_the_peak/1,
      fun non_integer_count_is_a_count_error/1,
      fun pass_collects_large_processes/1,
      fun trim_disabled/1]}.

setup() ->
    stop_named(),
    atomics:new(1, [{signed, true}]).

cleanup(_Counter) ->
    %% Looked up now, not remembered from setup (#336).
    stop_named().

stop_named() ->
    case whereis(?NAME) of
        undefined -> ok;
        Pid ->
            unlink(Pid),
            gen_server:stop(Pid, shutdown, 5000)
    end.

%% A count function reading the atomics cell: -1 raises, -2 is not an integer.
start(Counter, Opts) ->
    CountFun = fun() ->
                       case atomics:get(Counter, 1) of
                           -1 -> error(count_broken);
                           -2 -> not_a_count;
                           N -> N
                       end
               end,
    {ok, Pid} = yuzu_gw_mem_reclaim:start_link(
                  maps:merge(#{interval_ms => 3600000, trim_interval_ms => 0,
                               followup_ms => 0, min_gap_ms => 0,
                               count_fun => CountFun}, Opts)),
    unlink(Pid),
    Pid.

tick(Pid, Counter, N) ->
    atomics:put(Counter, 1, N),
    Pid ! tick,
    _ = sys:get_state(Pid),
    yuzu_gw_mem_reclaim:stats().

drop_runs_a_pass_and_a_followup(Counter) ->
    Pid = start(Counter, #{followup_ms => 50}),
    S1 = tick(Pid, Counter, 5000),
    S2 = tick(Pid, Counter, 0),
    S3 = wait_reclaims(2, 5000),
    [?_assertMatch(#{reclaims := 0, peak := 5000}, S1),
     ?_assertMatch(#{reclaims := 1, peak := 0,
                     last_result := #{agents := 0}}, S2),
     ?_assertMatch(#{reclaims := 2, peak := 0}, S3)].

min_gap_holds_back_a_second_pass(Counter) ->
    Pid = start(Counter, #{min_gap_ms => 3600000}),
    _ = tick(Pid, Counter, 5000),
    S1 = tick(Pid, Counter, 0),
    _ = tick(Pid, Counter, 5000),
    S2 = tick(Pid, Counter, 0),
    %% the second drop is held back; the peak it is measured from is kept
    [?_assertMatch(#{reclaims := 1}, S1),
     ?_assertMatch(#{reclaims := 1, peak := 5000}, S2)].

ordinary_churn_runs_no_pass(Counter) ->
    Pid = start(Counter, #{}),
    _ = tick(Pid, Counter, 100000),
    S = tick(Pid, Counter, 95000),
    [?_assertMatch(#{reclaims := 0, peak := 100000}, S)].

raising_count_fun_keeps_the_peak(Counter) ->
    Pid = start(Counter, #{}),
    _ = tick(Pid, Counter, 5000),
    S1 = tick(Pid, Counter, -1),
    S2 = tick(Pid, Counter, -1),
    %% a raising count is not a drop to 0: no pass, the peak is kept
    [?_assert(is_process_alive(Pid)),
     ?_assertMatch(#{reclaims := 0, peak := 5000, count_errors := 1}, S1),
     ?_assertMatch(#{reclaims := 0, peak := 5000, count_errors := 2}, S2)].

non_integer_count_is_a_count_error(Counter) ->
    Pid = start(Counter, #{}),
    _ = tick(Pid, Counter, 5000),
    S = tick(Pid, Counter, -2),
    %% reclaim_now still collects, reports agents as undefined, keeps the peak
    R = yuzu_gw_mem_reclaim:reclaim_now(),
    [?_assertMatch(#{reclaims := 0, peak := 5000, count_errors := 1}, S),
     ?_assertMatch(#{agents := undefined}, R),
     ?_assertMatch(#{reclaims := 1, peak := 5000, count_errors := 2},
                   yuzu_gw_mem_reclaim:stats())].

pass_collects_large_processes(Counter) ->
    Self = self(),
    %% a process left holding a few MB of garbage
    Big = spawn(fun() -> _ = lists:seq(1, 200000), Self ! grown,
                         receive stop -> ok end end),
    receive grown -> ok end,
    {memory, Before} = erlang:process_info(Big, memory),
    _ = start(Counter, #{gc_min_bytes => 65536}),
    atomics:put(Counter, 1, 7),
    R = yuzu_gw_mem_reclaim:reclaim_now(),
    {memory, After} = erlang:process_info(Big, memory),
    Big ! stop,
    [?_assert(Before > 1000000),
     ?_assert(After < Before div 4),
     ?_assertMatch(#{agents := 7, gc_processes := N} when N >= 1, R),
     ?_assert(lists:member(maps:get(trim, R), [0, 1, unsupported, nif_not_loaded])),
     ?_assertMatch(#{reclaims := 1, peak := 7}, yuzu_gw_mem_reclaim:stats())].

trim_disabled(Counter) ->
    _ = start(Counter, #{trim => false}),
    R = yuzu_gw_mem_reclaim:reclaim_now(),
    [?_assertMatch(#{trim := disabled}, R),
     ?_assertMatch(#{trims := 0, trim_warned := false}, yuzu_gw_mem_reclaim:stats())].

%% enabled => false arms no timer: with a 10 ms interval, an enabled server
%% would call its count function within the window.
disabled_arms_no_timer_test() ->
    stop_named(),
    Self = self(),
    {ok, Pid} = yuzu_gw_mem_reclaim:start_link(
                  #{enabled => false, interval_ms => 10, trim_interval_ms => 10,
                    count_fun => fun() -> Self ! counted, 0 end}),
    unlink(Pid),
    try
        Counted = receive counted -> true after 300 -> false end,
        ?assertNot(Counted),
        ?assertMatch(#{reclaims := 0, trims := 0}, yuzu_gw_mem_reclaim:stats())
    after
        stop_named()
    end.

%% The control for the test above: the same server enabled does count.
enabled_counts_test() ->
    stop_named(),
    Self = self(),
    {ok, Pid} = yuzu_gw_mem_reclaim:start_link(
                  #{interval_ms => 10, trim_interval_ms => 0,
                    count_fun => fun() -> Self ! counted, 0 end}),
    unlink(Pid),
    try
        ?assert(receive counted -> true after 5000 -> false end)
    after
        stop_named(),
        flush_counted()
    end.

flush_counted() ->
    receive counted -> flush_counted() after 0 -> ok end.

wait_reclaims(N, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_reclaims_until(N, Deadline).

wait_reclaims_until(N, Deadline) ->
    S = yuzu_gw_mem_reclaim:stats(),
    case maps:get(reclaims, S) >= N orelse erlang:monotonic_time(millisecond) > Deadline of
        true -> S;
        false -> timer:sleep(10), wait_reclaims_until(N, Deadline)
    end.
