%%%-------------------------------------------------------------------
%%% @doc The slow-server definition of yuzu_gw_upstream_pressure, and the
%%% lock-free lane read of yuzu_gw_upstream it rests on.
%%%
%%% The first half drives the accounting with synthetic samples and a synthetic
%%% clock, so every threshold is tested at its boundary and no test waits. The
%%% second half runs a real yuzu_gw_upstream whose RPC is a mocked
%%% yuzu_grpc_client:unary/5 that blocks until released, which is a slow server
%%% as far as the process can tell.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_pressure_tests).
-include_lib("eunit/include/eunit.hrl").

-define(P, yuzu_gw_upstream_pressure).
-define(WAIT_MS, 3000).
%% A whole second, so a run of whole seconds fills whole buckets.
-define(T0, 10000000).

%%--------------------------------------------------------------------
%% Which lane is saturated
%%--------------------------------------------------------------------

snap(Overrides) ->
    maps:merge(#{permit_waiting => 0, mailbox_len => 0,
                 notify_inflight => 0, notify_limit => 10,
                 guardian_inflight => 0, guardian_limit => 50}, Overrides).

none() -> #{permits => false, notify => false, guardian => false}.

a_process_that_is_not_running_saturates_nothing_test() ->
    ?assertEqual(none(), ?P:saturated(undefined)).

permits_need_a_caller_waiting_test_() ->
    S = fun(Waiting, Len) ->
            maps:get(permits, ?P:saturated(snap(#{permit_waiting => Waiting, mailbox_len => Len})))
        end,
    [{"nobody waiting for a permit", ?_assertEqual(false, S(0, 0))},
     {"messages in the upstream's mailbox are not callers waiting", ?_assertEqual(false, S(0, 5))},
     {"one caller waiting", ?_assertEqual(true, S(1, 0))},
     {"many waiting", ?_assertEqual(true, S(5000, 0))}].

worker_lanes_saturate_when_every_slot_is_held_test_() ->
    N = fun(Held) -> maps:get(notify, ?P:saturated(snap(#{notify_inflight => Held}))) end,
    G = fun(Held) -> maps:get(guardian, ?P:saturated(snap(#{guardian_inflight => Held}))) end,
    [{"notify one below the limit", ?_assertEqual(false, N(9))},
     {"notify at the limit: the next one would be dropped", ?_assertEqual(true, N(10))},
     {"guardian one below the limit", ?_assertEqual(false, G(49))},
     {"guardian at the limit", ?_assertEqual(true, G(50))},
     {"the lanes are independent",
      ?_assertEqual(#{permits => false, notify => true, guardian => false},
                    ?P:saturated(snap(#{notify_inflight => 10})))}].

%%--------------------------------------------------------------------
%% Crediting time
%%--------------------------------------------------------------------

sat(Lanes) -> maps:merge(none(), maps:from_list([{L, true} || L <- Lanes])).

%% Take samples every `Step' ms from `T0' (the first at `T0' itself) up to `Ms' ms, the lanes in `Lanes'
%% saturated while `Pred(OffsetMs)' holds. Returns {acc, last-time, summed deltas}.
run(Acc, T0, Ms, Step, Pred) ->
    lists:foldl(
      fun(Off, {A, _, Sum}) ->
              Sample = case Pred(Off) of
                           false -> none();
                           true  -> sat([permits]);
                           Lanes when is_list(Lanes) -> sat(Lanes)
                       end,
              {A1, D} = ?P:observe(A, T0 + Off, Sample),
              {A1, T0 + Off, maps:map(fun(K, V) -> V + maps:get(K, D) end, Sum)}
      end,
      {Acc, T0, #{any_ms => 0, permits_ms => 0, notify_ms => 0, guardian_ms => 0}},
      lists:seq(0, Ms, Step)).

nothing_is_credited_before_the_first_step_test() ->
    {_, D} = ?P:observe(?P:new(?T0), ?T0, sat([permits])),
    ?assertEqual(#{any_ms => 0, permits_ms => 0, notify_ms => 0, guardian_ms => 0}, D).

a_sample_is_held_until_the_next_one_test() ->
    A0 = ?P:new(?T0),
    {A1, _} = ?P:observe(A0, ?T0, sat([permits])),
    %% the saturated sample at T0 covers T0..T0+100
    {A2, D1} = ?P:observe(A1, ?T0 + 100, none()),
    ?assertMatch(#{any_ms := 100, permits_ms := 100, notify_ms := 0, guardian_ms := 0}, D1),
    %% the idle sample at T0+100 covers the next 100 ms: nothing
    {_, D2} = ?P:observe(A2, ?T0 + 200, none()),
    ?assertMatch(#{any_ms := 0, permits_ms := 0}, D2).

overlapping_lanes_are_credited_to_each_and_once_to_any_test() ->
    A0 = ?P:new(?T0),
    {A1, _} = ?P:observe(A0, ?T0, sat([permits, notify])),
    {_, D} = ?P:observe(A1, ?T0 + 500, none()),
    ?assertEqual(#{any_ms => 500, permits_ms => 500, notify_ms => 500, guardian_ms => 0}, D).

one_step_is_credited_at_most_a_second_test() ->
    %% A VM stopped for a minute must not credit a minute of backpressure.
    {A1, _} = ?P:observe(?P:new(?T0), ?T0, sat([permits])),
    {_, D} = ?P:observe(A1, ?T0 + 60000, none()),
    ?assertMatch(#{any_ms := 1000, permits_ms := 1000}, D).

a_clock_that_goes_back_credits_nothing_and_does_not_rewind_test() ->
    {A1, _} = ?P:observe(?P:new(?T0), ?T0 + 500, sat([permits])),
    {A2, D} = ?P:observe(A1, ?T0 + 100, sat([permits])),
    ?assertMatch(#{any_ms := 0}, D),
    %% the next forward step is measured from the latest time seen
    {_, D2} = ?P:observe(A2, ?T0 + 600, none()),
    ?assertMatch(#{any_ms := 100}, D2).

%%--------------------------------------------------------------------
%% The duty cycle and the slow-server threshold
%%--------------------------------------------------------------------

constants_are_the_documented_ones_test() ->
    ?assertEqual({100, 60, 0.5, [permits, notify, guardian]},
                 {?P:sample_ms(), ?P:window_s(), ?P:slow_threshold(), ?P:lanes()}).

slow_is_at_least_the_threshold_test_() ->
    [?_assertEqual(false, ?P:slow(0.0)),
     ?_assertEqual(false, ?P:slow(0.4999)),
     {"exactly the threshold is slow", ?_assertEqual(true, ?P:slow(0.5))},
     ?_assertEqual(true, ?P:slow(0.5001)),
     ?_assertEqual(true, ?P:slow(1.0))].

an_unloaded_path_has_a_zero_duty_cycle_test() ->
    {A, T, _} = run(?P:new(?T0), ?T0, 60000, 100, fun(_) -> false end),
    ?assertEqual(0.0, ?P:duty_cycle(A, T)),
    ?assertEqual(false, ?P:slow(?P:duty_cycle(A, T))).

half_a_minute_saturated_is_exactly_the_threshold_test() ->
    %% 30 s saturated then 30 s idle, sampled every 100 ms: 300 saturated
    %% intervals of 100 ms is 30 000 ms of the 60 000 ms window.
    {A, T, Sum} = run(?P:new(?T0), ?T0, 59900, 100, fun(Off) -> Off < 30000 end),
    ?assertEqual(30000, maps:get(any_ms, Sum)),
    ?assertEqual(0.5, ?P:duty_cycle(A, T)),
    ?assertEqual(true, ?P:slow(?P:duty_cycle(A, T))).

a_little_less_than_half_is_not_slow_test() ->
    %% 29.9 s saturated.
    {A, T, _} = run(?P:new(?T0), ?T0, 59900, 100, fun(Off) -> Off < 29900 end),
    ?assert(?P:duty_cycle(A, T) < 0.5),
    ?assertEqual(false, ?P:slow(?P:duty_cycle(A, T))).

a_saturated_path_all_minute_is_a_duty_cycle_of_one_and_never_more_test() ->
    {A, T, _} = run(?P:new(?T0), ?T0, 120000, 100, fun(_) -> true end),
    ?assert(?P:duty_cycle(A, T) =< 1.0),
    ?assert(?P:duty_cycle(A, T) >= 0.98).

the_window_forgets_test() ->
    %% A minute of saturation, then it stops: half a minute later the duty
    %% cycle has fallen to about a half, and a minute later it is zero.
    {A1, T1, _} = run(?P:new(?T0), ?T0, 60000, 100, fun(_) -> true end),
    ?assert(?P:duty_cycle(A1, T1) >= 0.98),
    {A2, T2, _} = run(A1, T1, 30000, 100, fun(_) -> false end),
    D2 = ?P:duty_cycle(A2, T2),
    ?assert(D2 > 0.45 andalso D2 < 0.55),
    {A3, T3, _} = run(A2, T2, 30000, 100, fun(_) -> false end),
    ?assertEqual(0.0, ?P:duty_cycle(A3, T3)).

old_seconds_do_not_count_even_if_not_pruned_test() ->
    %% duty_cycle/2 reads only the window, whatever the map still holds.
    {A, T, _} = run(?P:new(?T0), ?T0, 10000, 100, fun(_) -> true end),
    ?assert(?P:duty_cycle(A, T) > 0.1),
    ?assertEqual(0.0, ?P:duty_cycle(A, T + 120000)).

a_burst_inside_one_second_cannot_overfill_its_bucket_test() ->
    %% The interval ending in a second is credited to that second, so two steps
    %% that straddle a boundary can credit more than 1000 ms to one bucket.
    A0 = ?P:new(?T0 - 500),
    {A1, _} = ?P:observe(A0, ?T0 - 500, sat([permits])),
    {A2, _} = ?P:observe(A1, ?T0 + 400, sat([permits])),
    {A3, _} = ?P:observe(A2, ?T0 + 999, sat([permits])),
    ?assert(?P:duty_cycle(A3, ?T0 + 999) =< 1000 / 60000 + 1.0e-9).

lanes_overlap_so_the_whole_is_not_the_sum_test() ->
    %% permits and notify saturated for the same 30 s: each lane's credit is 30 s
    %% and so is the whole, not 60 s.
    {_, _, Sum} = run(?P:new(?T0), ?T0, 59900, 100,
                      fun(Off) -> case Off < 30000 of true -> [permits, notify]; false -> false end end),
    ?assertEqual(30000, maps:get(any_ms, Sum)),
    ?assertEqual(30000, maps:get(permits_ms, Sum)),
    ?assertEqual(30000, maps:get(notify_ms, Sum)),
    ?assertEqual(0, maps:get(guardian_ms, Sum)).

%%--------------------------------------------------------------------
%% A real upstream whose server does not answer
%%--------------------------------------------------------------------

-define(SINK, yuzu_gw_pressure_sink).
-define(BLOCKED, yuzu_gw_pressure_blocked).

process_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{"a Register waiting for a permit saturates the permits lane; freeing it clears the lane",
       {timeout, 30, fun permits_lane_follows_a_waiter/0}},
      {"every permit held with nobody waiting is not saturated",
       {timeout, 30, fun held_alone_is_not_saturated/0}},
      {"every notify slot held saturates the notify lane, and the next notification is held",
       {timeout, 30, fun notify_lane_saturates/0}},
      {"there is no snapshot when the process is not running",
       {timeout, 30, fun no_snapshot_without_a_process/0}},
      {"a restarted process does not inherit waiters from the one that died",
       {timeout, 30, fun restart_clears_the_lane/0}},
      {"the sampler emits the seconds and the duty cycle while the lane is saturated",
       {timeout, 30, fun sampler_emits/0}}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    stop_named(yuzu_gw_upstream_pressure),
    stop_named(yuzu_gw_upstream),
    %% One Register permit: the second Register waits for it.
    application:set_env(yuzu_gw, upstream_register_concurrency, 1),
    catch meck:unload(yuzu_grpc_client),
    catch ets:delete(?BLOCKED),
    ?BLOCKED = ets:new(?BLOCKED, [named_table, public, bag]),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, Path, Req, _Def, _Opts) ->
                         Id = case Req of
                                  #{enrollment := #{token := T}} -> T;
                                  _ -> none
                              end,
                         %% Recorded so cleanup/1 can end every process still
                         %% blocked in this mock before the mock is unloaded.
                         ets:insert(?BLOCKED, {blocked, self()}),
                         sink() ! {rpc, Path, Id, self()},
                         receive go -> {ok, #{}, #{}} after 10000 -> {error, timeout} end
                     end),
    #{}.

cleanup(_) ->
    stop_named(yuzu_gw_upstream_pressure),
    stop_named(yuzu_gw_upstream),
    application:unset_env(yuzu_gw, upstream_register_concurrency),
    [kill(P) || {blocked, P} <- ets:tab2list(?BLOCKED), is_process_alive(P)],
    catch ets:delete(?BLOCKED),
    catch meck:unload(yuzu_grpc_client),
    ok.

start_upstream() ->
    bind(),
    {ok, Up} = gen_server:start({local, yuzu_gw_upstream}, yuzu_gw_upstream, [], []),
    Up.

permits_lane_follows_a_waiter() ->
    _Up = start_upstream(),
    ?assertEqual(none(), ?P:saturated(yuzu_gw_upstream:lane_snapshot())),
    First = spawn_register(<<"hold-1">>),
    Worker = await_rpc(<<"hold-1">>),
    Second = spawn_register(<<"hold-2">>),
    await_snapshot(fun(#{permit_waiting := W}) -> W =:= 1 end),
    ?assertEqual(sat([permits]), ?P:saturated(yuzu_gw_upstream:lane_snapshot())),
    Worker ! go,
    %% the second call now holds the permit, with nobody behind it
    Worker2 = await_rpc(<<"hold-2">>),
    await_snapshot(fun(#{permit_waiting := W}) -> W =:= 0 end),
    ?assertEqual(none(), ?P:saturated(yuzu_gw_upstream:lane_snapshot())),
    Worker2 ! go,
    await_reply(First),
    await_reply(Second),
    ?assertEqual(none(), ?P:saturated(yuzu_gw_upstream:lane_snapshot())).

held_alone_is_not_saturated() ->
    _Up = start_upstream(),
    First = spawn_register(<<"hold-1">>),
    Worker = await_rpc(<<"hold-1">>),
    ?assertMatch(#{register := #{held := 1}}, yuzu_gw_upstream_regulator:snapshot()),
    ?assertMatch(#{permit_waiting := 0}, yuzu_gw_upstream:lane_snapshot()),
    ?assertEqual(none(), ?P:saturated(yuzu_gw_upstream:lane_snapshot())),
    Worker ! go,
    await_reply(First).

notify_lane_saturates() ->
    _Up = start_upstream(),
    Notify = fun(Id) ->
                 yuzu_gw_upstream:notify_stream_status(Id, <<"s">>, connected,
                                                       <<"127.0.0.1">>, <<"h">>)
             end,
    [Notify(<<"a", (integer_to_binary(I))/binary>>) || I <- lists:seq(1, 10)],
    %% each notification is an RPC in a process of its own, blocked in the mock
    Workers = [receive {rpc, _, none, W} -> W after ?WAIT_MS -> error(no_notify_rpc) end
               || _ <- lists:seq(1, 10)],
    await_snapshot(fun(#{notify_inflight := N}) -> N =:= 10 end),
    ?assertEqual(sat([notify]), ?P:saturated(yuzu_gw_upstream:lane_snapshot())),
    %% the permits lane is not involved: nobody waits for a permit
    ?assertMatch(#{permit_waiting := 0}, yuzu_gw_upstream:lane_snapshot()),
    %% the eleventh is held, not sent: no slot is free, and nothing is dropped
    Notify(<<"eleventh">>),
    ?assertMatch(#{notify_inflight := 10}, yuzu_gw_upstream:lane_snapshot()),
    receive {rpc, _, none, _} -> error(sent_without_a_free_slot) after 100 -> ok end,
    %% freeing the slots sends it
    [W ! go || W <- Workers],
    Last = receive {rpc, _, none, W11} -> W11 after ?WAIT_MS -> error(held_notification_not_sent) end,
    Last ! go,
    await_snapshot(fun(#{notify_inflight := N}) -> N =:= 0 end),
    ?assertEqual(none(), ?P:saturated(yuzu_gw_upstream:lane_snapshot())).

no_snapshot_without_a_process() ->
    ?assertEqual(undefined, yuzu_gw_upstream:lane_snapshot()).

%% The regulator belongs to the upstream process: killed with it, restarted with
%% it, with nothing held and nobody waiting.
restart_clears_the_lane() ->
    Up = start_upstream(),
    _Caller1 = spawn_register(<<"hold-1">>),
    _Worker = await_rpc(<<"hold-1">>),
    _Caller2 = spawn_register(<<"hold-2">>),
    await_snapshot(fun(#{permit_waiting := W}) -> W =:= 1 end),
    kill(Up),
    _ = start_upstream(),
    ?assertMatch(#{permit_waiting := 0, mailbox_len := 0, notify_inflight := 0},
                 yuzu_gw_upstream:lane_snapshot()).

sampler_emits() ->
    _Up = start_upstream(),
    Ids = [{?MODULE, backpressure}, {?MODULE, state}],
    ok = telemetry:attach(hd(Ids), [yuzu, gw, upstream, backpressure],
                          fun(_E, M, _Meta, _) -> sink() ! {bp, M} end, none),
    ok = telemetry:attach(lists:last(Ids), [yuzu, gw, upstream, backpressure_state],
                          fun(_E, M, _Meta, _) -> sink() ! {state, M} end, none),
    try
        _Caller1 = spawn_register(<<"hold-1">>),
        _Worker = await_rpc(<<"hold-1">>),
        _Caller2 = spawn_register(<<"hold-2">>),
        await_snapshot(fun(#{permit_waiting := W}) -> W =:= 1 end),
        {ok, _} = yuzu_gw_upstream_pressure:start_link(),
        %% The lane stays saturated, so within a few seconds the sampler credits
        %% time to it and reports a duty cycle above zero that is not yet slow.
        Bp = await_event(bp, fun(#{any_ms := Ms}) -> Ms > 0 end),
        ?assertMatch(#{any_ms := _, permits_ms := _, notify_ms := 0, guardian_ms := 0}, Bp),
        ?assert(maps:get(permits_ms, Bp) =:= maps:get(any_ms, Bp)),
        State = await_event(state, fun(#{duty_cycle := D}) -> D > 0.0 end),
        ?assertMatch(#{slow := 0}, State),
        ?assert(maps:get(duty_cycle, State) =< 1.0)
    after
        [telemetry:detach(I) || I <- Ids]
    end.

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

bind() ->
    catch unregister(?SINK),
    true = register(?SINK, self()),
    flush(),
    ok.

sink() -> whereis(?SINK).

spawn_register(Id) ->
    Test = self(),
    spawn(fun() ->
              Reply = yuzu_gw_upstream:proxy_register(#{enrollment => #{token => Id}}),
              Test ! {reply, self(), Reply}
          end).

await_reply(Pid) ->
    receive {reply, Pid, _} -> ok after ?WAIT_MS -> error({no_reply, Pid}) end.

%% The pid of the process the mocked RPC for this token is blocked in.
await_rpc(Id) ->
    receive {rpc, _, Id, W} -> W after ?WAIT_MS -> error({no_rpc, Id}) end.

await_snapshot(Pred) ->
    until(fun() -> case yuzu_gw_upstream:lane_snapshot() of
                       undefined -> false;
                       S -> Pred(S)
                   end
          end, snapshot_not_reached).

until(Pred, What) ->
    Deadline = erlang:monotonic_time(millisecond) + ?WAIT_MS,
    until(Pred, What, Deadline).

until(Pred, What, Deadline) ->
    case Pred() of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> error(What);
                false -> receive after 5 -> until(Pred, What, Deadline) end
            end
    end.

%% The first event of this kind whose measurements satisfy Pred, within 10 s.
await_event(Tag, Pred) ->
    receive
        {Tag, M} -> case Pred(M) of true -> M; false -> await_event(Tag, Pred) end
    after 10000 -> error({no_event, Tag})
    end.

kill(Pid) ->
    Mon = monitor(process, Pid),
    exit(Pid, kill),
    receive {'DOWN', Mon, process, Pid, _} -> ok after ?WAIT_MS -> error(not_dead) end.

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
