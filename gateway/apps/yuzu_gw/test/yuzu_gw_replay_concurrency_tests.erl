%%%-------------------------------------------------------------------
%%% @doc A full registration replay, at fleet scale.
%%%
%%% A full replay re-proxies every agent the registry holds (since #5695 it is
%%% started by a heartbeat verdict that shows the server lost its state, not by a
%%% breaker recovery; these tests start it with the replay_registrations cast,
%%% which runs the same walk and workers). They pin the
%%% properties that make that work at thousands of agents:
%%%
%%%   - the replay runs in parallel, bounded by the regulator's replay cap
%%%     (upstream_replay_concurrency, default 24) and never above it;
%%%   - a live Register during the replay is not starved (the replay may hold
%%%     at most the replay cap of the register pool);
%%%   - the upstream process walks the agents table in chunks of small pairs and
%%%     never copies every stored RegisterRequest into its own heap (the workers
%%%     read each request when they run); its reductions are printed for N and 4N
%%%     agents as a linearity check.
%%%
%%% Real: yuzu_gw_registry (its agents table is what is walked). Mocked:
%%% yuzu_grpc_client:unary/5 (latency and an in-flight count kept in an ETS
%%% table this module creates and deletes) and yuzu_gw_agent's reannounce/2 and
%%% disconnect/1 (the dummy agent processes are not gen_statems).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_replay_concurrency_tests).
-include_lib("eunit/include/eunit.hrl").

-define(TAB, yuzu_gw_replay_concurrency_tests_tab).
-define(ENV_KEYS, [circuit_breaker_failure_threshold, circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms, registration_replay_spacing_ms,
                   registration_replay_start_jitter_ms, upstream_call_timeout_ms]).

replay_concurrency_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{timeout, 120, {"2,000 agents at 10 ms per call: replayed in parallel, at most 24 in "
                      "flight, in under 6 s", fun replay_is_parallel_and_capped/0}},
      {timeout, 120, {"a live Register during a replay is answered within a few calls' time",
                      fun live_register_is_not_starved/0}},
      {timeout, 240, {"the upstream never holds a copy of the fleet's stored requests",
                      fun upstream_holds_no_fleet_copy/0}}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_registry:ensure(),
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(yuzu_gw_agent),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    ok = meck:new(yuzu_gw_agent, [passthrough, no_link]),
    ok = meck:expect(yuzu_gw_agent, reannounce, fun(_, _) -> ok end),
    ok = meck:expect(yuzu_gw_agent, disconnect, fun(_) -> ok end),
    ?TAB = ets:new(?TAB, [named_table, public, set]),
    reset_counters(),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 1000),
    application:set_env(yuzu_gw, registration_replay_start_jitter_ms, 0),
    application:set_env(yuzu_gw, upstream_call_timeout_ms, 30000),
    Dummy = spawn(fun() -> receive stop -> ok end end),
    {Prev, Dummy}.

cleanup({Prev, Dummy}) ->
    yuzu_gw_test_upstream:stop_upstream(),
    [yuzu_gw_registry:deregister_agent(Id) || Id <- yuzu_gw_registry:all_agents()],
    wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end, 10000),
    Dummy ! stop,
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(yuzu_gw_agent),
    catch ets:delete(?TAB),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

%%--------------------------------------------------------------------

replay_is_parallel_and_capped() ->
    N = 2000,
    register_agents(N),
    mock_latency(10),
    _ = yuzu_gw_test_upstream:start_upstream(),
    T0 = erlang:monotonic_time(millisecond),
    trigger_recovery(),
    Done = wait_until(fun() -> replays() >= N end, 60000),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    Peak = ets:lookup_element(?TAB, peak, 2),
    ?debugFmt("replay: ~b agents, ~b replayed, peak ~b in flight, ~b ms",
              [N, replays(), Peak, Elapsed]),
    ?assertEqual(ok, Done),
    ?assert(Peak > 1),
    ?assert(Peak =< 24),
    ?assert(Elapsed < 6000).

live_register_is_not_starved() ->
    register_agents(2000),
    mock_latency(50),
    _ = yuzu_gw_test_upstream:start_upstream(),
    trigger_recovery(),
    ok = wait_until(fun() -> replays() >= 100 end, 30000),
    T0 = erlang:monotonic_time(millisecond),
    ?assertMatch({ok, _}, yuzu_gw_upstream:proxy_register(#{info => #{agent_id => <<"live">>}})),
    Took = erlang:monotonic_time(millisecond) - T0,
    ?debugFmt("live Register during replay answered in ~b ms", [Took]),
    ?assert(Took < 500).

upstream_holds_no_fleet_copy() ->
    mock_latency(0),
    %% A stored request of about 2,000 heap words each: 4,000 of them in one
    %% heap is about 8 million words.
    Pad = lists:seq(1, 1000),
    {Small, SmallHeap} = replay_footprint(1000, Pad),
    {Large, LargeHeap} = replay_footprint(4000, Pad),
    ?debugFmt("upstream: reductions 1000 agents ~b, 4000 agents ~b (ratio ~.2f); peak heap "
              "1000 agents ~b words, 4000 agents ~b words",
              [Small, Large, Large / max(1, Small), SmallHeap, LargeHeap]),
    %% A quarter of what a copy of the 4,000 requests alone would take. (The
    %% heap does grow a little with the fleet: the guard stamps of the replayed
    %% sessions and the workers' results in the mailbox, a few words each.)
    _ = SmallHeap,
    ?assert(LargeHeap < 2000000).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

%% Replay N agents (each stored request carrying Pad) and return the upstream's
%% reductions over the replay and the peak of its heap, sampled every 2 ms.
replay_footprint(N, Pad) ->
    register_agents(N, Pad),
    reset_counters(),
    application:set_env(yuzu_gw, registration_replay_spacing_ms, 0),
    Up = yuzu_gw_test_upstream:start_upstream(),
    {reductions, R0} = process_info(Up, reductions),
    Test = self(),
    Sampler = spawn(fun() -> sample_heap(Up, Test, 0) end),
    trigger_recovery(),
    ok = wait_until(fun() -> replays() >= N end, 120000),
    _ = yuzu_gw_upstream:circuit_state(),
    {reductions, R1} = process_info(Up, reductions),
    Sampler ! stop,
    Peak = receive {peak, Sampler, P} -> P after 5000 -> error(no_sample) end,
    yuzu_gw_test_upstream:stop_upstream(),
    [yuzu_gw_registry:deregister_agent(Id) || Id <- yuzu_gw_registry:all_agents()],
    ok = wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end, 10000),
    {R1 - R0, Peak}.

sample_heap(Up, Test, Peak) ->
    receive stop -> Test ! {peak, self(), Peak}
    after 2 ->
        case process_info(Up, total_heap_size) of
            {total_heap_size, H} -> sample_heap(Up, Test, max(H, Peak));
            undefined -> sample_heap(Up, Test, Peak)
        end
    end.

register_agents(N) ->
    register_agents(N, []).

register_agents(N, Pad) ->
    Dummy = spawn(fun() -> receive stop -> ok after 600000 -> ok end end),
    [begin
         Id = <<"rc-", (integer_to_binary(I))/binary>>,
         ok = yuzu_gw_registry:register_agent(Id, Dummy, <<"sess-", Id/binary>>, [<<"svc">>],
                                              <<"host">>, #{info => #{agent_id => Id},
                                                            pad => Pad})
     end || I <- lists:seq(1, N)],
    ok.

%% Start a full replay (the replay_registrations cast: a recovery no longer
%% starts one, #5695).
trigger_recovery() ->
    ok = gen_server:cast(yuzu_gw_upstream, replay_registrations).

reset_counters() ->
    ets:insert(?TAB, [{inflight, 0}, {peak, 0}, {replays, 0}, {fail_next, false}]).

replays() ->
    ets:lookup_element(?TAB, replays, 2).

%% Replays (the calls that carry x-yuzu-session-id) take Ms and are counted, with
%% their in-flight count and its peak; other calls answer at once.
mock_latency(Ms) ->
    ok = meck:expect(
           yuzu_grpc_client, unary,
           fun(Meta, _Path, _Req, _Def, _Opts) ->
               case maps:get(<<"x-yuzu-session-id">>, Meta, undefined) of
                   undefined ->
                       case ets:lookup_element(?TAB, fail_next, 2) of
                           true  -> ets:insert(?TAB, {fail_next, false}), {error, econnrefused};
                           false -> {ok, #{session_id => <<"live">>}, #{}}
                       end;
                   Sid ->
                       In = ets:update_counter(?TAB, inflight, 1),
                       bump_peak(In),
                       Ms > 0 andalso timer:sleep(Ms),
                       ets:update_counter(?TAB, inflight, -1),
                       ets:update_counter(?TAB, replays, 1),
                       {ok, #{session_id => Sid, accepted => true}, #{}}
               end
           end).

bump_peak(In) ->
    case In > ets:lookup_element(?TAB, peak, 2) of
        true -> ets:insert(?TAB, {peak, In});
        false -> ok
    end.

wait_until(Pred, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_until_(Pred, Deadline).

wait_until_(Pred, Deadline) ->
    case Pred() of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> timeout;
                false -> timer:sleep(10), wait_until_(Pred, Deadline)
            end
    end.
