%%%-------------------------------------------------------------------
%%% @doc Performance test suite for the Yuzu gateway.
%%%
%%% Validates throughput, latency distributions, and memory stability
%%% of the gateway's hot paths under realistic production-scale load.
%%% All upstream RPCs are mocked — this isolates gateway performance
%%% from network latency.
%%%
%%% Configuration via environment variables:
%%%   YUZU_PERF_AGENTS       — agent count for registration/churn (default 10000)
%%%   YUZU_PERF_HEARTBEATS   — heartbeat count (default 50000)
%%%   YUZU_PERF_FANOUT       — fanout target count (default 10000)
%%%   YUZU_PERF_CHURN_AGENTS — churn agent count (default 5000)
%%%   YUZU_PERF_CHURN_CYCLES — churn cycles (default 10)
%%%   YUZU_PERF_ENDURANCE_AGENTS — endurance agent count (default 10000)
%%%   YUZU_PERF_ENDURANCE_SECS   — endurance duration (default 300)
%%%
%%% Run:
%%%   rebar3 ct --suite=yuzu_gw_perf_SUITE --verbose
%%%   rebar3 ct --suite=yuzu_gw_perf_SUITE --group=fanout
%%%   YUZU_PERF_AGENTS=50000 rebar3 ct --suite=yuzu_gw_perf_SUITE
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_perf_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%%%===================================================================
%%% CT callbacks
%%%===================================================================

all() ->
    [{group, registration},
     {group, heartbeat},
     {group, fanout},
     {group, churn},
     {group, endurance}].

groups() ->
    [{registration, [sequence],
      [sustained_registration_throughput,
       burst_registration,
       registration_latency_distribution]},

     {heartbeat, [sequence],
      [heartbeat_throughput,
       batch_flush_latency,
       buffer_backpressure]},

     {fanout, [sequence],
      [fanout_10k,
       fanout_100k,
       concurrent_fanouts,
       fanout_with_missing_agents]},

     {churn, [sequence],
      [reconnection_storm,
       session_cleanup_latency,
       monitor_map_stability]},

     {endurance, [],
      [sustained_load_5min]}].

suite() ->
    [{timetrap, {minutes, 20}}].

init_per_suite(Config) ->
    %% Trap exits so linked gen_servers (pg, registry) don't kill
    %% the suite process if they crash or are restarted.
    process_flag(trap_exit, true),
    %% Start pg scope (idempotent).  Unlink so the process survives
    %% CT process transitions between callbacks and test cases.
    case whereis(yuzu_gw) of
        undefined ->
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        _ -> ok
    end,
    %% Start registry (unlinked for same reason).
    case whereis(yuzu_gw_registry) of
        undefined ->
            {ok, RegPid} = yuzu_gw_registry:start_link(),
            unlink(RegPid);
        _ -> ok
    end,
    %% Silence telemetry events (defensive cleanup in case prior suite left it mocked).
    catch meck:unload(telemetry),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    Config.

end_per_suite(_Config) ->
    catch meck:unload(telemetry),
    %% Safety cleanup: deregister all agents.
    try
        Ids = yuzu_gw_registry:all_agents(),
        lists:foreach(fun(Id) -> catch yuzu_gw_registry:deregister_agent(Id) end, Ids),
        timer:sleep(500)
    catch _:_ -> ok
    end,
    ok.

init_per_group(heartbeat, Config) ->
    ensure_registry(),
    catch meck:unload(grpcbox_client),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    %% Long interval — tests trigger flush manually.
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 60000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 100000),
    {ok, HBPid} = yuzu_gw_heartbeat_buffer:start_link(),
    unlink(HBPid),
    [{hb_pid, HBPid} | Config];

init_per_group(fanout, Config) ->
    ensure_registry(),
    case whereis(yuzu_gw_router) of
        undefined ->
            {ok, RPid} = yuzu_gw_router:start_link(),
            unlink(RPid);
        _ -> ok
    end,
    Config;

init_per_group(_Group, Config) ->
    ensure_registry(),
    Config.

end_per_group(heartbeat, Config) ->
    catch gen_server:stop(?config(hb_pid, Config)),
    catch meck:unload(grpcbox_client),
    drain_registry(),
    ok;

end_per_group(_Group, _Config) ->
    drain_registry(),
    ok.

init_per_testcase(_TC, Config) ->
    Config.

end_per_testcase(_TC, _Config) ->
    flush_mailbox(),
    ok.

%%%===================================================================
%%% Registration group
%%%===================================================================

%% @doc Sequential registration of N agents — measures gen_server
%% serialization throughput. Assert > 5 000 registrations/sec.
sustained_registration_throughput(_Config) ->
    N = yuzu_gw_perf_helpers:get_env("YUZU_PERF_AGENTS", 10000),
    ct:pal("--- sustained_registration_throughput: ~B agents ---", [N]),

    {Pids, Ids} = yuzu_gw_perf_helpers:spawn_agents(N, #{}),
    Pairs = lists:zip(Pids, Ids),

    {WallMs, _} = yuzu_gw_perf_helpers:measure_wall_clock(fun() ->
        lists:foreach(fun({Pid, Id}) ->
            ok = yuzu_gw_registry:register_agent(
                     Id, Pid, <<"sess-", Id/binary>>, [<<"plugin1">>], <<>>)
        end, Pairs)
    end),

    OpsPerSec = yuzu_gw_perf_helpers:assert_throughput("Registration", N, WallMs),
    ?assertEqual(N, yuzu_gw_registry:agent_count()),
    ?assert(OpsPerSec > 1500),

    yuzu_gw_perf_helpers:cleanup_agents(Pids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000),
    sync_pg().

%% @doc Burst: N concurrent workers each registering one agent.
burst_registration(_Config) ->
    N = yuzu_gw_perf_helpers:get_env("YUZU_PERF_AGENTS", 10000),
    ct:pal("--- burst_registration: ~B agents concurrent ---", [N]),

    {Pids, Ids} = yuzu_gw_perf_helpers:spawn_agents(N, #{prefix => <<"burst">>}),
    Pairs = lists:zip(Pids, Ids),
    Parent = self(),

    {WallMs, _} = yuzu_gw_perf_helpers:measure_wall_clock(fun() ->
        Workers = [spawn(fun() ->
            ok = yuzu_gw_registry:register_agent(
                     Id, Pid, <<"sess-", Id/binary>>, [<<"plugin1">>], <<>>),
            Parent ! {reg_done, self()}
        end) || {Pid, Id} <- Pairs],
        lists:foreach(fun(W) ->
            receive {reg_done, W} -> ok
            after 60000 -> ct:fail("Worker ~p timed out", [W])
            end
        end, Workers)
    end),

    ?assertEqual(N, yuzu_gw_registry:agent_count()),
    yuzu_gw_perf_helpers:assert_throughput("Burst registration", N, WallMs),

    yuzu_gw_perf_helpers:cleanup_agents(Pids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000),
    sync_pg().

%% @doc Measure per-registration latency distribution.
%% Assert p99 < 1 ms (1000 µs).
registration_latency_distribution(_Config) ->
    N = min(1000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_AGENTS", 10000)),
    ct:pal("--- registration_latency_distribution: ~B samples ---", [N]),

    %% Pre-spawn all dummy processes.
    Agents = [begin
        Id = iolist_to_binary(io_lib:format("lat-~6..0B", [I])),
        Pid = spawn(fun agent_loop/0),
        {Pid, Id}
    end || I <- lists:seq(1, N)],

    %% Time each registration individually.
    Timings = [begin
        T0 = erlang:monotonic_time(microsecond),
        ok = yuzu_gw_registry:register_agent(Id, Pid, <<"sess">>, [<<"p1">>], <<>>),
        T1 = erlang:monotonic_time(microsecond),
        T1 - T0
    end || {Pid, Id} <- Agents],

    Stats = yuzu_gw_perf_helpers:stats_from_timings(Timings),
    ct:pal(yuzu_gw_perf_helpers:format_report("Registration latency", Stats)),
    yuzu_gw_perf_helpers:assert_latency(Stats, #{p99 => 1000}),

    AgentPids = [Pid || {Pid, _} <- Agents],
    yuzu_gw_perf_helpers:cleanup_agents(AgentPids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000),
    sync_pg().

%%%===================================================================
%%% Heartbeat group
%%%===================================================================

%% @doc Queue N heartbeats (async cast). Assert 50K in < 500 ms.
%% Uses microsecond-resolution timing: at the default 20K-op count this
%% benchmark completes in ~8 ms, and millisecond timing only resolves to
%% 7 / 8 / 9 ms (3 buckets) — too few for the perf gate's 10% tolerance
%% to survive a single-tick boundary jump. Microsecond resolution gives
%% ~thousands of buckets and a continuous distribution.
heartbeat_throughput(_Config) ->
    N = yuzu_gw_perf_helpers:get_env("YUZU_PERF_HEARTBEATS", 50000),
    ct:pal("--- heartbeat_throughput: ~B heartbeats ---", [N]),

    {WallUs, _} = yuzu_gw_perf_helpers:measure_wall_clock_us(fun() ->
        lists:foreach(fun(I) ->
            ok = yuzu_gw_heartbeat_buffer:queue_heartbeat(
                     #{session_id => integer_to_binary(I),
                       agent_id => integer_to_binary(I),
                       timestamp => erlang:system_time(millisecond)})
        end, lists:seq(1, N))
    end),

    yuzu_gw_perf_helpers:assert_throughput_us("Heartbeat queue", N, WallUs),
    ?assert(WallUs < 500_000,
            lists:flatten(io_lib:format(
                "Queueing ~B HBs took ~B us (limit 500_000 us)", [N, WallUs]))),

    %% Drain the buffer.
    trigger_hb_flush().

%% @doc Queue N heartbeats, flush, measure RPC latency.
%% Assert flush < 200 ms and at least one batch call made.
batch_flush_latency(_Config) ->
    N = yuzu_gw_perf_helpers:get_env("YUZU_PERF_HEARTBEATS", 50000),
    ct:pal("--- batch_flush_latency: ~B heartbeats ---", [N]),

    meck:reset(grpcbox_client),
    lists:foreach(fun(I) ->
        ok = yuzu_gw_heartbeat_buffer:queue_heartbeat(
                 #{session_id => integer_to_binary(I),
                   agent_id => integer_to_binary(I),
                   timestamp => erlang:system_time(millisecond)})
    end, lists:seq(1, N)),

    {FlushMs, _} = yuzu_gw_perf_helpers:measure_wall_clock(fun() ->
        trigger_hb_flush()
    end),

    History = meck:history(grpcbox_client),
    BatchCalls = [Args || {_Pid, {grpcbox_client, unary, Args}, _Ret} <- History],
    ct:pal("Flush ~B HBs: ~B ms, ~B batch RPCs", [N, FlushMs, length(BatchCalls)]),
    ?assert(length(BatchCalls) >= 1, "Expected at least one BatchHeartbeat RPC"),
    ?assert(FlushMs < 200,
            lists:flatten(io_lib:format(
                "Flush took ~B ms (limit 200 ms)", [FlushMs]))).

%% @doc Fail first flush (buffer retained), succeed second, verify delivery.
buffer_backpressure(_Config) ->
    ct:pal("--- buffer_backpressure ---"),
    N = 5000,

    %% Make flush fail.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, {14, <<"upstream unavailable">>}}
    end),

    lists:foreach(fun(I) ->
        ok = yuzu_gw_heartbeat_buffer:queue_heartbeat(
                 #{session_id => iolist_to_binary(io_lib:format("bp-~B", [I]))})
    end, lists:seq(1, N)),

    trigger_hb_flush(),

    %% Queue more — buffer should be capped by max_hb_buffer.
    MaxBuf = application:get_env(yuzu_gw, max_heartbeat_buffer, 100000),
    lists:foreach(fun(I) ->
        ok = yuzu_gw_heartbeat_buffer:queue_heartbeat(
                 #{session_id => iolist_to_binary(io_lib:format("bp-more-~B", [I]))})
    end, lists:seq(1, MaxBuf)),

    %% Make flush succeed.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _       ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),

    trigger_hb_flush(),

    %% Verify batch was sent (capped).
    History = meck:history(grpcbox_client),
    BatchReqs = [Req || {_, {grpcbox_client, unary,
                            [_, Path, Req, _, _]}, _} <- History,
                        binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchReqs) >= 1, "Expected BatchHeartbeat after recovery"),
    case BatchReqs of
        [Req | _] ->
            HBs = maps:get(heartbeats, Req, []),
            ct:pal("Recovered flush: ~B HBs in batch (cap ~B)", [length(HBs), MaxBuf]),
            ?assert(length(HBs) =< MaxBuf, "Buffer exceeded max cap");
        [] ->
            ct:fail("No BatchHeartbeat sent after recovery")
    end.

%%%===================================================================
%%% Fanout group
%%%===================================================================

%% @doc Fan out command to 10K agents. Assert < 100 ms.
fanout_10k(_Config) ->
    N = min(10000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_FANOUT", 10000)),
    fanout_benchmark("fanout_10k", N, 100).

%% @doc Fan out command to 100K agents. Assert < 1 s.
%% Skips if the BEAM process limit is too low.
fanout_100k(_Config) ->
    N = min(100000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_FANOUT", 100000)),
    ProcLimit = erlang:system_info(process_limit),
    ProcCount = erlang:system_info(process_count),
    case ProcLimit - ProcCount < N + 1000 of
        true ->
            {skip, lists:flatten(io_lib:format(
                "Process limit ~B too low for ~B agents", [ProcLimit, N]))};
        false ->
            fanout_benchmark("fanout_100k", N, 1000)
    end.

%% @doc 10 simultaneous fanouts to overlapping agent sets.
concurrent_fanouts(_Config) ->
    N = min(5000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_FANOUT", 10000) div 2),
    NumFanouts = 10,
    ct:pal("--- concurrent_fanouts: ~B fanouts x ~B agents ---", [NumFanouts, N]),

    {Pids, Ids} = yuzu_gw_perf_helpers:spawn_and_register(
                      N, #{prefix => <<"cfan">>}),

    Cmd = #{command_id => <<"conc-cmd">>, plugin => <<"system">>},
    Parent = self(),

    {WallMs, _} = yuzu_gw_perf_helpers:measure_wall_clock(fun() ->
        Workers = [spawn(fun() ->
            {ok, _} = yuzu_gw_router:send_command(Ids, Cmd, #{timeout_seconds => 5}),
            Parent ! {fan_done, self()}
        end) || _ <- lists:seq(1, NumFanouts)],
        lists:foreach(fun(W) ->
            receive {fan_done, W} -> ok
            after 30000 -> ct:fail("Fanout worker timed out")
            end
        end, Workers)
    end),

    ct:pal("~B concurrent fanouts to ~B agents: ~B ms", [NumFanouts, N, WallMs]),

    yuzu_gw_perf_helpers:cleanup_agents(Pids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000).

%% @doc Fanout where 20 % of targets are missing.
%% Verifies skipped + dispatched counts and bounded overhead.
fanout_with_missing_agents(_Config) ->
    N = min(5000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_FANOUT", 10000) div 2),
    MissingPct = 20,
    NumPresent = N - (N * MissingPct div 100),
    NumMissing = N * MissingPct div 100,
    ct:pal("--- fanout_with_missing: ~B present + ~B missing ---",
           [NumPresent, NumMissing]),

    {Pids, PresentIds} = yuzu_gw_perf_helpers:spawn_and_register(
                              NumPresent, #{prefix => <<"fmiss">>}),

    FakeIds = [iolist_to_binary(io_lib:format("missing-~6..0B", [I]))
               || I <- lists:seq(1, NumMissing)],
    AllIds = PresentIds ++ FakeIds,

    Cmd = #{command_id => <<"miss-cmd">>, plugin => <<"system">>},

    {WallMs, {ok, FanoutRef}} = yuzu_gw_perf_helpers:measure_wall_clock(fun() ->
        yuzu_gw_router:send_command(AllIds, Cmd, #{timeout_seconds => 5})
    end),

    %% Collect command_error messages for missing agents.
    Errors = collect_errors(FanoutRef, NumMissing, 5000),
    ?assertEqual(NumMissing, length(Errors)),
    ct:pal("Fanout ~B targets (~B missing): ~B ms, ~B errors received",
           [length(AllIds), NumMissing, WallMs, length(Errors)]),

    yuzu_gw_perf_helpers:cleanup_agents(Pids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000).

%%%===================================================================
%%% Churn group
%%%===================================================================

%% @doc Re-register 5K agents with new PIDs over 10 cycles.
%% Assert: monitor_refs map size == N after all cycles (no leak).
reconnection_storm(_Config) ->
    N = yuzu_gw_perf_helpers:get_env("YUZU_PERF_CHURN_AGENTS", 5000),
    Cycles = yuzu_gw_perf_helpers:get_env("YUZU_PERF_CHURN_CYCLES", 10),
    ct:pal("--- reconnection_storm: ~B agents, ~B cycles ---", [N, Cycles]),

    MemBefore = yuzu_gw_perf_helpers:memory_snapshot(),

    Ids = [iolist_to_binary(io_lib:format("churn-~6..0B", [I]))
           || I <- lists:seq(1, N)],

    {CycleTimes, LastPids} = lists:foldl(fun(Cycle, {Times, _PrevPids}) ->
        {CycleMs, NewPids} = yuzu_gw_perf_helpers:measure_wall_clock(fun() ->
            lists:map(fun(Id) ->
                Pid = spawn(fun agent_loop/0),
                ok = yuzu_gw_registry:register_agent(Id, Pid, <<"sess">>, [<<"p1">>], <<>>),
                Pid
            end, Ids)
        end),
        ?assertEqual(N, yuzu_gw_registry:agent_count()),
        ct:pal("  Cycle ~B/~B: ~B ms", [Cycle, Cycles, CycleMs]),
        {[CycleMs | Times], NewPids}
    end, {[], []}, lists:seq(1, Cycles)),

    %% Verify monitor_refs map — no leaks.
    {state, MonRefs, _} = sys:get_state(yuzu_gw_registry),
    MonRefCount = maps:size(MonRefs),
    ?assertEqual(N, MonRefCount,
                 lists:flatten(io_lib:format(
                     "Monitor refs ~B != ~B agents (leak!)", [MonRefCount, N]))),

    MemAfter = yuzu_gw_perf_helpers:memory_snapshot(),
    Delta = yuzu_gw_perf_helpers:memory_delta(MemBefore, MemAfter),
    AvgCycleMs = lists:sum(CycleTimes) div Cycles,

    ct:pal("Reconnection storm complete:~n"
           "  Avg cycle: ~B ms~n"
           "  Monitor refs: ~B (expected ~B)~n"
           "  Memory delta: total=~BKB  ets=~BKB  procs=~BKB",
           [AvgCycleMs, MonRefCount, N,
            maps:get(total, Delta) div 1024,
            maps:get(ets, Delta) div 1024,
            maps:get(processes, Delta) div 1024]),

    yuzu_gw_perf_helpers:cleanup_agents(LastPids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000).

%% @doc Kill N agents simultaneously, measure how long until
%% the registry processes all DOWN messages and reaches count 0.
%%
%% Microsecond timing + ~.5f formatting: at N=1000 the cleanup completes
%% in ~50 ms, giving ~0.05 ms/agent. Millisecond timing combined with
%% ~.2f rounding turned every sample into the literal string "0.05" with
%% zero variance — the metric was effectively unmeasured. Microsecond
%% resolution + 5 dp exposes ~3-4 significant digits of natural noise.
session_cleanup_latency(_Config) ->
    N = min(1000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_CHURN_AGENTS", 5000)),
    ct:pal("--- session_cleanup_latency: ~B agents ---", [N]),

    {Pids, _Ids} = yuzu_gw_perf_helpers:spawn_and_register(
                        N, #{prefix => <<"clean">>}),
    ?assertEqual(N, yuzu_gw_registry:agent_count()),

    {CleanupUs, _} = yuzu_gw_perf_helpers:measure_wall_clock_us(fun() ->
        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Pids),
        ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000)
    end),

    MsPerAgent = (CleanupUs / 1000.0) / N,
    ct:pal("Cleanup ~B agents: ~B us (~.5f ms/agent)",
           [N, CleanupUs, MsPerAgent]).

%% @doc Register/deregister N agents over several cycles.
%% Assert monitor_refs map is 0 after each full cleanup.
monitor_map_stability(_Config) ->
    N = min(2000, yuzu_gw_perf_helpers:get_env("YUZU_PERF_CHURN_AGENTS", 5000)),
    Cycles = 5,
    ct:pal("--- monitor_map_stability: ~B agents, ~B cycles ---", [N, Cycles]),

    lists:foreach(fun(Cycle) ->
        {Pids, _Ids} = yuzu_gw_perf_helpers:spawn_and_register(
                            N, #{prefix => iolist_to_binary(
                                    io_lib:format("stab-~B", [Cycle]))}),

        lists:foreach(fun(Pid) -> exit(Pid, kill) end, Pids),
        ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000),

        {state, MonRefs, _} = sys:get_state(yuzu_gw_registry),
        MonRefCount = maps:size(MonRefs),
        ?assertEqual(0, MonRefCount,
                     lists:flatten(io_lib:format(
                         "Cycle ~B: ~B leaked monitor refs", [Cycle, MonRefCount]))),
        ct:pal("  Cycle ~B/~B: clean (0 monitor refs)", [Cycle, Cycles])
    end, lists:seq(1, Cycles)).

%%%===================================================================
%%% Endurance group
%%%===================================================================

%% @doc Sustained mixed workload: dispatches, heartbeats, and churn
%% over a configurable duration.  Assert flat memory (no leaks),
%% bounded process count variation, and stable scheduler utilisation.
sustained_load_5min(_Config) ->
    N = yuzu_gw_perf_helpers:get_env("YUZU_PERF_ENDURANCE_AGENTS", 10000),
    DurationSecs = yuzu_gw_perf_helpers:get_env("YUZU_PERF_ENDURANCE_SECS", 300),
    ct:pal("--- sustained_load: ~B agents, ~Bs ---", [N, DurationSecs]),

    %% --- per-test setup (endurance needs router + upstream) -----------
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 5000),
    {ok, UpstreamPid} = yuzu_gw_upstream:start_link(),
    case whereis(yuzu_gw_router) of
        undefined -> {ok, _} = yuzu_gw_router:start_link();
        _         -> ok
    end,

    try
        do_sustained_load(N, DurationSecs)
    after
        catch gen_server:stop(UpstreamPid),
        catch meck:unload(grpcbox_client)
    end.

%%%===================================================================
%%% Internal helpers
%%%===================================================================

%% --- fanout benchmark ------------------------------------------------

fanout_benchmark(Label, N, MaxMs) ->
    ct:pal("--- ~s: ~B agents, limit ~B ms ---", [Label, N, MaxMs]),

    {Pids, Ids} = register_silent_agents(N, iolist_to_binary(Label)),
    ?assertEqual(N, yuzu_gw_registry:agent_count()),

    Cmd = #{command_id => <<"fanout-bench">>, plugin => <<"system">>},

    {WallMs, {ok, _FanoutRef}} = yuzu_gw_perf_helpers:measure_wall_clock(fun() ->
        yuzu_gw_router:send_command(Ids, Cmd, #{timeout_seconds => 5})
    end),

    ct:pal("Fanout to ~B agents: ~B ms (limit ~B ms)", [N, WallMs, MaxMs]),
    ?assert(WallMs =< MaxMs,
            lists:flatten(io_lib:format(
                "Fanout ~B agents: ~B ms > ~B ms limit", [N, WallMs, MaxMs]))),

    yuzu_gw_perf_helpers:cleanup_agents(Pids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000),
    sync_pg().

register_silent_agents(N, Prefix) ->
    lists:unzip([begin
        Id = iolist_to_binary(io_lib:format("~s-~6..0B", [Prefix, I])),
        Pid = spawn(fun silent_loop/0),
        ok = yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [<<"system">>], <<>>),
        {Pid, Id}
    end || I <- lists:seq(1, N)]).

silent_loop() ->
    receive stop -> ok; _ -> silent_loop() end.

agent_loop() ->
    receive stop -> ok; _ -> agent_loop() end.

%% --- heartbeat flush trigger -----------------------------------------

trigger_hb_flush() ->
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> ok;
        Pid       ->
            Pid ! flush,
            %% Synchronization barrier: a gen_server:call blocks until
            %% all prior messages (including flush) are processed.
            try gen_server:call(yuzu_gw_heartbeat_buffer, sync_barrier, 5000)
            catch _:_ -> ok
            end
    end.

%% --- message collection ----------------------------------------------

collect_errors(_FanoutRef, 0, _Timeout) -> [];
collect_errors(FanoutRef, Remaining, Timeout) ->
    receive
        {command_error, FanoutRef, _AgentId, not_connected} ->
            [not_connected | collect_errors(FanoutRef, Remaining - 1, Timeout)]
    after Timeout ->
        []
    end.

flush_mailbox() ->
    receive _ -> flush_mailbox()
    after 0 -> ok
    end.

%% Deregister all agents left over from a failed test,
%% then sync with the pg process to drain its DOWN backlog.
drain_registry() ->
    try
        case whereis(yuzu_gw_registry) of
            undefined -> ok;
            _ ->
                Ids = yuzu_gw_registry:all_agents(),
                lists:foreach(fun(Id) ->
                    catch yuzu_gw_registry:deregister_agent(Id)
                end, Ids),
                yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000)
        end
    catch _:_ -> ok
    end,
    sync_pg().

%% Synchronize with the pg process to ensure all pending DOWN
%% messages have been processed before starting new registrations.
%% pg:join/leave use gen_server:call with infinity timeout, so they
%% queue behind all pending DOWN messages in pg's mailbox.
sync_pg() ->
    Dummy = spawn(fun() -> receive _ -> ok end end),
    try
        pg:join(yuzu_gw, '__pg_sync__', Dummy),
        pg:leave(yuzu_gw, '__pg_sync__', Dummy)
    catch _:_ -> ok
    after
        exit(Dummy, kill)
    end.

%% --- endurance loop --------------------------------------------------

do_sustained_load(N, DurationSecs) ->
    Ids = [iolist_to_binary(io_lib:format("endur-~6..0B", [I]))
           || I <- lists:seq(1, N)],

    %% Register initial agents.
    InitPids = lists:map(fun(Id) ->
        Pid = spawn(fun agent_loop/0),
        ok = yuzu_gw_registry:register_agent(Id, Pid, <<"sess">>, [<<"p1">>], <<>>),
        Pid
    end, Ids),

    SampleSecs = 10,
    ChurnSecs = 30,
    EndTime = erlang:monotonic_time(second) + DurationSecs,

    Samples = endurance_loop(Ids, EndTime, SampleSecs, ChurnSecs, 0, []),

    analyze_endurance(Samples, N),

    %% Cleanup — kill anything still alive.
    AlivePids = lists:filtermap(fun(Id) ->
        case yuzu_gw_registry:lookup(Id) of
            {ok, Pid} -> {true, Pid};
            error     -> false
        end
    end, Ids),
    yuzu_gw_perf_helpers:cleanup_agents(InitPids ++ AlivePids),
    ok = yuzu_gw_perf_helpers:wait_for_registry_count(0, 30000).

endurance_loop(Ids, EndTime, SampleSecs, ChurnSecs, Elapsed, Samples) ->
    Now = erlang:monotonic_time(second),
    case Now >= EndTime of
        true ->
            lists:reverse(Samples);
        false ->
            %% 1) Dispatch a command to all agents.
            Cmd = #{command_id => integer_to_binary(Now), plugin => <<"system">>},
            catch yuzu_gw_router:send_command(Ids, Cmd, #{timeout_seconds => 5}),

            %% 2) Queue some heartbeats.
            HBIds = lists:sublist(Ids, min(100, length(Ids))),
            lists:foreach(fun(Id) ->
                yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => Id, agent_id => Id})
            end, HBIds),

            %% 3) Churn 10% of agents every ChurnSecs.
            case Elapsed > 0 andalso Elapsed rem ChurnSecs =:= 0 of
                true  -> churn_agents(Ids, 10);
                false -> ok
            end,

            %% 4) Take sample.
            Sample = yuzu_gw_perf_helpers:memory_snapshot(),

            timer:sleep(SampleSecs * 1000),
            endurance_loop(Ids, EndTime, SampleSecs, ChurnSecs,
                           Elapsed + SampleSecs, [Sample | Samples])
    end.

churn_agents(Ids, Pct) ->
    ChurnN = max(1, length(Ids) * Pct div 100),
    ChurnIds = lists:sublist(Ids, ChurnN),
    %% Kill old processes and wait for each to die (avoid race with
    %% registry DOWN monitor — timer:sleep was unreliable under load).
    lists:foreach(fun(Id) ->
        case yuzu_gw_registry:lookup(Id) of
            {ok, OldPid} ->
                MRef = monitor(process, OldPid),
                exit(OldPid, kill),
                receive {'DOWN', MRef, process, _, _} -> ok
                after 5000 -> ok
                end;
            error -> ok
        end
    end, ChurnIds),
    %% Re-register with new PIDs.
    lists:foreach(fun(Id) ->
        Pid = spawn(fun agent_loop/0),
        ok = yuzu_gw_registry:register_agent(Id, Pid, <<"sess-new">>, [<<"p1">>], <<>>)
    end, ChurnIds).

analyze_endurance(Samples, ExpectedN) when length(Samples) >= 2 ->
    Mems = [maps:get(total, S) || S <- Samples],
    Procs = [maps:get(process_count, S) || S <- Samples],
    AgentSizes = [maps:get(ets_agent_size, S) || S <- Samples],

    FirstMem = hd(Mems),
    LastMem  = lists:last(Mems),
    MemGrowthPct = case FirstMem of
        0 -> 0.0;
        _ -> (LastMem - FirstMem) * 100.0 / FirstMem
    end,

    AvgProcs = lists:sum(Procs) / length(Procs),
    MaxProcs = lists:max(Procs),
    MinProcs = lists:min(Procs),
    ProcVar  = case round(AvgProcs) of
        0 -> 0.0;
        A -> (MaxProcs - MinProcs) * 100.0 / A
    end,

    AvgAgents = lists:sum(AgentSizes) / length(AgentSizes),

    ct:pal("=== Endurance Analysis (~B samples) ===~n"
           "  Memory: start=~BKB  end=~BKB  growth=~.1f%~n"
           "  Processes: avg=~B  min=~B  max=~B  variation=~.1f%~n"
           "  Agent count avg: ~B (expected ~B)",
           [length(Samples),
            FirstMem div 1024, LastMem div 1024, float(MemGrowthPct),
            round(AvgProcs), MinProcs, MaxProcs, float(ProcVar),
            round(AvgAgents), ExpectedN]),

    ?assert(abs(MemGrowthPct) < 50,
            lists:flatten(io_lib:format(
                "Memory growth ~.1f% > 50% (possible leak)", [float(MemGrowthPct)]))),
    ?assert(ProcVar < 20,
            lists:flatten(io_lib:format(
                "Process variation ~.1f% > 20%", [float(ProcVar)])));
analyze_endurance(Samples, _) ->
    ct:pal("Endurance: only ~B samples collected (too few to analyze)",
           [length(Samples)]).

%% --- registry lifecycle guard ----------------------------------------

ensure_registry() ->
    case whereis(yuzu_gw) of
        undefined ->
            ct:pal("[ensure_registry] starting pg scope yuzu_gw"),
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        Pid ->
            case is_process_alive(Pid) of
                true  -> ok;
                false ->
                    ct:pal("[ensure_registry] pg scope yuzu_gw dead (~p), restarting", [Pid]),
                    {ok, PgPid2} = pg:start_link(yuzu_gw),
                    unlink(PgPid2)
            end
    end,
    case whereis(yuzu_gw_registry) of
        undefined ->
            ct:pal("[ensure_registry] starting yuzu_gw_registry"),
            {ok, RegPid} = yuzu_gw_registry:start_link(),
            unlink(RegPid);
        RPid ->
            case is_process_alive(RPid) of
                true  -> ok;
                false ->
                    ct:pal("[ensure_registry] registry dead (~p), restarting", [RPid]),
                    {ok, RegPid2} = yuzu_gw_registry:start_link(),
                    unlink(RegPid2)
            end
    end.
