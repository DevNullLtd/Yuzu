%%%-------------------------------------------------------------------
%%% @doc Scale and stress tests for the Yuzu gateway.
%%%
%%% These tests verify that the gateway's core data structures and
%%% coordination paths hold up under high agent counts.  They measure
%%% actual timings and memory to catch regressions.
%%%
%%% Default agent count: 50,000 (override with YUZU_SCALE_AGENTS env).
%%% Default fanout count: 10,000 (override with YUZU_FANOUT_AGENTS env).
%%%
%%% At full production scale (1M+), use the vm.args tuning (+P 4M,
%%% +Q 2M) and run on a dedicated machine.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_scale_tests).
-include_lib("eunit/include/eunit.hrl").

%% Scale defaults - can be overridden with env vars for CI
%% Local development: YUZU_SCALE_AGENTS=50000
-define(DEFAULT_SCALE, 500).
-define(DEFAULT_FANOUT, 250).

%% Wait for the registry to finish processing DOWN messages after
%% killing agents.  A single gen_server:call won't work because
%% thousands of DOWN messages may be queued ahead of it.  Instead
%% we poll the message_queue_len of the registry process.
drain_registry() ->
    case whereis(yuzu_gw_registry) of
        undefined -> ok;
        Pid ->
            drain_loop(Pid, 10000)
    end.

drain_loop(_Pid, Remaining) when Remaining =< 0 -> ok;
drain_loop(Pid, Remaining) ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, 0} -> ok;
        {message_queue_len, _} ->
            timer:sleep(50),
            drain_loop(Pid, Remaining - 50);
        undefined -> ok
    end.

%%%===================================================================
%%% Test fixture
%%%===================================================================

scale_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     {timeout, 120,   %% 2 minute timeout for scale tests
      [
       {timeout, 30, {"bulk registration: N agents in bounded time", fun bulk_register/0}},
       {timeout, 30, {"lookup is O(1) at scale", fun lookup_at_scale/0}},
       {timeout, 30, {"pagination covers all agents exactly once", fun pagination_completeness/0}},
       {timeout, 60, {"bulk deregistration cleans up completely", fun bulk_deregister/0}},
       {timeout, 30, {"concurrent registration storm", fun concurrent_registration/0}},
       {timeout, 30, {"reconnection churn: same IDs re-registered rapidly", fun reconnection_churn/0}},
       {timeout, 30, {"ETS memory per agent is bounded", fun memory_per_agent/0}},
       {timeout, 30, {"fanout dispatch throughput", fun fanout_throughput/0}},
       {timeout, 30, {"heartbeat batch accumulation at scale", fun heartbeat_batch_scale/0}}
      ]}}.

setup() ->
    %% Kill and restart the registry so we don't inherit a gen_server
    %% mailbox full of DOWN messages from other test modules. ensure_fresh
    %% evicts the old one and waits for its named ETS tables to be reaped
    %% before start_link — the fixed-sleep version raced that reap on slow
    %% runners (#1403 / #336).
    yuzu_gw_test_registry:ensure_fresh(),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    ok.

cleanup(_) ->
    %% Clean up any leftover agents first.
    try
        AllAgents = yuzu_gw_registry:all_agents(),
        lists:foreach(fun(Id) ->
            catch yuzu_gw_registry:deregister_agent(Id)
        end, AllAgents),
        %% Give the registry time to process all deregistrations.
        timer:sleep(500)
    catch
        _:_ -> ok
    end,
    %% Stop processes started inside individual test functions
    %% (fanout_throughput starts yuzu_gw_router, heartbeat_batch_scale
    %% starts yuzu_gw_heartbeat_buffer).  If they're not running, the
    %% catch swallows the error.
    lists:foreach(fun(Name) ->
        case whereis(Name) of
            undefined -> ok;
            Pid ->
                catch unlink(Pid),
                catch gen_server:stop(Pid, shutdown, 1000)
        end
    end, [yuzu_gw_router, yuzu_gw_heartbeat_buffer]),
    catch meck:unload(telemetry),
    catch meck:unload(grpcbox_channel),
    catch meck:unload(grpcbox_client),
    ok.

%%%===================================================================
%%% Scale parameters
%%%===================================================================

scale_count() ->
    case os:getenv("YUZU_SCALE_AGENTS") of
        false -> ?DEFAULT_SCALE;
        Str   -> list_to_integer(Str)
    end.

fanout_count() ->
    case os:getenv("YUZU_FANOUT_AGENTS") of
        false -> ?DEFAULT_FANOUT;
        Str   -> list_to_integer(Str)
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

bulk_register() ->
    N = scale_count(),
    %% Spawn N dummy processes and register them.
    {Pids, Ids} = spawn_and_register(N),

    ?assertEqual(N, length(Pids)),

    %% All agents should be registered.
    ActualCount = yuzu_gw_registry:agent_count(),
    ?assert(ActualCount >= N),

    %% Verify a sample of lookups succeed.
    SampleIds = lists:sublist(Ids, 100),
    lists:foreach(fun(Id) ->
        ?assertMatch({ok, _}, yuzu_gw_registry:lookup(Id))
    end, SampleIds),

    %% Cleanup.
    kill_all(Pids),
    drain_registry().

lookup_at_scale() ->
    N = scale_count(),
    {Pids, Ids} = spawn_and_register(N),

    %% Measure 10,000 random lookups — should be well under 1ms each.
    SampleIds = [lists:nth(rand:uniform(N), Ids) || _ <- lists:seq(1, 10000)],
    {TimeUs, _} = timer:tc(fun() ->
        lists:foreach(fun(Id) ->
            {ok, _} = yuzu_gw_registry:lookup(Id)
        end, SampleIds)
    end),

    AvgUs = TimeUs / 10000,
    %% ETS lookup should be < 10 microseconds on average.
    ?assert(AvgUs < 10.0),

    kill_all(Pids),
    drain_registry().

pagination_completeness() ->
    N = min(scale_count(), 10000),  %% Cap for pagination test
    {Pids, Ids} = spawn_and_register_prefixed(N, <<"pag-">>),

    %% Walk all pages and collect IDs.
    AllFound = collect_all_pages(500, undefined, []),

    %% Every registered ID should appear exactly once.
    FoundIds = [maps:get(agent_id, A) || A <- AllFound],
    lists:foreach(fun(Id) ->
        Matches = length([F || F <- FoundIds, F =:= Id]),
        ?assertEqual(1, Matches, {missing_or_dup, Id})
    end, Ids),

    kill_all(Pids),
    drain_registry().

bulk_deregister() ->
    N = scale_count(),
    {Pids, Ids} = spawn_and_register_prefixed(N, <<"dereg-">>),
    CountBefore = yuzu_gw_registry:agent_count(),

    %% Kill all processes — DOWN monitors should clean up ETS.
    kill_all(Pids),

    %% Wait for all DOWN messages to be processed by the registry.
    %% The count should drop by at least N.
    ok = wait_until(fun() ->
        yuzu_gw_registry:agent_count() =< CountBefore - N
    end, 30000),

    %% Verify our specific agents are gone.
    SampleIds = lists:sublist(Ids, 100),
    lists:foreach(fun(Id) ->
        ?assertEqual(error, yuzu_gw_registry:lookup(Id))
    end, SampleIds).

concurrent_registration() ->
    N = min(scale_count(), 20000),  %% 20K concurrent registrations
    Self = self(),

    %% Spawn N processes that each register themselves concurrently.
    Workers = [spawn_link(fun() ->
        Id = iolist_to_binary(io_lib:format("conc-~b", [I])),
        Dummy = spawn(fun() -> receive stop -> ok end end),
        ok = yuzu_gw_registry:register_agent(Id, Dummy, <<"s">>, [], <<>>),
        Self ! {registered, I, Dummy}
    end) || I <- lists:seq(1, N)],

    %% Collect all registrations.
    {Dummies, _} = lists:foldl(fun(_, {Acc, _}) ->
        receive
            {registered, _, Pid} -> {[Pid | Acc], ok}
        after 30000 ->
            {Acc, timeout}
        end
    end, {[], ok}, Workers),

    ?assertEqual(N, length(Dummies)),

    %% All should be findable.
    Count = yuzu_gw_registry:agent_count(),
    ?assert(Count >= N),

    kill_all(Dummies),
    drain_registry().

reconnection_churn() ->
    N = scale_count(),
    %% Register N agents, then re-register the same IDs with new processes.
    %% This simulates rapid agent reconnection.
    Ids = [iolist_to_binary(io_lib:format("churn-~b", [I])) || I <- lists:seq(1, N)],

    %% First wave.
    Pids1 = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, N)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s1">>, [], <<>>)
    end, lists:zip(Ids, Pids1)),

    %% Second wave — same IDs, different processes.
    Pids2 = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, N)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s2">>, [], <<>>)
    end, lists:zip(Ids, Pids2)),

    %% All lookups should return the second-wave pids.
    lists:foreach(fun({Id, ExpectedPid}) ->
        ?assertMatch({ok, ExpectedPid}, yuzu_gw_registry:lookup(Id))
    end, lists:zip(Ids, Pids2)),

    kill_all(Pids1),
    kill_all(Pids2),
    drain_registry().

memory_per_agent() ->
    %% Measure ETS memory before and after registering N agents.
    N = min(scale_count(), 20000),
    erlang:garbage_collect(),
    MemBefore = ets:info(yuzu_gw_agents, memory) * erlang:system_info(wordsize),

    {Pids, _Ids} = spawn_and_register(N),

    MemAfter = ets:info(yuzu_gw_agents, memory) * erlang:system_info(wordsize),
    PerAgent = (MemAfter - MemBefore) / N,

    %% Each ETS entry is {Id, Pid, Node, SessionId, Plugins, Timestamp}.
    %% Should be well under 1 KB per agent.
    ?assert(PerAgent < 1024),

    kill_all(Pids),
    drain_registry().

fanout_throughput() ->
    %% Test dispatching commands to many fake agents via the router.
    N = fanout_count(),
    case whereis(yuzu_gw_router) of
        undefined -> {ok, _} = yuzu_gw_router:start_link();
        _ -> ok
    end,

    %% Register N fake agents that silently accept dispatches.
    {Pids, Ids} = register_silent_agents(N),

    %% Measure fanout dispatch time.
    Cmd = #{command_id => <<"perf-cmd">>, plugin => <<"svc">>},
    {TimeUs, {ok, _FanoutRef}} = timer:tc(fun() ->
        yuzu_gw_router:send_command(Ids, Cmd, #{timeout_seconds => 300})
    end),

    TimeMs = TimeUs / 1000,
    %% Dispatching to N agents should complete in bounded time.
    %% Allow 1ms per 100 agents — 10K agents should be under 100ms.
    MaxMs = max(200, N / 100),
    ?assert(TimeMs < MaxMs),

    kill_all(Pids),
    drain_registry().

heartbeat_batch_scale() ->
    %% Verify that the upstream process can buffer many heartbeats
    %% without blocking callers.
    N = 10000,

    %% Defensive unload of grpcbox_channel/grpcbox_client before re-mocking.
    %% setup() at the top of this module mocks only telemetry and does NOT
    %% pre-unload these two — every other test in the file leaves them
    %% alone, so on most discovery orders they are absent. But other test
    %% modules in apps/yuzu_gw/test (circuit_breaker_*, upstream, health,
    %% heartbeat_metrics, perf_helpers→perf_SUITE, integration, e2e,
    %% metrics_e2e, fullstack) all mock grpcbox_client and rely on their
    %% own setup/teardown to balance. If any of them crash mid-test or
    %% are run with `--dir apps/yuzu_gw/test` discovery interleaving
    %% scale_tests after them, grpcbox_client/grpcbox_channel are still
    %% registered when we reach this line and `meck:new` aborts with
    %% `{already_started, <pid>}`. CI Linux saw this on first eunit run
    %% with the full module set; local WSL2 happened to discover scale
    %% before the leakers.
    catch meck:unload(grpcbox_channel),
    catch meck:unload(grpcbox_client),

    %% Mock upstream so it doesn't actually connect.
    meck:new(grpcbox_channel, [non_strict, no_link]),
    meck:expect(grpcbox_channel, pick, fun(_, _) -> {ok, fake_ch} end),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 600000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, N),
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> {ok, _} = yuzu_gw_heartbeat_buffer:start_link();
        _ -> ok
    end,

    %% Queue N heartbeats as fast as possible.
    {TimeUs, _} = timer:tc(fun() ->
        lists:foreach(fun(I) ->
            yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => integer_to_binary(I)})
        end, lists:seq(1, N))
    end),

    %% Queuing 10K heartbeats should be fast (gen_server cast is async).
    TimeMs = TimeUs / 1000,
    ?assert(TimeMs < 2000),

    %% Trigger flush and verify it sends all buffered.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    %% Poll rather than a fixed sleep(200): the buffer must first work through
    %% the N queued casts, and meck records the RPC with an async cast carrying
    %% the whole N-heartbeat batch. On a loaded runner (#4851 runs this suite on
    %% macOS CI, where BigMags shares its CPU between two agents) that can take
    %% longer than 200ms. The check is "the batch holds all N", not "how
    %% fast", so the 5s deadline (above the 2s used elsewhere, for the N-sized
    %% backlog) changes nothing it asserts; a missing RPC still fails below.
    BatchReqsFun = fun() ->
        [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _}
                    <- meck:history(grpcbox_client),
                binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch]
    end,
    _ = wait_until(fun() -> BatchReqsFun() =/= [] end, 5000),

    %% Verify that the batch contained all N heartbeats.
    BatchReqs = BatchReqsFun(),
    case BatchReqs of
        [Req | _] ->
            HBs = maps:get(heartbeats, Req, []),
            ?assertEqual(N, length(HBs));
        [] ->
            ?assert(false, "Expected BatchHeartbeat RPC call")
    end,

    meck:unload([grpcbox_channel, grpcbox_client]).

%%%===================================================================
%%% Helpers
%%%===================================================================

spawn_and_register(N) ->
    spawn_and_register_prefixed(N, <<"scale-">>).

spawn_and_register_prefixed(N, Prefix) ->
    Ids = [iolist_to_binary([Prefix, integer_to_binary(I)]) || I <- lists:seq(1, N)],
    Pids = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, N)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [], <<>>)
    end, lists:zip(Ids, Pids)),
    {Pids, Ids}.

register_silent_agents(N) ->
    Ids = [iolist_to_binary(io_lib:format("silent-~b", [I])) || I <- lists:seq(1, N)],
    Pids = [spawn(fun silent_loop/0) || _ <- lists:seq(1, N)],
    lists:foreach(fun({Id, Pid}) ->
        yuzu_gw_registry:register_agent(Id, Pid, <<"s">>, [<<"svc">>], <<>>)
    end, lists:zip(Ids, Pids)),
    {Pids, Ids}.

silent_loop() ->
    receive
        stop -> ok;
        _    -> silent_loop()
    end.

kill_all(Pids) ->
    lists:foreach(fun(Pid) -> Pid ! stop end, Pids).

wait_until(Fun, Timeout) when Timeout =< 0 ->
    case Fun() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Fun, Timeout) ->
    case Fun() of
        true  -> ok;
        false ->
            timer:sleep(100),
            wait_until(Fun, Timeout - 100)
    end.

collect_all_pages(_Limit, done, Acc) -> Acc;
collect_all_pages(Limit, Cursor, Acc) ->
    {Page, NextCursor} = yuzu_gw_registry:list_agents(Limit, Cursor),
    case Page of
        [] -> Acc;
        _  ->
            Next = case NextCursor of undefined -> done; C -> C end,
            collect_all_pages(Limit, Next, Acc ++ Page)
    end.
