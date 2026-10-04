%%%-------------------------------------------------------------------
%%% @doc Tests for heartbeat status_tags piggybacking through the
%%% gateway's BatchHeartbeat upstream path.
%%%
%%% Verifies that status_tags (yuzu.os, yuzu.arch, yuzu.uptime_s, etc.)
%%% are preserved end-to-end: queued into the heartbeat buffer, batched,
%%% and forwarded in the BatchHeartbeat RPC to the upstream server.
%%%
%%% Mocks grpcbox_client to inspect what the gateway actually sends.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_metrics_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

heartbeat_metrics_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"status_tags are preserved in queued heartbeats", fun tags_preserved/0},
      {"multiple agents with different status_tags", fun multi_agent_tags/0},
      {"status_tags survive buffer retention on failure", fun tags_survive_failure/0},
      {"HA WS-4 4.4 (F3): a real grpc-status error does not crash the buffer",
       fun real_grpc_status_error_does_not_crash/0},
      {"HA WS-4 4.4 (c-1/CH-2): an http_error shape does not crash",
       fun http_error_shape_does_not_crash/0},
      {"empty status_tags heartbeat is valid", fun empty_tags_valid/0},
      {"status_tags are maps not lists", fun tags_are_maps/0}
     ]}.

setup() ->
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    %% Use a long interval so flushes don't happen automatically during tests.
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 600000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 100),
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> ok;
        Old -> catch unlink(Old), catch gen_server:stop(Old, shutdown, 1000)
    end,
    {ok, Pid} = yuzu_gw_heartbeat_buffer:start_link(),
    Pid.

cleanup(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    timer:sleep(50),
    meck:unload([grpcbox_client, telemetry]),
    ok.

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Build a heartbeat map with status_tags for a given agent.
make_heartbeat(SessionId, Tags) ->
    #{session_id => SessionId,
      sent_at => #{millis_epoch => 1700000000000},
      status_tags => Tags}.

%% Standard set of status_tags for a Linux agent.
linux_tags() ->
    #{<<"yuzu.os">> => <<"linux">>,
      <<"yuzu.arch">> => <<"x86_64">>,
      <<"yuzu.uptime_s">> => <<"3600">>,
      <<"yuzu.commands_executed">> => <<"42">>,
      <<"yuzu.plugins_loaded">> => <<"7">>,
      <<"yuzu.agent_version">> => <<"0.3.0">>,
      <<"yuzu.healthy">> => <<"1">>}.

%% Drain any stale heartbeats from prior tests, then reset meck history.
drain_buffer() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    Pid ! flush,
    %% Barrier, not a sleep: the reply proves the drain flush was handled
    %% before meck history is reset (see flush_and_await/0).
    _ = sys:get_state(Pid),
    meck:reset(grpcbox_client).

%% Extract all BatchHeartbeat request maps from meck history.
batch_requests() ->
    Calls = meck:history(grpcbox_client),
    [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
            binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch].

%% Send the buffer a `flush` and wait until its BatchHeartbeat RPC is visible
%% in meck history; returns batch_requests(). Replaces `! flush` followed by a
%% fixed `timer:sleep(100)`, which is an UPPER-bound race on a loaded runner
%% (#4851 runs this suite on macOS CI for the first time; BigMags shares its
%% CPU between two agents, and a fixed sleep has already flaked twice there).
%% Two waits are needed. sys:get_state/1 is a system message queued behind
%% `flush`, so its reply proves the flush handler, and the RPC inside it, has
%% run (and fails the test here if the handler crashed). meck then records the
%% call with an async cast to its own process, so history is polled every 10ms
%% up to a 2s deadline. The callers only claim "the flush sent this batch", so
%% the deadline changes nothing they assert.
flush_and_await() ->
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    Pid ! flush,
    _ = sys:get_state(Pid),
    await_batches(erlang:monotonic_time(millisecond) + 2000).

await_batches(Deadline) ->
    case batch_requests() of
        [] ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> [];
                false -> timer:sleep(10), await_batches(Deadline)
            end;
        Batches ->
            Batches
    end.

%% Set up the unary mock so BatchHeartbeat succeeds and returns ack count.
mock_batch_success() ->
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end).

%%%===================================================================
%%% Tests
%%%===================================================================

tags_preserved() ->
    drain_buffer(),
    mock_batch_success(),

    HB = make_heartbeat(<<"s1">>, linux_tags()),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    %% Trigger flush.
    Batches = flush_and_await(),
    ?assert(length(Batches) > 0),
    [BatchReq | _] = Batches,
    HBs = maps:get(heartbeats, BatchReq, []),
    ?assertEqual(1, length(HBs)),
    [Sent] = HBs,
    SentTags = maps:get(status_tags, Sent),
    ?assertEqual(<<"linux">>, maps:get(<<"yuzu.os">>, SentTags)),
    ?assertEqual(<<"x86_64">>, maps:get(<<"yuzu.arch">>, SentTags)),
    ?assertEqual(<<"3600">>, maps:get(<<"yuzu.uptime_s">>, SentTags)),
    ?assertEqual(<<"42">>, maps:get(<<"yuzu.commands_executed">>, SentTags)),
    ?assertEqual(<<"7">>, maps:get(<<"yuzu.plugins_loaded">>, SentTags)),
    ?assertEqual(<<"0.3.0">>, maps:get(<<"yuzu.agent_version">>, SentTags)),
    ?assertEqual(<<"1">>, maps:get(<<"yuzu.healthy">>, SentTags)).

multi_agent_tags() ->
    drain_buffer(),
    mock_batch_success(),

    HB1 = make_heartbeat(<<"agent-linux">>, #{
        <<"yuzu.os">> => <<"linux">>,
        <<"yuzu.arch">> => <<"x86_64">>,
        <<"yuzu.uptime_s">> => <<"7200">>
    }),
    HB2 = make_heartbeat(<<"agent-win">>, #{
        <<"yuzu.os">> => <<"windows">>,
        <<"yuzu.arch">> => <<"x86_64">>,
        <<"yuzu.uptime_s">> => <<"1800">>
    }),
    HB3 = make_heartbeat(<<"agent-mac">>, #{
        <<"yuzu.os">> => <<"darwin">>,
        <<"yuzu.arch">> => <<"arm64">>,
        <<"yuzu.uptime_s">> => <<"600">>
    }),

    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB1),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB2),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB3),
    timer:sleep(20),

    Batches = flush_and_await(),
    ?assert(length(Batches) > 0),
    [BatchReq | _] = Batches,
    HBs = maps:get(heartbeats, BatchReq, []),
    ?assertEqual(3, length(HBs)),

    %% Build a map of session_id -> status_tags for easy lookup.
    BySession = maps:from_list([{maps:get(session_id, H), maps:get(status_tags, H)} || H <- HBs]),
    ?assertEqual(<<"linux">>,   maps:get(<<"yuzu.os">>, maps:get(<<"agent-linux">>, BySession))),
    ?assertEqual(<<"windows">>, maps:get(<<"yuzu.os">>, maps:get(<<"agent-win">>, BySession))),
    ?assertEqual(<<"darwin">>,  maps:get(<<"yuzu.os">>, maps:get(<<"agent-mac">>, BySession))),
    ?assertEqual(<<"arm64">>,   maps:get(<<"yuzu.arch">>, maps:get(<<"agent-mac">>, BySession))).

tags_survive_failure() ->
    drain_buffer(),

    %% Queue heartbeats with tags.
    HB1 = make_heartbeat(<<"fail1">>, #{<<"yuzu.os">> => <<"linux">>, <<"yuzu.healthy">> => <<"1">>}),
    HB2 = make_heartbeat(<<"fail2">>, #{<<"yuzu.os">> => <<"windows">>, <<"yuzu.healthy">> => <<"0">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB1),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB2),
    timer:sleep(20),

    %% Make flush fail.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = flush_and_await(),

    %% Now make flush succeed and retry.
    meck:reset(grpcbox_client),
    mock_batch_success(),

    Batches = flush_and_await(),
    ?assert(length(Batches) > 0),
    [BatchReq | _] = Batches,
    HBs = maps:get(heartbeats, BatchReq, []),
    ?assertEqual(2, length(HBs)),

    %% Verify tags survived the failure cycle.
    BySession = maps:from_list([{maps:get(session_id, H), maps:get(status_tags, H)} || H <- HBs]),
    ?assertEqual(<<"linux">>,   maps:get(<<"yuzu.os">>, maps:get(<<"fail1">>, BySession))),
    ?assertEqual(<<"1">>,       maps:get(<<"yuzu.healthy">>, maps:get(<<"fail1">>, BySession))),
    ?assertEqual(<<"windows">>, maps:get(<<"yuzu.os">>, maps:get(<<"fail2">>, BySession))),
    ?assertEqual(<<"0">>,       maps:get(<<"yuzu.healthy">>, maps:get(<<"fail2">>, BySession))).

real_grpc_status_error_does_not_crash() ->
    %% HA WS-4 4.4 review fix (F3): grpcbox_client:unary/5's REAL error
    %% shape for a genuine (non-transport) grpc status is a 3-element
    %% tuple — `error` + `{Status, Message}` + a trailers map — verified
    %% against the vendored _checkouts/grpcbox/src/grpcbox_client.erl. The
    %% OLD do_batch_heartbeat/2 error clause matched a shape grpcbox never
    %% actually returns, so a real status like RESOURCE_EXHAUSTED (reachable
    %% today on an oversized batch) would have crashed this process with a
    %% case_clause exception instead of retaining the buffer for the next
    %% flush.
    drain_buffer(),

    HB = make_heartbeat(<<"grpc-status-fail">>, #{<<"yuzu.os">> => <<"linux">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, {<<"8">>, <<"RESOURCE_EXHAUSTED">>}, #{}}
    end),
    _ = flush_and_await(),

    %% The process must still be alive (no case_clause crash) and the
    %% buffer must still hold the heartbeat, exactly like the
    %% transport-level failure path in tags_survive_failure/0.
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),

    meck:reset(grpcbox_client),
    mock_batch_success(),
    Batches = flush_and_await(),
    ?assert(length(Batches) > 0),
    [BatchReq | _] = Batches,
    HBs = maps:get(heartbeats, BatchReq, []),
    ?assertEqual(1, length(HBs)),
    [Sent] = HBs,
    ?assertEqual(<<"grpc-status-fail">>, maps:get(session_id, Sent)).

http_error_shape_does_not_crash() ->
    %% HA WS-4 4.4 round-2 review fix (consistency-auditor c-1 / chaos-injector
    %% CH-2): a FOURTH real grpcbox_client:unary/5 return shape,
    %% `{http_error, {Status, Message}, Trailers}`, was left uncovered by the
    %% F3 fix above despite sharing its root cause.
    drain_buffer(),

    HB = make_heartbeat(<<"http-error-fail">>, #{<<"yuzu.os">> => <<"linux">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {http_error, {502, <<>>}, #{}}
    end),
    _ = flush_and_await(),

    Pid = whereis(yuzu_gw_heartbeat_buffer),
    ?assert(is_pid(Pid)),
    ?assert(is_process_alive(Pid)),

    meck:reset(grpcbox_client),
    mock_batch_success(),
    Batches = flush_and_await(),
    ?assert(length(Batches) > 0),
    [BatchReq | _] = Batches,
    HBs = maps:get(heartbeats, BatchReq, []),
    ?assertEqual(1, length(HBs)),
    [Sent] = HBs,
    ?assertEqual(<<"http-error-fail">>, maps:get(session_id, Sent)).

empty_tags_valid() ->
    drain_buffer(),
    mock_batch_success(),

    HB = make_heartbeat(<<"empty-tags">>, #{}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    Batches = flush_and_await(),
    ?assert(length(Batches) > 0),
    [BatchReq | _] = Batches,
    HBs = maps:get(heartbeats, BatchReq, []),
    ?assertEqual(1, length(HBs)),
    [Sent] = HBs,
    ?assertEqual(#{}, maps:get(status_tags, Sent)).

tags_are_maps() ->
    drain_buffer(),
    mock_batch_success(),

    Tags = linux_tags(),
    HB = make_heartbeat(<<"map-check">>, Tags),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    Batches = flush_and_await(),
    ?assert(length(Batches) > 0),
    [BatchReq | _] = Batches,
    HBs = maps:get(heartbeats, BatchReq, []),
    ?assertEqual(1, length(HBs)),
    [Sent] = HBs,
    SentTags = maps:get(status_tags, Sent),
    ?assert(is_map(SentTags)),
    ?assertNot(is_list(SentTags)).
