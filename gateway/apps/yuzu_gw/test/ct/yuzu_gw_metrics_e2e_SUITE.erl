%%%-------------------------------------------------------------------
%%% @doc End-to-end test for agent heartbeat metrics piggybacking.
%%%
%%% Tests the full flow: agent sends heartbeat with status_tags →
%%% gateway batches → BatchHeartbeat upstream includes tags.
%%%
%%% Uses mocked upstream (no real C++ server required).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_metrics_e2e_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

%% CT callbacks
-export([all/0, suite/0,
         init_per_suite/1, end_per_suite/1,
         init_per_testcase/2, end_per_testcase/2]).

%% Test cases
-export([
    heartbeat_tags_flow_through_batch/1,
    multiple_agents_tags_in_single_batch/1,
    heartbeat_without_tags_is_valid/1,
    tags_survive_batch_retry/1
]).

%%%===================================================================
%%% CT Callbacks
%%%===================================================================

suite() ->
    [{timetrap, {minutes, 2}}].

all() ->
    [heartbeat_tags_flow_through_batch,
     multiple_agents_tags_in_single_batch,
     heartbeat_without_tags_is_valid,
     tags_survive_batch_retry].

init_per_suite(Config) ->
    application:ensure_all_started(telemetry),
    application:ensure_all_started(gproc),
    %% Use long interval so flushes are manual.
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 60000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 100),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TC, Config) ->
    catch meck:unload(grpcbox_client),
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    catch meck:unload(telemetry),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    catch meck:unload(yuzu_gw_heartbeat_buffer),
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> ok;
        OldHB -> catch gen_server:stop(OldHB, shutdown, 5000), timer:sleep(50)
    end,
    {ok, Pid} = yuzu_gw_heartbeat_buffer:start_link(),
    [{hb_pid, Pid} | Config].

end_per_testcase(_TC, Config) ->
    Pid = proplists:get_value(hb_pid, Config),
    catch unlink(Pid),
    catch exit(Pid, shutdown),
    timer:sleep(50),
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

heartbeat_tags_flow_through_batch(_Config) ->
    %% Queue a heartbeat with full status_tags.
    HB = make_heartbeat(<<"agent-1">>, <<"sess-1">>, #{
        <<"yuzu.os">> => <<"linux">>,
        <<"yuzu.arch">> => <<"x86_64">>,
        <<"yuzu.uptime_s">> => <<"3600">>,
        <<"yuzu.commands_executed">> => <<"42">>,
        <<"yuzu.plugins_loaded">> => <<"7">>,
        <<"yuzu.agent_version">> => <<"0.3.0">>,
        <<"yuzu.healthy">> => <<"1">>
    }),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    %% Set up mock to capture the BatchHeartbeat request.
    Self = self(),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                Self ! {batch_req, Req},
                {ok, #{acknowledged_count => 1}, #{}}
        end
    end),

    %% Flush.
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    receive
        {batch_req, Req} ->
            HBs = maps:get(heartbeats, Req, []),
            ?assert(length(HBs) >= 1),
            [Sent | _] = HBs,
            Tags = maps:get(status_tags, Sent, #{}),
            ?assertEqual(<<"linux">>, maps:get(<<"yuzu.os">>, Tags, undefined)),
            ?assertEqual(<<"x86_64">>, maps:get(<<"yuzu.arch">>, Tags, undefined)),
            ?assertEqual(<<"42">>, maps:get(<<"yuzu.commands_executed">>, Tags, undefined))
    after 3000 ->
        ct:fail("Timed out waiting for BatchHeartbeat")
    end.

multiple_agents_tags_in_single_batch(_Config) ->
    %% Queue heartbeats from 3 agents with different OS tags.
    lists:foreach(fun({AgentId, Os}) ->
        HB = make_heartbeat(AgentId, <<"sess-", AgentId/binary>>, #{
            <<"yuzu.os">> => Os,
            <<"yuzu.healthy">> => <<"1">>
        }),
        yuzu_gw_heartbeat_buffer:queue_heartbeat(HB)
    end, [{<<"a1">>, <<"linux">>},
          {<<"a2">>, <<"windows">>},
          {<<"a3">>, <<"darwin">>}]),
    timer:sleep(20),

    Self = self(),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                Self ! {batch_req, Req},
                {ok, #{acknowledged_count => 3}, #{}}
        end
    end),

    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    receive
        {batch_req, Req} ->
            HBs = maps:get(heartbeats, Req, []),
            ?assertEqual(3, length(HBs)),
            %% All heartbeats should have status_tags.
            lists:foreach(fun(H) ->
                Tags = maps:get(status_tags, H, #{}),
                ?assert(maps:is_key(<<"yuzu.os">>, Tags))
            end, HBs)
    after 3000 ->
        ct:fail("Timed out waiting for BatchHeartbeat")
    end.

heartbeat_without_tags_is_valid(_Config) ->
    %% Queue a heartbeat with empty status_tags.
    HB = #{session_id => <<"sess-empty">>, status_tags => #{}},
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    Self = self(),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                Self ! {batch_req, Req},
                {ok, #{acknowledged_count => 1}, #{}}
        end
    end),

    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    receive
        {batch_req, Req} ->
            HBs = maps:get(heartbeats, Req, []),
            ?assert(length(HBs) >= 1)
    after 3000 ->
        ct:fail("Timed out waiting for BatchHeartbeat")
    end.

tags_survive_batch_retry(_Config) ->
    %% Queue heartbeat with tags.
    HB = make_heartbeat(<<"retry-agent">>, <<"sess-retry">>, #{
        <<"yuzu.os">> => <<"linux">>,
        <<"yuzu.uptime_s">> => <<"100">>
    }),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(HB),
    timer:sleep(20),

    %% Make first flush fail.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(100),

    %% Now make flush succeed and capture.
    Self = self(),
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                Self ! {batch_req, Req},
                {ok, #{acknowledged_count => 1}, #{}}
        end
    end),

    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    receive
        {batch_req, Req} ->
            HBs = maps:get(heartbeats, Req, []),
            ?assert(length(HBs) >= 1),
            [Sent | _] = HBs,
            Tags = maps:get(status_tags, Sent, #{}),
            ?assertEqual(<<"linux">>, maps:get(<<"yuzu.os">>, Tags, undefined)),
            ?assertEqual(<<"100">>, maps:get(<<"yuzu.uptime_s">>, Tags, undefined))
    after 3000 ->
        ct:fail("Timed out waiting for BatchHeartbeat after retry")
    end.

%%%===================================================================
%%% Internal
%%%===================================================================

make_heartbeat(AgentId, SessionId, StatusTags) ->
    #{session_id => SessionId,
      agent_id => AgentId,
      sent_at => #{millis_epoch => erlang:system_time(millisecond)},
      status_tags => StatusTags}.
