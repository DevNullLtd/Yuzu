%%%-------------------------------------------------------------------
%%% @doc Agent supplied text in log lines (#4632).
%%%
%%% An agent id, a session id header and a command id in a response frame are
%%% text an agent chooses. Written raw with ~s, a carriage return, line feed or
%%% escape in them starts a second log line or recolours a terminal. Every log
%%% line that names such a value passes it through yuzu_gw_env:log_text/1 (cut to
%%% 128 bytes, control characters become `?'). The connect, registered and
%%% notification lines are pinned by the heartbeat-binding and notify-pending
%%% modules, the registration replay lines by the replay module; this module pins
%%% the rest, one group per source file:
%%%   - yuzu_gw_agent: stream error, stream handler died, adopted replay
%%%     re-announce (streaming and connecting), stale re-announce ignored,
%%%     orphaned response, disconnect
%%%   - yuzu_gw_agent_service: Subscribe with a session id nobody registered
%%%   - yuzu_gw_upstream: the guardian forward lines (circuit open, at capacity,
%%%     failed)
%%%
%%% Each test names an agent (or session or command) id made of a marker, CR, LF,
%%% an injected word and ESC, provokes the line, waits for it to be logged (the
%%% capturing handler sends a message before the logging call returns, so the
%%% wait is event driven with a bounded deadline) and requires the line to carry
%%% the marker and none of the raw control characters.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_log_text_sites_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-export([log/2]).  %% logger handler callback (log capture)

-define(LOG_HANDLER, yuzu_gw_log_text_sites_tests_logs).
-define(AWAIT_MS, 5000).
%% The guardian at-capacity fixture: the table of blocked workers and the key that
%% holds the test's pid.
-define(BLOCKED, yuzu_log_text_blocked_workers).
-define(BLOCKED_TEST, {?MODULE, blocked_test_pid}).
%% The agents a test of the agent group started, reaped by its teardown.
-define(STARTED, yuzu_log_text_started).
-define(ENV_KEYS, [circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms]).

%%%===================================================================
%%% yuzu_gw_agent
%%%===================================================================

agent_test_() ->
    {foreach,
     fun setup_agent/0,
     fun cleanup_agent/1,
     [
      t("stream error", fun agent_stream_error_line/0),
      t("stream handler died", fun agent_stream_handler_died_line/0),
      t("adopted replay re-announce (streaming)", fun agent_reannounce_line/0),
      t("adopted replay re-announce (still connecting)", fun agent_connecting_reannounce_line/0),
      t("stale re-announce ignored", fun agent_stale_reannounce_line/0),
      t("orphaned response names the agent and the command id",
        fun agent_orphaned_response_line/0),
      t("disconnect", fun agent_disconnect_line/0)
     ]}.

setup_agent() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(yuzu_gw_upstream),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    catch ets:delete(?STARTED),
    ?STARTED = ets:new(?STARTED, [named_table, public, set]),
    ok.

cleanup_agent(_) ->
    Pids = [P || {P} <- ets:tab2list(?STARTED)],
    Mons = [monitor(process, P) || P <- Pids],
    [exit(P, kill) || P <- Pids],
    [receive {'DOWN', M, process, _, _} -> ok after ?AWAIT_MS -> ok end || M <- Mons],
    ets:delete(?STARTED),
    catch meck:unload(yuzu_gw_upstream),
    ok.

%% An agent started the way the Subscribe handler starts it. The ets table of
%% the fixture records it so teardown can reap it. Registered in the (real)
%% registry under the marker id.
start_agent(Started, Id, StreamPid) ->
    Args = #{agent_id => Id, session_id => <<"sess-", Id/binary>>, stream_pid => StreamPid,
             agent_info => #{agent_id => Id}, peer_addr => <<"peer">>, conn_key => conn_log_text},
    {ok, Agent} = yuzu_gw_agent:start_link(Args),
    unlink(Agent),
    true = ets:insert(Started, {Agent}),
    Agent.

agent_stream_error_line() ->
    Started = started(),
    Id = control_id(<<"agent-err">>),
    Line = capture_line(<<"Stream error for agent">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        Agent ! {stream_error, boom}
    end),
    assert_clean(Line, <<"agent-err">>).

agent_stream_handler_died_line() ->
    Started = started(),
    Id = control_id(<<"agent-died">>),
    Stream = spawn(fun() -> receive stop -> ok end end),
    Line = capture_line(<<"Stream handler died for agent">>, fun() ->
        _ = start_agent(Started, Id, Stream),
        exit(Stream, kill)
    end),
    assert_clean(Line, <<"agent-died">>).

agent_reannounce_line() ->
    Started = started(),
    Id = control_id(<<"agent-reann">>),
    Line = capture_line(<<"upstream adopted replay under session">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        yuzu_gw_agent:reannounce(Agent, <<"sess-", Id/binary>>)
    end, debug),
    assert_clean(Line, <<"agent-reann">>).

%% An agent whose Subscribe handler has not yet reported its stream pid stays in
%% `connecting', which has its own copy of the line.
agent_connecting_reannounce_line() ->
    Started = started(),
    Id = control_id(<<"agent-conn-reann">>),
    Line = capture_line(<<"(still connecting)">>, fun() ->
        Agent = start_agent(Started, Id, undefined),
        yuzu_gw_agent:reannounce(Agent, <<"sess-", Id/binary>>)
    end, debug),
    assert_clean(Line, <<"agent-conn-reann">>).

%% A re-announce for a session this process has moved on from is ignored, and
%% says so under the agent id.
agent_stale_reannounce_line() ->
    Started = started(),
    Id = control_id(<<"agent-stale">>),
    Line = capture_line(<<"ignoring stale upstream_reannounced">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        yuzu_gw_agent:reannounce(Agent, <<"some-other-session">>)
    end, debug),
    assert_clean(Line, <<"agent-stale">>).

%% The command id is read from the response frame, so it is the agent's text too.
agent_orphaned_response_line() ->
    Started = started(),
    Id = control_id(<<"agent-orph">>),
    CmdId = control_id(<<"cmd-orph">>),
    Line = capture_line(<<"Orphaned response from">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        Agent ! {stream_data, #{<<"command_id">> => CmdId}}
    end, debug),
    assert_clean(Line, <<"agent-orph">>),
    ?assertNotEqual(nomatch, binary:match(Line, <<"cmd-orph">>)).

agent_disconnect_line() ->
    Started = started(),
    Id = control_id(<<"agent-disc">>),
    Line = capture_line(<<"disconnected (was connected">>, fun() ->
        Agent = start_agent(Started, Id, self()),
        yuzu_gw_agent:disconnect(Agent)
    end, info),
    assert_clean(Line, <<"agent-disc">>).

started() ->
    ?STARTED.

%%%===================================================================
%%% yuzu_gw_agent_service
%%%===================================================================

service_test_() ->
    {foreach,
     fun() ->
         {ok, _} = application:ensure_all_started(telemetry),
         yuzu_gw_test_registry:ensure(),
         ok
     end,
     fun(_) -> ok end,
     [
      t("Subscribe names the session id nobody registered without raw control characters",
        fun subscribe_unknown_session_line/0)
     ]}.

%% The x-yuzu-session-id header is client text. Subscribe logs it when no
%% registration is pending for it.
subscribe_unknown_session_line() ->
    Session = control_id(<<"session-unknown">>),
    catch meck:unload(grpcbox_stream),
    ok = meck:new(grpcbox_stream, [non_strict, no_link]),
    try
        ok = meck:expect(grpcbox_stream, ctx,
                         fun(_State) ->
                             ctx:set(ctx:background(), md_incoming_key,
                                     #{<<"x-yuzu-session-id">> => Session})
                         end),
        Line = capture_line(<<"Subscribe: no pending registration for session">>, fun() ->
            ?assertThrow({grpc_error, {?GRPC_STATUS_NOT_FOUND, _}},
                         yuzu_gw_agent_service:subscribe(make_ref(), not_a_stream_state))
        end),
        assert_clean(Line, <<"session-unknown">>)
    after
        meck:unload(grpcbox_stream)
    end.

%%%===================================================================
%%% yuzu_gw_upstream: the guardian forward lines
%%%===================================================================

guardian_test_() ->
    {foreach,
     fun setup_guardian/0,
     fun cleanup_guardian/1,
     [
      t("a guardian message dropped because the circuit is open",
        fun guardian_dropped_circuit_open_line/0),
      t("a guardian message the upstream failed to take",
        fun guardian_forward_failed_line/0)
     ]}.

%% The in-flight budget of guardian forwards (50) is full: each worker blocks
%% inside the mocked client until the test releases it.
guardian_capacity_test_() ->
    {foreach,
     fun setup_guardian_blocked/0,
     fun cleanup_guardian_blocked/1,
     [
      t("a guardian message dropped because the in-flight budget is full",
        fun guardian_dropped_at_capacity_line/0)
     ]}.

setup_guardian() ->
    {ok, _} = application:ensure_all_started(telemetry),
    catch meck:unload(grpcbox_client),
    stop_upstream(),
    Prev = [{Key, application:get_env(yuzu_gw, Key)} || Key <- ?ENV_KEYS],
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 600000),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 600000),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) -> {error, econnrefused} end),
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    unlink(Pid),
    #{prev_env => Prev}.

cleanup_guardian(#{prev_env := Prev}) ->
    stop_upstream(),
    catch meck:unload(grpcbox_client),
    lists:foreach(fun({Key, {ok, V}}) -> application:set_env(yuzu_gw, Key, V);
                     ({Key, undefined}) -> application:unset_env(yuzu_gw, Key)
                  end, Prev),
    ok.

%% The mocked client reports each call to the test process and then waits for a
%% release message, so the workers stay in flight for as long as the test needs.
%% The fixture's setup does not run in the test's process (eunit starts the test
%% in its own), so the test registers its pid under ?BLOCKED_TEST for the mock to
%% read at call time, and the workers are kept in a public table the teardown
%% releases (by exact pid) whatever the test did.
setup_guardian_blocked() ->
    {ok, _} = application:ensure_all_started(telemetry),
    catch meck:unload(grpcbox_client),
    stop_upstream(),
    Prev = [{Key, application:get_env(yuzu_gw, Key)} || Key <- ?ENV_KEYS],
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 600000),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 600000),
    catch ets:delete(?BLOCKED),
    ?BLOCKED = ets:new(?BLOCKED, [named_table, public, set]),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:expect(grpcbox_client, unary,
                     fun(_Ctx, _Path, _Req, _Def, _Opts) ->
                         true = ets:insert(?BLOCKED, {self()}),
                         persistent_term:get(?BLOCKED_TEST) ! {guardian_call_entered, self()},
                         receive release_guardian_call -> {error, {<<"3">>, <<"released">>}, #{}}
                         after 60000 -> {error, {<<"3">>, <<"never released">>}, #{}}
                         end
                     end),
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    unlink(Pid),
    #{prev_env => Prev}.

cleanup_guardian_blocked(Ctx) ->
    [W ! release_guardian_call || {W} <- ets:tab2list(?BLOCKED)],
    ets:delete(?BLOCKED),
    catch persistent_term:erase(?BLOCKED_TEST),
    cleanup_guardian(Ctx).

stop_upstream() ->
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Pid       -> catch unlink(Pid),
                     catch gen_server:stop(Pid, shutdown, 5000),
                     ok
    end.

guardian_dropped_circuit_open_line() ->
    Id = control_id(<<"guardian-open">>),
    [{error, _} = yuzu_gw_upstream:proxy_register(#{info => #{agent_id => <<"a">>}})
     || _ <- [1, 2, 3]],
    open = yuzu_gw_upstream:circuit_state(),
    Line = capture_line(<<"Dropping guardian message for">>, fun() ->
        yuzu_gw_upstream:forward_guardian_message(Id, #{})
    end, debug),
    assert_clean(Line, <<"guardian-open">>).

guardian_dropped_at_capacity_line() ->
    ok = persistent_term:put(?BLOCKED_TEST, self()),
    Fill = [yuzu_gw_upstream:forward_guardian_message(<<"filler-", (integer_to_binary(I))/binary>>, #{})
            || I <- lists:seq(1, 50)],
    ?assertEqual(50, length(Fill)),
    %% Every worker is inside the client before the next message is offered.
    Workers = [receive {guardian_call_entered, W} -> W
               after ?AWAIT_MS -> erlang:error(guardian_worker_not_entered)
               end || _ <- Fill],
    Id = control_id(<<"guardian-cap">>),
    try
        Line = capture_line(<<"(at capacity)">>, fun() ->
            yuzu_gw_upstream:forward_guardian_message(Id, #{})
        end, debug),
        assert_clean(Line, <<"guardian-cap">>)
    after
        [W ! release_guardian_call || W <- Workers]
    end.

guardian_forward_failed_line() ->
    Id = control_id(<<"guardian-fail">>),
    Line = capture_line(<<"Failed to forward guardian message for">>, fun() ->
        yuzu_gw_upstream:forward_guardian_message(Id, #{})
    end),
    assert_clean(Line, <<"guardian-fail">>).

%%%===================================================================
%%% Helpers
%%%===================================================================

t(Name, Fun) ->
    {timeout, 30, {Name, Fun}}.

%% The marker, a carriage return, a line feed, an injected word and an escape.
control_id(Marker) ->
    <<"ctl-", Marker/binary, 13, 10, "INJECTED", 27, "[31m">>.

assert_clean(Line, Marker) ->
    ?assertNotEqual(nomatch, binary:match(Line, <<"ctl-", Marker/binary>>)),
    %% A line may still wrap where ~p pretty prints a term, so a bare LF is not
    %% the signal: the injected word after it is.
    [?assertEqual({nomatch, Raw}, {binary:match(Line, Raw), Raw})
     || Raw <- [<<13>>, <<27>>, <<10, "INJECTED">>]].

capture_line(Pattern, Fun) ->
    capture_line(Pattern, Fun, warning).

%% Run Fun with a capturing handler at Level and return the first line that
%% contains Pattern and the marker prefix, waiting (bounded) for it to be logged.
capture_line(Pattern, Fun, Level) ->
    Prev = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, Level),
    catch logger:remove_handler(?LOG_HANDLER),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => Level}),
    try
        flush_logs(),
        Fun(),
        await_line(Pattern, erlang:monotonic_time(millisecond) + ?AWAIT_MS)
    after
        logger:remove_handler(?LOG_HANDLER),
        logger:set_primary_config(level, Prev)
    end.

await_line(Pattern, Deadline) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {captured_log, Text} ->
            case binary:match(Text, Pattern) =/= nomatch
                 andalso binary:match(Text, <<"ctl-">>) =/= nomatch of
                true  -> Text;
                false -> await_line(Pattern, Deadline)
            end
    after Left ->
        erlang:error({line_not_logged, Pattern})
    end.

flush_logs() ->
    receive {captured_log, _} -> flush_logs() after 0 -> ok end.

%% logger handler callback
log(#{msg := Msg, meta := _}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S} -> unicode:characters_to_binary(S);
        {report, R} -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args} -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    Pid ! {captured_log, Text},
    ok.
