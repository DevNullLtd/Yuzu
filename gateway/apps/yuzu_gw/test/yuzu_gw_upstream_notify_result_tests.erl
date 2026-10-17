%%%-------------------------------------------------------------------
%%% @doc A stream-status notification that fails must count against the
%%% upstream, so a lost CONNECTED is recovered (governance
%%% up-6-lost-connected-notification).
%%%
%%% The gateway tells the server about each agent's stream with a
%%% NotifyStreamStatus, sent from a worker process so a slow server cannot
%%% block the upstream process. The worker used to log a failure and exit: its
%%% result never reached the circuit breaker, so
%%%   - failed notifications never opened the breaker, and
%%%   - a notification that failed, followed by a success, never armed the
%%%     registration replay.
%%% A CONNECTED lost to a server that bounced then left an agent that was
%%% connected to the gateway and unknown to the server, with nothing to put it
%%% right until the agent reconnected on its own.
%%%
%%% Real:  yuzu_gw_upstream, yuzu_gw_registry.
%%% Mocks: yuzu_grpc_client (the server), telemetry, yuzu_gw_agent.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_notify_result_tests).
-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 3000).
-define(THRESHOLD, 5).

notify_result_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [t("failed notifications open the breaker, and results that arrive after it opened do not crash",
        fun failed_notifications_open_the_breaker/0),
      t("one failed CONNECTED is held again and retried; its success replays nothing",
        fun a_failed_connected_is_retried_and_replays_nothing/0),
      t("a notification that keeps failing is retried only until the breaker opens, then held",
        fun a_failing_notification_is_retried_until_the_breaker_opens/0),
      t("successful notifications on their own replay nothing",
        fun successful_notifications_replay_nothing/0),
      t("a failed notification for a gRPC status error counts the same as a transport error",
        fun a_grpc_status_error_counts_too/0),
      t("a notification the server refuses as a bad request does not open the breaker",
        fun a_refusal_of_the_request_does_not_count/0),
      t("a result that no tracked worker sent is ignored",
        fun a_result_from_a_stranger_is_ignored/0)]}.

t(Name, Fun) -> {timeout, 30, {Name, Fun}}.

%%--------------------------------------------------------------------
%% The tests
%%--------------------------------------------------------------------

failed_notifications_open_the_breaker() ->
    %% More notifications than the threshold, all in flight together: the
    %% results after the one that trips the breaker reach a breaker that is
    %% already open.
    server_answers(fun(<<"NotifyStreamStatus">>) -> {error, noproc};
                      (_) -> ok
                   end),
    [ok = notify(connected, I) || I <- lists:seq(1, 8)],
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_upstream:circuit_state() =:= open end)),
    ?assertEqual(ok, wait_until(fun notifications_settled/0)),
    %% The process survived the late results.
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%% #5695: a failed send is no longer lost. The CONNECTED is held again and
%% retried at once, and the retry succeeds. A success after a failure says the
%% upstream answers again, not that it lost what it knew: nothing is replayed
%% (it used to replay every agent the gateway holds).
a_failed_connected_is_retried_and_replays_nothing() ->
    Agents = register_agents(2),
    Fails = atomics:new(1, []),
    atomics:put(Fails, 1, 1),
    server_answers(fun(<<"NotifyStreamStatus">>) ->
                           case atomics:sub_get(Fails, 1, 1) of
                               0 -> {error, noproc};
                               _ -> ok
                           end;
                      (_) -> ok
                   end),
    ok = notify(connected, 1),
    ?assertEqual(ok, wait_until(fun() -> notify_count() =:= 2 end)),
    %% Two calls to the upstream and 100 ms: a replay the success had started
    %% (no start jitter here) would have sent its first ProxyRegister by then.
    _ = yuzu_gw_upstream:circuit_state(),
    timer:sleep(100),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(0, proxy_register_count()),
    _ = Agents.

%% The retry is bounded by the breaker: each failure counts, so a notification
%% the server keeps failing is sent at most the threshold number of times, then
%% held behind the open breaker (the half_open probe takes it from there).
a_failing_notification_is_retried_until_the_breaker_opens() ->
    server_answers(fun(<<"NotifyStreamStatus">>) -> {error, noproc};
                      (_) -> ok
                   end),
    ok = notify(connected, 1),
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_upstream:circuit_state() =:= open end)),
    ok = wait_until(fun notifications_settled/0),
    ?assertEqual(?THRESHOLD, notify_count()),
    ?assertMatch(#{notify_inflight := 0}, yuzu_gw_upstream:lane_snapshot()),
    ?assertEqual(1, yuzu_gw_notify_queue:size(element(notify_pending_index(),
                                                      sys:get_state(yuzu_gw_upstream)))).

notify_pending_index() ->
    Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_upstream.erl"]),
    {ok, Forms} = epp:parse_file(Src, []),
    [Fs] = [Fs0 || {attribute, _, record, {state, Fs0}} <- Forms],
    Names = [case F of
                 {typed_record_field, {record_field, _, {atom, _, N}}, _} -> N;
                 {typed_record_field, {record_field, _, {atom, _, N}, _}, _} -> N;
                 {record_field, _, {atom, _, N}} -> N;
                 {record_field, _, {atom, _, N}, _} -> N
             end || F <- Fs],
    [I] = [I || {I, notify_pending} <- lists:zip(lists:seq(2, length(Names) + 1), Names)],
    I.

successful_notifications_replay_nothing() ->
    _ = register_agents(2),
    server_answers(fun(_) -> ok end),
    [ok = notify(connected, I) || I <- lists:seq(1, 3)],
    ok = wait_until(fun() -> notify_count() =:= 3 end),
    ok = wait_until(fun notifications_settled/0),
    %% Room for a replay drip to start, were one wrongly armed.
    timer:sleep(100),
    ?assertEqual(0, proxy_register_count()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

a_grpc_status_error_counts_too() ->
    %% The server answers, but with an error status: the shape of a refused or
    %% overloaded call rather than a dead connection.
    server_answers(fun(<<"NotifyStreamStatus">>) -> {status_error, <<"14">>};
                      (_) -> ok
                   end),
    [ok = notify(disconnected, I) || I <- lists:seq(1, ?THRESHOLD)],
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_upstream:circuit_state() =:= open end)).

a_refusal_of_the_request_does_not_count() ->
    %% INVALID_ARGUMENT (3): the server answered, correctly, that the request
    %% is wrong. That is not a failing server (the breaker counts only server
    %% faults), however many are sent.
    server_answers(fun(<<"NotifyStreamStatus">>) -> {status_error, <<"3">>};
                      (_) -> ok
                   end),
    [ok = notify(connected, I) || I <- lists:seq(1, ?THRESHOLD * 2)],
    ok = wait_until(fun() -> notify_count() =:= ?THRESHOLD * 2 end),
    ok = wait_until(fun notifications_settled/0),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

a_result_from_a_stranger_is_ignored() ->
    %% Only a worker this process started speaks for the upstream.
    Up = whereis(yuzu_gw_upstream),
    [Up ! {notify_result, self(), {error, noproc}} || _ <- lists:seq(1, ?THRESHOLD * 2)],
    %% A call is answered after the messages sent before it were handled.
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

%%--------------------------------------------------------------------
%% Fixture
%%--------------------------------------------------------------------

setup() ->
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_agent),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Leaked    -> catch unlink(Leaked),
                     catch gen_server:stop(Leaked, shutdown, 1000)
    end,
    meck:new(yuzu_grpc_client, [non_strict, no_link]),
    server_answers(fun(_) -> ok end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    %% A replay re-announces through the agent process; the agents here are
    %% stand-ins.
    meck:new(yuzu_gw_agent, [passthrough, no_link]),
    meck:expect(yuzu_gw_agent, reannounce, fun(_, _) -> ok end),
    meck:expect(yuzu_gw_agent, disconnect, fun(_) -> ok end),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, ?THRESHOLD),
    %% Long, so an opened breaker stays open for the length of a test.
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 60000),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 60000),
    application:set_env(yuzu_gw, registration_replay_start_jitter_ms, 0),
    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    UpPid.

cleanup(UpPid) ->
    catch unlink(UpPid),
    catch gen_server:stop(UpPid, shutdown, 5000),
    lists:foreach(fun(Id) -> yuzu_gw_registry:deregister_agent(Id) end,
                  yuzu_gw_registry:all_agents()),
    wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end),
    [Pid ! stop || Pid <- take_dummies()],
    meck:unload([yuzu_grpc_client, telemetry, yuzu_gw_agent]),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 150),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    application:unset_env(yuzu_gw, registration_replay_start_jitter_ms),
    ok.

%% The server's answer by method name: `ok', `{error, Reason}' (a transport
%% error) or `{status_error, GrpcStatus}'.
server_answers(Answer) ->
    meck:expect(yuzu_grpc_client, unary,
                fun(_Meta, Path, _Req, _Def, _Opts) ->
                        Method = lists:last(binary:split(Path, <<"/">>, [global])),
                        case Answer(Method) of
                            ok                    -> {ok, #{accepted => true}, #{}};
                            {error, Reason}       -> {error, Reason};
                            {status_error, Code}  -> {error, {Code, <<"refused">>}, #{}}
                        end
                end).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

notify(Event, I) ->
    yuzu_gw_upstream:notify_stream_status(
      <<"notify-agent-", (integer_to_binary(I))/binary>>,
      <<"notify-session">>, Event, <<"203.0.113.9">>, <<"home">>).

%% Every notification worker has finished and the upstream process has seen its
%% result: the worker sends the result before it exits, and a signal the
%% process receives from one sender arrives in the order it was sent, so the
%% DOWN that frees the slot comes after the result.
notifications_settled() ->
    case yuzu_gw_upstream:lane_snapshot() of
        #{notify_inflight := 0} -> true;
        _ -> false
    end.

calls(Method) ->
    [Req || {_, {yuzu_grpc_client, unary, [_, Path, Req, _, _]}, _}
                <- meck:history(yuzu_grpc_client),
            is_binary(Path), binary:match(Path, Method) =/= nomatch].

notify_count() -> length(calls(<<"NotifyStreamStatus">>)).
proxy_register_requests() -> calls(<<"ProxyRegister">>).
proxy_register_count() -> length(proxy_register_requests()).

register_agents(N) ->
    Prefix = list_to_binary(pid_to_list(self())),
    lists:map(fun(I) ->
        Id  = <<"notify-result-", Prefix/binary, "-", (integer_to_binary(I))/binary>>,
        Req = #{info => #{agent_id => Id, hostname => <<"host">>,
                          plugins => [#{name => <<"svc">>}]},
                enrollment_token => <<"enroll-", Id/binary>>},
        Pid = spawn(fun() -> receive stop -> ok end end),
        remember_dummy(Pid),
        ok = yuzu_gw_registry:register_agent(
               Id, Pid, <<"sess-", Id/binary>>, [<<"svc">>], <<"host">>, Req),
        {Id, Req}
    end, lists:seq(1, N)).

remember_dummy(Pid) ->
    persistent_term:put({?MODULE, dummies}, [Pid | persistent_term:get({?MODULE, dummies}, [])]).

take_dummies() ->
    Pids = persistent_term:get({?MODULE, dummies}, []),
    persistent_term:erase({?MODULE, dummies}),
    Pids.

wait_until(Pred) -> wait_until(Pred, ?WAIT_MS).

wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(10), wait_until(Pred, Timeout - 10)
    end.
