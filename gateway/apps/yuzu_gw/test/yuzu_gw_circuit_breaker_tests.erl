%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the upstream circuit breaker.
%%%
%%% Tests the closed -> open -> half_open -> closed state machine,
%%% exponential backoff, and immediate rejection when open.
%%%
%%% Each test gets a fresh upstream process to ensure isolation.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_circuit_breaker_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — foreach restarts upstream between tests
%%%===================================================================

circuit_breaker_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"starts in closed state", fun starts_closed/0},
      {"stays closed on success", fun stays_closed_on_success/0},
      {"opens after threshold failures", fun opens_after_threshold/0},
      {"rejects immediately when open", fun rejects_when_open/0},
      {"transitions to half_open after timeout", fun transitions_to_half_open/0},
      {"closes on successful probe", fun closes_on_probe_success/0},
      {"reopens on failed probe", fun reopens_on_probe_failure/0},
      {"answers that blame the request never open the breaker", fun request_faults_do_not_trip/0},
      {"a request-fault answer from a half-open probe leaves the breaker half open", fun request_fault_probe_leaves_half_open/0},
      {"a request-fault answer neither resets nor extends the run of failures", fun request_fault_leaves_the_run/0},
      {"calls ended by one lost connection count as one failure", fun one_lost_connection_is_one_failure/0},
      {"each lost connection counts, so a server dropping every connection still opens the breaker",
       fun each_lost_connection_counts/0},
      {"the upstream asks the client which connection a call lost (report_conn)",
       fun calls_ask_for_the_lost_connection/0}
     ] ++
     %% The set of request faults is closed and the default is to count: each of
     %% these still opens the breaker. One entry each, so each gets a fresh process.
     [{"status " ++ binary_to_list(Status) ++ " still opens the breaker",
       fun() -> server_fault_trips(Status) end}
      || Status <- [<<"1">>, <<"2">>, <<"4">>, <<"8">>, <<"10">>, <<"7">>, <<"12">>, <<"13">>,
                    <<"14">>, <<"15">>, <<"16">>, <<"unparsed">>]]}.

setup() ->
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(telemetry),
    meck:new(yuzu_grpc_client, [non_strict, no_link]),
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    %% Low threshold for fast testing
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 3),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 200),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Old -> catch unlink(Old), catch gen_server:stop(Old, shutdown, 1000)
    end,
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    Pid.

cleanup(Pid) ->
    %% Synchronous stop — see issue #336 for the race exit/sleep replaces.
    catch unlink(Pid),
    catch gen_server:stop(Pid, shutdown, 5000),
    meck:unload([yuzu_grpc_client, telemetry]),
    ok.

%%%===================================================================
%%% Helper — trip the circuit to open state
%%%===================================================================

trip_circuit() ->
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    _ = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%% The open -> half_open transition is driven by an erlang:send_after timer in
%% yuzu_gw_upstream (the 200ms reset timeout set in setup), so on a loaded
%% runner the timer can fire late, or its message can queue behind this test's
%% circuit_state call. A fixed `timer:sleep(350)` then `half_open` check is an
%% UPPER-bound race of the kind that flaked on the first macOS CI runs (#4841,
%% #4851; BigMags shares its CPU between two agents, and macOS coalesces
%% background timers). Poll every 10ms up to a 2s deadline instead. These tests
%% only claim the transition happens, not when, so the deadline changes
%% nothing they assert (the backoff AMOUNTS are pinned in
%% yuzu_gw_circuit_breaker_nf_tests).
await_state(Want) ->
    poll_state(Want, erlang:monotonic_time(millisecond) + 2000).

poll_state(Want, Deadline) ->
    case yuzu_gw_upstream:circuit_state() of
        Want -> Want;
        Other ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> Other;
                false -> timer:sleep(10), poll_state(Want, Deadline)
            end
    end.

%%%===================================================================
%%% Tests
%%%===================================================================

starts_closed() ->
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

stays_closed_on_success() ->
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"s1">>}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

opens_after_threshold() ->
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    %% Failures 1 and 2 — still closed
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    %% Failure 3 — trips to open
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

rejects_when_open() ->
    trip_circuit(),
    %% Now calls should be rejected immediately without hitting yuzu_grpc_client
    meck:reset(yuzu_grpc_client),
    Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual({error, circuit_open}, Result),
    %% Verify yuzu_grpc_client was NOT called
    ?assertEqual(0, meck:num_calls(yuzu_grpc_client, unary, '_')).

transitions_to_half_open() ->
    trip_circuit(),
    %% Wait for the timer-driven half_open (200ms reset timeout).
    ?assertEqual(half_open, await_state(half_open)).

closes_on_probe_success() ->
    trip_circuit(),
    %% Wait for the timer-driven half_open.
    ?assertEqual(half_open, await_state(half_open)),
    %% Make the probe succeed
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"recovered">>}, #{}}
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()).

reopens_on_probe_failure() ->
    trip_circuit(),
    %% Wait for the timer-driven half_open.
    ?assertEqual(half_open, await_state(half_open)),
    %% Probe fails — should reopen
    {error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%%%===================================================================
%%% A server that answers "your request is wrong" is a healthy server
%%%===================================================================

%% Far more calls than the threshold (3), every one answered with a status
%% that blames the request: the breaker must stay closed.
request_faults_do_not_trip() ->
    [begin
         meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, {Status, <<"no">>}, #{}} end),
         [?assertMatch({error, {Status, _}}, yuzu_gw_upstream:proxy_register(#{info => #{}}))
          || _ <- lists:seq(1, 8)],
         ?assertEqual(closed, yuzu_gw_upstream:circuit_state())
     end || Status <- [<<"3">>, <<"5">>, <<"6">>, <<"9">>, <<"11">>]],
    ok.

server_fault_trips(Status) ->
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, {Status, <<"x">>}, #{}} end),
    [yuzu_gw_upstream:proxy_register(#{info => #{}}) || _ <- lists:seq(1, 3)],
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%% The server answered, so the breaker neither reopens nor closes: it waits for
%% an answer that says something about the upstream.
request_fault_probe_leaves_half_open() ->
    trip_circuit(),
    ?assertEqual(half_open, await_state(half_open)),
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, {<<"3">>, <<"bad">>}, #{}} end),
    ?assertMatch({error, {<<"3">>, _}}, yuzu_gw_upstream:proxy_register(#{info => #{}})),
    ?assertEqual(half_open, yuzu_gw_upstream:circuit_state()).

%% Two real failures, a request-fault answer, then one more real failure: the
%% answer is not a success, so it does not reset the run, and the third failure
%% opens the breaker (threshold 3).
request_fault_leaves_the_run() ->
    Fail = fun() ->
               meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, connection_refused} end),
               yuzu_gw_upstream:proxy_register(#{info => #{}})
           end,
    Answer = fun() ->
                 meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, {<<"3">>, <<"bad">>}, #{}} end),
                 yuzu_gw_upstream:proxy_register(#{info => #{}})
             end,
    Fail(), Fail(), Answer(),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    Fail(),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%% #5695: a connection that closes takes every call on it with it. They are one
%% event, not one failure each: ten calls ended by the same lost connection
%% leave the breaker closed with one failure (threshold 3), and the next call on
%% a new connection succeeds.
one_lost_connection_is_one_failure() ->
    Conn = spawn(fun() -> receive stop -> ok end end),
    meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
        {error, {connection_lost, Conn}}
    end),
    [{error, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}) || _ <- lists:seq(1, 10)],
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertEqual(1, cb_failures()),
    Conn ! stop.

%% A server that keeps dropping connections is still a failing server: each
%% lost connection is a failure, the third opens the breaker.
each_lost_connection_counts() ->
    Conns = [spawn(fun() -> receive stop -> ok end end) || _ <- lists:seq(1, 3)],
    lists:foreach(
      fun(Conn) ->
              meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) ->
                  {error, {connection_lost, Conn}}
              end),
              [_ = yuzu_gw_upstream:proxy_register(#{info => #{}}) || _ <- lists:seq(1, 2)]
      end, Conns),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),
    [C ! stop || C <- Conns].

%% Without report_conn the client returns the bare word, and the breaker could
%% not tell one connection from another.
calls_ask_for_the_lost_connection() ->
    {ok, _} = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    [Opts] = [O || {_, {yuzu_grpc_client, unary, [_, _, _, _, O]}, _}
                       <- meck:history(yuzu_grpc_client)],
    ?assertEqual(true, maps:get(report_conn, Opts, false)).

%% The breaker's run of consecutive failures, read from the state record by
%% field name (the record is private to yuzu_gw_upstream).
cb_failures() ->
    Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_upstream.erl"]),
    {ok, Forms} = epp:parse_file(Src, []),
    [Fs] = [Fs0 || {attribute, _, record, {state, Fs0}} <- Forms],
    Names = [field_name(F) || F <- Fs],
    [I] = [I || {I, cb_failures} <- lists:zip(lists:seq(2, length(Names) + 1), Names)],
    element(I, sys:get_state(yuzu_gw_upstream)).

field_name({typed_record_field, F, _Type}) -> field_name(F);
field_name({record_field, _, {atom, _, Name}}) -> Name;
field_name({record_field, _, {atom, _, Name}, _Default}) -> Name.
