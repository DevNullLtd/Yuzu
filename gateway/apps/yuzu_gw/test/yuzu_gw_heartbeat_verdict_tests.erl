%%%-------------------------------------------------------------------
%%% @doc Tests for how yuzu_gw_heartbeat_buffer consumes the server's
%%% unknown-session verdict (#1197): BatchHeartbeatResponse fields
%%% unknown_session_ids (2) and unknown_session_ids_truncated (3).
%%%
%%% The buffer's whole contract is: from either success shape of the
%%% BatchHeartbeat result, take the listed ids, drop the ones that cannot be
%%% session ids (counted as verdict_dropped reason malformed), sort and cap
%%% them, and hand the list to yuzu_gw_upstream:replay_sessions/1 with one
%%% cast. Error results never feed the verdict path. What the upstream then
%%% does with the ids is covered in yuzu_gw_registration_replay_tests.
%%%
%%% Mocks: grpcbox_client, telemetry, yuzu_gw_upstream (replay_sessions/1 is
%%% recorded). All mocks append to an ETS log from the calling process, so a
%%% flush_sync/0 reply (or the sys:get_state/1 barrier after a `flush`
%%% message) proves everything the flush did is already in the log.
%%%
%%% A "nothing happened" assertion always follows a positive control in the
%%% same test, so it cannot hold merely because nothing is wired.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_verdict_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).  %% logger handler callback, see capture_logs/1

-define(LOGK, {?MODULE, log}).
-define(LOG_HANDLER, yuzu_verdict_test_log).
-define(EV_DROP,  [yuzu, gw, heartbeat, verdict_dropped]).
-define(EV_TRUNC, [yuzu, gw, heartbeat, unknown_truncated]).
%% Element position in the buffer's state record (tag at 1).
-define(ST_INTERVAL, 5).

verdict_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"E5 a verdict in the acknowledged_count arm is cast to the upstream",
       fun first_arm_verdict_is_cast/0},
      {"E6 a verdict in the other success arm is cast too, from the timer flush",
       fun second_arm_verdict_is_cast/0},
      {"E6 no key, an empty list or truncated=false casts nothing",
       fun no_verdict_means_no_cast/0},
      {"E7 error results never cast",
       fun error_results_never_cast/0},
      {"E8 truncated=true with a short list casts that list, counts once, warns once",
       fun truncated_short_list_is_cast_and_counted_once/0},
      {"E13 ids that cannot be session ids are dropped as malformed before the cast",
       fun malformed_ids_are_dropped_before_the_cast/0},
      {"ids are deduplicated, sorted and capped at 4096",
       fun ids_are_deduplicated_sorted_and_capped/0},
      {"a verdict with the upstream not running still returns ok",
       fun verdict_with_upstream_not_running_returns_ok/0},
      {"a success body that is not a message is no verdict and the buffer survives",
       fun non_map_body_is_no_verdict/0},
      {"a verdict field of the wrong type is ignored and the buffer survives",
       fun wrong_typed_verdict_fields_are_ignored/0},
      {"the cast is skipped and counted queue_full while the upstream mailbox is over 100",
       fun cast_skipped_while_upstream_queue_is_long/0},
      {"the upstream mailbox check is harmless when the process is gone",
       fun queue_check_with_dead_upstream_still_casts/0},
      {"a flush interval outside 100..60000 or not an integer falls back with a warning",
       fun interval_invalid_falls_back/0},
      {"a flush interval inside 100..60000 is kept",
       fun interval_valid_is_kept/0}
     ]}.

setup() ->
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_upstream),
    persistent_term:put(?LOGK, ets:new(verdict_test_log, [public, ordered_set])),
    meck:new(grpcbox_client, [non_strict, no_link]),
    set_result({ok, #{acknowledged_count => 0}, #{}}),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(Event, Meas, Meta) ->
        rec({event, Event, Meas, Meta}),
        ok
    end),
    %% The real upstream must not be running: the buffer talks to the mock.
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Leaked    -> catch unlink(Leaked),
                     catch gen_server:stop(Leaked, shutdown, 1000)
    end,
    meck:new(yuzu_gw_upstream, [passthrough, no_link]),
    meck:expect(yuzu_gw_upstream, replay_sessions, fun(Ids) ->
        rec({cast, Ids}),
        ok
    end),
    %% A long interval: flushes only happen when the test asks for one.
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 60000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 100),
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> ok;
        Old -> catch unlink(Old), catch gen_server:stop(Old, shutdown, 1000)
    end,
    {ok, Pid} = yuzu_gw_heartbeat_buffer:start_link(),
    Pid.

cleanup(_SetupPid) ->
    %% Tests that restart the buffer leave the current one registered.
    stop_buffer(),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Standin   -> exit(Standin, kill)
    end,
    catch meck:unload([grpcbox_client, telemetry, yuzu_gw_upstream]),
    persistent_term:erase(?LOGK),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

%% flush_sync/0 runs the same do_flush/2 as the timer, so this is the first
%% success arm (the result carries acknowledged_count).
first_arm_verdict_is_cast() ->
    S1 = <<"verdict-session-1">>,
    ?assertEqual(ok, flush_sync({ok, #{acknowledged_count => 0,
                                       unknown_session_ids => [S1]}, #{}})),
    ?assertEqual([[S1]], casts()).

%% No acknowledged_count key: the second success arm. Driven by the `flush`
%% message the timer sends; the barrier proves the flush has been handled.
second_arm_verdict_is_cast() ->
    S1 = <<"verdict-session-2">>,
    flush_msg({ok, #{unknown_session_ids => [S1, <<>>]}, #{}}),
    ?assertEqual([[S1]], casts()),
    ?assertEqual(1, dropped(malformed)).

no_verdict_means_no_cast() ->
    Control = <<"verdict-control">>,
    ok = flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => [Control]}, #{}}),
    ?assertEqual([[Control]], casts()),
    NoVerdict = [{ok, #{acknowledged_count => 5}, #{}},
                 {ok, #{acknowledged_count => 0, unknown_session_ids => []}, #{}},
                 {ok, #{unknown_session_ids => []}, #{}},
                 {ok, #{}, #{}},
                 {ok, #{acknowledged_count => 1, unknown_session_ids => [],
                        unknown_session_ids_truncated => false}, #{}}],
    [ok = flush_sync(R) || R <- NoVerdict],
    flush_msg({ok, #{acknowledged_count => 2}, #{}}),
    ?assertEqual([[Control]], casts()),
    ?assertEqual([], events(?EV_TRUNC)),
    ?assertEqual(0, dropped(malformed)).

%% The three error shapes do_flush/2 handles. Their ids cannot exist (an
%% error carries no response), so the check is that the flush neither casts
%% nor crashes the buffer and keeps its heartbeats for the retry.
error_results_never_cast() ->
    Control = <<"verdict-control-e7">>,
    ok = flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => [Control]}, #{}}),
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    [?assertMatch({error, _}, flush_sync(R))
     || R <- [{error, econnrefused},
              {error, {<<"14">>, <<"unavailable">>}, #{}},
              {http_error, {<<"502">>, <<"bad gateway">>}, #{}}]],
    flush_msg({error, econnrefused}),
    ?assertEqual([[Control]], casts()),
    ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)),
    ?assertEqual([], events(?EV_TRUNC)),
    ?assertEqual(0, dropped(malformed)).

%% truncated=true says the server listed fewer ids than it knows. The buffer
%% replays what was listed (the rest arrive in later heartbeats), counts the
%% flush once and logs one warning; it never asks for a full replay.
truncated_short_list_is_cast_and_counted_once() ->
    S1 = <<"verdict-session-t">>,
    {Result, Lines} = capture_logs(fun() ->
        flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => [S1],
                          unknown_session_ids_truncated => true}, #{}})
    end),
    ?assertEqual(ok, Result),
    ?assertEqual([[S1]], casts()),
    ?assertEqual([#{count => 1}], [M || {M, _} <- events(?EV_TRUNC)]),
    ?assertMatch([_], [T || {warning, T} <- Lines,
                            binary:match(T, <<"omitted sessions may be reported by "
                                              "subsequent heartbeats">>) =/= nomatch]),
    %% The same list without the flag is cast but not counted.
    ok = flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => [S1]}, #{}}),
    ?assertEqual([[S1], [S1]], casts()),
    ?assertEqual(1, length(events(?EV_TRUNC))).

%% Valid ids are binaries of 1 to 64 bytes. The codec never produces anything
%% else; a mock or a future codec could, and the buffer is the only place
%% that can count what it drops.
malformed_ids_are_dropped_before_the_cast() ->
    Good = <<"good-session">>,
    Max = binary:copy(<<"b">>, 64),
    TooLong = binary:copy(<<"a">>, 65),
    ok = flush_sync({ok, #{acknowledged_count => 0,
                           unknown_session_ids => [Good, <<>>, TooLong, 42, some_atom, Max, <<"c">>]},
                     #{}}),
    ?assertEqual([lists:usort([Good, Max, <<"c">>])], casts()),
    ?assertEqual(4, dropped(malformed)).

ids_are_deduplicated_sorted_and_capped() ->
    Ids = [iolist_to_binary(io_lib:format("sess-~5..0b", [N])) || N <- lists:seq(1, 5000)],
    Listed = lists:reverse(Ids) ++ [hd(Ids), hd(Ids)],
    ok = flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => Listed}, #{}}),
    ?assertEqual([lists:sublist(Ids, 4096)], casts()),
    ?assertEqual(0, dropped(malformed)).

%% A cast to a process that is not running is a no-op, so the flush result
%% does not depend on the upstream. The malformed count shows the verdict was
%% consumed all the same.
verdict_with_upstream_not_running_returns_ok() ->
    meck:unload(yuzu_gw_upstream),
    ?assertEqual(undefined, whereis(yuzu_gw_upstream)),
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    ?assertEqual(ok, flush_sync({ok, #{acknowledged_count => 0,
                                       unknown_session_ids => [<<"session-u">>, <<>>]},
                                 #{}})),
    ?assert(is_process_alive(Pid)),
    ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)),
    ?assertEqual(1, dropped(malformed)).

%% grpcbox returns {ok, <<>>, Trailers} for an OK with trailers and no DATA
%% frame, which reaches the second success arm. Before the guard this raised
%% badmap inside the buffer and lost every heartbeat it held. The buffered
%% heartbeat is still counted as flushed (flush returns ok, buffer emptied).
non_map_body_is_no_verdict() ->
    Control = <<"verdict-control-nm">>,
    ok = flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => [Control]}, #{}}),
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    [begin
         ?assertEqual(ok, flush_sync({ok, Body, #{}})),
         flush_msg({ok, Body, #{}}),
         ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)),
         ?assert(is_process_alive(Pid))
     end || Body <- [<<>>, not_a_map, [], 42]],
    ?assertEqual([[Control]], casts()),
    ?assertEqual([], events(?EV_TRUNC)),
    ?assertEqual(0, dropped(malformed)),
    %% The buffer still works after all of that.
    S1 = <<"verdict-after-nm">>,
    ok = flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => [S1]}, #{}}),
    ?assertEqual([[Control], [S1]], casts()).

%% A map whose verdict fields have the wrong type, in both success arms: no
%% cast, no event, buffer alive. A non-boolean truncated flag is not `true'.
wrong_typed_verdict_fields_are_ignored() ->
    Control = <<"verdict-control-wt">>,
    ok = flush_sync({ok, #{acknowledged_count => 0, unknown_session_ids => [Control]}, #{}}),
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    Bad = [#{unknown_session_ids => not_a_list},
           #{unknown_session_ids => <<"abc">>},
           #{unknown_session_ids => [<<"improper">> | <<"tail">>]},
           #{unknown_session_ids_truncated => <<"true">>},
           #{unknown_session_ids_truncated => 1}],
    [begin
         ?assertEqual(ok, flush_sync({ok, Body#{acknowledged_count => 0}, #{}})),
         ?assertEqual(ok, flush_sync({ok, Body, #{}})),
         flush_msg({ok, Body, #{}}),
         ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer))
     end || Body <- Bad],
    ?assertEqual([[Control]], casts()),
    ?assertEqual([], events(?EV_TRUNC)),
    ?assertEqual(0, dropped(malformed)).

%% The bound on the upstream mailbox does not depend on configuration. A
%% stand-in registered as yuzu_gw_upstream never reads its mailbox, so its
%% length is exactly what the test put there. At 100 messages the cast goes
%% (the positive control); at 101 it is skipped, the ids are counted as
%% queue_full and one debug line says so, without naming an id.
cast_skipped_while_upstream_queue_is_long() ->
    Dummy = register_upstream_stand_in(),
    S1 = <<"verdict-session-q1">>,
    S2 = <<"verdict-session-q2">>,
    Verdict = {ok, #{acknowledged_count => 0, unknown_session_ids => [S2, S1]}, #{}},
    [Dummy ! filler || _ <- lists:seq(1, 100)],
    ?assertEqual({message_queue_len, 100}, process_info(Dummy, message_queue_len)),
    ok = flush_sync(Verdict),
    ?assertEqual([[S1, S2]], casts()),
    ?assertEqual(0, dropped(queue_full)),
    Dummy ! filler,
    {_, Lines} = capture_logs(fun() -> ok = flush_sync(Verdict) end, debug),
    ?assertEqual([[S1, S2]], casts()),
    ?assertEqual(2, dropped(queue_full)),
    Named = [T || {debug, T} <- Lines, binary:match(T, <<"upstream queue is 101">>) =/= nomatch],
    ?assertMatch([_], Named),
    ?assertEqual([], [T || T <- Named, binary:match(T, <<"verdict-session">>) =/= nomatch]),
    %% The mailbox drains: casting resumes.
    drain(Dummy),
    ok = flush_sync(Verdict),
    ?assertEqual([[S1, S2], [S1, S2]], casts()),
    ?assertEqual(2, dropped(queue_full)),
    stop_stand_in(Dummy).

%% The mailbox length is read from a registered pid that may be gone: a
%% name nobody holds, or a process that has just died, never costs the cast.
queue_check_with_dead_upstream_still_casts() ->
    Dummy = register_upstream_stand_in(),
    [Dummy ! filler || _ <- lists:seq(1, 500)],
    S1 = <<"verdict-session-dead">>,
    Verdict = {ok, #{acknowledged_count => 0, unknown_session_ids => [S1]}, #{}},
    ok = flush_sync(Verdict),
    ?assertEqual([], casts()),
    stop_stand_in(Dummy),
    ?assertEqual(undefined, whereis(yuzu_gw_upstream)),
    ok = flush_sync(Verdict),
    ?assertEqual([[S1]], casts()),
    ?assertEqual(1, dropped(queue_full)).

%% heartbeat_batch_interval_ms is read once in init/1. Anything but an
%% integer in 100..60000 falls back to 1000 and warns, naming the key.
interval_invalid_falls_back() ->
    [interval_case(Bad, 1000, invalid)
     || Bad <- [-1, 0, 99, 60001, 600000, 1.5, foo, <<"1000">>, "1000"]],
    ok.

interval_valid_is_kept() ->
    [interval_case(V, V, valid) || V <- [100, 1000, 60000]],
    ok.

interval_case(Val, Expected, Kind) ->
    stop_buffer(),
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, Val),
    try
        {Pid, Lines} = capture_logs(fun() ->
            {ok, P} = yuzu_gw_heartbeat_buffer:start_link(),
            unlink(P),
            P
        end),
        ?assertEqual(Expected, element(?ST_INTERVAL, sys:get_state(Pid))),
        Named = [T || {warning, T} <- Lines,
                      binary:match(T, <<"heartbeat_batch_interval_ms">>) =/= nomatch],
        case Kind of
            invalid -> ?assertMatch([_], Named);
            valid   -> ?assertEqual([], Named)
        end
    after
        stop_buffer(),
        application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 60000),
        {ok, P2} = yuzu_gw_heartbeat_buffer:start_link(),
        unlink(P2)
    end.

%%%===================================================================
%%% Helpers
%%%===================================================================

stop_buffer() ->
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> ok;
        Pid -> catch unlink(Pid), catch gen_server:stop(Pid, normal, 2000), ok
    end.

%% A process registered as yuzu_gw_upstream that never reads its mailbox.
register_upstream_stand_in() ->
    Pid = spawn(fun stand_in_loop/0),
    true = register(yuzu_gw_upstream, Pid),
    Pid.

stand_in_loop() ->
    receive
        stop  -> ok;
        drain -> drain_filler(), stand_in_loop()
    end.

drain_filler() ->
    receive filler -> drain_filler() after 0 -> ok end.

%% Empty the stand-in's mailbox of filler and wait until it has.
drain(Pid) ->
    Pid ! drain,
    wait_until(fun() -> process_info(Pid, message_queue_len) =:= {message_queue_len, 0} end).

stop_stand_in(Pid) ->
    Ref = monitor(process, Pid),
    Pid ! stop,
    receive {'DOWN', Ref, process, Pid, _} -> ok after 2000 -> error(stand_in_did_not_stop) end.

wait_until(Pred) ->
    case Pred() of
        true  -> ok;
        false -> erlang:yield(), wait_until(Pred)
    end.


%% Make the next BatchHeartbeat rpc return Result.
set_result(Result) ->
    meck:expect(grpcbox_client, unary, fun(_Ctx, _Path, _Req, _Def, _Opts) -> Result end).

%% Queue one heartbeat and flush it through flush_sync/0. The cast and the
%% call come from this process, so the flush sees the heartbeat.
flush_sync(Result) ->
    set_result(Result),
    queue_one(),
    yuzu_gw_heartbeat_buffer:flush_sync().

%% Same, through the `flush` message the timer sends. The sys:get_state/1
%% reply is queued behind it, so it proves the flush was handled.
flush_msg(Result) ->
    set_result(Result),
    queue_one(),
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    Pid ! flush,
    _ = sys:get_state(Pid),
    ok.

queue_one() ->
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"hb-session">>,
                                               sent_at => #{millis_epoch => 1700000000000}}).

rec(Entry) ->
    case persistent_term:get(?LOGK, undefined) of
        undefined -> ok;
        Tid ->
            Key = erlang:unique_integer([monotonic]),
            try ets:insert(Tid, {Key, Entry}) catch error:badarg -> ok end,
            ok
    end.

entries() ->
    [E || {_, E} <- ets:tab2list(persistent_term:get(?LOGK))].

casts() ->
    [Ids || {cast, Ids} <- entries()].

events(Name) ->
    [{Meas, Meta} || {event, N, Meas, Meta} <- entries(), N =:= Name].

norm(A) when is_atom(A) -> atom_to_binary(A, utf8);
norm(B) -> B.

%% Sum of the verdict_dropped counts with this reason.
dropped(Reason) ->
    R = atom_to_binary(Reason, utf8),
    lists:sum([maps:get(count, M, 0)
               || {M, Meta} <- events(?EV_DROP), norm(maps:get(reason, Meta, undefined)) =:= R]).

%% Run Fun with a capturing logger handler at info level (or Level); returns
%% {FunResult, [{Level, Text}]}. The handler is VM-wide: callers filter.
capture_logs(Fun) ->
    capture_logs(Fun, info).

capture_logs(Fun, Level) ->
    Prev = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, Level),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => Level}),
    try
        Result = Fun(),
        {Result, collect_logs([])}
    after
        logger:remove_handler(?LOG_HANDLER),
        logger:set_primary_config(level, Prev)
    end.

%% The handler runs in the logging process and sends before the logging call
%% returns; the capture body waits for the flush, so every line is in the
%% mailbox already.
collect_logs(Acc) ->
    receive {captured_log, Level, Text} -> collect_logs([{Level, Text} | Acc])
    after 0 -> lists:reverse(Acc)
    end.

%% logger handler callback
log(#{level := Level, msg := Msg}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S} -> unicode:characters_to_binary(S);
        {report, R} -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args} -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    Pid ! {captured_log, Level, Text},
    ok.
