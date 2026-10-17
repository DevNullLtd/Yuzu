%%%-------------------------------------------------------------------
%%% @doc What becomes of a Register's registry reservation when the process that
%%% runs the call is stopped from outside.
%%%
%%% The per-RPC process (yuzu_grpc_runner) does not trap exits and the stream
%%% handler stops it with `exit(Pid, shutdown)' whenever the stream ends: the
%%% client reset the stream, the grpc-timeout passed, the connection closed. A
%%% `try ... after' in the service function does not run for that, so the
%%% reservation Register took (a slot of the connection's session quota) would
%%% stay held until the pending TTL sweep, two minutes later. These cases drive
%%% the real stream handler, runner, AgentService and registry (only the upstream
%%% call is replaced, by a call that blocks until the test lets it go) and assert
%%% the reservation is gone as soon as the call is:
%%%
%%%   - a reset stream, an expired deadline and a brutal kill each leave no
%%%     `{reserved, _}' row, and the quota is free for the next Register; with two
%%     Registers in flight on one connection only the stopped one's is released;
%%%   - a Register that completes still commits its pending row, its guard is gone
%%%     and a repeated Register of the same agent works;
%%%   - a guard that fires after the reservation became a pending row removes
%%%     nothing.
%%%
%%% The wait for "the row is gone" is a wait on that condition (with a bound), not
%%% a sleep.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_register_lifecycle_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(REGISTER, <<"/yuzu.agent.v1.AgentService/Register">>).
-define(PENDING, yuzu_gw_pending).
-define(WAIT_MS, 3000).

lifecycle_test_() ->
    [{"a reset stream during a Register frees the reservation at once and the quota with it",
      fun() -> in_conn(fun reset_stream/0) end},
     {"a deadline that passes during a Register frees the reservation at once",
      fun() -> in_conn(fun deadline_passes/0) end},
     {"a brutal kill of the Register process frees the reservation",
      fun() -> in_conn(fun brutal_kill/0) end},
     {"a Register that was reset can be repeated for the same agent",
      fun() -> in_conn(fun retry_after_reset/0) end},
     {"a Register that completes commits its row, leaves no reservation and no guard",
      fun() -> in_conn(fun normal_register_commits/0) end},
     {"a guard that fires after the commit leaves the committed row and its count alone",
      fun() -> in_conn(fun late_guard_leaves_committed_row/0) end},
     {"a guard whose process ends normally after the release does nothing more",
      fun() -> in_conn(fun disarmed_guard_exits/0) end},
     {"two Registers in flight on one connection: the one that is stopped frees only its own reservation",
      fun() -> in_conn(2, fun one_of_two_is_stopped/0) end}].

%%--------------------------------------------------------------------
%% Cases
%%--------------------------------------------------------------------

reset_stream() ->
    {Runner, St} = start_register(<<"agent-a">>),
    await_in_flight(Runner),
    ?assertEqual(1, reserved_rows()),
    %% The client reset the stream: the stream handler ends and stops the runner.
    ok = yuzu_grpc_stream_h:terminate(1, {stream_error, cancel, 'Stream reset by peer.'}, St),
    await_down(Runner),
    await_no_reservations(),
    %% Cap 1: the freed slot admits another agent's Register, which commits.
    {Runner2, St2} = start_register(<<"agent-b">>),
    await_in_flight(Runner2),
    Runner2 ! {upstream_reply, {ok, #{session_id => <<"sess-agent-b">>}}},
    ?assertMatch({0, _}, await_status(Runner2, St2)),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(<<"sess-agent-b">>)).

deadline_passes() ->
    {Runner, St} = start_register(<<"agent-a">>, #{<<"grpc-timeout">> => <<"50m">>}),
    await_in_flight(Runner),
    ?assertEqual(1, reserved_rows()),
    %% The deadline timer the stream armed tells the stream (this process stands
    %% in for the connection); the stream ends with DEADLINE_EXCEEDED and Cowboy
    %% then stops the runner.
    Self = self(),
    receive {{Self, 1}, grpc_deadline} -> ok after ?WAIT_MS -> error(no_deadline) end,
    {Commands, Ended} = yuzu_grpc_stream_h:info(1, grpc_deadline, St),
    ?assertMatch([{response, 200, #{<<"grpc-status">> := <<"4">>}, <<>>}, stop], Commands),
    ok = yuzu_grpc_stream_h:terminate(1, {stop, deadline, <<>>}, Ended),
    await_down(Runner),
    await_no_reservations().

brutal_kill() ->
    {Runner, _St} = start_register(<<"agent-a">>),
    await_in_flight(Runner),
    ?assertEqual(1, reserved_rows()),
    %% Cowboy kills a handler that has not left five seconds after `shutdown'.
    exit(Runner, kill),
    await_down(Runner),
    await_no_reservations().

retry_after_reset() ->
    {Runner, St} = start_register(<<"agent-a">>),
    await_in_flight(Runner),
    ok = yuzu_grpc_stream_h:terminate(1, {stream_error, cancel, x}, St),
    await_no_reservations(),
    {Retry, St2} = start_register(<<"agent-a">>),
    await_in_flight(Retry),
    Retry ! {upstream_reply, {ok, #{session_id => <<"sess-retry">>}}},
    ?assertMatch({0, _}, await_status(Retry, St2)),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(<<"sess-retry">>)),
    ?assertEqual(0, reserved_rows()).

normal_register_commits() ->
    {Runner, St} = start_register(<<"agent-a">>),
    await_in_flight(Runner),
    Runner ! {upstream_reply, {ok, #{session_id => <<"sess-agent-a">>}}},
    ?assertMatch({0, _}, await_status(Runner, St)),
    %% the pending row is the committed registration; nothing is reserved
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(<<"sess-agent-a">>)),
    ?assertEqual(0, reserved_rows()),
    %% the guard was disarmed, not fired: it ends, and the row is still there
    await_until(fun() -> guards() =:= [] end, guard_still_running),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(<<"sess-agent-a">>)),
    %% a repeat of the same agent replaces its row
    {Again, St2} = start_register(<<"agent-a">>),
    await_in_flight(Again),
    Again ! {upstream_reply, {ok, #{session_id => <<"sess-agent-a2">>}}},
    ?assertMatch({0, _}, await_status(Again, St2)),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(<<"sess-agent-a2">>)).

%% The reservation of a Register that committed is gone (the row took its place),
%% so a guard for it releases nothing: the committed row and the count survive.
late_guard_leaves_committed_row() ->
    Key = self(),
    {ok, Reservation} = yuzu_gw_registry:reserve_session(Key, <<"agent-c">>),
    ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"sess-c">>, #{agent_id => <<"agent-c">>,
                                                                       conn_key => Key},
                                                     Reservation)),
    ?assertEqual(0, reserved_rows()),
    Dead = spawn(fun() -> ok end),
    Mon = monitor(process, Dead),
    receive {'DOWN', Mon, process, Dead, _} -> ok end,
    %% returns once the watched process is down, after releasing
    ok = yuzu_gw_agent_service:reservation_guard(Dead, Reservation),
    ?assertMatch({ok, Key}, yuzu_gw_registry:lookup_pending_session(<<"sess-c">>)),
    %% and the quota still counts it: at cap 1 another agent is refused
    ?assertEqual({error, session_limit}, yuzu_gw_registry:reserve_session(Key, <<"agent-d">>)).

%% A guard told to stand down ends without touching the reservation.
disarmed_guard_exits() ->
    Key = self(),
    {ok, Reservation} = yuzu_gw_registry:reserve_session(Key, <<"agent-e">>),
    Watched = spawn(fun() -> receive stop -> ok end end),
    Guard = spawn(yuzu_gw_agent_service, reservation_guard, [Watched, Reservation]),
    Mon = monitor(process, Guard),
    Guard ! {disarm, Watched},
    receive {'DOWN', Mon, process, Guard, normal} -> ok after ?WAIT_MS -> error(guard_alive) end,
    ?assertEqual(1, reserved_rows()),
    exit(Watched, kill),
    ok = yuzu_gw_registry:release_session(Reservation).

%% Two reservations are held on the connection (its quota is two). Stopping one
%% Register releases that one: the other still holds its slot (the quota refuses
%% a third agent while it waits) and then completes and commits its row.
one_of_two_is_stopped() ->
    {RunnerA, StA} = start_register(<<"agent-a">>),
    {RunnerB, StB} = start_register(<<"agent-b">>),
    await_in_flight(RunnerA),
    await_in_flight(RunnerB),
    ?assertEqual(2, reserved_rows()),
    ok = yuzu_grpc_stream_h:terminate(1, {stream_error, cancel, x}, StA),
    await_down(RunnerA),
    await_until(fun() -> reserved_rows() =:= 1 end, reservation_of_stopped_not_released),
    %% the survivor's reservation is its own: one slot is taken, one is free ...
    ?assertEqual([<<"agent-b">>], reserved_agents()),
    {ok, Other} = yuzu_gw_registry:reserve_session(self(), <<"agent-c">>),
    ?assertEqual({error, session_limit}, yuzu_gw_registry:reserve_session(self(), <<"agent-d">>)),
    ok = yuzu_gw_registry:release_session(Other),
    %% ... and its Register still completes
    RunnerB ! {upstream_reply, {ok, #{session_id => <<"sess-agent-b">>}}},
    ?assertMatch({0, _}, await_status(RunnerB, StB)),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(<<"sess-agent-b">>)),
    ?assertEqual(0, reserved_rows()).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

%% Run Fun as the "connection process" of a real stream handler: exits trapped
%% (the runners are linked to it), a real registry with a quota of one session,
%% and an upstream whose Register blocks until the test sends the reply.
in_conn(Fun) ->
    in_conn(1, Fun).

%% Cap is the quota of sessions one connection may hold.
in_conn(Cap, Fun) ->
    {ok, _} = application:ensure_all_started(telemetry),
    OldTrap = process_flag(trap_exit, true),
    Prev = {application:get_env(yuzu_gw, max_sessions_per_connection),
            application:get_env(yuzu_gw, dead_connection_grace_ms)},
    application:set_env(yuzu_gw, max_sessions_per_connection, Cap),
    application:set_env(yuzu_gw, dead_connection_grace_ms, 0),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    catch meck:unload(yuzu_gw_upstream),
    ok = meck:new(yuzu_gw_upstream, [passthrough, no_link]),
    Test = self(),
    ok = meck:expect(yuzu_gw_upstream, proxy_register,
                     fun(_Request, _Opts) ->
                         Test ! {upstream_entered, self()},
                         receive {upstream_reply, Reply} -> Reply end
                     end),
    try
        Fun()
    after
        meck:unload(yuzu_gw_upstream),
        [exit(P, kill) || P <- linked_processes(), is_runner(P)],
        %% The environment goes back BEFORE the registry is made again: it reads
        %% the cap once at start and keeps it in a persistent_term, so a registry
        %% started while the env still says Cap leaves Cap for every later module.
        restore_env(max_sessions_per_connection, element(1, Prev)),
        restore_env(dead_connection_grace_ms, element(2, Prev)),
        yuzu_gw_test_registry:ensure_fresh(),
        unlink(whereis(yuzu_gw_registry)),
        flush(),
        process_flag(trap_exit, OldTrap)
    end,
    %% only reached when the case passed; a failing case raises out of the try
    ?assertEqual(yuzu_gw_env:env_int(max_sessions_per_connection, 8, 1, 1000),
                 persistent_term:get({yuzu_gw_registry, max_sessions_per_connection})).

restore_env(Key, {ok, V}) -> application:set_env(yuzu_gw, Key, V);
restore_env(Key, undefined) -> application:unset_env(yuzu_gw, Key).

linked_processes() ->
    {links, Links} = process_info(self(), links),
    [P || P <- Links, is_pid(P)].

is_runner(Pid) ->
    case proc_lib:initial_call(Pid) of
        {yuzu_grpc_runner, run, _} -> true;
        _ -> false
    end.

flush() ->
    receive _ -> flush() after 0 -> ok end.

start_register(AgentId) ->
    start_register(AgentId, #{}).

%% A Register call as the stream handler starts it: {RunnerPid, StreamState}.
start_register(AgentId, ExtraHeaders) ->
    {ok, Routes} = yuzu_grpc_route:build([agent_pb], #{?SVC => yuzu_gw_agent_service}),
    Env = #{grpc => Routes, auth_fun => undefined, limits => #{}},
    Req = #{method => <<"POST">>, path => ?REGISTER,
            headers => maps:merge(#{<<"content-type">> => <<"application/grpc">>}, ExtraHeaders),
            peer => {{127, 0, 0, 1}, 40000}, cert => undefined, has_body => true},
    {[], St0} = yuzu_grpc_stream_h:init(1, Req, #{env => Env, stream_handlers => []}),
    Frame = yuzu_grpc_frame:encode(
              agent_pb:encode_msg(#{info => #{agent_id => AgentId, hostname => <<"h">>},
                                    enrollment_token => <<"t">>},
                                  'yuzu.agent.v1.RegisterRequest')),
    {[{spawn, Runner, _}, {flow, _}], St} = yuzu_grpc_stream_h:data(1, fin, Frame, St0),
    {Runner, St}.

%% The Register of Runner is waiting for the upstream (its reservation is held).
await_in_flight(Runner) ->
    receive {upstream_entered, Runner} -> ok
    after ?WAIT_MS -> error(register_never_reached_upstream)
    end.

%% Wait until no reservation is held. This is the property, not a mechanism:
%% whatever releases the reservation, it must happen without waiting for the TTL.
await_no_reservations() ->
    await_until(fun() -> reserved_rows() =:= 0 end, reservation_still_held).

%% Wait (up to a bound) for Pred to hold; checked again after every 5 ms.
await_until(Pred, Why) ->
    Deadline = erlang:monotonic_time(millisecond) + ?WAIT_MS,
    await_until(Pred, Why, Deadline).

await_until(Pred, Why, Deadline) ->
    case Pred() of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> error(Why);
                false ->
                    receive after 5 -> ok end,
                    await_until(Pred, Why, Deadline)
            end
    end.

%% The response frame and then the terminal status the runner reported to its
%% "connection", each run through the stream handler as Cowboy would. Returns the
%% status and the stream state.
await_status(Runner, St) ->
    Self = self(),
    receive
        {{Self, 1}, {grpc_frame, Runner, Ack, Frame}} ->
            {_, St1} = yuzu_grpc_stream_h:info(1, {grpc_frame, Runner, Ack, Frame}, St),
            await_end(Runner, St1)
    after ?WAIT_MS ->
        error(runner_sent_no_response)
    end.

await_end(Runner, St) ->
    Self = self(),
    receive
        {{Self, 1}, {grpc_end, Runner, Status, Message}} ->
            {_Commands, St1} = yuzu_grpc_stream_h:info(1, {grpc_end, Runner, Status, Message}, St),
            {Status, St1}
    after ?WAIT_MS ->
        error(runner_reported_no_status)
    end.

await_down(Pid) ->
    Mon = monitor(process, Pid),
    receive {'DOWN', Mon, process, Pid, _} -> ok
    after ?WAIT_MS -> error({still_alive, Pid})
    end.

guards() ->
    [P || P <- processes(), guard_of(P) =/= undefined].

guard_of(Pid) ->
    case proc_lib:initial_call(Pid) of
        {yuzu_gw_agent_service, reservation_guard, [Watched, _Reservation]} -> Watched;
        _ -> undefined
    end.

reserved_rows() ->
    length(ets:match(?PENDING, {{reserved, '_'}, '_', '_'})).

%% The agents that hold a reservation.
reserved_agents() ->
    lists:sort([maps:get(agent_id, Meta)
                || {{reserved, _}, Meta, _} <- ets:tab2list(?PENDING)]).
