%%%-------------------------------------------------------------------
%%% @doc /readyz reads the circuit breaker without waiting for the upstream
%%% process (#5680, governance up-5).
%%%
%%% yuzu_gw_upstream runs the proxied RPCs inline, one at a time. A readiness
%%% check that asked it for the breaker state by a call queued behind the RPC in
%%% progress, so against a slow server it waited out the call's 5 s timeout and
%%% reported the breaker open: /readyz answered 503 with the breaker closed, and a
%%% load balancer took every gateway out behind one slow server.
%%%
%%% Real:  yuzu_gw_upstream, yuzu_gw_health, yuzu_gw_registry.
%%% Mocks: yuzu_grpc_client (the server), telemetry, yuzu_gw_agent.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_readyz_breaker_tests).
-include_lib("eunit/include/eunit.hrl").

-define(WAIT_MS, 3000).
%% How long a readiness answer may take while the upstream is inside a slow
%% RPC. Far below the 5 s timeout of a call into the upstream process, which is
%% what the check used to wait for.
-define(READYZ_BUDGET_US, 2000000).

-define(ENV_KEYS, [health_port, grpc_listeners, allow_no_listeners,
                   circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms,
                   registration_replay_spacing_ms,
                   registration_replay_session_guard_ms,
                   notify_probe_timeout_ms]).

readyz_breaker_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{"readyz reports the closed breaker at once while the upstream is inside a slow RPC",
       {timeout, 30, fun readyz_answers_while_the_upstream_is_in_a_slow_rpc/0}},
      {"the published breaker state equals the process's own through every transition",
       {timeout, 60, fun published_state_follows_every_transition/0}}]}.

%%--------------------------------------------------------------------
%% The tests
%%--------------------------------------------------------------------

%% The upstream process is inside a ProxyRegister the server has not answered
%% (the mocked client blocks until released), with a second call queued behind
%% it. The breaker is closed the whole time: nothing has failed.
readyz_answers_while_the_upstream_is_in_a_slow_rpc() ->
    {ok, Port} = yuzu_gw_health:port(),
    server_answers(fun(_) -> block end),
    First = spawn_register(<<"slow-1">>),
    Worker = await_rpc(<<"ProxyRegister">>),
    %% The RPC runs in the upstream process itself, not in a worker.
    ?assertEqual(whereis(yuzu_gw_upstream), Worker),
    Second = spawn_register(<<"slow-2">>),
    await_queued(Worker, 1),
    {Micros, {Status, Body}} = timer:tc(fun() -> http_get(Port, "/readyz") end),
    Worker ! go,
    ?assertEqual(Worker, await_rpc(<<"ProxyRegister">>)),
    Worker ! go,
    await_reply(First),
    await_reply(Second),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    ?assertNotEqual(nomatch, binary:match(Body, <<"\"circuit_breaker\":true">>),
                    {Status, Body, Micros}),
    ?assert(Micros < ?READYZ_BUDGET_US).

%% Drive the breaker through every transition the code can make, by every path
%% that makes it, and after each one compare the state read without a call
%% (circuit_state_now/0, what /readyz reads) with the state the process holds
%% (circuit_state/0). The breaker state is assigned at four places in
%% yuzu_gw_upstream (init, the half_open timer, on_success from half_open,
%% trip_circuit); each path below ends in one of them, and each of the four is
%% reached at least once after the published value last differed from it, so
%% removing any one publication fails a comparison.
published_state_follows_every_transition() ->
    Up0 = whereis(yuzu_gw_upstream),

    %% init: a fresh process is closed.
    same(closed),

    %% closed -> open: proxied calls the server fails (trip_circuit).
    server_answers(fun(_) -> fail end),
    trip(),
    same(open),

    %% open -> half_open: the reset timer's message.
    half_open(),
    same(half_open),

    %% half_open -> closed: a proxied call succeeds (on_success from half_open).
    server_answers(fun(_) -> ok end),
    {ok, _} = yuzu_gw_upstream:proxy_register(req(<<"call-probe">>)),
    same(closed),

    %% half_open -> open: a proxied call fails (on_failure from half_open).
    server_answers(fun(_) -> fail end),
    trip(),
    half_open(),
    same(half_open),
    {error, _} = yuzu_gw_upstream:proxy_register(req(<<"call-probe">>)),
    same(open),

    %% closed -> open by the stream-status notifications a closed breaker sends
    %% (the notify_result path, up-6): no proxied call is made.
    server_answers(fun(_) -> ok end),
    half_open(),
    {ok, _} = yuzu_gw_upstream:proxy_register(req(<<"call-probe">>)),
    same(closed),
    meck:reset(yuzu_grpc_client),
    server_answers(fun(<<"NotifyStreamStatus">>) -> fail; (_) -> ok end),
    [notify(I) || I <- [1, 2]],
    await_state(open),
    ?assertEqual(0, rpc_count(<<"ProxyRegister">>)),
    same(open),

    %% half_open -> closed by the notification probe: the notification held while
    %% the breaker was open is sent when it half-opens, and succeeds.
    notify(3),
    meck:reset(yuzu_grpc_client),
    server_answers(fun(_) -> ok end),
    half_open(),
    await_state(closed),
    ?assertEqual(1, rpc_count(<<"NotifyStreamStatus">>)),
    ?assertEqual(0, rpc_count(<<"ProxyRegister">>)),
    same(closed),

    %% half_open -> open by the notification probe failing.
    server_answers(fun(_) -> fail end),
    trip(),
    notify(4),
    meck:reset(yuzu_grpc_client),
    half_open(),
    await_state(open),
    ?assertEqual(1, rpc_count(<<"NotifyStreamStatus">>)),
    same(open),

    %% half_open -> open by the notification probe's deadline: the server never
    %% answers it and it is killed after notify_probe_timeout_ms. The failed
    %% probe gave its notification back, so it is the probe again.
    meck:reset(yuzu_grpc_client),
    server_answers(fun(_) -> block end),
    half_open(),
    _Probe = await_rpc(<<"NotifyStreamStatus">>),
    await_state(open),
    same(open),

    %% A restart: the new process is closed, whatever the one before it was. Its
    %% held notifications go with it, so nothing below is a notification probe.
    ?assertEqual(Up0, whereis(yuzu_gw_upstream)),
    stop_named(yuzu_gw_upstream),
    ?assertEqual(undefined, whereis(yuzu_gw_upstream)),
    ?assertExit({noproc, _}, yuzu_gw_upstream:circuit_state_now()),
    ?assertExit({noproc, _}, yuzu_gw_upstream:circuit_state()),
    _ = yuzu_gw_test_upstream:start_upstream(),
    same(closed),

    %% half_open -> closed by the registration replay a heartbeat verdict asks
    %% for: the replayed ProxyRegister is the probe (record_result_no_replay).
    [S1, S2] = register_agents(2),
    server_answers(fun(_) -> fail end),
    trip(),
    half_open(),
    meck:reset(yuzu_grpc_client),
    server_answers(fun(_) -> ok end),
    ok = yuzu_gw_upstream:replay_sessions([S1]),
    await_state(closed),
    ?assertEqual([S1], replayed_sessions()),
    same(closed),

    %% closed -> open by failed replays of a verdict.
    meck:reset(yuzu_grpc_client),
    server_answers(fun(_) -> fail end),
    ok = yuzu_gw_upstream:replay_sessions([S1, S2]),
    await_state(open),
    ?assertEqual([S1, S2], replayed_sessions()),
    same(open),

    %% half_open -> open by a failed replay.
    half_open(),
    same(half_open),
    meck:reset(yuzu_grpc_client),
    ok = yuzu_gw_upstream:replay_sessions([S2]),
    await_state(open),
    ?assertEqual([S2], replayed_sessions()),
    same(open).

%%--------------------------------------------------------------------
%% Fixture
%%--------------------------------------------------------------------

setup() ->
    Env = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    stop_named(yuzu_gw_health),
    stop_named(yuzu_gw_upstream),
    %% A fresh registry: a breaker recovery replays every agent the registry
    %% holds, and an agent left by another module would add RPCs this module
    %% does not expect.
    yuzu_gw_test_registry:ensure_fresh(),
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_agent),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    server_answers(fun(_) -> ok end),
    ok = meck:new(telemetry, [passthrough, no_link]),
    ok = meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    ok = meck:new(yuzu_gw_agent, [passthrough, no_link]),
    ok = meck:expect(yuzu_gw_agent, reannounce, fun(_, _) -> ok end),
    ok = meck:expect(yuzu_gw_agent, disconnect, fun(_) -> ok end),
    application:set_env(yuzu_gw, health_port, 0),
    application:unset_env(yuzu_gw, grpc_listeners),
    application:set_env(yuzu_gw, allow_no_listeners, true),
    %% Two failures open the breaker; the reset timer is out of reach, so a test
    %% moves the breaker to half_open itself, with the timer's own message.
    ok = yuzu_gw_test_upstream:set_breaker_env(2),
    application:set_env(yuzu_gw, registration_replay_spacing_ms, 1),
    application:set_env(yuzu_gw, registration_replay_session_guard_ms, 0),
    application:set_env(yuzu_gw, notify_probe_timeout_ms, 100),
    _ = yuzu_gw_test_upstream:start_upstream(),
    {ok, Health} = yuzu_gw_health:start_link(),
    unlink(Health),
    Env.

cleanup(Env) ->
    stop_named(yuzu_gw_health),
    stop_named(yuzu_gw_upstream),
    catch [yuzu_gw_registry:deregister_agent(Id) || Id <- yuzu_gw_registry:all_agents()],
    [Pid ! stop || Pid <- take_dummies()],
    catch meck:unload([yuzu_grpc_client, telemetry, yuzu_gw_agent]),
    yuzu_gw_test_upstream:restore_env(Env),
    flush(),
    ok.

%% The server's answer by method name: `ok', `fail' (a transport error) or
%% `block' (no answer until the RPC's process is sent `go'; the process first
%% tells the test it is there).
server_answers(Answer) ->
    Test = self(),
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, Path, _Req, _Def, _Opts) ->
                             Method = lists:last(binary:split(Path, <<"/">>, [global])),
                             case Answer(Method) of
                                 ok    -> {ok, #{accepted => true}, #{}};
                                 fail  -> {error, econnrefused};
                                 block -> Test ! {rpc, Method, self()},
                                          receive go -> {ok, #{accepted => true}, #{}} end
                             end
                     end).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

%% The state read without a call is the state the process holds, and is the one
%% expected. circuit_state/0 is answered after every message this process sent
%% the upstream before it, so it is read first.
same(Expected) ->
    Held = yuzu_gw_upstream:circuit_state(),
    Published = yuzu_gw_upstream:circuit_state_now(),
    ?assertEqual({Expected, Expected}, {Held, Published}).

%% Two failed proxied calls: the threshold.
trip() ->
    [{error, _} = yuzu_gw_upstream:proxy_register(req(<<"trip">>)) || _ <- [1, 2]],
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()).

%% The message the reset timer sends (the timer itself is out of reach).
half_open() ->
    whereis(yuzu_gw_upstream) ! circuit_half_open,
    ok.

await_state(State) ->
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_upstream:circuit_state() =:= State end)).

req(Id) -> #{info => #{agent_id => Id}}.

notify(I) ->
    yuzu_gw_upstream:notify_stream_status(
      <<"breaker-cell-agent-", (integer_to_binary(I))/binary>>,
      <<"breaker-cell-session">>, connected, <<"203.0.113.9">>, <<"home">>).

rpc_count(Method) ->
    length([P || {_, {yuzu_grpc_client, unary, [_, P, _, _, _]}, _}
                     <- meck:history(yuzu_grpc_client),
                 binary:match(P, Method) =/= nomatch]).

%% The sessions of the replayed ProxyRegisters since the last reset, in order:
%% a replay carries the session it re-announces as x-yuzu-session-id.
replayed_sessions() ->
    [maps:get(<<"x-yuzu-session-id">>, Meta)
     || {_, {yuzu_grpc_client, unary, [Meta, P, _, _, _]}, _} <- meck:history(yuzu_grpc_client),
        binary:match(P, <<"ProxyRegister">>) =/= nomatch,
        is_map_key(<<"x-yuzu-session-id">>, Meta)].

%% Agents held by this gateway, each on a stand-in process; returns their
%% session ids.
register_agents(N) ->
    lists:map(fun(I) ->
        Id  = <<"breaker-cell-", (integer_to_binary(I))/binary>>,
        Session = <<"sess-", Id/binary>>,
        Req = #{info => #{agent_id => Id, hostname => <<"host">>},
                enrollment_token => <<"enroll-", Id/binary>>},
        Pid = spawn(fun() -> receive stop -> ok end end),
        persistent_term:put({?MODULE, dummies},
                            [Pid | persistent_term:get({?MODULE, dummies}, [])]),
        ok = yuzu_gw_registry:register_agent(Id, Pid, Session, [<<"svc">>], <<"host">>, Req),
        Session
    end, lists:seq(1, N)).

spawn_register(Id) ->
    Test = self(),
    spawn(fun() ->
              Reply = yuzu_gw_upstream:proxy_register(#{info => #{agent_id => Id}}),
              Test ! {reply, self(), Reply}
          end).

await_reply(Pid) ->
    receive {reply, Pid, Reply} -> Reply after ?WAIT_MS -> error({no_reply, Pid}) end.

%% The pid of the process the mocked RPC of this method is blocked in.
await_rpc(Method) ->
    receive {rpc, Method, Pid} -> Pid after ?WAIT_MS -> error({no_rpc, Method}) end.

await_queued(Pid, N) ->
    ok = wait_until(fun() ->
                            {message_queue_len, L} = process_info(Pid, message_queue_len),
                            L >= N
                    end).

take_dummies() ->
    Pids = persistent_term:get({?MODULE, dummies}, []),
    _ = persistent_term:erase({?MODULE, dummies}),
    Pids.

wait_until(Pred) ->
    wait_until(Pred, erlang:monotonic_time(millisecond) + ?WAIT_MS).

wait_until(Pred, Deadline) ->
    case Pred() of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true  -> {error, timeout};
                false -> receive after 5 -> wait_until(Pred, Deadline) end
            end
    end.

%% Stop a named process and wait for it to be gone. A process blocked in the
%% mocked RPC, or trapping exits, is killed after a grace period.
stop_named(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            catch unlink(Pid),
            Mon = monitor(process, Pid),
            exit(Pid, shutdown),
            receive {'DOWN', Mon, process, Pid, _} -> ok
            after 1000 ->
                exit(Pid, kill),
                receive {'DOWN', Mon, process, Pid, _} -> ok end
            end
    end.

flush() ->
    receive _ -> flush() after 0 -> ok end.

http_get(Port, Path) ->
    {ok, Sock} = gen_tcp:connect("127.0.0.1", Port, [binary, {active, false}]),
    ok = gen_tcp:send(Sock, ["GET ", Path, " HTTP/1.1\r\nHost: localhost\r\n"
                             "Connection: close\r\n\r\n"]),
    %% Longer than the 5 s the old check waited, so a slow answer is measured
    %% rather than cut off here.
    Data = recv_all(Sock, <<>>),
    gen_tcp:close(Sock),
    [StatusLine, Rest] = binary:split(Data, <<"\r\n">>),
    [_, Code | _] = binary:split(StatusLine, <<" ">>, [global]),
    [_Headers, Body] = binary:split(Rest, <<"\r\n\r\n">>),
    {binary_to_integer(Code), Body}.

recv_all(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 15000) of
        {ok, Chunk}     -> recv_all(Sock, <<Acc/binary, Chunk/binary>>);
        {error, closed} -> Acc
    end.
