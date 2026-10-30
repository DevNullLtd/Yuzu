%%%-------------------------------------------------------------------
%%% @doc A planned stop (application:stop/1, SIGTERM) tells the server about
%%% every session the gateway is giving up, as a last gasp (#5695).
%%%
%%% The whole application is started (no listeners, no upstream channel; the
%%% upstream RPCs are a mocked yuzu_grpc_client:unary/5), N real agent processes
%%% are started through yuzu_gw_agent_sup, and application:stop(yuzu_gw) is
%%% called. Before it returns, the mock must have received a DISCONNECTED for
%%% every one of the N sessions. A server that never answers instead must not
%%% hold the stop past the flush budget, and what is left is counted.
%%%
%%% Cleanup restores what the application start leaves behind in this VM: the
%%% prometheus httpd instance it starts and the telemetry handler it attaches.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_planned_stop_tests).
-include_lib("eunit/include/eunit.hrl").

-define(TAB, yuzu_gw_planned_stop_tests_tab).
-define(N, 100).
-define(ENV_KEYS, [allow_no_upstream, allow_no_listeners, prometheus_port, health_port,
                   grpc_listeners, shutdown_flush_budget_ms, upstream_client]).

planned_stop_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{timeout, 120, {"application stop with 100 sessions delivers 100 DISCONNECTED notices "
                      "before it returns", fun stop_delivers_every_disconnected/0}},
      {timeout, 120, {"a server that never answers does not hold the stop past the flush "
                      "budget; the rest is counted", fun stop_is_bounded_by_the_budget/0}},
      {timeout, 120, {"an agent still registering when the stop begins is ended too: its "
                      "CONNECTED is followed by its DISCONNECTED", fun registering_agent_is_ended/0}}]}.

setup() ->
    _ = application:stop(yuzu_gw),
    {ok, _} = application:ensure_all_started(telemetry),
    _ = application:load(yuzu_gw),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:stop_upstream(),
    %% Whatever an earlier module left running under the names the
    %% application's supervisor registers.
    [stop_named(N) || N <- [yuzu_gw_registry, yuzu_gw_agent_sup, yuzu_gw_heartbeat_buffer,
                            yuzu_gw_router, yuzu_gw_upstream_regulator,
                            yuzu_gw_upstream_pressure, yuzu_gw_gauge, yuzu_gw_health,
                            yuzu_gw_cluster_discovery, yuzu_gw_memory_shedder,
                            yuzu_gw_mem_reclaim, yuzu_gw_mgmt_pins, yuzu_gw_sup]],
    application:set_env(yuzu_gw, allow_no_upstream, true),
    application:set_env(yuzu_gw, allow_no_listeners, true),
    application:set_env(yuzu_gw, prometheus_port, 0),
    application:set_env(yuzu_gw, health_port, 0),
    application:set_env(yuzu_gw, grpc_listeners, []),
    application:unset_env(yuzu_gw, upstream_client),
    catch meck:unload(yuzu_grpc_client),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    catch ets:delete(?TAB),
    ?TAB = ets:new(?TAB, [named_table, public, duplicate_bag]),
    Httpd = httpd_services(),
    %% A distributed test VM (an earlier multinode module started the
    %% distribution) has a default cookie the application refuses; this test is
    %% about stopping, not about the cookie guard.
    Cookie = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE"),
    os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", "1"),
    {Prev, Httpd, Cookie}.

cleanup({Prev, Httpd0, Cookie}) ->
    case Cookie of
        false -> os:unsetenv("YUZU_GW_ALLOW_DEFAULT_COOKIE");
        _     -> os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", Cookie)
    end,
    _ = application:stop(yuzu_gw),
    [catch inets:stop(httpd, P) || P <- httpd_services() -- Httpd0],
    catch telemetry:detach(yuzu_gw_prometheus),
    catch meck:unload(yuzu_grpc_client),
    catch ets:delete(?TAB),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

%%--------------------------------------------------------------------

stop_delivers_every_disconnected() ->
    mock(fun(_) -> ok end),
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Ids = start_agents(?N),
    ok = wait_until(fun() -> length(sent('CONNECTED')) >= ?N end, 10000),
    ok = application:stop(yuzu_gw),
    Sent = sent('DISCONNECTED'),
    ?debugFmt("DISCONNECTED delivered before stop returned: ~b of ~b", [length(Sent), ?N]),
    ?assertEqual(lists:sort(Ids), lists:usort(Sent)).

stop_is_bounded_by_the_budget() ->
    application:set_env(yuzu_gw, shutdown_flush_budget_ms, 1500),
    mock(fun('DISCONNECTED') -> block; (_) -> ok end),
    {ok, _} = application:ensure_all_started(yuzu_gw),
    _ = start_agents(?N),
    ok = wait_until(fun() -> length(sent('CONNECTED')) >= ?N end, 10000),
    Self = self(),
    Id = {?MODULE, Self},
    ok = telemetry:attach(Id, [yuzu, gw, upstream, notify_lost],
                          fun(_E, #{count := C}, #{reason := R, event := Ev}, _) ->
                              Self ! {lost, Ev, R, C}
                          end, none),
    try
        T0 = erlang:monotonic_time(millisecond),
        ok = application:stop(yuzu_gw),
        Took = erlang:monotonic_time(millisecond) - T0,
        Lost = lists:sum([C || {lost, disconnected, shutdown, C} <- flush()]),
        ?debugFmt("stop with a silent server: ~b ms, ~b DISCONNECTED counted lost", [Took, Lost]),
        ?assert(Took < 1500 + 3000),
        ?assertEqual(?N, Lost)
    after
        telemetry:detach(Id),
        ets:insert(?TAB, {release_all}),
        [P ! go || {blocked, P} <- ets:tab2list(?TAB)]
    end.

%% An agent whose registration is still running (the registry is busy) when the
%% stop begins is not in the routing table yet. It must still be ended: once its
%% registration completes it announces CONNECTED, and the stop must then send
%% its DISCONNECTED too, not leave a session the server keeps as online.
registering_agent_is_ended() ->
    mock(fun(_) -> ok end),
    {ok, _} = application:ensure_all_started(yuzu_gw),
    [Live] = start_agents(1),
    ok = wait_until(fun() -> length(sent('CONNECTED')) >= 1 end, 10000),
    Reg = whereis(yuzu_gw_registry),
    ok = sys:suspend(Reg),
    Late = <<"stop-agent-late">>,
    Starter = spawn(fun() ->
                        Stream = spawn(fun() -> receive _ -> ok after 60000 -> ok end end),
                        _ = yuzu_gw_agent_sup:start_agent(
                              #{agent_id => Late, agent_info => #{agent_id => Late},
                                stream_pid => Stream, peer_addr => <<"127.0.0.1">>,
                                session_id => <<"stop-session-late">>,
                                register_req => #{info => #{agent_id => Late}}})
                    end),
    %% The late agent exists and is inside its registry call.
    ok = wait_until(fun() -> length(supervisor:which_children(yuzu_gw_agent_sup)) >= 2 end, 5000),
    Stopper = spawn(fun() -> ok = application:stop(yuzu_gw) end),
    StopMon = monitor(process, Stopper),
    timer:sleep(300),
    %% A stop that does not wait for the registering agent has already taken
    %% the tree (and the suspended registry) down by now.
    catch sys:resume(Reg),
    receive {'DOWN', StopMon, process, Stopper, R} -> ?assertEqual(normal, R)
    after 60000 -> error(stop_hung)
    end,
    _ = Starter,
    ?assertEqual(lists:sort([Live, Late]), lists:usort(sent('DISCONNECTED'))),
    ?assert(lists:member(Late, sent('CONNECTED'))).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

%% Answer(Event) for NotifyStreamStatus: ok, or block (until released); every
%% notification is recorded with its event and agent id. Other RPCs answer ok.
mock(Answer) ->
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(_Meta, Path, Req, _Def, _Opts) ->
                         case lists:last(binary:split(Path, <<"/">>, [global])) of
                             <<"NotifyStreamStatus">> ->
                                 Ev = maps:get(event, Req),
                                 case Answer(Ev) of
                                     ok ->
                                         ets:insert(?TAB, {sent, Ev, maps:get(agent_id, Req)}),
                                         {ok, #{acknowledged => true}, #{}};
                                     block ->
                                         ets:insert(?TAB, {blocked, self()}),
                                         receive go -> ok after 5000 -> ok end,
                                         {error, timeout}
                                 end;
                             _ ->
                                 {ok, #{}, #{}}
                         end
                     end).

sent(Event) ->
    [Id || {sent, E, Id} <- ets:tab2list(?TAB), E =:= Event].

%% N agent processes, each with a stand-in Subscribe stream process.
start_agents(N) ->
    [begin
         Id = <<"stop-agent-", (integer_to_binary(I))/binary>>,
         Stream = spawn(fun() -> receive _ -> ok after 60000 -> ok end end),
         {ok, _Pid} = yuzu_gw_agent_sup:start_agent(
                        #{agent_id => Id, agent_info => #{agent_id => Id},
                          stream_pid => Stream, peer_addr => <<"127.0.0.1">>,
                          session_id => <<"stop-session-", (integer_to_binary(I))/binary>>,
                          register_req => #{info => #{agent_id => Id}}}),
         Id
     end || I <- lists:seq(1, N)].

httpd_services() ->
    case catch inets:services() of
        L when is_list(L) -> [P || {httpd, P} <- L, is_pid(P)];
        _ -> []
    end.

flush() ->
    receive M -> [M | flush()] after 0 -> [] end.

stop_named(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            catch unlink(Pid),
            Mon = monitor(process, Pid),
            exit(Pid, shutdown),
            receive {'DOWN', Mon, process, Pid, _} -> ok after 5000 -> ok end
    end.

wait_until(Pred, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_until_(Pred, Deadline).

wait_until_(Pred, Deadline) ->
    case Pred() of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> timeout;
                false -> timer:sleep(10), wait_until_(Pred, Deadline)
            end
    end.
