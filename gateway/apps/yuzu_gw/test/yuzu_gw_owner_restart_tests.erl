%%%-------------------------------------------------------------------
%%% @doc What happens when an agent's owner process (yuzu_gw_agent) dies
%%% abnormally (#5695, OWNER-RESTART).
%%%
%%% The agent supervisor restarts the owner (`transient'); the restarted owner
%%% sends the DISCONNECTED notice for the session its predecessor held (with the
%%% predecessor's stream_home_id), then tries to recover the agent: it re-attaches
%%% to the agent's Subscribe stream if that is still open, registers the session
%%% again (routing table and server, presenting the same session id) and
%%% re-announces CONNECTED, so commands flow again without the agent
%%% reconnecting. If the stream is gone it stops after the DISCONNECTED. An owner
%%% that keeps crashing gives up after its budget; a crash of most of the fleet's
%%% owners escalates to the gateway supervisor, which restarts the agent
%%% supervisor.
%%%
%%% The whole application runs (no listeners, no upstream channel); the upstream
%%% RPCs are a mocked yuzu_grpc_client:unary/5 that records every
%%% NotifyStreamStatus and ProxyRegister. The Subscribe stream is the REAL relay
%%% loop (yuzu_gw_agent_service:stream_loop/3) in a test process, writing to a
%%% stand-in HTTP/2 connection process that acknowledges and records each frame.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_owner_restart_tests).
-include_lib("eunit/include/eunit.hrl").
-include("yuzu_grpc.hrl").

-define(TAB, yuzu_gw_owner_restart_tests_tab).
-define(ENV_KEYS, [allow_no_upstream, allow_no_listeners, prometheus_port, health_port,
                   grpc_listeners, shutdown_flush_budget_ms, upstream_client,
                   agent_restart_intensity, agent_restart_period_s]).
%% How long a notice may take to reach the mocked server ("promptly").
-define(PROMPT_MS, 3000).

owner_restart_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{timeout, 60, {"a killed owner: the DISCONNECTED for its session reaches the server",
                     fun killed_owner_sends_disconnected/0}},
      {timeout, 60, {"an owner that raised: the DISCONNECTED for its session reaches the server",
                     fun crashed_owner_sends_disconnected/0}},
      {timeout, 60, {"stream still open: the session is re-established and a command reaches "
                     "the agent, with no reconnect", fun open_stream_is_recovered/0}},
      {timeout, 60, {"stream gone: DISCONNECTED only, no resurrection, no child left",
                     fun gone_stream_is_not_resurrected/0}},
      {timeout, 60, {"an owner that crashes on every start gives up after its budget with one "
                     "DISCONNECTED, and the supervisor stays", fun crash_loop_gives_up/0}},
      {timeout, 60, {"a mass crash past the restart intensity restarts the agent supervisor; "
                     "every session ends consistent", fun mass_crash_escalates/0}},
      {timeout, 60, {"a superseded owner's crash sends nothing for the newer session",
                     fun superseded_owner_crash/0}},
      {timeout, 120, {"a kill during a planned stop: no resurrection, no double DISCONNECTED",
                      fun kill_during_planned_stop/0}},
      {timeout, 60, {"the agent's heartbeats stay admitted while its owner is being restarted",
                     fun heartbeat_admitted_during_restart/0}},
      {timeout, 60, {"heartbeats admitted between the kill and the successor's row takeover "
                     "(the row still names the dead owner)",
                     fun heartbeat_admitted_before_takeover/0}},
      {timeout, 60, {"a superseded session's heartbeats stay refused while its restarted owner "
                     "is mid-recovery", fun superseded_refused_mid_recovery/0}},
      {timeout, 60, {"an `ending' row with a dead owner admits no heartbeat",
                     fun ending_row_refused/0}}]}.

setup() ->
    _ = application:stop(yuzu_gw),
    {ok, _} = application:ensure_all_started(telemetry),
    _ = application:load(yuzu_gw),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:stop_upstream(),
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
    application:unset_env(yuzu_gw, agent_restart_intensity),
    application:unset_env(yuzu_gw, agent_restart_period_s),
    catch meck:unload(yuzu_grpc_client),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    catch ets:delete(?TAB),
    ?TAB = ets:new(?TAB, [named_table, public, duplicate_bag]),
    set_register_delay(0),
    mock(),
    Httpd = httpd_services(),
    Cookie = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE"),
    os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", "1"),
    %% Recorded in the table: the handler runs in the owner process, and the
    %% test body may not run in this process.
    HandlerId = {?MODULE, make_ref()},
    %% hold_outcome holds the owner here, after its outcome is decided and
    %% before it stops (and terminate/3 deletes its row).
    ok = telemetry:attach(HandlerId, [yuzu, gw, agent, owner_restart],
                          fun(_E, _M, #{outcome := O}, _) ->
                                  catch ets:insert(?TAB, {outcome, O}),
                                  hold_while(fun() -> held(hold_outcome) end, 10000)
                          end, none),
    {Prev, Httpd, Cookie, HandlerId}.

cleanup({Prev, Httpd0, Cookie, HandlerId}) ->
    telemetry:detach(HandlerId),
    case Cookie of
        false -> os:unsetenv("YUZU_GW_ALLOW_DEFAULT_COOKIE");
        _     -> os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", Cookie)
    end,
    _ = application:stop(yuzu_gw),
    [catch inets:stop(httpd, P) || P <- httpd_services() -- Httpd0],
    catch telemetry:detach(yuzu_gw_prometheus),
    catch meck:unload(yuzu_grpc_client),
    [catch exit(P, kill) || {proc, P} <- catch ets:tab2list(?TAB)],
    catch ets:delete(?TAB),
    flush(),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

%%--------------------------------------------------------------------
%% Cases
%%--------------------------------------------------------------------

killed_owner_sends_disconnected() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    #{owner := Owner, session := S, home := Home} = start_relayed(<<"or-kill">>),
    exit(Owner, kill),
    ?assertEqual(ok, wait_until(fun() -> notices(S, 'DISCONNECTED') =/= [] end, ?PROMPT_MS)),
    ?assertEqual([Home], [H || {H, _T} <- notices(S, 'DISCONNECTED')]).

crashed_owner_sends_disconnected() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    #{owner := Owner, session := S, home := Home} = start_relayed(<<"or-raise">>),
    %% A cast no state handles: the owner raises function_clause.
    gen_statem:cast(Owner, owner_restart_test_unexpected),
    ?assertEqual(ok, wait_until(fun() -> notices(S, 'DISCONNECTED') =/= [] end, ?PROMPT_MS)),
    ?assertEqual([Home], [H || {H, _T} <- notices(S, 'DISCONNECTED')]).

open_stream_is_recovered() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Id = <<"or-recover">>,
    #{owner := Owner, session := S, home := Home, relay := Relay, conn := Conn} =
        start_relayed(Id),
    TKill = erlang:monotonic_time(microsecond),
    exit(Owner, kill),
    %% DISCONNECTED, then the session presented again, then CONNECTED again,
    %% with the same session id and the same stream home.
    ?assertEqual(ok, wait_until(fun() -> length(notices(S, 'CONNECTED')) >= 2 end, ?PROMPT_MS)),
    [{_, TDisc}] = notices(S, 'DISCONNECTED'),
    [{Home, _}, {Home2, TConn2}] = lists:keysort(2, notices(S, 'CONNECTED')),
    ?assertEqual(Home, Home2),
    ?assert(TConn2 > TDisc),
    ?debugFmt("kill to DISCONNECTED ~b us, DISCONNECTED to CONNECTED again ~b us",
              [TDisc - TKill, TConn2 - TDisc]),
    ?assertMatch([_ | _], presented(Id, S)),
    %% Routable again, through a new owner, on the same stream (no reconnect).
    {ok, New} = yuzu_gw_registry:lookup(Id),
    ?assertNotEqual(Owner, New),
    ?assert(is_process_alive(Relay)),
    {ok, _Ref} = yuzu_gw_router:send_command([Id], #{command_id => <<"or-cmd-1">>,
                                                    plugin => <<"p">>, action => <<"a">>},
                                             #{}),
    ?assertEqual(ok, wait_until(fun() -> frames_with(Conn, <<"or-cmd-1">>) > 0 end, ?PROMPT_MS)),
    ?assertEqual([recovered], outcomes()).

gone_stream_is_not_resurrected() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Id = <<"or-gone">>,
    %% A stand-in stream that ends when its owner dies (no re-attach).
    #{owner := Owner, session := S} = start_with_stream(Id, fun mortal_stream/1),
    exit(Owner, kill),
    ?assertEqual(ok, wait_until(fun() -> notices(S, 'DISCONNECTED') =/= [] end, ?PROMPT_MS)),
    ?assertEqual(ok, wait_until(fun() -> children() =:= [] end, ?PROMPT_MS)),
    timer:sleep(300),
    ?assertEqual(1, length(notices(S, 'DISCONNECTED'))),
    ?assertEqual(1, length(notices(S, 'CONNECTED'))),
    ?assertEqual([], presented(Id, S)),
    ?assertEqual(error, yuzu_gw_registry:lookup(Id)),
    %% Nothing holds the session any more: its heartbeats are refused.
    ?assertEqual({reject, unknown_session},
                 yuzu_gw_heartbeat_admission:check(
                   yuzu_grpc:new_ctx(#{}, self(), undefined, undefined, undefined), S)),
    ?assertEqual([disconnected_only], outcomes()).

crash_loop_gives_up() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Sup = whereis(yuzu_gw_agent_sup),
    Id = <<"or-loop">>,
    #{owner := Owner, session := S, relay := Relay} = start_relayed(Id),
    %% Every restarted owner is killed while it waits for the server.
    set_register_delay(2000),
    Kills = kill_restarts([Owner], 10),
    ?debugFmt("owners killed before the restarted one gave up: ~b", [length(Kills)]),
    ?assertEqual(4, length(Kills)),
    ?assertEqual(ok, wait_until(fun() -> children() =:= [] end, ?PROMPT_MS)),
    ?assertEqual(ok, wait_until(fun() -> not is_process_alive(Relay) end, ?PROMPT_MS)),
    ?assertEqual(1, length(notices(S, 'DISCONNECTED'))),
    ?assertEqual(Sup, whereis(yuzu_gw_agent_sup)),
    ?assertEqual([gave_up], [O || O <- outcomes(), O =:= gave_up]).

mass_crash_escalates() ->
    application:set_env(yuzu_gw, agent_restart_intensity, 3),
    application:set_env(yuzu_gw, agent_restart_period_s, 10),
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Top = whereis(yuzu_gw_sup),
    Sup = whereis(yuzu_gw_agent_sup),
    Agents = [start_relayed(<<"or-mass-", (integer_to_binary(I))/binary>>)
              || I <- lists:seq(1, 8)],
    [exit(O, kill) || #{owner := O} <- Agents],
    ?assertEqual(ok, wait_until(fun() -> is_pid(whereis(yuzu_gw_agent_sup)) andalso
                                         whereis(yuzu_gw_agent_sup) =/= Sup end, ?PROMPT_MS)),
    ?assertEqual(Top, whereis(yuzu_gw_sup)),
    %% Every killed session's DISCONNECTED reached the server ...
    ?assertEqual(ok, wait_until(fun() ->
                                        lists:all(fun(#{session := S}) ->
                                                          notices(S, 'DISCONNECTED') =/= []
                                                  end, Agents)
                                end, 10000)),
    %% ... and each agent ends consistent: routable with CONNECTED as the last
    %% notice, or unroutable with DISCONNECTED as the last notice and its stream
    %% ended.
    ?assertEqual(ok, wait_until(fun() -> lists:all(fun consistent/1, Agents) end, 15000)).

%% Between the owner's death (the registry drops its session index row at once)
%% and the restarted owner registering again (after its predecessor's
%% DISCONNECTED has settled upstream, which under a mass crash waits behind the
%% other notices) the agent's heartbeat must still be admitted on its own
%% connection: a refusal is NOT_FOUND, and the agent then drops the very stream
%% the owner is recovering and registers a new session (found at scale: 2 of
%% 500 killed owners at 5,000 agents). Here the DISCONNECTED is held at the
%% server until the heartbeat has been checked.
heartbeat_admitted_during_restart() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Id = <<"or-hb">>,
    #{owner := Owner, session := S, conn := Conn} =
        start_with_stream(Id, <<Id/binary, "-session">>, fun relay_stream/1, #{bind => true}),
    Ctx = yuzu_grpc:new_ctx(#{}, Conn, undefined, undefined, undefined),
    ?assertEqual(ok, yuzu_gw_heartbeat_admission:check(Ctx, S)),
    ets:insert(?TAB, {cfg, hold_disconnected, true}),
    exit(Owner, kill),
    %% The registry has dropped the dead owner's session row ...
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_registry:lookup_session(S) =:= error end,
                                ?PROMPT_MS)),
    %% ... and the restarted owner is waiting for its DISCONNECTED to settle.
    ?assertEqual(ok, wait_until(fun() -> notices(S, 'DISCONNECTED') =/= [] end, ?PROMPT_MS)),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(S)),
    ?assertEqual(ok, yuzu_gw_heartbeat_admission:check(Ctx, S)),
    %% Not on another connection.
    Other = spawn(fun() -> receive _ -> ok end end),
    ets:insert(?TAB, {proc, Other}),
    ?assertMatch({reject, _},
                 yuzu_gw_heartbeat_admission:check(
                   yuzu_grpc:new_ctx(#{}, Other, undefined, undefined, undefined), S)),
    ets:match_delete(?TAB, {cfg, hold_disconnected, '_'}),
    ?assertEqual(ok, wait_until(fun() -> length(notices(S, 'CONNECTED')) >= 2 end, ?PROMPT_MS)),
    ?assertEqual(ok, yuzu_gw_heartbeat_admission:check(Ctx, S)),
    ?assertEqual([recovered], outcomes()).

%% The window between the kill and the successor's row takeover (recover/3):
%% the registry has dropped the session row, the owner row still says
%% `connected' and names the dead owner. Held by suspending the agent
%% supervisor, so the successor is not started until the checks are done.
heartbeat_admitted_before_takeover() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Id = <<"or-hb-pre">>,
    #{owner := Owner, session := S, conn := Conn} =
        start_with_stream(Id, <<Id/binary, "-session">>, fun relay_stream/1, #{bind => true}),
    Ctx = yuzu_grpc:new_ctx(#{}, Conn, undefined, undefined, undefined),
    ?assertEqual(ok, yuzu_gw_heartbeat_admission:check(Ctx, S)),
    Key = owner_key(S),
    ok = sys:suspend(yuzu_gw_agent_sup),
    try
        exit(Owner, kill),
        ?assertEqual(ok, wait_until(fun() -> yuzu_gw_registry:lookup_session(S) =:= error end,
                                    ?PROMPT_MS)),
        ?assertEqual(error, yuzu_gw_registry:lookup_pending_session(S)),
        ?assertNot(is_process_alive(Owner)),
        ?assertMatch({ok, #{announced := connected, pid := Owner}},
                     yuzu_gw_agent_sup:owner_row(Key)),
        ?assertEqual(ok, yuzu_gw_heartbeat_admission:check(Ctx, S)),
        Other = spawn(fun() -> receive _ -> ok end end),
        ets:insert(?TAB, {proc, Other}),
        ?assertMatch({reject, _},
                     yuzu_gw_heartbeat_admission:check(
                       yuzu_grpc:new_ctx(#{}, Other, undefined, undefined, undefined), S))
    after
        sys:resume(yuzu_gw_agent_sup)
    end,
    ?assertEqual(ok, wait_until(fun() -> length(notices(S, 'CONNECTED')) >= 2 end, ?PROMPT_MS)),
    ?assertEqual(ok, yuzu_gw_heartbeat_admission:check(Ctx, S)).

%% A superseded session whose owner is killed: its restarted owner has sent the
%% DISCONNECTED and marked the row `disconnected' (it is "being restarted"),
%% but the registry routes the agent to the newer session, so the old
%% session's heartbeats stay refused. Held after the restarted owner gave up
%% and before it stops (its row is deleted when it does).
superseded_refused_mid_recovery() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Id = <<"or-super-mid">>,
    #{owner := Old, session := S1, conn := Conn1} =
        start_with_stream(Id, <<"or-super-mid-s1">>, fun relay_stream/1, #{bind => true}),
    #{owner := New, session := S2} =
        start_with_stream(Id, <<"or-super-mid-s2">>, fun relay_stream/1, #{bind => true}),
    Ctx1 = yuzu_grpc:new_ctx(#{}, Conn1, undefined, undefined, undefined),
    Key = owner_key(S1),
    ets:insert(?TAB, {cfg, hold_outcome, true}),
    try
        exit(Old, kill),
        ?assertEqual(ok, wait_until(fun() -> notices(S1, 'DISCONNECTED') =/= [] end,
                                    ?PROMPT_MS)),
        ?assertEqual(ok, wait_until(fun() -> ets:lookup(?TAB, outcome) =/= [] end,
                                    ?PROMPT_MS)),
        %% Mid-recovery: the row is `disconnected', owned by the live successor.
        {ok, #{announced := disconnected, pid := Successor}} =
            yuzu_gw_agent_sup:owner_row(Key),
        ?assert(is_process_alive(Successor)),
        ?assertNotEqual(Old, Successor),
        ?assertEqual({ok, {New, S2}}, yuzu_gw_registry:lookup_local_session(Id)),
        ?assertEqual({reject, unknown_session}, yuzu_gw_heartbeat_admission:check(Ctx1, S1)),
        ?assertEqual(error, yuzu_gw_agent_sup:held_session(S1))
    after
        ets:match_delete(?TAB, {cfg, hold_outcome, '_'})
    end,
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_agent_sup:owner_row(Key) =:= none end,
                                ?PROMPT_MS)),
    ?assertEqual([disconnected_only], outcomes()),
    ?assertEqual({reject, unknown_session}, yuzu_gw_heartbeat_admission:check(Ctx1, S1)).

%% A session being ended on purpose (`ending') whose owner is dead, before the
%% successor takes the row over: no heartbeat is admitted.
ending_row_refused() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Id = <<"or-ending">>,
    #{owner := Owner, session := S, conn := Conn} =
        start_with_stream(Id, <<Id/binary, "-session">>, fun relay_stream/1, #{bind => true}),
    Ctx = yuzu_grpc:new_ctx(#{}, Conn, undefined, undefined, undefined),
    Key = owner_key(S),
    ok = sys:suspend(yuzu_gw_agent_sup),
    try
        exit(Owner, kill),
        ?assertEqual(ok, wait_until(fun() -> yuzu_gw_registry:lookup_session(S) =:= error end,
                                    ?PROMPT_MS)),
        ?assertMatch({ok, _}, yuzu_gw_agent_sup:held_session(S)),
        ok = yuzu_gw_agent_sup:owner_set(Key, [{announced, ending}]),
        ?assertEqual(error, yuzu_gw_agent_sup:held_session(S)),
        ?assertEqual({reject, unknown_session}, yuzu_gw_heartbeat_admission:check(Ctx, S))
    after
        sys:resume(yuzu_gw_agent_sup)
    end,
    %% The successor re-sends the DISCONNECTED and does not recover the session.
    ?assertEqual(ok, wait_until(fun() -> yuzu_gw_agent_sup:owner_row(Key) =:= none end,
                                ?PROMPT_MS)),
    ?assertEqual([disconnected_only], outcomes()).

superseded_owner_crash() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Id = <<"or-super">>,
    #{owner := Old, session := S1, conn := Conn1} =
        start_with_stream(Id, <<"or-super-s1">>, fun relay_stream/1, #{bind => true}),
    #{owner := New, session := S2} =
        start_with_stream(Id, <<"or-super-s2">>, fun relay_stream/1, #{bind => true}),
    %% The superseded session admits no heartbeat, owner table or not.
    Ctx1 = yuzu_grpc:new_ctx(#{}, Conn1, undefined, undefined, undefined),
    ?assertEqual({reject, unknown_session}, yuzu_gw_heartbeat_admission:check(Ctx1, S1)),
    exit(Old, kill),
    ?assertEqual(ok, wait_until(fun() -> notices(S1, 'DISCONNECTED') =/= [] end, ?PROMPT_MS)),
    timer:sleep(500),
    ?assertEqual([], notices(S2, 'DISCONNECTED')),
    ?assertEqual([], presented(Id, S1)),
    ?assertEqual({ok, New}, yuzu_gw_registry:lookup(Id)),
    ?assertEqual(1, length(notices(S1, 'DISCONNECTED'))),
    ?assertEqual({reject, unknown_session}, yuzu_gw_heartbeat_admission:check(Ctx1, S1)).

kill_during_planned_stop() ->
    {ok, _} = application:ensure_all_started(yuzu_gw),
    Agents = [start_relayed(<<"or-stop-", (integer_to_binary(I))/binary>>)
              || I <- lists:seq(1, 5)],
    [#{owner := Victim} | _] = Agents,
    exit(Victim, kill),
    ok = application:stop(yuzu_gw),
    timer:sleep(200),
    lists:foreach(
      fun(#{session := S}) ->
              Events = [E || {E, _H, _T} <- lists:keysort(3, all_notices(S))],
              %% Ends with DISCONNECTED, and never two in a row.
              ?assertEqual('DISCONNECTED', lists:last(Events)),
              ?assertEqual([], [x || {'DISCONNECTED', 'DISCONNECTED'} <- pairs(Events)])
      end, Agents).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

%% Every NotifyStreamStatus is recorded {notice, Event, AgentId, SessionId,
%% Home, T}; every ProxyRegister that presents a session {presented, AgentId,
%% Session} and is adopted after register_delay_ms.
mock() ->
    ok = meck:expect(yuzu_grpc_client, unary,
                     fun(Meta, Path, Req, _Def, _Opts) ->
                         case lists:last(binary:split(Path, <<"/">>, [global])) of
                             <<"NotifyStreamStatus">> ->
                                 ets:insert(?TAB, {notice, maps:get(event, Req),
                                                   maps:get(agent_id, Req),
                                                   maps:get(session_id, Req),
                                                   maps:get(stream_home_id, Req),
                                                   erlang:monotonic_time(microsecond)}),
                                 maps:get(event, Req) =:= 'DISCONNECTED' andalso
                                     hold_while(fun() -> held(hold_disconnected) end, 10000),
                                 {ok, #{acknowledged => true}, #{}};
                             <<"ProxyRegister">> ->
                                 [{cfg, register_delay_ms, Delay} | _] =
                                     [C || {cfg, register_delay_ms, _} = C
                                               <- ets:lookup(?TAB, cfg)],
                                 timer:sleep(Delay),
                                 Info = maps:get(info, Req, #{}),
                                 Agent = maps:get(agent_id, Info, <<>>),
                                 case maps:get(<<"x-yuzu-session-id">>, Meta, undefined) of
                                     undefined ->
                                         {ok, #{session_id => <<"fresh">>, accepted => true}, #{}};
                                     S ->
                                         ets:insert(?TAB, {presented, Agent, S}),
                                         {ok, #{session_id => S, accepted => true}, #{}}
                                 end;
                             _ ->
                                 {ok, #{}, #{}}
                         end
                     end).

%% Whether the test set the hold flag Flag (false once the table is gone).
held(Flag) ->
    try [x || {cfg, F, true} <- ets:lookup(?TAB, cfg), F =:= Flag] =/= []
    catch error:badarg -> false
    end.

hold_while(Pred, Left) when Left > 0 ->
    case Pred() of
        true  -> timer:sleep(10), hold_while(Pred, Left - 10);
        false -> true
    end;
hold_while(_Pred, _Left) ->
    true.

notices(Session, Event) ->
    [{H, T} || {notice, E, _A, S, H, T} <- ets:lookup(?TAB, notice), S =:= Session, E =:= Event].

all_notices(Session) ->
    [{E, H, T} || {notice, E, _A, S, H, T} <- ets:lookup(?TAB, notice), S =:= Session].

presented(Agent, Session) ->
    [x || {presented, A, S} <- ets:lookup(?TAB, presented), A =:= Agent, S =:= Session].

pairs([A, B | T]) -> [{A, B} | pairs([B | T])];
pairs(_) -> [].

%% The owner-table row key of Session.
owner_key(Session) ->
    [{_, Key}] = ets:lookup(yuzu_gw_owner_sessions, {session, Session}),
    Key.

children() ->
    [P || {_, P, _, _} <- supervisor:which_children(yuzu_gw_agent_sup), is_pid(P)].

outcomes() ->
    timer:sleep(200),
    [O || {outcome, O} <- ets:lookup(?TAB, outcome)].

set_register_delay(Ms) ->
    ets:match_delete(?TAB, {cfg, register_delay_ms, '_'}),
    ets:insert(?TAB, {cfg, register_delay_ms, Ms}).

consistent(#{agent := Id, session := S, relay := Relay}) ->
    Events = [E || {E, _H, _T} <- lists:keysort(3, all_notices(S))],
    case {yuzu_gw_registry:lookup(Id), Events} of
        {{ok, _}, [_ | _]} -> lists:last(Events) =:= 'CONNECTED';
        {error, [_ | _]}   -> lists:last(Events) =:= 'DISCONNECTED'
                                  andalso not is_process_alive(Relay);
        _                  -> false
    end.

%% Kill each owner the supervisor restarts for the killed one (found by the
%% agent id in the routing table or a fresh child), 150 ms after it appears,
%% until no new owner appears within 2 s. Returns the owners killed.
kill_restarts([Last | _] = Killed, 0) ->
    _ = Last,
    lists:reverse(Killed);
kill_restarts([Last | _] = Killed, Left) ->
    exit(Last, kill),
    case wait_new_child(Killed, 2000) of
        {ok, Next} ->
            timer:sleep(150),
            case is_process_alive(Next) of
                true  -> kill_restarts([Next | Killed], Left - 1);
                false -> lists:reverse(Killed)
            end;
        timeout ->
            lists:reverse(Killed)
    end.

wait_new_child(Seen, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    wait_new_child_(Seen, Deadline).

wait_new_child_(Seen, Deadline) ->
    case [P || P <- children(), not lists:member(P, Seen)] of
        [P | _] -> {ok, P};
        [] ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> timeout;
                false -> timer:sleep(5), wait_new_child_(Seen, Deadline)
            end
    end.

start_relayed(Id) ->
    start_relayed(Id, <<Id/binary, "-session">>).

start_relayed(Id, Session) ->
    start_with_stream(Id, Session, fun relay_stream/1).

start_with_stream(Id, Fun) ->
    start_with_stream(Id, <<Id/binary, "-session">>, Fun).

start_with_stream(Id, Session, Fun) ->
    start_with_stream(Id, Session, Fun, #{}).

%% A stream process (Fun(Conn) is its body once its owner is known) whose owner
%% is started through the agent supervisor, as the Subscribe handler does.
%% Opts: bind => true binds the session to the stand-in connection (its
%% heartbeats are then admitted on that connection only).
start_with_stream(Id, Session, Fun, Opts) ->
    Parent = self(),
    Conn = spawn(fun conn_loop/0),
    Stream = spawn(fun() ->
                           Args0 = #{agent_id => Id, agent_info => #{agent_id => Id},
                                     stream_pid => self(), peer_addr => <<"127.0.0.1">>,
                                     session_id => Session,
                                     register_req => #{info => #{agent_id => Id}}},
                           Args = case maps:get(bind, Opts, false) of
                                      true  -> Args0#{conn_key => Conn};
                                      false -> Args0
                                  end,
                           {ok, Owner} = yuzu_gw_agent_sup:start_agent(Args),
                           Parent ! {started, self(), Owner},
                           Fun({Conn, Owner})
                   end),
    ets:insert(?TAB, [{proc, Conn}, {proc, Stream}]),
    Owner = receive {started, Stream, O} -> O after 10000 -> error(start_timeout) end,
    ok = wait_until(fun() -> notices(Session, 'CONNECTED') =/= [] end, ?PROMPT_MS),
    [{Home, _}] = notices(Session, 'CONNECTED'),
    #{agent => Id, owner => Owner, session => Session, home => Home, relay => Stream,
      conn => Conn}.

%% The real Subscribe relay loop, writing to the stand-in connection.
relay_stream({Conn, Owner}) ->
    Stream = #yuzu_grpc_stream{conn = Conn, stream_id = 1, ctx = undefined,
                               method = <<"/yuzu.agent.v1.AgentService/Subscribe">>,
                               pb = agent_pb, output = 'yuzu.agent.v1.CommandRequest'},
    yuzu_gw_agent_service:stream_loop(make_ref(), Stream, Owner).

%% A stream that ends when its owner dies, and never re-attaches.
mortal_stream({_Conn, Owner}) ->
    Mon = monitor(process, Owner),
    receive {'DOWN', Mon, process, Owner, _} -> ok after 60000 -> ok end.

%% A stand-in HTTP/2 connection: acknowledges and records every frame.
conn_loop() ->
    receive
        {{_Conn, _Sid}, {grpc_frame, From, Ack, Frame}} ->
            ets:insert(?TAB, {frame, self(), iolist_to_binary(Frame)}),
            From ! {grpc_ack, Ack},
            conn_loop();
        stop ->
            ok
    after 120000 ->
        ok
    end.

frames_with(Conn, Bytes) ->
    length([1 || {frame, C, F} <- ets:lookup(?TAB, frame), C =:= Conn,
                 binary:match(F, Bytes) =/= nomatch]).

httpd_services() ->
    case catch inets:services() of
        L when is_list(L) -> [P || {httpd, P} <- L, is_pid(P)];
        _ -> []
    end.

flush() ->
    receive _ -> flush() after 0 -> ok end.

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
    case catch Pred() of
        true -> ok;
        _ ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> timeout;
                false -> timer:sleep(10), wait_until_(Pred, Deadline)
            end
    end.
