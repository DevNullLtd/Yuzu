%%%-------------------------------------------------------------------
%%% @doc The held stream-status notification store at fleet scale: its default
%%% size, what it drops when full, how a lost CONNECTED is put right, retries of
%%% a failed send, per-key order, and the high-water mark.
%%%
%%%   - The default cap holds a 5,000-agent fleet that flaps once while the
%%%     notices cannot be sent (two keys per agent) with room to spare.
%%%   - Full, an incoming DISCONNECTED evicts the oldest held CONNECTED (a lost
%%%     DISCONNECTED leaves a ghost session on the server that nothing removes;
%%%     a lost CONNECTED is put right by a full registration replay, which this
%%%     store arms and the upstream runs once the store has drained).
%%%   - A send that fails while the breaker is closed is held again and
%%%     counted, not lost.
%%%   - Two events for one key are never in flight together, so they cannot
%%%     reach the server out of order.
%%%   - The high-water mark of the store is reported.
%%%
%%% Mocked: yuzu_grpc_client:unary/5 (a gate per agent id, run in the worker
%%% processes) and yuzu_gw_agent's reannounce/disconnect. Telemetry handlers are
%%% attached in the test's own process and detached at the end of the test.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_notify_capacity_tests).
-include_lib("eunit/include/eunit.hrl").

-define(TAB, yuzu_gw_notify_capacity_tests_tab).
-define(ENV_KEYS, [notify_pending_max, circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms, circuit_breaker_max_reset_timeout_ms,
                   registration_replay_start_jitter_ms, grpc_listeners]).

capacity_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{timeout, 120, {"5,000 agents flapping once behind an open breaker, plus one more key: "
                      "nothing dropped", fun fleet_flap_fits_the_default_cap/0}},
      {timeout, 30, {"the default cap is three per agent the agent listeners admit",
                     fun default_cap_follows_the_listeners/0}},
      {timeout, 30, {"full: a DISCONNECTED evicts the oldest held CONNECTED, counted",
                     fun disconnected_evicts_oldest_connected/0}},
      {timeout, 30, {"full of DISCONNECTED: a DISCONNECTED is dropped, counted",
                     fun disconnected_over_disconnected_is_lost/0}},
      {timeout, 30, {"a lost CONNECTED arms a full registration replay once the store drains",
                     fun lost_connected_arms_a_heal_replay/0}},
      {timeout, 30, {"a send that fails with the breaker closed is held again and retried",
                     fun closed_failure_is_requeued/0}},
      {timeout, 30, {"an event for a key in flight waits for it: no reordering",
                     fun same_key_waits_for_the_one_in_flight/0}},
      {timeout, 30, {"the high-water mark of the held store is reported",
                     fun high_water_mark_is_reported/0}}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_registry:ensure(),
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(yuzu_gw_agent),
    ok = meck:new(yuzu_grpc_client, [non_strict, no_link]),
    ok = meck:new(yuzu_gw_agent, [passthrough, no_link]),
    ok = meck:expect(yuzu_gw_agent, reannounce, fun(_, _) -> ok end),
    ok = meck:expect(yuzu_gw_agent, disconnect, fun(_) -> ok end),
    ?TAB = ets:new(?TAB, [named_table, public, duplicate_bag]),
    application:unset_env(yuzu_gw, notify_pending_max),
    application:unset_env(yuzu_gw, grpc_listeners),
    application:set_env(yuzu_gw, registration_replay_start_jitter_ms, 0),
    %% Two failures open the breaker; it stays open until a test moves it.
    yuzu_gw_test_upstream:set_breaker_env(2),
    Prev.

cleanup(Prev) ->
    yuzu_gw_test_upstream:stop_upstream(),
    [yuzu_gw_registry:deregister_agent(Id) || Id <- yuzu_gw_registry:all_agents()],
    catch meck:unload(yuzu_grpc_client),
    catch meck:unload(yuzu_gw_agent),
    catch ets:delete(?TAB),
    yuzu_gw_test_upstream:restore_env(Prev),
    ok.

%%--------------------------------------------------------------------

fleet_flap_fits_the_default_cap() ->
    mock(fun(_) -> {error, econnrefused} end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    with_events([[yuzu, gw, upstream, notify_dropped], [yuzu, gw, upstream, notify_lost]],
      fun() ->
          trip(),
          [begin
               Id = agent(I),
               notify(Id, <<"old-", Id/binary>>, disconnected),
               notify(Id, <<"new-", Id/binary>>, connected)
           end || I <- lists:seq(1, 5000)],
          notify(<<"one-more">>, <<"s">>, connected),
          _ = yuzu_gw_upstream:circuit_state(),
          ?assertEqual(10001, held()),
          ?assertEqual([], events())
      end).

default_cap_follows_the_listeners() ->
    mock(fun(_) -> ok end),
    application:set_env(yuzu_gw, grpc_listeners,
                        [#{name => agent, port => 0,
                           services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service},
                           limits => #{max_connections => 20000}}]),
    _ = yuzu_gw_test_upstream:start_upstream(),
    ?assertEqual(60000, up_get(notify_pending_max)),
    yuzu_gw_test_upstream:stop_upstream(),
    application:unset_env(yuzu_gw, grpc_listeners),
    _ = yuzu_gw_test_upstream:start_upstream(),
    ?assertEqual(15000, up_get(notify_pending_max)).

disconnected_evicts_oldest_connected() ->
    application:set_env(yuzu_gw, notify_pending_max, 3),
    mock(fun(_) -> {error, econnrefused} end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    with_events([[yuzu, gw, upstream, notify_lost]],
      fun() ->
          trip(),
          [notify(agent(I), <<"s">>, connected) || I <- [1, 2, 3]],
          notify(agent(4), <<"s">>, disconnected),
          _ = yuzu_gw_upstream:circuit_state(),
          ?assertEqual(3, held()),
          ?assertEqual([{agent(2), 'CONNECTED'}, {agent(3), 'CONNECTED'},
                        {agent(4), 'DISCONNECTED'}], held_events()),
          ?assertEqual([{connected, evicted}], events())
      end).

disconnected_over_disconnected_is_lost() ->
    application:set_env(yuzu_gw, notify_pending_max, 2),
    mock(fun(_) -> {error, econnrefused} end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    with_events([[yuzu, gw, upstream, notify_lost]],
      fun() ->
          trip(),
          [notify(agent(I), <<"s">>, disconnected) || I <- [1, 2, 3]],
          _ = yuzu_gw_upstream:circuit_state(),
          ?assertEqual(2, held()),
          ?assertEqual([{disconnected, at_capacity}], events())
      end).

%% A lost CONNECTED with the breaker CLOSED (the server answers, slowly): no
%% recovery will replay anything. Ten notify sends are held in flight (each
%% holds a slot of the cap back, as its event may come back), the store (cap 12)
%% fills with CONNECTED notices of two live agents, and a DISCONNECTED evicts
%% the older one. Once the sends finish and the store drains, a full
%% registration replay re-proxies every local agent: the adopted replay makes
%% the agent re-send its CONNECTED, which puts the eviction right. The breaker
%% never moved.
lost_connected_arms_a_heal_replay() ->
    application:set_env(yuzu_gw, notify_pending_max, 12),
    Dummy = spawn(fun() -> receive stop -> ok end end),
    [ok = yuzu_gw_registry:register_agent(agent(I), Dummy, sid(I), [], <<"h">>,
                                          #{info => #{agent_id => agent(I)}})
     || I <- [1, 2, 3]],
    Test = self(),
    mock_raw(fun(Meta, Path, Req, _Def, _Opts) ->
                 Method = lists:last(binary:split(Path, <<"/">>, [global])),
                 ets:insert(?TAB, {call, Method, Req, Meta}),
                 case {Method, Req} of
                     {<<"NotifyStreamStatus">>, #{agent_id := <<"blocker", _/binary>>}} ->
                         Test ! {blocked, self()},
                         receive go -> ok after 10000 -> ok end,
                         {ok, #{}, #{}};
                     {<<"ProxyRegister">>, _} ->
                         {ok, #{session_id => maps:get(<<"x-yuzu-session-id">>, Meta, <<"s">>),
                                accepted => true}, #{}};
                     _ ->
                         {ok, #{}, #{}}
                 end
             end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    with_events([[yuzu, gw, upstream, circuit_state]],
      fun() ->
          [notify(<<"blocker", (integer_to_binary(I))/binary>>, <<"b">>, connected)
           || I <- lists:seq(1, 10)],
          Blocked = [receive {blocked, P} -> P after 5000 -> error(not_blocked) end
                     || _ <- lists:seq(1, 10)],
          notify(agent(1), sid(1), connected),
          notify(agent(2), sid(2), connected),
          notify(agent(9), <<"gone">>, disconnected),
          _ = yuzu_gw_upstream:circuit_state(),
          ?assertEqual([], replay_sids()),
          [P ! go || P <- Blocked],
          ok = wait_until(fun() -> length(replay_sids()) >= 3 end, 5000),
          ?assertEqual(lists:sort([sid(1), sid(2), sid(3)]), lists:sort(replay_sids())),
          ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
          ?assertEqual([], [x || {tel, [yuzu, gw, upstream, circuit_state], _, _} <- flush()])
      end),
    Dummy ! stop.

flush() ->
    receive M -> [M | flush()] after 0 -> [] end.

closed_failure_is_requeued() ->
    Fails = atomics:new(1, []),
    atomics:put(Fails, 1, 1),
    mock(fun(<<"NotifyStreamStatus">>) ->
                 case atomics:sub_get(Fails, 1, 1) of
                     0 -> {error, econnrefused};
                     _ -> ok
                 end;
            (_) -> ok
         end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    with_events([[yuzu, gw, upstream, notify_requeued]],
      fun() ->
          notify(agent(1), <<"s">>, connected),
          ok = wait_until(fun() -> length(notify_calls()) >= 2 end, 5000),
          ?assertEqual([agent(1), agent(1)], notify_calls()),
          ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
          ?assertEqual([requeued], events())
      end).

same_key_waits_for_the_one_in_flight() ->
    Test = self(),
    mock_raw(fun(_Meta, Path, Req, _Def, _Opts) ->
                 case lists:last(binary:split(Path, <<"/">>, [global])) of
                     <<"NotifyStreamStatus">> ->
                         Test ! {entered, self(), maps:get(event, Req)},
                         receive go -> ok after 10000 -> ok end,
                         {ok, #{}, #{}};
                     _ ->
                         {ok, #{}, #{}}
                 end
             end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    notify(agent(1), <<"s">>, connected),
    W1 = receive {entered, P1, 'CONNECTED'} -> P1 after 5000 -> error(no_connected) end,
    notify(agent(1), <<"s">>, disconnected),
    receive {entered, _, 'DISCONNECTED'} -> error(sent_while_the_connected_is_in_flight)
    after 200 -> ok
    end,
    W1 ! go,
    W2 = receive {entered, P2, 'DISCONNECTED'} -> P2 after 5000 -> error(no_disconnected) end,
    W2 ! go.

high_water_mark_is_reported() ->
    mock(fun(_) -> {error, econnrefused} end),
    _ = yuzu_gw_test_upstream:start_upstream(),
    with_events([[yuzu, gw, upstream, notify_held]],
      fun() ->
          trip(),
          [notify(agent(I), <<"s">>, connected) || I <- lists:seq(1, 5)],
          _ = yuzu_gw_upstream:circuit_state(),
          ?assertEqual(5, lists:max([0 | [H || {hwm, H} <- events()]]))
      end).

%%--------------------------------------------------------------------
%% Plumbing
%%--------------------------------------------------------------------

agent(I) -> <<"cap-agent-", (integer_to_binary(I))/binary>>.
sid(I) -> <<"cap-session-", (integer_to_binary(I))/binary>>.

notify(AgentId, SessionId, Event) ->
    yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, Event, <<"127.0.0.1">>,
                                          <<"home">>).

%% Two failed proxied calls open the breaker (threshold 2).
trip() ->
    Prev = meck:expect(yuzu_grpc_client, unary, fun(_, _, _, _, _) -> {error, econnrefused} end),
    _ = Prev,
    yuzu_gw_test_upstream:trip_breaker(#{info => #{agent_id => <<"trip">>}}, 2).

%% Answer(Method) -> ok | {error, Reason}; every call is recorded.
mock(Answer) ->
    mock_raw(fun(Meta, Path, Req, _Def, _Opts) ->
                 Method = lists:last(binary:split(Path, <<"/">>, [global])),
                 ets:insert(?TAB, {call, Method, Req, Meta}),
                 case Answer(Method) of
                     ok when Method =:= <<"ProxyRegister">> ->
                         {ok, #{session_id => maps:get(<<"x-yuzu-session-id">>, Meta, <<"s">>),
                                accepted => true}, #{}};
                     ok -> {ok, #{}, #{}};
                     Error -> Error
                 end
             end).

mock_raw(Fun) ->
    ok = meck:expect(yuzu_grpc_client, unary, Fun).

replay_sids() ->
    [S || {call, <<"ProxyRegister">>, _, #{<<"x-yuzu-session-id">> := S}} <- ets:tab2list(?TAB)].

notify_calls() ->
    [maps:get(agent_id, Req) || {call, <<"NotifyStreamStatus">>, Req, _} <- ets:tab2list(?TAB)].

held() ->
    yuzu_gw_notify_queue:size(up_get(notify_pending)).

held_events() ->
    [{A, maps:get(event, N)} || {_Key, {A, N}} <- yuzu_gw_notify_queue:to_list(up_get(notify_pending))].

%% Run Fun with handlers for Events attached in this process; events() inside
%% Fun returns what they saw, as {Event, Reason} for notify_lost, `requeued' and
%% {hwm, N}. Detached afterwards whatever happens.
with_events(Events, Fun) ->
    Self = self(),
    Id = {?MODULE, Self},
    ok = telemetry:attach_many(Id, Events,
                               fun(E, M, Meta, _) -> Self ! {tel, E, M, Meta} end, none),
    try Fun()
    after telemetry:detach(Id)
    end.

events() ->
    _ = yuzu_gw_upstream:circuit_state(),
    collect([]).

collect(Acc) ->
    receive
        {tel, [yuzu, gw, upstream, notify_lost], _, #{event := E, reason := R}} ->
            collect([{E, R} | Acc]);
        {tel, [yuzu, gw, upstream, notify_dropped], _, Meta} ->
            collect([{dropped, maps:get(reason, Meta, undefined)} | Acc]);
        {tel, [yuzu, gw, upstream, notify_requeued], _, _} ->
            collect([requeued | Acc]);
        {tel, [yuzu, gw, upstream, notify_held], #{hwm := H}, _} ->
            collect([{hwm, H} | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.

up_get(Field) ->
    State = sys:get_state(yuzu_gw_upstream),
    Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_upstream.erl"]),
    {ok, Forms} = epp:parse_file(Src, []),
    [Fs] = [Fs0 || {attribute, _, record, {state, Fs0}} <- Forms],
    Names = [field_name(F) || F <- Fs],
    [I] = [I || {I, F} <- lists:zip(lists:seq(2, length(Names) + 1), Names), F =:= Field],
    element(I, State).

field_name({typed_record_field, F, _Type}) -> field_name(F);
field_name({record_field, _, {atom, _, Name}}) -> Name;
field_name({record_field, _, {atom, _, Name}, _Default}) -> Name.

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
