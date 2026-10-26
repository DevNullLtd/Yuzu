%%%-------------------------------------------------------------------
%%% @doc The per-upstream capability gate on relayed inventory sources
%%% (slice-2 PR 2a-2a, governance g8sec-1; yuzu_gw_upstream's module doc).
%%%
%%% The gateway may replay a registration without the agent seeing the answer,
%%% and may send a later ProxyInventory to a different upstream than the one
%%% whose RegisterResponse the agent saw. So it records, per upstream HTTP/2
%%% connection, the gated capabilities of that connection's latest accepted
%%% ProxyRegister answer, and removes `certificate_inventory' from a relayed
%%% report whose connection did not list `certificate_inventory_v1'.
%%%
%%% The client is mocked the way grpcbox runs a call: the mock of
%%% grpcbox_client:unary/5 picks a subchannel (the test sets which), runs the
%%% REAL yuzu_gw_upstream:subchannel_interceptor/7 with it, and the handler calls
%%% the REAL request encoder (marshal_fun), which is where the gate acts. The
%%% subchannel and the connection are fakes: grpcbox_subchannel:conn/2 answers a
%%% fake stream set naming the connection process the test mapped the
%%% subchannel to, and h2_stream_set:connection/1 reads it back. Every encoded
%%% request is decoded from the bytes the encoder produced, so the assertions
%%% read what would have gone on the wire.
%%%
%%% Real: yuzu_gw_upstream, the encoder (gateway_pb), the interceptor, and for
%%%       the replay case yuzu_gw_registry (yuzu_gw_test_registry:ensure/0).
%%% Mocks: grpcbox_client, grpcbox_subchannel, h2_stream_set, telemetry,
%%%       yuzu_gw_agent (reannounce/disconnect only).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_inventory_capability_gate_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-define(T, cap_gate_test_tab).
-define(CERT, <<"certificate_inventory">>).
-define(CAP, <<"certificate_inventory_v1">>).
-define(EV, [yuzu, gw, upstream, inventory_source_stripped]).
-define(REG_PATH, <<"/yuzu.gateway.v1.GatewayUpstream/ProxyRegister">>).
-define(INV_PATH, <<"/yuzu.gateway.v1.GatewayUpstream/ProxyInventory">>).

%%%===================================================================
%%% Fixture
%%%===================================================================

gate_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun(_) -> {Name, {timeout, 30, Fun}} end
      || {Name, Fun} <-
             [{"a report to a capable upstream keeps the certificate_inventory key",
               fun capable_upstream_keeps_key/0},
              {"a report to an upstream with no recorded answer is stripped (upstream_unknown)",
               fun unknown_upstream_strips/0},
              {"a report to an upstream whose answer lacked the capability is stripped",
               fun incapable_upstream_strips/0},
              {"the record is per connection: capable A does not let a report through B",
               fun capability_is_per_connection/0},
              {"a later answer without the capability removes it",
               fun capability_lost_on_later_answer/0},
              {"a rejected answer (accepted=false) changes nothing",
               fun rejected_answer_changes_nothing/0},
              {"a connection that exits loses its record; its replacement starts unknown",
               fun connection_exit_drops_record/0},
              {"without the interceptor the connection is unknown and the key is stripped",
               fun no_interceptor_strips/0},
              {"a report without a gated key is forwarded unchanged and resolves no connection",
               fun ungated_report_untouched/0},
              {"a registration REPLAY answer records the capability too",
               fun replay_records_capability/0}]]}.

setup() ->
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(grpcbox_client),
    catch meck:unload(grpcbox_subchannel),
    catch meck:unload(h2_stream_set),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_agent),
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Leaked    -> catch unlink(Leaked),
                     catch gen_server:stop(Leaked, shutdown, 1000)
    end,
    catch ets:delete(?T),
    ets:new(?T, [named_table, public, set]),
    ets:insert(?T, [{interceptor, true}, {wire, []}, {stripped, []}, {conn_calls, 0}]),

    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun unary/5),
    meck:new(grpcbox_subchannel, [non_strict, no_link]),
    meck:expect(grpcbox_subchannel, conn,
                fun(Sub, _Timeout) ->
                        ets:update_counter(?T, conn_calls, 1),
                        case ets:lookup(?T, {route, Sub}) of
                            [{_, Conn}] -> {ok, {fake_set, Conn}, #{}};
                            []          -> {error, no_route}
                        end
                end),
    meck:new(h2_stream_set, [non_strict, no_link]),
    meck:expect(h2_stream_set, connection, fun({fake_set, Conn}) -> Conn end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute,
                fun(Ev, _Meas, Meta) when Ev =:= ?EV ->
                        [{stripped, L}] = ets:lookup(?T, stripped),
                        ets:insert(?T, {stripped, L ++ [{maps:get(source, Meta),
                                                         maps:get(reason, Meta)}]}),
                        ok;
                   (_, _, _) -> ok
                end),
    meck:new(yuzu_gw_agent, [passthrough, no_link]),
    meck:expect(yuzu_gw_agent, reannounce, fun(_Pid, _Sid) -> ok end),
    meck:expect(yuzu_gw_agent, disconnect, fun(_Pid) -> ok end),
    application:set_env(yuzu_gw, registration_replay_spacing_ms, 0),
    {ok, Up} = yuzu_gw_upstream:start_link(),
    Up.

cleanup(Up) ->
    catch unlink(Up),
    catch gen_server:stop(Up, shutdown, 5000),
    lists:foreach(fun(Id) -> yuzu_gw_registry:deregister_agent(Id) end,
                  yuzu_gw_registry:all_agents()),
    [catch exit(P, kill) || {{proc, _}, P} <- ets:tab2list(?T)],
    catch ets:delete(?T),
    application:unset_env(yuzu_gw, registration_replay_spacing_ms),
    meck:unload([grpcbox_client, grpcbox_subchannel, h2_stream_set, telemetry, yuzu_gw_agent]),
    ok.

%%%===================================================================
%%% The mocked client: one subchannel per call, the real interceptor, the
%%% real encoder.
%%%===================================================================

unary(Ctx, Path, Input, #grpcbox_def{marshal_fun = Marshal}, Opts) ->
    [{_, Sub}] = ets:lookup(?T, next_sub),
    Handler = fun(_Ctx, In) ->
                      Bin = Marshal(In),
                      [{wire, W}] = ets:lookup(?T, wire),
                      ets:insert(?T, {wire, W ++ [{Path, Bin}]}),
                      answer(Path, Sub)
              end,
    case ets:lookup(?T, interceptor) of
        [{_, true}] ->
            yuzu_gw_upstream:subchannel_interceptor(Ctx, Sub, Handler, Path, Input,
                                                     undefined, Opts);
        _ ->
            Handler(Ctx, Input)
    end.

answer(?REG_PATH, Sub) ->
    [{_, Conn}] = ets:lookup(?T, {route, Sub}),
    Resp = case ets:lookup(?T, {answer, Conn}) of
               [{_, R}] -> R;
               []       -> #{session_id => <<"s">>, accepted => true}
           end,
    {ok, Resp, #{}};
answer(?INV_PATH, _Sub) ->
    {ok, #{received => true}, #{}};
answer(_Path, _Sub) ->
    {ok, #{}, #{}}.

%%%===================================================================
%%% Helpers
%%%===================================================================

%% A fake upstream: a subchannel pid routed to a connection pid.
upstream(Name) ->
    Sub = spawn_idle(),
    Conn = spawn_idle(),
    ets:insert(?T, [{{route, Sub}, Conn}, {{proc, {sub, Name}}, Sub},
                    {{proc, {conn, Name}}, Conn}]),
    {Sub, Conn}.

spawn_idle() ->
    spawn(fun() -> receive stop -> ok end end).

via({Sub, _Conn}) -> ets:insert(?T, {next_sub, Sub}).

answers({_Sub, Conn}, Caps) ->
    ets:insert(?T, {{answer, Conn}, #{session_id => <<"s">>, accepted => true,
                                       server_capabilities => Caps}}).

register_via(U) ->
    via(U),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{agent_id => <<"agent-1">>}),
    ok.

report() ->
    #{session_id => <<"sess-1">>,
      plugin_data => #{?CERT => <<"cert-blob">>,
                       <<"installed_software">> => <<"sw-blob">>},
      content_hashes => #{?CERT => <<"h1">>, <<"installed_software">> => <<"h2">>}}.

%% Send Report through U; answer the decoded request that went on the wire.
inventory_via(U, Report) ->
    via(U),
    {ok, _} = yuzu_gw_upstream:proxy_inventory(Report),
    [{_, W}] = ets:lookup(?T, wire),
    {?INV_PATH, Bin} = lists:last(W),
    gateway_pb:decode_msg(Bin, 'yuzu.agent.v1.InventoryReport').

keys(Sent) -> lists:sort(maps:keys(maps:get(plugin_data, Sent, #{}))).

stripped() ->
    [{_, L}] = ets:lookup(?T, stripped),
    L.

%%%===================================================================
%%% Tests
%%%===================================================================

capable_upstream_keeps_key() ->
    A = upstream(a),
    answers(A, [<<"other_cap">>, ?CAP]),
    register_via(A),
    Sent = inventory_via(A, report()),
    ?assertEqual([?CERT, <<"installed_software">>], keys(Sent)),
    ?assertEqual(<<"cert-blob">>, maps:get(?CERT, maps:get(plugin_data, Sent))),
    ?assertEqual([], stripped()).

unknown_upstream_strips() ->
    A = upstream(a),
    Sent = inventory_via(A, report()),
    ?assertEqual([<<"installed_software">>], keys(Sent)),
    %% Every other key, content_hashes included, is forwarded unchanged.
    ?assertEqual(<<"sw-blob">>, maps:get(<<"installed_software">>, maps:get(plugin_data, Sent))),
    ?assertEqual(#{?CERT => <<"h1">>, <<"installed_software">> => <<"h2">>},
                 maps:get(content_hashes, Sent)),
    ?assertEqual([{?CERT, <<"upstream_unknown">>}], stripped()).

incapable_upstream_strips() ->
    A = upstream(a),
    answers(A, []),
    register_via(A),
    Sent = inventory_via(A, report()),
    ?assertEqual([<<"installed_software">>], keys(Sent)),
    ?assertEqual([{?CERT, <<"upstream_lacks_capability">>}], stripped()).

capability_is_per_connection() ->
    A = upstream(a),
    B = upstream(b),
    answers(A, [?CAP]),
    answers(B, []),
    register_via(A),
    register_via(B),
    ?assertEqual([?CERT, <<"installed_software">>], keys(inventory_via(A, report()))),
    ?assertEqual([<<"installed_software">>], keys(inventory_via(B, report()))),
    ?assertEqual([{?CERT, <<"upstream_lacks_capability">>}], stripped()).

capability_lost_on_later_answer() ->
    A = upstream(a),
    answers(A, [?CAP]),
    register_via(A),
    ?assertEqual([?CERT, <<"installed_software">>], keys(inventory_via(A, report()))),
    answers(A, []),
    register_via(A),
    ?assertEqual([<<"installed_software">>], keys(inventory_via(A, report()))),
    ?assertEqual([{?CERT, <<"upstream_lacks_capability">>}], stripped()).

rejected_answer_changes_nothing() ->
    A = upstream(a),
    answers(A, [?CAP]),
    register_via(A),
    {_, Conn} = A,
    ets:insert(?T, {{answer, Conn}, #{accepted => false, reject_reason => <<"no">>}}),
    register_via(A),
    ?assertEqual([?CERT, <<"installed_software">>], keys(inventory_via(A, report()))),
    %% And a rejected first answer records nothing: still unknown.
    B = upstream(b),
    {_, ConnB} = B,
    ets:insert(?T, {{answer, ConnB}, #{accepted => false, server_capabilities => [?CAP]}}),
    register_via(B),
    ?assertEqual([<<"installed_software">>], keys(inventory_via(B, report()))),
    ?assertEqual([{?CERT, <<"upstream_unknown">>}], stripped()).

connection_exit_drops_record() ->
    {Sub, Conn} = A = upstream(a),
    answers(A, [?CAP]),
    register_via(A),
    Ref = erlang:monitor(process, Conn),
    exit(Conn, kill),
    receive {'DOWN', Ref, process, Conn, _} -> ok after 5000 -> error(conn_not_down) end,
    %% The subchannel reconnects: a new connection, never answered.
    Conn2 = spawn_idle(),
    ets:insert(?T, [{{route, Sub}, Conn2}, {{proc, {conn, a2}}, Conn2}]),
    ?assertEqual([<<"installed_software">>], keys(inventory_via(A, report()))),
    ?assertEqual([{?CERT, <<"upstream_unknown">>}], stripped()),
    %% The record of the dead connection is gone (the DOWN is handled before the
    %% call above, which the gen_server processed after it).
    {status, _, _, [_, _, _, _, Misc]} = sys:get_status(yuzu_gw_upstream),
    [Fields] = [F || {data, [{"State", F}]} <- Misc],
    ?assertEqual(#{}, maps:get(upstream_caps, Fields)).

no_interceptor_strips() ->
    ets:insert(?T, {interceptor, false}),
    A = upstream(a),
    answers(A, [?CAP]),
    register_via(A),
    ?assertEqual([<<"installed_software">>], keys(inventory_via(A, report()))),
    ?assertEqual([{?CERT, <<"upstream_unknown">>}], stripped()).

ungated_report_untouched() ->
    A = upstream(a),
    Report = #{session_id => <<"sess-1">>,
               plugin_data => #{<<"installed_software">> => <<"sw-blob">>},
               content_hashes => #{<<"installed_software">> => <<"h2">>}},
    Sent = inventory_via(A, Report),
    ?assertEqual(maps:get(plugin_data, Report), maps:get(plugin_data, Sent)),
    ?assertEqual(maps:get(content_hashes, Report), maps:get(content_hashes, Sent)),
    ?assertEqual([], stripped()),
    %% No connection lookup for a report with no gated key.
    ?assertEqual([{conn_calls, 0}], ets:lookup(?T, conn_calls)).

replay_records_capability() ->
    A = upstream(a),
    answers(A, [?CAP]),
    via(A),
    Id = iolist_to_binary(["cap-gate-", integer_to_list(erlang:unique_integer([positive]))]),
    Sid = <<"sess-", Id/binary>>,
    Dummy = spawn_idle(),
    ets:insert(?T, {{proc, dummy}, Dummy}),
    ok = yuzu_gw_registry:register_agent(Id, Dummy, Sid, [<<"svc">>], <<"host">>,
                                         #{agent_id => Id}, conn_test),
    ok = yuzu_gw_upstream:replay_sessions([Sid]),
    ok = wait_until(fun() -> meck:num_calls(yuzu_gw_agent, reannounce, '_') > 0 end, 5000),
    %% The replay was the only ProxyRegister, so the capability came from it.
    [{_, W}] = ets:lookup(?T, wire),
    ?assertEqual([?REG_PATH], [P || {P, _} <- W]),
    ?assertEqual([?CERT, <<"installed_software">>], keys(inventory_via(A, report()))),
    ?assertEqual([], stripped()).

wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of true -> ok; false -> {error, timeout} end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(10), wait_until(Pred, Timeout - 10)
    end.

%%%===================================================================
%%% Pure: strip_gated_sources/2
%%%===================================================================

strip_keeps_key_when_listed_test() ->
    R = report(),
    ?assertEqual({R, []}, yuzu_gw_upstream:strip_gated_sources(R, [?CAP])).

strip_removes_key_when_unknown_or_unlisted_test() ->
    R = report(),
    Expected = R#{plugin_data := #{<<"installed_software">> => <<"sw-blob">>}},
    ?assertEqual({Expected, [{?CERT, upstream_unknown}]},
                 yuzu_gw_upstream:strip_gated_sources(R, unknown)),
    ?assertEqual({Expected, [{?CERT, upstream_lacks_capability}]},
                 yuzu_gw_upstream:strip_gated_sources(R, [<<"other">>])).

strip_leaves_reports_without_the_key_alone_test() ->
    R1 = #{session_id => <<"s">>},
    R2 = #{plugin_data => #{<<"device_ci">> => <<"x">>}},
    ?assertEqual({R1, []}, yuzu_gw_upstream:strip_gated_sources(R1, unknown)),
    ?assertEqual({R2, []}, yuzu_gw_upstream:strip_gated_sources(R2, unknown)).

%%%===================================================================
%%% The metric: closed label sets, pre-seeded at 0
%%%===================================================================

stripped_metric_test_() ->
    {setup,
     fun() ->
             {ok, S1} = application:ensure_all_started(prometheus),
             {ok, S2} = application:ensure_all_started(telemetry),
             catch telemetry:detach(yuzu_gw_prometheus),
             [catch prometheus_counter:remove(yuzu_gw_inventory_source_stripped_total, [S, R])
              || S <- [<<"certificate_inventory">>, <<"unknown">>],
                 R <- [<<"upstream_lacks_capability">>, <<"upstream_unknown">>, <<"unknown">>]],
             ok = yuzu_gw_telemetry:setup(),
             S1 ++ S2
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [{"every series exists at 0 after setup; events land on their own series; "
       "an out-of-set value folds to unknown",
       fun() ->
               V = fun(S, R) ->
                           prometheus_counter:value(yuzu_gw_inventory_source_stripped_total,
                                                    [S, R])
                   end,
               ?assertEqual(0, V(<<"certificate_inventory">>, <<"upstream_unknown">>)),
               ?assertEqual(0, V(<<"unknown">>, <<"unknown">>)),
               telemetry:execute(?EV, #{count => 1}, #{source => ?CERT,
                                                      reason => <<"upstream_unknown">>}),
               ?assertEqual(1, V(<<"certificate_inventory">>, <<"upstream_unknown">>)),
               telemetry:execute(?EV, #{count => 1}, #{source => <<"made_up">>,
                                                      reason => <<"made_up">>}),
               ?assertEqual(1, V(<<"unknown">>, <<"unknown">>))
       end}]}.

%%%===================================================================
%%% install_subchannel_interceptor/0
%%%===================================================================

install_interceptor_test() ->
    Tab = channels_table,
    Key = {default_channel, unary},
    Own = ets:whereis(Tab) =:= undefined,
    Saved = case Own of
                true  -> ets:new(Tab, [named_table, set, public]), [];
                false -> ets:lookup(Tab, Key)
            end,
    try
        ets:delete(Tab, Key),
        ?assertEqual(installed, yuzu_gw_upstream:install_subchannel_interceptor()),
        ?assertEqual([{Key, fun yuzu_gw_upstream:subchannel_interceptor/7}],
                     ets:lookup(Tab, Key)),
        ?assertEqual(installed, yuzu_gw_upstream:install_subchannel_interceptor()),
        Other = fun(C, Ch, H, P, I, D, O) ->
                        yuzu_gw_upstream:subchannel_interceptor(C, Ch, H, P, I, D, O)
                end,
        ets:insert(Tab, {Key, Other}),
        ?assertEqual(other_interceptor, yuzu_gw_upstream:install_subchannel_interceptor()),
        %% The operator's interceptor is never replaced.
        ?assertEqual([{Key, Other}], ets:lookup(Tab, Key))
    after
        case Own of
            true  -> ets:delete(Tab);
            false -> ets:delete(Tab, Key), ets:insert(Tab, Saved)
        end
    end.

install_interceptor_without_grpcbox_test() ->
    case ets:whereis(channels_table) of
        undefined ->
            ?assertEqual(not_running, yuzu_gw_upstream:install_subchannel_interceptor());
        _ ->
            ok
    end.

%% The interceptor restores the caller's process dictionary, even when the call
%% raises.
interceptor_restores_pd_test() ->
    Key = '$yuzu_gw_upstream_subchannel',
    erase(Key),
    Self = self(),
    ?assertEqual(ok, yuzu_gw_upstream:subchannel_interceptor(
                       ctx, Self, fun(_, _) -> Self = get(Key), ok end, <<>>, in, def, #{})),
    ?assertEqual(undefined, get(Key)),
    ?assertError(boom, yuzu_gw_upstream:subchannel_interceptor(
                         ctx, Self, fun(_, _) -> error(boom) end, <<>>, in, def, #{})),
    ?assertEqual(undefined, get(Key)).

%% A state from before the gate (one field short) gains an empty record.
code_change_appends_empty_caps_test() ->
    {ok, Up} = gen_server:start({local, cap_gate_cc_probe}, yuzu_gw_upstream, [], []),
    try
        New = sys:get_state(Up),
        Old = erlang:delete_element(tuple_size(New), New),
        ?assertEqual(#{}, element(tuple_size(New), New)),
        {ok, Upgraded} = yuzu_gw_upstream:code_change("0", Old, []),
        ?assertEqual(New, Upgraded),
        ?assertEqual({ok, New}, yuzu_gw_upstream:code_change("0", New, []))
    after
        gen_server:stop(Up, shutdown, 5000)
    end.
