%%%-------------------------------------------------------------------
%%% @doc ReportInventory session admission (#5695).
%%%
%%% `yuzu_gw_agent_service:report_inventory/2' forwards an InventoryReport
%%% upstream only for a session this node holds, on the connection bound to it
%%% (the Heartbeat decision, yuzu_gw_heartbeat_admission:check/2). A refused
%%% report is answered NOT_FOUND "unknown session", counted on
%%% [yuzu, gw, inventory, rejected] by reason, logged without the session id,
%%% and never reaches yuzu_gw_upstream:proxy_inventory/2, so it takes no
%%% upstream permit and holds no wait-queue slot.
%%%
%%% The connection key is injected by mocking `yuzu_gw_conn:key_from_ctx/1', as
%%% in yuzu_gw_heartbeat_binding_tests. The registry is the real one; the
%%% upstream client is a mock whose call history is the evidence.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_inventory_admission_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("yuzu_gw/src/yuzu_grpc.hrl").

%% telemetry handler and logger handler callbacks
-export([handle_event/4, log/2]).

-define(EVENTS_TAB, yuzu_gw_inventory_admission_tests_events).
-define(HOLDERS_TAB, yuzu_gw_inventory_admission_tests_holders).
-define(HANDLER, yuzu_gw_inventory_admission_tests_handler).
-define(LOG_HANDLER, yuzu_gw_inventory_admission_tests_logs).
-define(CTX_KEY, yuzu_test_conn_key).

inventory_admission_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{"no session held: refused NOT_FOUND, never forwarded, counted",
       fun unknown_session_refused/0},
      {"held session on another connection: refused, never forwarded",
       fun wrong_connection_refused/0},
      {"held session on its own connection: forwarded unchanged",
       fun bound_connection_forwarded/0},
      {"pending session on its registering connection: forwarded",
       fun pending_session_forwarded/0},
      {"missing, empty or malformed session ids are refused without raising",
       fun malformed_session_ids_refused/0},
      {"a refusal does not count as a heartbeat rejection",
       fun refusal_is_not_a_heartbeat_event/0},
      {"the refusal log line names the reason, never the session id",
       fun refusal_log_carries_no_session_id/0}]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(yuzu_gw_conn),
    catch meck:unload(yuzu_gw_upstream),
    ok = meck:new(yuzu_gw_conn, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_conn, key_from_ctx,
                     fun(Ctx) -> ctx:get(Ctx, ?CTX_KEY, undefined) end),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_upstream, proxy_inventory,
                     fun(_Report, _Opts) -> {ok, #{received => true, need_full => []}} end),
    catch ets:delete(?EVENTS_TAB),
    ?EVENTS_TAB = ets:new(?EVENTS_TAB, [named_table, public, ordered_set]),
    catch ets:delete(?HOLDERS_TAB),
    ?HOLDERS_TAB = ets:new(?HOLDERS_TAB, [named_table, public, set]),
    catch telemetry:detach(?HANDLER),
    ok = telemetry:attach_many(?HANDLER,
                               [[yuzu, gw, inventory, rejected],
                                [yuzu, gw, heartbeat, rejected],
                                [yuzu, gw, heartbeat, session_mismatch]],
                               fun ?MODULE:handle_event/4, none),
    ok.

cleanup(_) ->
    reap_holders(),
    catch telemetry:detach(?HANDLER),
    catch ets:delete(?EVENTS_TAB),
    catch ets:delete(?HOLDERS_TAB),
    catch meck:unload([yuzu_gw_conn, yuzu_gw_upstream]),
    ok.

handle_event(Event, Measurements, Meta, _Config) ->
    true = ets:insert(?EVENTS_TAB, {erlang:unique_integer([monotonic]),
                                    Event, Measurements, Meta}),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

unknown_session_refused() ->
    ?assertEqual(refused(), report(make_ref(), report_for(uid(<<"nobody">>)))),
    ?assertEqual(0, forwarded()),
    ?assertEqual([{[yuzu, gw, inventory, rejected], #{count => 1},
                   #{reason => unknown_session}}], events()).

wrong_connection_refused() ->
    Session = uid(<<"held">>),
    bind(uid(<<"agent">>), Session, make_ref()),
    ?assertEqual(refused(), report(make_ref(), report_for(Session))),
    ?assertEqual(0, forwarded()),
    ?assertEqual([{[yuzu, gw, inventory, rejected], #{count => 1},
                   #{reason => connection_mismatch}}], events()).

bound_connection_forwarded() ->
    Session = uid(<<"held">>),
    Conn = make_ref(),
    bind(uid(<<"agent">>), Session, Conn),
    Report = (report_for(Session))#{content_hashes => #{<<"installed_software">> => <<"h">>}},
    ?assertMatch({ok, #{received := true}, _}, report(Conn, Report)),
    %% The decoded report reaches the upstream exactly as the agent sent it.
    ?assertMatch([{_, {yuzu_gw_upstream, proxy_inventory, [Report, _Opts]}, _}],
                 meck:history(yuzu_gw_upstream)),
    ?assertEqual([], events()).

pending_session_forwarded() ->
    Session = uid(<<"pending">>),
    Conn = holder(),
    ok = yuzu_gw_registry:store_pending(Session, #{agent_id => uid(<<"agent">>),
                                                   conn_key => Conn}),
    try
        ?assertEqual(refused(), report(make_ref(), report_for(Session))),
        ?assertEqual(0, forwarded()),
        ?assertMatch({ok, #{received := true}, _}, report(Conn, report_for(Session))),
        ?assertEqual(1, forwarded())
    after
        _ = yuzu_gw_registry:take_pending(Session)
    end.

malformed_session_ids_refused() ->
    Conn = make_ref(),
    [?assertEqual(refused(), report(Conn, Req))
     || Req <- [#{}, #{session_id => <<>>}, #{session_id => 42},
                #{session_id => undefined}, not_a_map]],
    ?assertEqual(0, forwarded()).

refusal_is_not_a_heartbeat_event() ->
    _ = report(make_ref(), report_for(uid(<<"nobody">>))),
    ?assertEqual([], [E || {E, _, _} <- events(), lists:nth(3, E) =:= heartbeat]).

refusal_log_carries_no_session_id() ->
    Session = uid(<<"secret-session">>),
    yuzu_gw_safe_call:expire_limit(inventory_refused),
    Lines = capture_logs(fun() ->
                            ?assertEqual(refused(), report(make_ref(), report_for(Session)))
                        end),
    Mine = [L || L <- Lines, binary:match(L, <<"ReportInventory refused">>) =/= nomatch],
    ?assertMatch([_], Mine),
    [Line] = Mine,
    ?assertNotEqual(nomatch, binary:match(Line, <<"unknown_session">>)),
    ?assertEqual(nomatch, binary:match(Line, Session)).

%%%===================================================================
%%% Helpers
%%%===================================================================

report(Key, Req) ->
    yuzu_gw_agent_service:report_inventory(ctx:set(ctx:background(), ?CTX_KEY, Key), Req).

report_for(Session) ->
    #{session_id => Session,
      collected_at => #{millis_epoch => 1},
      plugin_data => #{<<"installed_software">> => <<"blob">>}}.

refused() ->
    {grpc_error, {?GRPC_STATUS_NOT_FOUND, <<"unknown session">>}}.

forwarded() ->
    meck:num_calls(yuzu_gw_upstream, proxy_inventory, '_').

uid(Prefix) ->
    iolist_to_binary([Prefix, "-", integer_to_list(erlang:unique_integer([positive]))]).

holder() ->
    Pid = spawn(fun() -> receive stop -> ok end end),
    true = ets:insert(?HOLDERS_TAB, {Pid}),
    Pid.

bind(AgentId, Session, Conn) ->
    ok = yuzu_gw_registry:register_agent(AgentId, holder(), Session, [], <<>>, #{}, Conn).

%% Kill every holder and wait for the registry to drop the rows they owned.
reap_holders() ->
    Pids = try [P || {P} <- ets:tab2list(?HOLDERS_TAB)] catch error:badarg -> [] end,
    Mons = [monitor(process, P) || P <- Pids],
    [exit(P, kill) || P <- Pids],
    [receive {'DOWN', M, process, _, _} -> ok after 5000 -> ok end || M <- Mons],
    wait_unrouted(Pids, erlang:monotonic_time(millisecond) + 5000).

wait_unrouted(Pids, Deadline) ->
    Routed = try [element(2, R) || R <- ets:tab2list(yuzu_gw_agents)]
             catch error:badarg -> []
             end,
    case [P || P <- Pids, lists:member(P, Routed)] of
        [] -> ok;
        _ ->
            case erlang:monotonic_time(millisecond) > Deadline of
                true -> ok;
                false -> receive after 10 -> wait_unrouted(Pids, Deadline) end
            end
    end.

events() ->
    Events = [{E, M, Meta} || {_, E, M, Meta} <- ets:tab2list(?EVENTS_TAB)],
    true = ets:delete_all_objects(?EVENTS_TAB),
    Events.

capture_logs(Fun) ->
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => warning}),
    try
        Fun(),
        collect_logs([])
    after
        logger:remove_handler(?LOG_HANDLER)
    end.

collect_logs(Acc) ->
    receive {captured_log, Text} -> collect_logs([Text | Acc])
    after 0 -> lists:reverse(Acc)
    end.

log(#{msg := Msg}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S} -> unicode:characters_to_binary(S);
        {report, R} -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args} -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    Pid ! {captured_log, Text},
    ok.
