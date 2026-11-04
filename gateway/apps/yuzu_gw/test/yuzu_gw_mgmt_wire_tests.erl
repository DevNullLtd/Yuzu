%%%-------------------------------------------------------------------
%%% @doc ManagementService over the wire: the REAL yuzu_gw_mgmt_service served
%%% by a REAL listener (yuzu_gw_test_listener) and driven by the gun-based
%%% client (yuzu_gw_test_client). Only the process boundaries it calls are
%%% replaced (yuzu_gw_registry, yuzu_gw_router, yuzu_gw_agent), so what a
%%% handler returns is judged by the gRPC status and messages a client receives,
%%% not by calling the function:
%%%
%%%   - the unary handlers take `(Ctx, Request)' and answer `{ok, Response, Ctx}'
%%%     (called with the arguments swapped they would not serve a single call);
%%%   - errors are `{grpc_error, {Status, Message}}': agent not connected is 5
%%%     (including a stale pid whose process is gone), router unavailable is 14
%%%     with no message, any other fanout failure is 13;
%%%   - SendCommand is server-streaming: the agents' responses arrive as
%%%     SendCommandResponse messages and the call ends with status 0, and the
%%%     response derived from a command_error carries the request's command_id.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_wire_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.server.v1.ManagementService').
-define(LIST, <<"/yuzu.server.v1.ManagementService/ListAgents">>).
-define(GET, <<"/yuzu.server.v1.ManagementService/GetAgent">>).
-define(SEND, <<"/yuzu.server.v1.ManagementService/SendCommand">>).
-define(WATCH, <<"/yuzu.server.v1.ManagementService/WatchEvents">>).
-define(INVENTORY, <<"/yuzu.server.v1.ManagementService/QueryInventory">>).
-define(MOCKS, [yuzu_gw_registry, yuzu_gw_router, yuzu_gw_agent]).

%% The agents of the mocked registry, in agent id order.
-define(ROWS, [row(<<"a1">>, <<"host-1">>, [<<"os_info">>, <<"echo">>], 1001),
               row(<<"a2">>, <<"host-2">>, [<<"echo">>], 1002),
               row(<<"a3">>, <<"host-3">>, [], 1003),
               row(<<"a4">>, <<"host-4">>, [<<"os_info">>], 1004),
               row(<<"a5">>, <<"host-5">>, [], 1005)]).

mgmt_wire_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        [{"ListAgents: a page of the registry with its cursor", fun() -> list_page(State) end},
         {"ListAgents: the cursor resumes after the last agent of the previous page",
          fun() -> list_cursor(State) end},
         {"ListAgents: the last page has no cursor", fun() -> list_last_page(State) end},
         {"ListAgents: a limit outside 1..1000 is the default of 100", fun() -> list_limit(State) end},
         {"GetAgent: a connected agent", fun() -> get_found(State) end},
         {"GetAgent: an agent that is not connected is NOT_FOUND (5)", fun() -> get_missing(State) end},
         {"GetAgent: a stale pid (noproc) is NOT_FOUND (5)", fun() -> get_stale(State) end},
         {"GetAgent: a node that went away is NOT_FOUND (5)", fun() -> get_nodedown(State) end},
         {"GetAgent: an agent that answers with an error is INTERNAL (13)",
          fun() -> get_error(State) end},
         {"QueryInventory: every agent when no filter is given", fun() -> inventory_all(State) end},
         {"QueryInventory: filtered by agent id", fun() -> inventory_by_agent(State) end},
         {"QueryInventory: filtered by plugin", fun() -> inventory_by_plugin(State) end},
         {"QueryInventory: filtered by agent id and plugin", fun() -> inventory_by_both(State) end},
         {"QueryInventory: nothing matches is an empty answer, status 0",
          fun() -> inventory_none(State) end},
         {"SendCommand: the agents' responses stream back, then status 0",
          fun() -> send_responses(State) end},
         {"SendCommand: a command_error answers with the request's command_id",
          fun() -> send_command_error(State) end},
         {"SendCommand: a fanout with no response is status 0 and no message",
          fun() -> send_empty(State) end},
         {"SendCommand: router unavailable is UNAVAILABLE (14) and no message",
          fun() -> send_router_unavailable(State) end},
         {"SendCommand: any other fanout failure is INTERNAL (13) and no message",
          fun() -> send_fanout_failed(State) end},
         {"WatchEvents: only the watched agents' events stream, and ending the watch is status 0",
          fun() -> watch_events(State) end}]
     end}.

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    Pg = case pg:start_link(yuzu_gw) of
        {ok, P} -> P;
        {error, {already_started, _}} -> undefined
    end,
    [begin
         catch meck:unload(M),
         ok = meck:new(M, [passthrough, no_link])
     end || M <- ?MOCKS],
    Agents = #{live => spawn_idle(), error => spawn_idle(), nodedown => spawn_idle(),
               stale => spawn_dead()},
    mock_registry(Agents),
    mock_agent(Agents),
    {Port, Listener} = yuzu_gw_test_listener:start(
                         #{name => mgmt_wire, service_protos => [management_pb],
                           services => #{?SVC => yuzu_gw_mgmt_service}}),
    Chan = yuzu_gw_test_listener:client_channel(mgmt_wire_chan, #{port => Port}),
    #{pg => Pg, listener => Listener, chan => Chan, agents => Agents}.

cleanup(#{pg := Pg, listener := Listener, chan := Chan, agents := Agents}) ->
    yuzu_gw_test_listener:stop_channel(Chan),
    yuzu_gw_test_listener:stop(Listener),
    [meck:unload(M) || M <- ?MOCKS],
    [exit(Pid, kill) || Pid <- maps:values(Agents)],
    case Pg of
        undefined ->
            ok;
        _ ->
            unlink(Pg),
            gen_server:stop(Pg)
    end,
    ok.

row(Id, Host, Plugins, ConnectedAt) ->
    #{agent_id => Id, pid => self(), node => node(), session_id => <<"s-", Id/binary>>,
      plugins => Plugins, connected_at => ConnectedAt, hostname => Host}.

spawn_idle() ->
    spawn(fun() -> receive stop -> ok end end).

%% A pid whose process is gone, as a stale entry of the cross-node lookup is.
spawn_dead() ->
    {Pid, Ref} = spawn_monitor(fun() -> ok end),
    receive {'DOWN', Ref, process, Pid, _} -> Pid end.

%% list_agents/2 pages the way the real registry does: ordered by agent id,
%% resuming after the cursor, one more row than the limit decides the next cursor.
mock_registry(#{live := Live, error := Err, nodedown := Nd, stale := Stale}) ->
    meck:expect(yuzu_gw_registry, list_agents,
                fun(Limit, Cursor) ->
                    After = [R || #{agent_id := Id} = R <- ?ROWS,
                                  Cursor =:= undefined orelse Cursor =:= <<>> orelse Id > Cursor],
                    Page = lists:sublist(After, Limit),
                    Next = case length(After) > Limit of
                        true -> maps:get(agent_id, lists:last(Page));
                        false -> undefined
                    end,
                    {Page, Next}
                end),
    meck:expect(yuzu_gw_registry, lookup,
                fun(<<"live">>) -> {ok, Live};
                   (<<"error">>) -> {ok, Err};
                   (<<"nodedown">>) -> {ok, Nd};
                   (<<"stale">>) -> {ok, Stale};
                   (_) -> error
                end).

%% The live agents answer get_info; the stale pid is left to the real call,
%% which exits noproc as a call to a dead process does.
mock_agent(#{live := Live, error := Err, nodedown := Nd}) ->
    meck:expect(yuzu_gw_agent, get_info,
                fun(Pid) when Pid =:= Live ->
                       {ok, #{hostname => <<"live-host">>, plugins => [<<"os_info">>, <<"echo">>],
                              connected_at => 4242}};
                   (Pid) when Pid =:= Err ->
                       {error, boom};
                   (Pid) when Pid =:= Nd ->
                       exit({nodedown, 'gone@nowhere'});
                   (Pid) ->
                       meck:passthrough([Pid])
                end).

%%--------------------------------------------------------------------
%% ListAgents
%%--------------------------------------------------------------------

list_page(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?LIST, #{limit => 2}, list_def()),
    ?assertEqual([<<"a1">>, <<"a2">>], [Id || #{agent_id := Id} <- maps:get(agents, Response)]),
    ?assertMatch([#{hostname := <<"host-1">>, online := true, last_seen := #{millis_epoch := 1001}},
                  #{hostname := <<"host-2">>, online := true, last_seen := #{millis_epoch := 1002}}],
                 maps:get(agents, Response)),
    ?assertEqual(<<"a2">>, maps:get(next_cursor, Response, <<>>)).

list_cursor(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?LIST, #{limit => 2, cursor => <<"a2">>}, list_def()),
    ?assertEqual([<<"a3">>, <<"a4">>], [Id || #{agent_id := Id} <- maps:get(agents, Response)]),
    ?assertEqual(<<"a4">>, maps:get(next_cursor, Response, <<>>)).

list_last_page(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?LIST, #{limit => 2, cursor => <<"a4">>}, list_def()),
    ?assertEqual([<<"a5">>], [Id || #{agent_id := Id} <- maps:get(agents, Response)]),
    ?assertEqual(<<>>, maps:get(next_cursor, Response, <<>>)).

list_limit(#{chan := Chan}) ->
    [begin
         meck:reset(yuzu_gw_registry),
         {ok, Response, _} = unary(Chan, ?LIST, Request, list_def()),
         ?assertEqual(5, length(maps:get(agents, Response))),
         ?assertEqual(100, meck:capture(last, yuzu_gw_registry, list_agents, '_', 1))
     end || Request <- [#{}, #{limit => 0}, #{limit => 1001}, #{limit => -3}]].

%%--------------------------------------------------------------------
%% GetAgent
%%--------------------------------------------------------------------

get_found(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?GET, #{agent_id => <<"live">>}, get_def()),
    ?assertMatch(#{summary := #{agent_id := <<"live">>, hostname := <<"live-host">>,
                                online := true, last_seen := #{millis_epoch := 4242}}},
                 Response),
    ?assertEqual([<<"os_info">>, <<"echo">>], [N || #{name := N} <- maps:get(plugins, Response)]).

get_missing(#{chan := Chan}) ->
    ?assertMatch({error, {<<"5">>, <<"Agent not connected">>}, _},
                 unary(Chan, ?GET, #{agent_id => <<"nobody">>}, get_def())).

get_stale(#{chan := Chan}) ->
    ?assertMatch({error, {<<"5">>, <<"Agent not connected">>}, _},
                 unary(Chan, ?GET, #{agent_id => <<"stale">>}, get_def())).

get_nodedown(#{chan := Chan}) ->
    ?assertMatch({error, {<<"5">>, <<"Agent not connected">>}, _},
                 unary(Chan, ?GET, #{agent_id => <<"nodedown">>}, get_def())).

get_error(#{chan := Chan}) ->
    ?assertMatch({error, {<<"13">>, _}, _},
                 unary(Chan, ?GET, #{agent_id => <<"error">>}, get_def())).

%%--------------------------------------------------------------------
%% QueryInventory
%%--------------------------------------------------------------------

inventory_all(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?INVENTORY, #{}, inventory_def()),
    Data = maps:get(plugin_data, Response),
    ?assertEqual([<<"a1">>, <<"a2">>, <<"a3">>, <<"a4">>, <<"a5">>], lists:sort(maps:keys(Data))),
    %% each value is the agent's summary as JSON
    A1 = maps:get(<<"a1">>, Data),
    ?assertMatch({_, _}, binary:match(A1, <<"\"agent_id\":\"a1\"">>)),
    ?assertMatch({_, _}, binary:match(A1, <<"\"session_id\":\"s-a1\"">>)),
    ?assertMatch({_, _}, binary:match(A1, <<"\"connected_at\":1001">>)),
    ?assertMatch({_, _}, binary:match(A1, <<"\"plugins\":[\"os_info\",\"echo\"]">>)),
    ?assertMatch(#{collected_at := #{millis_epoch := _}}, Response).

inventory_by_agent(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?INVENTORY, #{agent_id => <<"a2">>}, inventory_def()),
    ?assertEqual([<<"a2">>], maps:keys(maps:get(plugin_data, Response))),
    ?assertEqual(<<"a2">>, maps:get(agent_id, Response)).

inventory_by_plugin(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?INVENTORY, #{plugin => <<"echo">>}, inventory_def()),
    ?assertEqual([<<"a1">>, <<"a2">>], lists:sort(maps:keys(maps:get(plugin_data, Response)))).

inventory_by_both(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?INVENTORY, #{agent_id => <<"a1">>, plugin => <<"echo">>},
                              inventory_def()),
    ?assertEqual([<<"a1">>], maps:keys(maps:get(plugin_data, Response))),
    {ok, Other, _} = unary(Chan, ?INVENTORY, #{agent_id => <<"a2">>, plugin => <<"os_info">>},
                           inventory_def()),
    ?assertEqual(#{}, maps:get(plugin_data, Other, #{})).

inventory_none(#{chan := Chan}) ->
    {ok, Response, _} = unary(Chan, ?INVENTORY, #{plugin => <<"no_such_plugin">>}, inventory_def()),
    ?assertEqual(#{}, maps:get(plugin_data, Response, #{})).

%%--------------------------------------------------------------------
%% SendCommand
%%--------------------------------------------------------------------

send_responses(#{chan := Chan}) ->
    meck:reset(yuzu_gw_router),
    meck:expect(yuzu_gw_router, send_command,
                fun(_AgentIds, _Command, _Opts) ->
                    Ref = make_ref(),
                    %% the router sends to the process that called it: the handler
                    Handler = self(),
                    [Handler ! {command_response, Ref, Id,
                                #{command_id => <<"c-1">>, status => 'SUCCESS',
                                  output => <<"out-", Id/binary>>, exit_code => 0}}
                     || Id <- [<<"a1">>, <<"a2">>]],
                    Handler ! {fanout_complete, Ref, #{}},
                    {ok, Ref}
                end),
    Request = #{agent_ids => [<<"a1">>, <<"a2">>], timeout_seconds => 30,
                command => #{command_id => <<"c-1">>, plugin => <<"os_info">>, action => <<"get">>}},
    {Messages, Status, _} = collect(send(Chan, Request)),
    ?assertEqual(<<"0">>, Status),
    ?assertMatch([#{agent_id := <<"a1">>,
                    response := #{command_id := <<"c-1">>, status := 'SUCCESS', output := <<"out-a1">>}},
                  #{agent_id := <<"a2">>,
                    response := #{command_id := <<"c-1">>, status := 'SUCCESS', output := <<"out-a2">>}}],
                 Messages),
    %% what the router was asked to do
    ?assertEqual([<<"a1">>, <<"a2">>], meck:capture(last, yuzu_gw_router, send_command, '_', 1)),
    ?assertMatch(#{command_id := <<"c-1">>, plugin := <<"os_info">>, action := <<"get">>},
                 meck:capture(last, yuzu_gw_router, send_command, '_', 2)),
    ?assertMatch(#{timeout_seconds := 30}, meck:capture(last, yuzu_gw_router, send_command, '_', 3)).

send_command_error(#{chan := Chan}) ->
    meck:expect(yuzu_gw_router, send_command,
                fun(_AgentIds, _Command, _Opts) ->
                    Ref = make_ref(),
                    Handler = self(),
                    Handler ! {command_error, Ref, <<"a3">>, not_connected},
                    Handler ! {fanout_complete, Ref, #{}},
                    {ok, Ref}
                end),
    Request = #{agent_ids => [<<"a3">>], command => #{command_id => <<"c-err">>}},
    {Messages, Status, _} = collect(send(Chan, Request)),
    ?assertEqual(<<"0">>, Status),
    ?assertMatch([#{agent_id := <<"a3">>,
                    response := #{command_id := <<"c-err">>, status := 'FAILURE',
                                  output := <<"not_connected">>, exit_code := -1}}],
                 Messages).

send_empty(#{chan := Chan}) ->
    meck:expect(yuzu_gw_router, send_command,
                fun(_AgentIds, _Command, _Opts) ->
                    Ref = make_ref(),
                    self() ! {fanout_complete, Ref, #{}},
                    {ok, Ref}
                end),
    ?assertMatch({[], <<"0">>, _},
                 collect(send(Chan, #{agent_ids => [], command => #{command_id => <<"c-0">>}}))).

send_router_unavailable(#{chan := Chan}) ->
    meck:expect(yuzu_gw_router, send_command,
                fun(_AgentIds, _Command, _Opts) -> {error, router_unavailable} end),
    {Messages, Status, Message} = collect(send(Chan, #{agent_ids => [<<"a1">>],
                                                       command => #{command_id => <<"c-u">>}})),
    ?assertEqual([], Messages),
    ?assertEqual(<<"14">>, Status),
    ?assertEqual(<<"Command router unavailable">>, Message).

send_fanout_failed(#{chan := Chan}) ->
    meck:expect(yuzu_gw_router, send_command,
                fun(_AgentIds, _Command, _Opts) -> {error, no_targets} end),
    {Messages, Status, _} = collect(send(Chan, #{agent_ids => [<<"a1">>],
                                                 command => #{command_id => <<"c-f">>}})),
    ?assertEqual([], Messages),
    ?assertEqual(<<"13">>, Status).

%%--------------------------------------------------------------------
%% WatchEvents
%%--------------------------------------------------------------------

%% The handler joins the pg group `event_watchers' of scope yuzu_gw; the join is
%% the event the test waits for before it hands the handler an agent event, as
%% the agent processes do.
watch_events(#{chan := Chan}) ->
    {Monitor, _} = pg:monitor(yuzu_gw, event_watchers),
    try
        {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?WATCH, #{agent_ids => [<<"a1">>]}, watch_def(),
                                             #{channel => Chan}),
        Watcher = receive
            {Monitor, join, event_watchers, [Pid]} -> Pid
        after 5000 -> error(watcher_did_not_join)
        end,
        Event = fun(Id) ->
                    {agent_event, #{agent_id => Id, event => {connected, #{session_id => <<"s-", Id/binary>>}}}}
                end,
        %% the event of an agent that is not watched is dropped; the one after it
        %% proves the loop went past it
        Watcher ! Event(<<"b2">>),
        Watcher ! Event(<<"a1">>),
        ?assertMatch({ok, #{agent_id := <<"a1">>, event := {connected, #{session_id := <<"s-a1">>}}}},
                     yuzu_gw_test_client:recv_data(S, 5000)),
        Watcher ! stop_watching,
        ?assertEqual({[], <<"0">>, <<>>}, collect(S))
    after
        pg:demonitor(yuzu_gw, Monitor)
    end.

%%--------------------------------------------------------------------
%% Client side
%%--------------------------------------------------------------------

unary(Chan, Path, Request, Def) ->
    yuzu_gw_test_client:unary(ctx:new(), Path, Request, Def, #{channel => Chan}).

send(Chan, Request) ->
    {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?SEND, Request, send_def(), #{channel => Chan}),
    S.

%% Every message of a stream, then its status and message. The stream ends
%% with `stream_finished' whatever its status; the status (0 or an error) and
%% its message are then read from the trailers.
collect(S) ->
    collect(S, []).

collect(S, Acc) ->
    case yuzu_gw_test_client:recv_data(S, 5000) of
        {ok, Message} -> collect(S, [Message | Acc]);
        stream_finished ->
            case yuzu_gw_test_client:recv_trailers(S, 5000) of
                {ok, {Status, Message, _}} -> {lists:reverse(Acc), Status, Message};
                Other -> {lists:reverse(Acc), {unexpected, Other}, undefined}
            end;
        Other -> {lists:reverse(Acc), {unexpected, Other}, undefined}
    end.

def(Request, Response) ->
    #{marshal => fun(M) -> management_pb:encode_msg(M, Request) end,
      unmarshal => fun(B) -> management_pb:decode_msg(B, Response) end}.

list_def() -> def('yuzu.server.v1.ListAgentsRequest', 'yuzu.server.v1.ListAgentsResponse').
get_def() -> def('yuzu.server.v1.GetAgentRequest', 'yuzu.server.v1.GetAgentResponse').
send_def() -> def('yuzu.server.v1.SendCommandRequest', 'yuzu.server.v1.SendCommandResponse').
watch_def() -> def('yuzu.server.v1.WatchEventsRequest', 'yuzu.server.v1.AgentEvent').
inventory_def() -> def('yuzu.server.v1.QueryInventoryRequest', 'yuzu.server.v1.QueryInventoryResponse').
