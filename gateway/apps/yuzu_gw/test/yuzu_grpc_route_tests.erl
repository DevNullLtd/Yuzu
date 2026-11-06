%%%-------------------------------------------------------------------
%%% @doc yuzu_grpc_route: the method table of the real agent and management
%%% services, and what is left out of it.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_route_tests).
-include_lib("eunit/include/eunit.hrl").

-define(AGENT, 'yuzu.agent.v1.AgentService').
-define(MGMT, 'yuzu.server.v1.ManagementService').

snake_case_test_() ->
    [?_assertEqual(Expected, yuzu_grpc_route:snake_case(Name)) ||
        {Name, Expected} <- [{'Register', register},
                             {'ListAgents', list_agents},
                             {'GetAgent', get_agent},
                             {'QueryInventory', query_inventory},
                             {'CheckForUpdate', check_for_update},
                             {'ReportInventory', report_inventory},
                             {'ExecuteCommand', execute_command},
                             {'WatchEvents', watch_events},
                             {'GetV2Thing', get_v_2_thing}]].

%% The twelve RPCs of the two protos. The agent service module does not export
%% check_for_update/2 or download_update/2: those two are UNIMPLEMENTED today
%% and stay so (a method with no function is absent from the table).
real_services_resolve_test() ->
    {ok, Agent} = yuzu_grpc_route:build([agent_pb], #{?AGENT => yuzu_gw_agent_service}),
    {ok, Mgmt} = yuzu_grpc_route:build([management_pb], #{?MGMT => yuzu_gw_mgmt_service}),
    Expected = [{<<"/yuzu.agent.v1.AgentService/Register">>, yuzu_gw_agent_service, register, unary},
                {<<"/yuzu.agent.v1.AgentService/Heartbeat">>, yuzu_gw_agent_service, heartbeat, unary},
                {<<"/yuzu.agent.v1.AgentService/ExecuteCommand">>, yuzu_gw_agent_service,
                 execute_command, server_stream},
                {<<"/yuzu.agent.v1.AgentService/Subscribe">>, yuzu_gw_agent_service, subscribe, bidi},
                {<<"/yuzu.agent.v1.AgentService/ReportInventory">>, yuzu_gw_agent_service,
                 report_inventory, unary},
                {<<"/yuzu.server.v1.ManagementService/ListAgents">>, yuzu_gw_mgmt_service,
                 list_agents, unary},
                {<<"/yuzu.server.v1.ManagementService/GetAgent">>, yuzu_gw_mgmt_service,
                 get_agent, unary},
                {<<"/yuzu.server.v1.ManagementService/SendCommand">>, yuzu_gw_mgmt_service,
                 send_command, server_stream},
                {<<"/yuzu.server.v1.ManagementService/WatchEvents">>, yuzu_gw_mgmt_service,
                 watch_events, server_stream},
                {<<"/yuzu.server.v1.ManagementService/QueryInventory">>, yuzu_gw_mgmt_service,
                 query_inventory, unary}],
    Table = maps:merge(Agent, Mgmt),
    [begin
         {ok, Route} = yuzu_grpc_route:lookup(Path, Table),
         ?assertMatch(#{module := Mod, function := Fun, kind := Kind, path := Path}, Route)
     end || {Path, Mod, Fun, Kind} <- Expected],
    ?assertEqual(length(Expected), map_size(Table)),
    ?assertEqual(error, yuzu_grpc_route:lookup(
                          <<"/yuzu.agent.v1.AgentService/CheckForUpdate">>, Table)),
    ?assertEqual(error, yuzu_grpc_route:lookup(
                          <<"/yuzu.agent.v1.AgentService/DownloadUpdate">>, Table)).

route_carries_the_message_types_test() ->
    {ok, Table} = yuzu_grpc_route:build([agent_pb], #{?AGENT => yuzu_gw_agent_service}),
    {ok, Route} = yuzu_grpc_route:lookup(<<"/yuzu.agent.v1.AgentService/Subscribe">>, Table),
    %% Subscribe: the agent streams CommandResponses in, the gateway streams
    %% CommandRequests out.
    ?assertMatch(#{pb := agent_pb,
                   input := 'yuzu.agent.v1.CommandResponse',
                   output := 'yuzu.agent.v1.CommandRequest'}, Route).

%% management_pb also describes the agent service (it imports that proto). Only
%% the services named in `services' are routed.
only_named_services_are_routed_test() ->
    {ok, Table} = yuzu_grpc_route:build([management_pb], #{?MGMT => yuzu_gw_mgmt_service}),
    ?assertEqual(5, map_size(Table)),
    ?assertEqual(error, yuzu_grpc_route:lookup(<<"/yuzu.agent.v1.AgentService/Register">>, Table)).

%% A function the module does not export is a method that is not there.
unexported_function_is_absent_test() ->
    {ok, Table} = yuzu_grpc_route:build([management_pb], #{?MGMT => yuzu_gw_authz_stub_svc}),
    ?assertMatch({ok, #{function := list_agents}},
                 yuzu_grpc_route:lookup(<<"/yuzu.server.v1.ManagementService/ListAgents">>, Table)),
    ?assertMatch({ok, #{function := send_command, kind := server_stream}},
                 yuzu_grpc_route:lookup(<<"/yuzu.server.v1.ManagementService/SendCommand">>, Table)),
    ?assertEqual(error, yuzu_grpc_route:lookup(
                          <<"/yuzu.server.v1.ManagementService/GetAgent">>, Table)),
    ?assertEqual(2, map_size(Table)).

%% A module that exports none of a service's handlers is refused: a listener
%% serving a service nothing answers is a mistyped module, not a partial one.
module_without_handlers_is_refused_test() ->
    ?assertEqual({error, {service_without_routes, ?MGMT}},
                 yuzu_grpc_route:build([management_pb], #{?MGMT => yuzu_gw_authz_tests})),
    %% the refusal is per service: one good service does not excuse another
    ?assertEqual({error, {service_without_routes, ?AGENT}},
                 yuzu_grpc_route:build([agent_pb, management_pb],
                                       #{?AGENT => yuzu_gw_authz_tests,
                                         ?MGMT => yuzu_gw_mgmt_service})).

unknown_path_test() ->
    {ok, Table} = yuzu_grpc_route:build([agent_pb], #{?AGENT => yuzu_gw_agent_service}),
    [?assertEqual(error, yuzu_grpc_route:lookup(Path, Table)) ||
        Path <- [<<"/">>, <<>>, <<"/yuzu.agent.v1.AgentService">>,
                 <<"/yuzu.agent.v1.AgentService/">>,
                 <<"/yuzu.agent.v1.AgentService/register">>,
                 <<"/yuzu.agent.v1.AgentService/Register/">>,
                 <<"yuzu.agent.v1.AgentService/Register">>,
                 <<"/yuzu.agent.v1.AgentServiceX/Register">>,
                 <<"//yuzu.agent.v1.AgentService/Register">>]].

service_no_proto_describes_is_an_error_test() ->
    ?assertEqual({error, {unknown_service, 'no.such.Service'}},
                 yuzu_grpc_route:build([agent_pb], #{'no.such.Service' => yuzu_gw_agent_service})).

module_that_cannot_be_loaded_is_an_error_test() ->
    ?assertEqual({error, {module_not_loaded, no_such_module_for_yuzu_grpc}},
                 yuzu_grpc_route:build([agent_pb], #{?AGENT => no_such_module_for_yuzu_grpc})).

%% A service module that is not an atom is a missing module, not a crash of
%% code:ensure_loaded/1.
service_module_that_is_not_an_atom_is_an_error_test_() ->
    [?_assertEqual({error, {module_not_loaded, Bad}},
                   yuzu_grpc_route:build([agent_pb], #{?AGENT => Bad})) ||
        Bad <- ["yuzu_gw_agent_service", <<"yuzu_gw_agent_service">>, 42, {m, f}]].

no_services_is_an_empty_table_test() ->
    ?assertEqual({ok, #{}}, yuzu_grpc_route:build([agent_pb], #{})).
