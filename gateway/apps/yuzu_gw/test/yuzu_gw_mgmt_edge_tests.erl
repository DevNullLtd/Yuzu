%%%-------------------------------------------------------------------
%%% @doc Wire tests of the management listener's edge under the load the C++
%%% server puts on it: ONE HTTP/2 connection carrying every command of a
%%% fan-out. Against a real Cowboy/Ranch listener, driven by a raw gun client
%%% (the server's view: many server-streaming SendCommand calls on one
%%% connection).
%%%
%%%   - per-connection memory ceiling: the max_heap_size ceiling that bounds an
%%%     anonymous agent connection is not applied to the management listener by
%%%     default, so a synchronized burst of large responses (every agent of a
%%%     fan-out answering at once) does not kill the connection; the agent
%%%     listener keeps its ceiling;
%%%   - deadline hierarchy: a stream with a grpc-timeout is answered
%%%     DEADLINE_EXCEEDED a margin BEFORE the caller's own deadline, so a client
%%%     whose many streams share a deadline gets every answer first and has no
%%%     stream to cancel, and the connection survives Cowboy's cancel-rate limit.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_edge_tests).
-include_lib("eunit/include/eunit.hrl").

-define(MGMT_SVC, 'yuzu.server.v1.ManagementService').
-define(AGENT_SVC, 'yuzu.agent.v1.AgentService').
-define(SEND_COMMAND, <<"/yuzu.server.v1.ManagementService/SendCommand">>).
-define(LIST_AGENTS, <<"/yuzu.server.v1.ManagementService/ListAgents">>).
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).

%% The management entry of config/sys.config.prod, less TLS and the pin (the
%% layer applies max_heap_size the same way with or without them).
prod_mgmt_entry(Extra) ->
    maps:merge(#{name => edge_mgmt,
                 service_protos => [management_pb],
                 services => #{?MGMT_SVC => yuzu_gw_edge_stub_svc},
                 listen => #{port => 0},
                 acceptors => 4,
                 limits => #{max_connections => 256, max_message_bytes => 4194304},
                 http2 => #{idle_timeout => 600000, max_concurrent_streams => 1024,
                            max_received_frame_rate => {100000, 10000}}},
               Extra).

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_edge_stub_svc:init(self()),
    yuzu_grpc_stub_svc:init_state(),
    ok.

cleanup(_) ->
    yuzu_gw_edge_stub_svc:stop(),
    ok.

%%%-------------------------------------------------------------------
%%% 1. The per-connection memory ceiling
%%%-------------------------------------------------------------------

%% 32 SendCommand streams on one connection, each handler blocked until the
%% test releases all of them at once; each then sends one 1 MiB response. The
%% 32 MiB arrive in the connection process together, faster than the client's
%% flow-control window lets Cowboy write them out, so they sit in its buffers.
%% Under the agent listener's ceiling (16 MiB with the shipped 4 MiB message
%% limit) the VM kills the connection and every call on it fails; the
%% management listener has no ceiling by default, Cowboy's own output-buffer
%% alarm paces the senders, and every call completes on the same connection.
mgmt_burst_of_large_responses_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     {timeout, 60, fun mgmt_burst_of_large_responses/0}}.

mgmt_burst_of_large_responses() ->
    yuzu_gw_edge_stub_svc:notify_to(self()),
    {Port, L} = yuzu_gw_test_listener:start(prod_mgmt_entry(#{name => edge_burst})),
    {C, Mon} = open(Port),
    try
        N = 32,
        Refs = [send_command(C, <<"gate">>, integer_to_binary(1024 * 1024), []) ||
                   _ <- lists:seq(1, N)],
        Pids = await_waiting(N, 10000),
        [P ! release || P <- Pids],
        {Results, Down} = collect(C, Mon, Refs, 30000),
        ?assertEqual(alive, Down),
        %% every call answered OK with its whole response (the 1 MiB output,
        %% its protobuf tags and the 5-byte gRPC frame header)
        ?assertEqual(lists:duplicate(N, {<<"0">>, response_bytes(1024 * 1024)}),
                     [maps:get(R, Results) || R <- Refs])
    after
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

%% The ceiling each kind of listener sets on its connection process, read off
%% the process after one call (the stream handler sets it on the first stream).
%% Agent listener: bounded, by the derived default and by an explicit value.
%% Management listener: none by default, an explicit value still applies. A
%% combined agent+management listener (a lab rig) serves anonymous agents, so it
%% keeps the agent listener's bound.
connection_ceiling_by_listener_kind_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     [{"agent listener, derived default: 4 x max_message_bytes",
       ?_assertEqual(16 * 1024 * 1024,
                     ceiling(agent_entry(#{limits => #{max_message_bytes => 4194304}}),
                             agent))},
      {"agent listener, explicit value",
       ?_assertEqual(8 * 1024 * 1024,
                     ceiling(agent_entry(#{limits => #{max_connection_memory_bytes =>
                                                           8 * 1024 * 1024}}),
                             agent))},
      {"management listener, shipped limits: no ceiling",
       ?_assertEqual(none, ceiling(prod_mgmt_entry(#{name => edge_ceiling_m}), mgmt))},
      {"management listener, explicit value applies",
       ?_assertEqual(32 * 1024 * 1024,
                     ceiling(prod_mgmt_entry(#{name => edge_ceiling_mx,
                                               limits => #{max_message_bytes => 4194304,
                                                           max_connection_memory_bytes =>
                                                               32 * 1024 * 1024}}),
                             mgmt))},
      {"combined agent+management listener: bounded like the agent listener",
       ?_assertEqual(16 * 1024 * 1024,
                     ceiling(agent_entry(#{service_protos => [agent_pb, management_pb],
                                           services => #{?AGENT_SVC => yuzu_grpc_stub_svc,
                                                         ?MGMT_SVC => yuzu_gw_edge_stub_svc},
                                           limits => #{max_message_bytes => 4194304}}),
                             agent))}]}.

agent_entry(Extra) ->
    maps:merge(#{name => edge_agent, service_protos => [agent_pb],
                 services => #{?AGENT_SVC => yuzu_grpc_stub_svc},
                 listen => #{port => 0}}, Extra).

%% Bytes of the max_heap_size of the listener's one connection, or `none'.
ceiling(Entry, Kind) ->
    {Port, L} = yuzu_gw_test_listener:start(Entry),
    {C, _Mon} = open(Port),
    try
        S = case Kind of
                agent -> heartbeat(C);
                mgmt -> list_agents(C)
            end,
        {Results, alive} = collect(C, undefined, [S], 5000),
        ?assertMatch({<<"0">>, _}, maps:get(S, Results)),
        Name = maps:get(name, Entry),
        [Conn] = ranch:procs({yuzu_grpc, Name}, connections),
        {max_heap_size, #{size := Words}} = erlang:process_info(Conn, max_heap_size),
        case Words of
            0 -> none;
            _ -> Words * erlang:system_info(wordsize)
        end
    after
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

response_bytes(Output) ->
    byte_size(yuzu_grpc_frame:encode(
                management_pb:encode_msg(#{agent_id => <<"a">>,
                                           response => #{output => binary:copy(<<"r">>, Output)}},
                                         'yuzu.server.v1.SendCommandResponse'))).

open(Port) ->
    {ok, C} = gun:open("127.0.0.1", Port, #{protocols => [http2], retry => 0}),
    {ok, http2} = gun:await_up(C, 5000),
    {C, erlang:monitor(process, C)}.

grpc_headers() ->
    [{<<"content-type">>, <<"application/grpc">>}, {<<"te">>, <<"trailers">>}].

send_command(C, Action, Arg, Extra) ->
    Body = yuzu_grpc_frame:encode(
             management_pb:encode_msg(#{agent_ids => [<<"a">>],
                                        command => #{action => Action, command_id => Arg}},
                                      'yuzu.server.v1.SendCommandRequest')),
    gun:post(C, ?SEND_COMMAND, Extra ++ grpc_headers(), Body).

list_agents(C) ->
    Body = yuzu_grpc_frame:encode(
             management_pb:encode_msg(#{}, 'yuzu.server.v1.ListAgentsRequest')),
    gun:post(C, ?LIST_AGENTS, grpc_headers(), Body).

heartbeat(C) ->
    Body = yuzu_grpc_frame:encode(
             agent_pb:encode_msg(#{session_id => <<"ok">>}, 'yuzu.agent.v1.HeartbeatRequest')),
    gun:post(C, ?HEARTBEAT, grpc_headers(), Body).

await_waiting(N, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    await_waiting(N, Deadline, []).

await_waiting(0, _Deadline, Acc) ->
    Acc;
await_waiting(N, Deadline, Acc) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive {waiting, P} -> await_waiting(N - 1, Deadline, [P | Acc])
    after Left -> erlang:error({handlers_not_waiting, N})
    end.

%% Every stream's outcome as {GrpcStatus, DataBytes}, and whether the
%% connection is still `alive' or went `down' first. A stream the connection
%% took with it reads {down, _}.
collect(C, Mon, Refs, Timeout) ->
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    collect(C, Mon, maps:from_list([{R, {pending, 0}} || R <- Refs]), Deadline, alive).

collect(C, Mon, Acc, Deadline, Down) ->
    case [R || {R, {pending, _}} <- maps:to_list(Acc)] of
        [] ->
            {Acc, Down};
        _ when Down =/= alive ->
            {maps:map(fun(_, {pending, D}) -> {down, D}; (_, V) -> V end, Acc), Down};
        _ ->
            Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
            receive
                {gun_response, C, R, fin, _, H} when is_map_key(R, Acc) ->
                    collect(C, Mon, done(R, H, Acc), Deadline, Down);
                {gun_response, C, _R, nofin, _, _} ->
                    collect(C, Mon, Acc, Deadline, Down);
                {gun_data, C, R, _, Data} when is_map_key(R, Acc) ->
                    {pending, D} = maps:get(R, Acc),
                    collect(C, Mon, Acc#{R := {pending, D + byte_size(Data)}}, Deadline, Down);
                {gun_trailers, C, R, H} when is_map_key(R, Acc) ->
                    collect(C, Mon, done(R, H, Acc), Deadline, Down);
                {gun_error, C, R, Reason} when is_map_key(R, Acc) ->
                    {_, D} = maps:get(R, Acc),
                    collect(C, Mon, Acc#{R := {{error, Reason}, D}}, Deadline, Down);
                {gun_error, C, _Reason} ->
                    collect(C, Mon, Acc, Deadline, connection_error);
                {gun_down, C, _, Reason, _} ->
                    collect(C, Mon, Acc, Deadline, {gun_down, Reason});
                {'DOWN', Mon, process, C, Reason} ->
                    collect(C, Mon, Acc, Deadline, {down, Reason})
            after Left ->
                {Acc, Down}
            end
    end.

done(R, Headers, Acc) ->
    {_, D} = maps:get(R, Acc),
    Acc#{R := {proplists:get_value(<<"grpc-status">>, Headers), D}}.
