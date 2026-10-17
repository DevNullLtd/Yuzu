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
                 http2 => #{idle_timeout => 600000, max_concurrent_streams => 4096,
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
%%% 2. The deadline hierarchy
%%%-------------------------------------------------------------------

%% 600 SendCommand streams on one connection share one client deadline, 2 s
%% out, and every handler blocks (agents that never answer): the shape of a
%% mass dispatch whose agents are gone, the server's calls all expiring
%% together. The client does what a gRPC client does at its deadline: it resets
%% (RST_STREAM CANCEL) every stream still open. More than 500 resets inside
%% 10 s trip Cowboy's max_cancel_stream_rate, which closes the WHOLE connection
%% (GOAWAY enhance_your_calm). With the gateway's deadline equal to the
%% client's the gateway answers too late and the client cancels; answered a
%% margin early, every stream ends DEADLINE_EXCEEDED before the client's
%% deadline, the client has nothing to cancel, and the connection still serves.
mgmt_deadline_before_caller_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     {timeout, 60, fun mgmt_deadline_before_caller/0}}.

mgmt_deadline_before_caller() ->
    {Port, L} = yuzu_gw_test_listener:start(prod_mgmt_entry(#{name => edge_deadline})),
    {C, Mon} = open(Port),
    try
        N = 600,
        Deadline = erlang:monotonic_time(microsecond) + 2000 * 1000,
        Refs = [send_command(C, <<"sleep">>, <<>>,
                             [{<<"grpc-timeout">>, timeout_header(Deadline)}]) ||
                   _ <- lists:seq(1, N)],
        {Results, Down} = collect(C, Mon, Refs, until(Deadline)),
        %% the client's deadline: cancel what is still open, as gRPC does
        Open = [R || R <- Refs, element(1, maps:get(R, Results)) =:= pending],
        [gun:cancel(C, R) || R <- Open],
        Probe = list_agents(C),
        {ProbeResult, ProbeDown} = collect(C, Mon, [Probe], 5000),
        ?assertEqual({alive, 0}, {Down, length(Open)}),
        ?assertEqual(lists:duplicate(N, {<<"4">>, 0}), [maps:get(R, Results) || R <- Refs]),
        ?assertEqual({alive, {<<"0">>, response_bytes_list()}},
                     {ProbeDown, maps:get(Probe, ProbeResult)})
    after
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

%% The margin: a tenth of the client's timeout, at most one second.
deadline_margin_test_() ->
    [?_assertEqual(299000, yuzu_grpc_stream_h:deadline_ms(300000)),
     ?_assertEqual(9000, yuzu_grpc_stream_h:deadline_ms(10000)),
     ?_assertEqual(1800, yuzu_grpc_stream_h:deadline_ms(2000)),
     ?_assertEqual(90, yuzu_grpc_stream_h:deadline_ms(100)),
     ?_assertEqual(9, yuzu_grpc_stream_h:deadline_ms(9)),
     ?_assertEqual(0, yuzu_grpc_stream_h:deadline_ms(0))].

%%%-------------------------------------------------------------------
%%% 3. Messages for streams that have ended
%%%-------------------------------------------------------------------

%% A message for a stream that has already ended (a handler's frame, a status or
%% a deadline timer that lost the race with a client reset) makes Cowboy write
%% one warning per stream, with the whole message in it: a mass cancel wrote one
%% per stream, and a frame there is a response body. The listener's connections
%% write at most one such line per second, with the message's tag only.
late_stream_messages_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     {timeout, 30, fun late_stream_messages/0}}.

late_stream_messages() ->
    %% the limit is per node: a line another test wrote this second would hide ours
    yuzu_grpc_cowboy_log:reset(),
    {Port, L} = yuzu_gw_test_listener:start(prod_mgmt_entry(#{name => edge_late})),
    {C, Mon} = open(Port),
    try
        S = list_agents(C),
        {_, alive} = collect(C, Mon, [S], 5000),
        [Conn] = ranch:procs({yuzu_grpc, edge_late}, connections),
        Lines = yuzu_gw_test_logs:capture(
                  warning,
                  fun() ->
                          [Conn ! {{Conn, 100001 + 2 * I},
                                   {grpc_frame, self(), make_ref(), <<"secret-output">>}}
                           || I <- lists:seq(1, 200)],
                          %% a call the connection answers after the 200 messages
                          _ = sys:get_state(Conn)
                  end),
        Late = [Line || Line <- Lines, binary:match(Line, <<"stream">>) =/= nomatch],
        ?assertMatch([_], Late),
        ?assertNotEqual(nomatch, binary:match(hd(Late), <<"grpc_frame">>)),
        ?assertEqual([], [Line || Line <- Lines,
                                  binary:match(Line, <<"secret-output">>) =/= nomatch])
    after
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

%% The exit of a handler whose stream had gone: one line per second, the
%% reason's tag only. Every other Cowboy line is written as Cowboy writes it.
cowboy_log_lines_test() ->
    yuzu_grpc_cowboy_log:reset(),
    Lines = yuzu_gw_test_logs:capture(
              warning,
              fun() ->
                      in_fresh_process(
                        fun() ->
                                [yuzu_grpc_cowboy_log:warning(
                                   "Received EXIT signal ~p for unknown process ~p.~n",
                                   [{shutdown, {secret_request, I}}, self()])
                                 || I <- lists:seq(1, 50)],
                                yuzu_grpc_cowboy_log:error("plain ~p line", [error_kept]),
                                yuzu_grpc_cowboy_log:warning("Received stray message ~p.",
                                                             [stray_kept])
                        end)
              end),
    ?assertEqual([], [L || L <- Lines, binary:match(L, <<"secret_request">>) =/= nomatch]),
    %% (error_logger lines are captured as their format and args)
    ?assertMatch([_], [L || L <- Lines, binary:match(L, <<"stream had already ended">>) =/= nomatch,
                            binary:match(L, <<"shutdown">>) =/= nomatch]),
    ?assertMatch([_], [L || L <- Lines, binary:match(L, <<"error_kept">>) =/= nomatch]),
    ?assertMatch([_], [L || L <- Lines, binary:match(L, <<"stray_kept">>) =/= nomatch]).

in_fresh_process(Fun) ->
    {Pid, Mon} = spawn_monitor(Fun),
    receive {'DOWN', Mon, process, Pid, normal} -> ok end.

%%%-------------------------------------------------------------------
%%% 4. The management listener's stream cap
%%%-------------------------------------------------------------------

%% A listener that routes the ManagementService defaults to 4096 concurrent
%% streams (the fan-out of 5,000 agents answering within 10 s completes in about
%% 12 s, against about 31 s at 1024; see http2_opts/1). An agent listener keeps
%% 1024, and an explicit value wins.
mgmt_stream_cap_default_test_() ->
    Streams = fun(E) -> maps:get(max_concurrent_streams, yuzu_grpc_listener:http2_opts(E)) end,
    Bare = #{name => m, service_protos => [management_pb],
             services => #{?MGMT_SVC => yuzu_gw_edge_stub_svc}, listen => #{port => 0}},
    [{"management listener: 4096", ?_assertEqual(4096, Streams(Bare))},
     {"agent listener: 1024",
      ?_assertEqual(1024, Streams(Bare#{service_protos => [agent_pb],
                                        services => #{?AGENT_SVC => yuzu_grpc_stub_svc}}))},
     {"explicit value wins",
      ?_assertEqual(512, Streams(Bare#{http2 => #{max_concurrent_streams => 512}}))}].

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

%% Milliseconds from now until a monotonic deadline in microseconds, and the
%% grpc-timeout that deadline is from now, rounded UP to the millisecond as gRPC
%% does (a client never tells the server less time than it will wait).
until(DeadlineUs) ->
    max(0, (DeadlineUs - erlang:monotonic_time(microsecond)) div 1000).

timeout_header(DeadlineUs) ->
    Left = DeadlineUs - erlang:monotonic_time(microsecond),
    <<(integer_to_binary((Left + 999) div 1000))/binary, "m">>.

response_bytes_list() ->
    byte_size(yuzu_grpc_frame:encode(
                management_pb:encode_msg(#{agents => []}, 'yuzu.server.v1.ListAgentsResponse'))).

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
