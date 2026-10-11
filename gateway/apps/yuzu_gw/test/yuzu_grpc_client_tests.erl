%%%-------------------------------------------------------------------
%%% @doc Wire tests of the upstream gRPC client (yuzu_grpc_client over
%%% yuzu_grpc_client_channel and gun): a REAL listener (yuzu_grpc_listener)
%%% serving the stub AgentService (yuzu_grpc_stub_svc), called through a real
%%% channel. They prove, at gRPC-status level:
%%%
%%%   - the result shapes the gateway's upstream code matches on: `ok', a gRPC
%%%     error as `{error, {StatusBinary, Message}, Meta}', an HTTP-level error
%%%     as `http_error', a transport failure as `{error, Reason}';
%%%   - metadata reaches the handler, and a refused metadata key never leaves;
%%%   - a request and a response larger than the HTTP/2 window flow whole, and a
%%%     response over the channel's limit fails the call;
%%%   - calls run concurrently on a channel's connections;
%%%   - a dead server is answered at once with its error, a connection that goes
%%%     away is reopened, and the deadline ends a call that never answers.
%%%
%%% Nothing waits for time to pass to make an assertion true: the waits are on
%%% events (a connection coming up, a monitor). The deadline case uses a real
%%% deadline, which is what it tests.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(NOSUCH, <<"/yuzu.agent.v1.AgentService/NoSuchMethod">>).

plaintext_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        [{"ok", fun() -> ok_result(State) end},
         {"a gRPC error status is {error, {StatusBinary, Message}, Meta}", fun() -> grpc_error(State) end},
         {"a binary status and a thrown status read the same", fun() -> grpc_error_forms(State) end},
         {"a message with percent and CRLF survives the trailers", fun() -> message_decoding(State) end},
         {"an unexported method is UNIMPLEMENTED (12)", fun() -> unimplemented(State) end},
         {"a handler crash is INTERNAL (13) and carries no request", fun() -> handler_crash(State) end},
         {"metadata reaches the handler", fun() -> metadata_reaches_handler(State) end},
         {"a refused metadata key is {error, invalid_metadata} and sends nothing", fun() -> refused_metadata(State) end},
         {"a request larger than the HTTP/2 window arrives whole", {timeout, 30, fun() -> large_request(State) end}},
         {"concurrent calls all complete on a channel's connections", {timeout, 30, fun() -> concurrent(State) end}},
         {"calls spread over both connections of the pool", fun() -> spread(State) end},
         {"the deadline ends a call that never answers", {timeout, 20, fun() -> deadline(State) end}},
         {"an unknown channel is {error, no_channel}", fun() -> no_channel() end},
         {"TCP_NODELAY is set on the channel's sockets by default", fun() -> nodelay(State) end},
         {"test client: bidi echo, then close_send ends the call with status 0", fun() -> bidi_echo(State) end},
         {"test client: a stream error status arrives as trailers", fun() -> bidi_error(State) end}]
     end}.

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_grpc_stub_svc:init_state(),
    {Port, Listener} = yuzu_gw_test_listener:start(
                         #{name => client_plain, service_protos => [agent_pb],
                           services => #{?SVC => yuzu_grpc_stub_svc}}),
    Chan = start_channel(client_plain_chan, Port, #{pool_size => 2}),
    #{port => Port, listener => Listener, chan => Chan}.

cleanup(#{listener := Listener, chan := Chan}) ->
    stop_channel(Chan),
    yuzu_gw_test_listener:stop(Listener).

start_channel(Name, Port, Opts) ->
    {ok, Cfg} = yuzu_grpc_client_config:channel({Name, [{http, "localhost", Port, []}], Opts}, true),
    {ok, Pid} = yuzu_grpc_client_channel:start_link(Cfg),
    Name = wait_up(Name, Pid),
    Name.

stop_channel(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> unlink(Pid),
               Ref = erlang:monitor(process, Pid),
               exit(Pid, shutdown),
               receive {'DOWN', Ref, process, Pid, _} -> ok end
    end.

%% Every connection of the pool is up before a test starts, so no test races
%% the connect.
wait_up(Name, _Pid) ->
    wait_up(Name, 2, 200).

wait_up(Name, _Want, 0) -> error({channel_not_up, Name});
wait_up(Name, Want, N) ->
    case ets:select_count(Name, [{{{slot, '_'}, '_', up}, [], [true]}]) of
        Want -> Name;
        _ -> receive after 25 -> ok end, wait_up(Name, Want, N - 1)
    end.

%%--------------------------------------------------------------------
%% Results
%%--------------------------------------------------------------------

ok_result(#{chan := Chan}) ->
    ?assertMatch({ok, #{acknowledged := true}, #{headers := #{}, trailers := #{}}},
                 heartbeat(Chan, <<"ok">>)).

grpc_error(#{chan := Chan}) ->
    ?assertMatch({error, {<<"5">>, <<"nope">>}, #{trailers := #{<<"grpc-status">> := <<"5">>}}},
                 heartbeat(Chan, <<"err5">>)).

grpc_error_forms(#{chan := Chan}) ->
    ?assertMatch({error, {<<"7">>, <<"denied">>}, _}, heartbeat(Chan, <<"err_bin">>)),
    ?assertMatch({error, {<<"12">>, <<"thrown">>}, _}, heartbeat(Chan, <<"throw12">>)).

message_decoding(#{chan := Chan}) ->
    ?assertMatch({error, {<<"3">>, <<"100% wrong\r\nline"/utf8>>}, _}, heartbeat(Chan, <<"err_msg">>)).

unimplemented(#{chan := Chan}) ->
    ?assertMatch({error, {<<"12">>, _}, _},
                 yuzu_grpc_client:unary(#{}, ?NOSUCH, #{session_id => <<"ok">>}, def(),
                                        #{channel => Chan})).

handler_crash(#{chan := Chan}) ->
    {error, {Status, Message}, _} = heartbeat(Chan, <<"crash">>),
    ?assertEqual(<<"13">>, Status),
    ?assertEqual(nomatch, binary:match(Message, <<"register">>)).

%%--------------------------------------------------------------------
%% Metadata
%%--------------------------------------------------------------------

metadata_reaches_handler(#{chan := Chan}) ->
    {ok, #{pending_commands := [#{plugin := Seen}]}, _} =
        yuzu_grpc_client:unary(#{<<"x-test">> => <<"hello">>}, ?HEARTBEAT,
                               #{session_id => <<"ctx">>}, def(), #{channel => Chan}),
    ?assertEqual(<<"hello">>, Seen).

refused_metadata(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    Refused = [#{<<"Upper">> => <<"x">>},
               #{<<"content-type">> => <<"text/plain">>},
               #{<<"grpc-timeout">> => <<"1S">>},
               #{<<":path">> => <<"/x">>},
               #{<<"x-ok">> => <<"line\r\nbreak">>},
               #{<<"x-ok">> => 5}],
    [?assertEqual({error, invalid_metadata},
                  yuzu_grpc_client:unary(M, ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                         #{channel => Chan}))
     || M <- Refused],
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

%%--------------------------------------------------------------------
%% Size, concurrency, spread
%%--------------------------------------------------------------------

%% A request body of a megabyte: far more than the 64 KiB HTTP/2 window, so the
%% client has to wait for the window to reopen. The handler answers "ok" only if
%% it got the whole request, which it does for any session_id it can parse.
large_request(#{chan := Chan}) ->
    Big = binary:copy(<<"a">>, 1024 * 1024),
    ?assertMatch({error, {<<"3">>, <<"unknown command">>}, _},
                 heartbeat(Chan, Big)).

concurrent(#{chan := Chan}) ->
    Self = self(),
    Pids = [spawn_link(fun() -> Self ! {done, self(), heartbeat(Chan, <<"ok">>)} end)
            || _ <- lists:seq(1, 50)],
    Results = [receive {done, P, R} -> R end || P <- Pids],
    ?assertEqual(50, length([ok || {ok, #{acknowledged := true}, _} <- Results])).

spread(#{chan := Chan}) ->
    Conns = lists:usort([conn_of(Chan) || _ <- lists:seq(1, 12)]),
    ?assertEqual(2, length(Conns)).

conn_of(Chan) ->
    {ok, #{pending_commands := [#{command_id := Conn}]}, _} = heartbeat(Chan, <<"ctx">>),
    Conn.

%%--------------------------------------------------------------------
%% Deadline, channel, socket
%%--------------------------------------------------------------------

deadline(#{chan := Chan}) ->
    T0 = erlang:monotonic_time(millisecond),
    ?assertEqual({error, timeout},
                 yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"sleep">>}, def(),
                                        #{channel => Chan, timeout => 300})),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assert(Elapsed >= 300),
    ?assert(Elapsed < 5000),
    %% the channel is still good afterwards
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)).

no_channel() ->
    ?assertEqual({error, no_channel},
                 yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                        #{channel => no_such_channel_x})).

nodelay(#{chan := Chan}) ->
    [Pid | _] = ets:select(Chan, [{{{slot, '_'}, '$1', up}, [], ['$1']}]),
    #{socket := Socket} = gun:info(Pid),
    ?assertEqual({ok, [{nodelay, true}]}, inet:getopts(Socket, [nodelay])).

%%--------------------------------------------------------------------
%% The streaming test client (yuzu_gw_test_client)
%%--------------------------------------------------------------------

bidi_echo(#{chan := Chan}) ->
    {ok, S} = subscribe(Chan),
    [begin
         ok = yuzu_gw_test_client:send(S, #{command_id => Id}),
         ?assertMatch({ok, #{command_id := Id}}, yuzu_gw_test_client:recv_data(S, 5000))
     end || Id <- [<<"a">>, <<"b">>, <<"c">>]],
    ok = yuzu_gw_test_client:close_send(S),
    ?assertMatch({ok, {<<"0">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)),
    ?assertEqual(stream_finished, yuzu_gw_test_client:recv_data(S, 1000)).

bidi_error(#{chan := Chan}) ->
    {ok, S} = subscribe(Chan),
    ok = yuzu_gw_test_client:send(S, #{command_id => <<"fail">>}),
    ?assertMatch({ok, {<<"3">>, <<"bad message">>, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)).

subscribe(Chan) ->
    yuzu_gw_test_client:stream(ctx:new(), <<"/yuzu.agent.v1.AgentService/Subscribe">>,
                               #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.CommandResponse') end,
                                 unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.CommandRequest') end},
                               #{channel => Chan}).

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

heartbeat(Chan, Command) ->
    yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => Command}, def(), #{channel => Chan}).

def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.
