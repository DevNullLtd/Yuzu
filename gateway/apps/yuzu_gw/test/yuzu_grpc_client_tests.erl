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
%%%     away is reopened, and the deadline ends a call that never answers;
%%%   - a call that ends because its CONNECTION closed is `connection_lost', the
%%%     same connection pid for every call it took with it (`report_conn'), so
%%%     the circuit breaker can count one lost connection once (#5695);
%%%   - a connection the server closes gracefully (GOAWAY) is retired at the
%%%     first call it refuses: the next call runs on a new connection at once,
%%%     not after gun's closing_timeout (#5695).
%%%
%%% Nothing waits for time to pass to make an assertion true: the waits are on
%%% events (a connection coming up, a monitor). The deadline case uses a real
%%% deadline, which is what it tests.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_tests).
-include_lib("eunit/include/eunit.hrl").

-export([init/2]).  %% cowboy handler of the HTTP-error tests

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
         {"the call's timeout is sent upstream as grpc-timeout",
          fun() -> timeout_is_sent_as_grpc_timeout(State) end},
         {"a refused metadata key is {error, invalid_metadata} and sends nothing", fun() -> refused_metadata(State) end},
         {"a request larger than the HTTP/2 window arrives whole", {timeout, 30, fun() -> large_request(State) end}},
         {"concurrent calls all complete on a channel's connections", {timeout, 30, fun() -> concurrent(State) end}},
         {"calls spread over both connections of the pool", fun() -> spread(State) end},
         {"the deadline ends a call that never answers", {timeout, 20, fun() -> deadline(State) end}},
         {"a server that honours grpc-timeout ends the call first, DEADLINE_EXCEEDED",
          {timeout, 20, fun() -> server_deadline(State) end}},
         {"a timed-out call cancels its stream: the handler ends and nothing reaches the caller later",
          {timeout, 20, fun() -> timeout_cancels_the_stream(State) end}},
         {"a response over the limit that spans many frames stops the stream: nothing reaches the caller later",
          {timeout, 20, fun() -> oversize_multi_frame_response_is_abandoned(State) end}},
         {"a response that is not HTTP 200 is {http_error, {StatusBinary, <<>>}, Meta}, whatever its body",
          {timeout, 20, fun() -> http_error() end}},
         {"an unknown channel is {error, no_channel}", fun() -> no_channel() end},
         {"TCP_NODELAY is set on the channel's sockets by default", fun() -> nodelay(State) end},
         {"test client: bidi echo, then close_send ends the call with status 0", fun() -> bidi_echo(State) end},
         {"test client: a stream error status arrives as trailers", fun() -> bidi_error(State) end}]
     end}.

%% A listener and a one-connection channel of their own: these tests close the
%% server side of the channel's connection.
conn_loss_test_() ->
    {foreach,
     fun conn_setup/0,
     fun conn_cleanup/1,
     [fun(State) ->
              {"calls on a connection that closes are connection_lost, one pid for all",
               {timeout, 30, fun() -> lost_connection_is_one_pid(State) end}}
      end,
      fun(State) ->
              {"a connection the server closes gracefully is retired at the first refused call",
               {timeout, 30, fun() -> goaway_retires_the_connection(State) end}}
      end]}.

conn_setup() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_grpc_stub_svc:init_state(),
    Unique = integer_to_list(erlang:unique_integer([positive])),
    Name = list_to_atom("client_conn_loss_" ++ Unique),
    {Port, Listener} = yuzu_gw_test_listener:start(
                         #{name => Name, service_protos => [agent_pb],
                           services => #{?SVC => yuzu_grpc_stub_svc}}),
    Chan = yuzu_gw_test_listener:client_channel(list_to_atom("client_conn_loss_chan_" ++ Unique),
                                                #{port => Port}),
    #{ref => {yuzu_grpc, Name}, listener => Listener, chan => Chan}.

conn_cleanup(#{listener := Listener, chan := Chan}) ->
    [S ! release || S <- yuzu_grpc_stub_svc:sleepers()],
    yuzu_gw_test_listener:stop_channel(Chan),
    yuzu_gw_test_listener:stop(Listener),
    flush_mailbox().

%% Three calls are on the wire (their handlers sleep) when the server's side of
%% the connection is killed: each ends as connection_lost naming the one
%% connection, and a call without report_conn gets the bare word. The channel
%% reopens the slot and the next call is answered.
lost_connection_is_one_pid(#{ref := Ref, chan := Chan}) ->
    %% setup/0 may run in another process: the stub notifies this one.
    yuzu_grpc_stub_svc:notify(self()),
    {ok, Conn} = yuzu_grpc_client_channel:pick(Chan, 1000),
    Self = self(),
    Opts = [#{channel => Chan, report_conn => true}, #{channel => Chan, report_conn => true},
            #{channel => Chan}],
    Callers = [spawn_link(fun() ->
                                  R = yuzu_grpc_client:unary(#{}, ?HEARTBEAT,
                                                             #{session_id => <<"sleep">>},
                                                             def(), O#{timeout => 10000}),
                                  Self ! {caller, self(), R}
                          end) || O <- Opts],
    [receive {stub, sleeping, _} -> ok after 10000 -> error(handler_never_slept) end
     || _ <- Callers],
    [ServerConn] = ranch:procs(Ref, connections),
    exit(ServerConn, kill),
    Results = [receive {caller, C, R} -> R after 10000 -> error({caller_silent, C}) end
               || C <- Callers],
    ?assertEqual([{error, {connection_lost, Conn}}, {error, {connection_lost, Conn}},
                  {error, connection_lost}], Results),
    %% gun tells the channel after it told the calls; once the channel has
    %% redialled, calls are answered again.
    ok = wait_new_connection(Chan, Conn, 400),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)).

%% Wait (bounded) until the channel hands out a connection other than Old.
wait_new_connection(_Chan, Old, 0) ->
    error({still_handing_out, Old});
wait_new_connection(Chan, Old, N) ->
    case yuzu_grpc_client_channel:pick(Chan, 1000) of
        {ok, New} when New =/= Old -> ok;
        _ -> receive after 25 -> ok end, wait_new_connection(Chan, Old, N - 1)
    end.

%% The server closes the connection gracefully while a call sleeps on it:
%% Cowboy sends GOAWAY, and once the second GOAWAY (the real last stream id)
%% is in, gun is `closing' and refuses every new call on that connection until
%% the sleeping stream ends or its closing_timeout (3 s) passes. The first
%% refused call reports the connection to the channel, which retires it and
%% opens a new one: the very next call is answered, while the old connection
%% is still alive finishing the sleeping call.
goaway_retires_the_connection(#{ref := Ref, chan := Chan}) ->
    %% setup/0 may run in another process: the stub notifies this one.
    yuzu_grpc_stub_svc:notify(self()),
    {ok, Conn} = yuzu_grpc_client_channel:pick(Chan, 1000),
    Self = self(),
    Sleeper = spawn_link(fun() ->
                                 R = yuzu_grpc_client:unary(#{}, ?HEARTBEAT,
                                                            #{session_id => <<"sleep">>}, def(),
                                                            #{channel => Chan, timeout => 10000}),
                                 Self ! {sleeper, R}
                         end),
    receive {stub, sleeping, _} -> ok after 10000 -> error(handler_never_slept) end,
    [ServerConn] = ranch:procs(Ref, connections),
    _ = spawn(fun() -> catch sys:terminate(ServerConn, shutdown, 15000) end),
    ok = wait_gun_state(Conn, closing, 400),
    ?assertEqual({error, {connection_lost, Conn}},
                 yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                        #{channel => Chan, report_conn => true})),
    %% The retire is a cast: a call to the channel is handled after it.
    _ = sys:get_state(Chan),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)),
    {ok, Conn2} = yuzu_grpc_client_channel:pick(Chan, 1000),
    ?assertNotEqual(Conn, Conn2),
    ?assert(is_process_alive(Conn)),
    unlink(Sleeper),
    [S ! release || S <- yuzu_grpc_stub_svc:sleepers()].

%% Wait (bounded) until a gun connection's state machine is in StateName.
wait_gun_state(_Conn, StateName, 0) ->
    error({gun_never_reached, StateName});
wait_gun_state(Conn, StateName, N) ->
    case catch sys:get_state(Conn, 1000) of
        {StateName, _} -> ok;
        _ -> receive after 25 -> ok end, wait_gun_state(Conn, StateName, N - 1)
    end.

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

%% The server can stop working on a call nobody waits for only if it knows the
%% deadline: the header carries what is left of the call's timeout, never more.
timeout_is_sent_as_grpc_timeout(#{chan := Chan}) ->
    {ok, #{pending_commands := [#{plugin := Header}]}, _} =
        yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"deadline">>}, def(),
                               #{channel => Chan, timeout => 2500}),
    ?assertMatch({ok, _}, yuzu_grpc_frame:parse_timeout(Header)),
    {ok, Ms} = yuzu_grpc_frame:parse_timeout(Header),
    ?assert(Ms =< 2500),
    ?assert(Ms > 1500).

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

%% The client's own deadline (no grpc-timeout sent: a server that honours it
%% would end the call first, see server_deadline/1).
deadline(#{chan := Chan}) ->
    T0 = erlang:monotonic_time(millisecond),
    ?assertEqual({error, timeout},
                 yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"sleep">>}, def(),
                                        #{channel => Chan, timeout => 300,
                                          send_timeout => false})),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assert(Elapsed >= 300),
    ?assert(Elapsed < 5000),
    %% the channel is still good afterwards
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)).

%% With grpc-timeout sent (the default), the gateway's own listener ends the
%% handler a tenth early (yuzu_grpc_stream_h:deadline_ms/1) and answers status 4,
%% so the client gets the server's answer, not its local timeout.
server_deadline(#{chan := Chan}) ->
    T0 = erlang:monotonic_time(millisecond),
    ?assertMatch({error, {<<"4">>, _}, _},
                 yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"sleep">>}, def(),
                                        #{channel => Chan, timeout => 1000})),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assert(Elapsed < 1000),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)).

%% The call is given up on at 300 ms. The stream is cancelled (RST_STREAM), so the
%% server ends the handler that was sleeping on it, and no message of gun's about
%% the stream reaches the caller afterwards (it would, if the stream were left
%% open and the handler later answered, or if the cancel were not sent).
timeout_cancels_the_stream(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    yuzu_grpc_stub_svc:notify(self()),
    flush_mailbox(),
    Self = self(),
    Caller = spawn_link(fun() ->
                            R = yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"sleep">>},
                                                       def(), #{channel => Chan, timeout => 300,
                                                                send_timeout => false}),
                            Stray = collect_messages(500),
                            Self ! {caller, R, Stray}
                        end),
    {Sleeper, Result, Stray1} =
        receive {stub, sleeping, H} ->
                    receive {caller, R0, S0} -> {H, R0, S0}
                    after 10000 -> error({caller_silent, Caller})
                    end
        after 10000 -> error(handler_never_slept)
        end,
    ?assertEqual({error, timeout}, Result),
    ?assertEqual([], Stray1),
    ?assertEqual(ok, wait_dead(Sleeper)),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)).

%% 256 KiB in many DATA frames against a limit of 1 KiB: the call fails with
%% response_too_large at the first frame, the stream is cancelled, and the frames
%% still in flight are not delivered to the caller afterwards. The connection is
%% the same one, and serves the next call.
oversize_multi_frame_response_is_abandoned(#{port := Port}) ->
    Name = list_to_atom("yuzu_client_tests_small_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{http, "localhost", Port, []}],
                   #{pool_size => 1, max_receive_message_bytes => 1024}}, true),
    {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
    try
        Name = wait_up(Name, 1, 200),
        [Conn] = ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}]),
        flush_mailbox(),
        [begin
             ?assertEqual({error, response_too_large}, heartbeat(Name, <<"huge">>)),
             ?assertEqual([], collect_messages(300))
         end || _ <- lists:seq(1, 3)],
        ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name, <<"ok">>)),
        ?assertEqual([Conn], ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}])),
        ?assert(is_process_alive(Conn))
    after
        stop_channel(Name)
    end.

%% Not a gRPC server at all: a cowboy handler that answers every request with
%% the status the request asks for (x-status), with or without a body (x-body).
%% This is a gateway talking to a proxy or a load balancer in front of the real
%% server, and the answer must be `http_error' (status as a decimal binary, the
%% body not returned), never an `ok' or a gRPC `error' the upstream code would
%% read as the server's. Nothing of the stream reaches the caller afterwards, and
%% the connection serves the next call.
http_error() ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    Ref = list_to_atom("yuzu_client_tests_http_" ++ integer_to_list(erlang:unique_integer([positive]))),
    Dispatch = cowboy_router:compile([{'_', [{"/[...]", ?MODULE, []}]}]),
    {ok, _} = cowboy:start_clear(Ref, [{ip, {127, 0, 0, 1}}, {port, Port}],
                                 #{env => #{dispatch => Dispatch}}),
    Name = list_to_atom("yuzu_client_tests_http_chan_" ++ integer_to_list(erlang:unique_integer([positive]))),
    {ok, Cfg} = yuzu_grpc_client_config:channel({Name, [{http, "127.0.0.1", Port, []}],
                                                 #{pool_size => 1}}, true),
    {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
    try
        Name = wait_up(Name, 1, 200),
        flush_mailbox(),
        Call = fun(Status, Body) ->
                   Meta0 = #{<<"x-status">> => Status},
                   Meta = case Body of
                              none -> Meta0;
                              _    -> Meta0#{<<"x-body">> => Body}
                          end,
                   yuzu_grpc_client:unary(Meta, ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                          #{channel => Name})
               end,
        [begin
             ?assertMatch({http_error, {Status, <<>>}, #{headers := #{<<"content-type">> := <<"text/plain">>},
                                                         trailers := #{}}},
                          Call(Status, Body)),
             %% with or without a body the stream ends on its own (the client reads
             %% the body out instead of cancelling a stream gun is finishing), so
             %% no gun message is left in the caller's mailbox
             ?assertEqual([], collect_messages(150))
         end || Status <- [<<"502">>, <<"503">>, <<"404">>, <<"400">>, <<"500">>],
                Body <- [none, <<"upstream is unavailable">>]],
        %% a body that never ends (a proxy dripping an error page) cannot hold the
        %% caller past its deadline, and leaves nothing in its mailbox
        T0 = erlang:monotonic_time(millisecond),
        ?assertMatch({http_error, {<<"502">>, <<>>}, _},
                     yuzu_grpc_client:unary(#{<<"x-status">> => <<"502">>, <<"x-drip">> => <<"1">>},
                                            ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                            #{channel => Name, timeout => 1000})),
        ?assert(erlang:monotonic_time(millisecond) - T0 < 2500),
        ?assertEqual([], collect_messages(300)),
        %% a 200 that is not gRPC is not an http_error: it has no grpc-status
        ?assertNotMatch({http_error, _, _}, Call(<<"200">>, <<"hello">>))
    after
        stop_channel(Name),
        cowboy:stop_listener(Ref)
    end.

%% cowboy handler: the status and body the request asks for.
init(Req, State) ->
    case cowboy_req:header(<<"x-drip">>, Req, undefined) of
        undefined -> reply(Req, State);
        _ -> drip(Req, State)
    end.

%% A 502 whose body arrives 100 kB every 300 ms for up to 30 s.
drip(Req0, State) ->
    Req = cowboy_req:stream_reply(502, #{<<"content-type">> => <<"text/plain">>}, Req0),
    Chunk = binary:copy(<<"x">>, 100000),
    [begin cowboy_req:stream_body(Chunk, nofin, Req), timer:sleep(300) end || _ <- lists:seq(1, 100)],
    cowboy_req:stream_body(<<>>, fin, Req),
    {ok, Req, State}.

reply(Req, State) ->
    Status = binary_to_integer(cowboy_req:header(<<"x-status">>, Req, <<"502">>)),
    Body = cowboy_req:header(<<"x-body">>, Req, <<>>),
    {ok, cowboy_req:reply(Status, #{<<"content-type">> => <<"text/plain">>}, Body, Req), State}.

flush_mailbox() ->
    receive _ -> flush_mailbox() after 0 -> ok end.

%% Every message that arrives in the next Ms milliseconds.
collect_messages(Ms) ->
    receive M -> [M | collect_messages(Ms)]
    after Ms -> []
    end.

%% Wait (bounded) for a process to be gone.
wait_dead(Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive {'DOWN', Ref, process, Pid, _} -> ok
    after 5000 -> {still_alive, Pid}
    end.

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
