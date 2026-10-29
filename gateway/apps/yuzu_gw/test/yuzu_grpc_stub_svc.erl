%%%-------------------------------------------------------------------
%%% @doc A stub AgentService for the wire tests of the yuzu_grpc layer
%%% (yuzu_grpc_wire_tests). Each RPC does what the request asks, so a test
%%% picks the handler behaviour it needs from the client side:
%%%
%%%   Heartbeat (unary)         HeartbeatRequest.session_id is the command
%%%   ExecuteCommand (server    CommandRequest.action is the command,
%%%     stream)                   command_id its argument
%%%   Subscribe (bidi)          every CommandResponse is echoed back as a
%%%                             CommandRequest with the same command_id; a few
%%%                             command_ids are commands themselves
%%%
%%% The same stub answers two ManagementService methods in the same spirit
%%% (list_agents: unary, send_command: server stream) for the wire tests of a
%%% listener that carries an auth_fun and so may not serve the AgentService.
%%%
%%% It counts invocations in an ETS table so a test can assert that a handler
%%% ran exactly as many times as it should (never, for a refused call), and
%%% records the pids of handlers that block, to assert they are dead after a
%%% deadline. CheckForUpdate and DownloadUpdate are deliberately not exported:
%%% they are UNIMPLEMENTED.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_stub_svc).

-export([heartbeat/2, execute_command/2, subscribe/2]).
%% ManagementService shapes, for the listeners that carry an auth_fun
-export([list_agents/2, send_command/2]).
-export([init_state/0, reset/0, notify/1, calls/0, sleepers/0, result/1]).

-define(TAB, yuzu_grpc_stub_state).
%% The reason of a crash the log must never show.
-define(NOBODY, yuzu_grpc_stub_nobody).

%%--------------------------------------------------------------------
%% Test API
%%--------------------------------------------------------------------

-spec init_state() -> ok.
init_state() ->
    _ = (catch ets:delete(?TAB)),
    ets:new(?TAB, [named_table, public, set]),
    reset().

%% @doc Forget the counters and the sleepers (not the notify pid).
-spec reset() -> ok.
reset() ->
    Keep = ets:lookup(?TAB, notify),
    ets:delete_all_objects(?TAB),
    ets:insert(?TAB, [{calls, 0} | Keep]),
    ok.

%% @doc Have the stub send `{stub, Event, HandlerPid}' to Pid at the moments a
%% test needs to wait for: `sleeping' (a handler is about to block), `eos' (a
%% Subscribe handler saw the end of its input) and `closed' (an until_closed
%% handler found its stream over). A test waits for the message; it never polls.
-spec notify(pid()) -> ok.
notify(Pid) ->
    ets:insert(?TAB, {notify, Pid}),
    ok.

%% @doc How many times a handler body has started.
-spec calls() -> non_neg_integer().
calls() ->
    [{calls, N}] = ets:lookup(?TAB, calls),
    N.

%% @doc The pids of the handlers that blocked on purpose.
-spec sleepers() -> [pid()].
sleepers() ->
    [Pid || {{sleeper, Pid}} <- ets:tab2list(?TAB)].

-spec result(term()) -> term() | undefined.
result(Key) ->
    case ets:lookup(?TAB, {result, Key}) of
        [{_, V}] -> V;
        [] -> undefined
    end.

%%--------------------------------------------------------------------
%% Unary
%%--------------------------------------------------------------------

heartbeat(Ctx, Request) ->
    bump(),
    heartbeat(maps:get(session_id, Request, <<>>), Ctx, Request).

heartbeat(<<"ok">>, _Ctx, _Request) ->
    {ok, #{acknowledged => true}};
heartbeat(<<"ok3">>, Ctx, _Request) ->
    {ok, #{acknowledged => true}, Ctx};
%% What the handler can see of its call, returned in the response.
heartbeat(<<"ctx">>, Ctx, _Request) ->
    Headers = yuzu_grpc:headers(Ctx),
    {ok, #{acknowledged => true,
           pending_commands => [#{command_id => list_to_binary(pid_to_list(yuzu_grpc:conn_pid(Ctx))),
                                  plugin => maps:get(<<"x-test">>, Headers, <<>>),
                                  action => case yuzu_grpc:peer_cert(Ctx) of
                                                undefined -> <<"no-cert">>;
                                                _ -> <<"cert">>
                                            end}]}};
%% The grpc-timeout header the call arrived with, in `plugin' (<<>> if none).
heartbeat(<<"deadline">>, Ctx, _Request) ->
    {ok, #{acknowledged => true,
           pending_commands => [#{plugin => maps:get(<<"grpc-timeout">>, yuzu_grpc:headers(Ctx),
                                                     <<>>)}]}};
%% Where the call is attributed and what it reached the handler over: the
%% origin address and how it was learned, the TCP peer, and whether a client
%% certificate arrived (in `parameters').
heartbeat(<<"origin">>, Ctx, _Request) ->
    {Origin, Source} = yuzu_grpc:origin(Ctx),
    {PeerIp, _} = yuzu_grpc:peer(Ctx),
    {ok, #{acknowledged => true,
           pending_commands =>
               [#{command_id => yuzu_grpc_origin:format(Origin),
                  plugin => atom_to_binary(Source, utf8),
                  action => yuzu_grpc_origin:format(PeerIp),
                  parameters => #{<<"cert">> => case yuzu_grpc:peer_cert(Ctx) of
                                                    undefined -> <<"no-cert">>;
                                                    _ -> <<"cert">>
                                                end}}]}};
heartbeat(<<"err5">>, _Ctx, _Request) ->
    {grpc_error, {5, <<"nope">>}};
heartbeat(<<"err_bin">>, _Ctx, _Request) ->
    {grpc_error, {<<"7">>, <<"denied">>}};
heartbeat(<<"err_msg">>, _Ctx, _Request) ->
    {grpc_error, {3, <<"100% wrong\r\nline"/utf8>>}};
heartbeat(<<"throw12">>, _Ctx, _Request) ->
    yuzu_grpc_stream:error(12, "thrown");
heartbeat(<<"badreturn">>, _Ctx, _Request) ->
    %% The shape of a mgmt handler defect: a tuple the gRPC layer does not understand.
    {error, #{status => 5, message => <<"not a grpc_error">>}};
%% A gen_server:call to nothing exits with a reason that embeds the request.
heartbeat(<<"crash">>, _Ctx, Request) ->
    gen_server:call(?NOBODY, {register, Request}, 100);
heartbeat(<<"error">>, _Ctx, Request) ->
    erlang:error({badmatch, Request});
heartbeat(<<"sleep">>, _Ctx, _Request) ->
    sleep(),
    {ok, #{acknowledged => true}};
%% A unary response of a known size (4 KiB in one field), for the client's
%% response-size limit.
heartbeat(<<"big">>, _Ctx, _Request) ->
    {ok, #{acknowledged => true,
           pending_commands => [#{plugin => binary:copy(<<"x">>, 4096)}]}};
%% 256 KiB in one field: many HTTP/2 DATA frames (the largest is 16 KiB), for a
%% client that must stop reading a response part way.
heartbeat(<<"huge">>, _Ctx, _Request) ->
    {ok, #{acknowledged => true,
           pending_commands => [#{plugin => binary:copy(<<"x">>, 256 * 1024)}]}};
heartbeat(_Other, _Ctx, _Request) ->
    {grpc_error, {3, <<"unknown command">>}}.

%% ManagementService.ListAgents: ListAgentsRequest.filter is the command.
list_agents(Ctx, Request) ->
    bump(),
    list_agents_for(maps:get(filter, Request, <<>>), Ctx).

list_agents_for(<<"ok">>, _Ctx) ->
    {ok, #{agents => []}};
%% whether a client certificate reached the handler, in the one agent's id
list_agents_for(<<"ctx">>, Ctx) ->
    {ok, #{agents => [#{agent_id => case yuzu_grpc:peer_cert(Ctx) of
                                        undefined -> <<"no-cert">>;
                                        _ -> <<"cert">>
                                    end}]}};
list_agents_for(_Other, _Ctx) ->
    {grpc_error, {3, <<"unknown command">>}}.

%%--------------------------------------------------------------------
%% Server streaming
%%--------------------------------------------------------------------

%% ManagementService.SendCommand: command.action "count" sends command.command_id
%% responses, numbered from 1.
send_command(Request, Stream) ->
    bump(),
    Command = maps:get(command, Request, #{}),
    send_command(maps:get(action, Command, <<>>), maps:get(command_id, Command, <<>>), Stream).

send_command(<<"count">>, N, Stream) ->
    lists:foreach(fun(I) ->
                          ok = yuzu_grpc_stream:send(
                                 Stream, #{agent_id => N, response => #{output => integer_to_binary(I)}})
                  end, lists:seq(1, binary_to_integer(N))),
    ok;
send_command(_Other, _Arg, _Stream) ->
    {grpc_error, {3, <<"unknown command">>}}.

execute_command(Request, Stream) ->
    bump(),
    execute_command(maps:get(action, Request, <<>>), maps:get(command_id, Request, <<>>), Stream).

execute_command(<<"count">>, N, Stream) ->
    lists:foreach(fun(I) ->
                          ok = yuzu_grpc_stream:send(Stream, #{command_id => N, output => integer_to_binary(I)})
                  end, lists:seq(1, binary_to_integer(N))),
    ok;
execute_command(<<"count_err">>, _Arg, Stream) ->
    ok = yuzu_grpc_stream:send(Stream, #{output => <<"1">>}),
    ok = yuzu_grpc_stream:send(Stream, #{output => <<"2">>}),
    {grpc_error, {5, <<"stream-err">>}};
execute_command(<<"empty">>, _Arg, _Stream) ->
    ok;
execute_command(<<"sleep">>, _Arg, _Stream) ->
    sleep(),
    ok;
%% Send until the stream is over; remember how that ended.
execute_command(<<"until_closed">>, _Arg, Stream) ->
    register_sleeper(),
    until_closed(Stream, 0);
execute_command(<<"crash">>, _Arg, Stream) ->
    ok = yuzu_grpc_stream:send(Stream, #{output => <<"before-crash">>}),
    erlang:error(deliberate);
execute_command(<<"badreturn">>, _Arg, _Stream) ->
    {error, #{status => 5}};
execute_command(<<"big">>, Bytes, Stream) ->
    yuzu_grpc_stream:send(Stream, #{output => binary:copy(<<"x">>, binary_to_integer(Bytes))}).

until_closed(Stream, N) ->
    case yuzu_grpc_stream:send(Stream, #{output => integer_to_binary(N)}) of
        ok ->
            timer:sleep(5),
            until_closed(Stream, N + 1);
        {error, closed} ->
            ets:insert(?TAB, {{result, until_closed}, closed}),
            event(closed),
            ok
    end.

%%--------------------------------------------------------------------
%% Bidirectional
%%--------------------------------------------------------------------

subscribe(Ref, Stream) ->
    bump(),
    subscribe_loop(Ref, Stream).

subscribe_loop(Ref, Stream) ->
    receive
        {Ref, eos} ->
            ets:insert(?TAB, {{result, subscribe}, eos}),
            event(eos),
            ok;
        {Ref, #{command_id := <<"conn">>}} ->
            ok = yuzu_grpc_stream:send(
                   Stream, #{command_id => list_to_binary(pid_to_list(yuzu_grpc_stream:conn_pid(Stream)))}),
            subscribe_loop(Ref, Stream);
        {Ref, #{command_id := <<"fail">>}} ->
            {grpc_error, {3, <<"bad message">>}};
        {Ref, #{command_id := <<"sleep">>}} ->
            sleep(),
            ok;
        {Ref, #{command_id := Id}} ->
            ok = yuzu_grpc_stream:send(Stream, #{command_id => Id}),
            subscribe_loop(Ref, Stream)
    end.

%%--------------------------------------------------------------------

bump() ->
    _ = ets:update_counter(?TAB, calls, 1),
    ok.

%% Block until the test says `release' (or the layer kills the process).
sleep() ->
    register_sleeper(),
    receive
        release -> ok
    end.

register_sleeper() ->
    ets:insert(?TAB, {{sleeper, self()}}),
    event(sleeping).

event(Event) ->
    case ets:lookup(?TAB, notify) of
        [{notify, Pid}] -> Pid ! {stub, Event, self()}, ok;
        [] -> ok
    end.
