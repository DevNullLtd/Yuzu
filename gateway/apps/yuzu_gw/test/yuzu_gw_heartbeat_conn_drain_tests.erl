%%%-------------------------------------------------------------------
%%% @doc Heartbeat admission when an HTTP/2 connection gets GOAWAY.
%%%
%%% Companion to yuzu_gw_heartbeat_conn_rpc_tests: the same REAL grpcbox
%%% listener serving the REAL yuzu_gw_agent_service, driven by REAL grpcbox
%%% client channels over plaintext HTTP/2 (the GOAWAY handling is transport
%%% independent). Characterises what the connection-bound admission rule does
%%% around a GOAWAY, and records what the vendored chatterbox 0.15.1 really
%%% does with one.
%%%
%%% What chatterbox does (h2_connection.erl):
%%%   - every GOAWAY site (listen/handshake timeout, protocol error, settings
%%%     timeout, a received GOAWAY) calls go_away/4 or go_away_/4 and moves the
%%%     connection to the `closing' state. The very next event in `closing'
%%%     closes the socket and stops the process (closing/3). There is no drain:
%%%     streams that were open when GOAWAY was written do not keep running.
%%%   - the client side treats a received GOAWAY the same way (route_frame for
%%%     a stream-0 GOAWAY), so the grpcbox client channel loses the connection
%%%     and its next call opens a NEW connection (a new connection key).
%%%
%%% What follows for admission, asserted below:
%%%   - the binding row is removed when the old Subscribe stream process ends;
%%%     a late heartbeat for that session is rejected as unknown session;
%%%   - a heartbeat that reaches the gateway on a NEW connection while the old
%%%     Subscribe is still bound is rejected as connection mismatch, never
%%%     admitted; chatterbox leaves that window open only for as long as the
%%%     old connection process takes to handle its closing event. The window is
%%%     held open here with sys:suspend/1 on the old connection process, which
%%%     models a slow drain; it is NOT a drain the library performs;
%%%   - the agent's recovery (re-Register, Subscribe on the new connection)
%%%     binds a fresh session to the new connection and ends the rejections.
%%%
%%% The GOAWAY is provoked on the wire by the real client connection process:
%%% it sends a PING frame on stream 1, which the server rejects with a
%%% PROTOCOL_ERROR GOAWAY (h2_connection.erl receive_data, ping on stream /= 0).
%%% Nothing in the gateway is replaced or injected.
%%%
%%% Not covered here, needs the real C++ agent (gRPC core): whether it keeps
%%% the old transport for the open Subscribe stream after GOAWAY and opens a new
%%% connection for the Heartbeat. Against this gateway the old Subscribe ends
%%% as soon as the server connection process handles its closing event.
%%%
%%% Ports are OS-assigned-then-probed with retry (shared CI boxes run several
%%% jobs).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_conn_drain_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(REGISTER_PATH,  <<"/yuzu.agent.v1.AgentService/Register">>).
-define(HEARTBEAT_PATH, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(SUBSCRIBE_PATH, <<"/yuzu.agent.v1.AgentService/Subscribe">>).

-define(GOAWAY, 7).
-define(PROTOCOL_ERROR, 1).
%% HTTP/2 preface, an empty SETTINGS frame, then a PING (length 8) on stream 1.
-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(EMPTY_SETTINGS, <<0:24, 4:8, 0:8, 0:1, 0:31>>).
-define(PING_ON_STREAM_1, <<8:24, 6:8, 0:8, 0:1, 1:31, 0:64>>).

-export([handle_telemetry/4]).

drain_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        %% Each case gets its own 60 s; the outer bound covers all six, since
        %% a group timeout is shared by the cases inside it.
        {timeout, 360,
         [{timeout, 60, T} || T <- [
          {"GOAWAY ends the Subscribe stream and the binding; a late heartbeat is unknown session",
           fun() -> goaway_ends_binding(State) end},
          {"after GOAWAY the agent reconnects: a fresh session binds to the new connection",
           fun() -> reconnect_binds_new_connection(State) end},
          {"pending session whose connection got GOAWAY: rejected until Subscribe binds the new connection",
           fun() -> pending_session_after_goaway(State) end},
          {"heartbeat on a new connection while the old Subscribe is still bound is rejected",
           fun() -> new_connection_during_drain_window(State) end},
          {"repeated connection mismatch does not end the Subscribe; re-Register recovers",
           fun() -> mismatch_streak_then_reregister(State) end},
          {"a GOAWAY on the wire is followed by the connection closing",
           fun() -> goaway_then_close_on_wire(State) end}]]}
     end}.

%%%-------------------------------------------------------------------
%%% Cases
%%%-------------------------------------------------------------------

goaway_ends_binding(State) ->
    with_channels(State, fun(A, B, Counts) ->
        Id = agent_id(<<"goaway">>),
        {S, Holder} = register_and_subscribe(A, Id),
        try
            ?assertMatch({ok, _, _}, heartbeat(A, S)),
            {ok, #{conn_key := K, pid := AgentPid}} = yuzu_gw_registry:lookup_session(S),
            Mon = monitor(process, K),
            Sub = client_goaway(A),
            %% No drain: the server connection process ends, normally, right away.
            ?assertEqual(normal, await_down(Mon)),
            ok = await_channel_lost(Sub),
            ok = await_unbound(S),
            ok = wait_until(fun() -> not is_process_alive(AgentPid) end, 3000),
            ?assertEqual(error, yuzu_gw_registry:lookup(Id)),
            %% The client side of the Subscribe stream ended too.
            ?assertMatch({holder_msg, Holder, _}, await_holder_msg(Holder)),
            %% A late heartbeat for the ended session, on the reconnected
            %% channel or on the other one, is unknown session, not mismatch.
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
            ?assertEqual(0, count(Counts, connection_mismatch)),
            ?assertEqual(2, count(Counts, unknown_session)),
            ?assertEqual(1, queued_for(S))
        after
            stop_holder(Holder)
        end
    end).

reconnect_binds_new_connection(State) ->
    with_channels(State, fun(A, B, Counts) ->
        Id = agent_id(<<"reconnect">>),
        {S1, Holder1} = register_and_subscribe(A, Id),
        {ok, #{conn_key := K1}} = yuzu_gw_registry:lookup_session(S1),
        Mon = monitor(process, K1),
        Sub = client_goaway(A),
        ?assertEqual(normal, await_down(Mon)),
        ok = await_channel_lost(Sub),
        ok = await_unbound(S1),
        stop_holder(Holder1),
        %% The same channel now opens a new connection: Register and Subscribe
        %% again, as the agent does after a broken stream.
        {S2, Holder2} = register_and_subscribe(A, Id),
        try
            {ok, #{conn_key := K2}} = yuzu_gw_registry:lookup_session(S2),
            ?assertNotEqual(K1, K2),
            ?assert(is_process_alive(K2)),
            ?assertMatch({ok, _, _}, heartbeat(A, S2)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S2)),
            ?assertEqual(1, count(Counts, connection_mismatch)),
            %% The old session id stays dead on both connections.
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S1)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S1)),
            ?assertEqual(2, count(Counts, unknown_session))
        after
            end_session(Holder2, S2)
        end
    end).

pending_session_after_goaway(State) ->
    with_channels(State, fun(A, B, Counts) ->
        S = register_session(A, agent_id(<<"pending">>)),
        {ok, K1} = yuzu_gw_registry:lookup_pending_session(S),
        ?assertMatch({ok, _, _}, heartbeat(A, S)),
        Mon = monitor(process, K1),
        Sub = client_goaway(A),
        ?assertEqual(normal, await_down(Mon)),
        ok = await_channel_lost(Sub),
        %% The pending row is not tied to the connection process: it stays,
        %% still naming the connection that registered, which is gone.
        ?assertEqual({ok, K1}, yuzu_gw_registry:lookup_pending_session(S)),
        %% So no connection is admitted for it until Subscribe binds it.
        ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)),
        ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
        ?assertEqual(2, count(Counts, connection_mismatch)),
        %% Subscribe on the reconnected channel binds the session to the NEW
        %% connection, and only that connection is admitted.
        Holder = subscribe(A, S),
        try
            ok = await_bound(S),
            {ok, #{conn_key := K2}} = yuzu_gw_registry:lookup_session(S),
            ?assertNotEqual(K1, K2),
            ?assertMatch({ok, _, _}, heartbeat(A, S)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
            ?assertEqual(3, count(Counts, connection_mismatch))
        after
            end_session(Holder, S)
        end
    end).

%% The interesting case. The old connection process is held (suspended) after
%% the GOAWAY is on the wire, so its Subscribe stream is still bound while the
%% client has already moved to a new connection.
new_connection_during_drain_window(State) ->
    with_channels(State, fun(A, B, Counts) ->
        Id = agent_id(<<"window">>),
        {S, Holder} = register_and_subscribe(A, Id),
        try
            {ok, #{conn_key := K1}} = yuzu_gw_registry:lookup_session(S),
            Mon = monitor(process, K1),
            ok = sys:suspend(K1),
            try
                Sub = client_goaway(A),
                ok = await_channel_lost(Sub),
                %% The client already dropped the old connection: its Subscribe
                %% stream ended on the client side.
                ?assertMatch({holder_msg, Holder, _}, await_holder_msg(Holder)),
                %% The gateway still holds the session, bound to the old key.
                ?assertMatch({ok, #{conn_key := K1}}, yuzu_gw_registry:lookup_session(S)),
                ?assert(is_process_alive(K1)),
                %% The agent's channel opens a new connection for its next
                %% heartbeat. It is rejected, with the answer the agent already
                %% handles (NOT_FOUND), and nothing is queued for the session.
                ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)),
                ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
                ?assertEqual(2, count(Counts, connection_mismatch)),
                ?assertEqual(0, count(Counts, unknown_session)),
                ?assertEqual(0, queued_for(S))
            after
                ok = sys:resume(K1)
            end,
            %% Once the old connection handles its closing event the binding is
            %% removed, and the same heartbeat is now unknown session.
            ?assertEqual(normal, await_down(Mon)),
            ok = await_unbound(S),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)),
            ?assertEqual(2, count(Counts, connection_mismatch)),
            ?assertEqual(1, count(Counts, unknown_session)),
            %% Recovery: Register again and Subscribe on the new connection.
            stop_holder(Holder),
            {S2, Holder2} = register_and_subscribe(A, Id),
            try
                ?assertMatch({ok, _, _}, heartbeat(A, S2)),
                ?assertEqual(2, count(Counts, connection_mismatch)),
                ?assertEqual(1, count(Counts, unknown_session))
            after
                end_session(Holder2, S2)
            end
        after
            stop_holder(Holder)
        end
    end).

%% The agent-side recovery path, modelled with grpcbox clients (the real agent
%% is gRPC core): heartbeats arrive on a connection other than the Subscribe's,
%% are answered NOT_FOUND, and the agent then cancels the Subscribe and
%% registers again on the connection it is using.
mismatch_streak_then_reregister(State) ->
    with_channels(State, fun(A, B, Counts) ->
        Id = agent_id(<<"streak">>),
        {S1, Holder1} = register_and_subscribe(A, Id),
        {ok, #{pid := P1}} = yuzu_gw_registry:lookup_session(S1),
        %% Heartbeats now travel on B while the Subscribe stays on A.
        [?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S1))
         || _ <- lists:seq(1, 3)],
        ?assertEqual(3, count(Counts, connection_mismatch)),
        %% Rejections have no side effect: the session, its agent process and
        %% the Subscribe stream are untouched, and A is still admitted.
        ?assertMatch({ok, #{pid := P1}}, yuzu_gw_registry:lookup_session(S1)),
        ?assert(is_process_alive(P1)),
        ?assertMatch({ok, _, _}, heartbeat(A, S1)),
        %% Recovery: cancel the Subscribe, Register and Subscribe on B.
        stop_holder(Holder1),
        {S2, Holder2} = register_and_subscribe(B, Id),
        try
            ok = await_unbound(S1),
            ?assertMatch({ok, _, _}, heartbeat(B, S2)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S2)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S1)),
            %% Bounded: after recovery the only further rejections are the two
            %% probes just made.
            ?assertEqual(4, count(Counts, connection_mismatch)),
            ?assertEqual(1, count(Counts, unknown_session))
        after
            end_session(Holder2, S2)
        end
    end).

%% A raw HTTP/2 client provokes the same server GOAWAY and reads the wire:
%% the GOAWAY frame (PROTOCOL_ERROR) is the last frame, then the server closes.
goaway_then_close_on_wire(#{port := Port}) ->
    {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, Port,
                                 [binary, {active, false}, {packet, raw}], 5000),
    try
        ok = gen_tcp:send(Sock, [?PREFACE, ?EMPTY_SETTINGS, ?PING_ON_STREAM_1]),
        {Bytes, End} = read_until_closed(Sock, <<>>),
        ?assertEqual(closed, End),
        Frames = parse_frames(Bytes),
        ?assertMatch([_ | _], Frames),
        {Type, 0, Payload} = lists:last(Frames),
        ?assertEqual(?GOAWAY, Type),
        <<_LastStream:32, Code:32, _/binary>> = Payload,
        ?assertEqual(?PROTOCOL_ERROR, Code),
        %% Exactly one GOAWAY, nothing after it.
        ?assertEqual(1, length([x || {?GOAWAY, _, _} <- Frames]))
    after
        gen_tcp:close(Sock)
    end.

%%%-------------------------------------------------------------------
%%% Raw wire helpers
%%%-------------------------------------------------------------------

read_until_closed(Sock, Acc) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data}       -> read_until_closed(Sock, <<Acc/binary, Data/binary>>);
        {error, closed}  -> {Acc, closed};
        {error, Other}   -> {Acc, Other}
    end.

%% [{Type, StreamId, Payload}]
parse_frames(<<Len:24, Type:8, _Flags:8, _R:1, StreamId:31, Payload:Len/binary,
               Rest/binary>>) ->
    [{Type, StreamId, Payload} | parse_frames(Rest)];
parse_frames(<<>>) ->
    [].

%%%-------------------------------------------------------------------
%%% Client helpers
%%%-------------------------------------------------------------------

%% Make the real client connection process of Chan send a PING on stream 1.
%% The server answers with a PROTOCOL_ERROR GOAWAY and closes (see the header).
client_goaway(Chan) ->
    {ok, {Sub, _}} = grpcbox_channel:pick(Chan, unary),
    {ok, Conn, _Info} = grpcbox_subchannel:conn(Sub),
    ClientConn = h2_stream_set:connection(Conn),
    ok = h2_connection:send_frame(ClientConn, ?PING_ON_STREAM_1),
    Sub.

%% Wait until the client channel has dropped its connection (its subchannel is
%% back in `disconnected'), so the next call on it opens a new connection
%% instead of racing the old one's teardown.
await_channel_lost(Sub) ->
    wait_until(fun() -> element(1, sys:get_state(Sub)) =:= disconnected end, 5000).

agent_id(Prefix) ->
    iolist_to_binary([Prefix, "-", integer_to_list(erlang:unique_integer([positive]))]).

register_session(Chan, AgentId) ->
    Req = #{info => #{agent_id => AgentId, hostname => <<"h">>}},
    {ok, #{session_id := S}, _} =
        grpcbox_client:unary(ctx:new(), ?REGISTER_PATH, Req, register_def(),
                             #{channel => Chan}),
    S.

%% Open the Subscribe stream from a dedicated process, like a real agent holds
%% it (see yuzu_gw_heartbeat_conn_rpc_tests). The holder is not linked to the
%% test process: its stream ends when the connection does. Every message the
%% holder receives (the client library reports the end of a stream as a
%% message) is passed on to the test process.
subscribe(Chan, SessionId) ->
    Owner = self(),
    Holder = spawn(fun() ->
        Ctx = grpcbox_metadata:append_to_outgoing_ctx(
                ctx:new(), #{<<"x-yuzu-session-id">> => SessionId}),
        {ok, Stream} = grpcbox_client:stream(Ctx, ?SUBSCRIBE_PATH, subscribe_def(),
                                             #{channel => Chan}),
        ok = grpcbox_client:send(Stream, #{command_id => <<"hello">>}),
        Owner ! {subscribed, self()},
        holder_loop(Owner, Stream)
    end),
    receive {subscribed, Holder} -> Holder
    after 5000 -> error(subscribe_timeout)
    end.

holder_loop(Owner, Stream) ->
    receive
        {close, From} ->
            catch grpcbox_client:close_send(Stream),
            From ! {closed, self()};
        Msg ->
            Owner ! {holder_msg, self(), Msg},
            holder_loop(Owner, Stream)
    end.

%% End a live session: close the Subscribe stream and wait for the gateway to
%% drop the binding, so the client channel is not stopped under an open stream.
end_session(Holder, SessionId) ->
    stop_holder(Holder),
    ok = await_unbound(SessionId).

%% End the holder: ask it to close its stream and wait for it to finish; it is
%% killed only if it does not (it ends by itself on a stream that is already gone).
stop_holder(Holder) ->
    Mon = monitor(process, Holder),
    Holder ! {close, self()},
    receive
        {'DOWN', Mon, process, Holder, _} -> ok
    after 5000 ->
        exit(Holder, kill),
        demonitor(Mon, [flush])
    end,
    receive {closed, Holder} -> ok after 0 -> ok end,
    ok.

%% The first message the holder saw (the client library's end-of-stream
%% report). The text of the message is a client library detail and is not
%% asserted.
await_holder_msg(Holder) ->
    receive {holder_msg, Holder, _} = Msg -> Msg
    after 5000 -> {error, no_holder_message}
    end.

register_and_subscribe(Chan, AgentId) ->
    S = register_session(Chan, AgentId),
    Holder = subscribe(Chan, S),
    ok = await_bound(S),
    {S, Holder}.

heartbeat(Chan, SessionId) ->
    grpcbox_client:unary(ctx:new(), ?HEARTBEAT_PATH, #{session_id => SessionId},
                         heartbeat_def(), #{channel => Chan}).

queued_for(SessionId) ->
    length([x || {_, {_, queue_heartbeat, [#{session_id := S}]}, _} <-
                     meck:history(yuzu_gw_heartbeat_buffer), S =:= SessionId]).

await_bound(S) ->
    wait_until(fun() ->
        case yuzu_gw_registry:lookup_session(S) of
            {ok, _} -> true;
            _       -> false
        end
    end, 3000).

await_unbound(S) ->
    wait_until(fun() -> yuzu_gw_registry:lookup_session(S) =:= error end, 3000).

await_down(Mon) ->
    receive {'DOWN', Mon, process, _, Reason} -> Reason
    after 5000 -> timeout
    end.

wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of true -> ok; false -> {error, timeout} end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(10), wait_until(Pred, Timeout - 10)
    end.

register_def() ->
    #grpcbox_def{service = ?SVC,
                 marshal_fun = fun(M) ->
                     agent_pb:encode_msg(M, 'yuzu.agent.v1.RegisterRequest') end,
                 unmarshal_fun = fun(B) ->
                     agent_pb:decode_msg(B, 'yuzu.agent.v1.RegisterResponse') end}.

heartbeat_def() ->
    #grpcbox_def{service = ?SVC,
                 marshal_fun = fun(M) ->
                     agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
                 unmarshal_fun = fun(B) ->
                     agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

subscribe_def() ->
    #grpcbox_def{service = ?SVC,
                 marshal_fun = fun(M) ->
                     agent_pb:encode_msg(M, 'yuzu.agent.v1.CommandResponse') end,
                 unmarshal_fun = fun(B) ->
                     agent_pb:decode_msg(B, 'yuzu.agent.v1.CommandRequest') end}.

%%%-------------------------------------------------------------------
%%% Fixture
%%%-------------------------------------------------------------------

setup() ->
    {ok, _} = application:ensure_all_started(grpcbox),
    {ok, _} = application:ensure_all_started(telemetry),
    ok = yuzu_gw_test_registry:ensure(),
    AgentSup = case whereis(yuzu_gw_agent_sup) of
        undefined ->
            {ok, P} = yuzu_gw_agent_sup:start_link(),
            unlink(P),
            P;
        _ ->
            undefined
    end,
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(yuzu_gw_heartbeat_buffer),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    ok = meck:expect(yuzu_gw_upstream, proxy_register,
                     fun(#{info := #{agent_id := Id}}) ->
                         N = integer_to_binary(erlang:unique_integer([positive])),
                         {ok, #{session_id => <<"drain-session-", Id/binary, "-", N/binary>>}}
                     end),
    ok = meck:new(yuzu_gw_heartbeat_buffer, [passthrough, no_link]),
    ok = meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(_) -> ok end),
    %% Rejections are counted through their telemetry events into a public
    %% table: eunit runs setup and the test bodies in different processes.
    Counts = ets:new(yuzu_gw_hb_drain_counts, [public, set]),
    HandlerId = {?MODULE, make_ref()},
    ok = telemetry:attach_many(HandlerId,
                               [[yuzu, gw, heartbeat, session_mismatch],
                                [yuzu, gw, heartbeat, rejected]],
                               fun ?MODULE:handle_telemetry/4, Counts),
    {Port, Server} = start_listener(5),
    #{port => Port, server => Server, agent_sup => AgentSup,
      counts => Counts, handler_id => HandlerId}.

cleanup(#{server := Server, agent_sup := AgentSup, handler_id := HandlerId,
          counts := Counts}) ->
    catch supervisor:terminate_child(grpcbox_services_simple_sup, Server),
    catch telemetry:detach(HandlerId),
    catch ets:delete(Counts),
    catch meck:unload([yuzu_gw_upstream, yuzu_gw_heartbeat_buffer]),
    yuzu_gw_test_registry:stop_agent_sup(AgentSup).

%% Two fresh client channels (two HTTP/2 connections) per case, with zeroed
%% rejection counters and an empty heartbeat buffer history.
with_channels(#{port := Port, counts := Counts}, Fun) ->
    Endpoint = {http, "localhost", Port, []},
    A = start_chan(chan_name(a), Endpoint),
    B = start_chan(chan_name(b), Endpoint),
    try
        ok = warm_chan(A),
        ok = warm_chan(B),
        true = ets:delete_all_objects(Counts),
        meck:reset(yuzu_gw_heartbeat_buffer),
        Fun(A, B, Counts)
    after
        catch grpcbox_channel:stop(A),
        catch grpcbox_channel:stop(B)
    end.

%% Cold-start guard: the first call on a fresh channel dials the listener, and
%% under CPU oversubscription grpcbox's internal 5 s call into the subchannel
%% can time out. Retry a harmless unary call (an unknown session is answered
%% with a gRPC status, which proves the connection works) until it gets an
%% answer, so the case bodies only ever see a warm connection.
warm_chan(Chan) ->
    warm_chan(Chan, 5).

warm_chan(Chan, 0) ->
    error({channel_not_ready, Chan});
warm_chan(Chan, Left) ->
    Result = try heartbeat(Chan, <<"warm-up">>)
             catch _:_ -> {error, exception}
             end,
    case Result of
        {ok, _, _}                    -> ok;
        {error, {<<_/binary>>, _}, _} -> ok;
        _ ->
            timer:sleep(1000),
            warm_chan(Chan, Left - 1)
    end.

chan_name(Role) ->
    list_to_atom("yuzu_hb_drain_" ++ atom_to_list(Role) ++ "_"
                 ++ integer_to_list(erlang:unique_integer([positive]))).

handle_telemetry([yuzu, gw, heartbeat, session_mismatch], #{count := N}, _Meta, Tab) ->
    _ = ets:update_counter(Tab, connection_mismatch, N, {connection_mismatch, 0}),
    ok;
handle_telemetry([yuzu, gw, heartbeat, rejected], #{count := N}, #{reason := Reason}, Tab) ->
    _ = ets:update_counter(Tab, Reason, N, {Reason, 0}),
    ok.

count(Tab, Key) ->
    case ets:lookup(Tab, Key) of
        [{Key, N}] -> N;
        []         -> 0
    end.

start_listener(0) ->
    error(no_free_port);
start_listener(Retries) ->
    Port = probe_free_port(),
    GrpcOpts = #{service_protos => [agent_pb],
                 services => #{?SVC => yuzu_gw_agent_service}},
    case grpcbox:start_server(#{grpc_opts => GrpcOpts,
                                listen_opts => #{port => Port, ip => {127, 0, 0, 1}},
                                transport_opts => #{}}) of
        {ok, Pid}  -> {Port, Pid};
        {error, _} -> start_listener(Retries - 1)
    end.

probe_free_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    ok = gen_tcp:close(L),
    Port.

%% sync_start registers the endpoint before start_child returns (see
%% yuzu_gw_authz_rpc_tests:start_chan/5 for the race it closes).
start_chan(Name, Endpoint) ->
    {ok, _} = grpcbox_channel_sup:start_child(Name, [Endpoint], #{sync_start => true}),
    Name.
