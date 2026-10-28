%%%-------------------------------------------------------------------
%%% @doc Heartbeat admission and session cleanup when a connection dies.
%%%
%%% Companion to yuzu_gw_heartbeat_conn_rpc_tests: the same REAL
%%% yuzu_grpc_listener serving the REAL yuzu_gw_agent_service, driven by REAL
%%% gRPC client channels (yuzu_grpc_client_channel) over plaintext HTTP/2 (the death of a connection is
%%% transport independent). The intent: a connection's death drains its
%%% sessions, and until it has, no other connection is admitted for them.
%%%
%%% How a connection dies here, with nothing in the gateway replaced or
%%% injected and nothing of the HTTP/2 library touched:
%%%   - the test kills the connection process (`exit(Pid, kill)'). The pid is the
%%%     connection key the registry reports for the session, so the same pid the
%%%     admission rule compares is the one that dies; its socket closes with it;
%%%   - the client abandons its connection (stopping the channel closes the
%%%     socket) while the server's connection process is held with
%%%     sys:suspend/1, which models a slow server-side teardown.
%%% The chain under test is: connection ends, the Subscribe handler ends, the
%%% session's agent process (which monitors the handler) cleans up and
%%% deregisters, and the binding row goes. Every wait is on a monitor or a
%%% message; the registry's cast is flushed with a synchronous call.
%%%
%%% What follows for admission, asserted below:
%%%   - the binding row is removed when the connection's Subscribe stream ends;
%%%     a late heartbeat for that session is rejected as unknown session;
%%%   - a heartbeat that reaches the gateway on a NEW connection while the old
%%%     Subscribe is still bound is rejected as connection mismatch, never
%%%     admitted;
%%%   - one dead connection drains every session on it and no session of
%%%     another connection;
%%%   - the agent's recovery (re-Register, Subscribe on the new connection)
%%%     binds a fresh session to the new connection and ends the rejections.
%%%
%%% The last case reads the wire: a protocol error from a raw client is answered
%%% with a GOAWAY and the connection is closed.
%%%
%%% Not covered here, needs the real C++ agent (gRPC core): whether it keeps
%%% the old transport for the open Subscribe stream after GOAWAY and opens a new
%%% connection for the Heartbeat.
%%%
%%% Listeners and channels come from yuzu_gw_test_listener (OS-assigned ports;
%%% shared CI boxes run several jobs).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_conn_drain_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(REGISTER_PATH,  <<"/yuzu.agent.v1.AgentService/Register">>).
-define(HEARTBEAT_PATH, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(SUBSCRIBE_PATH, <<"/yuzu.agent.v1.AgentService/Subscribe">>).

-define(GOAWAY, 7).
-define(PROTOCOL_ERROR, 1).
%% HTTP/2 preface, an empty SETTINGS frame, then a PING (length 8) on stream 1,
%% which a server must answer with a PROTOCOL_ERROR GOAWAY.
-define(PREFACE, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>).
-define(EMPTY_SETTINGS, <<0:24, 4:8, 0:8, 0:1, 0:31>>).
-define(PING_ON_STREAM_1, <<8:24, 6:8, 0:8, 0:1, 1:31, 0:64>>).

-export([handle_telemetry/4]).

drain_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        %% Each case gets its own 60 s; the outer bound covers all of them,
        %% since a group timeout is shared by the cases inside it.
        {timeout, 420,
         [{timeout, 60, T} || T <- [
          {"a dead connection ends the Subscribe stream and the binding; a late heartbeat is unknown session",
           fun() -> connection_death_ends_binding(State) end},
          {"a dead connection drains every session on it and none of another connection",
           fun() -> death_drains_all_its_sessions(State) end},
          {"after the connection died the agent reconnects: a fresh session binds to the new connection",
           fun() -> reconnect_binds_new_connection(State) end},
          {"pending session whose connection died: rejected until Subscribe binds the new connection",
           fun() -> pending_session_after_death(State) end},
          {"heartbeat on a new connection while the old Subscribe is still bound is rejected",
           fun() -> new_connection_during_drain_window(State) end},
          {"repeated connection mismatch does not end the Subscribe; re-Register recovers",
           fun() -> mismatch_streak_then_reregister(State) end},
          {"a protocol error on the wire is answered with a GOAWAY and the connection closes",
           fun() -> goaway_then_close_on_wire(State) end}]]}
     end}.

%%%-------------------------------------------------------------------
%%% Cases
%%%-------------------------------------------------------------------

connection_death_ends_binding(State) ->
    with_channels(State, fun(A, B, Counts, Dial) ->
        Id = agent_id(<<"death">>),
        {S, Holder} = register_and_subscribe(A, Id),
        try
            ?assertMatch({ok, _, _}, heartbeat(A, S)),
            {ok, #{conn_key := K, pid := AgentPid}} = yuzu_gw_registry:lookup_session(S),
            ok = kill_connection(K, [AgentPid]),
            ?assertEqual(error, yuzu_gw_registry:lookup_session(S)),
            ?assertEqual(error, yuzu_gw_registry:lookup(Id)),
            %% The client side of the Subscribe stream ended too: the holder
            %% reports the end of the stream, and that end is not its own
            %% recv_trailers timeout (which it reports as a stream end as well).
            {holder_msg, Holder, {stream_end, End}} = await_holder_msg(Holder),
            ?assertNotEqual(timeout, End),
            %% A late heartbeat for the ended session, on another connection or
            %% on a new one, is unknown session, not mismatch.
            A2 = Dial(),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A2, S)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
            ?assertEqual(0, count(Counts, connection_mismatch)),
            ?assertEqual(2, count(Counts, unknown_session)),
            %% Only the heartbeat admitted before the death reached the buffer.
            ?assertEqual(1, queued_for(S))
        after
            stop_holder(Holder)
        end
    end).

death_drains_all_its_sessions(State) ->
    with_channels(State, fun(A, B, Counts, _Dial) ->
        {S1, H1} = register_and_subscribe(A, agent_id(<<"drain-1">>)),
        {S2, H2} = register_and_subscribe(A, agent_id(<<"drain-2">>)),
        {S3, H3} = register_and_subscribe(B, agent_id(<<"drain-3">>)),
        try
            {ok, #{conn_key := K, pid := P1}} = yuzu_gw_registry:lookup_session(S1),
            {ok, #{conn_key := K, pid := P2}} = yuzu_gw_registry:lookup_session(S2),
            {ok, #{conn_key := KB, pid := P3}} = yuzu_gw_registry:lookup_session(S3),
            ?assertNotEqual(K, KB),
            ok = kill_connection(K, [P1, P2]),
            ?assertEqual(error, yuzu_gw_registry:lookup_session(S1)),
            ?assertEqual(error, yuzu_gw_registry:lookup_session(S2)),
            %% The other connection's session is untouched and still admitted.
            ?assertMatch({ok, #{pid := P3, conn_key := KB}}, yuzu_gw_registry:lookup_session(S3)),
            ?assert(is_process_alive(P3)),
            ?assertMatch({ok, _, _}, heartbeat(B, S3)),
            ?assertEqual(0, count(Counts, connection_mismatch))
        after
            [stop_holder(H) || H <- [H1, H2]],
            end_session(H3, S3)
        end
    end).

reconnect_binds_new_connection(State) ->
    with_channels(State, fun(A, B, Counts, Dial) ->
        Id = agent_id(<<"reconnect">>),
        {S1, Holder1} = register_and_subscribe(A, Id),
        {ok, #{conn_key := K1, pid := P1}} = yuzu_gw_registry:lookup_session(S1),
        ok = kill_connection(K1, [P1]),
        ?assertEqual(error, yuzu_gw_registry:lookup_session(S1)),
        stop_holder(Holder1),
        %% The agent dials again: Register and Subscribe on a new connection.
        A2 = Dial(),
        {S2, Holder2} = register_and_subscribe(A2, Id),
        try
            {ok, #{conn_key := K2}} = yuzu_gw_registry:lookup_session(S2),
            ?assertNotEqual(K1, K2),
            ?assert(is_process_alive(K2)),
            ?assertMatch({ok, _, _}, heartbeat(A2, S2)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S2)),
            ?assertEqual(1, count(Counts, connection_mismatch)),
            %% The old session id stays dead on both connections.
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A2, S1)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S1)),
            ?assertEqual(2, count(Counts, unknown_session))
        after
            end_session(Holder2, S2)
        end
    end).

pending_session_after_death(State) ->
    with_channels(State, fun(A, B, Counts, Dial) ->
        S = register_session(A, agent_id(<<"pending">>)),
        {ok, K1} = yuzu_gw_registry:lookup_pending_session(S),
        ?assertMatch({ok, _, _}, heartbeat(A, S)),
        ok = kill_connection(K1, []),
        %% The pending row is not tied to the connection process: it stays,
        %% still naming the connection that registered, which is gone.
        ?assertEqual({ok, K1}, yuzu_gw_registry:lookup_pending_session(S)),
        %% So no connection is admitted for it until Subscribe binds it.
        A2 = Dial(),
        ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A2, S)),
        ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
        ?assertEqual(2, count(Counts, connection_mismatch)),
        %% Subscribe on the new connection binds the session to it, and only
        %% that connection is admitted.
        Holder = subscribe(A2, S),
        try
            ok = await_bound(S),
            {ok, #{conn_key := K2}} = yuzu_gw_registry:lookup_session(S),
            ?assertNotEqual(K1, K2),
            ?assertMatch({ok, _, _}, heartbeat(A2, S)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
            ?assertEqual(3, count(Counts, connection_mismatch))
        after
            end_session(Holder, S)
        end
    end).

%% The interesting case. The old connection process is held (suspended) after
%% the client has dropped the connection, so its Subscribe stream is still bound
%% while the client has already moved to a new connection.
new_connection_during_drain_window(State) ->
    with_channels(State, fun(A, B, Counts, Dial) ->
        Id = agent_id(<<"window">>),
        {S, Holder} = register_and_subscribe(A, Id),
        try
            {ok, #{conn_key := K1, pid := AgentPid}} = yuzu_gw_registry:lookup_session(S),
            Mon = monitor(process, K1),
            AgentMon = monitor(process, AgentPid),
            ok = sys:suspend(K1),
            A2 = try
                %% The client abandons its connection and dials a new one.
                ok = yuzu_gw_test_listener:stop_channel(A),
                NewChan = Dial(),
                %% The gateway still holds the session, bound to the old key,
                %% because the connection process has not run since.
                ?assertMatch({ok, #{conn_key := K1}}, yuzu_gw_registry:lookup_session(S)),
                ?assert(is_process_alive(K1)),
                %% The new connection's next heartbeat is rejected, with the
                %% answer the agent already handles (NOT_FOUND), and nothing is
                %% queued for the session.
                ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(NewChan, S)),
                ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
                ?assertEqual(2, count(Counts, connection_mismatch)),
                ?assertEqual(0, count(Counts, unknown_session)),
                ?assertEqual(0, queued_for(S)),
                NewChan
            after
                ok = sys:resume(K1)
            end,
            %% Once the old connection process runs it sees its socket closed and
            %% ends; the binding is then removed, and the same heartbeat is now
            %% unknown session.
            ok = await_drained(Mon, K1, AgentMon, AgentPid),
            ?assertEqual(error, yuzu_gw_registry:lookup_session(S)),
            ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A2, S)),
            ?assertEqual(2, count(Counts, connection_mismatch)),
            ?assertEqual(1, count(Counts, unknown_session)),
            %% Recovery: Register again and Subscribe on the new connection.
            stop_holder(Holder),
            {S2, Holder2} = register_and_subscribe(A2, Id),
            try
                ?assertMatch({ok, _, _}, heartbeat(A2, S2)),
                ?assertEqual(2, count(Counts, connection_mismatch)),
                ?assertEqual(1, count(Counts, unknown_session))
            after
                end_session(Holder2, S2)
            end
        after
            stop_holder(Holder)
        end
    end).

%% The agent-side recovery path, modelled with the test gRPC client (the real agent
%% is gRPC core): heartbeats arrive on a connection other than the Subscribe's,
%% are answered NOT_FOUND, and the agent then cancels the Subscribe and
%% registers again on the connection it is using.
mismatch_streak_then_reregister(State) ->
    with_channels(State, fun(A, B, Counts, _Dial) ->
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

%% A raw HTTP/2 client provokes a connection error and reads the wire: the
%% GOAWAY frame (PROTOCOL_ERROR) is the last frame, then the server closes.
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

%% Kill the connection process K, and wait for the whole chain behind it: K is
%% down, every agent process in Agents (the sessions bound to K) has cleaned up
%% and ended, and the registry has processed their deregistration.
kill_connection(K, Agents) ->
    Mon = monitor(process, K),
    AgentMons = [{monitor(process, P), P} || P <- Agents],
    exit(K, kill),
    receive {'DOWN', Mon, process, K, killed} -> ok
    after 5000 -> error(connection_not_killed)
    end,
    await_agents_down(AgentMons).

%% After the client dropped a connection whose server process had been
%% suspended and has been resumed: the connection ended, its sessions followed.
await_drained(Mon, K, AgentMon, AgentPid) ->
    receive {'DOWN', Mon, process, K, _} -> ok
    after 5000 -> error(connection_still_alive)
    end,
    await_agents_down([{AgentMon, AgentPid}]).

await_agents_down([]) ->
    registry_flushed();
await_agents_down([{Mon, P} | Rest]) ->
    receive {'DOWN', Mon, process, P, _} -> await_agents_down(Rest)
    after 5000 -> error(session_not_drained)
    end.

%% The agent process casts its deregistration to the registry before it exits;
%% a call to the registry returns after that cast was handled.
registry_flushed() ->
    _ = sys:get_state(yuzu_gw_registry),
    ok.

agent_id(Prefix) ->
    iolist_to_binary([Prefix, "-", integer_to_list(erlang:unique_integer([positive]))]).

register_session(Chan, AgentId) ->
    Req = #{info => #{agent_id => AgentId, hostname => <<"h">>}},
    {ok, #{session_id := S}, _} =
        yuzu_gw_test_client:unary(ctx:new(), ?REGISTER_PATH, Req, register_def(),
                                  #{channel => Chan}),
    S.

%% Open the Subscribe stream from a dedicated process, like a real agent holds
%% it (see yuzu_gw_heartbeat_conn_rpc_tests). The holder is not linked to the
%% test process: its stream ends when the connection does. The test client's
%% stream process is linked to the holder, so it ends with the holder. The
%% holder reads the end of its stream (its status, or the error that ended it)
%% on request and passes it on to the test process.
subscribe(Chan, SessionId) ->
    Owner = self(),
    Holder = spawn(fun() ->
        Ctx = yuzu_gw_test_client:with_metadata(
                ctx:new(), #{<<"x-yuzu-session-id">> => SessionId}),
        {ok, Stream} = yuzu_gw_test_client:stream(Ctx, ?SUBSCRIBE_PATH, subscribe_def(),
                                                  #{channel => Chan}),
        ok = yuzu_gw_test_client:send(Stream, #{command_id => <<"hello">>}),
        Owner ! {subscribed, self()},
        holder_loop(Owner, Stream)
    end),
    receive {subscribed, Holder} -> Holder
    after 5000 -> error(subscribe_timeout)
    end.

holder_loop(Owner, Stream) ->
    receive
        {close, From} ->
            catch yuzu_gw_test_client:close_send(Stream),
            From ! {closed, self()};
        await_end ->
            Owner ! {holder_msg, self(), {stream_end, yuzu_gw_test_client:recv_trailers(Stream, 5000)}},
            holder_loop(Owner, Stream);
        _Other ->
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

%% The holder's report of how its stream ended: its status, or the error that
%% ended it. The content is a client detail and is not asserted.
await_holder_msg(Holder) ->
    Holder ! await_end,
    receive {holder_msg, Holder, _} = Msg -> Msg
    after 5000 -> {error, no_holder_message}
    end.

register_and_subscribe(Chan, AgentId) ->
    S = register_session(Chan, AgentId),
    Holder = subscribe(Chan, S),
    ok = await_bound(S),
    {S, Holder}.

heartbeat(Chan, SessionId) ->
    yuzu_gw_test_client:unary(ctx:new(), ?HEARTBEAT_PATH, #{session_id => SessionId},
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

wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of true -> ok; false -> {error, timeout} end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(10), wait_until(Pred, Timeout - 10)
    end.

register_def() ->
    #{marshal => fun(M) ->
          agent_pb:encode_msg(M, 'yuzu.agent.v1.RegisterRequest') end,
      unmarshal => fun(B) ->
          agent_pb:decode_msg(B, 'yuzu.agent.v1.RegisterResponse') end}.

heartbeat_def() ->
    #{marshal => fun(M) ->
          agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) ->
          agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

subscribe_def() ->
    #{marshal => fun(M) ->
          agent_pb:encode_msg(M, 'yuzu.agent.v1.CommandResponse') end,
      unmarshal => fun(B) ->
          agent_pb:decode_msg(B, 'yuzu.agent.v1.CommandRequest') end}.

%%%-------------------------------------------------------------------
%%% Fixture
%%%-------------------------------------------------------------------

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    %% A pending session must outlive the death of its connection until a
    %% Subscribe on a new connection takes it: a grace far beyond the case, on
    %% a registry started with it (a reused one may hold another value).
    PrevGrace = application:get_env(yuzu_gw, dead_connection_grace_ms),
    application:set_env(yuzu_gw, dead_connection_grace_ms, 60000),
    ok = yuzu_gw_test_registry:ensure_fresh(),
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
                     fun(#{info := #{agent_id := Id}}, _Opts) ->
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
    {Port, Server} = yuzu_gw_test_listener:start(
                       #{name => hb_conn_drain,
                         service_protos => [agent_pb],
                         services => #{?SVC => yuzu_gw_agent_service}}),
    #{port => Port, server => Server, agent_sup => AgentSup,
      counts => Counts, handler_id => HandlerId, prev_grace => PrevGrace}.

cleanup(#{server := Server, agent_sup := AgentSup, handler_id := HandlerId,
          counts := Counts, prev_grace := PrevGrace}) ->
    case PrevGrace of
        {ok, V}   -> application:set_env(yuzu_gw, dead_connection_grace_ms, V);
        undefined -> application:unset_env(yuzu_gw, dead_connection_grace_ms)
    end,
    yuzu_gw_test_listener:stop(Server),
    catch telemetry:detach(HandlerId),
    catch ets:delete(Counts),
    catch meck:unload([yuzu_gw_upstream, yuzu_gw_heartbeat_buffer]),
    yuzu_gw_test_registry:stop_agent_sup(AgentSup).

%% Two fresh client channels (two HTTP/2 connections) per case, with zeroed
%% rejection counters and an empty heartbeat buffer history. The case also gets
%% Dial, which opens one more warm channel (a new connection) without touching
%% the counters; every channel opened is stopped when the case ends.
with_channels(#{port := Port, counts := Counts}, Fun) ->
    Opened = ets:new(yuzu_gw_hb_drain_chans, [public, bag]),
    Dial = fun() ->
        Chan = yuzu_gw_test_listener:client_channel(chan_name(), #{port => Port}),
        true = ets:insert(Opened, {chan, Chan}),
        %% The warm-up heartbeats are rejections too: keep them out of the counts.
        Before = ets:tab2list(Counts),
        ok = warm_chan(Chan),
        true = ets:delete_all_objects(Counts),
        true = ets:insert(Counts, Before),
        Chan
    end,
    try
        A = Dial(),
        B = Dial(),
        true = ets:delete_all_objects(Counts),
        meck:reset(yuzu_gw_heartbeat_buffer),
        Fun(A, B, Counts, Dial)
    after
        [yuzu_gw_test_listener:stop_channel(C) || {chan, C} <- ets:tab2list(Opened)],
        ets:delete(Opened)
    end.

%% Cold-start guard: the channel is up when client_channel/2 returns, but the
%% first call on it can still outlast the call's default 5 s timeout under CPU
%% oversubscription. Retry a harmless unary call (an unknown session is
%% answered with a gRPC status, which proves the connection works) until it
%% gets an answer, so the case bodies only ever see a warm connection.
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
            timer:sleep(250),
            warm_chan(Chan, Left - 1)
    end.

chan_name() ->
    list_to_atom("yuzu_hb_drain_" ++ integer_to_list(erlang:unique_integer([positive]))).

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
