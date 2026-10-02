%%%-------------------------------------------------------------------
%%% @doc Transport-level evidence for connection-bound heartbeat admission.
%%%
%%% Starts a REAL grpcbox listener serving the REAL yuzu_gw_agent_service,
%%% with the real registry and agent supervisor behind it, and drives it with
%%% real grpcbox client channels (one channel = one HTTP/2 connection).
%%% Only the upstream C++ server client and the heartbeat buffer are mocked.
%%% No part of the connection key is injected: it comes from the vendored
%%% grpcbox accessors, for both the bidi Subscribe stream and the unary
%%% Register / Heartbeat calls. Proves, at gRPC-status level:
%%%   - a live Subscribe plus a concurrent Heartbeat on the SAME connection
%%%     is admitted and queued; the same Heartbeat on a different connection
%%%     is answered NOT_FOUND and is not queued;
%%%   - the key a unary Register observes equals the key the Subscribe stream
%%%     observes on that connection;
%%%   - a pending session (Register done, no Subscribe yet) admits only the
%%%     connection that registered;
%%%   - replacement, ending a stream, closing a connection and a registry
%%%     restart end or fence the binding as specified;
%%%   - reannounce and replay reads leave the stored binding byte-identical.
%%%
%%% Listener ports are OS-assigned-then-probed with retry (shared CI boxes
%%% run several jobs; fixed ports collide across jobs). The listener is
%%% plaintext HTTP/2: the connection pid is the same object under TLS, and
%%% TLS adds nothing to what is being tested.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_conn_rpc_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(REGISTER_PATH,  <<"/yuzu.agent.v1.AgentService/Register">>).
-define(HEARTBEAT_PATH, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(SUBSCRIBE_PATH, <<"/yuzu.agent.v1.AgentService/Subscribe">>).
-define(SESSIONS, yuzu_gw_sessions).

rpc_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        [{"live Subscribe + Heartbeat on one connection admitted; on another rejected",
          fun() -> same_connection_admitted(State) end},
         {"pending session admits only the connection that registered",
          fun() -> pending_binding(State) end},
         {"the Register key and the Subscribe key are the same on one connection",
          fun() -> register_and_subscribe_keys_match(State) end},
         {"replacement: the old session stops admitting, the new one binds to its own connection",
          fun() -> replacement_fencing(State) end},
         {"ending the Subscribe stream removes the binding",
          fun() -> stream_end_removes_binding(State) end},
         {"closing the connection removes the binding",
          fun() -> connection_close_removes_binding(State) end},
         {"reannounce and replay reads leave the binding byte-identical",
          fun() -> replay_leaves_binding(State) end},
         {"registry restart: heartbeats fail closed, then a fresh session binds again",
          fun() -> registry_restart(State) end}]
     end}.

%%%-------------------------------------------------------------------
%%% Cases
%%%-------------------------------------------------------------------

same_connection_admitted(#{chan_a := A, chan_b := B}) ->
    meck:reset(yuzu_gw_heartbeat_buffer),
    {S, Stream} = register_and_subscribe(A, agent_id(<<"same-conn">>)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    %% Exactly the two admitted heartbeats reached the buffer.
    ?assertEqual(2, queued()),
    close_stream(Stream),
    ok = await_unbound(S).

pending_binding(#{chan_a := A, chan_b := B}) ->
    meck:reset(yuzu_gw_heartbeat_buffer),
    Id = agent_id(<<"pending">>),
    S = register_session(A, Id),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(S)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
    ?assertEqual(1, queued()),
    %% Admission did not consume the pending row.
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_pending_session(S)),
    true = ets:delete(yuzu_gw_pending, S).

register_and_subscribe_keys_match(#{chan_a := A, chan_b := B}) ->
    Id = agent_id(<<"keys">>),
    S = register_session(A, Id),
    {ok, RegisterKey} = yuzu_gw_registry:lookup_pending_session(S),
    ?assert(is_pid(RegisterKey)),
    Stream = subscribe(A, S),
    ok = await_bound(S),
    {ok, #{conn_key := SubscribeKey}} = yuzu_gw_registry:lookup_session(S),
    ?assertEqual(RegisterKey, SubscribeKey),
    %% A different connection reports a different key.
    S2 = register_session(B, agent_id(<<"keys-b">>)),
    {ok, OtherKey} = yuzu_gw_registry:lookup_pending_session(S2),
    ?assertNotEqual(RegisterKey, OtherKey),
    true = ets:delete(yuzu_gw_pending, S2),
    close_stream(Stream),
    ok = await_unbound(S).

replacement_fencing(#{chan_a := A, chan_b := B}) ->
    Id = agent_id(<<"replace">>),
    {S1, Stream1} = register_and_subscribe(A, Id),
    {ok, #{pid := P1}} = yuzu_gw_registry:lookup_session(S1),
    %% The same agent reconnects on another connection under a new session.
    {S2, Stream2} = register_and_subscribe(B, Id),
    {ok, #{pid := P2}} = yuzu_gw_registry:lookup_session(S2),
    ?assertNotEqual(P1, P2),
    %% The superseded session no longer admits anywhere.
    ?assertMatch({error, {<<"5">>, _}, _}, heartbeat(A, S1)),
    ?assertMatch({error, {<<"5">>, _}, _}, heartbeat(B, S1)),
    %% The new session admits only on its own connection.
    ?assertMatch({ok, _, _}, heartbeat(B, S2)),
    ?assertMatch({error, {<<"5">>, _}, _}, heartbeat(A, S2)),
    %% The old stream finishes after the replacement: its cleanup must leave
    %% the newer registration alone, in both tables.
    close_stream(Stream1),
    ok = wait_until(fun() -> not is_process_alive(P1) end, 3000),
    ?assertEqual({ok, P2}, yuzu_gw_registry:lookup(Id)),
    ?assertMatch({ok, #{pid := P2}}, yuzu_gw_registry:lookup_session(S2)),
    ?assertMatch({ok, _, _}, heartbeat(B, S2)),
    close_stream(Stream2),
    ok = await_unbound(S2).

stream_end_removes_binding(#{chan_a := A}) ->
    {S, Stream} = register_and_subscribe(A, agent_id(<<"stream-end">>)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    close_stream(Stream),
    ok = await_unbound(S),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)).

connection_close_removes_binding(#{port := Port}) ->
    Chan = start_chan(chan_closing, Port),
    {S, _Holder} = register_and_subscribe(Chan, agent_id(<<"conn-close">>)),
    ?assertMatch({ok, _, _}, heartbeat(Chan, S)),
    %% Closing the client channel closes the HTTP/2 connection; the stream
    %% process on the gateway ends with it and the agent process follows.
    ok = grpcbox_channel:stop(Chan),
    ok = await_unbound(S),
    %% A fresh connection that presents the same session id is not admitted.
    Fresh = start_chan(chan_fresh, Port),
    try
        ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(Fresh, S))
    after
        grpcbox_channel:stop(Fresh)
    end.

replay_leaves_binding(#{chan_a := A, chan_b := B}) ->
    {S, Stream} = register_and_subscribe(A, agent_id(<<"replay">>)),
    {ok, #{agent_id := Id, pid := Pid}} = yuzu_gw_registry:lookup_session(S),
    Before = ets:lookup(?SESSIONS, S),
    ?assertMatch([{S, Id, Pid, _Key}], Before),
    %% What the upstream registration replay reads and does.
    _ = yuzu_gw_registry:all_register_reqs(),
    _ = yuzu_gw_registry:lookup_local_session(Id),
    ok = yuzu_gw_agent:reannounce(Pid, S),
    {ok, _} = yuzu_gw_agent:get_info(Pid),
    ?assertEqual(Before, ets:lookup(?SESSIONS, S)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    ?assertMatch({error, {<<"5">>, _}, _}, heartbeat(B, S)),
    close_stream(Stream),
    ok = await_unbound(S).

registry_restart(#{chan_a := A}) ->
    {S, Stream} = register_and_subscribe(A, agent_id(<<"restart">>)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    %% Registry-only restart: its tables are recreated empty while the
    %% agent process and the connection survive.
    ok = gen_server:stop(whereis(yuzu_gw_registry)),
    ok = wait_until(fun() -> ets:info(?SESSIONS, size) =:= undefined end, 2000),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)),
    ok = yuzu_gw_test_registry:ensure_fresh(),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)),
    %% A new Register + Subscribe on the same connection binds again.
    {S2, Stream2} = register_and_subscribe(A, agent_id(<<"restart-again">>)),
    ?assertMatch({ok, _, _}, heartbeat(A, S2)),
    close_stream(Stream),
    close_stream(Stream2),
    ok = await_unbound(S2).

%%%-------------------------------------------------------------------
%%% Client helpers
%%%-------------------------------------------------------------------

agent_id(Prefix) ->
    iolist_to_binary([Prefix, "-", integer_to_list(erlang:unique_integer([positive]))]).

register_session(Chan, AgentId) ->
    Req = #{info => #{agent_id => AgentId, hostname => <<"h">>}},
    {ok, #{session_id := S}, _} =
        grpcbox_client:unary(ctx:new(), ?REGISTER_PATH, Req, register_def(),
                             #{channel => Chan}),
    S.

%% Open the Subscribe stream from a dedicated process, like a real agent
%% holds it. A grpcbox client delivers a stream's messages to the process that
%% opened it, tagged with the HTTP/2 stream id only, and stream ids repeat
%% across connections: opening the stream in the test process would let its
%% messages be picked up by a unary call on another channel.
subscribe(Chan, SessionId) ->
    Owner = self(),
    Holder = spawn_link(fun() ->
        Ctx = grpcbox_metadata:append_to_outgoing_ctx(
                ctx:new(), #{<<"x-yuzu-session-id">> => SessionId}),
        {ok, Stream} = grpcbox_client:stream(Ctx, ?SUBSCRIBE_PATH, subscribe_def(),
                                             #{channel => Chan}),
        %% Open the stream on the wire; the gateway ignores agent frames that
        %% carry no command id.
        ok = grpcbox_client:send(Stream, #{command_id => <<"hello">>}),
        Owner ! {subscribed, self()},
        receive
            {close, From} ->
                catch grpcbox_client:close_send(Stream),
                From ! {closed, self()}
        end
    end),
    receive {subscribed, Holder} -> Holder
    after 5000 -> error(subscribe_timeout)
    end.

%% Register and open a Subscribe stream on Chan; returns once the gateway has
%% bound the session.
register_and_subscribe(Chan, AgentId) ->
    S = register_session(Chan, AgentId),
    Stream = subscribe(Chan, S),
    ok = await_bound(S),
    {S, Stream}.

heartbeat(Chan, SessionId) ->
    grpcbox_client:unary(ctx:new(), ?HEARTBEAT_PATH, #{session_id => SessionId},
                         heartbeat_def(), #{channel => Chan}).

%% End the client side of a Subscribe stream (the stream's owner process).
close_stream(Holder) ->
    Holder ! {close, self()},
    receive {closed, Holder} -> ok
    after 5000 -> error(close_timeout)
    end.

queued() ->
    meck:num_calls(yuzu_gw_heartbeat_buffer, queue_heartbeat, '_').

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
                         {ok, #{session_id => <<"rpc-session-", Id/binary, "-", N/binary>>}}
                     end),
    ok = meck:new(yuzu_gw_heartbeat_buffer, [passthrough, no_link]),
    ok = meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(_) -> ok end),
    {Port, Server} = start_listener(5),
    #{port => Port,
      server => Server,
      agent_sup => AgentSup,
      chan_a => start_chan(chan_a, Port),
      chan_b => start_chan(chan_b, Port)}.

cleanup(#{server := Server, agent_sup := AgentSup} = State) ->
    [catch grpcbox_channel:stop(maps:get(C, State)) || C <- [chan_a, chan_b]],
    catch supervisor:terminate_child(grpcbox_services_simple_sup, Server),
    catch meck:unload([yuzu_gw_upstream, yuzu_gw_heartbeat_buffer]),
    case AgentSup of
        undefined -> ok;
        _ -> catch exit(AgentSup, shutdown)
    end,
    ok.

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
start_chan(Name, Port) ->
    {ok, _} = grpcbox_channel_sup:start_child(
                Name, [{http, "localhost", Port, []}], #{sync_start => true}),
    Name.
