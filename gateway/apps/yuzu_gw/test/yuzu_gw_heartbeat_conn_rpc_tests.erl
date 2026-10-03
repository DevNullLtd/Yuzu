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
%%% run several jobs; fixed ports collide across jobs).
%%%
%%% The whole case list runs over three listener transports, each with its
%%% own listener and client channels:
%%%   - plaintext HTTP/2 (the original evidence);
%%%   - one-way TLS: the shipped agent-listener posture of
%%%     gateway/config/sys.config.prod (`ssl => true', `verify => verify_none',
%%%     `fail_if_no_peer_cert => false'), clients verify the gateway and
%%%     present no certificate;
%%%   - mutual TLS: the same listener with the grpcbox strict defaults, and
%%%     both client channels presenting the SAME client certificate, so the
%%%     only thing that differs between them is the connection.
%%% Over TLS the connection key is still the pid of the HTTP/2 connection
%%% process, and the cases below observe that rather than assume it. Throwaway
%%% certificates are minted with the openssl CLI (the helper in
%%% yuzu_gw_authz_tests) under $TMPDIR. When openssl is unavailable the TLS
%%% legs contribute no tests and announce the skip on the console, unless the
%%% environment variable YUZU_REQUIRE_TLS_TESTS is `1', in which case each
%%% unavailable leg is one failing test. A CI leg that is expected to carry
%%% openssl should set it.
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
-define(MISMATCH_TAB, yuzu_gw_hb_conn_rpc_mismatch).
-define(MISMATCH_HANDLER, yuzu_gw_heartbeat_conn_rpc_mismatch).

-export([handle_mismatch/4]).

rpc_test_() ->
    {setup,
     fun certs/0,
     fun uncerts/1,
     fun(Certs) ->
        [transport_fixture(plain, Certs),
         transport_fixture(oneway, Certs),
         transport_fixture(mtls, Certs)]
     end}.

%% One fixture per transport: its own listener and channels, torn down before
%% the next one starts. The TLS legs need the minted certificates.
transport_fixture(plain, _Certs) ->
    {setup, fun() -> setup(plain, undefined) end, fun cleanup/1, fun cases/1};
transport_fixture(Mode, {error, Why}) ->
    yuzu_gw_authz_tests:certs_unavailable(
        lists:flatten(io_lib:format("yuzu_gw_heartbeat_conn_rpc_tests ~p transport", [Mode])),
        Why);
transport_fixture(Mode, Certs) ->
    {setup, fun() -> setup(Mode, Certs) end, fun cleanup/1,
     fun(State) -> cases(State) ++ tls_cases(State) end}.

cases(State) ->
    Mode = maps:get(mode, State),
    [{timeout, 60, {name(Mode, Title), Fun}} || {Title, Fun} <- [
        {"live Subscribe + Heartbeat on one connection admitted; on another rejected",
          fun() -> same_connection_admitted(State) end},
         {"pending session admits only the connection that registered",
          fun() -> pending_binding(State) end},
         {"the Register key and the Subscribe key are the same on one connection",
          fun() -> register_and_subscribe_keys_match(State) end},
         {"replacement: the old session stops admitting, the new one binds to its own connection",
          fun() -> replacement_fencing(State) end},
         {"Register on one connection and Subscribe on another bind the session to the Subscribe connection",
          fun() -> subscribe_connection_is_the_binding(State) end},
         {"ending the Subscribe stream removes the binding",
          fun() -> stream_end_removes_binding(State) end},
         {"closing the connection removes the binding",
          fun() -> connection_close_removes_binding(State) end},
         {"reannounce and replay reads leave the binding byte-identical",
          fun() -> replay_leaves_binding(State) end},
         {"registry restart: heartbeats fail closed, then a fresh session binds again",
          fun() -> registry_restart(State) end}]].

name(Mode, Title) ->
    lists:flatten(io_lib:format("[~p] ~s", [Mode, Title])).

%% Cases that only make sense on a TLS listener.
tls_cases(#{mode := Mode} = State) ->
    Common = [{name(Mode, "the listener completes a verified TLS handshake and serves gRPC"),
               fun() -> tls_handshake_observed(State) end}],
    Strict = [{name(Mode, "a client with no certificate is refused"),
               fun() -> certless_refused(State) end}
              || Mode =:= mtls],
    [{timeout, 60, T} || T <- Common ++ Strict].

%%%-------------------------------------------------------------------
%%% Cases
%%%-------------------------------------------------------------------

same_connection_admitted(#{chan_a := A, chan_b := B}) ->
    meck:reset(yuzu_gw_heartbeat_buffer),
    ok = reset_mismatches(),
    {S, Stream} = register_and_subscribe(A, agent_id(<<"same-conn">>)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    ?assertEqual(0, mismatches()),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(B, S)),
    %% The connection mismatch was counted once.
    ?assertEqual(1, mismatches()),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    %% Exactly the two admitted heartbeats reached the buffer.
    ?assertEqual(2, queued()),
    ?assertEqual(1, mismatches()),
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
    %% The routing table itself, not lookup/1, which falls back to the pg
    %% group and would hide a deleted routing row.
    ?assertEqual({ok, {P2, S2}}, yuzu_gw_registry:lookup_local_session(Id)),
    ?assertMatch({ok, #{pid := P2}}, yuzu_gw_registry:lookup_session(S2)),
    ?assertMatch({ok, _, _}, heartbeat(B, S2)),
    close_stream(Stream2),
    ok = await_unbound(S2).

%% The session is bound to the connection carrying the Subscribe stream, not
%% to the connection that performed the Register: heartbeats follow the
%% stream. (Admitting the Subscribe itself from the pending Register record is
%% unchanged.)
subscribe_connection_is_the_binding(#{chan_a := A, chan_b := B}) ->
    meck:reset(yuzu_gw_heartbeat_buffer),
    S = register_session(A, agent_id(<<"split">>)),
    {ok, KeyA} = yuzu_gw_registry:lookup_pending_session(S),
    Stream = subscribe(B, S),
    ok = await_bound(S),
    {ok, #{conn_key := Bound}} = yuzu_gw_registry:lookup_session(S),
    %% B's key, as a Register on B records it.
    SB = register_session(B, agent_id(<<"split-b">>)),
    {ok, KeyB} = yuzu_gw_registry:lookup_pending_session(SB),
    true = ets:delete(yuzu_gw_pending, SB),
    ?assertNotEqual(KeyA, KeyB),
    ?assertEqual(KeyB, Bound),
    ?assertMatch({ok, _, _}, heartbeat(B, S)),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)),
    ?assertEqual(1, queued()),
    close_stream(Stream),
    ok = await_unbound(S).

stream_end_removes_binding(#{chan_a := A}) ->
    {S, Stream} = register_and_subscribe(A, agent_id(<<"stream-end">>)),
    ?assertMatch({ok, _, _}, heartbeat(A, S)),
    close_stream(Stream),
    ok = await_unbound(S),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(A, S)).

connection_close_removes_binding(#{mode := Mode, endpoint := Endpoint}) ->
    Chan = start_chan(chan_name(Mode, closing), Endpoint),
    {S, _Holder} = register_and_subscribe(Chan, agent_id(<<"conn-close">>)),
    ?assertMatch({ok, _, _}, heartbeat(Chan, S)),
    %% Closing the client channel closes the HTTP/2 connection; the stream
    %% process on the gateway ends with it and the agent process follows.
    ok = grpcbox_channel:stop(Chan),
    ok = await_unbound(S),
    %% A fresh connection that presents the same session id is not admitted.
    Fresh = start_chan(chan_name(Mode, fresh), Endpoint),
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
%%% TLS-only cases
%%%-------------------------------------------------------------------

%% A raw client handshake against the listener: the server certificate is
%% verified against the minted CA (verify_peer, so a non-TLS or wrongly signed
%% listener fails here), the negotiated version is the listener's TLS 1.2, and
%% HTTP/2 is negotiated for a client that offers it the way the grpcbox client
%% does (both ALPN and NPN).
tls_handshake_observed(#{port := Port, client_ssl := ClientSsl}) ->
    {ok, Sock} = ssl:connect("localhost", Port,
                             ClientSsl ++ [{mode, binary}, {active, false},
                                           {alpn_advertised_protocols, [<<"h2">>]},
                                           {client_preferred_next_protocols,
                                            {client, [<<"h2">>]}}],
                             5000),
    try
        {ok, Info} = ssl:connection_information(Sock, [protocol]),
        ?assertEqual([{protocol, 'tlsv1.2'}], Info),
        ?assertEqual({ok, <<"h2">>}, ssl:negotiated_protocol(Sock)),
        ?assertMatch({ok, _}, ssl:peercert(Sock))
    after
        ssl:close(Sock)
    end.

%% The strict (mutual TLS) listener refuses a client that presents no
%% certificate, so the mutual TLS cases above prove something: both of their
%% channels hold the same certificate and only the connection differs.
certless_refused(#{port := Port, certs := #{ca := Ca}}) ->
    Res = ssl:connect("localhost", Port,
                      [{cacertfile, Ca}, {verify, verify_peer},
                       {versions, ['tlsv1.2']}, {mode, binary}, {active, false},
                       {server_name_indication, "localhost"}], 5000),
    Refused = case Res of
        {error, _} -> true;
        {ok, Sock} ->
            %% A stack may finish the handshake and then end the session; a
            %% failed first read is equally a refusal.
            R = ssl:recv(Sock, 0, 2000),
            catch ssl:close(Sock),
            element(1, R) =:= error
    end,
    ?assert(Refused).

%%%-------------------------------------------------------------------
%%% Fixture
%%%-------------------------------------------------------------------

%% Throwaway certificates (openssl CLI) in a 0700 directory under $TMPDIR.
certs() ->
    Base = case os:getenv("TMPDIR") of
        false -> "/tmp";
        ""    -> "/tmp";
        Dir   -> Dir
    end,
    yuzu_gw_authz_tests:setup_certs(Base).

uncerts(Certs) ->
    yuzu_gw_authz_tests:cleanup_certs(Certs).

setup(Mode, Certs) ->
    {ok, _} = application:ensure_all_started(grpcbox),
    {ok, _} = application:ensure_all_started(telemetry),
    {ok, _} = application:ensure_all_started(ssl),
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
    %% The mismatch counter is observed through its telemetry event, recorded in
    %% a public table: eunit runs this setup and the test bodies in different
    %% processes.
    catch ets:delete(?MISMATCH_TAB),
    ?MISMATCH_TAB = ets:new(?MISMATCH_TAB, [named_table, public, set]),
    catch telemetry:detach(?MISMATCH_HANDLER),
    ok = telemetry:attach(?MISMATCH_HANDLER,
                          [yuzu, gw, heartbeat, session_mismatch],
                          fun ?MODULE:handle_mismatch/4, none),
    {ListenerOpts, ClientSsl} = transport(Mode, Certs),
    {Port, Server} = start_listener(ListenerOpts, 5),
    Endpoint = case Mode of
        plain -> {http, "localhost", Port, []};
        _     -> {https, "localhost", Port, ClientSsl}
    end,
    #{mode => Mode,
      certs => Certs,
      client_ssl => ClientSsl,
      port => Port,
      endpoint => Endpoint,
      server => Server,
      agent_sup => AgentSup,
      chan_a => warmed(start_chan(chan_name(Mode, a), Endpoint)),
      chan_b => warmed(start_chan(chan_name(Mode, b), Endpoint))}.

cleanup(#{server := Server, agent_sup := AgentSup} = State) ->
    [catch grpcbox_channel:stop(maps:get(C, State)) || C <- [chan_a, chan_b]],
    catch supervisor:terminate_child(grpcbox_services_simple_sup, Server),
    catch telemetry:detach(?MISMATCH_HANDLER),
    catch ets:delete(?MISMATCH_TAB),
    catch meck:unload([yuzu_gw_upstream, yuzu_gw_heartbeat_buffer]),
    yuzu_gw_test_registry:stop_agent_sup(AgentSup).

%% {Listener transport_opts, client channel ssl options} for a transport.
%% The one-way listener options mirror the agent listener in
%% gateway/config/sys.config.prod; the mutual TLS listener omits the two
%% relaxing keys so grpcbox applies its strict defaults (verify_peer plus
%% fail_if_no_peer_cert). Neither listener has an auth_fun.
transport(plain, _Certs) ->
    {#{}, []};
transport(Mode, #{dir := Dir, ca := Ca, gw_pem := GwPem, agent_pem := AgentPem}) ->
    GwKey = filename:join(Dir, "gw.key"),
    AgentKey = filename:join(Dir, "agent.key"),
    Listener = #{ssl => true, certfile => GwPem, keyfile => GwKey,
                 cacertfile => Ca},
    Client = [{cacertfile, Ca}, {verify, verify_peer},
              {versions, ['tlsv1.2']},
              {server_name_indication, "localhost"}],
    case Mode of
        oneway ->
            {Listener#{verify => verify_none, fail_if_no_peer_cert => false},
             Client};
        mtls ->
            %% Both channels get this same client certificate.
            {Listener, Client ++ [{certfile, AgentPem}, {keyfile, AgentKey}]}
    end.

warmed(Chan) ->
    ok = warm_chan(Chan),
    Chan.

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

chan_name(Mode, Role) ->
    list_to_atom("yuzu_hb_conn_" ++ atom_to_list(Mode) ++ "_" ++ atom_to_list(Role)).

handle_mismatch(_Event, #{count := N}, _Meta, _Config) ->
    _ = ets:update_counter(?MISMATCH_TAB, count, N, {count, 0}),
    ok.

mismatches() ->
    case ets:lookup(?MISMATCH_TAB, count) of
        [{count, N}] -> N;
        []           -> 0
    end.

reset_mismatches() ->
    true = ets:delete_all_objects(?MISMATCH_TAB),
    ok.

start_listener(_TransportOpts, 0) ->
    error(no_free_port);
start_listener(TransportOpts, Retries) ->
    Port = probe_free_port(),
    GrpcOpts = #{service_protos => [agent_pb],
                 services => #{?SVC => yuzu_gw_agent_service}},
    case grpcbox:start_server(#{grpc_opts => GrpcOpts,
                                listen_opts => #{port => Port, ip => {127, 0, 0, 1}},
                                transport_opts => TransportOpts}) of
        {ok, Pid}  -> {Port, Pid};
        {error, _} -> start_listener(TransportOpts, Retries - 1)
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
