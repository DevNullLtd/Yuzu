%%%-------------------------------------------------------------------
%%% @doc AgentService over the wire: the REAL yuzu_gw_agent_service on REAL
%%% agent listeners (yuzu_gw_test_listener), driven by the gun-based client
%%% (yuzu_gw_test_client). Only the process boundaries it calls are replaced
%%% (yuzu_gw_upstream, yuzu_gw_registry, yuzu_gw_heartbeat_buffer), so every
%%% assertion is on what a client receives (a gRPC status) or on what the
%%% service handed those boundaries:
%%%
%%%   - Register overwrites RegisterRequest.gateway_observed_peer with the
%%%     address the gateway decided: the TCP peer on a plain listener, the
%%%     trusted `x-forwarded-for' entry on a forwarded_for listener, the address
%%%     in a PROXY header from a trusted source, never what the agent put in the
%%%     field, never `:authority', never a forged leading header entry. When a
%%%     trusted proxy gave no usable address the field is EMPTY (the server then
%%%     records that the origin was not observed), never the proxy's own address.
%%%     The stored peer_addr is that same text, or "unknown" for an empty one;
%%%   - a refused Register is the intended status: the connection's session cap
%%%     is 14, an unavailable registry or a failed upstream is 13;
%%%   - ExecuteCommand is server-streaming and ends with status 12;
%%%   - Subscribe answers with the intended status, not UNKNOWN: a missing
%%%     x-yuzu-session-id header is 3, an unknown session 5, an unavailable
%%%     registry 13;
%%%   - Heartbeat: an unknown session, or a session held by another connection,
%%%     is 5 and queues nothing.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_service_wire_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(REGISTER, <<"/yuzu.agent.v1.AgentService/Register">>).
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(EXECUTE, <<"/yuzu.agent.v1.AgentService/ExecuteCommand">>).
-define(SUBSCRIBE, <<"/yuzu.agent.v1.AgentService/Subscribe">>).
-define(MOCKS, [yuzu_gw_upstream, yuzu_gw_registry, yuzu_gw_heartbeat_buffer]).
-define(LOOPBACK, <<"127.0.0.1">>).
-define(CLIENT, <<"203.0.113.9">>).
%% What the test agents put in the gateway-authoritative field.
-define(FORGED, <<"198.51.100.200">>).

agent_service_wire_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        [{"Register: the observed peer is the transport address, not the agent's own claim",
          fun() -> register_transport(State) end},
         {"Register: the rest of the request is forwarded as it came",
          fun() -> register_forwards_request(State) end},
         {"Register: a trusted x-forwarded-for entry is the observed peer, a forged leading one is not",
          fun() -> register_forwarded_for(State) end},
         {"Register: a forged field and 120 forged leading x-forwarded-for entries still yield the proxy's entry",
          fun() -> register_forwarded_for_long_header(State) end},
         {"Register: a trusted proxy that sent no usable x-forwarded-for yields an empty observation, not the proxy",
          fun() -> register_forwarded_for_unusable(State) end},
         {"Register: a PROXY header from a trusted source is the observed peer",
          fun() -> register_proxy_protocol(State) end},
         {"Register: a PROXY LOCAL from a trusted source yields an empty observation, not the proxy",
          fun() -> register_proxy_protocol_local(State) end},
         {"Register: a PROXY header from a source that is not trusted keeps the TCP peer",
          fun() -> register_proxy_protocol_untrusted(State) end},
         {"Register: with no origin at all the observation is empty and the stored peer is unknown",
          fun() -> register_without_origin(State) end},
         {"Register: x-forwarded-for from a peer that is not a trusted proxy is ignored",
          fun() -> register_forwarded_for_untrusted(State) end},
         {"Register: a listener with no forwarded_for origin ignores x-forwarded-for",
          fun() -> register_forwarded_for_not_configured(State) end},
         {"Register: the session cap is UNAVAILABLE (14) and nothing is proxied",
          fun() -> register_session_limit(State) end},
         {"Register: an unavailable registry is INTERNAL (13) and nothing is proxied",
          fun() -> register_registry_unavailable(State) end},
         {"Register: a failed upstream is INTERNAL (13) and the reservation is released",
          fun() -> register_upstream_failed(State) end},
         {"ExecuteCommand is server-streaming and ends with UNIMPLEMENTED (12)",
          fun() -> execute_unimplemented(State) end},
         {"Subscribe without x-yuzu-session-id is INVALID_ARGUMENT (3)",
          fun() -> subscribe_no_session(State) end},
         {"Subscribe with an unknown session is NOT_FOUND (5)",
          fun() -> subscribe_unknown_session(State) end},
         {"Subscribe with the registry unavailable is INTERNAL (13)",
          fun() -> subscribe_registry_unavailable(State) end},
         {"Heartbeat on an unknown session is NOT_FOUND (5) and queues nothing",
          fun() -> heartbeat_unknown(State) end},
         {"Heartbeat without a session id is NOT_FOUND (5)",
          fun() -> heartbeat_no_session(State) end},
         {"Heartbeat on the connection that registered the session is acknowledged and queued",
          fun() -> heartbeat_same_connection(State) end},
         {"Heartbeat on another connection than the one that registered the session is NOT_FOUND (5)",
          fun() -> heartbeat_other_connection(State) end}]
     end}.

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    [begin
         catch meck:unload(M),
         ok = meck:new(M, [passthrough, no_link])
     end || M <- ?MOCKS],
    mock_boundaries(),
    Base = #{service_protos => [agent_pb], services => #{?SVC => yuzu_gw_agent_service}},
    Local = [{127, 0, 0, 1}],
    {PlainPort, Plain} = yuzu_gw_test_listener:start(Base#{name => agent_wire_plain}),
    {FwdPort, Fwd} = yuzu_gw_test_listener:start(
                       Base#{name => agent_wire_fwd,
                             origin => #{mode => forwarded_for, sources => Local}}),
    {OtherPort, Other} = yuzu_gw_test_listener:start(
                           Base#{name => agent_wire_fwd_other,
                                 origin => #{mode => forwarded_for, sources => [{10, 0, 0, 5}]}}),
    {PxPort, Px} = yuzu_gw_test_listener:start(
                     Base#{name => agent_wire_proxy,
                           origin => #{mode => proxy_protocol, sources => Local}}),
    {PxUntrustedPort, PxUntrusted} = yuzu_gw_test_listener:start(
                                       Base#{name => agent_wire_proxy_other,
                                             origin => #{mode => proxy_protocol,
                                                         sources => [{10, 0, 0, 5}]}}),
    Header = yuzu_gw_test_relay:proxy_header(2, binary_to_ip(?CLIENT)),
    {PxRelayPort, PxRelay} = yuzu_gw_test_relay:start(PxPort, Header),
    {LocalRelayPort, LocalRelay} = yuzu_gw_test_relay:start(PxPort, yuzu_gw_test_relay:local_header()),
    {UntrustedRelayPort, UntrustedRelay} = yuzu_gw_test_relay:start(PxUntrustedPort, Header),
    Chans = #{plain => yuzu_gw_test_listener:client_channel(agent_wire_plain_chan, #{port => PlainPort}),
              plain2 => yuzu_gw_test_listener:client_channel(agent_wire_plain_chan2, #{port => PlainPort}),
              fwd => yuzu_gw_test_listener:client_channel(agent_wire_fwd_chan, #{port => FwdPort}),
              other => yuzu_gw_test_listener:client_channel(agent_wire_other_chan, #{port => OtherPort}),
              proxy => yuzu_gw_test_listener:client_channel(agent_wire_proxy_chan, #{port => PxRelayPort}),
              proxy_local => yuzu_gw_test_listener:client_channel(agent_wire_proxy_local_chan,
                                                                  #{port => LocalRelayPort}),
              proxy_untrusted => yuzu_gw_test_listener:client_channel(agent_wire_proxy_untrusted_chan,
                                                                      #{port => UntrustedRelayPort})},
    maps:merge(#{listeners => [Plain, Fwd, Other, Px, PxUntrusted],
                 relays => [PxRelay, LocalRelay, UntrustedRelay]}, Chans).

cleanup(#{listeners := Listeners, relays := Relays} = State) ->
    [yuzu_gw_test_listener:stop_channel(maps:get(K, State))
     || K <- [plain, plain2, fwd, other, proxy, proxy_local, proxy_untrusted]],
    [yuzu_gw_test_relay:stop(R) || R <- Relays],
    [yuzu_gw_test_listener:stop(L) || L <- Listeners],
    [meck:unload(M) || M <- ?MOCKS],
    ok.

%% The test agent's id picks the answer of a boundary, so one set of expectations
%% serves every test: `session-limit' and `registry-down' are refused by the
%% registry, `upstream-fails' by the upstream. Any other agent registers and
%% gets the session id `sess-<agent id>'. No session is pending or live unless a
%% test says so (pending_session/2).
mock_boundaries() ->
    meck:expect(yuzu_gw_upstream, proxy_register,
                fun(#{info := #{agent_id := <<"upstream-fails">>}}, _Opts) -> {error, unavailable};
                   (#{info := #{agent_id := Id}}, _Opts) ->
                       {ok, #{session_id => <<"sess-", Id/binary>>, accepted => true}}
                end),
    meck:expect(yuzu_gw_registry, reserve_session,
                fun(_Key, <<"session-limit">>) -> {error, session_limit};
                   (_Key, <<"registry-down">>) -> {error, registry_unavailable};
                   (_Key, _AgentId) -> {ok, make_ref()}
                end),
    meck:expect(yuzu_gw_registry, store_pending, fun(_Session, _Info, _Reservation) -> ok end),
    meck:expect(yuzu_gw_registry, release_session, fun(_Reservation) -> ok end),
    meck:expect(yuzu_gw_registry, take_pending,
                fun(<<"registry-down">>) -> {error, registry_unavailable};
                   (_Session) -> undefined
                end),
    meck:expect(yuzu_gw_registry, lookup_session, fun(_Session) -> error end),
    no_pending_sessions(),
    meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(_Heartbeat) -> ok end).

no_pending_sessions() ->
    meck:expect(yuzu_gw_registry, lookup_pending_session, fun(_Session) -> error end).

%% Session Session is pending on connection Key.
pending_session(Session, Key) ->
    meck:expect(yuzu_gw_registry, lookup_pending_session,
                fun(S) when S =:= Session -> {ok, Key};
                   (_) -> error
                end).

%%--------------------------------------------------------------------
%% Register
%%--------------------------------------------------------------------

register_transport(#{plain := Chan}) ->
    reset(),
    ?assertMatch({ok, #{session_id := <<"sess-agent-t">>}, _},
                 register(Chan, <<"agent-t">>, ?FORGED)),
    ?assertEqual(?LOOPBACK, proxied_peer()),
    {Session, Info, _} = stored(),
    ?assertEqual(<<"sess-agent-t">>, Session),
    ?assertEqual(?LOOPBACK, maps:get(peer_addr, Info)),
    ?assertEqual(?LOOPBACK, maps:get(gateway_observed_peer, maps:get(register_req, Info))).

register_forwards_request(#{plain := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-r">>, ?FORGED),
    Forwarded = meck:capture(last, yuzu_gw_upstream, proxy_register, '_', 1),
    ?assertEqual(<<"agent-r">>, maps:get(agent_id, maps:get(info, Forwarded))),
    ?assertEqual(<<"host-agent-r">>, maps:get(hostname, maps:get(info, Forwarded))),
    ?assertEqual(<<"enroll-secret">>, maps:get(enrollment_token, Forwarded)).

register_forwarded_for(#{fwd := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-f">>, ?FORGED, <<"9.9.9.9, 203.0.113.9">>),
    ?assertEqual(?CLIENT, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(?CLIENT, maps:get(peer_addr, Info)).

register_forwarded_for_long_header(#{fwd := Chan}) ->
    reset(),
    Forged = iolist_to_binary(lists:join(<<", ">>, lists:duplicate(120, <<"9.9.9.9">>) ++ [?CLIENT])),
    {ok, _, _} = register(Chan, <<"agent-l">>, ?FORGED, Forged),
    ?assertEqual(?CLIENT, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(?CLIENT, maps:get(peer_addr, Info)).

register_forwarded_for_unusable(#{fwd := Chan}) ->
    reset(),
    %% the agent's own claim in the field is not kept either
    {ok, _, _} = register(Chan, <<"agent-x">>, ?FORGED, <<"not-an-address">>),
    ?assertEqual(<<>>, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(<<"unknown">>, maps:get(peer_addr, Info)),
    ?assertEqual(<<>>, maps:get(gateway_observed_peer, maps:get(register_req, Info))),
    %% and with no header at all
    reset(),
    {ok, _, _} = register(Chan, <<"agent-y">>, ?FORGED),
    ?assertEqual(<<>>, proxied_peer()).

register_proxy_protocol(#{proxy := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-p">>, ?FORGED),
    ?assertEqual(?CLIENT, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(?CLIENT, maps:get(peer_addr, Info)).

register_proxy_protocol_local(#{proxy_local := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-pl">>, ?FORGED),
    ?assertEqual(<<>>, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(<<"unknown">>, maps:get(peer_addr, Info)).

register_proxy_protocol_untrusted(#{proxy_untrusted := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-pu">>, ?FORGED),
    ?assertEqual(?LOOPBACK, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(?LOOPBACK, maps:get(peer_addr, Info)).

%% No origin in the ctx (no peer address to start from): the gateway has nothing
%% to vouch for. The server reads the empty field as "not observed"; a made-up
%% address would be recorded as if it were one.
register_without_origin(_State) ->
    reset(),
    Ctx = yuzu_grpc:new_ctx(#{}, self(), undefined, undefined, undefined),
    Request = #{info => #{agent_id => <<"agent-o">>, hostname => <<"h">>},
                gateway_observed_peer => ?FORGED},
    ?assertMatch({ok, #{session_id := <<"sess-agent-o">>}, _},
                 yuzu_gw_agent_service:register(Ctx, Request)),
    ?assertEqual(<<>>, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(<<"unknown">>, maps:get(peer_addr, Info)),
    ?assertEqual(<<>>, maps:get(gateway_observed_peer, maps:get(register_req, Info))).

register_forwarded_for_untrusted(#{other := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-u">>, ?FORGED, ?CLIENT),
    ?assertEqual(?LOOPBACK, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(?LOOPBACK, maps:get(peer_addr, Info)).

register_forwarded_for_not_configured(#{plain := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-n">>, ?FORGED, ?CLIENT),
    ?assertEqual(?LOOPBACK, proxied_peer()),
    {_, Info, _} = stored(),
    ?assertEqual(?LOOPBACK, maps:get(peer_addr, Info)).

register_session_limit(#{plain := Chan}) ->
    reset(),
    ?assertMatch({error, {<<"14">>, _}, _}, register(Chan, <<"session-limit">>, <<>>)),
    ?assertEqual(0, meck:num_calls(yuzu_gw_upstream, proxy_register, '_')).

register_registry_unavailable(#{plain := Chan}) ->
    reset(),
    ?assertMatch({error, {<<"13">>, _}, _}, register(Chan, <<"registry-down">>, <<>>)),
    ?assertEqual(0, meck:num_calls(yuzu_gw_upstream, proxy_register, '_')).

register_upstream_failed(#{plain := Chan}) ->
    reset(),
    ?assertMatch({error, {<<"13">>, _}, _}, register(Chan, <<"upstream-fails">>, <<>>)),
    ?assertEqual(0, meck:num_calls(yuzu_gw_registry, store_pending, '_')),
    %% the slot reserved for the Register is given back
    ?assertEqual(1, meck:num_calls(yuzu_gw_registry, release_session, '_')).

%%--------------------------------------------------------------------
%% ExecuteCommand
%%--------------------------------------------------------------------

execute_unimplemented(#{plain := Chan}) ->
    {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?EXECUTE, #{command_id => <<"c">>, plugin => <<"p">>},
                                         command_def(), #{channel => Chan}),
    ?assertMatch({[], <<"12">>, _}, collect(S)).

%%--------------------------------------------------------------------
%% Subscribe
%%--------------------------------------------------------------------

subscribe_no_session(#{plain := Chan}) ->
    ?assertMatch({<<"3">>, _}, subscribe_status(Chan, undefined)).

subscribe_unknown_session(#{plain := Chan}) ->
    ?assertMatch({<<"5">>, _}, subscribe_status(Chan, <<"no-such-session">>)).

subscribe_registry_unavailable(#{plain := Chan}) ->
    ?assertMatch({<<"13">>, _}, subscribe_status(Chan, <<"registry-down">>)).

%%--------------------------------------------------------------------
%% Heartbeat
%%--------------------------------------------------------------------

heartbeat_unknown(#{plain := Chan}) ->
    reset(),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(Chan, <<"no-such-session">>)),
    ?assertEqual(0, meck:num_calls(yuzu_gw_heartbeat_buffer, queue_heartbeat, '_')).

heartbeat_no_session(#{plain := Chan}) ->
    reset(),
    ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(Chan, <<>>)),
    ?assertEqual(0, meck:num_calls(yuzu_gw_heartbeat_buffer, queue_heartbeat, '_')).

%% The session is pending on the connection the Register arrived on (the key the
%% service stored); only that connection may heartbeat it.
heartbeat_same_connection(#{plain := Chan}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-h1">>, <<>>),
    {Session, Info, _} = stored(),
    try
        pending_session(Session, maps:get(conn_key, Info)),
        ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, Session)),
        ?assertEqual(1, meck:num_calls(yuzu_gw_heartbeat_buffer, queue_heartbeat, '_'))
    after
        no_pending_sessions()
    end.

heartbeat_other_connection(#{plain := Chan, plain2 := Other}) ->
    reset(),
    {ok, _, _} = register(Chan, <<"agent-h2">>, <<>>),
    {Session, Info, _} = stored(),
    try
        pending_session(Session, maps:get(conn_key, Info)),
        ?assertMatch({error, {<<"5">>, <<"unknown session">>}, _}, heartbeat(Other, Session)),
        ?assertEqual(0, meck:num_calls(yuzu_gw_heartbeat_buffer, queue_heartbeat, '_'))
    after
        no_pending_sessions()
    end.

%%--------------------------------------------------------------------
%% Client side
%%--------------------------------------------------------------------

reset() ->
    [meck:reset(M) || M <- ?MOCKS],
    ok.

%% gateway_observed_peer is the field an agent has no business filling; the tests
%% send a forged one so an overwrite is what is observed, not an empty field.
register(Chan, AgentId, Forged) ->
    register(Chan, AgentId, Forged, undefined).

register(Chan, AgentId, Forged, ForwardedFor) ->
    Ctx = case ForwardedFor of
        undefined -> ctx:new();
        _ -> yuzu_gw_test_client:with_metadata(ctx:new(), #{<<"x-forwarded-for">> => ForwardedFor})
    end,
    Request = #{info => #{agent_id => AgentId, hostname => <<"host-", AgentId/binary>>},
                enrollment_token => <<"enroll-secret">>,
                gateway_observed_peer => Forged},
    yuzu_gw_test_client:unary(Ctx, ?REGISTER, Request, register_def(), #{channel => Chan}).

binary_to_ip(Text) ->
    {ok, Ip} = inet:parse_strict_address(binary_to_list(Text)),
    Ip.

%% The gateway_observed_peer of the RegisterRequest the upstream was given.
proxied_peer() ->
    maps:get(gateway_observed_peer, meck:capture(last, yuzu_gw_upstream, proxy_register, '_', 1)).

%% {SessionId, Info, Reservation} of the pending registration the service stored.
stored() ->
    [Call] = [A || {_Pid, {yuzu_gw_registry, store_pending, A}, _Result} <- meck:history(yuzu_gw_registry)],
    list_to_tuple(Call).

heartbeat(Chan, Session) ->
    yuzu_gw_test_client:unary(ctx:new(), ?HEARTBEAT, #{session_id => Session}, heartbeat_def(),
                              #{channel => Chan}).

%% The status a Subscribe stream ends with when the handler refuses it before
%% sending anything. The client keeps the stream open for sending until it says
%% otherwise, so the status is read from the trailers and the stream then closed.
subscribe_status(Chan, Session) ->
    Ctx = case Session of
        undefined -> ctx:new();
        _ -> yuzu_gw_test_client:with_metadata(ctx:new(), #{<<"x-yuzu-session-id">> => Session})
    end,
    {ok, S} = yuzu_gw_test_client:stream(Ctx, ?SUBSCRIBE, subscribe_def(), #{channel => Chan}),
    {ok, {Status, Message, _}} = yuzu_gw_test_client:recv_trailers(S, 5000),
    ok = yuzu_gw_test_client:close_send(S),
    {Status, Message}.

%% Every message of a stream, then its status and message. The stream ends
%% with `stream_finished' whatever its status; the status (0 or an error) and
%% its message are then read from the trailers.
collect(S) ->
    collect(S, []).

collect(S, Acc) ->
    case yuzu_gw_test_client:recv_data(S, 5000) of
        {ok, Message} -> collect(S, [Message | Acc]);
        stream_finished ->
            case yuzu_gw_test_client:recv_trailers(S, 5000) of
                {ok, {Status, Message, _}} -> {lists:reverse(Acc), Status, Message};
                Other -> {lists:reverse(Acc), {unexpected, Other}, undefined}
            end;
        Other -> {lists:reverse(Acc), {unexpected, Other}, undefined}
    end.

register_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.RegisterRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.RegisterResponse') end}.

heartbeat_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

command_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.CommandRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.CommandResponse') end}.

subscribe_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.CommandResponse') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.CommandRequest') end}.
