%%%-------------------------------------------------------------------
%%% @doc Which address a call is attributed to, over a real listener
%%% (yuzu_grpc_origin; the decision table is in yuzu_grpc_origin_tests). The
%%% client is grpcbox_client; a test-only TCP relay (yuzu_gw_test_relay) plays
%%% the load balancer that prepends a PROXY protocol header, an F5 iRule or
%%% HAProxy `send-proxy-v2'.
%%%
%%%   - a PROXY header (version 1 and 2, IPv4 and IPv6) from a trusted source
%%%     is the origin, and the TCP peer stays the proxy;
%%%   - a claim from a peer that is not a trusted source is ignored and counted,
%%%     and the call is still served (never refused);
%%%   - a proxy-protocol listener closes a connection that sends no header;
%%%   - x-forwarded-for: the entry `trusted_hops' places from the right, never
%%%     a forged leading one, and nothing at all on a listener that has no
%%%     forwarded_for origin;
%%%   - client certificates and the proxy: a certificate reaches the handler
%%%     through a PROXY-protocol relay (TLS passes through it), a listener that
%%%     requests but does not require a certificate serves both kinds of
%%%     client, and an auth_fun still gates a proxy-protocol listener. These are
%%%     the properties a move of the agent edge to mutual TLS behind an F5 rests
%%%     on.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_origin_wire_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-export([forward_origin/4]).

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(CLIENT, {203, 0, 113, 9}).
-define(CLIENT_TEXT, <<"203.0.113.9">>).
-define(LOOPBACK, <<"127.0.0.1">>).
-define(EVENTS, yuzu_grpc_origin_wire_events).

%%%-------------------------------------------------------------------
%%% Plaintext listeners
%%%-------------------------------------------------------------------

origin_test_() ->
    {setup,
     fun plain_setup/0,
     fun plain_cleanup/1,
     fun(State) ->
        [{"PROXY v2 from a trusted source: the header's address is the origin, the peer is the proxy",
          fun() -> proxy_v2(State) end},
         {"PROXY v1 is read the same way", fun() -> proxy_v1(State) end},
         {"PROXY v2 with an IPv6 client address", fun() -> proxy_ipv6(State) end},
         {"PROXY from a source that is not trusted is ignored and counted, and the call is served",
          fun() -> proxy_untrusted(State) end},
         {"a connection to a proxy-protocol listener without a header is closed",
          fun() -> proxy_header_missing(State) end},
         {"x-forwarded-for from a trusted proxy: the last entry is the origin",
          fun() -> xff_last_entry(State) end},
         {"x-forwarded-for: a forged leading entry is never used",
          fun() -> xff_forged_leading(State) end},
         {"x-forwarded-for with trusted_hops 1 skips the proxy in front",
          fun() -> xff_hops(State) end},
         {"x-forwarded-for with fewer entries than trusted_hops is ignored and counted",
          fun() -> xff_too_short(State) end},
         {"x-forwarded-for that is not an address is ignored and counted",
          fun() -> xff_garbage(State) end},
         {"x-forwarded-for from a peer that is not a trusted proxy is ignored and counted",
          fun() -> xff_untrusted(State) end},
         {"a listener with no origin configured ignores x-forwarded-for and counts nothing",
          fun() -> xff_not_configured(State) end}]
     end}.

plain_setup() ->
    start_apps(),
    yuzu_grpc_stub_svc:init_state(),
    Base = #{service_protos => [agent_pb], services => #{?SVC => yuzu_grpc_stub_svc}},
    Local = [{127, 0, 0, 1}],
    Elsewhere = [{10, 0, 0, 5}],
    Start = fun(Name, Origin) ->
                yuzu_gw_test_listener:start(maps:merge(Base#{name => Name}, Origin))
            end,
    {PtPort, Pt} = Start(ow_proxy_trusted, #{origin => #{mode => proxy_protocol, sources => Local}}),
    {PuPort, Pu} = Start(ow_proxy_untrusted,
                         #{origin => #{mode => proxy_protocol, sources => Elsewhere}}),
    {FtPort, Ft} = Start(ow_fwd_trusted, #{origin => #{mode => forwarded_for, sources => Local}}),
    {FuPort, Fu} = Start(ow_fwd_untrusted,
                         #{origin => #{mode => forwarded_for, sources => Elsewhere}}),
    {FhPort, Fh} = Start(ow_fwd_hops,
                         #{origin => #{mode => forwarded_for, sources => Local, trusted_hops => 1}}),
    {NoPort, No} = Start(ow_none, #{}),
    Relays = [{r_v2, yuzu_gw_test_relay:start(PtPort, yuzu_gw_test_relay:proxy_header(2, ?CLIENT))},
              {r_v1, yuzu_gw_test_relay:start(PtPort, yuzu_gw_test_relay:proxy_header(1, ?CLIENT))},
              {r_v6, yuzu_gw_test_relay:start(
                       PtPort, yuzu_gw_test_relay:proxy_header(2, {16#2001, 16#db8, 0, 0, 0, 0, 0, 7}))},
              {r_untrusted, yuzu_gw_test_relay:start(
                              PuPort, yuzu_gw_test_relay:proxy_header(2, ?CLIENT))}],
    Channel = fun(Name, Port) -> yuzu_gw_test_listener:client_channel(Name, #{port => Port}) end,
    Chans = [{chan_v2, Channel(ow_v2, element(1, proplists:get_value(r_v2, Relays)))},
             {chan_v1, Channel(ow_v1, element(1, proplists:get_value(r_v1, Relays)))},
             {chan_v6, Channel(ow_v6, element(1, proplists:get_value(r_v6, Relays)))},
             {chan_untrusted, Channel(ow_untrusted,
                                      element(1, proplists:get_value(r_untrusted, Relays)))},
             {chan_fwd, Channel(ow_fwd, FtPort)},
             {chan_fwd_untrusted, Channel(ow_fwd_untrusted_chan, FuPort)},
             {chan_fwd_hops, Channel(ow_fwd_hops_chan, FhPort)},
             {chan_none, Channel(ow_none_chan, NoPort)}],
    %% eunit runs setup and each test in different processes, so the events go
    %% to a table rather than to a mailbox.
    ?EVENTS = ets:new(?EVENTS, [named_table, public, ordered_set]),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, grpc, origin_ignored], fun ?MODULE:forward_origin/4, none),
    maps:merge(#{listeners => [Pt, Pu, Ft, Fu, Fh, No], relays => [R || {_, {_, R}} <- Relays],
                 proxy_port => PtPort, telemetry => Id},
               maps:from_list(Chans)).

plain_cleanup(#{listeners := Listeners, relays := Relays, telemetry := Id} = State) ->
    telemetry:detach(Id),
    ets:delete(?EVENTS),
    [yuzu_gw_test_listener:stop_channel(maps:get(K, State))
     || K <- [chan_v2, chan_v1, chan_v6, chan_untrusted, chan_fwd, chan_fwd_untrusted,
              chan_fwd_hops, chan_none]],
    [yuzu_gw_test_relay:stop(R) || R <- Relays],
    [yuzu_gw_test_listener:stop(P) || P <- Listeners],
    ok.

proxy_v2(#{chan_v2 := Chan}) ->
    flush_events(),
    ?assertEqual({?CLIENT_TEXT, <<"proxy_protocol">>, ?LOOPBACK, <<"no-cert">>}, origin_of(Chan)),
    ?assertEqual(none, origin_event()).

proxy_v1(#{chan_v1 := Chan}) ->
    ?assertEqual({?CLIENT_TEXT, <<"proxy_protocol">>, ?LOOPBACK, <<"no-cert">>}, origin_of(Chan)).

proxy_ipv6(#{chan_v6 := Chan}) ->
    ?assertEqual({<<"2001:db8::7">>, <<"proxy_protocol">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan)).

proxy_untrusted(#{chan_untrusted := Chan}) ->
    flush_events(),
    yuzu_grpc_stub_svc:reset(),
    %% the relay's header claims a client, but this listener trusts only 10.0.0.5
    ?assertEqual({?LOOPBACK, <<"transport">>, ?LOOPBACK, <<"no-cert">>}, origin_of(Chan)),
    ?assertEqual({proxy_protocol, untrusted_source}, origin_event()),
    ?assertEqual(1, yuzu_grpc_stub_svc:calls()).

proxy_header_missing(#{proxy_port := Port}) ->
    yuzu_grpc_stub_svc:reset(),
    {ok, Sock} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    ok = gen_tcp:send(Sock, <<"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n">>),
    ?assertMatch({error, _}, gen_tcp:recv(Sock, 0, 5000)),
    gen_tcp:close(Sock),
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

xff_last_entry(#{chan_fwd := Chan}) ->
    flush_events(),
    ?assertEqual({?CLIENT_TEXT, <<"forwarded_for">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan, <<"203.0.113.9">>)),
    ?assertEqual(none, origin_event()).

xff_forged_leading(#{chan_fwd := Chan}) ->
    ?assertEqual({?CLIENT_TEXT, <<"forwarded_for">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan, <<"1.1.1.1, 2.2.2.2, 203.0.113.9">>)).

xff_hops(#{chan_fwd_hops := Chan}) ->
    ?assertEqual({?CLIENT_TEXT, <<"forwarded_for">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan, <<"203.0.113.9, 192.0.2.50">>)).

xff_too_short(#{chan_fwd_hops := Chan}) ->
    flush_events(),
    ?assertEqual({?LOOPBACK, <<"transport">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan, <<"203.0.113.9">>)),
    ?assertEqual({forwarded_for, bad_claim}, origin_event()).

xff_garbage(#{chan_fwd := Chan}) ->
    flush_events(),
    ?assertEqual({?LOOPBACK, <<"transport">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan, <<"not-an-address">>)),
    ?assertEqual({forwarded_for, bad_claim}, origin_event()).

xff_untrusted(#{chan_fwd_untrusted := Chan}) ->
    flush_events(),
    ?assertEqual({?LOOPBACK, <<"transport">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan, <<"203.0.113.9">>)),
    ?assertEqual({forwarded_for, untrusted_source}, origin_event()).

xff_not_configured(#{chan_none := Chan}) ->
    flush_events(),
    ?assertEqual({?LOOPBACK, <<"transport">>, ?LOOPBACK, <<"no-cert">>},
                 origin_of(Chan, <<"203.0.113.9">>)),
    ?assertEqual(none, origin_event()).

%%%-------------------------------------------------------------------
%%% TLS: client certificates and the proxy
%%%-------------------------------------------------------------------

tls_test_() ->
    {setup,
     fun tls_setup/0,
     fun tls_cleanup/1,
     fun(State) ->
        case State of
            #{} ->
                [{"a listener that requests but does not require a certificate: a client with one is served "
                  "and the handler sees it", fun() -> opportunistic_with_cert(State) end},
                 {"...and a client without one is served too",
                  fun() -> opportunistic_without_cert(State) end},
                 {"PROXY protocol keeps TLS end to end: the client certificate reaches the handler "
                  "together with the proxied origin", fun() -> proxy_keeps_cert(State) end},
                 {"...and a certless client behind the proxy is served",
                  fun() -> proxy_certless(State) end},
                 {"an auth_fun still gates a proxy-protocol listener: the pinned leaf is admitted "
                  "with its proxied origin", fun() -> proxy_auth_admitted(State) end},
                 {"...and an unpinned leaf is refused before the handler runs",
                  fun() -> proxy_auth_refused(State) end}];
            {error, Why} ->
                yuzu_gw_authz_tests:certs_unavailable("yuzu_grpc_origin_wire_tests", Why)
        end
     end}.

tls_setup() ->
    case yuzu_gw_authz_tests:setup_certs() of
        {error, _} = E ->
            E;
        Certs = #{dir := Dir, ca := Ca, srv_pem := SrvPem} ->
            start_apps(),
            yuzu_grpc_stub_svc:init_state(),
            application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
            Tls = #{certfile => filename:join(Dir, "gw.pem"), keyfile => filename:join(Dir, "gw.key"),
                    cacertfile => Ca},
            Opportunistic = Tls#{verify => verify_peer, fail_if_no_peer_cert => false},
            Base = #{service_protos => [agent_pb], services => #{?SVC => yuzu_grpc_stub_svc}},
            Proxied = #{mode => proxy_protocol, sources => [{127, 0, 0, 1}]},
            {OppPort, Opp} = yuzu_gw_test_listener:start(
                               Base#{name => ow_tls_opp, tls => Opportunistic}),
            {PxPort, Px} = yuzu_gw_test_listener:start(
                             Base#{name => ow_tls_proxy, tls => Opportunistic, origin => Proxied}),
            {AuPort, Au} = yuzu_gw_test_listener:start(
                             Base#{name => ow_tls_proxy_auth, tls => Tls, origin => Proxied,
                                   auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1}),
            Header = yuzu_gw_test_relay:proxy_header(2, ?CLIENT),
            {PxRelayPort, PxRelay} = yuzu_gw_test_relay:start(PxPort, Header),
            {AuRelayPort, AuRelay} = yuzu_gw_test_relay:start(AuPort, Header),
            Chans = [{chan_opp_cert, wire_chan(ow_opp_cert, OppPort, Certs, "agent")},
                     {chan_opp_none, wire_chan(ow_opp_none, OppPort, Certs, undefined)},
                     {chan_px_cert, wire_chan(ow_px_cert, PxRelayPort, Certs, "agent")},
                     {chan_px_none, wire_chan(ow_px_none, PxRelayPort, Certs, undefined)},
                     {chan_au_srv, wire_chan(ow_au_srv, AuRelayPort, Certs, "srv")},
                     {chan_au_agent, wire_chan(ow_au_agent, AuRelayPort, Certs, "agent")}],
            maps:merge(#{certs => Certs, listeners => [Opp, Px, Au], relays => [PxRelay, AuRelay]},
                       maps:from_list(Chans))
    end.

tls_cleanup({error, _}) ->
    ok;
tls_cleanup(#{certs := Certs, listeners := Listeners, relays := Relays} = State) ->
    [yuzu_gw_test_listener:stop_channel(maps:get(K, State))
     || K <- [chan_opp_cert, chan_opp_none, chan_px_cert, chan_px_none, chan_au_srv, chan_au_agent]],
    [yuzu_gw_test_relay:stop(R) || R <- Relays],
    [yuzu_gw_test_listener:stop(P) || P <- Listeners],
    application:unset_env(yuzu_gw, mgmt_peer_pins),
    yuzu_gw_authz_tests:cleanup_certs(Certs),
    ok.

wire_chan(Name, Port, Certs, Leaf) ->
    yuzu_grpc_wire_tests:client_chan(Name, Port, Certs, Leaf).

opportunistic_with_cert(#{chan_opp_cert := Chan}) ->
    ?assertEqual({?LOOPBACK, <<"transport">>, ?LOOPBACK, <<"cert">>}, origin_of(Chan)).

opportunistic_without_cert(#{chan_opp_none := Chan}) ->
    ?assertEqual({?LOOPBACK, <<"transport">>, ?LOOPBACK, <<"no-cert">>}, origin_of(Chan)).

proxy_keeps_cert(#{chan_px_cert := Chan}) ->
    ?assertEqual({?CLIENT_TEXT, <<"proxy_protocol">>, ?LOOPBACK, <<"cert">>}, origin_of(Chan)).

proxy_certless(#{chan_px_none := Chan}) ->
    ?assertEqual({?CLIENT_TEXT, <<"proxy_protocol">>, ?LOOPBACK, <<"no-cert">>}, origin_of(Chan)).

proxy_auth_admitted(#{chan_au_srv := Chan}) ->
    ?assertEqual({?CLIENT_TEXT, <<"proxy_protocol">>, ?LOOPBACK, <<"cert">>}, origin_of(Chan)).

proxy_auth_refused(#{chan_au_agent := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    ?assertMatch({error, {<<"16">>, _}, _}, heartbeat(Chan, <<"origin">>, ctx:new())),
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

start_apps() ->
    {ok, _} = application:ensure_all_started(grpcbox),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    ok.

%% What the handler reports: {Origin, how it was learned, TCP peer, cert | no-cert}.
origin_of(Chan) ->
    origin_of(Chan, undefined).

origin_of(Chan, Forwarded) ->
    Ctx = case Forwarded of
        undefined -> ctx:new();
        _ -> grpcbox_metadata:append_to_outgoing_ctx(ctx:new(), #{<<"x-forwarded-for">> => Forwarded})
    end,
    {ok, #{pending_commands := [#{command_id := Origin, plugin := Source, action := Peer,
                                  parameters := #{<<"cert">> := Cert}}]}, _} =
        heartbeat(Chan, <<"origin">>, Ctx),
    {Origin, Source, Peer, Cert}.

heartbeat(Chan, Command, Ctx) ->
    grpcbox_client:unary(Ctx, ?HEARTBEAT, #{session_id => Command}, heartbeat_def(),
                         #{channel => Chan}).

heartbeat_def() ->
    #grpcbox_def{service = ?SVC,
                 marshal_fun = fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
                 unmarshal_fun = fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

forward_origin(_Event, #{count := 1}, #{mode := Mode, reason := Reason}, _Config) ->
    ets:insert(?EVENTS, {erlang:unique_integer([monotonic]), Mode, Reason}),
    ok.

%% The oldest origin_ignored event not yet read, or `none'. The event is emitted
%% when the call starts, before its handler runs, so it is in the table before
%% the reply the test has already received.
origin_event() ->
    case ets:first(?EVENTS) of
        '$end_of_table' ->
            none;
        Key ->
            [{Key, Mode, Reason}] = ets:lookup(?EVENTS, Key),
            ets:delete(?EVENTS, Key),
            {Mode, Reason}
    end.

flush_events() ->
    ets:delete_all_objects(?EVENTS),
    ok.
