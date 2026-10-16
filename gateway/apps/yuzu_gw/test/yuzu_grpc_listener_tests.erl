%%%-------------------------------------------------------------------
%%% @doc What yuzu_grpc_listener:validate/1 accepts and refuses (the key sets
%%% are closed), the TLS and HTTP/2 options it derives and the line it logs when
%%% a listener is up. A refused entry never binds a port. The management
%%% listener's frame ceiling is also proven on a real listener: a fan-out of
%%% 6000 unary RPCs over one connection.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_listener_tests).

-include_lib("eunit/include/eunit.hrl").

%% logger handler callback (the "up" line test attaches this module)
-export([log/2]).
%% supervisor callback (the listener-supervisor test supervises one listener)
-export([init/1]).

-define(TLS, (tls_base())).

tls_base() ->
    #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => "ca.pem"}.

entry() ->
    entry(#{}).

entry(Extra) ->
    maps:merge(#{name => t, service_protos => [agent_pb],
                 services => #{'yuzu.agent.v1.AgentService' => yuzu_grpc_stub_svc},
                 listen => #{port => 0}}, Extra).

proxied() -> #{mode => proxy_protocol, sources => [{10, 0, 0, 5}]}.
forwarded() -> #{mode => forwarded_for, sources => [{10, 0, 0, 5}]}.

validate_origin_test_() ->
    [?_assertEqual(ok, yuzu_grpc_listener:validate(entry())),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(#{origin => #{mode => transport}}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(#{origin => proxied()}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(#{origin => forwarded()}))),
     %% a proxied listener that trusts nobody is refused, whatever the mode
     ?_assertEqual({error, origin_sources_required},
                   yuzu_grpc_listener:validate(entry(#{origin => #{mode => proxy_protocol,
                                                                   sources => []}}))),
     ?_assertEqual({error, origin_sources_required},
                   yuzu_grpc_listener:validate(entry(#{origin => #{mode => forwarded_for}}))),
     ?_assertEqual({error, {unknown_origin_mode, nonsense}},
                   yuzu_grpc_listener:validate(entry(#{origin => #{mode => nonsense}}))),
     %% the option the layer owns cannot be set through http2
     ?_assertMatch({error, {reserved_http2_options, [proxy_header]}},
                   yuzu_grpc_listener:validate(entry(#{http2 => #{proxy_header => true}})))].


%% An auth_fun authenticates the peer of the TLS connection. Behind a proxy
%% that terminates TLS that peer is the proxy, so the combination would read as
%% agent authentication and be nothing of the kind. PROXY protocol does not
%% terminate TLS, so an auth_fun there is still about the client.
validate_origin_with_auth_fun_test_() ->
    Auth = #{tls => ?TLS, auth_fun => fun(_) -> true end,
             service_protos => [management_pb],
             services => #{'yuzu.server.v1.ManagementService' => yuzu_grpc_stub_svc}},
    [?_assertEqual({error, auth_fun_behind_terminating_proxy},
                   yuzu_grpc_listener:validate(entry(Auth#{origin => forwarded()}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(Auth#{origin => proxied()}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(Auth#{service_protos => [management_pb]}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(
                         entry(#{tls => ?TLS, origin => forwarded()})))].

%% The ways a listener can ask for client certificates; the agent edge can move
%% from none to optional to required by configuration alone.
ssl_opts_client_certificates_test_() ->
    Verify = fun(Tls) ->
                 Opts = yuzu_grpc_listener:ssl_opts(maps:merge(?TLS, Tls)),
                 {proplists:get_value(verify, Opts), proplists:get_value(fail_if_no_peer_cert, Opts)}
             end,
    [%% mutual TLS is the default for a tls map
     ?_assertEqual({verify_peer, true}, Verify(#{})),
     %% one-way TLS: no certificate requested (today's agent edge)
     ?_assertEqual({verify_none, false}, Verify(#{verify => verify_none})),
     ?_assertEqual({verify_none, false},
                   Verify(#{verify => verify_none, fail_if_no_peer_cert => false})),
     %% requested, not required: an enrolled agent presents its certificate, an
     %% unenrolled one still bootstraps
     ?_assertEqual({verify_peer, false}, Verify(#{fail_if_no_peer_cert => false}))].

%%--------------------------------------------------------------------
%% The key sets are closed: nothing the layer does not read is accepted
%%--------------------------------------------------------------------

refused(Extra) ->
    yuzu_grpc_listener:validate(entry(Extra)).

%% The keys of the former shape are refused by name, each with where it went. An
%% entry that kept `transport_opts' with certificates and no `tls' would
%% otherwise start as plaintext HTTP/2.
legacy_entry_keys_are_refused_by_name_test_() ->
    Legacy = fun(Key, Value) ->
                 {error, {legacy_keys, entry, [{Key, Hint}]}} = refused(#{Key => Value}),
                 ?assert(is_list(Hint) andalso Hint =/= [])
             end,
    [{atom_to_list(Key), fun() -> Legacy(Key, Value) end}
     || {Key, Value} <- [{transport_opts, #{ssl => true, certfile => "gw.pem",
                                            keyfile => "gw.key", cacertfile => "ca.pem"}},
                         {listen_opts, #{port => 50051}},
                         {grpc_opts, #{service_protos => [agent_pb], services => #{}}},
                         {pool_opts, #{size => 4}},
                         {ssl, true}]].

certificates_configured_in_the_former_shape_do_not_start_plaintext_test() ->
    Former = #{transport_opts => #{ssl => true, certfile => "gw.pem", keyfile => "gw.key",
                                   cacertfile => "ca.pem"}},
    ?assertMatch({error, {legacy_keys, entry, [{transport_opts, _}]}}, refused(Former)),
    %% every key of the former shape at once: all are named
    {error, {legacy_keys, entry, Named}} =
        refused(Former#{listen_opts => #{port => 1}, grpc_opts => #{}, ssl => true}),
    ?assertEqual([grpc_opts, listen_opts, ssl, transport_opts],
                 lists:sort([K || {K, _} <- Named])).

unknown_keys_are_refused_with_the_allowed_ones_test_() ->
    Allowed = [name, service_protos, services, listen, tls, auth_fun, origin, http2,
               limits, acceptors],
    [%% a typo of `origin' would run the listener as `transport'
     ?_assertEqual({error, {unknown_keys, entry, [origins], {allowed, Allowed}}},
                   refused(#{origins => forwarded()})),
     ?_assertMatch({error, {unknown_keys, entry, [acceptor], {allowed, _}}},
                   refused(#{acceptor => 8})),
     ?_assertMatch({error, {unknown_keys, tls, [verfy], {allowed, _}}},
                   refused(#{tls => (?TLS)#{verfy => verify_none}})),
     ?_assertMatch({error, {unknown_keys, http2, [idle_timout], {allowed, _}}},
                   refused(#{http2 => #{idle_timout => 1000}})),
     ?_assertMatch({error, {unknown_keys, listen, [prot], {allowed, [port, ip, socket_opts]}}},
                   refused(#{listen => #{port => 0, prot => 1}})),
     ?_assertMatch({error, {unknown_keys, limits, [max_message_byte], {allowed, _}}},
                   refused(#{limits => #{max_message_byte => 1}}))].

%% `ssl => true' of the former shape lived in the transport options; in a `tls'
%% map it is refused by name.
tls_ssl_key_is_refused_by_name_test() ->
    ?assertMatch({error, {legacy_keys, tls, [{ssl, _}]}},
                 refused(#{tls => (?TLS)#{ssl => true}})).

the_tls_keys_the_listener_reads_are_accepted_test() ->
    ?assertEqual(ok, refused(#{tls => (?TLS)#{verify => verify_none,
                                              fail_if_no_peer_cert => false,
                                              ciphers => ["ECDHE-RSA-AES128-GCM-SHA256"]}})),
    ?assertEqual(ok, refused(#{listen => #{port => 0, ip => {127, 0, 0, 1},
                                           socket_opts => [{reuseaddr, true}]},
                               acceptors => 32,
                               limits => #{max_message_bytes => 65536, send_timeout_ms => 5000},
                               http2 => #{idle_timeout => 180000, max_concurrent_streams => 32}})).

bad_values_are_refused_test_() ->
    [?_assertEqual({error, bad_acceptors}, refused(#{acceptors => 0})),
     ?_assertEqual({error, bad_acceptors}, refused(#{acceptors => <<"4">>})),
     ?_assertEqual({error, bad_acceptors}, refused(#{acceptors => 2.0})),
     ?_assertEqual({error, bad_limits}, refused(#{limits => garbage})),
     ?_assertEqual({error, {bad_limits, [max_message_bytes]}},
                   refused(#{limits => #{max_message_bytes => 0}})),
     ?_assertEqual({error, {bad_limits, [send_timeout_ms]}},
                   refused(#{limits => #{send_timeout_ms => -1}})),
     ?_assertEqual({error, {bad_limits, [max_connections]}},
                   refused(#{limits => #{max_connections => 0}})),
     ?_assertEqual({error, {bad_limits, [max_connections]}},
                   refused(#{limits => #{max_connections => "100"}})),
     ?_assertEqual(ok, refused(#{limits => #{max_connections => infinity}})),
     ?_assertEqual(ok, refused(#{limits => #{max_connections => 60000}})),
     ?_assertEqual({error, {bad_tls_values, [verify]}},
                   refused(#{tls => (?TLS)#{verify => sometimes}})),
     ?_assertEqual({error, {bad_tls_values, [fail_if_no_peer_cert]}},
                   refused(#{tls => (?TLS)#{fail_if_no_peer_cert => yes}})),
     ?_assertEqual({error, {bad_tls_values, [ciphers]}},
                   refused(#{tls => (?TLS)#{ciphers => []}})),
     ?_assertEqual({error, bad_listen_ip}, refused(#{listen => #{port => 0, ip => "0.0.0.0"}})),
     ?_assertEqual({error, bad_listen_socket_opts},
                   refused(#{listen => #{port => 0, socket_opts => nodelay}})),
     ?_assertEqual({error, bad_http2}, refused(#{http2 => []}))].

%% An auth_fun on a listener that serves agent_pb would refuse every agent that
%% has no certificate yet: refused, with or without `tls', alone or combined with
%% the management service. A listener that serves only the management service
%% takes one.
auth_fun_is_refused_on_any_listener_that_serves_agent_pb_test_() ->
    Fun = fun yuzu_gw_authz:check_mgmt_peer/1,
    Mgmt = #{service_protos => [management_pb],
             services => #{'yuzu.server.v1.ManagementService' => yuzu_grpc_stub_svc}},
    Combined = #{service_protos => [agent_pb, management_pb],
                 services => #{'yuzu.agent.v1.AgentService' => yuzu_grpc_stub_svc,
                               'yuzu.server.v1.ManagementService' => yuzu_grpc_stub_svc}},
    [?_assertEqual({error, auth_fun_on_agent_listener},
                   refused(#{auth_fun => Fun})),
     ?_assertEqual({error, auth_fun_on_agent_listener},
                   refused(#{tls => ?TLS, auth_fun => Fun})),
     ?_assertEqual({error, auth_fun_on_agent_listener},
                   refused(Combined#{tls => ?TLS, auth_fun => Fun})),
     ?_assertEqual(ok, refused(Mgmt#{tls => ?TLS, auth_fun => Fun})),
     ?_assertEqual({error, auth_fun_without_tls}, refused(Mgmt#{auth_fun => Fun})),
     ?_assertEqual({error, bad_auth_fun}, refused(Mgmt#{tls => ?TLS, auth_fun => not_a_fun})),
     %% one listener for both services (the single-port rig) needs no auth_fun
     ?_assertEqual(ok, refused(Combined)),
     ?_assertEqual(ok, refused(Combined#{tls => ?TLS}))].

%% management_pb embeds the AgentService definition, so an entry that names only
%% management_pb in service_protos can still serve the agent RPCs through
%% `services'. The auth_fun refusal follows what is served, not what the entry
%% calls itself.
auth_fun_is_refused_when_the_agent_service_is_served_under_another_proto_test_() ->
    Fun = fun yuzu_gw_authz:check_mgmt_peer/1,
    MgmtAndAgent = #{service_protos => [management_pb],
                     services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service,
                                   'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}},
    AgentOnly = #{service_protos => [management_pb],
                  services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service}},
    Mgmt = #{service_protos => [management_pb],
             services => #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}},
    [{"the crafted entry: management_pb protos, AgentService served, auth_fun",
      ?_assertEqual({error, auth_fun_on_agent_listener},
                    refused(MgmtAndAgent#{tls => ?TLS, auth_fun => Fun}))},
     {"the same through evaluate_listeners (the boot guard)",
      ?_assertEqual({error, [{t, auth_fun_on_agent_listener}]},
                    yuzu_gw_app:evaluate_listeners(
                      [entry(MgmtAndAgent#{tls => ?TLS, auth_fun => Fun})]))},
     {"AgentService alone under management_pb",
      ?_assertEqual({error, auth_fun_on_agent_listener},
                    refused(AgentOnly#{tls => ?TLS, auth_fun => Fun}))},
     {"without an auth_fun the same entries are a valid combined listener",
      [?_assertEqual(ok, refused(MgmtAndAgent#{tls => ?TLS})),
       ?_assertEqual(ok, refused(AgentOnly))]},
     {"a management-only listener still takes an auth_fun",
      ?_assertEqual(ok, refused(Mgmt#{tls => ?TLS, auth_fun => Fun}))},
     {"serves_agent/1 is the one answer to the question",
      [?_assert(yuzu_grpc_listener:serves_agent(entry())),
       ?_assert(yuzu_grpc_listener:serves_agent(MgmtAndAgent)),
       ?_assert(yuzu_grpc_listener:serves_agent(AgentOnly)),
       ?_assertNot(yuzu_grpc_listener:serves_agent(Mgmt)),
       ?_assertNot(yuzu_grpc_listener:serves_agent(#{})),
       ?_assertNot(yuzu_grpc_listener:serves_agent(#{service_protos => bad, services => bad})),
       ?_assertNot(yuzu_grpc_listener:serves_agent(not_a_map))]}].

%% routes_agent/1 is the strict test the boot guard and /readyz ask: the
%% AgentService is a key of `services'. Listing agent_pb in service_protos
%% builds a route table without it, and an agent's RPC answers UNIMPLEMENTED.
routes_agent_test_() ->
    Svc = 'yuzu.agent.v1.AgentService',
    Mgmt = #{'yuzu.server.v1.ManagementService' => yuzu_grpc_stub_svc},
    [{"an entry that maps the AgentService routes it",
      [?_assert(yuzu_grpc_listener:routes_agent(entry())),
       ?_assert(yuzu_grpc_listener:routes_agent(entry(#{service_protos => [management_pb]}))),
       ?_assert(yuzu_grpc_listener:routes_agent(
                  entry(#{services => Mgmt#{Svc => yuzu_grpc_stub_svc}})))]},
     {"agent_pb in service_protos alone does not",
      [?_assertNot(yuzu_grpc_listener:routes_agent(entry(#{services => #{}}))),
       ?_assertNot(yuzu_grpc_listener:routes_agent(entry(#{services => Mgmt}))),
       ?_assertNot(yuzu_grpc_listener:routes_agent(
                     entry(#{service_protos => [agent_pb, management_pb], services => Mgmt})))]},
     {"yet serves_agent/1, the broad test the auth_fun refusal uses, says yes",
      [?_assert(yuzu_grpc_listener:serves_agent(entry(#{services => #{}}))),
       ?_assert(yuzu_grpc_listener:serves_agent(
                  entry(#{service_protos => [agent_pb, management_pb], services => Mgmt})))]},
     {"it is total: any other term is false",
      [?_assertNot(yuzu_grpc_listener:routes_agent(#{})),
       ?_assertNot(yuzu_grpc_listener:routes_agent(not_a_map)),
       ?_assertNot(yuzu_grpc_listener:routes_agent(#{services => [{Svc, m}]})),
       ?_assertNot(yuzu_grpc_listener:routes_agent(#{services => [{Svc, m} | tail]})),
       ?_assertNot(yuzu_grpc_listener:routes_agent(undefined))]},
     {"only the atom key counts: the binary and string forms of the name do not",
      [?_assertNot(yuzu_grpc_listener:routes_agent(
                     #{services => #{<<"yuzu.agent.v1.AgentService">> => m}})),
       ?_assertNot(yuzu_grpc_listener:routes_agent(
                     #{services => #{"yuzu.agent.v1.AgentService" => m}}))]}].

%% A list from configuration that is improper (`[a | b]') is a refusal, never a
%% crash of the guard or of /readyz that walks it.
improper_lists_are_refused_not_crashed_test_() ->
    Improper = [agent_pb | management_pb],
    [{"proper_list/1",
      [?_assert(yuzu_grpc_listener:proper_list([])),
       ?_assert(yuzu_grpc_listener:proper_list([a, b])),
       ?_assertNot(yuzu_grpc_listener:proper_list([a | b])),
       ?_assertNot(yuzu_grpc_listener:proper_list([a, b | c])),
       ?_assertNot(yuzu_grpc_listener:proper_list(a)),
       ?_assertNot(yuzu_grpc_listener:proper_list(#{}))]},
     {"service_protos",
      [?_assertEqual({error, bad_service_protos}, refused(#{service_protos => Improper})),
       ?_assertNot(yuzu_grpc_listener:serves_agent(entry(#{service_protos => [management_pb | agent_pb],
                                                           services => #{}}))),
       ?_assert(yuzu_grpc_listener:serves_proto(#{service_protos => [agent_pb | tail]}, agent_pb)),
       ?_assertNot(yuzu_grpc_listener:serves_proto(#{service_protos => [a | tail]}, agent_pb)),
       ?_assertNot(yuzu_grpc_listener:serves_proto(#{service_protos => tail}, agent_pb)),
       ?_assertNot(yuzu_grpc_listener:serves_proto(not_a_map, agent_pb))]},
     {"socket_opts",
      ?_assertEqual({error, bad_listen_socket_opts},
                    refused(#{listen => #{port => 0, socket_opts => [{nodelay, true} | nodelay]}}))},
     {"ciphers",
      ?_assertEqual({error, {bad_tls_values, [ciphers]}},
                    refused(#{tls => (tls_base())#{ciphers => ["ECDHE-ECDSA-AES256-GCM-SHA384" | x]}}))},
     {"origin sources",
      ?_assertEqual({error, {bad_origin_sources, improper_list}},
                    refused(#{origin => #{mode => proxy_protocol, sources => [{10, 0, 0, 5} | x]}}))}].

%% The route table is built from these two; a wrong type is a refusal, not a
%% crash in the guard that calls validate/1 for every entry.
service_shapes_are_checked_test_() ->
    [?_assertEqual({error, bad_service_protos}, refused(#{service_protos => agent_pb})),
     ?_assertEqual({error, bad_service_protos}, refused(#{service_protos => ["agent_pb"]})),
     ?_assertEqual({error, bad_services}, refused(#{services => [{svc, mod}]})),
     ?_assertEqual({error, [{t, bad_services}]},
                   yuzu_gw_app:evaluate_listeners([entry(#{services => not_a_map})]))].

%% `listen' decides where the socket binds; a socket option may not move it.
socket_opts_may_not_set_the_bind_test_() ->
    Opts = fun(SocketOpts) ->
               refused(#{listen => #{port => 0, ip => {127, 0, 0, 1}, socket_opts => SocketOpts}})
           end,
    [?_assertEqual({error, {listen_socket_opts_set_the_bind, [ip]}}, Opts([{ip, {0, 0, 0, 0}}])),
     ?_assertEqual({error, {listen_socket_opts_set_the_bind, [ifaddr]}},
                   Opts([{ifaddr, {0, 0, 0, 0}}])),
     ?_assertEqual({error, {listen_socket_opts_set_the_bind, [fd]}}, Opts([{fd, 3}])),
     ?_assertEqual({error, {listen_socket_opts_set_the_bind, [port]}}, Opts([{port, 8080}])),
     ?_assertEqual({error, {listen_socket_opts_set_the_bind, [local]}},
                   Opts([{local, "/tmp/yuzu_gw.sock"}])),
     ?_assertEqual({error, {listen_socket_opts_set_the_bind, [local]}}, Opts([local])),
     ?_assertEqual({error, {listen_socket_opts_set_the_bind, [fd, ifaddr]}},
                   Opts([{reuseaddr, true}, {ifaddr, {0, 0, 0, 0}}, {fd, 3}])),
     ?_assertEqual(ok, Opts([{reuseaddr, true}, {keepalive, true}, nodelay]))].

%%--------------------------------------------------------------------
%% Cipher suites follow the key type of the certificate
%%--------------------------------------------------------------------

-define(EC_SUITES, ["ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256",
                    "ECDHE-ECDSA-CHACHA20-POLY1305"]).
-define(RSA_SUITES, ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"]).

ciphers_of(Tls) ->
    proplists:get_value(ciphers, yuzu_grpc_listener:ssl_opts(Tls)).

cipher_selection_test_() ->
    {setup, fun() -> {make_cert(ec), make_cert(rsa)} end,
     fun({Ec, Rsa}) -> remove_cert(Ec), remove_cert(Rsa) end,
     fun({Ec, Rsa}) ->
         [{"an EC certificate gets the ECDSA suites",
           ?_assertEqual(?EC_SUITES, ciphers_of(tls_of(Ec)))},
          {"an RSA certificate gets the ECDHE-RSA AES-GCM suites",
           ?_assertEqual(?RSA_SUITES, ciphers_of(tls_of(Rsa)))},
          {"tls.ciphers always wins, whatever the key",
           [?_assertEqual(["ECDHE-RSA-AES128-GCM-SHA256"],
                          ciphers_of((tls_of(Ec))#{ciphers => ["ECDHE-RSA-AES128-GCM-SHA256"]})),
            ?_assertEqual(?EC_SUITES, ciphers_of((tls_of(Rsa))#{ciphers => ?EC_SUITES}))]},
          {"a certificate that cannot be read gets the EC suites",
           [?_assertEqual(?EC_SUITES, ciphers_of(?TLS)),
            ?_assertEqual(?EC_SUITES,
                          ciphers_of((tls_of(Ec))#{certfile => maps:get(keyfile, tls_of(Ec))}))]},
          {"TLS 1.2 only, whatever the key",
           ?_assertEqual(['tlsv1.2'],
                         proplists:get_value(versions, yuzu_grpc_listener:ssl_opts(tls_of(Rsa))))},
          {"an RSA gateway certificate completes a TLS 1.2 handshake",
           ?_assertMatch({ok, 'tlsv1.2'}, handshake(Rsa, tls_of(Rsa)))},
          {"an EC gateway certificate completes a TLS 1.2 handshake",
           ?_assertMatch({ok, 'tlsv1.2'}, handshake(Ec, tls_of(Ec)))},
          {"the ECDSA suites cannot serve an RSA certificate",
           ?_assertMatch({error, _}, handshake(Rsa, (tls_of(Rsa))#{ciphers => ?EC_SUITES}))}]
     end}.

tls_of(#{dir := Dir}) ->
    #{certfile => filename:join(Dir, "cert.pem"), keyfile => filename:join(Dir, "key.pem"),
      cacertfile => filename:join(Dir, "ca.pem"), verify => verify_none}.

%% A server on the listener's socket options and a client that trusts nothing in
%% particular: what is under test is whether the two agree on a suite.
handshake(#{cacerts := CaCerts}, Tls) ->
    {ok, _} = application:ensure_all_started(ssl),
    case ssl:listen(0, [{ip, {127, 0, 0, 1}}, {reuseaddr, true} | yuzu_grpc_listener:ssl_opts(Tls)]) of
        {error, _} = Error ->
            Error;
        {ok, Listen} ->
            {ok, {_, Port}} = ssl:sockname(Listen),
            Self = self(),
            Server = spawn_link(fun() ->
                Result = case ssl:transport_accept(Listen, 5000) of
                    {ok, Sock} -> ssl:handshake(Sock, 5000);
                    {error, _} = E -> E
                end,
                Self ! {server, self(), Result},
                receive stop -> ok after 5000 -> ok end
            end),
            Client = ssl:connect({127, 0, 0, 1}, Port,
                                 [{versions, ['tlsv1.2']}, {verify, verify_none},
                                  {cacerts, CaCerts}, {alpn_advertised_protocols, [<<"h2">>]},
                                  {ciphers, ssl:cipher_suites(all, 'tlsv1.2')}], 5000),
            Result = case Client of
                {ok, CSock} ->
                    {ok, Info} = ssl:connection_information(CSock, [protocol]),
                    ssl:close(CSock),
                    {ok, proplists:get_value(protocol, Info)};
                {error, _} = Err ->
                    Err
            end,
            receive {server, Server, _} -> ok after 5000 -> ok end,
            Server ! stop,
            ssl:close(Listen),
            Result
    end.

make_cert(Kind) ->
    KeyOpt = case Kind of
        rsa -> {rsa, 2048, 17};
        ec -> {namedCurve, secp256r1}
    end,
    %% sha256 explicitly: the default digest (sha1) is refused by some OpenSSL builds
    Data = public_key:pkix_test_data(#{root => [{key, KeyOpt}, {digest, sha256}],
                                       peer => [{key, KeyOpt}, {digest, sha256}]}),
    Cert = proplists:get_value(cert, Data),
    {KeyType, KeyDer} = proplists:get_value(key, Data),
    CaCerts = proplists:get_value(cacerts, Data),
    Rand = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8))),
    Dir = filename:join("/tmp", "yuzu_test_cipher_" ++ Rand),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    ok = file:write_file(filename:join(Dir, "cert.pem"),
                         public_key:pem_encode([{'Certificate', Cert, not_encrypted}])),
    ok = file:write_file(filename:join(Dir, "key.pem"),
                         public_key:pem_encode([{KeyType, KeyDer, not_encrypted}])),
    ok = file:write_file(filename:join(Dir, "ca.pem"),
                         public_key:pem_encode([{'Certificate', C, not_encrypted} || C <- CaCerts])),
    #{dir => Dir, cacerts => CaCerts}.

remove_cert(#{dir := Dir}) ->
    [file:delete(filename:join(Dir, F)) || F <- ["cert.pem", "key.pem", "ca.pem"]],
    file:del_dir(Dir),
    ok.

%%--------------------------------------------------------------------
%% The line a listener logs when it is up reaches an operator
%%--------------------------------------------------------------------

%% logger handler callback: hands every event it is given to the test process.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {logged, Event},
    ok.

%% The shipped sys.config files configure the `default' handler without
%% filters of their own, so it carries OTP's: events whose domain is not otp or
%% sasl are stopped. A handler with those filters sees what the shipped one sees.
default_handler_config(Pid) ->
    #{level => all,
      filter_default => stop,
      filters => [{remote_gl, {fun logger_filters:remote_gl/2, stop}},
                  {domain, {fun logger_filters:domain/2, {log, super, [otp, sasl]}}},
                  {no_domain, {fun logger_filters:domain/2, {log, undefined, []}}}],
      config => #{pid => Pid}}.

listener_up_line_is_delivered_by_the_default_log_handler_test() ->
    Id = yuzu_grpc_listener_tests_handler,
    Primary = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, info),
    ok = logger:add_handler(Id, ?MODULE, default_handler_config(self())),
    try
        %% the control: an event with a domain outside otp/sasl is stopped by
        %% these filters, so the handler is a faithful stand-in for the shipped one
        logger:info("control", [], #{domain => [yuzu_gw, grpc]}),
        ?assertEqual(nothing, receive {logged, _} -> delivered after 0 -> nothing end),
        Origin = #{mode => forwarded_for, sources => [{10, 9, 9, 9}]},
        {Port, Pid} = yuzu_gw_test_listener:start(
                        entry(#{name => up_line_listener, origin => Origin})),
        try
            Text = receive
                {logged, #{msg := {Fmt, Args}, level := info}} when is_list(Fmt), is_list(Args) ->
                    lists:flatten(io_lib:format(Fmt, Args))
            after 5000 -> no_line
            end,
            ?assertNotEqual(no_line, Text),
            {match, _} = re:run(Text, "up_line_listener"),
            {match, _} = re:run(Text, integer_to_list(Port)),
            {match, _} = re:run(Text, "tls=false"),
            {match, _} = re:run(Text, "origin=forwarded_for"),
            %% what trust is made of stays out of the line
            ?assertEqual(nomatch, re:run(Text, "10\\.9\\.9\\.9", [{capture, none}]))
        after
            yuzu_gw_test_listener:stop(Pid)
        end
    after
        ok = logger:remove_handler(Id),
        ok = logger:set_primary_config(level, Primary)
    end.

%%--------------------------------------------------------------------
%% The Ranch listener supervisor dies under a running listener
%%--------------------------------------------------------------------

%% supervisor callback: one listener, as the gateway's own supervisor runs it.
init(Entry) ->
    {ok, {#{strategy => one_for_one, intensity => 5, period => 60},
          [yuzu_grpc_listener:child_spec(Entry)]}}.

%% Ranch restarts a permanent listener supervisor of its own accord. The
%% listener process must stop WITHOUT forgetting its Ref, so terminate/2 removes
%% Ranch's entry and the supervisor's restart alone brings the port back: a
%% listener that dropped the Ref left the two restarts to race for the name, and
%% the loser took ranch_sup, and the node's other listeners, down with it.
%% The listener supervisor is stopped the way it stops when it gives up
%% (reason `shutdown', its children first); a brutal kill leaves the old listen
%% socket open while ranch_sup restarts, which fails on its own, whatever the
%% listener process does. ranch_sup allows one restart per ranch_sup_period
%% (5 s) and, measured, a second one 5.5 s after the first still counts as too
%% soon, so the second stop waits twice the period and two seconds more: the
%% elapsed time is the point, not a synchronisation.
listener_supervisor_death_restarts_the_listener_test_() ->
    {timeout, 60, fun listener_supervisor_death_restarts_the_listener/0}.

listener_supervisor_death_restarts_the_listener() ->
    {ok, _} = application:ensure_all_started(cowboy),
    Port = yuzu_gw_test_listener:probe_free_port(),
    Entry = entry(#{name => race_listener,
                    listen => #{port => Port, ip => {127, 0, 0, 1}}}),
    Ref = {yuzu_grpc, race_listener},
    process_flag(trap_exit, true),
    {ok, Sup} = supervisor:start_link(?MODULE, Entry),
    RanchSup = whereis(ranch_sup),
    try
        First = listener_pid(Sup),
        ?assertEqual({ok, Port}, served(Ref, Port)),
        Second = stop_ranch_listener(Sup, Ref, First, Port),
        ?assertNotEqual(First, Second),
        ?assertEqual(RanchSup, whereis(ranch_sup)),
        Period = application:get_env(ranch, ranch_sup_period, 5),
        receive after (2 * Period + 2) * 1000 -> ok end,
        Third = stop_ranch_listener(Sup, Ref, Second, Port),
        ?assertNotEqual(Second, Third),
        ?assertEqual(RanchSup, whereis(ranch_sup)),
        ?assert(is_process_alive(Sup))
    after
        unlink(Sup),
        MRef = erlang:monitor(process, Sup),
        exit(Sup, shutdown),
        receive {'DOWN', MRef, process, Sup, _} -> ok after 20000 -> error(supervisor_not_stopped) end,
        process_flag(trap_exit, false),
        drain_exits()
    end.

%% Stop Ranch's supervisor of the listener and wait until a NEW listener process
%% is serving the same port again. Returns its pid.
stop_ranch_listener(Sup, Ref, Old, Port) ->
    MRef = erlang:monitor(process, Old),
    ok = sys:terminate(ranch_server:get_listener_sup(Ref), shutdown),
    receive {'DOWN', MRef, process, Old, _} -> ok
    after 10000 -> error(listener_did_not_stop)
    end,
    New = await(fun() ->
                    case listener_pid(Sup) of
                        P when is_pid(P), P =/= Old ->
                            case served(Ref, Port) of {ok, Port} -> P; _ -> false end;
                        _ -> false
                    end
                end, 10000),
    ?assert(is_pid(New)),
    New.

listener_pid(Sup) ->
    [{_, Pid, _, _}] = supervisor:which_children(Sup),
    Pid.

%% {ok, Port} when Ranch says the listener runs and the port accepts a connection.
served(Ref, Port) ->
    try
        running = ranch:get_status(Ref),
        {ok, Port} = {ok, ranch:get_port(Ref)},
        {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}], 1000),
        ok = gen_tcp:close(S),
        {ok, Port}
    catch
        _:_ -> not_served
    end.

%% Poll Fun (every 20 ms, up to Timeout ms) until it returns something but
%% `false'; a state is awaited, not a duration.
await(Fun, Timeout) when Timeout > 0 ->
    case Fun() of
        false -> receive after 20 -> await(Fun, Timeout - 20) end;
        Value -> Value
    end;
await(_Fun, _Timeout) ->
    timeout.

drain_exits() ->
    receive {'EXIT', _, _} -> drain_exits() after 0 -> ok end.

%%--------------------------------------------------------------------
%% limits.max_connections bounds what a flood of connections can hold
%%--------------------------------------------------------------------

%% With a ceiling of two, the third connection is not served until one of the
%% first two closes: the server's HTTP/2 SETTINGS frame, which a served
%% connection gets at once, is the evidence either way. One acceptor, because the
%% ceiling is soft by the number of acceptors: each acceptor that is not asleep
%% yet takes one more connection before Ranch holds them all.
max_connections_ceiling_test() ->
    {Port, Pid} = yuzu_gw_test_listener:start(entry(#{name => ceiling_listener,
                                                     acceptors => 1,
                                                     limits => #{max_connections => 2}})),
    Ref = {yuzu_grpc, ceiling_listener},
    Open = fun() ->
               {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
               S
           end,
    Served = fun(S, Timeout) -> element(1, gen_tcp:recv(S, 0, Timeout)) =:= ok end,
    try
        ?assertEqual(2, ranch:get_max_connections(Ref)),
        S1 = Open(),
        S2 = Open(),
        ?assert(Served(S1, 5000)),
        ?assert(Served(S2, 5000)),
        ok = ranch:wait_for_connections(Ref, '==', 2),
        %% the kernel completes the TCP handshake from the backlog; nothing
        %% serves it while two connections are up
        S3 = Open(),
        ?assertNot(Served(S3, 500)),
        ?assertEqual(2, length(ranch:procs(Ref, connections))),
        %% a connection closing frees the slot and the waiting one is served
        ok = gen_tcp:close(S1),
        ?assert(Served(S3, 5000)),
        [gen_tcp:close(S) || S <- [S2, S3]]
    after
        yuzu_gw_test_listener:stop(Pid)
    end.

%% No ceiling unless the entry sets one.
no_ceiling_by_default_test() ->
    {_Port, Pid} = yuzu_gw_test_listener:start(entry(#{name => no_ceiling_listener})),
    try
        ?assertEqual(infinity, ranch:get_max_connections({yuzu_grpc, no_ceiling_listener}))
    after
        yuzu_gw_test_listener:stop(Pid)
    end.

%%%-------------------------------------------------------------------
%%% HTTP/2 options: the management listener's received-frame ceiling
%%%-------------------------------------------------------------------

-define(MGMT_SVC, 'yuzu.server.v1.ManagementService').
-define(LIST_AGENTS, <<"/yuzu.server.v1.ManagementService/ListAgents">>).

mgmt_entry() ->
    mgmt_entry(#{}).

mgmt_entry(Extra) ->
    maps:merge(#{name => m, service_protos => [management_pb],
                 services => #{?MGMT_SVC => yuzu_grpc_stub_svc},
                 listen => #{port => 0}}, Extra).

frame_rate(Entry) ->
    maps:get(max_received_frame_rate, yuzu_grpc_listener:http2_opts(Entry), cowboy_default).

%% The listener that routes the ManagementService is the one the server fans
%% commands out over, on one connection: ten times Cowboy's ceiling. A listener
%% that serves only agents keeps Cowboy's (the option is left unset), including
%% one that lists management_pb only for the AgentService it embeds. A combined
%% listener carries the fan-out and gets the raised value. An explicit `http2'
%% value wins either way, and the other defaults are unchanged.
http2_frame_rate_default_test_() ->
    Agent = #{'yuzu.agent.v1.AgentService' => yuzu_grpc_stub_svc},
    [{"management listener: 100000 frames per 10 s",
      ?_assertEqual({100000, 10000}, frame_rate(mgmt_entry()))},
     {"agent listener: Cowboy's own",
      ?_assertEqual(cowboy_default, frame_rate(entry()))},
     {"management_pb listing that routes only the AgentService: Cowboy's own",
      ?_assertEqual(cowboy_default, frame_rate(mgmt_entry(#{services => Agent})))},
     {"combined agent and management listener: raised",
      ?_assertEqual({100000, 10000},
                    frame_rate(mgmt_entry(#{service_protos => [agent_pb, management_pb],
                                            services => Agent#{?MGMT_SVC => yuzu_grpc_stub_svc}})))},
     {"an explicit http2 value wins on the management listener",
      ?_assertEqual({20000, 10000},
                    frame_rate(mgmt_entry(#{http2 => #{max_received_frame_rate => {20000, 10000}}})))},
     {"an explicit http2 value applies on the agent listener",
      ?_assertEqual({20000, 10000},
                    frame_rate(entry(#{http2 => #{max_received_frame_rate => {20000, 10000}}})))},
     {"the other defaults are the same on both, and an override leaves the rest",
      fun() ->
          Base = #{idle_timeout => 600000, max_concurrent_streams => 1024,
                   max_frame_size_received => 16384, linger_timeout => 1000},
          ?assertEqual(Base, yuzu_grpc_listener:http2_opts(entry())),
          ?assertEqual(Base#{max_received_frame_rate => {100000, 10000}},
                       yuzu_grpc_listener:http2_opts(mgmt_entry())),
          ?assertEqual(Base#{max_received_frame_rate => {100000, 10000},
                             max_concurrent_streams => 32},
                       yuzu_grpc_listener:http2_opts(
                         mgmt_entry(#{http2 => #{max_concurrent_streams => 32}})))
      end}].

%% The server holds ONE connection to the management listener and sends every
%% command of a fan-out over it. 6000 unary RPCs in 12 waves of 500 concurrent
%% calls are about 12000 received frames (HEADERS and DATA per call); inside one
%% 10 s window that is past Cowboy's ceiling, which closes the connection with
%% enhance_your_calm and fails the calls in flight on it (the review's
%% reproduction lost 69 of wave 10). Under the management default every call
%% succeeds, on the connection the fan-out started on. The ceiling counts from
%% the connection's start, so the run must also finish inside 10 s for the test
%% to prove anything; on loopback it takes a few seconds.
mgmt_listener_carries_a_fan_out_over_one_connection_test_() ->
    {timeout, 60, fun mgmt_fan_out_over_one_connection/0}.

mgmt_fan_out_over_one_connection() ->
    yuzu_grpc_stub_svc:init_state(),
    {Port, Pid} = yuzu_gw_test_listener:start(mgmt_entry(#{name => frame_rate_mgmt})),
    Chan = yuzu_gw_test_listener:client_channel(frame_rate_mgmt_chan, #{port => Port}),
    try
        [Conn] = up_conns(Chan),
        T0 = erlang:monotonic_time(millisecond),
        Results = lists:append([wave(Chan, 500) || _ <- lists:seq(1, 12)]),
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        Failed = [R || R <- Results, not is_ok(R)],
        ?assertEqual({0, []}, {length(Failed), lists:sublist(Failed, 3)}),
        ?assertEqual(6000, yuzu_grpc_stub_svc:calls()),
        %% the same connection, never closed and reopened by the channel
        ?assertEqual([Conn], up_conns(Chan)),
        ?assert(is_process_alive(Conn)),
        ?assert(Elapsed < 10000)
    after
        yuzu_gw_test_listener:stop_channel(Chan),
        yuzu_gw_test_listener:stop(Pid)
    end.

%% N concurrent ListAgents calls over the channel; every result, in order.
wave(Chan, N) ->
    Self = self(),
    Call = fun() ->
               Result = try yuzu_grpc_client:unary(#{}, ?LIST_AGENTS, #{filter => <<"ok">>},
                                                   list_agents_def(),
                                                   #{channel => Chan, timeout => 15000})
                        catch Class:Reason -> {Class, Reason}
                        end,
               Self ! {self(), Result}
           end,
    Pids = [spawn(Call) || _ <- lists:seq(1, N)],
    [receive {P, R} -> R after 20000 -> {no_result, P} end || P <- Pids].

is_ok({ok, #{agents := []}, _}) -> true;
is_ok(_) -> false.

up_conns(Chan) ->
    ets:select(Chan, [{{{slot, '_'}, '$1', up}, [], ['$1']}]).

list_agents_def() ->
    #{marshal => fun(M) -> management_pb:encode_msg(M, 'yuzu.server.v1.ListAgentsRequest') end,
      unmarshal => fun(B) -> management_pb:decode_msg(B, 'yuzu.server.v1.ListAgentsResponse') end}.
