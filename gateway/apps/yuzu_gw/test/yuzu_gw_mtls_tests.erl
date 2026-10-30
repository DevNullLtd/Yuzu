%%%-------------------------------------------------------------------
%%% @doc Tests for the PKI PR5 gateway mTLS surface:
%%%
%%%   1. RegisterRequest/RegisterResponse PR3 fields (csr_pem,
%%%      issued_certificate, issued_ca_chain) survive an agent_pb
%%%      encode->decode roundtrip. This is the regression net for the
%%%      vendored-proto regen: if a future `gpb' run drops the fields,
%%%      the gateway silently stops forwarding the agent CSR and
%%%      per-agent mTLS auto-provisioning breaks for gateway-connected
%%%      agents (the bug this PR fixes).
%%%
%%%   2. The listener TLS contract of the `grpc_listeners' entry
%%%      (yuzu_grpc_listener, yuzu_gw_app): a `tls' map is TLS and nothing
%%%      else is, and an incomplete one refuses to start, so there is no
%%%      state in which cert material is configured and the listener serves
%%%      plaintext. verify defaults to the strict verify_peer with
%%%      fail_if_no_peer_cert=true, so an unconfigured TLS listener is mTLS and
%%%      the agent listener relaxes both explicitly.
%%%
%%%   3. Real TLS 1.2 handshakes against a REAL listener of the layer, using EC
%%%      certs (P-384 CA, P-256 leaf with serverAuth+clientAuth, the shape the
%%%      server mints as `default-gateway'), with the client restricted to the
%%%      production cipher whitelist: mutual auth succeeds, a client presenting
%%%      NO cert is refused by a mutual listener and served by a one-way one.
%%%
%%%   4. The mgmt-listener boot guard (#1422) over the entry shape.
%%%
%%% Pure Erlang: no Docker, no running upstream. The end-to-end
%%% containerised agent->gateway->server TLS path is CI/UAT-gated.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mtls_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% 1. agent_pb PR3 field roundtrip
%%%===================================================================

-define(REGISTER_REQ, 'yuzu.agent.v1.RegisterRequest').
-define(REGISTER_RESP, 'yuzu.agent.v1.RegisterResponse').

csr_pem_survives_register_request_roundtrip_test() ->
    CSR = <<"-----BEGIN CERTIFICATE REQUEST-----\nMIIBexample==\n"
            "-----END CERTIFICATE REQUEST-----\n">>,
    Req = #{info => #{agent_id => <<"agent-007">>},
            enrollment_token => <<"tok">>,
            csr_pem => CSR},
    Decoded = agent_pb:decode_msg(agent_pb:encode_msg(Req, ?REGISTER_REQ), ?REGISTER_REQ),
    ?assertEqual(CSR, maps:get(csr_pem, Decoded, undefined)).

issued_cert_fields_survive_register_response_roundtrip_test() ->
    Resp = #{session_id => <<"s1">>,
             accepted => true,
             issued_certificate => <<"-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n">>,
             issued_ca_chain => <<"-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n">>},
    Decoded = agent_pb:decode_msg(agent_pb:encode_msg(Resp, ?REGISTER_RESP), ?REGISTER_RESP),
    ?assertEqual(maps:get(issued_certificate, Resp),
                 maps:get(issued_certificate, Decoded, undefined)),
    ?assertEqual(maps:get(issued_ca_chain, Resp),
                 maps:get(issued_ca_chain, Decoded, undefined)).

%% Wire compatibility: bytes encoded by a producer that DOES know csr_pem
%% (field 7) must decode with csr_pem present — i.e. the field number matches
%% the canonical yuzu.agent.v1 proto (7). A mismatch would silently drop the
%% CSR at the gateway exactly like the pre-regen bug.
csr_pem_is_field_7_test() ->
    %% Manually frame field 7, wire type 2 (length-delimited): tag = (7 bsl 3) bor 2 = 58.
    Payload = <<"csr-bytes">>,
    Wire = <<58, (byte_size(Payload)):8, Payload/binary>>,
    Decoded = agent_pb:decode_msg(Wire, ?REGISTER_REQ),
    ?assertEqual(Payload, maps:get(csr_pem, Decoded, undefined)).

%% CRITICAL — gateway_pb is the marshaller `yuzu_gw_upstream:do_rpc/3` actually
%% uses for the ProxyRegister hot path (gateway -> server). `agent_pb` is ONLY the
%% agent-facing listener proto. gpb generates SELF-CONTAINED modules, so a field
%% present in agent_pb but missing in gateway_pb's embedded copy is silently
%% stripped in transit (gateway.proto:89 documents this exact trap). agent_pb,
%% gateway_pb (load-bearing), and management_pb (also imports agent.proto) MUST
%% all carry the fields — so we assert every embedding module, not just agent_pb.
csr_pem_survives_gateway_pb_roundtrip_test() ->
    CSR = <<"-----BEGIN CERTIFICATE REQUEST-----\nMIIBexample==\n"
            "-----END CERTIFICATE REQUEST-----\n">>,
    Req = #{info => #{agent_id => <<"agent-007">>}, csr_pem => CSR},
    Decoded = gateway_pb:decode_msg(gateway_pb:encode_msg(Req, ?REGISTER_REQ), ?REGISTER_REQ),
    ?assertEqual(CSR, maps:get(csr_pem, Decoded, undefined)).

issued_cert_fields_survive_gateway_pb_roundtrip_test() ->
    Resp = #{session_id => <<"s1">>, accepted => true,
             issued_certificate => <<"LEAF-PEM">>, issued_ca_chain => <<"CA-PEM">>},
    Decoded = gateway_pb:decode_msg(gateway_pb:encode_msg(Resp, ?REGISTER_RESP), ?REGISTER_RESP),
    ?assertEqual(<<"LEAF-PEM">>, maps:get(issued_certificate, Decoded, undefined)),
    ?assertEqual(<<"CA-PEM">>, maps:get(issued_ca_chain, Decoded, undefined)).

csr_pem_present_in_management_pb_test() ->
    CSR = <<"csr-bytes">>,
    Req = #{info => #{agent_id => <<"a">>}, csr_pem => CSR},
    Decoded = management_pb:decode_msg(management_pb:encode_msg(Req, ?REGISTER_REQ), ?REGISTER_REQ),
    ?assertEqual(CSR, maps:get(csr_pem, Decoded, undefined)).


%%%===================================================================
%%% 2. Listener TLS contract
%%%===================================================================

-define(TLS, (tls())).
-define(SVC, 'yuzu.agent.v1.AgentService').

tls() ->
    #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => "ca.pem"}.

entry(Extra) ->
    maps:merge(#{name => tls_contract, service_protos => [agent_pb],
                 services => #{?SVC => yuzu_grpc_stub_svc},
                 listen => #{port => 0, ip => {127, 0, 0, 1}}}, Extra).

%% What the listener asks of the handshake for the same `tls' map.
verify_of(Tls) ->
    Opts = yuzu_grpc_listener:ssl_opts(maps:merge(?TLS, Tls)),
    {proplists:get_value(verify, Opts), proplists:get_value(fail_if_no_peer_cert, Opts)}.

%% A `tls' map is mutual TLS unless it says otherwise: TLS 1.2 with the
%% ECDHE-ECDSA AEAD suites, h2 only.
tls_map_selects_strict_mutual_tls_test() ->
    Opts = yuzu_grpc_listener:ssl_opts(?TLS),
    ?assertEqual("gw.pem", proplists:get_value(certfile, Opts)),
    ?assertEqual("gw.key", proplists:get_value(keyfile, Opts)),
    ?assertEqual("ca.pem", proplists:get_value(cacertfile, Opts)),
    ?assertEqual(verify_peer, proplists:get_value(verify, Opts)),
    ?assertEqual(true, proplists:get_value(fail_if_no_peer_cert, Opts)),
    ?assertEqual(['tlsv1.2'], proplists:get_value(versions, Opts)),
    ?assertEqual(prod_ciphers(), proplists:get_value(ciphers, Opts)),
    ?assertEqual([<<"h2">>], proplists:get_value(alpn_preferred_protocols, Opts)).

%% One-way (server-authenticated) TLS: the agent edge, where an UNENROLLED agent
%% (no client cert yet) bootstraps over an encrypted, gateway-authenticated
%% channel. Both must be asked for: verify_none alone also drops the requirement.
oneway_tls_map_requests_no_client_cert_test() ->
    ?assertEqual({verify_none, false}, verify_of(#{verify => verify_none})),
    ?assertEqual({verify_none, false},
                 verify_of(#{verify => verify_none, fail_if_no_peer_cert => false})).

%% Backward-compat: WITHOUT those keys the strict mTLS default is kept, and a
%% missing key never silently weakens a listener.
omitted_verify_keys_preserve_strict_mtls_test() ->
    ?assertEqual({verify_peer, true}, verify_of(#{})),
    ?assertEqual({verify_peer, true}, verify_of(#{verify => verify_peer})),
    %% a requested-but-optional certificate is an explicit relaxation
    ?assertEqual({verify_peer, false}, verify_of(#{fail_if_no_peer_cert => false})).

%% The trap of the previous listener shape: cert material present but TLS not
%% switched on served PLAINTEXT silently. A `tls' map is the one switch, and the
%% listener does not start without all three files.
incomplete_tls_map_is_refused_not_plaintext_test_() ->
    Refused = fun(Tls) -> yuzu_grpc_listener:validate(entry(#{tls => Tls})) end,
    [?_assertEqual(ok, Refused(?TLS)),
     ?_assertEqual({error, {tls_incomplete, [cacertfile]}},
                   Refused(maps:remove(cacertfile, ?TLS))),
     ?_assertEqual({error, {tls_incomplete, [certfile, keyfile]}},
                   Refused(#{cacertfile => "ca.pem"})),
     %% even a single key
     ?_assertEqual({error, {tls_incomplete, [certfile, cacertfile]}},
                   Refused(#{keyfile => "gw.key"})),
     ?_assertEqual({error, {tls_incomplete, [certfile, keyfile, cacertfile]}}, Refused(#{})),
     %% placeholders are not material
     ?_assertEqual({error, {tls_incomplete, [certfile]}},
                   Refused(?TLS#{certfile => undefined})),
     ?_assertEqual({error, {tls_incomplete, [certfile, keyfile]}},
                   Refused(?TLS#{certfile => "", keyfile => <<>>})),
     %% inline DER is not the file path forms the listener takes: a key it does
     %% not read is refused, not ignored
     ?_assertMatch({error, {unknown_keys, tls, [cert], {allowed, _}}},
                   Refused(maps:remove(certfile, ?TLS#{cert => <<"der">>}))),
     %% the wrong container (a proplist) is not a tls map
     ?_assertEqual({error, bad_tls}, Refused([{certfile, "gw.pem"}, {keyfile, "gw.key"}])),
     ?_assertEqual({error, bad_tls}, Refused(true))].

%% The same refusals through the boot guard, which names the entry: a gateway
%% with such an entry does not start, however many other listeners are fine.
boot_guard_refuses_an_incomplete_tls_map_test_() ->
    Good = entry(#{name => good, tls => ?TLS}),
    Bad = fun(Tls) -> entry(#{name => bad, listen => #{port => 50063}, tls => Tls}) end,
    [?_assertEqual(ok, yuzu_gw_app:evaluate_listeners([Good, Bad(?TLS)])),
     ?_assertEqual({error, [{bad, {tls_incomplete, [cacertfile]}}]},
                   yuzu_gw_app:evaluate_listeners([Good, Bad(maps:remove(cacertfile, ?TLS))])),
     ?_assertEqual({error, [{bad, {tls_incomplete, [certfile]}}]},
                   yuzu_gw_app:evaluate_listeners([Good, Bad(?TLS#{certfile => undefined})])),
     ?_assertEqual({error, [{bad, bad_tls}]},
                   yuzu_gw_app:evaluate_listeners([Good, Bad([{certfile, "gw.pem"}])]))].

%% Which listener sets are TLS listeners: those with a tls map, wherever the
%% verify/fail_if_no_peer_cert switches are.
listeners_have_tls_detects_a_tls_map_test() ->
    ?assert(yuzu_gw_app:listeners_have_tls([entry(#{tls => ?TLS})])),
    ?assert(yuzu_gw_app:listeners_have_tls(
              [entry(#{}), entry(#{tls => ?TLS#{verify => verify_none}})])).

listeners_have_tls_false_for_plaintext_listeners_test() ->
    ?assertNot(yuzu_gw_app:listeners_have_tls([entry(#{})])),
    ?assertNot(yuzu_gw_app:listeners_have_tls([])),
    ?assertNot(yuzu_gw_app:listeners_have_tls(undefined)),
    %% a placeholder is not a tls map
    ?assertNot(yuzu_gw_app:listeners_have_tls([entry(#{tls => undefined})])).

%%%===================================================================
%%% 2b. Startup TLS-posture detection (yuzu_gw_app helpers)
%%%===================================================================

client_has_https_detects_https_endpoint_test() ->
    Cfg = #{channels => [{default_channel,
                          [{https, "server", 50055, [{verify, verify_peer}]}], #{}}]},
    ?assert(yuzu_gw_app:client_has_https(Cfg)).

client_has_https_false_for_plaintext_test() ->
    Cfg = #{channels => [{default_channel, [{http, "server", 50055, []}], #{}}]},
    ?assertNot(yuzu_gw_app:client_has_https(Cfg)),
    ?assertNot(yuzu_gw_app:client_has_https(undefined)).

client_tls_posture_verified_test() ->
    Cfg = #{channels => [{default_channel,
                          [{https, "server", 50055, [{verify, verify_peer}, {cacertfile, "ca"}]}], #{}}]},
    ?assertEqual(verified, yuzu_gw_app:client_tls_posture(Cfg)).

%% https WITHOUT {verify,verify_peer}: encrypted but not authenticated (MITM-able).
%% log_tls_state/0 must NOT report this as plain "TLS".
client_tls_posture_unverified_test() ->
    Cfg = #{channels => [{default_channel,
                          [{https, "server", 50055, [{cacertfile, "ca"}]}], #{}}]},
    ?assertEqual(unverified, yuzu_gw_app:client_tls_posture(Cfg)).

client_tls_posture_plaintext_test() ->
    Cfg = #{channels => [{default_channel, [{http, "server", 50055, []}], #{}}]},
    ?assertEqual(plaintext, yuzu_gw_app:client_tls_posture(Cfg)),
    ?assertEqual(plaintext, yuzu_gw_app:client_tls_posture(undefined)).

%% `verified' is verify_peer AND a trust anchor of the operator's own. verify_peer
%% alone leaves gun to fill in the operating system's CA store, so the gateway
%% would accept any publicly trusted certificate for its upstream: that is not
%% the pinned private PKI the guard exists to enforce, and it counts as
%% unverified (boot refuses it unless YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1).
client_tls_posture_needs_verify_peer_and_a_trust_anchor_test_() ->
    Posture = fun(Ssl) ->
                  yuzu_gw_app:client_tls_posture(
                    #{channels => [{default_channel, [{https, "server", 50055, Ssl}], #{}}]})
              end,
    Der = <<48, 3, 2, 1, 1>>,
    [{"verify_peer alone is unverified",
      ?_assertEqual(unverified, Posture([{verify, verify_peer}]))},
     {"verify_peer with a cacertfile is verified",
      ?_assertEqual(verified, Posture([{verify, verify_peer}, {cacertfile, "/etc/yuzu/ca.pem"}]))},
     {"verify_peer with a binary cacertfile is verified",
      ?_assertEqual(verified, Posture([{verify, verify_peer}, {cacertfile, <<"/etc/yuzu/ca.pem">>}]))},
     {"verify_peer with cacerts is verified",
      ?_assertEqual(verified, Posture([{verify, verify_peer}, {cacerts, [Der]}]))},
     {"the order of the options does not matter",
      ?_assertEqual(verified, Posture([{cacertfile, "/etc/yuzu/ca.pem"}, {verify, verify_peer}]))},
     {"an empty string cacertfile is no trust anchor",
      ?_assertEqual(unverified, Posture([{verify, verify_peer}, {cacertfile, ""}]))},
     {"an empty binary cacertfile is no trust anchor",
      ?_assertEqual(unverified, Posture([{verify, verify_peer}, {cacertfile, <<>>}]))},
     {"an empty cacerts list is no trust anchor",
      ?_assertEqual(unverified, Posture([{verify, verify_peer}, {cacerts, []}]))},
     {"an undefined cacertfile is no trust anchor",
      ?_assertEqual(unverified, Posture([{verify, verify_peer}, {cacertfile, undefined}]))},
     {"empty cacertfile and cacerts together are no trust anchor",
      ?_assertEqual(unverified, Posture([{verify, verify_peer}, {cacertfile, ""}, {cacerts, []}]))},
     {"verify_none with a cacertfile is unverified",
      ?_assertEqual(unverified, Posture([{verify, verify_none}, {cacertfile, "/etc/yuzu/ca.pem"}]))},
     {"verify_none with cacerts is unverified",
      ?_assertEqual(unverified, Posture([{verify, verify_none}, {cacerts, [Der]}]))},
     {"a cacertfile without any verify option is unverified",
      ?_assertEqual(unverified, Posture([{cacertfile, "/etc/yuzu/ca.pem"}]))},
     {"no options at all is unverified",
      ?_assertEqual(unverified, Posture([]))},
     {"options that are not a list are unverified, not a crash",
      ?_assertEqual(unverified, Posture(not_a_list))},
     {"an endpoint with a settings map is judged by the same rule",
      ?_assertEqual(unverified,
                    yuzu_gw_app:client_tls_posture(
                      #{channels => [{default_channel,
                                      [{https, "server", 50055, [{verify, verify_peer}], #{}}],
                                      #{}}]}))},
     {"an endpoint with a settings map and a trust anchor is verified",
      ?_assertEqual(verified,
                    yuzu_gw_app:client_tls_posture(
                      #{channels => [{default_channel,
                                      [{https, "server", 50055,
                                        [{verify, verify_peer}, {cacertfile, "ca"}], #{}}],
                                      #{}}]}))}].

%% Across channels the strongest posture wins (unchanged by the trust-anchor
%% rule): one verified channel makes the client verified, an unverified one
%% outranks plaintext.
client_tls_posture_mixed_channels_test_() ->
    Good = {https, "server", 50055, [{verify, verify_peer}, {cacertfile, "ca"}]},
    Weak = {https, "server", 50056, [{verify, verify_peer}]},
    Plain = {http, "server", 50057, []},
    Posture = fun(Endpoints) ->
                  yuzu_gw_app:client_tls_posture(
                    #{channels => [{N, [E], #{}} || {N, E} <- Endpoints]})
              end,
    [{"verified and unverified channels: verified",
      ?_assertEqual(verified, Posture([{default_channel, Good}, {other, Weak}]))},
     {"unverified first, verified second: verified",
      ?_assertEqual(verified, Posture([{other, Weak}, {default_channel, Good}]))},
     {"unverified and plaintext channels: unverified",
      ?_assertEqual(unverified, Posture([{default_channel, Weak}, {other, Plain}]))},
     {"verified and plaintext channels: verified",
      ?_assertEqual(verified, Posture([{default_channel, Good}, {other, Plain}]))},
     {"only plaintext channels: plaintext",
      ?_assertEqual(plaintext, Posture([{default_channel, Plain}, {other, Plain}]))}].

%% The upstream guard decision for a verify_peer channel with no trust anchor:
%% the posture is unverified, and an unverified posture is refused unless the
%% dev/CI override is set.
verify_peer_without_a_trust_anchor_is_refused_test() ->
    Cfg = #{channels => [{default_channel,
                          [{https, "server", 50055, [{verify, verify_peer}]}], #{}}]},
    Posture = yuzu_gw_app:client_tls_posture(Cfg),
    ?assertEqual(unverified, Posture),
    ?assertEqual({error, unverified_upstream_tls},
                 yuzu_gw_app:evaluate_upstream_posture(Posture, false)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_upstream_posture(Posture, true)).

%% Fail-closed upstream-posture guard (#PR5, UP-11): only the dangerous
%% "encrypted but unauthenticated" state is refused; plaintext (UAT/dev) and
%% verified both boot. Override flips unverified back to ok.
evaluate_upstream_posture_refuses_unverified_test() ->
    ?assertEqual({error, unverified_upstream_tls},
                 yuzu_gw_app:evaluate_upstream_posture(unverified, false)).

evaluate_upstream_posture_override_allows_unverified_test() ->
    ?assertEqual(ok, yuzu_gw_app:evaluate_upstream_posture(unverified, true)).

evaluate_upstream_posture_allows_verified_and_plaintext_test() ->
    ?assertEqual(ok, yuzu_gw_app:evaluate_upstream_posture(verified, false)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_upstream_posture(plaintext, false)).

%%%===================================================================
%%% 3. Real handshakes against a listener of the layer
%%%   The listeners below are started from entries as they are configured,
%%%   the client verifies the gateway and offers only the production cipher
%%%   whitelist. Cases: mutual (the strict default), one-way (the agent edge:
%%%   verify_none, no client cert needed) and optional (a certificate is asked
%%%   for and not required, the step towards mutual TLS on the agent edge).
%%%===================================================================

handshake_test_() ->
    {setup, fun handshake_setup/0, fun handshake_cleanup/1,
     fun(State) ->
        case State of
            {error, Why} ->
                yuzu_gw_authz_tests:certs_unavailable("yuzu_gw_mtls_tests", Why);
            #{} ->
                [{"mutual handshake with client cert succeeds",
                  fun() -> mutual_handshake_ok(State) end},
                 {"client with no cert is rejected (fail_if_no_peer_cert)",
                  fun() -> no_client_cert_rejected(State) end},
                 {"unenrolled client (NO cert) connects to a one-way-TLS listener",
                  fun() -> oneway_no_client_cert_ok(State) end},
                 {"a one-way-TLS listener serves a client that does bring a cert too",
                  fun() -> oneway_client_cert_ok(State) end},
                 {"unenrolled client (NO cert) connects to a listener that only requests one",
                  fun() -> optional_no_client_cert_ok(State) end},
                 {"a client that offers a cipher outside the whitelist is refused",
                  fun() -> cipher_outside_whitelist_refused(State) end},
                 {"a client that offers only TLS 1.3 is refused (TLS 1.2 only)",
                  fun() -> tls13_only_refused(State) end}]
        end
     end}.

handshake_setup() ->
    case yuzu_gw_authz_tests:setup_certs() of
        {error, _} = E ->
            E;
        Certs = #{dir := Dir, ca := Ca} ->
            Tls = #{certfile => filename:join(Dir, "gw.pem"),
                    keyfile => filename:join(Dir, "gw.key"), cacertfile => Ca},
            Base = #{service_protos => [agent_pb], services => #{?SVC => yuzu_grpc_stub_svc}},
            {MutualPort, Mutual} = yuzu_gw_test_listener:start(Base#{tls => Tls}),
            {OnePort, OneWay} = yuzu_gw_test_listener:start(
                                  Base#{tls => Tls#{verify => verify_none}}),
            {OptPort, Optional} = yuzu_gw_test_listener:start(
                                    Base#{tls => Tls#{fail_if_no_peer_cert => false}}),
            #{certs => Certs, mutual => MutualPort, oneway => OnePort, optional => OptPort,
              listeners => [Mutual, OneWay, Optional]}
    end.

handshake_cleanup({error, _}) ->
    ok;
handshake_cleanup(#{certs := Certs, listeners := Listeners}) ->
    [yuzu_gw_test_listener:stop(L) || L <- Listeners],
    yuzu_gw_authz_tests:cleanup_certs(Certs),
    ok.

%% The hardened cipher whitelist shipped in gateway/config/sys.config.prod --
%% asserting a real handshake completes with EXACTLY these suites proves the
%% production option set is valid and negotiates against an EC (P-256) leaf.
prod_ciphers() ->
    ["ECDHE-ECDSA-AES256-GCM-SHA384",
     "ECDHE-ECDSA-AES128-GCM-SHA256",
     "ECDHE-ECDSA-CHACHA20-POLY1305"].

%% Client opts == the {https,...} channel SslOpts we ship (version floor + cipher
%% whitelist + verify_peer -- verify_peer is required or the client would not
%% verify the server). Leaf =:= none presents no certificate.
client_ssl_opts(#{dir := Dir, ca := Ca}, Leaf) ->
    Base = [{cacertfile, Ca}, {verify, verify_peer}, {versions, ['tlsv1.2']},
            {ciphers, prod_ciphers()}, {server_name_indication, "localhost"},
            {alpn_advertised_protocols, [<<"h2">>]}, {mode, binary}, {active, false}],
    case Leaf of
        none -> Base;
        _ -> [{certfile, filename:join(Dir, Leaf ++ ".pem")},
              {keyfile, filename:join(Dir, Leaf ++ ".key")} | Base]
    end.

connect(Port, Opts) ->
    ssl:connect("localhost", Port, Opts, 5000).

%% A connection that works: the handshake finished on h2 and TLS 1.2.
assert_connected(Result) ->
    ?assertMatch({ok, _}, Result),
    {ok, Sock} = Result,
    ?assertEqual({ok, <<"h2">>}, ssl:negotiated_protocol(Sock)),
    ?assertMatch({ok, [{protocol, 'tlsv1.2'}]}, ssl:connection_information(Sock, [protocol])),
    ssl:close(Sock).

%% A connection the listener refused. With TLS 1.2 the client's handshake can
%% complete before the server rejects the missing certificate, so the refusal
%% shows on the client's connect or on its first read; either way the answer is
%% an error from the peer (a closed or alerted connection), never a timeout.
assert_refused({error, _}) ->
    ok;
assert_refused({ok, Sock}) ->
    Read = ssl:recv(Sock, 0, 5000),
    ssl:close(Sock),
    ?assertMatch({error, _}, Read),
    ?assertNotEqual({error, timeout}, Read).

mutual_handshake_ok(#{certs := Certs, mutual := Port}) ->
    assert_connected(connect(Port, client_ssl_opts(Certs, "agent"))).

no_client_cert_rejected(#{certs := Certs, mutual := Port}) ->
    assert_refused(connect(Port, client_ssl_opts(Certs, none))).

%% The unenrolled-agent bootstrap case: NO client cert, but the client still
%% verifies the gateway's server cert (one-way / server-authenticated TLS).
oneway_no_client_cert_ok(#{certs := Certs, oneway := Port}) ->
    assert_connected(connect(Port, client_ssl_opts(Certs, none))).

oneway_client_cert_ok(#{certs := Certs, oneway := Port}) ->
    assert_connected(connect(Port, client_ssl_opts(Certs, "agent"))).

optional_no_client_cert_ok(#{certs := Certs, optional := Port}) ->
    assert_connected(connect(Port, client_ssl_opts(Certs, none))),
    assert_connected(connect(Port, client_ssl_opts(Certs, "agent"))).

cipher_outside_whitelist_refused(#{certs := Certs, oneway := Port}) ->
    Opts = lists:keyreplace(ciphers, 1, client_ssl_opts(Certs, none),
                            {ciphers, ["ECDHE-RSA-AES256-GCM-SHA384"]}),
    ?assertMatch({error, _}, connect(Port, Opts)).

tls13_only_refused(#{certs := Certs, oneway := Port}) ->
    Opts = lists:keyreplace(versions, 1,
               lists:keydelete(ciphers, 1, client_ssl_opts(Certs, none)),
               {versions, ['tlsv1.3']}),
    ?assertMatch({error, _}, connect(Port, Opts)).

%%%-------------------------------------------------------------------
%%% 4. Mgmt-listener boot-guard policy (#1422) -- evaluate_mgmt_posture/3
%%%-------------------------------------------------------------------

-define(PIN_FUN, fun yuzu_gw_authz:check_mgmt_peer/1).

secure_mgmt() ->
    #{name => mgmt,
      service_protos => [management_pb],
      services => #{},
      listen => #{port => 50063, ip => {0, 0, 0, 0}},
      tls => ?TLS,
      auth_fun => ?PIN_FUN}.

plain_mgmt(Listen) ->
    #{name => mgmt, service_protos => [management_pb], services => #{}, listen => Listen}.

pins() -> [{cert_file, "srv.pem"}].

with_tls(Fun) ->
    S = secure_mgmt(),
    S#{tls := Fun(maps:get(tls, S))}.

%% The defects the guard names for a lone listener on port 50063.
defects(Listener, Pins) ->
    {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
        yuzu_gw_app:evaluate_mgmt_posture([Listener], Pins, false),
    Defects.

mgmt_posture_secure_ok_test() ->
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([secure_mgmt()], pins(), false)),
    %% the strict switches stated out loud are the defaults
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(
                       [with_tls(fun(T) -> T#{verify => verify_peer,
                                              fail_if_no_peer_cert => true} end)],
                       pins(), false)),
    %% an explicit transport origin is the default
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(
                       [(secure_mgmt())#{origin => #{mode => transport}}], pins(), false)).

mgmt_posture_loopback_exempt_test() ->
    %% Loopback (v4 and v6) plaintext mgmt is the dev posture -- no network
    %% attack surface, boots without the hatch.
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(
                       [plain_mgmt(#{port => 50063, ip => {127, 0, 0, 1}})], [], false)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(
                       [plain_mgmt(#{port => 50063, ip => {0, 0, 0, 0, 0, 0, 0, 1}})], [], false)).

mgmt_posture_wildcard_plaintext_refused_test() ->
    Plain = plain_mgmt(#{port => 50063, ip => {0, 0, 0, 0}}),
    ?assert(lists:member(plaintext, defects(Plain, []))),
    %% what else is missing is named too
    ?assertEqual([plaintext, missing_or_wrong_auth_fun, no_mgmt_peer_pins], defects(Plain, [])).

mgmt_posture_missing_ip_is_exposed_test() ->
    %% The listener binds {0,0,0,0} when ip is missing, so the guard must too.
    ?assert(lists:member(plaintext, defects(plain_mgmt(#{port => 50063}), []))).

mgmt_posture_escape_hatch_boots_with_warning_result_test() ->
    Plain = plain_mgmt(#{port => 50063, ip => {0, 0, 0, 0}}),
    ?assertMatch({ok_insecure, [{50063, _}]},
                 yuzu_gw_app:evaluate_mgmt_posture([Plain], [], true)).

mgmt_posture_incomplete_tls_refused_test() ->
    %% A tls map without all the cert material cannot start at all
    %% (yuzu_grpc_listener:validate/1); the guard names it regardless, and an
    %% empty placeholder is not material.
    lists:foreach(fun(S) ->
        ?assert(lists:member(missing_cert_material, defects(S, pins())))
    end, [with_tls(fun(T) -> maps:remove(cacertfile, T) end),
          with_tls(fun(T) -> T#{keyfile := ""} end),
          with_tls(fun(T) -> T#{certfile := <<>>} end),
          with_tls(fun(T) -> T#{certfile := undefined} end)]).

mgmt_posture_verify_none_refused_test() ->
    %% TLS + verify_none would hand the auth_fun a SELF-SIGNED cert -- the
    %% CA gate must stay in front of the pin.
    S = with_tls(fun(T) -> T#{verify => verify_none} end),
    ?assert(lists:member(verify_not_peer, defects(S, pins()))),
    %% verify_none with the peer cert nominally required still has no CA check
    S2 = with_tls(fun(T) -> T#{verify => verify_none, fail_if_no_peer_cert => true} end),
    ?assert(lists:member(verify_not_peer, defects(S2, pins()))).

mgmt_posture_optional_peer_cert_refused_test() ->
    %% fail_if_no_peer_cert=false: a certless peer skips the auth_fun
    %% entirely (it only authenticates a PRESENTED cert).
    S = with_tls(fun(T) -> T#{fail_if_no_peer_cert => false} end),
    ?assertEqual([peer_cert_not_required], defects(S, pins())).

mgmt_posture_wrong_auth_fun_refused_test() ->
    S0 = secure_mgmt(),
    Wrong = S0#{auth_fun := fun erlang:is_binary/1},
    Missing = maps:remove(auth_fun, S0),
    lists:foreach(fun(S) ->
        ?assertEqual([missing_or_wrong_auth_fun], defects(S, pins()))
    end, [Wrong, Missing]).

mgmt_posture_empty_pins_refused_test() ->
    ?assertEqual([no_mgmt_peer_pins], defects(secure_mgmt(), [])),
    %% pins that are not a list are none
    ?assertEqual([no_mgmt_peer_pins], defects(secure_mgmt(), undefined)).

%% A management listener behind a proxy takes its authority from the proxy, not
%% from the certificate the auth_fun pins, and the server's own client could
%% not reach it: refused whatever else is right.
mgmt_posture_proxied_origin_refused_test_() ->
    Sources = [{10, 0, 0, 5}],
    Proxied = fun(Origin) -> (secure_mgmt())#{origin => Origin} end,
    [{"proxy_protocol",
      ?_assertEqual([proxied_origin],
                    defects(Proxied(#{mode => proxy_protocol, sources => Sources}), pins()))},
     {"forwarded_for",
      ?_assertEqual([proxied_origin],
                    defects(Proxied(#{mode => forwarded_for, sources => Sources}), pins()))},
     {"an origin that is not a map is not the transport peer either",
      ?_assertEqual([proxied_origin], defects(Proxied(transport), pins()))},
     {"an origin without a mode is not the transport peer either",
      ?_assertEqual([proxied_origin], defects(Proxied(#{}), pins()))}].

mgmt_posture_non_mgmt_listener_ignored_test() ->
    %% The wildcard one-way-TLS agent listener (verify_none, no auth_fun) is
    %% NOT a mgmt listener -- the guard must not refuse it, nor one that is
    %% proxied.
    Agent = #{name => agent, service_protos => [agent_pb], services => #{},
              listen => #{port => 50051, ip => {0, 0, 0, 0}},
              tls => ?TLS#{verify => verify_none, fail_if_no_peer_cert => false}},
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([Agent], [], false)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(
                       [Agent#{origin => #{mode => forwarded_for, sources => [{10, 0, 0, 5}]}}],
                       [], false)).

mgmt_posture_each_listener_reported_by_port_test() ->
    A = (plain_mgmt(#{port => 50063, ip => {0, 0, 0, 0}}))#{name => a},
    B = (secure_mgmt())#{name => b, listen => #{port => 50064, ip => {0, 0, 0, 0}},
                         auth_fun := fun erlang:is_binary/1},
    ?assertEqual({error, {insecure_mgmt_listener,
                          [{50063, [plaintext, missing_or_wrong_auth_fun]},
                           {50064, [missing_or_wrong_auth_fun]}]}},
                 yuzu_gw_app:evaluate_mgmt_posture([A, secure_mgmt(), B], pins(), false)).

mgmt_posture_malformed_entries_tolerated_test() ->
    %% Non-map junk in the listener list can't be proven to expose the mgmt
    %% proto -- the guard skips it (evaluate_listeners/1 refuses it
    %% separately at boot).
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([not_a_map, []], [], false)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(undefined, [], false)),
    ?assertEqual({error, [{unknown, entry_not_a_map}]},
                 yuzu_gw_app:evaluate_listeners([not_a_map])).

mgmt_posture_non_map_tls_refused_test() ->
    %% Only a tls MAP is TLS: the wrong container (a proplist) with full material
    %% leaves the listener plaintext as far as the guard is concerned, and
    %% yuzu_grpc_listener:validate/1 refuses it as bad_tls.
    S = (secure_mgmt())#{tls := [{certfile, "gw.pem"}, {keyfile, "gw.key"},
                                 {cacertfile, "ca.pem"}]},
    ?assert(lists:member(plaintext, defects(S, pins()))),
    ?assertEqual({error, bad_tls}, yuzu_grpc_listener:validate(S)).

mgmt_posture_fd_socket_forfeits_loopback_exemption_test_() ->
    %% PR #3905 review blocking finding: a socket option can override the bind. An
    %% inherited {fd, _} (systemd socket activation) binds wherever the descriptor
    %% points, and an {ip, _} inside socket_opts is appended after the map ip in
    %% the inet option list, where the later occurrence wins -- so a nominal
    %% loopback ip is a dead letter and must NOT exempt the listener. An
    %% unrecognised socket_opts shape is unprovable -- exposed.
    Plain = fun(SockOpts) ->
        plain_mgmt(maps:merge(#{port => 50063, ip => {127, 0, 0, 1}}, SockOpts))
    end,
    [{"loopback ip + {fd,_} socket option refused",
      ?_assertMatch({error, {insecure_mgmt_listener, [{50063, _}]}},
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_opts => [{fd, 42}]})], [], false))},
     {"loopback ip + overriding {ip,_} socket option refused",
      ?_assertMatch({error, {insecure_mgmt_listener, [{50063, _}]}},
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_opts => [{ip, {0, 0, 0, 0}}]})], [], false))},
     {"loopback ip + unrecognised socket_opts shape refused",
      ?_assertMatch({error, {insecure_mgmt_listener, [{50063, _}]}},
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_opts => junk})], [], false))},
     {"loopback ip + benign socket_opts list stays exempt",
      ?_assertEqual(ok,
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_opts => [{reuseaddr, true}]})], [], false))},
     {"the key is socket_opts: the old socket_options name overrides nothing",
      ?_assertEqual(ok,
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_options => [{fd, 42}]})], [], false))},
     {"secure posture with {fd,_} still passes (exemption lost, posture holds)",
      ?_assertEqual(ok,
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [(secure_mgmt())#{listen := #{port => 50063, ip => {127, 0, 0, 1},
                                                      socket_opts => [{fd, 42}]}}],
                        pins(), false))}].
