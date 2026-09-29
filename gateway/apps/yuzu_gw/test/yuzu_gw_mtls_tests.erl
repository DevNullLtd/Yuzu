%%%-------------------------------------------------------------------
%%% @doc Tests for the PKI PR5 gateway mTLS surface:
%%%
%%%   1. RegisterRequest/RegisterResponse PR3 fields (csr_pem,
%%%      issued_certificate, issued_ca_chain) survive an agent_pb
%%%      encode→decode roundtrip. This is the regression net for the
%%%      vendored-proto regen: if a future `gpb` run drops the fields,
%%%      the gateway silently stops forwarding the agent CSR and
%%%      per-agent mTLS auto-provisioning breaks for gateway-connected
%%%      agents (the bug this PR fixes).
%%%
%%%   2. The vendored grpcbox listener TLS contract: a transport_opts map
%%%      enables TLS ONLY when it carries `ssl => true` AND all three of
%%%      keyfile/certfile/cacertfile (grpcbox_pool.erl). A map that
%%%      omits `ssl => true` silently degrades to plaintext — the latent
%%%      bug in the old config/sys.config.prod. The _checkouts patch made
%%%      verify / fail_if_no_peer_cert CONFIGURABLE (stock v0.17.1
%%%      hardcoded them), defaulting to the strict verify_peer +
%%%      fail_if_no_peer_cert=true when omitted — so an unconfigured TLS
%%%      listener is mTLS, and :50051 relaxes both explicitly.
%%%
%%%   3. A real TLS 1.2 mutual handshake using EC certs (P-384 CA, P-256
%%%      leaf with serverAuth+clientAuth — the shape the server mints as
%%%      `default-gateway`) with the exact ssl option set grpcbox derives,
%%%      proving (a) mutual auth succeeds and (b) a client presenting NO
%%%      cert is rejected (fail_if_no_peer_cert enforcement).
%%%
%%% Pure Erlang — no Docker, no running upstream. The end-to-end
%%% containerised agent→gateway→server TLS path is CI/UAT-gated.
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
%%% 2. grpcbox listener TLS-selection contract
%%%===================================================================

%% Extract the {Transport, SslOpts} grpcbox_pool:init/1 derives from a
%% transport_opts map (it is buried in the acceptor child spec).
pool_transport(TransportOpts) ->
    {ok, {_SupFlags, [Child]}} =
        grpcbox_pool:init([#{}, #{}, TransportOpts]),
    {grpcbox_acceptor, {Transport, _ServerOpts, _CbOpts, SslOpts}, []} =
        maps:get(start, Child),
    {Transport, SslOpts}.

transport_opts_with_ssl_true_selects_ssl_test() ->
    {Transport, SslOpts} = pool_transport(#{ssl => true,
                                            keyfile => "/x/gw.key",
                                            certfile => "/x/gw.pem",
                                            cacertfile => "/x/ca.pem"}),
    ?assertEqual(ssl, Transport),
    %% grpcbox forces mutual TLS on every TLS listener.
    ?assertEqual(true, proplists:get_value(fail_if_no_peer_cert, SslOpts)),
    ?assertEqual(verify_peer, proplists:get_value(verify, SslOpts)).

%% The trap that shipped in the old sys.config.prod: cert keys present but no
%% `ssl => true` ⇒ grpcbox silently runs PLAINTEXT.
transport_opts_missing_ssl_flag_is_plaintext_test() ->
    {Transport, _} = pool_transport(#{keyfile => "/x/gw.key",
                                     certfile => "/x/gw.pem",
                                     cacertfile => "/x/ca.pem",
                                     verify => verify_peer}),
    ?assertEqual(gen_tcp, Transport).

empty_transport_opts_is_plaintext_test() ->
    ?assertEqual({gen_tcp, []}, pool_transport(#{})).

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

servers_have_tls_detects_ssl_true_test() ->
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                 transport_opts => #{ssl => true, certfile => "c", keyfile => "k",
                                     cacertfile => "ca"}}],
    ?assert(yuzu_gw_app:servers_have_tls(Servers)).

servers_have_tls_false_for_plaintext_listeners_test() ->
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051}}],
    ?assertNot(yuzu_gw_app:servers_have_tls(Servers)),
    ?assertNot(yuzu_gw_app:servers_have_tls(undefined)).

%% listener_tls_traps/1: cert material present but `ssl => true` absent is the
%% silent-plaintext footgun (#1244) — grpcbox serves plaintext despite the
%% cert config. The detector must flag it and report the port.
listener_tls_trap_flags_cert_material_without_ssl_test() ->
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                 transport_opts => #{certfile => "c", keyfile => "k",
                                     cacertfile => "ca"}}],
    ?assertEqual([50051], yuzu_gw_app:listener_tls_traps(Servers)).

listener_tls_trap_flags_partial_cert_material_test() ->
    %% even a single cert key (here just keyfile) without ssl=>true is a trap.
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50063},
                 transport_opts => #{keyfile => "k"}}],
    ?assertEqual([50063], yuzu_gw_app:listener_tls_traps(Servers)).

listener_tls_trap_clear_when_ssl_true_test() ->
    %% a correctly-configured TLS listener (ssl=>true) is NOT a trap.
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                 transport_opts => #{ssl => true, certfile => "c", keyfile => "k",
                                     cacertfile => "ca"}}],
    ?assertEqual([], yuzu_gw_app:listener_tls_traps(Servers)).

listener_tls_trap_clear_for_plaintext_listener_test() ->
    %% a deliberately-plaintext listener (no transport_opts / no cert material)
    %% is NOT a trap — only "cert material but no ssl" is.
    ?assertEqual([], yuzu_gw_app:listener_tls_traps(
                       [#{grpc_opts => #{}, listen_opts => #{port => 50051}}])),
    ?assertEqual([], yuzu_gw_app:listener_tls_traps(
                       [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                          transport_opts => #{}}])),
    ?assertEqual([], yuzu_gw_app:listener_tls_traps(undefined)).

listener_tls_trap_reports_only_misconfigured_of_many_test() ->
    %% a mixed listener set reports ONLY the trapped port, leaving the correct
    %% TLS and the intentional-plaintext listeners out.
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                 transport_opts => #{ssl => true, certfile => "c", keyfile => "k",
                                     cacertfile => "ca"}},
               #{grpc_opts => #{}, listen_opts => #{port => 50063},
                 transport_opts => #{certfile => "c", keyfile => "k"}},
               #{grpc_opts => #{}, listen_opts => #{port => 50099}}],
    ?assertEqual([50063], yuzu_gw_app:listener_tls_traps(Servers)).

%% Hermes pass-1 HIGH: a PROPLIST transport_opts (wrong container — grpcbox wants
%% a map, so it yields plaintext) carrying cert material is still a trap.
listener_tls_trap_flags_proplist_transport_opts_test() ->
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                 transport_opts => [{certfile, "c"}, {keyfile, "k"}]}],
    ?assertEqual([50051], yuzu_gw_app:listener_tls_traps(Servers)).

%% Hermes pass-1 HIGH: inline-DER ssl material keys (cert/key/cacert), not just
%% the *file path forms, count as cert material.
listener_tls_trap_flags_inline_der_material_test() ->
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                 transport_opts => #{cert => <<"der">>}}],
    ?assertEqual([50051], yuzu_gw_app:listener_tls_traps(Servers)).

%% Hermes pass-1 INFO: `ssl` set to a non-true value (e.g. verify_peer) is NOT
%% the same as `ssl => true` — grpcbox still runs plaintext, so it is a trap.
listener_tls_trap_flags_ssl_set_to_non_true_test() ->
    Servers = [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                 transport_opts => #{ssl => verify_peer, certfile => "c"}}],
    ?assertEqual([50051], yuzu_gw_app:listener_tls_traps(Servers)).

%% Hermes pass-1 MEDIUM: a placeholder cert key with an undefined/empty value
%% must NOT trigger the warning (avoids training operators to ignore it).
listener_tls_trap_ignores_empty_placeholder_values_test() ->
    ?assertEqual([], yuzu_gw_app:listener_tls_traps(
                       [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                          transport_opts => #{certfile => undefined}}])),
    ?assertEqual([], yuzu_gw_app:listener_tls_traps(
                       [#{grpc_opts => #{}, listen_opts => #{port => 50051},
                          transport_opts => #{certfile => "", keyfile => <<>>}}])).

%%%===================================================================
%%% 3. Real EC mutual-TLS handshake (the option shape grpcbox uses)
%%%===================================================================

mtls_handshake_test_() ->
    {setup, fun setup_certs/0, fun cleanup_certs/1,
     fun(Certs) ->
        case Certs of
            {error, Why} ->
                %% openssl unavailable / failed — do not fail the suite, but
                %% make the skip visible.
                [{"mTLS handshake skipped: " ++ lists:flatten(io_lib:format("~p", [Why])),
                  fun() -> ?assert(true) end}];
            #{} ->
                [{"mutual handshake with client cert succeeds",
                  fun() -> mutual_handshake_ok(Certs) end},
                 {"client with no cert is rejected (fail_if_no_peer_cert)",
                  fun() -> no_client_cert_rejected(Certs) end}]
        end
     end}.

%% The hardened cipher whitelist shipped in gateway/config/sys.config.prod —
%% asserting a real handshake completes with EXACTLY these suites proves the
%% production option set is valid and negotiates against an EC (P-256) leaf.
prod_ciphers() ->
    ["ECDHE-ECDSA-AES256-GCM-SHA384",
     "ECDHE-ECDSA-AES128-GCM-SHA256",
     "ECDHE-ECDSA-CHACHA20-POLY1305"].

%% Server ssl opts == exactly what grpcbox_pool:init derives for a TLS listener.
server_ssl_opts(#{leaf := Leaf, key := Key, ca := Ca}) ->
    [{certfile, Leaf}, {keyfile, Key}, {honor_cipher_order, false},
     {cacertfile, Ca}, {fail_if_no_peer_cert, true}, {verify, verify_peer},
     {versions, ['tlsv1.2']}, {ciphers, prod_ciphers()},
     {mode, binary}, {active, false}, {reuseaddr, true}].

%% Client opts == the {https,...} channel SslOpts we ship (version floor + cipher
%% whitelist + verify_peer — verify_peer is required or the client would not
%% verify the server).
client_ssl_opts(#{leaf := Leaf, key := Key, ca := Ca}) ->
    [{certfile, Leaf}, {keyfile, Key}, {cacertfile, Ca},
     {verify, verify_peer}, {versions, ['tlsv1.2']}, {ciphers, prod_ciphers()},
     {server_name_indication, "localhost"}, {mode, binary}, {active, false}].

mutual_handshake_ok(Certs) ->
    {ok, _} = application:ensure_all_started(ssl),
    {ok, LSock} = ssl:listen(0, server_ssl_opts(Certs)),
    {ok, {_, Port}} = ssl:sockname(LSock),
    Parent = self(),
    Acceptor = spawn_link(fun() ->
        {ok, TSock} = ssl:transport_accept(LSock, 5000),
        Parent ! {server_result, ssl:handshake(TSock, 5000)}
    end),
    ClientRes = ssl:connect("localhost", Port, client_ssl_opts(Certs), 5000),
    ServerRes = receive {server_result, R} -> R after 6000 -> {error, server_timeout} end,
    catch ssl:close(LSock),
    catch unlink(Acceptor),
    ?assertMatch({ok, _}, ClientRes),
    ?assertMatch({ok, _}, ServerRes),
    {ok, CSock} = ClientRes,
    catch ssl:close(CSock).

no_client_cert_rejected(Certs) ->
    {ok, _} = application:ensure_all_started(ssl),
    {ok, LSock} = ssl:listen(0, server_ssl_opts(Certs)),
    {ok, {_, Port}} = ssl:sockname(LSock),
    Parent = self(),
    _ = spawn_link(fun() ->
        case ssl:transport_accept(LSock, 5000) of
            {ok, TSock} -> Parent ! {server_result, ssl:handshake(TSock, 5000)};
            Err -> Parent ! {server_result, Err}
        end
    end),
    %% Client presents CA (to verify the server) but NO client cert.
    NoCert = [{cacertfile, maps:get(ca, Certs)}, {verify, verify_peer},
              {versions, ['tlsv1.2']}, {server_name_indication, "localhost"},
              {mode, binary}, {active, false}],
    ClientRes = ssl:connect("localhost", Port, NoCert, 5000),
    ServerRes = receive {server_result, R} -> R after 6000 -> {error, server_timeout} end,
    catch ssl:close(LSock),
    %% The server must refuse: it requires a peer cert. Depending on timing the
    %% rejection surfaces on the client connect OR the server handshake — at
    %% least one side must report an error (never both ok).
    BothOk = (element(1, ClientRes) =:= ok) andalso (element(1, ServerRes) =:= ok),
    ?assertNot(BothOk).

%%%===================================================================
%%% 4. One-way (server-authenticated) TLS — PR5c
%%%   The vendored+patched grpcbox (_checkouts/grpcbox) lets a listener set
%%%   verify_none + fail_if_no_peer_cert=false so an UNENROLLED agent (no client
%%%   cert yet) can bootstrap over an ENCRYPTED, gateway-authenticated channel —
%%%   closing the plaintext agent<->gateway edge without breaking enrollment.
%%%===================================================================

%% Patched grpcbox_pool reads verify/fail_if_no_peer_cert from transport_opts.
oneway_transport_opts_selects_ssl_without_client_cert_test() ->
    {Transport, SslOpts} = pool_transport(#{ssl => true, keyfile => "k", certfile => "c",
                                            cacertfile => "ca", verify => verify_none,
                                            fail_if_no_peer_cert => false}),
    ?assertEqual(ssl, Transport),
    ?assertEqual(verify_none, proplists:get_value(verify, SslOpts)),
    ?assertEqual(false, proplists:get_value(fail_if_no_peer_cert, SslOpts)).

%% Backward-compat: WITHOUT those keys the patch must preserve strict mTLS
%% (the PR5 default) — a missing key must never silently weaken a listener.
default_transport_opts_preserve_strict_mtls_test() ->
    {ssl, SslOpts} = pool_transport(#{ssl => true, keyfile => "k", certfile => "c",
                                      cacertfile => "ca"}),
    ?assertEqual(verify_peer, proplists:get_value(verify, SslOpts)),
    ?assertEqual(true, proplists:get_value(fail_if_no_peer_cert, SslOpts)).

oneway_handshake_test_() ->
    {setup, fun setup_certs/0, fun cleanup_certs/1,
     fun(Certs) ->
        case Certs of
            {error, _} ->
                [{"one-way handshake skipped (openssl unavailable)",
                  fun() -> ?assert(true) end}];
            #{} ->
                [{"unenrolled client (NO cert) connects to a one-way-TLS server",
                  fun() -> oneway_no_client_cert_ok(Certs) end}]
        end
     end}.

%% Server == the grpcbox one-way listener shape (verify_none, no peer-cert required).
oneway_server_ssl_opts(#{leaf := Leaf, key := Key, ca := Ca}) ->
    [{certfile, Leaf}, {keyfile, Key}, {honor_cipher_order, false},
     {cacertfile, Ca}, {fail_if_no_peer_cert, false}, {verify, verify_none},
     {versions, ['tlsv1.2']}, {ciphers, prod_ciphers()},
     {mode, binary}, {active, false}, {reuseaddr, true}].

oneway_no_client_cert_ok(Certs) ->
    {ok, _} = application:ensure_all_started(ssl),
    {ok, LSock} = ssl:listen(0, oneway_server_ssl_opts(Certs)),
    {ok, {_, Port}} = ssl:sockname(LSock),
    Parent = self(),
    _ = spawn_link(fun() ->
        case ssl:transport_accept(LSock, 5000) of
            {ok, TSock} -> Parent ! {server_result, ssl:handshake(TSock, 5000)};
            Err -> Parent ! {server_result, Err}
        end
    end),
    %% The unenrolled-agent bootstrap case: NO client cert, but the client still
    %% verifies the gateway's server cert (one-way / server-authenticated TLS).
    NoCert = [{cacertfile, maps:get(ca, Certs)}, {verify, verify_peer},
              {versions, ['tlsv1.2']}, {ciphers, prod_ciphers()},
              {server_name_indication, "localhost"}, {mode, binary}, {active, false}],
    ClientRes = ssl:connect("localhost", Port, NoCert, 5000),
    ServerRes = receive {server_result, R} -> R after 6000 -> {error, server_timeout} end,
    catch ssl:close(LSock),
    ?assertMatch({ok, _}, ClientRes),
    ?assertMatch({ok, _}, ServerRes),
    {ok, CSock} = ClientRes,
    catch ssl:close(CSock).

%%%-------------------------------------------------------------------
%%% Cert generation (EC P-384 CA, EC P-256 leaf serverAuth+clientAuth)
%%%-------------------------------------------------------------------

setup_certs() ->
    %% Crypto-random suffix + 0700 mode: /tmp is world-writable, so a predictable
    %% name invites a pre-create race under parallel test runs.
    Rand = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(12))),
    Dir = filename:join(["/tmp", "yuzu_gw_mtls_" ++ Rand]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    _ = file:change_mode(Dir, 8#700),
    Ca   = filename:join(Dir, "ca.pem"),
    CaK  = filename:join(Dir, "ca.key"),
    Leaf = filename:join(Dir, "gw.pem"),
    LeafK = filename:join(Dir, "gw.key"),
    Csr  = filename:join(Dir, "gw.csr"),
    Ext  = filename:join(Dir, "gw.ext"),
    ok = file:write_file(Ext,
        <<"subjectAltName=DNS:localhost,IP:127.0.0.1\n"
          "extendedKeyUsage=serverAuth,clientAuth\n"
          "basicConstraints=CA:FALSE\n">>),
    Cmds = [
        % P-384 self-signed CA
        ["openssl ecparam -name secp384r1 -genkey -noout -out ", q(CaK)],
        ["openssl req -x509 -new -key ", q(CaK), " -sha384 -days 1 ",
         "-subj /CN=Yuzu-Test-CA ",
         "-addext basicConstraints=critical,CA:TRUE ",
         "-addext keyUsage=critical,keyCertSign,cRLSign ",
         "-out ", q(Ca)],
        % P-256 leaf with both EKUs (mirrors default-gateway)
        ["openssl ecparam -name prime256v1 -genkey -noout -out ", q(LeafK)],
        ["openssl req -new -key ", q(LeafK), " -subj /CN=localhost -out ", q(Csr)],
        ["openssl x509 -req -in ", q(Csr), " -CA ", q(Ca), " -CAkey ", q(CaK),
         " -CAcreateserial -days 1 -sha256 -extfile ", q(Ext), " -out ", q(Leaf)]
    ],
    case run_all(Cmds) of
        ok ->
            case filelib:is_regular(Leaf) andalso filelib:is_regular(Ca) of
                true  -> #{dir => Dir, ca => Ca, leaf => Leaf, key => LeafK};
                false -> {error, {certs_not_written, Dir}}
            end;
        {error, _} = E ->
            E
    end.

cleanup_certs(#{dir := Dir}) -> os:cmd("rm -rf " ++ q(Dir)), ok;
cleanup_certs(_) -> ok.

q(S) -> "'" ++ S ++ "'".

run_all([]) -> ok;
run_all([Cmd | Rest]) ->
    Flat = lists:flatten(Cmd) ++ " 2>&1",
    Out = os:cmd(Flat),
    %% openssl prints nothing on success for keygen; req/x509 may print status.
    %% Detect hard failures by checking the expected output file existence in
    %% the caller — here we only bail if openssl is entirely absent.
    case string:find(Out, "not found") of
        nomatch -> run_all(Rest);
        _ -> {error, {openssl_missing, Out}}
    end.

%%%-------------------------------------------------------------------
%%% Mgmt-listener boot-guard policy (#1422) — evaluate_mgmt_posture/3
%%%-------------------------------------------------------------------

-define(PIN_FUN, fun yuzu_gw_authz:check_mgmt_peer/1).

secure_mgmt() ->
    #{grpc_opts => #{service_protos => [management_pb],
                     services => #{},
                     auth_fun => ?PIN_FUN},
      listen_opts => #{port => 50063, ip => {0, 0, 0, 0}},
      transport_opts => #{ssl => true, certfile => "c.pem", keyfile => "k.pem",
                          cacertfile => "ca.pem"}}.

pins() -> [{cert_file, "srv.pem"}].

with_transport(Fun) ->
    S = secure_mgmt(),
    S#{transport_opts := Fun(maps:get(transport_opts, S))}.

mgmt_posture_secure_ok_test() ->
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([secure_mgmt()], pins(), false)).

mgmt_posture_loopback_exempt_test() ->
    %% Loopback (v4 and v6) plaintext mgmt is the dev posture — no network
    %% attack surface, boots without the hatch.
    Plain = fun(Ip) ->
        #{grpc_opts => #{service_protos => [management_pb], services => #{}},
          listen_opts => #{port => 50063, ip => Ip}}
    end,
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([Plain({127, 0, 0, 1})], [], false)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(
                       [Plain({0, 0, 0, 0, 0, 0, 0, 1})], [], false)).

mgmt_posture_wildcard_plaintext_refused_test() ->
    Plain = #{grpc_opts => #{service_protos => [management_pb], services => #{}},
              listen_opts => #{port => 50063, ip => {0, 0, 0, 0}}},
    {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
        yuzu_gw_app:evaluate_mgmt_posture([Plain], [], false),
    ?assert(lists:member(plaintext, Defects)).

mgmt_posture_missing_ip_is_exposed_test() ->
    %% grpcbox defaults a missing ip to {0,0,0,0} — the guard must too.
    Plain = #{grpc_opts => #{service_protos => [management_pb], services => #{}},
              listen_opts => #{port => 50063}},
    ?assertMatch({error, {insecure_mgmt_listener, _}},
                 yuzu_gw_app:evaluate_mgmt_posture([Plain], [], false)).

mgmt_posture_escape_hatch_boots_with_warning_result_test() ->
    Plain = #{grpc_opts => #{service_protos => [management_pb], services => #{}},
              listen_opts => #{port => 50063, ip => {0, 0, 0, 0}}},
    ?assertMatch({ok_insecure, [{50063, _}]},
                 yuzu_gw_app:evaluate_mgmt_posture([Plain], [], true)).

mgmt_posture_tcp_fallback_refused_test() ->
    %% ssl => true WITHOUT full cert material: grpcbox_pool silently serves
    %% plaintext TCP — must be refused, not treated as TLS.
    S = with_transport(fun(T) -> maps:remove(cacertfile, T) end),
    {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
        yuzu_gw_app:evaluate_mgmt_posture([S], pins(), false),
    ?assert(lists:member(missing_cert_material, Defects)).

mgmt_posture_verify_none_refused_test() ->
    %% TLS + verify_none would hand the auth_fun a SELF-SIGNED cert — the
    %% CA gate must stay in front of the pin.
    S = with_transport(fun(T) -> T#{verify => verify_none} end),
    {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
        yuzu_gw_app:evaluate_mgmt_posture([S], pins(), false),
    ?assert(lists:member(verify_not_peer, Defects)).

mgmt_posture_optional_peer_cert_refused_test() ->
    %% fail_if_no_peer_cert=false: a certless peer skips the auth_fun
    %% entirely (grpcbox only authenticates a PRESENTED cert).
    S = with_transport(fun(T) -> T#{fail_if_no_peer_cert => false} end),
    {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
        yuzu_gw_app:evaluate_mgmt_posture([S], pins(), false),
    ?assert(lists:member(peer_cert_not_required, Defects)).

mgmt_posture_wrong_auth_fun_refused_test() ->
    S0 = secure_mgmt(),
    Grpc = maps:get(grpc_opts, S0),
    Wrong = S0#{grpc_opts := Grpc#{auth_fun := fun erlang:is_binary/1}},
    Missing = S0#{grpc_opts := maps:remove(auth_fun, Grpc)},
    lists:foreach(fun(S) ->
        {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
            yuzu_gw_app:evaluate_mgmt_posture([S], pins(), false),
        ?assert(lists:member(missing_or_wrong_auth_fun, Defects))
    end, [Wrong, Missing]).

mgmt_posture_empty_pins_refused_test() ->
    {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
        yuzu_gw_app:evaluate_mgmt_posture([secure_mgmt()], [], false),
    ?assert(lists:member(no_mgmt_peer_pins, Defects)).

mgmt_posture_non_mgmt_listener_ignored_test() ->
    %% The wildcard one-way-TLS agent listener (verify_none, no auth_fun) is
    %% NOT a mgmt listener — the guard must not refuse it.
    Agent = #{grpc_opts => #{service_protos => [agent_pb], services => #{}},
              listen_opts => #{port => 50051, ip => {0, 0, 0, 0}},
              transport_opts => #{ssl => true, certfile => "c", keyfile => "k",
                                  cacertfile => "ca", verify => verify_none,
                                  fail_if_no_peer_cert => false}},
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([Agent], [], false)).

mgmt_posture_malformed_entries_tolerated_test() ->
    %% Non-map junk in the servers list can't be proven to expose the mgmt
    %% proto — the guard skips it (the tls-trap logger covers misconfig).
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([not_a_map, []], [], false)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(undefined, [], false)).

mgmt_posture_proplist_transport_refused_test() ->
    %% A PROPLIST transport_opts with {ssl,true} + full material is the
    %% is_tls_trap shape: grpcbox only enables TLS on the MAP form, so this
    %% listener serves plaintext TCP — the guard must refuse it, not read
    %% the proplist as TLS.
    S = (secure_mgmt())#{transport_opts := [{ssl, true}, {certfile, "c.pem"},
                                            {keyfile, "k.pem"},
                                            {cacertfile, "ca.pem"}]},
    {error, {insecure_mgmt_listener, [{50063, Defects}]}} =
        yuzu_gw_app:evaluate_mgmt_posture([S], pins(), false),
    ?assert(lists:member(plaintext, Defects)).

mgmt_posture_fd_socket_forfeits_loopback_exemption_test_() ->
    %% PR #3905 review blocking finding: grpcbox DELETES the map ip whenever
    %% socket_options carries an inherited {fd, _} (systemd socket
    %% activation) and binds wherever the descriptor points — so a nominal
    %% loopback ip is a dead letter and must NOT exempt the listener. An
    %% {ip, _} inside socket_options likewise overrides (later inet option
    %% wins). An unrecognised socket_options shape is unprovable — exposed.
    Plain = fun(SockOpts) ->
        #{grpc_opts => #{service_protos => [management_pb], services => #{}},
          listen_opts => maps:merge(#{port => 50063, ip => {127, 0, 0, 1}},
                                    SockOpts)}
    end,
    [{"loopback ip + {fd,_} socket option refused",
      ?_assertMatch({error, {insecure_mgmt_listener, [{50063, _}]}},
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_options => [{fd, 42}]})], [], false))},
     {"loopback ip + overriding {ip,_} socket option refused",
      ?_assertMatch({error, {insecure_mgmt_listener, [{50063, _}]}},
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_options => [{ip, {0, 0, 0, 0}}]})], [], false))},
     {"loopback ip + unrecognised socket_options shape refused",
      ?_assertMatch({error, {insecure_mgmt_listener, [{50063, _}]}},
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_options => junk})], [], false))},
     {"loopback ip + benign socket_options list stays exempt",
      ?_assertEqual(ok,
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [Plain(#{socket_options => [{reuseaddr, true}]})], [], false))},
     {"secure posture with {fd,_} still passes (exemption lost, posture holds)",
      ?_assertEqual(ok,
                    yuzu_gw_app:evaluate_mgmt_posture(
                        [#{grpc_opts => #{service_protos => [management_pb],
                                          services => #{},
                                          auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1},
                           listen_opts => #{port => 50063, ip => {127, 0, 0, 1},
                                            socket_options => [{fd, 42}]},
                           transport_opts => #{ssl => true, certfile => "c.pem",
                                               keyfile => "k.pem",
                                               cacertfile => "ca.pem"}}],
                        [{cert_file, "srv.pem"}], false))}].
