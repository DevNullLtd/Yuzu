%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_authz — the mgmt-plane SPKI peer pin (#1422).
%%%
%%% Mints a throwaway CA + leaves with openssl (same pattern and tool
%%% dependency as yuzu_gw_mtls_tests) shaped like the real
%%% default_certs.cpp / sign_agent_csr output:
%%%   srv      CN="Yuzu Default server",  EKU serverAuth,clientAuth
%%%   gw       CN="Yuzu Default gateway", EKU serverAuth,clientAuth (own key)
%%%   agent    CN=agent-123,              EKU clientAuth, agent URI SAN
%%%   collide  CN="Yuzu Default server",  EKU clientAuth  — the enrollment
%%%            CN-collision bypass an earlier CN-allowlist design admitted;
%%%            this MUST stay rejected (regression pin for the #1422 fix)
%%%   selfs    self-signed, CN="Yuzu Default server", EKU serverAuth
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_authz_tests).
-include_lib("eunit/include/eunit.hrl").

%% cert-mint helpers shared with yuzu_gw_authz_rpc_tests
-export([setup_certs/0, cleanup_certs/1, der/2]).

%%%-------------------------------------------------------------------
%%% Fixture
%%%-------------------------------------------------------------------

authz_test_() ->
    {setup,
     fun setup_certs/0,
     fun cleanup_certs/1,
     fun(Certs) ->
        case Certs of
            #{} ->
                [{"srv leaf accepted via cert_file pin",
                  fun() -> accept_cert_file_pin(Certs) end},
                 {"srv leaf accepted via spki_sha256 hex pin",
                  fun() -> accept_hex_pin(Certs) end},
                 {"spki hash matches openssl's own SPKI digest",
                  fun() -> spki_matches_openssl(Certs) end},
                 {"agent leaf rejected (no serverAuth EKU, wrong key)",
                  fun() -> reject_agent_leaf(Certs) end},
                 {"REGRESSION: agent leaf with CN='Yuzu Default server' rejected",
                  fun() -> reject_cn_collision(Certs) end},
                 {"gateway leaf rejected (serverAuth EKU but wrong key)",
                  fun() -> reject_gateway_leaf(Certs) end},
                 {"self-signed cert with pinned-looking subject rejected",
                  fun() -> reject_self_signed(Certs) end},
                 {"empty pin list rejects (fail closed)",
                  fun() -> reject_empty_pins(Certs) end},
                 {"garbage DER rejected",
                  fun() -> reject_garbage_der() end},
                 {"malformed pins are skipped; all-malformed rejects",
                  fun() -> malformed_pins(Certs) end},
                 {"two-pin rotation overlap: both keys accepted",
                  fun() -> rotation_overlap(Certs) end},
                 {"cert_file pin re-reads after the file changes",
                  fun() -> file_pin_rotation(Certs) end},
                 {"check_mgmt_peer reads pins from app env",
                  fun() -> app_env_entry_point(Certs) end}];
            _ ->
                %% openssl unavailable / mint failed — same skip posture as
                %% yuzu_gw_mtls_tests (openssl is present on every CI leg
                %% that runs the gateway suite).
                []
        end
     end}.

%%%-------------------------------------------------------------------
%%% Cases
%%%-------------------------------------------------------------------

accept_cert_file_pin(#{srv_pem := SrvPem} = Certs) ->
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(der(Certs, srv_pem),
                                          [{cert_file, SrvPem}])).

accept_hex_pin(Certs) ->
    Der = der(Certs, srv_pem),
    {ok, Spki} = yuzu_gw_authz:spki_sha256(Der),
    Hex = binary_to_list(binary:encode_hex(Spki)),
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(Der, [{spki_sha256, Hex}])),
    %% lowercase hex must work too (operators will paste openssl output)
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(Der, [{spki_sha256, string:lowercase(Hex)}])).

%% Empirically validates the plain-decode → der_encode SPKI round trip
%% against openssl's own extraction of the same certificate's public key.
spki_matches_openssl(#{srv_pem := SrvPem} = Certs) ->
    {ok, Spki} = yuzu_gw_authz:spki_sha256(der(Certs, srv_pem)),
    Out = os:cmd("openssl x509 -in '" ++ SrvPem ++ "' -pubkey -noout"
                 " | openssl pkey -pubin -outform DER"
                 " | openssl dgst -sha256 -hex"),
    %% output shape: "SHA2-256(stdin)= <hex>\n" (tool-version dependent
    %% prefix) — take the last whitespace-separated token.
    OpensslHex = lists:last(string:lexemes(string:trim(Out), " =\n")),
    ?assertEqual(string:lowercase(binary_to_list(binary:encode_hex(Spki))),
                 string:lowercase(OpensslHex)).

reject_agent_leaf(#{srv_pem := SrvPem} = Certs) ->
    ?assertEqual(false,
                 yuzu_gw_authz:check_peer(der(Certs, agent_pem),
                                          [{cert_file, SrvPem}])),
    %% and specifically: no serverAuth EKU
    ?assertNot(yuzu_gw_authz:has_server_auth_eku(der(Certs, agent_pem))).

reject_cn_collision(#{srv_pem := SrvPem} = Certs) ->
    %% The bypass a CN allowlist admits: a CA-issued AGENT leaf whose CN
    %% is exactly the server's ("--agent-id 'Yuzu Default server'"). The
    %% SPKI pin must reject it — the attacker never holds the server key.
    ?assertEqual(false,
                 yuzu_gw_authz:check_peer(der(Certs, collide_pem),
                                          [{cert_file, SrvPem}])).

reject_gateway_leaf(#{srv_pem := SrvPem} = Certs) ->
    %% default-gateway carries serverAuth+clientAuth AND its key is
    %% group-readable in the shared cert volume — EKU alone must not admit
    %% it; the key pin must.
    Der = der(Certs, gw_pem),
    ?assert(yuzu_gw_authz:has_server_auth_eku(Der)),
    ?assertEqual(false,
                 yuzu_gw_authz:check_peer(Der, [{cert_file, SrvPem}])).

reject_self_signed(#{srv_pem := SrvPem} = Certs) ->
    ?assertEqual(false,
                 yuzu_gw_authz:check_peer(der(Certs, selfs_pem),
                                          [{cert_file, SrvPem}])).

reject_empty_pins(Certs) ->
    ?assertEqual(false, yuzu_gw_authz:check_peer(der(Certs, srv_pem), [])).

reject_garbage_der() ->
    ?assertEqual(false, yuzu_gw_authz:check_peer(<<1, 2, 3, 4>>,
                                                 [{spki_sha256, lists:duplicate(64, $a)}])),
    ?assertEqual(false, yuzu_gw_authz:check_peer(not_a_binary,
                                                 [{spki_sha256, lists:duplicate(64, $a)}])).

malformed_pins(#{srv_pem := SrvPem} = Certs) ->
    Der = der(Certs, srv_pem),
    %% all malformed / unreadable → fail closed
    ?assertEqual(false,
                 yuzu_gw_authz:check_peer(Der,
                     [{spki_sha256, "zz"}, {cert_file, "/nonexistent/x.pem"}, bogus])),
    %% one malformed + one good → good pin still admits
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(Der,
                     [{spki_sha256, "zz"}, {cert_file, SrvPem}])).

rotation_overlap(#{srv_pem := SrvPem} = Certs) ->
    %% Overlap window: old pin (hex of gw key, standing in for the outgoing
    %% leaf) + new pin (srv cert file) — a peer matching EITHER is admitted.
    {ok, GwSpki} = yuzu_gw_authz:spki_sha256(der(Certs, gw_pem)),
    Pins = [{spki_sha256, binary_to_list(binary:encode_hex(GwSpki))},
            {cert_file, SrvPem}],
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(der(Certs, srv_pem), Pins)),
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(der(Certs, gw_pem), Pins)).

file_pin_rotation(#{dir := Dir, srv_pem := SrvPem, gw_pem := GwPem} = Certs) ->
    %% Pin path starts as a copy of srv; after the file is replaced (new
    %% mtime), the pin must follow the NEW cert without a process restart.
    Rotating = filename:join(Dir, "rotating.pem"),
    {ok, _} = file:copy(SrvPem, Rotating),
    ok = file:change_time(Rotating, {{2020, 1, 1}, {0, 0, 0}}),
    Pins = [{cert_file, Rotating}],
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(der(Certs, srv_pem), Pins)),
    {ok, _} = file:copy(GwPem, Rotating),
    ok = file:change_time(Rotating, {{2021, 1, 1}, {0, 0, 0}}),
    ?assertEqual({true, <<"yuzu-server">>},
                 yuzu_gw_authz:check_peer(der(Certs, gw_pem), Pins)),
    ?assertEqual(false,
                 yuzu_gw_authz:check_peer(der(Certs, srv_pem), Pins)).

app_env_entry_point(#{srv_pem := SrvPem} = Certs) ->
    Prev = application:get_env(yuzu_gw, mgmt_peer_pins),
    try
        application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
        ?assertEqual({true, <<"yuzu-server">>},
                     yuzu_gw_authz:check_mgmt_peer(der(Certs, srv_pem))),
        application:unset_env(yuzu_gw, mgmt_peer_pins),
        ?assertEqual(false,
                     yuzu_gw_authz:check_mgmt_peer(der(Certs, srv_pem)))
    after
        case Prev of
            {ok, V}   -> application:set_env(yuzu_gw, mgmt_peer_pins, V);
            undefined -> application:unset_env(yuzu_gw, mgmt_peer_pins)
        end
    end.

%%%-------------------------------------------------------------------
%%% Cert minting (openssl CLI — mirrors yuzu_gw_mtls_tests)
%%%-------------------------------------------------------------------

setup_certs() ->
    Rand = binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(12))),
    Dir = filename:join(["/tmp", "yuzu_gw_authz_" ++ Rand]),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    _ = file:change_mode(Dir, 8#700),
    CaK = filename:join(Dir, "ca.key"),
    Ca  = filename:join(Dir, "ca.pem"),
    SrvExt = ext_file(Dir, "srv.ext",
        <<"subjectAltName=DNS:localhost,IP:127.0.0.1\n"
          "extendedKeyUsage=serverAuth,clientAuth\n"
          "basicConstraints=CA:FALSE\n">>),
    AgentExt = ext_file(Dir, "agent.ext",
        <<"subjectAltName=URI:yuzu://cafp/agent/agent-123\n"
          "extendedKeyUsage=clientAuth\n"
          "basicConstraints=CA:FALSE\n">>),
    Cmds =
        [["openssl ecparam -name secp384r1 -genkey -noout -out ", q(CaK)],
         ["openssl req -x509 -new -key ", q(CaK), " -sha384 -days 1 ",
          "-subj /CN=Yuzu-Test-CA ",
          "-addext basicConstraints=critical,CA:TRUE ",
          "-addext keyUsage=critical,keyCertSign,cRLSign ",
          "-out ", q(Ca)]]
        ++ leaf_cmds(Dir, "srv", "'/O=Yuzu/CN=Yuzu Default server'", SrvExt, Ca, CaK)
        ++ leaf_cmds(Dir, "gw", "'/O=Yuzu/CN=Yuzu Default gateway'", SrvExt, Ca, CaK)
        ++ leaf_cmds(Dir, "agent", "'/O=Yuzu/CN=agent-123'", AgentExt, Ca, CaK)
        ++ leaf_cmds(Dir, "collide", "'/O=Yuzu/CN=Yuzu Default server'", AgentExt, Ca, CaK)
        %% self-signed: not CA-issued at all (`req -x509` takes -addext, not -extfile)
        ++ [["openssl ecparam -name prime256v1 -genkey -noout -out ",
             q(filename:join(Dir, "selfs.key"))],
            ["openssl req -x509 -new -key ", q(filename:join(Dir, "selfs.key")),
             " -sha256 -days 1 -subj '/O=Yuzu/CN=Yuzu Default server' ",
             "-addext extendedKeyUsage=serverAuth -addext basicConstraints=CA:FALSE ",
             "-out ", q(filename:join(Dir, "selfs.pem"))]],
    Out = #{dir => Dir,
            ca => Ca,
            srv_pem => filename:join(Dir, "srv.pem"),
            gw_pem => filename:join(Dir, "gw.pem"),
            agent_pem => filename:join(Dir, "agent.pem"),
            collide_pem => filename:join(Dir, "collide.pem"),
            selfs_pem => filename:join(Dir, "selfs.pem")},
    case run_all(Cmds) of
        ok ->
            %% openssl mostly succeeds silently — verify the artifacts exist
            %% (same detection strategy as yuzu_gw_mtls_tests).
            Pems = [P || {K, P} <- maps:to_list(Out), K =/= dir],
            case lists:all(fun filelib:is_regular/1, Pems) of
                true  -> Out;
                false -> {error, {certs_not_written, Dir}}
            end;
        {error, _} = E ->
            E
    end.

leaf_cmds(Dir, Name, Subj, Ext, Ca, CaK) ->
    Key = filename:join(Dir, Name ++ ".key"),
    Csr = filename:join(Dir, Name ++ ".csr"),
    Pem = filename:join(Dir, Name ++ ".pem"),
    [["openssl ecparam -name prime256v1 -genkey -noout -out ", q(Key)],
     ["openssl req -new -key ", q(Key), " -subj ", Subj, " -out ", q(Csr)],
     ["openssl x509 -req -in ", q(Csr), " -CA ", q(Ca), " -CAkey ", q(CaK),
      " -CAcreateserial -days 1 -sha256 -extfile ", q(Ext), " -out ", q(Pem)]].

ext_file(Dir, Name, Content) ->
    Path = filename:join(Dir, Name),
    ok = file:write_file(Path, Content),
    Path.

cleanup_certs(#{dir := Dir}) -> os:cmd("rm -rf '" ++ Dir ++ "'"), ok;
cleanup_certs(_) -> ok.

q(S) -> "'" ++ S ++ "'".

run_all([]) -> ok;
run_all([Cmd | Rest]) ->
    Flat = lists:flatten(Cmd) ++ " 2>&1",
    Out = os:cmd(Flat),
    %% openssl prints status noise on success; hard failure is detected by
    %% the artifact-existence check in setup_certs (mirrors yuzu_gw_mtls_tests)
    %% — here we only bail if openssl is entirely absent.
    case string:find(Out, "not found") of
        nomatch -> run_all(Rest);
        _ -> {error, {openssl_missing, Out}}
    end.

%% @private DER of the (first) certificate in the named PEM.
der(Certs, Which) ->
    {ok, Pem} = file:read_file(maps:get(Which, Certs)),
    [{'Certificate', Der, not_encrypted} | _] = public_key:pem_decode(Pem),
    Der.

%%%-------------------------------------------------------------------
%%% Toolchain canary + telemetry wiring (Gate 7 additions)
%%%-------------------------------------------------------------------

%% The cert-minting fixtures above SKIP (emit zero tests) when openssl is
%% absent — which would silently drop the CN-collision, EKU and pin
%% regression nets on a CI leg with a broken toolchain. This canary makes
%% that state loud: every leg that runs gateway eunit is expected to carry
%% openssl (Linux + Windows/MSYS2 both do).
openssl_available_canary_test() ->
    ?assertNotEqual(false, os:find_executable("openssl")).

%% gw-S1 regression: a badarg-class {spki_sha256, ...} entry (codepoints
%% > 255 — a pasted Unicode lookalike) must be SKIPPED like any other
%% malformed pin, never abort the pin walk and reject every peer.
badarg_class_pin_is_skipped_test_() ->
    {setup, fun setup_certs/0, fun cleanup_certs/1,
     fun(Certs) ->
        case Certs of
            #{srv_pem := SrvPem} ->
                [{"unicode-junk pin skipped; valid co-pin still admits",
                  fun() ->
                      Der = der(Certs, srv_pem),
                      Pins = [{spki_sha256, [16#2010 | lists:duplicate(63, $a)]},
                              {cert_file, SrvPem}],
                      ?assertEqual({true, <<"yuzu-server">>},
                                   yuzu_gw_authz:check_peer(Der, Pins)),
                      %% and alone it fails CLOSED, not internal_error-open
                      ?assertEqual(false,
                                   yuzu_gw_authz:check_peer(
                                       Der, [{spki_sha256,
                                              [16#2010 | lists:duplicate(63, $a)]}]))
                  end}];
            _ -> []
        end
     end}.

%% sec-M1 closure evidence: every reject reason increments the Prometheus
%% counter through the REAL yuzu_gw_telemetry handler (event name, ?EVENTS
%% registration, handler clause, and metric declaration all exercised), and
%% an unresolved configured pin bumps the pin_unresolved counter.
telemetry_counter_test_() ->
    {setup,
     fun() ->
        {ok, Started} = application:ensure_all_started(prometheus),
        {ok, Started2} = application:ensure_all_started(telemetry),
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup(),
        Certs = setup_certs(),
        {Certs, Started ++ Started2}
     end,
     fun({Certs, _}) ->
        catch telemetry:detach(yuzu_gw_prometheus),
        cleanup_certs(Certs)
     end,
     fun({Certs, _}) ->
        case Certs of
            #{srv_pem := SrvPem} ->
                [{"each reject reason lands on the counter with its label",
                  fun() ->
                      Der = der(Certs, srv_pem),
                      Cases =
                          [{<<"no_pins_configured">>,
                            fun() -> yuzu_gw_authz:check_peer(Der, []) end},
                           {<<"pin_mismatch">>,
                            fun() -> yuzu_gw_authz:check_peer(
                                         der(Certs, gw_pem), [{cert_file, SrvPem}]) end},
                           {<<"missing_server_auth_eku">>,
                            fun() -> yuzu_gw_authz:check_peer(
                                         der(Certs, agent_pem), [{cert_file, SrvPem}]) end},
                           {<<"bad_peer_cert">>,
                            fun() -> yuzu_gw_authz:check_peer(
                                         <<1, 2, 3>>, [{cert_file, SrvPem}]) end},
                           {<<"no_pins_resolved">>,
                            fun() -> yuzu_gw_authz:check_peer(
                                         Der, [{cert_file, "/nonexistent.pem"}]) end},
                           {<<"bad_pin_config">>,
                            fun() -> yuzu_gw_authz:check_peer(Der, not_a_list) end}],
                      lists:foreach(fun({Label, Fire}) ->
                          Before = counter_val(yuzu_gw_mgmt_auth_rejected_total, [Label]),
                          ?assertEqual(false, Fire()),
                          ?assertEqual(Before + 1,
                                       counter_val(yuzu_gw_mgmt_auth_rejected_total,
                                                   [Label]))
                      end, Cases)
                  end},
                 {"unresolved configured pin bumps pin_unresolved",
                  fun() ->
                      Der = der(Certs, srv_pem),
                      Before = counter_val(yuzu_gw_mgmt_auth_pin_unresolved_total, []),
                      ?assertEqual({true, <<"yuzu-server">>},
                                   yuzu_gw_authz:check_peer(
                                       Der, [{spki_sha256, "zz"},
                                             {cert_file, SrvPem}])),
                      ?assertEqual(Before + 1,
                                   counter_val(yuzu_gw_mgmt_auth_pin_unresolved_total,
                                               []))
                  end}];
            _ -> []
        end
     end}.

counter_val(Name, Labels) ->
    case prometheus_counter:value(Name, Labels) of
        undefined -> 0;
        V -> V
    end.
