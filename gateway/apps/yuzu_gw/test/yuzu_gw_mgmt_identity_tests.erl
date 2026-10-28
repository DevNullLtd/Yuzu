%%%-------------------------------------------------------------------
%%% @doc Tests for the management-plane server identity and the serial
%%% deny-list (#6016): yuzu_gw_mgmt_identity (resolution) and the identity /
%%% deny-list paths of yuzu_gw_authz:check_peer/3.
%%%
%%% The certificates are minted with openssl under a throwaway CA, shaped like
%%% the C++ server's output (default_certs.cpp): the server leaf carries
%%% `URI:yuzu://<CA fingerprint>/server', an agent leaf only
%%% `URI:yuzu://<CA fingerprint>/agent/<id>' and a clientAuth EKU, the gateway
%%% leaf no URI. Where openssl is unavailable the certificate cases are skipped
%%% the way the other TLS suites skip (yuzu_gw_authz_tests:certs_unavailable/2).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_identity_tests).
-include_lib("eunit/include/eunit.hrl").

-export([capture/4]).

-define(SERVER_ID, <<"yuzu-server">>).

%%%-------------------------------------------------------------------
%%% Resolution (no certificates)
%%%-------------------------------------------------------------------

validate_identity_test_() ->
    Ok = fun(V) -> ?assertMatch({ok, _}, yuzu_gw_mgmt_identity:validate_identity(V)) end,
    Bad = fun(V) -> ?assertEqual(error, yuzu_gw_mgmt_identity:validate_identity(V)) end,
    [{"the exact form, as a string and as a binary",
      fun() ->
          Ok("yuzu://ABC123/server"),
          Ok(<<"yuzu://ABC123/server">>),
          Ok(<<"yuzu://abc.1_2~3-x/server">>)
      end},
     {"nothing else is an identity",
      fun() ->
          [Bad(V) || V <- [<<"yuzu://ABC123/agent/a1">>, <<"yuzu://ABC123/server/">>,
                           <<"yuzu://ABC123/Server">>, <<"yuzu://ABC123/servers">>,
                           <<"yuzu://ABC123/server/extra">>, <<"yuzu://ABC123/server%00">>,
                           <<"https://ABC123/server">>, <<"YUZU://ABC123/server">>,
                           <<"yuzu:///server">>, <<"yuzu://AB C/server">>,
                           <<"yuzu://AB/C/server">>, <<" yuzu://ABC/server">>,
                           <<"yuzu://ABC/server ">>, <<"">>, <<"server">>,
                           %% PCRE's `$' would let a trailing newline through
                           <<"yuzu://ABC123/server\n">>, <<"yuzu://ABC123/server\r\n">>,
                           list_to_binary(["yuzu://", lists:duplicate(129, $A), "/server"])]],
          Bad([16#20AC]),
          Bad(an_atom),
          Bad(42)
      end}].

validate_denied_test_() ->
    [{"serials are hex of any case, 1 to 40 digits, sorted and deduplicated",
      fun() ->
          ?assertEqual({ok, [1, 255, 4096]},
                       yuzu_gw_mgmt_identity:validate_denied(
                         [{serial, "0FF"}, {serial, <<"ff">>}, {serial, "1000"},
                          {serial, <<"01">>}])),
          ?assertEqual({ok, []}, yuzu_gw_mgmt_identity:validate_denied([])),
          ?assertEqual({ok, [(1 bsl 160) - 1]},
                       yuzu_gw_mgmt_identity:validate_denied(
                         [{serial, lists:duplicate(40, $F)}]))
      end},
     {"every malformed entry is reported, none is dropped",
      fun() ->
          {error, Defects} = yuzu_gw_mgmt_identity:validate_denied(
                               [{serial, "ZZ"}, {serial, ""}, {serial, "0x1F"},
                                {serial, "1F\n"}, {serial, "1:F"},
                                {serial, lists:duplicate(41, $1)},
                                {spki_sha256, lists:duplicate(64, $a)},
                                {serial, [16#20AC]}, bare, {serial, "1F"}]),
          ?assertEqual(9, length(Defects)),
          ?assert(lists:all(fun({bad_mgmt_peer_denied, _}) -> true; (_) -> false end,
                            Defects))
      end},
     {"a deny entry for a key is refused: the key is shared with the replacement",
      fun() ->
          ?assertMatch({error, [{bad_mgmt_peer_denied, _}]},
                       yuzu_gw_mgmt_identity:validate_denied(
                         [{spki_sha256, lists:duplicate(64, $a)}]))
      end},
     {"not a list, and too many entries",
      fun() ->
          ?assertMatch({error, [{bad_mgmt_peer_denied, _}]},
                       yuzu_gw_mgmt_identity:validate_denied(not_a_list)),
          ?assertMatch({error, [{bad_mgmt_peer_denied, {too_many_entries, 4097}}]},
                       yuzu_gw_mgmt_identity:validate_denied(
                         lists:duplicate(4097, {serial, "1"})))
      end}].

%% A per-call directory, salted with random bytes (CI runners share one OS identity,
%% and a per-VM counter repeats across concurrent VMs).
yuzu_test_dir() ->
    Salt = binary:encode_hex(crypto:strong_rand_bytes(12), lowercase),
    Dir = filename:join(filename:basedir(user_cache, "yuzu_test_mgmt_identity"), Salt),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

yuzu_test_dir_cleanup(Dir) ->
    _ = file:del_dir_r(Dir),
    _ = file:del_dir(filename:dirname(Dir)),   % the parent, only if now empty
    ok.

resolve_test_() ->
    Pins = [{spki_sha256, lists:duplicate(64, $a)}],
    Mgmt = fun(Ca) -> #{name => mgmt, service_protos => [management_pb],
                        tls => #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => Ca}}
           end,
    [{"unset mode is ALWAYS the pin mode: the identity is an explicit opt-in",
      fun() ->
          Pin = {ok, #{mode => pin, identity => undefined, denied => []}},
          ?assertEqual(Pin, yuzu_gw_mgmt_identity:resolve(undefined, undefined, [], [], Pins)),
          %% no pins used to mean the identity mode (a boot that admitted by a derived
          %% identity); it must stay the pin mode so the boot guard refuses it
          ?assertEqual(Pin, yuzu_gw_mgmt_identity:resolve(undefined, undefined, [], [], [])),
          %% ...even with an explicit identity and a listener it could be derived from
          ?assertEqual(Pin, yuzu_gw_mgmt_identity:resolve(
                              undefined, "yuzu://X/server", [],
                              [Mgmt("/no/such/ca.pem")], []))
      end},
     {"an improper deny list is a defect, not a crash",
      fun() ->
          ?assertMatch({error, [{bad_mgmt_peer_denied, _}]},
                       yuzu_gw_mgmt_identity:validate_denied([{serial, "1"} | bad])),
          ?assertMatch({error, [{bad_mgmt_peer_denied, _}]},
                       yuzu_gw_mgmt_identity:resolve(pin, undefined, [{serial, "1"} | bad], [], Pins)),
          %% a binary with a trailing newline is not hex either
          ?assertMatch({error, [{bad_mgmt_peer_denied, _}]},
                       yuzu_gw_mgmt_identity:validate_denied([{serial, <<"1F\n">>}]))
      end},
     {"pin mode reads no file and ignores a configured identity",
      fun() ->
          ?assertEqual({ok, #{mode => pin, identity => undefined, denied => []}},
                       yuzu_gw_mgmt_identity:resolve(pin, "yuzu://X/server", [],
                                                     [Mgmt("/no/such/ca.pem")], Pins))
      end},
     {"an explicit identity wins over the derivation and is exact",
      fun() ->
          ?assertEqual({ok, #{mode => identity, identity => <<"yuzu://X/server">>,
                              denied => [255]}},
                       yuzu_gw_mgmt_identity:resolve(identity, "yuzu://X/server",
                                                     [{serial, "FF"}],
                                                     [Mgmt("/no/such/ca.pem")], Pins))
      end},
     {"an identity over a CA file that is not demonstrably ONE certificate needs mode identity AND a pin",
      fun() ->
          %% unreadable, empty and half-written files count as a bundle: the listener
          %% reads the file again when it starts
          Dir = yuzu_test_dir(),
          Empty = filename:join(Dir, "empty.pem"),
          Broken = filename:join(Dir, "broken.pem"),
          ok = file:write_file(Empty, <<>>),
          ok = file:write_file(Broken, <<"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n"
                                         "-----END CERTIFICATE-----\n">>),
          try
              [begin
                   ?assertEqual(0, yuzu_gw_mgmt_identity:cacert_count(F)),
                   ?assertEqual(error, yuzu_gw_mgmt_identity:derive_from_cacertfile(F)),
                   ?assertMatch({error, [{identity_over_ca_bundle, identity_or_pin}]},
                                yuzu_gw_mgmt_identity:resolve(identity_or_pin, "yuzu://X/server",
                                                              [], [Mgmt(F)], Pins)),
                   ?assertMatch({error, [{identity_over_ca_bundle, identity}]},
                                yuzu_gw_mgmt_identity:resolve(identity, "yuzu://X/server",
                                                              [], [Mgmt(F)], [])),
                   ?assertMatch({ok, #{mode := identity, identity := <<"yuzu://X/server">>}},
                                yuzu_gw_mgmt_identity:resolve(identity, "yuzu://X/server",
                                                              [], [Mgmt(F)], Pins))
               end || F <- [Empty, Broken, filename:join(Dir, "missing.pem")]],
              %% a plaintext listener has no cacertfile: nothing to judge
              ?assertMatch({ok, #{identity := <<"yuzu://X/server">>}},
                           yuzu_gw_mgmt_identity:resolve(
                             identity, "yuzu://X/server", [],
                             [#{name => mgmt, service_protos => [management_pb]}], [])),
              %% ...and no identity at all is never a defect here
              ?assertMatch({ok, #{identity := undefined}},
                           yuzu_gw_mgmt_identity:resolve(identity_or_pin, undefined, [],
                                                         [Mgmt(Empty)], Pins))
          after
              yuzu_test_dir_cleanup(Dir)
          end
      end},
     {"an unusable mode, identity or deny entry is a defect, all reported at once",
      fun() ->
          ?assertMatch({error, [{bad_mgmt_peer_auth_mode, strict},
                                {bad_mgmt_peer_denied, B}]} when is_binary(B),
                       yuzu_gw_mgmt_identity:resolve(strict, undefined, [{serial, "ZZ"}], [], [])),
          ?assertMatch({error, [{bad_mgmt_peer_identity, _}]},
                       yuzu_gw_mgmt_identity:resolve(identity, "yuzu://X/agent/a", [], [], []))
      end},
     {"nothing derivable is unresolved, not a defect",
      fun() ->
          ?assertEqual({ok, #{mode => identity, identity => undefined, denied => []}},
                       yuzu_gw_mgmt_identity:resolve(identity, undefined, [],
                                                     [Mgmt("/no/such/ca.pem")], [])),
          ?assertEqual({ok, #{mode => identity_or_pin, identity => undefined, denied => []}},
                       yuzu_gw_mgmt_identity:resolve(identity_or_pin, undefined, [],
                                                     [#{name => agent,
                                                        service_protos => [agent_pb]}], Pins))
      end}].

%%%-------------------------------------------------------------------
%%% With certificates
%%%-------------------------------------------------------------------

%% Mismatching forms of the server URI: each must be refused as
%% identity_mismatch even though the leaf is CA-issued and carries serverAuth.
vectors(Fp) ->
    Lower = string:lowercase(Fp),
    [{lower_case_install, "yuzu://" ++ Lower ++ "/server"},
     {trailing_slash, "yuzu://" ++ Fp ++ "/server/"},
     {capitalised, "yuzu://" ++ Fp ++ "/Server"},
     {plural, "yuzu://" ++ Fp ++ "/servers"},
     {agent_named_server, "yuzu://" ++ Fp ++ "/agent/server"},
     {percent_nul, "yuzu://" ++ Fp ++ "/server%00"},
     {extra_path, "yuzu://" ++ Fp ++ "/server/extra"},
     {other_install, "yuzu://" ++ lists:duplicate(64, $0) ++ "/server"},
     {https_scheme, "https://" ++ Fp ++ "/server"},
     {agent_uri, "yuzu://" ++ Fp ++ "/agent/agent-123"}].

identity_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(Certs) ->
        case Certs of
            #{} -> cases(Certs);
            {error, Why} -> yuzu_gw_authz_tests:certs_unavailable("yuzu_gw_mgmt_identity_tests", Why)
        end
     end}.

cases(Certs) ->
    Check = fun(Which, Pins, Auth) ->
                yuzu_gw_authz:check_peer(der(Certs, Which), Pins, Auth)
            end,
    Id = fun(Mode) -> #{mode => Mode, identity => maps:get(identity, Certs), denied => []} end,
    SrvPin = fun() -> [{cert_file, maps:get(srv_pem, Certs)}] end,
    ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
    [{"the derivation byte-matches openssl's own fingerprint of the CA",
      fun() ->
          Out = os:cmd("openssl x509 -in '" ++ maps:get(ca, Certs)
                       ++ "' -noout -fingerprint -sha256"),
          [_, Colons] = string:split(string:trim(Out), "="),
          Fp = string:replace(Colons, ":", "", all),
          ?assertEqual(list_to_binary("yuzu://" ++ lists:flatten(Fp) ++ "/server"),
                       maps:get(identity, Certs)),
          ?assertEqual({ok, maps:get(identity, Certs)},
                       yuzu_gw_mgmt_identity:derive_from_cacertfile(maps:get(ca, Certs)))
      end},
     {"the leaf's URI SANs are read exactly, several at once",
      fun() ->
          Id0 = maps:get(identity, Certs),
          ?assertEqual([Id0], yuzu_gw_authz:server_uri_sans(der(Certs, id_srv))),
          ?assertMatch([_, Id0], yuzu_gw_authz:server_uri_sans(der(Certs, id_two))),
          ?assertEqual([], yuzu_gw_authz:server_uri_sans(der(Certs, srv))),
          ?assertEqual([], yuzu_gw_authz:server_uri_sans(<<"not a certificate">>))
      end},
     {"identity mode admits the server leaf with no pin configured",
      fun() ->
          ?assertEqual({true, ?SERVER_ID}, Check(id_srv, [], Id(identity)))
      end},
     {"a server key renewal that keeps the identity needs no change on the gateway",
      fun() ->
          ?assertEqual({true, ?SERVER_ID}, Check(id_srv, [], Id(identity))),
          ?assertEqual({true, ?SERVER_ID}, Check(id_rot, [], Id(identity)))
      end},
     {"a leaf carrying two URI SANs is admitted when either is the identity",
      fun() ->
          ?assertEqual({true, ?SERVER_ID}, Check(id_two, [], Id(identity)))
      end},
     {"a leaf without the identity is refused with the reason that names why",
      fun() ->
          ?assertEqual(false, Check(srv, [], Id(identity))),      % no URI at all
          ?assertEqual(false, Check(gw, [], Id(identity))),
          ?assertEqual(false, Check(agent, [], Id(identity))),    % clientAuth only
          ?assertEqual(false, Check(selfs, [], Id(identity))),
          ?assertEqual(false, Check(id_noeku, [], Id(identity))),
          ?assertEqual(false, Check(id_srv, [], (Id(identity))#{identity := undefined}))
      end},
     {"the reasons are the closed ones",
      fun() ->
          Reason = fun(Which, Auth) -> reason_of(Certs, Which, [], Auth) end,
          ?assertEqual(no_uri_san, Reason(srv, Id(identity))),
          ?assertEqual(no_uri_san, Reason(gw, Id(identity))),
          ?assertEqual(missing_server_auth_eku, Reason(agent, Id(identity))),
          ?assertEqual(missing_server_auth_eku, Reason(id_noeku, Id(identity))),
          ?assertEqual(identity_unresolved,
                       Reason(id_srv, (Id(identity))#{identity := undefined})),
          ?assertEqual(identity_mismatch,
                       Reason(id_srv, (Id(identity))#{identity := <<"yuzu://OTHER/server">>}))
      end},
     {"every near-miss form of the URI is refused as a mismatch",
      fun() ->
          [begin
               ?assertEqual({Name, identity_mismatch},
                            {Name, reason_of(Certs, {vec, Name}, [], Id(identity))}),
               ?assertEqual({Name, identity_mismatch},
                            {Name, reason_of(Certs, {vec, Name}, [], Id(identity_or_pin))})
           end || {Name, _} <- vectors(maps:get(fp, Certs))]
      end},
     {"identity mode with a pin: BOTH must hold",
      fun() ->
          ok = yuzu_gw_mgmt_pins:refresh([{cert_file, maps:get(id_srv_pem, Certs)}]),
          ?assertEqual({true, ?SERVER_ID}, Check(id_srv, [{cert_file, maps:get(id_srv_pem, Certs)}],
                                                 Id(identity))),
          %% the identity is right, the pinned key is not
          ?assertEqual(pin_mismatch,
                       reason_of(Certs, id_rot, [{cert_file, maps:get(id_srv_pem, Certs)}],
                                 Id(identity))),
          %% a pin that never resolved pins nothing
          ?assertEqual(no_pins_resolved,
                       reason_of(Certs, id_srv, [{cert_file, "/no/such/pin.pem"}],
                                 Id(identity))),
          %% the pinned key WITHOUT the identity is refused: a pin never admits on
          %% its own in this mode (the CA-key-only attacker has neither)
          ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
          ?assertEqual(no_uri_san, reason_of(Certs, srv, SrvPin(), Id(identity)))
      end},
     {"identity_or_pin: the identity alone, or the pin alone, admits",
      fun() ->
          ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
          Or = Id(identity_or_pin),
          ?assertEqual({true, ?SERVER_ID}, Check(id_srv, [], Or)),
          ?assertEqual({true, ?SERVER_ID}, Check(id_srv, SrvPin(), Or)),   % wrong pin, right identity
          ?assertEqual({true, ?SERVER_ID}, Check(srv, SrvPin(), Or)),      % pinned key, no identity
          ?assertEqual(pin_mismatch, reason_of(Certs, gw, SrvPin(), Or)),
          ?assertEqual(no_uri_san, reason_of(Certs, gw, [], Or)),
          ?assertEqual(missing_server_auth_eku, reason_of(Certs, agent, SrvPin(), Or))
      end},
     {"identity_or_pin: a dead pin is reported even while the identity admits",
      fun() ->
          Ref = make_ref(),
          Self = self(),
          ok = telemetry:attach({?MODULE, Ref}, [yuzu, gw, mgmt_auth, pin_unresolved],
                                fun ?MODULE:capture/4, Self),
          try
              Dead = [{cert_file, "/no/such/pin.pem"}],
              ?assertEqual({true, ?SERVER_ID}, Check(id_srv, Dead, Id(identity_or_pin))),
              receive {event, pin_unresolved, _} -> ok
              after 2000 -> ?assert(false)
              end,
              %% nothing is reported when every pin resolves
              ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
              ?assertEqual({true, ?SERVER_ID}, Check(id_srv, SrvPin(), Id(identity_or_pin))),
              receive {event, pin_unresolved, _} -> ?assert(false)
              after 100 -> ok
              end
          after
              telemetry:detach({?MODULE, Ref})
          end
      end},
     {"identity_or_pin with an unresolved identity is the pin mode",
      fun() ->
          ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
          Or = (Id(identity_or_pin))#{identity := undefined},
          ?assertEqual({true, ?SERVER_ID}, Check(srv, SrvPin(), Or)),
          %% a peer the pin does not admit is reported as the configuration defect it
          %% is, not as a rotation-shaped pin_mismatch
          ?assertEqual(identity_unresolved, reason_of(Certs, id_srv, SrvPin(), Or)),
          ?assertEqual(identity_unresolved, reason_of(Certs, id_srv, [], Or))
      end},
     {"pin mode is unchanged: the identity does not admit, no pins refuse",
      fun() ->
          ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
          Pin = Id(pin),
          ?assertEqual({true, ?SERVER_ID}, Check(srv, SrvPin(), Pin)),
          ?assertEqual(pin_mismatch, reason_of(Certs, id_rot, SrvPin(), Pin)),
          ?assertEqual(no_pins_configured, reason_of(Certs, id_srv, [], Pin))
      end},
     {"a pin list that is not a list is refused in every mode",
      fun() ->
          [?assertEqual(bad_pin_config, reason_of(Certs, id_srv, not_a_list, Id(M)))
           || M <- [pin, identity_or_pin, identity]]
      end},
     {"the serial is read as the integer openssl reports",
      fun() ->
          Out = os:cmd("openssl x509 -in '" ++ maps:get(id_srv_pem, Certs)
                       ++ "' -noout -serial"),
          [_, Hex] = string:split(string:trim(Out), "="),
          ?assertEqual({ok, list_to_integer(Hex, 16)},
                       yuzu_gw_authz:serial_number(der(Certs, id_srv))),
          ?assertEqual(error, yuzu_gw_authz:serial_number(<<"junk">>))
      end},
     {"a denied serial is refused in every mode, even with the identity or the pin",
      fun() ->
          ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
          {ok, S} = yuzu_gw_authz:serial_number(der(Certs, id_srv)),
          {ok, PinSerial} = yuzu_gw_authz:serial_number(der(Certs, srv)),
          ?assertEqual(revoked, reason_of(Certs, id_srv, [], (Id(identity))#{denied := [S]})),
          ?assertEqual(revoked, reason_of(Certs, id_srv, [], (Id(identity_or_pin))#{denied := [S]})),
          ?assertEqual(revoked, reason_of(Certs, srv, SrvPin(),
                                          (Id(pin))#{denied := [PinSerial]})),
          ?assertEqual(revoked, reason_of(Certs, srv, SrvPin(),
                                          (Id(identity_or_pin))#{denied := [PinSerial]}))
      end},
     {"withdrawal is by SERIAL: the same-key re-issue and a renewed key stay admitted",
      fun() ->
          {ok, Old} = yuzu_gw_authz:serial_number(der(Certs, id_srv)),
          {ok, Re} = yuzu_gw_authz:serial_number(der(Certs, id_reissue)),
          ?assertNotEqual(Old, Re),
          %% the re-issue shares id_srv's public key (what #6072 does)
          ?assertEqual(yuzu_gw_authz:spki_sha256(der(Certs, id_srv)),
                       yuzu_gw_authz:spki_sha256(der(Certs, id_reissue))),
          Denied = (Id(identity))#{denied := [Old]},
          ?assertEqual(revoked, reason_of(Certs, id_srv, [], Denied)),
          ?assertEqual({true, ?SERVER_ID}, Check(id_reissue, [], Denied)),
          ?assertEqual({true, ?SERVER_ID}, Check(id_rot, [], Denied))
      end},
     {"a serial that cannot be read is refused when a deny-list is configured",
      fun() ->
          Neg = negative_serial(der(Certs, id_srv)),
          ?assertEqual(error, yuzu_gw_authz:serial_number(Neg)),
          ?assertEqual(revoked, reason_of(Certs, {raw, Neg}, [], (Id(identity))#{denied := [1]})),
          %% with no deny-list the serial is never read, and the peer is otherwise admitted
          ?assertEqual({true, ?SERVER_ID}, Check({raw, Neg}, [], Id(identity)))
      end},
     {"a deny state that is not a list refuses (never a silent pass)",
      fun() ->
          ?assertEqual(revoked, reason_of(Certs, id_srv, [], (Id(identity))#{denied := not_a_list}))
      end},
     {"an identity that is neither a binary nor undefined is unresolved",
      fun() ->
          ?assertEqual(identity_unresolved,
                       reason_of(Certs, id_srv, [], (Id(identity))#{identity := 42}))
      end},
     {"a denied serial that matches nothing changes nothing",
      fun() ->
          ?assertEqual({true, ?SERVER_ID},
                       Check(id_srv, [], (Id(identity))#{denied := [1, 2, 3]}))
      end},
     {"the entry point reads the published mode, identity and deny-list",
      fun() ->
          {ok, S} = yuzu_gw_authz:serial_number(der(Certs, id_srv)),
          application:set_env(yuzu_gw, mgmt_peer_pins, []),
          try
              %% nothing published: the pre-#6016 pin mode, which refuses with no pins
              ok = yuzu_gw_mgmt_identity:reset(),
              ?assertEqual(false, yuzu_gw_authz:check_mgmt_peer(der(Certs, id_srv))),
              ok = yuzu_gw_mgmt_identity:publish(Id(identity)),
              ?assertEqual({true, ?SERVER_ID}, yuzu_gw_authz:check_mgmt_peer(der(Certs, id_srv))),
              ok = yuzu_gw_mgmt_identity:publish((Id(identity))#{denied := [S]}),
              ?assertEqual(false, yuzu_gw_authz:check_mgmt_peer(der(Certs, id_srv)))
          after
              ok = yuzu_gw_mgmt_identity:reset(),
              application:unset_env(yuzu_gw, mgmt_peer_pins)
          end
      end},
     {"admissions are counted by method, rejections by reason",
      fun() ->
          ok = yuzu_gw_mgmt_pins:refresh(SrvPin()),
          Ref = make_ref(),
          Self = self(),
          ok = telemetry:attach_many({?MODULE, Ref},
                                     [[yuzu, gw, mgmt_auth, admitted],
                                      [yuzu, gw, mgmt_auth, rejected]],
                                     fun ?MODULE:capture/4, Self),
          try
              {true, _} = Check(id_srv, [], Id(identity)),
              {true, _} = Check(srv, SrvPin(), Id(identity_or_pin)),
              false = Check(gw, [], Id(identity)),
              ?assertEqual([{admitted, identity}, {admitted, pin}, {rejected, no_uri_san}],
                           drain(3))
          after
              telemetry:detach({?MODULE, Ref})
          end
      end}].

%% @private telemetry handler: forward {Kind, Label} to the test process.
capture([yuzu, gw, mgmt_auth, admitted], _M, #{method := Method}, Pid) ->
    Pid ! {event, admitted, Method};
capture([yuzu, gw, mgmt_auth, rejected], _M, #{reason := Reason}, Pid) ->
    Pid ! {event, rejected, Reason};
capture([yuzu, gw, mgmt_auth, pin_unresolved], _M, _Meta, Pid) ->
    Pid ! {event, pin_unresolved, none}.

drain(0) -> [];
drain(N) ->
    receive {event, Kind, Label} -> [{Kind, Label} | drain(N - 1)]
    after 2000 -> [timeout]
    end.

reason_of(Certs, Which, Pins, Auth) ->
    Ref = make_ref(),
    Self = self(),
    ok = telemetry:attach({?MODULE, Ref}, [yuzu, gw, mgmt_auth, rejected],
                          fun ?MODULE:capture/4, Self),
    try
        false = yuzu_gw_authz:check_peer(der(Certs, Which), Pins, Auth),
        receive {event, rejected, Reason} -> Reason
        after 2000 -> no_event
        end
    after
        telemetry:detach({?MODULE, Ref})
    end.

der(_Certs, {raw, Der}) ->
    Der;
der(Certs, {vec, Name}) ->
    {ok, Pem} = file:read_file(maps:get({vec, Name}, Certs)),
    [{'Certificate', Der, not_encrypted} | _] = public_key:pem_decode(Pem),
    Der;
der(Certs, Which) ->
    yuzu_gw_authz_tests:der(Certs, pem_key(Which)).

%% The certificate with its serial number flipped to a negative INTEGER (the
%% signature no longer verifies; the authorization check never verifies it, TLS
%% already did).
negative_serial(Der) ->
    Marker = <<16#A0, 3, 2, 1, 2, 2>>,
    [Pre, <<Len, _First, Tail/binary>>] = binary:split(Der, Marker),
    <<Pre/binary, Marker/binary, Len, 16#FF, Tail/binary>>.

pem_key(Which) ->
    list_to_atom(atom_to_list(Which) ++ "_pem").

%%%-------------------------------------------------------------------
%%% Fixture: the authz suite's CA and leaves, plus the identity leaves
%%%-------------------------------------------------------------------

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    case yuzu_gw_authz_tests:setup_certs() of
        #{dir := Dir, ca := Ca} = Base ->
            {ok, CaPem} = file:read_file(Ca),
            [{'Certificate', CaDer, not_encrypted}] = public_key:pem_decode(CaPem),
            Identity = yuzu_gw_mgmt_identity:identity_from_ca_der(CaDer),
            <<"yuzu://", FpBin:64/binary, "/server">> = Identity,
            Fp = binary_to_list(FpBin),
            CaK = filename:join(Dir, "ca.key"),
            Ext = fun(Name, San, Eku) ->
                      Path = filename:join(Dir, Name ++ ".ext"),
                      ok = file:write_file(
                             Path, ["subjectAltName=", San, "\n", Eku, "basicConstraints=CA:FALSE\n"]),
                      Path
                  end,
            ServerUri = "URI:yuzu://" ++ Fp ++ "/server",
            Leaves =
                [{id_srv, Ext("id_srv", ServerUri ++ ",DNS:localhost",
                              "extendedKeyUsage=serverAuth,clientAuth\n")},
                 {id_rot, Ext("id_rot", ServerUri ++ ",DNS:localhost",
                              "extendedKeyUsage=serverAuth,clientAuth\n")},
                 {id_two, Ext("id_two", "URI:yuzu://" ++ Fp ++ "/agent/a1," ++ ServerUri,
                              "extendedKeyUsage=serverAuth,clientAuth\n")},
                 {id_noeku, Ext("id_noeku", ServerUri, "extendedKeyUsage=clientAuth\n")}]
                ++ [{{vec, Name}, Ext("vec_" ++ atom_to_list(Name), "URI:" ++ Uri,
                                      "extendedKeyUsage=serverAuth,clientAuth\n")}
                    || {Name, Uri} <- vectors(Fp)],
            Cmds = lists:append(
                     [mint(Dir, leaf_name(K), Ext1, Ca, CaK) || {K, Ext1} <- Leaves]),
            %% the SAME key as id_srv under a new serial: what the server's in-place
            %% re-issue does (default_certs.cpp upgrade_server_leaf)
            Reissue = ["openssl x509 -req -in ", q(filename:join(Dir, "id_srv.csr")),
                       " -CA ", q(Ca), " -CAkey ", q(CaK), " -set_serial 4242 -days 1 -sha256",
                       " -extfile ", q(filename:join(Dir, "id_srv.ext")),
                       " -out ", q(filename:join(Dir, "id_reissue.pem"))],
            lists:foreach(fun(C) -> _ = os:cmd(lists:flatten(C) ++ " 2>&1") end, Cmds ++ [Reissue]),
            Pems = maps:from_list(
                     [{pem_key_of(K), filename:join(Dir, leaf_name(K) ++ ".pem")} || {K, _} <- Leaves]
                     ++ [{id_reissue_pem, filename:join(Dir, "id_reissue.pem")}]),
            case lists:all(fun filelib:is_regular/1, maps:values(Pems)) of
                true ->
                    maps:merge(maps:merge(Base, Pems),
                               #{identity => Identity, fp => Fp});
                false ->
                    yuzu_gw_authz_tests:cleanup_certs(Base),
                    {error, identity_certs_not_written}
            end;
        {error, _} = E ->
            E
    end.

cleanup(#{} = Certs) ->
    ok = yuzu_gw_mgmt_identity:reset(),
    yuzu_gw_authz_tests:cleanup_certs(Certs);
cleanup(_) ->
    ok.

leaf_name({vec, Name}) -> "vec_" ++ atom_to_list(Name);
leaf_name(K) -> atom_to_list(K).

pem_key_of({vec, Name}) -> {vec, Name};
pem_key_of(K) -> list_to_atom(atom_to_list(K) ++ "_pem").

mint(Dir, Name, Ext, Ca, CaK) ->
    Key = filename:join(Dir, Name ++ ".key"),
    Csr = filename:join(Dir, Name ++ ".csr"),
    Pem = filename:join(Dir, Name ++ ".pem"),
    [["openssl ecparam -name prime256v1 -genkey -noout -out ", q(Key)],
     ["openssl req -new -key ", q(Key), " -subj '/O=Yuzu/CN=Yuzu Default server' -out ", q(Csr)],
     ["openssl x509 -req -in ", q(Csr), " -CA ", q(Ca), " -CAkey ", q(CaK),
      " -CAcreateserial -days 1 -sha256 -extfile ", q(Ext), " -out ", q(Pem)]].

q(S) -> "'" ++ S ++ "'".
