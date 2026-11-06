%%% @doc The CA revocation list in the management peer check, and the boot guard that
%%% publishes its configuration (#6016 PR 4b). Certificates and CRLs are the server-built
%%% fixtures (fixtures/crl/README.md): `server.pem' carries the identity `yuzu://AAAA/server' and
%%% serverAuth, and is the serial `crl-populated.der' revokes; `other.pem' is another leaf of the
%%% same CA, with serverAuth, no identity, and not revoked (admitted here by its SPKI pin).
-module(yuzu_gw_mgmt_crl_authz_tests).

-include_lib("eunit/include/eunit.hrl").

-export([handle_event/4]).

%% thisUpdate / nextUpdate of every fixture CRL (nextUpdate is thisUpdate + 300 s + 48 h).
-define(THIS, 1793628888).
-define(NEXT, (?THIS + 300 + 48 * 3600)).
-define(NOW, (?THIS + 600)).
-define(GRACE, 86400).
-define(ID, <<"yuzu://AAAA/server">>).

server() -> yuzu_gw_crl_fixture:cert_der("server.pem").
other() -> yuzu_gw_crl_fixture:cert_der("other.pem").

identity_auth() ->
    #{mode => identity, identity => ?ID, denied => []}.

pin_auth() ->
    #{mode => pin, identity => undefined, denied => []}.

other_pins() ->
    {ok, Spki} = yuzu_gw_authz:spki_sha256(other()),
    [{spki_sha256, binary_to_list(binary:encode_hex(Spki))}].

policy() ->
    #{source => {file, "unused"}, grace_s => ?GRACE, refresh_ms => 5000,
      verify_cacertfiles => [yuzu_gw_crl_fixture:path("root-ca.pem")]}.

state() ->
    #{crl => none, crl_hash => undefined, ca_hash => undefined, etag => undefined,
      last_reject => undefined}.

load(Name) ->
    Bin = yuzu_gw_crl_fixture:read(Name),
    yuzu_gw_mgmt_crl_source:load(policy(), state(), fun(_, _) -> {ok, Bin, undefined} end, ?NOW).

handle_event(_Event, _Measurements, Meta, Pid) ->
    Pid ! {rejected, maps:get(reason, Meta, undefined)},
    ok.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_mgmt_crl_source:reset(),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, mgmt_auth, rejected], fun ?MODULE:handle_event/4, self()),
    Id.

cleanup(Id) ->
    telemetry:detach(Id),
    yuzu_gw_mgmt_crl_source:reset().

reasons() ->
    receive {rejected, R} -> [R | reasons()] after 0 -> [] end.

check(Der, Pins, Auth, Now) ->
    yuzu_gw_authz:check_peer(Der, Pins, Auth, Now).

authz_test_() ->
    {foreach, local, fun setup/0, fun cleanup/1,
     [{"no source configured: the CRL is not consulted and the identity admits as before",
       fun() ->
           ?assertMatch({true, _}, check(server(), [], identity_auth(), ?NOW)),
           ?assertEqual([], reasons())
       end},
      {"a source with nothing loaded refuses a peer that is otherwise admitted",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           ?assertEqual(false, check(server(), [], identity_auth(), ?NOW)),
           ?assertEqual([revocation_unknown], reasons())
       end},
      {"a loaded CRL that lists the peer's serial refuses it as crl_revoked",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           _ = load("crl-populated.der"),
           ?assertEqual(false, check(server(), [], identity_auth(), ?NOW)),
           ?assertEqual([crl_revoked], reasons())
       end},
      {"a loaded CRL that does not list the serial admits",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           _ = load("crl-empty.der"),
           ?assertMatch({true, _}, check(server(), [], identity_auth(), ?NOW)),
           ?assertEqual([], reasons())
       end},
      {"the CRL checks every admitted peer, whatever admitted it (here a pin)",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           _ = load("crl-populated.der"),
           ?assertMatch({true, _}, check(other(), other_pins(), pin_auth(), ?NOW)),
           yuzu_gw_mgmt_crl_source:reset(),
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           ?assertEqual(false, check(other(), other_pins(), pin_auth(), ?NOW)),
           ?assertEqual([revocation_unknown], reasons())
       end},
      {"nextUpdate plus the grace is the last second the CRL is believed",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           _ = load("crl-empty.der"),
           Edge = ?NEXT + ?GRACE,
           ?assertMatch({true, _}, check(server(), [], identity_auth(), Edge)),
           ?assertEqual(false, check(server(), [], identity_auth(), Edge + 1)),
           ?assertEqual([revocation_stale], reasons())
       end},
      {"a CRL stale for a revoked serial is stale, not 'revoked': it proves nothing either way",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           _ = load("crl-populated.der"),
           ?assertEqual(false, check(server(), [], identity_auth(), ?NEXT + ?GRACE + 1)),
           ?assertEqual([revocation_stale], reasons())
       end},
      {"the grace in the policy is the one applied",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy((policy())#{grace_s => 0}),
           _ = load("crl-empty.der"),
           ?assertMatch({true, _}, check(server(), [], identity_auth(), ?NEXT)),
           ?assertEqual(false, check(server(), [], identity_auth(), ?NEXT + 1)),
           ?assertEqual([revocation_stale], reasons())
       end},
      {"the CRL never removes a denial: an empty CRL does not admit a denied serial",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           _ = load("crl-empty.der"),
           {ok, Serial} = yuzu_gw_authz:serial_number(server()),
           Auth = (identity_auth())#{denied => [Serial]},
           ?assertEqual(false, check(server(), [], Auth, ?NOW)),
           ?assertEqual([revoked], reasons())
       end},
      {"a peer the identity does not admit is refused for that reason, before the CRL is read",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           ?assertEqual(false, check(other(), [], identity_auth(), ?NOW)),
           ?assertEqual([no_uri_san], reasons())
       end},
      {"the auth_fun entry point reads the clock itself and stays total",
       fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           ?assertEqual(false, yuzu_gw_authz:check_mgmt_peer(<<"not a certificate">>))
       end}]}.

%%--------------------------------------------------------------------
%% The boot guard
%%--------------------------------------------------------------------

guard_test_() ->
    Keys = [mgmt_crl_source, mgmt_crl_grace_s, mgmt_crl_refresh_ms, grpc_listeners],
    Mgmt = #{name => mgmt, service_protos => [management_pb],
             tls => #{certfile => "gw.pem", keyfile => "gw.key",
                      cacertfile => yuzu_gw_crl_fixture:path("root-ca.pem")},
             auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1},
    {foreach, local,
     fun() ->
             Saved = [{K, application:get_env(yuzu_gw, K)} || K <- Keys],
             [application:unset_env(yuzu_gw, K) || K <- Keys],
             application:set_env(yuzu_gw, grpc_listeners, [Mgmt]),
             yuzu_gw_mgmt_crl_source:reset(),
             yuzu_gw_mgmt_identity:reset(),
             Saved
     end,
     fun(Saved) ->
             [case V of
                  {ok, X} -> application:set_env(yuzu_gw, K, X);
                  undefined -> application:unset_env(yuzu_gw, K)
              end || {K, V} <- Saved],
             yuzu_gw_mgmt_crl_source:reset(),
             yuzu_gw_mgmt_identity:reset()
     end,
     [{"no source: ok, nothing is published and the check is off",
       fun() ->
           ?assertEqual(ok, yuzu_gw_app:check_mgmt_crl_source()),
           ?assertEqual(none, yuzu_gw_mgmt_crl_source:policy())
       end},
      {"a url source is published with the listener's cacertfile as the fetch CA",
       fun() ->
           application:set_env(yuzu_gw, mgmt_crl_source, {url, "https://server:8443/api/v1/ca/crl"}),
           ?assertEqual(ok, yuzu_gw_app:check_mgmt_crl_source()),
           Root = yuzu_gw_crl_fixture:path("root-ca.pem"),
           ?assertMatch(#{grace_s := 86400, refresh_ms := 5000,
                          source := {url, #{host := "server", port := 8443, cacertfile := Root}},
                          verify_cacertfiles := [Root]},
                        yuzu_gw_mgmt_crl_source:policy())
       end},
      {"explicit grace and refresh are published",
       fun() ->
           application:set_env(yuzu_gw, mgmt_crl_source, {file, "/var/lib/yuzu/crl.der"}),
           application:set_env(yuzu_gw, mgmt_crl_grace_s, 3600),
           application:set_env(yuzu_gw, mgmt_crl_refresh_ms, 2000),
           ?assertEqual(ok, yuzu_gw_app:check_mgmt_crl_source()),
           ?assertMatch(#{grace_s := 3600, refresh_ms := 2000}, yuzu_gw_mgmt_crl_source:policy()),
           ?assertEqual(3600, yuzu_gw_mgmt_crl_source:grace_s()),
           ?assertEqual(2000, yuzu_gw_mgmt_crl_source:refresh_ms())
       end},
      {"each defect refuses the boot and publishes nothing",
       fun() ->
           [begin
                application:set_env(yuzu_gw, mgmt_crl_source, Source),
                ?assertEqual({error, bad_mgmt_crl_source}, yuzu_gw_app:check_mgmt_crl_source()),
                ?assertEqual(none, yuzu_gw_mgmt_crl_source:policy())
            end || Source <- [{url, "http://server:8080/api/v1/ca/crl"},
                              {url, "https://u:p@server/crl"},
                              {url, "https://server/crl", #{cacertfile => "/no/such/ca.pem"}},
                              {url, "https://server/crl", #{insecure => true}},
                              {file, 42},
                              "https://server/crl"]]
       end},
      {"an out-of-range grace or refresh refuses the boot",
       fun() ->
           application:set_env(yuzu_gw, mgmt_crl_source, {file, "/x"}),
           application:set_env(yuzu_gw, mgmt_crl_grace_s, 604801),
           ?assertEqual({error, bad_mgmt_crl_source}, yuzu_gw_app:check_mgmt_crl_source()),
           application:unset_env(yuzu_gw, mgmt_crl_grace_s),
           application:set_env(yuzu_gw, mgmt_crl_refresh_ms, 10),
           ?assertEqual({error, bad_mgmt_crl_source}, yuzu_gw_app:check_mgmt_crl_source())
       end},
      {"a url source with no CA to trust refuses the boot (a plaintext lab listener has none)",
       fun() ->
           application:set_env(yuzu_gw, grpc_listeners,
                               [#{name => mgmt, service_protos => [management_pb]}]),
           application:set_env(yuzu_gw, mgmt_crl_source, {url, "https://server:8443/crl"}),
           ?assertEqual({error, bad_mgmt_crl_source}, yuzu_gw_app:check_mgmt_crl_source())
       end},
      {"the guard runs after the auth configuration it reads the mode from",
       fun() ->
           Names = [element(2, erlang:fun_info(G, name)) || G <- yuzu_gw_app:startup_guards()],
           Pos = fun(N) -> length(lists:takewhile(fun(X) -> X =/= N end, Names)) end,
           ?assert(lists:member(check_mgmt_crl_source, Names)),
           ?assert(Pos(check_mgmt_auth_config) < Pos(check_mgmt_crl_source)),
           ?assert(Pos(check_mgmt_crl_source) < Pos(check_mgmt_listener_posture))
       end}]}.
