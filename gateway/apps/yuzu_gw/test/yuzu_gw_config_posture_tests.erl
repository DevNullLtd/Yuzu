%%%-------------------------------------------------------------------
%%% @doc Static posture checks over the TRACKED gateway config files.
%%%
%%% Parses each real sys.config with file:consult (so a syntax slip,
%%% including in the `fun M:F/1' auth_fun term, fails here, not at a
%%% container boot) and asserts, through the same pure decision functions the
%%% boot guards use:
%%%
%%%   - no config carries a `{grpcbox, servers}' block (it refuses boot), and
%%%     every `{yuzu_gw, grpc_listeners}' list is one `evaluate_listeners/1'
%%%     accepts;
%%%   - every management_pb listener in an mTLS config carries
%%%     auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1, a complete `tls' map
%%%     and the transport origin, and the yuzu_gw env carries a non-empty
%%%     mgmt_peer_pins (#1422);
%%%   - NO other listener carries an auth_fun (on the one-way-TLS agent
%%%     listener it would refuse every unenrolled agent, which has no
%%%     certificate);
%%%   - the dev config's mgmt listener stays on loopback (why it is exempt
%%%     from the strict posture).
%%%
%%% Paths are relative to the gateway/ project root (rebar3 eunit's cwd).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_config_posture_tests).
-include_lib("eunit/include/eunit.hrl").

-define(AUTH_FUN, fun yuzu_gw_authz:check_mgmt_peer/1).

%% Tracked configs with a STRICT (mTLS) mgmt listener.
strict_configs() ->
    ["config/sys.config.prod",
     "../deploy/docker/reference-gateway-sys.config"].

%% Tracked LAB-RIG configs whose mgmt listener is deliberately plaintext on
%% 0.0.0.0 behind the explicit acknowledgement hatch (their composes keep
%% :50063 unpublished). The docker-compose.uat.yml INLINE config carries the
%% same hatch but is YAML-embedded, so it cannot be consulted here.
rig_configs() ->
    ["../deploy/docker/gateway-sys.config",
     "../deploy/config/uat/gateway-sys.config",
     "../deploy/docker/demo-gateway-sys.config"].

%% Every tracked config that configures listeners.
listener_configs() ->
    ["config/sys.config"] ++ strict_configs() ++ rig_configs().

consult_strict_configs_test_() ->
    [{Path, fun() -> check_strict(Path) end} || Path <- strict_configs()].

consult_rig_configs_test_() ->
    [{Path, fun() -> check_rig(Path) end} || Path <- rig_configs()].

%% A leftover {grpcbox, servers} refuses boot (yuzu_gw_app:check_legacy_grpcbox_servers/0),
%% so no tracked config may carry one; only the upstream {client, ...} remains.
no_config_has_grpcbox_servers_test_() ->
    [{Path, fun() ->
                Grpcbox = proplists:get_value(grpcbox, consult(Path), []),
                ?assertEqual(undefined, proplists:get_value(servers, Grpcbox)),
                ?assertMatch(#{channels := [_ | _]}, proplists:get_value(client, Grpcbox))
            end}
     || Path <- ["config/test.config" | listener_configs()]].

%% Every list the gateway would be started with passes the boot guard that
%% validates the entries, and the agent edge never carries an auth_fun.
listener_entries_are_valid_test_() ->
    [{Path, fun() ->
                Listeners = listeners(consult(Path)),
                ?assertMatch([_ | _], Listeners),
                ?assertEqual(ok, yuzu_gw_app:evaluate_listeners(Listeners)),
                lists:foreach(fun(L) ->
                    case is_mgmt(L) of
                        true  -> ok;
                        false -> ?assertEqual(missing, maps:get(auth_fun, L, missing))
                    end
                end, Listeners)
            end}
     || Path <- listener_configs()].

%% A rig config must parse, must carry the LITERAL hatch (so the boot guard
%% warns instead of refusing), and must still pass evaluate_mgmt_posture the
%% way the running gateway will evaluate it.
check_rig(Path) ->
    Cfg = consult(Path),
    YuzuEnv = proplists:get_value(yuzu_gw, Cfg, []),
    ?assertEqual(true, proplists:get_value(allow_insecure_mgmt, YuzuEnv)),
    Pins = proplists:get_value(mgmt_peer_pins, YuzuEnv, []),
    ?assertMatch({ok_insecure, _},
                 yuzu_gw_app:evaluate_mgmt_posture(listeners(Cfg), Pins, true)).

dev_config_mgmt_is_loopback_test() ->
    Cfg = consult("config/sys.config"),
    [Listener] = mgmt_listeners(Cfg),
    ?assertEqual({127, 0, 0, 1}, listen_ip(Listener)).

check_strict(Path) ->
    Cfg = consult(Path),
    Listeners = listeners(Cfg),
    MgmtListeners = [L || L <- Listeners, is_mgmt(L)],
    ?assertMatch([_ | _], MgmtListeners),
    %% Evaluate through the REAL production decision function first -- the
    %% hand-rolled shape checks below are supplements, not the gate. A test
    %% that re-implements the guard can diverge from it (PR #3905 review:
    %% exactly such divergence hid the fd-socket loopback bypass).
    YuzuEnv = proplists:get_value(yuzu_gw, Cfg, []),
    Pins = proplists:get_value(mgmt_peer_pins, YuzuEnv, []),
    ?assertMatch([_ | _], Pins),
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(Listeners, Pins, false)),
    %% ...and non-vacuously: strip the pins and the same evaluation must
    %% REFUSE, proving the guard actually recognised the mgmt listener.
    ?assertMatch({error, {insecure_mgmt_listener, _}},
                 yuzu_gw_app:evaluate_mgmt_posture(Listeners, [], false)),
    lists:foreach(fun(L) ->
        ?assertEqual(?AUTH_FUN, maps:get(auth_fun, L, missing)),
        ?assertMatch(#{certfile := [_ | _], keyfile := [_ | _], cacertfile := [_ | _]},
                     maps:get(tls, L, #{})),
        ?assertEqual(#{mode => transport}, maps:get(origin, L, #{mode => transport}))
    end, MgmtListeners).

%%%-------------------------------------------------------------------
%%% helpers
%%%-------------------------------------------------------------------

consult(Path) ->
    ?assert(filelib:is_regular(Path)),
    {ok, [Cfg]} = file:consult(Path),
    Cfg.

listeners(Cfg) ->
    proplists:get_value(grpc_listeners, proplists:get_value(yuzu_gw, Cfg, []), []).

mgmt_listeners(Cfg) ->
    [L || L <- listeners(Cfg), is_mgmt(L)].

is_mgmt(L) when is_map(L) ->
    lists:member(management_pb, maps:get(service_protos, L, []));
is_mgmt(_) ->
    false.

listen_ip(L) ->
    maps:get(ip, maps:get(listen, L, #{}), undefined).
