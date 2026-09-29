%%%-------------------------------------------------------------------
%%% @doc Static posture checks over the TRACKED gateway config files.
%%%
%%% Parses each real sys.config with file:consult (so a syntax slip —
%%% including in the `fun M:F/1` auth_fun term — fails here, not at a
%%% container boot) and asserts the #1422 mgmt-plane pin shape:
%%%
%%%   - every management_pb listener in an mTLS config carries
%%%     auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1 in grpc_opts,
%%%     and the yuzu_gw env carries a non-empty mgmt_peer_pins;
%%%   - NO other listener carries an auth_fun (leaked onto the
%%%     verify_none :50051 agent listener it would reject every certless
%%%     unenrolled agent — grpcbox fails a missing peer cert whenever an
%%%     auth_fun is installed);
%%%   - the dev config's mgmt listener stays on loopback (why it is
%%%     exempt from the strict posture).
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

consult_strict_configs_test_() ->
    [{Path, fun() -> check_strict(Path) end} || Path <- strict_configs()].

consult_rig_configs_test_() ->
    [{Path, fun() -> check_rig(Path) end} || Path <- rig_configs()].

%% A rig config must parse, must carry the LITERAL hatch (so the boot guard
%% warns instead of refusing), and must still pass evaluate_mgmt_posture the
%% way the running gateway will evaluate it.
check_rig(Path) ->
    Cfg = consult(Path),
    YuzuEnv = proplists:get_value(yuzu_gw, Cfg, []),
    ?assertEqual(true, proplists:get_value(allow_insecure_mgmt, YuzuEnv)),
    Pins = proplists:get_value(mgmt_peer_pins, YuzuEnv, []),
    ?assertMatch({ok_insecure, _},
                 yuzu_gw_app:evaluate_mgmt_posture(servers(Cfg), Pins, true)).

dev_config_mgmt_is_loopback_test() ->
    Cfg = consult("config/sys.config"),
    [Listener] = mgmt_listeners(Cfg),
    ?assertEqual({127, 0, 0, 1}, listen_ip(Listener)).

check_strict(Path) ->
    Cfg = consult(Path),
    Servers = servers(Cfg),
    MgmtListeners = [S || S <- Servers, is_mgmt(S)],
    ?assertMatch([_ | _], MgmtListeners),
    %% Evaluate through the REAL production decision function first — the
    %% hand-rolled shape checks below are supplements, not the gate. A test
    %% that re-implements the guard can diverge from it (PR #3905 review:
    %% exactly such divergence hid the fd-socket loopback bypass).
    YuzuEnv0 = proplists:get_value(yuzu_gw, Cfg, []),
    Pins0 = proplists:get_value(mgmt_peer_pins, YuzuEnv0, []),
    ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(Servers, Pins0, false)),
    %% ...and non-vacuously: strip the pins and the same evaluation must
    %% REFUSE, proving the guard actually recognised the mgmt listener.
    ?assertMatch({error, {insecure_mgmt_listener, _}},
                 yuzu_gw_app:evaluate_mgmt_posture(Servers, [], false)),
    lists:foreach(fun(S) ->
        GrpcOpts = maps:get(grpc_opts, S),
        ?assertEqual(?AUTH_FUN, maps:get(auth_fun, GrpcOpts, missing)),
        Transport = maps:get(transport_opts, S, #{}),
        ?assertEqual(true, maps:get(ssl, Transport, false))
    end, MgmtListeners),
    %% auth_fun must appear on NOTHING but mgmt listeners.
    lists:foreach(fun(S) ->
        case is_mgmt(S) of
            true  -> ok;
            false ->
                ?assertEqual(missing,
                             maps:get(auth_fun, maps:get(grpc_opts, S, #{}), missing))
        end
    end, Servers),
    %% Pins configured and non-empty.
    YuzuEnv = proplists:get_value(yuzu_gw, Cfg, []),
    Pins = proplists:get_value(mgmt_peer_pins, YuzuEnv, []),
    ?assertMatch([_ | _], Pins).

%%%-------------------------------------------------------------------
%%% helpers
%%%-------------------------------------------------------------------

consult(Path) ->
    ?assert(filelib:is_regular(Path)),
    {ok, [Cfg]} = file:consult(Path),
    Cfg.

servers(Cfg) ->
    Grpcbox = proplists:get_value(grpcbox, Cfg, []),
    proplists:get_value(servers, Grpcbox, []).

mgmt_listeners(Cfg) ->
    [S || S <- servers(Cfg), is_mgmt(S)].

is_mgmt(S) when is_map(S) ->
    Protos = maps:get(service_protos, maps:get(grpc_opts, S, #{}), []),
    lists:member(management_pb, Protos);
is_mgmt(_) ->
    false.

listen_ip(S) ->
    maps:get(ip, maps:get(listen_opts, S, #{}), undefined).
