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
%%%     from the strict posture);
%%%   - no config carries the listener keys nothing reads (agent_listen_*,
%%%     mgmt_listen_*): the ports and addresses are the `listen' of the entries;
%%%   - the sys.config embedded in docker-compose.uat.yml (YAML, so it is cut out
%%%     of the file) passes the same decisions as the standalone ones.
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

%% The keys of the former listener settings, which nothing reads any more; a
%% copy would read as the place the port or the bind address is set.
dead_listener_keys() ->
    [agent_listen_addr, agent_listen_port, mgmt_listen_addr, mgmt_listen_port].

no_config_carries_dead_listener_keys_test_() ->
    [{Path, fun() ->
                Env = proplists:get_value(yuzu_gw, consult(Path), []),
                ?assertEqual([], [K || K <- dead_listener_keys(), proplists:is_defined(K, Env)])
            end}
     || Path <- ["config/test.config" | listener_configs()]].

%% The suites start their own listeners; a gateway with none refuses to boot
%% unless the configuration says that is meant.
test_config_allows_no_listeners_test() ->
    Env = proplists:get_value(yuzu_gw, consult("config/test.config"), []),
    ?assertEqual(true, proplists:get_value(allow_no_listeners, Env)),
    ?assertEqual([], proplists:get_value(grpc_listeners, Env, [])).

%% {allow_no_listeners, true} is the acknowledgement of a gateway under test or
%% one that serves nothing; a shipped config that carried it would boot with no
%% agent listener, or none at all, and answer /healthz. Only config/test.config
%% sets it (above). Every shipped config also has the agent listener boot asks for.
no_shipped_config_allows_no_listeners_test_() ->
    [{Path, fun() ->
                Env = proplists:get_value(yuzu_gw, consult(Path), []),
                ?assertEqual(undefined, proplists:get_value(allow_no_listeners, Env)),
                ?assert(lists:any(fun yuzu_grpc_listener:serves_agent/1, listeners(consult(Path))))
            end}
     || Path <- listener_configs()].

%% The compose file's inline gateway config: the lines under
%% `gateway-sys-config:' / `content: |', up to the first line indented less
%% than the block, with the block's indent removed.
uat_compose_inline_config_test() ->
    {ok, Bin} = file:read_file("../docker-compose.uat.yml"),
    Lines = string:split(binary_to_list(Bin), "\n", all),
    [_ | AfterHeader] = lists:dropwhile(fun(L) -> L =/= "  gateway-sys-config:" end, Lines),
    ?assertMatch(["    content: |" | _], AfterHeader),
    [_ | Block] = AfterHeader,
    Body = lists:takewhile(fun(L) -> L =:= "" orelse lists:prefix("      ", L) end, Block),
    Text = string:join([drop6(L) || L <- Body], "\n"),
    {ok, Tokens, _} = erl_scan:string(Text),
    {ok, Cfg} = erl_parse:parse_term(Tokens),
    YuzuEnv = proplists:get_value(yuzu_gw, Cfg, []),
    Listeners = proplists:get_value(grpc_listeners, YuzuEnv, []),
    ?assertMatch([_, _], Listeners),
    ?assertEqual(ok, yuzu_gw_app:evaluate_listeners(Listeners)),
    ?assertEqual(true, proplists:get_value(allow_insecure_mgmt, YuzuEnv)),
    ?assertEqual(undefined, proplists:get_value(allow_no_listeners, YuzuEnv)),
    ?assert(lists:any(fun yuzu_grpc_listener:serves_agent/1, Listeners)),
    ?assertMatch({ok_insecure, _},
                 yuzu_gw_app:evaluate_mgmt_posture(Listeners, [], true)),
    ?assertEqual([], [K || K <- dead_listener_keys(), proplists:is_defined(K, YuzuEnv)]),
    ?assertEqual(undefined, proplists:get_value(servers, proplists:get_value(grpcbox, Cfg, []))).

%% The sys.config the compose wizard emits for a gateway stack, one golden file
%% per TLS mode (tests/fixtures/compose-wizard/; tests/test_compose_wizard.py
%% proves the wizard still emits exactly these, under node, without Erlang).
%% Here each golden faces the gateway's own boot decisions. A missing golden
%% fails: the half of the check that needs it would otherwise pass blind.
wizard_golden_configs_test_() ->
    [{Mode, fun() -> check_wizard_golden(Mode) end} || Mode <- ["plaintext", "operator"]].

check_wizard_golden(Mode) ->
    Cfg = consult("../tests/fixtures/compose-wizard/gateway-sys.config." ++ Mode),
    YuzuEnv = proplists:get_value(yuzu_gw, Cfg, []),
    Listeners = listeners(Cfg),
    ?assertMatch([_, _], Listeners),
    ?assertEqual(ok, yuzu_gw_app:evaluate_listeners(Listeners)),
    %% the lab posture: plaintext mgmt listener behind the explicit acknowledgement
    ?assertEqual(true, proplists:get_value(allow_insecure_mgmt, YuzuEnv)),
    Pins = proplists:get_value(mgmt_peer_pins, YuzuEnv, []),
    ?assertMatch({ok_insecure, _}, yuzu_gw_app:evaluate_mgmt_posture(Listeners, Pins, true)),
    ?assertMatch({error, {insecure_mgmt_listener, _}},
                 yuzu_gw_app:evaluate_mgmt_posture(Listeners, Pins, false)),
    ?assertEqual([], [K || K <- dead_listener_keys(), proplists:is_defined(K, YuzuEnv)]),
    ?assertEqual(undefined, proplists:get_value(servers, proplists:get_value(grpcbox, Cfg, []))),
    ?assertEqual(undefined, proplists:get_value(allow_no_listeners, YuzuEnv)),
    ?assert(lists:any(fun yuzu_grpc_listener:serves_agent/1, Listeners)),
    ?assertMatch([_], mgmt_listeners(Cfg)).

drop6(L) -> case lists:prefix("      ", L) of true -> lists:nthtail(6, L); false -> L end.

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

%% The shipped production shapes bound the unauthenticated agent edge: a finite
%% connection ceiling under the systemd unit's LimitNOFILE (65536) with room for
%% the other descriptors, and a stated message ceiling. The numbers and the
%% reasoning are in the config's own comments.
agent_edge_is_bounded_in_the_production_configs_test_() ->
    [{Path, fun() ->
                [Agent] = [L || L <- listeners(consult(Path)),
                                lists:member(agent_pb, maps:get(service_protos, L, []))],
                #{max_connections := Max, max_message_bytes := Bytes} = maps:get(limits, Agent),
                ?assert(is_integer(Max) andalso Max > 0 andalso Max =< 65536 - 5000),
                ?assertEqual(4194304, Bytes)
            end}
     || Path <- strict_configs()].

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
