%%%-------------------------------------------------------------------
%%% @doc Static posture checks over the TRACKED gateway config files.
%%%
%%% Parses each real sys.config with file:consult (so a syntax slip,
%%% including in the `fun M:F/1' auth_fun term, fails here, not at a
%%% container boot) and asserts, through the same pure decision functions the
%%% boot guards use:
%%%
%%%   - no config carries a `{grpcbox, ...}' block with a `servers' or a `client'
%%%     key (either refuses boot: nothing reads them, and OTP does not apply a
%%%     sys.config entry to an application that is not loaded), every config
%%%     names its upstream channels in `{yuzu_gw, upstream_client}' with a
%%%     `default_channel', and every `{yuzu_gw, grpc_listeners}' list is one
%%%     `evaluate_listeners/1' accepts;
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
%%% The last groups exercise the boot guards over the upstream channels,
%%% `yuzu_gw_app:check_upstream_client_config/0' (with `{yuzu_gw,
%%% upstream_client}' set per case and restored after), and the scan for a
%%% leftover `{grpcbox, ...}' block in config files,
%%% `yuzu_gw_app:legacy_grpcbox_in_files/2', over temporary files.
%%%
%%% Paths are relative to the gateway/ project root (rebar3 eunit's cwd).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_config_posture_tests).
-include_lib("eunit/include/eunit.hrl").

-define(AUTH_FUN, fun yuzu_gw_authz:check_mgmt_peer/1).

%% A marker for what a refusal must never log: a key file path in an endpoint's
%% SSL options.
-define(SECRET_KEY, "/secret/key.pem").

-export([log/2]). %% logger handler callback, see capture_logs/1

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
    ?assertEqual(undefined, proplists:get_value(grpcbox, Cfg)),
    ?assert(has_default_channel(YuzuEnv)).

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
    ?assertEqual(undefined, proplists:get_value(grpcbox, Cfg)),
    ?assert(has_default_channel(YuzuEnv)),
    ?assertEqual(undefined, proplists:get_value(allow_no_listeners, YuzuEnv)),
    ?assert(lists:any(fun yuzu_grpc_listener:serves_agent/1, Listeners)),
    ?assertMatch([_], mgmt_listeners(Cfg)).

drop6(L) -> case lists:prefix("      ", L) of true -> lists:nthtail(6, L); false -> L end.

consult_strict_configs_test_() ->
    [{Path, fun() -> check_strict(Path) end} || Path <- strict_configs()].

consult_rig_configs_test_() ->
    [{Path, fun() -> check_rig(Path) end} || Path <- rig_configs()].

%% A leftover {grpcbox, servers} or {grpcbox, client} refuses boot
%% (yuzu_gw_app:check_legacy_grpcbox_servers/0, check_legacy_grpcbox_client/0),
%% so no tracked config may carry one; the upstream channels are
%% {yuzu_gw, upstream_client}, and a gateway without a `default_channel' there
%% refuses boot too (check_upstream_client_config/0).
no_config_has_legacy_grpcbox_blocks_test_() ->
    [{Path, fun() ->
                ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [Path])),
                ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [Path])),
                ?assertEqual(undefined, proplists:get_value(grpcbox, consult(Path))),
                Env = proplists:get_value(yuzu_gw, consult(Path), []),
                ?assert(has_default_channel(Env))
            end}
     || Path <- ["config/test.config" | listener_configs()]].

%% The upstream channels of a yuzu_gw env parse, and one is `default_channel'
%% (what yuzu_gw_upstream and yuzu_gw_heartbeat_buffer call).
has_default_channel(YuzuEnv) ->
    case yuzu_grpc_client_config:channels(proplists:get_value(upstream_client, YuzuEnv)) of
        {ok, Channels} -> lists:any(fun(#{name := N}) -> N =:= default_channel end, Channels);
        {error, _}     -> false
    end.

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
%%% The upstream channel guard: yuzu_gw_app:check_upstream_client_config/0
%%%-------------------------------------------------------------------

upstream_client_config_accepts_test_() ->
    Https = {https, "gw-upstream.example", 50051,
             [{verify, verify_peer}, {cacertfile, "/secret/ca.pem"},
              {certfile, "/secret/cert.pem"}, {keyfile, ?SECRET_KEY}]},
    Plain = #{channels => [{default_channel, [{http, "127.0.0.1", 50051, []}], #{}}]},
    [{"a plaintext default_channel",
      fun() ->
          with_upstream_env(Plain, unset, fun() ->
              ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config())
          end)
      end},
     {"an https default_channel with TLS options",
      fun() ->
          with_upstream_env(#{channels => [{default_channel, [Https], #{pool_size => 4}}]},
                            unset, fun() ->
              ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config())
          end)
      end},
     {"a default_channel among other channels",
      fun() ->
          with_upstream_env(#{channels => [{other, [{http, "127.0.0.1", 50052, []}], #{}},
                                           {default_channel, [Https], #{}}]},
                            unset, fun() ->
              ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config())
          end)
      end}].

%% No channel the gateway can use: not configured at all, or none named
%% `default_channel' (the name yuzu_gw_upstream and yuzu_gw_heartbeat_buffer
%% call). A gateway like that registers no agent and answers /readyz, so it is
%% refused, unless {yuzu_gw, allow_no_upstream} is the literal `true'.
upstream_client_config_requires_a_default_channel_test_() ->
    NoDefault = #{channels => [{other, [{http, "127.0.0.1", 50052, []}], #{}}]},
    [{"no upstream_client at all is refused",
      fun() ->
          with_upstream_env(unset, unset, fun() ->
              ?assertEqual({error, no_upstream_channel},
                           yuzu_gw_app:check_upstream_client_config())
          end)
      end},
     {"an empty channel list is refused",
      fun() ->
          with_upstream_env(#{channels => []}, unset, fun() ->
              ?assertEqual({error, no_upstream_channel},
                           yuzu_gw_app:check_upstream_client_config())
          end)
      end},
     {"channels none of which is default_channel are refused",
      fun() ->
          with_upstream_env(NoDefault, unset, fun() ->
              ?assertEqual({error, no_upstream_channel},
                           yuzu_gw_app:check_upstream_client_config())
          end)
      end},
     {"{allow_no_upstream, true} excuses having none",
      fun() ->
          [with_upstream_env(V, true, fun() ->
               ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config())
           end) || V <- [unset, #{channels => []}, NoDefault]]
      end},
     {"only the literal true counts as the acknowledgement",
      fun() ->
          [with_upstream_env(unset, Ack, fun() ->
               ?assertEqual({error, no_upstream_channel},
                            yuzu_gw_app:check_upstream_client_config(), Ack)
           end) || Ack <- [false, "true", <<"true">>, 1, yes]]
      end},
     {"the acknowledgement does not excuse an unusable channel value",
      fun() ->
          with_upstream_env(not_a_map, true, fun() ->
              ?assertEqual({error, bad_upstream_client_config},
                           yuzu_gw_app:check_upstream_client_config())
          end)
      end},
     {"the refusal says where the channels are configured and how to excuse it",
      fun() ->
          with_upstream_env(unset, unset, fun() ->
              Text = lists:flatten(capture_logs(fun() ->
                  {error, no_upstream_channel} = yuzu_gw_app:check_upstream_client_config()
              end)),
              {match, _} = re:run(Text, "Refusing to start: no upstream channel is configured",
                                  [unicode]),
              {match, _} = re:run(Text, "upstream_client", [unicode])
          end)
      end}].

upstream_client_config_refuses_test_() ->
    Refused = [
        {"a client value that is not a map", not_a_map},
        {"a client value that is a list of channels, not a map",
         [{default_channel, [{http, "127.0.0.1", 50051, []}], #{}}]},
        {"a channel with an empty endpoint list",
         #{channels => [{default_channel, [], #{}}]}},
        {"an endpoint with a port of zero",
         #{channels => [{default_channel, [{http, "127.0.0.1", 0, []}], #{}}]}},
        {"an endpoint with a port above 65535",
         #{channels => [{default_channel, [{http, "127.0.0.1", 65536, []}], #{}}]}},
        {"an endpoint whose port is a string",
         #{channels => [{default_channel, [{http, "127.0.0.1", "50051", []}], #{}}]}},
        {"an endpoint whose socket_options are not a list",
         #{channels => [{default_channel,
                         [{http, "127.0.0.1", 50051, [], #{socket_options => nodelay}}],
                         #{}}]}},
        {"a good channel followed by a bad one",
         #{channels => [{default_channel, [{http, "127.0.0.1", 50051, []}], #{}},
                        {bad, [{http, "127.0.0.1", 0, []}], #{}}]}}],
    [{Title, fun() ->
                 with_upstream_env(Value, unset, fun() ->
                     ?assertEqual({error, bad_upstream_client_config},
                                  yuzu_gw_app:check_upstream_client_config())
                 end)
             end}
     || {Title, Value} <- Refused].

%% The refusal says what is wrong in shape only. An endpoint's SSL options name
%% key files, and the log of a refused boot is read by operators and shipped.
upstream_client_config_refusal_logs_no_ssl_options_test_() ->
    Ssl = [{certfile, "/secret/cert.pem"}, {keyfile, ?SECRET_KEY},
           {cacertfile, "/secret/ca.pem"}, {password, "hunter2"}],
    Cases = [
        {"a bad port", {https, "gw-upstream.example", 0, Ssl}},
        {"a bad port that is itself the key path", {https, "gw-upstream.example", ?SECRET_KEY, Ssl}},
        {"non-list socket_options", {https, "gw-upstream.example", 50051, Ssl,
                                     #{socket_options => list_to_binary(?SECRET_KEY)}}},
        {"a bad scheme", {tls, "gw-upstream.example", 50051, Ssl}},
        {"an endpoint of the wrong shape", {https, "gw-upstream.example", 50051, Ssl, #{}, extra}}],
    [{Title, fun() ->
                 with_upstream_env(#{channels => [{default_channel, [Endpoint], #{}}]}, unset, fun() ->
                     Text = lists:flatten(capture_logs(fun() ->
                         ?assertEqual({error, bad_upstream_client_config},
                                      yuzu_gw_app:check_upstream_client_config())
                     end)),
                     {match, _} = re:run(Text, "Refusing to start: the upstream channel configuration",
                                         [unicode]),
                     [?assertEqual(nomatch, re:run(Text, Needle, [unicode, {capture, none}]))
                      || Needle <- ["/secret", "key\\.pem", "keyfile", "cert\\.pem",
                                    "hunter2", "gw-upstream\\.example"]]
                 end)
             end}
     || {Title, Endpoint} <- Cases].

%%%-------------------------------------------------------------------
%%% A leftover {grpcbox, ...} block
%%%-------------------------------------------------------------------

%% OTP applies a sys.config entry only to a LOADED application and none is named
%% grpcbox, so a leftover block is invisible to the application env: the guards
%% read the config files the VM was started with instead.
legacy_grpcbox_in_files_test_() ->
    Client = "[{grpcbox, [{client, #{channels => []}}]}].\n",
    Servers = "[{grpcbox, [{servers, [#{listen_opts => #{port => 50051}}]}]}].\n",
    [{"a {grpcbox, [{client, _}]} block is found for client and not for servers",
      with_files([{"a.config", Client}], fun([A]) ->
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [A])),
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [A]))
      end)},
     {"a {grpcbox, [{servers, _}]} block is found for servers and not for client",
      with_files([{"a.config", Servers}], fun([A]) ->
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(servers, [A])),
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [A]))
      end)},
     {"both keys in one block are each found",
      with_files([{"a.config", "[{grpcbox, [{servers, [x]}, {client, #{channels => []}}]}].\n"}],
                 fun([A]) ->
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(servers, [A])),
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [A]))
      end)},
     {"an empty or undefined value is no key",
      with_files([{"empty.config", "[{grpcbox, [{servers, []}, {client, []}]}].\n"},
                  {"undef.config", "[{grpcbox, [{servers, undefined}, {client, undefined}]}].\n"},
                  {"none.config", "[{grpcbox, []}].\n"}],
                 fun(Paths) ->
          [begin
               ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [P])),
               ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [P]))
           end || P <- Paths]
      end)},
     {"the same keys under another application are not a grpcbox block",
      with_files([{"a.config",
                   "[{yuzu_gw, [{client, #{channels => []}}, {servers, [x]}]}].\n"}],
                 fun([A]) ->
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [A])),
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [A]))
      end)},
     {"a path may be given with or without the .config suffix",
      with_files([{"a.config", Client}], fun([A]) ->
          ?assertEqual(".config", filename:extension(A)),
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [filename:rootname(A)])),
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [A]))
      end)},
     {"a file name inside a config is followed, with or without the suffix",
      with_files([{"inner.config", Client}], fun([Inner]) ->
          Dir = filename:dirname(Inner),
          Outer = write_file(Dir, "outer.config",
                             io_lib:format("[{yuzu_gw, []}, ~p].\n", [filename:rootname(Inner)])),
          Outer2 = write_file(Dir, "outer2.config",
                              io_lib:format("[{yuzu_gw, []}, ~p].\n", [Inner])),
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [Outer])),
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [Outer2])),
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [Outer]))
      end)},
     {"a chain of four files is followed to its end",
      with_files([{"l4.config", Client}], fun([L4]) ->
          Dir = filename:dirname(L4),
          L3 = write_file(Dir, "l3.config", io_lib:format("[~p].\n", [L4])),
          L2 = write_file(Dir, "l2.config", io_lib:format("[~p].\n", [L3])),
          L1 = write_file(Dir, "l1.config", io_lib:format("[~p].\n", [L2])),
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [L1]))
      end)},
     {"a config that names itself ends the scan",
      with_files([{"loop.config", ""}], fun([Loop]) ->
          ok = file:write_file(Loop, io_lib:format("[~p, {yuzu_gw, []}].\n", [Loop])),
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [Loop]))
      end)},
     {"a file that does not parse is skipped, and does not hide a later one",
      with_files([{"bad.config", "[{grpcbox, [{client, \n"}, {"good.config", Client}],
                 fun([Bad, Good]) ->
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [Bad])),
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [Bad, Good]))
      end)},
     {"a config that is not a list of terms is skipped",
      with_files([{"odd.config", "#{grpcbox => {client, x}}.\n"}], fun([Odd]) ->
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [Odd]))
      end)},
     {"a missing file and no files at all are absent",
      with_files([{"a.config", Client}], fun([A]) ->
          Missing = filename:join(filename:dirname(A), "missing_file"),
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [Missing])),
          ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [])),
          %% a missing file does not hide one that is there
          ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [Missing, A]))
      end)}].

%% A value set at run time is a leftover too; the refusal says where the value
%% belongs.
legacy_grpcbox_client_in_the_env_is_refused_test() ->
    Prev = application:get_env(grpcbox, client),
    application:set_env(grpcbox, client,
                        #{channels => [{default_channel, [{http, "127.0.0.1", 50051, []}], #{}}]}),
    try
        Text = lists:flatten(capture_logs(fun() ->
            ?assertEqual({error, legacy_grpcbox_client}, yuzu_gw_app:check_legacy_grpcbox_client())
        end)),
        {match, _} = re:run(Text, "Refusing to start: \\{grpcbox, \\[\\{client, \\.\\.\\.\\}\\]\\} is set",
                            [unicode]),
        {match, _} = re:run(Text, "upstream_client", [unicode])
    after
        case Prev of
            {ok, V}   -> application:set_env(grpcbox, client, V);
            undefined -> application:unset_env(grpcbox, client)
        end
    end.

%% Temporary config files under a `yuzu_test_'-prefixed directory with a unique
%% name, removed afterwards. Files is [{Name, Text}]; Fun gets their paths.
with_files(Files, Fun) ->
    fun() ->
        Base = case os:getenv("TMPDIR") of
            false -> "/tmp";
            ""    -> "/tmp";
            D     -> D
        end,
        Dir = filename:join(Base, "yuzu_test_gw_posture_" ++ os:getpid() ++ "_"
                                  ++ integer_to_list(erlang:unique_integer([positive]))),
        ok = filelib:ensure_path(Dir),
        try
            Fun([write_file(Dir, Name, Text) || {Name, Text} <- Files])
        after
            _ = file:del_dir_r(Dir)
        end
    end.

write_file(Dir, Name, Text) ->
    Path = filename:join(Dir, Name),
    ok = file:write_file(Path, Text),
    Path.

%% Run Fun with `{yuzu_gw, upstream_client}' set to Value and `{yuzu_gw,
%% allow_no_upstream}' to Allow (`unset' removes either), and put back what was
%% there.
with_upstream_env(Value, Allow, Fun) ->
    Keys = [{upstream_client, Value}, {allow_no_upstream, Allow}],
    Prev = [{K, application:get_env(yuzu_gw, K)} || {K, _} <- Keys],
    [set_or_unset(K, V) || {K, V} <- Keys],
    try
        Fun()
    after
        [case P of
             {ok, V}   -> application:set_env(yuzu_gw, K, V);
             undefined -> application:unset_env(yuzu_gw, K)
         end || {K, P} <- Prev]
    end.

set_or_unset(K, unset) -> application:unset_env(yuzu_gw, K);
set_or_unset(K, V)     -> application:set_env(yuzu_gw, K, V).

%% The log events of Fun, as text. The handler takes everything (no filters), so
%% what is captured is what the code under test logged, at any level.
capture_logs(Fun) ->
    Id = yuzu_gw_config_posture_tests_handler,
    Primary = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Fun(),
        drain_logs([])
    after
        ok = logger:remove_handler(Id),
        ok = logger:set_primary_config(level, Primary)
    end.

drain_logs(Acc) ->
    receive
        {logged, #{msg := {Fmt, Args}}} when is_list(Fmt), is_list(Args) ->
            drain_logs([io_lib:format(Fmt, Args) | Acc]);
        {logged, #{msg := {string, Text}}} ->
            drain_logs([io_lib:format("~ts", [Text]) | Acc]);
        {logged, _} ->
            drain_logs(Acc)
    after 0 ->
        lists:reverse(Acc)
    end.

log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {logged, Event},
    ok.

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
