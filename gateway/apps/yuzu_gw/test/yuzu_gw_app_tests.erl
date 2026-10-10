%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_app: the distribution cookie guard (#659), the
%%% guards over the listener configuration ({grpcbox, servers} refused, the
%%% {yuzu_gw, grpc_listeners} entries validated, the listener port overrides of
%%% the environment) and the boot wiring around them.
%%%
%%% evaluate_cookie/3 is the pure policy decision behind the boot guard
%%% that refuses to start with a known-insecure Erlang distribution cookie
%%% (the cookie is the sole authentication for inter-node RPC; a publicly
%%% known value is unauthenticated remote code execution via EPMD).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_app_tests).
-include_lib("eunit/include/eunit.hrl").

%% A non-distributed node has no inter-node attack surface, so no cookie is
%% ever rejected — this keeps eunit/CT (which run as nonode@nohost) unaffected.
non_distributed_accepts_any_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('nonode@nohost', 'yuzu_gw_secret_change_me', false)),
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('nonode@nohost', '', false)).

%% The historical committed default must fail closed once distribution is up.
default_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'yuzu_gw_secret_change_me', false)).

%% An empty cookie (e.g. unsubstituted ${YUZU_GW_COOKIE}) is equally insecure.
empty_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', '', false)).

%% The explicit dev/CI override permits the default cookie.
override_allows_default_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'yuzu_gw_secret_change_me', true)).

%% A strong unique cookie is accepted when distributed.
strong_cookie_accepted_when_distributed_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1',
                                    'a3f9c1e2b7d84056a3f9c1e2b7d84056f0e1d2c3', false)).

%% #659 UP-1: if relx `.src` substitution fails, the cookie atom is the literal
%% `${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}`. Substring matching must catch it
%% (it embeds the default), otherwise the unauthenticated-RPC surface re-opens.
literal_unsubstituted_default_rejected_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1',
                                    '${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}', false)).

%% A bare unsubstituted placeholder (no fallback) is rejected via the `${` check.
unsubstituted_placeholder_rejected_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', '${YUZU_GW_COOKIE}', false)).

%%%===================================================================
%%% HA WS-4 #4555 — minimum cookie length floor (ADR-2002 §7b)
%%%===================================================================

%% A short but otherwise well-formed custom cookie is still insecure: DNS-based
%% discovery lets a node dial addresses it did not choose by hand, and the
%% distribution handshake's initiator sends the cookie hash first — a short
%% cookie is brute-forceable offline. Not the known-default substring, so this
%% exercises the length floor specifically, not the #659 default-cookie check.
short_custom_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'too_short_cookie', false)).

%% Exactly at the floor (32 chars) is accepted.
cookie_at_minimum_length_accepted_test() ->
    Cookie = list_to_atom(lists:duplicate(32, $a)),
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', Cookie, false)).

%% One character short of the floor is rejected.
cookie_one_below_minimum_length_rejected_test() ->
    Cookie = list_to_atom(lists:duplicate(31, $a)),
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', Cookie, false)).

%% The existing dev/CI override also covers a too-short (not just default) cookie.
override_allows_short_custom_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'too_short_cookie', true)).

%%%===================================================================
%%% Listener configuration guards
%%%
%%% These read the application environment and the process environment, so each
%%% runs in a fixture that saves, clears and restores every key it can touch.
%%%===================================================================

-define(ENV_KEYS, [{yuzu_gw, grpc_listeners}, {yuzu_gw, allow_insecure_mgmt},
                   {yuzu_gw, mgmt_peer_pins}, {yuzu_gw, agent_listen_port},
                   {yuzu_gw, mgmt_listen_port}, {grpcbox, servers}]).
-define(PORT_VARS, ["YUZU_GW_AGENT_PORT", "YUZU_GW_MGMT_PORT"]).

env_setup() ->
    Saved = {[{K, application:get_env(A, Key)} || {A, Key} = K <- ?ENV_KEYS],
             [{V, os:getenv(V)} || V <- ?PORT_VARS]},
    [application:unset_env(A, Key) || {A, Key} <- ?ENV_KEYS],
    [os:unsetenv(V) || V <- ?PORT_VARS],
    Saved.

env_cleanup({AppEnv, OsEnv}) ->
    [case Value of
         {ok, V} -> application:set_env(A, Key, V);
         undefined -> application:unset_env(A, Key)
     end || {{A, Key}, Value} <- AppEnv],
    [case Value of
         false -> os:unsetenv(Var);
         V -> os:putenv(Var, V)
     end || {Var, Value} <- OsEnv],
    ok.

env_case(Tests) ->
    {foreach, fun env_setup/0, fun env_cleanup/1, Tests}.

agent_entry() ->
    #{name => agent,
      service_protos => [agent_pb],
      services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service},
      listen => #{port => 50051, ip => {0, 0, 0, 0}}}.

mgmt_entry() ->
    #{name => mgmt,
      service_protos => [management_pb],
      services => #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service},
      listen => #{port => 50063, ip => {0, 0, 0, 0}},
      tls => #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => "ca.pem"},
      auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1}.

%% A leftover {grpcbox, servers} would make the grpcbox application bind a
%% listener of its own, next to ours and without the management peer pin: boot
%% refuses it. Only the upstream {client, ...} may remain in the grpcbox env.
check_legacy_grpcbox_servers_test_() ->
    env_case(
      [{"no servers key is fine",
        fun() ->
            ?assertEqual(ok, yuzu_gw_app:check_legacy_grpcbox_servers())
        end},
       {"an empty servers list is fine",
        fun() ->
            application:set_env(grpcbox, servers, []),
            ?assertEqual(ok, yuzu_gw_app:check_legacy_grpcbox_servers())
        end},
       {"a servers key set to undefined is fine",
        fun() ->
            application:set_env(grpcbox, servers, undefined),
            ?assertEqual(ok, yuzu_gw_app:check_legacy_grpcbox_servers())
        end},
       {"a non-empty servers list is refused",
        fun() ->
            application:set_env(grpcbox, servers,
                                [#{grpc_opts => #{service_protos => [agent_pb], services => #{}},
                                   listen_opts => #{port => 50051}}]),
            ?assertEqual({error, legacy_grpcbox_servers},
                         yuzu_gw_app:check_legacy_grpcbox_servers())
        end},
       {"anything else under servers is refused too",
        fun() ->
            application:set_env(grpcbox, servers, not_a_list),
            ?assertEqual({error, legacy_grpcbox_servers},
                         yuzu_gw_app:check_legacy_grpcbox_servers())
        end}]).

%% The guard over the configured entries: no entries is allowed (a gateway
%% under test, or one that only routes), an invalid one is refused.
check_grpc_listeners_test_() ->
    env_case(
      [{"no listeners configured is allowed",
        fun() ->
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners()),
            application:set_env(yuzu_gw, grpc_listeners, []),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners())
        end},
       {"the agent and management listeners of the shipped shape are accepted",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [agent_entry(), mgmt_entry()]),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners())
        end},
       {"an invalid entry refuses boot",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners,
                                [agent_entry(), (mgmt_entry())#{tls := #{certfile => "gw.pem"}}]),
            ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"a value that is not a list refuses boot",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, #{agent => agent_entry()}),
            ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:check_grpc_listeners())
        end}]).

%% The guard on the privileged command plane, over the configured entries and
%% the configured pins. {yuzu_gw, allow_insecure_mgmt} is an acknowledgement for
%% lab rigs and counts only as the literal `true`.
check_mgmt_listener_posture_test_() ->
    Set = fun(Listeners) -> application:set_env(yuzu_gw, grpc_listeners, Listeners) end,
    Pins = fun() -> application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, "srv.pem"}]) end,
    Plain = (mgmt_entry())#{name => plain},
    PlainMgmt = maps:without([tls, auth_fun], Plain),
    env_case(
      [{"no listeners, or no management listener, has nothing to guard",
        fun() ->
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture()),
            Set([agent_entry()]),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"the strict mTLS listener with pins boots",
        fun() ->
            Set([agent_entry(), mgmt_entry()]),
            Pins(),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"without pins it is refused",
        fun() ->
            Set([agent_entry(), mgmt_entry()]),
            ?assertEqual({error, insecure_mgmt_listener}, yuzu_gw_app:check_mgmt_listener_posture()),
            application:set_env(yuzu_gw, mgmt_peer_pins, []),
            ?assertEqual({error, insecure_mgmt_listener}, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"a plaintext listener on the wildcard address is refused",
        fun() ->
            Set([agent_entry(), PlainMgmt]),
            Pins(),
            ?assertEqual({error, insecure_mgmt_listener}, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"a plaintext listener on loopback boots",
        fun() ->
            Set([PlainMgmt#{listen := #{port => 50063, ip => {127, 0, 0, 1}}}]),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"a proxied management listener is refused even with the full posture",
        fun() ->
            Set([(mgmt_entry())#{origin => #{mode => proxy_protocol, sources => [{10, 0, 0, 5}]}}]),
            Pins(),
            ?assertEqual({error, insecure_mgmt_listener}, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"allow_insecure_mgmt => true boots the refused listener",
        fun() ->
            Set([PlainMgmt]),
            application:set_env(yuzu_gw, allow_insecure_mgmt, true),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"anything but the literal true is not the acknowledgement",
        fun() ->
            Set([PlainMgmt]),
            lists:foreach(
              fun(Value) ->
                  application:set_env(yuzu_gw, allow_insecure_mgmt, Value),
                  ?assertEqual({error, insecure_mgmt_listener},
                               yuzu_gw_app:check_mgmt_listener_posture(), Value)
              end, [false, "true", <<"true">>, 1, yes])
        end}]).

evaluate_listeners_accepts_the_shipped_shape_test() ->
    ?assertEqual(ok, yuzu_gw_app:evaluate_listeners([agent_entry(), mgmt_entry()])),
    ?assertEqual(ok, yuzu_gw_app:evaluate_listeners([])),
    %% Port 0 is "any free port": two of them do not clash.
    ?assertEqual(ok, yuzu_gw_app:evaluate_listeners(
                       [with_listen(agent_entry(), #{port => 0}),
                        (with_listen(agent_entry(), #{port => 0}))#{name => agent2}])).

evaluate_listeners_refuses_what_is_not_a_listener_list_test_() ->
    [?_assertEqual({error, [{unknown, grpc_listeners_not_a_list}]},
                   yuzu_gw_app:evaluate_listeners(not_a_list)),
     ?_assertEqual({error, [{unknown, grpc_listeners_not_a_list}]},
                   yuzu_gw_app:evaluate_listeners(agent_entry())),
     ?_assertEqual({error, [{unknown, entry_not_a_map}]},
                   yuzu_gw_app:evaluate_listeners([not_a_map])),
     ?_assertEqual({error, [{unknown, entry_not_a_map}]},
                   yuzu_gw_app:evaluate_listeners([{name, agent}]))].

evaluate_listeners_names_the_defect_of_each_invalid_entry_test_() ->
    Bad = fun(Entry) ->
              {error, Defects} = yuzu_gw_app:evaluate_listeners([Entry]),
              Defects
          end,
    [{"missing keys",
      ?_assertEqual([{agent, {missing_keys, [services, listen]}}],
                    Bad(maps:without([services, listen], agent_entry())))},
     {"an entry with no name is reported as unknown",
      ?_assertEqual([{unknown, {missing_keys, [name]}}],
                    Bad(maps:without([name], agent_entry())))},
     {"a listen map without a usable port",
      [?_assertEqual([{agent, bad_listen}],
                     Bad(with_listen(agent_entry(), #{ip => {0, 0, 0, 0}}))),
       ?_assertEqual([{agent, bad_listen}],
                     Bad(with_listen(agent_entry(), #{port => 70000})))]},
     {"a tls map must carry certfile, keyfile and cacertfile",
      [?_assertEqual([{mgmt, {tls_incomplete, [cacertfile]}}],
                     Bad((mgmt_entry())#{tls := #{certfile => "gw.pem", keyfile => "gw.key"}})),
       ?_assertEqual([{mgmt, {tls_incomplete, [certfile, keyfile, cacertfile]}}],
                     Bad((mgmt_entry())#{tls := #{}})),
       ?_assertEqual([{mgmt, {tls_incomplete, [cacertfile]}}],
                     Bad((mgmt_entry())#{tls := #{certfile => "gw.pem", keyfile => "gw.key",
                                                  cacertfile => ""}}))]},
     {"a tls value that is not a map",
      ?_assertEqual([{mgmt, bad_tls}], Bad((mgmt_entry())#{tls := "gw.pem"}))},
     {"an auth_fun needs a tls map to authenticate",
      ?_assertEqual([{agent, auth_fun_without_tls}],
                    Bad((agent_entry())#{auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1}))},
     {"a proxied origin must name the proxies it trusts",
      [?_assertEqual([{agent, origin_sources_required}],
                     Bad((agent_entry())#{origin => #{mode => proxy_protocol}})),
       ?_assertEqual([{agent, {unknown_origin_mode, nonsense}}],
                     Bad((agent_entry())#{origin => #{mode => nonsense}}))]},
     {"an auth_fun behind a proxy that terminates TLS",
      ?_assertEqual([{mgmt, auth_fun_behind_terminating_proxy}],
                    Bad((mgmt_entry())#{origin => #{mode => forwarded_for,
                                                    sources => [{10, 0, 0, 5}]}}))},
     {"options the layer owns cannot be set through http2",
      ?_assertEqual([{agent, {reserved_http2_options, [proxy_header]}}],
                    Bad((agent_entry())#{http2 => #{proxy_header => true}}))}].

%% The route table is built here too, so a service the proto does not describe
%% or a module that cannot be loaded refuses boot instead of failing when the
%% listener starts.
evaluate_listeners_builds_the_route_table_test_() ->
    Bad = fun(Services) ->
              {error, Defects} = yuzu_gw_app:evaluate_listeners(
                                   [(agent_entry())#{services := Services}]),
              Defects
          end,
    [?_assertEqual([{agent, {bad_routes, {unknown_service, 'yuzu.agent.v1.NoSuchService'}}}],
                   Bad(#{'yuzu.agent.v1.NoSuchService' => yuzu_gw_agent_service})),
     ?_assertEqual([{agent, {bad_routes, {module_not_loaded, yuzu_gw_no_such_service}}}],
                   Bad(#{'yuzu.agent.v1.AgentService' => yuzu_gw_no_such_service})),
     %% a service of the other proto is not one this listener's protos describe
     ?_assertEqual([{agent, {bad_routes, {unknown_service, 'yuzu.server.v1.ManagementService'}}}],
                   Bad(#{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}))].

evaluate_listeners_refuses_a_name_used_twice_test() ->
    Second = (with_listen(agent_entry(), #{port => 50052}))#{service_protos => [agent_pb]},
    ?assertEqual({error, [{agent, duplicate_name}]},
                 yuzu_gw_app:evaluate_listeners([agent_entry(), Second])).

evaluate_listeners_refuses_a_fixed_port_used_twice_test() ->
    Second = (agent_entry())#{name => other},
    ?assertEqual({error, [{port, {duplicate_port, 50051}}]},
                 yuzu_gw_app:evaluate_listeners([agent_entry(), Second])),
    %% every defect is reported, not only the first
    ?assertEqual({error, [{agent, duplicate_name}, {port, {duplicate_port, 50051}}]},
                 yuzu_gw_app:evaluate_listeners([agent_entry(), agent_entry()])).

listeners_have_tls_test_() ->
    [?_assertEqual(true, yuzu_gw_app:listeners_have_tls([agent_entry(), mgmt_entry()])),
     ?_assertEqual(false, yuzu_gw_app:listeners_have_tls([agent_entry()])),
     ?_assertEqual(false, yuzu_gw_app:listeners_have_tls([])),
     ?_assertEqual(false, yuzu_gw_app:listeners_have_tls([not_a_map])),
     ?_assertEqual(false, yuzu_gw_app:listeners_have_tls((agent_entry())#{tls => none})),
     ?_assertEqual(false, yuzu_gw_app:listeners_have_tls(undefined))].

with_listen(Entry, Listen) ->
    Entry#{listen := Listen}.

%% YUZU_GW_AGENT_PORT / YUZU_GW_MGMT_PORT rewrite the port of the entry that
%% serves agent_pb / management_pb. They are read from the process environment:
%% the {yuzu_gw, agent_listen_port} / {yuzu_gw, mgmt_listen_port} keys the
%% deployed configs still carry are not consulted, and some of them name a port
%% other than the listener's.
apply_listener_port_overrides_test_() ->
    Ports = fun() ->
                [{maps:get(name, L), maps:get(port, maps:get(listen, L))}
                 || L <- application:get_env(yuzu_gw, grpc_listeners, [])]
            end,
    Set = fun(Listeners) -> application:set_env(yuzu_gw, grpc_listeners, Listeners) end,
    env_case(
      [{"both variables move their own listener and nothing else",
        fun() ->
            Set([agent_entry(), mgmt_entry()]),
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            ?assertEqual(ok, yuzu_gw_app:apply_listener_port_overrides()),
            ?assertEqual([{agent, 52001}, {mgmt, 52002}], Ports()),
            %% the rest of the entry is untouched
            [Agent, Mgmt] = application:get_env(yuzu_gw, grpc_listeners, []),
            ?assertEqual({0, 0, 0, 0}, maps:get(ip, maps:get(listen, Agent))),
            ?assertEqual(maps:without([listen], mgmt_entry()), maps:without([listen], Mgmt))
        end},
       {"one variable leaves the other listener alone",
        fun() ->
            Set([agent_entry(), mgmt_entry()]),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual([{agent, 50051}, {mgmt, 52002}], Ports())
        end},
       {"no variable set changes nothing",
        fun() ->
            Set([agent_entry(), mgmt_entry()]),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual([{agent, 50051}, {mgmt, 50063}], Ports())
        end},
       {"port 0 (any free port) is a valid override",
        fun() ->
            Set([agent_entry()]),
            os:putenv("YUZU_GW_AGENT_PORT", "0"),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual([{agent, 0}], Ports())
        end},
       {"an invalid value is ignored",
        fun() ->
            Set([agent_entry(), mgmt_entry()]),
            lists:foreach(
              fun(Bad) ->
                  os:putenv("YUZU_GW_AGENT_PORT", Bad),
                  os:putenv("YUZU_GW_MGMT_PORT", Bad),
                  ok = yuzu_gw_app:apply_listener_port_overrides(),
                  ?assertEqual([{agent, 50051}, {mgmt, 50063}], Ports(), Bad)
              end, ["abc", "", "-1", "65536", "70000", "50051x", "5.5", " 5"])
        end},
       {"the dead agent_listen_port / mgmt_listen_port keys move no listener",
        fun() ->
            Set([agent_entry(), mgmt_entry()]),
            application:set_env(yuzu_gw, agent_listen_port, 53001),
            application:set_env(yuzu_gw, mgmt_listen_port, 53002),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual([{agent, 50051}, {mgmt, 50063}], Ports())
        end},
       {"a listener serving neither proto is left alone",
        fun() ->
            Other = (agent_entry())#{name => other, service_protos => [gateway_pb]},
            Set([Other]),
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual([{other, 50051}], Ports())
        end},
       {"entries that are not listeners are kept as they are",
        fun() ->
            Set([not_a_map, agent_entry()]),
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertMatch([not_a_map, #{name := agent, listen := #{port := 52001}}],
                         application:get_env(yuzu_gw, grpc_listeners, []))
        end},
       {"with no listeners configured it sets nothing",
        fun() ->
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual(undefined, application:get_env(yuzu_gw, grpc_listeners)),
            Set([]),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual({ok, []}, application:get_env(yuzu_gw, grpc_listeners))
        end}]).

%%%===================================================================
%%% Boot wiring
%%%
%%% Every test below boots yuzu_gw_app with the listener, telemetry setup,
%%% supervisor and heartbeat buffer replaced (no port or process is started).
%%% Each runs in a setup/cleanup fixture: eunit kills a test body that
%%% outlives its timeout and a `try ... after' inside the body dies with it,
%%% while the fixture's cleanup still runs, so a cancelled test cannot leave
%%% its mocks, logger filter or environment behind for the next module.
%%%===================================================================

-define(BOOT_MODS, [yuzu_gw_telemetry, prometheus_httpd, yuzu_gw_sup,
                    yuzu_gw_heartbeat_buffer]).
-define(SUMMARY_KEY, {yuzu_gw_heartbeat_admission, summary_state}).
-define(SAFE_CALL_KEYS, [{yuzu_gw_safe_call, S}
                         || S <- [yuzu_gw_upstream, yuzu_gw_registry,
                                  yuzu_gw_agent_sup, yuzu_gw_router]]).
-define(NODELAY_KEY, {?MODULE, nodelay_applied}).

%% yuzu_gw_app:start/2 must create the summary-log state before it starts the
%% metrics listener and the supervision tree. Nothing else boots the app, so
%% without this a deleted or reordered init_summary_state/0 call is invisible
%% (the lazy path in yuzu_gw_heartbeat_admission hides it). The listener and
%% supervisor are replaced by recorders so no port or process is started; each
%% recorder notes whether the state already existed at the moment it ran.
boot_creates_summary_state_before_listener_and_sup_test_() ->
    boot_case(
      fun() ->
          persistent_term:erase(?SUMMARY_KEY),
          Self = self(),
          Note = fun(Tag) ->
                     Self ! {booted, Tag, persistent_term:get(?SUMMARY_KEY, undefined) =/= undefined}
                 end,
          meck:expect(prometheus_httpd, start, fun() -> Note(listener), {ok, self()} end),
          meck:expect(yuzu_gw_sup, start_link, fun() -> Note(supervisor), {ok, self()} end),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(true, receive {booted, listener, S1} -> S1 after 0 -> missing end),
          ?assertEqual(true, receive {booted, supervisor, S2} -> S2 after 0 -> missing end)
      end).

%%%===================================================================
%%% Boot wiring: the upstream crash-report redaction filter (#1197)
%%%===================================================================

%% yuzu_gw_app:start/2 installs the yuzu_gw_crash_redact primary filter before
%% the supervision tree starts (so the upstream's first crash is already
%% redacted) and stop/1 removes it. Nothing else boots the app, so a deleted
%% install or remove call is invisible without this.
boot_installs_crash_filter_before_sup_and_stop_removes_it_test_() ->
    boot_case(
      fun() ->
          Self = self(),
          meck:expect(yuzu_gw_sup, start_link,
                      fun() -> Self ! {sup_started, crash_filter_installed()}, {ok, self()} end),
          ?assertEqual(false, crash_filter_installed()),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(true, receive {sup_started, F} -> F after 0 -> missing end),
          ?assertEqual(true, crash_filter_installed()),
          ?assertEqual(ok, yuzu_gw_app:stop([])),
          ?assertEqual(false, crash_filter_installed())
      end).

%% A supervision tree that does not start must not leave the filter behind.
boot_removes_crash_filter_when_the_tree_does_not_start_test_() ->
    boot_case(
      fun() ->
          meck:expect(yuzu_gw_sup, start_link, fun() -> {error, boom} end),
          ?assertEqual({error, boom}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(false, crash_filter_installed())
      end).

%% yuzu_gw_app:start/2 creates the WARN limit state of yuzu_gw_safe_call before
%% the supervision tree starts, so a burst of first failures shares one limit.
boot_creates_safe_call_limits_before_sup_test_() ->
    boot_case(
      fun() ->
          Keys = ?SAFE_CALL_KEYS,
          [persistent_term:erase(K) || K <- Keys],
          Self = self(),
          meck:expect(yuzu_gw_sup, start_link,
                      fun() ->
                          Self ! {sup_started, [persistent_term:get(K, undefined) =/= undefined
                                                || K <- Keys]},
                          {ok, self()}
                      end),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual([true, true, true, true],
                       receive {sup_started, L} -> L after 0 -> missing end)
      end).

%%%===================================================================
%%% Boot wiring: TCP_NODELAY on the upstream channel
%%%===================================================================

%% yuzu_gw_app:start/2 applies the upstream channel's nodelay rewrite before the
%% supervision tree starts (the tree holds the channel's only callers, so no
%% call can see the channel mid-restart). Nothing else boots the app, so a
%% deleted or reordered apply_nodelay/0 call is invisible without this.
boot_applies_upstream_nodelay_before_sup_test_() ->
    boot_case(
      [yuzu_gw_upstream_channel],
      fun() ->
          Self = self(),
          meck:expect(yuzu_gw_upstream_channel, apply_nodelay,
                      fun() -> persistent_term:put(?NODELAY_KEY, true), ok end),
          meck:expect(yuzu_gw_sup, start_link,
                      fun() ->
                          Self ! {sup_started, persistent_term:get(?NODELAY_KEY, false)},
                          {ok, self()}
                      end),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(true, receive {sup_started, A} -> A after 0 -> missing end),
          ?assertEqual(1, meck:num_calls(yuzu_gw_upstream_channel, apply_nodelay, []))
      end).

%%%===================================================================
%%% Boot wiring: the configuration guards run before anything is started
%%%===================================================================

%% Each guard refuses on configuration alone: no metrics endpoint, no
%% supervision tree (whose last children are the listeners) and no crash filter
%% exists when start/2 answers the error.
boot_refuses_a_leftover_grpcbox_servers_block_test_() ->
    boot_refusal(fun() ->
                     application:set_env(grpcbox, servers, [#{listen_opts => #{port => 50051}}])
                 end,
                 legacy_grpcbox_servers).

boot_refuses_an_invalid_listener_entry_test_() ->
    boot_refusal(fun() ->
                     application:set_env(yuzu_gw, grpc_listeners,
                                         [(mgmt_entry())#{tls := #{certfile => "gw.pem"}}])
                 end,
                 bad_grpc_listeners).

boot_refuses_a_network_reachable_mgmt_listener_without_the_posture_test_() ->
    boot_refusal(fun() ->
                     %% pins are missing
                     application:set_env(yuzu_gw, grpc_listeners, [mgmt_entry()])
                 end,
                 insecure_mgmt_listener).

%% The same listener boots under the acknowledgement that lab rigs carry.
boot_accepts_the_mgmt_listener_under_the_escape_hatch_test_() ->
    boot_case(
      fun() ->
          application:set_env(yuzu_gw, grpc_listeners, [agent_entry(), mgmt_entry()]),
          application:set_env(yuzu_gw, allow_insecure_mgmt, true),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(1, meck:num_calls(yuzu_gw_sup, start_link, []))
      end).

%% The environment's listener ports are applied before the guards read the
%% configuration (two entries on one port are a defect only after the rewrite).
boot_applies_the_listener_port_overrides_before_the_guards_test_() ->
    boot_case(
      fun() ->
          application:set_env(yuzu_gw, grpc_listeners, [agent_entry(), mgmt_entry()]),
          application:set_env(yuzu_gw, allow_insecure_mgmt, true),
          os:putenv("YUZU_GW_AGENT_PORT", "52001"),
          os:putenv("YUZU_GW_MGMT_PORT", "52001"),
          ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:start(normal, []))
      end).

boot_refusal(Configure, Reason) ->
    boot_case(
      [yuzu_gw_upstream_channel],
      fun() ->
          Configure(),
          ?assertEqual({error, Reason}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(0, meck:num_calls(yuzu_gw_sup, start_link, [])),
          ?assertEqual(0, meck:num_calls(prometheus_httpd, start, [])),
          ?assertEqual(0, meck:num_calls(yuzu_gw_telemetry, setup, [])),
          ?assertEqual(0, meck:num_calls(yuzu_gw_upstream_channel, apply_nodelay, [])),
          ?assertEqual(false, crash_filter_installed())
      end).

crash_filter_installed() ->
    lists:keymember(yuzu_gw_crash_redact, 1, maps:get(filters, logger:get_primary_config())).

%% A boot test: Body runs with ?BOOT_MODS (and Extra, passthrough) mocked and
%% the process-wide state boot touches saved; boot_cleanup/1 puts it all back.
%% The 60 s bound is far above the work (milliseconds) so it only ever fires
%% on a genuine hang, and the cleanup still runs then.
boot_case(Body) ->
    boot_case([], Body).

boot_case(Extra, Body) ->
    {setup,
     fun() -> boot_setup(Extra) end,
     fun boot_cleanup/1,
     {timeout, 60, Body}}.

boot_setup(Extra) ->
    PrevCookieFlag = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE"),
    %% The guards read the listener configuration, which an earlier module may
    %% have left set: boot runs against an empty one unless a test sets its own.
    PrevEnv = env_setup(),
    PrevPrometheus = application:get_env(prometheus, prometheus_http),
    AbsentKeys = [K || K <- [?SUMMARY_KEY | ?SAFE_CALL_KEYS],
                       persistent_term:get(K, undefined) =:= undefined],
    %% yuzu_gw_app:stop/1 drains every member of the `all_agents' pg group and
    %% spends up to a second on each one that does not answer. A member left
    %% there by another module is not this test's business and must not be able
    %% to push stop/1 past the test's time bound, so park them for the
    %% duration (cleanup joins the survivors back).
    Parked = park_foreign_agents(),
    %% rebar3 runs eunit on a named node with a short cookie.
    os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", "1"),
    ok = yuzu_gw_crash_redact:remove(),
    Fixture = #{env => PrevEnv, cookie_flag => PrevCookieFlag, prometheus => PrevPrometheus,
                absent_keys => AbsentKeys, parked => Parked, extra => Extra},
    try
        ok = meck:new(?BOOT_MODS, [non_strict, no_link]),
        [ok = meck:new(M, [passthrough, no_link]) || M <- Extra],
        meck:expect(yuzu_gw_telemetry, setup, fun() -> ok end),
        meck:expect(prometheus_httpd, start, fun() -> {ok, self()} end),
        meck:expect(yuzu_gw_sup, start_link, fun() -> {ok, self()} end),
        meck:expect(yuzu_gw_heartbeat_buffer, flush_sync, fun() -> ok end),
        Fixture
    catch Class:Reason:Stack ->
        boot_cleanup(Fixture),
        erlang:raise(Class, Reason, Stack)
    end.

boot_cleanup(#{env := PrevEnv, cookie_flag := PrevCookieFlag, prometheus := PrevPrometheus,
               absent_keys := AbsentKeys, parked := Parked, extra := Extra}) ->
    catch meck:unload(?BOOT_MODS ++ Extra),
    ok = yuzu_gw_crash_redact:remove(),
    case PrevCookieFlag of
        false -> os:unsetenv("YUZU_GW_ALLOW_DEFAULT_COOKIE");
        Prev  -> os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", Prev)
    end,
    case PrevPrometheus of
        {ok, V}   -> application:set_env(prometheus, prometheus_http, V);
        undefined -> application:unset_env(prometheus, prometheus_http)
    end,
    env_cleanup(PrevEnv),
    [persistent_term:erase(K) || K <- AbsentKeys],
    persistent_term:erase(?SUMMARY_KEY),
    persistent_term:erase(?NODELAY_KEY),
    unpark_foreign_agents(Parked).

park_foreign_agents() ->
    Members = try pg:get_members(yuzu_gw, all_agents) catch _:_ -> [] end,
    _ = [pg:leave(yuzu_gw, all_agents, P) || P <- Members],
    Members.

unpark_foreign_agents(Parked) ->
    Alive = [P || P <- Parked, is_process_alive(P)],
    case Alive of
        [] -> ok;
        _  -> catch pg:join(yuzu_gw, all_agents, Alive), ok
    end.
