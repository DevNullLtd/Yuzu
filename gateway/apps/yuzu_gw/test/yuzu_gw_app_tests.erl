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

%% logger handler callback (the log-capturing tests attach this module)
-export([log/2]).

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
                   {yuzu_gw, allow_no_listeners},
                   {yuzu_gw, mgmt_peer_pins}, {yuzu_gw, mgmt_peer_auth_mode},
                   {yuzu_gw, mgmt_peer_identity}, {yuzu_gw, mgmt_peer_denied},
                   {yuzu_gw, agent_listen_port},
                   {yuzu_gw, mgmt_listen_port}, {grpcbox, servers}, {grpcbox, client},
                   {yuzu_gw, upstream_client}, {yuzu_gw, allow_no_upstream}]).
-define(PORT_VARS, ["YUZU_GW_AGENT_PORT", "YUZU_GW_MGMT_PORT"]).

env_setup() ->
    Saved = {[{K, application:get_env(A, Key)} || {A, Key} = K <- ?ENV_KEYS],
             [{V, os:getenv(V)} || V <- ?PORT_VARS]},
    [application:unset_env(A, Key) || {A, Key} <- ?ENV_KEYS],
    [os:unsetenv(V) || V <- ?PORT_VARS],
    ok = yuzu_gw_mgmt_identity:reset(),
    Saved.

env_cleanup({AppEnv, OsEnv}) ->
    ok = yuzu_gw_mgmt_identity:reset(),
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

%% Nothing reads a leftover {grpcbox, servers}, so an operator who kept the block
%% believes a listener is configured that is not: boot refuses it. Only the
%% upstream {client, ...} may remain in the grpcbox env (the key keeps its name).
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

%% The guard over the configured entries: no entries is refused unless the
%% configuration says it is meant (a gateway under test, or one that only
%% routes), an invalid one is refused.
check_grpc_listeners_test_() ->
    env_case(
      [{"no listeners configured is refused",
        fun() ->
            ?assertEqual({error, no_grpc_listeners}, yuzu_gw_app:check_grpc_listeners()),
            application:set_env(yuzu_gw, grpc_listeners, []),
            ?assertEqual({error, no_grpc_listeners}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"{allow_no_listeners, true} accepts a gateway with none",
        fun() ->
            application:set_env(yuzu_gw, allow_no_listeners, true),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners()),
            application:set_env(yuzu_gw, grpc_listeners, []),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners())
        end},
       {"anything but the literal true is not the acknowledgement",
        fun() ->
            lists:foreach(
              fun(Value) ->
                  application:set_env(yuzu_gw, allow_no_listeners, Value),
                  ?assertEqual({error, no_grpc_listeners},
                               yuzu_gw_app:check_grpc_listeners(), Value)
              end, [false, "true", <<"true">>, 1, yes])
        end},
       {"the acknowledgement does not excuse an invalid entry",
        fun() ->
            application:set_env(yuzu_gw, allow_no_listeners, true),
            application:set_env(yuzu_gw, grpc_listeners, [(agent_entry())#{origins => #{}}]),
            ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"the refusal says what to do",
        fun() ->
            Text = lists:flatten(capture_logs(
                     fun() -> {error, no_grpc_listeners} = yuzu_gw_app:check_grpc_listeners() end)),
            {match, _} = re:run(Text, "Refusing to start: \\{yuzu_gw, grpc_listeners\\} is unset or empty", [unicode]),
            {match, _} = re:run(Text, "allow_no_listeners", [unicode])
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
        end},
       {"valid entries none of which serves the agent service are refused",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [mgmt_entry()]),
            ?assertEqual({error, no_agent_listener}, yuzu_gw_app:check_grpc_listeners()),
            application:set_env(yuzu_gw, allow_no_listeners, false),
            ?assertEqual({error, no_agent_listener}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"the refusal for a missing agent listener says what to do",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [mgmt_entry()]),
            Text = lists:flatten(capture_logs(
                     fun() -> {error, no_agent_listener} = yuzu_gw_app:check_grpc_listeners() end)),
            {match, _} = re:run(Text, "Refusing to start: no \\{yuzu_gw, grpc_listeners\\} entry routes the AgentService", [unicode]),
            {match, _} = re:run(Text, "readyz", [unicode]),
            {match, _} = re:run(Text, "allow_no_listeners", [unicode])
        end},
       {"{allow_no_listeners, true} excuses a missing agent listener, with a warning",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [mgmt_entry()]),
            application:set_env(yuzu_gw, allow_no_listeners, true),
            Text = lists:flatten(capture_logs(
                     fun() -> ok = yuzu_gw_app:check_grpc_listeners() end)),
            {match, _} = re:run(Text, "routes the agent service and .*allow_no_listeners.* is true", [unicode])
        end},
       {"the acknowledgement does not excuse a missing agent listener when an entry is invalid",
        fun() ->
            application:set_env(yuzu_gw, allow_no_listeners, true),
            application:set_env(yuzu_gw, grpc_listeners,
                                [(mgmt_entry())#{tls := #{certfile => "gw.pem"}}]),
            ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"an entry that lists agent_pb but routes no AgentService is not an agent listener",
        fun() ->
            Unrouted = (agent_entry())#{services := #{}},
            ?assertEqual(ok, yuzu_gw_app:evaluate_listeners([Unrouted])),
            application:set_env(yuzu_gw, grpc_listeners, [Unrouted]),
            ?assertEqual({error, no_agent_listener}, yuzu_gw_app:check_grpc_listeners()),
            %% nor next to a management listener that is valid
            application:set_env(yuzu_gw, grpc_listeners, [Unrouted, mgmt_entry()]),
            ?assertEqual({error, no_agent_listener}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"a combined agent and management entry that maps only the management service is not an agent listener",
        fun() ->
            Combined = (combined_entry())#{
                         services := #{'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}},
            application:set_env(yuzu_gw, grpc_listeners, [Combined]),
            ?assertEqual({error, no_agent_listener}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"the refusal for an unrouted agent entry names the rule, not the protos",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [(agent_entry())#{services := #{}}]),
            Text = lists:flatten(capture_logs(
                     fun() -> {error, no_agent_listener} = yuzu_gw_app:check_grpc_listeners() end)),
            {match, _} = re:run(Text, "no \\{yuzu_gw, grpc_listeners\\} entry routes the AgentService", [unicode]),
            {match, _} = re:run(Text, "'yuzu.agent.v1.AgentService'", [unicode]),
            {match, _} = re:run(Text, "services", [unicode])
        end},
       {"only the literal true excuses a missing agent listener",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [(agent_entry())#{services := #{}}]),
            lists:foreach(
              fun(Value) ->
                  application:set_env(yuzu_gw, allow_no_listeners, Value),
                  ?assertEqual({error, no_agent_listener},
                               yuzu_gw_app:check_grpc_listeners(), Value)
              end, [false, "true", <<"true">>, 1, yes]),
            application:set_env(yuzu_gw, allow_no_listeners, true),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners())
        end},
       {"a listeners value that is an improper list is refused, not a crash",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [agent_entry() | not_a_list]),
            ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:check_grpc_listeners()),
            ?assertEqual({error, [{unknown, grpc_listeners_not_a_list}]},
                         yuzu_gw_app:evaluate_listeners([agent_entry() | not_a_list])),
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            ?assertEqual(ok, yuzu_gw_app:apply_listener_port_overrides()),
            %% the management guard cannot show an improper list holds no
            %% management listener, so it refuses (fail closed), escape hatch or not
            ?assertEqual({error, insecure_mgmt_listener}, yuzu_gw_app:check_mgmt_listener_posture()),
            ?assertEqual({error, {insecure_mgmt_listener, [{unknown, improper_list}]}},
                         yuzu_gw_app:evaluate_mgmt_posture([agent_entry() | not_a_list], [], false)),
            ?assertEqual({error, {insecure_mgmt_listener, [{unknown, improper_list}]}},
                         yuzu_gw_app:evaluate_mgmt_posture([agent_entry() | not_a_list], [], true)),
            ?assertEqual(false, yuzu_gw_app:listeners_have_tls([mgmt_entry() | not_a_list]))
        end},
       {"a management listener is exposed when its bind cannot be proven loopback",
        fun() ->
            Loop = (mgmt_entry())#{listen := #{port => 50063, ip => {127, 0, 0, 1}}},
            Refused = fun(Entry) ->
                          ?assertMatch({error, {insecure_mgmt_listener, [{_, _}]}},
                                       yuzu_gw_app:evaluate_mgmt_posture([Entry], [], false))
                      end,
            %% the control: a loopback bind with proper socket_opts is not exposed
            ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(
                               [Loop#{listen := #{port => 50063, ip => {127, 0, 0, 1},
                                                  socket_opts => [{nodelay, true}]}}], [], false)),
            %% improper socket_opts, and a `listen' that is not a map, are exposed
            Refused(Loop#{listen := #{port => 50063, ip => {127, 0, 0, 1},
                                      socket_opts => [{nodelay, true} | x]}}),
            Refused(Loop#{listen := not_a_map}),
            ?assertEqual({error, {insecure_mgmt_listener, [{unknown, [plaintext, no_mgmt_peer_pins]}]}},
                         yuzu_gw_app:evaluate_mgmt_posture(
                           [(mgmt_entry())#{listen := not_a_map, tls := none}], [], false))
        end},
       {"a service module that exports none of its service's methods is refused",
        fun() ->
            Typo = (agent_entry())#{services := #{'yuzu.agent.v1.AgentService' => yuzu_gw_app}},
            Expected = {agent, {bad_routes, {service_without_routes, 'yuzu.agent.v1.AgentService'}}},
            ?assertEqual({error, [Expected]}, yuzu_gw_app:evaluate_listeners([Typo])),
            ?assertEqual(ok, yuzu_grpc_listener:validate(Typo)),
            application:set_env(yuzu_gw, grpc_listeners, [Typo]),
            ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:check_grpc_listeners())
        end},
       {"a service module that exports only some of its methods is accepted",
        fun() ->
            %% heartbeat/execute_command/subscribe only: the other agent RPCs are
            %% absent from the route table and answer UNIMPLEMENTED
            Partial = (agent_entry())#{services := #{'yuzu.agent.v1.AgentService' => yuzu_grpc_stub_svc}},
            ?assertEqual(ok, yuzu_gw_app:evaluate_listeners([Partial])),
            application:set_env(yuzu_gw, grpc_listeners, [Partial]),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners())
        end},
       {"an entry whose service_protos is an improper list is refused, not a crash",
        fun() ->
            Improper = (agent_entry())#{service_protos := [agent_pb | management_pb]},
            ?assertEqual({error, [{agent, bad_service_protos}]},
                         yuzu_gw_app:evaluate_listeners([Improper])),
            application:set_env(yuzu_gw, grpc_listeners, [Improper]),
            ?assertEqual({error, bad_grpc_listeners}, yuzu_gw_app:check_grpc_listeners()),
            %% the port override and the management guard read the same list
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            ?assertEqual(ok, yuzu_gw_app:apply_listener_port_overrides()),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"an entry that serves the AgentService under another proto counts as an agent listener",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners,
                                [(maps:remove(auth_fun, mgmt_entry()))#{
                                   services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service}}]),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners())
        end},
       {"a combined listener, and the agent and management pair, are agent listeners",
        fun() ->
            application:set_env(yuzu_gw, grpc_listeners, [combined_entry()]),
            ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners())
        end}]).

%% #6016: the management peer authorization the boot guard resolves and
%% publishes for yuzu_gw_authz, and the posture decision that depends on its mode.
check_mgmt_auth_config_test_() ->
    Set = fun(Listeners) -> application:set_env(yuzu_gw, grpc_listeners, Listeners) end,
    Env = fun(Key, V) -> application:set_env(yuzu_gw, Key, V) end,
    Pins = [{cert_file, "srv.pem"}],
    WithCa = fun(Body) ->
                 case yuzu_gw_authz_tests:setup_certs() of
                     #{ca := Ca} = Certs ->
                         try Body(Ca) after yuzu_gw_authz_tests:cleanup_certs(Certs) end;
                     {error, Why} ->
                         %% skipped (no openssl), or a failure where the leg requires TLS tests
                         ?assertEqual([], yuzu_gw_authz_tests:certs_unavailable(
                                            "check_mgmt_auth_config", Why))
                 end
             end,
    env_case(
      [{"the guards run in order: the auth configuration is published before the posture is judged",
        fun() ->
            Names = [element(2, erlang:fun_info(G, name)) || G <- yuzu_gw_app:startup_guards()],
            Pos = fun(N) -> length(lists:takewhile(fun(X) -> X =/= N end, Names)) end,
            ?assert(lists:member(check_mgmt_auth_config, Names)),
            ?assert(Pos(check_mgmt_auth_config) < Pos(check_mgmt_listener_posture))
        end},
       {"unset: the pin mode, with or without pins (the identity is never implied)",
        fun() ->
            Env(mgmt_peer_pins, Pins),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config()),
            ?assertMatch(#{mode := pin, identity := undefined, denied := []},
                         yuzu_gw_mgmt_identity:current()),
            Env(mgmt_peer_pins, []),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config()),
            ?assertMatch(#{mode := pin, identity := undefined}, yuzu_gw_mgmt_identity:current()),
            %% ...so an exposed listener with no pins is still refused, as before #6016
            Set([agent_entry(), mgmt_entry()]),
            ?assertEqual({error, insecure_mgmt_listener}, yuzu_gw_app:check_mgmt_listener_posture())
        end},
       {"an explicit identity that differs from the derived one is warned of (and its case noted)",
        fun() ->
            WithCa(fun(Ca) ->
                {ok, Derived} = yuzu_gw_mgmt_identity:derive_from_cacertfile(Ca),
                Set([agent_entry(),
                     (mgmt_entry())#{tls := #{certfile => "gw.pem", keyfile => "gw.key",
                                              cacertfile => Ca}}]),
                Env(mgmt_peer_auth_mode, identity_or_pin),
                Env(mgmt_peer_pins, Pins),
                Warned = fun(Text) ->
                             Lines = yuzu_gw_test_logs:capture(warning, fun() ->
                                         ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config())
                                     end),
                             [L || L <- Lines, binary:match(L, Text) =/= nomatch]
                         end,
                Needle = <<"is not the identity derived from">>,
                %% the derived value itself: silent
                Env(mgmt_peer_identity, binary_to_list(Derived)),
                ?assertEqual([], Warned(Needle)),
                %% another install
                Env(mgmt_peer_identity, "yuzu://OTHERINSTALL/server"),
                ?assertMatch([_], Warned(Needle)),
                ?assertEqual([], Warned(<<"differ only in letter case">>)),
                %% a lower-case copy of the fingerprint
                Env(mgmt_peer_identity, string:lowercase(binary_to_list(Derived))),
                ?assertMatch([_], Warned(<<"differ only in letter case">>))
            end)
        end},
       {"the deny-list is logged as the upper-case hex it parsed to",
        fun() ->
            Env(mgmt_peer_pins, Pins),
            Env(mgmt_peer_denied, [{serial, "0a1b"}, {serial, "255"}]),
            Lines = yuzu_gw_test_logs:capture(info, fun() ->
                        ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config())
                    end),
            ?assertMatch([_], [L || L <- Lines,
                                    binary:match(L, <<"upper-case hex as parsed): 255 (decimal 597), A1B (decimal 2587)">>) =/= nomatch])
        end},
       {"an identity set without the mode is ignored, and says so",
        fun() ->
            Env(mgmt_peer_pins, Pins),
            Env(mgmt_peer_identity, "yuzu://X/server"),
            Lines = yuzu_gw_test_logs:capture(warning, fun() ->
                        ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config())
                    end),
            ?assertMatch([_], [L || L <- Lines,
                                    binary:match(unicode:characters_to_binary(L),
                                                 <<"identity is ignored">>) =/= nomatch]),
            ?assertMatch(#{mode := pin, identity := undefined}, yuzu_gw_mgmt_identity:current())
        end},
       {"the identity is derived from a management listener's single-certificate CA",
        fun() ->
            WithCa(fun(Ca) ->
                {ok, Expected} = yuzu_gw_mgmt_identity:derive_from_cacertfile(Ca),
                Set([agent_entry(),
                     (mgmt_entry())#{tls := #{certfile => "gw.pem", keyfile => "gw.key",
                                              cacertfile => Ca}}]),
                Env(mgmt_peer_auth_mode, identity),
                ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config()),
                ?assertMatch(#{mode := identity, identity := Expected},
                             yuzu_gw_mgmt_identity:current()),
                %% that is enough for the exposed listener: no pin is needed
                ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture())
            end)
        end},
       {"a CA bundle derives nothing: the listener is refused, naming the identity",
        fun() ->
            WithCa(fun(Ca) ->
                {ok, One} = file:read_file(Ca),
                Bundle = filename:join(filename:dirname(Ca), "bundle.pem"),
                ok = file:write_file(Bundle, [One, One]),
                Set([agent_entry(),
                     (mgmt_entry())#{tls := #{certfile => "gw.pem", keyfile => "gw.key",
                                              cacertfile => Bundle}}]),
                Env(mgmt_peer_auth_mode, identity),
                ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config()),
                ?assertMatch(#{mode := identity, identity := undefined},
                             yuzu_gw_mgmt_identity:current()),
                ?assertEqual({error, insecure_mgmt_listener},
                             yuzu_gw_app:check_mgmt_listener_posture()),
                %% ...an explicit identity over the bundle is refused unless a pin must
                %% ALSO match: every CA in the bundle could mint the identity
                Env(mgmt_peer_identity, "yuzu://INSTALL/server"),
                ?assertEqual({error, bad_mgmt_peer_auth}, yuzu_gw_app:check_mgmt_auth_config()),
                Env(mgmt_peer_auth_mode, identity_or_pin),
                Env(mgmt_peer_pins, Pins),
                ?assertEqual({error, bad_mgmt_peer_auth}, yuzu_gw_app:check_mgmt_auth_config()),
                Env(mgmt_peer_auth_mode, identity),
                ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config()),
                ?assertEqual(ok, yuzu_gw_app:check_mgmt_listener_posture())
            end)
        end},
       {"an unresolved identity is warned of only where the auth_fun runs",
        fun() ->
            Lines = fun() ->
                        yuzu_gw_test_logs:capture(warning, fun() ->
                            ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config())
                        end)
                    end,
            Warned = fun(Ls) -> [L || L <- Ls, binary:match(unicode:characters_to_binary(L),
                                                            <<"could not resolve the server identity">>) =/= nomatch]
                     end,
            Env(mgmt_peer_auth_mode, identity),
            %% a plaintext lab-rig listener runs no auth_fun: nothing to resolve, nothing to say
            Set([agent_entry(), maps:without([tls, auth_fun], mgmt_entry())]),
            ?assertEqual([], Warned(Lines())),
            %% the strict listener, whose cacertfile does not exist here, does
            Set([agent_entry(), mgmt_entry()]),
            ?assertMatch([_], Warned(Lines()))
        end},
       {"two management listeners that derive different identities refuse the boot",
        fun() ->
            WithCa(fun(Ca) ->
                Other = filename:join(filename:dirname(Ca), "other-ca.pem"),
                Key = filename:join(filename:dirname(Ca), "other-ca.key"),
                _ = os:cmd("openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 "
                           "-nodes -days 1 -subj /CN=Other -keyout '" ++ Key ++ "' -out '"
                           ++ Other ++ "' 2>&1"),
                ?assert(filelib:is_regular(Other)),
                Tls = fun(F) -> #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => F} end,
                Set([(mgmt_entry())#{name => mgmt_a, listen => #{port => 50063, ip => {0, 0, 0, 0}},
                                     tls := Tls(Ca)},
                     (mgmt_entry())#{name => mgmt_b, listen => #{port => 50064, ip => {0, 0, 0, 0}},
                                     tls := Tls(Other)}]),
                Env(mgmt_peer_auth_mode, identity),
                ?assertEqual({error, bad_mgmt_peer_auth}, yuzu_gw_app:check_mgmt_auth_config()),
                Set([(mgmt_entry())#{name => mgmt_a, tls := Tls(Ca)},
                     (mgmt_entry())#{name => mgmt_b, listen => #{port => 50064, ip => {0, 0, 0, 0}},
                                     tls := Tls(Ca)}]),
                ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config())
            end)
        end},
       {"an unusable mode, identity or deny entry refuses the boot",
        fun() ->
            Bad = fun(Key, V) ->
                      Env(Key, V),
                      ?assertEqual({error, bad_mgmt_peer_auth}, yuzu_gw_app:check_mgmt_auth_config(),
                                   {Key, V}),
                      application:unset_env(yuzu_gw, Key)
                  end,
            Bad(mgmt_peer_auth_mode, strict),
            Bad(mgmt_peer_auth_mode, "identity"),
            Env(mgmt_peer_auth_mode, identity_or_pin),
            Bad(mgmt_peer_identity, "yuzu://X/agent/a"),
            application:unset_env(yuzu_gw, mgmt_peer_auth_mode),
            Bad(mgmt_peer_denied, [{serial, "not hex"}]),
            Bad(mgmt_peer_denied, [{spki_sha256, lists:duplicate(64, $a)}]),
            Bad(mgmt_peer_denied, not_a_list),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config())
        end},
       {"the deny-list is published as integers",
        fun() ->
            Env(mgmt_peer_denied, [{serial, "0A"}, {serial, <<"ff">>}]),
            ?assertEqual(ok, yuzu_gw_app:check_mgmt_auth_config()),
            ?assertMatch(#{denied := [10, 255]}, yuzu_gw_mgmt_identity:current())
        end},
       {"what admits the server depends on the mode, and the defect names it",
        fun() ->
            L = [agent_entry(), mgmt_entry()],
            Auth = fun(Mode, Id) -> #{mode => Mode, identity => Id, denied => []} end,
            Refused = fun(Defect, ConfiguredPins, A) ->
                          ?assertEqual({error, {insecure_mgmt_listener,
                                                [{50063, [Defect]}]}},
                                       yuzu_gw_app:evaluate_mgmt_posture(L, ConfiguredPins, false, A))
                      end,
            Id = <<"yuzu://X/server">>,
            %% pin: pins, and only pins
            ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(L, Pins, false, Auth(pin, undefined))),
            Refused(no_mgmt_peer_pins, [], Auth(pin, Id)),
            %% identity: a resolved identity, and only that (a pin is an extra constraint)
            ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(L, [], false, Auth(identity, Id))),
            ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(L, Pins, false, Auth(identity, Id))),
            Refused(no_mgmt_peer_identity, [], Auth(identity, undefined)),
            Refused(no_mgmt_peer_identity, Pins, Auth(identity, undefined)),
            %% identity_or_pin: either
            ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(L, [], false, Auth(identity_or_pin, Id))),
            ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture(L, Pins, false,
                                                               Auth(identity_or_pin, undefined))),
            Refused(no_mgmt_peer_pins_or_identity, [], Auth(identity_or_pin, undefined))
        end},
       {"the three-argument form is the pin mode",
        fun() ->
            ?assertEqual({error, {insecure_mgmt_listener, [{50063, [no_mgmt_peer_pins]}]}},
                         yuzu_gw_app:evaluate_mgmt_posture([mgmt_entry()], [], false)),
            ?assertEqual(ok, yuzu_gw_app:evaluate_mgmt_posture([mgmt_entry()], Pins, false))
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
       {"a socket option that rebinds a loopback listener is not loopback",
        fun() ->
            %% the entry guard refuses it outright (see the evaluate_listeners
            %% tests); the posture decision does not trust it either
            lists:foreach(
              fun(Opts) ->
                  Set([PlainMgmt#{listen := #{port => 50063, ip => {127, 0, 0, 1},
                                              socket_opts => Opts}}]),
                  ?assertEqual({error, insecure_mgmt_listener},
                               yuzu_gw_app:check_mgmt_listener_posture(), Opts)
              end, [[{ifaddr, {0, 0, 0, 0}}], [{ip, {0, 0, 0, 0}}], [{fd, 3}], [{local, "/x"}]])
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
      ?_assertEqual([{mgmt, auth_fun_without_tls}],
                    Bad(maps:remove(tls, mgmt_entry())))},
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
                    Bad((agent_entry())#{http2 => #{proxy_header => true}}))},
     %% Closed key sets: an entry may carry only keys the layer reads. The first
     %% two are the shape that would otherwise leave an encrypted-looking agent
     %% edge serving plaintext.
     {"the former transport_opts / listen_opts / grpc_opts / ssl keys are refused by name",
      [?_assertMatch([{agent, {legacy_keys, entry, [{transport_opts, _}]}}],
                     Bad((agent_entry())#{transport_opts => #{ssl => true, certfile => "gw.pem",
                                                             keyfile => "gw.key",
                                                             cacertfile => "ca.pem"}})),
       ?_assertMatch([{agent, {legacy_keys, entry, [{listen_opts, _}]}}],
                     Bad((agent_entry())#{listen_opts => #{port => 50051}})),
       ?_assertMatch([{agent, {legacy_keys, entry, [{grpc_opts, _}]}}],
                     Bad((agent_entry())#{grpc_opts => #{}})),
       ?_assertMatch([{agent, {legacy_keys, entry, [{ssl, _}]}}],
                     Bad((agent_entry())#{ssl => true}))]},
     {"a mistyped key is refused, not ignored",
      [?_assertMatch([{agent, {unknown_keys, entry, [origins], {allowed, _}}}],
                     Bad((agent_entry())#{origins => #{mode => forwarded_for,
                                                       sources => [{10, 0, 0, 5}]}})),
       ?_assertMatch([{mgmt, {unknown_keys, tls, [certfil], {allowed, _}}}],
                     Bad((mgmt_entry())#{tls := #{certfil => "gw.pem", keyfile => "gw.key",
                                                  cacertfile => "ca.pem"}})),
       ?_assertMatch([{agent, {unknown_keys, http2, [idle_timout], {allowed, _}}}],
                     Bad((agent_entry())#{http2 => #{idle_timout => 1}})),
       ?_assertMatch([{agent, {unknown_keys, listen, [host], {allowed, _}}}],
                     Bad(with_listen(agent_entry(), #{port => 50051, host => "0.0.0.0"})))]},
     {"acceptors and limits are checked for type",
      [?_assertEqual([{agent, bad_acceptors}], Bad((agent_entry())#{acceptors => "32"})),
       ?_assertEqual([{agent, bad_limits}], Bad((agent_entry())#{limits => garbage})),
       ?_assertEqual([{agent, {bad_limits, [max_message_bytes]}}],
                     Bad((agent_entry())#{limits => #{max_message_bytes => -1}}))]},
     {"an auth_fun is refused on a listener that serves agent_pb",
      [?_assertEqual([{agent, auth_fun_on_agent_listener}],
                     Bad((agent_entry())#{tls => #{certfile => "gw.pem", keyfile => "gw.key",
                                                   cacertfile => "ca.pem"},
                                          auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1})),
       ?_assertEqual([{combined, auth_fun_on_agent_listener}],
                     Bad((combined_entry())#{tls => #{certfile => "gw.pem", keyfile => "gw.key",
                                                      cacertfile => "ca.pem"},
                                             auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1}))]},
     {"a socket option cannot move the bind address or port",
      [?_assertEqual([{mgmt, {listen_socket_opts_set_the_bind, [ifaddr]}}],
                     Bad(with_listen(mgmt_entry(), #{port => 50063, ip => {127, 0, 0, 1},
                                                     socket_opts => [{ifaddr, {0, 0, 0, 0}}]}))),
       ?_assertEqual([{mgmt, {listen_socket_opts_set_the_bind, [port]}}],
                     Bad(with_listen(mgmt_entry(), #{port => 50063, ip => {127, 0, 0, 1},
                                                     socket_opts => [{port, 50052}]})))]}].

%% The crafted entry: management_pb in service_protos, the AgentService served
%% through `services', and an auth_fun. It reads as a management-only listener
%% and serves the agent RPCs to peers an auth_fun would shut out.
evaluate_listeners_refuses_an_auth_fun_on_a_listener_serving_the_agent_service_test() ->
    Crafted = (mgmt_entry())#{
                services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service,
                              'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service}},
    ?assertEqual({error, [{mgmt, auth_fun_on_agent_listener}]},
                 yuzu_gw_app:evaluate_listeners([agent_entry(), Crafted])),
    %% the legitimate management listener passes
    ?assertEqual(ok, yuzu_gw_app:evaluate_listeners([agent_entry(), mgmt_entry()])).

%% One listener for both services (the single-port rig) is a valid shape and
%% carries no auth_fun.
evaluate_listeners_accepts_a_combined_listener_without_an_auth_fun_test() ->
    ?assertEqual(ok, yuzu_gw_app:evaluate_listeners([combined_entry()])).

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

combined_entry() ->
    #{name => combined,
      service_protos => [agent_pb, management_pb],
      services => #{'yuzu.agent.v1.AgentService' => yuzu_gw_agent_service,
                    'yuzu.server.v1.ManagementService' => yuzu_gw_mgmt_service},
      listen => #{port => 50051, ip => {0, 0, 0, 0}}}.

%% The log events of Fun, as text. The handler takes everything (no filters), so
%% what is captured is what the code under test logged, at any level.
capture_logs(Fun) ->
    [Text || {_Level, Text} <- capture_events(Fun)].

%% The same, with the level of each event: {Level, Text}.
capture_events(Fun) ->
    Id = yuzu_gw_app_tests_handler,
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
        {logged, #{level := Level, msg := {Fmt, Args}}} when is_list(Fmt), is_list(Args) ->
            drain_logs([{Level, lists:flatten(io_lib:format(Fmt, Args))} | Acc]);
        {logged, #{level := Level, msg := {string, Text}}} ->
            drain_logs([{Level, lists:flatten(io_lib:format("~ts", [Text]))} | Acc]);
        {logged, _} ->
            drain_logs(Acc)
    after 0 ->
        lists:reverse(Acc)
    end.

log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {logged, Event},
    ok.

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
       {"an entry whose listen is not a map is left unchanged for validate to refuse",
        fun() ->
            Bad = (agent_entry())#{listen := not_a_map},
            Set([Bad]),
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            ?assertEqual(ok, yuzu_gw_app:apply_listener_port_overrides()),
            ?assertEqual([Bad], application:get_env(yuzu_gw, grpc_listeners, [])),
            ?assertEqual({error, [{agent, bad_listen}]}, yuzu_gw_app:evaluate_listeners([Bad]))
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
       {"with two agent listeners the variable is ignored, with a warning, and boot is not refused",
        fun() ->
            %% one listener for a load balancer, one for a router
            Second = (agent_entry())#{name => agent_router, listen => #{port => 50052}},
            Set([agent_entry(), Second, mgmt_entry()]),
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            Text = lists:flatten(capture_logs(
                     fun() -> ok = yuzu_gw_app:apply_listener_port_overrides() end)),
            ?assertEqual([{agent, 50051}, {agent_router, 50052}, {mgmt, 50063}], Ports()),
            {match, _} = re:run(Text, "YUZU_GW_AGENT_PORT is ignored", [unicode]),
            ?assertEqual(ok, yuzu_gw_app:evaluate_listeners(
                               application:get_env(yuzu_gw, grpc_listeners, [])))
        end},
       {"two management listeners are no different",
        fun() ->
            Second = (mgmt_entry())#{name => mgmt2, listen => #{port => 50064}},
            Set([mgmt_entry(), Second]),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual([{mgmt, 50063}, {mgmt2, 50064}], Ports())
        end},
       {"a variable whose proto no listener serves is ignored, with a warning naming it",
        fun() ->
            Set([agent_entry()]),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            Text = lists:flatten(capture_logs(
                     fun() -> ok = yuzu_gw_app:apply_listener_port_overrides() end)),
            ?assertEqual([{agent, 50051}], Ports()),
            {match, _} = re:run(Text, "YUZU_GW_MGMT_PORT is ignored", [unicode])
        end},
       {"a variable that is not set warns about nothing",
        fun() ->
            Set([agent_entry(), (agent_entry())#{name => agent2}]),
            ?assertEqual([], capture_logs(
                               fun() -> ok = yuzu_gw_app:apply_listener_port_overrides() end))
        end},
       {"a listener that serves both protos has one port: the agent variable sets it",
        fun() ->
            Set([combined_entry()]),
            os:putenv("YUZU_GW_AGENT_PORT", "52001"),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            Text = lists:flatten(capture_logs(
                     fun() -> ok = yuzu_gw_app:apply_listener_port_overrides() end)),
            ?assertEqual([{combined, 52001}], Ports()),
            {match, _} = re:run(Text, "YUZU_GW_MGMT_PORT is ignored", [unicode])
        end},
       {"the management variable alone does not move a listener that also serves agents",
        fun() ->
            Set([combined_entry()]),
            os:putenv("YUZU_GW_MGMT_PORT", "52002"),
            ok = yuzu_gw_app:apply_listener_port_overrides(),
            ?assertEqual([{combined, 50051}], Ports())
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
-define(THROTTLE_KEY, {yuzu_grpc_runner, warn_throttle}).

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

%% The same for the runner's WARN limit (yuzu_grpc_runner): its state exists
%% before the tree whose last children are the listeners serves a request.
boot_creates_runner_throttle_before_sup_test_() ->
    boot_case(
      fun() ->
          persistent_term:erase(?THROTTLE_KEY),
          Self = self(),
          meck:expect(yuzu_gw_sup, start_link,
                      fun() ->
                          Self ! {sup_started, persistent_term:get(?THROTTLE_KEY, undefined) =/= undefined},
                          {ok, self()}
                      end),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(true, receive {sup_started, T} -> T after 0 -> missing end)
      end).

%%%===================================================================
%%% Boot wiring: the upstream channel configuration guard
%%%===================================================================

-define(DEFAULT_CHANNEL_CONFIG,
        #{channels => [{default_channel, [{http, "127.0.0.1", 59999, []}], #{}}]}).

%% The upstream channels are read from {yuzu_gw, upstream_client}. A channel
%% dropped as unreadable would leave the gateway with no upstream, so an
%% unusable value is refused rather than skipped; so is none at all, because
%% the two callers of the channel use `default_channel' and /readyz would
%% answer for a gateway that can register no agent.
%% The files an https endpoint names. A file that is missing is warned about and
%% the gateway starts (the server creates its certificates on first start,
%% possibly after the gateway's); a DIRECTORY where a file belongs is refused, as
%% it never becomes one. No path of a key file is ever logged.
check_upstream_tls_files_test_() ->
    Chan = fun(Ssl) ->
               #{channels => [{default_channel, [{https, "gw.example", 50055, Ssl}], #{}}]}
           end,
    Set = fun(Ssl) -> application:set_env(yuzu_gw, upstream_client, Chan(Ssl)) end,
    env_case(
      [{"a plaintext endpoint has nothing to check",
        fun() ->
            application:set_env(yuzu_gw, upstream_client, ?DEFAULT_CHANNEL_CONFIG),
            Events = capture_events(fun() -> ?assertEqual(ok, yuzu_gw_app:check_upstream_tls_files()) end),
            ?assertEqual([], Events)
        end},
       {"no upstream_client at all is not this guard's business",
        fun() -> ?assertEqual(ok, yuzu_gw_app:check_upstream_tls_files()) end},
       {"a missing CA file is warned about with its path and the gateway starts",
        fun() ->
            Set([{verify, verify_peer}, {cacertfile, "/nonexistent/ca.pem"},
                 {keyfile, "/marker/private/KEY-bb88.pem"}]),
            Events = capture_events(fun() -> ?assertEqual(ok, yuzu_gw_app:check_upstream_tls_files()) end),
            Warnings = [T || {warning, T} <- Events],
            ?assertEqual(2, length(Warnings)),
            Text = lists:flatten(Warnings),
            {match, _} = re:run(Text, "default_channel endpoint gw.example:50055: cacertfile "
                                      "/nonexistent/ca.pem does not exist \\(yet\\)", [unicode]),
            {match, _} = re:run(Text, "starts anyway", [unicode]),
            nomatch = re:run(Text, "KEY-bb88", [unicode])
        end},
       {"a CA path that is a directory refuses boot, and says why",
        fun() ->
            Set([{verify, verify_peer}, {cacertfile, "/tmp"}]),
            Events = capture_events(
                       fun() ->
                           ?assertEqual({error, unusable_upstream_tls_file},
                                        yuzu_gw_app:check_upstream_tls_files())
                       end),
            Text = lists:flatten([T || {_, T} <- Events]),
            {match, _} = re:run(Text, "cacertfile /tmp is a directory, not a file", [unicode]),
            {match, _} = re:run(Text, "Refusing to start: a TLS file of an upstream endpoint", [unicode]),
            nomatch = re:run(Text, "starts anyway", [unicode])
        end},
       {"an unusable upstream_client value is left to the config guard",
        fun() ->
            application:set_env(yuzu_gw, upstream_client, not_a_map),
            ?assertEqual(ok, yuzu_gw_app:check_upstream_tls_files())
        end}]).

check_upstream_client_config_test_() ->
    env_case(
      [{"a well-formed default_channel is fine",
        fun() ->
            application:set_env(yuzu_gw, upstream_client, ?DEFAULT_CHANNEL_CONFIG),
            ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config())
        end},
       {"a replaced option is warned about at boot, and the gateway still starts",
        fun() ->
            application:set_env(
              yuzu_gw, upstream_client,
              #{channels => [{default_channel, [{http, "127.0.0.1", 59999, []}],
                              #{pool_size => 100, connect_timeout => "5s"}}]}),
            Events = capture_events(
                       fun() -> ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config()) end),
            Warned = [T || {warning, T} <- Events,
                           string:find(T, "Bad values replaced") =/= nomatch],
            ?assertEqual(2, length(Warned)),
            Text = lists:flatten(Warned),
            {match, _} = re:run(Text, "default_channel: pool_size is 100, not an integer from 1 to 64; "
                                      "the default 1 is used", [unicode]),
            {match, _} = re:run(Text, "connect_timeout is a list, not an integer from 1 to 600000; "
                                      "the default 5000 is used", [unicode]),
            {match, _} = re:run(Text, "Bad values replaced by defaults", [unicode]),
            %% the value of a non-integer is never printed
            nomatch = re:run(Text, "5s", [unicode])
        end},
       {"an in-range configuration warns about nothing of the kind",
        fun() ->
            application:set_env(
              yuzu_gw, upstream_client,
              #{channels => [{default_channel, [{http, "127.0.0.1", 59999, []}],
                              #{pool_size => 1, connect_timeout => 1000}}]}),
            Events = capture_events(
                       fun() -> ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config()) end),
            ?assertEqual([], [T || {_, T} <- Events,
                                   string:find(T, "Bad values replaced") =/= nomatch])
        end},
       {"no upstream_client key is refused",
        fun() ->
            ?assertEqual({error, no_upstream_channel},
                         yuzu_gw_app:check_upstream_client_config())
        end},
       {"an empty channel list is refused",
        fun() ->
            application:set_env(yuzu_gw, upstream_client, #{channels => []}),
            ?assertEqual({error, no_upstream_channel},
                         yuzu_gw_app:check_upstream_client_config())
        end},
       {"channels none of which is default_channel are refused",
        fun() ->
            application:set_env(yuzu_gw, upstream_client,
                                #{channels => [{other_channel,
                                                [{http, "127.0.0.1", 59999, []}], #{}}]}),
            ?assertEqual({error, no_upstream_channel},
                         yuzu_gw_app:check_upstream_client_config())
        end},
       {"{allow_no_upstream, true} accepts a gateway with none",
        fun() ->
            application:set_env(yuzu_gw, allow_no_upstream, true),
            ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config())
        end},
       {"only the literal true is an acknowledgement",
        fun() ->
            [begin
                 application:set_env(yuzu_gw, allow_no_upstream, Value),
                 ?assertEqual({error, no_upstream_channel},
                              yuzu_gw_app:check_upstream_client_config())
             end || Value <- [false, "true", <<"true">>, 1, yes]]
        end},
       {"{allow_no_upstream, true} does not excuse an unusable channel",
        fun() ->
            application:set_env(yuzu_gw, allow_no_upstream, true),
            application:set_env(yuzu_gw, upstream_client, #{channels => [bogus]}),
            ?assertEqual({error, bad_upstream_client_config},
                         yuzu_gw_app:check_upstream_client_config())
        end},
       {"a value that is not a channels map is refused",
        fun() ->
            application:set_env(yuzu_gw, upstream_client, not_a_map),
            ?assertEqual({error, bad_upstream_client_config},
                         yuzu_gw_app:check_upstream_client_config())
        end},
       {"a channel that is not {Name, Endpoints, Options} is refused",
        fun() ->
            application:set_env(yuzu_gw, upstream_client, #{channels => [default_channel]}),
            ?assertEqual({error, bad_upstream_client_config},
                         yuzu_gw_app:check_upstream_client_config())
        end},
       {"an endpoint with a port out of range is refused",
        fun() ->
            application:set_env(yuzu_gw, upstream_client,
                                #{channels => [{default_channel,
                                                [{http, "127.0.0.1", 0, []}], #{}}]}),
            ?assertEqual({error, bad_upstream_client_config},
                         yuzu_gw_app:check_upstream_client_config())
        end}]).

%% The refusal names the shape of the defect and nothing of the value: an
%% endpoint's SSL options name key files.
check_upstream_client_config_logs_no_value_test_() ->
    env_case(
      [fun() ->
          application:set_env(yuzu_gw, upstream_client,
                              #{channels => [{default_channel,
                                              [{https, "gw-upstream.example", 50051,
                                                [{certfile, "/secret/gw-leaf.pem"}], not_a_map}],
                                              #{}}]}),
          Text = lists:flatten(
                   capture_logs(fun() ->
                                    ?assertEqual({error, bad_upstream_client_config},
                                                 yuzu_gw_app:check_upstream_client_config())
                                end)),
          {match, _} = re:run(Text, "Refusing to start: the upstream channel configuration",
                              [unicode]),
          ?assertEqual(nomatch, re:run(Text, "gw-leaf", [unicode, {capture, none}])),
          ?assertEqual(nomatch, re:run(Text, "gw-upstream.example", [unicode, {capture, none}]))
      end]).

%% What an operator reads when there is no channel: where to put one.
check_upstream_client_config_no_channel_names_the_key_test_() ->
    env_case(
      [fun() ->
          Text = lists:flatten(
                   capture_logs(fun() ->
                                    ?assertEqual({error, no_upstream_channel},
                                                 yuzu_gw_app:check_upstream_client_config())
                                end)),
          {match, _} = re:run(Text, "Refusing to start: no upstream channel is configured",
                              [unicode]),
          {match, _} = re:run(Text, "upstream_client", [unicode])
      end]).

%% Boot refuses an unusable upstream configuration before it starts anything
%% (through start/2 itself, so a guard dropped from the list is visible).
boot_refuses_an_unusable_upstream_client_config_test_() ->
    boot_refusal(fun() -> application:set_env(yuzu_gw, upstream_client, #{channels => [bogus]}) end,
                 bad_upstream_client_config).

boot_refuses_a_gateway_without_a_default_channel_test_() ->
    boot_refusal(fun() -> application:unset_env(yuzu_gw, allow_no_upstream) end,
                 no_upstream_channel).

boot_accepts_a_gateway_with_a_default_channel_test_() ->
    boot_case(
      fun() ->
          application:unset_env(yuzu_gw, allow_no_upstream),
          application:set_env(yuzu_gw, upstream_client, ?DEFAULT_CHANNEL_CONFIG),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(1, meck:num_calls(yuzu_gw_sup, start_link, []))
      end).

%% An https upstream is verified only with {verify, verify_peer} AND a trust
%% anchor of its own ({cacertfile, _} or {cacerts, _}); verify_peer alone would
%% let gun use the operating system's CA store, so boot refuses it like any
%% other unverified channel (through start/2, so a guard dropped is visible).
boot_refuses_an_https_upstream_with_verify_peer_and_no_trust_anchor_test_() ->
    Https = fun(Ssl) ->
                fun() ->
                    application:set_env(
                      yuzu_gw, upstream_client,
                      #{channels => [{default_channel,
                                      [{https, "gw-upstream.example", 50051, Ssl}], #{}}]})
                end
            end,
    [{"verify_peer alone",
      boot_refusal(Https([{verify, verify_peer}]), unverified_upstream_tls)},
     {"verify_peer with an empty cacertfile",
      boot_refusal(Https([{verify, verify_peer}, {cacertfile, ""}]), unverified_upstream_tls)},
     {"verify_peer with an empty cacerts list",
      boot_refusal(Https([{verify, verify_peer}, {cacerts, []}]), unverified_upstream_tls)},
     {"verify_none with a cacertfile",
      boot_refusal(Https([{verify, verify_none}, {cacertfile, "/etc/yuzu/ca.pem"}]),
                   unverified_upstream_tls)},
     {"no verify option",
      boot_refusal(Https([]), unverified_upstream_tls)},
     {"the refusal is logged at critical and names the missing trust anchor, not a value",
      boot_case(
        fun() ->
            Configure = Https([{verify, verify_peer}, {keyfile, "/secret/gw-leaf.key"}]),
            Configure(),
            Events = capture_events(fun() ->
                         ?assertEqual({error, unverified_upstream_tls},
                                      yuzu_gw_app:start(normal, []))
                     end),
            Refusals = [Text || {critical, Text} <- Events,
                                re:run(Text, "Refusing to start", [unicode, {capture, none}]) =:= match],
            ?assertMatch([_], Refusals),
            [Text] = Refusals,
            {match, _} = re:run(Text, "cacertfile", [unicode]),
            ?assertEqual(nomatch, re:run(Text, "gw-leaf", [unicode, {capture, none}])),
            ?assertEqual(nomatch, re:run(Text, "gw-upstream.example", [unicode, {capture, none}]))
        end)}].

boot_accepts_an_https_upstream_with_verify_peer_and_a_trust_anchor_test_() ->
    Https = fun(Ssl) ->
                fun() ->
                    application:unset_env(yuzu_gw, allow_no_upstream),
                    application:set_env(
                      yuzu_gw, upstream_client,
                      #{channels => [{default_channel,
                                      [{https, "gw-upstream.example", 50051, Ssl}], #{}}]}),
                    ?assertMatch({ok, _}, yuzu_gw_app:start(normal, []))
                end
            end,
    [{"verify_peer with a cacertfile",
      boot_case(Https([{verify, verify_peer}, {cacertfile, "/etc/yuzu/ca.pem"}]))},
     {"verify_peer with cacerts",
      boot_case(Https([{verify, verify_peer}, {cacerts, [<<48, 3, 2, 1, 1>>]}]))}].

%% The dev/CI override still lets an unverified upstream boot (and says so).
boot_allows_an_unverified_upstream_only_with_the_override_test_() ->
    boot_case(
      fun() ->
          application:unset_env(yuzu_gw, allow_no_upstream),
          application:set_env(yuzu_gw, upstream_client,
                              #{channels => [{default_channel,
                                              [{https, "gw-upstream.example", 50051,
                                                [{verify, verify_peer}]}], #{}}]}),
          Prev = os:getenv("YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM"),
          try
              os:putenv("YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM", "1"),
              ?assertMatch({ok, _}, yuzu_gw_app:start(normal, []))
          after
              case Prev of
                  false -> os:unsetenv("YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM");
                  P     -> os:putenv("YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM", P)
              end
          end
      end).

%%%===================================================================
%%% The TLS posture of the upstream channels
%%%
%%% Calls go round-robin over EVERY connection of a channel, so what decides
%%% the boot guard and the boot log is the WEAKEST endpoint, not the strongest:
%%% one unverified (or plaintext) endpoint beside a verified one carries calls.
%%%===================================================================

-define(CA_FILE, {cacertfile, "/etc/yuzu/ca.pem"}).
-define(UP_HOST, "gw-upstream.example").

%% An https endpoint: server verified against a CA of its own.
ep_verified() -> {https, ?UP_HOST, 50051, [{verify, verify_peer}, ?CA_FILE]}.
%% ...and presenting a certificate of its own.
ep_mutual() ->
    {https, ?UP_HOST, 50051, [{verify, verify_peer}, ?CA_FILE,
                              {certfile, "/etc/yuzu/gw-leaf.pem"},
                              {keyfile, "/etc/yuzu/gw-leaf.key"}]}.
%% Encrypted, not authenticated.
ep_unverified() -> {https, ?UP_HOST, 50051, []}.
ep_plain() -> {http, ?UP_HOST, 50051, []}.

client(Channels) -> #{channels => Channels}.
chan(Name, Endpoints) -> {Name, Endpoints, #{}}.
default(Endpoints) -> client([chan(default_channel, Endpoints)]).

%%--------------------------------------------------------------------
%% Pure: client_tls_weakest/1, client_has_unverified/1, client_mixed_channels/1,
%% client_all_present_client_cert/1
%%--------------------------------------------------------------------

client_tls_weakest_test_() ->
    W = fun yuzu_gw_app:client_tls_weakest/1,
    [{"no endpoint at all is plaintext",
      [?_assertEqual(plaintext, W(undefined)),
       ?_assertEqual(plaintext, W(client([]))),
       ?_assertEqual(plaintext, W(client([chan(default_channel, [])]))),
       ?_assertEqual(plaintext, W(not_a_client)),
       ?_assertEqual(plaintext, W(#{channels => not_a_list}))]},
     {"one endpoint reads as itself",
      [?_assertEqual(verified, W(default([ep_verified()]))),
       ?_assertEqual(verified, W(default([ep_mutual()]))),
       ?_assertEqual(unverified, W(default([ep_unverified()]))),
       ?_assertEqual(plaintext, W(default([ep_plain()])))]},
     {"the weakest endpoint of a channel decides",
      [?_assertEqual(unverified, W(default([ep_verified(), ep_unverified()]))),
       ?_assertEqual(unverified, W(default([ep_unverified(), ep_verified()]))),
       ?_assertEqual(plaintext, W(default([ep_verified(), ep_plain()]))),
       ?_assertEqual(plaintext, W(default([ep_plain(), ep_verified()]))),
       ?_assertEqual(plaintext, W(default([ep_unverified(), ep_plain(), ep_verified()]))),
       ?_assertEqual(verified, W(default([ep_verified(), ep_mutual()])))]},
     {"and so does the weakest channel",
      [?_assertEqual(plaintext,
                     W(client([chan(default_channel, [ep_verified()]), chan(other, [ep_plain()])]))),
       ?_assertEqual(unverified,
                     W(client([chan(other, [ep_verified()]), chan(default_channel, [ep_unverified()])]))),
       ?_assertEqual(verified,
                     W(client([chan(default_channel, [ep_verified()]), chan(other, [ep_mutual()])])))]},
     {"the strongest-endpoint reading (client_tls_posture/1) is a different answer for the same value",
      [?_assertEqual(verified, yuzu_gw_app:client_tls_posture(default([ep_verified(), ep_plain()]))),
       ?_assertEqual(plaintext, W(default([ep_verified(), ep_plain()])))]},
     {"an endpoint of five elements (with settings) reads like one of four",
      [?_assertEqual(verified,
                     W(default([{https, ?UP_HOST, 50051, [{verify, verify_peer}, ?CA_FILE], #{}}]))),
       ?_assertEqual(plaintext, W(default([{http, ?UP_HOST, 50051, [], #{}}])))]},
     {"a channel or an endpoint of another shape counts as plaintext (it is refused elsewhere)",
      [?_assertEqual(plaintext, W(client([not_a_channel]))),
       ?_assertEqual(plaintext, W(default([not_an_endpoint]))),
       ?_assertEqual(plaintext, W(default([ep_verified(), not_an_endpoint])))]}].

client_has_unverified_test_() ->
    U = fun yuzu_gw_app:client_has_unverified/1,
    [?_assertEqual(false, U(undefined)),
     ?_assertEqual(false, U(client([]))),
     ?_assertEqual(false, U(not_a_client)),
     ?_assertEqual(false, U(default([ep_verified()]))),
     ?_assertEqual(false, U(default([ep_plain()]))),
     ?_assertEqual(false, U(default([ep_verified(), ep_plain()]))),
     ?_assertEqual(true, U(default([ep_unverified()]))),
     {"beside a verified endpoint of the same channel",
      ?_assertEqual(true, U(default([ep_verified(), ep_unverified()])))},
     {"beside a verified endpoint of another channel",
      ?_assertEqual(true, U(client([chan(default_channel, [ep_mutual()]),
                                    chan(other, [ep_unverified()])])))},
     {"beside a plaintext endpoint",
      ?_assertEqual(true, U(default([ep_plain(), ep_unverified()])))},
     {"verify_peer with no CA of its own is unverified",
      ?_assertEqual(true, U(default([{https, ?UP_HOST, 50051, [{verify, verify_peer}]}])))},
     {"a CA with verify_none is unverified",
      ?_assertEqual(true, U(default([{https, ?UP_HOST, 50051, [{verify, verify_none}, ?CA_FILE]}])))},
     {"SSL options that are not a list are unverified",
      ?_assertEqual(true, U(default([{https, ?UP_HOST, 50051, not_a_list}])))}].

%% What counts as a trust anchor of the endpoint's own: a CA file NAMED (a
%% non-empty printable string or a non-empty binary) or certificates GIVEN (a
%% non-empty list). An atom, an empty value or a list of numbers is not one.
trust_anchor_rule_test_() ->
    Verified = fun(Anchor) ->
                   yuzu_gw_app:client_tls_weakest(
                     default([{https, ?UP_HOST, 50051, [{verify, verify_peer} | Anchor]}]))
               end,
    NotAnchors = [{"cacertfile is an empty string", [{cacertfile, ""}]},
                  {"cacertfile is an atom", [{cacertfile, ca_file}]},
                  {"cacertfile is undefined", [{cacertfile, undefined}]},
                  {"cacertfile is an empty binary", [{cacertfile, <<>>}]},
                  {"cacertfile is a list that is not text", [{cacertfile, [1, 2, 3]}]},
                  {"cacertfile is a number", [{cacertfile, 5}]},
                  {"cacerts is empty", [{cacerts, []}]},
                  {"cacerts is the atom system", [{cacerts, system}]},
                  {"cacerts is a binary", [{cacerts, <<48, 3>>}]},
                  {"neither is given", []}],
    Anchors = [{"cacertfile is a string", [{cacertfile, "/etc/yuzu/ca.pem"}]},
               {"cacertfile is a binary", [{cacertfile, <<"/etc/yuzu/ca.pem">>}]},
               {"cacerts holds a certificate", [{cacerts, [<<48, 3, 2, 1, 1>>]}]},
               {"an empty cacertfile beside certificates",
                [{cacertfile, ""}, {cacerts, [<<48, 3, 2, 1, 1>>]}]}],
    [{"not an anchor: " ++ Why, ?_assertEqual(unverified, Verified(Opts))}
     || {Why, Opts} <- NotAnchors]
    ++ [{"an anchor: " ++ Why, ?_assertEqual(verified, Verified(Opts))} || {Why, Opts} <- Anchors].

client_mixed_channels_test_() ->
    M = fun yuzu_gw_app:client_mixed_channels/1,
    [?_assertEqual([], M(undefined)),
     ?_assertEqual([], M(not_a_client)),
     ?_assertEqual([], M(client([]))),
     ?_assertEqual([], M(client(not_a_list))),
     {"a channel of one scheme is not mixed, whatever the scheme",
      [?_assertEqual([], M(default([ep_verified(), ep_mutual()]))),
       ?_assertEqual([], M(default([ep_plain(), ep_plain()]))),
       ?_assertEqual([], M(default([ep_unverified(), ep_verified()])))]},
     {"channels of different schemes are not a mixed channel",
      ?_assertEqual([], M(client([chan(default_channel, [ep_plain()]),
                                  chan(other, [ep_verified()])])))},
     {"http beside https in one channel is mixed, in either order",
      [?_assertEqual([default_channel], M(default([ep_verified(), ep_plain()]))),
       ?_assertEqual([default_channel], M(default([ep_plain(), ep_verified()]))),
       ?_assertEqual([default_channel], M(default([ep_plain(), ep_unverified()]))),
       ?_assertEqual([default_channel], M(default([ep_plain(), ep_mutual(), ep_plain()])))]},
     {"every mixed channel is named, in order, and only they",
      ?_assertEqual([b, d],
                    M(client([chan(a, [ep_verified()]), chan(b, [ep_plain(), ep_verified()]),
                              chan(c, [ep_plain()]), chan(d, [ep_unverified(), ep_plain()])])))},
     {"a channel of another shape is skipped, not a crash",
      ?_assertEqual([], M(client([not_a_channel, {x, not_a_list, #{}}])))}].

client_all_present_client_cert_test_() ->
    C = fun yuzu_gw_app:client_all_present_client_cert/1,
    Https = fun(Ssl) -> {https, ?UP_HOST, 50051, [{verify, verify_peer}, ?CA_FILE | Ssl]} end,
    [{"no endpoint, or no client value, is false (nothing is presented)",
      [?_assertEqual(false, C(undefined)),
       ?_assertEqual(false, C(not_a_client)),
       ?_assertEqual(false, C(client([]))),
       ?_assertEqual(false, C(client([chan(default_channel, [])])))]},
     {"certfile and keyfile",
      ?_assertEqual(true, C(default([ep_mutual()])))},
     {"cert and key in memory count as well",
      [?_assertEqual(true, C(default([Https([{cert, <<1>>}, {key, {'RSAPrivateKey', <<2>>}}])]))),
       ?_assertEqual(true, C(default([Https([{certfile, "c.pem"}, {key, {'RSAPrivateKey', <<2>>}}])])))]},
     {"a certificate without its key, or a key without its certificate, is not mutual",
      [?_assertEqual(false, C(default([Https([{certfile, "c.pem"}])]))),
       ?_assertEqual(false, C(default([Https([{keyfile, "k.pem"}])]))),
       ?_assertEqual(false, C(default([Https([{cert, <<1>>}])]))),
       ?_assertEqual(false, C(default([ep_verified()])))]},
     {"EVERY endpoint must present one",
      [?_assertEqual(false, C(default([ep_mutual(), ep_verified()]))),
       ?_assertEqual(false, C(default([ep_verified(), ep_mutual()]))),
       ?_assertEqual(true, C(default([ep_mutual(), ep_mutual()]))),
       ?_assertEqual(false, C(client([chan(default_channel, [ep_mutual()]),
                                      chan(other, [ep_verified()])]))),
       ?_assertEqual(true, C(client([chan(default_channel, [ep_mutual()]),
                                     chan(other, [ep_mutual()])])))]},
     {"a plaintext endpoint presents nothing",
      [?_assertEqual(false, C(default([ep_plain()]))),
       ?_assertEqual(false, C(default([ep_mutual(), ep_plain()])))]},
     {"SSL options that are not a list present nothing",
      ?_assertEqual(false, C(default([{https, ?UP_HOST, 50051, not_a_list}])))},
     {"an endpoint with settings is read like one without",
      ?_assertEqual(true, C(default([erlang:append_element(ep_mutual(), #{})])))}].

%%--------------------------------------------------------------------
%% check_upstream_channel_mix/0
%%--------------------------------------------------------------------

%% A channel is one scheme: calls go round-robin over every live connection of
%% it, so with http and https endpoints in one channel some calls (a
%% ProxyRegister carries the enrollment token and the CSR) travel unencrypted
%% whatever the https endpoint is verified against.
check_upstream_channel_mix_test_() ->
    Set = fun(Client) -> application:set_env(yuzu_gw, upstream_client, Client) end,
    Mix = fun yuzu_gw_app:check_upstream_channel_mix/0,
    env_case(
      [{"no upstream_client is fine (the other guards answer for it)",
        fun() -> ?assertEqual(ok, Mix()) end},
       {"a value that is not a channels map is fine here (check_upstream_client_config/0 refuses it)",
        fun() -> Set(not_a_map), ?assertEqual(ok, Mix()) end},
       {"channels of one scheme each are fine",
        fun() ->
            [begin Set(Client), ?assertEqual(ok, Mix()) end
             || Client <- [default([ep_plain()]), default([ep_verified(), ep_mutual()]),
                           default([ep_unverified()]),
                           client([chan(default_channel, [ep_plain()]), chan(other, [ep_verified()])])]]
        end},
       {"http beside https in one channel is refused",
        fun() ->
            [begin Set(Client), ?assertEqual({error, mixed_upstream_endpoints}, Mix()) end
             || Client <- [default([ep_plain(), ep_verified()]), default([ep_mutual(), ep_plain()]),
                           default([ep_plain(), ep_unverified()]),
                           client([chan(default_channel, [ep_verified()]),
                                   chan(other, [ep_plain(), ep_verified()])])]]
        end},
       {"the refusal is logged at critical, names the channel and no value of its config",
        fun() ->
            Set(default([{https, "gw-secret-host.example", 50077,
                          [{verify, verify_peer}, {cacertfile, "/secret/ca/CA-FILE.pem"},
                           {certfile, "/secret/leaf/LEAF-CERT.pem"},
                           {keyfile, "/secret/leaf/LEAF-KEY.pem"}]},
                         {http, "gw-secret-plain.example", 50078, []}])),
            Events = capture_events(fun() ->
                                        ?assertEqual({error, mixed_upstream_endpoints}, Mix())
                                    end),
            ?assertMatch([{critical, _}], Events),
            [{critical, Text}] = Events,
            {match, _} = re:run(Text, "Refusing to start", [unicode]),
            {match, _} = re:run(Text, "default_channel", [unicode]),
            [?assertEqual(nomatch, re:run(Text, Secret, [unicode, {capture, none}]))
             || Secret <- ["secret", "CA-FILE", "LEAF", "50077", "50078", "gw-secret"]]
        end},
       {"the first mixed channel is the one named",
        fun() ->
            Set(client([chan(a, [ep_plain()]), chan(b, [ep_plain(), ep_verified()]),
                        chan(c, [ep_plain(), ep_verified()])])),
            [{critical, Text}] = capture_events(fun() -> {error, _} = Mix() end),
            {match, _} = re:run(Text, "channel b ", [unicode])
        end}]).

%%--------------------------------------------------------------------
%% check_upstream_tls_posture/0
%%--------------------------------------------------------------------

-define(OVERRIDE_VAR, "YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM").

%% env_case, and the dev/CI override variable cleared and put back.
posture_case(Tests) ->
    {foreach,
     fun() ->
         Saved = {env_setup(), os:getenv(?OVERRIDE_VAR)},
         os:unsetenv(?OVERRIDE_VAR),
         Saved
     end,
     fun({Env, Override}) ->
         env_cleanup(Env),
         restore_override(Override)
     end,
     Tests}.

restore_override(false) -> os:unsetenv(?OVERRIDE_VAR), ok;
restore_override(Value) -> os:putenv(?OVERRIDE_VAR, Value), ok.

check_upstream_tls_posture_test_() ->
    Set = fun(Client) -> application:set_env(yuzu_gw, upstream_client, Client) end,
    Check = fun yuzu_gw_app:check_upstream_tls_posture/0,
    Refused = {error, unverified_upstream_tls},
    posture_case(
      [{"plaintext, verified and no upstream boot",
        fun() ->
            [begin Set(Client), ?assertEqual(ok, Check()) end
             || Client <- [undefined, client([]), default([ep_plain()]), default([ep_verified()]),
                           default([ep_mutual()]), default([ep_verified(), ep_mutual()]),
                           default([ep_verified(), ep_plain()])]]
        end},
       {"https with no verification is refused",
        fun() -> Set(default([ep_unverified()])), ?assertEqual(Refused, Check()) end},
       {"an unverified https endpoint BESIDE a verified one is refused (the same channel)",
        fun() ->
            Set(default([ep_verified(), ep_unverified()])), ?assertEqual(Refused, Check()),
            Set(default([ep_unverified(), ep_verified()])), ?assertEqual(Refused, Check())
        end},
       {"...and in another channel",
        fun() ->
            Set(client([chan(default_channel, [ep_mutual()]), chan(other, [ep_unverified()])])),
            ?assertEqual(Refused, Check()),
            Set(client([chan(other, [ep_mutual()]), chan(default_channel, [ep_unverified()])])),
            ?assertEqual(Refused, Check())
        end},
       {"an unverified https endpoint beside a plaintext one is still refused",
        fun() ->
            Set(default([ep_plain(), ep_unverified()])), ?assertEqual(Refused, Check()),
            Set(client([chan(default_channel, [ep_plain()]), chan(other, [ep_unverified()])])),
            ?assertEqual(Refused, Check())
        end},
       {"verify_peer with no cacertfile and no cacerts counts as unverified",
        fun() ->
            Set(default([{https, ?UP_HOST, 50051, [{verify, verify_peer}]}])),
            ?assertEqual(Refused, Check()),
            Set(default([ep_verified(), {https, ?UP_HOST, 50052, [{verify, verify_peer}]}])),
            ?assertEqual(Refused, Check())
        end},
       {"a cacertfile that is an empty string, an atom or an empty binary is not an anchor",
        fun() ->
            [begin
                 Set(default([{https, ?UP_HOST, 50051, [{verify, verify_peer}, {cacertfile, Bad}]}])),
                 ?assertEqual(Refused, Check())
             end || Bad <- ["", ca_file, <<>>]]
        end},
       {"cacerts that is empty, or an atom, is not an anchor either",
        fun() ->
            [begin
                 Set(default([{https, ?UP_HOST, 50051, [{verify, verify_peer}, {cacerts, Bad}]}])),
                 ?assertEqual(Refused, Check())
             end || Bad <- [[], system]]
        end},
       {"a trust anchor of its own makes it verified",
        fun() ->
            [begin
                 Set(default([{https, ?UP_HOST, 50051, [{verify, verify_peer} | Anchor]}])),
                 ?assertEqual(ok, Check())
             end || Anchor <- [[{cacertfile, "/etc/yuzu/ca.pem"}], [{cacertfile, <<"/etc/yuzu/ca.pem">>}],
                               [{cacerts, [<<48, 3, 2, 1, 1>>]}]]]
        end},
       {"the refusal is logged at critical without a value of the config",
        fun() ->
            Set(default([ep_verified(),
                         {https, "gw-secret-host.example", 50077,
                          [{certfile, "/secret/leaf/LEAF-CERT.pem"},
                           {keyfile, "/secret/leaf/LEAF-KEY.pem"}]}])),
            Events = capture_events(fun() -> ?assertEqual(Refused, Check()) end),
            ?assertMatch([{critical, _}], Events),
            [{critical, Text}] = Events,
            {match, _} = re:run(Text, "Refusing to start", [unicode]),
            {match, _} = re:run(Text, ?OVERRIDE_VAR, [unicode]),
            [?assertEqual(nomatch, re:run(Text, Secret, [unicode, {capture, none}]))
             || Secret <- ["secret", "LEAF", "50077", "gw-secret", "gw-upstream"]]
        end},
       {"YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1 lets an unverified endpoint boot, and says so",
        fun() ->
            os:putenv(?OVERRIDE_VAR, "1"),
            [begin
                 Set(Client),
                 Events = capture_events(fun() -> ?assertEqual(ok, Check()) end),
                 ?assertMatch([{warning, _}], Events),
                 [{warning, Text}] = Events,
                 {match, _} = re:run(Text, "unverified", [unicode]),
                 {match, _} = re:run(Text, ?OVERRIDE_VAR, [unicode])
             end || Client <- [default([ep_unverified()]), default([ep_verified(), ep_unverified()]),
                               default([{https, ?UP_HOST, 50051, [{verify, verify_peer}]}])]]
        end},
       {"the override says nothing when nothing needs it",
        fun() ->
            os:putenv(?OVERRIDE_VAR, "1"),
            [begin
                 Set(Client),
                 Events = capture_events(fun() -> ?assertEqual(ok, Check()) end),
                 ?assertEqual([], Events)
             end || Client <- [default([ep_verified()]), default([ep_plain()]), undefined]]
        end},
       {"only the value 1 is the override",
        fun() ->
            Set(default([ep_unverified()])),
            [begin
                 os:putenv(?OVERRIDE_VAR, Value),
                 ?assertEqual(Refused, Check())
             end || Value <- ["0", "true", "yes", "", "11", " 1"]]
        end}]).

%%--------------------------------------------------------------------
%% The boot log: what the transport line says of the upstream
%%--------------------------------------------------------------------

%% The posture line is written before any guard runs, from start/2, so it is read
%% through a boot. Returns {StartResult, Events}.
boot_events(Client) ->
    application:unset_env(yuzu_gw, allow_no_upstream),
    application:set_env(yuzu_gw, upstream_client, Client),
    Events = capture_events(fun() -> put(boot_result, yuzu_gw_app:start(normal, [])) end),
    {erase(boot_result), Events}.

upstream_word(Events) ->
    [Text] = [T || {info, T} <- Events,
                   re:run(T, "Gateway transport TLS \\(configured\\)", [{capture, none}]) =:= match],
    {match, [Word]} = re:run(Text, "upstream->server=(.*), listeners:", [{capture, all_but_first, list}]),
    {Word, Text}.

warned(Events, Pattern) ->
    [T || {warning, T} <- Events, re:run(T, Pattern, [unicode, {capture, none}]) =:= match].

with_override(Fun) ->
    Prev = os:getenv(?OVERRIDE_VAR),
    try
        os:putenv(?OVERRIDE_VAR, "1"),
        Fun()
    after
        restore_override(Prev)
    end.

%% "mutual-TLS" is said only when the gateway also presents a certificate on
%% every endpoint; a verified channel without one authenticates the server to
%% the gateway and nothing more.
boot_log_names_the_upstream_posture_test_() ->
    [{"verified with no client certificate: server-authenticated TLS, not mutual",
      boot_case(
        fun() ->
            {Result, Events} = boot_events(default([ep_verified()])),
            ?assertMatch({ok, _}, Result),
            {Word, Line} = upstream_word(Events),
            ?assertEqual("server-authenticated TLS (no client certificate)", Word),
            ?assertEqual(nomatch, re:run(Line, "mutual", [{capture, none}])),
            ?assertEqual([], warned(Events, "PLAINTEXT|ENCRYPTED but")),
            %% a value of the config is not in the line
            [?assertEqual(nomatch, re:run(Line, V, [{capture, none}])) || V <- ["gw-upstream", "etc/yuzu"]]
        end)},
     {"verified with a certificate and a key: mutual-TLS",
      boot_case(
        fun() ->
            {Result, Events} = boot_events(default([ep_mutual()])),
            ?assertMatch({ok, _}, Result),
            {Word, Line} = upstream_word(Events),
            ?assertEqual("mutual-TLS", Word),
            ?assertEqual(nomatch, re:run(Line, "server-authenticated", [{capture, none}])),
            ?assertEqual([], warned(Events, "PLAINTEXT|ENCRYPTED but")),
            [?assertEqual(nomatch, re:run(Line, V, [{capture, none}])) || V <- ["gw-leaf", "gw-upstream"]]
        end)},
     {"verified with a certificate but no key: server-authenticated",
      boot_case(
        fun() ->
            Ep = {https, ?UP_HOST, 50051, [{verify, verify_peer}, ?CA_FILE,
                                           {certfile, "/etc/yuzu/gw-leaf.pem"}]},
            {_, Events} = boot_events(default([Ep])),
            ?assertEqual("server-authenticated TLS (no client certificate)",
                         element(1, upstream_word(Events)))
        end)},
     {"two endpoints, one of which presents no certificate: server-authenticated",
      boot_case(
        fun() ->
            {Result, Events} = boot_events(default([ep_mutual(), ep_verified()])),
            ?assertMatch({ok, _}, Result),
            ?assertEqual("server-authenticated TLS (no client certificate)",
                         element(1, upstream_word(Events)))
        end)},
     {"a verified endpoint beside a plaintext one is plaintext, and says so",
      boot_case(
        fun() ->
            {Result, Events} = boot_events(default([ep_mutual(), ep_plain()])),
            %% the same channel mixes schemes: the guard refuses it after the line
            ?assertEqual({error, mixed_upstream_endpoints}, Result),
            ?assertEqual("plaintext", element(1, upstream_word(Events))),
            ?assertMatch([_], warned(Events, "upstream is PLAINTEXT"))
        end)},
     {"a verified channel beside a plaintext one of another name: plaintext, and it boots",
      boot_case(
        fun() ->
            {Result, Events} = boot_events(client([chan(default_channel, [ep_plain()]),
                                                   chan(other, [ep_mutual()])])),
            ?assertMatch({ok, _}, Result),
            ?assertEqual("plaintext", element(1, upstream_word(Events))),
            ?assertMatch([_], warned(Events, "upstream is PLAINTEXT"))
        end)},
     {"plaintext only",
      boot_case(
        fun() ->
            {Result, Events} = boot_events(default([ep_plain()])),
            ?assertMatch({ok, _}, Result),
            ?assertEqual("plaintext", element(1, upstream_word(Events))),
            ?assertMatch([_], warned(Events, "upstream is PLAINTEXT"))
        end)},
     {"an unverified endpoint beside a verified one: UNVERIFIED, with the warning, under the override",
      boot_case(
        fun() ->
            with_override(
              fun() ->
                  {Result, Events} = boot_events(default([ep_mutual(), ep_unverified()])),
                  ?assertMatch({ok, _}, Result),
                  ?assertEqual("TLS(UNVERIFIED!)", element(1, upstream_word(Events))),
                  ?assertMatch([_], warned(Events, "does NOT verify the server certificate")),
                  ?assertMatch([_], warned(Events, ?OVERRIDE_VAR))
              end)
        end)},
     {"verify_peer with no CA of its own: UNVERIFIED, and refused without the override",
      boot_case(
        fun() ->
            {Result, Events} = boot_events(default([{https, ?UP_HOST, 50051, [{verify, verify_peer}]}])),
            ?assertEqual({error, unverified_upstream_tls}, Result),
            ?assertEqual("TLS(UNVERIFIED!)", element(1, upstream_word(Events))),
            ?assertMatch([_], warned(Events, "CA of its own"))
        end)}].

%%--------------------------------------------------------------------
%% Several connections on one channel
%%--------------------------------------------------------------------

%% pool_size above 1, or several endpoints, spreads one gateway's calls over
%% several connections: behind a layer-4 VIP in front of several core replicas
%% that means different replicas. Allowed, and said at boot.
check_upstream_client_config_warns_on_several_connections_test_() ->
    Set = fun(Client) -> application:set_env(yuzu_gw, upstream_client, Client) end,
    Check = fun() ->
                Events = capture_events(fun() ->
                                            ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config())
                                        end),
                [T || {warning, T} <- Events,
                      re:run(T, "connections", [{capture, none}]) =:= match]
            end,
    Ep = fun(Port) -> {http, "gw-secret-host.example", Port, []} end,
    env_case(
      [{"one endpoint, pool_size 1: nothing to say",
        fun() ->
            Set(default([Ep(50051)])),
            ?assertEqual([], Check())
        end},
       {"pool_size 4: the channel and the count",
        fun() ->
            Set(client([{default_channel, [Ep(50051)], #{pool_size => 4}}])),
            [Text] = Check(),
            {match, _} = re:run(Text, "channel default_channel holds 4 connections "
                                      "\\(pool_size 4, 1 endpoint\\(s\\)\\)", [unicode])
        end},
       {"two endpoints, pool_size 1",
        fun() ->
            Set(default([Ep(50051), Ep(50052)])),
            [Text] = Check(),
            {match, _} = re:run(Text, "holds 2 connections \\(pool_size 1, 2 endpoint", [unicode])
        end},
       {"pool_size 2 over 3 endpoints is 6 connections",
        fun() ->
            Set(client([{default_channel, [Ep(50051), Ep(50052), Ep(50053)], #{pool_size => 2}}])),
            [Text] = Check(),
            {match, _} = re:run(Text, "holds 6 connections \\(pool_size 2, 3 endpoint", [unicode])
        end},
       {"only the channel that holds several is named",
        fun() ->
            Set(client([{default_channel, [Ep(50051)], #{}},
                        {wide, [Ep(50052)], #{pool_size => 3}}])),
            [Text] = Check(),
            {match, _} = re:run(Text, "channel wide holds 3 connections", [unicode])
        end},
       {"the warning names no endpoint",
        fun() ->
            Set(default([Ep(50051), Ep(50052)])),
            [Text] = Check(),
            [?assertEqual(nomatch, re:run(Text, V, [unicode, {capture, none}]))
             || V <- ["gw-secret", "50051", "50052"]]
        end},
       {"a configuration that is refused warns of nothing",
        fun() ->
            Set(client([{default_channel, [Ep(50051)], #{pool_size => 4}}, bogus])),
            Events = capture_events(
                       fun() ->
                           ?assertEqual({error, bad_upstream_client_config},
                                        yuzu_gw_app:check_upstream_client_config())
                       end),
            ?assertEqual([], [T || {warning, T} <- Events])
        end}]).

%% Two channels of one name are refused where the config is read, and the
%% refusal names no value.
check_upstream_client_config_refuses_duplicate_channels_test_() ->
    env_case(
      [fun() ->
          application:set_env(yuzu_gw, upstream_client,
                              #{channels => [{default_channel,
                                              [{https, "gw-secret-host.example", 50051,
                                                [{keyfile, "/secret/LEAF-KEY.pem"}]}], #{}},
                                             {default_channel,
                                              [{http, "gw-secret-other.example", 50052, []}], #{}}]}),
          Text = lists:flatten(
                   capture_logs(fun() ->
                                    ?assertEqual({error, bad_upstream_client_config},
                                                 yuzu_gw_app:check_upstream_client_config())
                                end)),
          {match, _} = re:run(Text, "Refusing to start: the upstream channel configuration", [unicode]),
          [?assertEqual(nomatch, re:run(Text, V, [unicode, {capture, none}]))
           || V <- ["gw-secret", "LEAF-KEY", "50051", "50052"]]
      end]).


%%%===================================================================
%%% The leftover {grpcbox, client} block
%%%===================================================================

%% OTP applies a sys.config entry only to a LOADED application and none is named
%% grpcbox, so a leftover {grpcbox, [{client, ...}]} is invisible rather than
%% unused: the gateway would start without the TLS options the operator can
%% read in the file. Boot refuses it, as it refuses {grpcbox, servers}.
check_legacy_grpcbox_client_test_() ->
    env_case(
      [{"no client key is fine",
        fun() ->
            ?assertEqual(ok, yuzu_gw_app:check_legacy_grpcbox_client())
        end},
       {"an empty or undefined client value is fine",
        fun() ->
            [begin
                 application:set_env(grpcbox, client, V),
                 ?assertEqual(ok, yuzu_gw_app:check_legacy_grpcbox_client())
             end || V <- [[], undefined]]
        end},
       {"a client value in the application env is refused",
        fun() ->
            application:set_env(grpcbox, client, ?DEFAULT_CHANNEL_CONFIG),
            ?assertEqual({error, legacy_grpcbox_client},
                         yuzu_gw_app:check_legacy_grpcbox_client())
        end},
       {"anything else under client is refused too",
        fun() ->
            application:set_env(grpcbox, client, not_a_map),
            ?assertEqual({error, legacy_grpcbox_client},
                         yuzu_gw_app:check_legacy_grpcbox_client())
        end},
       {"the refusal names the new key and quotes no value",
        fun() ->
            application:set_env(grpcbox, client,
                                #{channels => [{default_channel,
                                                [{https, "gw-upstream.example", 50051,
                                                  [{certfile, "/secret/gw-leaf.pem"}]}], #{}}]}),
            Text = lists:flatten(
                     capture_logs(fun() ->
                                      ?assertEqual({error, legacy_grpcbox_client},
                                                   yuzu_gw_app:check_legacy_grpcbox_client())
                                  end)),
            {match, _} = re:run(Text, "Refusing to start: \\{grpcbox, \\[\\{client, \\.\\.\\.\\}\\]\\} is set",
                                [unicode]),
            {match, _} = re:run(Text, "upstream_client", [unicode]),
            ?assertEqual(nomatch, re:run(Text, "gw-leaf", [unicode, {capture, none}])),
            ?assertEqual(nomatch, re:run(Text, "gw-upstream.example", [unicode, {capture, none}]))
        end}]).

boot_refuses_a_leftover_grpcbox_client_block_test_() ->
    boot_refusal(fun() -> application:set_env(grpcbox, client, ?DEFAULT_CHANNEL_CONFIG) end,
                 legacy_grpcbox_client).

%% Which refusal an operator reads first when several guards would refuse:
%% the two leftover grpcbox blocks (servers, then client), then the listener
%% entries, then the upstream channel configuration. Each pair below holds the
%% earlier defect and the later one at once.
boot_refuses_in_the_order_the_guards_run_test_() ->
    Legacy = fun() -> application:set_env(grpcbox, client, ?DEFAULT_CHANNEL_CONFIG) end,
    BadListeners = fun() -> application:set_env(yuzu_gw, grpc_listeners, [bogus]) end,
    BadUpstream = fun() -> application:set_env(yuzu_gw, upstream_client, #{channels => [bogus]}) end,
    [{"servers before client",
      boot_refusal(fun() ->
                       application:set_env(grpcbox, servers, [#{listen_opts => #{port => 50051}}]),
                       Legacy()
                   end,
                   legacy_grpcbox_servers)},
     {"a leftover client before a bad listener entry",
      boot_refusal(fun() -> Legacy(), BadListeners() end, legacy_grpcbox_client)},
     {"a bad listener entry before a bad upstream configuration",
      boot_refusal(fun() -> BadListeners(), BadUpstream() end, bad_grpc_listeners)},
     {"a bad upstream configuration before a missing default channel",
      boot_refusal(fun() ->
                       application:unset_env(yuzu_gw, allow_no_upstream),
                       BadUpstream()
                   end,
                   bad_upstream_client_config)}].

%% The leftover block is looked for in the config files the VM was started
%% with as well: OTP never copies an entry for an unloaded application into the
%% application env, so that is where a sys.config one is. Each case writes its
%% own files and removes them.
legacy_grpcbox_in_files_test_() ->
    {foreach,
     fun config_dir_setup/0,
     fun config_dir_cleanup/1,
     [fun(Dir) ->
          {"a grpcbox client entry in a config file is found, and servers is not",
           fun() ->
               F = write_config(Dir, "a.config", [{grpcbox, [{client, #{channels => []}}]}]),
               ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [F])),
               ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [F]))
           end}
      end,
      fun(Dir) ->
          {"a servers entry in a config file is found, and client is not",
           fun() ->
               F = write_config(Dir, "b.config", [{grpcbox, [{servers, [#{}]}]}]),
               ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(servers, [F])),
               ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [F]))
           end}
      end,
      fun(Dir) ->
          {"an empty value, and other applications' entries, are not a leftover",
           fun() ->
               F = write_config(Dir, "c.config",
                                [{grpcbox, [{client, []}, {servers, []}]},
                                 {yuzu_gw, [{upstream_client, ?DEFAULT_CHANNEL_CONFIG}]}]),
               ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [F])),
               ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [F]))
           end}
      end,
      fun(Dir) ->
          {"the file name may omit .config, as the VM's -config accepts",
           fun() ->
               F = write_config(Dir, "d.config", [{grpcbox, [{client, #{channels => []}}]}]),
               ?assertEqual(found,
                            yuzu_gw_app:legacy_grpcbox_in_files(client, [filename:rootname(F)]))
           end}
      end,
      fun(Dir) ->
          {"a file named by another config file is followed",
           fun() ->
               Inner = write_config(Dir, "inner.config",
                                    [{grpcbox, [{client, #{channels => []}}]}]),
               Outer = write_config(Dir, "outer.config", [Inner]),
               ?assertEqual(found, yuzu_gw_app:legacy_grpcbox_in_files(client, [Outer]))
           end}
      end,
      fun(Dir) ->
          {"a file that is missing or is not a config is skipped, not a crash",
           fun() ->
               Bad = filename:join(Dir, "bad.config"),
               ok = file:write_file(Bad, <<"this is not [erlang">>),
               ?assertEqual(absent,
                            yuzu_gw_app:legacy_grpcbox_in_files(
                              client, [filename:join(Dir, "missing.config"), Bad]))
           end}
      end,
      fun(Dir) ->
          {"a file that names itself ends: nesting is bounded",
           fun() ->
               Self = filename:join(Dir, "self.config"),
               ok = file:write_file(Self, io_lib:format("~p.~n", [[Self]])),
               ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [Self]))
           end}
      end]}.

config_dir_setup() ->
    Dir = filename:join(os:getenv("TMPDIR", "/tmp"),
                        "yuzu_test_app_cfg_" ++ os:getpid() ++ "_"
                        ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_path(Dir),
    Dir.

config_dir_cleanup(Dir) ->
    _ = [file:delete(F) || F <- filelib:wildcard(filename:join(Dir, "*"))],
    _ = file:del_dir(Dir),
    ok.

write_config(Dir, Name, Terms) ->
    Path = filename:join(Dir, Name),
    ok = file:write_file(Path, io_lib:format("~p.~n", [Terms])),
    Path.

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

%% The refusal is the whole explanation: the listener summary printed before the
%% guards reads "none configured" for an entry that was never read, which sends
%% an operator looking for the wrong problem.
boot_refusing_a_leftover_grpcbox_servers_block_logs_no_listener_summary_test_() ->
    boot_case(
      fun() ->
          application:set_env(grpcbox, servers, [#{listen_opts => #{port => 50051}}]),
          Text = lists:flatten(
                   capture_logs(fun() ->
                                    ?assertEqual({error, legacy_grpcbox_servers},
                                                 yuzu_gw_app:start(normal, []))
                                end)),
          {match, _} = re:run(Text, "Refusing to start: \\{grpcbox, servers\\} is set", [unicode]),
          ?assertEqual(nomatch, re:run(Text, "none configured", [unicode, {capture, none}])),
          ?assertEqual(nomatch, re:run(Text, "transport TLS", [unicode, {capture, none}]))
      end).

%% An unset or empty grpc_listeners is the state the operator reaches by removing
%% the refused {grpcbox, servers} block and adding nothing.
boot_refuses_an_unset_or_empty_grpc_listeners_test_() ->
    [boot_refusal(fun() -> application:unset_env(yuzu_gw, allow_no_listeners) end,
                  no_grpc_listeners),
     boot_refusal(fun() ->
                      application:unset_env(yuzu_gw, allow_no_listeners),
                      application:set_env(yuzu_gw, grpc_listeners, [])
                  end,
                  no_grpc_listeners),
     boot_refusal(fun() ->
                      application:set_env(yuzu_gw, allow_no_listeners, false)
                  end,
                  no_grpc_listeners)].

%% What an operator reads at boot, through start/2 itself.
boot_logs_an_unset_grpc_listeners_refusal_test_() ->
    boot_case(
      fun() ->
          application:unset_env(yuzu_gw, allow_no_listeners),
          Text = lists:flatten(
                   capture_logs(fun() ->
                                    ?assertEqual({error, no_grpc_listeners},
                                                 yuzu_gw_app:start(normal, []))
                                end)),
          {match, _} = re:run(Text, "Refusing to start: \\{yuzu_gw, grpc_listeners\\} is unset or empty", [unicode]),
          {match, _} = re:run(Text, "allow_no_listeners", [unicode])
      end).

%% The refusals are CRITICAL events: an operator's log shipper alerts on the
%% level, and a refusal logged lower would be read as a clean start that stopped.
boot_refusals_are_logged_at_critical_test_() ->
    Levels = fun(Configure) ->
                 fun() ->
                     Configure(),
                     Events = capture_events(fun() -> {error, _} = yuzu_gw_app:start(normal, []) end),
                     [L || {L, Text} <- Events,
                           re:run(Text, "Refusing to start", [unicode, {capture, none}]) =:= match]
                 end
             end,
    [{"no listeners configured",
      boot_case(fun() ->
                    application:unset_env(yuzu_gw, allow_no_listeners),
                    ?assertEqual([critical],
                                 (Levels(fun() -> application:set_env(yuzu_gw, grpc_listeners, []) end))())
                end)},
     {"no listener routes the AgentService",
      boot_case(fun() ->
                    application:unset_env(yuzu_gw, allow_no_listeners),
                    ?assertEqual([critical],
                                 (Levels(fun() ->
                                             application:set_env(yuzu_gw, grpc_listeners,
                                                                 [(agent_entry())#{services := #{}}])
                                         end))())
                end)},
     {"a leftover grpcbox servers block",
      boot_case(fun() ->
                    ?assertEqual([critical],
                                 (Levels(fun() ->
                                             application:set_env(grpcbox, servers,
                                                                 [#{listen_opts => #{port => 50051}}])
                                         end))())
                end)},
     {"a leftover grpcbox client block",
      boot_case(fun() ->
                    ?assertEqual([critical],
                                 (Levels(fun() ->
                                             application:set_env(grpcbox, client, ?DEFAULT_CHANNEL_CONFIG)
                                         end))())
                end)},
     {"no upstream channel",
      boot_case(fun() ->
                    ?assertEqual([critical],
                                 (Levels(fun() ->
                                             application:unset_env(yuzu_gw, allow_no_upstream)
                                         end))())
                end)}].

%% An entry in the shape of the former grpcbox block (certificates in
%% transport_opts) never starts as a plaintext listener: boot names the defect
%% and where the key went.
boot_logs_a_former_shape_entry_refusal_test_() ->
    boot_case(
      fun() ->
          Former = maps:without([listen], agent_entry()),
          application:set_env(yuzu_gw, grpc_listeners,
                              [Former#{listen_opts => #{port => 50051},
                                       transport_opts => #{ssl => true, certfile => "gw.pem",
                                                           keyfile => "gw.key",
                                                           cacertfile => "ca.pem"}}]),
          Text = lists:flatten(
                   capture_logs(fun() ->
                                    ?assertEqual({error, bad_grpc_listeners},
                                                 yuzu_gw_app:start(normal, []))
                                end)),
          {match, _} = re:run(Text, "Refusing to start: invalid \\{yuzu_gw, grpc_listeners\\} entry", [unicode]),
          {match, _} = re:run(Text, "legacy_keys", [unicode]),
          {match, _} = re:run(Text, "transport_opts", [unicode]),
          {match, _} = re:run(Text, "listen_opts", [unicode]),
          %% the hint says where the key went
          {match, _} = re:run(Text, "renamed `tls'", [unicode]),
          {match, _} = re:run(Text, "renamed `listen'", [unicode]),
          ?assertEqual(0, meck:num_calls(yuzu_gw_sup, start_link, []))
      end).

boot_refuses_valid_entries_with_no_agent_listener_test_() ->
    boot_refusal(fun() ->
                     application:unset_env(yuzu_gw, allow_no_listeners),
                     application:set_env(yuzu_gw, grpc_listeners, [mgmt_entry()])
                 end,
                 no_agent_listener).

boot_accepts_no_listeners_when_the_configuration_says_so_test_() ->
    boot_case(
      fun() ->
          application:set_env(yuzu_gw, allow_no_listeners, true),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(1, meck:num_calls(yuzu_gw_sup, start_link, []))
      end).

boot_refuses_an_invalid_listener_entry_test_() ->
    boot_refusal(fun() ->
                     application:set_env(yuzu_gw, grpc_listeners,
                                         [(mgmt_entry())#{tls := #{certfile => "gw.pem"}}])
                 end,
                 bad_grpc_listeners).

%% The TLS summary printed before the guards walks the same value: an improper
%% list is a refusal there too, not a crash of start/2.
boot_refuses_a_listeners_value_that_is_an_improper_list_test_() ->
    boot_refusal(fun() ->
                     os:putenv("YUZU_GW_AGENT_PORT", "52001"),
                     application:set_env(yuzu_gw, grpc_listeners, [agent_entry() | not_a_list])
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
      fun() ->
          Configure(),
          ?assertEqual({error, Reason}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(0, meck:num_calls(yuzu_gw_sup, start_link, [])),
          ?assertEqual(0, meck:num_calls(prometheus_httpd, start, [])),
          ?assertEqual(0, meck:num_calls(yuzu_gw_telemetry, setup, [])),
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
    %% ...and with no listeners at all, which boot refuses unless told it is meant
    %% (the tests that are about that unset it again).
    application:set_env(yuzu_gw, allow_no_listeners, true),
    %% ...and with no upstream channel, likewise.
    application:set_env(yuzu_gw, allow_no_upstream, true),
    PrevPrometheus = application:get_env(prometheus, prometheus_http),
    AbsentKeys = [K || K <- [?SUMMARY_KEY, ?THROTTLE_KEY | ?SAFE_CALL_KEYS],
                       persistent_term:get(K, undefined) =:= undefined],
    %% rebar3 runs eunit on a named node with a short cookie.
    os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", "1"),
    ok = yuzu_gw_crash_redact:remove(),
    Fixture = #{env => PrevEnv, cookie_flag => PrevCookieFlag, prometheus => PrevPrometheus,
                absent_keys => AbsentKeys, extra => Extra},
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
               absent_keys := AbsentKeys, extra := Extra}) ->
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
    persistent_term:erase(?SUMMARY_KEY).
