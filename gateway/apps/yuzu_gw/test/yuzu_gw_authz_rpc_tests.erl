%%%-------------------------------------------------------------------
%%% @doc RPC-level tests for the mgmt-plane SPKI peer pin (#1422).
%%%
%%% Starts a REAL yuzu_grpc_listener TLS listener shaped like the :50063
%%% mgmt listener (strict mTLS + auth_fun => yuzu_gw_authz:check_mgmt_peer/1)
%%% plus a second listener shaped like the :50051 agent listener
%%% (verify_none, no auth_fun), then drives them with real gRPC client
%%% channels (yuzu_grpc_client_channel) holding different leaf certs. Proves,
%%% at gRPC-status level (NOT just a TLS handshake):
%%%   - the pinned server leaf is admitted (unary + streaming);
%%%   - a CA-issued agent leaf gets UNAUTHENTICATED (status 16) and the
%%%     service callback is NEVER invoked;
%%%   - the gateway's own (group-readable) leaf likewise gets 16;
%%%   - a certless peer cannot reach the mgmt plane at all
%%%     (fail_if_no_peer_cert);
%%%   - a certless peer still completes RPCs against the agent-listener
%%%     posture — the auth_fun must never leak onto :50051.
%%%
%%% Listeners and channels come from yuzu_gw_test_listener (OS-assigned
%%% ports; two runner agents share each CI box).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_authz_rpc_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.server.v1.ManagementService').
-define(LIST_PATH, <<"/yuzu.server.v1.ManagementService/ListAgents">>).
-define(SEND_PATH, <<"/yuzu.server.v1.ManagementService/SendCommand">>).

rpc_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        case State of
            #{} ->
                [{"pinned server leaf admitted (unary)",
                  fun() -> unary_ok(State) end},
                 {"agent leaf gets UNAUTHENTICATED; handler never runs (unary)",
                  fun() -> unary_agent_rejected(State) end},
                 {"gateway's own leaf gets UNAUTHENTICATED (unary)",
                  fun() -> unary_gateway_rejected(State) end},
                 {"agent leaf gets UNAUTHENTICATED on the streaming RPC",
                  fun() -> stream_agent_rejected(State) end},
                 {"pinned server leaf admitted on the streaming RPC",
                  fun() -> stream_ok(State) end},
                 {"certless peer cannot reach the mgmt listener",
                  fun() -> certless_mgmt_blocked(State) end},
                 {"certless peer completes RPCs on the agent-listener posture",
                  fun() -> certless_agent_listener_ok(State) end}];
            {error, Why} ->
                %% openssl unavailable: no tests, announced, or a failing
                %% test when YUZU_REQUIRE_TLS_TESTS=1.
                yuzu_gw_authz_tests:certs_unavailable("yuzu_gw_authz_rpc_tests", Why)
        end
     end}.

%%%-------------------------------------------------------------------
%%% Cases
%%%-------------------------------------------------------------------

unary_ok(#{chan_srv := Chan}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    ?assertMatch({ok, #{agents := []}, _}, list_agents(Chan)),
    ?assertEqual(1, yuzu_gw_authz_stub_svc:invocations()).

unary_agent_rejected(#{chan_agent := Chan}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    ?assertMatch({error, {<<"16">>, _}, _}, list_agents(Chan)),
    ?assertEqual(0, yuzu_gw_authz_stub_svc:invocations()).

unary_gateway_rejected(#{chan_gw := Chan}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    ?assertMatch({error, {<<"16">>, _}, _}, list_agents(Chan)),
    ?assertEqual(0, yuzu_gw_authz_stub_svc:invocations()).

stream_agent_rejected(#{chan_agent := Chan}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?SEND_PATH, send_command_def(),
                                       #{channel => Chan}),
    ok = yuzu_gw_test_client:send(S, #{agent_ids => [], timeout_seconds => 1}),
    ok = yuzu_gw_test_client:close_send(S),
    ?assertMatch({error, {<<"16">>, _}}, stream_result(S)),
    ?assertEqual(0, yuzu_gw_authz_stub_svc:invocations()).

stream_ok(#{chan_srv := Chan}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?SEND_PATH, send_command_def(),
                                       #{channel => Chan}),
    ok = yuzu_gw_test_client:send(S, #{agent_ids => [], timeout_seconds => 1}),
    ok = yuzu_gw_test_client:close_send(S),
    ?assertMatch({ok, {<<"0">>, _, _}}, stream_result(S)),
    ?assertEqual(1, yuzu_gw_authz_stub_svc:invocations()).

certless_mgmt_blocked(#{mgmt_port := Port, certs := #{ca := Ca}}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    %% No client cert: the strict listener refuses the handshake
    %% (fail_if_no_peer_cert) — the connection never becomes gRPC.
    Res = ssl:connect("localhost", Port,
                      [{cacertfile, Ca}, {verify, verify_peer},
                       {versions, ['tlsv1.2']}, {mode, binary}, {active, false},
                       {server_name_indication, "localhost"}], 5000),
    Blocked = case Res of
        {error, _} -> true;
        {ok, Sock} ->
            %% Some TLS stacks complete the handshake and then kill the
            %% session; a dead socket on first read is equally blocked.
            R = ssl:recv(Sock, 0, 2000),
            catch ssl:close(Sock),
            R =/= {ok, <<>>} andalso element(1, R) =:= error
    end,
    ?assert(Blocked),
    ?assertEqual(0, yuzu_gw_authz_stub_svc:invocations()).

certless_agent_listener_ok(#{chan_agentless := Chan}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    %% The verify_none/no-auth_fun posture (the :50051 agent listener) must
    %% keep serving certless peers — an auth_fun leaked onto it would turn
    %% every unenrolled-agent bootstrap into UNAUTHENTICATED.
    ?assertMatch({ok, #{agents := []}, _}, list_agents(Chan)),
    ?assertEqual(1, yuzu_gw_authz_stub_svc:invocations()).

%%%-------------------------------------------------------------------
%%% client plumbing
%%%-------------------------------------------------------------------

list_agents(Chan) ->
    Def = #{marshal => fun(M) ->
                management_pb:encode_msg(M, 'yuzu.server.v1.ListAgentsRequest')
            end,
            unmarshal => fun(B) ->
                management_pb:decode_msg(B, 'yuzu.server.v1.ListAgentsResponse')
            end},
    yuzu_gw_test_client:unary(ctx:new(), ?LIST_PATH, #{limit => 10}, Def,
                             #{channel => Chan}).

send_command_def() ->
    #{marshal => fun(M) ->
          management_pb:encode_msg(M, 'yuzu.server.v1.SendCommandRequest')
      end,
      unmarshal => fun(B) ->
          management_pb:decode_msg(B, 'yuzu.server.v1.SendCommandResponse')
      end}.

%% Drain a client stream to its terminating trailers.
stream_result(S) ->
    case yuzu_gw_test_client:recv_trailers(S, 5000) of
        {ok, {<<"0">>, _, _} = T} -> {ok, T};
        {ok, {Status, Msg, _}}    -> {error, {Status, Msg}};
        Other                     -> Other
    end.

%%%-------------------------------------------------------------------
%%% Fixture
%%%-------------------------------------------------------------------

setup() ->
    case yuzu_gw_authz_tests:setup_certs() of
        {error, _} = E ->
            E;
        Certs = #{dir := Dir, ca := Ca, srv_pem := SrvPem} ->
            {ok, _} = application:ensure_all_started(telemetry),
            yuzu_gw_authz_stub_svc:init_counters(),
            application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
            %% What the running gateway's yuzu_gw_mgmt_pins does at boot: the
            %% auth_fun reads the published pin, never the file.
            ok = yuzu_gw_mgmt_pins:refresh(),
            Tls = #{certfile => filename:join(Dir, "gw.pem"),
                    keyfile => filename:join(Dir, "gw.key"),
                    cacertfile => Ca},
            Base = #{service_protos => [management_pb],
                     services => #{?SVC => yuzu_gw_authz_stub_svc}},
            %% Mgmt-shaped listener: strict mTLS + the pin auth_fun.
            {MgmtPort, MgmtSrv} = yuzu_gw_test_listener:start(
                Base#{name => authz_rpc_mgmt, tls => Tls,
                      auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1}),
            %% Agent-shaped listener: one-way TLS, NO auth_fun.
            {AgentPort, AgentSrv} = yuzu_gw_test_listener:start(
                Base#{name => authz_rpc_agent,
                      tls => Tls#{verify => verify_none, fail_if_no_peer_cert => false}}),
            ChanSrv = yuzu_grpc_wire_tests:client_chan(chan_srv, MgmtPort, Certs, "srv"),
            ChanAgent = yuzu_grpc_wire_tests:client_chan(chan_agent, MgmtPort, Certs, "agent"),
            ChanGw = yuzu_grpc_wire_tests:client_chan(chan_gw, MgmtPort, Certs, "gw"),
            ChanAgentless = yuzu_grpc_wire_tests:client_chan(chan_agentless, AgentPort, Certs, undefined),
            #{certs => Certs,
              mgmt_port => MgmtPort, agent_port => AgentPort,
              servers => [MgmtSrv, AgentSrv],
              chan_srv => ChanSrv, chan_agent => ChanAgent,
              chan_gw => ChanGw, chan_agentless => ChanAgentless}
    end.

cleanup({error, _}) ->
    ok;
cleanup(#{certs := Certs, servers := Servers} = State) ->
    [yuzu_gw_test_listener:stop_channel(maps:get(K, State))
     || K <- [chan_srv, chan_agent, chan_gw, chan_agentless]],
    [yuzu_gw_test_listener:stop(P) || P <- Servers],
    application:unset_env(yuzu_gw, mgmt_peer_pins),
    yuzu_gw_authz_tests:cleanup_certs(Certs),
    ok.
