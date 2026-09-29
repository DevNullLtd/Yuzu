%%%-------------------------------------------------------------------
%%% @doc RPC-level tests for the mgmt-plane SPKI peer pin (#1422).
%%%
%%% Starts a REAL grpcbox TLS listener shaped like the :50063 mgmt
%%% listener (strict mTLS + auth_fun => yuzu_gw_authz:check_mgmt_peer/1)
%%% plus a second listener shaped like the :50051 agent listener
%%% (verify_none, no auth_fun), then drives them with real grpcbox client
%%% channels holding different leaf certs. Proves, at gRPC-status level
%%% (NOT just a TLS handshake):
%%%   - the pinned server leaf is admitted (unary + streaming);
%%%   - a CA-issued agent leaf gets UNAUTHENTICATED (status 16) and the
%%%     service callback is NEVER invoked;
%%%   - the gateway's own (group-readable) leaf likewise gets 16;
%%%   - a certless peer cannot reach the mgmt plane at all
%%%     (fail_if_no_peer_cert);
%%%   - a certless peer still completes RPCs against the agent-listener
%%%     posture — the auth_fun must never leak onto :50051.
%%%
%%% Listener ports are OS-assigned-then-probed with retry (two runner
%%% agents share each CI box; fixed ports collide across jobs).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_authz_rpc_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

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
            _ ->
                %% openssl unavailable — same skip posture as the sibling
                %% suites that mint real certs.
                []
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
    {ok, S} = grpcbox_client:stream(ctx:new(), ?SEND_PATH, send_command_def(),
                                    #{channel => Chan}),
    ok = grpcbox_client:send(S, #{agent_ids => [], timeout_seconds => 1}),
    ok = grpcbox_client:close_send(S),
    ?assertMatch({error, {<<"16">>, _}}, stream_result(S)),
    ?assertEqual(0, yuzu_gw_authz_stub_svc:invocations()).

stream_ok(#{chan_srv := Chan}) ->
    yuzu_gw_authz_stub_svc:init_counters(),
    {ok, S} = grpcbox_client:stream(ctx:new(), ?SEND_PATH, send_command_def(),
                                    #{channel => Chan}),
    ok = grpcbox_client:send(S, #{agent_ids => [], timeout_seconds => 1}),
    ok = grpcbox_client:close_send(S),
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
%%% grpcbox plumbing
%%%-------------------------------------------------------------------

list_agents(Chan) ->
    Def = #grpcbox_def{service = ?SVC,
                       marshal_fun = fun(M) ->
                           management_pb:encode_msg(M, 'yuzu.server.v1.ListAgentsRequest')
                       end,
                       unmarshal_fun = fun(B) ->
                           management_pb:decode_msg(B, 'yuzu.server.v1.ListAgentsResponse')
                       end},
    grpcbox_client:unary(ctx:new(), ?LIST_PATH, #{limit => 10}, Def,
                         #{channel => Chan}).

send_command_def() ->
    #grpcbox_def{service = ?SVC,
                 marshal_fun = fun(M) ->
                     management_pb:encode_msg(M, 'yuzu.server.v1.SendCommandRequest')
                 end,
                 unmarshal_fun = fun(B) ->
                     management_pb:decode_msg(B, 'yuzu.server.v1.SendCommandResponse')
                 end}.

%% Drain a client stream to its terminating trailers.
stream_result(S) ->
    case grpcbox_client:recv_trailers(S, 5000) of
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
            {ok, _} = application:ensure_all_started(grpcbox),
            {ok, _} = application:ensure_all_started(telemetry),
            yuzu_gw_authz_stub_svc:init_counters(),
            application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
            GwPem = filename:join(Dir, "gw.pem"),
            GwKey = filename:join(Dir, "gw.key"),
            %% Mgmt-shaped listener: strict mTLS + the pin auth_fun.
            {MgmtPort, MgmtSrv} = start_listener(
                #{ssl => true, certfile => GwPem, keyfile => GwKey,
                  cacertfile => Ca},
                #{auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1}),
            %% Agent-shaped listener: one-way TLS, NO auth_fun.
            {AgentPort, AgentSrv} = start_listener(
                #{ssl => true, certfile => GwPem, keyfile => GwKey,
                  cacertfile => Ca, verify => verify_none,
                  fail_if_no_peer_cert => false},
                #{}),
            ChanSrv = start_chan(chan_srv, MgmtPort, Ca, Dir, "srv"),
            ChanAgent = start_chan(chan_agent, MgmtPort, Ca, Dir, "agent"),
            ChanGw = start_chan(chan_gw, MgmtPort, Ca, Dir, "gw"),
            ChanAgentless = start_chan(chan_agentless, AgentPort, Ca, undefined, undefined),
            #{certs => Certs,
              mgmt_port => MgmtPort, agent_port => AgentPort,
              servers => [MgmtSrv, AgentSrv],
              chan_srv => ChanSrv, chan_agent => ChanAgent,
              chan_gw => ChanGw, chan_agentless => ChanAgentless}
    end.

cleanup({error, _}) ->
    ok;
cleanup(#{certs := Certs, servers := Servers} = State) ->
    [catch grpcbox_channel:stop(C) || C <- [maps:get(chan_srv, State),
                                            maps:get(chan_agent, State),
                                            maps:get(chan_gw, State),
                                            maps:get(chan_agentless, State)]],
    [catch supervisor:terminate_child(grpcbox_services_simple_sup, P)
     || P <- Servers],
    application:unset_env(yuzu_gw, mgmt_peer_pins),
    yuzu_gw_authz_tests:cleanup_certs(Certs),
    ok.

%% Start a grpcbox listener on an OS-probed free port; retry on the
%% probe→bind race (shared CI boxes run multiple jobs).
start_listener(TransportOpts, ExtraGrpcOpts) ->
    start_listener(TransportOpts, ExtraGrpcOpts, 5).

start_listener(_TransportOpts, _ExtraGrpcOpts, 0) ->
    error(no_free_port);
start_listener(TransportOpts, ExtraGrpcOpts, Retries) ->
    Port = probe_free_port(),
    GrpcOpts = maps:merge(
        #{service_protos => [management_pb],
          services => #{?SVC => yuzu_gw_authz_stub_svc}},
        ExtraGrpcOpts),
    case grpcbox:start_server(#{grpc_opts => GrpcOpts,
                                listen_opts => #{port => Port, ip => {127, 0, 0, 1}},
                                transport_opts => TransportOpts}) of
        {ok, Pid} -> {Port, Pid};
        {error, _} -> start_listener(TransportOpts, ExtraGrpcOpts, Retries - 1)
    end.

probe_free_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    ok = gen_tcp:close(L),
    Port.

%% Client channel; Leaf =:= undefined means no client cert (certless).
start_chan(Name, Port, Ca, Dir, Leaf) ->
    Base = [{cacertfile, Ca}, {verify, verify_peer},
            {versions, ['tlsv1.2']},
            {server_name_indication, "localhost"}],
    SslOpts = case Leaf of
        undefined -> Base;
        _ -> Base ++ [{certfile, filename:join(Dir, Leaf ++ ".pem")},
                      {keyfile, filename:join(Dir, Leaf ++ ".key")}]
    end,
    %% sync_start: register the endpoint in gproc_pool before start_child
    %% returns. Without it, init/1 replies while still `idle` and queues
    %% the internal `connect` event that calls start_workers/4 -- the very
    %% next RPC in this suite can race that event and see {error,
    %% no_endpoints} from grpcbox_channel:pick/2 (CI flake, shared runner
    %% box widens the window). This is a genuine cross-process race, not
    %% just an in-order queue: pick/2 reads gproc_pool directly, bypassing
    %% the channel gen_statem entirely.
    {ok, _} = grpcbox_channel_sup:start_child(
                Name, [{https, "localhost", Port, SslOpts}], #{sync_start => true}),
    Name.
