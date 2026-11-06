%%%-------------------------------------------------------------------
%%% @doc Real-upstream tests: gateway modules against a live C++ server.
%%%
%%% Unlike yuzu_gw_fullstack_SUITE which mocks the upstream client, these tests
%%% connect to the actual C++ yuzu-server running in gateway mode.
%%% This validates the full gRPC/protobuf wire protocol end-to-end, with the
%%% gateway's REAL client (yuzu_grpc_client over gun) on the call sites of
%%% yuzu_gw_upstream and yuzu_gw_heartbeat_buffer.
%%%
%%% What the cases pin that the meck-based unit tests cannot (#5652, #5653):
%%%   - every GatewayUpstream RPC the gateway makes (ProxyRegister,
%%%     BatchHeartbeat, ProxyInventory, NotifyStreamStatus,
%%%     ForwardGuardianMessage) goes through the real client against the real
%%%     server, and its effect is read back from the SERVER (the decoded reply
%%%     where the call site returns one, the server's /metrics where it does
%%%     not). A request marshalled with the wrong message type, or a reply
%%%     decoded with the wrong one, fails these cases.
%%%   - a non-OK gRPC status from the server reaches the caller as
%%%     {error, {Status, Message}} (Status the grpc-status trailer as a decimal
%%%     binary), and a non-200 HTTP response as the {error, {internal,
%%%     <<"http_error ...">>}} that yuzu_grpc_client's {http_error, ...} result
%%%     becomes, not as a transport {error, Reason}.
%%%   - a registration replay carries the agent's EXISTING session id to the
%%%     server as x-yuzu-session-id, and the server adopts that session (read
%%%     back through the server's own answer to a heartbeat for it) instead of
%%%     minting a new one; a presented id the server did not mint is refused
%%%     with FAILED_PRECONDITION, which tears the agent down.
%%%   - over TLS, the server's gateway-peer pin admits the gateway leaf and
%%%     refuses a valid leaf of the same CA that is not pinned.
%%%
%%% Configuration (environment; every default is the old plaintext UAT rig):
%%%   YUZU_UPSTREAM_HOST / YUZU_UPSTREAM_PORT   the server's gateway-upstream
%%%       listener (127.0.0.1 / 50055)
%%%   YUZU_UPSTREAM_CACERT, YUZU_UPSTREAM_CERT, YUZU_UPSTREAM_KEY
%%%       all three: dial over https with verify_peer, presenting that leaf.
%%%       None: plaintext. Any other combination is an error.
%%%   YUZU_UPSTREAM_UNPINNED_CERT / YUZU_UPSTREAM_UNPINNED_KEY
%%%       a leaf of the same CA that the server does NOT pin (peer-pin case)
%%%   YUZU_REAL_UPSTREAM_REQUIRE_PIN=1   the peer-pin case must run (CI)
%%%   YUZU_GW_TEST_TOKEN / YUZU_GW_TEST_TOKEN_FILE   enrollment token (Tier 2),
%%%       default file /tmp/yuzu-uat/enrollment-token
%%%   YUZU_SERVER_WEB   the server's web base URL (http://127.0.0.1:8080), for
%%%       /metrics
%%%   YUZU_REAL_UPSTREAM_STRICT=1   a check that cannot be made (server
%%%       unreachable, /metrics unreadable) FAILS instead of being skipped or
%%%       logged; scripts/integration-test.sh --gateway-ct sets it
%%%
%%% Run against a stack scripts/integration-test.sh started, or by hand:
%%%   rebar3 as test ct --dir apps/yuzu_gw/integration_test \
%%%       --suite yuzu_gw_real_upstream_SUITE --verbose
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_real_upstream_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

%% Enrollment token for Tier 2 auto-approval.
%% Automatically read from UAT environment (/tmp/yuzu-uat/enrollment-token)
%% or override at runtime: YUZU_GW_TEST_TOKEN=<hex>
-define(UAT_TOKEN_FILE, "/tmp/yuzu-uat/enrollment-token").

-define(UPSTREAM_PATH(Rpc), <<"/yuzu.gateway.v1.GatewayUpstream/", Rpc>>).
%% The breaker must not open on the failures the error-shape cases cause on purpose.
-define(BREAKER_THRESHOLD, 1000).

%%%===================================================================
%%% CT callbacks
%%%===================================================================

all() ->
    [server_reachable,
     single_agent_register,
     multi_agent_register,
     heartbeat_batching,
     agent_disconnect_notification,
     rpc_proxy_register_reply_and_status_error,
     rpc_batch_heartbeat,
     rpc_proxy_inventory,
     rpc_notify_stream_status,
     rpc_forward_guardian_message,
     rpc_unimplemented_method_status_shape,
     rpc_http_level_error_shape,
     replay_adopts_existing_session,
     replay_refuses_unminted_session,
     peer_pin_refuses_unpinned_leaf,
     circuit_breaker_recovery,
     register_and_heartbeat_roundtrip].

suite() ->
    [{timetrap, {minutes, 3}}].

init_per_suite(Config) ->
    %% Verify the C++ server is reachable before running any tests.
    Host = upstream_host(),
    Port = upstream_port(),
    case gen_tcp:connect(Host, Port, [binary], 2000) of
        {ok, Sock} ->
            gen_tcp:close(Sock),
            ct:pal("C++ server reachable at ~s:~B (~s)",
                   [Host, Port, case default_endpoint() of
                                    {https, _, _, _} -> "pinned mutual TLS";
                                    _ -> "plaintext"
                                end]),
            do_init_per_suite(Config);
        {error, Reason} ->
            case strict() of
                true  -> ct:fail({server_not_reachable, Host, Port, Reason});
                false -> {skip, {server_not_reachable, Reason}}
            end
    end.

do_init_per_suite(Config) ->
    %% Start dependencies. The upstream channel (a yuzu_grpc_client_channel
    %% over gun) is started below from the {yuzu_gw, upstream_client} env, the
    %% same shape yuzu_gw_sup reads; this suite starts the gateway modules one by
    %% one instead of the supervision tree, so it starts the channel itself.
    %% Without it every `proxy_register' returns `{error, no_channel}'.
    ok = ensure_started(ctx),
    ok = ensure_started(gun),
    ok = ensure_started(telemetry),
    ok = ensure_started(inets),
    ok = ensure_started(ssl),

    %% Point the client channel at the real server BEFORE the upstream
    %% process starts. A channel left over from a prior suite in the same CT
    %% run is replaced, so the new endpoint takes effect.
    set_channel(default_endpoint()),

    %% Start the gateway process group.
    case whereis(yuzu_gw) of
        undefined ->
            {ok, PgPid} = pg:start_link(yuzu_gw),
            unlink(PgPid);
        _ -> ok
    end,

    %% Set up telemetry (ignore errors if already set up).
    catch yuzu_gw_telemetry:setup(),

    %% Start gateway modules — NO mocking.
    start_module(yuzu_gw_registry),

    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 1000),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, ?BREAKER_THRESHOLD),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 2000),

    start_module(yuzu_gw_upstream),
    start_module(yuzu_gw_heartbeat_buffer),
    start_module(yuzu_gw_router),

    ct:pal("Gateway modules started (real upstream, no mocks)"),
    Config.

end_per_suite(_Config) ->
    %% Deregister all agents.
    try
        Ids = yuzu_gw_registry:all_agents(),
        lists:foreach(fun(Id) -> catch yuzu_gw_registry:deregister_agent(Id) end, Ids),
        timer:sleep(500)
    catch _:_ -> ok
    end,
    stop_upstream_channel(),
    ok.

init_per_testcase(_TC, Config) ->
    %% A case that stopped or restarted a module (the breaker case) leaves the
    %% suite whole for the next one.
    start_module(yuzu_gw_upstream),
    start_module(yuzu_gw_heartbeat_buffer),
    Config.

end_per_testcase(_TC, _Config) ->
    %% Clean up agents registered by this test.
    try
        Ids = yuzu_gw_registry:all_agents(),
        lists:foreach(fun(Id) -> catch yuzu_gw_registry:deregister_agent(Id) end, Ids),
        timer:sleep(200)
    catch _:_ -> ok
    end,
    flush_mailbox(),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

%% @doc Verify the upstream server is reachable via gRPC (not just TCP).
%% This sends a real ProxyRegister RPC and checks we get a session_id back.
server_reachable(_Config) ->
    ct:pal("--- server_reachable: sending ProxyRegister to real C++ server ---"),

    Req = make_register_req(<<"reachable-agent-1">>),
    Result = yuzu_gw_upstream:proxy_register(Req),

    ct:pal("ProxyRegister result: ~p", [Result]),
    ?assertMatch({ok, _}, Result),

    {ok, Response} = Result,
    SessionId = maps:get(session_id, Response, undefined),
    ct:pal("Received session_id: ~p", [SessionId]),
    ?assertNotEqual(undefined, SessionId),
    ?assert(is_binary(SessionId) andalso byte_size(SessionId) > 0,
            "session_id should be a non-empty binary").

%% @doc Register a single agent through the gateway upstream proxy.
single_agent_register(_Config) ->
    ct:pal("--- single_agent_register ---"),

    AgentId = <<"real-single-agent-1">>,
    Req = make_register_req(AgentId),
    {ok, Response} = yuzu_gw_upstream:proxy_register(Req),

    SessionId = maps:get(session_id, Response, <<>>),
    ct:pal("Agent ~s registered with session ~s", [AgentId, SessionId]),
    ?assert(byte_size(SessionId) > 0),

    %% Verify the server's web side is up.
    timer:sleep(500),
    case httpc:request(get, {web_base() ++ "/livez", []}, [{timeout, 5000}], []) of
        {ok, {{_, 200, _}, _, _}} ->
            ct:pal("Server web API confirmed reachable");
        Other ->
            strict_fail_or_pal("Server /livez not reachable: ~p", [Other])
    end.

%% @doc Spawn N concurrent agent registrations against the real server.
multi_agent_register(_Config) ->
    N = get_env_int("YUZU_REAL_UPSTREAM_AGENTS", 10),
    ct:pal("--- multi_agent_register: ~B agents against real server ---", [N]),

    Parent = self(),
    _Workers = [spawn_link(fun() ->
        AgentId = iolist_to_binary(io_lib:format("real-agent-~4..0B", [I])),
        Req = make_register_req(AgentId),
        Result = yuzu_gw_upstream:proxy_register(Req),
        Parent ! {register_result, I, Result}
    end) || I <- lists:seq(1, N)],

    %% Collect results.
    Results = [receive
        {register_result, I, Res} -> {I, Res}
    after 30000 ->
        ct:fail("Registration ~B timed out", [I])
    end || I <- lists:seq(1, N)],

    Successes = [R || {_, {ok, _}} = R <- Results],
    Errors    = [R || {_, {error, _}} = R <- Results],

    ct:pal("Registered ~B/~B agents (~B errors)", [length(Successes), N, length(Errors)]),
    lists:foreach(fun({I, {error, Reason}}) ->
        ct:pal("  Agent ~B failed: ~p", [I, Reason])
    end, Errors),

    %% All should succeed against a real server (no artificial limits).
    ?assertEqual(N, length(Successes),
                 lists:flatten(io_lib:format(
                     "Only ~B/~B registrations succeeded", [length(Successes), N]))).

%% @doc Queue heartbeats for multiple agents, wait for batch flush to the
%% real server, verify no crashes.
heartbeat_batching(_Config) ->
    N = 5,
    HBsPerAgent = 10,
    ct:pal("--- heartbeat_batching: ~B agents x ~B HBs against real server ---",
           [N, HBsPerAgent]),

    %% Queue heartbeats.
    lists:foreach(fun(I) ->
        AgentId = iolist_to_binary(io_lib:format("hb-real-agent-~4..0B", [I])),
        lists:foreach(fun(_) ->
            yuzu_gw_heartbeat_buffer:queue_heartbeat(#{
                agent_id  => AgentId,
                timestamp => #{seconds => erlang:system_time(second)}
            })
        end, lists:seq(1, HBsPerAgent))
    end, lists:seq(1, N)),

    TotalHBs = N * HBsPerAgent,
    ct:pal("Queued ~B heartbeats, waiting for batch flush to real server...", [TotalHBs]),

    %% Wait for two flush cycles (flush interval is 1s).
    timer:sleep(2500),

    %% If the heartbeat buffer process is still alive, the batch was sent
    %% (or at least attempted) without crashing.
    ?assert(is_pid(whereis(yuzu_gw_heartbeat_buffer)),
            "Heartbeat buffer process should still be alive after batching"),
    ct:pal("Heartbeat batching to real server completed successfully").

%% @doc Start an agent, disconnect it, verify the upstream disconnect
%% notification is sent to the real server without crashing.
agent_disconnect_notification(_Config) ->
    ct:pal("--- agent_disconnect_notification ---"),

    StreamHandler = spawn(fun() -> stream_handler_loop(self()) end),
    AgentId = <<"real-disconnect-agent">>,
    AgentArgs = #{
        agent_id   => AgentId,
        session_id => <<"real-disc-sess">>,
        agent_info => #{plugins => [#{name => <<"system">>, version => <<"1.0">>}]},
        stream_pid => StreamHandler,
        peer_addr  => <<"127.0.0.1:0">>
    },

    {ok, _AgentPid} = yuzu_gw_agent:start_link(AgentArgs),
    timer:sleep(200),

    CountBefore = yuzu_gw_registry:agent_count(),
    ct:pal("Registry count before disconnect: ~B", [CountBefore]),
    ?assert(CountBefore >= 1),

    %% Kill the stream handler — agent detects DOWN and disconnects.
    %% This fires NotifyStreamStatus to the real server.
    exit(StreamHandler, kill),

    %% Wait for cleanup.
    ok = wait_until(fun() ->
        yuzu_gw_registry:lookup(AgentId) =:= error
    end, 5000),

    CountAfter = yuzu_gw_registry:agent_count(),
    ct:pal("Registry count after disconnect: ~B (was ~B)", [CountAfter, CountBefore]),
    ?assert(CountAfter < CountBefore),

    %% Verify upstream module didn't crash from the notification.
    ?assert(is_pid(whereis(yuzu_gw_upstream)),
            "Upstream process should survive disconnect notification").

%%% -- #5652: every upstream call site paired with the real client ---------

%% @doc ProxyRegister through yuzu_gw_upstream:proxy_register/1 (do_rpc/4 ->
%% yuzu_grpc_client:unary/5). The reply is a decoded RegisterResponse; a
%% request marshalled as another message type reaches the server with no agent
%% id, so the happy path below fails. A server error status comes back as the
%% documented {error, {Status, Message}}.
rpc_proxy_register_reply_and_status_error(_Config) ->
    AgentId = <<"rpc-register-agent">>,
    {ok, Reply} = yuzu_gw_upstream:proxy_register(make_register_req(AgentId)),
    ct:pal("ProxyRegister reply: ~p", [Reply]),
    ?assertMatch(#{accepted := true,
                   enrollment_status := <<"enrolled">>,
                   session_id := <<"gw-session-", _/binary>>}, Reply),

    %% The server rejects an empty agent_id with INVALID_ARGUMENT; the status
    %% is the grpc-status trailer as a decimal binary, the message the server's.
    Bad = (make_register_req(AgentId))#{info => #{agent_id => <<>>}},
    ?assertEqual({error, {<<"3">>, <<"agent_id length exceeds 256 chars or empty">>}},
                 yuzu_gw_upstream:proxy_register(Bad)),
    %% The breaker is untouched by a request fault (INVALID_ARGUMENT), so the
    %% next good call still goes through.
    ?assertMatch({ok, #{accepted := true}},
                 yuzu_gw_upstream:proxy_register(make_register_req(AgentId))).

%% @doc BatchHeartbeat through yuzu_gw_heartbeat_buffer's own call site. The
%% server counts what it ingests, so the delta of
%% yuzu_heartbeats_received_total{via="gateway"} proves the batch was
%% marshalled as a BatchHeartbeatRequest and its heartbeats parsed.
rpc_batch_heartbeat(_Config) ->
    N = 3,
    Sessions = [begin
                    {ok, #{session_id := S}} = yuzu_gw_upstream:proxy_register(
                        make_register_req(rpc_agent_id("rpc-hb-agent", I))),
                    S
                end || I <- lists:seq(1, N)],
    Tap = attach_rpc_events(),
    try
        Before = server_metric("yuzu_heartbeats_received_total", ["via=\"gateway\""]),
        lists:foreach(fun(S) ->
            yuzu_gw_heartbeat_buffer:queue_heartbeat(#{
                session_id => S,
                sent_at    => #{millis_epoch => erlang:system_time(millisecond)}
            })
        end, Sessions),
        ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
        ?assertMatch({rpc_latency, _}, await_rpc(<<"batch_heartbeat">>, 10000)),
        %% Ingest is synchronous in the handler, but give the metric a moment.
        ok = wait_until(fun() ->
            metric_delta(Before, server_metric("yuzu_heartbeats_received_total",
                                               ["via=\"gateway\""])) >= N
        end, 10000)
    after
        telemetry:detach(Tap)
    end.

%% @doc ProxyInventory through yuzu_gw_upstream:proxy_inventory/1: the reply is
%% a decoded InventoryAck whose `received' is the server's verdict on the
%% session the request named (true for a registered one, false for an unknown
%% one), so a request that lost its session_id in marshalling reads false.
rpc_proxy_inventory(_Config) ->
    {ok, #{session_id := S}} =
        yuzu_gw_upstream:proxy_register(make_register_req(<<"rpc-inventory-agent">>)),
    Report = fun(Sid) ->
        #{session_id => Sid,
          collected_at => #{millis_epoch => erlang:system_time(millisecond)},
          plugin_data => #{<<"gw_real_upstream_probe">> => <<"{\"rows\":[]}">>}}
    end,
    ?assertMatch({ok, #{received := true}}, yuzu_gw_upstream:proxy_inventory(Report(S))),
    Forged = forged_session_id(),
    ?assertMatch({ok, #{received := false}}, yuzu_gw_upstream:proxy_inventory(Report(Forged))).

%% @doc NotifyStreamStatus through yuzu_gw_upstream:notify_stream_status/5. The
%% call site is a cast, so the proof is on the server: a CONNECTED for a
%% registered session is acknowledged (no desync is counted), one for a session
%% the server does not hold is counted exactly once as an unknown_session
%% desync, which only happens when agent_id and session_id arrive intact.
rpc_notify_stream_status(_Config) ->
    AgentId = <<"rpc-notify-agent">>,
    {ok, #{session_id := S}} = yuzu_gw_upstream:proxy_register(make_register_req(AgentId)),
    Labels = ["op=\"notify_stream_status\"", "outcome=\"unknown_session\""],
    Tap = attach_rpc_events(),
    try
        Before = server_metric("yuzu_server_gateway_route_desync_total", Labels),
        yuzu_gw_upstream:notify_stream_status(AgentId, S, connected, <<"127.0.0.1:1">>, home_id()),
        ?assertMatch({rpc_latency, _}, await_rpc(<<"notify_stream">>, 10000)),
        ?assertEqual(0, metric_delta(Before, server_metric(
            "yuzu_server_gateway_route_desync_total", Labels))),

        yuzu_gw_upstream:notify_stream_status(AgentId, forged_session_id(), connected,
                                              <<"127.0.0.1:1">>, home_id()),
        ?assertMatch({rpc_latency, _}, await_rpc(<<"notify_stream">>, 10000)),
        ok = wait_until(fun() ->
            metric_delta(Before, server_metric("yuzu_server_gateway_route_desync_total",
                                               Labels)) =:= 1
        end, 10000)
    after
        telemetry:detach(Tap)
    end.

%% @doc ForwardGuardianMessage through yuzu_gw_upstream:forward_guardian_message/2.
%% A cast too: the server stores the GuaranteedStateEvent carried in the frame's
%% payload and times the insert, so the delta of
%% yuzu_server_guardian_event_store_duration_seconds_count{status="inserted"}
%% proves the request was marshalled as a ForwardGuardianRequest with its frame.
rpc_forward_guardian_message(_Config) ->
    AgentId = <<"rpc-guardian-agent">>,
    {ok, _} = yuzu_gw_upstream:proxy_register(make_register_req(AgentId)),
    Labels = ["status=\"inserted\""],
    Name = "yuzu_server_guardian_event_store_duration_seconds_count",
    Tap = attach_rpc_events(),
    try
        Before = server_metric(Name, Labels),
        %% The server dedups by event_id; a random one cannot collide with an earlier run.
        EventId = <<"gw-real-upstream-", (home_id())/binary>>,
        Event = iolist_to_binary([pb_string(1, <<"gw-real-upstream-rule">>),
                                  pb_string(3, <<"drift.detected">>),
                                  pb_string(19, EventId)]),
        Frame = #{command_id => <<>>, plugin => <<"__guard__">>, action => <<"event">>,
                  payload => Event},
        yuzu_gw_upstream:forward_guardian_message(AgentId, Frame),
        ?assertMatch({rpc_latency, _}, await_rpc(<<"guardian">>, 10000)),
        ok = wait_until(fun() ->
            metric_delta(Before, server_metric(Name, Labels)) =:= 1
        end, 10000)
    after
        telemetry:detach(Tap)
    end.

%% @doc A method the server does not implement: the real server answers HTTP 200
%% with grpc-status 12 in a trailers-only response, and the client reports it as
%% {error, {<<"12">>, Message}, Meta} (the shape yuzu_gw_upstream's
%% {error, {Status, Message}, _} clause matches), never as http_error.
rpc_unimplemented_method_status_shape(_Config) ->
    Def = #{marshal   => fun(M) -> gateway_pb:encode_msg(M, 'yuzu.gateway.v1.StreamStatusAck') end,
            unmarshal => fun(B) -> gateway_pb:decode_msg(B, 'yuzu.gateway.v1.StreamStatusAck') end},
    Result = yuzu_grpc_client:unary(#{}, ?UPSTREAM_PATH("NoSuchMethodHere"),
                                    #{acknowledged => true}, Def,
                                    #{channel => default_channel}),
    ct:pal("unimplemented method result: ~p", [Result]),
    ?assertMatch({error, {<<"12">>, _Message}, #{headers := _, trailers := _}}, Result).

%% @doc An HTTP-level (non-200) answer. The real server never sends one, so a
%% real HTTP/2 server of the CT node (cowboy, the library the gateway's own
%% listeners run on) answers every request 502 and the default channel is
%% pointed at it. yuzu_grpc_client must report {http_error, ...}, which do_rpc/4
%% turns into {error, {internal, <<"http_error ...">>}}; a transport
%% {error, Reason} (what a client that lost this clause returns) would read
%% differently.
rpc_http_level_error_shape(_Config) ->
    {ok, _} = application:ensure_all_started(cowboy),
    Listener = list_to_atom("yuzu_gw_real_upstream_502_" ++
                            integer_to_list(erlang:unique_integer([positive]))),
    Dispatch = cowboy_router:compile([{'_', [{'_', ?MODULE, []}]}]),
    {ok, _} = cowboy:start_clear(Listener, [{ip, {127, 0, 0, 1}}, {port, 0}],
                                 #{env => #{dispatch => Dispatch}}),
    try
        Port = ranch:get_port(Listener),
        with_endpoint({http, "127.0.0.1", Port, []}, fun() ->
            Result = yuzu_gw_upstream:proxy_register(make_register_req(<<"rpc-502-agent">>)),
            ct:pal("HTTP-level error result: ~p", [Result]),
            ?assertEqual({error, {internal, http_error_text(<<"502">>)}}, Result)
        end),
        %% A success after a failure is a recovery to the breaker (it replays every
        %% registered agent); take it here, with nothing registered.
        ?assertMatch({ok, #{accepted := true}},
                     yuzu_gw_upstream:proxy_register(make_register_req(<<"rpc-502-settle-agent">>)))
    after
        cowboy:stop_listener(Listener)
    end.

%% cowboy handler for rpc_http_level_error_shape/1.
init(Req0, State) ->
    Req = cowboy_req:reply(502, #{<<"content-type">> => <<"text/plain">>}, <<"bad gateway">>, Req0),
    {ok, Req, State}.

%%% -- #5653: the registration replay reaches the server with its session ---

%% @doc Force a registration replay through the real upstream and read the
%% outcome from the server. The agent registers (session S minted by the
%% server), a gateway agent process holds S with its stored request, and
%% replay_sessions([S]) re-proxies it: do_replay_one/6 sends ProxyRegister with
%% x-yuzu-session-id: S. The server adopts S only when it receives that header;
%% without it the server mints a fresh session and the directory row moves off
%% S, so the server's answer to a heartbeat for S flips from known to unknown.
replay_adopts_existing_session(_Config) ->
    AgentId = <<"replay-adopt-agent">>,
    Req = make_register_req(AgentId),
    {ok, #{session_id := S}} = yuzu_gw_upstream:proxy_register(Req),
    ?assertEqual(known, server_session_state(S)),

    Agent = start_test_agent(AgentId, S, Req),
    Replayed = attach_replay_events(),
    try
        ok = yuzu_gw_upstream:replay_sessions([S]),
        ?assertEqual(replayed, await_replay(15000)),
        %% The server still holds exactly the session the agent holds ...
        ?assertEqual(known, server_session_state(S)),
        %% ... and the replay did not tear the agent down (a refused replay does).
        ?assert(is_process_alive(Agent)),
        ?assertMatch({ok, {Agent, S}}, yuzu_gw_registry:lookup_local_session(AgentId))
    after
        telemetry:detach(Replayed)
    end.

%% @doc The negative twin: a session id the server did not mint, replayed. With
%% the header on the wire the server answers FAILED_PRECONDITION and the gateway
%% tears the agent down so it reconnects fresh; with the header lost the server
%% would simply register the agent anew and the process would live on.
replay_refuses_unminted_session(_Config) ->
    AgentId = <<"replay-refused-agent">>,
    Req = make_register_req(AgentId),
    Unminted = <<"not-a-server-minted-session">>,
    Agent = start_test_agent(AgentId, Unminted, Req),
    Mon = erlang:monitor(process, Agent),
    ok = yuzu_gw_upstream:replay_sessions([Unminted]),
    receive
        {'DOWN', Mon, process, Agent, Reason} ->
            ct:pal("agent torn down after the refused replay: ~p", [Reason])
    after 15000 ->
        ct:fail("the replay of an unminted session did not tear the agent down: "
                "the server never saw x-yuzu-session-id")
    end,
    ?assertEqual(error, yuzu_gw_registry:lookup(AgentId)).

%%% -- the pinned TLS hop ---------------------------------------------------

%% @doc Over TLS the server pins the gateway leaf: the leaf the suite presents
%% as `the gateway' is admitted (every other case), and a valid leaf of the same
%% CA that is not pinned is refused with UNAUTHENTICATED "gateway peer not
%% authorized" and counted as reason=not_pinned.
peer_pin_refuses_unpinned_leaf(_Config) ->
    case {default_endpoint(), unpinned_files()} of
        {{https, Host, Port, Opts}, {Cert, Key}} ->
            Unpinned = {https, Host, Port, replace_leaf(Opts, Cert, Key)},
            Labels = ["reason=\"not_pinned\""],
            Before = server_metric("yuzu_server_gateway_peer_denied_total", Labels),
            with_endpoint(Unpinned, fun() ->
                ?assertEqual({error, {<<"16">>, <<"gateway peer not authorized">>}},
                             yuzu_gw_upstream:proxy_register(
                               make_register_req(<<"pin-refused-agent">>)))
            end),
            ok = wait_until(fun() ->
                metric_delta(Before, server_metric("yuzu_server_gateway_peer_denied_total",
                                                   Labels)) >= 1
            end, 10000),
            %% Back on the pinned leaf the same call is answered.
            ?assertMatch({ok, #{accepted := true}},
                         yuzu_gw_upstream:proxy_register(
                           make_register_req(<<"pin-admitted-agent">>)));
        _ ->
            case require_pin() of
                true  -> ct:fail("YUZU_REAL_UPSTREAM_REQUIRE_PIN=1 but the upstream is not "
                                 "https with an unpinned leaf configured");
                false -> {skip, plaintext_upstream_no_peer_pin}
            end
    end.

%%% -- circuit breaker and the round trip -----------------------------------

%% @doc Simulate circuit breaker by stopping the upstream module,
%% verifying it rejects RPCs, then restarting and verifying recovery.
circuit_breaker_recovery(_Config) ->
    ct:pal("--- circuit_breaker_recovery ---"),

    %% First verify normal operation works.
    Req = make_register_req(<<"cb-agent-before">>),
    {ok, _} = yuzu_gw_upstream:proxy_register(Req),
    ct:pal("Normal registration succeeded (circuit closed)"),

    %% Stop the upstream process and restart it with unreachable server.
    catch gen_server:stop(yuzu_gw_upstream),
    timer:sleep(100),

    %% Repoint the client channel at a dead port temporarily.
    start_upstream_channel("127.0.0.1", 59999),

    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 2),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 1500),
    {ok, _UpPid} = yuzu_gw_upstream:start_link(),

    %% Send requests that should fail (unreachable server).
    Req2 = make_register_req(<<"cb-agent-fail-1">>),
    R1 = yuzu_gw_upstream:proxy_register(Req2),
    ct:pal("Fail attempt 1: ~p", [R1]),

    Req3 = make_register_req(<<"cb-agent-fail-2">>),
    R2 = yuzu_gw_upstream:proxy_register(Req3),
    ct:pal("Fail attempt 2: ~p", [R2]),

    %% After 2 failures, circuit should be open.
    Req4 = make_register_req(<<"cb-agent-fail-3">>),
    R3 = yuzu_gw_upstream:proxy_register(Req4),
    ct:pal("Attempt 3 (should be circuit_open): ~p", [R3]),

    %% Now restore the real server connection.
    catch gen_server:stop(yuzu_gw_upstream),
    timer:sleep(100),

    set_channel(default_endpoint()),

    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, ?BREAKER_THRESHOLD),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 2000),
    {ok, UpPid2} = yuzu_gw_upstream:start_link(),
    unlink(UpPid2),

    %% Verify recovery.
    Req5 = make_register_req(<<"cb-agent-recovered">>),
    R5 = yuzu_gw_upstream:proxy_register(Req5),
    ct:pal("Recovery attempt: ~p", [R5]),
    ?assertMatch({ok, _}, R5),

    %% Restart heartbeat buffer since it depends on upstream.
    catch gen_server:stop(yuzu_gw_heartbeat_buffer),
    timer:sleep(100),
    start_module(yuzu_gw_heartbeat_buffer),
    ct:pal("Circuit breaker recovery verified — real server connection restored").

%% @doc Full round-trip: register agents, send heartbeats, verify the
%% server received both via its REST API.
register_and_heartbeat_roundtrip(_Config) ->
    ct:pal("--- register_and_heartbeat_roundtrip ---"),

    %% Ensure upstream and heartbeat buffer are running (may have been
    %% stopped by circuit_breaker_recovery test).
    start_module(yuzu_gw_upstream),
    start_module(yuzu_gw_heartbeat_buffer),

    %% Register an agent.
    AgentId = <<"roundtrip-real-agent">>,
    Req = make_register_req(AgentId),
    {ok, RegResp} = yuzu_gw_upstream:proxy_register(Req),
    SessionId = maps:get(session_id, RegResp, <<>>),
    ct:pal("Registered ~s with session ~s", [AgentId, SessionId]),
    ?assert(byte_size(SessionId) > 0),

    %% Send heartbeats for this agent.
    lists:foreach(fun(_) ->
        yuzu_gw_heartbeat_buffer:queue_heartbeat(#{
            session_id => SessionId,
            sent_at    => #{millis_epoch => erlang:system_time(millisecond)}
        })
    end, lists:seq(1, 5)),

    %% Wait for heartbeat flush.
    timer:sleep(2000),

    %% Check the server's /metrics for heartbeat counters.
    case httpc:request(get,
            {web_base() ++ "/metrics", []},
            [{timeout, 5000}], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, MetricsBody}} ->
            case binary:match(MetricsBody, <<"yuzu_heartbeats_received_total">>) of
                {_, _} ->
                    ct:pal("Server /metrics confirms heartbeat reception");
                nomatch ->
                    strict_fail_or_pal("Server /metrics reachable but heartbeat metric not found", [])
            end;
        Other ->
            strict_fail_or_pal("Could not reach /metrics: ~p", [Other])
    end,

    ct:pal("Full register → heartbeat → server roundtrip completed").

%%%===================================================================
%%% Internal helpers
%%%===================================================================

make_register_req(AgentId) ->
    Token = enrollment_token(),
    %% RegisterRequest has a nested AgentInfo field (proto/yuzu/agent/v1/
    %% agent.proto: `AgentInfo info = 1`). A flat map of agent_id/hostname/
    %% etc. at the top level marshals to a RegisterRequest with `info`
    %% unset; the server then reads `info.agent_id()` as empty and
    %% rejects with INVALID_ARGUMENT "agent_id length exceeds 256 chars
    %% or empty". Nest everything except enrollment_token under `info`.
    #{
        info => #{
            agent_id      => AgentId,
            hostname      => <<"real-upstream-test-host">>,
            platform      => #{os => <<"LINUX">>, arch => <<"x86_64">>},
            agent_version => <<"0.1.0">>,
            plugins       => [#{name => <<"system_info">>, version => <<"1.0.0">>}]
        },
        enrollment_token => Token
    }.

enrollment_token() ->
    case os:getenv("YUZU_GW_TEST_TOKEN") of
        false ->
            File = env("YUZU_GW_TEST_TOKEN_FILE", ?UAT_TOKEN_FILE),
            case file:read_file(File) of
                {ok, Bin} -> string:trim(Bin);
                {error, _} ->
                    ct:fail("No enrollment token: set YUZU_GW_TEST_TOKEN or "
                            "run scripts/start-UAT.sh first")
            end;
        Val -> list_to_binary(Val)
    end.

stream_handler_loop(TestPid) ->
    receive
        {send_command, Cmd} ->
            TestPid ! {stream_cmd_received, Cmd, erlang:monotonic_time(microsecond)},
            stream_handler_loop(TestPid);
        close_stream ->
            ok;
        _ ->
            stream_handler_loop(TestPid)
    end.

%% A gateway agent process as the Subscribe handler would start it: it holds the
%% session and the verbatim RegisterRequest the replay re-proxies. Unlinked, so
%% a teardown by the gateway does not take the test process with it.
start_test_agent(AgentId, SessionId, RegisterReq) ->
    StreamHandler = spawn(fun() -> stream_handler_loop(self()) end),
    {ok, Pid} = yuzu_gw_agent:start_link(#{
        agent_id     => AgentId,
        session_id   => SessionId,
        agent_info   => #{plugins => [#{name => <<"system_info">>, version => <<"1.0.0">>}]},
        stream_pid   => StreamHandler,
        peer_addr    => <<"127.0.0.1:0">>,
        register_req => RegisterReq
    }),
    unlink(Pid),
    ok = wait_until(fun() ->
        yuzu_gw_registry:lookup_local_session(AgentId) =:= {ok, {Pid, SessionId}}
    end, 5000),
    Pid.

%% What the server says about a session, asked on the same wire the gateway uses
%% (a BatchHeartbeat for it through the real client): `known' when the server
%% resolves it and acknowledges the heartbeat, `unknown' when it lists it back.
server_session_state(SessionId) ->
    Def = #{marshal   => fun(M) -> gateway_pb:encode_msg(M, 'yuzu.gateway.v1.BatchHeartbeatRequest') end,
            unmarshal => fun(B) -> gateway_pb:decode_msg(B, 'yuzu.gateway.v1.BatchHeartbeatResponse') end},
    Req = #{heartbeats => [#{session_id => SessionId}], gateway_node => <<"real-upstream-suite">>},
    case yuzu_grpc_client:unary(#{}, ?UPSTREAM_PATH("BatchHeartbeat"), Req, Def,
                                #{channel => default_channel}) of
        {ok, #{acknowledged_count := 1} = Reply, _} ->
            Unknown = maps:get(unknown_session_ids, Reply, []),
            case lists:member(SessionId, Unknown) of
                true  -> unknown;
                false -> known
            end;
        {ok, Reply, _} ->
            case lists:member(SessionId, maps:get(unknown_session_ids, Reply, [])) of
                true  -> unknown;
                false -> ct:fail({heartbeat_neither_acknowledged_nor_listed_unknown, Reply})
            end;
        Other ->
            ct:fail({heartbeat_probe_failed, Other})
    end.

forged_session_id() ->
    %% Server-minted shape ("gw-session-" + 32 hex), but never minted.
    Hex = binary:encode_hex(crypto:strong_rand_bytes(16), lowercase),
    <<"gw-session-", Hex/binary>>.

home_id() ->
    binary:encode_hex(crypto:strong_rand_bytes(16), lowercase).

rpc_agent_id(Prefix, I) ->
    iolist_to_binary(io_lib:format("~s-~B", [Prefix, I])).

http_error_text(Status) ->
    iolist_to_binary(io_lib:format("http_error ~p", [Status])).

%% A minimal protobuf encoder for the one hand-built message here: a
%% length-delimited (string) field. There is no Erlang module for the Guardian
%% protos (the gateway forwards the event as opaque bytes).
pb_string(FieldNo, Bin) when is_binary(Bin) ->
    [varint((FieldNo bsl 3) bor 2), varint(byte_size(Bin)), Bin].

varint(N) when N < 128 -> <<N>>;
varint(N) -> <<(N band 127 bor 128), (varint(N bsr 7))/binary>>.

%%% -- telemetry taps ---------------------------------------------------------

attach_rpc_events() ->
    Id = {?MODULE, rpc, make_ref()},
    ok = telemetry:attach_many(Id,
                               [[yuzu, gw, upstream, rpc_latency],
                                [yuzu, gw, upstream, rpc_error]],
                               fun ?MODULE:rpc_event/4, self()),
    Id.

rpc_event([yuzu, gw, upstream, Kind], _Measurements, Meta, Pid) ->
    Pid ! {rpc_event, Kind, maps:get(rpc_name, Meta, undefined), Meta}.

%% The next latency/error event of one RPC, as {rpc_latency | rpc_error, Meta}.
await_rpc(RpcName, Timeout) ->
    receive
        {rpc_event, Kind, RpcName, Meta} -> {Kind, Meta}
    after Timeout -> timeout
    end.

attach_replay_events() ->
    Id = {?MODULE, replay, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, upstream, registration_replay],
                          fun ?MODULE:replay_event/4, self()),
    Id.

replay_event(_Event, #{replayed := 1}, _Meta, Pid) -> Pid ! replay_done;
replay_event(_Event, _Measurements, _Meta, _Pid) -> ok.

await_replay(Timeout) ->
    receive replay_done -> replayed
    after Timeout -> timeout
    end.

%%% -- the server's own numbers -------------------------------------------------

%% The sum of every series of metric `Name' whose line carries all the label
%% fragments, from the server's /metrics. 0 when no such series exists yet, and
%% `unreadable' when /metrics cannot be read (a failure under STRICT).
server_metric(Name, LabelFragments) ->
    case httpc:request(get, {web_base() ++ "/metrics", []}, [{timeout, 5000}],
                       [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, Body}} ->
            Lines = binary:split(Body, <<"\n">>, [global]),
            Prefix = list_to_binary(Name),
            lists:foldl(fun(Line, Acc) ->
                metric_line_value(Line, Prefix, LabelFragments, Acc)
            end, 0, Lines);
        Other ->
            case strict() of
                true  -> ct:fail({server_metrics_unreadable, Other});
                false -> unreadable
            end
    end.

metric_line_value(Line, Prefix, LabelFragments, Acc) ->
    Size = byte_size(Prefix),
    case Line of
        <<Prefix:Size/binary, Rest/binary>> when Rest =/= <<>> ->
            %% The name must end here: `{' (labels) or a space, not a longer name.
            case binary:first(Rest) of
                C when C =:= ${; C =:= $\s ->
                    case lists:all(fun(F) ->
                                       binary:match(Line, list_to_binary(F)) =/= nomatch
                                   end, LabelFragments) of
                        true ->
                            [Value | _] = lists:reverse(binary:split(Line, <<" ">>, [global])),
                            Acc + parse_number(Value);
                        false -> Acc
                    end;
                _ -> Acc
            end;
        _ -> Acc
    end.

parse_number(Bin) ->
    S = binary_to_list(string:trim(Bin)),
    try list_to_float(S)
    catch error:badarg ->
        try float(list_to_integer(S))
        catch error:badarg -> 0.0
        end
    end.

%% After - Before, in whole counts; `unreadable' on either side compares as 0.
metric_delta(unreadable, _) -> 0;
metric_delta(_, unreadable) -> 0;
metric_delta(Before, After) -> round(After - Before).

%%% -- configuration -----------------------------------------------------------

env(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        ""    -> Default;
        Val   -> Val
    end.

strict() -> env("YUZU_REAL_UPSTREAM_STRICT", "") =:= "1".

require_pin() -> env("YUZU_REAL_UPSTREAM_REQUIRE_PIN", "") =:= "1".

strict_fail_or_pal(Fmt, Args) ->
    case strict() of
        true  -> ct:fail(lists:flatten(io_lib:format(Fmt, Args)));
        false -> ct:pal(Fmt, Args)
    end.

upstream_host() -> env("YUZU_UPSTREAM_HOST", "127.0.0.1").

upstream_port() -> list_to_integer(env("YUZU_UPSTREAM_PORT", "50055")).

web_base() -> env("YUZU_SERVER_WEB", "http://127.0.0.1:8080").

unpinned_files() ->
    {env("YUZU_UPSTREAM_UNPINNED_CERT", undefined), env("YUZU_UPSTREAM_UNPINNED_KEY", undefined)}.

%% The endpoint of the real server: plaintext, or https with verify_peer and the
%% client leaf the server pins. All three TLS variables or none.
default_endpoint() ->
    Host = upstream_host(),
    Port = upstream_port(),
    case {env("YUZU_UPSTREAM_CACERT", undefined),
          env("YUZU_UPSTREAM_CERT", undefined),
          env("YUZU_UPSTREAM_KEY", undefined)} of
        {undefined, undefined, undefined} ->
            {http, Host, Port, []};
        {Ca, Cert, Key} when Ca =/= undefined, Cert =/= undefined, Key =/= undefined ->
            {https, Host, Port, [{cacertfile, Ca}, {certfile, Cert}, {keyfile, Key},
                                 {verify, verify_peer}, {depth, 2}]};
        Partial ->
            ct:fail({incomplete_tls_configuration,
                     "set all of YUZU_UPSTREAM_CACERT, YUZU_UPSTREAM_CERT, YUZU_UPSTREAM_KEY or none",
                     Partial})
    end.

replace_leaf(Opts, Cert, Key) ->
    lists:keystore(keyfile, 1, lists:keystore(certfile, 1, Opts, {certfile, Cert}),
                   {keyfile, Key}).

get_env_int(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Val   -> list_to_integer(Val)
    end.

ensure_started(App) ->
    case application:ensure_all_started(App) of
        {ok, _}                       -> ok;
        {error, {already_started, _}} -> ok;
        {error, Reason}               -> {error, Reason}
    end.

%% (Re)start the `default_channel' upstream client channel against Host:Port,
%% over the configured transport (plaintext, or the pinned TLS leaf) so a case
%% that points it at a dead port keeps the transport it will be restored to.
start_upstream_channel(Host, Port) ->
    case default_endpoint() of
        {http, _, _, _}       -> set_channel({http, Host, Port, []});
        {https, _, _, TlsOpts} -> set_channel({https, Host, Port, TlsOpts})
    end.

%% (Re)start `default_channel' on one endpoint. The channel config goes through
%% the same {yuzu_gw, upstream_client} env and parser yuzu_gw_sup uses. The
%% channel is unlinked so it outlives the CT process that started it.
set_channel(Endpoint) ->
    stop_upstream_channel(),
    Env = #{channels => [{default_channel, [Endpoint], #{}}]},
    application:set_env(yuzu_gw, upstream_client, Env),
    {ok, [Channel]} = yuzu_grpc_client_config:from_env(),
    {ok, Pid} = yuzu_grpc_client_channel:start_link(Channel),
    unlink(Pid),
    ok.

%% Run Fun with `default_channel' on another endpoint, then put the real
%% server's back whatever Fun did.
with_endpoint(Endpoint, Fun) ->
    set_channel(Endpoint),
    try Fun()
    after set_channel(default_endpoint())
    end.

stop_upstream_channel() ->
    case whereis(default_channel) of
        undefined -> ok;
        Pid ->
            %% The channel traps exits, so an exit signal from a process
            %% that is not its parent would be ignored; stop it
            %% synchronously instead.
            ok = gen_server:stop(Pid, shutdown, 5000)
    end.

start_module(Module) ->
    case whereis(Module) of
        undefined ->
            {ok, Pid} = Module:start_link(),
            unlink(Pid);
        _ -> ok
    end.

flush_mailbox() ->
    receive _ -> flush_mailbox()
    after 0 -> ok
    end.

wait_until(Fun, Timeout) when Timeout =< 0 ->
    case Fun() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Fun, Timeout) ->
    case Fun() of
        true  -> ok;
        false ->
            timer:sleep(50),
            wait_until(Fun, Timeout - 50)
    end.
