%%%-------------------------------------------------------------------
%%% @doc The per-upstream capability gate over the real client stack: a real
%%% grpcbox GatewayUpstream server (yuzu_gw_upstream_stub_svc) on loopback, a
%%% real default_channel, the real yuzu_gw_upstream with the interceptor it
%%% installs at init. Nothing on the call path is mocked, so this pins the
%%% grpcbox and chatterbox behaviour the gate relies on (the unary interceptor
%%% row, grpcbox_subchannel:conn/2 and h2_stream_set:connection/1), which
%%% yuzu_gw_inventory_capability_gate_tests mocks.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_inventory_capability_gate_wire_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.gateway.v1.GatewayUpstream').
-define(CH, default_channel).
-define(CERT, <<"certificate_inventory">>).
-define(CAP, <<"certificate_inventory_v1">>).

wire_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(_) ->
             [{timeout, 30, {"the gate follows the real connection's latest ProxyRegister answer",
                             fun gate_over_real_stack/0}}]
     end}.

setup() ->
    {ok, _} = application:ensure_all_started(grpcbox),
    catch meck:unload(grpcbox_client),
    catch meck:unload(grpcbox_subchannel),
    catch meck:unload(h2_stream_set),
    yuzu_gw_test_upstream:stop_upstream(),
    yuzu_gw_upstream_stub_svc:init(),
    {Port, Server} = start_listener(5),
    catch grpcbox_channel:stop(?CH, normal),
    {ok, _} = start_channel({http, "127.0.0.1", Port, []}, 100),
    Up = yuzu_gw_test_upstream:start_upstream(),
    #{server => Server, up => Up}.

cleanup(#{server := Server}) ->
    yuzu_gw_test_upstream:stop_upstream(),
    catch grpcbox_channel:stop(?CH, normal),
    catch supervisor:terminate_child(grpcbox_services_simple_sup, Server),
    ok.

gate_over_real_stack() ->
    Report = #{session_id => <<"s">>,
               plugin_data => #{?CERT => <<"c">>, <<"installed_software">> => <<"i">>},
               content_hashes => #{?CERT => <<"h">>}},
    %% No answer recorded for the connection yet: stripped.
    {ok, _} = yuzu_gw_upstream:proxy_inventory(Report),
    %% An answer without the capability: still stripped.
    {ok, #{server_capabilities := []}} =
        yuzu_gw_upstream:proxy_register(#{agent_id => <<"wire-agent">>}),
    {ok, _} = yuzu_gw_upstream:proxy_inventory(Report),
    %% The same server now lists it: forwarded.
    ok = yuzu_gw_upstream_stub_svc:set_capabilities([?CAP]),
    {ok, #{server_capabilities := [?CAP]}} =
        yuzu_gw_upstream:proxy_register(#{agent_id => <<"wire-agent">>}),
    {ok, _} = yuzu_gw_upstream:proxy_inventory(Report),
    %% And a later answer without it takes it away again.
    ok = yuzu_gw_upstream_stub_svc:set_capabilities([]),
    {ok, _} = yuzu_gw_upstream:proxy_register(#{agent_id => <<"wire-agent">>}),
    {ok, _} = yuzu_gw_upstream:proxy_inventory(Report),
    ?assertEqual([[<<"installed_software">>],
                  [<<"installed_software">>],
                  [?CERT, <<"installed_software">>],
                  [<<"installed_software">>]],
                 yuzu_gw_upstream_stub_svc:received_keys()).

start_listener(0) ->
    error(no_free_port);
start_listener(Retries) ->
    Port = probe_free_port(),
    GrpcOpts = #{service_protos => [gateway_pb],
                 services => #{?SVC => yuzu_gw_upstream_stub_svc}},
    case grpcbox:start_server(#{grpc_opts => GrpcOpts,
                                listen_opts => #{port => Port, ip => {127, 0, 0, 1}},
                                transport_opts => #{}}) of
        {ok, Pid}  -> {Port, Pid};
        {error, _} -> start_listener(Retries - 1)
    end.

probe_free_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    ok = gen_tcp:close(L),
    Port.

%% A stopped channel's registered name is released when gproc sees the DOWN.
start_channel(Endpoint, Attempts) ->
    case grpcbox_channel_sup:start_child(?CH, [Endpoint], #{sync_start => true}) of
        {error, {already_started, _}} when Attempts > 1 ->
            timer:sleep(10),
            start_channel(Endpoint, Attempts - 1);
        Other ->
            Other
    end.
