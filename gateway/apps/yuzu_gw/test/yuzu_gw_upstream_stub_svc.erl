%%%-------------------------------------------------------------------
%%% @doc Minimal GatewayUpstream stub for
%%% yuzu_gw_inventory_capability_gate_wire_tests: ProxyRegister answers
%%% accepted with the server_capabilities the test set, ProxyInventory records
%%% the plugin_data keys it received. State lives in a public named ETS table
%%% the test creates (init/0). Not a test module: no eunit.hrl, no *_test.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_stub_svc).

-export([proxy_register/2, proxy_inventory/2]).
-export([init/0, set_capabilities/1, received_keys/0]).

-define(TAB, yuzu_gw_upstream_stub_tab).

init() ->
    catch ets:delete(?TAB),
    ets:new(?TAB, [named_table, public, set]),
    ets:insert(?TAB, [{caps, []}, {received, []}]),
    ok.

set_capabilities(Caps) ->
    ets:insert(?TAB, {caps, Caps}),
    ok.

%% The plugin_data keys of every ProxyInventory received, oldest first.
received_keys() ->
    [{received, L}] = ets:lookup(?TAB, received),
    L.

proxy_register(Ctx, _Request) ->
    [{caps, Caps}] = ets:lookup(?TAB, caps),
    {ok, #{session_id => <<"stub-session">>, accepted => true,
           server_capabilities => Caps}, Ctx}.

proxy_inventory(Ctx, Report) ->
    Keys = lists:sort(maps:keys(maps:get(plugin_data, Report, #{}))),
    [{received, L}] = ets:lookup(?TAB, received),
    ets:insert(?TAB, {received, L ++ [Keys]}),
    {ok, #{received => true}, Ctx}.
