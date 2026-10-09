%%%-------------------------------------------------------------------
%%% @doc The one place a test starts a real gRPC listener and a client channel
%%% to it. Replaces the copies of start_listener/probe_free_port that lived in
%%% each RPC test module.
%%%
%%% Listener ports are OS-assigned-then-probed with a retry on the probe->bind
%%% race: two runner agents share each CI box, so a fixed port collides across
%%% jobs. The client is grpcbox_client (a chatterbox HTTP/2 client), which is
%%% also a second, independent implementation to interoperate with.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_test_listener).

-export([probe_free_port/0, start/1, stop/1]).
-export([client_channel/2, stop_channel/1]).

-spec probe_free_port() -> inet:port_number().
probe_free_port() ->
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(L),
    ok = gen_tcp:close(L),
    Port.

%% @doc Start the listener of one `grpc_listeners' entry on a probed free
%% loopback port. A `name' is made up when the entry has none.
-spec start(yuzu_grpc_listener:entry()) -> {inet:port_number(), pid()}.
start(Entry) ->
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    {ok, _} = application:ensure_all_started(grpcbox),
    start(Entry, 5).

start(_Entry, 0) ->
    error(no_free_port);
start(Entry0, Retries) ->
    Port = probe_free_port(),
    Listen = maps:merge(#{ip => {127, 0, 0, 1}}, maps:get(listen, Entry0, #{})),
    Entry = Entry0#{name => maps:get(name, Entry0, erlang:unique_integer([positive])),
                    listen => Listen#{port => Port}},
    case yuzu_grpc_listener:start(Entry) of
        {ok, Pid} -> {Port, Pid};
        {error, _} -> start(Entry0, Retries - 1)
    end.

-spec stop(pid()) -> ok.
stop(Pid) ->
    yuzu_grpc_listener:stop(Pid).

%% @doc A client channel (one HTTP/2 connection) to a listener port. Opts:
%% `scheme' (http | https, default http) and `ssl' (client TLS options for
%% https). sync_start registers the endpoint before this returns: without it the
%% next RPC races the channel's connect and sees {error, no_endpoints}.
-spec client_channel(atom(), #{port := inet:port_number(), scheme => http | https,
                               ssl => [ssl:tls_client_option()]}) -> atom().
client_channel(Name, #{port := Port} = Opts) ->
    Endpoint = {maps:get(scheme, Opts, http), "localhost", Port, maps:get(ssl, Opts, [])},
    {ok, _} = grpcbox_channel_sup:start_child(Name, [Endpoint], #{sync_start => true}),
    Name.

-spec stop_channel(atom()) -> ok.
stop_channel(Name) ->
    _ = (catch grpcbox_channel:stop(Name)),
    ok.
