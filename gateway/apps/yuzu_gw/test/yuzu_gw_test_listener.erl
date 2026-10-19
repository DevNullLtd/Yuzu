%%%-------------------------------------------------------------------
%%% @doc The one place a test starts a real gRPC listener and a client channel
%%% to it. Replaces the copies of start_listener/probe_free_port that lived in
%%% each RPC test module.
%%%
%%% Listener ports are OS-assigned-then-probed with a retry on the probe->bind
%%% race: two runner agents share each CI box, so a fixed port collides across
%%% jobs. The client is the production channel (gun) with yuzu_gw_test_client for
%%% streams; neither shares the HTTP/2 stack of the listener (cowboy).
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
    {ok, _} = application:ensure_all_started(gun),
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

%% @doc A client channel (one HTTP/2 connection) to a listener port, up before
%% this returns: without that the next RPC races the connect. Opts: `scheme'
%% (http | https, default http), `ssl' (client TLS options for https) and
%% `pool_size' (connections, default 1).
-spec client_channel(atom(), #{port := inet:port_number(), scheme => http | https,
                               ssl => [ssl:tls_client_option()], pool_size => pos_integer()}) -> atom().
client_channel(Name, #{port := Port} = Opts) ->
    Endpoint = {maps:get(scheme, Opts, http), "localhost", Port, maps:get(ssl, Opts, [])},
    PoolSize = maps:get(pool_size, Opts, 1),
    {ok, Cfg} = yuzu_grpc_client_config:channel({Name, [Endpoint], #{pool_size => PoolSize}}, true),
    {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
    ok = wait_up(Name, PoolSize, 400),
    Name.

wait_up(Name, _Want, 0) -> error({channel_not_up, Name});
wait_up(Name, Want, N) ->
    case ets:select_count(Name, [{{{slot, '_'}, '_', up}, [], [true]}]) of
        Want -> ok;
        _ -> receive after 25 -> ok end, wait_up(Name, Want, N - 1)
    end.

-spec stop_channel(atom()) -> ok.
stop_channel(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> unlink(Pid),
               Ref = erlang:monitor(process, Pid),
               exit(Pid, shutdown),
               receive {'DOWN', Ref, process, Pid, _} -> ok end
    end.
