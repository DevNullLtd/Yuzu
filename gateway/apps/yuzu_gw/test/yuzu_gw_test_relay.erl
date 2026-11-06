%%%-------------------------------------------------------------------
%%% @doc A TCP relay for tests that stands in for a load balancer: it accepts
%%% connections on a loopback port, opens a connection to an upstream port,
%%% writes a fixed header (a PROXY protocol header, as an F5 iRule or HAProxy
%%% `send-proxy-v2' would) and then copies bytes both ways without looking at
%%% them. Because it is a plain TCP splice, TLS passes through it untouched:
%%% the client's handshake, and its certificate, reach the upstream listener.
%%% yuzu_grpc_client needs no change to use it: point the channel at the relay.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_test_relay).

-export([start/2, stop/1, proxy_header/2, local_header/0]).

-opaque relay() :: {pid(), port()}.
-export_type([relay/0]).

%% @doc A relay in front of `UpstreamPort' that sends `Header' first on every
%% connection. Returns the port to connect to.
-spec start(inet:port_number(), iodata()) -> {inet:port_number(), relay()}.
start(UpstreamPort, Header) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}}, {active, false},
                                      {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    Pid = spawn_link(fun() -> accept_loop(Listen, UpstreamPort, iolist_to_binary(Header)) end),
    {Port, {Pid, Listen}}.

-spec stop(relay()) -> ok.
stop({Pid, Listen}) ->
    unlink(Pid),
    exit(Pid, kill),
    _ = gen_tcp:close(Listen),
    ok.

%% @doc A PROXY protocol header (version 1 or 2) claiming `Src' as the client.
-spec proxy_header(1 | 2, inet:ip_address()) -> binary().
proxy_header(Version, Src) ->
    Family = case tuple_size(Src) of 4 -> ipv4; 8 -> ipv6 end,
    Dest = case Family of ipv4 -> {10, 0, 0, 9}; ipv6 -> {16#2001, 16#db8, 0, 0, 0, 0, 0, 9} end,
    iolist_to_binary(
      ranch_proxy_header:header(#{version => Version, command => proxy,
                                  transport_family => Family, transport_protocol => stream,
                                  src_address => Src, src_port => 41000,
                                  dest_address => Dest, dest_port => 50051})).

%% @doc A PROXY protocol version 2 `LOCAL' header: the proxy's own connection (a
%% health check), with no client behind it.
-spec local_header() -> binary().
local_header() ->
    iolist_to_binary(ranch_proxy_header:header(#{version => 2, command => local})).

accept_loop(Listen, UpstreamPort, Header) ->
    case gen_tcp:accept(Listen) of
        {ok, Client} ->
            Pid = spawn(fun() -> serve(Client, UpstreamPort, Header) end),
            ok = gen_tcp:controlling_process(Client, Pid),
            Pid ! go,
            accept_loop(Listen, UpstreamPort, Header);
        {error, _} ->
            ok
    end.

serve(Client, UpstreamPort, Header) ->
    receive go -> ok end,
    case gen_tcp:connect({127, 0, 0, 1}, UpstreamPort,
                         [binary, {active, false}, {nodelay, true}]) of
        {ok, Up} ->
            ok = gen_tcp:send(Up, Header),
            Self = self(),
            spawn_link(fun() -> pipe(Client, Up), Self ! done end),
            spawn_link(fun() -> pipe(Up, Client), Self ! done end),
            receive done -> ok end,
            _ = gen_tcp:close(Client),
            _ = gen_tcp:close(Up),
            ok;
        {error, _} ->
            gen_tcp:close(Client)
    end.

pipe(From, To) ->
    case gen_tcp:recv(From, 0) of
        {ok, Data} ->
            case gen_tcp:send(To, Data) of
                ok -> pipe(From, To);
                {error, _} -> ok
            end;
        {error, _} ->
            ok
    end.
