%%%-------------------------------------------------------------------
%%% @doc What a service handler can learn about its call, read from the `ctx'
%%% it is handed (a unary handler receives the ctx itself, a streaming handler
%%% reads it with yuzu_grpc_stream:ctx/1).
%%%
%%% Everything here is read-only. In particular nothing installs an
%%% authenticator: a listener's `auth_fun' runs in yuzu_grpc_stream_h before
%%% a handler exists, and a handler learns the peer certificate only to look at
%%% it. Never log a ctx or the headers of one: they carry request metadata.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc).

-export([headers/1, peer/1, origin/1, peer_cert/1, conn_pid/1]).
-export([new_ctx/5]).

-define(HEADERS, yuzu_grpc_headers).
-define(CONN, yuzu_grpc_conn).
-define(PEER, yuzu_grpc_peer).
-define(ORIGIN, yuzu_grpc_origin).
-define(CERT, yuzu_grpc_cert).

%% @doc The request headers, names lowercased. A header sent more than once is
%% the values joined by ", ". The pseudo-headers (:path, :authority ...) are not
%% among them. `#{}' for a ctx that carries no call (ctx:background()).
-spec headers(ctx:t()) -> #{binary() => binary()}.
headers(Ctx) ->
    ctx:get(Ctx, ?HEADERS, #{}).

%% @doc The address of the TCP peer of the connection, or `undefined'. Behind a
%% proxy this is the proxy. It is what the socket says and is never altered by
%% anything the client sent; use origin/1 for the address of the agent.
-spec peer(ctx:t()) -> {inet:ip_address(), inet:port_number()} | undefined.
peer(Ctx) ->
    ctx:get(Ctx, ?PEER, undefined).

%% @doc The address the call is attributed to, and where it came from. On a
%% listener that is not behind a proxy this is the TCP peer (`transport'). On a
%% listener configured as proxied, a claim from one of its trusted proxy
%% addresses (the PROXY protocol header, or x-forwarded-for) is used instead
%% (`proxy_protocol' / `forwarded_for'); a claim from anyone else is ignored.
%% See yuzu_grpc_origin. The address has no port. `undefined' is NO OBSERVATION:
%% the connection has no peer address, or the listener is proxied and its
%% trusted proxy gave no usable address (the TCP peer is then the proxy, which
%% is not the agent). A handler must not substitute the TCP peer for it.
-spec origin(ctx:t()) ->
    {inet:ip_address(), transport | proxy_protocol | forwarded_for} | undefined.
origin(Ctx) ->
    ctx:get(Ctx, ?ORIGIN, undefined).

%% @doc The DER certificate the peer presented in the TLS handshake, or
%% `undefined' (plaintext, or a peer that sent none).
-spec peer_cert(ctx:t()) -> binary() | undefined.
peer_cert(Ctx) ->
    ctx:get(Ctx, ?CERT, undefined).

%% @doc The pid of the HTTP/2 connection process that carries the call: every
%% call on one connection reports the same pid, calls on different connections
%% differ. `undefined' for a ctx that carries no call.
-spec conn_pid(ctx:t()) -> pid() | undefined.
conn_pid(Ctx) ->
    ctx:get(Ctx, ?CONN, undefined).

%% @doc The ctx of a new call (for yuzu_grpc_stream_h).
-spec new_ctx(#{binary() => binary()}, pid(),
              {inet:ip_address(), inet:port_number()} | undefined,
              yuzu_grpc_origin:origin() | undefined,
              binary() | undefined) -> ctx:t().
new_ctx(Headers, ConnPid, Peer, Origin, Cert) ->
    ctx:with_values(#{?HEADERS => Headers, ?CONN => ConnPid,
                      ?PEER => Peer, ?ORIGIN => Origin, ?CERT => Cert}).
