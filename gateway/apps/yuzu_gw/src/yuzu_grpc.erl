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

-export([headers/1, peer/1, peer_cert/1, conn_pid/1]).
-export([new_ctx/4]).

-define(HEADERS, yuzu_grpc_headers).
-define(CONN, yuzu_grpc_conn).
-define(PEER, yuzu_grpc_peer).
-define(CERT, yuzu_grpc_cert).

%% @doc The request headers, names lowercased. A header sent more than once is
%% the values joined by ", ". The pseudo-headers (:path, :authority ...) are not
%% among them. `#{}' for a ctx that carries no call (ctx:background()).
-spec headers(ctx:t()) -> #{binary() => binary()}.
headers(Ctx) ->
    ctx:get(Ctx, ?HEADERS, #{}).

%% @doc The address of the TCP peer of the connection, or `undefined'. Behind a
%% proxy this is the proxy.
-spec peer(ctx:t()) -> {inet:ip_address(), inet:port_number()} | undefined.
peer(Ctx) ->
    ctx:get(Ctx, ?PEER, undefined).

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
              binary() | undefined) -> ctx:t().
new_ctx(Headers, ConnPid, Peer, Cert) ->
    ctx:with_values(#{?HEADERS => Headers, ?CONN => ConnPid,
                      ?PEER => Peer, ?CERT => Cert}).
