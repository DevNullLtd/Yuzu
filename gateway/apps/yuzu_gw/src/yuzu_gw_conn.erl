%%%-------------------------------------------------------------------
%%% @doc Connection identity of an agent-facing gRPC call.
%%%
%%% A "connection key" is the pid of the HTTP/2 connection process that
%%% carries the call. Every stream of one connection (the long-lived
%%% Subscribe stream and the unary Heartbeat calls an agent makes on the
%%% same channel) reports the same key; calls on different connections
%%% report different keys. Heartbeat admission compares these keys.
%%%
%%% The pid is the Cowboy connection process, read from the call's ctx
%%% (`yuzu_grpc:conn_pid/1') or stream (`yuzu_grpc_stream:conn_pid/1'). This
%%% module is the only place the agent-facing handlers obtain a key, so tests can
%%% replace it.
%%%
%%% `undefined' means "no key available" (for example a ctx that does not
%%% come from a live stream). It is never a usable key: a session bound to
%%% `undefined' admits nothing.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_conn).

-export([key_from_ctx/1, key_from_stream/1]).
-export_type([key/0]).

-type key() :: pid() | undefined.

%% @doc Connection key for the ctx a unary handler receives.
-spec key_from_ctx(ctx:t()) -> key().
key_from_ctx(Ctx) ->
    try yuzu_grpc:conn_pid(Ctx)
    catch _:_ -> undefined
    end.

%% @doc Connection key for the stream state a bidi handler receives.
-spec key_from_stream(yuzu_grpc_stream:stream()) -> key().
key_from_stream(Stream) ->
    try yuzu_grpc_stream:conn_pid(Stream)
    catch _:_ -> undefined
    end.
