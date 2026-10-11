%%%-------------------------------------------------------------------
%%% @doc The API a streaming service handler uses on the `Stream' it is handed
%%% (a unary handler gets a ctx instead; see yuzu_grpc).
%%%
%%% send/2 gives real backpressure: it returns once the connection process has
%%% taken the frame, and the connection process holds that answer back while the
%%% peer is not reading and the send buffer is full. A handler that sends
%%% therefore slows to the speed of its peer instead of growing a queue.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_stream).

-include("yuzu_grpc.hrl").

-export([ctx/1, conn_pid/1, send/2, error/2]).

-export_type([stream/0]).

-type stream() :: #yuzu_grpc_stream{}.

%% @doc The ctx of the call.
-spec ctx(stream()) -> ctx:t().
ctx(#yuzu_grpc_stream{ctx = Ctx}) ->
    Ctx.

%% @doc The pid of the HTTP/2 connection process that carries the stream (see
%% yuzu_grpc:conn_pid/1).
-spec conn_pid(stream()) -> pid().
conn_pid(#yuzu_grpc_stream{conn = Conn}) ->
    Conn.

%% @doc Send one response message (a map of the response type). `{error,
%% closed}' means the stream is over (the peer reset it, the deadline passed,
%% the connection died): stop sending. Waiting longer than the stream's send
%% timeout for the connection to take the frame ends the call with UNAVAILABLE.
-spec send(stream(), map()) -> ok | {error, closed}.
send(#yuzu_grpc_stream{conn = Conn, stream_id = StreamId, pb = Pb, output = Output,
                       send_timeout = Timeout}, Message) ->
    Frame = yuzu_grpc_frame:encode(Pb:encode_msg(Message, Output)),
    Ack = make_ref(),
    Mon = erlang:monitor(process, Conn),
    Conn ! {{Conn, StreamId}, {grpc_frame, self(), Ack, Frame}},
    receive
        {grpc_ack, Ack} ->
            erlang:demonitor(Mon, [flush]),
            ok;
        {grpc_nack, Ack} ->
            erlang:demonitor(Mon, [flush]),
            {error, closed};
        {'DOWN', Mon, process, Conn, _} ->
            {error, closed}
    after Timeout ->
        erlang:demonitor(Mon, [flush]),
        throw({grpc_error, {?GRPC_STATUS_UNAVAILABLE, <<"send stalled">>}})
    end.

%% @doc End the call with a status: throws, and the runner turns the throw into
%% the trailers. This is a plain throw, so it works from
%% a nested function of the handler and from every kind of handler.
-spec error(yuzu_grpc_frame:status() | binary(), iodata()) -> no_return().
error(Status, Message) ->
    throw({grpc_error, {Status, Message}}).
