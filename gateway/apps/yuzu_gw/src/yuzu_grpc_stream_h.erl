%%%-------------------------------------------------------------------
%%% @doc The gRPC layer as a Cowboy stream handler. It replaces cowboy_stream_h
%%% on a listener (`stream_handlers => [yuzu_grpc_stream_h]'), so there is no
%%% HTTP routing, no request body reading and no middleware: one stream is one
%%% RPC, and this module is its state machine.
%%%
%%% It runs inside the Cowboy connection process, which decodes the frames of
%%% every stream of that connection. Nothing that can block runs here: the
%%% service function runs in its own process (yuzu_grpc_runner), linked to the
%%% connection and registered with Cowboy as the stream's child, so Cowboy shuts
%%% it down when the stream ends and delivers its EXIT to info/3.
%%%
%%%   awaiting_request  unary / server-streaming: buffering the one request
%%%   running           bidirectional / client-streaming: every decoded message
%%%                     goes to the handler as {Ref, Map}, END_STREAM as {Ref, eos}
%%%   running_single    the handler of a one-request call has started; any
%%%                     further request DATA is dropped and counted
%%%   ended             a status was sent; every DATA frame is dropped
%%%
%%% DATA that reaches a stream that must not execute anything is dropped in
%%% this state machine, not by a check in a handler: a peer that was refused
%%% (UNAUTHENTICATED, UNIMPLEMENTED ...) and has frames in flight cannot make a
%%% handler run (#1422), and the second message of a unary call cannot run it
%%% twice (#5591). Every DATA frame is answered with `{flow, N}' so the peer's
%%% window is never left closed.
%%%
%%% Cowboy logs the arguments of a stream handler callback that raises, which
%%% here would be request bytes, request headers and the handler's state. No
%%% callback may raise: each is wrapped, and a failure ends the stream with
%%% INTERNAL after one log line naming only the exception class. Nothing in
%%% this module logs a request, a ctx, a header, a certificate or an exit term.
%%%
%%% Two bounds on an unauthenticated peer's memory use live here (a third, the
%%% node-wide one, is yuzu_gw_memory_shedder):
%%%
%%%   - the connection process is given a max_heap_size ceiling on the first
%%%     stream it serves (init runs here, in that process). The ceiling counts
%%%     shared binaries, so the request bytes every stream holds in its reader
%%%     (#st.reader) count against it, and a connection that buffers more than
%%%     limits.max_connection_memory_bytes of half-finished requests is killed
%%%     by the VM (yuzu_gw_conn_watch counts the kill). Without it a peer could
%%%     open max_concurrent_streams streams and hold a full message short of its
%%%     last byte on each, for the life of the connection. The VM checks it when
%%%     the process collects garbage and counts the dead binaries too, so the
%%%     reader copies each chunk once and joins once (yuzu_grpc_frame:read/3)
%%%     and the process collects after every MiB of requests (maybe_collect/2):
%%%     a well-behaved client sending messages of max_message_bytes must never
%%%     reach the ceiling. The listener leaves it off on a management-only
%%%     listener unless configured (yuzu_grpc_listener:stream_limits/1): the
%%%     ceiling also counts the responses waiting to be written, and killed the
%%%     pinned server's one connection when a fan-out's responses arrived
%%%     together;
%%%   - a unary or server-streaming stream that stays in `awaiting_request'
%%%     (buffering its one request, no handler yet) past limits.request_timeout_ms
%%%     is aborted with DEADLINE_EXCEEDED and its buffer dropped. It is armed
%%%     only for the one-request kinds, and only while they await that request:
%%%     a bidirectional or client-streaming handler (an agent's Subscribe) is
%%%     spawned before any message and is never cut by it. A grpc-timeout the
%%%     client sent runs alongside; whichever fires first ends the stream.
%%%
%%% A grpc-timeout ends the call DEADLINE_EXCEEDED a margin before the client's
%%% deadline (deadline_ms/1), so the client gets the status rather than having
%%% to reset the stream: many resets at once close the whole connection.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_stream_h).
-behaviour(cowboy_stream).

-include("yuzu_grpc.hrl").

-export([init/3, data/4, info/3, terminate/3, early_error/5]).
-export([deadline_ms/1]).

%% Cowboy kills a handler that ignores the shutdown signal after this long.
-define(SHUTDOWN_MS, 5000).
%% The connection process collects its garbage once this many request bytes
%% have passed through it since the last collection (or max_message_bytes, if
%% that is smaller): see maybe_collect/2.
-define(COLLECT_AFTER_BYTES, 1048576).
%% A call with a grpc-timeout is ended this much before the client's deadline:
%% a tenth of the timeout, at most one second (deadline_ms/1).
-define(DEADLINE_MARGIN_MAX_MS, 1000).
-define(DEADLINE_MARGIN_DIVISOR, 10).
%% Connection-process dictionary keys: the listener role, and the mark that a
%% close of this connection was already counted.
-define(LISTENER_KEY, '$yuzu_grpc_listener').
-define(CLOSED_KEY, '$yuzu_grpc_close_counted').
%% Connection-process dictionary key: request bytes since the last collection.
-define(UNCOLLECTED_KEY, '$yuzu_grpc_uncollected').

-record(st, {
    phase = awaiting_request :: awaiting_request | running | running_single | ended,
    route :: yuzu_grpc_route:route() | undefined,
    stream :: yuzu_grpc_stream:stream() | undefined,
    max_message :: pos_integer(),
    %% The request bytes of a message not yet complete (yuzu_grpc_frame:read/3).
    reader = yuzu_grpc_frame:reader() :: yuzu_grpc_frame:reader(),
    handler :: pid() | undefined,
    ref :: reference() | undefined,
    headers_sent = false :: boolean(),
    timer :: reference() | undefined,
    %% The request-receive deadline of a one-request stream still awaiting its
    %% request; cancelled the moment the request is complete (the handler spawns).
    recv_timer :: reference() | undefined,
    alarms = [] :: [atom()],
    waiting = [] :: [{pid(), reference()}]
}).

%%--------------------------------------------------------------------
%% cowboy_stream callbacks
%%--------------------------------------------------------------------

-spec init(cowboy_stream:streamid(), cowboy_req:req(), cowboy:opts()) ->
    {cowboy_stream:commands(), #st{}}.
init(StreamId, Req, Opts) ->
    try
        start(StreamId, Req, maps:get(env, Opts, #{}))
    catch
        Class:_ -> failed(#st{max_message = ?YUZU_GRPC_MAX_MESSAGE_BYTES}, Class)
    end.

-spec data(cowboy_stream:streamid(), cowboy_stream:fin(), binary(), #st{}) ->
    {cowboy_stream:commands(), #st{}}.
data(_StreamId, IsFin, Data, St) ->
    try
        uncollected(byte_size(Data)),
        maybe_collect(on_data(IsFin, Data, St), St#st.max_message)
    catch
        Class:_ -> failed(St, Class)
    end.

-spec info(cowboy_stream:streamid(), term(), #st{}) ->
    {cowboy_stream:commands(), #st{}}.
info(_StreamId, Msg, St) ->
    try
        on_info(Msg, St)
    catch
        Class:_ -> failed(St, Class)
    end.

%% The handler is stopped with `shutdown' whatever the reason (a reset stream, a
%% deadline, a closed connection): it does not trap exits, so it ends at once
%% wherever it is blocked and runs no cleanup of its own (see yuzu_grpc_runner).
-spec terminate(cowboy_stream:streamid(), cowboy_stream:reason(), #st{}) -> ok.
terminate(_StreamId, Reason, #st{handler = Handler, timer = Timer, recv_timer = RecvTimer}) ->
    count_close(Reason),
    cancel_timer(Timer),
    cancel_timer(RecvTimer),
    _ = case Handler of
        undefined -> ok;
        Pid -> exit(Pid, shutdown)
    end,
    ok.

-spec early_error(cowboy_stream:streamid(), cowboy_stream:reason(),
                  cowboy_stream:partial_req(), Resp, cowboy:opts()) -> Resp
    when Resp :: cowboy_stream:resp_command().
early_error(_StreamId, _Reason, _PartialReq, Resp, _Opts) ->
    Resp.

%%--------------------------------------------------------------------
%% A new stream
%%--------------------------------------------------------------------

start(StreamId, Req, Env) ->
    Limits = maps:get(limits, Env, #{}),
    MaxMessage = maps:get(max_message_bytes, Limits, ?YUZU_GRPC_MAX_MESSAGE_BYTES),
    %% Cap this connection's memory the first time it serves a stream (init runs
    %% in the connection process). It is per connection, not per stream, so do
    %% it once; a later stream on the same connection finds it already set.
    cap_connection_memory(MaxMessage, Limits),
    %% The listener role a close of this connection is counted under.
    put(?LISTENER_KEY, maps:get(listener, Env, other)),
    St0 = #st{max_message = MaxMessage},
    case authenticate(maps:get(auth_fun, Env, undefined), maps:get(cert, Req, undefined)) of
        false ->
            reject(St0, ?GRPC_STATUS_UNAUTHENTICATED, <<"unauthenticated">>);
        true ->
            admitted(StreamId, Req, Env, St0)
    end.

%% A connection Cowboy closes itself, counted once per connection when the close
%% reaches a stream: Cowboy ends every stream still open with the connection's
%% reason, and this runs in the connection process, so the first stream to see
%% it counts it and the rest find the mark. Only Cowboy's own reasons are
%% counted, from a closed set: an idle_timeout (nothing received for the
%% listener's idle_timeout), enhance_your_calm (a flood limit: resets, cancels,
%% settings, pings, priorities or empty frames past its rate) and any other
%% HTTP/2 connection error (protocol_error). A peer that closes, a socket error
%% and a stop of the listener are not counted; a connection the VM kills for
%% its memory ceiling never gets here (yuzu_gw_conn_watch counts that); a
%% connection with no stream open when it closes is not seen.
count_close({connection_error, enhance_your_calm, _}) -> connection_closed(enhance_your_calm);
count_close({connection_error, _, _}) -> connection_closed(protocol_error);
count_close({stop, timeout, _}) -> connection_closed(idle_timeout);
count_close(_) -> ok.

connection_closed(Reason) ->
    case get(?CLOSED_KEY) of
        true -> ok;
        _ ->
            put(?CLOSED_KEY, true),
            Listener = case get(?LISTENER_KEY) of
                           undefined -> other;
                           L -> L
                       end,
            telemetry:execute([yuzu, gw, grpc, connection_closed], #{count => 1},
                              #{listener => Listener, reason => Reason})
    end.

%% The max_heap_size ceiling on the connection process. `include_shared_binaries'
%% makes it count the refc binaries the streams' in-flight requests hold (the
%% chunks in each stream's reader), which is where a flood of half-finished
%% streams keeps its bytes: the connection process's own heap stays tiny. `kill' ends the
%% connection (every stream on it) when the ceiling is passed; `error_logger'
%% emits the report yuzu_gw_conn_watch counts. `infinity' disables it.
cap_connection_memory(MaxMessage, Limits) ->
    case get('$yuzu_grpc_conn_capped') of
        true -> ok;
        _ ->
            put('$yuzu_grpc_conn_capped', true),
            case max_connection_memory_bytes(MaxMessage, Limits) of
                infinity -> ok;
                Bytes ->
                    Words = Bytes div erlang:system_info(wordsize),
                    _ = process_flag(max_heap_size,
                                     #{size => Words, kill => true,
                                       error_logger => true,
                                       include_shared_binaries => true}),
                    ok
            end
    end.

max_connection_memory_bytes(MaxMessage, Limits) ->
    case maps:get(max_connection_memory_bytes, Limits, undefined) of
        undefined ->
            %% Floor the derived default: a multiple of a small max_message_bytes
            %% could be below a connection's baseline memory and kill it at once.
            max(?YUZU_GRPC_MIN_CONN_MEMORY_BYTES,
                ?YUZU_GRPC_MAX_CONN_MEMORY_FACTOR * MaxMessage);
        Explicit ->
            %% An explicit value is used as given (the listener's validation has
            %% already refused anything below the floor, bar `infinity').
            Explicit
    end.

%% The authentication is the first thing that happens to a stream, ahead of
%% even the method lookup: a refused peer learns nothing about the service. A
%% listener with an auth_fun refuses a peer with no certificate and an auth_fun
%% that fails or raises (the term it raised with is never looked at).
authenticate(undefined, _Cert) ->
    true;
authenticate(_AuthFun, undefined) ->
    false;
authenticate(AuthFun, Cert) ->
    try AuthFun(Cert) of
        {true, _Identity} -> true;
        true -> true;
        _ -> false
    catch
        _:_ -> false
    end.

admitted(StreamId, Req, Env, St0) ->
    Headers = maps:get(headers, Req),
    case check_request(Req, Headers, maps:get(grpc, Env, #{})) of
        {error, Status, Message} ->
            reject(St0, Status, Message);
        {ok, Route} ->
            case yuzu_grpc_frame:parse_timeout(maps:get(<<"grpc-timeout">>, Headers, undefined)) of
                {error, invalid} ->
                    reject(St0, ?GRPC_STATUS_INVALID_ARGUMENT, <<"invalid grpc-timeout">>);
                Timeout ->
                    call(StreamId, Req, Headers, Route, Timeout, Env, St0)
            end
    end.

check_request(Req, Headers, Routes) ->
    case {maps:get(method, Req), maps:get(<<"content-type">>, Headers, undefined),
          maps:get(<<"grpc-encoding">>, Headers, <<"identity">>)} of
        {<<"POST">>, ContentType, <<"identity">>}
          when ContentType =:= <<"application/grpc">>;
               ContentType =:= <<"application/grpc+proto">> ->
            case yuzu_grpc_route:lookup(maps:get(path, Req), Routes) of
                {ok, Route} -> {ok, Route};
                error -> {error, ?GRPC_STATUS_UNIMPLEMENTED, <<"method not found">>}
            end;
        {<<"POST">>, ContentType, <<"identity">>} when ContentType =/= undefined ->
            {error, ?GRPC_STATUS_INVALID_ARGUMENT, <<"unsupported content-type">>};
        {<<"POST">>, undefined, <<"identity">>} ->
            {error, ?GRPC_STATUS_INVALID_ARGUMENT, <<"missing content-type">>};
        {<<"POST">>, _, _} ->
            {error, ?GRPC_STATUS_UNIMPLEMENTED, <<"compression is not supported">>};
        _ ->
            {error, ?GRPC_STATUS_INVALID_ARGUMENT, <<"method must be POST">>}
    end.

call(StreamId, Req, Headers, Route, Timeout, Env, St0) ->
    #{path := Path, pb := Pb, output := Output, kind := Kind} = Route,
    Limits = maps:get(limits, Env, #{}),
    Conn = self(),
    Peer = maps:get(peer, Req, undefined),
    Ctx = yuzu_grpc:new_ctx(Headers, Conn, Peer, origin(Env, Peer, Req, Headers),
                            maps:get(cert, Req, undefined)),
    Stream = #yuzu_grpc_stream{conn = Conn, stream_id = StreamId, ctx = Ctx,
                               method = Path, pb = Pb, output = Output,
                               send_timeout = maps:get(send_timeout_ms, Limits,
                                                       ?YUZU_GRPC_SEND_TIMEOUT_MS)},
    St1 = St0#st{route = Route, stream = Stream, timer = arm_deadline(StreamId, Timeout)},
    case {Kind, maps:get(has_body, Req, true)} of
        {K, true} when K =:= bidi; K =:= client_stream ->
            Ref = make_ref(),
            Pid = spawn_runner(Route, Stream, #{ref => Ref}),
            {[{spawn, Pid, ?SHUTDOWN_MS}],
             St1#st{phase = running, handler = Pid, ref = Ref}};
        {K, false} when K =:= bidi; K =:= client_stream ->
            %% The peer half-closed with its headers: a stream of no messages.
            Ref = make_ref(),
            Pid = spawn_runner(Route, Stream, #{ref => Ref}),
            Pid ! {Ref, eos},
            {[{spawn, Pid, ?SHUTDOWN_MS}],
             St1#st{phase = running, handler = Pid, ref = Ref}};
        {_, true} ->
            %% A one-request stream awaiting its request: arm the receive
            %% deadline so a peer cannot hold the buffer open forever.
            RecvTimer = arm_recv_deadline(StreamId,
                                          maps:get(request_timeout_ms, Limits,
                                                   ?YUZU_GRPC_REQUEST_TIMEOUT_MS)),
            {[], St1#st{phase = awaiting_request, recv_timer = RecvTimer}};
        {_, false} ->
            reject(St1, ?GRPC_STATUS_INTERNAL, <<"missing request message">>)
    end.

%% The address the call is attributed to (yuzu_grpc_origin), or `undefined' when
%% a trusted proxy gave none. A claim that was ignored is counted by mode and
%% reason only: the address is never logged or put in a metric label.
origin(_Env, undefined, _Req, _Headers) ->
    undefined;
origin(Env, {PeerIp, _Port}, Req, Headers) ->
    Config = maps:get(origin, Env, #{mode => transport}),
    {Origin, Note} = yuzu_grpc_origin:resolve(Config, PeerIp, maps:get(proxy_header, Req, undefined),
                                              Headers),
    case Note of
        ok -> ok;
        _ -> telemetry:execute([yuzu, gw, grpc, origin_ignored], #{count => 1},
                               #{mode => maps:get(mode, Config), reason => Note})
    end,
    Origin.

%% The client's grpc-timeout, less a margin: the call is answered
%% DEADLINE_EXCEEDED BEFORE the client's own deadline passes, so a client that
%% would reset the stream at its deadline (a gRPC client sends RST_STREAM CANCEL
%% then) receives the status instead and has nothing to cancel. When many
%% streams of one connection share a deadline (a fan-out whose agents are gone,
%% each command a call with the same 300 s deadline) those resets arrive
%% together, and past Cowboy's max_cancel_stream_rate (500 per 10 s) Cowboy
%% closes the WHOLE connection, every call on it with it. See deadline_ms/1.
arm_deadline(_StreamId, infinity) ->
    undefined;
arm_deadline(StreamId, {ok, Ms}) ->
    Conn = self(),
    erlang:send_after(deadline_ms(Ms), Conn, {{Conn, StreamId}, grpc_deadline}).

%% @doc When the gateway ends a call whose client sent a grpc-timeout of Ms: a
%% tenth of the timeout early, at most ?DEADLINE_MARGIN_MAX_MS. The margin has to
%% cover the time the request took to arrive (the gateway's timer starts that
%% much after the client's), the time the connection process takes to write the
%% statuses of every stream expiring together (thousands of trailers, one
%% process), and the time they take to reach the client: one second is far
%% above all three on a LAN and still under 0.4% of the server's 300 s. A tenth
%% keeps a short timeout useful (a 2 s call is answered at 1.8 s, not at 1 s).
-spec deadline_ms(non_neg_integer()) -> non_neg_integer().
deadline_ms(Ms) ->
    Ms - min(?DEADLINE_MARGIN_MAX_MS, Ms div ?DEADLINE_MARGIN_DIVISOR).

arm_recv_deadline(_StreamId, infinity) ->
    undefined;
arm_recv_deadline(StreamId, Ms) when is_integer(Ms), Ms > 0 ->
    Conn = self(),
    erlang:send_after(Ms, Conn, {{Conn, StreamId}, grpc_recv_deadline});
arm_recv_deadline(_StreamId, _Other) ->
    undefined.

spawn_runner(#{kind := Kind, module := Module, function := Function}, Stream, Extra) ->
    proc_lib:spawn_link(yuzu_grpc_runner, run,
                        [Extra#{kind => Kind, module => Module, function => Function,
                                stream => Stream}]).

%%--------------------------------------------------------------------
%% Request DATA
%%--------------------------------------------------------------------

on_data(IsFin, Data, #st{phase = awaiting_request, reader = Reader, max_message = Max} = St) ->
    Size = byte_size(Data),
    case yuzu_grpc_frame:read(Data, Max, Reader) of
        {ok, Message, Rest} ->
            case decode_request(St, Message) of
                {ok, Request} ->
                    %% The request is complete: the handler runs now, so the
                    %% receive deadline has done its job.
                    cancel_timer(St#st.recv_timer),
                    uncollected(2 * byte_size(Message)),
                    Pid = spawn_runner(St#st.route, St#st.stream, #{request => Request}),
                    dropped(byte_size(Rest), St, extra_request_data),
                    {[{spawn, Pid, ?SHUTDOWN_MS} | credit(Size)],
                     St#st{phase = running_single, handler = Pid,
                           reader = yuzu_grpc_frame:reader(), recv_timer = undefined}};
                error ->
                    abort(St, ?GRPC_STATUS_INTERNAL, <<"invalid request message">>)
            end;
        {more, _} when IsFin =:= fin ->
            abort(St, ?GRPC_STATUS_INTERNAL, <<"incomplete request message">>);
        {more, Reader1} ->
            {credit(Size), St#st{reader = Reader1}};
        {error, {Status, Message}} ->
            abort(St, Status, Message)
    end;
on_data(IsFin, Data, #st{phase = running, reader = Reader0, max_message = Max,
                         handler = Handler, ref = Ref} = St) ->
    case deliver(Data, Max, Reader0, St) of
        {ok, Reader} ->
            case {IsFin, yuzu_grpc_frame:reader_bytes(Reader)} of
                {fin, 0} ->
                    Handler ! {Ref, eos},
                    {credit(byte_size(Data)), St#st{reader = Reader}};
                {fin, _} ->
                    abort(St, ?GRPC_STATUS_INTERNAL, <<"incomplete request message">>);
                {nofin, _} ->
                    {credit(byte_size(Data)), St#st{reader = Reader}}
            end;
        {error, Status, Message} ->
            abort(St, Status, Message)
    end;
on_data(_IsFin, Data, #st{phase = running_single} = St) ->
    dropped(byte_size(Data), St, extra_request_data),
    {credit(byte_size(Data)), St};
on_data(_IsFin, Data, #st{phase = ended} = St) ->
    dropped(byte_size(Data), St, stream_ended),
    {credit(byte_size(Data)), St}.

%% Give the peer back the window the DATA it just sent used. Every DATA frame is
%% answered with this, whatever became of it, so a stream's window never closes
%% (Cowlib reopens a window only for a stream that has asked for flow).
credit(0) -> [];
credit(Size) -> [{flow, Size}].

%% Hand every complete message of Data to the handler; the reader returned holds
%% the start of the next one.
deliver(Data, Max, Reader, #st{handler = Handler, ref = Ref} = St) ->
    case yuzu_grpc_frame:read(Data, Max, Reader) of
        {ok, Message, Rest} ->
            case decode_request(St, Message) of
                {ok, Request} ->
                    uncollected(2 * byte_size(Message)),
                    Handler ! {Ref, Request},
                    deliver(Rest, Max, yuzu_grpc_frame:reader(), St);
                error ->
                    {error, ?GRPC_STATUS_INTERNAL, <<"invalid request message">>}
            end;
        {more, Reader1} ->
            {ok, Reader1};
        {error, {Status, Message}} ->
            {error, Status, Message}
    end.

%% Request bytes that became (or will become) garbage of the connection process:
%% every DATA frame (the socket buffer it came in), and twice a complete message
%% (the joined message and the decoded request, both garbage once the request is
%% handed to its handler).
uncollected(Bytes) ->
    put(?UNCOLLECTED_KEY, Bytes + case get(?UNCOLLECTED_KEY) of
                                      undefined -> 0;
                                      N -> N
                                  end).

%% Have the connection process collect its garbage once enough request bytes
%% went through it. The memory ceiling (cap_connection_memory/2) is checked when
%% the process collects, and it counts every binary the process references AT
%% THAT MOMENT, the dead ones included: left to itself the VM collects a process
%% with large binaries only when their total passes a threshold it sizes from
%% the live total (up to about twice it), so the garbage of one full-size
%% message was still counted while the next one arrived, and one well-behaved
%% client was killed (#5695). Collecting after every max_message_bytes (at most
%% every MiB) keeps what the ceiling sees close to the bytes actually buffered:
%% a complete message costs three times its size at its peak (the chunks, the
%% joined message, the decoded request) and the garbage on top of that is under
%% a MiB.
%%
%% The collection cannot run here: Cowboy's state, on the stack of this call,
%% still holds this stream's previous state and with it the chunks just joined.
%% So it is a message to the stream itself, handled once this call has
%% returned (on_info(grpc_collect, ...)). It goes only to a stream that stays
%% open; a stream reset between the send and its handling drops it (Cowboy logs
%% it as a message for an ended stream, rate-limited by yuzu_grpc_cowboy_log),
%% and the next DATA frame sends another. A connection's collection costs the
%% size of its own heap, a few kilowords: the request bytes are off it.
maybe_collect({Commands, #st{phase = Phase,
                             stream = #yuzu_grpc_stream{conn = Conn, stream_id = Id}}} = Result,
              MaxMessage) when Phase =/= ended ->
    case get(?UNCOLLECTED_KEY) of
        N when is_integer(N), N >= min(?COLLECT_AFTER_BYTES, MaxMessage) ->
            case lists:member(stop, Commands) of
                true ->
                    Result;
                false ->
                    put(?UNCOLLECTED_KEY, 0),
                    Conn ! {{Conn, Id}, grpc_collect},
                    Result
            end;
        _ ->
            Result
    end;
maybe_collect(Result, _MaxMessage) ->
    Result.

decode_request(#st{route = #{pb := Pb, input := Input}}, Message) ->
    try
        {ok, Pb:decode_msg(Message, Input)}
    catch
        _:_ -> error
    end.

dropped(0, _St, _Reason) ->
    ok;
dropped(Bytes, #st{route = Route}, Reason) ->
    telemetry:execute([yuzu, gw, grpc, dropped_data], #{bytes => Bytes},
                      #{reason => Reason, method => path_of(Route)}).

path_of(#{path := Path}) -> Path;
path_of(undefined) -> undefined.

%%--------------------------------------------------------------------
%% Messages from the handler, the deadline and Cowboy
%%--------------------------------------------------------------------

%% A frame to send. The first one opens the response.
on_info({grpc_frame, From, Ack, Frame}, #st{handler = From, phase = Phase} = St)
  when Phase =/= ended ->
    Commands = case St#st.headers_sent of
        true -> [{data, nofin, Frame}];
        false -> [{headers, 200, #{<<"content-type">> => <<"application/grpc">>}},
                  {data, nofin, Frame}]
    end,
    {Commands, answer_sender(From, Ack, St#st{headers_sent = true})};
on_info({grpc_frame, From, Ack, _Frame}, #st{handler = From} = St) ->
    From ! {grpc_nack, Ack},
    {[], St};
%% The handler's status. The stream stays up until the handler exits, so that a
%% handler finishing its last send is never cut off.
on_info({grpc_end, From, Status, Message}, #st{handler = From, phase = Phase} = St)
  when Phase =/= ended ->
    finish(St, yuzu_grpc_frame:normalize_status(Status),
           yuzu_grpc_frame:normalize_message(Message), []);
on_info(grpc_deadline, #st{phase = Phase} = St) when Phase =/= ended ->
    finish(St#st{timer = undefined}, ?GRPC_STATUS_DEADLINE_EXCEEDED,
           <<"deadline exceeded">>, [stop]);
%% The request-receive deadline fired while the stream was still buffering its
%% one request: no handler ran, so drop the buffer and end the stream. In any
%% other phase the timer was cancelled when the request completed; a message
%% that races the cancel is ignored.
on_info(grpc_recv_deadline, #st{phase = awaiting_request} = St) ->
    telemetry:execute([yuzu, gw, grpc, recv_timeout], #{count => 1},
                      #{method => path_of(St#st.route)}),
    abort(St#st{recv_timer = undefined, reader = yuzu_grpc_frame:reader()},
          ?GRPC_STATUS_DEADLINE_EXCEEDED,
          <<"request deadline exceeded">>);
on_info(grpc_recv_deadline, St) ->
    {[], St};
%% See maybe_collect/2. The stream's own state holds no request bytes now.
on_info(grpc_collect, St) ->
    _ = erlang:garbage_collect(),
    {[], St};
on_info({'EXIT', Pid, Reason}, #st{handler = Pid} = St) ->
    exited(Reason, St);
%% Cowboy's buffer alarms (see cowboy_http2:maybe_send_data_alarm/3).
on_info({alarm, Name, on}, #st{alarms = Alarms} = St) ->
    {[], St#st{alarms = lists:usort([Name | Alarms])}};
on_info({alarm, Name, off}, #st{alarms = Alarms} = St) ->
    {[], release_senders(St#st{alarms = lists:delete(Name, Alarms)})};
on_info(_Other, St) ->
    {[], St}.

%% Let the sender go on, unless the peer is not reading: then its answer waits
%% for the alarm to go off, which is what slows a streaming handler down.
answer_sender(From, Ack, #st{alarms = []} = St) ->
    From ! {grpc_ack, Ack},
    St;
answer_sender(From, Ack, #st{waiting = Waiting} = St) ->
    St#st{waiting = [{From, Ack} | Waiting]}.

release_senders(#st{alarms = [], waiting = Waiting} = St) ->
    [From ! {grpc_ack, Ack} || {From, Ack} <- lists:reverse(Waiting)],
    St#st{waiting = []};
release_senders(St) ->
    St.

exited(_Reason, #st{phase = ended} = St) ->
    {[stop], St};
exited(normal, St) ->
    %% The handler left without a status of its own: it completed.
    finish(St, ?GRPC_STATUS_OK, <<>>, [stop]);
exited(Reason, #st{route = Route} = St) ->
    {Commands, St1} = finish(St, ?GRPC_STATUS_INTERNAL, <<"internal error">>, [stop]),
    {[{log, error, "gateway grpc handler ~s exited: ~s",
       [path_of(Route), reason_class(Reason)]} | Commands], St1}.

%% The shape of an exit reason, and nothing of its content.
reason_class(Reason) when is_atom(Reason) -> atom_to_list(Reason);
reason_class({shutdown, _}) -> "shutdown";
reason_class(Reason) when is_tuple(Reason) -> "tuple";
reason_class(_) -> "other".

%%--------------------------------------------------------------------
%% Ending a stream
%%--------------------------------------------------------------------

%% Send the terminal status and enter the `ended' state. Trailers-only when the
%% response was never opened. Total over a stream that has already ended: a
%% second set of trailers would raise inside the connection process, so only
%% what follows them (a `stop') is kept.
finish(#st{phase = ended} = St, _Status, _Message, After) ->
    {After, St};
finish(#st{headers_sent = Sent, timer = Timer, recv_timer = RecvTimer} = St,
       Status, Message, After) ->
    cancel_timer(Timer),
    cancel_timer(RecvTimer),
    Trailers = yuzu_grpc_frame:trailers(Status, Message),
    Commands = case Sent of
        true -> [{trailers, Trailers}];
        false -> [{response, 200, trailers_only(Trailers), <<>>}]
    end,
    {Commands ++ After,
     nack_senders(St#st{phase = ended, timer = undefined, recv_timer = undefined})}.

trailers_only(Trailers) ->
    Trailers#{<<"content-type">> => <<"application/grpc">>}.

%% Refuse a stream that has no handler: the status, then Cowboy drops the stream
%% (and every frame of it still in flight).
reject(St, Status, Message) ->
    finish(St, Status, Message, [stop]).

%% Refuse a stream whose handler may be running. Cowboy's `stop' sends the
%% handler the shutdown signal and kills it if it does not leave.
abort(St, Status, Message) ->
    finish(St, Status, Message, [stop]).

%% The internal-error exit of a callback.
failed(St, Class) ->
    {Commands, St1} = finish(St, ?GRPC_STATUS_INTERNAL, <<"internal error">>, [stop]),
    {[{log, error, "gateway grpc stream failed: class=~s", [atom_to_list(Class)]}
      | Commands], St1}.

nack_senders(#st{waiting = Waiting} = St) ->
    [From ! {grpc_nack, Ack} || {From, Ack} <- Waiting],
    St#st{waiting = []}.

cancel_timer(undefined) ->
    ok;
cancel_timer(Timer) ->
    _ = erlang:cancel_timer(Timer, [{async, true}, {info, false}]),
    ok.
