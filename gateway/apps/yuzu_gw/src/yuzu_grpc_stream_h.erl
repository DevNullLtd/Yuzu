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
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_stream_h).
-behaviour(cowboy_stream).

-include("yuzu_grpc.hrl").

-export([init/3, data/4, info/3, terminate/3, early_error/5]).

%% Cowboy kills a handler that ignores the shutdown signal after this long.
-define(SHUTDOWN_MS, 5000).

-record(st, {
    phase = awaiting_request :: awaiting_request | running | running_single | ended,
    route :: yuzu_grpc_route:route() | undefined,
    stream :: yuzu_grpc_stream:stream() | undefined,
    max_message :: pos_integer(),
    buf = <<>> :: binary(),
    handler :: pid() | undefined,
    ref :: reference() | undefined,
    headers_sent = false :: boolean(),
    timer :: reference() | undefined,
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
        on_data(IsFin, Data, St)
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

-spec terminate(cowboy_stream:streamid(), cowboy_stream:reason(), #st{}) -> ok.
terminate(_StreamId, _Reason, #st{handler = Handler, timer = Timer}) ->
    cancel_timer(Timer),
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
    St0 = #st{max_message = maps:get(max_message_bytes, Limits, ?YUZU_GRPC_MAX_MESSAGE_BYTES)},
    case authenticate(maps:get(auth_fun, Env, undefined), maps:get(cert, Req, undefined)) of
        false ->
            reject(St0, ?GRPC_STATUS_UNAUTHENTICATED, <<"unauthenticated">>);
        true ->
            admitted(StreamId, Req, Env, St0)
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
            {[], St1#st{phase = awaiting_request}};
        {_, false} ->
            reject(St1, ?GRPC_STATUS_INTERNAL, <<"missing request message">>)
    end.

%% The address the call is attributed to (yuzu_grpc_origin). A claim that was
%% ignored is counted by mode and reason only: the address is never logged or
%% put in a metric label.
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

arm_deadline(_StreamId, infinity) ->
    undefined;
arm_deadline(StreamId, {ok, Ms}) ->
    Conn = self(),
    erlang:send_after(Ms, Conn, {{Conn, StreamId}, grpc_deadline}).

spawn_runner(#{kind := Kind, module := Module, function := Function}, Stream, Extra) ->
    proc_lib:spawn_link(yuzu_grpc_runner, run,
                        [Extra#{kind => Kind, module => Module, function => Function,
                                stream => Stream}]).

%%--------------------------------------------------------------------
%% Request DATA
%%--------------------------------------------------------------------

on_data(IsFin, Data, #st{phase = awaiting_request, buf = Buf0, max_message = Max} = St) ->
    Size = byte_size(Data),
    case yuzu_grpc_frame:decode(<<Buf0/binary, Data/binary>>, Max) of
        {ok, Message, Rest} ->
            case decode_request(St, Message) of
                {ok, Request} ->
                    Pid = spawn_runner(St#st.route, St#st.stream, #{request => Request}),
                    dropped(byte_size(Rest), St, extra_request_data),
                    {[{spawn, Pid, ?SHUTDOWN_MS} | credit(Size)],
                     St#st{phase = running_single, handler = Pid, buf = <<>>}};
                error ->
                    abort(St, ?GRPC_STATUS_INTERNAL, <<"invalid request message">>)
            end;
        {more, _} when IsFin =:= fin ->
            abort(St, ?GRPC_STATUS_INTERNAL, <<"incomplete request message">>);
        {more, Buf} ->
            {credit(Size), St#st{buf = Buf}};
        {error, {Status, Message}} ->
            abort(St, Status, Message)
    end;
on_data(IsFin, Data, #st{phase = running, buf = Buf0, max_message = Max,
                         handler = Handler, ref = Ref} = St) ->
    case deliver(<<Buf0/binary, Data/binary>>, Max, St) of
        {ok, Buf} when IsFin =:= fin, Buf =/= <<>> ->
            abort(St, ?GRPC_STATUS_INTERNAL, <<"incomplete request message">>);
        {ok, Buf} ->
            case IsFin of
                fin -> Handler ! {Ref, eos};
                nofin -> ok
            end,
            {credit(byte_size(Data)), St#st{buf = Buf}};
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

%% Hand every complete message of the buffer to the handler; what is left is an
%% incomplete frame.
deliver(Buf, Max, #st{handler = Handler, ref = Ref} = St) ->
    case yuzu_grpc_frame:decode(Buf, Max) of
        {ok, Message, Rest} ->
            case decode_request(St, Message) of
                {ok, Request} ->
                    Handler ! {Ref, Request},
                    deliver(Rest, Max, St);
                error ->
                    {error, ?GRPC_STATUS_INTERNAL, <<"invalid request message">>}
            end;
        {more, Rest} ->
            {ok, Rest};
        {error, {Status, Message}} ->
            {error, Status, Message}
    end.

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
finish(#st{headers_sent = Sent, timer = Timer} = St, Status, Message, After) ->
    cancel_timer(Timer),
    Trailers = yuzu_grpc_frame:trailers(Status, Message),
    Commands = case Sent of
        true -> [{trailers, Trailers}];
        false -> [{response, 200, trailers_only(Trailers), <<>>}]
    end,
    {Commands ++ After, nack_senders(St#st{phase = ended, timer = undefined})}.

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
