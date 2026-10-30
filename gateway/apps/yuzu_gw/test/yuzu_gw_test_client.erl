%%%-------------------------------------------------------------------
%%% @doc A gRPC client for TESTS: unary, server-streaming and bidirectional
%%% calls over a channel (yuzu_grpc_client_channel), with the call shapes the
%%% gateway's wire tests were written against (grpcbox_client's `unary',
%%% `stream', `send', `close_send', `recv_data', `recv_trailers').
%%%
%%% Production has only the unary client (yuzu_grpc_client): the gateway makes
%%% no streaming call to the server. The listener side of the gateway serves
%%% streams (the agent `Subscribe', the management `SendCommand'), and the wire
%%% tests need something that opens one. That is this module, kept out of the
%%% release on purpose.
%%%
%%% It shares `yuzu_grpc_frame' (the length-prefixed message codec) with the
%%% server it tests, and gun with the production client; it does NOT share the
%%% HTTP/2 stack with the listener (cowboy), so a framing-level disagreement in
%%% the listener still shows. The real interop against a C++ gRPC peer is the
%%% live rig, not this module.
%%%
%%% A context is a `ctx' as before: a deadline set with
%%% `ctx:with_deadline_after/3' is sent as `grpc-timeout' (the listener enforces
%%% it) and metadata is added with `with_metadata/2'.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_test_client).

-export([with_metadata/2]).
-export([unary/5, stream/4, stream/5]).
-export([send/2, close_send/1, recv_data/2, recv_trailers/2, recv_headers/2, cancel/1]).
%% the stream process
-export([stream_init/1]).

-define(META_KEY, yuzu_test_metadata).
-define(MAX_MESSAGE, 64 * 1024 * 1024).
-define(PICK_TIMEOUT_MS, 5000).

-type def() :: yuzu_grpc_client:def().
-type stream() :: pid().
-export_type([stream/0]).

%%--------------------------------------------------------------------
%% Context
%%--------------------------------------------------------------------

%% @doc Outgoing request metadata, added to what the context already has.
-spec with_metadata(ctx:t(), #{binary() => binary()}) -> ctx:t().
with_metadata(Ctx, Metadata) ->
    ctx:set(Ctx, ?META_KEY, maps:merge(ctx:get(Ctx, ?META_KEY, #{}), Metadata)).

metadata(Ctx) -> ctx:get(Ctx, ?META_KEY, #{}).

%% Milliseconds left on the context's deadline, or `infinity'.
remaining_ms(Ctx) ->
    case ctx:deadline(Ctx) of
        undefined -> infinity;
        infinity -> infinity;
        {Deadline, _} ->
            max(0, erlang:convert_time_unit(Deadline - erlang:monotonic_time(),
                                            native, millisecond))
    end.

%%--------------------------------------------------------------------
%% Unary
%%--------------------------------------------------------------------

%% @doc yuzu_grpc_client:unary/5 with the context's metadata and deadline.
-spec unary(ctx:t(), binary(), term(), def(), map()) -> yuzu_grpc_client:result().
unary(Ctx, Path, Input, Def, Options) ->
    Options1 = case remaining_ms(Ctx) of
                   infinity -> Options;
                   Ms -> Options#{timeout => Ms}
               end,
    yuzu_grpc_client:unary(metadata(Ctx), Path, Input, Def, Options1).

%%--------------------------------------------------------------------
%% Streams
%%--------------------------------------------------------------------

%% @doc Open a stream with no first message (bidirectional, or a client stream).
-spec stream(ctx:t(), binary(), def(), map()) -> {ok, stream()} | {error, term()}.
stream(Ctx, Path, Def, Options) ->
    Channel = maps:get(channel, Options, default_channel),
    case yuzu_grpc_client_channel:pick(Channel, ?PICK_TIMEOUT_MS) of
        {ok, Conn} ->
            Owner = self(),
            Pid = spawn_link(?MODULE, stream_init, [#{owner => Owner, conn => Conn, path => Path,
                                                      def => Def, ctx => Ctx}]),
            receive
                {Pid, opened} -> {ok, Pid};
                {Pid, {open_failed, Reason}} -> {error, Reason}
            after ?PICK_TIMEOUT_MS -> {error, timeout}
            end;
        {error, _} = Error ->
            Error
    end.

%% @doc Open a stream, send one message and half-close: a server-streaming call.
-spec stream(ctx:t(), binary(), term(), def(), map()) -> {ok, stream()} | {error, term()}.
stream(Ctx, Path, Input, Def, Options) ->
    case stream(Ctx, Path, Def, Options) of
        {ok, S} ->
            ok = send(S, Input),
            ok = close_send(S),
            {ok, S};
        {error, _} = Error ->
            Error
    end.

-spec send(stream(), term()) -> ok | {error, term()}.
send(S, Message) -> call(S, {send, Message}).

-spec close_send(stream()) -> ok | {error, term()}.
close_send(S) -> call(S, close_send).

%% @doc The next message, `stream_finished' when the stream has ended with none
%% left (its status is then in recv_trailers/2), or `timeout'.
-spec recv_data(stream(), timeout()) -> {ok, term()} | stream_finished | timeout | {error, term()}.
recv_data(S, Timeout) -> call(S, {recv_data, Timeout}, Timeout).

%% @doc The status of the stream once it has ended: `{ok, {Status, Message,
%% Trailers}}' with Status a decimal binary, or `timeout'.
-spec recv_trailers(stream(), timeout()) -> {ok, {binary(), binary(), map()}} | timeout | {error, term()}.
recv_trailers(S, Timeout) -> call(S, {recv_trailers, Timeout}, Timeout).

%% @doc The response headers, once they have arrived.
-spec recv_headers(stream(), timeout()) -> {ok, map()} | timeout | {error, term()}.
recv_headers(S, Timeout) -> call(S, {recv_headers, Timeout}, Timeout).

%% @doc Reset the stream.
-spec cancel(stream()) -> ok.
cancel(S) -> S ! cancel, ok.

call(S, Request) -> call(S, Request, 5000).

call(S, Request, Timeout) ->
    Ref = erlang:monitor(process, S),
    S ! {call, {self(), Ref}, Request},
    Wait = case Timeout of infinity -> infinity; T -> T + 2000 end,
    receive
        {Ref, Reply} -> erlang:demonitor(Ref, [flush]), Reply;
        {'DOWN', Ref, process, S, _} -> {error, closed}
    after Wait ->
        erlang:demonitor(Ref, [flush]),
        timeout
    end.

%%--------------------------------------------------------------------
%% The stream process: the owner of the gun stream and the reply_to of its
%% messages, so a caller reads with plain calls and never selective-receives
%% gun messages itself.
%%--------------------------------------------------------------------

-record(s, {conn, ref, marshal, unmarshal,
            buf = <<>>, msgs = queue:new(), headers, trailers, status,
            ended = false, sent_fin = false, waiters = []}).

stream_init(#{owner := Owner, conn := Conn, path := Path, def := Def, ctx := Ctx}) ->
    process_flag(trap_exit, true),
    Headers = [{<<"content-type">>, <<"application/grpc">>},
               {<<"te">>, <<"trailers">>}
               | [{K, V} || {K, V} <- maps:to_list(metadata(Ctx))]]
              ++ case remaining_ms(Ctx) of
                     infinity -> [];
                     Ms -> [{<<"grpc-timeout">>, <<(integer_to_binary(Ms))/binary, "m">>}]
                 end,
    Ref = gun:post(Conn, Path, Headers, #{reply_to => self()}),
    erlang:monitor(process, Conn),
    Owner ! {self(), opened},
    loop(#s{conn = Conn, ref = Ref,
            marshal = maps:get(marshal, Def), unmarshal = maps:get(unmarshal, Def)},
         Owner).

loop(S, Owner) ->
    receive
        {call, From, Request} ->
            loop(handle_call(Request, From, S), Owner);
        cancel ->
            catch gun:cancel(S#s.conn, S#s.ref),
            ok;
        {gun_response, _, Ref, IsFin, Status, Headers} when Ref =:= S#s.ref ->
            loop(on_response(IsFin, Status, Headers, S), Owner);
        {gun_data, _, Ref, IsFin, Data} when Ref =:= S#s.ref ->
            loop(on_data(IsFin, Data, S), Owner);
        {gun_trailers, _, Ref, Trailers} when Ref =:= S#s.ref ->
            loop(on_trailers(Trailers, S), Owner);
        %% A reset or a closed connection AFTER the stream ended (the server may send
        %% RST_STREAM(NO_ERROR) once a complete reply is out and the client keeps
        %% sending) is not the stream's status: the trailers already told it.
        {gun_error, _, Ref, _Reason} when Ref =:= S#s.ref, S#s.ended ->
            loop(S, Owner);
        {gun_error, _, Ref, Reason} when Ref =:= S#s.ref ->
            loop(finish(S#s{status = {error, Reason}}), Owner);
        {'DOWN', _, process, Conn, _Reason} when Conn =:= S#s.conn, S#s.ended ->
            loop(S, Owner);
        {'DOWN', _, process, Conn, Reason} when Conn =:= S#s.conn ->
            loop(finish(S#s{status = {error, down_word(Reason)}}), Owner);
        {waiter_timeout, {From, Request} = W} ->
            case lists:member(W, S#s.waiters) of
                true ->
                    reply(From, timeout_reply(Request)),
                    loop(S#s{waiters = lists:delete(W, S#s.waiters)}, Owner);
                false ->
                    loop(S, Owner)
            end;
        {'EXIT', Owner, _} ->
            catch gun:cancel(S#s.conn, S#s.ref),
            ok;
        _Other ->
            loop(S, Owner)
    end.

down_word(Reason) -> yuzu_grpc_client_channel:compact(Reason).

timeout_reply(_Request) -> timeout.

handle_call({send, _}, From, #s{sent_fin = true} = S) ->
    reply(From, {error, closed}), S;
handle_call({send, Message}, From, #s{conn = Conn, ref = Ref, marshal = Marshal} = S) ->
    ok = gun:data(Conn, Ref, nofin, yuzu_grpc_frame:encode(Marshal(Message))),
    reply(From, ok), S;
handle_call(close_send, From, #s{sent_fin = true} = S) ->
    reply(From, ok), S;
handle_call(close_send, From, #s{conn = Conn, ref = Ref} = S) ->
    ok = gun:data(Conn, Ref, fin, <<>>),
    reply(From, ok), S#s{sent_fin = true};
handle_call(Request, From, S) ->
    %% recv_*: answer now if possible, else park the caller until the data
    %% arrives or its timeout fires.
    Waiter = {From, Request},
    S1 = S#s{waiters = S#s.waiters ++ [Waiter]},
    case Request of
        {recv_data, Timeout} -> arm(Waiter, Timeout);
        {recv_trailers, Timeout} -> arm(Waiter, Timeout);
        {recv_headers, Timeout} -> arm(Waiter, Timeout)
    end,
    serve(S1).

arm(Waiter, infinity) -> _ = Waiter, ok;
arm(Waiter, Timeout) -> erlang:send_after(Timeout, self(), {waiter_timeout, Waiter}).

%% Answer every parked caller that can be answered.
serve(#s{waiters = Waiters} = S) ->
    lists:foldl(fun(W, Acc) -> serve_one(W, Acc) end, S#s{waiters = []}, Waiters).

serve_one({From, {recv_data, _}} = W, S) ->
    case queue:out(S#s.msgs) of
        {{value, Msg}, Rest} -> reply(From, {ok, Msg}), S#s{msgs = Rest};
        {empty, _} when S#s.ended -> reply(From, stream_finished), S;
        {empty, _} -> park(W, S)
    end;
serve_one({From, {recv_trailers, _}} = W, S) ->
    case S#s.ended of
        true -> reply(From, trailers_reply(S)), S;
        false -> park(W, S)
    end;
serve_one({From, {recv_headers, _}} = W, S) ->
    case S#s.headers of
        undefined -> park(W, S);
        H -> reply(From, {ok, H}), S
    end.

park(W, S) -> S#s{waiters = S#s.waiters ++ [W]}.

trailers_reply(#s{status = {error, Reason}}) -> {error, Reason};
trailers_reply(#s{status = {Status, Message, Trailers}}) -> {ok, {Status, Message, Trailers}};
trailers_reply(#s{trailers = undefined, headers = H}) -> status_from(H);
trailers_reply(#s{trailers = T}) -> status_from(T).

status_from(Fields) ->
    {ok, {maps:get(<<"grpc-status">>, Fields, <<"2">>),
          yuzu_grpc_frame:decode_message(maps:get(<<"grpc-message">>, Fields, <<>>)),
          Fields}}.

on_response(IsFin, 200, Headers, S) ->
    S1 = S#s{headers = to_map(Headers)},
    case IsFin of
        fin -> finish(S1#s{trailers = to_map(Headers)});
        nofin -> serve(S1)
    end;
on_response(_IsFin, Status, Headers, S) ->
    finish(S#s{headers = to_map(Headers),
               status = {integer_to_binary(Status), <<>>, #{}}}).

on_data(IsFin, Data, #s{buf = Buf, msgs = Msgs, unmarshal = Unmarshal} = S) ->
    {Buf1, Msgs1} = frames(<<Buf/binary, Data/binary>>, Msgs, Unmarshal),
    S1 = S#s{buf = Buf1, msgs = Msgs1},
    case IsFin of
        fin -> finish(S1);
        nofin -> serve(S1)
    end.

frames(Buf, Msgs, Unmarshal) ->
    case yuzu_grpc_frame:decode(Buf, ?MAX_MESSAGE) of
        {ok, Message, Rest} -> frames(Rest, queue:in(Unmarshal(Message), Msgs), Unmarshal);
        {more, Buf1} -> {Buf1, Msgs};
        {error, _} -> {<<>>, Msgs}
    end.

on_trailers(Trailers, S) ->
    finish(S#s{trailers = to_map(Trailers)}).

finish(S) ->
    serve(S#s{ended = true}).

reply({Pid, Ref}, Reply) -> Pid ! {Ref, Reply}, ok.

to_map(Headers) ->
    maps:from_list([{K, V} || {K, V} <- Headers, is_binary(K), is_binary(V)]).
