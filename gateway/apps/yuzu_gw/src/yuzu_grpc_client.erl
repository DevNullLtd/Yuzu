%%%-------------------------------------------------------------------
%%% @doc The gateway's unary gRPC client: one request, one response, over an
%%% HTTP/2 connection of a channel (yuzu_grpc_client_channel, gun).
%%%
%%% It returns the shapes the gateway's upstream code was written against, so
%%% the callers keep their clauses:
%%%   {ok, Response, #{headers => H, trailers => T}}
%%%   {error, {Status, Message}, #{headers => H, trailers => T}}
%%%       a gRPC status other than OK; Status is the `grpc-status' trailer, a
%%%       decimal binary (<<"9">>, never an atom), Message its decoded text
%%%   {http_error, {HttpStatus, <<>>}, #{headers => H, trailers => #{}}}
%%%       a response that is not HTTP 200, so not from the gRPC layer
%%%   {error, Reason}
%%%       the call did not complete: `timeout' (the whole call, waiting for a
%%%       connection included), a connection error word (`econnrefused',
%%%       `closed', `{tls_alert, Alert}', `{options, tls}'), `no_channel',
%%%       `stream_error' or `connection_error' (the connection reset or refused
%%%       the stream, or went away mid-call), `response_too_large' (over the
%%%       channel's limit), `invalid_metadata' (a refused request header; nothing
%%%       was sent) or `protocol' (gun sent something this client does not read)
%%% Marshalling runs in the caller: a request that cannot be encoded raises
%%% here, and the caller decides what that means.
%%%
%%% Only identity encoding exists (yuzu_grpc_frame refuses a compressed
%%% message), and the response is bounded while it is read: a server that sends
%%% more than the channel's `max_receive_message_bytes' fails the call as soon as
%%% the limit is passed, instead of being buffered first.
%%%
%%% Nothing here logs a request, a header or a reason term.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client).

%% How long the barrier after a cancel waits for the connection to answer.
-define(BARRIER_MS, 500).

-export([unary/5]).
-export([metadata_headers/1]).
-export_type([def/0, result/0]).

-define(DEFAULT_TIMEOUT_MS, 5000).
-define(USER_AGENT, <<"yuzu-gw/0.2 (gun)">>).

-type def() :: #{marshal := fun((term()) -> iodata()),
                 unmarshal := fun((binary()) -> term())}.
-type meta() :: #{headers := #{binary() => binary()}, trailers := #{binary() => binary()}}.
-type result() :: {ok, term(), meta()}
                | {error, {binary(), binary()}, meta()}
                | {http_error, {binary(), binary()}, meta()}
                | {error, term()}.

%% @doc One unary call. `Metadata' is sent as request headers (lowercase
%% names; see metadata_headers/1 for what is refused). Options: `channel'
%% (default `default_channel'), `timeout' in ms for the whole call, connection
%% wait included (default 5000); what is left of it when the request goes out
%% is sent as the `grpc-timeout' header.
-spec unary(map(), binary(), term(), def(), map()) -> result().
unary(Metadata, Path, Request, #{marshal := Marshal, unmarshal := Unmarshal}, Options)
  when is_map(Metadata), is_binary(Path), is_map(Options) ->
    Channel = maps:get(channel, Options, default_channel),
    Timeout = maps:get(timeout, Options, ?DEFAULT_TIMEOUT_MS),
    Deadline = erlang:monotonic_time(millisecond) + Timeout,
    case metadata_headers(Metadata) of
        {error, _} = Error ->
            Error;
        {ok, Extra} ->
            Body = yuzu_grpc_frame:encode(Marshal(Request)),
            case yuzu_grpc_client_channel:pick(Channel, remaining(Deadline)) of
                {ok, Conn} ->
                    Max = yuzu_grpc_client_channel:max_receive(Channel),
                    call(Conn, Path, Extra, Body, Unmarshal, Max, Deadline);
                {error, _} = Error ->
                    Error
            end
    end.

%% @doc Request headers for a metadata map. A key that is not a lowercase
%% token, a value with a control character, and the names the protocol owns
%% (pseudo-headers, content-type, te, user-agent, host, content-length, anything
%% `grpc-') are refused: metadata is data from the caller, not a way to reshape
%% the request.
-spec metadata_headers(map()) -> {ok, [{binary(), binary()}]} | {error, invalid_metadata}.
metadata_headers(Metadata) ->
    try {ok, [header(K, V) || {K, V} <- lists:sort(maps:to_list(Metadata))]}
    catch throw:invalid -> {error, invalid_metadata}
    end.

header(Key, Value) when is_binary(Key), is_binary(Value) ->
    case valid_key(Key) andalso not reserved(Key) andalso valid_value(Value) of
        true  -> {Key, Value};
        false -> throw(invalid)
    end;
header(_, _) ->
    throw(invalid).

valid_key(<<>>) -> false;
valid_key(Key)  -> lists:all(fun(C) -> (C >= $a andalso C =< $z) orelse (C >= $0 andalso C =< $9)
                                      orelse C =:= $- orelse C =:= $_ orelse C =:= $. end,
                             binary_to_list(Key)).

valid_value(Value) -> not lists:any(fun(C) -> C < 16#20 orelse C =:= 16#7F end,
                                    binary_to_list(Value)).

reserved(<<"grpc-", _/binary>>) -> true;
reserved(Key) -> lists:member(Key, [<<"content-type">>, <<"te">>, <<"user-agent">>,
                                    <<"host">>, <<"content-length">>, <<"connection">>,
                                    <<"transfer-encoding">>, <<"upgrade">>]).

%%--------------------------------------------------------------------
%% The call
%%--------------------------------------------------------------------

call(Conn, Path, Extra, Body, Unmarshal, Max, Deadline) ->
    %% What is left of the call's timeout goes to the server as grpc-timeout, so
    %% it can stop working on a call this client no longer waits for.
    Headers = [{<<"content-type">>, <<"application/grpc">>},
               {<<"te">>, <<"trailers">>},
               {<<"user-agent">>, ?USER_AGENT},
               {<<"grpc-timeout">>, timeout_header(remaining(Deadline))}
               | Extra],
    Ref = gun:post(Conn, Path, Headers, Body, #{reply_to => self()}),
    case response(Conn, Ref, Deadline) of
        {response, Fin, Status, RespHeaders} ->
            case Status of
                200 -> grpc(Conn, Ref, Fin, RespHeaders, Unmarshal, Max, Deadline);
                _   -> finish_http_error(Conn, Ref, Fin, Max, Deadline),
                       {http_error, {integer_to_binary(Status), <<>>},
                        #{headers => to_map(RespHeaders), trailers => #{}}}
            end;
        {error, Reason} = Error ->
            end_stream(Conn, Ref, Reason),
            Error
    end.

%% The response head, skipping informational (1xx) responses.
response(Conn, Ref, Deadline) ->
    case gun:await(Conn, Ref, remaining(Deadline)) of
        {inform, _Status, _Headers} -> response(Conn, Ref, Deadline);
        {response, _, _, _} = R     -> R;
        {error, Reason}             -> {error, transport(Reason)};
        _Other                      -> {error, protocol}
    end.

grpc(_Conn, _Ref, fin, Headers, _Unmarshal, _Max, _Deadline) ->
    %% Trailers-only response: one HEADERS frame ends the stream, so what it
    %% carries are the trailers (the status among them) and there is no body.
    HeaderMap = to_map(Headers),
    status(<<>>, HeaderMap, HeaderMap, undefined);
grpc(Conn, Ref, nofin, Headers, Unmarshal, Max, Deadline) ->
    case body(Conn, Ref, <<>>, Max, Deadline) of
        {ok, Data, Trailers} -> status(Data, to_map(Headers), Trailers, Unmarshal);
        {error, Reason} = Error -> end_stream(Conn, Ref, Reason), Error
    end.

%% Read the body to its end, refusing more than Max bytes plus the frame header.
body(Conn, Ref, Acc, Max, Deadline) ->
    case gun:await(Conn, Ref, remaining(Deadline)) of
        {data, IsFin, Data} ->
            Acc1 = <<Acc/binary, Data/binary>>,
            case byte_size(Acc1) > Max + 5 of
                true  -> {error, response_too_large};
                false -> case IsFin of
                             fin   -> {ok, Acc1, #{}};
                             nofin -> body(Conn, Ref, Acc1, Max, Deadline)
                         end
            end;
        {trailers, Trailers} ->
            {ok, Acc, to_map(Trailers)};
        {error, Reason} ->
            {error, transport(Reason)};
        _Other ->
            {error, protocol}
    end.

%% The status is a trailer; a trailers-only response carries it in the headers.
status(Data, HeaderMap, Trailers, Unmarshal) ->
    Meta = #{headers => HeaderMap, trailers => Trailers},
    Fields = maps:merge(HeaderMap, Trailers),
    case maps:get(<<"grpc-status">>, Fields, undefined) of
        <<"0">> ->
            message(Data, Meta, Unmarshal);
        undefined ->
            {error, {<<"2">>, <<"missing grpc-status">>}, Meta};
        Status ->
            {error, {Status, yuzu_grpc_frame:decode_message(
                               maps:get(<<"grpc-message">>, Fields, <<>>))}, Meta}
    end.

message(<<>>, Meta, _Unmarshal) ->
    {ok, <<>>, Meta};
message(Data, Meta, Unmarshal) ->
    case yuzu_grpc_frame:decode(Data, 1 bsl 30) of
        {ok, Message, <<>>} ->
            try {ok, Unmarshal(Message), Meta}
            catch _:_ -> {error, {<<"13">>, <<"undecodable response">>}, Meta}
            end;
        {ok, _Message, _More} ->
            {error, {<<"13">>, <<"more than one message in a unary response">>}, Meta};
        {more, _} ->
            {error, {<<"13">>, <<"truncated response message">>}, Meta};
        {error, {_Status, _Text}} ->
            {error, {<<"13">>, <<"invalid response message">>}, Meta}
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

remaining(Deadline) ->
    max(0, Deadline - erlang:monotonic_time(millisecond)).

%% A grpc-timeout value: at most eight digits, so milliseconds up to 99999999
%% (about 27 hours) and seconds beyond. At least 1 ms.
timeout_header(Ms) when Ms =< 99999999 -> <<(integer_to_binary(max(1, Ms)))/binary, "m">>;
timeout_header(Ms) -> <<(integer_to_binary(min(99999999, Ms div 1000)))/binary, "S">>.

to_map(Headers) ->
    maps:from_list([{K, V} || {K, V} <- Headers, is_binary(K), is_binary(V),
                              not (byte_size(K) > 0 andalso binary:first(K) =:= $:)]).

%% A non-200 response (a proxy's 502, say) may carry a body. Reading it to the end
%% lets gun finish the stream on its own; cancelling a stream gun is already
%% finishing makes gun answer with a `badstate' message that lands in the
%% caller's mailbox. The read is bounded like any response body: by the call's
%% deadline (each wait is for what is left of it, so the total cannot exceed it)
%% and by the same byte limit, and past either the stream is abandoned.
finish_http_error(_Conn, _Ref, fin, _Max, _Deadline) ->
    ok;
finish_http_error(Conn, Ref, nofin, Max, Deadline) ->
    drain(Conn, Ref, 0, Max, Deadline).

drain(Conn, Ref, Seen, Max, Deadline) ->
    case gun:await(Conn, Ref, remaining(Deadline)) of
        {data, fin, _}      -> ok;
        {data, nofin, Data} ->
            Seen1 = Seen + byte_size(Data),
            case Seen1 > Max + 5 of
                true  -> end_stream(Conn, Ref, response_too_large);
                false -> drain(Conn, Ref, Seen1, Max, Deadline)
            end;
        {trailers, _}       -> ok;
        {error, Reason}     -> end_stream(Conn, Ref, transport(Reason));
        _Other              -> end_stream(Conn, Ref, protocol)
    end.

%% End a stream we are no longer reading and drop what it already delivered.
abandon(Conn, Ref) ->
    catch gun:cancel(Conn, Ref),
    %% gun may already have sent more of the stream before it handles the cancel.
    %% A call to the connection is answered only after the cancel is handled, and
    %% a message gun sent earlier reaches us before that answer, so the flush
    %% below sees all of them.
    catch sys:get_state(Conn, ?BARRIER_MS),
    catch gun:flush(Ref),
    ok.

%% The stream after a failure. It is cancelled only when it may still be alive:
%% the call timed out, the response was over the limit, or gun sent something
%% this client does not understand. When gun itself reported the stream gone (a
%% reset, a refused stream, a GOAWAY, a closed connection) it has already removed
%% it, and cancelling a stream gun does not have makes gun answer with a
%% `badstate' error message that lands in the caller's mailbox, which the
%% gen_servers above swallow in a catch-all, but only by luck.
end_stream(Conn, Ref, Reason)
  when Reason =:= timeout; Reason =:= response_too_large; Reason =:= protocol ->
    abandon(Conn, Ref);
end_stream(_Conn, Ref, _Reason) ->
    catch gun:flush(Ref),
    ok.

%% A transport failure as a short term: the connection's own reason where it
%% is a plain word (the channel's `compact/1' classification), never a term
%% that could carry request data.
transport(timeout) -> timeout;
transport({stream_error, _}) -> stream_error;
transport({connection_error, _}) -> connection_error;
transport(Reason) -> yuzu_grpc_client_channel:compact(Reason).
