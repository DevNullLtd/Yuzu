%%%-------------------------------------------------------------------
%%% @doc gRPC wire details that need no process: the length-prefixed message
%%% frame, the `grpc-timeout' header, the percent-encoding of `grpc-message'
%%% and the status helpers. Pure; the one place these rules live.
%%%
%%% Only the identity encoding exists: a frame with the compressed flag set is
%%% refused (UNIMPLEMENTED), because the layer never advertises another
%%% encoding.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_frame).

-export([encode/1, decode/2]).
-export([parse_timeout/1]).
-export([encode_message/1, decode_message/1, normalize_message/1]).
-export([status_to_binary/1, normalize_status/1, trailers/2]).

-export_type([status/0, error/0]).

-type status() :: 0..16.
-type error() :: {status(), binary()}.

%% The longest grpc-message the layer sends, before percent-encoding. A handler
%% that formats a large term into its message must not blow the peer's header
%% limit.
-define(MAX_MESSAGE_BYTES, 1024).
%% erlang:send_after/3 rejects anything above this.
-define(MAX_TIMER_MS, 4294967295).

%%--------------------------------------------------------------------
%% Length-prefixed messages
%%--------------------------------------------------------------------

%% @doc One message as a frame: flag 0 (uncompressed), a 4-byte big-endian
%% length, the message.
-spec encode(iodata()) -> binary().
encode(Message) ->
    Bin = iolist_to_binary(Message),
    <<0, (byte_size(Bin)):32, Bin/binary>>.

%% @doc The first frame of Buffer. The caller appends each received chunk to the
%% rest it was given and calls again; `{more, Buffer}' hands the buffer back.
%% A frame whose declared length is over Max is refused as soon as its header is
%% seen, before any of its body is buffered.
-spec decode(binary(), pos_integer()) ->
    {ok, binary(), binary()} | {more, binary()} | {error, error()}.
decode(<<1, _/binary>>, _Max) ->
    {error, {12, <<"compressed messages are not supported">>}};
decode(<<Flag, _/binary>>, _Max) when Flag =/= 0 ->
    {error, {13, <<"invalid message flag">>}};
decode(<<0, Len:32, _/binary>>, Max) when Len > Max ->
    {error, {8, <<"message too large">>}};
decode(<<0, Len:32, Body/binary>>, _Max) when byte_size(Body) >= Len ->
    <<Message:Len/binary, Rest/binary>> = Body,
    {ok, Message, Rest};
decode(Buffer, _Max) ->
    {more, Buffer}.

%%--------------------------------------------------------------------
%% grpc-timeout
%%--------------------------------------------------------------------

%% @doc The deadline a `grpc-timeout' header value asks for, in milliseconds:
%% 1 to 8 digits and one unit (H M S m u n). Units finer than a millisecond
%% round up, so a deadline is never earlier than asked; a value too large for
%% a timer is clamped to the largest timer. `undefined' (no header) is
%% `infinity'.
-spec parse_timeout(binary() | undefined) ->
    infinity | {ok, non_neg_integer()} | {error, invalid}.
parse_timeout(undefined) ->
    infinity;
parse_timeout(Value) when is_binary(Value), byte_size(Value) >= 2, byte_size(Value) =< 9 ->
    Digits = byte_size(Value) - 1,
    <<N:Digits/binary, Unit>> = Value,
    case is_digits(N) andalso lists:member(Unit, "HMSmun") of
        true -> {ok, min(to_ms(binary_to_integer(N), Unit), ?MAX_TIMER_MS)};
        false -> {error, invalid}
    end;
parse_timeout(_) ->
    {error, invalid}.

to_ms(N, $H) -> N * 3600000;
to_ms(N, $M) -> N * 60000;
to_ms(N, $S) -> N * 1000;
to_ms(N, $m) -> N;
to_ms(N, $u) -> (N + 999) div 1000;
to_ms(N, $n) -> (N + 999999) div 1000000.

is_digits(<<>>) -> false;
is_digits(Bin) -> lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Bin)).

%%--------------------------------------------------------------------
%% grpc-message
%%--------------------------------------------------------------------

%% @doc Percent-encode a status message: every byte outside printable ASCII,
%% and `%' itself, becomes %XX.
-spec encode_message(binary()) -> binary().
encode_message(Message) ->
    << <<(encode_byte(B))/binary>> || <<B>> <= Message >>.

encode_byte($%) -> <<"%25">>;
encode_byte(B) when B >= 16#20, B =< 16#7E -> <<B>>;
encode_byte(B) -> <<$%, (hex(B bsr 4)), (hex(B band 16#F))>>.

hex(N) when N < 10 -> $0 + N;
hex(N) -> $A + N - 10.

%% @doc The inverse of encode_message/1. A malformed escape is kept as it came.
-spec decode_message(binary()) -> binary().
decode_message(Message) ->
    unescape(Message, <<>>).

unescape(<<$%, H, L, Rest/binary>>, Acc) ->
    case {unhex(H), unhex(L)} of
        {{ok, Hi}, {ok, Lo}} -> unescape(Rest, <<Acc/binary, (Hi * 16 + Lo)>>);
        _ -> unescape(<<H, L, Rest/binary>>, <<Acc/binary, $%>>)
    end;
unescape(<<B, Rest/binary>>, Acc) ->
    unescape(Rest, <<Acc/binary, B>>);
unescape(<<>>, Acc) ->
    Acc.

unhex(C) when C >= $0, C =< $9 -> {ok, C - $0};
unhex(C) when C >= $A, C =< $F -> {ok, C - $A + 10};
unhex(C) when C >= $a, C =< $f -> {ok, C - $a + 10};
unhex(_) -> error.

%% @doc A handler's status message as a binary of bounded size. Anything that is
%% not text becomes the empty message rather than failing the status that
%% carries it.
-spec normalize_message(term()) -> binary().
normalize_message(Message) when is_binary(Message) ->
    binary:part(Message, 0, min(byte_size(Message), ?MAX_MESSAGE_BYTES));
normalize_message(Message) ->
    try unicode:characters_to_binary(Message) of
        Bin when is_binary(Bin) -> normalize_message(Bin);
        _ -> <<>>
    catch
        _:_ -> <<>>
    end.

%%--------------------------------------------------------------------
%% Status
%%--------------------------------------------------------------------

-spec status_to_binary(status()) -> binary().
status_to_binary(Status) ->
    integer_to_binary(Status).

%% @doc The integer status of what a handler returned: 0..16 or its decimal
%% binary. Anything else is a handler bug and reads as INTERNAL.
-spec normalize_status(term()) -> status().
normalize_status(Status) when is_integer(Status), Status >= 0, Status =< 16 ->
    Status;
normalize_status(Status) when is_binary(Status), byte_size(Status) =< 2 ->
    try binary_to_integer(Status) of
        N when N >= 0, N =< 16 -> N;
        _ -> 13
    catch
        _:_ -> 13
    end;
normalize_status(_) ->
    13.

%% @doc The trailer fields of a status. An empty message is left out.
-spec trailers(status(), binary()) -> #{binary() => binary()}.
trailers(Status, <<>>) ->
    #{<<"grpc-status">> => status_to_binary(Status)};
trailers(Status, Message) ->
    #{<<"grpc-status">> => status_to_binary(Status),
      <<"grpc-message">> => encode_message(Message)}.
