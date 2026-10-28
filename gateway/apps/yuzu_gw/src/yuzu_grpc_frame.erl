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
-export([reader/0, read/3, reader_bytes/1]).
-export([parse_timeout/1]).
-export([encode_message/1, decode_message/1, normalize_message/1]).
-export([status_to_binary/1, normalize_status/1, trailers/2]).

-export_type([status/0, error/0, reader/0]).

-type status() :: 0..16.
-type error() :: {status(), binary()}.
%% An incremental frame reader (read/3): the start of a header (fewer than five
%% bytes), or the body of a frame whose header was read, as the number of bytes
%% still missing and the chunks received so far, most recent first.
-opaque reader() :: {header, binary()}
                  | {body, pos_integer(), [binary()]}.

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

%% @doc A reader with nothing buffered. read/3 feeds it.
-spec reader() -> reader().
reader() ->
    {header, <<>>}.

%% @doc decode/2 for a message that arrives in many chunks, without copying it
%% over and over. decode/2 needs the buffer as ONE binary, so a caller that
%% appends each chunk to the last buffer copies the whole buffer at every chunk
%% (matching a binary makes it read-only, so the next append cannot grow it in
%% place): a 4 MiB message in 16 KiB DATA frames is about 512 MiB of copies, all
%% of it garbage the receiving process holds until it next collects. Counted by
%% the per-connection memory ceiling (a max_heap_size that includes shared
%% binaries, see yuzu_grpc_stream_h), that garbage killed a connection sending
%% ONE message of max_message_bytes.
%%
%% Each chunk is copied once as it arrives and the copies are joined once, when
%% the last byte is in. The copy is deliberate: a chunk is a part of the
%% receiving connection's socket buffer, which can be several times larger (it
%% holds the frames of other streams, and the HTTP/2 layer re-copies a frame
%% split between two reads), and keeping the part would keep the whole buffer.
%% With the copy, what a reader holds is the bytes it was given, so the memory a
%% half-finished message costs is its own size whatever the read pattern was. A
%% message that came in one chunk is not copied at all (decode/2's case).
%%
%% Data is the next chunk. `{ok, Message, Rest}': the first complete message and
%% what follows it in Data (feed Rest to a fresh reader()); `{more, Reader}':
%% keep Reader for the next chunk; `{error, _}' as decode/2, a frame over Max
%% refused as soon as its header is in, before any of its body is kept.
-spec read(binary(), pos_integer(), reader()) ->
    {ok, binary(), binary()} | {more, reader()} | {error, error()}.
read(Data, Max, {header, <<>>}) ->
    header(Data, Max);
read(Data, Max, {header, Head}) ->
    Need = 5 - byte_size(Head),
    case Data of
        <<More:Need/binary, Body/binary>> ->
            <<0, Len:32>> = <<Head/binary, More/binary>>,
            body_of(Len, Body, Max);
        _ ->
            {more, {header, <<Head/binary, Data/binary>>}}
    end;
read(Data, _Max, {body, Missing, Chunks}) ->
    body(Data, Missing, Chunks).

%% @doc The bytes of an unfinished message a reader has taken, its 5-byte header
%% included: zero only between messages (a header alone, with no body byte yet,
%% is still an unfinished message).
-spec reader_bytes(reader()) -> non_neg_integer().
reader_bytes({header, Head}) ->
    byte_size(Head);
reader_bytes({body, _Missing, Chunks}) ->
    5 + iolist_size(Chunks).

header(<<1, _/binary>>, _Max) ->
    {error, {12, <<"compressed messages are not supported">>}};
header(<<Flag, _/binary>>, _Max) when Flag =/= 0 ->
    {error, {13, <<"invalid message flag">>}};
header(<<0, Len:32, Body/binary>>, Max) ->
    body_of(Len, Body, Max);
header(Short, _Max) ->
    %% Under five bytes: copied (a few bytes) so the reader does not keep the
    %% chunk they came in alive.
    {more, {header, binary:copy(Short)}}.

body_of(Len, _Body, Max) when Len > Max ->
    {error, {8, <<"message too large">>}};
body_of(Len, Body, _Max) ->
    body(Body, Len, []).

body(Data, Missing, Chunks) when byte_size(Data) < Missing ->
    {more, {body, Missing - byte_size(Data), add_chunk(Data, Chunks)}};
body(Data, Missing, Chunks) ->
    <<Last:Missing/binary, Rest/binary>> = Data,
    {ok, join(Last, Chunks), Rest}.

%% Copied: see read/3.
add_chunk(<<>>, Chunks) -> Chunks;
add_chunk(Data, Chunks) -> [binary:copy(Data) | Chunks].

%% A message that came in one chunk is a part of it, not a copy.
join(Last, []) -> Last;
join(Last, Chunks) -> iolist_to_binary(lists:reverse(Chunks, [Last])).

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
