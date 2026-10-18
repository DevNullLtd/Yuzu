%%%-------------------------------------------------------------------
%%% @doc yuzu_grpc_frame: framing, grpc-timeout, grpc-message, statuses.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_frame_tests).
-include_lib("eunit/include/eunit.hrl").

-define(MAX, 1024).

%%--------------------------------------------------------------------
%% Framing
%%--------------------------------------------------------------------

round_trip_test() ->
    Msg = crypto:strong_rand_bytes(300),
    Frame = yuzu_grpc_frame:encode(Msg),
    ?assertEqual(<<0, 300:32, Msg/binary>>, Frame),
    ?assertEqual({ok, Msg, <<>>}, yuzu_grpc_frame:decode(Frame, ?MAX)).

empty_message_test() ->
    ?assertEqual(<<0, 0:32>>, yuzu_grpc_frame:encode(<<>>)),
    ?assertEqual({ok, <<>>, <<>>}, yuzu_grpc_frame:decode(<<0, 0:32>>, ?MAX)).

encode_takes_iodata_test() ->
    ?assertEqual(yuzu_grpc_frame:encode(<<"abcdef">>),
                 yuzu_grpc_frame:encode([<<"abc">>, "def"])).

nothing_buffered_test() ->
    ?assertEqual({more, <<>>}, yuzu_grpc_frame:decode(<<>>, ?MAX)).

%% The caller appends each chunk to what decode handed back.
message_split_across_three_chunks_test() ->
    Msg = crypto:strong_rand_bytes(200),
    <<A:3/binary, B:100/binary, C/binary>> = yuzu_grpc_frame:encode(Msg),
    {more, Buf1} = yuzu_grpc_frame:decode(A, ?MAX),
    ?assertEqual(A, Buf1),
    {more, Buf2} = yuzu_grpc_frame:decode(<<Buf1/binary, B/binary>>, ?MAX),
    ?assertEqual(<<A/binary, B/binary>>, Buf2),
    ?assertEqual({ok, Msg, <<>>}, yuzu_grpc_frame:decode(<<Buf2/binary, C/binary>>, ?MAX)).

header_split_inside_the_length_test() ->
    Frame = yuzu_grpc_frame:encode(<<"hello">>),
    {more, Buf} = yuzu_grpc_frame:decode(binary:part(Frame, 0, 4), ?MAX),
    ?assertEqual({ok, <<"hello">>, <<>>},
                 yuzu_grpc_frame:decode(<<Buf/binary, (binary:part(Frame, 4, 6))/binary>>, ?MAX)).

two_frames_in_one_buffer_test() ->
    Buf = <<(yuzu_grpc_frame:encode(<<"one">>))/binary, (yuzu_grpc_frame:encode(<<"two">>))/binary>>,
    {ok, <<"one">>, Rest} = yuzu_grpc_frame:decode(Buf, ?MAX),
    ?assertEqual({ok, <<"two">>, <<>>}, yuzu_grpc_frame:decode(Rest, ?MAX)).

compressed_flag_is_unimplemented_test() ->
    ?assertMatch({error, {12, _}}, yuzu_grpc_frame:decode(<<1, 3:32, "abc">>, ?MAX)),
    %% refused on the first byte, before the rest has arrived
    ?assertMatch({error, {12, _}}, yuzu_grpc_frame:decode(<<1>>, ?MAX)).

unknown_flag_is_internal_test() ->
    ?assertMatch({error, {13, _}}, yuzu_grpc_frame:decode(<<2, 0:32>>, ?MAX)).

oversize_is_resource_exhausted_test() ->
    ?assertMatch({error, {8, _}}, yuzu_grpc_frame:decode(<<0, (?MAX + 1):32, "x">>, ?MAX)),
    %% refused on the header alone: the body is never awaited
    ?assertMatch({error, {8, _}}, yuzu_grpc_frame:decode(<<0, 16#FFFFFFFF:32>>, ?MAX)),
    %% exactly the limit is fine
    Msg = binary:copy(<<"x">>, ?MAX),
    ?assertEqual({ok, Msg, <<>>}, yuzu_grpc_frame:decode(yuzu_grpc_frame:encode(Msg), ?MAX)).

%%--------------------------------------------------------------------
%% The incremental reader (read/3)
%%--------------------------------------------------------------------

%% Feed Chunks to a fresh reader; the messages read and the reader left.
read_all(Chunks) ->
    read_all(Chunks, yuzu_grpc_frame:reader(), []).

read_all([], Reader, Acc) ->
    {lists:reverse(Acc), Reader};
read_all([Chunk | Chunks], Reader, Acc) ->
    case yuzu_grpc_frame:read(Chunk, ?MAX, Reader) of
        {ok, Msg, Rest} -> read_all([Rest | Chunks], yuzu_grpc_frame:reader(), [Msg | Acc]);
        {more, Reader1} -> read_all(Chunks, Reader1, Acc);
        {error, _} = Error -> Error
    end.

%% Cut Bin into pieces of Size bytes (the last may be shorter).
pieces(Bin, Size) when byte_size(Bin) =< Size -> [Bin];
pieces(Bin, Size) ->
    <<Piece:Size/binary, Rest/binary>> = Bin,
    [Piece | pieces(Rest, Size)].

reader_whole_message_in_one_chunk_test() ->
    Msg = crypto:strong_rand_bytes(300),
    ?assertEqual({ok, Msg, <<>>},
                 yuzu_grpc_frame:read(yuzu_grpc_frame:encode(Msg), ?MAX, yuzu_grpc_frame:reader())).

reader_empty_message_test() ->
    ?assertEqual({ok, <<>>, <<"x">>},
                 yuzu_grpc_frame:read(<<0, 0:32, "x">>, ?MAX, yuzu_grpc_frame:reader())).

%% Every way of cutting two back-to-back frames into equal pieces, from one
%% byte at a time (the header split at every offset) to the whole buffer, reads
%% the same two messages and leaves nothing behind.
reader_any_chunking_reads_the_same_messages_test() ->
    A = crypto:strong_rand_bytes(700),
    B = crypto:strong_rand_bytes(5),
    Buf = <<(yuzu_grpc_frame:encode(A))/binary, (yuzu_grpc_frame:encode(B))/binary>>,
    [begin
         {Msgs, Reader} = read_all(pieces(Buf, Size)),
         ?assertEqual({Size, [A, B]}, {Size, Msgs}),
         ?assertEqual(0, yuzu_grpc_frame:reader_bytes(Reader))
     end || Size <- lists:seq(1, byte_size(Buf))].

reader_bytes_counts_what_it_holds_test() ->
    Frame = yuzu_grpc_frame:encode(binary:copy(<<"x">>, 100)),
    <<Head:3/binary, Rest/binary>> = Frame,
    {more, R1} = yuzu_grpc_frame:read(Head, ?MAX, yuzu_grpc_frame:reader()),
    ?assertEqual(3, yuzu_grpc_frame:reader_bytes(R1)),
    <<More:42/binary, _/binary>> = Rest,
    {more, R2} = yuzu_grpc_frame:read(More, ?MAX, R1),
    %% the 5 header bytes and 40 body bytes of an unfinished message
    ?assertEqual(45, yuzu_grpc_frame:reader_bytes(R2)),
    %% a header alone is an unfinished message too (END_STREAM there is an error)
    {more, R3} = yuzu_grpc_frame:read(<<0, 7:32>>, ?MAX, yuzu_grpc_frame:reader()),
    ?assertEqual(5, yuzu_grpc_frame:reader_bytes(R3)).

%% A held chunk is a copy: it does not keep the (larger) binary it was cut from.
reader_does_not_keep_the_buffer_a_chunk_came_in_test() ->
    Big = binary:copy(<<"z">>, 64 * 1024),
    Frame = yuzu_grpc_frame:encode(binary:copy(<<"x">>, 900)),
    <<Part:100/binary, _/binary>> = Frame,
    <<_:16/binary, Chunk:100/binary, _/binary>> = <<"0123456789abcdef", Part/binary, Big/binary>>,
    {more, Reader} = yuzu_grpc_frame:read(Chunk, ?MAX, yuzu_grpc_frame:reader()),
    {body, _, [Held]} = Reader,
    ?assertEqual(byte_size(Held), binary:referenced_byte_size(Held)).

reader_refuses_on_the_header_test() ->
    New = yuzu_grpc_frame:reader(),
    ?assertMatch({error, {12, _}}, yuzu_grpc_frame:read(<<1>>, ?MAX, New)),
    ?assertMatch({error, {13, _}}, yuzu_grpc_frame:read(<<2, 0:32>>, ?MAX, New)),
    ?assertMatch({error, {8, _}}, yuzu_grpc_frame:read(<<0, (?MAX + 1):32>>, ?MAX, New)),
    %% an oversize length split across two chunks is refused once it is whole
    {more, R} = yuzu_grpc_frame:read(<<0, 0>>, ?MAX, New),
    ?assertMatch({error, {8, _}}, yuzu_grpc_frame:read(<<16#FF, 16#FF, 16#FF>>, ?MAX, R)),
    %% exactly the limit is fine
    Msg = binary:copy(<<"x">>, ?MAX),
    {Msgs, _} = read_all(pieces(yuzu_grpc_frame:encode(Msg), 100)),
    ?assertEqual([Msg], Msgs).

%%--------------------------------------------------------------------
%% grpc-timeout
%%--------------------------------------------------------------------

timeout_table_test_() ->
    [?_assertEqual({ok, 3600000}, yuzu_grpc_frame:parse_timeout(<<"1H">>)),
     ?_assertEqual({ok, 120000}, yuzu_grpc_frame:parse_timeout(<<"2M">>)),
     ?_assertEqual({ok, 90000}, yuzu_grpc_frame:parse_timeout(<<"90S">>)),
     ?_assertEqual({ok, 250}, yuzu_grpc_frame:parse_timeout(<<"250m">>)),
     %% finer than a millisecond rounds UP: never an earlier deadline than asked
     ?_assertEqual({ok, 1}, yuzu_grpc_frame:parse_timeout(<<"5u">>)),
     ?_assertEqual({ok, 1}, yuzu_grpc_frame:parse_timeout(<<"1n">>)),
     ?_assertEqual({ok, 2}, yuzu_grpc_frame:parse_timeout(<<"1001u">>)),
     ?_assertEqual({ok, 0}, yuzu_grpc_frame:parse_timeout(<<"0S">>)),
     ?_assertEqual({ok, 0}, yuzu_grpc_frame:parse_timeout(<<"0n">>)),
     ?_assertEqual(infinity, yuzu_grpc_frame:parse_timeout(undefined))].

timeout_garbage_test_() ->
    [?_assertEqual({error, invalid}, yuzu_grpc_frame:parse_timeout(Bad)) ||
        Bad <- [<<>>, <<"S">>, <<"1">>, <<"abc">>, <<"1x">>, <<"1 S">>, <<"-1S">>, <<"1.5S">>,
                <<"+1S">>, <<"123456789S">>, <<"1S ">>, <<"１S"/utf8>>, <<"1s">>]].

%% erlang:send_after/3 raises above 2^32-1 ms (about 49.7 days).
timeout_is_clamped_to_a_valid_timer_test() ->
    {ok, Ms} = yuzu_grpc_frame:parse_timeout(<<"99999999H">>),
    ?assertEqual(4294967295, Ms),
    Ref = erlang:send_after(Ms, self(), never),
    ?assert(is_reference(Ref)),
    erlang:cancel_timer(Ref).

%%--------------------------------------------------------------------
%% grpc-message
%%--------------------------------------------------------------------

message_plain_ascii_is_untouched_test() ->
    ?assertEqual(<<"not found: abc-123 ~!@#$^&*()">>,
                 yuzu_grpc_frame:encode_message(<<"not found: abc-123 ~!@#$^&*()">>)).

message_percent_encoding_test() ->
    ?assertEqual(<<"100%25 sure">>, yuzu_grpc_frame:encode_message(<<"100% sure">>)),
    ?assertEqual(<<"a%0D%0Ab">>, yuzu_grpc_frame:encode_message(<<"a\r\nb">>)),
    ?assertEqual(<<"caf%C3%A9">>, yuzu_grpc_frame:encode_message(<<"café"/utf8>>)),
    ?assertEqual(<<"%00%7F%FF">>, yuzu_grpc_frame:encode_message(<<0, 127, 255>>)).

message_round_trip_test() ->
    All = list_to_binary(lists:seq(0, 255)),
    ?assertEqual(All, yuzu_grpc_frame:decode_message(yuzu_grpc_frame:encode_message(All))).

message_encoded_form_has_no_header_breaking_bytes_test() ->
    Enc = yuzu_grpc_frame:encode_message(list_to_binary(lists:seq(0, 255))),
    ?assertEqual(nomatch, binary:match(Enc, [<<"\r">>, <<"\n">>, <<0>>])),
    ?assert(lists:all(fun(B) -> B >= 16#20 andalso B =< 16#7E end, binary_to_list(Enc))).

message_malformed_escape_is_kept_test() ->
    ?assertEqual(<<"%zz">>, yuzu_grpc_frame:decode_message(<<"%zz">>)),
    ?assertEqual(<<"50%">>, yuzu_grpc_frame:decode_message(<<"50%">>)).

normalize_message_test() ->
    ?assertEqual(<<"abc">>, yuzu_grpc_frame:normalize_message(<<"abc">>)),
    ?assertEqual(<<"abc">>, yuzu_grpc_frame:normalize_message("abc")),
    ?assertEqual(<<"ab">>, yuzu_grpc_frame:normalize_message([<<"a">>, $b])),
    ?assertEqual(<<"é"/utf8>>, yuzu_grpc_frame:normalize_message([233])),
    %% not text: an empty message, never a failure of the status that carries it
    ?assertEqual(<<>>, yuzu_grpc_frame:normalize_message(an_atom)),
    ?assertEqual(<<>>, yuzu_grpc_frame:normalize_message({tuple, 1})),
    ?assertEqual(<<>>, yuzu_grpc_frame:normalize_message([-1])),
    %% bounded
    ?assertEqual(1024, byte_size(yuzu_grpc_frame:normalize_message(binary:copy(<<"x">>, 5000)))).

%%--------------------------------------------------------------------
%% Status
%%--------------------------------------------------------------------

status_to_binary_test() ->
    ?assertEqual(<<"0">>, yuzu_grpc_frame:status_to_binary(0)),
    ?assertEqual(<<"16">>, yuzu_grpc_frame:status_to_binary(16)).

normalize_status_test_() ->
    [?_assertEqual(5, yuzu_grpc_frame:normalize_status(5)),
     ?_assertEqual(0, yuzu_grpc_frame:normalize_status(0)),
     ?_assertEqual(16, yuzu_grpc_frame:normalize_status(<<"16">>)),
     ?_assertEqual(5, yuzu_grpc_frame:normalize_status(<<"5">>)),
     %% not a status: a handler bug, read as INTERNAL
     ?_assertEqual(13, yuzu_grpc_frame:normalize_status(17)),
     ?_assertEqual(13, yuzu_grpc_frame:normalize_status(-1)),
     ?_assertEqual(13, yuzu_grpc_frame:normalize_status(<<"17">>)),
     ?_assertEqual(13, yuzu_grpc_frame:normalize_status(<<"x">>)),
     ?_assertEqual(13, yuzu_grpc_frame:normalize_status(<<"123">>)),
     ?_assertEqual(13, yuzu_grpc_frame:normalize_status(not_a_status)),
     ?_assertEqual(13, yuzu_grpc_frame:normalize_status(5.0))].

trailers_test() ->
    ?assertEqual(#{<<"grpc-status">> => <<"0">>}, yuzu_grpc_frame:trailers(0, <<>>)),
    ?assertEqual(#{<<"grpc-status">> => <<"5">>, <<"grpc-message">> => <<"no%25">>},
                 yuzu_grpc_frame:trailers(5, <<"no%">>)).
