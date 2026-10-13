%%%-------------------------------------------------------------------
%%% @doc EUnit tests for yuzu_gw_peer_addr:sanitize/1 (#4632): the value that
%%% reaches a stream-status notification is always valid UTF-8 of at most 255
%%% bytes. Pure function, no fixtures.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_peer_addr_tests).
-include_lib("eunit/include/eunit.hrl").

-define(INVALID, <<"invalid">>).

%% Three-byte character (U+20AC) and four-byte character (U+1F600).
-define(EURO, <<226, 130, 172>>).
-define(GRIN, <<240, 159, 152, 128>>).

unchanged_test_() ->
    [{Name, ?_assertEqual(Addr, yuzu_gw_peer_addr:sanitize(Addr))}
     || {Name, Addr} <- [{"ascii", <<"peer-a:1">>},
                         {"empty", <<>>},
                         {"exactly the limit (255 bytes)", binary:copy(<<"a">>, 255)}]].

valid_multibyte_within_the_limit_is_unchanged_test() ->
    Addr = <<"host-", ?EURO/binary, "-", ?GRIN/binary>>,
    ?assertEqual(Addr, yuzu_gw_peer_addr:sanitize(Addr)).

%% The boundary itself: one byte over the limit is cut to the limit. Every other
%% cut case starts well past it, so only this one separates "at most 255" from
%% "at most 256".
one_over_the_limit_is_cut_to_the_limit_test() ->
    Addr = binary:copy(<<"a">>, 256),
    ?assertEqual(binary:copy(<<"a">>, 255), yuzu_gw_peer_addr:sanitize(Addr)).

cut_never_splits_a_multibyte_character_test_() ->
    %% A multibyte character that starts before byte 255 and ends at or after it:
    %% the result stops before it. Pad so the character begins at offset Pad, for
    %% every offset where it straddles the limit (the first is the one where only
    %% its last byte lies past the limit, which needs the longest step back) and
    %% for the offset where it starts exactly at the limit.
    [{lists:flatten(io_lib:format("~b-byte char at offset ~b", [byte_size(Char), Pad])),
      fun() ->
          Addr = <<(binary:copy(<<"a">>, Pad))/binary, Char/binary, "tail">>,
          Out = yuzu_gw_peer_addr:sanitize(Addr),
          ?assertEqual(binary:part(Addr, 0, Pad), Out),
          ?assert(byte_size(Out) =< 255),
          ?assert(is_binary(unicode:characters_to_binary(Out, utf8, utf8)))
      end}
     || Char <- [?EURO, ?GRIN],
        Pad <- lists:seq(256 - byte_size(Char), 255)].

cut_keeps_a_character_that_ends_exactly_at_the_limit_test() ->
    Addr = <<(binary:copy(<<"a">>, 252))/binary, ?EURO/binary, "tail">>,
    Out = yuzu_gw_peer_addr:sanitize(Addr),
    ?assertEqual(255, byte_size(Out)),
    ?assertEqual(<<(binary:copy(<<"a">>, 252))/binary, ?EURO/binary>>, Out).

invalid_utf8_becomes_the_placeholder_test_() ->
    [{Name, ?_assertEqual(?INVALID, yuzu_gw_peer_addr:sanitize(Bin))}
     || {Name, Bin} <- [{"bytes that are not UTF-8", <<255, 254, 200>>},
                        {"a lone continuation byte", <<"host", 16#80>>},
                        {"a truncated character at the end", <<"host", 226, 130>>},
                        {"an overlong encoding", <<192, 175>>},
                        {"a surrogate", <<237, 160, 128>>},
                        {"a code point above U+10FFFF", <<244, 144, 128, 128>>},
                        {"invalid bytes after a valid prefix longer than the limit",
                         <<(binary:copy(<<"a">>, 300))/binary, 255>>}]].

non_binary_becomes_the_placeholder_test_() ->
    [{lists:flatten(io_lib:format("~p", [V])),
      ?_assertEqual(?INVALID, yuzu_gw_peer_addr:sanitize(V))}
     || V <- [undefined, "host:1", 42]].

a_huge_value_is_bounded_test_() ->
    {timeout, 30, fun() ->
        Big = binary:copy(<<"a">>, 5 * 1024 * 1024),
        ?assertEqual(binary:copy(<<"a">>, 255), yuzu_gw_peer_addr:sanitize(Big)),
        BigBad = <<Big/binary, 255>>,
        ?assertEqual(?INVALID, yuzu_gw_peer_addr:sanitize(BigBad))
    end}.

%% A peer address read out of a large request is a sub-binary that keeps the
%% whole parent alive for as long as the notification is held. The result is a
%% copy, whether the value passed unchanged, was cut, or was replaced.
result_does_not_keep_the_parent_binary_alive_test_() ->
    Big = binary:copy(<<"a">>, 5 * 1024 * 1024),
    [{Name,
      fun() ->
          Sub = binary:part(Big, Start, Len),
          ?assert(binary:referenced_byte_size(Sub) > 1024 * 1024),
          Out = yuzu_gw_peer_addr:sanitize(Sub),
          ?assert(binary:referenced_byte_size(Out) =< 255)
      end}
     || {Name, Start, Len} <- [{"a valid value within the limit", 0, 100},
                               {"a valid value of exactly the limit", 10, 255},
                               {"a valid value over the limit, cut", 0, 1000}]].

result_is_always_encodable_test() ->
    %% The point of the module: the real encoder accepts the result of every
    %% input above, including the ones that used to raise.
    Inputs = [<<255, 254, 200>>, <<"host", 226, 130>>, binary:copy(<<"a">>, 5000),
              <<(binary:copy(<<"a">>, 254))/binary, ?GRIN/binary>>, undefined, <<>>],
    lists:foreach(
      fun(In) ->
          Msg = #{agent_id => <<"a">>, session_id => <<"s">>, event => 'CONNECTED',
                  peer_addr => yuzu_gw_peer_addr:sanitize(In), gateway_node => <<"n">>,
                  cluster_id => <<"c">>, wire_capabilities => [], stream_home_id => <<"h">>},
          ?assert(is_binary(iolist_to_binary(
                    gateway_pb:encode_msg(Msg, 'yuzu.gateway.v1.StreamStatusNotification'))))
      end, Inputs).
