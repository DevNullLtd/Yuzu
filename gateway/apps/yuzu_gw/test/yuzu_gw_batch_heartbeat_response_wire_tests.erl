%%%-------------------------------------------------------------------
%%% @doc BatchHeartbeatResponse wire-contract tests (#1197) - gpb must carry the
%%% server's unknown-session verdict (fields 2 and 3) through gateway_pb, and
%%% must keep an old-style response byte-identical.
%%%
%%% gpb silently drops any wire field absent from a module's vendored proto, so
%%% a regenerated-but-field-less gateway_pb would make the gateway ignore the
%%% verdict with no error. The codegen gate catches drift between the .proto and
%%% the committed module; these tests pin the property itself. The gateway does
%%% not act on the fields yet (the gateway-side replay is tracked in #1197), so
%%% nothing here exercises behaviour, only the codec.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_batch_heartbeat_response_wire_tests).
-include_lib("eunit/include/eunit.hrl").

-define(MSG, 'yuzu.gateway.v1.BatchHeartbeatResponse').

round_trips_unknown_session_ids_and_truncated_flag_test() ->
    Ids = [<<"gw-session-aaaa">>, <<"gw-session-bbbb">>, <<"gw-session-cccc">>],
    Msg = #{acknowledged_count => 7,
            unknown_session_ids => Ids,
            unknown_session_ids_truncated => true},
    Out = gateway_pb:decode_msg(gateway_pb:encode_msg(Msg, ?MSG), ?MSG),
    ?assertEqual(7, maps:get(acknowledged_count, Out)),
    %% Order is preserved by the codec (the server's own order is arbitrary).
    ?assertEqual(Ids, maps:get(unknown_session_ids, Out)),
    ?assertEqual(true, maps:get(unknown_session_ids_truncated, Out)).

round_trips_a_full_4096_id_list_test() ->
    Ids = [iolist_to_binary(io_lib:format("gw-session-~32.16.0b", [N])) || N <- lists:seq(1, 4096)],
    Msg = #{acknowledged_count => 0, unknown_session_ids => Ids},
    Out = gateway_pb:decode_msg(gateway_pb:encode_msg(Msg, ?MSG), ?MSG),
    ?assertEqual(Ids, maps:get(unknown_session_ids, Out)).

old_bytes_decode_to_empty_list_and_false_test() ->
    %% <<8,5>> is what a server that predates fields 2 and 3 sends for
    %% acknowledged_count = 5.
    Out = gateway_pb:decode_msg(<<8, 5>>, ?MSG),
    ?assertEqual(5, maps:get(acknowledged_count, Out)),
    ?assertEqual([], maps:get(unknown_session_ids, Out, [])),
    ?assertEqual(false, maps:get(unknown_session_ids_truncated, Out, false)).

old_style_response_encodes_byte_identically_test() ->
    %% A response with nothing unknown must be indistinguishable on the wire
    %% from one produced before these fields existed.
    ?assertEqual(<<8, 5>>,
                 iolist_to_binary(
                   gateway_pb:encode_msg(#{acknowledged_count => 5}, ?MSG))),
    ?assertEqual(<<8, 5>>,
                 iolist_to_binary(
                   gateway_pb:encode_msg(#{acknowledged_count => 5,
                                           unknown_session_ids => [],
                                           unknown_session_ids_truncated => false},
                                         ?MSG))).
