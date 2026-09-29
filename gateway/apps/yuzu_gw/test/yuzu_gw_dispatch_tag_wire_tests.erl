%%%-------------------------------------------------------------------
%%% @doc PR1.9b / CC-03 dispatch_tag wire-contract tests — gpb must
%%% preserve CommandRequest.dispatch_tag (field 9) end-to-end through the
%%% gateway, and MUST silently strip it when decoded against a schema
%%% that still lacks the field — the explicit new-server -> old-gateway
%%% regression that CC-03's wire-capability handshake exists to detect
%%% before the dispatch chokepoint ever routes a tagged command there.
%%%
%%% Follows the pattern of yuzu_gw_guardian_wire_tests.erl /
%%% yuzu_gw_inventory_wire_tests.erl: hand off to the actual gpb-generated
%%% codec (agent_pb, regenerated from gateway/priv/proto/agent.proto by
%%% this package's edit) rather than asserting against yuzu_gw_proto.erl's
%%% map helpers alone, because the strip mechanism lives in gpb's decoder,
%%% not in gateway Erlang code.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_dispatch_tag_wire_tests).
-include_lib("eunit/include/eunit.hrl").

%% Wire grammar frozen by server/core/src/command_capability_parsers.hpp
%% (encode_dispatch_tag/decode_dispatch_tag) — see agent.proto
%% CommandRequest.dispatch_tag. The exact token contents don't matter to
%% gpb (it's an opaque string on the wire); this just exercises a
%% realistic value.
-define(DISPATCH_TAG, <<"v1|mut|rev|deadbeefcafef00d">>).

%% Field 9 (dispatch_tag) must survive an agent_pb encode/decode round trip
%% unchanged, alongside plugin/action/payload — proving the gateway's
%% vendored agent.proto (this package's edit) actually carries it end to
%% end through the exact codec the gateway uses on the CommandRequest path.
dispatch_tag_survives_gateway_roundtrip_test() ->
    Cmd = #{command_id   => <<"c1">>,
            plugin       => <<"services">>,
            action       => <<"restart">>,
            parameters   => #{},
            payload      => <<>>,
            dispatch_tag => ?DISPATCH_TAG},
    Wire = agent_pb:encode_msg(Cmd, 'yuzu.agent.v1.CommandRequest'),
    Decoded = agent_pb:decode_msg(Wire, 'yuzu.agent.v1.CommandRequest'),
    ?assertEqual(?DISPATCH_TAG, maps:get(dispatch_tag, Decoded, undefined)),
    ?assertEqual(<<"services">>, maps:get(plugin, Decoded, undefined)),
    ?assertEqual(<<"restart">>,  maps:get(action, Decoded, undefined)).

%% CC-03 regression: the exact same wire bytes, decoded by a gpb module
%% generated from a CommandRequest schema that has fields 1-8 but NOT field
%% 9, must NOT surface dispatch_tag — gpb 4.21.7 has no
%% preserve_unknown_fields, so an unrecognised field is skipped by wire
%% type and simply absent from the decoded map. This reproduces, at the
%% gpb-decode level, exactly the failure check-proto-codegen.sh's
%% flat/nested byte-diff exists to prevent for the two committed gateway
%% mirrors — here for the sharper case of a gateway build old enough that
%% BOTH mirrors (and the regenerated agent_pb) still predate this field.
dispatch_tag_stripped_by_old_gateway_schema_test() ->
    Cmd = #{command_id   => <<"c1">>,
            plugin       => <<"services">>,
            action       => <<"restart">>,
            parameters   => #{},
            payload      => <<>>,
            dispatch_tag => ?DISPATCH_TAG},
    Wire = agent_pb:encode_msg(Cmd, 'yuzu.agent.v1.CommandRequest'),

    OldMod = old_agent_pb_pre_dispatch_tag,
    {ok, OldMod, Code} = gpb_compile:string(
        OldMod, old_command_request_proto(),
        [binary, maps, strings_as_binaries, use_packages,
         {maps_unset_optional, omitted}, {target_erlang_version, 26},
         return_errors]),
    {module, OldMod} = code:load_binary(
        OldMod, "old_agent_pb_pre_dispatch_tag.erl", Code),

    OldDecoded = OldMod:decode_msg(Wire, 'yuzu.agent.v1.CommandRequest'),
    ?assertEqual(undefined, maps:get(dispatch_tag, OldDecoded, undefined)),
    %% Fields 1-8 are unaffected — only the field the old schema never
    %% declared is lost, proving this is a targeted strip, not garbage.
    ?assertEqual(<<"services">>, maps:get(plugin, OldDecoded, undefined)),
    ?assertEqual(<<"restart">>,  maps:get(action, OldDecoded, undefined)),

    code:purge(OldMod),
    code:delete(OldMod).

%% A minimal CommandRequest schema frozen at fields 1-8 (this package's
%% agent.proto before dispatch_tag = 9 was added). Deliberately
%% self-contained (no common.proto import for `expires_at`) since the test
%% never populates that field and an unset proto3 message field carries no
%% wire bytes to decode either way — the schema mismatch is irrelevant to
%% what this test measures.
old_command_request_proto() ->
    "syntax = \"proto3\";\n"
    "package yuzu.agent.v1;\n"
    "message CommandRequest {\n"
    "  string command_id = 1;\n"
    "  string plugin     = 2;\n"
    "  string action     = 3;\n"
    "  map<string, string> parameters = 4;\n"
    "  int32 stagger_seconds = 6;\n"
    "  int32 delay_seconds   = 7;\n"
    "  bytes payload = 8;\n"
    "}\n".
