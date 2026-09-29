%%%-------------------------------------------------------------------
%%% @doc OTA signature wire-contract tests (ADR-0016, #416/#3807) — gpb must
%%% preserve `update_signature` through both vendored codecs.
%%%
%%% gpb SILENTLY DROPS any wire field absent from a module's vendored proto. The
%%% agent verifies an OTA binary against a detached CMS signature carried in
%%% CheckForUpdateResponse field 7; if that field were missing from a generated
%%% codec, the signature would be stripped in transit and every agent running
%%% --update-require-signature would refuse every update — while direct
%%% (non-gateway) mode kept working. That is the hardest class of regression to
%%% catch, and it is exactly what shipped here: the vendored protos gained the
%%% field but the committed _pb modules were not regenerated, which the codegen
%%% gate caught (an external reviewer found it; three modules had drifted,
%%% because gateway.proto and management.proto both embed the message).
%%%
%%% The codegen gate already prevents that drift. These tests pin the PROPERTY
%%% the gate exists to protect, so a future change that regenerates cleanly but
%%% drops the field from the proto still fails.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_ota_signature_wire_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SIG, <<"-----BEGIN CMS-----\nMIIBogYJKoZIhvcNAQcC\n-----END CMS-----\n">>).

%% agent_pb: the codec the gateway uses to talk to the AGENT.
agent_pb_round_trips_update_signature_test() ->
    Msg = #{update_available => true,
            latest_version   => "1.2.3",
            sha256           => "abc123",
            mandatory        => false,
            eligible         => true,
            file_size        => 4096,
            update_signature => ?SIG},
    Bin = agent_pb:encode_msg(Msg, 'yuzu.agent.v1.CheckForUpdateResponse'),
    Out = agent_pb:decode_msg(Bin, 'yuzu.agent.v1.CheckForUpdateResponse'),
    ?assertEqual(?SIG, maps:get(update_signature, Out)),
    %% The neighbouring field must survive too: adding field 7 after file_size
    %% is exactly the edit that can corrupt the preceding field's encoding.
    ?assertEqual(4096, maps:get(file_size, Out)).

%% gateway_pb: the codec the gateway uses to talk to the SERVER. gateway.proto
%% embeds CheckForUpdateResponse, so it needs the field independently.
gateway_pb_round_trips_update_signature_test() ->
    Msg = #{update_available => true,
            latest_version   => "1.2.3",
            sha256           => "abc123",
            mandatory        => false,
            eligible         => true,
            file_size        => 4096,
            update_signature => ?SIG},
    Bin = gateway_pb:encode_msg(Msg, 'yuzu.agent.v1.CheckForUpdateResponse'),
    Out = gateway_pb:decode_msg(Bin, 'yuzu.agent.v1.CheckForUpdateResponse'),
    ?assertEqual(?SIG, maps:get(update_signature, Out)).

%% The hop that matters: a signature encoded by one codec must survive being
%% decoded and re-encoded by the other, which is what a proxying gateway does.
cross_codec_hop_preserves_update_signature_test() ->
    Msg = #{update_available => true,
            latest_version   => "1.2.3",
            sha256           => "abc123",
            mandatory        => false,
            eligible         => true,
            file_size        => 4096,
            update_signature => ?SIG},
    FromServer = gateway_pb:encode_msg(Msg, 'yuzu.agent.v1.CheckForUpdateResponse'),
    Decoded    = gateway_pb:decode_msg(FromServer, 'yuzu.agent.v1.CheckForUpdateResponse'),
    ToAgent    = agent_pb:encode_msg(Decoded, 'yuzu.agent.v1.CheckForUpdateResponse'),
    Final      = agent_pb:decode_msg(ToAgent, 'yuzu.agent.v1.CheckForUpdateResponse'),
    ?assertEqual(?SIG, maps:get(update_signature, Final)).

%% An absent signature must decode as absent/empty, never as a spurious value —
%% the agent treats empty as "unsigned", which is a policy decision, so a codec
%% that invented bytes here would silently change enforcement behaviour.
absent_signature_stays_absent_test() ->
    Msg = #{update_available => true, latest_version => "1.2.3", sha256 => "abc123",
            mandatory => false, eligible => true, file_size => 4096},
    Bin = agent_pb:encode_msg(Msg, 'yuzu.agent.v1.CheckForUpdateResponse'),
    Out = agent_pb:decode_msg(Bin, 'yuzu.agent.v1.CheckForUpdateResponse'),
    %% NO default argument: maps:get/3 would make this pass if the codec had
    %% dropped update_signature entirely, which is the exact regression this
    %% module exists to pin. proto3 emits the field unconditionally, so a bare
    %% maps:get/2 is correct and discriminating.
    ?assertEqual(<<>>, maps:get(update_signature, Out)).
