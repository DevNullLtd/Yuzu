%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_proto — pure helper functions.
%%%
%%% No mocking needed. These functions must handle both atom keys
%%% (internal Erlang maps) and binary keys (proto-decoded maps),
%%% which is critical for correctness at any scale.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_proto_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Timestamp helpers
%%%===================================================================

now_timestamp_returns_millis_test() ->
    #{millis_epoch := M} = yuzu_gw_proto:now_timestamp(),
    ?assert(is_integer(M)),
    ?assert(M > 1700000000000).  %% Sanity: after 2023

timestamp_to_millis_atom_key_test() ->
    ?assertEqual(12345, yuzu_gw_proto:timestamp_to_millis(#{millis_epoch => 12345})).

timestamp_to_millis_binary_key_test() ->
    ?assertEqual(12345, yuzu_gw_proto:timestamp_to_millis(#{<<"millis_epoch">> => 12345})).

timestamp_to_millis_undefined_test() ->
    ?assertEqual(0, yuzu_gw_proto:timestamp_to_millis(undefined)).

timestamp_to_millis_garbage_test() ->
    ?assertEqual(0, yuzu_gw_proto:timestamp_to_millis(#{foo => bar})).

millis_to_timestamp_roundtrip_test() ->
    M = erlang:system_time(millisecond),
    ?assertEqual(M, yuzu_gw_proto:timestamp_to_millis(yuzu_gw_proto:millis_to_timestamp(M))).

%%%===================================================================
%%% CommandRequest field accessors
%%%===================================================================

command_id_atom_test() ->
    ?assertEqual(<<"cmd-1">>, yuzu_gw_proto:command_id(#{command_id => <<"cmd-1">>})).

command_id_binary_test() ->
    ?assertEqual(<<"cmd-1">>, yuzu_gw_proto:command_id(#{<<"command_id">> => <<"cmd-1">>})).

command_id_missing_test() ->
    ?assertEqual(<<>>, yuzu_gw_proto:command_id(#{})).

command_plugin_atom_test() ->
    ?assertEqual(<<"services">>, yuzu_gw_proto:command_plugin(#{plugin => <<"services">>})).

command_plugin_binary_test() ->
    ?assertEqual(<<"services">>, yuzu_gw_proto:command_plugin(#{<<"plugin">> => <<"services">>})).

command_action_atom_test() ->
    ?assertEqual(<<"list">>, yuzu_gw_proto:command_action(#{action => <<"list">>})).

command_action_binary_test() ->
    ?assertEqual(<<"list">>, yuzu_gw_proto:command_action(#{<<"action">> => <<"list">>})).

%%%===================================================================
%%% CommandResponse field accessors
%%%===================================================================

response_status_atom_test() ->
    ?assertEqual('SUCCESS', yuzu_gw_proto:response_status(#{status => 'SUCCESS'})).

response_status_binary_test() ->
    ?assertEqual(<<"SUCCESS">>, yuzu_gw_proto:response_status(#{<<"status">> => <<"SUCCESS">>})).

is_terminal_running_atom_test() ->
    ?assertNot(yuzu_gw_proto:is_terminal_status('RUNNING')).

is_terminal_running_binary_test() ->
    ?assertNot(yuzu_gw_proto:is_terminal_status(<<"RUNNING">>)).

is_terminal_running_int_test() ->
    ?assertNot(yuzu_gw_proto:is_terminal_status(0)).

is_terminal_success_test() ->
    ?assert(yuzu_gw_proto:is_terminal_status('SUCCESS')).

is_terminal_failure_test() ->
    ?assert(yuzu_gw_proto:is_terminal_status('FAILURE')).

is_terminal_integer_test() ->
    ?assert(yuzu_gw_proto:is_terminal_status(1)).

%%%===================================================================
%%% AgentInfo field accessors
%%%===================================================================

agent_id_atom_test() ->
    ?assertEqual(<<"a-1">>, yuzu_gw_proto:agent_id(#{agent_id => <<"a-1">>})).

agent_id_binary_test() ->
    ?assertEqual(<<"a-1">>, yuzu_gw_proto:agent_id(#{<<"agent_id">> => <<"a-1">>})).

agent_hostname_test() ->
    ?assertEqual(<<"host1">>, yuzu_gw_proto:agent_hostname(#{hostname => <<"host1">>})).

agent_plugins_atom_test() ->
    Plugins = [#{name => <<"svc">>}, #{name => <<"fs">>}],
    ?assertEqual([<<"svc">>, <<"fs">>], yuzu_gw_proto:agent_plugins(#{plugins => Plugins})).

agent_plugins_binary_keys_test() ->
    Plugins = [#{<<"name">> => <<"svc">>}],
    ?assertEqual([<<"svc">>], yuzu_gw_proto:agent_plugins(#{<<"plugins">> => Plugins})).

agent_plugins_empty_test() ->
    ?assertEqual([], yuzu_gw_proto:agent_plugins(#{})).

%%%===================================================================
%%% Encoding helpers
%%%===================================================================

encode_command_request_normalizes_test() ->
    Input = #{<<"command_id">> => <<"c1">>, <<"plugin">> => <<"p">>,
              <<"action">> => <<"a">>, <<"parameters">> => #{<<"k">> => <<"v">>}},
    Encoded = yuzu_gw_proto:encode_command_request(Input),
    ?assertEqual(<<"c1">>, maps:get(command_id, Encoded)),
    ?assertEqual(<<"p">>,  maps:get(plugin, Encoded)),
    ?assertEqual(<<"a">>,  maps:get(action, Encoded)),
    ?assertEqual(#{<<"k">> => <<"v">>}, maps:get(parameters, Encoded)).

%% M8 / #1209: the normaliser must preserve the Guardian push `payload` (bytes,
%% binary-safe incl. embedded NUL) so it can never become a silent strip point.
encode_command_request_preserves_payload_test() ->
    Payload = <<"guardian-push", 0, 255>>,
    Input = #{plugin => <<"__guard__">>, action => <<"push_rules">>,
              command_id => <<"g1">>, payload => Payload},
    Encoded = yuzu_gw_proto:encode_command_request(Input),
    ?assertEqual(Payload, maps:get(payload, Encoded)).

%% PR1.9b / CC-03: the normaliser must preserve `dispatch_tag` (field 9) the
%% same way it preserves `payload` (field 8) above — same rationale, same
%% not-on-the-forward-path caveat, same "must never become a silent strip
%% point" requirement.
encode_command_request_preserves_dispatch_tag_test() ->
    Tag = <<"v1|dest|irrev|deadbeefcafef00d">>,
    Input = #{plugin => <<"services">>, action => <<"remove">>,
              command_id => <<"c1">>, dispatch_tag => Tag},
    Encoded = yuzu_gw_proto:encode_command_request(Input),
    ?assertEqual(Tag, maps:get(dispatch_tag, Encoded)).

encode_command_response_fills_defaults_test() ->
    Input = #{command_id => <<"c1">>, status => 'SUCCESS'},
    Encoded = yuzu_gw_proto:encode_command_response(Input),
    ?assertEqual(<<"c1">>, maps:get(command_id, Encoded)),
    ?assertEqual('SUCCESS', maps:get(status, Encoded)),
    ?assertEqual(<<>>, maps:get(output, Encoded)),
    ?assertEqual(0, maps:get(exit_code, Encoded)).

%% C4-gw: the normaliser must carry plugin(7)/action(8)/payload(9) — the
%% Guardian side-channel shape — through untouched, the same as its
%% encode_command_request/1 sibling.
encode_command_response_preserves_guardian_fields_test() ->
    Payload = <<"guardian-event", 0, 7>>,
    Input = #{command_id => <<"c1">>, status => 'SUCCESS',
              plugin => <<"__guard__">>, action => <<"status">>,
              payload => Payload},
    Encoded = yuzu_gw_proto:encode_command_response(Input),
    ?assertEqual(<<"__guard__">>, maps:get(plugin, Encoded)),
    ?assertEqual(<<"status">>,    maps:get(action, Encoded)),
    ?assertEqual(Payload,         maps:get(payload, Encoded)).

%% C4-gw: field 10 (CC-07 plugin_result_status, ABI4) must not be dropped by
%% the whitelist rebuild either.
encode_command_response_preserves_plugin_result_status_test() ->
    Input = #{command_id => <<"c1">>, status => 'SUCCESS',
              plugin_result_status => 'PLUGIN_RESULT_CONSTRAINED'},
    Encoded = yuzu_gw_proto:encode_command_response(Input),
    ?assertEqual('PLUGIN_RESULT_CONSTRAINED',
                 maps:get(plugin_result_status, Encoded)).

%% C5-gw: pin the field-10 encode->decode round-trip through the actual gpb
%% wire codec, not just the map-normaliser above — this is the assertion the
%% register calls out as missing entirely.
plugin_result_status_wire_roundtrip_test() ->
    Input = #{command_id => <<"c1">>, status => 'SUCCESS',
              output => <<>>, exit_code => 0,
              plugin => <<>>, action => <<>>, payload => <<>>,
              plugin_result_status => 'PLUGIN_RESULT_PERMISSION_DENIED'},
    Normalized = yuzu_gw_proto:encode_command_response(Input),
    Wire = agent_pb:encode_msg(Normalized, 'yuzu.agent.v1.CommandResponse'),
    Decoded = agent_pb:decode_msg(Wire, 'yuzu.agent.v1.CommandResponse'),
    ?assertEqual('PLUGIN_RESULT_PERMISSION_DENIED',
                 maps:get(plugin_result_status, Decoded)).

encode_agent_event_connected_test() ->
    E = yuzu_gw_proto:encode_agent_event(<<"a1">>, connected, #{session_id => <<"s1">>}),
    ?assertEqual(<<"a1">>, maps:get(agent_id, E)),
    ?assertMatch(#{session_id := <<"s1">>}, maps:get(connected, E)).

encode_agent_event_disconnected_test() ->
    E = yuzu_gw_proto:encode_agent_event(<<"a1">>, disconnected, #{reason => <<"timeout">>}),
    ?assertMatch(#{reason := <<"timeout">>}, maps:get(disconnected, E)).
