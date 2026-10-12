%%%-------------------------------------------------------------------
%%% @doc Tests for the cluster_id configuration read (#4632).
%%%
%%% The cluster id is stamped on every stream-status notification as a protobuf
%%% string, so it must be valid UTF-8. A name with an umlaut arrives from the
%%% environment (or sys.config) as a list of Unicode code points; a byte-wise
%%% conversion truncates it to latin-1 and every notification then fails the
%%% encoder. These tests pin the conversion (YUZU_GW_CLUSTER_ID override,
%%% yuzu_gw_env:utf8_binary/1) and the boot refusal for an unrepresentable value
%%% (yuzu_gw_app:evaluate_cluster_id/2).
%%%
%%% os:getenv/1 returns the variable's BYTES as code points on a latin1 native
%%% encoding node (no LANG/LC_ALL, no +fnu) and decoded characters on a utf8 one,
%%% so the encoding-parameterised tests pin both whatever locale the runner has.
%%% Every test restores the application env key and the OS variable it touched.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_cluster_id_tests).
-include_lib("eunit/include/eunit.hrl").

-define(VAR, "YUZU_GW_CLUSTER_ID").

cluster_id_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"the env override keeps the original UTF-8 bytes whatever the native encoding",
       t(fun env_override_converts_to_utf8/0)},
      {"the env override keeps UTF-8 text with characters above 255 too",
       t(fun env_override_converts_wide_characters/0)},
      {"an ASCII env override is unchanged",
       t(fun env_override_ascii_is_unchanged/0)},
      {"the env text is interpreted in the given native encoding, then must be UTF-8",
       t(fun env_text_by_encoding/0)},
      {"the env override that cannot be represented is not applied and its warning never prints the value",
       t(fun env_override_warning_never_echoes_the_value/0)},
      {"utf8_binary accepts valid chardata and nothing else",
       t(fun utf8_binary_contract/0)},
      {"boot check: a representable cluster_id passes, from either source",
       t(fun boot_check_accepts_representable_values/0)},
      {"boot check: an unrepresentable cluster_id is refused, naming the source",
       t(fun boot_check_refuses_unrepresentable_values/0)},
      {"boot check: the env value is judged in the native encoding",
       t(fun boot_check_judges_the_env_in_the_native_encoding/0)},
      {"the application refuses to start with an unrepresentable cluster_id, before starting anything",
       t(fun application_start_refuses_an_unrepresentable_cluster_id/0)}
     ]}.

t(Fun) ->
    {timeout, 30, Fun}.

setup() ->
    {application:get_env(yuzu_gw, cluster_id), os:getenv(?VAR)}.

cleanup({PrevApp, PrevVar}) ->
    case PrevApp of
        {ok, V}   -> application:set_env(yuzu_gw, cluster_id, V);
        undefined -> application:unset_env(yuzu_gw, cluster_id)
    end,
    case PrevVar of
        false -> os:unsetenv(?VAR);
        Val   -> os:putenv(?VAR, Val)
    end,
    ok.

override(Chars) ->
    application:unset_env(yuzu_gw, cluster_id),
    os:putenv(?VAR, Chars),
    yuzu_gw_app:apply_env_overrides(),
    application:get_env(yuzu_gw, cluster_id).

%% What os:getenv/1 returns for a variable whose bytes are the UTF-8 text, on the
%% running node: the bytes themselves under a latin1 native encoding (os:putenv/1
%% stores a latin1 list as those bytes), the decoded characters under utf8.
env_text(Utf8) when is_binary(Utf8) ->
    case file:native_name_encoding() of
        utf8   -> unicode:characters_to_list(Utf8);
        latin1 -> binary_to_list(Utf8)
    end.

env_override_converts_to_utf8() ->
    ?assertEqual({ok, <<90, 195, 188, 114, 105, 99, 104>>},
                 override(env_text(<<90, 195, 188, 114, 105, 99, 104>>))).

env_override_converts_wide_characters() ->
    ?assertEqual({ok, <<228, 184, 173, 230, 150, 135>>},
                 override(env_text(<<228, 184, 173, 230, 150, 135>>))).

%% What the running locale returns is not assumed: both encodings are pinned with
%% the encoding as a parameter. Under latin1 the text is bytes (code points below
%% 256) and the bytes must be valid UTF-8; under utf8 the text is characters.
env_text_by_encoding() ->
    Zurich = <<90, 195, 188, 114, 105, 99, 104>>,
    ?assertEqual({ok, Zurich},
                 yuzu_gw_env:env_utf8_binary([90, 195, 188, 114, 105, 99, 104], latin1)),
    ?assertEqual({ok, Zurich},
                 yuzu_gw_env:env_utf8_binary([90, 252, 114, 105, 99, 104], utf8)),
    ?assertEqual({ok, <<228, 184, 173, 230, 150, 135>>},
                 yuzu_gw_env:env_utf8_binary([16#4E2D, 16#6587], utf8)),
    ?assertEqual({ok, <<228, 184, 173, 230, 150, 135>>},
                 yuzu_gw_env:env_utf8_binary([228, 184, 173, 230, 150, 135], latin1)),
    ?assertEqual({ok, <<"eu-west-1">>}, yuzu_gw_env:env_utf8_binary("eu-west-1", latin1)),
    ?assertEqual({ok, <<"eu-west-1">>}, yuzu_gw_env:env_utf8_binary("eu-west-1", utf8)),
    ?assertEqual({ok, <<>>}, yuzu_gw_env:env_utf8_binary([], latin1)),
    %% Bytes that are not UTF-8 are refused, not reinterpreted.
    ?assertEqual(error, yuzu_gw_env:env_utf8_binary([90, 252], latin1)),
    ?assertEqual(error, yuzu_gw_env:env_utf8_binary([195], latin1)),
    ?assertEqual(error, yuzu_gw_env:env_utf8_binary([255, 254], latin1)),
    %% A latin1 node cannot return a code point above 255; if one is asked for,
    %% it is refused (never truncated).
    ?assertEqual(error, yuzu_gw_env:env_utf8_binary([16#4E2D], latin1)),
    ?assertEqual(error, yuzu_gw_env:env_utf8_binary([90, 16#100], latin1)),
    %% Not text at all.
    [?assertEqual(error, yuzu_gw_env:env_utf8_binary(Bad, Enc))
     || Enc <- [latin1, utf8],
        Bad <- [[16#D800], [16#110000], [-1], [$a | b], foo, 12, undefined, <<"abc">>, {a}]].

%% A value that cannot be represented is not applied, and the warning says which
%% variable and never the value (the critical refusal line never prints it
%% either). Driven with the encoding as a parameter, so it runs the same on a
%% latin1 and on a utf8 node: the marker followed by a lone 0xFC byte is not UTF-8
%% as latin1 bytes.
env_override_warning_never_echoes_the_value() ->
    Marker = <<"secret-marker-id">>,
    Lines = yuzu_gw_test_logs:capture(warning, fun() ->
        application:unset_env(yuzu_gw, cluster_id),
        os:putenv(?VAR, binary_to_list(Marker) ++ [252]),
        yuzu_gw_app:apply_env_overrides(latin1)
    end),
    ?assertEqual(undefined, application:get_env(yuzu_gw, cluster_id)),
    ?assertMatch([_ | _], [L || L <- Lines, binary:match(L, <<?VAR>>) =/= nomatch]),
    ?assertEqual([], [L || L <- Lines, binary:match(L, Marker) =/= nomatch]),
    %% The same variable read as utf8 characters is a valid name and applies.
    application:unset_env(yuzu_gw, cluster_id),
    yuzu_gw_app:apply_env_overrides(utf8),
    ?assertEqual({ok, <<"secret-marker-id", 195, 188>>},
                 application:get_env(yuzu_gw, cluster_id)).

env_override_ascii_is_unchanged() ->
    ?assertEqual({ok, <<"eu-west-1">>}, override("eu-west-1")).

utf8_binary_contract() ->
    ?assertEqual({ok, <<"abc">>}, yuzu_gw_env:utf8_binary(<<"abc">>)),
    ?assertEqual({ok, <<"abc">>}, yuzu_gw_env:utf8_binary("abc")),
    ?assertEqual({ok, <<>>}, yuzu_gw_env:utf8_binary(<<>>)),
    ?assertEqual({ok, <<195, 188>>}, yuzu_gw_env:utf8_binary([252])),
    ?assertEqual({ok, <<195, 188>>}, yuzu_gw_env:utf8_binary(<<195, 188>>)),
    ?assertEqual({ok, <<"a", 195, 188>>}, yuzu_gw_env:utf8_binary([$a, <<195, 188>>])),
    [?assertEqual(error, yuzu_gw_env:utf8_binary(Bad))
     || Bad <- [<<255>>, <<195>>, [16#110000], [16#D800], [-1], [$a | b], foo, 12,
                undefined, {a}, [<<255>>], [foo]]].

boot_check_accepts_representable_values() ->
    [?assertEqual(ok, yuzu_gw_app:evaluate_cluster_id(App, Var))
     || {App, Var} <- [{<<"default">>, false},
                       {"default", false},
                       {[90, 252, 114, 105, 99, 104], false},
                       {<<"default">>, env_text(<<90, 195, 188, 114, 105, 99, 104>>)},
                       {<<255>>, "env-wins"}]].

%% The same value judged under each native encoding: UTF-8 bytes that a latin1 node
%% returns as code points below 256 pass; the same list on a utf8 node would be
%% a two character text (valid, with an A tilde and a currency sign), while a lone
%% byte is refused under latin1.
boot_check_judges_the_env_in_the_native_encoding() ->
    ?assertEqual(ok, yuzu_gw_app:evaluate_cluster_id(<<"default">>,
                                                     [90, 195, 188, 114, 105, 99, 104], latin1)),
    ?assertEqual(ok, yuzu_gw_app:evaluate_cluster_id(<<"default">>,
                                                     [90, 252, 114, 105, 99, 104], utf8)),
    ?assertEqual({error, {invalid_cluster_id, env}},
                 yuzu_gw_app:evaluate_cluster_id(<<"default">>, [90, 252, 114], latin1)),
    ?assertEqual({error, {invalid_cluster_id, env}},
                 yuzu_gw_app:evaluate_cluster_id(<<"default">>, [16#4E2D], latin1)),
    %% The application setting is not an environment text: the encoding does not
    %% apply to it.
    ?assertEqual(ok, yuzu_gw_app:evaluate_cluster_id([90, 252, 114], false, latin1)),
    ?assertEqual({error, {invalid_cluster_id, app_env}},
                 yuzu_gw_app:evaluate_cluster_id(<<255>>, false, latin1)).

boot_check_refuses_unrepresentable_values() ->
    [?assertEqual({error, {invalid_cluster_id, app_env}}, yuzu_gw_app:evaluate_cluster_id(App, false))
     || App <- [[16#110000], <<255>>, foo, 12, [$a | b]]],
    ?assertEqual({error, {invalid_cluster_id, env}},
                 yuzu_gw_app:evaluate_cluster_id(<<"default">>, [16#110000])),
    ?assertEqual({error, {invalid_cluster_id, env}},
                 yuzu_gw_app:evaluate_cluster_id(<<"default">>, [$a | b])).

%% start/2 returns the refusal before anything is started (the check runs right
%% after the environment overrides). Another test module may have made this node
%% distributed with a weak cookie, which the cookie guard ahead of the check would
%% refuse first, so the documented dev/CI override is set for the call and put
%% back. A representable value is not tried here: it would start the whole
%% application.
application_start_refuses_an_unrepresentable_cluster_id() ->
    PrevAllow = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE"),
    os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", "1"),
    try
        os:unsetenv(?VAR),
        application:set_env(yuzu_gw, cluster_id, [16#110000]),
        ?assertEqual({error, {invalid_cluster_id, app_env}}, yuzu_gw_app:start(normal, [])),
        ?assertEqual(undefined, whereis(yuzu_gw_sup))
    after
        case PrevAllow of
            false -> os:unsetenv("YUZU_GW_ALLOW_DEFAULT_COOKIE");
            Val   -> os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", Val)
        end
    end.
