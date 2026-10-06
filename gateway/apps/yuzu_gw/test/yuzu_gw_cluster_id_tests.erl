%%%-------------------------------------------------------------------
%%% @doc Tests for the cluster_id configuration read (#4632).
%%%
%%% The cluster id is stamped on every stream-status notification as a protobuf
%%% string, so it must be valid UTF-8. A name such as one with an umlaut arrives
%%% from the environment (or sys.config) as a list of Unicode code points, and a
%%% byte-wise conversion truncates it to latin-1: every notification then fails
%%% the encoder. These tests pin the conversion (YUZU_GW_CLUSTER_ID override and
%%% yuzu_gw_env:utf8_binary/1) and the boot refusal for a value that cannot be
%%% represented (yuzu_gw_app:evaluate_cluster_id/2).
%%%
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
      {"the env override converts code points to UTF-8",
       fun env_override_converts_to_utf8/0},
      {"the env override converts code points above 255 too",
       fun env_override_converts_wide_characters/0},
      {"an ASCII env override is unchanged",
       fun env_override_ascii_is_unchanged/0},
      {"utf8_binary accepts valid chardata and nothing else",
       fun utf8_binary_contract/0},
      {"boot check: a representable cluster_id passes, from either source",
       fun boot_check_accepts_representable_values/0},
      {"boot check: an unrepresentable cluster_id is refused, naming the source",
       fun boot_check_refuses_unrepresentable_values/0}
     ]}.

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

env_override_converts_to_utf8() ->
    ?assertEqual({ok, <<90, 195, 188, 114, 105, 99, 104>>},
                 override([90, 252, 114, 105, 99, 104])).

env_override_converts_wide_characters() ->
    ?assertEqual({ok, <<228, 184, 173, 230, 150, 135>>}, override([16#4E2D, 16#6587])).

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
                       {<<"default">>, [90, 252, 114, 105, 99, 104]},
                       {<<255>>, "env-wins"}]].

boot_check_refuses_unrepresentable_values() ->
    [?assertEqual({error, {invalid_cluster_id, app_env}}, yuzu_gw_app:evaluate_cluster_id(App, false))
     || App <- [[16#110000], <<255>>, foo, 12, [$a | b]]],
    ?assertEqual({error, {invalid_cluster_id, env}},
                 yuzu_gw_app:evaluate_cluster_id(<<"default">>, [16#110000])),
    ?assertEqual({error, {invalid_cluster_id, env}},
                 yuzu_gw_app:evaluate_cluster_id(<<"default">>, [$a | b])).
