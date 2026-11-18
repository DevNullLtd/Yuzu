%%%-------------------------------------------------------------------
%%% @doc A Register the server rejected leaves NO state in the REAL registry
%%% tables (F29 of the 2026-11-17 security scan). The wire tests mock the
%%% registry; this module runs the real `yuzu_gw_registry' ETS tables, so the
%%% check is on what Subscribe actually reads: the pending table and
%%% take_pending/1.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_register_reject_state_tests).
-include_lib("eunit/include/eunit.hrl").

reject_state_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [{"accepted=false, empty sid: nothing pending, <<>> is not takeable",
       fun rejected_empty_sid/0},
      {"accepted=false with a sid: nothing pending",
       fun rejected_with_sid/0},
      {"accepted=true with an empty sid: nothing pending",
       fun accepted_empty_sid/0},
      {"control: an accepted Register with a sid IS pending and takeable",
       fun accepted_is_pending/0}]}.

setup() ->
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(yuzu_gw_upstream),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok.

cleanup(_) ->
    catch meck:unload(yuzu_gw_upstream),
    ok.

answer(Answer) ->
    ok = meck:expect(yuzu_gw_upstream, proxy_register, fun(_Req, _Opts) -> {ok, Answer} end).

register_agent(Id) ->
    yuzu_gw_agent_service:register(ctx:new(),
                                   #{info => #{agent_id => Id, hostname => <<"h">>},
                                     enrollment_token => <<"t">>}).

pending_rows() -> ets:tab2list(yuzu_gw_pending).

rejected_empty_sid() ->
    answer(#{session_id => <<>>, accepted => false}),
    ?assertMatch({ok, #{accepted := false}, _}, register_agent(<<"rej-1">>)),
    ?assertEqual([], pending_rows()),
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<>>)).

rejected_with_sid() ->
    answer(#{session_id => <<"sess-x">>, accepted => false}),
    ?assertMatch({ok, #{accepted := false}, _}, register_agent(<<"rej-2">>)),
    ?assertEqual([], pending_rows()),
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<"sess-x">>)).

accepted_empty_sid() ->
    answer(#{session_id => <<>>, accepted => true}),
    ?assertMatch({grpc_error, {13, _}}, register_agent(<<"rej-3">>)),
    ?assertEqual([], pending_rows()),
    ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<>>)).

accepted_is_pending() ->
    answer(#{session_id => <<"sess-ok">>, accepted => true}),
    ?assertMatch({ok, #{session_id := <<"sess-ok">>}, _}, register_agent(<<"ok-1">>)),
    ?assertMatch(#{agent_id := <<"ok-1">>}, yuzu_gw_registry:take_pending(<<"sess-ok">>)).
