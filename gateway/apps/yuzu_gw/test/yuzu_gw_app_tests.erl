%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_app — distribution cookie guard (#659).
%%%
%%% evaluate_cookie/3 is the pure policy decision behind the boot guard
%%% that refuses to start with a known-insecure Erlang distribution cookie
%%% (the cookie is the sole authentication for inter-node RPC; a publicly
%%% known value is unauthenticated remote code execution via EPMD).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_app_tests).
-include_lib("eunit/include/eunit.hrl").

%% A non-distributed node has no inter-node attack surface, so no cookie is
%% ever rejected — this keeps eunit/CT (which run as nonode@nohost) unaffected.
non_distributed_accepts_any_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('nonode@nohost', 'yuzu_gw_secret_change_me', false)),
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('nonode@nohost', '', false)).

%% The historical committed default must fail closed once distribution is up.
default_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'yuzu_gw_secret_change_me', false)).

%% An empty cookie (e.g. unsubstituted ${YUZU_GW_COOKIE}) is equally insecure.
empty_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', '', false)).

%% The explicit dev/CI override permits the default cookie.
override_allows_default_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'yuzu_gw_secret_change_me', true)).

%% A strong unique cookie is accepted when distributed.
strong_cookie_accepted_when_distributed_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1',
                                    'a3f9c1e2b7d84056a3f9c1e2b7d84056f0e1d2c3', false)).

%% #659 UP-1: if relx `.src` substitution fails, the cookie atom is the literal
%% `${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}`. Substring matching must catch it
%% (it embeds the default), otherwise the unauthenticated-RPC surface re-opens.
literal_unsubstituted_default_rejected_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1',
                                    '${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}', false)).

%% A bare unsubstituted placeholder (no fallback) is rejected via the `${` check.
unsubstituted_placeholder_rejected_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', '${YUZU_GW_COOKIE}', false)).

%%%===================================================================
%%% HA WS-4 #4555 — minimum cookie length floor (ADR-2002 §7b)
%%%===================================================================

%% A short but otherwise well-formed custom cookie is still insecure: DNS-based
%% discovery lets a node dial addresses it did not choose by hand, and the
%% distribution handshake's initiator sends the cookie hash first — a short
%% cookie is brute-forceable offline. Not the known-default substring, so this
%% exercises the length floor specifically, not the #659 default-cookie check.
short_custom_cookie_rejected_when_distributed_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'too_short_cookie', false)).

%% Exactly at the floor (32 chars) is accepted.
cookie_at_minimum_length_accepted_test() ->
    Cookie = list_to_atom(lists:duplicate(32, $a)),
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', Cookie, false)).

%% One character short of the floor is rejected.
cookie_one_below_minimum_length_rejected_test() ->
    Cookie = list_to_atom(lists:duplicate(31, $a)),
    ?assertEqual({error, insecure_distribution_cookie},
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', Cookie, false)).

%% The existing dev/CI override also covers a too-short (not just default) cookie.
override_allows_short_custom_cookie_test() ->
    ?assertEqual(ok,
        yuzu_gw_app:evaluate_cookie('yuzu_gw1@127.0.0.1', 'too_short_cookie', true)).

%%%===================================================================
%%% Boot wiring
%%%
%%% Every test below boots yuzu_gw_app with the listener, telemetry setup,
%%% supervisor and heartbeat buffer replaced (no port or process is started).
%%% Each runs in a setup/cleanup fixture: eunit kills a test body that
%%% outlives its timeout and a `try ... after' inside the body dies with it,
%%% while the fixture's cleanup still runs, so a cancelled test cannot leave
%%% its mocks, logger filter or environment behind for the next module.
%%%===================================================================

-define(BOOT_MODS, [yuzu_gw_telemetry, prometheus_httpd, yuzu_gw_sup,
                    yuzu_gw_heartbeat_buffer]).
-define(SUMMARY_KEY, {yuzu_gw_heartbeat_admission, summary_state}).
-define(SAFE_CALL_KEYS, [{yuzu_gw_safe_call, S}
                         || S <- [yuzu_gw_upstream, yuzu_gw_registry,
                                  yuzu_gw_agent_sup, yuzu_gw_router]]).
-define(NODELAY_KEY, {?MODULE, nodelay_applied}).

%% yuzu_gw_app:start/2 must create the summary-log state before it starts the
%% metrics listener and the supervision tree. Nothing else boots the app, so
%% without this a deleted or reordered init_summary_state/0 call is invisible
%% (the lazy path in yuzu_gw_heartbeat_admission hides it). The listener and
%% supervisor are replaced by recorders so no port or process is started; each
%% recorder notes whether the state already existed at the moment it ran.
boot_creates_summary_state_before_listener_and_sup_test_() ->
    boot_case(
      fun() ->
          persistent_term:erase(?SUMMARY_KEY),
          Self = self(),
          Note = fun(Tag) ->
                     Self ! {booted, Tag, persistent_term:get(?SUMMARY_KEY, undefined) =/= undefined}
                 end,
          meck:expect(prometheus_httpd, start, fun() -> Note(listener), {ok, self()} end),
          meck:expect(yuzu_gw_sup, start_link, fun() -> Note(supervisor), {ok, self()} end),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(true, receive {booted, listener, S1} -> S1 after 0 -> missing end),
          ?assertEqual(true, receive {booted, supervisor, S2} -> S2 after 0 -> missing end)
      end).

%%%===================================================================
%%% Boot wiring: the upstream crash-report redaction filter (#1197)
%%%===================================================================

%% yuzu_gw_app:start/2 installs the yuzu_gw_crash_redact primary filter before
%% the supervision tree starts (so the upstream's first crash is already
%% redacted) and stop/1 removes it. Nothing else boots the app, so a deleted
%% install or remove call is invisible without this.
boot_installs_crash_filter_before_sup_and_stop_removes_it_test_() ->
    boot_case(
      fun() ->
          Self = self(),
          meck:expect(yuzu_gw_sup, start_link,
                      fun() -> Self ! {sup_started, crash_filter_installed()}, {ok, self()} end),
          ?assertEqual(false, crash_filter_installed()),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(true, receive {sup_started, F} -> F after 0 -> missing end),
          ?assertEqual(true, crash_filter_installed()),
          ?assertEqual(ok, yuzu_gw_app:stop([])),
          ?assertEqual(false, crash_filter_installed())
      end).

%% A supervision tree that does not start must not leave the filter behind.
boot_removes_crash_filter_when_the_tree_does_not_start_test_() ->
    boot_case(
      fun() ->
          meck:expect(yuzu_gw_sup, start_link, fun() -> {error, boom} end),
          ?assertEqual({error, boom}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(false, crash_filter_installed())
      end).

%% yuzu_gw_app:start/2 creates the WARN limit state of yuzu_gw_safe_call before
%% the supervision tree starts, so a burst of first failures shares one limit.
boot_creates_safe_call_limits_before_sup_test_() ->
    boot_case(
      fun() ->
          Keys = ?SAFE_CALL_KEYS,
          [persistent_term:erase(K) || K <- Keys],
          Self = self(),
          meck:expect(yuzu_gw_sup, start_link,
                      fun() ->
                          Self ! {sup_started, [persistent_term:get(K, undefined) =/= undefined
                                                || K <- Keys]},
                          {ok, self()}
                      end),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual([true, true, true, true],
                       receive {sup_started, L} -> L after 0 -> missing end)
      end).

%%%===================================================================
%%% Boot wiring: TCP_NODELAY on the upstream channel
%%%===================================================================

%% yuzu_gw_app:start/2 applies the upstream channel's nodelay rewrite before the
%% supervision tree starts (the tree holds the channel's only callers, so no
%% call can see the channel mid-restart). Nothing else boots the app, so a
%% deleted or reordered apply_nodelay/0 call is invisible without this.
boot_applies_upstream_nodelay_before_sup_test_() ->
    boot_case(
      [yuzu_gw_upstream_channel],
      fun() ->
          Self = self(),
          meck:expect(yuzu_gw_upstream_channel, apply_nodelay,
                      fun() -> persistent_term:put(?NODELAY_KEY, true), ok end),
          meck:expect(yuzu_gw_sup, start_link,
                      fun() ->
                          Self ! {sup_started, persistent_term:get(?NODELAY_KEY, false)},
                          {ok, self()}
                      end),
          ?assertMatch({ok, _}, yuzu_gw_app:start(normal, [])),
          ?assertEqual(true, receive {sup_started, A} -> A after 0 -> missing end),
          ?assertEqual(1, meck:num_calls(yuzu_gw_upstream_channel, apply_nodelay, []))
      end).

crash_filter_installed() ->
    lists:keymember(yuzu_gw_crash_redact, 1, maps:get(filters, logger:get_primary_config())).

%% A boot test: Body runs with ?BOOT_MODS (and Extra, passthrough) mocked and
%% the process-wide state boot touches saved; boot_cleanup/1 puts it all back.
%% The 60 s bound is far above the work (milliseconds) so it only ever fires
%% on a genuine hang, and the cleanup still runs then.
boot_case(Body) ->
    boot_case([], Body).

boot_case(Extra, Body) ->
    {setup,
     fun() -> boot_setup(Extra) end,
     fun boot_cleanup/1,
     {timeout, 60, Body}}.

boot_setup(Extra) ->
    PrevCookieFlag = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE"),
    PrevPrometheus = application:get_env(prometheus, prometheus_http),
    AbsentKeys = [K || K <- [?SUMMARY_KEY | ?SAFE_CALL_KEYS],
                       persistent_term:get(K, undefined) =:= undefined],
    %% yuzu_gw_app:stop/1 drains every member of the `all_agents' pg group and
    %% spends up to a second on each one that does not answer. A member left
    %% there by another module is not this test's business and must not be able
    %% to push stop/1 past the test's time bound, so park them for the
    %% duration (cleanup joins the survivors back).
    Parked = park_foreign_agents(),
    %% rebar3 runs eunit on a named node with a short cookie.
    os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", "1"),
    ok = yuzu_gw_crash_redact:remove(),
    Fixture = #{cookie_flag => PrevCookieFlag, prometheus => PrevPrometheus,
                absent_keys => AbsentKeys, parked => Parked, extra => Extra},
    try
        ok = meck:new(?BOOT_MODS, [non_strict, no_link]),
        [ok = meck:new(M, [passthrough, no_link]) || M <- Extra],
        meck:expect(yuzu_gw_telemetry, setup, fun() -> ok end),
        meck:expect(prometheus_httpd, start, fun() -> {ok, self()} end),
        meck:expect(yuzu_gw_sup, start_link, fun() -> {ok, self()} end),
        meck:expect(yuzu_gw_heartbeat_buffer, flush_sync, fun() -> ok end),
        Fixture
    catch Class:Reason:Stack ->
        boot_cleanup(Fixture),
        erlang:raise(Class, Reason, Stack)
    end.

boot_cleanup(#{cookie_flag := PrevCookieFlag, prometheus := PrevPrometheus,
               absent_keys := AbsentKeys, parked := Parked, extra := Extra}) ->
    catch meck:unload(?BOOT_MODS ++ Extra),
    ok = yuzu_gw_crash_redact:remove(),
    case PrevCookieFlag of
        false -> os:unsetenv("YUZU_GW_ALLOW_DEFAULT_COOKIE");
        Prev  -> os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", Prev)
    end,
    case PrevPrometheus of
        {ok, V}   -> application:set_env(prometheus, prometheus_http, V);
        undefined -> application:unset_env(prometheus, prometheus_http)
    end,
    [persistent_term:erase(K) || K <- AbsentKeys],
    persistent_term:erase(?SUMMARY_KEY),
    persistent_term:erase(?NODELAY_KEY),
    unpark_foreign_agents(Parked).

park_foreign_agents() ->
    Members = try pg:get_members(yuzu_gw, all_agents) catch _:_ -> [] end,
    _ = [pg:leave(yuzu_gw, all_agents, P) || P <- Members],
    Members.

unpark_foreign_agents(Parked) ->
    Alive = [P || P <- Parked, is_process_alive(P)],
    case Alive of
        [] -> ok;
        _  -> catch pg:join(yuzu_gw, all_agents, Alive), ok
    end.
