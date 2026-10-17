%%%-------------------------------------------------------------------
%%% @doc Shared EUnit helper: the fixture pieces every test module that runs a
%%% real `yuzu_gw_upstream' re-wrote by hand.
%%%
%%% - `stop_upstream/0': stop a running upstream, silently (a prior module may
%%%   have leaked one).
%%% - `start_upstream/0': start one that the fixture owns (unlinked, so a kill
%%%   in a test does not take the test process with it).
%%% - `save_env/1' and `restore_env/1': remember application env keys and put
%%%   them back (or unset them when they were not set).
%%% - `set_breaker_env/1': a failure threshold and reset timers far beyond a
%%%   test, so nothing races a reset timer.
%%% - `trip_breaker/2': open the breaker with failing registrations.
%%%
%%% Not a test module: it exports no `*_test' function and does not include
%%% eunit.hrl (which would export test/0), so eunit finds nothing to run in it
%%% (same as `yuzu_gw_test_registry').
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_test_upstream).

-export([stop_upstream/0, start_upstream/0,
         save_env/1, restore_env/1, set_breaker_env/1,
         trip_breaker/2]).

%% The breaker timers a test runs with: far beyond any test.
-define(FAR_MS, 600000).

-spec stop_upstream() -> ok.
stop_upstream() ->
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Pid       -> catch unlink(Pid),
                     catch gen_server:stop(Pid, shutdown, 5000),
                     ok
    end.

%% @doc Start the real upstream and unlink it: the fixture owns its lifetime.
-spec start_upstream() -> pid().
start_upstream() ->
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    unlink(Pid),
    Pid.

-spec save_env([atom()]) -> [{atom(), {ok, term()} | undefined}].
save_env(Keys) ->
    [{Key, application:get_env(yuzu_gw, Key)} || Key <- Keys].

-spec restore_env([{atom(), {ok, term()} | undefined}]) -> ok.
restore_env(Prev) ->
    lists:foreach(fun({Key, {ok, V}}) -> application:set_env(yuzu_gw, Key, V);
                     ({Key, undefined}) -> application:unset_env(yuzu_gw, Key)
                  end, Prev).

%% @doc Set the failure threshold and push both reset timers out of reach.
-spec set_breaker_env(pos_integer()) -> ok.
set_breaker_env(Threshold) ->
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, Threshold),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, ?FAR_MS),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, ?FAR_MS),
    ok.

%% @doc Send Count registrations that must fail (the caller has mocked the
%% client to fail) and assert the breaker is open.
-spec trip_breaker(map(), pos_integer()) -> ok.
trip_breaker(Request, Count) ->
    [{error, _} = yuzu_gw_upstream:proxy_register(Request) || _ <- lists:seq(1, Count)],
    case yuzu_gw_upstream:circuit_state() of
        open  -> ok;
        State -> erlang:error({breaker_not_open, State})
    end.
