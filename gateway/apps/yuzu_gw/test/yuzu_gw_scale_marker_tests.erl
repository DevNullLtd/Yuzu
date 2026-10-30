%%%-------------------------------------------------------------------
%%% @doc The scale suite's markers select what STARTED after them (#5695 Gate 8
%%% round 6): an attempt of the load generator (yuzu_gw_scale_fleet) takes its
%%% sequence number when it starts, not when it ends.
%%%
%%% A connection opened before a marker and failing after it used to take its
%%% number in the failure arm, after gun:await_up/3, so attempts/1 returned it as
%%% started after the marker; gateway_crash's no_register_failures_after_restart
%%% could then fail on an attempt made before the restart. Here gun is mocked so
%%% the connection's await_up blocks until the test lets it fail, with the
%%% marker taken in between.
%%%
%%% Real:  yuzu_gw_scale_fleet (in this node).
%%% Mocks: gun (open, await_up, close, flush).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_scale_marker_tests).
-include_lib("eunit/include/eunit.hrl").

-define(FLEET, yuzu_gw_scale_fleet).
-define(WAIT_MS, 5000).

marker_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [{timeout, 30, {"a connection opened before the marker that fails after it is not "
                     "counted after the marker",
                     fun opened_before_failed_after/0}},
      {timeout, 30, {"a connection opened after the marker that fails is counted after it",
                     fun opened_after_marker/0}}]}.

opened_before_failed_after() ->
    listen(),
    ok = ?FLEET:spawn_agents(#{from => 1, count => 1, mode => storm}),
    Agent = awaiting_up(),
    #{seq := Since} = ?FLEET:mark(),
    Agent ! fail,
    [{_, 1, _, _, Outcome}] = wait_attempts(1),
    ?assertEqual({connect_failed, timeout}, Outcome),
    ?assertEqual([], ?FLEET:attempts(Since)).

opened_after_marker() ->
    listen(),
    #{seq := Since} = ?FLEET:mark(),
    ok = ?FLEET:spawn_agents(#{from => 2, count => 1, mode => storm}),
    awaiting_up() ! fail,
    [{Id, 1, _, _, {connect_failed, timeout}}] = wait_attempts(1),
    ?assertMatch([{Id, 1, _, _, {connect_failed, timeout}}], ?FLEET:attempts(Since)).

%%--------------------------------------------------------------------
%% Fixture
%%--------------------------------------------------------------------

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    catch meck:unload(gun),
    meck:new(gun, [no_link]),
    meck:expect(gun, open, fun(_Ip, _Port, _Opts) ->
                                   {ok, spawn(fun() -> receive stop -> ok end end)}
                           end),
    %% Runs in the simulated agent: report to the test (registered by listen/0:
    %% eunit runs the test body in another process than setup, so self() here
    %% would be the wrong one), then fail when the test says so.
    meck:expect(gun, await_up, fun(_Conn, _Timeout, _MRef) ->
                                       ?MODULE ! {awaiting_up, self()},
                                       receive fail -> {error, timeout} end
                               end),
    meck:expect(gun, close, fun(Conn) -> Conn ! stop, ok end),
    meck:expect(gun, flush, fun(_Conn) -> ok end),
    ok = ?FLEET:start(#{targets => [{{127, 0, 0, 1}, 1}], plugins => [],
                        reconnect => false, prefix => <<"marker">>}),
    ok.

cleanup(_) ->
    catch ?FLEET:stop_all(),
    catch gen_server:stop(?FLEET, normal, 5000),
    persistent_term:erase({?FLEET, seq}),
    meck:unload(gun),
    catch unregister(?MODULE),
    ok.

%% The test process receives the agents' reports.
listen() ->
    catch unregister(?MODULE),
    true = register(?MODULE, self()),
    ok.

awaiting_up() ->
    receive {awaiting_up, Pid} -> Pid
    after ?WAIT_MS -> error(no_connection_opened)
    end.

wait_attempts(N) ->
    wait_attempts(N, ?WAIT_MS).

wait_attempts(N, Left) ->
    case ?FLEET:attempts() of
        L when length(L) >= N -> L;
        _ when Left =< 0 -> error({attempts_not_recorded, N});
        _ -> timer:sleep(10), wait_attempts(N, Left - 10)
    end.
