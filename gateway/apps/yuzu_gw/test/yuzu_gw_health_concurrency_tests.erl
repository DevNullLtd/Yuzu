%%%-------------------------------------------------------------------
%%% @doc The health port (/healthz, /readyz) serves its clients concurrently: a
%%% client that connects and sends nothing does not hold up the probes behind
%%% it. Before, the endpoint served one connection at a time and waited 5 s for
%%% each request, so one idle connection stalled liveness and readiness alike.
%%%
%%% Only /healthz is asked: it needs no other gateway process, so this module
%%% starts the endpoint alone (on an OS-assigned port, unlinked, stopped in
%%% cleanup) and leaves the readiness fixture to yuzu_gw_health_tests.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_health_concurrency_tests).
-include_lib("eunit/include/eunit.hrl").

idle_client_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun({Port, _Pid, _Prev}) ->
             [{timeout, 30, {"one idle client does not stall a probe",
                             fun() -> idle_clients_then_probe(Port, 1) end}},
              {timeout, 30, {"ten idle clients do not stall a probe",
                             fun() -> idle_clients_then_probe(Port, 10) end}},
              {timeout, 30, {"an idle client is closed after the request timeout",
                             fun() -> idle_client_closed(Port) end}}]
     end}.

setup() ->
    Prev = application:get_env(yuzu_gw, health_port),
    application:set_env(yuzu_gw, health_port, 0),
    %% A stale endpoint from another module would hold the registered name.
    case whereis(yuzu_gw_health) of
        undefined -> ok;
        Stale -> gen_server:stop(Stale, shutdown, 5000)
    end,
    {ok, Pid} = gen_server:start({local, yuzu_gw_health}, yuzu_gw_health, [], []),
    {ok, Port} = yuzu_gw_health:port(),
    {Port, Pid, Prev}.

cleanup({_Port, Pid, Prev}) ->
    catch gen_server:stop(Pid, shutdown, 5000),
    case Prev of
        {ok, V} -> application:set_env(yuzu_gw, health_port, V);
        undefined -> application:unset_env(yuzu_gw, health_port)
    end,
    ok.

%% N connections that send nothing, then a /healthz: answered at once, not
%% after N request timeouts.
idle_clients_then_probe(Port, N) ->
    Idle = [begin
                {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
                S
            end || _ <- lists:seq(1, N)],
    try
        T0 = erlang:monotonic_time(millisecond),
        {ok, P} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
        ok = gen_tcp:send(P, <<"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n">>),
        Answer = gen_tcp:recv(P, 0, 1500),
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        gen_tcp:close(P),
        ?assertMatch({ok, <<"HTTP/1.1 200", _/binary>>}, Answer),
        ?assert(Elapsed < 1500)
    after
        [gen_tcp:close(S) || S <- Idle]
    end.

%% A connection that never sends a request is closed by the endpoint, well
%% inside the old 5 s.
idle_client_closed(Port) ->
    {ok, S} = gen_tcp:connect({127, 0, 0, 1}, Port, [binary, {active, false}]),
    T0 = erlang:monotonic_time(millisecond),
    Result = gen_tcp:recv(S, 0, 10000),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    gen_tcp:close(S),
    ?assertEqual({error, closed}, Result),
    ?assert(Elapsed < 4000).
