%%%-------------------------------------------------------------------
%%% @doc EUnit tests for registration replay on upstream reconnect.
%%%
%%% When yuzu_gw_upstream detects the upstream connection coming back
%%% after a failure, it must re-proxy a ProxyRegister for every agent
%%% the registry currently holds — otherwise a freshly-restarted C++
%%% server comes up with an empty registry and the agents the gateway
%%% still holds are silently stranded.
%%%
%%% These tests drive the *closed-state* recovery path (RPC failures
%%% below the trip threshold, then a success) and the *half_open ->
%%% closed* recovery path, and assert:
%%%   - reconnect with N registered agents => N replay ProxyRegister RPCs
%%%   - reconnect with zero agents => no replay RPCs
%%%   - an agent deregistered before reconnect is NOT replayed
%%%   - the replayed payload is byte-identical to the stored RegisterRequest
%%%   - the half_open -> closed transition also triggers replay
%%%
%%% Real:  yuzu_gw_registry (needs pg + ETS — all_register_reqs/0 reads
%%%        straight from the table).
%%% Mocks: grpcbox_client, telemetry.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registration_replay_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture — fresh upstream per test, shared real registry
%%%===================================================================

replay_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"reconnect re-proxies every registered agent",
       fun reconnect_replays_all_agents/0},
      {"reconnect with zero agents sends no replay rpc",
       fun reconnect_zero_agents_no_rpc/0},
      {"agent deregistered before reconnect is not replayed",
       fun deregistered_agent_not_replayed/0},
      {"replayed payload is byte-identical to stored request",
       fun replay_payload_is_verbatim/0},
      {"half_open to closed transition triggers replay",
       fun half_open_recovery_triggers_replay/0},
      {"HA WS-4 4.4: an ADOPTED replay re-announces CONNECTED",
       fun adopted_replay_reannounces_connected/0},
      {"HA WS-4 4.4: a SUPERSEDED replay counts as breaker success and "
       "forces reconnect",
       fun superseded_replay_forces_reconnect/0}
     ]}.

setup() ->
    %% pg + a real registry, race-safe across modules (#1403 / #336).
    yuzu_gw_test_registry:ensure(),

    %% Clean up stale mocks from prior modules.
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_agent),

    %% Fail loud at the boundary if a prior test leaked the real
    %% yuzu_gw_upstream gen_server — a meck stub coexisting with the
    %% registered process would make this suite time out opaquely (#336).
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Leaked    -> catch unlink(Leaked),
                     catch gen_server:stop(Leaked, shutdown, 1000)
    end,

    meck:new(grpcbox_client, [non_strict, no_link]),
    %% Default: every RPC succeeds. Individual tests override this.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{}, #{}}
    end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    %% HA WS-4 4.4 (`#4246` #6): mocked at the FIXTURE level (unloaded in
    %% cleanup/1 unconditionally, unlike the old per-test meck:new/unload
    %% this replaced) so a failed assertion mid-test can never leave
    %% yuzu_gw_agent mocked for every module that runs after this one —
    %% `passthrough` means only reannounce/2 and disconnect/1 are
    %% intercepted; every other yuzu_gw_agent function used elsewhere in
    %% this suite (none, today) would fall through to the real code.
    meck:new(yuzu_gw_agent, [passthrough, no_link]),
    meck:expect(yuzu_gw_agent, reannounce, fun(_Pid, _SessionId) -> ok end),
    meck:expect(yuzu_gw_agent, disconnect, fun(_Pid) -> ok end),

    %% Low threshold + fast timers + tight replay spacing so the tests
    %% run quickly. Threshold 5 means 1-2 failures stay closed — that is
    %% the closed-state recovery path the observed bug exercises.
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 5),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 150),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 1000),
    application:set_env(yuzu_gw, registration_replay_spacing_ms, 3),

    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    UpPid.

cleanup(UpPid) ->
    %% Synchronous stop — exit/shutdown + sleep is racy (#336).
    catch unlink(UpPid),
    catch gen_server:stop(UpPid, shutdown, 5000),
    %% Drop every agent this run registered so the shared registry stays
    %% clean for the next test / module. deregister_agent is a cast, so
    %% poll until the table is empty rather than guessing a sleep.
    lists:foreach(fun(Id) -> yuzu_gw_registry:deregister_agent(Id) end,
                  yuzu_gw_registry:all_agents()),
    wait_until(fun() -> yuzu_gw_registry:agent_count() =:= 0 end, 2000),
    meck:unload([grpcbox_client, telemetry, yuzu_gw_agent]),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

reconnect_replays_all_agents() ->
    N = 4,
    Agents = register_n_agents(N),

    %% Drive a closed-state recovery: one failing RPC (below threshold,
    %% circuit stays closed), then reset history, then a succeeding RPC.
    %% The success-after-failure is the reconnect signal.
    cause_one_failure(),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    %% The trigger RPC itself succeeds and is a ProxyRegister.
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    %% Replay drips one ProxyRegister per registered agent. Plus the
    %% trigger call itself => N + 1 ProxyRegister RPCs total.
    ok = wait_for_proxy_register_count(N + 1, 3000),

    %% Every registered agent's stored request must appear in the
    %% replayed set (the trigger request is distinct and excluded).
    Replayed = proxy_register_requests(),
    lists:foreach(fun({_Id, Req}) ->
        ?assert(lists:member(Req, Replayed))
    end, Agents).

reconnect_zero_agents_no_rpc() ->
    %% No agents registered at all.
    ?assertEqual(0, count_test_agents()),

    cause_one_failure(),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    %% Only the trigger RPC — the replay finds nothing to re-proxy.
    %% Give the (empty) replay cast time to be processed.
    ok = wait_for_proxy_register_count(1, 2000),
    timer:sleep(80),  %% would-be drip window; nothing should arrive
    ?assertEqual(1, proxy_register_count()).

deregistered_agent_not_replayed() ->
    N = 3,
    Agents = register_n_agents(N),
    %% Deregister the middle agent *before* the reconnect — it must not
    %% be replayed. all_register_reqs/0 reads ETS at replay time, so the
    %% deregister just has to land first.
    {DroppedId, DroppedReq} = lists:nth(2, Agents),
    yuzu_gw_registry:deregister_agent(DroppedId),
    wait_until(fun() -> yuzu_gw_registry:lookup(DroppedId) =:= error end, 2000),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    %% N-1 surviving agents + the trigger call.
    ok = wait_for_proxy_register_count(N, 3000),
    timer:sleep(80),  %% let any stray drip step land before asserting
    ?assertEqual(N, proxy_register_count()),

    Replayed = proxy_register_requests(),
    %% The dropped agent's request is absent...
    ?assertNot(lists:member(DroppedReq, Replayed)),
    %% ...and the two survivors are present.
    Survivors = [R || {Id, R} <- Agents, Id =/= DroppedId],
    lists:foreach(fun(Req) ->
        ?assert(lists:member(Req, Replayed))
    end, Survivors).

replay_payload_is_verbatim() ->
    %% A single agent with a rich RegisterRequest — the replayed bytes
    %% must equal the stored term exactly (this is why option (a) stashes
    %% the verbatim request rather than reconstructing it: the top-level
    %% enrollment_token is not otherwise recoverable).
    Id  = unique_id(<<"verbatim">>),
    Req = #{info => #{agent_id => Id,
                      hostname => <<"verbatim-host">>,
                      plugins  => [#{name => <<"svc">>}]},
            enrollment_token => <<"tok-secret-123">>},
    Pid = spawn_dummy(),
    ok = yuzu_gw_registry:register_agent(Id, Pid, <<"sess-verbatim">>,
                                         [<<"svc">>], <<"verbatim-host">>, Req),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    succeed_rpcs(),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    ok = wait_for_proxy_register_count(2, 3000),  %% trigger + 1 replay
    Replayed = proxy_register_requests(),
    ?assert(lists:member(Req, Replayed)),
    kill_dummy(Pid).

half_open_recovery_triggers_replay() ->
    %% Drive the full circuit trip: 5 consecutive failures -> open, wait
    %% for the half_open timer, then succeed the probe. The half_open ->
    %% closed transition must also trigger the replay.
    N = 2,
    Agents = register_n_agents(N),

    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    lists:foreach(fun(_) ->
        _ = yuzu_gw_upstream:proxy_register(trigger_req())
    end, lists:seq(1, 5)),
    ?assertEqual(open, yuzu_gw_upstream:circuit_state()),

    %% Wait for the open -> half_open timer (150ms reset).
    ok = wait_until(fun() ->
        yuzu_gw_upstream:circuit_state() =:= half_open
    end, 2000),

    meck:reset(grpcbox_client),
    succeed_rpcs(),
    %% This probe succeeds: half_open -> closed, which schedules replay.
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),

    ok = wait_for_proxy_register_count(N + 1, 3000),
    Replayed = proxy_register_requests(),
    lists:foreach(fun({_Id, Req}) ->
        ?assert(lists:member(Req, Replayed))
    end, Agents).

adopted_replay_reannounces_connected() ->
    %% HA WS-4 4.4 (`#4246` #6): a successful ADOPT-S replay must tell the
    %% still-live agent process to re-send its own CONNECTED, so the
    %% server's freshly-installed (and placement-wiped, per
    %% gateway_service_impl.cpp's ProxyRegister) AgentSession converges.
    %% Verified via the fixture-level meck on yuzu_gw_agent (setup/0)
    %% rather than a real gen_statem — the WIRING is this file's concern;
    %% yuzu_gw_agent_tests.erl covers the state-function's own reaction
    %% to the cast.
    Id  = unique_id(<<"adopt">>),
    Req = agent_req(Id),
    Pid = spawn_dummy(),
    SessionId = <<"sess-", Id/binary>>,
    ok = yuzu_gw_registry:register_agent(Id, Pid, SessionId, [<<"svc">>], <<"host">>, Req),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    %% Distinguish the trigger RPC (always succeeds, kicking off the
    %% replay) from THIS agent's own replayed request (verbatim-equal to
    %% Req, per replay_payload_is_verbatim's own precedent) by CONTENT —
    %% Path is identical ("ProxyRegister") for both.
    meck:expect(grpcbox_client, unary, fun(_, Path, IncomingReq, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                case IncomingReq of
                    Req -> {ok, #{session_id => SessionId}, #{}};
                    _   -> {ok, #{session_id => <<"ok">>}, #{}}
                end
        end
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    ok = wait_for_proxy_register_count(2, 3000), %% trigger + 1 replay
    ok = wait_until(fun() -> length(meck:history(yuzu_gw_agent)) > 0 end, 2000),
    ReannounceCalls = [{P, S} || {_, {yuzu_gw_agent, reannounce, [P, S]}, _}
                                     <- meck:history(yuzu_gw_agent)],
    ?assert(lists:member({Pid, SessionId}, ReannounceCalls)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    kill_dummy(Pid).

superseded_replay_forces_reconnect() ->
    %% HA WS-4 4.4 (`#4246` #6): a genuine stale/zombie replay (the
    %% server's presented-session row belongs to a DIFFERENT, live
    %% session) must (a) NOT trip the circuit breaker — the server
    %% answered authoritatively, this is not an outage — and (b) force
    %% this process to reconnect via yuzu_gw_agent:disconnect/1, per
    %% gateway_route_store.hpp's FORWARD NOTE (agent-driven reconnect is
    %% the only sanctioned recovery for a superseded session). Mocked at
    %% the fixture level (setup/0).
    Id  = unique_id(<<"zombie">>),
    Req = agent_req(Id),
    Pid = spawn_dummy(),
    SessionId = <<"sess-", Id/binary>>,
    ok = yuzu_gw_registry:register_agent(Id, Pid, SessionId, [<<"svc">>], <<"host">>, Req),

    cause_one_failure(),
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, IncomingReq, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                case IncomingReq of
                    %% ?GRPC_STATUS_FAILED_PRECONDITION (grpcbox.hrl) is the
                    %% BINARY digit string <<"9">> — the raw grpc-status
                    %% trailer value (grpcbox_client_stream.erl reads it
                    %% straight off the HTTP/2 header, never converting to
                    %% an integer). Using the integer 9 here (as the
                    %% pre-existing proxy_register_error test's OWN mock
                    %% does for a different status) would silently miss
                    %% do_replay_one's `Status =:= ?GRPC_STATUS_FAILED_PRECONDITION`
                    %% guard and fall through to the generic error branch.
                    Req -> {error, {<<"9">>, <<"session superseded; reconnect">>}, #{}};
                    _   -> {ok, #{session_id => <<"ok">>}, #{}}
                end
        end
    end),
    {ok, _} = yuzu_gw_upstream:proxy_register(trigger_req()),

    ok = wait_for_proxy_register_count(2, 3000), %% trigger + 1 replay attempt
    ok = wait_until(fun() -> length(meck:history(yuzu_gw_agent)) > 0 end, 2000),
    DisconnectCalls = [P || {_, {yuzu_gw_agent, disconnect, [P]}, _}
                                <- meck:history(yuzu_gw_agent)],
    ?assert(lists:member(Pid, DisconnectCalls)),
    ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
    kill_dummy(Pid).

%%%===================================================================
%%% Helpers — registry population
%%%===================================================================

%% Register N agents in the shared registry, each with a uniquely
%% identifiable verbatim RegisterRequest. Returns [{AgentId, Req}].
register_n_agents(N) ->
    lists:map(fun(I) ->
        Id  = unique_id(integer_to_binary(I)),
        Req = agent_req(Id),
        Pid = spawn_dummy(),
        ok = yuzu_gw_registry:register_agent(
               Id, Pid, <<"sess-", Id/binary>>, [<<"svc">>], <<"host">>, Req),
        {Id, Req}
    end, lists:seq(1, N)).

%% A per-agent RegisterRequest, tagged so it is distinguishable from
%% both other agents and the trigger request.
agent_req(Id) ->
    #{info => #{agent_id => Id,
                hostname => <<"host-", Id/binary>>,
                plugins  => [#{name => <<"svc">>}]},
      enrollment_token => <<"enroll-", Id/binary>>}.

%% The request used for the RPCs that drive circuit transitions. Tagged
%% distinctly so it is never mistaken for a replayed agent request.
trigger_req() ->
    #{info => #{agent_id => <<"__trigger__">>}}.

%% Count agents currently in the registry whose id was minted by this
%% module (unique_id/1 prefixes with the test pid). Used to assert a
%% clean starting state without disturbing other suites' agents.
count_test_agents() ->
    Prefix = id_prefix(),
    length([Id || Id <- yuzu_gw_registry:all_agents(),
                  binary:match(Id, Prefix) =:= {0, byte_size(Prefix)}]).

%%%===================================================================
%%% Helpers — circuit breaker driving
%%%===================================================================

%% One failing RPC. With threshold 5 the circuit stays closed but
%% cb_failures becomes 1 — the precondition for closed-state recovery.
cause_one_failure() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    {error, _} = yuzu_gw_upstream:proxy_register(trigger_req()),
    ok.

%% Make every subsequent RPC succeed.
succeed_rpcs() ->
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{session_id => <<"ok">>}, #{}}
    end).

%%%===================================================================
%%% Helpers — meck history inspection
%%%===================================================================

%% All ProxyRegister request payloads currently in grpcbox_client history.
proxy_register_requests() ->
    [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _}
                <- meck:history(grpcbox_client),
            is_binary(Path),
            binary:match(Path, <<"ProxyRegister">>) =/= nomatch].

proxy_register_count() ->
    length(proxy_register_requests()).

%% Poll until exactly Expected ProxyRegister RPCs have been recorded.
wait_for_proxy_register_count(Expected, Timeout) ->
    wait_until(fun() -> proxy_register_count() =:= Expected end, Timeout).

%%%===================================================================
%%% Helpers — generic
%%%===================================================================

%% Poll Pred every 10ms until it returns true or Timeout elapses.
wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false ->
            timer:sleep(10),
            wait_until(Pred, Timeout - 10)
    end.

%% A unique, this-module-attributable agent id.
unique_id(Suffix) ->
    <<(id_prefix())/binary, Suffix/binary>>.

id_prefix() ->
    PidBin = list_to_binary(pid_to_list(self())),
    <<"replay-", PidBin/binary, "-">>.

spawn_dummy() ->
    spawn(fun() -> receive stop -> ok end end).

kill_dummy(Pid) ->
    Pid ! stop.
