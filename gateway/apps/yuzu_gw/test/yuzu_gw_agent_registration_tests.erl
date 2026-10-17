%%%-------------------------------------------------------------------
%%% @doc How an agent process registers, seen from the agent supervisor
%%% (PR #5695, 5,000-agent work).
%%%
%%% There is one `yuzu_gw_agent_sup' per gateway, and `supervisor:start_child'
%%% does not return until the child's init/1 has. The agent used to make its
%%% registry call (30 s timeout) inside init/1, so a registry that was slow,
%%% or busy with a reconnect storm, held the supervisor too: every other
%%% Subscribe's start_child, and every child EXIT, queued behind it. The
%%% registration now runs as the agent's first event after init/1 returns.
%%% `yuzu_gw_agent_sup:start_agent/1' (the Subscribe handler's call) still
%%% answers only once the registration is decided, with the same results as
%%% before, but it waits in the CALLER, not in the supervisor.
%%%
%%% Refusals must never take the agent tree down. The supervisor has restart
%%% intensity 0, and its children are `temporary', which the supervisor never
%%% restarts, so an exit never counts against the intensity; a refused agent
%%% also exits `normal', so a storm of refusals writes no crash reports.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_registration_tests).
-include_lib("eunit/include/eunit.hrl").

-define(CAP_KEY, {yuzu_gw_registry, max_sessions_per_connection}).
-define(BURST, 50).

registration_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{timeout, 60, {"start_child returns while the registry is blocked",
                     fun start_child_does_not_wait_for_the_registry/0}},
      {"start_agent answers once the agent is in the routing table",
       fun start_agent_waits_for_registration/0},
      {"the agent joins its own {agent, Id} group and no other",
       fun agent_joins_only_its_own_group/0},
      {"a superseded agent leaves {agent, Id}",
       fun superseded_agent_leaves_group/0},
      {timeout, 60, {"a burst of refused registrations leaves the supervisor running",
                     fun refusal_burst_keeps_the_supervisor/0}},
      {"start_link reports a refusal without killing its linked caller",
       fun start_link_refusal_spares_the_caller/0}]}.

setup() ->
    yuzu_gw_test_registry:ensure(),
    catch meck:unload([yuzu_gw_upstream, telemetry]),
    ?assertEqual(undefined, whereis(yuzu_gw_upstream)),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    ok = meck:new(telemetry, [passthrough, no_link]),
    ok = meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    case whereis(yuzu_gw_agent_sup) of
        undefined -> ok;
        Old       -> yuzu_gw_test_registry:stop_agent_sup(Old)
    end,
    {ok, Sup} = yuzu_gw_agent_sup:start_link(),
    unlink(Sup),
    erase(holders),
    #{sup => Sup, cap => persistent_term:get(?CAP_KEY, undefined)}.

cleanup(#{sup := Sup, cap := Cap}) ->
    %% A test that failed with the registry suspended must not leave it so.
    catch sys:resume(yuzu_gw_registry),
    yuzu_gw_test_registry:stop_agent_sup(Sup),
    %% foreach runs setup, the test and cleanup in one process.
    [exit(P, kill) || P <- holders()],
    erase(holders),
    case Cap of
        undefined -> persistent_term:erase(?CAP_KEY);
        _         -> persistent_term:put(?CAP_KEY, Cap)
    end,
    _ = sys:get_state(yuzu_gw_registry),
    catch meck:unload([yuzu_gw_upstream, telemetry]),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

%% Ten start_child calls, made one after another while the registry handles
%% nothing, all return. With the registry call inside init/1 the first one
%% would not return until that call timed out (30 s).
start_child_does_not_wait_for_the_registry() ->
    Ids = [iolist_to_binary(["reg-blocked-", integer_to_binary(I)]) || I <- lists:seq(1, 10)],
    Self = self(),
    ok = sys:suspend(yuzu_gw_registry),
    Caller = spawn(fun() ->
        Results = [supervisor:start_child(yuzu_gw_agent_sup, [args(Id)]) || Id <- Ids],
        Self ! {started, self(), Results}
    end),
    Results = receive {started, Caller, R} -> R
              after 2000 -> exit(Caller, kill), start_child_blocked
              end,
    ok = sys:resume(yuzu_gw_registry),
    ?assertMatch([_ | _], Results),
    ?assert(lists:all(fun({ok, P}) -> is_pid(P); (_) -> false end, Results)),
    %% Once the registry runs again every agent registers.
    ok = wait_until(fun() ->
        %% lookup/1 answers the bare atom `error' until the row is there, so
        %% the predicate matches instead of taking element/2 of it.
        lists:all(fun(Id) -> case yuzu_gw_registry:lookup(Id) of
                                 {ok, _} -> true;
                                 _ -> false
                             end
                  end, Ids)
    end, 5000),
    ?assertEqual(10, yuzu_gw_agent_sup:count()).

start_agent_waits_for_registration() ->
    Id = <<"reg-wait-1">>,
    {ok, Pid} = yuzu_gw_agent_sup:start_agent(args(Id)),
    %% No polling: the answer means the row is there.
    ?assertEqual({ok, Pid}, yuzu_gw_registry:lookup(Id)),
    ?assertEqual([Pid], pg:get_local_members(yuzu_gw, {agent, Id})).

%% The registry joins no pg group; the agent joins `{agent, Id}' (read by the
%% cross-node lookup fallback) itself, and leaves it when it disconnects.
agent_joins_only_its_own_group() ->
    Id = <<"reg-group-1">>,
    Args = args(Id),
    {ok, Pid} = yuzu_gw_agent_sup:start_agent(
                  Args#{agent_info => #{hostname => <<"h">>,
                                        plugins => [#{name => N} || N <- plugins()]}}),
    ?assertEqual([{agent, Id}], groups_of(Pid)),
    Mon = monitor(process, Pid),
    yuzu_gw_agent:disconnect(Pid),
    receive {'DOWN', Mon, process, Pid, _} -> ok after 5000 -> error(agent_stayed) end,
    ok = wait_until(fun() -> pg:get_local_members(yuzu_gw, {agent, Id}) =:= [] end, 2000).

%% An agent that registers again under a new session while its old process is
%% still alive: the old process stops being a member of `{agent, Id}', so the
%% cross-node fallback cannot pick it.
superseded_agent_leaves_group() ->
    Id = <<"reg-super-1">>,
    {ok, Old} = yuzu_gw_agent_sup:start_agent(args(Id)),
    {ok, New} = yuzu_gw_agent_sup:start_agent((args(Id))#{session_id => <<"reg-super-1-b">>}),
    ?assert(is_process_alive(Old)),
    ok = wait_until(fun() -> pg:get_local_members(yuzu_gw, {agent, Id}) =:= [New] end, 2000),
    ?assertEqual({ok, New}, yuzu_gw_registry:lookup(Id)).

%% With the connection's quota (1) held by another agent, a burst of
%% registrations is refused, both through start_agent/1 and through a bare
%% start_child. The supervisor is the same process afterwards and holds no
%% child, and nothing was logged as a crash.
refusal_burst_keeps_the_supervisor() ->
    Sup = whereis(yuzu_gw_agent_sup),
    persistent_term:put(?CAP_KEY, 1),
    Conn = holder(),
    Held = holder(),
    ok = yuzu_gw_registry:register_agent(<<"reg-burst-held">>, Held, <<"reg-burst-held-s">>,
                                         [], <<>>, #{}, Conn),
    Logged = yuzu_gw_test_logs:capture(error, fun() ->
        Refused = [yuzu_gw_agent_sup:start_agent((args(burst_id(I)))#{conn_key => Conn})
                   || I <- lists:seq(1, ?BURST)],
        ?assertEqual(lists:duplicate(?BURST, {error, session_limit}), Refused),
        Bare = [supervisor:start_child(yuzu_gw_agent_sup,
                                       [(args(burst_id(?BURST + I)))#{conn_key => Conn}])
                || I <- lists:seq(1, ?BURST)],
        ?assertEqual(?BURST, length(Bare)),
        ok = wait_until(fun() -> yuzu_gw_agent_sup:count() =:= 0 end, 5000)
    end),
    %% A refusal is an answer, not a crash: no crash or supervisor report per
    %% refused agent (100 of them would bury a real fault in a storm).
    %% (The capture renders a report as its raw term: a proc_lib crash report is
    %% labelled {proc_lib,crash}, a supervisor one {supervisor,child_terminated}.)
    ?assertEqual(0, length([L || L <- Logged,
                                 binary:match(L, [<<"crash">>, <<"child_terminated">>])
                                     =/= nomatch])),
    ?assertEqual(Sup, whereis(yuzu_gw_agent_sup)),
    ?assert(is_process_alive(Sup)),
    ?assertEqual([], [I || I <- lists:seq(1, 2 * ?BURST),
                           yuzu_gw_registry:lookup(burst_id(I)) =/= error]),
    %% Still serving: an agent on a connection with room starts.
    {ok, Pid} = yuzu_gw_agent_sup:start_agent(args(<<"reg-burst-after">>)),
    ?assert(is_pid(Pid)).

%% yuzu_gw_agent:start_link/1 (used by tests and direct callers) answers the
%% refusal as {error, Reason}, and the refused process's exit does not take the
%% linked caller with it.
start_link_refusal_spares_the_caller() ->
    persistent_term:put(?CAP_KEY, 1),
    Conn = holder(),
    ok = yuzu_gw_registry:register_agent(<<"reg-link-held">>, holder(),
                                         <<"reg-link-held-s">>, [], <<>>, #{}, Conn),
    Self = self(),
    Caller = spawn(fun() ->
        R = yuzu_gw_agent:start_link((args(<<"reg-link-1">>))#{conn_key => Conn}),
        timer:sleep(100),
        Self ! {result, self(), R},
        receive stop -> ok end
    end),
    Mon = monitor(process, Caller),
    receive {result, Caller, R} -> ?assertEqual({error, session_limit}, R)
    after 5000 -> error(no_result)
    end,
    ?assert(is_process_alive(Caller)),
    Caller ! stop,
    receive {'DOWN', Mon, process, Caller, Reason} -> ?assertEqual(normal, Reason)
    after 2000 -> error(caller_stayed)
    end.

%%%===================================================================
%%% Helpers
%%%===================================================================

args(Id) ->
    #{agent_id     => Id,
      session_id   => <<Id/binary, "-s">>,
      stream_pid   => undefined,
      agent_info   => #{hostname => <<"h">>, plugins => [#{name => <<"svc">>}]},
      register_req => #{},
      peer_addr    => <<"127.0.0.1">>}.

burst_id(I) ->
    iolist_to_binary(["reg-burst-", integer_to_binary(I)]).

plugins() ->
    yuzu_gw_registry_cost_tests:plugin_names().

groups_of(Pid) ->
    lists:sort([G || G <- pg:which_groups(yuzu_gw),
                     lists:member(Pid, pg:get_local_members(yuzu_gw, G))]).

%% A stand-in process (a connection key, or an agent held on one), remembered
%% so that cleanup/1 can stop it.
holder() ->
    Pid = spawn(fun() -> receive stop -> ok end end),
    put(holders, [Pid | holders()]),
    Pid.

holders() ->
    case get(holders) of
        undefined -> [];
        L         -> L
    end.

wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of true -> ok; false -> {error, timeout} end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false -> timer:sleep(10), wait_until(Pred, Timeout - 10)
    end.
