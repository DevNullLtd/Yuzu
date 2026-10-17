%%%-------------------------------------------------------------------
%%% @doc Tests for the caller side of the calls that carry a RegisterRequest
%%% (#1197): yuzu_gw_upstream:proxy_register/1 and proxy_inventory/1,
%%% yuzu_gw_registry:register_agent/7 and the yuzu_gw_agent that makes it.
%%%
%%% The defect: the exit of a gen_server:call embeds the call, and so the
%%% request. The caller is a gRPC handler process; a crash report names the
%%% exit reason, and a handler wrapper that logged the exception would too,
%%% neither of which the crash report filter can tell is ours. Here every
%%% caller runs the call UNCAUGHT in a plain proc_lib process (as a handler
%%% would), with the crash report filter installed and a capturing handler
%%% that sees every event after the primary filters. The service handlers are
%%% run through yuzu_grpc_runner, the wrapper a real handler runs in, whose own
%%% rule is that a crash logs the method, the exception class and the top
%%% frame and nothing else. Each event is rendered with the default formatter
%%% and with ~p, and none may contain a credential marker. The server is
%%% absent (noproc), never answers (a fake, with a few milliseconds of call
%%% timeout) or dies serving the call.
%%%
%%% Positive controls make the same raw gen_server:call (and a handler wrapper
%%% that logs the exception) and require the markers to show, so a clean result
%%% cannot be an artefact of the harness.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_safe_call_tests).
-include_lib("eunit/include/eunit.hrl").
-include("yuzu_grpc.hrl").

-export([log/2]).  %% logger handler
-export([run_fun/2]).  %% a unary handler for yuzu_grpc_runner: runs the fun it is given

-define(HANDLER, yuzu_safe_call_test_log).
-define(M_TOKEN, <<"MARKER-enrollment-token-1c9e">>).
-define(M_CSR,   <<"MARKER-csr-pem-77d2">>).
-define(M_CERT,  <<"MARKER-machine-certificate-a35f">>).
-define(MARKERS, [?M_TOKEN, ?M_CSR, ?M_CERT]).
-define(TIMEOUT_KEY, upstream_call_timeout_ms).
-define(WAIT_MS, 5000).

safe_call_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"register: upstream not running answers upstream_unavailable, nothing leaks",
       fun register_noproc/0},
      {"runner: a crashing handler logs the method, the class and the top frame, nothing else",
       fun runner_crash_logs_no_request_no_reason/0},
      {"register: an upstream that never answers times out without leaking",
       fun register_timeout/0},
      {"register: an upstream that dies serving the call does not leak",
       fun register_died_serving/0},
      {"inventory: upstream not running answers upstream_unavailable, nothing leaks",
       fun inventory_noproc/0},
      {"inventory: an upstream that never answers times out without leaking",
       fun inventory_timeout/0},
      {"registry: register_agent with the registry not running answers an error, nothing leaks",
       fun registry_noproc/0},
      {"registry: a registry that never answers times out without leaking",
       fun registry_died_serving/0},
      {"agent: a registry that is not running refuses with a fixed reason, no crash report",
       fun agent_init_registry_down/0},
      {"the WARN names the exit class only, and at most one per second per server",
       fun warn_names_class_only_and_is_limited/0},
      {"exit_class reads only the shape of the reason",
       fun exit_class_shapes/0},
      {"init_limits creates the stamp of every warning kind",
       fun warn_kinds_have_stamps_after_init/0},
      {"warn_limited logs the first line, counts the rest and reports the count on the next",
       fun warn_limited_counts_suppressed_lines/0},
      {"warn_limited keeps the kinds apart and logs the first line of a kind without a stamp",
       fun warn_limited_kinds_are_independent/0},
      {"control: an uncaught gen_server:call to the same server does leak",
       fun control_raw_call_leaks/0},
      {"500 concurrent first failures after init_limits log at most two WARNs",
       fun warn_burst_is_limited_after_init/0},
      {"a server without a stamp logs no WARN and creates no stamp",
       fun missing_stamp_logs_nothing_and_creates_nothing/0},
      {"init_limits is idempotent: it resets the stamp and does not replace it",
       fun init_limits_is_idempotent/0},
      {"upstream_call_timeout_ms: 100..300000 is kept, anything else warns and takes 30000",
       fun call_timeout_validation/0},
      {"Register handler: the registry not running answers a fixed error, nothing leaks",
       fun register_handler_registry_down/0},
      {"Subscribe handler: the registry not running answers a fixed error, nothing leaks",
       fun subscribe_handler_registry_down/0},
      {"Subscribe handler: the agent supervisor not running answers a fixed error, nothing leaks",
       fun subscribe_handler_agent_sup_down/0},
      {"store_pending and take_pending answer registry_unavailable without a registry",
       fun pending_calls_without_registry/0},
      {"start_agent answers agent_sup_unavailable for an exit, and an error is not caught",
       fun start_agent_guard/0},
      {"router send_command with the router not running answers an error, nothing leaks",
       fun router_send_command_router_down/0},
      {"mgmt SendCommand through the runner with the router not running answers UNAVAILABLE (14) and logs one WARN",
       fun mgmt_send_command_router_down/0},
      {"control: a handler wrapper that logs the exception does leak",
       fun control_logging_wrapper_leaks/0}
     ]}.

setup() ->
    catch meck:unload(yuzu_gw_upstream),
    stop_named(yuzu_gw_upstream),
    ok = yuzu_gw_crash_redact:install(),
    Level = maps:get(level, logger:get_primary_config()),
    logger:set_primary_config(level, all),
    yuzu_gw_safe_call:reset_limits(),
    application:set_env(yuzu_gw, ?TIMEOUT_KEY, 100),
    %% each case reads the runner's line for its own failure: no rate limit
    application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, 0),
    Level.

cleanup(Level) ->
    catch logger:remove_handler(?HANDLER),
    ok = yuzu_gw_crash_redact:remove(),
    logger:set_primary_config(level, Level),
    application:unset_env(yuzu_gw, ?TIMEOUT_KEY),
    application:unset_env(yuzu_gw, grpc_runner_warn_interval_ms),
    stop_named(yuzu_gw_upstream),
    stop_named(yuzu_gw_registry),
    yuzu_gw_safe_call:reset_limits(),
    flush_events(),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

register_noproc() ->
    ?assertEqual(undefined, whereis(yuzu_gw_upstream)),
    {Result, Events} = run_caller(fun() -> yuzu_gw_upstream:proxy_register(req()) end),
    ?assertEqual({returned, {error, upstream_unavailable}}, Result),
    assert_no_markers(Events).

%% The runner is what a handler runs in. Whatever escapes a handler, the call
%% ends INTERNAL with a fixed message and the log carries the method, the
%% exception class and the top frame's M:F/Arity: never the exit reason (which
%% embeds the call), the stacktrace arguments (the frame of a badarg or a
%% function_clause carries them), the thrown term or the returned one.
runner_crash_logs_no_request_no_reason() ->
    start_fake(yuzu_gw_upstream, hang),
    Cases =
        [{"exit of a raw gen_server:call (the reason embeds the request)", <<"class=exit">>,
          fun(_Ctx) -> gen_server:call(yuzu_gw_upstream, {proxy_register, req()}, 50) end},
         {"badarg whose stacktrace arguments are the request", <<"ets:insert/2">>,
          fun(_Ctx) -> ets:insert(yuzu_gw_pending_missing_table, {<<"s">>, req()}) end},
         {"throw of the request", <<"class=throw">>,
          fun(_Ctx) -> throw(req()) end},
         {"a return that is no result", <<"class=bad_return">>,
          fun(_Ctx) -> req() end}],
    lists:foreach(
      fun({What, Needle, Fun}) ->
          {Result, Events} = run_caller(fun() ->
              via_runner(unary, ?MODULE, run_fun, #{request => #{call => Fun}})
          end),
          ?assertEqual({returned, {?GRPC_STATUS_INTERNAL, <<"internal error">>}}, Result, What),
          assert_no_markers(Events),
          Warns = [W || W <- warnings(Events), contains(W, <<"/test.Service/Method">>)],
          ?assertMatch([_], Warns, What),
          ?assert(contains(hd(Warns), Needle), What)
      end, Cases).

register_timeout() ->
    start_fake(yuzu_gw_upstream, hang),
    {Result, Events} = run_caller(fun() -> yuzu_gw_upstream:proxy_register(req()) end),
    ?assertEqual({returned, {error, upstream_unavailable}}, Result),
    assert_no_markers(Events),
    ?assert(has_warning(Events, <<"timeout">>)).

register_died_serving() ->
    start_fake(yuzu_gw_upstream, die),
    {Result, Events} = run_caller(fun() -> yuzu_gw_upstream:proxy_register(req()) end),
    ?assertEqual({returned, {error, upstream_unavailable}}, Result),
    assert_no_markers(Events),
    ?assert(has_warning(Events, <<"other">>)).

inventory_noproc() ->
    {Result, Events} = run_caller(fun() ->
        yuzu_gw_upstream:proxy_inventory(#{agent_id => ?M_TOKEN, plugin_data => ?M_CSR})
    end),
    ?assertEqual({returned, {error, upstream_unavailable}}, Result),
    assert_no_markers(Events).

inventory_timeout() ->
    start_fake(yuzu_gw_upstream, hang),
    {Result, Events} = run_caller(fun() ->
        yuzu_gw_upstream:proxy_inventory(#{agent_id => ?M_TOKEN, plugin_data => ?M_CSR})
    end),
    ?assertEqual({returned, {error, upstream_unavailable}}, Result),
    assert_no_markers(Events).

registry_noproc() ->
    stop_named(yuzu_gw_registry),
    {Result, Events} = run_caller(fun() -> register_agent() end),
    ?assertEqual({returned, {error, registry_unavailable}}, Result),
    assert_no_markers(Events),
    ?assert(has_warning(Events, <<"noproc">>)).

registry_died_serving() ->
    stop_named(yuzu_gw_registry),
    start_fake(yuzu_gw_registry, die),
    {Result, Events} = run_caller(fun() -> register_agent() end),
    ?assertEqual({returned, {error, registry_unavailable}}, Result),
    assert_no_markers(Events).

%% The agent is started the way the supervisor does (yuzu_gw_agent's start
%% function returns once the process exists; the registration is its first
%% event), and the caller waits for the outcome the way start_agent/1 does. A
%% registry that is not running is answered with the fixed reason, the process
%% stops `normal' (a refusal is not a crash: no crash report to print the
%% request), and nothing logged meanwhile carries the request.
agent_init_registry_down() ->
    stop_named(yuzu_gw_registry),
    capture_to_self(),
    Args = #{agent_id => <<"a-1">>, agent_info => #{hostname => <<"h">>},
             stream_pid => self(), peer_addr => <<"peer">>, session_id => <<"s-1">>,
             register_req => req()},
    Alias = alias([reply]),
    {ok, Pid} = gen_statem:start(yuzu_gw_agent, Args#{registered_ack => Alias}, []),
    ?assertEqual({error, registry_unavailable}, yuzu_gw_agent:await_registration(Pid, Alias)),
    ?assertNot(is_process_alive(Pid)),
    %% Give a late report (there should be none) time to arrive.
    timer:sleep(100),
    Events = drain_events(),
    ?assertEqual([], [E || E <- Events, is_agent_crash_report(E)]),
    assert_no_markers(Events).

%% The six closed kinds of warn_limited/3 each have a stamp as soon as init_limits/0
%% has run, so the first failures of a burst share it instead of each creating its
%% own (the race init_limits/0 exists to remove). The key shape is the one
%% warn_limited_kinds_are_independent/0 also reads.
warn_kinds_have_stamps_after_init() ->
    ok = yuzu_gw_safe_call:init_limits(),
    [?assertNotEqual(undefined, persistent_term:get({yuzu_gw_safe_call, {kind, Kind}}, undefined))
     || Kind <- [register_refused, register_peer_addr, register_failed, inventory_failed,
                 rpc_raised, rpc_answered_error]].

%% The stamp is held quiet around the burst, so the interval cannot pass in the
%% middle of it: the counts are exact.
warn_limited_counts_suppressed_lines() ->
    ok = yuzu_gw_safe_call:init_limits(),
    capture_to_self(),
    ok = yuzu_gw_safe_call:warn_limited(register_refused, "probe line ~b", [1]),
    ok = yuzu_gw_safe_call:hold_limit(register_refused),
    [ok = yuzu_gw_safe_call:warn_limited(register_refused, "probe line ~b", [N])
     || N <- lists:seq(2, 8)],
    First = [W || W <- warnings(drain_events()), contains(W, <<"probe line">>)],
    ?assertMatch([_], First),
    ?assert(contains(hd(First), <<"probe line 1">>)),
    ?assertNot(contains(hd(First), <<"suppressed">>)),
    ok = yuzu_gw_safe_call:expire_limit(register_refused),
    ok = yuzu_gw_safe_call:warn_limited(register_refused, "probe line ~b", [9]),
    Next = [W || W <- warnings(drain_events()), contains(W, <<"probe line">>)],
    ?assertMatch([_], Next),
    ?assert(contains(hd(Next), <<"probe line 9">>)),
    ?assert(contains(hd(Next), <<"(7 similar line(s) suppressed since the last)">>)),
    %% The count was taken: the line after that one carries none.
    ok = yuzu_gw_safe_call:expire_limit(register_refused),
    ok = yuzu_gw_safe_call:warn_limited(register_refused, "probe line ~b", [10]),
    Last = [W || W <- warnings(drain_events()), contains(W, <<"probe line">>)],
    ?assertMatch([_], Last),
    ?assertNot(contains(hd(Last), <<"suppressed">>)).

warn_limited_kinds_are_independent() ->
    ok = yuzu_gw_safe_call:init_limits(),
    capture_to_self(),
    ok = yuzu_gw_safe_call:warn_limited(register_refused, "kind one", []),
    ok = yuzu_gw_safe_call:warn_limited(register_peer_addr, "kind two", []),
    %% A kind nobody created a stamp for still logs its first line.
    ?assertEqual(undefined, persistent_term:get({yuzu_gw_safe_call, {kind, probe_unlisted_kind}},
                                                undefined)),
    ok = yuzu_gw_safe_call:warn_limited(probe_unlisted_kind, "kind three", []),
    Lines = [W || W <- warnings(drain_events()), contains(W, <<"kind ">>)],
    ?assertEqual(3, length(Lines)).

warn_names_class_only_and_is_limited() ->
    %% Not running: noproc. One WARN, however many callers fail in a burst.
    {_, E1} = run_caller(fun() ->
        _ = yuzu_gw_upstream:proxy_register(req()),
        _ = yuzu_gw_upstream:proxy_register(req()),
        yuzu_gw_upstream:proxy_inventory(#{})
    end),
    Warns = [W || W <- warnings(E1), contains(W, <<"yuzu_gw_upstream">>)],
    ?assertMatch([_], Warns),
    [W] = Warns,
    ?assert(contains(W, <<"noproc">>)),
    %% The line names the server and the class, and no request or reason.
    ?assertNot(contains(W, <<"gen_server">>)),
    ?assertNot(contains(W, <<"proxy_register">>)),
    %% The stamp is per server: another one still logs at once.
    ok = yuzu_gw_safe_call:init_limits([yuzu_gw_registry_probe]),
    start_fake(yuzu_gw_registry_probe, hang),
    ?assertEqual({error, x}, yuzu_gw_safe_call:call(yuzu_gw_registry_probe, ping, 20, x)),
    ?assertMatch([_|_], [M || M <- warnings(drain_events()),
                              contains(M, <<"yuzu_gw_registry_probe">>)]),
    stop_named(yuzu_gw_registry_probe).

%% Every first failure of a burst used to create its own stamp (and log): the
%% stamp is created once, by init_limits/0, and 500 callers failing together
%% share it.
warn_burst_is_limited_after_init() ->
    ok = yuzu_gw_safe_call:init_limits(),
    capture_to_self(),
    Parent = self(),
    N = 500,
    Pids = [spawn_monitor(fun() ->
                Parent ! {burst_ready, self()},
                receive go -> ok end,
                {error, x} = yuzu_gw_safe_call:call(yuzu_gw_upstream, ping, 20, x)
            end) || _ <- lists:seq(1, N)],
    [receive {burst_ready, P} -> ok after ?WAIT_MS -> error(burst_not_ready) end
     || {P, _} <- Pids],
    [P ! go || {P, _} <- Pids],
    [receive {'DOWN', M, process, P, normal} -> ok
     after ?WAIT_MS -> error({burst_caller_failed, P})
     end || {P, M} <- Pids],
    Warns = [W || W <- warnings(drain_events()), contains(W, <<"yuzu_gw_upstream">>)],
    %% One per interval; a second only if the burst straddled the interval.
    ?assert(length(Warns) >= 1),
    ?assert(length(Warns) =< 2).

missing_stamp_logs_nothing_and_creates_nothing() ->
    Key = {yuzu_gw_safe_call, yuzu_gw_never_initialised},
    ?assertEqual(undefined, persistent_term:get(Key, undefined)),
    {Result, Events} = run_caller(fun() ->
        yuzu_gw_safe_call:call(yuzu_gw_never_initialised, ping, 20, x)
    end),
    ?assertEqual({returned, {error, x}}, Result),
    ?assertEqual([], [W || W <- warnings(Events), contains(W, <<"never_initialised">>)]),
    ?assertEqual(undefined, persistent_term:get(Key, undefined)).

init_limits_is_idempotent() ->
    Key = {yuzu_gw_safe_call, yuzu_gw_upstream},
    Ref = persistent_term:get(Key),
    %% Use the stamp up (a WARN), then init again: same array, stamp reset.
    {_, E1} = run_caller(fun() -> yuzu_gw_safe_call:call(yuzu_gw_upstream, ping, 20, x) end),
    ?assertMatch([_], [W || W <- warnings(E1), contains(W, <<"yuzu_gw_upstream">>)]),
    {_, E2} = run_caller(fun() -> yuzu_gw_safe_call:call(yuzu_gw_upstream, ping, 20, x) end),
    ?assertEqual([], [W || W <- warnings(E2), contains(W, <<"yuzu_gw_upstream">>)]),
    ok = yuzu_gw_safe_call:init_limits(),
    ?assertEqual(Ref, persistent_term:get(Key)),
    {_, E3} = run_caller(fun() -> yuzu_gw_safe_call:call(yuzu_gw_upstream, ping, 20, x) end),
    ?assertMatch([_], [W || W <- warnings(E3), contains(W, <<"yuzu_gw_upstream">>)]).

call_timeout_validation() ->
    Default = 30000,
    [begin
         application:set_env(yuzu_gw, ?TIMEOUT_KEY, V),
         capture_to_self(),
         ?assertEqual(V, yuzu_gw_upstream:call_timeout()),
         ?assertEqual([], [W || W <- warnings(drain_events()),
                                contains(W, <<"upstream_call_timeout_ms">>)])
     end || V <- [100, 5000, 300000]],
    application:unset_env(yuzu_gw, ?TIMEOUT_KEY),
    capture_to_self(),
    ?assertEqual(Default, yuzu_gw_upstream:call_timeout()),
    ?assertEqual([], warnings(drain_events())),
    [begin
         application:set_env(yuzu_gw, ?TIMEOUT_KEY, Bad),
         capture_to_self(),
         ?assertEqual(Default, yuzu_gw_upstream:call_timeout()),
         ?assertMatch([_], [W || W <- warnings(drain_events()),
                                 contains(W, <<"upstream_call_timeout_ms">>)])
     end || Bad <- [0, -1, 99, 300001, 999999999, 1.5, foo, <<"100">>]],
    ok.

exit_class_shapes() ->
    Call = {gen_server, call, [s, {proxy_register, #{enrollment_token => ?M_TOKEN}}, 1]},
    ?assertEqual(noproc,  yuzu_gw_safe_call:exit_class({noproc, Call})),
    ?assertEqual(timeout, yuzu_gw_safe_call:exit_class({timeout, Call})),
    ?assertEqual(other,   yuzu_gw_safe_call:exit_class({boom, Call})),
    ?assertEqual(other,   yuzu_gw_safe_call:exit_class({{nodedown, n}, Call})),
    ?assertEqual(other,   yuzu_gw_safe_call:exit_class(killed)),
    ?assertEqual(other,   yuzu_gw_safe_call:exit_class(garbage)).

%% The harness sees the leak when there is one: the same call, made raw.
control_raw_call_leaks() ->
    start_fake(yuzu_gw_upstream, hang),
    {Result, Events} = run_caller(fun() ->
        gen_server:call(yuzu_gw_upstream, {proxy_register, req()}, 50)
    end),
    ?assertEqual(no_result, Result),
    Text = events_text(Events),
    [?assert(contains(Text, M)) || M <- ?MARKERS].

%% The Register handler stores the request in the pending table from its own
%% process. The registry owns the table, so with the registry down the insert
%% raised badarg with the request in the stacktrace; the call now answers a
%% fixed error, through the runner, and logs a fixed line.
register_handler_registry_down() ->
    stop_named(yuzu_gw_registry),
    ok = meck:new(yuzu_gw_upstream, [passthrough, no_link]),
    try
        ok = meck:expect(yuzu_gw_upstream, proxy_register,
                         fun(_) -> {ok, #{session_id => <<"s-1">>}} end),
        {Result, Events} = run_caller(fun() ->
            via_runner(unary, yuzu_gw_agent_service, register,
                       #{request => maps:merge(req(), #{info => #{agent_id => <<"a-1">>}})})
        end),
        ?assertEqual({returned, {?GRPC_STATUS_INTERNAL,
                                 <<"Registration failed: registry unavailable">>}}, Result),
        assert_no_markers(Events),
        %% The handler says what happened, in a fixed line.
        ?assert(lists:any(fun(W) -> contains(W, <<"registry_unavailable">>) end,
                          warnings(Events)))
    after
        meck:unload(yuzu_gw_upstream)
    end.

subscribe_handler_registry_down() ->
    stop_named(yuzu_gw_registry),
    {Result, Events} = run_subscribe(<<"s-sub-1">>),
    ?assertEqual({returned, {?GRPC_STATUS_INTERNAL, <<"Internal: registry unavailable">>}}, Result),
    assert_no_markers(Events).

subscribe_handler_agent_sup_down() ->
    stop_named(yuzu_gw_registry),
    stop_named(yuzu_gw_agent_sup),
    {ok, Reg} = yuzu_gw_registry:start_link(),
    unlink(Reg),
    try
        S = <<"s-sub-2">>,
        ok = yuzu_gw_registry:store_pending(S,
                #{agent_id => <<"a-2">>, agent_info => #{}, peer_addr => <<"p">>,
                  register_req => req(), conn_key => undefined}),
        {Result, Events} = run_subscribe(S),
        ?assertEqual({returned, {?GRPC_STATUS_INTERNAL,
                                 <<"Internal: agent process start failed">>}}, Result),
        assert_no_markers(Events),
        %% Positive control: the pending row was consumed, so the handler got
        %% as far as the supervisor.
        ?assertEqual(undefined, yuzu_gw_registry:take_pending(S))
    after
        stop_named(yuzu_gw_registry)
    end.

pending_calls_without_registry() ->
    stop_named(yuzu_gw_registry),
    ?assertEqual({error, registry_unavailable},
                 yuzu_gw_registry:store_pending(<<"s">>, #{register_req => req()})),
    ?assertEqual({error, registry_unavailable}, yuzu_gw_registry:take_pending(<<"s">>)),
    %% Control: with the registry running they work.
    {ok, Reg} = yuzu_gw_registry:start_link(),
    unlink(Reg),
    try
        ?assertEqual(ok, yuzu_gw_registry:store_pending(<<"s">>, #{a => 1})),
        ?assertEqual(#{a => 1}, yuzu_gw_registry:take_pending(<<"s">>)),
        ?assertEqual(undefined, yuzu_gw_registry:take_pending(<<"s">>))
    after
        stop_named(yuzu_gw_registry)
    end.

start_agent_guard() ->
    stop_named(yuzu_gw_agent_sup),
    {Result, Events} = run_caller(fun() ->
        yuzu_gw_agent_sup:start_agent(#{register_req => req()})
    end),
    ?assertEqual({returned, {error, agent_sup_unavailable}}, Result),
    assert_no_markers(Events),
    ?assert(has_warning(Events, <<"noproc">>)),
    %% Only an exit is caught: an error keeps its own shape.
    ?assertError(boom, yuzu_gw_safe_call:guard(some_server, fun() -> error(boom) end, x)),
    ?assertEqual({error, x},
                 yuzu_gw_safe_call:guard(some_server, fun() -> exit(boom) end, x)).

%% The management handler calls the router with the CommandRequest, whose plugin
%% parameters can be secrets, in the call: a router that is not running exited
%% the handler with the call (and so the request) in the reason.
router_send_command_router_down() ->
    stop_named(yuzu_gw_router),
    {Result, Events} = run_caller(fun() ->
        yuzu_gw_router:send_command([<<"a-1">>],
            #{plugin => <<"p">>, parameters => #{<<"password">> => ?M_TOKEN}}, #{})
    end),
    ?assertEqual({returned, {error, router_unavailable}}, Result),
    assert_no_markers(Events),
    ?assert(has_warning(Events, <<"noproc">>)).

%% The operator-facing handler, run through the runner: a router that is down is a transient condition
%% (UNAVAILABLE, 14), not INTERNAL (13); one WARN names only the class, however
%% many commands fail inside the limiter's second, and the request is not logged.
mgmt_send_command_router_down() ->
    stop_named(yuzu_gw_router),
    Request = #{agent_ids => [<<"a-1">>],
                command => #{plugin => <<"p">>, parameters => #{<<"password">> => ?M_TOKEN}}},
    {Result, Events} = run_caller(fun() ->
        [via_runner(server_stream, yuzu_gw_mgmt_service, send_command, #{request => Request})
         || _ <- lists:seq(1, 5)]
    end),
    {returned, Replies} = Result,
    ?assertEqual(5, length(Replies)),
    [?assertEqual({?GRPC_STATUS_UNAVAILABLE, <<"Command router unavailable">>}, R)
     || R <- Replies],
    assert_no_markers(Events),
    ?assert(has_warning(Events, <<"noproc">>)),
    ?assertEqual(1, length([W || W <- warnings(Events),
                                 contains(W, <<"Call to yuzu_gw_router failed">>)])).

%% The harness sees the leak when there is one: the same insert, made raw,
%% under a wrapper that logs the exception the way a careless handler wrapper
%% would (the runner does not).
control_logging_wrapper_leaks() ->
    {Result, Events} = run_caller(fun() ->
        logging_wrapper(fun() ->
            ets:insert(yuzu_gw_pending_missing_table, {<<"s">>, #{register_req => req()}, 1})
        end)
    end),
    ?assertMatch({returned, {caught, error, badarg}}, Result),
    Text = events_text(Events),
    [?assert(contains(Text, M)) || M <- ?MARKERS].

%%%===================================================================
%%% Scenario helpers
%%%===================================================================

%% The unary handler of the tests that need an arbitrary function: calls the
%% fun in the request with the ctx.
run_fun(Ctx, #{call := Fun}) ->
    Fun(Ctx).

%% Service function Module:Function run the way the stream handler runs it
%% (yuzu_grpc_runner:run/1), in the calling process, and the {Status, Message}
%% the runner ended the call with. Extra is the `request' (unary, server_stream)
%% or `ref' (bidi). The stream's connection is the calling process, which is
%% also the connection key of the ctx, and its ctx carries Headers. Only for
%% calls that end in a status without sending a response.
via_runner(Kind, Module, Function, Extra) ->
    via_runner(Kind, Module, Function, Extra, #{}).

via_runner(Kind, Module, Function, Extra, Headers) ->
    Conn = self(),
    Ctx = yuzu_grpc:new_ctx(Headers, Conn, undefined, undefined, undefined),
    Stream = #yuzu_grpc_stream{conn = Conn, stream_id = 1, ctx = Ctx,
                               method = <<"/test.Service/Method">>,
                               pb = agent_pb, output = 'yuzu.agent.v1.RegisterResponse'},
    ok = yuzu_grpc_runner:run(Extra#{kind => Kind, module => Module, function => Function,
                                     stream => Stream}),
    receive {{Conn, 1}, {grpc_end, _Runner, Status, Message}} -> {Status, Message}
    after 0 -> no_status
    end.

%% A handler wrapper that catches everything and logs the exception: the
%% careless version of the runner, for the positive control.
logging_wrapper(Fun) ->
    try Fun()
    catch C:E:S ->
        logger:info("crash: class=~p exception=~p stacktrace=~p", [C, E, S]),
        {caught, C, E}
    end.

%% yuzu_gw_agent_service:subscribe/2 for session S, through the runner, with
%% the session id header on the call.
run_subscribe(S) ->
    run_caller(fun() ->
        via_runner(bidi, yuzu_gw_agent_service, subscribe, #{ref => make_ref()},
                   #{<<"x-yuzu-session-id">> => S})
    end).

req() ->
    #{enrollment_token => ?M_TOKEN, machine_certificate => ?M_CERT, csr_pem => ?M_CSR}.

register_agent() ->
    yuzu_gw_registry:register_agent(<<"a-1">>, self(), <<"s-1">>, [], <<"h">>, req(),
                                    undefined).

%% Run Fun, uncaught, in a plain proc_lib process (as a gRPC handler is),
%% and return {{returned, Result} | no_result, EventsItLogged}. The capture
%% handler runs in the logging process, so every event of the caller is in this
%% process's mailbox before the 'DOWN' that follows its exit.
run_caller(Fun) ->
    capture_to_self(),
    Parent = self(),
    Ref = make_ref(),
    {Pid, Mon} = proc_lib:spawn_opt(fun() -> Parent ! {Ref, returned, Fun()} end,
                                    [monitor]),
    receive {'DOWN', Mon, process, Pid, _} -> ok
    after ?WAIT_MS -> error({caller_did_not_finish, Pid})
    end,
    Result = receive {Ref, returned, R} -> {returned, R}
             after 0 -> no_result
             end,
    {Result, drain_events()}.

%% A process that holds the registered name and is blocked in `receive'. On a
%% call it hangs forever (`hang') or exits (`die').
start_fake(Name, Mode) ->
    stop_named(Name),
    Pid = spawn(fun() ->
        receive
            {'$gen_call', _From, _Msg} when Mode =:= die -> exit(boom);
            {'$gen_call', _From, _Msg} when Mode =:= hang -> receive stop -> ok end;
            stop -> ok
        end
    end),
    true = register(Name, Pid),
    Pid.

stop_named(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            catch unlink(Pid),
            Ref = monitor(process, Pid),
            catch unregister(Name),
            case proc_lib:initial_call(Pid) of
                false -> exit(Pid, kill);
                _     -> catch gen_server:stop(Pid, normal, 2000)
            end,
            receive {'DOWN', Ref, process, Pid, _} -> ok
            after 3000 -> exit(Pid, kill), demonitor(Ref, [flush]), ok
            end
    end.

%%%===================================================================
%%% Capture
%%%===================================================================

capture_to_self() ->
    catch logger:remove_handler(?HANDLER),
    flush_events(),
    ok = logger:add_handler(?HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => all}).

%% logger handler callback: runs in the logging process, after the primary
%% filters.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {captured, Event},
    ok.

is_agent_crash_report(#{msg := {report, #{label := {proc_lib, crash},
                                          report := [ProcInfo | _]}}}) when is_list(ProcInfo) ->
    case lists:keyfind(initial_call, 1, ProcInfo) of
        {initial_call, {yuzu_gw_agent, init, _}} -> true;
        _                                        -> false
    end;
is_agent_crash_report(_) ->
    false.

drain_events() ->
    receive {captured, E} -> [E | drain_events()]
    after 0 -> []
    end.

flush_events() ->
    _ = drain_events(),
    ok.

formatted(Event) ->
    unicode:characters_to_binary(logger_formatter:format(Event, #{})).

raw(Event) ->
    unicode:characters_to_binary(io_lib:format("~0p", [Event])).

events_text(Events) ->
    iolist_to_binary([[formatted(E), raw(E)] || E <- Events]).

assert_no_markers(Events) ->
    lists:foreach(
      fun(E) ->
          Text = iolist_to_binary([formatted(E), raw(E)]),
          lists:foreach(
            fun(M) ->
                case contains(Text, M) of
                    true  -> error({marker_leaked, M, formatted(E)});
                    false -> ok
                end
            end, ?MARKERS)
      end, Events).

%% The formatted text of every WARNING event.
warnings(Events) ->
    [formatted(E) || #{level := warning} = E <- Events].

has_warning(Events, Class) ->
    lists:any(fun(W) -> contains(W, <<"failed (", Class/binary, ")">>) end,
              warnings(Events)).

contains(Bin, Needle) -> binary:match(Bin, Needle) =/= nomatch.
