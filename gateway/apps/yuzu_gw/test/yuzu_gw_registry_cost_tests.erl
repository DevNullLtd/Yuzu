%%%-------------------------------------------------------------------
%%% @doc What one registration and one deregistration cost the registry
%%% singleton (PR #5695, 5,000-agent work).
%%%
%%% The registry is one gen_server every Register and every disconnect passes
%%% through, so its per-call cost sets how fast a gateway can take a
%%% reconnect storm. Two costs are pinned here:
%%%
%%%  * pg traffic. A registration used to join one `pg' group per plugin plus
%%%    `all_agents' and `{agent, Id}', each a `gen_server:call' with an
%%%    infinite timeout made from inside the registry: about 71 synchronous
%%%    calls for an agent with the 69 plugins a full build ships. Nothing in
%%%    production read the per-plugin or `all_agents' groups. The registry now
%%%    makes no `pg' call at all; the agent process joins `{agent, Id}' itself.
%%%
%%%  * Monitor bookkeeping. Removing an agent used to filter (or fold) the map
%%%    of every agent monitor to find its one ref, so N disconnects cost
%%%    O(N^2). The test counts the registry's own reductions for N and 4N
%%%    removals: linear work gives a ratio near 4, quadratic near 16. A
%%%    reduction count is work done, not wall time, so a loaded CI runner does
%%%    not move it.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registry_cost_tests).
-include_lib("eunit/include/eunit.hrl").

-export([plugin_names/0]).

%% The plugin directory names of a full agent build (agents/plugins), the
%% shape of `info.plugins' in a real RegisterRequest.
-define(PLUGINS,
        [<<"agent_actions">>, <<"agent_logging">>, <<"antivirus">>, <<"app_control">>,
         <<"app_usage">>, <<"asset_tags">>, <<"autoruns">>, <<"bitlocker">>,
         <<"browser_inventory">>, <<"browser_policy">>, <<"certificates">>, <<"chargen">>,
         <<"content_dist">>, <<"device_identity">>, <<"diagnostics">>, <<"discovery">>,
         <<"disk_actions">>, <<"disk_space">>, <<"event_logs">>, <<"example">>,
         <<"execution_artifacts">>, <<"filesystem">>, <<"filesystem_posture">>,
         <<"firewall">>, <<"firmware_posture">>, <<"hardware">>, <<"http_client">>,
         <<"installed_apps">>, <<"interaction">>, <<"ioc">>, <<"license_scan">>,
         <<"local_security_policy">>, <<"mgmt_posture">>, <<"msi_packages">>,
         <<"netprobe">>, <<"netstat">>, <<"network_actions">>, <<"network_config">>,
         <<"network_diag">>, <<"os_info">>, <<"peripherals">>, <<"pkg_inventory">>,
         <<"platform_security">>, <<"power_health">>, <<"printing">>,
         <<"privacy_permissions">>, <<"processes">>, <<"procfetch">>, <<"quarantine">>,
         <<"rdp_control">>, <<"registry">>, <<"runtimes">>, <<"sccm">>, <<"script_exec">>,
         <<"services">>, <<"software_actions">>, <<"status">>, <<"storage">>,
         <<"system_hardening">>, <<"tags">>, <<"echo">>, <<"update_source_trust">>,
         <<"users">>, <<"vuln_scan">>, <<"wifi">>, <<"windows_optional_features">>,
         <<"windows_updates">>, <<"wmi">>, <<"wol">>]).

%% Removals measured: N and 4N. Large enough that the per-message constant
%% (gen_server loop, ETS work) does not hide an O(N) term, small enough to run
%% in a second or two even when the cost is quadratic.
-define(N, 1500).
%% Linear work gives about 4 (a little more: a larger map is a deeper HAMT);
%% quadratic gives about 16.
-define(MAX_RATIO, 8.0).

plugin_names() -> ?PLUGINS.

cost_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [{"69 plugins: the registry makes no pg call to register or deregister an agent",
       fun register_makes_no_pg_calls/0},
      {"the registry joins no pg group on an agent's behalf",
       fun registry_joins_no_group/0},
      {timeout, 120, {"N fenced deregisters (the agent's own cleanup) cost O(N)",
                      fun fenced_deregister_is_linear/0}},
      {timeout, 120, {"N superseding registrations (a reconnect storm) cost O(N)",
                      fun supersede_is_linear/0}},
      {timeout, 120, {"N agent deaths cost O(N)",
                      fun down_is_linear/0}}]}.

setup() ->
    ?assertEqual(69, length(?PLUGINS)),
    yuzu_gw_test_registry:ensure_fresh(),
    catch meck:unload(telemetry),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    ok.

cleanup(_) ->
    catch meck:unload(telemetry),
    ok.

%%%===================================================================
%%% pg traffic
%%%===================================================================

register_makes_no_pg_calls() ->
    Reg = whereis(yuzu_gw_registry),
    Pid = holder(),
    Id = <<"cost-pg-1">>,
    Calls = count_pg_calls(Reg, fun() ->
        ok = yuzu_gw_registry:register_agent(Id, Pid, <<"cost-pg-s1">>, ?PLUGINS, <<"h">>,
                                             #{}, undefined),
        ok = yuzu_gw_registry:deregister_agent(Id, Pid, <<"cost-pg-s1">>),
        barrier()
    end),
    %% Counted per function so a failure reads as "{join,3} => 71".
    Counts = lists:foldl(fun(C, M) -> maps:update_with(C, fun(X) -> X + 1 end, 1, M) end,
                         #{}, Calls),
    ?assertEqual(#{}, Counts),
    stop_holder(Pid).

registry_joins_no_group() ->
    Pid = holder(),
    Id = <<"cost-pg-2">>,
    ok = yuzu_gw_registry:register_agent(Id, Pid, <<"cost-pg-s2">>, ?PLUGINS, <<"h">>,
                                         #{}, undefined),
    Groups = [G || G <- pg:which_groups(yuzu_gw),
                   lists:member(Pid, pg:get_local_members(yuzu_gw, G))],
    stop_holder(Pid),
    drain(),
    ?assertEqual([], Groups).

%% The `pg' functions the registry process calls while Fun runs, as
%% {Function, Arity}. A trace session of its own, so no other tracer in the
%% node is disturbed.
count_pg_calls(Reg, Fun) ->
    Self = self(),
    Tracer = spawn_link(fun() -> collect_trace(Self, []) end),
    Session = trace:session_create(yuzu_gw_registry_cost_tests, Tracer, []),
    try
        _ = trace:function(Session, {pg, '_', '_'}, true, [global]),
        1 = trace:process(Session, Reg, true, [call]),
        Fun()
    after
        trace:session_destroy(Session)
    end,
    Tracer ! {done, Self},
    receive {trace_calls, Calls} -> lists:reverse(Calls)
    after 5000 -> error(tracer_lost)
    end.

collect_trace(Parent, Acc) ->
    receive
        {trace, _Pid, call, {pg, F, Args}} ->
            collect_trace(Parent, [{F, length(Args)} | Acc]);
        {done, Parent} ->
            Parent ! {trace_calls, Acc};
        _ ->
            collect_trace(Parent, Acc)
    end.

%%%===================================================================
%%% Monitor bookkeeping is O(1) per agent
%%%===================================================================

fenced_deregister_is_linear() ->
    Measure = fun(N, Tag) ->
        Agents = register_n(N, Tag),
        work(fun() ->
            [yuzu_gw_registry:deregister_agent(Id, Pid, Sid) || {Id, Pid, Sid} <- Agents]
        end, Agents)
    end,
    assert_linear(Measure, fenced).

supersede_is_linear() ->
    Measure = fun(N, Tag) ->
        Old = register_n(N, Tag),
        New = [{Id, holder(), <<Sid/binary, "-b">>} || {Id, _, Sid} <- Old],
        R = work(fun() ->
            [ok = yuzu_gw_registry:register_agent(Id, Pid, Sid, [], <<"h">>)
             || {Id, Pid, Sid} <- New]
        end, []),
        [stop_holder(P) || {_, P, _} <- Old ++ New],
        drain(),
        R
    end,
    assert_linear(Measure, supersede).

down_is_linear() ->
    Measure = fun(N, Tag) ->
        Agents = register_n(N, Tag),
        work(fun() -> [stop_holder(P) || {_, P, _} <- Agents] end, [])
    end,
    assert_linear(Measure, down).

assert_linear(Measure, Tag) ->
    Small = Measure(?N, iolist_to_binary([atom_to_binary(Tag), "-s"])),
    Large = Measure(4 * ?N, iolist_to_binary([atom_to_binary(Tag), "-l"])),
    Ratio = Large / Small,
    ?debugFmt("~p: ~b removals ~b reductions, ~b removals ~b reductions, ratio ~.2f",
              [Tag, ?N, Small, 4 * ?N, Large, Ratio]),
    ?assert(Ratio < ?MAX_RATIO, {Tag, quadratic, Ratio}),
    ?assertEqual(0, yuzu_gw_registry:agent_count()).

%% The reductions the registry spends handling what Fun sends it. The holders
%% left in Cleanup are stopped afterwards, outside the measurement.
work(Fun, Cleanup) ->
    Reg = whereis(yuzu_gw_registry),
    drain(),
    {reductions, R0} = process_info(Reg, reductions),
    Fun(),
    drain(),
    {reductions, R1} = process_info(Reg, reductions),
    [stop_holder(P) || {_, P, _} <- Cleanup],
    drain(),
    R1 - R0.

register_n(N, Tag) ->
    [begin
         Id = iolist_to_binary(["cost-", Tag, "-", integer_to_binary(I)]),
         Sid = iolist_to_binary(["cost-s-", Tag, "-", integer_to_binary(I)]),
         Pid = holder(),
         ok = yuzu_gw_registry:register_agent(Id, Pid, Sid, [], <<"h">>),
         {Id, Pid, Sid}
     end || I <- lists:seq(1, N)].

%%%===================================================================
%%% Helpers
%%%===================================================================

holder() ->
    spawn(fun() -> receive stop -> ok end end).

stop_holder(Pid) ->
    Pid ! stop.

%% Every message already sent to the registry has been handled: a call queues
%% behind them. The DOWNs of holders just told to stop may not have been sent
%% yet, so wait for the holders' deaths first via the mailbox going quiet.
drain() ->
    Reg = whereis(yuzu_gw_registry),
    quiet(Reg, 0),
    barrier().

quiet(Reg, Stable) when Stable >= 3 ->
    _ = Reg,
    ok;
quiet(Reg, Stable) ->
    timer:sleep(10),
    case process_info(Reg, message_queue_len) of
        {message_queue_len, 0} -> quiet(Reg, Stable + 1);
        _                      -> quiet(Reg, 0)
    end.

barrier() ->
    _ = sys:get_state(yuzu_gw_registry, 30000),
    ok.
