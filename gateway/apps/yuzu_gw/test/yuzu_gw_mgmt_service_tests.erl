%%%-------------------------------------------------------------------
%%% @doc Unit tests for yuzu_gw_mgmt_service — JSON escaping and
%%% management service helpers.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_service_tests).
-include_lib("eunit/include/eunit.hrl").

%% gRPC statuses the handlers return (the integers of yuzu_grpc.hrl).
-define(NOT_FOUND, 5).
-define(INTERNAL, 13).
-define(UNAVAILABLE, 14).

%%%===================================================================
%%% JSON escaping tests
%%%===================================================================

json_escape_plain_text_test() ->
    ?assertEqual(<<"hello world">>,
                 yuzu_gw_mgmt_service:json_escape(<<"hello world">>)).

json_escape_double_quotes_test() ->
    ?assertEqual(<<"say \\\"hello\\\"">>,
                 yuzu_gw_mgmt_service:json_escape(<<"say \"hello\"">>)).

json_escape_backslash_test() ->
    ?assertEqual(<<"path\\\\file">>,
                 yuzu_gw_mgmt_service:json_escape(<<"path\\file">>)).

json_escape_newline_test() ->
    ?assertEqual(<<"line1\\nline2">>,
                 yuzu_gw_mgmt_service:json_escape(<<"line1\nline2">>)).

json_escape_carriage_return_test() ->
    ?assertEqual(<<"a\\rb">>,
                 yuzu_gw_mgmt_service:json_escape(<<"a\rb">>)).

json_escape_tab_test() ->
    ?assertEqual(<<"a\\tb">>,
                 yuzu_gw_mgmt_service:json_escape(<<"a\tb">>)).

json_escape_control_chars_test() ->
    %% NUL, SOH, and US (31) should be \u-escaped.
    ?assertEqual(<<"\\u0000\\u0001\\u001f">>,
                 yuzu_gw_mgmt_service:json_escape(<<0, 1, 31>>)).

json_escape_empty_test() ->
    ?assertEqual(<<>>, yuzu_gw_mgmt_service:json_escape(<<>>)).

json_escape_mixed_test() ->
    Input = <<"He said \"hello\\world\"\nand\tthat's it">>,
    Expected = <<"He said \\\"hello\\\\world\\\"\\nand\\tthat's it">>,
    ?assertEqual(Expected, yuzu_gw_mgmt_service:json_escape(Input)).

json_escape_unicode_passthrough_test() ->
    %% Non-ASCII UTF-8 should pass through unchanged.
    Input = <<"café résumé"/utf8>>,
    ?assertEqual(Input, yuzu_gw_mgmt_service:json_escape(Input)).

%%%===================================================================
%%% list_agents Ctx pass-through test
%%%===================================================================

list_agents_passes_ctx_test_() ->
    {setup,
     fun ctx_setup/0,
     fun ctx_cleanup/1,
     [{"list_agents returns caller's ctx", fun list_agents_ctx/0},
      {"get_agent returns caller's ctx on success", fun get_agent_ctx/0}]}.

ctx_setup() ->
    %% The previous setup only checked `whereis(yuzu_gw_registry)` to
    %% decide whether to start_link the registry. That misses the case
    %% where a prior test left the registered name in place but the
    %% registry's `?TABLE` (`yuzu_gw_agents`) ETS table was destroyed
    %% (sibling test ran `ets:delete`, gen_server crashed-and-rerouted,
    %% or — most commonly — an earlier EUnit suite tore down its own
    %% registry between phases). When that mismatch holds,
    %% `ets:select(yuzu_gw_agents, ...)` from `yuzu_gw_registry:list_agents/2`
    %% blows up with `badarg` and the test fails as
    %% `list_agents_ctx ...*failed*` (eunit run `1778588897-12585`).
    %%
    %% Repair invariant: the registry must be alive AND its `?TABLE`
    %% ETS table must exist before any test in this suite runs. If
    %% either condition is violated we recreate cleanly. We don't blow
    %% up on `{already_started, _}` because a parallel EUnit gate may
    %% have started the registry between our `whereis` check and our
    %% `start_link` call (this is a real race under
    %% `REBAR_BASE_DIR=_build_eunit` parallel fan-out).
    ensure_yuzu_gw_pg(),
    ensure_registry_with_ets(),
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(telemetry),
    meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    ok.

ensure_yuzu_gw_pg() ->
    case whereis(yuzu_gw) of
        undefined ->
            case pg:start_link(yuzu_gw) of
                {ok, _}                          -> ok;
                {error, {already_started, _}}    -> ok
            end;
        _ -> ok
    end.

ensure_registry_with_ets() ->
    HasRegistry  = is_pid(whereis(yuzu_gw_registry)),
    HasEtsTable  = ets:info(yuzu_gw_agents, size) =/= undefined,
    case {HasRegistry, HasEtsTable} of
        {true, true} ->
            ok;
        _ ->
            %% Empirically observed (eunit run 1778588897-12585): when
            %% an earlier suite tears down, the registry's gen_server
            %% remains alive but its ETS tables have already been
            %% destroyed (the cleanup races between the gen_server's
            %% terminate/2 and the OS-level table reaper). The
            %% gen_server in that "zombie-but-still-registered" state
            %% does NOT respond to `gen_server:stop` because it has no
            %% useful state left to drain — stop succeeds without
            %% actually exiting the process, so a subsequent
            %% `gen_server:start` returns `{already_started, Pid}` and
            %% the test fires `ets:select` against the missing table.
            %%
            %% Force-kill the zombie via `exit(Pid, kill)` (untrappable;
            %% bypasses the misbehaving terminate path), wait for the
            %% registered name to clear, then start a fresh registry.
            %% Unlinked so the EUnit setup process's eventual exit
            %% doesn't propagate.
            case whereis(yuzu_gw_registry) of
                undefined -> ok;
                ZombiePid ->
                    exit(ZombiePid, kill),
                    wait_unregistered(yuzu_gw_registry, 50, 20)
            end,
            {ok, _} = gen_server:start({local, yuzu_gw_registry},
                                       yuzu_gw_registry, [], [])
    end.

%% Spin until the given registered name is `undefined`, max Attempts × WaitMs.
wait_unregistered(_Name, 0, _WaitMs) ->
    ok;
wait_unregistered(Name, Attempts, WaitMs) ->
    case whereis(Name) of
        undefined -> ok;
        _ ->
            timer:sleep(WaitMs),
            wait_unregistered(Name, Attempts - 1, WaitMs)
    end.

ctx_cleanup(_) ->
    catch meck:unload(yuzu_gw_upstream),
    catch meck:unload(telemetry),
    ok.

list_agents_ctx() ->
    Ctx = #{custom_header => <<"test">>},
    {ok, _Response, ReturnedCtx} = yuzu_gw_mgmt_service:list_agents(
        Ctx, #{limit => 10}),
    ?assertEqual(Ctx, ReturnedCtx).

get_agent_ctx() ->
    %% Register a real agent so get_agent succeeds.
    AgentId = <<"ctx-test-agent">>,
    StreamPid = spawn(fun() -> receive stop -> ok end end),
    Args = #{agent_id => AgentId, session_id => <<"s">>,
             stream_pid => StreamPid,
             agent_info => #{plugins => []}, peer_addr => <<"127.0.0.1">>},
    {ok, AgentPid} = yuzu_gw_agent:start_link(Args),
    unlink(AgentPid),
    timer:sleep(20),

    Ctx = #{custom_header => <<"test2">>},
    {ok, _Response, ReturnedCtx} = yuzu_gw_mgmt_service:get_agent(
        Ctx, #{agent_id => AgentId}),
    ?assertEqual(Ctx, ReturnedCtx),

    yuzu_gw_agent:disconnect(AgentPid),
    StreamPid ! stop,
    timer:sleep(50).

%%%===================================================================
%%% get_agent stale-pid handling (governance finding, external PR review)
%%%===================================================================

%% `yuzu_gw_registry:lookup/1`'s cross-node `pg` fallback (`lookup_remote/1`,
%% HA WS-4 4.3a) never verifies a REMOTE member's liveness — it trusts `pg`'s
%% own asynchronous cleanup. A stale pid reaching `get_agent/2` used to crash
%% the request handler (`gen_statem:call/3` raises `exit({noproc, _})`
%% uncaught) instead of returning the same NOT_FOUND response the `error`
%% branch already produces for "never was connected". Mock the registry to
%% return a genuinely-dead pid deterministically, rather than racing a real
%% kill against a real lookup.
get_agent_maps_stale_pid_to_not_found_test() ->
    DeadPid = spawn(fun() -> ok end),
    wait_dead(DeadPid, 100),
    ?assertEqual(false, is_process_alive(DeadPid)),

    catch meck:unload(yuzu_gw_registry),
    meck:new(yuzu_gw_registry, [passthrough, no_link]),
    try
        meck:expect(yuzu_gw_registry, lookup, fun(_) -> {ok, DeadPid} end),
        ?assertEqual({grpc_error, {?NOT_FOUND, <<"Agent not connected">>}},
                     yuzu_gw_mgmt_service:get_agent(#{}, #{agent_id => <<"stale-agent">>}))
    after
        meck:unload(yuzu_gw_registry)
    end.

%% An agent the registry has never heard of is the same NOT_FOUND.
get_agent_unknown_agent_is_not_found_test() ->
    catch meck:unload(yuzu_gw_registry),
    meck:new(yuzu_gw_registry, [passthrough, no_link]),
    try
        meck:expect(yuzu_gw_registry, lookup, fun(_) -> error end),
        ?assertEqual({grpc_error, {?NOT_FOUND, <<"Agent not connected">>}},
                     yuzu_gw_mgmt_service:get_agent(#{}, #{agent_id => <<"nobody">>}))
    after
        meck:unload(yuzu_gw_registry)
    end.

%% An agent process that answers with an error is INTERNAL, and the message
%% names the reason (it is the agent's own, never the request).
get_agent_query_failure_is_internal_test() ->
    catch meck:unload(yuzu_gw_registry),
    catch meck:unload(yuzu_gw_agent),
    meck:new(yuzu_gw_registry, [passthrough, no_link]),
    meck:new(yuzu_gw_agent, [passthrough, no_link]),
    try
        meck:expect(yuzu_gw_registry, lookup, fun(_) -> {ok, self()} end),
        meck:expect(yuzu_gw_agent, get_info, fun(_) -> {error, draining} end),
        ?assertEqual({grpc_error, {?INTERNAL, <<"Agent query failed: draining">>}},
                     yuzu_gw_mgmt_service:get_agent(#{}, #{agent_id => <<"a">>}))
    after
        meck:unload(yuzu_gw_agent),
        meck:unload(yuzu_gw_registry)
    end.

wait_dead(_Pid, 0) ->
    ok;
wait_dead(Pid, Attempts) ->
    case is_process_alive(Pid) of
        false -> ok;
        true ->
            timer:sleep(5),
            wait_dead(Pid, Attempts - 1)
    end.

%%%===================================================================
%%% stream_responses/3 command_id threading (HA WS-4 rest-of-4.3,
%%% quality-engineer Gate 3 finding)
%%%===================================================================

%% Regression test for the fix that threads the request's real command_id
%% through a command_error-derived response, instead of the previous
%% hardcoded `command_id => <<>>`. Before this fix, a gateway-side "agent
%% not connected on this cluster" error was invisible to the core server's
%% execution tracker (resolve_execution_id("") -> nullopt) — see
%% docs/adr/2002-high-availability-architecture.md §7d for the full
%% end-to-end story. `send_command/2` is exercised directly (not
%% `stream_responses/3`, which isn't exported) by mocking `yuzu_gw_router`'s
%% fan-out to synchronously deliver a `command_error` then `fanout_complete`
%% into this test process's own mailbox — `send_command/2` calls
%% `stream_responses/3` as a plain tail call in the SAME process, so its
%% `receive` loop picks both up in order — and `yuzu_grpc_stream:send/2` (the
%% stream is its FIRST argument) to capture the outgoing map instead of
%% touching a real HTTP/2 stream. The wire test of this handler over a real
%% listener is yuzu_gw_mgmt_wire_tests.
%% gateway-erlang Gate 8 re-review: the meck cleanup below MUST run even if
%% an assertion inside throws, or yuzu_gw_router/yuzu_grpc_stream stay mecked
%% for the rest of this eunit run — a LATER module (yuzu_gw_registry_
%% multinode_tests, which calls the real yuzu_gw_router:send_command/3)
%% would then silently hit this test's stale mock instead of the real
%% module. try/after, not the {setup,...} fixture pattern ctx_setup/0 uses
%% above, since this test's mocks are local to it, not shared suite state.
send_command_stamps_real_command_id_on_not_connected_error_test() ->
    catch meck:unload(yuzu_gw_router),
    catch meck:unload(yuzu_grpc_stream),
    meck:new(yuzu_gw_router, [non_strict, no_link]),
    meck:new(yuzu_grpc_stream, [non_strict, no_link]),
    try
        FanoutRef = make_ref(),
        Self = self(),
        meck:expect(yuzu_gw_router, send_command,
                    fun(_AgentIds, _CommandReq, _Opts) ->
                        Self ! {command_error, FanoutRef, <<"agent-1">>, not_connected},
                        Self ! {fanout_complete, FanoutRef, #{}},
                        {ok, FanoutRef}
                    end),
        meck:expect(yuzu_grpc_stream, send,
                    fun(test_stream, Msg) ->
                        Self ! {captured_send, Msg},
                        ok
                    end),

        Request = #{agent_ids => [<<"agent-1">>],
                    command => #{command_id => <<"real-cmd-id-123">>}},
        Result = yuzu_gw_mgmt_service:send_command(Request, test_stream),
        ?assertEqual(ok, Result),

        receive
            {captured_send, Msg} ->
                ?assertMatch(#{agent_id := <<"agent-1">>}, Msg),
                Response = maps:get(response, Msg),
                ?assertEqual(<<"real-cmd-id-123">>, maps:get(command_id, Response)),
                ?assertEqual('FAILURE', maps:get(status, Response)),
                ?assertEqual(-1, maps:get(exit_code, Response)),
                ?assertEqual(<<"not_connected">>, maps:get(output, Response))
        after 1000 ->
            ?assert(false)
        end
    after
        meck:unload(yuzu_gw_router),
        meck:unload(yuzu_grpc_stream)
    end.

%% A command_response is forwarded as it arrives, then the call ends with ok
%% (the runner turns that into status 0).
send_command_forwards_responses_in_order_test() ->
    catch meck:unload(yuzu_gw_router),
    catch meck:unload(yuzu_grpc_stream),
    meck:new(yuzu_gw_router, [non_strict, no_link]),
    meck:new(yuzu_grpc_stream, [non_strict, no_link]),
    try
        FanoutRef = make_ref(),
        Self = self(),
        meck:expect(yuzu_gw_router, send_command,
                    fun(_AgentIds, _CommandReq, _Opts) ->
                        Self ! {command_response, FanoutRef, <<"a1">>, #{output => <<"one">>}},
                        Self ! {command_response, FanoutRef, <<"a2">>, #{output => <<"two">>}},
                        Self ! {fanout_complete, FanoutRef, #{}},
                        {ok, FanoutRef}
                    end),
        meck:expect(yuzu_grpc_stream, send, fun(test_stream, _Msg) -> ok end),

        ?assertEqual(ok, yuzu_gw_mgmt_service:send_command(
                           #{agent_ids => [<<"a1">>, <<"a2">>], command => #{}}, test_stream)),
        Sent = [Msg || {_Pid, {yuzu_grpc_stream, send, [test_stream, Msg]}, _Result}
                           <- meck:history(yuzu_grpc_stream)],
        ?assertEqual([#{agent_id => <<"a1">>, response => #{output => <<"one">>}},
                      #{agent_id => <<"a2">>, response => #{output => <<"two">>}}], Sent)
    after
        meck:unload(yuzu_gw_router),
        meck:unload(yuzu_grpc_stream)
    end.

%% A router that is not running is UNAVAILABLE (a client may retry); any other
%% failure of the fan-out is INTERNAL. Neither carries the request.
send_command_router_failures_test() ->
    catch meck:unload(yuzu_gw_router),
    meck:new(yuzu_gw_router, [non_strict, no_link]),
    try
        Request = #{agent_ids => [<<"a">>], command => #{command_id => <<"secret-cmd">>}},
        meck:expect(yuzu_gw_router, send_command,
                    fun(_, _, _) -> {error, router_unavailable} end),
        ?assertEqual({grpc_error, {?UNAVAILABLE, <<"Command router unavailable">>}},
                     yuzu_gw_mgmt_service:send_command(Request, test_stream)),
        meck:expect(yuzu_gw_router, send_command, fun(_, _, _) -> {error, overloaded} end),
        ?assertEqual({grpc_error, {?INTERNAL, <<"Fanout failed: overloaded">>}},
                     yuzu_gw_mgmt_service:send_command(Request, test_stream))
    after
        meck:unload(yuzu_gw_router)
    end.

%% CommandResponse.action (field 8) must survive the management hop for an ORDINARY (non-Guardian)
%% response: the server's registry.write audit hook for a gateway-connected agent depends on it.
%% Drives send_command/2 exactly like the not_connected test above (the router delivers one
%% command_response and fanout_complete; yuzu_grpc_stream:send/2 is captured), then pushes the
%% captured message through management_pb, the codec the wire uses, and checks the decoded frame.
send_command_forwards_the_stamped_action_test() ->
    catch meck:unload(yuzu_gw_router),
    catch meck:unload(yuzu_grpc_stream),
    meck:new(yuzu_gw_router, [non_strict, no_link]),
    meck:new(yuzu_grpc_stream, [non_strict, no_link]),
    try
        FanoutRef = make_ref(),
        Self = self(),
        CmdId = <<"registry-0123456789abcdef">>,
        Frame = #{command_id => CmdId, status => 'RUNNING',
                  output => <<"audit|op=set_value">>, action => <<"set_value">>},
        meck:expect(yuzu_gw_router, send_command,
                    fun(_AgentIds, _CommandReq, _Opts) ->
                        Self ! {command_response, FanoutRef, <<"agent-1">>, Frame},
                        Self ! {fanout_complete, FanoutRef, #{}},
                        {ok, FanoutRef}
                    end),
        meck:expect(yuzu_grpc_stream, send,
                    fun(test_stream, Msg) ->
                        Self ! {captured_send, Msg},
                        ok
                    end),

        Request = #{agent_ids => [<<"agent-1">>],
                    command => #{command_id => CmdId}},
        ?assertEqual(ok, yuzu_gw_mgmt_service:send_command(Request, test_stream)),

        receive
            {captured_send, Msg} ->
                ?assertEqual(<<"set_value">>,
                             maps:get(action, maps:get(response, Msg), undefined)),
                Wire = management_pb:encode_msg(Msg, 'yuzu.server.v1.SendCommandResponse'),
                %% Field 8, length-delimited (tag 66), 9 bytes: encode and decode share one module,
                %% so the round trip alone would not notice the field being renumbered.
                ?assertNotEqual(nomatch, binary:match(Wire, <<66, 9, "set_value">>)),
                Decoded = management_pb:decode_msg(Wire, 'yuzu.server.v1.SendCommandResponse'),
                ?assertEqual(<<"set_value">>,
                             maps:get(action, maps:get(response, Decoded), undefined))
        after 1000 ->
            ?assert(false)
        end
    after
        meck:unload(yuzu_gw_router),
        meck:unload(yuzu_grpc_stream)
    end.
