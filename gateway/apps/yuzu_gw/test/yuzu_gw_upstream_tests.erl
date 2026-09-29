%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_upstream — heartbeat batching and proxying.
%%%
%%% Mocks grpcbox_client to test batching logic in isolation, without
%%% a real upstream server.
%%%
%%% Key assertions:
%%%   - Heartbeats accumulate in buffer between flushes
%%%   - Flush sends BatchHeartbeat with all buffered heartbeats
%%%   - Buffer is cleared after flush
%%%   - Empty buffer flush is a no-op (no RPC call)
%%%   - proxy_register returns upstream response
%%%   - proxy_inventory returns upstream response
%%%   - notify_stream_status is fire-and-forget (no crash on error)
%%%   - connect notification advertises the command_dispatch_tag_v1 wire
%%%     capability (CC-03)
%%%   - Buffer is retained on flush failure (not silently discarded)
%%%   - Buffer retention is capped to prevent unbounded growth
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_tests).
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test fixture
%%%===================================================================

upstream_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     [
      {"heartbeats are batched", fun heartbeats_batched/0},
      {"flush sends all buffered heartbeats", fun flush_sends_batch/0},
      {"empty flush sends no rpc", fun empty_flush_no_rpc/0},
      {"proxy_register returns response", fun proxy_register_ok/0},
      {"proxy_register returns error", fun proxy_register_error/0},
      {"HA WS-4 4.4 (c-1/CH-2): a real http_error shape does not crash",
       fun proxy_register_http_error/0},
      {"proxy_inventory returns response", fun proxy_inventory_ok/0},
      {"notify_stream_status does not crash on error", fun notify_no_crash/0},
      {"connect notification advertises command_dispatch_tag_v1", fun notify_advertises_dispatch_tag_capability/0},
      {"buffer retained on flush failure", fun buffer_retained_on_failure/0},
      {"buffer cap prevents unbounded growth", fun buffer_cap_on_failure/0}
     ]}.

setup() ->
    meck:new(grpcbox_client, [non_strict, no_link]),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(_, _, _) -> ok end),
    %% Use a long interval so flushes don't happen automatically during tests.
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 600000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 5),
    {ok, HBPid} = yuzu_gw_heartbeat_buffer:start_link(),
    {ok, UpPid} = yuzu_gw_upstream:start_link(),
    {HBPid, UpPid}.

cleanup({HBPid, UpPid}) ->
    %% Synchronous stop. notify_no_crash uses spawn_monitor inside the
    %% upstream process to fan out NotifyStreamStatus RPCs; killing the
    %% upstream gen_server with exit(_, shutdown) does not wait for
    %% those children, so they keep logging into the next test module
    %% and the heartbeat buffer keeps draining failed batches. The
    %% earlier sleep(50) was not enough on busy boxes — see #336.
    catch unlink(HBPid),
    catch unlink(UpPid),
    catch gen_server:stop(UpPid, shutdown, 5000),
    catch gen_server:stop(HBPid, shutdown, 5000),
    meck:unload([grpcbox_client, telemetry]),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

heartbeats_batched() ->
    %% Queue several heartbeats.
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"s1">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"s2">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"s3">>}),
    %% No RPC should have been called yet (interval is 10 minutes).
    timer:sleep(50),
    %% The unary mock records calls. Check that BatchHeartbeat was NOT called.
    Calls = meck:history(grpcbox_client),
    BatchCalls = [C || {_, {grpcbox_client, unary, [_, Path, _, _, _]}, _} = C <- Calls,
                       binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assertEqual(0, length(BatchCalls)).

flush_sends_batch() ->
    %% Drain any stale heartbeats from prior tests deterministically.
    %% flush_sync is a gen_server:call, so it serializes after any
    %% pending casts and waits for do_flush to complete before returning.
    %% Why: the original `! flush; timer:sleep(100)` pattern was racy
    %% under coverage-instrumented BEAM — the cast queue could outpace
    %% the 20ms settle window and the assertion would see <2 heartbeats.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    ok = yuzu_gw_heartbeat_buffer:flush_sync(),
    %% Now reset and set up the real assertion mock.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),
    %% Queue exactly 2 heartbeats. flush_sync's gen_server:call serializes
    %% after both casts in the mailbox, so no sleep is needed.
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"f1">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"f2">>}),
    ok = yuzu_gw_heartbeat_buffer:flush_sync(),
    %% Check that BatchHeartbeat was called with exactly 2 heartbeats.
    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),
    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ?assertEqual(2, length(HBs)).

empty_flush_no_rpc() ->
    meck:reset(grpcbox_client),
    %% Flush with empty buffer — just reschedules the timer.
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(50),
    %% No RPC calls should have been made.
    Calls = meck:history(grpcbox_client),
    ?assertEqual(0, length(Calls)).

proxy_register_ok() ->
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {ok, #{session_id => <<"new-sess">>}, #{}}
        end
    end),
    Result = yuzu_gw_upstream:proxy_register(#{info => #{agent_id => <<"a1">>}}),
    ?assertMatch({ok, #{session_id := <<"new-sess">>}}, Result).

proxy_register_error() ->
    %% HA WS-4 4.4 fix: grpcbox_client:unary/5's REAL error return for a
    %% genuine (non-transport) grpc status is a 3-ELEMENT tuple — `error`,
    %% the `{Status, Message}` pair, and the trailers map
    %% (grpcbox_client.erl's unary_handler, via recv_trailers/1) — not the
    %% OLD mocked shape here (`{error, {Status, Message, Trailers}}`, a
    %% 2-element tuple whose 2nd element was itself a 3-tuple), which this
    %% test previously used and do_rpc's matching clause mirrored. That
    %% shape does not match ANYTHING grpcbox actually returns, so do_rpc's
    %% corresponding clause could never fire against the real dependency —
    %% both were wrong together. Fixed to the real shape.
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {error, {14, <<"UNAVAILABLE">>}, #{}}
        end
    end),
    Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertMatch({error, {14, _}}, Result).

proxy_register_http_error() ->
    %% HA WS-4 4.4 round-2 review fix (consistency-auditor c-1 / chaos-injector
    %% CH-2): a FOURTH real grpcbox_client:unary/5 return shape,
    %% `{http_error, {Status, Message}, Trailers}` (a non-grpc-layer HTTP
    %% error), previously matched no clause in do_rpc and would have crashed
    %% this gen_server with a case_clause exception.
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyRegister">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {http_error, {502, <<>>}, #{}}
        end
    end),
    Result = yuzu_gw_upstream:proxy_register(#{info => #{}}),
    ?assertMatch({error, {internal, _}}, Result),
    %% Above all: the gen_server survived and answers normally.
    ?assert(is_pid(whereis(yuzu_gw_upstream))).

proxy_inventory_ok() ->
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"ProxyInventory">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {ok, #{received => true}, #{}}
        end
    end),
    Result = yuzu_gw_upstream:proxy_inventory(#{session_id => <<"s1">>}),
    ?assertMatch({ok, #{received := true}}, Result).

notify_no_crash() ->
    %% Make the notify RPC fail — should not crash the upstream process.
    meck:expect(grpcbox_client, unary, fun(_, Path, _, _, _) ->
        case binary:match(Path, <<"NotifyStreamStatus">>) of
            nomatch -> {ok, #{}, #{}};
            _       -> {error, connection_refused}
        end
    end),
    yuzu_gw_upstream:notify_stream_status(<<"a1">>, <<"s1">>, connected, <<"127.0.0.1">>,
                                           <<"test-home-1">>),
    timer:sleep(100),
    %% The upstream process should still be alive.
    ?assert(is_process_alive(whereis(yuzu_gw_upstream))).

%% CC-03: the StreamStatusNotification the gateway sends on the agent's
%% CONNECTED event — the first message a gateway-connected agent's session
%% causes the gateway to emit upstream — must advertise the literal
%% "command_dispatch_tag_v1" in wire_capabilities, proving to the server's
%% dispatch chokepoint that this gateway build carries
%% CommandRequest.dispatch_tag = 9 through untouched.
notify_advertises_dispatch_tag_capability() ->
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged => true}, #{}}
    end),
    yuzu_gw_upstream:notify_stream_status(<<"a1">>, <<"s1">>, connected, <<"127.0.0.1">>,
                                           <<"test-home-1">>),
    timer:sleep(100),
    Calls = meck:history(grpcbox_client),
    NotifyReqs = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"NotifyStreamStatus">>) =/= nomatch],
    ?assert(length(NotifyReqs) > 0),
    [LastReq | _] = lists:reverse(NotifyReqs),
    ?assert(lists:member(<<"command_dispatch_tag_v1">>,
                         maps:get(wire_capabilities, LastReq, []))).

buffer_retained_on_failure() ->
    %% First drain any existing buffer.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(50),
    meck:reset(grpcbox_client),

    %% Queue 3 heartbeats.
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"r1">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"r2">>}),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"r3">>}),
    timer:sleep(20),

    %% Make flush fail.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(100),

    %% Now make flush succeed and add one more heartbeat.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),
    yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => <<"r4">>}),
    timer:sleep(20),

    %% Trigger flush — should include all 4 heartbeats (3 retained + 1 new).
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(100),

    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),
    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ?assertEqual(4, length(HBs)).

buffer_cap_on_failure() ->
    %% Max buffer is set to 5 in setup. First drain any existing buffer.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {ok, #{acknowledged_count => 0}, #{}}
    end),
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(50),
    meck:reset(grpcbox_client),

    %% Queue 10 heartbeats (exceeds cap of 5).
    lists:foreach(fun(I) ->
        yuzu_gw_heartbeat_buffer:queue_heartbeat(#{session_id => integer_to_binary(I)})
    end, lists:seq(1, 10)),
    timer:sleep(20),

    %% Make flush fail.
    meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) ->
        {error, connection_refused}
    end),
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(100),

    %% Now make flush succeed.
    meck:reset(grpcbox_client),
    meck:expect(grpcbox_client, unary, fun(_, Path, Req, _, _) ->
        case binary:match(Path, <<"BatchHeartbeat">>) of
            nomatch -> {ok, #{}, #{}};
            _ ->
                HBs = maps:get(heartbeats, Req, []),
                {ok, #{acknowledged_count => length(HBs)}, #{}}
        end
    end),

    %% Trigger flush — should include at most 5 (capped) heartbeats.
    whereis(yuzu_gw_heartbeat_buffer) ! flush,
    timer:sleep(100),

    Calls = meck:history(grpcbox_client),
    BatchCalls = [Req || {_, {grpcbox_client, unary, [_, Path, Req, _, _]}, _} <- Calls,
                         binary:match(Path, <<"BatchHeartbeat">>) =/= nomatch],
    ?assert(length(BatchCalls) > 0),
    [LastBatch | _] = BatchCalls,
    HBs = maps:get(heartbeats, LastBatch, []),
    ?assert(length(HBs) =< 5).

%%% R-3 (#1243): classify_tls_error/1 picks TLS handshake failures out of the
%%% upstream transport-error term (so they get a distinct metric) without
%%% mis-flagging ordinary RPC/network errors and without looping on deep terms.
classify_tls_error_test() ->
    %% Bare and nested tls_alert → recognised, alert name surfaced as the kind.
    ?assertEqual({true, <<"unknown_ca">>},
                 yuzu_gw_upstream:classify_tls_error({tls_alert, {unknown_ca, "msg"}})),
    ?assertEqual({true, <<"certificate_expired">>},
                 yuzu_gw_upstream:classify_tls_error(
                     {shutdown, {tls_alert, {certificate_expired, "msg"}}})),
    ?assertEqual({true, <<"handshake_failure">>},
                 yuzu_gw_upstream:classify_tls_error({tls_alert, handshake_failure})),
    %% Bad ssl options (unreadable/missing certfile) → recognised.
    ?assertMatch({true, _},
                 yuzu_gw_upstream:classify_tls_error({options, {certfile, "/missing.pem"}})),
    %% Ordinary transport/RPC errors → NOT flagged as TLS.
    ?assertEqual({false, <<>>}, yuzu_gw_upstream:classify_tls_error(closed)),
    ?assertEqual({false, <<>>}, yuzu_gw_upstream:classify_tls_error(timeout)),
    ?assertEqual({false, <<>>}, yuzu_gw_upstream:classify_tls_error({grpc_error, 14})),
    %% A deeply-nested non-TLS term terminates (depth-bounded) rather than looping.
    ?assertEqual({false, <<>>},
                 yuzu_gw_upstream:classify_tls_error({a, {b, {c, {d, {e, deep}}}}})).
