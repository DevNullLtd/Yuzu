%%%-------------------------------------------------------------------
%%% @doc Wire tests of the two per-connection memory bounds in the gRPC layer
%%% (yuzu_grpc_stream_h), against a REAL Cowboy/Ranch listener driven by a raw
%%% gun HTTP/2 client (the attacker's view: it opens streams and sends a length
%%% prefix with the body short of its last byte, so a request never completes):
%%%
%%%   - max_connection_memory_bytes: a well-behaved client sending messages up
%%%     to the FULL max_message_bytes, back to back, is never killed by the
%%%     production-default ceiling (also with every scheduler kept busy, since
%%%     what the ceiling sees depends on when the connection process collects
%%%     its garbage); a connection that buffers more than the ceiling of
%%%     half-finished requests is killed by the VM, its kill is counted, and a
%%%     second connection doing ordinary work is untouched; and the connection
%%%     process collects its garbage as request bytes go through it, so a
%%%     delivered full-size request leaves no dead binaries for the ceiling to
%%%     count;
%%%   - request_timeout_ms: a unary stream that buffers its request past the
%%%     deadline is aborted DEADLINE_EXCEEDED and its buffer dropped, while a
%%%     bidirectional stream (an agent's Subscribe) that delivered its first
%%%     message is never cut by it.
%%%
%%% These bounds are time- and memory-driven by nature, so the cases wait on the
%%% event (the connection going down, the stream's trailers), not on a fixed
%%% sleep.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_grpc_memory_bounds_tests).
-include_lib("eunit/include/eunit.hrl").
-include("../src/yuzu_grpc.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(SUBSCRIBE, <<"/yuzu.agent.v1.AgentService/Subscribe">>).

%%--------------------------------------------------------------------
%% Bound 1: per-connection memory ceiling
%%--------------------------------------------------------------------

%% The production message limit; every case below runs under the ceiling the
%% stream handler derives from it (no explicit max_connection_memory_bytes), the
%% default every shipped config uses.
-define(MAX_MSG, 4 * 1024 * 1024).
%% Full-size requests sent back to back on one connection.
-define(FULL_SIZE_REPEATS, 20).

full_size_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     [{timeout, 120, fun full_size_requests_survive_the_default_ceiling/0},
      {timeout, 120, fun full_size_requests_survive_busy_schedulers/0}]}.

%% A legit client sends messages of exactly max_message_bytes, one after the
%% other on one connection: the ceiling must never kill it. The ceiling counts
%% the binaries the connection process still references when it collects its
%% garbage, so what matters is the worst moment of every request, not the
%% average; 20 in a row cross many collections.
full_size_requests_survive_the_default_ceiling() ->
    full_size_requests(bounds_full, ?FULL_SIZE_REPEATS).

%% The same with every scheduler kept busy by a spinning process, so the
%% connection process is descheduled at arbitrary points (the CI condition the
%% default ceiling once failed under). Fewer repeats: each is slower.
full_size_requests_survive_busy_schedulers() ->
    Spinners = [spawn(fun spin/0) || _ <- lists:seq(1, erlang:system_info(schedulers_online))],
    try
        full_size_requests(bounds_busy, ?FULL_SIZE_REPEATS div 2)
    after
        [exit(P, kill) || P <- Spinners]
    end.

full_size_requests(ChanName, Repeats) ->
    {Port, L} = start(#{max_message_bytes => ?MAX_MSG, request_timeout_ms => infinity}),
    Kill0 = counter(yuzu_gw_grpc_connection_killed_total, [<<"max_heap_size">>]),
    Chan = yuzu_gw_test_listener:client_channel(ChanName, #{port => Port}),
    try
        ?assertMatch({ok, _, _}, unary(Chan, #{session_id => <<"ok">>})),
        [Conn] = ranch:procs({yuzu_grpc, bounds}, connections),
        %% The ceiling in force is the derived default, whatever it is set to.
        {max_heap_size, #{size := Words}} = erlang:process_info(Conn, max_heap_size),
        ?assertEqual(?YUZU_GRPC_MAX_CONN_MEMORY_FACTOR * ?MAX_MSG,
                     Words * erlang:system_info(wordsize)),
        Msg = full_size_message(?MAX_MSG),
        ?assertEqual(?MAX_MSG, byte_size(encode_hb(Msg))),
        Results = [unary(Chan, Msg, 30000) || _ <- lists:seq(1, Repeats)],
        ?assertEqual(lists:duplicate(Repeats, ok), [ok_of(R) || R <- Results]),
        ?assert(is_process_alive(Conn)),
        ?assertEqual(Kill0, counter(yuzu_gw_grpc_connection_killed_total,
                                    [<<"max_heap_size">>]))
    after
        yuzu_gw_test_listener:stop_channel(Chan),
        yuzu_gw_test_listener:stop(L)
    end.

ok_of({ok, _, _}) -> ok;
ok_of(Other) -> Other.

spin() -> spin(0).
spin(N) -> spin(N + 1).

%% A HeartbeatRequest whose encoding is exactly Size bytes: the largest message
%% the listener accepts.
full_size_message(Size) ->
    full_size_message(Size, <<"ok">>).

%% The same for a stub command other than `ok' (the session_id).
full_size_message(Size, Command) ->
    Empty = byte_size(encode_hb(blob_message(Command, <<>>))),
    fit_message(Size, Command, Size - Empty - 8).

fit_message(Size, Command, BlobBytes) ->
    Msg = blob_message(Command, binary:copy(<<"x">>, BlobBytes)),
    case byte_size(encode_hb(Msg)) of
        Size -> Msg;
        S when S < Size -> fit_message(Size, Command, BlobBytes + 1);
        _ -> fit_message(Size, Command, BlobBytes - 1)
    end.

blob_message(Command, Blob) ->
    #{session_id => Command, status_tags => #{<<"blob">> => Blob}}.

encode_hb(Msg) ->
    agent_pb:encode_msg(Msg, 'yuzu.agent.v1.HeartbeatRequest').

%% Full-size requests sent on one connection for the collection case.
-define(COLLECT_REPEATS, 5).
%% A collection is forced after every MiB of request bytes, so a request of
%% max_message_bytes forces about four (three while its DATA arrives, one once
%% it is complete). The floor asserted is well under that but above zero.
-define(MIN_COLLECTIONS_PER_REQUEST, 3).

collect_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     {timeout, 120, fun full_size_requests_leave_no_dead_binaries/0}}.

%% The other half of the ceiling fix, next to the incremental reader in
%% yuzu_grpc_frame:read/3: the stream handler has the connection process collect
%% its garbage after every MiB of request bytes (yuzu_grpc_stream_h's
%% maybe_collect/2). The ceiling counts every binary the process references
%% when it collects, the dead ones included, so without those collections the
%% garbage of one full-size request is still counted while the next one
%% arrives. The full-size cases above do not catch its loss: the VM's own
%% collections keep one connection under the ceiling there.
%%
%% Each full-size request goes to a stub handler that blocks (`sleep') until
%% the test releases it, so the stream is open while the test looks. Two
%% checks, neither timed:
%%   - behaviour: while the handler holds the request, the connection process
%%     references (almost) no binaries: the request's chunks and joined message
%%     are dead in it, and were collected. Without the forced collections they
%%     are still referenced: between delivering the request and the test's
%%     look the connection allocates next to nothing, so the VM seldom
%%     collects on its own (with the collections disabled, the first request
%%     always showed 12 MiB still referenced, most later ones 8 to 12 MiB);
%%   - mechanism: the connection process called erlang:garbage_collect at least
%%     ?MIN_COLLECTIONS_PER_REQUEST times per request. That is a count of
%%     request bytes, not of how they happened to arrive, so it fails for
%%     certain where the first check could pass by the VM's luck. It is traced
%%     in a private trace session, destroyed afterwards, so no other process or
%%     test sees the trace.
full_size_requests_leave_no_dead_binaries() ->
    {Port, L} = start(#{max_message_bytes => ?MAX_MSG, request_timeout_ms => infinity}),
    Chan = yuzu_gw_test_listener:client_channel(bounds_collect, #{port => Port}),
    Session = trace:session_create(yuzu_gw_grpc_collect_trace, self(), []),
    ok = yuzu_grpc_stub_svc:notify(self()),
    try
        ?assertMatch({ok, _, _}, unary(Chan, #{session_id => <<"ok">>})),
        [Conn] = ranch:procs({yuzu_grpc, bounds}, connections),
        Msg = full_size_message(?MAX_MSG, <<"sleep">>),
        _ = [trace:function(Session, {erlang, garbage_collect, A}, true, [local])
             || A <- [0, 1, 2]],
        1 = trace:process(Session, Conn, true, [call]),
        Held = [held_request_bytes(Chan, Conn, Msg) || _ <- lists:seq(1, ?COLLECT_REPEATS)],
        1 = trace:process(Session, Conn, false, [call]),
        TraceRef = erlang:trace_delivered(Conn),
        receive {trace_delivered, Conn, TraceRef} -> ok end,
        Collections = count_collect_calls(Conn, 0),
        ?assertEqual([], [B || B <- Held, B >= 1024 * 1024]),
        ?assertMatch(N when N >= ?MIN_COLLECTIONS_PER_REQUEST * ?COLLECT_REPEATS,
                     Collections)
    after
        trace:session_destroy(Session),
        flush_collect_calls(),
        yuzu_gw_test_listener:stop_channel(Chan),
        yuzu_gw_test_listener:stop(L)
    end.

%% Send one request to a blocking handler and return the binary bytes the
%% connection process references while the handler holds it. The handler has
%% the request, so the connection finished the data/4 call that delivered it,
%% and with it queued its own collection message. Two sys:get_state/1 round
%% trips then wait for the connection to have handled that message: the first
%% may be queued before it (the connection can be descheduled between handing
%% the request over and queuing the collection), the second is queued after the
%% connection returned to its loop, so after it. Then release the handler.
held_request_bytes(Chan, Conn, Msg) ->
    Self = self(),
    {Caller, Mon} = spawn_monitor(fun() -> Self ! {held_reply, self(), unary(Chan, Msg, 30000)} end),
    Handler = receive {stub, sleeping, H} -> H
              after 30000 -> erlang:error(handler_never_got_the_request)
              end,
    _ = sys:get_state(Conn),
    _ = sys:get_state(Conn),
    Bytes = binary_bytes(Conn),
    Handler ! release,
    receive {held_reply, Caller, Reply} -> ?assertMatch({ok, _, _}, Reply)
    after 30000 -> erlang:error(held_request_not_answered)
    end,
    receive {'DOWN', Mon, process, Caller, _} -> ok end,
    Bytes.

count_collect_calls(Conn, N) ->
    receive
        {trace, Conn, call, {erlang, garbage_collect, _}} ->
            count_collect_calls(Conn, N + 1)
    after 0 ->
        N
    end.

flush_collect_calls() ->
    receive {trace, _, call, {erlang, garbage_collect, _}} -> flush_collect_calls()
    after 0 -> ok
    end.

%% The bytes of the off-heap binaries a process references, dead or alive: what
%% the ceiling counts when the process collects.
binary_bytes(Pid) ->
    {binary, Bins} = erlang:process_info(Pid, binary),
    lists:sum([Size || {_, Size, _} <- Bins]).

max_conn_memory_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     {timeout, 60, fun max_conn_memory_kills_the_flooder/0}}.

max_conn_memory_kills_the_flooder() ->
    %% The production-default sizing: a 4 MiB message limit and the ceiling
    %% derived from it. The receive deadline is off so the KILL, not the
    %% deadline, ends the flood.
    {Port, L} = start(#{max_message_bytes => ?MAX_MSG, request_timeout_ms => infinity}),
    Kill0 = counter(yuzu_gw_grpc_connection_killed_total, [<<"max_heap_size">>]),
    LegitChan = yuzu_gw_test_listener:client_channel(bounds_legit, #{port => Port}),
    try
        %% A legit connection: an ordinary call, then a full-size one.
        ?assertMatch({ok, _, _}, unary(LegitChan, #{session_id => <<"ok">>})),
        ?assertMatch({ok, _, _}, unary(LegitChan, full_size_message(?MAX_MSG), 30000)),

        %% The flooder: 32 streams, each a 4 MiB length prefix with all but the
        %% last byte, no grpc-timeout. Their buffers cross the ceiling.
        {ok, C} = gun:open("127.0.0.1", Port, #{protocols => [http2], retry => 0}),
        {ok, http2} = gun:await_up(C, 5000),
        CMon = erlang:monitor(process, C),
        Body = binary:copy(<<"A">>, ?MAX_MSG - 1),
        [begin
             S = gun:post(C, ?HEARTBEAT, grpc_headers()),
             gun:data(C, S, nofin, [<<0, (?MAX_MSG):32>>, Body])
         end || _ <- lists:seq(1, 32)],

        %% The connection is killed: gun sees it go down.
        receive {'DOWN', CMon, process, C, _} -> ok
        after 30000 -> erlang:error(flooder_connection_not_killed) end,

        ok = wait_counter_above(yuzu_gw_grpc_connection_killed_total,
                                [<<"max_heap_size">>], Kill0, 100),

        %% The legit connection still works after the flood.
        ?assertMatch({ok, _, _}, unary(LegitChan, #{session_id => <<"ok">>})),
        LiveConns = [P || P <- ranch:procs({yuzu_grpc, bounds}, connections),
                          is_process_alive(P)],
        ?assertEqual(1, length(LiveConns))
    after
        yuzu_gw_test_listener:stop_channel(LegitChan),
        yuzu_gw_test_listener:stop(L)
    end.

%%--------------------------------------------------------------------
%% Bound 2: request-receive deadline
%%--------------------------------------------------------------------

request_timeout_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     {timeout, 30, fun request_timeout_aborts_a_stalled_unary/0}}.

request_timeout_aborts_a_stalled_unary() ->
    {Port, L} = start(#{max_message_bytes => ?MAX_MSG, request_timeout_ms => 400}),
    T0 = counter(yuzu_gw_grpc_recv_timeout_total, []),
    {ok, C} = gun:open("127.0.0.1", Port, #{protocols => [http2], retry => 0}),
    {ok, http2} = gun:await_up(C, 5000),
    try
        %% A unary stream: a length prefix and one byte, then stall.
        S = gun:post(C, ?HEARTBEAT, grpc_headers()),
        gun:data(C, S, nofin, [<<0, (4 * 1024 * 1024):32>>, <<"A">>]),
        ?assertEqual(<<"4">>, grpc_status(C, S, 5000)),
        ok = wait_counter_above(yuzu_gw_grpc_recv_timeout_total, [], T0, 100),

        %% A Subscribe (bidi) that delivers its first message is NOT cut by the
        %% request deadline: it is still open well past the 400 ms deadline.
        Sub = gun:post(C, ?SUBSCRIBE,
                       [{<<"x-yuzu-session-id">>, <<"s1">>} | grpc_headers()]),
        First = yuzu_grpc_frame:encode(
                  agent_pb:encode_msg(#{command_id => <<"keepalive">>},
                                      'yuzu.agent.v1.CommandResponse')),
        gun:data(C, Sub, nofin, First),
        ?assert(stream_open_after(C, Sub, 1200))
    after
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    {ok, _} = application:ensure_all_started(prometheus),
    %% Attach the prometheus handler cleanly. It is a GLOBAL telemetry handler:
    %% leaving it attached would make later test modules' heartbeat events, which
    %% run with no handler, start hitting it (an eunit cross-module leak, #336).
    catch telemetry:detach(yuzu_gw_prometheus),
    yuzu_gw_telemetry:setup(),
    ok = yuzu_gw_conn_watch:install(),
    yuzu_grpc_stub_svc:init_state(),
    ok.

cleanup(_) ->
    ok = yuzu_gw_conn_watch:remove(),
    catch telemetry:detach(yuzu_gw_prometheus),
    ok.

start(Limits) ->
    yuzu_gw_test_listener:start(
      #{name => bounds, service_protos => [agent_pb],
        services => #{?SVC => yuzu_grpc_stub_svc},
        http2 => #{idle_timeout => 180000, max_concurrent_streams => 32},
        limits => Limits}).

grpc_headers() ->
    [{<<"content-type">>, <<"application/grpc">>}, {<<"te">>, <<"trailers">>}].

unary(Chan, Msg) -> unary(Chan, Msg, 5000).
unary(Chan, Msg, Timeout) ->
    yuzu_grpc_client:unary(#{}, ?HEARTBEAT, Msg, hb_def(),
                           #{channel => Chan, timeout => Timeout}).

hb_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

%% The grpc-status of a stream, from the trailers or a trailers-only response.
grpc_status(C, S, Timeout) ->
    receive
        {gun_response, C, S, nofin, _Code, Headers} ->
            case proplists:get_value(<<"grpc-status">>, Headers) of
                undefined -> grpc_status(C, S, Timeout);
                GS -> GS
            end;
        {gun_response, C, S, fin, _Code, Headers} ->
            proplists:get_value(<<"grpc-status">>, Headers);
        {gun_trailers, C, S, Trailers} ->
            proplists:get_value(<<"grpc-status">>, Trailers);
        {gun_error, C, S, _} -> error;
        _Other -> grpc_status(C, S, Timeout)
    after Timeout -> timeout end.

%% True when the stream has NOT ended (no trailers/error) after a grace window.
stream_open_after(C, S, Grace) ->
    receive
        {gun_trailers, C, S, _} -> false;
        {gun_response, C, S, fin, _, _} -> false;
        {gun_error, C, S, _} -> false
    after Grace -> true
    end.

counter(Name, Labels) ->
    case prometheus_counter:value(Name, Labels) of
        undefined -> 0;
        V -> V
    end.

wait_counter_above(_Name, _Labels, _Base, 0) ->
    erlang:error(counter_did_not_advance);
wait_counter_above(Name, Labels, Base, N) ->
    case counter(Name, Labels) > Base of
        true -> ok;
        false -> timer:sleep(20), wait_counter_above(Name, Labels, Base, N - 1)
    end.
