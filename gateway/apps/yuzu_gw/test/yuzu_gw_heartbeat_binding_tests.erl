%%%-------------------------------------------------------------------
%%% @doc Unit tests for connection-bound heartbeat admission.
%%%
%%% `yuzu_gw_agent_service:heartbeat/2' admits a heartbeat only for a
%%% session this node holds, and only when it arrives on the same HTTP/2
%%% connection that opened the session's Subscribe stream (or, for a
%%% session still pending, on the connection that performed the Register).
%%% Every rejection is the identical `NOT_FOUND "unknown session"', is
%%% counted and is never queued.
%%%
%%% The connection key is injected by mocking `yuzu_gw_conn:key_from_ctx/1'
%%% (the real accessor needs a live grpcbox stream; that part is covered
%%% end to end by `yuzu_gw_heartbeat_conn_rpc_tests'). The registry is the
%%% real one; the heartbeat buffer and the upstream client are mocks.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_binding_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

%% logger handler callback (log capture)
-export([log/2]).
%% telemetry handler callback
-export([handle_event/4]).

-define(SESSIONS, yuzu_gw_sessions).
-define(PENDING,  yuzu_gw_pending).
-define(HB_HANDLER, yuzu_gw_heartbeat_binding_tests_events).
-define(EVENTS_TAB, yuzu_gw_heartbeat_binding_tests_events_tab).
-define(LOG_HANDLER, yuzu_gw_heartbeat_binding_tests_logs).
-define(CTX_KEY, yuzu_test_conn_key).

%%%===================================================================
%%% Fixture
%%%===================================================================

binding_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"unknown session: rejected, not queued, counted",
       fun unknown_session_rejected/0},
      {"held session on a different connection: rejected, not queued, mismatch counted",
       fun wrong_connection_rejected/0},
      {"held session on its own connection: admitted, request queued verbatim",
       fun bound_connection_admitted/0},
      {"request without a connection key is rejected",
       fun no_connection_key_rejected/0},
      {"malformed session ids are rejected without raising",
       fun malformed_session_ids_rejected/0},
      {"pending session: only the registering connection is admitted",
       fun pending_binding/0},
      {"pending session without a recorded key is rejected",
       fun pending_without_key_rejected/0},
      {"pending session past its TTL is rejected",
       fun pending_expired_rejected/0},
      {"replacement: the old session is rejected, the new one admitted only on its own connection",
       fun replacement_binding/0},
      {"cleanup of a superseded process leaves the newer session bound",
       fun superseded_cleanup_is_fenced/0},
      {"cleanup by a process that does not own the session leaves it indexed",
       fun non_owner_cleanup_keeps_session/0},
      {"cleanup of the owning process removes exactly its own session",
       fun owner_cleanup_removes_row/0},
      {"legacy deregister_agent/1 also removes the session row",
       fun legacy_deregister_removes_row/0},
      {"process death removes the session row",
       fun process_death_removes_row/0},
      {"registrations without a connection key never admit",
       fun unbound_registrations_never_admit/0},
      {"every rejection reason yields the same response",
       fun uniform_response/0},
      {"admission does not depend on the upstream server",
       fun independent_of_upstream/0},
      {"reannounce leaves the binding unchanged",
       fun reannounce_leaves_binding/0},
      {"registry restart: heartbeats fail closed without raising",
       fun registry_restart_fails_closed/0},
      {"missing session index: the registry keeps routing, heartbeats fail closed",
       fun missing_session_index_keeps_routing/0},
      {"the session index is protected and the pending table stays public",
       fun table_protection/0},
      {"lookup_session/1 is local, live-checked and reports the key",
       fun lookup_session_contract/0},
      {"Register records the connection key in the pending row",
       fun register_records_conn_key/0},
      {"rejections produce a rate-limited summary log with no session id",
       fun rejection_log_is_rate_limited_and_id_free/0},
      {"Register and agent-connected info logs carry no session id",
       fun info_logs_carry_no_session_id/0},
      {"500 concurrent rejections are all counted and produce one summary line",
       fun rejection_storm_is_counted_and_logs_once/0},
      {"re-registration churn: one index row per agent, no superseded session admitted",
       {timeout, 60, fun registration_churn_keeps_one_row_per_agent/0}}
     ]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(yuzu_gw_conn),
    catch meck:unload(yuzu_gw_heartbeat_buffer),
    catch meck:unload(yuzu_gw_upstream),
    ok = meck:new(yuzu_gw_conn, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_conn, key_from_ctx,
                     fun(Ctx) -> ctx:get(Ctx, ?CTX_KEY, undefined) end),
    ok = meck:new(yuzu_gw_heartbeat_buffer, [passthrough, no_link]),
    ok = meck:expect(yuzu_gw_heartbeat_buffer, queue_heartbeat, fun(_) -> ok end),
    ok = meck:new(yuzu_gw_upstream, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_upstream, notify_stream_status, fun(_, _, _, _, _) -> ok end),
    ok = meck:expect(yuzu_gw_upstream, proxy_register,
                     fun(#{info := #{agent_id := Id}}) ->
                         {ok, #{session_id => <<"reg-session-", Id/binary>>}}
                     end),
    %% Events are recorded in a public table: eunit runs the fixture setup
    %% and the test body in different processes, so a pid captured here
    %% would not be the one the test reads from.
    catch ets:delete(?EVENTS_TAB),
    ?EVENTS_TAB = ets:new(?EVENTS_TAB, [named_table, public, ordered_set]),
    catch telemetry:detach(?HB_HANDLER),
    ok = telemetry:attach_many(?HB_HANDLER,
                               [[yuzu, gw, heartbeat, rejected],
                                [yuzu, gw, heartbeat, session_mismatch]],
                               fun ?MODULE:handle_event/4, none),
    Prev = application:get_env(yuzu_gw, telemetry_gauge_interval_ms),
    application:set_env(yuzu_gw, telemetry_gauge_interval_ms, 600000),
    flush(),
    Prev.

cleanup(Prev) ->
    catch telemetry:detach(?HB_HANDLER),
    catch ets:delete(?EVENTS_TAB),
    case Prev of
        {ok, V}   -> application:set_env(yuzu_gw, telemetry_gauge_interval_ms, V);
        undefined -> application:unset_env(yuzu_gw, telemetry_gauge_interval_ms)
    end,
    catch meck:unload([yuzu_gw_conn, yuzu_gw_heartbeat_buffer, yuzu_gw_upstream]),
    ok.

handle_event(Event, Measurements, Meta, _Config) ->
    true = ets:insert(?EVENTS_TAB, {erlang:unique_integer([monotonic]),
                                    Event, Measurements, Meta}),
    ok.

%%%===================================================================
%%% Helpers
%%%===================================================================

uid(Prefix) ->
    iolist_to_binary([Prefix, "-", integer_to_list(erlang:unique_integer([positive]))]).

holder() ->
    spawn(fun() -> receive stop -> ok end end).

ctx_with(Key) ->
    ctx:set(ctx:background(), ?CTX_KEY, Key).

beat(Key, SessionId) ->
    beat(Key, SessionId, #{}).

beat(Key, SessionId, Extra) ->
    yuzu_gw_agent_service:heartbeat(ctx_with(Key),
                                    maps:merge(#{session_id => SessionId}, Extra)).

rejected() ->
    {grpc_error, {?GRPC_STATUS_NOT_FOUND, <<"unknown session">>}}.

%% Register a live agent process bound to ConnKey; returns its pid.
bind(AgentId, SessionId, ConnKey) ->
    Pid = holder(),
    ok = yuzu_gw_registry:register_agent(AgentId, Pid, SessionId, [], <<>>,
                                         #{}, ConnKey),
    Pid.

queued() ->
    meck:num_calls(yuzu_gw_heartbeat_buffer, queue_heartbeat, '_').

flush() ->
    true = ets:delete_all_objects(?EVENTS_TAB),
    ok.

%% All heartbeat telemetry events recorded so far, oldest first; clears them.
events() ->
    Events = [{E, M, Meta} || {_, E, M, Meta} <- ets:tab2list(?EVENTS_TAB)],
    flush(),
    Events.

reject_event(Reason) ->
    {[yuzu, gw, heartbeat, rejected], #{count => 1}, #{reason => Reason}}.

mismatch_event() ->
    {[yuzu, gw, heartbeat, session_mismatch], #{count => 1}, #{}}.

assert_events(Expected) ->
    Got = [{E, M, maps:with([reason], Meta)} || {E, M, Meta} <- events()],
    ?assertEqual(Expected, Got).

%%%===================================================================
%%% Admission
%%%===================================================================

unknown_session_rejected() ->
    ?assertEqual(rejected(), beat(conn_a, uid(<<"nobody">>))),
    ?assertEqual(0, queued()),
    assert_events([reject_event(unknown_session)]).

wrong_connection_rejected() ->
    S = uid(<<"s">>),
    bind(uid(<<"a">>), S, conn_a),
    ?assertEqual(rejected(), beat(conn_b, S)),
    ?assertEqual(0, queued()),
    assert_events([mismatch_event()]).

bound_connection_admitted() ->
    S = uid(<<"s">>),
    bind(uid(<<"a">>), S, conn_a),
    Extra = #{status_tags => #{<<"yuzu.os">> => <<"linux">>}},
    {ok, Resp, _} = beat(conn_a, S, Extra),
    ?assertMatch(#{acknowledged := true, pending_commands := []}, Resp),
    ?assertEqual(1, queued()),
    ?assert(meck:called(yuzu_gw_heartbeat_buffer, queue_heartbeat,
                        [#{session_id => S, status_tags => #{<<"yuzu.os">> => <<"linux">>}}])),
    assert_events([]).

no_connection_key_rejected() ->
    S = uid(<<"s">>),
    bind(uid(<<"a">>), S, conn_a),
    ?assertEqual(rejected(), beat(undefined, S)),
    ?assertEqual(0, queued()),
    assert_events([reject_event(no_connection)]).

malformed_session_ids_rejected() ->
    Bad = [undefined, <<>>, 42, "string", {tuple}],
    lists:foreach(fun(B) ->
        ?assertEqual(rejected(),
                     yuzu_gw_agent_service:heartbeat(ctx_with(conn_a), #{session_id => B}))
    end, Bad),
    ?assertEqual(rejected(),
                 yuzu_gw_agent_service:heartbeat(ctx_with(conn_a), #{})),
    ?assertEqual(0, queued()),
    Got = [R || {[yuzu, gw, heartbeat, rejected], _, #{reason := R}} <- events()],
    ?assertEqual(lists:duplicate(length(Bad) + 1, unknown_session), Got).

%%%===================================================================
%%% Pending (Register done, Subscribe not yet admitted)
%%%===================================================================

pending_binding() ->
    S = uid(<<"p">>),
    ok = yuzu_gw_registry:store_pending(S, #{agent_id => <<"x">>, conn_key => conn_a}),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    ?assertEqual(rejected(), beat(conn_b, S)),
    ?assertEqual(1, queued()),
    assert_events([mismatch_event()]),
    %% Admission does not consume the pending row: Subscribe still can.
    ?assertMatch(#{agent_id := <<"x">>}, yuzu_gw_registry:take_pending(S)).

pending_without_key_rejected() ->
    S = uid(<<"p">>),
    ok = yuzu_gw_registry:store_pending(S, #{agent_id => <<"x">>}),
    ?assertEqual(rejected(), beat(conn_a, S)),
    ?assertEqual(0, queued()),
    assert_events([reject_event(no_connection)]).

pending_expired_rejected() ->
    S = uid(<<"p">>),
    Old = erlang:system_time(millisecond) - 10 * 60 * 1000,
    true = ets:insert(?PENDING, {S, #{agent_id => <<"x">>, conn_key => conn_a}, Old}),
    ?assertEqual(rejected(), beat(conn_a, S)),
    ?assertEqual(0, queued()),
    assert_events([reject_event(unknown_session)]),
    true = ets:delete(?PENDING, S).

%%%===================================================================
%%% Lifecycle
%%%===================================================================

replacement_binding() ->
    A = uid(<<"a">>),
    S1 = uid(<<"s1">>),
    S2 = uid(<<"s2">>),
    P1 = bind(A, S1, conn_a),
    ?assertMatch({ok, _, _}, beat(conn_a, S1)),
    P2 = bind(A, S2, conn_b),
    flush(),
    %% The superseded session no longer admits anywhere.
    ?assertEqual(rejected(), beat(conn_a, S1)),
    ?assertEqual(rejected(), beat(conn_b, S1)),
    %% The new session admits only on its own connection.
    ?assertMatch({ok, _, _}, beat(conn_b, S2)),
    ?assertEqual(rejected(), beat(conn_a, S2)),
    exit(P1, kill),
    exit(P2, kill).

superseded_cleanup_is_fenced() ->
    A = uid(<<"a">>),
    S1 = uid(<<"s1">>),
    S2 = uid(<<"s2">>),
    P1 = bind(A, S1, conn_a),
    P2 = bind(A, S2, conn_b),
    %% The old process finishes its own cleanup after the replacement.
    ok = yuzu_gw_registry:deregister_agent(A, P1, S1),
    sync_registry(),
    ?assertMatch({ok, _, _}, beat(conn_b, S2)),
    %% lookup_local_session/1 reads the routing table only: lookup/1 would
    %% fall back to the pg group, which still holds P2 and would hide a
    %% deleted routing row.
    ?assertEqual({ok, {P2, S2}}, yuzu_gw_registry:lookup_local_session(A)),
    ?assertMatch({ok, #{pid := P2}}, yuzu_gw_registry:lookup_session(S2)),
    exit(P1, kill),
    exit(P2, kill).

%% The index entry is removed only when it belongs to the calling pid: a
%% second live process naming the same session id must not unindex it.
non_owner_cleanup_keeps_session() ->
    A = uid(<<"a">>),
    S = uid(<<"s">>),
    P = bind(A, S, conn_a),
    Other = holder(),
    ok = yuzu_gw_registry:deregister_agent(uid(<<"other">>), Other, S),
    sync_registry(),
    ?assertMatch({ok, #{pid := P}}, yuzu_gw_registry:lookup_session(S)),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    exit(Other, kill),
    exit(P, kill).

owner_cleanup_removes_row() ->
    A = uid(<<"a">>),
    S = uid(<<"s">>),
    P = bind(A, S, conn_a),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    ok = yuzu_gw_registry:deregister_agent(A, P, S),
    sync_registry(),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(S)),
    ?assertEqual(error, yuzu_gw_registry:lookup(A)),
    flush(),
    ?assertEqual(rejected(), beat(conn_a, S)),
    exit(P, kill).

legacy_deregister_removes_row() ->
    A = uid(<<"a">>),
    S = uid(<<"s">>),
    P = bind(A, S, conn_a),
    yuzu_gw_registry:deregister_agent(A),
    sync_registry(),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(S)),
    exit(P, kill).

process_death_removes_row() ->
    A = uid(<<"a">>),
    S = uid(<<"s">>),
    P = bind(A, S, conn_a),
    ?assertMatch({ok, _}, yuzu_gw_registry:lookup_session(S)),
    exit(P, kill),
    ok = wait_until(fun() -> ets:lookup(?SESSIONS, S) =:= [] end, 2000),
    flush(),
    ?assertEqual(rejected(), beat(conn_a, S)).

unbound_registrations_never_admit() ->
    S5 = uid(<<"s5">>),
    S6 = uid(<<"s6">>),
    P5 = holder(),
    P6 = holder(),
    ok = yuzu_gw_registry:register_agent(uid(<<"a5">>), P5, S5, [], <<>>),
    ok = yuzu_gw_registry:register_agent(uid(<<"a6">>), P6, S6, [], <<>>, #{}),
    ?assertEqual(rejected(), beat(conn_a, S5)),
    ?assertEqual(rejected(), beat(conn_a, S6)),
    %% A call without a connection key never matches a session without one
    %% either: two missing keys are not "the same connection".
    ?assertEqual(rejected(), beat(undefined, S5)),
    ?assertEqual(rejected(), beat(undefined, S6)),
    ?assertEqual(0, queued()),
    ?assertEqual(lists:duplicate(4, reject_event(no_connection)),
                 [{E, M, maps:with([reason], Meta)} || {E, M, Meta} <- events()]),
    exit(P5, kill),
    exit(P6, kill).

uniform_response() ->
    Known = uid(<<"known">>),
    bind(uid(<<"a">>), Known, conn_a),
    Pending = uid(<<"pending">>),
    ok = yuzu_gw_registry:store_pending(Pending, #{agent_id => <<"x">>, conn_key => conn_a}),
    Responses = [beat(conn_a, uid(<<"unknown">>)),   %% not held
                 beat(undefined, Known),             %% no key presented
                 beat(conn_b, Known),                %% held, other connection
                 beat(conn_b, Pending)],             %% pending, other connection
    ?assertEqual(lists:duplicate(4, rejected()), Responses).

independent_of_upstream() ->
    S = uid(<<"s">>),
    bind(uid(<<"a">>), S, conn_a),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    ?assertEqual(2, queued()),
    %% No heartbeat touched the upstream client: admission is local state only.
    ?assertEqual([], meck:history(yuzu_gw_upstream)).

reannounce_leaves_binding() ->
    A = uid(<<"a">>),
    S = uid(<<"s">>),
    Args = #{agent_id => A, session_id => S, stream_pid => self(),
             agent_info => #{agent_id => A}, peer_addr => <<"127.0.0.1">>,
             conn_key => conn_a},
    {ok, Agent} = yuzu_gw_agent:start_link(Args),
    unlink(Agent),
    ok = wait_until(fun() -> yuzu_gw_registry:lookup_session(S) =/= error end, 2000),
    Before = ets:lookup(?SESSIONS, S),
    ?assertMatch([{S, A, Agent, conn_a}], Before),
    %% The registry's replay surfaces and the agent's own reannounce path.
    _ = yuzu_gw_registry:all_register_reqs(),
    _ = yuzu_gw_registry:lookup_local_session(A),
    ok = yuzu_gw_agent:reannounce(Agent, S),
    ok = yuzu_gw_agent:reannounce(Agent, uid(<<"stale">>)),
    {ok, _} = yuzu_gw_agent:get_info(Agent),
    ?assertEqual(Before, ets:lookup(?SESSIONS, S)),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    ?assertEqual(rejected(), beat(conn_b, S)),
    yuzu_gw_agent:disconnect(Agent),
    ok = wait_until(fun() -> ets:lookup(?SESSIONS, S) =:= [] end, 2000).

registry_restart_fails_closed() ->
    S = uid(<<"s">>),
    bind(uid(<<"a">>), S, conn_a),
    %% A normal stop drops the registry's tables without sending a kill
    %% signal down its links (the process that started it is not ours).
    ok = gen_server:stop(whereis(yuzu_gw_registry)),
    ok = wait_until(fun() ->
        ets:info(?SESSIONS, size) =:= undefined andalso
        ets:info(?PENDING, size) =:= undefined
    end, 2000),
    flush(),
    try
        ?assertEqual(rejected(), beat(conn_a, S)),
        ?assertEqual(0, queued()),
        assert_events([reject_event(registry_unavailable)])
    after
        yuzu_gw_test_registry:ensure_fresh()
    end.

%% The session index is a secondary table. If it does not exist (new code
%% loaded into a node whose registry was started before the table was added),
%% registering, deregistering and process exit must still maintain the routing
%% table, and admission must keep failing closed.
missing_session_index_keeps_routing() ->
    Reg = whereis(yuzu_gw_registry),
    X = uid(<<"x">>),
    PX = bind(X, uid(<<"sx">>), conn_a),
    drop_sessions_table(),
    try
        %% register
        Y = uid(<<"y">>),
        SY = uid(<<"sy">>),
        PY = bind(Y, SY, conn_a),
        ?assertEqual(Reg, whereis(yuzu_gw_registry)),
        ?assertEqual({ok, PX}, yuzu_gw_registry:lookup(X)),
        ?assertEqual({ok, PY}, yuzu_gw_registry:lookup(Y)),
        %% admission fails closed and is counted as registry_unavailable
        ?assertEqual({error, unavailable}, yuzu_gw_registry:lookup_session(SY)),
        flush(),
        ?assertEqual(rejected(), beat(conn_a, SY)),
        ?assertEqual(0, queued()),
        assert_events([reject_event(registry_unavailable)]),
        %% re-register the same agent id (supersede path)
        SY2 = uid(<<"sy2">>),
        PY2 = bind(Y, SY2, conn_a),
        ?assertEqual({ok, PY2}, yuzu_gw_registry:lookup(Y)),
        %% fenced and unfenced deregistration
        ok = yuzu_gw_registry:deregister_agent(Y, PY2, SY2),
        sync_registry(),
        ?assertEqual(error, yuzu_gw_registry:lookup(Y)),
        yuzu_gw_registry:deregister_agent(X),
        sync_registry(),
        ?assertEqual(error, yuzu_gw_registry:lookup(X)),
        %% process exit
        Z = uid(<<"z">>),
        PZ = bind(Z, uid(<<"sz">>), conn_a),
        exit(PZ, kill),
        ok = wait_until(fun() -> yuzu_gw_registry:lookup(Z) =:= error end, 2000),
        ?assertEqual(Reg, whereis(yuzu_gw_registry)),
        ?assert(is_process_alive(Reg))
    after
        yuzu_gw_test_registry:ensure_fresh()
    end,
    exit(PX, kill).

%% Only the registry process writes the session index; handler processes
%% (here: this test process) only read it. The pending table is written by
%% handler processes and stays public.
table_protection() ->
    ?assertEqual(protected, ets:info(?SESSIONS, protection)),
    ?assertEqual(public, ets:info(?PENDING, protection)),
    ?assertError(badarg, ets:insert(?SESSIONS, {uid(<<"w">>), <<"a">>, self(), conn_a})),
    ?assertError(badarg, ets:delete(?SESSIONS, uid(<<"w">>))),
    %% Reads from this non-owner process work.
    S = uid(<<"s">>),
    P = bind(uid(<<"a">>), S, conn_a),
    ?assertMatch([{S, _, P, conn_a}], ets:lookup(?SESSIONS, S)),
    ?assertMatch({ok, #{pid := P}}, yuzu_gw_registry:lookup_session(S)),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    exit(P, kill).

lookup_session_contract() ->
    A = uid(<<"a">>),
    S = uid(<<"s">>),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(S)),
    P = bind(A, S, conn_a),
    ?assertEqual({ok, #{agent_id => A, pid => P, conn_key => conn_a}},
                 yuzu_gw_registry:lookup_session(S)),
    %% A row for a pid that has exited is not reported (liveness check),
    %% even before the registry has processed the exit.
    Dead = spawn(fun() -> ok end),
    Ref = monitor(process, Dead),
    receive {'DOWN', Ref, process, Dead, _} -> ok end,
    DeadS = uid(<<"dead">>),
    %% The table is protected: the row is written from inside its owner.
    _ = sys:replace_state(yuzu_gw_registry, fun(State) ->
        true = ets:insert(?SESSIONS, {DeadS, uid(<<"dead-a">>), Dead, conn_a}),
        State
    end),
    ?assertEqual(error, yuzu_gw_registry:lookup_session(DeadS)),
    _ = sys:replace_state(yuzu_gw_registry, fun(State) ->
        true = ets:delete(?SESSIONS, DeadS),
        State
    end),
    exit(P, kill).

register_records_conn_key() ->
    A = uid(<<"reg">>),
    S = <<"reg-session-", A/binary>>,
    Req = #{info => #{agent_id => A, hostname => <<"h">>}},
    {ok, #{session_id := S}, _} = yuzu_gw_agent_service:register(ctx_with(conn_a), Req),
    ?assertEqual({ok, conn_a}, yuzu_gw_registry:lookup_pending_session(S)),
    ?assertMatch({ok, _, _}, beat(conn_a, S)),
    ?assertEqual(rejected(), beat(conn_b, S)).

%%%===================================================================
%%% Logging
%%%===================================================================

rejection_log_is_rate_limited_and_id_free() ->
    yuzu_gw_heartbeat_admission:reset_summary_state(),
    Ids = [uid(<<"rej">>) || _ <- lists:seq(1, 5)],
    Lines = rejection_lines(capture_logs(fun() ->
        lists:foreach(fun(Id) -> beat(conn_a, Id) end, Ids)
    end)),
    %% Five rejections inside one interval produce exactly one summary line.
    ?assertEqual(1, length(Lines)),
    [Line] = Lines,
    lists:foreach(fun(Id) ->
        ?assertEqual(nomatch, binary:match(Line, Id))
    end, Ids),
    ?assertNotEqual(nomatch, binary:match(Line, <<"unknown_session">>)).

%% Many handler processes reject at once. Every rejection is counted exactly
%% once (telemetry events are what drive the Prometheus counters), and the
%% rate limit lets exactly one summary line out inside one interval (the fixture
%% sets the interval to 10 minutes).
rejection_storm_is_counted_and_logs_once() ->
    yuzu_gw_heartbeat_admission:reset_summary_state(),
    N = 500,
    Ctx = ctx_with(conn_a),
    flush(),
    Lines = rejection_lines(capture_logs(fun() ->
        Self = self(),
        Workers = [spawn_link(fun() ->
                       receive go -> ok end,
                       Self ! {admitted, self(),
                               yuzu_gw_heartbeat_admission:admit(Ctx, uid(<<"storm">>))}
                   end) || _ <- lists:seq(1, N)],
        [W ! go || W <- Workers],
        Results = [receive {admitted, W, R} -> R after 10000 -> timeout end
                   || W <- Workers],
        ?assertEqual(lists:duplicate(N, rejected), Results)
    end)),
    Counted = [R || {[yuzu, gw, heartbeat, rejected], #{count := 1}, #{reason := R}}
                        <- events()],
    ?assertEqual(lists:duplicate(N, unknown_session), Counted),
    ?assertEqual(1, length(Lines)),
    ?assertNotEqual(nomatch, binary:match(hd(Lines), <<"unknown_session=">>)).

%% Agents re-register under rotating session ids while heartbeats race. Once a
%% registration call has returned, the session it replaced must not be
%% admitted by any heartbeat, and at quiescence each agent id has exactly one
%% index row: the last session.
registration_churn_keeps_one_row_per_agent() ->
    Agents = 12,
    Rounds = 20,
    Racers = 4,
    Superseded = ets:new(churn_superseded, [public, bag]),
    Violations = ets:new(churn_violations, [public, bag]),
    Ids = [uid(<<"churn">>) || _ <- lists:seq(1, Agents)],
    Keyed = lists:zip(Ids, [{churn_conn, I} || I <- lists:seq(1, Agents)]),
    Self = self(),
    %% Racers: heartbeat for sessions known to be superseded; any admission is
    %% a violation.
    RacerPids = [spawn_link(fun() -> racer(Superseded, Violations) end)
                 || _ <- lists:seq(1, Racers)],
    Workers = [spawn_link(fun() ->
                   Last = churn_agent(Id, Key, Rounds, Superseded, Violations),
                   Self ! {churned, self(), Id, Last}
               end) || {Id, Key} <- Keyed],
    Finals = [receive {churned, W, Id, Last} -> {Id, Last} after 30000 -> timeout end
              || {W, {Id, _}} <- lists:zip(Workers, Keyed)],
    [R ! stop || R <- RacerPids],
    try
        ?assertEqual([], ets:tab2list(Violations)),
        lists:foreach(fun({Id, {Pid, S}}) ->
            %% Exactly one row for this agent id, and it is the last session.
            ?assertMatch([[S, Pid, _]],
                         [[Sid, P, K] || [Sid, P, K] <- ets:match(?SESSIONS, {'$1', Id, '$2', '$3'})]),
            ?assertEqual({ok, {Pid, S}}, yuzu_gw_registry:lookup_local_session(Id))
        end, Finals),
        %% Every superseded session is gone from the index.
        Old = [S || {S} <- ets:tab2list(Superseded)],
        ?assertEqual(Agents * (Rounds - 1), length(Old)),
        lists:foreach(fun(S) ->
            ?assertEqual(error, yuzu_gw_registry:lookup_session(S))
        end, Old)
    after
        [exit(P, kill) || {_, {P, _}} <- Finals],
        ok = wait_until(fun() ->
            lists:all(fun(Id) ->
                ets:match(?SESSIONS, {'_', Id, '_', '_'}) =:= []
            end, Ids)
        end, 3000),
        ets:delete(Superseded),
        ets:delete(Violations)
    end.

%% One agent: register Rounds times under rotating session ids on its own
%% connection. Returns {Pid, SessionId} of the last registration.
churn_agent(Id, Key, Rounds, Superseded, Violations) ->
    Ctx = ctx_with(Key),
    churn_agent(Id, Key, Ctx, 1, Rounds, undefined, Superseded, Violations).

churn_agent(_Id, _Key, _Ctx, N, Rounds, Last, _Superseded, _Violations) when N > Rounds ->
    Last;
churn_agent(Id, Key, Ctx, N, Rounds, Prev, Superseded, Violations) ->
    S = iolist_to_binary([Id, "-s", integer_to_list(N)]),
    Pid = bind(Id, S, Key),
    case Prev of
        {_PrevPid, PrevS} ->
            %% The register call above has returned: the replaced session is
            %% no longer admitted, and racers may now start probing it.
            ets:insert(Superseded, {PrevS}),
            case yuzu_gw_heartbeat_admission:admit(ctx_with(Key), PrevS) of
                ok       -> ets:insert(Violations, {PrevS, Key, worker});
                rejected -> ok
            end;
        undefined ->
            ok
    end,
    %% The new session is admitted on its own connection straight away.
    case yuzu_gw_heartbeat_admission:admit(Ctx, S) of
        ok       -> ok;
        rejected -> ets:insert(Violations, {S, Key, current_rejected})
    end,
    churn_agent(Id, Key, Ctx, N + 1, Rounds, {Pid, S}, Superseded, Violations).

racer(Superseded, Violations) ->
    receive stop -> ok
    after 0 ->
        case ets:tab2list(Superseded) of
            [] ->
                ok;
            Sessions ->
                {S} = lists:nth(rand:uniform(length(Sessions)), Sessions),
                %% Probe on every connection: a superseded session is
                %% admitted on none of them.
                case yuzu_gw_registry:lookup_session(S) of
                    error -> ok;
                    Other -> ets:insert(Violations, {S, Other, racer})
                end
        end,
        erlang:yield(),
        racer(Superseded, Violations)
    end.

info_logs_carry_no_session_id() ->
    A = uid(<<"logagent">>),
    S = <<"reg-session-", A/binary>>,
    Req = #{info => #{agent_id => A, hostname => <<"h">>}},
    Lines = capture_logs(fun() ->
        {ok, _, _} = yuzu_gw_agent_service:register(ctx_with(conn_a), Req),
        Args = #{agent_id => A, session_id => S, stream_pid => self(),
                 agent_info => #{agent_id => A}, peer_addr => <<"127.0.0.1">>,
                 conn_key => conn_a},
        {ok, Agent} = yuzu_gw_agent:start_link(Args),
        unlink(Agent),
        {ok, _} = yuzu_gw_agent:get_info(Agent),
        yuzu_gw_agent:disconnect(Agent),
        ok = wait_until(fun() -> not is_process_alive(Agent) end, 2000)
    end),
    ?assertNotEqual([], [L || L <- Lines, binary:match(L, A) =/= nomatch]),
    lists:foreach(fun(L) ->
        ?assertEqual(nomatch, binary:match(L, S))
    end, Lines).

%% Run Fun with a capturing logger handler at info level; returns the
%% rendered text of every event logged meanwhile.
capture_logs(Fun) ->
    Prev = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, info),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => info}),
    try
        Fun(),
        collect_logs([])
    after
        logger:remove_handler(?LOG_HANDLER),
        logger:set_primary_config(level, Prev)
    end.

%% The capturing handler is VM-wide, so keep only the rejection summary lines:
%% an unrelated info log must not change a count.
rejection_lines(Lines) ->
    [L || L <- Lines,
          binary:match(L, <<"Heartbeat admission rejected">>) =/= nomatch].

collect_logs(Acc) ->
    receive {captured_log, Text} -> collect_logs([Text | Acc])
    after 100 -> lists:reverse(Acc)
    end.

%% logger handler callback
log(#{msg := Msg, meta := _}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S}     -> unicode:characters_to_binary(S);
        {report, R}     -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args}     -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    Pid ! {captured_log, Text},
    ok.

%%%===================================================================
%%% Utilities
%%%===================================================================

%% The session index is owned by the registry process and protected, so a
%% test cannot delete it directly: run the delete inside the owner.
drop_sessions_table() ->
    _ = sys:replace_state(yuzu_gw_registry,
                          fun(State) -> ets:delete(?SESSIONS), State end),
    ok.

%% deregister_agent/1,3 are casts: a synchronous registry call drains them.
sync_registry() ->
    _ = sys:get_state(yuzu_gw_registry),
    ok.

wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of true -> ok; false -> {error, timeout} end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true -> ok;
        false -> timer:sleep(10), wait_until(Pred, Timeout - 10)
    end.
