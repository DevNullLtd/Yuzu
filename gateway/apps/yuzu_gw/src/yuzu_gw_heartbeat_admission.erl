%%%-------------------------------------------------------------------
%%% @doc Admission decision for agent Heartbeat calls.
%%%
%%% A heartbeat is admitted only for a session this node holds, and only
%%% when it arrives on the HTTP/2 connection the session is bound to:
%%%   - an established session is bound to the connection of the Subscribe
%%%     stream that created it;
%%%   - a session that has registered but not yet subscribed is bound to
%%%     the connection that performed the Register.
%%% Anything else is rejected. The decision reads node-local state only
%%% (`yuzu_gw_registry:lookup_session/1' and `lookup_pending_session/1',
%%% never `pg'); it does not depend on the upstream server's view of the
%%% session. A missing registry table fails closed.
%%%
%%% Every rejection is counted (`yuzu_gw_heartbeat_rejected_total{reason}',
%%% or `yuzu_gw_heartbeat_session_mismatch_total{event="security"}' for a
%%% held session arriving on a different connection) and folded into a
%%% rate-limited summary log line. There is no per-heartbeat log and no
%%% log line ever carries a session id.
%%%
%%% The caller answers every rejection with the same NOT_FOUND
%%% "unknown session" regardless of reason.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_admission).

-export([admit/2, check/2]).
-export([init_summary_state/0, reset_summary_state/0]).
-export_type([reason/0]).

-type reason() :: unknown_session | no_connection | registry_unavailable
                | connection_mismatch.

%% Order is the slot order of the summary counters.
-define(REASONS, [unknown_session, no_connection, registry_unavailable,
                  connection_mismatch]).
-define(LAST_SLOT, 5).  %% slot after the per-reason counters: last summary time
-define(STATE_KEY, {?MODULE, summary_state}).
-define(DEFAULT_SUMMARY_INTERVAL_MS, 10000).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Decide, count and (rate-limited) log. `ok' means admit the
%% heartbeat; `rejected' means answer NOT_FOUND and do not queue it.
-spec admit(ctx:t(), term()) -> ok | rejected.
admit(Ctx, SessionId) ->
    case check(Ctx, SessionId) of
        ok ->
            ok;
        {reject, Reason} ->
            note_rejection(Reason),
            rejected
    end.

%% @doc The pure decision: no counting, no logging.
-spec check(ctx:t(), term()) -> ok | {reject, reason()}.
check(_Ctx, SessionId) when not is_binary(SessionId); SessionId =:= <<>> ->
    {reject, unknown_session};
check(Ctx, SessionId) ->
    Key = yuzu_gw_conn:key_from_ctx(Ctx),
    case yuzu_gw_registry:lookup_session(SessionId) of
        {ok, #{conn_key := Bound}} ->
            compare(Key, Bound);
        {error, unavailable} ->
            {reject, registry_unavailable};
        error ->
            case yuzu_gw_registry:lookup_pending_session(SessionId) of
                {ok, Bound} ->
                    compare(Key, Bound);
                {error, unavailable} ->
                    {reject, registry_unavailable};
                error ->
                    {reject, unknown_session}
            end
    end.

%% @doc Create the summary-log state. Called once at boot, before the
%% supervision tree serves heartbeats (the agent listener belongs to the
%% grpcbox dependency application, which can start first; the lazy path
%% covers that window): creating it lazily on the first rejection is racy
%% when the first rejections arrive together (each concurrent first caller
%% would create its own state and log its own line).
-spec init_summary_state() -> ok.
init_summary_state() ->
    _ = new_summary_state(),
    ok.

%% @doc Replace the summary-log state with a fresh one (tests).
-spec reset_summary_state() -> ok.
reset_summary_state() ->
    init_summary_state().

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

%% A session or a call without a key can never match, even against another
%% call without one.
compare(undefined, _Bound) -> {reject, no_connection};
compare(_Key, undefined)   -> {reject, no_connection};
compare(Key, Key)          -> ok;
compare(_Key, _Bound)      -> {reject, connection_mismatch}.

note_rejection(connection_mismatch) ->
    telemetry:execute([yuzu, gw, heartbeat, session_mismatch], #{count => 1}, #{}),
    summarize(connection_mismatch);
note_rejection(Reason) ->
    telemetry:execute([yuzu, gw, heartbeat, rejected], #{count => 1},
                      #{reason => Reason}),
    summarize(Reason).

%% Count the rejection and, at most once per interval, log one line with the
%% counts accumulated since the previous line. Only the process that wins the
%% compare_exchange on the last-summary slot emits, so concurrent rejections
%% produce one line, and a line is only ever produced by a rejection, so it is
%% never empty. The line carries reason names and counts, nothing else.
summarize(Reason) ->
    Ref = summary_state(),
    atomics:add(Ref, slot(Reason), 1),
    Now = erlang:monotonic_time(millisecond),
    Last = atomics:get(Ref, ?LAST_SLOT),
    case Now - Last >= summary_interval_ms() of
        true ->
            case atomics:compare_exchange(Ref, ?LAST_SLOT, Last, Now) of
                ok -> emit_summary(Ref);
                _  -> ok
            end;
        false ->
            ok
    end.

emit_summary(Ref) ->
    Counts = [{R, atomics:exchange(Ref, slot(R), 0)} || R <- ?REASONS],
    case [io_lib:format("~s=~b", [R, N]) || {R, N} <- Counts, N > 0] of
        [] ->
            ok;
        Parts ->
            logger:info("Heartbeat admission rejected heartbeats since the last "
                        "summary: ~s", [lists:join(", ", Parts)])
    end.

slot(Reason) ->
    slot(Reason, ?REASONS, 1).

slot(Reason, [Reason | _], N) -> N;
slot(Reason, [_ | Rest], N)   -> slot(Reason, Rest, N + 1).

%% Normally created at boot by init_summary_state/0. The lazy path only
%% covers a caller that runs before that (unit tests): a concurrent first call
%% may create the state more than once, which only affects the log lines.
summary_state() ->
    case persistent_term:get(?STATE_KEY, undefined) of
        undefined -> new_summary_state();
        Ref       -> Ref
    end.

new_summary_state() ->
    Ref = atomics:new(?LAST_SLOT, [{signed, true}]),
    %% First rejection logs immediately.
    atomics:put(Ref, ?LAST_SLOT,
                erlang:monotonic_time(millisecond) - summary_interval_ms()),
    persistent_term:put(?STATE_KEY, Ref),
    Ref.

summary_interval_ms() ->
    application:get_env(yuzu_gw, telemetry_gauge_interval_ms,
                        ?DEFAULT_SUMMARY_INTERVAL_MS).
