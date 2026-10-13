%%%-------------------------------------------------------------------
%%% @doc gen_server:call/3 for requests that carry registration credentials.
%%%
%%% A call that exits (the server is not running, is stalled past the timeout,
%%% or died while serving it) exits the CALLER with a reason that embeds the
%%% whole call: {Why, {gen_server, call, [Server, Request, Timeout]}}. The
%%% caller here is a grpcbox handler process, and grpcbox logs the exception of
%%% a handler that crashes (grpcbox_stream, INFO `exception=~p'). The crash
%%% report filter (yuzu_gw_crash_redact) never sees that line, so a
%%% RegisterRequest in the call (enrollment_token, machine_certificate,
%%% csr_pem) would reach the default log.
%%%
%%% call/4 (and guard/3, for a supervisor:start_child) turns every such exit into `{error, Error}' (Error is a fixed atom
%%% chosen by the caller) and logs one WARN naming only the class of the exit:
%%%   noproc  - the server is not running
%%%   timeout - the server did not answer in time
%%%   other   - anything else (the server died while serving the call, ...)
%%% Neither the exit reason nor the request is ever logged or returned. The WARN
%%% is limited to one per second per server (the limit state is created once, at
%%% application start, by init_limits/0), so an outage that fails every
%%% registering agent does not flood the log; the callers log their own
%%% per-request line with the fixed atom.
%%%
%%% warn_limited/3 is the same limit for a warning of a named kind that a
%%% registration can provoke once per request (a refused agent id, a replaced
%%% peer address, a failed upstream call): at most one line per second per kind,
%%% and the line that follows a quiet interval carries the number of lines that
%%% were suppressed since the previous one. The first occurrence always logs.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_safe_call).

-export([call/4, guard/3, warn_limited/3]).
-export([init_limits/0, init_limits/1]).
-export([exit_class/1, reset_limits/0, expire_limit/1, hold_limit/1]).  %% for testing

-define(WARN_INTERVAL_MS, 1000).
%% The servers a caller here names: the WARN stamp of each is created at
%% application start by init_limits/0.
-define(SERVERS, [yuzu_gw_upstream, yuzu_gw_registry, yuzu_gw_agent_sup, yuzu_gw_router]).
%% The warning kinds warn_limited/3 limits: one stamp each, created at
%% application start too. Each is a line a registration can make
%% the gateway write once per request.
-define(KINDS, [register_refused, register_peer_addr, register_failed, inventory_failed,
                rpc_raised, rpc_answered_error]).

%% @doc gen_server:call(Server, Request, Timeout), with an exit turned into
%% {error, Error}. A reply is returned as is.
-spec call(atom(), term(), timeout(), atom()) -> term() | {error, atom()}.
call(Server, Request, Timeout, Error) ->
    guard(Server, fun() -> gen_server:call(Server, Request, Timeout) end, Error).

%% @doc Fun(), with an exit turned into {error, Error}, for a call that is not
%% a gen_server:call (a supervisor:start_child with the register request in its
%% arguments). Server is only the name the WARN uses. Only an exit is caught: an
%% error or a throw is not the shape of a dead or stalled server, and its
%% stacktrace is not ours to hide.
-spec guard(atom(), fun(() -> term()), atom()) -> term() | {error, atom()}.
guard(Server, Fun, Error) ->
    try
        Fun()
    catch
        exit:Reason ->
            warn_limited(Server, exit_class(Reason)),
            {error, Error}
    end.

%% @doc The class of a gen_server:call exit reason; only its shape is read.
-spec exit_class(term()) -> noproc | timeout | other.
exit_class({noproc, _}) -> noproc;
exit_class({timeout, _}) -> timeout;
exit_class(_)            -> other.

%% @doc logger:warning(Format, Args), at most once per second for the Kind. A call
%% inside the interval is counted, not logged; the next line that is logged says
%% how many were counted since the previous one. A Kind without a stamp (a caller
%% before init_limits/0 ran) gets one on its first use: that costs at most an
%% extra line when the first uses race, never a missed first line.
-spec warn_limited(atom(), string(), [term()]) -> ok.
warn_limited(Kind, Format, Args) ->
    Ref = kind_stamp(Kind),
    Now = erlang:monotonic_time(millisecond),
    Last = atomics:get(Ref, 1),
    case Now - Last >= ?WARN_INTERVAL_MS
         andalso atomics:compare_exchange(Ref, 1, Last, Now) =:= ok of
        true ->
            case atomics:exchange(Ref, 2, 0) of
                0 ->
                    logger:warning(Format, Args);
                Suppressed ->
                    logger:warning(Format ++ " (~b similar line(s) suppressed since the last)",
                                   Args ++ [Suppressed])
            end;
        false ->
            atomics:add(Ref, 2, 1)
    end,
    ok.

%% @doc Make the next warn_limited/3 of the Kind log (a test's way of letting the
%% interval pass without waiting for it). The count of suppressed lines is kept.
-spec expire_limit(atom()) -> ok.
expire_limit(Kind) ->
    atomics:put(kind_stamp(Kind), 1, never_warned()).

%% @doc Keep the Kind quiet for an hour (a test's way of making sure the interval
%% cannot pass in the middle of a burst). expire_limit/1 or reset_limits/0 lifts it.
-spec hold_limit(atom()) -> ok.
hold_limit(Kind) ->
    atomics:put(kind_stamp(Kind), 1, erlang:monotonic_time(millisecond) + 3600000).

%% @doc Create the WARN stamp of every server a caller here names, once, before
%% any of them can fail (yuzu_gw_app calls this ahead of the supervision tree).
%% Creating it on the first failure instead is racy: when the first failures
%% arrive together every caller creates its own stamp and logs its own line.
%% Idempotent: a stamp that exists is reset, not replaced (a persistent_term:put
%% over an existing key costs a global GC).
-spec init_limits() -> ok.
init_limits() ->
    init_limits(?SERVERS),
    lists:foreach(fun init_kind_stamp/1, ?KINDS).

%% @doc init_limits/0 for the named servers (a test's own fake).
-spec init_limits([atom()]) -> ok.
init_limits(Servers) ->
    lists:foreach(fun init_stamp/1, Servers).

%% @doc Forget the WARN stamps and create the default ones afresh, so the next
%% failure of each default server logs.
-spec reset_limits() -> ok.
reset_limits() ->
    lists:foreach(fun({?MODULE, _} = Key) -> persistent_term:erase(Key);
                     (_)                  -> ok
                  end, [K || {K, _} <- persistent_term:get()]),
    init_limits().

%%%===================================================================
%%% Internal
%%%===================================================================

%% At most one WARN per ?WARN_INTERVAL_MS per server. The stamp lives in an
%% atomics array kept in persistent_term, created once by init_limits/0. A
%% server with no stamp (a caller that runs before the application start, or
%% names a server init_limits/0 does not) logs nothing and creates nothing: the
%% callers log their own per-request line, and creating a stamp here is the race
%% init_limits/0 exists to remove.
warn_limited(Server, Class) ->
    case persistent_term:get({?MODULE, Server}, undefined) of
        undefined ->
            ok;
        Ref ->
            Now = erlang:monotonic_time(millisecond),
            Last = atomics:get(Ref, 1),
            case Now - Last >= ?WARN_INTERVAL_MS
                 andalso atomics:compare_exchange(Ref, 1, Last, Now) =:= ok of
                true ->
                    logger:warning("Call to ~s failed (~s); the request is not logged",
                                   [Server, Class]);
                false ->
                    ok
            end
    end.

%% The stamp of a warning kind: slot 1 is the time of the last logged line, slot
%% 2 the number of lines counted since it.
kind_stamp(Kind) ->
    case persistent_term:get({?MODULE, {kind, Kind}}, undefined) of
        undefined -> init_kind_stamp(Kind);
        Ref       -> Ref
    end.

init_kind_stamp(Kind) ->
    Key = {?MODULE, {kind, Kind}},
    case persistent_term:get(Key, undefined) of
        undefined ->
            Ref = atomics:new(2, [{signed, true}]),
            atomics:put(Ref, 1, never_warned()),
            persistent_term:put(Key, Ref),
            Ref;
        Ref ->
            atomics:put(Ref, 1, never_warned()),
            atomics:put(Ref, 2, 0),
            Ref
    end.

init_stamp(Server) ->
    Key = {?MODULE, Server},
    case persistent_term:get(Key, undefined) of
        undefined ->
            Ref = atomics:new(1, [{signed, true}]),
            atomics:put(Ref, 1, never_warned()),
            persistent_term:put(Key, Ref);
        Ref ->
            atomics:put(Ref, 1, never_warned())
    end.

%% A stamp old enough that the first failure logs.
never_warned() ->
    erlang:monotonic_time(millisecond) - 2 * ?WARN_INTERVAL_MS.
