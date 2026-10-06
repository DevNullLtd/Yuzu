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
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_safe_call).

-export([call/4, guard/3]).
-export([init_limits/0, init_limits/1]).
-export([exit_class/1, reset_limits/0]).  %% for testing

-define(WARN_INTERVAL_MS, 1000).
%% The servers a caller here names: the WARN stamp of each is created at
%% application start by init_limits/0.
-define(SERVERS, [yuzu_gw_upstream, yuzu_gw_registry, yuzu_gw_agent_sup, yuzu_gw_router]).

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

%% @doc Create the WARN stamp of every server a caller here names, once, before
%% any of them can fail (yuzu_gw_app calls this ahead of the supervision tree).
%% Creating it on the first failure instead is racy: when the first failures
%% arrive together every caller creates its own stamp and logs its own line.
%% Idempotent: a stamp that exists is reset, not replaced (a persistent_term:put
%% over an existing key costs a global GC).
-spec init_limits() -> ok.
init_limits() ->
    init_limits(?SERVERS).

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
