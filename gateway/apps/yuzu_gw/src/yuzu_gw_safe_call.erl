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
%%% call/4 turns every such exit into `{error, Error}' (Error is a fixed atom
%%% chosen by the caller) and logs one WARN naming only the class of the exit:
%%%   noproc  - the server is not running
%%%   timeout - the server did not answer in time
%%%   other   - anything else (the server died while serving the call, ...)
%%% Neither the exit reason nor the request is ever logged or returned. The WARN
%%% is limited to one per second per server, so an outage that fails every
%%% registering agent does not flood the log; the callers log their own
%%% per-request line with the fixed atom.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_safe_call).

-export([call/4]).
-export([exit_class/1, reset_limits/0]).  %% for testing

-define(WARN_INTERVAL_MS, 1000).

%% @doc gen_server:call(Server, Request, Timeout), with an exit turned into
%% {error, Error}. A reply is returned as is.
-spec call(atom(), term(), timeout(), atom()) -> term() | {error, atom()}.
call(Server, Request, Timeout, Error) ->
    try
        gen_server:call(Server, Request, Timeout)
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

%% @doc Forget the WARN stamps, so the next failure of every server logs.
-spec reset_limits() -> ok.
reset_limits() ->
    lists:foreach(fun({?MODULE, _} = Key) -> persistent_term:erase(Key);
                     (_)                  -> ok
                  end, [K || {K, _} <- persistent_term:get()]),
    ok.

%%%===================================================================
%%% Internal
%%%===================================================================

%% At most one WARN per ?WARN_INTERVAL_MS per server. The stamp lives in an
%% atomics array kept in persistent_term (created on the first failure of that
%% server, so the global-GC cost of persistent_term:put/2 is paid once); two
%% callers racing the first creation each hold a valid array, the later put
%% wins, and at worst one extra line is logged.
warn_limited(Server, Class) ->
    Now = erlang:monotonic_time(millisecond),
    Ref = stamp_ref(Server, Now),
    Last = atomics:get(Ref, 1),
    case Now - Last >= ?WARN_INTERVAL_MS
         andalso atomics:compare_exchange(Ref, 1, Last, Now) =:= ok of
        true ->
            logger:warning("Call to ~s failed (~s); the request is not logged",
                           [Server, Class]);
        false ->
            ok
    end.

stamp_ref(Server, Now) ->
    Key = {?MODULE, Server},
    case persistent_term:get(Key, undefined) of
        undefined ->
            Ref = atomics:new(1, [{signed, true}]),
            atomics:put(Ref, 1, Now - 2 * ?WARN_INTERVAL_MS),
            persistent_term:put(Key, Ref),
            Ref;
        Ref ->
            Ref
    end.
