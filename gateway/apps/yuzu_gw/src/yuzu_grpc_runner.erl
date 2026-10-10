%%%-------------------------------------------------------------------
%%% @doc The process one RPC runs in: calls the service function and turns
%%% whatever it does into one terminal status for yuzu_grpc_stream_h.
%%%
%%% The handler contract, one convention for every service:
%%%
%%%   kind           call                         accepted results
%%%   unary          Mod:F(Ctx, Request)          {ok, Resp} | {ok, Resp, Ctx}
%%%                                               | {grpc_error, {Status, Msg}}
%%%   server_stream  Mod:F(Request, Stream)       ok | {grpc_error, {Status, Msg}}
%%%   bidi,          Mod:F(Ref, Stream)           ok | {grpc_error, {Status, Msg}}
%%%   client_stream  (inbound {Ref, Map} and {Ref, eos} messages)
%%%
%%% A streaming handler sends with yuzu_grpc_stream:send/2. Any handler may
%%% throw({grpc_error, {Status, Msg}}) (yuzu_grpc_stream:error/2 does). Any other
%%% result, throw, error or exit ends the call with INTERNAL.
%%%
%%% The process is not trapping exits and is stopped from outside when its
%%% stream ends (a reset, a deadline, a closed connection): `exit(Pid, shutdown)'
%%% takes effect at once, wherever the handler is blocked, and a `try ... after'
%%% in a service function does not run. A service that holds something outside
%%% this process for the length of a call hands its release to a process that
%%% watches the handler (see yuzu_gw_agent_service:register/2).
%%%
%%% Logging rule: a crash is logged as the method, the exception CLASS and the
%%% top stack frame's M:F/Arity, never the reason, the stacktrace arguments, the
%%% request or the ctx. A reason such as the exit of a gen_server:call embeds the
%%% whole call (see yuzu_gw_safe_call), and a request here can carry enrollment
%%% credentials.
%%%
%%% Rate: one failing call is one line, so an outage that fails every request
%%% would write one per request. At most one line is written per second per node
%%% (application env grpc_runner_warn_interval_ms of yuzu_gw, default 1000, 0 for
%%% every failure; a value that is not a non-negative integer reads as the
%%% default and one above an hour as an hour, so a typo cannot silence the log);
%%% a line that follows suppressed ones says how many. The count of failed calls
%%% is kept by the status each of them answers with, not by the log. This module
%%% keeps its own limit and depends on nothing else of the gateway: the
%%% application creates the limit's state at start (init_throttle/0), and a
%%% failure that finds none makes it without taking a lock.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_runner).

-include("yuzu_grpc.hrl").

-export([run/1]).
-export([top_frame/1]).
-export([init_throttle/0]).
-export([warn_throttled/4, reset_throttle/0, warn_interval/0]).  %% for testing

-export_type([args/0]).

-define(DEFAULT_WARN_INTERVAL_MS, 1000).
-define(MAX_WARN_INTERVAL_MS, 3600000).
-define(THROTTLE_KEY, {?MODULE, warn_throttle}).
%% "No line written yet": far enough before any clock reading, whatever its origin.
-define(NEVER, -(1 bsl 62)).

-type args() :: #{kind := yuzu_grpc_route:kind(),
                  module := module(),
                  function := atom(),
                  stream := yuzu_grpc_stream:stream(),
                  request => map(),
                  ref => reference()}.

%% @doc The body of the handler process. Ends by telling the stream handler how
%% the call finished; the process then exits normally.
-spec run(args()) -> ok.
run(#{stream := #yuzu_grpc_stream{conn = Conn, stream_id = StreamId}} = Args) ->
    {Status, Message} = execute(Args),
    Conn ! {{Conn, StreamId}, {grpc_end, self(), Status, Message}},
    ok.

%% @doc "Module:Function/Arity" of the top frame of a stacktrace, from which
%% nothing about the arguments can be read: when the frame carries the argument
%% list (an undef or function_clause) only its length is used.
-spec top_frame(term()) -> string().
top_frame([{Module, Function, Args, _} | _]) when is_atom(Module), is_atom(Function) ->
    Arity = case Args of
        N when is_integer(N) -> N;
        L when is_list(L) -> length(L);
        _ -> 0
    end,
    lists:flatten(io_lib:format("~s:~s/~b", [Module, Function, Arity]));
top_frame(_) ->
    "unknown".

%%--------------------------------------------------------------------

-spec execute(args()) -> {yuzu_grpc_frame:status(), binary()}.
execute(#{stream := Stream} = Args) ->
    try
        call(Args)
    catch
        throw:{grpc_error, {Status, Message}} ->
            error_status(Status, Message);
        exit:normal ->
            {?GRPC_STATUS_OK, <<>>};
        Class:_:Stack ->
            log_failure(Stream, Class, top_frame(Stack)),
            internal()
    end.

call(#{kind := unary, module := Module, function := Function, stream := Stream,
       request := Request}) ->
    case Module:Function(yuzu_grpc_stream:ctx(Stream), Request) of
        {ok, Response} -> reply(Stream, Response);
        {ok, Response, _Ctx} -> reply(Stream, Response);
        {grpc_error, {Status, Message}} -> error_status(Status, Message);
        _ -> bad_return(Stream)
    end;
call(#{kind := server_stream, module := Module, function := Function, stream := Stream,
       request := Request}) ->
    result(Stream, Module:Function(Request, Stream));
call(#{kind := Kind, module := Module, function := Function, stream := Stream,
       ref := Ref}) when Kind =:= bidi; Kind =:= client_stream ->
    result(Stream, Module:Function(Ref, Stream)).

reply(Stream, Response) ->
    _ = yuzu_grpc_stream:send(Stream, Response),
    {?GRPC_STATUS_OK, <<>>}.

result(_Stream, ok) ->
    {?GRPC_STATUS_OK, <<>>};
result(_Stream, {grpc_error, {Status, Message}}) ->
    error_status(Status, Message);
result(Stream, _) ->
    bad_return(Stream).

bad_return(Stream) ->
    log_failure(Stream, bad_return, "unknown"),
    internal().

error_status(Status, Message) ->
    {yuzu_grpc_frame:normalize_status(Status), yuzu_grpc_frame:normalize_message(Message)}.

internal() ->
    {?GRPC_STATUS_INTERNAL, <<"internal error">>}.

log_failure(#yuzu_grpc_stream{method = Method}, Class, Frame) ->
    warn_throttled(erlang:monotonic_time(millisecond), Method, Class, Frame).

%% @doc The failure line, unless one was written less than the interval before
%% Now (milliseconds, any monotonic origin). Of callers racing at the same
%% moment exactly one writes: the others count themselves as suppressed.
-spec warn_throttled(integer(), binary(), term(), string()) -> ok.
warn_throttled(Now, Method, Class, Frame) ->
    case warn_interval() of
        0 -> warn(Method, Class, Frame, 0);
        Interval -> warn_limited(Now, Interval, Method, Class, Frame)
    end,
    ok.

warn_limited(Now, Interval, Method, Class, Frame) ->
    Throttle = throttle(),
    Last = atomics:get(Throttle, 1),
    case Now - Last >= Interval of
        true ->
            case atomics:compare_exchange(Throttle, 1, Last, Now) of
                ok ->
                    warn(Method, Class, Frame, atomics:exchange(Throttle, 2, 0));
                _Raced ->
                    atomics:add(Throttle, 2, 1)
            end;
        false ->
            atomics:add(Throttle, 2, 1)
    end.

warn(Method, Class, Frame, 0) ->
    logger:warning("gateway grpc handler ~s failed: class=~p at ~s", [Method, Class, Frame]);
warn(Method, Class, Frame, Suppressed) ->
    logger:warning("gateway grpc handler ~s failed: class=~p at ~s "
                   "(~b similar failures not logged since the last line)",
                   [Method, Class, Frame, Suppressed]).

%% @doc The interval between lines, in milliseconds, as configured.
-spec warn_interval() -> non_neg_integer().
warn_interval() ->
    case application:get_env(yuzu_gw, grpc_runner_warn_interval_ms, ?DEFAULT_WARN_INTERVAL_MS) of
        Ms when is_integer(Ms), Ms >= 0 -> min(Ms, ?MAX_WARN_INTERVAL_MS);
        _ -> ?DEFAULT_WARN_INTERVAL_MS
    end.

%% The limit's state: slot 1 the time of the last line, slot 2 the failures since
%% it that were not written. Made by init_throttle/0 at application start, before
%% the first request; a failure that finds none (this layer on its own, or a call
%% ahead of the start) makes it here. Two failures that make it together each
%% write a first line, and one of the two arrays is then unused: harmless, and
%% the cost of taking no lock on a path that runs during an outage.
throttle() ->
    case persistent_term:get(?THROTTLE_KEY, undefined) of
        undefined -> new_throttle();
        Throttle -> Throttle
    end.

new_throttle() ->
    Throttle = atomics:new(2, [{signed, true}]),
    atomics:put(Throttle, 1, ?NEVER),
    persistent_term:put(?THROTTLE_KEY, Throttle),
    Throttle.

%% @doc Create the limit's state if it does not exist, and forget the last line
%% and the suppressed count if it does (a persistent_term:put over an existing
%% key costs a global GC, so an existing array is reset, not replaced). Called by
%% the application before it serves a request.
-spec init_throttle() -> ok.
init_throttle() ->
    reset_throttle().

%% @doc Forget the last line and the suppressed count, so the next failure is
%% written.
-spec reset_throttle() -> ok.
reset_throttle() ->
    Throttle = throttle(),
    atomics:put(Throttle, 1, ?NEVER),
    atomics:put(Throttle, 2, 0).
