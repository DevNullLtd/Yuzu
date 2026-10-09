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
%%% Logging rule: a crash is logged as the method, the exception CLASS and the
%%% top stack frame's M:F/Arity, never the reason, the stacktrace arguments, the
%%% request or the ctx. A reason such as the exit of a gen_server:call embeds the
%%% whole call (see yuzu_gw_safe_call), and a request here can carry enrollment
%%% credentials.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_runner).

-include("yuzu_grpc.hrl").

-export([run/1]).
-export([top_frame/1]).

-export_type([args/0]).

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
    logger:warning("gateway grpc handler ~s failed: class=~p at ~s",
                   [Method, Class, Frame], #{domain => [yuzu_gw, grpc]}).
