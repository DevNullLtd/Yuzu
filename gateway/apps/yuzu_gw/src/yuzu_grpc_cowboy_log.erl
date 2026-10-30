%%%-------------------------------------------------------------------
%%% @doc The `logger' module of the gRPC listeners' Cowboy connections
%%% (cowboy:log/4 calls Module:Level(Format, Args), in the connection process).
%%%
%%% Every line is written as Cowboy writes it by default (error_logger, with
%%% Cowboy's own level mapping), except two that arrive once per STREAM:
%%%
%%%   "Received message ~p for unknown stream ~p."
%%%       a message for a stream that has already ended: a handler's frame or
%%%       status, or the stream's deadline timer, that lost a race with a reset
%%%   "Received EXIT signal ~p for unknown process ~p."
%%%       the exit of a handler whose stream has already gone
%%%
%%% When a client resets many streams at once (a mass cancel) each of them can
%%% produce one, and so can many connections at once: every agent whose Register
%%% timed out (a registration storm against a slow server) ends its own stream
%%% on its own connection, and the handler's late status then arrives for a
%%% stream that has gone, about 15,000 lines at 25,000 agents when the limit was
%%% kept per connection. So each kind is written at most once per ?INTERVAL_MS
%%% per NODE, the next line saying how many were not written; and the message
%%% or exit reason is reduced to its tag, because Cowboy would print the whole
%%% term: a handler's frame there is a response body (an agent's command
%%% output), and an exit reason can embed a request.
%%%
%%% The limit's state is an atomics array per kind, found through
%%% persistent_term and made on first use (no lock, no process: a line racing
%%% another may make a second array, which is harmless, as in
%%% yuzu_grpc_runner). Of callers racing at the same moment exactly one writes.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_cowboy_log).

%% Cowboy calls Module:error/2 like any other level.
-compile({no_auto_import, [error/2]}).

-export([emergency/2, alert/2, critical/2, error/2, warning/2, notice/2, info/2,
         debug/2]).
-export([tag/1]).
-export([reset/0]).  %% for testing

-define(INTERVAL_MS, 1000).
%% "No line written yet": far enough before any clock reading, whatever its origin.
-define(NEVER, -(1 bsl 62)).
-define(UNKNOWN_STREAM, "Received message ~p for unknown stream ~p.").
-define(UNKNOWN_EXIT, "Received EXIT signal ~p for unknown process ~p.~n").

emergency(Format, Args) -> log(emergency, Format, Args).
alert(Format, Args) -> log(alert, Format, Args).
critical(Format, Args) -> log(critical, Format, Args).
error(Format, Args) -> log(error, Format, Args).
warning(Format, Args) -> log(warning, Format, Args).
notice(Format, Args) -> log(notice, Format, Args).
info(Format, Args) -> log(info, Format, Args).
debug(Format, Args) -> log(debug, Format, Args).

log(warning, ?UNKNOWN_STREAM, [Msg, StreamId]) ->
    limited(unknown_stream,
            "gateway grpc: a ~s message arrived for stream ~p, which had already ended; dropped",
            [tag(Msg), StreamId]);
log(warning, ?UNKNOWN_EXIT, [Reason, _Pid]) ->
    limited(unknown_exit,
            "gateway grpc: a process whose stream had already ended exited (~s)",
            [tag(Reason)]);
log(Level, Format, Args) ->
    cowboy_default(Level, Format, Args).

%% @doc The first atom of a term (a tagged tuple's tag, the tag of a message
%% inside Cowboy's {{Pid, StreamId}, Msg} envelope), and nothing of its content.
-spec tag(term()) -> string().
tag(Atom) when is_atom(Atom) -> atom_to_list(Atom);
tag({{Pid, _StreamId}, Msg}) when is_pid(Pid) -> tag(Msg);
tag(Tuple) when is_tuple(Tuple), tuple_size(Tuple) > 0, is_atom(element(1, Tuple)) ->
    atom_to_list(element(1, Tuple));
tag(_) -> "other".

%% One line per interval per node; the next written line counts the rest.
limited(Kind, Format, Args) ->
    Limit = limit(Kind),
    Now = erlang:monotonic_time(millisecond),
    Last = atomics:get(Limit, 1),
    case Now - Last >= ?INTERVAL_MS andalso
         atomics:compare_exchange(Limit, 1, Last, Now) =:= ok of
        true ->
            case atomics:exchange(Limit, 2, 0) of
                0 -> error_logger:warning_msg(Format ++ "~n", Args);
                Suppressed ->
                    error_logger:warning_msg(Format ++ " (~b similar line(s) not logged "
                                             "since the last)~n", Args ++ [Suppressed])
            end;
        false ->
            atomics:add(Limit, 2, 1)
    end,
    ok.

%% The limit of one kind: slot 1 the time of the last line, slot 2 the lines
%% since it that were not written.
limit(Kind) ->
    case persistent_term:get({?MODULE, Kind}, undefined) of
        undefined ->
            Limit = atomics:new(2, [{signed, true}]),
            atomics:put(Limit, 1, ?NEVER),
            persistent_term:put({?MODULE, Kind}, Limit),
            Limit;
        Limit ->
            Limit
    end.

%% @doc Forget the last line and the count of each kind, so the next line of
%% each is written.
-spec reset() -> ok.
reset() ->
    [begin
         Limit = limit(Kind),
         atomics:put(Limit, 1, ?NEVER),
         atomics:put(Limit, 2, 0)
     end || Kind <- [unknown_stream, unknown_exit]],
    ok.

%% What cowboy:log/4 does when no logger module is set.
cowboy_default(Level, Format, Args) ->
    Function = case Level of
        emergency -> error_msg;
        alert -> error_msg;
        critical -> error_msg;
        error -> error_msg;
        warning -> warning_msg;
        notice -> warning_msg;
        info -> info_msg;
        debug -> info_msg
    end,
    error_logger:Function(Format, Args).
