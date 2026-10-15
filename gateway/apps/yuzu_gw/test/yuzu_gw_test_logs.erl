%%%-------------------------------------------------------------------
%%% @doc Shared EUnit helper: capture the log lines a test provokes.
%%%
%%% `with_handler/2' installs a logger handler that sends the rendered text of
%%% every event to the calling process, runs a fun, and always removes the
%%% handler and puts the primary level back. The handler runs in the logging
%%% process and sends before the logging call returns, so a body that has waited
%%% for the processes that log has nothing pending when it calls `collect/0'.
%%% A body that cannot know that waits for its line with its own bounded
%%% `receive' on `{captured_log, Text}'.
%%%
%%% Not a test module: it exports no `*_test' function, so eunit finds nothing
%%% to run in it (same as `yuzu_gw_test_registry').
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_test_logs).

-export([with_handler/2, capture/2, collect/0, flush/0]).
-export([log/2]).  %% logger handler callback

-define(HANDLER, yuzu_gw_test_logs_handler).

%% @doc Run Fun with the capturing handler at Level (the primary level is raised
%% to Level too) and return Fun's result. Captured lines are left in the
%% caller's mailbox as `{captured_log, Text}' for the body to collect or await.
-spec with_handler(logger:level(), fun(() -> Result)) -> Result.
with_handler(Level, Fun) ->
    Prev = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, Level),
    catch logger:remove_handler(?HANDLER),
    try
        %% Inside the try: a handler that cannot be added must still put the
        %% primary level back.
        ok = logger:add_handler(?HANDLER, ?MODULE,
                                #{config => #{pid => self()}, level => Level}),
        flush(),
        Fun()
    after
        logger:remove_handler(?HANDLER),
        logger:set_primary_config(level, Prev)
    end.

%% @doc Run Fun with the handler at Level and return the rendered text of every
%% event logged meanwhile, oldest first.
-spec capture(logger:level(), fun(() -> term())) -> [binary()].
capture(Level, Fun) ->
    with_handler(Level, fun() -> Fun(), collect() end).

%% @doc The lines captured so far, oldest first; the mailbox is drained.
-spec collect() -> [binary()].
collect() ->
    collect([]).

collect(Acc) ->
    receive {captured_log, Text} -> collect([Text | Acc])
    after 0 -> lists:reverse(Acc)
    end.

%% @doc Drop every captured line not yet read.
-spec flush() -> ok.
flush() ->
    receive {captured_log, _} -> flush() after 0 -> ok end.

%% logger handler callback
log(#{msg := Msg, meta := _}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S} -> unicode:characters_to_binary(S);
        {report, R} -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args} -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    Pid ! {captured_log, Text},
    ok.
