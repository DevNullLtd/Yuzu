%%%-------------------------------------------------------------------
%%% @doc Tests for the crash-report redaction of yuzu_gw_router (#1197): its
%%% mailbox holds SendCommand requests, whose plugin parameters can be secrets.
%%% (The registration holders are in yuzu_gw_crash_redact_holders_tests and the
%%% upstream in yuzu_gw_crash_redact_tests.)
%%%
%%% The real router runs under a real supervisor and is suspended; calls that
%%% carry a marker in their command parameters are queued in its mailbox behind
%%% one that makes it crash (a command that is not a map, which raises inside
%%% the router with the request in the stacktrace arguments). A capturing logger
%%% handler records every event after the primary filters ran; each is rendered
%%% with the default formatter and with ~p, and none may contain a marker.
%%%
%%% A positive control runs the same scenario without the filter and requires
%%% the markers to appear, so the clean result cannot be an artefact of the
%%% harness.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_crash_redact_fanout_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2, init/1]).  %% logger handler / supervisor

-define(HANDLER, yuzu_crash_redact_fanout_log).
-define(SUP, yuzu_crash_redact_fanout_sup).
-define(M_QUEUED, <<"MARKER-queued-command-param-6d21">>).
-define(M_QUEUED2, <<"MARKER-queued-command-param-b7e4">>).
-define(M_LAST, <<"MARKER-failing-command-param-c9a0">>).
-define(MARKERS, [?M_QUEUED, ?M_QUEUED2, ?M_LAST]).

redact_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"router: a crash with commands queued leaks no command parameter through the filter",
       fun router_crash_is_redacted_through_the_installed_filter/0},
      {"router: the same crash without the filter leaks them (control)",
       fun router_crash_without_filter_leaks_control/0},
      {"router: sys:get_status shows counts only, sys:get_state still the real record",
       fun router_get_status_redacted/0}
     ]}.

setup() ->
    stop_named(yuzu_gw_router),
    ok = yuzu_gw_crash_redact:remove(),
    Level = maps:get(level, logger:get_primary_config()),
    logger:set_primary_config(level, notice),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    Agent = spawn(fun() -> receive stop -> ok end end),
    ok = yuzu_gw_registry:register_agent(<<"redact-a-1">>, Agent, <<"s">>, [<<"svc">>], <<>>),
    {Level, Agent}.

cleanup({Level, Agent}) ->
    catch logger:remove_handler(?HANDLER),
    ok = yuzu_gw_crash_redact:remove(),
    logger:set_primary_config(level, Level),
    Agent ! stop,
    stop_named(yuzu_gw_router),
    case whereis(?SUP) of
        undefined -> ok;
        Sup -> catch unlink(Sup), catch exit(Sup, kill)
    end,
    stop_named(yuzu_gw_registry),
    flush_events(),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

router_crash_is_redacted_through_the_installed_filter() ->
    ok = yuzu_gw_crash_redact:install(),
    Events = crash_router(),
    ?assertMatch([_], by_label(Events, {proc_lib, crash})),
    ?assertMatch([_], by_label(Events, {gen_server, terminate})),
    ?assertMatch([_], by_label(Events, {supervisor, child_terminated})),
    assert_no_markers(Events),
    [Crash] = by_label(Events, {proc_lib, crash}),
    CrashText = formatted(Crash),
    %% The diagnosis survives: what failed, and how much was queued.
    ?assert(contains(CrashText, <<"badmap">>)),
    ?assert(contains(CrashText, <<"{redacted,2}">>)).

router_crash_without_filter_leaks_control() ->
    ?assertEqual(false, has_filter()),
    Events = crash_router(),
    Text = iolist_to_binary([[formatted(E), raw(E)] || E <- Events]),
    %% The mailbox (both queued commands) and the failing command in the frames.
    [?assert(contains(Text, M)) || M <- ?MARKERS].

router_get_status_redacted() ->
    {ok, Pid} = start_router(),
    {ok, _} = yuzu_gw_router:send_command([<<"redact-a-1">>],
        #{plugin => <<"p">>, parameters => #{<<"pw">> => ?M_LAST}}, #{}),
    Status = iolist_to_binary(io_lib:format("~0p", [sys:get_status(Pid)])),
    [?assertNot(contains(Status, M)) || M <- ?MARKERS],
    ?assert(contains(Status, <<"fanouts">>)),
    %% Only the report is redacted: the process still holds the real record.
    ?assertMatch({state, #{}}, sys:get_state(Pid)),
    ?assertEqual(1, map_size(element(2, sys:get_state(Pid)))).

%%%===================================================================
%%% Scenario
%%%===================================================================

%% Crash the real router with two commands queued behind a failing one; return
%% the proc_lib crash report, the gen_server terminate report and the supervisor
%% child_terminated report.
crash_router() ->
    capture_to_self(),
    {ok, Pid} = start_router(),
    ok = sys:suspend(Pid),
    Cmd = fun(M) -> #{plugin => <<"p">>, parameters => #{<<"pw">> => M}} end,
    %% The first caller is the one the crash happens on (its command is not a
    %% map, so maps:get/3 raises with it in the frame arguments); the others
    %% stay queued. Each is queued before the next is sent.
    Calls = [?M_LAST, Cmd(?M_QUEUED), Cmd(?M_QUEUED2)],
    lists:foldl(fun(C, N) ->
                    spawn(fun() ->
                        catch yuzu_gw_router:send_command([<<"redact-a-1">>], C, #{})
                    end),
                    wait_queue_len(Pid, N),
                    N + 1
                end, 1, Calls),
    ok = sys:resume(Pid),
    collect([{proc_lib, crash}, {gen_server, terminate}, {supervisor, child_terminated}]).

start_router() ->
    {ok, Sup} = supervisor:start_link({local, ?SUP}, ?MODULE, []),
    unlink(Sup),
    supervisor:start_child(?SUP, #{id => yuzu_gw_router,
                                   start => {yuzu_gw_router, start_link, []},
                                   restart => temporary}).

%% supervisor callback
init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 0, period => 1}, []}}.

%%%===================================================================
%%% Helpers
%%%===================================================================

capture_to_self() ->
    catch logger:remove_handler(?HANDLER),
    flush_events(),
    ok = logger:add_handler(?HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => all}).

%% logger handler callback: runs in the logging process, after the primary
%% filters, and sends the event to the test.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {captured, Event},
    ok.

collect(Labels) ->
    collect(Labels, []).

collect([], Acc) ->
    lists:reverse(Acc);
collect(Wanted, Acc) ->
    receive
        {captured, Event} ->
            case label(Event) of
                L when L =/= undefined ->
                    case lists:member(L, Wanted) of
                        true  -> collect(Wanted -- [L], [Event | Acc]);
                        false -> collect(Wanted, Acc)
                    end;
                _ -> collect(Wanted, Acc)
            end
    after 5000 ->
        error({missing_log_events, Wanted})
    end.

label(#{msg := {report, #{label := L}}}) -> L;
label(_) -> undefined.

by_label(Events, L) -> [E || E <- Events, label(E) =:= L].

flush_events() ->
    receive {captured, _} -> flush_events() after 0 -> ok end.

formatted(Event) ->
    unicode:characters_to_binary(logger_formatter:format(Event, #{})).

raw(Event) ->
    unicode:characters_to_binary(io_lib:format("~0p", [Event])).

assert_no_markers(Events) ->
    lists:foreach(
      fun(E) ->
          Text = iolist_to_binary([formatted(E), raw(E)]),
          lists:foreach(
            fun(M) ->
                case contains(Text, M) of
                    true  -> error({marker_leaked, M, label(E)});
                    false -> ok
                end
            end, ?MARKERS)
      end, Events).

contains(Bin, Needle) -> binary:match(Bin, Needle) =/= nomatch.

has_filter() ->
    lists:keymember(yuzu_gw_crash_redact, 1, maps:get(filters, logger:get_primary_config())).

wait_queue_len(Pid, N) ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, L} when L >= N -> ok;
        _ -> erlang:yield(), wait_queue_len(Pid, N)
    end.

stop_named(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid -> catch unlink(Pid), catch exit(Pid, kill), wait_down(Pid)
    end.

wait_down(Pid) ->
    case is_process_alive(Pid) of
        true  -> erlang:yield(), wait_down(Pid);
        false -> ok
    end.
