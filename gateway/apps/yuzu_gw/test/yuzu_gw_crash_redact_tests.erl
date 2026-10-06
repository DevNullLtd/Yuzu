%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_crash_redact (#1197): the logger primary filter
%%% that keeps registration credentials out of the crash reports of
%%% yuzu_gw_upstream.
%%%
%%% The scenario is a real one. The real upstream runs under a supervisor and
%%% is suspended; three proxy_register calls, each carrying one credential
%%% marker, are queued in its mailbox behind a fourth that makes it crash (its
%%% state is replaced by a term no clause matches, and the state itself carries
%%% a marker that lands in the stacktrace frame arguments). That crash does NOT
%%% go through format_status/1 for the mailbox, the exception line, the
%%% gen_server stacktrace or the supervisor reason, which is what the filter
%%% exists for. A capturing logger handler records every event after the
%%% primary filters ran; each is rendered with the default formatter and with
%%% ~p, and none may contain a marker.
%%%
%%% A positive control runs the same scenario without the filter and requires
%%% the markers to appear, so the clean result cannot be an artefact of the
%%% harness. Events of other processes must pass through unchanged.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_crash_redact_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2, init/1, start_other/0]).  %% logger handler / supervisor / child

-define(HANDLER, yuzu_crash_redact_test_log).
-define(SUP, yuzu_crash_redact_test_sup).

%% The credentials that sit in the upstream's mailbox, and the marker carried
%% by its (garbage) state, which ends up in the stacktrace of the exception.
-define(M_TOKEN,  <<"MARKER-enrollment-token-7f3a">>).
-define(M_CSR,    <<"MARKER-csr-pem-91bc">>).
-define(M_CERT,   <<"MARKER-machine-certificate-c04d">>).
-define(M_STATE,  <<"MARKER-state-arg-2e8e">>).
-define(M_LAST,   <<"MARKER-last-message-55aa">>).
-define(MARKERS,  [?M_TOKEN, ?M_CSR, ?M_CERT, ?M_STATE, ?M_LAST]).

redact_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"a crash of the upstream leaks none of its credentials through the filter",
       fun crash_is_redacted_through_the_installed_filter/0},
      {"the same crash without the filter does leak them (control)",
       fun crash_without_filter_leaks_control/0},
      {"the filter applied to raw reports redacts all three kinds, nothing else",
       fun filter_rewrites_only_upstream_reports/0},
      {"reports of other processes pass through unchanged",
       fun other_process_reports_are_unchanged/0},
      {"a filter failure keeps the event and withholds its content",
       fun filter_failure_withholds_content/0},
      {"install is idempotent and remove is tolerant",
       fun install_and_remove_are_idempotent/0}
     ]}.

setup() ->
    stop_upstream(),
    ok = yuzu_gw_crash_redact:remove(),
    logger:set_primary_config(level, notice),
    ok.

cleanup(_) ->
    catch logger:remove_handler(?HANDLER),
    ok = yuzu_gw_crash_redact:remove(),
    stop_upstream(),
    case whereis(?SUP) of
        undefined -> ok;
        Sup -> catch unlink(Sup), catch exit(Sup, kill)
    end,
    flush_events(),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

crash_is_redacted_through_the_installed_filter() ->
    ok = yuzu_gw_crash_redact:install(),
    Events = crash_upstream(),
    %% The three reports are all there, so the assertions below are not vacuous.
    ?assertMatch([_], by_label(Events, {proc_lib, crash})),
    ?assertMatch([_], by_label(Events, {gen_server, terminate})),
    ?assertMatch([_], by_label(Events, {supervisor, child_terminated})),
    assert_no_markers(Events),
    [Crash] = by_label(Events, {proc_lib, crash}),
    CrashText = formatted(Crash),
    %% The diagnosis survives: what failed, where, and how much was queued.
    ?assert(contains(CrashText, <<"check_circuit">>)),
    ?assert(contains(CrashText, <<"function_clause">>)),
    ?assert(contains(CrashText, <<"{redacted,3}">>)).

crash_without_filter_leaks_control() ->
    ?assertEqual(false, has_filter()),
    Events = crash_upstream(),
    Text = iolist_to_binary([[formatted(E), raw(E)] || E <- Events]),
    %% The mailbox (all three credentials) and the state in the stack frames.
    [?assert(contains(Text, M)) || M <- [?M_TOKEN, ?M_CSR, ?M_CERT, ?M_STATE]],
    %% format_status already covered the last message; the control must not
    %% claim otherwise, or it would hide a regression in that callback.
    ?assertNot(contains(Text, ?M_LAST)).

filter_rewrites_only_upstream_reports() ->
    Raw = crash_upstream(),
    Out = [yuzu_gw_crash_redact:filter(E, []) || E <- Raw],
    assert_no_markers(Out),
    %% Every upstream report changed.
    [?assertNotEqual(In, After) || {In, After} <- lists:zip(Raw, Out)],
    %% The reason of the supervisor report keeps its atoms and frame arities.
    [Sup] = by_label(Out, {supervisor, child_terminated}),
    SupText = formatted(Sup),
    ?assert(contains(SupText, <<"check_circuit">>)),
    %% A sibling child of the same supervisor, an unrelated crash, and plain
    %% events are not touched.
    Others = crash_other(),
    [?assertEqual(E, yuzu_gw_crash_redact:filter(E, [])) || E <- Others],
    Plain = #{level => error, meta => #{}, msg => {report, #{label => {x, y}, n => 1}}},
    ?assertEqual(Plain, yuzu_gw_crash_redact:filter(Plain, [])),
    PlainStr = #{level => info, meta => #{}, msg => {string, "hello"}},
    ?assertEqual(PlainStr, yuzu_gw_crash_redact:filter(PlainStr, [])).

other_process_reports_are_unchanged() ->
    ok = yuzu_gw_crash_redact:install(),
    Events = crash_other(),
    ?assertMatch([_], by_label(Events, {proc_lib, crash})),
    ?assertMatch([_], by_label(Events, {supervisor, child_terminated})),
    Text = iolist_to_binary([[formatted(E), raw(E)] || E <- Events]),
    %% Neither the mailbox nor the reason of another process is touched.
    ?assert(contains(Text, <<"OTHER-MAILBOX-MARKER">>)),
    ?assert(contains(Text, <<"OTHER-REASON-MARKER">>)),
    ?assertNot(contains(Text, <<"{redacted,">>)).

%% An exception inside the filter (here an improper stacktrace list) must not
%% pass the raw event on and must not lose the line: the message is replaced by
%% a fixed text, the report callbacks are dropped from the metadata, and the
%% event still formats.
filter_failure_withholds_content() ->
    Secret = <<"MARKER-in-failing-event-3b1d">>,
    ProcInfo = [{registered_name, yuzu_gw_upstream},
                {messages, [{secret, Secret}]},
                {error_info, {error, boom, [a | b]}}],
    Event = #{level => error,
              meta => #{report_cb => fun proc_lib:report_cb/2,
                        error_logger => #{tag => error_report,
                                          report_cb => fun gen_server:format_log/1},
                        time => 1},
              msg => {report, #{label => {proc_lib, crash}, report => [ProcInfo, []]}}},
    Out = yuzu_gw_crash_redact:filter(Event, []),
    ?assertMatch(#{level := error, msg := {string, _}}, Out),
    #{meta := Meta} = Out,
    ?assertEqual(false, maps:is_key(report_cb, Meta)),
    ?assertEqual(false, maps:is_key(error_logger, Meta)),
    ?assertEqual(1, maps:get(time, Meta)),
    ?assertNot(contains(raw(Out), Secret)),
    Text = formatted(Out),
    ?assertNot(contains(Text, Secret)),
    ?assert(contains(Text, <<"event content withheld">>)),
    %% Not an event at all: returned as is.
    ?assertEqual(garbage, yuzu_gw_crash_redact:filter(garbage, [])).

install_and_remove_are_idempotent() ->
    ?assertEqual(false, has_filter()),
    ?assertEqual(ok, yuzu_gw_crash_redact:remove()),
    ?assertEqual(ok, yuzu_gw_crash_redact:install()),
    ?assertEqual(ok, yuzu_gw_crash_redact:install()),
    ?assertEqual(1, length([F || {yuzu_gw_crash_redact, _} = F <- filters()])),
    ?assertEqual(ok, yuzu_gw_crash_redact:remove()),
    ?assertEqual(ok, yuzu_gw_crash_redact:remove()),
    ?assertEqual(false, has_filter()).

%%%===================================================================
%%% Scenarios
%%%===================================================================

%% Crash the real upstream with three credentials in its mailbox and return the
%% events that reached the capturing handler (the proc_lib crash report, the
%% gen_server terminate report and the supervisor child_terminated report).
crash_upstream() ->
    capture_to_self(),
    {ok, Sup} = supervisor:start_link({local, ?SUP}, ?MODULE, []),
    unlink(Sup),
    {ok, Pid} = supervisor:start_child(?SUP, #{id => yuzu_gw_upstream,
                                               start => {yuzu_gw_upstream, start_link, []},
                                               restart => temporary}),
    ok = sys:suspend(Pid),
    %% The first caller is the one the crash happens on; the other three stay
    %% queued. Each is queued before the next is sent, so the order is fixed.
    Reqs = [#{enrollment_token => ?M_LAST},
            #{enrollment_token => ?M_TOKEN},
            #{csr_pem => ?M_CSR},
            #{machine_certificate => ?M_CERT}],
    lists:foldl(fun(Req, N) ->
                    spawn(fun() -> catch yuzu_gw_upstream:proxy_register(Req) end),
                    wait_queue_len(Pid, N),
                    N + 1
                end, 1, Reqs),
    _ = sys:replace_state(Pid, fun(_) -> {garbage, ?M_STATE} end),
    ok = sys:resume(Pid),
    collect([{proc_lib, crash}, {gen_server, terminate}, {supervisor, child_terminated}]).

%% An unrelated child of the same kind of supervisor crashes with a mailbox
%% and a reason carrying markers; returns its events (crash report and
%% supervisor report).
crash_other() ->
    capture_to_self(),
    {ok, Sup} = supervisor:start_link(?MODULE, []),
    unlink(Sup),
    {ok, Child} = supervisor:start_child(Sup, #{id => other_child,
                                                start => {?MODULE, start_other, []},
                                                restart => temporary}),
    Child ! {mailbox, <<"OTHER-MAILBOX-MARKER">>},
    Child ! die,
    Events = collect([{proc_lib, crash}, {supervisor, child_terminated}]),
    catch exit(Sup, kill),
    Events.

%% supervisor callback
init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 0, period => 1}, []}}.

%% child start function: a proc_lib process that exits with a marker reason
start_other() ->
    {ok, proc_lib:spawn_link(fun() ->
        receive die -> exit({bad, <<"OTHER-REASON-MARKER">>}) end
    end)}.

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Send every logged event (after the primary filters) to the calling process.
%% The fixture's setup runs in another process than the test, so this is done
%% from the scenario itself.
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

%% Receive events until one of each wanted label has arrived (the supervisor's
%% comes last), keeping only those; fails the test on a timeout.
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

%% The event as the default formatter shows it.
formatted(Event) ->
    unicode:characters_to_binary(logger_formatter:format(Event, #{})).

%% The event term itself.
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

filters() ->
    maps:get(filters, logger:get_primary_config()).

has_filter() ->
    lists:keymember(yuzu_gw_crash_redact, 1, filters()).

wait_queue_len(Pid, N) ->
    case process_info(Pid, message_queue_len) of
        {message_queue_len, L} when L >= N -> ok;
        _ -> erlang:yield(), wait_queue_len(Pid, N)
    end.

stop_upstream() ->
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Pid -> catch unlink(Pid), catch exit(Pid, kill),
               wait_down(Pid)
    end.

wait_down(Pid) ->
    case is_process_alive(Pid) of
        true  -> erlang:yield(), wait_down(Pid);
        false -> ok
    end.
