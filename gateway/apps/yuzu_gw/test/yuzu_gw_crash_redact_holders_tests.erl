%%%-------------------------------------------------------------------
%%% @doc Tests for the crash-report redaction of the two processes that keep a
%%% RegisterRequest besides the upstream client (#1197): yuzu_gw_agent (one per
%%% connected agent, unregistered, holds `register_req' in its data) and
%%% yuzu_gw_registry (is sent it by the `register' call). The upstream's own
%%% scenario is in yuzu_gw_crash_redact_tests.
%%%
%%% Real processes crash, under a real yuzu_gw_agent_sup for the agent, and a
%%% capturing logger handler records every event after the primary filters; each
%%% is rendered with the default formatter and with ~p, and none may contain a
%%% credential marker. Three agent scenarios and one registry scenario:
%%%   - format_status only (no filter): an agent with valid data crashes, so OTP
%%%     prints its state and last event through format_status/1;
%%%   - through the filter: the agent's state is replaced by a term that carries
%%%     the real data, so the stacktrace frames of the failing call print the
%%%     whole record, outside format_status;
%%%   - the same without the filter, as a positive control;
%%%   - the registry crashes on a `register' call with register calls queued in
%%%     its mailbox.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_crash_redact_holders_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2, init/1]).  %% logger handler / supervisor

-define(HANDLER, yuzu_crash_redact_holders_log).
-define(M_TOKEN, <<"MARKER-enrollment-token-5be1">>).
-define(M_CSR,   <<"MARKER-csr-pem-0a77">>).
-define(M_CERT,  <<"MARKER-machine-certificate-d9c3">>).
-define(MARKERS, [?M_TOKEN, ?M_CSR, ?M_CERT]).
-define(WAIT_MS, 5000).

holders_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"agent: format_status keeps register_req out of a crash with valid data",
       fun agent_format_status_redacts_register_req/0},
      {"agent: sys:get_status shows no register_req, sys:get_state still does",
       fun agent_get_status_redacted_get_state_real/0},
      {"agent: a crash that prints the data in a stacktrace is redacted by the filter",
       fun agent_crash_through_filter/0},
      {"agent: the same crash without the filter leaks (control)",
       fun agent_crash_without_filter_leaks_control/0},
      {"registry: a crash with register calls queued is redacted by format_status and the filter",
       fun registry_crash_through_filter/0},
      {"registry: the same crash without the filter leaks (control)",
       fun registry_crash_without_filter_leaks_control/0},
      {"a child named `agent' of another supervisor is not touched",
       fun other_agent_child_unchanged/0}
     ]}.

setup() ->
    catch meck:unload(yuzu_gw_upstream),
    stop_named(yuzu_gw_upstream),
    ok = yuzu_gw_crash_redact:remove(),
    Level = maps:get(level, logger:get_primary_config()),
    logger:set_primary_config(level, notice),
    yuzu_gw_test_registry:ensure_fresh(),
    unlink(whereis(yuzu_gw_registry)),
    {ok, Sup} = supervisor:start_link({local, yuzu_gw_agent_sup_probe}, ?MODULE,
                                      agent_sup),
    unlink(Sup),
    {Level, Sup}.

cleanup({Level, Sup}) ->
    catch logger:remove_handler(?HANDLER),
    ok = yuzu_gw_crash_redact:remove(),
    logger:set_primary_config(level, Level),
    yuzu_gw_test_registry:stop_agent_sup(Sup),
    stop_named(yuzu_gw_registry),
    flush_events(),
    ok.

%%%===================================================================
%%% Agent
%%%===================================================================

%% Valid data, a crash raised by the event itself (maps:get/3 on a non-map).
%% Nothing in the stacktrace names the data, so only the `State:' line and the
%% sys status carry it: format_status/1 is the only thing between them and the
%% log.
agent_format_status_redacts_register_req() ->
    capture_to_self(),
    Pid = start_agent(),
    ok = sys:suspend(Pid),
    gen_statem:cast(Pid, {dispatch, not_a_map, {self(), make_ref()}}),
    ok = sys:resume(Pid),
    Events = collect([{gen_statem, terminate}, {supervisor, child_terminated}]),
    assert_no_markers(Events),
    [Terminate] = by_label(Events, {gen_statem, terminate}),
    Text = formatted(Terminate),
    ?assert(contains(Text, <<"$redacted">>)),
    %% What failed is still shown.
    ?assert(contains(Text, <<"badmap">>)),
    ?assert(contains(Text, <<"a-1">>)).

agent_get_status_redacted_get_state_real() ->
    Pid = start_agent(),
    Status = iolist_to_binary(io_lib:format("~0p", [sys:get_status(Pid)])),
    [?assertNot(contains(Status, M)) || M <- ?MARKERS],
    ?assert(contains(Status, <<"$redacted">>)),
    %% Only the report is redacted: the process still holds the real request.
    {_State, Data} = sys:get_state(Pid),
    ?assert(contains(iolist_to_binary(io_lib:format("~0p", [Data])), ?M_TOKEN)).

agent_crash_through_filter() ->
    ok = yuzu_gw_crash_redact:install(),
    Events = crash_agent_with_data_in_stacktrace(),
    ?assertMatch([_], by_label(Events, {gen_statem, terminate})),
    ?assertMatch([_], by_label(Events, {proc_lib, crash})),
    ?assertMatch([_], by_label(Events, {supervisor, child_terminated})),
    assert_no_markers(Events),
    [Crash] = by_label(Events, {proc_lib, crash}),
    CrashText = formatted(Crash),
    %% The diagnosis survives: what failed, where, and the queued mailbox.
    ?assert(contains(CrashText, <<"do_cleanup">>)),
    ?assert(contains(CrashText, <<"function_clause">>)),
    ?assert(contains(CrashText, <<"{redacted,1}">>)),
    [Sup] = by_label(Events, {supervisor, child_terminated}),
    ?assert(contains(formatted(Sup), <<"function_clause">>)).

agent_crash_without_filter_leaks_control() ->
    ?assertEqual(false, has_filter()),
    Events = crash_agent_with_data_in_stacktrace(),
    Text = events_text(Events),
    [?assert(contains(Text, M)) || M <- ?MARKERS].

%% A crash of the agent whose state is replaced by a term carrying the real
%% data: the failing call's argument list, printed by OTP in the stacktrace of
%% the three reports, then holds the whole record. A second event is queued so
%% the crash report has a mailbox.
crash_agent_with_data_in_stacktrace() ->
    capture_to_self(),
    Pid = start_agent(),
    ok = sys:suspend(Pid),
    Pid ! {first, event},
    gen_statem:cast(Pid, {dispatch, x, y}),
    _ = sys:replace_state(Pid, fun({S, D}) -> {S, {garbage, D}} end),
    ok = sys:resume(Pid),
    collect([{gen_statem, terminate}, {proc_lib, crash}, {supervisor, child_terminated}]).

%%%===================================================================
%%% Registry
%%%===================================================================

registry_crash_through_filter() ->
    ok = yuzu_gw_crash_redact:install(),
    Events = crash_registry(),
    ?assertMatch([_], by_label(Events, {gen_server, terminate})),
    ?assertMatch([_], by_label(Events, {proc_lib, crash})),
    assert_no_markers(Events),
    [Crash] = by_label(Events, {proc_lib, crash}),
    ?assert(contains(formatted(Crash), <<"{redacted,2}">>)),
    [Terminate] = by_label(Events, {gen_server, terminate}),
    TermText = formatted(Terminate),
    %% The failing request is still identified: its tag and the agent.
    ?assert(contains(TermText, <<"register">>)),
    ?assert(contains(TermText, <<"badarg">>)).

registry_crash_without_filter_leaks_control() ->
    ?assertEqual(false, has_filter()),
    Events = crash_registry(),
    Text = events_text(Events),
    %% The mailbox (the credentials of the two queued calls) and the stacktrace.
    ?assert(contains(Text, ?M_TOKEN) orelse contains(Text, ?M_CSR)),
    %% format_status already covered the last message: the control must not
    %% claim otherwise, or it would hide a regression in that callback.
    Terminate = hd(by_label(Events, {gen_server, terminate})),
    ?assertNot(contains(events_text([Terminate]), ?M_CERT)).

%% The registry is suspended, three `register' calls are queued (the first one
%% names a pid that is not one, which crashes the handler), then it runs. Only
%% the first carries the certificate marker, so a leak of the last message and
%% of the mailbox can be told apart.
crash_registry() ->
    capture_to_self(),
    Pid = whereis(yuzu_gw_registry),
    ok = sys:suspend(Pid),
    Reqs = [{not_a_pid, #{machine_certificate => ?M_CERT}},
            {self(), #{enrollment_token => ?M_TOKEN}},
            {self(), #{csr_pem => ?M_CSR}}],
    lists:foldl(
      fun({AgentPid, Req}, N) ->
          spawn(fun() ->
              yuzu_gw_registry:register_agent(<<"agent-", (integer_to_binary(N))/binary>>,
                                              AgentPid, <<"s">>, [], <<"h">>, Req, undefined)
          end),
          wait_queue_len(Pid, N),
          N + 1
      end, 1, Reqs),
    ok = sys:resume(Pid),
    collect([{gen_server, terminate}, {proc_lib, crash}]).

%%%===================================================================
%%% Other supervisors
%%%===================================================================

%% The offender id `agent' is a common word: only the module in the start spec
%% makes it ours.
other_agent_child_unchanged() ->
    Reason = {boom, [{some_other_module, f, [<<"SECRET-ARG">>], []}]},
    Event = #{level => error, meta => #{},
              msg => {report, #{label => {supervisor, child_terminated},
                                report => [{supervisor, {local, other_sup}},
                                           {errorContext, child_terminated},
                                           {reason, Reason},
                                           {offender, [{pid, self()}, {id, agent},
                                                       {mfargs, {some_other_module,
                                                                 start_link, undefined}}]}]}}},
    ?assertEqual(Event, yuzu_gw_crash_redact:filter(Event, [])),
    %% And with our module in the spec, the same report is redacted.
    Ours = Event#{msg := {report, #{label => {supervisor, child_terminated},
                                    report => [{supervisor, {local, yuzu_gw_agent_sup}},
                                               {errorContext, child_terminated},
                                               {reason, Reason},
                                               {offender, [{pid, self()}, {id, agent},
                                                           {mfargs, {yuzu_gw_agent,
                                                                     start_link,
                                                                     undefined}}]}]}}},
    ?assertNot(contains(events_text([yuzu_gw_crash_redact:filter(Ours, [])]),
                        <<"SECRET-ARG">>)).

%%%===================================================================
%%% supervisor callback (a simple_one_for_one that starts real agents)
%%%===================================================================

init(agent_sup) ->
    {ok, {#{strategy => simple_one_for_one, intensity => 0, period => 1},
          [#{id => agent, start => {yuzu_gw_agent, start_link, []}, restart => temporary,
             shutdown => 5000, type => worker}]}}.

%%%===================================================================
%%% Helpers
%%%===================================================================

req() ->
    #{enrollment_token => ?M_TOKEN, machine_certificate => ?M_CERT, csr_pem => ?M_CSR}.

%% A real agent in `streaming', child of the probe supervisor (the same child
%% spec as yuzu_gw_agent_sup's), holding the three markers in register_req.
start_agent() ->
    Args = #{agent_id => <<"a-1">>, agent_info => #{hostname => <<"h">>},
             stream_pid => self(), peer_addr => <<"peer">>, session_id => <<"s-1">>,
             register_req => req()},
    {ok, Pid} = supervisor:start_child(yuzu_gw_agent_sup_probe, [Args]),
    Pid.

capture_to_self() ->
    catch logger:remove_handler(?HANDLER),
    flush_events(),
    ok = logger:add_handler(?HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => all}).

%% logger handler callback: runs in the logging process, after the primary
%% filters.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {captured, Event},
    ok.

%% Receive events until one of each wanted label has arrived, keeping only
%% those; fails the test on a timeout.
collect(Labels) ->
    collect(Labels, []).

collect([], Acc) ->
    lists:reverse(Acc);
collect(Wanted, Acc) ->
    receive
        {captured, Event} ->
            case lists:member(label(Event), Wanted) of
                true  -> collect(Wanted -- [label(Event)], [Event | Acc]);
                false -> collect(Wanted, Acc)
            end
    after ?WAIT_MS ->
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

events_text(Events) ->
    iolist_to_binary([[formatted(E), raw(E)] || E <- Events]).

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
        Pid ->
            catch unlink(Pid),
            Ref = monitor(process, Pid),
            catch unregister(Name),
            exit(Pid, kill),
            receive {'DOWN', Ref, process, Pid, _} -> ok
            after 3000 -> demonitor(Ref, [flush]), ok
            end
    end.
