%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_crash_redact over the processes of the upstream
%%% CLIENT: the gun connection (a gen_statem with no format_status/1) and the
%%% channel that owns it.
%%%
%%% A gun connection holds the request in flight (a ProxyRegister carries the
%%% enrollment token, the certificate and the CSR) in its event queue and the
%%% TLS options, key file paths included, in its state. When it crashes, OTP
%%% prints `Last event', the queue, the postponed events, the state and the log
%%% verbatim, because nothing formats them; only the filter stands between those
%%% bytes and the log. The filter must therefore redact them for a gen_statem
%%% whose callback module is `gun', in addition to the reason it always redacted
%%% for the protected modules.
%%%
%%% Three groups:
%%%   - synthetic gen_statem terminate events through filter/2: the data keys of
%%%     a gun report are redacted and the shape that makes the report readable
%%%     (name, modules) is not; an agent statem event keeps its data (only its
%%%     reason is redacted, as before); an unrelated module's event is untouched;
%%%   - a REAL crash of a gun connection, forced from outside by casting it a
%%%     request that no clause can handle, with the marker in the request and a
%%%     key path in the connection's TLS options, through the installed filter and
%%%     a capturing handler. A control run without the filter must show the
%%%     markers, and the filtered run must capture the crash reports at all, so
%%%     the clean result cannot be an artefact of an empty log;
%%%   - a synthetic proc_lib crash report whose initial call is {gun, init, _}.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_crash_redact_gun_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).  %% logger handler

-define(HANDLER, yuzu_crash_redact_gun_test_log).
-define(M_TOKEN, <<"ENROLLMENT-TOKEN-SECRET">>).
-define(M_KEY,   "/marker/private/gw-leaf-KEY.pem").
-define(M_LOG,   <<"MARKER-log-entry-4d2a">>).
-define(M_POST,  <<"MARKER-postponed-77c1">>).
-define(M_TIME,  <<"MARKER-timeout-b09e">>).

%%%===================================================================
%%% Synthetic gen_statem terminate events
%%%===================================================================

synthetic_test_() ->
    [{"a gun report: queue, postponed, log, timeouts and state are redacted, name and modules stay",
      fun gun_report_is_redacted/0},
     {"a gun report: every key keeps the shape gen_statem:format_log/2 reads and loses its content",
      fun gun_report_replacements/0},
     {"a redacted gun report is still formatted by gen_statem:format_log/2, not printed raw",
      fun gun_report_still_formats/0},
     {"a gun report: the reason is redacted too (as for every protected module)",
      fun gun_reason_is_redacted/0},
     {"gun among other modules is still a gun report",
      fun gun_among_other_modules/0},
     {"a gun report that lacks some data keys still redacts the rest",
      fun gun_report_with_missing_keys/0},
     {"an agent statem report keeps its data; only its reason is redacted",
      fun agent_statem_report_is_not_given_the_extra_redaction/0},
     {"the other protected statem modules are not given it either",
      fun other_protected_modules_keep_their_data/0},
     {"a statem report of an unrelated module is untouched",
      fun unrelated_statem_report_is_untouched/0},
     {"the filter is total on a gun report it cannot parse",
      fun malformed_gun_report_is_withheld_not_leaked/0}].

gun_report_is_redacted() ->
    Out = yuzu_gw_crash_redact:filter(gun_event(), []),
    Text = text(Out),
    [?assertEqual(nomatch, binary:match(Text, M))
     || M <- [?M_TOKEN, list_to_binary(?M_KEY), ?M_LOG, ?M_POST, ?M_TIME]],
    #{msg := {report, R}} = Out,
    ?assertEqual({gen_statem, terminate}, maps:get(label, R)),
    ?assertEqual([gun], maps:get(modules, R)),
    ?assertEqual(gun_conn, maps:get(name, R)),
    ?assertEqual(state_functions, maps:get(callback_mode, R)),
    %% one {EventType, Content} per queued event, which is what format_log/2 reads
    ?assertEqual([{internal, '$redacted'}, {internal, '$redacted'}], maps:get(queue, R)),
    ?assertEqual([{internal, '$redacted'}], maps:get(postponed, R)),
    ?assertEqual([], maps:get(log, R)),
    ?assertEqual({0, []}, maps:get(timeouts, R)),
    ?assertEqual('$redacted', maps:get(state, R)),
    %% what is not request data stays
    ?assertEqual(maps:get(client_info, gun_report()), maps:get(client_info, R)),
    ?assertEqual(false, maps:get(state_enter, R)).

gun_report_replacements() ->
    R0 = (gun_report())#{queue := [], postponed := not_a_list, state := {connected, #{a => 1}},
                         log := [a, b, c], timeouts := undefined, data => ?M_TOKEN},
    #{msg := {report, R}} = yuzu_gw_crash_redact:filter(event(R0), []),
    ?assertEqual([], maps:get(queue, R)),
    %% a value that is not a list is replaced by the empty one, never kept
    ?assertEqual([], maps:get(postponed, R)),
    ?assertEqual('$redacted', maps:get(state, R)),
    ?assertEqual([], maps:get(log, R)),
    ?assertEqual({0, []}, maps:get(timeouts, R)),
    ?assertEqual('$redacted', maps:get(data, R)).

%% gen_statem:format_log/2 expects the queue and the postponed events as lists of
%% {EventType, Content}; a value of another shape makes it raise, and logger then
%% prints the whole raw report map in its place (the markers with it). The
%% redacted report must go through it, and nothing it prints may carry a marker.
gun_report_still_formats() ->
    #{msg := {report, R}} = yuzu_gw_crash_redact:filter(gun_event(), []),
    Text = unicode:characters_to_binary(gen_statem:format_log(R, #{})),
    ?assertNotEqual(nomatch, binary:match(Text, <<"State machine">>)),
    [?assertEqual(nomatch, binary:match(Text, M))
     || M <- [?M_TOKEN, list_to_binary(?M_KEY), ?M_LOG, ?M_POST, ?M_TIME]],
    %% a report that carries values of another shape for those keys formats as well
    #{msg := {report, R1}} =
        yuzu_gw_crash_redact:filter(event((gun_report())#{queue := not_a_list, postponed := {x},
                                                          log := [a, b], timeouts := undefined}), []),
    ?assertNotEqual(nomatch, binary:match(
                               unicode:characters_to_binary(gen_statem:format_log(R1, #{})),
                               <<"State machine">>)).

gun_reason_is_redacted() ->
    #{msg := {report, R}} = yuzu_gw_crash_redact:filter(gun_event(), []),
    Reason = maps:get(reason, R),
    ?assertMatch({error, _, _}, Reason),
    ?assertEqual(nomatch, binary:match(unicode:characters_to_binary(
                                         io_lib:format("~0p", [Reason])), ?M_TOKEN)),
    %% the diagnosis survives: the class and the function that failed
    {error, _, Stack} = Reason,
    ?assertEqual([lists, gun_http2, gun_http2, gun_http2, gun],
                 [M || {M, _, _, _} <- Stack]),
    ?assertEqual({badarg, '$redacted'}, element(2, Reason)).

gun_among_other_modules() ->
    R0 = (gun_report())#{modules := [some_wrapper, gun]},
    #{msg := {report, R}} = yuzu_gw_crash_redact:filter(event(R0), []),
    ?assertEqual([{internal, '$redacted'}, {internal, '$redacted'}], maps:get(queue, R)),
    ?assertEqual('$redacted', maps:get(state, R)),
    ?assertEqual([some_wrapper, gun], maps:get(modules, R)).

gun_report_with_missing_keys() ->
    R0 = maps:without([postponed, log, timeouts], gun_report()),
    #{msg := {report, R}} = yuzu_gw_crash_redact:filter(event(R0), []),
    ?assertEqual([{internal, '$redacted'}, {internal, '$redacted'}], maps:get(queue, R)),
    ?assertEqual('$redacted', maps:get(state, R)),
    ?assertEqual(false, maps:is_key(postponed, R)),
    ?assertEqual(false, maps:is_key(log, R)),
    ?assertEqual(false, maps:is_key(timeouts, R)).

agent_statem_report_is_not_given_the_extra_redaction() ->
    R0 = (gun_report())#{modules := [yuzu_gw_agent], name := <<"agent-1">>},
    Out = yuzu_gw_crash_redact:filter(event(R0), []),
    #{msg := {report, R}} = Out,
    %% the data is exactly what it was
    [?assertEqual(maps:get(K, R0), maps:get(K, R))
     || K <- [queue, postponed, log, timeouts, state, name, modules, callback_mode, client_info]],
    %% the reason is redacted, as before
    ?assertNotEqual(maps:get(reason, R0), maps:get(reason, R)),
    ?assertEqual(nomatch, binary:match(unicode:characters_to_binary(
                                         io_lib:format("~0p", [maps:get(reason, R)])), ?M_TOKEN)).

other_protected_modules_keep_their_data() ->
    [begin
         R0 = (gun_report())#{modules := [Mod]},
         #{msg := {report, R}} = yuzu_gw_crash_redact:filter(event(R0), []),
         [?assertEqual(maps:get(K, R0), maps:get(K, R)) || K <- [queue, postponed, log, state]]
     end || Mod <- [yuzu_gw_upstream, yuzu_gw_registry, yuzu_gw_router,
                    yuzu_gw_heartbeat_buffer, yuzu_grpc_client_channel]].

unrelated_statem_report_is_untouched() ->
    Event = event((gun_report())#{modules := [some_other_statem]}),
    ?assertEqual(Event, yuzu_gw_crash_redact:filter(Event, [])).

%% An event the clauses do not match (no modules list) is not a gun report to the
%% filter and passes as is; one that matches and then fails inside it is
%% withheld, never passed on raw.
malformed_gun_report_is_withheld_not_leaked() ->
    R0 = (gun_report())#{reason := {error, boom, [a | b]}},
    Out = yuzu_gw_crash_redact:filter(event(R0), []),
    ?assertMatch(#{msg := {string, _}}, Out),
    ?assertEqual(nomatch, binary:match(text(Out), ?M_TOKEN)),
    ?assertNotEqual(nomatch, binary:match(text(Out), <<"event content withheld">>)).

%% A gen_statem terminate report as OTP builds it for a gun connection that
%% crashed handling a request: the event is the head of the queue.
gun_report() ->
    Request = {request, self(), make_ref(), <<"POST">>,
               <<"/yuzu.server.v1.GatewayUpstream/ProxyRegister">>, [], ?M_TOKEN, infinity},
    Stack = [{gun_http2, request1, 13,
              [{file, "gun_http2.erl"}, {line, 1125}, {error_info, #{module => erl_stdlib_errors}}]},
             {gun_http2, request, 13, [{file, "gun_http2.erl"}, {line, 1109}]},
             {gun, connected, 3, [{file, "gun.erl"}, {line, 1487}]}],
    #{label => {gen_statem, terminate},
      name => gun_conn,
      queue => [{cast, Request}, {info, {queued, ?M_TOKEN}}],
      postponed => [{cast, {request, ?M_POST}}],
      callback_mode => state_functions,
      state_enter => false,
      state => {connected, {state, [{tls_opts, [{keyfile, ?M_KEY}, {certfile, "/marker/leaf.pem"}]}]}},
      timeouts => [{{timeout, idle}, 5000, ?M_TIME}],
      log => [{in, {cast, {request, ?M_LOG}}}],
      reason => {error, {badarg, ?M_TOKEN}, [{lists, keystore, 4, [{file, "lists.erl"}]},
                                              {gun_http2, request1, [#{body => ?M_TOKEN}, ?M_TOKEN], []}
                                              | Stack]},
      client_info => {self(), {self(), []}},
      process_label => undefined,
      modules => [gun]}.

gun_event() -> event(gun_report()).

event(Report) ->
    #{level => error, meta => #{time => 1}, msg => {report, Report}}.

%%%===================================================================
%%% A synthetic proc_lib crash report of a gun connection
%%%===================================================================

proc_lib_test_() ->
    [{"the crash report of a process whose initial call is {gun, init, _} is protected",
      fun gun_proc_lib_report_is_protected/0},
     {"the crash report of an unrelated process is not",
      fun unrelated_proc_lib_report_is_untouched/0}].

gun_proc_lib_report_is_protected() ->
    ProcInfo = [{pid, self()},
                {registered_name, []},
                {error_info, {error, {badarg, ?M_TOKEN},
                              [{gun_http2, request1, [#{body => ?M_TOKEN}], []}]}},
                {initial_call, {gun, init, ['Argument__1']}},
                {ancestors, [self()]},
                {message_queue_len, 1},
                {messages, [{'$gen_cast', {request, ?M_TOKEN}}]},
                {links, []},
                {dictionary, [{key, ?M_TOKEN}, {tls, [{keyfile, ?M_KEY}]}]},
                {trap_exit, false},
                {status, running}],
    Event = #{level => error, meta => #{},
              msg => {report, #{label => {proc_lib, crash}, report => [ProcInfo, []]}}},
    Out = yuzu_gw_crash_redact:filter(Event, []),
    Text = text(Out),
    [?assertEqual(nomatch, binary:match(Text, M)) || M <- [?M_TOKEN, list_to_binary(?M_KEY)]],
    #{msg := {report, #{report := [Redacted, []]}}} = Out,
    ?assertEqual({redacted, 1}, proplists:get_value(messages, Redacted)),
    ?assertEqual({redacted, 2}, proplists:get_value(dictionary, Redacted)),
    ?assertMatch({error, _, [{gun_http2, request1, _, _}]},
                 proplists:get_value(error_info, Redacted)),
    ?assertEqual({gun, init, ['Argument__1']}, proplists:get_value(initial_call, Redacted)),
    %% a gun connection also named is protected the same way
    Named = lists:keystore(registered_name, 1, ProcInfo, {registered_name, gun_conn}),
    NamedOut = yuzu_gw_crash_redact:filter(
                 Event#{msg := {report, #{label => {proc_lib, crash}, report => [Named, []]}}}, []),
    ?assertEqual(nomatch, binary:match(text(NamedOut), ?M_TOKEN)).

unrelated_proc_lib_report_is_untouched() ->
    ProcInfo = [{pid, self()}, {registered_name, []},
                {error_info, {error, boom, []}},
                {initial_call, {some_other, init, ['Argument__1']}},
                {messages, [{'$gen_cast', ?M_TOKEN}]},
                {dictionary, [{key, ?M_TOKEN}]}],
    Event = #{level => error, meta => #{},
              msg => {report, #{label => {proc_lib, crash}, report => [ProcInfo, []]}}},
    ?assertEqual(Event, yuzu_gw_crash_redact:filter(Event, [])).

%%%===================================================================
%%% A real crash of a gun connection
%%%===================================================================

real_crash_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [{"a gun connection crashing on a request leaks neither the request nor the TLS options",
       {timeout, 60, fun real_crash_is_redacted/0}},
      {"the same crash without the filter does leak them (control)",
       {timeout, 60, fun real_crash_without_filter_leaks_control/0}}]}.

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    ok = yuzu_gw_crash_redact:remove(),
    Level = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, all),
    Level.

cleanup(Level) ->
    catch logger:remove_handler(?HANDLER),
    ok = yuzu_gw_crash_redact:remove(),
    ok = logger:set_primary_config(level, Level),
    flush(),
    ok.

real_crash_is_redacted() ->
    ok = yuzu_gw_crash_redact:install(),
    Events = crash_gun(),
    %% both reports are there, so the assertions below are not vacuous
    ?assertMatch([_], by_label(Events, {gen_statem, terminate})),
    ?assertMatch([_], by_label(Events, {proc_lib, crash})),
    ?assert(length(Events) >= 2),
    Text = iolist_to_binary([[formatted(E), raw(E)] || E <- Events]),
    ?assertEqual(nomatch, binary:match(Text, ?M_TOKEN)),
    ?assertEqual(nomatch, binary:match(Text, <<"gw-leaf-KEY">>)),
    ?assertEqual(nomatch, binary:match(Text, list_to_binary(?M_KEY))),
    %% the diagnosis survives: it was gun that crashed, in the request path
    [Statem] = by_label(Events, {gen_statem, terminate}),
    StatemText = formatted(Statem),
    ?assertNotEqual(nomatch, binary:match(StatemText, <<"gun">>)),
    %% and the report was FORMATTED (gen_statem:format_log/2 took the redacted
    %% queue), not replaced by logger's raw-map fallback for a report it could not
    ?assertNotEqual(nomatch, binary:match(StatemText, <<"State machine">>)),
    ?assertNotEqual(nomatch, binary:match(StatemText, <<"$redacted">>)),
    ?assertEqual(nomatch, binary:match(StatemText, <<"label">>)).

real_crash_without_filter_leaks_control() ->
    ?assertEqual(false, lists:keymember(yuzu_gw_crash_redact, 1,
                                        maps:get(filters, logger:get_primary_config()))),
    Events = crash_gun(),
    ?assertMatch([_], by_label(Events, {gen_statem, terminate})),
    Text = iolist_to_binary([[formatted(E), raw(E)] || E <- Events]),
    %% the request in the queue, and the key path in the connection's state
    ?assertNotEqual(nomatch, binary:match(Text, ?M_TOKEN)),
    ?assertNotEqual(nomatch, binary:match(Text, <<"gw-leaf-KEY">>)).

%% Open a gun connection to a local socket that accepts and says nothing (the
%% connection comes up on prior knowledge), then cast it a request whose headers
%% are not a list: gun_http2 cannot handle it, the gen_statem crashes with the
%% request as its last event and the TLS options in its state. Returns the log
%% events (after the primary filters) of the gen_statem report and the proc_lib
%% crash report.
crash_gun() ->
    process_flag(trap_exit, true),
    {ok, Listen} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}, {active, false}, binary]),
    {ok, Port} = inet:port(Listen),
    Acceptor = spawn(fun() -> hold(Listen) end),
    capture_to_self(),
    try
        {ok, Conn} = gun:open("127.0.0.1", Port,
                              #{protocols => [http2], transport => tcp, retry => 0,
                                supervise => false,
                                tls_opts => [{keyfile, ?M_KEY}, {certfile, "/marker/leaf.pem"},
                                             {verify, verify_peer}]}),
        {ok, http2} = gun:await_up(Conn, 5000),
        Ref = erlang:monitor(process, Conn),
        gen_statem:cast(Conn, {request, self(), make_ref(), <<"POST">>,
                               <<"/yuzu.server.v1.GatewayUpstream/ProxyRegister">>,
                               not_a_header_list, ?M_TOKEN, infinity}),
        receive {'DOWN', Ref, process, Conn, _} -> ok
        after 5000 -> error(gun_did_not_crash)
        end,
        collect([{gen_statem, terminate}, {proc_lib, crash}])
    after
        exit(Acceptor, kill),
        catch gen_tcp:close(Listen),
        drain_exits(),
        process_flag(trap_exit, false),
        catch logger:remove_handler(?HANDLER)
    end.

%% Accept every connection and keep it open, saying nothing.
hold(Listen) ->
    case gen_tcp:accept(Listen) of
        {ok, S} -> _ = hold_loop(S), hold(Listen);
        _       -> ok
    end.

hold_loop(S) ->
    case gen_tcp:recv(S, 0) of
        {ok, _}    -> hold_loop(S);
        {error, _} -> ok
    end.

%%%===================================================================
%%% Helpers
%%%===================================================================

capture_to_self() ->
    catch logger:remove_handler(?HANDLER),
    flush(),
    ok = logger:add_handler(?HANDLER, ?MODULE, #{config => #{pid => self()}, level => all}).

%% logger handler callback: runs in the logging process, after the primary
%% filters, and sends the event to the test.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {captured, Event},
    ok.

collect(Wanted) ->
    collect(Wanted, []).

collect([], Acc) ->
    lists:reverse(Acc);
collect(Wanted, Acc) ->
    receive
        {captured, Event} ->
            L = label(Event),
            case lists:member(L, Wanted) of
                true  -> collect(Wanted -- [L], [Event | Acc]);
                false -> collect(Wanted, Acc)
            end
    after 5000 ->
        error({missing_log_events, Wanted})
    end.

label(#{msg := {report, #{label := L}}}) -> L;
label(_) -> undefined.

by_label(Events, L) -> [E || E <- Events, label(E) =:= L].

flush() ->
    receive {captured, _} -> flush() after 0 -> ok end.

drain_exits() ->
    receive {'EXIT', _, _} -> drain_exits() after 0 -> ok end.

formatted(Event) ->
    unicode:characters_to_binary(logger_formatter:format(Event, #{})).

raw(Event) ->
    unicode:characters_to_binary(io_lib:format("~0p", [Event])).

%% Both renderings of an event.
text(Event) ->
    iolist_to_binary([formatted(Event), raw(Event)]).
