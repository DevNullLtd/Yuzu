%%%-------------------------------------------------------------------
%%% @doc EUnit tests for yuzu_gw_telemetry's event -> Prometheus wiring.
%%%
%%% HA WS-4 4.4 round-2 review (Gate 3 finding NEW-1, Gate 6 findings
%%% COMP-1/COMP-2/NEW-2): the original F2 fix (yuzu_gw_upstream emitting
%%% `[yuzu, gw, upstream, notify_dropped]`) was asserted "Fixed" but the
%%% event was never added to yuzu_gw_telemetry's ?EVENTS list, handle_event/4
%%% clauses, or declare_metrics/0 -- so telemetry:execute/3 on that event
%%% name was a pure no-op (an unattached event name), and the drop stayed
%%% exactly as invisible as before the "fix". Every OTHER producer module's
%%% own tests mock the `telemetry` module entirely (meck `execute` ->
%%% `ok`), which verifies the EMISSION call happened but can NEVER catch a
%%% CONSUMPTION-side wiring gap like this one -- this file exists
%%% specifically to close that blind spot, mirroring
%%% yuzu_gw_authz_tests.erl's own `telemetry_counter_test_` precedent: fire
%%% the REAL event through the REAL attached handler (no meck on
%%% `telemetry` at all) and assert the Prometheus counter actually moves.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_telemetry_tests).
-include_lib("eunit/include/eunit.hrl").

notify_dropped_test_() ->
    {setup,
     fun() ->
        {ok, Started} = application:ensure_all_started(prometheus),
        {ok, Started2} = application:ensure_all_started(telemetry),
        %% A prior test module's own yuzu_gw_telemetry:setup() call (or a
        %% leaked yuzu_gw_app boot) may have already attached this handler
        %% id -- detach first so re-attaching here is not a silent no-op
        %% under {error, already_exists} (mirrors the authz precedent).
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup(),
        Started ++ Started2
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"circuit_open drop reaches the real Prometheus counter",
       fun() ->
           Before = counter_val(yuzu_gw_upstream_notify_dropped_total,
                                 [<<"circuit_open">>]),
           telemetry:execute([yuzu, gw, upstream, notify_dropped],
                             #{count => 1}, #{reason => <<"circuit_open">>}),
           ?assertEqual(Before + 1,
                        counter_val(yuzu_gw_upstream_notify_dropped_total,
                                    [<<"circuit_open">>]))
       end},
      {"at_capacity drop reaches the real Prometheus counter, labeled "
       "distinctly from circuit_open",
       fun() ->
           Before = counter_val(yuzu_gw_upstream_notify_dropped_total,
                                 [<<"at_capacity">>]),
           telemetry:execute([yuzu, gw, upstream, notify_dropped],
                             #{count => 1}, #{reason => <<"at_capacity">>}),
           ?assertEqual(Before + 1,
                        counter_val(yuzu_gw_upstream_notify_dropped_total,
                                    [<<"at_capacity">>]))
       end}
     ]}.

counter_val(Name, Labels) ->
    case prometheus_counter:value(Name, Labels) of
        undefined -> 0;
        V -> V
    end.

%% #5177: every scrape of :9568/metrics returned HTTP 500 from 0.14.0-rc1 to
%% rc3. Five HELP strings in declare_metrics/0 held an em-dash; in a UTF-8
%% source a non-ASCII literal becomes an integer > 255 in the charlist, and
%% prometheus_text_format's iolist_to_binary/1 raised badarg on it, which
%% prometheus_httpd answers with a bare 500 and no log line. No test called
%% the formatter, so nothing caught it. Render the whole registry exactly as
%% a scrape does, and require every HELP line to be ASCII.
metrics_scrape_renders_test_() ->
    {setup,
     fun() ->
        {ok, Started} = application:ensure_all_started(prometheus),
        {ok, Started2} = application:ensure_all_started(telemetry),
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup(),
        Started ++ Started2
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"the text exposition of every declared metric renders without crashing",
       fun() ->
           Out = prometheus_text_format:format(),
           ?assert(is_binary(Out)),
           %% A metric from declare_metrics/0 is in the output, so this
           %% really covered the gateway's own declarations.
           ?assertNotEqual(nomatch,
                           binary:match(Out, <<"# HELP yuzu_gw_cluster_connect_failures_total ">>))
       end},
      {"every HELP line is ASCII (Prometheus help text must be ASCII)",
       fun() ->
           Out = prometheus_text_format:format(),
           Help = [L || L <- binary:split(Out, <<"\n">>, [global]),
                        binary:longest_common_prefix([L, <<"# HELP ">>]) =:= 7],
           ?assertNotEqual([], Help),
           NonAscii = [L || L <- Help, lists:any(fun(B) -> B > 127 end,
                                                 binary_to_list(L))],
           ?assertEqual([], NonAscii)
       end},
      %% #1197: a family that is declared but missing from the scrape, or
      %% missing its help text, would be invisible to every operator.
      {"the three heartbeat-verdict families render with their HELP lines",
       fun() ->
           Out = prometheus_text_format:format(),
           [?assertNotEqual(nomatch, binary:match(Out, Help))
            || Help <- [<<"# HELP yuzu_gw_registration_replay_triggered_total ">>,
                        <<"# HELP yuzu_gw_heartbeat_unknown_truncated_total ">>,
                        <<"# HELP yuzu_gw_heartbeat_verdict_dropped_total ">>]]
       end},
      %% queue_full has two causes; the HELP must name both, or an operator
      %% reading a rising series looks only at the replay queue.
      {"verdict_dropped HELP names both causes of queue_full",
       fun() ->
           Out = prometheus_text_format:format(),
           [?assertNotEqual(nomatch, binary:match(Out, Part))
            || Part <- [<<"queue_full = the replay queue is at its cap, or the upstream ">>,
                        <<"process already holds more than 100 unhandled messages">>]]
       end}
     ]}.

%% #5177 review: yuzu_gw_mgmt_auth_rejected_total's series used to appear only
%% at the first rejection, already at 1, which increase() cannot see, so the
%% first probe per reason never alerted. Every reason must exist at 0 after
%% setup(), and the list must match the reject/1 calls in yuzu_gw_authz.
mgmt_auth_reasons_precreated_test_() ->
    {setup,
     fun() ->
        {ok, S1} = application:ensure_all_started(prometheus),
        {ok, S2} = application:ensure_all_started(telemetry),
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup(),
        S1 ++ S2
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"every rejection reason has a series from startup",
       fun() ->
           Out = prometheus_text_format:format(),
           [?assertNotEqual(nomatch,
                            binary:match(Out, iolist_to_binary(
                              ["yuzu_gw_mgmt_auth_rejected_total{reason=\"",
                               atom_to_binary(R, utf8), "\"}"])))
            || R <- yuzu_gw_telemetry:mgmt_auth_reject_reasons()]
       end},
      {"the reason list matches every reject/1 call in yuzu_gw_authz",
       fun() ->
           %% Parse the source, not the .beam: under rebar3's cover
           %% compilation the loaded module has no readable beam file.
           Src = filename:join([code:lib_dir(yuzu_gw), "src", "yuzu_gw_authz.erl"]),
           {ok, Forms} = epp:parse_file(Src, []),
           Called = lists:usort(reject_atoms(Forms)),
           ?assertNotEqual([], Called),
           ?assertEqual(Called,
                        lists:usort(yuzu_gw_telemetry:mgmt_auth_reject_reasons()))
       end}
     ]}.

%% Every literal atom passed to a local reject/1 call, found in the module's
%% parsed source.
reject_atoms(Term) when is_tuple(Term) ->
    case Term of
        {call, _, {atom, _, reject}, [{atom, _, A}]} -> [A];
        _ -> reject_atoms(tuple_to_list(Term))
    end;
reject_atoms(Term) when is_list(Term) ->
    lists:append([reject_atoms(E) || E <- Term]);
reject_atoms(_) -> [].

%% Heartbeat admission counters. Both families must exist at 0 after setup()
%% (a series that first appears already at 1 is invisible to increase()), the
%% reason list must match the reject reasons yuzu_gw_heartbeat_admission can
%% return, and the mismatch family carries event="security" so it routes to
%% the SIEM like the server's own session-binding counters.
heartbeat_admission_series_test_() ->
    {setup,
     fun() ->
        {ok, S1} = application:ensure_all_started(prometheus),
        {ok, S2} = application:ensure_all_started(telemetry),
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup(),
        S1 ++ S2
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"every rejection reason has a series from startup",
       fun() ->
           Out = prometheus_text_format:format(),
           [?assertNotEqual(nomatch,
                            binary:match(Out, iolist_to_binary(
                              ["yuzu_gw_heartbeat_rejected_total{reason=\"",
                               atom_to_binary(R, utf8), "\"} 0"])))
            || R <- yuzu_gw_telemetry:heartbeat_reject_reasons()]
       end},
      {"the mismatch family exists at 0 and carries event=\"security\"",
       fun() ->
           Out = prometheus_text_format:format(),
           ?assertNotEqual(nomatch,
                           binary:match(Out,
                             <<"yuzu_gw_heartbeat_session_mismatch_total{event=\"security\"} 0">>))
       end},
      {"events increment the matching series",
       fun() ->
           Read = fun(Name, Labels) ->
               prometheus_counter:value(Name, Labels)
           end,
           B1 = Read(yuzu_gw_heartbeat_rejected_total, [<<"unknown_session">>]),
           B2 = Read(yuzu_gw_heartbeat_session_mismatch_total, [<<"security">>]),
           telemetry:execute([yuzu, gw, heartbeat, rejected], #{count => 1},
                             #{reason => unknown_session}),
           telemetry:execute([yuzu, gw, heartbeat, session_mismatch], #{count => 1}, #{}),
           ?assertEqual(B1 + 1,
                        Read(yuzu_gw_heartbeat_rejected_total, [<<"unknown_session">>])),
           ?assertEqual(B2 + 1,
                        Read(yuzu_gw_heartbeat_session_mismatch_total, [<<"security">>]))
       end},
      {"the reason list matches every reject reason in yuzu_gw_heartbeat_admission",
       fun() ->
           Src = filename:join([code:lib_dir(yuzu_gw), "src",
                                "yuzu_gw_heartbeat_admission.erl"]),
           {ok, Forms} = epp:parse_file(Src, []),
           Returned = lists:usort(admission_reject_atoms(Forms)),
           ?assertNotEqual([], Returned),
           %% connection_mismatch is its own family, so it is not a `reason'.
           ?assertEqual(lists:usort([connection_mismatch |
                                     yuzu_gw_telemetry:heartbeat_reject_reasons()]),
                        Returned)
       end}
     ]}.

%% Every literal atom A in a `{reject, A}' tuple expression in the parsed source.
admission_reject_atoms(Term) when is_tuple(Term) ->
    case Term of
        {tuple, _, [{atom, _, reject}, {atom, _, A}]} -> [A];
        _ -> admission_reject_atoms(tuple_to_list(Term))
    end;
admission_reject_atoms(Term) when is_list(Term) ->
    lists:append([admission_reject_atoms(E) || E <- Term]);
admission_reject_atoms(_) -> [].

%% #1197: the heartbeat-verdict families. Real telemetry:execute through
%% the real handler (the producers' own tests mock telemetry entirely, which
%% cannot see a missing handler clause or a missing ?EVENTS entry, see the
%% notify_dropped precedent at the top of this file). The labelled series must
%% exist at 0 straight after setup(), or the first increment is invisible to
%% increase(). The labels in the events are atoms, like the heartbeat
%% admission events above.
verdict_families_test_() ->
    {setup,
     fun() ->
        {ok, S1} = application:ensure_all_started(prometheus),
        {ok, S2} = application:ensure_all_started(telemetry),
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup(),
        S1 ++ S2
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"every verdict series exists from startup",
       fun() ->
           Out = prometheus_text_format:format(),
           [?assertNotEqual(nomatch, binary:match(Out, Line))
            || Line <- [<<"yuzu_gw_registration_replay_triggered_total{trigger=\"breaker\"} ">>,
                        <<"yuzu_gw_registration_replay_triggered_total{trigger=\"heartbeat\"} ">>,
                        <<"yuzu_gw_heartbeat_unknown_truncated_total ">>,
                        <<"yuzu_gw_heartbeat_verdict_dropped_total{reason=\"malformed\"} ">>,
                        <<"yuzu_gw_heartbeat_verdict_dropped_total{reason=\"not_local\"} ">>,
                        <<"yuzu_gw_heartbeat_verdict_dropped_total{reason=\"circuit_open\"} ">>,
                        <<"yuzu_gw_heartbeat_verdict_dropped_total{reason=\"queue_full\"} ">>]]
       end},
      {"registration_replay_triggered moves the series of its trigger only",
       fun() ->
           Read = fun(T) -> prometheus_counter:value(yuzu_gw_registration_replay_triggered_total, [T]) end,
           H0 = Read(<<"heartbeat">>), B0 = Read(<<"breaker">>),
           telemetry:execute([yuzu, gw, upstream, registration_replay_triggered],
                             #{count => 1}, #{trigger => heartbeat}),
           ?assertEqual({H0 + 1, B0}, {Read(<<"heartbeat">>), Read(<<"breaker">>)}),
           telemetry:execute([yuzu, gw, upstream, registration_replay_triggered],
                             #{count => 1}, #{trigger => breaker}),
           ?assertEqual({H0 + 1, B0 + 1}, {Read(<<"heartbeat">>), Read(<<"breaker">>)})
       end},
      {"unknown_truncated moves the unlabelled counter",
       fun() ->
           V0 = prometheus_counter:value(yuzu_gw_heartbeat_unknown_truncated_total),
           telemetry:execute([yuzu, gw, heartbeat, unknown_truncated], #{count => 1}, #{}),
           ?assertEqual(V0 + 1, prometheus_counter:value(yuzu_gw_heartbeat_unknown_truncated_total))
       end},
      {"verdict_dropped adds its count to the series of its reason only",
       fun() ->
           Reasons = [malformed, not_local, circuit_open, queue_full],
           Read = fun(R) ->
               prometheus_counter:value(yuzu_gw_heartbeat_verdict_dropped_total,
                                        [atom_to_binary(R, utf8)])
           end,
           Before = [Read(R) || R <- Reasons],
           [telemetry:execute([yuzu, gw, heartbeat, verdict_dropped],
                              #{count => N}, #{reason => R})
            || {R, N} <- lists:zip(Reasons, [3, 4096, 2, 1])],
           ?assertEqual([B + N || {B, N} <- lists:zip(Before, [3, 4096, 2, 1])],
                        [Read(R) || R <- Reasons])
       end},
      %% Characterisation, not new behaviour: it passes without the verdict
      %% replay and pins what it relies on, that the depth reports it adds
      %% with replayed=0 (on append, skip and abort) move the gauge and leave
      %% the replay counter.
      {"a registration_replay event with replayed=0 sets the depth and adds no replay",
       fun() ->
           C0 = prometheus_counter:value(yuzu_gw_registration_replay_total, []),
           telemetry:execute([yuzu, gw, upstream, registration_replay],
                             #{replayed => 0, queue_depth => 7}, #{}),
           ?assertEqual(C0, prometheus_counter:value(yuzu_gw_registration_replay_total, [])),
           ?assertEqual(7, prometheus_gauge:value(yuzu_gw_registration_replay_queue_depth, [node()]))
       end}
     ]}.
