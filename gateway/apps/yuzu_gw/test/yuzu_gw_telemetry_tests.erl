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

%% #4707: a single non-Latin-1 character (an em dash) in one metric's HELP
%% string made prometheus_text_format crash with badarg on every scrape, so
%% :9568/metrics answered HTTP 500 for the whole registry. The CT suite that
%% scrapes the endpoint was masked by #4800 (zero suites ran), so the defect
%% shipped. This renders the REAL registry after the REAL setup through the
%% REAL text formatter, in eunit, so the regression fails the fast gate.
scrape_renders_test_() ->
    {setup,
     fun() ->
        {ok, _} = application:ensure_all_started(prometheus),
        {ok, _} = application:ensure_all_started(telemetry),
        catch telemetry:detach(yuzu_gw_prometheus),
        ok = yuzu_gw_telemetry:setup()
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [
      {"the default registry renders to Prometheus text without crashing",
       fun() ->
           Text = prometheus_text_format:format(default),
           ?assert(is_binary(Text)),
           ?assertNotEqual(nomatch,
                           binary:match(Text, <<"yuzu_gw_agents_connected_total">>))
       end},
      {"every yuzu_gw_* HELP line is plain ASCII",
       fun() ->
           Text = prometheus_text_format:format(default),
           Bad = [L || L <- binary:split(Text, <<"\n">>, [global]),
                       binary:match(L, <<"# HELP yuzu_gw_">>) =/= nomatch,
                       lists:any(fun(C) -> C > 127 end, binary_to_list(L))],
           ?assertEqual([], Bad)
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
