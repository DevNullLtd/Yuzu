%%%-------------------------------------------------------------------
%%% @doc The UPSTREAM metrics of #5695 (yuzu_gw_telemetry's last block): every
%%% series exists at 0 straight after setup, the events reach them, and a label
%%% outside the closed set folds to `unknown' instead of minting a series.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_metrics_tests).
-include_lib("eunit/include/eunit.hrl").

-define(COUNTERS, [yuzu_gw_upstream_permit_refused_total,
                   yuzu_gw_registration_replay_outcomes_total,
                   yuzu_gw_upstream_notify_lost_total,
                   yuzu_gw_upstream_notify_requeued_total]).
-define(GAUGES, [yuzu_gw_upstream_permits_held, yuzu_gw_upstream_permits_waiting,
                 yuzu_gw_upstream_permit_limit,
                 yuzu_gw_registration_replay_last_duration_seconds,
                 yuzu_gw_upstream_notify_pending_hwm, yuzu_gw_upstream_notify_pending_max]).

upstream_metrics_test_() ->
    {setup,
     fun() ->
         {ok, A} = application:ensure_all_started(prometheus),
         {ok, B} = application:ensure_all_started(telemetry),
         catch telemetry:detach(yuzu_gw_prometheus),
         [_ = prometheus_counter:deregister(C) || C <- ?COUNTERS],
         [_ = prometheus_gauge:deregister(G) || G <- ?GAUGES],
         _ = prometheus_histogram:deregister(yuzu_gw_upstream_permit_wait_seconds),
         ok = yuzu_gw_telemetry:setup(),
         A ++ B
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [{"every series is created at 0 by setup",
       fun() ->
           [begin
                ?assertEqual(0, prometheus_gauge:value(yuzu_gw_upstream_permits_held, [C])),
                ?assertEqual(0, prometheus_gauge:value(yuzu_gw_upstream_permits_waiting, [C])),
                [?assertEqual(0, prometheus_counter:value(yuzu_gw_upstream_permit_refused_total,
                                                          [C, R]))
                 || R <- [<<"queue_full">>, <<"deadline">>, <<"stopping">>]]
            end || C <- [<<"register">>, <<"replay">>, <<"inventory">>]],
           [?assertEqual(0, prometheus_counter:value(yuzu_gw_registration_replay_outcomes_total, [O]))
            || O <- [<<"adopted">>, <<"superseded">>, <<"rejected">>, <<"failed">>,
                     <<"skipped">>, <<"aborted">>]],
           [?assertEqual(0, prometheus_counter:value(yuzu_gw_upstream_notify_lost_total, [E, R]))
            || E <- [<<"connected">>, <<"disconnected">>],
               R <- [<<"at_capacity">>, <<"evicted">>, <<"rejected">>, <<"crashed">>,
                     <<"shutdown">>]],
           ?assertEqual(0, prometheus_counter:value(yuzu_gw_upstream_notify_requeued_total, [])),
           ?assertEqual(0, prometheus_gauge:value(yuzu_gw_upstream_notify_pending_hwm, [])),
           ?assertEqual(0, prometheus_gauge:value(yuzu_gw_upstream_notify_pending_max, []))
       end},
      {"the events reach their series",
       fun() ->
           telemetry:execute([yuzu, gw, upstream, permits], #{held => 3, waiting => 2},
                             #{class => register}),
           ?assertEqual(3, prometheus_gauge:value(yuzu_gw_upstream_permits_held, [<<"register">>])),
           ?assertEqual(2, prometheus_gauge:value(yuzu_gw_upstream_permits_waiting, [<<"register">>])),
           telemetry:execute([yuzu, gw, upstream, permit_refused], #{count => 1},
                             #{class => inventory, reason => queue_full}),
           ?assertEqual(1, prometheus_counter:value(yuzu_gw_upstream_permit_refused_total,
                                                    [<<"inventory">>, <<"queue_full">>])),
           telemetry:execute([yuzu, gw, upstream, notify_lost], #{count => 2},
                             #{event => disconnected, reason => shutdown}),
           ?assertEqual(2, prometheus_counter:value(yuzu_gw_upstream_notify_lost_total,
                                                    [<<"disconnected">>, <<"shutdown">>])),
           telemetry:execute([yuzu, gw, upstream, notify_held], #{hwm => 7, max => 15000}, #{}),
           ?assertEqual(7, prometheus_gauge:value(yuzu_gw_upstream_notify_pending_hwm, [])),
           ?assertEqual(15000, prometheus_gauge:value(yuzu_gw_upstream_notify_pending_max, [])),
           telemetry:execute([yuzu, gw, upstream, registration_replay_done], #{seconds => 1.5}, #{}),
           ?assertEqual(1.5, prometheus_gauge:value(
                               yuzu_gw_registration_replay_last_duration_seconds, [])),
           telemetry:execute([yuzu, gw, upstream, permit_wait], #{seconds => 0.02},
                             #{class => replay}),
           {Buckets, _Sum} = prometheus_histogram:value(yuzu_gw_upstream_permit_wait_seconds,
                                                        [<<"replay">>]),
           ?assertEqual(1, lists:sum(Buckets))
       end},
      {"a label outside the closed set folds to unknown",
       fun() ->
           telemetry:execute([yuzu, gw, upstream, notify_lost], #{count => 1},
                             #{event => <<"bogus">>, reason => made_up}),
           ?assertEqual(1, prometheus_counter:value(yuzu_gw_upstream_notify_lost_total,
                                                    [<<"unknown">>, <<"unknown">>])),
           telemetry:execute([yuzu, gw, upstream, registration_replay_outcome], #{count => 1},
                             #{outcome => {not_an, atom}}),
           ?assertEqual(1, prometheus_counter:value(yuzu_gw_registration_replay_outcomes_total,
                                                    [<<"unknown">>]))
       end},
      {"the scrape renders (ASCII-only help text)",
       fun() ->
           Out = prometheus_text_format:format(),
           [?assertNotEqual(nomatch, binary:match(Out, atom_to_binary(M, utf8)))
            || M <- ?COUNTERS ++ ?GAUGES ++ [yuzu_gw_upstream_permit_wait_seconds]]
       end}]}.
