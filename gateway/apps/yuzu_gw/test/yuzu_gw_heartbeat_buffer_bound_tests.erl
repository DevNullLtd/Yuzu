%%%-------------------------------------------------------------------
%%% @doc Tests for the bounds of yuzu_gw_heartbeat_buffer (#1197): one entry
%%% per session (coalescing), the byte cap, the oversize-snapshot drop and the
%%% chunked flush that keeps every BatchHeartbeat request under the server's
%%% 4194304-byte gRPC receive limit.
%%%
%%% The failure these guard against: a failed flush retained every heartbeat,
%%% capped by count only, so after a long outage the retained batch (each
%%% heartbeat can carry a 200 to 800 KB fleet snapshot) exceeded the server's
%%% receive limit and every later flush failed forever.
%%%
%%% Mocks: grpcbox_client (every request is encoded with the Def the buffer
%%% passes, so sizes are the real wire sizes), telemetry and
%%% yuzu_gw_upstream:replay_sessions/1 (both recorded). The log is an ETS
%%% table written from the calling process, so a flush_sync/0 reply (or the
%%% sys:get_state/1 barrier after a cast) proves everything the buffer did is
%%% already in it.
%%%
%%% A "nothing happened" assertion always sits next to a positive control.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_buffer_bound_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-export([log/2]).  %% logger handler callback, see capture_logs/1

-define(LOGK, {?MODULE, log}).
-define(LOG_HANDLER, yuzu_bound_test_log).
-define(SERVER_LIMIT, 4194304).
-define(MIB, 1048576).
-define(EV_COALESCED, [yuzu, gw, heartbeat, coalesced]).
-define(EV_DROPPED, [yuzu, gw, heartbeat, buffer_dropped]).
%% Element positions in the buffer's state record (tag at 1); one test asserts
%% the tuple size so a layout change fails loudly there.
-define(ST_BUFFER, 2).
-define(ST_BUF_BYTES, 3).
-define(ST_MAX_BYTES, 10).
-define(ST_SNAP_IDX, 11).

bound_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"coalesce keeps the newest fields per session",
       fun coalesce_keeps_newest_fields_per_session/0},
      {"coalesce carries forward the newest non-empty snapshot",
       fun coalesce_carries_forward_newest_nonempty_snapshot/0},
      {"the size estimate is an upper bound of the encoded size",
       fun estimate_is_upper_bound_of_encoded_size/0},
      {"a retained 30 x 800 KB batch drains in chunks each under the server limit",
       fun retained_30x800kb_batch_drains_in_chunks_each_under_4194304/0},
      {"chunks are oldest first",
       fun chunks_are_oldest_first/0},
      {"a failed chunk retains itself and the unsent chunks only",
       fun partial_failure_retains_failed_and_unsent_only/0},
      {"the verdict is consumed once per successful chunk",
       fun verdict_consumed_per_successful_chunk/0},
      {"one heartbeat with an oversize snapshot ships without it and is counted",
       fun oversize_single_heartbeat_ships_without_snapshot_and_counts/0},
      {"the byte cap strips the oldest snapshot before it drops a session",
       fun byte_cap_strips_oldest_snapshot_before_dropping_session/0},
      {"the count cap drop is counted and a coalescing heartbeat is never dropped",
       fun count_cap_drop_counted_and_replacement_never_dropped/0},
      {"a failed flush never reaches the circuit breaker",
       fun flush_failure_never_calls_breaker/0},
      {"the tracked bytes and the snapshot index stay consistent under a mixed load",
       fun bookkeeping_stays_consistent/0},
      {"a value that is not a heartbeat map is ignored and the buffer survives",
       fun non_map_value_is_ignored/0},
      {"max_heartbeat_buffer_bytes outside 1 MiB..1 GiB or not an integer falls back with a warning",
       fun max_bytes_invalid_falls_back/0},
      {"max_heartbeat_buffer_bytes inside 1 MiB..1 GiB is kept",
       fun max_bytes_valid_is_kept/0},
      {"a lone 5 MiB heartbeat ahead of 50 sessions is dropped on arrival and all 50 are delivered",
       fun poison_oversize_heartbeat_is_dropped_and_others_delivered/0},
      {"512 status tags are kept, 513 are dropped as heartbeat_oversize",
       fun status_tag_count_bound/0},
      {"a heartbeat over one chunk without its snapshot is dropped, not stripped",
       fun oversize_without_snapshot_is_dropped_not_stripped/0},
      {"a coalescing heartbeat over a chunk loses the older snapshot and keeps the heartbeat",
       fun coalesced_over_a_chunk_strips_the_snapshot/0},
      {"an oversize or invalid heartbeat leaves the older entry of its session untouched",
       fun dropped_heartbeat_keeps_the_older_entry/0},
      {"invalid UTF-8 in a tag or the session id is dropped and never crashes the buffer",
       fun invalid_utf8_is_dropped_and_buffer_survives/0},
      {"a one-heartbeat chunk refused with RESOURCE_EXHAUSTED or INVALID_ARGUMENT is dropped",
       fun refused_single_chunk_is_dropped/0},
      {"a refused chunk of several is split and only the refused heartbeat is dropped",
       fun refused_chunk_is_split_and_poison_dropped/0},
      {"a server that refuses every multi-heartbeat request still gets all heartbeats",
       fun refusal_of_multi_requests_delivers_singles/0},
      {"a server that refuses everything costs at most 64 RPCs per flush",
       fun refusing_server_is_bounded_per_flush/0},
      {"a transient failure keeps the chunk and every later one and stops the flush",
       fun transient_failures_retain_and_stop/0},
      {"an exception or exit out of the RPC is a failed flush, not a crash, and logs no reason",
       fun exception_out_of_rpc_is_a_failed_flush/0},
      {"entries the encoder raises on are dropped from a failed chunk and the rest is sent",
       fun encoder_raising_entries_are_dropped_from_the_chunk/0},
      {"the timer's flush sends at most 8 chunks per cycle: 30 chunks drain in 8, 8, 8, 6",
       fun timer_flush_sends_at_most_eight_chunks/0},
      {"flush_sync sends at most 8 chunks and the rest stays buffered",
       fun flush_sync_sends_at_most_eight_chunks/0}
     ]}.

setup() ->
    catch meck:unload(grpcbox_client),
    catch meck:unload(telemetry),
    catch meck:unload(yuzu_gw_upstream),
    persistent_term:put(?LOGK, ets:new(bound_test_log, [public, ordered_set])),
    meck:new(grpcbox_client, [non_strict, no_link]),
    set_unary(fun(_N) -> {ok, #{acknowledged_count => 0}, #{}} end),
    meck:new(telemetry, [passthrough, no_link]),
    meck:expect(telemetry, execute, fun(Event, Meas, Meta) ->
        rec({event, Event, Meas, Meta}),
        ok
    end),
    %% The real upstream must not run: the buffer talks to the mock.
    stop_upstream(),
    meck:new(yuzu_gw_upstream, [passthrough, no_link]),
    meck:expect(yuzu_gw_upstream, replay_sessions, fun(Ids) ->
        rec({cast, Ids}),
        ok
    end),
    application:set_env(yuzu_gw, heartbeat_batch_interval_ms, 60000),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 100),
    application:unset_env(yuzu_gw, max_heartbeat_buffer_bytes),
    start_buffer(),
    ok.

cleanup(_) ->
    stop_buffer(),
    stop_upstream(),
    catch meck:unload([grpcbox_client, telemetry, yuzu_gw_upstream]),
    persistent_term:erase(?LOGK),
    application:unset_env(yuzu_gw, max_heartbeat_buffer_bytes),
    application:set_env(yuzu_gw, max_heartbeat_buffer, 100),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

coalesce_keeps_newest_fields_per_session() ->
    Old = hb(<<"a">>, #{tags => #{<<"k1">> => <<"old">>, <<"gone">> => <<"x">>},
                        sent_at => 1, snap => <<"snap-old">>}),
    New = hb(<<"a">>, #{tags => #{<<"k1">> => <<"new">>},
                        sent_at => 2, snap => <<"snap-new">>}),
    Other = hb(<<"b">>, #{tags => #{<<"k">> => <<"v">>}, sent_at => 5}),
    [queue(H) || H <- [Old, Other, New]],
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    [Req] = requests(),
    Sent = maps:from_list([{maps:get(session_id, H), H} || H <- hbs(Req)]),
    ?assertEqual(2, map_size(Sent)),
    %% The newest heartbeat wins every field, including the tag set (no merge
    %% of tag keys across heartbeats).
    ?assertEqual(New, maps:get(<<"a">>, Sent)),
    ?assertEqual(Other, maps:get(<<"b">>, Sent)),
    ?assertEqual(1, event_count(?EV_COALESCED)),
    ?assertEqual(0, dropped_total()).

coalesce_carries_forward_newest_nonempty_snapshot() ->
    S1 = <<"snapshot-1">>,
    S2 = <<"snapshot-2">>,
    %% A newer heartbeat with the key absent, then with an explicit empty
    %% snapshot, must not discard the older snapshot.
    queue(hb(<<"a">>, #{snap => S1, sent_at => 1})),
    queue(hb(<<"a">>, #{snap => S2, sent_at => 2})),
    queue(hb(<<"a">>, #{sent_at => 3, tags => #{<<"t">> => <<"3">>}})),
    queue(hb(<<"a">>, #{snap => <<>>, sent_at => 4, tags => #{<<"t">> => <<"4">>}})),
    %% Control: a session that never had a snapshot ships without one.
    queue(hb(<<"b">>, #{sent_at => 1})),
    queue(hb(<<"b">>, #{sent_at => 2})),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    [Req] = requests(),
    Sent = maps:from_list([{maps:get(session_id, H), H} || H <- hbs(Req)]),
    A = maps:get(<<"a">>, Sent),
    ?assertEqual(S2, maps:get(fleet_snapshot_json, A)),
    ?assertEqual(#{millis_epoch => 4}, maps:get(sent_at, A)),
    ?assertEqual(#{<<"t">> => <<"4">>}, maps:get(status_tags, A)),
    B = maps:get(<<"b">>, Sent),
    ?assertEqual(<<>>, maps:get(fleet_snapshot_json, B, <<>>)),
    ?assertEqual(4, event_count(?EV_COALESCED)).

estimate_is_upper_bound_of_encoded_size() ->
    LongId = binary:copy(<<"i">>, 64),
    ManyTags = maps:from_list([{iolist_to_binary(["yuzu.tag.", integer_to_list(I)]),
                                binary:copy(<<"v">>, I rem 40)}
                               || I <- lists:seq(1, 300)]),
    Hbs = [
        %% 2 MiB snapshot, a long id, a maximal timestamp and many tags.
        #{session_id => LongId, sent_at => #{millis_epoch => 9223372036854775807},
          status_tags => ManyTags, fleet_snapshot_json => binary:copy(<<"s">>, 2 * ?MIB)},
        %% No tags: the fixed overhead alone must be covered.
        #{session_id => LongId, sent_at => #{millis_epoch => 9223372036854775807},
          fleet_snapshot_json => binary:copy(<<"s">>, 2 * ?MIB)},
        #{session_id => <<"a">>, sent_at => #{millis_epoch => 1},
          status_tags => #{<<"k">> => <<"v">>}},
        #{session_id => <<"b">>},
        #{session_id => <<>>},
        #{session_id => LongId, fleet_snapshot_json => binary:copy(<<"s">>, 127)},
        #{session_id => LongId, fleet_snapshot_json => binary:copy(<<"s">>, 128)},
        #{session_id => <<"c">>, sent_at => #{millis_epoch => -1},
          status_tags => #{binary:copy(<<"k">>, 200) => binary:copy(<<"v">>, 20000)}}
    ],
    [begin
         Enc = encoded_size(#{heartbeats => [H], gateway_node => <<>>}),
         Est = yuzu_gw_heartbeat_buffer:estimate_bytes(H),
         NTags = map_size(maps:get(status_tags, H, #{})),
         ?assert(Est >= Enc),
         %% Not wildly loose either: the slack is the fixed 32 plus at most 18
         %% per tag, so a huge constant (which would waste the byte cap) fails.
         ?assert(Est - Enc =< 32 + 18 * NTags)
     end || H <- Hbs],
    %% A whole batch: the sum of the estimates bounds the encoded request, and
    %% the 31-byte node name the flush adds fits the chunk's margin below the
    %% server limit.
    Enc1 = encoded_size(#{heartbeats => Hbs, gateway_node => <<>>}),
    ?assert(lists:sum([yuzu_gw_heartbeat_buffer:estimate_bytes(H) || H <- Hbs]) >= Enc1).

retained_30x800kb_batch_drains_in_chunks_each_under_4194304() ->
    Ids = [sid(I) || I <- lists:seq(1, 30)],
    [queue(hb(Id, #{snap => snap(800 * 1024), tags => tags(), sent_at => 1}))
     || Id <- Ids],
    %% The server is down for three flushes: the whole batch is retained. The
    %% first failure stops the flush, so only one request is attempted each.
    set_unary(fun(_N) -> {error, {unavailable, <<"down">>}, #{}} end),
    [?assertMatch({error, _}, yuzu_gw_heartbeat_buffer:flush_sync()) || _ <- [1, 2, 3]],
    ?assertEqual(3, length(requests())),
    ?assertEqual(30, session_count()),
    ?assertEqual(lists:sort(Ids), lists:sort(buffered_ids())),
    %% The server is back: 10 chunks of three, and a flush sends at most 8, so
    %% the second flush finishes the drain.
    reset_requests(),
    set_unary(fun(_N) -> {ok, #{acknowledged_count => 0}, #{}} end),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(8, length(requests())),
    ?assertEqual(6, session_count()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    Reqs = requests(),
    ?assertEqual(10, length(Reqs)),
    [?assert(Size < ?SERVER_LIMIT) || Size <- request_sizes()],
    Sent = [maps:get(session_id, H) || R <- Reqs, H <- hbs(R)],
    ?assertEqual(30, length(Sent)),
    ?assertEqual(lists:sort(Ids), lists:sort(Sent)),
    ?assertEqual(0, session_count()),
    ?assertEqual(0, buffered_bytes()),
    %% Control: the heartbeats were not stripped to get under the limit.
    [?assertEqual(snap(800 * 1024), maps:get(fleet_snapshot_json, H))
     || R <- Reqs, H <- hbs(R)],
    ?assertEqual(0, dropped_total()),
    %% Control: all 30 in ONE request would have been over the server limit,
    %% so the chunking is what the bound rests on.
    One = #{heartbeats => [hb(Id, #{snap => snap(800 * 1024)}) || Id <- Ids],
            gateway_node => <<"n">>},
    ?assert(encoded_size(One) > ?SERVER_LIMIT).

chunks_are_oldest_first() ->
    %% Descending ids: the map's own key order differs from arrival order.
    Ids = [sid(I) || I <- lists:seq(8, 1, -1)],
    [queue(hb(Id, #{snap => snap(?MIB)})) || Id <- Ids],
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    Reqs = requests(),
    ?assertEqual(4, length(Reqs)),
    ?assertEqual(Ids, [maps:get(session_id, H) || R <- Reqs, H <- hbs(R)]),
    %% A refreshed session is the newest again: it goes last.
    [queue(hb(Id, #{snap => snap(?MIB)})) || Id <- [sid(1), sid(2), sid(3)]],
    queue(hb(sid(1), #{snap => snap(?MIB), sent_at => 7})),
    reset_requests(),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual([sid(2), sid(3), sid(1)],
                 [maps:get(session_id, H) || R <- requests(), H <- hbs(R)]).

partial_failure_retains_failed_and_unsent_only() ->
    Ids = [sid(I) || I <- lists:seq(1, 6)],
    [queue(hb(Id, #{snap => snap(?MIB)})) || Id <- Ids],
    %% 1 MiB each: two per chunk, so three chunks. The second one fails.
    set_unary(fun(2) -> {error, {unavailable, <<"down">>}, #{}};
                 (_) -> {ok, #{acknowledged_count => 0}, #{}}
              end),
    ?assertMatch({error, _}, yuzu_gw_heartbeat_buffer:flush_sync()),
    Attempted = [[maps:get(session_id, H) || H <- hbs(R)] || R <- requests()],
    ?assertEqual([[sid(1), sid(2)], [sid(3), sid(4)]], Attempted),
    ?assertEqual([sid(3), sid(4), sid(5), sid(6)], lists:sort(buffered_ids())),
    %% The retry sends exactly the retained sessions, and never the first
    %% chunk again.
    reset_requests(),
    set_unary(fun(_N) -> {ok, #{acknowledged_count => 0}, #{}} end),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual([[sid(3), sid(4)], [sid(5), sid(6)]],
                 [[maps:get(session_id, H) || H <- hbs(R)] || R <- requests()]),
    ?assertEqual(0, session_count()).

verdict_consumed_per_successful_chunk() ->
    Ids = [sid(I) || I <- lists:seq(1, 6)],
    [queue(hb(Id, #{snap => snap(?MIB)})) || Id <- Ids],
    V = fun(Unknown) -> {ok, #{acknowledged_count => 2, unknown_session_ids => Unknown}, #{}} end,
    set_unary(fun(1) -> V([<<"unknown-a">>]);
                 (2) -> V([<<"unknown-b">>]);
                 (_) -> {error, {unavailable, <<"down">>}, #{}}
              end),
    ?assertMatch({error, _}, yuzu_gw_heartbeat_buffer:flush_sync()),
    %% One cast per SUCCESSFUL chunk, none for the failed one.
    ?assertEqual([[<<"unknown-a">>], [<<"unknown-b">>]], casts()),
    ?assertEqual(2, session_count()),
    %% The retry consumes its own chunk's verdict, once.
    set_unary(fun(_N) -> V([<<"unknown-c">>]) end),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual([[<<"unknown-a">>], [<<"unknown-b">>], [<<"unknown-c">>]], casts()).

oversize_single_heartbeat_ships_without_snapshot_and_counts() ->
    Big = hb(<<"big">>, #{snap => snap(3 * ?MIB + 1), tags => #{<<"k">> => <<"v">>},
                          sent_at => 9}),
    %% Control: a snapshot that still fits one chunk is kept.
    Fits = hb(<<"fits">>, #{snap => snap(3 * ?MIB - 4096)}),
    queue(Fits),
    ?assertEqual(0, dropped_total()),
    queue(Big),
    ?assertEqual(1, dropped(snapshot_oversize)),
    ?assertEqual(1, dropped_total()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    Sent = maps:from_list([{maps:get(session_id, H), H} || R <- requests(), H <- hbs(R)]),
    BigSent = maps:get(<<"big">>, Sent),
    ?assertEqual(<<>>, maps:get(fleet_snapshot_json, BigSent, <<>>)),
    ?assertEqual(#{<<"k">> => <<"v">>}, maps:get(status_tags, BigSent)),
    ?assertEqual(#{millis_epoch => 9}, maps:get(sent_at, BigSent)),
    ?assertEqual(maps:get(fleet_snapshot_json, Fits),
                 maps:get(fleet_snapshot_json, maps:get(<<"fits">>, Sent))),
    [?assert(Size < ?SERVER_LIMIT) || Size <- request_sizes()].

byte_cap_strips_oldest_snapshot_before_dropping_session() ->
    restart_buffer(100, 2 * ?MIB),
    Snap = snap(600 * 1024),
    [queue(hb(sid(I), #{snap => Snap})) || I <- [1, 2, 3]],
    %% 3 x 600 KB fits in 2 MiB: nothing evicted yet (positive control).
    ?assertEqual(0, dropped_total()),
    queue(hb(sid(4), #{snap => Snap})),
    ?assertEqual(1, dropped(snapshot_evicted)),
    ?assertEqual(1, dropped_total()),
    ?assert(buffered_bytes() =< 2 * ?MIB),
    ?assertEqual(4, session_count()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    Sent = maps:from_list([{maps:get(session_id, H), H} || R <- requests(), H <- hbs(R)]),
    %% The oldest snapshot went; the session did not, and the others kept theirs.
    ?assertEqual(<<>>, maps:get(fleet_snapshot_json, maps:get(sid(1), Sent), <<>>)),
    [?assertEqual(Snap, maps:get(fleet_snapshot_json, maps:get(sid(I), Sent)))
     || I <- [2, 3, 4]],
    %% No snapshot to strip: the oldest whole session goes. Three heartbeats
    %% of ~400 KB tags in a 1 MiB cap.
    restart_buffer(100, ?MIB),
    reset_events(),
    Tags = #{<<"big">> => binary:copy(<<"t">>, 400 * 1024)},
    [queue(hb(sid(I), #{tags => Tags})) || I <- [1, 2]],
    ?assertEqual(0, dropped_total()),
    queue(hb(sid(3), #{tags => Tags})),
    ?assertEqual(1, dropped(buffer_full)),
    ?assertEqual(0, dropped(snapshot_evicted)),
    ?assertEqual([sid(2), sid(3)], lists:sort(buffered_ids())),
    ?assert(buffered_bytes() =< ?MIB).

count_cap_drop_counted_and_replacement_never_dropped() ->
    restart_buffer(3, 64 * ?MIB),
    [queue(hb(sid(I), #{tags => #{<<"v">> => <<"1">>}})) || I <- [1, 2, 3]],
    ?assertEqual(0, dropped_total()),
    %% A fourth session is dropped, and counted.
    queue(hb(sid(4), #{})),
    ?assertEqual(1, dropped(buffer_full)),
    ?assertEqual(3, session_count()),
    ?assertNot(lists:member(sid(4), buffered_ids())),
    %% A heartbeat for a buffered session replaces its entry even at the cap.
    queue(hb(sid(2), #{tags => #{<<"v">> => <<"2">>}})),
    ?assertEqual(1, dropped(buffer_full)),
    ?assertEqual(1, event_count(?EV_COALESCED)),
    ?assertEqual(3, session_count()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    Sent = maps:from_list([{maps:get(session_id, H), H} || R <- requests(), H <- hbs(R)]),
    ?assertEqual([sid(1), sid(2), sid(3)], lists:sort(maps:keys(Sent))),
    ?assertEqual(#{<<"v">> => <<"2">>}, maps:get(status_tags, maps:get(sid(2), Sent))),
    %% Room again after the flush: a new session is accepted.
    queue(hb(sid(4), #{})),
    ?assertEqual(1, dropped(buffer_full)),
    ?assertEqual(1, session_count()).

%% A flush does not go through yuzu_gw_upstream, so its failures cannot trip
%% the upstream's circuit breaker. The control drives the SAME failing mock
%% through the upstream's own RPC path until the breaker opens, which proves
%% that the breaker would have seen a failure routed through it.
flush_failure_never_calls_breaker() ->
    meck:unload(yuzu_gw_upstream),
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, 2),
    {ok, Up} = yuzu_gw_upstream:start_link(),
    unlink(Up),
    try
        set_unary(fun(_N) -> {error, {unavailable, <<"down">>}, #{}} end),
        queue(hb(<<"a">>, #{})),
        [?assertMatch({error, _}, yuzu_gw_heartbeat_buffer:flush_sync()) || _ <- lists:seq(1, 6)],
        ?assertEqual(6, length(requests())),
        ?assertEqual(closed, yuzu_gw_upstream:circuit_state()),
        %% Control: failures routed through the upstream open the breaker.
        reset_requests(),
        [_ = yuzu_gw_upstream:proxy_inventory(#{session_id => <<"a">>}) || _ <- [1, 2]],
        ?assertEqual(2, length(requests())),
        ?assertEqual(open, yuzu_gw_upstream:circuit_state())
    after
        catch gen_server:stop(Up, shutdown, 2000),
        application:unset_env(yuzu_gw, circuit_breaker_failure_threshold)
    end.

%% Every mutation goes through put/remove/strip: after a mixed load the
%% tracked bytes equal the sum of the entries' estimates and the snapshot
%% index names exactly the entries that hold a snapshot.
bookkeeping_stays_consistent() ->
    restart_buffer(50, 3 * ?MIB),
    rand:seed(exsss, {1, 2, 3}),
    [queue(random_hb(rand:uniform(70))) || _ <- lists:seq(1, 400)],
    check_bookkeeping(),
    ?assert(session_count() =< 50),
    ?assert(buffered_bytes() =< 3 * ?MIB),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    check_bookkeeping(),
    ?assertEqual(0, session_count()),
    ?assertEqual(0, buffered_bytes()),
    ?assertEqual(0, gb_trees:size(snap_idx())).

non_map_value_is_ignored() ->
    yuzu_gw_heartbeat_buffer:queue_heartbeat(not_a_map),
    queue(hb(<<"a">>, #{})),
    ?assertEqual(1, session_count()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(1, length(requests())).

max_bytes_invalid_falls_back() ->
    [max_bytes_case(Bad, 67108864, invalid)
     || Bad <- [-1, 0, 1048575, 1073741825, 9999999999, 1.5, foo, <<"67108864">>, "67108864"]],
    ok.

max_bytes_valid_is_kept() ->
    [max_bytes_case(V, V, valid) || V <- [1048576, 67108864, 1073741824]],
    ok.

max_bytes_case(Val, Expected, Kind) ->
    stop_buffer(),
    application:set_env(yuzu_gw, max_heartbeat_buffer_bytes, Val),
    try
        {Pid, Lines} = capture_logs(fun() ->
            {ok, P} = yuzu_gw_heartbeat_buffer:start_link(),
            unlink(P),
            P
        end),
        ?assertEqual(Expected, element(?ST_MAX_BYTES, sys:get_state(Pid))),
        Named = [T || {warning, T} <- Lines,
                      binary:match(T, <<"max_heartbeat_buffer_bytes">>) =/= nomatch],
        case Kind of
            invalid -> ?assertMatch([_], Named);
            valid   -> ?assertEqual([], Named)
        end
    after
        stop_buffer(),
        application:unset_env(yuzu_gw, max_heartbeat_buffer_bytes),
        start_buffer()
    end.

%% A server that refuses a request over its receive limit, as the real one does.
%% One heartbeat with 5 MiB of status tags used to go out as a chunk of its own,
%% be refused every cycle and hold every newer heartbeat behind it.
poison_oversize_heartbeat_is_dropped_and_others_delivered() ->
    set_unary(fun(_N) -> {ok, #{acknowledged_count => 0}, #{}} end),
    refuse_over_limit(),
    queue(hb(<<"poison">>, #{tags => #{<<"big">> => binary:copy(<<"t">>, 5 * ?MIB)}})),
    Ids = [sid(I) || I <- lists:seq(1, 50)],
    [queue(hb(Id, #{snap => snap(100 * 1024), tags => tags()})) || Id <- Ids],
    ?assertEqual(1, dropped(heartbeat_oversize)),
    ?assertEqual(1, dropped_total()),
    ?assertEqual(0, dropped(snapshot_oversize)),
    ?assertEqual(50, session_count()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    Sent = [maps:get(session_id, H) || R <- requests(), H <- hbs(R)],
    ?assertEqual(Ids, Sent),
    ?assertEqual(0, session_count()),
    [?assert(Size =< ?SERVER_LIMIT) || Size <- request_sizes()],
    ?assertEqual(1, dropped_total()),
    %% Control: the refusing server does refuse a request that big, so the drop
    %% is what kept it out.
    Big = #{heartbeats => [hb(<<"poison">>, #{tags => #{<<"big">> => binary:copy(<<"t">>, 5 * ?MIB)}})],
            gateway_node => <<"n">>},
    ?assert(encoded_size(Big) > ?SERVER_LIMIT).

status_tag_count_bound() ->
    Tags = fun(N) -> maps:from_list([{iolist_to_binary(["k", integer_to_list(I)]), <<"v">>}
                                     || I <- lists:seq(1, N)]) end,
    queue(hb(<<"at-limit">>, #{tags => Tags(512)})),
    ?assertEqual(0, dropped_total()),
    queue(hb(<<"over-limit">>, #{tags => Tags(513)})),
    ?assertEqual(1, dropped(heartbeat_oversize)),
    ?assertEqual(1, dropped_total()),
    ?assertEqual([<<"at-limit">>], buffered_ids()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual([<<"at-limit">>], [maps:get(session_id, H) || R <- requests(), H <- hbs(R)]).

oversize_without_snapshot_is_dropped_not_stripped() ->
    %% 3.1 MiB of tags: over one chunk with no snapshot to strip. A 10 KB
    %% snapshot beside it does not make the snapshot the cause.
    Tags = #{<<"big">> => binary:copy(<<"t">>, 3 * ?MIB + 100 * 1024)},
    queue(hb(<<"no-snap">>, #{tags => Tags})),
    queue(hb(<<"with-snap">>, #{tags => Tags, snap => snap(10 * 1024)})),
    ?assertEqual(2, dropped(heartbeat_oversize)),
    ?assertEqual(0, dropped(snapshot_oversize)),
    ?assertEqual(2, dropped_total()),
    ?assertEqual(0, session_count()),
    %% Control: a snapshot over a chunk is still stripped and counted as such.
    queue(hb(<<"big-snap">>, #{snap => snap(3 * ?MIB + 1)})),
    ?assertEqual(1, dropped(snapshot_oversize)),
    ?assertEqual(2, dropped(heartbeat_oversize)),
    ?assertEqual([<<"big-snap">>], buffered_ids()).

%% Each part fits a chunk alone (a 2 MiB snapshot, then 1.5 MiB of tags) and the
%% coalesced heartbeat does not: the older snapshot goes, the heartbeat stays.
coalesced_over_a_chunk_strips_the_snapshot() ->
    queue(hb(<<"a">>, #{snap => snap(2 * ?MIB)})),
    ?assertEqual(0, dropped_total()),
    queue(hb(<<"a">>, #{tags => #{<<"t">> => binary:copy(<<"t">>, 3 * ?MIB div 2)}})),
    ?assertEqual(1, dropped(snapshot_oversize)),
    ?assertEqual(1, dropped_total()),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    [H] = [H || R <- requests(), H <- hbs(R)],
    ?assertEqual(<<>>, maps:get(fleet_snapshot_json, H, <<>>)),
    ?assertEqual(3 * ?MIB div 2, byte_size(maps:get(<<"t">>, maps:get(status_tags, H)))).

dropped_heartbeat_keeps_the_older_entry() ->
    queue(hb(<<"a">>, #{tags => #{<<"v">> => <<"old">>}, snap => <<"snap-old">>})),
    queue(hb(<<"a">>, #{tags => #{<<"big">> => binary:copy(<<"t">>, 4 * ?MIB)}})),
    ?assertEqual(1, dropped(heartbeat_oversize)),
    queue(#{session_id => <<"a">>, status_tags => #{<<"v">> => <<255>>}}),
    ?assertEqual(1, dropped(heartbeat_invalid)),
    ?assertEqual(0, event_count(?EV_COALESCED)),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    [H] = [H || R <- requests(), H <- hbs(R)],
    ?assertEqual(#{<<"v">> => <<"old">>}, maps:get(status_tags, H)),
    ?assertEqual(<<"snap-old">>, maps:get(fleet_snapshot_json, H)).

invalid_utf8_is_dropped_and_buffer_survives() ->
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    Bad = [
        %% a lone 0xFF byte as the key, as the value, and a truncated sequence
        #{session_id => <<"bad-key">>, status_tags => #{<<255>> => <<"v">>}},
        #{session_id => <<"bad-val">>, status_tags => #{<<"k">> => <<255>>}},
        #{session_id => <<"bad-cut">>, status_tags => #{<<"k">> => <<"ab", 226, 130>>}},
        %% an encoded surrogate and an overlong form
        #{session_id => <<"bad-surrogate">>, status_tags => #{<<"k">> => <<237, 160, 128>>}},
        #{session_id => <<"bad-overlong">>, status_tags => #{<<"k">> => <<192, 128>>}},
        %% the session id itself
        #{session_id => <<255, 1>>, status_tags => #{<<"k">> => <<"v">>}},
        %% not a binary at all
        #{session_id => <<"bad-type">>, status_tags => #{<<"k">> => not_a_binary}},
        #{session_id => <<"bad-tags">>, status_tags => [{<<"k">>, <<"v">>}]},
        #{session_id => 7}
    ],
    Good = [hb(<<"good-1">>, #{tags => #{<<"k">> => <<"v">>}}),
            %% multi-byte UTF-8 (a euro sign, an emoji) is valid
            hb(<<"good-euro">>, #{tags => #{<<226, 130, 172>> => <<240, 159, 146, 169>>}}),
            hb(<<"good-3">>, #{})],
    [queue(H) || H <- lists:sublist(Bad, 3) ++ [hd(Good)] ++ lists:nthtail(3, Bad) ++ tl(Good)],
    ?assertEqual(length(Bad), dropped(heartbeat_invalid)),
    ?assertEqual(length(Bad), dropped_total()),
    ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)),
    ?assertEqual(lists:sort([<<"good-1">>, <<"good-euro">>, <<"good-3">>]),
                 lists:sort(buffered_ids())),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)),
    ?assertEqual(lists:sort([<<"good-1">>, <<"good-euro">>, <<"good-3">>]),
                 lists:sort([maps:get(session_id, H) || R <- requests(), H <- hbs(R)])).

refused_single_chunk_is_dropped() ->
    [begin
         reset_requests(), reset_events(),
         queue(hb(<<"one">>, #{})),
         refuse_if(fun(_Req) -> true end, Status),
         ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
         ?assertEqual(1, length(requests())),
         ?assertEqual(1, dropped(chunk_rejected)),
         ?assertEqual(1, dropped_total()),
         ?assertEqual(0, session_count()),
         %% Nothing is left to retry: the next flush sends nothing.
         reset_requests(),
         ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
         ?assertEqual([], requests())
     end || Status <- [?GRPC_STATUS_RESOURCE_EXHAUSTED, ?GRPC_STATUS_INVALID_ARGUMENT]],
    ok.

%% Chunks of two 1 MiB heartbeats: [p,q1] and [q2]. The server refuses any
%% request holding p. [p,q1] is split, [p] dropped, [q1] and [q2] delivered, all
%% in one flush.
refused_chunk_is_split_and_poison_dropped() ->
    Ids = [<<"p">>, <<"q1">>, <<"q2">>],
    [queue(hb(Id, #{snap => snap(?MIB)})) || Id <- Ids],
    refuse_if(fun(Req) -> lists:any(fun(H) -> maps:get(session_id, H) =:= <<"p">> end,
                                    hbs(Req))
              end, ?GRPC_STATUS_RESOURCE_EXHAUSTED),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual([[<<"p">>, <<"q1">>], [<<"p">>], [<<"q1">>], [<<"q2">>]],
                 [[maps:get(session_id, H) || H <- hbs(R)] || R <- requests()]),
    ?assertEqual(1, dropped(chunk_rejected)),
    ?assertEqual(1, dropped_total()),
    ?assertEqual(0, session_count()),
    %% The ones the server accepted are q1 and q2, each once.
    ?assertEqual([[<<"q1">>], [<<"q2">>]],
                 [[maps:get(session_id, H) || H <- hbs(R)] || R <- requests(),
                  not lists:any(fun(H) -> maps:get(session_id, H) =:= <<"p">> end, hbs(R))]).

refusal_of_multi_requests_delivers_singles() ->
    Ids = [sid(I) || I <- lists:seq(1, 8)],
    [queue(hb(Id, #{tags => tags()})) || Id <- Ids],
    refuse_if(fun(Req) -> length(hbs(Req)) > 1 end, ?GRPC_STATUS_INVALID_ARGUMENT),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    Accepted = [maps:get(session_id, H) || R <- requests(), length(hbs(R)) =:= 1, H <- hbs(R)],
    ?assertEqual(Ids, Accepted),
    ?assertEqual(0, dropped_total()),
    ?assertEqual(0, session_count()),
    %% Halving: 1 + 2 + 4 refused requests then 8 singles, not a retry per entry
    %% of every level.
    ?assertEqual(15, length(requests())).

refusing_server_is_bounded_per_flush() ->
    [queue(hb(sid(I), #{})) || I <- lists:seq(1, 100)],
    refuse_if(fun(_Req) -> true end, ?GRPC_STATUS_INVALID_ARGUMENT),
    ?assertEqual({error, rpc_limit}, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(64, length(requests())),
    %% What the 64 RPCs got to is dropped; the rest stays for the next cycle.
    ?assert(dropped(chunk_rejected) > 0),
    ?assertEqual(100, session_count() + dropped(chunk_rejected)),
    ?assert(session_count() > 0),
    ?assert(is_process_alive(whereis(yuzu_gw_heartbeat_buffer))).

transient_failures_retain_and_stop() ->
    Failures = [
        {error, {?GRPC_STATUS_UNAVAILABLE, <<"down">>}, #{}},
        {error, {?GRPC_STATUS_DEADLINE_EXCEEDED, <<"slow">>}, #{}},
        {error, {?GRPC_STATUS_INTERNAL, <<"oops">>}, #{}},
        {error, {?GRPC_STATUS_NOT_FOUND, <<"?">>}, #{}},
        {error, econnrefused},
        {error, timeout},
        {error, {stream_down, normal}},
        {http_error, {<<"502">>, <<>>}, #{}}
    ],
    Ids = [sid(I) || I <- lists:seq(1, 4)],
    [queue(hb(Id, #{snap => snap(?MIB)})) || Id <- Ids],
    [begin
         reset_requests(),
         set_unary(fun(_N) -> F end),
         ?assertMatch({error, _}, yuzu_gw_heartbeat_buffer:flush_sync()),
         %% 1 MiB each, two per chunk: one request, the second chunk never sent.
         ?assertEqual(1, length(requests())),
         ?assertEqual(Ids, lists:sort(buffered_ids())),
         ?assertEqual(0, dropped_total())
     end || F <- Failures],
    ok.

%% grpcbox_client does not catch an exit of the HTTP/2 connection (an upstream
%% that accepts and closes made h2_connection:new_stream exit noproc), and the
%% marshal fun runs inside the call. The reason (it can hold the request) is
%% not logged: only the class.
exception_out_of_rpc_is_a_failed_flush() ->
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    Marker = <<"MARKER-heartbeat-tag-value">>,
    queue(hb(<<"a">>, #{tags => #{<<"k">> => Marker}})),
    Raisers = [
        {exit,  fun() -> exit({noproc, {gen_server, call, [h2_connection, {new_stream, Marker}]}}) end},
        {error, fun() -> error({badmatch, Marker}) end},
        {throw, fun() -> throw({Marker, thrown}) end}
    ],
    [begin
         meck:expect(grpcbox_client, unary, fun(_, _, _, _, _) -> Raise() end),
         {Result, Lines} = capture_logs(fun() -> yuzu_gw_heartbeat_buffer:flush_sync() end),
         ?assertEqual({error, {exception, Class}}, Result),
         ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)),
         ?assertEqual([<<"a">>], buffered_ids()),
         ?assertEqual([], [L || {_, L} <- Lines, binary:match(L, Marker) =/= nomatch]),
         ?assertMatch([_|_], [L || {warning, L} <- Lines,
                                   binary:match(L, <<"raised">>) =/= nomatch])
     end || {Class, Raise} <- Raisers],
    %% The buffer still works afterwards.
    set_unary(fun(_N) -> {ok, #{acknowledged_count => 1}, #{}} end),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(0, session_count()),
    ?assertEqual(0, dropped_total()).

%% Entries that screen/1 would have refused cannot be queued, so one is put in
%% the state directly: three heartbeats share one chunk, the middle one holds a
%% tag the encoder raises on. The raising mock is the real marshal fun.
encoder_raising_entries_are_dropped_from_the_chunk() ->
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    [queue(hb(Id, #{tags => tags()})) || Id <- [<<"a">>, <<"b">>, <<"c">>]],
    _ = sys:replace_state(Pid, fun(St) ->
        Buf = element(?ST_BUFFER, St),
        #{<<"b">> := E} = Buf,
        Bad = (maps:get(hb, E))#{status_tags => #{<<"k">> => <<255>>}},
        setelement(?ST_BUFFER, St, Buf#{<<"b">> := E#{hb := Bad}})
    end),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)),
    ?assertEqual(1, dropped(heartbeat_invalid)),
    ?assertEqual(1, dropped_total()),
    ?assertEqual(0, session_count()),
    ?assertEqual([<<"a">>, <<"c">>],
                 [maps:get(session_id, H) || R <- requests(), H <- hbs(R)]).

%% 60 heartbeats of 1 MiB: two to a chunk, so 30 chunks. A fast mock accepts
%% everything; what limits a cycle is the chunk count. The timer's message is
%% sent by hand (the same handle_info clause, without waiting for the interval),
%% and sys:get_state/1 is the barrier that proves the cycle has finished.
timer_flush_sends_at_most_eight_chunks() ->
    Pid = whereis(yuzu_gw_heartbeat_buffer),
    [queue(hb(sid(I), #{snap => snap(?MIB)})) || I <- lists:seq(1, 60)],
    ?assertEqual(60, session_count()),
    Cycle = fun() ->
        reset_requests(),
        Pid ! flush,
        _ = sys:get_state(Pid),
        {length(requests()), session_count()}
    end,
    ?assertEqual({8, 44}, Cycle()),
    ?assertEqual({8, 28}, Cycle()),
    ?assertEqual({8, 12}, Cycle()),
    ?assertEqual({6, 0}, Cycle()),
    ?assertEqual({0, 0}, Cycle()),
    ?assertEqual(0, dropped_total()),
    ?assertEqual(Pid, whereis(yuzu_gw_heartbeat_buffer)).

flush_sync_sends_at_most_eight_chunks() ->
    Ids = [sid(I) || I <- lists:seq(1, 60)],
    [queue(hb(Id, #{snap => snap(?MIB)})) || Id <- Ids],
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(8, length(requests())),
    ?assertEqual(44, session_count()),
    %% Oldest first: the 16 sent are the first 16 queued.
    ?assertEqual(lists:sublist(Ids, 16), [maps:get(session_id, H) || R <- requests(), H <- hbs(R)]),
    %% A buffer of 8 chunks or fewer is flushed completely (control).
    reset_requests(),
    ?assertEqual(ok, yuzu_gw_heartbeat_buffer:flush_sync()),
    ?assertEqual(8, length(requests())),
    ?assertEqual(28, session_count()).

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Every request is logged, and answered with Status when Pred(Req) holds and
%% accepted otherwise. The request is encoded with the real marshal fun first.
refuse_if(Pred, Status) ->
    meck:expect(grpcbox_client, unary, fun(_Ctx, _Path, Req, Def, _Opts) ->
        Size = iolist_size((Def#grpcbox_def.marshal_fun)(Req)),
        rec({request, Req, Size}),
        case Pred(Req) of
            true  -> {error, {Status, <<"refused">>}, #{}};
            false -> {ok, #{acknowledged_count => length(hbs(Req))}, #{}}
        end
    end).

%% The BatchHeartbeat mock answers RESOURCE_EXHAUSTED to a request over the
%% server's receive limit (measured with the real marshal fun) and accepts the
%% rest. The request is logged either way.
refuse_over_limit() ->
    Counter = counters:new(1, []),
    meck:expect(grpcbox_client, unary, fun(_Ctx, _Path, Req, Def, _Opts) ->
        counters:add(Counter, 1, 1),
        Size = iolist_size((Def#grpcbox_def.marshal_fun)(Req)),
        rec({request, Req, Size}),
        case Size > ?SERVER_LIMIT of
            true  -> {error, {?GRPC_STATUS_RESOURCE_EXHAUSTED, <<"too big">>}, #{}};
            false -> {ok, #{acknowledged_count => length(maps:get(heartbeats, Req))}, #{}}
        end
    end).

sid(I) -> iolist_to_binary(["session-", integer_to_list(I)]).

snap(N) -> binary:copy(<<"s">>, N).

tags() -> #{<<"yuzu.os">> => <<"linux">>, <<"yuzu.healthy">> => <<"1">>}.

%% A heartbeat map. Absent options are absent keys (maps_unset_optional).
hb(Sid, Opts) ->
    H0 = #{session_id => Sid},
    H1 = case maps:find(sent_at, Opts) of
             {ok, T} -> H0#{sent_at => #{millis_epoch => T}};
             error   -> H0
         end,
    H2 = case maps:find(tags, Opts) of
             {ok, Tags} -> H1#{status_tags => Tags};
             error      -> H1
         end,
    case maps:find(snap, Opts) of
        {ok, S} -> H2#{fleet_snapshot_json => S};
        error   -> H2
    end.

random_hb(I) ->
    Opts0 = #{sent_at => rand:uniform(1000)},
    Opts1 = case rand:uniform(3) of
                1 -> Opts0#{snap => snap(rand:uniform(900 * 1024))};
                2 -> Opts0#{snap => snap(rand:uniform(4 * ?MIB))};
                _ -> Opts0
            end,
    Opts2 = case rand:uniform(4) of
                1 -> Opts1#{tags => #{<<"big">> => snap(rand:uniform(200 * 1024))}};
                _ -> Opts1
            end,
    hb(sid(I), Opts2).

encoded_size(Batch) ->
    iolist_size(gateway_pb:encode_msg(Batch, 'yuzu.gateway.v1.BatchHeartbeatRequest')).

%% Queue one heartbeat and wait until the buffer has handled it.
queue(Hb) ->
    yuzu_gw_heartbeat_buffer:queue_heartbeat(Hb),
    _ = sys:get_state(whereis(yuzu_gw_heartbeat_buffer)),
    ok.

start_buffer() ->
    {ok, Pid} = yuzu_gw_heartbeat_buffer:start_link(),
    unlink(Pid),
    ok.

stop_buffer() ->
    case whereis(yuzu_gw_heartbeat_buffer) of
        undefined -> ok;
        Pid -> catch unlink(Pid), catch gen_server:stop(Pid, normal, 2000), ok
    end.

restart_buffer(MaxSessions, MaxBytes) ->
    stop_buffer(),
    application:set_env(yuzu_gw, max_heartbeat_buffer, MaxSessions),
    application:set_env(yuzu_gw, max_heartbeat_buffer_bytes, MaxBytes),
    start_buffer().

stop_upstream() ->
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Up -> catch unlink(Up), catch gen_server:stop(Up, shutdown, 1000), ok
    end.

buf_state() -> sys:get_state(whereis(yuzu_gw_heartbeat_buffer)).

buffer_map() -> element(?ST_BUFFER, buf_state()).
session_count() -> map_size(buffer_map()).
buffered_bytes() -> element(?ST_BUF_BYTES, buf_state()).
snap_idx() -> element(?ST_SNAP_IDX, buf_state()).
buffered_ids() -> maps:keys(buffer_map()).

check_bookkeeping() ->
    St = buf_state(),
    ?assertEqual(11, tuple_size(St)),
    Buf = element(?ST_BUFFER, St),
    Entries = maps:values(Buf),
    ?assertEqual(lists:sum([B || #{bytes := B} <- Entries]), element(?ST_BUF_BYTES, St)),
    [?assertEqual(yuzu_gw_heartbeat_buffer:estimate_bytes(Hb), B)
     || #{hb := Hb, bytes := B} <- Entries],
    Holders = lists:sort([{Seq, Sid} || Sid := #{seq := Seq, hb := Hb} <- Buf,
                                        maps:get(fleet_snapshot_json, Hb, <<>>) =/= <<>>]),
    ?assertEqual(Holders, gb_trees:to_list(element(?ST_SNAP_IDX, St))),
    %% Seqs are unique.
    Seqs = [S || #{seq := S} <- Entries],
    ?assertEqual(length(Seqs), length(lists:usort(Seqs))).

%% Make the BatchHeartbeat rpc answer by call number (1 for the first call
%% since the last set_unary/1). Every request is logged with its encoded size,
%% measured with the Def the buffer passed (the real marshal fun).
set_unary(Fun) ->
    Counter = counters:new(1, []),
    meck:expect(grpcbox_client, unary, fun(_Ctx, _Path, Req, Def, _Opts) ->
        counters:add(Counter, 1, 1),
        N = counters:get(Counter, 1),
        Size = iolist_size((Def#grpcbox_def.marshal_fun)(Req)),
        rec({request, Req, Size}),
        Fun(N)
    end).

rec(Entry) ->
    case persistent_term:get(?LOGK, undefined) of
        undefined -> ok;
        Tid ->
            Key = erlang:unique_integer([monotonic]),
            try ets:insert(Tid, {Key, Entry}) catch error:badarg -> ok end,
            ok
    end.

entries() ->
    [E || {_, E} <- ets:tab2list(persistent_term:get(?LOGK))].

requests() -> [Req || {request, Req, _} <- entries()].
request_sizes() -> [Size || {request, _, Size} <- entries()].
hbs(Req) -> maps:get(heartbeats, Req).
casts() -> [Ids || {cast, Ids} <- entries()].

reset_requests() ->
    [ets:delete(persistent_term:get(?LOGK), K)
     || {K, {request, _, _}} <- ets:tab2list(persistent_term:get(?LOGK))],
    ok.

reset_events() ->
    [ets:delete(persistent_term:get(?LOGK), K)
     || {K, {event, _, _, _}} <- ets:tab2list(persistent_term:get(?LOGK))],
    ok.

event_count(Name) ->
    lists:sum([maps:get(count, M, 0) || {event, N, M, _} <- entries(), N =:= Name]).

%% Sum of the buffer_dropped counts with this reason.
dropped(Reason) ->
    lists:sum([maps:get(count, M, 0)
               || {event, ?EV_DROPPED, M, #{reason := R}} <- entries(), R =:= Reason]).

dropped_total() ->
    event_count(?EV_DROPPED).

%% Run Fun with a capturing logger handler at info level; returns
%% {FunResult, [{Level, Text}]}. The handler is VM-wide: callers filter.
capture_logs(Fun) ->
    Prev = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, info),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE,
                            #{config => #{pid => self()}, level => info}),
    try
        Result = Fun(),
        {Result, collect_logs([])}
    after
        logger:remove_handler(?LOG_HANDLER),
        logger:set_primary_config(level, Prev)
    end.

collect_logs(Acc) ->
    receive {captured_log, Level, Text} -> collect_logs([{Level, Text} | Acc])
    after 0 -> lists:reverse(Acc)
    end.

%% logger handler callback
log(#{level := Level, msg := Msg}, #{config := #{pid := Pid}}) ->
    Text = case Msg of
        {string, S} -> unicode:characters_to_binary(S);
        {report, R} -> unicode:characters_to_binary(io_lib:format("~p", [R]));
        {Fmt, Args} -> unicode:characters_to_binary(io_lib:format(Fmt, Args))
    end,
    Pid ! {captured_log, Level, Text},
    ok.
