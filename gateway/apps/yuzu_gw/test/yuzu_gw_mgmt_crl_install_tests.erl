%%% @doc The load path of yuzu_gw_mgmt_crl_source as one unit, pinned where the earlier tests drove the
%%% pieces: the stale-CRL rule through install, the replay mark across ticks, what counts as a
%%% successful read (last_success), and the CA read that must neither stack nor stall the VM's file
%%% server. #6016 PR 4b (found by mutation: each case here kills a mutant the first tests let live).
-module(yuzu_gw_mgmt_crl_install_tests).
-include_lib("eunit/include/eunit.hrl").
-export([handle_event/4]).
-define(THIS, 1793628888).
-define(NOW, (?THIS + 600)).
-define(SRC, yuzu_gw_mgmt_crl_source).

root_pem() -> yuzu_gw_crl_fixture:path("root-ca.pem").
pol(Grace) -> #{source => {file, "unused"}, grace_s => Grace, refresh_ms => 100000,
                verify_cacertfiles => [root_pem()]}.
st() -> #{crl => none, crl_hash => undefined, ca_hash => undefined, etag => undefined, last_reject => undefined}.
handle_event(E, M, Meta, Pid) -> Pid ! {telemetry, E, M, Meta}, ok.
crl(N, T, X) -> #{number => N, this_update => T, next_update => X, issuer => <<>>, revoked => #{}}.
fl() -> receive _ -> fl() after 0 -> ok end.
ld(P, S, Bin, Now) -> ?SRC:load(P, S, fun(_, _) -> {ok, Bin, undefined} end, Now).
evs() -> receive {telemetry, _, _, _} = M -> [M | evs()] after 0 -> [] end.

with_events(Evs, F) ->
    ?SRC:reset(), {ok, _} = application:ensure_all_started(telemetry), fl(),
    Id = {?MODULE, make_ref()},
    [ok = telemetry:attach({Id, E}, [yuzu, gw, mgmt_crl, E], fun ?MODULE:handle_event/4, self()) || E <- Evs],
    try F() after [telemetry:detach({Id, E}) || E <- Evs], ?SRC:reset(), fl() end.

boundary_test_() ->
    Grace = 100,
    R = fun(L, N, Now) -> ?SRC:replace_rule(L, N, Now, Grace) end,
    Held = crl(5, 1000, 5050),
    [{"inside grace is not stale (replace by ordinary rule)", ?_assertMatch({replace, _}, R(Held, crl(6, 1500, 3000), 3000 + Grace))},
     {"one past grace is stale", ?_assertEqual({reject, replay}, R(Held, crl(6, 1500, 3000), 3000 + Grace + 1))},
     {"past nextUpdate but inside grace", ?_assertMatch({replace, _}, R(Held, crl(6, 1500, 3000), 3050))}].

install_path_uses_stale_rule_test() ->
    with_events([rejected], fun() ->
        Bin = yuzu_gw_crl_fixture:read("crl-populated.der"),
        {ok, #{next_update := Next}} = yuzu_gw_mgmt_crl:parse(Bin, yuzu_gw_mgmt_crl:ca_certs(element(2, file:read_file(root_pem()))), ?NOW),
        Held = crl(1, 1, Next + 10000000),
        S = (st())#{crl := Held},
        %% stale New (past nextUpdate+grace 86400) vs believed held -> replay
        _ = ld(pol(86400), S, Bin, Next + 86400 + 1),
        ?assertMatch([{telemetry, _, _, #{reason := replay}}], evs()),
        ?assertEqual(none, ?SRC:current()),
        %% inside grace: installed
        _ = ld(pol(86400), S, Bin, Next + 100),
        ?assertEqual([], evs()),
        ?assertMatch(#{number := 7}, ?SRC:current())
    end).

tick_state_keeps_the_mark_test() ->
    with_events([rejected], fun() ->
        Sub = yuzu_gw_crl_fixture:read("crl-sub.der"),
        Pop = yuzu_gw_crl_fixture:read("crl-populated.der"),
        P = pol(86400),
        S1 = ld(P, st(), Sub, ?NOW),
        ?assertMatch(#{number := 9}, ?SRC:current()),
        S2 = ld(P, S1, Pop, ?NOW),           %% 7 < 9: replay
        S3 = ld(P, S2, Pop, ?NOW),           %% still replay
        ?assertMatch(#{number := 9}, ?SRC:current()),
        S4 = ld(P, S3, Sub, ?NOW),           %% hash skip
        _ = ld(P, S4, Pop, ?NOW),
        ?assertMatch(#{number := 9}, ?SRC:current()),
        Rs = [R || {telemetry, _, _, #{reason := R}} <- evs()],
        ?assertEqual([replay, replay, replay], Rs)
    end).

last_success_test() ->
    with_events([state], fun() ->
        Pop = yuzu_gw_crl_fixture:read("crl-populated.der"),
        P = pol(86400),
        S1 = ld(P, st(), Pop, ?NOW),
        [{telemetry, _, M1, _}] = evs(),
        T = os:system_time(second),
        ?assert(abs(maps:get(last_success, M1) - T) < 5),
        _ = ld(P, S1, Pop, ?NOW),        %% unchanged bytes (hash skip)
        [{telemetry, _, M2, _}] = evs(),
        ?assert(maps:is_key(last_success, M2)),
        _ = ?SRC:load(P, S1, fun(_, _) -> not_modified end, ?NOW),
        [{telemetry, _, M3, _}] = evs(),
        ?assert(maps:is_key(last_success, M3))
    end).

catch_path_not_success_test() ->
    with_events([state], fun() ->
        ok = ?SRC:publish_policy(#{source => {file, "x"}, refresh_ms => 100000}),
        {ok, Pid} = gen_server:start(?SRC, [], []),
        unlink(Pid),
        {telemetry, _, M, _} = receive {telemetry, _, _, _} = T -> T after 2000 -> timeout end,
        gen_server:stop(Pid),
        ?assertNot(maps:is_key(last_success, M))
    end).

invalid_utf8_url_test() ->
    {error, {bad_mgmt_crl_url, Shown}} = ?SRC:parse_url(<<255, "//u:SECRET@h">>),
    ?assertEqual(nomatch, binary:match(iolist_to_binary(io_lib:format("~tp", [Shown])), <<"SECRET">>)).

tmp_dir() ->
    Dir = filename:join("/tmp", "yuzu_test_crli_" ++ binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(6)))),
    ok = filelib:ensure_dir(filename:join(Dir, "x")), Dir.
fifo(Dir) ->
    Path = filename:join(Dir, "fifo"),
    case os:cmd("mkfifo '" ++ Path ++ "' 2>&1 && echo made") of
        "made\n" -> {ok, Path};
        _ -> no_mkfifo
    end.
release(F) -> _ = os:cmd("echo > '" ++ F ++ "'"), ok.

ca_blocked_not_stacked_and_file_server_alive_test_() ->
    {timeout, 40, fun() ->
        with_events([rejected], fun() ->
            Dir = tmp_dir(),
            try
                case fifo(Dir) of
                    no_mkfifo -> ok;
                    {ok, Fifo} -> ca_blocked_case(Fifo)
                end
            after
                release_all(Dir), timer:sleep(300),
                os:cmd("rm -rf '" ++ Dir ++ "'")
            end
        end)
    end}.

ca_blocked_case(Fifo) ->
    Pop = yuzu_gw_crl_fixture:read("crl-populated.der"),
    P = (pol(86400))#{verify_cacertfiles => [Fifo]},
    _ = ld(P, st(), Pop, ?NOW),
    ?assertMatch([{telemetry, _, _, #{reason := file_unreadable}}], evs()),
    %% the VM file server still answers while the CA reader is stuck
    Me = self(),
    spawn(fun() -> Me ! {fs, file:read_file(root_pem())} end),
    ?assertMatch({fs, {ok, _}}, receive {fs, _} = X -> X after 1000 -> fs_stalled end),
    %% a second attempt does not start another reader: immediate
    T0 = erlang:monotonic_time(millisecond),
    _ = ld(P, st(), Pop, ?NOW),
    ?assert(erlang:monotonic_time(millisecond) - T0 < 500),
    ?assertMatch([{telemetry, _, _, #{reason := file_unreadable}}], evs()).

%% In `after': give any blocked reader of the test directory's FIFO a writer, even when an
%% assertion failed first.
release_all(Dir) ->
    Path = filename:join(Dir, "fifo"),
    case filelib:is_file(Path) of
        true  -> release(Path);
        false -> ok
    end.

%%--------------------------------------------------------------------
%% The gauges exist from startup (an unseeded gauge renders no series, so an alert on it
%% would have nothing to read before the first state event)
%%--------------------------------------------------------------------

crl_gauges_have_a_series_from_startup_test() ->
    {ok, _} = application:ensure_all_started(prometheus),
    {ok, _} = application:ensure_all_started(telemetry),
    catch telemetry:detach(yuzu_gw_prometheus),
    try
        ok = yuzu_gw_telemetry:setup(),
        Out = prometheus_text_format:format(),
        [?assertNotEqual(nomatch, binary:match(Out, iolist_to_binary([G, " "])))
         || G <- ["yuzu_gw_mgmt_crl_enforced", "yuzu_gw_mgmt_crl_loaded", "yuzu_gw_mgmt_crl_number",
                  "yuzu_gw_mgmt_crl_next_update_timestamp_seconds",
                  "yuzu_gw_mgmt_crl_last_success_timestamp_seconds",
                  "yuzu_gw_mgmt_crl_revoked_entries"]]
    after
        catch telemetry:detach(yuzu_gw_prometheus)
    end.
