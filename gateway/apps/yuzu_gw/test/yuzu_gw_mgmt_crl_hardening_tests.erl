%%% @doc CRL parser and watcher hardening (#7070 items 4 and 6, #7067): the bound on a CRL's own
%%% validity, the closed-set reasons `unsupported' and `validity_too_long', the refresh jitter, the
%%% near-the-size-bound warning, and the memory of rejected bytes.
%%%
%%% The memory is the part that can silence an alert, so what it must NOT do is pinned as hard as what
%%% it must: `future_dated' and `replay' are decided again every tick (a replay verdict depends on the
%%% CRL held and on its staleness, ADR 2004 A8), and a remembered refusal reports the same gauges as a
%%% fresh one, so `last_success' does not advance and RefreshStalled / NotLoaded still see it.
%%%
%%% Parses are counted with OTP's call_count trace on yuzu_gw_mgmt_crl:parse/4, which needs no mock
%%% and no timing. The CRLs are built in memory (yuzu_gw_crl_build) or are the C++ server's own
%%% fixtures (fixtures/crl/README.md).
-module(yuzu_gw_mgmt_crl_hardening_tests).

-include_lib("eunit/include/eunit.hrl").

-define(THIS, 1793628888).
-define(NOW, (?THIS + 600)).
%% The default builder CRL: 2026-11-02T14:14:48Z to 2026-11-04T14:19:48Z.
-define(WIDTH, 173100).

-export([handle_event/4, log/2]).

root_pem() -> yuzu_gw_crl_fixture:path("root-ca.pem").
crl(N) -> yuzu_gw_crl_fixture:read(N).

policy() -> policy([root_pem()]).
policy(VerifyFiles) ->
    #{source => {file, "unused"}, grace_s => 86400, refresh_ms => 5000,
      verify_cacertfiles => VerifyFiles}.

state() ->
    #{crl => none, crl_hash => undefined, ca_hash => undefined, etag => undefined,
      last_reject => undefined, rejected => none, size_warned_at => undefined}.

fetch_of(Bin) -> fun(_Policy, _State) -> {ok, Bin, undefined} end.

%%--------------------------------------------------------------------
%% The bound on a CRL's own validity (#7070 item 4)
%%--------------------------------------------------------------------

ca() -> yuzu_gw_crl_build:ca("Yuzu Install CA (test-host)").

parse(Crl, Ca, Now, Opts) -> yuzu_gw_mgmt_crl:parse(Crl, [maps:get(cert, Ca)], Now, Opts).

validity_bound_test_() ->
    Ca = ca(),
    Crl = yuzu_gw_crl_build:crl(Ca, #{number => 3}),
    [{"unset: no bound, whatever the width",
      ?_assertMatch({ok, _}, parse(Crl, Ca, ?NOW, #{}))},
     {"a width equal to the bound is accepted, one second more is not",
      fun() ->
          ?assertMatch({ok, _}, parse(Crl, Ca, ?NOW, #{max_validity_s => ?WIDTH})),
          ?assertEqual({error, validity_too_long},
                       parse(Crl, Ca, ?NOW, #{max_validity_s => ?WIDTH - 1}))
      end},
     {"the width is never measured against the clock: the same answer at any Now",
      fun() ->
          [?assertEqual({error, validity_too_long},
                        parse(Crl, Ca, Now, #{max_validity_s => 3600}))
           || Now <- [0, ?THIS - 10 * 365 * 86400, ?THIS, ?NOW, ?THIS + ?WIDTH + 86400 * 365]]
      end},
     {"a far-future nextUpdate (the case the alert cannot see) is refused",
      fun() ->
          Far = yuzu_gw_crl_build:crl(Ca, #{number => 3, next => {generalTime, "20990101000000Z"}}),
          ?assertMatch({ok, _}, parse(Far, Ca, ?NOW, #{})),
          ?assertEqual({error, validity_too_long},
                       parse(Far, Ca, ?NOW, #{max_validity_s => 691200}))
      end},
     {"the exact width is the same in generalizedTime and in a mixed utc/generalized pair",
      fun() ->
          G = yuzu_gw_crl_build:crl(Ca, #{number => 3, this => {generalTime, "20261102141448Z"},
                                         next => {generalTime, "20261104141948Z"}}),
          Mixed = yuzu_gw_crl_build:crl(Ca, #{number => 3, this => "261102141448Z",
                                             next => {generalTime, "20261104141948Z"}}),
          Mixed2 = yuzu_gw_crl_build:crl(Ca, #{number => 3, this => {generalTime, "20261102141448Z"},
                                              next => "261104141948Z"}),
          [begin
               ?assertMatch({ok, #{this_update := ?THIS, next_update := N}}
                              when N =:= ?THIS + ?WIDTH,
                            parse(C, Ca, ?NOW, #{max_validity_s => ?WIDTH})),
               ?assertEqual({error, validity_too_long},
                            parse(C, Ca, ?NOW, #{max_validity_s => ?WIDTH - 1}))
           end || C <- [G, Mixed, Mixed2]]
      end},
     {"the shipped 8 days admits both a 48 h CRL and the 7 days an older server publishes",
      fun() ->
          Week = yuzu_gw_crl_build:crl(Ca, #{number => 3, next => "261109141448Z"}),   %% 7 days exactly
          WeekPlus = yuzu_gw_crl_build:crl(Ca, #{number => 3, next => "261109141948Z"}), %% 7 d + 300 s
          Opts = #{max_validity_s => 691200},
          ?assertMatch({ok, _}, parse(Crl, Ca, ?NOW, Opts)),
          ?assertMatch({ok, _}, parse(Week, Ca, ?NOW, Opts)),
          ?assertMatch({ok, _}, parse(WeekPlus, Ca, ?NOW, Opts))
      end},
     {"the bound is checked only after the signature: an unsigned wide CRL is `unverified'",
      fun() ->
          Other = ca(),
          ?assertEqual({error, unverified},
                       yuzu_gw_mgmt_crl:parse(Crl, [maps:get(cert, Other)], ?NOW,
                                              #{max_validity_s => 3600}))
      end},
     {"too wide and future dated: the width is the reason (a property of the CRL, not the clock)",
      ?_assertEqual({error, validity_too_long},
                    parse(Crl, Ca, ?THIS - 7200, #{max_validity_s => 3600}))},
     {"parse/3 is parse/4 with no options",
      ?_assertEqual(parse(Crl, Ca, ?NOW, #{}), yuzu_gw_mgmt_crl:parse(Crl, [maps:get(cert, Ca)], ?NOW))}].

%%--------------------------------------------------------------------
%% The two new reasons, against the ones that stay `malformed' (#7070 item 6)
%%--------------------------------------------------------------------

reasons_split_test_() ->
    Ca = ca(),
    P = fun(Opts) -> parse(yuzu_gw_crl_build:crl(Ca, Opts), Ca, ?NOW, #{}) end,
    Delta = yuzu_gw_crl_build:ext({2, 5, 29, 27}, true, public_key:der_encode('CRLNumber', 1)),
    [{"a well-formed delta is `unsupported', not `malformed'",
      ?_assertEqual({error, unsupported}, P(#{exts => [Delta]}))},
     {"a missing cRLNumber stays `malformed'",
      ?_assertEqual({error, malformed}, P(#{number => none}))},
     {"garbage and a truncated CRL stay `malformed'",
      fun() ->
          Good = yuzu_gw_crl_build:crl(Ca, #{}),
          ?assertEqual({error, malformed},
                       yuzu_gw_mgmt_crl:parse(<<"garbage">>, [maps:get(cert, Ca)], ?NOW)),
          ?assertEqual({error, malformed},
                       yuzu_gw_mgmt_crl:parse(binary:part(Good, 0, byte_size(Good) - 20),
                                              [maps:get(cert, Ca)], ?NOW))
      end}].

%%--------------------------------------------------------------------
%% Configuration: mgmt_crl_max_validity_s
%%--------------------------------------------------------------------

resolve_max_validity_test_() ->
    Listeners = [#{name => mgmt, service_protos => [management_pb],
                   tls => #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => root_pem()}}],
    R = fun(Source, MaxValidity) ->
                yuzu_gw_mgmt_crl_source:resolve(Source, undefined, undefined, Listeners, MaxValidity)
        end,
    [{"unset: the key is absent from the policy (no bound, no behaviour change)",
      fun() ->
          {ok, P} = R({file, "/x"}, undefined),
          ?assertNot(maps:is_key(max_validity_s, P))
      end},
     {"the bounds are inclusive",
      [?_assertMatch({ok, #{max_validity_s := V}}, R({file, "/x"}, V)) || V <- [3600, 691200, 31536000]]},
     {"out of range, wrong type: a defect",
      [?_assertMatch({error, [{bad_mgmt_crl_max_validity_s, V, _}]}, R({file, "/x"}, V))
       || V <- [0, -1, 3599, 31536001, "691200", 1.5, 7200.0, 691200.0, infinity, <<"1">>]]},
     {"a typo is a defect even with no source",
      ?_assertMatch({error, [{bad_mgmt_crl_max_validity_s, 5, _}]}, R(undefined, 5))},
     {"reported together with the other defects",
      ?_assertMatch({error, [{bad_mgmt_crl_url, _}, {bad_mgmt_crl_max_validity_s, 1, _}]},
                    R({url, "http://x/"}, 1))},
     {"resolve/4 is resolve/5 with the key unset",
      ?_assertEqual(yuzu_gw_mgmt_crl_source:resolve({file, "/x"}, 7, 2000, []),
                    yuzu_gw_mgmt_crl_source:resolve({file, "/x"}, 7, 2000, [], undefined))}].

%%--------------------------------------------------------------------
%% Refresh jitter (#7067 item 2): DOWN only, up to 10 percent
%%--------------------------------------------------------------------

jitter_bounds_test_() ->
    J = fun yuzu_gw_mgmt_crl_source:jittered_ms/2,
    [{"the largest share is a tenth",
      ?_assertEqual(0.1, yuzu_gw_mgmt_crl_source:max_jitter_fraction())},
     {"no jitter drawn waits the whole interval; the longest draw waits just over 90 percent",
      fun() ->
          ?assertEqual(5000, J(5000, 0.0)),
          ?assert(J(5000, 0.9999999) > 4500),
          ?assert(J(5000, 0.9999999) =< 4501)
      end},
     {"a draw of one half takes half of the largest share",
      ?_assertEqual(4750, J(5000, 0.5))},
     {"never longer than the interval and never 10 percent or more shorter, at every draw",
      fun() ->
          [begin
               Ms = J(I, R / 1000),
               ?assert(Ms =< I),
               ?assert(Ms > I * 9 div 10)
           end || I <- [1000, 1001, 5000, 86400, 3600000], R <- lists:seq(0, 999)]
      end},
     {"the shortest legal interval stays positive",
      ?_assert(J(1000, 0.9999999) >= 900)}].

%% The watcher really waits what jittered_ms gives: every send_after the process makes carries a
%% delay in (0.9 * interval, interval], and the delays are not all equal.
watcher_waits_are_jittered_test_() ->
    {timeout, 60, fun watcher_waits/0}.

watcher_waits() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_mgmt_crl_source:reset(),
    ok = yuzu_gw_mgmt_crl_source:publish_policy(
           (policy())#{source => {file, "/no/such/yuzu_test_crl.der"}, refresh_ms => 1000}),
    {ok, Pid} = yuzu_gw_mgmt_crl_source:start_link(),
    unlink(Pid),
    try
        1 = erlang:trace_pattern({erlang, send_after, 3}, true, [global]),
        1 = erlang:trace(Pid, true, [call]),
        [begin Pid ! refresh, _ = sys:get_state(Pid) end || _ <- lists:seq(1, 40)],
        Ref = erlang:trace_delivered(Pid),
        receive {trace_delivered, Pid, Ref} -> ok after 5000 -> error(trace_not_delivered) end,
        erlang:trace(Pid, false, [call]),
        Delays = collect_delays([]),
        ?assert(length(Delays) >= 40),
        [begin ?assert(D =< 1000), ?assert(D > 900) end || D <- Delays],
        ?assert(length(lists:usort(Delays)) > 1)
    after
        erlang:trace_pattern({erlang, send_after, 3}, false, [global]),
        gen_server:stop(Pid),
        yuzu_gw_mgmt_crl_source:reset()
    end.

collect_delays(Acc) ->
    receive
        {trace, _, call, {erlang, send_after, [Ms, _, refresh]}} -> collect_delays([Ms | Acc]);
        {trace, _, call, _} -> collect_delays(Acc)
    after 0 -> Acc
    end.

%%--------------------------------------------------------------------
%% The near-the-size-bound warning (#7067 item 3)
%%--------------------------------------------------------------------

log(#{level := Level, msg := Msg}, #{config := #{test := Pid}}) ->
    Pid ! {log, Level, lists:flatten(case Msg of
                                         {string, S} -> io_lib:format("~ts", [S]);
                                         {F, A} -> io_lib:format(F, A);
                                         _ -> ""
                                     end)},
    ok.

with_log(Fun) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_mgmt_crl_source:reset(),
    Handler = yuzu_test_crl_hardening_log,
    catch logger:remove_handler(Handler),
    ok = logger:add_handler(Handler, ?MODULE, #{level => all, config => #{test => self()}}),
    flush_logs(),
    try Fun()
    after
        logger:remove_handler(Handler),
        yuzu_gw_mgmt_crl_source:reset()
    end.

%% eunit runs the tests of a module in one process: lines an earlier test left unread are not ours.
flush_logs() ->
    receive {log, _, _} -> flush_logs() after 50 -> ok end.

size_warnings() ->
    receive
        {log, warning, Text} ->
            case string:find(Text, "bound; past it") of
                nomatch -> size_warnings();
                _ -> [Text | size_warnings()]
            end;
        {log, _, _} -> size_warnings()
    after 200 -> []
    end.

size_warning_test_() ->
    Warn = yuzu_gw_mgmt_crl:warn_bytes(),
    Max = yuzu_gw_mgmt_crl:max_bytes(),
    Body = fun(Size) -> binary:copy(<<0>>, Size) end,
    Load = fun(Bin, State, Now) ->
                   yuzu_gw_mgmt_crl_source:load(policy(), State, fetch_of(Bin), Now)
           end,
    [{"the threshold is three quarters of the bound",
      ?_assertEqual(Max * 3 div 4, Warn)},
     {"a body at the threshold is silent, one byte over warns",
      fun() -> with_log(fun() ->
          S1 = Load(Body(Warn), state(), ?NOW),
          ?assertEqual([], size_warnings()),
          ?assertMatch(#{size_warned_at := undefined}, S1),
          S2 = Load(Body(Warn + 1), state(), ?NOW),
          [Text] = size_warnings(),
          ?assertNotEqual(nomatch, string:find(Text, integer_to_list(Warn + 1))),
          ?assertNotEqual(nomatch, string:find(Text, "75.0%")),
          ?assertMatch(#{size_warned_at := ?NOW}, S2)
      end) end},
     {"rate-limited: once per hour, then again",
      fun() -> with_log(fun() ->
          Bin = Body(Warn + 1),
          S1 = Load(Bin, state(), ?NOW),
          S2 = Load(Bin, S1, ?NOW + 5),
          S3 = Load(Bin, S2, ?NOW + 3599),
          ?assertEqual(1, length(size_warnings())),
          S4 = Load(Bin, S3, ?NOW + 3600),
          ?assertEqual(1, length(size_warnings())),
          ?assertMatch(#{size_warned_at := _}, S4),
          ?assertEqual(?NOW + 3600, maps:get(size_warned_at, S4))
      end) end},
     {"a clock stepped back past the last warning does not silence it for the next hour",
      fun() -> with_log(fun() ->
          Bin = Body(Warn + 1),
          S1 = Load(Bin, state(), ?NOW),
          _ = Load(Bin, S1, ?NOW - 1),
          ?assertEqual(2, length(size_warnings()))
      end) end},
     {"a body near the bound is still judged as a CRL (the warning is not a refusal)",
      fun() -> with_log(fun() ->
          S = Load(Body(Warn + 1), state(), ?NOW),
          ?assertMatch(#{last_reject := malformed}, S),
          _ = size_warnings()
      end) end},
     {"a real CRL is far below it and warns nothing",
      fun() -> with_log(fun() ->
          _ = Load(crl("crl-populated.der"), state(), ?NOW),
          ?assertEqual([], size_warnings())
      end) end}].

%%--------------------------------------------------------------------
%% Rejected bytes are remembered (#7067 item 4)
%%--------------------------------------------------------------------

handle_event(Event, Measurements, Meta, Pid) ->
    Pid ! {telemetry, Event, Measurements, Meta},
    ok.

with_memo(Fun) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_mgmt_crl_source:reset(),
    _ = code:ensure_loaded(yuzu_gw_mgmt_crl),
    Mfa = {yuzu_gw_mgmt_crl, parse, 4},
    erlang:trace_pattern(Mfa, false, [call_count]),
    erlang:trace_pattern(Mfa, true, [call_count]),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach_many(Id, [[yuzu, gw, mgmt_crl, rejected], [yuzu, gw, mgmt_crl, state]],
                               fun ?MODULE:handle_event/4, self()),
    flush(),
    try Fun()
    after
        telemetry:detach(Id),
        erlang:trace_pattern(Mfa, false, [call_count]),
        yuzu_gw_mgmt_crl_source:reset()
    end.

flush() ->
    receive {telemetry, _, _, _} -> flush() after 0 -> ok end.

parses() ->
    {call_count, N} = erlang:trace_info({yuzu_gw_mgmt_crl, parse, 4}, call_count),
    N.

%% {Rejections, StateMeasurements} since the last call.
drain() -> drain([], []).
drain(Rs, Ss) ->
    receive
        {telemetry, [yuzu, gw, mgmt_crl, rejected], _, #{reason := R}} -> drain([R | Rs], Ss);
        {telemetry, [yuzu, gw, mgmt_crl, state], M, _} -> drain(Rs, [M | Ss])
    after 0 -> {lists:reverse(Rs), lists:reverse(Ss)}
    end.

%% A CA certificate written as a PEM file, for a policy to verify against.
with_ca_file(Ca, Fun) ->
    Dir = filename:join("/tmp", "yuzu_test_crlh_" ++
                        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(6)))),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Pem = filename:join(Dir, "ca.pem"),
    ok = file:write_file(Pem, public_key:pem_encode([{'Certificate', maps:get(cert, Ca),
                                                     not_encrypted}])),
    try Fun(Pem)
    after os:cmd("rm -rf '" ++ Dir ++ "'")
    end.

%% The six reasons the bytes and the verification certificates alone decide: each is produced by a
%% real input, loaded twice under the same certificates.
memoised_reasons_test_() ->
    [{atom_to_list(Reason) ++ ": the same bytes are parsed once and counted once",
      fun() -> with_memo(fun() -> memoised(Reason) end) end}
     || Reason <- [malformed, unsupported, too_large, unverified, issuer_mismatch,
                   validity_too_long]].

%% {Policy, Bytes, Now} for an input the watcher must refuse as `Reason'.
case_for(malformed) ->
    {policy(), <<"garbage">>, ?NOW};
case_for(too_large) ->
    {policy(), binary:copy(<<0>>, yuzu_gw_mgmt_crl:max_bytes() + 1), ?NOW};
case_for(unverified) ->
    {policy(), crl("crl-evil.der"), ?NOW};
case_for(issuer_mismatch) ->
    {policy([yuzu_gw_crl_fixture:path("renamed-ca.pem")]), crl("crl-populated.der"), ?NOW};
case_for(validity_too_long) ->
    {(policy())#{max_validity_s => 3600}, crl("crl-populated.der"), ?NOW}.

memoised(unsupported) ->
    Ca = ca(),
    Delta = yuzu_gw_crl_build:ext({2, 5, 29, 27}, true, public_key:der_encode('CRLNumber', 1)),
    Bin = yuzu_gw_crl_build:crl(Ca, #{exts => [Delta]}),
    with_ca_file(Ca, fun(Pem) -> memoised(unsupported, policy([Pem]), Bin, ?NOW) end);
memoised(Reason) ->
    {Policy, Bin, Now} = case_for(Reason),
    memoised(Reason, Policy, Bin, Now).

memoised(Reason, Policy, Bin, Now) ->
    ok = yuzu_gw_mgmt_crl_source:publish_policy(Policy),
    S1 = yuzu_gw_mgmt_crl_source:load(Policy, state(), fetch_of(Bin), Now),
    ?assertEqual(1, parses()),
    {R1, [St1]} = drain(),
    ?assertEqual([Reason], R1),
    S2 = yuzu_gw_mgmt_crl_source:load(Policy, S1, fetch_of(Bin), Now + 5),
    S3 = yuzu_gw_mgmt_crl_source:load(Policy, S2, fetch_of(Bin), Now + 10),
    ?assertEqual(1, parses()),
    %% counted once: not per tick
    {R2, [St2, St3]} = drain(),
    ?assertEqual([], R2),
    %% reported every tick, as a refusal is: the state the alerts read is the fresh refusal's
    ?assertEqual(St1, St2),
    ?assertEqual(St1, St3),
    ?assertNot(maps:is_key(last_success, St1)),
    ?assertMatch(#{enforced := 1, loaded := 0}, St2),
    ?assertMatch(#{last_reject := Reason}, S3),
    %% never loaded, hashes and ETag not advanced
    ?assertEqual(none, yuzu_gw_mgmt_crl_source:current()),
    ?assertMatch(#{crl := none, crl_hash := undefined, etag := undefined}, S3).

%% The same on top of a loaded CRL: the gauges say "loaded, but the latest attempt got nothing",
%% which is what RefreshStalled keys on; a remembered refusal must say it too.
memoised_refusal_reports_like_a_fresh_one_over_a_loaded_crl_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(crl("crl-populated.der")), ?NOW),
        {[], [Loaded]} = drain(),
        ?assertMatch(#{loaded := 1, last_success := _}, Loaded),
        Bad = crl("crl-evil.der"),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(Bad), ?NOW + 5),
        S3 = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(Bad), ?NOW + 10),
        S4 = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(Bad), ?NOW + 15),
        ?assertEqual(2, parses()),     %% the good one, the bad one once
        {Rs, [Fresh, Again1, Again2]} = drain(),
        ?assertEqual([unverified], Rs),
        ?assertMatch(#{loaded := 1, number := 7, enforced := 1}, Fresh),
        ?assertNot(maps:is_key(last_success, Fresh)),
        ?assertEqual(Fresh, Again1),
        ?assertEqual(Fresh, Again2),
        %% the loaded CRL, its hash and its ETag are exactly what the first refusal left
        ?assertEqual(maps:with([crl, crl_hash, ca_hash, etag], S2),
                     maps:with([crl, crl_hash, ca_hash, etag], S4)),
        ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current())
    end).

%% A remembered refusal does not take the ETag the server sent with the bad bytes: the next request
%% would be answered 304, and a 304 is reported as a success.
memoised_refusal_does_not_advance_the_etag_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Bad = fun(_, _) -> {ok, <<"garbage">>, <<"\"bad\"">>} end,
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), Bad, ?NOW),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, Bad, ?NOW + 5),
        ?assertMatch(#{etag := undefined}, S1),
        ?assertMatch(#{etag := undefined}, S2)
    end).

changed_bytes_are_parsed_again_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(<<"garbage one">>), ?NOW),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(<<"garbage two">>), ?NOW + 5),
        S3 = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(<<"garbage two">>), ?NOW + 10),
        _ = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(<<"garbage one">>), ?NOW + 15),
        ?assertEqual(3, parses()),     %% one, two, one again (the memory is of the LAST refusal)
        {Rs, _} = drain(),
        ?assertEqual([malformed, malformed, malformed], Rs)
    end).

changed_ca_set_is_parsed_again_test() ->
    with_memo(fun() ->
        Bin = crl("crl-populated.der"),
        Evil = policy([yuzu_gw_crl_fixture:path("evil-ca.pem")]),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(Evil),
        S1 = yuzu_gw_mgmt_crl_source:load(Evil, state(), fetch_of(Bin), ?NOW),
        S2 = yuzu_gw_mgmt_crl_source:load(Evil, S1, fetch_of(Bin), ?NOW + 5),
        ?assertEqual(1, parses()),
        {Rs1, _} = drain(),
        ?assertEqual([unverified], Rs1),
        %% the same bytes under the right CA: no memory applies, and the CRL loads
        Root = policy(),
        S3 = yuzu_gw_mgmt_crl_source:load(Root, S2, fetch_of(Bin), ?NOW + 10),
        ?assertEqual(2, parses()),
        ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
        ?assertMatch(#{rejected := none, last_reject := undefined}, S3),
        {Rs2, _} = drain(),
        ?assertEqual([], Rs2),
        %% and another bad CA set re-parses and counts again
        Renamed = policy([yuzu_gw_crl_fixture:path("renamed-ca.pem")]),
        S4 = yuzu_gw_mgmt_crl_source:load(Renamed, state(), fetch_of(Bin), ?NOW + 15),
        ?assertEqual(3, parses()),
        ?assertMatch(#{last_reject := issuer_mismatch}, S4)
    end).

%% A good CRL after a refusal clears the memory: the same bad bytes later are a new rejection.
an_accepted_crl_ends_the_memory_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Bad = crl("crl-evil.der"),
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(Bad), ?NOW),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(crl("crl-populated.der")), ?NOW + 5),
        _ = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(Bad), ?NOW + 10),
        ?assertEqual(3, parses()),
        {Rs, _} = drain(),
        ?assertEqual([unverified, unverified], Rs)
    end).

%% What is never remembered.
only_the_six_are_memoisable_test() ->
    ?assertEqual(lists:sort([malformed, unsupported, too_large, unverified, issuer_mismatch,
                             validity_too_long]),
                 lists:sort([R || R <- yuzu_gw_mgmt_crl_source:reject_reasons(),
                                  yuzu_gw_mgmt_crl_source:memoisable(R)])),
    [?assertNot(yuzu_gw_mgmt_crl_source:memoisable(R))
     || R <- [future_dated, replay, fetch_timeout, fetch_connect, fetch_tls, fetch_status,
              fetch_error, file_unreadable]].

future_dated_is_decided_every_tick_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Bin = crl("crl-populated.der"),
        Early = ?THIS - 7200,
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(Bin), Early),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(Bin), Early + 5),
        S3 = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(Bin), Early + 10),
        ?assertEqual(3, parses()),
        ?assertMatch(#{rejected := none, last_reject := future_dated}, S3),
        {Rs, _} = drain(),
        ?assertEqual([future_dated, future_dated, future_dated], Rs),
        %% the clock catches up: the same bytes now load
        _ = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(Bin), ?NOW),
        ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current())
    end).

%% ADR 2004 A8: a CRL that is already stale is refused (`replay') while the held one is believed,
%% and the SAME bytes are accepted once the held one is itself stale. Remembering the first verdict
%% would turn that bounded blind window into a revocation_stale outage.
replay_is_decided_every_tick_test() ->
    with_memo(fun() ->
        Ca = ca(),
        with_ca_file(Ca, fun(Pem) ->
            P = (policy([Pem]))#{grace_s => 0},
            ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
            %% held: number 5, valid to 2026-11-04T14:19:48Z
            Held = yuzu_gw_crl_build:crl(Ca, #{number => 5}),
            %% number 6 (so the ordinary rule would replace) but valid only to 2026-11-02T00:00:00Z
            Stale = yuzu_gw_crl_build:crl(Ca, #{number => 6, this => "261101000000Z",
                                                next => "261102000000Z"}),
            S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(Held), ?NOW),
            S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(Stale), ?NOW + 5),
            S3 = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(Stale), ?NOW + 10),
            ?assertEqual(3, parses()),
            ?assertMatch(#{number := 5}, yuzu_gw_mgmt_crl_source:current()),
            ?assertMatch(#{rejected := none, last_reject := replay}, S3),
            {Rs, _} = drain(),
            ?assertEqual([replay, replay], Rs),
            %% the held CRL runs out: the same bytes are now the better evidence and are installed
            AfterHeld = ?THIS + ?WIDTH + 10,
            S4 = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(Stale), AfterHeld),
            ?assertEqual(4, parses()),
            ?assertMatch(#{number := 6}, yuzu_gw_mgmt_crl_source:current()),
            ?assertMatch(#{last_reject := undefined}, S4)
        end)
    end).

%% A replay verdict does not erase the memory of an earlier refusal, and is not remembered itself.
replay_after_a_remembered_refusal_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Bad = crl("crl-evil.der"),
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(crl("crl-sub.der")), ?NOW),   %% 9
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(Bad), ?NOW + 1),                   %% unverified
        S3 = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(crl("crl-populated.der")), ?NOW + 2), %% 7: replay
        S4 = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(crl("crl-populated.der")), ?NOW + 3), %% replay again
        S5 = yuzu_gw_mgmt_crl_source:load(P, S4, fetch_of(Bad), ?NOW + 4),                   %% remembered
        ?assertEqual(4, parses()),     %% 9, evil, 7, 7 (the evil one the second time is skipped)
        {Rs, _} = drain(),
        ?assertEqual([unverified, replay, replay], Rs),
        ?assertMatch(#{last_reject := unverified}, S5)
    end).

%% A fetch failure between two sightings of the same bad bytes neither clears nor spoils the memory,
%% and is itself counted every tick.
fetch_failures_are_counted_every_tick_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Fail = fun(_, _) -> {error, fetch_timeout} end,
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(<<"garbage">>), ?NOW),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, Fail, ?NOW + 5),
        S3 = yuzu_gw_mgmt_crl_source:load(P, S2, Fail, ?NOW + 10),
        _ = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(<<"garbage">>), ?NOW + 15),
        ?assertEqual(1, parses()),
        {Rs, _} = drain(),
        ?assertEqual([malformed, fetch_timeout, fetch_timeout], Rs)
    end).

%% The memory is a pair of hashes and a reason, not the bytes.
the_memory_holds_no_bytes_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Bad = binary:copy(<<"x">>, 100000),
        S = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(Bad), ?NOW),
        #{rejected := {H, C, undefined, malformed, ?NOW}} = S,
        ?assertEqual(32, byte_size(H)),
        ?assertEqual(32, byte_size(C))
    end).

%%--------------------------------------------------------------------
%% The memory's key includes the bound; its life is one hour
%%--------------------------------------------------------------------

%% A refusal recorded under one `mgmt_crl_max_validity_s' is not honoured under another.
memo_is_keyed_by_the_validity_bound_test() ->
    with_memo(fun() ->
        Bin = crl("crl-populated.der"),
        A = (policy())#{max_validity_s => 3600},
        B = (policy())#{max_validity_s => 7200},      %% still narrower than the CRL's 173100 s
        ok = yuzu_gw_mgmt_crl_source:publish_policy(A),
        S1 = yuzu_gw_mgmt_crl_source:load(A, state(), fetch_of(Bin), ?NOW),
        S2 = yuzu_gw_mgmt_crl_source:load(A, S1, fetch_of(Bin), ?NOW + 5),       %% honoured
        ?assertEqual(1, parses()),
        S3 = yuzu_gw_mgmt_crl_source:load(B, S2, fetch_of(Bin), ?NOW + 10),      %% another bound
        ?assertEqual(2, parses()),
        S4 = yuzu_gw_mgmt_crl_source:load(B, S3, fetch_of(Bin), ?NOW + 15),      %% honoured again
        ?assertEqual(2, parses()),
        %% unset is a different bound from any number, and the bound that admits the CRL loads it
        U = policy(),
        _ = yuzu_gw_mgmt_crl_source:load(U, S4, fetch_of(Bin), ?NOW + 20),
        ?assertEqual(3, parses()),
        ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
        {Rs, _} = drain(),
        ?assertEqual([validity_too_long, validity_too_long], Rs)
    end).

memo_under_a_wider_bound_is_not_reused_to_refuse_test() ->
    with_memo(fun() ->
        Bin = crl("crl-populated.der"),
        A = (policy())#{max_validity_s => 3600},
        C = (policy())#{max_validity_s => 691200},
        ok = yuzu_gw_mgmt_crl_source:publish_policy(A),
        S1 = yuzu_gw_mgmt_crl_source:load(A, state(), fetch_of(Bin), ?NOW),
        _ = yuzu_gw_mgmt_crl_source:load(C, S1, fetch_of(Bin), ?NOW + 5),
        ?assertEqual(2, parses()),
        ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current())
    end).

%% After memo_ttl_s() the same bytes are parsed, counted and logged again; inside it they are not.
memo_expires_after_an_hour_test() ->
    with_log(fun() -> with_memo(fun() ->
        Ttl = yuzu_gw_mgmt_crl_source:memo_ttl_s(),
        ?assertEqual(3600, Ttl),
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Bad = <<"garbage">>,
        Lines = fun() -> length(not_loaded_lines()) end,
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(Bad), ?NOW),
        ?assertEqual(1, Lines()),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(Bad), ?NOW + Ttl - 1),
        ?assertEqual(1, parses()),
        ?assertEqual(0, Lines()),
        {R1, _} = drain(),
        ?assertEqual([malformed], R1),
        %% exactly one hour: parsed, counted and logged once more
        S3 = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(Bad), ?NOW + Ttl),
        ?assertEqual(2, parses()),
        ?assertEqual(1, Lines()),
        {R2, [St]} = drain(),
        ?assertEqual([malformed], R2),
        ?assertNot(maps:is_key(last_success, St)),
        %% and the hour starts again from the new rejection
        S4 = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(Bad), ?NOW + Ttl + Ttl - 1),
        ?assertEqual(2, parses()),
        _ = yuzu_gw_mgmt_crl_source:load(P, S4, fetch_of(Bad), ?NOW + Ttl + Ttl),
        ?assertEqual(3, parses())
    end) end).

%% A clock stepped back past the rejection cannot age it: it is decided again.
memo_does_not_survive_a_clock_stepped_back_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(<<"garbage">>), ?NOW),
        _ = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(<<"garbage">>), ?NOW - 1),
        ?assertEqual(2, parses())
    end).

%% Bytes refused by a transient fault (a CA file half-written at the time) are not pinned for ever:
%% after the hour they are looked at again and load.
memo_is_not_pinned_for_ever_test() ->
    with_memo(fun() ->
        Bin = crl("crl-populated.der"),
        Evil = policy([yuzu_gw_crl_fixture:path("evil-ca.pem")]),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(Evil),
        S1 = yuzu_gw_mgmt_crl_source:load(Evil, state(), fetch_of(Bin), ?NOW),
        ?assertMatch(#{last_reject := unverified}, S1),
        %% same key (the key is the bytes, the certificates read, the bound): only time differs
        S2 = yuzu_gw_mgmt_crl_source:load(Evil, S1, fetch_of(Bin), ?NOW + 3600),
        ?assertEqual(2, parses()),
        ?assertMatch(#{last_reject := unverified}, S2)
    end).

not_loaded_lines() ->
    receive
        {log, warning, Text} ->
            case string:find(Text, "the CRL was not loaded") of
                nomatch -> not_loaded_lines();
                _ -> [Text | not_loaded_lines()]
            end;
        {log, _, _} -> not_loaded_lines()
    after 100 -> []
    end.

%%--------------------------------------------------------------------
%% Through the process: the memory threads across real ticks
%%--------------------------------------------------------------------

memo_threads_across_watcher_ticks_test_() ->
    {timeout, 30, fun memo_across_ticks/0}.

memo_across_ticks() ->
    with_memo(fun() ->
        Dir = filename:join("/tmp", "yuzu_test_crlh_" ++
                            binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(6)))),
        ok = filelib:ensure_dir(filename:join(Dir, "x")),
        File = filename:join(Dir, "crl.der"),
        ok = file:write_file(File, <<"garbage">>),
        P = (policy())#{source => {file, File}, refresh_ms => 100000},
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        {ok, Pid} = yuzu_gw_mgmt_crl_source:start_link(),
        unlink(Pid),
        try
            %% the synchronous boot load parsed once; three more ticks through handle_info/safe_load
            ?assertEqual(1, parses()),
            [begin Pid ! refresh, _ = sys:get_state(Pid) end || _ <- lists:seq(1, 3)],
            ?assertEqual(1, parses()),
            {Rs, States} = drain(),
            ?assertEqual([malformed], Rs),
            ?assertEqual(4, length(States)),
            [?assertNot(maps:is_key(last_success, St)) || St <- States],
            %% the file changes: the next tick parses it
            ok = file:write_file(File, crl("crl-populated.der")),
            Pid ! refresh, _ = sys:get_state(Pid),
            ?assertEqual(2, parses()),
            ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current())
        after
            gen_server:stop(Pid),
            os:cmd("rm -rf '" ++ Dir ++ "'")
        end
    end).

%% The same CRL under another encoding (PEM for DER) is the `unchanged' branch of install/7: it ends
%% the memory of an earlier refusal like any accepted CRL.
unchanged_crl_ends_the_memory_test() ->
    with_memo(fun() ->
        P = policy(),
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        Der = crl("crl-populated.der"),
        Pem = public_key:pem_encode([{'CertificateList', Der, not_encrypted}]),
        Bad = <<"garbage">>,
        S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(Der), ?NOW),
        S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fetch_of(Bad), ?NOW + 1),
        ?assertMatch(#{rejected := {_, _, _, malformed, _}}, S2),
        S3 = yuzu_gw_mgmt_crl_source:load(P, S2, fetch_of(Pem), ?NOW + 2),     %% unchanged
        ?assertMatch(#{rejected := none, last_reject := undefined}, S3),
        ?assertEqual(3, parses()),
        _ = yuzu_gw_mgmt_crl_source:load(P, S3, fetch_of(Bad), ?NOW + 3),
        ?assertEqual(4, parses()),
        {Rs, _} = drain(),
        ?assertEqual([malformed, malformed], Rs)
    end).

%%--------------------------------------------------------------------
%% The log line says what to do about a bound the operator set
%%--------------------------------------------------------------------

validity_too_long_log_carries_the_hint_only_for_that_reason_test() ->
    with_log(fun() -> with_memo(fun() ->
        P = (policy())#{max_validity_s => 3600},
        ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
        _ = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(crl("crl-populated.der")), ?NOW),
        [Wide] = not_loaded_lines(),
        ?assertNotEqual(nomatch, string:find(Wide, "(validity_too_long)")),
        ?assertNotEqual(nomatch, string:find(Wide, "mgmt_crl_max_validity_s")),
        ?assertNotEqual(nomatch, string:find(Wide, "raise the key or leave it unset")),
        ?assertNotEqual(nomatch, string:find(Wide, "(3600 s)")),
        %% every other reason's line has no such hint
        Others = [{malformed, <<"garbage">>, P}, {unverified, crl("crl-evil.der"), P}],
        [begin
             _ = yuzu_gw_mgmt_crl_source:load(Pol, state(), fetch_of(Bin), ?NOW),
             [Line] = not_loaded_lines(),
             ?assertNotEqual(nomatch, string:find(Line, "(" ++ atom_to_list(R) ++ ")")),
             ?assertEqual(nomatch, string:find(Line, "mgmt_crl_max_validity_s"))
         end || {R, Bin, Pol} <- Others],
        %% and the fetch reasons
        _ = yuzu_gw_mgmt_crl_source:load(P, state(), fun(_, _) -> {error, fetch_timeout} end, ?NOW),
        [Fetch] = not_loaded_lines(),
        ?assertEqual(nomatch, string:find(Fetch, "mgmt_crl_max_validity_s"))
    end) end).

%%--------------------------------------------------------------------
%% The heap of a parse is released, and the refusal says which bound
%%--------------------------------------------------------------------

%% After a load that parsed a body the watcher process has collected the garbage of the parse: its
%% heap is within a small multiple of what it still holds (the loaded CRL), not the hundreds of MiB
%% the parse needed. 40,000 entries peak at about 80 MiB here; the threshold is a fraction of that.
heap_is_released_after_a_parse_test_() ->
    {timeout, 60, fun heap_released/0}.

heap_released() ->
    with_memo(fun() ->
        Ca = ca(),
        Bin = yuzu_gw_crl_build:crl(Ca, #{number => 1, revoked => lists:seq(1, 40000)}),
        with_ca_file(Ca, fun(Pem) ->
            P = policy([Pem]),
            {Pid, Ref} = spawn_monitor(
                           fun() ->
                                   S = yuzu_gw_mgmt_crl_source:load(P, state(), fetch_of(Bin), ?NOW),
                                   {total_heap_size, H} = process_info(self(), total_heap_size),
                                   #{crl := Crl} = S,
                                   exit({done, H, erts_debug:flat_size(Crl)})
                           end),
            receive
                {'DOWN', Ref, process, Pid, {done, HeapWords, LiveWords}} ->
                    ?assert(HeapWords < 6 * LiveWords + 100000)
            after 30000 -> error(timeout)
            end
        end)
    end).
