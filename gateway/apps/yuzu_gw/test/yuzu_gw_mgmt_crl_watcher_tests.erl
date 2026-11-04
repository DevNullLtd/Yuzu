%%% @doc The CRL watcher as a process, and the failure shapes the governance run of #6016 PR 4b
%%% found: replay protection across a restart of the watcher, a CRL that is already stale,
%%% a read that never returns, the URL port and what a bad URL leaks, host-name verification of the
%%% fetch for a DNS name, and the gauges the shipped alerts read.
%%%
%%% The CRLs are the ones the C++ server built (fixtures/crl/README.md); the clock is injected
%%% wherever the code takes one.
-module(yuzu_gw_mgmt_crl_watcher_tests).

-include_lib("eunit/include/eunit.hrl").

-define(THIS, 1793628888).
-define(NOW, (?THIS + 600)).

-export([handle_event/4]).

root_pem() -> yuzu_gw_crl_fixture:path("root-ca.pem").

file_policy(Path, Refresh) ->
    #{source => {file, Path}, grace_s => 86400, refresh_ms => Refresh,
      verify_cacertfiles => [root_pem()]}.

tmp_dir() ->
    Dir = filename:join("/tmp", "yuzu_test_crlw_" ++
                        binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(6)))),
    ok = filelib:ensure_dir(filename:join(Dir, "x")),
    Dir.

handle_event(Event, Measurements, Meta, Pid) ->
    Pid ! {telemetry, Event, Measurements, Meta},
    ok.

%% A stand-in for a CRL that the replace rule reads: only these keys matter to it.
crl(Number, ThisUpdate, NextUpdate) ->
    #{number => Number, this_update => ThisUpdate, next_update => NextUpdate,
      issuer => <<>>, revoked => #{}}.

%%--------------------------------------------------------------------
%% Replay protection survives a restart of the WATCHER (sec-F1 / ge-F2)
%%--------------------------------------------------------------------

%% The tick state starts from the CRL already published: a CRL older than the one the stream check
%% is using cannot take its place just because the process that tracked it crashed.
restart_keeps_the_high_water_mark_test() ->
    yuzu_gw_mgmt_crl_source:reset(),
    Dir = tmp_dir(),
    F = filename:join(Dir, "crl.der"),
    try
        ok = yuzu_gw_mgmt_crl_source:publish_policy(file_policy(F, 100000)),
        ok = file:write_file(F, yuzu_gw_crl_fixture:read("crl-sub.der")),     %% number 9
        {ok, Pid} = yuzu_gw_mgmt_crl_source:start_link(),
        unlink(Pid),
        ?assertMatch(#{number := 9}, yuzu_gw_mgmt_crl_source:current()),
        gen_server:stop(Pid),
        %% number 7, the same thisUpdate: a replay of the CRL held
        ok = file:write_file(F, yuzu_gw_crl_fixture:read("crl-populated.der")),
        {ok, Pid2} = yuzu_gw_mgmt_crl_source:start_link(),
        unlink(Pid2),
        ?assertMatch(#{number := 9}, yuzu_gw_mgmt_crl_source:current())
    after
        stop_watcher(),
        yuzu_gw_mgmt_crl_source:reset(),
        os:cmd("rm -rf '" ++ Dir ++ "'")
    end.

stop_watcher() ->
    case whereis(yuzu_gw_mgmt_crl_source) of
        undefined -> ok;
        Pid -> unlink(Pid), catch gen_server:stop(Pid), ok
    end.

%% Nothing published (a restart of the whole gateway): the first signed CRL is accepted. This is
%% the residual ADR 2004 A6(d) records; the test pins it so the limit cannot widen unseen.
whole_gateway_restart_accepts_the_first_signed_crl_test() ->
    yuzu_gw_mgmt_crl_source:reset(),
    Dir = tmp_dir(),
    F = filename:join(Dir, "crl.der"),
    try
        ok = yuzu_gw_mgmt_crl_source:publish_policy(file_policy(F, 100000)),
        ok = file:write_file(F, yuzu_gw_crl_fixture:read("crl-populated.der")),
        {ok, Pid} = yuzu_gw_mgmt_crl_source:start_link(),
        ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
        unlink(Pid),
        gen_server:stop(Pid)
    after
        yuzu_gw_mgmt_crl_source:reset(),
        os:cmd("rm -rf '" ++ Dir ++ "'")
    end.

%%--------------------------------------------------------------------
%% A CRL that is already stale does not displace one in force
%%--------------------------------------------------------------------

replace_rule_test_() ->
    Grace = 100,
    Held = crl(5, 1000, 2000),
    R = fun(Loaded, New, Now) -> yuzu_gw_mgmt_crl_source:replace_rule(Loaded, New, Now, Grace) end,
    [{"a stale newer-numbered CRL does not evict a CRL still believed",
      %% Now 5000 is past 3000 + grace of the new one (nextUpdate 3000), the held one is believed
      ?_assertEqual({reject, replay}, R(crl(5, 1000, 5050), crl(6, 100, 3000), 3000 + Grace + 1))},
     {"a CRL not yet stale replaces by the ordinary rule",
      ?_assertMatch({replace, _}, R(Held, crl(6, 1500, 9000), 1500))},
     {"when the held CRL is itself stale the ordinary rule applies",
      ?_assertMatch({replace, _}, R(Held, crl(6, 100, 3000), 3000 + Grace + 1))},
     {"nothing held: a stale CRL is installed (the check then refuses as revocation_stale)",
      ?_assertMatch({replace, _}, R(none, crl(6, 100, 3000), 3000 + Grace + 1))}].

%%--------------------------------------------------------------------
%% The watcher process: ignore, synchronous boot load, rescheduling
%%--------------------------------------------------------------------

watcher_ignores_without_a_policy_test() ->
    yuzu_gw_mgmt_crl_source:reset(),
    ?assertEqual(ignore, yuzu_gw_mgmt_crl_source:start_link()).

watcher_loads_before_start_link_returns_and_keeps_refreshing_test_() ->
    {timeout, 20, fun watcher_loads_and_refreshes/0}.

watcher_loads_and_refreshes() ->
    yuzu_gw_mgmt_crl_source:reset(),
    {ok, _} = application:ensure_all_started(telemetry),
    ok = yuzu_gw_mgmt_crl_source:publish_policy(
           file_policy(yuzu_gw_crl_fixture:path("crl-populated.der"), 1000)),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, mgmt_crl, state], fun ?MODULE:handle_event/4, self()),
    try
        {ok, Pid} = yuzu_gw_mgmt_crl_source:start_link(),
        %% synchronous: the CRL is there when start_link returns, listeners start after it
        ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
        _ = flush_states(),
        %% and the refresh is rescheduled: two more state reports follow, a tick apart
        Ticks = lists:sum([receive {telemetry, _, _, _} -> 1 after 3500 -> 0 end
                           || _ <- [1, 2]]),
        unlink(Pid),
        gen_server:stop(Pid),
        ?assertEqual(2, Ticks)
    after
        telemetry:detach(Id),
        yuzu_gw_mgmt_crl_source:reset()
    end.

flush_states() ->
    receive {telemetry, _, _, _} = M -> [M | flush_states()] after 0 -> [] end.

%% Everything in the mailbox. A file worker that outlived its deadline answers its parent whenever
%% its call returns (the watcher's catch-all drops that); here the parent is the test process.
flush_all() ->
    receive _ -> flush_all() after 0 -> ok end.

%%--------------------------------------------------------------------
%% A read that never returns (ge-F1 / sec-F2)
%%--------------------------------------------------------------------

%% A reader blocked in open() on a FIFO ends when a writer opens it: do that, so the test does not
%% leave an OS thread blocked for the rest of the run.
release(Fifo) ->
    _ = os:cmd("echo > '" ++ Fifo ++ "'"),
    ok.

%% In every test's `after': the FIFO of this test directory, if one was made, gets a writer so a
%% blocked reader ends even when an assertion failed first.
release_fifo(Dir) ->
    Path = filename:join(Dir, "fifo"),
    case filelib:is_file(Path) of
        true  -> release(Path);
        false -> ok
    end.

fifo(Dir) ->
    Path = filename:join(Dir, "fifo"),
    case os:cmd("mkfifo '" ++ Path ++ "' 2>&1 && echo made") of
        "made\n" -> {ok, Path};
        _ -> no_mkfifo
    end.

%% A `{file, P}' source on a FIFO with no writer: the attempt is bounded, and a second attempt
%% while the first worker is still stuck fails at once instead of starting another.
a_file_source_that_blocks_is_bounded_and_not_stacked_test_() ->
    {timeout, 30, fun() ->
        Dir = tmp_dir(),
        try
            case fifo(Dir) of
                no_mkfifo -> ok;
                {ok, Fifo} ->
                    Policy = file_policy(Fifo, 5000),
                    T0 = erlang:monotonic_time(millisecond),
                    %% a blocked FILE read is `file_unreadable' from the first attempt (not the
                    %% server-flavoured `fetch_timeout')
                    ?assertEqual({error, file_unreadable},
                                 yuzu_gw_mgmt_crl_source:fetch(Policy, #{etag => undefined}, 500)),
                    ?assert(erlang:monotonic_time(millisecond) - T0 < 3000),
                    T1 = erlang:monotonic_time(millisecond),
                    ?assertEqual({error, file_unreadable},
                                 yuzu_gw_mgmt_crl_source:fetch(Policy, #{etag => undefined}, 500)),
                    ?assert(erlang:monotonic_time(millisecond) - T1 < 200),
                    ok
            end
        after
            release_fifo(Dir),
            os:cmd("rm -rf '" ++ Dir ++ "'")
        end
    end}.

%% The stuck marker is not the watcher's own memory: it survives the watcher process, so a restart
%% (the supervisor's) does not start another blocked read.
a_stuck_read_survives_a_restart_of_the_asker_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_mgmt_crl_source:reset(),
        Dir = tmp_dir(),
        try
            case fifo(Dir) of
                no_mkfifo -> ok;
                {ok, Fifo} ->
                    Policy = file_policy(Fifo, 5000),
                    Me = self(),
                    First = spawn(fun() ->
                        Me ! {first, yuzu_gw_mgmt_crl_source:fetch(Policy, #{etag => undefined}, 300)}
                    end),
                    ?assertEqual({error, file_unreadable},
                                 receive {first, R1} -> R1 after 5000 -> timeout end),
                    ?assertNot(is_process_alive(First)),
                    %% a NEW process (a restarted watcher) finds the blocked read and starts none
                    Second = spawn(fun() ->
                        T0 = erlang:monotonic_time(millisecond),
                        R = yuzu_gw_mgmt_crl_source:fetch(Policy, #{etag => undefined}, 300),
                        Me ! {second, R, erlang:monotonic_time(millisecond) - T0}
                    end),
                    _ = Second,
                    {error, file_unreadable, Elapsed} =
                        (fun() -> receive {second, R2, E} -> {element(1, R2), element(2, R2), E}
                                  after 5000 -> timeout end end)(),
                    ?assert(Elapsed < 150)
            end
        after
            release_fifo(Dir),
            yuzu_gw_mgmt_crl_source:reset(),
            os:cmd("rm -rf '" ++ Dir ++ "'")
        end
    end}.

%% A read that is slow but does finish is adopted by the next attempt, not thrown away.
a_slow_read_that_finishes_is_adopted_by_the_next_attempt_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_mgmt_crl_source:reset(),
        Dir = tmp_dir(),
        try
            case fifo(Dir) of
                no_mkfifo -> ok;
                {ok, Fifo} ->
                    Policy = file_policy(Fifo, 5000),
                    ?assertEqual({error, file_unreadable},
                                 yuzu_gw_mgmt_crl_source:fetch(Policy, #{etag => undefined}, 300)),
                    %% a writer arrives late: the blocked open completes and reads the data
                    Bin = yuzu_gw_crl_fixture:read("crl-populated.der"),
                    Tmp = filename:join(Dir, "payload.der"),
                    ok = file:write_file(Tmp, Bin),
                    _ = os:cmd("cat '" ++ Tmp ++ "' > '" ++ Fifo ++ "'"),
                    ok = wait_for(fun() ->
                        case yuzu_gw_mgmt_crl_source:fetch(Policy, #{etag => undefined}, 300) of
                            {ok, Got, undefined} -> Got =:= Bin;
                            _ -> false
                        end
                    end, 5000)
            end
        after
            yuzu_gw_mgmt_crl_source:reset(),
            os:cmd("rm -rf '" ++ Dir ++ "'")
        end
    end}.

wait_for(Fun, Ms) when Ms =< 0 -> case Fun() of true -> ok; false -> timeout end;
wait_for(Fun, Ms) ->
    case Fun() of
        true -> ok;
        false -> receive after 100 -> wait_for(Fun, Ms - 100) end
    end.

%% The verification certificates are read in a bounded worker too, and an unreadable set is
%% `file_unreadable', not "the CRL is unverified".
a_cacertfile_that_blocks_is_file_unreadable_test_() ->
    {timeout, 30, fun() ->
        yuzu_gw_mgmt_crl_source:reset(),
        {ok, _} = application:ensure_all_started(telemetry),
        flush_all(),
        Dir = tmp_dir(),
        Id = {?MODULE, make_ref()},
        ok = telemetry:attach(Id, [yuzu, gw, mgmt_crl, rejected], fun ?MODULE:handle_event/4,
                              self()),
        try
            case fifo(Dir) of
                no_mkfifo -> ok;
                {ok, Fifo} ->
                    Bin = yuzu_gw_crl_fixture:read("crl-populated.der"),
                    Fetch = fun(_P, _S) -> {ok, Bin, undefined} end,
                    State = #{crl => none, crl_hash => undefined, ca_hash => undefined,
                              etag => undefined, last_reject => undefined},
                    Policy = (file_policy("unused", 5000))#{verify_cacertfiles => [Fifo]},
                    T0 = erlang:monotonic_time(millisecond),
                    _ = yuzu_gw_mgmt_crl_source:load(Policy, State, Fetch, ?NOW),
                    ?assert(erlang:monotonic_time(millisecond) - T0 < 4000),
                    ?assertMatch({telemetry, _, _, #{reason := file_unreadable}},
                                 receive {telemetry, _, _, _} = M -> M after 1000 -> timeout end)
            end
        after
            release_fifo(Dir),
            telemetry:detach(Id),
            yuzu_gw_mgmt_crl_source:reset(),
            os:cmd("rm -rf '" ++ Dir ++ "'")
        end
    end}.

%% A readable file with no certificate in it is "unverified" (nothing could have signed the CRL),
%% distinct from an unreadable one.
a_cacertfile_without_certificates_is_unverified_test() ->
    yuzu_gw_mgmt_crl_source:reset(),
    {ok, _} = application:ensure_all_started(telemetry),
    flush_all(),
    Dir = tmp_dir(),
    Empty = filename:join(Dir, "empty.pem"),
    ok = file:write_file(Empty, <<"not a certificate\n">>),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, mgmt_crl, rejected], fun ?MODULE:handle_event/4, self()),
    try
        Bin = yuzu_gw_crl_fixture:read("crl-populated.der"),
        State = #{crl => none, crl_hash => undefined, ca_hash => undefined, etag => undefined,
                  last_reject => undefined},
        Policy = (file_policy("unused", 5000))#{verify_cacertfiles => [Empty]},
        _ = yuzu_gw_mgmt_crl_source:load(Policy, State, fun(_, _) -> {ok, Bin, undefined} end, ?NOW),
        ?assertMatch({telemetry, _, _, #{reason := unverified}},
                     receive {telemetry, _, _, _} = M -> M after 1000 -> timeout end)
    after
        telemetry:detach(Id),
        yuzu_gw_mgmt_crl_source:reset(),
        os:cmd("rm -rf '" ++ Dir ++ "'")
    end.

%%--------------------------------------------------------------------
%% The URL: the port, and what a bad one leaks (ge-F3 / ge-F4)
%%--------------------------------------------------------------------

url_port_test_() ->
    P = fun yuzu_gw_mgmt_crl_source:parse_url/1,
    [?_assertMatch({ok, #{port := 443}}, P("https://h/p")),
     ?_assertMatch({ok, #{port := 8443}}, P("https://h:8443/p")),
     ?_assertMatch({ok, #{port := 65535}}, P("https://h:65535/p")),
     {"an empty port is a defect, not `undefined'",
      ?_assertMatch({error, {bad_mgmt_crl_url, _}}, P("https://h:/p"))},
     {"port 0 and 65536 are defects",
      [?_assertMatch({error, {bad_mgmt_crl_url, _}}, P(U))
       || U <- ["https://h:0/p", "https://h:65536/p", "https://h:99999/p"]]}].

url_credentials_never_reach_the_error_test_() ->
    P = fun yuzu_gw_mgmt_crl_source:parse_url/1,
    Leaks = fun(Url) ->
                    {error, {bad_mgmt_crl_url, Shown}} = P(Url),
                    binary:match(iolist_to_binary(io_lib:format("~tp", [Shown])), <<"SECRET">>)
                        =/= nomatch
            end,
    [{"a URL that does not parse",
      ?_assertNot(Leaks("https://u:SECRET@h/a b"))},
     {"a URL with another scheme",
      ?_assertNot(Leaks("ftp://u:SECRET@h/p"))},
     {"a binary URL",
      ?_assertNot(Leaks(<<"ftp://u:SECRET@h/p">>))},
     {"a well-formed https URL with userinfo",
      ?_assertNot(Leaks("https://u:SECRET@h/p"))},
     {"a password with a slash, a question mark or a hash in it",
      [?_assertNot(Leaks(U)) || U <- ["https://u:SE/CRET@h:80/x", "https://u:SE?CRET@h/x",
                                      "https://u:SE#CRET@h/x"]]},
     {"a scheme-less form and an invalid port",
      [?_assertNot(Leaks(U)) || U <- ["user:SECRET@h/crl", "https://u:SECRET@h:notaport/x"]]},
     {"a query token in an unparsable URL",
      ?_assertNot(Leaks("https://h/p?token=SECRET x"))}].

%% A source written in the wrong shape is reported by its outline, never its contents.
a_source_of_the_wrong_shape_is_never_echoed_test_() ->
    R = fun(Source) ->
                {error, Errors} = yuzu_gw_mgmt_crl_source:resolve(Source, undefined, undefined, []),
                iolist_to_binary(io_lib:format("~tp", [Errors]))
        end,
    Leaks = fun(Source) -> binary:match(R(Source), <<"SECRET">>) =/= nomatch end,
    [?_assertNot(Leaks({url, "https://u:SECRET@h/x", [{cacertfile, "/x"}]})),
     ?_assertNot(Leaks({url, "https://u:SECRET@h/x", #{}, extra})),
     ?_assertNot(Leaks(#{url => "https://u:SECRET@h/x"})),
     ?_assertNot(Leaks("https://u:SECRET@h/x")),
     ?_assertMatch(<<_/binary>>, R({url, "https://u:SECRET@h/x", [{cacertfile, "/x"}]}))].

%% Both a bad URL and a bad fetch CA are reported as two entries, not one nested list.
errors_are_a_flat_list_test() ->
    {error, Errors} = yuzu_gw_mgmt_crl_source:resolve(
                        {url, "https://h:/p", #{cacertfile => "/no/such/ca.pem"}},
                        undefined, undefined, []),
    ?assertEqual(2, length(Errors)),
    ?assert(lists:all(fun is_tuple/1, Errors)).

%%--------------------------------------------------------------------
%% Host-name verification for a DNS name (qe-A): the production URL is https://server:8443
%%--------------------------------------------------------------------

dns_name_not_in_the_certificate_is_refused_test_() ->
    {setup,
     fun() ->
             {ok, _} = application:ensure_all_started(gun),
             yuzu_gw_authz_tests:setup_certs()
     end,
     fun yuzu_gw_authz_tests:cleanup_certs/1,
     fun(#{dir := Dir, ca := Ca}) ->
             [{"a certificate whose SANs name another host is fetch_tls for `localhost'",
               fun() -> dns_name_case(Dir, Ca) end}];
        (_Skipped) ->
             []
     end}.

dns_name_case(Dir, Ca) ->
    Q = fun(P) -> "'" ++ P ++ "'" end,
    Ext = filename:join(Dir, "other.ext"),
    Key = filename:join(Dir, "other.key"),
    Csr = filename:join(Dir, "other.csr"),
    Pem = filename:join(Dir, "other.pem"),
    CaKey = filename:join(Dir, "ca.key"),
    ok = file:write_file(Ext, <<"subjectAltName=DNS:other.example,IP:127.0.0.1\n"
                                "extendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n">>),
    _ = os:cmd(lists:flatten(
                 ["openssl ecparam -name secp384r1 -genkey -noout -out ", Q(Key),
                  " && openssl req -new -key ", Q(Key), " -subj /CN=other -out ", Q(Csr),
                  " && openssl x509 -req -in ", Q(Csr), " -CA ", Q(Ca), " -CAkey ", Q(CaKey),
                  " -CAcreateserial -days 1 -sha384 -extfile ", Q(Ext), " -out ", Q(Pem)])),
    {ok, L} = ssl:listen(0, [{certfile, Pem}, {keyfile, Key}, {reuseaddr, true},
                             {active, false}, {ip, {127, 0, 0, 1}}, binary]),
    {ok, {_, Port}} = ssl:sockname(L),
    Acceptor = spawn(fun() -> accept(L) end),
    try
        Policy = #{source => {url, #{host => "localhost", port => Port, path => "/",
                                     cacertfile => Ca}}},
        ?assertEqual({error, fetch_tls},
                     yuzu_gw_mgmt_crl_source:fetch(Policy, #{etag => undefined}, 3000)),
        %% the options themselves: peer verification on, the fetch CA, SNI for a name, TLS 1.2+
        Opts = yuzu_gw_mgmt_crl_source:tls_options("server", Ca, []),
        ?assertEqual(verify_peer, proplists:get_value(verify, Opts)),
        ?assertEqual(Ca, proplists:get_value(cacertfile, Opts)),
        ?assertEqual("server", proplists:get_value(server_name_indication, Opts)),
        ?assertEqual(['tlsv1.3', 'tlsv1.2'], proplists:get_value(versions, Opts)),
        ?assertEqual(undefined, proplists:get_value(server_name_indication,
                         yuzu_gw_mgmt_crl_source:tls_options("127.0.0.1", Ca, []))),
        %% what the fetch really passes: the anchors as certificates, never a path ssl would read
        {ok, CaPem} = file:read_file(Ca),
        Ders = yuzu_gw_mgmt_crl:ca_certs(CaPem),
        ?assertMatch([_ | _], Ders),
        OptsD = yuzu_gw_mgmt_crl_source:tls_options_ders("server", Ders, []),
        ?assertEqual(verify_peer, proplists:get_value(verify, OptsD)),
        ?assertEqual(Ders, proplists:get_value(cacerts, OptsD)),
        ?assertEqual(undefined, proplists:get_value(cacertfile, OptsD)),
        ?assertEqual("server", proplists:get_value(server_name_indication, OptsD))
    after
        ssl:close(L),
        exit(Acceptor, kill)
    end.

accept(L) ->
    case ssl:transport_accept(L, 5000) of
        {ok, S} ->
            spawn(fun() ->
                          case ssl:handshake(S, 3000) of
                              {ok, T} -> _ = ssl:recv(T, 0, 2000), ssl:close(T);
                              _ -> ok
                          end
                  end),
            accept(L);
        {error, timeout} -> accept(L);
        _ -> ok
    end.

%%--------------------------------------------------------------------
%% The gauges the shipped alerts read (qe-D): telemetry event -> Prometheus value
%%--------------------------------------------------------------------

gauges_follow_the_state_events_test_() ->
    {setup,
     fun() ->
             {ok, _} = application:ensure_all_started(prometheus),
             {ok, _} = application:ensure_all_started(telemetry),
             catch telemetry:detach(yuzu_gw_prometheus),
             ok = yuzu_gw_telemetry:setup()
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     fun(_) ->
             G = fun(Name) -> prometheus_gauge:value(Name, []) end,
             [{"state sets each gauge from its own measurement",
               fun() ->
                       telemetry:execute([yuzu, gw, mgmt_crl, state],
                                         #{enforced => 1, loaded => 1, number => 9,
                                           next_update => 4242, revoked_entries => 3,
                                           last_success => 1700000000}, #{}),
                       ?assertEqual(1, G(yuzu_gw_mgmt_crl_enforced)),
                       ?assertEqual(1, G(yuzu_gw_mgmt_crl_loaded)),
                       ?assertEqual(9, G(yuzu_gw_mgmt_crl_number)),
                       ?assertEqual(4242, G(yuzu_gw_mgmt_crl_next_update_timestamp_seconds)),
                       ?assertEqual(3, G(yuzu_gw_mgmt_crl_revoked_entries)),
                       ?assertEqual(1700000000, G(yuzu_gw_mgmt_crl_last_success_timestamp_seconds))
               end},
              {"a failed attempt (no last_success) leaves the last success time alone",
               fun() ->
                       telemetry:execute([yuzu, gw, mgmt_crl, state],
                                         #{enforced => 1, loaded => 0, number => 0,
                                           next_update => 0, revoked_entries => 0}, #{}),
                       ?assertEqual(0, G(yuzu_gw_mgmt_crl_loaded)),
                       ?assertEqual(1700000000, G(yuzu_gw_mgmt_crl_last_success_timestamp_seconds))
               end},
              {"a rejection increments the counter for its own reason only",
               fun() ->
                       Before = prometheus_counter:value(yuzu_gw_mgmt_crl_rejected_total,
                                                         [<<"fetch_tls">>]),
                       telemetry:execute([yuzu, gw, mgmt_crl, rejected], #{count => 1},
                                         #{reason => fetch_tls}),
                       ?assertEqual(Before + 1,
                                    prometheus_counter:value(yuzu_gw_mgmt_crl_rejected_total,
                                                             [<<"fetch_tls">>])),
                       ?assertEqual(0, prometheus_counter:value(yuzu_gw_mgmt_crl_rejected_total,
                                                                [<<"replay">>]))
               end}]
     end}.

%% A real load reports a success time; a failed fetch does not move it.
load_reports_last_success_test() ->
    yuzu_gw_mgmt_crl_source:reset(),
    {ok, _} = application:ensure_all_started(telemetry),
    flush_all(),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, mgmt_crl, state], fun ?MODULE:handle_event/4, self()),
    try
        Bin = yuzu_gw_crl_fixture:read("crl-populated.der"),
        State = #{crl => none, crl_hash => undefined, ca_hash => undefined, etag => undefined,
                  last_reject => undefined},
        Policy = file_policy("unused", 5000),
        _ = yuzu_gw_mgmt_crl_source:load(Policy, State, fun(_, _) -> {ok, Bin, undefined} end, ?NOW),
        ?assertMatch({telemetry, _, #{last_success := _, loaded := 1}, _},
                     receive {telemetry, _, _, _} = M -> M after 1000 -> timeout end),
        _ = yuzu_gw_mgmt_crl_source:load(Policy, State, fun(_, _) -> {error, fetch_timeout} end,
                                         ?NOW),
        {telemetry, _, Measurements, _} = receive {telemetry, _, _, _} = M2 -> M2 after 1000 -> timeout end,
        ?assertNot(maps:is_key(last_success, Measurements))
    after
        telemetry:detach(Id),
        yuzu_gw_mgmt_crl_source:reset()
    end.

%%--------------------------------------------------------------------
%% A caught load failure still reports that a source is configured (N8)
%%--------------------------------------------------------------------

an_unexpected_load_failure_still_reports_enforced_test() ->
    yuzu_gw_mgmt_crl_source:reset(),
    {ok, _} = application:ensure_all_started(telemetry),
    flush_all(),
    Dir = tmp_dir(),
    ok = yuzu_gw_mgmt_crl_source:publish_policy(file_policy(filename:join(Dir, "none"), 100000)),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, mgmt_crl, state], fun ?MODULE:handle_event/4, self()),
    try
        %% a policy missing a key makes load/4 raise inside safe_load's catch
        Broken = #{source => {file, "x"}, refresh_ms => 100000},
        yuzu_gw_mgmt_crl_source:publish_policy(Broken),
        {ok, Pid2} = gen_server:start(yuzu_gw_mgmt_crl_source, [], []),
        unlink(Pid2),
        {telemetry, _, M, _} = receive {telemetry, _, _, _} = T -> T after 2000 -> timeout end,
        gen_server:stop(Pid2),
        ?assertEqual(1, maps:get(enforced, M))
    after
        telemetry:detach(Id),
        yuzu_gw_mgmt_crl_source:reset(),
        os:cmd("rm -rf '" ++ Dir ++ "'")
    end.

%%--------------------------------------------------------------------
%% Fixtures hold certificates only (the .gitignore negation admits any *.pem there)
%%--------------------------------------------------------------------

fixtures_hold_no_private_key_test() ->
    Dir = filename:dirname(yuzu_gw_crl_fixture:path("root-ca.pem")),
    Files = filelib:wildcard(filename:join(Dir, "*")),
    ?assert(length(Files) > 5),
    [?assertEqual(nomatch, binary:match(element(2, file:read_file(F)), <<"PRIVATE KEY">>))
     || F <- Files, filelib:is_regular(F)].
