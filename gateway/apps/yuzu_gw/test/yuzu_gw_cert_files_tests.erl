%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_cert_files: the certificate-file reader the pin
%%% watcher shares, and the expiry gauges it publishes for every certificate
%%% file the gateway is configured with.
%%%
%%% Certificates are minted in-process with public_key:pkix_test_root_cert/2
%%% (no openssl), because these cases need exact notAfter dates, including one
%%% past 2049 that X.509 encodes as GeneralizedTime instead of UTCTime.
%%%
%%% Events are observed through a telemetry handler this module attaches under
%%% its own id and detaches in cleanup; the published pin term is saved and
%%% restored around every case, so nothing leaks into later modules.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_cert_files_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("kernel/include/file.hrl").

-export([forward/4, equal_size_rsa_pems/2, replace_keeping_mtime/2]).

-define(PIN_KEY, {yuzu_gw_mgmt_pins, resolved}).
-define(HANDLER, {?MODULE, cert_file_state}).
-define(EVENT, [yuzu, gw, cert_file, state]).

%%%-------------------------------------------------------------------
%%% Time and PEM parsing (pure)
%%%-------------------------------------------------------------------

time_to_unix_test_() ->
    T = fun yuzu_gw_cert_files:time_to_unix/1,
    [%% RFC 5280 4.1.2.5.1: a two-digit UTCTime year of 50 or more is 19YY,
     %% below 50 it is 20YY.
     ?_assertEqual({ok, unix({{1950, 1, 1}, {0, 0, 0}})}, T({utcTime, "500101000000Z"})),
     ?_assertEqual({ok, unix({{2049, 12, 31}, {23, 59, 59}})}, T({utcTime, "491231235959Z"})),
     ?_assertEqual({ok, unix({{2030, 6, 1}, {13, 0, 0}})}, T({utcTime, "300601130000Z"})),
     ?_assertEqual({ok, unix({{2055, 6, 1}, {13, 0, 0}})}, T({generalTime, "20550601130000Z"})),
     %% anything else is not a time this reader will vouch for
     ?_assertEqual(error, T({utcTime, "3006011300Z"})),
     ?_assertEqual(error, T({utcTime, "300601130000"})),
     ?_assertEqual(error, T({generalTime, "2055060113000Z"})),
     ?_assertEqual(error, T({utcTime, "301301130000Z"})),
     ?_assertEqual(error, T({utcTime, "30060113000xZ"})),
     ?_assertEqual(error, T({generalTime, "20550601130000.5Z"})),
     ?_assertEqual(error, T(not_a_time))].

parse_pem_test_() ->
    UtcDer = mint({2030, 6, 1}),
    GenDer = mint({2055, 6, 1}),
    {ok, UtcSpki} = yuzu_gw_authz:spki_sha256(UtcDer),
    [{"a UTCTime notAfter is read in Unix seconds, with the SPKI of the certificate",
      ?_assertEqual({ok, #{spki => UtcSpki, not_after => unix({{2030, 6, 1}, {13, 0, 0}})}},
                    yuzu_gw_cert_files:parse_pem(pem([UtcDer])))},
     {"a GeneralizedTime notAfter (after 2049) is read too",
      ?_assertMatch({ok, #{not_after := 2695467600}},
                    yuzu_gw_cert_files:parse_pem(pem([GenDer])))},
     {"a bundle reports its EARLIEST notAfter and the SPKI of its FIRST certificate",
      fun() ->
          {ok, GenSpki} = yuzu_gw_authz:spki_sha256(GenDer),
          ?assertEqual({ok, #{spki => GenSpki, not_after => unix({{2030, 6, 1}, {13, 0, 0}})}},
                       yuzu_gw_cert_files:parse_pem(pem([GenDer, UtcDer])))
      end},
     {"no certificate, garbage, or a truncated PEM is an error, not a crash",
      fun() ->
          ?assertEqual(error, yuzu_gw_cert_files:parse_pem(<<>>)),
          ?assertEqual(error, yuzu_gw_cert_files:parse_pem(<<"not a certificate">>)),
          Full = pem([UtcDer]),
          ?assertEqual(error, yuzu_gw_cert_files:parse_pem(binary:part(Full, 0, byte_size(Full) div 2)))
      end}].

%%%-------------------------------------------------------------------
%%% Which files: the configured sources (pure)
%%%-------------------------------------------------------------------

sources_test_() ->
    Listeners = [#{name => agent,
                   tls => #{certfile => "/c/gw.pem", keyfile => "/c/gw.key",
                            cacertfile => "/c/ca.pem"}},
                 #{name => plain},
                 #{name => <<"mgmt">>,
                   tls => #{certfile => <<"/c/gw.pem">>, keyfile => "/c/gw.key",
                            cacertfile => "/c/ca.pem"}},
                 not_a_map],
    Upstream = #{channels =>
                     [{default_channel,
                       [{https, "127.0.0.1", 50055,
                         [{cacertfile, "/c/ca.pem"}, {certfile, "/c/gw.pem"},
                          {keyfile, "/c/gw.key"}, {verify, verify_peer}]},
                        {https, "10.0.0.2", 50055,
                         [{cacertfile, "/c/ca.pem"}, {certfile, "/c/gw.pem"}], #{}},
                        {http, "127.0.0.1", 50056, []}],
                       #{}},
                      garbage]},
    Pins = [{cert_file, "/etc/yuzu/certs/default-server.pem"},
            {spki_sha256, "00"},
            {cert_file, <<"/other/default-server.pem">>}],
    S = yuzu_gw_cert_files:sources(Listeners, Upstream, Pins),
    [{"every configured certificate file, by role and name, each path once per name",
      ?_assertEqual(
         lists:sort([{<<"listener">>, <<"agent">>, "/c/gw.pem"},
                     {<<"listener_ca">>, <<"agent">>, "/c/ca.pem"},
                     {<<"listener">>, <<"mgmt">>, <<"/c/gw.pem">>},
                     {<<"listener_ca">>, <<"mgmt">>, "/c/ca.pem"},
                     {<<"upstream_client">>, <<"default_channel">>, "/c/gw.pem"},
                     {<<"upstream_ca">>, <<"default_channel">>, "/c/ca.pem"},
                     {<<"mgmt_peer_pin">>, <<"default-server.pem">>,
                      "/etc/yuzu/certs/default-server.pem"},
                     {<<"mgmt_peer_pin">>, <<"default-server.pem">>,
                      <<"/other/default-server.pem">>}]),
         lists:sort(S))},
     {"configuration that is not the expected shape yields no sources, not a crash",
      ?_assertEqual([], yuzu_gw_cert_files:sources(undefined, undefined, undefined))},
     {"a listener name that is not printable text is rendered, and bounded",
      fun() ->
          Long = list_to_atom(lists:duplicate(200, $a)),
          [{<<"listener">>, N1, _}, {<<"listener_ca">>, N1, _}] =
              yuzu_gw_cert_files:sources(
                [#{name => Long, tls => #{certfile => "/a", cacertfile => "/b"}}], undefined, []),
          ?assert(byte_size(N1) =< 64),
          [{<<"listener">>, N2, _} | _] =
              yuzu_gw_cert_files:sources(
                [#{name => {x, 1}, tls => #{certfile => "/a", cacertfile => "/b"}}], undefined, []),
          ?assertEqual(<<"{x,1}">>, N2)
      end}].

%%%-------------------------------------------------------------------
%%% The expiry refresh (file system + telemetry)
%%%-------------------------------------------------------------------

refresh_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [fun(F) -> {"the first refresh publishes readable=1 and notAfter for each role/name",
                 fun() -> first_refresh_publishes(F) end} end,
      fun(F) -> {"an unchanged file is read, not parsed again, and publishes nothing",
                 fun() -> unchanged_publishes_nothing(F) end} end,
      fun(F) -> {"a renewed certificate publishes its new notAfter",
                 fun() -> renewal_publishes_new_not_after(F) end} end,
      fun(F) -> {"a file that becomes unreadable or garbage reads 0 and keeps its last notAfter",
                 fun() -> failure_keeps_last_not_after(F) end} end,
      fun(F) -> {"a file unreadable from the start reads 0 and has no notAfter",
                 fun() -> unreadable_from_start(F) end} end,
      fun(F) -> {"two files under one role/name report the earlier notAfter",
                 fun() -> one_name_two_files(F) end} end,
      fun(F) -> {"a mgmt pin file is reported from the pin watcher's state, not read again",
                 fun() -> pin_role_follows_the_watcher(F) end} end,
      fun(F) -> {"a different key of the same size, written with the same mtime, is re-read",
                 fun() -> same_size_same_mtime_rotation_is_read(F) end} end]}.

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    Dir = make_dir(),
    Prev = persistent_term:get(?PIN_KEY, undefined),
    persistent_term:erase(?PIN_KEY),
    catch telemetry:detach(?HANDLER),
    #{dir => Dir, prev => Prev}.

cleanup(#{dir := Dir, prev := Prev}) ->
    catch telemetry:detach(?HANDLER),
    catch meck:unload(file),
    case Prev of
        undefined -> persistent_term:erase(?PIN_KEY);
        _ -> persistent_term:put(?PIN_KEY, Prev)
    end,
    os:cmd("rm -rf '" ++ Dir ++ "'"),
    flush(),
    ok.

%% Attach the observing handler with the CALLING process as the receiver. It is
%% called from each case, not from setup/0: EUnit runs a foreach setup in a
%% different process from the case, so a pid captured there would receive the
%% events instead of the case. cleanup/1 detaches it.
listen() ->
    catch telemetry:detach(?HANDLER),
    ok = telemetry:attach(?HANDLER, ?EVENT, fun ?MODULE:forward/4, self()).

forward(_Event, Measurements, #{role := R, name := N}, Pid) ->
    Pid ! {cert_state, R, N, Measurements},
    ok.

first_refresh_publishes(#{dir := Dir}) ->
    listen(),
    Gw = write(Dir, "gw.pem", [mint({2030, 6, 1})]),
    Ca = write(Dir, "ca.pem", [mint({2055, 6, 1})]),
    Sources = [{<<"listener">>, <<"agent">>, Gw}, {<<"listener_ca">>, <<"agent">>, Ca}],
    _ = yuzu_gw_cert_files:refresh(Sources, yuzu_gw_cert_files:new()),
    ?assertEqual(
       lists:sort([{<<"listener">>, <<"agent">>,
                    #{readable => 1, not_after => unix({{2030, 6, 1}, {13, 0, 0}})}},
                   {<<"listener_ca">>, <<"agent">>,
                    #{readable => 1, not_after => 2695467600}}]),
       lists:sort(events())).

unchanged_publishes_nothing(#{dir := Dir}) ->
    listen(),
    Gw = write(Dir, "gw.pem", [mint({2030, 6, 1})]),
    Sources = [{<<"listener">>, <<"agent">>, Gw}],
    S1 = yuzu_gw_cert_files:refresh(Sources, yuzu_gw_cert_files:new()),
    [_] = events(),
    ok = meck:new(file, [unstick, passthrough, no_link]),
    ok = meck:new(public_key, [passthrough, no_link]),
    try
        S2 = yuzu_gw_cert_files:refresh(Sources, S1),
        Calls = [F || {Pid, {file, F, _}, _} <- meck:history(file), Pid =:= self()],
        ?assert(lists:member(read_file, Calls)),
        ?assertEqual(0, meck:num_calls(public_key, pem_decode, '_')),
        ?assertEqual(S1, S2),
        ?assertEqual([], events())
    after
        meck:unload(public_key)
    end.

renewal_publishes_new_not_after(#{dir := Dir}) ->
    listen(),
    Gw = write(Dir, "gw.pem", [mint({2030, 6, 1})]),
    Sources = [{<<"listener">>, <<"agent">>, Gw}],
    S1 = yuzu_gw_cert_files:refresh(Sources, yuzu_gw_cert_files:new()),
    [_] = events(),
    Gw = write(Dir, "gw.pem", [mint({2031, 6, 1})]),
    ok = file:change_time(Gw, {{2021, 1, 1}, {0, 0, 0}}),
    _ = yuzu_gw_cert_files:refresh(Sources, S1),
    ?assertEqual([{<<"listener">>, <<"agent">>,
                   #{readable => 1, not_after => unix({{2031, 6, 1}, {13, 0, 0}})}}],
                 events()).

failure_keeps_last_not_after(#{dir := Dir}) ->
    listen(),
    Der = mint({2030, 6, 1}),
    Gw = write(Dir, "gw.pem", [Der]),
    Sources = [{<<"listener">>, <<"agent">>, Gw}],
    S1 = yuzu_gw_cert_files:refresh(Sources, yuzu_gw_cert_files:new()),
    [_] = events(),
    %% gone: readable drops to 0 and notAfter stays the last value read (an
    %% expiring certificate stays loud)
    NotAfter = unix({{2030, 6, 1}, {13, 0, 0}}),
    ok = file:delete(Gw),
    S2 = yuzu_gw_cert_files:refresh(Sources, S1),
    ?assertEqual([{<<"listener">>, <<"agent">>, #{readable => 0, not_after => NotAfter}}],
                 events()),
    %% still gone: nothing new to say
    S3 = yuzu_gw_cert_files:refresh(Sources, S2),
    ?assertEqual([], events()),
    %% back, as garbage: still unreadable, nothing new
    ok = file:write_file(Gw, <<"-----BEGIN CERTIFICATE-----\nAAAA">>),
    S4 = yuzu_gw_cert_files:refresh(Sources, S3),
    ?assertEqual([], events()),
    %% fixed: readable again
    Gw = write(Dir, "gw.pem", [Der]),
    ok = file:change_time(Gw, {{2022, 1, 1}, {0, 0, 0}}),
    _ = yuzu_gw_cert_files:refresh(Sources, S4),
    ?assertEqual([{<<"listener">>, <<"agent">>,
                   #{readable => 1, not_after => unix({{2030, 6, 1}, {13, 0, 0}})}}],
                 events()).

unreadable_from_start(#{dir := Dir}) ->
    listen(),
    Missing = filename:join(Dir, "missing.pem"),
    _ = yuzu_gw_cert_files:refresh([{<<"upstream_client">>, <<"default_channel">>, Missing}],
                                   yuzu_gw_cert_files:new()),
    ?assertEqual([{<<"upstream_client">>, <<"default_channel">>, #{readable => 0}}], events()).

one_name_two_files(#{dir := Dir}) ->
    listen(),
    A = write(Dir, "a.pem", [mint({2031, 6, 1})]),
    B = write(Dir, "b.pem", [mint({2030, 6, 1})]),
    _ = yuzu_gw_cert_files:refresh([{<<"upstream_client">>, <<"c">>, A},
                                    {<<"upstream_client">>, <<"c">>, B}],
                                   yuzu_gw_cert_files:new()),
    ?assertEqual([{<<"upstream_client">>, <<"c">>,
                   #{readable => 1, not_after => unix({{2030, 6, 1}, {13, 0, 0}})}}],
                 events()).

pin_role_follows_the_watcher(#{dir := Dir}) ->
    listen(),
    Pin = write(Dir, "default-server.pem", [mint({2030, 6, 1})]),
    Sources = [{<<"mgmt_peer_pin">>, <<"default-server.pem">>, Pin}],
    %% nothing published by the watcher yet: unreadable, no notAfter
    S1 = yuzu_gw_cert_files:refresh(Sources, yuzu_gw_cert_files:new()),
    ?assertEqual([{<<"mgmt_peer_pin">>, <<"default-server.pem">>, #{readable => 0}}], events()),
    %% the watcher resolves it: reported from its state, and this module makes
    %% no file call of its own for the pin file
    ok = yuzu_gw_mgmt_pins:refresh([{cert_file, Pin}]),
    ok = meck:new(file, [unstick, passthrough, no_link]),
    S2 = yuzu_gw_cert_files:refresh(Sources, S1),
    ?assertEqual([], [C || {P, C, _} <- meck:history(file), P =:= self()]),
    ok = meck:unload(file),
    ?assertEqual([{<<"mgmt_peer_pin">>, <<"default-server.pem">>,
                   #{readable => 1, not_after => unix({{2030, 6, 1}, {13, 0, 0}})}}],
                 events()),
    %% the watcher loses the file: readable 0, last notAfter kept
    ok = file:delete(Pin),
    ok = yuzu_gw_mgmt_pins:refresh([{cert_file, Pin}]),
    _ = yuzu_gw_cert_files:refresh(Sources, S2),
    ?assertEqual([{<<"mgmt_peer_pin">>, <<"default-server.pem">>,
                   #{readable => 0, not_after => unix({{2030, 6, 1}, {13, 0, 0}})}}],
                 events()).

%% Gate 8 #2. A rotation to a new key of the same type produces a PEM of the
%% same size (RSA-2048 DER has a fixed length), and copy tools that preserve
%% the mtime (cp -p, rsync -a, tar -p) or a rewrite within the same second
%% leave {mtime, size} unchanged. The new certificate must still be read: its
%% SPKI and its notAfter are what the gauges and the pin report.
same_size_same_mtime_rotation_is_read(#{dir := Dir}) ->
    listen(),
    {PemA, PemB} = equal_size_rsa_pems({2030, 6, 1}, {2031, 6, 1}),
    Path = filename:join(Dir, "gw.pem"),
    ok = file:write_file(Path, PemA),
    Sources = [{<<"listener">>, <<"agent">>, Path}],
    S1 = yuzu_gw_cert_files:refresh(Sources, yuzu_gw_cert_files:new()),
    [_] = events(),
    E1 = yuzu_gw_cert_files:step(Path, none),
    ok = replace_keeping_mtime(Path, PemB),
    _ = yuzu_gw_cert_files:refresh(Sources, S1),
    ?assertEqual([{<<"listener">>, <<"agent">>,
                   #{readable => 1, not_after => unix({{2031, 6, 1}, {13, 0, 0}})}}],
                 events()),
    #{good := #{spki := SpkiA}} = E1,
    #{good := #{spki := SpkiB}} = yuzu_gw_cert_files:step(Path, E1),
    ?assertNotEqual(SpkiA, SpkiB).

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

%% Two PEMs of self-signed RSA-2048 certificates with different keys and the
%% given notAfter dates (both before 2049, so both UTCTime), of EXACTLY the
%% same byte size. RSA-2048 makes the DER length fixed in practice; the size is
%% checked, and minting is retried, so the case never passes vacuously.
equal_size_rsa_pems(DateA, DateB) ->
    equal_size_rsa_pems(DateA, DateB, 20).

equal_size_rsa_pems(_, _, 0) ->
    error(could_not_mint_equal_size_certificates);
equal_size_rsa_pems(DateA, DateB, N) ->
    Mint = fun(Date) ->
                   #{cert := Der} = public_key:pkix_test_root_cert(
                                      "yuzu-cert-files-test",
                                      [{validity, {{2020, 1, 1}, Date}},
                                       {key, {rsa, 2048, 65537}}]),
                   pem([Der])
           end,
    A = Mint(DateA),
    B = Mint(DateB),
    case byte_size(A) =:= byte_size(B) andalso A =/= B of
        true -> {A, B};
        false -> equal_size_rsa_pems(DateA, DateB, N - 1)
    end.

%% Overwrite Path with Bin and put its previous mtime back, so a stat sees the
%% same {mtime, size} as before when Bin has the old size.
replace_keeping_mtime(Path, Bin) ->
    {ok, #file_info{mtime = M, atime = A, size = S}} = file:read_file_info(Path, [{time, posix}]),
    ok = file:write_file(Path, Bin),
    ok = file:write_file_info(Path, #file_info{mtime = M, atime = A}, [{time, posix}]),
    {ok, #file_info{mtime = M, size = S}} = file:read_file_info(Path, [{time, posix}]),
    ok.

%% A self-signed EC certificate whose notAfter is Date at 13:00:00 UTC (the
%% time pkix_test_root_cert/2 writes).
mint(Date) ->
    #{cert := Der} = public_key:pkix_test_root_cert(
                       "yuzu-cert-files-test",
                       [{validity, {{2020, 1, 1}, Date}}, {key, {namedCurve, secp256r1}}]),
    Der.

pem(Ders) ->
    public_key:pem_encode([{'Certificate', D, not_encrypted} || D <- Ders]).

write(Dir, Name, Ders) ->
    Path = filename:join(Dir, Name),
    ok = file:write_file(Path, pem(Ders)),
    Path.

unix(DateTime) ->
    calendar:datetime_to_gregorian_seconds(DateTime) - 62167219200.

make_dir() ->
    Base = case os:getenv("TMPDIR") of
               false -> "/tmp";
               T -> T
           end,
    Dir = filename:join(Base, "yuzu_cert_files_" ++ integer_to_list(erlang:unique_integer([positive]))
                              ++ "_" ++ os:getpid()),
    ok = file:make_dir(Dir),
    Dir.

%% Every event received so far, in arrival order.
events() ->
    receive {cert_state, R, N, M} -> [{R, N, M} | events()]
    after 0 -> []
    end.

flush() ->
    receive {cert_state, _, _, _} -> flush()
    after 0 -> ok
    end.
