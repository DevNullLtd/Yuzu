%%% @doc yuzu_gw_mgmt_crl_source: configuration, one load (the replace rule, last known good,
%%% what is counted), and the fetch (a file, and a real TLS server). #6016 PR 4b.
%%%
%%% The CRLs are the ones the C++ server built (fixtures/crl/README.md). The TLS server is a
%%% plain `ssl' listener answering canned HTTP/1.1, so every failure the fetch must survive (a
%%% 500, a stalled server, the wrong CA, a host name the certificate does not carry, a body
%%% past the bound, a refused connection) is produced for real.
-module(yuzu_gw_mgmt_crl_source_tests).

-include_lib("eunit/include/eunit.hrl").

%% thisUpdate of the fixture CRLs, and a clock a few minutes after it.
-define(THIS, 1793628888).
-define(NOW, (?THIS + 600)).

-export([handle_event/4]).

root_pem() -> yuzu_gw_crl_fixture:path("root-ca.pem").
crl(N) -> yuzu_gw_crl_fixture:read(N).

policy() ->
    policy([root_pem()]).

policy(VerifyFiles) ->
    #{source => {file, "unused"}, grace_s => 86400, refresh_ms => 5000,
      verify_cacertfiles => VerifyFiles}.

ok_fetch(Name) ->
    Bin = crl(Name),
    fun(_Policy, _State) -> {ok, Bin, undefined} end.

state() ->
    #{crl => none, crl_hash => undefined, ca_hash => undefined, etag => undefined,
      last_reject => undefined}.

%%--------------------------------------------------------------------
%% Configuration
%%--------------------------------------------------------------------

listener(Ca) ->
    #{name => mgmt, service_protos => [management_pb],
      tls => #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => Ca}}.

resolve_test_() ->
    Ca = root_pem(),
    Listeners = [listener(Ca)],
    Url = "https://server:8443/api/v1/ca/crl",
    R = fun(Source, Grace, Refresh, Ls) -> yuzu_gw_mgmt_crl_source:resolve(Source, Grace, Refresh, Ls) end,
    [{"no source is no CRL check, whatever the listeners",
      ?_assertEqual({ok, none}, R(undefined, undefined, undefined, Listeners))},
     {"an unset grace and refresh take their defaults",
      ?_assertMatch({ok, #{grace_s := 86400, refresh_ms := 5000,
                           source := {url, #{host := "server", port := 8443,
                                             path := "/api/v1/ca/crl", cacertfile := Ca}}}},
                    R({url, Url}, undefined, undefined, Listeners))},
     {"the fetch CA defaults to the first management listener's cacertfile",
      ?_assertMatch({ok, #{verify_cacertfiles := [Ca]}},
                    R({url, Url}, undefined, undefined, Listeners))},
     {"a binary URL is accepted and the port defaults to 443",
      ?_assertMatch({ok, #{source := {url, #{host := "server", port := 443, path := "/"}}}},
                    R({url, <<"https://server">>}, undefined, undefined, Listeners))},
     {"a query string is kept",
      ?_assertMatch({ok, #{source := {url, #{path := "/crl?x=1"}}}},
                    R({url, "https://s:1/crl?x=1"}, undefined, undefined, Listeners))},
     {"a per-source cacertfile overrides the listener's",
      ?_assertMatch({ok, #{source := {url, #{cacertfile := Ca}}}},
                    R({url, Url, #{cacertfile => Ca}}, undefined, undefined, []))},
     {"a file source needs no fetch CA",
      ?_assertMatch({ok, #{source := {file, "/var/crl.der"}}},
                    R({file, "/var/crl.der"}, undefined, undefined, []))},
     {"explicit grace and refresh",
      ?_assertMatch({ok, #{grace_s := 0, refresh_ms := 1000}},
                    R({file, "/x"}, 0, 1000, []))},
     {"http is a defect",
      ?_assertMatch({error, [{bad_mgmt_crl_url, _}]},
                    R({url, "http://server:8080/api/v1/ca/crl"}, undefined, undefined, Listeners))},
     {"userinfo in the URL is a defect",
      ?_assertMatch({error, [{bad_mgmt_crl_url, _}]},
                    R({url, "https://u:p@server/crl"}, undefined, undefined, Listeners))},
     {"a fragment is a defect",
      ?_assertMatch({error, [{bad_mgmt_crl_url, _}]},
                    R({url, "https://server/crl#x"}, undefined, undefined, Listeners))},
     {"no host is a defect",
      ?_assertMatch({error, [{bad_mgmt_crl_url, _}]},
                    R({url, "https:///crl"}, undefined, undefined, Listeners))},
     {"not a URL at all is a defect",
      ?_assertMatch({error, [{bad_mgmt_crl_url, _}]},
                    R({url, 42}, undefined, undefined, Listeners))},
     {"a url source with no CA to trust is a defect",
      ?_assertMatch({error, [{no_mgmt_crl_fetch_ca, _}]},
                    R({url, Url}, undefined, undefined, []))},
     {"a cacertfile override that does not exist is a defect, not a fall back to the listener's",
      ?_assertMatch({error, [{bad_mgmt_crl_cacertfile, "/no/such/ca.pem", not_a_file}]},
                    R({url, Url, #{cacertfile => "/no/such/ca.pem"}}, undefined, undefined,
                      Listeners))},
     {"an unknown option is a defect",
      ?_assertMatch({error, [{bad_mgmt_crl_source_options, [insecure]}]},
                    R({url, Url, #{insecure => true}}, undefined, undefined, Listeners))},
     {"a source of the wrong shape is a defect",
      ?_assertMatch({error, [{bad_mgmt_crl_source, _}]},
                    R(whatever, undefined, undefined, Listeners))},
     {"grace out of range is a defect",
      [?_assertMatch({error, [{bad_mgmt_crl_grace_s, G, _}]}, R({file, "/x"}, G, undefined, []))
       || G <- [-1, 604801, "86400", 1.5]]},
     {"refresh out of range is a defect",
      [?_assertMatch({error, [{bad_mgmt_crl_refresh_ms, V, _}]}, R({file, "/x"}, undefined, V, []))
       || V <- [999, 3600001, 0, "5000"]]},
     {"every defect is reported together",
      ?_assertMatch({error, [{bad_mgmt_crl_url, _}, {bad_mgmt_crl_grace_s, -5, _},
                             {bad_mgmt_crl_refresh_ms, 1, _}]},
                    R({url, "http://x/"}, -5, 1, Listeners))},
     {"a malformed grace is a defect even with no source (a typo is never silent)",
      ?_assertMatch({error, [{bad_mgmt_crl_grace_s, -1, _}]}, R(undefined, -1, undefined, []))}].

%%--------------------------------------------------------------------
%% One load
%%--------------------------------------------------------------------

handle_event(Event, Measurements, Meta, Pid) ->
    Pid ! {telemetry, Event, Measurements, Meta},
    ok.

with_load(Fun) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_mgmt_crl_source:reset(),
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach_many(Id, [[yuzu, gw, mgmt_crl, rejected], [yuzu, gw, mgmt_crl, state]],
                               fun ?MODULE:handle_event/4, self()),
    try Fun()
    after
        telemetry:detach(Id),
        yuzu_gw_mgmt_crl_source:reset()
    end.

rejections() ->
    receive
        {telemetry, [yuzu, gw, mgmt_crl, rejected], _, #{reason := R}} -> [R | rejections()];
        {telemetry, _, _, _} -> rejections()
    after 0 -> []
    end.

last_state() ->
    last_state(none).
last_state(Last) ->
    receive
        {telemetry, [yuzu, gw, mgmt_crl, state], M, _} -> last_state(M);
        {telemetry, _, _, _} -> last_state(Last)
    after 0 -> Last
    end.

load_test_() ->
    {foreach, fun() -> ok end, fun(_) -> ok end,
     [{"the first CRL is verified, published and reported",
       fun() -> with_load(fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           S = yuzu_gw_mgmt_crl_source:load(policy(), state(), ok_fetch("crl-populated.der"), ?NOW),
           ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
           ?assertMatch(#{crl := #{number := 7}, last_reject := undefined}, S),
           ?assertMatch(#{enforced := 1, loaded := 1, number := 7, revoked_entries := 1,
                          next_update := _}, last_state()),
           ?assertEqual([], rejections())
       end) end},
      {"a fetch failure on a first boot loads nothing and counts the reason",
       fun() -> with_load(fun() ->
           ok = yuzu_gw_mgmt_crl_source:publish_policy(policy()),
           S = yuzu_gw_mgmt_crl_source:load(policy(), state(),
                                            fun(_, _) -> {error, fetch_connect} end, ?NOW),
           ?assertEqual(none, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([fetch_connect], rejections()),
           ?assertMatch(#{crl := none, last_reject := fetch_connect}, S)
       end) end},
      {"a failed fetch KEEPS the loaded CRL and a later good one replaces it",
       fun() -> with_load(fun() ->
           P = policy(),
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fun(_, _) -> {error, fetch_status} end, ?NOW),
           ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([fetch_status], rejections()),
           S3 = yuzu_gw_mgmt_crl_source:load(P, S2, ok_fetch("crl-empty.der"), ?NOW),
           ?assertMatch(#{number := 8}, yuzu_gw_mgmt_crl_source:current()),
           ?assertMatch(#{last_reject := undefined}, S3)
       end) end},
      {"a CRL that does not verify never evicts the loaded one",
       fun() -> with_load(fun() ->
           P = policy(),
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           _ = yuzu_gw_mgmt_crl_source:load(P, S1, ok_fetch("crl-evil.der"), ?NOW),
           ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([unverified], rejections())
       end) end},
      {"garbage and a truncated CRL are malformed and keep the loaded one",
       fun() -> with_load(fun() ->
           P = policy(),
           Good = crl("crl-populated.der"),
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           Truncated = binary:part(Good, 0, byte_size(Good) - 20),
           lists:foreach(fun(Bad) ->
                                 yuzu_gw_mgmt_crl_source:load(P, S1, fun(_, _) -> {ok, Bad, undefined} end, ?NOW)
                         end, [<<"garbage">>, Truncated, <<>>]),
           ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([malformed, malformed, malformed], rejections())
       end) end},
      {"an older CRL (replay) is refused and counted, the loaded one stands",
       fun() -> with_load(fun() ->
           P = policy(),
           %% number 9 (crl-sub) then number 7 (crl-populated): same thisUpdate, lower number
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-sub.der"), ?NOW),
           _ = yuzu_gw_mgmt_crl_source:load(P, S1, ok_fetch("crl-populated.der"), ?NOW),
           ?assertMatch(#{number := 9}, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([replay], rejections())
       end) end},
      {"a higher number replaces at the same thisUpdate (the server clock stepped back)",
       fun() -> with_load(fun() ->
           P = policy(),
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           _ = yuzu_gw_mgmt_crl_source:load(P, S1, ok_fetch("crl-sub.der"), ?NOW),
           ?assertMatch(#{number := 9}, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([], rejections())
       end) end},
      {"the same CRL again is not a rejection",
       fun() -> with_load(fun() ->
           P = policy(),
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           _ = yuzu_gw_mgmt_crl_source:load(P, S1, ok_fetch("crl-populated.der"), ?NOW),
           ?assertEqual([], rejections())
       end) end},
      {"a CRL dated in the future is refused and never loaded",
       fun() -> with_load(fun() ->
           P = policy(),
           _ = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?THIS - 7200),
           ?assertEqual(none, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([future_dated], rejections())
       end) end},
      {"a CRL issued under another name than its verifying certificate is refused",
       fun() -> with_load(fun() ->
           P = policy([yuzu_gw_crl_fixture:path("renamed-ca.pem")]),
           _ = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           ?assertEqual(none, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([issuer_mismatch], rejections())
       end) end},
      {"an unreadable verification file means nothing is verified, and says it could not be read",
       fun() -> with_load(fun() ->
           P = policy(["/no/such/ca.pem"]),
           _ = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           ?assertEqual(none, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([file_unreadable], rejections())
       end) end},
      {"a CA set that changes under a loaded CRL is verified again",
       fun() -> with_load(fun() ->
           %% Same CRL bytes both times; the second time the verifying set no longer holds the
           %% issuing key, so the CRL is NOT trusted again, though the old one stays loaded.
           S1 = yuzu_gw_mgmt_crl_source:load(policy(), state(), ok_fetch("crl-populated.der"), ?NOW),
           _ = yuzu_gw_mgmt_crl_source:load(policy([yuzu_gw_crl_fixture:path("evil-ca.pem")]), S1,
                                            ok_fetch("crl-populated.der"), ?NOW),
           ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current()),
           ?assertEqual([unverified], rejections())
       end) end},
      {"the same reason repeated is counted every time, logged once",
       fun() -> with_load(fun() ->
           P = policy(),
           F = fun(_, _) -> {error, fetch_timeout} end,
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), F, ?NOW),
           S2 = yuzu_gw_mgmt_crl_source:load(P, S1, F, ?NOW),
           _ = yuzu_gw_mgmt_crl_source:load(P, S2, F, ?NOW),
           ?assertEqual([fetch_timeout, fetch_timeout, fetch_timeout], rejections())
       end) end},
      {"not_modified changes nothing and is no rejection",
       fun() -> with_load(fun() ->
           P = policy(),
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), ok_fetch("crl-populated.der"), ?NOW),
           S2 = yuzu_gw_mgmt_crl_source:load(P, S1, fun(_, _) -> not_modified end, ?NOW),
           ?assertEqual(S1, S2),
           ?assertEqual([], rejections())
       end) end},
      {"the ETag the server sent is remembered for the next request",
       fun() -> with_load(fun() ->
           P = policy(),
           Bin = crl("crl-populated.der"),
           S1 = yuzu_gw_mgmt_crl_source:load(P, state(), fun(_, _) -> {ok, Bin, <<"\"7\"">>} end, ?NOW),
           ?assertMatch(#{etag := <<"\"7\"">>}, S1)
       end) end},
      {"every reason a rejection can carry is in the closed set",
       fun() ->
           Set = yuzu_gw_mgmt_crl_source:reject_reasons(),
           ?assertEqual(length(Set), length(lists:usort(Set))),
           [?assert(lists:member(R, Set))
            || R <- [malformed, too_large, unverified, issuer_mismatch, future_dated, replay,
                     fetch_timeout, fetch_connect, fetch_tls, fetch_status, fetch_error,
                     file_unreadable]]
       end}]}.

%%--------------------------------------------------------------------
%% Fetch: a file
%%--------------------------------------------------------------------

file_fetch_test_() ->
    {setup,
     fun() ->
             Dir = filename:join("/tmp", "yuzu_test_crl_src_" ++
                                 binary_to_list(binary:encode_hex(crypto:strong_rand_bytes(8)))),
             ok = filelib:ensure_dir(filename:join(Dir, "x")),
             Dir
     end,
     fun(Dir) -> _ = os:cmd("rm -rf '" ++ Dir ++ "'"), ok end,
     fun(Dir) ->
             F = fun(Name) -> filename:join(Dir, Name) end,
             Fetch = fun(Path) ->
                             yuzu_gw_mgmt_crl_source:fetch(#{source => {file, Path}}, state(), 1000)
                     end,
             [{"a file is read whole",
               fun() ->
                       ok = file:write_file(F("a.der"), crl("crl-populated.der")),
                       ?assertEqual({ok, crl("crl-populated.der"), undefined}, Fetch(F("a.der")))
               end},
              {"a missing file is unreadable",
               ?_assertEqual({error, file_unreadable}, Fetch(F("absent.der")))},
              {"a directory is unreadable",
               ?_assertEqual({error, file_unreadable}, Fetch(Dir))},
              {"an empty file is malformed",
               fun() ->
                       ok = file:write_file(F("empty.der"), <<>>),
                       ?assertEqual({error, malformed}, Fetch(F("empty.der")))
               end},
              {"a file past the bound is too_large and never read whole",
               fun() ->
                       Max = yuzu_gw_mgmt_crl:max_bytes(),
                       ok = file:write_file(F("big.der"), binary:copy(<<0>>, Max + 1)),
                       ?assertEqual({error, too_large}, Fetch(F("big.der")))
               end},
              {"a file exactly at the bound is read (and then fails as a CRL, not as too large)",
               fun() ->
                       Max = yuzu_gw_mgmt_crl:max_bytes(),
                       ok = file:write_file(F("edge.der"), binary:copy(<<0>>, Max)),
                       ?assertMatch({ok, B, undefined} when byte_size(B) =:= Max, Fetch(F("edge.der")))
               end}]
     end}.

%%--------------------------------------------------------------------
%% Fetch: a TLS server
%%--------------------------------------------------------------------

https_test_() ->
    {setup,
     fun() ->
             {ok, _} = application:ensure_all_started(gun),
             yuzu_gw_authz_tests:setup_certs()
     end,
     fun yuzu_gw_authz_tests:cleanup_certs/1,
     fun({error, Why}) -> yuzu_gw_authz_tests:certs_unavailable("yuzu_gw_mgmt_crl_source_tests", Why);
        (#{dir := Dir, ca := Ca, srv_pem := Srv}) ->
        Key = filename:join(Dir, "srv.key"),
        Serve = fun(Handler) -> start_server(Srv, Key, Handler) end,
        Url = fun(Host, Port) ->
                      #{host => Host, port => Port, path => "/api/v1/ca/crl", cacertfile => Ca}
              end,
        Get = fun(U, Etag, Timeout) ->
                      yuzu_gw_mgmt_crl_source:fetch(#{source => {url, U}}, #{etag => Etag}, Timeout)
              end,
        Body = crl("crl-populated.der"),
        [{"a 200 returns the body and the ETag",
          fun() ->
              {Port, Stop} = Serve(respond(200, Body, [{"ETag", "\"7\""}])),
              try ?assertEqual({ok, Body, <<"\"7\"">>}, Get(Url("127.0.0.1", Port), undefined, 3000))
              after Stop() end
          end},
         {"the request carries If-None-Match once an ETag is known, and a 304 is not_modified",
          fun() ->
              {Port, Stop} = Serve(fun(Sock, Req) ->
                                           case binary:match(string:lowercase(Req),
                                                             <<"if-none-match: \"7\"">>) of
                                               nomatch -> send(Sock, 200, Body, []);
                                               _ -> send(Sock, 304, <<>>, [])
                                           end
                                   end),
              try
                  ?assertEqual({ok, Body, undefined}, Get(Url("127.0.0.1", Port), undefined, 3000)),
                  ?assertEqual(not_modified, Get(Url("127.0.0.1", Port), <<"\"7\"">>, 3000))
              after Stop() end
          end},
         {"a 500 is fetch_status",
          fun() ->
              {Port, Stop} = Serve(respond(500, <<"boom">>, [])),
              try ?assertEqual({error, fetch_status}, Get(Url("127.0.0.1", Port), undefined, 3000))
              after Stop() end
          end},
         {"a 404 is fetch_status",
          fun() ->
              {Port, Stop} = Serve(respond(404, <<"no">>, [])),
              try ?assertEqual({error, fetch_status}, Get(Url("127.0.0.1", Port), undefined, 3000))
              after Stop() end
          end},
         {"a redirect is NOT followed: it is fetch_status (the no-redirect contract is pinned)",
          fun() ->
              [begin
                   {Port, Stop} = Serve(respond(Status, <<>>, [{"Location", "https://elsewhere.invalid/crl"}])),
                   try ?assertEqual({error, fetch_status}, Get(Url("127.0.0.1", Port), undefined, 3000))
                   after Stop() end
               end || Status <- [301, 302, 307, 308]]
          end},
         {"a server that never answers is fetch_timeout, within the budget",
          fun() ->
              {Port, Stop} = Serve(fun(_Sock, _Req) -> timer:sleep(30000) end),
              try
                  T0 = erlang:monotonic_time(millisecond),
                  ?assertEqual({error, fetch_timeout}, Get(Url("127.0.0.1", Port), undefined, 500)),
                  ?assert(erlang:monotonic_time(millisecond) - T0 < 3000)
              after Stop() end
          end},
         {"a body that trickles past the deadline is fetch_timeout",
          fun() ->
              {Port, Stop} = Serve(fun(Sock, _Req) ->
                                           ok = ssl:send(Sock, <<"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n">>),
                                           timer:sleep(30000)
                                   end),
              try ?assertEqual({error, fetch_timeout}, Get(Url("127.0.0.1", Port), undefined, 500))
              after Stop() end
          end},
         {"a connection refused is fetch_connect",
          fun() ->
              {Port, Stop} = Serve(respond(200, Body, [])),
              Stop(),
              ?assertEqual({error, fetch_connect}, Get(Url("127.0.0.1", Port), undefined, 3000))
          end},
         {"a certificate the fetch CA did not issue is fetch_tls",
          fun() ->
              {Port, Stop} = Serve(respond(200, Body, [])),
              try
                  Wrong = (Url("127.0.0.1", Port))#{cacertfile => root_pem()},
                  ?assertEqual({error, fetch_tls}, Get(Wrong, undefined, 3000))
              after Stop() end
          end},
         {"a host name the certificate does not carry is fetch_tls",
          fun() ->
              {Port, Stop} = Serve(respond(200, Body, [])),
              try ?assertEqual({error, fetch_tls}, Get(Url("127.0.0.2", Port), undefined, 3000))
              after Stop() end
          end},
         {"a body past the bound is aborted mid-stream as too_large",
          fun() ->
              Max = yuzu_gw_mgmt_crl:max_bytes(),
              {Port, Stop} = Serve(fun(Sock, _Req) ->
                                           ok = ssl:send(Sock, <<"HTTP/1.1 200 OK\r\n"
                                                                 "Transfer-Encoding: chunked\r\n\r\n">>),
                                           chunks(Sock, Max + 1048576)
                                   end),
              try ?assertEqual({error, too_large}, Get(Url("127.0.0.1", Port), undefined, 20000))
              after Stop() end
          end},
         {"a declared length past the bound is too_large before any body is read",
          fun() ->
              {Port, Stop} = Serve(fun(Sock, _Req) ->
                                           ok = ssl:send(Sock, <<"HTTP/1.1 200 OK\r\n"
                                                                 "Content-Length: 99999999999\r\n\r\n">>),
                                           timer:sleep(30000)
                                   end),
              try ?assertEqual({error, too_large}, Get(Url("127.0.0.1", Port), undefined, 3000))
              after Stop() end
          end},
         {"a fetch never raises, whatever it is handed",
          fun() ->
              {Port, Stop} = Serve(respond(200, Body, [])),
              Stop(),
              ?assertMatch({error, _}, yuzu_gw_mgmt_crl_source:fetch(
                                         #{source => {url, #{host => "no-such-host.invalid",
                                                              port => Port, path => "/", cacertfile => Ca}}},
                                         #{etag => undefined}, 1500))
          end},
         {"end to end: the fetched bytes load and publish",
          fun() ->
              {Port, Stop} = Serve(respond(200, Body, [])),
              yuzu_gw_mgmt_crl_source:reset(),
              try
                  P = (policy())#{source => {url, Url("127.0.0.1", Port)}},
                  ok = yuzu_gw_mgmt_crl_source:publish_policy(P),
                  _ = yuzu_gw_mgmt_crl_source:load(
                        P, state(), fun(Pol, St) -> yuzu_gw_mgmt_crl_source:fetch(Pol, St, 3000) end,
                        ?NOW),
                  ?assertMatch(#{number := 7}, yuzu_gw_mgmt_crl_source:current())
              after Stop(), yuzu_gw_mgmt_crl_source:reset() end
          end}]
     end}.

%%--------------------------------------------------------------------
%% A canned HTTPS server
%%--------------------------------------------------------------------

respond(Status, Body, Headers) ->
    fun(Sock, _Req) -> send(Sock, Status, Body, Headers) end.

send(Sock, Status, Body, Headers) ->
    Reason = case Status of 200 -> "OK"; 304 -> "Not Modified"; 404 -> "Not Found"; _ when Status >= 300, Status < 400 -> "Redirect"; _ -> "Error" end,
    Head = [io_lib:format("HTTP/1.1 ~b ~s\r\n", [Status, Reason]),
            [io_lib:format("~s: ~s\r\n", [K, V]) || {K, V} <- Headers],
            io_lib:format("Content-Length: ~b\r\nConnection: close\r\n\r\n", [byte_size(Body)])],
    _ = ssl:send(Sock, [Head, Body]),
    _ = ssl:close(Sock),
    ok.

chunks(_Sock, Left) when Left =< 0 ->
    ok;
chunks(Sock, Left) ->
    Size = min(Left, 65536),
    case ssl:send(Sock, [io_lib:format("~.16b\r\n", [Size]), binary:copy(<<$x>>, Size), "\r\n"]) of
        ok -> chunks(Sock, Left - Size);
        {error, _} -> ok
    end.

start_server(Cert, Key, Handler) ->
    {ok, L} = ssl:listen(0, [{certfile, Cert}, {keyfile, Key}, {reuseaddr, true},
                             {active, false}, binary, {ip, {0, 0, 0, 0}},
                             {versions, ['tlsv1.3', 'tlsv1.2']}]),
    {ok, {_, Port}} = ssl:sockname(L),
    Acceptor = spawn(fun() -> accept(L, Handler) end),
    {Port, fun() ->
                   _ = ssl:close(L),
                   exit(Acceptor, kill),
                   ok
           end}.

accept(L, Handler) ->
    case ssl:transport_accept(L, 5000) of
        {ok, S} ->
            _ = spawn(fun() ->
                              case ssl:handshake(S, 5000) of
                                  {ok, TS} -> serve(TS, Handler, <<>>);
                                  {error, _} -> ok
                              end
                      end),
            accept(L, Handler);
        {error, timeout} -> accept(L, Handler);
        {error, _} -> ok
    end.

serve(Sock, Handler, Acc) ->
    case binary:match(Acc, <<"\r\n\r\n">>) of
        nomatch ->
            case ssl:recv(Sock, 0, 5000) of
                {ok, Data} -> serve(Sock, Handler, <<Acc/binary, Data/binary>>);
                {error, _} -> ok
            end;
        _ ->
            Handler(Sock, Acc)
    end.
