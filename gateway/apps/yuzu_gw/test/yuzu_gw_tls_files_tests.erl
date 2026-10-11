%%%-------------------------------------------------------------------
%%% @doc yuzu_gw_tls_files: what is wrong with the files an upstream endpoint's
%%% TLS options name. Real files in a fresh 0700 directory.
%%%
%%% Pinned: every reason (missing, directory, empty, garbage, a certificate where
%%% a key belongs and the reverse, unreadable), that a good file is no problem,
%%% that a keyfile's path is never returned, and that only a directory or other
%%% non-file counts as a definite defect (a missing file may appear later).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_tls_files_tests).
-include_lib("eunit/include/eunit.hrl").

%% Certificates come from the openssl CLI (yuzu_gw_authz_tests), as the other TLS
%% suites do: public_key:pkix_test_data/1 cannot sign on a host whose OpenSSL
%% refuses its default digest. Without openssl these tests contribute nothing
%% unless YUZU_REQUIRE_TLS_TESTS=1.
files_test_() ->
    {setup, fun yuzu_gw_authz_tests:setup_certs/0, fun yuzu_gw_authz_tests:cleanup_certs/1,
     fun({error, Why}) -> yuzu_gw_authz_tests:certs_unavailable("yuzu_gw_tls_files_tests", Why);
        (#{dir := Dir, ca := Cert}) ->
        Key = filename:join(Dir, "srv.key"),
        P = fun(Name) -> filename:join(Dir, Name) end,
        [{"good CA, certificate and key are no problem",
          fun() ->
              ?assertEqual([], yuzu_gw_tls_files:diagnose(
                                 [{cacertfile, Cert}, {certfile, Cert}, {keyfile, Key}]))
          end},
         {"a missing file is enoent and not a definite defect",
          fun() ->
              Missing = P("absent.pem"),
              Problems = yuzu_gw_tls_files:diagnose([{cacertfile, Missing}]),
              ?assertEqual([{cacertfile, Missing, enoent}], Problems),
              ?assertNot(yuzu_gw_tls_files:has_definite_defect(Problems))
          end},
         {"a directory is a definite defect",
          fun() ->
              Problems = yuzu_gw_tls_files:diagnose([{cacertfile, Dir}]),
              ?assertEqual([{cacertfile, Dir, directory}], Problems),
              ?assert(yuzu_gw_tls_files:has_definite_defect(Problems))
          end},
         {"an empty file is empty, and not a definite defect",
          fun() ->
              ok = file:write_file(P("empty.pem"), <<>>),
              Problems = yuzu_gw_tls_files:diagnose([{cacertfile, P("empty.pem")}]),
              ?assertEqual([{cacertfile, P("empty.pem"), empty}], Problems),
              ?assertNot(yuzu_gw_tls_files:has_definite_defect(Problems))
          end},
         {"text that is not PEM holds no certificate",
          fun() ->
              ok = file:write_file(P("junk.pem"), <<"not a certificate\n">>),
              ?assertEqual([{cacertfile, P("junk.pem"), no_certificate}],
                           yuzu_gw_tls_files:diagnose([{cacertfile, P("junk.pem")}]))
          end},
         {"a key where a certificate belongs holds no certificate",
          fun() ->
              ?assertEqual([{certfile, Key, no_certificate}],
                           yuzu_gw_tls_files:diagnose([{certfile, Key}]))
          end},
         {"a certificate where a key belongs holds no key, and the keyfile path is withheld",
          fun() ->
              ?assertEqual([{keyfile, undefined, no_key}],
                           yuzu_gw_tls_files:diagnose([{keyfile, Cert}]))
          end},
         {"a missing keyfile reports no path either",
          fun() ->
              ?assertEqual([{keyfile, undefined, enoent}],
                           yuzu_gw_tls_files:diagnose([{keyfile, P("nokey.pem")}]))
          end},
         {"several problems are all reported, CA first",
          fun() ->
              Got = yuzu_gw_tls_files:diagnose([{keyfile, P("k")}, {certfile, P("c")},
                                                {cacertfile, P("a")}]),
              ?assertMatch([{cacertfile, _, enoent}, {certfile, _, enoent},
                            {keyfile, undefined, enoent}], Got)
          end},
         {"options that are absent or not paths are not checked",
          fun() ->
              ?assertEqual([], yuzu_gw_tls_files:diagnose([])),
              ?assertEqual([], yuzu_gw_tls_files:diagnose(
                                 [{verify, verify_peer}, {cacertfile, <<>>}, {certfile, []},
                                  {keyfile, #{}}, {cacertfile, undefined}]))
          end},
         {"a binary path works as a string path does",
          fun() ->
              ?assertEqual([], yuzu_gw_tls_files:diagnose([{cacertfile, list_to_binary(Cert)}]))
          end},
         {"an unreadable file is eacces (skipped when running as root)",
          fun() ->
              F = P("noread.pem"),
              ok = file:write_file(F, <<"x">>),
              ok = file:change_mode(F, 8#000),
              case file:read_file(F) of
                  {error, eacces} ->
                      ?assertEqual([{cacertfile, F, eacces}],
                                   yuzu_gw_tls_files:diagnose([{cacertfile, F}]));
                  _ ->
                      ok
              end
          end},
         {"a plaintext endpoint has nothing to check; a TLS one is checked",
          fun() ->
              ?assertEqual([], yuzu_gw_tls_files:diagnose_endpoint(
                                 #{transport => tcp, tls_opts => [{cacertfile, P("absent.pem")}]})),
              ?assertEqual([{cacertfile, P("absent.pem"), enoent}],
                           yuzu_gw_tls_files:diagnose_endpoint(
                             #{transport => tls, tls_opts => [{cacertfile, P("absent.pem")}]}))
          end},
         {"describe names the option and path, never a key path",
          fun() ->
              ?assertEqual("cacertfile /x/ca.pem does not exist (yet)",
                           yuzu_gw_tls_files:describe({cacertfile, "/x/ca.pem", enoent})),
              ?assertEqual("keyfile contains no PEM private key",
                           yuzu_gw_tls_files:describe({keyfile, undefined, no_key})),
              ?assertEqual("certfile /x/c.pem cannot be read (eio)",
                           yuzu_gw_tls_files:describe({certfile, "/x/c.pem", eio}))
          end}]
     end}.
