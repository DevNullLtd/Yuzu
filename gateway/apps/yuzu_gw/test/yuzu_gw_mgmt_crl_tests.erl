%%% @doc yuzu_gw_mgmt_crl: parsing, verification, the replace rule and the per-stream check
%%% (#6016 PR 4b). Every CRL here is one the C++ server built (fixtures/crl/README.md).
-module(yuzu_gw_mgmt_crl_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%% thisUpdate of every fixture CRL: 2026-11-02T14:14:48Z.
-define(THIS, 1793628888).
-define(NEXT, (?THIS + 300 + 48 * 3600)).
-define(NOW, (?THIS + 600)).

root() -> yuzu_gw_crl_fixture:cert_der("root-ca.pem").
sub() -> yuzu_gw_crl_fixture:cert_der("sub-ca.pem").
evil() -> yuzu_gw_crl_fixture:cert_der("evil-ca.pem").
renamed() -> yuzu_gw_crl_fixture:cert_der("renamed-ca.pem").
server() -> yuzu_gw_crl_fixture:cert_der("server.pem").
other() -> yuzu_gw_crl_fixture:cert_der("other.pem").
crl(N) -> yuzu_gw_crl_fixture:read(N).

loaded(Name) ->
    {ok, Crl} = yuzu_gw_mgmt_crl:parse(crl(Name), [root()], ?NOW),
    Crl.

%%--------------------------------------------------------------------
%% time_to_epoch/1
%%--------------------------------------------------------------------

times_test_() ->
    [?_assertEqual(?THIS, yuzu_gw_mgmt_crl:time_to_epoch({utcTime, "261102141448Z"})),
     ?_assertEqual(?THIS, yuzu_gw_mgmt_crl:time_to_epoch({generalTime, "20261102141448Z"})),
     %% RFC 5280: two-digit years 50..99 are 19xx, 00..49 are 20xx.
     ?_assertEqual(-631152000, yuzu_gw_mgmt_crl:time_to_epoch({utcTime, "500101000000Z"})),
     ?_assertEqual(2524521600, yuzu_gw_mgmt_crl:time_to_epoch({utcTime, "491231000000Z"})),
     ?_assertEqual(2556144000, yuzu_gw_mgmt_crl:time_to_epoch({generalTime, "20510101000000Z"}))].

%%--------------------------------------------------------------------
%% parse/3
%%--------------------------------------------------------------------

parse_populated_test() ->
    {ok, #{number := 7, this_update := ?THIS, next_update := ?NEXT, revoked := Revoked}} =
        yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [root()], ?NOW),
    ?assertEqual(#{yuzu_gw_crl_fixture:server_serial() => true}, Revoked).

parse_empty_test() ->
    ?assertMatch({ok, #{number := 8, revoked := R}} when map_size(R) =:= 0,
                 yuzu_gw_mgmt_crl:parse(crl("crl-empty.der"), [root()], ?NOW)).

parse_accepts_pem_test() ->
    Pem = public_key:pem_encode([{'CertificateList', crl("crl-populated.der"), not_encrypted}]),
    ?assertMatch({ok, #{number := 7}}, yuzu_gw_mgmt_crl:parse(Pem, [root()], ?NOW)).

parse_verifies_against_any_certificate_of_the_set_test() ->
    %% A bundle: the issuing certificate need not be first.
    ?assertMatch({ok, #{number := 7}},
                 yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [evil(), root()], ?NOW)),
    ?assertMatch({ok, #{number := 99}},
                 yuzu_gw_mgmt_crl:parse(crl("crl-evil.der"), [root(), evil()], ?NOW)).

%% A subordinate-CA install keeps the issuing key and the issuer name; its CRL's AKI names a
%% different key identifier than the self-signed root's SKI.
parse_subordinate_crl_verifies_against_the_root_test() ->
    ?assertMatch({ok, #{number := 9}},
                 yuzu_gw_mgmt_crl:parse(crl("crl-sub.der"), [root()], ?NOW)).

parse_wrong_key_is_unverified_test() ->
    %% Same issuer name, another key: a name match is not authenticity.
    ?assertEqual({error, unverified},
                 yuzu_gw_mgmt_crl:parse(crl("crl-evil.der"), [root()], ?NOW)),
    ?assertEqual({error, unverified},
                 yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [evil()], ?NOW)).

parse_empty_verification_set_is_unverified_test() ->
    ?assertEqual({error, unverified},
                 yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [], ?NOW)).

%% The signature verifies, the issuer NAME is not the verifying certificate's.
parse_issuer_name_must_be_the_verifying_certificates_test() ->
    ?assertEqual({error, issuer_mismatch},
                 yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [renamed()], ?NOW)).

parse_malformed_input_never_raises_test_() ->
    Good = crl("crl-populated.der"),
    Mid = byte_size(Good) div 2,
    <<Pre:Mid/binary, B, Post/binary>> = Good,
    Garbled = <<Pre/binary, (B bxor 16#ff), Post/binary>>,
    Truncated = binary:part(Good, 0, byte_size(Good) - 20),
    [?_assertEqual({error, malformed}, yuzu_gw_mgmt_crl:parse(Bin, [root()], ?NOW))
     || Bin <- [<<>>, <<"not a crl">>, Truncated, Garbled,
                <<"-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n">>]]
        ++ [?_assertEqual({error, malformed}, yuzu_gw_mgmt_crl:parse(Bad, [root()], ?NOW))
            || Bad <- [undefined, 42, "string", {tuple}]]
        ++ [?_assertEqual({error, malformed}, yuzu_gw_mgmt_crl:parse(Good, not_a_list, ?NOW)),
            ?_assertEqual({error, malformed}, yuzu_gw_mgmt_crl:parse(Good, [root()], not_time))].

%% A signature flip that leaves the ASN.1 intact decodes and then fails verification.
parse_flipped_signature_is_not_loaded_test() ->
    Good = crl("crl-populated.der"),
    Last = byte_size(Good) - 1,
    <<Pre:Last/binary, B>> = Good,
    ?assertMatch({error, _},
                 yuzu_gw_mgmt_crl:parse(<<Pre/binary, (B bxor 1)>>, [root()], ?NOW)).

parse_a_certificate_bytes_are_malformed_test() ->
    ?assertEqual({error, malformed}, yuzu_gw_mgmt_crl:parse(root(), [root()], ?NOW)).

parse_over_the_byte_bound_test() ->
    Max = yuzu_gw_mgmt_crl:max_bytes(),
    ?assertEqual({error, too_large},
                 yuzu_gw_mgmt_crl:parse(binary:copy(<<0>>, Max + 1), [root()], ?NOW)),
    %% At the bound it is read (and is garbage, not too large).
    ?assertEqual({error, malformed},
                 yuzu_gw_mgmt_crl:parse(binary:copy(<<0>>, Max), [root()], ?NOW)).

parse_future_dated_test() ->
    Max = yuzu_gw_mgmt_crl:max_future_s(),
    %% thisUpdate exactly at the allowance is accepted; one second beyond is not.
    ?assertMatch({ok, _}, yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [root()],
                                                 ?THIS - Max)),
    ?assertEqual({error, future_dated},
                 yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [root()], ?THIS - Max - 1)),
    %% 30 minutes ahead is accepted, 2 hours ahead is not.
    ?assertMatch({ok, _}, yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [root()],
                                                 ?THIS - 1800)),
    ?assertEqual({error, future_dated},
                 yuzu_gw_mgmt_crl:parse(crl("crl-populated.der"), [root()], ?THIS - 7200)).

%%--------------------------------------------------------------------
%% replace/2
%%--------------------------------------------------------------------

crl_map(Number, This) ->
    #{number => Number, this_update => This, next_update => This + 100000,
      issuer => issuer, signers => [], revoked => #{}}.

replace_first_load_test() ->
    New = crl_map(5, 1000),
    ?assertEqual({replace, New}, yuzu_gw_mgmt_crl:replace(none, New)).

replace_truth_table_test_() ->
    Old = crl_map(10, 1000),
    [%% newer time AND higher number
     ?_assertMatch({replace, _}, yuzu_gw_mgmt_crl:replace(Old, crl_map(11, 2000))),
     %% restore from backup: lower number, later time
     ?_assertMatch({replace, _}, yuzu_gw_mgmt_crl:replace(Old, crl_map(3, 2000))),
     %% server clock stepped back: earlier time, higher number
     ?_assertMatch({replace, _}, yuzu_gw_mgmt_crl:replace(Old, crl_map(11, 500))),
     %% same time, higher number; later time, same number
     ?_assertMatch({replace, _}, yuzu_gw_mgmt_crl:replace(Old, crl_map(11, 1000))),
     ?_assertMatch({replace, _}, yuzu_gw_mgmt_crl:replace(Old, crl_map(10, 1001))),
     %% replay of an older CRL: earlier AND lower
     ?_assertEqual({reject, replay}, yuzu_gw_mgmt_crl:replace(Old, crl_map(9, 999))),
     %% earlier, same number; same time, lower number
     ?_assertEqual({reject, replay}, yuzu_gw_mgmt_crl:replace(Old, crl_map(10, 999))),
     ?_assertEqual({reject, replay}, yuzu_gw_mgmt_crl:replace(Old, crl_map(9, 1000))),
     %% the identical CRL again is not news and not an error
     ?_assertEqual(unchanged, yuzu_gw_mgmt_crl:replace(Old, crl_map(10, 1000))),
     %% same number and time but different content: not the same CRL, and not newer
     ?_assertEqual({reject, replay},
                   yuzu_gw_mgmt_crl:replace(Old, (crl_map(10, 1000))#{revoked => #{1 => true}}))].

%%--------------------------------------------------------------------
%% check/4
%%--------------------------------------------------------------------

check_nothing_loaded_test() ->
    ?assertEqual({reject, revocation_unknown},
                 yuzu_gw_mgmt_crl:check(none, other(), ?NOW, 86400)).

check_admits_an_unlisted_serial_test() ->
    ?assertEqual(ok, yuzu_gw_mgmt_crl:check(loaded("crl-populated.der"), other(), ?NOW, 86400)).

check_refuses_a_listed_serial_test() ->
    ?assertEqual({reject, crl_revoked},
                 yuzu_gw_mgmt_crl:check(loaded("crl-populated.der"), server(), ?NOW, 86400)).

check_an_empty_crl_admits_everything_it_was_issued_for_test() ->
    Empty = loaded("crl-empty.der"),
    ?assertEqual(ok, yuzu_gw_mgmt_crl:check(Empty, server(), ?NOW, 86400)),
    ?assertEqual(ok, yuzu_gw_mgmt_crl:check(Empty, other(), ?NOW, 86400)).

%% A peer issued by another root than the CRL's: the CRL says nothing about it.
check_a_peer_of_another_issuer_is_unknown_test() ->
    ?assertEqual({reject, revocation_unknown},
                 yuzu_gw_mgmt_crl:check(loaded("crl-populated.der"), sub(), ?NOW, 86400)).

check_freshness_boundary_test_() ->
    Crl = loaded("crl-populated.der"),
    Grace = 86400,
    Edge = ?NEXT + Grace,
    [?_assertEqual(ok, yuzu_gw_mgmt_crl:check(Crl, other(), ?NEXT, Grace)),
     ?_assertEqual(ok, yuzu_gw_mgmt_crl:check(Crl, other(), ?NEXT + 1, Grace)),
     ?_assertEqual(ok, yuzu_gw_mgmt_crl:check(Crl, other(), Edge, Grace)),
     ?_assertEqual({reject, revocation_stale}, yuzu_gw_mgmt_crl:check(Crl, other(), Edge + 1, Grace)),
     %% stale outranks revoked: a CRL that is too old proves nothing about any serial
     ?_assertEqual({reject, revocation_stale}, yuzu_gw_mgmt_crl:check(Crl, server(), Edge + 1, Grace)),
     %% zero grace: stale the second after nextUpdate
     ?_assertEqual(ok, yuzu_gw_mgmt_crl:check(Crl, other(), ?NEXT, 0)),
     ?_assertEqual({reject, revocation_stale}, yuzu_gw_mgmt_crl:check(Crl, other(), ?NEXT + 1, 0))].

check_unreadable_peer_test_() ->
    Crl = loaded("crl-populated.der"),
    [?_assertEqual({reject, bad_peer_cert}, yuzu_gw_mgmt_crl:check(Crl, Bad, ?NOW, 86400))
     || Bad <- [<<>>, <<"garbage">>, undefined]].

check_issuer_of_cert_test() ->
    ?assertMatch({ok, {rdnSequence, _}}, yuzu_gw_mgmt_crl:issuer_of_cert(server())),
    ?assertEqual(error, yuzu_gw_mgmt_crl:issuer_of_cert(<<"x">>)).

%%--------------------------------------------------------------------
%% ca_certs/1
%%--------------------------------------------------------------------

ca_certs_test_() ->
    Bundle = <<(yuzu_gw_crl_fixture:read("root-ca.pem"))/binary,
               (yuzu_gw_crl_fixture:read("evil-ca.pem"))/binary>>,
    [?_assertEqual([root()], yuzu_gw_mgmt_crl:ca_certs(yuzu_gw_crl_fixture:read("root-ca.pem"))),
     ?_assertEqual([root(), evil()], yuzu_gw_mgmt_crl:ca_certs(Bundle)),
     ?_assertEqual([], yuzu_gw_mgmt_crl:ca_certs(<<>>)),
     ?_assertEqual([], yuzu_gw_mgmt_crl:ca_certs(<<"not pem">>)),
     ?_assertEqual([], yuzu_gw_mgmt_crl:ca_certs(undefined))].

%%--------------------------------------------------------------------
%% A CRL the CA would not publish is refused as malformed before any signature question
%% (the entry is re-encoded with the original, now invalid, signature, so a defect that is only
%% caught later would read `unverified' instead)
%%--------------------------------------------------------------------

tampered(Fun) ->
    Rec = public_key:der_decode('CertificateList', crl("crl-populated.der")),
    Tbs = Rec#'CertificateList'.tbsCertList,
    public_key:der_encode('CertificateList', Rec#'CertificateList'{tbsCertList = Fun(Tbs)}).

hostile_crl_test_() ->
    P = fun(Bin) -> yuzu_gw_mgmt_crl:parse(Bin, [root()], ?NOW) end,
    Rev = fun(Serial) ->
                  fun(Tbs) ->
                          [E | _] = Tbs#'TBSCertList'.revokedCertificates,
                          Tbs#'TBSCertList'{revokedCertificates =
                              [E#'TBSCertList_revokedCertificates_SEQOF'{userCertificate = Serial}]}
                  end
          end,
    [{"control: a re-encoding with nothing changed still verifies (so the cases below fail for their own reason)",
      ?_assertMatch({ok, _}, P(tampered(fun(T) -> T end)))},
     {"nextUpdate before thisUpdate",
      ?_assertEqual({error, malformed},
                    P(tampered(fun(T) -> T#'TBSCertList'{thisUpdate = T#'TBSCertList'.nextUpdate,
                                                         nextUpdate = T#'TBSCertList'.thisUpdate}
                               end)))},
     {"nextUpdate equal to thisUpdate",
      ?_assertEqual({error, malformed},
                    P(tampered(fun(T) -> T#'TBSCertList'{nextUpdate = T#'TBSCertList'.thisUpdate}
                               end)))},
     {"a negative serial",
      ?_assertEqual({error, malformed}, P(tampered(Rev(-5))))},
     {"a serial of more than 20 octets",
      ?_assertEqual({error, malformed}, P(tampered(Rev(1 bsl 170))))},
     {"the largest serial RFC 5280 allows is accepted as far as the signature",
      ?_assertEqual({error, unverified}, P(tampered(Rev((1 bsl 160) - 1))))}].
