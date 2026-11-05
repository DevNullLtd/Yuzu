%%% @doc What a CRL must be to count as the issuer's COMPLETE list, and whose list it is
%%% (#6016 PR 4b, review round on PR #7060).
%%%
%%% Two properties, each of which a reviewer reproduced against the first version of
%%% yuzu_gw_mgmt_crl:
%%%
%%%   1. A CRL carrying anything that makes it something other than the issuer's full list (a delta,
%%%      a scoped list, an indirect list, an entry that un-revokes, an extension the CA marked
%%%      critical that this module does not understand) is refused `malformed'. Accepting one let a
%%%      delta with a higher cRLNumber replace the full list and drop serials only the base listed.
%%%
%%%   2. A loaded CRL covers a peer only when the peer certificate verifies under a key that signed
%%%      the CRL. A matching issuer NAME is not enough: two CAs can share one (the server CA's
%%%      subject is `Yuzu Install CA (<hostname>)', reused by a same-host re-root), and serial numbers
%%%      are only unique per issuing key.
%%%
%%% The CRLs here are built by yuzu_gw_crl_build (shapes only another CA or a hostile feed can
%%% produce); the second property is also run against the C++ server's own fixtures.
-module(yuzu_gw_mgmt_crl_scope_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

%% thisUpdate of every CRL built here and of the fixtures: 2026-11-02T14:14:48Z.
-define(THIS, 1793628888).
-define(NOW, (?THIS + 600)).
-define(GRACE, 86400).

-define(UNKNOWN_CRITICAL, {1, 3, 6, 1, 4, 1, 99999, 1}).

parse(Crl, Ca) -> yuzu_gw_mgmt_crl:parse(Crl, [maps:get(cert, Ca)], ?NOW).

ca() -> yuzu_gw_crl_build:ca("Yuzu Install CA (test-host)").

%% A CRL with the given CRL-level extensions, otherwise well formed.
with_exts(Exts) ->
    Ca = ca(),
    {yuzu_gw_crl_build:crl(Ca, #{exts => Exts}), Ca}.

%% A CRL listing one serial with the given entry extensions.
with_entry_exts(Exts) ->
    Ca = ca(),
    {yuzu_gw_crl_build:crl(Ca, #{revoked => [{42, Exts}]}), Ca}.

%%--------------------------------------------------------------------
%% The control: the builder makes CRLs the module accepts
%%--------------------------------------------------------------------

builder_baseline_is_accepted_test() ->
    Ca = ca(),
    Crl = yuzu_gw_crl_build:crl(Ca, #{number => 5, revoked => [7, 9]}),
    ?assertMatch({ok, #{number := 5, revoked := #{7 := true, 9 := true}}}, parse(Crl, Ca)).

%%--------------------------------------------------------------------
%% 1. Only the issuer's complete list is loaded
%%--------------------------------------------------------------------

crl_level_extensions_test_() ->
    Delta = fun(Critical) ->
                    yuzu_gw_crl_build:ext(?'id-ce-deltaCRLIndicator', Critical,
                                          public_key:der_encode('CRLNumber', 4))
            end,
    Idp = fun(Critical) ->
                  yuzu_gw_crl_build:ext(?'id-ce-issuingDistributionPoint', Critical, <<48, 0>>)
          end,
    Unknown = fun(Critical) ->
                      yuzu_gw_crl_build:ext(?UNKNOWN_CRITICAL, Critical, <<5, 0>>)
              end,
    Accepted = fun(Exts) ->
                       {Crl, Ca} = with_exts(Exts),
                       ?assertMatch({ok, _}, parse(Crl, Ca))
               end,
    Refused = fun(Exts) -> {Crl, Ca} = with_exts(Exts), parse(Crl, Ca) end,
    [%% a delta CRL is not the issuer's list, critical (as RFC 5280 says it must be) or not
     ?_assertEqual({error, malformed}, Refused([Delta(true)])),
     ?_assertEqual({error, malformed}, Refused([Delta(false)])),
     %% a scoped list covers only some certificates or some reasons
     ?_assertEqual({error, malformed}, Refused([Idp(true)])),
     ?_assertEqual({error, malformed}, Refused([Idp(false)])),
     %% RFC 5280 5.2: a relying party that cannot process a critical extension must not use the CRL
     ?_assertEqual({error, malformed}, Refused([Unknown(true)])),
     %% ... and an extension it does not understand that is NOT critical is ignorable
     ?_test(Accepted([Unknown(false)])),
     %% authorityKeyIdentifier is understood (and only ever a hint), even marked critical
     ?_test(Accepted([yuzu_gw_crl_build:ext(?'id-ce-authorityKeyIdentifier', true, <<48, 0>>)]))].

entry_extensions_test_() ->
    Refused = fun(Exts) -> {Crl, Ca} = with_entry_exts(Exts), parse(Crl, Ca) end,
    Reason = fun(R) ->
                     yuzu_gw_crl_build:ext(?'id-ce-cRLReasons', false,
                                           public_key:der_encode('CRLReason', R))
             end,
    [%% an indirect CRL: the serial is in another issuer's namespace
     ?_assertEqual({error, malformed},
                   Refused([yuzu_gw_crl_build:ext(?'id-ce-certificateIssuer', true, <<48, 0>>)])),
     ?_assertEqual({error, malformed},
                   Refused([yuzu_gw_crl_build:ext(?'id-ce-certificateIssuer', false, <<48, 0>>)])),
     %% removeFromCRL un-revokes: only a delta CRL may say it
     ?_assertEqual({error, malformed}, Refused([Reason(removeFromCRL)])),
     %% an unknown critical entry extension
     ?_assertEqual({error, malformed},
                   Refused([yuzu_gw_crl_build:ext(?UNKNOWN_CRITICAL, true, <<5, 0>>)])),
     %% the ones that change nothing about whether the serial is listed
     ?_assertMatch({ok, #{revoked := #{42 := true}}}, Refused([Reason(keyCompromise)])),
     ?_assertMatch({ok, #{revoked := #{42 := true}}},
                   Refused([yuzu_gw_crl_build:ext(?'id-ce-invalidityDate', false,
                                                  public_key:der_encode('InvalidityDate',
                                                                        "20261102000000Z"))])),
     ?_assertMatch({ok, #{revoked := #{42 := true}}},
                   Refused([yuzu_gw_crl_build:ext(?UNKNOWN_CRITICAL, false, <<5, 0>>)])),
     %% a reasonCode that is not understood-as-a-string must not be taken for "fine"
     ?_assertEqual({error, malformed},
                   Refused([yuzu_gw_crl_build:ext(?'id-ce-cRLReasons', false, <<1, 2, 3>>)]))].

%% The reviewer's scenario end to end: a full CRL lists the serial; a delta with a higher number
%% cannot take its place, so the serial stays revoked.
a_delta_cannot_displace_the_full_list_test() ->
    Ca = ca(),
    Peer = yuzu_gw_crl_build:leaf(Ca),
    Serial = yuzu_gw_crl_build:serial(Peer),
    Full = yuzu_gw_crl_build:crl(Ca, #{number => 10, revoked => [Serial]}),
    Delta = yuzu_gw_crl_build:crl(
              Ca, #{number => 11,
                    exts => [yuzu_gw_crl_build:ext(?'id-ce-deltaCRLIndicator', true,
                                                   public_key:der_encode('CRLNumber', 10))]}),
    {ok, Held} = parse(Full, Ca),
    ?assertEqual({error, malformed}, parse(Delta, Ca)),
    ?assertEqual({reject, crl_revoked}, yuzu_gw_mgmt_crl:check(Held, Peer, ?NOW, ?GRACE)).


%% The boundary of "understood": a critical extension the module understands is accepted, one it does
%% not is refused, and the X.509 scope and ordering extensions are refused even when non-critical.
understood_and_scope_extensions_test_() ->
    Refused = fun(Exts) -> {Crl, Ca} = with_exts(Exts), parse(Crl, Ca) end,
    EntryCrit = fun(Exts) -> {Crl, Ca} = with_entry_exts(Exts), parse(Crl, Ca) end,
    [%% freshestCRL points at deltas: a base CRL that names them is still the base list
     ?_assertMatch({ok, _}, Refused([yuzu_gw_crl_build:ext(?'id-ce-freshestCRL', false, <<48, 0>>)])),
     ?_assertEqual({error, malformed},
                   Refused([yuzu_gw_crl_build:ext(?'id-ce-freshestCRL', true, <<48, 0>>)])),
     %% cRLStreamIdentifier, cRLScope, statusReferrals, orderedList
     ?_assertEqual({error, malformed}, Refused([yuzu_gw_crl_build:ext({2, 5, 29, 40}, false, <<5, 0>>)])),
     ?_assertEqual({error, malformed}, Refused([yuzu_gw_crl_build:ext({2, 5, 29, 44}, false, <<5, 0>>)])),
     ?_assertEqual({error, malformed}, Refused([yuzu_gw_crl_build:ext({2, 5, 29, 45}, false, <<5, 0>>)])),
     ?_assertEqual({error, malformed}, Refused([yuzu_gw_crl_build:ext({2, 5, 29, 47}, false, <<5, 0>>)])),
     %% an understood entry extension is understood even when marked critical
     ?_assertMatch({ok, _},
                   EntryCrit([yuzu_gw_crl_build:ext(?'id-ce-invalidityDate', true,
                                                    public_key:der_encode('InvalidityDate',
                                                                          "20261102000000Z"))]))].

%% cRLNumber is required, and exactly one.
crl_number_is_required_test_() ->
    Ca = ca(),
    Parse = fun(Opts) -> parse(yuzu_gw_crl_build:crl(Ca, Opts), Ca) end,
    Number = yuzu_gw_crl_build:ext(?'id-ce-cRLNumber', false, public_key:der_encode('CRLNumber', 9)),
    [?_assertEqual({error, malformed}, Parse(#{number => none})),
     ?_assertEqual({error, malformed}, Parse(#{number => 1, exts => [Number]})),
     ?_assertMatch({ok, #{number := 1}}, Parse(#{number => 1}))].

%%--------------------------------------------------------------------
%% 2. A CRL covers a peer only when the peer's issuing key signed it
%%--------------------------------------------------------------------

%% Two roots, one subject name, two keys: the same-host re-root. A leaf under B, revoked by B's
%% CRL, must not be admitted because A's (empty) CRL is the one held.
same_name_other_key_is_not_covered_test() ->
    A = ca(),
    B = ca(),
    PeerB = yuzu_gw_crl_build:leaf(B),
    SerialB = yuzu_gw_crl_build:serial(PeerB),
    Both = [maps:get(cert, A), maps:get(cert, B)],
    {ok, HeldB} = yuzu_gw_mgmt_crl:parse(
                    yuzu_gw_crl_build:crl(B, #{number => 2, revoked => [SerialB]}), Both, ?NOW),
    {ok, HeldA} = yuzu_gw_mgmt_crl:parse(
                    yuzu_gw_crl_build:crl(A, #{number => 9}), Both, ?NOW),
    %% the names really are equal: that is what makes this the dangerous case
    ?assertEqual(maps:get(issuer, HeldA), maps:get(issuer, HeldB)),
    ?assertEqual({reject, crl_revoked}, yuzu_gw_mgmt_crl:check(HeldB, PeerB, ?NOW, ?GRACE)),
    ?assertEqual({reject, revocation_unknown}, yuzu_gw_mgmt_crl:check(HeldA, PeerB, ?NOW, ?GRACE)).

%% ... and the CRL of the right key still covers the peers of that key.
same_name_the_signing_key_is_covered_test() ->
    A = ca(),
    B = ca(),
    PeerA = yuzu_gw_crl_build:leaf(A),
    PeerB = yuzu_gw_crl_build:leaf(B),
    Both = [maps:get(cert, B), maps:get(cert, A)],
    {ok, HeldA} = yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_build:crl(A, #{number => 3}), Both, ?NOW),
    ?assertEqual(ok, yuzu_gw_mgmt_crl:check(HeldA, PeerA, ?NOW, ?GRACE)),
    ?assertEqual({reject, revocation_unknown}, yuzu_gw_mgmt_crl:check(HeldA, PeerB, ?NOW, ?GRACE)).

%% The loaded CRL remembers the key(s) that signed it, not the whole verification set.
signers_are_the_verifying_keys_test() ->
    A = ca(),
    B = ca(),
    {ok, #{signers := Signers}} =
        yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_build:crl(A, #{}), [maps:get(cert, B), maps:get(cert, A)],
                               ?NOW),
    ?assertEqual(1, length(Signers)).

%% The same two properties against the C++ server's own certificates and CRLs: evil-ca.pem has the
%% SAME subject DN as root-ca.pem and a DIFFERENT key, and server.pem is issued by root-ca.pem.
fixture_crl_of_the_same_name_other_key_does_not_cover_the_server_test() ->
    Root = yuzu_gw_crl_fixture:cert_der("root-ca.pem"),
    Evil = yuzu_gw_crl_fixture:cert_der("evil-ca.pem"),
    Server = yuzu_gw_crl_fixture:cert_der("server.pem"),
    {ok, Held} = yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_fixture:read("crl-evil.der"), [Root, Evil], ?NOW),
    ?assertEqual({reject, revocation_unknown}, yuzu_gw_mgmt_crl:check(Held, Server, ?NOW, ?GRACE)).

fixture_crl_of_the_issuing_key_covers_the_server_test() ->
    Root = yuzu_gw_crl_fixture:cert_der("root-ca.pem"),
    Evil = yuzu_gw_crl_fixture:cert_der("evil-ca.pem"),
    Server = yuzu_gw_crl_fixture:cert_der("server.pem"),
    {ok, Held} = yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_fixture:read("crl-populated.der"),
                                        [Evil, Root], ?NOW),
    ?assertEqual({reject, crl_revoked}, yuzu_gw_mgmt_crl:check(Held, Server, ?NOW, ?GRACE)).

%% The subordinate-CA import case: sub-ca.pem has root-ca.pem's key and subject, so a CRL built
%% from it covers peers root-ca.pem issued.
fixture_subordinate_crl_covers_the_root_issued_server_test() ->
    Root = yuzu_gw_crl_fixture:cert_der("root-ca.pem"),
    Sub = yuzu_gw_crl_fixture:cert_der("sub-ca.pem"),
    Other = yuzu_gw_crl_fixture:cert_der("other.pem"),
    {ok, Held} = yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_fixture:read("crl-sub.der"), [Sub, Root], ?NOW),
    ?assertEqual(ok, yuzu_gw_mgmt_crl:check(Held, Other, ?NOW, ?GRACE)).

%% The binding works for every key type a CA can have: a CRL covers the peers its own key issued and
%% not those of a same-named CA with another key, and revokes the peers it lists.
key_types_test_() ->
    [{atom_to_list(Type), fun() -> key_type(Type) end} || Type <- [ec, rsa, ed25519, ed448]].

key_type(Type) ->
    A = yuzu_gw_crl_build:ca("Yuzu Install CA (test-host)", Type),
    B = yuzu_gw_crl_build:ca("Yuzu Install CA (test-host)", Type),
    PeerA = yuzu_gw_crl_build:leaf(A),
    PeerB = yuzu_gw_crl_build:leaf(B),
    Both = [maps:get(cert, A), maps:get(cert, B)],
    {ok, HeldA} = yuzu_gw_mgmt_crl:parse(
                    yuzu_gw_crl_build:crl(A, #{revoked => [yuzu_gw_crl_build:serial(PeerA)]}),
                    Both, ?NOW),
    ?assertEqual(1, length(maps:get(signers, HeldA))),
    ?assertEqual({reject, crl_revoked}, yuzu_gw_mgmt_crl:check(HeldA, PeerA, ?NOW, ?GRACE)),
    ?assertEqual({reject, revocation_unknown}, yuzu_gw_mgmt_crl:check(HeldA, PeerB, ?NOW, ?GRACE)).

%% A CA certificate over the same key as another is one signer, not two (the subordinate-CA import
%% case), and it is the key itself that is kept.
signers_dedupe_by_key_test() ->
    Root = yuzu_gw_crl_fixture:cert_der("root-ca.pem"),
    Sub = yuzu_gw_crl_fixture:cert_der("sub-ca.pem"),
    {ok, #{signers := [{Point, _Params}]}} =
        yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_fixture:read("crl-empty.der"), [Root, Sub], ?NOW),
    #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{
        subjectPublicKeyInfo = #'OTPSubjectPublicKeyInfo'{subjectPublicKey = Expected}}} =
        public_key:pkix_decode_cert(Root, otp),
    ?assertEqual(Expected, Point).

%% The name is checked as well as the key. renamed-ca.pem has root-ca.pem's key under another
%% subject: held with that issuer name, a CRL whose signer key DID issue the server still does not
%% cover it, because the server's issuer name is not the CRL's. (The key check alone would admit.)
a_matching_key_under_another_name_is_not_covered_test() ->
    Root = yuzu_gw_crl_fixture:cert_der("root-ca.pem"),
    Renamed = yuzu_gw_crl_fixture:cert_der("renamed-ca.pem"),
    Server = yuzu_gw_crl_fixture:cert_der("server.pem"),
    {ok, Held} = yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_fixture:read("crl-empty.der"), [Root], ?NOW),
    ?assertEqual(ok, yuzu_gw_mgmt_crl:check(Held, Server, ?NOW, ?GRACE)),
    {ok, RenamedIssuer} = yuzu_gw_mgmt_crl:issuer_of_cert(Renamed),
    ?assertEqual({reject, revocation_unknown},
                 yuzu_gw_mgmt_crl:check(Held#{issuer := RenamedIssuer}, Server, ?NOW, ?GRACE)).

%% The same list under a different signing key replaces the held one (a re-root's first CRL); the
%% identical CRL does not.
replace_takes_a_new_signing_key_test() ->
    A = ca(),
    B = ca(),
    Both = [maps:get(cert, A), maps:get(cert, B)],
    {ok, FromA} = yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_build:crl(A, #{number => 4}), Both, ?NOW),
    {ok, FromB} = yuzu_gw_mgmt_crl:parse(yuzu_gw_crl_build:crl(B, #{number => 4}), Both, ?NOW),
    ?assertEqual(unchanged, yuzu_gw_mgmt_crl:replace(FromA, FromA)),
    ?assertMatch({replace, _}, yuzu_gw_mgmt_crl:replace(FromA, FromB)).
