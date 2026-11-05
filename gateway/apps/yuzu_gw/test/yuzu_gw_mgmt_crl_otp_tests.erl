%%% @doc Does OTP read the CRLs the C++ server really writes? (#6016 PR 4b, the first test.)
%%%
%%% The gateway verifies the CRL by SIGNATURE (public_key:pkix_crl_verify/2) against the
%%% mgmt listener's cacertfile, and reads cRLNumber, thisUpdate, nextUpdate, the issuer DN and the
%%% revoked serials from the decoded record. Everything after this module rests on OTP
%%% decoding pki::build_crl output and on the behaviours pinned here, so these run against bytes
%%% the server built (fixtures/crl/README.md), not against a CRL made by OTP's own test helpers.
%%%
%%% Each test pins a fact the implementation relies on:
%%%   - a real CRL decodes and verifies against the self-signed root;
%%%   - AKI is only a hint: a CRL whose AKI names another key still verifies by signature;
%%%   - a wrong key under the same issuer DN does NOT verify, although pkix_is_issuer says it
%%%     does (it compares names only, so it is never the authenticity check);
%%%   - pkix_crl_verify RAISES on malformed input instead of returning false;
%%%   - cRLNumber is a raw DER integer extension value, decoded with der_decode('CRLNumber', _);
%%%   - the issuer DN is O before CN, compared structurally;
%%%   - the times are utcTime (generalizedTime after 2049 is parsed too, by the module that uses them).
-module(yuzu_gw_mgmt_crl_otp_tests).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

root() -> yuzu_gw_crl_fixture:cert_der("root-ca.pem").
sub() -> yuzu_gw_crl_fixture:cert_der("sub-ca.pem").
evil() -> yuzu_gw_crl_fixture:cert_der("evil-ca.pem").
crl(Name) -> yuzu_gw_crl_fixture:read(Name).

tbs(CrlDer) ->
    #'CertificateList'{tbsCertList = Tbs} = public_key:der_decode('CertificateList', CrlDer),
    Tbs.

ext(#'TBSCertList'{crlExtensions = Exts}, Id) when is_list(Exts) ->
    [V || #'Extension'{extnID = I, extnValue = V} <- Exts, I =:= Id];
ext(_, _) ->
    [].

revoked_serials(#'TBSCertList'{revokedCertificates = asn1_NOVALUE}) ->
    [];
revoked_serials(#'TBSCertList'{revokedCertificates = L}) ->
    [S || #'TBSCertList_revokedCertificates_SEQOF'{userCertificate = S} <- L].

%%--------------------------------------------------------------------

a_server_built_crl_decodes_test() ->
    Tbs = tbs(crl("crl-populated.der")),
    ?assertEqual(v2, Tbs#'TBSCertList'.version),
    ?assertMatch({utcTime, _}, Tbs#'TBSCertList'.thisUpdate),
    ?assertMatch({utcTime, _}, Tbs#'TBSCertList'.nextUpdate),
    ?assertEqual([yuzu_gw_crl_fixture:server_serial()], revoked_serials(Tbs)).

an_empty_crl_has_no_revoked_entries_test() ->
    Tbs = tbs(crl("crl-empty.der")),
    ?assertEqual([], revoked_serials(Tbs)),
    ?assertMatch({utcTime, _}, Tbs#'TBSCertList'.nextUpdate).

the_crl_verifies_against_the_self_signed_root_test_() ->
    [?_assertEqual(true, public_key:pkix_crl_verify(crl(N), root()))
     || N <- ["crl-populated.der", "crl-empty.der"]].

%% Subordinate import: the issuing key and the issuer DN are the root's, the SKI is not.
aki_is_only_a_hint_test() ->
    CrlDer = crl("crl-sub.der"),
    [AkiRaw] = [V || #'Extension'{extnID = ?'id-ce-authorityKeyIdentifier', extnValue = V}
                         <- (tbs(CrlDer))#'TBSCertList'.crlExtensions],
    ?assertNotEqual(asn1_NOVALUE, AkiRaw),
    ?assertEqual(true, public_key:pkix_crl_verify(CrlDer, root())),
    ?assertEqual(true, public_key:pkix_crl_verify(CrlDer, sub())).

wrong_key_under_the_same_issuer_dn_does_not_verify_test() ->
    CrlDer = crl("crl-evil.der"),
    ?assertEqual(false, public_key:pkix_crl_verify(CrlDer, root())),
    ?assertEqual(true, public_key:pkix_crl_verify(CrlDer, evil())).

%% pkix_is_issuer compares names only. Pinned so nobody reaches for it as the authenticity check.
pkix_is_issuer_is_name_only_test() ->
    Crl = public_key:der_decode('CertificateList', crl("crl-evil.der")),
    ?assertEqual(true, public_key:pkix_is_issuer(Crl, root())),
    ?assertEqual(true, public_key:pkix_is_issuer(Crl, evil())).

pkix_crl_verify_raises_on_malformed_input_test_() ->
    Good = crl("crl-populated.der"),
    Truncated = binary:part(Good, 0, byte_size(Good) - 20),
    %% Flip a byte inside the signed part so the ASN.1 itself no longer decodes.
    Mid = byte_size(Good) div 2,
    <<Pre:Mid/binary, B, Post/binary>> = Good,
    Garbled = <<Pre/binary, (B bxor 16#ff), Post/binary>>,
    [?_assertError(_, public_key:pkix_crl_verify(Truncated, root())),
     ?_assertError(_, public_key:pkix_crl_verify(<<"not a crl">>, root())),
     ?_assertError(_, public_key:pkix_crl_verify(<<>>, root())),
     ?_assert(is_boolean(catch_verify(Garbled)) orelse is_tuple(catch_verify(Garbled)))].

catch_verify(Der) ->
    try public_key:pkix_crl_verify(Der, root())
    catch Class:Reason -> {Class, Reason}
    end.

a_flipped_signature_byte_does_not_verify_test() ->
    Good = crl("crl-populated.der"),
    Last = byte_size(Good) - 1,
    <<Pre:Last/binary, B>> = Good,
    Flipped = <<Pre/binary, (B bxor 1)>>,
    ?assertNotEqual(true, catch_verify(Flipped)).

crl_number_is_raw_der_and_decodes_with_the_crl_number_type_test() ->
    Tbs = tbs(crl("crl-populated.der")),
    [Raw] = ext(Tbs, ?'id-ce-cRLNumber'),
    ?assert(is_binary(Raw)),
    ?assertEqual(7, public_key:der_decode('CRLNumber', Raw)),
    [RawEmpty] = ext(tbs(crl("crl-empty.der")), ?'id-ce-cRLNumber'),
    ?assertEqual(8, public_key:der_decode('CRLNumber', RawEmpty)),
    [RawEvil] = ext(tbs(crl("crl-evil.der")), ?'id-ce-cRLNumber'),
    ?assertEqual(99, public_key:der_decode('CRLNumber', RawEvil)).

%% O before CN, as the server emits it. Compared structurally, never as a string.
issuer_dn_is_organisation_then_common_name_test() ->
    #'TBSCertList'{issuer = {rdnSequence, Rdns}} = tbs(crl("crl-populated.der")),
    Attrs = [{T, V} || [#'AttributeTypeAndValue'{type = T, value = V}] <- Rdns],
    ?assertMatch([{?'id-at-organizationName', _}, {?'id-at-commonName', _}], Attrs),
    #'OTPCertificate'{tbsCertificate = #'OTPTBSCertificate'{subject = Subject}} =
        public_key:pkix_decode_cert(root(), otp),
    ?assertEqual({rdnSequence, Rdns}, Subject).

the_server_leaf_is_issued_by_the_root_and_not_by_the_evil_ca_test() ->
    Leaf = yuzu_gw_crl_fixture:cert_der("server.pem"),
    ?assertEqual(true, public_key:pkix_is_issuer(Leaf, root())),
    ?assertEqual({ok, yuzu_gw_crl_fixture:server_serial()}, yuzu_gw_authz:serial_number(Leaf)),
    Other = yuzu_gw_crl_fixture:cert_der("other.pem"),
    {ok, OtherSerial} = yuzu_gw_authz:serial_number(Other),
    ?assertNot(lists:member(OtherSerial, revoked_serials(tbs(crl("crl-populated.der"))))).
