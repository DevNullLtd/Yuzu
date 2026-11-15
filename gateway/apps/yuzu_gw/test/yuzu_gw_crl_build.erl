%%% @doc Builds throwaway CAs, leaves and CRLs for the cases the checked-in fixtures cannot cover
%%% (#6016 PR 4b): a CRL carrying an extension, two CAs with the same subject name and different
%%% keys. Everything is generated in memory by OTP's public_key, signed with a key made for the
%%% test and discarded with it; nothing here is written to disk.
%%%
%%% The checked-in fixtures (fixtures/crl/README.md) are the bytes the C++ server builds and stay
%%% the evidence for the shapes the server really produces. These are shapes only another CA or
%%% a hostile feed could produce, built to the encoding RFC 5280 gives them.
-module(yuzu_gw_crl_build).

-include_lib("public_key/include/public_key.hrl").

-export([ca/1, ca/2, leaf/1, serial/1, crl/2, ext/3]).

-define(THIS_S, "261102141448Z").
-define(NEXT_S, "261104141948Z").

%% @doc A self-signed CA with the given subject common name and a fresh EC P-384 key. Two calls
%% with the same name give the same subject DN and different keys.
-spec ca(string()) -> #{cert := binary(), key := term()}.
ca(Name) ->
    ca(Name, ec).

%% @doc The same, with the key type: `ec' (P-384), `rsa' (2048), `ed25519' or `ed448'.
-spec ca(string(), ec | rsa | ed25519 | ed448) -> #{cert := binary(), key := term()}.
ca(Name, ec) ->
    public_key:pkix_test_root_cert(Name, [{key, {namedCurve, secp384r1}}]);
ca(Name, rsa) ->
    public_key:pkix_test_root_cert(Name, [{key, {rsa, 2048, 65537}}]);
ca(Name, ed25519) ->
    public_key:pkix_test_root_cert(Name, [{key, {namedCurve, ed25519}}]);
ca(Name, ed448) ->
    public_key:pkix_test_root_cert(Name, [{key, {namedCurve, ed448}}]).

%% @doc The DER of a leaf certificate issued by `Ca'.
-spec leaf(#{cert := binary(), key := term()}) -> binary().
leaf(#{key := CaKey} = Ca) ->
    PeerKey = case CaKey of
                  #'RSAPrivateKey'{} -> {rsa, 2048, 65537};
                  #'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'}} -> {namedCurve, ed25519};
                  #'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed448'}} -> {namedCurve, ed448};
                  _ -> {namedCurve, secp256r1}
              end,
    Config = public_key:pkix_test_data(#{root => Ca, peer => [{key, PeerKey}]}),
    proplists:get_value(cert, Config).

-spec serial(binary()) -> non_neg_integer().
serial(Der) ->
    #'Certificate'{tbsCertificate = #'TBSCertificate'{serialNumber = S}} =
        public_key:pkix_decode_cert(Der, plain),
    S.

%% @doc An extension, with the DER of its value already encoded.
-spec ext(tuple(), boolean(), binary()) -> #'Extension'{}.
ext(Id, Critical, Value) ->
    #'Extension'{extnID = Id, critical = Critical, extnValue = Value}.

%% @doc A CRL signed by `Ca' (a map from ca/1). Options:
%%   number   the cRLNumber (default 1); `none' leaves the extension out
%%   revoked  [Serial | {Serial, [#'Extension'{}]}]  (default none)
%%   exts     extra CRL extensions, after cRLNumber (default none)
%%   this     thisUpdate: a utcTime string, or {generalTime, String} (default 261102141448Z,
%%            2026-11-02T14:14:48Z)
%%   next     nextUpdate, the same forms (default 261104141948Z: 48 h 5 min wide, 173100 s)
-spec crl(#{cert := binary(), key := term()}, map()) -> binary().
crl(#{cert := CaDer, key := Key}, Opts) ->
    #'Certificate'{tbsCertificate = #'TBSCertificate'{subject = Issuer}} =
        public_key:pkix_decode_cert(CaDer, plain),
    Number = maps:get(number, Opts, 1),
    Extensions = case Number of
                     none -> [];
                     _ -> [ext(?'id-ce-cRLNumber', false, public_key:der_encode('CRLNumber', Number))]
                 end ++ maps:get(exts, Opts, []),
    Revoked = case maps:get(revoked, Opts, []) of
                  [] -> asn1_NOVALUE;
                  List -> [entry(E) || E <- List]
              end,
    {Oid, Digest} = case Key of
                        #'RSAPrivateKey'{} -> {?'sha256WithRSAEncryption', sha256};
                        #'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed25519'}} ->
                            {?'id-Ed25519', none};
                        #'ECPrivateKey'{parameters = {namedCurve, ?'id-Ed448'}} ->
                            {?'id-Ed448', none};
                        _ -> {?'ecdsa-with-SHA384', sha384}
                    end,
    Algorithm = #'AlgorithmIdentifier'{algorithm = Oid},
    Tbs = #'TBSCertList'{version = v2,
                         signature = Algorithm,
                         issuer = Issuer,
                         thisUpdate = time(maps:get(this, Opts, ?THIS_S)),
                         nextUpdate = time(maps:get(next, Opts, ?NEXT_S)),
                         revokedCertificates = Revoked,
                         crlExtensions = Extensions},
    Signature = public_key:sign(public_key:der_encode('TBSCertList', Tbs), Digest, Key),
    public_key:der_encode('CertificateList',
                          #'CertificateList'{tbsCertList = Tbs,
                                             signatureAlgorithm = Algorithm,
                                             signature = Signature}).

time({generalTime, _} = T) -> T;
time(S) when is_list(S) -> {utcTime, S}.

entry({Serial, Exts}) ->
    #'TBSCertList_revokedCertificates_SEQOF'{userCertificate = Serial,
                                             revocationDate = {utcTime, ?THIS_S},
                                             crlEntryExtensions = Exts};
entry(Serial) ->
    entry({Serial, asn1_NOVALUE}).
