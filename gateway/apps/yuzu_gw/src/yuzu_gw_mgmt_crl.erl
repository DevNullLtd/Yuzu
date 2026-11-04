%%%-------------------------------------------------------------------
%%% @doc The CA's certificate revocation list, as the management plane uses it (#6016 PR 4b).
%%%
%%% PURE: no process, no file, no socket, no clock of its own. The watcher
%%% (yuzu_gw_mgmt_crl_source) feeds it bytes and a time and publishes what it returns; the
%%% per-stream check (yuzu_gw_authz) feeds it a peer certificate and a time. Everything here
%%% is a function of its arguments, which is what lets the replace rule, the freshness
%%% boundary and the verification failures be tested exhaustively.
%%%
%%% A CRL is trusted by its SIGNATURE and by nothing else. parse/3 verifies it with
%%% public_key:pkix_crl_verify/2 against the certificates of the management listener's
%%% `cacertfile'; the transport that delivered it (TLS to the server's HTTPS port, a file on a
%%% volume) protects availability and replay, never integrity. The AKI extension is a hint only
%%% (a subordinate-CA install keeps the issuing KEY and issuer name, and its CRL carries a different
%%% key identifier), and public_key:pkix_is_issuer/2 compares NAMES only (a wrong key under the
%%% same name is "an issuer"), so neither decides authenticity. See
%%% yuzu_gw_mgmt_crl_otp_tests for the behaviours of OTP this relies on, measured against CRLs the
%%% C++ server really built.
%%%
%%% What a loaded CRL is (crl()): the cRLNumber, thisUpdate and nextUpdate as seconds since the
%%% epoch, the issuer name, and the revoked serials as a map. Nothing else of the file is kept.
%%%
%%% Replace rule (replace/2). A newly parsed CRL replaces the loaded one when its thisUpdate is
%%% LATER or its cRLNumber is HIGHER. It is refused only when both are older or equal, and a
%%% refused CRL never evicts the loaded one. The server stamps thisUpdate = build time - 300 s and
%%% numbers CRLs MAX+1, so a restore from backup (lower number, later time) and a server clock
%%% stepped back (earlier time, higher number) both carry a revocation that must arrive, while a
%%% replay of an old CRL (earlier AND lower) is the only thing this module refuses (the watcher
%%% adds one more: yuzu_gw_mgmt_crl_source:replace_rule/4 does not let a CRL that is already stale
%%% displace one still believed). Only a holder of the CA
%%% key can build anything outside those three cases, and that party can mint the server identity.
%%%
%%% Freshness (check/4). The CRL is stale when `now > nextUpdate + grace'. The server republishes
%%% when under 24 hours remain of a 48 hour validity (#6016 step 4d), so a healthy server never
%%% lets a gateway see a CRL within a day of expiry, and the default 24 hour grace makes
%%% `nextUpdate + grace' about three days after the last publish.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_crl).

-include_lib("public_key/include/public_key.hrl").

-export([parse/3, replace/2, check/4, ca_certs/1, issuer_of_cert/1]).
-export([max_bytes/0, max_future_s/0, time_to_epoch/1]).

-export_type([crl/0, load_reject/0, check_reject/0, replace_result/0]).

%% The largest CRL read or kept. A CRL is a few hundred bytes plus about 40 per revoked
%% certificate, so 16 MiB is hundreds of thousands of entries; over it the file is a read failure
%% and the previous CRL stands. The fetch (yuzu_gw_mgmt_crl_source) enforces it while streaming.
-define(MAX_BYTES, 16 * 1024 * 1024).
%% thisUpdate this far ahead of the gateway's clock is a clock fault on one side or the other;
%% beyond it the CRL is refused (and never evicts a loaded one).
-define(MAX_FUTURE_S, 3600).

-type crl() :: #{number := non_neg_integer(),
                 this_update := integer(),
                 next_update := integer(),
                 issuer := term(),
                 revoked := #{non_neg_integer() => true}}.

%% Why a CRL was not loaded (a closed set; the label of yuzu_gw_mgmt_crl_rejected_total
%% together with the fetch failures of yuzu_gw_mgmt_crl_source).
-type load_reject() :: malformed | too_large | unverified | issuer_mismatch
                     | future_dated | replay.
-type check_reject() :: revocation_unknown | revocation_stale | crl_revoked | bad_peer_cert.
-type replace_result() :: {replace, crl()} | unchanged | {reject, replay}.

-spec max_bytes() -> pos_integer().
max_bytes() -> ?MAX_BYTES.

-spec max_future_s() -> pos_integer().
max_future_s() -> ?MAX_FUTURE_S.

%%--------------------------------------------------------------------
%% Parsing and verification
%%--------------------------------------------------------------------

%% @doc Parse and verify a DER CRL (a PEM `X509 CRL' is accepted too). `CaDers' are the DER
%% certificates the signature is checked against; `Now' is seconds since the epoch. Total: any
%% input maps to a result, never an exception (pkix_crl_verify/2 RAISES on malformed input).
-spec parse(term(), [binary()], integer()) -> {ok, crl()} | {error, load_reject()}.
parse(Bin, _CaDers, _Now) when is_binary(Bin), byte_size(Bin) > ?MAX_BYTES ->
    {error, too_large};
parse(Bin, CaDers, Now) when is_binary(Bin), is_list(CaDers), is_integer(Now) ->
    try
        Der = to_der(Bin),
        Crl = public_key:der_decode('CertificateList', Der),
        Fields = fields(Crl),
        verified(Der, Fields, CaDers, Now)
    catch
        throw:{reject, Reason} -> {error, Reason};
        _:_ -> {error, malformed}
    end;
parse(_, _, _) ->
    {error, malformed}.

%% PEM wraps the DER in an `X509 CRL' block; anything else is taken to be DER already.
to_der(<<"-----BEGIN", _/binary>> = Pem) ->
    case public_key:pem_decode(Pem) of
        [{'CertificateList', Der, not_encrypted} | _] -> Der;
        _ -> throw({reject, malformed})
    end;
to_der(Der) ->
    Der.

fields(#'CertificateList'{tbsCertList = #'TBSCertList'{
                              issuer = Issuer,
                              thisUpdate = This,
                              nextUpdate = Next,
                              revokedCertificates = Rev,
                              crlExtensions = Exts}}) ->
    Number = crl_number(Exts),
    true = Next =/= asn1_NOVALUE,
    ThisEpoch = time_to_epoch(This),
    NextEpoch = time_to_epoch(Next),
    %% A validity interval that ends before it begins is not a CRL the CA meant to publish.
    true = NextEpoch > ThisEpoch,
    #{issuer => Issuer,
      this_update => ThisEpoch,
      next_update => NextEpoch,
      number => Number,
      revoked => revoked(Rev)}.

%% The cRLNumber extension's value is the raw DER of an INTEGER, not a decoded one.
crl_number(Exts) when is_list(Exts) ->
    case [V || #'Extension'{extnID = ?'id-ce-cRLNumber', extnValue = V} <- Exts] of
        [Raw] when is_binary(Raw) ->
            N = public_key:der_decode('CRLNumber', Raw),
            true = is_integer(N) andalso N >= 0,
            N;
        _ ->
            throw({reject, malformed})
    end;
crl_number(_) ->
    throw({reject, malformed}).

revoked(asn1_NOVALUE) ->
    #{};
revoked(List) when is_list(List) ->
    %% RFC 5280 4.1.2.2: a serial is a positive integer of at most 20 octets. An entry outside
    %% that is not something the CA publishes, and the whole CRL is refused rather than the entry
    %% skipped, so a CRL that does not mean what it says never takes the place of one that does.
    maps:from_keys(
      [valid_serial(S) || #'TBSCertList_revokedCertificates_SEQOF'{userCertificate = S} <- List],
      true).

valid_serial(S) when is_integer(S), S >= 0, S < (1 bsl 160) -> S;
valid_serial(_) -> throw({reject, malformed}).

verified(Der, #{issuer := Issuer, this_update := This} = Fields, CaDers, Now) ->
    case verifying_ca(Der, Issuer, CaDers) of
        none ->
            {error, unverified};
        issuer_mismatch ->
            {error, issuer_mismatch};
        ok ->
            case This > Now + ?MAX_FUTURE_S of
                true  -> {error, future_dated};
                false -> {ok, maps:with([number, this_update, next_update, issuer, revoked], Fields)}
            end
    end.

%% Does any certificate in the verification set verify the signature? Order does not matter:
%% every certificate is tried, each inside its own try (a CRL that raises against one
%% certificate says nothing about another). Having verified, the CRL's issuer name must be the
%% name of the certificate that verified it, so a CRL cannot claim to be issued by a name it
%% is not signed under.
verifying_ca(Der, Issuer, CaDers) ->
    Verifying = [Ca || Ca <- CaDers, signature_verifies(Der, Ca)],
    case Verifying of
        [] -> none;
        _ ->
            case lists:any(fun(Ca) -> dn_matches(dn_of(Ca), Issuer) end, Verifying) of
                true  -> ok;
                false -> issuer_mismatch
            end
    end.

signature_verifies(CrlDer, CaDer) ->
    try public_key:pkix_crl_verify(CrlDer, CaDer) =:= true
    catch _:_ -> false
    end.

%% Names are compared in the `plain' decoding on every side (the CRL's issuer, a CA's subject, a
%% peer's issuer), so equal DER is equal terms.
dn_of(CaDer) ->
    try
        #'Certificate'{tbsCertificate = #'TBSCertificate'{subject = Subject}} =
            public_key:pkix_decode_cert(CaDer, plain),
        {ok, Subject}
    catch _:_ -> error
    end.

dn_matches({ok, A}, B) -> names_equal(A, B);
dn_matches(_, _) -> false.

%% X.509 name comparison (RFC 5280 4.1.2.4: the attribute values are compared after
%% normalisation), structurally and never as a rendered string: the RDN order is part of the name
%% and Yuzu emits organisation before common name.
names_equal(A, B) when A =:= B ->
    true;
names_equal(A, B) ->
    try public_key:pkix_normalize_name(A) =:= public_key:pkix_normalize_name(B)
    catch _:_ -> false
    end.

%%--------------------------------------------------------------------
%% Times
%%--------------------------------------------------------------------

%% @doc Seconds since the epoch of an ASN.1 Time: utcTime (`YYMMDDHHMMSSZ', two-digit years
%% pivot at 50 as RFC 5280 says) or generalizedTime (`YYYYMMDDHHMMSSZ', used from 2050).
-spec time_to_epoch({utcTime | generalTime, string()}) -> integer().
time_to_epoch({utcTime, [Y1, Y2 | Rest]}) ->
    YY = list_to_integer([Y1, Y2]),
    Year = case YY >= 50 of true -> 1900 + YY; false -> 2000 + YY end,
    stamp(Year, Rest);
time_to_epoch({generalTime, [Y1, Y2, Y3, Y4 | Rest]}) ->
    stamp(list_to_integer([Y1, Y2, Y3, Y4]), Rest).

stamp(Year, [M1, M2, D1, D2, H1, H2, N1, N2, S1, S2, $Z]) ->
    Dt = {{Year, list_to_integer([M1, M2]), list_to_integer([D1, D2])},
          {list_to_integer([H1, H2]), list_to_integer([N1, N2]), list_to_integer([S1, S2])}},
    calendar:datetime_to_gregorian_seconds(Dt) - 62167219200.

%%--------------------------------------------------------------------
%% Replacing
%%--------------------------------------------------------------------

%% @doc What to do with a freshly verified CRL given the loaded one (`none' when there is none).
-spec replace(crl() | none, crl()) -> replace_result().
replace(none, New) ->
    {replace, New};
replace(#{number := N, this_update := T, issuer := I, revoked := R},
        #{number := N2, this_update := T2, issuer := I2, revoked := R2} = New) ->
    if
        T2 > T; N2 > N ->
            {replace, New};
        T2 =:= T, N2 =:= N, I2 =:= I, R2 =:= R ->
            unchanged;
        true ->
            {reject, replay}
    end.

%%--------------------------------------------------------------------
%% The per-stream check
%%--------------------------------------------------------------------

%% @doc The decision for one management peer certificate, from the loaded CRL alone:
%% a pure function, called on the stream path with a persistent_term read.
%%   no CRL loaded                          revocation_unknown
%%   the CRL is not this peer's issuer's    revocation_unknown   (a different root; see the docs)
%%   now > nextUpdate + grace               revocation_stale
%%   the peer's serial is listed            crl_revoked
%%   the peer's serial cannot be read       bad_peer_cert
-spec check(crl() | none, binary(), integer(), non_neg_integer()) -> ok | {reject, check_reject()}.
check(none, _PeerDer, _Now, _Grace) ->
    {reject, revocation_unknown};
check(#{issuer := CrlIssuer, next_update := Next, revoked := Revoked}, PeerDer, Now, Grace) ->
    case peer_fields(PeerDer) of
        error ->
            {reject, bad_peer_cert};
        {ok, PeerIssuer, Serial} ->
            if
                not is_tuple(PeerIssuer) ->
                    {reject, bad_peer_cert};
                true ->
                    case names_equal(PeerIssuer, CrlIssuer) of
                        false -> {reject, revocation_unknown};
                        true when Now > Next + Grace -> {reject, revocation_stale};
                        true ->
                            case maps:is_key(Serial, Revoked) of
                                true  -> {reject, crl_revoked};
                                false -> ok
                            end
                    end
            end
    end.

peer_fields(PeerDer) when is_binary(PeerDer) ->
    try
        #'Certificate'{tbsCertificate = #'TBSCertificate'{issuer = Issuer,
                                                           serialNumber = Serial}} =
            public_key:pkix_decode_cert(PeerDer, plain),
        true = is_integer(Serial) andalso Serial >= 0,
        {ok, Issuer, Serial}
    catch _:_ -> error
    end;
peer_fields(_) ->
    error.

%% @doc The issuer name of a certificate, as check/4 compares it.
-spec issuer_of_cert(binary()) -> {ok, term()} | error.
issuer_of_cert(Der) ->
    case peer_fields(Der) of
        {ok, Issuer, _} -> {ok, Issuer};
        error -> error
    end.

%%--------------------------------------------------------------------
%% The verification set
%%--------------------------------------------------------------------

%% @doc The DER certificates of a PEM file's bytes (the management listener's `cacertfile'),
%% `Certificate' blocks only; anything else in the file is ignored. An unparsable file is [].
-spec ca_certs(binary()) -> [binary()].
ca_certs(Pem) when is_binary(Pem) ->
    try [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(Pem)]
    catch _:_ -> []
    end;
ca_certs(_) ->
    [].
