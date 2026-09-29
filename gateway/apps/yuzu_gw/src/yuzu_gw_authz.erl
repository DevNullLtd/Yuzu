%%%-------------------------------------------------------------------
%%% @doc Management-plane peer authorization (#1422, the #1314 M-1 residual).
%%%
%%% The :50063 mgmt listener's mTLS authenticates the peer to the shared
%%% internal CA — but that CA also signs every agent leaf AND the gateway's
%%% own leaf (whose key is group-readable in the shared cert volume under
%%% `--cert-group`). Holding a CA-issued cert must NOT be authorization to
%%% command the fleet, so this module pins the mgmt peer to the C++
%%% server's KEY, not merely its issuer.
%%%
%%% Wired as the grpcbox `auth_fun` on the mgmt listener ONLY (never the
%%% :50051 agent listener, which is verify_none — grpcbox rejects a
%%% certless peer whenever an auth_fun is installed, so an auth_fun there
%%% would kill every agent connection). grpcbox invokes it per-stream,
%%% before the service handler, with the peer's DER certificate; any
%%% non-{true,_} return ends the stream UNAUTHENTICATED.
%%%
%%% Pin model: `{yuzu_gw, mgmt_peer_pins}` is a list of
%%%   {cert_file, Path}       — pin to the SPKI of the FIRST certificate in
%%%                             the PEM at Path (default deployments point at
%%%                             the shared-volume default-server.pem; re-read
%%%                             when the file changes, so server leaf rotation
%%%                             self-heals without a gateway restart), or
%%%   {spki_sha256, Hex}      — a literal SHA-256 of the peer's DER-encoded
%%%                             SubjectPublicKeyInfo (64 hex chars; for
%%%                             bring-your-own-cert installs / split hosts
%%%                             where the server cert file isn't mounted).
%%% Two or more pins may be listed so a rotation can overlap.
%%%
%%% Why SPKI and not the subject CN: `agent_id` is only length-checked and
%%% is chosen by the endpoint (`--agent-id`), and sign_agent_csr puts it in
%%% the leaf CN verbatim — so a compromised endpoint holding a still-usable
%%% enrollment token can mint a CA-issued leaf with ANY CN, including the
%%% server's. The SPKI pin requires the server's PRIVATE KEY, which never
%%% leaves the server (0600, never group-shared). Defense-in-depth: the
%%% peer must also carry the serverAuth EKU, which sign_agent_csr never
%%% grants (EKU is server-chosen; the CSR's requests are ignored), so even
%%% a misconfigured pin set can never re-admit an agent leaf.
%%%
%%% Fail-closed: no/empty/unresolvable pins, undecodable peer certs, and
%%% any internal error all reject. Rejections emit a low-cardinality
%%% telemetry counter + a reason-only log line (never certificate contents:
%%% every CA-issued cert holder reaches this callback, so per-cert logging
%%% would hand an authenticated-but-unauthorized peer a log-spam lever).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_authz).

-include_lib("public_key/include/public_key.hrl").
-include_lib("kernel/include/file.hrl").

-export([check_mgmt_peer/1]).
%% exported for testing
-export([check_peer/2, spki_sha256/1, has_server_auth_eku/1,
         resolve_pin/1, pem_file_spki/1]).

-define(IDENTITY, <<"yuzu-server">>).

%%--------------------------------------------------------------------
%% grpcbox auth_fun entry point
%%--------------------------------------------------------------------

%% @doc grpcbox auth_fun for the mgmt listener. Total: any throw/error
%% rejects rather than crashing the stream process.
-spec check_mgmt_peer(public_key:der_encoded()) -> {true, binary()} | false.
check_mgmt_peer(DerCert) ->
    try
        check_peer(DerCert, application:get_env(yuzu_gw, mgmt_peer_pins, []))
    catch
        _:_ -> reject(internal_error)
    end.

%% @doc Pure-ish core (pin list injected) — exported for testing.
-spec check_peer(public_key:der_encoded(), [term()]) -> {true, binary()} | false.
check_peer(_DerCert, []) ->
    %% Installed auth_fun but no pins configured: fail closed. The boot
    %% guard refuses this posture on an exposed listener; this is the
    %% runtime backstop.
    reject(no_pins_configured);
check_peer(DerCert, Pins) when is_list(Pins) ->
    case spki_sha256(DerCert) of
        {ok, PeerSpki} ->
            case has_server_auth_eku(DerCert) of
                true ->
                    Resolved = [H || P <- Pins, {ok, H} <- [resolve_pin(P)]],
                    %% A configured-but-unresolvable pin is otherwise SILENT
                    %% while a sibling pin still admits the server — exactly
                    %% the pre-staged-rotation-typo shape that stays green
                    %% until the old leaf retires. Surface it every time.
                    case length(Resolved) < length(Pins) of
                        true  -> report_unresolved_pins(Pins);
                        false -> ok
                    end,
                    case Resolved =/= [] andalso lists:member(PeerSpki, Resolved) of
                        true  -> {true, ?IDENTITY};
                        false when Resolved =:= [] -> reject(no_pins_resolved);
                        false -> reject(pin_mismatch)
                    end;
                false ->
                    reject(missing_server_auth_eku)
            end;
        error ->
            reject(bad_peer_cert)
    end;
check_peer(_DerCert, _Bad) ->
    reject(bad_pin_config).

%%--------------------------------------------------------------------
%% Certificate inspection
%%--------------------------------------------------------------------

%% @doc SHA-256 of the certificate's DER-encoded SubjectPublicKeyInfo.
%% Uses the `plain` decode so the SPKI substructure round-trips through
%% der_encode byte-identically (the `otp` decode parses the key material
%% itself, which does not re-encode to the original DER).
-spec spki_sha256(public_key:der_encoded()) -> {ok, binary()} | error.
spki_sha256(DerCert) when is_binary(DerCert) ->
    try
        #'Certificate'{tbsCertificate =
            #'TBSCertificate'{subjectPublicKeyInfo = Spki}} =
            public_key:pkix_decode_cert(DerCert, plain),
        {ok, crypto:hash(sha256, public_key:der_encode('SubjectPublicKeyInfo', Spki))}
    catch
        _:_ -> error
    end;
spki_sha256(_) ->
    error.

%% @doc True iff the certificate carries the serverAuth extended key usage.
%% Agent leaves are clientAuth-only by construction (sign_agent_csr chooses
%% the EKU server-side and ignores the CSR), so this alone excludes every
%% agent leaf regardless of its subject.
-spec has_server_auth_eku(public_key:der_encoded()) -> boolean().
has_server_auth_eku(DerCert) when is_binary(DerCert) ->
    try
        #'OTPCertificate'{tbsCertificate =
            #'OTPTBSCertificate'{extensions = Exts}} =
            public_key:pkix_decode_cert(DerCert, otp),
        is_list(Exts) andalso
            lists:any(fun(#'Extension'{extnID = ?'id-ce-extKeyUsage',
                                       extnValue = Ekus}) when is_list(Ekus) ->
                              lists:member(?'id-kp-serverAuth', Ekus);
                         (_) ->
                              false
                      end, Exts)
    catch
        _:_ -> false
    end;
has_server_auth_eku(_) ->
    false.

%%--------------------------------------------------------------------
%% Pin resolution
%%--------------------------------------------------------------------

%% @doc Resolve one configured pin to a 32-byte SPKI SHA-256, or error.
%% A malformed/unreadable pin resolves to error and is skipped — with an
%% all-error pin list the caller rejects (fail closed), so a typo'd config
%% can never widen access.
-spec resolve_pin(term()) -> {ok, binary()} | error.
resolve_pin({spki_sha256, Hex}) when is_list(Hex) ->
    %% list_to_binary badargs on improper lists and codepoints > 255 (pasted
    %% Unicode hex lookalikes) — that must stay a SKIPPED pin, never abort the
    %% whole pin walk (which would reject every peer, valid co-pin included).
    try resolve_pin({spki_sha256, list_to_binary(Hex)})
    catch _:_ -> error
    end;
resolve_pin({spki_sha256, Hex}) when is_binary(Hex), byte_size(Hex) =:= 64 ->
    try {ok, binary:decode_hex(Hex)}
    catch _:_ -> error
    end;
resolve_pin({cert_file, Path}) when is_list(Path); is_binary(Path) ->
    cached_file_spki(Path);
resolve_pin(_) ->
    error.

%% @private SPKI of the first certificate in the PEM at Path, cached in
%% persistent_term keyed by {mtime, size} so the shared-volume default
%% server leaf is re-read after the C++ server rotates it (no gateway
%% restart needed). persistent_term:put triggers a global GC scan, but the
%% token only changes on rotation, so puts are rare by construction.
%% Granularity note: a same-second, SAME-SIZE rewrite is not detected — and
%% a re-minted same-type key typically yields a same-length DER, so the size
%% half of the token does NOT catch that case. What bounds the risk is that
%% rotation is rare, the miss direction is fail-closed (stale pin rejects
%% the new leaf, never admits a wrong one), and a gateway restart recovers.
-spec cached_file_spki(file:name_all()) -> {ok, binary()} | error.
cached_file_spki(Path) ->
    Token = file_token(Path),
    Key = {?MODULE, cert_file, Path},
    case {Token, persistent_term:get(Key, undefined)} of
        {error, _} ->
            error;
        {_, {Token, Hash}} ->
            {ok, Hash};
        {_, _} ->
            case pem_file_spki(Path) of
                {ok, Hash} ->
                    persistent_term:put(Key, {Token, Hash}),
                    {ok, Hash};
                error ->
                    error
            end
    end.

%% @doc Uncached read: SPKI SHA-256 of the first PEM certificate in Path.
-spec pem_file_spki(file:name_all()) -> {ok, binary()} | error.
pem_file_spki(Path) ->
    case file:read_file(Path) of
        {ok, Pem} ->
            case [D || {'Certificate', D, not_encrypted} <- public_key:pem_decode(Pem)] of
                [Der | _] -> spki_sha256(Der);
                []        -> error
            end;
        {error, _} ->
            error
    end.

-spec file_token(file:name_all()) -> {calendar:datetime(), non_neg_integer()} | error.
file_token(Path) ->
    case file:read_file_info(Path, [{time, universal}]) of
        {ok, #file_info{mtime = M, size = S}} -> {M, S};
        {error, _}                            -> error
    end.

%%--------------------------------------------------------------------
%% Rejection
%%--------------------------------------------------------------------

%% @private Count + log the rejection by reason only. Reasons are a small
%% closed atom set (low cardinality); no certificate-derived data reaches
%% the log or the metric labels. Event name lives in yuzu_gw_telemetry's
%% ?EVENTS ([yuzu, gw, ...] namespace) — an unlisted name would fire into
%% the void and the advertised counter would never move.
-spec reject(atom()) -> false.
reject(Reason) ->
    telemetry:execute([yuzu, gw, mgmt_auth, rejected], #{count => 1},
                      #{reason => Reason}),
    logger:notice("mgmt-plane peer rejected: ~p (CA-issued cert is not "
                  "authorization to command the fleet — see mgmt_peer_pins)",
                  [Reason]),
    false.

%% @private A configured pin entry did not resolve. Counted on every auth
%% attempt (so a dashboard sees it move), logged once per BEAM per distinct
%% unresolved-set (so a dead entry cannot become a per-stream log flood).
-spec report_unresolved_pins([term()]) -> ok.
report_unresolved_pins(Pins) ->
    Dead = [P || P <- Pins, resolve_pin(P) =:= error],
    telemetry:execute([yuzu, gw, mgmt_auth, pin_unresolved],
                      #{count => 1}, #{}),
    Key = {?MODULE, warned_unresolved, erlang:phash2(Dead)},
    case persistent_term:get(Key, false) of
        true -> ok;
        false ->
            persistent_term:put(Key, true),
            logger:warning("mgmt_peer_pins: ~p configured entr~s could not be "
                           "resolved (typo'd fingerprint? unreadable cert "
                           "file?) — a dead pin is invisible while another "
                           "pin still admits the server, then bites at "
                           "rotation cutover. Entries: ~0p",
                           [length(Dead),
                            case length(Dead) of 1 -> "y"; _ -> "ies" end,
                            Dead])
    end,
    ok.
