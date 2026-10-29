%%%-------------------------------------------------------------------
%%% @doc Management-plane peer IDENTITY and withdrawal configuration (#6016).
%%%
%%% yuzu_gw_authz admits the C++ server on :50063 by one of two things the
%%% operator configures here, both resolved ONCE at boot and published to
%%% persistent_term, so the per-stream check does no I/O (M1(b), #5696):
%%%
%%%   identity  the exact URI SAN `yuzu://<install>/server' that the install CA
%%%             mints ONLY onto the `default-server' leaf (default_certs.cpp,
%%%             #6072). `sign_agent_csr' ignores a CSR's SAN and only ever emits
%%%             `yuzu://<install>/agent/<id>', and the gateway's own leaf carries
%%%             no URI, so holding a CA-issued certificate -- an agent's, the
%%%             gateway's -- does not provide it. A server key renewal needs no
%%%             gateway change: the new leaf carries the same identity.
%%%   pins      the SPKI pin of yuzu_gw_authz / yuzu_gw_mgmt_pins (unchanged).
%%%
%%% `{yuzu_gw, mgmt_peer_auth_mode}' selects how they combine:
%%%
%%%   pin               pins only (the behaviour before #6016). ALWAYS the default
%%%                     when the mode is unset, so an upgrade changes nothing and
%%%                     a configuration with no pins still refuses to boot: the
%%%                     identity is an explicit opt-in, never implied by a missing
%%%                     key. Bring-your-own certificates, `--no-default-certs' and
%%%                     a server run with its own `--cert'/`--key' never carry the
%%%                     URI and stay here.
%%%   identity_or_pin   the identity OR a pin admits. The transition mode.
%%%   identity          the identity admits; a pin, if any is configured, must
%%%                     ALSO match.
%%%
%%% The identity is only as strong as the issuing CA's refusal to mint it for
%%% anyone else. That holds for the Yuzu install CA (default_certs.cpp mints it
%%% only onto the server leaf). It does NOT hold for a corporate CA that lets a
%%% requester choose a URI SAN, nor for a bundle: every CA in the listener's
%%% `cacertfile' could mint it. So an identity over a `cacertfile' that is not
%%% demonstrably exactly ONE readable certificate (a bundle, or empty, unreadable
%%% or half-written at boot; only possible with an explicit `mgmt_peer_identity')
%%% is a boot defect unless the mode is `identity' AND a pin is configured, which
%%% then must also match.
%%%
%%% Identity source: an explicit `{yuzu_gw, mgmt_peer_identity}' (a string or
%%% binary, exactly `yuzu://<install>/server'), else derived from the management
%%% listener's `cacertfile' ONLY when that file holds exactly ONE certificate:
%%% `yuzu://' ++ upper-case hex SHA-256 of its DER ++ `/server', which is what
%%% the server computes from the on-disk root (`install_id_from_fingerprint').
%%% A bundle, an unreadable file or an absent one derives nothing, so the
%%% identity is UNRESOLVED and fails closed; set the identity explicitly. Two
%%% management listeners that derive different values are a boot defect.
%%%
%%% Withdrawal. `{yuzu_gw, mgmt_peer_denied}' is a list of `{serial, Hex}':
%%% certificate serial numbers (1 to 40 hex digits, any case) the gateway
%%% refuses even when they carry the identity or a pinned key. It is keyed on
%%% the SERIAL and never on the key: the server re-issues its leaf over the SAME
%%% key to add the identity, so a key deny would also refuse the replacement.
%%% The list is read at boot; applying a change needs a restart. Applying it
%%% automatically from the CA's revocation list is the follow-up of #6016.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_identity).

-export([resolve/0, resolve/5, publish/1, current/0, reset/0,
         validate_identity/1, validate_denied/1,
         identity_from_ca_der/1, derive_from_cacertfile/1, cacert_count/1,
         derive_for_listeners/1]).

-export_type([mode/0, state/0]).

-define(KEY, {?MODULE, state}).
-define(MAX_DENIED, 4096).
-define(MAX_SERIAL_HEX, 40).

-type mode() :: pin | identity_or_pin | identity.
-type state() :: #{mode := mode(),
                   identity := binary() | undefined,
                   denied := [non_neg_integer()]}.

%%--------------------------------------------------------------------
%% Published state
%%--------------------------------------------------------------------

%% @doc What the boot guard published; the pre-#6016 behaviour (pins only, no
%% deny-list) when nothing was published. A persistent_term read.
-spec current() -> state().
current() ->
    persistent_term:get(?KEY, #{mode => pin, identity => undefined, denied => []}).

-spec publish(state()) -> ok.
publish(State) when is_map(State) ->
    persistent_term:put(?KEY, State).

%% @doc Forget what was published (tests): `current/0' is the pre-#6016
%% default again.
-spec reset() -> ok.
reset() ->
    _ = persistent_term:erase(?KEY),
    ok.

%%--------------------------------------------------------------------
%% Resolution
%%--------------------------------------------------------------------

%% @doc Resolve the configuration from the application environment.
-spec resolve() -> {ok, state()} | {error, [term()]}.
resolve() ->
    resolve(application:get_env(yuzu_gw, mgmt_peer_auth_mode, undefined),
            application:get_env(yuzu_gw, mgmt_peer_identity, undefined),
            application:get_env(yuzu_gw, mgmt_peer_denied, []),
            application:get_env(yuzu_gw, grpc_listeners, []),
            application:get_env(yuzu_gw, mgmt_peer_pins, [])).

%% @doc Pure core (the file reads of the derivation aside) -- exported for
%% testing. Defects are returned together so one boot attempt names them all.
-spec resolve(term(), term(), term(), term(), term()) ->
          {ok, state()} | {error, [term()]}.
resolve(Mode0, Identity0, Denied0, Listeners, Pins) ->
    Mode = case Mode0 of
               undefined -> {ok, pin};
               M when M =:= pin; M =:= identity_or_pin; M =:= identity -> {ok, M};
               Other -> {error, {bad_mgmt_peer_auth_mode, Other}}
           end,
    Denied = validate_denied(Denied0),
    Identity = case Mode of
                   {ok, pin} -> {ok, undefined};
                   {ok, M0} -> bundle_guard(M0, resolve_identity(Identity0, Listeners),
                                            Listeners, Pins);
                   {error, _} -> {ok, undefined}
               end,
    case [E || {error, E} <- [Mode, Denied, Identity]] of
        [] ->
            {ok, M1} = Mode,
            {ok, D1} = Denied,
            {ok, I1} = Identity,
            {ok, #{mode => M1, identity => I1, denied => D1}};
        Errors ->
            {error, lists:flatten(Errors)}
    end.

%% An identity that a bundle's other CAs could mint is admitted only together
%% with a pin (mode identity): see the module header. A management listener
%% whose cacertfile does not demonstrably hold exactly ONE certificate (more than
%% one, or empty, unreadable or undecodable at this moment) is treated as a
%% bundle: the listener reads the file again when it starts, and a guard that
%% passes on a file it could not read would be raced by whatever it then finds.
bundle_guard(_Mode, {ok, undefined} = Unresolved, _Listeners, _Pins) ->
    Unresolved;
bundle_guard(Mode, {ok, _} = Resolved, Listeners, Pins) ->
    Bundles = [F || S <- mgmt_listeners(Listeners), F <- [cacertfile(S)],
                    F =/= undefined, cacert_count(F) =/= 1],
    HasPins = is_list(Pins) andalso Pins =/= [],
    case {Bundles, Mode, HasPins} of
        {[], _, _}          -> Resolved;
        {_, identity, true} -> Resolved;
        _                   -> {error, {identity_over_ca_bundle, Mode}}
    end;
bundle_guard(_Mode, Error, _Listeners, _Pins) ->
    Error.

resolve_identity(undefined, Listeners) ->
    derive_for_listeners(Listeners);
resolve_identity(Explicit, _Listeners) ->
    case validate_identity(Explicit) of
        {ok, _} = Ok -> Ok;
        error -> {error, {bad_mgmt_peer_identity, redact(Explicit)}}
    end.

%% The identity derived from every management listener's cacertfile.
%% undefined (unresolved, fails closed) when there is none or any cannot be
%% derived; a defect when two listeners disagree.
-spec derive_for_listeners(term()) -> {ok, binary() | undefined} | {error, identity_ambiguous}.
derive_for_listeners(Listeners) ->
    %% a plaintext listener has no cacertfile and no auth_fun: nothing to derive from
    Files = [F || S <- mgmt_listeners(Listeners), F <- [cacertfile(S)], F =/= undefined],
    case Files of
        [] ->
            {ok, undefined};
        _ ->
            Derived = [derive_from_cacertfile(F) || F <- Files],
            case lists:usort(Derived) of
                [{ok, Id}] -> {ok, Id};
                [error] -> {ok, undefined};
                Many ->
                    case lists:member(error, Many) of
                        true -> {ok, undefined};
                        false -> {error, identity_ambiguous}
                    end
            end
    end.

mgmt_listeners(Listeners) ->
    try [S || S <- Listeners, yuzu_grpc_listener:serves_proto(S, management_pb)]
    catch _:_ -> []
    end.

cacertfile(#{tls := #{cacertfile := F}}) when is_list(F); is_binary(F) -> F;
cacertfile(_) -> undefined.

%%--------------------------------------------------------------------
%% Identity
%%--------------------------------------------------------------------

%% @doc An explicit identity: `yuzu://<install>/server' with an install id of
%% 1 to 128 of A-Z a-z 0-9 . _ ~ -. Exact bytes; nothing is normalised. The
%% pattern is anchored with \\A and \\z: PCRE's `$' also matches before a
%% trailing newline, which would admit `yuzu://x/server\n'.
-spec validate_identity(term()) -> {ok, binary()} | error.
validate_identity(V) when is_list(V) ->
    try validate_identity(list_to_binary(V))
    catch _:_ -> error
    end;
validate_identity(V) when is_binary(V) ->
    case re:run(V, <<"\\Ayuzu://[A-Za-z0-9._~-]{1,128}/server\\z">>, [{capture, none}]) of
        match -> {ok, V};
        nomatch -> error
    end;
validate_identity(_) ->
    error.

%% @doc `yuzu://<UPPER-HEX-SHA256-OF-DER>/server' for a DER certificate.
%% Upper case, written explicitly: it must byte-match the server's
%% pki::fingerprint_sha256 with the colons stripped.
-spec identity_from_ca_der(binary()) -> binary().
identity_from_ca_der(Der) when is_binary(Der) ->
    Hex = binary:encode_hex(crypto:hash(sha256, Der), uppercase),
    <<"yuzu://", Hex/binary, "/server">>.

%% @doc Derive the identity from the CA file at Path: only when it holds
%% exactly one certificate. A bundle, an empty file, an unreadable one or an
%% undecodable one is `error'.
-spec derive_from_cacertfile(file:name_all() | undefined) -> {ok, binary()} | error.
derive_from_cacertfile(undefined) ->
    error;
derive_from_cacertfile(Path) ->
    case cacert_ders(Path) of
        [Der] -> {ok, identity_from_ca_der(Der)};
        _ -> error
    end.

%% @doc How many certificates the PEM file at Path holds (0 when absent,
%% unreadable or undecodable).
-spec cacert_count(file:name_all() | undefined) -> non_neg_integer().
cacert_count(undefined) ->
    0;
cacert_count(Path) ->
    length(cacert_ders(Path)).

%% The DER of every certificate in the PEM file at Path; [] when it is absent,
%% unreadable or not decodable (a half-written file raises inside pem_decode,
%% which is why the decode sits INSIDE the try).
cacert_ders(undefined) ->
    [];
cacert_ders(Path) ->
    try
        {ok, Pem} = file:read_file(Path),
        [Der || {'Certificate', Der, not_encrypted} <- public_key:pem_decode(Pem)]
    catch
        _:_ -> []
    end.

%%--------------------------------------------------------------------
%% Deny-list
%%--------------------------------------------------------------------

%% @doc `[{serial, Hex}]' to the serial numbers as integers; every defect is
%% reported, so a typo never silently narrows the list. Hex is a string or a
%% binary of 1 to 40 hex digits (any case, no separators).
-spec validate_denied(term()) -> {ok, [non_neg_integer()]} | {error, [term()]}.
validate_denied(List) ->
    %% length/1 raises on an improper list, which is a defect, not a crash.
    Count = try length(List) catch _:_ -> not_a_list end,
    validate_denied(List, Count).

validate_denied(List, Count) when is_integer(Count), Count =< ?MAX_DENIED ->
    Parsed = [parse_denied(E) || E <- List],
    case [{bad_mgmt_peer_denied, redact(E)} || {error, E} <- Parsed] of
        [] -> {ok, lists:usort([N || {ok, N} <- Parsed])};
        Bad -> {error, Bad}
    end;
validate_denied(_List, Count) when is_integer(Count) ->
    {error, [{bad_mgmt_peer_denied, {too_many_entries, Count}}]};
validate_denied(Other, not_a_list) ->
    {error, [{bad_mgmt_peer_denied, redact(Other)}]}.

parse_denied({serial, Hex}) when is_list(Hex) ->
    try parse_denied({serial, list_to_binary(Hex)})
    catch _:_ -> {error, {serial, Hex}}
    end;
parse_denied({serial, Hex} = E) when is_binary(Hex), byte_size(Hex) >= 1,
                                      byte_size(Hex) =< ?MAX_SERIAL_HEX ->
    case re:run(Hex, <<"\\A[0-9A-Fa-f]+\\z">>, [{capture, none}]) of
        match -> {ok, binary_to_integer(Hex, 16)};
        nomatch -> {error, E}
    end;
parse_denied(E) ->
    {error, E}.

%% A configured value in a boot log line is bounded, so a pasted blob cannot
%% flood it.
redact(V) ->
    unicode:characters_to_binary(io_lib:format("~0tP", [V, 8])).
