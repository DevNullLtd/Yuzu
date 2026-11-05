%%%-------------------------------------------------------------------
%%% @doc The management-plane CRL watcher (#6016 PR 4b): fetch the install CA's CRL, verify it,
%%% publish it, and let the stream check refuse the server's certificate once the CA has revoked it.
%%%
%%% yuzu_gw_authz admits the server by its identity (yuzu_gw_mgmt_identity). That is an
%%% ADMISSION rule: it says nothing about a certificate the CA has since REVOKED. This process feeds
%%% the second half: every `mgmt_crl_refresh_ms' it reads the CRL, parses and verifies it
%%% (yuzu_gw_mgmt_crl, by SIGNATURE), and publishes the revoked serials to persistent_term, one put
%%% per actual change, so the per-stream check (yuzu_gw_mgmt_crl:check/4) is a persistent_term
%%% read and does no I/O on the Cowboy connection process (M1(b), #5696). A stalled server or
%%% volume stalls this process only.
%%%
%%% Configuration, all optional (`{yuzu_gw, ...}'; an absent `mgmt_crl_source' means no CRL check):
%%%
%%%   mgmt_crl_source      {url, Url} | {url, Url, #{cacertfile => Path}} | {file, Path}
%%%     url   GET of an https URL, normally the server's own `https://<server>:8443/api/v1/ca/crl'.
%%%           The TLS options are set EXPLICITLY (verify_peer, the fetch CA, SNI, hostname
%%%           verification; there is no way to turn verification off). The trust anchor is the
%%%           per-source `cacertfile' when given, else the management listener's `cacertfile'.
%%%           The server's HTTPS port presents default-https.pem (signed by the install CA)
%%%           unless the operator gave --https-cert/--https-key; a corporate or public certificate
%%%           there does not chain to the install CA, so name its CA in `cacertfile' (or use `file').
%%%           The URL host must be in that certificate's SANs.
%%%     file  a CRL file the operator keeps current (DER or PEM). Its health is on the same gauges.
%%%   mgmt_crl_grace_s     0..604800, default 86400: how long past nextUpdate a loaded CRL is still
%%%                        believed (yuzu_gw_mgmt_crl:check/4).
%%%   mgmt_crl_refresh_ms  1000..3600000, default 5000. Separate from mgmt_pin_refresh_ms: a url
%%%                        source is a request to another host, not a stat of a local file. Each
%%%                        wait is jittered DOWN by up to 10% (never up: the withdrawal latency
%%%                        bound of ADR 2004 A6(a) is this interval).
%%%   mgmt_crl_max_validity_s  3600..31536000, default UNSET (no bound): the widest `nextUpdate -
%%%                        thisUpdate' a CRL may carry; wider is refused `validity_too_long'. Never
%%%                        measured against the gateway's clock. The shipped reference configs set
%%%                        691200 (8 days: above the 7 days an older server publishes).
%%%
%%% Every defect in these is a boot defect (yuzu_gw_app:check_mgmt_crl_source/0): a malformed value,
%%% an `http://' URL, userinfo in the URL, a missing `cacertfile' override, a url source with no
%%% fetch CA to use. None falls back silently.
%%%
%%% Fail closed, last known good. With a source configured, the check refuses every stream as
%%% `revocation_unknown' until a CRL has loaded. Once one has, a failed fetch or a bad file KEEPS it
%%% (and counts a rejection by reason); a CRL that fails verification, names the wrong issuer, is
%%% dated in the future or is a replay never evicts the loaded one. The only thing that ends a
%%% loaded CRL's usefulness is time: past `nextUpdate + grace' the check refuses as
%%% `revocation_stale'. So the gateway never admits on a CRL it could not verify, and a server that
%%% cannot publish for longer than that takes the management plane down until a server replica is
%%% restarted (a restart republishes the CRL at startup, independent of leadership).
%%%
%%% Boot. init/1 loads once, synchronously (the fetch bounded to 5 s, the whole call total: nothing
%%% escapes), before the listeners start. A source with no good CRL at boot does NOT stop the
%%% gateway, since the agent plane must come up: the management plane refuses with
%%% `revocation_unknown' and the alerts fire. The server does not retry a refused management
%%% stream, so the synchronous boot load only closes the race of the first stream; correctness
%%% never depends on it.
%%%
%%% Fetch mechanics. One gun connection per attempt, in a worker process that is killed at the
%%% deadline (a tick is bounded to 3 s, the boot load to 5 s; a FILE read is bounded the same way
%%% but its worker cannot be killed out of a blocked call, see run_worker/4), the body read with a running byte
%%% bound (yuzu_gw_mgmt_crl:max_bytes/0) and aborted mid-stream past it. An `ETag' the server sends
%%% is returned as `If-None-Match' on the next attempt, and a 304 is "unchanged". A parse is skipped
%%% when neither the CRL's bytes nor the verification certificates changed.
%%%
%%% Rejected bytes. A rejection whose cause is the bytes (and the verification certificates) alone
%%% (`malformed', `unsupported', `too_large', `unverified', `issuer_mismatch', `validity_too_long')
%%% is remembered by the key (hash of the bytes, hash of the certificates, the `max_validity_s' in
%%% force) until one of them changes, so the same bad file is not decoded and verified again on every
%%% tick. The memory lasts memo_ttl_s() (one hour): then the same bytes are parsed, counted and logged
%%% again, which bounds a refusal pinned by a transient fault and reminds of a persistent one. `future_dated' (it clears when
%%% the clock catches up), `replay' (it depends on the CRL held and on its staleness: remembering it
%%% would turn the bounded blind window of ADR 2004 A8 into a `revocation_stale' outage) and every
%%% fetch failure are never remembered. A remembered refusal is REPORTED exactly like a fresh one
%%% (the gauges say the latest attempt obtained nothing good, so `last_success' does not advance and
%%% the alerts keyed on it still fire); the only difference is that the rejection COUNTER moves once
%%% per distinct rejection rather than once per tick.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_crl_source).
-behaviour(gen_server).

-export([start_link/0]).
-export([policy/0, publish_policy/1, current/0, reset/0, grace_s/0]).
-export([resolve/0, resolve/4, resolve/5, refresh_ms/0, reject_reasons/0]).
-export([load/4, fetch/3, parse_url/1, tls_options/3, tls_options_ders/3, replace_rule/4]).
-export([jittered_ms/2, max_jitter_fraction/0, memoisable/1, size_warn_interval_s/0, memo_ttl_s/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-export_type([policy/0, source/0, tick_state/0]).

-define(SERVER, ?MODULE).
-define(POLICY, {?MODULE, policy}).
-define(CRL, {?MODULE, crl}).
-define(DEFAULT_GRACE_S, 86400).
-define(MAX_GRACE_S, 604800).
-define(DEFAULT_REFRESH_MS, 5000).
-define(MIN_REFRESH_MS, 1000).
-define(MAX_REFRESH_MS, 3600000).
-define(TICK_FETCH_MS, 3000).
-define(BOOT_FETCH_MS, 5000).
-define(CA_READ_MS, 2000).
%% The widest nextUpdate - thisUpdate an operator may set as the bound: from one hour (below that
%% no CA publishes and the setting is a typo) to a year.
-define(MIN_MAX_VALIDITY_S, 3600).
-define(MAX_MAX_VALIDITY_S, 31536000).
%% The refresh wait is shortened by a random fraction of up to this much, never lengthened.
-define(JITTER_FRACTION, 0.1).
%% The near-the-size-bound warning is logged at most once per this many seconds.
-define(SIZE_WARN_INTERVAL_S, 3600).
%% A remembered refusal is honoured for this many seconds, then the same bytes are parsed, counted
%% and logged again: it bounds a refusal pinned by a transient fault and reminds of a persistent one.
-define(MEMO_TTL_S, 3600).
%% What a remembered rejection can be: refusals decided by the bytes and the verification
%% certificates ALONE (see the module doc).
-define(MEMOISABLE, [malformed, unsupported, too_large, unverified, issuer_mismatch,
                     validity_too_long]).

-type source() :: {url, #{host := string(), port := 1..65535, path := string(),
                          cacertfile := string()}}
                | {file, string()}.
-type policy() :: #{source := source(),
                    grace_s := 0..604800,
                    refresh_ms := 1000..3600000,
                    %% absent: no bound
                    max_validity_s => 3600..31536000,
                    verify_cacertfiles := [string()]}.
%% `rejected': the key, reason and time (seconds since the epoch) of the last memoisable rejection,
%% since the last accepted CRL. The key is the hash of the bytes, the hash of the verification
%% certificates and the `max_validity_s' in force; it is honoured for `memo_ttl_s()' seconds.
%% `size_warned_at': seconds since the epoch of the last near-the-bound warning.
%% Both optional so a state built before they existed still works.
-type tick_state() :: #{crl := yuzu_gw_mgmt_crl:crl() | none,
                        crl_hash := binary() | undefined,
                        ca_hash := binary() | undefined,
                        etag := binary() | undefined,
                        last_reject := atom() | undefined,
                        rejected => none | {binary(), binary(), pos_integer() | undefined, atom(), integer()},
                        size_warned_at => integer() | undefined,
                        %% the bound of the load in progress, for the log line of a refusal
                        max_validity_s => pos_integer() | undefined}.

%%--------------------------------------------------------------------
%% Published state (persistent_term reads; no process call)
%%--------------------------------------------------------------------

%% @doc The resolved configuration, or `none' when no CRL source is configured. What the boot
%% guard published.
-spec policy() -> policy() | none.
policy() ->
    persistent_term:get(?POLICY, none).

-spec publish_policy(policy() | none) -> ok.
publish_policy(Policy) ->
    persistent_term:put(?POLICY, Policy).

%% @doc The loaded CRL, or `none'.
-spec current() -> yuzu_gw_mgmt_crl:crl() | none.
current() ->
    case persistent_term:get(?CRL, none) of
        #{crl := Crl} -> Crl;
        none -> none
    end.

%% @doc Forget everything published (tests).
-spec reset() -> ok.
reset() ->
    _ = persistent_term:erase(?POLICY),
    _ = persistent_term:erase(?CRL),
    [clear_stuck(K) || K <- [file, ca, fetch_ca, http]],
    ok.

%% @doc The grace the stream check applies; the default when no policy is published.
-spec grace_s() -> non_neg_integer().
grace_s() ->
    case policy() of
        #{grace_s := G} -> G;
        none -> ?DEFAULT_GRACE_S
    end.

%% @doc The closed set of reasons yuzu_gw_mgmt_crl_rejected_total carries: why a CRL was not loaded
%% (yuzu_gw_mgmt_crl) or not obtained (the fetch).
-spec reject_reasons() -> [atom()].
reject_reasons() ->
    [malformed, unsupported, too_large, unverified, issuer_mismatch, validity_too_long,
     future_dated, replay,
     fetch_timeout, fetch_connect, fetch_tls, fetch_status, fetch_error, file_unreadable].

%% @doc The reasons a rejection is remembered for (by bytes and verification certificates).
-spec memoisable(atom()) -> boolean().
memoisable(Reason) ->
    lists:member(Reason, ?MEMOISABLE).

%% @doc The largest share of the refresh interval a wait is shortened by.
-spec max_jitter_fraction() -> float().
max_jitter_fraction() -> ?JITTER_FRACTION.

%% @doc The wait before the next refresh: the interval shortened by `R' (a number in [0, 1)) times
%% the largest jitter share, so always in (0.9 * Interval, Interval]. DOWN only: a longer wait would
%% stretch ADR 2004 A6(a)'s "up to mgmt_crl_refresh_ms after the server publishes". `R' is a
%% parameter so the bounds are test-pinned without randomness.
-spec jittered_ms(pos_integer(), float()) -> pos_integer().
jittered_ms(Interval, R) when is_integer(Interval), Interval > 0, is_number(R), R >= 0, R < 1 ->
    max(1, Interval - trunc(Interval * ?JITTER_FRACTION * R)).

%% @doc Seconds a remembered refusal is honoured before the same bytes are parsed again.
-spec memo_ttl_s() -> pos_integer().
memo_ttl_s() -> ?MEMO_TTL_S.

%% @doc Seconds between two near-the-size-bound warnings.
-spec size_warn_interval_s() -> pos_integer().
size_warn_interval_s() -> ?SIZE_WARN_INTERVAL_S.

%%--------------------------------------------------------------------
%% Configuration
%%--------------------------------------------------------------------

%% @doc Resolve the configuration from the application environment.
-spec resolve() -> {ok, policy() | none} | {error, [term()]}.
resolve() ->
    resolve(application:get_env(yuzu_gw, mgmt_crl_source, undefined),
            application:get_env(yuzu_gw, mgmt_crl_grace_s, undefined),
            application:get_env(yuzu_gw, mgmt_crl_refresh_ms, undefined),
            application:get_env(yuzu_gw, grpc_listeners, []),
            application:get_env(yuzu_gw, mgmt_crl_max_validity_s, undefined)).

%% @doc Pure core (the file-existence check of a `cacertfile' override aside) -- exported for
%% testing. Every defect is returned together so one boot attempt names them all.
-spec resolve(term(), term(), term(), term()) -> {ok, policy() | none} | {error, [term()]}.
resolve(Source, Grace, Refresh, Listeners) ->
    resolve(Source, Grace, Refresh, Listeners, undefined).

%% @doc resolve/4 with `mgmt_crl_max_validity_s'.
-spec resolve(term(), term(), term(), term(), term()) -> {ok, policy() | none} | {error, [term()]}.
resolve(undefined, Grace, Refresh, _Listeners, MaxValidity) ->
    %% No source: the other keys are then meaningless, and a malformed one is still a typo.
    case [E || {error, E} <- [grace(Grace), refresh(Refresh), max_validity(MaxValidity)]] of
        [] -> {ok, none};
        Errors -> {error, Errors}
    end;
resolve(Source0, Grace0, Refresh0, Listeners, MaxValidity0) ->
    VerifyFiles = mgmt_cacertfiles(Listeners),
    Source = source(Source0, VerifyFiles),
    Grace = grace(Grace0),
    Refresh = refresh(Refresh0),
    MaxValidity = max_validity(MaxValidity0),
    case lists:flatmap(fun({error, E}) when is_list(E) -> E; ({error, E}) -> [E]; (_) -> [] end,
                       [Source, Grace, Refresh, MaxValidity]) of
        [] ->
            {ok, S} = Source,
            {ok, G} = Grace,
            {ok, R} = Refresh,
            {ok, M} = MaxValidity,
            Policy = #{source => S, grace_s => G, refresh_ms => R,
                       verify_cacertfiles => VerifyFiles},
            {ok, case M of
                     undefined -> Policy;
                     _ -> Policy#{max_validity_s => M}
                 end};
        Errors ->
            {error, Errors}
    end.

grace(undefined) -> {ok, ?DEFAULT_GRACE_S};
grace(G) when is_integer(G), G >= 0, G =< ?MAX_GRACE_S -> {ok, G};
grace(G) -> {error, {bad_mgmt_crl_grace_s, G, {expected_integer_seconds_between, 0, ?MAX_GRACE_S}}}.

%% Unset is no bound (the code default; the shipped reference configs set one).
max_validity(undefined) -> {ok, undefined};
max_validity(V) when is_integer(V), V >= ?MIN_MAX_VALIDITY_S, V =< ?MAX_MAX_VALIDITY_S -> {ok, V};
max_validity(V) ->
    {error, {bad_mgmt_crl_max_validity_s, V,
             {expected_integer_seconds_between, ?MIN_MAX_VALIDITY_S, ?MAX_MAX_VALIDITY_S}}}.

refresh(undefined) -> {ok, ?DEFAULT_REFRESH_MS};
refresh(R) when is_integer(R), R >= ?MIN_REFRESH_MS, R =< ?MAX_REFRESH_MS -> {ok, R};
refresh(R) ->
    {error, {bad_mgmt_crl_refresh_ms, R,
             {expected_integer_ms_between, ?MIN_REFRESH_MS, ?MAX_REFRESH_MS}}}.

%% The refresh interval in milliseconds, from the published policy.
-spec refresh_ms() -> pos_integer().
refresh_ms() ->
    case policy() of
        #{refresh_ms := R} -> R;
        none -> ?DEFAULT_REFRESH_MS
    end.

source({file, Path}, _VerifyFiles) when is_list(Path), Path =/= [] ->
    case printable(Path) of
        true  -> {ok, {file, Path}};
        false -> {error, {bad_mgmt_crl_source, {file, redacted}}}
    end;
source({url, Url}, VerifyFiles) ->
    source({url, Url, #{}}, VerifyFiles);
source({url, Url, Opts}, VerifyFiles) when is_map(Opts) ->
    case {parse_url(Url), fetch_ca(Opts, VerifyFiles)} of
        {{ok, U}, {ok, Ca}} -> {ok, {url, U#{cacertfile => Ca}}};
        {{error, E}, {ok, _}} -> {error, E};
        {{ok, _}, {error, E}} -> {error, E};
        {{error, E1}, {error, E2}} -> {error, [E1, E2]}
    end;
source(Other, _VerifyFiles) ->
    %% The term is NOT echoed: a source written in the wrong shape (a proplist where a map is
    %% required, a 4-tuple) can still hold a URL with a credential in it, and this goes to a boot
    %% log line. Only its outline is reported.
    {error, {bad_mgmt_crl_source, outline(Other)}}.

%% The CA the fetch trusts: the override when given (it must exist: a typo must not become a
%% silent fall back to another anchor), else the management listener's cacertfile.
fetch_ca(#{cacertfile := Path}, _VerifyFiles) when is_list(Path), Path =/= [] ->
    case filelib:is_regular(Path) of
        true  -> {ok, Path};
        false -> {error, {bad_mgmt_crl_cacertfile, Path, not_a_file}}
    end;
fetch_ca(#{cacertfile := Other}, _VerifyFiles) ->
    {error, {bad_mgmt_crl_cacertfile, shape(Other)}};
fetch_ca(Opts, VerifyFiles) when is_map(Opts) ->
    case maps:keys(Opts) -- [cacertfile] of
        [] ->
            case VerifyFiles of
                [First | _] -> {ok, First};
                [] -> {error, {no_mgmt_crl_fetch_ca,
                               "no management listener cacertfile to trust; set "
                               "#{cacertfile => Path} in mgmt_crl_source"}}
            end;
        Unknown ->
            {error, {bad_mgmt_crl_source_options, Unknown}}
    end.

%% @doc Parse an https URL into the parts the fetch needs. http, a missing host, userinfo (a
%% credential in a configuration file and a log line), a fragment and an empty authority are
%% defects.
-spec parse_url(term()) -> {ok, #{host := string(), port := 1..65535, path := string()}}
                         | {error, term()}.
parse_url(Url) when is_binary(Url) ->
    try parse_url(unicode:characters_to_list(Url))
    catch _:_ -> {error, {bad_mgmt_crl_url, redacted}}
    end;
parse_url(Url) when is_list(Url) ->
    try uri_string:parse(Url) of
        #{scheme := "https", host := Host} = Parts when Host =/= "" ->
            case maps:is_key(userinfo, Parts) orelse maps:is_key(fragment, Parts) of
                true ->
                    {error, {bad_mgmt_crl_url, "userinfo and fragment are not allowed"}};
                false ->
                    Path = case maps:get(path, Parts, "") of "" -> "/"; P -> P end,
                    Query = case maps:find(query, Parts) of
                                {ok, Q} -> "?" ++ Q;
                                error -> ""
                            end,
                    case maps:get(port, Parts, 443) of
                        Port when is_integer(Port), Port >= 1, Port =< 65535 ->
                            {ok, #{host => Host, port => Port, path => Path ++ Query}};
                        _ ->
                            {error, {bad_mgmt_crl_url, "the port must be a number from 1 to 65535"}}
                    end
            end;
        #{scheme := "http"} ->
            {error, {bad_mgmt_crl_url, "must be https: the CRL is signed, but TLS keeps a "
                                       "replayed or withheld CRL out of the path"}};
        _ ->
            {error, {bad_mgmt_crl_url, url_shape(Url)}}
    catch _:_ -> {error, {bad_mgmt_crl_url, url_shape(Url)}}
    end;
parse_url(Other) ->
    {error, {bad_mgmt_crl_url, url_shape(Other)}}.

%% A URL that did not parse, as the boot log may carry it: NOT AT ALL. It was typed into a
%% configuration file, it may hold a credential in userinfo or in a query token, and no pattern
%% over its text can promise to catch every way of writing one (a password with `/', `?' or `#'
%% in it, a scheme-less `user:secret@host', an invalid port). The error names the problem; the
%% operator has the value in front of them in their own configuration.
url_shape(_Url) -> redacted.

%% The outline of a term that is not a source in any accepted shape: its kind, never its contents.
outline(V) when is_tuple(V) ->
    {tuple, tuple_size(V), case element(1, V) of A when is_atom(A) -> A; _ -> other end};
outline(V) when is_map(V) -> map;
outline(V) when is_list(V) -> list;
outline(V) when is_binary(V) -> binary;
outline(V) when is_atom(V) -> V;
outline(_) -> other.

mgmt_cacertfiles(Listeners) ->
    try
        [F || S <- Listeners, yuzu_grpc_listener:serves_proto(S, management_pb),
              F <- [mgmt_cacertfile(S)], F =/= undefined]
    catch _:_ -> []
    end.

mgmt_cacertfile(#{tls := #{cacertfile := F}}) when is_list(F), F =/= [] -> F;
mgmt_cacertfile(#{tls := #{cacertfile := F}}) when is_binary(F), F =/= <<>> ->
    binary_to_list(F);
mgmt_cacertfile(_) -> undefined.

%% A configured value in a boot log line is bounded, so a pasted blob cannot flood it.
shape(V) -> unicode:characters_to_binary(io_lib:format("~0tP", [V, 6])).

printable(Path) ->
    try unicode:characters_to_binary(Path) =/= <<>> andalso io_lib:printable_unicode_list(Path)
    catch _:_ -> false
    end.

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
    case policy() of
        none ->
            report_state(none, false),
            ignore;
        #{refresh_ms := Interval} = Policy ->
            %% Synchronous on purpose: the listeners start after this returns. The tick state is
            %% seeded from the CRL already published, so a restart of THIS process (a crash and
            %% the supervisor's restart) keeps the replace rule's high-water mark: an older CRL
            %% still cannot displace the one the stream check is using. A restart of the whole
            %% gateway empties persistent_term and does not (ADR 2004, A6(d)).
            State = safe_load(Policy, seeded_state(), ?BOOT_FETCH_MS),
            schedule(Interval),
            {ok, #{policy => Policy, tick => State}}
    end.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(refresh, #{policy := #{refresh_ms := Interval} = Policy, tick := Tick} = State) ->
    Tick1 = safe_load(Policy, Tick, ?TICK_FETCH_MS),
    schedule(Interval),
    {noreply, State#{tick := Tick1}};
handle_info(_Msg, State) ->
    {noreply, State}.

schedule(Interval) ->
    erlang:send_after(jittered_ms(Interval, rand:uniform()), self(), refresh),
    ok.

-spec new_state() -> tick_state().
new_state() ->
    #{crl => none, crl_hash => undefined, ca_hash => undefined, etag => undefined,
      last_reject => undefined, rejected => none, size_warned_at => undefined}.

-spec seeded_state() -> tick_state().
seeded_state() ->
    (new_state())#{crl := current()}.

%% A defect in loading must never stop the watcher (a crash here would restart it every tick and
%% could take the supervisor, and so the gateway, down): it is logged and the previous state kept.
safe_load(Policy, State, FetchMs) ->
    try
        load(Policy, State, fun(P, S) -> fetch(P, S, FetchMs) end, os:system_time(second))
    catch
        Class:Reason ->
            %% Rate-limited: a defect that persists would otherwise log every tick. Only the
            %% KIND of the failure is logged, never its terms: they can hold a path, a URL or
            %% the CRL's own bytes.
            yuzu_gw_safe_call:warn_limited(
              mgmt_crl_load_failed,
              "mgmt_crl_source: loading the CRL failed unexpectedly: ~p:~p; the "
              "previous CRL, if any, stays loaded", [Class, failure_kind(Reason)]),
            %% The gauges must reflect that a source is configured even when the very first
            %% attempt failed this way, or YuzuGatewayMgmtCrlNotLoaded (enforced == 1) cannot fire.
            _ = (catch report_state(maps:get(crl, State), false)),
            State
    end.

failure_kind(Reason) when is_atom(Reason) -> Reason;
failure_kind(Reason) when is_tuple(Reason), tuple_size(Reason) > 0,
                          is_atom(element(1, Reason)) -> element(1, Reason);
failure_kind(_) -> other.

%%--------------------------------------------------------------------
%% One load
%%--------------------------------------------------------------------

%% @doc One refresh, in the calling process: obtain the bytes (Fetch/2), verify, apply the replace
%% rule, publish if the CRL changed, report. `Now' is seconds since the epoch. Returns the next
%% state. Exported so the tests drive it with a fake fetch and a chosen clock.
-spec load(policy(), tick_state(), fun((policy(), tick_state()) ->
                                           {ok, binary(), binary() | undefined}
                                         | not_modified
                                         | {error, atom()}), integer()) -> tick_state().
load(#{verify_cacertfiles := Files} = Policy, State0, Fetch, Now) ->
    State = State0#{max_validity_s => maps:get(max_validity_s, Policy, undefined)},
    case Fetch(Policy, State) of
        {ok, Bin, Etag} ->
            case verification_set(Files) of
                {ok, CaDers} -> applied(Bin, CaDers, Etag, State, Now, Policy);
                {error, Reason} -> rejected(Reason, State)
            end;
        not_modified ->
            report_state(maps:get(crl, State), true),
            State;
        {error, Reason} ->
            rejected(Reason, State)
    end.

applied(Bin, CaDers, Etag, State0, Now, Policy) ->
    #{crl := Loaded, crl_hash := OldHash, ca_hash := OldCaHash} = State =
        warn_size(Bin, State0, Now),
    Grace = maps:get(grace_s, Policy),
    Hash = crypto:hash(sha256, Bin),
    CaHash = crypto:hash(sha256, CaDers),
    case Loaded =/= none andalso Hash =:= OldHash andalso CaHash =:= OldCaHash of
        true ->
            %% The same bytes under the same certificates: nothing to verify again.
            report_state(Loaded, true),
            State#{etag := Etag, last_reject := undefined};
        false ->
            MaxValidity = maps:get(max_validity_s, Policy, undefined),
            case memo_state(maps:get(rejected, State, none), Hash, CaHash, MaxValidity, Now) of
                {hit, Reason} ->
                    %% Bytes already refused under these certificates and this bound, for a reason
                    %% only they decide: not parsed or verified again, and not counted again, but
                    %% reported exactly as a refusal is (the gauges, the log on a change of
                    %% reason). The ETag is NOT advanced, as on any refusal, so the next request is
                    %% not a 304 that would read as success.
                    rejected_again(Reason, State);
                Other ->
                    %% `expired': the memory is an hour old, so the refusal is decided, counted and
                    %% logged again (last_reject is cleared so the log line is not suppressed).
                    State1 = case Other of
                                 expired -> State#{rejected => none, last_reject := undefined};
                                 none    -> State
                             end,
                    Opts = case Policy of
                               #{max_validity_s := Max} -> #{max_validity_s => Max};
                               _ -> #{}
                           end,
                    Parsed = yuzu_gw_mgmt_crl:parse(Bin, CaDers, Now, Opts),
                    %% The parse of a CRL near the bound leaves hundreds of MiB of garbage on this
                    %% long-lived process's heap; collect it now rather than at some later GC.
                    _ = erlang:garbage_collect(),
                    case Parsed of
                        {ok, New} ->
                            install(New, Hash, CaHash, Etag, State1, Now, Grace);
                        {error, Reason} ->
                            remember(Reason, {Hash, CaHash, MaxValidity, Now},
                                     rejected(Reason, State1))
                    end
            end
    end.

%% Is there a live memory of exactly these bytes, certificates and bound? `expired' once it is
%% `memo_ttl_s()' old, or when the clock has been stepped back past it (it cannot be trusted to age).
memo_state({Hash, CaHash, MaxValidity, Reason, At}, Hash, CaHash, MaxValidity, Now) ->
    case Now < At orelse Now - At >= ?MEMO_TTL_S of
        true  -> expired;
        false -> {hit, Reason}
    end;
memo_state(_Other, _Hash, _CaHash, _MaxValidity, _Now) ->
    none.

%% Remember a refusal only when the bytes, the certificates and the bound alone decided it.
remember(Reason, {Hash, CaHash, MaxValidity, Now}, State) ->
    case memoisable(Reason) of
        true  -> State#{rejected => {Hash, CaHash, MaxValidity, Reason, Now}};
        false -> State
    end.

%% Near the size bound: a CRL only grows (revoked rows are append-only), and past the bound every
%% fetch is `too_large'. Said when the body has passed three quarters of it, at most once an hour.
warn_size(Bin, State, Now) ->
    Size = byte_size(Bin),
    Last = maps:get(size_warned_at, State, undefined),
    case Size > yuzu_gw_mgmt_crl:warn_bytes()
         andalso (Last =:= undefined orelse Now < Last orelse Now - Last >= ?SIZE_WARN_INTERVAL_S) of
        true ->
            Max = yuzu_gw_mgmt_crl:max_bytes(),
            logger:warning(
              "mgmt_crl_source: the CA's CRL is ~b bytes, ~.1f% of the ~b byte bound; past it "
              "every fetch is refused (too_large) and the CRL held stops being refreshed. The "
              "CRL only grows: plan the gateway upgrade (docs/user-manual/gateway.md, Limits)",
              [Size, Size * 100 / Max, Max]),
            State#{size_warned_at => Now};
        false ->
            State
    end.

install(New, Hash, CaHash, Etag, #{crl := Loaded} = State0, Now, Grace) ->
    %% An accepted (or identical) CRL ends the memory of a refusal.
    State = State0#{rejected => none},
    case replace_rule(Loaded, New, Now, Grace) of
        {replace, Crl} ->
            ok = persistent_term:put(?CRL, #{crl => Crl, loaded_at => Now}),
            logger:notice("mgmt_crl_source: loaded the CA's CRL number ~b (thisUpdate ~b, "
                          "nextUpdate ~b, ~b revoked serial(s))",
                          [maps:get(number, Crl), maps:get(this_update, Crl),
                           maps:get(next_update, Crl), map_size(maps:get(revoked, Crl))]),
            report_state(Crl, true),
            State#{crl := Crl, crl_hash := Hash, ca_hash := CaHash, etag := Etag,
                   last_reject := undefined};
        unchanged ->
            report_state(Loaded, true),
            State#{crl_hash := Hash, ca_hash := CaHash, etag := Etag, last_reject := undefined};
        {reject, replay} ->
            case maps:get(last_reject, State) of
                replay -> ok;
                _ ->
                    %% Said once per change of reason, with the numbers: a CRL that is only OLDER
                    %% looks the same as one from a server whose clock is far behind.
                    logger:warning(
                      "mgmt_crl_source: refused CRL number ~b (thisUpdate ~b, nextUpdate ~b) against "
                      "the CRL in force, number ~b (thisUpdate ~b, nextUpdate ~b): older, or already "
                      "stale (is the server's clock behind?)",
                      [maps:get(number, New), maps:get(this_update, New), maps:get(next_update, New),
                       maps:get(number, Loaded), maps:get(this_update, Loaded),
                       maps:get(next_update, Loaded)])
            end,
            %% Never remembered: the verdict depends on the CRL held and on how stale it is, so it
            %% is decided again every tick (A8's bounded blind window is not an outage). It is not
            %% an acceptance either, so the memory of an EARLIER refusal (State0) stands.
            rejected(replay, State0)
    end.

%% The replace rule of yuzu_gw_mgmt_crl:replace/2, plus one more refusal: a CRL that is already
%% past its nextUpdate plus the grace never displaces a held CRL that is still believed. Such a CRL
%% (a server whose clock is days behind publishes them) could only turn every stream into
%% `revocation_stale', and the CRL it would evict is the better evidence. It is counted as `replay':
%% an older CRL than the one in force. When the held CRL is itself stale, or none is held, the
%% ordinary rule applies.
replace_rule(Loaded, New, Now, Grace) ->
    case Loaded =/= none andalso not stale(Loaded, Now, Grace) andalso stale(New, Now, Grace) of
        true  -> {reject, replay};
        false -> yuzu_gw_mgmt_crl:replace(Loaded, New)
    end.

stale(#{next_update := Next}, Now, Grace) -> Now > Next + Grace.

%% Count a refusal by reason; log it when the reason CHANGES (a bad file is one line, not one per
%% tick). The loaded CRL, if any, is untouched.
rejected(Reason, State) ->
    telemetry:execute([yuzu, gw, mgmt_crl, rejected], #{count => 1}, #{reason => Reason}),
    rejected_again(Reason, State).

%% A refusal of bytes already counted: everything of rejected/2 except the count. The state it
%% reports is the same as a fresh refusal's (the latest attempt obtained nothing good), which is
%% what the alerts read.
rejected_again(Reason, #{crl := Loaded, last_reject := Last} = State) ->
    case Reason =:= Last of
        true -> ok;
        false ->
            logger:warning("mgmt_crl_source: the CRL was not loaded (~p); ~s~s",
                           [Reason, case Loaded of
                                        none -> "no CRL is loaded, so every management stream is "
                                                "refused (revocation_unknown) until one is";
                                        _ -> "the CRL loaded earlier stays in force until "
                                             "nextUpdate plus the grace"
                                    end, hint(Reason, maps:get(max_validity_s, State, undefined))])
    end,
    report_state(Loaded, false),
    State#{last_reject := Reason}.

%% What the operator can do about a refusal whose cause is a setting of theirs, appended to the log line.
hint(validity_too_long, Bound) ->
    io_lib:format(". A CRL wider than the configured mgmt_crl_max_validity_s (~s) was refused: "
                  "raise the key or leave it unset (docs/user-manual/gateway.md)",
                  [case Bound of undefined -> "unset"; _ -> integer_to_list(Bound) ++ " s" end]);
hint(_Reason, _Bound) ->
    "".

%% The certificates the CRL may be verified against: every certificate of every management
%% listener's cacertfile, read now (a re-rooted CA is picked up without a restart).
%% The read runs in a bounded worker like the fetch: a stalled volume under a cacertfile must not
%% wedge this process (and with it the only thing that refreshes the CRL). If no certificate could
%% be had because a read failed, that is `file_unreadable', not "the CRL is unverified".
verification_set(Files) ->
    case run_worker(ca, fun() -> {ok, read_verification_set(Files)} end, ?CA_READ_MS,
                    file_unreadable) of
        {ok, {[], true}}   -> {error, file_unreadable};
        {ok, {Ders, true}} ->
            %% Verified against what could be read: a CRL signed by the file that could not be
            %% read will be `unverified', which is not the cause.
            yuzu_gw_safe_call:warn_limited(
              mgmt_crl_ca_partial,
              "mgmt_crl_source: a management listener cacertfile could not be read; the CRL is "
              "verified against the certificates that could be", []),
            {ok, Ders};
        {ok, {Ders, false}} -> {ok, Ders};
        {error, _}          -> {error, file_unreadable}
    end.

read_verification_set(Files) ->
    lists:foldl(fun(F, {Ders, Failed}) ->
                        %% Raw, as the CRL file's read is, and not file:read_file/1: that call is
                        %% served by the VM's file server process, so a read that blocks in it would
                        %% stall every other file operation in the VM. A raw read blocks only this
                        %% worker (and pins its OS thread, which is why such a worker is never
                        %% killed and never stacked: see run_worker/4).
                        case read_file(F) of
                            {ok, Pem, _} -> {Ders ++ yuzu_gw_mgmt_crl:ca_certs(Pem), Failed};
                            {error, _}   -> {Ders, true}
                        end
                end, {[], false}, Files).

%% The gauges. `Healthy' is whether the latest attempt obtained something; the state of the loaded
%% CRL itself (loaded, number, nextUpdate, size) is reported either way.
report_state(none, Healthy) ->
    telemetry:execute([yuzu, gw, mgmt_crl, state],
                      success(Healthy, #{enforced => enforced(), loaded => 0, number => 0,
                                         next_update => 0, revoked_entries => 0}), #{});
report_state(#{number := N, next_update := Next, revoked := Revoked}, Healthy) ->
    telemetry:execute([yuzu, gw, mgmt_crl, state],
                      success(Healthy, #{enforced => enforced(), loaded => 1, number => N,
                                         next_update => Next,
                                         revoked_entries => map_size(Revoked)}), #{}).

%% `last_success' (seconds since the epoch) rides on the state event only when the latest attempt
%% obtained something, so the gauge keeps the time of the last good attempt and an alert can see a
%% watcher that is wedged or whose fetches keep failing behind a still-valid CRL.
success(true, Measurements) -> Measurements#{last_success => os:system_time(second)};
success(false, Measurements) -> Measurements.

enforced() ->
    case policy() of none -> 0; _ -> 1 end.

%%--------------------------------------------------------------------
%% Fetch
%%--------------------------------------------------------------------

%% @doc Obtain the CRL bytes for Policy. Total: any failure is a closed reason, nothing is raised.
%% `TimeoutMs' bounds the whole attempt (connect, handshake, request, body).
-spec fetch(policy(), tick_state(), pos_integer()) ->
          {ok, binary(), binary() | undefined} | not_modified | {error, atom()}.
fetch(#{source := {file, Path}}, _State, TimeoutMs) ->
    %% In a worker for the same reason as the url path: an open or read of a file on a dead mount
    %% or a FIFO with no writer never returns, and must not take init/1 or the watcher with it.
    case run_worker(file, fun() -> read_file(Path) end, TimeoutMs + 500, file_unreadable) of
        {error, fetch_timeout} -> {error, file_unreadable};
        Other -> Other
    end;
fetch(#{source := {url, #{cacertfile := Ca} = Url}}, #{etag := Etag}, TimeoutMs) ->
    %% The fetch CA is read HERE, raw and bounded, and handed to TLS as certificates: given as
    %% `{cacertfile, Path}' OTP's ssl would read it with file:read_file/1 inside the (killable)
    %% HTTP worker, through the VM's file server process, where a blocked read stalls every file
    %% operation in the VM.
    case run_worker(fetch_ca, fun() -> read_ca_ders(Ca) end, ?CA_READ_MS, file_unreadable) of
        {ok, Ders} ->
            run_worker(http, fun() -> http_get(Url#{cacerts => Ders}, Etag, TimeoutMs) end,
                       TimeoutMs + 500, fetch_timeout);
        {error, fetch_timeout} ->
            {error, file_unreadable};
        {error, _} = Error ->
            Error
    end.

%% The certificates of a CA file, or why there are none: unreadable is `file_unreadable', and a
%% file that holds no certificate can verify nothing, which is what a TLS failure says.
read_ca_ders(Ca) ->
    case read_file(Ca) of
        {ok, Pem, _} ->
            case yuzu_gw_mgmt_crl:ca_certs(Pem) of
                []   -> {error, fetch_tls};
                Ders -> {ok, Ders}
            end;
        {error, _} = Error ->
            Error
    end.

read_file(Path) ->
    Max = yuzu_gw_mgmt_crl:max_bytes(),
    try
        case file:open(Path, [read, binary, raw]) of
            {ok, Fd} ->
                try file:read(Fd, Max + 1) of
                    {ok, Bin} when byte_size(Bin) > Max -> {error, too_large};
                    {ok, Bin} -> {ok, Bin, undefined};
                    eof -> {error, malformed};
                    {error, _} -> {error, file_unreadable}
                after
                    _ = file:close(Fd)
                end;
            {error, _} ->
                {error, file_unreadable}
        end
    catch _:_ -> {error, file_unreadable}
    end.

%% The attempt runs in its own process so that a connection that dies, a worker that crashes or
%% a server that never answers can neither stall nor kill the caller. Killed at the deadline.
%%
%% A kill does not free a worker that is blocked inside a file operation on a dead mount or a FIFO:
%% the process disappears, but the OS thread stays in the blocked call, and each one holds one of
%% the VM's ten dirty I/O threads for good. Measured: a few killed-but-blocked workers wedge every
%% file operation in the VM. So a FILE worker is not killed at its deadline; it is left to finish
%% whenever the call returns, remembered per `Key' (in persistent_term, so a restart of this
%% process does not forget it and start another), and no new one is started for that key until it
%% is gone: the attempt fails at once with `StuckReason'. A stuck file costs one thread, not one
%% per tick. If the worker finishes late its result is taken by the next attempt instead of being
%% thrown away, so a source that is merely slow still loads. (An HTTP worker blocks in no such
%% call, and is killed.)
run_worker(Key, Fun, DeadlineMs, StuckReason) ->
    case stuck(Key) of
        none ->
            run_worker(Key, Fun, DeadlineMs);
        {Pid, Ref} ->
            receive
                {Ref, Result} ->
                    clear_stuck(Key),
                    Result
            after 0 ->
                    case is_process_alive(Pid) of
                        true ->
                            yuzu_gw_safe_call:warn_limited(
                              mgmt_crl_worker_blocked,
                              "mgmt_crl_source: the previous read of the ~p is still blocked (a "
                              "dead mount or a FIFO with no writer?); not starting another, so the "
                              "CRL is not refreshed until it returns (docs/user-manual/gateway.md, "
                              "Limits)", [Key]),
                            {error, StuckReason};
                        false ->
                            clear_stuck(Key),
                            run_worker(Key, Fun, DeadlineMs)
                    end
            end
    end.

stuck(Key) ->
    persistent_term:get({?MODULE, stuck, Key}, none).

clear_stuck(Key) ->
    _ = persistent_term:erase({?MODULE, stuck, Key}),
    ok.

run_worker(Key, Fun, DeadlineMs) ->
    Parent = self(),
    Ref = make_ref(),
    {Pid, MRef} = spawn_opt(fun() ->
                                    process_flag(trap_exit, true),
                                    Result = try Fun()
                                             catch _:_ -> {error, fetch_error}
                                             end,
                                    Parent ! {Ref, Result}
                            end, [monitor]),
    receive
        {Ref, Result} ->
            erlang:demonitor(MRef, [flush]),
            Result;
        {'DOWN', MRef, process, Pid, _} ->
            receive {Ref, Result} -> Result after 0 -> {error, fetch_error} end
    after DeadlineMs ->
            case Key of
                http -> exit(Pid, kill);
                _    -> persistent_term:put({?MODULE, stuck, Key}, {Pid, Ref})
            end,
            erlang:demonitor(MRef, [flush]),
            receive {Ref, _} -> ok after 0 -> ok end,
            {error, fetch_timeout}
    end.

http_get(#{host := Host, port := Port, path := Path, cacerts := Ders}, Etag, TimeoutMs) ->
    Deadline = erlang:monotonic_time(millisecond) + TimeoutMs,
    Opts = #{protocols => [http],
             transport => tls,
             tls_opts => tls_options_ders(Host, Ders, []),
             connect_timeout => TimeoutMs,
             domain_lookup_timeout => TimeoutMs,
             tls_handshake_timeout => TimeoutMs,
             retry => 0,
             %% Unsupervised: the connection is linked to this worker, so its failure arrives
             %% as an EXIT with the reason instead of vanishing under gun's supervisor.
             supervise => false},
    case gun:open(Host, Port, Opts) of
        {ok, Conn} ->
            try
                case gun:await_up(Conn, remaining(Deadline)) of
                    {ok, _Protocol} -> request(Conn, Path, Etag, Deadline);
                    {error, Reason} -> {error, classify(Reason)}
                end
            after
                unlink(Conn),
                exit(Conn, shutdown)
            end;
        {error, Reason} ->
            {error, classify(Reason)}
    end.

request(Conn, Path, Etag, Deadline) ->
    Headers = [{<<"accept">>, <<"application/pkix-crl, application/octet-stream">>}
               | [{<<"if-none-match">>, Etag} || is_binary(Etag)]],
    Stream = gun:get(Conn, Path, Headers),
    case gun:await(Conn, Stream, remaining(Deadline)) of
        {response, fin, 304, _} when is_binary(Etag) ->
            not_modified;
        {response, fin, 200, _} ->
            {error, malformed};
        {response, nofin, 200, RespHeaders} ->
            Max = yuzu_gw_mgmt_crl:max_bytes(),
            case declared_too_large(RespHeaders, Max) of
                true ->
                    {error, too_large};
                false ->
                    case body(Conn, Stream, Deadline, Max, []) of
                        {ok, Bin} -> {ok, Bin, header(<<"etag">>, RespHeaders)};
                        {error, _} = E -> E
                    end
            end;
        {response, _, _Status, _} ->
            {error, fetch_status};
        {error, Reason} ->
            {error, classify(Reason)};
        _ ->
            {error, fetch_error}
    end.

%% The body is read frame by frame against a running byte bound: a response past it is aborted
%% mid-stream, never buffered whole and then measured.
body(Conn, Stream, Deadline, Max, Acc) ->
    body(Conn, Stream, Deadline, Max, 0, Acc).

body(Conn, Stream, Deadline, Max, Size, Acc) ->
    case gun:await(Conn, Stream, remaining(Deadline)) of
        {data, IsFin, Data} ->
            Size1 = Size + byte_size(Data),
            case Size1 > Max of
                true ->
                    gun:cancel(Conn, Stream),
                    {error, too_large};
                false ->
                    Acc1 = [Data | Acc],
                    case IsFin of
                        fin   -> {ok, iolist_to_binary(lists:reverse(Acc1))};
                        nofin -> body(Conn, Stream, Deadline, Max, Size1, Acc1)
                    end
            end;
        {error, Reason} ->
            {error, classify(Reason)};
        _ ->
            {error, fetch_error}
    end.

remaining(Deadline) ->
    max(1, Deadline - erlang:monotonic_time(millisecond)).

declared_too_large(Headers, Max) ->
    case header(<<"content-length">>, Headers) of
        undefined -> false;
        Len ->
            try binary_to_integer(Len) > Max
            catch _:_ -> false
            end
    end.

header(Name, Headers) ->
    case lists:keyfind(Name, 1, Headers) of
        {_, V} -> V;
        false -> undefined
    end.

%% Explicit, and not gun's defaults: verification cannot be switched off from here. `Extra' is for
%% the tests (a client certificate is never needed: the CRL endpoint is public).
-spec tls_options(string(), string(), [ssl:tls_client_option()]) -> [ssl:tls_client_option()].
tls_options(Host, CaFile, Extra) ->
    tls_options_base(Host, {cacertfile, CaFile}, Extra).

%% The same with the trust anchors as DER certificates (what the fetch uses, see fetch/3).
-spec tls_options_ders(string(), [binary()], [ssl:tls_client_option()]) ->
          [ssl:tls_client_option()].
tls_options_ders(Host, Ders, Extra) ->
    tls_options_base(Host, {cacerts, Ders}, Extra).

tls_options_base(Host, Anchors, Extra) ->
    Base = [{verify, verify_peer},
            Anchors,
            {versions, ['tlsv1.3', 'tlsv1.2']},
            {customize_hostname_check,
             [{match_fun, public_key:pkix_verify_hostname_match_fun(https)}]}],
    Sni = case inet:parse_address(Host) of
              {ok, _Ip} -> [];  %% an address literal is matched against the certificate's IP SANs
              {error, _} -> [{server_name_indication, Host}]
          end,
    Base ++ Sni ++ Extra.

%% A closed reason from whatever gun/ssl/inet reported. A TLS failure is told apart from a
%% refused or unreachable connection because the remedy differs (the fetch CA or the host name
%% versus the network).
classify(timeout) -> fetch_timeout;
classify(Reason) ->
    case contains(Reason, fun tls_marker/1) of
        true  -> fetch_tls;
        false ->
            case contains(Reason, fun(T) -> T =:= timeout end) of
                true  -> fetch_timeout;
                false -> fetch_connect
            end
    end.

tls_marker({tls_alert, _}) -> true;
tls_marker({options, _}) -> true;
tls_marker({bad_certificate, _}) -> true;
tls_marker(A) when A =:= bad_certificate; A =:= unknown_ca; A =:= certificate_expired;
                   A =:= handshake_failure; A =:= hostname_check_failed;
                   A =:= unknown_certificate_authority; A =:= certificate_unknown ->
    true;
tls_marker(_) -> false.

contains(T, Pred) ->
    Pred(T) orelse case T of
                       L when is_list(L) -> try lists:any(fun(E) -> contains(E, Pred) end, L)
                                            catch _:_ -> false end;
                       Tup when is_tuple(Tup) -> lists:any(fun(E) -> contains(E, Pred) end,
                                                           tuple_to_list(Tup));
                       _ -> false
                   end.
