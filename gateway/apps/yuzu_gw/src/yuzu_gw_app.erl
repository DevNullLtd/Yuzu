%%%-------------------------------------------------------------------
%%% @doc yuzu_gw application callback module.
%%%
%%% Starts the top-level supervisor, initialises telemetry handlers,
%%% and creates the pg scope used for cluster-wide agent groups.
%%%
%%% Supports environment variable overrides for container deployments.
%%% See apply_env_overrides/0 for the full list.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_app).
-behaviour(application).

-export([start/2, stop/1]).
-export([apply_env_overrides/0, evaluate_cookie/3]).  %% exported for testing
-export([client_has_https/1, client_tls_posture/1, servers_have_tls/1]). %% for testing
-export([evaluate_upstream_posture/2, listener_tls_traps/1]).            %% for testing
-export([evaluate_mgmt_posture/3]).                                      %% for testing

%%--------------------------------------------------------------------
%% application callbacks
%%--------------------------------------------------------------------

start(_StartType, _StartArgs) ->
    %% #659: refuse to boot with a known-insecure Erlang distribution cookie,
    %% before any side effects. The cookie is the sole authentication for
    %% inter-node RPC; a publicly known value is unauthenticated RCE.
    case check_distribution_cookie() of
        {error, Reason} -> {error, Reason};
        ok              -> do_start()
    end.

do_start() ->
    %% Apply environment variable overrides (container deployment).
    apply_env_overrides(),

    %% Log the ACTUAL transport TLS posture. grpcbox reads its own
    %% {grpcbox, client|servers} config at boot and is the source of truth; the
    %% yuzu_gw `tls`/`tls_enabled` env is advisory only (nothing wires it into
    %% grpcbox — see docs/pki-architecture.md "Gateway TLS"). The previous code
    %% matched `{ok, _}` against application:get_env/3, which returns the bare
    %% value (never `{ok, _}`), so it was dead — and a real `tls` proplist would
    %% have crashed boot with a case_clause.
    log_tls_state(),

    %% #PR5: fail CLOSED on a misconfigured-but-encrypted upstream (https without
    %% verify_peer is MITM-able) — same fail-closed philosophy as the distribution
    %% cookie guard, rather than booting with only a log warning. PLAINTEXT upstream
    %% is still allowed (the legitimate UAT/dev posture); only the "TLS but
    %% unauthenticated" footgun is refused.
    case check_upstream_tls_posture() of
        {error, Reason} ->
            {error, Reason};
        ok ->
            case check_mgmt_listener_posture() of
                {error, Reason2} -> {error, Reason2};
                ok               -> do_start_services()
            end
    end.

do_start_services() ->
    %% Attach telemetry/prometheus handlers.
    yuzu_gw_telemetry:setup(),

    %% Start Prometheus HTTP exporter for /metrics endpoint.
    Port = application:get_env(yuzu_gw, prometheus_port, 9568),
    application:set_env(prometheus, prometheus_http, [{port, Port}, {path, "/metrics"}]),
    {ok, _} = prometheus_httpd:start(),
    logger:info("Prometheus metrics endpoint started on port ~p", [Port]),

    %% Start the supervision tree.
    yuzu_gw_sup:start_link().

%%--------------------------------------------------------------------
%% Distribution cookie guard (#659)
%%--------------------------------------------------------------------

%% @private Refuse to boot if the Erlang distribution cookie is a known-
%% insecure default. The cookie is the SOLE authentication for inter-node
%% RPC; a publicly known value (the repo's historical default) means
%% unauthenticated remote code execution for anyone who can reach EPMD.
-spec check_distribution_cookie() -> ok | {error, insecure_distribution_cookie}.
check_distribution_cookie() ->
    Allow = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE") =:= "1",
    evaluate_cookie(node(), erlang:get_cookie(), Allow).

%% Minimum distribution-cookie length (HA WS-4 #4555, ADR-2002 §7b). DNS-sourced
%% discovery makes this node DIAL OUT to addresses it did not choose by hand —
%% and the OTP distribution handshake has the INITIATOR send
%% MD5(cookie ‖ peer_challenge) first, before the peer proves anything back. So
%% anything able to influence what the seed name resolves to (a compromised or
%% misconfigured DNS answer) gets an offline brute-force oracle against the
%% cookie from a legitimately-configured node dialing out — a stronger position
%% than an inbound attacker against a normal listener ever gets. 32 is HALF
%% the output length of the `openssl rand -hex 32` this module's own
%% guidance already recommends operators generate (that command emits 64
%% hex characters, i.e. 256 bits) — the floor is comfortably cleared by the
%% recommended generator, not merely equal to it. This is a LENGTH check
%% only, not an entropy check: a hand-typed 32-character string that isn't
%% genuinely random also clears it. That residual is a deliberate,
%% documented trade-off (ADR-2002 §7b) — going further (mandating a
%% specific generation method, or verifying character-class distribution)
%% was judged disproportionate here.
-define(MIN_COOKIE_LENGTH, 32).

%% @doc Pure cookie policy decision — exported for testing.
%% A non-distributed node ('nonode@nohost') has no inter-node attack surface,
%% so any cookie is accepted. Otherwise the known-default, empty, and
%% too-short cookies are rejected unless explicitly overridden for dev/CI.
-spec evaluate_cookie(node(), atom(), boolean()) ->
          ok | {error, insecure_distribution_cookie}.
evaluate_cookie('nonode@nohost', _Cookie, _Allow) ->
    ok;
evaluate_cookie(_Node, Cookie, Allow) ->
    CookieStr = atom_to_list(Cookie),
    %% Reject (a) the empty cookie, (b) the historical committed default as a
    %% SUBSTRING — so the literal `${YUZU_GW_COOKIE:-yuzu_gw_secret_change_me}`
    %% is caught if relx `.src` env-substitution ever fails (missing awk in a
    %% broken/minimal image, or a hand-edited vm.args) — and (c) any
    %% unsubstituted `${...}` env placeholder. Substring (not exact) match is
    %% the #659 UP-1 hardening: an exact-match list would let the unsubstituted
    %% literal through and silently re-open the unauthenticated-RPC surface.
    IsDefault = CookieStr =:= ""
        orelse string:find(CookieStr, "yuzu_gw_secret_change_me") =/= nomatch
        orelse string:find(CookieStr, "${") =/= nomatch,
    TooShort = not IsDefault andalso length(CookieStr) < ?MIN_COOKIE_LENGTH,
    Insecure = IsDefault orelse TooShort,
    case {Insecure, Allow} of
        {true, false} when TooShort ->
            logger:critical(
                "Refusing to start: Erlang distribution cookie is shorter than "
                "~p characters. DNS-based cluster discovery (#4555) means this "
                "node dials addresses it did not choose by hand, and the "
                "distribution handshake's INITIATOR sends the cookie hash "
                "first — a short cookie is brute-forceable offline from a "
                "legitimate node dialing out. Set a strong unique cookie via "
                "the YUZU_GW_COOKIE environment variable (e.g. `openssl rand "
                "-hex 32`). Dev/CI may override with "
                "YUZU_GW_ALLOW_DEFAULT_COOKIE=1.", [?MIN_COOKIE_LENGTH]),
            {error, insecure_distribution_cookie};
        {true, false} ->
            logger:critical(
                "Refusing to start: Erlang distribution cookie is the insecure default. "
                "The cookie is the sole authentication for inter-node RPC; a known value "
                "means unauthenticated remote code execution for anyone who can reach EPMD "
                "(port 4369). Set a strong unique cookie via the YUZU_GW_COOKIE environment "
                "variable (e.g. `openssl rand -hex 32`). Dev/CI may override with "
                "YUZU_GW_ALLOW_DEFAULT_COOKIE=1."),
            {error, insecure_distribution_cookie};
        {true, true} ->
            %% Name WHICH condition(s) triggered — a bare "default or too
            %% short" reads as one undifferentiated warning, and an operator
            %% who set this override for a KNOWN-default cookie (low stakes,
            %% isolated lab) may not register that a short-but-CUSTOM cookie
            %% is what's actually flagged, leaving the DNS-dial-out
            %% brute-force oracle #4555 introduces fully open (unhappy-path
            %% UP-6, #4555 governance run).
            Reason = case {IsDefault, TooShort} of
                {true, true}  -> "the insecure default value AND shorter than the minimum length";
                {true, false} -> "the insecure default value";
                {false, true} -> "shorter than the minimum length"
            end,
            logger:warning(
                "Erlang distribution cookie is insecure (~s), but "
                "YUZU_GW_ALLOW_DEFAULT_COOKIE=1 is set — proceeding (dev/CI only). "
                "A short custom cookie remains brute-forceable via the DNS-based "
                "cluster discovery dial-out even with this override set.",
                [Reason]),
            ok;
        {false, _} ->
            ok
    end.

stop(_State) ->
    logger:info("Gateway shutting down — entering drain phase"),

    %% 1. Stop accepting new commands via the router.
    case whereis(yuzu_gw_router) of
        undefined -> ok;
        RouterPid ->
            logger:info("Notifying router to stop accepting new commands"),
            RouterPid ! drain,
            ok
    end,

    %% 2. Wait for in-flight commands to complete (up to 10 seconds).
    DrainDeadline = erlang:monotonic_time(second) + 10,
    drain_pending(DrainDeadline),

    %% 3. Flush heartbeat buffer synchronously.
    logger:info("Flushing heartbeat buffer"),
    try yuzu_gw_heartbeat_buffer:flush_sync()
    catch _:_ ->
        %% flush_sync failed (process already down) — allow brief drain.
        timer:sleep(500)
    end,

    logger:info("Gateway shutdown complete"),
    ok.

%% @private Wait for pending commands to drain or until deadline.
drain_pending(Deadline) ->
    Now = erlang:monotonic_time(second),
    case Now >= Deadline of
        true ->
            logger:warning("Drain deadline reached — proceeding with shutdown");
        false ->
            %% Check if any agent processes still have pending commands.
            %% pg:get_members may fail if pg is already shutting down.
            Agents = try pg:get_members(yuzu_gw, all_agents) catch _:_ -> [] end,
            HasPending = lists:any(fun(Pid) ->
                try gen_statem:call(Pid, pending_count, 1000) > 0
                catch _:_ -> false
                end
            end, Agents),
            case HasPending of
                false ->
                    logger:info("All in-flight commands drained");
                true ->
                    logger:info("Draining: waiting for in-flight commands..."),
                    timer:sleep(1000),
                    drain_pending(Deadline)
            end
    end.

%%--------------------------------------------------------------------
%% Environment variable overrides for container deployment
%%--------------------------------------------------------------------

apply_env_overrides() ->
    Overrides = [
        {"YUZU_GW_UPSTREAM_ADDR",    upstream_addr,    fun(V) -> V end},
        {"YUZU_GW_UPSTREAM_PORT",    upstream_port,    fun list_to_integer/1},
        {"YUZU_GW_AGENT_PORT",       agent_listen_port, fun list_to_integer/1},
        {"YUZU_GW_MGMT_PORT",        mgmt_listen_port,  fun list_to_integer/1},
        {"YUZU_GW_PROMETHEUS_PORT",  prometheus_port,   fun list_to_integer/1},
        {"YUZU_GW_HEALTH_PORT",      health_port,       fun list_to_integer/1},
        {"YUZU_GW_HEARTBEAT_INTERVAL_MS", heartbeat_batch_interval_ms, fun list_to_integer/1},
        {"YUZU_GW_COMMAND_TIMEOUT_S",     default_command_timeout_s,   fun list_to_integer/1},
        {"YUZU_GW_BACKPRESSURE_THRESHOLD", backpressure_threshold,     fun list_to_integer/1},
        {"YUZU_GW_CB_FAILURE_THRESHOLD",   circuit_breaker_failure_threshold, fun list_to_integer/1},
        {"YUZU_GW_CB_RESET_TIMEOUT_MS",    circuit_breaker_reset_timeout_ms,  fun list_to_integer/1},
        {"YUZU_GW_CB_MAX_RESET_TIMEOUT_MS", circuit_breaker_max_reset_timeout_ms, fun list_to_integer/1},
        %% HA WS-4 4.1 — trust-zone/region cluster id (ADR-2002 §7), stamped
        %% on every StreamStatusNotification (yuzu_gw_upstream:handle_cast/2).
        {"YUZU_GW_CLUSTER_ID", cluster_id, fun list_to_binary/1},
        %% HA WS-4 #4555 — gateway cluster FORMATION config (ADR-2002 §7b).
        {"YUZU_GW_SEED_DNS_NAME", cluster_seed_dns_name, fun list_to_binary/1},
        %% Explicit peer list; when non-empty REPLACES DNS resolution outright
        %% (never merged). "10.0.0.1,10.0.0.2" -> [<<"10.0.0.1">>, <<"10.0.0.2">>].
        {"YUZU_GW_SEED_NODES", cluster_seed_nodes, fun(V) ->
            [list_to_binary(string:trim(N))
             || N <- string:split(V, ",", all), string:trim(N) =/= ""]
        end},
        {"YUZU_GW_CLUSTER_REDIAL_INTERVAL_MS", cluster_redial_interval_ms,
         fun list_to_integer/1},
        {"YUZU_GW_TLS_ENABLED", tls_enabled, fun
            ("true")  -> true;
            ("false") -> false;
            ("1")     -> true;
            ("0")     -> false;
            (V)       -> error({bad_bool, V})
        end}
    ],
    lists:foreach(fun({EnvVar, AppKey, ParseFun}) ->
        case os:getenv(EnvVar) of
            false -> ok;
            Value ->
                try
                    Parsed = ParseFun(Value),
                    application:set_env(yuzu_gw, AppKey, Parsed),
                    logger:info("ENV override: ~s = ~p", [EnvVar, Parsed])
                catch
                    _:_ ->
                        logger:warning("ENV override: ~s has invalid value '~s', ignoring",
                                       [EnvVar, Value])
                end
        end
    end, Overrides),

    %% HA WS-4 #4555: YUZU_GW_SEED_NODES set but every entry was empty/
    %% whitespace-only (a stray trailing comma, blank entries) parses to []
    %% with no error — correct, one bad entry among good ones should not
    %% abort the whole override — but the generic "ENV override: ... = []"
    %% info line above is easy to miss and indistinguishable at a skim from
    %% "operator never set this at all", which silently falls through
    %% resolve_targets/0 to DNS discovery instead of the intended static
    %% topology (unhappy-path UP-9, #4555 governance run). Surface it
    %% distinctly.
    case os:getenv("YUZU_GW_SEED_NODES") of
        false ->
            ok;
        RawSeedNodes ->
            case application:get_env(yuzu_gw, cluster_seed_nodes) of
                {ok, []} ->
                    logger:warning(
                        "YUZU_GW_SEED_NODES was set ('~s') but every entry was "
                        "empty after trimming — falling back to DNS discovery "
                        "(YUZU_GW_SEED_DNS_NAME) instead of the intended static "
                        "peer list. Check for a stray comma or blank entry.",
                        [RawSeedNodes]);
                _ ->
                    ok
            end
    end,

    %% TLS cert overrides (these set the tls proplist)
    apply_tls_overrides().

apply_tls_overrides() ->
    Cert = os:getenv("YUZU_GW_TLS_CERTFILE"),
    Key  = os:getenv("YUZU_GW_TLS_KEYFILE"),
    Ca   = os:getenv("YUZU_GW_TLS_CACERTFILE"),
    case {Cert, Key, Ca} of
        {false, false, false} ->
            ok;  % No TLS env vars — use sys.config values
        _ ->
            Base = application:get_env(yuzu_gw, tls, []),
            TlsOpts0 = case Cert of
                false -> Base;
                C     -> lists:keystore(certfile, 1, Base, {certfile, C})
            end,
            TlsOpts1 = case Key of
                false -> TlsOpts0;
                K     -> lists:keystore(keyfile, 1, TlsOpts0, {keyfile, K})
            end,
            TlsOpts2 = case Ca of
                false -> TlsOpts1;
                A     -> lists:keystore(cacertfile, 1, TlsOpts1, {cacertfile, A})
            end,
            application:set_env(yuzu_gw, tls, TlsOpts2),
            logger:info("TLS config updated from environment variables")
    end.

%%--------------------------------------------------------------------
%% TLS posture reporting (PKI PR5)
%%--------------------------------------------------------------------

-type tls_posture() :: verified | unverified | plaintext.

%% @private Report the real transport TLS posture from grpcbox's OWN config —
%% the authoritative source (grpcbox reads {grpcbox, client|servers} at boot,
%% not yuzu_gw's advisory `tls` env). Never crashes on unexpected shapes.
-spec log_tls_state() -> ok.
log_tls_state() ->
    case application:get_env(yuzu_gw, tls_enabled, auto) of
        false ->
            logger:warning("YUZU_GW_TLS_ENABLED=false is advisory only — the actual "
                           "transport is whatever the grpcbox config selects (below)");
        _ -> ok
    end,
    Up = client_tls_posture(application:get_env(grpcbox, client, undefined)),
    Listen = servers_have_tls(application:get_env(grpcbox, servers, undefined)),
    %% This reflects the CONFIGURED grpcbox posture, not a live handshake — the
    %% upstream channel connects lazily (and the server may not have generated
    %% certs yet at boot), so a startup file/handshake probe would false-alarm.
    logger:info("Gateway transport TLS (configured): upstream->server=~s, "
                "listeners(agent/mgmt)=~s", [posture_word(Up), tls_word(Listen)]),
    case Up of
        plaintext ->
            logger:warning("Gateway->server upstream is PLAINTEXT. For production point "
                           "the grpcbox default_channel at {https,...} with the gateway "
                           "leaf + CA (see config/sys.config.prod / deploy gateway-sys.config).");
        unverified ->
            %% https without {verify,verify_peer}: encrypted but NOT authenticated —
            %% an active MITM can impersonate the server. Do not report this as "TLS".
            logger:warning("Gateway->server upstream is ENCRYPTED but does NOT verify the "
                           "server certificate ({verify,verify_peer} missing from the "
                           "grpcbox default_channel SslOpts) — vulnerable to MITM. Add "
                           "{verify,verify_peer} + {cacertfile,...}.");
        verified -> ok
    end,
    %% Listener footgun: cert material in transport_opts but no `ssl => true`
    %% means grpcbox serves PLAINTEXT on that port despite the cert config — the
    %% operator believes the agent/mgmt hop is encrypted, it is not. Warn loudly
    %% (same "looks secure, isn't" class the upstream `unverified` guard refuses).
    case listener_tls_traps(application:get_env(grpcbox, servers, undefined)) of
        [] -> ok;
        TrapPorts ->
            logger:warning("Gateway listener(s) on port(s) ~p carry TLS cert material in "
                           "transport_opts but `ssl` is not set to `true` (missing, or set "
                           "to another value like verify_peer) — grpcbox runs PLAINTEXT on "
                           "these ports despite the cert config (silent downgrade). "
                           "transport_opts must be a MAP with `ssl => true`. See "
                           "config/sys.config.prod.", [TrapPorts])
    end,
    %% Advisory-env footgun: an operator who set YUZU_GW_TLS_* populated only the
    %% unconsumed yuzu_gw `tls` env; it does NOT configure grpcbox, REGARDLESS of
    %% the actual upstream posture. Warn whenever it is set so the misconception is
    %% always surfaced (not only when the upstream happens to be plaintext).
    case application:get_env(yuzu_gw, tls, []) of
        [] -> ok;
        _ ->
            logger:warning("yuzu_gw `tls` env is set (YUZU_GW_TLS_*) but those env vars are "
                           "advisory and do NOT configure grpcbox (it reads its own config). "
                           "Set TLS in the grpcbox block of sys.config. See "
                           "docs/pki-architecture.md 'Gateway TLS'.")
    end,
    ok.

%% @private Fail-closed guard: refuse to boot if the grpcbox upstream channel is
%% TLS-but-unverified (https without {verify,verify_peer}) — encrypted yet
%% MITM-able. PLAINTEXT upstream is permitted (the legitimate UAT/dev posture);
%% only the dangerous "looks secure, isn't" middle state is refused. Mirrors the
%% distribution-cookie guard's fail-closed posture. Dev/CI override:
%% YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1.
-spec check_upstream_tls_posture() -> ok | {error, unverified_upstream_tls}.
check_upstream_tls_posture() ->
    Posture = client_tls_posture(application:get_env(grpcbox, client, undefined)),
    Allow = os:getenv("YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM") =:= "1",
    case evaluate_upstream_posture(Posture, Allow) of
        {error, unverified_upstream_tls} ->
            logger:critical(
                "Refusing to start: the grpcbox upstream channel uses TLS (https) WITHOUT "
                "{verify,verify_peer} — encrypted but UNAUTHENTICATED (MITM-able). Add "
                "{verify,verify_peer} + {cacertfile,...} to the default_channel SslOpts "
                "(see config/sys.config.prod). Dev/CI may override with "
                "YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1."),
            {error, unverified_upstream_tls};
        ok when Posture =:= unverified ->
            logger:warning("Upstream TLS is unverified (no verify_peer) but "
                           "YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1 — proceeding (dev/CI only)."),
            ok;
        ok ->
            ok
    end.

%% @doc Pure upstream-posture policy decision — exported for testing. Only
%% `unverified` (https without verify_peer) without an explicit override is
%% refused; `verified` and `plaintext` boot.
-spec evaluate_upstream_posture(tls_posture(), boolean()) ->
          ok | {error, unverified_upstream_tls}.
evaluate_upstream_posture(unverified, false) -> {error, unverified_upstream_tls};
evaluate_upstream_posture(_Posture, _Allow)  -> ok.

%%--------------------------------------------------------------------
%% Mgmt-listener posture guard (#1422)
%%--------------------------------------------------------------------

%% @private Fail-closed guard for the PRIVILEGED command plane: refuse to boot
%% when a management_pb listener is network-reachable without the full #1422
%% posture (strict mTLS + the SPKI-pin auth_fun + configured pins). A
%% mgmt listener without it hands fleet-wide command execution to any peer
%% that can reach the port — the finding this guard makes non-recurring.
%%
%% Placement caveat: grpcbox is an application DEPENDENCY, so its listeners
%% are already up when this runs; refusing here halts the release moments
%% after listen. In that window the router/registry are not yet started, so
%% a mgmt RPC cannot dispatch — acceptable, and consistent with the other
%% posture guards in this module. A pre-listen validator inside the vendored
%% grpcbox is tracked follow-up hardening.
%%
%% Escape hatch: {yuzu_gw, allow_insecure_mgmt} set to the literal `true`
%% boots anyway with a loud warning — an ACKNOWLEDGEMENT for lab/UAT rigs
%% (which the tracked rig configs set explicitly), not a mitigation.
-spec check_mgmt_listener_posture() -> ok | {error, insecure_mgmt_listener}.
check_mgmt_listener_posture() ->
    Servers = application:get_env(grpcbox, servers, []),
    Pins = application:get_env(yuzu_gw, mgmt_peer_pins, []),
    Allow = application:get_env(yuzu_gw, allow_insecure_mgmt, false) =:= true,
    case evaluate_mgmt_posture(Servers, Pins, Allow) of
        ok ->
            ok;
        {ok_insecure, Details} ->
            logger:warning(
                "Management listener(s) ~p lack the #1422 secure posture but "
                "{yuzu_gw, allow_insecure_mgmt} is true — booting anyway. This "
                "plane fans commands to the ENTIRE fleet; this override is for "
                "isolated lab/UAT rigs only, never production.", [Details]),
            ok;
        {error, {insecure_mgmt_listener, Details}} ->
            logger:critical(
                "Refusing to start: management listener(s) ~p are network-"
                "reachable without the required posture (strict mTLS with "
                "certfile+keyfile+cacertfile, verify_peer, fail_if_no_peer_cert, "
                "auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1, and non-empty "
                "{yuzu_gw, mgmt_peer_pins}). Anyone reaching this port could "
                "otherwise command the entire fleet (#1422). Fix the grpcbox "
                "listener config (see config/sys.config.prod), bind it to "
                "loopback, or — isolated lab/UAT rigs ONLY — set "
                "{yuzu_gw, allow_insecure_mgmt} to true.", [Details]),
            {error, insecure_mgmt_listener}
    end.

%% @doc Pure mgmt-posture policy decision — exported for testing. Returns a
%% per-listener defect list keyed by listen port; the escape hatch converts a
%% refusal into {ok_insecure, Details} (boot + warn), never a silent pass.
-spec evaluate_mgmt_posture(term(), term(), boolean()) ->
          ok | {ok_insecure, [term()]} | {error, {insecure_mgmt_listener, [term()]}}.
evaluate_mgmt_posture(Servers, Pins, Allow) when is_list(Servers) ->
    Details = [{listener_port(S), D}
               || S <- Servers, is_mgmt_listener(S),
                  not loopback_bound(S),
                  D <- [mgmt_defects(S, Pins)],
                  D =/= []],
    case {Details, Allow} of
        {[], _}     -> ok;
        {_, true}   -> {ok_insecure, Details};
        {_, false}  -> {error, {insecure_mgmt_listener, Details}}
    end;
evaluate_mgmt_posture(_Servers, _Pins, _Allow) ->
    %% Unrecognisable servers config: nothing provably exposes management_pb.
    ok.

%% @private A listener serving the management proto. Identified by
%% service_protos — never by port or the advisory yuzu_gw env keys.
-spec is_mgmt_listener(term()) -> boolean().
is_mgmt_listener(S) when is_map(S) ->
    Protos = opt_value(service_protos, maps:get(grpc_opts, S, #{})),
    is_list(Protos) andalso lists:member(management_pb, Protos);
is_mgmt_listener(_) ->
    false.

%% @private Loopback-only binds have no network attack surface. A missing or
%% unrecognised ip is EXPOSED (grpcbox defaults to {0,0,0,0}). The map `ip` is
%% authoritative ONLY when `socket_options` cannot override the bind: grpcbox
%% DELETES the ip whenever socket_options carries an inherited `{fd, _}`
%% descriptor (grpcbox_socket:maybe_adjust_port_opts_for_fdopt/2 — the socket
%% binds wherever the fd points, e.g. systemd socket activation), and an
%% `{ip, _}` inside socket_options is appended after the map ip in the inet
%% option list, where the later occurrence wins. Either shape makes a nominal
%% `ip => {127,0,0,1}` a dead letter, so both forfeit the exemption
%% (PR #3905 review, Doomgoose blocking finding — verified live: the fd shape
%% previously evaluated `ok` with zero TLS/auth_fun/pins).
-spec loopback_bound(map()) -> boolean().
loopback_bound(S) ->
    ListenOpts = maps:get(listen_opts, S, #{}),
    Overridable = case opt_value(socket_options, ListenOpts) of
        undefined -> false;
        L when is_list(L) ->
            lists:keymember(fd, 1, L) orelse lists:keymember(ip, 1, L);
        _ -> true  % unrecognised shape: cannot prove the bind — exposed
    end,
    case {Overridable, maps:get(ip, ListenOpts, undefined)} of
        {true, _}                        -> false;
        {false, {127, _, _, _}}          -> true;
        {false, {0, 0, 0, 0, 0, 0, 0, 1}} -> true;
        _                                -> false
    end.

%% @private Everything wrong with one mgmt listener's posture. `ssl => true`
%% alone is NOT TLS: grpcbox_pool silently falls back to TCP unless certfile,
%% keyfile AND cacertfile are all present. TLS with verify_none would let a
%% self-signed cert reach the auth_fun, and without fail_if_no_peer_cert a
%% certless peer skips it entirely — both count as defects. The auth_fun must
%% be exactly the approved pin callback, and the pin set non-empty.
-spec mgmt_defects(map(), term()) -> [atom()].
mgmt_defects(S, Pins) ->
    T = maps:get(transport_opts, S, #{}),
    GrpcOpts = maps:get(grpc_opts, S, #{}),
    HasMaterial = lists:all(fun(K) -> has_material(K, T) end,
                            [certfile, keyfile, cacertfile]),
    %% verify / fail_if_no_peer_cert default to the patched grpcbox's strict
    %% values when omitted, so absent is fine; an explicit relaxation is not.
    Verify = case opt_value(verify, T) of undefined -> verify_peer; V -> V end,
    FailNoPeer = case opt_value(fail_if_no_peer_cert, T) of
                     undefined -> true;
                     F -> F
                 end,
    %% grpcbox selects TLS only when transport_opts is a MAP with ssl => true —
    %% a PROPLIST carrying {ssl, true} still serves plaintext TCP (the same
    %% shape is_tls_trap/1 flags), so the guard must demand the map form.
    Checks =
        [{plaintext, not (is_map(T) andalso maps:get(ssl, T, undefined) =:= true)},
         {missing_cert_material, not HasMaterial},
         {verify_not_peer, opt_value(ssl, T) =:= true andalso
                           Verify =/= verify_peer},
         {peer_cert_not_required, opt_value(ssl, T) =:= true andalso
                                  FailNoPeer =/= true},
         {missing_or_wrong_auth_fun,
          maps:get(auth_fun, GrpcOpts, undefined) =/=
              fun yuzu_gw_authz:check_mgmt_peer/1},
         {no_mgmt_peer_pins, not (is_list(Pins) andalso Pins =/= [])}],
    [Defect || {Defect, true} <- Checks].

-spec tls_word(boolean()) -> string().
tls_word(true)  -> "TLS";
tls_word(false) -> "plaintext".

-spec posture_word(tls_posture()) -> string().
posture_word(verified)   -> "mutual-TLS";
posture_word(unverified) -> "TLS(UNVERIFIED!)";
posture_word(plaintext)  -> "plaintext".

%% @doc Strongest TLS posture across grpcbox client channels: `verified` (an
%% `https` endpoint with {verify,verify_peer}), `unverified` (https without it),
%% else `plaintext`. Pure; exported for testing.
-spec client_tls_posture(term()) -> tls_posture().
client_tls_posture(#{channels := Channels}) when is_list(Channels) ->
    lists:foldl(fun(Ch, Acc) -> strongest(channel_posture(Ch), Acc) end,
                plaintext, Channels);
client_tls_posture(_) ->
    plaintext.

%% @doc True if any grpcbox client channel has an `https` endpoint (verified or
%% not). Pure; exported for testing.
-spec client_has_https(term()) -> boolean().
client_has_https(Client) -> client_tls_posture(Client) =/= plaintext.

-spec channel_posture(term()) -> tls_posture().
channel_posture({_Name, Endpoints, _Opts}) when is_list(Endpoints) ->
    lists:foldl(fun(E, Acc) -> strongest(endpoint_posture(E), Acc) end,
                plaintext, Endpoints);
channel_posture(_) ->
    plaintext.

-spec endpoint_posture(term()) -> tls_posture().
endpoint_posture(E) when is_tuple(E), tuple_size(E) >= 4, element(1, E) =:= https ->
    SslOpts = element(4, E),
    case is_list(SslOpts) andalso proplists:get_value(verify, SslOpts) =:= verify_peer of
        true  -> verified;
        false -> unverified
    end;
endpoint_posture(_) ->
    plaintext.

-spec strongest(tls_posture(), tls_posture()) -> tls_posture().
strongest(verified, _)            -> verified;
strongest(_, verified)            -> verified;
strongest(unverified, _)          -> unverified;
strongest(_, unverified)          -> unverified;
strongest(plaintext, plaintext)   -> plaintext.

%% @doc True if any grpcbox server (listener) carries TLS transport_opts
%% (`ssl => true`). Pure; exported for testing.
-spec servers_have_tls(term()) -> boolean().
servers_have_tls(Servers) when is_list(Servers) ->
    lists:any(fun(S) when is_map(S) ->
                      case maps:get(transport_opts, S, #{}) of
                          #{ssl := true} -> true;
                          _ -> false
                      end;
                 (_) -> false
              end, Servers);
servers_have_tls(_) ->
    false.

%% @doc Listener TLS footgun detector: returns the listen ports of any grpcbox
%% server whose `transport_opts` carries cert material (certfile/keyfile/
%% cacertfile) but is MISSING `ssl => true`. grpcbox_pool enables TLS ONLY on
%% `ssl => true`, so such a listener serves PLAINTEXT despite the cert config —
%% the silent-downgrade "looks secure, isn't" middle state. Pure; exported for
%% testing. Mirrors the upstream `unverified` detection on the listener side.
-spec listener_tls_traps(term()) -> [term()].
listener_tls_traps(Servers) when is_list(Servers) ->
    lists:filtermap(fun(S) when is_map(S) ->
                            case is_tls_trap(maps:get(transport_opts, S, #{})) of
                                true  -> {true, listener_port(S)};
                                false -> false
                            end;
                       (_) -> false
                    end, Servers);
listener_tls_traps(_) ->
    [].

%% @private cert material present but `ssl` not exactly `true`. Handles BOTH the
%% grpcbox map form (`#{ssl => true, certfile => ...}`) AND a proplist
%% (`[{certfile, ...}]`): a proplist is itself a misconfiguration — grpcbox
%% expects a map and yields plaintext — so flagging it is correct. Keys with an
%% undefined/empty value don't count as material (avoids warning on placeholders).
%% The material key set covers both file-path (certfile/keyfile/cacertfile/dhfile)
%% and inline-DER (cert/key/cacert) ssl options.
-spec is_tls_trap(term()) -> boolean().
is_tls_trap(T) when is_map(T); is_list(T) ->
    HasCertMaterial = lists:any(fun(K) -> has_material(K, T) end,
                                [certfile, keyfile, cacertfile, dhfile,
                                 cert, key, cacert]),
    SslOn = opt_value(ssl, T) =:= true,
    HasCertMaterial andalso not SslOn;
is_tls_trap(_) ->
    false.

%% @private fetch an option value from a map or a proplist; undefined if absent.
-spec opt_value(atom(), map() | list()) -> term().
opt_value(K, Opts) when is_map(Opts) -> maps:get(K, Opts, undefined);
opt_value(K, Opts) when is_list(Opts) -> proplists:get_value(K, Opts, undefined);
opt_value(_, _) -> undefined.

%% @private true if the key carries a non-empty value (undefined/""/<<>> don't
%% count — a placeholder shouldn't trigger the trap warning).
-spec has_material(atom(), map() | list()) -> boolean().
has_material(K, Opts) ->
    case opt_value(K, Opts) of
        undefined -> false;
        ""        -> false;
        <<>>      -> false;
        _         -> true
    end.

-spec listener_port(map()) -> term().
listener_port(S) ->
    case maps:get(listen_opts, S, #{}) of
        #{port := P} -> P;
        _            -> unknown
    end.
