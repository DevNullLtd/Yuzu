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

-export([start/2, prep_stop/1, stop/1]).

%% The planned stop's budget (prep_stop/1): shutdown_flush_budget_ms.
-define(DEFAULT_FLUSH_BUDGET_MS, 20000).
-define(MAX_FLUSH_BUDGET_MS, 600000).
-export([apply_env_overrides/0, evaluate_cookie/3]).  %% exported for testing
-export([client_has_https/1, client_tls_posture/1, listeners_have_tls/1]). %% for testing
-export([client_all_present_client_cert/1, client_tls_weakest/1, client_has_unverified/1, client_mixed_channels/1]). %% for testing
-export([check_upstream_tls_posture/0, check_upstream_channel_mix/0, warn_replaced_options/0,
         check_upstream_tls_files/0]).
-export([evaluate_upstream_posture/2, evaluate_listeners/1]).             %% for testing
-export([evaluate_mgmt_posture/3, apply_listener_port_overrides/0]).      %% for testing
-export([check_legacy_grpcbox_servers/0, check_legacy_grpcbox_client/0,
         legacy_grpcbox_in_files/2, check_grpc_listeners/0,
         check_upstream_client_config/0,
         check_mgmt_listener_posture/0, check_memory_shedding/0,
         check_mgmt_pin_refresh/0]).                                      %% for testing
-export([evaluate_cluster_id/2, evaluate_cluster_id/3]).                  %% for testing
-export([apply_env_overrides/1]).                                          %% for testing

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

    %% #4632: refuse to boot with a cluster_id that cannot be sent as a protobuf
    %% string (see check_cluster_id/0), before anything is started.
    case check_cluster_id() of
        {error, ClusterReason} -> {error, ClusterReason};
        ok                     -> do_start_checked()
    end.

do_start_checked() ->
    %% A leftover {grpcbox, servers} is refused before anything else is said about
    %% the listeners: the summary below would read "none configured" for it, and
    %% the refusal is the whole explanation.
    case check_legacy_grpcbox_servers() of
        ok ->
            case check_legacy_grpcbox_client() of
                ok -> do_start_guarded();
                {error, _} = Error -> Error
            end;
        {error, _} = Error ->
            Error
    end.

do_start_guarded() ->
    %% Log the ACTUAL transport TLS posture: the {yuzu_gw, grpc_listeners} entries
    %% for the two listeners and {yuzu_gw, upstream_client} for the upstream hop;
    %% the yuzu_gw `tls`/`tls_enabled` env is advisory only (nothing wires it into
    %% a listener or the channel -- see docs/pki-architecture.md "Gateway TLS").
    log_tls_state(),

    %% Every guard below runs on configuration alone, before the supervision
    %% tree is started, and the listeners are the tree's last children: nothing
    %% is bound while a guard can still refuse.
    %%
    %% #PR5: fail CLOSED on a misconfigured-but-encrypted upstream (https without
    %% verify_peer and a CA of its own is MITM-able) -- same fail-closed philosophy as the distribution
    %% cookie guard, rather than booting with only a log warning. PLAINTEXT upstream
    %% is still allowed (the legitimate UAT/dev posture); only the "TLS but
    %% unauthenticated" footgun is refused.
    run_guards([fun check_grpc_listeners/0,
                fun check_upstream_client_config/0,
                fun check_upstream_channel_mix/0,
                fun check_upstream_tls_posture/0,
                fun check_upstream_tls_files/0,
                fun check_mgmt_listener_posture/0,
                fun check_mgmt_pin_refresh/0,
                fun check_memory_shedding/0],
               fun do_start_services/0).

run_guards([], Next) ->
    Next();
run_guards([Guard | Rest], Next) ->
    case Guard() of
        ok -> run_guards(Rest, Next);
        {error, _} = Error -> Error
    end.

do_start_services() ->
    %% Attach telemetry/prometheus handlers.
    yuzu_gw_telemetry:setup(),
    %% Heartbeat-rejection summary log state: created before the supervision
    %% tree (whose last children are the listeners) serves heartbeats, so a burst
    %% of first rejections shares one rate limit. The lazy path in
    %% yuzu_gw_heartbeat_admission covers a heartbeat that races it.
    ok = yuzu_gw_heartbeat_admission:init_summary_state(),
    %% The same for the WARN limit of the calls that carry a registration
    %% request (yuzu_gw_safe_call): a burst of first failures shares one limit.
    ok = yuzu_gw_safe_call:init_limits(),
    %% And for the runner's WARN limit (yuzu_grpc_runner): the same burst, the
    %% same reason, and no lock to take when it comes.
    ok = yuzu_grpc_runner:init_throttle(),

    %% Start Prometheus HTTP exporter for /metrics endpoint.
    Port = application:get_env(yuzu_gw, prometheus_port, 9568),
    application:set_env(prometheus, prometheus_http, [{port, Port}, {path, "/metrics"}]),
    {ok, _} = prometheus_httpd:start(),
    logger:info("Prometheus metrics endpoint started on port ~p", [Port]),
    logger:info("Heartbeat admission is connection-bound: a heartbeat is "
                "admitted only on the connection that opened its session"),

    %% Start the supervision tree. The crash-report filter goes in first so
    %% the upstream's first crash is already redacted (it holds registration
    %% credentials in its mailbox); a tree that does not start removes it again.
    %% The connection-kill counter filter goes in beside it (it counts the VM's
    %% max_heap_size report for a connection the memory bound killed).
    ok = yuzu_gw_crash_redact:install(),
    ok = yuzu_gw_conn_watch:install(),
    case yuzu_gw_sup:start_link() of
        {ok, _} = Started -> Started;
        Other             -> ok = yuzu_gw_conn_watch:remove(),
                             ok = yuzu_gw_crash_redact:remove(),
                             Other
    end.

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

%% @doc Planned stop, before the supervision tree goes (#5695). OTP calls this
%% while every process is still alive; stop/1 runs after the tree is gone, so
%% nothing that needs a process can happen there. Within one budget,
%% shutdown_flush_budget_ms (default 20000, valid 0..600000):
%%   1. The upstream stops taking work (yuzu_gw_upstream:begin_stop/0):
%%      proxied Registers and inventory reports are refused UNAVAILABLE, so
%%      agents go to another gateway; no registration replay runs.
%%   2. No new agent connection: the memory shedder is stopped (it could
%%      resume a listener) and every agent listener is suspended (Ranch keeps
%%      the established connections). The router stops taking commands.
%%   3. In-flight commands get min(3 s, 30% of the budget) to finish.
%%   4. Every local session is ended through its own agent process
%%      (yuzu_gw_agent:disconnect/1), which closes its stream and casts the
%%      DISCONNECTED notice with the session's own stream_home_id (the server
%%      matches a DISCONNECTED to the placement by it, and it lives only in the
%%      agent process, not in the registry table), up to min(5 s, 40% of the
%%      budget) for them to finish.
%%   5. The heartbeat buffer is flushed.
%%   6. The upstream sends every held notification as a last gasp, whatever
%%      the breaker state, until none is left or the budget ends
%%      (yuzu_gw_upstream:last_gasp/1); what is left is counted and logged.
%% Each step is skipped when its process is not running. A kill -9, or a stop
%% that outlasts the container's or unit's stop timeout, gives no last gasp:
%% the server then keeps those sessions until the agents register again. The
%% compose files and the systemd unit give the stop 40 s, the budget plus the
%% tree's own shutdown (docs/user-manual/gateway.md, "Planned stop").
prep_stop(State) ->
    Budget = yuzu_gw_env:env_int(shutdown_flush_budget_ms, ?DEFAULT_FLUSH_BUDGET_MS, 0,
                                 ?MAX_FLUSH_BUDGET_MS),
    T0 = erlang:monotonic_time(millisecond),
    Deadline = T0 + Budget,
    logger:info("Gateway stopping: ending agent sessions and sending their DISCONNECTED "
                "notices to the server (budget ~b ms)", [Budget]),
    _ = safely(fun yuzu_gw_upstream:begin_stop/0),
    _ = safely(fun() -> supervisor:terminate_child(yuzu_gw_sup, yuzu_gw_memory_shedder) end),
    [safely(fun() -> ranch:suspend_listener(Ref) end) || Ref <- agent_listener_refs()],
    case whereis(yuzu_gw_router) of
        undefined -> ok;
        RouterPid -> RouterPid ! drain
    end,
    drain_pending(min(T0 + min(3000, Budget * 3 div 10), Deadline)),
    end_sessions(min(erlang:monotonic_time(millisecond) + min(5000, Budget * 4 div 10),
                     Deadline)),
    _ = safely(fun yuzu_gw_heartbeat_buffer:flush_sync/0),
    case safely(fun() -> yuzu_gw_upstream:last_gasp(Deadline) end) of
        #{sent := Sent, left := Left} ->
            logger:info("Gateway stop: ~b notice(s) sent upstream, ~b left, in ~b ms",
                        [Sent, Left, erlang:monotonic_time(millisecond) - T0]);
        _ ->
            ok
    end,
    State.

stop(_State) ->
    %% The supervision tree is already down: the drain happened in prep_stop/1.
    %% The filter outlives the supervision tree, so the upstream's shutdown
    %% reports are redacted too.
    ok = yuzu_gw_crash_redact:remove(),
    ok = yuzu_gw_conn_watch:remove(),
    logger:info("Gateway shutdown complete"),
    ok.

%% Run Fun, turning an exit or error into `skipped': a step of a stop whose
%% process is gone is skipped, not fatal (an exception here would stop the
%% application master from stopping the tree).
safely(Fun) ->
    try Fun()
    catch _:_ -> skipped
    end.

%% The Ranch refs of the listeners that route the agent service (never the
%% management listener, which stays up while the stop drains commands).
agent_listener_refs() ->
    case application:get_env(yuzu_gw, grpc_listeners, []) of
        Listeners when is_list(Listeners) ->
            [{yuzu_grpc, maps:get(name, E)}
             || E <- Listeners, is_map(E), maps:is_key(name, E),
                yuzu_grpc_listener:routes_agent(E)];
        _ ->
            []
    end.

%% The agent processes of this node: the registry's routing table, filtered to
%% real yuzu_gw_agent processes ([] once the registry, and with it the table,
%% is down).
local_agent_pids() ->
    lists:usort(yuzu_gw_registry:local_agent_pids()).

%% @private Wait for pending commands to drain or until Deadline (monotonic
%% ms). Each agent is asked with a short timeout; the walk stops at the deadline.
drain_pending(Deadline) ->
    case erlang:monotonic_time(millisecond) >= Deadline of
        true ->
            ok;
        false ->
            HasPending = lists:any(fun(Pid) ->
                                       erlang:monotonic_time(millisecond) < Deadline andalso
                                       (try gen_statem:call(Pid, pending_count, 200) > 0
                                        catch _:_ -> false
                                        end)
                                   end, local_agent_pids()),
            case HasPending of
                false ->
                    ok;
                true ->
                    logger:info("Gateway stop: waiting for in-flight commands"),
                    timer:sleep(min(200, max(0, Deadline - erlang:monotonic_time(millisecond)))),
                    drain_pending(Deadline)
            end
    end.

%% @private End every local session through its agent process and wait, until
%% Deadline, for the processes to finish (each casts its DISCONNECTED before it
%% exits). One that is still running at the deadline is left to the tree.
%%
%% The agents are the routing table's AND the agent supervisor's children: an
%% agent still inside its registry call (the `registering' state) is not in the
%% table yet, and ending only the table's agents would let it register, announce
%% CONNECTED and never send its DISCONNECTED. It postpones the disconnect until
%% its registration is done, then ends like the others. A second pass ends any
%% agent started meanwhile (a Subscribe for a session registered just before the
%% stop); at most three passes.
end_sessions(Deadline) ->
    {Ended, Left} = end_sessions(Deadline, #{}, 3),
    case Left of
        0 -> logger:info("Gateway stop: ended ~b agent session(s)", [Ended]);
        _ -> logger:warning("Gateway stop: ~b of ~b agent session(s) had not ended by the "
                            "deadline", [Left, Ended])
    end.

end_sessions(_Deadline, Seen, 0) ->
    {map_size(Seen), 0};
end_sessions(Deadline, Seen, Passes) ->
    case [P || P <- agent_pids(), not is_map_key(P, Seen)] of
        [] ->
            {map_size(Seen), 0};
        Pids ->
            Mons = [{erlang:monitor(process, P), P} || P <- Pids],
            [yuzu_gw_agent:disconnect(P) || P <- Pids],
            Seen1 = maps:merge(Seen, maps:from_keys(Pids, true)),
            case await_down(maps:from_list(Mons), Deadline) of
                0    -> end_sessions(Deadline, Seen1, Passes - 1);
                Left -> {map_size(Seen1), Left}
            end
    end.

agent_pids() ->
    Children = try supervisor:which_children(yuzu_gw_agent_sup)
               catch _:_ -> []
               end,
    lists:usort(local_agent_pids() ++ [P || {_, P, _, _} <- Children, is_pid(P)]).

await_down(Mons, _Deadline) when map_size(Mons) =:= 0 ->
    0;
await_down(Mons, Deadline) ->
    Wait = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {'DOWN', Ref, process, _, _} when is_map_key(Ref, Mons) ->
            await_down(maps:remove(Ref, Mons), Deadline)
    after Wait ->
        [erlang:demonitor(R, [flush]) || R <- maps:keys(Mons)],
        map_size(Mons)
    end.

%%--------------------------------------------------------------------
%% Environment variable overrides for container deployment
%%--------------------------------------------------------------------

%% YUZU_GW_UPSTREAM_ADDR / YUZU_GW_UPSTREAM_PORT used to be copied into the
%% upstream_addr / upstream_port app env, which nothing reads: the server the
%% gateway dials is the endpoint list of the channel in {yuzu_gw, upstream_client}.
%% They logged "ENV override" as if they applied. They are not applied, and a
%% variable set in an operator's compose file now says so instead of looking
%% like it worked.
warn_inert_upstream_env() ->
    [logger:warning("~s is set but has no effect: the upstream server is the endpoint "
                    "list of the channel in {yuzu_gw, upstream_client} (see "
                    "docs/user-manual/gateway.md 'The upstream client').", [Var])
     || Var <- ["YUZU_GW_UPSTREAM_ADDR", "YUZU_GW_UPSTREAM_PORT"],
        os:getenv(Var) =/= false],
    ok.

apply_env_overrides() ->
    warn_inert_upstream_env(),
    apply_env_overrides(file:native_name_encoding()).

%% The environment text is interpreted in the node's native name encoding
%% (yuzu_gw_env:env_utf8_binary/2); the parameter lets a test run both.
apply_env_overrides(Encoding) ->
    Overrides = [
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
        %% The variable's text is read in the node's native name encoding and
        %% its bytes must be valid UTF-8 (yuzu_gw_env:env_utf8_binary/2: a latin1
        %% node, the default of the shipped images, gets the bytes one per
        %% element, a utf8 node the characters). A value that cannot be
        %% represented is left unset here, without printing it, and refused by
        %% check_cluster_id/0 (#4632).
        {"YUZU_GW_CLUSTER_ID", cluster_id, fun(V) -> cluster_id_from_env(V, Encoding) end},
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
                    error:invalid_cluster_id ->
                        %% Never the value: it is the text that could not be
                        %% represented, and check_cluster_id/0 refuses to boot
                        %% for it right after the overrides.
                        logger:warning("ENV override: ~s cannot be represented as UTF-8; "
                                       "ignoring it (the value is not logged)", [EnvVar]);
                    _:_ ->
                        logger:warning("ENV override: ~s has invalid value '~ts', ignoring",
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

    %% The listener ports are not app keys any more: they are inside the
    %% listener entries.
    apply_listener_port_overrides(),

    %% TLS cert overrides (these set the tls proplist)
    apply_tls_overrides().

%% @doc Apply YUZU_GW_AGENT_PORT / YUZU_GW_MGMT_PORT to the listener entries:
%% the port of the entry that serves agent_pb (resp. management_pb), and ONLY
%% when exactly one entry serves that proto. With none, or with several (the
%% two-agent-listener topology: one for a load balancer, one for a router), a
%% single variable cannot say which entry it means and moving them all would
%% put two on one port, so the variable is ignored with a warning. An entry that
%% serves both protos has one port, which YUZU_GW_AGENT_PORT sets;
%% YUZU_GW_MGMT_PORT is ignored for it. Read from the process environment, not
%% from the {yuzu_gw, agent_listen_port} / {yuzu_gw, mgmt_listen_port} keys the
%% deployed configs may still carry: nothing reads those.
-spec apply_listener_port_overrides() -> ok.
apply_listener_port_overrides() ->
    Overrides = [{agent_pb, "YUZU_GW_AGENT_PORT"}, {management_pb, "YUZU_GW_MGMT_PORT"}],
    case application:get_env(yuzu_gw, grpc_listeners, []) of
        [_ | _] = Listeners ->
            case yuzu_grpc_listener:proper_list(Listeners) of
                true ->
                    Updated = lists:foldl(fun({Proto, Var}, Acc) ->
                                              override_proto_port(Proto, Var, Acc)
                                          end, Listeners, Overrides),
                    application:set_env(yuzu_gw, grpc_listeners, Updated);
                false ->
                    ok  %% check_grpc_listeners/0 refuses it
            end;
        _ ->
            ok
    end.

override_proto_port(Proto, Var, Listeners) ->
    case os:getenv(Var) of
        false ->
            Listeners;
        Value ->
            case [L || L <- Listeners, serves_proto(L, Proto)] of
                [Only] ->
                    case Proto =:= management_pb andalso serves_proto(Only, agent_pb) of
                        true ->
                            logger:warning("ENV override: ~s is ignored: the one listener "
                                           "that serves management_pb also serves agent_pb "
                                           "and has one port, set by YUZU_GW_AGENT_PORT", [Var]),
                            Listeners;
                        false ->
                            [case L of
                                 Only -> with_port(L, Value, Var);
                                 _ -> L
                             end || L <- Listeners]
                    end;
                Serving ->
                    logger:warning("ENV override: ~s is ignored: it applies only when exactly "
                                   "one grpc_listeners entry serves ~s and ~b do",
                                   [Var, Proto, length(Serving)]),
                    Listeners
            end
    end.

serves_proto(Entry, Proto) ->
    yuzu_grpc_listener:serves_proto(Entry, Proto).

with_port(Listener, Value, Var) ->
    try list_to_integer(Value) of
        Port when Port >= 0, Port =< 65535 ->
            case maps:get(listen, Listener, #{}) of
                Listen when is_map(Listen) ->
                    logger:info("ENV override: ~s = ~p", [Var, Port]),
                    Listener#{listen => Listen#{port => Port}};
                _ ->
                    %% A `listen' that is not a map is left for validate/1 to
                    %% refuse (bad_listen); no port is applied to it.
                    logger:warning("ENV override: ~s is ignored: the entry's `listen' is not "
                                   "a map", [Var]),
                    Listener
            end;
        _ ->
            logger:warning("ENV override: ~s has invalid value '~s', ignoring", [Var, Value]),
            Listener
    catch
        error:badarg ->
            logger:warning("ENV override: ~s has invalid value '~s', ignoring", [Var, Value]),
            Listener
    end.

cluster_id_from_env(Value, Encoding) ->
    case yuzu_gw_env:env_utf8_binary(Value, Encoding) of
        {ok, Bin} -> Bin;
        error     -> error(invalid_cluster_id)
    end.

%% @private Fail-closed guard (#4632): refuse to boot if the cluster id cannot be
%% represented as UTF-8. It is stamped on every stream-status notification as a
%% protobuf string; a value the encoder rejects would fail every notification,
%% and a notification that is the half_open probe would keep the breaker from
%% closing. Refusing at boot is preferred over booting with a different id (the
%% id pins agents to a trust zone) or one that silently loses every
%% notification. The message names the source, never the value.
-spec check_cluster_id() -> ok | {error, {invalid_cluster_id, env | app_env}}.
check_cluster_id() ->
    AppValue = application:get_env(yuzu_gw, cluster_id, <<"default">>),
    case evaluate_cluster_id(AppValue, os:getenv("YUZU_GW_CLUSTER_ID"),
                             file:native_name_encoding()) of
        {error, {invalid_cluster_id, Source} = Reason} ->
            logger:critical(
                "Refusing to start: the cluster id (~s) cannot be represented as UTF-8 "
                "(a code point above 16#10FFFF, a surrogate, or bytes that are not "
                "UTF-8). Set YUZU_GW_CLUSTER_ID, or cluster_id in sys.config, to a "
                "name made of valid Unicode characters.",
                [case Source of
                     env     -> "YUZU_GW_CLUSTER_ID";
                     app_env -> "the cluster_id application setting"
                 end]),
            {error, Reason};
        ok ->
            ok
    end.

%% @doc Pure policy of check_cluster_id/0 (exported for testing). When the
%% environment variable is set it is what applies (the override replaces the
%% setting), so only it is checked; otherwise the application setting is.
%%
%% The two sources are different kinds of text:
%%  - the ENVIRONMENT value is os:getenv/1 text, interpreted in the node's native
%%    name encoding (yuzu_gw_env:env_utf8_binary/2): its bytes must be valid
%%    UTF-8. Only bytes that are not UTF-8 (or, on a latin1 node, a code point
%%    above 255) are refused, so a refusal from this source is rare;
%%  - the APPLICATION setting (sys.config) is Erlang data, converted with
%%    yuzu_gw_env:utf8_binary/1 and independent of the node's locale. The file is
%%    read as UTF-8 (file:consult), so the working literals for a non-ASCII name
%%    are a string (code points: the name typed as UTF-8 text, or "Z\x{FC}rich")
%%    or a binary with the utf8 modifier (<<"Z\x{FC}rich"/utf8>>). A plain binary
%%    literal (<<"...">>) is not a working form: it holds ONE BYTE per character,
%%    and a character above 255 is truncated to its low 8 bits (by the compiler,
%%    and by file:consult for a sys.config literal). It is accepted only if the
%%    surviving bytes happen to be valid UTF-8, so the name it holds is generally
%%    not the one typed (<<"\x{4E2D}">> becomes the single byte 45, a hyphen,
%%    and is accepted); <<"Z\x{FC}rich">> is the byte 252, not valid UTF-8, and is
%%    refused. Use the utf8 form. Checked with file:consult and with `erl -config'
%%    plus application:load/1 under LC_ALL=C and LC_ALL=C.UTF-8: the same bytes
%%    on both. Most refusals come from this source.
-spec evaluate_cluster_id(term(), string() | false) ->
          ok | {error, {invalid_cluster_id, env | app_env}}.
evaluate_cluster_id(AppValue, EnvValue) ->
    evaluate_cluster_id(AppValue, EnvValue, file:native_name_encoding()).

-spec evaluate_cluster_id(term(), string() | false, latin1 | utf8) ->
          ok | {error, {invalid_cluster_id, env | app_env}}.
evaluate_cluster_id(AppValue, false, _Encoding) ->
    case yuzu_gw_env:utf8_binary(AppValue) of
        {ok, _}  -> ok;
        error    -> {error, {invalid_cluster_id, app_env}}
    end;
evaluate_cluster_id(_AppValue, EnvValue, Encoding) ->
    case yuzu_gw_env:env_utf8_binary(EnvValue, Encoding) of
        {ok, _}  -> ok;
        error    -> {error, {invalid_cluster_id, env}}
    end.

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

%% @private Report the real transport TLS posture: the listener entries of
%% {yuzu_gw, grpc_listeners} and, for the upstream hop, the upstream channel
%% config {yuzu_gw, upstream_client} (see yuzu_grpc_client_config). Never crashes
%% on unexpected shapes.
-spec log_tls_state() -> ok.
log_tls_state() ->
    case application:get_env(yuzu_gw, tls_enabled, auto) of
        false ->
            logger:warning("YUZU_GW_TLS_ENABLED=false is advisory only -- the actual "
                           "transport is whatever the listener entries and the upstream "
                           "client config select (below)");
        _ -> ok
    end,
    %% The WEAKEST endpoint decides what the line says: calls travel over all of
    %% them, so a verified endpoint beside a plaintext one is not "mutual-TLS".
    Up = client_tls_weakest(application:get_env(yuzu_gw, upstream_client, undefined)),
    Listeners = application:get_env(yuzu_gw, grpc_listeners, []),
    %% This reflects the CONFIGURED posture, not a live handshake -- the
    %% upstream channel starts after this line and keeps retrying a connection
    %% that fails (and the server may not have generated certs yet at boot), so
    %% a startup file/handshake probe would false-alarm.
    logger:info("Gateway transport TLS (configured): upstream->server=~s, listeners: ~s",
                [posture_word(Up, client_all_present_client_cert(
                                  application:get_env(yuzu_gw, upstream_client, undefined))),
                 listeners_summary(Listeners)]),
    case Up of
        plaintext ->
            logger:warning("Gateway->server upstream is PLAINTEXT. For production point "
                           "the upstream default_channel at {https,...} with the gateway "
                           "leaf + CA (see config/sys.config.prod / deploy gateway-sys.config).");
        unverified ->
            %% https without {verify,verify_peer}: encrypted but NOT authenticated --
            %% an active MITM can impersonate the server. Do not report this as "TLS".
            logger:warning("Gateway->server upstream is ENCRYPTED but does NOT verify the "
                           "server certificate against a CA of its own ({verify,verify_peer} "
                           "or {cacertfile,...} missing from an upstream channel's SslOpts) "
                           "-- vulnerable to MITM. Add {verify,verify_peer} + {cacertfile,...}.");
        verified -> ok
    end,
    %% Advisory-env footgun: an operator who set YUZU_GW_TLS_* populated only the
    %% unconsumed yuzu_gw `tls` env; it does NOT configure a listener, REGARDLESS
    %% of the actual posture. Warn whenever it is set so the misconception is
    %% always surfaced (not only when the upstream happens to be plaintext).
    case application:get_env(yuzu_gw, tls, []) of
        [] -> ok;
        _ ->
            logger:warning("yuzu_gw `tls` env is set (YUZU_GW_TLS_*) but those env vars are "
                           "advisory and do NOT configure a listener (each reads the `tls` "
                           "map of its own {yuzu_gw, grpc_listeners} entry). See "
                           "docs/pki-architecture.md 'Gateway TLS'.")
    end,
    ok.

%% "agent: one-way TLS, mgmt: mutual TLS": one phrase per listener entry.
-spec listeners_summary(term()) -> string().
listeners_summary([_ | _] = Listeners) ->
    case yuzu_grpc_listener:proper_list(Listeners) of
        true -> lists:flatten(lists:join(", ", [listener_summary(L) || L <- Listeners]));
        false -> "unrecognised entries"
    end;
listeners_summary(_) ->
    "none configured".

listener_summary(#{name := Name} = L) ->
    Origin = case maps:get(origin, L, undefined) of
        #{mode := Mode} when Mode =/= transport -> io_lib:format(" behind ~p", [Mode]);
        _ -> ""
    end,
    lists:flatten(io_lib:format("~p=~s~s", [Name, tls_word(L), Origin]));
listener_summary(_) ->
    "unrecognised entry".

-spec tls_word(map()) -> string().
tls_word(#{tls := Tls}) when is_map(Tls) ->
    case maps:get(verify, Tls, verify_peer) of
        verify_peer ->
            case maps:get(fail_if_no_peer_cert, Tls, true) of
                true -> "mutual-TLS";
                _ -> "TLS(client certificate requested)"
            end;
        _ -> "one-way TLS"
    end;
tls_word(_) ->
    "plaintext".

%% @private Refuse to boot with an upstream channel config the client cannot
%% use, and with none. The value is `{yuzu_gw, upstream_client}' (see
%% yuzu_grpc_client_config); a channel dropped as unreadable would leave the
%% gateway with no upstream, and one whose TLS options were ignored would be
%% worse than none. Nothing of the offending value is logged, only its shape:
%% an endpoint's SSL options name key files.
%%
%% The two callers of the channel, yuzu_gw_upstream and yuzu_gw_heartbeat_buffer,
%% use `default_channel'. A gateway without one registers no agent and forwards
%% no heartbeat while /readyz answers (its upstream check is that a process is
%% alive), so it is refused unless {yuzu_gw, allow_no_upstream} is the literal
%% `true' (a gateway under test).
-spec check_upstream_client_config() -> ok | {error, bad_upstream_client_config | no_upstream_channel}.
check_upstream_client_config() ->
    case yuzu_grpc_client_config:from_env() of
        {ok, Channels} ->
            warn_replaced_options(),
            warn_multi_connection(Channels),
            Has = lists:any(fun(#{name := N}) -> N =:= default_channel end, Channels),
            case Has orelse application:get_env(yuzu_gw, allow_no_upstream, false) =:= true of
                true ->
                    ok;
                false ->
                    logger:critical(
                        "Refusing to start: no upstream channel is configured. Set "
                        "{yuzu_gw, [{upstream_client, #{channels => [{default_channel, "
                        "[Endpoint], #{}}]}}]} (see config/sys.config and "
                        "docs/user-manual/gateway.md); without it the gateway can register "
                        "no agent and forward no heartbeat."),
                    {error, no_upstream_channel}
            end;
        {error, Why} ->
            logger:critical(
                "Refusing to start: the upstream channel configuration "
                "{yuzu_gw, upstream_client} is unusable (~p). Each channel is "
                "{Name, [Endpoint], Options}; an endpoint is "
                "{http | https, Host, Port, SslOptions} (see config/sys.config and "
                "docs/user-manual/gateway.md).", [Why]),
            {error, bad_upstream_client_config}
    end.

%% A channel option that is present but not an integer in its range is replaced
%% by its default (yuzu_grpc_client_config:channel/2), which is a different gateway
%% from the one the file describes: a pool_size of 100 runs as 1, a connect_timeout
%% of 0 as 5000. Said at boot, one line per option, naming the channel, the option,
%% what was given (a number or a type word, never the contents) and what runs. The
%% gateway still starts: a refusal here would turn a typo in a tuning knob into a
%% fleet outage on the next restart.
-spec warn_replaced_options() -> ok.
warn_replaced_options() ->
    [logger:warning(
       "Upstream channel ~s: ~s is ~s, not an integer from ~b to ~b; the default ~b is "
       "used instead (docs/user-manual/gateway.md 'Bad values replaced by defaults').",
       [Channel, Option, Given, Min, Max, Default])
     || #{channel := Channel, option := Option, given := Given,
          min := Min, max := Max, default := Default}
            <- yuzu_grpc_client_config:replaced_options(
                 application:get_env(yuzu_gw, yuzu_grpc_client_config:env_key(), undefined))],
    ok.

%% A channel holding more than one connection (pool_size above 1, or several
%% endpoints) sends its calls round-robin over them. Behind a layer-4 virtual IP
%% in front of several core replicas that spreads ONE gateway's calls over
%% different replicas, which the registration reconcile (ADR-2002 7c) assumes
%% does not happen. Allowed, and said at boot.
warn_multi_connection(Channels) ->
    [logger:warning("Upstream channel ~s holds ~b connections (pool_size ~b, ~b endpoint(s)): "
                    "its calls go round-robin over them. Behind a layer-4 VIP in front of "
                    "several core replicas that spreads one gateway's calls over different "
                    "replicas; keep one connection per gateway unless that is intended "
                    "(docs/user-manual/gateway.md 'The upstream client').",
                    [N, Size * length(Es), Size, length(Es)])
     || #{name := N, pool_size := Size, endpoints := Es} <- Channels, Size * length(Es) > 1],
    ok.

%% @private The files an https endpoint's TLS options name, looked at once at
%% boot. A file that is missing, empty or holds no certificate is WARNED about
%% and the gateway starts: the server creates its certificates on first start,
%% possibly after the gateway's, the channel keeps retrying, and its own error
%% line and /readyz carry on saying so until a connection is made. A DIRECTORY
%% (or other non-file) where a file belongs is REFUSED: it can never become one
%% by waiting, and it is what a container runtime creates in place of a
%% bind-mounted file that does not exist on the host. Reads files, not the option
%% values: a key file's path is never logged (yuzu_gw_tls_files).
-spec check_upstream_tls_files() -> ok | {error, unusable_upstream_tls_file}.
check_upstream_tls_files() ->
    case yuzu_grpc_client_config:from_env() of
        {ok, Channels} ->
            Found = [{N, H, P, Problem}
                     || #{name := N, endpoints := Es} <- Channels,
                        #{host := H, port := P} = E <- Es,
                        Problem <- yuzu_gw_tls_files:diagnose_endpoint(E)],
            [logger:warning("Upstream channel ~s endpoint ~s:~b: ~ts. Every connection to it "
                            "fails until this is fixed.~ts",
                            [N, H, P, yuzu_gw_tls_files:describe(Problem),
                             case yuzu_gw_tls_files:has_definite_defect([Problem]) of
                                 true  -> "";
                                 false -> " The gateway starts anyway because the server may "
                                          "create the file after the gateway does; /readyz stays "
                                          "503 until a connection is made."
                             end])
             || {N, H, P, Problem} <- Found],
            case yuzu_gw_tls_files:has_definite_defect([Pr || {_, _, _, Pr} <- Found]) of
                false ->
                    ok;
                true ->
                    logger:critical(
                        "Refusing to start: a TLS file of an upstream endpoint is a directory "
                        "or not a regular file (see the warning above). It cannot become a file "
                        "by waiting. A container runtime creates a directory in place of a "
                        "bind-mounted file that does not exist on the host: create the file, "
                        "or fix the path (docs/user-manual/gateway.md 'The upstream client')."),
                    {error, unusable_upstream_tls_file}
            end;
        {error, _} ->
            ok
    end.

%% @private Refuse to boot if one channel lists both plaintext (http) and TLS
%% (https) endpoints. A call goes round-robin over every live connection of its
%% channel, so some calls would travel unencrypted (a ProxyRegister carries the
%% enrollment token and the CSR) whatever the https endpoint is verified against,
%% and the boot log would still have said the upstream was TLS. A channel is
%% one scheme.
-spec check_upstream_channel_mix() -> ok | {error, mixed_upstream_endpoints}.
check_upstream_channel_mix() ->
    case client_mixed_channels(application:get_env(yuzu_gw, upstream_client, undefined)) of
        [] ->
            ok;
        [Name | _] ->
            logger:critical(
                "Refusing to start: the upstream channel ~p lists both plaintext (http) "
                "and TLS (https) endpoints. Calls go round-robin over every live "
                "connection of a channel, so some would travel unencrypted. Give a "
                "channel one scheme.", [Name]),
            {error, mixed_upstream_endpoints}
    end.

%% @private Fail-closed guard: refuse to boot if ANY https upstream endpoint is
%% TLS-but-unverified (no {verify,verify_peer}, or no {cacertfile,...} /
%% {cacerts,...} of its own) — encrypted yet MITM-able, or trusting every CA in
%% the operating system's store. PLAINTEXT upstream is permitted (the legitimate UAT/dev posture);
%% only the dangerous "looks secure, isn't" middle state is refused. Mirrors the
%% distribution-cookie guard's fail-closed posture. Dev/CI override:
%% YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1.
-spec check_upstream_tls_posture() -> ok | {error, unverified_upstream_tls}.
check_upstream_tls_posture() ->
    Client = application:get_env(yuzu_gw, upstream_client, undefined),
    %% ANY unverified https endpoint refuses, even beside a verified one: calls
    %% are spread over all of them.
    Posture = case client_has_unverified(Client) of
                  true  -> unverified;
                  false -> client_tls_weakest(Client)
              end,
    Allow = os:getenv("YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM") =:= "1",
    case evaluate_upstream_posture(Posture, Allow) of
        {error, unverified_upstream_tls} ->
            logger:critical(
                "Refusing to start: the upstream channel uses TLS (https) WITHOUT "
                "{verify,verify_peer} and a {cacertfile,...} of its own — encrypted but "
                "UNAUTHENTICATED (MITM-able), or trusting the operating system's CAs. Add "
                "{verify,verify_peer} + {cacertfile,...} to the default_channel SslOpts "
                "(see config/sys.config.prod). Dev/CI may override with "
                "YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1."),
            {error, unverified_upstream_tls};
        ok when Posture =:= unverified ->
            logger:warning("Upstream TLS is unverified (no verify_peer, or no CA of its own) but "
                           "YUZU_GW_ALLOW_UNVERIFIED_UPSTREAM=1 — proceeding (dev/CI only)."),
            ok;
        ok ->
            ok
    end.

%% @doc Pure upstream-posture policy decision — exported for testing. Only
%% `unverified` (https without verify_peer, or without a CA of its own) without
%% an explicit override is refused; `verified` and `plaintext` boot.
-spec evaluate_upstream_posture(tls_posture(), boolean()) ->
          ok | {error, unverified_upstream_tls}.
evaluate_upstream_posture(unverified, false) -> {error, unverified_upstream_tls};
evaluate_upstream_posture(_Posture, _Allow)  -> ok.

%%--------------------------------------------------------------------
%% Listener configuration guards
%%--------------------------------------------------------------------

%% @private Refuse to boot with a non-empty {grpcbox, servers}. The listeners are
%% {yuzu_gw, grpc_listeners}; the gateway does not contain grpcbox, so nothing
%% reads a leftover block, and the operator who kept it believes a listener is
%% configured that is not. It is refused rather than ignored for that reason.
-spec check_legacy_grpcbox_servers() -> ok | {error, legacy_grpcbox_servers}.
check_legacy_grpcbox_servers() ->
    case legacy_grpcbox_value(servers) of
        absent ->
            ok;
        found ->
            logger:critical(
                "Refusing to start: {grpcbox, servers} is set. The gateway's listeners "
                "are configured in {yuzu_gw, grpc_listeners} (one entry per listener) "
                "and nothing reads {grpcbox, servers}: that block would configure no "
                "listener. Move the listener settings into grpc_listeners and remove "
                "the {servers, ...} block (see config/sys.config.prod and "
                "docs/user-manual/gateway.md)."),
            {error, legacy_grpcbox_servers}
    end.

%% @private Refuse to boot with a {grpcbox, client}. The upstream channels are
%% {yuzu_gw, upstream_client} (same value); nothing reads the old key. Left in
%% place it would be INVISIBLE, not merely unused: OTP applies a sys.config entry
%% only to a loaded application, and none is named grpcbox, so the gateway would
%% start with no TLS client options and the operator would read the file and
%% see them.
-spec check_legacy_grpcbox_client() -> ok | {error, legacy_grpcbox_client}.
check_legacy_grpcbox_client() ->
    case legacy_grpcbox_value(client) of
        absent ->
            ok;
        found ->
            logger:critical(
                "Refusing to start: {grpcbox, [{client, ...}]} is set. The upstream "
                "channels are configured in {yuzu_gw, [{upstream_client, ...}]} and "
                "nothing reads the old key. Move the value across unchanged and remove "
                "the {grpcbox, ...} block (see config/sys.config and "
                "docs/user-manual/gateway.md)."),
            {error, legacy_grpcbox_client}
    end.

%% A `grpcbox' key counts when it is in the application env (set at run time) or
%% in one of the config files the VM was started with. The files have to be read
%% because a sys.config entry for an application that is not loaded never reaches
%% the application env. A key whose value is empty or undefined is no key.
legacy_grpcbox_value(Key) ->
    case application:get_env(grpcbox, Key) of
        {ok, V} when V =/= [], V =/= undefined -> found;
        _ -> legacy_grpcbox_in_files(Key, config_files())
    end.

config_files() ->
    case init:get_argument(config) of
        {ok, Lists} -> [P || L <- Lists, P <- L];
        error       -> []
    end.

%% @doc Whether a `{grpcbox, KVs}' entry with a non-empty `Key' is in any of
%% these config files (or a file they name; nesting is followed a few levels).
%% A file that cannot be read or parsed is skipped: the gateway's own boot is the
%% place that fails on a bad config, not this scan. Exported for testing.
-spec legacy_grpcbox_in_files(servers | client, [file:filename()]) -> found | absent.
legacy_grpcbox_in_files(Key, Paths) ->
    case lists:any(fun(P) -> scan_config(P, Key, 4) end, Paths) of
        true  -> found;
        false -> absent
    end.

scan_config(_Path, _Key, 0) ->
    false;
scan_config(Path, Key, Depth) ->
    case read_config(Path) of
        {ok, File, Terms} -> scan_terms(Terms, Key, Depth, filename:dirname(File));
        error             -> false
    end.

read_config(Path) ->
    Candidates = [Path, Path ++ ".config"],
    try
        [{File, Terms} | _] = [{C, T} || C <- Candidates, {ok, [T]} <- [file:consult(C)]],
        {ok, File, Terms}
    catch
        _:_ -> error
    end.

%% A config file named inside another is resolved against the directory of the
%% file that names it, as the VM does; a path relative to the working directory
%% would find a different file, or none, and the scan would report `absent' for
%% a file the VM loads.
nested_path(Nested, Dir) ->
    case filename:pathtype(Nested) of
        absolute -> Nested;
        _        -> filename:join(Dir, Nested)
    end.

scan_terms(Terms, Key, Depth, Dir) when is_list(Terms) ->
    lists:any(fun({grpcbox, KVs}) when is_list(KVs) ->
                      case proplists:get_value(Key, KVs, undefined) of
                          undefined -> false;
                          []        -> false;
                          _         -> true
                      end;
                 (Nested) when is_list(Nested), Nested =/= [], is_integer(hd(Nested)) ->
                      scan_config(nested_path(Nested, Dir), Key, Depth - 1);
                 (_) ->
                      false
              end, Terms);
scan_terms(_, _, _, _) ->
    false.

%% @private Refuse to boot with a listener entry that cannot start, and with no
%% entries at all. Everything checked here is checked before any child of the
%% supervision tree starts: an entry that fails (an incomplete `tls', a key the
%% layer does not read, an origin mode with no sources, a service module that
%% exports none of its service's methods) never binds a port. A module that
%% exports only SOME of them is accepted: the route table leaves the others out
%% and a request for one answers UNIMPLEMENTED (yuzu_grpc_route). An unset or
%% empty `grpc_listeners' is a gateway that accepts no agent and no command
%% while /healthz answers -- what an operator gets by removing the refused
%% {grpcbox, servers} block and adding nothing -- so it is refused unless
%% {yuzu_gw, allow_no_listeners} is the literal `true' (a gateway under test, or
%% one that only routes). The same holds for entries none of which routes the
%% AgentService (check_agent_listener/1).
-spec check_grpc_listeners() ->
          ok | {error, bad_grpc_listeners | no_grpc_listeners | no_agent_listener}.
check_grpc_listeners() ->
    case application:get_env(yuzu_gw, grpc_listeners, []) of
        [] ->
            case application:get_env(yuzu_gw, allow_no_listeners, false) of
                true ->
                    logger:warning("No gRPC listeners are configured ({yuzu_gw, grpc_listeners}) "
                                   "and {yuzu_gw, allow_no_listeners} is true: this gateway "
                                   "accepts no agent or management connection."),
                    ok;
                _ ->
                    logger:critical(
                        "Refusing to start: {yuzu_gw, grpc_listeners} is unset or empty, so this "
                        "gateway would accept no agent and no management connection. Configure "
                        "the listeners in the yuzu_gw block (one entry per listener; see "
                        "config/sys.config.prod and docs/user-manual/gateway.md). A gateway that "
                        "is meant to serve none (a test) sets {yuzu_gw, allow_no_listeners} to "
                        "true."),
                    {error, no_grpc_listeners}
            end;
        Listeners ->
            case evaluate_listeners(Listeners) of
                ok ->
                    check_agent_listener(Listeners);
                {error, Defects} ->
                    logger:critical(
                        "Refusing to start: invalid {yuzu_gw, grpc_listeners} entry/entries ~p. "
                        "See docs/user-manual/gateway.md for the entry shape.", [Defects]),
                    {error, bad_grpc_listeners}
            end
    end.

%% Entries that are all valid but none of which routes the agent service: no agent
%% could ever connect, and /readyz (which requires one) would never answer ready,
%% so a clear refusal is better than a gateway that boots and is never put in
%% rotation. "Routes" is the strict test (yuzu_grpc_listener:routes_agent/1): the
%% AgentService is a key of the entry's `services'. An entry that only lists
%% agent_pb in its service_protos builds a route table without it and answers
%% every agent RPC UNIMPLEMENTED. Excused by {yuzu_gw, allow_no_listeners} (the
%% literal `true') like the empty list.
check_agent_listener(Listeners) ->
    case lists:any(fun yuzu_grpc_listener:routes_agent/1, Listeners) of
        true ->
            ok;
        false ->
            case application:get_env(yuzu_gw, allow_no_listeners, false) of
                true ->
                    logger:warning("No {yuzu_gw, grpc_listeners} entry routes the agent service "
                                   "and {yuzu_gw, allow_no_listeners} is true: this gateway "
                                   "accepts no agent connection."),
                    ok;
                _ ->
                    logger:critical(
                        "Refusing to start: no {yuzu_gw, grpc_listeners} entry routes the "
                        "AgentService (its `services' map has no 'yuzu.agent.v1.AgentService' "
                        "key), so no agent could connect and /readyz would never report "
                        "ready. Add the agent listener (see config/sys.config.prod and "
                        "docs/user-manual/gateway.md). A gateway that is meant to serve none "
                        "(a test) sets {yuzu_gw, allow_no_listeners} to true."),
                    {error, no_agent_listener}
            end
    end.

%% @doc Fail-closed guard: refuse to boot on a malformed {yuzu_gw, memory_shedding}
%% config. Only the SHAPE is checked here (keys and value types); whether the
%% watermarks can be resolved from system memory is environmental and decided by
%% yuzu_gw_memory_shedder at init (an unresolvable mark runs the backstop
%% inactive, it does not fail boot). An unset key is valid (the defaults apply).
-spec check_memory_shedding() -> ok | {error, bad_memory_shedding}.
check_memory_shedding() ->
    case application:get_env(yuzu_gw, memory_shedding, #{}) of
        Cfg ->
            case yuzu_gw_memory_shedder:validate_config(Cfg) of
                ok -> ok;
                {error, Reason} ->
                    logger:critical(
                        "Refusing to start: invalid {yuzu_gw, memory_shedding} config: ~p. "
                        "See docs/user-manual/gateway.md for the shape.", [Reason]),
                    {error, bad_memory_shedding}
            end
    end.

%% @doc Fail-closed guard: refuse to boot on a {yuzu_gw, mgmt_pin_refresh_ms}
%% that is set but is not an integer from 100 to 3600000 (ms). It is how often
%% yuzu_gw_mgmt_pins re-stats the {cert_file, Path} management pins, so it bounds
%% how long a rotated server leaf is refused (#5696). Unset is valid (5000).
-spec check_mgmt_pin_refresh() -> ok | {error, bad_mgmt_pin_refresh_ms}.
check_mgmt_pin_refresh() ->
    case yuzu_gw_mgmt_pins:validate_refresh_ms(
           application:get_env(yuzu_gw, mgmt_pin_refresh_ms, undefined)) of
        ok ->
            ok;
        {error, Reason} ->
            logger:critical(
              "Refusing to start: invalid {yuzu_gw, mgmt_pin_refresh_ms}: ~p. It must be "
              "an integer number of milliseconds from 100 to 3600000, or unset (5000). "
              "See docs/user-manual/gateway.md.", [Reason]),
            {error, bad_mgmt_pin_refresh_ms}
    end.

%% @doc Pure listener-configuration decision -- exported for testing. A defect
%% is `{Name, Reason}' (Name is `unknown' for an entry that has none): the
%% entry's own validation (yuzu_grpc_listener:validate/1), the route table it
%% would build, a name used twice, or a fixed port used twice.
-spec evaluate_listeners(term()) -> ok | {error, [{term(), term()}]}.
evaluate_listeners(Listeners) when is_list(Listeners) ->
    case yuzu_grpc_listener:proper_list(Listeners) of
        true -> evaluate_entries(Listeners);
        false -> {error, [{unknown, grpc_listeners_not_a_list}]}
    end;
evaluate_listeners(_) ->
    {error, [{unknown, grpc_listeners_not_a_list}]}.

evaluate_entries(Listeners) ->
    Names = [N || #{name := N} <- Listeners],
    Ports = [P || #{listen := #{port := P}} <- Listeners, is_integer(P), P > 0],
    Defects = lists:flatmap(fun listener_defects/1, Listeners)
        ++ [{N, duplicate_name} || N <- lists:usort(Names -- lists:usort(Names))]
        ++ [{port, {duplicate_port, P}} || P <- lists:usort(Ports -- lists:usort(Ports))],
    case Defects of
        [] -> ok;
        _ -> {error, Defects}
    end.

listener_defects(Entry) when is_map(Entry) ->
    Name = maps:get(name, Entry, unknown),
    case yuzu_grpc_listener:validate(Entry) of
        {error, Reason} ->
            [{Name, Reason}];
        ok ->
            case yuzu_grpc_route:build(maps:get(service_protos, Entry), maps:get(services, Entry)) of
                {ok, _Routes} -> [];
                {error, Reason} -> [{Name, {bad_routes, Reason}}]
            end
    end;
listener_defects(_) ->
    [{unknown, entry_not_a_map}].

%% @doc True if any listener entry serves TLS (it has a `tls' map). Pure;
%% exported for testing.
-spec listeners_have_tls(term()) -> boolean().
listeners_have_tls([_ | _] = Listeners) ->
    yuzu_grpc_listener:proper_list(Listeners)
        andalso lists:any(fun(#{tls := Tls}) when is_map(Tls) -> true;
                             (_) -> false
                          end, Listeners);
listeners_have_tls(_) ->
    false.

%%--------------------------------------------------------------------
%% Mgmt-listener posture guard (#1422)
%%--------------------------------------------------------------------

%% @private Fail-closed guard for the PRIVILEGED command plane: refuse to boot
%% when a management_pb listener is network-reachable without the full #1422
%% posture (strict mTLS + the SPKI-pin auth_fun + configured pins). A
%% mgmt listener without it hands fleet-wide command execution to any peer
%% that can reach the port -- the finding this guard makes non-recurring.
%%
%% This runs on configuration before the supervision tree starts, and the
%% listeners are the tree's last children: when it refuses, no management port
%% was ever bound.
%%
%% Escape hatch: {yuzu_gw, allow_insecure_mgmt} set to the literal `true'
%% boots anyway with a loud warning -- an ACKNOWLEDGEMENT for lab/UAT rigs
%% (which the tracked rig configs set explicitly), not a mitigation.
-spec check_mgmt_listener_posture() -> ok | {error, insecure_mgmt_listener}.
check_mgmt_listener_posture() ->
    Listeners = application:get_env(yuzu_gw, grpc_listeners, []),
    Pins = application:get_env(yuzu_gw, mgmt_peer_pins, []),
    Allow = application:get_env(yuzu_gw, allow_insecure_mgmt, false) =:= true,
    case evaluate_mgmt_posture(Listeners, Pins, Allow) of
        ok ->
            ok;
        {ok_insecure, Details} ->
            logger:warning(
                "Management listener(s) ~p lack the #1422 secure posture but "
                "{yuzu_gw, allow_insecure_mgmt} is true -- booting anyway. This "
                "plane fans commands to the ENTIRE fleet; this override is for "
                "isolated lab/UAT rigs only, never production.", [Details]),
            ok;
        {error, {insecure_mgmt_listener, Details}} ->
            logger:critical(
                "Refusing to start: management listener(s) ~p are network-"
                "reachable without the required posture (a `tls' map with "
                "certfile+keyfile+cacertfile, verify_peer, fail_if_no_peer_cert, "
                "auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1, no proxied "
                "origin, and non-empty {yuzu_gw, mgmt_peer_pins}). Anyone reaching "
                "this port could otherwise command the entire fleet (#1422). Fix "
                "the grpc_listeners entry (see config/sys.config.prod), bind it to "
                "loopback, or -- isolated lab/UAT rigs ONLY -- set "
                "{yuzu_gw, allow_insecure_mgmt} to true.", [Details]),
            {error, insecure_mgmt_listener}
    end.

%% @doc Pure mgmt-posture policy decision -- exported for testing. Returns a
%% per-listener defect list keyed by listen port; the escape hatch converts a
%% refusal into {ok_insecure, Details} (boot + warn), never a silent pass.
-spec evaluate_mgmt_posture(term(), term(), boolean()) ->
          ok | {ok_insecure, [term()]} | {error, {insecure_mgmt_listener, [term()]}}.
evaluate_mgmt_posture([_ | _] = Listeners, Pins, Allow) ->
    case yuzu_grpc_listener:proper_list(Listeners) of
        true -> mgmt_posture(Listeners, Pins, Allow);
        %% An improper list cannot be walked, so no listener can be shown NOT to
        %% be a management one: refused, whatever the escape hatch says.
        false -> {error, {insecure_mgmt_listener, [{unknown, improper_list}]}}
    end;
evaluate_mgmt_posture(_Listeners, _Pins, _Allow) ->
    %% No listeners, or an unrecognisable listeners config: nothing provably
    %% exposes management_pb (evaluate_listeners/1 refuses an unusable one
    %% separately).
    ok.

mgmt_posture(Listeners, Pins, Allow) ->
    Details = [{listener_port(S), D}
               || S <- Listeners, is_mgmt_listener(S),
                  not loopback_bound(S),
                  D <- [mgmt_defects(S, Pins)],
                  D =/= []],
    case {Details, Allow} of
        {[], _}     -> ok;
        {_, true}   -> {ok_insecure, Details};
        {_, false}  -> {error, {insecure_mgmt_listener, Details}}
    end.

%% @private A listener serving the management proto. Identified by
%% service_protos -- never by port or the advisory yuzu_gw env keys.
-spec is_mgmt_listener(term()) -> boolean().
is_mgmt_listener(S) ->
    yuzu_grpc_listener:serves_proto(S, management_pb).

%% @private Loopback-only binds have no network attack surface. A missing or
%% unrecognised ip is EXPOSED (the listener binds {0,0,0,0} by default). The
%% `ip' of `listen' is authoritative ONLY when `socket_opts' cannot override the
%% bind: an inherited `{fd, _}' descriptor makes the socket bind wherever the fd
%% points (e.g. systemd socket activation), and an `{ip, _}' or `{ifaddr, _}'
%% inside socket_opts is appended after the map ip in the inet option list,
%% where the later occurrence wins. Any of them makes a nominal
%% `ip => {127,0,0,1}' a dead letter, so all forfeit the exemption (PR #3905
%% review, Doomgoose blocking finding). yuzu_grpc_listener:validate/1 refuses
%% these options outright on every listener; this stays the fail-safe for a
%% caller that reaches the posture decision without it.
-spec loopback_bound(map()) -> boolean().
loopback_bound(S) ->
    case maps:get(listen, S, #{}) of
        Listen when is_map(Listen) -> loopback_bound_listen(Listen);
        _ -> false  % unrecognised shape: cannot prove the bind -- exposed
    end.

loopback_bound_listen(Listen) ->
    Overridable = case maps:get(socket_opts, Listen, undefined) of
        undefined -> false;
        L when is_list(L) ->
            not yuzu_grpc_listener:proper_list(L)  % unrecognised shape: exposed
                orelse lists:keymember(fd, 1, L) orelse lists:keymember(ip, 1, L)
                orelse lists:keymember(ifaddr, 1, L) orelse lists:keymember(local, 1, L)
                orelse lists:member(local, L);
        _ -> true  % unrecognised shape: cannot prove the bind -- exposed
    end,
    case {Overridable, maps:get(ip, Listen, undefined)} of
        {true, _}                         -> false;
        {false, {127, _, _, _}}           -> true;
        {false, {0, 0, 0, 0, 0, 0, 0, 1}} -> true;
        _                                 -> false
    end.

%% @private Everything wrong with one mgmt listener's posture. A listener without
%% a `tls' map is plaintext, and an incomplete map cannot start at all
%% (yuzu_grpc_listener:validate/1), so there is no "cert material but plaintext"
%% state to catch. TLS with verify_none would let a self-signed cert reach the
%% auth_fun, and without fail_if_no_peer_cert a certless peer skips it entirely
%% -- both count as defects. The auth_fun must be exactly the approved pin
%% callback, the pin set non-empty, and the origin the TCP peer: this plane takes
%% its authority from the certificate, and a proxied listener would not be
%% reachable by the server's own client.
-spec mgmt_defects(map(), term()) -> [atom()].
mgmt_defects(S, Pins) ->
    Tls = maps:get(tls, S, undefined),
    IsTls = is_map(Tls),
    HasMaterial = IsTls andalso lists:all(fun(K) -> has_material(K, Tls) end,
                                          [certfile, keyfile, cacertfile]),
    %% verify defaults to verify_peer and fail_if_no_peer_cert to "verify is
    %% verify_peer" (yuzu_grpc_listener:ssl_opts/1), so absent is fine; an
    %% explicit relaxation is not.
    Verify = case IsTls of true -> maps:get(verify, Tls, verify_peer); false -> undefined end,
    FailNoPeer = case IsTls of
        true -> maps:get(fail_if_no_peer_cert, Tls, Verify =:= verify_peer);
        false -> undefined
    end,
    Origin = maps:get(origin, S, #{mode => transport}),
    Checks =
        [{plaintext, not IsTls},
         {missing_cert_material, IsTls andalso not HasMaterial},
         {verify_not_peer, IsTls andalso Verify =/= verify_peer},
         {peer_cert_not_required, IsTls andalso FailNoPeer =/= true},
         {missing_or_wrong_auth_fun,
          maps:get(auth_fun, S, undefined) =/= fun yuzu_gw_authz:check_mgmt_peer/1},
         {no_mgmt_peer_pins, not (is_list(Pins) andalso Pins =/= [])},
         {proxied_origin, not (is_map(Origin) andalso maps:get(mode, Origin, undefined) =:= transport)}],
    [Defect || {Defect, true} <- Checks].

%% "mutual-TLS" is said only when the gateway also PRESENTS a certificate on
%% every endpoint (certfile + keyfile); a verified channel without one
%% authenticates the server to the gateway and nothing more.
-spec posture_word(tls_posture(), boolean()) -> string().
posture_word(verified, true)  -> "mutual-TLS";
posture_word(verified, false) -> "server-authenticated TLS (no client certificate)";
posture_word(unverified, _)   -> "TLS(UNVERIFIED!)";
posture_word(plaintext, _)    -> "plaintext".

%% @doc True if there is at least one endpoint and every https endpoint of every
%% channel carries both a {certfile,..} and a {keyfile,..} (or {key,..}/{cert,..}).
%% Pure; exported for testing.
-spec client_all_present_client_cert(term()) -> boolean().
client_all_present_client_cert(#{channels := Channels}) when is_list(Channels) ->
    Es = [E || {_N, Endpoints, _O} <- Channels, is_list(Endpoints), E <- Endpoints],
    Es =/= [] andalso lists:all(fun presents_client_cert/1, Es);
client_all_present_client_cert(_) ->
    false.

presents_client_cert(E) when is_tuple(E), tuple_size(E) >= 4, element(1, E) =:= https ->
    Ssl = element(4, E),
    is_list(Ssl)
        andalso (proplists:is_defined(certfile, Ssl) orelse proplists:is_defined(cert, Ssl))
        andalso (proplists:is_defined(keyfile, Ssl) orelse proplists:is_defined(key, Ssl));
presents_client_cert(_) ->
    false.

%% @doc Strongest TLS posture across the upstream client channels: `verified` (an
%% `https` endpoint with {verify,verify_peer} and a {cacertfile,..}/{cacerts,..}
%% of its own), `unverified` (https without both), else `plaintext`. This is the
%% STRONGEST endpoint: it answers "is there TLS at all" (client_has_https/1). The
%% boot guard and the boot log use the weakest one (client_tls_weakest/1,
%% client_has_unverified/1), because calls travel over every endpoint. Pure;
%% exported for testing.
-spec client_tls_posture(term()) -> tls_posture().
client_tls_posture(#{channels := Channels}) when is_list(Channels) ->
    lists:foldl(fun(Ch, Acc) -> strongest(channel_posture(Ch), Acc) end,
                plaintext, Channels);
client_tls_posture(_) ->
    plaintext.

%% @doc True if any upstream client channel has an `https` endpoint (verified or
%% not). Pure; exported for testing.
-spec client_has_https(term()) -> boolean().
client_has_https(Client) -> client_tls_posture(Client) =/= plaintext.

%% @doc The WEAKEST posture of any endpoint of any channel: `plaintext` if any
%% endpoint is http, else `unverified` if any https endpoint is, else `verified`
%% (no endpoint at all is `plaintext`). Pure; exported for testing.
-spec client_tls_weakest(term()) -> tls_posture().
client_tls_weakest(Client) ->
    case endpoint_postures(Client) of
        [] -> plaintext;
        Ps -> case {lists:member(plaintext, Ps), lists:member(unverified, Ps)} of
                  {true, _}      -> plaintext;
                  {false, true}  -> unverified;
                  {false, false} -> verified
              end
    end.

%% @doc True if any https endpoint of any channel is unverified. Pure; exported
%% for testing.
-spec client_has_unverified(term()) -> boolean().
client_has_unverified(Client) ->
    lists:member(unverified, endpoint_postures(Client)).

%% @doc The names of the channels that list both plaintext and TLS endpoints.
%% Pure; exported for testing.
-spec client_mixed_channels(term()) -> [term()].
client_mixed_channels(#{channels := Channels}) when is_list(Channels) ->
    [Name || {Name, Endpoints, _Opts} <- Channels, is_list(Endpoints),
             begin
                 Ps = [endpoint_posture(E) || E <- Endpoints],
                 lists:member(plaintext, Ps) andalso lists:any(fun(P) -> P =/= plaintext end, Ps)
             end];
client_mixed_channels(_) ->
    [].

endpoint_postures(#{channels := Channels}) when is_list(Channels) ->
    [endpoint_posture(E) || {_Name, Endpoints, _Opts} <- Channels, is_list(Endpoints),
                            E <- Endpoints];
endpoint_postures(_) ->
    [].

-spec channel_posture(term()) -> tls_posture().
channel_posture({_Name, Endpoints, _Opts}) when is_list(Endpoints) ->
    lists:foldl(fun(E, Acc) -> strongest(endpoint_posture(E), Acc) end,
                plaintext, Endpoints);
channel_posture(_) ->
    plaintext.

-spec endpoint_posture(term()) -> tls_posture().
endpoint_posture(E) when is_tuple(E), tuple_size(E) >= 4, element(1, E) =:= https ->
    %% verify_peer AND a trust anchor of the operator's own. Without one, gun
    %% fills in the operating system's CA store ({cacerts, system}), where ssl
    %% on its own refuses verify_peer with no CA; a channel left that way would
    %% trust every public CA to vouch for the gateway's own server, which is not
    %% what a pinned private PKI means, so it counts as unverified.
    SslOpts = element(4, E),
    case is_list(SslOpts)
         andalso proplists:get_value(verify, SslOpts) =:= verify_peer
         andalso has_trust_anchor(SslOpts) of
        true  -> verified;
        false -> unverified
    end;
endpoint_posture(_) ->
    plaintext.

%% A CA file named (a non-empty string or binary) or certificates given (a
%% non-empty list of them): not an atom, not an empty value. Whether the file
%% EXISTS is not asked here: the server may generate its certificates after the
%% gateway has started, and a missing file fails the first connection loudly.
has_trust_anchor(SslOpts) ->
    anchor_file(proplists:get_value(cacertfile, SslOpts))
        orelse anchor_certs(proplists:get_value(cacerts, SslOpts)).

anchor_file(File) when is_binary(File) -> File =/= <<>>;
anchor_file(File) when is_list(File)   -> File =/= [] andalso io_lib:printable_unicode_list(File);
anchor_file(_)                         -> false.

anchor_certs([_ | _]) -> true;
anchor_certs(_)       -> false.

-spec strongest(tls_posture(), tls_posture()) -> tls_posture().
strongest(verified, _)            -> verified;
strongest(_, verified)            -> verified;
strongest(unverified, _)          -> unverified;
strongest(_, unverified)          -> unverified;
strongest(plaintext, plaintext)   -> plaintext.

%% @private true if the key carries a non-empty value (undefined/""/<<>> don't
%% count -- a placeholder is not material).
-spec has_material(atom(), map()) -> boolean().
has_material(K, Opts) ->
    case maps:get(K, Opts, undefined) of
        undefined -> false;
        ""        -> false;
        <<>>      -> false;
        _         -> true
    end.

-spec listener_port(map()) -> term().
listener_port(S) ->
    case maps:get(listen, S, #{}) of
        #{port := P} -> P;
        _            -> unknown
    end.
