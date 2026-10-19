%%%-------------------------------------------------------------------
%%% @doc Non-functional EUnit tests for C1: TLS configuration and
%%% environment variable overrides.
%%%
%%% Tests apply_env_overrides/0 and apply_tls_overrides/0 with
%%% various valid, invalid, and partial environment variable
%%% combinations. Verifies that the config system is robust
%%% against malformed input and correctly propagates overrides.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_env_override_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).  %% logger handler (the log-capturing tests attach this module)

%%%===================================================================
%%% Test fixture — foreach clears env between tests
%%%===================================================================

env_override_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [
      {"integer env overrides are applied", fun integer_overrides/0},
      {"boolean env override: true/false strings", fun bool_override_strings/0},
      {"boolean env override: 1/0 strings", fun bool_override_numeric/0},
      {"invalid integer env override is ignored", fun invalid_integer_ignored/0},
      {"invalid boolean env override is ignored", fun invalid_bool_ignored/0},
      {"TLS cert env overrides set tls proplist", fun tls_cert_overrides/0},
      {"partial TLS cert env override merges with base", fun partial_tls_cert_override/0},
      {"TLS cert override with no base creates new proplist", fun tls_cert_override_no_base/0},
      {"env overrides do not clobber unrelated config", fun no_clobber/0},
      {"all env vars absent leaves defaults untouched", fun absent_env_noop/0},
      {"YUZU_GW_UPSTREAM_ADDR/PORT are not applied: the upstream is the channel's endpoint list",
       fun upstream_vars_are_inert/0},
      {"YUZU_GW_UPSTREAM_ADDR/PORT set: a warning for each, naming the variable and not its value",
       fun upstream_vars_warn/0},
      {"YUZU_GW_UPSTREAM_ADDR/PORT unset: no warning",
       fun upstream_vars_unset_do_not_warn/0},
      {"the upstream channel config is not touched by either variable",
       fun upstream_vars_leave_the_channel_config/0}
     ]}.

setup() ->
    %% Save original env state for restoration.
    %% Clear any leftover env vars from prior tests.
    EnvVars = [
        "YUZU_GW_UPSTREAM_ADDR", "YUZU_GW_UPSTREAM_PORT",
        "YUZU_GW_AGENT_PORT", "YUZU_GW_MGMT_PORT",
        "YUZU_GW_PROMETHEUS_PORT", "YUZU_GW_HEALTH_PORT",
        "YUZU_GW_HEARTBEAT_INTERVAL_MS", "YUZU_GW_COMMAND_TIMEOUT_S",
        "YUZU_GW_BACKPRESSURE_THRESHOLD",
        "YUZU_GW_CB_FAILURE_THRESHOLD", "YUZU_GW_CB_RESET_TIMEOUT_MS",
        "YUZU_GW_CB_MAX_RESET_TIMEOUT_MS",
        "YUZU_GW_TLS_ENABLED",
        "YUZU_GW_TLS_CERTFILE", "YUZU_GW_TLS_KEYFILE", "YUZU_GW_TLS_CACERTFILE"
    ],
    lists:foreach(fun(V) -> os:unsetenv(V) end, EnvVars),
    %% Set known defaults so we can verify they're changed.
    application:set_env(yuzu_gw, upstream_addr, "127.0.0.1"),
    application:set_env(yuzu_gw, upstream_port, 50055),
    application:set_env(yuzu_gw, health_port, 8081),
    application:set_env(yuzu_gw, backpressure_threshold, 1000),
    application:unset_env(yuzu_gw, tls_enabled),
    application:unset_env(yuzu_gw, tls),
    EnvVars.

cleanup(EnvVars) ->
    lists:foreach(fun(V) -> os:unsetenv(V) end, EnvVars),
    ok.

%%%===================================================================
%%% Tests
%%%===================================================================

integer_overrides() ->
    os:putenv("YUZU_GW_PROMETHEUS_PORT", "9999"),
    os:putenv("YUZU_GW_HEALTH_PORT", "18888"),
    os:putenv("YUZU_GW_BACKPRESSURE_THRESHOLD", "500"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(9999, application:get_env(yuzu_gw, prometheus_port, undefined)),
    ?assertEqual(18888, application:get_env(yuzu_gw, health_port, undefined)),
    ?assertEqual(500, application:get_env(yuzu_gw, backpressure_threshold, undefined)).

bool_override_strings() ->
    os:putenv("YUZU_GW_TLS_ENABLED", "false"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(false, application:get_env(yuzu_gw, tls_enabled, undefined)),

    os:putenv("YUZU_GW_TLS_ENABLED", "true"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(true, application:get_env(yuzu_gw, tls_enabled, undefined)).

bool_override_numeric() ->
    os:putenv("YUZU_GW_TLS_ENABLED", "0"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(false, application:get_env(yuzu_gw, tls_enabled, undefined)),

    os:putenv("YUZU_GW_TLS_ENABLED", "1"),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(true, application:get_env(yuzu_gw, tls_enabled, undefined)).

invalid_integer_ignored() ->
    application:set_env(yuzu_gw, health_port, 8081),
    os:putenv("YUZU_GW_HEALTH_PORT", "not_a_number"),
    yuzu_gw_app:apply_env_overrides(),
    %% Original value preserved.
    ?assertEqual(8081, application:get_env(yuzu_gw, health_port, undefined)).

invalid_bool_ignored() ->
    application:unset_env(yuzu_gw, tls_enabled),
    os:putenv("YUZU_GW_TLS_ENABLED", "maybe"),
    yuzu_gw_app:apply_env_overrides(),
    %% tls_enabled should not be set (error was caught and ignored).
    ?assertEqual(undefined, application:get_env(yuzu_gw, tls_enabled, undefined)).

tls_cert_overrides() ->
    os:putenv("YUZU_GW_TLS_CERTFILE", "/tmp/test.crt"),
    os:putenv("YUZU_GW_TLS_KEYFILE", "/tmp/test.key"),
    os:putenv("YUZU_GW_TLS_CACERTFILE", "/tmp/ca.crt"),
    yuzu_gw_app:apply_env_overrides(),
    {ok, TlsOpts} = application:get_env(yuzu_gw, tls),
    ?assertEqual("/tmp/test.crt", proplists:get_value(certfile, TlsOpts)),
    ?assertEqual("/tmp/test.key", proplists:get_value(keyfile, TlsOpts)),
    ?assertEqual("/tmp/ca.crt", proplists:get_value(cacertfile, TlsOpts)).

partial_tls_cert_override() ->
    %% Set a base TLS config.
    application:set_env(yuzu_gw, tls, [
        {certfile, "/etc/yuzu/old.crt"},
        {keyfile,  "/etc/yuzu/old.key"},
        {verify, verify_peer}
    ]),
    %% Only override certfile, leave keyfile and verify alone.
    os:putenv("YUZU_GW_TLS_CERTFILE", "/tmp/new.crt"),
    yuzu_gw_app:apply_env_overrides(),
    {ok, TlsOpts} = application:get_env(yuzu_gw, tls),
    ?assertEqual("/tmp/new.crt", proplists:get_value(certfile, TlsOpts)),
    ?assertEqual("/etc/yuzu/old.key", proplists:get_value(keyfile, TlsOpts)),
    ?assertEqual(verify_peer, proplists:get_value(verify, TlsOpts)).

tls_cert_override_no_base() ->
    %% No base TLS config at all.
    application:unset_env(yuzu_gw, tls),
    os:putenv("YUZU_GW_TLS_CERTFILE", "/tmp/brand-new.crt"),
    yuzu_gw_app:apply_env_overrides(),
    {ok, TlsOpts} = application:get_env(yuzu_gw, tls),
    ?assertEqual("/tmp/brand-new.crt", proplists:get_value(certfile, TlsOpts)),
    %% keyfile and cacertfile should not be present.
    ?assertEqual(undefined, proplists:get_value(keyfile, TlsOpts)),
    ?assertEqual(undefined, proplists:get_value(cacertfile, TlsOpts)).

no_clobber() ->
    %% Set an unrelated config key.
    application:set_env(yuzu_gw, hash_ring_vnodes, 256),
    %% Apply an override to a different key.
    os:putenv("YUZU_GW_HEALTH_PORT", "18889"),
    yuzu_gw_app:apply_env_overrides(),
    %% Unrelated key must be untouched.
    ?assertEqual(256, application:get_env(yuzu_gw, hash_ring_vnodes, undefined)),
    ?assertEqual(18889, application:get_env(yuzu_gw, health_port, undefined)).

absent_env_noop() ->
    %% No env vars set at all. Defaults should remain.
    application:set_env(yuzu_gw, upstream_port, 50055),
    application:set_env(yuzu_gw, health_port, 8081),
    yuzu_gw_app:apply_env_overrides(),
    ?assertEqual(50055, application:get_env(yuzu_gw, upstream_port, undefined)),
    ?assertEqual(8081, application:get_env(yuzu_gw, health_port, undefined)).

%%%===================================================================
%%% YUZU_GW_UPSTREAM_ADDR / YUZU_GW_UPSTREAM_PORT
%%%
%%% They used to be copied into the upstream_addr / upstream_port app env, which
%%% nothing reads: the server the gateway dials is the endpoint list of the
%%% channel in {yuzu_gw, upstream_client}. A variable an operator's compose file
%%% still sets now says it has no effect, instead of logging "ENV override" as
%%% if it applied.
%%%===================================================================

upstream_vars_are_inert() ->
    application:set_env(yuzu_gw, upstream_addr, "127.0.0.1"),
    application:set_env(yuzu_gw, upstream_port, 50055),
    os:putenv("YUZU_GW_UPSTREAM_ADDR", "10.9.8.7"),
    os:putenv("YUZU_GW_UPSTREAM_PORT", "9999"),
    _ = capture_events(fun() -> ?assertEqual(ok, yuzu_gw_app:apply_env_overrides()) end),
    ?assertEqual("127.0.0.1", application:get_env(yuzu_gw, upstream_addr, undefined)),
    ?assertEqual(50055, application:get_env(yuzu_gw, upstream_port, undefined)),
    %% and where the key was never set, it is not created
    application:unset_env(yuzu_gw, upstream_addr),
    application:unset_env(yuzu_gw, upstream_port),
    _ = capture_events(fun() -> yuzu_gw_app:apply_env_overrides() end),
    ?assertEqual(undefined, application:get_env(yuzu_gw, upstream_addr, undefined)),
    ?assertEqual(undefined, application:get_env(yuzu_gw, upstream_port, undefined)).

upstream_vars_warn() ->
    os:putenv("YUZU_GW_UPSTREAM_ADDR", "10.9.8.7"),
    os:putenv("YUZU_GW_UPSTREAM_PORT", "9999"),
    Events = capture_events(fun() -> yuzu_gw_app:apply_env_overrides() end),
    Warnings = [T || {warning, T} <- Events],
    Addr = [T || T <- Warnings, string:find(T, "YUZU_GW_UPSTREAM_ADDR") =/= nomatch],
    Port = [T || T <- Warnings, string:find(T, "YUZU_GW_UPSTREAM_PORT") =/= nomatch],
    ?assertMatch([_], Addr),
    ?assertMatch([_], Port),
    %% it says what to do instead, and that the variable has no effect
    [?assertNotEqual(nomatch, string:find(T, "has no effect")) || T <- Addr ++ Port],
    [?assertNotEqual(nomatch, string:find(T, "upstream_client")) || T <- Addr ++ Port],
    %% the value is not echoed (an address is configuration)
    Text = lists:flatten(Warnings),
    ?assertEqual(nomatch, string:find(Text, "10.9.8.7")),
    ?assertEqual(nomatch, string:find(Text, "9999")),
    %% and it is not reported as an applied override
    ?assertEqual([], [T || {_, T} <- Events, string:find(T, "ENV override: YUZU_GW_UPSTREAM") =/= nomatch]).

upstream_vars_unset_do_not_warn() ->
    Events = capture_events(fun() -> yuzu_gw_app:apply_env_overrides() end),
    ?assertEqual([], [T || {_, T} <- Events, string:find(T, "YUZU_GW_UPSTREAM") =/= nomatch]),
    %% one of the two set: one warning, for that one
    os:putenv("YUZU_GW_UPSTREAM_PORT", "9999"),
    Events1 = capture_events(fun() -> yuzu_gw_app:apply_env_overrides() end),
    ?assertMatch([_], [T || {warning, T} <- Events1, string:find(T, "YUZU_GW_UPSTREAM_PORT") =/= nomatch]),
    ?assertEqual([], [T || {_, T} <- Events1, string:find(T, "YUZU_GW_UPSTREAM_ADDR") =/= nomatch]).

upstream_vars_leave_the_channel_config() ->
    Client = #{channels => [{default_channel, [{http, "127.0.0.1", 59999, []}], #{}}]},
    Prev = application:get_env(yuzu_gw, upstream_client),
    application:set_env(yuzu_gw, upstream_client, Client),
    try
        os:putenv("YUZU_GW_UPSTREAM_ADDR", "10.9.8.7"),
        os:putenv("YUZU_GW_UPSTREAM_PORT", "9999"),
        _ = capture_events(fun() -> yuzu_gw_app:apply_env_overrides() end),
        ?assertEqual({ok, Client}, application:get_env(yuzu_gw, upstream_client))
    after
        case Prev of
            {ok, V}   -> application:set_env(yuzu_gw, upstream_client, V);
            undefined -> application:unset_env(yuzu_gw, upstream_client)
        end
    end.

%% The log events of Fun as {Level, Text}; the handler takes everything.
capture_events(Fun) ->
    Id = yuzu_gw_env_override_tests_handler,
    Primary = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Fun(),
        drain_logs([])
    after
        ok = logger:remove_handler(Id),
        ok = logger:set_primary_config(level, Primary)
    end.

drain_logs(Acc) ->
    receive
        {logged, #{level := Level, msg := {Fmt, Args}}} when is_list(Fmt), is_list(Args) ->
            drain_logs([{Level, lists:flatten(io_lib:format(Fmt, Args))} | Acc]);
        {logged, #{level := Level, msg := {string, Text}}} ->
            drain_logs([{Level, lists:flatten(io_lib:format("~ts", [Text]))} | Acc]);
        {logged, _} ->
            drain_logs(Acc)
    after 0 ->
        lists:reverse(Acc)
    end.

log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {logged, Event},
    ok.
