%%%-------------------------------------------------------------------
%%% @doc The management-pin freshness watcher (M1(b), #5696).
%%%
%%% yuzu_gw_authz:check_mgmt_peer/1 runs once per management stream, inside
%%% the Cowboy connection process that decodes every stream of that connection.
%%% A `{cert_file, Path}' pin is the SPKI of the certificate at Path, which the
%%% C++ server may rotate at any time. Checking the file there, per stream,
%%% put a stat (through the node-wide file server) on the decode path: a stalled
%%% cert volume would stall the connection. This process takes the file system
%%% off that path. The stream check reads what it publishes and nothing else.
%%%
%%% What it does. Every `mgmt_pin_refresh_ms' (default 5000) it reads each
%%% `{cert_file, Path}' entry of `{yuzu_gw, mgmt_peer_pins}' with `raw' file
%%% operations (no file server), parses the PEM again only when the SHA-256 of
%%% its bytes changed (yuzu_gw_cert_files:step/2; the file's {mtime, size} is
%%% not trusted as a change token, see that module), and publishes the result
%%% to persistent_term: one put per actual change, none when nothing changed. The published term maps each Path to a yuzu_gw_cert_files entry:
%%%   obs    the latest observation of the file (parsed, not a certificate, or
%%%          unreadable)
%%%   good   what the last observation that parsed held: the SPKI SHA-256 of
%%%          the FIRST certificate of the PEM (the pin) and the earliest notAfter
%%% A path the configuration no longer names stays in the map (the pin list is
%%% fixed at boot; an edit needs a restart). lookup/1 is the stream check's only
%%% way in, and only a `good' SPKI is a pin.
%%%
%%% Last known good. Once a path has resolved, a later failure -- a stat or
%%% read error of any kind (enoent included), a file that is not a PEM
%%% certificate, a PEM cut off half-way -- KEEPS the key last read from it, and
%%% the source is reported unhealthy: healthy/1 is false, the pin watcher logs a
%%% WARNING once, and yuzu_gw_cert_file_readable{role="mgmt_peer_pin"} reads 0
%%% (alert YuzuGatewayMgmtPinUnresolved: fix the file). Without this, one
%%% failed read of the cert volume refused every management stream while
%%% /readyz stayed green. There is no time limit on the kept key.
%%%
%%% DELETING, BLANKING OR CORRUPTING THE PIN FILE DOES NOT REVOKE THE PINNED
%%% KEY: the gateway keeps admitting it. A key is revoked only by
%%%   - replacing the file with the new certificate: a file that IS read
%%%     successfully and holds a DIFFERENT key replaces the pin (rotation),
%%%     within one refresh interval; or
%%%   - removing the entry from mgmt_peer_pins and restarting the gateway. That
%%%     disconnects every agent on the node: released agents without the #5183
%%%     fix may not re-register after it, and their agent service must then be
%%%     restarted. Prefer replacing the file.
%%% Revocation that does not depend on a file at all is the identity design of
%%% #6016 (authorize the server by a CA-issued identity, not an SPKI pin).
%%%
%%% Fail closed. Last known good only ever keeps a key that WAS pinned; it never
%%% admits one that was not. A path that has never resolved (missing,
%%% unreadable or not a certificate since start, or not yet published)
%%% contributes no pin however many ticks pass; with no pin resolved the check
%%% refuses every peer (`no_pins_resolved'), the server's own key included
%%% (yuzu_gw_mgmt_pins_tests: never_resolved_refuses_every_peer,
%%% last_good_admits_only_the_pinned_key). This is the routed-concern rule
%%% "check_mgmt_peer/1 fails closed on empty or unresolvable pins": a pin that
%%% resolved once is not unresolvable. `{spki_sha256, Hex}' pins are resolved
%%% by the check itself and never involve this process.
%%%
%%% Rotation is picked up within one refresh interval. Between the server
%%% replacing its leaf and the next tick, the gateway still holds the OLD key:
%%% a management stream the server opens with the new leaf in that window is
%%% refused UNAUTHENTICATED (`pin_mismatch', fail closed). The server does NOT
%%% retry that refusal: it fails the command terminally (`gateway_unauthenticated',
%%% counted in yuzu_server_gateway_forward_total{status="unauthenticated"}), so
%%% commands forwarded in that window are dropped and show as terminal
%%% failures; commands after the tick go through. Every tick compares the
%%% file's bytes, so a new key is picked up even when the new PEM has the same
%%% size and mtime as the old one (a re-minted same-type key usually has the
%%% same DER length, and cp -p / rsync -a keep the mtime). A file whose
%%% {mtime, size} changed while it was being read is not cached: the previous
%%% value stands and the next tick reads it again.
%%%
%%% Rotation timestamp. When a path's pinned key changes from one key to a
%%% different one, this process emits [yuzu, gw, mgmt_pins, rotated] with the
%%% wall-clock second, after publishing the new pin; yuzu_gw_telemetry sets
%%% yuzu_gw_mgmt_pin_rotated_timestamp_seconds from it (0 until the first
%%% rotation). The first resolve at boot, a rewrite of the same key and a
%%% recovery with the same key are not rotations. The pin_mismatch alert uses
%%% it to stay quiet through the rotation window above.
%%%
%%% Certificate expiry. On the same tick (and in init/1) it refreshes
%%% yuzu_gw_cert_files' expiry gauges for every certificate file the gateway is
%%% configured with (listeners, upstream client, these pins); see that module.
%%% A failure in that refresh is logged and never stops the pin watcher.
%%%
%%% A stalled volume stalls this process only: the stream check keeps answering
%%% from the last published value, and the ticks resume when the volume does.
%%%
%%% Boot. init/1 resolves once, synchronously, before start_link returns. This
%%% process is a child of yuzu_gw_sup ahead of the listeners (its last
%%% children), so the first management stream finds the pin. A volume that is
%%% stalled at boot therefore stalls boot here -- as it would the listeners,
%%% which read their own certificates from it. The process can restart without
%%% a gap: the published term outlives it.
%%%
%%% It also creates the per-reason log-limit stamps of yuzu_gw_authz's
%%% rejection line (yuzu_gw_authz:init_log_limits/0), for the same reason the
%%% application creates the other limits before the listeners start.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_pins).
-behaviour(gen_server).

-export([start_link/0, lookup/1, healthy/1, source/1, refresh/0, refresh/1]).
-export([refresh_ms/0, validate_refresh_ms/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(KEY, {?MODULE, resolved}).
-define(DEFAULT_REFRESH_MS, 5000).
-define(MIN_REFRESH_MS, 100).
-define(MAX_REFRESH_MS, 3600000).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

-spec start_link() -> {ok, pid()} | ignore | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc The published SPKI SHA-256 of the certificate at Path, or `error' when
%% it is not (yet) known: never published, unreadable, or not a certificate.
%% A persistent_term read; no file I/O, no call into this process.
-spec lookup(file:name_all()) -> {ok, binary()} | error.
lookup(Path) ->
    case persistent_term:get(?KEY, #{}) of
        #{Path := #{good := #{spki := Hash}}} -> {ok, Hash};
        _ -> error
    end.

%% @doc True when the latest observation of the pin file at Path parsed as a
%% certificate. False when it failed (the last good key, if any, is still
%% pinned) or when Path was never published. A persistent_term read.
-spec healthy(file:name_all()) -> boolean().
healthy(Path) ->
    yuzu_gw_cert_files:healthy(source(Path)).

%% @doc What was published for the pin file at Path, or `none'. A
%% persistent_term read; yuzu_gw_cert_files reports the mgmt_peer_pin role
%% from it.
-spec source(file:name_all()) -> yuzu_gw_cert_files:entry() | none.
source(Path) ->
    maps:get(Path, persistent_term:get(?KEY, #{}), none).

%% @doc Refresh the configured pins in the calling process.
-spec refresh() -> ok.
refresh() ->
    refresh(application:get_env(yuzu_gw, mgmt_peer_pins, [])).

%% @doc Read every `{cert_file, Path}' entry of Pins, parse the ones whose
%% bytes changed, and publish the result if anything changed; emit the
%% rotation event if a pinned key changed. Runs in the calling process (this
%% server, or a test). A malformed pin list publishes nothing for it (the boot
%% guard refuses it before the listeners start; the stream check rejects it as
%% `bad_pin_config').
-spec refresh(term()) -> ok.
refresh(Pins) ->
    Old = persistent_term:get(?KEY, #{}),
    New = lists:foldl(
            fun(Path, Acc) ->
                    Acc#{Path => yuzu_gw_cert_files:step(Path, maps:get(Path, Old, none))}
            end, Old, cert_file_paths(Pins)),
    case New =:= Old of
        true -> ok;
        false ->
            report_changes(Old, New),
            persistent_term:put(?KEY, New),
            case rotated(Old, New) of
                true ->
                    telemetry:execute([yuzu, gw, mgmt_pins, rotated],
                                      #{system_time => os:system_time(second)}, #{});
                false ->
                    ok
            end
    end,
    ok.

%% @doc The refresh interval in milliseconds: `mgmt_pin_refresh_ms', or the
%% default when it is unset. A value the boot guard would refuse reads as the
%% default (the guard has refused it before this process starts).
-spec refresh_ms() -> pos_integer().
refresh_ms() ->
    case application:get_env(yuzu_gw, mgmt_pin_refresh_ms) of
        {ok, Ms} ->
            case validate_refresh_ms(Ms) of
                ok -> Ms;
                {error, _} -> ?DEFAULT_REFRESH_MS
            end;
        undefined ->
            ?DEFAULT_REFRESH_MS
    end.

%% @doc `ok' for an unset value or an integer from 100 to 3600000 (ms).
-spec validate_refresh_ms(term()) -> ok | {error, term()}.
validate_refresh_ms(undefined) ->
    ok;
validate_refresh_ms(Ms) when is_integer(Ms), Ms >= ?MIN_REFRESH_MS, Ms =< ?MAX_REFRESH_MS ->
    ok;
validate_refresh_ms(Ms) ->
    {error, {mgmt_pin_refresh_ms, Ms,
             {expected_integer_ms_between, ?MIN_REFRESH_MS, ?MAX_REFRESH_MS}}}.

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------

init([]) ->
    ok = yuzu_gw_authz:init_log_limits(),
    Interval = refresh_ms(),
    %% Synchronous on purpose: the listeners start after this returns.
    ok = refresh(),
    Certs = refresh_certs(yuzu_gw_cert_files:new()),
    schedule(Interval),
    {ok, #{interval => Interval, certs => Certs}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(refresh, #{interval := Interval, certs := Certs} = State) ->
    ok = refresh(),
    schedule(Interval),
    {noreply, State#{certs := refresh_certs(Certs)}};
handle_info(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

schedule(Interval) ->
    erlang:send_after(Interval, self(), refresh),
    ok.

%% The distinct paths of the `{cert_file, Path}' entries; [] for anything that
%% is not a proper list.
-spec cert_file_paths(term()) -> [file:name_all()].
cert_file_paths(Pins) when is_list(Pins) ->
    try lists:usort([P || {cert_file, P} <- Pins, is_list(P) orelse is_binary(P)])
    catch error:_ -> []
    end;
cert_file_paths(_) ->
    [].

%% The expiry gauges are observability: a defect in them must never stop the
%% pin watcher (a crash here would restart it every tick and could take the
%% supervisor down), so a failure is logged and the previous state kept.
refresh_certs(Certs) ->
    try
        yuzu_gw_cert_files:refresh(yuzu_gw_cert_files:sources(), Certs)
    catch
        Class:Reason ->
            logger:warning("certificate expiry refresh failed: ~p:~0P; the expiry "
                           "gauges keep their last values", [Class, Reason, 10]),
            Certs
    end.

%% True when some path's pinned key changed from one key to a different one.
%% Gaining a first key (boot) or keeping the same key is not a rotation.
rotated(Old, New) ->
    lists:any(fun({Path, Entry}) ->
                      case {pinned(maps:get(Path, Old, none)), pinned(Entry)} of
                          {H1, H2} when is_binary(H1), is_binary(H2) -> H1 =/= H2;
                          _ -> false
                      end
              end, maps:to_list(New)).

pinned(#{good := #{spki := H}}) -> H;
pinned(_) -> none.

%% One line per path whose state changed: the operator-visible record of a
%% rotation being picked up, of a pin file becoming unusable (and whether a
%% key is still pinned from it), and of its recovery. The path is
%% configuration, never certificate contents.
report_changes(Old, New) ->
    maps:foreach(
      fun(Path, Entry) ->
              report(Path, state(maps:get(Path, Old, none)), state(Entry))
      end, New).

report(_Path, Same, Same) ->
    ok;
report(Path, {_, H1}, {true, H2}) when is_binary(H1), H1 =/= H2 ->
    logger:notice("mgmt_peer_pins: the certificate at ~0tp changed; the new key is pinned",
                  [Path]);
report(Path, {false, H}, {true, H}) when is_binary(H) ->
    logger:info("mgmt_peer_pins: the certificate at ~0tp is readable again; the pinned "
                "key is unchanged", [Path]);
report(Path, _, {true, _}) ->
    logger:info("mgmt_peer_pins: pinned the certificate at ~0tp", [Path]);
report(Path, _, {false, H}) when is_binary(H) ->
    logger:warning("mgmt_peer_pins: the certificate at ~0tp cannot be read or is not a "
                   "PEM certificate; the key last read from it stays pinned and is still "
                   "admitted (deleting or damaging the file does not revoke it). Fix the "
                   "file before the server rotates; to change or revoke the pin, replace "
                   "the file with the new certificate", [Path]);
report(Path, _, {false, none}) ->
    logger:warning("mgmt_peer_pins: the certificate at ~0tp cannot be read or is not a "
                   "PEM certificate; it pins nothing until it is fixed (fail closed)",
                   [Path]).

%% `none' (never resolved) differs from {false, none} (tried and failed), so a
%% pin file that is already unusable at boot is reported too.
state(none) -> none;
state(Entry) -> {yuzu_gw_cert_files:healthy(Entry), pinned(Entry)}.
