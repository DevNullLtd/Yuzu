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
%%% What it does. Every `mgmt_pin_refresh_ms' (default 5000) it stats each
%%% `{cert_file, Path}' entry of `{yuzu_gw, mgmt_peer_pins}' with `raw' file
%%% operations (no file server), re-reads and parses the PEM only when the
%%% file's {mtime, size} changed, and publishes the result to persistent_term:
%%% one put per actual change, none when nothing changed. The published term is
%%% a map from each Path to its state:
%%%   {Token, {ok, SpkiSha256}}   the first certificate of the PEM, read at Token
%%%   {Token, error}              the file at Token is not a PEM certificate;
%%%                               not re-read until its {mtime, size} changes
%%%   unreadable                  the stat or the read failed; tried again on
%%%                               the next tick
%%% A path the configuration no longer names stays in the map (the pin list is
%%% fixed at boot; an edit needs a restart). lookup/1 is the stream check's only
%%% way in, and only `{ok, _}' is a pin.
%%%
%%% Fail closed. A missing, unreadable, unparsable or not-yet-published file
%%% contributes no pin; with no pin resolved the check refuses
%%% (`no_pins_resolved'). `{spki_sha256, Hex}' pins are resolved by the check
%%% itself and never involve this process.
%%%
%%% Rotation is picked up within one refresh interval. Between the server
%%% replacing its leaf and the next tick, the gateway still holds the OLD key:
%%% a connection made with the new leaf in that window is refused
%%% UNAUTHENTICATED (fail closed), and the same connection succeeds on retry
%%% once the tick has run. Granularity: a same-second, same-size rewrite keeps
%%% its token and is not re-read (a re-minted same-type key usually has the
%%% same DER length); the token is also compared after the read, so a file
%%% replaced while it was being read is not cached. The miss direction is
%%% fail-closed and a gateway restart recovers.
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

-include_lib("kernel/include/file.hrl").

-export([start_link/0, lookup/1, refresh/0, refresh/1]).
-export([refresh_ms/0, validate_refresh_ms/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(SERVER, ?MODULE).
-define(KEY, {?MODULE, resolved}).
-define(DEFAULT_REFRESH_MS, 5000).
-define(MIN_REFRESH_MS, 100).
-define(MAX_REFRESH_MS, 3600000).

-type token() :: {integer(), non_neg_integer()}.
-type entry() :: {token(), {ok, binary()} | error} | unreadable.

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
        #{Path := {_Token, {ok, Hash}}} -> {ok, Hash};
        _ -> error
    end.

%% @doc Refresh the configured pins in the calling process.
-spec refresh() -> ok.
refresh() ->
    refresh(application:get_env(yuzu_gw, mgmt_peer_pins, [])).

%% @doc Stat every `{cert_file, Path}' entry of Pins, re-read the ones whose
%% {mtime, size} changed, and publish the result if anything changed. Runs in
%% the calling process (this server, or a test). A malformed pin list
%% publishes nothing for it (the boot guard refuses it before the listeners
%% start; the stream check rejects it as `bad_pin_config').
-spec refresh(term()) -> ok.
refresh(Pins) ->
    Old = persistent_term:get(?KEY, #{}),
    New = lists:foldl(fun(Path, Acc) -> Acc#{Path => resolve(Path, maps:get(Path, Old, none))} end,
                      Old, cert_file_paths(Pins)),
    case New =:= Old of
        true -> ok;
        false ->
            report_changes(Old, New),
            persistent_term:put(?KEY, New)
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
    schedule(Interval),
    {ok, #{interval => Interval}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(refresh, #{interval := Interval} = State) ->
    ok = refresh(),
    schedule(Interval),
    {noreply, State};
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

%% The new state of one path, given its previous one.
-spec resolve(file:name_all(), entry() | none) -> entry().
resolve(Path, Previous) ->
    case stat(Path) of
        error ->
            unreadable;
        Token ->
            case Previous of
                {Token, _} = Unchanged ->
                    Unchanged;
                _ ->
                    read(Path, Token)
            end
    end.

%% Read and parse the file stat'ed at Token. The token is taken again after the
%% read: a file replaced while it was being read is not cached (it is tried
%% again on the next tick).
read(Path, Token) ->
    case file:read_file(Path, [raw]) of
        {ok, Pem} ->
            case stat(Path) of
                Token -> {Token, spki_of(Pem)};
                _ -> unreadable
            end;
        {error, _} ->
            unreadable
    end.

spki_of(Pem) ->
    try [D || {'Certificate', D, not_encrypted} <- public_key:pem_decode(Pem)] of
        [Der | _] ->
            case yuzu_gw_authz:spki_sha256(Der) of
                {ok, Hash} -> {ok, Hash};
                error -> error
            end;
        [] ->
            error
    catch _:_ ->
        error
    end.

-spec stat(file:name_all()) -> token() | error.
stat(Path) ->
    case file:read_file_info(Path, [raw, {time, posix}]) of
        {ok, #file_info{mtime = M, size = S}} -> {M, S};
        {error, _} -> error
    end.

%% One line per path whose resolution changed: the operator-visible record of
%% a rotation being picked up, or of a pin file becoming unusable. The path is
%% configuration, never certificate contents.
report_changes(Old, New) ->
    maps:foreach(
      fun(Path, Entry) ->
              case {usable(maps:get(Path, Old, none)), usable(Entry)} of
                  {Same, Same} ->
                      ok;
                  {{ok, _}, {ok, _}} ->
                      logger:notice("mgmt_peer_pins: the certificate at ~0tp changed; "
                                    "the new key is pinned", [Path]);
                  {_, {ok, _}} ->
                      logger:info("mgmt_peer_pins: pinned the certificate at ~0tp", [Path]);
                  {_, error} ->
                      logger:warning("mgmt_peer_pins: the certificate at ~0tp cannot be "
                                     "read or is not a PEM certificate; it pins nothing "
                                     "until it is fixed (fail closed)", [Path])
              end
      end, New).

%% `none' (never resolved) differs from `error', so a pin file that is already
%% unusable at boot is reported too.
usable(none) -> none;
usable({_Token, {ok, Hash}}) -> {ok, Hash};
usable(_) -> error.
