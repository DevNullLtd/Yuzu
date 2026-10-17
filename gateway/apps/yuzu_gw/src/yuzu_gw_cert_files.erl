%%%-------------------------------------------------------------------
%%% @doc The certificate files the gateway is configured with: how they are
%%% read, and the expiry gauges published for them.
%%%
%%% Reading a file (step/2). A file is stat'ed with `raw' file operations (no
%%% file server) and re-read and parsed only when its {mtime, size} changed. A
%%% file replaced while it was being read is not cached: the previous
%%% observation stands and the file is tried again on the next call. What is
%%% kept per path is an entry:
%%%   obs    the latest observation: {Token, {ok, Info}} (the file parsed),
%%%          {Token, error} (read at Token, not a PEM certificate, or one whose
%%%          notAfter this reader cannot parse; not re-read until the token
%%%          changes), or `unreadable' (the stat or the read failed; tried
%%%          again next time)
%%%   good   the Info of the last observation that parsed, or `none'. It is
%%%          KEPT when a later observation fails: a cert volume that hiccups,
%%%          or a writer caught half-way, does not erase what was last read.
%%% Info is #{spki => SHA-256 of the FIRST certificate's SubjectPublicKeyInfo,
%%% not_after => the EARLIEST notAfter of all certificates in the file, in Unix
%%% seconds}. yuzu_gw_mgmt_pins uses step/2 for the management pins, and this
%%% module for every other configured certificate file, so both read a file
%%% the same way.
%%%
%%% Expiry gauges (refresh/2, run on yuzu_gw_mgmt_pins' tick). For every
%%% certificate file in the configuration (sources/0), grouped by role and
%%% name:
%%%   role=listener         a grpc_listeners entry's tls.certfile  (name = listener name)
%%%   role=listener_ca      the same entry's tls.cacertfile
%%%   role=upstream_client  an upstream_client channel's certfile  (name = channel name)
%%%   role=upstream_ca      the same channel's cacertfile
%%%   role=mgmt_peer_pin    a mgmt_peer_pins {cert_file, Path}     (name = basename)
%%% it emits [yuzu, gw, cert_file, state] when what it would report changes:
%%% `readable' (1 when every file of the group parsed on its latest
%%% observation, else 0) and, when known, `not_after' (the earliest notAfter of
%%% the group's last good reads). yuzu_gw_telemetry turns that into
%%% yuzu_gw_cert_file_readable{role,name} and
%%% yuzu_gw_cert_expiry_timestamp_seconds{role,name}.
%%%
%%% An unreadable file. The readable gauge drops to 0 and the expiry gauge
%%% keeps the notAfter of the certificate last read from that file: an expiring
%%% certificate stays loud, and the 0 says the value is no longer confirmed
%%% (YuzuGatewayCertificateFileUnreadable / YuzuGatewayMgmtPinUnresolved alert
%%% on it). A file that has never been read has no expiry series at all.
%%%
%%% The mgmt_peer_pin role is reported from what yuzu_gw_mgmt_pins published
%%% (yuzu_gw_mgmt_pins:source/1), never read a second time here, so the gauge
%%% cannot disagree with the pin the stream check uses.
%%%
%%% Inline `cert'/`cacerts' DER options are not files and are not reported.
%%% Labels carry configuration names only, never certificate contents.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_cert_files).

-include_lib("kernel/include/file.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([step/2, healthy/1, parse_pem/1, time_to_unix/1]).
-export([new/0, sources/0, sources/3, refresh/2]).
-export_type([entry/0, info/0, state/0, source/0]).

-define(MAX_LABEL_BYTES, 64).
%% Seconds from 0000-01-01 (calendar's gregorian seconds) to 1970-01-01.
-define(UNIX_EPOCH_GREGORIAN, 62167219200).

-type token() :: {integer(), non_neg_integer()}.
-type info() :: #{spki := binary(), not_after := integer()}.
-type obs() :: {token(), {ok, info()} | error} | unreadable.
-type entry() :: #{obs := obs(), good := info() | none}.
-type source() :: {Role :: binary(), Name :: binary(), file:name_all()}.
-type group_state() :: {0 | 1, integer() | none}.
-opaque state() :: #{files := #{file:name_all() => entry()},
                     emitted := #{{binary(), binary()} => group_state()}}.

%%--------------------------------------------------------------------
%% Reading one file
%%--------------------------------------------------------------------

%% @doc The new entry of Path given its previous one (`none' the first time).
-spec step(file:name_all(), entry() | none) -> entry().
step(Path, none) ->
    next(observe(Path, none), none);
step(Path, #{obs := PrevObs, good := PrevGood}) ->
    next(observe(Path, PrevObs), PrevGood).

next({_, {ok, Info}} = Obs, _PrevGood) -> #{obs => Obs, good => Info};
next(Obs, PrevGood) -> #{obs => Obs, good => PrevGood}.

%% @doc True when the latest observation of the entry parsed.
-spec healthy(entry() | none) -> boolean().
healthy(#{obs := {_, {ok, _}}}) -> true;
healthy(_) -> false.

-spec observe(file:name_all(), obs() | none) -> obs().
observe(Path, PrevObs) ->
    case stat(Path) of
        error ->
            unreadable;
        Token ->
            case PrevObs of
                {Token, _} -> PrevObs;
                _ -> read(Path, Token, PrevObs)
            end
    end.

%% The token is taken again after the read: a file replaced while it was being
%% read is not cached, the previous observation stands (or `unreadable' when
%% there is none) and the file is read again next time, as its token differs.
read(Path, Token, PrevObs) ->
    case file:read_file(Path, [raw]) of
        {ok, Pem} ->
            case stat(Path) of
                Token -> {Token, parse_pem(Pem)};
                _ when PrevObs =:= none -> unreadable;
                _ -> PrevObs
            end;
        {error, _} ->
            unreadable
    end.

-spec stat(file:name_all()) -> token() | error.
stat(Path) ->
    case file:read_file_info(Path, [raw, {time, posix}]) of
        {ok, #file_info{mtime = M, size = S}} -> {M, S};
        {error, _} -> error
    end.

%% @doc The SPKI SHA-256 of the first certificate of a PEM and the earliest
%% notAfter of all of them, or `error': no certificate, a certificate that does
%% not decode, or a notAfter this reader cannot parse. Total.
-spec parse_pem(binary()) -> {ok, info()} | error.
parse_pem(Pem) ->
    try [D || {'Certificate', D, not_encrypted} <- public_key:pem_decode(Pem)] of
        [First | _] = Ders ->
            case {yuzu_gw_authz:spki_sha256(First), earliest_not_after(Ders)} of
                {{ok, Spki}, {ok, NotAfter}} -> {ok, #{spki => Spki, not_after => NotAfter}};
                _ -> error
            end;
        [] ->
            error
    catch _:_ ->
        error
    end.

earliest_not_after(Ders) ->
    Times = [not_after(D) || D <- Ders],
    case [T || {ok, T} <- Times] of
        Ok when length(Ok) =:= length(Times) -> {ok, lists:min(Ok)};
        _ -> error
    end.

not_after(Der) ->
    try public_key:pkix_decode_cert(Der, otp) of
        #'OTPCertificate'{tbsCertificate =
            #'OTPTBSCertificate'{validity = #'Validity'{notAfter = NotAfter}}} ->
            time_to_unix(NotAfter);
        _ ->
            error
    catch _:_ ->
        error
    end.

%% @doc An X.509 Time in Unix seconds. UTCTime is YYMMDDHHMMSSZ with a year
%% of 50 to 99 meaning 19YY and 00 to 49 meaning 20YY; GeneralizedTime is
%% YYYYMMDDHHMMSSZ (RFC 5280 4.1.2.5). Anything else, fractional seconds
%% included (5280 forbids them), is `error'.
-spec time_to_unix(term()) -> {ok, integer()} | error.
time_to_unix({utcTime, [Y1, Y2 | Rest]}) when length(Rest) =:= 11 ->
    case digits([Y1, Y2]) of
        {ok, YY} when YY >= 50 -> datetime(1900 + YY, Rest);
        {ok, YY} -> datetime(2000 + YY, Rest);
        error -> error
    end;
time_to_unix({generalTime, [Y1, Y2, Y3, Y4 | Rest]}) when length(Rest) =:= 11 ->
    case digits([Y1, Y2, Y3, Y4]) of
        {ok, Y} -> datetime(Y, Rest);
        error -> error
    end;
time_to_unix(_) ->
    error.

%% MMDDHHMMSSZ
datetime(Year, [Mo1, Mo2, D1, D2, H1, H2, Mi1, Mi2, S1, S2, $Z]) ->
    case [digits(P) || P <- [[Mo1, Mo2], [D1, D2], [H1, H2], [Mi1, Mi2], [S1, S2]]] of
        [{ok, Mo}, {ok, D}, {ok, H}, {ok, Mi}, {ok, S}] ->
            case calendar:valid_date(Year, Mo, D) andalso H < 24 andalso Mi < 60 andalso S < 60 of
                true ->
                    {ok, calendar:datetime_to_gregorian_seconds({{Year, Mo, D}, {H, Mi, S}})
                         - ?UNIX_EPOCH_GREGORIAN};
                false ->
                    error
            end;
        _ ->
            error
    end;
datetime(_, _) ->
    error.

digits(Cs) ->
    case lists:all(fun(C) -> is_integer(C) andalso C >= $0 andalso C =< $9 end, Cs) of
        true -> {ok, list_to_integer(Cs)};
        false -> error
    end.

%%--------------------------------------------------------------------
%% Which files
%%--------------------------------------------------------------------

%% @doc Every certificate file in the configuration, as {Role, Name, Path}.
-spec sources() -> [source()].
sources() ->
    sources(application:get_env(yuzu_gw, grpc_listeners, []),
            application:get_env(yuzu_gw, upstream_client, undefined),
            application:get_env(yuzu_gw, mgmt_peer_pins, [])).

%% @doc sources/0 over given values of grpc_listeners, upstream_client and
%% mgmt_peer_pins. Anything not of the expected shape contributes nothing (the
%% boot guards refuse such a configuration before this runs). Each
%% {Role, Name, Path} appears once.
-spec sources(term(), term(), term()) -> [source()].
sources(Listeners, Upstream, Pins) ->
    lists:usort(listener_sources(Listeners) ++ upstream_sources(Upstream)
                ++ pin_sources(Pins)).

listener_sources(Listeners) when is_list(Listeners) ->
    lists:append([listener_source(L) || L <- proper(Listeners)]);
listener_sources(_) ->
    [].

listener_source(#{tls := Tls} = L) when is_map(Tls) ->
    Name = label(maps:get(name, L, undefined)),
    [{<<"listener">>, Name, P} || P <- [maps:get(certfile, Tls, undefined)], is_path(P)]
        ++ [{<<"listener_ca">>, Name, P} || P <- [maps:get(cacertfile, Tls, undefined)], is_path(P)];
listener_source(_) ->
    [].

upstream_sources(#{channels := Channels}) when is_list(Channels) ->
    lists:append([channel_sources(C) || C <- proper(Channels)]);
upstream_sources(_) ->
    [].

channel_sources({Name, Endpoints, _Options}) when is_list(Endpoints) ->
    N = label(Name),
    lists:append([endpoint_sources(N, E) || E <- proper(Endpoints)]);
channel_sources(_) ->
    [].

endpoint_sources(Name, {_Scheme, _Host, _Port, SslOpts}) ->
    ssl_sources(Name, SslOpts);
endpoint_sources(Name, {_Scheme, _Host, _Port, SslOpts, _Extra}) ->
    ssl_sources(Name, SslOpts);
endpoint_sources(_, _) ->
    [].

ssl_sources(Name, SslOpts) when is_list(SslOpts) ->
    Opts = proper(SslOpts),
    [{<<"upstream_client">>, Name, P} || {certfile, P} <- Opts, is_path(P)]
        ++ [{<<"upstream_ca">>, Name, P} || {cacertfile, P} <- Opts, is_path(P)];
ssl_sources(_, _) ->
    [].

pin_sources(Pins) when is_list(Pins) ->
    [{<<"mgmt_peer_pin">>, label(filename:basename(P)), P}
     || {cert_file, P} <- proper(Pins), is_path(P)];
pin_sources(_) ->
    [].

is_path(P) -> (is_list(P) andalso P =/= [] andalso io_lib:printable_unicode_list(P))
              orelse (is_binary(P) andalso P =/= <<>>).

%% The proper prefix of a list; [] for anything else.
proper(L) -> proper(L, []).
proper([H | T], Acc) -> proper(T, [H | Acc]);
proper(_, Acc) -> lists:reverse(Acc).

%% A configuration name as label text, at most ?MAX_LABEL_BYTES bytes.
label(A) when is_atom(A) -> clip(atom_to_binary(A, utf8));
label(B) when is_binary(B) -> clip(B);
label(L) when is_list(L) ->
    case io_lib:printable_unicode_list(L) of
        true -> clip(unicode:characters_to_binary(L));
        false -> clip(iolist_to_binary(io_lib:format("~0tp", [L])))
    end;
label(T) ->
    clip(iolist_to_binary(io_lib:format("~0tp", [T]))).

clip(B) when byte_size(B) =< ?MAX_LABEL_BYTES -> B;
clip(B) -> binary:part(B, 0, ?MAX_LABEL_BYTES).

%%--------------------------------------------------------------------
%% Expiry gauges
%%--------------------------------------------------------------------

%% @doc The state before the first refresh: nothing read, nothing reported.
-spec new() -> state().
new() ->
    #{files => #{}, emitted => #{}}.

%% @doc Observe every source and emit [yuzu, gw, cert_file, state] for each
%% role/name whose readable flag or notAfter changed since the last refresh
%% (every role/name the first time). Files of the mgmt_peer_pin role are
%% taken from yuzu_gw_mgmt_pins' published state, without I/O.
-spec refresh([source()], state()) -> state().
refresh(Sources, #{files := Files0, emitted := Emitted0}) ->
    Paths = lists:usort([P || {R, _, P} <- Sources, R =/= <<"mgmt_peer_pin">>]),
    Files = maps:from_list([{P, step(P, maps:get(P, Files0, none))} || P <- Paths]),
    Entry = fun(<<"mgmt_peer_pin">>, P) -> yuzu_gw_mgmt_pins:source(P);
               (_, P) -> maps:get(P, Files)
            end,
    Groups = maps:groups_from_list(fun({R, N, _}) -> {R, N} end,
                                   fun({R, _, P}) -> Entry(R, P) end, Sources),
    Emitted = maps:map(fun(_, Entries) -> group_state(Entries) end, Groups),
    maps:foreach(
      fun({Role, Name} = Key, {Readable, NotAfter} = St) ->
              case maps:find(Key, Emitted0) of
                  {ok, St} ->
                      ok;
                  _ ->
                      M = case NotAfter of
                              none -> #{readable => Readable};
                              _ -> #{readable => Readable, not_after => NotAfter}
                          end,
                      telemetry:execute([yuzu, gw, cert_file, state], M,
                                        #{role => Role, name => Name})
              end
      end, Emitted),
    #{files => Files, emitted => Emitted}.

-spec group_state([entry() | none]) -> group_state().
group_state(Entries) ->
    Readable = case lists:all(fun healthy/1, Entries) of
                   true -> 1;
                   false -> 0
               end,
    NotAfter = case [T || #{good := #{not_after := T}} <- Entries] of
                   [] -> none;
                   Ts -> lists:min(Ts)
               end,
    {Readable, NotAfter}.
