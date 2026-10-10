%%%-------------------------------------------------------------------
%%% @doc Which address a call is attributed to. Pure: no process, no socket.
%%%
%%% A gateway that sits behind a load balancer or a router sees the balancer as
%%% its TCP peer. The address of the agent behind it arrives as a claim: in a
%%% PROXY protocol header (an F5 iRule, HAProxy `send-proxy-v2') or in an
%%% `x-forwarded-for' header (a router that terminates TLS). A claim is only
%%% believable when it comes from the proxy, so the decision is made by WHO
%%% CONNECTED, never by whether the claim matches the connection:
%%%
%%%   transport       the default. The TCP peer, and nothing else. Any claim a
%%%                   client sends is ignored.
%%%   proxy_protocol  the PROXY header counts when the TCP peer is one of
%%%                   `sources'. Cowboy reads the header before the TLS
%%%                   handshake, so it works with TLS passthrough and the
%%%                   client certificate still reaches the gateway.
%%%   forwarded_for   `x-forwarded-for' counts when the TCP peer is one of
%%%                   `sources': the entry `trusted_hops' places from the right
%%%                   (0: the last one, the one the nearest proxy appended).
%%%                   Entries further left were written by the client or by
%%%                   proxies we were not told about and are never used.
%%%
%%% A claim from anywhere else is IGNORED, not refused: behind NAT or a
%%% balancer the claim and the TCP peer legitimately differ, and refusing the
%%% call would turn a configuration slip into an outage. Ignoring it is safe
%%% because the answer then is the TCP peer, which is what a client that sent a
%%% claim directly really is. The note returned beside the address says what
%%% happened, so the caller can count it (never log the address).
%%%
%%% Sources are the addresses of the proxies as the gateway's socket sees them:
%%% an IP, or `{Ip, PrefixLength}' for a network. They are a defence in depth
%%% for a listener that is also reachable only from the proxy (a firewall rule,
%%% a NetworkPolicy); neither replaces the other.
%%%
%%% An address is returned without a port: it is attribution, and a proxy's
%%% view of the source port means nothing here. IPv4-mapped IPv6 addresses are
%%% folded to IPv4 so a dual-stack listener and an IPv4 source list agree.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_origin).

-export([validate/1, resolve/4, format/1, in_sources/2]).

-export_type([config/0, source/0, origin/0, note/0]).

%% Longest x-forwarded-for value and most entries looked at. A header past
%% either is a claim we do not interpret.
-define(MAX_XFF_BYTES, 1024).
-define(MAX_XFF_ENTRIES, 32).

-type source() :: inet:ip_address() | {inet:ip_address(), non_neg_integer()}.
-type config() :: #{mode := transport}
                | #{mode := proxy_protocol, sources := [source()]}
                | #{mode := forwarded_for, sources := [source()],
                    trusted_hops => non_neg_integer()}.
-type origin() :: {inet:ip_address(), transport | proxy_protocol | forwarded_for}.
%% ok: the claim was used (or none was expected). untrusted_source: the TCP
%% peer is not a configured proxy, so any claim was ignored. no_claim: a trusted
%% proxy sent nothing usable (a PROXY `LOCAL' health check, no header).
%% bad_claim: a trusted proxy sent something that is not an address.
-type note() :: ok | untrusted_source | no_claim | bad_claim.

%%--------------------------------------------------------------------
%% Validation (listener start)
%%--------------------------------------------------------------------

%% @doc Whether an `origin' option is well formed. A proxy mode must name at
%% least one source: a proxied listener that trusts nobody is a typo.
-spec validate(term()) -> ok | {error, term()}.
validate(#{mode := transport} = Config) ->
    case maps:keys(Config) -- [mode] of
        [] -> ok;
        Extra -> {error, {origin_transport_takes_no_options, Extra}}
    end;
validate(#{mode := proxy_protocol} = Config) ->
    check_keys(Config, [mode, sources]);
validate(#{mode := forwarded_for} = Config) ->
    case check_keys(Config, [mode, sources, trusted_hops]) of
        ok ->
            case maps:get(trusted_hops, Config, 0) of
                Hops when is_integer(Hops), Hops >= 0, Hops < ?MAX_XFF_ENTRIES -> ok;
                _ -> {error, bad_trusted_hops}
            end;
        {error, _} = Error ->
            Error
    end;
validate(#{mode := Mode}) ->
    {error, {unknown_origin_mode, Mode}};
validate(_) ->
    {error, bad_origin}.

check_keys(Config, Allowed) ->
    case maps:keys(Config) -- Allowed of
        [] -> check_sources(maps:get(sources, Config, undefined));
        Extra -> {error, {unknown_origin_options, Extra}}
    end.

check_sources([_ | _] = Sources) ->
    case [S || S <- Sources, not valid_source(S)] of
        [] -> ok;
        Bad -> {error, {bad_origin_sources, Bad}}
    end;
check_sources(_) ->
    {error, origin_sources_required}.

valid_source({Ip, Prefix}) when is_integer(Prefix), Prefix >= 1 ->
    case is_ip(Ip) of
        {true, Bits} -> Prefix =< Bits;
        false -> false
    end;
valid_source({_, _}) ->
    false;
valid_source(Ip) ->
    is_ip(Ip) =/= false.

%% A /0 network would trust every address, which is the absence of a source
%% list, so it is not accepted (valid_source/1 requires Prefix >= 1).
is_ip({A, B, C, D}) ->
    case lists:all(fun(X) -> is_integer(X) andalso X >= 0 andalso X =< 255 end,
                   [A, B, C, D]) of
        true -> {true, 32};
        false -> false
    end;
is_ip({A, B, C, D, E, F, G, H}) ->
    case lists:all(fun(X) -> is_integer(X) andalso X >= 0 andalso X =< 65535 end,
                   [A, B, C, D, E, F, G, H]) of
        true -> {true, 128};
        false -> false
    end;
is_ip(_) ->
    false.

%%--------------------------------------------------------------------
%% Resolution (per call)
%%--------------------------------------------------------------------

%% @doc The address a call is attributed to. `Peer' is the TCP peer, `Proxy' the
%% PROXY protocol information Cowboy read (undefined when the listener does not
%% read one), `Headers' the request headers with lower-case names.
-spec resolve(config(), inet:ip_address(), map() | undefined, #{binary() => binary()}) ->
    {origin(), note()}.
resolve(#{mode := transport}, Peer, _Proxy, _Headers) ->
    {{fold(Peer), transport}, ok};
resolve(#{mode := proxy_protocol, sources := Sources}, Peer, Proxy, _Headers) ->
    case in_sources(Peer, Sources) of
        false -> {{fold(Peer), transport}, untrusted_source};
        true -> from_proxy_header(Peer, Proxy)
    end;
resolve(#{mode := forwarded_for, sources := Sources} = Config, Peer, _Proxy, Headers) ->
    case in_sources(Peer, Sources) of
        false -> {{fold(Peer), transport}, untrusted_source};
        true -> from_forwarded_for(Peer, maps:get(trusted_hops, Config, 0),
                                   maps:get(<<"x-forwarded-for">>, Headers, undefined))
    end.

from_proxy_header(Peer, #{command := proxy, src_address := Src})
  when is_tuple(Src) ->
    case is_ip(Src) of
        {true, _} -> {{fold(Src), proxy_protocol}, ok};
        false -> {{fold(Peer), transport}, bad_claim}
    end;
from_proxy_header(Peer, #{command := proxy}) ->
    %% A family with no address (UNSPEC, a unix socket): not an IP to attribute.
    {{fold(Peer), transport}, bad_claim};
from_proxy_header(Peer, _LocalOrAbsent) ->
    %% PROXY `LOCAL' is the proxy's own health check: no client behind it.
    {{fold(Peer), transport}, no_claim}.

from_forwarded_for(Peer, _Hops, undefined) ->
    {{fold(Peer), transport}, no_claim};
from_forwarded_for(Peer, _Hops, Value) when byte_size(Value) > ?MAX_XFF_BYTES ->
    {{fold(Peer), transport}, bad_claim};
from_forwarded_for(Peer, Hops, Value) ->
    Entries = [string:trim(E) || E <- binary:split(Value, <<",">>, [global])],
    Count = length(Entries),
    case Count =< ?MAX_XFF_ENTRIES andalso Hops < Count of
        false ->
            {{fold(Peer), transport}, bad_claim};
        true ->
            Entry = lists:nth(Count - Hops, Entries),
            case inet:parse_strict_address(binary_to_list(Entry)) of
                {ok, Ip} -> {{fold(Ip), forwarded_for}, ok};
                {error, _} -> {{fold(Peer), transport}, bad_claim}
            end
    end.

%%--------------------------------------------------------------------
%% Addresses
%%--------------------------------------------------------------------

%% @doc Whether an address is one of the sources (an IP, or inside a network).
-spec in_sources(inet:ip_address(), [source()]) -> boolean().
in_sources(Ip0, Sources) ->
    Ip = fold(Ip0),
    lists:any(fun(Source) -> matches(Ip, Source) end, Sources).

matches(Ip, {Net, Prefix}) ->
    same_family_match(Ip, fold(Net), Prefix);
matches(Ip, Net) ->
    Ip =:= fold(Net).

same_family_match(Ip, Net, Prefix) when tuple_size(Ip) =:= tuple_size(Net) ->
    Bits = case tuple_size(Ip) of 4 -> 32; 8 -> 128 end,
    Shift = Bits - Prefix,
    (to_int(Ip) bsr Shift) =:= (to_int(Net) bsr Shift);
same_family_match(_, _, _) ->
    false.

to_int({A, B, C, D}) ->
    (A bsl 24) bor (B bsl 16) bor (C bsl 8) bor D;
to_int({A, B, C, D, E, F, G, H}) ->
    lists:foldl(fun(W, Acc) -> (Acc bsl 16) bor W end, 0, [A, B, C, D, E, F, G, H]).

%% IPv4-mapped IPv6 (::ffff:a.b.c.d) is the same host as a.b.c.d.
fold({0, 0, 0, 0, 0, 16#ffff, Hi, Lo}) ->
    {Hi bsr 8, Hi band 255, Lo bsr 8, Lo band 255};
fold(Ip) ->
    Ip.

%% @doc The address as text: a bare IPv4 or IPv6 address, no port, no brackets
%% (the form the server's RegisterRequest.gateway_observed_peer takes).
-spec format(inet:ip_address()) -> binary().
format(Ip) ->
    list_to_binary(inet:ntoa(fold(Ip))).
