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
%%%                   proxies we were not told about; they are never examined,
%%%                   so their length, count or bytes cannot spoil the claim.
%%%                   `trusted_hops' must be the number of proxies in front of
%%%                   the gateway: a larger count selects an entry a client
%%%                   can write, and the address is then the client's choice.
%%%
%%% What a call is attributed to, by who connected:
%%%
%%%   the peer is not a configured source   the TCP peer, claim ignored
%%%                                         (`untrusted_source'). This is a
%%%                                         client that reached the listener
%%%                                         directly, and the TCP peer is
%%%                                         what it really is.
%%%   the listener is not proxied           the TCP peer (`transport').
%%%   a trusted proxy sent a usable claim   the claimed address.
%%%   a trusted proxy sent no usable claim  NO OBSERVATION (`undefined'). The
%%%                                         TCP peer here is the proxy itself,
%%%                                         and attributing the call to it
%%%                                         would vouch for an address that is
%%%                                         not the agent's. The caller sends
%%%                                         an empty observation and the server
%%%                                         records that it was not observed.
%%%
%%% A claim from anywhere else is IGNORED, not refused: behind NAT or a
%%% balancer the claim and the TCP peer legitimately differ, and refusing the
%%% call would turn a configuration slip into an outage. The note returned
%%% beside the address says what happened, so the caller can count it (never
%%% log the address).
%%%
%%% Sources are the addresses of the proxies as the gateway's socket sees them:
%%% an IP, or `{Ip, PrefixLength}' for a network. They are a defence in depth
%%% for a listener that is also reachable only from the proxy (a firewall rule,
%%% a NetworkPolicy); neither replaces the other.
%%%
%%% An address is returned without a port: it is attribution, and a proxy's
%%% view of the source port means nothing here. IPv4-mapped IPv6 addresses are
%%% folded to IPv4 so a dual-stack listener and an IPv4 source list agree; a
%%% source network written as an IPv4-mapped IPv6 network ({::ffff:a.b.c.d, P},
%%% P between 97 and 128) is folded the same way, its prefix reduced by 96.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_origin).

-export([validate/1, resolve/4, format/1, in_sources/2]).

-export_type([config/0, source/0, origin/0, note/0]).

%% The entry of x-forwarded-for that is used, after trimming, is at most this
%% long: the longest IP text is 45 bytes (an IPv6 address with an embedded IPv4
%% one), so anything longer is not an address. Nothing else of the header is
%% bounded here; only the one entry is read.
-define(MAX_XFF_ENTRY_BYTES, 64).
%% trusted_hops is a count of proxies in front of the gateway.
-define(MAX_TRUSTED_HOPS, 32).

-type source() :: inet:ip_address() | {inet:ip_address(), non_neg_integer()}.
-type config() :: #{mode := transport}
                | #{mode := proxy_protocol, sources := [source()]}
                | #{mode := forwarded_for, sources := [source()],
                    trusted_hops => non_neg_integer()}.
-type origin() :: {inet:ip_address(), transport | proxy_protocol | forwarded_for}.
%% ok: the claim was used (or none was expected). untrusted_source: the TCP
%% peer is not a configured proxy, so any claim was ignored (the origin is the
%% TCP peer). no_claim: a trusted proxy sent nothing usable (a PROXY `LOCAL'
%% header on a connection that then makes a call, or no x-forwarded-for header).
%% The origin is resolved per call: a health check that opens no stream is never
%% resolved, so never counted. bad_claim: a trusted proxy sent something that is
%% not an address, or fewer entries than trusted_hops asks for. For the last two
%% there is no observation: the origin is `undefined'.
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
                Hops when is_integer(Hops), Hops >= 0, Hops < ?MAX_TRUSTED_HOPS -> ok;
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
    case yuzu_grpc_listener:proper_list(Sources) of
        true -> check_source_list(Sources);
        false -> {error, {bad_origin_sources, improper_list}}
    end;
check_sources(_) ->
    {error, origin_sources_required}.

check_source_list(Sources) ->
    case [S || S <- Sources, not valid_source(S)] of
        [] ->
            %% An IPv4-mapped base folds to IPv4 with the prefix reduced by 96:
            %% a prefix of 96 or less would be a /0 (every IPv4 address) or a
            %% network that cannot match one, so it is refused, not guessed at.
            case [S || {Net, Prefix} = S <- Sources, is_mapped(Net), Prefix =< 96] of
                [] -> ok;
                Short -> {error, {ipv4_mapped_source_prefix_must_exceed_96, Short}}
            end;
        Bad ->
            {error, {bad_origin_sources, Bad}}
    end.

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

%% @doc The address a call is attributed to, with a note saying what happened to
%% any claim. `Peer' is the TCP peer, `Proxy' the PROXY protocol information
%% Cowboy read (undefined when the listener does not read one), `Headers' the
%% request headers with lower-case names. `undefined' is no observation: a
%% trusted proxy was configured but gave no usable address, so the TCP peer (the
%% proxy) is not the agent's.
-spec resolve(config(), inet:ip_address(), map() | undefined, #{binary() => binary()}) ->
    {origin() | undefined, note()}.
resolve(#{mode := transport}, Peer, _Proxy, _Headers) ->
    {{fold(Peer), transport}, ok};
resolve(#{mode := proxy_protocol, sources := Sources}, Peer, Proxy, _Headers) ->
    case in_sources(Peer, Sources) of
        false -> {{fold(Peer), transport}, untrusted_source};
        true -> from_proxy_header(Proxy)
    end;
resolve(#{mode := forwarded_for, sources := Sources} = Config, Peer, _Proxy, Headers) ->
    case in_sources(Peer, Sources) of
        false -> {{fold(Peer), transport}, untrusted_source};
        true -> from_forwarded_for(maps:get(trusted_hops, Config, 0),
                                   maps:get(<<"x-forwarded-for">>, Headers, undefined))
    end.

from_proxy_header(#{command := proxy, src_address := Src}) when is_tuple(Src) ->
    case is_ip(Src) of
        {true, _} -> {{fold(Src), proxy_protocol}, ok};
        false -> {undefined, bad_claim}
    end;
from_proxy_header(#{command := proxy}) ->
    %% A family with no address (UNSPEC, a unix socket): not an IP to attribute.
    {undefined, bad_claim};
from_proxy_header(_LocalOrAbsent) ->
    %% PROXY `LOCAL' means the proxy opened this connection itself: no client
    %% behind it (resolved only if the connection goes on to make a call).
    {undefined, no_claim}.

%% The entry Hops places from the right of the header, and nothing else of it.
%% Cowboy joins repeated header lines with ", " in order, so the entry the
%% nearest proxy appended is the last one whether it sent a new line or extended
%% the client's. Only the bytes from the Hops-th comma from the right are
%% examined; what is to the left (any length, any bytes) cannot matter.
from_forwarded_for(_Hops, undefined) ->
    {undefined, no_claim};
from_forwarded_for(Hops, Value) ->
    case entry_from_right(Value, Hops) of
        none ->
            {undefined, bad_claim};
        {ok, Raw} ->
            case parse_entry(trim(Raw)) of
                {ok, Ip} -> {{fold(Ip), forwarded_for}, ok};
                error -> {undefined, bad_claim}
            end
    end.

%% The Hops-th entry counting from the right (0: the last), or `none' when the
%% header has fewer entries. Scans from the right, byte by byte.
entry_from_right(Value, Hops) ->
    case find_end(Value, byte_size(Value), Hops) of
        none -> none;
        End -> Start = start_of(Value, End),
               {ok, binary:part(Value, Start, End - Start)}
    end.

%% The offset where the entry Hops from the right stops: the size for Hops 0,
%% otherwise the offset of the Hops-th comma from the right.
find_end(_Value, End, 0) ->
    End;
find_end(Value, End, Hops) ->
    case last_comma(Value, End) of
        none -> none;
        Comma -> find_end(Value, Comma, Hops - 1)
    end.

start_of(Value, End) ->
    case last_comma(Value, End) of
        none -> 0;
        Comma -> Comma + 1
    end.

%% The offset of the last comma before Before, or `none'.
last_comma(_Value, 0) ->
    none;
last_comma(Value, Before) ->
    case binary:at(Value, Before - 1) of
        $, -> Before - 1;
        _ -> last_comma(Value, Before - 1)
    end.

%% Only SP and HT are trimmed, byte-wise: the value is client-influenced bytes,
%% not text (string:trim would raise on invalid UTF-8).
trim(Bin) ->
    trim_right(trim_left(Bin)).

trim_left(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t -> trim_left(Rest);
trim_left(Bin) -> Bin.

trim_right(Bin) ->
    Size = byte_size(Bin),
    case Size > 0 andalso binary:at(Bin, Size - 1) of
        C when C =:= $\s; C =:= $\t -> trim_right(binary:part(Bin, 0, Size - 1));
        _ -> Bin
    end.

parse_entry(Entry) when byte_size(Entry) > 0, byte_size(Entry) =< ?MAX_XFF_ENTRY_BYTES ->
    case inet:parse_strict_address(binary_to_list(Entry)) of
        {ok, Ip} -> {ok, Ip};
        {error, _} -> error
    end;
parse_entry(_) ->
    error.

%%--------------------------------------------------------------------
%% Addresses
%%--------------------------------------------------------------------

%% @doc Whether an address is one of the sources (an IP, or inside a network).
-spec in_sources(inet:ip_address(), [source()]) -> boolean().
in_sources(Ip0, Sources) ->
    Ip = fold(Ip0),
    lists:any(fun(Source) -> matches(Ip, Source) end, Sources).

matches(Ip, {Net, Prefix}) ->
    {Net1, Prefix1} = fold_network(Net, Prefix),
    same_family_match(Ip, Net1, Prefix1);
matches(Ip, Net) ->
    Ip =:= fold(Net).

%% An IPv4-mapped network is the IPv4 network with 96 fewer prefix bits. A prefix
%% of 96 or less is left alone (it cannot match an IPv4 address; validate/1
%% refuses it).
fold_network(Net, Prefix) ->
    case is_mapped(Net) andalso Prefix > 96 of
        true -> {fold(Net), Prefix - 96};
        false -> {Net, Prefix}
    end.

is_mapped({0, 0, 0, 0, 0, 16#ffff, _, _}) -> true;
is_mapped(_) -> false.

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
