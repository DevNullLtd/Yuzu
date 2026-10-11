%%%-------------------------------------------------------------------
%%% @doc The upstream gRPC client's channel configuration, read from
%%% `{yuzu_gw, [{upstream_client, #{channels => [...]}}]}'.
%%%
%%% The value has the shape it had when it lived at `{grpcbox, [{client, ...}]}':
%%% move it, do not rewrite it. The old location cannot be read any more. OTP
%%% applies a sys.config entry only to a LOADED application, and nothing loads
%%% one named `grpcbox' now that the gateway does not contain it; a value left
%%% there is silently invisible, so a gateway whose TLS client options were
%%% ignored would not dial the server at all, and a plaintext one would look
%%% configured. yuzu_gw_app refuses to start when it finds the old key
%%% (check_legacy_grpcbox_client/0), reading the config files themselves.
%%%
%%% A channel is `{Name, Endpoints, Options}'. An endpoint is
%%% `{http | https, Host, Port, SslOptions}' or the same with a fifth element,
%%% a map whose `socket_options' (a proplist) are passed to the TCP socket.
%%% `SslOptions' are `ssl' client options, handed on unchanged. Options:
%%%   pool_size                connections per endpoint (default 1; see below)
%%%   connect_timeout          ms to connect, TCP and TLS each (default 5000)
%%%   max_receive_message_bytes
%%%                            the largest response message accepted
%%%                            (default 16 MiB); a larger one fails the call
%%% One connection per endpoint is the default, as it was: every call a gateway
%%% makes then reaches ONE server replica through a layer-4 virtual IP, which the
%%% multi-replica registration reconcile relies on (ADR-2002 7c), and every call
%%% sees the same client certificate. More connections give calls more parallel
%%% paths and put them on different replicas and different handshakes; raise it
%%% only knowing that.
%%% The old options `balancer', `encoding' and `sync_start' are accepted and
%%% ignored: calls go round-robin over the live connections, messages are never
%%% compressed, and connections are opened when the channel starts.
%%%
%%% Pure: no process, no socket. Exported for testing.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_config).

-export([from_env/0, channels/1, channel/2, nodelay_default/0]).
-export([env_key/0]).
-export_type([channel/0, endpoint/0]).

-define(DEFAULT_POOL_SIZE, 1).
-define(MAX_POOL_SIZE, 64).
-define(DEFAULT_CONNECT_TIMEOUT_MS, 5000).
-define(DEFAULT_MAX_RECEIVE_BYTES, 16 * 1024 * 1024).
-define(NODELAY_ENV, upstream_tcp_nodelay).

-type endpoint() :: #{host := string(),
                      port := inet:port_number(),
                      transport := tcp | tls,
                      tls_opts := [ssl:tls_client_option()],
                      tcp_opts := [gen_tcp:connect_option()]}.
-type channel() :: #{name := atom(),
                     endpoints := [endpoint(), ...],
                     pool_size := pos_integer(),
                     connect_timeout := pos_integer(),
                     max_receive_message_bytes := pos_integer()}.

%% @doc The application env key the channels are read from.
-spec env_key() -> upstream_client.
env_key() -> upstream_client.

%% @doc Every configured channel: `channels/1' of the `upstream_client' env of
%% yuzu_gw.
-spec from_env() -> {ok, [channel()]} | {error, term()}.
from_env() ->
    channels(application:get_env(yuzu_gw, env_key(), undefined)).

%% @doc Every channel of a `client' value. `{error, Reason}' names the first
%% thing wrong with it: a channel that is quietly dropped would leave the
%% gateway with no upstream, or with the wrong one.
-spec channels(term()) -> {ok, [channel()]} | {error, term()}.
channels(#{channels := Channels}) when is_list(Channels) ->
    case collect([channel(C, nodelay_default()) || C <- Channels]) of
        {ok, Parsed} -> distinct(Parsed);
        {error, _} = Error -> Error
    end;
channels(undefined) ->
    {ok, []};
channels(Other) ->
    {error, {bad_client_config, shape(Other)}}.

%% @doc One channel definition, with the TCP_NODELAY default for the endpoints
%% that do not say.
-spec channel(term(), boolean()) -> {ok, channel()} | {error, term()}.
channel({Name, Endpoints, Options}, Nodelay)
  when is_atom(Name), is_list(Endpoints), Endpoints =/= [], is_map(Options) ->
    case collect([endpoint(E, Nodelay) || E <- Endpoints]) of
        {ok, Parsed} ->
            {ok, #{name => Name,
                   endpoints => Parsed,
                   pool_size => bounded(maps:get(pool_size, Options, ?DEFAULT_POOL_SIZE),
                                        1, ?MAX_POOL_SIZE, ?DEFAULT_POOL_SIZE),
                   connect_timeout => bounded(maps:get(connect_timeout, Options,
                                                       ?DEFAULT_CONNECT_TIMEOUT_MS),
                                              1, 600000, ?DEFAULT_CONNECT_TIMEOUT_MS),
                   max_receive_message_bytes =>
                       bounded(maps:get(max_receive_message_bytes, Options,
                                        ?DEFAULT_MAX_RECEIVE_BYTES),
                               1, 1 bsl 30, ?DEFAULT_MAX_RECEIVE_BYTES)}};
        {error, _} = Error ->
            Error
    end;
channel(Other, _Nodelay) ->
    {error, {bad_channel, shape(Other)}}.

%% @doc Whether endpoints get TCP_NODELAY unless their own socket options say
%% otherwise: application env `upstream_tcp_nodelay' (default true).
%%
%% Without it a request under about 64 KiB waits for Nagle's algorithm to meet
%% the server's delayed ACK, about 41-43 ms per call, and a gateway then
%% registers only about 24 agents a second over one connection.
-spec nodelay_default() -> boolean().
nodelay_default() ->
    yuzu_gw_env:env_bool(?NODELAY_ENV, true).

%% Two channels of one name would start two processes under one registered
%% name and ETS table: the second fails inside the supervisor with a start_spec
%% error that names neither. Refused here, where the config is read.
distinct(Channels) ->
    Names = [N || #{name := N} <- Channels],
    case Names -- lists:usort(Names) of
        []            -> {ok, Channels};
        [Name | _]    -> {error, {duplicate_channel, Name}}
    end.

endpoint({Scheme, Host, Port, Ssl}, Nodelay) ->
    endpoint({Scheme, Host, Port, Ssl, #{}}, Nodelay);
endpoint({Scheme, Host, Port, Ssl, Settings}, Nodelay)
  when (Scheme =:= http orelse Scheme =:= https),
       is_integer(Port), Port > 0, Port < 65536,
       is_list(Ssl), is_map(Settings) ->
    case host(Host) of
        {ok, H} ->
            case socket_options(Settings, Nodelay) of
                {ok, Tcp} ->
                    {ok, #{host => H, port => Port,
                           transport => transport(Scheme),
                           tls_opts => Ssl, tcp_opts => Tcp}};
                {error, _} = Error ->
                    Error
            end;
        {error, _} = Error ->
            Error
    end;
endpoint(Other, _Nodelay) ->
    {error, {bad_endpoint, shape(Other)}}.

transport(http)  -> tcp;
transport(https) -> tls.

host(Host) when is_list(Host), Host =/= [] -> {ok, Host};
host(Host) when is_binary(Host), Host =/= <<>> -> {ok, binary_to_list(Host)};
host(Other) -> {error, {bad_host, shape(Other)}}.

%% An operator's own `nodelay' entry always wins, in either direction.
socket_options(Settings, Nodelay) ->
    case maps:get(socket_options, Settings, []) of
        Opts when is_list(Opts) ->
            try proplists:is_defined(nodelay, Opts) of
                true            -> {ok, Opts};
                false when Nodelay -> {ok, Opts ++ [{nodelay, true}]};
                false           -> {ok, Opts}
            catch
                error:_ -> {error, {bad_socket_options, shape(Opts)}}
            end;
        Bad ->
            {error, {bad_socket_options, shape(Bad)}}
    end.

bounded(N, Min, Max, _Default) when is_integer(N), N >= Min, N =< Max -> N;
bounded(_Other, _Min, _Max, Default) -> Default.

collect(Results) ->
    case [E || {error, _} = E <- Results] of
        []        -> {ok, [V || {ok, V} <- Results]};
        [Err | _] -> Err
    end.

%% What a rejected value looks like, without its contents: an endpoint's SSL
%% options can name a private key file, and a rejection is logged.
shape(T) when is_tuple(T) -> {tuple, tuple_size(T)};
shape(L) when is_list(L)  -> try {list, length(L)} catch error:_ -> {list, improper} end;
shape(M) when is_map(M)   -> {map, map_size(M)};
shape(B) when is_binary(B) -> {binary, byte_size(B)};
shape(A) when is_atom(A)  -> A;
shape(_)                  -> other.
