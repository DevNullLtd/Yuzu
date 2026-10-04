%%%-------------------------------------------------------------------
%%% @doc TCP_NODELAY on the gateway-to-server (upstream) gRPC channel.
%%%
%%% chatterbox's client connects with `gen_tcp:connect(.., [{active,false}])'
%%% and sets no `nodelay'. On the upstream socket every request smaller than
%%% about 64 KiB then waits for Nagle's algorithm to meet the server's delayed
%%% ACK: about 41-43 ms per upstream call, and every ProxyRegister goes through
%%% the one `yuzu_gw_upstream' process over one connection, so a gateway
%%% registered only about 24 agents per second. With `nodelay' the same call
%%% takes about 1 ms.
%%%
%%% The channel is not built by yuzu_gw. grpcbox reads `{grpcbox, client}'
%%% verbatim and starts `default_channel' when the grpcbox application starts,
%%% which is before yuzu_gw starts (grpcbox is one of its `applications').
%%% So `apply_nodelay/0', run by yuzu_gw_app before the supervision tree (and
%%% with it every caller of the channel) exists, rewrites the endpoints of
%%% `default_channel' and restarts that one channel with the rewritten list.
%%% Subchannels connect lazily, on the first call, so the restart drops no
%%% connection and no request. Existing sys.config files need no edit.
%%%
%%% Only `default_channel' is touched: it is the channel `yuzu_gw_upstream' and
%%% `yuzu_gw_heartbeat_buffer' call. The agent-facing and management listeners
%%% are grpcbox servers and are not channels.
%%%
%%% Switch: application env `upstream_tcp_nodelay' (boolean, default true),
%%% read through yuzu_gw_env:env_bool/2. An operator's own `nodelay' entry in an
%%% endpoint's `socket_options' always wins, so `{nodelay, false}' set by hand
%%% keeps Nagle on that endpoint; any other `socket_options' are kept as given.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_channel).

-export([apply_nodelay/0, with_nodelay/2]).

-define(CHANNEL, default_channel).
-define(ENV_KEY, upstream_tcp_nodelay).

%% How long a restarted channel may wait for the old channel's registered name
%% to be released: gproc drops a name when it sees the owner's DOWN message.
-define(START_ATTEMPTS, 100).
-define(START_RETRY_MS, 10).

%% @doc Make the running upstream channel use nodelay (see the module doc).
%% Never crashes the application start: a channel that cannot be restarted with
%% the rewritten endpoints is restored with the original ones, with a warning.
-spec apply_nodelay() -> ok.
apply_nodelay() ->
    Enabled = yuzu_gw_env:env_bool(?ENV_KEY, true),
    case application:get_env(grpcbox, client) of
        {ok, Client} ->
            apply_nodelay(Client, with_nodelay(Client, Enabled), Enabled);
        _ ->
            ok
    end.

apply_nodelay(Client, Client, false) ->
    logger:info("Upstream channel TCP_NODELAY is disabled (~s=false)", [?ENV_KEY]);
apply_nodelay(Client, Client, true) ->
    %% No upstream channel configured, or every endpoint already has an
    %% operator-set nodelay entry.
    ok;
apply_nodelay(Client, #{channels := NewChannels} = NewClient, true) ->
    case lists:keyfind(?CHANNEL, 1, NewChannels) of
        {?CHANNEL, Endpoints, Options} ->
            #{channels := OldChannels} = Client,
            {?CHANNEL, OldEndpoints, _} = lists:keyfind(?CHANNEL, 1, OldChannels),
            case restart_channel(Endpoints, OldEndpoints, Options) of
                ok ->
                    application:set_env(grpcbox, client, NewClient),
                    logger:info("Upstream channel ~s: TCP_NODELAY on (set ~s=false "
                                "to turn off)", [?CHANNEL, ?ENV_KEY]);
                {error, Reason} ->
                    logger:warning("Upstream channel ~s: could not restart it with "
                                   "TCP_NODELAY (~p)", [?CHANNEL, Reason])
            end;
        false ->
            ok
    end.

%% Stop the channel (reason `normal': grpcbox_channel's terminate stops every
%% subchannel itself and then deletes the pool) and start it again with the new
%% endpoints.
-spec restart_channel([term()], [term()], map()) -> ok | {error, term()}.
restart_channel(Endpoints, OldEndpoints, Options) ->
    try
        try grpcbox_channel:stop(?CHANNEL, normal)
        catch
            exit:noproc      -> ok;
            exit:{noproc, _} -> ok
        end,
        case start_channel(Endpoints, Options, ?START_ATTEMPTS) of
            {ok, _Pid} ->
                ok;
            {error, Reason} ->
                %% Leave the node with a channel rather than without one, and
                %% say when even that failed: the node then has no upstream.
                case start_channel(OldEndpoints, Options, ?START_ATTEMPTS) of
                    {ok, _} ->
                        ok;
                    Failed ->
                        logger:warning("Upstream channel ~s: could not restore it "
                                       "with the endpoints as configured either "
                                       "(~p); the node has no upstream channel",
                                       [?CHANNEL, Failed])
                end,
                {error, Reason}
        end
    catch
        Class:Why ->
            {error, {Class, Why}}
    end.

start_channel(Endpoints, Options, Attempts) ->
    case grpcbox_channel_sup:start_child(?CHANNEL, Endpoints, Options) of
        {error, {already_started, _}} when Attempts > 1 ->
            timer:sleep(?START_RETRY_MS),
            start_channel(Endpoints, Options, Attempts - 1);
        Other ->
            Other
    end.

%% @doc Pure: the grpcbox `client' value with `nodelay' added to every endpoint
%% of `default_channel' when `Enabled' is true. Other channels, the SSL options
%% of an endpoint (so the TLS posture checks read the same thing) and a value
%% of an unexpected shape pass through unchanged. Exported for testing.
-spec with_nodelay(term(), boolean()) -> term().
with_nodelay(Client, false) ->
    Client;
with_nodelay(#{channels := Channels} = Client, true) when is_list(Channels) ->
    Client#{channels := [channel_with_nodelay(C) || C <- Channels]};
with_nodelay(Client, true) ->
    Client.

channel_with_nodelay({?CHANNEL, Endpoints, Options}) when is_list(Endpoints) ->
    {?CHANNEL, [endpoint_with_nodelay(E) || E <- Endpoints], Options};
channel_with_nodelay(Other) ->
    Other.

endpoint_with_nodelay({Transport, Host, Port, SslOpts}) ->
    endpoint_with_nodelay({Transport, Host, Port, SslOpts, #{}});
endpoint_with_nodelay({Transport, Host, Port, SslOpts, Settings}) when is_map(Settings) ->
    case maps:get(socket_options, Settings, []) of
        SocketOpts when is_list(SocketOpts) ->
            case proplists:is_defined(nodelay, SocketOpts) of
                true ->
                    {Transport, Host, Port, SslOpts, Settings};
                false ->
                    {Transport, Host, Port, SslOpts,
                     Settings#{socket_options => SocketOpts ++ [{nodelay, true}]}}
            end;
        Bad ->
            logger:warning("Upstream channel ~s: socket_options ~p of the endpoint "
                           "~p:~p is not a list; TCP_NODELAY not added",
                           [?CHANNEL, Bad, Host, Port]),
            {Transport, Host, Port, SslOpts, Settings}
    end;
endpoint_with_nodelay(Other) ->
    Other.
