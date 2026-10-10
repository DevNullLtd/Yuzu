%%%-------------------------------------------------------------------
%%% @doc One gRPC listener: translates a `grpc_listeners' entry into a Ranch
%%% listener running Cowboy's HTTP/2 connection process with yuzu_grpc_stream_h
%%% as its only stream handler. A gen_server owns it, so a supervisor can start
%%% and stop it like any child, and a listener that dies is restarted.
%%%
%%% An entry is a map:
%%%
%%%   name           any term; names the listener (the Ranch ref is {yuzu_grpc, Name})
%%%   service_protos [gpb module]; the proto modules that describe the services
%%%   services       #{ServiceName => Module}; the module that serves each
%%%   listen         #{port => P, ip => Ip}; ip defaults to 0.0.0.0, port 0 is
%%%                  any free port (read it back with port/1); an optional
%%%                  socket_opts list is appended to the socket options
%%%   tls            omitted: plaintext HTTP/2 (prior knowledge, no HTTP/1.1).
%%%                  Present: #{certfile, keyfile, cacertfile} are ALL required
%%%                  and an incomplete map refuses to start. verify defaults to
%%%                  verify_peer and fail_if_no_peer_cert to true for it (mutual
%%%                  TLS); verify => verify_none gives one-way TLS and then
%%%                  fail_if_no_peer_cert defaults to false. TLS 1.2 only.
%%%   auth_fun       optional fun(Der) -> {true, Id} | true | false, run on the
%%%                  peer certificate before anything else happens to a stream
%%%                  (yuzu_grpc_stream_h). Only on a listener with `tls'. NEVER
%%%                  give one to the agent listener: a peer without a
%%%                  certificate is refused whenever there is an auth_fun, and the
%%%                  agent listener must admit the agents that have none yet.
%%%   origin         optional, how the address of the caller is decided; see
%%                  yuzu_grpc_origin. Omitted: `#{mode => transport}', the TCP
%%                  peer. A listener behind a load balancer or a router says so
%%                  here, and names the proxies it trusts:
%%                    #{mode => proxy_protocol, sources => [Ip | {Ip, Prefix}]}
%%                    #{mode => forwarded_for, sources => [...], trusted_hops => 0}
%%                  Both are refused to start without `sources'. proxy_protocol
%%                  makes the listener require a PROXY header on every
%%                  connection (one without is closed after a second), so it
%%                  serves only the proxy; the header precedes the TLS
%%                  handshake, so a client certificate still reaches the
%%                  gateway. forwarded_for reads x-forwarded-for from a proxy
%%                  that terminates TLS: the certificate the gateway sees is
%%                  the proxy's, so it cannot be combined with an `auth_fun'.
%%   http2          optional overrides of the Cowboy HTTP/2 options
%%%   limits         optional #{max_message_bytes, send_timeout_ms}
%%%   acceptors      optional acceptor count (default 4)
%%%
%%% The defaults suit a low-volume control listener (idle timeout 10 minutes,
%%% 1024 concurrent streams per connection, 4 acceptors). A listener that serves
%%% a fleet sets its own: the agents ping every 60 s, so 180000 for the idle
%%% timeout, a handful of streams per connection, and more acceptors.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_listener).
-behaviour(gen_server).

-export([start_link/1, start/1, stop/1, child_spec/1]).
-export([port/1, validate/1, ssl_opts/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-export_type([entry/0]).

-type entry() :: #{atom() => term()}.

%% Options the layer owns; an entry may not override them.
-define(RESERVED_HTTP2, [stream_handlers, env, protocols, alpn_default_protocol,
                         connection_type, middlewares, proxy_header]).
%% ECDHE-ECDSA AEAD suites only, the list the gateway's upstream client uses
%% (config/sys.config.prod): the gateway and server leaves are EC P-256.
-define(CIPHERS, ["ECDHE-ECDSA-AES256-GCM-SHA384",
                  "ECDHE-ECDSA-AES128-GCM-SHA256",
                  "ECDHE-ECDSA-CHACHA20-POLY1305"]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start a listener linked to the caller (a supervisor).
-spec start_link(entry()) -> {ok, pid()} | {error, term()}.
start_link(Entry) ->
    gen_server:start_link(?MODULE, Entry, []).

%% @doc Start a listener that is not linked to the caller (a test). A failure to
%% start is an `{error, _}' and does not take the caller down.
-spec start(entry()) -> {ok, pid()} | {error, term()}.
start(Entry) ->
    gen_server:start(?MODULE, Entry, []).

%% @doc Stop the listener and close its connections.
-spec stop(pid()) -> ok.
stop(Pid) ->
    gen_server:stop(Pid, normal, 15000).

-spec child_spec(entry()) -> supervisor:child_spec().
child_spec(#{name := Name} = Entry) ->
    #{id => {?MODULE, Name},
      start => {?MODULE, start_link, [Entry]},
      restart => permanent,
      shutdown => 15000,
      type => worker,
      modules => [?MODULE]}.

%% @doc The port the listener is bound to.
-spec port(pid()) -> inet:port_number().
port(Pid) ->
    gen_server:call(Pid, port).

%% @doc Whether an entry can be started. The checks are structural: an entry
%% that fails one never binds a port.
-spec validate(entry()) -> ok | {error, term()}.
validate(Entry) when is_map(Entry) ->
    first_error([fun() -> check_required(Entry) end,
                 fun() -> check_listen(maps:get(listen, Entry, undefined)) end,
                 fun() -> check_tls(Entry) end,
                 fun() -> check_origin(Entry) end,
                 fun() -> check_http2(maps:get(http2, Entry, #{})) end]);
validate(_) ->
    {error, entry_not_a_map}.

%% @doc The TLS socket options of a `tls' map. Mutual TLS by default; TLS 1.2
%% with ECDHE-ECDSA AEAD suites only.
-spec ssl_opts(map()) -> [ssl:tls_server_option()].
ssl_opts(#{certfile := Cert, keyfile := Key, cacertfile := CaCert} = Tls) ->
    Verify = maps:get(verify, Tls, verify_peer),
    [{certfile, Cert}, {keyfile, Key}, {cacertfile, CaCert},
     {verify, Verify},
     {fail_if_no_peer_cert, maps:get(fail_if_no_peer_cert, Tls, Verify =:= verify_peer)},
     {versions, ['tlsv1.2']},
     {ciphers, maps:get(ciphers, Tls, ?CIPHERS)},
     {alpn_preferred_protocols, [<<"h2">>]},
     {honor_cipher_order, true},
     {reuse_sessions, false}].

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------

-spec init(entry()) -> {ok, map()} | {stop, term()}.
init(Entry) ->
    process_flag(trap_exit, true),
    case validate(Entry) of
        ok ->
            case yuzu_grpc_route:build(maps:get(service_protos, Entry),
                                       maps:get(services, Entry)) of
                {ok, Routes} -> listen(Entry, Routes);
                {error, Reason} -> {stop, {bad_routes, Reason}}
            end;
        {error, Reason} ->
            {stop, {bad_listener, Reason}}
    end.

-spec handle_call(term(), {pid(), term()}, map()) -> {reply, term(), map()}.
handle_call(port, _From, #{ref := Ref} = State) ->
    {reply, ranch:get_port(Ref), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

-spec handle_cast(term(), map()) -> {noreply, map()}.
handle_cast(_Msg, State) ->
    {noreply, State}.

%% The Ranch listener went away under us: stop, so the supervisor restarts the
%% whole listener rather than leaving a port unserved.
-spec handle_info(term(), map()) -> {noreply, map()} | {stop, listener_down, map()}.
handle_info({'DOWN', Mon, process, _Pid, _Reason}, #{mon := Mon} = State) ->
    {stop, listener_down, State#{ref := undefined}};
handle_info(_Info, State) ->
    {noreply, State}.

-spec terminate(term(), map()) -> ok.
terminate(_Reason, #{ref := Ref}) when Ref =/= undefined ->
    _ = (catch cowboy:stop_listener(Ref)),
    ok;
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Starting Ranch
%%--------------------------------------------------------------------

listen(#{name := Name} = Entry, Routes) ->
    Ref = {yuzu_grpc, Name},
    Tls = maps:get(tls, Entry, undefined),
    Trans = transport_opts(Entry, Tls),
    Proto = protocol_opts(Entry, Routes),
    Started = case Tls of
        undefined -> cowboy:start_clear(Ref, Trans, Proto);
        _ -> cowboy:start_tls(Ref, Trans, Proto)
    end,
    case Started of
        {ok, Sup} ->
            Mon = erlang:monitor(process, Sup),
            logger:info("gateway grpc listener ~p up on port ~p (tls=~p, auth_fun=~p)",
                        [Name, ranch:get_port(Ref), Tls =/= undefined,
                         maps:is_key(auth_fun, Entry)],
                        #{domain => [yuzu_gw, grpc]}),
            {ok, #{ref => Ref, sup => Sup, mon => Mon}};
        {error, Reason} ->
            {stop, {listen_failed, Reason}}
    end.

transport_opts(Entry, Tls) ->
    #{port := Port} = Listen = maps:get(listen, Entry),
    Ip = maps:get(ip, Listen, {0, 0, 0, 0}),
    SocketOpts = [{ip, Ip}, {port, Port}, {backlog, 4096}, {nodelay, true}]
        ++ maps:get(socket_opts, Listen, [])
        ++ case Tls of
               undefined -> [];
               _ -> ssl_opts(Tls)
           end,
    #{num_acceptors => maps:get(acceptors, Entry, 4),
      %% Ranch's default of 1024 connections would cap the fleet.
      max_connections => infinity,
      handshake_timeout => 10000,
      socket_opts => SocketOpts}.

protocol_opts(Entry, Routes) ->
    Limits = maps:get(limits, Entry, #{}),
    Defaults = #{idle_timeout => 600000,
                 max_concurrent_streams => 1024,
                 max_frame_size_received => 16384,
                 linger_timeout => 1000},
    Origin = maps:get(origin, Entry, #{mode => transport}),
    maps:merge(maps:merge(Defaults, maps:get(http2, Entry, #{})),
               #{stream_handlers => [yuzu_grpc_stream_h],
                 env => #{grpc => Routes,
                          auth_fun => maps:get(auth_fun, Entry, undefined),
                          origin => Origin,
                          limits => Limits},
                 %% Cowboy reads the PROXY header itself, before the TLS
                 %% handshake; the stream handler decides whether to believe it.
                 proxy_header => maps:get(mode, Origin) =:= proxy_protocol,
                 %% HTTP/2 only: prior knowledge in cleartext. On TLS ALPN
                 %% settles on h2 (a client offering only http/1.1 or another
                 %% protocol is refused with a no_application_protocol alert);
                 %% a client that sends no ALPN at all is parsed as HTTP/2 too.
                 protocols => [http2],
                 alpn_default_protocol => http2}).

%%--------------------------------------------------------------------
%% Validation
%%--------------------------------------------------------------------

first_error([]) ->
    ok;
first_error([Check | Rest]) ->
    case Check() of
        ok -> first_error(Rest);
        {error, _} = Error -> Error
    end.

check_required(Entry) ->
    case [Key || Key <- [name, service_protos, services, listen], not maps:is_key(Key, Entry)] of
        [] -> ok;
        Missing -> {error, {missing_keys, Missing}}
    end.

check_listen(#{port := Port}) when is_integer(Port), Port >= 0, Port =< 65535 ->
    ok;
check_listen(_) ->
    {error, bad_listen}.

check_tls(Entry) ->
    case maps:get(tls, Entry, undefined) of
        undefined ->
            case maps:is_key(auth_fun, Entry) of
                true -> {error, auth_fun_without_tls};
                false -> ok
            end;
        Tls when is_map(Tls) ->
            case [Key || Key <- [certfile, keyfile, cacertfile], not has_path(Tls, Key)] of
                [] -> ok;
                Missing -> {error, {tls_incomplete, Missing}}
            end;
        _ ->
            {error, bad_tls}
    end.

has_path(Tls, Key) ->
    case maps:get(Key, Tls, undefined) of
        Path when is_list(Path), Path =/= [] -> true;
        Path when is_binary(Path), Path =/= <<>> -> true;
        _ -> false
    end.

check_origin(Entry) ->
    case maps:get(origin, Entry, undefined) of
        undefined ->
            ok;
        Origin ->
            case yuzu_grpc_origin:validate(Origin) of
                ok -> check_origin_auth(Origin, maps:is_key(auth_fun, Entry));
                {error, _} = Error -> Error
            end
    end.

%% An auth_fun authenticates the peer of the TLS connection. Behind a proxy that
%% terminates TLS that peer is the proxy, so the check would pass on the
%% proxy's certificate and say nothing about the agent: refuse the combination
%% rather than let it read as agent authentication. (PROXY protocol does not
%% terminate TLS and does not have the problem.)
check_origin_auth(#{mode := forwarded_for}, true) ->
    {error, auth_fun_behind_terminating_proxy};
check_origin_auth(_, _) ->
    ok.

check_http2(Http2) when is_map(Http2) ->
    case [Key || Key <- ?RESERVED_HTTP2, maps:is_key(Key, Http2)] of
        [] -> ok;
        Reserved -> {error, {reserved_http2_options, Reserved}}
    end;
check_http2(_) ->
    {error, bad_http2}.
