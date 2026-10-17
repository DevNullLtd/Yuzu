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
%%%                  fail_if_no_peer_cert defaults to false. TLS 1.2 only. `ciphers'
%%%                  is optional; when it is unset the suites follow the key type
%%%                  of certfile (see ssl_opts/1) and when it is set it is used
%%%                  as given.
%%%   auth_fun       optional fun(Der) -> {true, Id} | true | false, run on the
%%%                  peer certificate before anything else happens to a stream
%%%                  (yuzu_grpc_stream_h). Only on a listener with `tls', and
%%%                  never on a listener that serves the agent service (agent_pb
%%%                  in service_protos, or the AgentService a key of services): a
%%%                  peer without a certificate is refused whenever there is an
%%%                  auth_fun, and the agent listener must admit the agents that
%%%                  have none yet.
%%%   origin         optional, how the address of the caller is decided; see
%%%                  yuzu_grpc_origin. Omitted: `#{mode => transport}', the TCP
%%%                  peer. A listener behind a load balancer or a router says so
%%%                  here, and names the proxies it trusts:
%%%                    #{mode => proxy_protocol, sources => [Ip | {Ip, Prefix}]}
%%%                    #{mode => forwarded_for, sources => [...], trusted_hops => 0}
%%%                  Both are refused to start without `sources'. proxy_protocol
%%%                  makes the listener require a PROXY header on every
%%%                  connection (one without is closed after a second), so it
%%%                  serves only the proxy; the header precedes the TLS
%%%                  handshake, so a client certificate still reaches the
%%%                  gateway. forwarded_for reads x-forwarded-for from a proxy
%%%                  that terminates TLS: the certificate the gateway sees is
%%%                  the proxy's, so it cannot be combined with an `auth_fun'.
%%%   http2          optional overrides of the Cowboy HTTP/2 options (see
%%%                  http2_opts/1 for the defaults they override)
%%%   limits         optional #{max_message_bytes, send_timeout_ms, max_connections,
%%%                  max_connection_memory_bytes, request_timeout_ms}
%%%                  max_connection_memory_bytes caps a single connection's memory
%%%                  (a max_heap_size on the Cowboy connection process counting the
%%%                  refc buffers its streams hold); a connection that buffers more
%%%                  half-finished requests than this is killed. Default: four times
%%%                  max_message_bytes (`infinity' disables it), except on a listener
%%%                  that routes the ManagementService and does not serve the agent
%%%                  service, where the default is none: its one peer is the pinned
%%%                  server, and the ceiling killed the server's connection when a
%%%                  fan-out's responses arrived together (stream_limits/1). An
%%%                  explicit value applies on any listener. request_timeout_ms
%%%                  is how long a unary/server-streaming stream may buffer its one
%%%                  request before it is aborted DEADLINE_EXCEEDED (default 30000,
%%%                  `infinity' disables it); it never cuts a bidirectional or
%%%                  client-streaming handler, which runs before any message. The
%%%                  two together bound an unauthenticated peer that opens streams
%%%                  and stalls them half-sent (yuzu_grpc_stream_h).
%%%                  max_connections is the most connections the listener holds
%%%                  at once (default infinity). At the ceiling the listener stops
%%%                  accepting until one closes; connections that are already
%%%                  up are untouched. The ceiling is soft by the number of
%%%                  acceptors less one (Ranch puts an acceptor to sleep only
%%%                  after the connection that reached it). It bounds the file
%%%                  descriptors a flood of connections can take. It does NOT
%%%                  bound how long they are held, so it does not stop a flood
%%%                  from filling it: a TLS handshake that never completes is
%%%                  cut after 10 s and a PROXY header that never arrives after
%%%                  1 s, but a connection past those is held until its HTTP/2
%%%                  idle_timeout runs out, and cowboy_http2 resets that counter
%%%                  on every byte it receives, so a peer that keeps sending
%%%                  (a PING every few seconds) holds its slot indefinitely.
%%%                  Once the ceiling is full new connections wait in the
%%%                  kernel backlog; the connections already up are served
%%%                  as before. On a listener whose peers are not authenticated
%%%                  before the connection is held (the agent listener) only a
%%%                  firewall or a per-source rate limit in front of it closes
%%%                  that. Size it under the process's file descriptor limit
%%%                  with headroom for the other listeners, the upstream channel
%%%                  and the health port.
%%%   acceptors      optional acceptor count (default 4)
%%%
%%% The key sets are closed: a key the layer does not read is refused rather
%%% than ignored, so a typo or a key of the former grpcbox shape (transport_opts,
%%% listen_opts, grpc_opts, pool_opts, ssl) never starts a listener that is not the one
%%% configured. The `tls' map takes certfile, keyfile, cacertfile, verify,
%%% fail_if_no_peer_cert and ciphers; `listen' takes port, ip and socket_opts
%%% (which may not set the bind address or port).
%%%
%%% A listener that goes away is restarted by its supervisor, and a graceful stop
%%% or a single death of the Ranch listener supervisor recovers that way. A brutal
%%% exit(kill) of that supervisor, or of this process itself, can still take the
%%% listeners down: two deaths of a listener supervisor inside the 5 s restart
%%% period of ranch_sup take ranch_sup, and with it every listener of the node,
%%% down. None of this is known to be network-triggerable.
%%%
%%% The defaults suit a low-volume control listener (idle timeout 10 minutes,
%%% 1024 concurrent streams per connection, 4 acceptors). A listener that serves
%%% a fleet sets its own: the agents ping every 60 s, so 180000 for the idle
%%% timeout, a handful of streams per connection, and more acceptors. A listener
%%% that routes the ManagementService also gets a received-frame ceiling ten
%%% times Cowboy's and 4096 concurrent streams (http2_opts/1), because the server
%%% fans every command out over the one connection it holds to it, and no
%%% per-connection memory ceiling unless it sets one (stream_limits/1).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_listener).
-behaviour(gen_server).

-include_lib("public_key/include/public_key.hrl").
-include("yuzu_grpc.hrl").

-export([start_link/1, start/1, stop/1, child_spec/1]).
-export([port/1, validate/1, ssl_opts/1, http2_opts/1]).
-export([serves_agent/1, routes_agent/1, serves_proto/2, proper_list/1]).
-export([role/1, ref/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-export_type([entry/0]).

-type entry() :: #{atom() => term()}.

%% Options the layer owns; an entry may not override them.
-define(RESERVED_HTTP2, [stream_handlers, env, protocols, alpn_default_protocol,
                         connection_type, middlewares, proxy_header, logger]).
%% The suites when `tls.ciphers' is unset, by the key type of the certificate:
%% AEAD suites with ephemeral ECDH only. For an EC certificate (the generated
%% gateway leaf is EC P-256) the list the gateway's upstream client uses
%% (config/sys.config.prod); for an RSA certificate, which cannot sign an ECDSA
%% key exchange, the ECDHE-RSA AES-GCM pair.
-define(CIPHERS_EC, ["ECDHE-ECDSA-AES256-GCM-SHA384",
                     "ECDHE-ECDSA-AES128-GCM-SHA256",
                     "ECDHE-ECDSA-CHACHA20-POLY1305"]).
-define(CIPHERS_RSA, ["ECDHE-RSA-AES256-GCM-SHA384",
                      "ECDHE-RSA-AES128-GCM-SHA256"]).

%% The keys an entry, its `tls', `listen' and `limits' maps may carry. Any other
%% key is refused. The former grpcbox keys are named, with where they went.
-define(ENTRY_KEYS, [name, service_protos, services, listen, tls, auth_fun, origin,
                     http2, limits, acceptors]).
-define(TLS_KEYS, [certfile, keyfile, cacertfile, verify, fail_if_no_peer_cert, ciphers]).
-define(LISTEN_KEYS, [port, ip, socket_opts]).
-define(LIMIT_KEYS, [max_message_bytes, send_timeout_ms, max_connections,
                     max_connection_memory_bytes, request_timeout_ms]).
-define(LEGACY_ENTRY_KEYS,
        [{transport_opts, "renamed `tls' (a `tls' map is TLS and its absence is plaintext)"},
         {listen_opts, "renamed `listen'"},
         {grpc_opts, "dissolved: service_protos, services and auth_fun are keys of the entry itself"},
         {pool_opts, "renamed `acceptors' (a count)"},
         {ssl, "dropped: a `tls' map is TLS and its absence is plaintext"}]).
-define(LEGACY_TLS_KEYS,
        [{ssl, "dropped: a `tls' map is TLS and its absence is plaintext"}]).
%% The Cowboy HTTP/2 options an entry may set (cowboy_http2:opts/0), without the
%% ones the layer owns (?RESERVED_HTTP2) and the hooks that run caller code.
-define(HTTP2_KEYS,
        [active_n, compress_buffering, compress_threshold, connection_window_margin_size,
         connection_window_update_threshold, dynamic_buffer, dynamic_buffer_initial_average,
         dynamic_buffer_initial_size, enable_connect_protocol, goaway_initial_timeout,
         goaway_complete_timeout, hibernate, idle_timeout, inactivity_timeout,
         initial_connection_window_size, initial_stream_window_size, linger_timeout,
         max_authority_length, max_cancel_stream_rate, max_concurrent_streams,
         max_connection_buffer_size, max_connection_window_size, max_decode_table_size,
         max_encode_table_size, max_fragmented_header_block_size, max_frame_size_received,
         max_frame_size_sent, max_headers, max_received_frame_rate, max_reset_stream_rate,
         max_stream_buffer_size, max_stream_window_size, preface_timeout,
         reset_idle_timeout_on_send, sendfile, settings_timeout, shutdown_timeout,
         stream_window_data_threshold, stream_window_margin_size,
         stream_window_update_threshold]).
%% The service the agents call; a listener that serves it takes no auth_fun.
-define(AGENT_SERVICE, 'yuzu.agent.v1.AgentService').
%% The service the C++ server calls to fan commands out to the fleet.
-define(MGMT_SERVICE, 'yuzu.server.v1.ManagementService').
%% Cowboy's flood guard counts the HTTP/2 frames a connection receives and
%% closes the WHOLE connection (GOAWAY enhance_your_calm) when more than N arrive
%% inside the period; its own default is {10000, 10000}: 10000 frames per 10 s.
%% A unary RPC is about two received frames (HEADERS, then DATA with END_STREAM;
%% WINDOW_UPDATE and PING add a few more), so that is about 5000 RPCs per 10 s on
%% one connection, and the server holds ONE connection to the management
%% listener and sends every command of a fan-out over it: past that the
%% connection is closed and every call in flight on it fails. Ten times Cowboy's
%% (10000 frames/s, about 5000 RPC/s) is far above the ~205 responses/s measured
%% per server channel, even with K=8 channels to one gateway, and is still
%% finite, so a peer that floods the port is still cut off.
-define(MGMT_FRAME_RATE, {100000, 10000}).
%% The management listener's concurrent-stream cap. The server sends each
%% forwarded command as its own call over its one connection, and its client
%% queues the calls past the cap, so a fan-out takes about
%%   max(agent answer time, agents x mean answer time / cap).
%% Measured over one loopback connection with 5,000 agents answering uniformly
%% in 0 to 10 s: 1024 streams 30.7 s, 2048 18.8 s, 4096 11.9 s, 8192 10.1 s
%% (25,000 agents: 37.1 s at 4096, 21.7 s at 8192). 4096 brings 5,000 agents
%% within about 2 s of the answer time itself. It is not set higher because the
%% responses of the calls in flight can all be waiting to be written at once
%% (one per stream when agents answer faster than the server reads): 5,000
%% answers of 256 KiB inside 1 s peaked at about 0.98 GB in the connection at
%% 4096 and 1.2 GB at 8192, so the cap is also the bound on that, and 8192
%% doubles it for under 2 s. Beyond 5,000 agents the way forward is more
%% connections or one message per fan-out (#5956), not a larger cap.
-define(MGMT_MAX_CONCURRENT_STREAMS, 4096).
%% Socket options that would move the bind address or port, which `listen' alone
%% decides (and the management-plane posture guard reads).
-define(BIND_SOCKET_OPTS, [ip, ifaddr, fd, port, local]).

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
    first_error([fun() -> check_keys(entry, Entry, ?ENTRY_KEYS, ?LEGACY_ENTRY_KEYS) end,
                 fun() -> check_required(Entry) end,
                 fun() -> check_services(Entry) end,
                 fun() -> check_listen(maps:get(listen, Entry, undefined)) end,
                 fun() -> check_auth_fun(Entry) end,
                 fun() -> check_tls(Entry) end,
                 fun() -> check_origin(Entry) end,
                 fun() -> check_http2(maps:get(http2, Entry, #{})) end,
                 fun() -> check_acceptors(maps:get(acceptors, Entry, undefined)) end,
                 fun() -> check_limits(maps:get(limits, Entry, #{})) end]);
validate(_) ->
    {error, entry_not_a_map}.

%% @doc The TLS socket options of a `tls' map. Mutual TLS by default; TLS 1.2
%% with ECDHE AEAD suites only, chosen by the key type of the certificate
%% unless the map sets `ciphers': ECDSA suites for an EC certificate, RSA suites
%% for an RSA one. A certificate that cannot be read here (it fails when the
%% listener starts, with the reason) gets the EC list.
-spec ssl_opts(map()) -> [ssl:tls_server_option()].
ssl_opts(#{certfile := Cert, keyfile := Key, cacertfile := CaCert} = Tls) ->
    Verify = maps:get(verify, Tls, verify_peer),
    [{certfile, Cert}, {keyfile, Key}, {cacertfile, CaCert},
     {verify, Verify},
     {fail_if_no_peer_cert, maps:get(fail_if_no_peer_cert, Tls, Verify =:= verify_peer)},
     {versions, ['tlsv1.2']},
     {ciphers, maps:get(ciphers, Tls, default_ciphers(Cert))},
     {alpn_preferred_protocols, [<<"h2">>]},
     {honor_cipher_order, true},
     {reuse_sessions, false}].

%% The suites for the key of the first certificate in the file.
default_ciphers(CertFile) ->
    case cert_key_type(CertFile) of
        rsa -> ?CIPHERS_RSA;
        _ -> ?CIPHERS_EC
    end.

cert_key_type(CertFile) ->
    try
        {ok, Pem} = file:read_file(CertFile),
        [Der | _] = [D || {'Certificate', D, not_encrypted} <- public_key:pem_decode(Pem)],
        #'OTPCertificate'{tbsCertificate = Tbs} = public_key:pkix_decode_cert(Der, otp),
        #'OTPSubjectPublicKeyInfo'{algorithm = #'PublicKeyAlgorithm'{algorithm = Oid}} =
            Tbs#'OTPTBSCertificate'.subjectPublicKeyInfo,
        key_type(Oid)
    catch
        _:_ -> unknown
    end.

key_type(?rsaEncryption) -> rsa;
key_type(?'id-RSASSA-PSS') -> rsa;
key_type(?'id-ecPublicKey') -> ec;
key_type(_) -> unknown.

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
%% whole listener rather than leaving a port unserved. The Ref stays in the state
%% on purpose: terminate/2 then stops the listener's entry in ranch_sup too.
%% Ranch restarts a permanent listener supervisor of its own accord; left alone
%% that restart would run beside ours and race it for the name, and the loser's
%% failure can take ranch_sup, and with it every listener of the node, down.
-spec handle_info(term(), map()) -> {noreply, map()} | {stop, listener_down, map()}.
handle_info({'DOWN', Mon, process, _Pid, _Reason}, #{mon := Mon} = State) ->
    {stop, listener_down, State};
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
    Ref = ref(Entry),
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
            logger:info("gateway grpc listener ~p up on port ~p (tls=~p, auth_fun=~p, origin=~p)",
                        [Name, ranch:get_port(Ref), Tls =/= undefined,
                         maps:is_key(auth_fun, Entry),
                         maps:get(mode, maps:get(origin, Entry, #{mode => transport}))]),
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
      %% Ranch's default of 1024 connections would cap the fleet, so the
      %% default here is none; `limits.max_connections' sets a ceiling.
      max_connections => maps:get(max_connections, maps:get(limits, Entry, #{}), infinity),
      handshake_timeout => 10000,
      socket_opts => SocketOpts}.

%% @doc The Cowboy HTTP/2 options of an entry other than the ones the layer
%% owns: the defaults, overridden key by key by its `http2' map.
%%
%% A listener that routes the ManagementService gets ?MGMT_MAX_CONCURRENT_STREAMS
%% (4096) as its stream cap, and ?MGMT_FRAME_RATE as its
%% `max_received_frame_rate'; one that does not keeps Cowboy's own, since its
%% connections are agents' and the stock flood guard is the one to keep there. A
%% combined agent+management listener gets the raised value: it carries the
%% server's fan-out, which the stock value would cut, and it cannot be the
%% network-facing agent edge of a deployment that refuses insecure management
%% (it may not take an auth_fun, so the boot posture guard refuses it off
%% loopback unless allow_insecure_mgmt acknowledges a lab rig). The test is what
%% the entry ROUTES, not management_pb in service_protos (the broad test the
%% posture guard fails closed on): management_pb embeds the AgentService, so an
%% agent-only entry may list it, and an entry that does not route the
%% ManagementService answers its RPCs UNIMPLEMENTED, so no fan-out lands there.
-spec http2_opts(entry()) -> map().
http2_opts(Entry) ->
    Defaults = #{idle_timeout => 600000,
                 max_concurrent_streams => 1024,
                 max_frame_size_received => 16384,
                 linger_timeout => 1000},
    RoleDefaults = case routes_service(Entry, ?MGMT_SERVICE) of
                       true -> Defaults#{max_received_frame_rate => ?MGMT_FRAME_RATE,
                                         max_concurrent_streams => ?MGMT_MAX_CONCURRENT_STREAMS};
                       false -> Defaults
                   end,
    maps:merge(RoleDefaults, maps:get(http2, Entry, #{})).

protocol_opts(Entry, Routes) ->
    Limits = stream_limits(Entry),
    Origin = maps:get(origin, Entry, #{mode => transport}),
    maps:merge(http2_opts(Entry),
               #{stream_handlers => [yuzu_grpc_stream_h],
                 %% Cowboy's per-stream warnings (a message or an exit for a
                 %% stream that has ended), rate-limited and without the term.
                 logger => yuzu_grpc_cowboy_log,
                 env => #{grpc => Routes,
                          %% the closed role the connection's metrics are
                          %% labelled with (yuzu_grpc_stream_h)
                          listener => role(Entry),
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

%% The `limits' the stream handler reads. A listener that routes the
%% ManagementService and does not serve the agent service gets no per-connection
%% memory ceiling unless its `limits' sets one: max_connection_memory_bytes
%% exists to bound an ANONYMOUS peer that opens streams and stalls them
%% half-sent, and the management peer is the pinned server (the auth_fun runs
%% before any stream of it is served), which holds ONE connection and sends a
%% whole fan-out over it. On that connection the ceiling killed the server's
%% connection, every call in flight on it, when the agents of a fan-out answered
%% together with large responses: the derived 16 MiB equals Cowboy's own
%% output-buffer alarm (max_connection_buffer_size, 16000000 bytes), so the VM
%% killed the connection before that alarm could slow the senders, and each
%% stream holds one more response than the alarm counts. Without the ceiling the
%% alarm paces the senders; what one connection can then hold is about 16 MB
%% plus one response per stream in flight (max_concurrent_streams of them). A
%% combined agent+management listener serves anonymous agents and keeps the
%% ceiling (it is a lab rig: the boot guard refuses it off loopback unless
%% allow_insecure_mgmt acknowledges one).
stream_limits(Entry) ->
    Limits = maps:get(limits, Entry, #{}),
    case routes_service(Entry, ?MGMT_SERVICE) andalso not serves_agent(Entry)
         andalso not maps:is_key(max_connection_memory_bytes, Limits) of
        true -> Limits#{max_connection_memory_bytes => infinity};
        false -> Limits
    end.

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

%% The keys of Map must be Allowed. A key of the former grpcbox shape is refused
%% by name with where it went; any other unknown key is refused with the keys
%% that are allowed.
check_keys(Where, Map, Allowed, Legacy) ->
    Extra = maps:keys(Map) -- Allowed,
    case [{K, Hint} || K <- Extra, {LK, Hint} <- Legacy, K =:= LK] of
        [_ | _] = Found ->
            {error, {legacy_keys, Where, Found}};
        [] when Extra =:= [] ->
            ok;
        [] ->
            {error, {unknown_keys, Where, Extra, {allowed, Allowed}}}
    end.

check_required(Entry) ->
    case [Key || Key <- [name, service_protos, services, listen], not maps:is_key(Key, Entry)] of
        [] -> ok;
        Missing -> {error, {missing_keys, Missing}}
    end.

%% The route table is built from these two (yuzu_grpc_route:build/2 takes a list
%% and a map); a wrong type is a refusal here, not a crash in the caller.
check_services(#{service_protos := Protos, services := Services}) ->
    case {proper_list(Protos) andalso lists:all(fun is_atom/1, Protos), is_map(Services)} of
        {true, true} -> ok;
        {false, _} -> {error, bad_service_protos};
        {true, false} -> {error, bad_services}
    end.

check_listen(#{port := Port} = Listen) when is_integer(Port), Port >= 0, Port =< 65535 ->
    first_error([fun() -> check_keys(listen, Listen, ?LISTEN_KEYS, []) end,
                 fun() -> check_ip(maps:get(ip, Listen, {0, 0, 0, 0})) end,
                 fun() -> check_socket_opts(maps:get(socket_opts, Listen, [])) end]);
check_listen(_) ->
    {error, bad_listen}.

check_ip(Ip) ->
    case inet:is_ip_address(Ip) of
        true -> ok;
        false -> {error, bad_listen_ip}
    end.

%% `listen' decides the bind address and port, and the management-plane posture
%% guard reads them there: a socket option that sets them again (the later one
%% wins in the option list) would bind somewhere the guard did not look.
check_socket_opts(Opts) ->
    case proper_list(Opts) of
        true ->
            case [Name || Opt <- Opts, Name <- [socket_opt_name(Opt)],
                          lists:member(Name, ?BIND_SOCKET_OPTS)] of
                [] -> ok;
                Refused -> {error, {listen_socket_opts_set_the_bind, lists:usort(Refused)}}
            end;
        false ->
            {error, bad_listen_socket_opts}
    end.

socket_opt_name(Opt) when is_atom(Opt) -> Opt;
socket_opt_name(Opt) when is_tuple(Opt), tuple_size(Opt) >= 1 -> element(1, Opt);
socket_opt_name(_) -> undefined.

%% The agent listener admits agents that have no certificate yet; an auth_fun
%% refuses every peer without one (yuzu_grpc_stream_h), which would shut the
%% fleet out. Only the management plane authenticates its peer.
check_auth_fun(Entry) ->
    case {maps:get(auth_fun, Entry, undefined), serves_agent(Entry)} of
        {undefined, _} -> ok;
        {_, true} -> {error, auth_fun_on_agent_listener};
        {Fun, false} when is_function(Fun, 1) -> ok;
        {_, false} -> {error, bad_auth_fun}
    end.

%% @doc Whether the entry serves the agent service, in the broad sense the
%% auth_fun refusal needs: agent_pb is among its service_protos (as the
%% management-plane guard identifies its own listener,
%% yuzu_gw_app:is_mgmt_listener/1: never by port) or the AgentService itself is a
%% key of `services'. The second test is not redundant: management_pb embeds the
%% AgentService definition, so `service_protos => [management_pb]' with
%% `services' naming AgentService serves the agent RPCs and would otherwise read
%% as a management-only listener. Total on any term.
-spec serves_agent(term()) -> boolean().
serves_agent(Entry) ->
    serves_proto(Entry, agent_pb) orelse routes_agent(Entry).

%% @doc The Ranch reference of an entry's listener.
-spec ref(entry()) -> {yuzu_grpc, term()}.
ref(#{name := Name}) ->
    {yuzu_grpc, Name}.

%% @doc What a listener is for, as a metric label (a closed set, never the
%% configured name): `agent' when it serves the agent service (a combined
%% agent+management lab listener included), `management' when it routes the
%% ManagementService and not the agent service, `other' otherwise.
-spec role(term()) -> agent | management | other.
role(Entry) ->
    case serves_agent(Entry) of
        true -> agent;
        false ->
            case routes_service(Entry, ?MGMT_SERVICE) of
                true -> management;
                false -> other
            end
    end.

%% @doc Whether the entry routes the AgentService: it is a key of `services'.
%% The strict test, which the boot guard and /readyz ask: an entry that lists
%% agent_pb in its service_protos and maps no service builds a route table that
%% answers every agent RPC UNIMPLEMENTED, so no agent can use it. Total on any
%% term.
-spec routes_agent(term()) -> boolean().
routes_agent(Entry) ->
    routes_service(Entry, ?AGENT_SERVICE).

%% Whether the service is a key of the entry's `services'. Total on any term.
routes_service(#{services := Services}, Service) when is_map(Services) ->
    maps:is_key(Service, Services);
routes_service(_, _) ->
    false.

%% @doc Whether the entry lists the proto module among its service_protos. Total:
%% an entry that is not a map, a list that is not one (or is improper) is false.
-spec serves_proto(term(), atom()) -> boolean().
serves_proto(#{service_protos := Protos}, Proto) ->
    list_member(Proto, Protos);
serves_proto(_, _) ->
    false.

list_member(Item, [Item | _]) -> true;
list_member(Item, [_ | Rest]) -> list_member(Item, Rest);
list_member(_, _) -> false.

%% @doc True for a proper list (the end of an improper one, `[a | b]', is not
%% `[]'). The checks that walk a list from configuration ask it first, so a
%% malformed one is a refusal and not a crash.
-spec proper_list(term()) -> boolean().
proper_list([]) -> true;
proper_list([_ | Rest]) -> proper_list(Rest);
proper_list(_) -> false.

check_tls(Entry) ->
    case maps:get(tls, Entry, undefined) of
        undefined ->
            case maps:is_key(auth_fun, Entry) of
                true -> {error, auth_fun_without_tls};
                false -> ok
            end;
        Tls when is_map(Tls) ->
            first_error([fun() -> check_keys(tls, Tls, ?TLS_KEYS, ?LEGACY_TLS_KEYS) end,
                         fun() -> check_tls_paths(Tls) end,
                         fun() -> check_tls_values(Tls) end]);
        _ ->
            {error, bad_tls}
    end.

check_tls_paths(Tls) ->
    case [Key || Key <- [certfile, keyfile, cacertfile], not has_path(Tls, Key)] of
        [] -> ok;
        Missing -> {error, {tls_incomplete, Missing}}
    end.

check_tls_values(Tls) ->
    case [Key || {Key, Valid} <- [{verify, fun(V) -> V =:= verify_peer orelse V =:= verify_none end},
                                  {fail_if_no_peer_cert, fun is_boolean/1},
                                  {ciphers, fun valid_ciphers/1}],
                 maps:is_key(Key, Tls), not Valid(maps:get(Key, Tls))] of
        [] -> ok;
        Bad -> {error, {bad_tls_values, Bad}}
    end.

valid_ciphers([_ | _] = Ciphers) ->
    proper_list(Ciphers) andalso lists:all(fun(C) -> is_list(C) orelse is_tuple(C) end, Ciphers);
valid_ciphers(_) ->
    false.

has_path(Tls, Key) ->
    case maps:get(Key, Tls, undefined) of
        Path when is_list(Path), Path =/= [] -> true;
        Path when is_binary(Path), Path =/= <<>> -> true;
        _ -> false
    end.

check_acceptors(undefined) -> ok;
check_acceptors(N) when is_integer(N), N > 0 -> ok;
check_acceptors(_) -> {error, bad_acceptors}.

check_limits(Limits) when is_map(Limits) ->
    case check_keys(limits, Limits, ?LIMIT_KEYS, []) of
        ok ->
            case [Key || {Key, Value} <- maps:to_list(Limits), not valid_limit(Key, Value)] of
                [] -> ok;
                Bad -> {error, {bad_limits, Bad}}
            end;
        {error, _} = Error ->
            Error
    end;
check_limits(_) ->
    {error, bad_limits}.

valid_limit(max_message_bytes, N) -> is_integer(N) andalso N > 0;
valid_limit(send_timeout_ms, N) -> N =:= infinity orelse (is_integer(N) andalso N > 0);
valid_limit(max_connections, N) -> N =:= infinity orelse (is_integer(N) andalso N > 0);
valid_limit(max_connection_memory_bytes, N) ->
    N =:= infinity orelse (is_integer(N) andalso N >= ?YUZU_GRPC_MIN_CONN_MEMORY_BYTES);
valid_limit(request_timeout_ms, N) -> N =:= infinity orelse (is_integer(N) andalso N > 0).

check_origin(Entry) ->
    case maps:get(origin, Entry, undefined) of
        undefined ->
            ok;
        Origin ->
            case origin_sources_walkable(Origin) of
                true ->
                    case yuzu_grpc_origin:validate(Origin) of
                        ok -> check_origin_auth(Origin, maps:is_key(auth_fun, Entry));
                        {error, _} = Error -> Error
                    end;
                false ->
                    {error, {bad_origin_sources, improper_list}}
            end
    end.

%% yuzu_grpc_origin:validate/1 walks `sources' as a proper list; one that is not
%% is refused here instead of crashing the check.
origin_sources_walkable(#{sources := Sources}) when is_list(Sources) ->
    proper_list(Sources);
origin_sources_walkable(_) ->
    true.

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
        [] -> check_keys(http2, Http2, ?HTTP2_KEYS, []);
        Reserved -> {error, {reserved_http2_options, Reserved}}
    end;
check_http2(_) ->
    {error, bad_http2}.
