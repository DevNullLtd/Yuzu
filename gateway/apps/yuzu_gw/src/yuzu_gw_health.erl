%%%-------------------------------------------------------------------
%%% @doc HTTP health and readiness endpoint for Kubernetes / load
%%% balancer integration.
%%%
%%% Listens on a configurable port (default 8081) and responds to:
%%%   GET /healthz — liveness probe (200 if process is responding)
%%%   GET /readyz  — readiness probe (200 if all core processes alive and
%%%                  every configured gRPC listener is running, 503 if any
%%%                  is down or circuit breaker is open)
%%%
%%% Readiness also requires the registry's session index table: without it
%%% every heartbeat is rejected. It requires every listener of
%%% {yuzu_gw, grpc_listeners} to be running in Ranch (the gateway answers nothing
%%% on a port whose listener is down, and /healthz alone would still say 200),
%%% at least one of them routing the AgentService (a key of its `services', the
%%% rule the boot guard applies), and is not ready when none is configured unless
%%% {yuzu_gw, allow_no_listeners} is the literal `true' (which also excuses the
%%% absence of an agent listener, as it does at boot). The check asks Ranch
%%% for the listener's status; it does not connect to the port.
%%%
%%% Designed to coexist with the Prometheus /metrics endpoint (port 9568).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_health).
-behaviour(gen_server).

%% API
-export([start_link/0, port/0]).
-export([check_upstream_tls_files/0]). %% for testing

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(SERVER, ?MODULE).
-define(DEFAULT_PORT, 8081).

-record(state, {
    listen_sock :: gen_tcp:socket()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% Returns the actual port the health endpoint is listening on. Useful
%% when the configured port is 0 (OS-assigned ephemeral), as is the case
%% in eunit tests that need to avoid colliding with whatever already owns
%% a fixed port on the host (Windows dev tools squatting on 18080 was
%% the trigger — 302 instead of 200 because the test was hitting a
%% different HTTP server bound to the same port).
-spec port() -> {ok, inet:port_number()} | {error, term()}.
port() ->
    gen_server:call(?SERVER, get_port, 5000).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Port = application:get_env(yuzu_gw, health_port, ?DEFAULT_PORT),
    case gen_tcp:listen(Port, [
        binary,
        {active, false},
        {reuseaddr, true},
        {backlog, 32}
    ]) of
        {ok, LSock} ->
            logger:info("Health endpoint listening on port ~b (/healthz, /readyz)", [Port]),
            self() ! accept,
            {ok, #state{listen_sock = LSock}};
        {error, Reason} ->
            logger:error("Health endpoint failed to listen on port ~b: ~p", [Port, Reason]),
            {stop, {listen_failed, Reason}}
    end.

handle_call(get_port, _From, #state{listen_sock = LSock} = State) ->
    {reply, inet:port(LSock), State};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(accept, #state{listen_sock = LSock} = State) ->
    case gen_tcp:accept(LSock, 1000) of
        {ok, Sock} ->
            _ = handle_request(Sock),
            gen_tcp:close(Sock),
            self() ! accept,
            {noreply, State};
        {error, timeout} ->
            self() ! accept,
            {noreply, State};
        {error, closed} ->
            {stop, normal, State};
        {error, Reason} ->
            logger:warning("Health endpoint accept error: ~p", [Reason]),
            self() ! accept,
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, #state{listen_sock = LSock}) ->
    gen_tcp:close(LSock),
    ok.

%%%===================================================================
%%% Internal — HTTP request handling
%%%===================================================================

handle_request(Sock) ->
    case gen_tcp:recv(Sock, 0, 5000) of
        {ok, Data} ->
            Path = extract_path(Data),
            {Status, Body} = route(Path),
            send_response(Sock, Status, Body);
        {error, _} ->
            ok
    end.

route(<<"/healthz">>) -> health_check();
route(<<"/readyz">>)  -> readiness_check();
route(_)              -> {404, <<"{\"status\":\"not_found\"}">>}.

%% @doc Liveness: if this process can respond, the gateway is alive.
health_check() ->
    Node = atom_to_binary(node(), utf8),
    {200, <<"{\"status\":\"ok\",\"node\":\"", Node/binary, "\"}">>}.

%% @doc Readiness: all core processes must be alive and circuit must not be open.
readiness_check() ->
    Checks = [
        check_process(<<"registry">>, yuzu_gw_registry),
        check_session_index(),
        check_process(<<"upstream">>, yuzu_gw_upstream),
        check_process(<<"agent_sup">>, yuzu_gw_agent_sup),
        check_process(<<"router">>, yuzu_gw_router),
        check_listeners(),
        check_upstream_tls_files(),
        check_circuit_breaker()
    ],
    AllOk = lists:all(fun({_, V}) -> V end, Checks),
    ChecksJson = build_checks_json(Checks),
    Status = case AllOk of true -> <<"ready">>; false -> <<"not_ready">> end,
    Body = <<"{\"status\":\"", Status/binary, "\",\"checks\":{", ChecksJson/binary, "}}">>,
    case AllOk of
        true  -> {200, Body};
        false -> {503, Body}
    end.

check_process(Name, RegisteredName) ->
    case whereis(RegisteredName) of
        undefined -> {Name, false};
        Pid       -> {Name, erlang:is_process_alive(Pid)}
    end.

%% Heartbeat admission reads the registry's session index; without the table
%% every heartbeat is rejected, so the gateway is not ready even though the
%% registry process is alive.
check_session_index() ->
    {<<"sessions_index">>, yuzu_gw_registry:session_index_available()}.

check_listeners() ->
    {<<"listeners">>, listeners_ready(application:get_env(yuzu_gw, grpc_listeners, []))}.

listeners_ready([]) ->
    allow_no_listeners();
listeners_ready([_ | _] = Listeners) ->
    yuzu_grpc_listener:proper_list(Listeners)
        andalso lists:all(fun listener_running/1, Listeners)
        andalso (lists:any(fun yuzu_grpc_listener:routes_agent/1, Listeners)
                 orelse allow_no_listeners());
listeners_ready(_) ->
    false.

allow_no_listeners() ->
    application:get_env(yuzu_gw, allow_no_listeners, false) =:= true.

listener_running(#{name := Name}) ->
    try ranch:get_status({yuzu_grpc, Name}) =:= running
    catch _:_ -> false
    end;
listener_running(_) ->
    false.

%% Not ready while any upstream channel's most recent connection attempt failed
%% because its TLS options are unusable (a missing, empty or wrong CA, certificate
%% or key file; yuzu_grpc_client_channel:config_error/1). Such a gateway can reach
%% no server, and the breaker above stays closed until five calls have failed. A
%% table read, never a call into the channel, so a slow upstream cannot hold it.
check_upstream_tls_files() ->
    Names = case yuzu_grpc_client_config:from_env() of
                {ok, Channels} -> [N || #{name := N} <- Channels];
                {error, _}     -> []
            end,
    {<<"upstream_tls_files">>,
     lists:all(fun(N) -> yuzu_grpc_client_channel:config_error(N) =:= none end, Names)}.

%% Read from the state the upstream process publishes, never by a call into it:
%% a call queues behind the RPC in progress, so against a slow server it waited
%% out its 5 s timeout and /readyz answered 503 with the breaker closed (#5680).
%% Not running is not ready: circuit_state_now/0 then exits, as a call would.
check_circuit_breaker() ->
    try
        case yuzu_gw_upstream:circuit_state_now() of
            closed    -> {<<"circuit_breaker">>, true};
            half_open -> {<<"circuit_breaker">>, true};  % allowing probes
            open      -> {<<"circuit_breaker">>, false}
        end
    catch
        _:_ -> {<<"circuit_breaker">>, false}
    end.

build_checks_json(Checks) ->
    Pairs = lists:map(fun({Name, Val}) ->
        V = case Val of true -> <<"true">>; false -> <<"false">> end,
        <<"\"", Name/binary, "\":", V/binary>>
    end, Checks),
    iolist_to_binary(lists:join(<<",">>, Pairs)).

send_response(Sock, Status, Body) ->
    StatusLine = case Status of
        200 -> <<"HTTP/1.1 200 OK\r\n">>;
        503 -> <<"HTTP/1.1 503 Service Unavailable\r\n">>;
        _   -> <<"HTTP/1.1 404 Not Found\r\n">>
    end,
    Len = integer_to_binary(byte_size(Body)),
    Response = [StatusLine,
                <<"Content-Type: application/json\r\n">>,
                <<"Connection: close\r\n">>,
                <<"Content-Length: ", Len/binary, "\r\n">>,
                <<"\r\n">>,
                Body],
    gen_tcp:send(Sock, Response).

extract_path(Data) ->
    %% Parse "GET /path HTTP/1.1\r\n..."
    case binary:split(Data, <<" ">>) of
        [_Method, Rest] ->
            case binary:split(Rest, <<" ">>) of
                [Path | _] -> Path;
                _          -> <<"/">>
            end;
        _ -> <<"/">>
    end.
