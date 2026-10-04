%%%-------------------------------------------------------------------
%%% @doc Agent-facing gRPC service — implements AgentService.
%%%
%%% Agents connect here using the exact same proto they already use.
%%% Zero agent-side changes required.
%%%
%%% - Register: proxied upstream to C++ server
%%% - Subscribe: terminated locally, one yuzu_gw_agent process spawned
%%% - Heartbeat: admitted per session and connection, then buffered for
%%%   batch upstream delivery
%%% - ReportInventory: proxied upstream
%%% - ExecuteCommand: not used (Subscribe is the primary channel)
%%%
%%% grpcbox calling conventions (v0.17.1):
%%%   Unary:   Module:Fun(Ctx, Request)   -> {ok, Response, Ctx} | {grpc_error, {Status, Msg}}
%%%   Bidi:    Module:Fun(Ref, State)     -> any()  (loops until stream ends)
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_service).

-include_lib("grpcbox/include/grpcbox.hrl").

%% grpcbox service callbacks
-export([register/2,
         subscribe/2,
         heartbeat/2,
         execute_command/2,
         report_inventory/2]).

%%--------------------------------------------------------------------
%% Register — proxy to C++ server
%%--------------------------------------------------------------------

register(Ctx, RegisterReq) ->
    Headers = grpcbox_metadata:from_incoming_ctx(Ctx),
    PeerAddr = maps:get(<<":authority">>, Headers,
                        maps:get(<<"x-forwarded-for">>, Headers, <<"unknown">>)),

    case yuzu_gw_upstream:proxy_register(RegisterReq) of
        {ok, Response} when is_map(Response) ->
            %% Stash the session_id and agent_info; the agent process is
            %% created when Subscribe arrives (matched by session_id).
            SessionId = maps:get(session_id, Response,
                                 maps:get(<<"session_id">>, Response, undefined)),
            AgentInfo = maps:get(info, RegisterReq,
                                 maps:get(<<"info">>, RegisterReq, #{})),
            AgentId = extract_agent_id(AgentInfo),

            %% Store pending registration for Subscribe matching.
            %% register_req is the verbatim RegisterRequest; it is carried
            %% through to the agent process so the registry can stash it
            %% for upstream-reconnect replay. conn_key is the connection
            %% this Register arrived on: until Subscribe is admitted, a
            %% heartbeat for the pending session is admitted only on it.
            case yuzu_gw_registry:store_pending(SessionId,
                                #{agent_id  => AgentId,
                                  agent_info => AgentInfo,
                                  register_req => RegisterReq,
                                  peer_addr  => PeerAddr,
                                  conn_key   => yuzu_gw_conn:key_from_ctx(Ctx),
                                  registered_at => erlang:system_time(millisecond)}) of
                ok ->
                    logger:info("Agent ~s registered, awaiting Subscribe", [AgentId]),
                    {ok, Response, Ctx};
                {error, registry_unavailable} ->
                    %% The registry is not running: the session cannot be
                    %% matched by Subscribe, so the agent must register again.
                    logger:warning("Register failed: registry_unavailable"),
                    {grpc_error, {?GRPC_STATUS_INTERNAL,
                                  <<"Registration failed: registry unavailable">>}}
            end;

        {ok, _NotAMap} ->
            %% An OK whose message is not a decoded response: the same failure
            %% as an RPC error, with no body in the log or in the error.
            logger:warning("Upstream Register failed: answer is not a response message"),
            {grpc_error, {?GRPC_STATUS_INTERNAL,
                          <<"Upstream registration failed: malformed response">>}};

        {error, Reason} ->
            logger:warning("Upstream Register failed: ~p", [Reason]),
            {grpc_error, {?GRPC_STATUS_INTERNAL,
                          iolist_to_binary(
                              io_lib:format("Upstream registration failed: ~p", [Reason]))}}
    end.

%%--------------------------------------------------------------------
%% Subscribe — terminate bidi stream locally
%%
%% grpcbox calls this as subscribe(Ref, State) where:
%%   Ref   = make_ref() used as the mailbox key for incoming agent data
%%   State = grpcbox_stream:state() (opaque record; use grpcbox_stream API)
%%
%% Incoming data (agent -> gateway) arrives as {Ref, DecodedMap} messages.
%% To send data (gateway -> agent) use grpcbox_stream:send(Msg, State).
%% Stream end is signalled as {Ref, eos}.
%%--------------------------------------------------------------------

subscribe(Ref, State) ->
    Ctx = grpcbox_stream:ctx(State),
    Headers = grpcbox_metadata:from_incoming_ctx(Ctx),
    SessionId = maps:get(<<"x-yuzu-session-id">>, Headers, undefined),

    case SessionId of
        undefined ->
            logger:warning("Subscribe: missing x-yuzu-session-id header"),
            throw({grpc_error, {?GRPC_STATUS_INVALID_ARGUMENT,
                                <<"Missing x-yuzu-session-id header">>}});
        _ ->
            case yuzu_gw_registry:take_pending(SessionId) of
                {error, registry_unavailable} ->
                    logger:warning("Subscribe failed: registry_unavailable"),
                    throw({grpc_error, {?GRPC_STATUS_INTERNAL,
                                        <<"Internal: registry unavailable">>}});

                undefined ->
                    logger:warning("Subscribe: no pending registration for session ~s",
                                   [SessionId]),
                    throw({grpc_error, {?GRPC_STATUS_NOT_FOUND,
                                        <<"No pending registration for session">>}});

                #{agent_id := AgentId, agent_info := AgentInfo,
                  peer_addr := PeerAddr} = Pending ->

                    %% register_req carries the verbatim RegisterRequest.
                    %% maps:get/3 (not a match clause) so a pending entry
                    %% written by a pre-upgrade Register still resolves.
                    RegisterReq = maps:get(register_req, Pending, #{}),

                    %% Spawn the agent process — it owns this stream.
                    %% We pass stream_pid=self() so the agent process sends
                    %% commands back to us via {send_command, Cmd} messages.
                    %% conn_key is the connection carrying THIS Subscribe
                    %% stream: the session is bound to it for the life of
                    %% the agent process (heartbeat admission).
                    Args = #{agent_id     => AgentId,
                             session_id   => SessionId,
                             stream_pid   => self(),
                             agent_info   => AgentInfo,
                             register_req => RegisterReq,
                             peer_addr    => PeerAddr,
                             conn_key     => yuzu_gw_conn:key_from_stream(State)},

                    case yuzu_gw_agent_sup:start_agent(Args) of
                        {ok, AgentPid} ->
                            stream_loop(Ref, State, AgentPid);

                        {error, Reason} ->
                            logger:error("Failed to start agent process for ~s: ~p",
                                         [AgentId, Reason]),
                            throw({grpc_error, {?GRPC_STATUS_INTERNAL,
                                                <<"Internal: agent process start failed">>}})
                    end
            end
    end.

%% Subscribe stream loop: relay messages between grpcbox and the agent process.
%%
%% Backpressure: before writing a command to the HTTP/2 stream, we check
%% our own message queue length. If it exceeds the threshold (configurable
%% via backpressure_threshold, default 1000), we emit a telemetry event
%% and skip the send to prevent unbounded mailbox growth under load.

stream_loop(Ref, State, AgentPid) ->
    receive
        {Ref, eos} ->
            %% Agent disconnected (gRPC stream closed by client).
            AgentPid ! stream_closed,
            ok;

        {Ref, DataFromAgent} ->
            %% Data from the agent (CommandResponse frame).
            AgentPid ! {stream_data, DataFromAgent},
            stream_loop(Ref, State, AgentPid);

        {send_command, Cmd} ->
            %% Command from the agent gen_statem to send to the agent.
            %% Check backpressure before writing to stream.
            case check_backpressure() of
                ok ->
                    grpcbox_stream:send(Cmd, State),
                    stream_loop(Ref, State, AgentPid);
                {backpressure, QueueLen} ->
                    %% H13: Log and count dropped commands instead of dropping silently.
                    CmdId = maps:get(<<"command_id">>, Cmd,
                                     maps:get(command_id, Cmd, <<"unknown">>)),
                    logger:warning("Backpressure: dropping command ~s (queue_len=~B)",
                                   [CmdId, QueueLen]),
                    telemetry:execute([yuzu, gw, stream, command_dropped],
                                      #{count => 1},
                                      #{stream_pid => self(), queue_len => QueueLen,
                                        command_id => CmdId}),
                    stream_loop(Ref, State, AgentPid)
            end;

        close_stream ->
            %% Agent process requested graceful disconnect.
            ok
    end.

%% @doc Check if our message queue is too deep; emit telemetry if so.
check_backpressure() ->
    Threshold = application:get_env(yuzu_gw, backpressure_threshold, 1000),
    case process_info(self(), message_queue_len) of
        {message_queue_len, Len} when Len > Threshold ->
            telemetry:execute([yuzu, gw, stream, backpressure],
                              #{queue_len => Len},
                              #{stream_pid => self()}),
            {backpressure, Len};
        _ ->
            ok
    end.

%%--------------------------------------------------------------------
%% Heartbeat — buffer for batch upstream delivery
%%--------------------------------------------------------------------

%% Admitted only for a session this node holds, on the connection that
%% opened it (see yuzu_gw_heartbeat_admission). Every rejection is the same
%% NOT_FOUND "unknown session" the agent already recovers from by
%% re-registering; a rejected heartbeat is never queued.
heartbeat(Ctx, HeartbeatReq) ->
    SessionId = case is_map(HeartbeatReq) of
        true  -> maps:get(session_id, HeartbeatReq, undefined);
        false -> undefined
    end,
    case yuzu_gw_heartbeat_admission:admit(Ctx, SessionId) of
        ok ->
            yuzu_gw_heartbeat_buffer:queue_heartbeat(HeartbeatReq),

            %% Respond immediately — the agent doesn't need to wait for upstream ack.
            Response = #{
                acknowledged => true,
                server_time  => #{millis_epoch => erlang:system_time(millisecond)},
                pending_commands => []
            },
            {ok, Response, Ctx};
        rejected ->
            {grpc_error, {?GRPC_STATUS_NOT_FOUND, <<"unknown session">>}}
    end.

%%--------------------------------------------------------------------
%% ExecuteCommand — not used (Subscribe is the primary channel)
%%--------------------------------------------------------------------

execute_command(_Ctx, _CommandReq) ->
    {grpc_error, {?GRPC_STATUS_UNIMPLEMENTED,
                  <<"Use Subscribe for command delivery">>}}.

%%--------------------------------------------------------------------
%% ReportInventory — proxy upstream
%%--------------------------------------------------------------------

report_inventory(Ctx, InventoryReport) ->
    case yuzu_gw_upstream:proxy_inventory(InventoryReport) of
        {ok, Response} ->
            {ok, Response, Ctx};
        {error, Reason} ->
            logger:warning("Upstream ReportInventory failed: ~p", [Reason]),
            {grpc_error, {?GRPC_STATUS_INTERNAL,
                          iolist_to_binary(
                              io_lib:format("Upstream inventory report failed: ~p", [Reason]))}}
    end.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

extract_agent_id(AgentInfo) ->
    maps:get(<<"agent_id">>, AgentInfo,
             maps:get(agent_id, AgentInfo, <<"unknown">>)).
