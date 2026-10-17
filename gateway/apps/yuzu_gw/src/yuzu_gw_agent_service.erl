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
%%% Calling conventions (yuzu_grpc_runner):
%%%   Unary:         Module:Fun(Ctx, Request) -> {ok, Response, Ctx} | {grpc_error, {Status, Msg}}
%%%   Server stream: Module:Fun(Request, Stream) -> ok | {grpc_error, {Status, Msg}}
%%%   Bidi:          Module:Fun(Ref, Stream)  -> ok | {grpc_error, {Status, Msg}}
%%%                  (loops until the stream ends)
%%% A handler may also throw({grpc_error, {Status, Msg}}) from anywhere.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_service).

-include("yuzu_grpc.hrl").

%% service callbacks (yuzu_grpc_runner)
-export([register/2,
         subscribe/2,
         heartbeat/2,
         execute_command/2,
         report_inventory/2]).

%% The reservation guard's process body (proc_lib entry point, see guard/1).
-export([reservation_guard/2]).

%% The bound on a Register's agent id, the same condition the server applies in
%% GatewayUpstreamServiceImpl::ProxyRegister (and in the direct Register) before
%% anything else: `info.agent_id().empty() || info.agent_id().size() >
%% auth::kMaxAgentIdLength' (server/core/src/gateway_service_impl.cpp, the check
%% under the "agent_id length bound" comment; kMaxAgentIdLength = 256 in
%% server/core/include/yuzu/server/auth.hpp). Bytes, not characters. The gateway
%% forwards the agent's RegisterRequest as it is, so without the same bound here
%% a request the server refuses as wrong would be forwarded, and a request fault
%% must not count against the circuit breaker. A change to the server's constant
%% must change this one.
-define(MAX_AGENT_ID_BYTES, 256).
%% The proxied-call refusals answered UNAVAILABLE (see retryable_error/2).
-define(RETRYABLE(Reason), (Reason =:= circuit_open orelse Reason =:= overloaded orelse
                            Reason =:= deadline orelse Reason =:= stopping)).

%%--------------------------------------------------------------------
%% Register — proxy to C++ server
%%--------------------------------------------------------------------

register(Ctx, RegisterReq) ->
    case check_agent_id(RegisterReq) of
        ok ->
            register_checked(Ctx, RegisterReq);
        {refused, Size} ->
            %% Answered here, before a reservation and before any upstream call:
            %% the server would answer the same status, and the gateway used to
            %% count that answer as a failure of the upstream (see
            %% ?MAX_AGENT_ID_BYTES). The line carries the size, never the id.
            telemetry:execute([yuzu, gw, register, refused],
                              #{count => 1}, #{reason => <<"agent_id_length">>}),
            yuzu_gw_safe_call:warn_limited(
              register_refused,
              "Register refused: the agent id is empty or longer than ~b bytes (size ~b bytes)",
              [?MAX_AGENT_ID_BYTES, Size]),
            {grpc_error, {?GRPC_STATUS_INVALID_ARGUMENT,
                          <<"agent_id length exceeds 256 bytes or is empty">>}}
    end.

register_checked(Ctx, RegisterReq0) ->
    %% The address of the agent, as the gateway decided it (yuzu_grpc_origin):
    %% the TCP peer, or the address a TRUSTED proxy vouched for. It is put in
    %% RegisterRequest.gateway_observed_peer, which is gateway-authoritative: the
    %% field is set here whatever the agent put in it, to an empty value when the
    %% gateway has no observation (a trusted proxy gave no usable address). The
    %% server records it as the agent's source_ip and trusts it on this path, so
    %% passing the agent's own value through would let an agent choose the
    %% address its registration is attributed to.
    Origin = origin_text(Ctx),
    RegisterReq = RegisterReq0#{gateway_observed_peer => Origin},
    PeerAddr = case Origin of
        <<>> -> <<"unknown">>;
        _ -> Origin
    end,

    %% A slot on the connection is RESERVED before the registration goes
    %% upstream: the check and the claim are one step in the registry, so
    %% concurrent Registers on one connection admit at most the quota and a
    %% refused one leaves nothing on the server. The reservation becomes the
    %% pending row in store_pending/3 and is released here on every other way out.
    %% This process can be killed while it waits for the upstream (the stream was
    %% reset, its deadline passed, the connection closed), and a kill skips the
    %% `after' clause: a guard process watching this one releases the reservation
    %% then, promptly (see guard/1).
    AgentInfo0 = maps:get(info, RegisterReq, maps:get(<<"info">>, RegisterReq, #{})),
    case yuzu_gw_registry:reserve_session(yuzu_gw_conn:key_from_ctx(Ctx),
                                          extract_agent_id(AgentInfo0)) of
        {ok, Reservation} ->
            Guard = guard(Reservation),
            try
                register_upstream(Ctx, RegisterReq, PeerAddr, Reservation)
            after
                yuzu_gw_registry:release_session(Reservation),
                disarm(Guard)
            end;
        {error, session_limit} ->
            session_limit_error();
        {error, registry_unavailable} ->
            %% Nothing was proxied: the session could not be matched by Subscribe.
            logger:warning("Register failed: registry_unavailable"),
            {grpc_error, {?GRPC_STATUS_INTERNAL,
                          <<"Registration failed: registry unavailable">>}}
    end.

%% A process that releases Reservation when the calling process dies before it
%% disarms the guard. Releasing is idempotent and keyed by the reservation's own
%% reference, so a guard that fires after the reservation became a pending row
%% (the reservation is gone by then) removes nothing. The guard is not linked:
%% it must outlive the process it watches.
guard(undefined) ->
    undefined;
guard(Reservation) ->
    proc_lib:spawn(?MODULE, reservation_guard, [self(), Reservation]).

disarm(undefined) ->
    ok;
disarm(Guard) ->
    Guard ! {disarm, self()},
    ok.

%% @private
reservation_guard(Watched, Reservation) ->
    Mon = erlang:monitor(process, Watched),
    receive
        {disarm, Watched} ->
            erlang:demonitor(Mon, [flush]),
            ok;
        {'DOWN', Mon, process, Watched, _Reason} ->
            yuzu_gw_registry:release_session(Reservation)
    end.

%% The origin address of a call as text (a bare IP), or <<>> when it has none.
origin_text(Ctx) ->
    case yuzu_grpc:origin(Ctx) of
        {Ip, _How} -> yuzu_grpc_origin:format(Ip);
        undefined -> <<>>
    end.

register_upstream(Ctx, RegisterReq, PeerAddr, Reservation) ->
    case yuzu_gw_upstream:proxy_register(RegisterReq, upstream_opts(Ctx)) of
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
                                  registered_at => erlang:system_time(millisecond)},
                                Reservation) of
                ok ->
                    logger:info("Agent ~s registered, awaiting Subscribe",
                                [yuzu_gw_env:log_text(AgentId)]),
                    {ok, Response, Ctx};
                {error, superseded} ->
                    %% A newer Register of this agent id on the connection
                    %% committed first: this session will never be matched by
                    %% Subscribe, and the registry is healthy. The agent retries
                    %% on any non-OK status; UNAVAILABLE is the retryable class
                    %% (the session cap answers it too), not a server fault.
                    logger:info("Register superseded by a newer registration"),
                    {grpc_error, {?GRPC_STATUS_UNAVAILABLE,
                                  <<"Registration superseded by a newer registration">>}};
                {error, registry_unavailable} ->
                    %% The registry is not running: the session cannot be
                    %% matched by Subscribe, so the agent must register again.
                    logger:warning("Register failed: registry_unavailable"),
                    {grpc_error, {?GRPC_STATUS_INTERNAL,
                                  <<"Registration failed: registry unavailable">>}};
                {error, session_limit} ->
                    session_limit_error()
            end;

        {ok, _NotAMap} ->
            %% An OK whose message is not a decoded response: the same failure
            %% as an RPC error, with no body in the log or in the error.
            yuzu_gw_safe_call:warn_limited(
              register_failed, "Upstream Register failed: answer is not a response message", []),
            {grpc_error, {?GRPC_STATUS_INTERNAL,
                          <<"Upstream registration failed: malformed response">>}};

        {error, Reason} when ?RETRYABLE(Reason) ->
            retryable_error(<<"Registration">>, Reason);

        {error, Reason} ->
            yuzu_gw_safe_call:warn_limited(register_failed,
                                           "Upstream Register failed: ~p", [Reason]),
            {grpc_error, {?GRPC_STATUS_INTERNAL,
                          iolist_to_binary(
                              io_lib:format("Upstream registration failed: ~p", [Reason]))}}
    end.

%%--------------------------------------------------------------------
%% Subscribe — terminate bidi stream locally
%%
%% Called as subscribe(Ref, Stream) in its own process, where:
%%   Ref    = make_ref() used as the mailbox key for incoming agent data
%%   Stream = the stream handle (opaque; use the yuzu_grpc_stream API)
%%
%% Incoming data (agent -> gateway) arrives as {Ref, DecodedMap} messages.
%% To send data (gateway -> agent) use yuzu_grpc_stream:send(Stream, Msg).
%% Stream end is signalled as {Ref, eos}.
%%--------------------------------------------------------------------

subscribe(Ref, State) ->
    Ctx = yuzu_grpc_stream:ctx(State),
    Headers = yuzu_grpc:headers(Ctx),
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
                                   [yuzu_gw_env:log_text(SessionId)]),
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

                    %% The connection's session quota is asked before the agent
                    %% process is started: a refusal then costs no process and
                    %% no crash report. The registry asks again at the live
                    %% insert, where the decision is made.
                    case yuzu_gw_registry:session_admission(maps:get(conn_key, Args),
                                                            AgentId) of
                        ok                     -> ok;
                        {error, session_limit} -> throw(session_limit_error())
                    end,

                    case yuzu_gw_agent_sup:start_agent(Args) of
                        {ok, AgentPid} ->
                            stream_loop(Ref, State, AgentPid);

                        {error, session_limit} ->
                            %% Counted and logged by the registry (one WARN per
                            %% second, naming only the cap).
                            throw(session_limit_error());

                        {error, Reason} ->
                            logger:error("Failed to start agent process for ~s: ~p",
                                         [yuzu_gw_env:log_text(AgentId), Reason]),
                            throw({grpc_error, {?GRPC_STATUS_INTERNAL,
                                                <<"Internal: agent process start failed">>}})
                    end
            end
    end.

%% Subscribe stream loop: relay messages between the stream and the agent process.
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
                    yuzu_grpc_stream:send(State, Cmd),
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

execute_command(_CommandReq, _Stream) ->
    {grpc_error, {?GRPC_STATUS_UNIMPLEMENTED,
                  <<"Use Subscribe for command delivery">>}}.

%%--------------------------------------------------------------------
%% ReportInventory — proxy upstream
%%--------------------------------------------------------------------

report_inventory(Ctx, InventoryReport) ->
    case yuzu_gw_upstream:proxy_inventory(InventoryReport, upstream_opts(Ctx)) of
        {ok, Response} ->
            {ok, Response, Ctx};
        {error, Reason} when ?RETRYABLE(Reason) ->
            retryable_error(<<"Inventory report">>, Reason);
        {error, Reason} ->
            yuzu_gw_safe_call:warn_limited(inventory_failed,
                                           "Upstream ReportInventory failed: ~p", [Reason]),
            {grpc_error, {?GRPC_STATUS_INTERNAL,
                          iolist_to_binary(
                              io_lib:format("Upstream inventory report failed: ~p", [Reason]))}}
    end.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

%% The options of a proxied call: the handler's deadline, so the call upstream,
%% and any wait for a permit before it, ends before the agent stops waiting. The
%% stream handler ends the handler at the agent's grpc-timeout less min(1000,
%% Ms div 10) (yuzu_grpc_stream_h:deadline_ms/1 on the EDGE branch; the same
%% formula is applied here until that is merged), counted from when it armed
%% the timer; counting from now instead leans late by the request-receive time,
%% which the upstream's own margin (DEADLINE_MARGIN_MS) covers. No usable
%% header: the upstream's default budget applies.
upstream_opts(Ctx) ->
    case yuzu_grpc_frame:parse_timeout(maps:get(<<"grpc-timeout">>, yuzu_grpc:headers(Ctx),
                                                undefined)) of
        {ok, Ms} -> #{deadline => erlang:monotonic_time(millisecond) + handler_deadline_ms(Ms)};
        _        -> #{}
    end.

handler_deadline_ms(Ms) ->
    Ms - min(1000, Ms div 10).

%% A refusal that means "try again later", answered UNAVAILABLE (the retryable
%% gRPC status the agent backs off on) with a fixed message per reason:
%%   circuit_open  the server is unreachable (the breaker is open)
%%   overloaded    every permit is held and the wait queue is full
%%   deadline      the agent's deadline passed while it waited for a permit
%%   stopping      this gateway is stopping (planned)
%% Not logged per request: the regulator counts them
%% (yuzu_gw_upstream_permit_refused_total) and the breaker logs its own moves.
retryable_error(What, Reason) ->
    Why = case Reason of
              circuit_open -> <<"the server is unreachable">>;
              overloaded   -> <<"the gateway is busy">>;
              deadline     -> <<"the gateway could not reach the server in time">>;
              stopping     -> <<"the gateway is stopping">>
          end,
    {grpc_error, {?GRPC_STATUS_UNAVAILABLE, <<What/binary, " not forwarded: ", Why/binary,
                                              "; retry">>}}.

%% The answer to a session refused by the per-connection quota: UNAVAILABLE, the
%% retryable status (the agent backs off and registers again; the quota frees as
%% the connection's other sessions end). No request in it, and no id.
session_limit_error() ->
    {grpc_error, {?GRPC_STATUS_UNAVAILABLE,
                  <<"Too many agent sessions on this connection">>}}.

%% The bound of ?MAX_AGENT_ID_BYTES, on the id as the request carries it, before
%% any fallback: a missing `info', a missing id and a value that is not a binary
%% are all "empty" (a request that came off the wire always has the id, <<>> when
%% the agent sent none; only a hand built request can lack it). Returns the size
%% to report (0 for a value that is not a binary).
check_agent_id(RegisterReq) when is_map(RegisterReq) ->
    Info = maps:get(info, RegisterReq, maps:get(<<"info">>, RegisterReq, #{})),
    Raw = case is_map(Info) of
              true  -> maps:get(<<"agent_id">>, Info, maps:get(agent_id, Info, undefined));
              false -> undefined
          end,
    case Raw of
        Id when is_binary(Id), byte_size(Id) >= 1, byte_size(Id) =< ?MAX_AGENT_ID_BYTES ->
            ok;
        Id when is_binary(Id) ->
            {refused, byte_size(Id)};
        _NotABinary ->
            {refused, 0}
    end;
check_agent_id(_NotAMap) ->
    {refused, 0}.

%% The id as a log and registry key once the bound has passed. The fallback is
%% only reachable for an `info' without the id, which check_agent_id/1 refuses.
extract_agent_id(AgentInfo) ->
    maps:get(<<"agent_id">>, AgentInfo,
             maps:get(agent_id, AgentInfo, <<"unknown">>)).
