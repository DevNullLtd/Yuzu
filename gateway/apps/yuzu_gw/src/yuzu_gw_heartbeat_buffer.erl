%%%-------------------------------------------------------------------
%%% @doc Dedicated heartbeat buffer gen_server.
%%%
%%% Split from yuzu_gw_upstream to prevent registration storms from
%%% blocking heartbeat processing. This gen_server handles only:
%%%   - queue_heartbeat/1 casts (buffering)
%%%   - timer-based flush (batch RPC to upstream)
%%%
%%% The upstream gen_server retains synchronous RPCs (register,
%%% inventory, notify_stream_status) which may block on slow upstream.
%%% Heartbeats are now isolated and cannot be starved by those RPCs.
%%%
%%% Flushing calls do_flush/1 which sends a BatchHeartbeat RPC via
%%% grpcbox. On failure, the buffer is retained (capped) for retry
%%% on the next flush cycle.
%%%
%%% Heartbeat verdict (#1197 PR-C): a successful BatchHeartbeatResponse may
%%% list sessions the server does not know (unknown_session_ids), typically
%%% after a server restart. Each flush hands that list to
%%% yuzu_gw_upstream:replay_sessions/1, which re-proxies exactly those
%%% sessions. The buffer only validates the ids and counts what it drops as
%%% malformed; every other decision (which are local, which are already
%%% queued, the breaker, the queue cap) belongs to the upstream. Flush results
%%% never feed the circuit breaker, and the only coupling to the upstream is
%%% that one cast per flush: a cast returns at once, so the handoff adds no
%%% wait to the flush (the BatchHeartbeat RPC itself is still a synchronous
%%% unary call under grpcbox's default deadline). A cast to an upstream that is
%%% not running is a no-op, never a flush failure.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_buffer).
-behaviour(gen_server).

-include_lib("grpcbox/include/grpcbox.hrl").

%% API
-export([start_link/0, queue_heartbeat/1, flush_sync/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_MAX_HB_BUFFER, 10000).
%% Bounds on one verdict: the longest session id the gateway will carry and
%% the most ids handed to the upstream per flush.
-define(MAX_SESSION_ID_BYTES, 64).
-define(MAX_VERDICT_IDS, 4096).

-record(state, {
    buffer      :: [map()],           %% buffered heartbeat requests
    buf_len     :: non_neg_integer(), %% tracked length (avoid length/1)
    timer       :: reference() | undefined,
    interval    :: non_neg_integer(), %% flush interval in ms
    max_buf     :: non_neg_integer()  %% cap for retained buffer on failure
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Queue a heartbeat for batching. Non-blocking cast.
-spec queue_heartbeat(map()) -> ok.
queue_heartbeat(HeartbeatReq) ->
    gen_server:cast(?SERVER, {queue_heartbeat, HeartbeatReq}).

%% @doc Flush the heartbeat buffer synchronously. Blocks until done.
-spec flush_sync() -> ok | {error, term()}.
flush_sync() ->
    gen_server:call(?SERVER, flush_sync, 5000).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    Interval = application:get_env(yuzu_gw, heartbeat_batch_interval_ms, 1000),
    MaxBuf = application:get_env(yuzu_gw, max_heartbeat_buffer, ?DEFAULT_MAX_HB_BUFFER),

    TRef = erlang:send_after(Interval, self(), flush),

    logger:info("Heartbeat buffer started, interval=~bms, max_buf=~b",
                [Interval, MaxBuf]),

    {ok, #state{
        buffer   = [],
        buf_len  = 0,
        timer    = TRef,
        interval = Interval,
        max_buf  = MaxBuf
    }}.

handle_call(flush_sync, _From, #state{buffer = []} = State) ->
    %% Nothing to flush.
    {reply, ok, State};
handle_call(flush_sync, _From, #state{buffer = Buf, buf_len = BufLen,
                                       timer = TRef, interval = Interval} = State) ->
    %% Cancel the pending timer and flush immediately.
    _ = erlang:cancel_timer(TRef),
    BatchReq = #{
        heartbeats   => lists:reverse(Buf),
        gateway_node => atom_to_binary(node(), utf8)
    },
    Result = do_flush(BatchReq, BufLen),
    NewTRef = erlang:send_after(Interval, self(), flush),
    case Result of
        ok ->
            {reply, ok, State#state{buffer = [], buf_len = 0, timer = NewTRef}};
        {error, Reason} ->
            {reply, {error, Reason}, State#state{timer = NewTRef}}
    end;
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({queue_heartbeat, HbReq},
            #state{buffer = Buf, buf_len = Len, max_buf = MaxBuf} = State) ->
    case Len >= MaxBuf of
        true  -> {noreply, State};  %% drop — buffer at capacity
        false -> {noreply, State#state{buffer = [HbReq | Buf],
                                        buf_len = Len + 1}}
    end;

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(flush, #state{buffer = [], interval = Interval} = State) ->
    TRef = erlang:send_after(Interval, self(), flush),
    {noreply, State#state{timer = TRef}};

handle_info(flush, #state{buffer = Buf, buf_len = BufLen,
                           interval = Interval,
                           max_buf = MaxBuf} = State) ->
    BatchReq = #{
        heartbeats   => lists:reverse(Buf),
        gateway_node => atom_to_binary(node(), utf8)
    },

    {NewBuf, NewLen} = case do_flush(BatchReq, BufLen) of
        ok ->
            {[], 0};
        {error, _Reason} ->
            %% Retain buffer for retry, capped to prevent unbounded growth.
            case BufLen > MaxBuf of
                true  -> {lists:sublist(Buf, MaxBuf), MaxBuf};
                false -> {Buf, BufLen}
            end
    end,

    TRef = erlang:send_after(Interval, self(), flush),
    {noreply, State#state{buffer = NewBuf, buf_len = NewLen, timer = TRef}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

%% @doc Send a BatchHeartbeat RPC to the upstream C++ server.
do_flush(BatchReq, BufLen) ->
    InputType = 'yuzu.gateway.v1.BatchHeartbeatRequest',
    OutputType = 'yuzu.gateway.v1.BatchHeartbeatResponse',
    Def = #grpcbox_def{
        service       = 'yuzu.gateway.v1.GatewayUpstream',
        message_type  = atom_to_binary(InputType, utf8),
        marshal_fun   = fun(Msg) -> gateway_pb:encode_msg(Msg, InputType) end,
        unmarshal_fun = fun(Bin) -> gateway_pb:decode_msg(Bin, OutputType) end
    },
    Path = <<"/yuzu.gateway.v1.GatewayUpstream/BatchHeartbeat">>,
    StartTime = erlang:monotonic_time(millisecond),
    Result = grpcbox_client:unary(ctx:background(), Path, BatchReq, Def,
                                  #{channel => default_channel}),
    Duration = erlang:monotonic_time(millisecond) - StartTime,
    case Result of
        {ok, #{acknowledged_count := Count} = Response, _Headers} ->
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => <<"batch_heartbeat">>}),
            logger:debug("Flushed ~b heartbeats (ack=~b)", [BufLen, Count]),
            consume_verdict(Response),
            ok;
        {ok, Response, _Headers} ->
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => <<"batch_heartbeat">>}),
            logger:debug("Flushed ~b heartbeats", [BufLen]),
            consume_verdict(Response),
            ok;
        {error, {Status, Message}, _Trailers} ->
            %% HA WS-4 4.4 review fix (F3, mirrors yuzu_gw_upstream:do_rpc/4's
            %% identical bug): grpcbox_client:unary/5's REAL error shape for a
            %% genuine (non-transport) grpc status is a 3-ELEMENT tuple —
            %% `error`, the `{Status, Message}` pair, and the trailers map —
            %% not the 2-element `{error, {Status, Message, Trailers}}` this
            %% clause used to match, which grpcbox never actually returns. A
            %% real grpc-status error on BatchHeartbeat (e.g. RESOURCE_EXHAUSTED
            %% on an oversized batch) previously matched NEITHER this clause
            %% nor the transport-level `{error, Reason}` one below, crashing
            %% this process with a case_clause exception.
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => <<"batch_heartbeat">>,
                                code => Status}),
            logger:warning("BatchHeartbeat failed (~b buffered): ~p ~s",
                           [BufLen, Status, Message]),
            {error, {Status, Message}};
        {http_error, {Status, _}, _Trailers} ->
            %% HA WS-4 4.4 round-2 review fix (consistency-auditor c-1 /
            %% chaos-injector CH-2), mirrors yuzu_gw_upstream:do_rpc/4's
            %% identical fix — see that clause's comment for the full
            %% rationale (a fourth real grpcbox_client:unary/5 return shape
            %% this file's classifier didn't cover either).
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => <<"batch_heartbeat">>,
                                code => Status}),
            logger:warning("BatchHeartbeat failed (~b buffered) with HTTP-level error: ~p",
                           [BufLen, Status]),
            {error, {internal, iolist_to_binary(io_lib:format("http_error ~p", [Status]))}};
        {error, Reason} ->
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => <<"batch_heartbeat">>,
                                code => Reason}),
            logger:warning("BatchHeartbeat failed (~b buffered): ~p",
                           [BufLen, Reason]),
            {error, {internal, Reason}}
    end.

%% @doc Hand the server's list of unknown sessions to the upstream replay.
%%
%% Called from both success arms of do_flush/2 (a decoded response always
%% carries acknowledged_count, a test double may not). Only ids that can be
%% session ids are kept (binaries of 1 to 64 bytes); the rest are counted as
%% verdict_dropped with reason malformed, here, because only this module sees
%% them. The kept ids are deduplicated, sorted and capped at
%% ?MAX_VERDICT_IDS before the cast. The ids are never logged: only counts.
%% No key, or an empty list, casts nothing.
-spec consume_verdict(map()) -> ok.
consume_verdict(Response) ->
    Listed = maps:get(unknown_session_ids, Response, []),
    {Kept, Malformed} = lists:partition(fun is_session_id/1, Listed),
    Ids = lists:sublist(lists:usort(Kept), ?MAX_VERDICT_IDS),
    case Listed of
        [] ->
            ok;
        _ ->
            logger:debug("Heartbeat verdict: ~b unknown session(s) listed, ~b malformed",
                         [length(Listed), length(Malformed)])
    end,
    case Malformed of
        [] ->
            ok;
        _ ->
            telemetry:execute([yuzu, gw, heartbeat, verdict_dropped],
                              #{count => length(Malformed)},
                              #{reason => malformed})
    end,
    case maps:get(unknown_session_ids_truncated, Response, false) of
        true ->
            telemetry:execute([yuzu, gw, heartbeat, unknown_truncated],
                              #{count => 1}, #{}),
            logger:warning("Heartbeat verdict truncated by the server (~b listed); "
                           "omitted sessions may be reported by subsequent heartbeats",
                           [length(Listed)]);
        _ ->
            ok
    end,
    case Ids of
        [] -> ok;
        _  -> yuzu_gw_upstream:replay_sessions(Ids)
    end.

is_session_id(Id) ->
    is_binary(Id) andalso byte_size(Id) > 0 andalso byte_size(Id) =< ?MAX_SESSION_ID_BYTES.
