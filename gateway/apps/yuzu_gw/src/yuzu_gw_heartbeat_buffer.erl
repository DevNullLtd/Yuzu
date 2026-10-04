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
%%% Buffering: one entry per session. A heartbeat for a session already
%%% buffered is coalesced into it: the newest heartbeat wins every field,
%%% except fleet_snapshot_json, which keeps the newest NON-EMPTY snapshot (the
%%% agent attaches a snapshot only when its pump sequence advanced and never
%%% resends it, so a newer heartbeat without one must not discard an older
%%% snapshot). A snapshot can be 200 to 800 KB, so the buffer is bounded in
%%% bytes as well as in sessions: each entry carries an upper-bound estimate
%%% of its encoded size, a snapshot that alone exceeds one chunk is dropped
%%% (the heartbeat still ships), and when the total passes the byte cap the
%%% snapshots of the oldest entries are dropped first, whole sessions only
%%% when none holds a snapshot. Every drop is counted by reason in
%%% yuzu_gw_heartbeat_buffer_dropped_total; coalescing is counted in
%%% yuzu_gw_heartbeat_coalesced_total.
%%%
%%% A heartbeat that could never be sent is screened out on arrival, before it
%%% touches the buffer (the session's older entry, if any, is kept): one with
%%% more than ?MAX_STATUS_TAGS status tags, or still larger than one chunk
%%% without its snapshot, is dropped as heartbeat_oversize, and one whose
%%% session id or a status tag key or value is not valid UTF-8 (the encoder
%%% raises on it) as heartbeat_invalid. So every entry fits one chunk and every
%%% request is under the server's receive limit: nothing here relies on the
%%% sender being well behaved (the gateway puts no inbound size limit on a
%%% Heartbeat).
%%%
%%% Flushing calls do_flush/2 which sends BatchHeartbeat RPCs via grpcbox.
%%% The buffer is split into chunks, oldest entry first, each estimated under
%%% 3 MiB, so no request reaches the server's 4 MiB receive limit however long
%%% the outage was. A chunk that the server accepted is removed. On a transient
%%% failure (the server unreachable, a timeout, an exception out of the RPC, any
%%% status not named below) that chunk and every later one are retained for the
%%% next flush cycle and the flush stops. On a non-transient refusal
%%% (RESOURCE_EXHAUSTED or INVALID_ARGUMENT) a chunk of one heartbeat is dropped
%%% as chunk_rejected and the flush goes on; a chunk of several is split in
%%% halves and each half is sent again in the same flush, so the heartbeat the
%%% server will not take is found and dropped without holding back the others.
%%% One flush makes at most ?MAX_RPCS_PER_FLUSH RPCs, those retries included;
%%% what is left stays buffered. An exception out of the RPC (a heartbeat the
%%% encoder raises on, an exit of the HTTP/2 connection) never crashes this
%%% process: of the entries of the failed chunk, those the encoder raises on
%%% alone are dropped as heartbeat_invalid and the rest is sent again; with no
%%% such entry the failure is transient.
%%%
%%% Heartbeat verdict (#1197): a successful BatchHeartbeatResponse may
%%% list sessions the server does not know (unknown_session_ids), typically
%%% after a server restart. Each successful chunk hands that list to
%%% yuzu_gw_upstream:replay_sessions/1, which re-proxies exactly those
%%% sessions. The buffer only validates the ids and counts what it drops as
%%% malformed; every other decision (which are local, which are already
%%% queued, the breaker, the queue cap) belongs to the upstream. Flush results
%%% never feed the circuit breaker, and the only coupling to the upstream is
%%% one cast per successful chunk (plus a look at its mailbox length first): a
%%% cast returns at once, so the handoff adds no wait to the flush (the
%%% BatchHeartbeat RPC itself is still a synchronous unary call under
%%% grpcbox's default deadline). A cast to an upstream that is not running is
%%% a no-op, never a flush failure. While the upstream's mailbox holds more
%%% than 100 messages the cast is skipped and counted (queue_full), so the
%%% cast rate cannot outrun the drip whatever the flush interval is.
%%%
%%% Configuration (sys.config / application env):
%%%   heartbeat_batch_interval_ms  - flush period (default 1000, valid 100..60000)
%%%   max_heartbeat_buffer         - sessions retained (default 10000)
%%%   max_heartbeat_buffer_bytes   - estimated bytes retained (default 67108864,
%%%                                  valid 1048576..1073741824)
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_heartbeat_buffer).
-behaviour(gen_server).

-include_lib("grpcbox/include/grpcbox.hrl").

%% API
-export([start_link/0, queue_heartbeat/1, flush_sync/0]).
%% Exported for tests (the upper-bound property is asserted against the encoder).
-export([estimate_bytes/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_MAX_HB_BUFFER, 10000).
%% One flush makes at most this many RPCs, retries of a refused chunk included:
%% a server that refuses every request would otherwise cost one RPC per
%% buffered heartbeat in a single flush.
-define(MAX_RPCS_PER_FLUSH, 64).
%% A heartbeat with more status tags than this is dropped (heartbeat_oversize).
%% The agent sends about 25; the bound only has to stop a sender that floods the
%% tag map.
-define(MAX_STATUS_TAGS, 512).
%% max_heartbeat_buffer_bytes: the cap on the buffer's estimated encoded size.
%% Valid 1 MiB..1 GiB (default 64 MiB); anything else logs a warning naming the
%% key and takes the default.
-define(DEFAULT_MAX_HB_BYTES, 67108864).
-define(MIN_MAX_HB_BYTES, 1048576).
-define(MAX_MAX_HB_BYTES, 1073741824).
%% One BatchHeartbeat request is packed up to this many estimated bytes: under
%% the server's 4194304-byte gRPC receive limit with a wide margin for the
%% estimate's slack and the request's own framing.
-define(CHUNK_BYTES, 3145728).
%% A flush that released more than this many estimated bytes forces a GC, so
%% the large binaries of a drained backlog are not held until the next one.
-define(GC_AFTER_RELEASED_BYTES, 8388608).
%% heartbeat_batch_interval_ms: the flush period, and so the ceiling on how
%% often one verdict can be cast. Valid 100..60000 (default 1000); anything
%% else logs a warning naming the key and takes the default.
-define(DEFAULT_BATCH_INTERVAL_MS, 1000).
-define(MIN_BATCH_INTERVAL_MS, 100).
-define(MAX_BATCH_INTERVAL_MS, 60000).
%% The verdict cast is skipped, and its ids counted as dropped, while the
%% upstream process already holds more than this many unhandled messages. The
%% bound does not depend on configuration: it holds whatever the interval is.
-define(UPSTREAM_QUEUE_MAX, 100).
%% At most one truncated-verdict warning per this long (monotonic ms).
-define(TRUNC_WARN_INTERVAL_MS, 60000).
%% Bounds on one verdict: the longest session id the gateway will carry and
%% the most ids handed to the upstream per flush.
-define(MAX_SESSION_ID_BYTES, 64).
%% Same bound as ?MAX_REPLAY_SESSION_IDS in yuzu_gw_upstream, which applies it
%% again at the cast boundary; keep the two equal.
-define(MAX_VERDICT_IDS, 4096).

%% One buffered session: its insertion/refresh order, the heartbeat to send and
%% the estimate_bytes/1 of that heartbeat.
-type entry() :: #{seq := non_neg_integer(), hb := map(), bytes := non_neg_integer()}.
-type drop_reason() :: buffer_full | snapshot_oversize | snapshot_evicted
                     | heartbeat_oversize | heartbeat_invalid | chunk_rejected.
-type chunk() :: [{term(), map(), non_neg_integer()}].

%% What one flush has done so far.
-record(acc, {
    sent     = 0 :: non_neg_integer(), %% heartbeats the server accepted
    nchunks  = 0 :: non_neg_integer(), %% requests the server accepted
    released = 0 :: non_neg_integer(), %% estimated bytes removed from the buffer
    rpcs     = 0 :: non_neg_integer()  %% RPCs made, failed ones included
}).
-define(BATCH_REQUEST, 'yuzu.gateway.v1.BatchHeartbeatRequest').

-record(state, {
    buffer      = #{} :: #{term() => entry()}, %% session id => entry
    buf_bytes   = 0   :: non_neg_integer(),    %% sum of the entries' bytes
    timer       :: reference() | undefined,
    interval    :: non_neg_integer(), %% flush interval in ms
    max_buf     :: non_neg_integer(), %% cap on buffered sessions
    %% Monotonic ms of the last truncated-verdict warning (undefined: none
    %% yet), and the truncated verdicts seen since it, not logged.
    trunc_warned_at  = undefined :: integer() | undefined,
    trunc_suppressed = 0         :: non_neg_integer(),
    next_seq    = 0   :: non_neg_integer(), %% seq of the next insertion/refresh
    max_bytes   :: pos_integer(),           %% cap on buf_bytes
    %% seq => session id of the entries that hold a non-empty snapshot, so the
    %% oldest snapshot is found without scanning the buffer.
    snap_idx    = gb_trees:empty() :: gb_trees:tree(non_neg_integer(), term())
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
    Interval = yuzu_gw_env:env_int(heartbeat_batch_interval_ms,
                                ?DEFAULT_BATCH_INTERVAL_MS,
                                ?MIN_BATCH_INTERVAL_MS, ?MAX_BATCH_INTERVAL_MS),
    MaxBuf = application:get_env(yuzu_gw, max_heartbeat_buffer, ?DEFAULT_MAX_HB_BUFFER),
    MaxBytes = yuzu_gw_env:env_int(max_heartbeat_buffer_bytes, ?DEFAULT_MAX_HB_BYTES,
                                   ?MIN_MAX_HB_BYTES, ?MAX_MAX_HB_BYTES),

    TRef = erlang:send_after(Interval, self(), flush),

    logger:info("Heartbeat buffer started, interval=~bms, max_buf=~b, max_bytes=~b",
                [Interval, MaxBuf, MaxBytes]),

    {ok, #state{
        timer     = TRef,
        interval  = Interval,
        max_buf   = MaxBuf,
        max_bytes = MaxBytes
    }}.

handle_call(flush_sync, _From, #state{buffer = Buf} = State) when map_size(Buf) =:= 0 ->
    %% Nothing to flush.
    {reply, ok, State};
handle_call(flush_sync, _From, #state{timer = TRef, interval = Interval} = State) ->
    %% Cancel the pending timer and flush immediately.
    _ = erlang:cancel_timer(TRef),
    {Result, State1} = flush_chunks(chunks(State), State),
    NewTRef = erlang:send_after(Interval, self(), flush),
    {reply, Result, State1#state{timer = NewTRef}};
handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({queue_heartbeat, HbReq}, State) when is_map(HbReq) ->
    {noreply, enqueue(HbReq, State)};

handle_cast({queue_heartbeat, _NotAMap}, State) ->
    %% Not a heartbeat: encoding it would crash every later flush.
    logger:debug("Heartbeat buffer: ignoring a queued value that is not a map"),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(flush, #state{buffer = Buf, interval = Interval} = State)
  when map_size(Buf) =:= 0 ->
    TRef = erlang:send_after(Interval, self(), flush),
    {noreply, State#state{timer = TRef}};

handle_info(flush, #state{interval = Interval} = State) ->
    %% A failed chunk (and every later one) stays buffered for the next cycle.
    {_Result, State1} = flush_chunks(chunks(State), State),
    TRef = erlang:send_after(Interval, self(), flush),
    {noreply, State1#state{timer = TRef}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

%% @doc Send one BatchHeartbeat RPC (a chunk of N heartbeats) to the upstream
%% C++ server. A success returns the decoded response untouched; flush_chunks/2
%% consumes its verdict. This calls grpcbox_client directly, never through
%% yuzu_gw_upstream, so a flush result can not feed the circuit breaker.
-spec do_flush(map(), non_neg_integer()) -> {ok, term()} | {error, term()}.
do_flush(BatchReq, N) ->
    InputType = ?BATCH_REQUEST,
    OutputType = 'yuzu.gateway.v1.BatchHeartbeatResponse',
    Def = #grpcbox_def{
        service       = 'yuzu.gateway.v1.GatewayUpstream',
        message_type  = atom_to_binary(InputType, utf8),
        marshal_fun   = fun(Msg) -> gateway_pb:encode_msg(Msg, InputType) end,
        unmarshal_fun = fun(Bin) -> gateway_pb:decode_msg(Bin, OutputType) end
    },
    Path = <<"/yuzu.gateway.v1.GatewayUpstream/BatchHeartbeat">>,
    StartTime = erlang:monotonic_time(millisecond),
    %% The marshal fun runs inside the call, so an invalid heartbeat raises here
    %% (error), and the HTTP/2 connection can exit under it (an exit that
    %% grpcbox_client does not catch). Neither may end this process, which holds
    %% every buffered heartbeat: only the class is kept, never the reason (it
    %% can hold the request).
    Result = try grpcbox_client:unary(ctx:background(), Path, BatchReq, Def,
                                      #{channel => default_channel})
             catch
                 Caught:_ -> {caught, Caught}
             end,
    Duration = erlang:monotonic_time(millisecond) - StartTime,
    case Result of
        {ok, #{acknowledged_count := Count} = Response, _Headers} ->
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => <<"batch_heartbeat">>}),
            logger:debug("Flushed ~b heartbeats (ack=~b)", [N, Count]),
            {ok, Response};
        {ok, Response, _Headers} ->
            telemetry:execute([yuzu, gw, upstream, rpc_latency],
                              #{duration_ms => Duration},
                              #{rpc_name => <<"batch_heartbeat">>}),
            logger:debug("Flushed ~b heartbeats", [N]),
            {ok, Response};
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
            logger:warning("BatchHeartbeat failed (~b in chunk): ~p ~s",
                           [N, Status, Message]),
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
            logger:warning("BatchHeartbeat failed (~b in chunk) with HTTP-level error: ~p",
                           [N, Status]),
            {error, {internal, iolist_to_binary(io_lib:format("http_error ~p", [Status]))}};
        {caught, Class} ->
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => <<"batch_heartbeat">>,
                                code => <<"exception">>}),
            logger:warning("BatchHeartbeat raised (~b in chunk): class ~p; "
                           "the reason is not logged", [N, Class]),
            {error, {exception, Class}};
        {error, Reason} ->
            telemetry:execute([yuzu, gw, upstream, rpc_error],
                              #{count => 1},
                              #{rpc_name => <<"batch_heartbeat">>,
                                code => Reason}),
            logger:warning("BatchHeartbeat failed (~b in chunk): ~p",
                           [N, Reason]),
            {error, {internal, Reason}}
    end.

%% @doc Queue one heartbeat: drop it when it can never be sent (screen/1), else
%% coalesce it into its session's entry, or insert it, or drop it when the
%% session count is at its cap. The count cap never drops a heartbeat for a
%% session already buffered. A snapshot too large for one chunk is dropped from
%% the entry, then the byte cap is enforced.
-spec enqueue(map(), #state{}) -> #state{}.
enqueue(Hb, #state{} = State) ->
    case screen(Hb) of
        ok ->
            enqueue_screened(Hb, State);
        {drop, Reason} ->
            note_dropped(Reason),
            State
    end.

enqueue_screened(Hb, #state{buffer = Buf, max_buf = MaxBuf} = State) ->
    Sid = maps:get(session_id, Hb, <<>>),
    case Buf of
        #{Sid := #{hb := Old} = Entry} ->
            telemetry:execute([yuzu, gw, heartbeat, coalesced], #{count => 1}, #{}),
            State1 = remove_entry(Sid, Entry, State),
            admit(Sid, put_entry(Sid, coalesce(Old, Hb), State1));
        _ when map_size(Buf) >= MaxBuf ->
            note_dropped(buffer_full),
            State;
        _ ->
            admit(Sid, put_entry(Sid, Hb, State))
    end.

%% @doc Whether a heartbeat can ever be sent, decided on the heartbeat alone
%% (never on the buffer), so a dropped heartbeat leaves its session's older entry
%% untouched. The newest heartbeat wins every field but the snapshot, so a
%% heartbeat too large without its snapshot is too large coalesced as well. Size
%% is checked first: it is cheap, and the UTF-8 walk then only runs over a
%% heartbeat that fits one chunk.
-spec screen(map()) -> ok | {drop, heartbeat_oversize | heartbeat_invalid}.
screen(Hb) ->
    Tags = maps:get(status_tags, Hb, #{}),
    case tag_count(Tags) > ?MAX_STATUS_TAGS
         orelse estimate_bytes(Hb#{fleet_snapshot_json => <<>>}) > ?CHUNK_BYTES of
        true ->
            {drop, heartbeat_oversize};
        false ->
            case valid_text(Hb) of
                true  -> ok;
                false -> {drop, heartbeat_invalid}
            end
    end.

tag_count(Tags) when is_map(Tags) -> map_size(Tags);
tag_count(_)                      -> 0.

%% The session id and every status tag key and value are binaries of valid UTF-8
%% (what the encoder accepts: gateway_pb raises badarg on anything else, and the
%% decoder of the agent's own message keeps invalid bytes as they came). An
%% absent field is valid; a status_tags that is not a map is not.
-spec valid_text(map()) -> boolean().
valid_text(Hb) ->
    valid_utf8(maps:get(session_id, Hb, <<>>))
        andalso case maps:get(status_tags, Hb, #{}) of
                    Tags when is_map(Tags) ->
                        maps:fold(fun(K, V, Ok) -> Ok andalso valid_utf8(K) andalso valid_utf8(V) end,
                                  true, Tags);
                    _ ->
                        false
                end.

valid_utf8(B) when is_binary(B) -> is_binary(unicode:characters_to_binary(B, utf8, utf8));
valid_utf8(_)                   -> false.

%% @doc The newest heartbeat wins every field; fleet_snapshot_json is the
%% newest non-empty snapshot (see the module doc).
-spec coalesce(map(), map()) -> map().
coalesce(Old, New) ->
    case maps:get(fleet_snapshot_json, New, <<>>) of
        <<>> ->
            case maps:get(fleet_snapshot_json, Old, <<>>) of
                <<>>  -> New;
                OldSn -> New#{fleet_snapshot_json => OldSn}
            end;
        _ ->
            New
    end.

%% A heartbeat that passed screen/1 fits one chunk without its snapshot, so an
%% entry over a chunk holds a snapshot: that is what is dropped (and counted).
-spec admit(term(), #state{}) -> #state{}.
admit(Sid, #state{buffer = Buf} = State) ->
    #{Sid := #{bytes := Bytes, hb := Hb}} = Buf,
    State1 = case Bytes > ?CHUNK_BYTES andalso has_snapshot(Hb) of
        true ->
            note_dropped(snapshot_oversize),
            strip_snapshot(Sid, State);
        false ->
            State
    end,
    enforce_byte_cap(State1).

%% @doc Drop snapshots, oldest entry first, until the estimated total fits;
%% drop the oldest whole session only when no entry holds a snapshot.
-spec enforce_byte_cap(#state{}) -> #state{}.
enforce_byte_cap(#state{buf_bytes = Bytes, max_bytes = Max} = State) when Bytes =< Max ->
    State;
enforce_byte_cap(#state{buffer = Buf, snap_idx = Idx} = State) ->
    case gb_trees:is_empty(Idx) of
        false ->
            {_Seq, Sid} = gb_trees:smallest(Idx),
            note_dropped(snapshot_evicted),
            enforce_byte_cap(strip_snapshot(Sid, State));
        true ->
            {Sid, _} = oldest_entry(Buf),
            note_dropped(buffer_full),
            enforce_byte_cap(remove_entry(Sid, maps:get(Sid, Buf), State))
    end.

%% @doc The {SessionId, Entry} with the lowest seq. The buffer is not empty.
-spec oldest_entry(#{term() => entry()}) -> {term(), entry()}.
oldest_entry(Buf) ->
    maps:fold(fun(Sid, #{seq := Seq} = E, {_, #{seq := Best}}) when Seq < Best ->
                      {Sid, E};
                 (_, _, Acc) ->
                      Acc
              end, {undefined, #{seq => infinity}}, Buf).

-spec note_dropped(drop_reason()) -> ok.
note_dropped(Reason) ->
    telemetry:execute([yuzu, gw, heartbeat, buffer_dropped],
                      #{count => 1}, #{reason => Reason}).

%% @doc Insert a heartbeat under a fresh seq (a refresh is a new seq too, so
%% eviction and flush order follow the last update).
-spec put_entry(term(), map(), #state{}) -> #state{}.
put_entry(Sid, Hb, #state{buffer = Buf, buf_bytes = Total, next_seq = Seq,
                          snap_idx = Idx} = State) ->
    Bytes = estimate_bytes(Hb),
    State#state{buffer    = Buf#{Sid => #{seq => Seq, hb => Hb, bytes => Bytes}},
                buf_bytes = Total + Bytes,
                next_seq  = Seq + 1,
                snap_idx  = case has_snapshot(Hb) of
                                true  -> gb_trees:insert(Seq, Sid, Idx);
                                false -> Idx
                            end}.

-spec remove_entry(term(), entry(), #state{}) -> #state{}.
remove_entry(Sid, #{seq := Seq, bytes := Bytes},
             #state{buffer = Buf, buf_bytes = Total, snap_idx = Idx} = State) ->
    State#state{buffer    = maps:remove(Sid, Buf),
                buf_bytes = Total - Bytes,
                snap_idx  = gb_trees:delete_any(Seq, Idx)}.

%% @doc Empty the entry's snapshot and re-estimate it; its seq is kept.
-spec strip_snapshot(term(), #state{}) -> #state{}.
strip_snapshot(Sid, #state{buffer = Buf, buf_bytes = Total, snap_idx = Idx} = State) ->
    #{Sid := #{seq := Seq, hb := Hb, bytes := Bytes}} = Buf,
    Hb1 = Hb#{fleet_snapshot_json => <<>>},
    Bytes1 = estimate_bytes(Hb1),
    State#state{buffer    = Buf#{Sid => #{seq => Seq, hb => Hb1, bytes => Bytes1}},
                buf_bytes = Total - Bytes + Bytes1,
                snap_idx  = gb_trees:delete_any(Seq, Idx)}.

has_snapshot(Hb) ->
    case maps:get(fleet_snapshot_json, Hb, <<>>) of
        <<>> -> false;
        Sn   -> is_binary(Sn)
    end.

%% @doc An upper bound of the heartbeat's gpb-encoded size (inside a
%% BatchHeartbeatRequest): 32 covers the request framing, the session id and
%% snapshot tag+length (at most 6 each), sent_at (13) and the repeated-field tag
%% and length (6); each status tag costs its key and value plus 24, which covers
%% its three tags and length varints. Absent fields are missing keys.
-spec estimate_bytes(map()) -> non_neg_integer().
estimate_bytes(Hb) ->
    32 + bin_size(maps:get(session_id, Hb, <<>>))
       + bin_size(maps:get(fleet_snapshot_json, Hb, <<>>))
       + tags_bytes(maps:get(status_tags, Hb, #{})).

tags_bytes(Tags) when is_map(Tags) ->
    maps:fold(fun(K, V, Acc) -> Acc + bin_size(K) + bin_size(V) + 24 end, 0, Tags);
tags_bytes(_) ->
    0.

bin_size(B) when is_binary(B) -> byte_size(B);
bin_size(_)                   -> 0.

%% @doc The buffer as chunks of {SessionId, Heartbeat, Bytes}, oldest entry
%% first, packed greedily up to ?CHUNK_BYTES by estimate (a chunk always holds
%% at least one entry).
-spec chunks(#state{}) -> [[{term(), map(), non_neg_integer()}]].
chunks(#state{buffer = Buf}) ->
    Ordered = lists:keysort(1, [{Seq, {Sid, Hb, Bytes}}
                                || Sid := #{seq := Seq, hb := Hb, bytes := Bytes} <- Buf]),
    pack([E || {_, E} <- Ordered], [], 0, []).

pack([], [], _, Done) ->
    lists:reverse(Done);
pack([], Cur, _, Done) ->
    lists:reverse([lists:reverse(Cur) | Done]);
pack([{_, _, Bytes} = E | Rest], Cur, CurBytes, Done)
  when Cur =/= [], CurBytes + Bytes > ?CHUNK_BYTES ->
    pack([E | Rest], [], 0, [lists:reverse(Cur) | Done]);
pack([{_, _, Bytes} = E | Rest], Cur, CurBytes, Done) ->
    pack(Rest, [E | Cur], CurBytes + Bytes, Done).

%% @doc Send the chunks in order. A chunk the server accepted has its verdict
%% consumed (once) and its sessions removed from the buffer. What happens on a
%% failure depends on its class (see the module doc and classify/1); a
%% transient one ends the flush with {error, Reason}, the failed chunk and the
%% unsent ones staying buffered. A flush that released more than
%% ?GC_AFTER_RELEASED_BYTES forces a GC.
-spec flush_chunks([chunk()], #state{}) -> {ok | {error, term()}, #state{}}.
flush_chunks(Chunks, State) ->
    flush_loop(Chunks, State, #acc{}).

flush_loop([], State, Acc) ->
    finish(ok, State, Acc);
flush_loop(_Work, State, #acc{rpcs = Rpcs} = Acc) when Rpcs >= ?MAX_RPCS_PER_FLUSH ->
    finish({error, rpc_limit}, State, Acc);
flush_loop([Chunk | Rest], State, #acc{rpcs = Rpcs} = Acc) ->
    BatchReq = #{
        heartbeats   => [Hb || {_, Hb, _} <- Chunk],
        gateway_node => atom_to_binary(node(), utf8)
    },
    Acc1 = Acc#acc{rpcs = Rpcs + 1},
    case do_flush(BatchReq, length(Chunk)) of
        {ok, Response} ->
            State1 = consume_verdict(Response, State),
            {State2, Bytes} = remove_chunk(Chunk, State1),
            flush_loop(Rest, State2,
                       Acc1#acc{sent     = Acc1#acc.sent + length(Chunk),
                                nchunks  = Acc1#acc.nchunks + 1,
                                released = Acc1#acc.released + Bytes});
        {error, Error} ->
            failed(classify(Error), Error, Chunk, Rest, State, Acc1)
    end.

%% How a failed RPC is handled. The status of a gRPC error is the binary grpcbox
%% returns (<<"8">> is RESOURCE_EXHAUSTED, <<"3">> INVALID_ARGUMENT); the server
%% refusing a request this way will refuse the same request again, so retrying
%% it every cycle would hold back everything behind it. Any other failure,
%% including a status this module does not know, is transient: the data stays.
-spec classify(term()) -> refused | raised | transient.
classify({Status, _Message}) when Status =:= ?GRPC_STATUS_RESOURCE_EXHAUSTED;
                                  Status =:= ?GRPC_STATUS_INVALID_ARGUMENT ->
    refused;
classify({exception, error}) ->
    raised;
classify(_Other) ->
    transient.

-spec failed(refused | raised | transient, term(), chunk(), [chunk()],
             #state{}, #acc{}) -> {ok | {error, term()}, #state{}}.
failed(transient, Error, _Chunk, _Rest, State, Acc) ->
    finish({error, Error}, State, Acc);
failed(refused, _Error, [{Sid, _, Bytes}], Rest, State, Acc) ->
    %% One heartbeat the server will not take: drop it, go on with the rest.
    note_dropped(chunk_rejected),
    State1 = remove_entry(Sid, maps:get(Sid, State#state.buffer), State),
    flush_loop(Rest, State1, Acc#acc{released = Acc#acc.released + Bytes});
failed(refused, _Error, Chunk, Rest, State, Acc) ->
    %% Which heartbeat is not known: send each half again (a half of one is a
    %% single, handled above), so the cost of finding one is logarithmic.
    {First, Second} = lists:split(length(Chunk) div 2, Chunk),
    flush_loop([First, Second | Rest], State, Acc);
failed(raised, Error, Chunk, Rest, State, Acc) ->
    %% The encoder raised: the heartbeats it raises on alone are invalid (they
    %% cannot reach here through enqueue/2, which screens them). With none, the
    %% exception came from somewhere else and is transient.
    case lists:partition(fun({_, Hb, _}) -> encodes(Hb) end, Chunk) of
        {_, []} ->
            finish({error, Error}, State, Acc);
        {Good, Bad} ->
            lists:foreach(fun(_) -> note_dropped(heartbeat_invalid) end, Bad),
            {State1, Bytes} = remove_chunk(Bad, State),
            Acc1 = Acc#acc{released = Acc#acc.released + Bytes},
            case Good of
                [] -> flush_loop(Rest, State1, Acc1);
                _  -> flush_loop([Good | Rest], State1, Acc1)
            end
    end.

%% Whether the encoder accepts a request holding just this heartbeat.
-spec encodes(map()) -> boolean().
encodes(Hb) ->
    try gateway_pb:encode_msg(#{heartbeats => [Hb], gateway_node => <<>>}, ?BATCH_REQUEST) of
        _ -> true
    catch
        _:_ -> false
    end.

%% Remove the chunk's sessions; the estimated bytes removed.
-spec remove_chunk(chunk(), #state{}) -> {#state{}, non_neg_integer()}.
remove_chunk(Chunk, State) ->
    lists:foldl(fun({Sid, _, Bytes}, {S, Total}) ->
                        {remove_entry(Sid, maps:get(Sid, S#state.buffer), S), Total + Bytes}
                end, {State, 0}, Chunk).

finish(Result, State, Acc) ->
    flushed(Acc),
    {Result, State}.

%% @doc Log what a flush sent (counts only, never session ids) and collect the
%% garbage of a large release.
flushed(#acc{sent = 0, released = Released}) ->
    gc_after(Released);
flushed(#acc{sent = Sent, nchunks = NChunks, released = Released}) ->
    case NChunks > 1 of
        true  -> logger:info("Flushed ~b heartbeats in ~b chunk(s)", [Sent, NChunks]);
        false -> logger:debug("Flushed ~b heartbeats in ~b chunk(s)", [Sent, NChunks])
    end,
    gc_after(Released).

gc_after(Released) ->
    case Released > ?GC_AFTER_RELEASED_BYTES of
        true  -> erlang:garbage_collect();
        false -> ok
    end,
    ok.

%% @doc Hand the server's list of unknown sessions to the upstream replay.
%%
%% Called for both success shapes of do_flush/2 (a decoded response always
%% carries acknowledged_count, a test double may not). Only ids that can be
%% session ids are kept (binaries of 1 to 64 bytes); the rest are counted as
%% verdict_dropped with reason malformed, here, because only this module sees
%% them. The kept ids are deduplicated, sorted and capped at
%% ?MAX_VERDICT_IDS before the cast. The ids are never logged: only counts.
%% No key, or an empty list, casts nothing.
%%
%% The cast is skipped when the upstream already holds more than
%% ?UPSTREAM_QUEUE_MAX unhandled messages: the ids are counted as
%% verdict_dropped with reason queue_full and one debug line is logged (a
%% later heartbeat lists the sessions again). Casting faster than the upstream
%% drains would only grow its mailbox.
%%
%% A truncated verdict is counted every time, but warned about at most once per
%% ?TRUNC_WARN_INTERVAL_MS; the warning says how many were suppressed since the
%% last one. The timestamps live in the returned state.
%%
%% A body that is not a map is no verdict (grpcbox returns {ok, <<>>, Trailers}
%% for an OK with trailers and no DATA frame): nothing is cast or counted and
%% the flush still succeeds. A key of the wrong type is treated as absent. A
%% crash here would take this process, and every heartbeat it buffers, with it.
-spec consume_verdict(term(), #state{}) -> #state{}.
consume_verdict(Response, State) when is_map(Response) ->
    Listed = listed_ids(maps:get(unknown_session_ids, Response, [])),
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
    State1 = case maps:get(unknown_session_ids_truncated, Response, false) of
        true ->
            telemetry:execute([yuzu, gw, heartbeat, unknown_truncated],
                              #{count => 1}, #{}),
            warn_truncated(length(Listed), State);
        _ ->
            State
    end,
    case Ids of
        [] -> ok;
        _  -> cast_replay(Ids)
    end,
    State1;
consume_verdict(_NotAMap, State) ->
    logger:debug("Heartbeat verdict: response body is not a message; no verdict"),
    State.

%% @doc Cast Ids to the upstream replay unless its mailbox is already long.
%% No upstream process (or one that died since the lookup) has no queue to
%% protect: the cast is a no-op then, exactly as before.
-spec cast_replay([binary()]) -> ok.
cast_replay(Ids) ->
    case upstream_queue_len() of
        Len when is_integer(Len), Len > ?UPSTREAM_QUEUE_MAX ->
            telemetry:execute([yuzu, gw, heartbeat, verdict_dropped],
                              #{count => length(Ids)},
                              #{reason => queue_full}),
            logger:debug("Heartbeat verdict: upstream queue is ~b messages; "
                         "~b session id(s) not cast", [Len, length(Ids)]),
            ok;
        _ ->
            yuzu_gw_upstream:replay_sessions(Ids)
    end.

-spec upstream_queue_len() -> non_neg_integer() | undefined.
upstream_queue_len() ->
    case whereis(yuzu_gw_upstream) of
        undefined ->
            undefined;
        Pid ->
            case erlang:process_info(Pid, message_queue_len) of
                {message_queue_len, Len} -> Len;
                undefined                -> undefined
            end
    end.

%% @doc The truncated-verdict warning, at most once per ?TRUNC_WARN_INTERVAL_MS.
-spec warn_truncated(non_neg_integer(), #state{}) -> #state{}.
warn_truncated(ListedCount, #state{trunc_warned_at = Last,
                                   trunc_suppressed = Suppressed} = State) ->
    Now = erlang:monotonic_time(millisecond),
    case Last =:= undefined orelse Now - Last >= ?TRUNC_WARN_INTERVAL_MS of
        true ->
            logger:warning("Heartbeat verdict truncated by the server (~b listed); "
                           "omitted sessions may be reported by subsequent heartbeats "
                           "(suppressed ~b)",
                           [ListedCount, Suppressed]),
            State#state{trunc_warned_at = Now, trunc_suppressed = 0};
        false ->
            State#state{trunc_suppressed = Suppressed + 1}
    end.

%% @doc The listed ids when the field is a proper list, else none.
listed_ids(Ids) when is_list(Ids) ->
    try length(Ids) of
        _ -> Ids
    catch
        error:badarg -> []
    end;
listed_ids(_) ->
    [].

is_session_id(Id) ->
    is_binary(Id) andalso byte_size(Id) > 0 andalso byte_size(Id) =< ?MAX_SESSION_ID_BYTES.
