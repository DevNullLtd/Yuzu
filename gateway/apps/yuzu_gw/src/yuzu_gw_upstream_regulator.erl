%%%-------------------------------------------------------------------
%%% @doc Permits for the upstream RPCs a request process makes itself.
%%%
%%% ProxyRegister and ProxyInventory run in the process of the gRPC request
%%% that asked for them (yuzu_gw_upstream:proxy_register/2), not inside the
%%% yuzu_gw_upstream gen_server, so that one slow call no longer holds up
%%% every other one (Erlang in Anger 3.1.2: leave the work to the caller and
%%% enforce the limits as if the hub had done it). This process enforces the
%%% limits. It does bookkeeping only, never an RPC, so a message to it costs
%%% O(1) work.
%%%
%%% == Pools and classes ==
%%%
%%%   register   pool `register', upstream_register_concurrency permits
%%%              (default 48). A live ProxyRegister.
%%%   replay     pool `register' too (a replay is a ProxyRegister to the same
%%%              server), at most upstream_replay_concurrency of them at once
%%%              (default 24, at most the register pool). The rest of the pool
%%%              stays for live registrations.
%%%   inventory  pool `inventory', upstream_inventory_concurrency permits
%%%              (default 8). A ProxyInventory.
%%%
%%% When a permit frees, a waiting live Register is served before a waiting
%%% replay. Within a class the order is first come, first served.
%%%
%%% == The server's stream limit ==
%%%
%%% Every upstream call is one HTTP/2 stream on a connection of the
%%% `default_channel'. The server declares how many it accepts at once on a
%%% connection, SETTINGS_MAX_CONCURRENT_STREAMS, in the SETTINGS frame that
%%% starts the connection, and may change it at any time (RFC 9113 6.5.2, 6.5).
%%% The client must not exceed it (5.1.2): gun refuses a request past it locally
%%% (too_many_streams). The C++ server registers the gateway-upstream service on
%%% the same gRPC builder as its agent service (server.cpp), so the value is its
%%% --grpc-max-concurrent-streams (default 128).
%%%
%%% The gateway does not assume that value: the channel learns it from the
%%% server (yuzu_grpc_client_channel, gun's settings_changed notification) and
%%% passes every change here (server_capacity/2). The capacity is the sum of the
%%% limits of the channel's current connections, or `none' when nothing is
%%% known (no connection up) or the server declared no limit; it is published as
%%% yuzu_gw_upstream_server_max_streams (0 for `none').
%%%
%%% The effective ceilings (effective_limits/3, yuzu_gw_upstream_permit_limit):
%%%   - The other upstream lanes are not regulated here and are subtracted
%%%     first: stream-status notifications (10 in flight), Guardian forwards
%%%     (50) and the heartbeat flush (1, serial): 61 streams,
%%%     yuzu_gw_upstream:reserved_streams/0.
%%%   - What is left, Capacity - 61, caps the register and inventory pools
%%%     together. When it is at least the two configured sizes together, they
%%%     apply unchanged (at the C++ default of 128 and pool_size 1: 67 left for
%%%     48 + 8). Otherwise it is split in proportion to the configured sizes:
%%%     register gets Left x R / (R + I) rounded down, inventory the rest, and
%%%     neither gets less than 1 or more than its configured size. A pool is
%%%     never closed outright: one permit each, even when the server allows
%%%     fewer streams than the other lanes reserve (a warning says so; then the
%%%     other lanes can themselves meet the limit, see yuzu_gw_upstream).
%%%   - The replay cap scales with register: configured replay x effective
%%%     register / configured register, rounded down, at least 1, at most the
%%%     effective register.
%%%   - With no capacity known, the configured sizes apply.
%%%
%%% Two limits of this sizing (#6057, from the independent review of
%%% 2026-10-18). (1) The capacity is SUMMED over the channel's connections, but
%%% gun enforces the server's limit PER CONNECTION and yuzu_grpc_client_channel:
%%% pick/2 hands calls out round-robin, so with more than one connection
%%% (pool_size above 1, or several endpoints) one connection can be asked for
%%% more streams than the server allows on it. Keep pool_size 1 and one
%%% endpoint, the shipped default; yuzu_gw_app warns at boot otherwise. (2)
%%% After the connection is lost, the capacity is `none' until the new
%%% connection's SETTINGS arrives, so the configured ceilings apply in that
%%% redial window: 48 + 8 permits plus the 61 reserved streams, 117, which fits
%%% the C++ default of 128; a server limit below that can be exceeded by the
%%% first burst, and the server's REFUSED_STREAM reset is an ordinary
%%% stream_error to yuzu_gw_upstream.
%%% Every change is applied at once. A ceiling that drops below the permits
%%% already held revokes nothing: those calls finish, and no permit of the pool
%%% is granted until the held count is below the new ceiling. A ceiling that
%%% rises serves the waiters at once.
%%%
%%% A grant can still race a decrease (the server lowered its limit while the
%%% caller was being granted). yuzu_gw_upstream treats the resulting
%%% too_many_streams as local backpressure: the caller hands its permit back,
%%% asks again (and waits in the queue below, within its deadline), and the
%%% circuit breaker is not touched.
%%%
%%% == Why these numbers ==
%%%
%%% The register pool, by Little's law (L = lambda x W). A restarted gateway can
%%% see its whole fleet register at once. 5,000 agents served inside 25 s (the
%%% agent's 30 s Register deadline less margin) is lambda = 200 per second; at
%%% W = 50 to 200 ms per server call that is L = 10 to 40 calls in flight, so 48
%%% serves the storm with margin even at 200 ms (240 per second: 5,000 in 21 s).
%%% Replay takes at most half, so live registrations always have 24 permits
%%% (half of a lowered register ceiling likewise; at a ceiling of one permit a
%%% replay can hold it, and a waiting live Register is still served first when
%%% it frees).
%%%
%%% The inventory pool is small: an inventory report is not on the path that
%%% gets an agent connected, and its payload is large (up to 4 MiB).
%%%
%%% == The wait queue ==
%%%
%%% A caller that finds no free permit waits, it is not refused (an agent whose
%%% retry has no jitter would otherwise be refused again in lockstep). The wait
%%% is bounded twice:
%%%   - by length: upstream_register_queue_max (default 10000, two of a 5,000
%%%     agent fleet) and upstream_inventory_queue_max (default 1000). A caller
%%%     that finds its queue full is refused at once (`overloaded'). Replays
%%%     are not counted: yuzu_gw_upstream runs at most the replay cap of them.
%%%   - by time: each caller carries its own deadline (sbroker-style). The
%%%     caller stops waiting at its deadline and cancels; a queued entry whose
%%%     deadline has passed when a permit frees is refused (`deadline') and
%%%     skipped. Nothing is served for a caller that has given up.
%%%
%%% == Holders are monitored ==
%%%
%%% The stream handler kills a request process on a reset, a deadline or a
%%% closed connection, and an exit signal skips any `after' clause, so a
%%% counter alone would leak the permit. Every holder and every waiter is
%%% monitored; its 'DOWN' frees what it held. A caller that timed out still
%%% alive cancels by message; a grant that crossed its cancel is dropped by the
%%% caller's request alias (gen_server:receive_response/2 abandons the request
%%% at its time-out) and freed by the cancel.
%%%
%%% == Stopping ==
%%%
%%% refuse_all/0 (a planned stop, yuzu_gw_app:prep_stop/1) refuses every
%%% waiter at once and every later request (`stopping'), so the agents go to
%%% another gateway instead of waiting on one that is going away.
%%%
%%% == Lock-free read ==
%%%
%%% The held and waiting counts of each class are published in an atomics
%%% array behind a persistent_term, so snapshot/0 and the pressure sampler read
%%% them without a call.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_regulator).
-behaviour(gen_server).

-export([start_link/0, ask/2, done/1, refuse_all/0, snapshot/0, limits/0]).
-export([server_capacity/2, effective_limits/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export_type([class/0, permit/0]).

-define(SERVER, ?MODULE).
-define(CELL, {?MODULE, cell}).
%% The channel every upstream call is made on (yuzu_gw_upstream:do_rpc/5).
-define(CHANNEL, default_channel).

-define(DEFAULT_REGISTER, 48).
-define(DEFAULT_INVENTORY, 8).
-define(DEFAULT_REGISTER_QUEUE, 10000).
-define(DEFAULT_INVENTORY_QUEUE, 1000).
-define(MAX_CONCURRENCY, 1024).
-define(MAX_QUEUE, 1000000).

%% Cell slots: held then waiting, per class, in this order.
-define(SLOT_REGISTER_HELD, 1).
-define(SLOT_REGISTER_WAIT, 2).
-define(SLOT_REPLAY_HELD, 3).
-define(SLOT_REPLAY_WAIT, 4).
-define(SLOT_INVENTORY_HELD, 5).
-define(SLOT_INVENTORY_WAIT, 6).
-define(SLOT_REGISTER_LIMIT, 7).
-define(SLOT_REPLAY_LIMIT, 8).
-define(SLOT_INVENTORY_LIMIT, 9).
-define(CELL_SLOTS, 9).

-type class() :: register | replay | inventory.
-opaque permit() :: {pid(), reference()}.
-type refusal() :: overloaded | deadline | stopping | unavailable.

-record(entry, {
    pid      :: pid(),
    mon      :: reference(),
    class    :: class(),
    deadline :: integer(),           %% monotonic ms
    asked    :: integer(),           %% monotonic native, for the wait histogram
    from     :: gen_server:from() | held
}).

-record(st, {
    %% the effective ceilings (effective_limits/3), what free/2 checks
    limit    :: #{class() => pos_integer()},
    %% the configured sizes (limits/0)
    configured :: #{class() => pos_integer()},
    %% what the channel learned of the server's stream limit
    capacity = none :: non_neg_integer() | none,
    qmax     :: #{class() => non_neg_integer() | infinity},
    held     = #{register => 0, replay => 0, inventory => 0} :: #{class() => non_neg_integer()},
    waiting  = #{register => 0, replay => 0, inventory => 0} :: #{class() => non_neg_integer()},
    queues   :: #{class() => queue:queue(reference())},
    entries  = #{} :: #{reference() => #entry{}},
    mons     = #{} :: #{reference() => reference()},
    stopping = false :: boolean()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Wait for a permit of Class until Deadline (monotonic milliseconds).
%% `{error, overloaded}' when the class's wait queue is full, `{error,
%% deadline}' when the deadline passed first (or had passed), `{error,
%% stopping}' during a planned stop, `{error, unavailable}' when this process
%% is not running. A permit is handed back with done/1; a caller that dies
%% holding one frees it by its death.
-spec ask(class(), integer()) -> {ok, permit()} | {error, refusal()}.
ask(Class, Deadline) when Class =:= register; Class =:= replay; Class =:= inventory ->
    case whereis(?SERVER) of
        undefined ->
            {error, unavailable};
        Pid ->
            Wait = Deadline - erlang:monotonic_time(millisecond),
            case Wait > 0 of
                false ->
                    {error, deadline};
                true ->
                    Tag = make_ref(),
                    ReqId = gen_server:send_request(Pid, {ask, Tag, Class, Deadline}),
                    case gen_server:receive_response(ReqId, Wait) of
                        {reply, granted} ->
                            {ok, {Pid, Tag}};
                        {reply, {refused, Reason}} ->
                            {error, Reason};
                        timeout ->
                            %% receive_response/2 abandoned the request: a grant
                            %% sent after this point is dropped by the alias, and
                            %% the cancel frees it.
                            gen_server:cast(Pid, {cancel, Tag}),
                            {error, deadline};
                        {error, {_Reason, _}} ->
                            {error, unavailable}
                    end
            end
    end.

%% @doc Hand a permit back. Safe to call twice, and after this process restarted.
-spec done(permit()) -> ok.
done({Pid, Tag}) ->
    gen_server:cast(Pid, {cancel, Tag}).

%% @doc The channel `Channel' learned that the server allows `Capacity'
%% concurrent streams on its connections together (`none': not known, or no
%% limit). Only `default_channel' counts. A cast; a no-op when this process is
%% not running (init/1 reads the channel's current value).
-spec server_capacity(atom(), non_neg_integer() | none) -> ok.
server_capacity(?CHANNEL, Capacity) ->
    case whereis(?SERVER) of
        undefined -> ok;
        Pid       -> gen_server:cast(Pid, {server_capacity, Capacity})
    end;
server_capacity(_Channel, _Capacity) ->
    ok.

%% @doc The effective permit ceilings for the configured sizes, the server's
%% capacity and the streams the other lanes reserve (see the module doc).
-spec effective_limits(#{register := pos_integer(), replay := pos_integer(),
                         inventory := pos_integer(), atom() => term()},
                       non_neg_integer() | none, non_neg_integer()) ->
          #{register := pos_integer(), replay := pos_integer(), inventory := pos_integer()}.
effective_limits(#{register := R, replay := P, inventory := I}, none, _Reserved) ->
    #{register => R, replay => P, inventory => I};
effective_limits(#{register := R, replay := P, inventory := I}, Capacity, Reserved) ->
    case max(0, Capacity - Reserved) of
        Left when Left >= R + I ->
            #{register => R, replay => P, inventory => I};
        Left ->
            Reg = min(R, max(1, Left * R div (R + I))),
            Inv = min(I, max(1, Left - Reg)),
            Rep = min(Reg, min(P, max(1, P * Reg div R))),
            #{register => Reg, replay => Rep, inventory => Inv}
    end.

%% @doc Refuse every waiter now and every later request (planned stop).
-spec refuse_all() -> ok.
refuse_all() ->
    case whereis(?SERVER) of
        undefined -> ok;
        Pid       -> gen_server:call(Pid, refuse_all, 5000)
    end.

%% @doc Held and waiting counts per class, read without a call.
-spec snapshot() -> #{class() => #{held := non_neg_integer(), waiting := non_neg_integer(),
                                   limit := non_neg_integer()}}.
snapshot() ->
    case persistent_term:get(?CELL, undefined) of
        undefined ->
            maps:from_keys([register, replay, inventory], #{held => 0, waiting => 0, limit => 0});
        Cell ->
            #{register  => read(Cell, ?SLOT_REGISTER_HELD, ?SLOT_REGISTER_WAIT, ?SLOT_REGISTER_LIMIT),
              replay    => read(Cell, ?SLOT_REPLAY_HELD, ?SLOT_REPLAY_WAIT, ?SLOT_REPLAY_LIMIT),
              inventory => read(Cell, ?SLOT_INVENTORY_HELD, ?SLOT_INVENTORY_WAIT,
                                ?SLOT_INVENTORY_LIMIT)}
    end.

read(Cell, H, W, L) ->
    #{held => atomics:get(Cell, H), waiting => atomics:get(Cell, W), limit => atomics:get(Cell, L)}.

%% @doc The configured permit counts, as init/1 reads them (also used by
%% yuzu_gw_upstream for its replay worker cap). The ceilings in force can be
%% lower: see effective_limits/3 and snapshot/0.
-spec limits() -> #{register := pos_integer(), replay := pos_integer(),
                    inventory := pos_integer(),
                    register_queue := non_neg_integer(),
                    inventory_queue := non_neg_integer()}.
limits() ->
    Register = yuzu_gw_env:env_int(upstream_register_concurrency, ?DEFAULT_REGISTER,
                                   1, ?MAX_CONCURRENCY),
    Replay = yuzu_gw_env:env_int(upstream_replay_concurrency, max(1, Register div 2),
                                 1, Register),
    #{register  => Register,
      replay    => Replay,
      inventory => yuzu_gw_env:env_int(upstream_inventory_concurrency, ?DEFAULT_INVENTORY,
                                       1, ?MAX_CONCURRENCY),
      register_queue => yuzu_gw_env:env_int(upstream_register_queue_max,
                                            ?DEFAULT_REGISTER_QUEUE, 0, ?MAX_QUEUE),
      inventory_queue => yuzu_gw_env:env_int(upstream_inventory_queue_max,
                                             ?DEFAULT_INVENTORY_QUEUE, 0, ?MAX_QUEUE)}.

%%%===================================================================
%%% gen_server
%%%===================================================================

init([]) ->
    #{register := R, replay := P, inventory := I,
      register_queue := RQ, inventory_queue := IQ} = limits(),
    Cell = cell(),
    [atomics:put(Cell, S, 0) || S <- lists:seq(1, ?SLOT_INVENTORY_WAIT)],
    Configured = #{register => R, replay => P, inventory => I},
    St0 = #st{limit  = Configured,
              configured = Configured,
              qmax   = #{register => RQ, replay => infinity, inventory => IQ},
              queues = maps:from_keys([register, replay, inventory], queue:new())},
    [emit(C, St0) || C <- [register, replay, inventory]],
    logger:info("Upstream permits configured: register=~b (replay at most ~b), inventory=~b; "
                "wait queues register=~b, inventory=~b", [R, P, I, RQ, IQ]),
    %% What the channel has learned so far; later changes arrive as casts.
    St = apply_capacity(yuzu_grpc_client_channel:server_capacity(?CHANNEL), St0, true),
    {ok, St}.

handle_call({ask, Tag, Class, Deadline}, {Pid, _} = From, St) ->
    Now = erlang:monotonic_time(millisecond),
    if
        St#st.stopping ->
            refused(Class, stopping),
            {reply, {refused, stopping}, St};
        Deadline =< Now ->
            refused(Class, deadline),
            {reply, {refused, deadline}, St};
        true ->
            case free(Class, St) andalso maps:get(Class, St#st.waiting) =:= 0 of
                true ->
                    {reply, granted, hold(Tag, Pid, Class, Deadline, erlang:monotonic_time(), St)};
                false ->
                    case maps:get(Class, St#st.waiting) >= maps:get(Class, St#st.qmax) of
                        true ->
                            refused(Class, queue_full),
                            {reply, {refused, overloaded}, St};
                        false ->
                            {noreply, enqueue(Tag, From, Class, Deadline, St)}
                    end
            end
    end;
handle_call(refuse_all, _From, St) ->
    St1 = lists:foldl(fun refuse_queue/2, St#st{stopping = true}, [register, replay, inventory]),
    {reply, ok, St1};
handle_call(_Req, _From, St) ->
    {reply, {error, unknown_call}, St}.

handle_cast({cancel, Tag}, St) ->
    {noreply, grant_next(release(Tag, St))};
handle_cast({server_capacity, Capacity}, St) ->
    {noreply, grant_next(apply_capacity(Capacity, St, false))};
handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info({'DOWN', Mon, process, _Pid, _Reason}, #st{mons = Mons} = St) ->
    case maps:find(Mon, Mons) of
        {ok, Tag} -> {noreply, grant_next(release(Tag, St))};
        error     -> {noreply, St}
    end;
handle_info(_Info, St) ->
    {noreply, St}.

terminate(_Reason, _St) ->
    ok.

code_change(_OldVsn, St, _Extra) ->
    {ok, St}.

%%%===================================================================
%%% Internal
%%%===================================================================

%% Take the server's capacity: recompute the ceilings, publish them (cell,
%% gauges) and log a change. Held permits are untouched; the caller runs
%% grant_next/1 for a ceiling that rose. Always publishes on the first call.
apply_capacity(Capacity, #st{configured = Configured, limit = Old, capacity = OldCap} = St,
               First) ->
    Reserved = yuzu_gw_upstream:reserved_streams(),
    New = effective_limits(Configured, Capacity, Reserved),
    St1 = St#st{limit = New, capacity = Capacity},
    case First orelse Capacity =/= OldCap of
        true ->
            telemetry:execute([yuzu, gw, upstream, server_max_streams],
                              #{streams => case Capacity of none -> 0; N -> N end}, #{});
        false ->
            ok
    end,
    case First orelse New =/= Old of
        true ->
            Cell = cell(),
            [begin
                 atomics:put(Cell, Slot, maps:get(C, New)),
                 telemetry:execute([yuzu, gw, upstream, permit_limit],
                                   #{limit => maps:get(C, New)}, #{class => C})
             end || {C, Slot} <- [{register, ?SLOT_REGISTER_LIMIT},
                                  {replay, ?SLOT_REPLAY_LIMIT},
                                  {inventory, ?SLOT_INVENTORY_LIMIT}]],
            log_limits(Capacity, Reserved, New, Configured);
        false ->
            ok
    end,
    St1.

log_limits(none, _Reserved, #{register := R, replay := P, inventory := I}, _Configured) ->
    logger:info("Upstream permits in force: register=~b (replay at most ~b), inventory=~b "
                "(the configured sizes; the server's stream limit is not known)", [R, P, I]);
log_limits(Capacity, Reserved, #{register := R, replay := P, inventory := I}, Configured) ->
    case Configured of
        #{register := R, replay := P, inventory := I} ->
            logger:info("Upstream permits in force: register=~b (replay at most ~b), "
                        "inventory=~b (the configured sizes; the server allows ~b concurrent "
                        "streams on the gateway's connections)", [R, P, I, Capacity]);
        #{register := CR, inventory := CI} when Capacity - Reserved < 2 ->
            logger:warning("The server allows ~b concurrent streams on the gateway's "
                           "connections; its other upstream lanes reserve ~b, so ProxyRegister "
                           "and ProxyInventory keep only one permit each (configured ~b and "
                           "~b) and the other lanes can meet the server's limit too. Raise the "
                           "server's --grpc-max-concurrent-streams or the channel's pool_size.",
                           [Capacity, Reserved, CR, CI]);
        #{register := CR, inventory := CI} ->
            logger:notice("Upstream permits lowered to the server's stream limit: register=~b "
                          "(replay at most ~b), inventory=~b, configured ~b and ~b (the server "
                          "allows ~b concurrent streams on the gateway's connections, ~b of them "
                          "kept for the other upstream lanes)",
                          [R, P, I, CR, CI, Capacity, Reserved])
    end.

%% A permit of Class is free: its pool has room, and a replay is under its own cap.
free(inventory, #st{held = H, limit = L}) ->
    maps:get(inventory, H) < maps:get(inventory, L);
free(register, #st{held = H, limit = L}) ->
    maps:get(register, H) + maps:get(replay, H) < maps:get(register, L);
free(replay, #st{held = H, limit = L} = St) ->
    maps:get(replay, H) < maps:get(replay, L) andalso free(register, St).

hold(Tag, Pid, Class, Deadline, Asked, #st{entries = E, mons = M, held = H} = St) ->
    Mon = erlang:monitor(process, Pid),
    observe_wait(Class, Asked),
    St1 = St#st{entries = E#{Tag => #entry{pid = Pid, mon = Mon, class = Class,
                                           deadline = Deadline, asked = Asked, from = held}},
                mons = M#{Mon => Tag},
                held = H#{Class := maps:get(Class, H) + 1}},
    emit(Class, St1),
    St1.

enqueue(Tag, {Pid, _} = From, Class, Deadline, #st{entries = E, mons = M, waiting = W,
                                                   queues = Q} = St) ->
    Mon = erlang:monitor(process, Pid),
    St1 = St#st{entries = E#{Tag => #entry{pid = Pid, mon = Mon, class = Class,
                                           deadline = Deadline, asked = erlang:monotonic_time(),
                                           from = From}},
                mons = M#{Mon => Tag},
                waiting = W#{Class := maps:get(Class, W) + 1},
                queues = Q#{Class := queue:in(Tag, maps:get(Class, Q))}},
    emit(Class, St1),
    St1.

%% Forget Tag, whether it holds a permit or waits for one. The queue keeps the
%% tag as a tombstone that grant_next/1 skips; compact/2 bounds them.
release(Tag, #st{entries = E, mons = M, held = H, waiting = W} = St) ->
    case maps:take(Tag, E) of
        error ->
            St;
        {#entry{mon = Mon, class = Class, from = held}, E1} ->
            erlang:demonitor(Mon, [flush]),
            St1 = St#st{entries = E1, mons = maps:remove(Mon, M),
                        held = H#{Class := maps:get(Class, H) - 1}},
            emit(Class, St1),
            St1;
        {#entry{mon = Mon, class = Class}, E1} ->
            erlang:demonitor(Mon, [flush]),
            St1 = compact(Class, St#st{entries = E1, mons = maps:remove(Mon, M),
                                       waiting = W#{Class := maps:get(Class, W) - 1}}),
            emit(Class, St1),
            St1
    end.

%% Hand free permits to waiters: live Registers before replays, each class
%% first come first served, expired waiters refused on the way.
grant_next(St) ->
    lists:foldl(fun grant_class/2, St, [register, replay, inventory]).

grant_class(Class, #st{queues = Q} = St) ->
    case free(Class, St) of
        false ->
            St;
        true ->
            case queue:out(maps:get(Class, Q)) of
                {empty, _} ->
                    St;
                {{value, Tag}, Rest} ->
                    St1 = St#st{queues = Q#{Class := Rest}},
                    grant_class(Class, serve(Tag, St1))
            end
    end.

serve(Tag, #st{entries = E, mons = M, waiting = W} = St) ->
    case maps:take(Tag, E) of
        error ->
            St;                                     %% a tombstone
        {#entry{pid = Pid, mon = Mon, class = Class, deadline = Deadline,
                asked = Asked, from = From}, E1} ->
            erlang:demonitor(Mon, [flush]),
            St1 = St#st{entries = E1, mons = maps:remove(Mon, M),
                        waiting = W#{Class := maps:get(Class, W) - 1}},
            case Deadline =< erlang:monotonic_time(millisecond) of
                true ->
                    refused(Class, deadline),
                    gen_server:reply(From, {refused, deadline}),
                    emit(Class, St1),
                    St1;
                false ->
                    gen_server:reply(From, granted),
                    hold(Tag, Pid, Class, Deadline, Asked, St1)
            end
    end.

refuse_queue(Class, #st{queues = Q} = St) ->
    St1 = lists:foldl(
            fun(Tag, #st{entries = E, mons = M, waiting = W} = Acc) ->
                    case maps:take(Tag, E) of
                        {#entry{mon = Mon, from = From}, E1} when From =/= held ->
                            erlang:demonitor(Mon, [flush]),
                            refused(Class, stopping),
                            gen_server:reply(From, {refused, stopping}),
                            Acc#st{entries = E1, mons = maps:remove(Mon, M),
                                   waiting = W#{Class := maps:get(Class, W) - 1}};
                        _ ->
                            Acc
                    end
            end, St, queue:to_list(maps:get(Class, Q))),
    St2 = St1#st{queues = Q#{Class := queue:new()}},
    emit(Class, St2),
    St2.

%% Drop tombstones once they outnumber the live waiters (plus a floor), so a
%% stream of callers that time out while the pool is stuck cannot grow the
%% queue without bound. Amortized O(1) per removal.
compact(Class, #st{queues = Q, waiting = W, entries = E} = St) ->
    Queue = maps:get(Class, Q),
    case queue:len(Queue) > 2 * maps:get(Class, W) + 64 of
        true  -> St#st{queues = Q#{Class := queue:filter(fun(T) -> maps:is_key(T, E) end, Queue)}};
        false -> St
    end.

cell() ->
    case persistent_term:get(?CELL, undefined) of
        undefined ->
            Cell = atomics:new(?CELL_SLOTS, [{signed, false}]),
            persistent_term:put(?CELL, Cell),
            Cell;
        Cell ->
            Cell
    end.

emit(Class, #st{held = H, waiting = W}) ->
    Held = maps:get(Class, H),
    Waiting = maps:get(Class, W),
    {HS, WS} = case Class of
                   register  -> {?SLOT_REGISTER_HELD, ?SLOT_REGISTER_WAIT};
                   replay    -> {?SLOT_REPLAY_HELD, ?SLOT_REPLAY_WAIT};
                   inventory -> {?SLOT_INVENTORY_HELD, ?SLOT_INVENTORY_WAIT}
               end,
    Cell = cell(),
    atomics:put(Cell, HS, Held),
    atomics:put(Cell, WS, Waiting),
    telemetry:execute([yuzu, gw, upstream, permits], #{held => Held, waiting => Waiting},
                      #{class => Class}).

refused(Class, Reason) ->
    telemetry:execute([yuzu, gw, upstream, permit_refused], #{count => 1},
                      #{class => Class, reason => Reason}).

observe_wait(Class, Asked) ->
    Seconds = erlang:convert_time_unit(erlang:monotonic_time() - Asked, native, microsecond) / 1.0e6,
    telemetry:execute([yuzu, gw, upstream, permit_wait], #{seconds => Seconds}, #{class => Class}).
