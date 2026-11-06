%%%-------------------------------------------------------------------
%%% @doc Supervised periodic sampler of the gateway's runtime state.
%%%
%%% Every telemetry_gauge_interval_ms (default 10 s) it emits telemetry events
%%% (yuzu_gw_telemetry turns them into Prometheus gauges):
%%%   - agent count (the registry's ETS table size)
%%%   - BEAM process count and memory breakdown
%%%   - scheduler utilisation of the NORMAL schedulers since the last tick
%%%     (wall-time deltas; the dirty schedulers, mostly idle, would dilute it)
%%%   - the run queue (erlang:statistics(total_run_queue_lengths), the cheap
%%%     call; statistics(run_queue) is documented as much more expensive)
%%%   - ports in use against the port limit and the OS file descriptor limit
%%%   - for a FIXED list of named singletons (processes/0): mailbox length and
%%%     queue wait
%%%   - per listener role: Ranch's active connections and max_connections
%%%     (ranch:info/1), and on the management listener the handler processes
%%%     its connections are running
%%%
%%% Bounded cost, whatever the fleet size: nothing here walks every process or
%%% every connection. The mailbox of each named process is one
%%% process_info(Pid, message_queue_len) (the length only, never the messages).
%%% The queue wait is a probe: a `{statistics, get}' system message (any OTP
%%% behaviour answers it, cheaply, in mailbox order) sent at one tick, answered
%%% when the process reaches it; the time it took is how long a message arriving
%%% then waited. While a probe is unanswered each tick reports the time since it
%%% was sent (a lower bound that grows), and no second probe is sent, so a stuck
%%% process gets one message per stuck period, not one per tick. A listener costs
%%% one ranch:info/1 (a message to each of its connection supervisors, about
%%% num_acceptors of them). The management listener's handler count is one
%%% count_children call per management connection (Cowboy's connection process
%%% answers the supervisor calls; the server holds one or a few connections),
%%% bounded by a short timeout; the agent listener's connections are never
%%% visited.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_gauge).
-behaviour(gen_server).

-export([start_link/0]).
-export([compute_scheduler_util/2, normal_schedulers/2, sampled_processes/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
%% How long one management connection may take to report its handler count.
-define(COUNT_CHILDREN_TIMEOUT_MS, 500).

-type label() :: atom().

-record(state, {
    interval   :: pos_integer(),
    prev_sched :: [{pos_integer(), non_neg_integer(), non_neg_integer()}] | undefined,
    processes  :: [{label(), atom()}],
    %% `env': the grpc_listeners entries of the application environment, read
    %% each tick; a list: these entries (a test).
    listeners  :: env | [map()],
    %% Outstanding queue-wait probes: Label => {Pid, Tag, SentAtMs}.
    probes = #{} :: #{label() => {pid(), reference(), integer()}}
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, #{}, []).

%% @doc The named processes whose mailbox and queue wait are sampled, as
%% {Label, RegisteredName}. A fixed list: the label set of
%% yuzu_gw_process_mailbox_len and yuzu_gw_process_queue_wait_seconds is exactly
%% these labels. Each is a single process every agent's traffic can queue on.
-spec sampled_processes() -> [{label(), atom()}].
sampled_processes() ->
    [{upstream, yuzu_gw_upstream},
     {upstream_regulator, yuzu_gw_upstream_regulator},
     {registry, yuzu_gw_registry},
     {router, yuzu_gw_router},
     {heartbeat_buffer, yuzu_gw_heartbeat_buffer},
     {agent_sup, yuzu_gw_agent_sup},
     %% the pg scope every registration joins
     {pg, yuzu_gw},
     %% the upstream channel the proxied calls use
     {upstream_channel, default_channel},
     %% OTP logger's default handler process
     {logger, logger_std_h_default}].

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%% Opts (tests): interval, processes, listeners. The supervised instance takes
%% the defaults.
init(Opts) when is_map(Opts) ->
    Interval = maps:get(interval, Opts,
                        application:get_env(yuzu_gw, telemetry_gauge_interval_ms, 10000)),
    %% Enable scheduler wall time tracking for utilization metrics.
    erlang:system_flag(scheduler_wall_time, true),
    PrevSched = erlang:statistics(scheduler_wall_time_all),
    %% The first sample at once: the series hold real values from the start,
    %% not only from the end of the first interval.
    self() ! tick,
    {ok, #state{interval = Interval, prev_sched = PrevSched,
                processes = maps:get(processes, Opts, sampled_processes()),
                listeners = maps:get(listeners, Opts, env)}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(tick, #state{interval = Interval, prev_sched = PrevSched} = State) ->
    %% Agent count — guard against registry not being up yet.
    Count = try yuzu_gw_registry:agent_count() catch _:_ -> 0 end,
    telemetry:execute([yuzu, gw, agent, count], #{count => Count}, #{}),

    %% BEAM process count.
    telemetry:execute([yuzu, gw, vm, process_count],
                      #{count => erlang:system_info(process_count)}, #{}),

    %% BEAM memory breakdown.
    Mem = erlang:memory(),
    telemetry:execute([yuzu, gw, vm, memory],
                      #{total     => proplists:get_value(total, Mem, 0),
                        processes => proplists:get_value(processes, Mem, 0),
                        ets       => proplists:get_value(ets, Mem, 0),
                        binary    => proplists:get_value(binary, Mem, 0)},
                      #{}),

    %% Scheduler utilization (delta-based).
    NewPrevSched = emit_scheduler_util(PrevSched),

    telemetry:execute([yuzu, gw, vm, run_queue],
                      #{length => erlang:statistics(total_run_queue_lengths)}, #{}),
    telemetry:execute([yuzu, gw, vm, ports],
                      #{count => erlang:system_info(port_count),
                        limit => erlang:system_info(port_limit),
                        fd_limit => fd_limit()}, #{}),

    Probes = sample_processes(State#state.processes, State#state.probes),
    sample_listeners(listener_entries(State#state.listeners)),

    erlang:send_after(Interval, self(), tick),
    {noreply, State#state{prev_sched = NewPrevSched, probes = Probes}};

%% A queue-wait probe answered (the reply to a `{statistics, get}' system message).
handle_info({Tag, _Reply}, #state{probes = Probes} = State) when is_reference(Tag) ->
    case [L || {L, {_Pid, T, _}} <- maps:to_list(Probes), T =:= Tag] of
        [Label] ->
            {_, _, SentAt} = maps:get(Label, Probes),
            emit_queue_wait(Label, erlang:monotonic_time(millisecond) - SentAt),
            {noreply, State#state{probes = maps:remove(Label, Probes)}};
        [] ->
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

emit_scheduler_util(PrevSched) ->
    case erlang:statistics(scheduler_wall_time_all) of
        undefined ->
            PrevSched;
        CurrSched when PrevSched =:= undefined ->
            %% First snapshot — no delta available yet.
            CurrSched;
        CurrSched ->
            N = erlang:system_info(schedulers),
            Avg = compute_scheduler_util(normal_schedulers(PrevSched, N),
                                         normal_schedulers(CurrSched, N)),
            telemetry:execute([yuzu, gw, vm, scheduler_util],
                              #{weighted_avg => Avg}, #{}),
            CurrSched
    end.

%% @doc The entries of the normal schedulers (ids 1..N) of a scheduler_wall_time
%% snapshot. statistics(scheduler_wall_time_all) also lists the dirty CPU and
%% dirty I/O schedulers after them; mostly idle, they would dilute the figure.
-spec normal_schedulers([{pos_integer(), non_neg_integer(), non_neg_integer()}],
                        pos_integer()) ->
    [{pos_integer(), non_neg_integer(), non_neg_integer()}].
normal_schedulers(Snapshot, N) ->
    [S || {Id, _, _} = S <- Snapshot, Id =< N].

%% @doc Compute scheduler utilization from two wall-time snapshots.
%% Returns a float in [0.0, 1.0].
%% Each snapshot is [{SchedulerId, ActiveTime, TotalTime}].
compute_scheduler_util(PrevSched, CurrSched) ->
    PrevMap = maps:from_list(
        [{Id, {Active, Total}} || {Id, Active, Total} <- PrevSched]),
    {DeltaActive, DeltaTotal} = lists:foldl(
        fun({Id, CurrActive, CurrTotal}, {AccActive, AccTotal}) ->
            case maps:find(Id, PrevMap) of
                {ok, {PrevActive, PrevTotal}} ->
                    {AccActive + (CurrActive - PrevActive),
                     AccTotal + (CurrTotal - PrevTotal)};
                error ->
                    {AccActive, AccTotal}
            end
        end, {0, 0}, CurrSched),
    case DeltaTotal of
        0 -> 0.0;
        _ -> DeltaActive / DeltaTotal
    end.

%% The OS file descriptor limit the emulator found at start (check_io's
%% max_fds; one entry per poll set, all the same), or undefined where it does
%% not report one.
fd_limit() ->
    try erlang:system_info(check_io) of
        Info when is_list(Info) ->
            case [M || P <- Info, is_list(P), {max_fds, M} <- P, is_integer(M), M > 0] ++
                 [M || {max_fds, M} <- Info, is_integer(M), M > 0] of
                [] -> undefined;
                Ms -> lists:max(Ms)
            end
    catch
        _:_ -> undefined
    end.

%% Mailbox length and queue wait of each named process. A name that is not
%% registered (the process is restarting, or not part of this configuration)
%% reads 0 for both.
sample_processes(Processes, Probes0) ->
    Now = erlang:monotonic_time(millisecond),
    lists:foldl(fun({Label, Name}, Probes) -> sample_process(Label, Name, Now, Probes) end,
                Probes0, Processes).

sample_process(Label, Name, Now, Probes) ->
    case whereis(Name) of
        Pid when is_pid(Pid) ->
            Len = case erlang:process_info(Pid, message_queue_len) of
                      {message_queue_len, N} -> N;
                      undefined -> 0
                  end,
            telemetry:execute([yuzu, gw, process, mailbox], #{len => Len},
                              #{process => Label}),
            case maps:get(Label, Probes, undefined) of
                {Pid, _Tag, SentAt} ->
                    %% Still unanswered: report how long so far, send no other.
                    emit_queue_wait(Label, Now - SentAt),
                    Probes;
                _ ->
                    Probes#{Label => {Pid, probe(Pid), Now}}
            end;
        _ ->
            telemetry:execute([yuzu, gw, process, mailbox], #{len => 0}, #{process => Label}),
            telemetry:execute([yuzu, gw, process, queue_wait], #{seconds => 0},
                              #{process => Label}),
            maps:remove(Label, Probes)
    end.

%% A `{statistics, get}' system message, the reply to which arrives as
%% {Tag, Reply}. It is handled in mailbox order like any message, and answered
%% without copying the process's state.
probe(Pid) ->
    Tag = make_ref(),
    _ = erlang:send(Pid, {system, {self(), Tag}, {statistics, get}}, [noconnect]),
    Tag.

emit_queue_wait(Label, Ms) ->
    telemetry:execute([yuzu, gw, process, queue_wait], #{seconds => Ms / 1000},
                      #{process => Label}).

listener_entries(env) ->
    case application:get_env(yuzu_gw, grpc_listeners, []) of
        L when is_list(L) -> [E || E <- L, is_map(E), is_map_key(name, E)];
        _ -> []
    end;
listener_entries(Entries) ->
    Entries.

%% Per listener role: the active connections and the ceiling, summed over the
%% listeners of that role (a ceiling of `infinity' on any makes the role's
%% infinity); and the handlers running on the management listener's
%% connections. A listener that is not running (restarting, or not started yet
%% at the first tick) is skipped for this tick.
sample_listeners(Entries) ->
    Infos = [{yuzu_grpc_listener:role(E), I}
             || E <- Entries, I <- [listener_info(E)], I =/= undefined],
    Roles = lists:usort([R || {R, _} <- Infos]),
    [telemetry:execute([yuzu, gw, listener, connections],
                       #{active => lists:sum([A || {R1, #{active := A}} <- Infos, R1 =:= R]),
                         max => sum_max([M || {R1, #{max := M}} <- Infos, R1 =:= R])},
                       #{listener => R})
     || R <- Roles],
    case [Ref || {management, #{ref := Ref}} <- Infos] of
        [] -> ok;
        Refs ->
            telemetry:execute([yuzu, gw, mgmt, streams],
                              #{count => lists:sum([handlers(C) || Ref <- Refs,
                                                                   C <- connections(Ref)])},
                              #{})
    end,
    ok.

listener_info(Entry) ->
    Ref = yuzu_grpc_listener:ref(Entry),
    try ranch:info(Ref) of
        #{active_connections := A, max_connections := M} ->
            #{ref => Ref, active => A, max => M}
    catch
        _:_ -> undefined
    end.

sum_max(Maxes) ->
    case lists:member(infinity, Maxes) of
        true -> infinity;
        false -> lists:sum(Maxes)
    end.

connections(Ref) ->
    try ranch:procs(Ref, connections)
    catch _:_ -> []
    end.

%% The handler processes a Cowboy connection is running: it answers the
%% supervisor call count_children (cowboy_children), one handler per stream
%% that has started one. A connection that does not answer in time counts 0.
handlers(Conn) ->
    try gen_server:call(Conn, count_children, ?COUNT_CHILDREN_TIMEOUT_MS) of
        Counts when is_list(Counts) -> proplists:get_value(active, Counts, 0);
        _ -> 0
    catch
        _:_ -> 0
    end.
