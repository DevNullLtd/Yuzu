%%%-------------------------------------------------------------------
%%% @doc The measuring end of the gateway scale suite (yuzu_gw_scale_SUITE),
%%% run INSIDE the gateway node under test.
%%%
%%% One sampler process, not linked to anything, started by the suite through
%%% peer:call after the gateway application is up. Every `interval_ms' it reads
%%% the mailbox length of each named singleton of the gateway (one
%%% process_info call per name, never a scan of all processes) and keeps the
%%% peak per name. It also holds the scheduler utilisation sample the suite asks
%%% for (scheduler:sample/0 turns scheduler wall-time accounting on for the
%%% process that calls it, so the sampler, which lives for the whole run, takes
%%% both samples).
%%%
%%% Not a test module: no *_test function, no eunit.hrl.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_scale_probe).

-export([start/1, stop/0, report/0, reset_hwm/0, sched_mark/0, sched_report/0,
         memory/0, mailboxes/0, singletons/0, footprint/1]).
-export([init/1]).

-define(NAME, yuzu_gw_scale_probe).

%% The named singletons every registration, notice or command passes through.
%% `yuzu_gw' is the pg scope, `default_channel' the upstream client channel.
-spec singletons() -> [atom()].
singletons() ->
    [yuzu_gw_upstream, yuzu_gw_upstream_regulator, yuzu_gw_registry, yuzu_gw_router,
     yuzu_gw_agent_sup, yuzu_gw_sup,
     yuzu_gw_heartbeat_buffer, yuzu_gw_upstream_pressure, yuzu_gw, default_channel,
     yuzu_gw_gauge, yuzu_gw_health, logger].

-spec start(pos_integer()) -> ok.
start(IntervalMs) ->
    stop(),
    Parent = self(),
    Pid = proc_lib:spawn(fun() -> init({Parent, IntervalMs}) end),
    receive {Pid, ready} -> ok after 5000 -> error(probe_not_ready) end.

-spec stop() -> ok.
stop() ->
    case whereis(?NAME) of
        undefined -> ok;
        Pid -> Ref = monitor(process, Pid), exit(Pid, kill),
               receive {'DOWN', Ref, process, Pid, _} -> ok end
    end.

%% @doc #{mailbox_hwm => #{Name => Peak}, samples => Count, memory_hwm => Bytes,
%% process_count_hwm => Count}.
-spec report() -> map().
report() -> call(report).

-spec reset_hwm() -> ok.
reset_hwm() -> call(reset_hwm).

%% @doc Take the scheduler sample a later sched_report/0 measures from.
-spec sched_mark() -> ok.
sched_mark() -> call(sched_mark).

%% @doc Scheduler utilisation since sched_mark/0: total and weighted, as
%% fractions (scheduler:utilization/2).
-spec sched_report() -> map().
sched_report() -> call(sched_report).

-spec memory() -> map().
memory() ->
    #{total => erlang:memory(total), processes => erlang:memory(processes),
      binary => erlang:memory(binary), ets => erlang:memory(ets),
      process_count => erlang:system_info(process_count),
      port_count => erlang:system_info(port_count)}.

%% @doc The current mailbox length of each singleton (absent names are left out).
-spec mailboxes() -> #{atom() => non_neg_integer()}.
mailboxes() ->
    maps:from_list([{N, L} || N <- singletons(), {ok, L} <- [qlen(N)]]).

%% @doc Where an agent's memory is: the average `memory' (bytes) of the three
%% processes one agent costs (its yuzu_gw_agent process, the Subscribe handler
%% that runs its stream, and the Cowboy connection process), over up to K
%% registered agents, as they are and after a garbage collection of each (the
%% difference is heap the process holds but no longer uses).
-spec footprint(pos_integer()) -> map().
footprint(K) ->
    Ids = lists:sublist(yuzu_gw_registry:all_agents(), K),
    Rows = [R || Id <- Ids, {ok, R} <- [footprint_one(Id)]],
    Avg = fun(Key) ->
                  case Rows of
                      [] -> 0;
                      _ -> lists:sum([maps:get(Key, R) || R <- Rows]) div length(Rows)
                  end
          end,
    #{sampled => length(Rows),
      agent_process => Avg(agent), agent_process_after_gc => Avg(agent_gc),
      stream_process => Avg(stream), stream_process_after_gc => Avg(stream_gc),
      connection_process => Avg(conn), connection_process_after_gc => Avg(conn_gc)}.

footprint_one(Id) ->
    try
        {ok, Agent} = yuzu_gw_registry:lookup(Id),
        {_State, Data} = sys:get_state(Agent, 5000),
        Stream = element(4, Data),          %% #data.stream_pid
        {links, Links} = process_info(Stream, links),
        [Conn | _] = [P || P <- Links, is_pid(P), P =/= Agent],
        Before = [mem(P) || P <- [Agent, Stream, Conn]],
        [garbage_collect(P) || P <- [Agent, Stream, Conn]],
        [AG, SG, CG] = [mem(P) || P <- [Agent, Stream, Conn]],
        [A, S, C] = Before,
        {ok, #{agent => A, stream => S, conn => C, agent_gc => AG, stream_gc => SG, conn_gc => CG}}
    catch _:_ -> error
    end.

mem(Pid) ->
    {memory, M} = process_info(Pid, memory),
    M.

call(Msg) ->
    Pid = whereis(?NAME),
    Ref = monitor(process, Pid),
    Pid ! {Msg, self(), Ref},
    receive
        {Ref, Reply} -> demonitor(Ref, [flush]), Reply;
        {'DOWN', Ref, process, Pid, Reason} -> error({probe_down, Reason})
    after 10000 -> error(probe_timeout)
    end.

init({Parent, IntervalMs}) ->
    register(?NAME, self()),
    Parent ! {self(), ready},
    loop(#{interval => IntervalMs, hwm => #{}, samples => 0,
           mem_hwm => 0, proc_hwm => 0, sched => undefined}, IntervalMs).

loop(S, Interval) ->
    receive
        {report, From, Ref} ->
            From ! {Ref, #{mailbox_hwm => maps:get(hwm, S), samples => maps:get(samples, S),
                           memory_hwm => maps:get(mem_hwm, S),
                           process_count_hwm => maps:get(proc_hwm, S)}},
            loop(S, Interval);
        {reset_hwm, From, Ref} ->
            From ! {Ref, ok},
            loop(S#{hwm := #{}, samples := 0, mem_hwm := 0, proc_hwm := 0}, Interval);
        {sched_mark, From, Ref} ->
            From ! {Ref, ok},
            loop(S#{sched := scheduler:sample()}, Interval);
        {sched_report, From, Ref} ->
            Reply = case maps:get(sched, S) of
                        undefined -> #{};
                        S0 -> util(scheduler:utilization(S0, scheduler:sample()))
                    end,
            From ! {Ref, Reply},
            loop(S, Interval)
    after Interval ->
        loop(sample(S), Interval)
    end.

sample(#{hwm := Hwm, samples := N, mem_hwm := M, proc_hwm := P} = S) ->
    Hwm1 = lists:foldl(fun(Name, Acc) ->
                               case qlen(Name) of
                                   {ok, L} -> maps:update_with(Name, fun(Old) -> max(Old, L) end,
                                                               L, Acc);
                                   error -> Acc
                               end
                       end, Hwm, singletons()),
    S#{hwm := Hwm1, samples := N + 1,
       mem_hwm := max(M, erlang:memory(total)),
       proc_hwm := max(P, erlang:system_info(process_count))}.

qlen(Name) ->
    case whereis(Name) of
        undefined -> error;
        Pid ->
            case process_info(Pid, message_queue_len) of
                {message_queue_len, L} -> {ok, L};
                undefined -> error
            end
    end.

util(List) ->
    Total = [F || {total, F, _} <- List],
    Weighted = [F || {weighted, F, _} <- List],
    Normal = [F || {normal, _Id, F, _} <- List],
    #{total => first(Total), weighted => first(Weighted),
      normal_max => case Normal of [] -> 0.0; _ -> lists:max(Normal) end,
      schedulers => length(Normal)}.

first([F | _]) -> F;
first([]) -> 0.0.
