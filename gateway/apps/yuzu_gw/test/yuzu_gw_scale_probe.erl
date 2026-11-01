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
%% Idle memory per connection (the idle_memory case of yuzu_gw_scale_SUITE).
-export([idle_sample/1, os_memory/0, socket_memory/1, roles/1, top_ets/1,
         heartbeat_buffer/0, gc_all/0]).
%% Crash and supervisor reports logged in this node (planned_stop counts them).
-export([count_crash_reports/0, crash_reports/0]).
%% Kill agent owner processes (owner_kill, OWNER-RESTART #5695).
-export([kill_owners/1, owner_events/1]).
-export([log/2]).  %% logger handler callback
%% The upstream as the gateway's own telemetry sees it (upstream_trace/0).
-export([upstream_trace/0, upstream_trace_reset/0, handle_event/4]).

-define(TRACE, yuzu_gw_scale_probe_trace).
-define(TRACE_EVENTS, [[yuzu, gw, upstream, rpc_latency], [yuzu, gw, upstream, rpc_error],
                       [yuzu, gw, upstream, circuit_state],
                       [yuzu, gw, upstream, registration_replay_triggered],
                       [yuzu, gw, agent, owner_restart]]).
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

%% @doc Count, from now on, every crash report (a process that died with an
%% exception, proc_lib) and every supervisor report (a child that died or
%% failed to start) logged in this node; read with crash_reports/0. A logger
%% handler with a counter of its own, so it outlives any process.
-spec count_crash_reports() -> ok.
count_crash_reports() ->
    C = counters:new(1, [write_concurrency]),
    persistent_term:put({?MODULE, crash_reports}, C),
    _ = logger:remove_handler(yuzu_gw_scale_crash_count),
    ok = logger:add_handler(yuzu_gw_scale_crash_count, ?MODULE,
                            #{level => error, config => #{counter => C}}).

-spec crash_reports() -> non_neg_integer().
crash_reports() ->
    counters:get(persistent_term:get({?MODULE, crash_reports}), 1).

log(#{msg := {report, #{label := {proc_lib, crash}}}}, #{config := #{counter := C}}) ->
    counters:add(C, 1, 1);
log(#{msg := {report, #{label := {supervisor, _}}}}, #{config := #{counter := C}}) ->
    counters:add(C, 1, 1);
log(_Event, _Config) ->
    ok.

%% @doc Kill (exit kill: no terminate, no cleanup) the owner process of each
%% agent id this node routes, as an untrappable crash would. Returns the
%% {AgentId, SessionId} of each owner killed; an id with no local owner is
%% left out.
-spec kill_owners([binary()]) -> [{binary(), binary() | undefined}].
kill_owners(Ids) ->
    lists:filtermap(fun(Id) ->
                            case yuzu_gw_registry:lookup_local_session(Id) of
                                {ok, {Pid, Session}} -> exit(Pid, kill), {true, {Id, Session}};
                                _ -> false
                            end
                    end, Ids).

%% @doc What each restarted owner of these agents did: {AgentId, SystemTimeMs,
%% Outcome, Why}.
-spec owner_events([binary()]) -> [{binary(), integer(), atom(), term()}].
owner_events(Ids) ->
    lists:append([[{Id, T, O, W} || {{owner, _, T, _}, O, W}
                                        <- ets:match_object(?TRACE, {{owner, Id, '_', '_'}, '_', '_'})]
                  || Id <- Ids]).

%% @doc What the gateway's own telemetry saw of the upstream since start/1 (or
%% upstream_trace_reset/0): every breaker transition with its time (ms since the
%% trace started), the BatchHeartbeat flushes' RPC time (stats, and how many
%% took over 1 s and over 4 s), upstream RPC errors by RPC and code, and the
%% replays started by trigger.
-spec upstream_trace() -> map().
upstream_trace() ->
    [{t0, T0}] = ets:lookup(?TRACE, t0),
    Rows = ets:tab2list(?TRACE),
    Hb = [D || {{hb, _}, D} <- Rows],
    Count = fun(Prefix) ->
                    maps:from_list([{K, N} || {{P, K}, N} <- Rows, P =:= Prefix])
            end,
    #{breaker => lists:sort([[T - T0, S] || {{cb, T, _}, S} <- Rows]),
      breaker_counts => Count(cb_count),
      batch_heartbeat_ms => stats(Hb),
      batch_heartbeat_over_1s => length([1 || D <- Hb, D > 1000]),
      batch_heartbeat_over_4s => length([1 || D <- Hb, D > 4000]),
      rpc_errors => Count(err),
      replay_triggers => Count(trigger)}.

-spec upstream_trace_reset() -> ok.
upstream_trace_reset() ->
    ets:delete_all_objects(?TRACE),
    ets:insert(?TRACE, {t0, erlang:system_time(millisecond)}),
    ok.

handle_event([yuzu, gw, upstream, rpc_latency], #{duration_ms := D},
             #{rpc_name := <<"batch_heartbeat">>}, _) ->
    ets:insert(?TRACE, {{hb, erlang:unique_integer([monotonic])}, D});
handle_event([yuzu, gw, upstream, rpc_error], #{count := N}, Meta, _) ->
    K = iolist_to_binary(io_lib:format("~s/~0p", [maps:get(rpc_name, Meta, <<"?">>),
                                                    maps:get(code, Meta, '?')])),
    ets:update_counter(?TRACE, {err, K}, N, {{err, K}, 0});
handle_event([yuzu, gw, upstream, circuit_state], _, #{state := S}, _) ->
    T = erlang:system_time(millisecond),
    ets:insert(?TRACE, {{cb, T, erlang:unique_integer([monotonic])}, S}),
    ets:update_counter(?TRACE, {cb_count, S}, 1, {{cb_count, S}, 0});
handle_event([yuzu, gw, upstream, registration_replay_triggered], #{count := N}, Meta, _) ->
    K = maps:get(trigger, Meta, unknown),
    ets:update_counter(?TRACE, {trigger, K}, N, {{trigger, K}, 0});
handle_event([yuzu, gw, agent, owner_restart], _, #{agent_id := Id} = Meta, _) ->
    ets:insert(?TRACE, {{owner, Id, erlang:system_time(millisecond),
                         erlang:unique_integer([monotonic])},
                        maps:get(outcome, Meta, unknown), maps:get(why, Meta, none)});
handle_event(_, _, _, _) ->
    ok.

stats([]) -> #{n => 0};
stats(L) ->
    S = lists:sort(L),
    N = length(S),
    P = fun(Q) -> lists:nth(max(1, min(N, round(Q / 100 * N))), S) end,
    #{n => N, p50 => P(50), p95 => P(95), p99 => P(99), max => lists:last(S),
      mean => lists:sum(S) / N}.

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
        {ok, #{agent := Agent, stream := Stream, conn := Conn}} = agent_processes(Id),
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

%% The long-lived processes one registered agent costs, by role: its
%% yuzu_gw_agent owner, the Subscribe handler (relay) that runs its stream, the
%% Cowboy HTTP/2 connection process and, on a TLS listener, OTP ssl's three
%% (the connection's dynamic supervisor, the receiver, which owns the TCP
%% socket and the connection state, and the sender). The ssl ones are found
%% from the socket the Cowboy process holds (an #sslsocket{} names the
%% receiver and the sender) and the receiver's parent.
-spec agent_processes(binary()) -> {ok, #{atom() => pid()}} | error.
agent_processes(Id) ->
    try
        {ok, Agent} = yuzu_gw_registry:lookup(Id),
        {_State, Data} = sys:get_state(Agent, 5000),
        Stream = element(4, Data),          %% #data.stream_pid
        {links, Links} = process_info(Stream, links),
        [Conn | _] = [P || P <- Links, is_pid(P), P =/= Agent],
        Base = #{agent => Agent, stream => Stream, conn => Conn},
        {ok, maps:merge(Base, ssl_processes(Conn))}
    catch _:_ -> error
    end.

ssl_processes(Conn) ->
    try sys:get_state(Conn, 5000) of
        State ->
            case find_sslsocket(State, 3) of
                {ok, Sock} ->
                    Pids = lists:usort([P || P <- deep_pids(Sock), P =/= Conn]),
                    ssl_roles(Pids);
                error -> #{}
            end
    catch _:_ -> #{}
    end.

%% The #sslsocket{} in a Cowboy connection's sys state (which may be wrapped,
%% e.g. {State, Buffer}), at most Depth tuples down.
find_sslsocket(T, _) when is_tuple(T), tuple_size(T) > 0, element(1, T) =:= sslsocket ->
    {ok, T};
find_sslsocket(T, D) when is_tuple(T), D > 0 ->
    first_ok([find_sslsocket(E, D - 1) || E <- tuple_to_list(T), is_tuple(E)]);
find_sslsocket(_, _) -> error.

first_ok([{ok, _} = Ok | _]) -> Ok;
first_ok([_ | T]) -> first_ok(T);
first_ok([]) -> error.

%% Of the pids an #sslsocket{} holds, the receiver is the one whose initial
%% call is the ssl connection state machine; the sender is tls_sender; the
%% receiver's parent ('$ancestors') is the per-connection supervisor.
ssl_roles(Pids) ->
    Named = [{role_of(P), P} || P <- Pids],
    Recv = proplists:get_value(ssl_receiver, Named),
    Sup = case Recv of
              undefined -> undefined;
              _ -> parent(Recv)
          end,
    maps:from_list([{R, P} || {R, P} <- [{ssl_sup, Sup} | Named], is_pid(P), R =/= other]).

role_of(P) ->
    case catch proc_lib:translate_initial_call(P) of
        {tls_sender, _, _} -> ssl_sender;
        {M, _, _} when M =:= tls_connection; M =:= tls_server_connection;
                       M =:= tls_gen_connection; M =:= ssl_gen_statem;
                       M =:= tls_client_connection -> ssl_receiver;
        _ -> other
    end.

parent(P) ->
    case process_info(P, dictionary) of
        {dictionary, D} ->
            case proplists:get_value('$ancestors', D) of
                [Parent | _] when is_pid(Parent) -> Parent;
                _ -> undefined
            end;
        _ -> undefined
    end.

deep_pids(P) when is_pid(P) -> [P];
deep_pids(T) when is_tuple(T) -> deep_pids(tuple_to_list(T));
deep_pids(L) when is_list(L) -> lists:append([deep_pids(E) || E <- L]);
deep_pids(_) -> [].

%% @doc Per role (see agent_processes/1), the average over up to K registered
%% agents of: `memory' (process_info, heap + stack + mailbox + process
%% struct), the refc binary bytes it references (off-heap, so NOT in
%% `memory', and counted in erlang:memory(binary)) shared out by reference
%% count, and the same two after a garbage collection of that process. Also
%% the role's process count per agent. The garbage collection changes the
%% sampled processes, so run it after the natural samples.
-spec roles(pos_integer()) -> map().
roles(K) ->
    Ids = lists:sublist(yuzu_gw_registry:all_agents(), K),
    Sets = [S || Id <- Ids, {ok, S} <- [agent_processes(Id)]],
    Measure = fun(P) -> #{memory => mem0(P), refc_binary => refc_bytes(P),
                         total_heap_words => heap_words(P)} end,
    Before = [maps:map(fun(_R, P) -> Measure(P) end, S) || S <- Sets],
    [[catch garbage_collect(P) || P <- maps:values(S)] || S <- Sets],
    After = [maps:map(fun(_R, P) -> Measure(P) end, S) || S <- Sets],
    Roles = lists:usort(lists:append([maps:keys(S) || S <- Sets])),
    Avg = fun(Rows, R, Key) ->
                  Vs = [maps:get(Key, maps:get(R, Row)) || Row <- Rows, is_map_key(R, Row)],
                  case Vs of [] -> 0; _ -> lists:sum(Vs) div length(Vs) end
          end,
    PerRole = maps:from_list(
                [{R, #{present_in => length([1 || S <- Sets, is_map_key(R, S)]),
                       memory => Avg(Before, R, memory),
                       refc_binary => Avg(Before, R, refc_binary),
                       memory_after_gc => Avg(After, R, memory),
                       refc_binary_after_gc => Avg(After, R, refc_binary)}}
                 || R <- Roles]),
    Sum = fun(Key) -> lists:sum([maps:get(Key, V) || V <- maps:values(PerRole)]) end,
    #{sampled => length(Sets), roles => PerRole,
      processes_per_agent => length(Roles),
      total => #{memory => Sum(memory), refc_binary => Sum(refc_binary),
                 memory_after_gc => Sum(memory_after_gc),
                 refc_binary_after_gc => Sum(refc_binary_after_gc)}}.

mem0(P) ->
    case process_info(P, memory) of {memory, M} -> M; undefined -> 0 end.

heap_words(P) ->
    case process_info(P, total_heap_size) of {total_heap_size, W} -> W; undefined -> 0 end.

refc_bytes(P) ->
    case process_info(P, binary) of
        {binary, Bins} -> lists:sum([Size div max(1, Refs) || {_, Size, Refs} <- Bins]);
        undefined -> 0
    end.

%% @doc One idle-memory sample of this node: erlang:memory/0 by category,
%% process and port counts, the OS view of this process (os_memory/0), the
%% kernel socket memory of the given listener ports (socket_memory/1), and
%% the heartbeat buffer's size (heartbeat_buffer/0).
-spec idle_sample([inet:port_number()]) -> map().
idle_sample(Ports) ->
    #{beam => maps:from_list(erlang:memory()),
      process_count => erlang:system_info(process_count),
      port_count => erlang:system_info(port_count),
      os => os_memory(),
      sockets => socket_memory(Ports),
      heartbeat_buffer => heartbeat_buffer(),
      ms => erlang:system_time(millisecond)}.

%% @doc This OS process's memory as the OS sees it, in bytes.
%% Linux: /proc/self/status (RssAnon = the kernel's count of the process's
%% anonymous resident pages, which is the budget's "OS anon"; RssFile, VmHWM)
%% and /proc/self/smaps_rollup (rss, pss, smaps_anon = its Anonymous). The
%% rollup is not the budget figure: it walks the mappings, and under the
%% release's allocator flags (carriers mapped and unmapped every heartbeat) a
%% read can miss some. On Rocky 9 (kernel 5.14) at 3,000 agents single reads
%% fell as far as 63% below the RssAnon read in the same sample (2026-10-27),
%% consistent with the walk dropping mmap_lock while a writer waits. macOS: `ps' RSS and `footprint' (the physical
%% footprint: dirty anonymous plus compressed pages, the nearest macOS has to
%% Linux's anonymous RSS). Elsewhere, or when a read fails: what was read.
-spec os_memory() -> map().
os_memory() ->
    case os:type() of
        {unix, linux} -> linux_memory();
        {unix, darwin} -> darwin_memory();
        _ -> #{source => none}
    end.

linux_memory() ->
    Rollup = kv_kb("/proc/self/smaps_rollup",
                   [{"Rss", rss}, {"Pss", pss}, {"Anonymous", smaps_anon}, {"Pss_Anon", pss_anon},
                    {"Private_Dirty", private_dirty}, {"Swap", swap}]),
    Status = kv_kb("/proc/self/status",
                   [{"VmRSS", vm_rss}, {"RssAnon", rss_anon}, {"RssFile", rss_file},
                    {"VmHWM", vm_hwm}, {"VmSize", vm_size}]),
    maps:merge(Status, Rollup#{source => smaps_rollup}).

%% "Key:   1234 kB" lines; values in bytes.
kv_kb(File, Keys) ->
    case file:read_file(File) of
        {ok, Bin} ->
            Lines = binary:split(Bin, <<"\n">>, [global]),
            maps:from_list(
              [{Out, Kb * 1024}
               || L <- Lines,
                  [K, V] <- [binary:split(L, <<":">>)],
                  {In, Out} <- Keys, K =:= list_to_binary(In),
                  {Kb, _} <- [string:to_integer(string:trim(binary_to_list(V)))],
                  is_integer(Kb)]);
        {error, _} -> #{}
    end.

darwin_memory() ->
    Pid = os:getpid(),
    Rss = case string:to_integer(string:trim(os:cmd("ps -o rss= -p " ++ Pid))) of
              {Kb, _} when is_integer(Kb) -> #{rss => Kb * 1024};
              _ -> #{}
          end,
    %% "name [pid]: 64-bit    Footprint: 1648 KB (16384 bytes per page)"
    Fp = case re:run(os:cmd("footprint " ++ Pid ++ " 2>/dev/null"),
                     "Footprint: ([0-9.]+) (B|KB|MB|GB)", [{capture, all_but_first, list}]) of
             {match, [N, U]} -> #{phys_footprint => scale(N, U)};
             nomatch -> #{}
         end,
    maps:merge(Rss, Fp#{source => ps_footprint}).

scale(N, U) ->
    V = case string:to_float(N) of
            {F, []} -> F;
            _ -> float(list_to_integer(N))
        end,
    Mul = case U of "B" -> 1; "KB" -> 1024; "MB" -> 1024 * 1024; "GB" -> 1024 * 1024 * 1024 end,
    round(V * Mul).

%% @doc Kernel memory of the TCP sockets on these local ports (the gateway's
%% agent listeners), outside the process and outside the budget, reported so a
%% regression there is still seen. Linux: `ss -tmn' per socket, summed:
%% `allocated' is r + t + f + w + o + bl + d (receive and send queues, forward
%% alloc, write queue, option memory, backlog, drops), `queued' is r + t,
%% `limits' rb + tb (the buffer sizes autotuned). Also the host-wide TCP
%% memory from /proc/net/sockstat (every socket on the host, the load
%% generator's included). macOS: `netstat' receive and send queue bytes only
%% (no allocation figures).
-spec socket_memory([inet:port_number()]) -> map().
socket_memory([]) -> #{};
socket_memory(Ports) ->
    case os:type() of
        {unix, linux} -> linux_sockets(Ports);
        {unix, darwin} -> darwin_sockets(Ports);
        _ -> #{source => none}
    end.

linux_sockets(Ports) ->
    Filter = string:join(["sport = :" ++ integer_to_list(P) || P <- Ports], " or "),
    Out = os:cmd(ss_path() ++ " -tmnH state established '( " ++ Filter ++ " )' 2>/dev/null"),
    Mems = [parse_skmem(M) || {match, [M]} <- [re:run(L, "skmem:\\(([^)]*)\\)",
                                                     [{capture, all_but_first, list}])
                                              || L <- string:split(Out, "\n", all)]],
    Sum = fun(Keys) -> lists:sum([maps:get(K, M, 0) || M <- Mems, K <- Keys]) end,
    Host = case file:read_file("/proc/net/sockstat") of
               {ok, B} ->
                   case re:run(B, "TCP: .* mem ([0-9]+)", [{capture, all_but_first, list}]) of
                       {match, [Pages]} -> list_to_integer(Pages) * 4096;
                       nomatch -> null
                   end;
               _ -> null
           end,
    Allocated = Sum([r, t, f, w, o, bl, d]),
    Socks = #{source => ss, sockets => length(Mems),
              allocated => Allocated, queued => Sum([r, t]),
              limits => Sum([rb, tb]), host_tcp_mem => Host},
    maps:merge(Socks, kernel_memory(Allocated, Host)).

%% @doc The kernel's per-connection memory beyond the socket buffers: slab.
%% Read from /proc/slabinfo (root only on most hosts, so `sudo -n cat' is
%% tried when the plain read is refused; with neither, only the socket
%% buffers are reported and `slab_source' says so). A group's figure is
%% active_objs * objsize summed over its caches: the objects in use. The
%% pages a cache holds (num_slabs * pagesperslab * page size) are not used for
%% the groups, because a cache with free space in its existing slabs absorbs
%% new objects without new pages, so the page count follows the host's
%% history more than the connections (at 200 kTLS connections on Rocky Linux 9 the
%% kmalloc pages grew 0.5 KB per connection for about 4 KB of objects); at
%% thousands of connections the two converge. `slab_total' is every cache's
%% pages, kept for reference. The caches a connection touches, in four groups:
%%
%%   slab_pair      one object per socket at EACH end of a connection: TCP,
%%                  TCPv6, sock_inode_cache, filp, dentry, eventpoll_epi,
%%                  eventpoll_pwq, lsm_inode_cache, lsm_file_cache. The
%%                  load generator runs on the same host, so its client
%%                  sockets hold the same objects; the gateway's share is half.
%%   slab_kmalloc   kmalloc-* (and kmalloc-cg-*, kmalloc-rcl-*): kTLS keeps
%%                  its context, AEAD transforms and RX parser here (about
%%                  4 KB per connection, measured 2026-10-28), plus small LSM
%%                  and socket blobs of both ends. Counted whole (the
%%                  client's small share makes this an overestimate).
%%   slab_conntrack nf_conntrack*: one entry per flow when conntrack is loaded
%%                  (a gateway host with conntrack pays it). Counted whole.
%%   slab_net       skbuff_*, tcp_bind_bucket, request_sock_TCP*, tw_sock_TCP*,
%%                  inet_peer_cache. Counted whole.
%%
%% kernel = slab_pair / 2 + slab_kmalloc + slab_conntrack + slab_net +
%% the gateway sockets' own buffers (`allocated', from ss): the gateway's
%% kernel memory. kernel_host = every group whole + /proc/net/sockstat's TCP
%% memory: both ends of every connection on the host, an upper bound. Both
%% are host-wide reads, so anything else on the host that allocates in these
%% caches between M(0) and M(N) shows up; `slab_total' (every cache) is kept
%% to make that visible.
kernel_memory(Allocated, HostTcp) ->
    case slabinfo() of
        {Source, Rows} ->
            G = fun(Pred) -> lists:sum([B || {Name, B, _} <- Rows, Pred(Name)]) end,
            Pair = G(fun(N) -> lists:member(N, ["TCP", "TCPv6", "sock_inode_cache", "filp",
                                                "dentry", "eventpoll_epi", "eventpoll_pwq",
                                                "lsm_inode_cache", "lsm_file_cache"]) end),
            Kmalloc = G(fun(N) -> lists:prefix("kmalloc-", N) end),
            Ct = G(fun(N) -> lists:prefix("nf_conntrack", N) end),
            Net = G(fun(N) -> lists:prefix("skbuff_", N) orelse lists:prefix("request_sock_TCP", N)
                                  orelse lists:prefix("tw_sock_TCP", N)
                                  orelse lists:member(N, ["tcp_bind_bucket", "inet_peer_cache"]) end),
            HostTcpB = case HostTcp of null -> 0; _ -> HostTcp end,
            #{slab_source => Source, slab_pair => Pair, slab_kmalloc => Kmalloc,
              slab_conntrack => Ct, slab_net => Net, slab_total => lists:sum([P || {_, _, P} <- Rows]),
              kernel => Pair div 2 + Kmalloc + Ct + Net + Allocated,
              kernel_host => Pair + Kmalloc + Ct + Net + HostTcpB};
        none ->
            #{slab_source => none, kernel => Allocated}
    end.

slabinfo() ->
    Text = case file:read_file("/proc/slabinfo") of
               {ok, B} -> {proc, binary_to_list(B)};
               {error, _} ->
                   case os:cmd("sudo -n cat /proc/slabinfo 2>/dev/null") of
                       "slabinfo" ++ _ = T -> {sudo, T};
                       _ -> none
                   end
           end,
    case Text of
        none -> none;
        {Src, T1} ->
            Page = page_size(),
            %% {Name, objects in use (bytes), pages held (bytes)}
            {Src, [{Name, Active * Size, NumSlabs * PagesPerSlab * Page}
                   || L <- string:split(T1, "\n", all),
                      [Name, A, _Num, Sz, _PerSlab, PPS | Rest] <- [string:lexemes(L, " ")],
                      hd(Name) =/= $#, Name =/= "slabinfo",
                      {Active, []} <- [string:to_integer(A)],
                      {Size, []} <- [string:to_integer(Sz)],
                      {PagesPerSlab, []} <- [string:to_integer(PPS)],
                      ["slabdata", _ActiveSlabs, NS | _] <- [lists:dropwhile(fun(X) -> X =/= "slabdata" end, Rest)],
                      {NumSlabs, []} <- [string:to_integer(NS)]]}
    end.

page_size() ->
    case string:to_integer(string:trim(os:cmd("getconf PAGESIZE 2>/dev/null"))) of
        {P, []} when P > 0 -> P;
        _ -> 4096
    end.

%% ss lives in /usr/sbin on most distributions, which a non-root PATH (the
%% node's, via os:cmd) often lacks.
ss_path() ->
    case [P || P <- ["/usr/sbin/ss", "/sbin/ss", "/usr/bin/ss", "/bin/ss"], filelib:is_regular(P)] of
        [P | _] -> P;
        [] -> case os:find_executable("ss") of false -> "ss"; P -> P end
    end.

%% "r0,rb131072,t0,tb87040,f0,w0,o0,bl0,d0"
parse_skmem(S) ->
    maps:from_list(
      [{list_to_atom(K), list_to_integer(V)}
       || Item <- string:split(S, ",", all),
          {match, [K, V]} <- [re:run(Item, "^([a-z]+)([0-9]+)$", [{capture, all_but_first, list}])]]).

darwin_sockets(Ports) ->
    Out = os:cmd("netstat -an -p tcp 2>/dev/null"),
    Suffixes = ["." ++ integer_to_list(P) || P <- Ports],
    Rows = [{list_to_integer(R), list_to_integer(S)}
            || L <- string:split(Out, "\n", all),
               [_Proto, R, S, Local, _Remote, "ESTABLISHED" | _] <- [string:lexemes(L, " ")],
               lists:any(fun(Sfx) -> lists:suffix(Sfx, Local) end, Suffixes)],
    #{source => netstat, sockets => length(Rows),
      queued => lists:sum([R + S || {R, S} <- Rows])}.

%% @doc The K largest ETS tables of the node by memory: name (or id), rows,
%% bytes.
-spec top_ets(pos_integer()) -> [map()].
top_ets(K) ->
    W = erlang:system_info(wordsize),
    Rows = [#{name => ets_name(T), size => S, bytes => M * W}
            || T <- ets:all(),
               [S, M] <- [[ets:info(T, size), ets:info(T, memory)]],
               is_integer(S), is_integer(M)],
    lists:sublist(lists:sort(fun(#{bytes := A}, #{bytes := B}) -> A >= B end, Rows), K).

ets_name(T) ->
    case ets:info(T, name) of
        N when is_atom(N) -> N;
        _ -> undefined
    end.

%% @doc The heartbeat buffer's size and what it dropped, by reason (the
%% buffer's own format_status/1 view; the drops from its Prometheus counter).
-spec heartbeat_buffer() -> map().
heartbeat_buffer() ->
    State = try sys:get_status(yuzu_gw_heartbeat_buffer, 5000) of
                Status -> find_map_with(buf_bytes, Status)
            catch _:_ -> #{}
            end,
    Drops = maps:from_list(
              [{R, V} || R <- [buffer_full, snapshot_oversize, snapshot_evicted,
                               heartbeat_oversize, heartbeat_invalid, chunk_rejected],
                         V <- [catch prometheus_counter:value(
                                       yuzu_gw_heartbeat_buffer_dropped_total, [R])],
                         is_number(V)]),
    maps:merge(maps:with([sessions, snapshots, buf_bytes, max_bytes], State),
               #{dropped => Drops,
                 process_memory => case whereis(yuzu_gw_heartbeat_buffer) of
                                       undefined -> 0;
                                       P -> mem0(P)
                                   end}).

find_map_with(Key, M) when is_map(M) ->
    case is_map_key(Key, M) of
        true -> M;
        false -> find_map_with(Key, maps:values(M))
    end;
find_map_with(Key, T) when is_tuple(T) -> find_map_with(Key, tuple_to_list(T));
find_map_with(Key, [H | T]) ->
    case find_map_with(Key, H) of
        #{} = M when map_size(M) > 0 -> M;
        _ -> find_map_with(Key, T)
    end;
find_map_with(_Key, _) -> #{}.

%% @doc Garbage-collect every process of the node (a diagnostic: what the
%% steady state holds that a collection would free).
-spec gc_all() -> ok.
gc_all() ->
    [garbage_collect(P) || P <- processes()],
    ok.

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
    %% The trace table lives with this process, which outlives the application.
    _ = (catch ets:delete(?TRACE)),
    ets:new(?TRACE, [named_table, public, set, {write_concurrency, true}]),
    ets:insert(?TRACE, {t0, erlang:system_time(millisecond)}),
    _ = telemetry:detach({?MODULE, trace}),
    ok = telemetry:attach_many({?MODULE, trace}, ?TRACE_EVENTS, fun ?MODULE:handle_event/4, #{}),
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
