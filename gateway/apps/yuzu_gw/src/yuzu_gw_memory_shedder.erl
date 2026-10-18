%%%-------------------------------------------------------------------
%%% @doc Node-wide memory load shedding: the third of the three bounds on an
%%% unauthenticated peer's memory use (the per-connection and per-stream bounds
%%% are in yuzu_grpc_stream_h).
%%%
%%% A gen_server samples erlang:memory(total) every interval_ms. Above a
%%% high-water mark it SHEDS: it suspends the AGENT listener(s) in Ranch
%%% (ranch:suspend_listener/1). Suspending closes the listen socket, so a new
%%% agent connection is REFUSED at once (ECONNREFUSED; connections the kernel
%%% had queued but Ranch had not accepted are reset), and every connection
%%% already up is untouched. Below a low-water mark it resumes them, which opens
%%% the socket again. The two marks give hysteresis so a node hovering at the
%%% line does not flap. The MANAGEMENT listener is never suspended: the
%%% operator/command plane must stay reachable to drain the fleet and to act on
%%% the pressure.
%%%
%%% Why refuse rather than leave connections waiting in the kernel backlog
%%% (which lowering Ranch's max_connections would do): a refused connect costs
%%% the agent nothing and sends it straight into its reconnect backoff, and a
%%% load balancer retries a refused connect on another node. A connection
%%% parked in the backlog completes the TCP handshake, so the agent's Register
%%% then waits on a TLS handshake nobody answers until gRPC gives up (about 18 s
%%% measured, agent.cpp kRegisterTimeout 30 s) and backs off anyway; a balancer
%%% sees a healthy connect and does not retry elsewhere; the parked connections
%%% hold kernel socket memory, which counts against a container's memory limit;
%%% and on resume every one of them, most already abandoned, is accepted in one
%%% burst just as memory has dropped below the low-water mark.
%%%
%%% Each tick DECIDES (shed or not, with the hysteresis above) and then
%%% RECONCILES every agent listener with the decision: one that is running while
%%% shed is suspended, one this shedder suspended is resumed when no longer
%%% shed. A suspend or resume that fails (resuming opens a socket, which can
%%% fail with eaddrinuse, emfile or enobufs) leaves that listener as it was and
%%% is tried again on the next tick; it is logged (the first failure, then at
%%% most once a minute while it lasts, and the recovery), counted
%%% (yuzu_gw_memory_shedding_transition_failures_total{action}) and shown
%%% (yuzu_gw_memory_shedding_transition_failing{action}, the listeners still
%%% not moved), and alerted on only when it lasts (YuzuGatewayMemoryShedding-
%%% TransitionFailing). A shedder that starts and finds an agent listener
%%% already suspended (it crashed while shed and the supervisor restarted it)
%%% takes that listener as its own: it starts shed and resumes it below the
%%% low-water mark. Nothing else suspends an agent listener while the shedder
%%% runs (the planned stop, yuzu_gw_app:prep_stop/1, stops the shedder first).
%%%
%%% The marks are bytes. They may be given directly (high_water_bytes,
%%% low_water_bytes) or as a fraction of the MEMORY LIMIT (high_water_fraction
%%% default 0.75, low_water_fraction default 0.65). The memory limit is the
%%% smaller of the host's memory (/proc/meminfo MemTotal; on macOS the
%%% hw.memsize sysctl) and the cgroup memory limit the process runs under, read
%%% once at start without pulling in os_mon: cgroup v2 memory.max ("max" is no
%%% limit) and cgroup v1 memory.limit_in_bytes (a value of 2^62 or more is no
%%% limit), in the process's own cgroup (from /proc/self/cgroup) and each of
%%% its ancestors, so a container limit and a systemd MemoryMax= are both seen.
%%% Without the cgroup a container's shedder used the host's memory and never
%%% tripped before the kernel's OOM killer did. A cgroup file that exists but
%%% cannot be read or parsed is logged and skipped (the host's memory is then
%%% used, which may be too high: set absolute bytes). Where no limit can be
%%% read at all (no cgroup, no /proc/meminfo, not macOS) and no absolute bytes
%%% are configured the shedder runs INACTIVE and says so: it is a backstop, and
%%% the per-connection and per-stream bounds still hold, so an unresolvable
%%% node-wide mark disables only the backstop, it does not fail boot; it is
%%% shown as yuzu_gw_memory_shedding_inactive = 1 (alert
%%% YuzuGatewayMemorySheddingInactive), never only as a log line.
%%%
%%% One absolute mark. When exactly one of high_water_bytes / low_water_bytes
%%% is set and the other mark is not set at all, the other is derived from it
%%% with the ratio of the fraction defaults (low = high x 0.65 / 0.75, high =
%%% low x 0.75 / 0.65; a derived high mark at or above the memory limit is
%%% clamped halfway between the low mark and the limit). Before, the unset mark
%%% took its fraction default, so high_water_bytes => 1 GiB on a 16 GiB host
%%% put the low mark at 10.4 GiB, above the high mark, and the shedder ran
%%% inactive with a warning line only (Dave Rae's review of 2026-10-18).
%%%
%%% Boot (yuzu_gw_app:check_memory_shedding/0, check_config/1) refuses an
%%% invalid SHAPE and, when shedding is enabled, marks that cannot work once
%%% resolved against the memory limit read at boot: a low mark not below the
%%% high mark, a mark at or above the memory limit (it could never act before
%%% the OOM killer), a mark that is not positive. The refusal names the
%%% settings (format_error/1).
%%%
%%% What is sampled stays erlang:memory(total), the memory the VM has
%%% allocated, not the cgroup's memory.current: that is what the agent
%%% connections cost and what shedding them relieves, it is read without file
%%% I/O, and it does not move with the page cache (memory.current counts file
%%% cache the kernel reclaims before any OOM, so log writes alone would trip
%%% the shedder). The cost is that it does not count allocator overhead, memory
%%% outside the VM's allocators or kernel socket buffers, all of which the
%%% cgroup does count; the default high-water mark of 0.75 of the limit leaves
%%% that quarter for them.
%%%
%%% Config: {yuzu_gw, [{memory_shedding, #{high_water_fraction | high_water_bytes,
%%%                                         low_water_fraction | low_water_bytes,
%%%                                         interval_ms, enabled}}]}.
%%%
%%% Metrics (yuzu_gw_telemetry): whether the shedder has decided to shed
%%% (yuzu_gw_memory_shedding_active), each shed decision
%%% (yuzu_gw_memory_shedding_suspensions_total), the marks in force
%%% (yuzu_gw_memory_shedding_{high,low}_water_bytes, 0 when inactive), whether
%%% shedding is enabled but cannot run (yuzu_gw_memory_shedding_inactive: 1
%%% when no memory limit is readable for a fraction, or the marks do not work;
%%% 0 while it runs, when it is disabled by configuration, and when there is no
%%% agent listener to shed) and the transition failures above. While an agent listener is suspended, shed or
%%% stuck after a failed resume, its ranch:get_status/1 reads `suspended',
%%% which yuzu_gw_health treats as not ready, so /readyz answers 503 and a load
%%% balancer drains this node; /readyz is ready again only once the listener is
%%% actually running.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_memory_shedder).
-behaviour(gen_server).

-export([start_link/0, start_link/1, status/0, status/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Exported for yuzu_gw_app's boot-time config check and for tests.
-export([validate_config/1, check_config/1, check_config/2, resolve_marks/2,
         format_error/1, system_memory_bytes/0, memory_limit/1, sample_now/1]).

-define(SERVER, ?MODULE).
-define(DEFAULT_HIGH_FRACTION, 0.75).
-define(DEFAULT_LOW_FRACTION, 0.65).
-define(DEFAULT_INTERVAL_MS, 1000).
%% While a suspend or resume keeps failing, how often it is logged again.
-define(FAIL_LOG_INTERVAL_MS, 60000).
%% A cgroup v1 memory.limit_in_bytes at or above this is "no limit" (the kernel
%% reports 2^63 - 4096 rounded down to the page size).
-define(V1_UNLIMITED, (1 bsl 62)).

-type action() :: suspend | resume.
-type limit_source() :: cgroup_v2 | cgroup_v1 | host | none.
-type limit_info() :: #{bytes := non_neg_integer() | undefined,
                        source := limit_source(),
                        cgroup := non_neg_integer() | unlimited | none,
                        host := non_neg_integer() | undefined,
                        unreadable := [{file:filename(), term()}]}.

%% A streak of failed attempts at one action: when it began, how many
%% attempts failed, when it was last logged.
-type streak() :: #{since := integer(), attempts := pos_integer(), logged := integer()}.

-record(st, {
    active = false :: boolean(),
    high :: non_neg_integer() | undefined,
    low :: non_neg_integer() | undefined,
    interval :: pos_integer() | undefined,
    refs = [] :: [term()],
    mem_fun :: fun(() -> non_neg_integer()),
    suspend_fun :: fun((term()) -> term()),
    resume_fun :: fun((term()) -> term()),
    status_fun :: fun((term()) -> term()),
    %% The decision: memory crossed the high-water mark and has not yet fallen
    %% to the low-water mark.
    shed = false :: boolean(),
    %% The listeners this shedder suspended (or found suspended at start), the
    %% only ones it resumes.
    owned = [] :: [term()],
    %% Listeners the last attempt of each action failed to move.
    failing = #{suspend => 0, resume => 0} :: #{action() => non_neg_integer()},
    streaks = #{} :: #{action() => streak()},
    limit :: limit_info() | undefined,
    timer :: reference() | undefined
}).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link(#{}).

%% @doc Start with test overrides. Opts keys (all optional):
%%   config        the memory_shedding map (default: the yuzu_gw env)
%%   listener_refs the Ranch refs to shed (default: the agent listeners of
%%                 {yuzu_gw, grpc_listeners})
%%   mem_fun       0-arity fun giving the sampled byte count (default
%%                 erlang:memory(total))
%%   suspend_fun   1-arity fun run to shed a ref (default ranch:suspend_listener)
%%   resume_fun    1-arity fun run to unshed a ref (default ranch:resume_listener)
%%   status_fun    1-arity fun giving a ref's status, running | suspended
%%                 (default ranch:get_status; a crash reads as `missing')
%%   memory_paths  where the memory limit is read from (memory_limit/1)
%%   register      whether to register the server name (default true)
-spec start_link(map()) -> {ok, pid()} | {error, term()}.
start_link(Opts) when is_map(Opts) ->
    case maps:get(register, Opts, true) of
        true  -> gen_server:start_link({local, ?SERVER}, ?MODULE, Opts, []);
        false -> gen_server:start_link(?MODULE, Opts, [])
    end.

%% @doc A snapshot of the registered shedder's state, for tests and diagnostics.
-spec status() -> map().
status() ->
    status(?SERVER).

-spec status(pid() | atom()) -> map().
status(Server) ->
    gen_server:call(Server, status, 5000).

%% @doc Run one sample synchronously (test hook); the reply is the new shed
%% decision, or `{error, inactive}' when the shedder did not resolve a
%% watermark.
-spec sample_now(pid() | atom()) -> {ok, boolean()} | {error, inactive}.
sample_now(Server) ->
    gen_server:call(Server, sample_now, 5000).

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------

init(Opts) ->
    Cfg = maps:get(config, Opts, application:get_env(yuzu_gw, memory_shedding, #{})),
    MemFun = maps:get(mem_fun, Opts, fun() -> erlang:memory(total) end),
    SuspendFun = maps:get(suspend_fun, Opts, fun ranch:suspend_listener/1),
    ResumeFun = maps:get(resume_fun, Opts, fun ranch:resume_listener/1),
    StatusFun = maps:get(status_fun, Opts, fun ranch:get_status/1),
    Refs = maps:get(listener_refs, Opts, agent_listener_refs()),
    Paths = maps:get(memory_paths, Opts, #{}),
    Base = #st{mem_fun = MemFun, suspend_fun = SuspendFun, resume_fun = ResumeFun,
               status_fun = StatusFun, refs = Refs},
    emit_failing(suspend, 0),
    emit_failing(resume, 0),
    case resolve(Cfg, Paths) of
        disabled ->
            logger:info("gateway memory shedding is disabled by configuration"),
            inactive(Base, 0);
        {inactive, Reason, Limit} ->
            logger:warning("gateway memory shedding is inactive: ~p (the per-connection "
                           "and per-stream memory bounds still apply; "
                           "yuzu_gw_memory_shedding_inactive reads 1). Set "
                           "memory_shedding high_water_bytes below this gateway's memory "
                           "limit", [Reason]),
            inactive(Base#st{limit = Limit}, 1);
        {error, Reason, Limit} ->
            %% The boot guard refuses this (check_config/1); here only when the
            %% shedder is started some other way (a test, a config changed
            %% under a running node).
            logger:warning("gateway memory shedding is inactive: ~ts (the per-connection "
                           "and per-stream memory bounds still apply; "
                           "yuzu_gw_memory_shedding_inactive reads 1)", [format_error(Reason)]),
            inactive(Base#st{limit = Limit}, 1);
        {ok, High, Low, Interval, Limit} when Refs =:= [] ->
            %% Nothing to shed is not an operator problem: no agent can connect.
            logger:warning("gateway memory shedding has no agent listener to shed; inactive"),
            inactive(Base#st{high = High, low = Low, interval = Interval, limit = Limit}, 0);
        {ok, High, Low, Interval, Limit} ->
            logger:info("gateway memory shedding active: high=~p bytes low=~p bytes "
                        "interval=~p ms listeners=~p (memory limit ~p bytes, from ~p)",
                        [High, Low, Interval, Refs, maps:get(bytes, Limit),
                         maps:get(source, Limit)]),
            St = Base#st{active = true, high = High, low = Low, interval = Interval,
                         limit = Limit},
            emit_marks(High, Low),
            emit_inactive(0),
            {ok, arm(adopt(St))}
    end.

handle_call(status, _From, St) ->
    {reply, #{active => St#st.active, shed => St#st.shed, suspended => St#st.shed,
              owned => St#st.owned, failing => St#st.failing,
              high => St#st.high, low => St#st.low, interval => St#st.interval,
              refs => St#st.refs, limit => St#st.limit}, St};
%% Test hook: run one sample synchronously and reply with the new decision, so
%% a test drives the transition on an event rather than waiting for the timer.
handle_call(sample_now, _From, #st{active = true} = St) ->
    St1 = sample(St),
    {reply, {ok, St1#st.shed}, St1};
handle_call(sample_now, _From, St) ->
    {reply, {error, inactive}, St};
handle_call(_Request, _From, St) ->
    {reply, {error, unknown_call}, St}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info(tick, #st{active = true} = St) ->
    {noreply, arm(sample(St))};
handle_info(_Info, St) ->
    {noreply, St}.

terminate(_Reason, _St) ->
    ok.

%% Inactive is 1 when shedding is enabled but cannot run (no memory limit
%% for a fraction, or marks that do not work), so an operator can be told
%% (YuzuGatewayMemorySheddingInactive); 0 when it is off on purpose.
inactive(St, Inactive) ->
    emit_active(0),
    emit_marks(0, 0),
    emit_inactive(Inactive),
    {ok, St#st{active = false}}.

%% A listener already suspended at start was suspended by a predecessor of this
%% process (nothing else suspends one while the shedder runs): take it as ours,
%% and start shed so it is resumed below the low-water mark, not stranded.
adopt(#st{refs = Refs} = St) ->
    case [Ref || Ref <- Refs, listener_status(St, Ref) =:= suspended] of
        [] ->
            emit_active(0),
            St;
        Owned ->
            logger:warning("gateway memory shedding: agent listener(s) ~p found suspended at "
                           "start; treating them as shed until memory is at or below the "
                           "low-water mark", [Owned]),
            emit_active(1),
            St#st{shed = true, owned = Owned}
    end.

%%--------------------------------------------------------------------
%% The sampling tick: decide, then reconcile the listeners with the decision
%%--------------------------------------------------------------------

sample(#st{mem_fun = MemFun} = St) ->
    reconcile(decide(St, MemFun())).

decide(#st{shed = false, high = High, refs = Refs} = St, Mem) when Mem >= High ->
    logger:warning("gateway memory shedding ON: erlang:memory(total)=~p bytes >= high-water ~p; "
                   "suspending agent listener(s) ~p (new agent connections are refused)",
                   [Mem, High, Refs]),
    telemetry:execute([yuzu, gw, memory_shedding, suspended], #{count => 1}, #{}),
    emit_active(1),
    St#st{shed = true};
decide(#st{shed = true, low = Low, owned = Owned} = St, Mem) when Mem =< Low ->
    logger:info("gateway memory shedding OFF: erlang:memory(total)=~p bytes =< low-water ~p; "
                "resuming agent listener(s) ~p", [Mem, Low, Owned]),
    emit_active(0),
    St#st{shed = false};
decide(St, _Mem) ->
    St.

%% Shed: every agent listener should be suspended, and becomes ours.
reconcile(#st{shed = true, refs = Refs, owned = Owned0} = St) ->
    {Owned, Failed} =
        lists:foldl(
          fun(Ref, {Own, Fail}) ->
                  case listener_status(St, Ref) of
                      suspended -> {add(Ref, Own), Fail};
                      missing   -> {Own, Fail};
                      running   ->
                          case attempt(St#st.suspend_fun, Ref) of
                              ok              -> {add(Ref, Own), Fail};
                              {error, Reason} -> {Own, [{Ref, Reason} | Fail]}
                          end
                  end
          end, {Owned0, []}, Refs),
    note(resume, [], note(suspend, lists:reverse(Failed), St#st{owned = Owned}));
%% Not shed: every listener we suspended should be running again; one whose
%% resume fails stays ours and is tried again next tick.
reconcile(#st{shed = false, owned = Owned0} = St) ->
    {Owned, Failed} =
        lists:foldl(
          fun(Ref, {Own, Fail}) ->
                  case listener_status(St, Ref) of
                      suspended ->
                          case attempt(St#st.resume_fun, Ref) of
                              ok              -> {Own, Fail};
                              {error, Reason} -> {[Ref | Own], [{Ref, Reason} | Fail]}
                          end;
                      _RunningOrMissing ->
                          {Own, Fail}
                  end
          end, {[], []}, Owned0),
    note(suspend, [], note(resume, lists:reverse(Failed),
                           St#st{owned = lists:reverse(Owned)})).

add(Ref, Refs) ->
    case lists:member(Ref, Refs) of
        true  -> Refs;
        false -> Refs ++ [Ref]
    end.

listener_status(#st{status_fun = StatusFun}, Ref) ->
    try StatusFun(Ref) of
        running   -> running;
        suspended -> suspended;
        _         -> missing
    catch
        _:_ -> missing
    end.

attempt(Fun, Ref) ->
    try Fun(Ref) of
        ok    -> ok;
        Other -> {error, Other}
    catch
        Class:Reason -> {error, {Class, Reason}}
    end.

%% Account for this tick's failures of Action: count them, log the start of a
%% streak, then at most once a minute while it lasts, and its end; publish the
%% number of listeners still not moved.
note(Action, [], #st{streaks = Streaks} = St) ->
    case maps:take(Action, Streaks) of
        {#{since := Since, attempts := N}, Rest} ->
            logger:info("gateway memory shedding: agent listener ~s succeeded after ~b failed "
                        "attempt(s) over ~b ms",
                        [Action, N, erlang:monotonic_time(millisecond) - Since]),
            set_failing(Action, 0, St#st{streaks = Rest});
        error ->
            set_failing(Action, 0, St)
    end;
note(Action, Failed, #st{streaks = Streaks, interval = Interval} = St) ->
    N = length(Failed),
    telemetry:execute([yuzu, gw, memory_shedding, transition_failed], #{count => N},
                      #{action => Action}),
    Now = erlang:monotonic_time(millisecond),
    Streak =
        case maps:find(Action, Streaks) of
            error ->
                logger:warning("gateway memory shedding: could not ~s agent listener(s) ~0p; "
                               "retrying every ~b ms", [Action, Failed, Interval]),
                #{since => Now, attempts => 1, logged => Now};
            {ok, #{since := Since, attempts := A, logged := Logged} = S}
              when Now - Logged >= ?FAIL_LOG_INTERVAL_MS ->
                logger:warning("gateway memory shedding: still could not ~s agent listener(s) "
                               "~0p after ~b attempts over ~b ms",
                               [Action, Failed, A + 1, Now - Since]),
                S#{attempts := A + 1, logged := Now};
            {ok, #{attempts := A} = S} ->
                S#{attempts := A + 1}
        end,
    set_failing(Action, N, St#st{streaks = Streaks#{Action => Streak}}).

set_failing(Action, N, #st{failing = Failing} = St) ->
    case maps:get(Action, Failing) of
        N -> St;
        _ -> emit_failing(Action, N),
             St#st{failing = Failing#{Action := N}}
    end.

emit_active(V) ->
    telemetry:execute([yuzu, gw, memory_shedding, state], #{active => V}, #{}).

emit_failing(Action, N) ->
    telemetry:execute([yuzu, gw, memory_shedding, failing], #{count => N}, #{action => Action}).

emit_marks(High, Low) ->
    telemetry:execute([yuzu, gw, memory_shedding, marks], #{high => High, low => Low}, #{}).

emit_inactive(V) ->
    telemetry:execute([yuzu, gw, memory_shedding, inactive], #{inactive => V}, #{}).

arm(#st{interval = Interval} = St) ->
    St#st{timer = erlang:send_after(Interval, self(), tick)}.

%%--------------------------------------------------------------------
%% Config
%%--------------------------------------------------------------------

%% @doc Validate the memory_shedding config SHAPE for the boot guard. The
%% memory-limit resolution a fraction needs is environmental, checked at init,
%% not here.
-spec validate_config(term()) -> ok | {error, term()}.
validate_config(Cfg) when is_map(Cfg) ->
    Checks =
        [{enabled, fun erlang:is_boolean/1},
         {interval_ms, fun(V) -> is_integer(V) andalso V > 0 end},
         {high_water_bytes, fun(V) -> is_integer(V) andalso V > 0 end},
         {low_water_bytes, fun(V) -> is_integer(V) andalso V > 0 end},
         {high_water_fraction, fun valid_fraction/1},
         {low_water_fraction, fun valid_fraction/1}],
    Allowed = [K || {K, _} <- Checks],
    case maps:keys(Cfg) -- Allowed of
        [] ->
            case [K || {K, Valid} <- Checks, maps:is_key(K, Cfg), not Valid(maps:get(K, Cfg))] of
                []  -> ok;
                Bad -> {error, {bad_memory_shedding_values, Bad}}
            end;
        Extra ->
            {error, {unknown_memory_shedding_keys, Extra}}
    end;
validate_config(_) ->
    {error, memory_shedding_not_a_map}.

valid_fraction(V) when is_float(V) -> V > 0.0 andalso V < 1.0;
valid_fraction(_) -> false.

%% @doc The boot guard's decision (yuzu_gw_app:check_memory_shedding/0): the
%% SHAPE (validate_config/1) and, when shedding is enabled, the marks resolved
%% against the memory limit read now (resolve_marks/2). Marks that cannot work
%% are refused; a fraction with no memory limit readable is not (the shedder
%% then runs inactive and says so: it is a backstop, environment-dependent).
-spec check_config(term()) -> ok | {error, term()}.
check_config(Cfg) ->
    check_config(Cfg, #{}).

%% @doc check_config/1 with the memory-limit paths of memory_limit/1 (tests).
-spec check_config(term(), map()) -> ok | {error, term()}.
check_config(Cfg, Paths) ->
    case validate_config(Cfg) of
        {error, _} = Error ->
            Error;
        ok ->
            case maps:get(enabled, Cfg, true) of
                false ->
                    ok;
                true ->
                    case resolve_marks(Cfg, maps:get(bytes, memory_limit(Paths))) of
                        {error, _} = Error -> Error;
                        _ -> ok
                    end
            end
    end.

resolve(Cfg, Paths) ->
    case validate_config(Cfg) of
        {error, Reason} ->
            %% Shape was accepted at boot; a mismatch here is defensive only.
            {inactive, Reason, undefined};
        ok ->
            case maps:get(enabled, Cfg, true) of
                false -> disabled;
                true  ->
                    Limit = memory_limit(Paths),
                    report_limit(Limit),
                    Interval = maps:get(interval_ms, Cfg, ?DEFAULT_INTERVAL_MS),
                    case resolve_marks(Cfg, maps:get(bytes, Limit)) of
                        {ok, High, Low} -> {ok, High, Low, Interval, Limit};
                        {inactive, Reason} -> {inactive, Reason, Limit};
                        {error, Reason} -> {error, Reason, Limit}
                    end
            end
    end.

%% @doc The high- and low-water marks of a (shape-valid) memory_shedding
%% config, given the memory limit in bytes (`undefined' when none could be
%% read).
%%
%% Each mark is its absolute bytes if set, else its fraction (configured or
%% default) of the memory limit. When exactly ONE mark of the pair is set in
%% bytes and the other is not set at all (neither bytes nor fraction), the
%% other is derived from it with the ratio the fraction defaults imply:
%% low = high x 0.65 / 0.75, high = low x 0.75 / 0.65. A derived high mark at
%% or above the memory limit is clamped to halfway between the low mark and the
%% limit. (Dave Rae's review of 2026-10-18: high_water_bytes alone used to
%% leave the low mark at 0.65 of the limit, above a small high mark, and the
%% shedder ran inactive with only a warning line.)
%%
%% `{error, Reason}' for marks that cannot work: a mark that is not positive,
%% a mark at or above the memory limit (the shedder could never act before the
%% OOM killer), or a low mark not below the high mark. The boot guard refuses
%% these. `{inactive, memory_limit_unknown}' when a mark needs the memory limit
%% and none could be read (not refused).
-spec resolve_marks(map(), non_neg_integer() | undefined) ->
          {ok, pos_integer(), pos_integer()} | {inactive, memory_limit_unknown}
          | {error, term()}.
resolve_marks(Cfg, Total) ->
    case marks(Cfg, Total) of
        {ok, High, Low} -> check_marks(High, Low, Total);
        {error, memory_limit_unknown} -> {inactive, memory_limit_unknown}
    end.

%% Each mark as {Bytes, From}, From saying where it came from (for the error
%% text).
marks(Cfg, Total) ->
    Has = fun(K) -> maps:is_key(K, Cfg) end,
    case {Has(high_water_bytes), Has(low_water_bytes),
          Has(high_water_fraction), Has(low_water_fraction)} of
        {true, false, _, false} ->
            High = maps:get(high_water_bytes, Cfg),
            {ok, {High, high_water_bytes},
             {round(High * ?DEFAULT_LOW_FRACTION / ?DEFAULT_HIGH_FRACTION),
              {derived_from, high_water_bytes}}};
        {false, true, false, _} ->
            Low = maps:get(low_water_bytes, Cfg),
            {ok, clamp_high(round(Low * ?DEFAULT_HIGH_FRACTION / ?DEFAULT_LOW_FRACTION),
                            Low, Total),
             {Low, low_water_bytes}};
        _ ->
            case {mark(Cfg, high_water_bytes, high_water_fraction, ?DEFAULT_HIGH_FRACTION, Total),
                  mark(Cfg, low_water_bytes, low_water_fraction, ?DEFAULT_LOW_FRACTION, Total)} of
                {{ok, High}, {ok, Low}} -> {ok, High, Low};
                _ -> {error, memory_limit_unknown}
            end
    end.

clamp_high(High, Low, Total) when is_integer(Total), High >= Total ->
    {(Low + Total) div 2, {derived_from, low_water_bytes, clamped_below_limit}};
clamp_high(High, _Low, _Total) ->
    {High, {derived_from, low_water_bytes}}.

%% Absolute bytes win; otherwise the fraction of the memory limit, if known.
mark(Cfg, BytesKey, FractionKey, DefaultFraction, Total) ->
    case {maps:get(BytesKey, Cfg, undefined), Total} of
        {N, _} when is_integer(N), N > 0 ->
            {ok, {N, BytesKey}};
        {_, undefined} ->
            {error, memory_limit_unknown};
        {_, _} ->
            case maps:find(FractionKey, Cfg) of
                {ok, F} -> {ok, {round(Total * F), {FractionKey, F}}};
                error -> {ok, {round(Total * DefaultFraction),
                               {default, FractionKey, DefaultFraction}}}
            end
    end.

%% Against the limit, the mark the operator set is reported first: a derived
%% mark above the limit is the consequence, not the setting to change.
check_marks({High, HF}, {Low, LF}, Total) ->
    Info = #{high => High, low => Low, high_from => HF, low_from => LF, limit => Total},
    HighOver = {is_integer(Total) andalso High >= Total, high_water_not_below_memory_limit},
    LowOver = {is_integer(Total) andalso Low >= Total, low_water_not_below_memory_limit},
    Checks = [{High =< 0 orelse Low =< 0, mark_not_positive}]
             ++ case derived(HF) of
                    true -> [LowOver, HighOver];
                    false -> [HighOver, LowOver]
                end
             ++ [{Low >= High, low_water_not_below_high_water}],
    case [Reason || {true, Reason} <- Checks] of
        [Reason | _] -> {error, {Reason, Info}};
        [] -> {ok, High, Low}
    end.

derived({derived_from, _}) -> true;
derived({derived_from, _, _}) -> true;
derived(_) -> false.

%% @doc An error of check_config/1 or resolve_marks/2 as text that names the
%% settings, for the boot refusal and the inactive warning.
-spec format_error(term()) -> string().
format_error({low_water_not_below_high_water, #{high := H, low := L} = I}) ->
    lists:flatten(io_lib:format(
      "the low-water mark (~b bytes, ~ts) is not below the high-water mark (~b bytes, "
      "~ts). Set low_water_bytes below high_water_bytes (or low_water_fraction below "
      "high_water_fraction), or set only high_water_bytes and let the low mark be "
      "derived from it", [L, from(maps:get(low_from, I)), H, from(maps:get(high_from, I))]));
format_error({high_water_not_below_memory_limit, #{high := H, limit := T} = I}) ->
    lists:flatten(io_lib:format(
      "the high-water mark (~b bytes, ~ts) is not below the gateway's memory limit (~b "
      "bytes, the smaller of host memory and the cgroup memory limit), so shedding could "
      "never start before the OOM killer. Set high_water_bytes below the limit",
      [H, from(maps:get(high_from, I)), T]));
format_error({low_water_not_below_memory_limit, #{low := L, limit := T} = I}) ->
    lists:flatten(io_lib:format(
      "the low-water mark (~b bytes, ~ts) is not below the gateway's memory limit (~b "
      "bytes, the smaller of host memory and the cgroup memory limit). Set "
      "low_water_bytes below the limit, or set high_water_bytes instead",
      [L, from(maps:get(low_from, I)), T]));
format_error({mark_not_positive, #{high := H, low := L} = I}) ->
    lists:flatten(io_lib:format(
      "a watermark is not positive: high-water ~b bytes (~ts), low-water ~b bytes (~ts). "
      "Set high_water_bytes and low_water_bytes to larger values",
      [H, from(maps:get(high_from, I)), L, from(maps:get(low_from, I))]));
format_error(Reason) ->
    lists:flatten(io_lib:format("~0tp", [Reason])).

from(high_water_bytes) -> "high_water_bytes";
from(low_water_bytes) -> "low_water_bytes";
from({derived_from, K}) -> "derived from " ++ from(K);
from({derived_from, K, clamped_below_limit}) ->
    "derived from " ++ from(K) ++ ", clamped below the memory limit";
from({K, F}) when is_atom(K), is_float(F) ->
    lists:flatten(io_lib:format("~ts ~tp of the memory limit", [K, F]));
from({default, K, F}) ->
    lists:flatten(io_lib:format("the default ~ts ~tp of the memory limit", [K, F])).

report_limit(#{unreadable := []}) ->
    ok;
report_limit(#{unreadable := Bad, bytes := Bytes, source := Source}) ->
    logger:warning("gateway memory shedding: could not read the cgroup memory limit from ~0p; "
                   "using ~p bytes (from ~p). If this gateway runs under a memory limit, "
                   "set memory_shedding high_water_bytes below it",
                   [Bad, Bytes, Source]).

%%--------------------------------------------------------------------
%% The memory limit
%%--------------------------------------------------------------------

%% @doc Total memory the marks are fractions of, in bytes: the smaller of the
%% host's memory and the cgroup memory limit, or `undefined' when neither can
%% be read.
-spec system_memory_bytes() -> non_neg_integer() | undefined.
system_memory_bytes() ->
    maps:get(bytes, memory_limit(#{})).

%% @doc The memory limit and where it came from. Paths (each optional, for
%% tests): cgroup_root (default "/sys/fs/cgroup"), proc_cgroup (default
%% "/proc/self/cgroup"), meminfo (default "/proc/meminfo"), darwin_sysctl
%% (default true: on macOS, read hw.memsize when there is no meminfo).
%%
%% The cgroup limit is the smallest of: cgroup v2 memory.max and cgroup v1
%% memory/memory.limit_in_bytes, in the process's own cgroup and each ancestor
%% up to the root of the mounted hierarchy. A file that does not exist is
%% skipped; one that exists but cannot be read or parsed is listed in
%% `unreadable' and skipped.
-spec memory_limit(map()) -> limit_info().
memory_limit(Paths0) when is_map(Paths0) ->
    Paths = maps:merge(#{cgroup_root => "/sys/fs/cgroup",
                         proc_cgroup => "/proc/self/cgroup",
                         meminfo => "/proc/meminfo",
                         darwin_sysctl => true}, Paths0),
    Host = host_memory_bytes(Paths),
    {Cgroup, Unreadable} = cgroup_limit(Paths),
    {Bytes, Source} =
        case {Cgroup, Host} of
            {{L, _Src}, H} when is_integer(H), H =< L -> {H, host};
            {{L, Src}, _}                             -> {L, Src};
            {_, H} when is_integer(H)                 -> {H, host};
            {_, undefined}                            -> {undefined, none}
        end,
    #{bytes => Bytes, source => Source, host => Host, unreadable => Unreadable,
      cgroup => case Cgroup of {C, _} -> C; Other -> Other end}.

host_memory_bytes(#{meminfo := Meminfo} = Paths) ->
    case file:read_file(Meminfo) of
        {ok, Data} ->
            meminfo_total(Data);
        _ ->
            case {os:type(), maps:get(darwin_sysctl, Paths)} of
                {{unix, darwin}, true} -> darwin_memsize();
                _                      -> undefined
            end
    end.

meminfo_total(Data) ->
    case re:run(Data, "MemTotal:\\s+([0-9]+)\\s+kB", [{capture, [1], list}]) of
        {match, [KbStr]} -> list_to_integer(KbStr) * 1024;
        _                -> undefined
    end.

%% macOS has neither /proc/meminfo nor cgroups. Read once, at start.
darwin_memsize() ->
    case string:to_integer(string:trim(os:cmd("/usr/sbin/sysctl -n hw.memsize"))) of
        {N, ""} when is_integer(N), N > 0 -> N;
        _ -> undefined
    end.

%% {Limit, Source} | unlimited | none, plus the files that could not be read.
cgroup_limit(#{cgroup_root := Root, proc_cgroup := ProcCgroup}) ->
    Lines = case file:read_file(ProcCgroup) of
                {ok, Data} -> binary:split(Data, <<"\n">>, [global, trim_all]);
                _          -> []
            end,
    V2Files = [{cgroup_v2, filename:join(Dir ++ ["memory.max"])}
               || Dir <- ancestors(Root, own_path(Lines, v2))],
    V1Files = [{cgroup_v1, filename:join(Dir ++ ["memory.limit_in_bytes"])}
               || Dir <- ancestors(filename:join(Root, "memory"), own_path(Lines, v1))],
    lists:foldl(fun({Src, File}, {Acc, Bad}) ->
                        case read_limit(Src, File) of
                            absent           -> {Acc, Bad};
                            unlimited        -> {tighter(unlimited, Acc), Bad};
                            {limit, N}       -> {tighter({N, Src}, Acc), Bad};
                            {unreadable, R}  -> {Acc, Bad ++ [{File, R}]}
                        end
                end, {none, []}, V2Files ++ V1Files).

%% The smaller limit wins; any limit beats `unlimited', which beats `none'.
tighter({N, _} = New, {M, _}) when N < M -> New;
tighter(_New, {_, _} = Old)              -> Old;
tighter({_, _} = New, _Old)              -> New;
tighter(unlimited, _Old)                 -> unlimited.

%% The process's cgroup path from /proc/self/cgroup: the "0::" line for v2,
%% the line whose controller list names `memory' for v1. "/" when absent.
own_path(Lines, v2) ->
    first_path([P || <<"0::", P/binary>> <- Lines]);
own_path(Lines, v1) ->
    first_path([iolist_to_binary(lists:join(<<":">>, Rest))
                || L <- Lines,
                   [_Id, Ctrls | Rest] <- [binary:split(L, <<":">>, [global])],
                   Rest =/= [],
                   lists:member(<<"memory">>, binary:split(Ctrls, <<",">>, [global]))]).

first_path([P | _]) -> binary_to_list(P);
first_path([])      -> "/".

%% The directories to read, deepest first: Root/a/b, Root/a, Root. A path that
%% climbs out of the cgroup namespace ("/../..") is not followed; only Root is
%% read.
ancestors(Root, Path) ->
    Parts = string:lexemes(Path, "/"),
    case lists:member("..", Parts) orelse lists:member(".", Parts) of
        true  -> [[Root]];
        false -> [[Root | lists:sublist(Parts, N)] || N <- lists:seq(length(Parts), 0, -1)]
    end.

read_limit(Src, File) ->
    case file:read_file(File) of
        {ok, Data} ->
            case {Src, string:trim(binary_to_list(Data))} of
                {cgroup_v2, "max"} ->
                    unlimited;
                {_, Str} ->
                    case string:to_integer(Str) of
                        {N, ""} when is_integer(N), N >= 0, Src =:= cgroup_v1,
                                     N >= ?V1_UNLIMITED -> unlimited;
                        {N, ""} when is_integer(N), N >= 0 -> {limit, N};
                        _ -> {unreadable, bad_value}
                    end
            end;
        {error, enoent}  -> absent;
        {error, enotdir} -> absent;
        {error, Reason}  -> {unreadable, Reason}
    end.

%% The Ranch refs of the listeners that route the agent service; never the
%% management listener (which must stay reachable under pressure).
agent_listener_refs() ->
    case application:get_env(yuzu_gw, grpc_listeners, []) of
        Listeners when is_list(Listeners) ->
            [{yuzu_grpc, maps:get(name, E)}
             || E <- Listeners, is_map(E), maps:is_key(name, E),
                yuzu_grpc_listener:routes_agent(E)];
        _ ->
            []
    end.
