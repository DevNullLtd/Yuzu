%%%-------------------------------------------------------------------
%%% @doc Node-wide memory load shedding: the third of the three bounds on an
%%% unauthenticated peer's memory use (the per-connection and per-stream bounds
%%% are in yuzu_grpc_stream_h).
%%%
%%% A gen_server samples erlang:memory(total) every interval_ms. Above a
%%% high-water mark it suspends the AGENT listener(s) in Ranch
%%% (ranch:suspend_listener/1): the socket stops accepting, new connections wait
%%% in the kernel backlog, and every connection already up is untouched. Below a
%%% low-water mark it resumes them. The two marks give hysteresis so a node
%%% hovering at the line does not flap. The MANAGEMENT listener is never
%%% suspended: the operator/command plane must stay reachable to drain the fleet
%%% and to act on the pressure.
%%%
%%% The marks are bytes. They may be given directly (high_water_bytes,
%%% low_water_bytes) or as a fraction of system memory (high_water_fraction
%%% default 0.75, low_water_fraction default 0.65); a fraction needs the system's
%%% total memory, read from /proc/meminfo (the Linux production target) without
%%% pulling in os_mon. Where that cannot be read (a non-Linux host with no
%%% absolute bytes configured) the shedder runs INACTIVE and says so: it is a
%%% backstop, and the per-connection and per-stream bounds still hold, so an
%%% unresolvable node-wide mark disables only the backstop, it does not fail
%%% boot. The config SHAPE is validated at boot by yuzu_gw_app:check_memory_shedding/0;
%%% an invalid shape is refused there.
%%%
%%% Config: {yuzu_gw, [{memory_shedding, #{high_water_fraction | high_water_bytes,
%%%                                         low_water_fraction | low_water_bytes,
%%%                                         interval_ms, enabled}}]}.
%%%
%%% Metrics (yuzu_gw_telemetry): a gauge of whether the agent listeners are
%%% currently shed (yuzu_gw_memory_shedding_active) and a counter of shed
%%% transitions (yuzu_gw_memory_shedding_suspensions_total). While shed, each
%%% suspended listener's ranch:get_status/1 reads `suspended', which
%%% yuzu_gw_health already treats as not-ready, so /readyz turns 503 and a load
%%% balancer drains this node without any change to the health module.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_memory_shedder).
-behaviour(gen_server).

-export([start_link/0, start_link/1, status/0, status/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

%% Exported for yuzu_gw_app's boot-time config check and for tests.
-export([validate_config/1, system_memory_bytes/0, sample_now/1]).

-define(SERVER, ?MODULE).
-define(DEFAULT_HIGH_FRACTION, 0.75).
-define(DEFAULT_LOW_FRACTION, 0.65).
-define(DEFAULT_INTERVAL_MS, 1000).

-record(st, {
    active = false :: boolean(),
    high :: non_neg_integer() | undefined,
    low :: non_neg_integer() | undefined,
    interval :: pos_integer() | undefined,
    refs = [] :: [term()],
    mem_fun :: fun(() -> non_neg_integer()),
    suspend_fun :: fun((term()) -> term()),
    resume_fun :: fun((term()) -> term()),
    suspended = false :: boolean(),
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
%% state, or `{error, inactive}' when the shedder did not resolve a watermark.
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
    Refs = maps:get(listener_refs, Opts, agent_listener_refs()),
    Base = #st{mem_fun = MemFun, suspend_fun = SuspendFun, resume_fun = ResumeFun, refs = Refs},
    case resolve(Cfg) of
        disabled ->
            logger:info("gateway memory shedding is disabled by configuration"),
            emit_active(0),
            {ok, Base#st{active = false}};
        {inactive, Reason} ->
            logger:warning("gateway memory shedding is inactive: ~p (the per-connection "
                           "and per-stream memory bounds still apply)", [Reason]),
            emit_active(0),
            {ok, Base#st{active = false}};
        {ok, High, Low, Interval} when Refs =:= [] ->
            logger:warning("gateway memory shedding has no agent listener to shed; inactive"),
            emit_active(0),
            {ok, Base#st{active = false, high = High, low = Low, interval = Interval}};
        {ok, High, Low, Interval} ->
            logger:info("gateway memory shedding active: high=~p bytes low=~p bytes "
                        "interval=~p ms listeners=~p", [High, Low, Interval, Refs]),
            emit_active(0),
            {ok, arm(Base#st{active = true, high = High, low = Low, interval = Interval})}
    end.

handle_call(status, _From, St) ->
    {reply, #{active => St#st.active, suspended => St#st.suspended,
              high => St#st.high, low => St#st.low, interval => St#st.interval,
              refs => St#st.refs}, St};
%% Test hook: run one sample synchronously and reply with the new shed state, so
%% a test drives the transition on an event rather than waiting for the timer.
handle_call(sample_now, _From, #st{active = true} = St) ->
    St1 = sample(St),
    {reply, {ok, St1#st.suspended}, St1};
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

%%--------------------------------------------------------------------
%% The sampling tick
%%--------------------------------------------------------------------

sample(#st{mem_fun = MemFun, high = High, low = Low, suspended = Suspended} = St) ->
    Mem = MemFun(),
    case {Suspended, Mem >= High, Mem =< Low} of
        {false, true, _} -> shed(St, Mem);
        {true, _, true}  -> unshed(St, Mem);
        {_, _, _}        -> St
    end.

shed(#st{refs = Refs, suspend_fun = Suspend} = St, Mem) ->
    logger:warning("gateway memory shedding ON: erlang:memory(total)=~p bytes >= high-water ~p; "
                   "suspending agent listener(s) ~p", [Mem, St#st.high, Refs]),
    [catch Suspend(Ref) || Ref <- Refs],
    telemetry:execute([yuzu, gw, memory_shedding, suspended], #{count => 1}, #{}),
    emit_active(1),
    St#st{suspended = true}.

unshed(#st{refs = Refs, resume_fun = Resume} = St, Mem) ->
    logger:info("gateway memory shedding OFF: erlang:memory(total)=~p bytes =< low-water ~p; "
                "resuming agent listener(s) ~p", [Mem, St#st.low, Refs]),
    [catch Resume(Ref) || Ref <- Refs],
    emit_active(0),
    St#st{suspended = false}.

emit_active(V) ->
    telemetry:execute([yuzu, gw, memory_shedding, state], #{active => V}, #{}).

arm(#st{interval = Interval} = St) ->
    St#st{timer = erlang:send_after(Interval, self(), tick)}.

%%--------------------------------------------------------------------
%% Config
%%--------------------------------------------------------------------

%% @doc Validate the memory_shedding config SHAPE for the boot guard. The
%% system-memory resolution a fraction needs is environmental, checked at init,
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

resolve(Cfg) ->
    case validate_config(Cfg) of
        {error, Reason} ->
            %% Shape was accepted at boot; a mismatch here is defensive only.
            {inactive, Reason};
        ok ->
            case maps:get(enabled, Cfg, true) of
                false -> disabled;
                true  -> resolve_marks(Cfg)
            end
    end.

resolve_marks(Cfg) ->
    Interval = maps:get(interval_ms, Cfg, ?DEFAULT_INTERVAL_MS),
    case mark(Cfg, high_water_bytes, high_water_fraction, ?DEFAULT_HIGH_FRACTION) of
        {error, HR} ->
            {inactive, HR};
        {ok, High} ->
            case mark(Cfg, low_water_bytes, low_water_fraction, ?DEFAULT_LOW_FRACTION) of
                {error, LR}             -> {inactive, LR};
                {ok, Low} when Low < High -> {ok, High, Low, Interval};
                {ok, _Low}              -> {inactive, low_water_not_below_high_water}
            end
    end.

%% Absolute bytes win; otherwise the fraction of system memory, if it can be read.
mark(Cfg, BytesKey, FractionKey, DefaultFraction) ->
    case maps:get(BytesKey, Cfg, undefined) of
        N when is_integer(N), N > 0 ->
            {ok, N};
        _ ->
            Fraction = maps:get(FractionKey, Cfg, DefaultFraction),
            case system_memory_bytes() of
                undefined -> {error, system_memory_unknown};
                Total     -> {ok, round(Total * Fraction)}
            end
    end.

%% @doc Total system memory in bytes, or `undefined' when it cannot be read
%% without os_mon. Linux: /proc/meminfo MemTotal (kB). Other platforms:
%% undefined (configure absolute bytes to shed there).
-spec system_memory_bytes() -> non_neg_integer() | undefined.
system_memory_bytes() ->
    case file:read_file("/proc/meminfo") of
        {ok, Data} -> meminfo_total(Data);
        _          -> undefined
    end.

meminfo_total(Data) ->
    case re:run(Data, "MemTotal:\\s+([0-9]+)\\s+kB", [{capture, [1], list}]) of
        {match, [KbStr]} -> list_to_integer(KbStr) * 1024;
        _                -> undefined
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
