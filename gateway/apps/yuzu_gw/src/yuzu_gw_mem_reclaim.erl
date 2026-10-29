%%%-------------------------------------------------------------------
%%% @doc Gives OS memory back after the agent population drops.
%%%
%%% After a connection storm or a drain, most of the memory the gateway still
%%% holds is garbage in the long-lived processes whose heaps grew during it
%%% (the Ranch connection supervisors, the acceptors, the registries): they
%%% are rarely collected because they are rarely busy afterwards. A full GC of
%%% them lets the VM return their carriers to the OS. On glibc, malloc_trim(0)
%%% then returns the free malloc arena pages (OpenSSL's, for one).
%%%
%%% Measured on 2026-10-29 (a transport + HTTP/2 probe, not the full gateway:
%%% 10,000 TLS connections, a 30,000-handshake storm, all closed; OrbStack
%%% arm64; dev's vm.args flags): two minutes after the close, OS anonymous
%%% memory above the pre-test level was +343 MiB on musl and +251 on glibc
%%% with nothing, about +150 on both with these GC passes, and +121 on glibc
%%% with the GC, malloc_trim and two other vm.args changes this module does
%%% not make. A single pass ran too early (the agent count falls before the
%%% closing connections' processes and buffers have gone), hence the second.
%%%
%%% What it does, in one gen_server:
%%%   reclaim   every interval_ms it reads the agent count (the size of the
%%%             registry table, O(1)) and keeps the peak. When the count has
%%%             fallen below the peak by drop_fraction of the peak AND by at
%%%             least min_drop agents, and min_gap_ms has passed since the
%%%             last pass, it garbage-collects every process holding more than
%%%             gc_min_bytes, then calls malloc_trim(0), logs one notice line,
%%%             and resets the peak to the current count. A follow-up pass
%%%             runs followup_ms later.
%%%   trim      every trim_interval_ms it calls malloc_trim(0) whatever the
%%%             count did.
%%%
%%% Cost. A pass walks erlang:processes() and reads process_info(P, memory)
%%% for each; only processes over gc_min_bytes are collected, so the ~2 KB
%%% hibernated agent connection processes of a large fleet are skipped. On
%%% 2026-10-29 a pass over 300,000 idle processes (plus 300 large ones to
%%% collect) took 350-450 ms on an Apple M5 Max laptop, almost all of it the
%%% walk; the time on the 100,000-agent rig (about 300,000 processes) is not
%%% measured yet. The pass runs in this process, never on an agent's path,
%%% and the malloc_trim NIF runs on a dirty CPU scheduler.
%%%
%%% malloc_trim is yuzu_gw_mem_trim, a NIF built only on glibc Linux. Where it
%%% is absent (the default Alpine image, macOS, Windows) the first trim logs
%%% one notice and every pass is GC only.
%%%
%%% This is an optional optimisation under a one_for_one supervisor with a
%%% restart intensity shared by the whole gateway, so nothing in it raises: a
%%% count_fun that raises or returns a non-integer skips the tick (the peak is
%%% kept, `count_errors' is incremented), and an invalid configuration value
%%% is replaced by its default with a warning.
%%%
%%% Configuration: {yuzu_gw, [{mem_reclaim, #{...}}]}; see defaults/0 and
%%% docs/user-manual/gateway.md, "Giving memory back after a drop".
%%% `enabled => false' starts the server idle.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mem_reclaim).
-behaviour(gen_server).

-export([start_link/0, start_link/1, reclaim_now/0, stats/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).
-ifdef(TEST).
-export([decide/3, validate/1]).
-endif.

-define(REGISTRY_TABLE, yuzu_gw_agents).

-type opts() :: #{enabled => boolean(),
                  interval_ms => pos_integer(),
                  drop_fraction => number(),
                  min_drop => non_neg_integer(),
                  min_gap_ms => non_neg_integer(),
                  gc_min_bytes => non_neg_integer(),
                  followup_ms => non_neg_integer(),
                  trim => boolean(),
                  trim_interval_ms => non_neg_integer(),
                  count_fun => fun(() -> non_neg_integer())}.

-type trim_result() :: 0 | 1 | unsupported | nif_not_loaded | disabled.

defaults() ->
    #{enabled => true,
      interval_ms => 10000,
      %% a quarter of the peak and at least 1,000 agents: a storm or a
      %% drain, not ordinary churn
      drop_fraction => 0.25,
      min_drop => 1000,
      min_gap_ms => 60000,
      %% a hibernated agent connection is a few KB and is skipped; the Ranch
      %% supervisors, acceptors and registries that grow in a storm are not
      gc_min_bytes => 32768,
      %% a second pass once the closing connections have gone: the count
      %% falls before their processes and buffers are freed (0: no second pass)
      followup_ms => 30000,
      %% malloc_trim(0) after each pass (glibc only; a no-op elsewhere)
      trim => true,
      %% malloc_trim(0) on its own every 5 minutes (0: never)
      trim_interval_ms => 300000,
      count_fun => fun registry_count/0}.

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    start_link(application:get_env(yuzu_gw, mem_reclaim, #{})).

-spec start_link(opts()) -> {ok, pid()} | {error, term()}.
start_link(Opts) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Opts, []).

%% @doc Run a reclaim pass now, whatever the count did. Returns what it did.
-spec reclaim_now() -> map().
reclaim_now() ->
    gen_server:call(?MODULE, reclaim_now, 60000).

-spec stats() -> map().
stats() ->
    gen_server:call(?MODULE, stats).

init(Opts0) ->
    Opts = validate(Opts0),
    St = #{opts => Opts, peak => 0, last => undefined, reclaims => 0, trims => 0,
           count_errors => 0, trim_warned => false, last_result => none},
    case maps:get(enabled, Opts) of
        true ->
            _ = erlang:send_after(maps:get(interval_ms, Opts), self(), tick),
            arm_trim(Opts),
            {ok, St};
        false ->
            {ok, St}
    end.

handle_call(reclaim_now, _From, St0) ->
    {Agents, St1} = count(St0),
    {Result, St2} = reclaim(Agents, St1),
    {reply, Result, St2};
handle_call(stats, _From, St) ->
    {reply, maps:without([opts], St), St};
handle_call(_Req, _From, St) ->
    {reply, {error, unknown_call}, St}.

handle_cast(_Msg, St) ->
    {noreply, St}.

handle_info(tick, #{opts := Opts} = St0) ->
    _ = erlang:send_after(maps:get(interval_ms, Opts), self(), tick),
    case count(St0) of
        {undefined, St1} ->
            {noreply, St1};
        {N, #{peak := Peak0, last := Last} = St1} ->
            Peak = max(Peak0, N),
            Now = erlang:monotonic_time(millisecond),
            GapOk = Last =:= undefined orelse Now - Last >= maps:get(min_gap_ms, Opts),
            case GapOk andalso decide(N, Peak, Opts) =:= reclaim of
                true ->
                    {_Result, St2} = reclaim(N, St1),
                    arm_followup(Opts),
                    {noreply, St2};
                false ->
                    {noreply, St1#{peak := Peak}}
            end
    end;
handle_info(followup, St0) ->
    {Agents, St1} = count(St0),
    {_Result, St2} = reclaim(Agents, St1),
    {noreply, St2};
handle_info(trim, #{opts := Opts} = St) ->
    arm_trim(Opts),
    {_, St1} = trim(St),
    {noreply, St1};
handle_info(_Info, St) ->
    {noreply, St}.

%% @doc reclaim when the count N has fallen far enough below the peak.
-spec decide(non_neg_integer(), non_neg_integer(), map()) -> reclaim | wait.
decide(N, Peak, #{drop_fraction := F, min_drop := Min}) ->
    Drop = Peak - N,
    case Drop >= Min andalso Drop >= F * Peak andalso Drop > 0 of
        true -> reclaim;
        false -> wait
    end.

%% One pass. Agents is the count just read, or undefined when it could not be
%% read (the peak is then kept as it was).
reclaim(Agents, #{opts := Opts, reclaims := R, peak := Peak} = St) ->
    T0 = erlang:monotonic_time(millisecond),
    Anon0 = rss_anon_kb(),
    Min = maps:get(gc_min_bytes, Opts),
    Self = self(),
    Gcd = length([P || P <- erlang:processes(), P =/= Self, big(P, Min),
                       erlang:garbage_collect(P)]),
    {Trim, St1} = case maps:get(trim, Opts) of
                      true -> trim(St);
                      false -> {disabled, St}
                  end,
    T1 = erlang:monotonic_time(millisecond),
    Result = #{agents => Agents, gc_processes => Gcd, trim => Trim,
               rss_anon_kb_before => Anon0, rss_anon_kb_after => rss_anon_kb(),
               ms => T1 - T0},
    logger:notice("gateway memory reclaim: ~p", [Result]),
    NewPeak = case Agents of
                  undefined -> Peak;
                  N -> N
              end,
    {Result, St1#{peak := NewPeak, last := T1, reclaims := R + 1,
                  last_result := Result}}.

big(P, Min) ->
    case erlang:process_info(P, memory) of
        {memory, M} -> M > Min;
        undefined -> false
    end.

-spec trim(map()) -> {trim_result(), map()}.
trim(#{trims := T} = St) ->
    try yuzu_gw_mem_trim:malloc_trim() of
        Released when is_integer(Released) -> {Released, St#{trims := T + 1}};
        unsupported -> {unsupported, warn_trim(unsupported, St)}
    catch
        error:nif_not_loaded -> {nif_not_loaded, warn_trim(nif_not_loaded, St)}
    end.

warn_trim(_Why, #{trim_warned := true} = St) ->
    St;
warn_trim(Why, St) ->
    logger:notice("gateway memory reclaim: malloc_trim unavailable (~p, ~p); "
                  "garbage collection only", [Why, yuzu_gw_mem_trim:loaded()]),
    St#{trim_warned := true}.

arm_trim(#{trim := false}) -> ok;
arm_trim(#{trim_interval_ms := 0}) -> ok;
arm_trim(#{trim_interval_ms := Ms}) -> _ = erlang:send_after(Ms, self(), trim), ok.

arm_followup(#{followup_ms := 0}) -> ok;
arm_followup(#{followup_ms := Ms}) -> _ = erlang:send_after(Ms, self(), followup), ok.

%% {Count, State}; Count is undefined (and count_errors incremented) when the
%% count function raised or did not return a non-negative integer.
count(#{opts := #{count_fun := F}, count_errors := E} = St) ->
    try F() of
        N when is_integer(N), N >= 0 -> {N, St};
        _ -> {undefined, St#{count_errors := E + 1}}
    catch
        _:_ -> {undefined, St#{count_errors := E + 1}}
    end.

registry_count() ->
    case ets:info(?REGISTRY_TABLE, size) of
        undefined -> 0;
        N -> N
    end.

rss_anon_kb() ->
    case file:read_file("/proc/self/status") of
        {ok, B} ->
            case binary:split(B, <<"RssAnon:">>) of
                [_, Rest] ->
                    case string:to_integer(string:trim(Rest, leading)) of
                        {Kb, _} when is_integer(Kb) -> Kb;
                        _ -> undefined
                    end;
                _ -> undefined
            end;
        _ -> undefined
    end.

%% @doc The defaults, overlaid with every valid key of Opts. An invalid value,
%% an unknown key or a non-map is logged and ignored.
-spec validate(term()) -> opts().
validate(Opts) when is_map(Opts) ->
    maps:fold(fun(K, V, Acc) ->
                      case is_map_key(K, Acc) andalso valid(K, V) of
                          true ->
                              Acc#{K := V};
                          false ->
                              logger:warning("gateway memory reclaim: ignoring "
                                             "{mem_reclaim, #{~p => ~p}}; using ~p",
                                             [K, V, maps:get(K, Acc, none)]),
                              Acc
                      end
              end, defaults(), Opts);
validate(Other) ->
    logger:warning("gateway memory reclaim: {mem_reclaim, ~p} is not a map; "
                   "using the defaults", [Other]),
    defaults().

valid(enabled, V) -> is_boolean(V);
valid(trim, V) -> is_boolean(V);
valid(interval_ms, V) -> is_integer(V) andalso V > 0;
valid(drop_fraction, V) -> is_number(V) andalso V > 0 andalso V =< 1;
valid(count_fun, V) -> is_function(V, 0);
valid(_NonNegInteger, V) -> is_integer(V) andalso V >= 0.
