%%%-------------------------------------------------------------------
%%% @doc How much of the time the path to the C++ server is backed up, and the
%%% definition of a slow server that follows from it.
%%%
%%% == Definition ==
%%%
%%% The gateway reaches the server through lanes of bounded capacity. A lane is
%%% SATURATED at an instant when work is waiting on it or would be refused:
%%%
%%%   permits   a live ProxyRegister or ProxyInventory is waiting for a permit:
%%%             every permit of its pool is held (yuzu_gw_upstream_regulator;
%%%             48 for Register, 8 for inventory by default). A registration
%%%             replay waiting for one does not count: it waits behind live
%%%             registrations by design.
%%%   notify    all of the stream-status notification slots the upstream may
%%%             fill now are held (10). The next notification is held until a
%%%             slot frees (and is dropped only when the held store is full).
%%%   guardian  all of the Guardian forward slots are held (50): the next one
%%%             would be dropped.
%%%
%%% BACKPRESSURE is present at an instant when at least one lane is saturated.
%%% The DUTY CYCLE is the share of a window during which backpressure was
%%% present, a number from 0 to 1. The window is the trailing 60 s, kept as 60
%%% one-second buckets.
%%%
%%% A SLOW SERVER, as one gateway sees it, is a duty cycle of 0.5 or more: for at
%%% least half of the last minute, work waited on the server or was refused
%%% because it answered slower than work arrived. The comparison is `>=', so
%%% exactly 0.5 is slow. Until the process has run for a minute the missing
%%% seconds count as not saturated, so the figure can only under-read after a
%%% start, never over-read.
%%%
%%% What this does not tell apart: a server that answers slowly, and a burst of
%%% work (every agent of a restarted fleet registering at once) larger than the
%%% permits drain at a healthy server's pace. Both are the server's
%%% service rate being below the rate work arrives, which is the thing measured.
%%% yuzu_gw_upstream_rpc_duration_ms says which it was.
%%%
%%% == How it is measured ==
%%%
%%% A process samples the lanes every 100 ms, reading yuzu_gw_upstream:
%%% lane_snapshot/0, which makes no call into the upstream process (a call would
%%% wait for the slow RPC being measured). Each sample is held until the next
%%% one, so a state is credited with the time since the previous sample. One
%%% step is credited at most 1 s, so a VM that was stopped for a minute does not
%%% credit a minute. That is a sampled estimate with a resolution of 100 ms: a
%%% state that begins and ends between two samples is missed, one that straddles
%%% a sample is credited a whole interval. Over many intervals the two errors
%%% cancel, and none of them can push a bucket past its second.
%%%
%%% Once a second it emits two telemetry events, which yuzu_gw_telemetry turns
%%% into these metrics (all without a label per agent):
%%%
%%%   yuzu_gw_upstream_backpressure_seconds_total          seconds with any lane
%%%                                                         saturated; its rate()
%%%                                                         is the duty cycle
%%%   yuzu_gw_upstream_lane_saturated_seconds_total{lane}  the same, per lane
%%%   yuzu_gw_upstream_backpressure_duty_cycle             the trailing-60 s duty
%%%                                                         cycle, computed here
%%%   yuzu_gw_upstream_slow                                1 when that is >= 0.5
%%%
%%% The per-lane counters overlap (two lanes can be saturated at once), so they
%%% are never added together: the figure for the gateway as a whole is the first.
%%%
%%% The duty cycle is not a readiness input. A slow server is a reason to look,
%%% not a reason to take a gateway out of rotation: the gateways that would be
%%% left carry the same load against the same server.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_pressure).
-behaviour(gen_server).

-export([start_link/0]).
-export([new/1, observe/3, duty_cycle/2, slow/1, saturated/1,
         sample_ms/0, window_s/0, slow_threshold/0, lanes/0]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
-export_type([acc/0, sample/0, delta/0]).

-define(SERVER, ?MODULE).
-define(SAMPLE_MS, 100).
-define(EMIT_MS, 1000).
-define(WINDOW_S, 60).
-define(SLOW_THRESHOLD, 0.5).
%% The most one step is credited, and the most one bucket may hold.
-define(MAX_STEP_MS, 1000).
-define(BUCKET_MS, 1000).

-type lane() :: permits | notify | guardian.
-type sample() :: #{permits := boolean(), notify := boolean(), guardian := boolean()}.
-type delta() :: #{any_ms := non_neg_integer(), permits_ms := non_neg_integer(),
                   notify_ms := non_neg_integer(), guardian_ms := non_neg_integer()}.
-opaque acc() :: #{last_ms := integer(), last := sample(), buckets := #{integer() => non_neg_integer()}}.

-record(st, {
    acc     :: acc(),
    pending :: delta(),
    emitted :: integer()
}).

%%%===================================================================
%%% The definition, as pure functions
%%%===================================================================

-spec sample_ms() -> pos_integer().
sample_ms() -> ?SAMPLE_MS.

-spec window_s() -> pos_integer().
window_s() -> ?WINDOW_S.

-spec slow_threshold() -> float().
slow_threshold() -> ?SLOW_THRESHOLD.

-spec lanes() -> [lane(), ...].
lanes() -> [permits, notify, guardian].

%% @doc Which lanes a snapshot of yuzu_gw_upstream:lane_snapshot/0 has saturated.
%% `undefined' (the process is not running) saturates nothing: there is no
%% server path to be backed up, and the breaker, not this, reports an outage.
-spec saturated(undefined | map()) -> sample().
saturated(undefined) ->
    idle();
saturated(#{permit_waiting := Waiting,
            notify_inflight := N, notify_limit := NLimit,
            guardian_inflight := G, guardian_limit := GLimit}) ->
    #{permits  => Waiting > 0,
      notify   => N >= NLimit,
      guardian => G >= GLimit}.

idle() -> #{permits => false, notify => false, guardian => false}.

%% @doc A fresh accumulator whose first sample is taken to be at `NowMs'
%% (monotonic milliseconds). Nothing is credited before the first step.
-spec new(integer()) -> acc().
new(NowMs) ->
    #{last_ms => NowMs, last => idle(), buckets => #{}}.

%% @doc Take a sample at `NowMs'. The time since the previous sample is credited
%% to the lanes that sample found saturated (each held until the next), and to
%% `any' if at least one was. Returns the new accumulator and what was credited.
-spec observe(acc(), integer(), sample()) -> {acc(), delta()}.
observe(#{last_ms := LastMs, last := Last, buckets := Buckets} = Acc, NowMs, Sample) ->
    Step = min(max(NowMs - LastMs, 0), ?MAX_STEP_MS),
    Lane = fun(L) -> case maps:get(L, Last) of true -> Step; false -> 0 end end,
    Delta = #{any_ms      => case lists:any(fun(L) -> maps:get(L, Last) end, lanes()) of
                                 true -> Step;
                                 false -> 0
                             end,
              permits_ms   => Lane(permits),
              notify_ms   => Lane(notify),
              guardian_ms => Lane(guardian)},
    Second = NowMs div 1000,
    Credited = min(?BUCKET_MS, maps:get(Second, Buckets, 0) + maps:get(any_ms, Delta)),
    Kept = maps:filter(fun(S, _) -> S > Second - ?WINDOW_S end, Buckets),
    {Acc#{last_ms := max(NowMs, LastMs), last := Sample, buckets := Kept#{Second => Credited}},
     Delta}.

%% @doc The share of the trailing window with backpressure present, 0.0 to 1.0.
%% Buckets older than the window are not counted whether or not they have been
%% pruned yet.
-spec duty_cycle(acc(), integer()) -> float().
duty_cycle(#{buckets := Buckets}, NowMs) ->
    Second = NowMs div 1000,
    Total = maps:fold(fun(S, Ms, Sum) when S > Second - ?WINDOW_S, S =< Second -> Sum + Ms;
                         (_, _, Sum) -> Sum
                      end, 0, Buckets),
    min(1.0, Total / (?WINDOW_S * ?BUCKET_MS)).

%% @doc Whether a duty cycle is a slow server.
-spec slow(float()) -> boolean().
slow(DutyCycle) -> DutyCycle >= ?SLOW_THRESHOLD.

%%%===================================================================
%%% The sampling process
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
    Now = now_ms(),
    erlang:send_after(?SAMPLE_MS, self(), sample),
    {ok, #st{acc = new(Now), pending = zero(), emitted = Now}}.

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(sample, #st{acc = Acc, pending = Pending, emitted = Emitted} = State) ->
    Now = now_ms(),
    {Acc1, Delta} = observe(Acc, Now, saturated(yuzu_gw_upstream:lane_snapshot())),
    Pending1 = add(Pending, Delta),
    State1 =
        case Now - Emitted >= ?EMIT_MS of
            true ->
                emit(Pending1, Acc1, Now),
                State#st{acc = Acc1, pending = zero(), emitted = Now};
            false ->
                State#st{acc = Acc1, pending = Pending1}
        end,
    erlang:send_after(?SAMPLE_MS, self(), sample),
    {noreply, State1};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

now_ms() -> erlang:monotonic_time(millisecond).

zero() -> #{any_ms => 0, permits_ms => 0, notify_ms => 0, guardian_ms => 0}.

add(A, B) -> maps:map(fun(K, V) -> V + maps:get(K, B) end, A).

emit(Delta, Acc, Now) ->
    telemetry:execute([yuzu, gw, upstream, backpressure], Delta, #{}),
    DutyCycle = duty_cycle(Acc, Now),
    telemetry:execute([yuzu, gw, upstream, backpressure_state],
                      #{duty_cycle => DutyCycle,
                        slow => case slow(DutyCycle) of true -> 1; false -> 0 end},
                      #{}).
