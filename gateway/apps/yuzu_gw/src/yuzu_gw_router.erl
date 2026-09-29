%%%-------------------------------------------------------------------
%%% @doc Command fanout coordinator.
%%%
%%% Receives SendCommand requests from the management service,
%%% fans out to target agent processes via cast, and aggregates
%%% responses back to the operator's gRPC stream.
%%%
%%% Each fanout gets a unique ref. The router tracks outstanding
%%% fanouts and streams responses back as they arrive (progressive
%%% results, not blocking for all).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_router).
-behaviour(gen_server).

%% API
-export([start_link/0, send_command/3]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(fanout, {
    from         :: pid(),              %% caller (mgmt service handler)
    stream_ref   :: reference(),        %% gRPC response stream ref
    targets      :: non_neg_integer(),  %% total agents targeted
    received     :: non_neg_integer(),  %% terminal responses received
    skipped      :: non_neg_integer(),  %% agents not found
    timeout_ref  :: reference(),        %% erlang:send_after ref
    started_at   :: integer()           %% monotonic time
}).

-record(state, {
    fanouts :: #{reference() => #fanout{}}
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Fan out a command to the specified agents (or all if AgentIds is []).
%% Returns a fanout reference. Responses are sent to the caller's mailbox as:
%%   {command_response, FanoutRef, AgentId, Response}
%%   {fanout_complete, FanoutRef, Summary}
%%
%% CommandReq is passed to yuzu_gw_agent:dispatch/3 as an opaque map — the
%% router never extracts or rebuilds individual fields, so `dispatch_tag`
%% (like `payload`) rides through untouched, the same as every other
%% CommandRequest field. See agent.proto CommandRequest.dispatch_tag.
-spec send_command([binary()], map(), map()) -> {ok, reference()} | {error, term()}.
send_command(AgentIds, CommandReq, Opts) ->
    gen_server:call(?SERVER, {send_command, AgentIds, CommandReq, Opts}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    {ok, #state{fanouts = #{}}}.

handle_call({send_command, AgentIds, CommandReq, Opts}, {CallerPid, _Tag}, State) ->
    TimeoutS = maps:get(timeout_seconds, Opts,
                        application:get_env(yuzu_gw, default_command_timeout_s, 300)),

    Targets = case AgentIds of
        []    -> yuzu_gw_registry:all_agents();
        List  -> List
    end,

    FanoutRef = make_ref(),
    StartedAt = erlang:monotonic_time(millisecond),

    %% Dispatch to each agent process. HA WS-4 4.3a: `yuzu_gw_registry:lookup/1`
    %% may now resolve to a pid on a DIFFERENT node (the `pg`-backed
    %% cross-node fallback — see that function's doc comment); `dispatch/3`
    %% is a `gen_statem:cast` and dist-transparent either way, so the
    %% dispatch call itself needs no branch. `RemoteDispatched` is counted
    %% separately (not folded into `Dispatched`) purely for observability —
    %% distinguishing "routed to a sibling node" from "resolved locally"
    %% makes cross-node routing visible instead of indistinguishable from
    %% the local case.
    Self = node(),
    {Dispatched, Skipped, RemoteDispatched} = lists:foldl(fun(AgentId, {D, S, R}) ->
        case yuzu_gw_registry:lookup(AgentId) of
            {ok, Pid} ->
                yuzu_gw_agent:dispatch(Pid, CommandReq, {CallerPid, FanoutRef}),
                case node(Pid) of
                    Self -> {D + 1, S, R};
                    _    -> {D + 1, S, R + 1}
                end;
            error ->
                %% Agent not connected — notify caller immediately.
                CallerPid ! {command_error, FanoutRef, AgentId, not_connected},
                {D, S + 1, R}
        end
    end, {0, 0, 0}, Targets),

    telemetry:execute([yuzu, gw, command, fanout],
                      #{target_count => length(Targets),
                        dispatched => Dispatched, skipped => Skipped,
                        remote_dispatched => RemoteDispatched},
                      #{command_id => maps:get(command_id, CommandReq,
                                               maps:get(<<"command_id">>, CommandReq, undefined))}),

    case Dispatched of
        0 ->
            %% No agents to send to — complete immediately.
            CallerPid ! {fanout_complete, FanoutRef, #{targets => 0,
                                                        skipped => Skipped,
                                                        received => 0,
                                                        duration_ms => 0}},
            {reply, {ok, FanoutRef}, State};
        _ ->
            TRef = erlang:send_after(TimeoutS * 1000, self(), {fanout_timeout, FanoutRef}),
            Fanout = #fanout{
                from        = CallerPid,
                stream_ref  = FanoutRef,
                targets     = Dispatched,
                received    = 0,
                skipped     = Skipped,
                timeout_ref = TRef,
                started_at  = StartedAt
            },
            {reply, {ok, FanoutRef}, State#state{
                fanouts = maps:put(FanoutRef, Fanout, State#state.fanouts)
            }}
    end;

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({fanout_timeout, FanoutRef}, #state{fanouts = Fanouts} = State) ->
    case maps:find(FanoutRef, Fanouts) of
        {ok, #fanout{from = Caller, targets = T, received = R,
                     skipped = S, started_at = Started}} ->
            Duration = erlang:monotonic_time(millisecond) - Started,
            TimedOut = T - R,

            telemetry:execute([yuzu, gw, command, timeout],
                              #{count => TimedOut},
                              #{fanout_ref => FanoutRef}),

            Caller ! {fanout_complete, FanoutRef, #{targets => T,
                                                     received => R,
                                                     skipped => S,
                                                     timed_out => TimedOut,
                                                     duration_ms => Duration}},
            {noreply, State#state{fanouts = maps:remove(FanoutRef, Fanouts)}};
        error ->
            {noreply, State}
    end;

%% Agent processes send terminal response notifications to the router
%% so we can track fanout completion.
handle_info({fanout_terminal, FanoutRef, _AgentId}, #state{fanouts = Fanouts} = State) ->
    case maps:find(FanoutRef, Fanouts) of
        {ok, #fanout{received = R, targets = T} = F} ->
            R2 = R + 1,
            case R2 >= T of
                true ->
                    %% All responses received — complete the fanout.
                    erlang:cancel_timer(F#fanout.timeout_ref),
                    Duration = erlang:monotonic_time(millisecond) - F#fanout.started_at,
                    F#fanout.from ! {fanout_complete, FanoutRef,
                                    #{targets => T,
                                      received => R2,
                                      skipped => F#fanout.skipped,
                                      timed_out => 0,
                                      duration_ms => Duration}},
                    {noreply, State#state{
                        fanouts = maps:remove(FanoutRef, Fanouts)
                    }};
                false ->
                    {noreply, State#state{
                        fanouts = maps:put(FanoutRef, F#fanout{received = R2}, Fanouts)
                    }}
            end;
        error ->
            %% Already completed or timed out.
            {noreply, State}
    end;

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
