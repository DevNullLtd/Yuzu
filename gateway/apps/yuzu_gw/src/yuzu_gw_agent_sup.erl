%%%-------------------------------------------------------------------
%%% @doc simple_one_for_one supervisor for yuzu_gw_agent processes (the
%%% per-agent "owners").
%%%
%%% Each connected agent gets one owner process, started dynamically when the
%%% agent's Subscribe bidi stream arrives.
%%%
%%% == An owner that dies abnormally is restarted (OWNER-RESTART, #5695) ==
%%%
%%% Children are `transient': an owner that ends `normal' or `shutdown' (the
%%% agent disconnected, a refused registration, a planned stop) is not
%%% restarted; one that dies any other way (an exception, a kill) is. The
%%% restarted owner sends the DISCONNECTED notice for the session its
%%% predecessor held and then tries to recover the agent: it re-attaches to the
%%% agent's Subscribe stream if that is still open and re-establishes the
%%% session, so commands flow again without the agent reconnecting. See
%%% yuzu_gw_agent's `recovering' state.
%%%
%%% What survives the crash is the owner's row in the owner table
%%% (yuzu_gw_owner_sessions, see below), which start_agent/1 writes before the
%%% child is started. The child's start argument is only the row's key (and the
%%% caller's alias), so the supervisor, which keeps the start argument of a
%%% transient child for its restarts, holds no RegisterRequest and prints none
%%% in a report.
%%%
%%% Restart intensity (agent_restart_intensity, default 2000, within
%%% agent_restart_period_s, default 10). Intensity is shared by all children of
%%% a simple_one_for_one supervisor, so it is a fleet-wide number, sized so
%%% that isolated crashes never reach it and a crash of most of the fleet's
%%% owners does:
%%%   - each owner has its own budget too (yuzu_gw_agent: at most 3 restarts in
%%%     60 s, then it gives up after sending its DISCONNECTED and ends
%%%     `normal', which costs the supervisor nothing), so one agent in a crash
%%%     loop costs at most 3 restarts a minute;
%%%   - a loss of 10% of a 5,000-agent gateway's owners at once (500) restarts
%%%     without escalation;
%%%   - a fault that crashes more than 2000 owners within 10 s is a fault of
%%%     the gateway, not of an agent, and escalates: this supervisor exits, the
%%%     gateway supervisor (yuzu_gw_sup, one_for_one, 10 restarts in 60 s)
%%%     starts a fresh one. On the way down every owner still running ends
%%%     with `shutdown' and sends its own DISCONNECTED (owners trap exits for
%%%     this) and its stream closes, so those agents reconnect by their own
%%%     retry. The fresh supervisor starts a restarted owner for every row an
%%%     owner left behind without a successor (resume_orphans/1), which sends
%%%     that session's DISCONNECTED and recovers it if its stream is still
%%%     open. If the fault persists, yuzu_gw_sup's own intensity stops the
%%%     application, and the node's supervisor (container, systemd) restarts
%%%     the gateway: the OTP escalation, each step a larger restart.
%%% Raise agent_restart_intensity for a gateway that holds far more than
%%% 5,000 agents (about 40% of the agents per gateway keeps the same margins).
%%%
%%% The child's start function (yuzu_gw_agent:start_link_async/1) returns as
%%% soon as the process exists; the agent registers as its first event. So
%%% start_child never waits for the registry, and one slow registration does
%%% not hold every other Subscribe (and this supervisor's handling of child
%%% exits) behind it. start_agent/1 waits for the outcome in the caller. The
%%% start function never fails for a restart (yuzu_gw_agent:init/1 only reads
%%% the row), so a restart never counts twice against the intensity.
%%%
%%% == The owner table ==
%%%
%%% A named public ETS set, one row per owner instance:
%%%   {Key, Args, StreamHomeId, Announced, Restarts, OwnerPid, ConnectedAt}
%%% Args is the start map of the owner (the session, its stream, the
%%% RegisterRequest; the agent info only when it differs from the request's
%%% own), StreamHomeId the id the first owner minted, Announced the last
%%% stream-status notice sent for the session (none | connected | disconnected
%%% | ending), Restarts the restart times inside the budget window. The row is
%%% written by start_agent/1 and by the owner, and deleted by the owner when it
%%% ends for good. Beside each row, {{session, SessionId}, Key} finds it by
%%% session (held_session/1).
%%%
%%% Heartbeats while an owner is restarted. The registry drops a dead owner's
%%% session index row at once, and the restarted owner indexes the session again
%%% only once its predecessor's DISCONNECTED has settled upstream; under a mass
%%% crash that waits behind the other owners' notices (hundreds of ms at 500
%%% at once). A heartbeat refused in that gap is NOT_FOUND, and the agent drops
%%% the very stream the owner is recovering and registers a new session (2 of
%%% 500 killed owners at 5,000 agents on a 16-core host). So heartbeat
%%% admission falls back to this table: a session whose row names a dead owner,
%%% or says a successor is recovering it, is still held by this gateway, on
%%% the connection the row names (held_session/1). A live owner that holds its
%%% session but is missing from the registry (the registry restarted) is not:
%%% those heartbeats fail closed, as before.
%%%
%%% The table is owned by yuzu_gw_sup (created in its init/1), so it outlives a
%%% restart of this supervisor; a supervisor started without yuzu_gw_sup
%%% (tests) creates and owns it itself.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_sup).
-behaviour(supervisor).

-export([start_link/0, start_agent/1, count/0]).
-export([init/1]).
%% The owner table (yuzu_gw_agent, yuzu_gw_sup).
-export([ensure_owner_table/0, owner_row/1, owner_set/2, owner_delete/1]).
%% Heartbeat admission while an owner is being restarted (yuzu_gw_heartbeat_admission).
-export([held_session/1]).

-define(SERVER, ?MODULE).
-define(OWNERS, yuzu_gw_owner_sessions).
-define(DEFAULT_INTENSITY, 2000).
-define(DEFAULT_PERIOD_S, 10).

-type owner_row() :: #{args := map(), home := binary() | undefined,
                       announced := none | connected | disconnected | ending,
                       restarts := [integer()], pid := pid() | undefined,
                       connected_at := integer() | undefined}.
-export_type([owner_row/0]).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

%% @doc Start the supervisor, then a restarted owner for every row a previous
%% instance's owners left behind (see the module doc).
start_link() ->
    case supervisor:start_link({local, ?SERVER}, ?MODULE, []) of
        {ok, Pid} ->
            resume_orphans(Pid),
            {ok, Pid};
        Other ->
            Other
    end.

%% @doc Start a new agent process for an incoming Subscribe stream and
%% return once its registration is decided: `{ok, Pid}' with the agent in the
%% routing table, `{error, session_limit | registry_unavailable}' when it was
%% refused (the process is then gone). The supervisor is free as soon as the
%% process exists; the wait is in the caller (yuzu_gw_agent:await_registration/2).
%%
%% Args holds the RegisterRequest (enrollment_token, machine_certificate,
%% csr_pem). It goes into the owner table, not into the child's start argument.
%% A start_child that exits (this supervisor is not running) exits the CALLER,
%% a gRPC handler process, with a reason that embeds the call; it is turned
%% into the fixed {error, agent_sup_unavailable}, and the reason is not logged
%% (see yuzu_gw_safe_call).
-spec start_agent(map()) -> {ok, pid()} | {error, term()}.
start_agent(Args) ->
    Key = make_ref(),
    %% No table means no supervisor (it creates the table if yuzu_gw_sup did
    %% not): the start_child below then fails as for any absent supervisor.
    _ = owner_insert(Key, maps:remove(registered_ack, Args)),
    _ = index_session(maps:get(session_id, Args, undefined), Key),
    Alias = alias([reply]),
    case yuzu_gw_safe_call:guard(?SERVER,
                                 fun() ->
                                     supervisor:start_child(
                                       ?SERVER, [#{owner_key => Key, registered_ack => Alias}])
                                 end,
                                 agent_sup_unavailable) of
        {ok, Pid} when is_pid(Pid) ->
            yuzu_gw_agent:await_registration(Pid, Alias);
        Other ->
            unalias(Alias),
            owner_delete(Key),
            Other
    end.

%% @doc Return the number of active agent processes.
-spec count() -> non_neg_integer().
count() ->
    proplists:get_value(active, supervisor:count_children(?SERVER), 0).

%% @doc Create the owner table if it does not exist; the caller owns it then.
-spec ensure_owner_table() -> ok.
ensure_owner_table() ->
    case ets:whereis(?OWNERS) of
        undefined ->
            ?OWNERS = ets:new(?OWNERS, [named_table, public, set, {read_concurrency, true},
                                        {write_concurrency, true}]),
            ok;
        _ ->
            ok
    end.

%% @doc The owner row under Key, or `none' (no row, or no table).
-spec owner_row(reference()) -> {ok, owner_row()} | none.
owner_row(Key) ->
    try ets:lookup(?OWNERS, Key) of
        [{Key, Args, Home, Announced, Restarts, Pid, ConnectedAt}] ->
            {ok, #{args => restore_args(Args), home => Home, announced => Announced,
                   restarts => Restarts, pid => Pid, connected_at => ConnectedAt}};
        [] ->
            none
    catch
        error:badarg -> none
    end.

%% @doc Update fields of the row under Key (a missing row or table is ignored).
-spec owner_set(reference() | undefined, [{home | announced | restarts | pid | connected_at,
                                          term()}]) -> ok.
owner_set(undefined, _Fields) ->
    ok;
owner_set(Key, Fields) ->
    Pos = [{position(F), V} || {F, V} <- Fields],
    try ets:update_element(?OWNERS, Key, Pos) of
        _ -> ok
    catch
        error:badarg -> ok
    end.

%% @doc Delete the row under Key, and its session entry.
-spec owner_delete(reference() | undefined) -> ok.
owner_delete(undefined) ->
    ok;
owner_delete(Key) ->
    try ets:lookup(?OWNERS, Key) of
        [{Key, Args, _, _, _, _, _}] ->
            _ = ets:delete_object(?OWNERS, {{session, session_of(Args)}, Key}),
            true = ets:delete(?OWNERS, Key),
            ok;
        [] ->
            ok
    catch
        error:badarg -> ok
    end.

%% @doc The connection key of SessionId while its owner is being restarted:
%% the row names an owner that is dead (killed, its successor not yet running)
%% or says `disconnected' (a successor sent the DISCONNECTED and is recovering
%% the session), and the registry does not route the agent to a live process
%% under another session. Else `error': no row or table, never announced, being
%% ended on purpose (`ending'), superseded by a newer registration of the agent,
%% or a live owner that holds the session as `connected' but is missing from the
%% registry (the registry restarted and lost its rows: those heartbeats still
%% fail closed, so the agent registers again). A few ETS lookups; called only
%% when the registry's session index misses.
-spec held_session(term()) -> {ok, yuzu_gw_conn:key()} | error.
held_session(SessionId) when is_binary(SessionId), SessionId =/= <<>> ->
    try ets:lookup(?OWNERS, {session, SessionId}) of
        [{_, Key}] ->
            case owner_row(Key) of
                {ok, #{announced := A, pid := Owner, args := #{agent_id := AgentId} = Args}}
                  when A =:= disconnected; A =:= connected ->
                    Restarting = A =:= disconnected orelse not owner_alive(Owner),
                    case {Restarting, yuzu_gw_registry:lookup_local_session(AgentId)} of
                        {false, _}                                     -> error;
                        {true, {ok, {_Pid, Other}}} when Other =/= SessionId -> error;
                        {true, _} -> {ok, maps:get(conn_key, Args, undefined)}
                    end;
                _ ->
                    error
            end;
        [] ->
            error
    catch
        error:badarg -> error
    end;
held_session(_SessionId) ->
    error.

%%--------------------------------------------------------------------
%% supervisor callback
%%--------------------------------------------------------------------

init([]) ->
    ok = ensure_owner_table(),
    SupFlags = #{
        strategy  => simple_one_for_one,
        intensity => yuzu_gw_env:env_int(agent_restart_intensity, ?DEFAULT_INTENSITY,
                                         1, 1000000),
        period    => yuzu_gw_env:env_int(agent_restart_period_s, ?DEFAULT_PERIOD_S, 1, 3600)
    },

    ChildSpec = #{
        id       => agent,
        start    => {yuzu_gw_agent, start_link_async, []},
        restart  => transient,
        shutdown => 5000,
        type     => worker
    },

    {ok, {SupFlags, [ChildSpec]}}.

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

owner_insert(Key, Args) ->
    try ets:insert_new(?OWNERS, {Key, slim_args(Args), undefined, none, [], undefined,
                                 undefined}) of
        true -> ok
    catch
        error:badarg -> {error, agent_sup_unavailable}
    end.

owner_alive(Pid) when is_pid(Pid) -> is_process_alive(Pid);
owner_alive(_NoPid)                -> false.

index_session(SessionId, Key) when is_binary(SessionId), SessionId =/= <<>> ->
    try ets:insert(?OWNERS, {{session, SessionId}, Key})
    catch error:badarg -> false
    end;
index_session(_SessionId, _Key) ->
    false.

session_of(Args) ->
    maps:get(session_id, Args, undefined).

position(home)         -> 3;
position(announced)    -> 4;
position(restarts)     -> 5;
position(pid)          -> 6;
position(connected_at) -> 7.

%% The agent info is the RegisterRequest's own `info' for every agent the
%% Subscribe handler starts: kept once, not twice.
slim_args(#{agent_info := Info, register_req := #{info := Info}} = Args) ->
    (maps:remove(agent_info, Args))#{agent_info_from_req => true};
slim_args(Args) ->
    Args.

restore_args(#{agent_info_from_req := true, register_req := #{info := Info}} = Args) ->
    (maps:remove(agent_info_from_req, Args))#{agent_info => Info};
restore_args(Args) ->
    Args.

%% A row with a stream home belongs to an owner that ran; at this point none of
%% them runs (a supervisor ends all its children before it exits), so each gets
%% a restarted owner. A row without one was written by a start_agent/1 whose
%% child never started; that caller removes it.
resume_orphans(Sup) ->
    Orphans = try ets:select(?OWNERS, [{{'$1', '_', '$2', '_', '_', '_', '_'},
                                        [{'=/=', '$2', undefined}], ['$1']}])
              catch error:badarg -> []
              end,
    case Orphans of
        [] ->
            ok;
        _ ->
            logger:warning("Agent supervisor started with ~b owner(s) left by its predecessor; "
                           "restarting them to end or recover their sessions",
                           [length(Orphans)]),
            [supervisor:start_child(Sup, [#{owner_key => Key}]) || Key <- Orphans],
            ok
    end.
