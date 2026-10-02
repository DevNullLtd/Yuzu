%%%-------------------------------------------------------------------
%%% @doc Agent routing registry — ETS + pg.
%%%
%%% ETS (`yuzu_gw_agents`): fast O(1) lookup by agent_id. Each row also
%%%   carries the verbatim `RegisterRequest` the agent first sent, so
%%%   `yuzu_gw_upstream` can re-proxy it byte-for-byte when the upstream
%%%   connection re-establishes (the server comes back with an empty
%%%   registry and must relearn every agent the gateway already holds).
%%% ETS (`yuzu_gw_pending`): pending Register→Subscribe state with TTL.
%%% ETS (`yuzu_gw_sessions`): session index `{SessionId, AgentId, Pid, ConnKey}`
%%%   for heartbeat admission. ConnKey is the connection key (see
%%%   `yuzu_gw_conn') of the Subscribe stream that created the session, or
%%%   `undefined' for a registration made without one (such a session is held
%%%   but admits no heartbeat). The index is node-local by construction (it
%%%   never consults `pg'); a row is removed with the agent process that owns
%%%   it, and only ever by that process's own session id.
%%% pg (`yuzu_gw` scope):   cluster-aware process groups for broadcast
%%%   and plugin-targeted fanout.
%%%
%%% This gen_server owns the ETS tables and coordinates pg group
%%% membership on behalf of agent processes.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_registry).
-behaviour(gen_server).

%% API
-export([start_link/0,
         register_agent/5,
         register_agent/6,
         register_agent/7,
         deregister_agent/1,
         deregister_agent/3,
         lookup/1,
         lookup_local_session/1,
         lookup_session/1,
         lookup_pending_session/1,
         all_agents/0,
         all_agent_pids/0,
         all_register_reqs/0,
         agents_for_plugin/1,
         agent_count/0,
         list_agents/2,
         store_pending/2,
         take_pending/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(TABLE,  yuzu_gw_agents).
-define(PENDING_TABLE, yuzu_gw_pending).
-define(SESSIONS_TABLE, yuzu_gw_sessions).
-define(PG_SCOPE, yuzu_gw).
-define(PENDING_TTL_MS, 120000).     %% 2 minutes
-define(PENDING_SWEEP_MS, 60000).    %% 1 minute

-record(state, {
    monitor_refs :: #{reference() => binary()},
    sweep_timer  :: reference()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Register an agent with no stashed RegisterRequest.
%%
%% Back-compat entry point: production registration goes through
%% register_agent/6 (yuzu_gw_agent:init/1 always has the verbatim
%% request). This /5 form is for callers — chiefly routing-focused
%% tests — that do not exercise the upstream-reconnect replay path; it
%% records an empty request, so such an agent is simply skipped by the
%% replay drip.
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary()) -> ok.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname) ->
    register_agent(AgentId, Pid, SessionId, Plugins, Hostname, #{}).

%% @doc Register an agent process in the routing table.
%% Called by yuzu_gw_agent:init/1 from the agent process itself.
%%
%% RegisterReq is the verbatim `yuzu.agent.v1.RegisterRequest' map the
%% agent originally sent; it is stashed so the upstream client can
%% re-proxy it on reconnect (see all_register_reqs/0).
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary(), map()) -> ok.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq) ->
    register_agent(AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq, undefined).

%% @doc Register an agent process and bind its session to ConnKey.
%%
%% ConnKey is the connection key of the Subscribe stream that created the
%% session (`yuzu_gw_conn:key_from_stream/1'); heartbeat admission admits a
%% heartbeat for SessionId only on that connection. The /5 and /6 forms
%% register with `undefined', which admits nothing. A session id of
%% `undefined' is not indexed at all.
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary(), map(), yuzu_gw_conn:key()) -> ok.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq, ConnKey) ->
    gen_server:call(?SERVER,
                    {register, AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq,
                     ConnKey},
                    30000).

%% @doc Remove an agent from the routing table.
%%
%% Unfenced: deletes whatever process currently holds AgentId, together with
%% that row's session index entry. Production cleanup uses deregister_agent/3.
-spec deregister_agent(binary()) -> ok.
deregister_agent(AgentId) ->
    gen_server:cast(?SERVER, {deregister, AgentId}).

%% @doc Remove the agent process Pid, and its session SessionId, if it is
%% still the registered owner.
%%
%% Fenced: called by an agent process from its own cleanup. A process that
%% has been superseded by a newer registration of the same agent id (the
%% agent reconnected under a new session before the old stream was torn
%% down) removes only its own session index entry and leaves the newer
%% registration, in both tables, untouched.
-spec deregister_agent(binary(), pid(), binary() | undefined) -> ok.
deregister_agent(AgentId, Pid, SessionId) ->
    gen_server:cast(?SERVER, {deregister, AgentId, Pid, SessionId}).

%% @doc Lookup an agent by ID. Returns {ok, Pid} or error.
%%
%% HA WS-4 4.3a (intra-cluster routing, ADR-2002 §7): node-local ETS is tried
%% first (the common case — same node, zero cross-node cost) and remains the
%% AUTHORITATIVE source for a pid on THIS node. On a local miss, falls back
%% to the per-agent `pg' group (`{agent, AgentId}', joined/left alongside the
%% existing `all_agents'/`{plugin, X}' groups below) — `pg' replicates group
%% membership across every CONNECTED distributed-Erlang node in this
%% cluster, giving cross-node location transparency `pg' broadcast groups
%% alone do not provide (see ADR-2002 §7's "per-agent `pg' group, a global
%% registry, or fan-and-filter" mechanism list — this is the first of the
%% three). Deliberately NOT a consistent hash ring: `hash_ring_vnodes'
%% (`gateway/config/sys.config') is for DNS-based connection placement and
%% rebalancing only (`docs/erlang-gateway-blueprint.md`), explicitly NOT
%% command routing — see #4556.
%%
%% SINGLE-MEMBER DISPATCH RULE (load-bearing): `pg' membership is eventually
%% consistent, so during a re-home the OLD node's pid and the NEW node's pid
%% can both be members of `{agent, AgentId}' until the old stream process
%% actually exits. Dispatching to EVERY member would let one command yield
%% TWO responses (a real one plus an `agent_disconnected' from the dead
%% pid) for a single fanout target. Never happens today (agent reconnect is
%% the only re-home path, ADR-2002 §7 — a physical stream move is always
%% agent-reconnect-shaped, so at most one live member should exist at
%% steady state), but the rule holds regardless: pick exactly ONE —
%% preferring a LOCAL member if any (so `is_process_alive/1`'s liveness
%% check still applies) — never dispatch to more than one.
-spec lookup(binary()) -> {ok, pid()} | error.
lookup(AgentId) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, _, _, _, _}] ->
            case is_process_alive(Pid) of
                true  -> {ok, Pid};
                false -> lookup_remote(AgentId)
            end;
        [] ->
            lookup_remote(AgentId)
    end.

%% @doc Cross-node fallback for lookup/1 — see that function's doc comment
%% for the group-membership and single-member-dispatch rationale.
%%
%% `pg' membership removal on a monitored process's death is ASYNCHRONOUS
%% relative to any other observer's own death detection (confirmed
%% empirically: `yuzu_gw_registry_tests:lookup_dead_process/0' — which
%% waits on its OWN separate monitor's DOWN before asserting — intermittently
%% still found the dead pid as a live `{agent, AgentId}' pg member here,
%% because `pg''s internal cleanup hadn't run yet). A LOCAL member is one
%% this node CAN verify with `is_process_alive/1', so it must be — a dead
%% local member is filtered out rather than returned. A REMOTE member's
%% liveness is NOT locally verifiable; it is trusted to `pg''s own
%% monitoring on ITS node (the same trust boundary the rest of this
%% fallback already rests on).
-spec lookup_remote(binary()) -> {ok, pid()} | error.
lookup_remote(AgentId) ->
    case pg:get_members(?PG_SCOPE, {agent, AgentId}) of
        [] ->
            error;
        Members ->
            Self = node(),
            Live = lists:filter(fun(P) ->
                node(P) =/= Self orelse is_process_alive(P)
            end, Members),
            case lists:filter(fun(P) -> node(P) =:= Self end, Live) of
                [Local | _] ->
                    {ok, Local};
                [] ->
                    case Live of
                        [Remote | _] -> {ok, Remote};
                        []           -> error
                    end
            end
    end.

%% @doc HA WS-4 4.4 (`#4246` #6): the LOCAL live pid and CURRENT session id
%% for `AgentId`, straight from ETS — never the `pg` cross-node fallback
%% `lookup/1` uses. Used ONLY by `yuzu_gw_upstream`'s registration-replay
%% drip to re-check liveness right before replaying a queued
%% `{AgentId, SessionId, RegisterReq}` snapshot: the drip is self-paced
%% (one agent per scheduled message, `replay_spacing_ms` apart), so by the
%% time an entry's turn comes up the agent may have disconnected, or
%% reconnected under a BRAND-NEW session (register_agent/6 overwrites the
%% ETS row wholesale) — replaying the STALE snapshot's session in either
%% case would present an orphaned session the server can no longer (or
%% should no longer) adopt. `error` covers both "no longer registered" and
%% "the live pid, if any, is not actually alive" (mirrors `lookup/1`'s own
%% local liveness check, without its remote `pg` fallback — a replay is
%% only ever meaningful against a LOCAL process).
-spec lookup_local_session(binary()) -> {ok, {pid(), binary() | undefined}} | error.
lookup_local_session(AgentId) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, SessionId, _, _, _, _}] ->
            case is_process_alive(Pid) of
                true  -> {ok, {Pid, SessionId}};
                false -> error
            end;
        [] ->
            error
    end.

%% @doc The session this node holds under SessionId, for heartbeat admission.
%%
%% Reads the node-local session index only (never `pg'): a session held by
%% another node is not found here. `error' also covers a row whose process is
%% no longer alive. `{error, unavailable}' means the index does not exist
%% (the registry is not running or is restarting); callers must treat that
%% as "not admitted", never as "no filter".
-spec lookup_session(term()) ->
    {ok, #{agent_id := binary(), pid := pid(), conn_key := yuzu_gw_conn:key()}}
    | error
    | {error, unavailable}.
lookup_session(SessionId) ->
    try ets:lookup(?SESSIONS_TABLE, SessionId) of
        [{_, AgentId, Pid, ConnKey}] ->
            case is_local_alive(Pid) of
                true  -> {ok, #{agent_id => AgentId, pid => Pid, conn_key => ConnKey}};
                false -> error
            end;
        [] ->
            error
    catch
        error:badarg -> {error, unavailable}
    end.

%% @doc The connection key recorded by Register for a session that is still
%% pending (Register done, Subscribe not yet admitted). Does not consume the
%% row. A row past its TTL is reported as absent even if the periodic sweep
%% has not removed it yet. `{ok, undefined}' means the row carries no key.
-spec lookup_pending_session(term()) ->
    {ok, yuzu_gw_conn:key()} | error | {error, unavailable}.
lookup_pending_session(SessionId) ->
    try ets:lookup(?PENDING_TABLE, SessionId) of
        [{_, Info, StoredAt}] ->
            case erlang:system_time(millisecond) - StoredAt > ?PENDING_TTL_MS of
                true  -> error;
                false -> {ok, maps:get(conn_key, Info, undefined)}
            end;
        [] ->
            error
    catch
        error:badarg -> {error, unavailable}
    end.

is_local_alive(Pid) ->
    node(Pid) =:= node() andalso is_process_alive(Pid).

%% @doc Return all agent IDs.
-spec all_agents() -> [binary()].
all_agents() ->
    [AgentId || {AgentId, _, _, _, _, _, _, _} <- ets:tab2list(?TABLE)].

%% @doc Return all agent pids (for broadcast via pg fallback).
-spec all_agent_pids() -> [pid()].
all_agent_pids() ->
    pg:get_members(?PG_SCOPE, all_agents).

%% @doc Return {AgentId, SessionId, RegisterRequest} for every
%% currently-registered agent. Used by yuzu_gw_upstream to re-proxy
%% registrations when the upstream connection re-establishes. Because
%% this reads straight from ETS at call time, an agent that
%% deregistered during the outage is already absent — it will not be
%% replayed.
%%
%% SessionId (HA WS-4 4.1) is the session the agent originally
%% registered with; the replay carries it as `x-yuzu-session-id`
%% metadata on the re-proxied ProxyRegister so the server can treat the
%% replay as a re-announce of an existing session rather than minting a
%% new one. `undefined` for an agent registered without a session (the
%% register_agent/5 back-compat path, e.g. routing-focused tests).
%%
%% Returns [] if the table does not exist (registry not started, or
%% torn down) — same defensive contract as agent_count/0, so a caller
%% on the reconnect path never crashes just because the registry is
%% momentarily absent.
-spec all_register_reqs() -> [{binary(), binary() | undefined, map()}].
all_register_reqs() ->
    case ets:info(?TABLE, size) of
        undefined ->
            [];
        _ ->
            [{AgentId, SessionId, RegisterReq}
             || {AgentId, _, _, SessionId, _, _, _, RegisterReq} <- ets:tab2list(?TABLE)]
    end.

%% @doc Return pids of agents that have a specific plugin loaded.
-spec agents_for_plugin(binary()) -> [pid()].
agents_for_plugin(PluginName) ->
    pg:get_members(?PG_SCOPE, {plugin, PluginName}).

%% @doc Total number of connected agents on this node.
-spec agent_count() -> non_neg_integer().
agent_count() ->
    case ets:info(?TABLE, size) of
        undefined -> 0;
        N -> N
    end.

%% @doc Paginated agent listing for dashboard queries.
%% Returns {Agents, NextCursor} where Agents is a list of maps.
%%
%% Uses ets:select/2 with a match spec for cursor-based pagination.
%% This is O(k) where k = page size, instead of O(n log n) from the
%% previous tab2list + sort approach.
-spec list_agents(non_neg_integer(), binary() | undefined) ->
    {[map()], binary() | undefined}.
list_agents(Limit, Cursor) ->
    %% Build a match spec that selects rows where agent_id > Cursor.
    %% ETS ordered_set would give us ordered traversal natively, but
    %% the table is a `set` — so we use a guard condition on the key
    %% and fetch Limit+1 to detect whether more pages exist.
    %%
    %% '$8' (the verbatim RegisterRequest) is matched but deliberately
    %% not projected — it is an internal replay artifact, not dashboard
    %% data — so we select only the seven display fields explicitly.
    MatchHead = {'$1', '$2', '$3', '$4', '$5', '$6', '$7', '$8'},
    Guard = case Cursor of
        undefined -> [];
        <<>>      -> [];
        _         -> [{'>', '$1', {const, Cursor}}]
    end,
    Result = [{{'$1', '$2', '$3', '$4', '$5', '$6', '$7'}}],
    MatchSpec = [{MatchHead, Guard, Result}],

    %% Select all matching rows, then sort only this subset and take Limit+1.
    %% For small page sizes this is vastly cheaper than sorting the full table.
    Selected = ets:select(?TABLE, MatchSpec),
    Sorted = lists:sort(Selected),
    PagePlusOne = lists:sublist(Sorted, Limit + 1),

    {Page, HasMore} = case length(PagePlusOne) > Limit of
        true  -> {lists:sublist(PagePlusOne, Limit), true};
        false -> {PagePlusOne, false}
    end,

    Agents = [#{agent_id     => Id,
                pid          => Pid,
                node         => Node,
                session_id   => Sid,
                plugins      => Plugins,
                connected_at => T,
                hostname     => Hn}
              || {Id, Pid, Node, Sid, Plugins, T, Hn} <- Page],

    NextCursor = case HasMore andalso Page =/= [] of
        true  ->
            LastRow = lists:last(Page),
            element(1, LastRow);  %% agent_id is the first tuple element
        false ->
            undefined
    end,
    {Agents, NextCursor}.

%% @doc Store pending registration info for a session.
%% Called by agent_service on Register, consumed by Subscribe.
-spec store_pending(binary(), map()) -> ok.
store_pending(SessionId, Info) ->
    ets:insert(?PENDING_TABLE, {SessionId, Info, erlang:system_time(millisecond)}),
    ok.

%% @doc Atomically retrieve-and-delete pending registration info.
%% Returns the info map, or undefined if not found or already taken (by a
%% concurrent consumer). NOTE: TTL expiry is enforced by the periodic
%% `sweep_pending' handler, NOT here — this call does not inspect the stored
%% timestamp, so an entry within up to one sweep interval past its TTL may still
%% be returned. That admission leniency is deliberate and benign (the pending
%% row is session-id-bound; a late Register→Subscribe handshake simply completes).
%%
%% Uses `ets:take/2' — a SINGLE atomic retrieve-and-delete BIF — NOT a
%% lookup-then-delete pair. `?PENDING_TABLE' is `public', and this is called
%% directly from `yuzu_gw_agent_service:subscribe/2', which grpcbox runs as an
%% independent process per incoming stream, so two concurrent `Subscribe's
%% presenting the SAME session id race here with zero serialization. A
%% lookup-then-delete let BOTH win — each spawning an agent process and each
%% emitting its own `CONNECTED(S)', which is exactly the "more than one
%% CONNECTED(S) per session" producer that would break the HA WS-4 routing
%% directory's once-per-session invariant (see ADR-2002 §7 #4246 #4 / #4324).
%% `ets:take/2' guarantees exactly one concurrent caller receives the object
%% for a given key (all others get `[]'); the once-per-session property is
%% pinned by the concurrent-barrier test in yuzu_gw_registry_tests.erl.
-spec take_pending(binary()) -> map() | undefined.
take_pending(SessionId) ->
    case ets:take(?PENDING_TABLE, SessionId) of
        [{_, Info, _}] ->
            Info;
        [] ->
            undefined
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?TABLE, [named_table, set, public, {read_concurrency, true}]),
    ets:new(?PENDING_TABLE, [named_table, set, public]),
    ets:new(?SESSIONS_TABLE, [named_table, set, public, {read_concurrency, true}]),
    TRef = erlang:send_after(?PENDING_SWEEP_MS, self(), sweep_pending),
    {ok, #state{monitor_refs = #{}, sweep_timer = TRef}}.

handle_call({register, AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq, ConnKey},
            _From, #state{monitor_refs = Mons} = State) ->
    %% Remove any stale entry for this agent_id (returns cleaned Mons).
    Mons1 = maybe_cleanup(AgentId, Mons),

    %% Insert into ETS. The trailing field is the verbatim RegisterRequest,
    %% kept so yuzu_gw_upstream can re-proxy it on upstream reconnect.
    Now = erlang:system_time(millisecond),
    ets:insert(?TABLE, {AgentId, Pid, node(Pid), SessionId, Plugins, Now,
                        Hostname, RegisterReq}),

    %% Index the session for heartbeat admission. A session id of
    %% `undefined' (the routing-focused test path) is not indexed.
    index_session(SessionId, AgentId, Pid, ConnKey),

    %% Join pg groups. `{agent, AgentId}` (HA WS-4 4.3a) is the cross-node
    %% location-transparency group `lookup/1`'s fallback reads — see that
    %% function's doc comment.
    pg:join(?PG_SCOPE, all_agents, Pid),
    pg:join(?PG_SCOPE, {agent, AgentId}, Pid),
    lists:foreach(fun(Plugin) ->
        pg:join(?PG_SCOPE, {plugin, Plugin}, Pid)
    end, Plugins),

    %% Monitor the agent process for automatic cleanup.
    MonRef = monitor(process, Pid),
    Mons2 = Mons1#{MonRef => AgentId},

    {reply, ok, State#state{monitor_refs = Mons2}};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_call}, State}.

handle_cast({deregister, AgentId}, State) ->
    do_deregister(AgentId, State);

handle_cast({deregister, AgentId, Pid, SessionId}, State) ->
    do_deregister_fenced(AgentId, Pid, SessionId, State);

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({'DOWN', MonRef, process, Pid, _Reason},
            #state{monitor_refs = Mons} = State) ->
    case maps:find(MonRef, Mons) of
        {ok, AgentId} ->
            %% Drop this process's session index entry (read from its own
            %% routing row) before the row itself goes.
            case ets:lookup(?TABLE, AgentId) of
                [{_, Pid, _, SessionId, _, _, _, _}] -> unindex_session(SessionId, Pid);
                _                                    -> ok
            end,
            ets:delete(?TABLE, AgentId),
            %% pg auto-removes dead processes, but we clean ETS explicitly.
            {noreply, State#state{monitor_refs = maps:remove(MonRef, Mons)}};
        error ->
            {noreply, State}
    end;

handle_info(sweep_pending, State) ->
    %% PRE-EXISTING narrow race (NOT introduced by the take_pending atomicity
    %% fix; tracked as #4326): this collects expired keys then deletes each
    %% by key in a separate pass, without re-checking the timestamp at delete
    %% time. `store_pending/2' is a bare `ets:insert' from the (concurrent)
    %% stream process, so a re-store of the SAME session id landing between the
    %% foldl scan and the per-key delete would be swept. It is benign today —
    %% the stock agent never re-Registers the same session id (reconnect mints a
    %% fresh S', ADR-2002 §7), the window is the scan→delete gap, and the effect
    %% is one recoverable NOT_FOUND that triggers a re-Register. A tighter delete
    %% (ets:select_delete with a StoredAt guard) is the fix if a same-session
    %% re-Register path is ever added.
    Now = erlang:system_time(millisecond),
    Expired = ets:foldl(fun({SessionId, _, StoredAt}, Acc) ->
        case Now - StoredAt > ?PENDING_TTL_MS of
            true  -> [SessionId | Acc];
            false -> Acc
        end
    end, [], ?PENDING_TABLE),
    lists:foreach(fun(Id) -> ets:delete(?PENDING_TABLE, Id) end, Expired),
    case length(Expired) of
        0 -> ok;
        N -> logger:info("Swept ~b expired pending registrations", [N])
    end,
    TRef = erlang:send_after(?PENDING_SWEEP_MS, self(), sweep_pending),
    {noreply, State#state{sweep_timer = TRef}};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal
%%%===================================================================

do_deregister(AgentId, #state{monitor_refs = Mons} = State) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, SessionId, Plugins, _, _, _}] ->
            ets:delete(?TABLE, AgentId),
            unindex_session(SessionId, Pid),
            leave_groups(AgentId, Pid, Plugins),
            %% Find and remove the monitor ref.
            Mons2 = maps:filter(fun(_Ref, Id) -> Id =/= AgentId end, Mons),
            {noreply, State#state{monitor_refs = Mons2}};
        [] ->
            {noreply, State}
    end.

%% Fenced removal for an agent process cleaning up after itself. Its own
%% session index entry always goes (that entry can only be its own: it is
%% matched on this pid). The routing-table row and the pg memberships go only
%% while this pid is still the registered owner of AgentId; if a newer
%% registration replaced it, that registration is left alone.
do_deregister_fenced(AgentId, Pid, SessionId, #state{monitor_refs = Mons} = State) ->
    unindex_session(SessionId, Pid),
    case ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, _, Plugins, _, _, _}] ->
            ets:delete(?TABLE, AgentId),
            leave_groups(AgentId, Pid, Plugins),
            Mons2 = maps:filter(fun(_Ref, Id) -> Id =/= AgentId end, Mons),
            {noreply, State#state{monitor_refs = Mons2}};
        _ ->
            {noreply, State}
    end.

%% pg auto-removes on process exit, but leave explicitly for clarity.
leave_groups(AgentId, Pid, Plugins) ->
    catch pg:leave(?PG_SCOPE, all_agents, Pid),
    catch pg:leave(?PG_SCOPE, {agent, AgentId}, Pid),
    lists:foreach(fun(Plugin) ->
        catch pg:leave(?PG_SCOPE, {plugin, Plugin}, Pid)
    end, Plugins).

index_session(undefined, _AgentId, _Pid, _ConnKey) ->
    ok;
index_session(SessionId, AgentId, Pid, ConnKey) ->
    ets:insert(?SESSIONS_TABLE, {SessionId, AgentId, Pid, ConnKey}),
    ok.

%% Delete the index entry for SessionId only if it belongs to Pid. The key is
%% bound in the match head, so this is a single-key operation.
unindex_session(undefined, _Pid) ->
    ok;
unindex_session(SessionId, Pid) ->
    ets:select_delete(?SESSIONS_TABLE,
                      [{{SessionId, '_', Pid, '_'}, [], [true]}]),
    ok.

%% @doc Clean up a stale agent entry and return the updated monitor map.
maybe_cleanup(AgentId, Mons) ->
    case ets:lookup(?TABLE, AgentId) of
        [{_, OldPid, _, OldSessionId, OldPlugins, _, _, _}] ->
            leave_groups(AgentId, OldPid, OldPlugins),
            ets:delete(?TABLE, AgentId),
            %% The superseded session stops admitting heartbeats with its row.
            unindex_session(OldSessionId, OldPid),
            %% Demonitor old refs and remove them from the map.
            maps:fold(fun(Ref, Id, AccMons) ->
                case Id of
                    AgentId ->
                        demonitor(Ref, [flush]),
                        maps:remove(Ref, AccMons);
                    _ ->
                        AccMons
                end
            end, Mons, Mons);
        [] ->
            Mons
    end.
