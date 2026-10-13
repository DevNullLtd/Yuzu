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
%%%
%%% Sessions per connection. One enrolled connection could otherwise hold any
%%% number of sessions (a Register without a Subscribe stores a pending row, and
%%% every session may carry a fleet snapshot of up to 3 MiB into the heartbeat
%%% buffer). A connection key (see `yuzu_gw_conn') may hold at most
%%% `max_sessions_per_connection' (default 8, valid 1..1000) sessions, pending
%%% plus live, counted WITHOUT the agent being (re)registered: an agent id's own
%%% rows never count against it, so a reconnect or supersede never meets the cap
%%% by itself. The guarantee has three parts.
%%%
%%% 1. Rows, not agents. The count is the live rows plus the pending rows on the
%%% connection, one row per live session and one per agent with a pending or
%%% reserved session. A repeated Register of one agent id SUPERSEDES that agent's
%%% older pending rows on the connection (the live supersede does the same to the
%%% live row), so one agent holds at most one pending row and one live row and the
%%% counted slots of a connection stay within the cap (the agent being registered
%%% also keeps its own live and committed rows, which are not counted, until its
%%% Subscribe replaces them). A Register repeated with one id and no
%%% Subscribe therefore never grows the pending table. The exception is a Register
%%% still in flight: each reservation is a slot of its own, the registering
%%% agent's other reservations included (only its live row and its committed
%%% pending row are not counted, a commit supersedes them), so N concurrent
%%% Registers of one id admit at most the cap and a retry made while an earlier
%%% Register is in flight uses one more slot until that one is released or
%%% committed.
%%%
%%% 2. One atomic step. The check and the claim of a slot are made inside this
%%% process, which handles one call at a time: reserve_session/2 counts the slots held
%%% and, below the cap, stores a reservation row (a pending-table
%%% row keyed {reserved, Ref}, same TTL, counted like a pending row) before the
%%% registration is proxied upstream, so N concurrent Registers on a connection
%%% admit at most the cap and the rest are refused with nothing sent to the
%%% server. store_pending/3 then makes the reservation the pending row in one
%%% call to this process (commit_pending), which also supersedes the agent's older
%%% committed rows there, so concurrent same-agent Registers end with exactly one
%%% pending row (the newest committed). A commit that is itself superseded by a
%%% newer committed row, or whose own row a newer commit of the same agent already
%%% removed, answers {error, superseded} and leaves no row of its own: the registry
%%% is healthy, the agent's newer Register won, and the handler answers a retryable
%%% status. A commit whose own row is gone with no committed row of the agent there
%%% (the registry restarted since the insert) and a registry that cannot be reached
%%% (a missing table, a timeout) answer {error, registry_unavailable}. So no caller
%%% is told ok for a row that is not there AT COMMIT TIME: afterwards the row can
%%% be taken by Subscribe, swept after its TTL or removed with a dead connection,
%%% which is the later life of the row, not a false answer. The reservation is
%%% released by the caller when the proxied Register fails (release_session/1) and
%%% by the TTL sweep when the caller died; a stored pending row is released by
%%% Subscribe or its TTL.
%%%
%%% 3. Every other store is checked the same way. The live insert (the
%%% `register' call) asks session_admission/2 inside this process, and
%%% store_pending/2 without a reservation reserves one itself. All refuse with
%%% `{error, session_limit}'. Both counts are lookups in a per-connection index
%%% owned by this process (unnamed bags whose ids are kept in persistent_term), so
%%% a count costs the rows of that connection, never the size of either table. The
%%% live one is kept in step with the session index by index_session/4 and
%%% unindex_session/2 only, so every removal path (deregister, supersede, a dead
%%% process) releases the count. The pending one lists candidates, each checked
%%% against the row it names when counted (see pending_index_add/2): an entry whose
%%% row Subscribe took or a caller released counts for nothing and is dropped by
%%% the next reservation or commit on the connection, or by the sweep. A connection
%%% key of `undefined' is never counted.
%%%
%%% 4. A closed connection frees its rows after a grace. The registry monitors the
%%% connection process (one monitor per connection, taken when a reservation or
%%% pending row is first stored for it, whatever the number of rows). When it goes
%%% down the registry starts ONE timer for the connection, `dead_connection_grace_ms'
%%% (default 15000, 0..120000, 0 = at once), and when that fires removes every
%%% reservation and committed pending row of the connection (the rows its index
%%% names), so a client that reconnects over and over neither starts again below
%%% the cap nor leaves its stored RegisterRequests to wait for the TTL. Until then the rows stay and can be taken:
%%% an agent whose connection got GOAWAY after its Register subscribes on the
%%% reconnected channel and must find its session (a released agent answers
%%% NOT_FOUND by wedging, #2182). The rows count for the dead connection key only,
%%% which nothing uses. A dead connection with no row left has no timer, a row
%%% taken during the grace is simply gone when the timer fires, and the sweep
%%% cancels the timer of a dead connection whose rows are all gone. The sweep
%%% releases the monitor of a live connection that has no row left. Only a pid is
%%% monitored. A row stored for a connection that is already dead is removed the
%%% same way: the monitor of a dead process fires at once, and the connection's
%%% timer, if one runs, covers the new row (it does not restart). The removal reads
%%% the connection's index entries, so it costs the rows of that connection and
%%% never a scan of the pending table (one scan per lost connection is seconds of
%%% registry time when thousands go at once). A row a handler stored and has not
%%% committed yet is in no index and is NOT removed by it: its own commit finds the
%%% connection down and monitors it again (the removal then covers it), and if its
%%% caller died the TTL sweep removes it.
%%%
%%% Not covered: the gap between Subscribe taking a pending row and the live
%%% insert, where a slot is free for a moment and another Register can take it;
%%% the live insert is then the one refused, never a proxied Register left
%%% without a pending row.
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
         session_index_available/0,
         all_agents/0,
         all_agent_pids/0,
         all_register_reqs/0,
         entries_for_sessions/1,
         agents_for_plugin/1,
         agent_count/0,
         list_agents/2,
         store_pending/2,
         store_pending/3,
         take_pending/1,
         reserve_session/2,
         release_session/1,
         session_admission/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3,
         format_status/1]).

-define(SERVER, ?MODULE).
-define(TABLE,  yuzu_gw_agents).
-define(PENDING_TABLE, yuzu_gw_pending).
-define(SESSIONS_TABLE, yuzu_gw_sessions).
-define(PG_SCOPE, yuzu_gw).
-define(PENDING_TTL_MS, 120000).     %% 2 minutes
-define(PENDING_SWEEP_MS, 60000).    %% 1 minute
%% max_sessions_per_connection: distinct agents' sessions one connection may
%% hold. Valid 1..1000 (default 8); anything else logs a warning naming the key
%% and takes the default. Read once at registry start.
-define(DEFAULT_MAX_SESSIONS, 8).
%% How long the rows of a connection that went down stay takeable.
-define(DEFAULT_DEAD_GRACE_MS, 15000).
-define(MAX_DEAD_GRACE_MS, 120000).
-define(MIN_MAX_SESSIONS, 1).
-define(MAX_MAX_SESSIONS, 1000).
%% persistent_term keys: the configured cap, the per-connection index (an
%% unnamed table) and the stamp that limits the refusal WARN to one per second.
-define(MAX_SESSIONS_KEY, {?MODULE, max_sessions_per_connection}).
-define(CONN_INDEX_KEY, {?MODULE, conn_index}).
-define(PENDING_INDEX_KEY, {?MODULE, pending_index}).
-define(LIMIT_WARN_KEY, {?MODULE, session_limit_warn}).
-define(LIMIT_WARN_INTERVAL_MS, 1000).

-record(state, {
    monitor_refs :: #{reference() => binary()},
    %% One monitor per connection process that has a reservation or a pending row
    %% (the connection key, when it is a pid): its death removes those rows.
    conn_monitors = #{} :: #{pid() => reference()},
    sweep_timer  :: reference(),
    %% One grace timer per dead connection that still has a row: the rows go when
    %% it fires (never one timer per row).
    dead_conns = #{} :: #{pid() => reference()},
    dead_grace_ms = ?DEFAULT_DEAD_GRACE_MS :: non_neg_integer()
}).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%% @doc Register an agent with no stashed RegisterRequest.
%%
%% Back-compat entry point: production registration goes through
%% register_agent/7 (yuzu_gw_agent:init/1 always has the verbatim request
%% and the connection key). The /5 and /6 forms register with an undefined
%% connection key, so they admit no heartbeats; they are for tests and
%% legacy callers only. This /5 form is for callers - chiefly
%% routing-focused tests - that do not exercise the upstream-reconnect
%% replay path; it records an empty request, so such an agent is simply
%% skipped by the replay drip.
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary()) -> ok | {error, registry_unavailable | session_limit}.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname) ->
    register_agent(AgentId, Pid, SessionId, Plugins, Hostname, #{}).

%% @doc Register an agent process in the routing table.
%% Called by yuzu_gw_agent:init/1 from the agent process itself.
%%
%% RegisterReq is the verbatim `yuzu.agent.v1.RegisterRequest' map the
%% agent originally sent; it is stashed so the upstream client can
%% re-proxy it on reconnect (see all_register_reqs/0).
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary(), map()) ->
          ok | {error, registry_unavailable | session_limit}.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq) ->
    register_agent(AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq, undefined).

%% @doc Register an agent process and bind its session to ConnKey.
%%
%% ConnKey is the connection key of the Subscribe stream that created the
%% session (`yuzu_gw_conn:key_from_stream/1'); heartbeat admission admits a
%% heartbeat for SessionId only on that connection. The /5 and /6 forms
%% register with `undefined', which admits nothing. A session id of
%% `undefined' is not indexed at all.
%%
%% `{error, session_limit}' when the connection already holds the configured
%% number of other agents' sessions (see the module doc); nothing is changed.
%%
%% Never exits the caller: a registry that is not running, stalls past the call
%% timeout or dies serving the call gives `{error, registry_unavailable}'. The
%% exit of a gen_server:call carries the request, which here holds the stored
%% RegisterRequest (enrollment token, certificate, CSR). See yuzu_gw_safe_call.
-spec register_agent(binary(), pid(), binary() | undefined,
                     [binary()], binary(), map(), yuzu_gw_conn:key()) ->
          ok | {error, registry_unavailable | session_limit}.
register_agent(AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq, ConnKey) ->
    yuzu_gw_safe_call:call(?SERVER,
                           {register, AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq,
                            ConnKey},
                           30000, registry_unavailable).

%% @doc Remove an agent from the routing table.
%%
%% Unfenced: deletes whatever process currently holds AgentId, together with
%% that row's session index entry. Production code uses deregister_agent/3;
%% new callers must use /3.
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
%%
%% `{error, unavailable}' means the agents table does not exist (the registry
%% is not running or is restarting, which takes its tables with it); the
%% drip treats it as "stop", never as "agent gone" (#1197).
-spec lookup_local_session(binary()) ->
    {ok, {pid(), binary() | undefined}} | error | {error, unavailable}.
lookup_local_session(AgentId) ->
    try ets:lookup(?TABLE, AgentId) of
        [{_, Pid, _, SessionId, _, _, _, _}] ->
            case is_process_alive(Pid) of
                true  -> {ok, {Pid, SessionId}};
                false -> error
            end;
        [] ->
            error
    catch
        error:badarg -> {error, unavailable}
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
            case erlang:monotonic_time(millisecond) - StoredAt > ?PENDING_TTL_MS of
                true  -> error;
                false -> {ok, maps:get(conn_key, Info, undefined)}
            end;
        [] ->
            error
    catch
        error:badarg -> {error, unavailable}
    end.

%% @doc True when the session index table exists. Readiness uses it: a
%% registry process that is alive without the table (the state after new code
%% is loaded into a running node) keeps routing but rejects every heartbeat.
-spec session_index_available() -> boolean().
session_index_available() ->
    ets:whereis(?SESSIONS_TABLE) =/= undefined.

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

%% @doc The replay entries for the sessions this node holds (#1197).
%%
%% Resolves each id through the node-local session index
%% (`lookup_session/1'), then reads the agent's row once and requires it to
%% agree with the index: element 2 must be the indexed pid and element 4 the
%% session id. A row that has moved on (the agent re-registered under another
%% session, or its process died) is dropped. Returns the same
%% `{AgentId, SessionId, RegisterRequest}' tuple as `all_register_reqs/0', in
%% the order of `SessionIds', so a replay queue holds one shape whichever way
%% it was seeded.
%%
%% Ids this node does not hold are dropped, as is every id when either table
%% is missing (`badarg'); the caller counts the difference as "not local".
%% Read-only: neither table is ever written. Cost is O(k) ETS lookups for k
%% ids, never a table scan.
%%
%% Two keys on purpose. The caller enqueues by session (the server names
%% sessions) and pops by agent (`lookup_local_session/1' re-checks liveness
%% right before each send): two decisions, two keys.
-spec entries_for_sessions([binary()]) -> [{binary(), binary() | undefined, map()}].
entries_for_sessions(SessionIds) ->
    lists:filtermap(fun entry_for_session/1, SessionIds).

entry_for_session(SessionId) ->
    case lookup_session(SessionId) of
        {ok, #{agent_id := AgentId, pid := Pid}} ->
            try ets:lookup(?TABLE, AgentId) of
                [{_, Pid, _, SessionId, _, _, _, RegisterReq}] ->
                    {true, {AgentId, SessionId, RegisterReq}};
                _ ->
                    false
            catch
                error:badarg -> false
            end;
        _ ->
            false
    end.

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
%% Called by agent_service on Register, consumed by Subscribe. The row is
%% stamped with the node-local monotonic clock, so the TTL in
%% `lookup_pending_session/1' and the sweep is immune to wall-clock steps.
%%
%% Reservation is what reserve_session/2 returned for this Register (or
%% `undefined'): the row then takes the slot the reservation holds, with no
%% second count. Without one the connection's slot is reserved here, so a
%% caller that did not reserve is still refused over the cap. Either way the
%% pending rows of the same agent id on the same connection that are not newer than
%% this one are removed (see the module doc, part 2), and the reservation is
%% consumed. A row with no connection key is stored as is: it is never counted.
%%
%% The table is owned by the registry process and written from the caller's own
%% process (a grpcbox handler). With the registry down the table is gone and the
%% insert raises badarg, whose stacktrace carries Info, which holds the
%% RegisterRequest (enrollment token, certificate, CSR) and which grpcbox logs.
%% The error is caught here and the fixed {error, registry_unavailable} returned:
%% no stacktrace, no arguments. The one call made to the registry process carries
%% the session id, the connection key, the agent id and the reservation, never
%% Info.
%%
%% `{error, superseded}' when a newer Register of the same agent id on the
%% connection committed first: the row is not stored and the registry is healthy.
-spec store_pending(binary(), map()) ->
          ok | {error, registry_unavailable | session_limit | superseded}.
store_pending(SessionId, Info) ->
    store_pending(SessionId, Info, undefined).

-spec store_pending(binary(), map(), reference() | undefined) ->
          ok | {error, registry_unavailable | session_limit | superseded}.
store_pending(SessionId, Info, Reservation) ->
    case maps:get(conn_key, Info, undefined) of
        undefined ->
            insert_pending(SessionId, Info);
        ConnKey ->
            AgentId = maps:get(agent_id, Info, undefined),
            case held_reservation(ConnKey, AgentId, Reservation) of
                {ok, Ref}          -> store_counted(SessionId, Info, ConnKey, AgentId, Ref);
                {error, _} = Error -> Error
            end
    end.

held_reservation(ConnKey, AgentId, undefined) ->
    reserve_session(ConnKey, AgentId);
held_reservation(_ConnKey, _AgentId, Reservation) ->
    {ok, Reservation}.

%% The row goes in first and the registry process then commits it (one call):
%% the reservation it replaces is counted for the same agent in between, so the
%% count never reads lower than the rows that exist.
store_counted(SessionId, Info, ConnKey, AgentId, Ref) ->
    case insert_pending(SessionId, Info) of
        ok ->
            case yuzu_gw_safe_call:call(?SERVER,
                                        {commit_pending, SessionId, ConnKey, AgentId, Ref},
                                        5000, registry_unavailable) of
                ok ->
                    ok;
                {error, _} = Error ->
                    %% Refused (the registry already removed the row) or not
                    %% reachable (the row must not stay unadmitted).
                    try ets:delete(?PENDING_TABLE, SessionId)
                    catch error:badarg -> true
                    end,
                    release_session(Ref),
                    Error
            end;
        {error, _} = Error ->
            release_session(Ref),
            Error
    end.

insert_pending(SessionId, Info) ->
    try ets:insert(?PENDING_TABLE, {SessionId, Info, erlang:monotonic_time(millisecond)}) of
        true -> ok
    catch
        error:badarg -> {error, registry_unavailable}
    end.

%% @doc Claim a session slot on ConnKey for AgentId BEFORE the registration is
%% proxied upstream. `{ok, Reservation}' holds the slot until it is turned into
%% the pending row by store_pending/3, released by release_session/1 or swept
%% after the pending TTL; `{error, session_limit}' when the connection already
%% holds `max_sessions_per_connection' slots other than the agent's own live row
%% and committed pending row (the agent's other reservations in flight each count;
%% a refusal is counted, and logged as one WARN per second that names only the
%% cap). The check and the claim are
%% one step in the registry process, which is what makes the cap hold under
%% concurrent Registers. A `undefined' key is never counted: `{ok, undefined}'.
%% `{error, registry_unavailable}' when the registry cannot be called.
-spec reserve_session(yuzu_gw_conn:key(), term()) ->
          {ok, reference() | undefined} | {error, session_limit | registry_unavailable}.
reserve_session(undefined, _AgentId) ->
    {ok, undefined};
reserve_session(ConnKey, AgentId) ->
    yuzu_gw_safe_call:call(?SERVER, {reserve_session, ConnKey, AgentId}, 5000,
                           registry_unavailable).

%% @doc Release a reservation that was not turned into a pending row (the
%% proxied Register failed). Idempotent; `undefined' and a missing table are
%% no-ops.
-spec release_session(reference() | undefined) -> ok.
release_session(undefined) ->
    ok;
release_session(Reservation) ->
    try ets:delete(?PENDING_TABLE, {reserved, Reservation}) of
        true -> ok
    catch
        error:badarg -> ok
    end.

%% @doc Whether the connection ConnKey may take a session for AgentId: `ok', or
%% `{error, session_limit}' when it already holds `max_sessions_per_connection'
%% other agents' rows (pending, reserved or live). A refusal is counted
%% (yuzu_gw_session_limit_rejected_total) and logged as one WARN per second that
%% names only the cap. A `undefined' key is always admitted. This is a read: the
%% Subscribe handler asks it before it starts an agent process, and the registry
%% process asks it for the live insert and inside reserve_session/2, where the
%% decision and the claim are one step.
-spec session_admission(yuzu_gw_conn:key(), term()) -> ok | {error, session_limit}.
session_admission(undefined, _AgentId) ->
    ok;
session_admission(ConnKey, AgentId) ->
    admission(ConnKey, AgentId, live).

%% Mode `live': AgentId's own rows never count (the live insert replaces its live
%% row and consumes its Register's pending row). Mode `reserve': the agent's live
%% row and committed pending row still do not count (the commit this reservation
%% leads to supersedes them), but every other in-flight reservation of the agent
%% does, one slot each: each is a Register proxied upstream.
admission(undefined, _AgentId, _Mode) ->
    ok;
admission(ConnKey, AgentId, Mode) ->
    Cap = max_sessions_per_connection(),
    case others_on_connection(ConnKey, AgentId, Mode) >= Cap of
        true ->
            telemetry:execute([yuzu, gw, session, limit_rejected], #{count => 1}, #{}),
            warn_session_limit(Cap),
            {error, session_limit};
        false ->
            ok
    end.

max_sessions_per_connection() ->
    persistent_term:get(?MAX_SESSIONS_KEY, ?DEFAULT_MAX_SESSIONS).

%% The slots held on ConnKey other than AgentId's own live row and committed
%% pending row (its live insert replaces the first and its commit supersedes the
%% second): one per live session of another agent, one per reservation (each is a
%% Register in flight, whatever agent holds it), and one per other agent whose
%% committed pending row is not past its TTL and who has no reservation in flight
%% (a commit of that reservation supersedes the committed row). In mode `live'
%% AgentId's reservations are left out too. A table that does not exist counts as
%% empty: its absence is reported by the calls that need it, not here.
others_on_connection(ConnKey, AgentId, Mode) ->
    Live = [A || A <- live_agents(ConnKey), A =/= AgentId],
    {Reserved, Committed} = pending_slots(ConnKey),
    Reservations = case Mode of
        live    -> [A || A <- Reserved, A =/= AgentId];
        reserve -> Reserved
    end,
    Holding = sets:from_list(Reserved),
    Rows = [A || A <- lists:usort(Committed), A =/= AgentId, not sets:is_element(A, Holding)],
    length(Live) + length(Reservations) + length(Rows).

live_agents(ConnKey) ->
    case persistent_term:get(?CONN_INDEX_KEY, undefined) of
        undefined ->
            [];
        Index ->
            try [A || {_, A, _} <- ets:lookup(Index, ConnKey)]
            catch error:badarg -> []
            end
    end.

%% The agent ids of the reservation rows and of the committed pending rows on
%% ConnKey (a reservation is a pending-table row keyed {reserved, Ref}, a committed
%% row is keyed by its binary session id) not past their TTL; one entry per row.
%% Read from the connection's index: the cost is its rows, not the table's.
pending_slots(ConnKey) ->
    Oldest = erlang:monotonic_time(millisecond) - ?PENDING_TTL_MS,
    Rows = [{Key, A} || {Key, #{agent_id := A}, StoredAt} <- indexed_rows(ConnKey),
                        StoredAt >= Oldest],
    {[A || {{reserved, _}, A} <- Rows], [A || {Key, A} <- Rows, is_binary(Key)]}.

%% At most one WARN per second, from any process; the stamp is created by init/1
%% (without it nothing is logged: the registry is not running).
warn_session_limit(Cap) ->
    case persistent_term:get(?LIMIT_WARN_KEY, undefined) of
        undefined ->
            ok;
        Ref ->
            Now = erlang:monotonic_time(millisecond),
            Last = atomics:get(Ref, 1),
            case Now - Last >= ?LIMIT_WARN_INTERVAL_MS
                 andalso atomics:compare_exchange(Ref, 1, Last, Now) =:= ok of
                true ->
                    logger:warning("Registration refused: a connection already holds "
                                   "the configured ~b agent sessions "
                                   "(max_sessions_per_connection)", [Cap]);
                false ->
                    ok
            end
    end.

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
%%
%% With the registry down the table is gone: the fixed
%% {error, registry_unavailable}, caught here for the reason store_pending/2
%% gives.
-spec take_pending(binary()) -> map() | undefined | {error, registry_unavailable}.
take_pending(SessionId) ->
    try ets:take(?PENDING_TABLE, SessionId) of
        [{_, Info, _}] ->
            Info;
        [] ->
            undefined
    catch
        error:badarg -> {error, registry_unavailable}
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?TABLE, [named_table, set, public, {read_concurrency, true}]),
    %% public (unlike the session index below): handler processes write
    %% pending rows directly. protected on the session index guards against
    %% accidental writes; it is not a trust boundary, any code in the node can
    %% still call the registry.
    ets:new(?PENDING_TABLE, [named_table, set, public]),
    %% protected: only this process writes the session index; heartbeat
    %% handler processes read it.
    ets:new(?SESSIONS_TABLE, [named_table, set, protected, {read_concurrency, true}]),
    %% The per-connection index: unnamed, so a restarting registry never meets
    %% the previous one's table, and its id is published for the handlers.
    ConnIndex = ets:new(yuzu_gw_conn_sessions, [bag, protected, {read_concurrency, true}]),
    persistent_term:put(?CONN_INDEX_KEY, ConnIndex),
    %% The same for the pending table: {ConnKey, Key} of its connection-keyed rows.
    PendingIndex = ets:new(yuzu_gw_pending_conn, [bag, protected, {read_concurrency, true}]),
    persistent_term:put(?PENDING_INDEX_KEY, PendingIndex),
    put_if_changed(?MAX_SESSIONS_KEY,
                   yuzu_gw_env:env_int(max_sessions_per_connection, ?DEFAULT_MAX_SESSIONS,
                                       ?MIN_MAX_SESSIONS, ?MAX_MAX_SESSIONS)),
    init_limit_warn_stamp(),
    TRef = erlang:send_after(?PENDING_SWEEP_MS, self(), sweep_pending),
    Grace = yuzu_gw_env:env_int(dead_connection_grace_ms, ?DEFAULT_DEAD_GRACE_MS,
                                0, ?MAX_DEAD_GRACE_MS),
    {ok, #state{monitor_refs = #{}, sweep_timer = TRef, dead_grace_ms = Grace}}.

%% A persistent_term:put over a different value costs a global GC: skip it
%% when the value is already there.
put_if_changed(Key, Value) ->
    case persistent_term:get(Key, undefined) of
        Value -> ok;
        _     -> persistent_term:put(Key, Value)
    end.

%% A stamp old enough that the first refusal logs; an existing one is reset, not
%% replaced.
init_limit_warn_stamp() ->
    Old = erlang:monotonic_time(millisecond) - 2 * ?LIMIT_WARN_INTERVAL_MS,
    case persistent_term:get(?LIMIT_WARN_KEY, undefined) of
        undefined ->
            Ref = atomics:new(1, [{signed, true}]),
            atomics:put(Ref, 1, Old),
            persistent_term:put(?LIMIT_WARN_KEY, Ref);
        Ref ->
            atomics:put(Ref, 1, Old)
    end.

handle_call({reserve_session, ConnKey, AgentId}, _From, State) ->
    %% Check and claim in one step: this process handles one call at a time, so
    %% the count a reservation was admitted on is the count the next one sees.
    Reply = case admission(ConnKey, AgentId, reserve) of
        ok ->
            Ref = make_ref(),
            true = ets:insert(?PENDING_TABLE,
                              {{reserved, Ref}, #{conn_key => ConnKey, agent_id => AgentId},
                               erlang:monotonic_time(millisecond)}),
            pending_index_add(ConnKey, {reserved, Ref}),
            {ok, Ref};
        {error, session_limit} = Refused ->
            Refused
    end,
    prune_pending_index(ConnKey),
    {reply, Reply, case Reply of
                       {ok, _} -> monitor_connection(ConnKey, State);
                       _       -> State
                   end};

handle_call({commit_pending, SessionId, ConnKey, AgentId, Ref}, _From, State) ->
    %% The pending row is already stored, and it must still be there: a commit
    %% finds its own row gone when a later commit of the same agent id superseded
    %% it, when the table was replaced by a restart between the insert and this
    %% call, or when the caller timed out and this is the late call. It then
    %% answers the fixed error and changes nothing, so a row never reads as
    %% committed that is not there. A live reservation is the admission: consumed,
    %% not checked again (the connection may hold one row more than the cap by
    %% now through rows that count twice, and the proxied Register must not be
    %% left without its row). Without one (swept after its TTL, or released) the
    %% cap is checked here and a refusal removes the row.
    Reply = case ets:lookup(?PENDING_TABLE, SessionId) of
        [{_, _, StoredAt}] ->
            case take_reservation(ConnKey, Ref) of
                true ->
                    supersede_pending(ConnKey, AgentId, SessionId, StoredAt);
                false ->
                    case admission(ConnKey, AgentId, reserve) of
                        ok ->
                            supersede_pending(ConnKey, AgentId, SessionId, StoredAt);
                        {error, session_limit} = Refused ->
                            ets:delete(?PENDING_TABLE, SessionId),
                            Refused
                    end
            end;
        [] ->
            %% Superseded when a newer commit of the same agent removed this row
            %% (that one is committed, so its row is indexed); otherwise the row
            %% is lost with the table (a restart), which is a registry failure.
            case committed_rows_of(ConnKey, AgentId, SessionId) of
                [] -> {error, registry_unavailable};
                _  -> {error, superseded}
            end
    end,
    prune_pending_index(ConnKey),
    {reply, Reply, case Reply of
                       ok -> monitor_connection(ConnKey, State);
                       _  -> State
                   end};

handle_call({register, AgentId, _Pid, _SessionId, _Plugins, _Hostname, _RegisterReq, ConnKey}
            = Request, From, State) ->
    %% The cap is checked before anything is changed, so a refused registration
    %% leaves the agent's older one in place. An admitted one is handled by the
    %% clause below.
    case session_admission(ConnKey, AgentId) of
        ok                     -> handle_call(setelement(1, Request, admitted_register),
                                              From, State);
        {error, session_limit} -> {reply, {error, session_limit}, State}
    end;

handle_call({admitted_register, AgentId, Pid, SessionId, Plugins, Hostname, RegisterReq, ConnKey},
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
            %% A connection process: its reservations and pending rows go after
            %% the grace (a stored RegisterRequest is not kept for a connection
            %% that is gone, and a reconnect does not start again below the cap).
            %% The monitor is spent.
            #state{conn_monitors = ConnMons} = State,
            case maps:find(Pid, ConnMons) of
                {ok, MonRef} ->
                    {noreply, connection_down(
                                Pid, State#state{conn_monitors = maps:remove(Pid, ConnMons)})};
                _ ->
                    {noreply, State}
            end
    end;

handle_info({timeout, TRef, Pid}, #state{dead_conns = Dead} = State) when is_pid(Pid) ->
    %% The grace of a dead connection is over. A timer that was cancelled, or
    %% replaced, is not the one the state holds: nothing to do.
    case maps:find(Pid, Dead) of
        {ok, TRef} ->
            drop_connection_rows(Pid),
            {noreply, State#state{dead_conns = maps:remove(Pid, Dead)}};
        _ ->
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
    Now = erlang:monotonic_time(millisecond),
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
    {noreply, release_idle_monitors(State#state{sweep_timer = TRef})};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% What OTP prints for this process in a terminate report and in
%% sys:get_status/1: the last message with the RegisterRequest of a `register'
%% call (enrollment token, machine certificate, CSR) replaced. The state holds
%% no request. NOT covered here, because OTP prints it from raw data outside
%% this callback (the stacktrace, whose frames carry the argument list of a
%% failing handle_call/3, and the mailbox): yuzu_gw_crash_redact, the logger
%% primary filter yuzu_gw_app installs, rewrites those for this process. It is
%% NOT in place when this module is used without the application.
-spec format_status(map()) -> map().
format_status(Status) ->
    maps:map(fun(message, Msg) -> redact_message(Msg);
                (_Key, Value)  -> Value
             end, Status).

redact_message({register, AgentId, Pid, SessionId, Plugins, Hostname, _RegisterReq, ConnKey}) ->
    {register, AgentId, Pid, SessionId, Plugins, Hostname, '$redacted', ConnKey};
redact_message({'$gen_call', From, Msg}) -> {'$gen_call', From, redact_message(Msg)};
redact_message({'$gen_cast', Msg})       -> {'$gen_cast', redact_message(Msg)};
redact_message(Msg)                      -> Msg.

%%%===================================================================
%%% Internal
%%%===================================================================

%% Remove the reservation Ref and say whether it was live (stored and not past
%% its TTL). `undefined' holds nothing.
take_reservation(_ConnKey, undefined) ->
    false;
take_reservation(ConnKey, Ref) ->
    Oldest = erlang:monotonic_time(millisecond) - ?PENDING_TTL_MS,
    pending_index_delete(ConnKey, {reserved, Ref}),
    case ets:take(?PENDING_TABLE, {reserved, Ref}) of
        [{_, _, StoredAt}] -> StoredAt >= Oldest;
        []                 -> false
    end.

%% Monitor the connection process ConnKey once, when the first reservation or
%% pending row is stored for it. Only a pid is monitored (the key is any term in
%% tests, and a monitor of an atom names a registered process). A process that is
%% already dead is monitored all the same: its DOWN arrives at once and removes
%% the rows just stored.
monitor_connection(ConnKey, #state{conn_monitors = ConnMons} = State) when is_pid(ConnKey) ->
    case maps:is_key(ConnKey, ConnMons) of
        true  -> State;
        false -> State#state{conn_monitors = ConnMons#{ConnKey => monitor(process, ConnKey)}}
    end;
monitor_connection(_ConnKey, State) ->
    State.

%% The connection process ConnKey went down (its monitor is spent). With no row
%% left there is nothing to wait for. With a grace of 0 the rows go now. Otherwise
%% ONE timer starts for the connection, and none when one already runs (a row
%% stored for the dead connection meanwhile goes with the first timer).
connection_down(ConnKey, #state{dead_conns = Dead, dead_grace_ms = Grace} = State) ->
    case maps:is_key(ConnKey, Dead) of
        true ->
            State;
        false ->
            case indexed_rows(ConnKey) of
                [] ->
                    with_index(?PENDING_INDEX_KEY, fun(Index) -> ets:delete(Index, ConnKey) end),
                    State;
                _ when Grace =:= 0 ->
                    drop_connection_rows(ConnKey),
                    State;
                _ ->
                    TRef = erlang:start_timer(Grace, self(), ConnKey),
                    State#state{dead_conns = Dead#{ConnKey => TRef}}
            end
    end.

%% Remove every reservation and pending row of the connection ConnKey that its
%% index names (each by its key, so the cost is that connection's rows, not the
%% table's), and then its index entries. A row not in the index (inserted by a
%% handler and not yet committed) stays for its own commit or the TTL sweep.
drop_connection_rows(ConnKey) ->
    with_index(?PENDING_INDEX_KEY,
               fun(Index) ->
                   _ = [ets:select_delete(?PENDING_TABLE,
                                          [{{Key, #{conn_key => ConnKey}, '_'}, [], [true]}])
                        || {_, Key} <- ets:lookup(Index, ConnKey)],
                   ets:delete(Index, ConnKey)
               end).

%% Release the monitor of a connection with no reservation or pending row left
%% (Subscribe took its rows, or they expired): a connection that lives for days
%% must not hold one for as long. Run by the sweep; a connection that stores a
%% row later is monitored again by that call. The same for the grace timer of a
%% dead connection whose rows are all gone.
release_idle_monitors(#state{conn_monitors = ConnMons, dead_conns = Dead} = State) ->
    case persistent_term:get(?PENDING_INDEX_KEY, undefined) of
        undefined ->
            State;
        Index ->
            prune_entries(Index, ets:tab2list(Index)),
            Kept = maps:filter(fun(Conn, MonRef) ->
                                   case ets:member(Index, Conn) of
                                       true  -> true;
                                       false -> demonitor(MonRef, [flush]), false
                                   end
                               end, ConnMons),
            DeadKept = maps:filter(fun(Conn, TRef) ->
                                       case ets:member(Index, Conn) of
                                           true  -> true;
                                           false -> _ = erlang:cancel_timer(TRef), false
                                       end
                                   end, Dead),
            State#state{conn_monitors = Kept, dead_conns = DeadKept}
    end.

%% A Register of AgentId on ConnKey replaces its older pending rows there, as the
%% live insert replaces the live row. Run in this process when a caller commits
%% the row it stored (StoredAt is its stamp), against the COMMITTED rows of the
%% agent, which are the ones in the connection's index: the committed rows stored
%% at or before this one are removed and this one is indexed; when a committed row
%% of the agent is NEWER than this one, this one is the older Register and is
%% itself removed, and the fixed error is answered. So the agent has at most one
%% committed row after every commit, the one of the newest stamp (of equal stamps,
%% the last commit handled), and a caller answered ok has a row. A row stored and
%% not yet committed is another Register still in flight and is left alone, as are
%% reservation rows (keys that are not binaries).
supersede_pending(ConnKey, AgentId, SessionId, StoredAt) ->
    Committed = committed_rows_of(ConnKey, AgentId, SessionId),
    case lists:any(fun({_, T}) -> T > StoredAt end, Committed) of
        true ->
            ets:delete(?PENDING_TABLE, SessionId),
            {error, superseded};
        false ->
            _ = [begin
                     ets:delete(?PENDING_TABLE, Key),
                     pending_index_delete(ConnKey, Key)
                 end || {Key, _} <- Committed],
            pending_index_add(ConnKey, SessionId),
            ok
    end.

%% The committed pending rows of AgentId on ConnKey other than SessionId's own, as
%% `{Key, StoredAt}': the index lists only committed rows and reservations, and a
%% reservation key is not a binary.
committed_rows_of(ConnKey, AgentId, SessionId) ->
    [{Key, T} || {Key, #{agent_id := A}, T} <- indexed_rows(ConnKey),
                 is_binary(Key), Key =/= SessionId, A =:= AgentId].

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

%% The session index is a secondary table: it must never take down the
%% routing table. If it does not exist (new code loaded into a node whose
%% registry was started before the table was added), indexing is skipped, the
%% routing row and pg groups are maintained as usual, and heartbeat admission
%% keeps failing closed (`lookup_session/1' reports `{error, unavailable}').
%% Only `badarg' (a missing table) is tolerated; any other error still raises.
index_session(undefined, _AgentId, _Pid, _ConnKey) ->
    ok;
index_session(SessionId, AgentId, Pid, ConnKey) ->
    try
        %% A row already indexed under this session id is replaced: its
        %% per-connection entry goes with it.
        conn_index_remove(SessionId),
        ets:insert(?SESSIONS_TABLE, {SessionId, AgentId, Pid, ConnKey}),
        conn_index_add(ConnKey, AgentId, SessionId)
    of
        _ -> ok
    catch
        error:badarg ->
            warn_session_index_missing()
    end.

%% Delete the index entry for SessionId only if it belongs to Pid. The key is
%% bound in the match head, so this is a single-key operation. A missing table
%% is tolerated for the reason given at index_session/4. The per-connection
%% entry of the row goes first (this is the only place a session leaves the
%% index, so it is the only place the count is released).
unindex_session(undefined, _Pid) ->
    ok;
unindex_session(SessionId, Pid) ->
    try
        case ets:lookup(?SESSIONS_TABLE, SessionId) of
            [{_, AgentId, Pid, ConnKey}] -> conn_index_delete(ConnKey, AgentId, SessionId);
            _                            -> ok
        end,
        ets:select_delete(?SESSIONS_TABLE, [{{SessionId, '_', Pid, '_'}, [], [true]}])
    of
        _ -> ok
    catch
        error:badarg ->
            ok
    end.

%% The per-connection index: {ConnKey, AgentId, SessionId}, one object per
%% indexed session with a connection key. Written by this process only.
conn_index_add(undefined, _AgentId, _SessionId) ->
    ok;
conn_index_add(ConnKey, AgentId, SessionId) ->
    with_conn_index(fun(Index) -> ets:insert(Index, {ConnKey, AgentId, SessionId}) end).

conn_index_delete(undefined, _AgentId, _SessionId) ->
    ok;
conn_index_delete(ConnKey, AgentId, SessionId) ->
    with_conn_index(fun(Index) -> ets:delete_object(Index, {ConnKey, AgentId, SessionId}) end).

%% The per-connection indexes are secondary structures like the session index: a
%% registry that runs without one (new code loaded into a running node) skips it,
%% and the count then reads as empty.
with_conn_index(Fun) ->
    with_index(?CONN_INDEX_KEY, Fun).

with_index(PtKey, Fun) ->
    case persistent_term:get(PtKey, undefined) of
        undefined ->
            ok;
        Index ->
            try Fun(Index) of
                _ -> ok
            catch
                error:badarg -> ok
            end
    end.

%% The pending index: {ConnKey, Key} for each reservation and each committed
%% pending row of a connection (Key is the session id, or {reserved, Ref}), written
%% by this process only, in step with the commit (the row exists before it is
%% indexed). It is a list of CANDIDATES: a row taken by Subscribe, or released or
%% removed by its caller, leaves its entry behind until the next call for the
%% connection (prune_pending_index/1) or the sweep, so an entry counts only while
%% the row it names is stored and belongs to the connection (indexed_rows/1).
%% That keeps a count at the rows of one connection, however many the table holds.
pending_index_add(ConnKey, Key) ->
    with_index(?PENDING_INDEX_KEY, fun(Index) -> ets:insert(Index, {ConnKey, Key}) end).

pending_index_delete(ConnKey, Key) ->
    with_index(?PENDING_INDEX_KEY,
               fun(Index) -> ets:delete_object(Index, {ConnKey, Key}) end).

%% The stored rows of ConnKey named by its index entries: `{Key, Info, StoredAt}',
%% one per entry whose row exists and carries ConnKey. A missing index is empty.
indexed_rows(ConnKey) ->
    case persistent_term:get(?PENDING_INDEX_KEY, undefined) of
        undefined ->
            [];
        Index ->
            try [Row || {_, Key} <- ets:lookup(Index, ConnKey),
                        Row <- pending_row(ConnKey, Key)]
            catch error:badarg -> []
            end
    end.

pending_row(ConnKey, Key) ->
    case ets:lookup(?PENDING_TABLE, Key) of
        [{_, #{conn_key := ConnKey}, _} = Row] -> [Row];
        _                                      -> []
    end.

%% Drop the entries of ConnKey in the pending index whose row is gone or belongs
%% to another connection (the sweep prunes every connection's).
prune_pending_index(ConnKey) ->
    with_index(?PENDING_INDEX_KEY,
               fun(Index) -> prune_entries(Index, ets:lookup(Index, ConnKey)) end).

prune_entries(Index, Entries) ->
    _ = [ets:delete_object(Index, Entry)
         || {ConnKey, Key} = Entry <- Entries, pending_row(ConnKey, Key) =:= []],
    ok.

%% Drop the per-connection entry of whatever row is indexed under SessionId.
conn_index_remove(SessionId) ->
    case ets:lookup(?SESSIONS_TABLE, SessionId) of
        [{_, AgentId, _Pid, ConnKey}] -> conn_index_delete(ConnKey, AgentId, SessionId);
        []                            -> ok
    end.

%% One warning per registry process, not one per registration.
warn_session_index_missing() ->
    case get(session_index_missing_logged) of
        true ->
            ok;
        _ ->
            put(session_index_missing_logged, true),
            logger:warning("Session index table ~s is missing: heartbeats are "
                           "rejected until the gateway is restarted",
                           [?SESSIONS_TABLE])
    end.

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
