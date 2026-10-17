%%%-------------------------------------------------------------------
%%% @doc simple_one_for_one supervisor for yuzu_gw_agent processes.
%%%
%%% Each connected agent gets one process, started dynamically when
%%% the agent's Subscribe bidi stream arrives. `temporary` restart
%%% strategy: if an agent process crashes, the agent reconnects
%%% naturally via Register → Subscribe.
%%%
%%% A temporary child is never restarted, so no child exit counts against
%%% the restart intensity: neither a crash nor a refused registration (which
%%% exits `normal') can take this supervisor down, however many arrive at once.
%%%
%%% The child's start function (yuzu_gw_agent:start_link_async/1) returns as
%%% soon as the process exists; the agent registers as its first event. So
%%% start_child never waits for the registry, and one slow registration does
%%% not hold every other Subscribe (and this supervisor's handling of child
%%% exits) behind it. start_agent/1 waits for the outcome in the caller.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_agent_sup).
-behaviour(supervisor).

-export([start_link/0, start_agent/1, count/0]).
-export([init/1]).

-define(SERVER, ?MODULE).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%% @doc Start a new agent process for an incoming Subscribe stream and
%% return once its registration is decided: `{ok, Pid}' with the agent in the
%% routing table, `{error, session_limit | registry_unavailable}' when it was
%% refused (the process is then gone). The supervisor is free as soon as the
%% process exists; the wait is in the caller (yuzu_gw_agent:await_registration/2).
%%
%% Args holds the RegisterRequest (enrollment_token, machine_certificate,
%% csr_pem). A start_child that exits (this supervisor is not running) exits the
%% CALLER, a gRPC handler process, with a reason that embeds the call and so
%% Args, which would be logged. The exit is turned into the fixed
%% {error, agent_sup_unavailable}; neither the reason nor Args is logged (see
%% yuzu_gw_safe_call).
-spec start_agent(map()) -> {ok, pid()} | {error, term()}.
start_agent(Args) ->
    Alias = alias([reply]),
    case yuzu_gw_safe_call:guard(?SERVER,
                                 fun() ->
                                     supervisor:start_child(?SERVER,
                                                            [Args#{registered_ack => Alias}])
                                 end,
                                 agent_sup_unavailable) of
        {ok, Pid} when is_pid(Pid) ->
            yuzu_gw_agent:await_registration(Pid, Alias);
        Other ->
            unalias(Alias),
            Other
    end.

%% @doc Return the number of active agent processes.
-spec count() -> non_neg_integer().
count() ->
    proplists:get_value(active, supervisor:count_children(?SERVER), 0).

%%--------------------------------------------------------------------
%% supervisor callback
%%--------------------------------------------------------------------

init([]) ->
    SupFlags = #{
        strategy  => simple_one_for_one,
        intensity => 0,    %% Don't restart; agent will reconnect
        period    => 1
    },

    ChildSpec = #{
        id       => agent,
        start    => {yuzu_gw_agent, start_link_async, []},
        restart  => temporary,
        shutdown => 5000,
        type     => worker
    },

    {ok, {SupFlags, [ChildSpec]}}.
