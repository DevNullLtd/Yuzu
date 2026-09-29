%%%-------------------------------------------------------------------
%%% @doc Minimal ManagementService stub for yuzu_gw_authz_rpc_tests.
%%%
%%% Serves canned responses and counts invocations in an ETS table so the
%%% tests can assert the LISTENER's auth_fun gated a call before any
%%% service code ran (the load-bearing property of #1422: rejection must
%%% happen pre-handler). Deliberately NOT yuzu_gw_mgmt_service — these
%%% tests prove transport authorization mechanics, not fan-out logic, and
%%% the real handlers need the registry/router tree running.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_authz_stub_svc).

-export([list_agents/2, send_command/2]).
-export([init_counters/0, invocations/0]).

-define(TAB, yuzu_gw_authz_stub_calls).

%% Called from test setup (owner: the eunit setup process's group leader
%% lives for the fixture, so make the table public + named and tolerate
%% re-init).
init_counters() ->
    catch ets:delete(?TAB),
    ets:new(?TAB, [named_table, public, set]),
    ets:insert(?TAB, {invocations, 0}),
    ok.

invocations() ->
    case ets:lookup(?TAB, invocations) of
        [{invocations, N}] -> N;
        []                 -> 0
    end.

bump() ->
    _ = ets:update_counter(?TAB, invocations, 1),
    ok.

%% Unary: grpcbox calls Module:Function(Ctx, Message) and expects
%% {ok, Response, Ctx} (grpcbox_stream:handle_unary/3).
list_agents(Ctx, _Request) ->
    bump(),
    {ok, #{agents => [], next_cursor => <<>>}, Ctx}.

%% Output-streaming: grpcbox spawns handle_streams(Message, StreamState)
%% and calls Module:Function(Message, StreamState) — send nothing, end OK.
send_command(_Request, _Stream) ->
    bump(),
    ok.
