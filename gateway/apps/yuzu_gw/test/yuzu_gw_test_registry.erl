%%%-------------------------------------------------------------------
%%% @doc Shared EUnit helper: make a real `yuzu_gw_registry' available.
%%%
%%% Every gateway test module that exercises the registry `start_link's
%%% it in its own `setup/0'. Because `start_link' links the registry to
%%% the transient EUnit fixture process, the registry dies when that
%%% module's fixture process exits — and ETS table destruction on owner
%%% death is *asynchronous*. So when the next module's `setup/0' runs
%%% there is a window where `whereis(yuzu_gw_registry) =:= undefined' but
%%% the named tables the dead registry owned (`yuzu_gw_agents' /
%%% `yuzu_gw_pending' / `yuzu_gw_sessions') are not yet reaped. A naive `start_link' in that
%%% window crashes in `init/1' with
%%%
%%%     ets:new(yuzu_gw_pending, ...) → {badarg, ... table name already exists}
%%%
%%% which cancels the whole module's tests (`One or more tests were
%%% cancelled') and reddens CI. The window is timing-dependent and widens
%%% on the self-hosted Windows runner (slower scheduling + Defender I/O
%%% serialisation), which is why it surfaced there intermittently and
%%% cleared on re-run. Issue #1403; documented as `#336' hazard 2 in
%%% `yuzu_gw_registration_replay_tests'.
%%%
%%% A second hazard (#336): `yuzu_gw_health_nf_tests' can leave a
%%% non-gen_server "mock_loop" process registered under the name; reusing
%%% it would hang the next `register_agent' call. `ensure/0' evicts it.
%%%
%%% This module centralises the proven navigation of both hazards so every
%%% registry-using suite shares one correct implementation instead of
%%% re-deriving it (the bug only ever got fixed in one of six setups).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_test_registry).

-export([ensure/0, ensure_fresh/0]).

%% Tables owned by the registry gen_server (see yuzu_gw_registry:init/1).
-define(AGENTS_TABLE,  yuzu_gw_agents).
-define(PENDING_TABLE, yuzu_gw_pending).
-define(SESSIONS_TABLE, yuzu_gw_sessions).

-define(START_RETRIES,    20).
-define(REAP_TIMEOUT_MS, 1000).
-define(RETRY_BACKOFF_MS,  25).

%% @doc Idempotently ensure the `yuzu_gw' pg scope and a real
%% `yuzu_gw_registry' are up under the registered name, reusing a live
%% registry when one is present. Safe to call from every registry-using
%% test module's `setup/0'. Returns `ok'.
-spec ensure() -> ok.
ensure() ->
    ensure_pg(),
    case whereis(yuzu_gw_registry) of
        undefined ->
            start_fresh(?START_RETRIES);
        Existing ->
            case proc_lib:initial_call(Existing) of
                {gen_server, init_it, _} ->
                    %% A real registry from an earlier module — reuse it.
                    ok;
                _NotAGenServer ->
                    %% A mock_loop impostor (#336) — evict and replace.
                    evict(Existing),
                    start_fresh(?START_RETRIES)
            end
    end.

%% @doc Like `ensure/0' but always replaces any existing registry with a
%% brand-new one. Use where a suite must not inherit a shared registry's
%% monitor/DOWN backlog (`yuzu_gw_scale_tests'). Returns `ok'.
-spec ensure_fresh() -> ok.
ensure_fresh() ->
    ensure_pg(),
    case whereis(yuzu_gw_registry) of
        undefined -> ok;
        Existing  -> evict(Existing)
    end,
    start_fresh(?START_RETRIES).

%%%===================================================================
%%% Internal
%%%===================================================================

ensure_pg() ->
    case whereis(yuzu_gw) of
        undefined -> pg:start_link(yuzu_gw);
        _         -> ok
    end,
    ok.

%% A kill signal travels down every link the target process still holds, and a
%% registry started by an earlier module's fixture process is linked to that
%% (possibly still running) process: killing it cancels that module's tests.
%% So a real registry is first stopped with a normal exit reason, which a
%% non-trapping linked process ignores. The kill remains the fallback for a
%% process that is not a gen_server (the #336 `mock_loop' impostor) or that
%% does not stop in time.
evict(Pid) ->
    catch unlink(Pid),
    catch unregister(yuzu_gw_registry),
    case started_by_proc_lib(Pid) of
        true ->
            try gen_server:stop(Pid, normal, 1000)
            catch _:_ -> catch exit(Pid, kill)
            end;
        false ->
            catch exit(Pid, kill)
    end,
    ok.

%% True for a process started through proc_lib (every OTP behaviour, so the
%% real registry); false for a plain `spawn' such as the `mock_loop' impostor,
%% which would swallow the stop request and only burn the timeout.
started_by_proc_lib(Pid) ->
    proc_lib:initial_call(Pid) =/= false.

%% `start_link' can race a dying registry that still owns the named ETS
%% tables; the fresh `init/1' then crashes with a `{badarg, ...}' EXIT
%% propagated through the link. Trap exits so that crash arrives as a
%% drainable message rather than killing us, wait the tables out, and
%% retry a bounded number of times.
start_fresh(Retries) ->
    Prev = process_flag(trap_exit, true),
    Result = do_start_fresh(Retries),
    %% Drain any {'EXIT', _, _} left by a failed start_link attempt so the
    %% flag restore doesn't strand a signal in the mailbox.
    drain_exits(),
    process_flag(trap_exit, Prev),
    Result.

do_start_fresh(Retries) when Retries =< 0 ->
    %% Out of retries — make one last attempt and let it surface the real
    %% failure rather than loop silently.
    {ok, _} = yuzu_gw_registry:start_link(),
    ok;
do_start_fresh(Retries) ->
    %% Wait out any orphaned-but-not-yet-reaped registry that still owns
    %% the named tables — once they are gone, start_link is clean.
    _ = wait_until(fun() ->
        ets:info(?AGENTS_TABLE, size) =:= undefined andalso
        ets:info(?PENDING_TABLE, size) =:= undefined andalso
        ets:info(?SESSIONS_TABLE, size) =:= undefined
    end, ?REAP_TIMEOUT_MS),
    case yuzu_gw_registry:start_link() of
        {ok, _Pid} ->
            ok;
        {error, {already_started, _Pid}} ->
            %% Another process won the race with a real registry — fine.
            ok;
        {error, _Reason} ->
            %% Orphan still alive (tables not yet reaped) — drain its
            %% EXIT, back off, retry.
            drain_exits(),
            timer:sleep(?RETRY_BACKOFF_MS),
            do_start_fresh(Retries - 1)
    end.

drain_exits() ->
    receive {'EXIT', _, _} -> drain_exits()
    after 0 -> ok
    end.

%% Poll Pred every 10ms until it returns true or Timeout elapses.
wait_until(Pred, Timeout) when Timeout =< 0 ->
    case Pred() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Pred, Timeout) ->
    case Pred() of
        true  -> ok;
        false ->
            timer:sleep(10),
            wait_until(Pred, Timeout - 10)
    end.
