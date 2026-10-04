%%%-------------------------------------------------------------------
%%% @doc Logger primary filter that keeps registration credentials out of the
%%% crash reports of the gateway processes that hold a RegisterRequest (#1197).
%%%
%%% Three processes hold or are sent a RegisterRequest (enrollment_token,
%%% machine_certificate, csr_pem):
%%%   - yuzu_gw_upstream: its replay queue and its mailbox;
%%%   - yuzu_gw_agent (one per connected agent): the stored `register_req';
%%%   - yuzu_gw_registry: the `register' call that stores it.
%%% yuzu_gw_router is protected for other data: it is sent the SendCommand
%%% request (plugin parameters, which may be secrets). So is
%%% yuzu_gw_heartbeat_buffer: its mailbox and, in a crash, the stacktrace
%%% arguments hold buffered heartbeats (status tags and fleet snapshots:
%%% telemetry, not credentials).
%%% Each has a format_status/1 that redacts what OTP passes through that
%%% callback, but three things reach the log from raw data outside it:
%%%   - the `messages' (the whole mailbox) and the `error_info' exception of
%%%     the proc_lib CRASH REPORT;
%%%   - the stacktrace OTP appends to its own terminate report, whose frames
%%%     carry the argument lists of the failing calls (for an agent, its whole
%%%     data record; for the registry, the failing handle_call/3 request);
%%%   - the `reason' of the supervisor report that names the child.
%%% This filter rewrites those events before any handler sees them:
%%%   - proc_lib crash report of a protected process: `messages' becomes
%%%     {redacted, Count}; `dictionary' likewise; `error_info' keeps its class,
%%%     with the reason and stacktrace reduced by yuzu_gw_upstream's
%%%     redact_why/1 and redact_stack/1 (the functions its format_status uses:
%%%     one implementation, not a copy);
%%%   - gen_server terminate report of the upstream or the registry, and
%%%     gen_statem terminate report of an agent: `reason' reduced the same way;
%%%   - supervisor report whose offender is a protected process (child_terminated
%%%     and the other reports that carry a reason): `reason' likewise.
%%% A process is protected when it is registered under the name of one of the
%%% modules or was started by that module's init/1 (a crash report still names
%%% it after its name is gone), which covers the unregistered agent processes;
%%% a gen_statem terminate report names its callback module in `modules'; a
%%% supervisor report names the child by its id (upstream, registry) or by the
%%% module in its start spec (agent: its id is the shared word `agent').
%%% Reports of every other process pass through unchanged. Only the first
%%% process of a crash report is rewritten; the neighbours listed after it are
%%% other processes.
%%%
%%% Failure policy: an exception in the filter must neither leak nor lose the
%%% event. Returning the event unchanged would pass the raw data and `stop'
%%% would drop the line, so the event is kept with its message replaced by a
%%% fixed text that names no data (and the report callbacks, which would try to
%%% format that text as a report, are removed from its metadata).
%%%
%%% Installed by yuzu_gw_app on start and removed on stop. These processes used
%%% without the application (a test, a shell) are NOT covered.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_crash_redact).

-export([install/0, remove/0, filter/2]).

-define(FILTER_ID, yuzu_gw_crash_redact).
-define(UPSTREAM, yuzu_gw_upstream).
%% The modules whose processes are protected: the callback modules of the
%% upstream client, the agent state machine, the registry, the command router
%% (its mailbox holds SendCommand requests, whose plugin parameters may be
%% secrets) and the heartbeat buffer (fleet telemetry: status tags and snapshots).
-define(PROTECTED, [yuzu_gw_upstream, yuzu_gw_agent, yuzu_gw_registry,
                    yuzu_gw_router, yuzu_gw_heartbeat_buffer]).

%% @doc Add the primary filter. Idempotent: already present is success.
-spec install() -> ok.
install() ->
    case logger:add_primary_filter(?FILTER_ID, {fun ?MODULE:filter/2, []}) of
        ok                           -> ok;
        {error, {already_exist, _}}  -> ok
    end.

%% @doc Remove the primary filter. Tolerant: absent is success.
-spec remove() -> ok.
remove() ->
    case logger:remove_primary_filter(?FILTER_ID) of
        ok                      -> ok;
        {error, {not_found, _}} -> ok
    end.

%% @doc The filter callback. Total: never raises, never returns stop/ignore.
-spec filter(logger:log_event(), term()) -> logger:log_event().
filter(Event, _Extra) ->
    try
        rewrite(Event)
    catch
        _:_ -> withheld(Event)
    end.

%%%===================================================================
%%% Internal
%%%===================================================================

rewrite(#{msg := {report, #{label := {proc_lib, crash}, report := [ProcInfo | Rest]} = R}} = Event)
  when is_list(ProcInfo) ->
    case is_protected_proc(ProcInfo) of
        true  -> Event#{msg := {report, R#{report := [redact_proc(ProcInfo) | Rest]}}};
        false -> Event
    end;
rewrite(#{msg := {report, #{label := {gen_server, terminate}, name := Name,
                            reason := Reason} = R}} = Event) ->
    case is_protected_name(Name) of
        true  -> Event#{msg := {report, R#{reason := ?UPSTREAM:redact_reason(Reason)}}};
        false -> Event
    end;
rewrite(#{msg := {report, #{label := {gen_statem, terminate}, modules := Modules,
                            reason := Reason} = R}} = Event) when is_list(Modules) ->
    case lists:any(fun is_protected_module/1, Modules) of
        true  -> Event#{msg := {report, R#{reason := redact_statem_reason(Reason)}}};
        false -> Event
    end;
rewrite(#{msg := {report, #{label := {supervisor, _}, report := Props} = R}} = Event)
  when is_list(Props) ->
    case is_protected_offender(Props) andalso lists:keymember(reason, 1, Props) of
        true ->
            Reason = element(2, lists:keyfind(reason, 1, Props)),
            Props1 = lists:keyreplace(reason, 1, Props,
                                      {reason, ?UPSTREAM:redact_reason(Reason)}),
            Event#{msg := {report, R#{report := Props1}}};
        false ->
            Event
    end;
rewrite(Event) ->
    Event.

%% A crash report's first element is the crashed process's proplist. The
%% process is protected when it is registered under a protected module's name,
%% or was started by that module's init/1 (the name can already be gone, and an
%% agent process never had one).
is_protected_proc(ProcInfo) ->
    case lists:keyfind(registered_name, 1, ProcInfo) of
        {registered_name, Name} when is_atom(Name), Name =/= [] ->
            is_protected_name(Name) orelse initial_call_protected(ProcInfo);
        _ ->
            initial_call_protected(ProcInfo)
    end.

initial_call_protected(ProcInfo) ->
    case lists:keyfind(initial_call, 1, ProcInfo) of
        {initial_call, {Module, init, _}} -> is_protected_module(Module);
        _                                 -> false
    end.

%% The registered names of the protected modules are their module names.
is_protected_name(Name) -> is_protected_module(Name).

is_protected_module(Module) -> lists:member(Module, ?PROTECTED).

%% The offender of a supervisor report: the child id is the module name for the
%% upstream and the registry; the agent supervisor's id is `agent', so the
%% module of the start spec decides.
is_protected_offender(Props) ->
    case lists:keyfind(offender, 1, Props) of
        {offender, Offender} when is_list(Offender) ->
            case lists:keyfind(id, 1, Offender) of
                {id, Id} when is_atom(Id) ->
                    is_protected_module(Id) orelse mfargs_protected(Offender);
                _ ->
                    mfargs_protected(Offender)
            end;
        _ ->
            false
    end.

mfargs_protected(Offender) ->
    case lists:keyfind(mfargs, 1, Offender) of
        {mfargs, {Module, _, _}} -> is_protected_module(Module);
        _                        -> false
    end.

%% A gen_statem terminate reason is an atom or {Class, Reason, Stacktrace}.
redact_statem_reason(Reason) when is_atom(Reason) -> Reason;
redact_statem_reason({Class, Why, Stack}) when is_atom(Class) ->
    {Class, ?UPSTREAM:redact_why(Why), ?UPSTREAM:redact_stack(Stack)};
redact_statem_reason(_Other) ->
    '$redacted'.

redact_proc(ProcInfo) ->
    [redact_item(Item) || Item <- ProcInfo].

redact_item({messages, Msgs}) when is_list(Msgs) -> {messages, {redacted, length(Msgs)}};
redact_item({messages, _})                       -> {messages, '$redacted'};
redact_item({dictionary, Dict}) when is_list(Dict) -> {dictionary, {redacted, length(Dict)}};
redact_item({dictionary, _})                     -> {dictionary, '$redacted'};
redact_item({error_info, {Class, Reason, Stack}}) ->
    {error_info, {Class, ?UPSTREAM:redact_why(Reason), ?UPSTREAM:redact_stack(Stack)}};
redact_item({error_info, _})                     -> {error_info, '$redacted'};
redact_item(Item)                                -> Item.

%% The event as it can safely be shown after the filter itself failed.
withheld(#{meta := Meta} = Event) when is_map(Meta) ->
    Event#{msg := {string, "yuzu_gw crash report redaction failed; event content withheld"},
           meta := maps:without([report_cb, error_logger], Meta)};
withheld(Event) when is_map(Event) ->
    Event#{msg => {string, "yuzu_gw crash report redaction failed; event content withheld"}};
withheld(Other) ->
    %% Not a log event at all: nothing of ours in it to leak.
    Other.
