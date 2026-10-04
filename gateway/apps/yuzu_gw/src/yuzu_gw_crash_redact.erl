%%%-------------------------------------------------------------------
%%% @doc Logger primary filter that keeps registration credentials out of the
%%% crash reports of yuzu_gw_upstream (#1197).
%%%
%%% The upstream's replay queue and its mailbox hold stored or in-flight
%%% RegisterRequests (enrollment_token, machine_certificate, csr_pem).
%%% yuzu_gw_upstream:format_status/1 redacts what OTP passes through that
%%% callback, but three things reach the log from raw data outside it:
%%%   - the `messages' (the whole mailbox) and the `error_info' exception of
%%%     the proc_lib CRASH REPORT;
%%%   - the stacktrace gen_server appends to its own terminate report, whose
%%%     frames carry the argument lists of the failing calls;
%%%   - the `reason' of the supervisor report that names the child.
%%% This filter rewrites those events before any handler sees them:
%%%   - proc_lib crash report of the upstream: `messages' becomes
%%%     {redacted, Count}; `dictionary' likewise; `error_info' keeps its class,
%%%     with the reason and stacktrace reduced by yuzu_gw_upstream's
%%%     redact_why/1 and redact_stack/1 (the functions format_status uses: one
%%%     implementation, not a copy);
%%%   - gen_server terminate report of the upstream: `reason' through
%%%     yuzu_gw_upstream:redact_reason/1;
%%%   - supervisor report whose offender id is the upstream (child_terminated
%%%     and the other reports that carry a reason): `reason' likewise.
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
%%% Installed by yuzu_gw_app on start and removed on stop. A yuzu_gw_upstream
%%% used without the application (a test, a shell) is NOT covered.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_crash_redact).

-export([install/0, remove/0, filter/2]).

-define(FILTER_ID, yuzu_gw_crash_redact).
-define(UPSTREAM, yuzu_gw_upstream).

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
    case is_upstream_proc(ProcInfo) of
        true  -> Event#{msg := {report, R#{report := [redact_proc(ProcInfo) | Rest]}}};
        false -> Event
    end;
rewrite(#{msg := {report, #{label := {gen_server, terminate}, name := ?UPSTREAM,
                            reason := Reason} = R}} = Event) ->
    Event#{msg := {report, R#{reason := ?UPSTREAM:redact_reason(Reason)}}};
rewrite(#{msg := {report, #{label := {supervisor, _}, report := Props} = R}} = Event)
  when is_list(Props) ->
    case is_upstream_offender(Props) andalso lists:keymember(reason, 1, Props) of
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
%% process is the upstream when it is registered under that name, or was
%% started by its init/1 (the name can already be gone).
is_upstream_proc(ProcInfo) ->
    lists:keyfind(registered_name, 1, ProcInfo) =:= {registered_name, ?UPSTREAM}
        orelse case lists:keyfind(initial_call, 1, ProcInfo) of
                   {initial_call, {?UPSTREAM, init, _}} -> true;
                   _                                    -> false
               end.

is_upstream_offender(Props) ->
    case lists:keyfind(offender, 1, Props) of
        {offender, Offender} when is_list(Offender) ->
            lists:keyfind(id, 1, Offender) =:= {id, ?UPSTREAM};
        _ ->
            false
    end.

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
