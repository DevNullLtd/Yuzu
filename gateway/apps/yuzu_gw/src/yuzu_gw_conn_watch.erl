%%%-------------------------------------------------------------------
%%% @doc Logger primary filter that counts a connection the VM killed for
%%% passing its max_heap_size ceiling (the per-connection memory bound set in
%%% yuzu_grpc_stream_h).
%%%
%%% A process killed by max_heap_size cannot see its own death, and the kill is
%%% a plain `killed' exit indistinguishable at the supervisor from any other, so
%%% the only honest signal is the report the VM emits when the ceiling's
%%% `error_logger' option is set. That report is a logger event whose metadata
%%% carries `error_logger => #{emulator := true, ...}' and whose message format
%%% names "maximum heap size reached". This filter matches exactly that event,
%%% bumps a counter and passes the event on unchanged — it never drops a line and
%%% never rewrites one (yuzu_gw_crash_redact owns redaction; this owns counting).
%%%
%%% The counter carries a fixed reason label only (max_heap_size): a killed
%%% connection's pid or peer would make an unauthenticated peer the source of
%%% metric label cardinality, which is the very thing the memory bound exists to
%%% stop. In this application only yuzu_grpc_stream_h sets a kill ceiling, so a
%%% "maximum heap size reached" kill is a connection it capped.
%%%
%%% Installed by yuzu_gw_app on start and removed on stop, beside
%%% yuzu_gw_crash_redact. The counter is declared and zero-seeded by
%%% yuzu_gw_telemetry so it is visible to increase() before the first kill.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_conn_watch).

-export([install/0, remove/0, filter/2]).

-define(FILTER_ID, yuzu_gw_conn_watch).

%% @doc Add the primary filter. Idempotent: already present is success.
-spec install() -> ok.
install() ->
    case logger:add_primary_filter(?FILTER_ID, {fun ?MODULE:filter/2, []}) of
        ok                          -> ok;
        {error, {already_exist, _}} -> ok
    end.

%% @doc Remove the primary filter. Tolerant: absent is success.
-spec remove() -> ok.
remove() ->
    case logger:remove_primary_filter(?FILTER_ID) of
        ok                      -> ok;
        {error, {not_found, _}} -> ok
    end.

%% @doc The filter callback. Total: never raises, always returns the event
%% unchanged (counting is a side effect, not a decision).
-spec filter(logger:log_event(), term()) -> logger:log_event().
filter(Event, _Extra) ->
    try
        case is_max_heap_kill(Event) of
            true  -> count_kill();
            false -> ok
        end
    catch
        _:_ -> ok
    end,
    Event.

is_max_heap_kill(#{meta := #{error_logger := #{emulator := true}}, msg := Msg}) ->
    max_heap_text(Msg);
is_max_heap_kill(_) ->
    false.

%% The emulator report is a {Format, Args} message; the format string names the
%% condition. A {string, _} or {report, _} emulator message is some other report.
max_heap_text({Format, _Args}) when is_list(Format) ->
    string:find(Format, "maximum heap size reached") =/= nomatch;
max_heap_text(_) ->
    false.

count_kill() ->
    _ = (catch prometheus_counter:inc(yuzu_gw_grpc_connection_killed_total,
                                      [<<"max_heap_size">>], 1)),
    ok.
