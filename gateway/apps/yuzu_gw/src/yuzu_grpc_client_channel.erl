%%%-------------------------------------------------------------------
%%% @doc One upstream channel: a small pool of HTTP/2 connections (gun) to the
%%% server's endpoints, kept open and reopened with backoff.
%%%
%%% The process only OWNS the connections: it opens them, sees them come up and
%%% go down, and reopens them. A call does not pass through it. `pick/2' reads
%%% an ETS table this process maintains and hands the caller a live connection
%%% pid, and the caller sends its request on it (HTTP/2 multiplexes, gun accepts
%%% a request from any process). So one slow call does not queue the others
%%% behind a gen_server, and a busy upstream process never waits on this one.
%%%
%%% Table (named after the channel, `protected', read by every caller):
%%%   {{slot, Id}, Pid | undefined, up | connecting | down}
%%%   {rr, CountersRef}        round-robin position; the table is written only by this
%%%                            process, callers increment the counter, not the table
%%%   {last_error, Compact}    why the most recent connection attempt failed
%%%   {max_receive, Bytes}     the response size limit of the channel
%%%
%%% A call finding no connection up waits on one that is connecting (at most its
%%% own timeout); if none is, it fails at once with the last connection error,
%%% so a dead server is answered in microseconds and the circuit breaker above
%%% sees it, instead of every call waiting out its timeout.
%%%
%%% Nothing here logs a reason term: the exit reason of a connection can carry
%%% socket and TLS details, and a log line carries a word instead (`word/1').
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_channel).
-behaviour(gen_server).

-export([child_spec/1, start_link/1, pick/2, max_receive/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).
-export([compact/1, word/1, backoff_ms/1]).

-define(BACKOFF_BASE_MS, 100).
-define(BACKOFF_MAX_MS, 5000).

-record(slot, {id :: pos_integer(),
               endpoint :: yuzu_grpc_client_config:endpoint(),
               pid :: pid() | undefined,
               fails = 0 :: non_neg_integer(),
               timer :: reference() | undefined}).

-record(st, {name :: atom(),
             cfg :: yuzu_grpc_client_config:channel(),
             slots = #{} :: #{pos_integer() => #slot{}},
             by_pid = #{} :: #{pid() => pos_integer()}}).

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

-spec child_spec(yuzu_grpc_client_config:channel()) -> supervisor:child_spec().
child_spec(#{name := Name} = Cfg) ->
    #{id => {yuzu_grpc_client_channel, Name},
      start => {?MODULE, start_link, [Cfg]},
      restart => permanent,
      shutdown => 5000,
      type => worker}.

-spec start_link(yuzu_grpc_client_config:channel()) -> gen_server:start_ret().
start_link(#{name := Name} = Cfg) ->
    gen_server:start_link({local, Name}, ?MODULE, Cfg, []).

%% @doc A live connection of the channel, or why there is none. Waits at most
%% `Timeout' ms, and only for a connection that is already being opened.
-spec pick(atom(), non_neg_integer()) -> {ok, pid()} | {error, term()}.
pick(Name, Timeout) ->
    try ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}]) of
        [] ->
            wait_for_connection(Name, Timeout);
        Pids ->
            Counter = ets:lookup_element(Name, rr, 2),
            ok = counters:add(Counter, 1, 1),
            {ok, lists:nth(counters:get(Counter, 1) rem length(Pids) + 1, Pids)}
    catch
        error:badarg -> {error, no_channel}
    end.

-spec max_receive(atom()) -> pos_integer().
max_receive(Name) ->
    try ets:lookup_element(Name, max_receive, 2)
    catch error:badarg -> 16 * 1024 * 1024
    end.

%% @doc A connection failure as a small term, never the term itself: an atom for
%% a socket error, `{tls_alert, Alert}' for a TLS failure (the shape
%% yuzu_gw_upstream:classify_tls_error/1 reads for its handshake metric),
%% `{options, tls}' for unusable TLS options, `other' for anything else.
-spec compact(term()) -> atom() | {tls_alert, atom()} | {options, tls}.
compact(normal) -> closed;
compact({shutdown, Reason}) -> compact(Reason);
compact({down, Reason}) -> compact(Reason);
compact({tls_alert, {Alert, _}}) when is_atom(Alert) -> {tls_alert, Alert};
compact({tls_alert, Alert}) when is_atom(Alert) -> {tls_alert, Alert};
compact({options, _}) -> {options, tls};
compact(Reason) when is_atom(Reason) -> Reason;
compact(Reason) when is_tuple(Reason), tuple_size(Reason) > 0 ->
    case element(1, Reason) of
        Tag when is_atom(Tag) -> Tag;
        _ -> other
    end;
compact(_) -> other.

%% @doc The one word a log line carries for a compact reason.
-spec word(term()) -> atom().
word({tls_alert, Alert}) -> Alert;
word({options, tls}) -> bad_tls_options;
word(Reason) when is_atom(Reason) -> Reason;
word(_) -> other.

%% @doc Delay before reconnect attempt `Fails' (0-based): 100 ms doubling to
%% 5 s, with up to 20% jitter so a restarted server is not met by every
%% gateway at the same instant.
-spec backoff_ms(non_neg_integer()) -> pos_integer().
backoff_ms(Fails) ->
    Base = min(?BACKOFF_MAX_MS, ?BACKOFF_BASE_MS * (1 bsl min(Fails, 6))),
    Base + rand:uniform(max(1, Base div 5)) - 1.

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------

init(#{name := Name, endpoints := Endpoints, pool_size := Size,
       max_receive_message_bytes := Max} = Cfg) ->
    process_flag(trap_exit, true),
    Name = ets:new(Name, [named_table, protected, set, {read_concurrency, true}]),
    true = ets:insert(Name, [{rr, counters:new(1, [write_concurrency])},
                             {max_receive, Max}, {last_error, no_connection_yet}]),
    Ids = lists:seq(1, length(Endpoints) * Size),
    Slots = maps:from_list(
              [{Id, #slot{id = Id, endpoint = lists:nth((Id - 1) rem length(Endpoints) + 1,
                                                        Endpoints),
                          pid = undefined}} || Id <- Ids]),
    State0 = #st{name = Name, cfg = Cfg, slots = Slots},
    {ok, lists:foldl(fun(Id, S) -> open(Id, S) end, State0, Ids)}.

handle_call(_Request, _From, State) ->
    {reply, {error, unsupported}, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({gun_up, Pid, _Protocol}, #st{by_pid = ByPid} = State) ->
    case maps:find(Pid, ByPid) of
        {ok, Id} -> {noreply, mark(Id, up, reset_fails(Id, State))};
        error    -> {noreply, State}
    end;
handle_info({gun_down, Pid, _Protocol, Reason, _Killed}, State) ->
    {noreply, lost(Pid, Reason, State)};
handle_info({gun_error, Pid, _Ref, Reason}, State) when is_pid(Pid) ->
    {noreply, lost(Pid, Reason, State)};
handle_info({gun_error, Pid, Reason}, State) when is_pid(Pid) ->
    {noreply, lost(Pid, Reason, State)};
handle_info({'EXIT', Pid, Reason}, #st{by_pid = ByPid} = State) ->
    case maps:is_key(Pid, ByPid) of
        true  -> {noreply, lost(Pid, Reason, State)};
        false -> {noreply, State}
    end;
handle_info({reconnect, Id}, #st{slots = Slots} = State) ->
    case maps:find(Id, Slots) of
        {ok, #slot{pid = undefined}} -> {noreply, open(Id, State)};
        _                            -> {noreply, State}
    end;
handle_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #st{slots = Slots}) ->
    _ = [gun:close(P) || #slot{pid = P} <- maps:values(Slots), is_pid(P)],
    ok.

%%--------------------------------------------------------------------
%% Connections
%%--------------------------------------------------------------------

open(Id, #st{cfg = Cfg, slots = Slots, by_pid = ByPid} = State) ->
    #slot{endpoint = #{host := Host, port := Port} = Endpoint} = Slot = maps:get(Id, Slots),
    case gun:open(Host, Port, gun_opts(Endpoint, Cfg)) of
        {ok, Pid} ->
            Slot1 = Slot#slot{pid = Pid, timer = undefined},
            State1 = State#st{slots = Slots#{Id := Slot1}, by_pid = ByPid#{Pid => Id}},
            mark(Id, connecting, State1);
        {error, Reason} ->
            failed(Id, Reason, State)
    end.

%% The socket options go in gun's `tcp_opts' for BOTH transports: gun opens the
%% TCP socket from them and, for TLS, upgrades that same socket, so an option in
%% `tls_opts' (an ssl option list) never reaches it. TCP_NODELAY set only in
%% `tls_opts' was ignored, which left every upstream call to a TLS server waiting
%% about 43 ms for Nagle's algorithm to meet the server's delayed ACK.
gun_opts(#{transport := Transport, tcp_opts := Tcp} = Endpoint, #{connect_timeout := Timeout}) ->
    Base = #{protocols => [http2],
             transport => Transport,
             tcp_opts => socket_opts(Tcp),
             connect_timeout => Timeout,
             retry => 0,
             %% gun's default puts the connection under its own supervisor, which
             %% leaves a failed connect unreported: no gun_down (it was never up),
             %% no EXIT (no link) and no way to see it, so a slot would stay
             %% `connecting' for good and never reconnect. Unsupervised, the
             %% connection is linked to this process and its failure arrives as
             %% an EXIT with the reason (econnrefused, a TLS alert).
             supervise => false},
    case Transport of
        tcp -> Base;
        tls -> Base#{tls_opts => maps:get(tls_opts, Endpoint),
                     tls_handshake_timeout => Timeout}
    end.

%% gun's own defaults for the TCP socket (a stuck send gives up after 15 s and
%% closes), kept unless the operator set them; gun adds binary, {active,false}
%% and {packet,raw} itself.
socket_opts(Tcp) ->
    Defaults = [{send_timeout, 15000}, {send_timeout_close, true}],
    Tcp ++ [D || {Key, _} = D <- Defaults, not proplists:is_defined(Key, Tcp)].

lost(Pid, Reason, #st{slots = Slots, by_pid = ByPid} = State) ->
    case maps:find(Pid, ByPid) of
        {ok, Id} ->
            catch gun:close(Pid),
            Slot = maps:get(Id, Slots),
            State1 = State#st{slots = Slots#{Id := Slot#slot{pid = undefined}},
                              by_pid = maps:remove(Pid, ByPid)},
            failed(Id, Reason, State1);
        error ->
            State
    end.

%% A slot is down: record why, schedule the reopen.
failed(Id, Reason, #st{name = Name, slots = Slots} = State) ->
    Compact = compact(Reason),
    Word = word(Compact),
    #slot{fails = Fails} = Slot = maps:get(Id, Slots),
    true = ets:insert(Name, [{{slot, Id}, undefined, down}, {last_error, Compact}]),
    Delay = backoff_ms(Fails),
    logger:info("Upstream channel ~s connection ~b down (~s); retrying in ~b ms",
                [Name, Id, Word, Delay]),
    Timer = erlang:send_after(Delay, self(), {reconnect, Id}),
    State#st{slots = Slots#{Id := Slot#slot{fails = Fails + 1, timer = Timer, pid = undefined}}}.

reset_fails(Id, #st{slots = Slots} = State) ->
    Slot = maps:get(Id, Slots),
    State#st{slots = Slots#{Id := Slot#slot{fails = 0}}}.

mark(Id, Status, #st{name = Name, slots = Slots} = State) ->
    #slot{pid = Pid} = maps:get(Id, Slots),
    true = ets:insert(Name, {{slot, Id}, Pid, Status}),
    State.

%%--------------------------------------------------------------------
%% pick/2 helpers
%%--------------------------------------------------------------------

wait_for_connection(Name, Timeout) ->
    case ets:select(Name, [{{{slot, '_'}, '$1', connecting}, [], ['$1']}]) of
        [Pid | _] when Timeout > 0 ->
            case gun:await_up(Pid, Timeout) of
                {ok, _Protocol} -> {ok, Pid};
                {error, _}      -> last_error(Name)
            end;
        _ ->
            last_error(Name)
    end.

last_error(Name) ->
    try {error, ets:lookup_element(Name, last_error, 2)}
    catch error:badarg -> {error, no_channel}
    end.
