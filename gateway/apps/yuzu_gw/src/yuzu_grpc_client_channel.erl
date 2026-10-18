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
%%%   {config_error, Problems} present while the most recent attempt failed because
%%%                            the TLS options are unusable (config_error/1); the
%%%                            row is deleted when a connection comes up
%%%   {server_max_streams, Cap} the concurrent streams the server allows on the
%%%                            channel's connections together (server_capacity/1)
%%%
%%% The server's stream limit. RFC 9113 6.5.2: a server declares
%%% SETTINGS_MAX_CONCURRENT_STREAMS in the SETTINGS frame that starts the
%%% connection and may change it at any time (6.5); 5.1.2: the client must not
%%% open more streams than that, and gun refuses a request past it locally
%%% (`too_many_streams'). Every connection is opened with gun's
%%% notify_settings_changed, so gun tells this process the server's settings on
%%% the first SETTINGS frame and on every later one. The channel keeps each
%%% current connection's limit and publishes the sum (`Cap', the row above):
%%% `none' while no current connection has declared one (none is up yet), or
%%% while any of them declares none (RFC 9113: no limit); otherwise the sum of
%%% the declared values. A connection that goes down or is retired leaves the
%%% sum. Each change is passed to yuzu_gw_upstream_regulator, which sizes the
%%% gateway's upstream permits from it. The sum is right only for ONE
%%% connection: gun enforces the limit per connection and pick/2 is
%%% round-robin, so keep pool_size 1 and one endpoint (the shipped default; see
%%% the regulator's module doc and #6057, which also covers the redial window
%%% before the new connection's SETTINGS, and the `none' a killed channel never
%%% sends from terminate/2).
%%%
%%% A call finding no connection up waits on one that is connecting (at most its
%%% own timeout); if none is, it fails at once with the last connection error,
%%% so a dead server is answered in microseconds and the circuit breaker above
%%% sees it, instead of every call waiting out its timeout.
%%%
%%% A connection the server is closing (GOAWAY) is retired as soon as a caller
%%% reports it (retire/2, from yuzu_grpc_client): it is no longer handed out,
%%% the calls already on it finish, and its slot is redialled at once, the way a
%%% lost connection's is (failed/3). Without this the slot kept handing out the
%%% closing connection, whose new calls gun refuses, until gun closed it
%%% (closing_timeout, 3 s).
%%%
%%% Nothing here logs a reason term: the exit reason of a connection can carry
%%% socket and TLS details, and a log line carries a word instead (`word/1').
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_channel).
-behaviour(gen_server).

-export([child_spec/1, start_link/1, pick/2, retire/2, max_receive/1, config_error/1,
         server_capacity/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, format_status/1]).
-export([compact/1, word/1, backoff_ms/1]).

-define(BACKOFF_BASE_MS, 100).
-define(BACKOFF_MAX_MS, 5000).
%% A connection that has stayed up this long is healthy: only then does the backoff
%% start over. Resetting at the moment it comes up lets a server that accepts and
%% closes (or a middlebox resetting after the handshake) draw a reconnect every
%% 100 ms per slot, each with a TLS handshake.
-define(STABLE_MS, 5000).
%% The unusable-TLS-options error line is repeated no more often than this.
-define(CONFIG_LOG_EVERY_MS, 60000).

-record(slot, {id :: pos_integer(),
               endpoint :: yuzu_grpc_client_config:endpoint(),
               pid :: pid() | undefined,
               fails = 0 :: non_neg_integer(),
               timer :: reference() | undefined}).

-record(st, {name :: atom(),
             cfg :: yuzu_grpc_client_config:channel(),
             slots = #{} :: #{pos_integer() => #slot{}},
             %% every connection this process owns: the slot it serves, or
             %% {retired, Slot} for one that is closing (retire/2) and is only
             %% waited out (its end is not a failure of the slot)
             by_pid = #{} :: #{pid() => pos_integer() | {retired, pos_integer()}},
             %% callers of await_up waiting for a connection that is being opened,
             %% each with the monotonic ms at which it stops waiting (an expired
             %% caller has already given up; its entry is dropped, never answered)
             waiters = [] :: [{gen_server:from(), integer()}],
             %% monotonic ms of the last unusable-TLS-options error log line. Last in
             %% the record: the backoff tests read the fields above by position.
             config_logged_at :: integer() | undefined,
             %% the SETTINGS_MAX_CONCURRENT_STREAMS each current slot connection
             %% declared (gun's settings_changed notification), by connection
             streams = #{} :: #{pid() => non_neg_integer() | infinity}}).

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
%% `Timeout' ms, and only for a connection that is already being opened; if none
%% is, it answers at once with the last connection error. The channel can die
%% at any moment (its table goes with it), so every table read is inside the one
%% `catch': the answer is then `no_channel', never a `badarg' for the caller.
-spec pick(atom(), non_neg_integer()) -> {ok, pid()} | {error, term()}.
pick(Name, Timeout) ->
    try
        case ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}]) of
            [] ->
                wait_for_connection(Name, Timeout);
            Pids ->
                Counter = ets:lookup_element(Name, rr, 2),
                ok = counters:add(Counter, 1, 1),
                {ok, lists:nth(counters:get(Counter, 1) rem length(Pids) + 1, Pids)}
        end
    catch
        error:badarg -> {error, no_channel}
    end.

%% @doc A caller found that connection `Conn' is going away (the server sent
%% GOAWAY): stop handing it out and open its replacement. A cast; a connection
%% that is not (or no longer) a slot's current one is ignored, so any number of
%% callers may report the same connection.
-spec retire(atom(), pid()) -> ok.
retire(Name, Conn) when is_pid(Conn) ->
    gen_server:cast(Name, {retire, Conn}).

%% @doc `none' while the channel's connections can be tried, or the problems
%% found while its most recent attempt failed because the TLS options are
%% unusable: the list may be empty (the options are unusable for a reason that is
%% not one of the files). Read by /readyz; reads a table row, never the channel.
-spec config_error(atom()) -> none | [yuzu_gw_tls_files:problem()].
config_error(Name) ->
    try ets:lookup_element(Name, config_error, 2)
    catch error:badarg -> none
    end.

%% @doc The concurrent streams the server allows on the channel's current
%% connections together, as they declared it (see the module doc), or `none'
%% when nothing is known or the server declared no limit. A table read.
-spec server_capacity(atom()) -> non_neg_integer() | none.
server_capacity(Name) ->
    try ets:lookup_element(Name, server_max_streams, 2)
    catch error:badarg -> none
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
compact({error, Reason}) -> compact(Reason);
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
%% 5 s, then 80% to 100% of that, so a restarted server is not met by every
%% gateway at the same instant and the delay never exceeds the 5 s cap (a
%% jitter added on top of the cap reached 5.8 s).
-spec backoff_ms(non_neg_integer()) -> pos_integer().
backoff_ms(Fails) ->
    Base = min(?BACKOFF_MAX_MS, ?BACKOFF_BASE_MS * (1 bsl min(Fails, 6))),
    Base - (rand:uniform(max(1, Base div 5)) - 1).

%%--------------------------------------------------------------------
%% gen_server
%%--------------------------------------------------------------------

%% Every callback runs under guard/1: an exception here would leave through
%% OTP's own terminate report, whose reason and stacktrace carry the argument
%% lists of the failing calls (the endpoint and TLS option lists, with the key
%% and certificate file paths) and whose registered name is an arbitrary channel
%% name no crash filter can match. The channel leaves with its class alone.
init(Cfg) ->
    try do_init(Cfg)
    catch Class:_ -> {stop, {channel_failed, Class}}
    end.

do_init(#{name := Name, endpoints := Endpoints, pool_size := Size,
          max_receive_message_bytes := Max} = Cfg) ->
    process_flag(trap_exit, true),
    Name = ets:new(Name, [named_table, protected, set, {read_concurrency, true}]),
    true = ets:insert(Name, [{rr, counters:new(1, [write_concurrency])},
                             {max_receive, Max}, {last_error, no_connection_yet},
                             {server_max_streams, none}]),
    Ids = lists:seq(1, length(Endpoints) * Size),
    Slots = maps:from_list(
              [{Id, #slot{id = Id, endpoint = lists:nth((Id - 1) rem length(Endpoints) + 1,
                                                        Endpoints),
                          pid = undefined}} || Id <- Ids]),
    State0 = #st{name = Name, cfg = Cfg, slots = Slots},
    {ok, lists:foldl(fun(Id, S) -> open(Id, S) end, State0, Ids)}.

%% A caller that found no connection up while one is being opened. Only this
%% process can learn a connection came up (gun sends gun_up to its owner), so the
%% caller waits on a reply from here, not on the connection itself.
handle_call(Request, From, State) ->
    guard(fun() -> do_call(Request, From, State) end).

do_call({await_up, Timeout}, From, #st{name = Name} = State) ->
    case up_pids(Name) of
        [Pid | _] ->
            {reply, {ok, Pid}, State};
        [] ->
            case connecting(Name) of
                true  ->
                    Now = erlang:monotonic_time(millisecond),
                    Live = [W || {_, Deadline} = W <- State#st.waiters, Deadline > Now],
                    {noreply, State#st{waiters = [{From, Now + Timeout} | Live]}};
                false ->
                    {reply, last_error(Name), State}
            end
    end;
do_call(_Request, _From, State) ->
    {reply, {error, unsupported}, State}.

handle_cast(Msg, State) ->
    guard(fun() -> do_cast(Msg, State) end).

do_cast({retire, Pid}, #st{slots = Slots, by_pid = ByPid} = State) ->
    case maps:find(Pid, ByPid) of
        {ok, Id} when is_integer(Id) ->
            %% The slot's current connection: it stays linked and is waited out
            %% (gun ends it once its streams are done, or after closing_timeout),
            %% and the slot is redialled as for a loss: at once the first time,
            %% with backoff if its connections keep going away before they were
            %% stable.
            Slot = maps:get(Id, Slots),
            State1 = forget_streams(Pid, State#st{slots = Slots#{Id := Slot#slot{pid = undefined}},
                                                  by_pid = ByPid#{Pid := {retired, Id}}}),
            {noreply, failed(Id, goaway, State1)};
        _ ->
            {noreply, State}
    end;
do_cast(_Msg, State) ->
    {noreply, State}.

handle_info(Info, State) ->
    guard(fun() -> do_info(Info, State) end).

guard(Fun) ->
    try Fun()
    catch Class:_ -> exit({channel_failed, Class})
    end.

do_info({gun_up, Pid, _Protocol}, #st{by_pid = ByPid} = State) ->
    case maps:find(Pid, ByPid) of
        {ok, Id} when is_integer(Id) ->
            erlang:send_after(?STABLE_MS, self(), {stable, Id, Pid}),
            true = ets:delete(State#st.name, config_error),
            State1 = mark(Id, up, State#st{config_logged_at = undefined}),
            {noreply, reply_waiters({ok, Pid}, State1)};
        error ->
            {noreply, State}
    end;
do_info({stable, Id, Pid}, #st{slots = Slots} = State) ->
    case maps:find(Id, Slots) of
        {ok, #slot{pid = Pid}} -> {noreply, reset_fails(Id, State)};
        _                      -> {noreply, State}
    end;
do_info({gun_notify, Pid, settings_changed, Settings}, #st{by_pid = ByPid} = State)
  when is_map(Settings) ->
    %% The server's SETTINGS, the first and every later one. Only a slot's
    %% current connection counts: a retired one takes no new calls.
    case maps:find(Pid, ByPid) of
        {ok, Id} when is_integer(Id) ->
            Max = case maps:get(max_concurrent_streams, Settings, infinity) of
                      N when is_integer(N), N >= 0 -> N;
                      _ -> infinity
                  end,
            {noreply, publish_capacity(State#st{streams = (State#st.streams)#{Pid => Max}})};
        _ ->
            {noreply, State}
    end;
do_info({gun_down, Pid, _Protocol, Reason, _Killed}, State) ->
    {noreply, lost(Pid, Reason, State)};
do_info({gun_error, Pid, _Ref, Reason}, State) when is_pid(Pid) ->
    {noreply, lost(Pid, Reason, State)};
do_info({gun_error, Pid, Reason}, State) when is_pid(Pid) ->
    {noreply, lost(Pid, Reason, State)};
do_info({'EXIT', Pid, Reason}, #st{by_pid = ByPid} = State) ->
    case maps:is_key(Pid, ByPid) of
        true  -> {noreply, lost(Pid, Reason, State)};
        false -> {noreply, State}
    end;
do_info({reconnect, Id}, #st{slots = Slots} = State) ->
    case maps:find(Id, Slots) of
        {ok, #slot{pid = undefined}} -> {noreply, open(Id, State)};
        _                            -> {noreply, State}
    end;
do_info(_Other, State) ->
    {noreply, State}.

terminate(_Reason, #st{name = Name, slots = Slots, by_pid = ByPid}) ->
    %% The slots' connections and the retired ones still being waited out.
    _ = [close_conn(P) || #slot{pid = P} <- maps:values(Slots), is_pid(P)],
    _ = [close_conn(P) || {P, {retired, _}} <- maps:to_list(ByPid)],
    %% Their stream limits go with them (the table goes with this process).
    yuzu_gw_upstream_regulator:server_capacity(Name, none),
    ok.

%% What a crash report or sys:get_status shows of this process: the shape, not
%% the endpoint and TLS option lists (they name key and certificate files).
format_status(#{state := #st{name = Name, slots = Slots, waiters = Waiters}} = Status) ->
    Status#{state := #{channel => Name, slots => maps:size(Slots), waiters => length(Waiters)}};
format_status(Status) ->
    Status.

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
             domain_lookup_timeout => Timeout,
             %% Liveness: a PING every 45 s, the connection closed when two go
             %% unanswered (about 90 s to notice a peer that stopped answering
             %% without a FIN or RST; the kernel alone takes about 15 minutes).
             %% The interval must stay above the C++ server's 30 s floor for
             %% pings without data (GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS):
             %% a faster client draws GOAWAY too_many_pings. After a GOAWAY gun
             %% keeps the connection for closing_timeout so in-flight calls
             %% finish, and fails new requests on it meanwhile: 3 s, not the 15 s
             %% default (a call takes at most 5 s), then gun_down and the slot is
             %% redialled.
             %% notify_settings_changed: gun sends this process the server's
             %% SETTINGS (the first frame and every change), so the channel knows
             %% the server's concurrent-stream limit (see the module doc).
             http2_opts => #{keepalive => 45000, keepalive_tolerance => 1,
                             closing_timeout => 3000, notify_settings_changed => true},
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
%% closes), kept unless the operator set them, and SO_KEEPALIVE; gun adds binary,
%% {active,false} and {packet,raw} itself.
socket_opts(Tcp) ->
    Defaults = [{send_timeout, 15000}, {send_timeout_close, true}, {keepalive, true}],
    Tcp ++ [D || {Key, _} = D <- Defaults, not proplists:is_defined(Key, Tcp)].

lost(Pid, Reason, #st{slots = Slots, by_pid = ByPid} = State) ->
    case maps:find(Pid, ByPid) of
        {ok, {retired, _Id}} ->
            %% A retired connection has closed: its slot was redialled already.
            close_conn(Pid),
            State#st{by_pid = maps:remove(Pid, ByPid)};
        {ok, Id} ->
            close_conn(Pid),
            Slot = maps:get(Id, Slots),
            State1 = forget_streams(Pid, State#st{slots = Slots#{Id := Slot#slot{pid = undefined}},
                                                  by_pid = maps:remove(Pid, ByPid)}),
            failed(Id, Reason, State1);
        error ->
            State
    end.

%% A slot is down: record why, schedule the reopen.
failed(Id, Reason, #st{name = Name, slots = Slots} = State0) ->
    Compact = compact(Reason),
    Word = word(Compact),
    #slot{fails = Fails} = Slot = maps:get(Id, Slots),
    true = ets:insert(Name, {last_error, Compact}),
    State = unusable_options(Compact, Slot, State0),
    case Fails of
        0 ->
            %% The first loss of a healthy connection: dial again at once. The
            %% slot goes straight to `connecting', so a caller arriving now waits
            %% for it (await_up) instead of failing; each failed call counts
            %% toward the caller's circuit breaker, and a backoff here turned a
            %% 100 ms blip into 5 failures and a 10 s outage.
            logger:info("Upstream channel ~s connection ~b down (~s); reconnecting",
                        [Name, Id, Word]),
            open(Id, State#st{slots = Slots#{Id := Slot#slot{fails = 1, pid = undefined}}});
        _ ->
            true = ets:insert(Name, {{slot, Id}, undefined, down}),
            Delay = backoff_ms(Fails),
            logger:info("Upstream channel ~s connection ~b down (~s); retrying in ~b ms",
                        [Name, Id, Word, Delay]),
            Timer = erlang:send_after(Delay, self(), {reconnect, Id}),
            State1 = State#st{slots = Slots#{Id := Slot#slot{fails = Fails + 1, timer = Timer,
                                                             pid = undefined}}},
            case connecting(Name) orelse up_pids(Name) =/= [] of
                true  -> State1;
                false -> reply_waiters({error, Compact}, State1)
            end
    end.

%% The TLS options of an endpoint are unusable: `ssl' rejected the whole option
%% set, which is what a missing, empty or wrong CA, certificate or key file looks
%% like. Every attempt then fails the same way in about two milliseconds, so the
%% reason is looked up (yuzu_gw_tls_files) and put where it can be seen: an ERROR
%% log line (at most one a minute per channel, the first at once, because attempts
%% repeat every 5 s per connection) and the `config_error' row /readyz reads. It
%% is not a stop: the server creates its certificates on first start, possibly
%% after the gateway's, and the next attempt may find them.
unusable_options({options, tls}, #slot{endpoint = Endpoint},
                 #st{name = Name, config_logged_at = At} = State) ->
    Problems = yuzu_gw_tls_files:diagnose_endpoint(Endpoint),
    true = ets:insert(Name, {config_error, Problems}),
    Now = erlang:monotonic_time(millisecond),
    case At =:= undefined orelse Now - At >= ?CONFIG_LOG_EVERY_MS of
        true ->
            logger:error("Upstream channel ~s: the TLS client options cannot be used, so "
                         "every connection fails: ~ts. The gateway keeps retrying and /readyz "
                         "stays 503 until this is fixed (logged at most once a minute).",
                         [Name, problem_text(Problems)]),
            State#st{config_logged_at = Now};
        false ->
            State
    end;
unusable_options(_Other, _Slot, #st{name = Name} = State) ->
    true = ets:delete(Name, config_error),
    State.

problem_text([]) ->
    "none of the files named in the TLS options is missing, empty or unreadable, so check "
    "the other ssl options";
problem_text(Problems) ->
    lists:join("; ", [yuzu_gw_tls_files:describe(P) || P <- Problems]).

%% A connection no longer counts toward the server's capacity.
forget_streams(Pid, #st{streams = Streams} = State) ->
    case maps:is_key(Pid, Streams) of
        true  -> publish_capacity(State#st{streams = maps:remove(Pid, Streams)});
        false -> State
    end.

%% Publish the channel's capacity when it changed (table row, and the
%% regulator).
publish_capacity(#st{name = Name, streams = Streams} = State) ->
    Cap = capacity(maps:values(Streams)),
    case server_capacity(Name) of
        Cap ->
            State;
        _ ->
            true = ets:insert(Name, {server_max_streams, Cap}),
            yuzu_gw_upstream_regulator:server_capacity(Name, Cap),
            State
    end.

%% `none' for no connection or any connection without a limit, else the sum.
capacity([]) -> none;
capacity(Limits) ->
    case lists:member(infinity, Limits) of
        true  -> none;
        false -> lists:sum(Limits)
    end.

reply_waiters(Reply, #st{waiters = Waiters} = State) ->
    Now = erlang:monotonic_time(millisecond),
    _ = [gen_server:reply(From, Reply) || {From, Deadline} <- Waiters, Deadline > Now],
    State#st{waiters = []}.

%% gun:close/1 asks gun's connection supervisor to terminate the child, and an
%% unsupervised connection (supervise => false, see gun_opts/2) is not its child:
%% the call returns {error, not_found} and the process lives on. This process is
%% the connection's parent and its link, so exit/2 with `shutdown' ends it, and
%% unlinking first keeps the dead connection's EXIT out of the mailbox.
close_conn(Pid) ->
    unlink(Pid),
    exit(Pid, shutdown),
    ok.

up_pids(Name) ->
    ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}]).

connecting(Name) ->
    ets:select_count(Name, [{{{slot, '_'}, '_', connecting}, [], [true]}]) > 0.

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

wait_for_connection(Name, Timeout) when Timeout > 0 ->
    try gen_server:call(Name, {await_up, Timeout}, Timeout)
    catch
        exit:{timeout, _} -> {error, timeout};
        exit:_            -> last_error(Name)
    end;
wait_for_connection(Name, _Timeout) ->
    last_error(Name).

last_error(Name) ->
    try {error, ets:lookup_element(Name, last_error, 2)}
    catch error:badarg -> {error, no_channel}
    end.
