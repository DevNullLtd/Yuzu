%%%-------------------------------------------------------------------
%%% @doc The gateway's runtime metrics (#5695, METRICS workstream): what the
%%% periodic sampler (yuzu_gw_gauge) reports, what the gRPC layer counts when
%%% Cowboy closes a connection itself, and that each event reaches its
%%% Prometheus family with only closed label values.
%%%
%%%   sampler      mailbox length and queue wait of a FIXED list of named
%%%                processes (here a test process suspended with messages
%%%                queued), connections against max_connections per listener,
%%%                handler processes on the management listener, ports and
%%%                their limits, the run queue
%%%   closes       a Cowboy idle_timeout and a cancel flood (enhance_your_calm)
%%%                each counted once per connection, labelled by listener role
%%%   handlers     the events above reach their families; a value outside a
%%%                closed set folds to unknown; every closed series is there at 0
%%%                from the declaration
%%%   log          the "message for an ended stream" warning is limited per
%%%                NODE, not per connection: one timed-out Register per agent
%%%                connection used to write one line each
%%%
%%% Telemetry handlers are attached in the process running the case and
%%% detached in its `after'; the sampler under test is an unregistered yuzu_gw_gauge started
%%% with its own process and listener lists, so no canonical name is touched.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_runtime_metrics_tests).
-include_lib("eunit/include/eunit.hrl").

-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2]).

-define(MGMT_SVC, 'yuzu.server.v1.ManagementService').
-define(AGENT_SVC, 'yuzu.agent.v1.AgentService').
-define(SEND_COMMAND, <<"/yuzu.server.v1.ManagementService/SendCommand">>).
-define(SUBSCRIBE, <<"/yuzu.agent.v1.AgentService/Subscribe">>).
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(BOX, yuzu_gw_runtime_metrics_tests_box).

%%%===================================================================
%%% Sampler
%%%===================================================================

sampler_test_() ->
    {foreach, fun sampler_setup/0, fun sampler_cleanup/1,
     [{timeout, 30, {"a named process's mailbox length and queue wait; an absent "
                     "name reads 0", fun mailbox_and_queue_wait/0}},
      {timeout, 30, {"connections and the ceiling of a listener, by listener role",
                     fun listener_connections/0}},
      {timeout, 30, {"handler processes on the management listener's connections",
                     fun mgmt_streams/0}},
      {timeout, 30, {"ports, the port and file descriptor limits, the run queue",
                     fun ports_and_run_queue/0}},
      {"the production process list is fixed and its labels are the closed set",
       fun production_process_list/0}]}.

sampler_setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_edge_stub_svc:init(self()),
    yuzu_grpc_stub_svc:init_state(),
    ok.

sampler_cleanup(_) ->
    yuzu_gw_edge_stub_svc:stop(),
    stop_box(),
    ok.

-define(SAMPLER_EVENTS, [[yuzu, gw, process, mailbox],
                         [yuzu, gw, process, queue_wait],
                         [yuzu, gw, listener, connections],
                         [yuzu, gw, mgmt, streams],
                         [yuzu, gw, vm, ports],
                         [yuzu, gw, vm, run_queue]]).

mailbox_and_queue_wait() ->
    {ok, Box} = gen_server:start({local, ?BOX}, ?MODULE, [], []),
    true = erlang:suspend_process(Box),
    [Box ! {queued, I} || I <- lists:seq(1, 25)],
    H = attach(?SAMPLER_EVENTS),
    G = sampler(#{processes => [{box, ?BOX}, {absent, yuzu_gw_runtime_metrics_tests_none}]}),
    try
        ?assertMatch(#{len := 25}, await(mailbox, box, fun(#{len := L}) -> L =:= 25 end)),
        ?assertMatch(#{len := 0}, await(mailbox, absent, fun(_) -> true end)),
        ?assertMatch(#{seconds := 0}, await(queue_wait, absent, fun(_) -> true end)),
        %% suspended: the probe is not answered, and the wait reported grows
        #{seconds := Stuck} = await(queue_wait, box, fun(#{seconds := S}) -> S >= 0.3 end),
        ?assert(Stuck >= 0.3),
        true = erlang:resume_process(Box),
        %% resumed: the probe and the 25 messages ahead of it are handled, and a
        %% later probe finds an empty mailbox
        ?assertMatch(#{seconds := _},
                     await(queue_wait, box, fun(#{seconds := S}) -> S < 0.05 end)),
        ?assertMatch(#{len := 0}, await(mailbox, box, fun(#{len := L}) -> L =:= 0 end))
    after
        stop_sampler(G),
        detach(H)
    end.

listener_connections() ->
    Entry = agent_entry(#{name => rtm_conns, limits => #{max_connections => 7}}),
    {Port, L} = yuzu_gw_test_listener:start(Entry),
    Conns = [open(Port) || _ <- lists:seq(1, 3)],
    H = attach(?SAMPLER_EVENTS),
    G = sampler(#{listeners => [Entry]}),
    try
        ?assertMatch(#{active := 3, max := 7},
                     await(connections, agent, fun(#{active := A}) -> A =:= 3 end))
    after
        stop_sampler(G),
        detach(H),
        [gun:close(C) || {C, _} <- Conns],
        yuzu_gw_test_listener:stop(L)
    end.

mgmt_streams() ->
    Entry = mgmt_entry(#{name => rtm_streams}),
    {Port, L} = yuzu_gw_test_listener:start(Entry),
    {C, _} = open(Port),
    _ = [send_command(C, <<"sleep">>) || _ <- lists:seq(1, 3)],
    H = attach(?SAMPLER_EVENTS),
    G = sampler(#{listeners => [Entry]}),
    try
        ?assertMatch(#{count := 3}, await(streams, undefined, fun(#{count := N}) -> N =:= 3 end)),
        ?assertMatch(#{active := 1},
                     await(connections, management, fun(#{active := A}) -> A =:= 1 end))
    after
        stop_sampler(G),
        detach(H),
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

ports_and_run_queue() ->
    H = attach(?SAMPLER_EVENTS),
    G = sampler(#{}),
    try
        #{count := Ports, limit := Limit} = Ev = await(ports, undefined, fun(_) -> true end),
        ?assert(Ports > 0),
        ?assertEqual(erlang:system_info(port_limit), Limit),
        case maps:get(fd_limit, Ev) of
            undefined -> ok;
            Fds -> ?assert(is_integer(Fds) andalso Fds > 0)
        end,
        #{length := Q} = await(run_queue, undefined, fun(_) -> true end),
        ?assert(is_integer(Q) andalso Q >= 0)
    after
        stop_sampler(G),
        detach(H)
    end.

production_process_list() ->
    Procs = yuzu_gw_gauge:sampled_processes(),
    Labels = [L || {L, _} <- Procs],
    ?assertEqual(lists:usort(Labels), lists:sort(Labels)),
    ?assertEqual([upstream, upstream_regulator, registry, router, heartbeat_buffer,
                  agent_sup, pg, upstream_channel, logger], Labels),
    ?assert(length(Procs) =< 12).

%%%===================================================================
%%% Connections Cowboy closes itself
%%%===================================================================

closes_test_() ->
    {foreach, fun closes_setup/0, fun closes_cleanup/1,
     [{timeout, 30, {"an idle_timeout close of a connection with a stream open is "
                     "counted once, as idle_timeout on its listener",
                     fun idle_timeout_close/0}},
      {timeout, 30, {"a cancel flood closes the connection (enhance_your_calm), counted "
                     "once however many streams it held", fun cancel_flood_close/0}}]}.

closes_setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_edge_stub_svc:init(self()),
    yuzu_grpc_stub_svc:init_state(),
    ok.

closes_cleanup(_) ->
    yuzu_gw_edge_stub_svc:stop(),
    ok.

idle_timeout_close() ->
    Entry = agent_entry(#{name => rtm_idle, http2 => #{idle_timeout => 300}}),
    {Port, L} = yuzu_gw_test_listener:start(Entry),
    H = attach([[yuzu, gw, grpc, connection_closed]]),
    {C, Mon} = open(Port),
    try
        _ = gun:headers(C, <<"POST">>, ?SUBSCRIBE, grpc_headers()),
        receive {'DOWN', Mon, process, C, _} -> ok;
                {gun_down, C, _, _, _} -> ok
        after 10000 -> error(connection_not_closed)
        end,
        ?assertEqual([{agent, idle_timeout, 1}], closes(1000))
    after
        detach(H),
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

cancel_flood_close() ->
    Entry = mgmt_entry(#{name => rtm_flood,
                         http2 => #{max_cancel_stream_rate => {3, 60000}}}),
    {Port, L} = yuzu_gw_test_listener:start(Entry),
    H = attach([[yuzu, gw, grpc, connection_closed]]),
    {C, _Mon} = open(Port),
    try
        %% two streams stay open while the others are cancelled
        _ = [send_command(C, <<"sleep">>) || _ <- lists:seq(1, 2)],
        [gun:cancel(C, send_command(C, <<"sleep">>)) || _ <- lists:seq(1, 6)],
        receive {gun_down, C, _, _, _} -> ok
        after 10000 -> error(connection_not_closed)
        end,
        ?assertEqual([{management, enhance_your_calm, 1}], closes(1000))
    after
        detach(H),
        gun:close(C),
        yuzu_gw_test_listener:stop(L)
    end.

%% The connection_closed events received within Ms, as {listener, reason, count}.
closes(Ms) ->
    receive
        {event, [yuzu, gw, grpc, connection_closed], #{count := N},
         #{listener := Role, reason := Reason}} ->
            [{Role, Reason, N} | closes(Ms)]
    after Ms -> []
    end.

%%%===================================================================
%%% Telemetry handlers and families
%%%===================================================================

handlers_test_() ->
    {setup,
     fun() ->
         {ok, _} = application:ensure_all_started(prometheus),
         {ok, _} = application:ensure_all_started(telemetry),
         catch telemetry:detach(yuzu_gw_prometheus),
         ok = yuzu_gw_telemetry:setup()
     end,
     fun(_) -> catch telemetry:detach(yuzu_gw_prometheus) end,
     [{"every closed series exists from the declaration", fun seeded/0},
      {"the sampler's events reach their families", fun sampler_families/0},
      {"a label outside the closed set folds to unknown", fun folded/0},
      {"an unbounded ceiling removes the max_connections series", fun no_ceiling/0},
      {"a Cowboy close reaches its counter", fun close_counter/0},
      {"the router's fan-outs in flight reach their gauge", fun fanouts_gauge/0}]}.

seeded() ->
    [?assertEqual(0, prometheus_gauge:value(yuzu_gw_process_mailbox_len, [atom_to_binary(L)]))
     || {L, _} <- yuzu_gw_gauge:sampled_processes()],
    [?assertEqual(0, prometheus_gauge:value(yuzu_gw_process_queue_wait_seconds,
                                            [atom_to_binary(L)]))
     || {L, _} <- yuzu_gw_gauge:sampled_processes()],
    [?assertEqual(0, prometheus_gauge:value(yuzu_gw_listener_connections, [R]))
     || R <- [<<"agent">>, <<"management">>, <<"other">>]],
    [?assertEqual(0, prometheus_counter:value(yuzu_gw_grpc_connections_closed_total, [R, C]))
     || R <- [<<"agent">>, <<"management">>, <<"other">>],
        C <- [<<"idle_timeout">>, <<"enhance_your_calm">>, <<"protocol_error">>]],
    ?assertEqual(0, prometheus_gauge:value(yuzu_gw_mgmt_streams_inflight, [])),
    ?assertEqual(0, prometheus_gauge:value(yuzu_gw_router_fanouts_inflight, [])),
    ?assertEqual(0, prometheus_gauge:value(yuzu_gw_beam_run_queue, [])),
    ?assertEqual(0, prometheus_gauge:value(yuzu_gw_beam_ports, [])).

sampler_families() ->
    telemetry:execute([yuzu, gw, process, mailbox], #{len => 7}, #{process => router}),
    ?assertEqual(7, prometheus_gauge:value(yuzu_gw_process_mailbox_len, [<<"router">>])),
    telemetry:execute([yuzu, gw, process, queue_wait], #{seconds => 1.5}, #{process => upstream}),
    ?assertEqual(1.5, prometheus_gauge:value(yuzu_gw_process_queue_wait_seconds, [<<"upstream">>])),
    telemetry:execute([yuzu, gw, listener, connections], #{active => 3, max => 10},
                      #{listener => agent}),
    ?assertEqual(3, prometheus_gauge:value(yuzu_gw_listener_connections, [<<"agent">>])),
    ?assertEqual(10, prometheus_gauge:value(yuzu_gw_listener_max_connections, [<<"agent">>])),
    telemetry:execute([yuzu, gw, mgmt, streams], #{count => 4}, #{}),
    ?assertEqual(4, prometheus_gauge:value(yuzu_gw_mgmt_streams_inflight, [])),
    telemetry:execute([yuzu, gw, vm, ports], #{count => 12, limit => 65536, fd_limit => 1024}, #{}),
    ?assertEqual(12, prometheus_gauge:value(yuzu_gw_beam_ports, [])),
    ?assertEqual(65536, prometheus_gauge:value(yuzu_gw_beam_port_limit, [])),
    ?assertEqual(1024, prometheus_gauge:value(yuzu_gw_beam_fd_limit, [])),
    telemetry:execute([yuzu, gw, vm, run_queue], #{length => 2}, #{}),
    ?assertEqual(2, prometheus_gauge:value(yuzu_gw_beam_run_queue, [])).

folded() ->
    telemetry:execute([yuzu, gw, process, mailbox], #{len => 9}, #{process => <<"10.0.0.1">>}),
    ?assertEqual(9, prometheus_gauge:value(yuzu_gw_process_mailbox_len, [<<"unknown">>])),
    ?assertEqual(undefined,
                 prometheus_gauge:value(yuzu_gw_process_mailbox_len, [<<"10.0.0.1">>])),
    Before = prometheus_counter:value(yuzu_gw_grpc_connections_closed_total,
                                      [<<"unknown">>, <<"unknown">>]),
    telemetry:execute([yuzu, gw, grpc, connection_closed], #{count => 1},
                      #{listener => {yuzu_grpc, x}, reason => "free text"}),
    ?assertEqual(inc(Before), prometheus_counter:value(yuzu_gw_grpc_connections_closed_total,
                                                       [<<"unknown">>, <<"unknown">>])).

no_ceiling() ->
    telemetry:execute([yuzu, gw, listener, connections], #{active => 1, max => 5},
                      #{listener => other}),
    ?assertEqual(5, prometheus_gauge:value(yuzu_gw_listener_max_connections, [<<"other">>])),
    telemetry:execute([yuzu, gw, listener, connections], #{active => 1, max => infinity},
                      #{listener => other}),
    ?assertEqual(undefined,
                 prometheus_gauge:value(yuzu_gw_listener_max_connections, [<<"other">>])),
    telemetry:execute([yuzu, gw, vm, ports], #{count => 1, limit => 2, fd_limit => undefined}, #{}),
    ?assertEqual(1, prometheus_gauge:value(yuzu_gw_beam_ports, [])).

close_counter() ->
    Labels = [<<"management">>, <<"enhance_your_calm">>],
    Before = prometheus_counter:value(yuzu_gw_grpc_connections_closed_total, Labels),
    telemetry:execute([yuzu, gw, grpc, connection_closed], #{count => 1},
                      #{listener => management, reason => enhance_your_calm}),
    ?assertEqual(Before + 1,
                 prometheus_counter:value(yuzu_gw_grpc_connections_closed_total, Labels)).

fanouts_gauge() ->
    telemetry:execute([yuzu, gw, router, fanouts], #{inflight => 5}, #{}),
    ?assertEqual(5, prometheus_gauge:value(yuzu_gw_router_fanouts_inflight, [])).

inc(undefined) -> 1;
inc(N) -> N + 1.

%%%===================================================================
%%% The warning for a message to an ended stream, per node
%%%===================================================================

%% One timed-out Register per agent connection: each connection's first such
%% line used to be written (the limit was kept per connection), so a storm of
%% timed-out Registers wrote one line per agent. 200 connections (processes)
%% within the interval write one line, and the next line counts the rest.
late_message_lines_are_limited_per_node_test() ->
    yuzu_grpc_cowboy_log:reset(),
    Lines = yuzu_gw_test_logs:capture(
              warning,
              fun() ->
                      [in_fresh_process(
                         fun() ->
                                 yuzu_grpc_cowboy_log:warning(
                                   "Received message ~p for unknown stream ~p.",
                                   [{{self(), 1}, {grpc_end, self(), 4, <<"secret">>}}, 1])
                         end) || _ <- lists:seq(1, 200)]
              end),
    Late = [L || L <- Lines, binary:match(L, <<"had already ended">>) =/= nomatch],
    ?assertMatch([_], Late),
    ?assertEqual([], [L || L <- Lines, binary:match(L, <<"secret">>) =/= nomatch]),
    yuzu_grpc_cowboy_log:reset().

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Telemetry handlers live in the process that runs the test (a fixture's setup
%% runs in another), and go in its `after'.
attach(Events) ->
    Id = {?MODULE, self(), erlang:unique_integer()},
    Self = self(),
    ok = telemetry:attach_many(Id, Events,
                               fun(E, M, Meta, _) -> Self ! {event, E, M, Meta} end, none),
    Id.

detach(Id) ->
    telemetry:detach(Id),
    flush().

sampler(Opts) ->
    {ok, G} = gen_server:start(yuzu_gw_gauge,
                               maps:merge(#{interval => 100, processes => [], listeners => []},
                                          Opts), []),
    G.

stop_sampler(G) ->
    Mon = monitor(process, G),
    exit(G, shutdown),
    receive {'DOWN', Mon, process, G, _} -> ok after 5000 -> ok end.

stop_box() ->
    case whereis(?BOX) of
        undefined -> ok;
        Pid ->
            catch erlang:resume_process(Pid),
            Mon = monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', Mon, process, Pid, _} -> ok after 5000 -> ok end
    end.

%% The next event of Kind for Label (undefined: no label) whose measurements
%% satisfy Pred, within 10 s.
await(Kind, Label, Pred) ->
    await(Kind, Label, Pred, erlang:monotonic_time(millisecond) + 10000).

await(Kind, Label, Pred, Deadline) ->
    Left = max(0, Deadline - erlang:monotonic_time(millisecond)),
    receive
        {event, Event, M, Meta} ->
            case matches(Kind, Label, Event, Meta) andalso Pred(M) of
                true  -> M;
                false -> await(Kind, Label, Pred, Deadline)
            end
    after Left ->
        error({no_event, Kind, Label})
    end.

matches(mailbox, L, [yuzu, gw, process, mailbox], #{process := L}) -> true;
matches(queue_wait, L, [yuzu, gw, process, queue_wait], #{process := L}) -> true;
matches(connections, L, [yuzu, gw, listener, connections], #{listener := L}) -> true;
matches(streams, _, [yuzu, gw, mgmt, streams], _) -> true;
matches(ports, _, [yuzu, gw, vm, ports], _) -> true;
matches(run_queue, _, [yuzu, gw, vm, run_queue], _) -> true;
matches(_, _, _, _) -> false.

agent_entry(Extra) ->
    maps:merge(#{service_protos => [agent_pb],
                 services => #{?AGENT_SVC => yuzu_grpc_stub_svc},
                 listen => #{port => 0}},
               Extra).

mgmt_entry(Extra) ->
    maps:merge(#{service_protos => [management_pb],
                 services => #{?MGMT_SVC => yuzu_gw_edge_stub_svc},
                 listen => #{port => 0}},
               Extra).

open(Port) ->
    {ok, C} = gun:open("127.0.0.1", Port, #{protocols => [http2], retry => 0,
                                            http2_opts => #{keepalive => infinity}}),
    {ok, http2} = gun:await_up(C, 5000),
    {C, erlang:monitor(process, C)}.

send_command(C, Action) ->
    Body = yuzu_grpc_frame:encode(
             management_pb:encode_msg(#{agent_ids => [<<"a">>],
                                        command => #{action => Action, command_id => <<>>}},
                                      'yuzu.server.v1.SendCommandRequest')),
    gun:post(C, ?SEND_COMMAND, grpc_headers(), Body).

grpc_headers() ->
    [{<<"content-type">>, <<"application/grpc">>}, {<<"te">>, <<"trailers">>}].

in_fresh_process(Fun) ->
    {Pid, Mon} = spawn_monitor(Fun),
    receive {'DOWN', Mon, process, Pid, normal} -> ok end.

flush() ->
    receive _ -> flush() after 0 -> ok end.

%% The suspended process of mailbox_and_queue_wait/0: a plain gen_server.
init([]) -> {ok, #{}}.
handle_call(_Req, _From, S) -> {reply, ok, S}.
handle_cast(_Msg, S) -> {noreply, S}.
handle_info(_Msg, S) -> {noreply, S}.
