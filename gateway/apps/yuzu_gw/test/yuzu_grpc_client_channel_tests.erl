%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_grpc_client_channel: the pool of gun connections behind
%%% the gateway's upstream client.
%%%
%%% Pure: backoff_ms/1 (monotone to its cap, jitter within 20%), and compact/1
%%% and word/1, the two functions that turn a connection failure into the small
%%% term the table and the log carry. compact/1 of a TLS failure must stay a
%%% term yuzu_gw_upstream:classify_tls_error/1 recognises, or the R-3 (#1243)
%%% handshake-failure metric goes quiet.
%%%
%%% Process level, against a real listener (yuzu_grpc_listener, the stub
%%% AgentService):
%%%   - an endpoint nobody listens on is answered at once with its error, and
%%%     that error is the table's `last_error';
%%%   - a listener that appears later is found by the channel by itself;
%%%   - a listener that goes away is noticed, calls fail fast meanwhile, and the
%%%     channel is reopened when the listener is back;
%%%   - stopping the channel closes its connections.
%%%
%%% Nothing sleeps to make an assertion true: the waits are bounded retry loops
%%% on the table rows.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_channel_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
%% A call that is answered at once or not at all must not wait for its timeout.
-define(FAST_MS, 1000).
-define(WAIT_ATTEMPTS, 600).

%%%===================================================================
%%% backoff_ms/1
%%%===================================================================

backoff_starts_at_100_ms_with_jitter_test() ->
    [?assert(within(yuzu_grpc_client_channel:backoff_ms(0), 100)) || _ <- lists:seq(1, 200)].

backoff_doubles_to_the_cap_test() ->
    Bases = [{0, 100}, {1, 200}, {2, 400}, {3, 800}, {4, 1600}, {5, 3200}, {6, 5000},
             {7, 5000}, {20, 5000}, {1000000, 5000}],
    [[?assert(within(yuzu_grpc_client_channel:backoff_ms(F), Base)) || _ <- lists:seq(1, 100)]
     || {F, Base} <- Bases].

backoff_is_monotone_up_to_the_cap_test() ->
    Samples = fun(F) -> [yuzu_grpc_client_channel:backoff_ms(F) || _ <- lists:seq(1, 300)] end,
    [?assert(lists:max(Samples(F)) < lists:min(Samples(F + 1))) || F <- lists:seq(0, 5)],
    ?assert(lists:min(Samples(6)) >= 5000).

backoff_never_exceeds_the_cap_plus_jitter_test() ->
    [?assert(yuzu_grpc_client_channel:backoff_ms(F) =< 6000) || F <- lists:seq(0, 100)].

backoff_is_jittered_test() ->
    Distinct = lists:usort([yuzu_grpc_client_channel:backoff_ms(3) || _ <- lists:seq(1, 200)]),
    ?assert(length(Distinct) > 1).

%% Base ms up to 20% more.
within(Delay, Base) -> Delay >= Base andalso Delay =< Base + Base div 5.

%%%===================================================================
%%% compact/1 and word/1
%%%===================================================================

compact_socket_errors_test() ->
    ?assertEqual(econnrefused, yuzu_grpc_client_channel:compact(econnrefused)),
    ?assertEqual(econnrefused, yuzu_grpc_client_channel:compact({shutdown, econnrefused})),
    ?assertEqual(econnrefused, yuzu_grpc_client_channel:compact({down, econnrefused})),
    ?assertEqual(econnrefused, yuzu_grpc_client_channel:compact({down, {shutdown, econnrefused}})),
    ?assertEqual(closed, yuzu_grpc_client_channel:compact({shutdown, {down, closed}})),
    ?assertEqual(timeout, yuzu_grpc_client_channel:compact(timeout)),
    %% a graceful close says nothing about a cause: it reads as a closed connection
    ?assertEqual(closed, yuzu_grpc_client_channel:compact(normal)),
    ?assertEqual(closed, yuzu_grpc_client_channel:compact({shutdown, normal})),
    ?assertEqual(closed, yuzu_grpc_client_channel:compact({down, normal})).

compact_tls_alerts_test() ->
    ?assertEqual({tls_alert, unknown_ca},
                 yuzu_grpc_client_channel:compact({tls_alert, {unknown_ca, "text of the alert"}})),
    ?assertEqual({tls_alert, handshake_failure},
                 yuzu_grpc_client_channel:compact({tls_alert, handshake_failure})),
    ?assertEqual({tls_alert, bad_certificate},
                 yuzu_grpc_client_channel:compact(
                   {shutdown, {tls_alert, {bad_certificate, "detail"}}})),
    ?assertEqual({tls_alert, certificate_expired},
                 yuzu_grpc_client_channel:compact(
                   {down, {shutdown, {tls_alert, {certificate_expired, <<"detail">>}}}})).

%% The text of an alert, and anything else a reason carries, never survives.
compact_options_test() ->
    ?assertEqual({options, tls}, yuzu_grpc_client_channel:compact({options, anything})),
    ?assertEqual({options, tls},
                 yuzu_grpc_client_channel:compact({options, [{keyfile, "/marker/KEY.pem"}]})),
    ?assertEqual({options, tls},
                 yuzu_grpc_client_channel:compact({shutdown, {options, {cacertfile, "/marker/ca"}}})).

compact_other_terms_test() ->
    %% a tuple is reduced to its tag, if the tag is an atom
    ?assertEqual(badmatch, yuzu_grpc_client_channel:compact({badmatch, <<"secret request">>})),
    ?assertEqual(stream_error, yuzu_grpc_client_channel:compact({stream_error, a, b, c})),
    %% a tls_alert whose alert is not an atom has no alert to name
    ?assertEqual(tls_alert, yuzu_grpc_client_channel:compact({tls_alert, "text"})),
    ?assertEqual(tls_alert, yuzu_grpc_client_channel:compact({tls_alert, {"text", x}})),
    [?assertEqual(other, yuzu_grpc_client_channel:compact(T))
     || T <- [{}, {"string", x}, {<<"bin">>, x}, {5, 6}, {[a], b}, [a, b], [], "text",
              <<"binary">>, 42, 1.5, #{a => 1}, make_ref(), self(), fun() -> ok end]].

compact_result_is_always_small_test() ->
    Inputs = [econnrefused, {shutdown, econnrefused}, {down, closed}, {tls_alert, {unknown_ca, "t"}},
              {tls_alert, handshake_failure}, {options, x}, {badmatch, <<"data">>}, {a, b, c},
              {}, [x], <<"x">>, 7, #{k => v}, {shutdown, {down, {shutdown, {tls_alert, {a, "b"}}}}}],
    [begin
         C = yuzu_grpc_client_channel:compact(T),
         ?assert(is_atom(C) orelse (tuple_size(C) =:= 2 andalso
                                    lists:member(element(1, C), [tls_alert, options]) andalso
                                    is_atom(element(2, C))))
     end || T <- Inputs].

word_test() ->
    W = fun(R) -> yuzu_grpc_client_channel:word(yuzu_grpc_client_channel:compact(R)) end,
    ?assertEqual(econnrefused, W(econnrefused)),
    ?assertEqual(econnrefused, W({shutdown, econnrefused})),
    ?assertEqual(econnrefused, W({down, econnrefused})),
    ?assertEqual(unknown_ca, W({tls_alert, {unknown_ca, "text"}})),
    ?assertEqual(handshake_failure, W({tls_alert, handshake_failure})),
    ?assertEqual(bad_tls_options, W({options, anything})),
    ?assertEqual(badmatch, W({badmatch, <<"x">>})),
    ?assertEqual(other, W({<<"bin">>, x})),
    ?assertEqual(other, W(<<"x">>)),
    %% word/1 on a term that is not compact still returns one atom
    ?assertEqual(other, yuzu_grpc_client_channel:word({a, b})),
    ?assertEqual(other, yuzu_grpc_client_channel:word("text")),
    ?assertEqual(other, yuzu_grpc_client_channel:word({options, other})).

%% R-3 (#1243): what a failed TLS connection puts in the table is still read as
%% a handshake failure by the upstream's classifier, with the alert as the kind.
compact_tls_alert_is_classified_as_a_handshake_failure_test() ->
    Classify = fun(R) ->
                   yuzu_gw_upstream:classify_tls_error(yuzu_grpc_client_channel:compact(R))
               end,
    ?assertEqual({true, <<"unknown_ca">>}, Classify({tls_alert, {unknown_ca, "text"}})),
    ?assertEqual({true, <<"handshake_failure">>}, Classify({tls_alert, handshake_failure})),
    ?assertEqual({true, <<"bad_certificate">>},
                 Classify({shutdown, {tls_alert, {bad_certificate, "t"}}})),
    ?assertEqual({true, <<"bad_tls_options">>}, Classify({options, [{verify, bogus}]})),
    %% and the shapes `pick/2' hands back around it
    ?assertEqual({true, <<"unknown_ca">>},
                 yuzu_gw_upstream:classify_tls_error(
                   {error, yuzu_grpc_client_channel:compact({tls_alert, {unknown_ca, "t"}})})),
    %% a plain connection failure is not a TLS failure
    [?assertMatch({false, _}, Classify(R))
     || R <- [econnrefused, {shutdown, econnrefused}, closed, timeout, {badmatch, x}, other]].

%%%===================================================================
%%% Process level
%%%===================================================================

process_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [fun(S) -> {"no channel by that name is {error, no_channel}",
                 fun() -> no_channel(S) end} end,
      fun(S) -> {"max_receive/1 is the channel's limit, and a default for no channel",
                 fun() -> max_receive(S) end} end,
      fun(S) -> {"an endpoint nobody listens on: pick/2 answers econnrefused at once",
                 {timeout, 30, fun() -> dead_endpoint_fails_fast(S) end}} end,
      fun(S) -> {"an endpoint nobody listens on: a call fails at once with econnrefused",
                 {timeout, 30, fun() -> dead_endpoint_call_fails_fast(S) end}} end,
      fun(S) -> {"a listener that appears later is found by the channel by itself",
                 {timeout, 60, fun() -> reconnects_when_listener_appears(S) end}} end,
      fun(S) -> {"a listener that goes away: calls fail fast, the channel reopens when it is back",
                 {timeout, 60, fun() -> listener_killed_and_back(S) end}} end,
      fun(S) -> {"a pool of two: the channel is usable on one connection while the other is down",
                 {timeout, 60, fun() -> pool_partially_down(S) end}} end,
      fun(S) -> {"stopping the channel closes its connections and removes its table",
                 {timeout, 30, fun() -> stop_closes_connections(S) end}} end,
      fun(S) -> {"a message to the channel it does not know is dropped; a call is {error, unsupported}",
                 fun() -> stray_messages(S) end} end]}.

setup() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_grpc_stub_svc:init_state(),
    #{listeners => ets:new(?MODULE, [public, bag]),
      name => list_to_atom("yuzu_chan_test_" ++ integer_to_list(erlang:unique_integer([positive])))}.

cleanup(#{listeners := Tab, name := Name}) ->
    ok = yuzu_gw_test_listener:stop_channel(Name),
    [catch yuzu_grpc_listener:stop(P) || {listener, P} <- ets:tab2list(Tab)],
    ets:delete(Tab),
    ok.

no_channel(_S) ->
    ?assertEqual({error, no_channel}, yuzu_grpc_client_channel:pick(yuzu_chan_test_nobody, 100)),
    ?assertEqual({error, no_channel}, yuzu_grpc_client_channel:pick(yuzu_chan_test_nobody, 0)).

max_receive(#{name := Name}) ->
    ?assertEqual(16 * 1024 * 1024, yuzu_grpc_client_channel:max_receive(yuzu_chan_test_nobody)),
    Port = yuzu_gw_test_listener:probe_free_port(),
    start(Name, Port, #{max_receive_message_bytes => 4321}),
    ?assertEqual(4321, yuzu_grpc_client_channel:max_receive(Name)).

dead_endpoint_fails_fast(#{name := Name}) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start(Name, Port, #{pool_size => 2}),
    ok = wait_for(fun() -> last_error(Name) =/= no_connection_yet end),
    T0 = erlang:monotonic_time(millisecond),
    Results = [yuzu_grpc_client_channel:pick(Name, 5000) || _ <- lists:seq(1, 20)],
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assertEqual([{error, econnrefused}], lists:usort(Results)),
    ?assert(Elapsed < ?FAST_MS),
    ?assertEqual(econnrefused, last_error(Name)),
    ?assertEqual([], up_slots(Name)).

%% The first answer, before the channel has had time to look at the failure: it
%% is an error either way, and a fast one; it names the cause once known.
dead_endpoint_call_fails_fast(#{name := Name}) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start(Name, Port, #{pool_size => 1}),
    T0 = erlang:monotonic_time(millisecond),
    Result = yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                    #{channel => Name, timeout => 5000}),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assertMatch({error, _}, Result),
    ?assert(Elapsed < ?FAST_MS),
    ok = wait_for(fun() -> last_error(Name) =:= econnrefused end),
    ?assertEqual({error, econnrefused},
                 yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                        #{channel => Name, timeout => 5000})).

reconnects_when_listener_appears(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> last_error(Name) =:= econnrefused end),
    ?assertEqual({error, econnrefused}, yuzu_grpc_client_channel:pick(Name, 1000)),
    start_listener(S, Port),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name)).

listener_killed_and_back(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    Listener = start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name)),
    ok = yuzu_grpc_listener:stop(Listener),
    ok = wait_for(fun() -> up_slots(Name) =:= [] end),
    %% down: the next call is answered at once, with an error, not by its timeout
    ok = wait_for(fun() -> last_error(Name) =:= econnrefused end),
    T0 = erlang:monotonic_time(millisecond),
    Failed = yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>}, def(),
                                    #{channel => Name, timeout => 5000}),
    ?assert(erlang:monotonic_time(millisecond) - T0 < ?FAST_MS),
    ?assertEqual({error, econnrefused}, Failed),
    %% back: the channel reopens by itself
    start_listener(S, Port),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name)).

%% One listener at a time, two endpoints: the live one carries every call.
pool_partially_down(#{name := Name} = S) ->
    Live = yuzu_gw_test_listener:probe_free_port(),
    Dead = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Live),
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{http, "localhost", Live, []}, {http, "localhost", Dead, []}],
                   #{pool_size => 1}}, true),
    {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 andalso last_error(Name) =:= econnrefused end),
    Results = [heartbeat(Name) || _ <- lists:seq(1, 10)],
    ?assertEqual(10, length([ok || {ok, #{acknowledged := true}, _} <- Results])),
    ?assertEqual(1, length(up_slots(Name))).

stop_closes_connections(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 2}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 2 end),
    Conns = up_slots(Name),
    Refs = [erlang:monitor(process, C) || C <- Conns],
    ok = yuzu_gw_test_listener:stop_channel(Name),
    [receive {'DOWN', R, process, _, _} -> ok after 5000 -> error(connection_not_closed) end
     || R <- Refs],
    ?assertEqual(undefined, whereis(Name)),
    ?assertEqual(undefined, ets:whereis(Name)),
    ?assertEqual({error, no_channel}, yuzu_grpc_client_channel:pick(Name, 0)).

stray_messages(#{name := Name}) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start(Name, Port, #{pool_size => 1}),
    Pid = whereis(Name),
    Pid ! {gun_up, self(), http2},
    Pid ! {gun_down, self(), http2, closed, []},
    Pid ! {gun_error, self(), make_ref(), boom},
    Pid ! {reconnect, 99},
    Pid ! unexpected,
    gen_server:cast(Pid, unexpected),
    ?assertEqual({error, unsupported}, gen_server:call(Pid, unexpected)),
    ?assertEqual(Pid, whereis(Name)).

%%%===================================================================
%%% Helpers
%%%===================================================================

%% Start the channel linked to the test process, without waiting for it.
start(Name, Port, Options) ->
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{http, "localhost", Port, []}], Options}, true),
    {ok, Pid} = yuzu_grpc_client_channel:start_link(Cfg),
    Pid.

%% A stub listener on the port; its pid is kept so cleanup can stop it. A port
%% just released can take a moment to bind again.
start_listener(S, Port) ->
    start_listener(S, Port, 50).

start_listener(_S, _Port, 0) ->
    error(listener_did_not_bind);
start_listener(#{listeners := Tab} = S, Port, Retries) ->
    Entry = #{name => erlang:unique_integer([positive]),
              listen => #{ip => {127, 0, 0, 1}, port => Port},
              service_protos => [agent_pb],
              services => #{?SVC => yuzu_grpc_stub_svc}},
    case yuzu_grpc_listener:start(Entry) of
        {ok, Pid} ->
            ets:insert(Tab, {listener, Pid}),
            Pid;
        {error, _} ->
            receive after 100 -> ok end,
            start_listener(S, Port, Retries - 1)
    end.

last_error(Name) ->
    ets:lookup_element(Name, last_error, 2).

up_slots(Name) ->
    ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}]).

%% Retry a condition until it holds: bounded, no fixed wait for it to become true.
wait_for(Fun) ->
    wait_for(Fun, ?WAIT_ATTEMPTS).

wait_for(_Fun, 0) ->
    {error, condition_not_met};
wait_for(Fun, N) ->
    case catch Fun() of
        true -> ok;
        _ -> receive after 25 -> ok end, wait_for(Fun, N - 1)
    end.

heartbeat(Name) ->
    yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>}, def(), #{channel => Name}).

def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.
