%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_grpc_client_channel: the pool of gun connections behind
%%% the gateway's upstream client.
%%%
%%% Pure: backoff_ms/1 (monotone to its cap, jitter of up to 20% below the base,
%%% never above the cap), and compact/1
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
%%%   - stopping the channel closes its connections;
%%%   - a caller that finds no connection up while one is being opened waits on
%%%     the channel (only the owner of a gun connection hears it come up) and is
%%%     woken when it comes up or fails, and is answered at once when none is
%%%     being opened; a caller whose own timeout expires is not left registered
%%%     once the attempt ends;
%%%   - a connection the channel gives up on is really closed (gun:close/1 does
%%%     nothing for an unsupervised connection), and so are all of them when the
%%%     channel ends;
%%%   - the reconnect backoff restarts only after a connection has stayed up
%%%     (`{stable, _, _}'), never merely because it came up, and only for the
%%%     same connection;
%%%   - the first loss of a connection is redialled at once, the next ones back off;
%%%   - a callback that raises ends the channel with its class alone: the report
%%%     OTP prints for it carries no endpoint and no TLS option, nor does a
%%%     failed init/1;
%%%   - what sys:get_status/1 shows of the channel carries no endpoint and no
%%%     TLS option;
%%%   - a host name that does not resolve fails within the connect timeout.
%%%
%%% Nothing sleeps to make an assertion true: the waits are bounded retry loops
%%% on the table rows. The tests of the backoff read the channel's state with
%%% sys:get_state/1 (see slot_fails/2 for the record positions it relies on).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_channel_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).  %% logger handler

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
%% A call that is answered at once or not at all must not wait for its timeout.
%% Windows reports a refused connect only after its SYN retries (about 2 s), so the
%% bound there is looser, but still under the 5000 ms the calls are given.
-define(FAST_MS, (fast_ms())).
-define(WAIT_ATTEMPTS, 600).

fast_ms() ->
    case os:type() of
        {win32, _} -> 4500;
        _          -> 1000
    end.

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
    ?assert(lists:max(Samples(6)) =< 5000),
    ?assert(lists:min(Samples(6)) >= 4000).

%% The jitter goes down from the base, so the delay never passes the 5 s cap
%% (adding it on top of the cap reached 5.8 s).
backoff_never_exceeds_the_cap_test() ->
    [?assert(yuzu_grpc_client_channel:backoff_ms(F) =< 5000) || F <- lists:seq(0, 100)],
    [?assert(yuzu_grpc_client_channel:backoff_ms(F) =< 5000) || F <- [1000, 1000000]].

backoff_is_jittered_test() ->
    Distinct = lists:usort([yuzu_grpc_client_channel:backoff_ms(3) || _ <- lists:seq(1, 200)]),
    ?assert(length(Distinct) > 1).

%% Base ms, or up to 20% less.
within(Delay, Base) -> Delay =< Base andalso Delay >= Base - Base div 5.

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
      fun(S) -> {"pick/2 answers no_channel when the table is there but the channel is not whole",
                 fun() -> pick_on_a_broken_table(S) end} end,
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
                 fun() -> stray_messages(S) end} end,
      fun(S) -> {"a waiter is woken with the error when the connecting slot fails",
                 {timeout, 30, fun() -> waiter_woken_when_connecting_slot_fails(S) end}} end,
      fun(S) -> {"a waiter whose own timeout expires gets the last error and is not left registered",
                 {timeout, 30, fun() -> waiter_timeout_leaves_nothing_behind(S) end}} end,
      fun(S) -> {"a waiter that gave up is dropped, and one that did not is still answered",
                 {timeout, 30, fun() -> expired_waiter_does_not_hide_a_live_one(S) end}} end,
      fun(S) -> {"await_up with every slot down (waiting out its backoff) is answered at once",
                 {timeout, 30, fun() -> await_up_with_every_slot_down(S) end}} end,
      fun(S) -> {"await_up with a connection up is answered with it",
                 {timeout, 30, fun() -> await_up_with_a_connection_up(S) end}} end,
      fun(S) -> {"a connection the channel gives up on is dead shortly after, and replaced",
                 {timeout, 30, fun() -> lost_connection_is_closed(S) end}} end,
      fun(S) -> {"when the channel ends normally, every connection is dead",
                 {timeout, 30, fun() -> normal_stop_closes_connections(S) end}} end,
      fun(S) -> {"the first loss of a live connection is redialled at once, with no backoff",
                 {timeout, 30, fun() -> first_loss_redials_at_once(S) end}} end,
      fun(S) -> {"the loss after it backs off: the slot is down with a reconnect timer",
                 {timeout, 30, fun() -> second_loss_backs_off(S) end}} end,
      fun(S) -> {"a connection that comes up and drops at once does not reset the backoff",
                 {timeout, 60, fun() -> accept_and_close_grows_the_backoff(S) end}} end,
      fun(S) -> {"gun_up alone does not reset the failure count",
                 {timeout, 30, fun() -> gun_up_does_not_reset_fails(S) end}} end,
      fun(S) -> {"{stable, Id, Pid} resets the failure count only for the slot's own connection",
                 {timeout, 30, fun() -> stable_resets_only_the_same_connection(S) end}} end,
      fun(S) -> {"a connection that stays up resets the failure count by itself",
                 {timeout, 60, fun() -> stable_timer_resets_fails(S) end}} end,
      fun(S) -> {"sys:get_status/1 shows the shape of the channel, not its endpoints or TLS options",
                 {timeout, 30, fun() -> status_hides_endpoints_and_tls_options(S) end}} end,
      fun(S) -> {"format_status/1 reduces the state and passes anything else through",
                 {timeout, 30, fun() -> format_status_shapes(S) end}} end,
      fun(S) -> {"a host name that does not resolve fails within the connect timeout",
                 {timeout, 30, fun() -> unresolvable_host_fails_fast(S) end}} end,
      fun(S) -> {"the connections are opened with the connect timeout as their lookup timeout",
                 {timeout, 30, fun() -> connections_carry_the_lookup_timeout(S) end}} end,
      fun(S) -> {"the connections are opened with HTTP/2 keepalive pings and SO_KEEPALIVE",
                 {timeout, 30, fun() -> connections_carry_the_liveness_options(S) end}} end,
      fun(S) -> {"an operator's own socket options win over the channel's defaults",
                 {timeout, 30, fun() -> operator_socket_options_win(S) end}} end,
      fun(S) -> {"a CA file that does not exist is reported once, with its path, and never a key path; /readyz says not ready",
                 {timeout, 30, fun() -> unusable_ca_is_reported(S) end}} end,
      fun(S) -> {"the report clears once an attempt fails for another reason, and /readyz recovers",
                 {timeout, 30, fun() -> unusable_ca_report_clears(S) end}} end,
      fun(S) -> {"a plaintext channel with a connection up reports no TLS file problem",
                 {timeout, 30, fun() -> plaintext_channel_has_no_config_error(S) end}} end,
      fun(S) -> {"a channel whose init/1 fails leaves with its class alone, nothing of its config logged",
                 {timeout, 30, fun() -> init_failure_logs_no_config(S) end}} end,
      fun(S) -> {"a channel whose callback raises leaves with its class alone, nothing of its state logged",
                 {timeout, 30, fun() -> callback_failure_logs_no_config(S) end}} end]}.

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
    [begin catch exit(Acceptor, kill), catch gen_tcp:close(Listen) end
     || {raw, Listen, Acceptor} <- ets:tab2list(Tab)],
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
    %% the pick may wait for a connection attempt already under way, which on
    %% Windows outlasts a second
    ?assertEqual({error, econnrefused}, yuzu_grpc_client_channel:pick(Name, 5000)),
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
%%% Callers that arrive while a connection is being opened
%%%===================================================================

%% A TLS endpoint whose server accepts and says nothing for 700 ms, then closes
%% the connection: the slot is `connecting' for those 700 ms and then fails. The
%% caller must be answered with the failure then, not when its own 4 s are up.
waiter_woken_when_connecting_slot_fails(#{name := Name} = S) ->
    Port = start_raw_listener(S, 700),
    start_tls(Name, Port, #{pool_size => 1, connect_timeout => 3000}),
    ?assertEqual([], up_slots(Name)),
    ?assertEqual(no_connection_yet, last_error(Name)),
    T0 = erlang:monotonic_time(millisecond),
    Result = yuzu_grpc_client_channel:pick(Name, 4000),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assertMatch({error, _}, Result),
    {error, Why} = Result,
    ?assertNotEqual(no_connection_yet, Why),
    ?assertEqual(last_error(Name), Why),
    ?assert(Elapsed < 3000),
    ?assertEqual(0, waiters(Name)),
    %% and a call is answered the same way
    ok = wait_for(fun() -> last_error(Name) =/= no_connection_yet end),
    ?assertMatch({error, _}, yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>},
                                                    def(), #{channel => Name, timeout => 5000})).

%% The server never answers the handshake, so the slot stays `connecting' until
%% the connect timeout (1.5 s). A caller that gives up after 300 ms gets
%% {error, timeout} (its own time ran out; the channel has no error yet to give),
%% the channel is unharmed, and the caller is no longer registered once the
%% attempt has ended.
waiter_timeout_leaves_nothing_behind(#{name := Name} = S) ->
    Port = start_raw_listener(S, infinity),
    Pid = start_tls(Name, Port, #{pool_size => 1, connect_timeout => 1500}),
    T0 = erlang:monotonic_time(millisecond),
    Result = yuzu_grpc_client_channel:pick(Name, 300),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assertEqual({error, timeout}, Result),
    ?assert(Elapsed >= 250),
    ?assert(Elapsed < 1400),
    ?assertEqual(Pid, whereis(Name)),
    ?assertEqual(1, waiters(Name)),
    %% the attempt ends (handshake timeout): the stale waiter is dropped, with
    %% the failure as its (unheard) answer
    ok = wait_for(fun() -> last_error(Name) =/= no_connection_yet end),
    ok = wait_for(fun() -> waiters(Name) =:= 0 end),
    ?assertEqual(Pid, whereis(Name)),
    ?assertMatch({error, _}, yuzu_grpc_client_channel:pick(Name, 0)),
    %% nothing the late reply could have left in the caller's mailbox
    receive Stray -> error({stray_message, Stray}) after 100 -> ok end.

%% The slot has failed twice and is waiting out its backoff (at least 80 ms; the
%% first failure is redialled at once, so the slot is only `down' after the
%% second): no connection is being opened, so await_up has nothing to wait for.
await_up_with_every_slot_down(#{name := Name}) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> last_error(Name) =:= econnrefused end),
    ok = wait_for(fun() -> slot_status(Name, 1) =:= down end),
    T0 = erlang:monotonic_time(millisecond),
    Result = gen_server:call(Name, {await_up, 5000}, 5000),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    ?assertEqual({error, econnrefused}, Result),
    ?assert(Elapsed < 100),
    ?assertEqual([], up_slots(Name)),
    ?assertEqual(0, waiters(Name)).

await_up_with_a_connection_up(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Conn] = up_slots(Name),
    ?assertEqual({ok, Conn}, gen_server:call(Name, {await_up, 5000}, 5000)),
    ?assertEqual({ok, Conn}, yuzu_grpc_client_channel:pick(Name, 5000)).

%% Two callers wait on one connecting slot (a server that holds the connection
%% 700 ms and closes it): one gives up after 200 ms, the other waits 4 s. The
%% first gets {error, timeout} and is never answered afterwards (no stray reply
%% lands in its mailbox), the second is answered with the failure when it comes.
expired_waiter_does_not_hide_a_live_one(#{name := Name} = S) ->
    Port = start_raw_listener(S, 700),
    start_tls(Name, Port, #{pool_size => 1, connect_timeout => 3000}),
    Parent = self(),
    Quitter = spawn_link(fun() ->
                             R = yuzu_grpc_client_channel:pick(Name, 200),
                             Stray = receive M -> {stray, M} after 1200 -> none end,
                             Parent ! {quitter, R, Stray}
                         end),
    ok = wait_for(fun() -> waiters(Name) =:= 1 end),
    Result = yuzu_grpc_client_channel:pick(Name, 4000),
    {error, Why} = Result,
    ?assertNotEqual(timeout, Why),
    ?assertNotEqual(no_connection_yet, Why),
    receive {quitter, QuitterResult, Stray} ->
            ?assertEqual({error, timeout}, QuitterResult),
            ?assertEqual(none, Stray)
    after 5000 -> error({quitter_silent, Quitter})
    end,
    ?assertEqual(0, waiters(Name)).

%%%===================================================================
%%% Closing connections
%%%===================================================================

%% gun:close/1 is a no-op for a connection started with `supervise => false', so
%% a connection the channel dropped from its table used to live on, owned by a
%% process that no longer tracked it.
lost_connection_is_closed(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Old] = up_slots(Name),
    Ref = erlang:monitor(process, Old),
    whereis(Name) ! {gun_down, Old, http2, closed, []},
    receive {'DOWN', Ref, process, Old, _} -> ok
    after 5000 -> error(connection_still_alive)
    end,
    %% the slot is reopened with a new connection
    ok = wait_for(fun() -> case up_slots(Name) of [New] -> New =/= Old; _ -> false end end),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name)),
    %% a message about the connection that is gone changes nothing
    [Current] = up_slots(Name),
    whereis(Name) ! {gun_down, Old, http2, closed, []},
    whereis(Name) ! {gun_error, Old, boom},
    _ = sys:get_state(Name),
    ?assertEqual([Current], up_slots(Name)).

normal_stop_closes_connections(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    Chan = start(Name, Port, #{pool_size => 2}),
    unlink(Chan),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 2 end),
    Refs = [erlang:monitor(process, C) || C <- up_slots(Name)],
    ok = gen_server:stop(Name),
    [receive {'DOWN', R, process, _, _} -> ok after 5000 -> error(connection_not_closed) end
     || R <- Refs],
    ?assertEqual(undefined, ets:whereis(Name)).

%%%===================================================================
%%% Backoff
%%%===================================================================

%% The server accepts, lets the connection come up (gun_up) and closes it 50 ms
%% later. If coming up reset the failure count, it would never pass 1 and the
%% reconnects would come every ~100 ms for ever; the count has to grow.
accept_and_close_grows_the_backoff(#{name := Name} = S) ->
    Port = start_raw_listener(S, 50),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> slot_fails(Name, 1) >= 3 end),
    ?assert(slot_fails(Name, 1) >= 3).

gun_up_does_not_reset_fails(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Conn] = up_slots(Name),
    set_fails(Name, 1, 3),
    whereis(Name) ! {gun_up, Conn, http2},
    _ = sys:get_state(Name),
    ?assertEqual(3, slot_fails(Name, 1)),
    ?assertEqual([Conn], up_slots(Name)).

stable_resets_only_the_same_connection(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Old] = up_slots(Name),
    %% replace the connection: Old is now a connection of the past
    whereis(Name) ! {gun_down, Old, http2, closed, []},
    ok = wait_for(fun() -> case up_slots(Name) of [New] -> New =/= Old; _ -> false end end),
    [New] = up_slots(Name),
    set_fails(Name, 1, 3),
    Chan = whereis(Name),
    %% a stale connection, a pid that is not a connection, an unknown slot
    Chan ! {stable, 1, Old},
    Chan ! {stable, 1, self()},
    Chan ! {stable, 99, New},
    _ = sys:get_state(Name),
    ?assertEqual(3, slot_fails(Name, 1)),
    ?assertEqual(Chan, whereis(Name)),
    %% the slot's own connection
    Chan ! {stable, 1, New},
    _ = sys:get_state(Name),
    ?assertEqual(0, slot_fails(Name, 1)).

%% STABLE_MS (5 s) after it comes up, a connection that is still the slot's
%% resets the count by itself.
stable_timer_resets_fails(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    set_fails(Name, 1, 3),
    ?assertEqual(3, slot_fails(Name, 1)),
    ok = wait_for(fun() -> slot_fails(Name, 1) =:= 0 end, 400),
    ?assertEqual(1, length(up_slots(Name))).

%% The first loss of a healthy connection is redialled at once: the slot goes
%% straight to `connecting' (no `down' row, no reconnect timer), so a caller that
%% arrives waits for the new connection instead of failing; a backoff here turned
%% a blip of 100 ms into several failed calls at the caller's circuit breaker.
first_loss_redials_at_once(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Old] = up_slots(Name),
    whereis(Name) ! {gun_down, Old, http2, closed, []},
    _ = sys:get_state(Name),
    ?assertEqual(1, slot_fails(Name, 1)),
    ?assertEqual(undefined, slot_timer(Name, 1)),
    ?assertNotEqual(down, slot_status(Name, 1)),
    ok = wait_for(fun() -> case up_slots(Name) of [New] -> New =/= Old; _ -> false end end),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name)).

%% The listener goes away: the connection is lost (the first loss, redialled at
%% once) and the redial is refused, which is the second failure in a row: now the
%% slot is `down' with a reconnect timer, and the count has grown.
second_loss_backs_off(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    Listener = start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    ok = yuzu_grpc_listener:stop(Listener),
    ok = wait_for(fun() -> slot_status(Name, 1) =:= down end),
    ?assert(slot_fails(Name, 1) >= 2),
    ?assert(is_reference(slot_timer(Name, 1))),
    ?assertEqual(econnrefused, last_error(Name)).

%%%===================================================================
%%% What the channel shows of itself
%%%===================================================================

status_hides_endpoints_and_tls_options(#{name := Name}) ->
    Ssl = [{verify, verify_peer}, {cacertfile, "/marker/ca/CA-FILE.pem"},
           {certfile, "/marker/leaf/LEAF-CERT.pem"}, {keyfile, "/marker/leaf/LEAF-KEY.pem"}],
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{https, "marker-host.example.test", 50051, Ssl}], #{pool_size => 2}}, true),
    {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
    Text = lists:flatten(io_lib:format("~p", [sys:get_status(Name)])),
    [?assertEqual(nomatch, string:find(Text, Marker))
     || Marker <- ["CA-FILE", "LEAF-CERT", "LEAF-KEY", "/marker/", "marker-host", "verify_peer",
                   "cacertfile", "keyfile", "50051"]],
    %% not vacuous: it does show the channel
    ?assertEqual(#{channel => Name, slots => 2, waiters => 0}, shown_state(Name)).

format_status_shapes(#{name := Name}) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start(Name, Port, #{pool_size => 2}),
    State = sys:get_state(Name),
    ?assertEqual(st, element(1, State)),
    Shown = yuzu_grpc_client_channel:format_status(#{state => State, reason => normal}),
    ?assertEqual(#{state => #{channel => Name, slots => 2, waiters => 0}, reason => normal}, Shown),
    %% a status without a recognisable state is passed on as it is
    ?assertEqual(#{state => garbage}, yuzu_grpc_client_channel:format_status(#{state => garbage})),
    ?assertEqual(#{}, yuzu_grpc_client_channel:format_status(#{})).

%%%===================================================================
%%% A channel that is not whole, and one that fails
%%%===================================================================

%% The channel can die at any moment and its table goes with it, so every table
%% read of pick/2 is inside its one catch. A table that is there without a
%% channel behind it (or without its round-robin counter) is the same answer as
%% no table: {error, no_channel}, never a badarg for the caller.
pick_on_a_broken_table(#{name := Name}) ->
    Owner = spawn_link(fun() ->
                           receive {make, From} ->
                                       Name = ets:new(Name, [named_table, public, set]),
                                       From ! made,
                                       receive stop -> ok end
                           end
                       end),
    Owner ! {make, self()},
    receive made -> ok after 5000 -> error(table_not_made) end,
    try
        %% a table and no channel process: nothing up, nobody to wait on
        ?assertEqual(undefined, whereis(Name)),
        ?assertEqual({error, no_channel}, yuzu_grpc_client_channel:pick(Name, 100)),
        ?assertEqual({error, no_channel}, yuzu_grpc_client_channel:pick(Name, 0)),
        %% a live connection in the table and no round-robin counter
        true = ets:insert(Name, {{slot, 1}, self(), up}),
        ?assertEqual({error, no_channel}, yuzu_grpc_client_channel:pick(Name, 100))
    after
        Owner ! stop
    end.

%% HTTP/2 PINGs every 45 s (above the C++ server's 30 s floor for pings without
%% data) and the connection closed when one goes unanswered, GOAWAY drained for
%% 3 s, and SO_KEEPALIVE on the socket, read from the connection itself.
connections_carry_the_liveness_options(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Conn] = up_slots(Name),
    Opts = find_opts(sys:get_state(Conn)),
    ?assertMatch(#{http2_opts := #{keepalive := 45000, keepalive_tolerance := 1,
                                   closing_timeout := 3000}}, Opts),
    Tcp = maps:get(tcp_opts, Opts),
    ?assertEqual(true, proplists:get_value(keepalive, Tcp)),
    ?assertEqual(true, proplists:get_value(nodelay, Tcp)),
    ?assertEqual(15000, proplists:get_value(send_timeout, Tcp)),
    ?assertEqual(true, proplists:get_value(send_timeout_close, Tcp)).

%% A socket option the operator names is not given a default beside it.
operator_socket_options_win(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{http, "localhost", Port,
                           [], #{socket_options => [{send_timeout, 1234}, {keepalive, false}]}}],
                   #{pool_size => 1}}, true),
    {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Conn] = up_slots(Name),
    Tcp = maps:get(tcp_opts, find_opts(sys:get_state(Conn))),
    ?assertEqual([1234], [V || {send_timeout, V} <- Tcp]),
    ?assertEqual([false], [V || {keepalive, V} <- Tcp]),
    %% the defaults the operator did not name are still there
    ?assertEqual([true], [V || {send_timeout_close, V} <- Tcp]).

-define(CFG_MARKERS, ["LEAF-KEY", "LEAF-CERT", "CA-FILE", "/marker/", "marker-host"]).

%% init/1 fails (an endpoint with no host): start_link gives the class and
%% nothing else. OTP prints the reason and the arguments of a failing init, and
%% the arguments of this one are the endpoint list with its TLS options (key and
%% certificate file paths), so none of it may reach a log.
init_failure_logs_no_config(#{name := Name}) ->
    process_flag(trap_exit, true),
    try
        Endpoint = #{host => marker_host_missing, port => 50051, transport => tls, tcp_opts => [],
                     tls_opts => marker_tls_opts()},
        %% no `host' key: open/2 cannot match the endpoint
        Cfg = #{name => Name, endpoints => [maps:remove(host, Endpoint)], pool_size => 1,
                connect_timeout => 1000, max_receive_message_bytes => 1000},
        {Result, Text} = capture(fun() -> yuzu_grpc_client_channel:start_link(Cfg) end),
        ?assertEqual({error, {channel_failed, error}}, Result),
        ?assertEqual(undefined, whereis(Name)),
        ?assertEqual(undefined, ets:whereis(Name)),
        assert_no_config(Text)
    after
        drain_exits(),
        process_flag(trap_exit, false)
    end.

%% A callback raises (a connection the channel believes in is no slot of its):
%% the channel exits with {channel_failed, Class}, and what OTP logs about it,
%% with the stacktrace whose argument lists would be the slots, carries none of
%% the configuration. The log is not empty: the exit and its reason are in it.
callback_failure_logs_no_config(#{name := Name}) ->
    process_flag(trap_exit, true),
    try
        Port = yuzu_gw_test_listener:probe_free_port(),
        {ok, Cfg} = yuzu_grpc_client_config:channel(
                      {Name, [{https, "127.0.0.1", Port, marker_tls_opts()}], #{pool_size => 1}}, true),
        {ok, Chan} = yuzu_grpc_client_channel:start_link(Cfg),
        Me = self(),
        _ = sys:replace_state(Name, fun(State) ->
                                            st = element(1, State),
                                            setelement(5, State, #{Me => 99})
                                    end),
        {_, Text} = capture(fun() ->
                                Chan ! {gun_up, Me, http2},
                                receive {'EXIT', Chan, Reason} ->
                                            ?assertEqual({channel_failed, error}, Reason)
                                after 5000 -> error(channel_still_alive)
                                end
                            end),
        ?assertNotEqual(nomatch, string:find(Text, "channel_failed")),
        assert_no_config(Text)
    after
        drain_exits(),
        process_flag(trap_exit, false)
    end.

marker_tls_opts() ->
    [{verify, verify_peer}, {cacertfile, "/marker/ca/CA-FILE.pem"},
     {certfile, "/marker/leaf/LEAF-CERT.pem"}, {keyfile, "/marker/leaf/LEAF-KEY.pem"}].

assert_no_config(Text) ->
    [?assertEqual(nomatch, string:find(Text, Marker)) || Marker <- ?CFG_MARKERS].

%%%===================================================================
%%% Host names
%%%===================================================================

%% RFC 6761: `.invalid' never resolves. The channel must report a word and keep
%% trying, within the connect timeout, whatever the resolver does about it.
unresolvable_host_fails_fast(#{name := Name}) ->
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{http, "yuzu-gw-no-such-host.invalid", 50051, []}],
                   #{pool_size => 1, connect_timeout => 500}}, true),
    {ok, Pid} = yuzu_grpc_client_channel:start_link(Cfg),
    T0 = erlang:monotonic_time(millisecond),
    ok = wait_for(fun() -> last_error(Name) =/= no_connection_yet end),
    Elapsed = erlang:monotonic_time(millisecond) - T0,
    Why = last_error(Name),
    ?assert(is_atom(Why)),
    ?assertEqual({error, Why}, yuzu_grpc_client_channel:pick(Name, 0)),
    ?assertEqual({error, Why}, yuzu_grpc_client:unary(#{}, ?HEARTBEAT, #{session_id => <<"ok">>},
                                                      def(), #{channel => Name, timeout => 5000})),
    %% the connect timeout (500 ms) plus the time to notice, not the resolver's own
    ?assert(Elapsed < 3000),
    ?assertEqual(Pid, whereis(Name)),
    ?assertEqual([], up_slots(Name)).

%% The lookup is bounded by the same timeout as the connect: an unanswered
%% resolver would otherwise hold a slot `connecting' for as long as the resolver
%% takes (gun's default is `infinity'). Read from the connection itself.
connections_carry_the_lookup_timeout(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{pool_size => 1, connect_timeout => 2345}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    [Conn] = up_slots(Name),
    Opts = find_opts(sys:get_state(Conn)),
    ?assertMatch(#{connect_timeout := 2345, domain_lookup_timeout := 2345}, Opts).

%% The options map of a gun connection, found by shape in its state.
find_opts(#{protocols := _, connect_timeout := _} = Opts) -> Opts;
find_opts(Map) when is_map(Map) -> find_opts(maps:values(Map));
find_opts(Tuple) when is_tuple(Tuple) -> find_opts(tuple_to_list(Tuple));
find_opts([H | T]) ->
    case find_opts(H) of
        undefined -> find_opts(T);
        Found     -> Found
    end;
find_opts(_) ->
    undefined.

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

%% A TLS channel to the port, linked to the test process, without waiting for it.
%% The endpoint does not verify the server: what these tests need from the
%% handshake is its timing, not its certificate.
start_tls(Name, Port, Options) ->
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{https, "127.0.0.1", Port, [{verify, verify_none}]}], Options}, true),
    {ok, Pid} = yuzu_grpc_client_channel:start_link(Cfg),
    Pid.

%% A TCP listener that is not a gRPC server: each connection is accepted, held
%% for HoldMs milliseconds without a byte either way (`infinity': until the
%% listener is gone), then closed. Kept in the fixture's table for cleanup.
start_raw_listener(#{listeners := Tab}, HoldMs) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}}, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    Acceptor = spawn(fun() -> raw_accept(Listen, HoldMs) end),
    ets:insert(Tab, {raw, Listen, Acceptor}),
    Port.

raw_accept(Listen, HoldMs) ->
    Acceptor = self(),
    case gen_tcp:accept(Listen) of
        {ok, Socket} ->
            Holder = spawn(fun() ->
                               erlang:monitor(process, Acceptor),
                               receive
                                   {'DOWN', _, process, _, _} -> ok
                               after HoldMs -> ok
                               end,
                               gen_tcp:close(Socket)
                           end),
            ok = gen_tcp:controlling_process(Socket, Holder),
            raw_accept(Listen, HoldMs);
        {error, _} ->
            ok
    end.

%% An https endpoint whose CA file does not exist. A raw listening socket lets the
%% TCP connect succeed, so the failure is the TLS options being rejected, as it is
%% against a real server: every attempt then fails in about 2 ms.
unusable_ca_is_reported(#{name := Name}) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}]),
    {ok, Port} = inet:port(Listen),
    Missing = "/nonexistent/yuzu_test_ca.pem",
    Ssl = [{verify, verify_peer}, {cacertfile, Missing},
           {keyfile, "/marker/private/KEY-aa77.pem"}],
    {ok, Cfg} = yuzu_grpc_client_config:channel({Name, [{https, "localhost", Port, Ssl}], #{}}, true),
    application:set_env(yuzu_gw, upstream_client,
                        #{channels => [{Name, [{https, "localhost", Port, Ssl}], #{}}]}),
    try
        {_, Text} = capture(
                      fun() ->
                          {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
                          ok = wait_for(fun() ->
                                            yuzu_grpc_client_channel:config_error(Name) =/= none
                                        end),
                          %% several attempts have failed, yet one line was logged
                          ok = wait_for(fun() -> slot_fails(Name, 1) >= 3 end)
                      end),
        ?assertEqual([{cacertfile, Missing, enoent}, {keyfile, undefined, enoent}],
                     yuzu_grpc_client_channel:config_error(Name)),
        {match, _} = re:run(Text, "TLS client options cannot be used", [unicode]),
        {match, _} = re:run(Text, "cacertfile " ++ Missing ++ " does not exist", [unicode]),
        {match, _} = re:run(Text, "keyfile does not exist", [unicode]),
        %% the line this channel writes names no key path (OTP's own ssl progress
        %% reports do, a separate known gap; those are not this line)
        {match, [{Start, _}]} = re:run(Text, "TLS client options cannot be used", [unicode]),
        Own = lists:sublist(Text, Start + 1, 400),
        [OwnLine | _] = string:split(Own, "\n"),
        nomatch = re:run(OwnLine, "KEY-aa77", [unicode]),
        ?assertEqual(1, length(re:split(Text, "TLS client options cannot be used", [unicode])) - 1),
        ?assertEqual({<<"upstream_tls_files">>, false}, yuzu_gw_health:check_upstream_tls_files())
    after
        application:unset_env(yuzu_gw, upstream_client),
        gen_tcp:close(Listen)
    end.

%% The row means "the most recent attempt failed because the options are
%% unusable", so an attempt that fails otherwise (here the CA now exists and the
%% peer never answers the handshake) clears it, and /readyz with it.
unusable_ca_report_clears(S) ->
    case yuzu_gw_authz_tests:setup_certs() of
        #{ca := Cert} = Certs ->
            try unusable_ca_report_clears(S, Cert)
            after yuzu_gw_authz_tests:cleanup_certs(Certs)
            end;
        {error, Why} ->
            io:format(user, "SKIPPED unusable_ca_report_clears: openssl certificates "
                      "unavailable: ~p~n", [Why])
    end.

unusable_ca_report_clears(#{name := Name}, Cert) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}]),
    {ok, Port} = inet:port(Listen),
    Dir = "/tmp/yuzu_test_chan_ca_" ++ integer_to_list(erlang:unique_integer([positive])),
    ok = filelib:ensure_path(Dir),
    Ca = filename:join(Dir, "ca.pem"),
    Ssl = [{verify, verify_peer}, {cacertfile, Ca}],
    Endpoint = {https, "localhost", Port, Ssl},
    {ok, Cfg} = yuzu_grpc_client_config:channel({Name, [Endpoint], #{connect_timeout => 300}}, true),
    application:set_env(yuzu_gw, upstream_client,
                        #{channels => [{Name, [Endpoint], #{connect_timeout => 300}}]}),
    try
        {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
        ok = wait_for(fun() -> yuzu_grpc_client_channel:config_error(Name) =/= none end),
        ?assertEqual({<<"upstream_tls_files">>, false}, yuzu_gw_health:check_upstream_tls_files()),
        {ok, _} = file:copy(Cert, Ca),
        ok = wait_for(fun() -> yuzu_grpc_client_channel:config_error(Name) =:= none end),
        ?assertEqual({<<"upstream_tls_files">>, true}, yuzu_gw_health:check_upstream_tls_files())
    after
        application:unset_env(yuzu_gw, upstream_client),
        gen_tcp:close(Listen),
        file:del_dir_r(Dir)
    end.

plaintext_channel_has_no_config_error(#{name := Name} = S) ->
    Port = yuzu_gw_test_listener:probe_free_port(),
    start_listener(S, Port),
    start(Name, Port, #{}),
    ok = wait_for(fun() -> length(up_slots(Name)) =:= 1 end),
    application:set_env(yuzu_gw, upstream_client,
                        #{channels => [{Name, [{http, "localhost", Port, []}], #{}}]}),
    try
        ?assertEqual(none, yuzu_grpc_client_channel:config_error(Name)),
        ?assertEqual({<<"upstream_tls_files">>, true}, yuzu_gw_health:check_upstream_tls_files())
    after
        application:unset_env(yuzu_gw, upstream_client)
    end.

%% The slot record is private to the channel; these are the positions in the
%% state (#st{name, cfg, slots, by_pid, waiters}) and in a slot (#slot{id,
%% endpoint, pid, fails, timer}) that the backoff tests read and set, with the
%% record tags checked so a change of layout fails here and says so.
slots(Name) ->
    State = sys:get_state(Name),
    st = element(1, State),
    element(4, State).

slot_fails(Name, Id) ->
    Slot = maps:get(Id, slots(Name)),
    slot = element(1, Slot),
    element(5, Slot).

set_fails(Name, Id, Fails) ->
    _ = sys:replace_state(Name,
                          fun(State) ->
                              Slots = element(4, State),
                              Slot = maps:get(Id, Slots),
                              setelement(4, State, Slots#{Id := setelement(5, Slot, Fails)})
                          end),
    ok.

%% What sys:get_status/1 shows of the channel's state (format_status/1's map),
%% and its number of registered waiters.
shown_state(Name) ->
    find_shape(sys:get_status(Name)).

waiters(Name) ->
    #{waiters := N} = shown_state(Name),
    N.

find_shape(#{channel := _, slots := _, waiters := _} = Shape) -> Shape;
find_shape(Map) when is_map(Map) -> find_shape(maps:values(Map));
find_shape(Tuple) when is_tuple(Tuple) -> find_shape(tuple_to_list(Tuple));
find_shape([H | T]) ->
    case find_shape(H) of
        undefined -> find_shape(T);
        Found     -> Found
    end;
find_shape(_) ->
    undefined.

last_error(Name) ->
    ets:lookup_element(Name, last_error, 2).

slot_status(Name, Id) ->
    ets:lookup_element(Name, {slot, Id}, 3).

%% The reconnect timer of the slot (#slot{timer}), `undefined' when none is set.
slot_timer(Name, Id) ->
    Slot = maps:get(Id, slots(Name)),
    slot = element(1, Slot),
    element(6, Slot).

%% Every log event Fun causes, rendered as text (event, metadata and report), up
%% to a quiet 300 ms after it returns: a crash report is written by the dying
%% process, which may be a moment behind. Returns {FunResult, Text}.
capture(Fun) ->
    Id = yuzu_grpc_client_channel_tests_handler,
    Primary = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(Id, ?MODULE, #{level => all, config => #{pid => self()}}),
    try
        Result = Fun(),
        {Result, lists:flatten(drain_captured([]))}
    after
        ok = logger:remove_handler(Id),
        ok = logger:set_primary_config(level, Primary)
    end.

drain_captured(Acc) ->
    receive
        {captured, Event} ->
            drain_captured([io_lib:format("~0p~n", [Event]) | Acc])
    after 300 ->
        lists:reverse(Acc)
    end.

%% logger handler callback: runs in the logging process.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {captured, Event},
    ok.

drain_exits() ->
    receive {'EXIT', _, _} -> drain_exits() after 0 -> ok end.

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
