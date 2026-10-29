%%%-------------------------------------------------------------------
%%% @doc The upstream gRPC client (yuzu_grpc_client over
%%% yuzu_grpc_client_channel, gun) over TLS, against a real listener
%%% (yuzu_grpc_listener, TLS 1.2) serving the stub AgentService.
%%%
%%% Certificates are minted with the openssl CLI by yuzu_gw_authz_tests, as the
%%% other TLS suites do; without openssl these tests contribute nothing unless
%%% YUZU_REQUIRE_TLS_TESTS=1, which makes the missing toolchain a failure.
%%%
%%% What is pinned:
%%%   - one-way TLS with verify_peer and a CA file works, and so does a
%%%     verify_none client (the posture yuzu_gw_app's boot guard warns about);
%%%   - a certificate for another name, or from a CA the client does not trust,
%%%     fails the connection with a `{tls_alert, _}' term from pick/2 and from
%%%     unary/5, the handler never runs, and nothing falls back to plaintext:
%%%     an https channel to a plaintext listener fails too;
%%%   - mutual TLS: a client certificate is presented and seen by the handler;
%%%     a client without one is refused, and the handler never runs;
%%%   - TCP_NODELAY reaches the live socket of a TLS connection and of a
%%%     plaintext one, and an operator's `{nodelay, false}' wins on both;
%%%   - a response over the channel's `max_receive_message_bytes' fails the
%%%     call with `response_too_large' and the channel stays usable;
%%%   - a failed TLS connection puts no key or certificate path, and no key
%%%     material, in an error term or a log line;
%%%   - a caller that finds no connection up while a TLS handshake is still in
%%%     progress (here delayed by a relay in front of the listener) is handed the
%%%     connection as soon as it comes up, not left to wait out its timeout.
%%%
%%% Nothing sleeps to make an assertion true: the waits are bounded retry loops
%%% on the channel's table rows.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_tls_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(WAIT_ATTEMPTS, 400).
-define(LOG_HANDLER, yuzu_grpc_client_tls_tests_log).
-define(LOG_TAB, yuzu_grpc_client_tls_tests_log_tab).

tls_test_() ->
    {setup,
     fun setup/0,
     fun cleanup/1,
     fun(State) ->
        case State of
            #{} ->
                [{"one-way TLS, verify_peer + cacertfile: a call succeeds",
                  fun() -> oneway_ok(State) end},
                 {"one-way TLS: a verify_none client connects too",
                  fun() -> verify_none_ok(State) end},
                 {"hostname mismatch: {tls_alert, _} from pick/2 and unary/5, handler never runs",
                  {timeout, 30, fun() -> hostname_mismatch(State) end}},
                 {"unknown CA: {tls_alert, unknown_ca}, handler never runs",
                  {timeout, 30, fun() -> unknown_ca(State) end}},
                 {"no plaintext fallback: an https channel to a plaintext listener fails",
                  {timeout, 30, fun() -> https_to_plaintext(State) end}},
                 {"no plaintext fallback: a plaintext channel to a TLS listener fails",
                  {timeout, 30, fun() -> http_to_tls(State) end}},
                 {"a TLS failure is classified as a handshake failure by the upstream",
                  {timeout, 30, fun() -> failure_is_classified(State) end}},
                 {"mTLS: the client certificate is presented and the handler sees it",
                  fun() -> mtls_ok(State) end},
                 {"mTLS: a client without a certificate is refused and the handler never runs",
                  {timeout, 30, fun() -> mtls_no_cert(State) end}},
                 {"TCP_NODELAY is on a live TLS socket by default",
                  fun() -> nodelay_tls_default(State) end},
                 {"an operator's {nodelay, false} wins on a TLS socket",
                  fun() -> nodelay_tls_operator_false(State) end},
                 {"an operator's {nodelay, false} wins on a plaintext socket",
                  fun() -> nodelay_plain_operator_false(State) end},
                 {"TCP_NODELAY is on a live plaintext socket by default",
                  fun() -> nodelay_plain_default(State) end},
                 {"a response over max_receive_message_bytes is {error, response_too_large}; the channel stays usable",
                  {timeout, 30, fun() -> oversized_response(State) end}},
                 {"a response within the limit passes",
                  fun() -> response_within_limit(State) end},
                 {"a failed TLS connection leaks no key path and no key material",
                  {timeout, 30, fun() -> failure_leaks_nothing(State) end}},
                 {"pick/2 during a slow TLS handshake returns the connection as soon as it is up",
                  {timeout, 30, fun() -> pick_waits_for_a_connecting_slot(State) end}},
                 {"a first call during a slow TLS handshake succeeds once the connection is up",
                  {timeout, 30, fun() -> first_call_waits_for_a_connecting_slot(State) end}}];
            {error, Why} ->
                yuzu_gw_authz_tests:certs_unavailable("yuzu_grpc_client_tls_tests", Why)
        end
     end}.

%%%-------------------------------------------------------------------
%%% Fixture
%%%-------------------------------------------------------------------

setup() ->
    case yuzu_gw_authz_tests:setup_certs() of
        {error, _} = E ->
            E;
        Certs = #{dir := Dir, ca := Ca} ->
            {ok, _} = application:ensure_all_started(gun),
            {ok, _} = application:ensure_all_started(ssl),
            {ok, _} = application:ensure_all_started(cowboy),
            {ok, _} = application:ensure_all_started(telemetry),
            yuzu_grpc_stub_svc:init_state(),
            Tls = #{certfile => filename:join(Dir, "gw.pem"), keyfile => filename:join(Dir, "gw.key"),
                    cacertfile => Ca},
            Base = #{service_protos => [agent_pb], services => #{?SVC => yuzu_grpc_stub_svc}},
            {PlainPort, PlainPid} = yuzu_gw_test_listener:start(Base#{name => cli_tls_plain}),
            {OnePort, OnePid} = yuzu_gw_test_listener:start(
                                  Base#{name => cli_tls_oneway,
                                        tls => Tls#{verify => verify_none, fail_if_no_peer_cert => false}}),
            {MutualPort, MutualPid} = yuzu_gw_test_listener:start(Base#{name => cli_tls_mutual, tls => Tls}),
            #{certs => Certs, counter => counters:new(1, []),
              plain_port => PlainPort, oneway_port => OnePort, mutual_port => MutualPort,
              listeners => [PlainPid, OnePid, MutualPid]}
    end.

cleanup({error, _}) ->
    ok;
cleanup(#{certs := Certs, listeners := Listeners}) ->
    [yuzu_gw_test_listener:stop(P) || P <- Listeners],
    yuzu_gw_authz_tests:cleanup_certs(Certs),
    ok.

%% A verifying client's ssl options; Leaf =:= undefined presents no certificate.
ssl_opts(#{dir := Dir, ca := Ca}, Leaf) ->
    Base = [{cacertfile, Ca}, {verify, verify_peer}, {versions, ['tlsv1.2']},
            {server_name_indication, "localhost"}],
    case Leaf of
        undefined -> Base;
        _ -> Base ++ [{certfile, filename:join(Dir, Leaf ++ ".pem")},
                      {keyfile, filename:join(Dir, Leaf ++ ".key")}]
    end.

%%%-------------------------------------------------------------------
%%% Success
%%%-------------------------------------------------------------------

oneway_ok(#{certs := Certs, oneway_port := Port} = S) ->
    with_channel(S, https, Port, ssl_opts(Certs, undefined), #{}, #{},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name, <<"ok">>)),
                     %% one-way TLS: the handler sees no client certificate
                     {ok, #{pending_commands := [#{action := Cert}]}, _} = heartbeat(Name, <<"ctx">>),
                     ?assertEqual(<<"no-cert">>, Cert)
                 end).

verify_none_ok(#{oneway_port := Port} = S) ->
    with_channel(S, https, Port, [{verify, verify_none}, {versions, ['tlsv1.2']}], #{}, #{},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name, <<"ok">>))
                 end).

mtls_ok(#{certs := Certs, mutual_port := Port} = S) ->
    with_channel(S, https, Port, ssl_opts(Certs, "agent"), #{}, #{},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     {ok, #{pending_commands := [#{action := Cert}]}, _} = heartbeat(Name, <<"ctx">>),
                     ?assertEqual(<<"cert">>, Cert)
                 end).

%%%-------------------------------------------------------------------
%%% Failure
%%%-------------------------------------------------------------------

hostname_mismatch(#{certs := Certs, oneway_port := Port} = S) ->
    yuzu_grpc_stub_svc:reset(),
    Ssl = lists:keystore(server_name_indication, 1, ssl_opts(Certs, undefined),
                         {server_name_indication, "other.example.test"}),
    with_channel(S, https, Port, Ssl, #{}, #{},
                 fun(Name) ->
                     {tls_alert, _} = wait_tls_failure(Name),
                     ?assertMatch({error, {tls_alert, _}}, yuzu_grpc_client_channel:pick(Name, 1000)),
                     ?assertMatch({error, {tls_alert, _}}, heartbeat(Name, <<"ok">>)),
                     ?assertEqual([], up_slots(Name)),
                     ?assertEqual(0, yuzu_grpc_stub_svc:calls())
                 end).

unknown_ca(#{certs := #{selfs_pem := Selfs} = Certs, oneway_port := Port} = S) ->
    yuzu_grpc_stub_svc:reset(),
    %% trust only an unrelated certificate: the gateway's chain does not lead to it
    Ssl = lists:keystore(cacertfile, 1, ssl_opts(Certs, undefined), {cacertfile, Selfs}),
    with_channel(S, https, Port, Ssl, #{}, #{},
                 fun(Name) ->
                     ?assertEqual({tls_alert, unknown_ca}, wait_tls_failure(Name)),
                     ?assertEqual({error, {tls_alert, unknown_ca}},
                                  yuzu_grpc_client_channel:pick(Name, 1000)),
                     ?assertEqual({error, {tls_alert, unknown_ca}}, heartbeat(Name, <<"ok">>)),
                     ?assertEqual([], up_slots(Name)),
                     ?assertEqual(0, yuzu_grpc_stub_svc:calls())
                 end).

https_to_plaintext(#{certs := Certs, plain_port := Port} = S) ->
    yuzu_grpc_stub_svc:reset(),
    with_channel(S, https, Port, ssl_opts(Certs, undefined), #{}, #{},
                 fun(Name) ->
                     ok = wait_for(fun() -> last_error(Name) =/= no_connection_yet end),
                     ?assertEqual([], up_slots(Name)),
                     ?assertMatch({error, _}, heartbeat(Name, <<"ok">>)),
                     ?assertEqual([], up_slots(Name)),
                     ?assertEqual(0, yuzu_grpc_stub_svc:calls())
                 end).

http_to_tls(#{oneway_port := Port} = S) ->
    yuzu_grpc_stub_svc:reset(),
    with_channel(S, http, Port, [], #{}, #{},
                 fun(Name) ->
                     %% the TLS listener never speaks HTTP/2 in the clear
                     R = heartbeat(Name, <<"ok">>),
                     ?assertMatch({error, _}, R),
                     ?assertEqual(0, yuzu_grpc_stub_svc:calls())
                 end).

failure_is_classified(#{certs := #{selfs_pem := Selfs} = Certs, oneway_port := Port} = S) ->
    Ssl = lists:keystore(cacertfile, 1, ssl_opts(Certs, undefined), {cacertfile, Selfs}),
    with_channel(S, https, Port, Ssl, #{}, #{},
                 fun(Name) ->
                     _ = wait_tls_failure(Name),
                     {error, Reason} = heartbeat(Name, <<"ok">>),
                     %% R-3 (#1243): the term the call fails with is read as a TLS handshake failure
                     ?assertEqual({true, <<"unknown_ca">>}, yuzu_gw_upstream:classify_tls_error(Reason)),
                     ?assertEqual({true, <<"unknown_ca">>},
                                  yuzu_gw_upstream:classify_tls_error({error, Reason}))
                 end).

mtls_no_cert(#{certs := Certs, mutual_port := Port} = S) ->
    yuzu_grpc_stub_svc:reset(),
    with_channel(S, https, Port, ssl_opts(Certs, undefined), #{}, #{},
                 fun(Name) ->
                     {tls_alert, _} = wait_tls_failure(Name),
                     ?assertMatch({error, {tls_alert, _}}, heartbeat(Name, <<"ok">>)),
                     ?assertEqual([], up_slots(Name)),
                     ?assertEqual(0, yuzu_grpc_stub_svc:calls())
                 end).

%%%-------------------------------------------------------------------
%%% TCP_NODELAY on live sockets
%%%-------------------------------------------------------------------

nodelay_tls_default(#{certs := Certs, oneway_port := Port} = S) ->
    with_channel(S, https, Port, ssl_opts(Certs, undefined), #{}, #{},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     Socks = [socket_of(P) || P <- up_slots(Name)],
                     ?assertEqual(2, length(Socks)),
                     [?assertEqual({ok, [{nodelay, true}]}, ssl:getopts(Sock, [nodelay]))
                      || Sock <- Socks]
                 end).

nodelay_tls_operator_false(#{certs := Certs, oneway_port := Port} = S) ->
    with_channel(S, https, Port, ssl_opts(Certs, undefined),
                 #{socket_options => [{nodelay, false}]}, #{},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     Socks = [socket_of(P) || P <- up_slots(Name)],
                     ?assertEqual(2, length(Socks)),
                     [?assertEqual({ok, [{nodelay, false}]}, ssl:getopts(Sock, [nodelay]))
                      || Sock <- Socks],
                     ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name, <<"ok">>))
                 end).

nodelay_plain_default(#{plain_port := Port} = S) ->
    with_channel(S, http, Port, [], #{}, #{},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     [?assertEqual({ok, [{nodelay, true}]}, inet:getopts(socket_of(P), [nodelay]))
                      || P <- up_slots(Name)]
                 end).

nodelay_plain_operator_false(#{plain_port := Port} = S) ->
    with_channel(S, http, Port, [], #{socket_options => [{nodelay, false}]}, #{},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     [?assertEqual({ok, [{nodelay, false}]}, inet:getopts(socket_of(P), [nodelay]))
                      || P <- up_slots(Name)]
                 end).

socket_of(Pid) ->
    #{socket := Sock} = gun:info(Pid),
    Sock.

%%%-------------------------------------------------------------------
%%% Response size limit
%%%-------------------------------------------------------------------

oversized_response(#{certs := Certs, oneway_port := OnePort, plain_port := PlainPort} = S) ->
    [with_channel(S, Scheme, Port, Ssl, #{}, #{max_receive_message_bytes => 1024},
                  fun(Name) ->
                      ok = wait_up(Name, 2),
                      Before = lists:sort(up_slots(Name)),
                      ?assertEqual({error, response_too_large}, heartbeat(Name, <<"big">>)),
                      ?assertEqual({error, response_too_large}, heartbeat(Name, <<"big">>)),
                      %% the channel is untouched and still serves calls
                      ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Name, <<"ok">>)),
                      ?assertMatch({error, {<<"3">>, _}, _}, heartbeat(Name, <<"nonsense">>)),
                      ?assertEqual(Before, lists:sort(up_slots(Name))),
                      [?assert(is_process_alive(P)) || P <- Before],
                      ?assertEqual(1024, yuzu_grpc_client_channel:max_receive(Name))
                  end)
     || {Scheme, Port, Ssl} <- [{https, OnePort, ssl_opts(Certs, undefined)}, {http, PlainPort, []}]],
    ok.

response_within_limit(#{plain_port := Port} = S) ->
    with_channel(S, http, Port, [], #{}, #{max_receive_message_bytes => 8192},
                 fun(Name) ->
                     ok = wait_up(Name, 2),
                     {ok, #{pending_commands := [#{plugin := Plugin}]}, _} = heartbeat(Name, <<"big">>),
                     ?assertEqual(4096, byte_size(Plugin))
                 end).

%%%-------------------------------------------------------------------
%%% Nothing leaks
%%%-------------------------------------------------------------------

%% The client is configured with a key and a certificate and fails for another
%% reason (a certificate for the wrong name). Neither the paths nor the key
%% itself may appear in an error the caller sees, in the table, or in a log line.
failure_leaks_nothing(#{certs := #{dir := Dir} = Certs, mutual_port := Port} = S) ->
    {ok, Key} = file:read_file(filename:join(Dir, "agent.key")),
    Ssl = lists:keystore(server_name_indication, 1, ssl_opts(Certs, "agent"),
                         {server_name_indication, "other.example.test"}),
    ?assertMatch({_, _}, binary:match(Key, <<"PRIVATE KEY">>)),
    Seen = capture_logs(
             fun() ->
                 with_channel(S, https, Port, Ssl, #{}, #{},
                              fun(Name) ->
                                  _ = wait_tls_failure(Name),
                                  Terms = [yuzu_grpc_client_channel:pick(Name, 1000),
                                           heartbeat(Name, <<"ok">>),
                                           last_error(Name),
                                           ets:tab2list(Name)
                                           -- [{rr, ets:lookup_element(Name, rr, 2)}]],
                                  [assert_no_secret(T, Dir, Key) || T <- Terms],
                                  %% give the channel's own log line and ssl's a chance to be written
                                  _ = sys:get_state(Name)
                              end)
             end),
    ?assert(length(Seen) > 0),
    %% The capture is global, so it also holds what other processes log while it
    %% runs: ssl's reports print the option sets they were given (a listener's
    %% CA path, for one), and whatever else the suite has running. What this test
    %% owns is the CHANNEL's line and everything about the CLIENT's key: no log
    %% line may carry the client's key file name or key material, and the lines
    %% the channel itself writes may not carry the certificate directory either.
    [assert_no_key(L, Key) || L <- Seen],
    Own = [L || L <- Seen, string:find(L, "Upstream channel") =/= nomatch],
    ?assert(length(Own) > 0),
    [assert_no_secret(L, Dir, Key) || L <- Own].

assert_no_key(Term, Key) ->
    Text = unicode:characters_to_binary(io_lib:format("~0p", [Term])),
    ?assertEqual(nomatch, binary:match(Text, <<"agent.key">>)),
    ?assertEqual(nomatch, binary:match(Text, <<"PRIVATE KEY">>)),
    ?assertEqual(nomatch, binary:match(Text, binary:part(Key, 40, 40))).

assert_no_secret(Term, Dir, Key) ->
    Text = unicode:characters_to_binary(io_lib:format("~0p", [Term])),
    ?assertEqual(nomatch, binary:match(Text, list_to_binary(Dir))),
    ?assertEqual(nomatch, binary:match(Text, <<"agent.key">>)),
    ?assertEqual(nomatch, binary:match(Text, <<"PRIVATE KEY">>)),
    ?assertEqual(nomatch, binary:match(Text, binary:part(Key, 40, 40))).

capture_logs(Fun) ->
    ?LOG_TAB = ets:new(?LOG_TAB, [named_table, public, bag]),
    Level = maps:get(level, logger:get_primary_config()),
    catch logger:remove_handler(?LOG_HANDLER),
    ok = logger:set_primary_config(level, all),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE, #{config => #{}, level => all}),
    try
        Fun(),
        [L || {L} <- ets:tab2list(?LOG_TAB)]
    after
        catch logger:remove_handler(?LOG_HANDLER),
        logger:set_primary_config(level, Level),
        ets:delete(?LOG_TAB)
    end.

%% logger handler callback. OTP's own supervisor PROGRESS reports are left out: at
%% level info, ssl's connection supervisors print the whole option set of every
%% TLS connection they start, key file paths included, whether it succeeds or
%% not. That is OTP's output, not this client's, and it is not tied to a
%% failure; this test is about what the client and the channel log.
log(#{msg := {report, #{label := {supervisor, progress}}}}, _Config) ->
    ok;
log(#{msg := Msg, meta := Meta}, _Config) ->
    ets:insert(?LOG_TAB, {lists:flatten(io_lib:format("~tp ~tp", [format(Msg), Meta]))}),
    ok.

format({string, S}) -> io_lib:format("~ts", [S]);
format({report, R}) -> io_lib:format("~p", [R]);
format({Fmt, Args}) -> io_lib:format(Fmt, Args).

%%%-------------------------------------------------------------------
%%% A caller that arrives while a connection is being opened
%%%-------------------------------------------------------------------

%% The connection is opened by the channel process, so gun's gun_up goes to the
%% channel and to nobody else: a caller can only learn the connection is up from
%% the channel. The relay holds the handshake for 1.2 s, so the channel has one
%% slot `connecting' and none up when the caller comes.
pick_waits_for_a_connecting_slot(#{certs := Certs, oneway_port := Port} = S) ->
    with_delay_relay(Port, 1200, fun(RelayPort) ->
        with_channel(S, https, RelayPort, ssl_opts(Certs, undefined), #{}, #{pool_size => 1},
                     fun(Name) ->
                         ?assertEqual([], up_slots(Name)),
                         T0 = erlang:monotonic_time(millisecond),
                         Result = yuzu_grpc_client_channel:pick(Name, 4000),
                         Elapsed = erlang:monotonic_time(millisecond) - T0,
                         ?assertMatch({ok, _}, Result),
                         {ok, Conn} = Result,
                         %% woken by the connection coming up, not by the 4 s timeout
                         ?assert(Elapsed < 3000),
                         ?assertEqual([Conn], up_slots(Name)),
                         ?assert(is_process_alive(Conn))
                     end)
    end).

first_call_waits_for_a_connecting_slot(#{certs := Certs, oneway_port := Port} = S) ->
    with_delay_relay(Port, 1200, fun(RelayPort) ->
        with_channel(S, https, RelayPort, ssl_opts(Certs, undefined), #{}, #{pool_size => 1},
                     fun(Name) ->
                         ?assertEqual([], up_slots(Name)),
                         T0 = erlang:monotonic_time(millisecond),
                         Result = heartbeat(Name, <<"ok">>),
                         Elapsed = erlang:monotonic_time(millisecond) - T0,
                         ?assertMatch({ok, #{acknowledged := true}, _}, Result),
                         ?assert(Elapsed < 4000),
                         ?assertEqual(1, length(up_slots(Name)))
                     end)
    end).

%% A TCP relay in front of a listener that holds each connection for DelayMs
%% before it connects to the target and passes bytes both ways: the client's
%% connect succeeds at once (the kernel accepts it) and its TLS handshake
%% completes DelayMs later. Fun gets the relay's port.
with_delay_relay(TargetPort, DelayMs, Fun) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {ip, {127, 0, 0, 1}}, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(Listen),
    Acceptor = spawn(fun() -> relay_accept(Listen, TargetPort, DelayMs) end),
    try
        Fun(Port)
    after
        exit(Acceptor, kill),
        catch gen_tcp:close(Listen)
    end.

relay_accept(Listen, TargetPort, DelayMs) ->
    case gen_tcp:accept(Listen) of
        {ok, Client} ->
            Self = self(),
            Pid = spawn(fun() ->
                            receive {socket, Client} -> relay(Client, TargetPort, DelayMs, Self) end
                        end),
            ok = gen_tcp:controlling_process(Client, Pid),
            Pid ! {socket, Client},
            relay_accept(Listen, TargetPort, DelayMs);
        {error, _} ->
            ok
    end.

relay(Client, TargetPort, DelayMs, Acceptor) ->
    erlang:monitor(process, Acceptor),
    receive after DelayMs -> ok end,
    case gen_tcp:connect({127, 0, 0, 1}, TargetPort, [binary, {active, false}]) of
        {ok, Target} ->
            ok = inet:setopts(Client, [{active, once}]),
            ok = inet:setopts(Target, [{active, once}]),
            relay_loop(Client, Target);
        {error, _} ->
            gen_tcp:close(Client)
    end.

relay_loop(Client, Target) ->
    receive
        {tcp, Client, Data} ->
            _ = gen_tcp:send(Target, Data),
            _ = inet:setopts(Client, [{active, once}]),
            relay_loop(Client, Target);
        {tcp, Target, Data} ->
            _ = gen_tcp:send(Client, Data),
            _ = inet:setopts(Target, [{active, once}]),
            relay_loop(Client, Target);
        {tcp_closed, _} -> relay_close(Client, Target);
        {tcp_error, _, _} -> relay_close(Client, Target);
        {'DOWN', _, process, _, _} -> relay_close(Client, Target)
    end.

relay_close(Client, Target) ->
    gen_tcp:close(Client),
    gen_tcp:close(Target).

%%%-------------------------------------------------------------------
%%% Helpers
%%%-------------------------------------------------------------------

%% Run Fun(Name) with a started channel of two connections to the port, and stop
%% the channel afterwards even if Fun fails. `Settings' is the endpoint's fifth
%% element, `Options' the channel's.
with_channel(#{counter := Counter}, Scheme, Port, Ssl, Settings, Options, Fun) ->
    counters:add(Counter, 1, 1),
    Name = list_to_atom("yuzu_cli_tls_chan_" ++ integer_to_list(counters:get(Counter, 1))),
    {ok, Cfg} = yuzu_grpc_client_config:channel(
                  {Name, [{Scheme, "localhost", Port, Ssl, Settings}],
                   maps:merge(#{pool_size => 2}, Options)}, true),
    {ok, _} = yuzu_grpc_client_channel:start_link(Cfg),
    try
        Fun(Name)
    after
        ok = yuzu_gw_test_listener:stop_channel(Name)
    end.

up_slots(Name) ->
    ets:select(Name, [{{{slot, '_'}, '$1', up}, [], ['$1']}]).

last_error(Name) ->
    ets:lookup_element(Name, last_error, 2).

wait_up(Name, Want) ->
    wait_for(fun() -> length(up_slots(Name)) =:= Want end).

%% Wait until the channel has recorded a TLS failure; returns the term.
wait_tls_failure(Name) ->
    ok = wait_for(fun() -> element(1, tuple_or_other(last_error(Name))) =:= tls_alert end),
    last_error(Name).

tuple_or_other(T) when is_tuple(T), tuple_size(T) > 0 -> T;
tuple_or_other(_) -> {other}.

wait_for(Fun) ->
    wait_for(Fun, ?WAIT_ATTEMPTS).

wait_for(_Fun, 0) ->
    {error, condition_not_met};
wait_for(Fun, N) ->
    case catch Fun() of
        true -> ok;
        _ -> receive after 25 -> ok end, wait_for(Fun, N - 1)
    end.

heartbeat(Name, Command) ->
    yuzu_grpc_client:unary(#{<<"x-test">> => <<"t">>}, ?HEARTBEAT, #{session_id => Command}, def(),
                           #{channel => Name, timeout => 5000}).

def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.
