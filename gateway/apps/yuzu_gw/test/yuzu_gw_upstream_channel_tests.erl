%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_upstream_channel: TCP_NODELAY on the
%%% gateway-to-server gRPC channel.
%%%
%%% Two layers. The pure endpoint rewrite (with_nodelay/2) is pinned case by
%%% case: an endpoint with no socket options gets nodelay, an operator's own
%%% socket options and an explicit nodelay entry survive, the switch off leaves
%%% the term identical, TLS options pass through untouched and only
%%% `default_channel' is rewritten. The runtime layer then starts the channel
%%% the way grpcbox does at boot (from the `{grpcbox, client}' env), runs
%%% apply_nodelay/0, forces the connect to a private listener and reads the
%%% option off the client's actual socket, for plaintext and for TLS (the
%%% endpoint's socket_options reach ssl:connect too). The control case shows the
%%% same read gives `false' on the stock channel, so the check measures the
%%% option and not a default.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_upstream_channel_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).

-define(LOG_HANDLER, yuzu_gw_upstream_channel_tests_log).
-define(LOG_TAB, yuzu_gw_upstream_channel_tests_log_tab).
-define(CH, default_channel).
-define(NODELAY, #{socket_options => [{nodelay, true}]}).

%%%===================================================================
%%% Pure rewrite
%%%===================================================================

endpoint_without_socket_options_gets_nodelay_test() ->
    ?assertEqual(client([{http, "gw", 50055, [], ?NODELAY}]),
                 yuzu_gw_upstream_channel:with_nodelay(client([{http, "gw", 50055, []}]), true)),
    %% The 5-tuple form with an empty settings map is rewritten the same way.
    ?assertEqual(client([{http, "gw", 50055, [], ?NODELAY}]),
                 yuzu_gw_upstream_channel:with_nodelay(
                   client([{http, "gw", 50055, [], #{}}]), true)).

operator_socket_options_are_kept_and_nodelay_added_test() ->
    In  = client([{http, "gw", 50055, [], #{socket_options => [{keepalive, true}, {sndbuf, 4096}],
                                            connect_timeout => 1234}}]),
    Out = client([{http, "gw", 50055, [], #{socket_options => [{keepalive, true}, {sndbuf, 4096},
                                                                {nodelay, true}],
                                            connect_timeout => 1234}}]),
    ?assertEqual(Out, yuzu_gw_upstream_channel:with_nodelay(In, true)).

operator_nodelay_entry_is_never_overridden_test() ->
    [begin
         In = client([{http, "gw", 50055, [], #{socket_options => Opts}}]),
         ?assertEqual(In, yuzu_gw_upstream_channel:with_nodelay(In, true))
     end || Opts <- [[{nodelay, false}], [{keepalive, true}, {nodelay, false}],
                     [{nodelay, true}], [nodelay]]].

switch_off_leaves_the_term_identical_test() ->
    In = client([{http, "gw", 50055, []},
                 {https, "gw2", 50056, [{verify, verify_peer}], #{socket_options => [{keepalive, true}]}}]),
    ?assertEqual(In, yuzu_gw_upstream_channel:with_nodelay(In, false)).

every_endpoint_of_the_channel_is_rewritten_test() ->
    Out = yuzu_gw_upstream_channel:with_nodelay(
            client([{http, "a", 1, []}, {http, "b", 2, [], #{}}, {http, "c", 3, [], ?NODELAY}]),
            true),
    ?assertEqual(client([{http, "a", 1, [], ?NODELAY}, {http, "b", 2, [], ?NODELAY},
                         {http, "c", 3, [], ?NODELAY}]), Out).

rewrite_is_idempotent_test() ->
    Once = yuzu_gw_upstream_channel:with_nodelay(client([{http, "gw", 50055, []}]), true),
    ?assertEqual(Once, yuzu_gw_upstream_channel:with_nodelay(Once, true)).

tls_options_pass_through_and_posture_is_unchanged_test() ->
    Ssl = [{verify, verify_peer}, {cacertfile, "/x/ca.pem"}, {server_name_indication, "gw"}],
    In  = client([{https, "gw", 50055, Ssl}]),
    Out = yuzu_gw_upstream_channel:with_nodelay(In, true),
    ?assertEqual(client([{https, "gw", 50055, Ssl, ?NODELAY}]), Out),
    ?assertEqual(verified, yuzu_gw_app:client_tls_posture(Out)),
    Unverified = yuzu_gw_upstream_channel:with_nodelay(client([{https, "gw", 50055, []}]), true),
    ?assertEqual(unverified, yuzu_gw_app:client_tls_posture(Unverified)).

only_the_upstream_channel_is_rewritten_test() ->
    Other = {other_channel, [{http, "x", 9, []}], #{balancer => random}},
    In  = #{channels => [Other, {?CH, [{http, "gw", 50055, []}], #{sync_start => true}}],
            marker => kept},
    Out = yuzu_gw_upstream_channel:with_nodelay(In, true),
    ?assertEqual(#{channels => [Other, {?CH, [{http, "gw", 50055, [], ?NODELAY}],
                                         #{sync_start => true}}],
                   marker => kept}, Out).

unexpected_shapes_pass_through_unchanged_test() ->
    Odd = [undefined, #{}, #{channels => not_a_list}, #{channels => []},
           client([{http, "gw", 50055, [], #{socket_options => not_a_list}}]),
           client([{unix, {local, "/s"}}]),
           #{channels => [{?CH, not_a_list, #{}}]}],
    [?assertEqual(T, yuzu_gw_upstream_channel:with_nodelay(T, true)) || T <- Odd].

%%%===================================================================
%%% Runtime: the option on the connected socket
%%%===================================================================

runtime_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [fun(S) -> {"control: the stock channel's socket has nodelay off", fun() -> control(S) end} end,
      fun(S) -> {"apply_nodelay/0 turns nodelay on for a channel started from sys.config",
                 fun() -> default_on(S) end} end,
      fun(S) -> {"the restart replaces the channel, orphans no subchannel, and the env carries the rewritten endpoint",
                 fun() -> env_follows(S) end} end,
      fun(S) -> {"an operator's socket options survive next to nodelay",
                 fun() -> operator_options(S) end} end,
      fun(S) -> {"an operator's nodelay=false is honoured and the channel is not restarted",
                 fun() -> operator_nodelay_false(S) end} end,
      fun(S) -> {"upstream_tcp_nodelay=false leaves the channel and the env alone",
                 fun() -> switched_off(S) end} end,
      fun(S) -> {"an invalid upstream_tcp_nodelay value falls back to the default (on)",
                 fun() -> invalid_switch(S) end} end,
      fun(S) -> {"no grpcbox client config is a no-op",
                 fun() -> no_client_config(S) end} end,
      fun(S) -> {"a failed restart warns; the restore of the original endpoints that works is silent",
                 fun() -> restart_fails_restore_works(S) end} end,
      fun(S) -> {"a failed restart whose restore fails too warns about the restore as well",
                 fun() -> restart_and_restore_fail(S) end} end]}.

control(S) ->
    Endpoint = {http, "127.0.0.1", port(S), []},
    boot_channel(Endpoint),
    ?assertEqual({ok, [{nodelay, false}]}, client_nodelay(S)).

default_on(S) ->
    Endpoint = {http, "127.0.0.1", port(S), []},
    boot_channel(Endpoint),
    ?assertEqual(ok, yuzu_gw_upstream_channel:apply_nodelay()),
    ?assertEqual({ok, [{nodelay, true}]}, client_nodelay(S)).

env_follows(S) ->
    Endpoint = {http, "127.0.0.1", port(S), []},
    boot_channel(Endpoint),
    Before = channel_pid(),
    ok = wait_ready(100),
    OldSubs = [P || {_, P} <- gproc_pool:active_workers(?CH)],
    ?assertMatch([_], OldSubs),
    ok = yuzu_gw_upstream_channel:apply_nodelay(),
    ?assertNotEqual(Before, channel_pid()),
    ?assertNot(is_process_alive(Before)),
    %% The old channel took its subchannel down with it: nothing is orphaned.
    ?assertEqual([], [P || P <- OldSubs, is_process_alive(P)]),
    {ok, #{channels := [{?CH, [Rewritten], #{}}]}} = application:get_env(grpcbox, client),
    ?assertEqual({http, "127.0.0.1", port(S), [], ?NODELAY}, Rewritten),
    ok = wait_ready(100),
    [{Rewritten, _}] = gproc_pool:active_workers(?CH).

operator_options(S) ->
    Endpoint = {http, "127.0.0.1", port(S), [], #{socket_options => [{keepalive, true}]}},
    boot_channel(Endpoint),
    ok = yuzu_gw_upstream_channel:apply_nodelay(),
    ?assertEqual({ok, [{nodelay, true}, {keepalive, true}]}, client_opts(S, [nodelay, keepalive])).

operator_nodelay_false(S) ->
    Endpoint = {http, "127.0.0.1", port(S), [], #{socket_options => [{nodelay, false}]}},
    boot_channel(Endpoint),
    Before = channel_pid(),
    ok = yuzu_gw_upstream_channel:apply_nodelay(),
    ?assertEqual(Before, channel_pid()),
    ?assertEqual({ok, [{nodelay, false}]}, client_nodelay(S)).

switched_off(S) ->
    Endpoint = {http, "127.0.0.1", port(S), []},
    {Client, _} = boot_channel(Endpoint),
    Before = channel_pid(),
    application:set_env(yuzu_gw, upstream_tcp_nodelay, false),
    ok = yuzu_gw_upstream_channel:apply_nodelay(),
    ?assertEqual(Before, channel_pid()),
    ?assertEqual({ok, Client}, application:get_env(grpcbox, client)),
    ?assertEqual({ok, [{nodelay, false}]}, client_nodelay(S)).

invalid_switch(S) ->
    Endpoint = {http, "127.0.0.1", port(S), []},
    boot_channel(Endpoint),
    application:set_env(yuzu_gw, upstream_tcp_nodelay, "no"),
    ok = yuzu_gw_upstream_channel:apply_nodelay(),
    ?assertEqual({ok, [{nodelay, true}]}, client_nodelay(S)).

%% The channel cannot start with the rewritten (nodelay) endpoints but starts
%% with the original ones: one WARN, for the restart, and the channel is back.
restart_fails_restore_works(S) ->
    Endpoint = {http, "127.0.0.1", port(S), []},
    boot_channel(Endpoint),
    with_failing_start(fun(Endpoints) -> lists:any(fun(E) -> tuple_size(E) =:= 5 end, Endpoints) end,
                       fun() -> ok = yuzu_gw_upstream_channel:apply_nodelay() end),
    ?assertEqual(1, length(warnings("could not restart it"))),
    ?assertEqual([], warnings("could not restore it")),
    ?assertMatch(P when is_pid(P), channel_pid()),
    %% The env is unchanged: the channel runs with the endpoints as configured.
    ?assertEqual({ok, #{channels => [{?CH, [Endpoint], #{}}]}},
                 application:get_env(grpcbox, client)).

%% Neither start works: the restart warns, and so does the restore, which is the
%% node left without an upstream channel.
restart_and_restore_fail(S) ->
    Endpoint = {http, "127.0.0.1", port(S), []},
    boot_channel(Endpoint),
    with_failing_start(fun(_Endpoints) -> true end,
                       fun() -> ok = yuzu_gw_upstream_channel:apply_nodelay() end),
    ?assertEqual(1, length(warnings("could not restart it"))),
    ?assertEqual(1, length(warnings("could not restore it"))),
    ?assertEqual(undefined, channel_pid()).

%% grpcbox_channel_sup:start_child/3 answers `{error, boom}' when Fails(Endpoints)
%% and starts the channel otherwise; the log is captured meanwhile.
with_failing_start(Fails, Run) ->
    ?LOG_TAB = ets:new(?LOG_TAB, [named_table, public, bag]),
    catch logger:remove_handler(?LOG_HANDLER),
    ok = logger:add_handler(?LOG_HANDLER, ?MODULE, #{config => #{}, level => all}),
    ok = meck:new(grpcbox_channel_sup, [passthrough, no_link]),
    try
        ok = meck:expect(grpcbox_channel_sup, start_child,
                         fun(Name, Endpoints, Options) ->
                                 case Fails(Endpoints) of
                                     true  -> {error, boom};
                                     false -> meck:passthrough([Name, Endpoints, Options])
                                 end
                         end),
        Run()
    after
        meck:unload(grpcbox_channel_sup),
        catch logger:remove_handler(?LOG_HANDLER)
    end.

warnings(Text) ->
    [M || {warning, M} <- ets:tab2list(?LOG_TAB), string:find(M, Text) =/= nomatch].

%% logger handler callback
log(#{level := Level, msg := Msg}, _Config) ->
    ets:insert(?LOG_TAB, {Level, lists:flatten(format(Msg))}),
    ok.

format({string, S}) -> io_lib:format("~ts", [S]);
format({report, R}) -> io_lib:format("~p", [R]);
format({Fmt, Args}) -> io_lib:format(Fmt, Args).

no_client_config(_S) ->
    application:unset_env(grpcbox, client),
    ?assertEqual(ok, yuzu_gw_upstream_channel:apply_nodelay()),
    application:set_env(grpcbox, client, #{channels => []}),
    ?assertEqual(ok, yuzu_gw_upstream_channel:apply_nodelay()).

%%%-------------------------------------------------------------------
%%% TLS: nodelay reaches ssl:connect through the endpoint's socket_options
%%%-------------------------------------------------------------------

tls_runtime_test_() ->
    {setup,
     fun() -> yuzu_gw_authz_tests:setup_certs(tmp_base()) end,
     fun yuzu_gw_authz_tests:cleanup_certs/1,
     fun(#{} = Certs) ->
             {foreach,
              fun() -> setup_tls(Certs) end,
              fun cleanup/1,
              [fun(S) -> {"TLS control: nodelay is off on the stock https channel",
                          fun() -> tls_control(Certs, S) end} end,
               fun(S) -> {"TLS: apply_nodelay/0 turns nodelay on for a verified https channel",
                          fun() -> tls_on(Certs, S) end} end]};
        ({error, Why}) ->
             yuzu_gw_authz_tests:certs_unavailable("yuzu_gw_upstream_channel_tests", Why)
     end}.

tls_endpoint(#{ca := Ca}, S) ->
    {https, "127.0.0.1", port(S),
     [{cacertfile, Ca}, {verify, verify_peer}, {versions, ['tlsv1.2']},
      {server_name_indication, "localhost"}]}.

tls_control(Certs, S) ->
    boot_channel(tls_endpoint(Certs, S)),
    ?assertEqual({ok, [{nodelay, false}]}, client_nodelay(S)).

tls_on(Certs, S) ->
    boot_channel(tls_endpoint(Certs, S)),
    ?assertEqual(verified, yuzu_gw_app:client_tls_posture(
                             element(2, application:get_env(grpcbox, client)))),
    ok = yuzu_gw_upstream_channel:apply_nodelay(),
    ?assertEqual(verified, yuzu_gw_app:client_tls_posture(
                             element(2, application:get_env(grpcbox, client)))),
    ?assertEqual({ok, [{nodelay, true}]}, client_nodelay(S)).

%%%-------------------------------------------------------------------
%%% Fixtures
%%%-------------------------------------------------------------------

%% S = #{listener, port, acceptor, prev_client, tls}.
setup() ->
    {ok, _} = application:ensure_all_started(grpcbox),
    {ok, _} = application:ensure_all_started(ssl),
    Prev = application:get_env(grpcbox, client),
    application:unset_env(yuzu_gw, upstream_tcp_nodelay),
    catch grpcbox_channel:stop(?CH, normal),
    {ok, L} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}, {active, false}, {reuseaddr, true}]),
    {ok, Port} = inet:port(L),
    Acceptor = spawn(fun() -> acceptor(gen_tcp, L, fun(Sock) -> {ok, Sock} end, []) end),
    #{listener => {gen_tcp, L}, port => Port, acceptor => Acceptor, prev_client => Prev}.

setup_tls(#{dir := Dir, gw_pem := GwPem}) ->
    {ok, _} = application:ensure_all_started(grpcbox),
    {ok, _} = application:ensure_all_started(ssl),
    Prev = application:get_env(grpcbox, client),
    application:unset_env(yuzu_gw, upstream_tcp_nodelay),
    catch grpcbox_channel:stop(?CH, normal),
    {ok, L} = ssl:listen(0, [{ip, {127, 0, 0, 1}}, {active, false}, {reuseaddr, true},
                             {certfile, GwPem}, {keyfile, filename:join(Dir, "gw.key")},
                             {versions, ['tlsv1.2']}]),
    {ok, {_, Port}} = ssl:sockname(L),
    Handshake = fun(T) -> ssl:handshake(T, 10000) end,
    Acceptor = spawn(fun() -> acceptor(ssl, L, Handshake, []) end),
    #{listener => {ssl, L}, port => Port, acceptor => Acceptor, prev_client => Prev}.

%% Accept connections and keep them open until the process is killed. The
%% connection's own HTTP/2 handshake is never answered: the check needs the
%% connected socket, not a working RPC.
acceptor(Mod, L, Handshake, Held) ->
    Accept = case Mod of
                 gen_tcp -> gen_tcp:accept(L);
                 ssl     -> ssl:transport_accept(L)
             end,
    case Accept of
        {ok, Sock} ->
            case Handshake(Sock) of
                {ok, Conn} -> acceptor(Mod, L, Handshake, [Conn | Held]);
                _          -> acceptor(Mod, L, Handshake, Held)
            end;
        {error, _} ->
            ok
    end.

cleanup(#{listener := {Mod, L}, acceptor := Acceptor, prev_client := Prev}) ->
    catch ets:delete(?LOG_TAB),
    catch grpcbox_channel:stop(?CH, normal),
    exit(Acceptor, kill),
    catch Mod:close(L),
    application:unset_env(yuzu_gw, upstream_tcp_nodelay),
    case Prev of
        {ok, Client} -> application:set_env(grpcbox, client, Client);
        undefined    -> application:unset_env(grpcbox, client)
    end,
    ok.

%% Start the channel the way grpcbox_app does at boot: from the `client' env.
boot_channel(Endpoint) ->
    Client = #{channels => [{?CH, [Endpoint], #{}}]},
    application:set_env(grpcbox, client, Client),
    {ok, Pid} = grpcbox_channel_sup:start_child(?CH, [Endpoint], #{}),
    {Client, Pid}.

channel_pid() ->
    gproc:where({n, l, {grpcbox_channel, ?CH}}).

port(#{port := Port}) -> Port.

client_nodelay(S) -> client_opts(S, [nodelay]).

%% Force the subchannel to connect, then read the options off the client end of
%% the connection: the Erlang port whose peer is the listener.
client_opts(#{port := Port}, Opts) ->
    ok = wait_ready(100),
    [{_Endpoint, Sub}] = gproc_pool:active_workers(?CH),
    {ok, _Conn, _Info} = grpcbox_subchannel:conn(Sub, 10000),
    case [P || P <- erlang:ports(), is_client_of(P, Port)] of
        [P] -> inet:getopts(P, Opts);
        Other -> {error, {client_sockets, length(Other)}}
    end.

is_client_of(P, ListenPort) ->
    try inet:peername(P) of
        {ok, {{127, 0, 0, 1}, ListenPort}} -> true;
        _ -> false
    catch _:_ -> false
    end.

%% The channel registers its workers from an internal event right after start.
wait_ready(0) -> {error, channel_not_ready};
wait_ready(N) ->
    case catch grpcbox_channel:is_ready(?CH) of
        true -> ok;
        _    -> timer:sleep(10), wait_ready(N - 1)
    end.

client(Endpoints) ->
    #{channels => [{?CH, Endpoints, #{}}]}.

tmp_base() ->
    case os:getenv("TMPDIR") of
        false -> "/tmp";
        ""    -> "/tmp";
        Dir   -> Dir
    end.
