%%%-------------------------------------------------------------------
%%% @doc Wire tests of the yuzu_grpc layer: a REAL Cowboy/Ranch listener
%%% (yuzu_grpc_listener) serving a stub AgentService (yuzu_grpc_stub_svc),
%%% driven by a gun client (the production channel for unary calls,
%%% yuzu_gw_test_client for streams) whose HTTP/2 stack is independent of the
%%% server's Cowboy and which shares only the length-prefixed frame codec
%%% (yuzu_grpc_frame) with the server side. They prove, at gRPC-status level:
%%%
%%%   - the four handler kinds: unary, server-streaming (including an error
%%%     status and no messages at all) and bidirectional;
%%%   - the status mapping: grpc_error, a binary status, a throw, a bad return,
%%%     a crash, an unknown method, the deadline, an oversize message;
%%%   - the request is handled exactly once, however much DATA follows it
%%%     (#1422, #5591), and request/response bodies larger than the HTTP/2
%%%     window flow (the window is reopened);
%%%   - a handler crash logs the method, the exception class and the frame,
%%%     and neither the request nor the exit term;
%%%   - what a handler can see: headers, the TCP peer, the peer certificate and
%%%     a connection identity (one pid per connection, shared by its streams);
%%%   - auth_fun: a refused peer gets UNAUTHENTICATED with the handler never
%%%     run; a certless peer is refused on the auth_fun listener and admitted
%%%     on a one-way TLS listener.
%%%
%%% Nothing here waits for time to pass to make an assertion true: every wait
%%% is on an event (a message, a monitor, a telemetry event). The deadline cases
%%% do use a real deadline, which is what they test. The TLS cases mint
%%% certificates with the openssl CLI (yuzu_gw_authz_tests) and, like the other
%%% TLS tests, contribute no tests without it unless YUZU_REQUIRE_TLS_TESTS=1.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_wire_tests).
-include_lib("eunit/include/eunit.hrl").

%% logger handler and telemetry handler callbacks
-export([log/2, forward_dropped/4]).
%% shared with yuzu_grpc_origin_wire_tests
-export([client_chan/4]).

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(EXECUTE, <<"/yuzu.agent.v1.AgentService/ExecuteCommand">>).
-define(SUBSCRIBE, <<"/yuzu.agent.v1.AgentService/Subscribe">>).
-define(UPDATE, <<"/yuzu.agent.v1.AgentService/CheckForUpdate">>).
-define(MGMT_SVC, 'yuzu.server.v1.ManagementService').
-define(LIST_AGENTS, <<"/yuzu.server.v1.ManagementService/ListAgents">>).
-define(SEND_COMMAND, <<"/yuzu.server.v1.ManagementService/SendCommand">>).
-define(LOGS, yuzu_grpc_wire_logs).
-define(MARKER, "SECRET-MARKER-9f3a7c").

%%%-------------------------------------------------------------------
%%% Plaintext listener
%%%-------------------------------------------------------------------

plaintext_test_() ->
    {setup,
     fun plain_setup/0,
     fun plain_cleanup/1,
     fun(State) ->
        [{"unary ok", fun() -> unary_ok(State) end},
         {"unary ok with the three-tuple result", fun() -> unary_ok3(State) end},
         {"unary {grpc_error, {5, _}} is status 5 and its message", fun() -> unary_error(State) end},
         {"a binary status is the same status", fun() -> unary_binary_status(State) end},
         {"a thrown grpc_error (yuzu_grpc_stream:error/2) is its status", fun() -> unary_throw(State) end},
         {"a message with percent and CRLF survives the trailers", fun() -> unary_message_encoding(State) end},
         {"a bad return is INTERNAL", fun() -> unary_bad_return(State) end},
         {"an unexported method is UNIMPLEMENTED and runs nothing", fun() -> unimplemented(State) end},
         {"server-stream: N messages then status 0", fun() -> stream_messages(State) end},
         {"server-stream: no messages is status 0", fun() -> stream_empty(State) end},
         {"server-stream returning {grpc_error, _} gives that status after its messages",
          fun() -> stream_error(State) end},
         {"server-stream: a bad return is INTERNAL (not an empty OK)", fun() -> stream_bad_return(State) end},
         {"server-stream: a crash after a message is INTERNAL in the trailers", fun() -> stream_crash(State) end},
         {"bidi: echo each message, then eos ends the call with 0", fun() -> bidi_echo(State) end},
         {"bidi: {grpc_error, _} ends the call with its status", fun() -> bidi_error(State) end},
         {"a second message on a unary call does not run the handler twice",
          fun() -> unary_second_message(State) end},
         {"a second message on a unary call, after the handler finished, runs nothing",
          fun() -> unary_second_message_after_reply(State) end},
         {"deadline on a server-stream: status 4 and the handler is dead",
          {timeout, 20, fun() -> stream_deadline(State) end}},
         {"deadline on a bidi stream: status 4 and the handler is dead",
          {timeout, 20, fun() -> bidi_deadline(State) end}},
         {"a request larger than the HTTP/2 window arrives whole",
          {timeout, 30, fun() -> large_request(State) end}},
         {"a response larger than the HTTP/2 window arrives whole",
          {timeout, 30, fun() -> large_response(State) end}},
         {"a handler crash logs its class and frame, never the request or the exit term",
          fun() -> crash_is_redacted(State) end},
         {"a handler that raises logs its class and frame, never the request",
          fun() -> error_is_redacted(State) end},
         {"the handler sees the request headers, no peer cert on plaintext",
          fun() -> ctx_headers(State) end},
         {"streams of one connection share a connection key; connections differ",
          fun() -> conn_key(State) end},
         {"the unary key equals the bidi key on the same connection",
          fun() -> conn_key_unary_vs_bidi(State) end},
         {"the connection ending while a handler sends ends the handler quietly",
          {timeout, 20, fun() -> send_after_disconnect(State) end}}]
     end}.

plain_setup() ->
    start_apps(),
    %% the logging cases read the runner's line for their own failure: no rate limit
    application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, 0),
    ensure_log_table(),
    yuzu_grpc_stub_svc:init_state(),
    {Port, Pid} = yuzu_gw_test_listener:start(#{name => wire_plain, service_protos => [agent_pb],
                                                services => #{?SVC => yuzu_grpc_stub_svc}}),
    Chans = [yuzu_gw_test_listener:client_channel(N, #{port => Port})
             || N <- [wire_plain_a, wire_plain_b]],
    ok = logger:add_handler(?MODULE, ?MODULE, #{}),
    #{port => Port, listener => Pid, chans => Chans, chan => wire_plain_a, chan_b => wire_plain_b}.

plain_cleanup(#{listener := Pid, chans := Chans}) ->
    application:unset_env(yuzu_gw, grpc_runner_warn_interval_ms),
    _ = logger:remove_handler(?MODULE),
    [yuzu_gw_test_listener:stop_channel(C) || C <- Chans],
    yuzu_gw_test_listener:stop(Pid).

%%--------------------------------------------------------------------
%% Unary
%%--------------------------------------------------------------------

unary_ok(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)),
    ?assertEqual(1, yuzu_grpc_stub_svc:calls()).

unary_ok3(#{chan := Chan}) ->
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok3">>)).

unary_error(#{chan := Chan}) ->
    ?assertMatch({error, {<<"5">>, <<"nope">>}, _}, heartbeat(Chan, <<"err5">>)).

unary_binary_status(#{chan := Chan}) ->
    ?assertMatch({error, {<<"7">>, <<"denied">>}, _}, heartbeat(Chan, <<"err_bin">>)).

unary_throw(#{chan := Chan}) ->
    ?assertMatch({error, {<<"12">>, <<"thrown">>}, _}, heartbeat(Chan, <<"throw12">>)).

unary_message_encoding(#{chan := Chan}) ->
    {error, {<<"3">>, Message}, _} = heartbeat(Chan, <<"err_msg">>),
    %% whether the client decodes the percent-encoding or not, the text is intact
    ?assertEqual(<<"100% wrong\r\nline">>, yuzu_grpc_frame:decode_message(Message)).

unary_bad_return(#{chan := Chan}) ->
    ?assertMatch({error, {<<"13">>, _}, _}, heartbeat(Chan, <<"badreturn">>)).

unimplemented(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    ?assertMatch({error, {<<"12">>, _}, _},
                 yuzu_gw_test_client:unary(ctx:new(), ?UPDATE, #{}, update_def(), #{channel => Chan})),
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

%%--------------------------------------------------------------------
%% Server streaming
%%--------------------------------------------------------------------

stream_messages(#{chan := Chan}) ->
    {Messages, Status, _} = collect(execute(Chan, <<"count">>, <<"5">>)),
    ?assertEqual([<<"1">>, <<"2">>, <<"3">>, <<"4">>, <<"5">>], [O || #{output := O} <- Messages]),
    ?assertEqual(<<"0">>, Status).

stream_empty(#{chan := Chan}) ->
    ?assertMatch({[], <<"0">>, _}, collect(execute(Chan, <<"empty">>, <<>>))).

stream_error(#{chan := Chan}) ->
    {Messages, Status, Message} = collect(execute(Chan, <<"count_err">>, <<>>)),
    ?assertEqual(2, length(Messages)),
    ?assertEqual({<<"5">>, <<"stream-err">>}, {Status, Message}).

stream_bad_return(#{chan := Chan}) ->
    ?assertMatch({[], <<"13">>, _}, collect(execute(Chan, <<"badreturn">>, <<>>))).

stream_crash(#{chan := Chan}) ->
    {Messages, Status, _} = collect(execute(Chan, <<"crash">>, <<>>)),
    ?assertEqual([<<"before-crash">>], [O || #{output := O} <- Messages]),
    ?assertEqual(<<"13">>, Status).

%%--------------------------------------------------------------------
%% Bidirectional
%%--------------------------------------------------------------------

bidi_echo(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    yuzu_grpc_stub_svc:notify(self()),
    {ok, S} = subscribe(Chan),
    [begin
         ok = yuzu_gw_test_client:send(S, #{command_id => Id}),
         ?assertMatch({ok, #{command_id := Id}}, yuzu_gw_test_client:recv_data(S, 5000))
     end || Id <- [<<"a">>, <<"b">>, <<"c">>]],
    ok = yuzu_gw_test_client:close_send(S),
    ?assertMatch({ok, {<<"0">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)),
    %% the handler saw the end of its input
    _ = await(eos),
    ?assertEqual(eos, yuzu_grpc_stub_svc:result(subscribe)).

bidi_error(#{chan := Chan}) ->
    {ok, S} = subscribe(Chan),
    ok = yuzu_gw_test_client:send(S, #{command_id => <<"fail">>}),
    ?assertMatch({ok, {<<"3">>, <<"bad message">>, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)).

%%--------------------------------------------------------------------
%% Exactly once (#1422, #5591)
%%--------------------------------------------------------------------

%% Two messages on a unary call: the first starts the handler (which blocks), the
%% second is dropped by the state machine. The telemetry event is the signal
%% that the second reached it, so no assertion waits on a guess.
unary_second_message(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    yuzu_grpc_stub_svc:notify(self()),
    Id = {?MODULE, dropped, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, grpc, dropped_data], fun ?MODULE:forward_dropped/4, self()),
    try
        {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?HEARTBEAT, heartbeat_def(), #{channel => Chan}),
        ok = yuzu_gw_test_client:send(S, #{session_id => <<"sleep">>}),
        Sleeper = await(sleeping),
        ok = yuzu_gw_test_client:send(S, #{session_id => <<"sleep">>}),
        receive
            {dropped, #{bytes := Bytes}, #{reason := extra_request_data}} -> ?assert(Bytes > 0)
        after 5000 -> error(second_message_was_not_dropped)
        end,
        ?assertEqual(1, yuzu_grpc_stub_svc:calls()),
        %% let the handler answer: the one reply, then the end of the call
        Sleeper ! release,
        ?assertMatch({ok, #{acknowledged := true}}, yuzu_gw_test_client:recv_data(S, 5000)),
        ?assertMatch({ok, {<<"0">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)),
        ?assertEqual(1, yuzu_grpc_stub_svc:calls())
    after
        telemetry:detach(Id)
    end.

%% The same after the handler has already answered: whether the second message
%% finds the stream still open or gone, nothing runs a second time.
unary_second_message_after_reply(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?HEARTBEAT, heartbeat_def(), #{channel => Chan}),
    ok = yuzu_gw_test_client:send(S, #{session_id => <<"ok">>}),
    ?assertMatch({ok, #{acknowledged := true}}, yuzu_gw_test_client:recv_data(S, 5000)),
    _ = (catch yuzu_gw_test_client:send(S, #{session_id => <<"ok">>})),
    ?assertMatch({ok, {<<"0">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)),
    ?assertEqual(1, yuzu_grpc_stub_svc:calls()).

%%--------------------------------------------------------------------
%% Deadlines
%%--------------------------------------------------------------------

stream_deadline(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    yuzu_grpc_stub_svc:notify(self()),
    Ctx = ctx:with_deadline_after(ctx:new(), 800, millisecond),
    S = execute(Chan, Ctx, <<"sleep">>, <<>>),
    Sleeper = await(sleeping),
    ?assertMatch({ok, {<<"4">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 10000)),
    assert_dead(Sleeper).

bidi_deadline(#{chan := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    yuzu_grpc_stub_svc:notify(self()),
    Ctx = ctx:with_deadline_after(ctx:new(), 800, millisecond),
    {ok, S} = yuzu_gw_test_client:stream(Ctx, ?SUBSCRIBE, subscribe_def(), #{channel => Chan}),
    ok = yuzu_gw_test_client:send(S, #{command_id => <<"sleep">>}),
    Sleeper = await(sleeping),
    ?assertMatch({ok, {<<"4">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 10000)),
    assert_dead(Sleeper).

%%--------------------------------------------------------------------
%% Flow control
%%--------------------------------------------------------------------

%% 200 000 bytes is three HTTP/2 windows: if the window were never reopened the
%% client would stall after 65 535 and this would time out.
large_request(#{chan := Chan}) ->
    Big = binary:copy(<<"x">>, 200000),
    ?assertMatch({ok, #{acknowledged := true}, _},
                 heartbeat(Chan, <<"ok">>, #{status_tags => #{<<"k">> => Big}})).

large_response(#{chan := Chan}) ->
    {[#{output := Output}], Status, _} = collect(execute(Chan, <<"big">>, <<"1000000">>), 20000),
    ?assertEqual(1000000, byte_size(Output)),
    ?assertEqual(<<"0">>, Status).

%%--------------------------------------------------------------------
%% Logging
%%--------------------------------------------------------------------

crash_is_redacted(#{chan := Chan}) ->
    clear_logs(),
    ?assertMatch({error, {<<"13">>, <<"internal error">>}, _},
                 heartbeat(Chan, <<"crash">>, #{status_tags => #{<<"k">> => <<?MARKER>>}})),
    Lines = logs(),
    ?assert(lists:any(fun(L) -> contains(L, "/yuzu.agent.v1.AgentService/Heartbeat")
                                andalso contains(L, "class=exit") end, Lines)),
    assert_no_leak(Lines).

error_is_redacted(#{chan := Chan}) ->
    clear_logs(),
    ?assertMatch({error, {<<"13">>, _}, _},
                 heartbeat(Chan, <<"error">>, #{status_tags => #{<<"k">> => <<?MARKER>>}})),
    Lines = logs(),
    ?assert(lists:any(fun(L) -> contains(L, "class=error")
                                andalso contains(L, "yuzu_grpc_stub_svc:heartbeat/3") end, Lines)),
    assert_no_leak(Lines).

assert_no_leak(Lines) ->
    %% neither the request, nor the reason of the exit (which names the missing
    %% server and embeds the whole call)
    [[?assertEqual({L, false}, {L, contains(L, Needle)})
      || Needle <- [?MARKER, "noproc", "yuzu_grpc_stub_nobody"]] || L <- Lines],
    ok.

%%--------------------------------------------------------------------
%% What a handler can see
%%--------------------------------------------------------------------

ctx_headers(#{chan := Chan}) ->
    Ctx = yuzu_gw_test_client:with_metadata(ctx:new(), #{<<"x-test">> => <<"hello">>}),
    {ok, #{pending_commands := [#{plugin := Header, action := Cert}]}, _} =
        yuzu_gw_test_client:unary(Ctx, ?HEARTBEAT, #{session_id => <<"ctx">>}, heartbeat_def(),
                                  #{channel => Chan}),
    ?assertEqual(<<"hello">>, Header),
    ?assertEqual(<<"no-cert">>, Cert).

conn_key(#{chan := A, chan_b := B}) ->
    K1 = conn_key_of(A),
    K2 = conn_key_of(A),
    K3 = conn_key_of(B),
    ?assertEqual(K1, K2),
    ?assertNotEqual(K1, K3),
    ?assert(is_pid(list_to_pid(binary_to_list(K1)))).

conn_key_unary_vs_bidi(#{chan := Chan}) ->
    {ok, S} = subscribe(Chan),
    ok = yuzu_gw_test_client:send(S, #{command_id => <<"conn">>}),
    {ok, #{command_id := BidiKey}} = yuzu_gw_test_client:recv_data(S, 5000),
    %% a second stream while the first is open, on the same connection
    UnaryKey = conn_key_of(Chan),
    ?assertEqual(BidiKey, UnaryKey),
    ok = yuzu_gw_test_client:close_send(S),
    ?assertMatch({ok, {<<"0">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)).

%% The connection ends under a handler that is sending: the handler is stopped
%% by Cowboy, or sees {error, closed}; it never crashes and nothing is logged as
%% a failure.
send_after_disconnect(#{port := Port}) ->
    yuzu_grpc_stub_svc:reset(),
    yuzu_grpc_stub_svc:notify(self()),
    clear_logs(),
    Chan = yuzu_gw_test_listener:client_channel(wire_plain_gone, #{port => Port}),
    S = execute(Chan, <<"until_closed">>, <<>>),
    Handler = await(sleeping),
    {ok, _First} = yuzu_gw_test_client:recv_data(S, 5000),
    yuzu_gw_test_listener:stop_channel(Chan),
    assert_dead(Handler),
    ?assertEqual([], [L || L <- logs(), contains(L, "gateway grpc")]).

%%%-------------------------------------------------------------------
%%% Limits
%%%-------------------------------------------------------------------

limits_test_() ->
    {setup,
     fun() ->
        start_apps(),
        yuzu_grpc_stub_svc:init_state(),
        {Port, Pid} = yuzu_gw_test_listener:start(
                        #{name => wire_limits, service_protos => [agent_pb],
                          services => #{?SVC => yuzu_grpc_stub_svc},
                          limits => #{max_message_bytes => 1024}}),
        Chan = yuzu_gw_test_listener:client_channel(wire_limits_chan, #{port => Port}),
        #{listener => Pid, chan => Chan}
     end,
     fun(#{listener := Pid, chan := Chan}) ->
        yuzu_gw_test_listener:stop_channel(Chan),
        yuzu_gw_test_listener:stop(Pid)
     end,
     fun(#{chan := Chan}) ->
        [{"a message over max_message_bytes is RESOURCE_EXHAUSTED and runs nothing",
          fun() ->
              yuzu_grpc_stub_svc:reset(),
              Big = binary:copy(<<"x">>, 2000),
              ?assertMatch({error, {<<"8">>, _}, _},
                           heartbeat(Chan, <<"ok">>, #{status_tags => #{<<"k">> => Big}})),
              ?assertEqual(0, yuzu_grpc_stub_svc:calls())
          end},
         {"a message at the limit is served",
          fun() ->
              yuzu_grpc_stub_svc:reset(),
              Small = binary:copy(<<"x">>, 500),
              ?assertMatch({ok, #{acknowledged := true}, _},
                           heartbeat(Chan, <<"ok">>, #{status_tags => #{<<"k">> => Small}})),
              ?assertEqual(1, yuzu_grpc_stub_svc:calls())
          end},
         {"an oversize message on a bidi stream ends the call and the handler",
          fun() ->
              yuzu_grpc_stub_svc:reset(),
              {ok, S} = subscribe(Chan),
              ok = yuzu_gw_test_client:send(S, #{command_id => <<"first">>}),
              ?assertMatch({ok, #{command_id := <<"first">>}}, yuzu_gw_test_client:recv_data(S, 5000)),
              ok = yuzu_gw_test_client:send(S, #{command_id => binary:copy(<<"x">>, 2000)}),
              ?assertMatch({ok, {<<"8">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000))
          end}]
     end}.

%%%-------------------------------------------------------------------
%%% Flow control, pinned to this layer
%%%-------------------------------------------------------------------

%% Cowboy keeps a margin of window above what a stream handler asked for
%% (stream_window_margin_size, 65 535 by default), which would hide a layer that
%% never granted any credit. With the margins at 0 the only thing that reopens
%% the receive window is the {flow, N} this layer returns for every DATA frame.
no_margin_test_() ->
    {setup,
     fun() ->
        start_apps(),
        yuzu_grpc_stub_svc:init_state(),
        {Port, Pid} = yuzu_gw_test_listener:start(
                        #{name => wire_nomargin, service_protos => [agent_pb],
                          services => #{?SVC => yuzu_grpc_stub_svc},
                          http2 => #{stream_window_margin_size => 0,
                                     connection_window_margin_size => 0}}),
        Chan = yuzu_gw_test_listener:client_channel(wire_nomargin_chan, #{port => Port}),
        #{listener => Pid, chan => Chan}
     end,
     fun(#{listener := Pid, chan := Chan}) ->
        yuzu_gw_test_listener:stop_channel(Chan),
        yuzu_gw_test_listener:stop(Pid)
     end,
     fun(#{chan := Chan}) ->
        [{"a unary request of three windows arrives whole",
          {timeout, 30, fun() ->
              Big = binary:copy(<<"x">>, 200000),
              ?assertMatch({ok, #{acknowledged := true}, _},
                           heartbeat(Chan, <<"ok">>, #{status_tags => #{<<"k">> => Big}}))
          end}},
         {"two large requests in a row on one connection",
          {timeout, 30, fun() ->
              %% the connection window is replenished across calls too
              Big = binary:copy(<<"x">>, 100000),
              ?assertMatch({ok, #{acknowledged := true}, _},
                           heartbeat(Chan, <<"ok">>, #{status_tags => #{<<"k">> => Big}})),
              ?assertMatch({ok, #{acknowledged := true}, _},
                           heartbeat(Chan, <<"ok">>, #{status_tags => #{<<"k">> => Big}}))
          end}},
         {"a bidi stream of many messages totalling three windows is echoed whole",
          {timeout, 30, fun() ->
              {ok, S} = subscribe(Chan),
              Body = binary:copy(<<"y">>, 20000),
              Ids = [<<(integer_to_binary(I))/binary, ":", Body/binary>> || I <- lists:seq(1, 10)],
              [ok = yuzu_gw_test_client:send(S, #{command_id => Id}) || Id <- Ids],
              Echoed = [begin
                            {ok, #{command_id := Echo}} = yuzu_gw_test_client:recv_data(S, 10000),
                            Echo
                        end || _ <- Ids],
              ?assertEqual(Ids, Echoed),
              ok = yuzu_gw_test_client:close_send(S),
              ?assertMatch({ok, {<<"0">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000))
          end}}]
     end}.

%%%-------------------------------------------------------------------
%%% TLS
%%%-------------------------------------------------------------------

tls_test_() ->
    {setup,
     fun tls_setup/0,
     fun tls_cleanup/1,
     fun(State) ->
        case State of
            #{} ->
                [{"mTLS + auth_fun: the pinned leaf is admitted (unary)", fun() -> auth_admitted(State) end},
                 {"mTLS + auth_fun: the pinned leaf is admitted (server-stream)",
                  fun() -> auth_admitted_stream(State) end},
                 {"mTLS + auth_fun: the handler sees the peer certificate", fun() -> auth_sees_cert(State) end},
                 {"mTLS + auth_fun: an unpinned leaf gets UNAUTHENTICATED and runs nothing (unary)",
                  fun() -> auth_refused(State) end},
                 {"mTLS + auth_fun: an unpinned leaf gets UNAUTHENTICATED and runs nothing (server-stream)",
                  fun() -> auth_refused_stream(State) end},
                 {"mTLS + auth_fun: an unpinned leaf's bidi stream runs nothing, however much it sends",
                  fun() -> auth_refused_bidi(State) end},
                 {"mTLS + auth_fun: a refused peer cannot tell a real method from a missing one",
                  fun() -> auth_refused_unknown_method(State) end},
                 {"mTLS + auth_fun: a certless peer cannot reach the listener", fun() -> certless_blocked(State) end},
                 {"mTLS + auth_fun, but the pin list is empty: everything is refused (fail closed)",
                  fun() -> auth_no_pins(State) end},
                 {"one-way TLS: a certless peer is served and the handler sees no cert",
                  fun() -> oneway_certless_ok(State) end},
                 {"one-way TLS: streaming works too", fun() -> oneway_stream_ok(State) end},
                 {"ALPN settles on h2; a client offering only http/1.1 is refused at the handshake",
                  fun() -> alpn_h2_only(State) end}];
            {error, Why} ->
                yuzu_gw_authz_tests:certs_unavailable("yuzu_grpc_wire_tests", Why)
        end
     end}.

tls_setup() ->
    case yuzu_gw_authz_tests:setup_certs() of
        {error, _} = E ->
            E;
        Certs = #{dir := Dir, ca := Ca, srv_pem := SrvPem} ->
            start_apps(),
            yuzu_grpc_stub_svc:init_state(),
            application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
            %% What the running gateway's yuzu_gw_mgmt_pins does at boot: the
            %% auth_fun reads the published pin, never the file.
            ok = yuzu_gw_mgmt_pins:refresh(),
            Tls = #{certfile => filename:join(Dir, "gw.pem"), keyfile => filename:join(Dir, "gw.key"),
                    cacertfile => Ca},
            Base = #{service_protos => [agent_pb], services => #{?SVC => yuzu_grpc_stub_svc}},
            %% A listener that serves the AgentService may not carry an auth_fun
            %% (yuzu_grpc_listener:validate/1), so the auth_fun legs run against a
            %% management listener: the stub answers two ManagementService methods
            %% (ListAgents, unary; SendCommand, server stream) and the AgentService
            %% is not served on that port at all.
            {AuthPort, AuthPid} = yuzu_gw_test_listener:start(
                                    #{name => wire_tls_auth, tls => Tls,
                                      service_protos => [management_pb],
                                      services => #{?MGMT_SVC => yuzu_grpc_stub_svc},
                                      auth_fun => fun yuzu_gw_authz:check_mgmt_peer/1}),
            {OnePort, OnePid} = yuzu_gw_test_listener:start(
                                  Base#{name => wire_tls_oneway,
                                        tls => Tls#{verify => verify_none, fail_if_no_peer_cert => false}}),
            Chans = [{chan_srv, client_chan(wire_tls_srv, AuthPort, Certs, "srv")},
                     {chan_agent, client_chan(wire_tls_agent, AuthPort, Certs, "agent")},
                     {chan_gw, client_chan(wire_tls_gw, AuthPort, Certs, "gw")},
                     {chan_oneway, client_chan(wire_tls_oneway_chan, OnePort, Certs, undefined)}],
            maps:merge(#{certs => Certs, auth_port => AuthPort, oneway_port => OnePort,
                         listeners => [AuthPid, OnePid]},
                       maps:from_list(Chans))
    end.

tls_cleanup({error, _}) ->
    ok;
tls_cleanup(#{certs := Certs, listeners := Listeners} = State) ->
    [yuzu_gw_test_listener:stop_channel(maps:get(K, State))
     || K <- [chan_srv, chan_agent, chan_gw, chan_oneway]],
    [yuzu_gw_test_listener:stop(P) || P <- Listeners],
    application:unset_env(yuzu_gw, mgmt_peer_pins),
    yuzu_gw_authz_tests:cleanup_certs(Certs),
    ok.

%% A client channel verifying the gateway; Leaf =:= undefined presents no certificate.
client_chan(Name, Port, #{dir := Dir, ca := Ca}, Leaf) ->
    Base = [{cacertfile, Ca}, {verify, verify_peer}, {versions, ['tlsv1.2']},
            {server_name_indication, "localhost"}],
    Ssl = case Leaf of
        undefined -> Base;
        _ -> Base ++ [{certfile, filename:join(Dir, Leaf ++ ".pem")},
                      {keyfile, filename:join(Dir, Leaf ++ ".key")}]
    end,
    yuzu_gw_test_listener:client_channel(Name, #{port => Port, scheme => https, ssl => Ssl}).

auth_admitted(#{chan_srv := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    ?assertMatch({ok, #{agents := []}, _}, list_agents(Chan, <<"ok">>)),
    ?assertEqual(1, yuzu_grpc_stub_svc:calls()).

auth_admitted_stream(#{chan_srv := Chan}) ->
    ?assertMatch({[_, _, _], <<"0">>, _}, collect(send_command(Chan, <<"count">>, <<"3">>))).

auth_sees_cert(#{chan_srv := Chan}) ->
    {ok, #{agents := [#{agent_id := Cert}]}, _} = list_agents(Chan, <<"ctx">>),
    ?assertEqual(<<"cert">>, Cert).

auth_refused(#{chan_agent := Agent, chan_gw := Gw}) ->
    yuzu_grpc_stub_svc:reset(),
    ?assertMatch({error, {<<"16">>, _}, _}, list_agents(Agent, <<"ok">>)),
    ?assertMatch({error, {<<"16">>, _}, _}, list_agents(Gw, <<"ok">>)),
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

auth_refused_stream(#{chan_agent := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    ?assertMatch({[], <<"16">>, _}, collect(send_command(Chan, <<"count">>, <<"3">>))),
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

%% A bidi handler would be started at once; frames already in flight behind the
%% refusal must not start or feed anything. ManagementService has no bidi method,
%% so the stream goes to the AgentService's Subscribe path, which this listener
%% does not serve: the refusal comes before routing either way (see
%% auth_refused_unknown_method), and what is tested is that the stream handler
%% answers it without reading the frames behind it.
auth_refused_bidi(#{chan_agent := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    {ok, S} = subscribe(Chan),
    _ = (catch yuzu_gw_test_client:send(S, #{command_id => <<"a">>})),
    _ = (catch yuzu_gw_test_client:send(S, #{command_id => <<"b">>})),
    _ = (catch yuzu_gw_test_client:close_send(S)),
    ?assertMatch({ok, {<<"16">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)),
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

auth_refused_unknown_method(#{chan_agent := Chan}) ->
    ?assertMatch({error, {<<"16">>, _}, _},
                 yuzu_gw_test_client:unary(ctx:new(), ?UPDATE, #{}, update_def(), #{channel => Chan})),
    ?assertMatch({error, {<<"16">>, _}, _},
                 yuzu_gw_test_client:unary(ctx:new(), <<"/no.such.Service/Nothing">>, #{}, update_def(),
                                           #{channel => Chan})).

certless_blocked(#{auth_port := Port, certs := #{ca := Ca}}) ->
    yuzu_grpc_stub_svc:reset(),
    Res = ssl:connect("localhost", Port,
                      [{cacertfile, Ca}, {verify, verify_peer}, {versions, ['tlsv1.2']},
                       {mode, binary}, {active, false}, {server_name_indication, "localhost"}], 5000),
    Blocked = case Res of
        {error, _} -> true;
        {ok, Sock} ->
            R = ssl:recv(Sock, 0, 2000),
            catch ssl:close(Sock),
            R =/= {ok, <<>>} andalso element(1, R) =:= error
    end,
    ?assert(Blocked),
    ?assertEqual(0, yuzu_grpc_stub_svc:calls()).

auth_no_pins(#{chan_srv := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    Pins = application:get_env(yuzu_gw, mgmt_peer_pins, []),
    application:set_env(yuzu_gw, mgmt_peer_pins, []),
    try
        ?assertMatch({error, {<<"16">>, _}, _}, list_agents(Chan, <<"ok">>)),
        ?assertEqual(0, yuzu_grpc_stub_svc:calls())
    after
        application:set_env(yuzu_gw, mgmt_peer_pins, Pins)
    end.

oneway_certless_ok(#{chan_oneway := Chan}) ->
    yuzu_grpc_stub_svc:reset(),
    ?assertMatch({ok, #{acknowledged := true}, _}, heartbeat(Chan, <<"ok">>)),
    {ok, #{pending_commands := [#{action := Cert}]}, _} = heartbeat(Chan, <<"ctx">>),
    ?assertEqual(<<"no-cert">>, Cert),
    ?assertEqual(2, yuzu_grpc_stub_svc:calls()).

oneway_stream_ok(#{chan_oneway := Chan}) ->
    ?assertMatch({[_, _], <<"0">>, _}, collect(execute(Chan, <<"count">>, <<"2">>))),
    {ok, S} = subscribe(Chan),
    ok = yuzu_gw_test_client:send(S, #{command_id => <<"x">>}),
    ?assertMatch({ok, #{command_id := <<"x">>}}, yuzu_gw_test_client:recv_data(S, 5000)),
    ok = yuzu_gw_test_client:close_send(S),
    ?assertMatch({ok, {<<"0">>, _, _}}, yuzu_gw_test_client:recv_trailers(S, 5000)).

alpn_h2_only(#{oneway_port := Port, certs := #{ca := Ca}}) ->
    Opts = fun(Offer) ->
               [{cacertfile, Ca}, {verify, verify_peer}, {versions, ['tlsv1.2']},
                {server_name_indication, "localhost"}, {alpn_advertised_protocols, Offer}]
           end,
    {ok, Sock} = ssl:connect("localhost", Port, Opts([<<"h2">>, <<"http/1.1">>]), 5000),
    ?assertEqual({ok, <<"h2">>}, ssl:negotiated_protocol(Sock)),
    ssl:close(Sock),
    ?assertMatch({error, {tls_alert, {no_application_protocol, _}}},
                 ssl:connect("localhost", Port, Opts([<<"http/1.1">>]), 5000)).

%%%-------------------------------------------------------------------
%%% Client plumbing
%%%-------------------------------------------------------------------

list_agents(Chan, Command) ->
    yuzu_gw_test_client:unary(ctx:new(), ?LIST_AGENTS, #{filter => Command},
                         list_agents_def(), #{channel => Chan}).

send_command(Chan, Action, Arg) ->
    {ok, S} = yuzu_gw_test_client:stream(ctx:new(), ?SEND_COMMAND,
                                    #{command => #{action => Action, command_id => Arg}},
                                    send_command_def(), #{channel => Chan}),
    S.

heartbeat(Chan, Command) ->
    heartbeat(Chan, Command, #{}).

heartbeat(Chan, Command, Extra) ->
    yuzu_gw_test_client:unary(ctx:new(), ?HEARTBEAT, maps:merge(#{session_id => Command}, Extra),
                              heartbeat_def(), #{channel => Chan}).

execute(Chan, Command, Arg) ->
    execute(Chan, ctx:new(), Command, Arg).

execute(Chan, Ctx, Command, Arg) ->
    {ok, S} = yuzu_gw_test_client:stream(Ctx, ?EXECUTE, #{action => Command, command_id => Arg},
                                         command_def(), #{channel => Chan}),
    S.

subscribe(Chan) ->
    yuzu_gw_test_client:stream(ctx:new(), ?SUBSCRIBE, subscribe_def(), #{channel => Chan}).

conn_key_of(Chan) ->
    {ok, #{pending_commands := [#{command_id := Key}]}, _} = heartbeat(Chan, <<"ctx">>),
    Key.

%% Every message of a server stream, then its status and message. The stream
%% ends with `stream_finished' whatever its status; the status (0 or an error)
%% and its message are then read from the trailers.
collect(S) ->
    collect(S, 5000).

collect(S, Timeout) ->
    collect(S, Timeout, []).

collect(S, Timeout, Acc) ->
    case yuzu_gw_test_client:recv_data(S, Timeout) of
        {ok, Message} -> collect(S, Timeout, [Message | Acc]);
        stream_finished -> end_status(S, Timeout, Acc);
        Other -> {lists:reverse(Acc), {unexpected, Other}, undefined}
    end.

end_status(S, Timeout, Acc) ->
    case yuzu_gw_test_client:recv_trailers(S, Timeout) of
        {ok, {Status, Message, _}} -> {lists:reverse(Acc), Status, Message};
        Other -> {lists:reverse(Acc), {unexpected, Other}, undefined}
    end.

list_agents_def() ->
    #{marshal => fun(M) -> management_pb:encode_msg(M, 'yuzu.server.v1.ListAgentsRequest') end,
      unmarshal => fun(B) -> management_pb:decode_msg(B, 'yuzu.server.v1.ListAgentsResponse') end}.

send_command_def() ->
    #{marshal => fun(M) -> management_pb:encode_msg(M, 'yuzu.server.v1.SendCommandRequest') end,
      unmarshal => fun(B) -> management_pb:decode_msg(B, 'yuzu.server.v1.SendCommandResponse') end}.

heartbeat_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.HeartbeatRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.HeartbeatResponse') end}.

command_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.CommandRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.CommandResponse') end}.

subscribe_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.CommandResponse') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.CommandRequest') end}.

update_def() ->
    #{marshal => fun(M) -> agent_pb:encode_msg(M, 'yuzu.agent.v1.CheckForUpdateRequest') end,
      unmarshal => fun(B) -> agent_pb:decode_msg(B, 'yuzu.agent.v1.CheckForUpdateResponse') end}.

%%%-------------------------------------------------------------------
%%% Waiting on events, capturing logs
%%%-------------------------------------------------------------------

start_apps() ->
    {ok, _} = application:ensure_all_started(gun),
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    ok.

%% Wait for the event the stub reports (yuzu_grpc_stub_svc:notify/1).
await(Event) ->
    receive
        {stub, Event, Handler} -> Handler
    after 5000 ->
        error({no_event, Event})
    end.

assert_dead(Pid) ->
    Ref = erlang:monitor(process, Pid),
    receive
        {'DOWN', Ref, process, Pid, _} -> ok
    after 5000 ->
        error({still_alive, Pid})
    end.

forward_dropped(_Event, Measurements, Meta, Pid) ->
    Pid ! {dropped, Measurements, Meta},
    ok.

ensure_log_table() ->
    case ets:whereis(?LOGS) of
        undefined -> ets:new(?LOGS, [named_table, public, ordered_set]);
        _ -> ok
    end,
    ok.

clear_logs() ->
    ets:delete_all_objects(?LOGS).

logs() ->
    [Line || {_, Line} <- ets:tab2list(?LOGS)].

%% logger handler callback: keep the formatted line of every event.
log(Event, _Config) ->
    Line = try
        lists:flatten(logger_formatter:format(
                        Event, #{single_line => true, template => [level, " ", msg]}))
    catch
        _:_ -> "unformattable"
    end,
    case ets:whereis(?LOGS) of
        undefined -> ok;
        _ -> ets:insert(?LOGS, {erlang:unique_integer([monotonic]), Line})
    end,
    ok.

contains(Line, Needle) ->
    string:find(Line, Needle) =/= nomatch.
