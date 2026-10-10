%%%-------------------------------------------------------------------
%%% @doc The state machine of yuzu_grpc_stream_h, driven through its Cowboy
%%% callbacks directly. The test process stands in for the Cowboy connection
%%% process: it makes the init/data/info calls, receives what the handler sends
%%% to the connection, and is the pid the handler's ctx names. The handlers are
%%% yuzu_grpc_probe_svc, which hands the test everything it receives.
%%%
%%% These cases cover what a chatterbox client cannot provoke or cannot be told
%%% apart on the wire: that every refusal ends in `stop' (Cowboy then drops the
%%% stream and the handler), that DATA after a start is dropped and counted,
%%% that an exit term never reaches a log command, and that no callback raises
%%% (Cowboy would log the request it was given).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_stream_h_tests).
-include_lib("eunit/include/eunit.hrl").

-export([forward_dropped/4, forward_origin/4]).

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, <<"/yuzu.agent.v1.AgentService/Heartbeat">>).
-define(EXECUTE, <<"/yuzu.agent.v1.AgentService/ExecuteCommand">>).
-define(SUBSCRIBE, <<"/yuzu.agent.v1.AgentService/Subscribe">>).
-define(HB_REQ, 'yuzu.agent.v1.HeartbeatRequest').
-define(CMD_RESP, 'yuzu.agent.v1.CommandResponse').

-define(CASE(Name, Body), {Name, fun() -> in_conn(fun(Routes) -> _ = Routes, Body end) end}).

%%%-------------------------------------------------------------------
%%% Refusals at init
%%%-------------------------------------------------------------------

init_refusals_test_() ->
    [?CASE("a method other than POST is INVALID_ARGUMENT",
           assert_refused(3, init((req(?HEARTBEAT))#{method => <<"GET">>}, env(Routes)))),
     ?CASE("a missing content-type is INVALID_ARGUMENT",
           assert_refused(3, init(req(?HEARTBEAT, #{}, [<<"content-type">>]), env(Routes)))),
     ?CASE("a foreign content-type is INVALID_ARGUMENT",
           begin
               [assert_refused(3, init(req(?HEARTBEAT, #{<<"content-type">> => Type}), env(Routes)))
                || Type <- [<<"application/json">>, <<"application/grpc+json">>, <<"text/plain">>,
                            <<"application/grpcx">>]]
           end),
     ?CASE("application/grpc and application/grpc+proto are served",
           begin
               [?assertMatch({[], _}, init(req(?HEARTBEAT, #{<<"content-type">> => Type}), env(Routes)))
                || Type <- [<<"application/grpc">>, <<"application/grpc+proto">>]]
           end),
     ?CASE("a compressed request encoding is UNIMPLEMENTED",
           begin
               assert_refused(12, init(req(?HEARTBEAT, #{<<"grpc-encoding">> => <<"gzip">>}), env(Routes))),
               ?assertMatch({[], _}, init(req(?HEARTBEAT, #{<<"grpc-encoding">> => <<"identity">>}),
                                          env(Routes)))
           end),
     ?CASE("an unknown path is UNIMPLEMENTED",
           begin
               [assert_refused(12, init(req(Path), env(Routes)))
                || Path <- [<<"/no.such.Service/Nothing">>, <<"/">>, <<"/yuzu.agent.v1.AgentService/CheckForUpdate">>,
                            <<"/yuzu.agent.v1.AgentService/heartbeat">>]]
           end),
     ?CASE("a malformed grpc-timeout is INVALID_ARGUMENT",
           [assert_refused(3, init(req(?HEARTBEAT, #{<<"grpc-timeout">> => Bad}), env(Routes)))
            || Bad <- [<<"abc">>, <<"5">>, <<"5x">>, <<"123456789S">>, <<>>]]),
     ?CASE("a unary call whose request ends with its headers is INTERNAL",
           assert_refused(13, init((req(?HEARTBEAT))#{has_body => false}, env(Routes)))),
     ?CASE("every refusal is a trailers-only 200 with the grpc content-type",
           begin
               {[{response, 200, Headers, <<>>}, stop], _} = init(req(<<"/x/Y">>), env(Routes)),
               ?assertEqual(<<"application/grpc">>, maps:get(<<"content-type">>, Headers)),
               ?assertEqual(<<"12">>, maps:get(<<"grpc-status">>, Headers))
           end)].

%%%-------------------------------------------------------------------
%%% auth_fun: the first thing that happens to a stream
%%%-------------------------------------------------------------------

auth_test_() ->
    Der = <<"der-of-the-peer-certificate">>,
    Cert = fun(Fun) -> fun(Routes) -> {(req(?HEARTBEAT))#{cert => Der}, env(Routes, #{auth_fun => Fun})} end end,
    [?CASE("auth_fun gets the DER certificate and {true, _} admits",
           begin
               Self = self(),
               Fun = fun(D) -> Self ! {auth_saw, D}, {true, <<"id">>} end,
               {Req, Env} = (Cert(Fun))(Routes),
               ?assertMatch({[], _}, init(Req, Env)),
               ?assertEqual(Der, receive {auth_saw, D} -> D after 1000 -> error(auth_fun_not_called) end)
           end),
     ?CASE("auth_fun returning true admits",
           begin
               {Req, Env} = (Cert(fun(_) -> true end))(Routes),
               ?assertMatch({[], _}, init(Req, Env))
           end),
     ?CASE("auth_fun returning false is UNAUTHENTICATED",
           begin
               {Req, Env} = (Cert(fun(_) -> false end))(Routes),
               assert_refused(16, init(Req, Env))
           end),
     ?CASE("auth_fun returning anything else is UNAUTHENTICATED",
           [begin
                {Req, Env} = (Cert(fun(_) -> Verdict end))(Routes),
                assert_refused(16, init(Req, Env))
            end || Verdict <- [ok, undefined, {error, x}, <<"true">>, 1]]),
     ?CASE("auth_fun that raises, throws or exits is UNAUTHENTICATED and logs nothing",
           [begin
                {Req, Env} = (Cert(Fun))(Routes),
                {Commands, _} = init(Req, Env),
                ?assertMatch([{response, 200, _, <<>>}, stop], Commands),
                assert_refused(16, init(Req, Env))
            end || Fun <- [fun(_) -> error(boom) end, fun(_) -> throw(boom) end,
                           fun(_) -> exit(boom) end]]),
     ?CASE("no certificate with an auth_fun is UNAUTHENTICATED, and auth_fun is not called",
           begin
               Self = self(),
               Env = env(Routes, #{auth_fun => fun(_) -> Self ! called, true end}),
               assert_refused(16, init((req(?HEARTBEAT))#{cert => undefined}, Env)),
               receive called -> error(auth_fun_called_without_a_certificate) after 0 -> ok end
           end),
     ?CASE("a refused peer learns nothing about the method: auth precedes the lookup",
           begin
               Env = env(Routes, #{auth_fun => fun(_) -> false end}),
               [assert_refused(16, init((req(Path))#{cert => Der, method => Method}, Env))
                || Path <- [?HEARTBEAT, <<"/no.such.Service/Nothing">>],
                   Method <- [<<"POST">>, <<"GET">>]]
           end),
     ?CASE("a refused bidi stream never starts a handler",
           begin
               Env = env(Routes, #{auth_fun => fun(_) -> false end}),
               {Commands, _} = init((req(?SUBSCRIBE))#{cert => Der}, Env),
               ?assertEqual([], [C || {spawn, _, _} = C <- Commands]),
               ?assertMatch([{response, 200, _, <<>>}, stop], Commands),
               receive {probe_started, _, _, _} -> error(handler_started) after 0 -> ok end
           end),
     ?CASE("DATA reaching a refused stream (if Cowboy still delivers it) runs nothing and opens the window",
           begin
               Env = env(Routes, #{auth_fun => fun(_) -> false end}),
               {_, St} = init((req(?HEARTBEAT))#{cert => Der}, Env),
               Frame = hb_frame(<<"x">>),
               ?assertMatch({[{flow, _}], _}, yuzu_grpc_stream_h:data(1, fin, Frame, St)),
               receive {probe_started, _, _, _} -> error(handler_started) after 0 -> ok end
           end)].

%%%-------------------------------------------------------------------
%%% The address a call is attributed to (yuzu_grpc_origin)
%%%-------------------------------------------------------------------

origin_test_() ->
    Lb = {10, 0, 0, 5},
    Client = {203, 0, 113, 9},
    ViaLb = fun(Req) -> Req#{peer => {Lb, 40000}} end,
    Xff = fun(Value) -> #{<<"x-forwarded-for">> => Value} end,
    FwdEnv = fun(Routes, Sources) ->
                 env(Routes, #{origin => #{mode => forwarded_for, sources => Sources}})
             end,
    ProxyEnv = fun(Routes, Sources) ->
                   env(Routes, #{origin => #{mode => proxy_protocol, sources => Sources}})
               end,
    ProxyInfo = #{version => 2, command => proxy, transport_family => ipv4,
                  transport_protocol => stream, src_address => Client, src_port => 41000,
                  dest_address => {10, 0, 0, 9}, dest_port => 50051},
    [?CASE("with no origin configured the TCP peer is the origin and a forwarded-for header is ignored",
           begin
               Ctx = unary_ctx(req(?HEARTBEAT, Xff(<<"192.0.2.1">>)), env(Routes)),
               ?assertEqual({{127, 0, 0, 1}, transport}, yuzu_grpc:origin(Ctx)),
               ?assertEqual({{127, 0, 0, 1}, 40000}, yuzu_grpc:peer(Ctx))
           end),
     ?CASE("a trusted proxy's x-forwarded-for entry is the origin; the peer is still the proxy",
           begin
               Req = ViaLb(req(?HEARTBEAT, Xff(<<"198.51.100.7, 203.0.113.9">>))),
               Ctx = unary_ctx(Req, FwdEnv(Routes, [Lb])),
               ?assertEqual({Client, forwarded_for}, yuzu_grpc:origin(Ctx)),
               ?assertEqual({Lb, 40000}, yuzu_grpc:peer(Ctx))
           end),
     ?CASE("x-forwarded-for from a peer that is not a trusted proxy is ignored and counted",
           with_origin_events(
             fun() ->
                 Ctx = unary_ctx(req(?HEARTBEAT, Xff(<<"192.0.2.1">>)), FwdEnv(Routes, [Lb])),
                 ?assertEqual({{127, 0, 0, 1}, transport}, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({forwarded_for, untrusted_source}, origin_event())
             end)),
     ?CASE("an unusable x-forwarded-for from a trusted proxy falls back to the peer and is counted",
           with_origin_events(
             fun() ->
                 Ctx = unary_ctx(ViaLb(req(?HEARTBEAT, Xff(<<"not-an-address">>))),
                                 FwdEnv(Routes, [Lb])),
                 ?assertEqual({Lb, transport}, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({forwarded_for, bad_claim}, origin_event())
             end)),
     ?CASE("a PROXY header from a trusted proxy is the origin",
           begin
               Req = (ViaLb(req(?HEARTBEAT)))#{proxy_header => ProxyInfo},
               Ctx = unary_ctx(Req, ProxyEnv(Routes, [Lb])),
               ?assertEqual({Client, proxy_protocol}, yuzu_grpc:origin(Ctx)),
               ?assertEqual({Lb, 40000}, yuzu_grpc:peer(Ctx))
           end),
     ?CASE("a PROXY header from a peer that is not a trusted proxy is ignored and counted",
           with_origin_events(
             fun() ->
                 Req = (req(?HEARTBEAT))#{proxy_header => ProxyInfo},
                 Ctx = unary_ctx(Req, ProxyEnv(Routes, [Lb])),
                 ?assertEqual({{127, 0, 0, 1}, transport}, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({proxy_protocol, untrusted_source}, origin_event())
             end)),
     ?CASE("a PROXY LOCAL (the balancer's own health check) is the peer and is counted",
           with_origin_events(
             fun() ->
                 Req = (ViaLb(req(?HEARTBEAT)))#{proxy_header => #{version => 2, command => local}},
                 Ctx = unary_ctx(Req, ProxyEnv(Routes, [Lb])),
                 ?assertEqual({Lb, transport}, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({proxy_protocol, no_claim}, origin_event())
             end)),
     ?CASE("a streaming handler's ctx carries the origin too",
           begin
               Env = FwdEnv(Routes, [Lb]),
               {[{spawn, _, _}], _} = init(ViaLb(req(?SUBSCRIBE, Xff(<<"203.0.113.9">>))), Env),
               {_Handler, _Ref, Stream} = started(),
               ?assertEqual({Client, forwarded_for},
                            yuzu_grpc:origin(yuzu_grpc_stream:ctx(Stream)))
           end),
     ?CASE("a call served with no usable origin reports nothing rather than guessing",
           begin
               Ctx = unary_ctx((req(?HEARTBEAT))#{peer => undefined}, env(Routes)),
               ?assertEqual(undefined, yuzu_grpc:origin(Ctx))
           end)].

%%%-------------------------------------------------------------------
%%% A one-request call
%%%-------------------------------------------------------------------

unary_test_() ->
    [?CASE("the request starts the handler, which gets it decoded and a ctx naming the connection",
           begin
               {[], St0} = init((req(?HEARTBEAT, #{<<"x-test">> => <<"hello">>}))#{cert => <<"cert">>},
                                env(Routes)),
               Frame = hb_frame(<<"hi">>),
               {Commands, _} = yuzu_grpc_stream_h:data(1, fin, Frame, St0),
               ?assertMatch([{spawn, _, 5000}, {flow, _}], Commands),
               [{spawn, Handler, 5000}, {flow, Flow}] = Commands,
               ?assertEqual(byte_size(Frame), Flow),
               {Handler, Request, Ctx} = started(),
               ?assertMatch(#{session_id := <<"hi">>}, Request),
               ?assertEqual(self(), yuzu_grpc:conn_pid(Ctx)),
               ?assertEqual(<<"hello">>, maps:get(<<"x-test">>, yuzu_grpc:headers(Ctx))),
               ?assertEqual({{127, 0, 0, 1}, 40000}, yuzu_grpc:peer(Ctx)),
               ?assertEqual(<<"cert">>, yuzu_grpc:peer_cert(Ctx))
           end),
     ?CASE("the first frame opens the response; the status closes it; the exit stops the stream",
           begin
               {Handler, St} = start_unary(Routes),
               Ack = make_ref(),
               {Frames, St1} = yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, Ack, <<"F1">>}, St),
               ?assertMatch([{headers, 200, #{<<"content-type">> := <<"application/grpc">>}},
                             {data, nofin, <<"F1">>}], Frames),
               {Frames2, St2} = yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, make_ref(), <<"F2">>}, St1),
               ?assertEqual([{data, nofin, <<"F2">>}], Frames2),
               {End, St3} = yuzu_grpc_stream_h:info(1, {grpc_end, Handler, 0, <<>>}, St2),
               ?assertEqual([{trailers, #{<<"grpc-status">> => <<"0">>}}], End),
               ?assertEqual({[stop], St3}, yuzu_grpc_stream_h:info(1, {'EXIT', Handler, normal}, St3))
           end),
     ?CASE("a status before any frame is a trailers-only response",
           begin
               {Handler, St} = start_unary(Routes),
               {End, _} = yuzu_grpc_stream_h:info(1, {grpc_end, Handler, 5, <<"gone 100%">>}, St),
               ?assertMatch([{response, 200, #{<<"grpc-status">> := <<"5">>,
                                               <<"grpc-message">> := <<"gone 100%25">>,
                                               <<"content-type">> := <<"application/grpc">>}, <<>>}], End)
           end),
     ?CASE("a status given as a binary, or not a status at all, is normalised",
           begin
               {H1, S1} = start_unary(Routes),
               ?assertMatch({[{response, 200, #{<<"grpc-status">> := <<"7">>}, _}], _},
                            yuzu_grpc_stream_h:info(1, {grpc_end, H1, <<"7">>, <<>>}, S1)),
               {H2, S2} = start_unary(Routes),
               ?assertMatch({[{response, 200, #{<<"grpc-status">> := <<"13">>}, _}], _},
                            yuzu_grpc_stream_h:info(1, {grpc_end, H2, banana, <<>>}, S2))
           end),
     ?CASE("a second DATA frame after the handler started is dropped, counted, and credited",
           with_dropped_events(fun() ->
               {_Handler, St} = start_unary(Routes),
               Linked = links(),
               Frame = hb_frame(<<"again">>),
               {Commands, _} = yuzu_grpc_stream_h:data(1, fin, Frame, St),
               ?assertEqual([{flow, byte_size(Frame)}], Commands),
               ?assertEqual({byte_size(Frame), extra_request_data}, dropped_event()),
               ?assertEqual(Linked, links())
           end)),
     ?CASE("a second message in the same DATA frame as the first is dropped and counted",
           with_dropped_events(fun() ->
               Before = links(),
               {[], St} = init(req(?HEARTBEAT), env(Routes)),
               First = hb_frame(<<"one">>),
               Second = hb_frame(<<"two">>),
               {[{spawn, _, _}, {flow, Flow}], _} =
                   yuzu_grpc_stream_h:data(1, fin, <<First/binary, Second/binary>>, St),
               ?assertEqual(byte_size(First) + byte_size(Second), Flow),
               ?assertEqual({byte_size(Second), extra_request_data}, dropped_event()),
               {_, Request, _} = started(),
               ?assertMatch(#{session_id := <<"one">>}, Request),
               %% exactly one handler: the one the first message started
               ?assertEqual(1, length(links() -- Before))
           end)),
     ?CASE("DATA after the status is dropped and counted (the stream is `ended')",
           with_dropped_events(fun() ->
               {Handler, St} = start_unary(Routes),
               {_, Ended} = yuzu_grpc_stream_h:info(1, {grpc_end, Handler, 0, <<>>}, St),
               Linked = links(),
               {Commands, Ended2} = yuzu_grpc_stream_h:data(1, nofin, <<"late">>, Ended),
               ?assertEqual([{flow, 4}], Commands),
               ?assertEqual({4, stream_ended}, dropped_event()),
               ?assertEqual(Ended, Ended2),
               %% only the handler the request started: nothing was spawned for the late DATA
               ?assertEqual(Linked, links())
           end)),
     ?CASE("an empty DATA frame (the END_STREAM of a half-close) is not counted as dropped",
           with_dropped_events(fun() ->
               {_Handler, St} = start_unary(Routes),
               ?assertEqual({[], St}, yuzu_grpc_stream_h:data(1, fin, <<>>, St)),
               receive {dropped, _, _} -> error(empty_frame_counted) after 0 -> ok end
           end)),
     ?CASE("a message split across DATA frames starts the handler once, on the last",
           begin
               {[], St0} = init(req(?HEARTBEAT), env(Routes)),
               <<A:3/binary, B:5/binary, C/binary>> = hb_frame(<<"split-me">>),
               {[{flow, 3}], St1} = yuzu_grpc_stream_h:data(1, nofin, A, St0),
               {[{flow, 5}], St2} = yuzu_grpc_stream_h:data(1, nofin, B, St1),
               {[{spawn, _, _}, {flow, Flow}], _} = yuzu_grpc_stream_h:data(1, fin, C, St2),
               ?assertEqual(byte_size(C), Flow),
               {_, Request, _} = started(),
               ?assertMatch(#{session_id := <<"split-me">>}, Request)
           end),
     ?CASE("END_STREAM before the message is complete is INTERNAL and starts nothing",
           begin
               {[], St0} = init(req(?HEARTBEAT), env(Routes)),
               <<Part:6/binary, _/binary>> = hb_frame(<<"truncated">>),
               {Commands, _} = yuzu_grpc_stream_h:data(1, fin, Part, St0),
               assert_refused(13, {Commands, undefined}),
               receive {probe_started, _, _, _} -> error(handler_started) after 0 -> ok end
           end),
     ?CASE("END_STREAM with no message at all is INTERNAL",
           begin
               {[], St0} = init(req(?HEARTBEAT), env(Routes)),
               assert_refused(13, yuzu_grpc_stream_h:data(1, fin, <<>>, St0))
           end),
     ?CASE("a message over max_message_bytes is RESOURCE_EXHAUSTED, on its header alone",
           begin
               {[], St0} = init(req(?HEARTBEAT), env(Routes, #{limits => #{max_message_bytes => 1024}})),
               assert_refused(8, yuzu_grpc_stream_h:data(1, nofin, <<0, 5000:32, "start">>, St0))
           end),
     ?CASE("a compressed message is UNIMPLEMENTED",
           begin
               {[], St0} = init(req(?HEARTBEAT), env(Routes)),
               assert_refused(12, yuzu_grpc_stream_h:data(1, fin, <<1, 3:32, "abc">>, St0))
           end),
     ?CASE("a message that is not the request type is INTERNAL and starts nothing",
           begin
               {[], St0} = init(req(?HEARTBEAT), env(Routes)),
               assert_refused(13, yuzu_grpc_stream_h:data(1, fin, yuzu_grpc_frame:encode(<<255, 255, 255>>), St0)),
               receive {probe_started, _, _, _} -> error(handler_started) after 0 -> ok end
           end)].

%%%-------------------------------------------------------------------
%%% Deadlines
%%%-------------------------------------------------------------------

deadline_test_() ->
    [?CASE("grpc-timeout arms a timer that tells the stream",
           begin
               Self = self(),
               {[], _} = init(req(?HEARTBEAT, #{<<"grpc-timeout">> => <<"0m">>}), env(Routes)),
               receive {{Self, 1}, grpc_deadline} -> ok after 5000 -> error(no_deadline_message) end
           end),
     ?CASE("no grpc-timeout, no timer",
           begin
               Self = self(),
               {[], _} = init(req(?HEARTBEAT), env(Routes)),
               receive {{Self, 1}, grpc_deadline} -> error(unexpected_deadline) after 0 -> ok end
           end),
     ?CASE("the deadline before the request ends the call with 4 and stops the stream",
           begin
               {[], St} = init(req(?HEARTBEAT, #{<<"grpc-timeout">> => <<"1H">>}), env(Routes)),
               {Commands, _} = yuzu_grpc_stream_h:info(1, grpc_deadline, St),
               assert_refused(4, {Commands, undefined})
           end),
     ?CASE("the deadline while the handler runs sends the trailers and stops the stream",
           begin
               {Handler, St} = start_unary(Routes),
               {Commands, Ended} = yuzu_grpc_stream_h:info(1, grpc_deadline, St),
               ?assertMatch([{response, 200, #{<<"grpc-status">> := <<"4">>}, <<>>}, stop], Commands),
               %% `stop' makes Cowboy shut the handler down; terminate/3 does too if
               %% it is the one asked
               Mon = erlang:monitor(process, Handler),
               ok = yuzu_grpc_stream_h:terminate(1, {stop, deadline, <<>>}, Ended),
               receive {'DOWN', Mon, process, Handler, _} -> ok after 5000 -> error(handler_alive) end
           end),
     ?CASE("the deadline after response headers is a trailers frame",
           begin
               {Handler, St} = start_unary(Routes),
               {_, St1} = yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, make_ref(), <<"F">>}, St),
               ?assertMatch({[{trailers, #{<<"grpc-status">> := <<"4">>}}, stop], _},
                            yuzu_grpc_stream_h:info(1, grpc_deadline, St1))
           end),
     ?CASE("a deadline after the status is nothing",
           begin
               {Handler, St} = start_unary(Routes),
               {_, Ended} = yuzu_grpc_stream_h:info(1, {grpc_end, Handler, 0, <<>>}, St),
               ?assertEqual({[], Ended}, yuzu_grpc_stream_h:info(1, grpc_deadline, Ended))
           end)].

%%%-------------------------------------------------------------------
%%% The handler's exit
%%%-------------------------------------------------------------------

exit_test_() ->
    [?CASE("a handler that exits normally without a status completed",
           begin
               {Handler, St} = start_unary(Routes),
               ?assertMatch({[{response, 200, #{<<"grpc-status">> := <<"0">>}, <<>>}, stop], _},
                            yuzu_grpc_stream_h:info(1, {'EXIT', Handler, normal}, St))
           end),
     ?CASE("any other exit is INTERNAL, logged as its shape only",
           begin
               {Handler, St} = start_unary(Routes),
               {Commands, _} = yuzu_grpc_stream_h:info(
                                 1, {'EXIT', Handler, {{noproc, {gen_server, call, [x, secret_request, 100]}}, []}}, St),
               ?assertMatch([{log, error, _, [?HEARTBEAT, "tuple"]},
                             {response, 200, #{<<"grpc-status">> := <<"13">>}, <<>>}, stop], Commands),
               [{log, error, _, Args} | _] = Commands,
               ?assertEqual(nomatch, string:find(lists:flatten(io_lib:format("~p", [Args])), "secret"))
           end),
     ?CASE("an exit by atom logs the atom, one by {shutdown, _} logs `shutdown'",
           [begin
                {Handler, St} = start_unary(Routes),
                {[{log, error, _, [_, Class]} | _], _} = yuzu_grpc_stream_h:info(1, {'EXIT', Handler, Reason}, St),
                ?assertEqual(Expected, Class)
            end || {Reason, Expected} <- [{killed, "killed"}, {badarg, "badarg"},
                                          {{shutdown, <<"private">>}, "shutdown"},
                                          {<<"binary">>, "other"}]]),
     ?CASE("the exit of a handler whose stream has ended just stops the stream",
           begin
               {Handler, St} = start_unary(Routes),
               {_, Ended} = yuzu_grpc_stream_h:info(1, {grpc_end, Handler, 0, <<>>}, St),
               [?assertEqual({[stop], Ended}, yuzu_grpc_stream_h:info(1, {'EXIT', Handler, Reason}, Ended))
                || Reason <- [normal, killed, {x, y}]]
           end),
     ?CASE("the exit of another process, and unknown messages, are ignored",
           begin
               {_Handler, St} = start_unary(Routes),
               Other = spawn(fun() -> ok end),
               ?assertEqual({[], St}, yuzu_grpc_stream_h:info(1, {'EXIT', Other, normal}, St)),
               ?assertEqual({[], St}, yuzu_grpc_stream_h:info(1, whatever, St)),
               ?assertEqual({[], St}, yuzu_grpc_stream_h:info(1, {grpc_end, Other, 0, <<>>}, St)),
               ?assertEqual({[], St}, yuzu_grpc_stream_h:info(1, {grpc_frame, Other, make_ref(), <<"F">>}, St))
           end),
     ?CASE("terminate shuts the handler down",
           begin
               {Handler, St} = start_unary(Routes),
               Mon = erlang:monitor(process, Handler),
               ok = yuzu_grpc_stream_h:terminate(1, normal, St),
               receive {'DOWN', Mon, process, Handler, Reason} -> ?assertEqual(shutdown, Reason)
               after 5000 -> error(handler_alive) end
           end)].

%%%-------------------------------------------------------------------
%%% Sending: acks and backpressure
%%%-------------------------------------------------------------------

backpressure_test_() ->
    [?CASE("a frame is acknowledged at once while the connection can take it",
           begin
               {Handler, St} = start_unary(Routes),
               Ack = make_ref(),
               {_, St1} = yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, Ack, <<"F">>}, St),
               Handler ! sentinel,
               %% same sender, so the ack was sent before the sentinel
               ?assertEqual({grpc_ack, Ack}, got(Handler)),
               ?assertEqual(sentinel, got(Handler)),
               ?assertNotEqual(St, St1)
           end),
     ?CASE("while a buffer alarm is on the ack is held until it goes off",
           begin
               {Handler, St} = start_unary(Routes),
               {[], St1} = yuzu_grpc_stream_h:info(1, {alarm, stream_buffer_full, on}, St),
               Ack = make_ref(),
               {Commands, St2} = yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, Ack, <<"F">>}, St1),
               ?assertMatch([{headers, 200, _}, {data, nofin, <<"F">>}], Commands),
               Handler ! sentinel,
               {[], _} = yuzu_grpc_stream_h:info(1, {alarm, stream_buffer_full, off}, St2),
               ?assertEqual(sentinel, got(Handler)),
               ?assertEqual({grpc_ack, Ack}, got(Handler))
           end),
     ?CASE("both the connection and the stream alarm must clear",
           begin
               {Handler, St} = start_unary(Routes),
               {[], S1} = yuzu_grpc_stream_h:info(1, {alarm, connection_buffer_full, on}, St),
               {[], S2} = yuzu_grpc_stream_h:info(1, {alarm, stream_buffer_full, on}, S1),
               Ack = make_ref(),
               {_, S3} = yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, Ack, <<"F">>}, S2),
               {[], S4} = yuzu_grpc_stream_h:info(1, {alarm, connection_buffer_full, off}, S3),
               Handler ! first_sentinel,
               {[], _} = yuzu_grpc_stream_h:info(1, {alarm, stream_buffer_full, off}, S4),
               ?assertEqual(first_sentinel, got(Handler)),
               ?assertEqual({grpc_ack, Ack}, got(Handler))
           end),
     ?CASE("a frame after the stream ended is refused with a nack",
           begin
               {Handler, St} = start_unary(Routes),
               {_, Ended} = yuzu_grpc_stream_h:info(1, {grpc_end, Handler, 4, <<>>}, St),
               Ack = make_ref(),
               ?assertEqual({[], Ended}, yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, Ack, <<"F">>}, Ended)),
               ?assertEqual({grpc_nack, Ack}, got(Handler))
           end),
     ?CASE("a sender still held when the stream ends is nacked, not left waiting",
           begin
               {Handler, St} = start_unary(Routes),
               {[], S1} = yuzu_grpc_stream_h:info(1, {alarm, stream_buffer_full, on}, St),
               Ack = make_ref(),
               {_, S2} = yuzu_grpc_stream_h:info(1, {grpc_frame, Handler, Ack, <<"F">>}, S1),
               {_, _Ended} = yuzu_grpc_stream_h:info(1, grpc_deadline, S2),
               ?assertEqual({grpc_nack, Ack}, got(Handler))
           end)].

%%%-------------------------------------------------------------------
%%% Streaming calls
%%%-------------------------------------------------------------------

bidi_test_() ->
    [?CASE("the handler starts at once, before any message",
           begin
               {Commands, _} = init(req(?SUBSCRIBE), env(Routes)),
               ?assertMatch([{spawn, _, 5000}], Commands),
               {_Handler, Ref, _Stream} = started(),
               ?assert(is_reference(Ref))
           end),
     ?CASE("each message reaches the handler as {Ref, Map}, in order, and END_STREAM as {Ref, eos}",
           begin
               {Handler, Ref, St} = start_bidi(Routes),
               Frames = <<(cmd_frame(<<"a">>))/binary, (cmd_frame(<<"b">>))/binary>>,
               {[{flow, Flow}], St1} = yuzu_grpc_stream_h:data(1, nofin, Frames, St),
               ?assertEqual(byte_size(Frames), Flow),
               {[{flow, _}], _} = yuzu_grpc_stream_h:data(1, fin, cmd_frame(<<"c">>), St1),
               ?assertMatch({Ref, #{command_id := <<"a">>}}, got(Handler)),
               ?assertMatch({Ref, #{command_id := <<"b">>}}, got(Handler)),
               ?assertMatch({Ref, #{command_id := <<"c">>}}, got(Handler)),
               ?assertEqual({Ref, eos}, got(Handler))
           end),
     ?CASE("a message split across DATA frames is delivered once, whole",
           begin
               {Handler, Ref, St} = start_bidi(Routes),
               <<A:4/binary, B/binary>> = cmd_frame(<<"whole">>),
               {[{flow, 4}], St1} = yuzu_grpc_stream_h:data(1, nofin, A, St),
               {[{flow, _}], _} = yuzu_grpc_stream_h:data(1, nofin, B, St1),
               ?assertMatch({Ref, #{command_id := <<"whole">>}}, got(Handler))
           end),
     ?CASE("a stream with no body is a handler that sees only eos",
           begin
               {Commands, _} = init((req(?SUBSCRIBE))#{has_body => false}, env(Routes)),
               ?assertMatch([{spawn, _, 5000}], Commands),
               {Handler, Ref, _} = started(),
               ?assertEqual({Ref, eos}, got(Handler))
           end),
     ?CASE("END_STREAM inside a message ends the call with INTERNAL",
           begin
               {Handler, _Ref, St} = start_bidi(Routes),
               <<Part:5/binary, _/binary>> = cmd_frame(<<"truncated">>),
               {Commands, _} = yuzu_grpc_stream_h:data(1, fin, Part, St),
               assert_refused(13, {Commands, undefined}),
               ?assert(is_pid(Handler))
           end),
     ?CASE("an oversize message ends the call with RESOURCE_EXHAUSTED and stops the stream",
           begin
               {Handler, Ref, St} = start_bidi(Routes, #{limits => #{max_message_bytes => 64}}),
               {Commands, Ended} = yuzu_grpc_stream_h:data(
                                     1, nofin, <<(cmd_frame(<<"ok">>))/binary, 0, 5000:32>>, St),
               %% the message before the oversize one was delivered
               ?assertMatch({Ref, #{command_id := <<"ok">>}}, got(Handler)),
               assert_refused(8, {Commands, undefined}),
               %% and the stream no longer takes DATA
               ?assertMatch({[{flow, 3}], _}, yuzu_grpc_stream_h:data(1, nofin, <<"abc">>, Ended))
           end),
     ?CASE("a message that is not the request type ends the call with INTERNAL",
           begin
               {_Handler, _Ref, St} = start_bidi(Routes),
               {Commands, _} = yuzu_grpc_stream_h:data(1, nofin, yuzu_grpc_frame:encode(<<255, 255, 255>>), St),
               assert_refused(13, {Commands, undefined})
           end)].

%%%-------------------------------------------------------------------
%%% No callback raises
%%%-------------------------------------------------------------------

no_raise_test_() ->
    [?CASE("init on a request it cannot read ends the stream INTERNAL, logging the class only",
           begin
               {Commands, _} = init(#{secret => <<"S3CR3T">>}, env(Routes)),
               ?assertMatch([{log, error, _, ["error"]},
                             {response, 200, #{<<"grpc-status">> := <<"13">>}, <<>>}, stop], Commands),
               ?assertEqual(nomatch, string:find(lists:flatten(io_lib:format("~p", [Commands])), "S3CR3T"))
           end),
     ?CASE("data on a stream it cannot read ends the stream INTERNAL",
           begin
               {[], St} = init(req(?HEARTBEAT), env(Routes)),
               {Commands, _} = yuzu_grpc_stream_h:data(1, nofin, not_a_binary, St),
               ?assertMatch([{log, error, _, ["error"]},
                             {response, 200, #{<<"grpc-status">> := <<"13">>}, <<>>}, stop], Commands)
           end),
     ?CASE("early_error passes Cowboy's own response through",
           begin
               Resp = {response, 501, #{<<"content-length">> => <<"0">>}, <<>>},
               ?assertEqual(Resp, yuzu_grpc_stream_h:early_error(1, {stream_error, no_error, x}, #{}, Resp, #{}))
           end)].

%%%-------------------------------------------------------------------
%%% Plumbing
%%%-------------------------------------------------------------------

%% Run Fun(Routes) as the "connection process": exits trapped (the handlers are
%% linked to it), the probe service reporting to it, handlers cleaned up after.
in_conn(Fun) ->
    {ok, _} = application:ensure_all_started(telemetry),
    OldTrap = process_flag(trap_exit, true),
    yuzu_grpc_probe_svc:set_test_pid(self()),
    put(probe_pids, []),
    {ok, Routes} = yuzu_grpc_route:build([agent_pb], #{?SVC => yuzu_grpc_probe_svc}),
    try
        Fun(Routes)
    after
        [exit(P, kill) || P <- get(probe_pids)],
        yuzu_grpc_probe_svc:clear_test_pid(),
        flush(),
        process_flag(trap_exit, OldTrap)
    end.

%% The processes linked to the test process: every handler the stream handler
%% spawns is linked to its "connection", and spawn_link returns only once the
%% link exists, so this says deterministically how many handlers there are.
links() ->
    {links, Links} = process_info(self(), links),
    lists:sort(Links).

flush() ->
    receive _ -> flush() after 0 -> ok end.

env(Routes) ->
    env(Routes, #{}).

env(Routes, Extra) ->
    maps:merge(#{grpc => Routes, auth_fun => undefined, limits => #{}}, Extra).

init(Req, Env) ->
    yuzu_grpc_stream_h:init(1, Req, #{env => Env, stream_handlers => []}).

req(Path) ->
    req(Path, #{}).

req(Path, Headers) ->
    req(Path, Headers, []).

%% A request as Cowboy builds it; Drop names default headers to leave out.
req(Path, Headers, Drop) ->
    Defaults = maps:without(Drop, #{<<"content-type">> => <<"application/grpc">>}),
    #{method => <<"POST">>, path => Path, headers => maps:merge(Defaults, Headers),
      peer => {{127, 0, 0, 1}, 40000}, cert => undefined, has_body => true}.

hb_frame(Command) ->
    yuzu_grpc_frame:encode(agent_pb:encode_msg(#{session_id => Command}, ?HB_REQ)).

cmd_frame(Id) ->
    yuzu_grpc_frame:encode(agent_pb:encode_msg(#{command_id => Id}, ?CMD_RESP)).

%% A unary call whose handler has started: {HandlerPid, StateAfterTheRequest}.
start_unary(Routes) ->
    {[], St0} = init(req(?HEARTBEAT), env(Routes)),
    {[{spawn, Handler, _}, {flow, _}], St} = yuzu_grpc_stream_h:data(1, fin, hb_frame(<<"x">>), St0),
    {Handler, _, _} = started(),
    {Handler, St}.

start_bidi(Routes) ->
    start_bidi(Routes, #{}).

start_bidi(Routes, EnvExtra) ->
    {[{spawn, _, _}], St} = init(req(?SUBSCRIBE), env(Routes, EnvExtra)),
    {Handler, Ref, _} = started(),
    {Handler, Ref, St}.

%% The next handler the probe service started: {Pid, Arg, Handle}.
started() ->
    receive
        {probe_started, Handler, Arg, Handle} ->
            put(probe_pids, [Handler | get(probe_pids)]),
            {Handler, Arg, Handle}
    after 5000 ->
        error(no_handler_started)
    end.

%% The next message the handler received, as it forwarded it.
got(Handler) ->
    receive
        {probe_got, Handler, Msg} -> Msg
    after 5000 ->
        error({handler_received_nothing, Handler})
    end.

%% A refusal: trailers-only 200 with the status, then `stop'.
assert_refused(Status, {Commands, _State}) ->
    Expected = integer_to_binary(Status),
    ?assertMatch([{response, 200, #{<<"grpc-status">> := Expected,
                                    <<"content-type">> := <<"application/grpc">>}, <<>>}, stop],
                 Commands).

%% The ctx a unary handler is handed for a request.
unary_ctx(Req, Env) ->
    {[], St0} = init(Req, Env),
    {[{spawn, _, _}, {flow, _}], _} = yuzu_grpc_stream_h:data(1, fin, hb_frame(<<"x">>), St0),
    {_Handler, _Request, Ctx} = started(),
    Ctx.

%% Telemetry: capture the origin_ignored events for the duration of Fun.
with_origin_events(Fun) ->
    fun() ->
        Id = {?MODULE, make_ref()},
        ok = telemetry:attach(Id, [yuzu, gw, grpc, origin_ignored], fun ?MODULE:forward_origin/4,
                              self()),
        try Fun() after telemetry:detach(Id) end
    end.

forward_origin(_Event, #{count := 1}, #{mode := Mode, reason := Reason}, Pid) ->
    Pid ! {origin_ignored, Mode, Reason},
    ok.

origin_event() ->
    receive {origin_ignored, Mode, Reason} -> {Mode, Reason}
    after 5000 -> error(no_origin_event) end.

%% Telemetry: capture the dropped_data events for the duration of Fun.
with_dropped_events(Fun) ->
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, grpc, dropped_data], fun ?MODULE:forward_dropped/4, self()),
    try Fun() after telemetry:detach(Id) end.

forward_dropped(_Event, #{bytes := Bytes}, #{reason := Reason}, Pid) ->
    Pid ! {dropped, Bytes, Reason},
    ok.

dropped_event() ->
    receive {dropped, Bytes, Reason} -> {Bytes, Reason} after 5000 -> error(no_dropped_event) end.
