%%%-------------------------------------------------------------------
%%% @doc The state machine of yuzu_grpc_stream_h, driven through its Cowboy
%%% callbacks directly. The test process stands in for the Cowboy connection
%%% process: it makes the init/data/info calls, receives what the handler sends
%%% to the connection, and is the pid the handler's ctx names. The handlers are
%%% yuzu_grpc_probe_svc, which hands the test everything it receives.
%%%
%%% These cases cover what a real HTTP/2 client cannot provoke or cannot be told
%%% apart on the wire: that every refusal ends in `stop' (Cowboy then drops the
%%% stream and the handler), that DATA after a start is dropped and counted,
%%% that an exit term never reaches a log command, and that no callback raises
%%% (Cowboy would log the request it was given).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_stream_h_tests).
-include_lib("eunit/include/eunit.hrl").
-include("yuzu_grpc.hrl").

-export([forward_dropped/4, forward_origin/4]).
%% the failing handlers of the runner log cases, and the logger handler callback
-export([crash/2, bad_return/2, log/2]).

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
     ?CASE("an unusable x-forwarded-for from a trusted proxy is no observation (not the proxy) and is counted",
           with_origin_events(
             fun() ->
                 Ctx = unary_ctx(ViaLb(req(?HEARTBEAT, Xff(<<"not-an-address">>))),
                                 FwdEnv(Routes, [Lb])),
                 ?assertEqual(undefined, yuzu_grpc:origin(Ctx)),
                 %% the TCP peer is still known, and is still the proxy
                 ?assertEqual({Lb, 40000}, yuzu_grpc:peer(Ctx)),
                 ?assertEqual({forwarded_for, bad_claim}, origin_event())
             end)),
     ?CASE("no x-forwarded-for from a trusted proxy is no observation and is counted",
           with_origin_events(
             fun() ->
                 Ctx = unary_ctx(ViaLb(req(?HEARTBEAT)), FwdEnv(Routes, [Lb])),
                 ?assertEqual(undefined, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({forwarded_for, no_claim}, origin_event())
             end)),
     ?CASE("fewer x-forwarded-for entries than trusted_hops is no observation and is counted",
           with_origin_events(
             fun() ->
                 Env = env(Routes, #{origin => #{mode => forwarded_for, sources => [Lb],
                                                 trusted_hops => 1}}),
                 Ctx = unary_ctx(ViaLb(req(?HEARTBEAT, Xff(<<"203.0.113.9">>))), Env),
                 ?assertEqual(undefined, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({forwarded_for, bad_claim}, origin_event())
             end)),
     ?CASE("an x-forwarded-for that is not UTF-8 is served: attributed by the rules, no error logged",
           with_origin_events(
             fun() ->
                 Env = FwdEnv(Routes, [Lb]),
                 %% bytes the client chose to the left of the proxy's entry
                 Junk = <<255, 254, 253, ", ", 192, 128, ", 203.0.113.9">>,
                 {[], St0} = init(ViaLb(req(?HEARTBEAT, Xff(Junk))), Env),
                 {Commands, _} = yuzu_grpc_stream_h:data(1, fin, hb_frame(<<"x">>), St0),
                 ?assertMatch([{spawn, _, _}, {flow, _}], Commands),
                 {_, _, Ctx} = started(),
                 ?assertEqual({Client, forwarded_for}, yuzu_grpc:origin(Ctx)),
                 %% and as the selected entry: no observation, a bad claim, still served
                 {InitCommands, St1} = init(ViaLb(req(?HEARTBEAT, Xff(<<"1.1.1.1, ", 255, 254>>))), Env),
                 ?assertEqual([], InitCommands),
                 ?assertEqual({forwarded_for, bad_claim}, origin_event()),
                 {DataCommands, _} = yuzu_grpc_stream_h:data(1, fin, hb_frame(<<"x">>), St1),
                 ?assertMatch([{spawn, _, _}, {flow, _}], DataCommands),
                 {_, _, Ctx2} = started(),
                 ?assertEqual(undefined, yuzu_grpc:origin(Ctx2)),
                 %% neither call produced a log command (Cowboy would print it as an error)
                 ?assertEqual([], [C || C = {log, _, _, _} <- InitCommands ++ DataCommands])
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
     ?CASE("a PROXY LOCAL (the balancer's own health check) is no observation and is counted",
           with_origin_events(
             fun() ->
                 Req = (ViaLb(req(?HEARTBEAT)))#{proxy_header => #{version => 2, command => local}},
                 Ctx = unary_ctx(Req, ProxyEnv(Routes, [Lb])),
                 ?assertEqual(undefined, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({proxy_protocol, no_claim}, origin_event())
             end)),
     ?CASE("a PROXY header with no address, or none at all, is no observation and is counted",
           with_origin_events(
             fun() ->
                 Unspec = #{version => 2, command => proxy, transport_family => undefined},
                 Ctx = unary_ctx((ViaLb(req(?HEARTBEAT)))#{proxy_header => Unspec},
                                 ProxyEnv(Routes, [Lb])),
                 ?assertEqual(undefined, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({proxy_protocol, bad_claim}, origin_event()),
                 Ctx2 = unary_ctx(ViaLb(req(?HEARTBEAT)), ProxyEnv(Routes, [Lb])),
                 ?assertEqual(undefined, yuzu_grpc:origin(Ctx2)),
                 ?assertEqual({proxy_protocol, no_claim}, origin_event())
             end)),
     ?CASE("a peer that is not a trusted proxy keeps the TCP peer as the origin, in both proxy modes",
           with_origin_events(
             fun() ->
                 Ctx = unary_ctx(req(?HEARTBEAT), FwdEnv(Routes, [Lb])),
                 ?assertEqual({{127, 0, 0, 1}, transport}, yuzu_grpc:origin(Ctx)),
                 ?assertEqual({forwarded_for, untrusted_source}, origin_event()),
                 Ctx2 = unary_ctx(req(?HEARTBEAT), ProxyEnv(Routes, [Lb])),
                 ?assertEqual({{127, 0, 0, 1}, transport}, yuzu_grpc:origin(Ctx2)),
                 ?assertEqual({proxy_protocol, untrusted_source}, origin_event())
             end)),
     ?CASE("a transport listener never reports no observation for a known peer",
           begin
               Ctx = unary_ctx(ViaLb(req(?HEARTBEAT)), env(Routes)),
               ?assertEqual({Lb, transport}, yuzu_grpc:origin(Ctx))
           end),
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
     %% #5591: the request's DATA reaching the gateway after the deadline fired
     %% must never run a handler (grpcbox discarded the ended state, so it did)
     ?CASE("DATA that arrives after the deadline is dropped and runs no handler (#5591)",
           with_dropped_events(fun() ->
               {[], St} = init(req(?HEARTBEAT, #{<<"grpc-timeout">> => <<"1H">>}), env(Routes)),
               {_, Ended} = yuzu_grpc_stream_h:info(1, grpc_deadline, St),
               Linked = links(),
               Frame = hb_frame(<<"late">>),
               {Commands, Ended2} = yuzu_grpc_stream_h:data(1, fin, Frame, Ended),
               ?assertEqual([{flow, byte_size(Frame)}], Commands),
               ?assertEqual({byte_size(Frame), stream_ended}, dropped_event()),
               ?assertEqual(Ended, Ended2),
               %% nothing was spawned or linked, and no handler was started
               ?assertEqual(Linked, links()),
               receive {probe_started, _, _, _} -> error(handler_started) after 0 -> ok end
           end)),
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
%%% A failing handler is logged where an operator can see it
%%%-------------------------------------------------------------------

%% The gateway ships OTP's default handler filters: `filter_default => stop', and
%% only events with no domain (or an OTP one) pass. An event the runner tagged
%% with a domain of its own is dropped before it is printed, so the line exists
%% only if it carries none.
default_handler_filters() ->
    [{remote_gl, {fun logger_filters:remote_gl/2, stop}},
     {domain, {fun logger_filters:domain/2, {log, super, [otp, sasl]}}},
     {no_domain, {fun logger_filters:domain/2, {log, undefined, []}}}].

runner_log_test_() ->
    [{"the filters are the default ones: a domain-tagged event is dropped, an untagged one is shown",
      fun() -> with_default_handler(fun() ->
          logger:warning("tagged", [], #{domain => [yuzu_gw, grpc]}),
          logger:warning("untagged"),
          %% custom handlers run in the logging process, so both were decided already
          ?assertEqual(["untagged"], logged_texts(fun(T) -> lists:member(T, ["tagged", "untagged"]) end))
      end) end},
     {"a handler that raises is logged with its method, exception class and top frame, and answers INTERNAL",
      fun() -> with_default_handler(fun() ->
          {Status, Message} = run_failing(crash, #{token => <<"S3CR3T">>}),
          ?assertEqual({?GRPC_STATUS_INTERNAL, <<"internal error">>}, {Status, Message}),
          [Text] = runner_texts(),
          ?assertNotEqual(nomatch, string:find(Text, "/yuzu.agent.v1.AgentService/Heartbeat")),
          ?assertNotEqual(nomatch, string:find(Text, "class=error")),
          ?assertNotEqual(nomatch, string:find(Text, "yuzu_grpc_stream_h_tests:crash/2")),
          %% never the reason, the request or the arguments
          ?assertEqual(nomatch, string:find(Text, "S3CR3T")),
          ?assertEqual(nomatch, string:find(Text, "secret"))
      end) end},
     {"failure lines are limited to one per interval and the next line counts what it skipped",
      fun() -> with_default_handler(fun() ->
          application:unset_env(yuzu_gw, grpc_runner_warn_interval_ms),
          yuzu_grpc_runner:reset_throttle(),
          Warn = fun(Now) -> yuzu_grpc_runner:warn_throttled(Now, ?HEARTBEAT, error, "m:f/1") end,
          [Warn(T) || T <- [0, 1, 500, 999]],
          [First] = runner_texts(),
          ?assertEqual(nomatch, string:find(First, "not logged")),
          ?assertNotEqual(nomatch, string:find(First, "class=error at m:f/1")),
          Warn(1000),
          [Second] = runner_texts(),
          ?assertNotEqual(nomatch, string:find(Second, "(3 similar failures not logged")),
          %% the count restarts after a line: one skipped at 1500, then the line at 2000
          Warn(1500),
          ?assertEqual([], runner_texts()),
          Warn(2000),
          [Third] = runner_texts(),
          ?assertNotEqual(nomatch, string:find(Third, "(1 similar failures not logged"))
      end) end},
     {"failures that arrive together write one line and are all counted",
      fun() -> with_default_handler(fun() ->
          application:unset_env(yuzu_gw, grpc_runner_warn_interval_ms),
          yuzu_grpc_runner:reset_throttle(),
          Pids = [spawn_monitor(fun() ->
                                    yuzu_grpc_runner:warn_throttled(5, ?HEARTBEAT, error, "m:f/1")
                                end) || _ <- lists:seq(1, 50)],
          [receive {'DOWN', Ref, process, Pid, _} -> ok after 5000 -> error(no_down) end
           || {Pid, Ref} <- Pids],
          ?assertEqual(1, length(runner_texts())),
          yuzu_grpc_runner:warn_throttled(1005, ?HEARTBEAT, error, "m:f/1"),
          [Next] = runner_texts(),
          ?assertNotEqual(nomatch, string:find(Next, "(49 similar failures not logged"))
      end) end},
     {"a burst of failing calls writes one line and each call still answers INTERNAL",
      fun() -> with_default_handler(fun() ->
          application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, 3600000),
          yuzu_grpc_runner:reset_throttle(),
          Answers = [run_failing(crash, #{token => <<"S3CR3T">>}) || _ <- lists:seq(1, 5)],
          ?assertEqual(lists:duplicate(5, {?GRPC_STATUS_INTERNAL, <<"internal error">>}), Answers),
          [Text] = runner_texts(),
          ?assertNotEqual(nomatch, string:find(Text, "class=error")),
          ?assertEqual(nomatch, string:find(Text, "S3CR3T"))
      end) end},
     {"an interval that is not a non-negative integer reads as the default of one second",
      fun() -> with_default_handler(fun() ->
          lists:foreach(
            fun(Bad) ->
                application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, Bad),
                ?assertEqual(1000, yuzu_grpc_runner:warn_interval(), Bad),
                yuzu_grpc_runner:reset_throttle(),
                Warn = fun(Now) -> yuzu_grpc_runner:warn_throttled(Now, ?HEARTBEAT, error, "m:f/1") end,
                Warn(0), Warn(999),
                ?assertEqual(1, length(runner_texts()), Bad),
                Warn(1000),
                [Next] = runner_texts(),
                ?assertNotEqual(nomatch, string:find(Next, "(1 similar failures not logged"), Bad)
            end, [-1, 1.5, "100", <<"100">>, infinity, undefined, abc])
      end) end},
     {"an interval above an hour is an hour: a typo cannot silence the log",
      fun() -> with_default_handler(fun() ->
          Warn = fun(Now) -> yuzu_grpc_runner:warn_throttled(Now, ?HEARTBEAT, error, "m:f/1") end,
          lists:foreach(
            fun(Huge) ->
                application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, Huge),
                ?assertEqual(3600000, yuzu_grpc_runner:warn_interval(), Huge),
                yuzu_grpc_runner:reset_throttle(),
                Warn(0), Warn(3599999),
                ?assertEqual(1, length(runner_texts()), Huge),
                Warn(3600000),
                ?assertEqual(1, length(runner_texts()), Huge)
            end, [3600001, 1000000000000, 1 bsl 80]),
          %% an hour exactly, and 0 (every failure), are kept
          application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, 3600000),
          ?assertEqual(3600000, yuzu_grpc_runner:warn_interval()),
          application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, 0),
          ?assertEqual(0, yuzu_grpc_runner:warn_interval())
      end) end},
     {"init_throttle creates the limit's state once and resets it afterwards, without replacing it",
      fun() ->
          Key = {yuzu_grpc_runner, warn_throttle},
          Prev = persistent_term:get(Key, undefined),
          try
              persistent_term:erase(Key),
              ok = yuzu_grpc_runner:init_throttle(),
              Made = persistent_term:get(Key),
              %% a failure the limit swallowed is counted in slot 2; init forgets it
              atomics:put(Made, 1, 5000),
              atomics:put(Made, 2, 7),
              ok = yuzu_grpc_runner:init_throttle(),
              ?assertEqual(Made, persistent_term:get(Key)),
              ?assertEqual(0, atomics:get(Made, 2)),
              ?assert(atomics:get(Made, 1) < -1000000)
          after
              case Prev of
                  undefined -> yuzu_grpc_runner:init_throttle();
                  _ -> persistent_term:put(Key, Prev)
              end
          end
      end},
     {"a failure that finds no state makes it, takes no global lock, and is logged",
      fun() -> with_default_handler(fun() ->
          Key = {yuzu_grpc_runner, warn_throttle},
          application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, 1000),
          persistent_term:erase(Key),
          %% Another process holds the global lock the former implementation took
          %% for this resource: a caller that asks for it cannot proceed.
          Self = self(),
          Holder = spawn_link(fun() ->
                                  true = global:set_lock({Key, self()}, [node()], 1),
                                  Self ! locked,
                                  receive release -> ok end
                              end),
          receive locked -> ok after 5000 -> error(lock_not_taken) end,
          {Pid, Ref} = spawn_monitor(fun() ->
              yuzu_grpc_runner:warn_throttled(5, ?HEARTBEAT, error, "m:f/1")
          end),
          receive {'DOWN', Ref, process, Pid, normal} -> ok
          after 3000 -> exit(Pid, kill), Holder ! release, error(blocked_on_a_lock)
          end,
          Holder ! release,
          ?assertEqual(1, length(runner_texts())),
          ?assertNotEqual(undefined, persistent_term:get(Key, undefined))
      end) end},
     {"a handler that returns something else is logged the same way",
      fun() -> with_default_handler(fun() ->
          ?assertEqual({?GRPC_STATUS_INTERNAL, <<"internal error">>},
                       run_failing(bad_return, #{token => <<"S3CR3T">>})),
          [Text] = runner_texts(),
          ?assertNotEqual(nomatch, string:find(Text, "class=bad_return")),
          ?assertEqual(nomatch, string:find(Text, "S3CR3T"))
      end) end}].

%% Run Fun with a handler installed with the default filters; it forwards every
%% event it is given to this process.
with_default_handler(Fun) ->
    {ok, _} = application:ensure_all_started(telemetry),
    %% a case that reads the runner's line for its own failure: no rate limit,
    %% unless the case sets one (the rate limit cases below do)
    application:set_env(yuzu_gw, grpc_runner_warn_interval_ms, 0),
    yuzu_grpc_runner:reset_throttle(),
    Id = yuzu_grpc_stream_h_tests_log,
    catch logger:remove_handler(Id),
    ok = logger:add_handler(Id, ?MODULE,
                            #{level => all, filter_default => stop,
                              filters => default_handler_filters(),
                              config => #{pid => self()}}),
    Level = maps:get(level, logger:get_primary_config()),
    ok = logger:set_primary_config(level, all),
    try
        Fun()
    after
        application:unset_env(yuzu_gw, grpc_runner_warn_interval_ms),
        yuzu_grpc_runner:reset_throttle(),
        logger:remove_handler(Id),
        logger:set_primary_config(level, Level),
        flush()
    end.

%% Run the real runner on a handler of this module, as a stream handler would
%% (a linked process); this process is the "connection" and gets the status.
run_failing(Function, Request) ->
    Stream = #yuzu_grpc_stream{conn = self(), stream_id = 1, ctx = ctx:new(),
                               method = <<"/yuzu.agent.v1.AgentService/Heartbeat">>,
                               pb = agent_pb, output = 'yuzu.agent.v1.HeartbeatResponse'},
    OldTrap = process_flag(trap_exit, true),
    try
        Pid = proc_lib:spawn_link(yuzu_grpc_runner, run,
                                  [#{kind => unary, module => ?MODULE, function => Function,
                                     stream => Stream, request => Request}]),
        Self = self(),
        receive {{Self, 1}, {grpc_end, Pid, Status, Message}} -> {Status, Message}
        after 5000 -> error(runner_sent_no_status)
        end
    after
        process_flag(trap_exit, OldTrap),
        receive {'EXIT', _, _} -> ok after 0 -> ok end
    end.

crash(_Ctx, #{token := Token}) ->
    erlang:error({secret, Token}).

bad_return(_Ctx, _Request) ->
    {definitely, not_a_result}.

%% The runner logs before it reports its status, from the same process, so the
%% line is in the mailbox once the status has been received. Only the events that
%% satisfy Keep are returned: the handler sees every event of the node, and a
%% line of another process must not decide a case.
logged_texts(Keep) ->
    [T || T <- all_logged_texts(), Keep(T)].

runner_texts() ->
    logged_texts(fun(T) -> string:find(T, "gateway grpc handler") =/= nomatch end).

all_logged_texts() ->
    receive
        {logged, Text} -> [Text | all_logged_texts()]
    after 0 -> []
    end.

%% logger handler callback: runs in the logging process.
log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {logged, lists:flatten(logger_formatter:format(Event, #{single_line => true,
                                                                  template => [msg]}))},
    ok.

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
    Id = {?MODULE, make_ref()},
    ok = telemetry:attach(Id, [yuzu, gw, grpc, origin_ignored], fun ?MODULE:forward_origin/4,
                          self()),
    try Fun() after telemetry:detach(Id) end.

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
