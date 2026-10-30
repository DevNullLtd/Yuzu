%%%-------------------------------------------------------------------
%%% @doc An independent check of the gateway's HTTP/2 + gRPC server layer.
%%%
%%% The gateway's client (gun) and server (cowboy) share cowlib (cow_http2,
%%% cow_http2_machine, cow_hpack), and the test client and server share
%%% yuzu_grpc_frame; a bug symmetric in those (HPACK, SETTINGS and flow control,
%%% the trailers-only shape, grpc-message encoding, the 5-byte message prefix)
%%% would pass every test that has the one talk to the other. curl links
%%% nghttp2, an HTTP/2 + HPACK implementation of its own, so a request built
%%% BYTE BY BYTE here, without yuzu_grpc_frame, and sent by curl to the stub
%%% AgentService behind a real yuzu_grpc_listener, is the cheap independent
%%% witness for the server direction:
%%%
%%%   - a unary call answers HTTP 200, content-type application/grpc and the
%%%     response message in a length-prefixed frame (grpc-status 0 in the
%%%     trailers when this curl reads them: curl 7.76 often does not);
%%%   - an unexported method answers grpc-status 12 (UNIMPLEMENTED), and a
%%%     handler's error status reaches the trailers.
%%%
%%% The tests need a curl that speaks HTTP/2 (`curl --version' lists HTTP2).
%%% Without one (or off a POSIX shell, i.e. on Windows) they are SKIPPED with a line saying so; with
%%% YUZU_REQUIRE_CURL_H2_TEST=1 a missing curl is a failure, so CI can insist.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_independent_h2_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SVC, 'yuzu.agent.v1.AgentService').
-define(HEARTBEAT, "/yuzu.agent.v1.AgentService/Heartbeat").
-define(NOSUCH, "/yuzu.agent.v1.AgentService/NoSuchMethod").

curl_h2_test_() ->
    case curl_h2() of
        {ok, Curl} ->
            {setup,
             fun setup/0,
             fun cleanup/1,
             fun(#{port := Port}) ->
                [{"a unary call: 200, application/grpc, the framed response",
                  {timeout, 30, fun() -> unary_call(Curl, Port) end}},
                 {"an unexported method: grpc-status 12",
                  {timeout, 30, fun() -> unimplemented(Curl, Port) end}},
                 {"a handler's error status reaches the trailers with its message",
                  {timeout, 30, fun() -> error_status(Curl, Port) end}}]
             end};
        {error, Why} ->
            case os:getenv("YUZU_REQUIRE_CURL_H2_TEST") of
                "1" -> [{"curl with HTTP/2 is required here",
                         fun() -> erlang:error({curl_h2_unavailable, Why}) end}];
                _   -> io:format(user, "~nSKIPPED yuzu_grpc_independent_h2_tests: ~ts~n", [Why]),
                       []
            end
    end.

setup() ->
    {ok, _} = application:ensure_all_started(cowboy),
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_grpc_stub_svc:init_state(),
    {Port, Listener} = yuzu_gw_test_listener:start(
                         #{name => independent_h2, service_protos => [agent_pb],
                           services => #{?SVC => yuzu_grpc_stub_svc}}),
    #{port => Port, listener => Listener}.

cleanup(#{listener := Listener}) ->
    yuzu_gw_test_listener:stop(Listener).

%%--------------------------------------------------------------------
%% The calls. HeartbeatRequest{session_id = "ok"} is field 1, length-delimited:
%% 0a 02 6f 6b. The gRPC message prefix is a flag byte (0) and a 4-byte
%% big-endian length. Both are written out here, not built by yuzu_grpc_frame.
%% The response HeartbeatResponse{acknowledged = true} is 08 01.
%%--------------------------------------------------------------------

unary_call(Curl, Port) ->
    Request = <<0, 0, 0, 0, 4, 16#0a, 16#02, 16#6f, 16#6b>>,
    #{exit := 0, status := Status, headers := Headers, trace := Trace, body := Body} =
        call(Curl, Port, ?HEARTBEAT, Request),
    ?assertEqual(200, Status),
    ?assertEqual(<<"application/grpc">>, header(<<"content-type">>, Headers)),
    ?assertEqual(<<0, 0, 0, 0, 2, 16#08, 16#01>>, Body),
    %% The trailers follow the body in a HEADERS frame of their own, and curl
    %% 7.76 (the oldest this is meant to run with) often finishes the transfer
    %% without reading it (about 9 runs in 10 here), so a trailer that is
    %% missing proves nothing. One that is there must be status 0.
    case trailer(<<"grpc-status">>, Trace) of
        undefined -> ok;
        Status0   -> ?assertEqual(<<"0">>, Status0)
    end.

unimplemented(Curl, Port) ->
    Request = <<0, 0, 0, 0, 4, 16#0a, 16#02, 16#6f, 16#6b>>,
    #{exit := 0, status := Status, trace := Trace, body := Body} =
        call(Curl, Port, ?NOSUCH, Request),
    ?assertEqual(200, Status),
    ?assertEqual(<<"12">>, trailer(<<"grpc-status">>, Trace)),
    ?assertEqual(<<>>, Body).

%% session_id "err5" makes the stub answer NOT_FOUND (5) with the message "nope".
error_status(Curl, Port) ->
    Msg = <<16#0a, 16#04, "err5">>,
    #{exit := 0, status := Status, trace := Trace} =
        call(Curl, Port, ?HEARTBEAT, <<0, 0, 0, 0, (byte_size(Msg)), Msg/binary>>),
    ?assertEqual(200, Status),
    ?assertEqual(<<"5">>, trailer(<<"grpc-status">>, Trace)),
    ?assertEqual(<<"nope">>, trailer(<<"grpc-message">>, Trace)).

%%--------------------------------------------------------------------
%% curl
%%--------------------------------------------------------------------

%% {ok, CurlPath} when curl is there and lists HTTP2, else {error, Why}.
curl_h2() ->
    case os:type() of
        {unix, _} -> curl_h2_unix(os:find_executable("curl"));
        _ -> {error, "needs a POSIX shell"}   %% call/4 builds a shell line for os:cmd/1
    end.

curl_h2_unix(Found) ->
    case Found of
        false ->
            {error, "curl is not installed"};
        Curl ->
            Version = os:cmd(Curl ++ " --version"),
            case re:run(Version, "HTTP2", [{capture, none}]) of
                match   -> {ok, Curl};
                nomatch -> {error, "curl has no HTTP/2 support"}
            end
    end.

%% POST Body (a gRPC message, framed by the caller) to Path with HTTP/2 prior
%% knowledge. Returns the exit code, the status and headers of the response head
%% (curl's header dump), curl's trace (which, unlike the dump of this curl, shows
%% the trailers: read with trailer/2) and the body.
call(Curl, Port, Path, Body) ->
    Dir = tmp_dir(),
    try
        Req = filename:join(Dir, "req.bin"),
        Head = filename:join(Dir, "head.txt"),
        Out = filename:join(Dir, "body.bin"),
        Trace = filename:join(Dir, "trace.txt"),
        ok = file:write_file(Req, Body),
        Cmd = lists:flatten(
                io_lib:format("~s --http2-prior-knowledge -sS --max-time 10 "
                              "-D ~s -o ~s --trace-ascii ~s -H 'content-type: application/grpc' -H 'te: trailers' "
                              "--data-binary @~s http://127.0.0.1:~b~s >/dev/null 2>&1; echo $?",
                              [Curl, Head, Out, Trace, Req, Port, Path])),
        Exit = list_to_integer(string:trim(os:cmd(Cmd))),
        {ok, HeadText} = file:read_file(Head),
        {ok, RespBody} = file:read_file(Out),
        {ok, TraceText} = file:read_file(Trace),
        {Status, Headers} = parse_head(HeadText),
        #{exit => Exit, status => Status, headers => Headers, trace => TraceText,
          body => RespBody}
    after
        _ = file:del_dir_r(Dir)
    end.

tmp_dir() ->
    Base = case os:getenv("TMPDIR") of
               false -> "/tmp";
               ""    -> "/tmp";
               D     -> D
           end,
    Dir = filename:join(Base, "yuzu_test_gw_indep_h2_" ++ os:getpid() ++ "_"
                              ++ integer_to_list(erlang:unique_integer([positive]))),
    ok = filelib:ensure_path(Dir),
    Dir.

%% curl -D writes the response head as CRLF-ended lines. (This curl does not
%% write the trailers into it.)
parse_head(Text) ->
    [Block | _] = binary:split(Text, <<"\r\n\r\n">>),
    [StatusLine | Lines] = binary:split(Block, <<"\r\n">>, [global]),
    Status = case re:run(StatusLine, "^HTTP/\\S+ (\\d+)", [{capture, all_but_first, binary}]) of
                 {match, [S]} -> binary_to_integer(S);
                 nomatch      -> undefined
             end,
    {Status, [header_line(L) || L <- Lines, L =/= <<>>]}.

%% A response header or trailer from curl's trace (`<= Recv header' lines): the
%% request carries none of these names, so the first match is the server's.
trailer(Name, Trace) ->
    case re:run(Trace, ["^[0-9a-f]{4}: ", Name, ": ([^\r\n]*)"],
                [multiline, caseless, {capture, all_but_first, binary}]) of
        {match, [V]} -> string:trim(V);
        nomatch      -> undefined
    end.

header_line(Line) ->
    [K, V] = binary:split(Line, <<":">>),
    {string:lowercase(K), string:trim(V)}.

header(Key, Headers) ->
    case lists:keyfind(Key, 1, Headers) of
        {Key, V} -> V;
        false    -> undefined
    end.
