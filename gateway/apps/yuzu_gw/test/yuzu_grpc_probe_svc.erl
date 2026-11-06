%%%-------------------------------------------------------------------
%%% @doc A service whose handlers are controlled by the test that started
%%% them, for yuzu_grpc_stream_h_tests (which drives the stream handler's
%%% callbacks directly, with the test process standing in for the Cowboy
%%% connection process).
%%%
%%% Every handler announces itself to the test pid held in persistent_term
%%% `yuzu_grpc_probe_pid' with {probe_started, HandlerPid, Arg, Stream} (Arg is
%%% the request of a one-request call, the Ref of a streaming one), then
%%% forwards every message it receives to the test as {probe_got, HandlerPid, Msg}
%%% until it is sent `stop_probe', when it returns ok. A test therefore sees,
%%% in order, what the stream handler sent to its handler (the acks, the
%%% inbound {Ref, Map} messages) without sleeping or polling.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_probe_svc).

-export([heartbeat/2, execute_command/2, subscribe/2]).
-export([set_test_pid/1, clear_test_pid/0]).

-define(KEY, yuzu_grpc_probe_pid).

-spec set_test_pid(pid()) -> ok.
set_test_pid(Pid) ->
    persistent_term:put(?KEY, Pid).

-spec clear_test_pid() -> ok.
clear_test_pid() ->
    _ = persistent_term:erase(?KEY),
    ok.

heartbeat(Ctx, Request) ->
    run(Request, Ctx),
    {ok, #{acknowledged => true}}.

execute_command(Request, Stream) ->
    run(Request, Stream).

subscribe(Ref, Stream) ->
    run(Ref, Stream).

run(Arg, Handle) ->
    Test = persistent_term:get(?KEY),
    Test ! {probe_started, self(), Arg, Handle},
    forward(Test).

forward(Test) ->
    receive
        stop_probe -> ok;
        Msg ->
            Test ! {probe_got, self(), Msg},
            forward(Test)
    end.
