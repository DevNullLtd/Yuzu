%%%-------------------------------------------------------------------
%%% @doc A stub ManagementService.SendCommand for the management-listener edge
%%% tests (yuzu_gw_mgmt_edge_tests). CommandRequest.action picks the behaviour
%%% and CommandRequest.command_id carries its argument:
%%%
%%%   gate     announce itself as waiting, block until the test sends `release',
%%%            then send ONE response whose output is command_id bytes long (a
%%%            synchronized burst of large responses: every handler of the test
%%%            sends at the same moment)
%%%   sleep    block until the stream is torn down (an agent that never answers)
%%%   delay    sleep command_id milliseconds, then send one small response (an
%%%            agent that answers after a while)
%%%   delay_big  command_id is "Ms:Bytes": sleep Ms, then send one response
%%%            whose output is Bytes long
%%%
%%% State is an ETS table the test creates with init/1 and removes with
%%% stop/0; `waiting' events go to the pid given to init/1.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_edge_stub_svc).

-export([send_command/2, list_agents/2]).
-export([init/1, stop/0, waiting/0, notify_to/1]).

-define(TAB, yuzu_gw_edge_stub_state).

-spec init(pid()) -> ok.
init(Notify) ->
    _ = (catch ets:delete(?TAB)),
    ?TAB = ets:new(?TAB, [named_table, public, set]),
    true = ets:insert(?TAB, {notify, Notify}),
    ok.

-spec stop() -> ok.
stop() ->
    _ = (catch ets:delete(?TAB)),
    ok.

%% @doc Send the `waiting' events to Pid from now on (a test fun runs in another
%% process than the fixture that called init/1).
-spec notify_to(pid()) -> ok.
notify_to(Pid) ->
    true = ets:insert(?TAB, {notify, Pid}),
    ok.

%% @doc The pids of the `gate' handlers blocked right now.
-spec waiting() -> [pid()].
waiting() ->
    [P || {{waiting, P}} <- ets:tab2list(?TAB), is_process_alive(P)].

list_agents(_Ctx, _Request) ->
    {ok, #{agents => []}}.

send_command(Request, Stream) ->
    Command = maps:get(command, Request, #{}),
    run(maps:get(action, Command, <<>>), maps:get(command_id, Command, <<>>), Stream).

run(<<"gate">>, Bytes, Stream) ->
    ets:insert(?TAB, {{waiting, self()}}),
    notify({waiting, self()}),
    receive release -> ok end,
    Output = binary:copy(<<"r">>, binary_to_integer(Bytes)),
    case yuzu_grpc_stream:send(Stream, #{agent_id => <<"a">>,
                                         response => #{output => Output}}) of
        ok -> ok;
        {error, closed} -> ok
    end;
run(<<"sleep">>, _Arg, _Stream) ->
    receive never_sent -> ok end;
run(<<"delay">>, Ms, Stream) ->
    timer:sleep(binary_to_integer(Ms)),
    _ = yuzu_grpc_stream:send(Stream, #{agent_id => <<"a">>,
                                        response => #{output => <<"done">>}}),
    ok;
run(<<"delay_big">>, Arg, Stream) ->
    [Ms, Bytes] = binary:split(Arg, <<":">>),
    timer:sleep(binary_to_integer(Ms)),
    _ = yuzu_grpc_stream:send(Stream, #{agent_id => <<"a">>,
                                        response => #{output => binary:copy(<<"r">>,
                                                                            binary_to_integer(Bytes))}}),
    ok;
run(_Other, _Arg, _Stream) ->
    {grpc_error, {3, <<"unknown action">>}}.

notify(Msg) ->
    case ets:lookup(?TAB, notify) of
        [{notify, Pid}] -> Pid ! Msg, ok;
        [] -> ok
    end.
