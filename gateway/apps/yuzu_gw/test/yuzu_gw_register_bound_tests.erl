%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the registration bound at the gateway edge and the
%%% classification of server statuses by the circuit breaker (#4632).
%%%
%%% Found by review: the gateway forwards an agent's RegisterRequest as it is
%%% and applied no bound to the agent id. The server answers INVALID_ARGUMENT
%%% for an empty id or one over 256 bytes, the gateway counted that answer as a
%%% failure of the upstream, and a handful of such Registers (the edge needs no
%%% client certificate on the one-way TLS listener) opened the breaker for the
%%% whole fleet. Two closures are pinned here:
%%%   - the edge refuses an empty, missing, non-binary or over-long agent id
%%%     itself, before any reservation and before any upstream call;
%%%   - the breaker treats the server statuses that say "this request was wrong"
%%%     as answers that neither fail nor recover it, and still counts every
%%%     status, transport error and exception that says the upstream is
%%%     unhealthy (the over-correction guards).
%%%
%%% The mock of grpcbox_client:unary/5 runs the REAL request encoder the way
%%% grpcbox does, then answers like the server: INVALID_ARGUMENT for a bad
%%% agent id, RESOURCE_EXHAUSTED for a message over the 4 MiB receive limit of
%%% a stock gRPC server, OK otherwise. The upstream and the registry are real.
%%% Waits: none, every call here is synchronous.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_register_bound_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-define(CTX_KEY, yuzu_register_bound_conn_key).
-define(WIRE_KEY, {?MODULE, wire}).
-define(MAX_AGENT_ID, 256).
%% The receive limit of a stock gRPC server (no override exists on the server).
-define(SERVER_MAX_MESSAGE, 4194304).
-define(ENV_KEYS, [circuit_breaker_failure_threshold,
                   circuit_breaker_reset_timeout_ms,
                   circuit_breaker_max_reset_timeout_ms]).

%%%===================================================================
%%% Fixture: a fresh real upstream per test, the breaker timers far
%%% beyond a test. Run with the test threshold (3) and the default (5).
%%%===================================================================

bound_test_() ->
    [{foreach,
      fun() -> setup(Threshold) end,
      fun cleanup/1,
      [
       t("an agent id the server refuses never reaches the upstream or the breaker",
         fun bad_agent_ids_are_refused_at_the_edge/0),
       t("an agent id of exactly 256 bytes is accepted",
         fun boundary_agent_id_is_accepted/0),
       t("the refusal names no agent id and is the status the server would answer",
         fun refusal_is_invalid_argument_without_the_id/0),
       t("statuses that mean the request was wrong leave the breaker alone",
         fun caller_fault_statuses_leave_the_breaker_alone/0),
       t("statuses that mean the upstream is unhealthy open the breaker",
         fun unhealthy_statuses_open_the_breaker/0),
       t("an HTTP-level error, a timeout and a refused connection each count once",
         fun transport_failures_count_by_reason/0),
       t("a request over the server receive limit never feeds the breaker",
         fun oversize_request_never_feeds_the_breaker/0)
      ]} || Threshold <- [3, 5]].

t(Name, Fun) ->
    {timeout, 30, {Name, Fun}}.

setup(Threshold) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(grpcbox_client),
    catch meck:unload(yuzu_gw_conn),
    stop_upstream(),
    Prev = [{Key, application:get_env(yuzu_gw, Key)} || Key <- ?ENV_KEYS],
    application:set_env(yuzu_gw, circuit_breaker_failure_threshold, Threshold),
    application:set_env(yuzu_gw, circuit_breaker_reset_timeout_ms, 600000),
    application:set_env(yuzu_gw, circuit_breaker_max_reset_timeout_ms, 600000),
    Wire = atomics:new(1, [{signed, false}]),
    persistent_term:put(?WIRE_KEY, Wire),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:new(yuzu_gw_conn, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_conn, key_from_ctx,
                     fun(Ctx) -> ctx:get(Ctx, ?CTX_KEY, undefined) end),
    mock_server(),
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    unlink(Pid),
    #{threshold => Threshold, prev_env => Prev}.

cleanup(#{prev_env := Prev}) ->
    stop_upstream(),
    catch meck:unload([grpcbox_client, yuzu_gw_conn]),
    lists:foreach(fun({Key, {ok, V}}) -> application:set_env(yuzu_gw, Key, V);
                     ({Key, undefined}) -> application:unset_env(yuzu_gw, Key)
                  end, Prev),
    persistent_term:erase(?WIRE_KEY),
    ok.

stop_upstream() ->
    case whereis(yuzu_gw_upstream) of
        undefined -> ok;
        Pid       -> catch unlink(Pid),
                     catch gen_server:stop(Pid, shutdown, 5000),
                     ok
    end.

%%%===================================================================
%%% The mock server
%%%===================================================================

%% Runs the real encoder in the calling process (as grpcbox_client:unary/5
%% does), then answers like the server. Every request that gets past the
%% encoder counts as one send on the wire.
mock_server() ->
    meck:expect(grpcbox_client, unary,
                fun(_Ctx, _Path, Req, #grpcbox_def{marshal_fun = Marshal}, _Opts) ->
                    Bin = Marshal(Req),
                    atomics:add(persistent_term:get(?WIRE_KEY), 1, 1),
                    server_answer(Req, byte_size(Bin))
                end).

%% A mock that answers every request with one fixed grpcbox_client:unary/5 result.
mock_answer(Answer) ->
    meck:expect(grpcbox_client, unary,
                fun(_Ctx, _Path, Req, #grpcbox_def{marshal_fun = Marshal}, _Opts) ->
                    _ = Marshal(Req),
                    atomics:add(persistent_term:get(?WIRE_KEY), 1, 1),
                    Answer
                end).

server_answer(#{info := #{agent_id := Id}}, _Size)
  when not is_binary(Id); byte_size(Id) =:= 0; byte_size(Id) > ?MAX_AGENT_ID ->
    {error, {<<"3">>, <<"agent_id length exceeds 256 chars or empty">>}, #{}};
server_answer(_Req, Size) when Size > ?SERVER_MAX_MESSAGE ->
    {error, {<<"8">>, <<"Received message larger than max">>}, #{}};
server_answer(_Req, _Size) ->
    {ok, #{session_id => unique(<<"srv-session">>), accepted => true}, #{}}.

wire_count() ->
    atomics:get(persistent_term:get(?WIRE_KEY), 1).

%%%===================================================================
%%% Helpers
%%%===================================================================

unique(Prefix) ->
    iolist_to_binary([Prefix, "-", integer_to_list(erlang:unique_integer([positive]))]).

%% The connection key is unique per call, so the per-connection session quota
%% never limits a test.
ctx() ->
    ctx:set(ctx:background(), ?CTX_KEY, unique(<<"conn">>)).

register_req(AgentId) ->
    #{info => #{agent_id => AgentId, hostname => <<"host">>}}.

good_register() ->
    yuzu_gw_agent_service:register(ctx(), register_req(unique(<<"good-agent">>))).

%% The breaker as the redacted status shows it (field names, not positions).
breaker() ->
    Status = yuzu_gw_upstream:format_status(#{state => sys:get_state(yuzu_gw_upstream)}),
    #{cb_state := State, cb_failures := Failures} = maps:get(state, Status),
    {State, Failures}.

restart_upstream() ->
    stop_upstream(),
    {ok, Pid} = yuzu_gw_upstream:start_link(),
    unlink(Pid),
    ok.

%%%===================================================================
%%% Edge bound
%%%===================================================================

bad_agent_ids_are_refused_at_the_edge() ->
    #{threshold := Threshold} = fixture_threshold(),
    Rounds = lists:seq(1, Threshold + 2),
    BadIds = [<<>>,
              binary:copy(<<"a">>, ?MAX_AGENT_ID + 1),
              binary:copy(<<"b">>, 300),
              binary:copy(<<"c">>, 100000),
              undefined,
              42],
    Replies =
        [yuzu_gw_agent_service:register(ctx(), register_req(Id)) || Id <- BadIds, _ <- Rounds]
        %% No info at all is an empty id too.
        ++ [yuzu_gw_agent_service:register(ctx(), #{}) || _ <- Rounds]
        %% The binary key spelling of the same fields is held to the same bound.
        ++ [yuzu_gw_agent_service:register(
              ctx(), #{<<"info">> => #{<<"agent_id">> => binary:copy(<<"d">>, 257)}})
            || _ <- Rounds],
    %% None of them went upstream, and the breaker never moved.
    ?assertEqual({closed, 0}, breaker()),
    ?assertEqual(0, wire_count()),
    ?assertEqual(0, meck:num_calls(grpcbox_client, unary, '_')),
    [?assertMatch({grpc_error, {?GRPC_STATUS_INVALID_ARGUMENT, _}}, Reply) || Reply <- Replies],
    %% A good Register still succeeds.
    ?assertMatch({ok, #{session_id := _}, _}, good_register()),
    ?assertEqual(1, wire_count()),
    ?assertEqual({closed, 0}, breaker()).

boundary_agent_id_is_accepted() ->
    Id = binary:copy(<<"z">>, ?MAX_AGENT_ID),
    ?assertMatch({ok, #{session_id := _}, _},
                 yuzu_gw_agent_service:register(ctx(), register_req(Id))),
    ?assertEqual({closed, 0}, breaker()).

refusal_is_invalid_argument_without_the_id() ->
    Id = binary:copy(<<"q">>, 400),
    {grpc_error, {Status, Message}} =
        yuzu_gw_agent_service:register(ctx(), register_req(Id)),
    ?assertEqual(?GRPC_STATUS_INVALID_ARGUMENT, Status),
    ?assert(is_binary(Message)),
    ?assertEqual(nomatch, binary:match(Message, <<"qqqq">>)),
    ?assertNotEqual(nomatch, binary:match(Message, <<"256">>)),
    {grpc_error, {Status, EmptyMessage}} =
        yuzu_gw_agent_service:register(ctx(), register_req(<<>>)),
    ?assertEqual(Message, EmptyMessage).

%%%===================================================================
%%% Status classification
%%%===================================================================

%% The statuses gRPC defines for a request that was wrong. The server returns
%% 3 (the agent id and enrollment field checks) and 9 (a superseded replay)
%% today; 5, 6 and 11 are the same class.
caller_fault_statuses_leave_the_breaker_alone() ->
    #{threshold := Threshold} = fixture_threshold(),
    Rounds = lists:seq(1, Threshold + 2),
    lists:foreach(
      fun(Status) ->
          mock_answer({error, {Status, <<"the request was wrong">>}, #{}}),
          [?assertEqual({error, {Status, <<"the request was wrong">>}},
                        yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)))
           || _ <- Rounds],
          [?assertEqual({error, {Status, <<"the request was wrong">>}},
                        yuzu_gw_upstream:proxy_inventory(#{session_id => <<"s">>}))
           || _ <- Rounds],
          ?assertEqual({closed, 0}, breaker())
      end, [<<"3">>, <<"5">>, <<"6">>, <<"9">>, <<"11">>]),
    %% The same answers do not clear failures that were real: one real failure,
    %% then answers of the neutral class, leaves the one failure counted.
    mock_answer({error, {<<"14">>, <<"unavailable">>}, #{}}),
    {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)),
    ?assertEqual({closed, 1}, breaker()),
    mock_answer({error, {<<"3">>, <<"the request was wrong">>}, #{}}),
    {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)),
    ?assertEqual({closed, 1}, breaker()).

%% Over-correction guard: a status that says the upstream is unhealthy or
%% unusable is still a failure, and threshold of them open the breaker.
unhealthy_statuses_open_the_breaker() ->
    #{threshold := Threshold} = fixture_threshold(),
    Statuses = [{<<"14">>, unavailable}, {<<"13">>, internal}, {<<"4">>, deadline_exceeded},
                {<<"2">>, unknown}, {<<"7">>, permission_denied},
                {<<"16">>, unauthenticated}, {<<"8">>, resource_exhausted},
                {<<"1">>, cancelled}, {<<"12">>, unimplemented}, {<<"10">>, aborted},
                {<<"15">>, data_loss}],
    lists:foreach(
      fun({Status, Name}) ->
          restart_upstream(),
          mock_answer({error, {Status, <<"upstream trouble">>}, #{}}),
          [begin
               ?assertMatch({error, {Status, _}},
                            yuzu_gw_upstream:proxy_register(register_req(<<"agent">>))),
               ?assertEqual({closed, N}, breaker(), Name)
           end || N <- lists:seq(1, Threshold - 1)],
          ?assertMatch({error, {Status, _}},
                       yuzu_gw_upstream:proxy_register(register_req(<<"agent">>))),
          ?assertEqual(open, yuzu_gw_upstream:circuit_state(), Name),
          %% The inventory call path counts the same way.
          restart_upstream(),
          [?assertMatch({error, {Status, _}},
                        yuzu_gw_upstream:proxy_inventory(#{session_id => <<"s">>}))
           || _ <- lists:seq(1, Threshold)],
          ?assertEqual(open, yuzu_gw_upstream:circuit_state(), Name)
      end, Statuses).

transport_failures_count_by_reason() ->
    lists:foreach(
      fun({Name, Answer}) ->
          restart_upstream(),
          mock_answer(Answer),
          {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)),
          ?assertEqual({closed, 1}, breaker(), Name),
          {error, _} = yuzu_gw_upstream:proxy_inventory(#{session_id => <<"s">>}),
          ?assertEqual({closed, 2}, breaker(), Name)
      end, [{http_error, {http_error, {503, <<"Service Unavailable">>}, #{}}},
            {timeout, {error, timeout}},
            {econnrefused, {error, econnrefused}},
            {closed, {error, closed}}]),
    %% An exception out of the client (a dead channel) counts too.
    restart_upstream(),
    meck:expect(grpcbox_client, unary,
                fun(_Ctx, _Path, _Req, _Def, _Opts) -> exit(channel_down) end),
    {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)),
    ?assertEqual({closed, 1}, breaker()).

%%%===================================================================
%%% Request size
%%%===================================================================

%% The gateway edge accepts a message of any size and the server refuses one
%% over 4 MiB with RESOURCE_EXHAUSTED before its handler runs. That is a fact
%% about the request, not about the upstream: the gateway refuses the request
%% itself, as a local encode failure, and RESOURCE_EXHAUSTED stays a failure.
oversize_request_never_feeds_the_breaker() ->
    #{threshold := Threshold} = fixture_threshold(),
    Huge = binary:copy(<<"h">>, ?SERVER_MAX_MESSAGE + 1),
    Req = #{info => #{agent_id => <<"big-agent">>, hostname => Huge}},
    [?assertMatch({error, {internal, _}}, yuzu_gw_upstream:proxy_register(Req))
     || _ <- lists:seq(1, Threshold + 2)],
    [?assertMatch({error, {internal, _}},
                  yuzu_gw_upstream:proxy_inventory(#{session_id => Huge}))
     || _ <- lists:seq(1, Threshold + 2)],
    [?assertMatch({grpc_error, {?GRPC_STATUS_INTERNAL, _}},
                  yuzu_gw_agent_service:register(ctx(), Req))
     || _ <- lists:seq(1, Threshold + 2)],
    ?assertEqual(0, wire_count()),
    ?assertEqual({closed, 0}, breaker()),
    ?assertMatch({ok, #{session_id := _}, _}, good_register()).

%%%===================================================================
%%% The fixture's threshold, read back from the running upstream
%%%===================================================================

fixture_threshold() ->
    {ok, Threshold} = application:get_env(yuzu_gw, circuit_breaker_failure_threshold),
    #{threshold => Threshold}.
