%%%-------------------------------------------------------------------
%%% @doc EUnit tests for the registration bound at the gateway edge and the
%%% classification of server statuses by the circuit breaker (#4632).
%%%
%%% The gateway refuses an agent id outside 1 to 256 bytes at its own edge with
%%% INVALID_ARGUMENT and makes no upstream call, and the circuit breaker treats a
%%% status that says the request itself was wrong as an answer, not as an
%%% upstream failure. Two closures are pinned here:
%%%   - the edge refuses an empty, missing, non-binary or over-long agent id
%%%     itself, before any reservation and before any upstream call;
%%%   - the breaker treats the server statuses that say "this request was wrong"
%%%     as answers that neither fail nor recover it on a live call, and still
%%%     counts every status, transport error and exception that says the
%%%     upstream is unhealthy (the over-correction guards). The one exception is
%%%     a registration replay answered FAILED_PRECONDITION (9), the server's
%%%     authoritative "session superseded": it counts as a breaker success via
%%%     record_result_no_replay({ok, superseded}); a replay answered with the
%%%     other four request-fault statuses stays neutral.
%%%
%%% The mock of grpcbox_client:unary/5 runs the REAL request encoder the way
%%% grpcbox does, then answers like the server: INVALID_ARGUMENT for a bad
%%% agent id, RESOURCE_EXHAUSTED for a message over the 4 MiB receive limit of
%%% a stock gRPC server, OK otherwise. The upstream and the registry are real.
%%% Waits: none beyond the bounded receives in the concurrent burst test.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_register_bound_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("grpcbox/include/grpcbox.hrl").

-export([handle_event/4]).  %% telemetry handler callback
-export([handle_refused/4]).  %% telemetry handler callback (edge refusals)

-define(CTX_KEY, yuzu_register_bound_conn_key).
-define(TELEMETRY_HANDLER, yuzu_register_bound_tests_events).
-define(REFUSED_HANDLER, yuzu_register_bound_tests_refused).
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
       t("statuses that mean the request was wrong leave the breaker alone",
         fun caller_fault_statuses_leave_the_breaker_alone/0),
       t("statuses that mean the upstream is unhealthy open the breaker",
         fun unhealthy_statuses_open_the_breaker/0),
       t("a request over the server receive limit never feeds the breaker",
         fun oversize_request_never_feeds_the_breaker/0)
      ]} || Threshold <- [3, 5]].

%%% Round 4 (#4632): the edge bound counts what it refuses, is measured in bytes and
%%% agrees with the server's constant, and the request bound is exact. One
%%% threshold is enough here, none of these depends on the breaker's threshold
%%% (the refusal text, the transport failures and the error codes are here too:
%%% they read no threshold, so running them at 3 and 5 added no coverage).
edge_test_() ->
    {foreach,
     fun() -> setup(3) end,
     fun cleanup/1,
     [
      t("the refusal names no agent id and is the status the server would answer",
        fun refusal_is_invalid_argument_without_the_id/0),
      t("an HTTP-level error, a timeout and a refused connection each count once",
        fun transport_failures_count_by_reason/0),
      t("a local encode failure is counted under code encode, an exception out of the client under exception",
        fun local_encode_failure_has_its_own_error_code/0),
      t("an edge refusal is counted once, by reason, and a valid Register is not counted",
        fun edge_refusal_is_counted_once/0),
      t("an agent id of 128 two-byte characters (256 bytes) is accepted, 129 (258 bytes) is refused: bytes, not characters",
        fun two_byte_characters_are_measured_in_bytes/0),
      t("a request of exactly 4194304 bytes reaches the wire and one byte more is refused locally",
        fun request_bound_is_exact/0),
      t("the gateway's agent id bound equals the server's kMaxAgentIdLength",
        fun agent_id_bound_matches_the_server/0)
     ]}.

%%% The warnings a refused registration can provoke are limited (#4632): the
%%% first occurrence logs, the rest of the interval is counted, and the next line
%%% carries the count. Each kind is driven the way a caller would provoke it.
limit_test_() ->
    {foreach,
     fun() -> setup_limits(3) end,
     fun cleanup_limits/1,
     [
      t("a refused agent id logs once per interval, then the count rides the next line",
        fun refused_agent_id_warning_is_limited/0),
      t("a replaced peer address logs once per interval, then the count rides the next line",
        fun peer_address_warning_is_limited/0),
      t("a Register that cannot be encoded: both its lines are limited",
        fun local_encode_warnings_are_limited/0),
      t("a Register the server answers as a request fault: its lines are limited",
        fun request_fault_warnings_are_limited/0),
      t("a failure that says the upstream is unhealthy is not limited",
        fun unhealthy_status_warning_is_not_limited/0),
      t("a burst of concurrent refused Registers writes a small bounded number of lines",
        fun concurrent_burst_is_bounded/0)
     ]}.

t(Name, Fun) ->
    {timeout, 30, {Name, Fun}}.

setup_limits(Threshold) ->
    Ctx = setup(Threshold),
    yuzu_gw_safe_call:reset_limits(),
    Ctx.

cleanup_limits(Ctx) ->
    yuzu_gw_safe_call:reset_limits(),
    cleanup(Ctx).

setup(Threshold) ->
    {ok, _} = application:ensure_all_started(telemetry),
    yuzu_gw_test_registry:ensure(),
    catch meck:unload(grpcbox_client),
    catch meck:unload(yuzu_gw_conn),
    yuzu_gw_test_upstream:stop_upstream(),
    Prev = yuzu_gw_test_upstream:save_env(?ENV_KEYS),
    yuzu_gw_test_upstream:set_breaker_env(Threshold),
    Wire = atomics:new(1, [{signed, false}]),
    persistent_term:put(?WIRE_KEY, Wire),
    ok = meck:new(grpcbox_client, [non_strict, no_link]),
    ok = meck:new(yuzu_gw_conn, [non_strict, no_link]),
    ok = meck:expect(yuzu_gw_conn, key_from_ctx,
                     fun(Ctx) -> ctx:get(Ctx, ?CTX_KEY, undefined) end),
    mock_server(),
    yuzu_gw_test_upstream:start_upstream(),
    #{threshold => Threshold, prev_env => Prev}.

cleanup(#{prev_env := Prev}) ->
    yuzu_gw_test_upstream:stop_upstream(),
    catch meck:unload([grpcbox_client, yuzu_gw_conn]),
    yuzu_gw_test_upstream:restore_env(Prev),
    persistent_term:erase(?WIRE_KEY),
    ok.

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
    yuzu_gw_test_upstream:stop_upstream(),
    yuzu_gw_test_upstream:start_upstream(),
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
%%% Round 4: counter, characters, exact bounds, drift
%%%===================================================================

%% The event is emitted by the calling process (telemetry runs the handler in the
%% caller), so each message is already in the mailbox when register/2 returns.
edge_refusal_is_counted_once() ->
    catch telemetry:detach(?REFUSED_HANDLER),
    ok = telemetry:attach(?REFUSED_HANDLER, [yuzu, gw, register, refused],
                          fun ?MODULE:handle_refused/4, #{pid => self()}),
    try
        {grpc_error, _} = yuzu_gw_agent_service:register(
                            ctx(), register_req(binary:copy(<<"r">>, ?MAX_AGENT_ID + 1))),
        ?assertEqual([<<"agent_id_length">>], refused_reasons()),
        %% Each other shape the edge refuses is one count too.
        [begin
             {grpc_error, _} = yuzu_gw_agent_service:register(ctx(), Req),
             ?assertEqual([<<"agent_id_length">>], refused_reasons())
         end || Req <- [register_req(<<>>), register_req(undefined), register_req(42), #{}]],
        %% A valid Register, and one the server (not the edge) refuses, are not.
        ?assertMatch({ok, #{session_id := _}, _}, good_register()),
        mock_answer({error, {<<"3">>, <<"invalid enrollment request">>}, #{}}),
        {grpc_error, _} = yuzu_gw_agent_service:register(ctx(), register_req(<<"a,b">>)),
        ?assertEqual([], refused_reasons())
    after
        catch telemetry:detach(?REFUSED_HANDLER)
    end.

refused_reasons() ->
    receive {register_refused, Reason} -> [Reason | refused_reasons()]
    after 0 -> []
    end.

%% telemetry handler callback
handle_refused(_Event, #{count := 1}, #{reason := Reason}, #{pid := Pid}) ->
    Pid ! {register_refused, Reason},
    ok.

%% The server compares agent_id().size(), bytes. 128 x U+00E9 is 256 bytes
%% (accepted, and one more character is 258 bytes, refused before the wire).
two_byte_characters_are_measured_in_bytes() ->
    AtBound = binary:copy(<<"\x{E9}"/utf8>>, 128),
    ?assertEqual(?MAX_AGENT_ID, byte_size(AtBound)),
    ?assertEqual(128, string:length(AtBound)),
    ?assertMatch({ok, #{session_id := _}, _},
                 yuzu_gw_agent_service:register(ctx(), register_req(AtBound))),
    ?assertEqual(1, wire_count()),
    Over = binary:copy(<<"\x{E9}"/utf8>>, 129),
    ?assertEqual(?MAX_AGENT_ID + 2, byte_size(Over)),
    ?assertEqual(129, string:length(Over)),
    ?assertMatch({grpc_error, {?GRPC_STATUS_INVALID_ARGUMENT, _}},
                 yuzu_gw_agent_service:register(ctx(), register_req(Over))),
    ?assertEqual(1, wire_count()),
    ?assertEqual({closed, 0}, breaker()).

%% A Register whose encoded size is exactly Size bytes: the hostname is padded,
%% and the size is read back from the real encoder, never assumed.
register_of_size(Size) ->
    Make = fun(Pad) -> #{info => #{agent_id => <<"edge-agent">>,
                                   hostname => binary:copy(<<"p">>, Pad)}} end,
    Encoded = fun(Pad) -> byte_size(gateway_pb:encode_msg(Make(Pad), 'yuzu.agent.v1.RegisterRequest')) end,
    Pad0 = Size - 1000,
    Pad = Pad0 + (Size - Encoded(Pad0)),
    ?assertEqual(Size, Encoded(Pad)),
    Make(Pad).

request_bound_is_exact() ->
    Exact = register_of_size(?SERVER_MAX_MESSAGE),
    ?assertMatch({ok, #{session_id := _}}, yuzu_gw_upstream:proxy_register(Exact)),
    ?assertEqual(1, wire_count()),
    ?assertEqual({closed, 0}, breaker()),
    OneOver = register_of_size(?SERVER_MAX_MESSAGE + 1),
    ?assertMatch({error, {internal, _}}, yuzu_gw_upstream:proxy_register(OneOver)),
    ?assertEqual(1, wire_count()),
    ?assertEqual({closed, 0}, breaker()),
    %% 64 bytes under the bound is accepted too, so the bound is not a margin.
    Under = register_of_size(?SERVER_MAX_MESSAGE - 64),
    ?assertMatch({ok, #{session_id := _}}, yuzu_gw_upstream:proxy_register(Under)),
    ?assertEqual(2, wire_count()).

%% The server's constant lives in a C++ header; this reads it from the source
%% tree, found by walking up from this file to the directory that holds both
%% `gateway/' and `server/'. It skips (with a message) ONLY when no such directory
%% exists, as in a build from a gateway-only checkout. When the server tree is
%% there but the header is unreadable or the symbol is missing, the test FAILS:
%% a rename of kMaxAgentIdLength must not turn the drift check into a silent
%% skip. The test is behavioural, so a drift in either direction shows: an id of
%% the server's size is accepted and one byte more is refused.
agent_id_bound_matches_the_server() ->
    case server_max_agent_id_length() of
        {ok, ServerValue} ->
            ?assertEqual(?MAX_AGENT_ID, ServerValue),
            ?assertMatch({ok, #{session_id := _}, _},
                         yuzu_gw_agent_service:register(
                           ctx(), register_req(binary:copy(<<"s">>, ServerValue)))),
            ?assertMatch({grpc_error, {?GRPC_STATUS_INVALID_ARGUMENT, _}},
                         yuzu_gw_agent_service:register(
                           ctx(), register_req(binary:copy(<<"s">>, ServerValue + 1))));
        skip ->
            ?debugMsg("no server/ tree above the gateway checkout: drift check skipped"),
            ok;
        {error, Why} ->
            erlang:error({server_tree_found_but_drift_check_cannot_read_it, Why})
    end.

-define(SERVER_AUTH_HEADER, "server/core/include/yuzu/server/auth.hpp").

server_max_agent_id_length() ->
    Source = proplists:get_value(source, ?MODULE:module_info(compile), ?FILE),
    server_max_agent_id_length(filename:dirname(filename:absname(Source)), undefined).

%% {ok, Value} | skip (no repository root above Dir) | {error, Why} (the root is
%% there, the header or the symbol is not). StopAt bounds the upward walk (the
%% throwaway trees below pass their own root, so a TMPDIR inside a real checkout
%% cannot make the walk escape into it); the real check passes `undefined`.
server_max_agent_id_length(StartDir, StopAt) ->
    case find_repo_root(StartDir, StopAt) of
        error ->
            skip;
        {ok, Root} ->
            Header = filename:join(Root, ?SERVER_AUTH_HEADER),
            case file:read_file(Header) of
                {ok, Text} ->
                    case re:run(Text, "kMaxAgentIdLength\\s*=\\s*([0-9]+)",
                                [{capture, [1], binary}]) of
                        {match, [Digits]} -> {ok, binary_to_integer(Digits)};
                        nomatch           -> {error, {symbol_not_found, Header}}
                    end;
                {error, Reason} ->
                    {error, {header_unreadable, Header, Reason}}
            end
    end.

%% The nearest directory above (or at) Dir that has both a gateway/ and a server/
%% directory: the repository root.
find_repo_root(Dir, StopAt) ->
    case filelib:is_dir(filename:join(Dir, "gateway"))
         andalso filelib:is_dir(filename:join(Dir, "server")) of
        true  -> {ok, Dir};
        false when Dir =:= StopAt -> error;
        false -> case filename:dirname(Dir) of
                     Dir    -> error;
                     Parent -> find_repo_root(Parent, StopAt)
                 end
    end.

%% The three states of the drift check, on throwaway trees (no source tree needed):
%% a header with the symbol is read, a server tree whose header lacks the symbol
%% or is missing is an error (the test above then fails), and a tree with no
%% server/ directory is the only skip.
drift_check_states_test_() ->
    {foreach,
     fun() ->
         Root = filename:join(os:getenv("TMPDIR", "/tmp"),
                              "yuzu_test_drift_" ++ os:getpid() ++ "_"
                              ++ integer_to_list(erlang:unique_integer([positive]))),
         Deep = filename:join([Root, "gateway", "apps", "yuzu_gw", "test"]),
         ok = filelib:ensure_dir(filename:join(Deep, "x")),
         {Root, Deep}
     end,
     fun({Root, _Deep}) -> ok = file:del_dir_r(Root) end,
     [fun({Root, Deep}) ->
          {"header present: the value is read",
           fun() ->
               write_auth_header(Root, "constexpr std::size_t kMaxAgentIdLength = 256;"),
               ?assertEqual({ok, 256}, server_max_agent_id_length(Deep, Root))
           end}
      end,
      fun({Root, Deep}) ->
          {"server tree present, symbol renamed: an error, not a skip",
           fun() ->
               write_auth_header(Root, "constexpr std::size_t kMaxAgentIdBytes = 256;"),
               ?assertMatch({error, {symbol_not_found, _}},
                            server_max_agent_id_length(Deep, Root))
           end}
      end,
      fun({Root, Deep}) ->
          {"server tree present, header missing: an error, not a skip",
           fun() ->
               ok = filelib:ensure_dir(filename:join([Root, "server", "x"])),
               ?assertMatch({error, {header_unreadable, _, enoent}},
                            server_max_agent_id_length(Deep, Root))
           end}
      end,
      fun({Root, Deep}) ->
          {"no server tree above the gateway checkout: skip",
           fun() -> ?assertEqual(skip, server_max_agent_id_length(Deep, Root)) end}
      end]}.

write_auth_header(Root, Line) ->
    Path = filename:join(Root, ?SERVER_AUTH_HEADER),
    ok = filelib:ensure_dir(Path),
    ok = file:write_file(Path, [Line, "\n"]).

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

%% A request over 4 MiB can still arrive at the upstream module, and the server
%% would refuse it with RESOURCE_EXHAUSTED. That is a fact about the request,
%% not about the upstream: the gateway refuses the request itself, as a local
%% encode failure, and RESOURCE_EXHAUSTED stays a failure.
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
%%% The error code label
%%%===================================================================

%% rpc_errors_total{code} tells a systematic local encoder fault (the breaker
%% stays closed, so nothing else shows it) from an exception out of the client
%% or transport, which still opens the breaker. Each of the three local causes (a
%% field that is not UTF-8, an oversize request) is "encode"; a dead channel is
%% "exception"; a server status keeps its status code.
local_encode_failure_has_its_own_error_code() ->
    attach_events(),
    try
        BadUtf8 = #{info => #{agent_id => <<"enc-agent">>, hostname => <<255, 254>>}},
        {error, _} = yuzu_gw_upstream:proxy_register(BadUtf8),
        ?assertEqual([<<"encode">>], error_codes()),
        Huge = #{info => #{agent_id => <<"big">>,
                           hostname => binary:copy(<<"h">>, ?SERVER_MAX_MESSAGE + 1)}},
        {error, _} = yuzu_gw_upstream:proxy_register(Huge),
        ?assertEqual([<<"encode">>], error_codes()),
        meck:expect(grpcbox_client, unary,
                    fun(_Ctx, _Path, _Req, _Def, _Opts) -> exit(channel_down) end),
        {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)),
        ?assertEqual([<<"exception">>], error_codes()),
        mock_answer({error, {<<"14">>, <<"unavailable">>}, #{}}),
        {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)),
        ?assertEqual([<<"14">>], error_codes())
    after
        catch telemetry:detach(?TELEMETRY_HANDLER)
    end.

attach_events() ->
    catch telemetry:detach(?TELEMETRY_HANDLER),
    ok = telemetry:attach(?TELEMETRY_HANDLER, [yuzu, gw, upstream, rpc_error],
                          fun ?MODULE:handle_event/4, #{pid => self()}).

%% The codes seen since the last call. The event is emitted by the upstream
%% process before it answers the caller, so it is already in the mailbox when the
%% call returns.
error_codes() ->
    receive {rpc_error, Code} -> [Code | error_codes()]
    after 0 -> []
    end.

%% telemetry handler callback
handle_event(_Event, #{count := 1}, #{code := Code}, #{pid := Pid}) ->
    Pid ! {rpc_error, Code},
    ok.

%%%===================================================================
%%% The fixture's threshold, read back from the running upstream
%%%===================================================================

fixture_threshold() ->
    {ok, Threshold} = application:get_env(yuzu_gw, circuit_breaker_failure_threshold),
    #{threshold => Threshold}.

%%%===================================================================
%%% Limited warnings
%%%===================================================================

%% One provoking call for a kind, and the text its limited line starts with.
%% Pattern is matched against the lines a call writes; the call is repeated
%% N times while the kind is held quiet, so the interval cannot pass mid burst.
refused_agent_id_warning_is_limited() ->
    limited_kind(register_refused, <<"Register refused: the agent id is empty">>,
                 fun() ->
                     {grpc_error, _} = yuzu_gw_agent_service:register(
                                         ctx(), register_req(binary:copy(<<"r">>, 300)))
                 end).

peer_address_warning_is_limited() ->
    limited_kind(register_peer_addr, <<"the peer address was replaced or cut">>,
                 fun() ->
                     Ctx = ctx:with_value(ctx(), md_incoming_key,
                                          #{<<":authority">> => <<255, 254, 200>>}),
                     {ok, _, _} = yuzu_gw_agent_service:register(
                                    Ctx, register_req(unique(<<"peer-agent">>)))
                 end).

%% Two kinds fire for one Register that cannot be encoded: the client line and
%% the handler line. Each is limited by its own kind.
local_encode_warnings_are_limited() ->
    Provoke = fun() ->
                  Req = #{info => #{agent_id => unique(<<"enc-agent">>),
                                    hostname => <<255, 254>>}},
                  {grpc_error, _} = yuzu_gw_agent_service:register(ctx(), Req)
              end,
    limited_kind(rpc_raised, <<"Upstream RPC ProxyRegister raised">>, Provoke),
    yuzu_gw_safe_call:reset_limits(),
    limited_kind(register_failed, <<"Upstream Register failed">>, Provoke).

%% An agent id with a comma is inside the edge bound and is refused by the
%% server's enrollment field check with INVALID_ARGUMENT.
request_fault_warnings_are_limited() ->
    mock_answer({error, {<<"3">>, <<"invalid enrollment request">>}, #{}}),
    Provoke = fun() ->
                  {grpc_error, _} = yuzu_gw_agent_service:register(
                                      ctx(), register_req(<<"a,b">>))
              end,
    limited_kind(rpc_answered_error, <<"Upstream RPC ProxyRegister failed">>, Provoke),
    yuzu_gw_safe_call:reset_limits(),
    limited_kind(register_failed, <<"Upstream Register failed">>, Provoke),
    %% The breaker stayed closed through all of it.
    ?assertEqual({closed, 0}, breaker()).

%% The counterpart: a status that says the upstream is unhealthy is the line an
%% operator needs on every occurrence, so it is not limited. Two calls, two lines.
unhealthy_status_warning_is_not_limited() ->
    mock_answer({error, {<<"14">>, <<"unavailable">>}, #{}}),
    Lines = capture_logs(fun() ->
        {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>)),
        {error, _} = yuzu_gw_upstream:proxy_register(register_req(<<"agent">>))
    end),
    ?assertEqual(2, length(matching(Lines, <<"Upstream RPC ProxyRegister failed">>))).

concurrent_burst_is_bounded() ->
    N = 200,
    Parent = self(),
    Provoke = fun() ->
        {grpc_error, _} = yuzu_gw_agent_service:register(
                            ctx(), register_req(binary:copy(<<"x">>, 400)))
    end,
    %% One refusal logs the first line, then the kind is held quiet: the interval
    %% cannot pass mid burst, so the number of lines the burst writes does not
    %% depend on how long it takes.
    yuzu_gw_safe_call:reset_limits(),
    First = capture_logs(fun() -> Provoke(), yuzu_gw_safe_call:hold_limit(register_refused) end),
    ?assertMatch([_], matching(First, <<"Register refused">>)),
    Pids = [spawn_monitor(fun() ->
                Parent ! {burst_ready, self()},
                receive go -> ok end,
                Provoke()
            end) || _ <- lists:seq(1, N)],
    [receive {burst_ready, P} -> ok after 5000 -> error(burst_not_ready) end
     || {P, _} <- Pids],
    Lines = capture_logs(fun() ->
        [P ! go || {P, _} <- Pids],
        [receive {'DOWN', M, process, P, normal} -> ok
         after 5000 -> error({burst_caller_failed, P})
         end || {P, M} <- Pids]
    end),
    ?assertEqual([], matching(Lines, <<"Register refused">>)),
    %% Every one of the N concurrent refusals was counted, none lost: the next
    %% line reports exactly N.
    yuzu_gw_safe_call:expire_limit(register_refused),
    Next = capture_logs(Provoke),
    Expected = iolist_to_binary(io_lib:format("~b similar line(s) suppressed since the last", [N])),
    ?assertMatch([_ | _], [L || L <- matching(Next, <<"Register refused">>),
                                binary:match(L, Expected) =/= nomatch]),
    ?assertEqual({closed, 0}, breaker()).

%% The first call logs, the kind is then held quiet, Count - 1 more calls log
%% nothing, and after the interval passes the next call logs a line that says how
%% many were suppressed.
limited_kind(Kind, Pattern, Provoke) ->
    Count = 50,
    First = capture_logs(fun() -> Provoke(), yuzu_gw_safe_call:hold_limit(Kind) end),
    ?assertMatch([_ | _], matching(First, Pattern)),
    [Line | _] = matching(First, Pattern),
    ?assertEqual(nomatch, binary:match(Line, <<"suppressed">>)),
    Quiet = capture_logs(fun() -> [Provoke() || _ <- lists:seq(2, Count)] end),
    ?assertEqual([], matching(Quiet, Pattern)),
    yuzu_gw_safe_call:expire_limit(Kind),
    Next = capture_logs(fun() -> Provoke() end),
    Lines = matching(Next, Pattern),
    ?assertMatch([_ | _], Lines),
    Expected = iolist_to_binary(io_lib:format("~b similar line(s) suppressed since the last",
                                              [Count - 1])),
    ?assertMatch([_ | _], [L || L <- Lines, binary:match(L, Expected) =/= nomatch]).

matching(Lines, Pattern) ->
    [L || L <- Lines, binary:match(L, Pattern) =/= nomatch].

%%%===================================================================
%%% Log capture
%%%===================================================================

%% Run Fun and return the rendered text of every warning logged meanwhile
%% (every body waits for the processes that log, so nothing is pending).
capture_logs(Fun) ->
    yuzu_gw_test_logs:capture(warning, Fun).
