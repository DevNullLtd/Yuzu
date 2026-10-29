%%%-------------------------------------------------------------------
%%% @doc Real management-plane tests: the gateway's :50063 listener over its
%%% production posture, against a REAL gateway release with a REAL agent behind
%%% it (#5175).
%%%
%%% scripts/integration-test.sh --tls --gateway-ct starts the gateway with the
%%% management listener of deploy/docker/reference-gateway-sys.config: TLS with
%%% verify_peer and fail_if_no_peer_cert, `auth_fun =>
%%% fun yuzu_gw_authz:check_mgmt_peer/1', and `mgmt_peer_pins' naming the
%%% SERVER's default leaf (`{cert_file, ...}'). The real yuzu-server dials it
%%% for every command it forwards (the script drives those through the server's
%%% REST API). This suite is the other client of the same listener: it dials it
%%% as the server would, with the server's own leaf, and as the peers the pin
%%% must refuse.
%%%
%%% What the cases pin:
%%%   - the server identity (#6016): the gateway derives it from the install CA
%%%     (a single-certificate cacertfile) and the C++ server mints it on its own
%%%     leaf, so the real server leaf is admitted by IDENTITY, not by the pin
%%%     (`yuzu_gw_mgmt_auth_admitted_total{method="identity"}` moves, `pin` does
%%%     not): the two sides compute the same bytes. A leaf with a NEW key and the
%%%     same identity (a server key renewal) and a same-key re-issue are served
%%%     with no change on the gateway; a leaf carrying another install's
%%%     identity is refused.
%%%   - the pin is enforced on THIS hop: a valid leaf of the same CA that is not
%%%     the pinned one (the gateway's own) is refused UNAUTHENTICATED and counted
%%%     as `pin_mismatch'; an enrolled agent's leaf (clientAuth only) is refused
%%%     and counted as `missing_server_auth_eku'; a peer with no certificate does
%%%     not get a call through. The pinned leaf is served.
%%%   - SendCommand (server streaming) over ONE connection: a command to the
%%%     real agent returns the agent's SUCCESS and ends the stream OK; a burst of
%%%     them multiplexed over that one connection all complete (the symptom of
%%%     #5175 was a stream crash that reached the caller as a transport error
%%%     with no gRPC status, for every call).
%%%   - the early-end paths: a fan-out to an agent that is not connected ends the
%%%     stream with a FAILURE frame and status OK; a fan-out whose deadline
%%%     passes before the agent answers ends the stream OK without that answer;
%%%     a client that cancels its streams (RST_STREAM) while the agent is still
%%%     working leaves the gateway serving. The script then greps the gateway log
%%%     for crash reports.
%%%
%%% Configuration (environment). YUZU_REAL_MGMT_STRICT=1 (the script sets it)
%%% turns an unset variable into a failure; without it the suite skips.
%%%   YUZU_MGMT_HOST / YUZU_MGMT_PORT          the gateway management listener
%%%   YUZU_MGMT_CACERT                         the install CA
%%%   YUZU_MGMT_CERT / YUZU_MGMT_KEY           the PINNED leaf (the server's)
%%%   YUZU_MGMT_CA_KEY                         the install CA's key (to mint leaves)
%%%   YUZU_MGMT_UNPINNED_CERT / _KEY           a valid leaf of that CA, not pinned
%%%   YUZU_MGMT_AGENT_CERT / _KEY              an enrolled agent's leaf
%%%   YUZU_MGMT_AGENT_ID                       the connected agent to command
%%%   YUZU_GW_METRICS_URL                      the gateway's /metrics URL
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_real_mgmt_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-compile([export_all, nowarn_export_all]).

-define(LIST_AGENTS, <<"/yuzu.server.v1.ManagementService/ListAgents">>).
-define(SEND_COMMAND, "/yuzu.server.v1.ManagementService/SendCommand").
-define(BURST, 300).
%% Streams in flight at once on the one connection (the listener allows 1024).
-define(WINDOW, 50).

%%%===================================================================
%%% CT callbacks
%%%===================================================================

all() ->
    [pinned_server_leaf_is_served,
     server_leaf_is_admitted_by_identity,
     renewed_server_key_with_the_same_identity_is_served,
     reissued_server_leaf_over_the_same_key_is_served,
     leaf_with_another_installs_identity_is_refused,
     unpinned_leaf_is_refused,
     agent_leaf_is_refused,
     no_client_certificate_gets_no_call,
     send_command_round_trip,
     send_command_burst_on_one_connection,
     send_command_to_unknown_agent_ends_early,
     send_command_deadline_before_agent_answers,
     send_command_cancelled_streams,
     gateway_serves_after_abuse].

suite() ->
    [{timetrap, {minutes, 5}}].

init_per_suite(Config) ->
    case os:getenv("YUZU_MGMT_PORT") of
        false ->
            case strict() of
                true  -> ct:fail({missing_environment, "YUZU_MGMT_PORT"});
                false -> {skip, no_management_listener_configured}
            end;
        _ ->
            ok = ensure_started(ctx),
            ok = ensure_started(gun),
            ok = ensure_started(inets),
            ok = ensure_started(ssl),
            %% Every variable the cases need, checked once, loudly.
            [_ = req_env(V) || V <- ["YUZU_MGMT_CACERT", "YUZU_MGMT_CERT", "YUZU_MGMT_KEY",
                                     "YUZU_MGMT_CA_KEY",
                                     "YUZU_MGMT_UNPINNED_CERT", "YUZU_MGMT_UNPINNED_KEY",
                                     "YUZU_MGMT_AGENT_CERT", "YUZU_MGMT_AGENT_KEY",
                                     "YUZU_MGMT_AGENT_ID", "YUZU_GW_METRICS_URL"]],
            %% The real agent must be connected before any case commands it.
            Agent = agent_id(),
            ok = wait_until(fun() -> agent_listed(Agent) end, 60000),
            ct:pal("management listener ~s:~B serves; agent ~s is connected",
                   [mgmt_host(), mgmt_port(), Agent]),
            Config
    end.

end_per_suite(_Config) ->
    ok.

%%%===================================================================
%%% The pin on the management hop
%%%===================================================================

pinned_server_leaf_is_served(_Config) ->
    {ok, #{agents := Agents}} = list_agents(pinned()),
    ?assert(lists:any(fun(#{agent_id := A}) -> A =:= agent_id() end, Agents)).

%% The identity check runs before the pin in `identity_or_pin', so a real server
%% leaf that is admitted by IDENTITY proves the gateway's derivation (SHA-256 of
%% the CA certificate, upper-case hex) is byte-for-byte the URI the C++ server
%% minted. Were they to differ the call would still succeed, by the pin, and only
%% the `pin' counter would move.
server_leaf_is_admitted_by_identity(_Config) ->
    IdBefore = admitted("identity"),
    PinBefore = admitted("pin"),
    ?assertMatch({ok, #{agents := _}}, list_agents(pinned())),
    ok = wait_until(fun() -> admitted("identity") >= IdBefore + 1 end, 10000),
    ?assertEqual(PinBefore, admitted("pin")).

%% A server key renewal that keeps the identity: a NEW key, so the pin does not
%% know it, yet the gateway needs no change and no pin refresh (#6016).
renewed_server_key_with_the_same_identity_is_served(Config) ->
    Leaf = mint_leaf(Config, "renewed", server_identity(), new_key),
    {ok, Spki} = yuzu_gw_authz:spki_sha256(der_of(Leaf)),
    {ok, PinnedSpki} = yuzu_gw_authz:spki_sha256(der_of(pinned())),
    ?assertNotEqual(PinnedSpki, Spki),
    IdBefore = admitted("identity"),
    Rejected = rejected("pin_mismatch"),
    ?assertMatch({ok, #{agents := _}}, list_agents(Leaf)),
    ok = wait_until(fun() -> admitted("identity") >= IdBefore + 1 end, 10000),
    ?assertEqual(Rejected, rejected("pin_mismatch")).

%% What the server's in-place upgrade does (#6072): a new certificate, a new
%% serial, over the SAME key. Served, and the existing pin still matches it.
reissued_server_leaf_over_the_same_key_is_served(Config) ->
    Leaf = mint_leaf(Config, "reissued", server_identity(), same_key),
    ?assertNotEqual(yuzu_gw_authz:serial_number(der_of(pinned())),
                    yuzu_gw_authz:serial_number(der_of(Leaf))),
    ?assertEqual(yuzu_gw_authz:spki_sha256(der_of(pinned())),
                 yuzu_gw_authz:spki_sha256(der_of(Leaf))),
    ?assertMatch({ok, #{agents := _}}, list_agents(Leaf)).

%% A serverAuth leaf of this CA whose URI names another install (or the agent
%% family): not the identity, and not a pinned key, so refused.
leaf_with_another_installs_identity_is_refused(Config) ->
    Before = rejected("pin_mismatch"),
    Other = mint_leaf(Config, "foreign", "yuzu://" ++ lists:duplicate(64, $0) ++ "/server",
                      new_key),
    {error, {<<"16">>, _}} = list_agents(Other),
    Agent = mint_leaf(Config, "agenturi",
                      string:replace(server_identity(), "/server", "/agent/integration-agent-1"),
                      new_key),
    {error, {<<"16">>, _}} = list_agents(Agent),
    ok = wait_until(fun() -> rejected("pin_mismatch") >= Before + 2 end, 10000),
    ?assertMatch({ok, #{agents := _}}, list_agents(pinned())).

%% A valid leaf of the same CA that the gateway does not pin: the TLS handshake
%% passes (CA membership), the auth_fun refuses the stream.
unpinned_leaf_is_refused(_Config) ->
    Before = rejected("pin_mismatch"),
    {error, {<<"16">>, _}} = list_agents(unpinned()),
    ok = wait_until(fun() -> rejected("pin_mismatch") >= Before + 1 end, 10000),
    %% And the pinned leaf is still served afterwards.
    ?assertMatch({ok, #{agents := _}}, list_agents(pinned())).

%% An enrolled agent's leaf: CA-issued, clientAuth only, so it is not the pinned
%% key and it lacks serverAuth. Both defects are real; the EKU check runs first.
agent_leaf_is_refused(_Config) ->
    Before = rejected("missing_server_auth_eku"),
    {error, {<<"16">>, _}} = list_agents(agent_leaf()),
    ok = wait_until(fun() -> rejected("missing_server_auth_eku") >= Before + 1 end, 10000).

%% fail_if_no_peer_cert: a peer with no certificate gets no answer. (Under TLS
%% 1.3 the client can see the handshake complete before the server's alert
%% arrives, so the refusal may surface on the first read; it is never a reply.)
no_client_certificate_gets_no_call(_Config) ->
    Result = list_agents(no_cert()),
    ?assertMatch({error, _}, Result),
    ?assertNotMatch({error, {<<"16">>, _}}, Result),
    ?assertMatch({ok, #{agents := _}}, list_agents(pinned())).

%%%===================================================================
%%% SendCommand over the pinned connection
%%%===================================================================

send_command_round_trip(_Config) ->
    {Conn, _} = open_pinned(),
    try
        {200, Frames, <<"0">>} = send_command(Conn, command_req(<<"mgmt-rt-1">>, [agent_id()], 30)),
        ct:pal("round trip: ~p", [Frames]),
        ?assertMatch([_ | _], Frames),
        %% Every frame is the real agent's, for this command ...
        ?assertEqual([], [F || #{agent_id := A, response := #{command_id := C}} = F <- Frames,
                               A =/= agent_id() orelse C =/= <<"mgmt-rt-1">>]),
        %% ... one of them is its SUCCESS, and the output it returned is not empty.
        ?assertMatch([_ | _], [F || #{response := #{status := 'SUCCESS'}} = F <- Frames]),
        Out = iolist_to_binary([maps:get(output, R, <<>>) || #{response := R} <- Frames]),
        ?assertNotEqual(<<>>, Out)
    after
        gun:close(Conn)
    end.

send_command_burst_on_one_connection(_Config) ->
    {Conn, _} = open_pinned(),
    try
        T0 = erlang:monotonic_time(millisecond),
        Results = burst(Conn, ?BURST, fun(I) ->
            Id = iolist_to_binary(io_lib:format("mgmt-burst-~B", [I])),
            {Id, command_req(Id, [agent_id()], 60)}
        end),
        Ms = erlang:monotonic_time(millisecond) - T0,
        Bad = [R || {_Id, Res} = R <- Results, not completed_ok(R, Res)],
        ct:pal("burst: ~B SendCommand streams on one connection in ~B ms (~B failed)",
               [length(Results), Ms, length(Bad)]),
        ?assertEqual([], lists:sublist(Bad, 5)),
        ?assertEqual(?BURST, length(Results))
    after
        gun:close(Conn)
    end.

%% No such agent connected: the gateway answers with a FAILURE frame and ends
%% the stream with status OK, immediately (the early-end path, no agent involved).
send_command_to_unknown_agent_ends_early(_Config) ->
    {Conn, _} = open_pinned(),
    try
        T0 = erlang:monotonic_time(millisecond),
        {200, Frames, <<"0">>} =
            send_command(Conn, command_req(<<"mgmt-unknown-1">>, [<<"no-such-agent">>], 30)),
        Ms = erlang:monotonic_time(millisecond) - T0,
        ?assertMatch([#{agent_id := <<"no-such-agent">>,
                        response := #{status := 'FAILURE', command_id := <<"mgmt-unknown-1">>}}],
                     Frames),
        ?assert(Ms < 5000)
    after
        gun:close(Conn)
    end.

%% The agent holds the command for 4 s (delay_seconds) and the fan-out's deadline
%% is 1 s: the stream ends OK at the deadline without the agent's answer, and the
%% answer that arrives later has nowhere to go and must not hurt anything.
send_command_deadline_before_agent_answers(_Config) ->
    {Conn, _} = open_pinned(),
    try
        Req = (command_req(<<"mgmt-deadline-1">>, [agent_id()], 1))#{
                command => #{command_id => <<"mgmt-deadline-1">>, plugin => <<"os_info">>,
                             action => <<"os_name">>, delay_seconds => 4}},
        T0 = erlang:monotonic_time(millisecond),
        {200, Frames, <<"0">>} = send_command(Conn, Req),
        Ms = erlang:monotonic_time(millisecond) - T0,
        ct:pal("deadline: stream ended after ~B ms with ~p", [Ms, Frames]),
        ?assert(Ms >= 900),
        ?assert(Ms < 3500),
        ?assertEqual([], [F || #{response := #{status := 'SUCCESS'}} = F <- Frames]),
        %% Let the agent's late answer reach the gateway, then use the same connection.
        timer:sleep(5000),
        {200, Again, <<"0">>} =
            send_command(Conn, command_req(<<"mgmt-deadline-2">>, [agent_id()], 30)),
        ?assertMatch([_ | _], [F || #{response := #{status := 'SUCCESS'}} = F <- Again])
    after
        gun:close(Conn)
    end.

%% The client cancels streams (RST_STREAM) while the agent is still working on
%% them; the connection and the gateway must carry on.
send_command_cancelled_streams(_Config) ->
    {Conn, _} = open_pinned(),
    try
        Refs = [begin
                    Id = iolist_to_binary(io_lib:format("mgmt-cancel-~B", [I])),
                    Req = (command_req(Id, [agent_id()], 30))#{
                            command => #{command_id => Id, plugin => <<"os_info">>,
                                         action => <<"os_name">>, delay_seconds => 2}},
                    post_send_command(Conn, Req)
                end || I <- lists:seq(1, 100)],
        timer:sleep(200),
        [gun:cancel(Conn, Ref) || Ref <- Refs],
        %% The same connection still answers.
        {200, Frames, <<"0">>} =
            send_command(Conn, command_req(<<"mgmt-cancel-after">>, [agent_id()], 30)),
        ?assertMatch([_ | _], [F || #{response := #{status := 'SUCCESS'}} = F <- Frames]),
        %% The abandoned commands finish on the agent about 2 s later; let their
        %% answers arrive at fan-outs that no longer have a caller.
        timer:sleep(4000)
    after
        gun:close(Conn)
    end.

gateway_serves_after_abuse(_Config) ->
    ?assertMatch({ok, #{agents := _}}, list_agents(pinned())),
    {Conn, _} = open_pinned(),
    try
        {200, Frames, <<"0">>} =
            send_command(Conn, command_req(<<"mgmt-final">>, [agent_id()], 30)),
        ?assertMatch([_ | _], [F || #{response := #{status := 'SUCCESS'}} = F <- Frames])
    after
        gun:close(Conn)
    end.

%%%===================================================================
%%% Streams
%%%===================================================================

command_req(CommandId, AgentIds, TimeoutS) ->
    #{agent_ids => AgentIds,
      command => #{command_id => CommandId, plugin => <<"os_info">>, action => <<"os_name">>},
      timeout_seconds => TimeoutS}.

post_send_command(Conn, Req) ->
    Body = yuzu_grpc_frame:encode(
             management_pb:encode_msg(Req, 'yuzu.server.v1.SendCommandRequest')),
    gun:post(Conn, ?SEND_COMMAND,
             [{<<"content-type">>, <<"application/grpc">>}, {<<"te">>, <<"trailers">>}], Body).

%% One SendCommand to its end: {HttpStatus, Frames, GrpcStatus} or {error, Reason}.
send_command(Conn, Req) ->
    read_stream(Conn, post_send_command(Conn, Req)).

read_stream(Conn, Ref) ->
    case gun:await(Conn, Ref, 70000) of
        {response, fin, Status, Headers} ->
            {Status, [], grpc_status(Headers)};
        {response, nofin, Status, Headers} ->
            case read_body(Conn, Ref, <<>>, []) of
                {ok, Frames, Trailers} ->
                    {Status, Frames, grpc_status(Trailers ++ Headers)};
                {error, _} = Error ->
                    Error
            end;
        {error, Reason} ->
            {error, Reason};
        Other ->
            {error, {unexpected, Other}}
    end.

read_body(Conn, Ref, Buf, Acc) ->
    case gun:await(Conn, Ref, 70000) of
        {data, IsFin, Data} ->
            case frames(<<Buf/binary, Data/binary>>, Acc) of
                {ok, _Rest, Acc1} when IsFin =:= fin -> {ok, lists:reverse(Acc1), []};
                {ok, Rest, Acc1} -> read_body(Conn, Ref, Rest, Acc1);
                {error, _} = Error -> Error
            end;
        {trailers, Trailers} ->
            {ok, lists:reverse(Acc), Trailers};
        {error, Reason} ->
            {error, Reason};
        Other ->
            {error, {unexpected, Other}}
    end.

frames(Buf, Acc) ->
    case yuzu_grpc_frame:decode(Buf, 1 bsl 24) of
        {ok, Msg, Rest} ->
            frames(Rest, [management_pb:decode_msg(Msg, 'yuzu.server.v1.SendCommandResponse') | Acc]);
        {more, Rest} ->
            {ok, Rest, Acc};
        {error, Err} ->
            {error, {bad_frame, Err}}
    end.

grpc_status(Headers) ->
    proplists:get_value(<<"grpc-status">>, Headers, <<"missing">>).

%% N commands, at most ?WINDOW streams in flight at once on Conn.
burst(Conn, N, Make) ->
    burst(Conn, lists:seq(1, N), Make, []).

burst(_Conn, [], _Make, Acc) ->
    lists:reverse(Acc);
burst(Conn, Is, Make, Acc) ->
    {Now, Later} = lists:split(min(?WINDOW, length(Is)), Is),
    Started = [begin
                   {Id, Req} = Make(I),
                   {Id, post_send_command(Conn, Req)}
               end || I <- Now],
    Done = [{Id, read_stream(Conn, Ref)} || {Id, Ref} <- Started],
    burst(Conn, Later, Make, lists:reverse(Done, Acc)).

%% HTTP 200, grpc-status 0, and the agent's SUCCESS for THIS command.
completed_ok({Id, _}, {200, Frames, <<"0">>}) ->
    lists:any(fun(#{response := #{status := 'SUCCESS', command_id := C}}) -> C =:= Id;
                 (_) -> false
              end, Frames);
completed_ok(_, _) ->
    false.

%%%===================================================================
%%% Connections and ListAgents
%%%===================================================================

pinned()      -> {req_env("YUZU_MGMT_CERT"), req_env("YUZU_MGMT_KEY")}.
unpinned()    -> {req_env("YUZU_MGMT_UNPINNED_CERT"), req_env("YUZU_MGMT_UNPINNED_KEY")}.
agent_leaf()  -> {req_env("YUZU_MGMT_AGENT_CERT"), req_env("YUZU_MGMT_AGENT_KEY")}.
no_cert()     -> none.

tls_opts(none) ->
    base_tls();
tls_opts({Cert, Key}) ->
    [{certfile, Cert}, {keyfile, Key} | base_tls()].

base_tls() ->
    [{cacertfile, req_env("YUZU_MGMT_CACERT")}, {verify, verify_peer}, {depth, 2}].

open_pinned() ->
    open(pinned()).

open(Identity) ->
    {ok, Conn} = gun:open(mgmt_host(), mgmt_port(),
                          #{protocols => [http2], transport => tls, tls_opts => tls_opts(Identity),
                            retry => 0, connect_timeout => 10000, tls_handshake_timeout => 10000}),
    case gun:await_up(Conn, 15000) of
        {ok, http2} -> {Conn, Identity};
        Other       -> gun:close(Conn), ct:fail({management_connection_failed, Other})
    end.

%% ListAgents as the identity: {ok, Response} | {error, {GrpcStatus, Message}} |
%% {error, Reason} when no call completed.
list_agents(Identity) ->
    Result = try open(Identity)
             catch exit:{test_case_failed, _} -> {error, no_connection}
             end,
    case Result of
        {error, _} = E -> E;
        {Conn, _} ->
            try unary(Conn)
            after gun:close(Conn)
            end
    end.

unary(Conn) ->
    Body = yuzu_grpc_frame:encode(
             management_pb:encode_msg(#{limit => 1000}, 'yuzu.server.v1.ListAgentsRequest')),
    Ref = gun:post(Conn, binary_to_list(?LIST_AGENTS),
                   [{<<"content-type">>, <<"application/grpc">>}, {<<"te">>, <<"trailers">>}], Body),
    case gun:await(Conn, Ref, 10000) of
        {response, fin, 200, Headers} ->
            unary_status(grpc_status(Headers), Headers, <<>>);
        {response, nofin, 200, Headers} ->
            case read_unary_body(Conn, Ref, <<>>) of
                {ok, Data, Trailers} -> unary_status(grpc_status(Trailers ++ Headers),
                                                     Trailers ++ Headers, Data);
                {error, _} = Error   -> Error
            end;
        {error, Reason} ->
            {error, Reason};
        Other ->
            {error, {unexpected, Other}}
    end.

read_unary_body(Conn, Ref, Acc) ->
    case gun:await(Conn, Ref, 10000) of
        {data, fin, D}      -> {ok, <<Acc/binary, D/binary>>, []};
        {data, nofin, D}    -> read_unary_body(Conn, Ref, <<Acc/binary, D/binary>>);
        {trailers, T}       -> {ok, Acc, T};
        {error, Reason}     -> {error, Reason};
        Other               -> {error, {unexpected, Other}}
    end.

unary_status(<<"0">>, _Fields, Data) ->
    {ok, Msg, _} = yuzu_grpc_frame:decode(Data, 1 bsl 24),
    {ok, management_pb:decode_msg(Msg, 'yuzu.server.v1.ListAgentsResponse')};
unary_status(Status, Fields, _Data) ->
    {error, {Status, proplists:get_value(<<"grpc-message">>, Fields, <<>>)}}.

agent_listed(Agent) ->
    case list_agents(pinned()) of
        {ok, #{agents := Agents}} -> lists:any(fun(#{agent_id := A}) -> A =:= Agent end, Agents);
        _ -> false
    end.

%%%===================================================================
%%% Metrics and environment
%%%===================================================================

%% yuzu_gw_mgmt_auth_rejected_total{reason="Reason"} from the gateway's /metrics.
rejected(Reason) ->
    counter("yuzu_gw_mgmt_auth_rejected_total{reason=\"" ++ Reason ++ "\"}").

%% yuzu_gw_mgmt_auth_admitted_total{method="Method"} (identity | pin).
admitted(Method) ->
    counter("yuzu_gw_mgmt_auth_admitted_total{method=\"" ++ Method ++ "\"}").

counter(Prefix) ->
    {ok, {{_, 200, _}, _, Body}} =
        httpc:request(get, {req_env("YUZU_GW_METRICS_URL"), []}, [{timeout, 5000}], []),
    Lines = string:split(Body, "\n", all),
    case [string:trim(string:slice(L, length(Prefix))) || L <- Lines, lists:prefix(Prefix, L)] of
        [V | _] -> metric_number(V);
        []      -> 0
    end.

%% The server identity the REAL server leaf carries, read from its URI SANs (not
%% derived here), so the leaves minted below are compared with what the C++
%% server really emits.
server_identity() ->
    Uris = yuzu_gw_authz:server_uri_sans(der_of(pinned())),
    [Id] = [binary_to_list(U) || U <- Uris, binary:longest_common_suffix([U, <<"/server">>]) =:= 7],
    Id.

der_of({Cert, _Key}) ->
    {ok, Pem} = file:read_file(Cert),
    [{'Certificate', Der, not_encrypted} | _] = public_key:pem_decode(Pem),
    Der.

%% A serverAuth+clientAuth leaf signed by the install CA with the given URI SAN,
%% the way default_certs.cpp shapes the server's: over a new key, or over the
%% server's own key (a re-issue). Returns the {Cert, Key} files.
mint_leaf(Config, Name, Uri, KeyMode) ->
    Dir = proplists:get_value(priv_dir, Config),
    Key = case KeyMode of
              same_key -> req_env("YUZU_MGMT_KEY");
              new_key  -> filename:join(Dir, Name ++ ".key")
          end,
    Csr = filename:join(Dir, Name ++ ".csr"),
    Ext = filename:join(Dir, Name ++ ".ext"),
    Pem = filename:join(Dir, Name ++ ".pem"),
    ok = file:write_file(Ext, ["subjectAltName=DNS:localhost,IP:127.0.0.1,URI:", Uri, "\n",
                               "extendedKeyUsage=serverAuth,clientAuth\n",
                               "basicConstraints=CA:FALSE\n"]),
    Serial = integer_to_list(erlang:unique_integer([positive]) + 1000000),
    Cmds = [[case KeyMode of
                 new_key -> ["openssl ecparam -name prime256v1 -genkey -noout -out '", Key, "'"];
                 same_key -> "true"
             end],
            ["openssl req -new -key '", Key, "' -subj '/O=Yuzu/CN=Yuzu Default server' -out '", Csr, "'"],
            ["openssl x509 -req -in '", Csr, "' -CA '", req_env("YUZU_MGMT_CACERT"),
             "' -CAkey '", req_env("YUZU_MGMT_CA_KEY"), "' -set_serial ", Serial,
             " -days 1 -sha256 -extfile '", Ext, "' -out '", Pem, "'"]],
    [_ = os:cmd(lists:flatten(C) ++ " 2>&1") || C <- Cmds],
    true = filelib:is_regular(Pem),
    {Pem, Key}.

metric_number(V) ->
    try list_to_integer(V)
    catch error:badarg -> trunc(list_to_float(V))
    end.

mgmt_host() -> env("YUZU_MGMT_HOST", "127.0.0.1").
mgmt_port() -> list_to_integer(req_env("YUZU_MGMT_PORT")).
agent_id()  -> list_to_binary(req_env("YUZU_MGMT_AGENT_ID")).

strict() -> os:getenv("YUZU_REAL_MGMT_STRICT") =:= "1".

env(Name, Default) ->
    case os:getenv(Name) of
        false -> Default;
        Val   -> Val
    end.

req_env(Name) ->
    case os:getenv(Name) of
        false -> ct:fail({missing_environment, Name});
        Val   -> Val
    end.

ensure_started(App) ->
    case application:ensure_all_started(App) of
        {ok, _}                       -> ok;
        {error, {already_started, _}} -> ok;
        {error, Reason}               -> {error, Reason}
    end.

wait_until(Fun, Timeout) when Timeout =< 0 ->
    case Fun() of
        true  -> ok;
        false -> {error, timeout}
    end;
wait_until(Fun, Timeout) ->
    case Fun() of
        true  -> ok;
        false ->
            timer:sleep(200),
            wait_until(Fun, Timeout - 200)
    end.
