%%%-------------------------------------------------------------------
%%% @doc What yuzu_grpc_listener:validate/1 accepts and refuses, and the TLS
%%% options it derives. A refused entry never binds a port.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_listener_tests).

-include_lib("eunit/include/eunit.hrl").

-define(TLS, #{certfile => "gw.pem", keyfile => "gw.key", cacertfile => "ca.pem"}).

entry() ->
    entry(#{}).

entry(Extra) ->
    maps:merge(#{name => t, service_protos => [agent_pb],
                 services => #{'yuzu.agent.v1.AgentService' => yuzu_grpc_stub_svc},
                 listen => #{port => 0}}, Extra).

proxied() -> #{mode => proxy_protocol, sources => [{10, 0, 0, 5}]}.
forwarded() -> #{mode => forwarded_for, sources => [{10, 0, 0, 5}]}.

validate_origin_test_() ->
    [?_assertEqual(ok, yuzu_grpc_listener:validate(entry())),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(#{origin => #{mode => transport}}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(#{origin => proxied()}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(#{origin => forwarded()}))),
     %% a proxied listener that trusts nobody is refused, whatever the mode
     ?_assertEqual({error, origin_sources_required},
                   yuzu_grpc_listener:validate(entry(#{origin => #{mode => proxy_protocol,
                                                                   sources => []}}))),
     ?_assertEqual({error, origin_sources_required},
                   yuzu_grpc_listener:validate(entry(#{origin => #{mode => forwarded_for}}))),
     ?_assertEqual({error, {unknown_origin_mode, nonsense}},
                   yuzu_grpc_listener:validate(entry(#{origin => #{mode => nonsense}}))),
     %% the option the layer owns cannot be set through http2
     ?_assertMatch({error, {reserved_http2_options, [proxy_header]}},
                   yuzu_grpc_listener:validate(entry(#{http2 => #{proxy_header => true}})))].

%% An auth_fun authenticates the peer of the TLS connection. Behind a proxy
%% that terminates TLS that peer is the proxy, so the combination would read as
%% agent authentication and be nothing of the kind. PROXY protocol does not
%% terminate TLS, so an auth_fun there is still about the client.
validate_origin_with_auth_fun_test_() ->
    Auth = #{tls => ?TLS, auth_fun => fun(_) -> true end},
    [?_assertEqual({error, auth_fun_behind_terminating_proxy},
                   yuzu_grpc_listener:validate(entry(Auth#{origin => forwarded()}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(Auth#{origin => proxied()}))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(entry(Auth))),
     ?_assertEqual(ok, yuzu_grpc_listener:validate(
                         entry(#{tls => ?TLS, origin => forwarded()})))].

%% The ways a listener can ask for client certificates; the agent edge can move
%% from none to optional to required by configuration alone.
ssl_opts_client_certificates_test_() ->
    Verify = fun(Tls) ->
                 Opts = yuzu_grpc_listener:ssl_opts(maps:merge(?TLS, Tls)),
                 {proplists:get_value(verify, Opts), proplists:get_value(fail_if_no_peer_cert, Opts)}
             end,
    [%% mutual TLS is the default for a tls map
     ?_assertEqual({verify_peer, true}, Verify(#{})),
     %% one-way TLS: no certificate requested (today's agent edge)
     ?_assertEqual({verify_none, false}, Verify(#{verify => verify_none})),
     ?_assertEqual({verify_none, false},
                   Verify(#{verify => verify_none, fail_if_no_peer_cert => false})),
     %% requested, not required: an enrolled agent presents its certificate, an
     %% unenrolled one still bootstraps
     ?_assertEqual({verify_peer, false}, Verify(#{fail_if_no_peer_cert => false}))].
