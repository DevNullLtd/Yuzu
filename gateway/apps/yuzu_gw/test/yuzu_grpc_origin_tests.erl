%%%-------------------------------------------------------------------
%%% @doc Which address a call is attributed to (yuzu_grpc_origin): the trust
%%% decision is by who connected, a claim from anyone else is ignored (never
%%% refused), and what is ignored is reported in the note.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_origin_tests).

-include_lib("eunit/include/eunit.hrl").

-define(LB, {10, 0, 0, 5}).
-define(CLIENT, {203, 0, 113, 9}).
-define(OTHER, {198, 51, 100, 7}).

proxy_cfg() -> #{mode => proxy_protocol, sources => [?LB]}.
xff_cfg() -> #{mode => forwarded_for, sources => [?LB]}.
xff_cfg(Hops) -> #{mode => forwarded_for, sources => [?LB], trusted_hops => Hops}.

proxy_info(Src) ->
    #{version => 2, command => proxy, transport_family => ipv4,
      transport_protocol => stream, src_address => Src, src_port => 40000,
      dest_address => {10, 0, 0, 9}, dest_port => 50051}.

xff(Value) -> #{<<"x-forwarded-for">> => Value}.

%%--------------------------------------------------------------------
%% validate/1
%%--------------------------------------------------------------------

validate_test_() ->
    [?_assertEqual(ok, yuzu_grpc_origin:validate(#{mode => transport})),
     ?_assertEqual(ok, yuzu_grpc_origin:validate(proxy_cfg())),
     ?_assertEqual(ok, yuzu_grpc_origin:validate(xff_cfg())),
     ?_assertEqual(ok, yuzu_grpc_origin:validate(xff_cfg(2))),
     ?_assertEqual(ok, yuzu_grpc_origin:validate(
                         #{mode => proxy_protocol,
                           sources => [{10, 0, 0, 0}, {{10, 1, 0, 0}, 16},
                                       {{16#2001, 16#db8, 0, 0, 0, 0, 0, 0}, 32}]})),
     %% a proxied listener that trusts nobody is a typo
     ?_assertEqual({error, origin_sources_required},
                   yuzu_grpc_origin:validate(#{mode => proxy_protocol, sources => []})),
     ?_assertEqual({error, origin_sources_required},
                   yuzu_grpc_origin:validate(#{mode => forwarded_for})),
     %% a /0 network would trust every address
     ?_assertMatch({error, {bad_origin_sources, _}},
                   yuzu_grpc_origin:validate(#{mode => proxy_protocol,
                                               sources => [{{0, 0, 0, 0}, 0}]})),
     ?_assertMatch({error, {bad_origin_sources, _}},
                   yuzu_grpc_origin:validate(#{mode => proxy_protocol,
                                               sources => [{{10, 0, 0, 0}, 33}]})),
     ?_assertMatch({error, {bad_origin_sources, _}},
                   yuzu_grpc_origin:validate(#{mode => proxy_protocol,
                                               sources => [{999, 0, 0, 1}]})),
     ?_assertMatch({error, {bad_origin_sources, _}},
                   yuzu_grpc_origin:validate(#{mode => proxy_protocol,
                                               sources => ["10.0.0.5"]})),
     ?_assertEqual({error, bad_trusted_hops},
                   yuzu_grpc_origin:validate(xff_cfg(-1))),
     ?_assertEqual({error, bad_trusted_hops},
                   yuzu_grpc_origin:validate(xff_cfg(64))),
     ?_assertMatch({error, {unknown_origin_options, [trusted_hops]}},
                   yuzu_grpc_origin:validate(#{mode => proxy_protocol, sources => [?LB],
                                               trusted_hops => 1})),
     ?_assertMatch({error, {origin_transport_takes_no_options, [sources]}},
                   yuzu_grpc_origin:validate(#{mode => transport, sources => [?LB]})),
     ?_assertEqual({error, {unknown_origin_mode, tcp}},
                   yuzu_grpc_origin:validate(#{mode => tcp})),
     ?_assertEqual({error, bad_origin}, yuzu_grpc_origin:validate(transport))].

%%--------------------------------------------------------------------
%% transport: a claim from a client is never read
%%--------------------------------------------------------------------

transport_ignores_every_claim_test() ->
    Headers = xff(<<"192.0.2.1">>),
    ?assertEqual({{?CLIENT, transport}, ok},
                 yuzu_grpc_origin:resolve(#{mode => transport}, ?CLIENT,
                                          proxy_info({192, 0, 2, 1}), Headers)).

%%--------------------------------------------------------------------
%% proxy_protocol
%%--------------------------------------------------------------------

proxy_protocol_trusted_source_is_believed_test() ->
    ?assertEqual({{?CLIENT, proxy_protocol}, ok},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, proxy_info(?CLIENT), #{})).

proxy_protocol_from_an_unlisted_peer_is_ignored_not_refused_test() ->
    %% A client that connects straight to the listener and sends its own PROXY
    %% header is attributed to what it really is.
    ?assertEqual({{?OTHER, transport}, untrusted_source},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?OTHER, proxy_info({192, 0, 2, 1}), #{})).

proxy_protocol_local_command_is_a_health_check_test() ->
    Local = #{version => 2, command => local},
    ?assertEqual({{?LB, transport}, no_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, Local, #{})),
    ?assertEqual({{?LB, transport}, no_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, undefined, #{})).

proxy_protocol_without_an_ip_is_a_bad_claim_test() ->
    Unspec = #{version => 2, command => proxy, transport_family => undefined},
    Unix = #{version => 2, command => proxy, transport_family => unix,
             src_address => <<"/run/x.sock">>},
    ?assertEqual({{?LB, transport}, bad_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, Unspec, #{})),
    ?assertEqual({{?LB, transport}, bad_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, Unix, #{})).

proxy_protocol_ipv6_and_mapped_addresses_test() ->
    V6 = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
    ?assertEqual({{V6, proxy_protocol}, ok},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, proxy_info(V6), #{})),
    %% a dual-stack listener reports an IPv4 peer as ::ffff:a.b.c.d
    Mapped = {0, 0, 0, 0, 0, 16#ffff, 16#0a00, 16#0005},
    ?assertEqual({{?CLIENT, proxy_protocol}, ok},
                 yuzu_grpc_origin:resolve(proxy_cfg(), Mapped,
                                          proxy_info({0, 0, 0, 0, 0, 16#ffff, 16#cb00, 16#7109}),
                                          #{})).

%%--------------------------------------------------------------------
%% forwarded_for
%%--------------------------------------------------------------------

xff_last_entry_is_the_proxys_test() ->
    %% The client wrote "198.51.100.7"; the router appended what it saw.
    ?assertEqual({{?CLIENT, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined,
                                          xff(<<"198.51.100.7, 203.0.113.9">>))),
    ?assertEqual({{?CLIENT, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(<<"203.0.113.9">>))).

xff_a_forged_leading_entry_is_never_used_test() ->
    ?assertEqual({{?CLIENT, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined,
                                          xff(<<"1.1.1.1, 2.2.2.2, 3.3.3.3, 203.0.113.9">>))).

xff_trusted_hops_skips_the_proxies_in_front_test() ->
    %% client, f5 (appended by the router: the address it saw), nothing else
    Value = xff(<<"203.0.113.9, 192.0.2.50">>),
    ?assertEqual({{{192, 0, 2, 50}, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(0), ?LB, undefined, Value)),
    ?assertEqual({{?CLIENT, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(1), ?LB, undefined, Value)),
    %% asking for more hops than the header has is a bad claim, not the first entry
    ?assertEqual({{?LB, transport}, bad_claim},
                 yuzu_grpc_origin:resolve(xff_cfg(2), ?LB, undefined, Value)).

xff_from_an_unlisted_peer_is_ignored_not_refused_test() ->
    ?assertEqual({{?OTHER, transport}, untrusted_source},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?OTHER, undefined, xff(<<"192.0.2.1">>))),
    %% and with no header at all: someone reached the listener without the proxy
    ?assertEqual({{?OTHER, transport}, untrusted_source},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?OTHER, undefined, #{})).

xff_absent_from_a_trusted_proxy_is_no_claim_test() ->
    ?assertEqual({{?LB, transport}, no_claim},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, #{})).

xff_not_an_address_is_a_bad_claim_test_() ->
    Bad = [<<>>, <<"unknown">>, <<"_hidden">>, <<"203.0.113.9:4000">>, <<"203.0.113.256">>,
           <<"[2001:db8::1]:443">>, <<"203.0.113.9, ">>, <<",">>, <<"1.2.3">>,
           <<"203.0.113.9 203.0.113.10">>, <<"203.0.113.9;evil">>],
    [?_assertEqual({{?LB, transport}, bad_claim},
                   yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(V)))
     || V <- Bad].

xff_header_bounds_test() ->
    TooLong = binary:copy(<<"1.1.1.1,">>, 200),
    ?assertEqual({{?LB, transport}, bad_claim},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(TooLong))),
    ManyEntries = iolist_to_binary(lists:join(<<", ">>, lists:duplicate(40, <<"1.1.1.1">>))),
    ?assertEqual({{?LB, transport}, bad_claim},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(ManyEntries))).

xff_ipv6_and_whitespace_test() ->
    V6 = {16#2001, 16#db8, 0, 0, 0, 0, 0, 1},
    ?assertEqual({{V6, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(<<"2001:db8::1">>))),
    ?assertEqual({{?CLIENT, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined,
                                          xff(<<"  198.51.100.7 ,\t203.0.113.9  ">>))),
    %% an IPv4-mapped claim is the IPv4 host
    ?assertEqual({{?CLIENT, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined,
                                          xff(<<"::ffff:203.0.113.9">>))).

%%--------------------------------------------------------------------
%% in_sources/2
%%--------------------------------------------------------------------

in_sources_exact_and_network_test() ->
    Sources = [{10, 0, 0, 5}, {{10, 1, 0, 0}, 16}, {{172, 16, 4, 128}, 25}],
    ?assert(yuzu_grpc_origin:in_sources({10, 0, 0, 5}, Sources)),
    ?assertNot(yuzu_grpc_origin:in_sources({10, 0, 0, 6}, Sources)),
    ?assert(yuzu_grpc_origin:in_sources({10, 1, 0, 0}, Sources)),
    ?assert(yuzu_grpc_origin:in_sources({10, 1, 255, 255}, Sources)),
    ?assertNot(yuzu_grpc_origin:in_sources({10, 2, 0, 0}, Sources)),
    %% /25 boundaries: .128-.255 in, .127 out
    ?assert(yuzu_grpc_origin:in_sources({172, 16, 4, 128}, Sources)),
    ?assert(yuzu_grpc_origin:in_sources({172, 16, 4, 255}, Sources)),
    ?assertNot(yuzu_grpc_origin:in_sources({172, 16, 4, 127}, Sources)).

in_sources_ipv6_and_families_test() ->
    Net = {{16#2001, 16#db8, 1, 0, 0, 0, 0, 0}, 48},
    ?assert(yuzu_grpc_origin:in_sources({16#2001, 16#db8, 1, 5, 0, 0, 0, 9}, [Net])),
    ?assertNot(yuzu_grpc_origin:in_sources({16#2001, 16#db8, 2, 0, 0, 0, 0, 1}, [Net])),
    %% an IPv4 address is never inside an IPv6 network, nor the reverse
    ?assertNot(yuzu_grpc_origin:in_sources({10, 0, 0, 5}, [Net])),
    ?assertNot(yuzu_grpc_origin:in_sources({16#2001, 16#db8, 1, 5, 0, 0, 0, 9},
                                           [{{10, 0, 0, 0}, 8}])),
    %% IPv4-mapped IPv6 on either side matches the IPv4 host
    ?assert(yuzu_grpc_origin:in_sources({0, 0, 0, 0, 0, 16#ffff, 16#0a00, 16#0005},
                                        [{10, 0, 0, 5}])),
    ?assert(yuzu_grpc_origin:in_sources({10, 0, 0, 5},
                                        [{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 16#0005}])),
    ?assertNot(yuzu_grpc_origin:in_sources({10, 0, 0, 5}, [])).

%%--------------------------------------------------------------------
%% format/1
%%--------------------------------------------------------------------

format_is_a_bare_address_test() ->
    ?assertEqual(<<"203.0.113.9">>, yuzu_grpc_origin:format(?CLIENT)),
    ?assertEqual(<<"2001:db8::1">>,
                 yuzu_grpc_origin:format({16#2001, 16#db8, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(<<"203.0.113.9">>,
                 yuzu_grpc_origin:format({0, 0, 0, 0, 0, 16#ffff, 16#cb00, 16#7109})).
