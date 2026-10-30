%%%-------------------------------------------------------------------
%%% @doc Which address a call is attributed to (yuzu_grpc_origin): the trust
%%% decision is by who connected, a claim from anyone else is ignored (never
%%% refused), and what is ignored is reported in the note. A trusted proxy that
%%% gave no usable address leaves the call with NO observation (`undefined'),
%%% never the proxy's own address.
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
     %% a sources list that is improper is a refusal, not a crash (the listener
     %% also guards this before calling, as defence in depth)
     ?_assertEqual({error, {bad_origin_sources, improper_list}},
                   yuzu_grpc_origin:validate(#{mode => proxy_protocol,
                                               sources => [{10, 0, 0, 5} | tail]})),
     ?_assertEqual({error, {bad_origin_sources, improper_list}},
                   yuzu_grpc_origin:validate(#{mode => forwarded_for,
                                               sources => [{10, 0, 0, 5}, {10, 0, 0, 6} | tail]})),
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
     %% an IPv4-mapped network is accepted from /97 (a /96 is every IPv4 address)
     ?_assertEqual(ok, yuzu_grpc_origin:validate(
                         #{mode => proxy_protocol,
                           sources => [{{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 0}, 104},
                                       {{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 5}, 128},
                                       {0, 0, 0, 0, 0, 16#ffff, 16#0a00, 5}]})),
     ?_assertMatch({error, {ipv4_mapped_source_prefix_must_exceed_96, [_]}},
                   yuzu_grpc_origin:validate(
                     #{mode => proxy_protocol,
                       sources => [{{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 0}, 64}]})),
     ?_assertMatch({error, {ipv4_mapped_source_prefix_must_exceed_96, [_]}},
                   yuzu_grpc_origin:validate(
                     #{mode => forwarded_for,
                       sources => [{{0, 0, 0, 0, 0, 16#ffff, 0, 0}, 96}]})),
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
    %% The balancer's own connection: no client behind it, so no observation.
    %% The TCP peer is the balancer and is not put in its place.
    Local = #{version => 2, command => local},
    ?assertEqual({undefined, no_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, Local, #{})),
    ?assertEqual({undefined, no_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, undefined, #{})).

proxy_protocol_without_an_ip_is_a_bad_claim_test() ->
    Unspec = #{version => 2, command => proxy, transport_family => undefined},
    Unix = #{version => 2, command => proxy, transport_family => unix,
             src_address => <<"/run/x.sock">>},
    ?assertEqual({undefined, bad_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, Unspec, #{})),
    ?assertEqual({undefined, bad_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, Unix, #{})),
    %% a source address that is a tuple but not an address
    Garbage = #{version => 2, command => proxy, src_address => {1, 2, 3}},
    ?assertEqual({undefined, bad_claim},
                 yuzu_grpc_origin:resolve(proxy_cfg(), ?LB, Garbage, #{})).

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
    ?assertEqual({undefined, bad_claim},
                 yuzu_grpc_origin:resolve(xff_cfg(2), ?LB, undefined, Value)).

xff_from_an_unlisted_peer_is_ignored_not_refused_test() ->
    ?assertEqual({{?OTHER, transport}, untrusted_source},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?OTHER, undefined, xff(<<"192.0.2.1">>))),
    %% and with no header at all: someone reached the listener without the proxy
    ?assertEqual({{?OTHER, transport}, untrusted_source},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?OTHER, undefined, #{})).

xff_absent_from_a_trusted_proxy_is_no_claim_test() ->
    ?assertEqual({undefined, no_claim},
                 yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, #{})).

xff_not_an_address_is_a_bad_claim_test_() ->
    Bad = [<<>>, <<"unknown">>, <<"_hidden">>, <<"203.0.113.9:4000">>, <<"203.0.113.256">>,
           <<"[2001:db8::1]:443">>, <<"203.0.113.9, ">>, <<",">>, <<"1.2.3">>,
           <<"203.0.113.9 203.0.113.10">>, <<"203.0.113.9;evil">>],
    [?_assertEqual({undefined, bad_claim},
                   yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(V)))
     || V <- Bad] ++
    %% leading zeros, a port, brackets, a zone-less short form: not a bare address
    [?_assertEqual({undefined, bad_claim},
                   yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(V)))
     || V <- [<<"010.0.0.1">>, <<"203.0.113.009">>, <<"[::1]">>, <<"::1:80:">>,
              <<"203.0.113.9\0">>, <<"0x7f.1.1.1">>, <<255, 254, "1.2.3.4">>]].

%% Only the selected entry is read. What a client put to the LEFT of it, however
%% long, however many entries, whatever bytes, cannot make the proxy's own entry
%% unusable: a client behind a trusted proxy would otherwise choose to have its
%% calls attributed to the proxy.
xff_leading_text_never_matters_test_() ->
    Join = fun(Parts) -> iolist_to_binary(lists:join(<<", ">>, Parts)) end,
    Resolve = fun(Cfg, Value) -> yuzu_grpc_origin:resolve(Cfg, ?LB, undefined, xff(Value)) end,
    Ok = {{?CLIENT, forwarded_for}, ok},
    [{"120 forged entries before the proxy's",
      ?_assertEqual(Ok, Resolve(xff_cfg(), Join(lists:duplicate(120, <<"1.1.1.1">>) ++ [<<"203.0.113.9">>])))},
     {"40 forged entries before the proxy's (past the old entry cap)",
      ?_assertEqual(Ok, Resolve(xff_cfg(), Join(lists:duplicate(40, <<"1.1.1.1">>) ++ [<<"203.0.113.9">>])))},
     {"a megabyte of text before the proxy's entry",
      ?_assertEqual(Ok, Resolve(xff_cfg(), <<(binary:copy(<<"A">>, 1048576))/binary, ", 203.0.113.9">>))},
     {"a megabyte of padding in the same entry as nothing else",
      ?_assertEqual(Ok, Resolve(xff_cfg(), <<(binary:copy(<<"1.1.1.1,">>, 131072))/binary, "203.0.113.9">>))},
     {"bytes that are not UTF-8 before the proxy's entry",
      ?_assertEqual(Ok, Resolve(xff_cfg(), <<255, 254, 253, ",", 192, 128, ", 203.0.113.9">>))},
     {"an entry that is not an address before the proxy's",
      ?_assertEqual(Ok, Resolve(xff_cfg(), <<"unknown, [::1]:80, 203.0.113.9">>))},
     {"empty entries before the proxy's",
      ?_assertEqual(Ok, Resolve(xff_cfg(), <<",,,, ,203.0.113.9">>))},
     {"trusted_hops 1 uses the second from the right and ignores 120 before it",
      ?_assertEqual({{?CLIENT, forwarded_for}, ok},
                    Resolve(xff_cfg(1), Join(lists:duplicate(120, <<"9.9.9.9">>)
                                              ++ [<<"203.0.113.9">>, <<"192.0.2.50">>])))},
     {"trusted_hops 2 uses the third from the right",
      ?_assertEqual({{?CLIENT, forwarded_for}, ok},
                    Resolve(xff_cfg(2), <<"7.7.7.7, 203.0.113.9, 10.1.1.1, 192.0.2.50">>))},
     {"padding in front of the selected entry is trimmed, padding to its left is not read",
      ?_assertEqual(Ok, Resolve(xff_cfg(), <<(binary:copy(<<" ">>, 5000))/binary, "\t 203.0.113.9 \t">>))}].

%% The selected entry is bounded: nothing longer than an address (45 bytes) can be
%% one, and the bound is on the entry, not on the header.
xff_selected_entry_is_bounded_test_() ->
    Resolve = fun(Value) -> yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(Value)) end,
    LongZeros = <<(binary:copy(<<"0">>, 70))/binary, "1">>,
    [?_assertEqual({undefined, bad_claim}, Resolve(binary:copy(<<"1">>, 65))),
     ?_assertEqual({undefined, bad_claim}, Resolve(<<"203.0.113.9, ", LongZeros/binary>>)),
     ?_assertEqual({undefined, bad_claim}, Resolve(<<"203.0.113.9, ", (binary:copy(<<"x">>, 100000))/binary>>)),
     %% the longest IPv6 text (an IPv4-embedded address) is well inside the bound
     ?_assertEqual({{{16#2001, 16#db8, 0, 0, 0, 0, 16#cb00, 16#7109}, forwarded_for}, ok},
                   Resolve(<<"::1, 2001:db8::203.0.113.9">>)),
     %% a header of nothing but commas has only empty entries
     ?_assertEqual({undefined, bad_claim}, Resolve(<<",,,,">>)),
     %% fewer entries than trusted_hops + 1, however long the single entry
     ?_assertEqual({undefined, bad_claim},
                   yuzu_grpc_origin:resolve(xff_cfg(3), ?LB, undefined,
                                            xff(<<"1.1.1.1, 2.2.2.2, 3.3.3.3">>)))].

%% The bound is 64 bytes on the trimmed entry. inet:parse_strict_address/1 also
%% accepts a zone id after the address ("fe80::1%eth0", the zone dropped), which
%% makes a valid entry of any length possible: up to the bound it is the address,
%% past it it is not read at all.
xff_entry_length_bound_is_exactly_64_bytes_test_() ->
    Resolve = fun(Value) -> yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined, xff(Value)) end,
    LinkLocal = {16#fe80, 0, 0, 0, 0, 0, 0, 1},
    Zoned = fun(Size) ->
                Prefix = <<"fe80::1%">>,
                <<Prefix/binary, (binary:copy(<<"z">>, Size - byte_size(Prefix)))/binary>>
            end,
    Longest = <<"ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255">>,
    [{"the longest address text there is (45 bytes) is accepted",
      [?_assertEqual(45, byte_size(Longest)),
       ?_assertEqual({{{16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff, 16#ffff},
                       forwarded_for}, ok}, Resolve(Longest))]},
     {"a valid zone-id entry from 41 to 64 bytes is the address",
      [?_assertEqual({{LinkLocal, forwarded_for}, ok}, Resolve(Zoned(N))) || N <- [41, 45, 63, 64]]},
     {"the same entry with the bound exceeded is a bad claim, not an address",
      [?_assertEqual({undefined, bad_claim}, Resolve(Zoned(N))) || N <- [65, 66, 200]]},
     {"the bound is on the trimmed entry: padding around a 64-byte entry does not count",
      ?_assertEqual({{LinkLocal, forwarded_for}, ok},
                    Resolve(<<"  \t", (Zoned(64))/binary, " \t ">>))},
     {"the bound is on the selected entry only: a long valid one to its left is not read",
      ?_assertEqual({{?CLIENT, forwarded_for}, ok},
                    Resolve(<<(Zoned(200))/binary, ", 203.0.113.9">>))},
     {"with trusted_hops the selected entry is the one bounded",
      [?_assertEqual({undefined, bad_claim},
                     yuzu_grpc_origin:resolve(xff_cfg(1), ?LB, undefined,
                                              xff(<<(Zoned(65))/binary, ", 203.0.113.9">>))),
       ?_assertEqual({{LinkLocal, forwarded_for}, ok},
                     yuzu_grpc_origin:resolve(xff_cfg(1), ?LB, undefined,
                                              xff(<<(Zoned(64))/binary, ", 203.0.113.9">>)))]}].

%% A header that is not text must not raise (the caller would answer INTERNAL and
%% log an error for every such request).
xff_never_raises_test_() ->
    Bytes = [<<255>>, <<255, 254, "1.2.3.4">>, <<"1.2.3.4", 255>>, <<192, 128>>, <<0>>,
             <<"\r\n">>, <<237, 160, 128>>, <<",", 255, ",">>, <<>>],
    [?_assertMatch({undefined, bad_claim},
                   yuzu_grpc_origin:resolve(xff_cfg(Hops), ?LB, undefined, xff(V)))
     || V <- Bytes, Hops <- [0, 1, 5]]
    ++ [?_assertMatch({{_, forwarded_for}, ok},
                      yuzu_grpc_origin:resolve(xff_cfg(), ?LB, undefined,
                                               xff(<<255, 254, ", 1.2.3.4">>)))].

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

%% A network written as IPv4-mapped IPv6 is the IPv4 network: its prefix counts
%% from the start of the 128 bits, so /104 is an IPv4 /8.
in_sources_ipv4_mapped_network_test() ->
    Net = {{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 0}, 104},
    ?assert(yuzu_grpc_origin:in_sources({10, 1, 2, 3}, [Net])),
    ?assert(yuzu_grpc_origin:in_sources({10, 255, 255, 255}, [Net])),
    ?assertNot(yuzu_grpc_origin:in_sources({11, 0, 0, 0}, [Net])),
    ?assertNot(yuzu_grpc_origin:in_sources({9, 255, 255, 255}, [Net])),
    %% and the peer may itself arrive mapped
    ?assert(yuzu_grpc_origin:in_sources({0, 0, 0, 0, 0, 16#ffff, 16#0a01, 16#0203}, [Net])),
    ?assertNot(yuzu_grpc_origin:in_sources({0, 0, 0, 0, 0, 16#ffff, 16#0b00, 0}, [Net])),
    %% a /128 mapped host is the IPv4 host, a /97 is the lower half of the space
    ?assert(yuzu_grpc_origin:in_sources({10, 0, 0, 5},
                                        [{{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 5}, 128}])),
    ?assertNot(yuzu_grpc_origin:in_sources({10, 0, 0, 6},
                                           [{{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 5}, 128}])),
    Half = {{0, 0, 0, 0, 0, 16#ffff, 0, 0}, 97},
    ?assert(yuzu_grpc_origin:in_sources({127, 255, 255, 255}, [Half])),
    ?assertNot(yuzu_grpc_origin:in_sources({128, 0, 0, 0}, [Half])),
    %% an unvalidated /96 or shorter never trusts anybody (it would be /0)
    ?assertNot(yuzu_grpc_origin:in_sources({10, 1, 2, 3},
                                           [{{0, 0, 0, 0, 0, 16#ffff, 0, 0}, 96}])),
    ?assertNot(yuzu_grpc_origin:in_sources({10, 1, 2, 3},
                                           [{{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 0}, 64}])).

%% The resolution through such a source: a mapped network trusts its IPv4 hosts.
mapped_network_source_trusts_its_ipv4_peers_test() ->
    Cfg = #{mode => forwarded_for,
            sources => [{{0, 0, 0, 0, 0, 16#ffff, 16#0a00, 0}, 104}]},
    ?assertEqual({{?CLIENT, forwarded_for}, ok},
                 yuzu_grpc_origin:resolve(Cfg, ?LB, undefined, xff(<<"203.0.113.9">>))),
    ?assertEqual({{?OTHER, transport}, untrusted_source},
                 yuzu_grpc_origin:resolve(Cfg, ?OTHER, undefined, xff(<<"203.0.113.9">>))).

%%--------------------------------------------------------------------
%% format/1
%%--------------------------------------------------------------------

format_is_a_bare_address_test() ->
    ?assertEqual(<<"203.0.113.9">>, yuzu_grpc_origin:format(?CLIENT)),
    ?assertEqual(<<"2001:db8::1">>,
                 yuzu_grpc_origin:format({16#2001, 16#db8, 0, 0, 0, 0, 0, 1})),
    ?assertEqual(<<"203.0.113.9">>,
                 yuzu_grpc_origin:format({0, 0, 0, 0, 0, 16#ffff, 16#cb00, 16#7109})).
