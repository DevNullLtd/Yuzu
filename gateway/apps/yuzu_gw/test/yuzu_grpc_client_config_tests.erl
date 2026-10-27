%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_grpc_client_config: the parser of the upstream channel
%%% configuration (the `{yuzu_gw, [{upstream_client, ...}]}' application value).
%%%
%%% Pure, except for the cases that read the application env
%%% (`upstream_tcp_nodelay' through nodelay_default/0, `upstream_client'
%%% through from_env/0). Pinned case by case:
%%%   - both endpoint tuple shapes, host as string or binary, the port bounds;
%%%   - TCP_NODELAY: added unless the endpoint's own socket options mention
%%%     it (an operator's `{nodelay, false}' wins), other socket options and the
%%%     ssl options are kept as written, every channel is treated alike, the
%%%     switch off leaves the options alone, and the app env switch;
%%%   - pool_size, connect_timeout and max_receive_message_bytes: defaults, and
%%%     an out-of-range or non-integer value falls back to the default;
%%%   - from_env/0 reads `{yuzu_gw, upstream_client}' and nothing at the old
%%%     `{grpcbox, client}' key;
%%%   - the grpcbox-era options `balancer', `encoding' and `sync_start' are
%%%     accepted and ignored;
%%%   - a rejected value is reported as `{error, _}' and the error term never
%%%     contains the ssl options (which can name a private key file).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_grpc_client_config_tests).
-include_lib("eunit/include/eunit.hrl").

-define(CH, default_channel).
%% A path that must never appear in an error term.
-define(KEY_MARKER, "/marker/private/KEY-ffee11.pem").
-define(MARKER_SSL, [{keyfile, ?KEY_MARKER}, {certfile, "/marker/cert.pem"},
                     {cacertfile, "/marker/ca.pem"}, {verify, verify_peer}]).

%%%===================================================================
%%% Endpoints
%%%===================================================================

four_tuple_endpoint_test() ->
    {ok, #{endpoints := [E]}} = chan([{http, "gw", 50055, []}]),
    ?assertEqual(#{host => "gw", port => 50055, transport => tcp,
                   tls_opts => [], tcp_opts => [{nodelay, true}]}, E).

five_tuple_endpoint_test() ->
    Ssl = [{verify, verify_peer}, {cacertfile, "/x/ca.pem"}],
    {ok, #{endpoints := [E]}} =
        chan([{https, "gw", 50056, Ssl, #{socket_options => [{keepalive, true}]}}]),
    ?assertEqual(#{host => "gw", port => 50056, transport => tls,
                   tls_opts => Ssl, tcp_opts => [{keepalive, true}, {nodelay, true}]}, E).

five_tuple_with_empty_settings_equals_four_tuple_test() ->
    ?assertEqual(chan([{http, "gw", 50055, []}]), chan([{http, "gw", 50055, [], #{}}])).

settings_other_than_socket_options_are_ignored_test() ->
    ?assertEqual(chan([{http, "gw", 50055, []}]),
                 chan([{http, "gw", 50055, [], #{connect_timeout => 1, whatever => x}}])).

host_as_binary_becomes_a_string_test() ->
    {ok, #{endpoints := [#{host := H}]}} = chan([{http, <<"gw.example">>, 50055, []}]),
    ?assertEqual("gw.example", H).

host_as_string_is_kept_test() ->
    {ok, #{endpoints := [#{host := H}]}} = chan([{http, "gw.example", 50055, []}]),
    ?assertEqual("gw.example", H).

bad_hosts_are_rejected_test() ->
    [?assertMatch({error, {bad_host, _}}, chan([{http, Host, 50055, []}]))
     || Host <- ["", <<>>, gw, 42, {127, 0, 0, 1}, undefined]].

port_bounds_test() ->
    [?assertMatch({ok, _}, chan([{http, "gw", P, []}])) || P <- [1, 80, 65535]],
    [?assertMatch({error, {bad_endpoint, _}}, chan([{http, "gw", P, []}]))
     || P <- [0, -1, 65536, 100000, "80", <<"80">>, 80.0, undefined]].

scheme_selects_the_transport_test() ->
    {ok, #{endpoints := [#{transport := T1}, #{transport := T2}]}} =
        chan([{http, "a", 1, []}, {https, "b", 2, []}]),
    ?assertEqual({tcp, tls}, {T1, T2}).

unknown_scheme_and_shapes_are_rejected_test() ->
    Bad = [{grpc, "gw", 1, []}, {http, "gw", 1}, {http, "gw", 1, not_a_list},
           {http, "gw", 1, [], not_a_map}, {http, "gw", 1, [], #{}, extra},
           {unix, {local, "/s"}}, "gw:1", gw, 7, #{}],
    [?assertMatch({error, {bad_endpoint, _}}, chan([E])) || E <- Bad].

endpoint_order_is_kept_test() ->
    {ok, #{endpoints := Es}} = chan([{http, "a", 1, []}, {http, "b", 2, []}, {http, "c", 3, []}]),
    ?assertEqual(["a", "b", "c"], [H || #{host := H} <- Es]).

one_bad_endpoint_rejects_the_channel_test() ->
    ?assertMatch({error, {bad_endpoint, _}}, chan([{http, "a", 1, []}, {http, "b", 0, []}])).

empty_endpoints_are_rejected_test() ->
    ?assertMatch({error, {bad_channel, _}}, yuzu_grpc_client_config:channel({?CH, [], #{}}, true)).

%%%===================================================================
%%% TCP_NODELAY
%%%===================================================================

nodelay_added_when_endpoint_has_no_socket_options_test() ->
    ?assertEqual([{nodelay, true}], tcp_opts([{http, "gw", 1, []}], true)).

nodelay_not_added_when_switched_off_test() ->
    ?assertEqual([], tcp_opts([{http, "gw", 1, []}], false)),
    ?assertEqual([{keepalive, true}],
                 tcp_opts([{http, "gw", 1, [], #{socket_options => [{keepalive, true}]}}], false)).

operator_socket_options_are_kept_and_nodelay_appended_test() ->
    Opts = [{keepalive, true}, {sndbuf, 4096}],
    ?assertEqual(Opts ++ [{nodelay, true}],
                 tcp_opts([{http, "gw", 1, [], #{socket_options => Opts}}], true)).

operator_nodelay_entry_is_never_overridden_test() ->
    [begin
         ?assertEqual(Opts, tcp_opts([{http, "gw", 1, [], #{socket_options => Opts}}], true)),
         ?assertEqual(Opts, tcp_opts([{http, "gw", 1, [], #{socket_options => Opts}}], false))
     end || Opts <- [[{nodelay, false}], [{keepalive, true}, {nodelay, false}],
                     [{nodelay, true}], [nodelay]]].

every_endpoint_and_every_channel_is_decided_alone_test() ->
    {ok, [#{endpoints := Es1}, #{endpoints := Es2}]} =
        yuzu_grpc_client_config:channels(
          #{channels => [{?CH, [{http, "a", 1, []},
                                {http, "b", 2, [], #{socket_options => [{nodelay, false}]}}], #{}},
                         {other_channel, [{http, "c", 3, []}], #{}}]}),
    ?assertEqual([[{nodelay, true}], [{nodelay, false}]], [T || #{tcp_opts := T} <- Es1]),
    ?assertEqual([[{nodelay, true}]], [T || #{tcp_opts := T} <- Es2]).

tls_options_are_untouched_by_nodelay_test() ->
    Ssl = [{verify, verify_peer}, {cacertfile, "/x/ca.pem"}, {server_name_indication, "gw"}],
    {ok, #{endpoints := [E]}} = chan([{https, "gw", 1, Ssl}]),
    ?assertEqual(Ssl, maps:get(tls_opts, E)),
    ?assertEqual([{nodelay, true}], maps:get(tcp_opts, E)).

socket_options_not_a_list_are_rejected_test() ->
    [?assertMatch({error, {bad_socket_options, _}},
                  chan([{http, "gw", 1, [], #{socket_options => Bad}}]))
     || Bad <- [not_a_list, #{nodelay => true}, <<"nodelay">>, 5, {nodelay, true}]].

%% An improper list is not a proplist: reported, not a crash of the parser.
improper_socket_options_are_rejected_test() ->
    Improper = [{keepalive, true} | improper],
    ?assertMatch({error, {bad_socket_options, {list, _}}},
                 chan([{http, "gw", 1, [], #{socket_options => Improper}}])),
    ?assertMatch({error, {bad_socket_options, _}},
                 yuzu_grpc_client_config:channel(
                   {?CH, [{http, "gw", 1, [], #{socket_options => [{x, ?KEY_MARKER} | improper]}}], #{}},
                   false)).

nodelay_default_follows_the_env_switch_test_() ->
    {foreach,
     fun() -> application:unset_env(yuzu_gw, upstream_tcp_nodelay) end,
     fun(_) -> application:unset_env(yuzu_gw, upstream_tcp_nodelay) end,
     [{"unset: on", fun() -> ?assertEqual(true, yuzu_grpc_client_config:nodelay_default()) end},
      {"true: on", fun() -> env(true), ?assertEqual(true, yuzu_grpc_client_config:nodelay_default()) end},
      {"false: off", fun() -> env(false), ?assertEqual(false, yuzu_grpc_client_config:nodelay_default()) end},
      {"an invalid value falls back to on",
       fun() ->
           [begin
                env(Bad),
                ?assertEqual(true, yuzu_grpc_client_config:nodelay_default())
            end || Bad <- ["no", 0, off, <<"false">>]]
       end},
      {"channels/1 applies the switch to the endpoints",
       fun() ->
           Client = #{channels => [{?CH, [{http, "gw", 1, []}], #{}}]},
           env(false),
           ?assertMatch({ok, [#{endpoints := [#{tcp_opts := []}]}]},
                        yuzu_grpc_client_config:channels(Client)),
           env(true),
           ?assertMatch({ok, [#{endpoints := [#{tcp_opts := [{nodelay, true}]}]}]},
                        yuzu_grpc_client_config:channels(Client))
       end}]}.

env(V) -> application:set_env(yuzu_gw, upstream_tcp_nodelay, V).

%%%===================================================================
%%% Options
%%%===================================================================

defaults_test() ->
    {ok, C} = chan([{http, "gw", 1, []}]),
    ?assertEqual(#{name => ?CH,
                   endpoints => [#{host => "gw", port => 1, transport => tcp,
                                   tls_opts => [], tcp_opts => [{nodelay, true}]}],
                   pool_size => 1,
                   connect_timeout => 5000,
                   max_receive_message_bytes => 16 * 1024 * 1024}, C).

options_in_range_are_kept_test() ->
    {ok, C} = opts(#{pool_size => 8, connect_timeout => 1234, max_receive_message_bytes => 1024}),
    ?assertMatch(#{pool_size := 8, connect_timeout := 1234, max_receive_message_bytes := 1024}, C).

pool_size_bounds_test() ->
    [?assertMatch(#{pool_size := P}, ok_opts(#{pool_size => P})) || P <- [1, 2, 64]],
    [?assertMatch(#{pool_size := 1}, ok_opts(#{pool_size => P}))
     || P <- [0, -1, 65, 1000, "4", 2.0, undefined, infinity]].

%% replaced_options/1 reports exactly what channel/2 replaces, so the boot
%% warning and the behaviour cannot drift: for every value, a replacement is
%% reported if and only if the option comes out as its default for that reason.
replaced_options_agree_with_channel_test() ->
    Values = [0, -1, 1, 2, 64, 65, 1000, 600000, 600001, 1 bsl 30, (1 bsl 30) + 1,
              "4", <<"4">>, 2.0, undefined, infinity, #{}, {a}, [1]],
    [begin
         Raw = #{channels => [{?CH, [{http, "gw", 1, []}], #{Key => V}}]},
         Reported = [O || #{option := O} <- yuzu_grpc_client_config:replaced_options(Raw)],
         {ok, [#{Key := Got}]} = yuzu_grpc_client_config:channels(Raw),
         InRange = is_integer(V) andalso V >= Min andalso V =< Max,
         ?assertEqual(not InRange, Reported =:= [Key]),
         ?assertEqual(InRange orelse Got =:= Default, true)
     end || {Key, Min, Max, Default} <- yuzu_grpc_client_config:option_limits(), V <- Values],
    ok.

replaced_options_describes_without_contents_test() ->
    Raw = #{channels => [{?CH, [{http, "gw", 1, []}],
                          #{pool_size => 100, connect_timeout => "secret-looking",
                            max_receive_message_bytes => infinity}}]},
    ?assertEqual(
       [#{channel => ?CH, option => pool_size, given => "100", min => 1, max => 64, default => 1},
        #{channel => ?CH, option => connect_timeout, given => "a list", min => 1,
          max => 600000, default => 5000},
        #{channel => ?CH, option => max_receive_message_bytes, given => "infinity", min => 1,
          max => 1 bsl 30, default => 16 * 1024 * 1024}],
       yuzu_grpc_client_config:replaced_options(Raw)).

replaced_options_ignores_absent_and_malformed_test() ->
    ?assertEqual([], yuzu_grpc_client_config:replaced_options(undefined)),
    ?assertEqual([], yuzu_grpc_client_config:replaced_options(#{channels => []})),
    ?assertEqual([], yuzu_grpc_client_config:replaced_options(
                       #{channels => [{?CH, [{http, "gw", 1, []}], #{}}]})),
    ?assertEqual([], yuzu_grpc_client_config:replaced_options(
                       #{channels => [garbage, {?CH, [{http, "gw", 1, []}], [{pool_size, 0}]}]})),
    ?assertEqual([], yuzu_grpc_client_config:replaced_options(not_a_map)).

connect_timeout_bounds_test() ->
    [?assertMatch(#{connect_timeout := T}, ok_opts(#{connect_timeout => T})) || T <- [1, 5000, 600000]],
    [?assertMatch(#{connect_timeout := 5000}, ok_opts(#{connect_timeout => T}))
     || T <- [0, -5, 600001, "10", 1.5, infinity]].

max_receive_message_bytes_bounds_test() ->
    Max = 1 bsl 30,
    [?assertMatch(#{max_receive_message_bytes := N}, ok_opts(#{max_receive_message_bytes => N}))
     || N <- [1, 4 * 1024 * 1024, Max]],
    [?assertMatch(#{max_receive_message_bytes := 16777216}, ok_opts(#{max_receive_message_bytes => N}))
     || N <- [0, -1, Max + 1, "1024", 1.0e3, infinity]].

grpcbox_era_options_are_accepted_and_ignored_test() ->
    Plain = ok_opts(#{}),
    With = ok_opts(#{balancer => round_robin, encoding => gzip, sync_start => true,
                     unheard_of => [x]}),
    ?assertEqual(Plain, With),
    ?assertEqual([connect_timeout, endpoints, max_receive_message_bytes, name, pool_size],
                 lists:sort(maps:keys(With))).

options_not_a_map_are_rejected_test() ->
    ?assertMatch({error, {bad_channel, _}},
                 yuzu_grpc_client_config:channel({?CH, [{http, "gw", 1, []}], [{pool_size, 4}]}, true)).

%%%===================================================================
%%% channels/1
%%%===================================================================

undefined_client_is_no_channels_test() ->
    ?assertEqual({ok, []}, yuzu_grpc_client_config:channels(undefined)).

empty_channel_list_is_no_channels_test() ->
    ?assertEqual({ok, []}, yuzu_grpc_client_config:channels(#{channels => []})).

several_channels_keep_their_order_test() ->
    {ok, Cs} = yuzu_grpc_client_config:channels(
                 #{channels => [{b, [{http, "x", 1, []}], #{}}, {a, [{http, "y", 2, []}], #{}},
                                {?CH, [{https, "z", 3, [], #{}}], #{pool_size => 3}}]}),
    ?assertEqual([b, a, ?CH], [N || #{name := N} <- Cs]),
    ?assertEqual([1, 1, 3], [P || #{pool_size := P} <- Cs]).

unknown_keys_of_the_client_map_are_ignored_test() ->
    ?assertMatch({ok, [#{name := ?CH}]},
                 yuzu_grpc_client_config:channels(
                   #{channels => [{?CH, [{http, "gw", 1, []}], #{}}], marker => kept})).

bad_client_values_are_rejected_test() ->
    [?assertMatch({error, {bad_client_config, _}}, yuzu_grpc_client_config:channels(V))
     || V <- [#{}, #{channels => not_a_list}, not_a_map, [], {client, x}, 5]].

bad_channels_are_rejected_test() ->
    [?assertMatch({error, {bad_channel, _}}, yuzu_grpc_client_config:channels(#{channels => [C]}))
     || C <- [{"name", [{http, "gw", 1, []}], #{}}, {?CH, not_a_list, #{}}, {?CH, [{http, "gw", 1, []}]},
              {?CH, [{http, "gw", 1, []}], #{}, extra}, ?CH, 7]].

%% Two channels of one name would start two processes under one registered name
%% and one ETS table, and the second would fail inside the supervisor with an error
%% that names neither: refused where the config is read.
duplicate_channel_names_are_rejected_test() ->
    Ch = fun(Name, Port) -> {Name, [{http, "gw", Port, []}], #{}} end,
    ?assertEqual({error, {duplicate_channel, a}},
                 yuzu_grpc_client_config:channels(#{channels => [Ch(a, 1), Ch(a, 2)]})),
    ?assertEqual({error, {duplicate_channel, b}},
                 yuzu_grpc_client_config:channels(#{channels => [Ch(a, 1), Ch(b, 2), Ch(c, 3), Ch(b, 4)]})),
    %% the same endpoint under different names is fine, and so is one channel
    ?assertMatch({ok, [#{name := a}, #{name := b}]},
                 yuzu_grpc_client_config:channels(#{channels => [Ch(a, 1), Ch(b, 1)]})),
    ?assertMatch({ok, [#{name := a}]}, yuzu_grpc_client_config:channels(#{channels => [Ch(a, 1)]})),
    %% an unusable channel is reported as itself, not as a duplicate
    ?assertMatch({error, {bad_endpoint, _}},
                 yuzu_grpc_client_config:channels(
                   #{channels => [Ch(a, 1), Ch(a, 2), {a, [{http, "gw", 0, []}], #{}}]})).

one_bad_channel_rejects_the_whole_value_test() ->
    ?assertMatch({error, {bad_endpoint, _}},
                 yuzu_grpc_client_config:channels(
                   #{channels => [{a, [{http, "gw", 1, []}], #{}}, {b, [{http, "gw", 0, []}], #{}}]})).

%%%===================================================================
%%% from_env/0
%%%===================================================================

from_env_test_() ->
    {foreach,
     fun() -> {application:get_env(yuzu_gw, upstream_client),
               application:get_env(grpcbox, client)} end,
     fun({Prev, PrevOld}) ->
         restore(yuzu_gw, upstream_client, Prev),
         restore(grpcbox, client, PrevOld)
     end,
     [{"the key is upstream_client",
       fun() -> ?assertEqual(upstream_client, yuzu_grpc_client_config:env_key()) end},
      {"unset: no channels",
       fun() ->
           application:unset_env(yuzu_gw, upstream_client),
           ?assertEqual({ok, []}, yuzu_grpc_client_config:from_env())
       end},
      {"the channels of yuzu_gw/upstream_client are parsed",
       fun() ->
           application:set_env(yuzu_gw, upstream_client,
                               #{channels => [{?CH, [{http, "gw", 7, []}], #{pool_size => 3}}]}),
           ?assertMatch({ok, [#{name := ?CH, pool_size := 3,
                                endpoints := [#{host := "gw", port := 7}]}]},
                        yuzu_grpc_client_config:from_env())
       end},
      {"a bad value is an error, not an empty list",
       fun() ->
           application:set_env(yuzu_gw, upstream_client, #{channels => [{?CH, [], #{}}]}),
           ?assertMatch({error, {bad_channel, _}}, yuzu_grpc_client_config:from_env()),
           application:set_env(yuzu_gw, upstream_client, not_a_map),
           ?assertMatch({error, {bad_client_config, _}}, yuzu_grpc_client_config:from_env())
       end},
      {"a value at the old {grpcbox, client} key is not read",
       fun() ->
           application:unset_env(yuzu_gw, upstream_client),
           application:set_env(grpcbox, client,
                               #{channels => [{?CH, [{http, "gw", 7, []}], #{}}]}),
           ?assertEqual({ok, []}, yuzu_grpc_client_config:from_env())
       end}]}.

restore(App, Key, {ok, V}) -> application:set_env(App, Key, V);
restore(App, Key, undefined) -> application:unset_env(App, Key).

%%%===================================================================
%%% Errors leak nothing
%%%===================================================================

%% An endpoint's ssl options can name a private key; a rejection is logged. No
%% error term may carry them, whichever part of the endpoint is wrong.
errors_never_contain_ssl_options_or_key_paths_test() ->
    Ssl = ?MARKER_SSL,
    Bad = [{https, "gw", 0, Ssl},
           {https, "gw", 70000, Ssl, #{}},
           {https, "", 1, Ssl},
           {https, gw, 1, Ssl, #{}},
           {https, "gw", 1, Ssl, #{socket_options => list_to_binary(?KEY_MARKER)}},
           {https, "gw", 1, Ssl, not_a_map},
           {grpcs, "gw", 1, Ssl},
           {https, "gw", 1, Ssl, #{}, ?KEY_MARKER},
           {https, "gw", 1, list_to_binary(?KEY_MARKER)},
           {https, <<>>, 1, Ssl, #{socket_options => [{x, ?KEY_MARKER}]}},
           ?KEY_MARKER,
           {?KEY_MARKER, Ssl}],
    Errors = [chan([E]) || E <- Bad]
        ++ [yuzu_grpc_client_config:channel({?CH, [], #{ssl => Ssl}}, true),
            yuzu_grpc_client_config:channel({?CH, ?KEY_MARKER, #{}}, true),
            yuzu_grpc_client_config:channel({?KEY_MARKER, [{https, "gw", 1, Ssl}], #{}}, true),
            yuzu_grpc_client_config:channel({?CH, [{https, "gw", 1, Ssl}], ?MARKER_SSL}, true),
            yuzu_grpc_client_config:channels(#{channels => [{?CH, [{https, "gw", 1, Ssl, #{x => 1}}], bad}]}),
            yuzu_grpc_client_config:channels(#{channels => ?KEY_MARKER}),
            yuzu_grpc_client_config:channels({client, ?MARKER_SSL}),
            yuzu_grpc_client_config:channels([{channels, ?MARKER_SSL}])],
    [begin
         ?assertMatch({error, _}, R),
         Text = lists:flatten(io_lib:format("~0p", [R])),
         ?assertEqual(nomatch, string:find(Text, "marker")),
         ?assertEqual(nomatch, string:find(Text, "KEY")),
         ?assertEqual(nomatch, string:find(Text, "keyfile"))
     end || R <- Errors].

%% A good channel carries its ssl options (the channel process needs them) but a
%% failure about ANOTHER endpoint does not echo them back.
success_keeps_ssl_options_failure_drops_them_test() ->
    Good = {https, "gw", 1, ?MARKER_SSL},
    {ok, #{endpoints := [E]}} = chan([Good]),
    ?assertEqual(?MARKER_SSL, maps:get(tls_opts, E)),
    Err = chan([Good, {https, "gw2", 0, ?MARKER_SSL}]),
    ?assertMatch({error, {bad_endpoint, _}}, Err),
    ?assertEqual(nomatch, string:find(lists:flatten(io_lib:format("~0p", [Err])), "marker")).

%%%===================================================================
%%% Helpers
%%%===================================================================

chan(Endpoints) ->
    yuzu_grpc_client_config:channel({?CH, Endpoints, #{}}, true).

opts(Options) ->
    yuzu_grpc_client_config:channel({?CH, [{http, "gw", 1, []}], Options}, true).

ok_opts(Options) ->
    {ok, C} = opts(Options),
    C.

tcp_opts(Endpoints, Nodelay) ->
    {ok, #{endpoints := [#{tcp_opts := T} | _]}} =
        yuzu_grpc_client_config:channel({?CH, Endpoints, #{}}, Nodelay),
    T.
