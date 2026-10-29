%%%-------------------------------------------------------------------
%%% @doc Every gateway metric reaches Prometheus (#5695, METRICS workstream).
%%%
%%% The declared set is not a list in this file: it is
%%% yuzu_gw_telemetry:declared_metrics/0, the names of the specs
%%% yuzu_gw_telemetry:metric_specs/0 holds, which is the list declare_metrics/0
%%% declares. A metric added there is covered here with no edit to this test.
%%%
%%%   scrape   The whole application is started from the shipped
%%%            gateway/config/sys.config (its agent and management listeners up,
%%%            on loopback and a free port each, an upstream channel to a port
%%%            nothing listens on, the Prometheus endpoint on a free port). One
%%%            real HTTP GET of /metrics is parsed. Every declared metric must
%%%            render a TYPE line of its declared type and a HELP line, and at
%%%            least one sample unless yuzu_gw_telemetry:unseeded_metrics/0 says
%%%            why it has none at start; every yuzu_gw_ family the endpoint
%%%            renders must be declared.
%%%   docs     Every declared metric is named in docs/user-manual/metrics.md,
%%%            and every yuzu_gw_ metric name there is declared.
%%%   alerts   Every yuzu_gw_ metric an `expr' in docs/prometheus/yuzu-alerts.yml
%%%            reads is declared (an alert on a metric nothing emits never fires).
%%%
%%% Isolation: the scrape case deregisters the declared metrics first, so what
%%% it sees is what the application's own start declared and seeded, not what
%%% an earlier module in this VM incremented. Cleanup stops the application,
%%% the httpd instance its start opened, and the telemetry handler it attached,
%%% and restores the application environment.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_metrics_scrape_tests).
-include_lib("eunit/include/eunit.hrl").

%% The names the application's supervisor registers; an earlier module may have
%% left one of them running. The pg scope (yuzu_gw) too: an earlier module's
%% fixture may have started it linked to the process that runs this one's, and
%% the application's supervisor adopts a running scope and stops it with the
%% application, which would take that process down.
-define(NAMED, [yuzu_gw, yuzu_gw_registry, yuzu_gw_agent_sup, yuzu_gw_heartbeat_buffer,
                yuzu_gw_router, yuzu_gw_upstream_regulator, yuzu_gw_upstream,
                yuzu_gw_upstream_pressure, yuzu_gw_gauge, yuzu_gw_health,
                yuzu_gw_cluster_discovery, yuzu_gw_memory_shedder,
                yuzu_gw_mem_reclaim, yuzu_gw_mgmt_pins, yuzu_gw_sup]).

%%%===================================================================
%%% docs and alerts: no application needed
%%%===================================================================

docs_name_every_declared_metric_test() ->
    {ok, Root} = yuzu_gw_config_files_tests:repo_root(),
    {ok, Doc} = file:read_file(filename:join([Root, "docs", "user-manual", "metrics.md"])),
    Declared = declared(),
    Named = metric_names(Doc, Declared),
    ?assertEqual({undocumented, []}, {undocumented, lists:sort(Declared -- Named)}),
    ?assertEqual({documented_not_declared, []},
                 {documented_not_declared, lists:sort(Named -- Declared)}).

alerts_read_only_declared_metrics_test() ->
    {ok, Root} = yuzu_gw_config_files_tests:repo_root(),
    {ok, Rules} = file:read_file(filename:join([Root, "docs", "prometheus", "yuzu-alerts.yml"])),
    Exprs = exprs(Rules),
    %% the parser found the gateway's rules (a vacuous pass would prove nothing)
    ?assertNotEqual([], [E || E <- Exprs, binary:match(E, <<"yuzu_gw_">>) =/= nomatch]),
    Declared = declared(),
    Read = lists:usort(lists:append([metric_names(E, Declared) || E <- Exprs])),
    ?assertNotEqual([], Read),
    Unknown = [N || N <- Read, not lists:member(N, Declared)],
    ?assertEqual({read_by_an_alert_not_declared, []}, {read_by_an_alert_not_declared, Unknown}).

%% unseeded_metrics/0 names only declared metrics, each with a reason.
unseeded_are_declared_test() ->
    Declared = declared(),
    [?assert(lists:member(N, Declared) andalso is_list(Why) andalso Why =/= "")
     || {N, Why} <- yuzu_gw_telemetry:unseeded_metrics()].

%%%===================================================================
%%% scrape a running gateway
%%%===================================================================

scrape_test_() ->
    {setup, fun setup/0, fun cleanup/1,
     fun(#{port := Port}) ->
         {timeout, 60,
          fun() ->
              {Status, Type, Body} = get_metrics(Port),
              ?assertEqual(200, Status),
              ?assertEqual("text/plain", hd(string:split(Type, ";"))),
              Families = families(Body),
              Specs = yuzu_gw_telemetry:metric_specs(),
              ?assert(length(Specs) > 50),
              Missing = [{N, T, maps:get(atom_to_binary(N), Families, absent)}
                         || {T, Spec} <- Specs,
                            N <- [proplists:get_value(name, Spec)],
                            not rendered(maps:get(atom_to_binary(N), Families, absent), T)],
              ?assertEqual({not_rendered_with_help_and_type, []},
                           {not_rendered_with_help_and_type, Missing}),
              Unseeded = [N || {N, _} <- yuzu_gw_telemetry:unseeded_metrics()],
              NoSample = [N || N <- declared() -- Unseeded,
                               maps:get(samples, maps:get(atom_to_binary(N), Families,
                                                          #{samples => 0})) =:= 0],
              ?assertEqual({declared_without_a_sample_at_start, []},
                           {declared_without_a_sample_at_start, NoSample}),
              Foreign = [F || F <- maps:keys(Families),
                              binary:longest_common_prefix([F, <<"yuzu_gw_">>]) =:= 8,
                              not lists:member(F, [atom_to_binary(N) || N <- declared()])],
              ?assertEqual({rendered_not_declared, []}, {rendered_not_declared, Foreign})
          end}
     end}.

setup() ->
    _ = application:stop(yuzu_gw),
    [stop_named(N) || N <- ?NAMED],
    {ok, _} = application:ensure_all_started(prometheus),
    {ok, _} = application:ensure_all_started(telemetry),
    {ok, _} = application:ensure_all_started(inets),
    _ = application:load(yuzu_gw),
    Env0 = application:get_all_env(yuzu_gw),
    Httpd0 = httpd_services(),
    Cookie = os:getenv("YUZU_GW_ALLOW_DEFAULT_COOKIE"),
    %% A distributed test VM (an earlier multinode module) has a default cookie
    %% the application refuses; this test is about metrics, not the cookie guard.
    os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", "1"),
    %% Start from an empty slate: what renders is what this start declares.
    catch telemetry:detach(yuzu_gw_prometheus),
    [deregister(T, proplists:get_value(name, S)) || {T, S} <- yuzu_gw_telemetry:metric_specs()],
    apply_shipped_config(),
    {ok, _} = application:ensure_all_started(yuzu_gw),
    [Httpd] = httpd_services() -- Httpd0,
    [{port, Port}] = httpd:info(Httpd, [port]),
    #{port => Port, env0 => Env0, httpd0 => Httpd0, cookie => Cookie}.

cleanup(#{env0 := Env0, httpd0 := Httpd0, cookie := Cookie}) ->
    %% The httpd first: its listening socket belongs to the application's
    %% start, and goes with it.
    [catch inets:stop(httpd, P) || P <- httpd_services() -- Httpd0],
    _ = application:stop(yuzu_gw),
    catch telemetry:detach(yuzu_gw_prometheus),
    [application:unset_env(yuzu_gw, K) || {K, _} <- application:get_all_env(yuzu_gw)],
    [application:set_env(yuzu_gw, K, V) || {K, V} <- Env0],
    case Cookie of
        false -> os:unsetenv("YUZU_GW_ALLOW_DEFAULT_COOKIE");
        _     -> os:putenv("YUZU_GW_ALLOW_DEFAULT_COOKIE", Cookie)
    end,
    ok.

%% The yuzu_gw section of the shipped gateway/config/sys.config, with every port
%% the test cannot own replaced: each listener on loopback and port 0, the
%% Prometheus and health endpoints on port 0, and the upstream channel at a
%% port that was free a moment ago (nothing answers there; the channel retries
%% in the background, as a gateway started before its server does).
apply_shipped_config() ->
    {ok, Root} = yuzu_gw_config_files_tests:repo_root(),
    {ok, [Terms]} = file:consult(filename:join([Root, "gateway", "config", "sys.config"])),
    {yuzu_gw, Env} = lists:keyfind(yuzu_gw, 1, Terms),
    [application:set_env(yuzu_gw, K, V) || {K, V} <- Env],
    {ok, Listeners} = application:get_env(yuzu_gw, grpc_listeners),
    ?assert(length(Listeners) >= 2),
    application:set_env(yuzu_gw, grpc_listeners,
                        [L#{listen => #{port => 0, ip => {127, 0, 0, 1}}} || L <- Listeners]),
    application:set_env(yuzu_gw, prometheus_port, 0),
    application:set_env(yuzu_gw, health_port, 0),
    {ok, #{channels := Channels}} = application:get_env(yuzu_gw, upstream_client),
    Dead = free_port(),
    application:set_env(yuzu_gw, upstream_client,
                        #{channels => [{Name, [{Scheme, "127.0.0.1", Dead, Opts}
                                               || {Scheme, _H, _P, Opts} <- Endpoints], ChOpts}
                                       || {Name, Endpoints, ChOpts} <- Channels]}).

get_metrics(Port) ->
    Url = "http://127.0.0.1:" ++ integer_to_list(Port) ++ "/metrics",
    {ok, {{_, Status, _}, Headers, Body}} =
        httpc:request(get, {Url, []}, [{timeout, 10000}], [{body_format, binary}]),
    {Status, proplists:get_value("content-type", Headers, ""), Body}.

%% #{FamilyName => #{help, type, samples}} from the text exposition.
families(Body) ->
    lists:foldl(fun line/2, #{}, binary:split(Body, <<"\n">>, [global])).

line(<<"# HELP ", Rest/binary>>, Acc) ->
    [Name | _] = binary:split(Rest, <<" ">>),
    update(Name, fun(F) -> F#{help => true} end, Acc);
line(<<"# TYPE ", Rest/binary>>, Acc) ->
    [Name, Type] = binary:split(Rest, <<" ">>),
    update(Name, fun(F) -> F#{type => Type} end, Acc);
line(<<"#", _/binary>>, Acc) ->
    Acc;
line(<<>>, Acc) ->
    Acc;
line(Sample, Acc) ->
    [Series | _] = binary:split(Sample, [<<"{">>, <<" ">>]),
    update(family(Series, Acc), fun(F) -> F#{samples => maps:get(samples, F) + 1} end, Acc).

%% A histogram's samples are Name_bucket, Name_count and Name_sum.
family(Series, Acc) ->
    case [B || Suffix <- [<<"_bucket">>, <<"_count">>, <<"_sum">>],
               B <- [strip(Series, Suffix)], B =/= Series, maps:is_key(B, Acc)] of
        [Base | _] -> Base;
        []         -> Series
    end.

update(Name, Fun, Acc) ->
    Acc#{Name => Fun(maps:get(Name, Acc, #{help => false, type => undefined, samples => 0}))}.

rendered(#{help := true, type := Type}, T) -> Type =:= atom_to_binary(T);
rendered(_, _) -> false.

%%%===================================================================
%%% Helpers
%%%===================================================================

declared() ->
    yuzu_gw_telemetry:declared_metrics().

%% The yuzu_gw_ metric names a text mentions, a histogram's _bucket/_count/_sum
%% series read as the histogram. A yuzu_gw_ word that is a module on the code
%% path (yuzu_gw_conn_watch, this test) is not a metric name.
metric_names(Text, Declared) ->
    Words = case re:run(Text, <<"yuzu_gw_[a-z0-9_]+">>, [global, {capture, first, binary}]) of
                {match, Ms} -> [W || [W] <- Ms];
                nomatch     -> []
            end,
    lists:usort([base(W, Declared) || W <- Words, not is_module(W)]).

base(Word, Declared) ->
    Atom = binary_to_atom(Word),
    case lists:member(Atom, Declared) of
        true -> Atom;
        false ->
            case [B || Suffix <- [<<"_bucket">>, <<"_count">>, <<"_sum">>],
                       B <- [strip(Word, Suffix)], B =/= Word,
                       lists:member(binary_to_atom(B), Declared)] of
                [B | _] -> binary_to_atom(B);
                []      -> Atom
            end
    end.

strip(Word, Suffix) ->
    case byte_size(Word) > byte_size(Suffix) andalso
         binary:longest_common_suffix([Word, Suffix]) =:= byte_size(Suffix) of
        true  -> binary:part(Word, 0, byte_size(Word) - byte_size(Suffix));
        false -> Word
    end.

is_module(Word) ->
    code:which(binary_to_atom(Word)) =/= non_existing.

%% The expressions of the rules file: an `expr:' line's own text, or the lines
%% of its block scalar (indented deeper than the key). Commented-out rules are
%% not read.
exprs(Rules) ->
    exprs(binary:split(Rules, <<"\n">>, [global]), []).

exprs([], Acc) ->
    lists:reverse(Acc);
exprs([Line | Rest], Acc) ->
    case re:run(Line, <<"^(\\s*)expr:\\s*(.*)$">>, [{capture, all_but_first, binary}]) of
        {match, [Indent, Block]} when Block =:= <<"|">>; Block =:= <<"|-">>;
                                      Block =:= <<">">>; Block =:= <<">-">> ->
            {Body, Rest1} = block(Rest, byte_size(Indent), []),
            exprs(Rest1, [Body | Acc]);
        {match, [_Indent, Inline]} ->
            exprs(Rest, [Inline | Acc]);
        nomatch ->
            exprs(Rest, Acc)
    end.

block([Line | Rest] = All, Indent, Acc) ->
    Lead = byte_size(Line) - byte_size(string:trim(Line, leading)),
    case Line =:= <<>> orelse Lead > Indent of
        true  -> block(Rest, Indent, [Line | Acc]);
        false -> {iolist_to_binary(lists:join(<<"\n">>, lists:reverse(Acc))), All}
    end;
block([], _Indent, Acc) ->
    {iolist_to_binary(lists:join(<<"\n">>, lists:reverse(Acc))), []}.

deregister(counter, Name)   -> prometheus_counter:deregister(Name);
deregister(gauge, Name)     -> prometheus_gauge:deregister(Name);
deregister(histogram, Name) -> prometheus_histogram:deregister(Name).

free_port() ->
    {ok, S} = gen_tcp:listen(0, [{ip, {127, 0, 0, 1}}]),
    {ok, Port} = inet:port(S),
    ok = gen_tcp:close(S),
    Port.

httpd_services() ->
    case catch inets:services() of
        L when is_list(L) -> [P || {httpd, P} <- L, is_pid(P)];
        _ -> []
    end.

stop_named(Name) ->
    case whereis(Name) of
        undefined -> ok;
        Pid ->
            catch unlink(Pid),
            Mon = monitor(process, Pid),
            exit(Pid, shutdown),
            receive {'DOWN', Mon, process, Pid, _} -> ok after 5000 -> ok end
    end.
