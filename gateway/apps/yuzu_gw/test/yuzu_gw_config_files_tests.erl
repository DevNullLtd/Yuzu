%%%-------------------------------------------------------------------
%%% @doc The SHIPPED sys.config files, read the way a release reads them.
%%%
%%% A configuration can parse and still be invisible at boot: an earlier design
%%% shipped the upstream channels under `{grpcbox, [{client, ...}]}', a key OTP
%%% never applies because it applies a sys.config entry only to a LOADED
%%% application and none is named grpcbox. Every unit test that set the value
%%% with application:set_env/3 passed; the real files would have booted a gateway
%%% with no upstream. This module closes that gap by reading the files
%%% themselves, for each one:
%%%
%%%   1. file:consult/1 parses it (so a syntax slip, including in a
%%%      `fun M:F/A' term, fails here and not at a container boot);
%%%   2. it carries no `{grpcbox, _}' entry at all, and
%%%      yuzu_gw_app:legacy_grpcbox_in_files/2 finds neither `client' nor
%%%      `servers' in it (the scan the boot guards run);
%%%   3. `{yuzu_gw, upstream_client}' is accepted by
%%%      yuzu_grpc_client_config:channels/1, names a `default_channel', and
%%%      passes yuzu_gw_app:check_upstream_client_config/0 once set as the
%%%      application env (with `allow_no_upstream' unset, so the acknowledgement
%%%      cannot excuse a missing channel);
%%%   4. when the file configures `grpc_listeners', they pass
%%%      yuzu_gw_app:check_grpc_listeners/0 once set as the application env (with
%%%      `allow_no_listeners' unset, for the same reason).
%%%
%%% The application env keys this touches are saved and restored around the run.
%%%
%%% Where the files are: the repository root is found by walking up from
%%% code:lib_dir(yuzu_gw) and then from the working directory until a directory
%%% holds `gateway/config/sys.config' and `deploy/docker/'; the environment
%%% variable YUZU_CONFIG_FILES_ROOT names it explicitly and wins. When no root is
%%% found the module reports SKIPPED on stderr and runs nothing (EUnit has no skip
%%% result), unless YUZU_REQUIRE_CONFIG_FILES_TEST=1, which makes that a failure.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_config_files_tests).

%% The repository root, for other modules that read shipped files.
-export([repo_root/0]).
-include_lib("eunit/include/eunit.hrl").

%% Every shipped Erlang config, relative to the repository root. test.config is
%% the suites' config rather than a release's; it is held to items 1-3 as well,
%% because a channel the suites could not see would hide the same defect.
config_files() ->
    ["gateway/config/sys.config",
     "gateway/config/sys.config.prod",
     "gateway/config/test.config",
     "deploy/config/uat/gateway-sys.config",
     "deploy/docker/gateway-sys.config",
     "deploy/docker/demo-gateway-sys.config",
     "deploy/docker/reference-gateway-sys.config"].

%% The application env keys the checks set, saved and restored around the run.
env_keys() ->
    [upstream_client, grpc_listeners, allow_no_listeners, allow_no_upstream].

config_files_test_() ->
    case repo_root() of
        {ok, Root} ->
            {setup, fun save_env/0, fun restore_env/1,
             [{File, [{"parses", fun() -> check_parses(Root, File) end},
                      {"no grpcbox entry", fun() -> check_no_grpcbox(Root, File) end},
                      {"upstream_client is visible and names default_channel",
                       fun() -> check_upstream_client(Root, File) end},
                      {"grpc_listeners pass the boot guard",
                       fun() -> check_listeners(Root, File) end}]}
              || File <- config_files()]};
        {error, Why} ->
            case os:getenv("YUZU_REQUIRE_CONFIG_FILES_TEST") of
                "1" ->
                    [{"the shipped config files are found",
                      fun() -> erlang:error({config_files_not_found, Why}) end}];
                _ ->
                    io:format(standard_error,
                              "~nSKIPPED yuzu_gw_config_files_tests: ~ts~n"
                              "(set YUZU_REQUIRE_CONFIG_FILES_TEST=1 to make this a failure, "
                              "YUZU_CONFIG_FILES_ROOT=<repo root> to name the root)~n",
                              [Why]),
                    []
            end
    end.

%%--------------------------------------------------------------------
%% Checks
%%--------------------------------------------------------------------

check_parses(Root, File) ->
    Path = filename:join(Root, File),
    ?assert(filelib:is_regular(Path)),
    ?assertMatch({ok, [Cfg]} when is_list(Cfg), file:consult(Path)).

check_no_grpcbox(Root, File) ->
    Path = filename:join(Root, File),
    Cfg = consult(Path),
    ?assertEqual(false, lists:keymember(grpcbox, 1, Cfg)),
    ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(client, [Path])),
    ?assertEqual(absent, yuzu_gw_app:legacy_grpcbox_in_files(servers, [Path])).

check_upstream_client(Root, File) ->
    Cfg = consult(filename:join(Root, File)),
    Env = proplists:get_value(yuzu_gw, Cfg, []),
    V = proplists:get_value(upstream_client, Env, undefined),
    ?assertNotEqual(undefined, V),
    {ok, Channels} = yuzu_grpc_client_config:channels(V),
    ?assert(lists:any(fun(#{name := N}) -> N =:= default_channel end, Channels)),
    %% And through the boot guard, which reads the application env the way a
    %% release has filled it from this file.
    with_env([{upstream_client, V}, {allow_no_upstream, unset}],
             fun() -> ?assertEqual(ok, yuzu_gw_app:check_upstream_client_config()) end).

check_listeners(Root, File) ->
    Cfg = consult(filename:join(Root, File)),
    Env = proplists:get_value(yuzu_gw, Cfg, []),
    case proplists:get_value(grpc_listeners, Env, undefined) of
        undefined ->
            ok;
        Listeners ->
            with_env([{grpc_listeners, Listeners}, {allow_no_listeners, unset}],
                     fun() -> ?assertEqual(ok, yuzu_gw_app:check_grpc_listeners()) end)
    end.

%%--------------------------------------------------------------------
%% Helpers
%%--------------------------------------------------------------------

consult(Path) ->
    {ok, [Cfg]} = file:consult(Path),
    Cfg.

%% Run Fun with these yuzu_gw env values (`unset' removes the key), putting the
%% values it found back afterwards, also when Fun fails.
with_env(Settings, Fun) ->
    Saved = [{K, application:get_env(yuzu_gw, K)} || {K, _} <- Settings],
    try
        lists:foreach(fun({K, unset}) -> application:unset_env(yuzu_gw, K);
                         ({K, V})     -> application:set_env(yuzu_gw, K, V)
                      end, Settings),
        Fun()
    after
        restore(Saved)
    end.

save_env() ->
    [{K, application:get_env(yuzu_gw, K)} || K <- env_keys()].

restore_env(Saved) ->
    restore(Saved).

restore(Saved) ->
    lists:foreach(fun({K, {ok, V}}) -> application:set_env(yuzu_gw, K, V);
                     ({K, undefined}) -> application:unset_env(yuzu_gw, K)
                  end, Saved).

%% The repository root: the environment variable, else the first ancestor of the
%% library directory (then of the working directory) that looks like one.
repo_root() ->
    case os:getenv("YUZU_CONFIG_FILES_ROOT") of
        Dir when is_list(Dir), Dir =/= "" ->
            case is_root(Dir) of
                true  -> {ok, Dir};
                false -> {error, "YUZU_CONFIG_FILES_ROOT=" ++ Dir ++ " does not hold "
                                 "gateway/config/sys.config and deploy/docker"}
            end;
        _ ->
            Starts = [S || S <- [lib_dir(), cwd()], S =/= undefined],
            case [R || S <- Starts, R <- [walk_up(filename:absname(S))], R =/= undefined] of
                [Root | _] -> {ok, Root};
                []         -> {error, "no ancestor of the yuzu_gw library directory or the "
                                      "working directory holds gateway/config/sys.config "
                                      "and deploy/docker"}
            end
    end.

lib_dir() ->
    case code:lib_dir(yuzu_gw) of
        {error, _} -> undefined;
        Dir        -> Dir
    end.

cwd() ->
    case file:get_cwd() of
        {ok, Dir} -> Dir;
        _         -> undefined
    end.

walk_up(Dir) ->
    case is_root(Dir) of
        true  -> Dir;
        false ->
            case filename:dirname(Dir) of
                Dir    -> undefined;
                Parent -> walk_up(Parent)
            end
    end.

is_root(Dir) ->
    filelib:is_regular(filename:join([Dir, "gateway", "config", "sys.config"]))
        andalso filelib:is_dir(filename:join([Dir, "deploy", "docker"])).
