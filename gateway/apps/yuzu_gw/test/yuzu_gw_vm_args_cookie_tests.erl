%%%-------------------------------------------------------------------
%%% @doc The shipped vm.args.src must not carry a usable distribution cookie
%%% (F24). The in-VM guard (yuzu_gw_app:check_distribution_cookie/0) runs after
%%% distribution is listening, so a published literal in the boot file is
%%% reachable for the whole boot window; the file must name none. Reads the file
%%% through yuzu_gw_config_files_tests:repo_root/0 (SKIPPED when no root is
%%% found, unless YUZU_REQUIRE_CONFIG_FILES_TEST=1).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_vm_args_cookie_tests).
-include_lib("eunit/include/eunit.hrl").

vm_args_has_no_published_cookie_test() ->
    case yuzu_gw_config_files_tests:repo_root() of
        {error, _} ->
            ?assertNotEqual("1", os:getenv("YUZU_REQUIRE_CONFIG_FILES_TEST"));
        {ok, Root} ->
            {ok, Bin} = file:read_file(filename:join([Root, "gateway", "config", "vm.args.src"])),
            Lines = [string:trim(L) || L <- string:split(binary_to_list(Bin), "\n", all)],
            Active = [L || L <- Lines, L =/= "", hd(L) =/= $#],
            ?assertEqual([], [L || L <- Active,
                                   string:find(L, "yuzu_gw_secret_change_me") =/= nomatch]),
            %% the cookie line must name the env var and give it no non-empty default
            Cookie = [L || L <- Active, string:prefix(L, "-setcookie") =/= nomatch],
            ?assertEqual(["-setcookie ${YUZU_GW_COOKIE:-}"], Cookie)
    end.

%% PINNED CURRENT BEHAVIOUR, not an endorsement: with YUZU_GW_ALLOW_DEFAULT_COOKIE=1 the in-VM
%% guard tolerates an empty, short, exactly-default or literal-containing cookie on a
%% distributed node (a start that bypasses the container entrypoint: docker run --entrypoint,
%% bin/yuzu_gw by hand, the chisel image). The entrypoint is stricter (it refuses short and
%% literal-prefixed cookies under the override). If this test fails, evaluate_cookie changed:
%% update gateway.md, upgrading.md and the changelog fragment with it.
in_vm_guard_override_tolerance_is_pinned_test() ->
    N = 'yuzu_gw@127.0.0.1',
    [?assertEqual(ok, yuzu_gw_app:evaluate_cookie(N, C, true))
     || C <- ['', short, yuzu_gw_secret_change_me,
              'yuzu_gw_secret_change_meabcdefgh',
              'zzzzzzzzzzzzzzzzzzzzyuzu_gw_secret_change_mezzzzzzzzzzzzzzzzzzzz']],
    [?assertEqual({error, insecure_distribution_cookie}, yuzu_gw_app:evaluate_cookie(N, C, false))
     || C <- ['', short, yuzu_gw_secret_change_me,
              'zzzzzzzzzzzzzzzzzzzzyuzu_gw_secret_change_mezzzzzzzzzzzzzzzzzzzz']].

%% The published value is still refused by the in-VM guard (defence in depth).
guard_still_refuses_the_published_default_test() ->
    ?assertEqual({error, insecure_distribution_cookie},
                 yuzu_gw_app:evaluate_cookie('yuzu_gw@127.0.0.1', yuzu_gw_secret_change_me, false)).
