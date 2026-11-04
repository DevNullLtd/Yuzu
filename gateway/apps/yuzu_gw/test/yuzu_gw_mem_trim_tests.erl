%%%-------------------------------------------------------------------
%%% @doc yuzu_gw_mem_trim: the module always loads; with the NIF, malloc_trim/0
%%% returns glibc's answer; without it, it raises nif_not_loaded. On a glibc
%%% Linux target the compile hook must have built and the NIF must load (a
%%% build that silently dropped it would ship a gateway that never trims);
%%% on any other target there is no NIF.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mem_trim_tests).
-include_lib("eunit/include/eunit.hrl").

loads_or_reports_why_test() ->
    {module, yuzu_gw_mem_trim} = code:ensure_loaded(yuzu_gw_mem_trim),
    case yuzu_gw_mem_trim:loaded() of
        true ->
            ?assert(lists:member(yuzu_gw_mem_trim:malloc_trim(), [0, 1, unsupported]));
        {false, Why} ->
            ?assert(is_list(Why)),
            ?assertError(nif_not_loaded, yuzu_gw_mem_trim:malloc_trim())
    end.

loaded_exactly_on_glibc_linux_test() ->
    {module, yuzu_gw_mem_trim} = code:ensure_loaded(yuzu_gw_mem_trim),
    Arch = erlang:system_info(system_architecture),
    case string:find(Arch, "-linux-gnu") of
        nomatch ->
            ?assertMatch({false, _}, yuzu_gw_mem_trim:loaded());
        _ ->
            ?assertEqual(true, yuzu_gw_mem_trim:loaded()),
            ?assert(lists:member(yuzu_gw_mem_trim:malloc_trim(), [0, 1]))
    end.
