%%%-------------------------------------------------------------------
%%% @doc Optional loader for the malloc_trim NIF (c_src/yuzu_gw_mem_trim_nif.c).
%%%
%%% The NIF is built only on glibc Linux (the "-linux-gnu-" hook in
%%% apps/yuzu_gw/rebar.config); the default Alpine image, macOS and Windows
%%% have no .so. A missing or unloadable shared object never stops this module
%%% from loading: init/0 always returns `ok' (a non-ok on_load return would
%%% make the module fail to load, and in an embedded release fail the boot).
%%% It records the outcome, which loaded/0 returns, and malloc_trim/0 then
%%% raises error:nif_not_loaded, which yuzu_gw_mem_reclaim turns into "GC
%%% only" with one notice line.
%%%
%%% malloc_trim/0 returns what glibc's malloc_trim(0) returns (1 if memory was
%%% given back to the OS, else 0), or `unsupported' when the NIF was compiled
%%% against another libc. It runs on a dirty CPU scheduler.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mem_trim).

-export([malloc_trim/0, loaded/0]).

-on_load(init/0).
-nifs([malloc_trim/0]).

-define(KEY, {?MODULE, loaded}).

-spec init() -> ok.
init() ->
    Result = case erlang:load_nif(filename:join(priv_dir(), "yuzu_gw_mem_trim_nif"), 0) of
                 ok -> true;
                 {error, {_Reason, Text}} -> {false, Text}
             end,
    persistent_term:put(?KEY, Result),
    ok.

%% @doc `true' when the NIF is loaded, else `{false, Why}' (the loader's text).
-spec loaded() -> true | {false, string()}.
loaded() ->
    persistent_term:get(?KEY, {false, "not loaded"}).

-spec malloc_trim() -> 0 | 1 | unsupported.
malloc_trim() ->
    erlang:nif_error(nif_not_loaded).

priv_dir() ->
    case code:priv_dir(yuzu_gw) of
        {error, bad_name} ->
            %% Not loaded as part of the yuzu_gw application (an ad hoc
            %% `erl -pa ebin'): the priv/ next to this module's ebin/. A
            %% module with no file (loaded from a binary) gets a relative
            %% "priv", which load_nif then reports as not found.
            case code:which(?MODULE) of
                Beam when is_list(Beam) ->
                    filename:join(filename:dirname(filename:dirname(Beam)), "priv");
                _ ->
                    "priv"
            end;
        Dir ->
            Dir
    end.
