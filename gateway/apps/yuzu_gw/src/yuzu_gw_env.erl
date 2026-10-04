%%%-------------------------------------------------------------------
%%% @doc Validated reads of the yuzu_gw application environment.
%%%
%%% One home for the bounded-integer read that yuzu_gw_upstream and
%%% yuzu_gw_heartbeat_buffer both need, so the two cannot drift, and for the
%%% boolean read the upstream channel setup uses. Depends on
%%% nothing but application and logger, so a test that mocks another yuzu_gw
%%% module does not lose it.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_env).

-export([env_int/4, env_bool/2]).

%% @doc Read an integer application env key that must lie in Min..Max; an
%% invalid value is logged (naming the key) and replaced by the default.
-spec env_int(atom(), integer(), integer(), integer()) -> integer().
env_int(Key, Default, Min, Max) ->
    case application:get_env(yuzu_gw, Key, Default) of
        Value when is_integer(Value), Value >= Min, Value =< Max ->
            Value;
        Bad ->
            logger:warning("Invalid ~s value ~p (expected an integer in ~b..~b); using ~b",
                           [Key, Bad, Min, Max, Default]),
            Default
    end.

%% @doc Read a boolean application env key (`true' or `false' only); any other
%% value is logged (naming the key) and replaced by the default.
-spec env_bool(atom(), boolean()) -> boolean().
env_bool(Key, Default) ->
    case application:get_env(yuzu_gw, Key, Default) of
        Value when is_boolean(Value) ->
            Value;
        Bad ->
            logger:warning("Invalid ~s value ~p (expected true or false); using ~p",
                           [Key, Bad, Default]),
            Default
    end.
