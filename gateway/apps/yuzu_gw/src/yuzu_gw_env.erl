%%%-------------------------------------------------------------------
%%% @doc Validated reads of the yuzu_gw application environment.
%%%
%%% One home for the bounded-integer read that yuzu_gw_upstream and
%%% yuzu_gw_heartbeat_buffer both need, so the two cannot drift, and for the
%%% boolean read the upstream channel setup uses, and for the bounded log text of
%%% untrusted server text that both also log. Depends on
%%% nothing but application and logger, so a test that mocks another yuzu_gw
%%% module does not lose it.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_env).

-export([env_int/4, env_bool/2, log_text/1, utf8_binary/1]).

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

%% @doc Convert configuration text to a UTF-8 binary: a binary that is valid
%% UTF-8, or a list of Unicode code points (or of such binaries), which is how
%% the environment and sys.config give a name with a non-ASCII character.
%% `list_to_binary/1' would truncate each code point to a byte and raise above
%% 255. Anything that is not representable (a code point above 16#10FFFF or a
%% surrogate, a binary that is not UTF-8, any other term) gives `error', never an
%% exception and never a partial result.
-spec utf8_binary(term()) -> {ok, binary()} | error.
utf8_binary(Text) ->
    try unicode:characters_to_binary(Text, utf8, utf8) of
        Bin when is_binary(Bin) -> {ok, Bin};
        _Other                  -> error
    catch
        error:_ -> error
    end.

%% @doc Untrusted server text for a log line (shared by yuzu_gw_upstream and
%% yuzu_gw_heartbeat_buffer): cut to 128 bytes, then every
%% control character is replaced by `?': C0 (below 32), DEL (127) and C1
%% (128..159, which ~s would render as the Latin-1 code points U+0080..U+009F,
%% among them NEL and CSI). The rest is shown as Latin-1 characters. Bytes,
%% not graphemes: the text need not be valid UTF-8, so the replacement is per
%% byte. Anything that is not a binary logs as empty.
-spec log_text(term()) -> binary().
log_text(Text) when is_binary(Text) ->
    Cut = binary:part(Text, 0, min(byte_size(Text), 128)),
    << <<(printable_byte(B))>> || <<B>> <= Cut >>;
log_text(_Other) ->
    <<>>.

printable_byte(B) when B < 32; B >= 127, B =< 159 -> $?;
printable_byte(B)                                  -> B.
