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

-export([env_int/4, env_bool/2, log_text/1, utf8_binary/1, env_utf8_binary/1,
         env_utf8_binary/2]).

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

%% @doc Convert the text of an OPERATING SYSTEM ENVIRONMENT variable, as
%% os:getenv/1 returned it on this node, to a UTF-8 binary.
-spec env_utf8_binary(term()) -> {ok, binary()} | error.
env_utf8_binary(Text) ->
    env_utf8_binary(Text, file:native_name_encoding()).

%% @doc env_utf8_binary/1 for a stated native name encoding (latin1 | utf8).
%%
%% os:getenv/1 decodes the variable's bytes with the node's native name
%% encoding. Under utf8 it returns the characters. Under latin1, which is what a
%% node gets with no UTF-8 locale and no +fnu (the shipped images set neither
%% LANG nor LC_ALL), it returns the BYTES, one per element: UTF-8 text comes back
%% as a list of code points below 256, and treating those as characters would
%% encode every non-ASCII byte a second time, into a different name that is still
%% valid UTF-8 and so is never refused. So the original bytes are recovered by
%% encoding the text back with the same encoding, and THEN must be valid UTF-8.
%% Under latin1 a code point above 255 cannot have come from the environment and
%% is refused, never truncated. Anything else that is not representable (bytes
%% that are not UTF-8, a surrogate, a code point above 16#10FFFF, any non-list
%% term) gives `error', never an exception and never a partial result.
%%
%% Limits: under utf8 the VM reads a byte sequence that is not valid UTF-8 as
%% latin1 characters (a lone 0xFC arrives as 252, as for the valid UTF-8 text
%% "u with umlaut"), so such a variable is indistinguishable from the valid text
%% and becomes that name. Only a latin1 node can refuse non-UTF-8 bytes.
-spec env_utf8_binary(term(), latin1 | utf8) -> {ok, binary()} | error.
env_utf8_binary(Text, Encoding) when is_list(Text) ->
    try unicode:characters_to_binary(Text, unicode, Encoding) of
        Bytes when is_binary(Bytes) -> utf8_binary(Bytes);
        _Other                      -> error
    catch
        error:_ -> error
    end;
env_utf8_binary(_Text, _Encoding) ->
    error.

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
