%%%-------------------------------------------------------------------
%%% @doc Sanitiser for the peer address an agent supplies (#4632).
%%%
%%% The peer address of a stream-status notification is the `:authority'
%%% header of the agent's Register call, so the agent controls every byte of
%%% it. The protobuf string encoder raises on a value that is not valid UTF-8,
%%% and the server's receive limit refuses a message that is too large. Either
%%% one makes the notification fail the same way every time it is sent. A
%%% notification like that, held at the head of the pending store while the
%%% circuit breaker is open, is the breaker probe: it would fail the probe on
%%% every half_open cycle and block every notification behind it. So the value
%%% is made safe where it is admitted, once, by this pure function.
%%%
%%%   - a value that is not a binary is replaced by the placeholder
%%%   - a valid UTF-8 value of at most 255 bytes is returned unchanged
%%%   - a longer valid UTF-8 value is cut to the longest prefix of at most 255
%%%     bytes that ends on a character boundary
%%%   - a value that is not valid UTF-8 is replaced by the placeholder
%%%
%%% The result is always a valid UTF-8 binary of at most 255 bytes, and always a
%%% copy: the input is typically a sub-binary of a large header block, and a
%%% sub-binary keeps its whole parent alive for as long as it is held (a 255 byte
%%% value would pin a multi-megabyte block for as long as the notification is
%%% held), so the result never shares storage with it.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_peer_addr).

-export([sanitize/1]).

-define(PLACEHOLDER, <<"invalid">>).
-define(MAX_BYTES, 255).

%% @doc Make an agent supplied peer address safe to encode and send.
-spec sanitize(term()) -> binary().
sanitize(Addr) when is_binary(Addr) ->
    case unicode:characters_to_binary(Addr, utf8, utf8) of
        Valid when is_binary(Valid), byte_size(Valid) =< ?MAX_BYTES ->
            binary:copy(Valid);
        Valid when is_binary(Valid) ->
            binary:copy(binary:part(Valid, 0, boundary(Valid, ?MAX_BYTES)));
        _NotUtf8 ->
            ?PLACEHOLDER
    end;
sanitize(_NotBinary) ->
    ?PLACEHOLDER.

%% The largest cut at or below Cut that does not split a character of the valid
%% UTF-8 binary Bin: byte Cut is the first byte dropped, so it must not be a
%% continuation byte (2#10xxxxxx). A character is at most 4 bytes, so this steps
%% back at most 3 times.
-spec boundary(binary(), non_neg_integer()) -> non_neg_integer().
boundary(_Bin, 0) ->
    0;
boundary(Bin, Cut) ->
    case binary:at(Bin, Cut) band 16#C0 of
        16#80 -> boundary(Bin, Cut - 1);
        _     -> Cut
    end.
