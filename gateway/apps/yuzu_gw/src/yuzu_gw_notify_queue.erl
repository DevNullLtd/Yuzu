%%%-------------------------------------------------------------------
%%% @doc Bounded pending store for stream-status notifications (#4632).
%%%
%%% A pure, process-free data structure: the upstream gen_server keeps one in
%%% its state, enqueues a notification instead of dropping it when the
%%% in-flight limit is reached or the circuit breaker is not closed, and takes
%%% entries off the head as capacity returns.
%%%
%%% Contract:
%%%
%%% - Latest wins within a key. `put/4' on a key that is already held replaces
%%%   its event and reports `replaced'; the key keeps its queue position, so a
%%%   noisy key cannot push itself behind older work.
%%% - `take/1' is first in first out by first insertion.
%%% - The cap counts keys, not events and not agents. `put/4' reports `full'
%%%   (and returns the store unchanged) only for an absent key when
%%%   `size + Reserved >= Max'. A replace never reports full and never grows
%%%   the store.
%%% - `Reserved' (0 or more, 1 in practice) is the number of slots the caller
%%%   holds back for an event it has taken out and may have to give back, for
%%%   example a probe in flight. It is the caller's accounting; the store does
%%%   not track it.
%%% - `push_front/3' gives a taken event back at the head. If a newer event for
%%%   the same key is already held, the given-back one is superseded and
%%%   dropped: the held event stays and the size is unchanged. Otherwise the
%%%   key is inserted at the head. It is not bounded by the cap; the caller's
%%%   `Reserved' slot is what guarantees it fits.
%%%
%%% Internally a `queue' of keys plus a map of `Key => Event', kept one to
%%% one, so nothing ever needs an arbitrary deletion. All operations are
%%% amortized O(1).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_notify_queue).

-export([new/1, put/4, push_front/3, take/1, size/1, to_list/1]).

-export_type([t/0, key/0, event/0]).

-record(nq, {
    max    :: pos_integer(),
    keys   :: queue:queue(key()),   %% held keys, head = oldest first insertion
    events :: #{key() => event()}   %% the event currently held for each key
}).

-opaque t() :: #nq{}.
-type key() :: term().
-type event() :: term().

%% @doc An empty store that holds at most `Max' keys.
-spec new(pos_integer()) -> t().
new(Max) when is_integer(Max), Max >= 1 ->
    #nq{max = Max, keys = queue:new(), events = #{}}.

%% @doc Hold `Event' for `Key'. See the module doc for the result meanings.
-spec put(key(), event(), non_neg_integer(), t()) ->
          {new | replaced | full, t()}.
put(Key, Event, Reserved, #nq{max = Max, keys = Keys, events = Events} = Q)
  when is_integer(Reserved), Reserved >= 0 ->
    case maps:is_key(Key, Events) of
        true ->
            {replaced, Q#nq{events = Events#{Key := Event}}};
        false ->
            case map_size(Events) + Reserved >= Max of
                true ->
                    {full, Q};
                false ->
                    {new, Q#nq{keys = queue:in(Key, Keys),
                               events = Events#{Key => Event}}}
            end
    end.

%% @doc Give a previously taken event back at the head, unless a newer event
%% for the same key is already held (then it is superseded and dropped).
-spec push_front(key(), event(), t()) -> {inserted | superseded, t()}.
push_front(Key, Event, #nq{keys = Keys, events = Events} = Q) ->
    case maps:is_key(Key, Events) of
        true ->
            {superseded, Q};
        false ->
            {inserted, Q#nq{keys = queue:in_r(Key, Keys),
                            events = Events#{Key => Event}}}
    end.

%% @doc Remove and return the oldest key with its current event, or `empty'.
-spec take(t()) -> {key(), event(), t()} | empty.
take(#nq{keys = Keys, events = Events} = Q) ->
    case queue:out(Keys) of
        {empty, _} ->
            empty;
        {{value, Key}, Keys2} ->
            {Event, Events2} = maps:take(Key, Events),
            {Key, Event, Q#nq{keys = Keys2, events = Events2}}
    end.

%% @doc Number of keys held.
-spec size(t()) -> non_neg_integer().
size(#nq{events = Events}) ->
    map_size(Events).

%% @doc The held entries in take order. For tests only: it is O(n) and must
%% not be called on a production path.
-spec to_list(t()) -> [{key(), event()}].
to_list(#nq{keys = Keys, events = Events}) ->
    [{Key, maps:get(Key, Events)} || Key <- queue:to_list(Keys)].
