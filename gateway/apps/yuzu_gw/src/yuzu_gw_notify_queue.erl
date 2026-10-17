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
%%% - Latest wins within a key. `put/5' on a key that is already held replaces
%%%   its event and reports `replaced'; the key keeps its queue position, so a
%%%   noisy key cannot push itself behind older work.
%%% - `take/1' is first in first out by first insertion.
%%% - The cap counts keys, not events and not agents. An absent key is admitted
%%%   only while `size + Reserved < Max'. A replace never reports full and never
%%%   grows the store.
%%% - When an absent key does not fit, what happens depends on its class
%%%   (the drop policy, #5695):
%%%     `disconnected'  the OLDEST held key of class `connected' is evicted to
%%%                     make room, and reported (`{evicted, Key, Event}');
%%%                     only when no `connected' key is held is it refused.
%%%     `connected', `other'  refused (`full').
%%%   The reason: a lost DISCONNECTED leaves a session the server still thinks
%%%   is connected and that nothing removes until the agent registers again; a
%%%   lost CONNECTED can be put right by a registration replay (the caller arms
%%%   one, see yuzu_gw_upstream). The store only applies the policy; it is told
%%%   the class, it does not look inside events.
%%% - `Reserved' (0 or more) is the number of slots the caller holds back for
%%%   events it has taken out and may have to give back, for example sends in
%%%   flight. It is the caller's accounting; the store does not track it.
%%% - `push_front/4' gives a taken event back at the head. If a newer event for
%%%   the same key is already held, the given-back one is superseded and
%%%   dropped: the held event stays and the size is unchanged. Otherwise the
%%%   key is inserted at the head. It is not bounded by the cap; the caller's
%%%   `Reserved' slots are what guarantee it fits.
%%% - `peek_key/1' names the key `take/1' would return, without taking it.
%%%
%%% Internally a `queue' of {Seq, Key} in take order, a `queue' of {Seq, Key}
%%% of the `connected' entries in eviction order, and a map Key => {Seq, Class,
%%% Event}. An eviction removes the key from the map only: the queue entries it
%%% leaves behind are tombstones (their Seq no longer matches the map) that
%%% `take/1', `peek_key/1' and eviction skip, and a queue whose tombstones
%%% outnumber its live entries is compacted. All operations are amortized O(1).
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_notify_queue).

-export([new/1, put/4, put/5, push_front/3, push_front/4, take/1, peek_key/1, size/1,
         cap/1, set_cap/2, to_list/1]).

-export_type([t/0, key/0, event/0, class/0]).

-record(nq, {
    max    :: pos_integer(),
    seq    = 0 :: non_neg_integer(),
    keys   :: queue:queue({non_neg_integer(), key()}),   %% take order (with tombstones)
    conns  :: queue:queue({non_neg_integer(), key()}),   %% connected entries, oldest first
    events :: #{key() => {non_neg_integer(), class(), event()}}
}).

-opaque t() :: #nq{}.
-type key() :: term().
-type event() :: term().
-type class() :: connected | disconnected | other.

%% @doc An empty store that holds at most `Max' keys.
-spec new(pos_integer()) -> t().
new(Max) when is_integer(Max), Max >= 1 ->
    #nq{max = Max, keys = queue:new(), conns = queue:new(), events = #{}}.

%% @doc put/5 with class `other' (never evicts).
-spec put(key(), event(), non_neg_integer(), t()) -> {new | replaced | full, t()}.
put(Key, Event, Reserved, Q) ->
    case put(Key, Event, other, Reserved, Q) of
        {{evicted, _, _}, _} -> erlang:error(unreachable);
        Result -> Result
    end.

%% @doc Hold `Event' for `Key'. See the module doc for the result meanings.
-spec put(key(), event(), class(), non_neg_integer(), t()) ->
          {new | replaced | full | {evicted, key(), event()}, t()}.
put(Key, Event, Class, Reserved, #nq{max = Max, events = Events} = Q)
  when is_integer(Reserved), Reserved >= 0 ->
    case maps:find(Key, Events) of
        {ok, {Seq, OldClass, _}} ->
            Q1 = case Class =:= connected andalso OldClass =/= connected of
                     true  -> Q#nq{conns = queue:in({Seq, Key}, Q#nq.conns)};
                     false -> Q
                 end,
            {replaced, Q1#nq{events = Events#{Key := {Seq, Class, Event}}}};
        error ->
            case map_size(Events) + Reserved < Max of
                true ->
                    {new, insert_back(Key, Event, Class, Q)};
                false when Class =:= disconnected ->
                    case evict_oldest_connected(Q) of
                        {ok, EvKey, EvEvent, Q1} ->
                            {{evicted, EvKey, EvEvent}, insert_back(Key, Event, Class, Q1)};
                        {none, Q1} ->
                            {full, Q1}
                    end;
                false ->
                    {full, Q}
            end
    end.

%% @doc push_front/4 with class `other'.
-spec push_front(key(), event(), t()) -> {inserted | superseded, t()}.
push_front(Key, Event, Q) ->
    push_front(Key, Event, other, Q).

%% @doc Give a previously taken event back at the head, unless a newer event
%% for the same key is already held (then it is superseded and dropped).
-spec push_front(key(), event(), class(), t()) -> {inserted | superseded, t()}.
push_front(Key, Event, Class, #nq{seq = Seq0, keys = Keys, conns = Conns, events = Events} = Q) ->
    case maps:is_key(Key, Events) of
        true ->
            {superseded, Q};
        false ->
            Seq = Seq0 + 1,
            Conns1 = case Class of
                         connected -> queue:in_r({Seq, Key}, Conns);
                         _         -> Conns
                     end,
            {inserted, Q#nq{seq = Seq, keys = queue:in_r({Seq, Key}, Keys), conns = Conns1,
                            events = Events#{Key => {Seq, Class, Event}}}}
    end.

%% @doc Remove and return the oldest key with its current event, or `empty'.
-spec take(t()) -> {key(), event(), t()} | empty.
take(Q) ->
    case peek_key(Q) of
        {empty, _} ->
            empty;
        {ok, Key, #nq{keys = Keys, events = Events} = Q1} ->
            Keys1 = queue:drop(Keys),
            {{_Seq, _Class, Event}, Events1} = maps:take(Key, Events),
            {Key, Event, Q1#nq{keys = Keys1, events = Events1}}
    end.

%% @doc The key take/1 would return next (and the store with the tombstones in
%% front of it dropped), or `empty'.
-spec peek_key(t()) -> {ok, key(), t()} | {empty, t()}.
peek_key(#nq{keys = Keys, events = Events} = Q) ->
    case queue:peek(Keys) of
        empty ->
            {empty, Q};
        {value, {Seq, Key}} ->
            case maps:find(Key, Events) of
                {ok, {Seq, _, _}} -> {ok, Key, Q};
                _ -> peek_key(Q#nq{keys = queue:drop(Keys)})
            end
    end.

%% @doc Number of keys held.
-spec size(t()) -> non_neg_integer().
size(#nq{events = Events}) ->
    map_size(Events).

%% @doc The cap.
-spec cap(t()) -> pos_integer().
cap(#nq{max = Max}) ->
    Max.

%% @doc Change the cap. Held keys are never dropped by it: a lower cap only
%% refuses new keys until the store is below it.
-spec set_cap(pos_integer(), t()) -> t().
set_cap(Max, Q) when is_integer(Max), Max >= 1 ->
    Q#nq{max = Max}.

%% @doc The held entries in take order. For tests only: it is O(n) and must
%% not be called on a production path.
-spec to_list(t()) -> [{key(), event()}].
to_list(#nq{keys = Keys, events = Events}) ->
    [{Key, Event} || {Seq, Key} <- queue:to_list(Keys),
                     {ok, {S, _, Event}} <- [maps:find(Key, Events)], S =:= Seq].

%%%===================================================================
%%% Internal
%%%===================================================================

insert_back(Key, Event, Class, #nq{seq = Seq0, keys = Keys, conns = Conns, events = Events} = Q) ->
    Seq = Seq0 + 1,
    Conns1 = case Class of
                 connected -> queue:in({Seq, Key}, Conns);
                 _         -> Conns
             end,
    compact(Q#nq{seq = Seq, keys = queue:in({Seq, Key}, Keys), conns = Conns1,
                 events = Events#{Key => {Seq, Class, Event}}}).

%% The oldest live `connected' entry, removed from the map (its take-queue entry
%% becomes a tombstone). Stale conns entries (evicted, taken, or replaced by an
%% event of another class) are dropped on the way.
evict_oldest_connected(#nq{conns = Conns, events = Events} = Q) ->
    case queue:out(Conns) of
        {empty, _} ->
            {none, Q};
        {{value, {Seq, Key}}, Conns1} ->
            case maps:find(Key, Events) of
                {ok, {Seq, connected, Event}} ->
                    {ok, Key, Event, Q#nq{conns = Conns1, events = maps:remove(Key, Events)}};
                _ ->
                    evict_oldest_connected(Q#nq{conns = Conns1})
            end
    end.

%% Drop tombstones once a queue holds more than twice the live keys (plus a
%% floor), so evictions and takes cannot grow it without bound.
compact(#nq{keys = Keys, conns = Conns, events = Events} = Q) ->
    Live = map_size(Events),
    Keys1 = case queue:len(Keys) > 2 * Live + 64 of
                true  -> queue:filter(fun(E) -> live(E, Events) end, Keys);
                false -> Keys
            end,
    Conns1 = case queue:len(Conns) > 2 * Live + 64 of
                 true  -> queue:filter(fun({S, K}) ->
                                               case maps:find(K, Events) of
                                                   {ok, {S, connected, _}} -> true;
                                                   _ -> false
                                               end
                                       end, Conns);
                 false -> Conns
             end,
    Q#nq{keys = Keys1, conns = Conns1}.

live({Seq, Key}, Events) ->
    case maps:find(Key, Events) of
        {ok, {Seq, _, _}} -> true;
        _ -> false
    end.
