%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_notify_queue, the pure bounded pending store behind
%%% the upstream's stream-status notifications (#4632).
%%%
%%% The contract pinned here: latest event wins within a key, a replacement
%%% keeps its queue position, `take/1' is first in first out by first
%%% insertion, `put/4' is full only for an absent key (size plus the reserved
%%% slots at or over the cap), and `push_front/3' puts a failed probe's event
%%% back at the head unless a newer event for the same key is already held.
%%% A seeded randomized comparison against a plain list model covers the
%%% interleavings the example tests cannot enumerate.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_notify_queue_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SEQUENCES, 200).
-define(MAX_LEN, 500).
-define(SEED, {4632, 20261005, 17}).
-define(KEY_SPACE, 12).
-define(RANDOM_CAP, 6).

k(N) -> {<<"agent-", (integer_to_binary(N))/binary>>, <<"session">>, <<"home">>}.

%% Put every {Key, Event} with Reserved 0, asserting each is accepted as new.
fill(Max, Pairs) ->
    lists:foldl(fun({K, E}, Q) ->
                        {new, Q2} = yuzu_gw_notify_queue:put(K, E, 0, Q),
                        Q2
                end, yuzu_gw_notify_queue:new(Max), Pairs).

drain(Q) ->
    case yuzu_gw_notify_queue:take(Q) of
        empty -> [];
        {K, E, Q2} -> [{K, E} | drain(Q2)]
    end.

%%--------------------------------------------------------------------
%% put / take / size
%%--------------------------------------------------------------------

basics_test_() ->
    [
     {"a new queue is empty and take on it is empty",
      fun() ->
          Q = yuzu_gw_notify_queue:new(5),
          ?assertEqual(0, yuzu_gw_notify_queue:size(Q)),
          ?assertEqual([], yuzu_gw_notify_queue:to_list(Q)),
          ?assertEqual(empty, yuzu_gw_notify_queue:take(Q))
      end},
     {"put of an absent key is new and grows the size",
      fun() ->
          Q0 = yuzu_gw_notify_queue:new(5),
          {new, Q1} = yuzu_gw_notify_queue:put(k(1), a, 0, Q0),
          ?assertEqual(1, yuzu_gw_notify_queue:size(Q1)),
          {new, Q2} = yuzu_gw_notify_queue:put(k(2), b, 0, Q1),
          ?assertEqual(2, yuzu_gw_notify_queue:size(Q2))
      end},
     {"put of a present key is replaced, the latest event wins and size is unchanged",
      fun() ->
          Q1 = fill(5, [{k(1), a}, {k(2), b}]),
          {replaced, Q2} = yuzu_gw_notify_queue:put(k(1), c, 0, Q1),
          ?assertEqual(2, yuzu_gw_notify_queue:size(Q2)),
          ?assertEqual([{k(1), c}, {k(2), b}], yuzu_gw_notify_queue:to_list(Q2))
      end},
     {"take returns the head, shrinks the queue and ends in empty",
      fun() ->
          Q1 = fill(5, [{k(1), a}, {k(2), b}]),
          {Key1, Ev1, Q2} = yuzu_gw_notify_queue:take(Q1),
          ?assertEqual({k(1), a}, {Key1, Ev1}),
          ?assertEqual(1, yuzu_gw_notify_queue:size(Q2)),
          {Key2, Ev2, Q3} = yuzu_gw_notify_queue:take(Q2),
          ?assertEqual({k(2), b}, {Key2, Ev2}),
          ?assertEqual(0, yuzu_gw_notify_queue:size(Q3)),
          ?assertEqual(empty, yuzu_gw_notify_queue:take(Q3))
      end},
     {"a taken key can be put again as new",
      fun() ->
          Q1 = fill(5, [{k(1), a}]),
          {Key1, a, Q2} = yuzu_gw_notify_queue:take(Q1),
          ?assertEqual(k(1), Key1),
          {new, Q3} = yuzu_gw_notify_queue:put(k(1), b, 0, Q2),
          ?assertEqual([{k(1), b}], yuzu_gw_notify_queue:to_list(Q3))
      end},
     {"keys that differ in any one element are distinct keys",
      fun() ->
          Q = fill(5, [{{<<"a">>, <<"s1">>, <<"h">>}, e1},
                       {{<<"a">>, <<"s2">>, <<"h">>}, e2},
                       {{<<"a">>, <<"s1">>, <<"h2">>}, e3},
                       {{<<"b">>, <<"s1">>, <<"h">>}, e4}]),
          ?assertEqual(4, yuzu_gw_notify_queue:size(Q))
      end}
    ].

%%--------------------------------------------------------------------
%% FIFO by first insertion
%%--------------------------------------------------------------------

fifo_test_() ->
    [
     {"take order is insertion order",
      fun() ->
          Pairs = [{k(N), N} || N <- [5, 3, 9, 1, 7]],
          ?assertEqual(Pairs, drain(fill(10, Pairs)))
      end},
     {"a replacement keeps its queue position",
      fun() ->
          Q1 = fill(10, [{k(1), a}, {k(2), b}, {k(3), c}]),
          {replaced, Q2} = yuzu_gw_notify_queue:put(k(1), a2, 0, Q1),
          {replaced, Q3} = yuzu_gw_notify_queue:put(k(2), b2, 0, Q2),
          ?assertEqual([{k(1), a2}, {k(2), b2}, {k(3), c}], drain(Q3))
      end},
     {"a key taken and put again goes to the back",
      fun() ->
          Q1 = fill(10, [{k(1), a}, {k(2), b}]),
          {Key1, a, Q2} = yuzu_gw_notify_queue:take(Q1),
          ?assertEqual(k(1), Key1),
          {new, Q3} = yuzu_gw_notify_queue:put(k(1), a2, 0, Q2),
          ?assertEqual([{k(2), b}, {k(1), a2}], drain(Q3))
      end}
    ].

%%--------------------------------------------------------------------
%% full, with and without Reserved
%%--------------------------------------------------------------------

full_test_() ->
    [
     {"Reserved 0: the cap-th key fits and the next absent key is full",
      fun() ->
          Q1 = fill(3, [{k(1), a}, {k(2), b}]),
          {new, Q2} = yuzu_gw_notify_queue:put(k(3), c, 0, Q1),
          ?assertEqual(3, yuzu_gw_notify_queue:size(Q2)),
          ?assertMatch({full, _}, yuzu_gw_notify_queue:put(k(4), d, 0, Q2))
      end},
     {"a full put leaves the queue exactly as it was",
      fun() ->
          Q = fill(2, [{k(1), a}, {k(2), b}]),
          {full, Q2} = yuzu_gw_notify_queue:put(k(3), c, 0, Q),
          ?assertEqual(2, yuzu_gw_notify_queue:size(Q2)),
          ?assertEqual([{k(1), a}, {k(2), b}], drain(Q2))
      end},
     {"Reserved 1: one slot is held back, so the cap-th key is already full",
      fun() ->
          Q1 = fill(3, [{k(1), a}, {k(2), b}]),
          ?assertMatch({full, _}, yuzu_gw_notify_queue:put(k(3), c, 1, Q1)),
          Q0 = fill(3, [{k(1), a}]),
          ?assertMatch({new, _}, yuzu_gw_notify_queue:put(k(2), b, 1, Q0))
      end},
     {"a replace of a present key is never full and never grows, at the cap",
      fun() ->
          Q = fill(2, [{k(1), a}, {k(2), b}]),
          {replaced, Q2} = yuzu_gw_notify_queue:put(k(1), a2, 0, Q),
          ?assertEqual(2, yuzu_gw_notify_queue:size(Q2)),
          ?assertEqual([{k(1), a2}, {k(2), b}], yuzu_gw_notify_queue:to_list(Q2))
      end},
     {"a replace of a present key is never full with Reserved 1 either",
      fun() ->
          Q = fill(2, [{k(1), a}, {k(2), b}]),
          {replaced, Q2} = yuzu_gw_notify_queue:put(k(2), b2, 1, Q),
          ?assertEqual(2, yuzu_gw_notify_queue:size(Q2)),
          ?assertEqual([{k(1), a}, {k(2), b2}], yuzu_gw_notify_queue:to_list(Q2))
      end},
     {"a replace is still accepted when size plus Reserved is over the cap",
      fun() ->
          %% size 2, cap 2, Reserved 1: a probe is out and the store is full.
          Q = fill(2, [{k(1), a}, {k(2), b}]),
          ?assertMatch({replaced, _}, yuzu_gw_notify_queue:put(k(1), a2, 1, Q))
      end},
     {"after a take there is room again",
      fun() ->
          Q1 = fill(2, [{k(1), a}, {k(2), b}]),
          ?assertMatch({full, _}, yuzu_gw_notify_queue:put(k(3), c, 0, Q1)),
          {Key1, a, Q2} = yuzu_gw_notify_queue:take(Q1),
          ?assertEqual(k(1), Key1),
          ?assertMatch({new, _}, yuzu_gw_notify_queue:put(k(3), c, 0, Q2))
      end},
     {"a cap of 1 holds one key",
      fun() ->
          Q1 = fill(1, [{k(1), a}]),
          ?assertMatch({full, _}, yuzu_gw_notify_queue:put(k(2), b, 0, Q1)),
          ?assertMatch({replaced, _}, yuzu_gw_notify_queue:put(k(1), a2, 0, Q1)),
          ?assertMatch({full, _},
                       yuzu_gw_notify_queue:put(k(1), a2, 1, yuzu_gw_notify_queue:new(1)))
      end}
    ].

%%--------------------------------------------------------------------
%% push_front
%%--------------------------------------------------------------------

push_front_test_() ->
    [
     {"an absent key is inserted at the head",
      fun() ->
          Q1 = fill(5, [{k(1), a}, {k(2), b}]),
          {inserted, Q2} = yuzu_gw_notify_queue:push_front(k(3), c, Q1),
          ?assertEqual(3, yuzu_gw_notify_queue:size(Q2)),
          ?assertEqual([{k(3), c}, {k(1), a}, {k(2), b}], drain(Q2))
      end},
     {"push_front on an empty queue inserts",
      fun() ->
          Q0 = yuzu_gw_notify_queue:new(5),
          {inserted, Q1} = yuzu_gw_notify_queue:push_front(k(1), a, Q0),
          ?assertEqual([{k(1), a}], yuzu_gw_notify_queue:to_list(Q1))
      end},
     {"a present key is superseded: the held newer event stays and size is unchanged",
      fun() ->
          Q1 = fill(5, [{k(1), a}, {k(2), b}]),
          {superseded, Q2} = yuzu_gw_notify_queue:push_front(k(2), old, Q1),
          ?assertEqual(2, yuzu_gw_notify_queue:size(Q2)),
          ?assertEqual([{k(1), a}, {k(2), b}], drain(Q2))
      end},
     {"a superseded push_front does not move the held key to the head",
      fun() ->
          Q1 = fill(5, [{k(1), a}, {k(2), b}, {k(3), c}]),
          {superseded, Q2} = yuzu_gw_notify_queue:push_front(k(3), old, Q1),
          ?assertEqual([k(1), k(2), k(3)],
                       [K || {K, _} <- yuzu_gw_notify_queue:to_list(Q2)])
      end},
     {"push_front is not bounded by the cap: the reserved probe slot always fits",
      fun() ->
          %% The caller reserved one slot for the probe, so a store holding
          %% Max - 1 keys is the fullest it can be while a probe is out.
          Q1 = fill(3, [{k(1), a}, {k(2), b}]),
          {inserted, Q2} = yuzu_gw_notify_queue:push_front(k(3), c, Q1),
          ?assertEqual(3, yuzu_gw_notify_queue:size(Q2)),
          ?assertEqual([k(3), k(1), k(2)],
                       [K || {K, _} <- yuzu_gw_notify_queue:to_list(Q2)])
      end},
     {"a key put after a push_front goes behind the pushed one",
      fun() ->
          Q1 = fill(5, [{k(1), a}]),
          {inserted, Q2} = yuzu_gw_notify_queue:push_front(k(2), b, Q1),
          {new, Q3} = yuzu_gw_notify_queue:put(k(3), c, 0, Q2),
          ?assertEqual([k(2), k(1), k(3)],
                       [K || {K, _} <- yuzu_gw_notify_queue:to_list(Q3)])
      end},
     {"a put onto a pushed key replaces it in place",
      fun() ->
          Q1 = fill(5, [{k(1), a}]),
          {inserted, Q2} = yuzu_gw_notify_queue:push_front(k(2), b, Q1),
          {replaced, Q3} = yuzu_gw_notify_queue:put(k(2), b2, 0, Q2),
          ?assertEqual([{k(2), b2}, {k(1), a}], drain(Q3))
      end}
    ].

%%--------------------------------------------------------------------
%% Seeded randomized comparison against a list model
%%--------------------------------------------------------------------

random_model_test_() ->
    {timeout, 120,
     {"200 seeded random sequences agree with a plain list model after every step",
      fun() ->
          rand:seed(exsss, ?SEED),
          lists:foreach(fun run_sequence/1, lists:seq(1, ?SEQUENCES))
      end}}.

run_sequence(SeqNo) ->
    Len = rand:uniform(?MAX_LEN),
    Q0 = yuzu_gw_notify_queue:new(?RANDOM_CAP),
    run_steps(SeqNo, 1, Len, Q0, [], []).

run_steps(_SeqNo, Step, Len, _Q, _Model, _Trace) when Step > Len ->
    ok;
run_steps(SeqNo, Step, Len, Q, Model, Trace) ->
    Key = k(rand:uniform(?KEY_SPACE)),
    Event = {SeqNo, Step},
    Op = rand:uniform(4),
    Reserved = rand:uniform(2) - 1,
    Where = where(SeqNo, Step, [{Step, {op, Op}, Key, Event, Reserved} | Trace]),
    {Q2, Model2, Action} = apply_op(Op, Key, Event, Reserved, Q, Model, Where),
    Trace2 = [{Step, Action, Key, Event, Reserved} | Trace],
    check_step(SeqNo, Step, Q2, Model2, Trace2),
    run_steps(SeqNo, Step + 1, Len, Q2, Model2, Trace2).

%% put (twice as likely as the others, so the store reaches the cap)
apply_op(Op, Key, Event, Reserved, Q, Model, Where) when Op =:= 1; Op =:= 2 ->
    {Result, Q2} = yuzu_gw_notify_queue:put(Key, Event, Reserved, Q),
    Present = lists:keymember(Key, 1, Model),
    {ExpResult, Model2} =
        case Present of
            true ->
                {replaced, lists:keyreplace(Key, 1, Model, {Key, Event})};
            false when length(Model) + Reserved >= ?RANDOM_CAP ->
                {full, Model};
            false ->
                {new, Model ++ [{Key, Event}]}
        end,
    ?assertEqual({Where, {put, ExpResult}}, {Where, {put, Result}}),
    {Q2, Model2, put};
apply_op(3, _Key, _Event, _Reserved, Q, Model, Where) ->
    case {yuzu_gw_notify_queue:take(Q), Model} of
        {empty, []} ->
            {Q, Model, take_empty};
        {{K, E, Q2}, [{K, E} | Rest]} ->
            {Q2, Rest, take};
        {Got, _} ->
            erlang:error({take_mismatch, Where, Got, Model})
    end;
apply_op(4, Key, Event, _Reserved, Q, Model, Where) ->
    {Result, Q2} = yuzu_gw_notify_queue:push_front(Key, Event, Q),
    case lists:keymember(Key, 1, Model) of
        true ->
            ?assertEqual({Where, {push_front, superseded}}, {Where, {push_front, Result}}),
            {Q2, Model, push_front};
        false ->
            ?assertEqual({Where, {push_front, inserted}}, {Where, {push_front, Result}}),
            {Q2, [{Key, Event} | Model], push_front}
    end.

%% Where a failure happened: the seed, the sequence, the step, and the last five
%% operations, newest first.
where(SeqNo, Step, Trace) ->
    lists:flatten(io_lib:format(
                    "seed ~w sequence ~w step ~w (last 5 ops, newest first: ~w)",
                    [?SEED, SeqNo, Step, lists:sublist(Trace, 5)])).

check_step(SeqNo, Step, Q, Model, Trace) ->
    Where = where(SeqNo, Step, Trace),
    List = yuzu_gw_notify_queue:to_list(Q),
    Keys = [K || {K, _} <- List],
    ?assertEqual({Where, length(Model)}, {Where, yuzu_gw_notify_queue:size(Q)}),
    ?assertEqual({Where, length(lists:usort(Keys))}, {Where, length(Keys)}),
    ?assertEqual({Where, Model}, {Where, List}).
