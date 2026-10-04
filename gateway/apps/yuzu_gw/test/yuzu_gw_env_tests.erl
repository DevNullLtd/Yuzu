%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_env:env_int/4, the bounded-integer env read shared
%%% by yuzu_gw_upstream and yuzu_gw_heartbeat_buffer. The callers' own tests
%%% (registration replay, heartbeat verdict) pin that each of them uses it for
%%% its keys; this pins the helper's contract and its exact warning text.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_env_tests).
-include_lib("eunit/include/eunit.hrl").

-export([log/2]).  %% logger handler

-define(KEY, yuzu_gw_env_test_key).
-define(HANDLER, yuzu_env_test_log).

env_int_test_() ->
    {foreach,
     fun() -> application:unset_env(yuzu_gw, ?KEY) end,
     fun(_) ->
         application:unset_env(yuzu_gw, ?KEY),
         catch logger:remove_handler(?HANDLER)
     end,
     [
      {"an unset key gives the default, silently",
       fun() -> ?assertEqual({15, []}, read(unset)) end},
      {"a value inside the range is kept, silently",
       fun() -> ?assertEqual({12, []}, read(12)) end},
      {"both ends of the range are valid",
       fun() ->
           ?assertEqual({10, []}, read(10)),
           ?assertEqual({20, []}, read(20))
       end},
      {"a value outside the range or not an integer gives the default and one warning",
       fun() ->
           [begin
                {Value, Lines} = read(Bad),
                ?assertEqual(15, Value),
                ?assertMatch([_], Lines)
            end || Bad <- [9, 21, -1, 12.0, <<"12">>, twelve, [12]]]
       end},
      {"the warning names the key and the range, byte for byte",
       fun() ->
           {15, [Line]} = read(21),
           ?assertEqual(<<"Invalid yuzu_gw_env_test_key value 21 (expected an integer in "
                          "10..20); using 15">>, Line)
       end}
     ]}.

%% The value of env_int(?KEY, 15, 10, 20) with the key set to V (or unset) and
%% the warnings it logged, as text. Logger handlers run in the logging process,
%% which is this one, so the lines are in the mailbox when the call returns.
read(V) ->
    case V of
        unset -> application:unset_env(yuzu_gw, ?KEY);
        _     -> application:set_env(yuzu_gw, ?KEY, V)
    end,
    catch logger:remove_handler(?HANDLER),
    flush(),
    ok = logger:add_handler(?HANDLER, ?MODULE, #{config => #{pid => self()}, level => all}),
    Value = yuzu_gw_env:env_int(?KEY, 15, 10, 20),
    ok = logger:remove_handler(?HANDLER),
    {Value, [unicode:characters_to_binary(logger_formatter:format(E, #{template => [msg]}))
             || E <- drain(), maps:get(level, E) =:= warning]}.

log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {captured, Event},
    ok.

drain() ->
    receive {captured, E} -> [E | drain()] after 0 -> [] end.

flush() -> _ = drain(), ok.
