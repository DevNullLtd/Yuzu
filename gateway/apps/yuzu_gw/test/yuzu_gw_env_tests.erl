%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_env:env_int/4, the bounded-integer env read shared
%%% by yuzu_gw_upstream and yuzu_gw_heartbeat_buffer, and of
%%% yuzu_gw_env:env_bool/2. The callers' own tests (registration replay,
%%% heartbeat verdict, upstream channel) pin that each of them uses it for its
%%% keys; this pins the helpers' contract and their exact warning text.
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

env_bool_test_() ->
    {foreach,
     fun() -> application:unset_env(yuzu_gw, ?KEY) end,
     fun(_) ->
         application:unset_env(yuzu_gw, ?KEY),
         catch logger:remove_handler(?HANDLER)
     end,
     [
      {"an unset key gives the default, silently",
       fun() ->
           ?assertEqual({true, []}, read_bool(unset, true)),
           ?assertEqual({false, []}, read_bool(unset, false))
       end},
      {"true and false are kept whatever the default, silently",
       fun() ->
           ?assertEqual({true, []}, read_bool(true, false)),
           ?assertEqual({false, []}, read_bool(false, true))
       end},
      {"anything else gives the default and one warning",
       fun() ->
           [begin
                {Value, Lines} = read_bool(Bad, true),
                ?assertEqual(true, Value),
                ?assertMatch([_], Lines)
            end || Bad <- [1, 0, "true", <<"true">>, yes, undefined, [true]]]
       end},
      {"the warning names the key and the default, byte for byte",
       fun() ->
           {false, [Line]} = read_bool(yes, false),
           ?assertEqual(<<"Invalid yuzu_gw_env_test_key value yes (expected true or false); "
                          "using false">>, Line)
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

%% As read/1, for env_bool(?KEY, Default).
read_bool(V, Default) ->
    case V of
        unset -> application:unset_env(yuzu_gw, ?KEY);
        _     -> application:set_env(yuzu_gw, ?KEY, V)
    end,
    catch logger:remove_handler(?HANDLER),
    flush(),
    ok = logger:add_handler(?HANDLER, ?MODULE, #{config => #{pid => self()}, level => all}),
    Value = yuzu_gw_env:env_bool(?KEY, Default),
    ok = logger:remove_handler(?HANDLER),
    {Value, [unicode:characters_to_binary(logger_formatter:format(E, #{template => [msg]}))
             || E <- drain(), maps:get(level, E) =:= warning]}.
