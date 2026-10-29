%%%-------------------------------------------------------------------
%%% @doc The nodes of the gateway scale suite (yuzu_gw_scale_SUITE).
%%%
%%% Each scenario runs three operating-system processes besides the Common
%%% Test node, so the load generator does not share schedulers with the system
%%% it measures (the amoc/Tsung practice) and a crash is a real process death:
%%%
%%%   gateway   the yuzu_gw application, configured like sys.config.prod's
%%%             listeners (without TLS), every port chosen by the OS;
%%%   upstream  the fake server (yuzu_gw_scale_upstream);
%%%   loadgen   the simulated agents and the management client
%%%             (yuzu_gw_scale_fleet).
%%%
%%% The nodes are started with peer's `standard_io' connection and no name: they
%%% are not distributed (no epmd, no cookie, nothing shared between two CI jobs
%%% on one host, #1871) and talk to each other only over TCP, as the real
%%% components do. The Common Test node drives them with peer:call.
%%%
%%% File descriptors: an agent costs one socket in the load generator and one in
%%% the gateway. On Unix each node is started through `/bin/sh -c "ulimit -n
%%% <fds>; exec erl ..."', which raises the soft limit for that node up to the
%%% hard limit (it cannot raise the hard limit, and it does not change the
%%% limit of the shell that runs the suite). fds/1 reads back what the node got.
%%%
%%% Logs: each node's logger writes to <log_dir>/<role>-<run>.log, at level
%%% notice, instead of its standard output (which is the peer control channel).
%%%
%%% Not a test module: no *_test function, no eunit.hrl.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_scale_peer).

-export([start/2, stop/1, kill/1, call/4, call/5, fds/1, os_pid/1, alive/1]).

-define(BOOT_MS, 60000).

-type role() :: gateway | upstream | loadgen.

%% @doc Start a node. Opts: fds (soft limit wanted), log (file path),
%% args (extra erl arguments).
-spec start(role(), #{fds := pos_integer(), log := file:filename(), args => [string()]}) ->
          {ok, pid()}.
start(Role, #{fds := Fds, log := Log} = Opts) ->
    Args = ["-pa" | code:get_path()]
        ++ ["+P", "4194304", "+Q", integer_to_list(max(65536, Fds)),
            "-setcookie", random_cookie()]
        ++ maps:get(args, Opts, []),
    Base = #{connection => standard_io, args => Args, wait_boot => ?BOOT_MS,
             peer_down => continue},
    PeerOpts = case os:type() of
                   {unix, _} -> Base#{exec => ulimit_exec(Fds)};
                   _ -> Base
               end,
    Peer = case peer:start(PeerOpts) of
               {ok, P} -> P;
               {ok, P, _Node} -> P
           end,
    ok = filelib:ensure_dir(Log),
    ok = call(Peer, logger, set_primary_config, [level, notice]),
    _ = call(Peer, logger, remove_handler, [default]),
    ok = call(Peer, logger, add_handler,
              [scale_file, logger_std_h,
               #{config => #{file => Log, max_no_bytes => 50000000, max_no_files => 2},
                 level => notice,
                 formatter => {logger_formatter, #{single_line => true}}}]),
    _ = Role,
    {ok, Peer}.

%% @doc Stop the node (and the control process).
-spec stop(pid()) -> ok.
stop(Peer) ->
    catch peer:stop(Peer),
    ok.

%% @doc Kill the node's operating-system process outright: on Unix `kill -9'
%% (no terminate callback, no flush; the OS closes its sockets), elsewhere
%% erlang:halt/2 without flushing, the nearest equivalent. Returns once the
%% control connection has seen the node go.
-spec kill(pid()) -> ok.
kill(Peer) ->
    case os:type() of
        {unix, _} ->
            OsPid = os_pid(Peer),
            _ = os:cmd("kill -9 " ++ OsPid),
            ok;
        _ ->
            catch peer:cast(Peer, erlang, halt, [137, [{flush, false}]])
    end,
    wait_down(Peer, 200).

wait_down(Peer, 0) -> error({peer_still_up, Peer});
wait_down(Peer, N) ->
    case alive(Peer) of
        false -> ok;
        true -> receive after 50 -> ok end, wait_down(Peer, N - 1)
    end.

-spec alive(pid()) -> boolean().
alive(Peer) ->
    case catch peer:get_state(Peer) of
        running -> true;
        booting -> true;
        _ -> false
    end.

-spec os_pid(pid()) -> string().
os_pid(Peer) ->
    call(Peer, os, getpid, []).

%% @doc The file descriptor limit the node runs with (the poll set size).
-spec fds(pid()) -> non_neg_integer() | unknown.
fds(Peer) ->
    Info = call(Peer, erlang, system_info, [check_io]),
    Max = [M || {max_fds, M} <- lists:flatten([Info])],
    case Max of
        [M | _] -> M;
        [] -> unknown
    end.

-spec call(pid(), module(), atom(), list()) -> term().
call(Peer, M, F, A) ->
    call(Peer, M, F, A, 30000).

-spec call(pid(), module(), atom(), list(), timeout()) -> term().
call(Peer, M, F, A, Timeout) ->
    peer:call(Peer, M, F, A, Timeout).

%%--------------------------------------------------------------------
%% Internal
%%--------------------------------------------------------------------

%% sh -c 'script' ERL ARGS...: the script sees ERL as $0 and the erl arguments as
%% "$@", so nothing is re-quoted. A soft limit above the hard limit is refused by
%% ulimit; the second ulimit then takes the hard limit itself.
ulimit_exec(Fds) ->
    Erl = erl_executable(),
    Script = "ulimit -n " ++ integer_to_list(Fds) ++ " 2>/dev/null || "
             "ulimit -n \"$(ulimit -Hn)\" 2>/dev/null; exec \"$0\" \"$@\"",
    {"/bin/sh", ["-c", Script, Erl]}.

erl_executable() ->
    Candidate = filename:join([code:root_dir(), "bin", "erl"]),
    case filelib:is_regular(Candidate) of
        true -> Candidate;
        false -> os:find_executable("erl")
    end.

%% The nodes are not distributed; the cookie is set only so no node ever reads or
%% writes ~/.erlang.cookie.
random_cookie() ->
    "scale_" ++ integer_to_list(erlang:unique_integer([positive])) ++ "_"
        ++ integer_to_list(rand:uniform(1 bsl 60)).
