%%%-------------------------------------------------------------------
%%% @doc Tests for yuzu_gw_mgmt_pins -- the management-pin freshness watcher
%%% (M1(b), #5696) -- and for the per-stream check that reads what it publishes.
%%%
%%% The property under test: yuzu_gw_authz:check_mgmt_peer/1 runs in a Cowboy
%%% connection process once per management stream, so it must not touch the
%%% file system. A `{cert_file, Path}' pin is re-stat'ed by the watcher on its
%%% own timer and the stream path reads the published SPKI hash. A stalled cert
%%% volume then stalls the watcher, never a connection.
%%%
%%% `file' is mocked (unstick, passthrough) to observe and to stall file
%%% operations. The mock passes every call through except the ones a case
%%% intercepts, and every fixture unloads it in cleanup.
%%% @end
%%%-------------------------------------------------------------------
-module(yuzu_gw_mgmt_pins_tests).
-include_lib("eunit/include/eunit.hrl").

-export([forward/4]).

-define(KEY, {yuzu_gw_mgmt_pins, resolved}).
-define(ENV_KEYS, [mgmt_peer_pins, mgmt_pin_refresh_ms]).
-define(WAIT_MS, 5000).
-define(HANDLER, {?MODULE, events}).
-define(EVENTS, [[yuzu, gw, mgmt_pins, rotated], [yuzu, gw, cert_file, state]]).

pins_test_() ->
    {foreach,
     fun setup/0,
     fun cleanup/1,
     [fun(F) -> {"the per-stream check does no file I/O",
                 fun() -> stream_check_does_no_file_io(F) end} end,
      fun(F) -> {"a check before anything was published fails closed, without a crash",
                 fun() -> unpublished_fails_closed(F) end} end,
      fun(F) -> {"the watcher resolves in init, before start_link returns",
                 fun() -> init_resolves_synchronously(F) end} end,
      fun(F) -> {timeout, 30, {"a stalled stat stalls only the watcher",
                 fun() -> stalled_stat_stalls_only_the_watcher(F) end}} end,
      fun(F) -> {timeout, 30, {"a rotated file is picked up within a refresh interval",
                 fun() -> rotation_picked_up_by_the_timer(F) end}} end,
      fun(F) -> {"an unchanged file is not re-read and nothing is re-published",
                 fun() -> unchanged_file_not_reread(F) end} end,
      fun(F) -> {"a resolved pin survives a failed read; the source is flagged unhealthy",
                 fun() -> failed_read_keeps_last_good_pin(F) end} end,
      fun(F) -> {"a readable file with a different key replaces the pin",
                 fun() -> replacement_swaps_the_pin(F) end} end,
      fun(F) -> {"a file unreadable from the start pins nothing (fail closed)",
                 fun() -> unreadable_at_boot_fails_closed(F) end} end,
      fun(F) -> {"a key change emits the rotation event; a same-key rewrite, the first "
                 "resolve and a recovery do not",
                 fun() -> rotation_event_only_on_key_change(F) end} end,
      fun(F) -> {"the watcher publishes certificate expiry when it starts",
                 fun() -> watcher_publishes_expiry_at_start(F) end} end,
      fun(F) -> {"a literal spki_sha256 pin needs nothing published",
                 fun() -> literal_pin_unaffected(F) end} end,
      fun(F) -> {"a malformed pin list publishes nothing and does not crash the refresh",
                 fun() -> malformed_config_publishes_nothing(F) end} end]}.

%%%-------------------------------------------------------------------
%%% Fixture
%%%-------------------------------------------------------------------

setup() ->
    {ok, _} = application:ensure_all_started(telemetry),
    stop_watcher(),
    Saved = [{K, application:get_env(yuzu_gw, K)} || K <- ?ENV_KEYS],
    PrevPublished = persistent_term:get(?KEY, undefined),
    persistent_term:erase(?KEY),
    catch meck:unload(file),
    catch telemetry:detach(?HANDLER),
    Certs = yuzu_gw_authz_tests:setup_certs(),
    #{certs => Certs, saved => Saved, prev => PrevPublished}.

cleanup(#{certs := Certs, saved := Saved, prev := Prev}) ->
    stop_watcher(),
    catch meck:unload(file),
    catch telemetry:detach(?HANDLER),
    flush_events(),
    [case V of
         {ok, Val} -> application:set_env(yuzu_gw, K, Val);
         undefined -> application:unset_env(yuzu_gw, K)
     end || {K, V} <- Saved],
    case Prev of
        undefined -> persistent_term:erase(?KEY);
        _ -> persistent_term:put(?KEY, Prev)
    end,
    yuzu_gw_authz_tests:cleanup_certs(Certs),
    ok.

%% Every case needs the minted certificates; without openssl the case is a
%% no-op here and yuzu_gw_authz_tests' canary reports the missing tool.
with_certs(#{certs := #{} = Certs}, Fun) -> Fun(Certs);
with_certs(_, _Fun) -> ok.

stop_watcher() ->
    case whereis(yuzu_gw_mgmt_pins) of
        undefined -> ok;
        Pid ->
            catch unlink(Pid),
            Mon = monitor(process, Pid),
            exit(Pid, kill),
            receive {'DOWN', Mon, process, Pid, _} -> ok after ?WAIT_MS -> error(watcher_stuck) end
    end.

%% Mock `file' so every call is still made, and recorded per caller.
mock_file() ->
    ok = meck:new(file, [unstick, passthrough, no_link]).

file_calls_from(Pid) ->
    [{F, A} || {CallerPid, {file, F, A}, _} <- meck:history(file), CallerPid =:= Pid].

srv(Certs) -> yuzu_gw_authz_tests:der(Certs, srv_pem).

%% The test's telemetry handler, attached by a case with the case's own pid as
%% the receiver (a foreach setup runs in another process) and detached in
%% cleanup. It runs in the process that emits: the case for a direct
%% refresh/1, the watcher for a tick or init/1.
listen() ->
    catch telemetry:detach(?HANDLER),
    ok = telemetry:attach_many(?HANDLER, ?EVENTS, fun ?MODULE:forward/4, self()).

forward(Event, Measurements, Meta, Pid) ->
    Pid ! {telemetry_event, Event, Measurements, Meta},
    ok.

rotations() ->
    receive {telemetry_event, [yuzu, gw, mgmt_pins, rotated], M, _} -> [M | rotations()]
    after 0 -> []
    end.

flush_events() ->
    receive {telemetry_event, _, _, _} -> flush_events()
    after 0 -> ok
    end.

%%%-------------------------------------------------------------------
%%% Cases
%%%-------------------------------------------------------------------

%% The stream path (yuzu_gw_authz:check_peer/2, which check_mgmt_peer/1 calls
%% with the configured pins) reads the published hash and makes no `file' call
%% from the calling process -- not a stat, not a read.
stream_check_does_no_file_io(F) ->
    with_certs(F, fun(#{srv_pem := SrvPem} = Certs) ->
        Pins = [{cert_file, SrvPem}],
        Der = srv(Certs),
        _ = (catch yuzu_gw_mgmt_pins:refresh(Pins)),
        mock_file(),
        [?assertEqual({true, <<"yuzu-server">>}, yuzu_gw_authz:check_peer(Der, Pins))
         || _ <- lists:seq(1, 20)],
        ?assertEqual([], file_calls_from(self()))
    end).

%% Nothing published yet (the watcher has not run): the cert_file pin resolves
%% to nothing, so the check refuses with no_pins_resolved -- it neither crashes
%% nor reads the file itself.
unpublished_fails_closed(F) ->
    with_certs(F, fun(#{srv_pem := SrvPem} = Certs) ->
        ?assertEqual(undefined, persistent_term:get(?KEY, undefined)),
        application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
        Der = srv(Certs),
        mock_file(),
        ?assertEqual(false, yuzu_gw_authz:check_peer(Der, [{cert_file, SrvPem}])),
        ?assertEqual(false, yuzu_gw_authz:check_mgmt_peer(Der)),
        ?assertEqual([], file_calls_from(self()))
    end).

%% The listeners are the supervisor's last children and the watcher comes
%% before them: it publishes in init/1, so start_link returning is the
%% guarantee the first stream finds the pin. The interval is an hour, so no
%% tick can be what published it.
init_resolves_synchronously(F) ->
    with_certs(F, fun(#{srv_pem := SrvPem} = Certs) ->
        application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
        application:set_env(yuzu_gw, mgmt_pin_refresh_ms, 3600000),
        {ok, Pid} = yuzu_gw_mgmt_pins:start_link(),
        unlink(Pid),
        ?assertEqual({true, <<"yuzu-server">>}, yuzu_gw_authz:check_mgmt_peer(srv(Certs)))
    end).

%% The watcher's stat blocks (a hung network volume). The stream checks keep
%% answering, promptly, from the last published hash, and make no file call.
stalled_stat_stalls_only_the_watcher(F) ->
    with_certs(F, fun(#{srv_pem := SrvPem} = Certs) ->
        application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
        application:set_env(yuzu_gw, mgmt_pin_refresh_ms, 100),
        {ok, Watcher} = yuzu_gw_mgmt_pins:start_link(),
        unlink(Watcher),
        Der = srv(Certs),
        Test = self(),
        mock_file(),
        ok = meck:expect(file, read_file_info,
                         fun(P, Opts) when P =:= SrvPem ->
                                 Test ! {stat_blocked, self()},
                                 receive release_stat -> ok end,
                                 meck:passthrough([P, Opts]);
                            (P, Opts) ->
                                 meck:passthrough([P, Opts])
                         end),
        Blocked = receive {stat_blocked, W} -> W after ?WAIT_MS -> error(watcher_never_stated) end,
        ?assertEqual(Watcher, Blocked),
        %% the watcher is stuck in the stat: its own mailbox and calls wait
        {current_function, {CurM, _, _}} = process_info(Watcher, current_function),
        ?assertNotEqual(gen_server, CurM),
        T0 = erlang:monotonic_time(millisecond),
        [?assertEqual({true, <<"yuzu-server">>}, yuzu_gw_authz:check_mgmt_peer(Der))
         || _ <- lists:seq(1, 200)],
        Elapsed = erlang:monotonic_time(millisecond) - T0,
        ?assert(Elapsed < 2000),
        ?assertEqual([], file_calls_from(self())),
        Watcher ! release_stat
    end).

%% The server rotates its leaf: the next tick re-reads the file and publishes
%% the new key; the old one stops being admitted. Until that tick the new leaf
%% is refused (fail closed) -- bounded here by waiting at most a few intervals.
rotation_picked_up_by_the_timer(F) ->
    with_certs(F, fun(#{dir := Dir, srv_pem := SrvPem, gw_pem := GwPem} = Certs) ->
        Rotating = filename:join(Dir, "rotating.pem"),
        {ok, _} = file:copy(SrvPem, Rotating),
        ok = file:change_time(Rotating, {{2020, 1, 1}, {0, 0, 0}}),
        application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, Rotating}]),
        application:set_env(yuzu_gw, mgmt_pin_refresh_ms, 100),
        {ok, Pid} = yuzu_gw_mgmt_pins:start_link(),
        unlink(Pid),
        GwDer = yuzu_gw_authz_tests:der(Certs, gw_pem),
        ?assertEqual({true, <<"yuzu-server">>}, yuzu_gw_authz:check_mgmt_peer(srv(Certs))),
        ?assertEqual(false, yuzu_gw_authz:check_mgmt_peer(GwDer)),
        {ok, _} = file:copy(GwPem, Rotating),
        ok = file:change_time(Rotating, {{2021, 1, 1}, {0, 0, 0}}),
        until(fun() -> yuzu_gw_authz:check_mgmt_peer(GwDer) =:= {true, <<"yuzu-server">>} end,
              rotation_not_picked_up),
        ?assertEqual(false, yuzu_gw_authz:check_mgmt_peer(srv(Certs)))
    end).

%% A refresh over an unchanged file stats it and stops there: no read, and the
%% published term is the same term (no persistent_term:put, which would make
%% the VM scan every process).
unchanged_file_not_reread(F) ->
    with_certs(F, fun(#{srv_pem := SrvPem}) ->
        Pins = [{cert_file, SrvPem}],
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        Published = persistent_term:get(?KEY),
        mock_file(),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        Calls = [Fn || {Fn, _} <- file_calls_from(self())],
        ?assert(lists:member(read_file_info, Calls)),
        ?assertNot(lists:member(read_file, Calls)),
        ?assert(persistent_term:get(?KEY) =:= Published)
    end).

%% Once a pin has resolved, a failed stat, a failed read (any errno, enoent
%% included) or a file that does not parse keeps the last key read from it: a
%% transient failure of the cert volume, or a writer caught half-way, must not
%% refuse every management stream while /readyz stays green. The source is
%% flagged unhealthy (healthy/1, and the yuzu_gw_cert_file_readable gauge) so
%% the operator is told to fix the file.
failed_read_keeps_last_good_pin(F) ->
    with_certs(F, fun(#{dir := Dir, srv_pem := SrvPem} = Certs) ->
        Path = filename:join(Dir, "going.pem"),
        {ok, _} = file:copy(SrvPem, Path),
        Pins = [{cert_file, Path}],
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        Admitted = {true, <<"yuzu-server">>},
        ?assertEqual(Admitted, yuzu_gw_authz:check_peer(srv(Certs), Pins)),
        ?assert(yuzu_gw_mgmt_pins:healthy(Path)),
        %% removed: the last good key stays pinned, the source is unhealthy
        ok = file:delete(Path),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assertMatch({ok, _}, yuzu_gw_mgmt_pins:lookup(Path)),
        ?assertEqual(Admitted, yuzu_gw_authz:check_peer(srv(Certs), Pins)),
        ?assertNot(yuzu_gw_mgmt_pins:healthy(Path)),
        %% replaced by something that is not a PEM certificate, or by a PEM
        %% cut off half-way: the same
        ok = file:write_file(Path, <<"not a certificate">>),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assertEqual(Admitted, yuzu_gw_authz:check_peer(srv(Certs), Pins)),
        ?assertNot(yuzu_gw_mgmt_pins:healthy(Path)),
        {ok, Pem} = file:read_file(SrvPem),
        ok = file:write_file(Path, binary:part(Pem, 0, byte_size(Pem) div 2)),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assertEqual(Admitted, yuzu_gw_authz:check_peer(srv(Certs), Pins)),
        ?assertNot(yuzu_gw_mgmt_pins:healthy(Path)),
        %% a read error other than enoent: the same
        ok = meck:new(file, [unstick, passthrough, no_link]),
        ok = meck:expect(file, read_file,
                         fun(P, _Opts) when P =:= Path -> {error, eio};
                            (P, Opts) -> meck:passthrough([P, Opts])
                         end),
        {ok, _} = file:copy(SrvPem, Path),
        ok = file:change_time(Path, {{2023, 1, 1}, {0, 0, 0}}),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assertEqual(Admitted, yuzu_gw_authz:check_peer(srv(Certs), Pins)),
        ?assertNot(yuzu_gw_mgmt_pins:healthy(Path)),
        ok = meck:unload(file),
        %% readable again: healthy, still admitted
        ok = file:change_time(Path, {{2022, 1, 1}, {0, 0, 0}}),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assert(yuzu_gw_mgmt_pins:healthy(Path)),
        ?assertEqual(Admitted, yuzu_gw_authz:check_peer(srv(Certs), Pins))
    end).

%% A file that is read successfully and holds a DIFFERENT key replaces the pin:
%% that is rotation, and the way to withdraw a key (deleting the file is not).
replacement_swaps_the_pin(F) ->
    with_certs(F, fun(#{dir := Dir, srv_pem := SrvPem, gw_pem := GwPem} = Certs) ->
        Path = filename:join(Dir, "swap.pem"),
        {ok, _} = file:copy(SrvPem, Path),
        Pins = [{cert_file, Path}],
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        GwDer = yuzu_gw_authz_tests:der(Certs, gw_pem),
        ?assertEqual({true, <<"yuzu-server">>}, yuzu_gw_authz:check_peer(srv(Certs), Pins)),
        %% a failure in between does not matter: the next good read wins
        ok = file:delete(Path),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        {ok, _} = file:copy(GwPem, Path),
        ok = file:change_time(Path, {{2021, 1, 1}, {0, 0, 0}}),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assert(yuzu_gw_mgmt_pins:healthy(Path)),
        ?assertEqual({true, <<"yuzu-server">>}, yuzu_gw_authz:check_peer(GwDer, Pins)),
        ?assertEqual(false, yuzu_gw_authz:check_peer(srv(Certs), Pins))
    end).

%% With no last good key there is nothing to keep: a file missing or garbage at
%% the first resolve pins nothing, exactly as before, and the check refuses.
unreadable_at_boot_fails_closed(F) ->
    with_certs(F, fun(#{dir := Dir} = Certs) ->
        Missing = filename:join(Dir, "missing.pem"),
        ok = yuzu_gw_mgmt_pins:refresh([{cert_file, Missing}]),
        ?assertEqual(error, yuzu_gw_mgmt_pins:lookup(Missing)),
        ?assertNot(yuzu_gw_mgmt_pins:healthy(Missing)),
        ?assertEqual(false, yuzu_gw_authz:check_peer(srv(Certs), [{cert_file, Missing}])),
        Garbage = filename:join(Dir, "garbage.pem"),
        ok = file:write_file(Garbage, <<"not a certificate">>),
        ok = yuzu_gw_mgmt_pins:refresh([{cert_file, Garbage}]),
        ?assertEqual(error, yuzu_gw_mgmt_pins:lookup(Garbage)),
        ?assertEqual(false, yuzu_gw_authz:check_peer(srv(Certs), [{cert_file, Garbage}]))
    end).

%% yuzu_gw_mgmt_pin_rotated_timestamp_seconds is what lets the pin_mismatch
%% alert stay quiet through a rotation. It must move ONLY when the pinned key
%% changes: not at the first resolve (boot), not on a rewrite of the same key
%% (new mtime, same SPKI), not when a source recovers with the key it had.
rotation_event_only_on_key_change(F) ->
    with_certs(F, fun(#{dir := Dir, srv_pem := SrvPem, gw_pem := GwPem}) ->
        listen(),
        Path = filename:join(Dir, "rot.pem"),
        {ok, _} = file:copy(SrvPem, Path),
        ok = file:change_time(Path, {{2020, 1, 1}, {0, 0, 0}}),
        Pins = [{cert_file, Path}],
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assertEqual([], rotations()),
        %% same key, new mtime
        ok = file:change_time(Path, {{2020, 6, 1}, {0, 0, 0}}),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assertEqual([], rotations()),
        %% lost and found again with the same key
        ok = file:delete(Path),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        {ok, _} = file:copy(SrvPem, Path),
        ok = file:change_time(Path, {{2020, 7, 1}, {0, 0, 0}}),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        ?assertEqual([], rotations()),
        %% a new key: one event, carrying the wall clock in seconds
        Before = os:system_time(second),
        {ok, _} = file:copy(GwPem, Path),
        ok = file:change_time(Path, {{2021, 1, 1}, {0, 0, 0}}),
        ok = yuzu_gw_mgmt_pins:refresh(Pins),
        After = os:system_time(second),
        [#{system_time := T}] = rotations(),
        ?assert(T >= Before andalso T =< After)
    end).

%% init/1 publishes the expiry of the configured certificate files before
%% start_link returns, through the same event the ticks use.
watcher_publishes_expiry_at_start(F) ->
    with_certs(F, fun(#{srv_pem := SrvPem}) ->
        listen(),
        application:set_env(yuzu_gw, mgmt_peer_pins, [{cert_file, SrvPem}]),
        application:set_env(yuzu_gw, mgmt_pin_refresh_ms, 3600000),
        {ok, Pid} = yuzu_gw_mgmt_pins:start_link(),
        unlink(Pid),
        Name = list_to_binary(filename:basename(SrvPem)),
        receive
            {telemetry_event, [yuzu, gw, cert_file, state], M,
             #{role := <<"mgmt_peer_pin">>, name := Name}} ->
                ?assertMatch(#{readable := 1, not_after := N} when is_integer(N), M)
        after 0 ->
            error(no_expiry_published_at_start)
        end
    end).

literal_pin_unaffected(F) ->
    with_certs(F, fun(Certs) ->
        {ok, Spki} = yuzu_gw_authz:spki_sha256(srv(Certs)),
        Pins = [{spki_sha256, binary_to_list(binary:encode_hex(Spki))}],
        Der = srv(Certs),
        mock_file(),
        ?assertEqual({true, <<"yuzu-server">>}, yuzu_gw_authz:check_peer(Der, Pins)),
        ?assertEqual([], file_calls_from(self()))
    end).

%% A configuration the boot guard would refuse (not a list, an improper list,
%% entries that are not pins) publishes nothing and does not crash the refresh.
malformed_config_publishes_nothing(F) ->
    with_certs(F, fun(#{srv_pem := SrvPem}) ->
        ok = yuzu_gw_mgmt_pins:refresh(not_a_list),
        ok = yuzu_gw_mgmt_pins:refresh([{cert_file, SrvPem} | improper]),
        ok = yuzu_gw_mgmt_pins:refresh([bogus, {cert_file, 42}]),
        ?assertEqual(error, yuzu_gw_mgmt_pins:lookup(SrvPem))
    end).

%%%-------------------------------------------------------------------
%%% The refresh interval: boot validation
%%%-------------------------------------------------------------------

refresh_interval_validation_test_() ->
    V = fun yuzu_gw_mgmt_pins:validate_refresh_ms/1,
    [?_assertEqual(ok, V(undefined)),
     ?_assertEqual(ok, V(5000)),
     ?_assertEqual(ok, V(100)),
     ?_assertEqual(ok, V(3600000)),
     ?_assertMatch({error, _}, V(99)),
     ?_assertMatch({error, _}, V(0)),
     ?_assertMatch({error, _}, V(-1)),
     ?_assertMatch({error, _}, V(3600001)),
     ?_assertMatch({error, _}, V("5000")),
     ?_assertMatch({error, _}, V(5000.0)),
     ?_assertMatch({error, _}, V(infinity))].

default_refresh_interval_test() ->
    Prev = application:get_env(yuzu_gw, mgmt_pin_refresh_ms),
    application:unset_env(yuzu_gw, mgmt_pin_refresh_ms),
    try
        ?assertEqual(5000, yuzu_gw_mgmt_pins:refresh_ms())
    after
        case Prev of
            {ok, P} -> application:set_env(yuzu_gw, mgmt_pin_refresh_ms, P);
            undefined -> ok
        end
    end.

%% The boot guard refuses an invalid interval before anything starts.
boot_guard_refuses_a_bad_interval_test() ->
    Prev = application:get_env(yuzu_gw, mgmt_pin_refresh_ms),
    try
        application:set_env(yuzu_gw, mgmt_pin_refresh_ms, 0),
        ?assertEqual({error, bad_mgmt_pin_refresh_ms}, yuzu_gw_app:check_mgmt_pin_refresh()),
        application:set_env(yuzu_gw, mgmt_pin_refresh_ms, 2000),
        ?assertEqual(ok, yuzu_gw_app:check_mgmt_pin_refresh()),
        application:unset_env(yuzu_gw, mgmt_pin_refresh_ms),
        ?assertEqual(ok, yuzu_gw_app:check_mgmt_pin_refresh())
    after
        case Prev of
            {ok, P} -> application:set_env(yuzu_gw, mgmt_pin_refresh_ms, P);
            undefined -> application:unset_env(yuzu_gw, mgmt_pin_refresh_ms)
        end
    end.

%%%-------------------------------------------------------------------

until(Pred, What) ->
    Deadline = erlang:monotonic_time(millisecond) + ?WAIT_MS,
    until(Pred, What, Deadline).

until(Pred, What, Deadline) ->
    case Pred() of
        true -> ok;
        false ->
            case erlang:monotonic_time(millisecond) >= Deadline of
                true -> error(What);
                false -> receive after 20 -> until(Pred, What, Deadline) end
            end
    end.
