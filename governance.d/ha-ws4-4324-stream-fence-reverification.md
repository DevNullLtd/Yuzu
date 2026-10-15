# #4324 once-per-session re-verification — HA WS-4 per-home stream-generation fence (task 3/3)

This slice (`feat/ha-ws4-4324-stream-fence`) closes #4324 end-to-end: it threads the
`stream_home_id` wire field (task 1, `46f1e72b6`) and the store's asymmetric tombstone predicate
(task 2, `4b248b504`) into `gateway_service_impl.cpp`'s `NotifyStreamStatus` handler, adding an
`AgentRegistry` in-memory fence resolved once, before any of the three DISCONNECTED effects run.

The issue requires this slice's review to re-verify the once-per-session property still holds —
same shape and rigor as the prior slice's note, `governance.d/ha-ws4-42b-4324-reverification.md`
— because this slice is the first to make the per-home fence LIVE rather than inert, and a
regression in the underlying once-per-session invariant would silently defeat it (the fence
compares `stream_home_id` values keyed by `(agent_id, session_id)`; if a single session_id could
ever legitimately carry two SIMULTANEOUSLY LIVE homes rather than one-at-a-time, "the current
home" would be ambiguous and the fence's asymmetric equality check would have nothing well-defined
to compare against).

## What was re-checked (against this branch's checkout)

1. **Single `CONNECTED` / `DISCONNECTED` emit site pair, still exactly one each, unchanged in
   shape by task 1's own diff.**
   `gateway/apps/yuzu_gw/src/yuzu_gw_agent.erl:144` —
   `yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr, StreamHomeId)`
   — inside the single-shot `init/1` connect path. `gateway/apps/yuzu_gw/src/yuzu_gw_agent.erl:349`
   — the `disconnected` counterpart inside `do_cleanup/1`. Grepped the whole file for
   `notify_stream_status(` calls: exactly these two sites exist (line numbers moved from the
   prior slice's `:129`/`:331` to `:144`/`:349` purely because task 1 inserted the `StreamHomeId`
   minting block and its doc comment above `init/1`'s body — no new call site was introduced, and
   the CONNECTED/DISCONNECTED discipline (one of each, in the same two functions) is byte-for-byte
   the shape the 4.2b note verified.

2. **`stream_home_id` is minted EXACTLY ONCE per process instance and never re-minted between the
   CONNECTED and DISCONNECTED it is attached to.**
   `yuzu_gw_agent.erl:99` — `StreamHomeId = string:lowercase(binary:encode_hex(
   crypto:strong_rand_bytes(16)))` — computed once in `init/1`, immediately stored on `#data{}`
   at construction (`:116`, `stream_home_id = StreamHomeId`) as an IMMUTABLE `gen_statem` process
   dictionary field (the record is never reconstructed with a different `stream_home_id` anywhere
   in the module — grepped every `#data{` construction/update site in the file). `do_cleanup/1`
   (`:322`) pattern-matches `stream_home_id = StreamHomeId` OUT of that SAME `#data{}` record — the
   value flowing into the DISCONNECTED notification at `:349` is provably the identical binary
   minted at `:99` for THIS process instance, never a fresh `crypto:strong_rand_bytes/1` call. A
   gateway-side re-home (a NEW `yuzu_gw_agent` process instance, per the re-announce mechanism in
   `gateway_service_impl.cpp`'s `ProxyRegister`) necessarily re-enters `init/1` and therefore mints
   a genuinely NEW `StreamHomeId` for the new instance — which is exactly the "new home, reused
   session id" shape #4324 fences against, not a bug in the minting discipline.

3. **Admission still funnels through the ATOMIC `take_pending/1`, unchanged by tasks 1 or 2.**
   `gateway/apps/yuzu_gw/src/yuzu_gw_registry.erl:234-235` —
   `take_pending(SessionId) -> case ets:take(?PENDING_TABLE, SessionId) of ...` — same single
   atomic ETS retrieve-and-delete BIF the 4.2b note verified, at the same lines. Neither task 1
   (wire field + Erlang producer) nor task 2 (store column + predicate, pure C++) touches this
   file. Of N concurrent `Subscribe`s presenting the same session id, exactly one still consumes
   the pending registration and spawns an agent process — the guarantee the once-per-session
   property, and therefore this fence's well-definedness, rests on.

4. **The concurrent-barrier regression test is present and GREEN on this branch.**
   `gateway/apps/yuzu_gw/test/yuzu_gw_registry_tests.erl:38-39` —
   `{"take_pending: exactly one winner under concurrent racers (PR #4299 round 6)", {timeout, 60,
   fun pending_take_concurrent_single_winner/0}}` — same lines as the 4.2b note (untouched by this
   slice). Re-ran the full `yuzu_gw_registry_tests` eunit module on this checkout
   (`rebar3 eunit --module=yuzu_gw_registry_tests`): **all 19 tests passed**, including this one,
   in 0.387s.

## Conclusion

No regression found. The once-per-session invariant (`session_id` ≡ exactly one gateway stream
placement AT A TIME) that 4.2a's tombstone fix, 4.2b's dispatch wiring, and this slice's fence all
rely on is unchanged by task 1's wire-field addition, task 2's store-layer predicate, or this
task's RPC-handler wiring — none of the three touches `yuzu_gw_agent.erl`'s CONNECTED/DISCONNECTED
emission shape or `yuzu_gw_registry.erl`'s admission path, and the `StreamHomeId` minting
discipline added by task 1 is provably once-per-process (point 2 above).

The per-home stream-generation fence itself (`#4324`) is CLOSED as of this slice: the store's
asymmetric predicate (task 2) and the RPC-handler's `stream_home_id` threading + `AgentRegistry`
in-memory fence (this task) together close the SAME-session late-DISCONNECTED gap that 4.2a's
tombstone fix alone did not (see `gateway_route_store.hpp`'s file-header SLICE #4324 section, and
`gateway_service_impl.cpp`'s `NotifyStreamStatus` DISCONNECTED-branch comment, both updated by this
slice). The forward note this slice ALSO records (in `gateway_route_store.hpp`): the equality
fence is necessary but not sufficient for a LIVE same-session re-home under real network
reordering — a stale DISCONNECTED(home1) landing BEFORE the new CONNECTED(home2) (two independent
RPCs, no ordering guarantee) still tombstones the row, and `announce_connected`'s
`ON CONFLICT DO NOTHING` fallback cannot re-arm a tombstoned row. That ordering gap is explicitly
OUT of scope for #4324 (which only had to make the fence itself correct once both notifications
have arrived) and is left for 4.3 to resolve — via `register_fresh`'s ordered epoch or an explicit
re-arm path — not silently assumed closed by this note.

See `docs/adr/2002-high-availability-architecture.md` §7 (the `#4246` item #4 bullet and the WS-4
delivery-matrix row) for the full narrative this note supports, and
`governance.d/ha-ws4-42b-4324-reverification.md` for the prior slice's equivalent check.
