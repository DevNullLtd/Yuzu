# #4324 once-per-session re-verification — HA WS-4 slice 4.2b

Fable's 4.2a review made this a precondition of landing Task C (the directory becomes
dispatch-authoritative): before wiring `GatewayRouteStore::lookup_routes` into confined dispatch,
re-verify that `session_id` still identifies exactly one gateway stream placement — the invariant
`docs/adr/2002-high-availability-architecture.md` §7 already established for 4.2a and that 4.2a's own
tombstone fix depends on (see the ADR's `#4246` item #4 bullet). This note records that
re-verification for 4.2b, done against this branch's checkout (`feat/ha-ws4-42b-dispatch-authoritative`)
before Task C's commit.

## What was re-checked

1. **Single `CONNECTED` emit site, still exactly one.**
   `gateway/apps/yuzu_gw/src/yuzu_gw_agent.erl:129` —
   `yuzu_gw_upstream:notify_stream_status(AgentId, SessionId, connected, PeerAddr)` — inside a
   single-shot `init`/connect path. Grepped the whole file for `notify_stream_status(` calls: the only
   other call site is `:331`, inside `do_cleanup`, which passes `disconnected`, never `connected`. No
   second `CONNECTED` producer exists anywhere in the module.

2. **Admission still funnels through the ATOMIC `take_pending/1`.**
   `gateway/apps/yuzu_gw/src/yuzu_gw_registry.erl:234-236` —
   `take_pending(SessionId) -> case ets:take(?PENDING_TABLE, SessionId) of ...` — a single atomic
   ETS retrieve-and-delete BIF, unchanged by the merged 4.2a work (PR #4299). Of N concurrent
   `Subscribe`s presenting the same session id, exactly one consumes the pending registration and
   spawns an agent process (the guarantee the once-per-session property rests on).

3. **The concurrent-barrier regression test is present and passes.**
   `gateway/apps/yuzu_gw/test/yuzu_gw_registry_tests.erl:38-39` —
   `{"take_pending: exactly one winner under concurrent racers (PR #4299 round 6)", {timeout, 60, fun
   pending_take_concurrent_single_winner/0}}` — a two-phase barrier releasing many racers
   simultaneously, asserting exactly one winner per round. Empirically reproduces RED against the old
   non-atomic lookup-then-delete (per the test's own comment), GREEN against `ets:take/2`.

## Conclusion

No regression found. The once-per-session invariant (`session_id` ≡ exactly one gateway stream
placement) that 4.2a's tombstone fix and this ADR section already rely on is unchanged by anything in
4.2a or 4.2b Tasks A–D — none of those tasks touch `yuzu_gw_agent.erl`'s `CONNECTED` emission or
`yuzu_gw_registry.erl`'s admission path. Task C (dispatch-wiring) was cleared to land on this basis.
The per-home stream-generation fence itself (`#4324`, re-scoped from `#4246` item #4) remains
deferred — this note only covers the re-verification Fable required before Task C, not a closure of
the tracking issue.

See `docs/adr/2002-high-availability-architecture.md` §7 (the `#4246` item #4 bullet and the 4.2b
status paragraph) for the full narrative this note supports.
