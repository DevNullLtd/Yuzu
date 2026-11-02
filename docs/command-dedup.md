# Durable agent command idempotency

Routed doc for the **durable agent command idempotency** concern in `.claude/routed-concerns.md`
(HA WS-0, ADR-2002). Loaded by `cpp-safety` + `architect` on the paths that row names.

`CommandDedupStore` (`command_dedup.db`, agent SQLite) makes command replay protection survive
restart **and** replays the ORIGINAL terminal outcome on a duplicate. This is **effectively-once,
NOT exactly-once.**

The invariants below are spread across the agent Subscribe command loop and are all silently
regressible — nothing fails loudly when one is broken.

## The seven invariants

1. **Every claimed command is resolved by EXACTLY ONE** of `record_terminal` (terminal, memoised) or
   `release` (transient — queue-full only). Otherwise its claim leaks.

2. **`record_terminal` is called BEFORE the terminal wire Write.** The durable record is the source
   of truth; the send is replayable. A new terminal-write site that forgets this degrades that
   command to RUNNING-forever / outcome-lost.

3. **The `__guard__` side channel is the ONLY dispatch that bypasses the claim.** Gate on the
   literal, so dedup stays the SAFE DEFAULT for any future reserved-name command.

4. **A duplicate NEVER re-executes.** Terminal replays the stored frame; InFlight answers RUNNING
   (indeterminate).

5. **Retention is a clock-free rowid ring over TERMINAL rows ONLY.** An IN-FLIGHT row is NEVER
   evicted — evicting a live claim silently permits a re-execution. This is why the clock-guarded
   retention concern's apparatus does not apply here: no clock is read.

6. **The store opens `synchronous=FULL`** — host-failure durability, not just process-crash.

7. **Store open/write failure is a DELIBERATE fail-OPEN** (run undeduplicated) that **MUST stay
   observable** (`yuzu.dedup_degraded` heartbeat plus local counters), never silent. The server
   turns those heartbeat tags into `yuzu_fleet_agents_dedup_*` gauges (`server/core/src/dedup_fleet_tags.hpp`)
   and the `YuzuDedupStoreDegraded` alert (#3663); `tests/test_dedup_fleet_tags_lexical.py` fails if an
   emitted `yuzu.dedup_*` tag has no server row, so a new tag cannot be a write nobody reads.

Invariants 3 and 4, the claim-error leg of 7 (`count_claim_error`), and the `owns_claim` result that
gates 1's queue-full release are decided by the pure, proto-free `agents/core/src/command_dedup_decision.hpp`
(`should_claim`, `decide_after_claim`), unit-tested in `tests/unit/test_command_dedup_decision.cpp`.
`agent.cpp`'s claim block acts on its answer, and `tests/test_agent_command_dedup_wiring_lexical.py`
pins that it still calls both functions and acts on every field. A change to which commands are
claimed, or to replay / RUNNING / proceed, belongs in the header, not inline.

## Two further contracts

- `record_terminal` is **FIRST-WRITE-WINS** (in-flight → terminal only).
- **The dedup window (`kMaxDedupRows`) MUST exceed the server's max retry/outbox horizon** (WS-1 /
  WS-3).

## Related

`docs/adr/2002-high-availability-architecture.md` (WS-0), `docs/ha-delivery-matrix.md` (WS-0 row),
and `docs/user-manual/security-hardening.md` "Command Replay Protection".
