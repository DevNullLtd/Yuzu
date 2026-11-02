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
   observable** (`yuzu.dedup_degraded` heartbeat plus local counters), never silent.

   **Corruption recovery (#3665).** A `command_dedup.db` that CANNOT BE OPENED because it is corrupt is
   quarantined and recreated, once, rather than leaving the agent degraded on every boot.
   `CommandDedupStore::open` moves the main file to `command_dedup.db.corrupt-<unix-epoch-seconds>[-n]`
   (never overwriting an earlier one; if every `-n` is taken it fails instead), carries any non-empty
   `-wal`/`-shm`/`-journal` with it as `<that name>-wal` etc (empty or unmovable sidecars are removed), and
   opens a fresh store. What counts is deliberately narrow:
   - `SQLITE_CORRUPT` / `SQLITE_NOTADB` from any open step (open, the `journal_mode`/`synchronous` pragmas,
     the schema step). BUSY, IOERR, FULL, CANTOPEN and PERM are NOT corruption and never quarantine (that
     would discard good history). Do not copy echo's `integrity_ok`, which treats any prepare failure as
     corrupt.
   - **There is no whole-file integrity scan, by owner ruling.** A file that opens but has a few damaged pages
     keeps serving the ids on intact pages (measured: about 99.6% with one page damaged), and only the claims
     that touch a bad page fail open, counted in `yuzu_agent_dedup_claim_errors_total`. Quarantining it would
     discard ALL history, including IN-FLIGHT claims, which invariants 4 and 5 forbid. Do not add
     `quick_check`/`integrity_check` to `open()` without re-opening that ruling.

   Limits, all deliberate:
   - **The history in the quarantined file is lost.** A command executed before the corruption and redelivered
     after it can re-execute. For a file that would not open at all that is no worse than staying degraded,
     which already permitted it.
   - **Only the newest 3 quarantined stores are kept** (owner ruling). Each holds up to a ring's worth of
     serialized responses, which can include command output, so they are not kept forever. The prune is
     count-based, not a clock cutoff, orders by the number in the name, and never removes the file the same
     open just created (a backward clock step can mis-order names). A failed remove is logged and left.
   - It is observable: an `error` log naming the reason and the quarantine path, a `warn` from the agent, the
     agent-local counter `yuzu_agent_dedup_quarantined_total`, and the `yuzu.dedup_quarantined` heartbeat tag
     (the counter value, nonzero for the lifetime of THAT agent process; it resets on restart because the
     agent has no `/metrics` endpoint). Recovery restores protection, so `yuzu.dedup_degraded` stays `0`. A
     corrupt file that cannot be moved aside fails the open instead and takes the normal degraded path
     (`yuzu_agent_dedup_open_failed_total`, `yuzu.dedup_degraded=1`).
   - The helper is a copy of echo's `quarantine_corrupt_db` (`echo_db.cpp`). Hoisting both into
     `agents/shared` is a candidate follow-up that has not been filed.

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
