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
   and a sample alert for the open-failure case, `YuzuDedupStoreDegraded` (#3663); its coverage limits (a store that
   opened and later failed writes, agents offline or slow past 90 s, per-replica counts) are listed in
   `docs/user-manual/security-hardening.md` "Fleet monitoring of the dedup store".
   `tests/test_dedup_fleet_tags_lexical.py` fails if an emitted `yuzu.dedup_*` tag has no server row OR a named,
   tracked exemption, so a new tag cannot quietly become a write nobody reads; the one current exemption is
   `yuzu.dedup_quarantined` (#6933).

   **Corruption recovery (#3665).** A `command_dedup.db` that CANNOT BE OPENED because it is corrupt is
   quarantined and recreated, once, rather than leaving the agent degraded on every boot.
   `CommandDedupStore::open` moves the main file to `command_dedup.db.corrupt-<unix-epoch-seconds>[-n]`
   (never overwriting an earlier one, even against a second process recovering in the same second: the name is
   claimed with an atomic hard link; if the hard link fails for any reason other than the name being taken, it
   falls back to check-then-rename, for which that guarantee does not hold; if every `-n` is taken it fails
   instead), carries any non-empty
   `-wal`/`-shm`/`-journal` with it as `<that name>-wal` etc (empty or unmovable sidecars are removed, best
   effort), and opens a fresh store. The filesystem half lives in `agents/core/src/command_dedup_quarantine.hpp`
   (header-only, unit-tested directly). The claim protects the quarantined EVIDENCE only: two agent daemons on
   one data dir are unsupported (there is no instance lock), and one can still drop the fresh store the other
   just created. What counts is deliberately narrow:
   - `SQLITE_CORRUPT` / `SQLITE_NOTADB` from any open step (open, the `journal_mode`/`synchronous` pragmas,
     creating the two tables). Damage confined to the unused `meta` table is tolerated: the
     `schema_version` seed that touches it only logs a warning. BUSY, IOERR, FULL, CANTOPEN and PERM are NOT corruption and never quarantine (that
     would discard good history). Do not copy echo's `integrity_ok`, which treats any prepare failure as
     corrupt.
   - **There is no whole-file integrity scan, by owner ruling.** A file that opens but has a few damaged pages
     keeps serving the ids on intact pages (in one experiment with a single damaged leaf page nearly every id
     still resolved; damage to an interior or root page costs many more), and only the claims that touch a bad
     page fail open, counted in `yuzu_agent_dedup_claim_errors_total`. Quarantining it would
     discard ALL history, including IN-FLIGHT claims, which invariants 4 and 5 forbid. Do not add
     `quick_check`/`integrity_check` to `open()` without re-opening that ruling.

   Limits, all deliberate:
   - **The history in the quarantined file is lost.** A command executed before the corruption and redelivered
     after it can re-execute. For a file that would not open at all that is no worse than staying degraded,
     which already permitted it.
   - **Only the newest 3 quarantined stores are kept** (owner ruling). Each holds up to a ring's worth of
     serialized terminal responses (status, exit code, short error text; not streamed output), so they are
     treated as sensitive as a precaution and are not kept forever. The prune is
     count-based, not a clock cutoff, orders by the number in the name, and never removes the file the same
     open just created (a clock step can mis-order names: a backward step can make the newest file sort
     oldest, and an endpoint whose clock was once set far into the future leaves a name that sorts as newest
     and keeps one of the 3 slots). It runs at the end of every recovery, including the one that creates the
     newest file, whether or not the fresh store then opened. It never throws, and a failed remove is logged
     and retried at the next recovery. It only ever touches names of the exact form
     `command_dedup.db.corrupt-<digits>[-<digits>][-wal|-shm|-journal]`.
   - It is observable: an `error` log naming the reason and the quarantine path, a `warn` from the agent, the
     agent-local counter `yuzu_agent_dedup_quarantined_total`, and the `yuzu.dedup_quarantined` heartbeat tag
     (the counter value, nonzero for the lifetime of THAT agent process; it resets on restart because the
     agent has no `/metrics` endpoint). Recovery restores protection, so `yuzu.dedup_degraded` stays `0`. A
     corrupt file that cannot be moved aside fails the open instead and takes the normal degraded path
     (`yuzu_agent_dedup_open_failed_total`, `yuzu.dedup_degraded=1`). So does a fresh store that cannot be
     created after a successful quarantine: the history is then lost AND the agent is degraded, the error names
     the quarantined file, and `yuzu_agent_dedup_quarantined_total` is NOT incremented (the store side of that branch is
     tested; the agent.cpp counter non-increment is not; see `docs/test-coverage.md`).
   - **The fleet signal does not survive a restart.** The heartbeat tag is a per-process counter, so one agent
     restart returns it to 0 while up to 3 quarantined files remain on the endpoint. A durable marker (derived
     from the `.corrupt-*` files, or a row in the fresh store) is to be designed WITH its server consumer, tracked in
     #6933. The first server consumer of the `yuzu.dedup_*` tags (#3663) deliberately does not read this tag: the
     owner shipped it without the marker, so the enterprise-architect ruling on #6912 ("consumer and durable marker
     ship together"; recorded in `governance.d/3665-dedup-corrupt-db-recovery.yrFs4G.jsonl`) is deferred, not
     satisfied, until #6933 lands.
   - The helper is a copy of echo's `quarantine_corrupt_db` (`echo_db.cpp`). Hoisting both into
     `agents/shared` is tracked in #6914. Echo does not yet have this code's
     no-overwrite claim or negative-epoch clamp.
   - Tracked follow-ups: a Windows rename retry and a Windows test leg for the hard-link claim (#6913); moving the
     sidecars before the main file so a crash cannot lose the newest WAL (#6915).

Invariants 3 and 4, the claim-error leg of 7 (`count_claim_error`), and the `owns_claim` result that
gates 1's queue-full release are decided by the pure, proto-free `agents/core/src/command_dedup_decision.hpp`
(`should_claim`, `decide_after_claim`), unit-tested in `tests/unit/test_command_dedup_decision.cpp`.
`agent.cpp`'s claim block acts on its answer, and `tests/test_agent_command_dedup_wiring_lexical.py`
pins that it still calls both functions and acts on every field. A change to which commands are
claimed, or to replay / RUNNING / proceed, belongs in the header, not inline.

## Two further contracts

- `record_terminal` is **FIRST-WRITE-WINS** (in-flight → terminal only).
- **The dedup window (`kMaxDedupRows`) MUST exceed the server's outbox redelivery horizon** (#3678).
  This is a compile-time check, not prose: `kMaxDedupRows` is `yuzu::kAgentDedupRingRows` and
  `kMaxOutboxRedeliveryHorizonCommands` is `static_assert`ed to at most half of it, both in
  `common/include/yuzu/command_replay_horizon.hpp`. The WS-3 command outbox
  (`command_outbox_delivery.cpp`) enforces the horizon by stamping the dispatch sequence
  (`ExecutionTracker::current_dispatch_seq`) on a row before its first attempt and dead-lettering any
  redrive once the sequence has advanced by the horizon (`redelivery_horizon_exceeded`).
  **What the bound is, honestly.** Every ring-consuming send is one dispatch call, so a count of
  dispatch calls estimates how many newer commands an agent has seen. It is an estimate, not a
  proof, and it errs both ways. It OVER-counts (safe: a row is dead-lettered early and a scheduled
  fire is lost, audited): the sequence is fleet-wide, a per-target push (Guardian, asset-tag, sync)
  counts once per target although each agent receives one command, and `__guard__` counts although
  it takes no ring slot. It can UNDER-count (unsafe: a redrive after the agent evicted the id): a
  dispatch whose record write failed is added back from this process's own count, but a failure on a
  replica other than the one reading the sequence is not counted, so a sustained record-write outage
  elsewhere can let the horizon trip late. The 2x margin absorbs the race between the check and the
  agent's claim; it is not sized for a sustained uncounted outage. Closing that needs the agent to
  refuse an id older than its own ring (a wire change, tracked separately). No test observes a real
  agent at the production ring size.

## Related

`docs/adr/2002-high-availability-architecture.md` (WS-0), `docs/ha-delivery-matrix.md` (WS-0 row),
and `docs/user-manual/security-hardening.md` "Command Replay Protection".
