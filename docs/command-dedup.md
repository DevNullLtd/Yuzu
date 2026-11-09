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
   claimed with an atomic hard link; if the hard link fails for any reason other than the name being taken, or
   if every `-n` is taken, it fails closed instead and the file stays where it is), carries any non-empty
   `-wal`/`-shm`/`-journal` with it as `<that name>-wal` etc (empty sidecars are removed; one that cannot be
   renamed is copied, then removed), and opens a fresh store. The filesystem half lives in `agents/core/src/command_dedup_quarantine.hpp`
   (header-only, unit-tested directly). The claim protects the quarantined EVIDENCE only: two agent daemons on
   one data dir are unsupported (no instance lock covers the dedup store; the Guardian boot-epoch lock guards only the epoch claim), and one can still drop the fresh store the other
   just created. What counts is deliberately narrow:
   - `SQLITE_CORRUPT` / `SQLITE_NOTADB` from any open step (open, the `journal_mode`/`synchronous` pragmas,
     creating the two tables). Damage confined to the unused `meta` table is tolerated: the
     `schema_version` seed that touches it only logs a warning. BUSY, IOERR, FULL, CANTOPEN and PERM are NOT corruption and never quarantine (that
     would discard good history). Echo's `classify_integrity_rc` draws the same line (#7286).
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
   - The move is the shared `agents/shared/sqlite_quarantine.hpp`, also used by echo's `echo_db.cpp` (#6914). It
     never overwrites an earlier quarantine, which needs a filesystem with hard links (NTFS, ReFS, ext4, xfs, APFS
     and tmpfs all have them): without them the claim fails closed, the file is left in place and this store
     degrades observably, because there is deliberately no check-then-rename fallback. A sidecar that cannot be
     renamed is copied to its quarantine name before the original is removed, and the helper returns notes that
     the store logs.
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
  The relationship between the two constants is a compile-time check, not prose: `kMaxDedupRows` is
  `yuzu::kAgentDedupRingRows` and `kMaxOutboxRedeliveryHorizonCommands` is `static_assert`ed to at
  most half of it, both in `common/include/yuzu/command_replay_horizon.hpp`. What the horizon
  actually measures at run time is an ESTIMATE, and it is not a proof.
  The WS-3 command outbox (`command_outbox_delivery.cpp`) records the dispatch counters
  (`ExecutionTracker::current_dispatch_position`: the shared `dispatch_seq`, plus this process's own
  count of dispatches whose record write failed) and the leader epoch on a row before its first
  attempt. A redrive's elapsed estimate is the shared delta plus the unrecorded delta: the exact
  local difference when the same leadership term reads it again, and the reader's whole local count
  when a different term does. The shared and local terms are never added into one stored number,
  because they are on different scales. A redrive whose estimate reaches the horizon is
  dead-lettered `redelivery_horizon_exceeded`; a shared sequence that went backwards (a restore or a
  lost-WAL failover) is dead-lettered `redelivery_sequence_regressed`.
  **It errs both ways.** It OVER-counts (safe: a row is dead-lettered early and a scheduled fire is
  lost, audited): the sequence is fleet-wide; a per-target push (Guardian, asset-tag, sync) counts
  once per target although each agent receives one command; `__guard__` counts although it takes no
  ring slot; every redrive that re-records its own id advances it, so rows stuck in a long
  gateway-directory outage age each other; and a reader in another leadership term charges its whole
  unrecorded count, which never decays inside a process (after about 10,000 such dispatches every
  later leadership change dead-letters every waiting row until a restart). It can UNDER-count
  (unsafe: a redrive after the agent evicted the id): a record-write failure on a replica other than
  the one reading the position is not counted, and neither are the failures an EARLIER PROCESS
  LIFETIME of the same replica made after the stamp (a restart or a leadership change; a restart
  resets the count to zero and cannot make the shared sequence go backwards, so it is NOT a safe
  `redelivery_sequence_regressed` refusal); a shared sequence restored to a value still above a
  row's stamp reads as small progress; a replica acting on a stale snapshot can still send a row a
  peer has just dead-lettered, because the send precedes the fenced bookkeeping write; and a command
  dispatched before the stamp but delivered to the agent after it takes a ring slot the count never
  saw. The 2x margin absorbs the race between the check and the agent's
  claim; it is not sized for a sustained uncounted outage. The sound close, which makes the agent
  refuse an id older than its own ring, needs a wire change and is not part of this change (tracked as #7204). No test
  observes a real agent at the production ring size.

## Related

`docs/adr/2002-high-availability-architecture.md` (WS-0), `docs/ha-delivery-matrix.md` (WS-0 row),
and `docs/user-manual/security-hardening.md` "Command Replay Protection".
