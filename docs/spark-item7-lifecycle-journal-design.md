# Item 7 - Durable lifecycle-audit journal (PR-1b design, rev 4.1 - implementation contract)

> **Committed as historical record (2026-08-10), not maintained against the code.**
> This is the pre-implementation design contract that PR-Ag (and the follow-on
> hardening rounds — #2283, #2297, #2345, #2388, #2468, #2469, #2573) built against;
> it stayed untracked while the feature was live in the codebase, which is itself
> the defect this commit fixes (a source-header citation into a file nobody could
> read). It is committed as-is for review lineage and is NOT updated for drift —
> several counter names and one eviction bucket changed during implementation (for
> example `evicted_without_send_evidence` shipped as `evicted_no_send_evidence`, and
> a third `evicted_unclassified` bucket was added later). **For the guarantee and
> loss-channel contract as shipped, see `docs/yuzu-guardian-design-v1.1.md` §25** —
> that section is the maintained source of truth; this doc is the design history
> behind it.

Status: **implementation contract**, converged after Sol (opine ×2) + two Fable passes, every finding
adjudicated against code. **rev 4.1** (2026-07-19) folds a build-plan review round (fresh Sol opine + Fable
advisory) - see the "rev-4.1 - implementation refinements" section below; it OVERRIDES conflicting rev-4 text
but reopens none of the guarantee/model. Scope **Option A** (Dave, 2026-07-18): honest **process-crash-durable,
duplicate-tolerant, bounded-retry** lifecycle journal; true end-to-end at-least-once (server batch-ack +
sub-second/boot-session ordering) DEFERRED to a named follow-up.

**Delivered as TWO PRs (Sol Decision 2):**
- **PR-Sv (server contract, lands FIRST, LIVE/non-inert):** a new `insert_event_classified` is four-way
  `Inserted/Redelivered/Conflict/Error`; DEX observers run only on `Inserted`; redelivery is quiet; the
  CC7.3 drop metric keeps meaning genuine loss/collision. Own security-guardian + DEX review.
- **PR-Ag (agent journal + retention, depends on PR-Sv, `prefer_spark`-gated INERT):** everything else here.
  Retention stays WITH the journal (Sol Decision 1 - it is part of the guarantee).

Cites are against branch `feat/spark-rung7-7b-pr1b` (off `origin/dev`).

Review lineage: rev-1 (Sol: not audit-grade w/o ack) → rev-2 journal-primary (Fable-1: watermark silent-loss
BLOCKER + 5 MAJORs) → rev-3 drop watermark (Fable-2: converged w/ 4 fold-ins) → **rev-4** (Sol-2: 4 more
BLOCKERs both Fable passes missed - server-age-gate false premise, residual staging phantom, lexical-nonce
cursor tail-miss, nonexistent heartbeat hook - all folded here). Architecture (no watermark, journal-primary,
re-send-all, LIVE server split) is **triple-confirmed**.

---

## rev-4.1 - implementation refinements (Sol opine + Fable advisory, 2026-07-19; all verified against dev)
These OVERRIDE the corresponding rev-4 text where they conflict; the guarantee, the journal-primary /
re-send-all / no-cursor model, and the loss-channel contract are unchanged.

1. **Storage home = engine, not runtime (overrides the "reserved at runtime construction" implication in §4).**
   A new `GuardianLifecycleJournal` component is OWNED by `GuardianEngine` and holds KV access, the paging
   mutex, the token bucket, retention, and batch provenance. The RUNTIME keeps ONLY staging (`pending_journal_`
   - DISARM must stage inside `detach_rule_locked`) behind a narrow API: `snapshot_pending()`,
   `erase_persisted_prefix(n)`, `try_page_batch(entries)` (headroom + window-scan membership + enqueue under
   `outbox_mu_`). RATIONALE: the runtime is the object deliberately built to survive the agent via detached
   SparkEngine handlers (`guardian_spark_runtime.hpp:8-15,165-170` - "own everything you touch, borrow
   nothing"); a borrowed `KvStore` there is a dormant UAF. The engine already borrows `kv_` with a proven
   member-destruction-order guarantee. CONSEQUENCE: the WRITE lock chain LOSES its `outbox_mu_ → KvStore.mu_`
   nesting - the engine snapshots pending via the runtime API, releases the runtime lock, then does I/O holding
   no runtime lock. Strictly simpler than §4's chain, and it matches §4's own "the flush is engine-side" wording.

2. **New loss channel - skewed-clock reject (adds a row to §2).** A lifecycle event whose normalized timestamp
   floors to `seconds <= 0` (pre-epoch / hostile clock) is stamped with SERVER RECEIPT-NOW by `ts_to_iso8601`
   (`guardian_ingest.cpp:34-40`), so the original insert and every replay carry DIFFERENT timestamps → the
   PR-Sv 13-field compare mismatches → loud Conflict + forgery WARN + CC7.3 drop on EVERY reconnect until
   retention. Mint-time fix: field validation REFUSES to journal (and counts `journal_clock_rejected`) any
   record with normalized `seconds <= 0`. Only behavioural addition to the loss contract.

3. **Batch provenance is a required mechanism (not optional).** The window `OutboxEntry` carries no batch key or
   last-entry marker, so without an explicit event→batch association the sent-label (`sent:<nonce>:<seq>`) can
   never be set and `journal_evicted_sent_unacked` is dead-zero while `journal_evicted_without_send_evidence`
   fires on DELIVERED evictions - a permanently-false alert channel. Mechanism (build in C2): a journal-owned
   `event_id → (batch_key, is_last_in_batch)` provenance map, published by a successful persist under
   `outbox_mu_` exclusion, consumed by the drain's post-send label write. Delivery correctness does NOT depend
   on it (membership is window-scan by event_id; eviction orders on `(ts_ms,key)`); ALERT-contract correctness
   does.

4. **event_id minted ONCE, shared window↔record.** `enqueue_lifecycle_locked`
   (`guardian_spark_runtime.cpp:439-455`) mints the id inline today; refactor to build-then-enqueue so the
   window `OutboxEntry` and the `JournalRecord` carry the SAME id. Freeze all replay fields at this mint (esp.
   `enqueued_ns`) - the journal replays the ORIGINAL serialized field set, never re-stamped/re-measured at drain.

5. **`journal_stage_failures` redefined.** Under a reserved-once vector + drop-oldest, `push_back` cannot fail,
   so §4's "reserve exhausted" trigger is DEAD. The reachable trigger is record-CONSTRUCTION failure
   (`make_shared<JournalRecord>` + string copies can throw `bad_alloc`), which for DISARM happens AFTER teardown
   - the genuine "disarm-stage-fail-after-teardown" gap. Keep the counter; this is its meaning. Sustained
   disk-full drop stays `journal_stage_dropped`.

6. **Maintenance tick is two-phase (resolves the §4/§5/Q5 internal inconsistency).** §4 says the tick is "under
   mtx_ ... runs the loader"; §5 says PAGE never takes `mtx_`. Only a split satisfies both: **phase 1** under
   engine `mtx_` - check `prefer_spark_`/`stopped_`, capture a `shared_ptr` to the runtime, bounded
   retry-persist; **phase 2** off `mtx_` - page + prune. Phase 2 runs on the heartbeat thread, so the token
   bucket MUST bound the pass (batches-considered, not just batches-enqueued) or a slow KvStore delays heartbeats.

7. **Stop-race gate - ONE engine-side atomic.** Because phase 2 / the reconnect hook page off `mtx_`, they can
   run AFTER `stop()` joins the drain worker. No data loss (a late page touches only the RAM window, discarded
   at exit; the waker is safe-after-stop), but wasteful. Guard: an engine-side `stopping_` atomic SET at the top
   of `GuardianEngine::stop()` BEFORE the drain-join, checked between paged batches. Do NOT also thread the
   runtime's `registry_mu_`-guarded state into the page path (single flag, clear ordering). Interacts cleanly
   with the existing sticky `stopped_`.

8. **Token bucket - steady-state, not just spike-smoothing.** Sent-labels never gate re-paging + membership is
   window-scan only ⇒ a sent-and-popped entry RE-PAGES on the NEXT maintenance tick on a STABLE connection and
   re-sends until retention evicts it (7 days). So the bucket REFILL RATE *is* the per-agent steady-state
   redelivery bandwidth, and each redelivery costs the server a BEGIN + failed INSERT + 13-field compare under
   its EXCLUSIVE lock. C5 ships explicit refill/burst numbers with the fleet math (refill × fleet × cap) and
   charges tokens ONLY for batches that contribute NET-NEW records (else the already-windowed head starves the
   stable-connection tail). This is why the deferred server ack + the compare-off-write-path follow-up should
   land AROUND the prefer_spark flip, not be parked.

9. **Substrate hardening.** The fallible scan checks the TERMINAL `sqlite3_step()` rc (not just prepare) - a
   mid-scan error yields partial results indistinguishable from end-of-rows in the raw `list()`. New primitives
   (insert-if-absent, batch-delete) use `RETURNING`, never `sqlite3_changes()` after step on the shared
   connection (#1033). The `PRAGMA synchronous` check is a boot-time SOFT warn+count on `!= FULL`, NEVER a hard
   abort (config drift must not kill an agent).

**Build order (7 commits, all prefer_spark-gated inert):** (1) substrate; (2) staging + persistence
[engine-owned journal component]; (3) retry + shutdown [two-phase tick]; (4) retention + quarantine; (5) replay
core [+ token bucket, boot-prune barrier]; (6) replay activation [hooks]; (7) observability. Server carry-ins
split OUT of PR-Ag into two separate PRs: ingest-duration histogram (lands first), and compare-off-write-path
(its own live storage-locking review, scheduled around the flip).

---

## 1. Problem (verified)
`GuardianLifecycleLog` (`guardian_outbox.hpp:314-377`) is in-memory, reject-new-on-full, never-evict
(`:322-329`); lifecycle events (`guard.armed`/`guard.disarmed`/`guard.errored` - the last gained its
first producer in #2818, see §Scope) pop on gRPC `Write()==true` (`guardian_spark_runtime.cpp:496-501`,
`agent.cpp:2733`). No per-event ack
(`ClientReaderWriter<CommandResponse,CommandRequest>` `agent.cpp:149`). Losses: at-most-once (pop on buffered
`Write`), capacity-lossy (ignored `false`), crash-lossy (RAM only). → **bounded-durable-retry** (§2).

---

## 2. Guarantee (honest)

> **Process-crash-durable, duplicate-tolerant, bounded-retry** of **armed/disarmed/errored** lifecycle
> events (the replay-validation allowlist that gates this guarantee was fixed in #2818/PR-2d to
> recognize "errored" too - before that fix an errored record would have been quarantined as tampered
> on any restart, not durably delivered). Once
> **persisted**, an event survives a process crash/restart and is **re-sent on every reconnect/restart -
> regardless of any possible prior acceptance (acceptance is unknowable, there is no ack) - until it ages out
> of retention.** A local `Write()` is **never** delivery confirmation. **Retention eviction and quarantine
> are the only deletion paths**; every removal is counted.

Backing: WAL + effective `synchronous=FULL` (no `PRAGMA synchronous`; vcpkg port overrides neither default -
Fable-verified; **implementation MUST confirm `PRAGMA synchronous;` on the built binary**) → committed batches
are power-loss durable and each `set()` is a real fsync (⇒ one `set()` per push-batch is load-bearing). Server
dedups by `event_id` PK (`guaranteed_state_store.cpp:218-219`, rollback-before-projection `:664-728`);
lifecycle `event_id`s are boot-nonce'd (`guardian_spark_runtime.cpp:435`) and preserved verbatim on replay.

**Loss / removal channels - the integrity contract (each counted):**
| channel | when | counter | severity |
|---|---|---|---|
| pre-persist crash | staged in RAM, boundary not yet run, process dies | (window-only residual, §4) | accepted |
| stage-drop | `pending_journal_` cap hit under persistent KV-write failure (disk-full) | `journal_stage_dropped` | integrity gap, alert |
| disarm-stage-fail-after-teardown | disarm record could not be staged though the rule was already torn down | `journal_stage_failures` | integrity gap, alert |
| eviction, no durable send evidence | aged out, no sent-label present (best-effort - a live entry may send before its batch key exists) | `journal_evicted_without_send_evidence` | integrity gap, alert |
| eviction, sent-unacked | aged out, sent-label present, never server-confirmed | `journal_evicted_sent_unacked` | monitor |
| quarantine | corrupt/unparseable value removed from replay | `journal_quarantined` | integrity gap, alert |
| quarantine-rename-fail | could not even quarantine a corrupt batch | `journal_quarantine_failures` | integrity gap, alert |
| field rejection | NUL/oversized field kept an entry out of the journal | `journal_field_rejected` | integrity gap, alert |
| skewed-clock reject | normalized event ts floors to `seconds<=0` → would replay as server-receipt-now → false Conflict (rev-4.1 #2) | `journal_clock_rejected` | integrity gap, alert |
| key-collision overwrite | boot-nonce+seq collision upserted over a batch (~2^-64) | `journal_key_collisions` | integrity gap, alert |

All fleet counters are **unlabeled or low-cardinality - never keyed by raw `agent_id`** (Sol: unbounded
Prometheus cardinality). **Not claimed:** end-to-end at-least-once; deterministic sub-second ordering (server
truncates to seconds, `guardian_ingest.cpp:91`). Those + the ack are deferred (§Deferred).

---

## 3. Substrate & layout - `kv_store.db`
API `set/get/del/exists/list(plugin,prefix)/clear` (`kv_store.hpp:47-63`), PK `(plugin,key)`, WAL, 5000 ms
busy timeout (`kv_store.cpp:100`), `get()` NUL-truncates (`:178-179`), `list()` fail-open (empty on error AND
no-rows, `:253-256`), `set()` is upsert (`:131-135`).
- Values are **JSON, NUL-free** (fields validated NUL-free + size-capped; failures → `journal_field_rejected`).
- **One `set()` per push-batch** (each set = one fsync).
- **NEW journal helpers (extend `KvStore` or a journal-local wrapper) - Sol BLOCKER 3:** a **fallible page-read
  returning `expected`** that distinguishes empty / missing / DB-error (the raw `list()`/`get()` cannot - a
  silent read error currently looks like "empty journal"). Key collision is ~2^-64 with a random nonce; an
  insert-if-absent op is optional (document the negligible overwrite risk + count `journal_key_collisions`).

### Namespace, keys, batching (paging unit = batch)
- Namespace **`"__guardian_journal__"`** (distinct from `"__guardian__"` `guardian_engine.cpp:61` / `"__sync__"`;
  survives `full_sync`'s `kv_->clear("__guardian__")` `:308`).
- **Batch key** `lc:<boot_nonce>:<seq12>` (per-process seq from 0 → sidesteps the `list()` fail-open `max+1`
  overwrite). **Ordering across batches is by `(ts_ms, key)`, NOT lexical key** - the boot-nonce is random, so
  lexical order is not chronological (Sol BLOCKER 3 / retention ordering).
- **Sent label** `sent:<boot_nonce>:<seq12>` (tiny) - set when a batch's last entry pops-after-send. **Never
  gates re-paging or deletion**; classifies eviction only, and only **best-effort** (§8 - a live entry may
  send before its batch key exists, so absence ≠ "never sent"; hence `journal_evicted_without_send_evidence`).
- **Value** `{ "v":4, "ts_ms":<batch wall ms>, "entries":[ {rule_id, generation, event_id, enqueued_ns, kind,
  guard_type, rule_name}, ... ] }` (`v` unknown → quarantine).
- **Volume bounds:** push builder appends all rules, no cap (`guardian_push_builder.cpp:107`).
  `kMaxJournalEntriesPerBatch`=256, `kMaxJournalBatchBytes`=256 KiB; larger push → chunked. A batch ≤256
  fits the window → **paging unit = one batch**.

---

## 4. Persist boundary (single, phantom-safe, all-exits, bounded, engine-driven retry)
`start_local` re-arms cached rules via `reconcile_rule_locked` **outside** `apply_rules`
(`guardian_engine.cpp:215+`); `apply_rules` early-returns on `put_rule_locked` failure after prior rules armed
(`:342`). One persist op, from every reconcile path, on every exit.

### Staging invariant (Sol BLOCKER 2 - phantom-safe, no allocating set)
**Invariant: a lifecycle record is staged for journaling iff its arm/disarm actually took effect - committed
arm (never a rolled-back arm → no phantom) or completed disarm (never dropped → no lost disarm).**
- `pending_journal_` (`vector<shared_ptr<JournalRecord>>`) is **reserved ONCE at runtime construction** to
  `kMaxPendingJournalRecords` (proposal 4096) - never from rule count (Sol: rule-count reserve contradicts the
  cap + can attempt an unbounded alloc). Within the reserve, `push_back` is **noexcept**; overflow →
  **drop-oldest + `journal_stage_dropped`** (bounded - persistent disk-full cannot OOM).
- **No separate membership set** (its allocation after the lifecycle enqueue was the residual phantom). The
  loader instead **scans the bounded window** (`lifecycle_log_`) for an `event_id` (§5).
- **ARM:** `lifecycle_log_.enqueue` stays the **last throwing op** before commit; the noexcept
  `pending_journal_.push_back` follows it. A throw in `enqueue` → `GuardianRollback` (`:120-132`) undoes the
  arm and nothing is staged → clean. (Concrete option: `attach_rule` returns the built `shared_ptr` record and
  the engine stages it after a successful return - equivalent, and keeps staging off the throwing path.)
- **DISARM:** the teardown at `detach_rule_locked` (`:222`) already happened, so the record is **staged first**
  (noexcept) - a real disarm is never lost - then the best-effort `lifecycle_log_.enqueue`. A stage failure
  here (only if the reserve is somehow exhausted) is an **accounted integrity gap** (`journal_stage_failures`),
  never a phantom.
- Staging is RAM-only under `registry_mu_`/`outbox_mu_` - **no I/O** there (item-4 decoupling; Q6).

### Persisting (engine `mtx_`, all exits, circuit-broken, snapshot-not-put-back)
`persist_lifecycle_journal_locked()` (under `mtx_`): **snapshot** the `pending_journal_` shared_ptrs (do NOT
remove), serialize+`set()` per chunk, and **erase the persisted prefix only after a successful `set()`** (Sol:
removes the fallible put-back that could throw while recovering from `bad_alloc`). Chunk to the caps; the flush
is **engine-side, between `reconcile_rule_locked` calls in `apply_rules` + once after `detach_all` - never
inside a runtime call under `registry_mu_`**.
- **All exits:** a **terminate-safe** RAII guard (destructor `catch(...)`, like `GuardianRollback`) fires on
  the `:342` early-return, the normal return, and the per-rule catch-continue firewall (`:352-363`).
- **Per-push circuit breaker:** the first `set()` failure in a push **stops flushing for that push** (else 500
  rules × the 5 s busy timeout = a multi-minute `apply_rules` stall under `mtx_`), counts
  `journal_write_failures`; records stay in `pending_journal_` for the maintenance tick.
- **Retry hook - explicit, engine-side (Sol BLOCKER 4).** The heartbeat calls **only**
  `policy_generation()` today (`agent.cpp:1989`) - no `get_status`. Add
  **`GuardianEngine::journal_maintenance_tick()`** (bounded; under `mtx_`) wired into the real heartbeat loop
  (`agent.cpp:~1989`): retry pending persists, run the loader (§5), drive prune. Plus a **final flush in
  `GuardianEngine::stop()`** (`:275-295`). Regression test: a failed write becomes persisted with **no** further
  push / reconnect / shutdown.

Lock order: **WRITE** `mtx_ → outbox_mu_ → KvStore.mu_` (apply_rules / start_local / maintenance-tick / stop -
all `mtx_` threads). **PAGE** (§5) acquires `KvStore.mu_` and `outbox_mu_` **sequentially, never nested**, and
**never** `mtx_`. No inversion; `stop()`'s mtx_-held drain-join (`:276,290-291`) cannot deadlock.

---

## 5. Delivery model - journal primary, RAM window paged, re-send-all, NO cursor
Journal = primary durable queue; `lifecycle_log_` = bounded RAM send window; **no persisted watermark** (rev-2
BLOCKER) **and no persistent lexical cursor** (Sol BLOCKER 3 - a random-nonce key can sort before an older
nonce, so a monotonic cursor drops a stable-connection tail).

**Loader `page_journal_into_window()`** - serialized by a dedicated **journal-paging mutex** (concurrent
callers: drain low-water, reconnect hook, maintenance tick):
1. Under `KvStore.mu_` **alone**, fallible-read (§3) the unexpired batches; release. Order candidates by
   `(ts_ms, key)`.
2. For each batch, **only if the window has ≥ batch-size headroom** (else leave it - page next pass when the
   window drains): under `outbox_mu_` **briefly**, for each entry **scan the window** to skip entries already
   present (membership = window scan, no allocating set), enqueue the rest.
- **Re-send-all:** each pass re-considers the full unexpired journal (skipping window-members), so nothing is
  permanently skipped - no cursor, no tail-miss. Runs on: reconnect hook at `agent.cpp:1718`, drain low-water
  (safe - no `mtx_`), and the maintenance tick.
- **Paging rate-limiter (Sol major):** a **process-lifetime token bucket** on paged bytes/batches - it **delays,
  never skips**, and does **not** reset when a new stream opens (else a flapping agent replays up to the
  retention cap every reconnect). Correctness is unaffected (delayed entries still send; retention-only
  deletion holds them).
- Paged (replayed) records enter `lifecycle_log_` **only**, never `pending_journal_` (already journaled).
- **Sent labelling:** when a batch's last entry pops-after-send, set `sent:<nonce>:<seq>` (best-effort;
  classifies eviction only, §2/§8).

**Accepted cost (quantified):** a reconnect/restart re-sends the unexpired backlog - worst case the retention
caps (§6), rate-limited. A crash-looping agent re-sends its unexpired backlog each boot (**correct** - those
events are at-risk). The true traffic optimization is the deferred ack.

**Replay hook:** loader + drain-wake **immediately after `set_event_sink` (`agent.cpp:1718`)** - sink live.
Also fills the mapped gap (the reconnect hook republishes only the legacy sink and never wakes the spark drain
worker). **Not** at `start_local` (`:990`, sink dead) nor `sync_with_server` (`:1631`, pre-stream).

---

## 6. Retention (bounded; cross-retention constraint, NO agent-clock gate)
No kv_store retention exists. Build it: **age** `D_max` (7 days), **count** ≤ `N_max` (1000) batches, **bytes**
≤ `B_max` (32 MiB) - **evict oldest by `(ts_ms, key)`** (NOT `(nonce,seq)` - random nonce). Quarantine keys are
**also bounded** (counted + pruned) so corrupt entries can't accumulate outside the caps.
- Eviction classification via the `sent:` label → `journal_evicted_sent_unacked` (labeled) vs
  `journal_evicted_without_send_evidence` (unlabeled, best-effort, alert).
- **NO server-side agent-clock age gate (Sol BLOCKER 1).** Server TTL is from **receipt** time
  (`compute_ttl_epoch` = `now() + retention_days`, `guaranteed_state_store.cpp:376`), so an old-timestamp event
  received now gets a *fresh* interval - it is NOT reaped immediately. An agent-timestamp gate would just drop
  valid late/slow-clock events for zero benefit. The real risk is narrower: if server retention < agent `D_max`,
  a server-**reaped** id replayed later is re-inserted (no PK row to conflict) and re-runs observers. Handled by
  a **documented deployment constraint** (`server retention == 0 || >= agent D_max`; `D_max` default 7 days is
  conservative) + **deferred** dedup-tombstones (§Deferred). Do **not** infer delivery eligibility from an
  untrusted agent clock.
- Prune at boot (before paging) + in the maintenance tick; **`prefer_spark_`-gated** (stale journal untouched
  under the flag - resolves the §7 zero-writes inertness). Prune failures counted, never fatal.

---

## Server-side - PR-Sv (LIVE, non-inert; security-guardian + DEX review)
`insert_event` (`guaranteed_state_store.cpp:665`) currently treats every uniqueness conflict as a dropped
event; the shared `ingest_guardian_response` (`guardian_ingest.cpp:53`, both direct-agent + gateway paths) runs
the DEX blast-radius + alert-router observers **only after** `insert_event` succeeds (`:99-104`).

**Tri-state result contract (Sol Decision 2).** `insert_event_classified` returns **`Inserted / Redelivered / Conflict /
Error`**; ingest applies one server-wide rule:
- **Inserted** → run observers.
- **Redelivered** (PK conflict where the stored row matches the incoming on **every immutable agent-supplied
  field** - `agent_id`, `rule_id`, `event_type`, `timestamp`, `detected_value`, `detail_json`, expected value,
  remediation result, guard identity, latency - **excluding** server-enriched `severity` `:95-96` + receipt TTL)
  → increment a **quiet** `yuzu_server_guardian_events_redelivered_total`, **return before observers** (else
  reconnect replay double-fires blast-radius + alerts).
- **Conflict** (PK conflict with a **mismatch**) → keep the **loud** `events_dropped_total` + WARN (genuine
  collision/forgery; `agent_id` is connection-bound `:65`, so a sub-gateway forgery mismatches → stays loud).
- **Error** → operational failure path.
- Update the #1414/CC7.3 metric wording + alerts so `events_dropped_total` means genuine loss/collision.
- **Invariant preserved:** event insert + DEX projection stay in one transaction (Sol risk).
- **Caveats (record):** a **gateway-asserted** `agent_id` is a trust boundary above this check (out of scope);
  timestamp compare is seconds-granularity (`:91`) - the same-agent/rule/type/second legacy re-mint edge
  (`guardian_engine.cpp:567-568`) is shrunk by the full-field compare. Test the legacy + DEX paths for duplicate
  ingest.

---

## 7. Inertness (agent path - PR-Ag)
Arm (`attach_rule`) under `if (prefer_spark_ && Available)` (`guardian_engine.cpp:845`); non-arm `detach_rule`
(`:814/:843/:880/:891/:901`) produces no entry with nothing attached; drain worker only starts under
`prefer_spark_` (`:983-986`). **Loader, replay, prune, and the maintenance-tick journal work are all
`prefer_spark_`-gated** - a leftover journal is neither paged, sent, nor pruned under the flag; test:
`prefer_spark=false` + pre-populated journal → **zero** paging/sends/writes. (PR-Sv is **not** inert - reviewed
as a live change.)

---

## 8. Observability
Agent counters (all in §2 table + these gauges): journal depth (batches/entries/bytes), window depth,
`journal_pages`, `journal_records_paged`, `journal_batches_written`, `journal_batches_pruned`. Sent-label
classification is **best-effort** - do not present `..._without_send_evidence` as a precise "never sent" count.
Server: `..._redelivered_total` (quiet) + retained `..._dropped_total` (genuine-loss/collision only). Item 9
wires these to the heartbeat → Prometheus (unlabeled/low-cardinality).

---

## 9. Failure posture
`set()` fail → `journal_write_failures`, per-push circuit-break, snapshot retained, retried by the maintenance
tick; `pending_journal_` bounded → `journal_stage_dropped`. Parse/unknown-`v` → **quarantine** (`quarantine:<key>`,
bounded/pruned) `journal_quarantined`; rename failure → `journal_quarantine_failures`. Field NUL/oversized →
`journal_field_rejected`. Fallible read error (§3) is distinguished from empty and retried, never treated as
"journal empty". Prune failure → count, continue.

---

## 10. Test plan (item 8 provides deeper seams; code review must be unusually adversarial - Sol)
Round-trip; crash-before-send; **stable-connection tail** (journal >> window, one connection, no reconnect →
loader completes - the rev-1 + Sol-BLOCKER-3 guard); **current-nonce sorts before/after historical nonces**
(BLOCKER-3 ordering); concurrent pagers (drain vs reconnect vs tick) under the paging mutex + TSan; insufficient
window headroom → batch deferred not dropped; injected list/get failure → distinguished from empty + retried;
within-session no-double-send across a Retain (window keeps entries, scanned, not re-paged); exception-safe
staging (throw in the last throwing op → no phantom, arm rolls back); disarm-stage-fail counted, not phantom;
`detach_all` > cap → chunked; boot re-arm persisted (`start_local`, no push); apply_rules early-exit → prior
arms journaled; **failed write persisted by the maintenance tick with no push/reconnect/shutdown** (BLOCKER-4);
persist circuit-break (no multi-minute `mtx_` stall); bounded retry (persistent failure → `journal_stage_dropped`,
no OOM); retention eviction by `(ts_ms,key)` + classification; rate-limiter delays-not-skips + no reset on new
stream; inertness (`prefer_spark=false` + pre-populated journal → zero writes). **PR-Sv:** tri-state ingest
(Inserted→observers; Redelivered→quiet+no observers; Conflict→loud; Error), full-field compare, atomic
insert+projection, legacy + DEX duplicate-ingest coverage.

---

## Resolved Q1-Q6 + all Sol/Fable fold-ins
- **Q1** bounded durable retry; no ack; retention + quarantine the only deletions; eviction split into
  best-effort no-send-evidence (gap) vs sent-unacked (monitor). **Q2** accept reboot double-arm; boot/session-id
  + reason deferred. **Q3** boot-nonce'd per-process seq keys; ordering by `(ts_ms,key)`. **Q4** `synchronous`
  is **FULL** (confirm empirically); deferred (c) likely moot. **Q5** persist under `mtx_`; no scans/prune/I-O
  under `mtx_` beyond the bounded `set()`. **Q6** RAM staging is not an item-4 violation; single-owner record,
  no allocating set.
- Sol BLOCKER 1 (age gate removed), 2 (phantom-safe staging + no set + snapshot-not-put-back + reserve-once), 3
  (drop cursor + `(ts_ms,key)` order + headroom-gate + paging mutex + fallible read), 4 (maintenance tick).
  Majors: tri-state ingest before observers; full-field compare; `(ts_ms,key)` eviction; bounded quarantine;
  rate-limiter delay-not-skip; counter/wording honesty; complete loss-channel table.

## Deferred (named follow-up - rung-4-adjacent, file an issue)
(a) True at-least-once: server→agent per-batch **ack** (post-commit) as the deletion linearization point -
removes sent-unacked + the re-send-all traffic. (b) Deterministic ordering: preserve **nanoseconds**
(`guardian_ingest.cpp:91`) + per-agent **boot/session sequence** server-side. (c) Power-loss: likely already
FULL - confirm. (d) Doc: correct §"7.7b split" item-7 "audit-grade" wording. (e) `guard.errored` producer -
**partially landed via #2818** (the subscription-death path only, see below); broader `errored` coverage
(arm/boot-failure paths) is still deferred.
(f) **Dedup tombstones** for cross-retention resurrection (server retention < agent `D_max`).

## Scope - armed/disarmed/errored(#2818 subscription-death only)
`guard.errored` gained its first producer in #2818: `GuardianSparkRuntime::on_subscription_lost`
(via `detach_rule_locked(rid, "errored")`) fires when a spark subscription dies out from under a
rule, plus `revalidate_subscriptions()`'s poll-backstop path calling the same detach - both dormant
while `prefer_spark_=false`. No other `errored` path exists yet (arm/boot failures still journal
nothing) - the journal itself is kind-agnostic, so widening this further needs only a producer
(deferred (e), narrowed).
