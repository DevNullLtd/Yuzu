---
status: accepted
date: 2026-06-22
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook; grill-with-docs design session 2026-06-22
scope: platform — the author-facing contract every server-side Postgres store obeys
builds-on: ADR-0006 (Postgres substrate), ADR-0007 (single-backend), ADR-0008 (substrate architecture), ADR-0010 (secrets-at-rest)
---

# 0012 — Server Postgres store contract: failure posture, lease discipline, cross-store query seam

## Context

ADR-0008 fixed the substrate *internals* — libpq + in-house RAII, one shared `PgPool`, one
Postgres SCHEMA per store, `PgMigrationRunner`. Exactly one store has been built on it
(`OfflineEndpointStore`, schema `endpoint_state`), and ~27 SQLite stores plus the auth DB are
queued to migrate (ADR-0006, now *all-or-nothing* per its 2026-06-22 Update; the ordered queue
is `docs/postgres-migration-ladder.md`). Before that fan-out, the **author-facing** contract has
to be fixed so 28 migrations don't each re-decide it:

- what a store does when the database is unavailable **at runtime** (not at boot — that is
  already fail-closed per ADR-0007),
- how a store shares the one pool without starving or deadlocking its peers, and
- how the cross-store joins that justified Postgres (ADR-0006) get written when each store owns
  only its own schema.

`OfflineEndpointStore` answered these implicitly, for one fail-soft store. This ADR makes the
answers explicit and general.

## Decision

### 1. Every store declares a runtime failure posture

Construction failure stays fail-closed (ADR-0007): a store that cannot migrate/open sets
`startup_failed_` and the server refuses to serve. *Runtime* failure (saturated pool, query
error, transient unreachable) splits stores into two **declared** kinds:

- **durability-on-top** (fail-soft) — a bounded acquire, returns empty/`false` on error, and an
  in-memory layer remains the source of truth. The store adds durability *on top of*
  authoritative live state, so a database blip degrades durability, never correctness.
  (`OfflineEndpointStore`: the live `FleetTopologyStore` cache is authoritative; the Postgres
  row just lets an aged-out host render stale-flagged instead of vanishing.)
- **authoritative** (fail-hard) — the database **is** the source of truth. A runtime error is
  surfaced to the caller, **never** papered over with an empty result, because a silent empty
  read is a correctness or security failure (an RBAC store returning "no roles" reads as
  fail-open). Authoritative stores may wait longer for a lease, but still bound the wait.

The posture is part of the store's documented contract (header comment + per-store ADR) and
drives its acquire discipline and error handling. Most migrated stores are authoritative.

Posture is declared **per operation-class (ingest vs read), not strictly per store.** A typed
projection fed by a self-healing agent push is **ingest-fail-soft + read-authoritative**: a failed
ingest is fine (the agent re-pushes), but a read has no in-memory authoritative layer to fall back
on, so a silent empty would be fail-open. `SoftwareInventoryStore` (ADR-0016 §7) is the worked
example — classifying it durability-on-top *wholesale* (the original header did) is the
misclassification this split guards against.

### 2. One shared pool; backpressure is lease discipline, not partitioning

ADR-0008's single `PgPool` stays. No per-class pools, per-store budgets, or priority queues —
premature before observed contention. Three hard rules make a shared pool safe:

- **(a) Runtime acquires are always bounded** (`try_acquire_for` with a deadline). Unbounded
  `acquire()` is permitted **only at construction**, where boot is serial and the substrate
  probe has already proved reachability.
- **(b) Never hold a lease (or a `with_txn`) across network, disk, or other external work.** A
  lease is checked out, used for SQL, and returned; nothing slow happens while it is held.
  The sole documented exception is a fail-closed, pre-serving, one-time legacy backfill whose
  atomic insert-plus-completion stamp requires one transaction while it streams a bounded row
  from the legacy store. The per-store ADR must justify that exception, cap per-row memory, and
  make retry behavior explicit; ordinary runtime methods, including erasure, remain subject to
  this rule without exception.
- **(c) One logical operation holds at most one lease at a time.** A store method must not call
  another store, or re-enter the pool, while holding a lease — that is the pool-exhaustion
  deadlock (the holder waits for a connection that only frees when holders return theirs).
  Cross-store work uses rule 3 instead.

### 3. Cross-store reads/joins/atomic writes are a first-class query-owner seam

The cross-store joins that justified one database (ADR-0006 — e.g. the vuln-graph edges ⨝
Guardian state ⨝ inventory join, spanning `vuln_graph_store` / `guaranteed_state_store` /
`inventory_store`) are written by a **dedicated query owner** that takes ONE
lease and issues schema-qualified SQL spanning the schemas directly — a read join on a pool
lease, or an atomic multi-store write via `pool.with_txn` issuing every statement on that one
lease. Per-store classes stay single-schema owners and **never expose their lease**. The shape
is committed now; the seam is **built when its first consumer (vuln-graph scoring) lands**, not
speculatively. Until then no store may grow a cross-schema method.

### 4. Read caching on an authoritative store (added 2026-07-24, #2367)

An authoritative store MAY cache reads, subject to all five of the following. The rules were
first worked out for `EnginePrincipalStore`'s stream-liveness cache (ADR-0031) after an external
review round found three ways to get it wrong; they are recorded here so the next store does not
re-derive them differently.

1. **Positive results only.** Never cache a "not found" (it needs a create-path invalidation hook
   to avoid masking a freshly created row) and never cache a store-unreachable result (caching
   "I could not ask" extends the outage). A failure MAY be *rate-limited* — repeating a recently
   obtained deny-class answer without taking a lease, for a window shorter than the positive
   TTL — which is a different thing from caching it, and is what stops the per-tick retry storm
   the cache exists to prevent from simply returning once entries age out.
2. **Invalidate synchronously on the store's own writes, AFTER the write lands**, under a
   generation guard whose re-check shares one critical section with the insert. Invalidating
   before the write leaves an unguarded window in which a concurrent reader re-reads the old row
   and installs an entry that outlives the write by a full TTL.
3. **Report provenance to the caller.** A cached answer must be distinguishable from a fresh one.
   A caller that grants time-bounded trust on the strength of a check — the canonical case is a
   held-open stream with a grace window — will otherwise let cache residency and its own budget
   ADD rather than nest, silently multiplying how long a dead credential is honoured. `ApiTokenStore`,
   the sibling this clause was derived alongside, does NOT yet satisfy this rule (it reports a cache
   hit as plain valid) — that gap is #2447, and it is exactly the additive-window failure this rule
   exists to prevent.
4. **Never serve a fresh authorization decision.** Split the accessor: the authoritative one stays
   read-through and keeps the chokepoint contract; the cached one is separate, narrowly typed
   (liveness only — do not hand back a row a caller might read as current), and has as few callers
   as the design can enforce.
5. **Bound residency, and bound every map you added.** A hard ceiling with a sweep on each map's
   own insert path, declining to insert rather than evicting something live. Note that a
   failure-backoff map fills precisely when the positive map does not, so a sweep hung only off
   the positive path never runs when it is needed.

A cache whose TTL is coupled to another component's timing constant (a grace window, a heartbeat
interval) must pin that relationship with a `static_assert`, not a comment.

## Considered and rejected

- **A single rule — all fail-soft, or all fail-hard.** Rejected. Fail-soft is wrong for
  authoritative data (a silent empty read is fail-open); fail-hard is wrong for the heartbeat
  hot path (it cannot block on a saturated pool or throw per heartbeat at 1M+ agents). The
  posture split is the minimum that serves both.
- **Partitioned pools / per-store budgets / priority queue.** Rejected as premature.
  `OfflineEndpointStore`'s fail-soft posture already protects ingest from a read burst, and we
  have no measured contention to size partitions against. Revisit only if the pool metrics
  (`yuzu_pg_acquire_wait_seconds`, `yuzu_pg_acquire_timeout_total`) show real starvation.
- **Stores expose their lease so callers compose cross-store work.** Rejected — breaks
  single-schema encapsulation and re-introduces exactly the nested-acquire deadlock rule 2(c)
  outlaws.

## Consequences

- Each per-store migration states its **posture** in its per-store ADR and header; reviewers
  check acquire discipline against rules 2(a)–(c). `cpp-safety` / `security-guardian` gate the
  fail-open risk on every authoritative store.
- The query-owner seam is **unbuilt** until vuln-graph scoring; cross-store stitching that
  exists stays application-layer until then, and no store grows a cross-schema method in the
  interim.
- A thin **non-polymorphic** construction helper (`open_with_migrations(...)` + a `server.cpp`
  construction helper that flips `startup_failed_` on `!is_open()`) is extracted **before** the
  fan-out so the construction-fail-closed wiring is written once, not 28 times — ADR-0008's
  "optional thin ctor helper", now mandatory (see the ADR-0008 2026-06-22 Update). Non-virtual,
  no backend abstraction (ADR-0007/0008 compliant). This is an implementation follow-up.
- The step-by-step recipe an author follows is `docs/postgres-store-playbook.md`; this ADR is
  the *why* it cites.

## Update (2026-09-20) -- fast-fail-on-saturation refines rule 2(a)'s bound

Rule 2(a) ("Runtime acquires are always bounded") let a caller's own timeout run to completion
even when the shared pool was ALREADY fully saturated at the moment of acquire -- no idle
connection and no spare capacity to open one. Governance finding `up-2146-a2r1-httplib-worker-
cascade` (#2146 A2-R1 Gate 8) found the shared pool's default worker-to-connection ratio
(~264:16 httplib workers per pool `size`) makes that saturation a foreseeable steady state, not
a rare edge case -- so every `try_acquire_for`/`with_txn_for` caller blocking up to its own
acquire timeout while saturated can, at volume, exhaust the httplib worker pool itself and stall
unrelated routes (auth included), not just the route that happened to hit the saturated pool.
The affected range is wider than a `kReadTimeout`/`kWriteTimeout` shorthand suggests: individual
stores' own acquire timeouts run from 1500ms up to `AuditStore::kReapTimeout{8000}` (the
retention reaper), `LicenseStore::kValidateTimeout{10000}`,
`AppPerfRollup::kRollAcquireTimeout{5000}`, and `AnalyticsEventStore::kDrainClaimTimeout{5000}`
(#2146 A2-R1 Gate 8 round 4, architect) -- up to a 20x compression at the extreme once clamped,
not merely the 3-8x a 1500-4000ms framing implies.

`PgPool::try_acquire_for` (`pg_pool.hpp`) now clamps the wait to
`min(caller's own timeout, Options::saturated_fast_fail)` (default 500ms) once it observes that
saturated state at entry -- never for a caller that arrives before saturation, and never for the
unbounded `acquire()`/`with_txn()` (construction-only, rule 2(a)'s existing carve-out). This does
not weaken rule 2(a) ("always bounded") -- it tightens the bound precisely when the caller's own
timeout is very unlikely to be honoured by an actual release in time anyway, freeing the calling
httplib worker for other routes instead of pinning it. The default (500ms) is chosen to sit AT OR
ABOVE every currently-deliberately-short acquire/retry timeout already in the codebase (e.g.
`auth_db.cpp`'s `#2396` login-resilience retry, and three call sites that tie at exactly 500ms --
see `Options::saturated_fast_fail`'s doc comment in `pg_pool.hpp` for the full survey) so this
refinement only compresses the long budgets the finding is about, never an already-tuned short
one.

**Scope is uniform across the pool, not read-only.** This is a single shared chokepoint with no
read/write distinction: it applies identically to security- and audit-critical WRITE paths
sharing this pool -- `RbacStore`, `AuditStore`, `QuarantineStore`, `SessionStore`,
`EnginePrincipalStore` among others, all with `kWriteTimeout` well above 500ms. A prior Gate 8
round (round 3, governance ledger row `proc-2146-a2r1-gate8-round2-closed-with-open-blocking`)
sketched a fix scoped only to read-only `*_checked` call sites and explicitly deferred a uniform,
all-callers version as "cross-cutting architecture work deserving its own ADR and sre-reviewed
rollout." The shipped fix IS that uniform version, reviewed and accepted in Gate 8 round 4 rather
than round 3: a failed `with_txn_for` already means "transaction never began" either way (no new
partial-mutation risk), so the change is to the RATE of a pre-existing failure mode under
sustained saturation, not its kind. This does not eliminate the original worker-cascade risk --
it substantially compresses it (Gate 8 round 4, sre: re-derives the residual risk from
HIGH/BLOCKING to MEDIUM given the magnitude reduction, not a structural elimination -- saturation
itself, and the 264:16 ratio driving it, are unchanged by this fix). The differential exposure
this widening adds to already-tracked fire-and-forget audit-write sites (#950, #3185, #4007,
#4526 -- pre-existing, not introduced here) is a separate, disclosed follow-up concern, not a
reason to withhold or narrow this fix.

## Update (2026-09-26) -- the cross-store query-owner seam exists

Section 3 and its Consequences describe the query-owner seam as unbuilt until vuln-graph scoring.
That is no longer accurate: `AppPerfRollup` (`app_perf_rollup.{hpp,cpp}`) is a dedicated query owner
that takes one pool lease and issues schema-qualified SQL across two store schemas, and
`RbacAdminAuthorityOwner` (`rbac_admin_authority_owner.{hpp,cpp}`, PR #4985) is one for the
last-Administrator guard, which needs the `rbac_store` grants and the `auth.users` account state
inside one transaction. The "until then" condition in section 3 (the seam's first consumer) has
therefore run out, since `AppPerfRollup` is that consumer. The rule itself is unchanged: per-store
classes stay single-schema owners, cross-schema work lives in a query owner, and
`RbacStore::unassign_role` delegates to the owner rather than issuing `auth` SQL itself.

## Update (2026-09-30) -- a third consumer, and a named exception for a shared-fragment predicate

A third query owner: `CommandDeliveryFinalizationOwner` (`command_delivery_finalization_owner.{hpp,cpp}`,
#4982), which owns the cross-schema write `CommandOutboxStore::mark_sent_with_target` delegates to —
the fenced `command_outbox_store.outbox` `pending -> sent` transition and
`execution_tracker.executions.agents_targeted` commit in one transaction, on one lease, exactly the
section 3 shape. Nothing about that write needs a new rule; it is recorded here only to keep this
ADR's consumer list current.

The same class also introduces a second SHAPE this ADR had not previously named:
`kPendingOutboxNotExistsClause`, a `static constexpr` SQL fragment (not an owner-executed method)
that spells out, once, what "still owned by the delivery loop" means for a
`command_outbox_store.outbox` row. `ExecutionTracker::reap_stuck_running_executions` embeds this
fragment, verbatim, into its own `WHERE` clauses — including the final atomic
`UPDATE ... WHERE ... RETURNING id` that re-evaluates the full cancel-candidate predicate — and
executes it on `ExecutionTracker`'s OWN transaction/connection. No `CommandDeliveryFinalizationOwner`
instance is constructed to use it.

This is a deliberate, narrow exception to section 3's default shape (an owner that takes its OWN
lease and executes the cross-schema query itself), not a violation of it. The precondition that
makes it correct: the caller needs the predicate evaluated as part of its OWN atomic check-and-act —
here, the reaper's cancel-candidate re-check must be evaluated AS PART OF the cancelling `UPDATE`
itself — on the same connection, inside the same transaction, under the same advisory lock — not as
a separate read whose answer could go stale before the write commits. (This is evaluation-order
atomicity, not a shared MVCC snapshot: Postgres READ COMMITTED gives each statement its own
snapshot, so the predicate's `NOT EXISTS` subqueries still see the data as of the UPDATE's own start,
not a snapshot shared with any earlier read — the `EvalPlanQual` re-check that protects the UPDATE's
locked TARGET row does not extend to those subqueries. See `execution_tracker.cpp`'s own comment on
the atomic cancel UPDATE for the resulting narrow residual.) Answering the predicate on a
separately-leased owner connection first (the normal section-3 shape) would reopen exactly the TOCTOU
the atomic re-check exists to close — a row could flip to outbox-pending between the owner's read and
the reaper's own `UPDATE` committing. A shared text fragment the caller embeds in its own statement
closes that specific window, because it is evaluated by the SAME statement, on the SAME connection,
under the SAME advisory lock as the write it gates.

This shape is not new to the codebase: `LeaderElector::epoch_fence_sql()` (`leader_elector.hpp`) is
the shipped precedent — also "a pure string builder (no connection)" (that header's own words) whose
SQL executes on a caller's own pooled connection, inside the caller's own claim statement, for the
identical reason (a standalone fence read would race a handover between the read and the claim
commit). `kPendingOutboxNotExistsClause` is the second instance of that same pattern.

**When this exception applies, precisely, so a future author cannot cite it as a general escape
hatch:** ONLY when a caller needs the predicate as one conjunct of its OWN atomic check-and-act
statement, where a separately-leased read would introduce a check-then-act race the caller's
transaction is specifically structured to avoid — OR as one conjunct of a preparatory `SELECT` that
runs inside that SAME transaction, under the SAME lock, directly selecting or counting candidates for
that same check-and-act, PROVIDED the predicate text is byte-identical to the one the final
check-and-act re-evaluates atomically. `ExecutionTracker::reap_stuck_running_executions`'s
candidate-count and candidate-select queries are this second case: preparatory reads under the same
advisory lock and transaction as the atomic cancel `UPDATE` that re-checks the identical clause (not
a shared MVCC snapshot — see the note above on READ COMMITTED). It does NOT license a cross-schema
`SELECT` embedded for convenience, run outside the
check-and-act's own transaction/lock, or against a predicate the final mutation does not itself
re-evaluate — nor a fragment a caller could just as well obtain by calling an owner method on its own
lease. The default in section 3 is still owner-executed, and this exception is for the one case that
default cannot serve: a predicate that must be evaluated INSIDE somebody else's transaction, not its
own. Adding a third instance of this shape should point back to this paragraph, not merely to
`kPendingOutboxNotExistsClause`'s doc comment, so the precondition is re-checked each time rather than
copied as a template.

## Update (2026-10-04) -- a fourth query owner: CredentialChangeOwner

A fourth query owner: `CredentialChangeOwner` (`credential_change_owner.{hpp,cpp}`, #5342), the ONLY
writer of an existing local account's `auth.users.password_hash` (the self-service change and the
administrative reset). One `pool.with_txn_for` on one lease, schema-qualified SQL across three
schemas: `SELECT ... FROM auth.users ... FOR UPDATE` (classification under the lock), the guarded
credential `UPDATE` (which also wipes a provisional TOTP secret and, for a reset, clears the
lockout), `DELETE FROM session_store.sessions`, the success audit row(s) in
`audit_store.audit_events`, and LAST the `session_store.session_meta` write-generation bump (every
session create/revoke shares that row, so the owner waits on nothing while holding it). The change, the account's
sessions, its provisional MFA state, its lockout and the audit evidence therefore commit or abort
together — there is no compensating write.

Two own-schema seams were extracted so the owner reuses, never copies, each store's statements --
the same shape `rbac_store_sql_helpers.hpp` gives `RbacAdminAuthorityOwner`:

- `session_store_sql_helpers.hpp` (`session_sql::delete_user_sessions_in_txn`,
  `session_sql::bump_generation_in_txn`, and their composite `session_sql::invalidate_user_in_txn`)
  -- the ONE "revoke every session of a user" statement pair; `SessionStore::invalidate_user` runs
  the composite, the owner runs the two halves split around its audit INSERT.
- `AuditStore::log_in_txn(PGconn*, const AuditEvent&)` -- the same sanitize + INSERT as
  `AuditStore::log()` (which is now exactly "lease + `log_in_txn` + `count_committed`"), issued on
  the caller's open transaction; the caller bumps the success bucket via
  `AuditStore::count_committed` only after its own commit. This is the audit store's section-3
  seam: any other mutation whose audit row must commit with it uses `log_in_txn` inside its owner's
  transaction (#5360 tracks moving the remaining "audit after commit + rollback" routes onto it),
  never a second INSERT.

Lock order (documented in the owner header; a change inverting it can deadlock): the `auth.users`
row, then `session_store.sessions` rows, then the `audit_store.audit_events` INSERT, then LAST the
`session_meta` `write_generation` row. It is acyclic against every other holder because no
`session_store` transaction touches another schema (nothing holds `session_meta` and then waits on
`auth.users`), no audit writer touches `session_store`, the locking post-mint re-read
(`AuthDB::recheck_role_locked`) takes `auth.users` only after its own session INSERT has committed,
and `RbacAdminAuthorityOwner` takes `principal_roles` before `auth.users` and never a session or
audit lock. Like the RBAC owner, it is correct only because `AuthDB`, `SessionStore` and
`AuditStore` share ONE pool/database (ADR-0006); a split onto separate databases fails every
statement closed, never a silent partial write.
