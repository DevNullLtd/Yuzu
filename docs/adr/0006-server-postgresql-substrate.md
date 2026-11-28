---
status: accepted
date: 2026-06-09
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook (decision); @fjarvis + FortitudeEtc (requested a standalone server DB); @lesault (indifferent)
scope: platform — every server-side store; supersedes the "SQLite for embedded storage" principle on the server only
generalises: ADR-0004 (which introduced server Postgres for the vuln-graph derived state — now the first instance of this mandate)
related: 0035-server-is-linux-only-windows-is-agent-only (the server is now single-OS as well as single-backend)
---

# 0006 — PostgreSQL is the server-side storage substrate; SQLite-everywhere is retired for the server

> **Update (2026-11-14, against dev @ 2c49b4ea0).** Every server store is now Postgres-native except
> `nvd_db` (`server/core/src/nvd_db.cpp`), the one residual server SQLite store; ADR-2002 withdraws
> it from the HA list and ADR-1005 moves it to a use-case engine. The other SQLite opens left in
> `server/core/src` are read-only legacy-file probes. Since ADR-0035 (accepted 2026-11-10) the
> server is also Linux-only.

## Context

ADR-0004 introduced server-side PostgreSQL **narrowly** — for the vuln-graph's derived
scored graph, last-known/offline endpoint state, the cross-store scoring join, and pgvector
— and flagged that it contradicted Yuzu's standing "SQLite for embedded storage" principle,
needing wider platform buy-in before implementation. **That buy-in was obtained 2026-06-09**
(@fjarvis and FortitudeEtc requested a standalone server database; @lesault indifferent;
Nathan decided), and the decision was deliberately **widened** beyond the vuln-graph: the
question on the table is no longer "may the vuln-graph use Postgres" but "what is the
server's storage substrate."

The server today runs ~27 separate SQLite stores. Their cross-store joins are
application-layer joins across files (`edges ⨝ findings ⨝ value ⨝ guardian_state` is the
sharp example — ADR-0004); the scale targets (>1M agents; 1.2M at HSBC), durable
offline-endpoint state, pgvector identity matching, and ordinary operational maturity (HA,
point-in-time backup/restore, real concurrency) all argue for one relational substrate
rather than a file-per-concern sprawl. `docs/architecture.md` already anticipated exactly
this — *"If the server outgrows SQLite, the storage layer can be swapped to PostgreSQL."*

## Decision

- **PostgreSQL is the standard server-side storage substrate.** The "SQLite for embedded
  storage" principle is **retired for the server** and **retained for the agent**
  (embedded-on-endpoint, zero-config, the federated edge warehouse of ADR-0003, agent
  KV/identity in `agent.db`). The endpoint-locality / kernel-boundary rationale that makes
  SQLite right *on the agent* is precisely what makes Postgres right *on the server*.
- **New server stores default to Postgres.** No new server-side SQLite store is added
  without an explicit exception ADR.
- **Existing server SQLite stores migrate incrementally — strangler, not big-bang.** Each
  store's migration carries **its own per-store ADR + migration plan**, covering: schema
  port, data migration/backfill, the transaction-owner port (`SqliteTxn`/`SqliteStmt` RAII
  in `sqlite_raii.hpp` → a Postgres equivalent), and the per-namespace `MigrationRunner`
  pattern → a Postgres schema-migration mechanism. **Prioritise by the pain ADR-0004
  named:** stores in the cross-store scoring join, stores needing durable offline state,
  and Guardian-scale write-volume stores go first; small, isolated, low-traffic stores
  (e.g. server config) may stay on SQLite indefinitely until touched.
- **The #1033 `sqlite3_changes()`-after-`step()` anti-pattern** becomes moot per migrated
  store, but the discipline it encodes — atomic mutate-and-return — carries over unchanged:
  Postgres `RETURNING` is the idiom there too.
- **Secrets caveat, carried forward from ADR-0004 (load-bearing):** "server-side durable
  state in Postgres" is **not** "secrets in a Postgres column." Secrets still require
  envelope encryption / KMS / `pgcrypto` and a separate `security-guardian`-reviewed
  decision. This ADR must not quietly become "we put secrets in a table."

## Considered and rejected

- **Postgres only for the new vuln-graph state (ADR-0004 as written); existing stores stay
  on SQLite forever.** Rejected by the 2026-06-09 widening — it leaves cross-store joins
  permanently straddling two engines and re-litigates the substrate question every time a
  store outgrows SQLite.
- **Per-store engine choice / polyglot persistence.** Rejected — one server substrate. A
  single HA story, a single backup story, and a single migration mechanism beat
  best-fit-per-store. The [November amendment](#amendment-2026-11-21--retention-bound-cold-records)
  assigns the separate recovery contract for retention-bound data.
- **A columnar engine (ClickHouse / Timescale) as the *server* substrate.** Rejected by
  ADR-0003 — the high-cardinality flow firehose stays at the agent edge, so the server
  holds only small, derived, joinable state that plain Postgres serves. (ClickHouse remains
  the *analytics* sink, fed separately; it is not the OLTP substrate.) The
  [November amendment](#amendment-2026-11-21--retention-bound-cold-records) adds two
  bounded exceptions and assigns their recovery and access-control obligations.

## Consequences

- **This is a BREAKING deployment change** — the same shape as removing an insecure default
  (packaging + systemd + compose + docs, not just a code guard). The server gains an
  external database dependency: the deploy composes, `Dockerfile.server`, systemd units,
  the UAT/demo rigs, and the operator install docs all grow a Postgres service (connection
  string, credentials, HA/backup posture). The single-binary "just run the server" story is
  gone server-side; `release-deploy` + `sre` own the rollout.
- **CI gains a Postgres service** for server tests that touch a migrated store (`build-ci`
  + the `/test` surface). The in-process `:memory:` SQLite test idiom (e.g. the
  `TrackerScope` helper) needs a Postgres-test equivalent — ephemeral schema / testcontainer
  / `pg_tmp`.
- **Backup/restore, HA, and capacity planning** become a tier-1 `sre` concern (deploy
  hardening + SLO docs); Postgres is now a tier-1 operational dependency, not an optional
  add-on.
- The **"Why SQLite everywhere?"** narrative in `docs/architecture.md` is superseded
  server-side; `architecture.md`, `data-architecture.md`, and `CLAUDE.md` are updated to
  match this ADR.
- This is a **multi-quarter program**, not one PR. This ADR records the *mandate and the
  rules*; the per-store migrations are tracked separately (a migration ladder / issues),
  each gated by its own ADR and the governance pipeline.

## Update (2026-06-22) — completeness: every server store migrates; none stays SQLite

The "**Prioritise by the pain ADR-0004 named** … small, isolated, low-traffic stores (e.g.
server config) may stay on SQLite indefinitely until touched" stance in the Decision above is
**superseded** on the *whether*, retained on the *order*. As of 2026-06-22 (grill-with-docs
session) the committed end state is that **every** server-side store reaches Postgres — no store
stays on SQLite. The agent remains SQLite (unchanged).

Rationale: the project is pre-alpha with zero production customers and one design partner, so the
migration is cheap to finish now, and a permanent two-engine server is the exact straddle a single
substrate exists to eliminate — mixed `SqliteTxn`/`PgPool` idioms, two backup stories, two test
stories, and a forever "is this store Pg or SQLite?" question for every contributor.

**Order** still follows the priorities above (cross-store-join + durable + high-write first,
trivial config stores last); the ordered queue is `docs/postgres-migration-ladder.md`. What
changed is that **completeness is no longer optional**. The author-facing store contract is
ADR-0012; the how-to is `docs/postgres-store-playbook.md`.

## Update (2026-07-16) — auth store (`AuthDB`) + SCIM migrated; last major SQLite server store gone

`AuthDB` (schema `auth`) and `ScimStore` (schema `scim_store`) shipped, out of Wave-3 order
(pulled forward as the last major server SQLite store — every operator credential, MFA
enrollment, and SCIM token now lives on the same substrate as everything else). Fresh-start, no
backfill (matches the `ApiTokenStore` 4.1 precedent, ADR-0009's "backfill is per-store, not
universal" allowance): the legacy SQLite `auth.db` is never read on upgrade — a first boot
against an empty `auth.users` re-seeds the config-file admin, existing accounts/roles/MFA
enrollments are lost, and SCIM self-heals on the IdP's next sync. `mfa_totp_secret` is
`SecretCodec`'s (ADR-0010) **first production consumer**. The SQLite-era `sessions` table (a
permanent v1 dead-write — sessions were always in-memory-authoritative) and the unused `auth_kv`
scaffolding were dropped, not migrated. Full record: `docs/auth-architecture.md` "AuthDB —
persistent authentication store" and `.claude/agents/authdb.md`; ladder entry:
`docs/postgres-migration-ladder.md` "Done".

## Amendment (2026-11-21) — retention-bound cold records

Nathan Dornbrook approved the criteria-run retention design on 2026-11-21 and the bulk
response destination on 2026-11-22. This narrows the rejection of a columnar server store
above. Each feature must specify its records, authorized reads, retention, durable
acknowledgement, recovery, and safe deletion. [ADR-0075 R11 and R13](0075-criteria-runs.md)
define the criteria-run requirements. The [response-store ADR](0039-response-store-postgres-migration.md)
describes the PostgreSQL implementation and the design required before its cutover.

| Responsibility | Storage and access |
|---|---|
| Run admission, ownership, authorization, pending work and export progress | PostgreSQL. Core owns the transaction that records a complete export. |
| Finalized per-device verdicts within cold retention | ClickHouse after packet 1.13. Core mediates every detail, count and aggregate under the same rules as warm reads. |
| Bulk live instruction response payloads | PostgreSQL until the response-store cutover. Ordinary and incident dispatch will then write directly to ClickHouse through authenticated core ingest. |
| Analytics and dashboards | The separate analytics feeds retain their existing access and retention policies. |

Before enabling either protected dataset, provision a dedicated ClickHouse database with
grants restricted to its core service identity. Grafana and analytics users must lack
access, including through views and distributed tables. Verify a denied query using the
deployed dashboard and analytics identities. Give only core the application credentials,
use verified TLS and source credentials from server secret configuration. ADR-0010
governs any persistent server secret. Document credential rotation and
backup coverage before enabling either protected dataset. Test a coordinated restore of
the protected data and its PostgreSQL access metadata. Reapply the retention deadline when restoring either copy.

For the 90-day cold verdict period (ADR-0075 R11), keep a compact PostgreSQL run header
with its creator, stored kind, input specifications (including definition digests) and
lineage through cold expiry.
Authorize reads against that header and the caller's current grants before querying
ClickHouse. Re-runs use the stored inputs under R12's current-authority checks. Warm
member deletion must preserve the header. Account for its space until reclaimed.
A revoked `CriteriaRun:Read` grant denies detail and count requests before and after warm expiry.
Fail closed when ownership or authority cannot be established. If an authorized cold read
cannot verify its data, return an availability error for the whole query, including counts.
At finalization record the expected count of distinct device verdicts and one cold expiry
instant, final plus 90 days. Bound header and verdict visibility to that instant, independently of
physical TTL cleanup. Preserve full cold retention through partition boundaries. The export
manifest records each deterministic batch number, device count and digest of its ordered
verdict records. Verify the complete export against that manifest in the same snapshot as
the read, before filtering or paginating. A missing or divergent batch fails the read even when the
sink is reachable. Verify both copies after restore before serving or resuming reaping.
If the warm source survives, retry missing batches. Otherwise recover the cold backup.

Route reads using the durable header state. Switch to the complete cold copy atomically
before deleting any warm member. A reader must observe one complete generation. Use the
existing `gc_sweep` as the sole automatic reclamation path. Its regenerable-scratch
exemption in the [clock-guard register](../clock-guarded-retention.md) does not cover
criteria-run members or headers. Packet 1.13 must add their distinct part-6 decision
to the register and the background-job annotation. Under the advisory lock, decline
and establish the shared anchor on a missing anchor before reclaiming those records. Bound and
charge retained headers across the entire cold period, separately from the warm members.

Export deterministic batches at finalization. Record `exported_at` only after **every**
batch has completed successfully to the destination's documented durability policy,
including any required replication acknowledgements. A transport status or a queued
insert alone cannot establish completion. Retry ambiguous or partial delivery with the
same batch identities, including across restart and upgrade. Record an empty final
run as a complete zero-batch export. Verify exact counts before merges. Re-check
PostgreSQL `ttl_at` and confirmed export inside the warm-reap transaction. Until terminal
expiry, keep a failed export readable warm. Per-device verdicts are working data. The counts-only audit event follows audit retention.

### Terminal expiry during an outage

On 2026-11-22 Nathan decided (D70) that a run without a confirmed export expires at final
plus 90 days, including when ClickHouse remains offline. At that deadline, stop serving
its verdicts and fence its exporter. Serialize the terminal transition with export
acknowledgement on the PostgreSQL run record, using the same guarded database clock.
A confirmed export follows normal expiry. An incomplete or unconfirmed export produces
one durable, counts-only loss event keyed by run and terminal transition. Record the run,
expiry time, reason, expected verdict count and count with confirmed durable receipts,
without device IDs. This event supplements the ordinary summary emitted at final.

In a single PostgreSQL transaction, write the uniquely keyed loss audit, dispose of
members before their header, and release the charges for both. The committed audit is
the durable witness of the terminal transition. A failed audit or commit must leave the expired data
inaccessible and still charged for retry. Restart, simultaneous replicas or an ambiguous
commit must produce one audit and one release. In-flight or retried batches cannot revive
the expired run; partial cold copies remain inaccessible and subject to the original TTL.
A restored database must reconcile expiry before serving or resuming export. Packet 1.13
tests an outage across day 90 with a partly acknowledged run, competing expiry and
acknowledgement, audit failure, restart and retry. Verify the loss event, disposal,
released capacity, refusal of reads, and absence of resurrection after recovery.

### PostgreSQL capacity during an export outage

Before enabling the export-dependent reap rule, bound the total warm space that criteria runs
can consume across all core replicas. Every create and re-run must atomically reserve capacity
before writing cohort members or scheduling collection. Use a conservative byte bound for the
admitted cohort, including its largest permitted terminal representation and indexes. Charge
existing warm records and outstanding reservations, including runs still gathering. Keep the
charge through export acknowledgement until the warm storage is reaped and reusable. Recover
reservations from durable run state after a restart or replica loss. Reconcile abandoned
and empty-run reservations without discarding charges for data still retained. Reconcile
existing warm runs before opening admission on upgrade.

Keep separate operational headroom for ordinary PostgreSQL transactions, WAL and maintenance.
If the request cannot fit even with an empty backlog, return a permanent size-limit error with the supported bound. If the
backlog consumes the budget, headroom is low, or capacity cannot be established, refuse new
criteria work before materialization with a retryable capacity error. Ordinary reads and
unrelated writes continue. Admitted runs have room to finish, and unexported verdicts remain
available until terminal expiry. Resume admission after pressure falls below a recovery threshold.

Bound export batch size, concurrent work and recovery throughput across replicas. Release database
transactions and connections before waiting on ClickHouse. On a sink outage, back off retries
with jitter and bound recovery throughput. Report charged bytes, available headroom, oldest
unexported age and admission refusals so an operator can distinguish a backlog from an
oversized request. Alert before the measured headroom for unrelated work is exhausted.

Verify with ClickHouse offline, concurrent fleet-sized create and re-run requests on multiple
core replicas, a core restart and ordinary PostgreSQL traffic. The acceptance criteria are
bounded warm usage and retry load, completion of previously admitted runs, and continued
unrelated database service against the documented latency and error budgets measured
with the same workload before the outage. Restore ClickHouse and verify exact
export counts, safe reaping and automatic resumption of admission. Size the default budget
and thresholds using measured storage and WAL growth before enabling this feature.

Packet 1.13 owns export, cold reads and the outage tests. Its implementation must
classify the exporter in the background-job registry and fence work across replicas.
It must document the recovery-time bound for abandoned reservations and the headroom
thresholds before testing. Verify explicit deletion during export: fence outstanding batches, revoke read access
and ensure restore cannot resurrect the deleted run. Verify relational and cold-store
restore and the same authorization-denial audit policy on both tiers. Ordinary successful
criteria-run reads add no per-device audit event.
Restore must reconcile a deletion record outside the restored copy before reopening reads;
if it cannot establish deletion history, keep the affected data unavailable. Remove expired
or explicitly deleted cold records under the disposal policy, including late batches.
Retain the access-grant review, disposal evidence and outage alert test with that packet.
Ship a bounded-label terminal-loss counter and alert, plus an advance alert on unexported
age before terminal expiry. Catalogue the loss audit verb and its idempotency key in 1.13. A release between packets 1.10
and 1.13 documents warm-only retention in its operator manual, changelog and upgrade notes
(ADR-0075 R11.9). A cold-store outage degrades those operations independently of core's
PostgreSQL startup and readiness contract.

### Notifying operators when a configured ClickHouse store goes offline

On 2026-11-22 Nathan required (D69) an outage notice at login and an MCP request for agentic
workers to notify their human operators. Surface the failure when core detects it. Keep
the notice visible while the configured store is offline, including when PostgreSQL can
still serve requests. Name ClickHouse and the affected functions without exposing data,
credentials or connection strings. Clear the notice after core confirms recovery.
Only an explicit configuration disabling every dependent feature with no outstanding
protected-store work suppresses this notice. Missing credentials, a missing DSN or an
unreachable host on an enabled deployment are failures. Outstanding runs keep their
original expiry and disposal rules across configuration changes.

Packet 1.13 owns the shared health state and the first protected-store outage test.
Publish bounded, timestamped health transitions to PostgreSQL for all replicas. Refresh
on a bounded cadence and require confirmed recovery before clearing the notice. Distinguish
an unknown or stale observation from health. Drive the authenticated dashboard landing
page, an authenticated REST datastore-status read, and MCP `yuzu://server/health` from
that state. Anonymous liveness and readiness probes retain their existing contracts.

Keep MCP's static orientation text shared with `yuzu://about`. On an authenticated
initialization or subsequent response-bearing interaction during an outage, include a
fixed notice in Yuzu result `_meta` (or error data on an error response) asking the
agentic worker to notify its human operator. Preserve tool result schemas. Use a
closed set of status codes and fixed messages. Test sign-in, authenticated REST,
new and existing MCP sessions, and a recovery that clears the notice on every replica.
The bulk response cutover reuses this signal. Verify unrelated PostgreSQL service
continues through the test.

### Bulk live instruction responses (approved design, 2026-11-22)

After the response-store cutover, authenticated core ingest will write ordinary and incident
bulk live response payloads to ClickHouse as their first durable destination.
Core owns the credentials and enforces device scope and Forensics tier on detail, facet and
aggregate reads. PostgreSQL owns admission, cohort, deadline, run status, audit and bounded
warm verdicts. Never spill raw responses into PostgreSQL when the sink stalls. Account for
in-flight response bytes across operators and replicas separately from the warm verdict
reservation above. Pause new waves on a sink stall, expose the pause and outstanding
coverage, and settle missing responses as incomplete at deadline. Release
database leases before sink waits. The response-store cutover requires its own migration and
rollback contract. ADR-0039 records the currently deployed response store.
