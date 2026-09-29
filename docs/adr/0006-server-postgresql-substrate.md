---
status: accepted
date: 2026-06-09
owner: Nathan Dornbrook (platform)
deciders: Nathan Dornbrook (decision); @fjarvis + FortitudeEtc (requested a standalone server DB); @lesault (indifferent)
scope: platform — every server-side store; supersedes the "SQLite for embedded storage" principle on the server only
generalises: ADR-0004 (which introduced server Postgres for the vuln-graph derived state — now the first instance of this mandate)
---

# 0006 — PostgreSQL is the server-side storage substrate; SQLite-everywhere is retired for the server

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
  best-fit-per-store.
- **A columnar engine (ClickHouse / Timescale) as the *server* substrate.** Rejected by
  ADR-0003 — the high-cardinality flow firehose stays at the agent edge, so the server
  holds only small, derived, joinable state that plain Postgres serves. (ClickHouse remains
  the *analytics* sink, fed separately; it is not the OLTP substrate.)

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
