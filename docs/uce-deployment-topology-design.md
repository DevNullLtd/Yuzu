# UCE deployment topology — design + implementation plan

Status: **Draft for governance review** — records the maintainer + colleague
deployment decisions of 2026-07-12 and turns them into buildable work. Refines
exec-plan **Decision 11** (amendment PR drafted separately); companion to
`docs/uce-host-requirements.md` (2c — cites this doc from NF-3/§10/§12); input
to the **stack ADR** (runtime/language, still deferred). The generic
shared-instance trade-offs were weighed and **accepted** by the maintainer for
current circumstances — this doc does not re-litigate them; it makes the chosen
topology safe.

---

## 1. The topology (decided 2026-07-12)

```
┌─ Data centre (one) ────────────────────────────────────────────────┐
│                                                                    │
│  Yuzu server host                      UCE VM                      │
│  ├─ yuzu-server (REST/MCP/gRPC)  ◄───  ├─ UCE backend ─┐ one       │
│  └─ PostgreSQL instance (one)          └─ UCE GUI     ─┘ deployable│
│      ├─ yuzu DB      (server's)              ▲                     │
│      └─ uce DB  ◄────TLS─────────────────────┘                     │
│        (separate DATABASE, same instance)                          │
└────────────────────────────────────────────────────────────────────┘
Operator browser → UCE GUI origin (VM) AND Yuzu origin (server) — two origins.
```

- **D1 — One PostgreSQL instance, two databases.** The UCE's data layer is a
  **separate database on the server's existing PG instance** (not its own
  instance). "Never the server's connection pool" (plan Decision 11) stands
  unchanged — separate database, separate role, separate pool.
> **D2 and D3 are SUPERSEDED by ADR-0031 (accepted 2026-07-14).** The engine is **headless** — no
> GUI, no second origin. One origin, one session, one auth; §3's cross-origin design is void with the
> origin it secured. Presentation, core and each engine are separate binaries, co-located by default.
> **D1 is REAFFIRMED** (one PostgreSQL instance, two databases, separate roles and pools, no
> cross-database grant) and becomes *more* load-bearing, because co-location removes the network as an
> accidental barrier (ADR-0031 INV-31-3).

- **D2 — UCE deployable = backend + GUI, one artifact, on its own VM**, same
  data centre as the server and the PG instance (intra-DC latency; the §6
  view-time read's 250 ms p95 budget is unaffected in practice).
- **D3 — Two browser origins.** The operator's browser talks to the GUI origin
  (VM) *and* the Yuzu origin (server) — the 2c §6 artifact acquisition and F-8
  hand-off flows are **cross-origin by construction** now, not hypothetically.

## 2. Isolation design (what makes D1 safe)

1. **Role separation.** A dedicated `uce` PG role owns the `uce` database.
   **`REVOKE CONNECT ON DATABASE yuzu, uce FROM PUBLIC`**, then grant CONNECT
   back only to each database's intended role — PostgreSQL grants CONNECT to
   PUBLIC on every database by default, so a bare `REVOKE ... FROM uce` is
   **inert**. No shared superuser; the server's role never granted on `uce`.
   The `uce` role is pinned **NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION
   NOBYPASSRLS** with no predefined-role memberships (`pg_read_server_files`,
   `pg_execute_server_program`, `pg_read_all_data` would bypass per-DB grants
   entirely).
2. **Cross-DB access is forbidden — mechanically.** No `postgres_fdw`, no
   `dblink`, no cross-DB grants, in either direction. Same-instance co-location
   makes bypassing the versioned API *trivially possible*; any such path is a
   private seam violating ADR-1005 Decision 3. Enforced by the role grants
   above + a standing **cross-DB-access-denied test** (2c NF-3's new verify
   hook) + extension-allowlist review (no `postgres_fdw`/`dblink` installed in
   either DB). The standing test asserts not just today's vectors but the
   **`uce` role-attribute + extension-allowlist state itself** — a later-added
   grant, extension, or predefined-role membership on a long-lived shared
   instance is the drift a one-time provisioning check misses; the mechanical
   guarantee is only as good as the continuously-enforced grant state.
3. **Network exposure, minimally.** The instance today serves localhost/compose
   peers; it now accepts remote connections from the UCE VM: `listen_addresses`
   widened only as needed, `pg_hba.conf` entry scoped to the UCE VM's
   address + the `uce` role + the `uce` database only, auth method
   `scram-sha-256` (optionally `clientcert=verify-full` on top), **TLS required**
   (`hostssl`, and `sslmode=verify-full` on the client DSN); host firewall/ACL
   additionally scopes 5432 to the UCE VM (the widened `listen_addresses` is a
   pre-auth TCP surface), and a **certificate-rotation obligation** is named
   alongside the cert source. Certificate source:
   recommend the existing internal-CA machinery reviews whether it can issue the
   PG server cert (`docs/pki-architecture.md`) rather than a hand-managed cert —
   stack-ADR decision, flagged not decided.
4. **Write pacing (the DB-tier noisy-neighbour seam).** 2c NF-2 now requires it:
   findings-store writes are bursty and share WAL/checkpoint/autovacuum/buffers
   with the server's real-time stores. The UCE data layer MUST write in bounded
   batches on a paced schedule; per-DB observability (2c NF-8(vi)) makes a
   violation attributable. Instance-level guards set at provisioning — **MUST-set, not optional**:
   per-role connection limit, `idle_in_transaction_session_timeout`, and
   `statement_timeout` for the `uce` role (transaction-ID/xmin-horizon tracking
   is **instance-wide** — one idle-in-transaction UCE session blocks vacuum
   freeze progress on the *server's* tables too; the sharpest shared-instance
   risk here), plus a per-role `work_mem` cap (one runaway UCE query must not
   flood shared storage with temp files — with the corollary (UP-10) that
   `statement_timeout` MUST be set **above the module's legitimate longest
   operation** (a large tier-2 expansion / O(hits) materialization) or those
   operations chunked to fit under it, else a mandated cap livelocks a legitimate
   sync. And because per-DB WAL/checkpoint pressure is not attributable (NF-8(vi)),
   the write pacing is **open-loop** — it cannot adaptively back off during a
   server-side incident, so it MUST be conservative by default and the
   throttle/kill-switch (NF-2) is the incident-time mitigation, not closed-loop
   feedback. Note `autovacuum_max_workers` is
   instance-global: a vacuum-hungry `uce` DB competes with the server's tables —
   watch `pg_stat_progress_vacuum` at T1.
5. **Backups split per database.** Instance-level physical backups capture both
   DBs — unacceptable as the *only* mechanism, because findings retention /
   DSAR / legal-hold (2c F-14) must not silently inherit the server DB's backup
   policy. Provisioning establishes **per-database logical backups** (`pg_dump`
   per DB) with independently stated retention; if instance-level PITR/WAL
   archiving exists, the joint policy is written down, not implicit, and MUST
   (a) bound backup-copy retention consistently with F-14/§3.5's findings
   retention (a PITR archive silently retaining findings past 90 days is a
   residual DSAR leak), (b) state a **restore-time re-purge obligation** (after
   any restore, re-run the reaper/erasure against restored data — *verified at
   the first post-store-ship restore drill*, compliance-officer), and (c) note
   native PITR restores are **whole-instance** — a UCE-only or yuzu-only PITR
   restore is not a thing; restore drills must not assume selectivity.
6. **Failure domain + upgrades — stated, accepted.** Instance down ⇒ server
   fails closed at boot (ADR-0007) and the UCE store is dark (2c NF-7). PG
   major-version upgrades now coordinate both sides. Accepted trade-off;
   runbooks must treat the instance as shared infrastructure. **UCE VM
   availability (decided 2026-07-12): single VM is accepted for v1** — VM loss
   darkens the findings UI only (no data lives on the VM; state is in the PG
   instance; redeploy restores service; agents/server/ingest unaffected).
   **HA is essential going forward**: an HA posture for the UCE deployable is a
   **committed pre-GA requirement** (Phase-8 gate), not an optional follow-up.
   One operational note for T1: changing `listen_addresses`/enabling `hostssl`
   requires an **instance restart** (a brief planned Yuzu outage window —
   ADR-0007 fail-closed applies); `pg_hba.conf` alone is reload-only. Schedule
   T1 accordingly.

## 3. Cross-origin design (what makes D3 work) — [VOID — ADR-0031]

> **VOID.** ADR-0031 makes the engine headless: there is no second origin, so there is no cross-origin
> problem to solve. Retained as the historical record of a design that a merged decision required and
> an accepted ADR removed.


The 2c flows that touch the Yuzu origin from the operator's browser:
- **§6 artifact acquisition** — browser obtains the short-lived read-purpose
  operator-bound artifact from the Yuzu origin.
- **F-8 hand-off** — browser writes a server-side object (e.g. result set) to
  the Yuzu origin under the operator's **existing Yuzu session**.

Both now run from the GUI origin. Yuzu session cookies with default `SameSite`
will not ride on cross-origin XHR/fetch — so a **Yuzu-server-side deliverable
exists regardless of flow choice**:

- **Recommended: redirect-based flows first.** Artifact acquisition via a
  top-level redirect to the Yuzu origin (session cookie is first-party there)
  returning the artifact to the GUI origin; the F-8 hand-off as a Yuzu-origin
  page/redirect step. Avoids `SameSite=None` weakening and CORS-credentialed
  fetch entirely; costs one visible navigation. Two pins for the stack ADR:
  the F-8 hand-off write is a **CSRF-protected POST from the Yuzu-origin page**,
  never a side-effecting top-level GET; and the artifact return channel avoids
  durable URL exposure (history/`Referer`) — INV-9's single-use property
  mitigates but does not excuse a URL-borne artifact.
- **Alternative: CORS-credentialed fetch.** Yuzu server grows a configured
  **CORS allowlist for the UCE origin** — following the **shipped
  origin-allowlist pattern from PR #2060** (`--mcp-allowed-origin` /
  `YUZU_MCP_ALLOWED_ORIGINS`: repeatable, exact-match `scheme://host:port`,
  absent-Origin-allowed on a credential-gated endpoint, empty-list-rejects-any-
  present-Origin, A4-shaped rejections + audited denials) rather than a
  divergent shape — e.g. a sibling `--api-allowed-origin` for the REST surface
  (default unset = no cross-origin grant beyond the existing self-origin
  reflection in `server.cpp`) + `SameSite=None; Secure` on the session cookie.
  **Critical port caveat (2c NF-9(e)):** the PR-#2060 pattern's
  **absent-Origin-allowed** sub-rule MUST NOT carry over to this cookie surface —
  it is safe for MCP only because that endpoint is bearer-token/non-browser (the
  per-request credential defeats rebinding); a `SameSite=None` cookie
  auto-attaches, so absent-Origin on a state-changing request re-opens CSRF.
  Reject absent-Origin / require a CSRF token on state-changing cookie requests,
  and note a CORS allowlist gates response *readability*, not request
  *admission* — it is **not** a CSRF control. Smoother UX; materially larger
  security surface.

**Operator login to the GUI (decided 2026-07-12): Yuzu is the identity
provider.** The UCE has **no user store**. First visit → top-level redirect to
the Yuzu origin (session first-party there; Yuzu's own login — including its
**shipped OIDC SSO** (`oidc_provider.cpp`, `oidc:<iss>#<sub>` principals) — runs
if needed) → Yuzu mints a **single-use, operator-bound artifact** (INV-9) →
redirect back to the GUI origin → the UCE backend redeems it server-side and
establishes its own UCE session for that operator. One identity end-to-end
(2b §3.4); the confinement identity is trustworthy by construction. **SSO is
therefore inherited transitively** — corporate IdP → Yuzu (existing relying
party) → UCE; the UCE never registers with the corporate IdP, and a customer's
SSO configuration lives where it already does. Known residual, inherited
knowingly: #1836 (IdP-side deprovisioning propagates at next SSO login — a live
Yuzu session can still mint UCE artifacts until revoked/expired; same operator
mitigation, and the UCE side is additionally bounded by the artifact's ≤5-min
TTL + fresh-at-redemption scope resolution, 2c INV-2). Protocol detail
(plain code-exchange vs OIDC-shaped) → stack ADR, but the **security-load-bearing
pins are 2c NF-9, not stack-ADR detail** — summarised here:

- **Two distinct artifacts, one primitive (NF-9(c)).** The **login** artifact is
  identity-only (attests who the operator is, carries no read/write authority);
  the **confinement-read** artifact (§6, 2b §5 read-purpose variant) is what a
  findings render redeems. They MUST NOT be conflated — the login artifact is
  shippable at T2b without ADR-0017 PR-A; the confined findings *read* is not
  (see §5). Re-mint is **browser-redirect-driven** (the UCE holds nothing
  durable — preserves INV-1's memory-only posture), never a UCE-backend refresh.
- **Login-callback integrity (NF-9(b)).** The redirect carries a `state`/nonce
  bound to a first-party pre-redirect UCE context, validated at redeem
  (anti-CSRF/fixation); the redirect-back target is a **server-side configured
  exact-match GUI origin**, never a request-supplied `return_to`
  (anti-open-redirect/exfiltration). The UCE never accepts a corporate-IdP token
  directly (NF-9(a)).
- **Session = bounded cache of Yuzu authority (NF-9(d)).** (1) UCE session
  max-age **≤ Yuzu's** (8 h today); re-auth is simply this redirect flow again —
  invisible while the Yuzu session is live. (2) A **definitively denied**
  artifact re-mint or a definitively revoked/expired-operator result on any
  read is **session-terminating** (restart the redirect flow → a revoked
  operator lands on Yuzu's login wall); an unreachable/timeout re-mint is
  indeterminate and follows the bounded retry/grace below. **Honest scope:
  revocation-via-reads propagates only while reads flow**, so NF-9(d) mandates an
  **unconditional, jittered re-validation floor** (revalidate operator liveness
  against Yuzu every ≤ artifact-TTL, *not* gated on user reads — an idle-timeout
  alone is insufficient, it never revalidates an active session) with a
  **bounded-retry/grace transient-failure posture** (an unreachable-Yuzu blip
  fails closed only after N-consecutive/grace, a definitive revoke terminates
  immediately) — extending Yuzu's `session.revoke_all` reach to idle sessions too
  without mass-logging-out the fleet on a wobble, still with **no new server
  surface** (INV-2 + INV-5 + the floor). NF-9(d) is authoritative; this is its
  summary. The UCE session is an honest *cache of Yuzu authority*, never an
  independent grant.

The redirect-vs-CORS choice for the *per-view reads* is a **stack-ADR decision
with a security-guardian gate**; the 2c invariants (INV-1…INV-10) and the login/
session pins (NF-9) hold under either. Either way the server work ships **before
the module's findings view** (view-ship), not before M1/M2.

## 4. Gotcha register (accepted-and-managed, not open)

| # | Gotcha | Managed by |
|---|---|---|
| 1 | DB-tier noisy neighbour (write bursts vs heartbeat ingest) | §2.4 pacing + NF-8(vi) signals |
| 2 | Cross-DB bypass (`postgres_fdw`/`dblink`) | §2.2 revokes + denied-test |
| 3 | One failure domain, coordinated upgrades | §2.6 runbooks; NF-7 honesty |
| 4 | Crown-jewel instance now network-reachable | §2.3 hostssl + scoped pg_hba |
| 5 | Cross-origin session mechanics | §3 server-side deliverable |
| 6 | Backup coupling vs findings DSAR/legal-hold | §2.5 per-DB backups + joint policy |

## 5. Implementation plan

Phased, PR-sized; each lands through full governance. Module-milestone
references use the module ladder's own numbering (store-ship / view-ship events
per 2c F-12/F-15).

- **T0 — docs (now).**
  (a) 2c fold — topology into NF-2/NF-3/NF-7/NF-8/§10 + this doc created
  (same PR/branch as 2c, `docs/uce-host-requirements`).
  (b) **Exec-plan amendment PR** — Decision 11 refinement (same-instance
  separate-DB + VM) batched with the pending Decision 4 ≥500k extension; small,
  vs `dev`. *Acceptance: both docs governed clean; amendment merged.*
- **T1 — PG provisioning.** Create `uce` database + `uce` role on the existing
  instance; both `REVOKE CONNECT`s; `hostssl` + scoped `pg_hba` entry; TLS cert
  (source per stack ADR); per-role connection limit; per-DB logical backup job;
  the **cross-DB-access-denied test** wired as a deploy-time self-check —
  tested at BOTH layers separately: the grant layer from a vantage `pg_hba`
  admits (local socket: `uce` role attempting `\c yuzu` and FDW creation →
  both fail on grants, so a pg_hba rejection cannot mask an inert revoke), and
  the network layer from the UCE VM. Deployment reality: the shipped composes
  run PG as a compose service (`yuzu-postgres` image) with **no published 5432**
  — T1 concretely means a compose-level port publish (or equivalent network
  path) + TLS/`pg_hba` config landing in the `yuzu-postgres` image or its
  mounted config, and any changed compose joins the release-gate tracked list
  (`scripts/check-compose-versions.sh` FILES array). Artifacts: provisioning
  script + compose/image changes under `deploy/` + UAT-rig wiring when an
  engines rig exists. *Acceptance:
  denied-test green at both layers; TLS-only verified (non-TLS conn refused);
  role timeouts/`work_mem` caps applied (§2.4); backups restorable per-DB.*
- **T2 — Yuzu server cross-origin work**, in two sub-steps: **T2a** — the
  redirect-vs-CORS decision (made in T3's stack ADR, security-guardian gate);
  **T2b** — implement the chosen server-side half (redirect endpoints or
  REST-surface origin allowlist per §3's PR-#2060-pattern + cookie posture)
  **plus the operator-login
  authorize+redeem endpoint pair** (§3 — the single-use artifact flow doing
  double duty as UCE login; small, authorization-code-shaped). *Acceptance: a browser on
  the GUI origin completes artifact acquisition and an F-8 hand-off write
  against a real Yuzu session (login + F-8 hand-off); NF-9(b)/(f)/(g) + NF-9(e)
  pins satisfied; the NF-9 login/session **audit events emit** (login
  success/failure, session-established, session-terminated-on-revocation — login
  and its audit trail ship in lockstep); CSRF review clean. A **populated**
  findings view additionally needs the module's store-ship milestone (F-12 / module
  M3) — T2b delivers the login + view *surface*; a non-empty view awaits store-ship,
  so view-ship = T2b **and** store-ship, not T2b alone. **T2b ships the
  identity-only login artifact + the F-15 *interim* findings view (no
  group-confined operator) — NOT the confined findings read**, which additionally
  gates on ADR-0017 PR-A + M3(d) (2c §6 dependency edge; §5 does not otherwise
  surface that prerequisite). Gates **view-ship**, not M1/M2.*
- **T3 — Stack ADR.** Runtime/language + packaging for the VM shape + the §3
  flow choice + cert source; consumes 2c §10 + this doc. *Acceptance: ADR
  through governance; unblocks module M1.*
- **T4 — Host skeleton on the VM.** `engines/host` skeleton (NF-3 CI guard
  live, NF-4 version-range refuse-to-start with actionable diagnostic, NF-8
  signals stubbed), module M1 (source-ingestion) begins per the module ladder.
  *Acceptance: separate artifact builds + deploys to a VM; CI include/link
  guard red-tested.*

- **T5 — observability wiring + capacity baseline.** Un-stub the NF-8 signals
  (wire to real metrics/alerting, incl. NF-8(vi)'s per-DB `pg_stat_database`
  attribution and NF-8(vii)'s login/session telemetry), and record a **pre-UCE capacity baseline** on the shared
  instance (server heartbeat-ingest/write-path p95 **and** the server's API
  request-rate/latency, since the NF-9(d) liveness ping and login land on the API
  path, not the DB write path — NF-2 names API-serving capacity a first-class
  pre-GA SLO input) so module M2's synthetic scale test has a before/after
  comparison. The baseline **informs** M2's test —
  the test mechanism itself is 2d implementation detail, not a prerequisite of
  this plan (maintainer direction 2026-07-12). *Acceptance: signals visible +
  alert rules live; baseline recorded.*

Dependencies: T1 ∥ T2b-prep; T2a is T3's deliverable, so **T2b needs T3**; T1's
own TLS acceptance can use an interim cert (the *final* cert source is a T3/stack-ADR
choice), so T1 is **not** blocked on T3;
T3 needs T0; T4 needs T1+T3; T5 needs T4 and informs module M2's scale test;
T2(b) needed only by view-ship. The module's M1/M2 (ingestion, two-tier read)
can proceed on T1+T3+T4(+T5 baseline) while T2b lands — noting M2's authenticated
tier-1/tier-2 server reads also depend on engine-principal auth (2b Phase 4) and
the F-3 shared access layer, a cross-program edge outside this deployment plan.

## 6. Open questions (stack ADR unless noted)

- Redirect vs CORS-credentialed fetch (§3) — security-guardian gate.
- PG server-cert source — internal CA (`docs/pki-architecture.md`) vs external.
- DB naming (`uce` single DB now; per-module databases if module count grows —
  revisit at second module, same trigger as plan Decision 6's re-examination).
- VM provisioning/config-management ownership (who stamps the VM, patching
  cadence) — Workstream D territory, named not decided.
- Shared-instance **upgrade-coordination runbook** (PG major upgrades now move
  both sides together, §2.6) — Workstream D owner, written before T1 completes.
