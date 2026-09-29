# Engine principals & delegation — auth-architecture follow-up design (ADR-1005 item 2b)

Status: **Phase 4 shipped (PR 4.1–4.3); Phase 5 (delegation) pending.** This
design is the execution plan's item 2b (`docs/adr-1005-execution-plan.md`,
Phase 2). Phase 4 (engine principal class — the identity store, RBAC
resolution, and the operator-facing REST/MCP/console lifecycle surface) is
built and live as of PR 4.3; see `docs/user-manual/rest-api.md` "Engine
Principals", `docs/user-manual/mcp.md`, and
`docs/user-manual/engine-principals.md` for the shipped operator-facing
surface. Phase 5 (delegation/write-back, RFC 8693 token exchange) and 2c's
Decision-14 confinement choice remain design-only and still consume this
document as their reference; every mechanism below not yet cross-referenced
against a shipped PR should be treated as still-design until verified against
code.

Companion docs: `docs/adr/1005-headless-platform-use-case-engines.md` (the
ADR; its Decision 5 is the trust-tier/delegation decision this design
elaborates), `docs/adr-1005-execution-plan.md` (phases + its own Decision log
— cited below as "plan Decision N", distinct from the ADR's Decisions 1–7),
`docs/auth-architecture.md` (shipped auth surface),
`docs/adr/0017-management-group-confinement-list-reads.md` (the scoped
list-read model this design adopts as its authorization chokepoint).

## 1. Scope

In scope (the six questions 2b was chartered to answer):

1. Delegation token-exchange mechanics (§5).
2. Principal granularity — per-module vs per-host (§3).
3. Credential lifetime and rotation ceilings (§7).
4. Token-session attribution change for engine principals (§6).
5. Self-target destruction-guard extension (§9).
6. MCP tier applicability to engine principals (§8).

Binding design directions from the maintainer (2026-07-08):

- **Every user keeps their own identity end-to-end** — including operators
  whose reads are served through a UCE. No shared-credential blob may ever
  stand in for a set of humans.
- **Authorization is three-dimensional**: securable type × operation ×
  **management-group scope** (e.g. `Inventory:Read` confined to one
  management group). Two-dimensional global grants are the legacy floor, not
  the model.
- **Established, industry-standard mechanisms; no v1 shortcuts.** Where a
  standard exists (OAuth 2.0 Token Exchange, cloud-IAM scoped role
  assignments, service-account governance norms), this design follows its
  shape rather than inventing a local variant.

Out of scope, tracked elsewhere: the full quota mechanism (Phase 8; minimum
cap = plan PR 4.4, interlock #1973), the Decision-14 confinement mechanism
*choice* (2c owns it; §10 hands over candidates + criteria), streaming
egress, write-back orchestration semantics beyond the delegation mechanics
themselves (plan Decision 13).

## 2. Current state (verified against `dev`, 2026-07-08)

The gaps this design closes, with their exact locations:

- **Token sessions attribute to the human creator.**
  `AuthRoutes::synthesize_token_session` (`server/core/src/auth_routes.cpp`)
  sets `session.username = api_token.principal_id` — and `ApiToken::principal_id`
  is documented as "Username who created it"
  (`server/core/src/api_token_store.hpp`). The session's role is re-resolved
  from the *creator's current role* via `auth_mgr_.get_user_role(...)`. An
  automation token is therefore always a mask over a human identity — the
  exact anti-pattern plan Decision 9 requires Phase 4 to remove.
- **No principal-kind exists anywhere.** `ApiToken` has no kind field;
  RBAC's `PrincipalRole::principal_type` (`server/core/src/rbac_store.hpp`)
  admits only `"user"` and `"group"`; the legacy `auth::Role` enum is
  `{user, admin}`. A repo grep for service-account/machine-principal
  scaffolding returns zero hits.
- **Permissions are two-dimensional and global.** `RbacStore::check_permission`
  resolves roles (direct + group-inherited) and consults `role_permissions`
  keyed on `(role_name, securable_type, operation)` — there is no scope
  column. Management-group confinement exists as a *separate, currently
  inert* mechanism: ADR-0017's `authorize_list_read(user, securable, op) →
  DenyAll | AdmitAll | AdmitScoped(visible_set)` is **designed and ratified
  but unbuilt** (its PR-A..E ladder has zero code in the tree; call sites
  across the server carry "not yet effective under the global gate" comments
  citing #1634/#1716).
- **The self-target destruction guard is a username-string comparison.**
  Three sites in `server/core/src/settings_routes.cpp` (self-delete,
  self-demote, plus the Users-fragment `is_self` suppression) compare the
  target name byte-exact against `session->username`
  (`docs/auth-architecture.md` "Self-target principal-destruction guard").
- **MCP tier rides the credential.** `ApiToken::mcp_tier`
  (`readonly|operator|supervised|""`) is copied onto `Session::mcp_tier` at
  synthesis and checked *before* RBAC at ~28 per-tool sites in
  `server/core/src/mcp_server.cpp` (`tier_allows` /
  `requires_approval`, `server/core/src/mcp_policy.hpp`).
- **Lifetime is uneven; rotation does not exist.** MCP-tier tokens force
  expiry ≤ 90 days and service-scoped tokens force an expiry
  (`ApiTokenStore::create_token`), but a plain API token may be perpetual
  (`expires_at = 0`). No token type has a rotation workflow — only create
  and revoke.
- **Interim rules already enforced (Phase 1, merged via PR #1972):** on-behalf-of
  assertions are rejected (not ignored) at the HTTP pre-routing chokepoint
  and via a gRPC interceptor (`on_behalf_guard.hpp`,
  `grpc_on_behalf_interceptor.hpp` — the gRPC side is enforced deterministically
  per-RPC-handler, not merely best-effort cancellation); the presentation-level
  `principal_class` label exists for HTTP metrics (`principal_class.hpp`)
  and the additive `AuditStore.principal_class` column (plan item 3a) merged
  in the same PR.

## 3. Identity model — every actor is a first-class principal

### 3.1 EnginePrincipalStore (born on Postgres)

A dedicated store, NOT columns bolted onto the token table — because the
governance metadata plan PR 4.3 requires does not describe a credential, it
describes an *identity* that outlives any one credential:

| Field | Notes |
|---|---|
| `principal_id` | Stable, immutable. Reserved namespace — see §3.3. |
| `display_name` | UI/audit label. |
| `owner_username` | **Named responsible human** — must reference an existing user. **Enforced, not aspirational:** the user-delete route fails closed (409) while the user owns any `active` engine principal — transfer-owner is a prerequisite step, itself audited and step-up-gated. **Force-transfer is an admin operation, independent of the current owner's cooperation** — a user under termination-for-cause must never be able to use engine-principal ownership as a lever to stall their own deprovisioning; an admin reassigns ownership directly, the outgoing owner has no veto. |
| `justification` | Grant justification captured at creation (cloud-IAM service-account norm; feeds access reviews). |
| `classification` | `internal` \| `external`, **required at creation — the creation API rejects an unset value.** `external` is the fallback only for pre-existing/backfilled rows (there are none at Phase 4 launch) and for any future write path that omits it; that fallback is itself audited and metered, not silent, so an internal module never loses Phase-8 capability without an operator-visible signal. |
| `lifecycle_state` | `active` \| `revoked`. **Terminal, not reversible** — a false-positive compromise response does not "un-revoke"; recovery mints a successor principal whose row records `superseded_by` (the predecessor's id). **Any tooling or query joining a principal's history across a `superseded_by` link must surface the revocation event and its stated cause alongside the join** — a seamless merged trail that doesn't show *why* the swap happened would understate that a security incident occurred; this is a requirement on the joining view, not just the raw data. **Soft-retained forever** — a revoked row is never hard-deleted, so audit attribution stays resolvable after credential revocation (plan Decision 9). |
| `created_at`, `revoked_at`, `created_by`, `superseded_by` | Lifecycle audit anchors. |

Substrate: born-on-Postgres per ADR-0006 (no new server SQLite stores) and
ADR-0012's author contract, **declared authoritative (fail-hard)**: a runtime
read failure at session synthesis or delegation redemption is treated as a
deny, exactly like a genuinely missing/revoked row — **but the two cases
must be observably distinct**, because they demand different operator
responses. A store-unreachable read returns a retryable, 503-class signal
(the module should back off and retry — this is not a credential problem);
a missing-or-revoked row returns a terminal 401-class signal (the module
should stop and alert — the credential is dead). Conflating them risks a
transient PG blip reading as "credential revoked," which could make an
autonomous module abandon a healthy credential. **This distinction changes
retry behavior only, never the authorization outcome** — both paths deny
the current request; there is no downgrade path from "unreachable" to
"admitted," so the split creates no bypass surface, only a better-informed
caller. The Phase-5 delegation-artifact store (`jti` state, §5) adopts the
same substrate and the same authoritative posture — no Phase-5
exception-ADR needed for either store.

**Named PR-4.2/Phase-5 deliverables — health + runbook.** Both stores must
join the `/readyz` conjunction the moment they become load-bearing (the
existing pattern every other server-core store follows, e.g.
`software_inventory_store`'s `is_open()` row) — the store-unreachable
signal above has no operational meaning without a health probe backing it.
An operator-facing runbook entry (mirroring `auth.db`'s pairing of a
`/readyz` row with `docs/ops-runbooks/auth-db-recovery.md`) must name which
probe to check and cross-reference `docs/postgres-store-playbook.md` for
the underlying PG-outage response — an on-call engineer seeing "engine
session synthesis failing" needs a path to that playbook, not just the
client-visible 503/401 split. Both stores are server-core (not
agent-control-plane) Postgres stores — separate from the shared `PgPool`
ADR-1005 already flags as a pre-GA capacity follow-up (engines and the
agent control plane sharing one bounded pool); this design adds no new
pressure to that specific shared pool, but the cross-reference is worth
carrying forward so whoever resources that follow-up has the full list of
contributors.

`EnginePrincipalStore` lands in **plan PR 4.2**, immediately alongside (not
inside) PR 4.1's `ApiTokenStore` Postgres migration + `principal_kind`
column — the two migrations are sequenced back-to-back but are separate
PRs, since 4.2 also introduces the `principal_type='engine'` RBAC value and
the `synthesize_token_session` branch (§6) that depend on 4.1's column
existing first. No secret material lives in `EnginePrincipalStore`
(credentials stay in `ApiTokenStore`, hash-only), so no ADR-0010 SecretCodec
involvement.

**Upgrade migration hazard:** the reserved-namespace rejection (§3.3) binds
only *new* creations. The PR 4.2 migration itself must scan existing
`users` and locally-created RBAC groups for the `engine:` prefix and refuse
to proceed (surfacing the exact colliding names to the admin) rather than
silently letting a pre-existing `engine:vuln`-named user coexist with a
newly minted engine principal of the same id — that silent coexistence is
precisely the identity-merge hazard §3.3 exists to prevent, and it is worse
undetected than loud at migration time.

### 3.2 Granularity: one principal per module

**Per-module, not per-host.** A UCE host running the vuln module and a
future second module holds two engine principals with disjoint grants. This
is the least-privilege cut: grants, quota (PR 4.4's per-principal cap),
audit attribution, and revocation blast-radius all land at module
granularity. A compromised or misbehaving module is revocable without
severing its host siblings. (Per-host was rejected: it recreates a
mini-union-of-permissions across modules — the ServiceNow-admin-token
shape at smaller scale.)

Per-module identity is defeated by an ops error that hands module B a
credential provisioned for module A — a host-level misconfiguration, not a
protocol gap, but worth a cheap check: the request declares which module
slug it believes it's authenticating as (e.g. a header set by the module's
own config), and a mismatch against the credential's actual principal is
denied and audited as an anomaly rather than silently accepted. **This
catches only accidental cross-module credential misassignment** (an ops
error where two config values drift independently) **— it is not a
defense against adversarial spoofing**, since a compromised module can set
its own self-declared slug to match whichever credential it holds. It is
advisory defense-in-depth, not a security boundary the design otherwise
depends on.

### 3.3 Identity namespace — collisions must be impossible

Engine principal ids live in a reserved namespace: `engine:<slug>` (e.g.
`engine:vuln`). Two structural rules:

- User creation (local, OIDC/SAML provisioning, SCIM later) **rejects**
  usernames matching the reserved prefix — an engine id can never collide
  with a human username. This matters because `session->username` is the
  key for audit rows, the self-target guard, token ownership, and RBAC
  lookups; a collision would silently merge two identities across every one
  of those surfaces. The same rejection applies to **locally created RBAC
  group names** (groups feed role collection too); IdP-sourced group names
  cannot be rejected at our boundary, but `principal_type` disambiguates
  them structurally — a group named `engine:x` can never be *an engine
  principal*, only an oddly-named group.
- The prefix makes audit rows and access-review exports self-describing
  without a join.

### 3.4 Operators viewing through a UCE keep their own identity

Plan Decision 14's requirement plus the maintainer's end-to-end-identity
direction means: the UCE findings view must never serve operator reads on
the engine principal's own fleet-wide credential. The mechanism *choice* is
2c's (§10), but this design fixes the invariant: **any read rendered to an
individual operator is authorized as that operator** — the engine
principal's autonomous-sync identity is for autonomous sync only.

## 4. Grant model — scoped role assignments, one model for every principal class

### 4.1 The assignment triple

Authorization becomes a set of **scoped role assignments**:

```
(principal, role, scope)
```

- `principal` — a user, a group, or an engine principal (`principal_type`
  gains `engine` as its third value — additive on either substrate, plan
  Decision 9).
- `role` — an RBAC role (the existing `role_permissions` machinery keeps
  defining what a role can do: securable × operation, deny-overrides-allow).
- `scope` — **fleet-wide** or **one management group**, expanding
  descendant-ward per ADR-0017's expansion invariant.

This is the cloud-IAM shape (a role assignment *at a scope*), and it
generalizes the existing management-group `GroupRoleAssignment` concept
rather than inventing an engine-only parallel path. The maintainer's
worked example — `Vuln → Read → management group X` — is exactly one
assignment row: `(engine:vuln-viewer-role-holder, role-with-Vuln:Read,
scope=MG-X)`.

**Named PR-4.2 deliverable — the assignment *authoring* surface.** Something
must let an admin write an `(engine principal, role, scope)` row in the
first place; §11's PR mapping previously left this implicit inside "the
existing role-assignment mechanism." It is not implicit: extending
whatever surface creates `PrincipalRole`/`GroupRoleAssignment` rows today to
accept an `engine:`-namespaced principal target is a named PR 4.2
deliverable, alongside the resolution-side fix below.

**Named PR-4.2 deliverable — the resolution side.** `RbacStore`'s
role-collection query resolves `principal_type = 'user'` (direct) or
`'group'` (via membership) today — it does not know about a third value.
Adding `principal_type='engine'` rows without extending this query would
make Phase 4's "fleet-wide grants are expressible in the current global
model" claim (§4.3) false in a particularly bad way: an engine assignment
would silently resolve to nothing, fail-closed but *inert* — a real grant
that never takes effect, discovered only when someone asks why the module
isn't reading anything. This resolution-site extension is therefore an
explicit PR 4.2 task, not an assumed side effect of adding the enum value.

**One model for all classes.** Humans, agentic workers (API/MCP tokens),
and engine principals resolve effective authority identically:

```
effective authority = ⋃ assignments, evaluated as (permissions ∩ scope)
```

enforced at ADR-0017's `authorize_list_read` chokepoint for list/fan-out
reads and at the per-device scoped-permission path for single-target
operations. No second resolution path is introduced — a deliberate
rejection of a separate engine-grants table, which would give every future
authorization change two places to forget. (A stated ceiling on
assignment-rows-per-principal is a reasonable PR-4.3 latency safeguard —
resolution cost grows with row count — but is not load-bearing enough to
fix a number here; today's self-limiting create-path gating is sufficient
until real data says otherwise.)

### 4.2 Engine-principal constraints (structural, not conventional)

- **Default-deny per securable.** An engine principal with no assignments
  can do nothing.
- **No admin, ever.** Assignment APIs *reject* (not merely omit in UI)
  granting an engine principal the `admin` legacy role, any built-in
  wildcard role, or elevation eligibility. The ServiceNow-integration
  admin-token pattern must be unconstructable through any surface.
- **No "all permissions" toggle** exists for engine principals on any
  surface (plan PR 4.3's explicit requirement).
- Engine principals are excluded from JIT elevation, MFA enrollment, login
  surfaces, and password paths — they are not users; they only ever
  authenticate by credential (§6).
- **Named PR-4.3/4.4 deliverable — auditor-runnable proof, not just a
  write-path claim.** "No admin, ever" and "no all-permissions toggle" are
  enforced at the write path, which is a claim about code behavior an
  auditor cannot verify by reading a policy doc. A query or report —
  joining `principal_type='engine'` against resolved effective role/scope
  and asserting zero admin/wildcard/unscoped-fleet-wide-by-accident rows —
  must exist as an independent check, the same way the sampled-auth-log
  export independently evidences auth-surface behavior rather than asking
  an auditor to trust the login code.

### 4.3 ADR-0017 is hereby on the critical path — named dependency

Phase 5's effective-authority intersection and plan Decision 14's confinement
outcome both cite `authorize_list_read` — which **does not exist in code**.
This design makes the dependency explicit rather than inherited silently:

> **Dependency edge:** ADR-0017 PR-A (the `authorize_list_read` chokepoint
> + scoped-assignment resolution) must ship **before Phase 5 begins**, and
> before any scoped engine assignment can actually confine a read. Phase 4
> can proceed without it (engine principals with *fleet-wide* read grants
> are expressible in the current global model), but the maintainer's
> three-dimensional-RBAC direction is only real once ADR-0017 PR-A lands.

**Charter delta, stated so it isn't discovered mid-implementation:**
ADR-0017 PR-A as chartered resolves scope for **users and groups** — it was
never scoped to a third principal type, because `engine` didn't exist when
PR-A was designed. This design's use of `authorize_list_read` for engine
and delegated reads therefore either (a) requires ADR-0017 PR-A's own
charter to be amended to resolve on `principal_type` generally (all three
classes through one chokepoint, consistent with §4.1's one-model claim), or
(b) requires a small named follow-on PR that extends the chokepoint for
`principal_type='engine'` once PR-A ships for users/groups. This design
does not choose between (a) and (b) — that is the maintainer's ladder to
resequence — but it names the choice explicitly rather than letting an
implementer assume PR-A already covers engine principals because this
design cites it.

Sequencing and resourcing of the ADR-0017 ladder (PR-A..E, plus the #1715
deny-precedence decision that gates PR-A, plus the charter-delta choice
above) is the maintainer's call — this doc's job is to ensure that call is
made consciously, not discovered at Phase-5 kickoff. **Follow-up:** file an
issue against the exec plan noting its Phase 5 gating (currently 3b + Phase
4 only, no ADR-0017 edge in the program-ladder diagram) needs amending to
match this design's §4.3/§11 dependency — the same kind of fold-back the
plan's own Round-4 M3(d)-edge fix already modeled.

## 5. Delegation — OAuth 2.0 Token Exchange shape (RFC 8693)

Phase 5's write-back unlock. The mechanics, fixed now so Phase 4's stores
don't need reshaping later:

1. **Grant:** an operator, authenticated to Yuzu normally (session or
   token), requests a delegation to a named engine principal for a named
   purpose. The server issues a **delegation artifact**:
   - opaque handle (not a self-contained JWT the UCE host could inspect
     or mint against) — server-side state keyed by `jti`;
   - **audience-bound** to one engine principal id;
   - **purpose-bound** (requested operation class recorded at issuance);
   - **short-lived** (minutes-scale TTL; single-digit default, operator
     cannot extend past a server ceiling); **all TTL/expiry evaluation is
     server-clock authoritative** — consumption/revocation are recorded as
     state transitions, not time comparisons, so a clock step (server NTP
     correction or engine-host skew) can never resurrect a consumed or
     revoked artifact, only misjudge a not-yet-expired one's remaining
     window;
   - single-use for **mutating** operations (`jti` consumed on redemption) —
     **and idempotent per consumption**: a retry presenting the *same*
     `jti` from the *same* engine credential within a short grace window
     after a first successful redemption returns the **persisted response
     of the original redemption** — never a re-invocation of the delegated
     operation — so an ordinary network retry (lost response, timeout)
     neither masquerades as artifact theft on the audit trail nor
     double-executes a non-idempotent side effect; a retry presenting a
     consumed `jti` from a *different* credential is the actual theft
     signal. **The consume-and-execute step is one atomic claim** (a
     unique constraint or compare-and-swap on `jti` state, not a
     check-then-act pair) — two concurrent presentations of the same
     valid `jti`+credential must serialize to exactly one execution, with
     the loser reading the winner's persisted response, never both
     executing;
   - **read-purpose artifacts are explicitly bounded-reuse, not
     unboundedly reusable within TTL:** each redemption of a read-purpose
     artifact still counts against the same per-artifact reuse tracking,
     so a reusable read artifact cannot become an unmetered drain on the
     consenting operator's own quota (§5 step 6) merely by being
     read-purpose rather than single-use;
   - capped outstanding-artifact count per operator and per engine
     principal, with expiry-driven pruning, so a scripted/looping issuer
     cannot grow unbounded server-side state — **and a capped issuance
     rate** (not just standing count), since a rapid issue→redeem→expire
     loop can drive unbounded write rate through the artifact store
     without ever exceeding the standing-count cap;
   - revocable (operator or admin can void it before expiry).
   - **Transport is explicitly in scope here, not deferred to plan
     Decision 13** (which is itself an unspecced placeholder, not a
     document that could receive this hand-off): the artifact travels from
     the operator's authenticated Yuzu context to the engine module over
     the same channel the module already uses to poll/receive its assigned
     work (plan Decision 13's future write-back-orchestration surface) —
     this design fixes the artifact's *shape and validity rules*, not the
     orchestration transport itself, which remains plan Decision 13's to
     design when write-back orchestration is scoped.
2. **Exchange:** the engine module presents *its own credential* + the
   artifact (RFC 8693 `subject_token` = artifact, `actor_token` = engine
   credential — the standard delegation, not impersonation, composition).
   The server verifies both, checks the audience binding, re-checks the
   engine principal's `lifecycle_state` **fail-closed**, and evaluates the
   delegated operation. The resulting delegated context is **non-bearer**
   — bound to the engine credential presented at exchange, never a
   free-standing secret an attacker could exfiltrate from the UCE host
   independently — and lives at most per-request / within the artifact's
   TTL; nothing delegated outlives the artifact.
   **Operator authority is resolved fresh at redemption** through the
   §4 chokepoint — never frozen at issuance time — and disabling,
   demoting, or de-scoping the operator voids their outstanding artifacts.
   Failed redemptions (bad audience, consumed `jti`, expired, revoked
   operator or principal) each write a denied audit row **and increment a
   dedicated Prometheus counter carrying `event="security"` and a bounded
   `reason` label** (one of the failure classes just listed) — following
   the same shape as existing security-signal counters
   (`docs/observability-conventions.md`); never a `principal_id` label, to
   keep cardinality bounded. This is the primary detection signal for
   artifact theft, so it is a paging alert (rare in normal operation);
   the idempotent-replay path in step 1 above is explicitly NOT this
   signal and must not share its alert — a replay is routine and log-only,
   a denied redemption is not.
3. **Effective authority of a delegated operation:**

   ```
   engine principal's assignments ∩ operator's assignments ∩ operator's scope
   ```

   — an intersection, never a union; computed through the same ADR-0017
   chokepoint (§4.3). A delegation can only ever *narrow*. The
   intersection is taken at the **effective-decision level** — an
   operation is permitted iff it is permitted for the engine principal
   AND permitted for the operator, each side independently evaluated
   under ADR-0017's (frozen-by-#1715) deny-precedence rules — never by
   intersecting allow-assignment *rows*, which would silently drop a deny
   row one side carries and widen the delegated decision past the
   operator's real effective authority.
4. **Self-asserted delegation stays rejected forever.** The Phase-1
   on-behalf-of guard (reserved header/metadata rejection) is permanent —
   ADR-1005's Interim rule survives as a standing invariant; the only
   delegation the server honors is one it issued itself.
5. **Audit:** every delegated operation writes both identities — the full
   audit shape ADR-1005's own Decision 5 specifies and plan Decision 9
   restates (engine principal id, `is_delegated`, delegated
   operator identity, delegation artifact id,
   `delegation_verification_status`), landing with AuditStore's Postgres
   Wave-1 migration (plan 3b). Until Phase 5 produces real values these
   columns carry defaults; pre-enforcement rows use
   `delegation_verification_status=unverified` per ADR-1005's
   incremental-shipping rule. The already-built 3a `principal_class` column
   is the early, delegation-independent half of this shape. **Delegated
   mutations are audit-fail-closed**, not set-and-proceed: if the audit row
   cannot be persisted, the mutation does not execute — the platform's
   set-and-proceed posture elsewhere (machine-scope, low-sensitivity reads)
   does not extend to a delegated write acting under someone else's
   authority, and a denied-redemption audit-write failure additionally
   trips a dedicated `event="security"` metric (paging — an audit-write
   failure on the theft-detection signal itself is not routine), since
   that row is this design's primary theft-detection signal (§5 step 1)
   and cannot be allowed to fail silently during exactly the outage window
   an attacker would prefer. **Named action-prefix requirement:** every
   delegation and engine-principal-lifecycle audit action uses a
   dedicated prefix (e.g. `delegation.`, `engine_principal.`) distinct
   from the existing `auth.`/`mfa.`/`session.` set, and the sampled
   auth-log evidence export (`GET /api/v1/audit/auth-sample`,
   `AuditQuery.action_prefixes`) must add these prefixes to its scope as a
   named Phase-4/5 deliverable — without it, fully audited delegation
   ships with a complete trail an auditor's existing evidence-export tool
   cannot find.
6. **Quota** (Phase 8's full mechanism; the minimum per-principal cap is
   plan PR 4.4) **is debited on both sides of a delegated operation** — the
   engine principal's cap and the delegating operator's own action budget,
   where the operator has one. Debiting only the engine principal would let
   any one operator exhaust a shared module's budget and starve its
   autonomous sync; debiting only the operator would let the engine
   principal amplify past its own cap under delegation. The
   quota-exhaustion counter (PR 4.4) names which side was exhausted.
7. **Long-running delegated mutations re-authorize per dispatch tick**,
   not once at redemption — the same pattern the existing DeploymentEngine
   already uses for its own multi-device fan-out (re-resolving
   `devices_fn(viewer)∩cohort` every tick, skipping a target that lost
   scope mid-run). A delegation redeemed at the start of a long fan-out
   must not carry frozen authority across an operator de-scoping event that
   happens while the operation is still running; §5 step 2's
   fresh-at-redemption rule covers the *start* of the operation, this rule
   covers its *duration*.

**Wire surface: none.** Every mechanism above — issuance, exchange,
redemption, audit — is server-HTTP-surface only. No `.proto` change is
implied anywhere in this design: the agent-daemon's gRPC channel and the
gateway's `ProxyRegister`/upstream path are untouched (the Phase-1
gRPC on-behalf-of interceptor, already shipped, is a separate, unrelated
control). If a future module needs a gRPC bulk-egress surface, that falls
under ADR-1005's deferred streaming-egress decision, not this design.

## 6. Token-session attribution — branch on persisted kind, never inference

`ApiToken` gains a persisted **`principal_kind`** (`human` | `engine`), set
at creation, immutable thereafter. Legacy rows backfill `human` —
bit-for-bit preservation of current behavior. Plan Decision 9's rule is
adopted verbatim: session synthesis branches on the stored field, **never**
on the shape of the `principal_id` string (the reserved namespace in §3.3
is defense-in-depth and readability, not the discriminator).

`synthesize_token_session` becomes a two-branch function. The carrier is an
in-memory `Session` field only — no `auth.db` sessions-schema change, since
token sessions are already synthesized fresh per request rather than
persisted, so `principal_kind` needs no storage beyond the `ApiToken` row
it was read from:

- `principal_kind=human` (all existing rows): attribute to the creating
  user. If the token is service-scoped (`scope_service` non-empty), the
  role is floored to `user` regardless of the creator's live role — an
  `ITServiceOwner` RBAC grant is the sole authority ceiling for such a
  token (#3201, shipped after this design was written; closes a
  privilege-inheritance gap the original "re-resolve their current role"
  wording here didn't anticipate). Otherwise, unchanged from before this
  design: re-resolve the creator's current role.
- `principal_kind=engine`: the session **is** the engine principal —
  `username = principal_id` (the `engine:<slug>` id), `auth_source =
  "engine_token"` (a sixth value alongside
  `local|oidc|saml|api_token|mcp_token`), role/authority resolved from the
  engine's scoped assignments (§4) — `get_user_role` is never consulted
  (there is no user row to consult), and the legacy `Role` enum slot is
  pinned to `user` (floor; real authority comes from assignments). A
  **revoked or missing engine-principal row fails closed** — no session —
  distinct from a store-unreachable read (§3.1: retryable, not terminal).

**Named PR-4.2/4.3 sweep deliverable.** Six sites compare `auth_source`
today (`mfa_step_up.cpp`, `auth_routes.cpp`, `auth_db.cpp` storage-only).
One is instructive: `mfa_step_up.cpp`'s bearer-token step-up exemption
checks for `api_token`/`mcp_token` and falls through to a `mfa_status()`
lookup for anything else — `engine_token` hits that fallthrough today by
accident of the default branch, which happens to be the *correct* posture
(an engine session has no MFA-enrolled user to step up, so it fails closed
via `UserNotFound`, consistent with §9's structural denial). The design
requires this to stop being accidental: PR 4.2 (introducing the value) or
4.3 (building on it) must sweep all six `auth_source` comparison sites and
record, per site, that its default-branch behavior for `engine_token` is
the intended one — not merely that it happens not to crash.

Creation-time referential integrity: minting an `ApiToken` with
`principal_kind=engine` validates that `principal_id` names an `active`
row in `EnginePrincipalStore` — a token can never be issued against a
principal that doesn't exist or has already been revoked.

`principal_class` then reports `engine` truthfully at both consumers: the
HTTP request metric (plan PR 4.5 flips the reserved value live) and the
AuditStore column (3a — already built to receive it; its honest-empty rule
for non-HTTP writers is unaffected).

## 7. Credential lifetime and rotation

- **Ceiling: 90 days**, inherited from the MCP-token precedent — engine
  credentials can never be perpetual. `create` for `principal_kind=engine`
  rejects `expires_at = 0` or > 90 days, same enforcement point as the
  existing MCP cap in `ApiTokenStore::create_token`.
- **Secret hand-off (both initial mint and rotation), stated explicitly:**
  `create`/`rotate` return the raw credential value to the caller **exactly
  once**, in the API response — the same contract `ApiTokenStore::create_token`
  already uses for every token type today (the store persists only the
  hash). Getting that value into the running module's actual configuration
  (an env var, a mounted secret, a config push, an operator paste — this
  design is deliberately silent on *which*) is an operational step the
  operator performs, same as onboarding any first API token today; this
  design fixes the server-side contract (one-time reveal, hash-only
  storage), not the module's deployment/secret-management mechanism.
- **Rotation: overlap-pair, designed here, built in plan PR 4.3.** An
  autonomous host cannot tolerate a hard cutover the way a human clicking
  "new token" can, so `rotate` is:
  1. mint the successor credential (same principal, same expiry rules) —
     **both credentials valid** from this moment, secret handed off as
     above. **Idempotent, but bounded — not "until confirmed."** If the
     caller never receives the response (timeout, dropped connection) and
     the ≤2-active ceiling then blocks a naive re-mint, `rotate` called
     again **within a short grace window after the original mint** (the
     same short-window shape §5 uses for redemption retries, not "until
     the module presents the successor" — that condition is attacker-
     influenceable: a network-positioned attacker delaying the module's
     first use of the successor could otherwise keep the re-serve window
     open indefinitely) returns the same successor's value again, subject
     to two further controls: **every replay re-validates the caller's
     step-up authentication** (a replay is not exempt from the same
     admin-session + MFA gate §9 requires for the original call), and
     **every individual reveal — original or replayed — is its own
     audited secret-disclosure event**, not folded into one "rotation
     succeeded" row. Once the grace window lapses, a `rotate` call against
     an unconfirmed successor errors rather than re-serving — the caller
     must fall back to the compromise runbook (principal-level revoke) or
     an explicit re-mint, not an indefinite retry loop. The
     one-time-reveal contract's "once" means once per grace-bounded
     rotation attempt, never once per rotation lifetime and never
     unboundedly;
  2. bounded overlap window (default 7 days, admin-configurable downward;
     never past either credential's own expiry — **and rotation itself is
     rejected, not silently truncated, if the resulting window would fall
     below a stated floor**, e.g. 24h, since a truncated window the module
     never gets a chance to act within is a worse failure than a rejected
     rotate call) for the module to pick up and verify the successor. The
     server tracks each credential's last-used timestamp; if the successor
     has **never been presented** as the overlap window nears its end, the
     predecessor's scheduled auto-revoke is preceded by a warning — an
     audit row plus a metric (bounded `reason="successor_unused"` label,
     not `event="security"`; this is an operational health signal, not a
     theft signal, and pages once per rotation rather than sharing the
     theft-detection alert's channel). **Revised (governance UP-5):** a
     window is a ceiling on the OVERLAP, not a promise that auto-revoke will
     leave a usable credential — so auto-revoke is withheld, not fired, when
     the successor was NEVER presented at all (`last_used_at == 0`): a
     dropped rotate response or an operator who never picked up the new
     credential must not end with zero usable credentials, unattended. In
     that case both credentials stay active past the window and the warning
     is raised again on crossing into the elapsed state; the sweep will
     never resolve this pair on its own, so an operator must act explicitly
     — confirm once the successor genuinely is in use, or revoke the
     specific credential no longer trusted via
     `DELETE /api/v1/tokens/{token_id}` (never the terminal
     principal-level `DELETE /api/v1/engine-principals/{id}` — see the
     confirm-identity-durability bullet below for why). **Cadence, and it is
     NOT uniform across the three
     signals** (`rotation_warn_dedup.hpp`): the **log line** repeats every
     tick while the pair stays stuck; the **audit row and the metric** named
     above fire ONCE per pair per state — once pre-elapse, once more on
     elapsing — and the state is process-local, so a restart re-emits once.
     An earlier revision of this paragraph said they were "no longer
     deduplicated once elapsed"; that held only briefly, and the
     un-throttled row was itself the defect (~1440/day per stuck pair into
     the SOC 2 audit store, whose retention pass caps at 25 000 deletions).
     Indefinite loudness lives on the log channel; the alertable
     current-state signal is tracked in #2969. A successor that WAS
     presented at least once is unaffected by this carve-out — auto-revoke
     still fires for it at window end exactly as before;
  3. predecessor **auto-revokes** at window end (or immediately on operator
     confirm) — UNLESS its successor was never presented (bullet 2 above),
     in which case it stays active until an operator acts explicitly.
  - At most **two** active credentials per engine principal at any moment —
    a third mint is rejected until the overlap resolves (see the
    idempotency carve-out above for the retry case). Every step audits.
  - **Revocation during overlap is defined, not emergent:** revoking a
    *single* credential mid-overlap immediately invalidates that credential
    and resolves the rotation state (the survivor is simply the principal's
    one active credential; a fresh rotation may then begin). The
    **compromise runbook is principal-level revoke** — one operation kills
    *both* credentials and flips the principal's `lifecycle_state` to
    `revoked` (terminal — see §3.1), so an operator responding to a leak
    never has to reason about which of two credentials was the stolen one.
- **Confirm-identity durability (#2961, fixed).** The check in step 3 above
  that only the operator who called `rotate` may `confirm` originally
  resolved **only** from a process-local grace-cache map, so a server
  restart mid-overlap silently and permanently blocked `confirm` for that
  pair (the sweep still cut over on the timer, with no error surfaced —
  the record showed nothing amiss). `api_tokens.rotation_initiator`
  (migration v3) durably stamps the operator onto the successor row at
  mint time, inside the same locked transaction; `confirm_rotation` now
  resolves the identity check via `ApiTokenStore::resolve_rotation_initiator`
  — RAM first, the durable column as the restart-recovery fallback, fail
  closed on disagreement, empty never a wildcard. A pair already in flight
  when v3 shipped has no durable value and stays unconfirmable after a
  restart by design — that does NOT strand the principal: the T12 sweep
  (§7 bullet 3 above) resolves the pair on the timer PROVIDED the successor
  was presented at least once (`last_used_at != 0`) — the same UP-5
  carve-out that gates every other sweep resolution (§7 bullet 2 above). If
  the successor was never presented at all, the sweep never resolves this
  pair (by design — see the UP-5 carve-out), so the correct response is NOT
  to do nothing: either confirm once the successor genuinely is in use, or
  revoke the specific credential no longer trusted via
  `DELETE /api/v1/tokens/{token_id}` (an
  engine credential is an ordinary API token row; an admin may revoke any
  token) — **never** the principal-level `DELETE
  /api/v1/engine-principals/{id}` runbook above, which is terminal and
  destroys BOTH credentials plus the principal itself, not just the one
  side that needs discarding. The raw successor secret's short
  re-serve window (step 1 above) is unaffected and stays RAM-only, since a
  one-time reveal must not become durable. The human-token rotation feature
  (`docs/auth-architecture.md` "Human API-token rotation") shares this same
  fix — one chokepoint, both arms.
- This is the platform's first rotation workflow (the gap matrix in
  `.claude/skills/auth-and-authz/SKILL.md` lists token rotation as missing
  for all types); the design is deliberately credential-generic so the
  later human-token rotation feature can adopt it unchanged.

## 8. MCP tier applicability

**Reused, hard-locked `readonly` for v1.** Engine credentials carry
`mcp_tier=readonly` — the creation API *rejects* any other tier while
plan Decision 1's read-only/autonomous scoping holds. Rationale: the two-gate
(tier-then-RBAC) ordering at ~28 MCP sites is exactly the defense-in-depth
this principal class most needs; discarding tier for engine principals
("defer to RBAC") would remove the second gate from the widest-read-scope
principal, and allowing `operator|supervised` now would hand a read-only-by-design
principal a write-capable tier the moment an assignment slips. Unlocking
higher tiers is a **Phase 5 decision**, taken together with delegation —
where `supervised`'s approval-ticket flow is the natural fit for delegated
mutations.

## 9. Self-target destruction guard

- **Phase 4 — structural posture.** Engine principals cannot reach
  principal-destruction surfaces at all: default-deny + the §4.2 admin bar
  means no engine session can hold `UserManagement:*`/`Security:*` grants
  on principal-lifecycle routes, and the engine-principal lifecycle surface
  itself (create/rotate/revoke/transfer-owner) requires a **human admin
  session + MFA step-up** (same posture as the existing 11 step-up
  surfaces). One defensive addition: those routes deny any engine-classed
  session outright (fail-closed belt to the structural braces), audited as
  `denied` — keyed on the session's **principal kind** (the persisted
  discriminator, §6), with `auth_source="engine_token"` as a second belt,
  so a future second engine authentication path cannot silently bypass a
  string-keyed deny.
- **Phase 5 — re-key on effective identity.** Once delegated mutations
  exist, the guard's comparison re-keys on the **effective delegated
  identity** (ADR-1005 Decision 5's named extension): a delegated operation
  targeting the *delegating operator's own* account or the *acting engine
  principal itself* is rejected exactly as a human self-target is today.
  The §3.3 reserved namespace guarantees the string comparison stays
  collision-free across classes.

## 10. Hand-off to 2c — plan Decision 14 confinement candidates

2c owns the choice; 2b supplies the candidates and the evaluation criteria.
The invariant to satisfy (plan Decision 14): a group-confined operator's
findings view shows the same device set `/devices` would show them — never
more — and per §3.4, authorized *as that operator*.

| Candidate | Sketch | Against the criteria |
|---|---|---|
| (a) View-time scoped read-through | Findings page render triggers per-operator reads to the Yuzu server, carrying a short-lived operator-bound artifact (the §5 primitive, read-purpose variant); server evaluates confinement via ADR-0017 | Server stays authoritative; zero staleness; per-view latency + server load; needs the §5 artifact early |
| (b) Identity assertion / session exchange | Operator's browser obtains an operator-bound artifact from Yuzu; UCE backend exchanges it for a scoped read context covering the view session | Same authority + freshness as (a) with fewer round-trips; more moving parts (exchange endpoint, context lifetime) |
| (c) Synced confinement predicate | Per-operator scope predicate synced alongside findings, re-validated on short TTL | No view-time server dependency; but confinement is evaluated *by the UCE* against a cached predicate — weakest fit for both "server authoritative" and the never-stale requirement (plan Decision 14 itself warns the shared access layer is explicitly a cache). It also fails ADR-1005's own mechanism-vs-interpretation boundary test: confinement is authorization *mechanism*, and (c) relocates that mechanism's evaluation into the UCE — an interpretation-layer component — rather than keeping it server-core, which (a)/(b) both preserve by construction. |

Evaluation criteria (in order): server remains the confinement authority;
staleness window ≈ 0 (a scope change takes effect at next view); per-view
identity preserved in Yuzu's audit; operational cost at fleet scale.
**2b's recommendation: the (a)/(b) family** — both reuse the §5 delegation
artifact as their identity primitive, which is why its shape is fixed now.
(c) should only survive 2c if a concrete latency/scale constraint defeats
(a)/(b), and then only with a TTL bound stated in the requirements doc.

Other onward hand-offs: internal-vs-external classification mechanics (plan
PR 4.3 named deliverable; store field reserved in §3.1), quota beyond the
minimum cap (Phase 8; interlock #1973 closes at plan PR 4.4), ADR-0017
ladder sequencing + #1715 deny-precedence decision (maintainer).

**Additional named hand-offs, so they aren't rediscovered independently:**

- **Periodic access reviews** (`.claude/skills/auth-and-authz/SKILL.md`
  gap-matrix Priority-1 item, currently unbuilt): when that export ships,
  it must enumerate `principal_type IN (user, group, engine)` — the
  `justification`/`owner_username` fields this design adds to
  `EnginePrincipalStore` (§3.1) exist specifically to feed it, and an
  export built against user/group only would silently exclude the
  principal class most in need of review.
- **Skill gap-matrix rows.** `.claude/skills/auth-and-authz/SKILL.md`'s
  token-rotation (item 88-region) and service-account-governance
  (item 92-region) rows currently read flatly "MISSING." Once this design
  is accepted, both rows need a forward annotation — "design complete,
  `docs/auth-engine-principals-design.md`; implementation Phase 4/5" — so
  a reader of the matrix alone doesn't either miss this design or mistake
  the SKILL.md cross-reference already added (§5) for shipped closure.
- **Customer-assurance narrative (SOC 2 Workstream G).** Plan Decision 13
  names the pilot-readiness note and shared-responsibility-matrix update
  as Workstream-G-owned and still unwritten. This design is their input,
  not their author — but 2b's own trail should say so explicitly rather
  than silently assuming the exec plan's mention is enough: when Workstream
  G writes that material, it consumes this doc's identity/delegation/audit
  model as its technical basis.
- **Engine-principal onboarding walkthrough** (user-manual deliverable,
  not this internal design doc): §7's secret hand-off is deliberately
  silent on deployment mechanism, which is the right scope boundary for
  2b — but a pilot admin's first friction point will be exactly that gap.
  Name a worked onboarding walkthrough (mint → one-time reveal → get the
  secret into the module, with at least one concrete example) as a
  required deliverable against plan PR 4.3 or the pilot-onboarding
  playbook, not something discovered fresh at Phase-4 ship time.
- **Enterprise parity plan.** `docs/enterprise-parity-plan.md` has no
  service-account/machine-principal capability row today; once this
  design ships, it is the capability that row would credit. Whoever next
  updates the parity plan should cross-reference this doc.

## 11. Phase-4/5 PR mapping

| Piece (this doc) | Ships in | Notes |
|---|---|---|
| `ApiTokenStore` → Postgres, + `principal_kind` column | plan PR 4.1 | Backfill `human`; hash-only, no SecretCodec needed |
| `EnginePrincipalStore` (§3.1) + reserved namespace (§3.3) + upgrade-migration collision scan + `/readyz` row + ops-runbook entry | plan PR 4.2 | With `principal_type='engine'` RBAC value, the assignment-authoring surface extension AND the role-collection resolution-site extension (both §4.1, both named PR 4.2 deliverables, not assumed side effects), `synthesize_token_session` branch (§6) + `auth_source="engine_token"` + the six-site sweep (§6) |
| Lifecycle surface: create/rotate/revoke/transfer-owner (incl. admin-forced owner transfer), REST + MCP + admin-console page; §7 rotation (incl. secret hand-off contract, bounded-and-reauthenticated idempotent mint, window-floor rejection, last-used tracking); §9 Phase-4 guard posture; §4.2 structural bars + auditor-runnable no-admin verification query; owner-delete blocking (§3.1) | plan PR 4.3 | Human-admin + step-up gated; classification mechanics decided here (required-at-creation per §3.1); onboarding walkthrough is a paired user-manual deliverable |
| Per-principal quota cap + exhaustion counter (bounded `side` label), dual-side debit under delegation (§5), delegation-artifact issuance-rate cap alongside the outstanding-count cap | plan PR 4.4 | Closes #1973 |
| `principal_class=engine` live on metrics | plan PR 4.5 | 3a audit column already receives it |
| Scoped role assignments resolution (§4.1) at the chokepoint | **ADR-0017 PR-A**, charter amended or a named follow-on PR to cover `principal_type='engine'` — maintainer's choice, see §4.3 | Gates Phase 5 and real 3-D confinement; exec-plan Phase-5 gating needs a matching amendment (§4.3 follow-up) |
| Delegation artifact issue/exchange/verify incl. atomic idempotent redemption + per-tick re-auth (§5); guard re-key (§9); full audit shape producers with a dedicated action-prefix (scoped into the sampled-evidence export); audit-fail-closed on mutations (§5); delegation-artifact store `/readyz` row | Phase 5 PRs | Gated on 3b (audit schema) + Phase 4 + ADR-0017 PR-A |
| Periodic access-review export enumerating `principal_type IN (user, group, engine)`; SKILL.md gap-matrix forward annotations (done, this commit); Workstream-G customer-assurance narrative + enterprise parity-plan cross-reference | Cross-cutting, not this program's PRs | Named hand-offs (§10) so they aren't rediscovered independently |

## 12. Decision log

1. Dedicated `EnginePrincipalStore` over token-row columns or `users`-table
   reuse — identity outlives credentials; soft-retain + owner/justification
   don't fit either alternative. Declared authoritative/fail-hard (ADR-0012),
   with store-unreachable kept observably distinct from missing/revoked
   (retryable vs terminal, UX/retry-behavior only — never an authorization
   downgrade) — conflating them risks a transient outage reading as
   credential death. Named `/readyz` + ops-runbook deliverables so the
   distinction has an operational signal behind it. `EnginePrincipalStore`
   lands in PR 4.2, sequenced immediately after PR 4.1's `ApiTokenStore`
   migration. Owner-delete blocks (409) while ownership is active, with an
   admin-forced transfer that never depends on the outgoing owner's
   cooperation. Revoke is terminal; any tooling joining across a
   `superseded_by` chain must surface the revocation cause, never present
   a seamless merged history.
2. Per-module principal granularity — least-privilege blast radius; a
   defensive advisory slug-binding check guards against host-level
   credential misconfiguration across co-located modules.
3. Reserved `engine:` namespace with creation-time rejection at every
   identity-surface (users AND locally created RBAC groups) — identity
   collision made impossible rather than unlikely. The PR 4.2 migration
   itself scans for pre-existing colliding names rather than allowing
   silent coexistence.
4. One scoped-assignment model for all principal classes (no engine-only
   grant table) — a second resolution path is a standing consistency bug.
   Two PR-4.2 deliverables named explicitly so this doesn't ship inert:
   the assignment-*authoring* surface, and the role-*resolution* query's
   extension to a third `principal_type` (today hardcoded to user/group).
5. ADR-0017 PR-A promoted to named critical-path prerequisite — with the
   charter delta stated explicitly (PR-A as chartered resolves user/group
   only; extending to `engine` is either PR-A's own amendment or a named
   follow-on PR, maintainer's call) and a follow-up filed to align the
   exec plan's Phase-5 gating with this dependency.
6. RFC 8693 delegation shape; artifact is opaque, audience/purpose-bound,
   short-lived, single-use-and-idempotent for mutations (a same-credential
   retry returns the original's persisted response via an atomic
   consume-claim — never a re-invocation, never a double-execution race;
   a different credential is the theft signal), read-purpose artifacts are
   bounded-reuse not unbounded, capped in both outstanding count AND
   issuance rate; authority intersects at the decision level (never
   row-level, to respect #1715 deny precedence), never unions; operator
   authority resolved fresh at redemption and re-checked per dispatch tick
   for long-running operations; quota debited on both sides; delegated
   mutations are audit-fail-closed with a paging theft-detection signal
   distinct from the idempotent-replay path's routine log; a dedicated
   audit-action prefix is named so the existing sampled-evidence export
   can be scoped to include it.
7. Attribution branches on persisted `principal_kind` only (plan Decision 9
   adopted); `auth_source="engine_token"` added with a named six-site sweep
   requirement; revoked principal ⇒ fail closed, distinct from
   store-unreachable; creation-time referential check against an active
   `EnginePrincipalStore` row.
8. 90-day ceiling + overlap-pair rotation (≤2 active credentials, secret
   re-serve on retry bounded to a short grace window — not "until
   confirmed," which an attacker could indefinitely extend — with
   step-up re-validated and each individual reveal independently audited;
   window-floor enforced; last-used tracked with a pre-auto-revoke
   operational-health warning distinct from the theft-detection alert
   channel); one-time-reveal secret hand-off contract matching
   `ApiTokenStore::create_token`'s existing shape; principal-level revoke
   is the compromise runbook and is terminal (recovery mints a
   `superseded_by`-linked successor); rotation designed credential-generic.
9. MCP tier reused, hard-locked `readonly` until Phase 5 revisits with
   delegation.
10. Self-target guard: structural denial in Phase 4, effective-identity
    re-key in Phase 5.
11. Plan Decision 14 recommendation to 2c: operator-bound-artifact family
    ((a)/(b)); synced-predicate (c) only under a stated, TTL-bounded
    constraint, and noted as the weaker fit against ADR-1005's own
    mechanism-vs-interpretation boundary test.
12. Classification (`internal`/`external`) required at creation, not
    silently defaulted — `external` is a backfill/omission fallback only,
    itself audited and metered when exercised.
13. "No admin, ever" and "no all-permissions toggle" get a named
    auditor-runnable verification query (PR 4.3/4.4), not just trust in
    the write path — an auditor should never have to take enforcement code
    on faith when a report can prove the zero-admin invariant directly.
14. Compliance/enterprise hand-offs named explicitly rather than left
    implicit: periodic-access-review export must enumerate the `engine`
    principal type once built; the SKILL.md gap-matrix rows this design
    answers get a forward annotation, not just a cross-reference; the
    Workstream-G customer-assurance narrative and the enterprise
    parity-plan both consume this design as their technical basis; an
    engine-principal onboarding walkthrough is named as a user-manual
    deliverable distinct from this internal design doc.
