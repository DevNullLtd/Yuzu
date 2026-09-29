---
status: accepted
date: 2026-07-13
owner: "@dgr (Dave Rae)"
deciders: >-
  Ratified 2026-07-14 by @dgr and the engineering colleagues, via the access-control ballot
  (A1–A5, D1–D12, pins P1–P11, open questions G1–G10). Independent review of record (SOC 2
  Workstream F change-management evidence): a two-reviewer adversarial review (findings S1–S11,
  three blockers, all closed by this ADR set), a convergence pass over the finished set, and an
  overclaim sweep. Open questions G1 (cross-process event transport), G6/G7 (MCP session and
  replay-ring placement) and G10 (the Drogon build canary) remain open by design and are named
  as prerequisites, not resolved by this acceptance.
scope: platform — process decomposition, the seams between the three binaries, and the invariants they exist to make structural
supersedes: >-
  docs/uce-deployment-topology-design.md D2 (UCE deployable = backend + GUI, one artifact, on its
  own VM), D3 (two browser origins) and §3 (the cross-origin login/redeem design) — all merged via
  PR #2079. D1 (one PostgreSQL instance, two databases, separate roles and pools) is REAFFIRMED,
  not superseded, and becomes MORE load-bearing.
  docs/uce-host-requirements.md: F-10 ("no machine consumer; private UI seam") is VOIDED — its
  premise disappears with the engine's UI. F-5 / F-6 / F-7 / §6 (the engine's own view-time
  confinement mechanism) and INV-6 / INV-7 (the M3(d) equivalence test) are RELOCATED, not deleted —
  confinement moves INTO core (INV-31-2 + ADR-0032 Decision 11); see "INV-7 moves, it does not
  vanish". NF-9 (engine login/session/origin) is VOID in its entirety; NF-3, NF-7 and NF-8(vii) are
  RE-SCOPED (a headless engine has no browser origin, no login and no session); NF-2, NF-5, NF-6
  stand.
  docs/adr-1005-execution-plan.md: Decision 3 ("no machine consumer of the UCE; the private UI
  seam") is VOIDED; Decision 11's "backend + GUI, one artifact, on its own VM" is SUPERSEDED;
  Decision 14 and M3(d) are RETARGETED (the confinement mechanism is core's release gate, not a
  module-side re-derivation — the M3 parity gate itself SURVIVES); Phase 5 is PARTIALLY PULLED
  FORWARD (the invocation grant IS the RFC-8693 delegation artifact, not a second token species).
  docs/adr/1005-headless-platform-use-case-engines.md: Decision 6's "UI shell" clause is AMENDED —
  the engine host is headless; the rest of Decision 6 (one host, many modules) stands. Decision 7's
  break-glass console survives but re-homes: see Decision 6a below.
depends-on: >-
  1005-headless-platform-use-case-engines (this ADR is how its central claim becomes structurally
  true rather than review-enforced).
related: >-
  0032-use-case-admission-protocol (the normative admission/grant/evidence protocol this
  decomposition's Decision 4 delegates to).
  0033-access-control-spine (the platform-wide authority, approval and Execution-Plan spine both
  of them enforce against).
  0034-held-open-connection-scaling (this decomposition is what makes ADR-0034's durable fix
  reachable: presentation becomes a separate binary, so its runtime is a free choice).
  docs/adr-1005-execution-plan.md Decision 3 (the machine surface — voided by this ADR), track 2c,
  track 2d, Phase 5 (server-issued delegation), track 2g (A5 annotations), issue #2056.
---

# ADR-0031 — Presentation, core and engines are separate binaries

## Binding status

Nothing here binds reviews or blocks PRs until this ADR's status is **accepted**. On acceptance the
Decisions and Invariants bind **prospectively**, and the migration below is the order in which they
become true. ADR-0032's sequencing interlock binds *immediately* on acceptance — a precondition can
only be honoured before the code exists.

## Terms and tag families

This ADR set is the output of a ballot, four grill rounds and an adversarial review, and it carries
their tags as **provenance labels**. The tags are not a dependency: every rule they label is stated
normatively in one of these ADRs. Because three of the families collide with identifiers already in
the tree, they are always written with their family:

| Family | Means | Do not confuse with |
|---|---|---|
| **ballot A1–A5** | the five architecture ratifications (A5 = the split control/data plane) | **agentic-first A1–A5** (`docs/agentic-first-principle.md`: dashboard parity, discovery, observability, the error envelope, and **A5 — the agentic context contract**). The collision is total, so ballot rows are always written "ballot A*n*". |
| **ballot D1–D12** | the twelve product/access decisions (D3 = presentation as a credential pipe) | **2c D1–D3** (the merged topology design: one Postgres/two databases; engine's own VM; two origins) |
| **pins P1–P11** | the admission-protocol semantics pinned in the grill rounds | — |
| **G1–G10** | grill-round questions against the ballot. **Most were answered and became rules** — G2 → INV-31-5, G3/G9 → ADR-0033 §2, G4 → ADR-0032 Decision 15, G5 → the version-skew cost, G8 → ADR-0033 §3. **Still open by design:** G1 (cross-process event transport), G6/G7 (MCP session + replay-ring placement), G10 (the Drogon build canary). | — |
| **S1–S11** | the 2026-07-14 adversarial-review findings | — |

Vocabulary, fixed for the set: an **engine** is a use-case engine binary (the 2c documents call it
the **UCE**; the terms denote one thing). A **module** is a use-case module activated inside an
engine. **Core** and **presentation** are the other two binaries. A **run** is one admitted episode
of one use case (ADR-0032).

## Context

**Today the server is one binary that is both the domain and its own front end.** Twenty-five route
families register on a single `httplib::Server` inside `yuzu-server` — REST v1, MCP, the HTMX
dashboard, settings, workflow, device, viz, DEX, Guardian, inventory, preflight, deployment,
network, CA, SCIM, webhooks, software licensing and the rest (`server.cpp`'s `register_routes` call
sites; the count grows with every feature, which is the trend this ADR is about). The dashboard
renderers can reach stores in-process.

That means ADR-1005's central claim — *no UI-only capabilities; a dashboard fragment is not an API
twin* — is a **rule enforced by review**. The `consistency-auditor` asks the standing question on
every capability-adding PR, and it asks it because nothing in the build prevents the answer being
wrong. A rule that can only be enforced by remembering to enforce it will eventually not be.

**And the 2c topology, as merged, has been producing damage.** Putting the engine on its own VM
*with its own GUI* (D2) forced three things:

1. **Two browser origins** (D3) — cross-origin artifact acquisition and hand-off, by construction.
2. **The engine re-implementing ADR-0017 confinement** (F-5, INV-7) — per-render, over the
   operator's confined device set, including which CVEs are even *visible* and every count — and
   then being graded against what `/devices` would have shown, by an M3(d) equivalence test that is
   a **hard interlock gating M3 acceptance and Phase 6**. The engine is rebuilding a mechanism the
   core already has, and being marked on whether it got the same answer.
3. **F-10 — "no machine consumer; private UI seam."** Because the engine's only external interface
   is a human UI, **an agentic worker cannot read a single vulnerability finding.** The platform's
   flagship agentic capability — an LLM-driven client triaging CVEs and dispatching the patch — is
   human-only on the first use-case engine we ship. The module's own machine-callable
   `confirm-now` action is already logged as an unresolved reconciliation item against it.

Each of those is a reasonable local decision. Together they are a decomposition telling us it is
wrong: three governed problems, all downstream of *where the UI lives*.

Separately, ADR-0034 recorded that cpp-httplib is thread-per-connection, so every held-open SSE
response pins a worker thread for its life — and that the durable fix is to stop owning a thread
per stream.

**How this ADR reached its present shape.** The first draft made core the byte path for engine
invocation. A colleague reconciliation memorandum and a counter-proposal both argued that this buys
audit coverage at the cost of making core parse, relay and re-assemble every engine request and
response — and that the property actually wanted is *control-plane mediation*, not *data-plane
proxying*. Four grill rounds and a Kimi+Codex adversarial review followed. **Decision 4 below is the
reconciled shape** (ballot A5); the earlier byte-path shape is recorded in Alternatives, because it
is the alternative most likely to be re-proposed.

## Decision

**1. Three kinds of binary: presentation, core, engine.** One fused binary today; co-located as
three components on one host is the initial target of this decomposition, independently deployable by
construction, with no code change required to move any of them to its own host. Responsibilities are
stable even if the deployment shape later changes.

**2. Core owns the API and is the sole authority.** Authentication, RBAC, tier policy, scope
confinement (ADR-0017), approvals, protected effects, audit, fleet truth and the engine-capability
registry all live in core. Every other component may **narrow** authority; none may **enlarge** it.
The platform-wide spine that expresses this is ADR-0033.
This is authority over the *mediated protocol*: every authorisation decision, every fact release,
every effect. It is **not** a claim of containment over plaintext an engine already holds. Data core
has released into the `uce` database persists there under the engine's own retention, so the engine
stays inside the confidentiality TCB for what it retains (INV-31-2's receive-vs-retain split;
ADR-0032 Decisions 7 and 15). "Sole authority" means nobody else may *create* authority, not that a
compromised engine can disclose nothing - and the offline RBAC-recovery / first-admin tool (6a) is
**core's own** authority-mutating mode under filesystem-owner authorisation, reusing core's validation
and evidence, not a second authority-creator.

**3. Presentation is a transport-and-render adapter.** It terminates HTTP, SSE and MCP, frames
protocol, renders the HTMX dashboard, and holds live connection state — and it reaches the domain
**only** through core's API, exactly as any external client does. The GUI becomes just another API
client.
**"Core's API" means the public, versioned API — nothing else** (grill decision, 2026-07-13; ballot
A4). Presentation holds no private endpoints on core; a gap discovered while porting a dashboard
fragment is, by definition, a missing public capability — the forcing function working as designed.
Where rendering wants batch or composite reads, those are added to the **public** surface (agentic
workers want them too); any exception goes in ADR-1005's exception ledger, not in a side API.

**4. Engines are headless capability providers, and invocation splits the control plane from the
data plane** (ballot A5). An engine has **no UI and no machine surface of its own**; its Use Cases
and schemas register into core's capability catalogue at module activation, and clients discover
them through the one public catalogue.

Invocation works like this, and only like this:

- **Core admits the run.** Presentation calls a public, versioned core endpoint with
  `use_case_id@version`, module version, the raw inputs and the requested scope. Core authenticates
  the stable principal, resolves RBAC, applies token attenuation and scope, evaluates risk tier,
  computes the normalised-input hash itself, and writes an admission or a denial audit row.
- **Core mints a bounded grant.** Short-lived and **audience-bound**, binding principal, engine and
  module and use-case versions, input hash, scope ceiling, risk tier and expiry. It is the *same*
  RFC 8693 delegation artifact family as the engine-principal design (2b) — not a second token
  species. It is never self-authored by presentation.
- **Presentation calls the engine directly with the grant.** The engine rejects a missing, expired,
  wrong-audience or mismatched grant.
- **The engine reaches facts and effects only through core.** Every fact read and every capability
  request carries the run identifier and is independently confined by core, against the admitting
  operator's **current** authority — the grant's TTL gates run *start*, not the run's life.
- **The engine composes, and finalises.** It assembles results from the confined inputs core
  released to it, finalises the run with core (canonical result hash + disclosure summary), and
  **redeems the release authorization at core before the first byte moves** (ADR-0032 Decision 12).

One exception to "only like this", named here so the two ADRs cannot be read as contradicting each
other: serving a **cached** result skips the engine's composition step, but not core. It is a
fast-lane **re-admission** — core re-runs the confinement check, the engine redeems a one-use grant
**at core** before it releases a byte, and core writes the disclosure. The engine never serves stored
bytes on its own authority (ADR-0032 Decision 10).

The normative protocol — run lifecycle, grant semantics, the release log, cached-result
re-admission, evidence and the sequencing interlock — is **ADR-0032**. This ADR fixes only the
shape: core is the **admission and authority chokepoint, not the byte path**.

**5. Presentation runs on Drogon** (ballot A3, amended). An asynchronous, event-loop C++ framework
with coroutine handlers: it removes one thread per held-open stream — ADR-0034's durable fix —
without this project building a web framework on Boost.Beast, and without re-homing ~5k lines of
`mcp_server.cpp` and the HTMX renderers into another language. Presentation uses Drogon for
transport, framing and rendering **only**: not its ORM, not its session authorization, not its
business-logic facilities. The Erlang gateway stays exactly where it is — **southbound**, holding
agent connections; it does not move northbound.
**Gate G10:** a build canary — Drogon linked into the existing Meson/vcpkg matrix, MSVC static
linkage included — must pass before this leg is committed to. The `#375` history (grpc/protobuf/
abseil static linkage on Windows MSVC) is the reason this is a gate and not an assumption.

**Size this honestly: G10 gates the linkage, not the port.** Choosing Drogon avoids a *language*
port — the C++ stays C++ — but it is still a **framework** port. Every handler registration across
the 25 `register_routes` families, the `*_ui.cpp` renderers, and the 5k-plus lines of
`mcp_server.cpp` move from `httplib::Server`'s synchronous `Get`/`Post(path, handler)` signature to
Drogon's async/coroutine controller model, and **every SSE content-provider is rewritten against a
different concurrency model** — which is exactly the code whose semantics this ADR set cares most
about. This is the **largest single item in the decomposition** and it needs its own estimate. "It
ports across" is true of the language and false of the effort.

**6. Isolation is enforced as if remote, from day one.** Components authenticate to each other over
the network protocol even when they are co-located. **Co-location is a deployment default, not the
mechanism** — nothing in the design rests on it, which is why any component can move to its own host
with no code change. Three invariants are what make that true, and they are load-bearing precisely
because co-location makes it tempting to skip them: authenticate over the network protocol even on
localhost; the public versioned API only (INV-31-4); and **no cross-component database access**
(INV-31-3) — the engine never touches the `yuzu` database, core holds no grant on `uce`, and
**presentation owns no database at all**. ADR-1005's `REVOKE CONNECT … FROM PUBLIC` + separate-role
isolation (2c D1) is reaffirmed and becomes *more* load-bearing, because co-location removes the
network as an accidental barrier.

**6a. Core keeps a break-glass ingress of its own — and it is a door, so it is built like one.**
ADR-1005 makes the in-server console a deliberately closed set of bootstrap and recovery capabilities
that must work with **zero dependency on any engine** — the thing you use when everything else is
broken. The split quietly puts it behind presentation, so a presentation failure would lock operators
out of RBAC and principal management *during an incident*, which is precisely when they need it. So
core exposes a **minimal break-glass surface** — authentication, RBAC and principal administration,
health — reachable without presentation.

This is a **fleet-administration ingress**, which means naming its posture here rather than
discovering it later:

- **It authenticates and authorises exactly like every other ingress.** Every applicable filter in ADR-0033 §1
  applies, every approval gate applies, `on_behalf_guard` applies, and the audit posture is the
  platform's. **No filter and no gate is skipped because the surface is called "break-glass".** It is
  not a private core API (INV-31-4 stands): it is the *same* authority, reachable by a second door.
- **It inherits `docs/auth-architecture.md`'s hard invariants** — TLS, the standard header bundle, the
  A4 error envelope, session/CSRF handling, lockout and rate limiting. NF-9 (the engine's login and
  session security requirements) was voided with the engine's GUI; **its ingress-security *class* does
  not disappear, it re-homes here.**
- **It binds to loopback by default**, and exposing it on a network interface is an explicit,
  documented act.
- **Every use is loud**: a security-relevant audit event on every request, not merely on failure.
- **And the question that actually matters, decided rather than deferred: break-glass does NOT
  operate when core's auth/RBAC store is degraded.** If it did, it would be an unauthenticated
  fleet-administration door — and "the auth store is down" is exactly the condition an attacker would
  induce to open it. So be precise about what 6a delivers: it survives **presentation** failure, not
  **authority** failure. A break-glass door that opens when the lock breaks is not a safety feature.
- **"Degraded" is a testable predicate, not a feeling** — an undefined one becomes whatever the first
  incident invents, under pressure, with no gate. It means: the auth/RBAC store is **unreachable**, or
  **fails its integrity check**, or reports a **migration/schema mismatch**. In any of those states
  core fails closed (the posture table below) and 6a refuses like every other surface.
- **A successfully-migrated but EMPTY store is healthy, not degraded** — and this distinction is load
  bearing, because the tempting hole is right here: *"no principals exist yet, so let the first caller
  create one."* That is an unauthenticated fleet-administration door with a friendly name, and an
  attacker who can reach a freshly-provisioned server would walk through it. **6a has no
  unauthenticated mode, ever, including at first boot.** First-admin seeding is the same offline,
  operator-at-the-console tool as recovery — which is the right authorisation boundary, because
  someone with filesystem access to the host already owns the machine.
- **Which leaves a real question answered honestly: what recovers a corrupted RBAC store?** Not a
  network endpoint — an **offline, operator-at-the-console tool**, run with filesystem access to the
  host, which is its own authorisation boundary (if an attacker has that, they have the machine). It
  carries the same evidence obligations as anything else that mutates authority: it writes an audit
  record, and the record survives the recovery. Naming the tool and its evidence contract is a
  deliverable, not a footnote — and inducing the degraded state is therefore a hard platform DoS
  against recovery-by-API, which is the correct trade (fail closed) but **must be alerted on**, not
  discovered.

**7. One PostgreSQL instance, two databases, in its own sibling container** (2c D1, reaffirmed;
ballot A2). Same host as the three binaries today; separate roles, separate pools, no cross-database
grant.

**8. Every seam is a versioned contract.** Running on the same host does not remove the need for
one. The seam inventory is normative:

| Seam | Boundary | Contract |
|---|---|---|
| **B1** | Operator → presentation | One origin, one discoverable product surface for people, REST clients and MCP clients. Transport authentication on every request. Presentation never accepts a caller-authored "act as" identity. Carries: `credential · channel · correlation_id · request_deadline · client_protocol_version`. |
| **B2** | Presentation → engine (Use Case request) | Channel-neutral, versioned, separately published. Presentation passes a **core-verifiable grant**, never a self-authored identity. Result carries facts, coverage, provenance, decisions, any proposed plan reference and the **finalisation receipt**, and only bytes the engine has had core release via a redeemed **release authorization** (ADR-0032 Decision 12). Carries: `use_case_id@version · module_id@version · normalised_inputs · grant · request_id · result_schema_version · finalisation_receipt`. |
| **B3** | Presentation → core (platform request) | The public, versioned core API — used for admission, platform administration, direct expert operations and **all** core reads. Core validates the real credential and remains the source of every security decision. Carries: `principal_credential · securable · operation · scope · correlation_id`. |
| **B4** | Engine → core (facts, capabilities, effects) | On the **public, versioned core API** — INV-31-4 admits no engine-only private surface either. The engine reads fleet facts through typed core capabilities, confined per read. For protected effects it submits an immutable **Execution Plan** (ADR-0033); core verifies plan hash, capability versions, scope, and **every applicable filter of ADR-0033 §1**: the **engine principal's** own grants (authenticated actor), the **admitting operator's** current authority (represented operator), the **requesting credential's** current grants, the module envelope, and the execution authorisation. It also **finalises** each run and **redeems the release authorization** here (ADR-0032 Decision 12), so no result byte leaves the engine without a core-adjudicated release. Carries: `plan_id · plan_hash · use_case_run_id · module_manifest_hash · capabilities[] · parameters[] · scope · fact_refs[] · expiry · provenance · finalisation_receipt · release_authorization`. |
| **B5** | Engine → `uce` database | The engine role connects only to `uce`. A `uce_system` schema holds host state; each module gets its own schema and migration ledger. Core has no grant here. Carries: `module_schema · migration_version · journal_id · derived_state_version · retention_class`. |
| **B6** | Core → `yuzu` database | Identity, authorisation, fleet truth, execution state, audit. The engine has no grant here. Cross-application data is exposed through a **core capability**, never a SQL view shared across roles. Carries: `principal · grants · fleet_fact · execution · pending_command · retry · audit_event`. |
| **B7** | Core → gateway → agent | Core sends already-authorised commands with stable identities, deadlines and idempotency keys. The gateway routes and applies backpressure without becoming durable. The agent suppresses duplicates and returns correlated results. Carries: `execution_id · command_id · idempotency_key · target_agent · deadline · payload_schema · result_schema`. |

## Invariants

Named, so that a future change can be tested against them rather than argued with.

**INV-31-1 — Presentation is a credential pipe, never an identity authority** (ballot D3). It
forwards the caller's real credential, the channel, a correlation id and infrastructure metadata. It
never asserts a user identity, never mints a grant, and never makes a permission decision. This is
the same sentence structure as the on-behalf-of ban (ADR-1005): an ingress surface that could assert
who you are is an ingress surface that will.

*The honest TCB statement.* This does **not** mean a compromised presentation is harmless.
Presentation terminates the client protocol, so it **is inside the bearer-credential trust boundary
for the traffic it handles**: it can replay any credential it sees, and core's audit will attribute
the resulting action to the legitimate user. The **fused server has exactly this exposure today** —
the split neither creates nor removes it. What the split buys is narrower and still worth having:
presentation cannot *enlarge* authority, cannot reach a store, and cannot answer a question core
would have denied. The hardening path is recorded, not hand-waved: presentation exchanges the raw
credential at core for a short-lived, **presentation-audience-bound** session token (the same RFC
8693 artifact family as the invocation grant), so raw bearers stop persisting in presentation
memory. That is a **phased deliverable, not a v1 gate** — but the claim must be stated at its true
strength from now on.

**INV-31-2 — Core confines the inputs; the engine composes them** (the relocation of INV-7). Core
is the only component that decides which devices, which rows and which data classes an engine may
see, and it records that release at the moment of the read (ADR-0032's release log). The engine
therefore cannot disclose device data **core never released to it** — a real narrowing, and one the
engine cannot get wrong by re-deriving ADR-0017 badly, because it never re-derives it. Aggregation
and interpretation are the engine's job; confinement never is.

Two honest qualifications, because this invariant is the one most likely to be over-read:

- **Its mechanism does not exist yet.** Core's release gate *is* the ADR-0017 admit-then-filter
  chokepoint evaluated as the admitting operator — and `authorize_list_read` has **zero occurrences
  in the server tree** (ADR-0017 PR-A unbuilt; its open prerequisite is #1715, the global/group
  deny-precedence decision - #1716 is the closed doc-honesty companion, not this gate). Until that gate and its evaluate-as-operator seam land
  (ADR-0032's interlock, prerequisite (b)), this invariant is a specification, not a property.
- **It bounds what the engine *receives*, not what it *retains*.** Everything core has ever released
  to a module persists in the `uce` database — results, journal, and **derived state**. ADR-0032
  Decision 10 closes the stored-result path (a cached serve is re-admitted and subset-checked).
  **Derived state is an open gap**: a rollup computed under a wide run's release, read later inside a
  narrower operator's run, is not confined by anything in this set today. It must be closed —
  per-run provenance on derived rows, or a ban on cross-run derived state — **before a module
  persists its first cross-run rollup.** Naming it here so it is not discovered by a works council.

**INV-31-3 — No cross-component database access.** Decision 6, restated as an invariant because it
is the one a "just this once, for performance" patch will attack first.

**INV-31-4 — There is no private core API.** Decision 3, restated for the same reason. A build or
contract test **must** detect undeclared endpoints — enumerating every registered route and failing
the build on any that is absent from the published OpenAPI. **That test does not exist today**; it is
a deliverable of migration step 3, and until it lands this invariant is enforced by review, like the
rule it replaces.

> **Update (2026-09-08): the enumerate-every-route-vs-OpenAPI contract test LANDED** — out-of-band from
> the split delivery matrix, under **#842 / #3991 / #3992**. `scripts/ci/check-api-parity.py` is the
> whole-tree CI gate; `tests/unit/server/test_openapi_spec_completeness.cpp` is the in-process unit half
> (registers `RestApiV1::register_routes()` into a `TestRouteSink` and diffs against `openapi_spec_json()`,
> TSan-safe, no socket); #3992 backfilled 39 routes so the `/api/vN` baseline is drift-zero (1 allowlisted
> CORS `OPTIONS` catch-all). **Important — this is a LEXICAL tripwire, not a proof** (the gate's own
> docstring), and it scans `server/core/src/*.cpp` only (not headers). It matches literal
> `<recv>.<Verb>("/path", …)` registrations, and there are **three** cases, not one: (1) a literal verb
> call is checked and fails the build on a gap; (2) a non-literal **direct** verb call
> (`<recv>.<Verb>(runtime_expr, …)`) emits a CI `::warning::` and exits 0 — a loud escape; (3) a
> registration reached through a **helper** whose call site carries no `<recv>.<Verb>(` token (e.g. a
> `register_*(sink, "/path", …)` helper whose body makes the verb call), or defined **in a header**, is
> **invisible to the lexical gate — no warning, no failure**, a SILENT escape (the in-process
> `test_openapi_spec_completeness.cpp` backstops only the unconditional subset of
> `RestApiV1::register_routes`, not the `*_routes.cpp` mounts). So the escape is not always loud. The
> type-aware (clang-based) successor that closes all
> three indirection gaps is tracked at **#2572**. Today's tree is verified drift-zero, so this invariant is
> now enforced by a lexical test for literal registrations — stronger than review alone but short of
> INV-31-4's full "every registered route," and not a compensating control against a silent (3) escape.
> **What remains for WS-A4** (split matrix): the *per-family* seam+contract enforcement that gates the
> WS-B2 strangler cutover, the "handlers/renderers call the API, never a `Store*`" seam refactor, and the
> cutover-time removal of the presentation handler's now-redundant behavioural-PII audit call (see the
> 2026-09-10 update below — not one of these was #842's).
>
> **Update (2026-09-10): the FIRST per-family seam landed, on `network`.** `NetworkApi`
> (`server/core/src/network_api.{hpp,cpp}`) is an abstract in-process API whose method set equals the
> family's public REST resources (`fleet_now`/`device_list` == `GET /api/v1/network/fleet`/`GET
> /api/v1/network/devices`); the store-backed impl (`LocalNetworkApi`) is private, the header is
> store-dependency-free, and all three consumers — dashboard, REST, MCP — now call through it instead of
> the prior ad-hoc `net_perf_fn` provider. `scripts/ci/check-seam-closure.py` pilots include-closure
> enforcement for this family's dashboard/routes/model/API translation units (`rest_api_v1.cpp` and
> `mcp_server.cpp` stay inspected-not-enforced — multi-family TUs). This is the template the other ~36
> families copy; it is not yet a general refactor. **Correction to the "behavioural-PII audit relocation"
> phrase above**, verified against the tree: the audit was never in `*_ui.cpp` (pure render functions, no
> audit calls) — `emit_behavioral_audit` already lives centrally in `rest_audit.hpp`, called only from
> `*_routes.cpp`/`rest_api_v1.cpp`. "PII-audit relocation" means removing the presentation-side handler's
> audit call at the WS-B2 cutover once core's REST-side audit covers the same view (avoiding a duplicate
> row per view), not moving anything out of `*_ui.cpp`. No family has cut over yet, so this step has not
> been exercised.
>
> **Update (2026-09-11, #4249): the seam template split into abstract + core-only headers.**
> `network_api.hpp` now holds only the abstract `NetworkApi` interface (zero store references, not even
> forward-declared); the store-backed factory (`make_local_network_api`) and its store forward-decls
> moved to a new `network_api_local.hpp`, included only by the impl, `server.cpp`'s wiring, and tests —
> never by a presentation TU. `scripts/ci/check-seam-closure.py` gained a fourth forbidden pattern,
> `*_api_local.hpp`, so this boundary is CI-enforced, not conventional. This is the corrected two-header
> shape the remaining families copy.

**INV-31-6 — Every store that a component depends on appears in that component's readiness probe.**
Stated as an invariant rather than a habit, because the existing `stores_ok` conjunction in `/readyz`
grew one row at a time, and every row was added after a store died while the server reported healthy.
The split multiplies the problem: **core** `/readyz` = its stores + the Postgres pool. Note the run
reaper is **not** in the conjunction: once run expiry is enforced inline (`now < expires_at`, ADR-0032
Decision 4/5), a stalled reaper strands terminal evidence and cleanup, **not** read authority - and
`/readyz` drives load-balancer / rolling-upgrade routing, so pulling an authority-safe core instance
out of rotation for a janitor stall trades capacity for zero correctness benefit. The reaper's death is
covered by its named critical alert (`yuzu_use_case_reaper_last_success_timestamp`, Decision 5), which
is the right instrument. So a green core `/readyz` **no longer implies cleanup liveness**: accumulating
non-terminalised runs and unpruned release-log/grant rows are the reaper alert's concern, not the
probe's - a deliberate split of "can serve requests correctly" (the probe) from "is the janitor
running" (the alert). **presentation** `/readyz` = "core reachable at a compatible API version" (it
must never be green while core is down, or a load balancer will route traffic to a surface that can
only 502); **engine** `/readyz` = its own database + core reachable + module manifests ratified.
`/livez` stays process-liveness on all three. ADR-0032 and ADR-0033 introduce six new stores; none is
in a probe today, and ADR-0032's interlock item (k) is what stops that shipping.

**INV-31-5 — Presentation's service identity attests infrastructure, not people** (ballot G2).
Presentation authenticates to core with its own mTLS service identity and may attest peer IP and
correlation id (without which session peer-binding and lockout break). Core trusts that metadata as
**infrastructure metadata only**; it never trusts it as an identity claim.

## Failure and degraded-mode posture

| Failure | Required behaviour | Reason |
|---|---|---|
| Engine unavailable | Use Cases report unavailable. Core platform administration and already-authorised fleet execution continue independently. | A specialist application must not become a fleet-control dependency. |
| Core unavailable | No new protected operation proceeds. Engine results needing fresh authority or fleet facts **fail closed** rather than serving an unconfined answer. | Core is the only authority and the only source of fleet truth. |
| `uce` database unavailable | The affected module cannot start or advance a run. Core does **not** reconstruct engine domain state. | Avoids a hidden second owner of that state. |
| `yuzu` database unavailable | Authentication, authorisation and new state-changing work fail closed; health endpoints report the condition. | Every fleet effect must remain attributed and authorised. |
| Presentation unavailable | The product surface is down; the fleet keeps running. Sessions and replay survive — **once** they have moved behind the core boundary (their durability and location are G6/G7, open; see Costs; today they are in `AuthManager`'s memory). That move is decided *with* the split, not after it, precisely because this row is otherwise false. | Presentation is replaceable by design. |
| Gateway unavailable | Core retains pending commands and retry deadlines, every command identity unchanged. | Gateway state is disposable. |
| Endpoint reconnects after an uncertain result | Core may redeliver the same command identity; the agent suppresses the duplicate effect and returns the remembered outcome where it has one. | At-least-once delivery without repeated effect. |
| Partial distributed query | Return a coverage envelope, then apply the Use Case's completeness policy (ADR-0033 D11). | Missing evidence must never be read as a negative finding. |
| Audit or release log cannot persist | State-changing work fails closed. Reads keep **their surface's** posture (ADR-0033 §9) — with one tightening: engine reads of device-attributable data fail closed on **every** surface, MCP included (ADR-0032 Decision 14), and a failed release-log write fails that read closed (ADR-0032 Decision 11). | Prevents an unattributable mutation and an unrecorded disclosure. |
| External connector unavailable | Return a typed dependency failure and mark the result incomplete. Never substitute invented data. | Assurance depends on honest provenance and completeness. |

## Consequences

### The headless claim stops being a promise and becomes a property — but only half of it, and not yet

**What the process boundary really buys:** the GUI cannot reach a store **in-process**, because it
is a different process. Every dashboard capability must therefore exist as a core API endpoint.
That much *is* structural, and it is the point of the ADR.

**What it does not buy, and what a hurried reader will assume it does.** ADR-1005 parity is a bigger
claim than "no in-process store access": it is *every capability reachable via versioned REST **and**
MCP, discoverable, A4-enveloped*. The split leaves three ways to violate that, and the build detects
none of them today:

1. **A private core endpoint.** INV-31-4 forbids it; nothing enforces it. The contract test that
   would — enumerate every registered route (25 `register_routes` families, and the handler
   registrations under them) and fail the build on any not present in the published OpenAPI —
   **does not exist**. It is a deliverable of migration step 3. *(Update 2026-09-08: it landed — see
   the INV-31-4 update note above; `scripts/ci/check-api-parity.py` + `test_openapi_spec_completeness.cpp`,
   #842/#3991/#3992. This gap is closed for `/api/vN/*` only by a LEXICAL gate (literal registrations fail
   the build; a non-literal *direct* verb call warns; a helper- or header-defined registration can escape
   SILENTLY — see the INV-31-4 update note above; #2572); the per-family enforcement (one family,
   `network`, done as the pilot as of 2026-09-10 — see the INV-31-4 update note above), the handler→API
   seam refactor generally, and the cutover-time audit-removal halves of WS-A4 remain.)*
2. **A REST route with no MCP twin.** Structurally invisible to the build.
3. **A database grant handed to presentation or the engine.** Prevented by Postgres role
   configuration (2c D1), not by the compiler.

So: **the `consistency-auditor`'s standing question still carries the rule.** It is not retired by
this ADR — it is retired by the contract test, and until that test exists, saying "the build answers
it" would delete a governance control on the strength of a property the build does not have. The
deployment flexibility is a bonus; the parity guarantee is *work*.

> **Update (2026-09-08): that global contract test now exists** (#842/#3991/#3992 — see the INV-31-4
> update note above), so for `/api/vN/*` the build *does* now answer it **for literal registrations** and
> the standing question is backed by an enforced (lexical) gate rather than review alone — but a
> non-literal *direct* verb call only warns, and a helper- or header-defined registration escapes it
> **silently** (#2572). The `consistency-auditor`'s question still carries the *per-family* and MCP-twin
> halves it was written for.

### F-10 is void, and the agentic gap closes as a side-effect

F-10 exists solely because the engine's only external interface was a human UI. Remove that UI and
the carve-out has no premise. Engine capabilities are reachable through the platform surface — by a
human and by an agentic worker, through the same tools, the same RBAC, the same audit chain. The
open `confirm-now` reconciliation item resolves itself.

**The boundary this creates must be named:** the set of questions anyone can ask is the set of
capabilities the engine exposes. Agentic-first does not mean handing out SQL; it means those
capabilities must be composable and richly described (track 2g's annotations) enough that a worker
can build questions nobody enumerated. **An engine that ships three coarse tools will strangle the
agentic story just as effectively as F-10 did.**

### INV-7 moves, it does not vanish

The engine no longer re-derives ADR-0017 confinement, so **F-5 / INV-7 relocate into core** as
INV-31-2, and the M3(d) equivalence test loses the thing it was testing (an independent
re-derivation). It does not lose its *purpose*: **M3 remains the parity gate**, and its confinement
leg **retargets** to core's release gate — that what core released to the engine for a given
operator equals what that operator could have read directly (the evaluate-as-operator seam,
ADR-0017 PR-A, #1715 prerequisite). The test moves; the interlock survives. `docs/uce-host-requirements.md` F-5 and
`docs/adr-1005-execution-plan.md` Decision 14 / M3(d) need amendment notices to say so.

### 2c D3's cross-origin problem disappears

One origin, one session, one auth. The 2c §6 artifact-acquisition and F-8 hand-off flows stop being
cross-origin by construction.

### ADR-0034's durable fix becomes reachable

Presentation is a separate binary, so **its runtime is a free choice**. What makes held-open
connections expensive is cpp-httplib's thread-per-connection model — a property of *that process*,
not of the domain. ADR-0034's answer is therefore not "put a gateway in front of the server" but
**"the presentation layer is the connection holder"**, and Decision 5 names Drogon as what it is
built on. The `StreamBudget` cap landing with track 2f PR 2 (built, not yet merged) stays exactly
what it was sold as: a stopgap that keeps the fused server from exhausting its thread pool until
this lands.

**State the claim precisely, because a looser version of it has already misled a reader.** The
comparison is against *inserting a gateway* — nginx, envoy, a BEAM tier — in front of the server:
a new thing to deploy, operate, version and secure, which would not even fix the ceiling (an SSE
proxy holds one upstream connection per client, so the C++ pool still pins a thread per stream).
Against that, the presentation split **adds no new component**: the code that terminates
connections, frames MCP and renders HTMX already exists, and the split draws a process boundary
around it. **It does add a hop** — one authenticated localhost call per request, costed under
"Latency" above. Both sentences are true, and only the first was being claimed. "A process
boundary, not a hop" is wrong, and the wrong inference it invites — that presentation and core
share a runtime and can therefore call each other in-process — is precisely the shortcut this ADR
exists to forbid: if it existed, the GUI could reach a store and the headless claim would stop
being structural.

### Costs, honestly

- **Session state.** Operator sessions live in `AuthManager`'s memory today. If presentation held
  them, restarting presentation would log everyone out and presentation could never scale
  horizontally. **Sessions and the MCP replay ring move behind the core boundary, out of
  presentation** - decided *with* the split, not after it. **Whether they become durable, and whether
  that is core memory or Postgres, is G6/G7 and remains open** (ADR-0034 Decision 4; exec-plan
  Decision 15(d) holds 2f's sessions in memory with a non-durable replay ring and no new store, so
  naming Postgres here would license a durable session store no ballot approved). What is decided is
  only that presentation stops *owning* them. This reworks the in-memory contracts around JIT
  elevation and inactivity timeout, and it is why the auth-store PG migration must be re-scoped before
  it starts.
- **Supervision, and a hard commitment: one deployment unit.** Three processes plus a Postgres
  sibling need a supervisor, or a pod of containers sharing a network namespace (the better hygiene
  if Kubernetes is a target). But the commitment matters more than the mechanism: a customer who
  installs Yuzu today gets **one server and a database**, and under this ADR they must still get
  **one thing to install, one health endpoint to watch, one upgrade to run, and one version to
  quote**. "Independently deployable by construction" is a property of the *code*, not an instruction
  to the *operator*. If a buyer experiences three of everything — three configs, three logs, three
  certs, three probes — the split will read as three things to break, and the deployment-simplicity
  comparison against a commercial competitor is one we would deserve to lose. **The endpoint fleet is
  entirely unaffected** (the agent, and its GPO/SCCM/Intune/Jamf install path, do not change) — say
  so plainly, or "we split the server into three binaries" will be heard as "your agent rollout
  changes".
- **Version skew.** The moment the binaries *can* be split, they *will* be, at different versions.
  The core API needs a compatibility contract from day one (ballot G5) — the same
  versioning/deprecation policy ADR-1005 Phase 0.3 already defines for the public API. The
  presentation↔engine contract (B2) is separately versioned and published.
- **A cross-process event spine.** The event buses are process-local today
  (`execution_event_bus.hpp`). Streaming progress from core to presentation across a process
  boundary is **new work and a prerequisite**, not an assumption — ballot G1, and a gate on
  ADR-0032's P4.
- **Latency — and the fan-out nobody has measured.** The hop is per **core call**, not per user
  request. A view that today does K in-process store reads becomes **K authenticated localhost
  calls** (Decision 6 admits no in-process shortcut), and an engine run adds admission, the
  presentation→engine call, one core call per confined fact read, **a release-log write on the
  fail-closed critical path of every one of them** (ADR-0032 Decision 11), finalisation, and **a
  seam-4b release-redemption round trip before the first byte renders** (ADR-0032 Decision 12). A
  single localhost round trip is genuinely small against a 250 ms p95 view budget. **K is not
  measured.** Measuring it on the busiest existing dashboard fragment is a **gate on migration step
  4**, not a footnote — sizing a fleet-scale resource off an unmeasured constant is precisely what
  ADR-0034 records going wrong.
- **Observability.** Three `/metrics` endpoints to scrape and one trace context to thread through.

### Migration — not a big bang

1. **Verify the baseline first.** Instruction-Set semantics, workflow dispatch-vs-outcome
   correlation, and approval checkpoint/resume are all documented as stronger than the code
   currently enforces. Correct the docs, then repair the execution semantics — an admission protocol
   layered on an execution engine that treats dispatch as success would inherit the lie.
2. **Define the contracts in-process.** Admission, grants, finalisation receipts, coverage, linked
   evidence — while everything still runs in one test process. Prove the *denial* and *audit*
   behaviour before adding network failure modes.
3. **Enforce the seam logically.** Dashboard, MCP and REST handlers call the API (or a local API
   client), never stores directly. This is checkable, and it is most of the value.
   **Size it honestly, because "the missing endpoint is the forcing function" is a slogan, not an
   estimate:** the tree has ~105 dashboard fragment routes against ~74 public REST v1 routes, and the
   gap is not a tail of exotica — it includes `/devices` and `/device` (no `/api/v1/devices` exists at
   all, on the most-used page in the product), the settings surface, and the `/auto`
   preflight/deploy/verify pages. Each gap is not one endpoint: it is a REST route **plus** its MCP
   twin, an OpenAPI entry, the A4 envelope, a securable and operation, and an audit verb. That is
   roughly **40–60 new public capabilities** — a programme of work, not a step. It is the right work
   (every one of them is a capability an agentic worker also wanted), but it must be planned as a
   programme or it will be discovered as a delay.
4. **Extract presentation** into its own Drogon binary against that seam (after G10), with sessions
   and replay moved behind the boundary (their durability and location are G6/G7).
5. **Extract the engine** — the cheapest of the five, because it is new code with no in-process
   store access to unwind. **It is not free, and it is not first.** Engine principals held a
   *reserved* `principal_class` that was **never emitted until execution-plan PR 4.5**, which made
   it live (`principal_class.hpp`); the engine's GUI must still go (superseding 2c D2), and no
   engine code path may ship before ADR-0032's interlock (a)–(d) and (h) have landed.

### The acceptance tests live in ADR-0032

The seven confidence conditions that decide whether this decomposition actually holds (no unadmitted
run; no authority in presentation; no unjoined evidence; no partial-fleet ambiguity; no private core
shortcut; no restart amnesia; no accidental second product) are recorded as the acceptance-test plan
in **ADR-0032**, next to the protocol they test. They are not repeated here.

## Alternatives considered

- **Keep the fused binary.** Parity stays a rule policed by review; the engine keeps a UI, so F-10
  keeps the agentic gap and F-5/INV-7 keep the equivalence-test interlock. Rejected: it is the status
  quo whose costs this ADR is written to explain.
- **Engine on its own VM with its own GUI** (2c D2/D3, merged). Rejected. Every one of the three
  governed problems above descends from it, and none is worth the isolation it buys — which the
  role/database separation already provides.
- **Core as the byte path** (this ADR's own first draft): core relays each engine invocation,
  injects the confined scope, receives `agent_id`-tagged rows back and re-assembles them itself.
  Rejected on the reconciliation memorandum's argument: it makes core parse, relay and re-assemble
  every request and response of every Use Case — importing engine-shaped, long-running composition
  into the authority component — to buy an audit property that **admission plus a bounded grant plus
  a release log already buys** (ADR-0032). The property wanted is control-plane mediation, not
  data-plane proxying. Kept in this list because it is the alternative most likely to be
  re-proposed, and because its audit claim is the thing ADR-0032 must actually deliver.
- **Presentation owns the API; core is a domain service behind it.** Rejected: it puts policy at the
  edge and produces two APIs, of which the private one quietly becomes the real one.
- **Give the engine its own MCP surface.** Rejected: every future engine then re-pays the whole
  ADR-1005 tax — twin surfaces, discovery, the A4 envelope, RBAC, audit, the on-behalf-of guard —
  and agentic workers must federate across N endpoints, which is exactly what the single-surface
  thesis exists to prevent.
- **Re-home presentation onto the BEAM.** Considered seriously (the project already builds, ships
  and supervises Erlang, and the BEAM holds long-lived connections as its natural unit). Rejected in
  favour of Drogon: re-homing `mcp_server.cpp` and the HTMX renderers means a language port of the
  entire northbound surface, and the connection-holding property is available in C++ without one.
  The gateway keeps its BEAM specialisation southbound, where the connection count actually is.
