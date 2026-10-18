---
status: accepted
date: 2026-10-18
owner: "@liamsomerville (Liam Somerville)"
deciders: >-
  maintainer review of the PR that lands this ADR (the acceptance event under
  docs/agents/domain.md "ADR Acceptance Convention"); ADR-1005 Decision 2 names the
  maintainer as the arbiter of boundary disputes, so that review also settles the four
  rulings flagged "maintainer ruling" in the placement table
scope: >-
  capability-map Domain 41 (Cryptographic Asset Inventory, roadmap Issue 18.8) — where
  each part is built under ADR-1005: collection, transport, storage, raw-fact reads,
  rollups, the slice-1 library-family table and CBOM export (core mechanism, built
  in-server); weak/deprecated-algorithm and PQC-readiness labels, expiry-risk scoring,
  library support/EOL status, third-party revocation status, policy and
  compliance-framework verdicts (use-case engine, behind the ADR-0032 interlock). Not in
  scope: the per-slice data designs, and the slice-3 privacy decisions, which are owed by
  their own ADRs
builds-on: >-
  1005 (headless platform — Decision 2's boundary test and tiebreakers govern every row
  below); 0024 (software licensing — its "Placement under ADR-1005" section is the
  template); 0016-agent-daily-sync-framework (the collection vehicle); 0028 (component
  inventory — the collection path for non-package crypto)
related: >-
  0031-presentation-core-engine-decomposition (engines are headless; INV-31-2);
  0032 (use-case admission and its sequencing interlock); 0033 (access-control spine);
  0053 (Yuzu's own CA store — deliberately NOT the home of fleet certificates);
  0067 (purview and incident — PROPOSED, unmerged in PR #5367; bears on slice 3);
  issue #6051 (this ADR's tracking issue); PR #6056 (slice 1)
---

# 0070 — Cryptographic asset inventory: placement under ADR-1005

> **Implementation status (2026-10-18).** Slice 1 (crypto-library presence, capability
> 41.1) is built in-server and **in review as PR #6056**; it is not on `dev` yet, so every
> slice-1 path below is cited at that PR's branch. Slices 2 and 3 (certificates, SSH) are
> not started. No use-case engine exists: ADR-1005's acceptance note records that "no
> `engines/` directory exists", and the ADR-0032 merge gate is CLOSED (cells b, c, d, h
> red in `tests/split_interlock_ledger.json`). This ADR builds nothing; it decides where
> things are built.

## Summary

Domain 41 inventories the cryptographic material and libraries on managed endpoints.
Its first slice reports which crypto libraries are installed where, at which versions.
The next slices will add a certificate inventory and an SSH key and login inventory. Those
pull towards interpretation: "is this algorithm weak?", "is this certificate about to
expire?", "is this estate ready for post-quantum cryptography?". Issue #6051 asked for the
line to be drawn before slice 2 is designed, so that the certificate slice does not settle
it by accident.

The line, drawn with ADR-1005 Decision 2's boundary test:

- **In-server (core mechanism).** Collecting cryptographic facts on the agent,
  transporting them over the ADR-0016 daily sync, storing them as raw facts, reading them
  back over REST + MCP (+ the dashboard), and aggregating them (distinct-device counts by
  raw value). This includes slice 1's curated library-family table, ruled here to be
  *identity resolution*, not interpretation, under conditions this ADR states. It also
  includes caller-parameterised filters over raw fields (`not_after` before a date the
  caller supplies), operator-authored policy over those facts, and a CBOM export that
  carries facts only.
- **Use-case engine (interpretation).** Any verdict whose semantics Yuzu would ship in
  code: weak, deprecated or broken algorithms and key sizes; post-quantum readiness;
  expiry-risk bands and scores; library support and end-of-life status; revocation status
  fetched from third-party CRL/OCSP endpoints; mappings to NIST, CNSA, PCI or any other
  framework; and the CVE join over library versions (already the vulnerability module's
  scope). None of this is built until a use-case engine exists and the ADR-0032 interlock
  opens.

Because slices 2 and 3 have not shipped, this is ADR-0024's outcome, a **re-scope, not a
carve-out**: the interpretation half is never built in-server, so nothing here is
grandfathered and nothing needs a strangler later.

## Background

Slice 1 (PR #6056) is a server-only read over the existing `installed_software` daily-sync
inventory. It adds no agent collection. A compiled-in table (`crypto_library_model`, 12
families, `kCryptoTableVersion = 2`) maps package names to library families by exact or
prefix match. The surfaces report, per family, the distinct devices carrying it, and the
versions and package names seen, plus a coverage pair (devices with a match, devices
reporting inventory):

| Surface | Name |
|---|---|
| REST | `GET /api/v1/crypto/libraries`, `GET /api/v1/crypto/libraries/devices` |
| MCP | `get_crypto_libraries`, `list_crypto_library_devices` |
| Dashboard | `/crypto` and its two fragments |
| Gate | `fleet_read_fn(..., "Inventory", "Read")` (ADR-0017 admit-then-filter) |
| Audit | `crypto.libraries.view`, `crypto.libraries.devices` |

Slice 1 was built on the premise that it is mechanism, and its code says so
(`crypto_library_model.hpp:10-14` at PR #6056: "MECHANISM, not interpretation (ADR-1005
D2, like ADR-0024's `product_normalize`) ... It never labels a library or version good,
bad, current or out of date; that is engine territory behind the ADR-0032 interlock").
That premise was an **inference**, recorded in the slice-1 governance run as finding
`arch-a4-placement-adr-before-slice2` and deferred to #6051. ADR-1005 does not mention
cryptography, PQC, ciphers or certificates anywhere. This ADR replaces the inference with a
recorded decision.

Two things about the governing text matter below and are easy to misread:

1. **ADR-1005 treats "pure aggregation" as mechanism, and ADR-0031 calls aggregation the
   engine's job.** ADR-1005:47 (tiebreakers): "pure aggregation of fleet-internal facts
   (rollups, histograms, distinct-device counts), are *mechanism*". ADR-0031 INV-31-2
   (`0031-presentation-core-engine-decomposition.md:302-307`): "Aggregation and
   interpretation are the engine's job; confinement never is." These do not conflict.
   INV-31-2 is about what an engine does *inside a run* with the inputs core released to
   it: it composes them, and core confines them. It does not reclassify core's own
   rollups, and ADR-1005:47 explicitly lists "the DEX/software-catalogue rollups as core".
   This ADR relies on ADR-1005:47 for core rollups.
2. **ADR-1005's "OS-EOL metadata" carve-out.** ADR-1005:47: "Infrastructure-supporting
   external fetches (NTP, CRL, OS-EOL metadata) are not 'domain data'." Read loosely,
   that would let core fetch library end-of-life data and label versions "out of date".
   This ADR rules otherwise (D3). Nothing in the server consumes OS-EOL metadata today
   (no end-of-life or OS-EOL reference exists in `server/core/src`), so no shipped behaviour sets a
   precedent either way.

## The test applied

ADR-1005 Decision 2 (`1005-headless-platform-use-case-engines.md:43-47`) is the whole
rule:

- **Boundary test:** "does it collect/enforce/transport facts about the estate
  (mechanism → core), or does it interpret those facts for a purpose (interpretation →
  use-case engine)?"
- **Mechanism tiebreakers:** "operator-authored content evaluated by a generic engine
  (policy rules, preflight checks, scope expressions, Guards, Reflexes)" and "pure
  aggregation of fleet-internal facts".
- **Engine tiebreakers:** "semantics are baked into code (domain scoring,
  compliance-framework mappings)" or a join of "fleet data with external domain data
  (vulnerability feeds, threat intel)".
- **Packaging is irrelevant:** "First-party-shipped content (build-time-embedded YAML) is
  judged by its semantics, not its packaging".

For cryptography the test reduces to one distinction, which every row below applies:

> **What a thing *is* is a fact; how *good* it is is a verdict.** "This package is
> OpenSSL 3.0.13", "this certificate's key is RSA 2048, signed with sha1WithRSAEncryption,
> valid until 2026-11-02" and "this host key is ssh-ed25519" are facts about the estate.
> "OpenSSL 3.0.13 is out of support", "RSA 2048 is not quantum-safe", "SHA-1 signatures
> are weak" and "this certificate is at risk" are judgements. Each depends on a standard,
> a date or a threat model Yuzu would have to choose and keep current. Facts are core.
> Judgements are engine territory, unless the operator authors the judgement themselves,
> as policy content evaluated by a generic engine.

## Placement under ADR-1005

**Ruling: re-scope, not a carve-out.** The interpretation half of Domain 41 is not built
in-server at all. The parts below marked **core** are permanently server/agent resident.
"Store ownership follows the layer" (ADR-1005 Consequences, `:697`), so the raw stores
stay core and any engine-derived state is the engine's own.

| Domain 41 element | Slice | ADR-1005 class | Justification (Decision 2 + tiebreakers) |
|---|---|---|---|
| `installed_software` daily-sync source (existing) | 1 | **core** | Collection and transport of estate facts on the ADR-0016 framework. |
| Library-family table `crypto_library_model` (12 families, versioned) | 1 | **core**, conditional — D2 (maintainer ruling) | Deterministic identity resolution ("which library is this package?") over fleet-internal data, no external data. Same class as ADR-0024's `product_normalize`, ruled core at `0024:162`. The conditions in D2 keep it there. |
| Per-family / per-version distinct-device rollups, coverage pair | 1 | **core** | "pure aggregation of fleet-internal facts" (ADR-1005:47). |
| `/api/v1/crypto/*` reads + MCP twins + `/crypto` page | 1 | **core** | Raw-fact reads, admit-then-filter confined. The REST+MCP twin satisfies Decision 1. |
| Non-package crypto (vendored, statically linked, OS-bundled `libcrypto`/`OpenSSL.dll`) | 1 gap | **core** (collection) — via ADR-0028 | ADR-0028 is "agent-side collection mechanism ... stays core" (ADR-1005:707). Domain 41 consumes its output; it does not build a second collector. |
| Certificate collection (agent), read-only enumeration of certificate stores | 2 | **core** | Collection of estate facts. Parallel to `vuln_scan`'s inventory action, which ADR-1005 keeps core. |
| Certificate daily-sync source + typed store of raw X.509 fields | 2 | **core** | Transport and storage of collected facts (ADR-0016 §7 typed projection). |
| Raw X.509 fields: subject, issuer, serial, validity dates, key algorithm + size, signature algorithm, SANs, KU/EKU, basic constraints, fingerprints, store/location | 2 | **core** | Each is a field of the certificate as found on the device. Naming an algorithm is a fact; grading it is not done here. |
| Caller-parameterised filters (e.g. `not_after < T`, `key_bits < N`) and distinct-device counts by raw value | 2 | **core** — D4 | A generic query primitive. The caller supplies the threshold, so the semantics are the caller's, not code-baked. |
| "Expired / expires in N days" as Yuzu-defined bands, risk scores, default thresholds, expiry notifications | 2 | **UCE** — D4 | Derived against "now" with a threshold Yuzu chooses. The same class as ADR-0024's *effective licence state* (`0024:126-128`), which that ADR sends to the engine. |
| Operator-authored policy over certificate facts (e.g. an operator's rule "fail if `not_after` < now + 30d") | 2 | **core** | "operator-authored content evaluated by a generic engine" (ADR-1005:47). The operator owns the semantics. |
| Chain-to-local-trust-store result computed on the device | 2 | **core**, if built — D5 | A deterministic fact about the device's own configuration, with no external data. Optional, not committed. |
| Revocation status from third-party CRL/OCSP endpoints | 2 | **UCE** — D5 (maintainer ruling) | A join of fleet data with external, third-party data for a judgement. ADR-1005's "CRL" carve-out covers Yuzu's own PKI infrastructure fetches, not grading fleet certificates against other CAs' revocation lists. |
| Certificate renewal, re-issue, deletion (roadmap Issue 18.3 lifecycle) | 2+ | out of scope here | These are mutations, not reads. When designed, they go through ADR-0033's Execution Plan and approval primitive. The existing `certificates.delete` action is Destructive/Irreversible and is never part of the inventory path (D6). |
| SSH key-at-rest collection (host keys; `authorized_keys` and user public keys: type, size, fingerprint, location; never key content) | 3 | **core** (collection) — privacy owed (D8) | Collection of estate facts. The per-user parts carry privacy obligations the slice-3 ADR must decide. |
| SSH login evidence (who, from where, with which key type) | 3 | **core** (collection) — privacy owed (D8) | Collection of estate facts, but behavioural personal data: ADR-1005 Decision 5's controls attach to any engine that consumes it. |
| "Unused / stale / anomalous key", "key used from an unusual location" | 3 | **UCE** | Semantics baked into code: a judgement about behaviour. |
| Protocol and configuration settings (enabled TLS/SSH versions, cipher, KEX, MAC lists, system crypto policy) | 41.5 | **core** (facts) / **UCE** (verdicts) | The configured list is a fact. "Weak cipher enabled" is a verdict. |
| CBOM export of the collected inventory | 41.6 | **core**, facts only — D7 (maintainer ruling) | A projection of core facts into a standard format, like ADR-0028's SBOM projection. Verdict-bearing CBOM fields are left empty in core. |
| Weak / deprecated / broken algorithm and key-size labels; PQC readiness; crypto-agility scoring | all | **UCE** | Semantics baked into code, tied to an external standard and threat model. The canonical engine case. |
| Library support / EOL / "out of date" status | 1 | **UCE** — D3 (maintainer ruling) | Domain data about third-party projects, used for a judgement. Not the "OS-EOL metadata" infrastructure carve-out. |
| CVE matching over crypto-library versions | 1 | **UCE** — the vulnerability module | Already engine territory by name ("vulnerability feeds", ADR-1005:47) and by the execution plan's catalogue-grain design (Decision 5). Domain 41 does not build a second matcher. |
| Mapping to frameworks (NIST SP 800-131A, CNSA 2.0, PCI DSS, FIPS 140 status, ...) | all | **UCE** | "compliance-framework mappings" is named engine territory (ADR-1005:47). |

## Decisions

Each decision is tagged **[core]** (built in-server), **[UCE]** (use-case engine only)
or **[split]**.

### D1 — Domain 41 is core collection plus a deferred engine half [split]

Domain 41 is split as the placement table states. The core half is buildable now, slice by
slice, each under its own design. The engine half is a scoped backlog for a future
"cryptographic posture" use-case-engine module, not an immediately buildable target. No
engine host exists, engines are headless (ADR-0031 D4, so the module would have no UI of
its own), and the ADR-0032 interlock is closed (D9).

No in-server crypto verdict is ever built as an interim measure. That differs from the
vulnerability vertical, which shipped in-server first and was grandfathered (ADR-1005
grandfathered surface #2). The difference is timing: as ADR-0024 put it, re-scoping is
"the cleaner outcome Decision 2 points to when the work has not yet shipped" (`0024:203-205`).

### D2 — The library-family table is identity resolution, under four conditions [core]

The slice-1 table answers "which library is this package?". That is the same question
ADR-0024's `product_normalize` answers for licences ("deterministic identity resolution
over pure fleet-internal aggregation (a generic engine, no external data)", `0024:162`),
and the same question the software-catalogue rollup answers for names. It is mechanism.

The strongest counter-argument is the agent `vuln_scan` plugin's embedded `cve_rules.hpp`.
That is also a curated, compiled-in list, and the execution plan freezes and deprecates it
as interpretation (`adr-1005-execution-plan.md` Decision 8). The two differ in what the
list *asserts*. `cve_rules.hpp` asserts a judgement ("this version is vulnerable"),
derived from external domain data (CVE feeds). The family table asserts identity only
("`libssl3` is OpenSSL") and carries no field about quality, support or vulnerability.

The table stays core only while all four of these hold:

1. **Identity only.** A rule maps a package name to a family. The table carries no
   attribute that grades a family or a version: no strength, support, EOL, CVE, PQC or
   preference field, and no colour or severity in any surface that renders it. Adding
   one moves that attribute, not the table, to the engine.
2. **Deterministic and inspectable.** Matching is exact or prefix on the package name
   only, with no version, publisher or file-content heuristics. The table is versioned
   (`table_version` on every response, and in the drill-cursor fingerprint) so a consumer
   can tell which mapping produced an answer.
3. **Inclusion is factual, not evaluative.** A family is included because it *is* a
   cryptographic library. Exclusions are factual too, for example `nss-mdns` is a name-
   service plugin, not NSS cryptography. A family is never included or omitted because it
   is considered good or bad.
4. **No second copy.** The SQL patterns are generated from the same table
   (`sql_patterns()`), and every store result is re-checked with `classify()` before it is
   shown. A second, divergent list would turn the table into two answers to one question.

**Known cost, accepted.** The table's family ids are compiled into the public contract
(the `family` enum in the OpenAPI spec and the MCP input schema), so changing the taxonomy
is a contract change. That is acceptable for identity data, and `table_version` exists for
it. A future engine can consume the results but cannot supply its own taxonomy through
`CryptoApi`. If one ever needs to, the store primitive underneath is domain-free
(`NamePatternQuery`: "the store never learns what a label means",
`software_inventory_store.hpp` at PR #6056), so a caller-supplied-pattern read could be
added in core without moving anything.

**If a later ruling reverses D2**, the slice-1 surfaces are on the versioned `/api/v1/`
contract from birth. Removing or re-homing them would follow the standard deprecation
cycle (ADR-1005 Decision 7: removal of a depended-on dashboard surface "is a breaking
change requiring a full deprecation cycle"), the same terms ADR-0024's re-home note
records for `/api/v1/sle/*`.

**Maintainer ruling requested:** confirm that D2's identity-resolution reading, with the
four conditions, is the binding classification.

### D3 — Library support and EOL status are engine territory [UCE]

Whether a library version is supported, end-of-life, current or out of date is a
judgement about a third-party project. It needs external domain data (upstream release and
support schedules) and a policy for what "current" means. That is engine territory by both
engine tiebreakers.

ADR-1005's "OS-EOL metadata" carve-out does not cover it. The carve-out exempts
infrastructure-supporting fetches: data the platform needs to run itself correctly, like
NTP and CRLs. Using upstream support schedules to grade the estate's software is the
purpose the boundary test calls interpretation. So slice 1's self-imposed rule, never
"current or out of date", is now a decided rule rather than an inference.

**Maintainer ruling requested:** confirm the narrow reading of the OS-EOL carve-out, and
record it in ADR-1005's Decision 2 examples appendix (D11).

### D4 — Expiry: raw dates and caller thresholds are core; Yuzu-chosen bands are not [split]

Core stores and returns each certificate's validity dates as found, at full precision.
Today's plugin truncates them to `YYYY-MM-DD`, so the slice-2 design must collect the full
time and keep it in UTC. Core may offer:

- filters and counts whose threshold the caller supplies (`not_after` before T, after T,
  between T1 and T2);
- sorting by `not_after`;
- operator-authored policy, preflight checks or Guards over these fields, evaluated by
  the existing generic engines.

Core does not ship:

- a built-in notion of "expiring soon" (no default 30/60/90-day bands, no "at risk"
  label, no colour coding of dates);
- expiry scores;
- notifications on a Yuzu-chosen threshold.

These are derived against "now" under a policy Yuzu would choose, the same class as
ADR-0024's *effective licence state* (`0024:126-128`), which that ADR assigns to the
engine. An expiry notification the *operator* configures, with their own threshold, over
core's generic alerting or policy machinery is operator-authored content, so it is core.

One thing is not a verdict: **"already expired at read time"**, `not_after < now`, if
returned as a plain comparison the caller can reproduce. It is still not built as a
default label. Caller-supplied T covers it (T = now), and a default label invites exactly
the grading this decision keeps out.

### D5 — Revocation and trust: device-local facts core, third-party status engine [split]

Two different things are called "is this certificate valid?":

- **Device-local trust.** Does the certificate chain to a root in the device's own trust
  store? That is a fact about the device's configuration, computable on the device with no
  external data. If built, it is core. It is **not committed** for slice 2: the current
  plugin deliberately does no chain or revocation work (its README, "deliberately does not
  validate a certificate's trust chain, check revocation"), and adding it is a separate
  design choice with its own cost.
- **Revocation status.** Fetching CRLs or querying OCSP responders run by third-party CAs
  joins fleet data with external data, to answer a judgement question. That is engine
  territory. ADR-1005:47's "CRL" example is an infrastructure fetch: the platform's own
  revocation needs, such as Yuzu's internal CA (`CaStore::publish_next_crl`, ADR-0053).
  It is not grading fleet certificates against other CAs' lists. Egress from core to
  arbitrary CA endpoints chosen by the certificates under inventory would also be a new
  outbound surface. That needs its own security review whichever side builds it.

**Maintainer ruling requested:** confirm the narrow reading of the "CRL" carve-out.

### D6 — The certificate inventory is read-only and never touches Yuzu's own CA [core]

Two boundaries bind the slice-2 design:

1. **Read-only path.** The inventory is collected by enumeration only. The existing
   `certificates` plugin's `delete` action is Destructive / Irreversible / AdminOrApproval
   (`plugin_action_catalogue_c.hpp`). The sync source must never invoke it, and no
   inventory surface may offer it. Lifecycle mutations (roadmap Issue 18.3) are a separate,
   separately governed capability.
2. **Not `CaStore`.** Fleet certificates are untrusted endpoint reports. `CaStore`
   (ADR-0053) holds the authority data of Yuzu's own internal CA, including the append-only
   revoked set that the mTLS accept path reads. Fleet certificate rows must not live in
   the `ca_store` schema, reuse its tables, or be read by any PKI decision path. They get
   their own typed store, owned by the inventory layer.

These are placement constraints, not the slice-2 data design. That design, including
which stores and fields to collect, per-OS coverage and the typed-store schema, is owed by
the slice-2 design doc and its own review. It must also cover the collection gaps found
while preparing this ADR:

- **Fields:** key algorithm and size, signature algorithm, SANs, EKU, basic constraints
  and a SHA-256 fingerprint are not collected today. The thumbprint is SHA-1 only.
- **Windows:** subject and issuer are a simple display name, not the full DN. Only four
  LocalMachine stores are read.
- **Linux:** only `/etc/ssl/certs` is read, and only the first certificate in each file is
  kept, so bundle files yield one row.
- **macOS:** only the console user's login keychain is read.

### D7 — CBOM export is core when it carries facts only [core]

A cryptographic bill of materials (for example CycloneDX's `cryptographic-asset`
components) is a projection of collected facts into a standard format. It is core
mechanism, like ADR-0028's SBOM projection.

Some CBOM schemas also have fields that carry verdicts: security-level fields such as
CycloneDX's classical and NIST-quantum security levels, and any "weak" or "approved"
classification. Core leaves those fields empty or omits them. It never fills them from a
table it ships. An engine may emit an enriched CBOM from core's facts plus its own
verdicts. Verify the exact field list against the CBOM schema version chosen at
implementation.

**Maintainer ruling requested:** confirm CBOM export as core under this condition.

### D8 — SSH placement is decided here; SSH privacy is not [core collection, owed ADR]

Placement is the easy half of slice 3:

- **Collection is core:** host keys, user public keys and `authorized_keys` entries
  (type, size, fingerprint, location, never key content) as keys at rest (41.3), and
  login evidence (41.4).
- **Behavioural judgements are engine territory:** stale, unused or anomalous key use,
  and unusual source locations.

The hard half is privacy, and this ADR deliberately does not decide it. The slice-3 ADR
must, before any slice-3 code. These obligations already apply:

- **Per-user material is not machine-scope.** `authorized_keys`, `~/.ssh` and key
  comments (which often carry `user@host`) are per-user data. The repo's precedents are
  ADR-0024 D11's pseudonymised `user_ref` and the Forensics-class, default-off,
  single-target posture of `browser_inventory`. Host keys are machine-scope.
- **Login evidence is behavioural personal data.** The relevant controls are
  `emit_behavioral_audit`, ADR-1005 Decision 5 ("bulk sync of behavioral PII requires
  explicit security-guardian design review", `:67`), and ADR-0032 D14 (engine behavioural
  reads fail closed on audit failure on every surface).
- **ADR-0067 (proposed, PR #5367, not accepted).** If accepted as drafted, its D5 says an
  EU co-determination deployment "must not enable ... any other new individually-
  identifying source" until purview enforcement ships, and its D7 makes a pre-read
  `authorize_behavioral_read` gate the single chokepoint. The slice-3 ADR must be written
  against whatever state ADR-0067 is in at the time.
- **Collection mechanism.** Login evidence comes from logs (sshd journal and auth logs,
  Windows OpenSSH event logs). That makes a TAR cursor source the likely collector, with
  its no-silent-replay contract, plus an `app_usage`-style daily-sync hand-off if the
  data is centralised at all. The slice-3 ADR must choose.

### D9 — The engine half waits for the ADR-0032 interlock [UCE]

No part of the engine half ships until ADR-0032's unconditional set **(a)–(d) and (h)** is
green (`0032-use-case-admission-protocol.md:964-967`). Today cell (a) is green, and (b),
(c), (d) and (h) are red (`tests/split_interlock_ledger.json`; the tripwire reports
"merge-gate CLOSED (red: b, c, d, h)"). Further cells gate specific paths, and the module
ships without them only if it does not walk them:

| Cell | What it gates, if the module does it |
|---|---|
| (g) derived-state confinement | persisting a cross-run rollup, e.g. a fleet crypto-posture score (ADR-0031 INV-31-2: "before a module persists its first cross-run rollup") |
| (f) per-action mutability in the plugin ABI | dispatching to agents |
| (j) generated OpenAPI / `tools/list` | reachability over REST or MCP |
| ADR-0032 D14, ADR-1005 Decision 5 | consuming slice-3 behavioural data |

Nothing in the core half touches an engine-path marker. A core-only Domain 41 slice does
not need the interlock, and this ADR does not change the tripwire's marker sets.

The engine reads facts the same way the vulnerability module is designed to: at catalogue
grain over core's versioned reads, expanding only the hits to devices, never holding a
fleet replica (execution plan Decisions 5 and 6). Slice 1's family/version summary is
already that grain. CVE matching over crypto-library versions belongs to the
vulnerability module, so the crypto-posture module, when scoped, must not build a second
matcher.

### D10 — Core surfaces state what they do not judge [core]

Every Domain 41 surface, REST, MCP and dashboard, keeps slice 1's posture:

- it says "presence and facts only, no verdicts" in its description;
- it renders no grading colour, icon or ordering by assumed risk (ordering by device
  count or by a raw field is fine);
- it states its blind spots honestly ("an empty result is not proof of absence", and the
  stores or roots a collector does not read).

New fields on these responses must be facts under the "is, not how good" test. A review
finding against this decision is a Decision-2 placement finding, not a style finding.

### D11 — Recording the boundary verdicts [core]

ADR-1005:47 says "verdicts accrete into an examples appendix in this file". No appendix
exists on `dev`; PR #5367 (unmerged) would create it. When it exists, the four rulings
this ADR requests (D2, D3, D5, D7) are added to it as verdict rows, each binding for the
class it names:

- curated identity tables;
- third-party lifecycle data;
- third-party revocation status;
- verdict-free standard-format exports.

This ADR does not edit ADR-1005, to avoid a conflict with #5367's appendix. Adding the
rows is a follow-up once that appendix exists.

## Consequences

- **Slice 2 is unblocked to design.** Its design doc must cite this ADR, satisfy D4, D5
  and D6, and close or disclose the collection gaps D6 lists. It starts after PR #6056
  merges.
- **Slice 3 needs its own ADR first** (D8), with the privacy decisions made by the owner.
- **Slice 1 needs no change.** PR #6056 already meets D2 and D10. Its capability-map
  Domain 41 and roadmap Issue 18.8 text cite "ADR-1005 D2" for the no-verdict rule; once
  both are on `dev`, they should cite this ADR as well (the link #6051 asks for), in a
  follow-up.
- **No engine work is created.** The crypto-posture module is a backlog entry for the
  engine host, behind D9.
- **A reviewer can now cite a rule** instead of an inference. "Does this field grade
  something?" is the question, and the placement table is the precedent.
- **Cost.** Operators who want "show me weak crypto" or "certificates expiring this month"
  get only the raw facts and their own policies until an engine exists. That is
  ADR-1005's intended trade, and D4's caller thresholds and operator policy cover the most
  common expiry need without Yuzu choosing the threshold.

## Alternatives considered

- **Build the verdicts in-server now and grandfather them** (the vulnerability vertical's
  path). Rejected. Grandfathering exists for shipped work, and nothing here has shipped.
  Building interpretation in-server now would grow a future deletion scope, which is the
  outcome ADR-0023's placement note warns of ("each further in-server PR on this ladder
  grows that deletion scope").
- **Classify the family table as interpretation too, and move all of Domain 41 to an
  engine.** Rejected. It would leave the estate's facts uncollected until an engine
  exists, contradicting ADR-1005's own placement of collection and inventory stores in
  core. And it misreads identity resolution as grading (D2).
- **A narrow, "obviously uncontroversial" built-in list, e.g. flag MD5 and SHA-1
  signatures only.** Rejected. Any built-in list is "semantics baked into code", however
  short. The line has to be where the semantics come from, not how many there are. An
  operator can author the same rule as policy (D4's mechanism).
- **Treat "already expired" as a fact and label it.** Rejected as a default label (D4).
  The comparison is reproducible from the raw date, and a label is the first step to
  bands.

## Ratification

Accepted by the merge of the reviewed PR that lands this file, per the ADR Acceptance
Convention (`docs/agents/domain.md`). ADR-1005 Decision 2 makes the maintainer the arbiter
of boundary disputes. The maintainer's approval of that PR is therefore also the ruling on
D2, D3, D5 and D7. A reviewer who disagrees with any one of them should block on it
specifically, so it can be split out rather than accepted silently.
