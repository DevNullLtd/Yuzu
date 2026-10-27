---
status: accepted
date: 2026-10-18
owner: "@liamsomerville (Liam Somerville)"
deciders: >-
  maintainer review of the PR that lands this ADR, by an approver who is not the author
  (the acceptance event under docs/agents/domain.md "ADR Acceptance Convention"); ADR-1005
  Decision 2 names the maintainer as the arbiter of boundary disputes, so that review also
  settles the five rulings flagged "maintainer ruling" below (D2, D3, D5, D7, D13)
scope: >-
  capability-map Domain 41 (Cryptographic Asset Inventory, roadmap Issue 18.8) — where
  each part is built under ADR-1005: collection, transport, storage, raw-fact reads,
  rollups, the slice-1 library-family table and a fact-only CBOM export (core mechanism,
  built in-server), plus one closed set of built-in weak-key rules and fixed dashboard
  time windows (core by maintainer ruling, D13), and revocation status read only from
  operator-registered CRLs (core by maintainer ruling, D5 as amended); deprecated-algorithm
  and PQC-readiness labels, expiry-risk scoring, library support/EOL status, OCSP and
  revocation fetched from certificate-supplied URLs, policy and compliance-framework
  verdicts (use-case engine, behind the ADR-0032 interlock); plus the binding constraints the slice-2 design must meet (D6, D12). Not in
  scope: the per-slice data designs, and the slice-3 privacy decisions, which are owed by
  their own ADR
builds-on: >-
  1005 (headless platform — Decision 2's boundary test and tiebreakers govern every row
  below); 0024 (software licensing — its "Placement under ADR-1005" section is the
  template); 0016-agent-daily-sync-framework (the collection vehicle); 0028 (component
  inventory — a collection path for bundled crypto)
related: >-
  0031-presentation-core-engine-decomposition (engines are headless; INV-31-2; seam B6);
  0032 (use-case admission and its sequencing interlock); 0033 (access-control spine);
  0017 (management-group confinement of list reads); 0053 (Yuzu's own CA store —
  deliberately NOT the home of fleet certificates); 0067 (purview and incident — PROPOSED
  and unmerged in PR #5367 as of 2026-10-18; bears on slice 3); issue #6051 (this ADR's
  tracking issue); PR #6056 (slice 1, merged 2026-10-18)
---

# 0070 — Cryptographic asset inventory: placement under ADR-1005

> **Implementation status (2026-10-19).** Slice 1 (crypto-library presence, capability
> 41.1) is built in-server and merged to `dev` (PR #6056). Slice-1 line citations below
> were taken at that PR's branch and may have moved since. Slices 2 and 3 (certificates, SSH) are
> not started, and nothing in them is available today. No use-case engine exists:
> ADR-1005's acceptance note records that "no `engines/` directory exists", and the
> ADR-0032 merge gate is CLOSED (cells b, c, d and h red in
> `tests/split_interlock_ledger.json`). This ADR builds nothing; it decides where things
> are built and what the next slices must satisfy.

## Summary

Domain 41 inventories the cryptographic material and libraries on managed endpoints. Its
first slice reports which crypto libraries are installed where, at which versions. The
planned slices add certificates and SSH keys and logins. Those pull towards
interpretation: "is this algorithm weak?", "is this certificate about to expire?", "is
this estate ready for post-quantum cryptography?". Issue #6051 asked for the line to be
drawn before slice 2 is designed, so that the certificate slice does not settle it by
accident.

The line, drawn with ADR-1005 Decision 2's boundary test:

- **In-server (core mechanism).** Core collects cryptographic facts on the agent,
  transports them over the ADR-0016 daily sync and stores them as raw facts. It reads them
  back over REST + MCP (+ the dashboard) under the existing confinement and audit, and
  aggregates them (distinct-device counts by raw value). This includes:
  - slice 1's curated library-family table, ruled here to be *identity resolution*, not
    interpretation, under four conditions (D2);
  - caller-parameterised filters over raw fields, such as `not_after` before a date the
    caller supplies;
  - operator-authored policy over those facts;
  - a CBOM export that carries facts only;
  - by maintainer ruling (D5 as amended), revocation status read only from CRLs an
    administrator has registered, with their CA certificates, and fetched from exactly the
    registered URLs;
  - by maintainer ruling (D13), and as the one exception to the derived-field rule ("The
    test applied"), a closed, versioned set of four weak-key rules (MD5 or SHA-1 signature,
    RSA under 2048 bits, EC under 224 bits) and fixed dashboard time windows (active,
    expiring within, expired or revoked within N days, issued within the last 7 days, a
    52-week per-week series (the current, partial week included), registered CRLs
    past their `nextUpdate` (`crl_past_next_update`), fleet-wide counts of SSH keys observed in use within N days),
    each computed at read time and shown with its criterion. The active, expiring, expired,
    issued and revoked counts also cover Yuzu's own CA population, read through a
    `CaStore` count method (R2, R6).

  The certificate and SSH parts are planned, not committed, and are not available until
  their slices ship.
- **Use-case engine (UCE; interpretation).** This covers any other verdict whose semantics
  Yuzu would ship in code:
  - deprecated or broken algorithms and key sizes beyond D13's four rules;
  - post-quantum readiness;
  - expiry-risk scores and "at risk" labels;
  - library support and end-of-life status;
  - revocation status from OCSP, or from CRL URLs taken from the certificates under
    inventory (AIA, CDP);
  - mappings to NIST, CNSA, PCI or any other framework;
  - the CVE join over library versions (already the vulnerability module's scope).

  None of this is built until a use-case engine exists and the ADR-0032 interlock opens.
  "UCE" is the execution plan's shorthand (Decision 12 there), also used by ADR-0024 and
  ADR-0032; ADR-1005 itself spells it out.

Slices 2 and 3 have not shipped, so the outcome is ADR-0024's: a **re-scope, not a
carve-out, except the D5 (as amended, R1) and closed D13 maintainer exceptions**. Apart
from those two exceptions, the interpretation half is not built in-server, so nothing here
is grandfathered. The exceptions do put a small amount of interpretation in core
(Consequences, "The cost"). D6 and D12 then fix the constraints the slice-2 design must
meet, so that the certificate inventory is safe to build as core.

## Background

### Slice 1

Slice 1 (PR #6056) is a server-only read over the existing `installed_software`
daily-sync inventory; it adds no agent collection.

- **The table.** A compiled-in table (`crypto_library_model`, 12 families,
  `kCryptoTableVersion`) maps package names to library families by exact or prefix match.
- **What it reports, per family:** the distinct devices carrying it, and the versions and
  package names seen. It also reports a coverage pair: devices with a match, and devices
  reporting inventory.
- **Surfaces:**
  - REST: `GET /api/v1/crypto/libraries` and `GET /api/v1/crypto/libraries/devices`
  - MCP: `get_crypto_libraries` and `list_crypto_library_devices`
  - Dashboard: `/crypto` and its two fragments
- **Gate:** all are gated by `fleet_read_fn(..., "Inventory", "Read")` (ADR-0017
  admit-then-filter).
- **Audit:** `crypto.libraries.view` and `crypto.libraries.devices`.

Slice 1 was built on the premise that it is mechanism, and its code says so
(`crypto_library_model.hpp:10-14` at PR #6056): "MECHANISM, not interpretation (ADR-1005
D2, like ADR-0024's `product_normalize`) ... It never labels a library or version good,
bad, current or out of date; that is engine territory behind the ADR-0032 interlock".

That premise was an **inference**. The slice-1 governance run recorded it as finding
`arch-a4-placement-adr-before-slice2` and deferred it to #6051. ADR-1005 does not mention
cryptography, PQC, ciphers or certificates anywhere. This ADR replaces the inference with
a recorded decision.

### Two readings that are easy to get wrong

1. **ADR-1005 treats "pure aggregation" as mechanism, and ADR-0031 calls aggregation the
   engine's job.**
   - ADR-1005:47 (tiebreakers): "pure aggregation of fleet-internal facts (rollups,
     histograms, distinct-device counts), are *mechanism*".
   - ADR-0031 INV-31-2 (`0031-presentation-core-engine-decomposition.md:302-307`):
     "Aggregation and interpretation are the engine's job; confinement never is."

   These do not conflict. INV-31-2 is about what an engine does *inside a run* with the
   inputs core released to it: the engine composes them, and core confines them. It does
   not reclassify core's own rollups, and ADR-1005:47 explicitly lists "the
   DEX/software-catalogue rollups as core". This ADR relies on ADR-1005:47 for core
   rollups.
2. **ADR-1005's carve-out for external fetches.** ADR-1005:47 says "Infrastructure-
   supporting external fetches (NTP, CRL, OS-EOL metadata) are not 'domain data'." Read
   loosely, that would let core fetch library end-of-life data and label versions "out of
   date", or fetch any CRL a certificate points to and label certificates revoked. This ADR
   rules otherwise: library end-of-life is engine territory (D3), and revocation status is
   core only from CRLs an administrator registered, never from a URL a certificate supplies
   (D5 as amended).

   As of 2026-10-18, nothing in `server/core/src` consumes OS-EOL metadata (there is no
   end-of-life reference in it), so no shipped behaviour sets a precedent either way.

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

> **What a thing *is* is a fact; how *good* it is is a verdict.**
>
> These are facts about the estate:
> - "this package is OpenSSL 3.0.13";
> - "this certificate's key is RSA 2048, signed with sha1WithRSAEncryption, valid until
>   2026-11-02T14:00:00Z";
> - "this host key is ssh-ed25519".
>
> These are judgements:
> - "OpenSSL 3.0.13 is out of support";
> - "RSA 2048 is not quantum-safe";
> - "SHA-1 signatures are weak" (core states this only as D13's named rule `sig_sha1`,
>   shown with its criterion "the signature algorithm uses SHA-1", never as a bare
>   "weak");
> - "this certificate is at risk".
>
> Each judgement depends on a standard, a date or a threat model that Yuzu would have to
> choose and keep current. Facts are core. Judgements are engine territory, unless the
> operator authors the judgement themselves, as policy content evaluated by a generic
> engine, or the judgement is one of the closed set D13 rules into core.

Outside D13's closed set, a **derived field** is core only if it is a pure function of
collected raw facts and a value the caller supplies. A field is a verdict, and belongs to
the engine, if it reads any clock (the server's or the agent's) or applies a cut-off Yuzu
chose. That holds whether the server computes it or the agent computes it at collection
time. Receipt and provenance timestamps
that the server records itself (`last_seen`, `observed_at`) are metadata about the
collection, not derived fields, so the rule does not apply to them.

This rule is scoped to Domain 41, and it is stricter than ADR-1005:47, which lists
"histograms" as mechanism without saying who picks the bucket edges. In cryptography a
fixed edge is itself a strength claim: a 2048/3072-bit boundary is a standards cut-off. So
a Yuzu-chosen bucketing is a verdict here. Fixed-edge rollups in other domains are
unaffected.

Under that rule:

| Field | Core? |
|---|---|
| `is_ca` (from basic constraints) | yes |
| `self_signed` (subject = issuer and the signature verifies under its own key), computed by the agent at collection time and stored as a collected fact, because the server does not hold the signature bytes | yes |
| `signature_hash` named from the signature OID | yes |
| `days_remaining` | no — it reads "now" |
| `signature_hash_strength` | no — it grades |
| a fixed bucketing of key sizes | no — the buckets are Yuzu's |
| a histogram whose bucket edges the caller supplies | yes |
| D13's four weak-key rules and fixed time windows, computed at read time, never stored | yes — by maintainer ruling (D13), the only exception to the derived-field rule (D5/R1 excepts a different rule, the external-data join) |

## Placement under ADR-1005

**Ruling: re-scope, not a carve-out, except the D5 (as amended, R1) and closed D13
maintainer exceptions.** Apart from those two exceptions, the interpretation half of
Domain 41 is not built in-server; the exceptions put a small amount of interpretation in
core, by maintainer ruling (Consequences, "The cost"), and are not a class-level precedent
for any other row. The parts below marked **core** are permanently server- or
agent-resident. "Store ownership follows the layer" (ADR-1005 Consequences, `:697`), so
the raw stores stay core and any engine-derived state is the engine's own.

Rows for slices 2 and 3, and for 41.5 and 41.6, are **planned, not committed**. They
classify the work if it is built; they do not promise it. The exception is a first 41.6
CBOM export of the slice-1 crypto-library inventory, which is built and on `dev` (#6123, landed
by #6143): library components only, no `purl`.

| Domain 41 element | Slice | ADR-1005 class | Justification (Decision 2 + tiebreakers) |
|---|---|---|---|
| `installed_software` daily-sync source (existing) | 1 | **core** | Collection and transport of estate facts on the ADR-0016 framework. |
| Library-family table `crypto_library_model` (12 families, versioned) | 1 | **core**, conditional — D2 (maintainer ruling) | Deterministic identity resolution ("which library is this package?") over fleet-internal data, with no external data. Same class as ADR-0024's `product_normalize`, ruled core at `0024:162`. The conditions in D2 keep it there. |
| Per-family / per-version distinct-device rollups, coverage pair | 1 | **core** | "pure aggregation of fleet-internal facts" (ADR-1005:47). |
| `/api/v1/crypto/*` reads + MCP twins + `/crypto` page | 1 | **core** | Raw-fact reads, admit-then-filter confined. The REST+MCP twin satisfies Decision 1. |
| Bundled (vendored, app-shipped) shared libraries such as `libcrypto.so` / `OpenSSL.dll`, identified by file identity | 1 gap | **core** (collection) — via ADR-0028 | ADR-0028 is "agent-side collection mechanism ... stays core" (ADR-1005:707). It identifies a component by declared file identity (soname, VERSIONINFO, `LC_ID_DYLIB`; `0028:112-122`), which D2 condition 2 admits. Domain 41 consumes that output and does not build a second collector. |
| Statically linked crypto, and OS-native providers (Windows CNG/Schannel, macOS CommonCrypto/Security.framework, the Linux kernel crypto API) | — | **gap** | Not package-visible, and ADR-0028 records statically linked code as "largely unrecoverable" (`0028:307`). OS-native providers are part of the OS version, which the device inventory already reports. A future way to see either is collection, so core. No vehicle exists. |
| Certificate collection (agent): read-only enumeration of certificate stores and trust-store files | 2 | **core** | Collection of estate facts. Parallel to `vuln_scan`'s inventory action, which ADR-1005 keeps core. Bound by D6 and D12. |
| Certificate daily-sync source + typed store of raw X.509 fields | 2 | **core** | Transport and storage of collected facts (ADR-0016 §7 typed projection). Bound by D12. |
| Raw X.509 fields: subject, issuer, serial, validity, key algorithm + size, signature algorithm, SANs, KU/EKU, basic constraints, SHA-256 fingerprint, store/location | 2 | **core** — subject and SAN may be personal data (D12) | Each is a field of the certificate as found on the device. Naming an algorithm is a fact; grading it is not done here. |
| Certificate ↔ private-key association: whether a key is associated with the certificate and, where the platform exposes it without opening the key, whether it is exportable and hardware- or TPM-backed (never the key; an associated key may since have been deleted) | 2 | **core** | Facts about the device's key storage, read from metadata, never from key material (D6). On Windows, export policy needs the key opened, so it is not collected there unless the design doc shows a way that opens no key. |
| Certificate read surface (REST + MCP + dashboard), raw-value rollups, paged per-certificate read | 2 | **core** — D12 | Raw-fact reads under existing confinement and audit. These are also the core capability an engine reads through (ADR-0031 seam B6, D9). |
| Caller-parameterised filters (e.g. `not_after < T`, `key_bits < N`) and distinct-device counts by raw value | 2 | **core** — D4 | A generic query primitive. The caller supplies the threshold, so the semantics are the caller's, not code-baked. |
| Fixed dashboard windows: active; expiring within 3/7/14/21/30/60 days; expired, revoked within the last 7/30/60/90 days; issued within the last 7 days; issued and revoked per ISO week over 52 weeks, the current, partial week included; registered CRLs past their `nextUpdate` (`crl_past_next_update`) | 2, except the Yuzu-CA counts | **core** — D13 (maintainer ruling) | Counts over raw dates against Postgres `now()` at read time, each response carrying the `as_of` time it used (R4), with the window edges of R5. A closed, versioned window set ruled into core by the maintainer. Fleet-certificate revoked windows count only revocations stated under D5's revocation-statement rule (R1) and are fleet rows under D12's dedicated certificate securable and confinement. The Yuzu-CA active, expiring, expired, issued and revoked counts are CA-population counts through a `CaStore` count method, revocations in three reason buckets (`superseded`, `unpublished`, other), gated by `Inventory:Read`, withheld from a confined caller and never joined to fleet rows (D13, R2, R6). They need no slice-2 data and can ship before slice 2 once that count method exists. `crl_past_next_update` has the registered-CRL list's audience (R9). |
| Expiry risk scores, "at risk" labels, Yuzu-chosen expiry notifications (roadmap Issue 18.3 "expiry alerts") | 2 | **UCE** — D4 | Derived against "now" with a threshold Yuzu chooses, beyond D13's closed set. Same class as ADR-0024's *effective licence state* (`0024:126-128`), which that ADR sends to the engine. |
| Operator-authored policy over certificate facts (e.g. an operator's rule "fail if `not_after` < now + 30d") | 2 | **core** | "operator-authored content evaluated by a generic engine" (ADR-1005:47). The operator owns the semantics. Not available until slice 2 exists (D4). |
| Chain-to-local-trust-store result computed on the device, with no network retrieval and no revocation check | 2 | **core**, only under D5's conditions; optional, not committed | A deterministic fact about the device's own configuration. A chain build that fetches, or consults revocation data, is a join with third-party data, so engine territory (D5). |
| Revocation status of fleet certificates from operator-registered CRLs | 2 | **core** — D5 as amended (maintainer ruling, R1) | A maintainer exception to ADR-1005's join-with-external-data tiebreaker, resting on a CRL entry being the CA's own signed statement of fact, matched by issuer and serial; operator registration of the source is a condition of it. Statements follow D5's revocation-statement rule; anything else reads "revocation not checked", with the cause. |
| Revocation status from OCSP, or from CRL URLs taken from the certificates under inventory (AIA, CDP) | 2 | **UCE** — D5 (maintainer ruling) | A join of fleet data with external data, for a judgement, outside R1's exception. A URL a certificate supplies is untrusted endpoint input (D5 condition 3), and OCSP is excluded by R1. |
| Registration of third-party CAs and their CRL URLs, and the server-side CRL fetcher that retrieves exactly the registered URLs | 2 | **core** — D5 as amended (maintainer ruling, R1) | Collection of operator-chosen reference data, under the obligations D5 and D12 list (registration twins, an admin-only securable in both RBAC states, audit verb, fetcher security review, leader-gated refresh, Postgres store, alerts on fetch failure and `crl_past_next_update`). |
| Certificate renewal, re-issue, deletion, revocation workflow (roadmap Issue 18.3 lifecycle) | 2+ | out of scope here | These are mutations, not reads. When designed, they go through ADR-0033's Execution Plan and approval primitive. The existing `certificates.delete` action is Destructive/Irreversible and is never part of the inventory path (D6). Renewal against an external CA (ACME, AD CS) is a connector-class join, to be classified against ADR-1005's Decision-2 appendix "Connectors" row once that row exists (PR #5367). |
| SSH key-at-rest collection: host public keys; `authorized_keys` entries and user public keys (type, size, fingerprint, location; never key content) | 3 | **core** (collection) — privacy owed (D8) | Collection of estate facts. The per-user parts carry privacy obligations the slice-3 ADR must decide. |
| SSH login evidence (who, from where, with which key type) | 3 | **core** (collection) — privacy owed (D8) | Collection of estate facts, but behavioural personal data. ADR-1005 Decision 5's controls will attach to any engine that consumes it. |
| Fleet-wide aggregate counts of SSH keys observed in use within 24h/3/7/21/30/60/90/120/180 days, and with no observed use | 3 | **core** — D13 (maintainer ruling, R3), collection still privacy-owed (D8) | Counts over raw observation timestamps at read time, never per device or per user. The slice-3 ADR sets the minimum cohort, the audit verb and the collection privacy decisions, and may hold the windows back until collection is permitted, but cannot remove them. |
| "Unused / stale / anomalous key", "key used from an unusual location" | 3 | **UCE** | Semantics baked into code: a judgement about behaviour. A D13 count with no observed use is a count, not a "stale" label. |
| Protocol and configuration settings: enabled TLS/SSH versions; cipher, KEX and MAC lists; system crypto policy | 41.5 | **core** (facts) / **UCE** (verdicts) | The configured list is a fact. "Weak cipher enabled" is a verdict. No collection vehicle is designed; it needs its own design. |
| CBOM export of the collected inventory | 41.6 | **core**, facts only — D7 (maintainer ruling) | A projection of core facts into a standard format, like ADR-0028's SBOM projection. Verdict-bearing CBOM fields are left empty in core. |
| D13's four weak-key rules: MD5 signature, SHA-1 signature, RSA key under 2048 bits, EC key under 224 bits | 2 | **core** — D13 (maintainer ruling) | Semantics baked into code, ruled into core by the maintainer as a closed, versioned exception. Each rule is shown with its criterion and is reproducible from the raw fields. |
| Any other weak / deprecated / broken algorithm and key-size label; PQC readiness; crypto-agility scoring | all | **UCE** | Semantics baked into code, tied to an external standard and threat model. The canonical engine case. |
| Library support / EOL / "out of date" status | 1 | **UCE** — D3 (maintainer ruling) | Domain data about third-party projects, used for a judgement. |
| CVE matching over crypto-library versions | 1 | **UCE** — the vulnerability module | Already engine territory by name ("vulnerability feeds", ADR-1005:47) and by the execution plan's catalogue-grain design (execution plan Decision 5). Domain 41 does not build a second matcher. |
| Mapping to frameworks (NIST SP 800-131A, CNSA 2.0, PCI DSS, FIPS 140 status, ...) | all | **UCE** | "compliance-framework mappings" is named engine territory (ADR-1005:47). |

## Decisions

Each decision is tagged **[core]** (built in-server), **[UCE]** (use-case engine only),
**[split]**, or **[process]**.

### D1 — Domain 41 is core collection plus a deferred engine half [split]

Domain 41 is split as the placement table states. The core half is buildable now, slice by
slice, each under its own design.

The engine half is a scoped backlog for a future "cryptographic posture" use-case-engine
module, not an immediately buildable target. Three things stand in the way:

- no engine host exists;
- engines are headless (ADR-0031 Decision 4), so the module would have no UI of its own;
- the ADR-0032 interlock is closed (D9).

No in-server crypto verdict is ever built as an interim measure. That differs from the
vulnerability vertical, which shipped in-server first and was grandfathered (ADR-1005
grandfathered surface #2). The difference is timing. In ADR-0024's words, re-scoping is
"the cleaner outcome Decision 2 [ADR-1005] points to when the work has not yet shipped"
(`0024:203-205`).

### D2 — The library-family table is identity resolution, under four conditions [core]

The slice-1 table answers "which library is this package?". The same question is
answered elsewhere:

- ADR-0024's `product_normalize` answers it for licences, described there as
  "deterministic identity resolution over pure fleet-internal aggregation (a generic
  engine, no external data)" (`0024:162`).
- The software-catalogue rollup answers it for names.

It is mechanism.

**The strongest counter-argument** is the agent `vuln_scan` plugin's embedded
`cve_rules.hpp`. That is also a curated, compiled-in list, and the execution plan freezes
and deprecates it as interpretation (execution plan Decision 8). The two differ in what
the list *asserts*:

- `cve_rules.hpp` asserts a judgement ("this version is vulnerable"), derived from
  external domain data (CVE feeds).
- The family table asserts identity only ("`libssl3` is OpenSSL"). It carries no field
  about quality, support or vulnerability.

**The table stays core only while all four conditions hold:**

1. **Identity only.** A rule maps a component's declared identity to a family. The table
   carries no attribute that grades a family or a version: no strength, support, EOL,
   CVE, PQC or preference field, and no colour or severity in any surface that renders
   it. Adding one moves that attribute, not the table, to the engine.
2. **Deterministic and inspectable.** Matching uses a component's *declared* identity only:
   - a package name today;
   - for ADR-0028 components, a soname, a VERSIONINFO product name or an install name.

   Matching is exact or prefix on the declared *name* only. It reads nothing from a file
   beyond its declared-identity record (no code bytes, hashes or embedded strings), and it
   never matches on version strings or publisher heuristics. The table is versioned: `table_version` is on every response and in the
   drill-cursor fingerprint, so a consumer can tell which mapping produced an answer.
3. **Inclusion is factual, not evaluative.** A family is included because it *is* a
   cryptographic library. Exclusions are factual too: for example, `nss-mdns` is a
   name-service plugin, not NSS cryptography. A family is never included or omitted
   because it is considered good or bad.
4. **No second copy.** The SQL patterns are generated from the same table
   (`sql_patterns()`), and every store result is re-checked with `classify()` before it is
   shown. A second, divergent list would turn the table into two answers to one question.

Conditions 2 and 4 are checkable in code. Conditions 1 and 3 are review judgements, so
D10 makes them a placement finding when broken.

**Known cost, accepted.** The table's family ids are compiled into the public contract:
the `family` enum in the OpenAPI spec and the MCP input schemas. Changing the taxonomy is
therefore a contract change. That is acceptable for identity data, and `table_version`
exists for it.

A future engine can consume the results but cannot supply its own taxonomy through
`CryptoApi`. If one ever needs to, the store primitive underneath is domain-free
(`NamePatternQuery`, "the store never learns what a label means",
`software_inventory_store.hpp` at PR #6056). A caller-supplied-pattern read could then be
added in core without moving anything.

**If a later ruling reverses D2,** the slice-1 surfaces are on the versioned `/api/v1/`
and MCP contract from birth, so the reversal goes through the standard deprecation
process:

- Re-homing or removing them follows the execution plan's Phase 0.3 deprecation cycle,
  the cycle ADR-1005 grandfathered surface #2's rider (a) applies to versioned surfaces.
- Removing the `/crypto` page also needs ADR-1005 Decision 7's dashboard deprecation
  cycle. Removal of a depended-on dashboard surface "is a breaking change requiring a full
  deprecation cycle".
- These are the same terms ADR-0024's re-home note records for `/api/v1/sle/*`.

**Maintainer ruling requested:** confirm that D2's identity-resolution reading, with the
four conditions, is the binding classification.

### D3 — Library support and EOL status are engine territory [UCE]

Whether a library version is supported, end-of-life, current or out of date is a
judgement about a third-party project. It needs two things Yuzu would have to choose and
keep current:

- external domain data (upstream release and support schedules);
- a policy for what "current" means.

ADR-1005's carve-out does not move it into core. The carve-out says only that
infrastructure fetches such as OS-EOL metadata "are not 'domain data'". That removes the
external-data tiebreaker, but it does not exempt a fetch from the boundary test itself,
and the test asks what the data is *for*. Using upstream support schedules to grade the
estate's software is interpretation, whoever fetches the schedule. So slice 1's
self-imposed rule (never "current or out of date") becomes a decided rule rather than an
inference.

**The class is wider than Domain 41.** Read this way, grading any estate software as out
of support, OS versions included, is engine territory. The platform may still fetch OS-EOL
metadata for its *own* operation, for example to decide which agent builds it supports.
If the maintainer intends the OS-EOL carve-out to cover grading OS versions in core, the
ruling should say so here, and D3's class narrows to third-party libraries.

**If reversed** (library EOL ruled core), core gains an outbound fetcher for upstream
lifecycle data. That fetcher needs its own security review: egress, source integrity and
failure behaviour. D10 and slice 1's no-"out of date" rule would also change in the same
change:

- `crypto_library_model.hpp:10-14`;
- the capability-map §41 preamble;
- `crypto.md`.

**Maintainer ruling requested:** confirm the purpose-based reading of the OS-EOL carve-out,
and whether it is intended to reach OS-version grading. Record it in ADR-1005's Decision 2
examples appendix (D11).

### D4 — Expiry: raw dates and caller thresholds are core; Yuzu-chosen bands are not [split]

**What core stores.** Core stores each certificate's validity dates as found, in UTC, to
the second. RFC 5280's `99991231235959Z` no-expiry sentinel and other edge dates are
preserved unclamped. Today's plugin truncates dates to `YYYY-MM-DD`, so the slice-2
collector must read full precision.

**Apart from D13's closed window set, core's built-in fields and reads never compare a
certificate's dates against the server's own clock.** Every such comparison takes a time T
the caller supplies. That includes "already expired", which is a query with T = now, chosen
by the caller, not a field or a label. Operator-authored policy and D13's windows (each
carrying `as_of`) are the only places a comparison may use "now": policy because the
operator wrote it, and must name whose clock "now" is (below); D13's windows because the
maintainer ruled them in, and they use Postgres `now()` (D13, R4).

**Core may offer:**
- filters and counts whose threshold the caller supplies (`not_after` before T, after T,
  or between T1 and T2);
- histograms with caller-supplied bucket edges;
- sorting by `not_after`;
- operator-authored policy over these facts, evaluated by the existing generic engines.

Today that means the agent-side policy engine (policy rules, Guards) evaluating the
certificate facts the agent collects. No server-side generic rule or alerting engine over
a typed inventory store exists yet. Any such rule must name the clock it compares against,
and an agent-side evaluation discloses the agent's clock offset from the server's receipt
time. None of this is available until slice 2 exists.

**Core does not ship** (except D13's closed window set, which supersedes this list for
those windows only):
- a built-in notion of "expiring soon" beyond D13's windows (no "at risk" label, no
  colour coding of dates);
- expiry scores;
- notifications on a Yuzu-chosen threshold (roadmap Issue 18.3's "expiry alerts", when
  Yuzu picks the threshold).

These are derived against "now" under a policy Yuzu would choose. That is the same class
as ADR-0024's *effective licence state*, which is derived against "now" and assigned to
the engine (`0024:126-128`). An expiry check the *operator* writes, with their own
threshold, is operator-authored content, so it is core.

### D5 — Revocation and trust: device-local facts core (they carry no revocation dates); revocation of fleet certificates core only from operator-registered CRLs [split]

Two different questions both get called "is this certificate valid?".

**Device-local trust.** Does the certificate chain to a root in the device's own trust
store? This is a fact about the device's configuration. It stays core only under three
conditions:

1. **No network retrieval.** The chain build must not fetch anything: not AIA, CDP or
   OCSP URLs, and not root-store auto-update. The OS chain APIs fetch by default.
   - Windows `CertGetCertificateChain` must be called with
     `CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL` and `CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE`.
   - macOS `SecTrust` evaluation must call `SecTrustSetNetworkFetchAllowed(trust, false)`.
   - The Linux OpenSSL verifier must be given no fetching lookup method.

   The implementing PR verifies these flags against the platform documentation and proves
   them with a test that observes zero outbound connections.
2. **No revocation check.** The build must pass no revocation flags: on Windows no
   `CERT_CHAIN_REVOCATION_CHECK_*`, on macOS no revocation policy, on Linux no CRL check.
   On Windows a revocation check can be answered from a *cached* CRL or OCSP response even
   with network retrieval off, so condition 1 alone does not exclude third-party
   revocation data.

   Two kinds of locally held data affect an OS trust evaluation, and D5 treats them
   differently:
   - **Distrust lists the OS vendor pushes.** For example: Apple's synced "Valid" database,
     which macOS `trustd` keeps under `/private/var/protected/trustd/`; Windows' Disallowed
     store and its untrusted-certificate list. These are maintained by the OS, are part of
     what the device will in fact trust, and are treated as **device configuration**,
     provided the chain build triggers no fetch of them. A result that reflects them says
     so: "what this device's OS trust evaluation returns, including OS-vendor distrust
     lists", never "valid" or "not revoked" in general.
   - **Cached responses from a certificate authority** (a cached CRL, or a cached OCSP
     response, such as `trustd`'s OCSP cache). These are third-party revocation data, and
     condition 2 already excludes them.

   **Outcome required:** a core result must be independent of every CA's own CRL and OCSP
   responses, fetched or cached. An OS-vendor distrust list counts as device configuration
   even where the vendor built it partly from CA data. On any platform where the implementation cannot show that (for
   example, if macOS `trustd` applies its OCSP cache whatever policy the caller passes), the
   chain result is **not built in core for that platform**.

   This reading is part of D5's maintainer ruling.
3. **AIA, CDP and OCSP URLs are untrusted endpoint input.** A low-privileged user can
   plant a certificate in a per-user store. That would make an agent running as SYSTEM or
   root fetch addresses of the attacker's choosing: request forgery towards internal
   addresses, or, on Windows, NTLM authentication to an attacker's SMB or HTTP server.
   Conditions 1 and 2 are what prevent that.

A chain build that cannot meet all three is engine territory, or is not built. The result
is **optional, not committed** for slice 2. The current plugin deliberately does no chain
or revocation work; its README says it "deliberately does not validate a certificate's
trust chain, check revocation".

Device-local facts carry no revocation dates. Neither the chain result nor an OS-vendor
distrust list says when, or by whom, a certificate was revoked, so neither is phrased
"revoked" and neither feeds D13's revoked windows.

**Revocation status (amended by maintainer ruling R1, 2026-10-19).** Teams must be able to
see fleet certificates revoked by their own and by other CAs. Revocation status is core
**only** through **operator-registered CRLs**:

- **Registration.** An administrator registers a CA: its CA certificate plus one or more CRL
  URLs.
- **Fetching.** A server-side fetcher retrieves **only the exact registered URLs**. It never
  fetches a URL taken from a fleet certificate (AIA, CDP or OCSP). It follows redirects only
  to registered URLs, sends no credentials, and bounds its timeouts and response sizes.
  Internal addresses are allowed **only** because an administrator registered that exact
  URL, for example an AD CS CRL on an internal host.
- **OCSP is not included.**

**Revocation statements.** For a fleet certificate, core states revocation status only from
a CRL that:
1. verifies against a CA key registered for that CA. A registered CA may hold several keys,
   so a CA renewal does not break verification.
2. is in scope for the certificate:
   - issuer by DER Name equality, authority key identifier (AKI) where present, and serial
     compared as an integer, not as text;
   - a partitioned CRL only within its distribution point and reasons;
   - a delta CRL only together with its base.
3. is not older than the newest verified CRL already held for that scope, by CRL number
   (else `thisUpdate`). An older CRL is never stored over a newer one.

From such a CRL it states one of:
- "revoked on <revocationDate> (reason <r>)". A `certificateHold` entry reads "on hold",
  never "revoked";
- "not listed on <CA>'s CRL of <thisUpdate>, next update <nextUpdate>", never "not revoked"
  or "valid". From a CRL that covers only some reasons (`onlySomeReasons`), the statement
  names the reasons it covers (R13).

Every per-certificate statement carries the same matching basis as the counts. Unless the
certificate's signature was verified against the registered CA key, "revoked" reads
"matched by issuer and serial: revoked on …", and "not listed" reads "matched by issuer and
serial: not listed on …". So a planted certificate that copies a registered issuer and a
serial cannot read as plainly revoked, or as plainly not listed. A certificate with no
AKI, whose signature was not verified, reads "revocation not checked" (issuer name alone
does not bind it to the registered CA). Signature verification is done by the server
against the DER the agent ships, not taken from the agent's own claim.

In every other case it reads "revocation not checked", with the cause. The causes are:
- issuer not registered;
- no CRL fetched yet;
- verification failed;
- over the size bound;
- out of scope;
- the certificate was already past its `notAfter` at the CRL's `thisUpdate`, and the CRL
  carries no `ExpiredCertsOnCRL` extension covering it (CAs drop expired entries).

The last verified CRL is kept when a later fetch fails, and its `thisUpdate` and
`nextUpdate` are shown. A failed or unverifiable fetch never turns a certificate into "not
listed". A registered CRL whose `nextUpdate` is before `as_of` is disclosed through D13's
`crl_past_next_update` window, with its criterion; there is no free-standing "stale" label.

Matching uses facts the agent reports. A revoked count is a count of certificates that name
that issuer and serial, and it says so, unless the server verified the certificate's
signature against the registered CA key, from the DER the agent ships. Every
revoked-window count also reports how many certificates in scope are "revocation not
checked", and beside it how many were checked against a CRL covering only some reasons
(R13).

Read-time CRL matching is admitted through the `/crypto` read gate (D12), like every other
Domain 41 read.

**Why this is core.** R1 is a maintainer exception to ADR-1005's join-with-external-data
tiebreaker. It rests on the CRL being the CA's own signed statement of fact, matched to the
certificate by issuer and serial, not a Yuzu grade: Yuzu chooses no standard and no
threshold. Operator choice of the source is a **condition** of the exception, not its
justification. Operator choice alone moves no join into core: an operator-configured
vulnerability feed is still engine territory.

**Still engine territory, or not built:** OCSP, and any revocation status fetched from a
URL taken from the certificates under inventory. Those URLs are untrusted endpoint input
(condition 3): a low-privileged user who plants a certificate chooses them. No fetcher,
in core or in an engine, takes a URL from a fleet certificate.

**Unchanged by R1:** the device-local chain conditions above. The chain result still never
reflects any CA's CRL or OCSP response, fetched or cached; registered-CRL status is a
separate, server-side fact shown beside it, never folded into it.

ADR-1005:47's "CRL" example covers the platform's *own* revocation needs, for example Yuzu's
internal CA publishing its CRL (`CaStore::publish_next_crl`, ADR-0053) and the agent's
signature verifier loading a local CRL file (`detached_signature.cpp`). The registered-CRL
path does not rest on that carve-out; it rests on R1. The obligations owed by its design are
listed in D12.

**If reversed** (R1 withdrawn), revocation status of fleet certificates is engine territory
again, the registration surface and fetcher are not built in core, and D13's fleet-certificate
revoked windows and `crl_past_next_update` are dropped. The Yuzu-CA counts are part of D13,
not of D5 (R1 covers fleet certificates), and so is the D6 exception that lets them read
`CaStore`; both are unaffected.

**Maintainer ruling** (D5, amended by the owner's rulings R1 and R13 on 2026-10-19): the
purpose-based reading of the "CRL" carve-out; OS-vendor distrust data already on the device
counts as device configuration under the conditions above; and revocation status of fleet
certificates is core only through operator-registered CRLs as stated here.

### D6 — The certificate inventory is read-only and stays apart from Yuzu's own PKI [core]

**1. Read-only by construction.** The inventory is collected by enumeration only. The
existing `certificates` plugin's `delete` action is Destructive / Irreversible /
AdminOrApproval (`server/core/src/capability_decls/plugin_action_catalogue_c.hpp`), and it
must stay unreachable from the
inventory:

- The daily-sync source runs plugin actions in-process through the agent's local
  dispatcher, so the server-side `ExecuteGate` never sees it. The sync source must
  therefore be a dedicated read-only collector, or a fixed list of read-only actions, and
  never `delete`.
- That list is checked by a compile-time assertion or a test against the catalogue's
  `DispatchClass::ReadOnly` / `Mutability::None` rows.
- No inventory surface may offer a mutation.
- Lifecycle mutations (roadmap Issue 18.3) are a separate, separately governed capability.

**2. No private keys.** The collector reads certificates and key *metadata* only: whether a
key is associated with the certificate and, where the platform exposes it without opening the key, whether it is
exportable or hardware-backed. It never reads key material, and it never
acquires or opens a key to find these things out.
- On Windows the metadata comes from certificate properties only, such as
  `CERT_KEY_PROV_INFO_PROP_ID`. Calling `CryptAcquireCertificatePrivateKey` or opening a
  key-storage-provider handle is not allowed: it can touch a smart card or raise a PIN
  prompt.
- On Linux the collector never opens private-key directories or key blocks in PEM files.

**3. Separate from `CaStore` and every trust anchor.** Fleet certificates are untrusted
endpoint reports. `CaStore` (ADR-0053) holds the authority data of Yuzu's own internal CA,
including the append-only revoked set that the mTLS accept path reads. So fleet
certificate rows:

- never live in the `ca_store` schema or reuse its tables;
- are never read by any PKI decision path;
- are never promoted into one.

No inventory surface or action may copy, import or pin a fleet certificate into any trust
anchor:

- the CA `import-chain` route (`ca_routes.cpp`);
- the client-CA bundle;
- gateway-peer SPKI pins (`--gateway-peer-pin` / `--gateway-peer-pin-file`), which share
  the inventory's SHA-256 fingerprint shape;
- the signature-verifier anchors.

The same holds for the CA certificates registered under D5's R1 path. A registered CA
certificate is supplied by an administrator, never imported from fleet rows, and never a
trust anchor for any PKI decision path; it is used only to verify registered CRLs.

The inventory does not read `CaStore`, except D13's Yuzu-CA counts through a `CaStore`
method, never joined to fleet certificate rows (amended by the owner's D13 ruling,
2026-10-19). That method is a new count method on `CaStore`, never a read of the
`ca_store` tables, and falls under the PKI routed-concern review when built. Its query
cost (the indexes it relies on and a bounded statement time) is a review item for that
method. Correlating
fleet certificates with Yuzu-issued ones would be a separate feature, reading `CaStore`
through its own core interface and never its tables, under its own review.

These are placement constraints. The slice-2 data design — which stores and fields to
collect, per-OS coverage and the typed-store schema — is owed by the slice-2 design doc
and its own review. It must also cover the collection gaps found while preparing this ADR
(as of 2026-10-18, origin/dev):

- **Fields:** none of key algorithm and size, signature algorithm, SANs, EKU, basic
  constraints or a SHA-256 fingerprint is collected today. The thumbprint is SHA-1 only.
- **Windows:**
  - Subject and issuer are a simple display name, not the full DN.
  - Only four LocalMachine stores are read (MY, ROOT, CA, Trust).
  - When LocalMachine cannot be opened, the plugin falls back to CurrentUser, which under
    the agent's service account is that account's own store, not a person's.
- **Linux:**
  - Only `/etc/ssl/certs` is read.
  - Only the first certificate in each file is kept, so a bundle file yields one row.
  - Other trust stores are not read: `/etc/pki`, local CA directories, Java `cacerts`,
    PKCS#12 and application stores.
- **macOS:** `System.keychain` and `SystemRootCertificates.keychain` are read in-process.
  The console user's login keychain is read by a `security find-certificate` subprocess
  launched in that user's launchd session through the agent's bounded process runner.

### D7 — CBOM export is core when it carries facts only [core]

A cryptographic bill of materials (for example CycloneDX's cryptographic-asset
components) is a projection of collected facts into a standard format. It is core
mechanism, like ADR-0028's SBOM projection.

**Verdict fields stay empty.** Some CBOM schemas have fields that carry verdicts:
security-level fields, such as CycloneDX's classical and NIST-quantum security levels,
and any "weak" or "approved" classification. Core leaves those fields empty or omits them,
and never fills them from a table it ships. An engine may emit an enriched CBOM from
core's facts plus its own verdicts. The exact field list is verified against the CBOM
schema version chosen at implementation.

**The export is an ordinary core read, not a side door:**
- it has REST + MCP twins (ADR-1005 Decision 1);
- it is confined by ADR-0017 to the caller's devices and audited per export;
- it is bounded or paged, and goes through the shared `/crypto` admission gate (D12);
- each half is gated by its own securable. The library half uses slice 1's gate; the
  certificate half uses D12's dedicated certificate securable (admin-only while RBAC is
  off). A caller who lacks one half's securable gets an export
  without that half, and the coverage metadata says it was left out. An omitted half never
  reads as "no certificates" or "no libraries".

**It must not be mistaken for complete.** Every export carries its coverage (devices
included, devices reporting), its confinement (fleet-wide or confined) and whether it was
truncated. A truncated export is marked or refused, never presented as the whole estate.

**It is not a bulk-egress route for engines.** ADR-1005 defers bulk egress (`:697`).

**Maintainer ruling requested:** confirm CBOM export as core under these conditions.

### D8 — SSH placement is decided here; SSH privacy is not [core collection, owed ADR]

Placement is the easy half of slice 3:
- **Collection is core:** host public keys, user public keys and `authorized_keys`
  entries as keys at rest (41.3, recording type, size, fingerprint and location, never key
  content), and login evidence (41.4).
- **Behavioural judgements are engine territory:** behavioural labels ("stale",
  "unused", "anomalous") and unusual source locations stay engine territory. A D13
  fixed-window count of keys with or without observed use is a count, not such a label
  (amended by maintainer ruling R3, 2026-10-19). Those counts are fleet-wide aggregates
  only, never per device or per user. The slice-3 ADR sets their minimum cohort, their
  audit verb and the collection privacy decisions below; it cannot remove the windows, but
  it can withhold them until collection is permitted.

Privacy is the hard half, and this ADR deliberately does not decide it. The slice-3 ADR
must decide privacy before any slice-3 code is written. It must at least settle these:

- **Per-user material is not machine-scope.** `authorized_keys`, `~/.ssh` and Windows
  `administrators_authorized_keys` hold per-user data, even when the file sits at a
  machine path. That includes:
  - key comments, which often carry `user@host`;
  - `authorized_keys` options: `from=` carries addresses and host names, and `command=` /
    `environment=` can carry secrets.

  Precedents: ADR-0024 D11's pseudonymised `user_ref`, and `browser_inventory`'s
  Forensics-class, default-off, single-target posture.
- **Host keys are machine-scope, but only the `.pub` halves are read.** The private host
  keys sit beside them and are never opened, and neither are users' private keys
  (`~/.ssh/id_*` without `.pub`).
- **Link-safe opens.** A user controls everything under their home directory, including
  whether `~/.ssh` is itself a symlink. A privileged agent must never read a file outside
  that user's own SSH files because of a link the user planted. The required outcome is
  that every directory and file is opened hop by hop from the home directory without
  following links (`openat`-style, as the `runtimes` and `privacy_permissions` plugins do),
  and each file is accepted only if:
  - it is a regular file;
  - it is owned by the home directory's account;
  - it has a single link, which excludes hard links to other files (macOS has no
    protected-hardlinks setting).

  Checking only the last path component is not enough.
- **Fleet-wide versus single-target.** A daily sync is fleet-wide by design. The Forensics
  securable is single-target (`requires_explicit_targets`, `docs/authz-model.md` §4). The
  slice-3 ADR must choose which posture each SSH source takes.
- **Login evidence is behavioural personal data.** These controls apply:
  - `emit_behavioral_audit`;
  - ADR-1005 Decision 5 ("bulk sync of behavioral PII requires explicit security-guardian
    design review", `:67`). This will bind any engine that consumes the data; Decisions
    5–7 gain their remaining force with their follow-ups (ADR-1005:17);
  - ADR-0032 D14: engine behavioural reads fail closed on audit failure on every surface.
- **ADR-0067** is proposed in PR #5367 and not accepted. If it is accepted as drafted:
  - its D3 denies an individually-identifying behavioural read of an in-purview subject
    unless the read is made under an approved Incident;
  - its D5 says an EU co-determination deployment "must not enable ... any other new
    individually-identifying source" until purview enforcement ships;
  - its D6 and D7 define the Incident state machine and a single pre-read
    `authorize_behavioral_read` gate.

  The slice-3 ADR must be written against whatever state ADR-0067 is in at the time.
- **DPIA, retention and processor obligations.** The slice-3 ADR must record:
  - a DPIA and works-council precondition before collection is enabled;
  - a retention decision for SSH key rows and login evidence, following the
    clock-guarded-retention routed concern for any prune;
  - the data-processor obligations an engine takes on when it consumes this data (the
    ADR-0024 re-home note is the precedent).
- **Collection mechanism.** Login evidence comes from logs: the sshd journal and auth logs,
  and the Windows OpenSSH event log. That makes a TAR cursor source the likely collector,
  with its no-silent-replay contract. An `app_usage`-style daily-sync hand-off follows if
  the data is centralised at all. The slice-3 ADR must choose.

### D9 — The engine half waits for the ADR-0032 interlock [UCE]

No part of the engine half ships until ADR-0032's unconditional set **(a)–(d) and (h)** is
green (`0032-use-case-admission-protocol.md:964-967`). As of 2026-10-18, cell (a) is green
and (b), (c), (d) and (h) are red (`tests/split_interlock_ledger.json`; the tripwire
reports "merge-gate CLOSED (red: b, c, d, h)").

ADR-0032's own table also gates specific paths, and it binds in full. A module ships
without one of those cells only if it does not walk that path. The cells most likely to
apply here:

| Cell | When it applies |
|---|---|
| (g) derived-state confinement | persisting any derived state across runs, such as a fleet posture score or cached per-certificate verdicts (ADR-0031 INV-31-2: "before a module persists its first cross-run rollup") |
| (f) per-action mutability in the plugin ABI | dispatching to agents |
| (i) outcome correlation + the coverage envelope | every distributed fact read and every effect |
| (j) generated OpenAPI / `tools/list` | reachability over REST or MCP |
| (k) operational readiness (new stores in the readiness conjunction, reaper liveness alert) | admitting a run in anger |
| (l) intra-module cross-run isolation | concurrent runs whose scope ceilings span operators who must not be blended |
| (m) per-principal quota caps | production admission |
| ADR-0032 D14, ADR-1005 Decision 5 | consuming slice-3 behavioural data |

Nothing in the core half touches an engine-path marker. A core-only Domain 41 slice does
not need the interlock, and this ADR does not change the tripwire's marker sets.

**How the engine reads.** The vulnerability module's design is the pattern: read raw facts
through core's versioned reads, expand only the hits to devices, and never hold a fleet
replica (execution plan Decisions 5 and 6). Cross-component data reaches an engine only
"through a core capability" (ADR-0031 seam B6). So each slice must ship a read at a grain
an engine can consume.

**What exists today, and what slice 2 adds.**
- Slice 1's family/version summary is close to that grain. It lacks the distro `release`
  field, which only the device drill carries, and it can truncate.
- Truncation flags are therefore binding input for an engine, never advisory. An
  engine-facing read either returns complete results, paged, or fails.
- Certificates have no small catalogue grain. Slice 2 therefore ships raw-value rollups
  (algorithm, key size, signature algorithm, `not_after` histograms with caller-supplied
  edges) and a paged per-certificate read (D12).

**CVE matching** over crypto-library versions belongs to the vulnerability module. The
crypto-posture module, when scoped, must not build a second matcher.

### D10 — Core surfaces state what they do not judge [core]

Every Domain 41 surface — REST, MCP and the dashboard — keeps slice 1's posture:
- its description says "facts only; the only built-in checks are D13's named rules and
  windows, each shown with its criterion";
- it renders no grading colour, icon or ordering by assumed risk (ordering by device count
  or by a raw field is fine);
- it states its blind spots honestly: an empty result is not proof of absence, and it
  names the stores or roots a collector does not read.

**New fields** on these responses must be facts under the "is, not how good" test and the
derived-field rule above. A review finding against this decision is a Decision-2
placement finding, not a style finding.

**A mechanical guard.** Slice 2 adds a lint over the Domain 41 OpenAPI and MCP schemas
that rejects verdict-shaped field names: `weak`, `strong`, `risk`, `score`, `expired`,
`expiring`, `eol`, `supported`, `vulnerable`, `pqc`, `quantum_safe`, `approved`,
`compliant`, and similar. Review alone does not catch a field added later. The lint carries
the closed allow-list D13 defines, keyed by (surface path, field), each entry citing D13;
any other verdict-shaped name, or an allow-listed name on any other surface, still fails.
The same lint enforces D13's mechanical checks. D13's widgets still render no grading
colour or icon.

### D11 — Recording the boundary verdicts [process]

ADR-1005:47 says "verdicts accrete into an examples appendix in this file". As of
2026-10-18 no appendix exists on `dev`; PR #5367 (unmerged) would create one, with the
columns `Date | Class | Verdict | Raised by`. When the appendix exists, the five rulings
this ADR requests are added to it as rows. Each binds for the class it names:

| Ruling | Class | The Verdict cell must carry |
|---|---|---|
| D2 | curated identity tables | D2's four conditions — without them the class is wider than D2 rules on |
| D3 | third-party lifecycle data used to grade estate software | whether OS-version grading is included (D3) |
| D5 | third-party revocation status of fleet certificates | closed: admits only operator-registered CRLs, never the class; R1's conditions: core only through operator-registered CRLs fetched from exactly the registered URLs; a statement only from a CRL that verifies against a registered key of that CA, is in scope for the certificate and is not older than the newest held, reading "revoked on …", "on hold" or "not listed on <CA>'s CRL of <thisUpdate>, next update <nextUpdate>", each read "matched by issuer and serial" unless the signature was verified; a CRL covering only some reasons names them (R13); every other case reads "revocation not checked", with the cause; never a certificate-supplied URL; OCSP excluded |
| D7 | verdict-free standard-format exports | — |
| D13 | built-in crypto rules and dashboard windows | D13's conditions and R2–R14, and that the exception is closed: it admits only the listed rules and windows, never the class of built-in crypto verdicts |

For each row, Date is the merge date of this ADR's PR, and Raised by is "ADR-0070, PR
#<n>". This ADR does not edit ADR-1005, to avoid conflicting with #5367's appendix.
Adding the rows is a follow-up once that appendix exists.

### D12 — Binding obligations for the slice-2 design [core]

The slice-2 design doc must meet each of the following, or record why not and get that
reviewed. These are constraints, not the design.

**Read surface.**
- Reads are ADR-0017 admit-then-filter confined, with REST + MCP twins (ADR-1005
  Decision 1).
- **Who may read: a dedicated, narrow securable, in both RBAC states.**
  - **Why today's access is the wrong baseline.** Certificate data reaches people today
    by two routes:
    - live `certificates.list`: `Security:Read`
      (`server/core/src/capability_decls/plugin_action_catalogue_c.hpp`), reached only by
      dispatch, which also needs `Execution:Execute`;
    - stored results of earlier runs, readable under `Response:Read`/`Execution:Read`.

    A synced, fleet-wide, queryable copy exposes far more than scattered per-run results,
    even to principals who could read some of those results. So slice 2 does not inherit
    either route's breadth.
  - **What slice 2 does instead.** Reads are gated by a **dedicated certificate
    securable** that no other surface uses.
    - RBAC on: it is seeded only to Administrator, plus any role the design doc names and
      justifies. It is never granted implicitly through `Security:Read`, `Inventory:Read`
      or a seeded read-only role.
    - RBAC off (the default): it is admin-only. Do this by extending
      `authz_topology_floor.hpp` (never forking it) with the dedicated securable, the same
      way `Forensics:Read` is floored for app usage. The entry fits that header's
      inclusion class for preserving an existing admin-only posture: the live
      certificate list is admin-only under RBAC off today. Flooring a shared securable is not
      allowed: `Security:Read` also gates quarantine, the CA routes and key-management
      status, and `Inventory:Read` gates slice 1 and the generic inventory.
- **Gate and denial text take the securable as a parameter.** Slice 1 hard-codes
  `"Inventory","Read"` and the denial text "Inventory:Read is required". A synced copy must
  not widen who can see fleet certificates, and a denial must name the permission actually
  required. On a page that shows both halves, a denied certificate half says it was denied
  and never renders as "no certificates".
- **Audit and degrade.** Each read is audited with its own verb, recording fleet-wide or
  confined scope. A degraded read is a 503 with a retry hint, never an empty 200. Every D13
  count degrades the same way: a 503 with a retry hint, never an empty 200 or a zero.
- **Admission.** Reads, including read-time CRL matching (R1), are admitted through the
  existing `/crypto` read gate and degrade metric. Extend them; never fork them.
- **Truncation is disclosed on every read.** A read response that is capped (a page limit,
  a per-device limit, a rollup row ceiling) carries a named truncation flag. It never
  looks complete, and never looks empty.

**Raw fields D13 depends on.** The collector records, as raw facts, every field D13's
fleet-certificate rules and windows read, so that each of those counts is reproducible from
the paged per-certificate read (D13 condition 2; the Yuzu-CA, CRL and SSH counts recompute
from their own sources, as that condition lists):
- the signature algorithm OID and, for RSASSA-PSS, the hash algorithm from its parameters
  (the PSS hash parameter), because the OID alone does not name the hash;
- the key algorithm, the RSA modulus length, and for EC keys the named curve, so that the
  bit length of the curve's group order n is known.

**Registered-CRL revocation (R1).** Slice 2 builds R1 revocation status (D5 as amended).
Its design doc must also cover:
- **The registration surface:** register, list and remove a CA certificate and its CRL
  URLs, with REST + MCP twins (ADR-1005 Decision 1) and its own audit verb.
  - It is admin-only in both RBAC states. Extend `authz_topology_floor.hpp` for it, never
    fork it; a registered-URL list fits none of that header's three inclusion classes, so
    the same change amends the header's inclusion test and says why.
  - The list of registered URLs is admin-only too, because it reveals internal hosts.
  - The list serves each registered CRL's `thisUpdate` and `nextUpdate`, so that every
    viewer of `crl_past_next_update` can recompute it (R9).
  - Registered URLs are logged through the CWE-117 token helper (`log_token`,
    `common/include/yuzu/log_token.hpp`).
- **The fetcher's own security review.** It is a new egress surface. The review covers at
  least:
  - D5's retrieval rules: exactly the registered URLs, redirects only to registered URLs,
    no credentials, bounded timeouts and response sizes;
  - `http` and `https` URL schemes only (no `file:`, LDAP or UNC);
  - the resolved address checked against the registered host on every fetch, so DNS
    rebinding cannot redirect it;
  - D5's revocation-statement rule (verification, scope, no rollback) before any entry is
    used.
- **A background refresh job**, classified in `background_jobs.hpp` and leader-gated, with
  any prune following the clock-guarded-retention routed concern.
- **A Postgres store** for registered CAs and CRL entries (ADR-0006; ADR-0012 author
  contract), separate from `ca_store`. It is in the readiness conjunction (`/readyz`).
- **Alerts and metrics:** an alert on fetch failure and on `crl_past_next_update` (D13),
  following `docs/observability-conventions.md`. Each alert rule ships with a test proving
  it can fire. The `crl_past_next_update` alert reads a gauge the background job emits
  (R9), so it fires without anyone opening a page. R12 sets the gauge's shape and how the
  alert treats an absent gauge and several replicas.

**Personal data.**
- Certificate subjects and SANs can carry personal data: e-mail addresses (`rfc822Name`),
  UPNs and names, on user, client, S/MIME and smart-card certificates.
- Per-user stores (a person's Windows certificate store, a macOS login keychain) are
  per-user data. Including them is a privacy decision the design doc makes, following the
  ADR-0024 D11 (`user_ref`) and `browser_inventory` precedents.
- The design doc also records three things for what it collects:
  - the DPIA, works-council and retention position;
  - the RBAC-off posture above;
  - the data-processor obligations an engine takes on when it consumes certificate
    subjects and SANs. The ADR-0024 re-home note is the precedent: the engine becomes a
    data processor with its own retention and deletion duties, and ADR-1005 Decision 5's
    review applies to any bulk transfer of that personal data.

**Untrusted input.** Every certificate field is untrusted endpoint input:
- validated as UTF-8 at ingest, with invalid bytes replaced or the field refused;
- escaped at every render;
- token-escaped in audit details.

The source inherits ADR-0016's ingest caps (entries, field length, blob bytes) and adds
per-certificate bounds on SAN and EKU counts. Collection is deadline-bounded.

**Honest capture.**
- A store the collector could not read is reported `unreadable` with a reason token.
- Its last-known rows are kept per store, not replaced by an empty set.
- Kept rows must never look fresh.
  - **Per-store freshness.** Each store records `observed_at`, separately from the source's
    check-in `last_seen`. `observed_at` is the server's receipt time of the last report in
    which that store was read successfully. It is never the agent's clock, for the same
    reason as `last_seen` (#1685). Every read exposes each store's status and
    `observed_at`.
  - **Bounded retention.** Rows kept from a store are pruned only when both hold: the
    store's most recent report says it was unreadable or not observed, and its
    `observed_at` is older than a bounded period the design doc states. A store or
    per-user scope that stops appearing in reports, for example after an agent reinstall
    loses `k_agent` or a profile is deleted or renamed, counts as not observed from the
    first report that omits it, so it too reaches the bound. Age alone never
    prunes, so an offline device or a fleet-wide outage does not wipe the inventory. The
    prune follows the clock-guarded-retention concern. The design doc also states how a
    pruned store's rows are re-sent despite the daily sync skipping unchanged content.
    Until pruned, kept rows are shown as last observed at their `observed_at`.
  - **R15 — location grain inside a `constrained` store (owner, 2026-10-23; amends the
    bounded-retention rule above).** A store whose reads keep succeeding only partly reports
    `constrained`, so its kept locations would never reach the store-grain condition and would
    grow without bound. A location inside such a store counts as not observed once it has been
    missing from every report the server received from that device over the stated bound
    (server receipt times on both sides), and the same pass prunes it. An offline device sends
    no reports, so nothing of it is pruned: age alone still never prunes. Ruled by the owner
    (liamsomerville) on 2026-10-23 and recorded as decision 6 in the Decisions section of
    `docs/crypto-slice2-certificate-design.md`, whose governance ledger is under `governance.d/`.
  - **R16 — one location-grain prune rule (owner, 2026-10-26; in force as written).**
    Governance on the prune PR showed that the store-grain condition, compared against the
    server's current time, prunes an offline device's rows once a store read `unreadable` before
    the device went offline, and never prunes a store whose first read was `constrained`. The
    proposed rule: a location is pruned only when its store's latest status is `unreadable`,
    `not_observed` or `constrained`, it has been missing from every report the server received
    from that device over the bound (the device's last receipt time minus the location's last
    receipt time), and the device's last receipt time is not in the future. An offline device is
    never pruned, and a location seen within the bound never is. Accepted residual: a forward step
    of the database clock in force when the device next reports shortens the bound by that step.
    Ruled by the owner (liamsomerville) on 2026-10-26: the rule is accepted and in force as
    written, with points (i)-(iv) accepted as residuals; recorded as decision 7 in the Decisions
    section of `docs/crypto-slice2-certificate-design.md`. Points raised by the prune PR's
    governance: (i) a device that returns after more than the bound offline can
    lose its kept locations after one report; (ii) a location in a `constrained` store that went
    unreported for longer than the bound is pruned on the next report that reads the store
    `unreadable`; (iii) the forward-clock residual above; (iv) the rule covers machine-scope
    stores only (per-user stores are not collected in slice 2).
  - **R17 — the agents-before-servers window for `certificate_inventory` (owner, 2026-10-26;
    closed in code by a capability gate).** D12 says stray certificate rows must never be
    readable and the mixed-version window is not acceptable for this source; that stands,
    with one exception: the owner-accepted L7 balancer residual named below (every backend at
    2a-1 or later; never roll a backend back below 2a-1 while certificate-collecting agents
    report). A server older than the typed-source read filter (or rolled back below it) that
    receives the agent's blob through a gateway would store it in the generic store, readable
    under `Infrastructure:Read`. The owner (liamsomerville) ruled on 2026-10-26 that the window is
    closed in code, not by deploy order (bar the L7 residual below): the agent sends `certificate_inventory` only when the
    server's `RegisterResponse` advertises `certificate_inventory_v1` (new field
    `repeated string server_capabilities = 9`), and the server advertises it only while its
    certificate store opened. Absent means never sent, so the gate fails closed and is stateless.
    The server capability ships in 2a-2a and the agent gate in 2a-2e. Not adopted: (a) accepting
    the window and closing it by deploy order (servers first, never roll back, a merge-order test
    and an `upgrading.md` note), because it relies on operators following an order nothing
    enforces and amends D12; (b) a reserved `__sync__` enable action persisted on the agent,
    because it adds a server-to-agent action and persistent agent state that a capability
    advertised on every registration makes unnecessary. Recorded as decision 8 in the Decisions
    section of `docs/crypto-slice2-certificate-design.md`.
    As built, the gateway also enforces the capability per upstream connection (record from
    `ProxyRegister`, strip for a connection without `certificate_inventory_v1`, fail closed for an
    unknown one, rate-limited re-probe for admitted sessions only). Accepted residual (owner,
    2026-10-27): behind an L7 balancer that spreads one connection's requests across backends,
    every backend must run the 2a-1 typed-source reservation release (PR #6563) or later before
    certificate-collecting agents are enabled, and no backend may be rolled back below it while
    those agents report (the no-rollback condition: a rolled-back backend stores the blob in the
    generic store, readable under `Inventory:Read` and `Infrastructure:Read`, which under RBAC off
    (the default) any authenticated session holds, until that backend is upgraded); SOC 2 risk register, review-by
    2027-01-31. The SOC 2 risk entry ships in 2a-2a.
- A capped or timed-out capture is reported `constrained`, and the report is never an
  empty success.
- An empty blob is never sent for a failed or constrained capture (the ADR-0016
  `app_usage` rule).
- A field an older agent did not send reads as unknown, never as empty, and the blob is
  versioned.

**Identity.**
- A row is keyed by (device, store/location/path, SHA-256 fingerprint), plus the per-user
  identifier for per-user rows. SHA-1 is display
  only.
- **Duplicates count once.** On Linux the same certificate commonly appears several times:
  - inside a bundle file;
  - as a separate file;
  - through hash links. For example, Debian's `/etc/ssl/certs/ca-certificates.crt` bundle
    and the links into `/usr/share/ca-certificates/` hold the same roots.

  Every count is therefore of distinct (device, SHA-256 fingerprint). Storage may keep one
  row per location, keyed as above, but every response and count presents a certificate
  as one entry, with the locations where it was found as a list on that entry.
  These counts are device-level ("present on this device").
- A fallback read never stands in for LocalMachine.
- A service account's own store is labelled as such, never as a person's.
- **Per-user rows** do not take part in the machine-scope replace. They have their own
  replace scope.
  - The scope is keyed by device and a per-user identifier that is stable on that device
    and never leaves it in the clear. By default this is the ADR-0024 D11 `user_ref`
    (`HMAC-SHA256(k_agent, profile)`): a per-agent keyed pseudonym of the local profile
    name, which does not correlate across devices. It is never a raw SID, uid or
    username. ADR-0024 also bars a SID as the HMAC input, so a design that needs a
    different input records that divergence and gets privacy review.
  - The per-user identifier is part of every per-user row's key, so two users holding
    the same certificate in their own stores are two rows and never overwrite each other.
  - A per-user location is recorded relative to the user's profile (for example
    `login.keychain` or `CurrentUser\Root`), never as a home-directory path that
    carries the username.
  - It is replaced only after a successful read of that user's store, so a certificate the
    user removed disappears.
  - A user whose store was not read this run is recorded as `not_observed`, and their rows
    stay under the bounded retention above. That covers a switched console user on macOS
    and a logged-off user on Windows. It never counts as an empty store.
- Every row carries the server-receipt `last_seen` (#1685), and engine-facing reads
  expose it.

**Lifecycle.**
- The new typed store joins `AgentDecommissionStores` (`agent_decommission.hpp`) and its
  drift guard in the same change.
- It is added to `typed_inventory_sources.hpp`'s typed set, with a test. Otherwise its
  rows also land in the generic inventory store under a broader securable. That set only
  stops new writes. Stray certificate rows in the generic store must also never be
  readable. The generic read path is gated on a broader securable that is not floored
  while RBAC is off, so this needs both:
  - a read-time filter that excludes typed sources;
  - membership of the boot-time purge, checked by a test against the typed set.

  App-usage accepts a mixed-version window in which stray rows stay readable. That window
  is **not** acceptable for this source.
- It is covered by `/readyz`.
- Any new background job is classified in `background_jobs.hpp`, and any prune follows
  the clock-guarded-retention routed concern.

**Chaos.** The slice-2 PR runs these six scenarios before merge. Each is defined by the
property it must prove; the tools are the design doc's choice.

| ID | Scenario | Must prove |
|---|---|---|
| CH-1 | A store read fails during a whole-device replace while a user logs off | Machine rows survive with their original `observed_at`. The failed store reads `unreadable`. The departed user's rows go only through the per-user scope. The blob is never empty. |
| CH-2 | Hostile certificates: 10k SANs, oversized subjects, script and control characters, invalid UTF-8, e-mail SANs | The caps hit and the certificate is `constrained`. Nothing executes in the dashboard (no CSP page error). Audit details are escaped. Personal data is handled as the design doc decided. |
| CH-3 | A planted certificate whose AIA/CDP/OCSP URLs point at a listener, plus a pre-seeded cached CRL and a cached OCSP response marking it revoked, run on each platform that builds the chain result | The listener receives zero connections. The result reflects neither the cached CRL nor the cached OCSP response. A platform that cannot meet this does not build the result in core (D5). Where an OS-vendor distrust list affects the result, the result is labelled as the OS's own evaluation. |
| CH-4 | An offline device, an engine-grain read and a capped read | Every row exposes `observed_at` and `last_seen`. The read completes across pages or fails. The truncation flag is set, and the CBOM carries its coverage metadata. |
| CH-5 | Agent clock skew; certificates expiring at day boundaries; the year-9999 sentinel; a pre-1970 date | Validity is stored as UTC to the second and never clamped. Core results change only with the caller's T, and for D13 windows with `as_of`. An agent-side policy discloses its clock offset. |
| CH-6 | Registered-CRL failure cases: never fetched, bad signature, an older replayed CRL, a delta without its base, a CA re-key, a hold entry, and a certificate past expiry | Each reads exactly as D5's revocation-statement rule says, and no case reads "not listed" or "revoked" wrongly. |

### D13 — A closed set of built-in weak-key rules and dashboard windows ships in core [core, maintainer ruling]

**Maintainer ruling (owner, 2026-10-18; amended 2026-10-19), ratified on merge.** The
`/crypto` dashboard must answer the questions operators ask on day one, "how many weak keys
do we have?" and "what expires this month?", without waiting for a use-case engine that
does not exist and whose ADR-0032 gate is closed. The owner rules that the following ship
in core, as a deliberate exception to the "is, not how good" test and the derived-field
rule. It is a maintainer verdict under ADR-1005 Decision 2, recorded per D11. The owner's
2026-10-19 amendments R1–R14 are folded in below and in D5, D6, D8 and D12.

**What is admitted, and nothing else:**
- **Weak-key rules, version 1** (`crypto_weak_rules` v1), four rules, each counted
  separately:
  - `sig_md5` — the signature algorithm uses MD5;
  - `sig_sha1` — the signature algorithm uses SHA-1;
  - `rsa_lt_2048` — the key is RSA with a modulus under 2048 bits;
  - `ec_lt_224` — the key is EC on a curve whose group order n is under 224 bits long.
    Ed25519 and Ed448 keys are outside this rule and never match it.

  `sig_md5` and `sig_sha1` include RSASSA-PSS signatures. For PSS the signature OID does
  not name the hash; the hash is in the algorithm parameters, so the rule reads the PSS hash
  parameter, which D12 requires as a raw field.

  The total and each per-rule count are of distinct (device, SHA-256 fingerprint), like
  every D12 count. A certificate matching several rules counts once in the total and once
  under each rule it matches.
- **Fixed time windows**, counted against Postgres `now()` at read time (R4 below), with
  the edges R5 defines:
  - active: valid at `as_of`, for fleet and Yuzu-CA certificates (R6);
  - expiring within 3, 7, 14, 21, 30 or 60 days, for fleet and Yuzu-CA certificates (R6;
    Yuzu-CA status `active` only, R11);
  - expired within the last 7, 30, 60 or 90 days, for fleet and Yuzu-CA certificates (R6;
    Yuzu-CA status `active` only, R11);
  - revoked within the last 7, 30, 60 or 90 days, from two sources only, never combined:
    - **fleet certificates**: revocations stated under D5's revocation-statement rule
      (R1), counted by the CRL's `revocationDate`. A `certificateHold` entry is "on hold"
      and is not counted as revoked. A count of certificates matched by issuer and serial
      says so, unless the server verified the certificate's signature, from the shipped DER, against the
      registered CA key. Every revoked-window count also reports how many certificates in
      scope are "revocation not checked", with the causes; such a certificate is never
      counted as not revoked. Beside that figure it reports how many were checked against
      a CRL covering only some reasons (R13). These are fleet rows: D12's dedicated
      certificate securable and confinement apply to them;
    - **Yuzu-CA certificates**: revocations in Yuzu's own CA, read only through a new
      `CaStore` count method, never the `ca_store` tables (D6 as amended), and never joined
      to fleet certificate rows. The method falls under the PKI routed-concern review when
      built. They are reported in three buckets and never labelled "security":
      - `superseded`;
      - `unpublished`;
      - "other (reason as recorded)".

      `superseded` and `unpublished` are system bookkeeping markers, not compromise
      (`ca_store.hpp:114-118`); an operator-typed reason that collides with one is stored
      qualified as `operator-supplied: <text>` (`ca_store.hpp:281-288`), so it falls under
      "other". Operator-supplied free-text reasons are not grouped beyond these buckets in a
      count. Any free text shown elsewhere is escaped and length-bounded;
  - issued within the last 7 days, and issued and revoked per ISO week, for fleet
    certificates and for Yuzu-CA certificates through the same `CaStore` count method:
    - a fleet certificate's issued windows use its `not_before`; a Yuzu-CA certificate's
      use `CaStore`'s `issued_at` (R4), since `ca_store` records no `not_before` per issued
      certificate;
    - `unpublished` Yuzu-CA certificates were never delivered, so they are excluded from
      the issued counts;
    - "per ISO week" means ISO 8601 weeks in UTC, labelled by ISO year and week number,
      over the last 52 weeks, the current week included (R7). The span is part of the
      rule-set version. The current week is partial and is flagged as partial;
  - `crl_past_next_update`: registered CRLs whose `nextUpdate` is before `as_of` (R1, R4),
    shown with that criterion, to the registered-CRL list's audience (R9). It is not the SSH
    "stale" label, and nothing else counts as staleness in core. The gauge behind its alert
    is an alerting signal, not a D13 read surface (R12);
  - SSH keys observed in use within 24 hours or 3, 7, 21, 30, 60, 90, 120 or 180 days,
    and with no observed use (slice 3; R3 below).

**R2 — who sees the Yuzu-CA count widgets (R6) (owner, 2026-10-19).**
- They are gated by `Inventory:Read`.
- They are CA-population counts with no device dimension, and are never joined to fleet
  rows.
- A caller whose view is confined (a present exec-visibility set) gets a "not available to
  this account" note, **never** a count. Unconfined `Inventory:Read` holders see the
  fleet-wide counts.
- This deliberately differs from the CA routes, which gate on `Security:Read`
  (`GET /api/v1/ca/issued`, `ca_routes.cpp:407-410`): the widgets show counts only, never a
  certificate's details. Agent-purpose certificates map one-to-one to enrolments, so these
  counts disclose fleet size and enrolment churn to unconfined `Inventory:Read` holders.
  That disclosure is accepted by this ruling.
- The Yuzu-CA counts follow D12's read-surface rules: REST + MCP twins, a new audit verb
  (documented in `docs/user-manual/audit-log.md` when built), admission through the `/crypto` read gate, and a degraded `CaStore` read is a 503
  with a retry hint, never a zero.
- The fleet-certificate revoked windows (R1's source) are not covered by R2. They are fleet
  rows under D12's dedicated certificate securable and confinement.

**R3 — SSH usage windows (owner, 2026-10-19).**
- They are fixed now as **fleet-wide aggregate counts only, never per device or per
  user**.
- The slice-3 ADR sets the minimum cohort, the audit verb and the collection privacy
  decisions (D8). It **cannot remove the windows**, but it can withhold them until
  collection is permitted.
- A count of keys with or without observed use is a count, not a "stale", "unused" or
  "anomalous" label (D8 as amended).
- SSH counts accept no scope, tag or device filter. A confined caller gets R2's "not
  available to this account" note. No caller can narrow a count below the whole fleet or
  the slice-3 minimum cohort.
- The counts derive from behavioural login evidence. The slice-3 ADR owns the cohort floor
  and the DPIA and works-council precondition (D8), and the counts cannot ship before
  them.

**R4 — the clock (owner, 2026-10-19).**
- `as_of` is Postgres `now()`, read in the same SQL statement as every comparison it
  governs and returned with the counts. It is never the replica's system clock.
- `CaStore`'s `issued_at` and `revoked_at` are authored from the replica's system clock, not
  Postgres: both come from `now_epoch()` (`ca_store.cpp:38-42`), through the insert's
  fallback at `:507` and the revoke `UPDATE` at `:647-650` (`now_epoch()` bound at `:650`).
  The Yuzu-CA windows compare those timestamps against `as_of`, so their window edges are
  accurate only to the replicas' clock synchronisation. Each Yuzu-CA count discloses that.
- That skew is a disclosure only, accepted by owner ruling (2026-10-19): no skew gauge or
  other measurement is required.

**R5 — window edges (owner, 2026-10-19).**
- A certificate is valid through its `notAfter`, inclusive (RFC 5280 §4.1.2.5).
- `as_of` is `date_trunc('second', now())`: R4's Postgres `now()` in whole seconds, returned
  exactly as compared.
- Every window is measured against `as_of`. Windows are cumulative, not banded: a
  certificate expiring in 5 days is in the 7-day window and in every longer one.
  - active (as amended by R10): valid at `as_of`, that is
    `not_before <= as_of <= not_after`; for a Yuzu-CA certificate, status `active`,
    `issued_at <= as_of` and `not_after >= as_of`;
  - expiring within N days (as amended by R14): active at `as_of` and
    `not_after <= as_of + N days`;
  - expired within the last N days: `as_of - N days <= not_after < as_of`;
  - revoked within the last N days: `as_of - N days < revocation time <= as_of`;
  - issued within the last 7 days: `as_of - 7 days < issue time <= as_of`, where the issue
    time is a fleet certificate's `not_before` and a Yuzu-CA certificate's `issued_at`;
  - per ISO week: `[week start, week start + 7 days)`, and no later than `as_of`. The
    current week is flagged partial.

**R6 — Yuzu-CA active, expiring and expired counts (owner, 2026-10-19).**
- They are admitted under D13, beside the issued and revoked counts, through the same
  `CaStore` count method and under R2's gate.
- `ca_store` records each issued certificate's `not_after` (`ca_store.hpp:125`), and
  `GET /api/v1/ca/issued` serves it (`ca_routes.cpp:454`).
- R11 amends this ruling: the Yuzu-CA expiring and expired counts cover status `active`
  only.

**R7 — the per-week span (owner, 2026-10-19).** The per-ISO-week series covers 52 weeks,
and the current, partial week is one of them.
The span is part of the rule-set version (condition 4).

**R8 — recomputing the Yuzu-CA counts (owner, 2026-10-19).**
- Each Yuzu-CA count is defined over the rows `GET /api/v1/ca/issued` serves
  (`Security:Read`, `ca_routes.cpp:407-410`).
- A `Security:Read` holder can check a count against that read only approximately: it has
  no `as_of` snapshot, it pages by offset (`ca_routes.cpp:418-419`), and its timestamps
  come from the replica's clock (R4).
- The exact check is the per-source unit test (mechanical checks below). It recomputes each
  count with an independent predicate over the raw rows, never with the `CaStore` count
  method's own SQL.
- An `Inventory:Read` holder without `Security:Read` sees the counts (R2) but cannot
  recompute them. The owner accepts this; it does not send these widgets back to the UCE
  rows.

**R9 — `crl_past_next_update` (owner, 2026-10-19).**
- It is gated to the same audience as the registered-CRL list (admin-only, D12), so every
  viewer can recompute it.
- The registration list serves each registered CRL's `thisUpdate` and `nextUpdate` (D12).
- A background job emits a gauge, named with the `yuzu_` prefix
  (`docs/observability-conventions.md`), so the D12 alert fires without a page view. R12
  amends this bullet: the gauge carries no per-registration label.

**R10 — the active edge (owner, 2026-10-19; amends R5).**
- A fleet certificate is active when it is valid at `as_of`:
  `not_before <= as_of <= not_after`.
- A Yuzu-CA certificate is active when its status is `active`, `issued_at <= as_of` and
  `not_after >= as_of`. `ca_store` records no `not_before` per issued certificate
  (`IssuedCertRecord`, `ca_store.hpp:125-129`), so `issued_at` stands in for it.

**R11 — what the Yuzu-CA expiring and expired counts cover (owner, 2026-10-19; amends
R6).**
- The Yuzu-CA expiring and expired counts cover status `active` only.
- A revoked certificate, including one revoked as `superseded` or `unpublished`, is counted
  only in the revoked windows.
- So "expired" means the certificate ran out while still active.

**R12 — the `crl_past_next_update` gauge (owner, 2026-10-19; amends R9).**
- It is one unlabelled gauge: the count of registered CRLs past their `nextUpdate`. It has
  no per-registration label.
- The admin registered-CRL page shows which CRLs are past their `nextUpdate`.
- Only the leader emits it. A replica that loses leadership stops exporting it, and the
  alert takes the `max` across replicas, so a former leader's stale value cannot hide a
  CRL past its `nextUpdate`. The design names the metric with the `yuzu_` prefix.
- The alert treats an absent or stale gauge as not healthy, through an `absent()` or
  freshness clause.
- The gauge is an alerting signal, not a D13 read surface.

**R13 — CRLs that cover only some reasons (owner, 2026-10-19; amends D5 and R1).**
- From a CRL that covers only some reasons (`onlySomeReasons`), the per-certificate
  statement names the reasons it covers.
- Each revoked-window count also reports how many certificates were checked for some
  reasons only. It sits beside the "revocation not checked" figure.
**R14 — expiring is a subset of active (owner, 2026-10-19; amends R5).**
- For both sources, a certificate is expiring within N days only when it is active at
  `as_of` (R10) and `not_after <= as_of + N days`. A certificate not yet valid is in
  neither count.


**The `CaStore` count method** (R2, R6) must:
- be backed by indexes on the columns its windows compare (`not_after`, `issued_at`,
  `revoked_at`);
- run under a bounded statement time and, past it, degrade to a 503 with a retry hint,
  never hang and never return zero;
- state, for review, the row scale it targets, with no SLO number copied from a
  measurement;
- never store a count. Its design states how callers are kept from polling it unbounded,
  by admission limits, not a cached or stored count.

**Conditions that keep the exception closed** (a surface failing one is not covered by
this ruling and is back to the UCE rows):
1. **Shown with its criterion.** Every count names the rule or window it applies ("RSA key
   under 2048 bits", "expiring within 30 days"), never a bare "weak" or "at risk". The
   REST and MCP responses carry the rule id, the threshold and the rule-set version.
2. **Reproducible from facts.** Each rule and window is a pure function of raw fields core
   already serves plus the response's `as_of` time, so a caller can recompute it from the
   raw read of that count's own source (for the Yuzu-CA counts, approximately and only with
   `Security:Read`, R8):
   - fleet-certificate rules and windows, including the fleet revoked windows and their
     "revocation not checked" figures: the paged per-certificate read (D12), which carries
     each certificate's R1 revocation statement;
   - Yuzu-CA counts: the rows `GET /api/v1/ca/issued` serves (`Security:Read`; it serves
     each certificate's `status`, `not_after`, `issued_at`, `revoked_at` and
     `revocation_reason`). Recomputing from that read is approximate; the exact check is
     the per-source unit test, and an `Inventory:Read` holder without `Security:Read`
     cannot recompute these counts (R8). A drill from these widgets to the certificates
     behind them, if built, is a filtered view of that read under the same `Security:Read`
     gate and, like the counts, withheld from a confined caller (R2). `/api/v1/ca/issued`
     is not confined today (pre-existing), so a drill must add the withholding;
   - `crl_past_next_update`: the registered-CRL list (R1), which serves each registered
     CRL's `thisUpdate` and `nextUpdate` to the same audience as the count (R9);
   - SSH counts: the slice-3 aggregate read the slice-3 ADR defines (fleet-wide only, R3).

   Core still serves the raw fields, and the caller-supplied filters of D4 remain.
3. **Computed at read, never stored.** No verdict column, no stored `days_remaining`, no
   verdict written into the CBOM (D7 unchanged). Each response carries `as_of`, the server
   time it compared against (R4).
4. **Changed only by a reviewed code change.** Adding, removing or retuning a rule or window
   is a change to this decision, bumps the rule-set version, and is reviewed as a placement
   change. Nothing updates the list from an external standard or feed, and no rule is
   labelled with a framework (no NIST, CNSA, PCI or FIPS mapping).
5. **No grading presentation.** D10's no-colour, no-icon, no-risk-ordering posture still
   applies to these widgets.

**Mechanical checks.** Conditions 1 and 3 are checked mechanically, not left to review:
- **The condition-1 lint** (part of D10's lint) requires `rule_id`, `threshold` (or the
  criterion, for example the algorithm name for `sig_*`), `rule_set_version` and `as_of`
  beside **every D13 count** in the same response object: the rules, the windows, the
  Yuzu-CA counts, the SSH counts and `crl_past_next_update`. It fails when any is missing.
  It also fails when a D13 `rule_id` appears in no recompute test below.
- **A schema and migration lint** rejects any stored column whose name is a D13 rule id or
  window field, or `days_remaining`.
- **Unit tests, one per source,** recompute each count from the raw read of its own source
  at the response's `as_of`, and fail when the two differ: fleet-certificate counts from the
  paged per-certificate read; Yuzu-CA counts from the `CaStore` raw issued-certificate
  rows, with an independent predicate, never the count method's own SQL (R8); `crl_past_next_update` from the registered-CRL read; SSH counts from the slice-3
  aggregate. Each test lands with the PR that adds that count.

**The D10 allow-list is closed.** It governs only verdict-shaped field *names*; the
condition-1 lint above checks every D13 count whether or not its name is allow-listed. Its
entries are keyed by (surface path, field), and the only fields it may contain are `weak_key_rules`, `expiring_within_days` and
`expired_within_days`. The surface path of each entry is one of D13's count reads (a REST
path, an MCP tool or a `/crypto` fragment), added by the PR that adds that read and citing
D13. A new field, or one of these fields on a surface that is not a D13 count read, is a
change to this decision.

**What it does not admit.** PQC readiness, deprecated-algorithm lists beyond the four
rules, risk scores, "at risk" or "stale" labels, Yuzu-chosen expiry notifications,
OCSP and certificate-supplied revocation URLs, and framework mappings all stay UCE. If a
use-case engine later offers a richer rule set, the four rules may stay in core or move to
it; either is a fresh placement decision.

## Consequences

- **The dashboard widgets are buildable in core (D13).** The library widgets can ship now.
  The Yuzu-CA active, expiring, expired, issued and revoked widgets can ship before slice 2
  only once the new `CaStore` count method exists (under PKI routed-concern review) and
  under R2's gate: `Inventory:Read`,
  a "not available to this account" note for a confined caller, revocations in three reason
  buckets, D12's read-surface rules, and no join to fleet rows. The certificate widgets ship
  on slice 2's data, the fleet-certificate revoked windows only once the registered-CRL path
  exists (R1), and the SSH widgets on slice 3's data, as fleet-wide counts only (R3).
- **Slice 2 is unblocked to design.** Its design doc must cite this ADR and satisfy D4,
  D5, D6, D7 and D12.
- **R1 creates core work items**, each owed by its own design and review (D12): the CA and
  CRL-URL registration surface (REST + MCP twins, admin-only in both RBAC states, an audit
  verb); the server-side CRL fetcher and its security review as a new egress surface; a
  classified, leader-gated background refresh job; a Postgres store for registered CAs and
  CRL entries, in the readiness conjunction; and alerts on fetch failure and on
  `crl_past_next_update`.
- **Slice 3 needs its own ADR first** (D8), with the privacy decisions made by the owner.
- **Slice 1 needs follow-up edits, not code changes.** This PR makes these edits:
  - `crypto_library_model.hpp:10-14` cites this ADR (D2, D3) for the rule it states.
  - `docs/user-manual/crypto.md`:
    - The Roadmap section stops saying future slices come "under the same permission and
      audit model". D8 and D12 decide those per slice.
    - The Roadmap qualifies CBOM as facts-only and SSH login evidence as subject to a
      separate privacy decision.
    - It says plainly which built-in rules and windows core applies (D13), that third-party
      revocation comes only from operator-registered CRLs (R1), that Yuzu does not label
      any other weak cryptography, expiry risk or PQC readiness in core, and what an
      operator can do instead.
    - It says that operator policy over certificate facts is not available until slice 2
      ships.
  - The capability-map §41 preamble and roadmap Issue 18.8 widen their list of excluded
    verdicts to match this ADR (expiry-risk scores and labels, EOL status, deprecated or
    broken algorithms beyond D13's four rules, OCSP and certificate-supplied revocation
    URLs, framework mappings) and cite it.
  - §41.6 says facts-only (D7), and §41.2's store wording matches D6's gap list.
  - These are also the links #6051 asks for.
- **No engine work is created.** The crypto-posture module is a backlog entry for the
  engine host, behind D9.
- **A reviewer can now cite a rule instead of an inference.** "Does this field grade
  something?" is the question, the placement table is the precedent, and D10's lint is the
  backstop.
- **The cost.** Two maintainer exceptions put a small amount of interpretation in core
  that ADR-1005 would otherwise send to an engine. D13 adds four weak-key rules and a fixed
  window set Yuzu must keep current by code change. D5/R1 adds revocation status from
  operator-registered CRLs, a join with external data. That is the owner's chosen trade for
  answering "show me weak keys", "what expires this month" and "what has been revoked"
  before an engine exists. Anything beyond D13's closed set and R1's registered-CRL
  revocation status still gets only the raw facts, D4's caller thresholds and operator
  policy, and the certificate half only once slice 2 ships.

## Alternatives considered

- **Build the verdicts in-server now and grandfather them** (the vulnerability vertical's
  path). Rejected. Grandfathering exists for shipped work, and nothing here has shipped.
  Building interpretation in-server now, except as D5/R1 and D13 rule, would grow a
  future deletion scope, which is the
  outcome ADR-0023's placement note warns of ("each further in-server PR on this ladder
  grows that deletion scope").
- **Classify the family table as interpretation too, and move all of Domain 41 to an
  engine.** Rejected. It would leave the estate's facts uncollected until an engine
  exists, contradicting ADR-1005's own placement of collection and inventory stores in
  core, and it misreads identity resolution as grading (D2).
- **A narrow, "obviously uncontroversial" built-in list**, for example flagging MD5 and
  SHA-1 signatures only. Originally rejected: any built-in list is "semantics baked into
  code", however short. **D13 supersedes the rejection for the four D13 rules** (owner
  ruling, 2026-10-18), which it admits as a closed, versioned exception under five
  conditions. The reasoning still binds everything outside that set.
- **Label "already expired" as a fact.** Still rejected as a stored field or label (D4).
  D13 admits "expired within the last N days" only as a read-time count carrying its
  `as_of` time.

## Ratification

Accepted by the merge of the reviewed PR that lands this file, under the ADR Acceptance
Convention (`docs/agents/domain.md`). The `status: accepted` above is the value the file
carries once that PR merges. Before the merge, the PR is the proposal.

**Who approves, and what the approval records:**
- The approving review must come from someone other than the author. That review, and the
  merge metadata that goes with it, is the change-management evidence. A self-merge does
  not accept this ADR.
- ADR-1005 Decision 2 makes the maintainer the arbiter of boundary disputes. The approval
  is also the ruling on the five decisions that ask for one:
  - D2: the library-family table is identity resolution, under four conditions;
  - D3: library support and end-of-life status are engine territory;
  - D5: device-local trust facts are core under three conditions, and revocation of fleet
    certificates is core only through operator-registered CRLs. D5's R1 and R13 amendments
    are the owner's rulings; the approver confirms them, and they are not a request;
  - D7: CBOM export is core when it carries facts only;
  - D13: the closed set of weak-key rules and dashboard windows, with R2–R14.
- R1–R14 are the owner's 2026-10-19 amendments, already decided: R1 (revocation of fleet
  certificates through operator-registered CRLs, amending D5), R2 (the Yuzu-CA widgets' gate), R3
  (SSH usage windows as fleet-wide counts; amends D8), R4 (the `as_of` clock, with clock skew
  a disclosure only), R5 (window edges), R6 (Yuzu-CA active, expiring and expired counts),
  R7 (the 52-week span), R8 (how the Yuzu-CA counts are recomputed), R9
  (`crl_past_next_update`'s audience and gauge), R10 (the active edge; amends R5), R11 (the
  Yuzu-CA expiring and expired counts cover active certificates only; amends R6), R12 (one
  unlabelled `crl_past_next_update` gauge and its alert; amends R9), R13 (CRLs that cover
  only some reasons; amends D5 and R1) and R14 (expiring is a subset of active; amends R5). The
  Yuzu-CA counts are part of D13, not of D5's revocation status (R1 covers fleet
  certificates), and D13's ruling also amends D6 so they may use a `CaStore` count
  method. The rulings are recorded here as rulings, not requests. They are also
  recorded in PR #6125's description, and are ratified by the approving review.
- R15 is the owner's 2026-10-23 amendment of D12's bounded-retention rule (location grain inside a
  `constrained` store), made after this ADR was accepted. It is ratified by the approving review
  of the PR that adds it (approver not the author), which records it alongside the slice-2
  design's decision 6.
- R16 and R17 are the owner's rulings of 2026-10-26, given in the session that produced this
  branch and recorded as decisions 7 and 8 of the slice-2 design; the ledger of that run is
  under `governance.d/` (`*-crypto-slice2-split-decisions*.jsonl`). They are ratified by the
  approving review of the PR that carries them, as R15 is.
- The approval grants those five rulings as written. Approvers are asked to state each
  ruling in the review, so that the record shows each one, but the statements are a
  request, not a separate acceptance gate. On merge, the "ruling requested" notes in those
  decisions record rulings granted by that approval.
- A reviewer who disagrees with any one of them blocks on it specifically, so that it can
  be split out rather than accepted silently.

## Update (2026-10-23) - `GET /api/v1/ca/issued` and the panel inventory are confined; the actual gate

This Update does not change R2's text above. It records what the code now does where R2 is
silent, and one correction to a statement in this ADR's narrative.

### What changed

- **Both forms of `GET /api/v1/ca/issued` (and MCP `list_issued_certs`), and the issued-certificate
  list in the Settings certificate panel, are confined.** R2 said the CA routes "gate on
  `Security:Read`" and the narrative above (the sentence beginning "`/api/v1/ca/issued` is not
  confined today (pre-existing)") recorded the unfiltered list as an unconfined gap. The unfiltered list
  returns the same per-agent rows (subject, SAN, issuing identity) the filtered list does, and
  `list_issued` has no scope parameter to narrow them by, so it is held to the same standing: a
  confined caller is withheld (403, no permission named; MCP permission denied), never served a
  narrowed list. The panel withholds only the inventory (CA details, downloads and the import form
  stay), and a revoke or import answers a non-empty body. Both forms are audited
  `crypto.ca.certificates.view` (`denied`, `failure`, `success`).

### The actual gate

The gate is `Security:Read` **plus** a standing probe on `Inventory:Read` (the same non-auditing
availability callback the `/crypto` widgets use, kFleetWideOnly class). It resolves to:

| Standing | Answer |
|---|---|
| kConfined (a present exec-visibility set from a management-group-scoped `Inventory:Read` grant) | withheld: 403 / permission denied; audited `denied` |
| kDegraded (the check answered 503: a store behind it could not be read) | 503, `retry_after_ms` 5000; audited `failure` |
| kAvailable (admitted, with no exec-visibility set: a global grant, or RBAC enforcement off) | served; success row ends `standing=available` |
| kRefused (the check admitted nobody and did not answer 503) | **served**; success row ends `standing=refused` |

The table is the behaviour of the REST and MCP lists. The Settings panel answers kConfined and
kDegraded with a note in place of the inventory (kDegraded: "Certificate inventory unavailable
(access check failed)") and a normal page, not a 403 or 503, and writes no audit row (#6384).

R2 says a confined caller is one with "a present exec-visibility set" and is silent on a failed
read. kRefused covers two causes the answer cannot tell apart:

1. **No `Inventory:Read` grant at all.** Served on purpose: `Security:Read` already admitted the
   caller, and R2 reads confinement as a property of a scoped grant ("unconfined `Inventory:Read`
   holders"). Consequence to state plainly: removing a group-scoped `Inventory:Read` grant, or
   adding a deny, does **not** confine a caller; granting a global `Inventory:Read` removes the
   confinement. Whether a `Security:Read` holder without `Inventory:Read` should see this list at
   all is a policy question this Update does not settle (#6383).
2. **A read failure partway through the access check** (the permission-groups or visible-set read
   errors, and `authorize_list_read` returns DenyAll). This is served too, i.e. the check **fails
   open**. That is an **exception to ADR-0017 INV-1** ("any error is deny") **and INV-5** (a partial
   failure 503s the whole read). It was previously unrecorded, and R2 does not say it; code
   comments cite R2 only for the confinement withholding. It also affects the filtered list and the `/crypto` drill
   (`ca_drill_gate`) and `authz_gates.cpp`'s documented 2c weakening. It is strictly narrower than
   the behaviour before the unfiltered list was confined (every confined caller was served), is
   pinned by tests that name it ("KNOWN RESIDUAL"), and is tracked by #6382 (a tri-state
   `read_failed` result from `authorize_list_read` so the answer becomes 503). The no-grant arm and
   the failed-read arm are indistinguishable at the probe today, so that fix changes the
   failed-read arm only; the no-grant arm stays served until #6383 decides it.
   When the tri-state fix lands, supersede this paragraph by a further dated Update (do not delete
   it, so the history of the exception stays on record) and update the code comments.

Detective control until then: on `GET /api/v1/ca/issued` and `list_issued_certs`, every success
row carries `standing=available|refused`; review the `refused` rows, knowing that `refused` cannot
separate a by-design no-grant caller from a read failure, that the audit row can be missing during
the same outage, and that no alert fires on this path. The `/crypto` drill's success rows carry no
standing token, so a drill page served on a failed read is not marked. The drill and the Settings
panel write no `denied` row for a confined caller (a separate gap, tracked with the drill's
missing `failure` row on a degraded gate: #6384).

### Record

`docs/user-manual/crypto.md` said of the unfiltered list that it "still returns every Yuzu-issued
certificate to any `Security:Read` holder, a confined one included (owner decision; the same
rows, without the dashboard's windows)". That sentence entered with commit 95486afc2, whose
message lists two owner decisions (layout saves; keyset drill paging) and not this one, and no ADR
records it. On 2026-10-23 the maintainer, Dave Rae, authorised reversing that statement: the unfiltered list is confined, as recorded in "What changed". He also ruled that a caller the standing check refuses without a 503 (kRefused) is served and the behaviour disclosed, with the failed-read exception tracked in #6382 and the no-grant question in #6383, and he approved this Update. He reports that the author of this ADR approved it offline before it was committed; that approval is not recorded elsewhere in the repository.

## Update (2026-10-24): the issued-certificate list is served only to an affirmatively unconfined caller

**Status of the 2026-10-23 Update.** It stays on record as history. Its "kRefused is served" row and
its "A read failure partway through the access check" exception are **superseded by this Update**;
the maintainer's 2026-10-23 ruling to keep serving was reviewed by an independent adjudicator on
2026-10-24 and was not upheld (see "Why", below). Its "Detective control until then" paragraph and its statement about the Settings panel are superseded too: success rows now carry only `standing=available`, `refused` is a withheld standing with its own `denied` row, and the panel withholds the list for a refused caller. Nothing in the 2026-10-23 Update is deleted.

**What changed.** The standing decides what `GET /api/v1/ca/issued` (both forms), MCP `list_issued_certs`,
the `/crypto` drill and the Settings certificate panel's inventory do. The standing is the same on all
four; the answer shape and the audit row differ by surface.

| Standing | Served? | REST route and MCP tool | `/crypto` drill and Settings panel |
|---|---|---|---|
| kAvailable (a global `Inventory:Read`, an elevated session, an engine principal holding the grant, or RBAC enforcement off) | yes | list served; success row ends `standing=available` | list rendered; the drill's success row carries no standing token, the panel is not audited |
| kConfined (`Inventory:Read` granted only through management groups) | no | 403 / permission denied; `denied` row ending `withheld=confined` | HTTP 200 fragment with a note in place of the list; no CA-view row |
| kRefused (no `Inventory:Read` grant at all) | **no** | 403 / permission denied; `denied` row ending `withheld=refused` | HTTP 200 fragment with a different note; no CA-view row |
| kDegraded (the access check could not complete, **including a read failure inside it**) | no | 503, `retry_after_ms` 5000; `failure` row | HTTP 200 fragment with an unavailable note and Retry; no CA-view row (the drill writes none when its check is unavailable) |

The missing rows on the drill and the panel are an existing gap, tracked as #6384; this Update does not
change it. The `failure` row is written for the resolver and engine branches this Update adds. A failed
service-ceiling or service-tag read at the fleet gate still audits `denied`.

1. **A read failure inside the access check is a 503, never the list.** `ListReadAuthorization` gains
   `bool read_failed`, set when the global-grant read, the permission-group resolution or the
   visible-set expansion fails, or the management-group store is not wired (not for an empty
   `allow_groups`). When the global-grant read fails nothing further is read. An engine principal's
   grant read is checked the same way. The fleet-read gate (`authz_gates.cpp`) and the list-read
   gate (`auth_routes.cpp`) answer 503 on it instead of a 403, so `crypto_access_for` already maps
   it to kDegraded. ADR-0017 INV-1 (any error is deny) and INV-5 (a partial failure never includes)
   hold again for these reads; the exception recorded on 2026-10-23 is closed. Every fleet-gated
   and list-gated read now answers 503 rather than 403 on a mid-query failure; both still deny.
   The front `Security:Read` gate and the other plain `require_permission` sites still answer 403
   on a failed first read (ADR-0041 deny-on-degrade); that is unchanged and is tracked as #6437.
2. **No grant is not an affirmative admission.** A `Security:Read` holder with no `Inventory:Read`
   grant is refused the list. R2's reading that confinement is a property of a scoped grant remains
   true, but the converse does not follow: removing a caller's last scoped grant must not widen what
   it can see. #6383 is decided by this Update.
3. **Corrections to the 2026-10-23 text.** (a) The slice withholds a confined caller's whole
   inventory; it does not filter it per device (`list_issued` has no scope parameter). (b) "Adding a
   deny" does not by itself widen the list: a global deny does not erase a group allow. The widening
   was the loss of the last scoped allow. (c) The two "KNOWN RESIDUAL" tests injected kRefused; they
   did not reproduce an authorization query failure. They are replaced by REST tests that run the real
   access check against a broken management-group store and against grant removal. The MCP
   refused-standing test still injects `kRefused`; it covers the consumer, and the failed-read and
   engine paths are covered by the real-stack and engine-gate tests.

**Why.** The governance rules do not let an author defer a CRITICAL or HIGH finding, and an
adjudication is not a waiver. The adjudicator (a second model, read-only, 2026-10-24) derived the
failed-read disclosure as CRITICAL (impact I1, exposure E2: an authenticated `Security:Read` holder
with only group-scoped inventory access receives out-of-scope device-certificate metadata: serial,
subject which is the agent id, SAN, status, dates, issuer) and the no-grant widening as HIGH.

**Consequence for operators.** Breaking for a custom role that holds `Security:Read` and no
`Inventory:Read`; the seeded Administrator and Viewer roles, the only seeded roles that hold
`Security:Read`, also hold a global `Inventory:Read`, per `seed_defaults()`. See
`docs/user-manual/upgrading.md`.

**Approval.** The maintainer, Dave Rae, approved applying this Update on 2026-10-24. The ADR author's confirmation is not recorded in the repository.
