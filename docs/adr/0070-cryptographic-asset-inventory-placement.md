---
status: accepted
date: 2026-10-18
owner: "@liamsomerville (Liam Somerville)"
deciders: >-
  maintainer review of the PR that lands this ADR, by an approver who is not the author
  (the acceptance event under docs/agents/domain.md "ADR Acceptance Convention"); ADR-1005
  Decision 2 names the maintainer as the arbiter of boundary disputes, so that review also
  settles the four rulings flagged "maintainer ruling" below (D2, D3, D5, D7)
scope: >-
  capability-map Domain 41 (Cryptographic Asset Inventory, roadmap Issue 18.8) — where
  each part is built under ADR-1005: collection, transport, storage, raw-fact reads,
  rollups, the slice-1 library-family table and a fact-only CBOM export (core mechanism,
  built in-server); weak/deprecated-algorithm and PQC-readiness labels, expiry-risk
  scoring, library support/EOL status, third-party revocation status, policy and
  compliance-framework verdicts (use-case engine, behind the ADR-0032 interlock); plus the
  binding constraints the slice-2 design must meet (D6, D12). Not in scope: the per-slice
  data designs, and the slice-3 privacy decisions, which are owed by their own ADR
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
  tracking issue); PR #6056 (slice 1, open as of 2026-10-18)
---

# 0070 — Cryptographic asset inventory: placement under ADR-1005

> **Implementation status (2026-10-18).** Slice 1 (crypto-library presence, capability
> 41.1) is built in-server and **in review as PR #6056**. It is not on `dev` yet, so every
> slice-1 path below is cited at that PR's branch. Slices 2 and 3 (certificates, SSH) are
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
  - a CBOM export that carries facts only.

  The certificate and SSH parts are planned, not committed, and are not available until
  their slices ship.
- **Use-case engine (UCE; interpretation).** This covers any verdict whose semantics Yuzu
  would ship in code:
  - weak, deprecated or broken algorithms and key sizes;
  - post-quantum readiness;
  - expiry-risk bands and scores;
  - library support and end-of-life status;
  - revocation status fetched from third-party CRL/OCSP endpoints;
  - mappings to NIST, CNSA, PCI or any other framework;
  - the CVE join over library versions (already the vulnerability module's scope).

  None of this is built until a use-case engine exists and the ADR-0032 interlock opens.
  "UCE" is the execution plan's shorthand (Decision 12 there), also used by ADR-0024 and
  ADR-0032; ADR-1005 itself spells it out.

Slices 2 and 3 have not shipped, so the outcome is ADR-0024's: a **re-scope, not a
carve-out**. The interpretation half is never built in-server, so nothing here is
grandfathered and nothing needs a strangler later. D6 and D12 then fix the constraints
the slice-2 design must meet, so that the certificate inventory is safe to build as core.

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
   date", or fetch third-party CRLs and label certificates revoked. This ADR rules
   otherwise (D3, D5).

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
> - "SHA-1 signatures are weak";
> - "this certificate is at risk".
>
> Each judgement depends on a standard, a date or a threat model that Yuzu would have to
> choose and keep current. Facts are core. Judgements are engine territory, unless the
> operator authors the judgement themselves, as policy content evaluated by a generic
> engine.

A **derived field** is core only if it is a pure function of collected raw facts and a value
the caller supplies. A field is a verdict, and belongs to the engine, if it reads any clock
(the server's or the agent's) or applies a cut-off Yuzu chose. That holds whether the server
computes it or the agent computes it at collection time.

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

## Placement under ADR-1005

**Ruling: re-scope, not a carve-out.** The interpretation half of Domain 41 is not built
in-server at all. The parts below marked **core** are permanently server- or
agent-resident. "Store ownership follows the layer" (ADR-1005 Consequences, `:697`), so
the raw stores stay core and any engine-derived state is the engine's own.

Rows for slices 2 and 3, and for 41.5 and 41.6, are **planned, not committed**. They
classify the work if it is built; they do not promise it.

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
| Certificate ↔ private-key association: whether a key is present and, where the platform exposes it without opening the key, whether it is exportable and hardware- or TPM-backed (never the key) | 2 | **core** | Facts about the device's key storage, read from metadata, never from key material (D6). On Windows, export policy needs the key opened, so it is not collected there unless the design doc shows a way that opens no key. |
| Certificate read surface (REST + MCP + dashboard), raw-value rollups, paged per-certificate read | 2 | **core** — D12 | Raw-fact reads under existing confinement and audit. These are also the core capability an engine reads through (ADR-0031 seam B6, D9). |
| Caller-parameterised filters (e.g. `not_after < T`, `key_bits < N`) and distinct-device counts by raw value | 2 | **core** — D4 | A generic query primitive. The caller supplies the threshold, so the semantics are the caller's, not code-baked. |
| "Expired / expires in N days" as Yuzu-defined bands, risk scores, default thresholds, Yuzu-chosen expiry notifications (roadmap Issue 18.3 "expiry alerts") | 2 | **UCE** — D4 | Derived against "now" with a threshold Yuzu chooses. Same class as ADR-0024's *effective licence state* (`0024:126-128`), which that ADR sends to the engine. |
| Operator-authored policy over certificate facts (e.g. an operator's rule "fail if `not_after` < now + 30d") | 2 | **core** | "operator-authored content evaluated by a generic engine" (ADR-1005:47). The operator owns the semantics. Not available until slice 2 exists (D4). |
| Chain-to-local-trust-store result computed on the device, with no network retrieval and no revocation check | 2 | **core**, only under D5's conditions; optional, not committed | A deterministic fact about the device's own configuration. A chain build that fetches, or consults revocation data, is a join with third-party data, so engine territory (D5). |
| Revocation status from third-party CRL/OCSP endpoints | 2 | **UCE** — D5 (maintainer ruling) | A join of fleet data with external, third-party data for a judgement. |
| Certificate renewal, re-issue, deletion, revocation workflow (roadmap Issue 18.3 lifecycle) | 2+ | out of scope here | These are mutations, not reads. When designed, they go through ADR-0033's Execution Plan and approval primitive. The existing `certificates.delete` action is Destructive/Irreversible and is never part of the inventory path (D6). Renewal against an external CA (ACME, AD CS) is a connector-class join, to be classified against ADR-1005's Decision-2 appendix "Connectors" row once that row exists (PR #5367). |
| SSH key-at-rest collection: host public keys; `authorized_keys` entries and user public keys (type, size, fingerprint, location; never key content) | 3 | **core** (collection) — privacy owed (D8) | Collection of estate facts. The per-user parts carry privacy obligations the slice-3 ADR must decide. |
| SSH login evidence (who, from where, with which key type) | 3 | **core** (collection) — privacy owed (D8) | Collection of estate facts, but behavioural personal data. ADR-1005 Decision 5's controls will attach to any engine that consumes it. |
| "Unused / stale / anomalous key", "key used from an unusual location" | 3 | **UCE** | Semantics baked into code: a judgement about behaviour. |
| Protocol and configuration settings: enabled TLS/SSH versions; cipher, KEX and MAC lists; system crypto policy | 41.5 | **core** (facts) / **UCE** (verdicts) | The configured list is a fact. "Weak cipher enabled" is a verdict. No collection vehicle is designed; it needs its own design. |
| CBOM export of the collected inventory | 41.6 | **core**, facts only — D7 (maintainer ruling) | A projection of core facts into a standard format, like ADR-0028's SBOM projection. Verdict-bearing CBOM fields are left empty in core. |
| Weak / deprecated / broken algorithm and key-size labels; PQC readiness; crypto-agility scoring | all | **UCE** | Semantics baked into code, tied to an external standard and threat model. The canonical engine case. |
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

**Core's built-in fields and reads never compare a certificate's dates against the server's
own clock.** Every such comparison takes a time T the caller supplies. That includes
"already expired", which is a query with T = now, chosen by the caller, not a field or a
label. Operator-authored policy is the one place a comparison may use "now", because the
operator wrote it; even then it must name whose clock "now" is (below).

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

**Core does not ship:**
- a built-in notion of "expiring soon" (no default 30/60/90-day bands, no "at risk"
  label, no colour coding of dates);
- expiry scores;
- notifications on a Yuzu-chosen threshold (roadmap Issue 18.3's "expiry alerts", when
  Yuzu picks the threshold).

These are derived against "now" under a policy Yuzu would choose. That is the same class
as ADR-0024's *effective licence state*, which is derived against "now" and assigned to
the engine (`0024:126-128`). An expiry check the *operator* writes, with their own
threshold, is operator-authored content, so it is core.

### D5 — Revocation and trust: device-local facts core, third-party status engine [split]

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

   **Outcome required:** a core result must be independent of every CA's revocation data,
   fetched or cached. On any platform where the implementation cannot show that (for
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

**Revocation status.** Fetching CRLs or querying OCSP responders run by third-party CAs
joins fleet data with external data to answer a judgement question, so it is engine
territory. ADR-1005:47's "CRL" example covers the platform's *own* revocation needs. For
example:
- Yuzu's internal CA publishes its CRL (`CaStore::publish_next_crl`, ADR-0053);
- the agent's signature verifier loads a local CRL file (`detached_signature.cpp`).

It does not cover grading fleet certificates against other CAs' lists. Whichever side
builds a fetcher, the URLs come from the certificates under inventory, which are
untrusted. The fetcher therefore needs its own security review, with at least:
- an allow-list or a no-internal-address policy;
- no credentials on outbound requests;
- bounded timeouts and sizes.

**If reversed** (third-party revocation ruled core), that fetcher lands in core, with the
same review obligations.

**Maintainer ruling requested:** confirm the purpose-based reading of the "CRL" carve-out,
and that OS-vendor distrust data already on the device counts as device configuration under
the conditions above.

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
key is present and, where the platform exposes it without opening the key, whether it is
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

The inventory does not read `CaStore` in slice 2 either. Correlating fleet certificates
with Yuzu-issued ones would be a separate feature, reading `CaStore` through its own core
interface and never its tables, under its own review.

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
- **Behavioural judgements are engine territory:** stale, unused or anomalous key use,
  and unusual source locations.

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
- its description says "presence and facts only, no verdicts";
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
`compliant`, and similar. Review alone does not catch a field added later.

### D11 — Recording the boundary verdicts [process]

ADR-1005:47 says "verdicts accrete into an examples appendix in this file". As of
2026-10-18 no appendix exists on `dev`; PR #5367 (unmerged) would create one, with the
columns `Date | Class | Verdict | Raised by`. When the appendix exists, the four rulings
this ADR requests are added to it as rows. Each binds for the class it names:

| Ruling | Class | The Verdict cell must carry |
|---|---|---|
| D2 | curated identity tables | D2's four conditions — without them the class is wider than D2 rules on |
| D3 | third-party lifecycle data used to grade estate software | whether OS-version grading is included (D3) |
| D5 | third-party revocation status | — |
| D7 | verdict-free standard-format exports | — |

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
      way `Forensics:Read` is floored for app usage. Flooring a shared securable is not
      allowed: `Security:Read` also gates quarantine, the CA routes and key-management
      status, and `Inventory:Read` gates slice 1 and the generic inventory.
- **Gate and denial text take the securable as a parameter.** Slice 1 hard-codes
  `"Inventory","Read"` and the denial text "Inventory:Read is required". A synced copy must
  not widen who can see fleet certificates, and a denial must name the permission actually
  required. On a page that shows both halves, a denied certificate half says it was denied
  and never renders as "no certificates".
- **Audit and degrade.** Each read is audited with its own verb, recording fleet-wide or
  confined scope. A degraded read is a 503 with a retry hint, never an empty 200.
- **Admission.** Reads are admitted through the existing `/crypto` read gate and degrade
  metric. Extend them; never fork them.
- **Truncation is disclosed on every read.** A read response that is capped (a page limit,
  a per-device limit, a rollup row ceiling) carries a named truncation flag. It never
  looks complete, and never looks empty.

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
    `observed_at` is older than a bounded period the design doc states. Age alone never
    prunes, so an offline device or a fleet-wide outage does not wipe the inventory. The
    prune follows the clock-guarded-retention concern. The design doc also states how a
    pruned store's rows are re-sent despite the daily sync skipping unchanged content.
    Until pruned, kept rows are shown as last observed at their `observed_at`.
- A capped or timed-out capture is reported `constrained`, and the report is never an
  empty success.
- An empty blob is never sent for a failed or constrained capture (the ADR-0016
  `app_usage` rule).
- A field an older agent did not send reads as unknown, never as empty, and the blob is
  versioned.

**Identity.**
- A row is keyed by (device, store/location/path, SHA-256 fingerprint). SHA-1 is display
  only.
- **Duplicates count once.** On Linux the same certificate commonly appears several times:
  - inside a bundle file;
  - as a separate file;
  - through hash links. For example, Debian's `/etc/ssl/certs/ca-certificates.crt` bundle
    and the links into `/usr/share/ca-certificates/` hold the same roots.

  Every count is therefore of distinct (device, SHA-256 fingerprint), and the locations a
  certificate was found at are a list on that one entry, never separate entries.
- A fallback read never stands in for LocalMachine.
- A service account's own store is labelled as such, never as a person's.
- **Per-user rows** do not take part in the machine-scope replace. They have their own
  replace scope.
  - The scope is keyed by device and a stable OS identity for the user (a SID or uid),
    never a username or a rotating pseudonym.
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

**Chaos.** The slice-2 PR runs these five scenarios before merge. Each is defined by the
property it must prove; the tools are the design doc's choice.

| ID | Scenario | Must prove |
|---|---|---|
| CH-1 | A store read fails during a whole-device replace while a user logs off | Machine rows survive with their original `observed_at`. The failed store reads `unreadable`. The departed user's rows go only through the per-user scope. The blob is never empty. |
| CH-2 | Hostile certificates: 10k SANs, oversized subjects, script and control characters, invalid UTF-8, e-mail SANs | The caps hit and the certificate is `constrained`. Nothing executes in the dashboard (no CSP page error). Audit details are escaped. Personal data is handled as the design doc decided. |
| CH-3 | A planted certificate whose AIA/CDP/OCSP URLs point at a listener, plus a pre-seeded cached CRL and a cached OCSP response marking it revoked, run on each platform that builds the chain result | The listener receives zero connections. The result reflects neither the cached CRL nor the cached OCSP response. A platform that cannot meet this does not build the result in core (D5). Where an OS-vendor distrust list affects the result, the result is labelled as the OS's own evaluation. |
| CH-4 | An offline device, an engine-grain read and a capped read | Every row exposes `observed_at` and `last_seen`. The read completes across pages or fails. The truncation flag is set, and the CBOM carries its coverage metadata. |
| CH-5 | Agent clock skew; certificates expiring at day boundaries; the year-9999 sentinel; a pre-1970 date | Validity is stored as UTC to the second and never clamped. Core results change only with the caller's T. An agent-side policy discloses its clock offset. |

## Consequences

- **Slice 2 is unblocked to design.** Its design doc must cite this ADR and satisfy D4,
  D5, D6, D7 and D12. It starts after PR #6056 merges.
- **Slice 3 needs its own ADR first** (D8), with the privacy decisions made by the owner.
- **Slice 1 needs follow-up edits, not code changes.** Once both PRs are on `dev`, a
  follow-up makes these edits:
  - `crypto_library_model.hpp:10-14` cites this ADR (D2, D3) for the rule it states.
  - `docs/user-manual/crypto.md`:
    - The Roadmap section stops saying future slices come "under the same permission and
      audit model". D8 and D12 decide those per slice.
    - The Roadmap qualifies CBOM as facts-only and SSH login evidence as subject to a
      separate privacy decision.
    - It says plainly that Yuzu does not label weak cryptography, expiry risk or PQC
      readiness in core, and what an operator can do instead.
    - It says that operator policy over certificate facts is not available until slice 2
      ships.
  - The capability-map §41 preamble and roadmap Issue 18.8 widen their list of excluded
    verdicts to match this ADR (expiry bands, EOL status, third-party revocation,
    framework mappings) and cite it.
  - §41.6 says facts-only (D7), and §41.2's store wording matches D6's gap list.
  - These are also the links #6051 asks for.
- **No engine work is created.** The crypto-posture module is a backlog entry for the
  engine host, behind D9.
- **A reviewer can now cite a rule instead of an inference.** "Does this field grade
  something?" is the question, the placement table is the precedent, and D10's lint is the
  backstop.
- **The cost.** Until an engine exists, operators who want "show me weak crypto" or
  "certificates expiring this month" get only the raw facts and their own policies, and
  the certificate half only once slice 2 ships. That is ADR-1005's intended trade, and
  D4's caller thresholds and operator policy cover the most common expiry need without
  Yuzu choosing the threshold.

## Alternatives considered

- **Build the verdicts in-server now and grandfather them** (the vulnerability vertical's
  path). Rejected. Grandfathering exists for shipped work, and nothing here has shipped.
  Building interpretation in-server now would grow a future deletion scope, which is the
  outcome ADR-0023's placement note warns of ("each further in-server PR on this ladder
  grows that deletion scope").
- **Classify the family table as interpretation too, and move all of Domain 41 to an
  engine.** Rejected. It would leave the estate's facts uncollected until an engine
  exists, contradicting ADR-1005's own placement of collection and inventory stores in
  core, and it misreads identity resolution as grading (D2).
- **A narrow, "obviously uncontroversial" built-in list**, for example flagging MD5 and
  SHA-1 signatures only. Rejected. Any built-in list is "semantics baked into code",
  however short. The line has to be where the semantics come from, not how many there are.
  An operator can author the same rule as policy (D4).
- **Label "already expired" as a fact.** Rejected (D4). It depends on the server's clock,
  the comparison is reproducible from the raw date with T = now, and a label is the first
  step towards bands.

## Ratification

Accepted by the merge of the reviewed PR that lands this file, under the ADR Acceptance
Convention (`docs/agents/domain.md`). The `status: accepted` above is the value the file
carries once that PR merges. Before the merge, the PR is the proposal.

**Who approves, and what the approval records:**
- The approving review must come from someone other than the author. That review, and the
  merge metadata that goes with it, is the change-management evidence. A self-merge does
  not accept this ADR.
- ADR-1005 Decision 2 makes the maintainer the arbiter of boundary disputes. The approval
  is also the ruling on D2, D3, D5 and D7.
- The approval grants those four rulings as written. Approvers are asked to state each
  ruling in the review, so that the record shows each one, but the statements are a
  request, not a separate acceptance gate. On merge, the "ruling requested" notes in those
  decisions record rulings granted by that approval.
- A reviewer who disagrees with any one of them blocks on it specifically, so that it can
  be split out rather than accepted silently.
