# Vuln-Scan Capability Map (standalone — to be merged)

**Status of this document:** standalone working map for the vuln_scan / CAVM workstream.
It is deliberately separate so the vuln_scan team can iterate without churning the
fleet-wide `docs/capability-map.md`. **Merge target:** expand `§9.4 Vulnerability
Scanning` and add a new top-level domain (provisionally **§32 — Vulnerability &
Attack-Path Management (CAVM)**). See **Merge guidance** at the bottom.

Sources of truth this map is reconciled against (2026-06-30; **last reconciled 2026-07-01**
against ADR-0018/ADR-0019 below):
- Plugin: `agents/plugins/vuln_scan/src/`, contract `content/definitions/vuln_scan.yaml`
- North-star design: `docs/vuln-scan-engine-design.md` (floor = Phases 1–5, differentiator = Phases 6–8)
- Theory: `CAVM_WhitePaper_v16` (EUC, composite score, AMAPC, choke points, crown jewels, gate model)
- Topology: `server/core/src/fleet_topology_store.{hpp,cpp}`, `fleet_topology_types.hpp`
- NVD infra: `nvd_client` + `nvd_db` (`NvdDatabase`) + `nvd_sync` (`NvdSyncManager`) — **wired**; feeds the fleet-topology vuln overlay (`match_inventory`). Full newest-first catalog backfill (was keyword-scoped); agent plugin not joined to it.
- Epic/issue breakdown: this workstream's sequenced plan (Epics 1–7)
- ADR: `docs/adr/0018-server-authoritative-vulnerability-matching.md` — matching location, wire
  format (typed identity, not PURL), Lane 1/2/3 routing
- ADR: `docs/adr/0019-tri-state-findings-coverage-dimension.md` — finding status model + coverage dimension

---

## Legend

**Status:** :white_check_mark: Done · :large_orange_diamond: Partial · :x: Not started

**Delivery tier** (mirrors the parent map's `T1/T2/T3`, and maps to the design-doc split):
- `T1` — **Floor / parity** (Phases 1–5): a correct, trustworthy scanner. Table stakes.
- `T2` — **Join & asset model** (Phases 5–6): make "vulnerable **and** reachable" expressible.
- `T3` — **Differentiator** (Phases 6–8): CAVM attack-path scoring and operational integration.

---

## Progress at a glance

| Domain | Done | Partial | Not started |
|---|---:|---:|---:|
| V1 Inventory & collection (collect-thin) | 2 | 1 | 0 |
| V2 CVE correlation & enrichment (correlate-rich) | 0 | 4 | 5 |
| V3 Configuration & compliance scanning | 0 | 1 | 1 |
| V4 Findings, output & reporting | 2 | 1 | 2 |
| V5 Topology integration (vuln↔graph) | 1 | 1 | 2 |
| V6 Asset model (crown jewels) | 0 | 0 | 2 |
| V7 Attack-path analytics (CAVM core) | 0 | 1 | 6 |
| V8 Operational integration | 0 | 0 | 3 |
| **Total** | **5** | **9** | **21** |

> The floor (collection + topology graph) is the strongest area; the differentiator
> (V6/V7/V8) is almost entirely greenfield. This matches the gap analysis: Yuzu has
> already solved the expensive *collection* problems and has almost none of the *scoring*.

---

## V1 — Inventory & Collection (collect-thin)
*The agent ships thin, structured endpoint state; correlation happens server-side.*

### V1.1 Installed-software / package inventory :white_check_mark: `T1`
`vuln_scan` `inventory` action emits `name|version` rows; reuses the daily-sync
`installed_software` source (ADR-0016). Cross-platform.

### V1.2 Process / listener / connection snapshot :white_check_mark: `T1`
`echo` plugin `fleet_snapshot.v1` (`agents/plugins/echo/src/echo_fleet_snapshot.cpp`) —
processes, listeners, 4-tuple connections with owning PID. Feeds V5.

### V1.3 Per-OS package identity (typed identity emit) :large_orange_diamond: `T1`
Collection exists, but the agent emits only `name|version` and drops the fields correct
matching needs (source/ecosystem, arch, full EVR). **Decided (2026-06-30, corrected 2026-07-01
by ADR-0018 D1):** the agent emits a **structured typed identity `oneof`** — `PackageIdentity`
(ecosystem, name, epoch, version, release, arch — lossless, decomposed, no PURL string) for
package-managed software, and `AppIdentity` (`DisplayName`/`Publisher`/`FileVersion` on Windows,
`CFBundleIdentifier`/version on macOS) for the GUI tail. **PURL is NOT the wire format** — it is
a server-derived projection computed only when interop needs it (SBOM/CycloneDX export, OSV.dev
queries for Lane 2 below). **CPE is also server-derived, never emitted by the agent** (lossy —
cannot carry epoch/release — and dictionary-dependent). See memory `vuln-scan-agent-emits-purl`,
ADR-0018, and `docs/vuln-scan-roadmap.md` M1a.
> **Gap:** build the typed-identity collector per-OS (dpkg/rpm/apk + `/etc/os-release` namespace
> + arch + EVR → `PackageIdentity`; Windows/macOS raw fields → `AppIdentity`); unify the
> duplicate collector (vuln_scan vs `installed_apps`); add kernel + OS build rows. *(roadmap M1a)*

---

## V2 — CVE Correlation & Enrichment (correlate-rich)
*The server resolves inventory against vulnerability data. **Two disjoint mechanisms exist
today** — a hardcoded agent-plugin matcher and a live server NVD pipeline — and they are not joined.*
*Identity model (ADR-0018): agent emits a **structured typed identity** (`PackageIdentity`/
`AppIdentity`), never PURL. Server routes by ecosystem into three lanes: **Lane 1** distro
packages (deb/rpm/apk) → **OVAL-primary, NVD-fallback** on the full EVR (dpkg/rpmvercmp/semver
comparators); **Lane 2** language ecosystems (pypi/npm/gem/cargo/…) → **OSV.dev by
server-derived PURL** (deterministic, no CPE guessing); **Lane 3** OS-native GUI apps
(Windows/macOS) → **not-assessed in v1** (no curated detection content authored; federation
deferred to ADR-0020). See V1.3 + memory `vuln-scan-agent-emits-purl`.*

### V2.1 Agent-side built-in CVE rules :large_orange_diamond: `T1`
The `vuln_scan` plugin matches against a **hardcoded** `cve_rules.hpp` (`std::array` of
hand-written `CveRule`s, substring product match + "version below"). This is the closed-PR
PoC with the #1301/#1206 defects: inverted multi-branch ranges, no distro backport
awareness, substring (non-CPE) identity, severity from a bare label. The plugin does **not**
consult the server NVD database (V2.2).
> **Gap:** this path **retires under ADR-0018** (server-authoritative matching) — no in-place
> correctness rebuild. Its comparator is salvaged into the server-side range-aware comparator
> (roadmap M1a); the ~40 rules and the #1206 runtime-rule pipeline are not carried forward.
> *(superseded; see ADR-0018 Consequences)*

### V2.2 Server-side NVD ingestion & database :large_orange_diamond: `T1`
**WIRED** (transport + a store), but **the match model is wrong, not just the corpus.**
`nvd_client` (HTTPS → `services.nvd.nist.gov`, NVD 2.0 API, API-key+proxy) → `nvd_db`
(`NvdDatabase`) → `nvd_sync` (`NvdSyncManager`, 4h). Constructed/started in `server.cpp:982-987`
when `nvd_sync_enabled`; CLI `--nvd-sync-interval` / `--nvd-api-key` / `--nvd-proxy` /
`--nvd-backfill-years` / `--no-nvd-sync`, env `YUZU_NVD_SYNC_INTERVAL` /
`YUZU_NVD_BACKFILL_YEARS`; status REST endpoint.
> **Gap (was two layers; layer 1 now CLOSED):**
> 1. **Schema now represents CPE ranges — CLOSED.** The store was reshaped (v1→v2 migration)
>    from the flat `cve(product, affected_below)` into a normalized `cve` + `cve_match` model
>    that holds NVD's `cpeMatch` range bounds (`version_start/end_including/excluding`, multiple
>    ranges per CVE) — see the `cve_match` schema in `nvd_db.cpp`. Delivered by the
>    CPE-range-matching PR.
> 2. **Corpus is now a full newest-first backfill** (configurable depth via
>    `--nvd-backfill-years`, default 8y, `0` = full history; resumable across restarts,
>    then periodic freshness), no longer keyword-scoped — that gap is **CLOSED**. The
>    remaining gap is **vendor-precise identity** (product-name matching, ADR-0018), not
>    corpus size; with no API key by default the initial backfill is slow (low rate limit).
> **Note:** the parent map's §9.4 "NVD database sync on server" claim describes wired infra, but
> **the sync never actually ran until 2026-07-04** — a `rate_limit()` integer overflow slept ~292
> years before the first HTTP request on every deployment (fixed in the NVD rate-limit PR; #1867).
> It is now verified E2E-populating. Treat "NVD sync works" as true only from that fix onward.

### V2.3 NVD → inventory correlation join :large_orange_diamond: `T2`
`NvdDatabase::match_inventory` now matches with **real CPE range semantics**: it builds a
`VersionRange` from each `cve_match` row and calls `nvd_version_in_range` (`nvd_db.cpp`),
honouring `versionStart/EndIncluding/Excluding`. Product selection is still name-based
(`product LIKE ?`), so range evaluation is only as precise as the product-name match feeding
it. It is consumed by the **fleet-topology vuln overlay** only (`FleetTopologyStore`,
`include_vuln=true`); the agent plugin's findings are **not** correlated against it.
> **Gap (range comparator now DONE; identity is the remaining gap):** the range-aware
> comparator + `cpeMatch` range test shipped with the CPE-range PR. What remains is
> **vendor-precise identity** — typed-identity→CPE mapping (curated + pgvector fuzzy, Lane 1's
> NVD-fallback and Lane 3's future federation) to replace the prefix-anchored `product LIKE 'name%'`
> match (ADR-0018) — alongside Lane 1's OVAL-primary (V2.4) and Lane 2's OSV.dev-by-PURL (V2.9), as
> part of the single server correlation engine. *(roadmap M1a; topology attach is M3)*

### V2.4 Distro advisory / OVAL backport correlation :x: `T1`
**Not ingested.** No OVAL/OVD anywhere in code — design-doc only
(`vuln-scan-engine-design.md` Phase 2 "backport correctness, the FP killer", item R3,
assigned to Andy). Without it, version-only matching false-positives on backported fixes.
**This is ADR-0018 Lane 1's authoritative path** for distro packages (OVAL-primary,
NVD-fallback) — see V1.3/V2 intro.
> **Gap:** OVAL/distro-advisory ingestion + backport-aware matching. *(Epic 1.1 / design Phase 2)*

### V2.5 CVSS-vector enrichment :large_orange_diamond: `T1`
NVD records carry severity, but there is no CVSS **base vector** decomposition into
exploitability/impact sub-scores for downstream weighting.
> **Gap:** persist + parse CVSS vectors. *(Epic 2.1)*

### V2.6 EPSS (exploit-probability) enrichment :x: `T2`
No EPSS data source. CAVM's threat weight (w=0.20) has no input.
> **Gap:** EPSS ingestion. *(Epic 2.2)*

### V2.7 KEV (known-exploited) enrichment :x: `T2`
No CISA KEV catalog. Cannot flag actively-exploited CVEs.
> **Gap:** KEV ingestion + per-finding flag. *(Epic 2.2)*

### V2.8 Enrichment-data store (CVSS/EPSS/KEV cache) :x: `T2`
`NvdDatabase` stores CVEs, but there is no store for the enrichment overlays (CVSS vector,
EPSS, KEV) that scoring needs.
> **Gap:** born-on-PG `vuln_data_store` (schema `vuln_data_store`, ADR-0008 naming;
> fail-soft per ADR-0012) **or** extend `NvdDatabase`. *(Epic 2.1)*

### V2.9 OSV.dev / language-ecosystem correlation (Lane 2) :x: `T2`
**Not ingested.** No OSV.dev client, no language-ecosystem (pypi/npm/gem/cargo/…) matching path
anywhere in code. **Decided (ADR-0018 Lane 2):** these ecosystems carry clean, deterministic
PURLs (server-derived from the agent's typed identity), so matching is OSV.dev-by-PURL directly
— no CPE guessing, and this lane is pulled *out* of the fuzzy-CPE surface (shrinking Lane 3 to
the GUI tail only).
> **Gap:** OSV.dev client + language-ecosystem identity in the correlation engine.
> *(roadmap M1a+, not yet milestone-assigned — new since the 2026-07-01 lane split)*

---

## V3 — Configuration & Compliance Scanning

### V3.1 Config-hardening checks :large_orange_diamond: `T1`
`vuln_scan` `config_scan` + `cve_scan` actions exist (per `vuln_scan.yaml`) at a basic
level; severity taxonomy CRITICAL/HIGH/MEDIUM/LOW/INFO defined.
> **Gap:** depth/coverage of checks; benchmark mapping (CIS/STIG) not present.

### V3.2 Benchmark / compliance-framework mapping :x: `T3`
No mapping of findings to CIS/STIG/regulatory controls.
> **Gap:** out of scope for the floor; revisit after V2.

---

## V4 — Findings, Output & Reporting

### V4.1 Structured finding output :white_check_mark: `T1`
Pipe-delimited finding rows; `summary` action aggregates. Verified end-to-end on the
native macOS agent (8 findings: 1 HIGH/3 MEDIUM/4 INFO).

### V4.2 Findings persistence :white_check_mark: `T1`
Findings land in the response store (filterable/aggregatable) like any instruction result.

### V4.3 Dashboard surfacing & charts :large_orange_diamond: `T2`
A `vuln_scan` chart ships in the `demo.visualization.fleet-posture` InstructionSet
(ECharts). No dedicated `/vuln` page or per-device vuln lens yet.
> **Gap:** dedicated vuln dashboard + MCP/REST parity (agentic-first A1). *(Epic 6 surfacing)*

### V4.4 Dedicated vulnerability store (current-state, dedup) :x: `T2`
Findings are per-execution rows; there is no current-state, deduplicated, per-device
vulnerability table to drive scoring/trend.
> **Gap:** born-on-PG findings store keyed by (agent, package-identity, CVE/advisory), carrying
> **tri-state status** (vulnerable/assessed-clean/not-assessed, ADR-0019) and the feed-sync
> timestamp behind each assessed-clean verdict. *(Epic 3.2 prerequisite; ADR-0019)*

### V4.5 Tri-state status & coverage metric :x: `T2`
No status enum — today's model is implicitly boolean (a finding row exists, or it doesn't) — and
no per-host coverage counter. **Decided (ADR-0019):** per-`(host, package)` status is
**vulnerable / assessed-clean / not-assessed**; "assessed-clean" is timestamped to the feed
version it was evaluated against; each scan reports a **coverage metric** (assessed N of M
installed packages) as a first-class figure, never inferred from the vulnerability count.
> **Gap:** thread the status enum + timestamp through the findings store (V4.4) and surface
> coverage in the dashboard/REST (V4.3), grouped by not-assessed reason (no-OVAL-stream /
> no-CPE-mapping / side-loaded). *(roadmap M2; ADR-0019)*

---

## V5 — Topology Integration (vuln ↔ graph join)
*The join that makes "vulnerable AND reachable" expressible. Yuzu's biggest head-start.*

### V5.1 Observed reachability graph :white_check_mark: `T2`
`FleetTopologyStore` — host + service nodes, edges classified Local/InternalFleet/External,
IP→agent_id stitching (first-claim-wins, 300s reclaim), anti-spoof UP-* invariants.
Served via `viz_routes` + `yuzu-viz.js`. **Natively produced — no external topology tool needed.**

### V5.2 Topology persistence (time-aware) :x: `T2`
In-memory only (60s TTL, no history). Scoring and AMAPC trend need persisted snapshots.
> **Gap:** born-on-PG `topology_snapshot_store`, keep the in-memory hot path for viz. *(Epic 3.1)*

### V5.3 Vuln→service/host-node attachment :x: `T2`
Findings and topology nodes are disjoint datasets — no join key wired.
> **Gap:** join on (agent_id + port/proc); node gains a finding-ref set. *(Epic 3.2)*

### V5.4 Vulnerability overlay in fleet viz :large_orange_diamond: `T3`
Planned as `feat/viz-engine` PR 10 (vulnerability overlay) + per-process posture glyph
(synthesising vuln/AV/signing/firewall/encryption). Infrastructure exists; overlay not shipped.
> **Gap:** depends on V5.3 join. *(Epic 3.2 surfacing)*

---

## V6 — Asset Model (crown jewels)
*Gating prerequisite for the entire differentiator — every CAVM score is relative to jewel reachability.*

### V6.1 Crown-jewel designation :x: `T3`
No asset-value, criticality, or crown-jewel concept anywhere in code (only false-positive
string matches like crypto "key").
> **Gap:** operator/CMDB-entry surface + RBAC securable + audit-on-write. *(Epic 4.1)*

### V6.2 Asset value / criticality on nodes :x: `T3`
Topology nodes carry no value/criticality field.
> **Gap:** extend `fleet_topology_types.hpp` node with optional asset-value. *(Epic 4.1)*

---

## V7 — Attack-Path Analytics (CAVM core — the differentiator)
*All depend on V2 (threat data), V5 (join + persistence), V6 (asset value). Build in order.*

### V7.1 EUC edge typing (Foothold/LateralMovement/PrivEsc/DataAccess) :x: `T3`
Edges are *network scope*, not *exploit semantics*. CAVM weights (F=0.1…DA=0.3) have
nothing to attach to.
> **Gap:** add `EucClass` to the edge model + classification pass; optional host-firewall
> potential-reachability enrichment. *(Epic 5.1)*

### V7.2 Composite priority score (Annex C.5) :x: `T3`
The 0.30/0.25/0.25/0.20 weighting (asset / reachability / centrality / threat).
> **Gap:** `cavm/priority_score`. *(Epic 6.1)*

### V7.3 Crown-jewel reachability + chain centrality :x: `T3`
No graph walks for jewel reachability or node centrality.
> **Gap:** `cavm/reachability` over persisted topology. *(Epic 6.2)*

### V7.4 AMAPC (Average Minimum Attack-Path Complexity) :x: `T3`
The board-facing resilience metric: Dijkstra on inverse-exploitability × log₂(len),
`C_max` monotonicity ceiling. **Note:** Guardian's "resilience" is enforcement-retry
policy — unrelated; AMAPC does not exist today.
> **Gap:** `cavm/amapc`. *(Epic 6.3)*

### V7.5 Choke-point analysis :x: `T3`
Sequential min-cut layers; 1.5× secondary-chokepoint flag.
> **Gap:** `cavm/chokepoint`. *(Epic 6.4)*

### V7.6 Gate model (act_now/attend/monitor/track) :x: `T3`
Thresholds 0.90/0.70/0.60/0.50 + velocity-decay windows.
> **Gap:** `cavm/gates`. *(Epic 6.5)*

### V7.7 Visibility discount :large_orange_diamond: `T3`
Yuzu *tracks* enrollment/visibility state, but no score consumes it (CAVM: full=0.75…not_enrolled=0.6).
> **Gap:** feed existing visibility state into the gate model. *(Epic 6.5)*

---

## V8 — Operational Integration

### V8.1 SOC real-time rescoring :x: `T3`
No alert→edge-weight modulation (CAVM: PE×1.8, DA elevation). Yuzu *has* the events/SSE
bus + Guardian signals to feed this.
> **Gap:** event-bus subscriber modulating `priority_score`. *(Epic 7.1)*

### V8.2 Board metric / AMAPC trend reporting :x: `T3`
No Prometheus gauges or trend panel for AMAPC / score distribution.
> **Gap:** `yuzu_cavm_amapc` gauges + dashboard trend (observability-conventions). *(Epic 7.2)*

### V8.3 Remediation batching / governance gates :x: `T3`
No co-location batching or remediation-governance surface.
> **Gap:** defer until scoring is trusted. *(Epic 7.3)*

---

## Merge guidance (folding into `docs/capability-map.md`)

1. **§9.4 Vulnerability Scanning** — replace the single `:white_check_mark: T1` line. The
   floor is **not** done: the agent matcher is the defective PoC (V2.1), NVD ingest now does a
   full-catalog backfill but is not joined to plugin findings (V2.2/V2.3), OVAL/backport correlation is
   absent (V2.4), OSV.dev/language-ecosystem correlation is absent (V2.9), and finding status is
   still boolean rather than tri-state (V4.5). Downgrade §9.4 to `:large_orange_diamond:`. The
   "NVD database sync on server" claim is **accurate — keep it** (corrects the 2026-06-30
   draft, which wrongly called NVD unwired). Fold V1–V4 in as §9.4.x sub-rows.
2. **New domain §32 — Vulnerability & Attack-Path Management (CAVM)** — fold in V5–V8.
   V5 cross-references §28.7 (fleet viz) and §28.9; V7.4 (AMAPC) is the headline board metric.
3. **Tier mapping** — V-tiers already match the parent `T1/T2/T3` scheme; no remap needed.
4. **Accuracy note** — the parent map's headline % is known-overstated
   (memory `project_capability_map_accuracy.md`); when recomputing totals after merge,
   the vuln_scan additions move the denominator up by ~26 capabilities, only 5 done.
5. **Renumber** the device-table footer / domain count (parent currently tops out at §31).

## Reconciliation cadence

This map will drift as the matcher rebuild and CAVM scoring land. Update a V-row's status
**in the same PR** that changes its backing code (same rule as the parent map). Re-reconcile
against `docs/vuln-scan-engine-design.md` whenever a design-doc phase closes, and against
`docs/adr/00NN-*.md` whenever a vuln_scan ADR is amended or newly accepted.

**Reconciliation log:** 2026-07-01 — folded in ADR-0018 (D1 wire-format correction: typed
identity, not PURL; Lane 1/2/3 routing; KEV pre-filter exception struck) and ADR-0019
(tri-state finding status + coverage dimension). Added V2.9, V4.5.
`docs/vuln-scan-roadmap.md` reconciled in the same pass.
