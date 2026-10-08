---
status: proposed
date: 2026-06-22
owner: Alex Young
deciders: pending HITL review
sibling: docs/adr/0012-prediction-engine.md (the probabilistic reliability counterpart;
  shares routing/validation seams, not a core)
builds-on: docs/adr/0002-reachability-graph-data-model.md (host/service nodes, edge classes),
  docs/adr/0005-attack-path-and-chokepoint-scoring.md (attack paths; "local proposes, server confirms"),
  docs/adr/0001-observed-grounded-reachability.md (observed, not potential),
  docs/adr/0003-telemetry-capture-model.md (event-driven flow warehouse),
  docs/yuzu-guardian-design-v1.1.md (guards), docs/dex-signal-catalog.md (DEX security signals)
---

# 0013 — Attack-Chain Correlation: deterministic campaign-state reconstruction over the observed reachability graph

> **Implementation status:** greenfield proposal. The *sensors* ship today (Guardian guards, the
> DEX security signals, the event-driven flow warehouse, the observed reachability / attack-path
> engine of ADRs 0001/0002/0005); the TTP-mapping and chain-assembly layer described here is **not
> built**.

## Context

Yuzu already observes, in real time, most of the host-level actions an intrusion takes — Guardian's
registry / file / service guards (kernel-event-driven) and the DEX *security* signals
(`security.rtp_disabled`, `security.tamper_blocked`, `security.kerberos_error`, service-stop,
BitLocker errors, RDP-session and logon events). It also retains the network flows those intrusions
generate (ADR-0003's event-driven edge warehouse) and a graph of which hosts can actually reach
which services (ADR-0002, observed). What it does **not** do is *tag those observations as ATT&CK
techniques and assemble them into a campaign*.

The detection problem this addresses is not anomaly scoring and not a single-TTP alarm — both of
which are notoriously high false-positive (a stopped service fires benignly all day). It is the
**cyber-campaign-chain** problem: a real intrusion is a *nest of kill chains* across the phases
**Intrusion → Ransom → Staging → Extortion**, and the discriminator between a campaign and noise is
the **chain** — a sequence of techniques walking those phases, across hosts — not any technique in
isolation. *Early-stage* detection is everything before binary detonation (pre-Extortion); catching
a campaign at *Staging* rather than at *Extortion* is the difference between an isolated incident
and a fleet-wide encryption event.

This is a **deterministic correlation** problem (did this chain of observed techniques occur, in
this order, across these hosts), not a probabilistic forecast. It is therefore a *different feature*
from the reliability Prediction Engine (ADR-0012): different kernel (sequence/graph matching vs
regression), different compute location (cross-host server-side vs per-device edge), different data
and privacy posture (identity-bearing vs machine-health), and a different buyer (SecOps vs IT ops).
The two are deliberately decided separately. **This ADR deliberately does not call its output a
"forecast."** A speculative horizon-to-impact layer is recorded as a deferred option (§ Future),
not the headline — the durable, defensible value is the deterministic chain reconstruction.

## Decision

### 1. Guards + DEX security signals are the host-side TTP sensor grid

A mapping layer turns each guard fire / DEX security signal into an `observed_technique` fact
(ATT&CK technique ID + cyber-campaign-chain phase). Every signal below ships today; it is simply
untagged and unchained:

| Yuzu signal (live today) | ATT&CK | CCC phase |
|---|---|---|
| `security.rtp_disabled`, `security.tamper_blocked` | T1562.001 Impair Defenses | Staging |
| service guard: security service stopped | T1489 Service Stop | Staging / Extortion |
| registry guard on Run / persistence keys (the H1 denylist) | T1547 / T1112 | Intrusion / Persistence |
| `security.kerberos_error`, `logon.machine_trust_failed`, `security.auth_error` | T1558 / credential access | Ransom |
| `logon.no_dc`, `session.rdp_disconnected` | T1021 Remote Services | lateral movement |
| `network.port_exhaustion` / scan bursts | T1046 Service Discovery | Ransom |
| file guard: mass file ops, `security.bitlocker_error` | T1486 Data Encrypted for Impact | Extortion (terminal) |
| edge flow warehouse: upload/download ratio, sized / automated transfers | T1020 / T1030 / T1537 | Staging |

The full mapping is a catalogue artifact (its own reference doc), not seven rows; the table above
is illustrative. Two properties are load-bearing:

- **The flow warehouse is already the exfil/C2 feature substrate** the network-traffic detection
  literature is built on — the D3FEND Network-Traffic-Analysis family (per-host download/upload
  ratio, protocol-metadata anomaly, community deviation, DNS analysis) maps straight onto the
  retained flow summaries. No new collector is needed for the network half.
- **A guard going blind is itself a positive observation, not a gap.** An adversary disabling the
  Defender guard to evade us *is* T1562; the evasion is the detection. The mapping treats "an
  expected guard stopped reporting" as a high-signal technique, not a blind spot.

### 2. The chain is the false-positive control

A single `observed_technique` **never** raises a campaign — it is the chain that discriminates. The
correlator surfaces a campaign only when observed techniques form a **sequence walking the CCC
phases**, and it stays deliberately **narrow and high-precision**: model the chains that
discriminate *impact* (ransomware-shaped progressions), not generic TTP coverage. This is the
explicit antithesis of a SIEM detection-content treadmill — we are not trying to alert on every
technique, only to reconstruct the campaigns that matter.

### 3. Chain assembly is server-side, over the observed reachability graph

A single host walking up its *own* kill chain can be scored locally at the edge; but a campaign
spans hosts (lateral movement), so campaign-level assembly is **server-side over the observed
reachability graph (ADR-0002)** — the direct application of ADR-0005's "the local tripwire
proposes, the bounded propagation confirms." The host emits cheap, privacy-bounded
`observed_technique` facts; the server assembles per-host TTP timelines into a campaign, using the
graph's network-reachability and local-IPC edges to connect a chain *across* hosts (which is
precisely lateral-movement reconstruction).

**The attack-path engine supplies the map; the observed chain supplies the position on it.**
ADR-0005 already computes the most-probable forward path to a crown jewel (`w = -log P(traverse)`).
Overlaying the *observed* TTP chain onto that path locates where on a known attack path the
adversary actually is — "this host cluster is observed at *Staging* on a path whose forward
continuation reaches crown-jewel Y." That is the deterministic, defensible output; it is
`dex_blast_radius` generalised from "N devices failing independently" to "N devices on one
correlated kill chain."

### 4. A reconstructed campaign is a fact; remediation is operator-gated

A campaign is surfaced as a structured *fact* — the ordered observed-technique chain, the
per-phase position, the hosts and graph edges involved, and the evidence behind each link —
uniformly `info`, routed (not alerted) through the existing `dex_alert_router` /
`dex_blast_radius` / gauge seams (the **only** machinery shared with ADR-0012; reuse, not a shared
core). Remediation is **manual / operator-gated only** (a campaign may *propose* — isolate the host
cluster, kill the exfil flow, quarantine — but never auto-acts). The agentic closed-loop is a
separate track; the existing `quarantine` plugin and Guardian enforcement are the obvious
operator-driven response surfaces.

### 5. Validation against ground truth — sparse and adversary-controlled

Reconstructed campaigns and their per-link technique attributions are recorded and, where an
outcome is known (confirmed incident vs benign), scored for precision. Unlike the reliability
counterpart, security ground truth is **sparse and adversary-controlled**, so the validation gate
matters even more: a chain pattern is promoted from observe-only to operator-routed only when its
precision holds on real outcomes. The scoring ledger is a **new server store, born on Postgres**
(ADR-0006, its own schema); raw guard/DEX events and raw flows stay in their warehouses and are
never copied in.

### 6. Identity-bearing telemetry — a distinct authority/consent gate

This feature **inverts** the reliability engine's privacy posture. It needs identity / behavioural
signal (logons, RDP sessions, lateral movement) — the surveillance-*capability* escalation the
macOS-ESF note and the works-council posture warn about. Campaign data therefore sits behind a
**distinct authority/consent gate** (a security-team role + a separate documented legal basis),
**never** the general DEX lens. The same telemetry being privacy-sensitive for DEX yet necessary
for security is a first-class constraint, and is a primary reason this is a separate feature from
ADR-0012.

## Business value

- **Lead time before impact.** The whole value is mean-time-to-remediation: reconstructing a chain
  at *Staging* (pre-detonation) instead of discovering it at *Extortion* lets the defender act while
  the adversary is still moving — the difference between an isolated host and an encrypted fleet.
- **Low-false-positive by construction.** The chain-as-discriminator means operators get
  reconstructed campaigns, not a TTP alert firehose — directly attacking the alert-fatigue problem
  that sinks SIEM/EDR value.
- **Closes the loop incumbents leave open.** ATT&CK (observe) → D3FEND (countermeasure) → Guardian
  (enforce) / quarantine (respond), in one platform.
- **Differentiates against EDR/XDR** in the same fleet that already runs Yuzu for management —
  campaign reconstruction grounded in a reachability graph the defender owns, with no new agent.

## Competitive comparison

| Capability | CrowdStrike / Defender XDR / SentinelOne (EDR/XDR) | SIEM + detection content | **Yuzu Attack-Chain Correlation** |
|---|---|---|---|
| Campaign-*phase* reconstruction (position on the chain) | Incident "storylines"; not explicit CCC-phase position | Rule-by-rule alerts, analyst-stitched | **Explicit phase position over the reachability graph** |
| Grounding of cross-host correlation | Vendor telemetry silo | Log-source dependent | **Defender-owned observed reachability graph (ADR-0002)** |
| Host + network + topology in one model | Partial (host-strong) | Log-dependent | **Guard/DEX TTPs + flow + reachability, one engine** |
| False-positive posture | Tuned detections | Notoriously noisy | **Chain-as-discriminator; narrow, high-precision** |
| Detect → enforce / remediate | Detect + respond | Alert only | **ATT&CK → D3FEND → Guardian enforce / quarantine** |

The contribution over the network-only early-stage-detection literature (which works from flow
features alone) is **host TTPs + flow + cross-host reachability assembled into one campaign** — the
multi-stage, multi-host model that single-telemetry approaches cannot build. The wedge over EDR is
*campaign reconstruction grounded in an observed reachability graph the defender controls*, with
the response loop closed through Guardian.

## Options considered

- **Call it "forecasting" and fold into ADR-0012 (rejected).** The durable value is deterministic
  chain reconstruction; "forecasting" oversells it (adversary *velocity* is not a trustworthy
  quantity) and would couple it to an opposite privacy model and a different buyer. The shared
  routing/validation plumbing is reuse, not a reason to merge.
- **Ship a generic TTP alert stream (rejected).** Becomes a detection-content treadmill and a
  false-positive firehose; the chain-as-discriminator keeps us narrow and high-precision.
- **Edge-only assembly (rejected).** A single host cannot see lateral movement; campaign assembly
  must be server-side over the reachability graph.
- **Potential-reachability paths (rejected, per ADR-0001).** Chains are reconstructed over
  *observed* reachability only; a path policy permits but no host exercised is invisible — the
  accepted low-FP trade.

## Consequences

- **Positioning.** This nudges Yuzu from endpoint *management* toward *detection & response*.
  Guardian already straddles that line; this commits to it. A deliberate strategic choice, named
  here rather than drifted into.
- **New:** the guard/DEX → ATT&CK → CCC mapping catalogue; the `observed_technique` fact; the
  server-side chain assembler over the reachability graph; the attack-path overlay; the Postgres
  validation store; a campaign surface on the dashboard behind the security gate.
- **Reused:** the Guardian guards, the DEX security signals, the flow warehouse, the
  reachability/attack-path engines, `dex_blast_radius`, `dex_alert_router`, the gauge path, the
  `quarantine` plugin.
- **Invariant — a single technique never raises a campaign.** Only a chain across phases does.
- **Invariant — observed reachability only** (ADR-0001).
- **Invariant — identity-bearing data behind the security gate**, never the DEX lens (§6).
- **Adversarial robustness:** a guard going blind is a positive T1562 observation, not a blind
  spot.
- **Residual — ground truth is sparse and adversary-controlled** (§5); chain patterns stay
  observe-only until precision holds on real outcomes.
- **Residual — through-gateway identity is app-layer** (`gateway_observed_peer`) until the
  gRPC gateway-hop identity binding lands (ADR-0066, under #4722; QUIC was withdrawn); cross-host chains that traverse the gateway inherit that limitation.

## Future (deferred — recorded so they are not lost)

- **Horizon-to-impact estimation (the speculative layer, explicitly not v1).** Estimating *when* a
  reconstructed campaign reaches Extortion (remaining path-to-impact × observed adversary velocity)
  is the probabilistic layer this ADR deliberately withholds — adversary velocity is unreliable;
  ship the deterministic position first, add a horizon only once outcome data supports it.
- **Learned chain models** trained on §5 outcomes, to generalise beyond hand-curated
  ransomware-shaped chains.
- **Agentic consumption:** campaigns as MCP facts so an autonomous worker can propose gated
  containment.
- **External export** of reconstructed campaigns (STIX/MITRE-shaped) to a customer SIEM/SOAR.
