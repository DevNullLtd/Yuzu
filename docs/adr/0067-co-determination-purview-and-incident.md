---
status: proposed
date: 2026-10-03
owner: Nathan Dornbrook
deciders: Nathan Dornbrook (project owner) — grilling session 2026-10-03; semantics fixed, mechanism to be designed; governance run PR #5367 (2026-10-04) folded
depends-on: ADR-1005 (one core-owned approval primitive), ADR-0033 §4 (approval — requester ≠ approver, distinct human roots, MFA step-up), ADR-0017 (confinement — orthogonal, named so the two are never conflated)
related: ADR-0068 (first consumer: network-element presence data), `docs/enterprise-readiness-soc2-first-customer.md` "Behavioral telemetry (DEX) — PII posture and works-council / co-determination" (the named roadmap gaps this partly closes), `server/core/src/rest_audit.hpp` (`emit_behavioral_audit` — the audit funnel the new gate sits in front of)
scope: platform — access control over individually-identifying reads; works-council / co-determination
tracking: PR #5367
---

# ADR-0067: Co-determination purview and the Incident — subject-level control over individually-identifying reads

> **Stub.** The *semantics* below were decided on 2026-10-03 and are binding on ADR-0068, which
> depends on them. The *mechanism* (store schema, the pre-read gate, the approval flow, incident
> lifecycle, export format, the deployment-default flag) is still to be designed; this ADR is
> `proposed` until that design is grilled and lands — see **Binding status**. The glossary entries
> **Purview** and **Incident** in `CONTEXT.md` restate these semantics; where the two differ,
> **this file governs**.

## Context

In jurisdictions with employee co-determination (Germany §87(1)(6) BetrVG; Austria; the
Netherlands; France; the Nordics) the works council's right is triggered by a system's
**capability** to monitor behaviour, not the operator's intent. Yuzu's posture today
(`docs/enterprise-readiness-soc2-first-customer.md`) is per-source collection toggles,
aggregate-by-default with a 10-device floor, and per-open audit of every individually-identifying
read through one funnel, `emit_behavioral_audit`. **No gate ever refuses an individual read to a
permitted role.** The same document names the gaps before an EU works-council deployment:
per-category collection toggles (fleet-wide and per-management-group), a kill switch for the
individual drill-down, a pseudonymisation mode, operator-set retention in the dashboard, a
dedicated `DEX:Read` securable, and a DSAR path.

The operating need is concrete: respond to security incidents in Germany, and read and write
unhindered in countries outside any works council's purview — with administrators, not code,
deciding which subjects are which.

## Decisions (semantics — fixed)

1. **Purview is an operator-declared marker on a subject.** For person-assigned devices it is
   declared on a **management group** (the unit the SOC 2 doc already names for per-group
   toggles). For a **network element** (ADR-0068) it is **derived** — in purview if its tables can
   reveal in-purview devices' presence — and admin-overridable. **Derivation is evaluated at read
   time against current group membership; there is no cached verdict**, so a device joining an
   in-purview group is covered on the next read.
2. **Purview follows the person, not the geography.** A German employee's laptop abroad stays in
   purview; a data-centre switch with only servers behind it is not. There is **no country flag**.
3. **In purview, an individually-identifying behavioural read is denied unless made under an
   Incident in the `approved` state.** Aggregate, floor-protected reads are unaffected.
4. **Out of purview, behaviour is today's**: permitted and per-open audited. Nothing changes for
   subjects nobody has declared.
5. **Default is out.** An undeclared subject is out of purview, preserving existing operators'
   drill-downs on upgrade. An **EU-wide deployment flips the deployment-wide default to in** via
   a deployment setting; in-by-default was weighed as the more privacy-protective posture and
   rejected only for upgrade breakage. **Until the flip ships, an EU co-determination deployment
   must not enable the ADR-0068 collector or any other new individually-identifying source**; the
   separately-deployed opt-in artifact is the collection off-switch (the SOC 2 doc's precedent).
6. **An Incident** is a declared, reasoned, **time-boxed** authorisation with a closed state
   machine — `requested → approved → closed | expired | denied` — in which **reads are admitted
   only in `approved`**; `incident.open` creates a `requested` Incident and admits nothing. It is
   opened with a justification (e.g. a ticket) by a holder of `Incident:Write`, **approved through
   the one
   core-owned approval primitive exactly as ADR-0033 §4 specifies — the approver holds
   `Incident:Approve`, requester ≠ approver as distinct human roots, with MFA step-up; there is
   no admin self-approval and no second approval gate** — stamping every read made under it with
   the incident id, closing on expiry or explicitly, after which the same reads are denied again.
   Its product is a complete, exportable account for the works council of what was read, by whom,
   and why. **The evidence is audit rows, each a named verb**: `incident.open` (justification),
   `incident.approve` / `incident.deny` (requester, approver, both human roots), `incident.close`,
   `incident.expire` (written by the gate at the first post-lapse evaluation or by a sweep,
   whichever comes first; the export derives expiry from `expires_at` regardless), `purview.set`
   and `network_element.purview.override` (every purview change — the element verb is ADR-0068's,
   one name), every stamped read (its own verb + `incident_id`), and every **denial** during the
   window. The export is
   generated from audit rows only, retained ≥ 365 days with the audit store, and its generation is
   itself an audit row carrying the export's content hash. **An unrecordable read is not made:**
   an audit-persist failure denies the read even under an Incident, and on an **audit-off**
   deployment (`audit_fn` absent, where the funnel's kernel returns `true` today) in-purview reads
   are refused outright and a purview declaration is itself refused — there is no Incident without
   evidence.
7. **Enforced by a pre-read, deny-capable decision in front of the single funnel.**
   `emit_behavioral_audit` (`rest_audit.hpp`) is an audit *wrapper*: it returns a persist bool,
   REST fails closed on it, the dashboard and MCP proceed by design, MCP wraps the kernel itself,
   and several sites audit *after* the read. It is therefore **not** the deny point. The gate is a
   new channel-agnostic decision (working name `authorize_behavioral_read`) called **before** the
   data is fetched on **all three channels** (REST, dashboard fragment, MCP), independent of
   audit-on/off, with the post-read audit sites re-sequenced to call it first. It is the ONE place
   — never per route, never a second list — and its gate set is derived from the funnel's callers
   (the SOC 2 doc's enumerated channels plus ADR-0068's two presence verbs). A read that cannot
   determine the subject's purview **fails closed for that subject only**: the undeterminable
   subject is denied, determinable subjects in the same call are unaffected, the omission is
   declared in the response (never an empty table), and the denial is counted and alerted.
8. **Orthogonal to Confinement, Scope and Trust zone.** Confinement decides *which operator may
   see which agents*; purview decides *what kind of read is permitted on a subject*. The two
   compose; neither substitutes for the other.

## Scenario of record

An incident responder in Warsaw opens an Incident on a ransomware alert, a second human approves
it, and the responder reads the process tree of a Düsseldorf laptop (in purview): permitted,
stamped with the incident id. A week later, Incident closed, the same responder wants to "just
check" that laptop: **denied**, and the denial is in the export. Same responder, same week, reads
a Warsaw laptop's process tree (out of purview): permitted, audited, no Incident needed.

## What this closes and what stays open (SOC 2 named gaps)

| Named gap | Status under this ADR |
|---|---|
| Kill switch for the individual drill-down | **Closed on acceptance + implementation of this ADR's mechanism, not before** — and as a *gate* (Incident-bypassable), not a kill switch; nothing is closed while this ADR is `proposed` |
| Per-category collection toggles (per management group) | **Related, not closed** — purview is declared per group but gates reads, not collection; ADR-0068's presence observations add a new per-category collection gap (no toggle), mitigated only by the opt-in collector |
| Pseudonymisation mode | **Open** |
| Operator-set retention in the dashboard | **Open** |
| Dedicated `DEX:Read` securable | **Open** |
| DSAR / per-subject erasure path | **Open** (ADR-0068 names its stores as erasure sources and an erasure verb; the subject-resolution path, including visitor MACs, is not this ADR) |
| Deployment-wide EU default flip (Decision 5) | **Open** — wholly undesigned, and the **precondition for any EU deployment**; until it ships, EU deployments must not enable new individually-identifying sources (ADR-0068's collector included) |
| Writes on in-purview subjects (remote control, screen capture classes) | **Open** — this ADR's first iteration gates reads only |

## Open (mechanism — to be designed)

- Purview store: a column on the management-group row vs a separate declaration table; the
  element derivation query (it needs ADR-0068's attachments query owner); the override's audit.
- **How a read binds to its Incident** — parameter, header, or session-scoped — and how the gate
  learns the binding before the fetch; the `requested → approved` transition's own audit and the
  sweep that writes `incident.expire`.
- Incident store and lifecycle; the `Incident` securable (`Write`, `Approve`, `Read`); maximum
  time box; renewal; what happens when the approver is deprovisioned (ADR-2001) or the time box
  lapses mid-request; export format and tamper-evidence beyond the content hash.
- The gate's exact signature and the re-sequencing of the post-read audit sites.
- Writes: whether in-purview *write* actions (remote control, screen capture classes) are also
  Incident-gated. The operating need says "unhindered read/write" *outside* purview; inside, the
  first iteration gates reads only.
- The deployment-default setting's name and whether it is flippable at runtime or boot-only.

## Binding status

**Not accepted by merge.** This ADR names an additional acceptance gate under
`docs/agents/domain.md`'s convention: it stays `proposed` until the mechanism above is designed,
grilled and landed, at which point `status` flips in that PR. Its **semantics** (Decisions 1–8)
are nonetheless binding on ADR-0068 from ADR-0068's acceptance, and ADR-0068's purview clauses
bind only once this ADR is accepted.
