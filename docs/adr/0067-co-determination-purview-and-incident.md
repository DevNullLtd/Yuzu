---
status: proposed
date: 2026-10-03
owner: Nathan Dornbrook
deciders: Nathan Dornbrook (project owner) — grilling session 2026-10-03; semantics fixed, mechanism to be designed
depends-on: ADR-1005 (one core-owned approval primitive), ADR-0017 (confinement — orthogonal, named so the two are never conflated)
related: ADR-0068 (first consumer: network-element presence data), `docs/enterprise-readiness-soc2-first-customer.md` "Behavioral telemetry (DEX) — PII posture and works-council / co-determination" (the named roadmap gaps this generalises), `rest_audit.hpp` (`emit_behavioral_audit`, the enforcement funnel)
scope: platform — access control over individually-identifying reads; works-council / co-determination
---

# ADR-0067: Co-determination purview and the Incident — subject-level control over individually-identifying reads

> **Stub.** The *semantics* below were decided on 2026-10-03 and are binding on ADR-0068, which
> depends on them. The *mechanism* (store schema, approval flow, incident lifecycle, export
> format, the deployment-default flag) is still to be designed; this ADR is `proposed` until that
> design is grilled and lands. The glossary entries **Purview** and **Incident** in `CONTEXT.md`
> are the canonical wording.

## Context

In jurisdictions with employee co-determination (Germany §87(1)(6) BetrVG; Austria; the
Netherlands; France; the Nordics) the works council's right is triggered by a system's
**capability** to monitor behaviour, not the operator's intent. Yuzu's posture today
(`docs/enterprise-readiness-soc2-first-customer.md`) is per-source collection toggles,
aggregate-by-default with a 10-device floor, and per-open audit of every individually-identifying
read through one funnel, `emit_behavioral_audit`. **No gate ever refuses an individual read to a
permitted role.** The same document names the gaps before an EU works-council deployment:
per-management-group toggles, a kill switch for the individual drill-down, pseudonymisation.

The operating need is concrete: respond to security incidents in Germany, and read and write
unhindered in countries outside any works council's purview — with administrators, not code,
deciding which subjects are which.

## Decisions (semantics — fixed)

1. **Purview is an operator-declared marker on a subject.** For person-assigned devices it is
   declared on a **management group** (the unit the SOC 2 doc already names for per-group
   toggles). For a **network element** (ADR-0068) it is **derived** — in purview if its tables can
   reveal in-purview devices' presence — and admin-overridable.
2. **Purview follows the person, not the geography.** A German employee's laptop abroad stays in
   purview; a data-centre switch with only servers behind it is not. There is **no country flag**.
3. **In purview, an individually-identifying behavioural read is denied unless made under an
   open Incident.** Aggregate, floor-protected reads are unaffected.
4. **Out of purview, behaviour is today's**: permitted and per-open audited. Nothing changes for
   subjects nobody has declared.
5. **Default is out.** An undeclared subject is out of purview, preserving existing operators'
   drill-downs on upgrade. An **EU-wide deployment flips the deployment-wide default to in** via
   a deployment setting; in-by-default was weighed as the more privacy-protective posture and
   rejected only for upgrade breakage.
6. **An Incident** is a declared, reasoned, **time-boxed** authorisation: opened with a
   justification (e.g. a ticket), approved through the **one core-owned approval primitive**
   (four-eyes or admin — ADR-1005 forbids a second approval gate), stamping every read made under
   it with the incident id, closing on expiry or explicitly, after which the same reads are denied
   again. Its product is a complete, exportable account for the works council of what was read,
   by whom, and why.
7. **Enforced at the single funnel.** The purview gate lives in `emit_behavioral_audit`
   (`rest_audit.hpp`), the chokepoint every individually-identifying read already passes through —
   never per route, never a second list. A read that cannot determine the subject's purview
   **fails closed** (denied), matching the funnel's existing fail-closed audit posture.
8. **Orthogonal to Confinement, Scope and Trust zone.** Confinement decides *which operator may
   see which agents*; purview decides *what kind of read is permitted on a subject*. The two
   compose; neither substitutes for the other.

## Scenario of record

An incident responder in Warsaw opens an Incident on a ransomware alert, reads the process tree of
a Düsseldorf laptop (in purview): permitted, stamped with the incident id. A week later, Incident
closed, the same responder wants to "just check" that laptop: **denied**. Same responder, same
week, reads a Warsaw laptop's process tree (out of purview): permitted, audited, no Incident
needed.

## Open (mechanism — to be designed)

- Purview store: a column on the management-group row vs a separate declaration table; the
  derivation rule for elements; the override's audit.
- Incident store and lifecycle; the approval flow through the core primitive; maximum time box;
  renewal; who may open vs approve; whether an Incident is itself an auditable securable.
- Which existing audit verbs are "individually-identifying behavioural" for gate purposes (the
  SOC 2 doc's enumerated channels: `dex.device.view`, `guardian.device.view`,
  `inventory.device.ci`, `sle.agent.view`, `device.live.*`, `app_usage.agent.view`, and ADR-0068's
  `network_element.state.view` / attachments) — derived from the funnel's callers, not re-listed.
- The works-council export format and retention.
- Writes: whether in-purview *write* actions (remote control, screen capture classes) are also
  Incident-gated. The operating need says "unhindered read/write" *outside* purview; inside, the
  first iteration gates reads only.
- The deployment-default setting's name and whether it is flippable at runtime or boot-only.
