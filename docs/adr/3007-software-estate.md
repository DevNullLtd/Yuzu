---
status: proposed
date: 2026-09-28
owner: "@Doomgoose (Alex Young)"
deciders: "@Doomgoose (author)"
scope: platform — fleet-wide software inventory, consolidation, and read access
builds-on: ADR-0016 (agent daily-sync framework), ADR-0004 (current state central, history at the edge), ADR-0006/0007 (Postgres-only server substrate), ADR-1005 (headless platform, core owns mechanism)
related: []
context-refs: []
---

# 3007 — Software Estate: a single, complete record of installed software

## Context

An operator managing a fleet through this platform needs one question answered reliably: *what
software is actually installed, where, and how do we know?* Today that question is answered
poorly. The platform collects installed-application data once a day from a single mechanism per
operating system, keeps only the current snapshot with no record of what changed or when, applies
no consistent naming across publishers and versions, and exposes the result through a query
capped at a thousand rows with no way to page further. Several classes of software present on a
managed fleet — packaged applications distributed through a platform store, software installed
through alternate package managers, language runtimes, device drivers — are invisible to it
entirely.

This is no longer sufficient. The fleet's software inventory needs to be complete across the
operating systems this platform manages, trustworthy enough that each entry states how it was
found, current enough that an operator can force an immediate check on a chosen group of
machines, and open enough that an organisation's own configuration-management or IT
service-management tooling can pull it in on its own terms, at its own scale, without bespoke
integration work on either side.

This decision record sets the shape that inventory takes. It does not specify how any of it is
built — that is the accompanying delivery roadmap's job. It specifies what changes for an operator
and an architect: what is collected, how often, by what single path, and where it can be read
from.

## Decision

### One collection path, expanded, not duplicated

The platform already collects installed-application data once a day through a standing
mechanism built for exactly this purpose. Rather than stand up a second, parallel collection
system for the additional software categories this decision adds, that existing mechanism is
**widened** to gather all of them in the same daily pass, as one report. There is exactly one
route by which software facts reach the platform's central record, and one route by which they
leave it for a reader. A new discovery capability added later is a new category folded into the
same one path — never a second path.

This also means every existing consumer of today's inventory — the current query, the current
per-device view — continues to work unmodified while the inventory underneath it grows. Nothing
is deprecated to make room for this; it is grown in place.

### Report what changed, not the whole picture every time

A host reports its full software picture once, the first time it is seen. After that, on each
daily pass, it reports nothing at all if nothing has changed, and reports only the specific
additions and removals when something has. The platform verifies, on its side, that what it holds
for a host and what the host believes it last confirmed still agree; any disagreement triggers one
full resend to re-synchronise, automatically, without operator involvement. The fleet is not
asked to re-transmit its entire software picture every day merely to prove nothing moved.

### One row per installed item, however it was found

A single application can be visible to more than one collection mechanism on the same host — an
install-tracking record, a platform-store package record, an alternate package manager's own
record. These are consolidated into one entry per distinct piece of software per host, and that
entry lists every mechanism that reported it. Nothing is silently dropped in the consolidation:
each contributing observation is retained as that entry's evidence trail.

### A record of change, not just a snapshot

Alongside the current picture, the platform now keeps a bounded history of installs, upgrades,
and removals as they are detected — with a fixed retention window, not an unbounded log. An
operator or an integration can ask "what changed on this fleet in the last week" and get a direct
answer, rather than having to infer it by diffing two snapshots themselves.

### A common name for the same software everywhere

Software titles and publisher names arrive from the operating system exactly as that operating
system happens to record them, which varies host to host and platform to platform for what is
recognisably the same product. This decision introduces a normalisation step that reconciles
those variations against an open, versioned reference list the platform maintains and an operator
can extend, so that "the same software" reads as the same software across the fleet regardless of
which host or which operating system reported it. Coverage is measured, not assumed: entries that
cannot yet be matched are visible as such, not hidden.

### Read access: paged, incremental, and exportable — nothing pushed out

The consolidated inventory is available to read in three ways, matching how downstream systems
typically want it: a filtered, pageable list for interactive or scripted queries; an incremental
feed of what changed since a given point, for a system that wants to stay in sync without
re-pulling everything; and a bulk export for an initial load or periodic reconciliation. All three
are pull — something reads from this platform on its own schedule. This platform does not push
software-inventory data out to another system on its own initiative. That remains a deliberate
boundary; see Non-goals.

### An operator can force a check — of a chosen group, never the whole fleet unbounded

Waiting for the next scheduled daily pass is not always acceptable — an operator investigating an
incident, or verifying a rollout, needs current data now. This decision adds that capability, but
only as a check against the fleet's own search and filter tools: an operator narrows to a group of
machines first — by tag, by hostname pattern, by operating system, by how long since they last
reported — and only that narrowed, bounded group can be told to check in immediately. There is no
control anywhere in the platform that re-checks the entire fleet on demand with no bound. This is
a deliberate design constraint, not an oversight: an unbounded "check everything now" control is
an availability risk against the fleet's own endpoints and the platform's own capacity, and this
decision closes that off structurally rather than relying on operator discipline.

### Everything here stays inside the core platform

This capability is built as part of the platform's core, in the same place today's inventory
already lives — not as a separate, independently-deployed module. Nothing in this decision assumes
or requires such a module to exist, now or later.

## What the dataset looks like

Every row below is collected in the same single daily pass described above, from the same host,
and lands in the same consolidated record. "Collected" is the cadence at which the platform
learns about it; "Stored" is where a reader finds it today.

| Data captured | How it's found | Windows | macOS | Linux | Collected | Stored |
|---|---|:---:|:---:|:---:|---|---|
| Registered applications (name, publisher, version, install date) | Read from the operating system's own record of installed software | ✅ | ✅ | ✅ | Daily, changes only | Fleet software inventory |
| Installer package records (product identifier, install location, how to uninstall) | Read from the operating system's installer subsystem | ✅ | — | — | Daily, changes only | Fleet software inventory |
| Platform-store packaged applications | Read from the operating system's own app-package registry | ✅ | — | — | Daily, changes only | Fleet software inventory |
| Alternate package-manager installs (e.g. a secondary Windows package manager, a macOS community package manager) | Read from each package manager's own installed-package listing | ✅ | ✅ | — | Daily, changes only | Fleet software inventory |
| Containerised/sandboxed application formats (Linux) | Read from each format's own installed-application listing | — | — | ✅ | Daily, changes only | Fleet software inventory |
| Language and application runtimes (e.g. a managed-runtime framework, a Java runtime) | Read from each runtime's own installation record | ✅ | ✅ | ✅ | Daily, changes only | Fleet software inventory |
| Device drivers | Read from the operating system's own driver registry | ✅ | — | ✅ | Daily, changes only | Fleet software inventory |
| Optional operating-system feature set (Windows) | Read from the operating system's own feature-management interface | ✅ | — | — | Daily, changes only | Fleet software inventory |
| Integrity evidence (publisher's digital signature, a content fingerprint of the installed binary where one can be resolved without searching the filesystem) | Verified against the operating system's own signing mechanism | ✅ | ✅ | Partial | Daily, changes only | Fleet software inventory |
| Change history (install / upgrade / removal, with a timestamp) | Derived by the platform itself, by comparing each day's report to the last | ✅ | ✅ | ✅ | Continuous, as detected | Fleet software change record (bounded retention) |
| Normalised identity (a common product/vendor/version reading, mapped from the raw values above) | Matched by the platform against its own maintained reference list | ✅ | ✅ | ✅ | Recomputed periodically | Fleet software inventory |

Two things are deliberately out of this table because they are out of scope for this decision:
per-user software (a user's own, non-machine-wide installs) and anything that requires searching
the filesystem rather than reading a known operating-system record. Both are addressed in
Non-goals.

## Timing and delivery model

- **Collection cadence:** once per managed host per day, spread across the day rather than all at
  once, so the fleet does not report in a single burst.
- **What's sent:** nothing, if nothing changed since the last report; only the specific
  differences, if something did; a complete picture only the first time a host is seen, or if the
  platform and the host ever need to re-synchronise.
- **On-demand check:** available at any time, against an operator-chosen, bounded group of hosts
  only — never the unbounded fleet — with a fixed ceiling on how large that group may be in one
  request, and a short cooldown between requests so the mechanism cannot be used to repeatedly
  overload the fleet.
- **Change visibility:** a detected change is reflected in the platform's change record within the
  same reporting cycle that surfaced it; there is no separate, faster path for change events.
- **No continuous stream:** this is a periodic-plus-on-demand model, not a continuous real-time
  feed. A live stream of every install and removal as it happens is not something this decision
  builds; see Non-goals.

## Consequences

**What this buys.** One inventory, grown from what already exists rather than built again beside
it. Every existing reader of today's inventory keeps working. A new software category is future
work added to the same pass, not a new integration point. An organisation's own tooling can treat
this platform as a dependable, poll-on-its-own-schedule source of software truth, without this
platform needing to know anything about that tooling.

**What this costs, or defers, deliberately (non-goals of this decision):**

- **Per-user software.** Only software visible at the machine level is in scope. Software
  installed for a single user account, rather than for the machine as a whole, is not collected by
  this decision; it depends on user-level access work this platform has not yet built, and is
  explicitly left for later.
- **Risk and compliance interpretation.** This decision produces facts — what is installed, where,
  and how it was found. It does not score those facts for vulnerability, license compliance, or
  policy violation. Those are separate, existing or future capabilities that can consume the
  identity this inventory now provides, but this decision does not build or extend them.
  Correspondingly, nothing in this decision touches this platform's existing vulnerability-related
  capabilities.
- **Outward-pushing integrations.** This platform is read from; it does not write to another
  system on its own initiative. A connector that actively pushes this inventory into a third-party
  system is not part of this decision and would be a separate, later one if ever pursued.
  Everything here is pull-only.
- **Real-time streaming.** The periodic-plus-on-demand model above is the whole delivery
  model. A continuously streaming feed of every change as it happens is not built here.
- **A visibility system that reaches machines this platform does not already manage,** or software
  running inside containers, virtual machines, or cloud services rather than directly on a managed
  host. Those are larger, separate undertakings and are explicitly out of scope for this decision.

**A data-handling note.** Some of the data this decision collects — specifically, where a piece of
software is installed on disk — can occasionally include a local account name as part of a file
path. This has been considered and is not treated as sensitive, personally-identifying data in
this context: it identifies a location on a single managed machine, not a person, and no handling
beyond what already applies to machine-level inventory data applies to it.

## Alternatives considered

- **A second, independent inventory system, run alongside today's.** Rejected: it would mean two
  places holding overlapping software facts, two things to keep consistent, and no clean way to
  retire the old one without breaking its existing readers. Growing the one that exists avoids
  all of that.
- **Pushing this inventory out to other systems as an integration.** Rejected for now: it makes
  this platform responsible for authenticating to, and staying compatible with, an unbounded set
  of external systems it does not control. A pull-only read surface puts that integration
  responsibility where it belongs — with the system doing the integrating — and can be revisited
  later if a genuine need for an outward push is demonstrated.
  \- **Continuous, real-time collection instead of daily-plus-on-demand.** Rejected for this phase:
  the operational cost of continuous collection across an entire fleet is substantial, and nothing
  in the stated need — an accurate, current, on-request-checkable inventory — requires
  sub-daily latency. The daily-plus-on-demand model meets the need at a fraction of the cost, and
  the on-demand check exists precisely for the cases where "as of this morning" genuinely isn't
  good enough.
- **Building per-user visibility, or risk/compliance interpretation, into this same decision.**
  Deferred, not rejected: both are real future needs, but bundling them here would make this
  decision depend on work — user-level machine access, a risk-scoring capability — that either
  does not exist yet or belongs to a different, already-established part of this platform. Keeping
  this decision to machine-level facts lets it ship on its own and lets those other capabilities
  consume it later without having shaped it prematurely.

## Where the detail lives

This record intentionally stops at the level an architect needs to sign off on the shape of the
capability. The execution detail — the exact data model, the wire protocol between a host and the
platform, the migration sequence, and the sequenced list of engineering work — lives in the
delivery roadmap for this programme, maintained alongside the team's other programme roadmaps.
Nothing in that roadmap may contradict this record without a dated amendment to it.
