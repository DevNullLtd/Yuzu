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
**widened** to gather all of them in the same pass, as one report. There is exactly one
route by which software facts reach the platform's central record, and one route by which they
leave it for a reader. A new discovery capability added later is a new category folded into the
same one path — never a second path.

This also means every existing consumer of today's inventory — the current query, the current
per-device view — continues to work unmodified while the inventory underneath it grows. Nothing
is deprecated to make room for this; it is grown in place.

### Collection starts on each machine, on that machine's own clock

Collection is not dispatched by the server. It is a standing behaviour of the platform's own agent
on each machine: when the agent connects, it starts its collection routine, which keeps its own
local timetable of when the next pass is due. That timetable survives restarts and time spent
offline. A newly enrolled machine does its first full pass within minutes, so it appears in the
inventory the same day; after that it follows its group's settings (below). A machine that misses
its window — a laptop asleep overnight, say — catches up soon after it next comes online, spread
out per machine so that a building's worth of laptops powering on together does not arrive in one
burst.

The server's role is to publish each machine's collection settings and, when an operator asks, to
request an immediate pass. It never schedules or dispatches routine collection itself, and so
never depends on a machine being online at a particular instant.

### Every discovery mechanism runs and fails on its own

A pass runs several independent discovery mechanisms — one for registered applications, one for
installer records, one for platform-store packages, and so on. Each runs on its own terms:

- A failure, a timeout or an oversized result in one mechanism never stops the others from
  reporting.
- A mechanism that stops responding is given up on after its own time limit, and is not attempted
  again until it has recovered, so one stuck mechanism cannot pile work up on the machine.
- Mechanisms run at most two at a time; the heaviest — verifying the integrity of installed
  programs — always runs last, on its own.
- When a mechanism cannot report cleanly, its last-known data is kept, never wiped, so a passing
  failure never looks like software being uninstalled. That data carries the time it was last
  confirmed, and once it has gone unconfirmed for three missed cycles or 24 hours, whichever is
  longer, it is marked unconfirmed everywhere it appears.
- Where a mechanism has never run on a machine, the inventory says so explicitly — "not
  collected" — rather than showing an empty field that could be read as "nothing installed".

Registered-applications collection is the backbone of the inventory and cannot be switched off
for an individual group.

### Report what changed, not the whole picture every time

A host reports its full software picture once, the first time it is seen. After that, on each
pass, it reports nothing at all if nothing has changed, and reports only the specific
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

### Collection settings belong to management groups

How often machines collect, in which window, and which discovery mechanisms are switched on is set
per management group, not once for the whole fleet:

- **Inheritance.** A group without its own settings inherits its parent's; the root of the group
  tree holds the fleet-wide default. A machine that belongs to groups on different branches takes
  its settings from the highest-priority of those groups. Priorities are set only by fleet
  administrators; groups without one rank lowest, and ties resolve the same way every time — the
  more specific group first, then the older. Every machine's effective settings, and the group
  they came from, are visible in the operator interface and the API.
- **Authority.** An administrator of a group may change the settings of that group and the groups
  beneath it, and no others. Only fleet administrators change the fleet-wide default. Every change
  is recorded with its before and after values. A mechanism's existing emergency kill switch
  overrides any group's settings.
- **Bounds.** The interval is between one hour and seven days. A time window can be set only for
  daily-or-longer intervals, and is read in each machine's local time unless the group pins a
  specific timezone — useful for machines whose clocks run on UTC while serving a local business.
  Settings that contradict themselves are refused when saved, so no machine ever receives an
  impossible instruction.
- **Default.** Once a day, inside an overnight window of 01:00–05:00 local time, with every
  lightweight mechanism on and integrity verification off until it has been proven within its
  resource budget on real hardware.
- **Delivery.** Settings reach machines durably: a machine that was offline when its settings
  changed picks them up when it next reconnects. A change takes effect at each machine's next
  pass. Saving settings never itself triggers collection — otherwise one fleet-wide change would
  become one unpaced, fleet-wide collection.

The settings live alongside the inventory itself, on the platform's software page, with the same
controls available through the API.

### Read access: paged, incremental, and exportable — nothing pushed out

The consolidated inventory is available to read in three ways, matching how downstream systems
typically want it: a filtered, pageable list for interactive or scripted queries; an incremental
feed of what changed since a given point, for a system that wants to stay in sync without
re-pulling everything; and a bulk export for an initial load, a periodic reconciliation, or simply
handing a report to someone without API access. The export is offered in four formats — JSON and
CSV for another system or a script to consume, a spreadsheet format (XLSX) for someone working
with the data directly, and a formatted document (PDF) for a report meant to be read rather than
processed — and every one of them is available equally through the operator interface and through
the API; a format offered in one is offered in the other, never an interface-only convenience. All
three read paths are pull — something reads from this platform on its own schedule. This platform
does not push software-inventory data out to another system on its own initiative. That remains a
deliberate boundary; see Non-goals.

Every entry is exported with its status — current, unconfirmed, or from a switched-off mechanism —
and the time it was last confirmed; per machine, a mechanism that has never run shows as "not
collected". Nothing drops out of the feed merely because it has gone unconfirmed, so a consumer
that treats absence as removal never mistakes a stale entry for an uninstall. A consumer that
wants only current entries can filter for them.

### An operator can force a check — paced, and gated by who is asking

Waiting for the next scheduled pass is not always acceptable — an operator investigating an
incident, or verifying a rollout, needs current data now. Any administrator may ask for an
immediate pass across machines they administer: a selection narrowed with the fleet's own search
and filter tools, or an entire group they administer. Only fleet administrators may ask for the
whole fleet. Checking an entire group, or the entire fleet, requires an explicit confirmation —
never a default, and never an empty filter silently meaning "everything" — and is recorded as the
larger action it is.

There is no ceiling on how many machines one check may cover. Instead, every on-demand check is
paced: machines report back spread out over time, under one platform-wide rate set from the
platform's measured capacity rather than by an administrator, so several checks running at once
share that capacity instead of stacking load. Before a check starts, the operator sees how many
machines it covers and roughly how long results will take. Each group has at most one check
running at a time — a repeated request joins the one already running — while checks on different
groups run side by side.

An on-demand check always runs every mechanism switched on for those machines. A question about a
single mechanism — "did this runtime update land?" — is answered by running that mechanism
directly as an ordinary instruction, which returns its answer to the operator but never alters
the inventory. That is what the mechanisms exist independently for.

### Visibility into what collection costs and where it fails

Every machine's report states, for each mechanism, whether it succeeded, how long it took and how
much it read. The platform turns that into fleet-wide health — for each mechanism, the share of
machines where it is timing out, unconfirmed or switched off — with alerting, and shows which
machines are slowest for each mechanism. Collection cost on the fleet is something an operator can
see, not something discovered when users complain.

### Everything here stays inside the core platform

This capability is built as part of the platform's core, in the same place today's inventory
already lives — not as a separate, independently-deployed module. Nothing in this decision assumes
or requires such a module to exist, now or later.

## What the dataset looks like

Every row below is gathered in the same single pass described above, from the same host, and
lands in the same consolidated record. "Collected" is how often the platform learns about it;
"Stored" is where a reader finds it today.

| Data captured | How it's found | Windows | macOS | Linux | Collected | Stored |
|---|---|:---:|:---:|:---:|---|---|
| Registered applications (name, publisher, version, install date) | Read from the operating system's own record of installed software | ✅ | ✅ | ✅ | Per group (default daily, overnight); changes only | Fleet software inventory |
| Installer package records (product identifier, install location, how to uninstall) | Read from the operating system's installer subsystem | ✅ | — | — | Per group (default daily, overnight); changes only | Fleet software inventory |
| Platform-store packaged applications | Read from the operating system's own app-package registry | ✅ | — | — | Per group (default daily, overnight); changes only | Fleet software inventory |
| Alternate package-manager installs (e.g. a secondary Windows package manager, a macOS community package manager) | Read from each package manager's own installed-package listing | ✅ | ✅ | — | Per group (default daily, overnight); changes only | Fleet software inventory |
| Containerised/sandboxed application formats (Linux) | Read from each format's own installed-application listing | — | — | ✅ | Per group (default daily, overnight); changes only | Fleet software inventory |
| Language and application runtimes (e.g. a managed-runtime framework, a Java runtime) | Read from each runtime's own installation record | ✅ | ✅ | ✅ | Per group (default daily, overnight); changes only | Fleet software inventory |
| Device drivers | Read from the operating system's own driver registry | ✅ | — | ✅ | Per group (default daily, overnight); changes only | Fleet software inventory |
| Optional operating-system feature set (Windows) | Read from the operating system's own feature-management interface | ✅ | — | — | Per group (default daily, overnight); changes only | Fleet software inventory |
| Integrity evidence (publisher's digital signature, a content fingerprint of the installed binary where one can be resolved without searching the filesystem) | Verified against the operating system's own signing mechanism | ✅ | ✅ | Partial | Per group, off by default until proven; changes only | Fleet software inventory |
| Change history (install / upgrade / removal, with a timestamp) | Derived by the platform itself, by comparing each day's report to the last | ✅ | ✅ | ✅ | Continuous, as detected | Fleet software change record (bounded retention) |
| Normalised identity (a common product/vendor/version reading, mapped from the raw values above) | Matched by the platform against its own maintained reference list | ✅ | ✅ | ✅ | Recomputed periodically | Fleet software inventory |

Two things are deliberately out of this table because they are out of scope for this decision:
per-user software (a user's own, non-machine-wide installs) and anything that requires searching
the filesystem rather than reading a known operating-system record. Both are addressed in
Non-goals.

### A worked example

The table below is not a schema — it is what an entry looks like once collected, consolidated,
and normalised, shown with representative, made-up values rather than a real fleet's data.

| Host | Product | Publisher | Version | Discovered by | First seen | Last confirmed | Status |
|---|---|---|---|---|---|---|---|
| WKS-LDN-0231 | 7-Zip | Igor Pavlov | 23.01 | Registered-application record + installer package record (both agree) | 2026-03-11 | 2026-09-28 | Current |
| WKS-LDN-0231 | Slack | Slack Technologies | 4.39.2 | Platform-store package record | 2026-06-02 | 2026-09-28 | Current |
| WKS-BER-1042 | Visual Studio Code | Microsoft | 1.94.1 | Alternate package-manager record | 2026-01-14 | 2026-09-24 | Unconfirmed |
| SRV-DB-07 | PostgreSQL client tools | PostgreSQL Global Development Group | 16.4 | Registered-application record | 2025-11-30 | 2026-09-28 | Current |
| WKS-LDN-0231 | .NET Runtime | Microsoft | 8.0.8 | Runtime installation record | 2026-02-20 | 2026-09-28 | Current |

WKS-BER-1042's package-manager mechanism has not reported cleanly since 2026-09-24, so its last
known entry is kept but marked unconfirmed rather than removed. Per machine, a mechanism that has
never run shows plainly — for example, *SRV-DB-07 — integrity verification: not collected* (off by
default). A corresponding change-history entry for the same fleet might read: *WKS-LDN-0231 — 7-Zip upgraded
from 22.01 to 23.01 — 2026-07-04.* An export in any of the four formats above carries the same
information as this table, shaped for its own use — JSON and CSV as machine-readable rows, XLSX as
a workbook, PDF as a formatted report.

## Timing and delivery model

- **Collection cadence:** set per management group (see Decision). By default once a day inside
  an overnight window of 01:00–05:00 machine-local time, each machine at its own point within the
  window so the fleet never reports in one burst. A new machine collects within minutes of
  enrolling; a machine that misses its window catches up soon after it next comes online, spread
  out per machine.
- **What's sent:** nothing, if nothing changed since the last report; only the specific
  differences, if something did; a complete picture only the first time a host is seen, or if the
  platform and the host ever need to re-synchronise.
- **On-demand check:** available at any time to administrators over the machines they administer
  (a filtered selection or a whole group), and to fleet administrators over the whole fleet. No
  size ceiling: every check is paced under one platform-wide rate; whole-group and whole-fleet
  checks need explicit confirmation; each group has at most one check running at a time.
- **When a mechanism can't report:** its last-known data stays, marked with the time it was last
  confirmed, and is flagged unconfirmed after three missed cycles or 24 hours, whichever is
  longer.
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
platform needing to know anything about that tooling. One broken or stuck discovery mechanism
degrades only its own slice of the picture, visibly, instead of silently taking the whole
inventory down with it. Each group of machines can be collected on a rhythm that suits it, set by
the people who run those machines, within bounds and under a default the fleet's administrators
control, and any administrator can refresh exactly the machines they are responsible for, at a
pace the platform can absorb. And whoever consumes the
result — a person or another system — can have it in whichever of the four formats already fits
their own workflow, from either the interface or the API.

**What this costs, or defers, deliberately (non-goals of this decision):**

- **Per-user software.** Only software visible at the machine level is in scope. Software
  installed for a single user account, rather than for the machine as a whole, is not collected by
  this decision; it depends on user-level access work this platform has not yet built, and is
  explicitly left for later.
- **Compliance interpretation.** This decision produces facts — what is installed, where, and how
  it was found. It does not score those facts for license compliance or policy violation. Other
  capabilities, existing or future, can consume the identity this inventory now provides, but this
  decision does not build or extend them.
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
- **The server dispatching a scheduled instruction for each discovery mechanism.** Considered in
  depth and rejected. A server-dispatched schedule reaches only machines that happen to be online
  at the moment it fires; a laptop asleep at that moment simply misses the run, with no catch-up.
  Each mechanism would need its own schedule, every run would return its full output rather than
  just what changed, and the results would land in a store built to hold transient command
  responses rather than a system of record. Collection that starts on the machine, on the
  machine's own clock, avoids all four problems while keeping each mechanism independent.
- **Pushing this inventory out to other systems as an integration.** Rejected for now: it makes
  this platform responsible for authenticating to, and staying compatible with, an unbounded set
  of external systems it does not control. A pull-only read surface puts that integration
  responsibility where it belongs — with the system doing the integrating — and can be revisited
  later if a genuine need for an outward push is demonstrated.
- **Continuous, real-time collection instead of daily-plus-on-demand.** Rejected for this phase:
  the operational cost of continuous collection across an entire fleet is substantial, and nothing
  in the stated need — an accurate, current, on-request-checkable inventory — requires
  sub-daily latency. The daily-plus-on-demand model meets the need at a fraction of the cost, and
  the on-demand check exists precisely for the cases where "as of this morning" genuinely isn't
  good enough.
- **Building per-user visibility, or compliance interpretation, into this same decision.**
  Deferred, not rejected: both are real future needs, but bundling them here would make this
  decision depend on work, such as user-level machine access, that does not exist yet. Keeping
  this decision to machine-level facts lets it ship on its own and lets other capabilities consume
  it later without having shaped it prematurely.

## Where the detail lives

This record intentionally stops at the level an architect needs to sign off on the shape of the
capability. The execution detail — the exact data model, the wire protocol between a host and the
platform, the migration sequence, and the sequenced list of engineering work — lives in the
delivery roadmap for this programme, maintained alongside the team's other programme roadmaps.
Nothing in that roadmap may contradict this record without a dated amendment to it.
