---
status: proposed
date: 2026-10-06
owner: "@Doomgoose (Alex Young)"
deciders: >-
  @Doomgoose (author and product owner for this decision). To be ratified by PR approval from
  the engineering colleagues under the dev-branch protection rule (at least one non-author
  approval).
effective: >-
  Binding on merge as the direction for every change to what DEX measures about applications
  and hardware, how those measurements are identified, summarised, trended and read, and which
  surfaces carry them. Nothing in the product changes on merge: the signals, views and read
  surfaces that exist today stay as they are until the work that extends them lands, and that
  work is sequenced in a separate roadmap.
scope: >-
  agent and server — the DEX lens over the applications and hardware on managed endpoints: the
  measurements it holds, the identity those measurements are keyed on, the summary figures
  computed from them, the permissions that read them, and the surfaces (dashboard, REST, and
  later MCP) that carry them
builds-on: >-
  ADR-0016 (agent daily-sync framework), ADR-1005 (no capability reachable only through the
  dashboard, and its boundary between mechanism and interpretation), the Guardian event design
  (whose ruleless observation path carries DEX signals), the DEX signal catalogue
amends: >-
  The capability map's statement (section 32.7) that composite experience scoring is
  deliberately not implemented and that the product positions evidence rather than scores.
  This ADR changes that position: a transparent composite is permitted alongside measured
  rates, while opaque and sentiment-based scoring stay out. For usage aggregates it also
  supersedes the statement in the authorization model and the permission documents that usage
  is reachable only through the administrator-only forensic surface (D9).
related: ["0017-management-group-confinement-list-reads", "3003-user-session-helper"]
context-refs: ["#1351", "#1355", "#1706", "#1766", "#2659", "#2744", "#4035", "#4489", "#4512", "#4513", "#4909", "#5059", "#5090"]
---

# 3008 — Application and hardware performance in DEX

## Summary

DEX (Digital Employee Experience) already watches what the workforce's applications and devices
do on the endpoint. It records crashes, hangs, blue screens, unexpected shutdowns, slow boots,
failing disks and throttled processors, and it keeps how much processor and memory each
application version uses, day by day. What it does not yet do is answer the questions an
end-user-services team asks of that evidence: which applications are unstable and since which
version; which hardware models crash, fail or start slowly; whether last week's rollout made
things better or worse; and how heavily each application is used.

This ADR makes DEX that answer. It is one lens over applications and hardware, in the DEX area of
the dashboard, with the same figures available through the REST API in the same change and
through MCP later. These points carry the direction:

- Everything measured is a DEX signal or a DEX series. Applications and hardware travel the same
  path, and nothing DEX can observe itself is measured by a new plugin.
- Measured rates lead. A transparent stability score summarises them, and it is one concept
  applied to two subjects: an application version and a hardware model.
- An application is identified by its image and version, and a hardware model by an
  operator-declared tag. Both are compared the same way: one against another.
- Every figure is over the devices that report it, and what is not collected is shown as not
  collected. A figure that cannot be computed says so.
- New measurements arrive on Windows first, with the gaps on other operating systems stated and
  never hidden.
- Blue screens, power losses and unexpected shutdowns are counted once and trended, and the agent
  reads what the operating system wrote while it was not listening.
- Usage means how long and how often an application runs; focus time is a separate decision.
  Fleet and management-group usage figures become readable at the DEX permission, which more
  roles hold than the forensic permission, and per-device usage keeps its forensic gate.
- A browser is an application like any other. What happens inside it is outside this capability.

This ADR records the direction and the reasons. It does not contain a schema, a protocol, a
screen design or a delivery plan; those belong to the roadmap that follows it.

## Context

### Where we are

DEX is a read-only lens over what endpoints report about themselves.

- **Signals.** The agent watches each operating system's own event sources and reports typed
  observations as they happen: more than a hundred signal types in thirteen families. They cover
  application crashes and hangs, service failures, blue screens and kernel panics, unexpected
  shutdowns, boot, shutdown and resume timing, logon problems, and disk, memory, battery, graphics
  and processor faults, as well as network and printing problems. Windows collects the whole
  catalogue; Linux and macOS collect a smaller subset. A new signal needs no new transport.
  Capture is forward-only: records the operating system wrote before the agent's observer armed,
  such as the blue-screen, power-loss and dirty-shutdown records written during boot, are not
  back-filled, and an observation raised while the agent cannot reach the server is dropped, not
  held.
- **Series.** Where per-application sampling is switched on, which it is not by default, the
  agent reports each day how much processor and working-set memory the heaviest applications on
  the device used, by image name and version. The server keeps it per device for about a month
  and rolled up across the fleet for about half a year. It exists for Windows and Linux, but only
  Windows resolves a version: every Linux row falls into an unknown-version bucket. macOS has no
  per-process source yet, and the fleet rollup carries no operating-system dimension (#4512).
- **Usage.** The agent's on-device history records how long and how often each executable ran, by
  executable name with no version, from the moment collection starts and for the retained window
  only. A separate plugin reads it. The agent syncs a trailing thirty-day summary each day and
  the server replaces the last one. It is read one device at a time under the forensic
  permission, with an audit record for each read. Nothing in the product measures how long an
  application has the user's focus; that is the subject of its own open decision.
- **Views.** The DEX area has eight views: Overview, Apps, Catalogue, Health score, Trends,
  Performance, App Performance and Network. Each has a REST twin and MCP tools. The Health score
  view leads with a measured rate and shows a composite beneath it, with its decomposition. The
  Overview opens with an Experience block of scores (an overall figure with device, application
  and network sub-scores) above its measured reliability tiles. Application-performance trend
  points over too few devices show a count only; the signal views apply no floor today.

The gaps, as the evidence stands today:

- Crash and hang counts are per application. They are not joined to the version on the
  performance trend, so "is the new version worse than the old one?" cannot be answered on one
  page. That join was deferred when the per-application views shipped.
- Boot and shutdown times are recorded, and an individual boot time is visible in a device's
  signal history, but there is no view of them over time, by hardware model or as a distribution.
  The boot family is excluded from the per-device score because its reports are routine, and the
  fleet composite weights it lightly and by how many devices reported, never by how long boots
  took, so slow boots have no summary at all.
- Blue screens and unexpected shutdowns show as counts and as activity over time. They are not
  expressed as a rate per device-day, grouped by stop code or compared by hardware model, and the
  same shutdown can be reported by two sources.
- Whether those records are captured completely is unproven. The operating system writes them
  during the boot that follows the event, which can be before the agent is listening, and capture
  is forward-only. The manual documents this limit, and the issue that raised it was closed on
  that basis (#1351). Until capture at agent start is shown to work on a live host, rates built on
  these records are lower bounds.
- Signals cannot be compared across hardware models. That comparison exists only for the
  performance series.
- Hardware has no retained series. Device performance is a current value.
- There is no source for logon duration.
- There is no usage view across the fleet. Usage is read one device at a time, by executable name
  with no version, and the server keeps one trailing thirty-day figure per device and executable
  rather than a daily series, so neither a usage trend nor a per-version usage figure exists.
- There is a health composite for the fleet and a score for a device, but none for one
  application or for one hardware model. The composite's weights are per signal family, so they
  cannot tell one application from another.
- The fleet composite divides signal counts by the number of Windows devices online, and a family
  that nobody reports deducts nothing, so a missing source reads as a healthy one.
- Most DEX aggregate reads return an empty result when the store read fails, so a degraded store
  can read as zero events or a full score (#2659, #4909).
- The capability map says composite scoring is deliberately not implemented, while the Overview
  and Health score views already show scores. The statement is out of date and needs reconciling.

### What the customer needs

The customer is the end-user-services team that owns a large enterprise's workstation estate.
Their questions, roughly in the order they ask them:

- Which applications are unstable right now, how many machines each affects, and since which
  version.
- Whether the version rolled out last week is worse than the one it replaced.
- Which hardware models blue-screen, shut down unexpectedly, lose disks or batteries, or start
  slowly, so that purchasing, driver and firmware decisions rest on evidence.
- How long machines take to start, shut down and log on, whether that is getting worse, and what
  is slowing it.
- Which applications are used most, how much, and by which groups of machines.
- One defensible number per application and per hardware model for service reviews, which can be
  taken apart on the spot into the observations behind it.
- The same figures from an API, for their own reporting and automation.
- To trust that a quiet screen means a healthy estate and not machines that could not be heard
  from.

### Where this sits in service management

The figures serve four routines. Event handling notices a spike in a crash or shutdown signal.
Incident diagnosis narrows it to a version, a model or a driver. Problem management finds the
application or model that keeps failing. Change validation compares an estate before and after a
rollout. This capability is evidence for those routines. It does not raise tickets, change
anything on an endpoint, or decide that a result is acceptable.

### The position this ADR starts from

The product owner's direction, given on 2026-10-06, is that application performance appears in
the DEX area of the dashboard, with the same capability available through the API from the start
and through MCP later; that it mirrors how DEX signals work today; that it adds boot performance,
unexpected-shutdown and blue-screen detection and an application stability score; that DEX covers
both applications and hardware, and that new measurements are DEX signals; and that the first
release must reach the customer within days of that date. This ADR reads that as a first release
that is, for the most part, a new reading of data DEX already holds; the exception is what the
operating system writes during boot (D7). In discussion the subject was narrowed to applications
running on the endpoint rather than websites, collection to the agent alone, and the first
release to Windows.

## Terminology

- **Observation** — one typed fact an endpoint reports about itself as it happens: a crash, a
  blue screen, a boot time. These are the DEX signals.
- **Series** — a numeric measurement the agent reports on a schedule and the server retains by
  day, such as an application's processor and memory use.
- **Heartbeat value** — a small current value the agent attaches to its periodic heartbeat to the
  server. It has no history of its own.
- **Platform** — an operating system family: Windows, Linux or macOS.
- **Application** — an executable, identified by its image name.
- **Application version** — an application together with its version in the canonical four-part
  form.
- **Cohort** and **reporting population** — as the repository's domain glossary defines them. A
  cohort is the devices sharing a value of an operator-chosen tag key; the reporting population
  is the devices that actually contributed to a figure. A **hardware cohort** is a cohort keyed
  on the model tag.
- **Subject** — what a figure is about: an application version, a hardware cohort or one device.
- **Not collected** — no connected platform reports the source. Different from zero.
- **Measured rate** — a figure counted directly from observations over a reporting population:
  the share of devices with no crash, events per 1,000 device-days, events per hour of use, the
  mean time between failures, or the median and 90th percentile of a time.
- **Stability score** — a 0–100 summary of measured rates for one subject: 100 minus weighted
  deductions, shown with the deductions.
- **Cohort floor** — the number of devices below which a figure shows a count only. Today it is
  ten.
- **Usage** — how long an application runs and how often it is launched, summed over devices.
- **Consolidated view** — the single view in the DEX area that holds this capability. Its
  navigation name is open.

## Decision

### D1 — One lens over applications and hardware

DEX is the single place that answers how applications and hardware are performing. This
capability extends it; it does not open a separate area. The dashboard presents one consolidated
view in the DEX area, organised by four questions: how stable are the applications (stability),
what do they consume (resources), how stable is the hardware and how quickly does it start and
stop (boot, shutdown and hardware stability), and how much are the applications used (usage). The
consolidated view replaces the App Performance view. The Apps and Performance views fold into it,
Performance as the device side of resources. The other views stay where they are and link into
it. Pages that are replaced are retired through a deprecation cycle with notice and redirects, as
ADR-1005 requires once a customer depends on a dashboard surface.

The view and its score are read models on the existing DEX dashboard surface, built API-first
(D11), as the shipped Health score is. ADR-1005 treats domain scoring baked into code as
interpretation, and the in-server DEX dashboards as surfaces that migrate toward an engine over
time. This work does not deepen the coupling to the core, and whether the score counts as
mechanism or interpretation is a boundary question ADR-1005 leaves to the maintainer (see Open
questions).

*Rejected:* adding the new views as further tabs beside the existing eight. They overlap with what
exists, and the team would move between tabs to see one application's crashes next to its resource
use. Also rejected: a new top-level area outside DEX. The evidence is DEX's evidence, and a second
home would split it.

### D2 — One vector: every measurement is a DEX signal or series

A measurement of how an application or a piece of hardware behaves enters DEX the way every
existing one does: as an observation the agent reports as it happens, as a series the agent
reports daily, or as a heartbeat value. Applications and hardware are reported, stored,
aggregated and read the same way. A new measurement extends the observation catalogue, adds a
daily source beside the existing series (ADR-0016), or adds a heartbeat value. It adds no new
transport and no plugin whose job is to measure what DEX can observe itself. A plugin remains the
right home for an operator-requested read of one device, which is a different thing and stays
outside DEX's evidence.

*Rejected:* a plugin for each new measurement. A standalone plugin would carry its own storage,
its own sync source and its own read surface, and its evidence would sit beside DEX's evidence
instead of within it, under different permissions and retention.

### D3 — Rates lead; a transparent score summarises them; one concept, two subjects

The consolidated view leads with measured rates: the share of devices with no crash in the
period; crashes and hangs per 1,000 device-days and, once usage is known, per hour of use; the
mean time between failures; blue screens and unexpected shutdowns per 1,000 device-days; and boot
and shutdown times as a median and a 90th percentile. A stability score then summarises them for
one subject at a time.

The score is 100 minus weighted deductions, with every deduction shown, a band, and the weighting
in force. It applies in the same way to an application version and to a hardware cohort. It is
secondary: it never replaces the rates or takes their place on the page, and any figure on the
page can be taken apart into the observations or series points behind it, for as long as they are
kept. It is evidence, not a decision. Nothing in the product acts on a score; the alerts DEX
raises are driven by signal counts and operator-declared routing, as today, and none by a score.
The weights are shipped reference content: visible, and selectable by preset where a preset
applies. Deductions weigh how many devices are affected before how many events any one device
raised, so one crash-looping device cannot dominate a score.

The two subjects differ in what they can be divided by. A hardware cohort's figures are over the
devices in the cohort. An application version's rate is over the devices known to have run that
version, which today is known only for devices that have per-application sampling switched on.
Where it is not known, the figure is breadth, the devices affected out of the reporting
population, and is labelled breadth, not a rate. The fleet composite's weights are per signal
family, which cannot tell one application from another, so an application's deductions are its
own (see Open questions).

*Rejected:* a score as the headline, because one number invites more precision than the evidence
has, and the Health score view deliberately leads with the measured rate. Also rejected: a
learned or opaque score, which cannot be defended in a service review and cannot say why it
moved. Also rejected: no score, because the customer needs one figure to rank by and to report,
and a ranking without a key is only a sorted list.

### D4 — Applications are identified by image and version; a hardware cohort is a model tag

An application is identified by its executable's image name, and an application version by that
name together with its version in the canonical four-part form. That is the identity the crash,
hang and performance data share on Windows, and it is matched exactly, never by similarity of
names. On Linux none of those data carries a version, so a Linux application is one row with an
unknown version. Applications are read application first, then version, then device, so a rollout
can be judged by setting a version beside the one before it.

A hardware cohort is a cohort as the repository glossary defines it: the devices sharing a value
of an operator-chosen tag key, the model by default, never a value a device reports about
itself. Hardware is read cohort first, then the devices in it. Nothing populates the model tag
automatically today, although the hardware inventory already records each device's manufacturer
and model; how the tag is populated is left open.

Linking an image to an installed package in the software inventory is intended and is decided
later. The inventory does not yet record where each package is installed, so an executable cannot
yet be tied to its package. Until then the consolidated view does not guess a display name.

*Rejected:* resolving each image to its installed package before showing it. It needs new
collection (where each package is installed), and it guesses wrong where one image belongs to
several packages. Also rejected: keying on the name alone, which loses the per-version comparison
a rollout needs; listing hardware by device only, which cannot answer "which model"; and taking
the model from what each device reports about itself, which an agent can misstate.

### D5 — The reporting population defines every figure, and failure directions are fixed

Every rate and every score is computed over a reporting population: the devices that contributed
to it in the period it covers. The number in it is shown beside the figure, together with how
many in-scope devices are not in it. A device that is not connected is unknown, never healthy. A
connected device whose source is switched off, whose sync was skipped, or whose observer is
disabled cannot yet be told from a quiet one; it counts as quiet until a coverage signal exists,
and the page names the population a figure is over. A source that no connected platform collects
is shown as not collected, never as zero, even when nothing is reporting. The failure directions
are fixed:

- No devices reporting a source that a connected platform collects gives a dash, not 100 and not
  0.
- A read that fails gives an error, never an empty or a perfect result, for every figure this
  capability adds. Most existing DEX reads fail soft today (#2659); the new reads are written to
  report failure distinctly, and the existing ones are not changed by this ADR.
- A read that is capped, or a window longer than the evidence kept, says so: the figure is marked
  partial or clamped and labelled to what is retained, never silently shortened or presented as
  complete.
- A figure this capability adds, over fewer devices than the cohort floor, gives a count only,
  because a rate over a handful of devices says too little to rely on, and a figure over one or
  two devices amounts to a per-device read without the per-device gate. A read that names devices
  is governed by D9, not by the floor.

*Rejected:* counting offline or silent devices as healthy, which inflates the headline exactly when
telemetry is broken. Also rejected: estimating figures for an operating system that does not
report, which fabricates evidence.

### D6 — Windows first; gaps are declared

New measurements ship for Windows first, where DEX's collection is fullest. Linux and macOS are
shown as not collected until their own pieces of work land. Bringing each of them to parity is
planned feature work, sequenced by the roadmap; it is not an omission and not a defect.

*Rejected:* holding every measurement until all three operating systems can report it. It misses
the customer's timeline, and for some measures a reliable source does not yet exist on every
platform. Also rejected: presenting Windows figures as the whole fleet, which D5 forbids.

### D7 — Boot, shutdown and stop events are captured at start, trended, and counted once

The operating system writes the records of a blue screen, a power loss and a dirty shutdown
during the boot that follows the event, which can be before the agent is listening. DEX captures
only from the moment its observer arms, and it drops an observation it raises while the agent
cannot reach the server. Rates built on those records are therefore only as complete as the
capture. This decision includes reading, when the agent starts, what the operating system has
written since the agent last ran, and holding observations raised before the agent is connected
until they can be sent. That is new collection on Windows, and until it is shown to work on a
live host the figures built on these records are labelled as lower bounds.

Boot time, shutdown time, resume time, blue screens, kernel panics, unexpected shutdowns and the
hardware faults that precede them are shown as trends and, for times, as distributions: by period,
by hardware cohort, and, where the platform reports it, for boot by what slowed it (application,
driver, service or device). They are not shown as totals alone. A blue screen's stop code travels
with the event and is a way to group them; where the platform also records what a stop implicates,
that is to be carried too. An event counts once: one failure of one boot is one event however many
records the platform writes for it, and two failures on two boots are two. One blue screen can
surface as a bugcheck, as a power loss that names a bugcheck and as a dirty shutdown; it is one
event.

Logon duration is wanted. If a reliable source exists it is added as a signal in the same way. None
exists today, and this ADR does not promise one.

*Rejected:* relying on the live subscription alone, which misses the records written before the
agent is listening. Also rejected: totals only, which cannot show that boots are getting slower or
that one model is worse. Also rejected: adding the sources together, which double counts the very
event the catalogue already marks as usually co-firing, and merging by device and time alone,
which would hide a boot loop as a single event.

### D8 — Usage is run-time and launches, at machine scope

Usage in this capability means how long each application runs and how many times it is launched,
summed across devices and groups, by version once usage can be tied to one. It is a view in its
own right (the most used applications, use by group) and it is the denominator that turns a crash
count into crashes per hour of use, once usage is matched to an application. A usage trend, as
opposed to the current thirty-day figure, needs the server to keep history that it now replaces.
That departs from ADR-0016's rule that the server holds current state and leaves history to the
endpoint (its section 7), as the application series already does; the departure is deliberate and
is recorded per source. Groups are the management groups that exist today; this ADR does not draw
groups from a directory. How long an application has the user's focus is a different measure with
its own pending decision (#2744). This ADR takes run-time and launches, which leaves that
decision focus time alone. A device without an agent is not measured; the product has no evidence
about it.

*Rejected:* deciding focus time here. It needs a component resident in each user's session, which
is ADR-3003's territory, and it would hold the whole capability to that schedule. Also rejected:
leaving usage out, which leaves crash counts without a denominator and the customer's question
about use unanswered.

### D9 — Fleet figures are read at the DEX permission; per-device usage keeps its gate

Fleet and management-group figures, usage aggregates included, are read under the permission that
governs the rest of DEX. That permission is held by any authenticated session while access
control is off, which is the default, and by most built-in roles when it is on. It is wider than
the administrator-only forensic permission on which usage sits today, and for usage aggregates
this ADR supersedes that restriction. Four rules bound the widening:

- A figure over fewer devices than the cohort floor is shown as a count only, and published
  figures are arranged so that a figure withheld below the floor cannot be recovered from those
  shown by subtraction: fleet total against groups, a parent group against its child, or one
  cohort against another. The roadmap sets how.
- Usage is published only along dimensions a reader cannot redefine: the fleet, the management
  groups, and fixed attributes such as the operating system. A cohort is built from tags that
  anyone who can write tags can change, so usage by tag cohort stays at the forensic permission.
  Otherwise two cohorts that differ by one device would hand that device's usage to anyone able
  to write tags.
- A read that names devices is not an aggregate. It is admit-then-filter and audited, failing
  closed when the audit record cannot be written, as the existing per-device drill-downs are, and
  it is not floored. A drill into usage that names devices stays at the forensic permission.
- A management-group-confined operator is refused an aggregate, never shown an unfiltered one,
  until per-caller slicing exists (#5090). A service-scoped token is denied, as on every DEX read
  today.

A per-device read of usage keeps the forensic permission and the audit it has today, and the
approval that gates the operator-requested plugin read is unchanged. No new permission is
created.

*Rejected:* keeping aggregates at the forensic tier. Most of the operators this capability is for
could not see the usage view, and the score would lose its denominator for them. Also rejected:
publishing usage sums with only a floor on each figure, which subtraction undoes; and a new
permission dedicated to usage, which is heavier than the need and is not what is being decided
here.

### D10 — A browser is an application; nothing inside it is measured

The browsers on an endpoint are measured as any other application: crashes, hangs, and processor
and memory by version. What happens inside a browser, such as page loads, rendering and which sites
are used, is outside this capability. So are websites and hosted services generally, and nothing is
installed in a browser to measure them.

*Rejected:* a managed browser extension for page-level telemetry. It is a new component to deploy
and maintain for each browser, it adds a trust boundary, and it measures web destinations rather
than the applications the customer runs. Also rejected: probing destinations from the agent, for the
same reason; it measures the network path, not the endpoint.

### D11 — Every view has a programmatic twin in the same change

Every figure the consolidated view shows is available through the REST API in the same change that
introduces the view, under the same permission, the same denials (service-scoped tokens and
confined operators) and the same floor. The dashboard and the API read one shared computation. MCP
tools for the same figures follow within the programme, each recorded as an exception to the rule
that a capability has both, with a tracking issue and a revisit-by date, until it lands. No view
is reachable only through the dashboard.

*Rejected:* dashboard first and API later. It builds up a parity debt that ADR-1005 forbids and that
the customer asked not to have.

## Scope and non-goals

In scope: what DEX holds about applications and hardware; how it is identified, summarised,
trended and read; the permissions it is read under; and the surfaces that carry it.

Not in scope, and not changed by this ADR:

- **Websites, hosted services and anything inside a browser** (D10).
- **Active probing of destinations**, and synthetic transactions.
- **Focus time and per-user attribution** (#2744, ADR-3003).
- **Devices without an agent.** They are not measured; the product has no evidence about them.
- **Survey, sentiment or learned scoring.**
- **Acting on a finding.** Remediation, tickets and automatic alerting from a score are not part of
  this capability. Alert routing stays operator-declared, as it is today.
- **Collecting crash dumps or their contents.** Only what the platform records about a crash is
  read. Dump collection is a separate, forensic capability.
- **A new permission**, including a dedicated DEX permission (#1355).
- **Replacing the fleet health composite.** It stays; the stability score sits beside it.
- **Moving DEX's read models out of the server.** ADR-1005's migration governs that (D1).
- **Boot duration on macOS**, for which no reliable unprivileged source exists.
- **Linking images to installed packages** (decided later, D4).
- **Schemas, protocol, screen design and delivery order.** These belong to the roadmap.

## Consequences

### What changes for customers

- The views over application stability, resources and usage collect nothing new on any endpoint:
  they read data DEX already holds. Per-application resource figures appear only for devices that
  have per-application sampling switched on, and usage figures are forward-only and cover the
  retained window. The blue-screen, power-loss and unexpected-shutdown figures depend on the
  capture at agent start in D7, which is new collection on Windows endpoints.
- Fleet and management-group usage figures become readable by everyone who can read DEX, where
  usage is administrator-only today. An upgrade note says so when it ships.
- Later releases add specific signals. Each is stated in the DEX signal catalogue, with the
  operating systems that collect it.
- REST routes and MCP tools keep working and keep their meaning. Pages the consolidated view
  replaces are retired with notice and redirects.
- One view answers "which application, which version, which model", with a number that can be
  taken apart.

### What changes in the product

The following is the starting point for the roadmap, which decides order and grouping.

- The DEX navigation: one consolidated view replaces App Performance, absorbs Apps and
  Performance, and links to the rest, with redirects and an upgrade note.
- The version joined onto crash and hang reads, so stability and resource use sit side by side per
  version.
- A stability read for applications and for hardware cohorts, with its decomposition. An
  application's deductions are its own.
- Trend and distribution reads for boot, shutdown and stop events, and a cohort dimension for
  signals, which today exists only for the performance series.
- A fleet usage read, published so that nothing withheld can be recovered by subtraction, and
  usage as the denominator for rates.
- New signals and extractors for what platforms already record about boot phases, stop codes and
  driver faults, a logon source if one exists, capture at agent start, and a hold for observations
  raised before the agent is connected.
- Reads that report a failed read distinctly from an empty one and say when they are capped. Most
  existing DEX reads fail soft (#2659).
- Retained daily summaries for stability, boot and usage trends, each keeping its reporting
  population (see the open question on retention). Any new retention pass follows the
  clock-guarded retention rule.
- The capability map's scoring statement, the authorization model and permission documents, the
  DEX manual and the signal catalogue, restated to match, with a changelog entry and an upgrade
  note.
- MCP tools for each new route, each parity exception recorded, and the Linux and macOS legs as
  feature work.

### Risks, and what answers each

| Risk | Answer |
|---|---|
| A score invites more confidence than the evidence supports | D3: rates lead, the score shows its deductions and is secondary; D5: the population is shown and nothing reporting gives a dash |
| A rate over a few devices reads as a trend | D5: the cohort floor |
| Windows figures are read as the whole fleet | D5 and D6: the reporting population is shown; other systems read as not collected |
| A survivor population hides most of a model's devices | D5: the number of in-scope devices not reporting is shown beside every figure |
| One shutdown or crash is counted twice, or two boot failures once | D7: one failure of one boot is one event |
| Blue screens and shutdowns written during boot are never seen | D7: capture at agent start, with the figures labelled as lower bounds until it is proven |
| A rollout looks better or worse than it is because exposure is unknown | D3: breadth is labelled as breadth, and a rate needs a known exposure |
| A version is mistaken for another, or one application reads as two | D4: exact identity on image and canonical version, never similarity of names; the residuals name the known splits |
| Widening usage to more readers lets one device's usage be worked out | D9: no recoverable subtraction, no reader-defined cohorts, and a per-device read keeps its gate |
| A read is slow or silently truncated at fleet scale | D5: reads say when they are capped; retained summaries are an open question |
| The dashboard gets ahead of the API | D11: the same change |
| Someone reads the score as a verdict | D3: nothing acts on a score |

### Accepted residuals

- Until the other operating systems have their own legs, a mixed fleet's rates describe its
  Windows part, and say so.
- A connected device whose crash reporting is switched off, whose observer is disabled, or whose
  application-series or usage sync is skipped for being over a size cap looks quiet, and counts as
  quiet in its population (#4489, #5059). A skipped usage sync leaves the server holding the
  device's last figure, which then ages unnoticed.
- Until capture at agent start exists and is shown to work on a live host, blue-screen,
  power-loss and dirty-shutdown figures are lower bounds. Agents also cap how many records of one
  type they report each hour and drop the overflow, so a storm's count is a lower bound too.
- Most existing DEX reads fail soft: when the store read fails they return an empty result that
  can read as zero events or a full score (#2659, #4909). The reads this ADR adds report failure
  distinctly; the existing ones are not changed here, and nothing acts on a score, which keeps the
  deferral safe.
- Per-application resource figures exist only for devices with per-application sampling switched
  on, and the fleet rollup of them has no operating-system dimension yet (#4512).
- Usage is recorded from when collection starts and covers the retained window only.
- The signal views apply no cohort floor today. This ADR sets the floor for the figures it adds and
  leaves those views as they are.
- Raw observations are kept for a limited period (thirty days by default). A trend longer than that
  depends on retained daily summaries, which exist for the application series and do not yet exist
  for stability, boot or usage.
- An image name shared by two different products is one application here.
- Packaged applications report no version on a crash while the performance series resolves one, so
  an exact match can show one application as two. A version that cannot be put into the canonical
  form falls into a shared unknown bucket, and on Linux every application is in it. Version
  suffixes are dropped, so two builds with the same four-part number are one version, and after a
  rollback "the version before it" is ambiguous.
- Cohorts below the floor, and devices that carry no model tag, appear as a count and an untagged
  residual, so a sparsely tagged estate sees little hardware comparison.
- The per-process source covers Windows and Linux only. macOS has none today.

## Verification

The decision is being followed when all of the following are true.

1. The App Performance, Apps and Performance views are retired through a deprecation cycle with
   notice and a redirect to the consolidated view, and no page disappears without notice.
2. A new measurement is added without a new transport and without a plugin whose job is to measure
   it.
3. For any figure in the consolidated view, the observations or series points behind it can be
   listed while they are kept, up to the read limit. For an older figure the retained daily values
   are listed and the view says the observations have aged out. A retained summary keeps each
   day's reporting population.
4. Nothing in the product acts on a score: no alert, action or approval depends on one.
5. An application version can be compared with the one before it on one page, by devices affected
   and by crash and hang rate over the devices known to have run each, with the exposure source
   named. Where exposure is unknown the figure is labelled as breadth, not as a rate.
6. A hardware model can be compared with others on blue-screen rate, unexpected-shutdown rate and
   boot time. Two versions of one application are two rows, and the same image on Linux is one row
   with an unknown version.
7. With no devices reporting a source that a connected platform collects, its rate and score show
   a dash. A source that no connected platform collects shows as not collected, even when nothing
   is reporting. With devices reporting, the number reporting and the number of in-scope devices
   not reporting are shown beside the figure.
8. Connecting the first device of a platform that collects a source changes that source from not
   collected to a figure over a population of one, shown as a count below the floor, and changes
   no other figure.
9. A degraded read of any source this capability adds gives an error, not an empty or a perfect
   figure. A capped read, or a window longer than the evidence kept, says so on the page.
10. A figure this capability adds, over fewer devices than the cohort floor, shows a count only, on
    the dashboard and in the API, and published figures do not allow a withheld one to be
    recovered by subtraction.
11. On a mixed fleet, the absence of a Linux or macOS device from a Windows-first signal measure is
    visible on the page. The application series shows the same once it carries an
    operating-system dimension.
12. A blue screen, a power loss or a dirty shutdown that happened while the agent was not running
    is in the figures once the agent starts and connects. Two sources reporting the same
    unexpected shutdown yield one event in every rate, and two failures on two boots are two.
13. Usage is available as run-time and launches by application and by group, and no figure claims
    to be focus time.
14. A per-device usage read still requires the forensic permission and leaves its audit record,
    failing closed when the record cannot be written. An aggregate read needs the DEX permission
    only and names no device. A read that names devices is audited and is not floored.
15. A management-group-confined operator and a service-scoped token are refused an aggregate, not
    shown an unfiltered one. Usage by tag cohort is refused below the forensic permission.
16. A browser appears as an application with its crashes, hangs and resource use, and nothing
    reports what happened inside it.
17. For every view the dashboard shows, the API returns the same figures with the same
    suppression. Every MCP tool still owed is a recorded exception with a tracking issue and a
    revisit-by date.

## Open questions

- **Retention.** Raw observations age out after thirty days by default. Stability and boot trends
  over a quarter need retained daily summaries like the application series has, and a usage trend
  needs the server to keep what it now replaces. Which figures are served from summaries at any
  horizon, for how long, and at what grain? A summary must keep each day's reporting population.
- Which deductions and bands does an application's score use, given that the fleet composite's
  per-family weights cannot separate one application from another, and do presets apply to it?
- Is the stability score mechanism or interpretation under ADR-1005's boundary test, which the
  maintainer arbitrates? Until it is ruled on, the score is built as a read model on the existing
  DEX surface.
- Should the fleet health composite keep weighting the boot family, whose reports are routine and
  which it counts by how many devices reported rather than by how long boots took? A change would
  alter what the existing health routes return, which counts as a change in their meaning.
- Should a device with crash reporting switched off be shown as not covered, and on what evidence?
- What is the consolidated view's name in the navigation, and does the "App Performance" label
  stay?
- Does logon duration have a reliable source on any platform?
- How does the model tag get populated for estates that have not tagged models, given that
  cohorts come from operator-declared tags and not from what a device reports? If the hardware
  inventory is the source, only the model value would cross to the DEX permission.
- How is usage, which is recorded by lowercased executable name, matched to an application's image
  name and version, including where Linux truncates process names, and over which window is a
  rate per hour of use computed?
