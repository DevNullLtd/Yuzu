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
  dashboard), the Guardian event design (whose ruleless observation path carries DEX signals),
  the DEX signal catalogue
amends: >-
  The capability map's statement (section 32.7) that composite experience scoring is
  deliberately not implemented. This ADR keeps what that statement protects — no opaque or
  sentiment-based score — and permits a transparent composite alongside measured rates.
related: ["0016-agent-daily-sync-framework", "1005-headless-platform-use-case-engines", "3003-user-session-helper"]
context-refs: ["#1706", "#1766", "#2744", "#4489", "#4512", "#4513", "#4909", "#5059", "#4035", "#1355"]
---

# 3008 — Application and hardware performance in DEX

## Summary

DEX already watches what the workforce's applications and devices do on the endpoint. It records
crashes, hangs, blue screens, unexpected shutdowns, slow boots, failing disks and throttled
processors, and it keeps how much processor and memory each application version uses, day by
day. What it does not yet do is answer the questions an end-user-services team asks of that
evidence: which applications are unstable and since which version; which hardware models crash,
fail or start slowly; whether last week's rollout made things better or worse; and how heavily
each application is used.

This ADR makes DEX that answer. It is one lens over applications and hardware, in the DEX area of
the dashboard, with the same figures available through the REST API in the same change and
through MCP later. Six points carry the direction:

- Everything measured is a DEX signal or a DEX series. Applications and hardware travel the same
  path, and nothing DEX can observe itself is measured by a new plugin.
- Measured rates lead. A transparent stability score summarises them, and it is one concept
  applied to two subjects: an application version and a hardware model.
- Every figure is over the devices that report it, and what is not collected is shown as not
  collected.
- New measurements arrive on Windows first, with the gaps on other operating systems stated and
  never hidden.
- Usage means how long and how often an application runs. How long it has the user's focus is a
  separate decision.
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
- **Series.** Each day the agent also reports how much processor and working-set memory each
  application version used. The server keeps it per device for about a month and rolled up
  across the fleet for about half a year. It exists for Windows and Linux; macOS has no
  per-process source yet.
- **Usage.** A separate plugin reports, on request and per device, how long and how often each
  executable ran. It is a forensic-tier read. Nothing in the product measures how long an
  application has the user's focus; that is the subject of its own open decision.
- **Views.** The DEX area has eight views: Overview, Apps, Catalogue, Health score, Trends,
  Performance, App Performance and Network. Each has a REST twin and MCP tools. Headline figures
  are measured rates over the devices that are reporting, not scores. A secondary health
  composite shows its decomposition, and the Overview splits it into fleet-wide device,
  application and network sub-scores. A figure over too few devices shows a count only.

The gaps, as the evidence stands today:

- Crash and hang counts are per application. They are not joined to the version on the
  performance trend, so "is the new version worse than the old one?" cannot be answered on one
  page. That join was deferred when the per-application views shipped.
- Boot and shutdown times are recorded, and an individual boot time is visible in the signal
  drill-down, but there is no view of them over time, by hardware model or as a distribution. The
  boot family is also deliberately excluded from the health composite, because its reports are
  benign, so slow boots have no summary at all.
- Blue screens and unexpected shutdowns show as counts and as activity over time. They are not
  expressed as a rate per device-day, grouped by stop code or compared by hardware model, and the
  same shutdown can be reported by two sources.
- Signals cannot be compared across hardware models. That comparison exists only for the
  performance series.
- There is no source for logon duration.
- There is no usage view across the fleet. Usage is read one device at a time.
- There is a health composite for the fleet and a score for a device, but none for one
  application or for one hardware model.
- The capability map says composite scoring is deliberately not implemented, while the product
  already ships a secondary composite. The two statements need reconciling.

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
release must reach the customer within days. This ADR reads that as a first release that is a new
reading of data DEX already holds. In discussion the subject was narrowed to applications running
on the endpoint rather than websites, collection to the agent alone, and the first release to
Windows.

## Terminology

- **Observation** — one typed fact an endpoint reports about itself as it happens: a crash, a
  blue screen, a boot time. These are the DEX signals.
- **Series** — a numeric measurement the agent reports on a schedule and the server retains by
  day, such as an application's processor and memory use.
- **Application** — an executable's image name together with its version in the canonical
  four-part form.
- **Hardware cohort** — the devices that share a value of a chosen attribute: the model by
  default.
- **Subject** — what a figure is about: an application version, a hardware cohort or one device.
- **Reporting population** — the devices that currently report the source a figure comes from.
  It is the denominator of every rate.
- **Not collected** — no connected platform reports the source. Different from zero.
- **Measured rate** — a figure counted directly from observations over a reporting population:
  the share of devices with no crash, events per 1,000 device-days, events per hour of use, the
  mean time between failures, or the median and 90th percentile of a time.
- **Stability score** — a 0–100 summary of measured rates for one subject: 100 minus weighted
  deductions, shown with the deductions.
- **Cohort floor** — the number of devices below which a figure shows a count only. Today it is
  ten.
- **Usage** — how long an application version runs and how often it is launched, summed over
  devices.
- **Hub** — the DEX view that holds this capability.

## Decision

### D1 — One lens over applications and hardware

DEX is the single place that answers how applications and hardware are performing. This
capability extends it; it does not open a separate area. The dashboard presents one hub in the DEX
area, organised by four questions: how stable are the applications (stability), what do they
consume (resources), how stable is the hardware and how quickly does it start and stop (boot,
shutdown and hardware stability), and how much are the applications used (usage). The existing
Apps and Performance views fold into the hub. The other views stay where they are and link into it.

*Rejected:* adding the new views as further tabs beside the existing eight. They overlap with what
exists, and the team would move between tabs to see one application's crashes next to its resource
use. Also rejected: a new top-level area outside DEX. The evidence is DEX's evidence, and a second
home would split it.

### D2 — One vector: every measurement is a DEX signal or series

A measurement of how an application or a piece of hardware behaves enters DEX the way every
existing one does: as an observation the agent reports as it happens, as a series the agent
reports daily, or as a current value on its heartbeat. Applications and hardware are reported,
stored, aggregated and read the same way. A new measurement extends the observation catalogue or
the daily series. It does not introduce a new plugin or a new transport. A plugin remains the
right home for an operator-requested read of one device, which is a different thing and stays
outside DEX's evidence.

*Rejected:* a plugin for each new measurement. A standalone plugin would carry its own storage,
its own sync source and its own read surface, and its evidence would sit beside DEX's evidence
instead of within it, under different permissions and retention.

### D3 — Rates lead; a transparent score summarises them; one concept, two subjects

The hub leads with measured rates: the share of devices with no crash in the period; crashes and
hangs per 1,000 device-days and, once usage is known, per hour of use; the mean time between
failures; blue screens and unexpected shutdowns per 1,000 device-days; and boot and shutdown times
as a median and a 90th percentile. A stability score then summarises them for one subject at a
time.

The score is 100 minus weighted deductions, with every deduction shown, a band, and the weighting
preset in force. It applies in the same way to an application version and to a hardware cohort.
It is secondary: it never replaces the rates or takes their place on the page, and any figure on
the page can be taken apart into the observations behind it. It is evidence, not a decision.
Nothing in the product acts on a score, and alerting stays with the routing an operator declares.
The weights are shipped reference content: visible, and selectable by preset.

*Rejected:* a score as the headline, because one number invites more precision than the evidence
has, and the existing views deliberately lead with rates. Also rejected: a learned or opaque score,
which cannot be defended in a service review and cannot say why it moved. Also rejected: no score,
because the customer needs one figure to rank by and to report, and a ranking without a key is
only a sorted list.

### D4 — An application is its image and version; a hardware cohort is a model

An application is identified by its executable's image name and its version in the canonical
four-part form. That is the one identity the crash, hang and performance data already share, and
it is matched exactly, never by similarity of names. Applications are read application first,
then version, then device, so a rollout can be judged by setting a version beside the one before
it. Hardware is read the same way: a cohort first (the model by default, or any other attribute
devices have been tagged with), then the devices in it. Linking an image to an installed package
in the software catalogue is intended and is decided later, when the catalogue exists. Until then
the hub does not guess a display name.

*Rejected:* resolving each image to its installed package before showing it. It depends on a
catalogue that has not landed and on new collection, and it guesses wrong where one image belongs
to several packages. Also rejected: keying on the name alone, which loses the per-version
comparison a rollout needs; and listing hardware by device only, which cannot answer "which
model".

### D5 — The reporting population defines every figure, and failure directions are fixed

Every rate and every score is computed over the devices that report the source it comes from, and
the number reporting is shown beside it. A device that cannot be heard from is unknown, never
healthy. A source that no connected platform collects is shown as not collected, never as zero.
The failure directions are fixed:

- No devices reporting gives a dash, not 100 and not 0.
- A read that fails gives an error, never an empty or a perfect result.
- A figure over fewer devices than the cohort floor gives a count only, because a rate over a
  handful of devices says too little to rely on.

*Rejected:* counting offline or silent devices as healthy, which inflates the headline exactly when
telemetry is broken. Also rejected: estimating figures for an operating system that does not
report, which fabricates evidence.

### D6 — Windows first; gaps are declared

New measurements ship for Windows first, where DEX's collection is fullest and where the first
release can land within days. Linux and macOS are shown as not collected until their own pieces of
work land. Bringing each of them to parity is planned feature work, sequenced by the roadmap; it is
not an omission and not a defect.

*Rejected:* holding every measurement until all three operating systems can report it. It misses
the date, and for some measures a reliable source does not yet exist on every platform. Also
rejected: presenting Windows figures as the whole fleet, which D5 forbids.

### D7 — Boot, shutdown and stop events are trended, and an event counts once

Boot time, shutdown time, resume time, blue screens, kernel panics, unexpected shutdowns and the
hardware faults that precede them are shown as trends and, for times, as distributions: by period,
by hardware cohort, and for boot by what slowed it (application, driver, service or device). They
are not shown as totals alone. A blue screen's stop code travels with the event and is a way to
group them; where the platform also records what a stop implicates, that is carried too. An event
reported by more than one source counts once in every rate: an unexpected shutdown seen both as a
power loss and as a dirty shutdown is one shutdown.

Logon duration is wanted. If a reliable source exists it is added as a signal in the same way. None
exists today, and this ADR does not promise one.

*Rejected:* totals only, which cannot show that boots are getting slower or that one model is
worse. Also rejected: adding the sources together, which double counts the very event the catalogue
already marks as co-firing.

### D8 — Usage is run-time and launches, at machine scope

Usage in this capability means how long each application version runs and how many times it is
launched, summed across devices and cohorts. It is a view in its own right (the most used
applications, use by group) and it is the denominator that turns a crash count into crashes per
hour of use. Groups are the management groups and tag-defined cohorts that exist today; there is no
directory integration. How long an application has the user's focus is a different measure with its
own pending decision (#2744) and is not decided here. A device without an agent is not measured;
the product has no evidence about it.

*Rejected:* deciding focus time here. It needs a component resident in each user's session, which
is ADR-3003's territory, and it would hold the whole capability to that schedule. Also rejected:
leaving usage out, which leaves crash counts without a denominator and the customer's question
about use unanswered.

### D9 — Fleet figures are read at the DEX permission; per-device usage keeps its gate

Fleet and cohort figures, usage aggregates included, are read under the permission that governs the
rest of DEX, and only above the cohort floor. A per-device read of usage keeps the forensic
permission, the approval and the audit it has today. No new permission is created.

*Rejected:* keeping aggregates at the forensic tier. Most of the operators this capability is for
could not see the usage view, and the score would lose its denominator for them. Also rejected: a
new permission dedicated to usage, which is heavier than the need and is not what is being decided
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

Every figure the hub shows is available through the REST API in the same change that introduces the
view, under the same permission and with the same floor. The dashboard and the API read one shared
computation. MCP tools for the same figures follow within the programme and are tracked until they
do. No view is reachable only through the dashboard.

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
- **Boot duration on macOS**, for which no reliable source exists.
- **Linking images to the software catalogue** (decided later, D4).
- **Schemas, protocol, screen design and delivery order.** These belong to the roadmap.

## Consequences

### What changes for customers

- The first release collects nothing new on any endpoint. It adds views, a score and API routes
  over data DEX already holds, so nothing changes on an endpoint when it lands.
- Later releases add specific signals. Each is stated in the DEX signal catalogue, with the
  operating systems that collect it.
- The existing API routes keep working; new ones are added beside them.
- One hub answers "which application, which version, which model", with a number that can be taken
  apart.

### What changes in the product

The following is the starting point for the roadmap, which decides order and grouping.

- The DEX navigation: one hub replaces the Apps and Performance views and links to the rest.
- The version joined onto crash and hang reads, so stability and resource use sit side by side per
  version.
- A stability read for applications and for hardware cohorts, with its decomposition.
- Trend and distribution reads for boot, shutdown and stop events, and a cohort dimension for
  signals, which today exists only for the performance series.
- A fleet usage read, and usage as the denominator for rates.
- New signals and extractors for what platforms already record about boot phases, stop codes and
  driver faults, and a logon source if one exists.
- Retained daily summaries for stability and boot trends (see the open question on retention).
- The capability map's scoring statement, the DEX manual and the signal catalogue, restated to
  match.
- MCP tools for each new route, and the Linux and macOS legs as feature work.

### Risks, and what answers each

| Risk | Answer |
|---|---|
| A score invites more confidence than the evidence supports | D3: rates lead, the score shows its deductions and is secondary; D5: the population is shown and nothing reporting gives a dash |
| A rate over a few devices reads as a trend | D5: the cohort floor |
| Windows figures are read as the whole fleet | D5 and D6: the reporting population is shown; other systems read as not collected |
| One shutdown or crash is counted twice | D7: an event counts once |
| A version is mistaken for another, or one application reads as two | D4: exact identity on image and canonical version, never similarity of names |
| Opening usage to more operators widens who can see a forensic-tier measure | D9: only aggregates above the floor move; a per-device read keeps its gate |
| The dashboard gets ahead of the API | D11: the same change |
| Someone reads the score as a verdict | D3: nothing acts on a score |

### Accepted residuals

- Until the other operating systems have their own legs, a mixed fleet's figures describe its
  Windows part, and say so.
- A device whose platform crash reporting is switched off by policy reports no crashes and looks
  quiet. The product does not yet show such a device as not covered.
- Raw observations are kept for a limited period (thirty days by default). A trend longer than that
  depends on retained daily summaries, which exist for the application series and do not yet exist
  for stability or boot.
- An image name shared by two different products is one application here.
- A version that cannot be put into the canonical form falls into a shared unknown bucket.
- The per-process source covers Windows and Linux only. macOS has none.

## Verification

The decision is being followed when all of the following are true.

1. For any figure on the hub, the observations behind it can be listed, and the figure can be
   recomputed from them.
2. With no devices reporting a source, its rate and score show a dash. With devices reporting, the
   number reporting is shown beside the figure.
3. A source that no connected platform collects is shown as not collected. The first device of a
   platform that does collect it lights the figure, with no change elsewhere.
4. Two sources reporting the same unexpected shutdown yield one event in every rate.
5. A figure over fewer devices than the cohort floor shows a count only, on the dashboard and in
   the API.
6. For every view the dashboard shows, the API returns the same figures with the same
   suppression, and the parity ledger carries no planned entry for a hub view.
7. An application version can be compared with the one before it on one page, by crash and hang
   rate and by resource use.
8. A hardware model can be compared with others on blue-screen rate, unexpected-shutdown rate and
   boot time.
9. A per-device usage read still requires the forensic permission and still leaves its audit
   trail. An aggregate read does not.
10. Nothing in the product acts on a score: no alert, action or approval depends on one.
11. A degraded read of any source gives an error, not an empty or a perfect figure.
12. On a mixed fleet, the absence of a Linux or macOS device from a Windows-first measure is visible
    on the page.

## Open questions

- **Retention.** Raw observations age out after thirty days by default. Stability and boot trends
  over a quarter need retained daily summaries like the application series has. How long, and at
  what grain?
- Whether the stability score's weights share the presets of the fleet health composite or are
  their own. This ADR requires only that they are visible and selectable.
- Whether a device with crash reporting switched off should be shown as not covered, and on what
  evidence.
- The hub's name in the navigation, and whether the "App Performance" label stays.
- Whether logon duration has a reliable source on any platform.
- Which attribute defines a hardware cohort for estates that do not tag models.
