# DEX — Digital Employee Experience

The **DEX dashboard** (`/dex`) is a read-only fleet-reliability lens over the
Guardian event store. It reinterprets ruleless [signal observations](guaranteed-state.md#dex-signal-observations)
— app crashes and hangs, service failures, device stability, boot/resume
performance, network, sign-in, security, update, and printing problems — as a
picture of what the workforce actually experiences on their machines. It does
**not** author or enforce anything (that is [Guardian](guaranteed-state.md)); it
only reads and aggregates.

It is reached from the **DEX** link in the dashboard nav, or directly at
`/dex`. Access requires the **`GuaranteedState:Read`** permission.

## The eight views

DEX is organised as a **hub** (the Overview at `/dex`) that *summarises and
links* into seven deep pages. A shared sub-nav switches between **Overview ·
Apps · Catalogue · Health score · Trends · Performance · App Performance ·
Network**; the window selector (below) applies to the signal views (Performance
and Network are now-views — see below). The Network view also has its own URL,
`/network`, but it is a DEX sub-view, not a standalone top-level nav item.

### Overview (the hub)

An at-a-glance executive summary that routes into the deep pages — it summarises
and links, it does not duplicate their detail.

- **Headline reliability (measured, not a score).** Four tiles of
  industry-standard *measured rates*, never a synthetic 0–100 number:
  - **Crash-free devices %** — the share of reporting Windows devices with no app
    crash in the window.
  - **Crashes / 1,000 device-days** — crash frequency normalised by fleet size
    and window length.
  - **Devices impacted** — distinct devices with a crash in the window.
  - **Agents reporting** — the count of currently-reporting agents. This is the
    honest stand-in for "telemetry coverage": a device we can't hear from is
    *unknown*, not healthy, so DEX shows the reporting count rather than
    fabricate a coverage percentage from a fleet size it doesn't know.

  The rates are computed over **currently-reporting Windows agents only** (the
  OS with the most complete collector). Offline agents are *excluded* from the
  denominator, not counted as healthy — so the number can't be inflated by
  broken telemetry. When no agents are reporting, the tile honestly shows **—**
  rather than a fabricated rate.
- **Explore cards** open the three deep pages, each with a live teaser figure.
- **Crashes per day**, then **top crashing apps** (with blast radius)
  side-by-side with **most-affected devices**, and a **by-operating-system**
  summary whose *signal scope* ("N of the monitored types") is derived live so a
  narrower-coverage OS is never mistaken for a healthier one.

### Apps

A **fleet-wide Applications list** ranked by reliability signals — crash counts
and hang counts, keyed on the process image name. Each row links to the existing
per-application blast-radius drill-down (top subjects, faulting modules,
most-affected devices). Built on the same `dex_top_apps` aggregation that drives
the Overview crash cards — no new agent collection. The app detail page
cross-links to per-version CPU & memory performance (the **App Performance**
tab's application trend), joined on the same process-image key an application's crash
and perf identity already share on Windows/Linux — an exact match, not a
name-normalized guess. Attribution of repository/install/service signals to the
originating app is a follow-on slice; the Apps tab today scopes to crash and
hang signals only. Per-version crash/hang *counts* on the performance trend
(as opposed to the per-app crash/hang totals already shown here) remain
deferred — see "Fleet-wide application performance" under Drill-downs.

### Catalogue

Every monitored signal type, organised into 13 families (App reliability,
Boot/start-up & shutdown, Service health, System stability, Hardware & storage,
Performance, File system, Network, Identity & logon, Security & protection,
Updates & installs, Policy & management, Printing). The Catalogue is
**coverage-first**: a family card shows how many of its types are **monitored**
(collected by a connected platform — lit even when nothing has fired) and a
0–100 **health score**. Under **All connected** the score is the family's slice
of the fleet health composite; under a **single-OS chip** (Windows / Linux /
macOS) the family is **rescored against that platform's own online agents and
its own signals**, so a Linux or macOS score is never a Windows-derived number
read under another OS's heading. A
monitored type with no events reads as **watched, nothing happened** — real
information, not a gap; a type that **no connected platform collects** shows
dimmed as **not collected**, never as healthy. (A type is *not collected* when no
currently-connected platform in your fleet emits it — e.g. a Linux-only signal on
an all-Windows fleet; it lights automatically when the first eligible device
connects, so this is a coverage fact, not a broken collector.) An **OS filter** (All connected /
Windows / Linux / macOS) narrows coverage to one platform, **rescores each
family for that platform**, and **persists** when you open a family or drill
into a type — the drill-down's rollup, per-signal rows, and score all follow
the selected lens. **Note:** the All connected composite keeps the established
Windows-online denominator (the coverage-honest fleet composite); on a macOS-
or Linux-only fleet the default lens can therefore show **—** — click your
platform's chip for a real per-family score. Opening a family lists **every** type
with its coverage (which platforms collect it) and, for the ones that fired,
event and device counts. Each type drills into a per-type view: top subjects,
the live OS split, the most-affected devices, and an activity trend. Any signal
a newer agent emits that isn't catalogued yet appears under **Other**, so
nothing the fleet reports is hidden.

### Health score

A **transparent, secondary** composite (0–100) derived from the measured rates —
explicitly *not* the headline (the measured crash-free % stays primary). The
score is `100 − Σ weighted deductions`, and the page shows the full
decomposition: the per-family deductions and the weighting preset in force
(default / stability / productivity / security). With no reporting agents the
score is **suppressed**, never a fabricated 100.

### Trends

Cross-OS comparison cards — each carrying its **live signal scope**, so an OS
with a narrower collector reads as *less observed*, not healthier — plus
per-family small-multiple sparklines and a family×day activity heatmap.

### Performance

Continuous device telemetry rolled up across the fleet — the *levels*, where
Trends shows the *events*. A **now-view**: every number is computed at render
time from the latest heartbeat sample of each reporting device (the same data
behind the `yuzu_fleet_perf_*` Prometheus gauges), with **no window selector**
— nothing on this page has retained history yet (trend charts arrive with the
server-side series store).

- **Fleet now cards** — CPU utilization, memory commit and disk I/O latency,
  each showing avg / p50 / p90 / max plus the **Reporting** population card
  (the honest denominator: an average over 12 devices is never silently
  presented as fleet-wide truth). Perf telemetry is collected by **Windows and
  Linux agents** today; macOS agents show as online but are absent from these
  numbers, not zero. The Reporting card's caption is **per-OS** (Windows W ·
  Linux L · macOS M online), fixing the previous known limitation where the
  denominator only counted Windows devices and could be legitimately exceeded
  by a mixed-fleet reporting count; the *not-reporting* drill now spans every
  OS with a real collector (Windows + Linux), not Windows only. `GET
  /api/v1/dex/perf/fleet` and the MCP `get_dex_perf_fleet` tool carry the same
  breakdown as additive `linux_online`/`macos_online`/`reporting_windows`/
  `reporting_linux`/`reporting_macos` fields alongside the original
  `windows_online`/`reporting`.
- **Cohort benchmarking** — fleet-relative percentiles per **cohort**: the
  distinct values of an operator-chosen **tag key** (default `model`; pick any
  key from the selector — e.g. an `image` key compares a vanilla VDI image
  against a layered one on identical hardware). Cohorts come from tags, not
  from a central inventory column: tag the fleet via the tag API (see the
  asset-tagging guide) and the comparison appears. Honesty rules: cohorts
  under **10 reporting devices** show "n too small" instead of noisy
  percentiles, and devices without the chosen key always appear as an explicit
  **(untagged)** residual row.
- **Everything drills.** Each metric card opens the worst devices by that
  metric; the Reporting card opens the devices *not* reporting; each cohort
  row opens that cohort's device list — and every device row opens the
  per-device drill-down.

### App Performance

A dedicated top-level tab for the **retained per-(app, version) performance
trend** (see "Fleet-wide application performance" under Drill-downs) — a
sibling of Performance, not a replacement: Performance is the live fleet-now
widget above; App Performance is the picker into retained history. Previously
this picker was reachable only via a buried inline link on the Performance
page; it now has its own tab.

The picker lists every application with retained history and adds three
controls, all server-rendered (HTMX round-trips, no client-side framework):

- **Search** — a text box that re-filters the list by name (case-insensitive
  substring), debounced client-side before each re-fetch.
- **Platform** — `All` / `Windows` / `Linux` chips. Today this is a **name-suffix
  heuristic** (an app name ending `.exe` is treated as Windows, anything else as
  Linux) — the app-perf roll-up carries no real per-app platform field yet, so a
  mismatch is possible; the page says so.
- **Sort** — most-recently-seen first (default), name (A–Z), or most retained
  versions first.

A result-count line ("N of M applications", or "N of M applications match
&lsquo;query&rsquo;") and an honest empty state (never a blank table) reflect
the current filters.

### Network

The fleet's TCP **network quality**, measured on each endpoint from kernel
counters (no packet capture, no flow export). A **now-view** like Performance:
fleet-now cards for round-trip time, the interval retransmit rate, and device
throughput — each with its own reporting population — plus a worst-devices
drill. It is **device / local-link health**, not localization: a bad local link
(Wi-Fi, congested uplink) shows up cleanly across every connection, but *which*
destination or app is affected is a later per-destination slice. Linux agents
report all three metrics; Windows reports throughput and retransmit rate (RTT
deferred — needs ESTATS); macOS is a later slice. Full detail,
platform coverage, and the privacy model are on the
[Network quality dashboard](network.md) page.

**Window selector.** `24h / 7d / 30d / All` rescopes every signal view.
Drill-downs opened from a panel inherit the window you were viewing, so the
numbers match.

## Drill-downs

- **Per-application** — click an app to see its crash/hang blast radius across
  the fleet: faulting modules, exception codes, and which devices are affected.
  Cross-links to that app's **fleet-wide performance trend** (below), and the
  trend links back — same process-image key both directions, exact match.
- **Fleet-wide application performance** — reached from its own **App
  Performance** top-level tab (search/platform/sort over the application list —
  see below), or the cross-link above: each version of an application
  gets its own row with avg/p95 CPU, a CPU sparkline, avg working set, and the
  reporting device count, over the retained fleet window (≤180 days) or, when a
  management group **or a device model** is selected, that cohort's on-the-fly
  aggregate (≤31 days, sub-10-device points suppressed to a count only — the
  same floor either way, since a named tag-value cohort is a set of specific
  devices exactly like a management group). The two cohort selectors
  (**Scope**, by management group, and **Model**, by device-tag value) are
  **mutually exclusive**: picking one clears the other, and a management
  group takes precedence if a URL somehow names both. Choosing a model calls
  the same trend read the `GET /api/v1/dex/perf/tag` / `get_dex_tag_app_perf`
  endpoints expose. The **Model** picker's own value list is the current fleet
  snapshot's device-model cohorts — the SAME population `GET
  /api/v1/dex/perf/cohorts?key=model` reports, so the two can never disagree —
  which means it lists device models **seen reporting performance in the
  current heartbeat cycle**, not every model ever tagged; a model with only
  retained historical data (no device of that model currently reporting) is
  omitted from the dropdown but can still be viewed directly by URL
  (`?model=<value>`). When the current fleet snapshot carries no device-model
  values at all — whether because no device is reporting this cycle, or
  devices are reporting but none carry a `model` tag — the picker shows an
  honest "Model: no device-model values in the current fleet snapshot." note
  instead of an empty or misleading selector (a genuine empty cohort list is
  never conflated with a degraded read — `fleet_snapshot` has no degrade
  channel). A **version filter**
  narrows the trend to one version at a time (the same `version` parameter the
  `GET /api/v1/dex/perf/app` / `/perf/group` / `/perf/tag` endpoints already
  accept); "all
  versions" is the default. Per-version crash/hang counts are not shown here
  yet (a separate central crash-store join, still deferred) — use the
  per-application crash/hang drill above for those.
  On the **fleet-wide** view (no management-group or device-model scope), each version row
  has a **&#9656; devices** affordance that expands in place to list the
  devices behind that number — `agent_id`, last-seen day, and that day's CPU /
  working set. This is a **top-N sample, not a census**: it lists devices
  where the exact app-version was among that device's own top resource
  consumers that day, not every device that has it installed (per-application
  sampling is opt-in and only retains the top-N heaviest processes per
  device) — use the [software inventory](inventory.md) for a full install
  census instead. It also reads a **shorter retention window** than the trend
  above: per-device data (B1) keeps 31 days, the fleet trend (B2) keeps 180,
  so clicking a version last seen more than a month ago can legitimately show
  no devices even though the trend row above it still shows aggregate
  history — the panel says so plainly rather than showing a bare "no data."
  Every row names an `agent_id`, so this drill is **audit-logged**
  (`dex.app_perf.devices.view`) and confined to the caller's own
  management-group / service-scope visibility, unlike the unaudited aggregate
  trend above it. The daily rollup that feeds this trend **excludes kernel
  threads** (Linux `PF_KTHREAD`, e.g. `kworker/*`) — unlike the live,
  per-device [procperf tier](tar.md) these devices still capture, where
  kernel threads remain visible (their zero working set keeps them out of the
  live working-set top-N, though a genuinely hot one can still surface in the
  CPU top-N as real signal; see the procperf row of the source-coverage
  table). A device
  upgraded across this change shows the old, unfiltered counts up to its last
  pre-upgrade day and the filtered counts from the day after — not a data
  glitch, just the two rollup versions meeting at the upgrade boundary. A
  userspace process whose name happens to collide with a kernel-thread name
  in one sampling tick loses that tick's contribution to the trend (diluted
  into the hourly bucket the collision landed in, not a whole-day or
  whole-app loss) — rare, since kernel-thread names are short and
  Linux-kernel-specific, but not impossible for an oddly-named binary. The
  `PF_KTHREAD` flag itself is read per-process from the real kernel flags
  bit, never derived from a name — but the per-tick rollup first groups
  every sampled process by NAME before deciding kernel-thread status, and
  OR's the flag across everything in that name group. A name collision
  therefore merges a real kernel thread and a same-named userspace process
  into one bucket, and the kernel thread's true flag marks the whole bucket
  excluded. This is accepted-by-design for accidental collisions and is
  **also the mechanism a local process could deliberately abuse**: an
  unprivileged process can rename itself to a live kernel-thread's name
  (e.g. `kthreadd`) via `prctl(PR_SET_NAME)` so its own CPU/memory activity
  lands in the same name-keyed bucket and rides the kernel thread's flag
  out of this rollup for that tick.
  A device already compromised enough to run an arbitrary renaming process
  has far cheaper ways to hide from an app-perf trend, so this does not
  raise the compromise's severity — but it means an *absence* of a process
  from this trend is not, on its own, evidence that nothing was running.
- **Per-device** — click a device to see its unified signal history (every
  signal type on one timeline, with friendly labels) plus a **device
  performance** panel: CPU, memory, and disk-latency sparklines built from the
  device's own hourly perf rollups. The panel is **click-to-load** and runs a
  **live, read-only TAR query on the device** when you load it — the raw
  samples stay in the on-device edge warehouse (federated model) until an
  operator asks, and merely viewing a device page never dispatches anything. It
  therefore needs the device online, the TAR perf sampler enabled, and (beyond
  `GuaranteedState:Read`) the **`Execution:Execute`** permission — without it
  the panel shows a note instead. Each query is audit-logged
  (`dex.device.perf.query`).

  Below the panel, **vs fleet & cohort strips** place the device's *current*
  heartbeat values against the current fleet p50–p90 band (the marker turns
  red above the fleet p90) and show its percentile position in the fleet and
  in its cohort — rendered live from registry state, no query dispatched, and
  the cohort comparison is withheld below the 10-device floor with an honest
  caption.

  A separate **Top applications** panel queries the device's opt-in per-app
  tier (`$ProcPerf_Hourly`, process **names only** — never command lines)
  behind its **own** "Load applications" click. Per-app data is usage-class
  telemetry — it observes what people run, not just how the machine behaves —
  so it carries its **own audit action (`dex.device.procperf.query`)**,
  keeping usage reads separately countable from machine-health reads. An
  empty result states plainly that per-app sampling is **off by default** on
  every device (or that no hourly rollup has completed yet) — the device's
  read-only query surface deliberately hides plugin config, so the server
  does not guess which. App rows cross-link to the per-application
  reliability drill.

  A third **Application performance over time** panel (behind its own "Load
  history" click) is the *retained* companion to the live Top-applications query:
  it reads the **central** Postgres B1 store (the daily per-app-version summaries
  the device ships on the daily sync, ≤31 days), so it runs **no live query** and
  needs **no Execute permission** — a read-only operator can open it. Each
  application is grouped with its **versions** as sub-rows, each carrying its own
  CPU-over-time sparkline and the window's sample-weighted avg / peak CPU and
  working set, so a per-version regression on this device reads straight off
  adjacent rows. It is the same behavioral-PII access class as the REST drill and
  carries the **same audit action (`dex.device.app_perf.view`)**; per-version
  crashes/hangs are a planned enrichment (a separate central crash-store join).
  When this panel's data cannot be read (the app-perf backing store is either
  not configured or degraded — the two are no longer distinguished), it shows
  "App performance data unavailable (not configured or degraded) — retry
  shortly." The **fleet-wide application performance** trend/app-list panel
  above shows the SAME unified wording on its own unwired-or-degraded path.
  The fleet-now Performance tab (the live heartbeat panel, unrelated to this
  retained B1/B2 surface) and the per-version "which devices" drill each keep
  their OWN unchanged, more specific wording ("no perf snapshot provider
  wired" / "no app-perf device provider wired" respectively) — only the two
  app-perf-over-time surfaces above collapsed to one message.
- **Per-signal-type** — from the Catalogue, open any type for its top subjects,
  live OS split, most-affected devices, and trend.
- **Per-observation** — click any row in a device's signal history to load the
  **event detail panel**: every captured projection field for that one event
  (subject, reason, symbolic name, component, metric, platform, exact timestamp,
  event ID). A point lookup bound to the event's own device — a guessed event ID
  scoped to the wrong device returns an opaque 200 placeholder (byte-identical to
  "no such event" — 200 so the htmx swap renders it). Each open is audit-logged
  (`dex.observation.view`, with the obs_type recorded for works-council
  countability).

> **Per-device history is behavioral data.** A device's signal history reveals
> which applications a person runs. Access is gated on `GuaranteedState:Read`
> and **every open is audit-logged** (`dex.device.view` for the signal-history
> view; the *Application performance over time* panel emits the distinct verb
> `dex.device.app_perf.view`, and the live per-app query emits
> `dex.device.procperf.query` — kept separate so usage-class reads stay
> separately countable). The same audit applies to the agent-scoped REST query
> `GET /api/v1/guaranteed-state/events?agent_id=…`. See the works-council /
> co-determination posture in `docs/enterprise-readiness-soc2-first-customer.md`.

## Agentic access (REST)

Every aggregation on this page has a machine-readable equivalent under
`/api/v1/dex/*` so an agentic worker sees the same DEX read-model the dashboard
does (agentic-first parity):

- **`GET /api/v1/dex/signals`** — the Catalogue rollup (every signal in the
  window: count, blast radius, last seen). Optional `os=windows|linux|macos`
  narrows to one OS's own signals (matching the dashboard's OS filter).
- **`GET /api/v1/dex/scope`** — the per-OS signal coverage that drives the
  cross-OS captions.
- **`GET /api/v1/dex/signals/{obs_type}`** — one signal's drill-down (subjects,
  OS split, most-affected devices, per-day trend). Optional
  `os=windows|linux|macos` scopes the subjects / devices / per-day lists to that
  OS (the `os` applied is echoed back); the OS-split view stays cross-OS by
  design, since that is the breakdown itself.
- **`GET /api/v1/dex/perf/fleet`** — the Performance tab's fleet-now stats
  (avg/p50/p90/max + n per metric, `null` when nobody reported it, plus the
  reporting/online denominators).
- **`GET /api/v1/dex/perf/cohorts?key=`** — the cohort benchmarking table
  (suppression and the untagged residual included in the response shape, plus
  `available_keys` for picker UIs).
- **`GET /api/v1/dex/perf/cohort-diff?key=&a=&b=`** — the direct A-vs-B cohort
  comparison (both cohort values required; `found_a`/`found_b`, the two cohort
  rows, and `delta_pct` with B as the baseline — null unless both clear the floor).
- **`GET /api/v1/dex/perf/devices?metric=&filter=&cohort_key=&cohort_value=`**
  — the one device list behind every Performance drill (worst-by-metric,
  not-reporting, cohort members).
- **`GET /api/v1/dex/perf/apps`** — the application-performance-over-time picker
  (apps with retained fleet data; `{app_name, versions, last_day}`).
- **`GET /api/v1/dex/perf/app?app=&version=`** — the fleet trend for one app, one
  point per `(version, day)` over the retained B2 window (≤180 days).
- **`GET /api/v1/dex/perf/app/devices?app=&version=`** — the version-row "which
  devices" drill: devices reporting one EXACT `(app, version)` among their
  retained top-N daily summaries (B1, ≤31 days), one row per device (`agent_id`,
  last-seen day, that day's CPU / working set). Unlike `/perf/app` above,
  `version` is **required** and matched exactly — there is no "all versions"
  form, and an empty string means the unknown-version bucket (the only bucket
  Linux agents report today), not "omit the filter." Confined to the caller's
  visible devices (ADR-0017), fail-closed audited
  (`dex.app_perf.devices.view`); a `truncated` flag means only the
  highest-CPU devices are returned.
- **`GET /api/v1/dex/perf/group?group_id=&app=&version=`** — the same trend for one
  management group's members (on-the-fly over B1, ≤31 days).
- **`GET /api/v1/dex/perf/tag?key=&value=&app=&version=`** — the same trend
  for one device-tag-value cohort (default `key=model`, e.g. one device
  model), on-the-fly over B1, ≤31 days. Same floor as `/perf/group` (a named
  tag-value cohort is a set of specific devices too); discover valid values
  for a key via `GET /api/v1/dex/perf/cohorts?key=` (its `cohorts[].cohort`
  field lists them) — this endpoint answers the trend for one already-known
  value.
- **`GET /api/v1/dex/devices/{id}/app-perf?app=`** — one device's retained per-app
  history (behavioral PII; scoped + audited fail-closed, `dex.device.app_perf.view`).

The signal endpoints take a `window` of `24h`/`7d`/`30d`/`all` (and the
catalogue rollup + per-signal drill-down additionally take the optional `os`
filter above, `all` when omitted); the
fleet-now/cohort perf endpoints are now-views (no window), while the
**application-performance-over-time** endpoints (`/perf/apps`, `/perf/app`,
`/perf/group`, `/perf/tag`) read **retained Postgres** data (≤180 days fleet /
≤31 days group or tag cohort), not a now-view. All are gated on
`GuaranteedState:Read`. The per-signal
drill-down returns a most-affected **devices** list (behavioral) and is
**audit-logged** (`dex.signal.view`) on every call, exactly like the dashboard
view; the rollup, scope, and true aggregate perf endpoints (`/perf/fleet`,
`/perf/cohorts`, `/perf/cohort-diff`, `/perf/apps`, `/perf/app`, `/perf/group`,
`/perf/tag`)
are machine-health telemetry / fleet metadata and are not audited — and the
app-perf aggregates suppress any sub-floor `(version, day)` point (fewer than
10 devices) to a count only. **`/perf/devices` and `/perf/app/devices` are the
exceptions**: each row names an `agent_id` fleet-wide (or, for `/perf/app/
devices`, the caller's visible subset), so unlike their aggregate siblings
they ARE audited — `/perf/devices` as `dex.perf.device.view` (fail-closed,
denies a service-scoped API token outright), `/perf/app/devices` as
`dex.app_perf.devices.view` (fail-closed, admit-then-filter confined instead
of an outright service-scoped deny — see routed-concerns.md's DEX row for
why the two device-fan-out routes take different confinement shapes). The
per-device app-perf drill IS also audited (`dex.device.app_perf.view`,
fail-closed). The aggregate reads are exposed as
MCP tools (`list_dex_signals`,
`get_dex_signal_scope`, `get_dex_signal_detail`, `get_dex_perf_fleet`,
`get_dex_perf_cohorts`, `get_dex_perf_cohort_diff`, `list_dex_perf_devices`,
`list_dex_perf_apps`, `get_dex_app_perf`, `get_dex_group_app_perf`,
`get_dex_tag_app_perf`); the
version-row devices drill has its own MCP twin `list_dex_app_perf_devices`
(same `dex.app_perf.devices.view` audit, set-and-proceed on MCP); the
per-device app-perf drill is exposed via REST **and** the dashboard device drill
(the "Application performance over time" panel, same `dex.device.app_perf.view`
audit) but has **no MCP twin** (MCP's set-and-proceed posture can't express the
REST fail-closed contract). Full request/response
shapes are in [`rest-api.md`](rest-api.md#dex-digital-employee-experience) and
`GET /api/v1/openapi.json`.

## Platform coverage

The **Windows** collector is the most complete — it covers the full Windows
signal catalogue. Alongside the event-log observer, Windows also runs a
**state poll** that emits `storage.low` (a fixed volume ≥90% full or under
5 GiB free) and battery health (`hw.error`, when full-charge capacity drops
below 80% of design) — the same two signals, and the same thresholds, the
macOS collector emits, so they render identically across both platforms. The
same poll also watches for **sustained performance breaches** (the
"Performance" family): `perf.cpu_sustained` (≥90% busy for 10 minutes),
`perf.memory_pressure` (commit charge ≥90% of limit for 10 minutes), and
`perf.disk_latency_high` (average ≥25 ms per IO for 10 minutes). Each fires
**once** per episode with the window average as its metric and re-arms only
after a sustained recovery, so a flapping metric cannot spam the feed;
thresholds are fixed in this release (operator-configurable thresholds are the
F1 follow-up, same as the blast-radius detector's). A
**macOS** collector ships too, but is deliberately *limited*: an unprivileged
collector that reuses the same OS-neutral signal types and covers roughly ten
of the eleven experience headings (crashes and hangs, resource pressure,
service failures, boot/resume reports, storage pressure, battery health, and
more). A **Linux** server collector ships too, reusing the same signal types across
several mechanisms: a `/proc` performance poll (sustained CPU, memory-commit pressure,
and `/proc/diskstats` disk-latency breaches — the same hysteresis as Windows), a
`statvfs` storage poll, a `/sys` CPU-thermal-throttle poll, and a **journald** reader
whose kernel-transport (`/dev/kmsg`) lines are classified into existing signal types
(kernel panic, machine-check errors, filesystem corruption, disk errors, dirty
shutdowns, hung tasks, the OOM-killer) alongside structured unit crash/hang and
clock-unsync records. So Linux servers light not only the Performance and Hardware/
storage views but also App reliability, Service health, System stability, and File
system; workstation-only headings (battery, Wi-Fi, display, GUI) are **N/A on headless
servers**, not gaps. `storage.low` uses a fixed
5 GiB-free floor (small cloud/VM root volumes can read as low until the F1
configurable thresholds land), and inside an unmodified container `/proc` reflects
the *host*, so the collector targets host/VM deployment. Because the by-OS and cross-OS views
label each OS with its live *signal scope*, a fleet running a narrower collector
reads as **less observed**, never as healthier; the rates are read *within* an
OS, never across. The exact macOS source mapping — and what additional fidelity
the Endpoint Security Framework or other entitlements would unlock — is in
[`docs/dex-signal-catalog.md`](../dex-signal-catalog.md).

## Fleet incident alerts (blast radius)

Beyond the per-signal drill-downs, the server watches for a single failure
*spreading across the fleet*. When **≥5 distinct devices** report the same DEX
signal — the same `obs_type` **and** the same subject (e.g. `process.crashed` /
`chrome.exe`) — within a **15-minute** sliding window, it raises a fleet
incident. Detection runs at the shared observation ingest point, so both
directly-connected and gateway-routed agents contribute, and the window uses
server receipt time (an agent with a skewed clock cannot smear it).

Each incident fires two things:

- an **operator notification** (dashboard bell, severity `warn`), and
- a **`dex.blast_radius`** webhook / offload event you can subscribe to so an
  ITSM auto-opens the incident.

`dex.blast_radius` payload:

| Field | Meaning |
|---|---|
| `obs_type` | the signal type (e.g. `process.crashed`) |
| `subject` | the failing entity (e.g. `chrome.exe`; empty for subject-less signals) |
| `device_count` | distinct devices that reported the pair within the window |
| `window_seconds` | the detection window (900 for the 15-minute default) |

A standing incident re-alerts at most once per cooldown period (per-pair), and
a global per-minute fan-out cap keeps a correlated multi-subject incident (e.g.
a bad update crashing many apps at once) from flooding your ITSM. The
thresholds (default **5 devices / 15 min window / 1 h cooldown**) are
**operator-tunable under Settings → DEX alerts** and apply immediately — no
restart. The memory and fan-out bounds are not configurable (they are DoS
posture, not policy). Detector activity is observable via the
`yuzu_server_dex_blast_radius_*` Prometheus metrics. Subscribe to the event in
[Webhooks](rest-api.md#event-subscriptions-webhooks).

## Routing signals to alerts

Beyond fleet incidents, you can route **individual signal types** to alerts
under **Settings → DEX alerts**: tick the types you care about (grouped by the
same families as the Catalogue) and each routed observation raises an operator
notification and fires the **`dex.signal`** webhook/offload event
(`obs_type`, `subject`, `agent_id`) — **once per device per hour** per type, so
a flapping device cannot spam, with a global per-minute fan-out cap underneath.
**Nothing is routed by default**; blast-radius incidents always alert
regardless. Good candidates are the low-volume, high-meaning types — the
`perf.*` sustained breaches (already latch-bounded at the agent),
`os.bugcheck`, `disk.smart_failure`, `security.rtp_disabled`. Routing a chatty
type (e.g. `process.crashed` on a large fleet) is safe for the server but
noisy for you. Changes apply live and are audit-logged
(`settings.dex_alerts.routing`); router activity is observable via the
`yuzu_server_dex_alert_fired_total`, `yuzu_server_dex_alert_delivery_failed_total`,
`yuzu_server_dex_alert_suppressed_total`, `yuzu_server_dex_alert_dropped_total`,
`yuzu_server_dex_alert_cooldowns_evicted_total`, and
`yuzu_server_dex_alert_routed_types` Prometheus metrics. The A3 perf-breach
*thresholds* themselves (90 % CPU / 10 min etc.) remain fixed agent-side in
this release — server-to-agent threshold distribution is a planned follow-up.

## Fleet performance rollup (Prometheus)

Each Windows agent ships its current utilization — CPU busy %, commit-charge %
of limit, and per-IO disk latency, derived over its heartbeat interval — as
heartbeat tags. The server aggregates the latest value from every reporting
agent into fleet gauges on `/metrics`:

| Gauge | Meaning |
|---|---|
| `yuzu_fleet_perf_reporting` | how many agents contributed this cycle (read the others against this population) |
| `yuzu_fleet_perf_cpu_pct{stat}` | fleet CPU busy %, `stat` = `avg` / `p50` / `p90` / `max` |
| `yuzu_fleet_perf_commit_pct{stat}` | fleet memory pressure (commit % of limit), same stats |
| `yuzu_fleet_perf_disk_lat_ms{stat}` | fleet per-IO disk service time in ms, same stats |

When no agent reports a metric the series goes **absent**, never a fabricated
zero. Values are validated server-side (non-finite and negative readings are
rejected; percentages clamp at 100) so a single misbehaving agent cannot poison
a fleet percentile. Agents with `--dex-disable` ship no perf tags at all.

**Per-cohort export (opt-in).** Setting a **cohort export tag key** in
Settings → DEX alerts additionally publishes the same stats per cohort of that
key:

| Gauge | Meaning |
|---|---|
| `yuzu_fleet_perf_cohort_cpu_pct{cohort,stat}` | per-cohort CPU busy %, same `stat` labels |
| `yuzu_fleet_perf_cohort_commit_pct{cohort,stat}` | per-cohort memory pressure |
| `yuzu_fleet_perf_cohort_disk_lat_ms{cohort,stat}` | per-cohort disk latency |
| `yuzu_fleet_perf_cohort_reporting{cohort}` | reporting devices per exported cohort |
| `yuzu_fleet_perf_cohort_clipped` | exportable cohorts dropped by the cardinality cap (a measured 0 when nothing was cut; absent when the export is off) |

Cardinality is bounded by design: only cohorts with **≥ 10 reporting devices**
export, capped at the **top 50 by population**, and clipping is visible via
the `_clipped` gauge rather than silent. Devices without the key export as
`cohort="(untagged)"`. The export refreshes on the same sweep — and through
the same validation — as the fleet gauges, so Grafana, the REST API and the
Performance tab can never disagree about the same heartbeat sample. The key is
empty (export disabled) by default; per-device and per-app data are **never**
exported to Prometheus — reach those via the REST endpoints on demand.

## Turning it off

DEX collection is a **deploy-time agent setting**. Start the agent with
**`--dex-disable`** (or `YUZU_AGENT_DEX_DISABLE=1`) and that endpoint arms no
observer and sends no DEX telemetry of any kind. **Note:** `--dex-disable` turns
off the DEX event observer, the Windows state poll, and the heartbeat perf
tags (the fleet rollup above), but the TAR performance
sampler is a separate subsystem — disable it with `perf_enabled=false` (see
[TAR configuration](tar.md#configuration)). There is no server-side runtime
toggle today; per-category collection toggles and an individual-view kill switch
are named roadmap items (see the enterprise-readiness plan).

## No mock data

Every view renders real aggregations or an explicit "no data" placeholder —
never sample or fabricated values. A zero is a measured zero, and a rate with no
denominator shows **—**, not a guess.

## Recovery — empty or stale DEX projection

`guardian_observations` (the table behind `/dex`) is a **derived, forward-only
read model** projected from the Guardian event store; it holds no source data of
its own. If the server logs a stale-schema warning (a dev/UAT database that ran
a pre-release build) or the projection is otherwise corrupt, the projection
degrades safely — the underlying events are preserved and
`yuzu_server_guardian_proj_failures_total` rises — and recovery is:

1. Stop the server.
2. `sqlite3 <data-dir>/guaranteed-state.db "DROP TABLE guardian_observations;"`
3. Restart — the table is recreated empty and projection resumes **forward only**.

There is no automatic back-fill today: projected history before the drop is not
reconstructed (a back-fill script from the retained source events is a tracked
follow-up). The Guardian event store and rules are unaffected by this operation.

## Related documentation

- [Guaranteed State (Guardian)](guaranteed-state.md) — the underlying event
  store, the observer, and `--dex-disable`.
- [`docs/dex-signal-catalog.md`](../dex-signal-catalog.md) — the full
  signal catalogue (channels, event IDs, extracted fields, privacy
  minimisations, macOS source mapping).
- `docs/enterprise-readiness-soc2-first-customer.md` — behavioral-telemetry
  data inventory and works-council / DPA posture.
