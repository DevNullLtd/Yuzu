# TAR Dashboard — Operator Page Design

**Status:** Design + partial ship (PR-A.A shipped 2026-04-26: page shell + retention-paused list + Scan / Re-enable; **typed-confirmation Purge shipped 2026-07-01** — dashboard fragment + `POST /api/v1/tar/retention-paused/purge`, §3.4; persistence still deferred. **PR-H shipped 2026-06-18: process tree viewer, as-built §5 — local-TAR-data-only.** See `docs/roadmap.md` Phase 15.)
**Audience:** Server engineers, dashboard UI engineers, TAR plugin maintainers
**Owners:** `architect` (page architecture), `plugin-developer` (TAR action surface), `security-guardian` (SQL execution surface), `docs-writer` (DSL + REST docs)
**Related:** `docs/scope-walking-design.md` (the cross-cutting result-set primitive this page consumes), `docs/yuzu-guardian-design-v1.1.md` (the agent tamper-resistance pillar that the process tree viewer's data quality depends on), `agents/plugins/tar/` (the data plane).

---

## 1. Why a dedicated TAR page

The Timeline Activity Record (TAR) plugin is one of the **highest-leverage operator surfaces** in Yuzu — it answers the "what happened on this machine" question that drives forensics, compliance, and reactive IR. Today it is reachable only via the generic instruction-launch flow and the `/fragments/tar-sql` HTMX fragment embedded in another page; the surface area is large but the affordances are scattered. Operators repeatedly asked "where do I go to *do TAR*" — the answer needs to be a single dashboard page.

The page is also the home for several affordances that did not have anywhere to live:

1. **Retention-paused source list** — the operator-facing view of `<source>_enabled=false` per device, born from issue #539. Without it, an operator who disabled `process_enabled` on a device for forensic preservation has no aggregate view of which boxes are accumulating non-aging data.
2. **Process tree viewer** — reconstructed per-host from that host's local TAR warehouse (`$Process_Live` + `$TCP_Live`) only, with no seed (as-built; see §5). Forensic timeline of every process born under a parent over a chosen window, with an honest "no-seed" completeness caveat (Windows is names-only). **The pane also embeds device-level DNS-cache + ARP-table panels (ADR-0015)** — dispatched read-only `tar.sql` over `$DNS_Live`/`$ARP_Live` to the selected host, rendered beside the tree. These are **device views, not per-process** (the DNS cache carries no pid); they audit `tar.dns.read` / `tar.arp.read` (DNS is usage-class PII, separately countable).
3. **Capture sources frame (ADR-0015)** — a per-device toggle table for every TAR capture source, with a category filter and a **staged-then-push guardrail**: toggling a source only *stages* the change; nothing is dispatched until the operator clicks **Push** (guards against accidentally enabling a usage-class source). Reads `tar status` + `tar compatibility`; Push dispatches `tar configure <source>_enabled` per change (audited `tar.sources.read` / `tar.sources.configure`). The same configure path is reachable via MCP/REST `crossplatform.tar.configure`.

The page is also the surface where **scope walking** (per `docs/scope-walking-design.md`) becomes most visibly useful — the TAR SQL frame is the canonical iterative-narrowing tool, and result-set chips on this page are the operator's reasoning chain made visible.

## 2. Information architecture

```
 Dashboard ──────────────────────────────────────────────────────────────────
 │
 ├─ Devices       (existing)
 ├─ Inventory     (existing)
 ├─ Instructions  (existing)
 ├─ Policies      (existing)
 ├─ TAR           (new — this page) ──────────────────────────────────────────┐
 │                                                                            │
 │  /tar                                                                      │
 │  ┌────────────────────────────────────────────────────────────────────┐    │
 │  │  [Scope chip ▼]  windows-chrome-suspects · 2,798 devices · pinned  │    │
 │  │  ─── lineage breadcrumb (per scope-walking §8.2) ────────────────  │    │
 │  └────────────────────────────────────────────────────────────────────┘    │
 │  ┌─ Retention-paused sources (PR-A) ──────────────────────────────────┐    │
 │  │   device              source     paused since   live rows  oldest  │    │
 │  │   prod-eu-1 (Linux)   process    2026-04-25      18,402   31d 4h   │    │
 │  │   prod-eu-1 (Linux)   tcp        2026-04-25       4,193   31d 4h   │    │
 │  │   ...                                                              │    │
 │  │   [Re-enable]  [Purge data]  [Export CSV]                          │    │
 │  └────────────────────────────────────────────────────────────────────┘    │
 │  ┌─ TAR SQL (PR-D, scope-walking-aware) ──────────────────────────────┐    │
 │  │   $TAR  > SELECT name, COUNT(*) FROM process_hourly GROUP BY name  │    │
 │  │   [Run scoped to: windows-chrome-suspects]                         │    │
 │  │                                                                    │    │
 │  │   results... (streamed)                                            │    │
 │  │   [Save as result set ▼ "chrome-procs"]                            │    │
 │  └────────────────────────────────────────────────────────────────────┘    │
 │  ┌─ Process tree viewer (PR-H) ───────────────────────────────────────┐    │
 │  │   device: [pick from scope ▼]                                      │    │
 │  │                                                                    │    │
 │  │   1   systemd                                                      │    │
 │  │   ├── 234   sshd                                                   │    │
 │  │   │   └── 1402  bash (user=alice)                                  │    │
 │  │   │       └── 1419  python3 train.py  ← still running              │    │
 │  │   ├── 412   docker                                                 │    │
 │  │   │   ├── 998   containerd                                         │    │
 │  │   │   └── ...                                                      │    │
 │  │   ├── 814   yuzu-agent  (★ self)                                   │    │
 │  │   ...                                                              │    │
 │  │   Tree as observed since 2026-04-12 09:14 UTC (agent install)      │    │
 │  └────────────────────────────────────────────────────────────────────┘    │
 │                                                                            │
 ├─ Settings      (existing)                                                  │
 └────────────────────────────────────────────────────────────────────────────┘
```

URL structure:

| Path | Purpose | Required permission |
|---|---|---|
| `/tar` | The page | `Infrastructure:Read` |
| `/fragments/tar/retention-paused` | HTMX fragment for the paused-sources table | `Infrastructure:Read` |
| `/fragments/tar/sql` | (existing, relocated) HTMX fragment for the SQL frame | `Infrastructure:Read` + dispatch |
| `/fragments/tar/process-tree` | HTMX fragment for the tree viewer | `Infrastructure:Read` |
| `/api/v1/tar/retention-status` | JSON: per-device per-source enabled/disabled | `Infrastructure:Read` |
| `/api/v1/tar/process-tree/{device_id}` | JSON: reconstructed tree for one device — **DEFERRED, not implemented (§5.6)**; the shipped viewer is HTMX-fragment-only | `Infrastructure:Read` |

## 3. PR-A — Retention-paused source list

**Goal:** every device × source pair where `<source>_enabled=false`, surfaced in a sortable, filterable, exportable table, with one-click re-enable and an explicit "purge data" action gated behind a typed-hostname confirmation.

### 3.1 Data flow

The source of truth is the agent's `tar_config` table — the `<source>_enabled` keys, set by the `tar.configure` action. The server does not currently maintain a centralised "TAR config" mirror; the data path is **request-driven**:

1. Page load fans out `tar.status` (extended in PR-A to emit the four `<source>_enabled` values + the `<source>_live_rows` count + `<source>_oldest_ts` per source) to every device the page's scope resolves to. Scope is the active scope chip (default `__all__` for fresh page load).
2. Responses stream back via the standard agent-streaming pipeline.
3. Server collates into a transient in-memory table; renders as HTMX OOB swaps.
4. Empty rows (`enabled=true` for all four sources) are dropped — the table only shows the *paused* state, not the entire fleet.

**Tri-state enabled values + dedup (#560/#558/#561).** The `<source>_enabled` value is read as a tri-state: `true` → dropped (collecting normally); `false` → normal paused row; **any other value** (`errored` from a corrupt/tampered agent DB, or garbage) → a **value-error badge** row showing the reported value (it is NOT silently dropped — that would hide a paused/broken source). A disabled source with `paused_at == 0` (a pre-v0.12.0 agent) renders a **"schema older than server" badge** and sorts as the oldest (top), instead of a bare `—` sunk to the bottom. Both value-error and unknown-`paused_at` rows float to the top. Before parsing, responses are **deduplicated to the most-recent per agent by the server-stamped `received_at_ms`** (never the agent-claimed `timestamp`, which a compromised agent could backdate to hide its state) — bounding render cost to O(agents × sources) against a response-spam DoS. The complementary store-side per-`(command_id, agent_id)` cap is a tracked follow-up.

This avoids a new persistent server-side mirror, which would have to be reconciled with agent state on every config change. The trade-off is a 5-15s page-load cost on a large fleet; mitigated by:
- Scope-restricted queries (the operator usually narrows first via a result set)
- Manual **Refresh** button for ad-hoc re-fan-out (automatic background refresh is planned for Phase 15.G operational hardening)
- Manual "Refresh" button for ad-hoc re-fan-out

### 3.2 Extending `tar.status`

The action's response gains four lines per source (so 16 new lines total for the 4 sources):

```
config|process_enabled|true
config|process_live_rows|18402
config|process_oldest_ts|1730000000
config|process_paused_at|0           # 0 = never; otherwise the ts when last set to false
config|tcp_enabled|false
config|tcp_live_rows|4193
config|tcp_oldest_ts|1733000000
config|tcp_paused_at|1735689600
...
```

`config|<source>_paused_at|...` is **new** — it requires the `do_configure` handler in `tar_plugin.cpp` to write this timestamp whenever it transitions a source from enabled to disabled (and clear it on the reverse). This is the operator-facing "paused since" column and is only meaningful at the server's wall-clock. Backwards-compatible — if the field is absent, the dashboard renders `—` and falls back to "unknown."

### 3.3 Re-enable action

Single-row "Re-enable" button → confirm modal → server dispatches `tar.configure` with the appropriate `<source>_enabled=true` to the named device. On success, the row drops out of the table on the next refresh; on failure the row turns yellow with the error tooltip.

Per-source independence (the #539 invariant) means re-enabling one source on a device does not touch the other three — the dispatched parameter is per-source.

### 3.4 Purge action

The "Purge data" button on a row is more dangerous than re-enable — it tells the agent to drop every row from `<source>_live`, `<source>_hourly`, `<source>_daily`, `<source>_monthly` for that source, *without* re-enabling the collector. The use case is "we paused process collection 8 weeks ago for forensic preservation; we have what we need, the disk is filling up, drop the rows but keep the collector paused."

Server dispatches a new agent action `tar.purge_source` with `{source: <name>}`. The action is gated behind a typed-hostname confirmation ("type the device hostname to confirm purge of `process` data"), per the destructive-action discipline in the project root `CLAUDE.md`. Audit row: `action: tar.source.purge, principal: <session>, result: success|failure, detail: device=<id> source=<name>` — the dispatch audit row does **not** carry `rows_deleted` (see the as-shipped note below).

> **As shipped (Phase 15.A, 2026-07-01).** Route `POST /fragments/tar/retention-paused/purge`; audit verb `tar.source.purge` (matching the `tar.source.reenable` sibling); metric `yuzu_tar_source_purge_total{result}`. The typed confirmation is a native `prompt()` ("type the device hostname"), not a bespoke modal — CSP-safe (no `hx-on`/eval), consistent with the native `confirm()` used for re-enable. **The paused-guard is agent-side and authoritative:** `tar.purge_source` refuses (`source_not_paused`) if the source is currently enabled, which closes the scan→purge TOCTOU. The server does **not** enforce a `SOURCE_NOT_PAUSED` check (§3.5) because the retention-paused frame is an ephemeral live scan with no persisted paused-state to check. Dispatch is fire-and-forget, so `rows_deleted` is computed agent-side and returned in the response record — it is not in the immediate dispatch audit row.
>
> **A1 REST parity + generic-dispatch hardening (2026-07-01).** Automation/MCP callers use the structured `POST /api/v1/tar/retention-paused/purge` (JSON body `{device_id, source}`, `Infrastructure:Delete` per-device-scoped, A4 error envelope, `202` + `command_id`; audited fail-closed — no dispatch without a durable audit row). Both the fragment and the REST route confirm the guard is agent-side authoritative. The generic `POST /api/command` escape hatch now also elevates destructive actions: `tar.purge_source` there additionally requires `Infrastructure:Delete` and is confined to the caller's visible agents with untargeted broadcast/scope fan-out refused, so it can't be a weaker path than the dedicated route. The atomic agent-side guard (check + delete under one lock) closes the agent-local check→delete race in addition to the scan→purge TOCTOU.

### 3.5 Permissions and safety

- View-only access requires `Infrastructure:Read`.
- **Scan fleet** requires `Execution:Execute` (it dispatches a fleet-wide command — same tier as `run-instruction` and `tar-execute` siblings).
- **Re-enable** requires `Execution:Execute` and the operator's RBAC visibility on the target device. Out-of-scope `device_id` values collapse to the same 404 response as not-connected agents (no enumeration oracle); the audit log records the real reason server-side.
- Purge requires `Infrastructure:Delete` on the target device (a higher tier than re-enable's `Execution:Execute`), plus the operator's RBAC visibility on the device (same 404-collapse as re-enable). The paused-state guard is **agent-side and authoritative**: `tar.purge_source` refuses (`source_not_paused`) unless the source currently reports disabled, which closes the scan→purge TOCTOU and prevents purging an actively-collecting source. The server does **not** enforce a `SOURCE_NOT_PAUSED` check — the retention-paused frame is an ephemeral live scan with no persisted paused-state to check, so the authoritative guard lives on the agent that owns the data (see §3.4). The agent action validates `source` against the full capture-source registry; the server route additionally restricts it to the four retention-frame sources `{process, tcp, service, user}`.

### 3.6 Tests

- Server-side: unit tests for the aggregation/render path against synthetic `tar.status` responses (paused-only, all-paused, none-paused, partial response).
- Agent-side: extends `tests/unit/test_tar_aggregator.cpp` (the suite added for #539) with a config-roundtrip test for `<source>_paused_at` write-on-disable / clear-on-enable.
- Integration: stand up the UAT stack, disable a source on a synthetic agent, confirm the row appears in the page within one refresh tick, click re-enable, confirm the row drops.

## 4. PR-D — TAR SQL frame, scope-walking-aware

The frame body is largely the existing `/fragments/tar-sql` route (`server/core/src/dashboard_routes.cpp:500`). PR-D moves it onto the new page and wires it into the result-set primitive (`docs/scope-walking-design.md`):

1. **Scope chip** in the frame header — operator picks an active result set (or a standard scope) before submitting. The dispatch resolves `from_result_set:<id>` to the device-ID set per `scope-walking-design.md` §4.
2. **"Save as result set" button** on the results pane — after a query returns, operator clicks "Save as result set," names it, and the server creates a new result set (`source_kind=tar_query`) with member IDs equal to the union of agents that returned ≥1 row. Default name is `tar-<first-five-chars-of-sql-hash>` so the operator can save without typing.
3. **Lineage breadcrumb** above the frame mirrors the active scope chip's lineage (`scope-walking-design.md` §8.2).

No changes to the `tar.sql` agent action; the change is purely server-side scope resolution + result-set persistence.

## 5. PR-H — Process tree viewer (**as-built**)

> **Deviation from the original seed-based design below (kept for history).** What
> shipped reconstructs the tree from **the agent's existing local TAR warehouse
> only** (`$Process_Live` + `$TCP_Live`, queried via the read-only `tar.sql`
> action) — there is **no agent-side seed action, no `action='seed'` rows, no
> `__checkpoint__` rows, and (until #4027) no `/api/v1/tar/process-tree` REST
> surface at all**. #4027 added `GET /api/v1/tar/process-tree` as the frame's
> device-PICKER list twin only (§5.6) — the per-device reconstructed-tree JSON
> surface this paragraph is about remains deferred. This was
> a deliberate scope choice (local-TAR-data-only); the consequence is an honest
> completeness limit (see "Honesty" below). Modules: server engine
> `server/core/src/tar_process_tree.{hpp,cpp}` (pure, unit-tested), routes
> `server/core/src/tar_tree_routes.{hpp,cpp}`, page `tar_page_ui.cpp` Frame 3.

### 5.1 Reconstruction model (as-built)

- The viewer dispatches two canned, **read-only** `tar.sql` queries to ONE selected
  live host — `SELECT … FROM $Process_Live` and `… FROM $TCP_Live` — through the
  same dispatch-and-poll seam the device-page "Get live info" uses (untracked
  dispatch, `execution_id=""`, so it never enters the executions drawer). The agent
  runs them on its read-only authorizer connection (#760/#631).
- The agent forbids recursive CTEs, so the tree is reconstructed **server-side in
  C++** from the flat event rows: per-pid alive-intervals are built from the
  `started`/`stopped` stream, incarnations whose lifetime overlaps the chosen window
  `[from, to]` are kept (PID-reuse-safe — each lifetime is its own node), and each is
  linked to the parent incarnation that owned its `ppid` when it started. Orphans
  (parent not present / `ppid` 0 / start event aged out) become roots. Cycle- and
  50k-node-cap guarded.
- **Timescale controls.** Preset chips — **On boot · On agent install · Last minute
  · Last 10m · Last hour · Last day** — plus a **custom From/To (UTC)** box.
  Point-in-time is the `from == to` case. `to` is the upper bound (running-vs-exited
  is decided at `to`); the SQL fetch lower bound stays oldest-retained so a
  long-running process started before the window still appears. **`On boot` and
  `On agent install` are TAR-derived proxies** (TAR has no boot/install-time column):
  install = `MIN(ts)` over retained rows; boot = the most-recent start of a root
  process (`ppid==0`), falling back to install.

**Honesty in framing.** Banner reads e.g. `Window <from> → <to> · observed since
<oldest-retained> · 411 nodes (281 running / 130 exited) · 0 flagged`, with a note
that — because there is **no seed** — a process whose `started` event has aged out of
the 100k `$Process_Live` cap (or that predates the oldest retained row) may not
appear, and that the boot/install anchors are proxies. On **Windows the feeder is
ETW (names-only)** so per-process path and command line are blank (stated inline);
they are populated on Linux/macOS.

### 5.2 Filtering, grouping, network (client-side display)

Reconstruction always returns the **full** tree; display filtering is client-side
(instant, no re-dispatch — each row carries `data-state`/`data-anom`):

- **State filter** — All / Running / Exited chips.
- **Anomalies only** — toggle (the sole heuristic is a **suspicious parent→child**
  name-pair denylist, e.g. an office app or browser spawning a shell/LOLBin; flagged
  server-side, name-based so it works on Windows).
- **Text filter** — matches name / PID / **remote IP**.
- All three combine, reveal+expand the ancestor branches of matches, and are
  re-applied after every tree swap (`htmx:afterSettle`).
- **Same-name grouping** — 4+ identical-name siblings collapse into one
  `name ×N (R running · E exited)` row (e.g. `svchost.exe ×106`), expandable to the
  individual PIDs (each still drill-able). Filters auto-expand groups with matches.
- **Inline network** — each row shows its `$TCP_Live` connections joined by pid:
  a count + remote `IP:port` endpoints (public/routable egress highlighted amber;
  listeners shown as `:port listen`). Full connection table is in the detail panel.

### 5.3 Layout & detail panel

Two-column: a scrollable tree on the left and a **sticky, always-visible detail
panel on the right** (stacks below on narrow viewports). Clicking any process row
hx-gets `/fragments/tar/process-tree/detail` into the right panel — name, PID, parent
PID, user, running/exited + start time, path + command line (blank-with-note on
Windows), the process's connections, and anomaly evidence. The detail renders from a
**server-side reconstruction cache** (bounded LRU, 180 s TTL, keyed by a CSPRNG token —
`secure_random::random_hex`, never `mt19937`) so row clicks need no further agent
round-trip. The cache entry is **bound to the operator who created it**: `detail`
fails closed unless the requesting session matches, so a predicted or leaked token
can't be replayed by a different operator (transparent to the normal same-session
flow). If secure token generation fails (entropy exhaustion), `result` returns an
in-panel error and caches nothing rather than minting a weak token.

### 5.4 Routes

| Route | Purpose |
|---|---|
| `GET /fragments/tar/process-tree` | Frame body: host picker (operator-scoped) + timescale + filter bar + tree/detail targets |
| `GET /fragments/tar/process-tree/run?device=&preset=&from=&to=` | Resolve window, dispatch the two `tar.sql`, return the polling fragment |
| `GET /fragments/tar/process-tree/result?…&pcmd=&tcmd=&n=` | Poll both commands, reconstruct, cache, render the tree |
| `GET /fragments/tar/process-tree/detail?token=&node=` | Render one node's detail from the cache (re-checks scope **+ Execute + originating principal**) |

### 5.5 Permissions & audit

- Viewing the frame: `Infrastructure:Read`.
- **Reconstructing dispatches a live `tar.sql`**, so `run`/`result` also require
  `Execution:Execute` **and** the per-device management scope
  (`require_scoped_permission`) — same posture as the TAR SQL frame and the device
  live-info probe. (This tightens the original "`Infrastructure:Read` to view"
  framing, which assumed a stored, non-dispatching tree.)
- `detail` holds the **same tier as the reconstruction** — it re-checks
  `Infrastructure:Read` **and** `Execution:Execute` scoped to the cached device, **and**
  binds to the originating principal. So a leaked/predicted token can neither cross
  management scope, downgrade the Execute tier (read behavioral detail an operator
  couldn't reconstruct themselves), nor be replayed under a different session.
- `$Process_Live.cmdline` is already redaction-applied at capture by the agent, so no
  server-side re-redaction is needed; all agent-controlled fields are HTML-escaped.
- Agent output is byte-capped before parse (16 MiB process / 4 MiB TCP, defense in
  depth over the gRPC message bound); the `tar.sql` query interpolates only an
  `int64` upper-bound timestamp (no string concat — see the load-bearing comment at
  the query site).
- Audit `tar.process_tree.read` fires twice (parity with `device.live.*`): a
  **dispatch** row when the live query is sent (recorded even if the device is offline
  or the poll never completes) and a **success** row after the tree renders; a
  **failure** row (`csprng_unavailable`) if secure token generation fails. The device
  is the `target_id` (not in `detail`); the success `detail` is
  `preset=… from=… to=… nodes=… anomalies=… os=… conns=…` (`preset` canonicalized to a
  fixed allowlist and `os` normalized to `{windows,linux,macos,?}` so neither can forge
  an audit field; `conns=1` flags that per-process connection data was shown). Each
  `detail` drilldown emits a `tar.process_tree.detail` row (`node=… os=…`). See
  `docs/user-manual/audit-log.md`.

### 5.6 Deferred

- **Agentic-first REST/MCP parity for the reconstruction itself** — a JSON
  surface returning the PER-DEVICE reconstructed tree (`{device_id}` in the
  path, the `/result`+`/detail` fragments' data) — remains deferred. #4027
  (API-parity programme) shipped REST+MCP twins for the OTHER three TAR
  fragment reads — the process-tree and capture-sources device PICKER lists
  (`GET /api/v1/tar/process-tree` / `GET /api/v1/tar/capture-sources`, no
  `{device_id}` segment — distinct routes from the still-deferred one above,
  no path collision) and the retention-paused source list (`GET
  /api/v1/tar/retention-paused`) — plus MCP tools `list_tar_process_tree_devices`
  / `list_tar_capture_sources_devices` / `list_tar_retention_paused`. #4027
  deliberately did NOT twin `/fragments/tar/process-tree/result` or `.../detail`
  — deferred as scope, not impossibility. `/detail`'s cache `token` is a CSPRNG
  value minted and principal-bound only inside the `/result` handler itself, so
  a `/detail` twin genuinely has no usable input today. `/result`'s `pcmd`/`tcmd`
  pair is an ordinary `tar sql` dispatch result (`Infrastructure:Read`, no
  execute gate) reachable in principle through the already-twinned generic
  dispatch surface (`execute_instruction` / `POST /api/command`) by reproducing
  the two canned `$Process_Live`/`$TCP_Live` queries verbatim — not a dedicated
  API path, and a real twin would still need a new async polling contract (no
  htmx auto-reissue on REST/MCP). Both are otherwise minted only by the
  dashboard-only `/run` route, itself excluded as dispatch-shaped (batched with
  #3994). Revisit once a `/run` (and `/result`) twin lands — see
  `scripts/ci/api-parity/tar.json`'s `exception:` rows on those two paths.
- **Loaded modules / libraries** — out of scope: TAR records no module-load data; it
  would need a new collector (ETW `Image`/`Load`) or a live modules probe.
- **Seed snapshot** (the original §5.1 below) — intentionally not built; revisit only
  if the no-seed completeness limit proves insufficient in the field.

---

<details><summary>Original seed-based design (superseded — kept for history)</summary>

### 5.1 Reconstruction model

Per the architectural direction set in the parent conversation:

- The agent runs from boot or first install, hardened against tampering (a separate roadmap track — see `docs/yuzu-guardian-windows-implementation-plan.md` and the open Guardian PR ladder).
- On first start, the agent runs `tar.process_tree` to produce a **seed snapshot** — every PID currently running, with PPID, name, cmdline, user, start_time. Walks `/proc` (Linux), `CreateToolhelp32Snapshot` + `Process32FirstW`/`NextW` (Windows), `proc_listallpids` + `proc_pidinfo(PROC_PIDTBSDINFO|PIDPATHINFO)` (macOS). Stored in `process_live` with a tagged `action='seed'` row per PID.
- From the seed onward, regular `collect_fast` cycles emit `action='started'` / `action='stopped'` events. These are appended to `process_live` and are the canonical mutation stream for the tree.
- At render time, the server queries `process_live` for one device's full history (or a time-bounded slice), replays the seed + events, and produces a tree JSON.

The dashboard rendered the seed timestamp prominently (`Tree as observed since … (agent install)`). Time slicing was via `?as_of=<ts>`. Mitigations for replay cost were a per-device LRU cache (5-min TTL), 24 h `__checkpoint__` rows, and a 50K-node render cap. A `GET /api/v1/tar/process-tree/{device_id}` JSON surface was planned alongside the fragment, and the renderer was to apply the TAR redaction patterns before serialisation.

</details>

## 6. Permissions matrix

| Surface | Required | Notes |
|---|---|---|
| `/tar` page load | `Infrastructure:Read` | Same as Devices/Inventory pages |
| Retention-paused list view | `Infrastructure:Read` | |
| Scan fleet (Phase 15.A) | `Execution:Execute` | Dispatches `tar.status` fleet-wide; same tier as run-instruction/tar-execute |
| Re-enable | `Execution:Execute` | Per-device RBAC visibility check; out-of-scope collapses to same 404 as not-connected (no enumeration oracle) |
| Purge | `Infrastructure:Delete` | Per-device RBAC visibility check + typed-hostname confirmation (native `prompt()`, CSP-safe). Agent-side `source_not_paused` guard is authoritative (no server-side `SOURCE_NOT_PAUSED` check) |
| TAR SQL submit | `Infrastructure:Read` (today) → may tighten later | The current grant is read-only because TAR SQL is bounded to the agent's own DB and runs SELECT-only on a read-only connection behind a SQLite authorizer that allows only registry-known warehouse tables (#760/#631) |
| Save SQL result as result set | `Infrastructure:Read` + result-set creation quota | Per scope-walking-design §3.3 |
| Process tree view (frame only) | `Infrastructure:Read` | Frame, host picker, filter bar |
| Process tree reconstruct | `Infrastructure:Read` + `Execution:Execute` | Dispatches two read-only `tar.sql` queries to one device; per-device management scope required; emits `tar.process_tree.read` |

## 7. Observability

Per `docs/observability-conventions.md`:

| Metric | Type | Labels | Status |
|---|---|---|---|
| `yuzu_tar_dashboard_view_total` | counter | `frame` (retention/sql/tree), `result` | shipped (PR-A.A) |
| `yuzu_tar_retention_paused_devices` | gauge | `source` | shipped (PR-A.A) |
| `yuzu_tar_source_purge_total` | counter | `result` | **shipped** (Phase 15.A — dashboard fragment + `POST /api/v1/tar/retention-paused/purge`) |
| `yuzu_tar_source_reenable_total` | counter | `result` | shipped (PR-A.A — dashboard fragment only, no REST twin) |
| `yuzu_tar_scan_dispatched_total` | counter | `result` | shipped (PR-A.A) |
| `yuzu_tar_process_tree_render_seconds` | histogram | `node_count_bucket` | **planned — not yet emitted** (SRE follow-up) |

> **Do not sum `yuzu_tar_source_purge_total` across surfaces yet.** The dashboard
> fragment and the REST twin write the same series with different `result` tokens:
> the fragment distinguishes `scope_violation` from `denied`, while REST folds
> per-device scope denial, missing wiring, and audit failure all into `denied` and
> otherwise only ever writes `requested`. `success` and `agent_not_connected` are
> comparable; nothing else is, and there is no `surface` label to split them.

> The PR-H viewer ships with **no process-tree metrics yet** (a dashboard read surface); the render-duration histogram + a dispatch counter + a node-count histogram are a tracked SRE follow-up. The seed-age gauge from the original design is removed (there is no seed).

Audit actions: `tar.status.scan` (Scan fleet — PR-A.A), `tar.source.reenable` (Re-enable a row — PR-A.A), `tar.source.purge` (purge — **shipped** Phase 15.A; also `csrf.denied`-style cross-origin refusals are audited under `tar.source.purge`/`reenable` with `detail=csrf_cross_origin`), `tar.process_tree.read` (PR-H — emitted at dispatch **and** on a successful reconstruction; the device is `target_id`, never in `detail`; see `docs/user-manual/audit-log.md`). The seed-based `tar.process_tree.reseed` verb is removed (no seed).

## 8. Cross-references

- `docs/scope-walking-design.md` — the result-set primitive consumed throughout this page
- `docs/yuzu-guardian-design-v1.1.md` — agent tamper-resistance, foundational to the process tree's data quality claim
- `docs/yuzu-guardian-windows-implementation-plan.md` — Windows-first hardening PR ladder
- `agents/plugins/tar/src/tar_aggregator.cpp` — the #539 retention pause that the retention-paused list surfaces
- `agents/plugins/tar/src/tar_plugin.cpp` — the action surface (`tar.status`, `tar.configure`, `tar.fleet_snapshot`, future `tar.process_tree`, `tar.purge_source`)
- `server/core/src/dashboard_routes.cpp` — the existing TAR SQL fragment to be relocated and extended
- `docs/data-architecture.md` — error code taxonomy, audit envelope conventions
- `docs/yaml-dsl-spec.md` — DSL surface (gains `fromResultSet:` per scope-walking-design §7)

## 9. Sequencing

| PR | Scope | Status |
|---|---|---|
| PR-A | Page shell + retention-paused list (this doc §3) | **Shipped** — PR-A.A (paused_at extension + dashboard page + retention-paused list) + typed-confirmation Purge action (§3.4, 2026-07-01). |
| PR-B | Result-set store + REST API (`scope-walking-design.md` PR-B) | Pending |
| PR-C | Scope chip + sidebar + breadcrumb (`scope-walking-design.md` PR-C) | Pending |
| PR-D | TAR SQL frame migrated and scope-walking-aware (this doc §4) | Pending |
| PR-E | DSL `fromResultSet:` (`scope-walking-design.md` PR-E) | Pending |
| PR-F | Reference IR walkthrough integration test (`scope-walking-design.md` PR-F) | Pending |
| PR-G | Operational hardening (live re-eval, GC, metrics) | Pending |
| PR-H | Process tree viewer (this doc §5) | **Shipped** (as-built §5 — local-TAR-data-only reconstruction; no seed). REST/MCP parity deferred (§5.6). |

## 10. Open questions

- Should the retention-paused list also surface `<source>_enabled=true` devices that have *zero* recent rows (silent collector failure)? Useful for SRE but visually noisy in IR; defer to PR-G.
- The "Purge data" action should ideally be replaced by an "Export then purge" flow that puts the rows into a signed evidence bundle before deletion — a SOC 2 CC7.2 evidence requirement. Defer to a follow-up issue once the retention-paused list ships.
- Multi-device re-enable (select-many in the table, single click "Re-enable selected") is an obvious affordance once the table has rows; ship in PR-A only if the single-row path is solid.
