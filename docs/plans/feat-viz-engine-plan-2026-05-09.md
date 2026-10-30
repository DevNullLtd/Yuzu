# Plan: Fleet network-topology 3D visualization (`feat/viz-engine`)

> **Status note (2026-05-10):** PRs 1–6 + six hardening rounds shipped on `origin/feat/viz-engine`. PR-7+ (interior process nodes / edges / vuln overlay) still ahead. The 11-PR ladder below is unchanged from the original plan; consult `git log origin/dev..HEAD` for current rung progress.
>
> **Provenance.** Drafted via the `/plan` skill on 2026-05-09 in worktree `/Users/<user>/Yuzu-viz`. This file is the version-controlled copy; the per-Claude-session original at `~/.claude/plans/we-re-in-a-git-encapsulated-yao.md` is unmaintained.

## Context

Yuzu operators today have no spatial view of their fleet. They can list devices, list processes per device, and list CVEs — but nothing answers *"which vulnerable processes on which machines are talking to which other machines?"*. The capability map calls this gap out as a flagship product differentiator (see `docs/scope-walking-design.md` and `docs/echo-dashboard.md`).

The new visualization will render each managed machine as a translucent cube, processes inside as positional nodes coloured by category, intra-machine localhost connections as interior lines, and external connections as edges that exit visible socket markers on one cube and enter sockets on another. WASD pans the camera, mouse drag rotates around scene centre, mouse wheel zooms.

The branch (`feat/viz-engine`, worktree `/Users/<user>/Yuzu-viz`) is at `origin/dev` HEAD `3cd5c06` with no diverging work yet. The prior 7-PR ladder (memory `project_viz_engine_branch_2026-05-09.md`) is **superseded by this plan** — the data plane is reorganised around fleet-level network topology rather than per-device process tree.

**Locked decisions (from clarifying questions):**
1. Process categorization in v1 = hardcoded heuristics (system / browser / database / web / runtime / other)
2. UI scope = single `/viz/fleet` page with click-to-drill-in (per-device exploration stays HTML on Echo page)
3. Cross-machine IP resolution = derive from connection snapshots (no `AgentRegistry` proto change)

**Library choice — Three.js r168 + OrbitControls only.** Vanilla Three.js, no `3d-force-graph` (force-directed is wrong for positional cubes), no `three-stdlib` (1.4 MB of unneeded helpers; can be added in polish PR if `Line2`/`InstancedMesh` helpers prove necessary). Custom WASD listener plus OrbitControls with `enablePan=false`.

**Prior art cribbed for visual idiom (no code copied):**
- `nettopo-3d` (zym9863/nettopo-3d) — devices as 3D models with explicit Connection.js class for links; OrbitControls-style camera; closest visual reference.
- `TensorSpace.js` — translucent cube containing interior nodes (their "layer" metaphor); transferable approach for the inside-the-cube layout.

---

## Critical audit findings (load-bearing)

These are *not* obvious from the code structure and shape several PR boundaries:

1. **Echo connection rows are agent-local-only.** `tcp_live` / `process_live` tables (`agents/plugins/echo/src/echo_db.cpp:454,512`) hold the row data. The server's `response_store` only sees the summary line `echo|collect_fast|<N>|events_recorded` (`echo_plugin.cpp:384`) — counts, not rows. The server cannot reconstruct topology from existing stored data; it must dispatch an Echo action on demand.
2. **`echo.query` exists** (`echo_plugin.cpp:533`) and emits JSON rows over the standard CommandRequest plumbing — no new wire protocol needed. We add one new Echo action that returns a single shaped JSON document.
3. **AgentSession lacks IP** (`agent_registry.hpp:47` — `agent_id, hostname, os, gateway_node`). IP set must come from somewhere else; we ship it inside the new snapshot payload (cheaper than extending the proto).
4. **`embed_js.py`** chunks JS at 14 KB (`scripts/embed_js.py:30`) due to MSVC C2026 limit. Three.js r168 minified (~660 KB) → ~50 chunks. Pipeline already proven by ECharts (1 MB committed at `server/core/vendor/echarts.min.js`).
5. **No long-lived `<canvas>` pattern.** HTMX swaps blow away DOM; a Three.js `WebGLRenderer` must own a node that survives swaps. PR 5 establishes this contract: persistent `<div id="viz-root">` with the canvas mounted once and left untouched on subsequent swaps; only an inner `#viz-overlay-panel` swaps.

---

## PR ladder

11 PRs. Each is independently mergeable, independently demoable when possible, and small enough for a single `/governance` pass. The first three are pure data plane (no rendering); demo-able via `curl` and `jq`.

### PR 1 — Agent: `echo.fleet_snapshot` action + `local_ips` collector

**Demo:** `yuzu-cli run --plugin echo --action fleet_snapshot --target hostname=foo | jq '{procs: (.processes|length), conns: (.connections|length), ips: .local_ips}'` returns a snapshot.

- `agents/plugins/echo/src/echo_plugin.cpp` — add `"fleet_snapshot"` to `actions()` (line 226), dispatch in `run()` (line 301), implement `do_fleet_snapshot()` (after `do_snapshot` at line 682).
- `agents/plugins/echo/src/echo_db.{hpp,cpp}` — add `select_active_processes(int64_t since_ts, int max=4096)` and `select_active_connections(int64_t since_ts, int max=4096)`. Read latest-snapshot rows from `process_live` / `tcp_live` where `action ∈ {'started','connected'}` minus subsequent `'stopped'/'disconnected'`.
- `agents/core/include/yuzu/agent/network_interfaces.hpp` (new) — `std::vector<std::string> enumerate_local_ips();` returning canonical-form, deduped, no-loopback.
- `agents/core/src/network_interfaces_posix.cpp` (new) — `getifaddrs` impl (Linux + macOS).
- `agents/core/src/network_interfaces_win.cpp` (new) — `GetAdaptersAddresses` impl.
- `agents/core/meson.build`, `agents/plugins/echo/src/meson.build` — wire new sources.
- `tests/unit/test_fleet_snapshot.cpp` (new, Catch2 `[echo][fleet]`) — synthesised rows roundtrip, stop/disconnect removes from snapshot, truncation at 4096, `cmdline` redaction (`should_redact` reused), `local_ips` injection, JSON byte size <512 KB on max-realistic load.

**Emitted schema (one JSON object per snapshot):**
```json
{"schema":"fleet_snapshot.v1","ts":1715299200,"hostname":"foo","local_ips":["10.0.1.7","fe80::1"],
 "processes":[{"pid":1234,"ppid":1,"name":"postgres","user":"postgres","cmdline":"...","rss_kb":234567}, ...],
 "connections":[{"proto":"tcp","local_addr":"10.0.1.7","local_port":5432,"remote_addr":"10.0.1.42","remote_port":54321,"state":"ESTABLISHED","pid":1234}, ...],
 "truncated_processes":false,"truncated_connections":false}
```

**No DDL changes** — read-only on existing `process_live` / `tcp_live`.

### PR 2 — Server: `FleetTopologyStore` + `ProcessCategory` heuristics

**Demo:** unit test prints serialised `TopologySnapshot` JSON; cache-hit timings shown.

- `server/core/src/fleet_topology_store.{hpp,cpp}` (new) — class with `std::shared_ptr<const TopologySnapshot> get(bool include_vuln)`; LRU-of-2 (with-vuln, without-vuln) keyed on flag, 60 s TTL, single-flight refill via `std::shared_mutex` + `std::condition_variable_any` (mirrors `server/core/src/api_token_store.hpp` pattern). On cache miss, dispatches `echo.fleet_snapshot` to each session in `AgentRegistry` (5 s per-agent timeout, partial results allowed; missing agents flagged `stale=true`).
- `server/core/src/process_category.hpp` (new, header-only) — `enum class Category` + `Category classify(std::string_view exe_basename, std::string_view user)` mapping ~60 known executable names. Tested name table: `postgres,mysqld,mariadbd,redis-server,mongod,memcached → Database`; `chrome,chromium,firefox,msedge,safari → Browser`; `nginx,apache2,httpd,iisexpress → Web`; `java,python,python3,node,dotnet,ruby,php-fpm → Runtime`; `systemd,init,launchd,svchost,kthreadd,kernel_task → System`; default `Other`.
- `server/core/src/fleet_topology_types.hpp` (new) — `MachineNode { agent_id, hostname, os, local_ips, processes[], connections[], stale }`, `ProcessNode { pid, ppid, name, user, category, rss_kb, worst_severity }`, `ConnectionEdge { src_pid, src_addr, src_port, dst_addr, dst_port, dst_agent_id (resolved or empty), proto, scope (LOCAL/INTERNAL_FLEET/EXTERNAL) }`.
- **IP resolution**: server builds `unordered_map<string, string> ip_to_agent_id` from each agent's `local_ips`; falls back to unioning `connections[].local_addr` for legacy/missing-field agents; flags `0.0.0.0` and `::` as ambiguous (skipped from map).
- **Vuln join**: when `include_vuln=true`, build `SoftwareItem{name, version=""}` per process basename and call `nvd_db_->match_inventory()` (existing API). Result writes `worst_severity` on `ProcessNode`.
- `server/core/src/fleet_topology_store.cpp` includes the categorisation + IP resolution + vuln join.
- `server/core/meson.build` — add new sources.
- `tests/unit/server/test_fleet_topology_store.cpp` (new) — fake `AgentRegistry` + `ResponseStore`, assert snapshot shape, cache hit on second call within TTL, TTL expiry triggers refill, vuln overlay matches mocked `nvd_db`, IP resolution to dst_agent_id, `0.0.0.0` ambiguity skip.

**Decision:** dispatch on cache miss (rather than push-from-agents) — testable end-to-end in PR 1 + 2 alone, no proto/scheduler work, no doubled steady-state traffic. PR 11 polish layer adds a 60 s background refresher so most `GET`s land warm.

### PR 3 — REST API + RBAC + audit + metrics

**Demo:** `curl -H 'Authorization: Bearer <token>' /api/v1/viz/fleet/topology | jq` returns full topology.

- `server/core/src/viz_routes.{hpp,cpp}` (new — sister of `compliance_routes.cpp`) — registers:
  - `GET /api/v1/viz/fleet/topology?include_vuln={bool}&fresh={1}` — returns full JSON snapshot.
  - `GET /fragments/viz/fleet/topology` — same data wrapped in `<script type="application/json" id="viz-data">...</script>` for HTMX swap-in (agentic-first A1: dashboard parity).
- RBAC: `require_permission(req, res, "Response", "Read")` mirroring `auth_routes.cpp:196`.
- Audit envelope: `audit_log(req, "viz.fleet_topology", "ok", agent_id="-", target="*", details=node_count)` per `docs/observability-conventions.md`.
- Metrics: `yuzu_viz_topology_request_seconds` histogram, `yuzu_viz_cache_hit_total` / `yuzu_viz_cache_miss_total` counters, `yuzu_viz_agent_dispatch_timeout_total` counter.
- `server/core/src/server.cpp` — instantiate `FleetTopologyStore`, register `VizRoutes`.
- Page-size limit: `?machines_max=N` (default 5000), error 413 above.
- `tests/unit/server/test_viz_routes.cpp` — auth required → 401, RBAC denied → 403, audit row written, oversized request → 413, metrics incremented.

### PR 4 — Vendor: Three.js r168 + OrbitControls embed

**Demo:** build green on Linux GCC + macOS Apple Clang + Windows MSVC; `curl /static/three.min.js | wc -c` matches vendored byte count.

- `server/core/vendor/three.min.js` (r168, ~660 KB, MIT) — committed.
- `server/core/vendor/three-orbit-controls.js` (UMD build, ~25 KB, MIT) — committed.
- `server/core/vendor/three-NOTICE.txt`, `three-orbit-NOTICE.txt`, `THIRD_PARTY_LICENSES.md` updated.
- `server/core/meson.build` — two new `custom_target` blocks mirroring `echarts_js_bundle` (lines 55–66) producing `three_js_bundle.cpp` (`kThreeJs`) and `three_orbit_js_bundle.cpp` (`kThreeOrbitJs`); add to `yuzu_server_core_lib` sources.
- `server/core/src/server.cpp` — `extern const std::string kThreeJs; extern const std::string kThreeOrbitJs;` near line 166; routes `/static/three.min.js` and `/static/three-orbit-controls.js` near line 2546 with `Cache-Control: max-age=86400`.
- **Punted to follow-up**: rename `embed_js.py` `DELIM = "ECHARTSEMBED" → "YUZUEMBED"`. Re-chunks every existing embed; out of scope for vendor-add.
- **Validation**: build on `yuzu-wsl2-linux` runner, macOS local, `Shulgi` for Windows MSVC.

### PR 5 — Page scaffold: `/viz/fleet` with persistent canvas + WASD/orbit/zoom controls

**Demo:** navigate to `/viz/fleet`, see empty grey scene with faint ground grid + axes helper; WASD moves camera (W=up, S=down, A=left, D=right), drag rotates, wheel zooms; F12 console clean on Linux/macOS/Windows.

- `server/core/src/viz_page_ui.cpp` (new — mirrors `echo_page_ui.cpp` shell + nav) — emits page with persistent outer `<div id="viz-root" data-yuzu-viz-url="/api/v1/viz/fleet/topology">` containing `<canvas id="viz-canvas">` and a swappable `<div id="viz-overlay-panel">` for future side-panels. `<script src="/static/three.min.js"></script><script src="/static/three-orbit-controls.js"></script><script src="/static/yuzu-viz.js"></script>`.
- `server/core/src/yuzu_viz_js_bundle.cpp` (new, hand-written ~6 KB — under MSVC limit, no chunking) — `window.YuzuViz` IIFE that:
  - Mounts the renderer once on first `htmx:afterSettle` for `[data-yuzu-viz-url]`; bails idempotently if already mounted (canvas survival contract).
  - Builds scene + perspective camera + ambient + directional light + ground grid + axes helper.
  - OrbitControls with `enablePan=false` (WASD owns translation).
  - WASD `keydown` listener: pans camera position by camera-basis-aligned step (W=+Y, S=−Y, A=−X, D=+X in screen space; `requestAnimationFrame`-throttled).
  - Empty `render()` placeholder for PR 6 to fill in.
- `server/core/src/server.cpp` — `extern const std::string kYuzuVizJs;` + `/static/yuzu-viz.js` route + `/viz/fleet` page route (gated behind same auth as `/echo`).
- `server/core/src/dashboard_ui.cpp:373` — insert `<a href="/viz/fleet" class="nav-link">Fleet Viz</a>` before Settings.
- `server/core/meson.build` — add `'src/viz_page_ui.cpp'`, `'src/yuzu_viz_js_bundle.cpp'`.

### PR 6 — Render machines (translucent cubes)

**Demo:** N cubes appear in a deterministic grid, hostname labels readable, hover tooltip shows hostname/OS/process_count/connection_count.

- `yuzu_viz_js_bundle.cpp` adapter — fetch topology JSON, lay out machines on `ceil(sqrt(N))` grid, deterministic positions seeded by `hash(agent_id)` for stability, `MeshPhysicalMaterial({transparent:true, opacity:0.18, color: per-OS palette})` cube. `Sprite` hostname label above each cube.
- Raycaster on `mousemove` → fixed-position tooltip div with hostname/os/process_count/connection_count.

### PR 7 — Render processes (interior nodes coloured by category)

**Demo:** cubes contain tens-to-hundreds of dots; colour matches category; hover tooltip shows pid/name/user/category.

- `yuzu_viz_js_bundle.cpp` — process nodes inside each cube on deterministic `hash(pid)`-mod-bucket layout (jitter to avoid collisions), colour from category enum mapped client-side (`{System: #6e7681, Browser: #58a6ff, Database: #d29922, Web: #56d364, Runtime: #bc8cff, Other: #8b949e}`), size = `log10(rss_kb+1)/3` if RSS available else uniform.

### PR 8 — Internal edges (localhost connections)

**Demo:** faint white lines appear inside cubes connecting localhost-talking processes.

- For connections where `local_addr ∈ {127.0.0.1, ::1}` and `remote_addr ∈ {127.0.0.1, ::1}` and the destination pid is resolvable in the same machine's process list (via `(remote_port → listening pid)` lookup), draw `LineSegments` between the two interior nodes; alpha 0.3.
- Drop edges with unresolved destination.

### PR 9 — External edges (cross-machine + Internet sentinel)

**Demo:** visible cross-cube traffic lines; faded edges to a single dark "External" sphere for non-fleet remote_addrs.

- Server already produced `dst_agent_id` per edge in PR 2.
- For each `INTERNAL_FLEET` edge: surface socket marker (small sphere) on the cube face nearest the destination cube, edge from process → source-side socket → dest-side socket → dest process.
- For each `EXTERNAL` edge: faded edge to a single dark sphere fixed at `(0, 30, 0)` labelled "External".
- **Edge bundling**: when `≥8` edges between a cube pair, replace with a single thicker edge labelled `Nx`.

### PR 10 — Vulnerability overlay

**Demo:** turn overlay toggle on, processes coloured by severity, cubes glow when any contained process is critical, click → side-panel shows CVE list with NVD links.

- Adapter respects `worst_severity` per process (already populated by PR 2 when `include_vuln=true`): `critical=#f85149`, `high=#d29922`, `medium=#e3b341`, `low=#58a6ff`, clean=category colour.
- Cube `MeshPhysicalMaterial.emissive` pulses red when any contained process is `critical`.
- Click on process → `htmx.ajax('GET', '/fragments/viz/process/<agent_id>/<pid>', {target: '#viz-overlay-panel'})` lists matched CVEs.
- `server/core/src/viz_routes.cpp` — add `GET /fragments/viz/process/{agent_id}/{pid}` rendering the side-panel HTML.

### PR 11 — Polish: LOD, bundling, a11y, perf, scheduler

- **Background scheduler** in `FleetTopologyStore` — a refresher thread refills the cache every 60 s so `GET` is always warm; on-demand refill stays as fast-path fallback.
- **LOD clustering** at >200 cubes: super-cubes by tag/OS-family (reuses tag DSL from `docs/asset-tagging-guide.md`); expand-on-click.
- **B-spline edge bundling** for >50 cross-cube edges.
- **A11y**: keyboard cube cycling (`Tab` advances focused machine), screen-reader announcements on focus, camera home/reset button.
- **Perf**: `InstancedMesh` for processes (one draw call per category), GPU-side line shader for cross-cube edges.

---

## Critical files to read before implementation

- `agents/plugins/echo/src/echo_plugin.cpp` — actions array (226), do_query (533), do_snapshot (682) — pattern to mirror for `do_fleet_snapshot`.
- `agents/plugins/echo/src/echo_db.cpp` — `process_live` / `tcp_live` insert (454, 512) — read direction for new selectors.
- `agents/plugins/echo/src/echo_collectors.hpp` — `NetConnection` struct + `redact_cmdline()`.
- `agents/core/include/yuzu/agent/process_enum.hpp` — `ProcessInfo` struct + `enumerate_processes()`.
- `server/core/src/api_token_store.hpp` — LRU + TTL + single-flight pattern to mirror.
- `server/core/src/agent_registry.hpp` — `AgentSession` (47), `send_to` (104) for dispatching `echo.fleet_snapshot`.
- `server/core/src/nvd_db.hpp` — `match_inventory()` for vuln overlay.
- `server/core/src/charts_js_bundle.cpp` — `[data-yuzu-chart-url]` HTMX hook + `htmx:afterSettle` listener pattern.
- `server/core/src/server.cpp:165–168, 2523–2569` — extern declarations + static-asset routes — pattern to mirror.
- `server/core/scripts/embed_js.py` — vendor embed pipeline (DELIM `ECHARTSEMBED`, CHUNK_SIZE 14_000).
- `server/core/meson.build:55–99` — `custom_target` blocks for embeds + static_library composition.
- `server/core/src/dashboard_ui.cpp:369–373` — nav-link block to extend.
- `server/core/src/echo_page_ui.cpp` — page shell pattern for `/viz/fleet`.
- `server/core/src/dashboard_routes.cpp:360–411` — fragment-route registration pattern (regex paths, RBAC, audit).
- `tests/unit/test_helpers.hpp` — `unique_temp_path` / `TempDbFile` (mandatory per CLAUDE.md test-helpers section).
- `docs/observability-conventions.md` — audit envelope + metric naming.
- `docs/agentic-first-principle.md` — A1 dashboard parity invariant for the fragment route.

---

## Reuse map

| Need | Reuse |
|---|---|
| Process enum | `yuzu::agent::enumerate_processes()` — `process_enum.hpp` |
| Connection enum | `echo::enumerate_connections()` — `echo_network_collector.cpp` |
| Cmdline redaction | `redact_cmdline()` — `echo_collectors.hpp` |
| Live-state read | new selectors on existing `process_live` / `tcp_live` — no DDL |
| LRU + TTL + single-flight | `api_token_store.hpp` |
| CVE matching | `NvdDatabase::match_inventory()` — `nvd_db.hpp` |
| Agent dispatch | `AgentRegistry::send_to()` |
| Vendor embed | `embed_js.py` + `custom_target` — `meson.build:55–66` |
| Static asset route | `server.cpp:2546` ECharts pattern |
| HTMX auto-render | `[data-yuzu-chart-url]` → adapt as `[data-yuzu-viz-url]` |
| RBAC + audit | `auth_routes.cpp:196` permission gate; `audit_log` envelope |
| Test helpers | `unique_temp_path` / `TempDbFile` — `test_helpers.hpp` |

---

## Verification

- **PR 1**: `meson test -C build-linux --suite echo --print-errorlogs` passes; `yuzu-cli run --plugin echo --action fleet_snapshot --target hostname=$(hostname) | jq .schema` returns `"fleet_snapshot.v1"`.
- **PR 2**: `meson test -C build-linux --suite server --test fleet_topology_store` passes; cache-hit time < 5 % of cache-miss time at TTL boundary.
- **PR 3**: `curl -H 'Authorization: Bearer …' http://localhost:8080/api/v1/viz/fleet/topology | jq '.machines | length'` returns ≥1 in UAT; metric `yuzu_viz_cache_hit_total` increments on second request within TTL.
- **PR 4**: `curl -sI http://localhost:8080/static/three.min.js` returns 200 with byte count matching `wc -c server/core/vendor/three.min.js`. Build green on Linux GCC, macOS Apple Clang, Windows MSVC (validate on Shulgi per memory `reference_shulgi_windows_box.md`).
- **PR 5**: navigate to `/viz/fleet` in browser, F12 console clean, WASD moves camera, drag rotates, wheel zooms.
- **PR 6**: deterministic grid of N cubes appears for an N-agent UAT; refresh produces identical layout.
- **PR 7**: cubes contain coloured process nodes; switching between two distinct fleets produces visibly different category distributions.
- **PR 8**: localhost-listening service (e.g., postgres) shows interior edges to its connecting clients.
- **PR 9**: `yuzu-cli` connecting agent A → server (running on B) shows a cross-cube edge from agent A's `yuzu-cli` process to agent B's `yuzu-server` process.
- **PR 10**: known-vulnerable image in UAT (e.g., `nginx:1.14`) renders red glow on its cube; click → CVE list non-empty.
- **PR 11**: 200-agent UAT loads `/viz/fleet` in under 3 s with stable 60 fps on a Macbook Pro M-class.
- **End-to-end gate**: `/governance` clean on each PR; `/test --quick` green; `/test` (full upgrade ladder) green before PR 11 merges.

---

## Out of scope (future work)

- Persistent topology history (`viz_history.db`) for time-travel views.
- `embed_js.py` `ECHARTSEMBED → YUZUEMBED` rename — separate cosmetic PR after PR 4.
- Push-from-agent topology updates (web-socket or SSE) — current pull-on-cache-miss + 60 s background refresh is the v1 model.
- Per-device 3D process tree (the prior plan's PR-5/6) — superseded by fleet drill-in.
- Mobile/touch controls.
- VR mode.
