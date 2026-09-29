# Fleet Visualization — Standing Invariants

The 3D fleet visualizer is built as an 11-PR ladder on `feat/viz-engine`. Each
PR layers on the previous one, and each round of governance hardening adds
invariants that successor PRs must respect. This doc collects those
invariants so they outlive any single PR description.

Triggers for this doc: any change touching
`viz_routes.{hpp,cpp}` / `fleet_topology_store.{hpp,cpp}` /
`viz_page_ui.cpp` / `static/yuzu-viz.js` / `--viz-disable` /
`Config::viz_disable` / `McpServer::set_viz_deps` / the `get_fleet_topology`
and `get_host_topology` MCP tool handlers in `mcp_server.cpp` (api-parity
#2146 Batch B3 - a second implementation site for these same invariants:
kill-switch-before-RBAC ordering, the `machines_max` DoS cap, the offline-merge
rule). Loaded by `security-guardian` + `docs-writer` during governance.

## MCP surface

`get_fleet_topology`/`get_host_topology` (`mcp_server.cpp`) are the MCP twins
of the REST endpoints below, wired via `McpServer::set_viz_deps()` (passes the
SAME `fleet_topology_store_`/`offline_endpoint_store_`/`viz_disabled_`
instances REST's `VizRoutes` registration uses, so the two surfaces cannot
disagree about cache state). Every invariant in this doc (kill-switch
ordering, the DoS cap, the offline-merge rule) applies identically to both
surfaces - a change to one that doesn't preserve parity with the other is a
regression, not a stylistic difference. That equal treatment does not extend
to confinement: **neither surface confines results to the caller's
management-group scope** - a caller with `Response:Read` sees every connected
agent's process/connection/listener data fleet-wide on both REST and MCP
alike (#4313, tracked parallel to #3526's identical gap on the
execution/fleet-statistics tools).

## REST and routing surface

- **Endpoints.** `/api/v1/viz/fleet/topology` (JSON snapshot) +
  `/fragments/...` (HTMX fragments).
- **Page route.** `/viz/fleet` (and `/viz/host/<agent_id>`), auth-gated.
  Responses set `Cache-Control: no-cache, no-store, must-revalidate` to
  close the stale-page-vs-fresh-asset skew window — page shell and module
  bundle must reload together.
- **Renderer bundles are `no-cache`, vendored libs are `max-age`.**
  `/static/yuzu-viz.js` and `/static/yuzu-viz-host.js` are *our* renderer
  code — they change every feat/viz-engine PR — so they're served
  `no-cache, no-store, must-revalidate`, same as the page shell. A
  `max-age` on them silently serves a stale renderer (wrong tier
  classification, missing layout code, outdated features) for the whole
  window after a server upgrade. The vendored libraries
  (`/static/cytoscape.min.js`, `/static/three.module.min.js`,
  `/static/three-orbit-controls.js`) keep `public, max-age=86400` — they
  are content-stable and only change on a deliberate vendor refresh.
- **Route ordering.** No future `/viz/<param>` regex may be registered
  *before* `/viz/fleet` in the route table — the more-specific literal must
  win the match (arch-S1).

## Kill switch and DoS cap

- **Kill switch.** `--viz-disable` flag or `YUZU_VIZ_DISABLE` env var. Tier
  check precedes RBAC permission check: a disabled tier returns 503 before
  any auth/permission evaluation.
- **`machines_max` DoS cap (M-1).** Default 5000, hard ceiling 100000.
  Snapshot fetch refuses to materialize beyond the cap.

## Audit

- **Actions.** `viz.fleet_topology` (read) and
  `viz.fleet_topology.invalidate` (cache bust).
- **Envelope.** `target_type = FleetTopology`. Results are one of `success` /
  `denied` / `failure`.

## Fragment / JSON escape

- **Fragment `</script>` escape.** Any JSON embedded in an HTML fragment
  flows through `escape_json_for_script` before insertion. Inline
  `<script type="application/json">` blocks must use this helper.
- **Fetcher executions-tracker opt-out.** The viz fetcher does not emit
  executions-history rows; rationale lives at the fetcher call site.

## Metrics

- **Store-internal gauges.** `yuzu_viz_refill_*` are gauge-as-snapshot — the
  store writes the value at refill time, not a counter.
- **Fetch duration histogram (PR 6 / OBS-2).**
  `yuzu_viz_topology_fetch_duration_seconds` is wired via
  `set_fetch_duration_observer`. **Fires once per refill including on
  fetcher exception** — observer must be invoked from a `finally`-equivalent
  path so a thrown fetcher still contributes a sample.

## Page-shell invariants (`viz_page_ui.cpp`)

- **Importmap ordering (UP-1, HTML spec).** `<script type="importmap">` must
  be parsed *before* any `<script type="module">` that imports a bare
  specifier. Reversing the order produces a silent module-not-found at
  runtime.
- **WebGL context loss handlers (UP-3).** Both `webglcontextlost` and
  `webglcontextrestored` must be wired; lost-context handler must call
  `event.preventDefault()` to allow restoration.
- **WASD listener guards (sec-M1).** Keyboard handlers must early-return when
  the focused target is `INPUT`, `TEXTAREA`, `SELECT`, or has
  `contentEditable === 'true'`. Without this, typing in a search box steers
  the camera.
- **Importmap support detector (UP-16).**
  `HTMLScriptElement.supports('importmap')` must be probed *before* the
  importmap tag is parsed. Browsers without importmap support need the
  fallback path.

## Renderer invariants — PR 6 (`static/yuzu-viz.js`)

The renderer bundle is built via `embed_js.py` rather than a hand-written
TU — it crossed the MSVC 16,380-byte raw-string literal limit at PR 6.
Standing rules:

- **Stable per-agent layout.** Use **FNV-1a 32-bit** (`hash32`) for
  deterministic agent → grid-slot assignment. Random or wall-clock-seeded
  layout breaks operator muscle memory across refreshes.
- **Cube material.** `MeshPhysicalMaterial({transparent: true, opacity:
  0.18})`. The historical `0.08` value made internal process dots
  effectively invisible against a dark background.
- **Hostname labels.** Sprite via `CanvasTexture`. No DOM-overlay labels —
  they don't survive frustum culling and they break the WebGL hit-test.
- **Tooltip raycasting.** `Raycaster` on `mousemove`. Tooltip output uses
  `escapeHtml` on every agent-controlled field written via `innerHTML`
  (sec-M1).
- **Camera reset guard (UP-7).** `Number.isFinite(camera.position.{x,y,z})`
  check in the render loop; on failure reset to the default position. NaN
  positions can leak in from bad orbit-control input and corrupt every
  subsequent frame.
- **HTTP status handling (UP-17).** `fetchAndRender` must surface 401, 403,
  and 503 explicitly — not collapse them to a generic error toast.
- **Schema gate.** Reject the response unless `schema === 'fleet_topology.v1'`
  before any render call.

## Edge invariants — PR 8 (intra-cube localhost edges)

- **`ConnectionEdge.dst_pid`** is the resolved peer pid on the SAME machine for
  `EdgeScope::Local` connections only. Default zero; non-zero only after the
  pairing pass.
- **Reciprocal-pair resolution.** `build_snapshot()` pairs each Local-scope
  edge with its reciprocal half by exact 4-tuple swap: edge C with
  `src_addr=X, src_port=P_X, dst_addr=Y, dst_port=P_Y` pairs with C' where
  `(C'.src_addr, C'.src_port) == (Y, P_Y)` AND
  `(C'.dst_addr, C'.dst_port) == (X, P_X)`. Sets `C.dst_pid = C'.src_pid`.
- **Drop unmatched.** Any `EdgeScope::Local` edge whose `dst_pid` is still 0
  after the pairing pass is dropped from the snapshot
  (`std::erase_if(m.connections, ...)`). Rationale: the renderer cannot draw a
  line into nothing, and the wire payload stays consistent with the
  rendered scene.
- **Non-Local edges untouched.** The pairing+drop pass discriminates on
  `scope != EdgeScope::Local`. `InternalFleet` and `External` edges keep
  `dst_pid == 0` and survive untouched.
- **Schema minor bump.** `schema_minor` is **2** (was 1 in PR 2–7).
  Renderers must ignore unknown minor versions; the JSON addition is
  `dst_pid` on Local edges and is emitted only when non-zero (mirrors the
  `dst_agent_id`-when-non-empty pattern from PR 2).
- **Renderer line construction.** For each Local edge with both `src_pid`
  and `dst_pid` set, build `THREE.LineSegments(BufferGeometry from points,
  LineBasicMaterial({color: 0xffffff, transparent: true, opacity: 0.3}))`
  and add to the per-cube `processGroup`. Per-cube parenting reuses
  `clearFleet`'s `traverse(disposeNode)` walk for free disposal — no
  separate edge index needed.
- **`Number.isFinite` guards.** Both `src_pid` and `dst_pid` go through
  `Number.isFinite` before being used as Map keys, so a malformed agent
  payload (string pid, NaN, undefined) cannot crash the render loop or
  leak undefined-keyed Map entries.

## Process-layer invariants — PR 7

- **Per-machine `processGroup`** is attached as a *child of each cube*
  (architect NICE-1). Sibling-group alternatives were considered and
  rejected; per-cube children give PR 8 per-cube edges and PR 11 per-cube
  LOD for free, and reuse `clearFleet`'s `traverse(disposeNode)` walk for
  free disposal.
- **`CATEGORY_PALETTE`** is six colours matching the agent's
  `category_to_string()` enum exactly:

  | Category | Hex |
  |---|---|
  | `system` | `#6e7681` |
  | `browser` | `#58a6ff` |
  | `database` | `#d29922` |
  | `web` | `#56d364` |
  | `runtime` | `#bc8cff` |
  | `other` | `#8b949e` |

- **Interior layout.** Deterministic `hash32(pid|ppid)`-mod-bucket placement
  with `hash32('j|pid')` jitter, inside `cubeSize * 0.78` interior fraction
  (leaves a ~11% margin on each side).
- **Process dot geometry.** Low-poly `SphereGeometry(0.22, 6, 4)` +
  `MeshBasicMaterial`, per-instance for clean disposal. **PR 11 polish moves
  to `InstancedMesh`** — defer until then to keep PR 7's diff focused.
- **Raycast.** Flat `processMeshes[]` index alongside `cubeMeshes[]`.
  **Process raycast must precede cube raycast** in `onMouseMove`. Process
  dots live inside the translucent cubes; without this ordering the cube's
  outer face always wins by distance and operators can never hover the
  dots.
- **Process tooltip.** Surfaces `pid / name / user / category`. `escapeHtml`
  on every interpolated string field; `Number(...) | 0` to coerce `pid` to
  an integer before formatting (sec-M1 mirror of renderer rule).
- **Soft cap.** 1000 process dots per cube; bundle size cap <80 KB.

## Listener-socket invariants — PR 9

- **`listeners[]` is the source of truth for LISTEN sockets.** Server-side
  `build_snapshot()` lifts every LISTEN-state row from the agent's
  `fleet_snapshot.v1` `connections[]` into a typed `ListenerSocket`
  entry. Renderer reads `machine.listeners`, never filters `connections`
  by state.
- **Dual-emit during deprecation.** For one release the same LISTEN row
  is *also* kept in `connections[]` (with `scope=external`) so
  pre-PR-9 consumers filtering `connections` by `state == "LISTEN"`
  don't break silently. Removal is gated on a `Breaking` CHANGELOG
  entry in a future release.
- **`pid == 0` is valid.** Agents that can't resolve the owning process
  emit `pid` omitted (treated as 0). Renderer renders the sphere with
  the "owner pid not reported" tooltip; no process-dot linkage.
- **Schema bump.** `schema_minor` is `4` (was `3` in PR 9). The new
  optional `local_addr` field on each `ListenerSocket` carries the
  kernel-reported bind address. Server treats it as agent-controlled
  string (bounded at parse time to 64 bytes / `kAddressMaxLen`); the
  loopback-bind filter lives in the renderer (`isLoopbackBind`) and
  drops `127.0.0.0/8`, `::1`, `[::1]`, and `::ffff:127.x` (including
  bracketed) from the cube surface. `0.0.0.0` / `::` / specific NIC
  IPs survive. Renderer treats `local_addr` absent/empty as
  non-loopback (safe default — show rather than hide).
- **Hostname label position.** Labels render BELOW each cube (not above)
  so the top-face socket-sphere area stays unoccluded. Fixed UAT
  decision (2026-05-12); do not revert without UAT sign-off.
- **Socket primitives.** `SphereGeometry(SOCKET_DOT_RADIUS, 10, 8)` on a
  ring of radius `CUBE_SIZE * 0.32` on the cube top face; port label
  Sprite floats `0.55` units above each sphere. Listener sphere colour
  is cream (`0xfff2cc`) — distinct from the cooler process-dot
  palette so operators see them as "ports" not "processes".
- **Cross-machine edges.** ESTABLISHED-state `connections` outbound
  from one cube's `local_ips` resolve to the destination's
  `listeners[]` socket position when `(dst_addr, dst_port)` matches.
  Fallback: cube centre (peer's listener wasn't in the snapshot).
  No match anywhere → external stub line + grey ring marker.
- **Raycast order.** sockets → processes → edges → cubes. Sockets are
  most-specific and operator-actionable; the cube face is least.

## Three-tier stacked layout — PR 12

- **TIER_Y dict is the source of truth for cube Y placement.**
  `database` lives at `CUBE_SIZE/2`, `app` at `CUBE_SIZE/2 + TIER_GAP`,
  `frontend` at `CUBE_SIZE/2 + 2*TIER_GAP`. `TIER_GAP = 22` (well over
  `CUBE_SIZE = 8` so planes read as separate). Top-tier is ALWAYS
  frontend; bottom-tier is ALWAYS database — flipping the order
  breaks the architectural-diagram convention every operator brings.
- **Classification priority is db > frontend > app.** A host running
  both nginx and postgres lands on the database plane; the heavier
  architectural role wins. `classifyTier` reads listener ports first
  (`DB_PORTS` / `WEB_PORTS` constant sets), then process category
  (`'database'` / `'web'` strings from `process_category.hpp`'s
  `category_to_string`). Hosts with no DB/web signal default to
  `app`.
- **`WEB_PORTS` intentionally excludes dev-server defaults.** The set
  is `{80, 443, 8080, 8443, 8088}` — reverse proxies, load balancers,
  API gateways. Common dev-server ports (`3000` express, `4200`
  angular, `5173` vite, `8000` django) are **not** in WEB_PORTS, even
  though they speak HTTP. A nodejs/django/vite server is application
  work in a classic three-tier deployment (HSBC-style: gateway →
  app servers → database); putting it on the frontend plane
  misrepresents the topology a reviewer expects. The dev-server
  ports cost a real misclassification on the Cedar & Vale UAT rig
  (yuzu-app on `:3000` landed on the frontend plane) before they
  were removed. Port-based heuristics are a starting point only;
  function-aware classification is tracked as a follow-up.
- **Tier placement is a VISUAL cue only.** It's computed from
  agent-controlled fields (listener ports + process category) and
  carries NO authorization weight. Never use the tier output as a
  security or trust signal.
- **AxesHelper removed from `buildScene`.** Originally shipped in
  PR 5 as an empty-scene orientation gizmo; clipped through the
  bottom tier and read as a fourth signal once the stacked layout
  landed. The three planes themselves are now the spatial cue. Pinned
  via `!ContainsSubstring("AxesHelper")` in `test_static_js_bundle.cpp`.
- **Camera default reframed.** `camera.position = (45, 60, 45)`,
  `lookAt(0, TIER_Y.app, 0)`, `OrbitControls.target = (0, TIER_Y.app, 0)`.
  NaN-recovery path uses the same values.
- **Per-tier grid.** Each populated tier renders its own
  `ceil(sqrt(N_tier))` grid centred on origin; within a tier,
  machines sort by `hash32(agent_id)` so the same fleet renders
  identically across reloads.

## Talking-socket primitive — PR 12

- **Mirror of the listener ring, on the bottom face.** One sphere
  per unique outbound `(proto, dst_ip, dst_port)` aggregated from
  `connections[]` ESTABLISHED rows whose `src_addr` is in the
  cube's `local_ips`. Loopback destinations are dropped (intra-host
  loopback edges live INSIDE the cube as PR 8 `LineSegments`, not
  on the surface).
- **Distinct colour.** `TALKING_SOCKET_COLOR = 0x7ec4f8` (cool blue)
  — visually distinct from the listener-cream `0xfff2cc`. Operators
  read incoming on the roof and outgoing through the floor.
- **Position.** Ring radius `CUBE_SIZE * 0.32` (same as listeners),
  Y position `-CUBE_SIZE * 0.5 - 0.30` (bottom face, slightly below).
- **`talkingWorldPos` map** is keyed `${agent_id}|${dst_ip}:${dst_port}`
  and consumed by the cross-machine edge pass as the source-end
  anchor. Wire travels from talking dot → listener sphere on the
  destination cube.
- **Raycast order.** sockets → talking-sockets → processes → edges
  → cubes. The talking-socket pass fires immediately after the
  listener pass so a hover on either dot type surfaces the right
  tooltip.
- **Tooltip framing.** `talking: proto → dst_ip:dst_port`. XSS
  posture identical to the listener tooltip (`escapeHtml` +
  `clampForTooltip`).

## Tube-wire geometry — PR 12

- **Wires are `THREE.TubeGeometry` along a `THREE.CubicBezierCurve3`,
  not `THREE.Line`.** `LineBasicMaterial.linewidth` is silently
  clamped to 1px by every shipping browser; using `Line` would
  regress wire visibility at typical zoom. Tube radius
  `EDGE_TUBE_RADIUS_INTERNAL = 0.10` / `EXTERNAL = 0.07`,
  20 path segments, 6 radial.
- **Vertical end-tangents on internal wires.** The cubic Bezier
  control points are `P1 = src + (0, -lift, 0) + fan` and
  `P2 = end + (0, +lift, 0) + fan` so the wire exits the talking
  socket straight down through the cube's bottom face, runs
  mostly-straight through free space, and re-enters the listener
  socket from straight above through the cube's top face.
- **`lift = clamp(len * 0.25, 2, 8)`.** Scales with the wire length
  so short same-tier wires don't overshoot.
- **Fan key.** `hash32(bowKey) & 1` decides which side of the
  midpoint the bow lands on. `bowKey = srcAgentId + '|' + dst_ip + ':' + dst_port`.
  Parallel wires from two distinct sources to the same destination
  fan opposite sides so they don't trace the same path.
- **External stubs keep the quadratic upward bow** — no destination
  cube to dock to, so the cubic-with-vertical-tangents geometry
  doesn't apply. A grey ring marker at the stub end signals
  "off-cluster".
- **NaN guard.** `buildWireTube` returns an invisible no-op mesh
  on non-finite `srcPos` / `endPos` so a poisoned upstream
  position can't paint NaN tube vertices that corrupt the depth
  buffer (Gate 7 UP-10).

## Push-ingestion invariants — PR 10

- **`fleet_snapshot_json` is additive proto field 4 on
  `HeartbeatRequest`.** Agents push the JSON every 30 s on their
  snapshot-pump cadence; server ingests via
  `FleetTopologyStore::push_snapshot()`. Old agents send empty and
  the server's legacy dispatch path takes over.
- **Shared parser is the single source of truth.**
  `FleetTopologyStore::parse_fleet_snapshot_json` is called from
  every ingestion site (direct `Heartbeat`, gateway `BatchHeartbeat`,
  legacy dispatch fetcher). Caps + exception sanitisation + field
  set stay in lock-step by construction. **Adding a new field means
  exactly one code edit** (the parser); future drift would defeat
  the invariant.
- **Row caps.** `kPushedSnapshotMaxRows = 4096` for both
  `processes[]` and `connections[]`. `kPushedSnapshotMaxBytes = 2
  MiB` for the whole payload. Caps match the agent-side
  `kFleetSnapshotMaxRows` so a legitimate snapshot never trips them.
- **Trust boundary.** `agent_id` and `os` are session-authenticated
  values passed *into* the parser, never read from JSON. JSON
  `hostname`, `local_ips`, `processes[]`, etc. are agent-controlled
  and may be fabricated; callers that need cross-agent validation
  apply it after the parser returns.
- **IP-spoof defence.** `pushed_` keeps a reverse `ip_owner_` index;
  a push claiming a `local_ip` already owned by a DIFFERENT
  `agent_id` is rejected wholesale, counted at
  `pushed_rejected_count_`, and audited as `topology.push.rejected`.
- **Push-staleness.** A pushed snapshot whose `ts` is older than
  `kPushedStaleAfter` (90 s) is marked `stale=true` at
  `build_snapshot` time even if the producer didn't set the flag.
  This makes a stuck pump (UP-3) visible to operators within the
  TTL window.
- **`pushed_` holds `shared_ptr<const RawAgentSnapshot>`.** Readers
  in `get()` copy pointer handles, not the underlying 5–20 KB
  struct. O(N) pointer walk under `pushed_mu_` instead of O(N×K)
  deep copy (UP-15).
- **No invalidate-on-push.** Cache TTL alone bounds rendered
  staleness; `push_snapshot` does NOT invalidate the slot cache
  (perf-B1 / UP-6). At 100k-agent / 30s cadence the previous
  behaviour fired ~3,333 invalidations/sec and serialised readers
  behind the write lock.
- **Eviction on disconnect.** `evict_pushed(agent_id)` runs when an
  agent's Subscribe stream closes, dropping the slot + freeing IP
  claims (sec-M4 / UP-5). Re-enrolling agents start clean.
- **Audit emission.** First push per agent per process lifetime
  emits `topology.push.first` (CC6.1/CC7.3 evidence chain).
  Rejections emit `topology.push.rejected`. Successful subsequent
  pushes are NOT audited individually — per-heartbeat audit at
  3,333/sec would overwhelm `audit.db`. Counter
  `yuzu_viz_topology_pushed_total{via=...}` is the canonical
  per-push metric.
- **Capture-mode CommandContextImpl on the agent.** Agent's
  snapshot pump invokes `tar.fleet_snapshot` locally with a
  `capture` pointer that diverts plugin output into a stack-local
  string. Capture buffer caps at 2 MiB (UP-9); truncated payloads
  are dropped on the floor (seq does NOT advance) so the next pump
  cycle ships a fresh non-truncated snapshot. Pump thread is
  Run()-lifetime — spawned once before the reconnect loop, joined
  post-loop — so a brief disconnect doesn't drop the snapshot
  buffer.
- **gpb regen.** The Erlang gateway's `*_pb.erl` files must carry
  field 4 of `HeartbeatRequest`; verify via `beam_lib:chunks(...,
  [atoms])` after `rebar3 compile`. Without the field on the
  gateway, gpb silently strips it on re-encode and the server
  falls back to dispatch for gateway-routed agents — visible only
  as `yuzu_viz_topology_pushed_total{via="gateway"} == 0`.

## Durable offline-host invariants — #1320 PR 3 (Postgres substrate)

The flip wired the born-on-Postgres `OfflineEndpointStore` (schema
`endpoint_state`) into `/viz/fleet` so a host that ages out of the in-memory
60 s topology cache renders **stale-flagged instead of vanishing**. Standing
rules for the `viz_routes.cpp::handle_topology` merge:

- **Merge, never replace.** After `store_->get()` returns the live snapshot,
  the handler queries `OfflineEndpointStore::query_stale_within(kOfflineStaleWindowSecs)`
  (7-day retention) and appends a `MachineNode` ONLY for an `agent_id` present
  in `endpoint_state` but **absent** from the live snapshot. A host the live
  store still has is never duplicated.
- **Stale placeholders are empty.** A merged offline node is `stale=true` with
  **empty `processes` / `connections` / `listeners`** and `ts=0` — it carries
  identity (`agent_id`/`hostname`/`os`) only. `procs.length == 0 && stale` is
  the renderer's tell that a cube is durable-offline rather than live. (Tests
  and the renderer must treat `ts: 0` as "unknown", not "epoch".)
- **Copy-on-write.** The snapshot is only deep-copied when there is ≥1 offline
  node to add (the all-online steady state pays only the PG round-trip, no
  copy).
- **The DoS cap counts merged nodes.** `machines_max` is enforced on the
  merged total (`live + offline`), so the offline merge can never smuggle the
  response past the cap.
- **Fail-soft, and currently silent.** A PG error on the offline query returns
  an empty set → the page renders live-only with no stale cubes and **no
  operator-visible signal** (the known UP-13 gap; a degraded-marker/metric is a
  tracked follow-up). Do not "fix" this by hard-failing the request.
- **`yuzu_viz_offline_hosts_total`** counts offline nodes merged (described in
  the `server.cpp` viz metric block — keep it described, `promtool`-clean).
- **`/readyz` and a Postgres outage.** The substrate `pg_pool` readyz row
  reads the connect-breaker, which can momentarily read closed between backoff
  windows during a sustained outage (a deliberate tradeoff: don't evict a
  busy-but-healthy server). Since HA WS-8 the `pg_reachable` row carries the
  steady signal instead — a dedicated-connection probe, red within seconds of
  an outage — and pages go out on `YuzuServerPostgresUnreachable`.

## Cross-references

- REST API surface: `docs/user-manual/rest-api.md` § Fleet Visualization
- Audit log rows: `docs/user-manual/audit-log.md` (viz rows)
- Metrics: `docs/user-manual/metrics.md` § Fleet visualization metrics
- Renderer source: `static/yuzu-viz.js` (codegen via `embed_js.py`); a
  shorter copy of these invariants is kept at the head of the file so
  edits don't drift from the rules.
- Page shell source: `viz_page_ui.cpp` (header comment block).
- REST source: `viz_routes.cpp` (header comment block).
