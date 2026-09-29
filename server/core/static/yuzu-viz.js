// Yuzu fleet visualization renderer (PR 5 + PR 6 + PR 7 of feat/viz-engine
// ladder).
//
// Scene built by PR 5: scene + perspective camera + ambient + directional
// light + ground grid, with OrbitControls drag-rotate / wheel-zoom and a
// custom WASD pan listener (OrbitControls' `enablePan` is off so WASD
// owns translation). The startup axes helper was removed once the
// three-tier stacked layout (frontend / app / database planes) made the
// origin gizmo more confusing than orienting.
//
// Cube layer added by PR 6: fetches `data-yuzu-viz-url`, lays N machines
// out on a `ceil(sqrt(N))` grid with positions seeded by a deterministic
// FNV-1a hash of `agent_id` (so the same fleet renders identically across
// reloads), draws each as a translucent `MeshPhysicalMaterial` cube
// coloured by OS family, and labels them with a Sprite carrying the
// hostname. Hover surfaces a fixed-position tooltip via a Raycaster.
//
// Process layer added by PR 7: each cube owns a child `THREE.Group`
// (`yuzu-processes`) of small `SphereGeometry` dots, one per process,
// laid out on an `hash(pid|ppid)`-mod-bucket interior 3D grid (deterministic
// across reloads, jittered to break stripes) and coloured from the
// six-category palette (system / browser / database / web / runtime /
// other). The per-machine subgroup is the deliberate architecture pick
// over a single sibling processGroup (gov R6 architect NICE-1) — it
// makes per-cube localhost edges (PR 8) trivial, gives clearFleet's
// existing `traverse(disposeNode)` walk free dispose for the new
// subtree, and keeps per-machine LOD culling for PR 11 a one-liner.
// Hover raycaster checks process meshes BEFORE cube meshes so an
// operator hovering a dot through the translucent cube face sees the
// process tooltip (otherwise the cube's outer face always wins by
// distance and PR 7's whole point — drilling into processes — would
// be visually unreachable).
//
// Mount contract: mount() runs idempotently on DOMContentLoaded and on
// `htmx:afterSettle`. It locates `[data-yuzu-viz-url]` (set in viz_page_ui.cpp
// on `#viz-root`) and bails early if already mounted (canvas survival
// invariant — HTMX swaps of `#viz-overlay-panel` must not blow away the
// WebGLRenderer's GPU context).
//
// PR 8/9 add intra- and inter-machine edges; PR 10 adds the
// vulnerability overlay; PR 11 polishes (LOD, instancing, scheduler).
//
// Load contract:
//   <script type="importmap"> maps "three" -> /static/three.module.min.js
//                       and    "three/addons/controls/OrbitControls.js"
//                              -> /static/three-orbit-controls.js
//   <script type="module" src="/static/yuzu-viz.js"> runs this file.
//
// The bundle is embedded into the server binary at build time via
// embed_js.py. Source byte-identical to the served asset.

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';

// Dev-console handle. The `__internal` namespace is intentional --
// the namespace itself signals that nothing here is a stable API.
// Future PRs (interior process nodes, edges, vuln overlay) will
// reshape these fields freely; if you're a userscript or third-party
// integration, do NOT depend on `window.YuzuViz.__internal.*`. Tests
// and the developer console use this surface; everything else should
// go through the REST endpoints. (gov R6 architect SHOULD-3.)
window.YuzuViz = window.YuzuViz || {};
window.YuzuViz.__internal = window.YuzuViz.__internal || {};

const STEP = 1.5;             // WASD pan step in world units per frame at full speed
const FOV = 50;               // perspective FOV (degrees)
const NEAR = 0.1;
const FAR = 2000;
const GRID_SIZE = 200;
const GRID_DIVISIONS = 40;

function showError(rootEl, msg) {
  const e = rootEl && rootEl.querySelector('#viz-error');
  if (!e) return;
  e.textContent = msg;
  e.classList.add('shown');
}

// PR 6: per-OS cube colour palette. Keys match the lowercase substring we
// expect in `MachineNode.os` from fleet_topology.v1; default covers
// agents whose os field is empty or unknown. Hex chosen for visual
// contrast on the dark default background; opacity is set on the
// material, not the colour, so colour stays vivid through transparency.
const OS_PALETTE = {
  linux:   '#f0c674',  // tango-yellow
  darwin:  '#a0a0a0',  // mac silver
  macos:   '#a0a0a0',
  windows: '#5294e2',  // win10 blue
  default: '#666666'
};
function pickOsColor(osName) {
  if (!osName) return OS_PALETTE.default;
  const k = String(osName).toLowerCase();
  if (k.indexOf('linux') >= 0) return OS_PALETTE.linux;
  if (k.indexOf('darwin') >= 0 || k.indexOf('mac') >= 0) return OS_PALETTE.darwin;
  if (k.indexOf('windows') >= 0 || k.indexOf('win32') >= 0) return OS_PALETTE.windows;
  return OS_PALETTE.default;
}

// PR 7: per-category process-node palette. Keys exactly match the lowercase
// strings emitted by category_to_string() in process_category.hpp; any
// string not in the table falls through to `other`. Hex chosen for visual
// contrast against the cube's translucent shell on the dark canvas. Pinned
// in test_static_js_bundle.cpp — the palette is a UX contract; changing
// a colour is deliberate, not incidental.
const CATEGORY_PALETTE = {
  system:   '#6e7681',
  browser:  '#58a6ff',
  database: '#d29922',
  web:      '#56d364',
  runtime:  '#bc8cff',
  other:    '#8b949e'
};
function pickCategoryColor(category) {
  if (!category) return CATEGORY_PALETTE.other;
  // gov R7 sec-MEDIUM: trim + lowercase normalises whitespace + case
  // variants ("System ", "WEB", "Browser\t") so they don't fall through
  // to `other`. Defence in depth — server-side classify() already emits
  // canonical lowercase strings, so this only fires if a future code
  // path bypasses classification.
  const k = String(category).trim().toLowerCase();
  // gov R7 sec-MEDIUM / UP-8: use Object.hasOwnProperty.call so an
  // agent-controlled (or future-bug-injected) category="constructor" /
  // "__proto__" / "toString" / "hasOwnProperty" cannot walk the
  // prototype chain. Without this guard CATEGORY_PALETTE['constructor']
  // returns the Object constructor (truthy non-string), bypasses the
  // `||` fallback, and gets passed to new THREE.Color() which silently
  // sets r/g/b = NaN and corrupts the material. Server-side classify()
  // currently makes this unreachable (categories are computed from a
  // typed enum, not an agent string), but the renderer must not assume
  // the upstream contract — defence in depth.
  if (Object.prototype.hasOwnProperty.call(CATEGORY_PALETTE, k)) {
    return CATEGORY_PALETTE[k];
  }
  return CATEGORY_PALETTE.other;
}

// FNV-1a 32-bit hash of a string. Used to derive a stable per-agent
// position so the same fleet renders in the same grid cells across
// reloads. Math.imul matches FNV's 32-bit unsigned multiply semantics
// in V8/JSC; the final `>>> 0` re-coerces to unsigned. Pure function;
// no globals.
function hash32(str) {
  let h = 0x811c9dc5;
  const s = String(str || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

// Three-tier stacked layout. Cubes group by architectural role —
// frontend (top), application (middle), database (bottom) — so the canvas
// reads like a classic three-tier diagram instead of a single flat grid.
// Each tier renders its own `ceil(sqrt(N_tier))` grid at a fixed Y so
// every plane stays sortable on its own; the tiers are separated by
// TIER_GAP which is generously larger than CUBE_SIZE so the planes don't
// visually merge. Within a tier, machines sort by hash32(agent_id) so
// the same fleet renders identically across reloads (preserves the
// pre-tier determinism contract). Returns [{machine, x, y, z}].
const CUBE_SIZE = 8;
const CUBE_SPACING = 18;
const TIER_GAP = 22;
// Tier order is fixed: 'frontend' renders highest, 'database' lowest.
// The dict is the source of truth for the layout AND camera framing; the
// per-tier Y is derived from CUBE_SIZE so cubes rest on each plane the
// way the lone tier did before (gov R5 UP-7 mirror — non-finite TIER_Y
// would crash WebGL; the constants are arithmetic, no agent input).
const TIER_Y = {
  database: CUBE_SIZE / 2,
  app:      CUBE_SIZE / 2 + TIER_GAP,
  frontend: CUBE_SIZE / 2 + 2 * TIER_GAP
};

// Listener-port hints. The classifier prefers listener ports over process
// category because a host bound to a DB/HTTP port is by definition serving
// that protocol on this box; process names alone misclassify common cases
// (e.g. an envoy reverse proxy with a `web` category is still serving as a
// frontend regardless of whether it also hosts a database client library).
const DB_PORTS = new Set([
  3306,  // mysql / mariadb
  5432,  // postgres
  6379,  // redis
  27017, // mongo
  1521,  // oracle
  1433,  // mssql
  9042,  // cassandra / scylla
  9200,  // elasticsearch
  5984,  // couchdb
  8086,  // influxdb
  11211  // memcached
]);
// "Frontend tier" in a classic three-tier deployment means an HTTP-
// serving reverse proxy / load balancer / API gateway — the box an
// external client first reaches. Dev-server defaults (express :3000,
// angular :4200, vite :5173, django :8000) listen on HTTP but are
// architecturally application servers, not frontend infrastructure;
// putting them on the frontend plane misrepresents the topology a
// reviewer expects. Tracked as a deeper classification rework (see
// follow-up GitHub issue on function-aware tier classification).
const WEB_PORTS = new Set([
  80, 443, 8080, 8443, 8088
]);

// Classify a machine into 'frontend' | 'app' | 'database'. Priority is
// db > frontend > app so a co-located db-and-web box lands on the db
// plane (the database is the architecturally heavier role; the operator
// reading the diagram cares more about where data lives than where the
// reverse proxy lives).
//
// Tier placement is purely a VISUAL cue and is computed from
// agent-controlled fields (listener ports + process category). It carries
// NO authorization or trust weight. Do not use the tier output as a
// security signal — a hostile agent could place itself on any plane.
function classifyTier(machine) {
  if (!machine) return 'app';
  let dbScore = 0;
  let webScore = 0;
  const sockets = extractListenSockets(machine);
  for (let i = 0; i < sockets.length; i++) {
    const port = sockets[i] && sockets[i].port;
    if (DB_PORTS.has(port)) dbScore++;
    if (WEB_PORTS.has(port)) webScore++;
  }
  const procs = Array.isArray(machine.processes) ? machine.processes : [];
  for (let i = 0; i < procs.length; i++) {
    const c = procs[i] && procs[i].category;
    if (c === 'database') dbScore++;
    if (c === 'web') webScore++;
  }
  if (dbScore > 0) return 'database';
  if (webScore > 0) return 'frontend';
  return 'app';
}

function layoutMachines(machines) {
  if (!machines || machines.length === 0) return [];
  // Bucket each machine into its tier.
  const tiers = {frontend: [], app: [], database: []};
  for (let i = 0; i < machines.length; i++) {
    const m = machines[i];
    if (!m) continue;
    const t = classifyTier(m);
    tiers[t].push(m);
  }
  // Per-tier sort + per-tier grid. Top-to-bottom order in the output is
  // frontend → app → database; the consumer is order-agnostic but this
  // keeps stack traces / dev-console inspection top-down readable.
  const order = ['frontend', 'app', 'database'];
  const out = [];
  for (let ti = 0; ti < order.length; ti++) {
    const name = order[ti];
    const bucket = tiers[name];
    if (bucket.length === 0) continue;
    bucket.sort(function (a, b) {
      const ha = hash32(a && a.agent_id);
      const hb = hash32(b && b.agent_id);
      if (ha !== hb) return ha - hb;
      const ka = (a && a.agent_id) || '';
      const kb = (b && b.agent_id) || '';
      return ka < kb ? -1 : ka > kb ? 1 : 0;
    });
    const N = bucket.length;
    const cols = Math.max(1, Math.ceil(Math.sqrt(N)));
    const rows = Math.ceil(N / cols);
    const y = TIER_Y[name];
    for (let i = 0; i < N; i++) {
      const col = i % cols;
      const row = Math.floor(i / cols);
      const x = (col - (cols - 1) / 2) * CUBE_SPACING;
      const z = (row - (rows - 1) / 2) * CUBE_SPACING;
      // gov R5 UP-7: defensive — Math operations on a large/strange agent
      // count could in principle yield non-finite intermediates. WebGL
      // crashes on NaN positions, so skip silently rather than render a
      // broken scene.
      if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(z)) continue;
      out.push({machine: bucket[i], x: x, y: y, z: z});
    }
  }
  return out;
}

function buildCube(machine) {
  const color = new THREE.Color(pickOsColor(machine.os));
  const geom = new THREE.BoxGeometry(CUBE_SIZE, CUBE_SIZE, CUBE_SIZE);
  const mat = new THREE.MeshPhysicalMaterial({
    color: color,
    transparent: true,
    // Stale agents (didn't respond to fetch_snapshot before deadline)
    // get a much fainter cube so they read as "unknown" without
    // disappearing entirely.
    opacity: machine && machine.stale ? 0.08 : 0.18,
    roughness: 0.4,
    metalness: 0.0,
    clearcoat: 0.1,
    side: THREE.DoubleSide
  });
  const cube = new THREE.Mesh(geom, mat);
  // Outline: a wireframe overlay reads better than just the translucent
  // shell against a dark grid. Subtle, same colour as the cube.
  const wire = new THREE.LineSegments(
    new THREE.EdgesGeometry(geom),
    new THREE.LineBasicMaterial({color: color, transparent: true, opacity: 0.55}));
  cube.add(wire);
  // Stash the machine on userData so the raycaster can read it back
  // without a parallel id->object map.
  cube.userData.yuzuMachine = machine;
  return cube;
}

// PR 7: lay N processes out on a 3D bucket grid INSIDE a cube's local
// coordinate frame. Returns [{process, x, y, z}] in cube-local units, so
// the caller attaches the dots to a Group that's a child of the cube and
// the dots orbit/translate with the cube unchanged.
//
// Bucket count is `ceil(cbrt(max(N*1.5, 8)))` — the *1.5 slack reduces
// hash-collision rates so processes with similar pids don't pile up; the
// floor of 8 ensures even tiny machines (a handful of system procs) get
// a roughly volumetric scatter rather than collapsing onto one cell.
//
// Layout key: `hash32(pid|ppid)` is the bucket index; a secondary
// `hash32('j|pid')` provides per-process sub-cell jitter in [-0.35, 0.35]
// of cell size, breaking the grid stripe pattern while preserving the
// "same fleet renders identically across reloads" contract.
//
// gov R7 arch-S2 / UP-3 — pid recycling caveat. Position is keyed on
// `(pid|ppid)` only. Linux pid namespaces wrap at 32768 by default
// (~minutes on a busy build host); a process that exits and a new one
// landing at the same pid will render at the SAME position. This is
// intentional for v1 — it keeps the layout stable across reloads when
// fleet-wide pid space is sparse — but PR 8+ might want to add a
// `(pid, start_time_ts)` salt to disambiguate recycled processes. Until
// then, operators on long-running dashboards should treat dot-position
// stability as "same pid bucket", not "same process identity".
//
// gov R7 arch-S4 — PR 11 InstancedMesh migration. When that polish
// lands, this function's per-process `{process, x, y, z}` placement
// shape stays valid (it's input data for either Mesh-per-dot or
// InstancedMesh-instance-per-dot), but `buildProcessNode` returning a
// per-process Mesh changes contract: hit-test will return
// `intersection.instanceId` instead of `intersection.object`, and
// the `processMeshes` flat array collapses from N entries to ≤6
// (one InstancedMesh per category since the palette is the natural
// partitioning). Dispose contract changes — InstancedMesh.dispose
// frees the whole instance pool. Test pins on
// `THREE.SphereGeometry(0.22, 6, 4) + THREE.MeshBasicMaterial +
// processMeshes.push(dot)` will need to lift to the new pattern.
//
// Interior fraction is 0.78 — keeps every dot well inside the cube faces
// (which are at ±CUBE_SIZE/2) so process dots never visually escape the
// cube on rotation. Combined with PROCESS_DOT_RADIUS the worst-case dot
// surface stays inside ~95% of the cube edge.
const PROCESS_DOT_RADIUS = 0.22;
const PROCESS_INTERIOR_FRACTION = 0.78;
// gov R7 CAP-1: soft cap on dots rendered per cube. Agent-side
// `tar.fleet_snapshot` already truncates at `kFleetSnapshotMaxRows`
// (4096); this bound is for graceful degradation when an agent on
// a heavily-threaded host (e.g. a JVM with thousands of threads)
// exceeds typical visualization tolerances. Operator sees 1000 dots;
// the rest are silently dropped. The cube tooltip's `processes`
// count still shows the true total. PR 11 InstancedMesh will lift
// this materially.
const PROCESS_PER_CUBE_SOFT_CAP = 1000;
function placeProcessesInCube(processes, cubeSize) {
  if (!processes || processes.length === 0) return [];
  const N = processes.length;
  // gov: process count from the server is bounded by tar.fleet_snapshot
  // truncation (per machine), so N stays in low thousands worst-case.
  const buckets = Math.max(2, Math.ceil(Math.cbrt(Math.max(N * 1.5, 8))));
  const span = cubeSize * PROCESS_INTERIOR_FRACTION;
  const cellSize = span / buckets;
  const halfSpan = span / 2;
  const out = [];
  for (let i = 0; i < N; i++) {
    const p = processes[i] || {};
    const pidStr = String(p.pid != null ? p.pid : '0');
    const ppidStr = String(p.ppid != null ? p.ppid : '0');
    const h = hash32(pidStr + '|' + ppidStr);
    const bx = h % buckets;
    const by = Math.floor(h / buckets) % buckets;
    const bz = Math.floor(h / (buckets * buckets)) % buckets;
    const jh = hash32('j|' + pidStr);
    // Each byte of the secondary hash gives a uniform-ish ±0.35 jitter.
    const jx = ((jh & 0xff) / 255 - 0.5) * 0.7;
    const jy = (((jh >> 8) & 0xff) / 255 - 0.5) * 0.7;
    const jz = (((jh >> 16) & 0xff) / 255 - 0.5) * 0.7;
    const x = (bx + 0.5 + jx) * cellSize - halfSpan;
    const y = (by + 0.5 + jy) * cellSize - halfSpan;
    const z = (bz + 0.5 + jz) * cellSize - halfSpan;
    // gov R5 UP-7 mirror: NaN/Infinity from Math.cbrt or hash arithmetic
    // would crash WebGL on render. Skip silently rather than emit a
    // malformed mesh position.
    if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(z)) continue;
    out.push({process: p, x: x, y: y, z: z});
  }
  return out;
}

// PR 7: build a small sphere mesh for one process. Per-process geometry +
// material (matches the cube's per-instance pattern in buildCube) so
// clearFleet's traverse(disposeNode) walk releases everything cleanly
// without a shared-resource skip flag. Low-poly sphere (6×4 segments)
// because each dot is ~0.22 units against a 8-unit cube — the polygon
// silhouette difference vs higher segment counts is invisible at any
// reasonable camera distance, and the triangle count savings matter
// once a 100-machine fleet × 50 processes/machine = 5k spheres land on
// the GPU. PR 11 polish moves to InstancedMesh.
//
// MeshBasicMaterial (not Phong/PBR) because lighting on a 0.22-unit
// dot is invisible and the basic shader is materially cheaper per draw
// call. The colour comes straight from the category palette.
// gov R7 UP-2: graceful-degradation wrapper around per-process mesh
// construction. If THREE.Color, SphereGeometry, or MeshBasicMaterial
// throws (e.g. a future palette-table typo emits a non-hex string,
// or a Three.js minor bump gains stricter validation), the throw must
// NOT cascade out of addMachines and leave a half-built processGroup
// orphaned with N-K dots in processMeshes. Caller treats null return
// as "skip this process; render the others".
function buildProcessNode(process) {
  try {
    const color = new THREE.Color(pickCategoryColor(process && process.category));
    const geom = new THREE.SphereGeometry(PROCESS_DOT_RADIUS, 6, 4);
    const mat = new THREE.MeshBasicMaterial({color: color});
    const mesh = new THREE.Mesh(geom, mat);
    mesh.userData.yuzuProcess = process;
    return mesh;
  } catch (e) {
    // Console-only; don't surface to the operator overlay (one bad
    // process should not blank the whole fleet). spdlog-style breadcrumb
    // for dev console + Sentry-style remote beacons should one ever land.
    if (typeof console !== 'undefined' && console.warn) {
      console.warn('Yuzu viz: buildProcessNode failed; skipping dot.', e);
    }
    return null;
  }
}

function buildHostnameLabel(hostname) {
  // Sprite-based label — always faces the camera, no text-vs-cube
  // perspective fight. Render to a small canvas, upload as a texture.
  const canvas = document.createElement('canvas');
  canvas.width = 256;
  canvas.height = 64;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = 'rgba(0,0,0,0.55)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.font = 'bold 28px sans-serif';
  ctx.fillStyle = '#ffffff';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  let label = String(hostname || '(unknown)');
  if (label.length > 24) label = label.slice(0, 23) + '…';
  ctx.fillText(label, canvas.width / 2, canvas.height / 2);
  const tex = new THREE.CanvasTexture(canvas);
  tex.minFilter = THREE.LinearFilter;
  // gov R6 perf-F4: hostname canvas is rendered at fixed 256x64 and never
  // sampled below its native resolution (Sprite is screen-space scaled,
  // not perspective-shrunk). Disable mipmap generation -- saves ~30% GPU
  // VRAM per sprite (no mip-chain build) and skips the synchronous GPU
  // pipeline pause on each upload during addMachines() at high N.
  tex.generateMipmaps = false;
  tex.needsUpdate = true;
  const mat = new THREE.SpriteMaterial({map: tex, transparent: true, depthTest: false});
  const sprite = new THREE.Sprite(mat);
  sprite.scale.set(8, 2, 1);
  return sprite;
}

// ── PR 9 / UAT 2026-05-12: socket primitive + cross-machine edges ─────────
// Listening sockets render as small bright spheres around the top face of
// each cube; ESTABLISHED connections render as lines joining the source
// socket to the destination's listening socket on the peer machine (or to
// a stub marker if the destination is outside the fleet).

const SOCKET_DOT_RADIUS = 0.34;
const SOCKET_RING_RADIUS = CUBE_SIZE * 0.32;    // ring radius on top face
const SOCKET_TOP_Y = CUBE_SIZE * 0.5 + 0.30;    // small lift above top face
const SOCKET_LABEL_Y = SOCKET_TOP_Y + 0.55;     // port label sits just above sphere
const EDGE_OPACITY_INTERNAL = 0.85;             // fleet ↔ fleet
const EDGE_OPACITY_EXTERNAL = 0.40;             // fleet → off-cluster
const EXTERNAL_STUB_LENGTH = CUBE_SIZE * 0.45;
// Wire geometry — TubeGeometry along a QuadraticBezier curve.
// MeshBasicMaterial linewidth is silently clamped to 1px on every
// browser we ship to, so we fake a thick line with a thin tube. The
// curve has a small perpendicular bow at its midpoint so wires don't
// all overlap on a straight vertical column between tier planes.
const EDGE_TUBE_RADIUS_INTERNAL = 0.10;
const EDGE_TUBE_RADIUS_EXTERNAL = 0.07;
const EDGE_TUBE_SEGMENTS = 20;
const EDGE_TUBE_RADIAL = 6;

// Normalise an IPv4-mapped-in-IPv6 address (`::ffff:192.168.1.5`) into the
// bare v4 form so `dst_addr` matches against `machine.local_ips` reliably.
// Bare v6 / v4 / empty are returned unchanged.
function normIp(addr) {
  if (!addr) return '';
  const s = String(addr);
  const m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(s);
  return m ? m[1] : s;
}

// Return true for any bind address that cannot accept connections from
// another instance: 127.0.0.0/8, ::1, and the v4-mapped-in-v6 form. The
// agent emits LISTEN rows for every kernel-visible listener (this matches
// what netstat's `attribution` action would surface for the host); the
// renderer's job is to keep only the ones that participate in inter-host
// topology.
function isLoopbackBind(addr) {
  if (!addr) return false;
  let s = String(addr);
  // Strip a single bracket wrapping pair `[...]` so `[::1]` and
  // `[::ffff:127.0.0.1]` collapse to the same path as their bare forms
  // (Gate 7 sec LOW + UP-2 partial fix).
  if (s.length >= 2 && s.charAt(0) === '[' && s.charAt(s.length - 1) === ']')
    s = s.substring(1, s.length - 1);
  if (s === '::1') return true;
  if (s.indexOf('127.') === 0) return true;
  // ::ffff:127.x.x.x — v4-mapped-in-v6 loopback. Rare but seen on dual-
  // stack Linux when a binder uses AF_INET6 without IPV6_V6ONLY.
  if (/^::ffff:127\./i.test(s)) return true;
  return false;
}

// Walk a machine's `listeners` array (schema_minor 3 + the `local_addr`
// field added in schema_minor 4) and return its unique LISTEN sockets
// that COULD be reached from another instance — i.e. drop loopback-only
// binds (`127.0.0.0/8`, `::1`). 0.0.0.0 and :: bind every interface
// including loopback and stay in; specific NIC IPs stay in. Dual-stack
// `tcp` + `tcp6` LISTENs on the same port collapse into one visible
// socket (operators perceive them as one bound port). `connections[]`
// is NOT consulted: the server strips LISTEN-only rows from that array
// because they'd render as edges into the void; the dedicated
// `listeners[]` field is the renderer's source of truth.
function extractListenSockets(machine) {
  if (!machine || !Array.isArray(machine.listeners)) return [];
  const seen = new Map();
  for (let i = 0; i < machine.listeners.length; i++) {
    const l = machine.listeners[i];
    if (!l) continue;
    const port = Number(l.port);
    if (!Number.isFinite(port) || port <= 0) continue;
    // Surface filter — only listeners reachable from other instances
    // belong on the cube surface. A listener bound to 127.0.0.1 cannot
    // be contacted by any peer cube, so it has no place in the
    // inter-host visual layer.
    if (isLoopbackBind(l.local_addr)) continue;
    const proto = String(l.proto || 'tcp').toLowerCase();
    const protoNorm = (proto === 'tcp6' ? 'tcp' : proto === 'udp6' ? 'udp' : proto);
    const key = protoNorm + ':' + port;
    if (seen.has(key)) continue;
    seen.set(key, {
      port: port,
      proto: protoNorm,
      pid: Number(l.pid) | 0,
      process_name: l.process_name || null
    });
  }
  return Array.from(seen.values()).sort(function (a, b) {
    return a.port - b.port;
  });
}

// Lay N listening sockets out on a ring on the cube's top face.
// Returns cube-local coordinates so the caller attaches them to a Group
// that's a child of the cube (same parent-transform pattern as PR 7).
function placeSocketsOnCube(sockets) {
  const n = sockets.length;
  const out = [];
  if (n === 0) return out;
  const ringR = n <= 1 ? 0 : SOCKET_RING_RADIUS;
  for (let i = 0; i < n; i++) {
    const theta = n <= 1 ? 0 : (2 * Math.PI * i) / n;
    out.push({
      socket: sockets[i],
      x: ringR * Math.cos(theta),
      y: SOCKET_TOP_Y,
      z: ringR * Math.sin(theta)
    });
  }
  return out;
}

function buildSocketSphere(socket, procName) {
  const geom = new THREE.SphereGeometry(SOCKET_DOT_RADIUS, 10, 8);
  // Warm cream against the dark canvas so listeners read as "open ports"
  // visually distinct from the cooler-coloured process dots inside the
  // cube. Single colour: protocol/port semantics live in the tooltip,
  // not in the colour channel.
  const mat = new THREE.MeshBasicMaterial({color: 0xfff2cc});
  const mesh = new THREE.Mesh(geom, mat);
  mesh.userData.yuzuSocket = {
    port: socket.port,
    proto: socket.proto,
    pid: socket.pid,
    proc_name: procName || null
  };
  return mesh;
}

function buildPortLabel(port) {
  // Same canvas-Sprite recipe as buildHostnameLabel — keeps the renderer
  // free of CSS2DRenderer / DOM-overlay machinery and the label always
  // faces the camera.
  const canvas = document.createElement('canvas');
  canvas.width = 96;
  canvas.height = 40;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = 'rgba(0,0,0,0.6)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.font = 'bold 22px sans-serif';
  ctx.fillStyle = '#fff2cc';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(':' + port, canvas.width / 2, canvas.height / 2);
  const tex = new THREE.CanvasTexture(canvas);
  tex.minFilter = THREE.LinearFilter;
  tex.generateMipmaps = false;
  tex.needsUpdate = true;
  const mat = new THREE.SpriteMaterial({map: tex, transparent: true, depthTest: false});
  const sprite = new THREE.Sprite(mat);
  sprite.scale.set(2.2, 0.9, 1);
  return sprite;
}

// ── Talking sockets (cross-tier connection origins) ────────────────────────
// Each established outbound connection has a *talking* socket on the source
// host — the ephemeral source port that the peer's listener answers. We
// aggregate by unique destination (dstIp:dstPort) so a busy frontend with
// many parallel connections to the same app port surfaces ONE dot, not
// hundreds. The dot sits on the cube's bottom face mirror of the listener
// ring on top, so the metaphor reads top-down: "incoming on the roof,
// outgoing through the floor". Inter-tier wires anchor at this dot so the
// operator sees both ends of the connection as concrete sockets.
const TALKING_SOCKET_DOT_RADIUS = 0.28;
const TALKING_SOCKET_RING_RADIUS = CUBE_SIZE * 0.32;
const TALKING_SOCKET_BOTTOM_Y = -CUBE_SIZE * 0.5 - 0.30;
const TALKING_SOCKET_COLOR = 0x7ec4f8; // cool blue, distinct from listener cream

// Walk a machine's ESTABLISHED outbound connections (rows whose src_addr
// is one of THIS machine's local_ips) and return one entry per unique
// (proto, dst_ip, dst_port) tuple — the canonical "we talk to N:p over
// proto" set. Loopback destinations are dropped (those edges are drawn
// inside the cube as Local-scope lines, not surface wires). External
// (off-fleet) destinations stay because their wire anchors at this same
// dot — the stub marker on the far end signals "out of fleet".
function extractTalkingDests(machine) {
  if (!machine || !Array.isArray(machine.connections)) return [];
  const localIps = new Set();
  const lips = Array.isArray(machine.local_ips) ? machine.local_ips : [];
  for (let i = 0; i < lips.length; i++) {
    const ip = normIp(lips[i]);
    if (ip) localIps.add(ip);
  }
  const seen = new Map();
  for (let i = 0; i < machine.connections.length; i++) {
    const c = machine.connections[i];
    if (!c || c.state !== 'ESTABLISHED') continue;
    const srcIp = normIp(c.src_addr);
    if (!localIps.has(srcIp)) continue;       // only the outbound side
    const dstIp = normIp(c.dst_addr);
    const dstPort = Number(c.dst_port);
    if (!dstIp || !Number.isFinite(dstPort) || dstPort <= 0) continue;
    if (isLoopbackBind(dstIp)) continue;      // intra-host loopback edges live inside the cube
    const proto = String(c.proto || 'tcp').toLowerCase();
    const protoNorm = (proto === 'tcp6' ? 'tcp' : proto === 'udp6' ? 'udp' : proto);
    const key = protoNorm + ':' + dstIp + ':' + dstPort;
    if (seen.has(key)) continue;
    seen.set(key, {
      dst_ip: dstIp,
      dst_port: dstPort,
      proto: protoNorm
    });
  }
  return Array.from(seen.values()).sort(function (a, b) {
    if (a.dst_ip !== b.dst_ip) return a.dst_ip < b.dst_ip ? -1 : 1;
    return a.dst_port - b.dst_port;
  });
}

// Mirror of placeSocketsOnCube but on the bottom face, with TALKING_SOCKET
// radius. Returns cube-local coordinates.
function placeTalkingSocketsOnCube(dests) {
  const n = dests.length;
  const out = [];
  if (n === 0) return out;
  const ringR = n <= 1 ? 0 : TALKING_SOCKET_RING_RADIUS;
  for (let i = 0; i < n; i++) {
    const theta = n <= 1 ? 0 : (2 * Math.PI * i) / n;
    out.push({
      dest: dests[i],
      x: ringR * Math.cos(theta),
      y: TALKING_SOCKET_BOTTOM_Y,
      z: ringR * Math.sin(theta)
    });
  }
  return out;
}

function buildTalkingSocketSphere(dest) {
  const geom = new THREE.SphereGeometry(TALKING_SOCKET_DOT_RADIUS, 10, 8);
  const mat = new THREE.MeshBasicMaterial({color: TALKING_SOCKET_COLOR});
  const mesh = new THREE.Mesh(geom, mat);
  mesh.userData.yuzuTalkingSocket = {
    dst_ip: dest.dst_ip,
    dst_port: dest.dst_port,
    proto: dest.proto
  };
  return mesh;
}

// Build a curved tube between two points. Internal fleet wires use a
// CubicBezierCurve3 with both end-tangents pointing vertically so the
// wire exits the talking socket straight down through the cube's
// bottom face, runs nearly-straight through the middle, and re-enters
// the listening socket from straight above through the cube's top
// face. A small horizontal bow keyed on `bowKey` fans parallel wires
// apart so two frontends both talking to the same app don't trace the
// same path. External stubs (off-fleet destinations) keep the simpler
// quadratic upward bow — there's no listener cube to approach.
function buildWireTube(srcPos, endPos, opts) {
  const isExternal = opts && opts.external;
  // gov R5 UP-7 mirror / Gate 7 UP-10: NaN in any control coordinate
  // produces NaN tube vertices, which paint as black geometry that fills
  // the canvas on some drivers and corrupts the depth buffer. Refuse to
  // build for non-finite inputs and return a no-op invisible mesh
  // (preserves the caller's .userData wiring without rendering).
  if (!Number.isFinite(srcPos.x) || !Number.isFinite(srcPos.y) || !Number.isFinite(srcPos.z) ||
      !Number.isFinite(endPos.x) || !Number.isFinite(endPos.y) || !Number.isFinite(endPos.z)) {
    const noop = new THREE.Mesh(
      new THREE.BufferGeometry(),
      new THREE.MeshBasicMaterial({transparent: true, opacity: 0}));
    return noop;
  }
  const dir = endPos.clone().sub(srcPos);
  const len = dir.length();
  let curve;
  if (isExternal || len < 1e-3) {
    const horiz = Math.hypot(dir.x, dir.z);
    const mid = srcPos.clone().lerp(endPos, 0.5);
    const bow = Math.min(5, horiz * 0.15 + 1.0);
    const ctrl = mid.clone().add(new THREE.Vector3(0, bow, 0));
    curve = new THREE.QuadraticBezierCurve3(srcPos, ctrl, endPos);
  } else {
    // Cubic Bezier with vertical end-tangents. P1 sits straight below
    // the source (P0) and P2 straight above the destination (P3) so
    // both tangents are (0, ±1, 0). The middle of the curve
    // interpolates between them as a mostly-straight diagonal/vertical
    // run, which is exactly what we want: a brief arc out of each
    // cube, then a straight stretch in free space.
    const lift = Math.max(2, Math.min(8, len * 0.25));
    // Fan parallel wires sideways so a pair of frontends both talking
    // to app-01 don't render the same path. Perpendicular to the line's
    // horizontal projection.
    let perp = new THREE.Vector3(-dir.z, 0, dir.x);
    if (perp.lengthSq() < 1e-6) perp.set(1, 0, 0);
    perp.normalize();
    const sign = (hash32(String(opts && opts.bowKey || '')) & 1) ? 1 : -1;
    const fan = perp.multiplyScalar(0.8 * sign);
    const p1 = srcPos.clone().add(new THREE.Vector3(0, -lift, 0)).add(fan);
    const p2 = endPos.clone().add(new THREE.Vector3(0,  lift, 0)).add(fan);
    curve = new THREE.CubicBezierCurve3(srcPos, p1, p2, endPos);
  }
  const radius = isExternal ? EDGE_TUBE_RADIUS_EXTERNAL : EDGE_TUBE_RADIUS_INTERNAL;
  const geom = new THREE.TubeGeometry(
    curve, EDGE_TUBE_SEGMENTS, radius, EDGE_TUBE_RADIAL, false);
  const colour = isExternal ? 0x8090a0 : 0x4ea8de;
  const mat = new THREE.MeshBasicMaterial({
    color: colour,
    transparent: true,
    opacity: isExternal ? EDGE_OPACITY_EXTERNAL : EDGE_OPACITY_INTERNAL
  });
  return new THREE.Mesh(geom, mat);
}

function buildScene() {
  const scene = new THREE.Scene();
  // Background pulled from CSS bg token at render time so theme switches
  // without a JS rebuild. fallback matches the dark default.
  const bgVar = getComputedStyle(document.documentElement)
    .getPropertyValue('--bg').trim() || '#0d1117';
  scene.background = new THREE.Color(bgVar);

  // Ambient + directional light gives flat translucent cubes (PR 6+) a
  // subtle face-shading hint without overwhelming the colour palette.
  scene.add(new THREE.AmbientLight(0xffffff, 0.55));
  const dir = new THREE.DirectionalLight(0xffffff, 0.65);
  dir.position.set(50, 80, 30);
  scene.add(dir);

  // Ground grid -- subtle, dim, gives the camera spatial reference. Pulls
  // its colours from CSS tokens like the rest of the design system.
  const gridFg = getComputedStyle(document.documentElement)
    .getPropertyValue('--mds-color-theme-text-tertiary').trim() || '#6e7681';
  const grid = new THREE.GridHelper(GRID_SIZE, GRID_DIVISIONS,
                                    new THREE.Color(gridFg),
                                    new THREE.Color(gridFg));
  grid.material.opacity = 0.25;
  grid.material.transparent = true;
  grid.position.y = 0;
  scene.add(grid);

  // No origin axes gizmo: the three-tier stacked layout (TIER_Y) gives
  // operators a richer spatial cue than the RGB X/Y/Z lines did, and the
  // lines themselves clipped through the bottom tier cubes at startup.

  return scene;
}

function mount() {
  const root = document.querySelector('[data-yuzu-viz-url]');
  if (!root) return;                          // not on /viz/fleet
  if (root.dataset.yuzuVizMounted === '1')    // already mounted -- HTMX swap
    return;                                   // re-fired afterSettle
  root.dataset.yuzuVizMounted = '1';

  const canvas = root.querySelector('#viz-canvas');
  if (!canvas) {
    showError(root, 'viz-canvas element missing');
    return;
  }

  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha: true,
      // gov R4 DEP-2: 'high-performance' would force the dGPU on hybrid
      // laptops, costing battery for an empty grid + a few hundred
      // translucent cubes. 'default' lets the browser pick (typically
      // the iGPU on battery, dGPU on AC) which is plenty for our scene.
      // Revisit if PR 11 LOD/instancing measurements show iGPU choking.
      powerPreference: 'default'
    });
  } catch (e) {
    showError(root, 'WebGL not available in this browser: ' + (e && e.message));
    return;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.setSize(canvas.clientWidth, canvas.clientHeight, false);

  // gov R4 UP-3 / CHAOS-2: WebGL context can be lost at runtime (GPU
  // driver crash, OS GPU reset, sleep/wake, dGPU<->iGPU switch). Without
  // a handler the rAF loop keeps calling renderer.render() on the dead
  // context, spamming console errors and showing a frozen frame with no
  // operator-visible signal. We surface the loss via #viz-error and stop
  // the rAF loop; on restored we hide the error and let the operator
  // refresh manually (Three.js does not auto-recover scene state, so a
  // full reload is the cleanest path).
  let _contextLost = false;
  canvas.addEventListener('webglcontextlost', (e) => {
    e.preventDefault();
    _contextLost = true;
    showError(root, 'WebGL context lost (GPU reset or driver issue). ' +
                    'Reload the page to recover.');
  }, false);
  canvas.addEventListener('webglcontextrestored', () => {
    _contextLost = false;
    const err = root.querySelector('#viz-error');
    if (err) err.classList.remove('shown');
  }, false);

  const scene = buildScene();

  const camera = new THREE.PerspectiveCamera(
    FOV, canvas.clientWidth / Math.max(canvas.clientHeight, 1), NEAR, FAR);
  // Frame the three-tier stack. Target sits at the middle tier's Y so
  // OrbitControls rotates around the visual centre of the stack instead
  // of the floor grid (which was the old single-grid default).
  camera.position.set(45, 60, 45);
  camera.lookAt(0, TIER_Y.app, 0);

  // OrbitControls drives drag-to-rotate + wheel-zoom; pan is disabled so
  // the WASD listener owns translation in screen space.
  const controls = new OrbitControls(camera, canvas);
  controls.target.set(0, TIER_Y.app, 0);
  controls.enablePan = false;
  controls.enableDamping = true;
  controls.dampingFactor = 0.08;
  controls.minDistance = 4;
  controls.maxDistance = 400;
  // Allow looking from above and below but not flipping past the poles.
  controls.minPolarAngle = 0.05;
  controls.maxPolarAngle = Math.PI - 0.05;

  // ── WASD pan ────────────────────────────────────────────────────────────
  // Pan vector accumulates each frame from the keys-held set; rAF loop
  // applies it in camera screen space. This avoids the per-keydown jitter
  // of binding pan directly to the keydown event.
  //
  // gov R4 sec-M1 / UP-6: skip when a focused element is text-editable so
  // typing W/A/S/D into a future overlay-panel <input> / <textarea> /
  // contenteditable region doesn't have its keystrokes silently eaten.
  const heldKeys = new Set();
  function isEditableTarget(t) {
    if (!t) return false;
    const tag = t.tagName;
    if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
    return t.isContentEditable === true;
  }
  function onKey(e, down) {
    if (isEditableTarget(e.target)) return;
    const k = e.key && e.key.toLowerCase();
    if (k !== 'w' && k !== 'a' && k !== 's' && k !== 'd') return;
    if (down) heldKeys.add(k); else heldKeys.delete(k);
    e.preventDefault();
  }
  window.addEventListener('keydown', (e) => onKey(e, true));
  window.addEventListener('keyup',   (e) => onKey(e, false));

  // Reusable temporaries so the rAF loop doesn't allocate per frame.
  // gov R4 perf-S2 / HP-1: `_offset` was previously allocated fresh each
  // frame WASD held; hoist alongside the other temporaries. Removed the
  // dead `_quat` declaration that was never referenced.
  const _right  = new THREE.Vector3();
  const _up     = new THREE.Vector3(0, 1, 0);
  const _mvDir  = new THREE.Vector3();
  const _offset = new THREE.Vector3();

  function applyWasdPan() {
    if (heldKeys.size === 0) return;
    // Camera-basis right vector: up x forward.
    camera.getWorldDirection(_mvDir).normalize();
    _right.crossVectors(_up, _mvDir).normalize();
    // Build a world-space pan from the keys: W=+screenY, S=-screenY,
    // A=-screenX, D=+screenX. We translate BOTH camera position AND
    // controls.target so OrbitControls' rotate-around-target stays sane.
    let dx = 0, dy = 0;
    if (heldKeys.has('w')) dy += STEP;
    if (heldKeys.has('s')) dy -= STEP;
    if (heldKeys.has('a')) dx -= STEP;
    if (heldKeys.has('d')) dx += STEP;
    if (dx === 0 && dy === 0) return;
    // dx maps along camera right, dy along camera up. Reset and reuse
    // the hoisted _offset rather than allocating per frame.
    _offset.set(0, 0, 0)
           .addScaledVector(_right, dx)
           .addScaledVector(_up,    dy);
    camera.position.add(_offset);
    controls.target.add(_offset);
  }

  // ── Resize handler ──────────────────────────────────────────────────────
  // ResizeObserver on the canvas keeps the renderer + camera aspect in
  // sync as the window or surrounding chrome changes. Cheaper than
  // listening to window.resize and querying clientWidth.
  const ro = new ResizeObserver(() => {
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (w === 0 || h === 0) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  });
  ro.observe(canvas);

  // ── PR 6: cube + label group ──────────────────────────────────────────
  // Single THREE.Group hosts every machine cube + sprite label. fetchAndRender
  // empties + repopulates the group on success; on failure the group stays
  // empty and #viz-error surfaces a message so the operator never sees a
  // silent blank scene.
  const fleetGroup = new THREE.Group();
  fleetGroup.name = 'yuzu-fleet';
  scene.add(fleetGroup);

  // Cubes that are eligible for raycasting hit-tests. Maintained alongside
  // fleetGroup so the raycaster doesn't have to walk wireframe LineSegments
  // (cheaper + avoids hit-test on the outline material).
  const cubeMeshes = [];

  // PR 7: process dots eligible for raycasting hit-tests. Maintained as a
  // flat array (rather than walking the per-cube subgroups) so the
  // raycaster does one Object3D.matrixWorld read per dot instead of
  // recursing through each cube's child graph. Mirrors the `cubeMeshes`
  // flat-array pattern declared just above (gov R7 C-S-4 — both
  // siblings under fleetGroup follow the same lifecycle: const
  // declaration in mount scope, push() in addMachines, .length = 0 in
  // clearFleet, intersectObjects(arr, false) first arg in onMouseMove,
  // exposure on __internal). PR 8 edge meshes will follow the same
  // pattern; arch-S1 recommends folding all three flat indices into a
  // single registration array to enforce the lockstep contract by
  // construction.
  const processMeshes = [];

  // PR 9 / UAT 2026-05-12: socket spheres + cross-machine edge meshes
  // tracked as flat raycast indices alongside cubeMeshes/processMeshes.
  // Hover order (closest semantic first): sockets → processes → edges →
  // cubes — see the raycaster block below for the rationale spelled out.
  const socketMeshes = [];
  const talkingSocketMeshes = [];
  const edgeMeshes = [];

  // gov R6 happy-S1 / UP-20: cubes carry a wireframe LineSegments child
  // (added in buildCube). The straight `for child of fleetGroup.children`
  // walk only sees the cube — wireframe geometry + material would never
  // get disposed and VRAM would leak proportional to N * #refills. PR 11
  // adds a 60s background refresher; without recursive disposal the leak
  // would be cumulative. Use traverse() so every descendant material +
  // geometry + texture lands on dispose().
  function disposeNode(obj) {
    if (obj.material) {
      const mats = Array.isArray(obj.material) ? obj.material : [obj.material];
      for (let i = 0; i < mats.length; i++) {
        if (mats[i].map) mats[i].map.dispose();
        mats[i].dispose();
      }
    }
    if (obj.geometry) obj.geometry.dispose();
  }
  function clearFleet() {
    // gov R7 UP-1: reset the flat raycast indices BEFORE walking the
    // tree. If `traverse(disposeNode)` throws partway through (e.g. a
    // future Sprite child has a corrupt material.map, or a PR 8
    // edgeMesh's geometry was already disposed), the function exits
    // with the throw and the trailing `length = 0` lines never run —
    // leaving stale references to half-disposed meshes in cubeMeshes
    // and processMeshes that the next mousemove raycasts against.
    // Resetting first means the raycast index reflects the
    // "no-longer-valid" state immediately; even on a throw, the worst
    // case is a benign empty raycast rather than ray-against-disposed.
    cubeMeshes.length = 0;
    processMeshes.length = 0;
    socketMeshes.length = 0;
    talkingSocketMeshes.length = 0;
    edgeMeshes.length = 0;
    while (fleetGroup.children.length > 0) {
      const child = fleetGroup.children[0];
      fleetGroup.remove(child);
      // Recurse to release wireframe LineSegments + sprite-internal
      // textures + the PR 7 per-machine processGroup subtree. Without
      // recursion, every refill leaks N machines × M processes worth of
      // SphereGeometry + MeshBasicMaterial into VRAM (PR 11 adds 60s
      // background refresher; this would be cumulative).
      child.traverse(disposeNode);
    }
  }

  function addMachines(machines) {
    clearFleet();
    const placements = layoutMachines(machines);

    // PR 9: world-space socket positions keyed by `${normalisedIp}:${port}`.
    // Built during the per-machine pass below, consumed by the cross-machine
    // edge pass that runs once every cube is placed. A separate map for
    // cube centres keyed by IP supports the "cube anchor" fallback when a
    // destination IP is in the fleet but the matching listener wasn't
    // captured in the snapshot (rare, but happens when the dst agent's
    // snapshot is stale).
    const socketWorldPos = new Map();
    const cubeWorldPosByIp = new Map();
    // World-space talking-socket positions keyed by
    // `${agent_id}|${dst_ip}:${dst_port}`. One dot per cube per unique
    // outbound destination. The edge pass uses this to anchor the source
    // end of cross-tier wires at a concrete socket primitive instead of
    // the cube centre — so the operator sees both ends of the connection
    // as visible sockets.
    const talkingWorldPos = new Map();

    for (let i = 0; i < placements.length; i++) {
      const p = placements[i];
      const cube = buildCube(p.machine);
      cube.position.set(p.x, p.y, p.z);
      fleetGroup.add(cube);
      cubeMeshes.push(cube);
      const label = buildHostnameLabel(p.machine.hostname);
      // Hostname label sits just below the cube (UAT request, 2026-05-12) so
      // the volume above the cube stays clear for the asset-tag chip stack
      // that ships separately and so operators reading the grid top-down
      // associate the text with the machine immediately under it.
      label.position.set(p.x, p.y - CUBE_SIZE * 0.85, p.z);
      fleetGroup.add(label);

      // PR 7: per-machine process subgroup. Attached as a child of the
      // cube (NOT as a sibling under fleetGroup) so the dots inherit
      // every transform on the cube — no synchronisation required as
      // the OrbitControls camera moves or as PR 11 toggles per-cube
      // visibility for LOD culling. Layout coordinates are cube-local.
      //
      // gov R7 CAP-1: agent-side `tar.fleet_snapshot` caps at
      // kFleetSnapshotMaxRows (4096 today). At the documented
      // machines_max ceiling (100k) the worst-case fleet would render
      // 4096 × 100,000 = 409M dots — well past anything WebGL can
      // handle pre-InstancedMesh (PR 11). For PR 7 we soft-cap dots
      // per cube at PROCESS_PER_CUBE_SOFT_CAP so a single
      // pathological-host fleet (e.g. a JVM threadpool with 4000
      // threads) doesn't lock up the renderer; the cap is well above
      // typical-machine counts (~50–200) so normal operators are
      // unaffected.
      // gov R7 HP-1: the earlier `buildCube(p.machine)` and
      // `buildHostnameLabel(p.machine.hostname)` calls already deref
      // `p.machine` without a guard — by the time we reach here,
      // `p.machine` is guaranteed non-null (`layoutMachines` filters
      // bogus rows). Drop the redundant `p.machine &&` clause.
      const allProcs = Array.isArray(p.machine.processes)
        ? p.machine.processes : [];
      const procs = allProcs.length > PROCESS_PER_CUBE_SOFT_CAP
        ? allProcs.slice(0, PROCESS_PER_CUBE_SOFT_CAP)
        : allProcs;
      if (procs.length > 0) {
        const processGroup = new THREE.Group();
        processGroup.name = 'yuzu-processes';
        cube.add(processGroup);
        const procPlacements = placeProcessesInCube(procs, CUBE_SIZE);
        // PR 8: pid → in-cube position index. Built alongside dots so the
        // edge pass below can resolve src_pid/dst_pid to the two endpoints
        // without re-walking the placements array. Stays empty if a
        // process row is missing pid or carries a non-finite one.
        const pidToPos = new Map();
        for (let j = 0; j < procPlacements.length; j++) {
          const pp = procPlacements[j];
          const dot = buildProcessNode(pp.process);
          // gov R7 UP-2: buildProcessNode returns null on construction
          // failure (e.g. THREE.Color throws). Skip the failed dot
          // rather than letting the throw cascade — the rest of the
          // fleet still renders.
          if (!dot) continue;
          dot.position.set(pp.x, pp.y, pp.z);
          processGroup.add(dot);
          processMeshes.push(dot);
          if (pp.process && Number.isFinite(pp.process.pid)) {
            pidToPos.set(pp.process.pid, new THREE.Vector3(pp.x, pp.y, pp.z));
          }
        }

        // PR 8: faint interior LineSegments between paired loopback peers.
        // The server has already (a) classified the connection as Local,
        // (b) resolved the reciprocal half's pid into dst_pid, and (c)
        // dropped Local edges that couldn't be paired — so by this point
        // a connection with scope==='local' AND both src_pid + dst_pid set
        // is guaranteed to map to two dots already placed in this cube.
        // Lines join the processGroup so clearFleet's traverse(disposeNode)
        // walk releases the BufferGeometry + LineBasicMaterial together
        // with the per-dot resources.
        const conns = Array.isArray(p.machine.connections) ? p.machine.connections : [];
        for (let k = 0; k < conns.length; k++) {
          const c = conns[k];
          if (!c || c.scope !== 'local') continue;
          if (!Number.isFinite(c.src_pid) || !Number.isFinite(c.dst_pid)) continue;
          const aPos = pidToPos.get(c.src_pid);
          const bPos = pidToPos.get(c.dst_pid);
          if (!aPos || !bPos) continue;
          const geom = new THREE.BufferGeometry().setFromPoints([aPos, bPos]);
          const mat = new THREE.LineBasicMaterial(
            {color: 0xffffff, transparent: true, opacity: 0.3});
          const line = new THREE.LineSegments(geom, mat);
          processGroup.add(line);
        }
      }

      // PR 9 / UAT 2026-05-12: socket spheres + port labels on the cube
      // top face. Built per-machine because each cube owns its sockets;
      // world-space positions are stashed in `socketWorldPos` so the
      // cross-machine edge pass (below) can resolve dst_ip:dst_port to
      // the matching socket on the peer cube.
      const procNameByPid = new Map();
      for (let q = 0; q < allProcs.length; q++) {
        const pr = allProcs[q];
        if (pr && Number.isFinite(pr.pid))
          procNameByPid.set(pr.pid, pr.name || null);
      }
      const sockets = extractListenSockets(p.machine);
      if (sockets.length > 0) {
        const socketGroup = new THREE.Group();
        socketGroup.name = 'yuzu-sockets';
        cube.add(socketGroup);
        const socketPlacements = placeSocketsOnCube(sockets);
        for (let s = 0; s < socketPlacements.length; s++) {
          const sp = socketPlacements[s];
          // Prefer the server-supplied process_name on the listener
          // (matches the listening socket's owning pid even when the
          // process didn't appear in the processes[] array — e.g.
          // owner pid lives in a different cgroup the agent couldn't
          // walk). Fall back to the pid → name join on processes[].
          const procName = sp.socket.process_name ||
                           procNameByPid.get(sp.socket.pid) || null;
          const sphere = buildSocketSphere(sp.socket, procName);
          sphere.position.set(sp.x, sp.y, sp.z);
          socketGroup.add(sphere);
          socketMeshes.push(sphere);
          const portLabel = buildPortLabel(sp.socket.port);
          portLabel.position.set(sp.x, SOCKET_LABEL_Y, sp.z);
          socketGroup.add(portLabel);

          // Record world-space position so cross-machine edges land on
          // the sphere. Every local_ip the snapshot reports is a valid
          // anchor for this listener (LISTEN sockets typically bind to
          // 0.0.0.0 / ::; the agent expands that into the machine's
          // local_ips when populating the snapshot).
          const wp = new THREE.Vector3(p.x + sp.x, p.y + sp.y, p.z + sp.z);
          const ips = Array.isArray(p.machine.local_ips) ? p.machine.local_ips : [];
          for (let ipi = 0; ipi < ips.length; ipi++) {
            const ip = normIp(ips[ipi]);
            if (ip) socketWorldPos.set(ip + ':' + sp.socket.port, wp);
          }
        }
      }

      // Talking sockets — outbound side of each unique fleet-internal /
      // external destination this cube speaks to. Mirror of the listener
      // ring but on the BOTTOM face so the spatial metaphor reads
      // unambiguously: incoming arrives on the roof, outgoing leaves
      // through the floor. The cross-machine edge pass anchors the
      // source end of every wire at the matching dot here.
      const talkingDests = extractTalkingDests(p.machine);
      if (talkingDests.length > 0) {
        const talkingGroup = new THREE.Group();
        talkingGroup.name = 'yuzu-talking-sockets';
        cube.add(talkingGroup);
        const talkingPlacements = placeTalkingSocketsOnCube(talkingDests);
        const agentId = (p.machine && p.machine.agent_id) || '';
        for (let t = 0; t < talkingPlacements.length; t++) {
          const tp = talkingPlacements[t];
          const sphere = buildTalkingSocketSphere(tp.dest);
          sphere.position.set(tp.x, tp.y, tp.z);
          talkingGroup.add(sphere);
          talkingSocketMeshes.push(sphere);
          // World position the edge pass reads to anchor the source end.
          const wp = new THREE.Vector3(p.x + tp.x, p.y + tp.y, p.z + tp.z);
          talkingWorldPos.set(
            agentId + '|' + tp.dest.dst_ip + ':' + tp.dest.dst_port, wp);
        }
      }

      // Also record the cube centre keyed by every local_ip — used by
      // the edge pass when the destination IP belongs to a fleet machine
      // but the matching LISTEN socket wasn't in its snapshot (stale or
      // not-yet-ingested peer). The edge lands on the cube centre
      // instead of dropping silently.
      const cubeCentre = new THREE.Vector3(p.x, p.y, p.z);
      const lips = Array.isArray(p.machine.local_ips) ? p.machine.local_ips : [];
      for (let ipi = 0; ipi < lips.length; ipi++) {
        const ip = normIp(lips[ipi]);
        if (ip) cubeWorldPosByIp.set(ip, cubeCentre);
      }
    }

    // ── PR 9 cross-machine edges ────────────────────────────────────────
    // After every cube + socket is placed, walk every machine's
    // ESTABLISHED connections and draw an edge from the source cube
    // (which is *this* machine for any outbound or accepted half) to the
    // destination socket on the peer cube. Two operators of dedup:
    //   • Skip the inbound half of each ESTABLISHED pair — keep only
    //     rows where src_addr ∈ this machine's local_ips. Source side
    //     "owns" the edge; dst side renders the listening socket.
    //   • Per-direction canonical key (srcIp:srcPort → dstIp:dstPort) so
    //     two snapshots reporting the same connection from both ends
    //     don't draw twice.
    // External destinations (dst not in any fleet machine's local_ips)
    // render as a short stub from the source cube going outward with a
    // small marker the operator can hover for the off-cluster address.
    const drawnEdges = new Set();
    for (let i = 0; i < placements.length; i++) {
      const p = placements[i];
      const conns = Array.isArray(p.machine.connections) ? p.machine.connections : [];
      const srcIps = new Set();
      const localIps = Array.isArray(p.machine.local_ips) ? p.machine.local_ips : [];
      for (let j = 0; j < localIps.length; j++) {
        const ip = normIp(localIps[j]);
        if (ip) srcIps.add(ip);
      }
      for (let k = 0; k < conns.length; k++) {
        const c = conns[k];
        if (!c || c.state !== 'ESTABLISHED') continue;
        const srcIp = normIp(c.src_addr);
        // Only draw from the "outbound" side. The accepted-side row has
        // src_addr = local listener IP and we'd double-draw.
        if (!srcIps.has(srcIp)) continue;
        const dstIp = normIp(c.dst_addr);
        const dstPort = Number(c.dst_port);
        if (!dstIp || !Number.isFinite(dstPort)) continue;

        const edgeKey = srcIp + ':' + (Number(c.src_port) | 0) + '→' +
                        dstIp + ':' + dstPort;
        if (drawnEdges.has(edgeKey)) continue;
        drawnEdges.add(edgeKey);

        // Source-end anchor: prefer the talking-socket dot on the source
        // cube's bottom face (placed in the per-machine pass above) so
        // both ends of the wire are concrete socket primitives. Falls
        // back to the cube centre when the talking dot is missing —
        // shouldn't happen given the same connection rows feed both
        // passes, but the fallback keeps the wire from disappearing if
        // extractTalkingDests ever filters a row the edge pass keeps.
        const srcAgentId = (p.machine && p.machine.agent_id) || '';
        const talkingKey = srcAgentId + '|' + dstIp + ':' + dstPort;
        const srcAnchorPos = talkingWorldPos.get(talkingKey) ||
                             new THREE.Vector3(p.x, p.y, p.z);
        const dstSocketPos = socketWorldPos.get(dstIp + ':' + dstPort) ||
                             cubeWorldPosByIp.get(dstIp);

        let endPos, isExternal;
        if (dstSocketPos) {
          endPos = dstSocketPos;
          isExternal = false;
        } else {
          // External destination — stub line pointing roughly away from
          // the fleet centre so adjacent cubes don't have their stubs
          // overlap with their neighbours' faces. Length is small so
          // the marker stays clearly tethered to the source cube.
          const fromCentre = srcAnchorPos.clone().normalize();
          if (fromCentre.lengthSq() < 1e-6) fromCentre.set(1, 0, 0);
          endPos = srcAnchorPos.clone().addScaledVector(fromCentre, EXTERNAL_STUB_LENGTH);
          isExternal = true;
        }

        // Internal edges in a cool blue; external stubs in a dimmer grey
        // so the fleet-internal traffic reads as "ours" at a glance.
        // TubeGeometry over a QuadraticBezierCurve3 — gives real 3D
        // thickness (LineBasicMaterial.linewidth is silently clamped to
        // 1px on every browser we ship to) AND a gentle arc that keeps
        // parallel wires from collapsing onto the same path.
        const line = buildWireTube(srcAnchorPos, endPos, {
          external: isExternal,
          bowKey: srcAgentId + '|' + dstIp + ':' + dstPort
        });
        line.userData.yuzuEdge = {
          src_hostname: p.machine.hostname,
          src_ip: srcIp,
          src_port: Number(c.src_port) | 0,
          dst_ip: dstIp,
          dst_port: dstPort,
          proto: String(c.proto || 'tcp'),
          external: isExternal
        };
        fleetGroup.add(line);
        edgeMeshes.push(line);

        if (isExternal) {
          // Tiny ring marker at the end of the stub so external dests
          // are visible (a bare line into empty space is easy to miss
          // on a dense canvas). Same warm colour family as cubes for
          // unknown OS so it reads as "out of fleet" not "another tier".
          const ringGeom = new THREE.RingGeometry(0.22, 0.36, 16);
          const ringMat = new THREE.MeshBasicMaterial({
            color: 0x8090a0, transparent: true, opacity: 0.7, side: THREE.DoubleSide
          });
          const ring = new THREE.Mesh(ringGeom, ringMat);
          ring.position.copy(endPos);
          ring.lookAt(camera.position);
          ring.userData.yuzuEdge = line.userData.yuzuEdge;
          fleetGroup.add(ring);
          edgeMeshes.push(ring);
        }
      }
    }
  }

  // ── PR 6: tooltip ─────────────────────────────────────────────────────
  // Lazily created div; appended to viz-root so it inherits the page's
  // stacking + cleanup. Position is updated in screen space on
  // mousemove.
  let _tooltip = null;
  function ensureTooltip() {
    if (_tooltip) return _tooltip;
    _tooltip = document.createElement('div');
    _tooltip.id = 'viz-tooltip';
    _tooltip.style.cssText =
      'position:absolute;pointer-events:none;background:rgba(0,0,0,0.85);' +
      'color:#fff;padding:0.4rem 0.6rem;border-radius:0.25rem;' +
      'font-size:0.78rem;line-height:1.3;z-index:6;display:none;' +
      // gov R6 UP-3: hostname / os come from agent payloads. Without
      // word-break + overflow caps a 100KB hostname turns the tooltip
      // into a screen-filling rectangle on hover. max-width caps the
      // visual footprint; word-break:break-all forces wrapping inside
      // a long unbroken string; max-height clips the worst case.
      'max-width:320px;max-height:240px;overflow:hidden;' +
      'word-break:break-all;border:1px solid #444;';
    root.appendChild(_tooltip);
    return _tooltip;
  }
  function hideTooltip() {
    if (_tooltip) _tooltip.style.display = 'none';
  }
  function showTooltip(machine, evt) {
    const tip = ensureTooltip();
    // gov R6 UP-1 / sec-MEDIUM: agent-controlled `processes` / `connections`
    // could be a non-array masquerading as one (e.g. {length: '<svg/onload=…>'}).
    // The `|| 0` short-circuit returns the malicious string and concatenates
    // it raw into innerHTML. Coerce through Number(...)|0 so any non-numeric
    // shape collapses to 0 and a 32-bit integer is the only thing the
    // template ever interpolates.
    const proc = Array.isArray(machine.processes) ? Number(machine.processes.length) | 0 : 0;
    const conn = Array.isArray(machine.connections) ? Number(machine.connections.length) | 0 : 0;
    const stale = machine.stale ? ' <span style="color:#f0c674">(stale)</span>' : '';
    tip.innerHTML =
      '<div style="font-weight:600;margin-bottom:0.2rem">' +
      escapeHtml(machine.hostname || '(unknown)') + stale + '</div>' +
      '<div>os: ' + escapeHtml(machine.os || '?') + '</div>' +
      '<div>processes: ' + proc + '</div>' +
      '<div>connections: ' + conn + '</div>';
    // Position relative to the canvas. Add a small offset so the cursor
    // doesn't sit on the tooltip and trigger flicker.
    const rect = canvas.getBoundingClientRect();
    tip.style.left = (evt.clientX - rect.left + 12) + 'px';
    tip.style.top = (evt.clientY - rect.top + 12) + 'px';
    tip.style.display = 'block';
  }
  // PR 7: process tooltip — pid / name / user / category. Same XSS
  // hardening as the cube tooltip: name + user are agent-controlled
  // strings, so every interpolated string field goes through escapeHtml,
  // and pid is coerced through `Number(...) | 0` so an agent-controlled
  // non-numeric pid collapses to 0 rather than getting concatenated raw.
  // The shared #viz-tooltip element inherits the cube tooltip's
  // max-width/max-height/word-break caps so a 100KB process name cannot
  // DoS layout (gov R6 UP-3 mirror).
  // gov R7 UP-10: agent-controlled `process.name` could be 1MB+ from a
  // pathological cmdline-as-comm parse on Linux. escapeHtml runs a
  // synchronous regex over the full string and would stutter 50ms+ per
  // tooltip render. Cap at 256 chars before escapeHtml so the worst-case
  // hover stays under the 16ms frame budget. The tooltip's existing
  // word-break + max-height CSS cap (gov R6 UP-3) bounds layout; this
  // truncation bounds CPU.
  const TOOLTIP_NAME_MAX = 256;
  function clampForTooltip(s) {
    const str = String(s);
    if (str.length <= TOOLTIP_NAME_MAX) return str;
    return str.slice(0, TOOLTIP_NAME_MAX - 1) + '…';
  }
  function showProcessTooltip(process, evt) {
    const tip = ensureTooltip();
    const pid = Number(process && process.pid) | 0;
    tip.innerHTML =
      '<div style="font-weight:600;margin-bottom:0.2rem">' +
      'pid ' + pid + ': ' +
      escapeHtml(clampForTooltip((process && process.name) || '(unknown)')) + '</div>' +
      '<div>user: ' + escapeHtml(clampForTooltip((process && process.user) || '?')) + '</div>' +
      '<div>category: ' + escapeHtml(clampForTooltip((process && process.category) || 'other')) + '</div>';
    const rect = canvas.getBoundingClientRect();
    tip.style.left = (evt.clientX - rect.left + 12) + 'px';
    tip.style.top = (evt.clientY - rect.top + 12) + 'px';
    tip.style.display = 'block';
  }
  // PR 9 / UAT 2026-05-12: socket tooltip — port / proto / owning process.
  // Same XSS / clamp posture as the process tooltip; pid coerced through
  // `Number(...) | 0`.
  function showSocketTooltip(socket, evt) {
    const tip = ensureTooltip();
    const port = Number(socket && socket.port) | 0;
    const proto = escapeHtml(clampForTooltip((socket && socket.proto) || 'tcp'));
    const pid = Number(socket && socket.pid) | 0;
    const procName = socket && socket.proc_name;
    tip.innerHTML =
      '<div style="font-weight:600;margin-bottom:0.2rem">' +
      'listening: ' + proto + '/:' + port + '</div>' +
      (pid > 0
        ? '<div>pid ' + pid +
          (procName ? ': ' + escapeHtml(clampForTooltip(procName)) : '') + '</div>'
        : '<div style="color:#888">owner pid not reported</div>');
    const rect = canvas.getBoundingClientRect();
    tip.style.left = (evt.clientX - rect.left + 12) + 'px';
    tip.style.top = (evt.clientY - rect.top + 12) + 'px';
    tip.style.display = 'block';
  }
  // PR 12: talking-socket tooltip — outbound (dst_ip:dst_port + proto).
  // Mirror of showSocketTooltip but framed from the sender's perspective:
  // "this cube → that endpoint" so the operator can trace the outbound
  // side of any cross-tier connection.
  function showTalkingSocketTooltip(ts, evt) {
    const tip = ensureTooltip();
    const dstIp = escapeHtml(clampForTooltip((ts && ts.dst_ip) || '?'));
    const dstPort = Number(ts && ts.dst_port) | 0;
    const proto = escapeHtml(clampForTooltip((ts && ts.proto) || 'tcp'));
    tip.innerHTML =
      '<div style="font-weight:600;margin-bottom:0.2rem">' +
      'talking: ' + proto + ' → ' + dstIp + ':' + dstPort + '</div>';
    const rect = canvas.getBoundingClientRect();
    tip.style.left = (evt.clientX - rect.left + 12) + 'px';
    tip.style.top = (evt.clientY - rect.top + 12) + 'px';
    tip.style.display = 'block';
  }
  // PR 9: edge tooltip — src → dst with port + proto. External edges
  // flag the off-fleet destination so operators can spot egress to
  // anything not represented by a cube.
  function showEdgeTooltip(edge, evt) {
    const tip = ensureTooltip();
    const src = escapeHtml(clampForTooltip(edge.src_hostname || edge.src_ip || '?')) +
                ':' + (Number(edge.src_port) | 0);
    const dst = escapeHtml(clampForTooltip(edge.dst_ip || '?')) +
                ':' + (Number(edge.dst_port) | 0);
    const proto = escapeHtml(clampForTooltip(edge.proto || 'tcp'));
    const ext = edge.external
      ? '<div style="color:#f0c674">external destination</div>' : '';
    tip.innerHTML =
      '<div style="font-weight:600;margin-bottom:0.2rem">' + proto + ' connection</div>' +
      '<div>' + src + ' → ' + dst + '</div>' + ext;
    const rect = canvas.getBoundingClientRect();
    tip.style.left = (evt.clientX - rect.left + 12) + 'px';
    tip.style.top = (evt.clientY - rect.top + 12) + 'px';
    tip.style.display = 'block';
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return c === '&' ? '&amp;' :
             c === '<' ? '&lt;' :
             c === '>' ? '&gt;' :
             c === '"' ? '&quot;' : '&#39;';
    });
  }

  const _ray = new THREE.Raycaster();
  const _ndc = new THREE.Vector2();
  // gov R7 perf-F1: rAF-throttle the raycast. mousemove fires up to
  // ~120 Hz on macOS trackpads. With cubeMeshes + processMeshes both
  // potentially in the hundreds of thousands at fleet ceilings, two
  // intersectObjects calls at 120 Hz is the renderer's dominant CPU
  // cost (perf-F1). Coalesce events into one raycast per
  // requestAnimationFrame tick (~60 Hz cap) by stashing the latest
  // event and processing it at most once per frame. PR 11 polish adds
  // a per-cube bounding-sphere prefilter (perf-F2) and InstancedMesh
  // (which collapses processMeshes from N entries to 1).
  let _pendingMouseEvt = null;
  let _rafScheduled = false;
  function processPendingMouse() {
    _rafScheduled = false;
    const evt = _pendingMouseEvt;
    _pendingMouseEvt = null;
    if (!evt) return;
    if (cubeMeshes.length === 0 && processMeshes.length === 0 &&
        socketMeshes.length === 0 && talkingSocketMeshes.length === 0) {
      hideTooltip();
      return;
    }
    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    _ndc.x = ((evt.clientX - rect.left) / rect.width) * 2 - 1;
    _ndc.y = -((evt.clientY - rect.top) / rect.height) * 2 + 1;
    _ray.setFromCamera(_ndc, camera);

    // PR 9 hover order — most specific first: sockets sit on top of the
    // cube and are operator-relevant for vuln-surface inspection, so a
    // hover over a port sphere must surface port details before
    // anything underneath. After sockets: processes (PR 7 reasoning —
    // process dots live inside the translucent shell and the cube face
    // would always win on distance otherwise). After processes: edges
    // (1D primitives drawn on top of cube faces; an operator hovering
    // a connection line through the cube wants edge details, not the
    // cube). Last: the cube itself.
    // gov R7 perf-F1 / R9 perf: edges use Line primitives, which
    // intersect against the ray with a threshold. Setting _ray.params.
    // Line.threshold tightens the hit zone so the operator has to be
    // visibly close to a line rather than the default ±1 unit which
    // would let edges hijack hovers from cubes behind them.
    _ray.params.Line = _ray.params.Line || {};
    _ray.params.Line.threshold = 0.25;
    if (socketMeshes.length > 0) {
      const socketHits = _ray.intersectObjects(socketMeshes, false);
      if (socketHits.length > 0 && socketHits[0].object.userData.yuzuSocket) {
        showSocketTooltip(socketHits[0].object.userData.yuzuSocket, evt);
        return;
      }
    }
    if (talkingSocketMeshes.length > 0) {
      const talkingHits = _ray.intersectObjects(talkingSocketMeshes, false);
      if (talkingHits.length > 0 && talkingHits[0].object.userData.yuzuTalkingSocket) {
        showTalkingSocketTooltip(talkingHits[0].object.userData.yuzuTalkingSocket, evt);
        return;
      }
    }
    if (processMeshes.length > 0) {
      const procHits = _ray.intersectObjects(processMeshes, false);
      if (procHits.length > 0 && procHits[0].object.userData.yuzuProcess) {
        showProcessTooltip(procHits[0].object.userData.yuzuProcess, evt);
        return;
      }
    }
    if (edgeMeshes.length > 0) {
      const edgeHits = _ray.intersectObjects(edgeMeshes, false);
      if (edgeHits.length > 0 && edgeHits[0].object.userData.yuzuEdge) {
        showEdgeTooltip(edgeHits[0].object.userData.yuzuEdge, evt);
        return;
      }
    }
    const hits = _ray.intersectObjects(cubeMeshes, false);
    if (hits.length > 0 && hits[0].object.userData.yuzuMachine) {
      showTooltip(hits[0].object.userData.yuzuMachine, evt);
    } else {
      hideTooltip();
    }
  }
  function onMouseMove(evt) {
    _pendingMouseEvt = evt;
    if (!_rafScheduled) {
      _rafScheduled = true;
      requestAnimationFrame(processPendingMouse);
    }
  }
  canvas.addEventListener('mousemove', onMouseMove);
  canvas.addEventListener('mouseleave', hideTooltip);

  // PR 9-pre / Slice 3 — double-click a cube to open the per-host
  // drill-down page in a new tab. Reuses _ray (no second Raycaster)
  // and respects the existing hover hit-order: only acts when the
  // outermost cube wins the hit-test (after sockets / processes /
  // edges have first refusal). dblclick on a socket or process is
  // reserved for future drill-down (do nothing for now).
  function onCubeDblClick(evt) {
    if (cubeMeshes.length === 0) return;
    const rect = canvas.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    _ndc.x = ((evt.clientX - rect.left) / rect.width) * 2 - 1;
    _ndc.y = -((evt.clientY - rect.top) / rect.height) * 2 + 1;
    _ray.setFromCamera(_ndc, camera);
    // Sockets / processes / edges have higher priority — if a hover-
    // priority object wins the hit, do nothing (dblclick on a port or
    // process dot is reserved).
    if (socketMeshes.length > 0 &&
        _ray.intersectObjects(socketMeshes, false).length > 0) return;
    if (talkingSocketMeshes.length > 0 &&
        _ray.intersectObjects(talkingSocketMeshes, false).length > 0) return;
    if (processMeshes.length > 0 &&
        _ray.intersectObjects(processMeshes, false).length > 0) return;
    const hits = _ray.intersectObjects(cubeMeshes, false);
    if (hits.length === 0 || !hits[0].object.userData.yuzuMachine) return;
    const machine = hits[0].object.userData.yuzuMachine;
    const cube = hits[0].object;
    heartbeatFlash(cube);
    const url = `/viz/host/${encodeURIComponent(machine.agent_id)}`;
    window.open(url, '_blank', 'noopener,noreferrer');
  }
  canvas.addEventListener('dblclick', onCubeDblClick);
  // Cmd/Ctrl + single-click is a power-user accelerator that mirrors
  // browser middle-click / Cmd-click semantics: opens the drill-down
  // in a new tab without the flash animation.
  canvas.addEventListener('click', (evt) => {
    if (!(evt.metaKey || evt.ctrlKey)) return;
    onCubeDblClick(evt);
  });

  // Heartbeat flash: lerp the cube material's emissive intensity in
  // a double-peak envelope. First (lower) peak at t=100 ms, second
  // (higher) peak at t=200 ms, settles back to baseline by t=350 ms.
  // Single rAF loop driven by elapsed-time interpolation — not
  // nested setTimeout — so the animation rides on the renderer's
  // own clock.
  function heartbeatFlash(cube) {
    const mat = cube.material;
    if (!mat || !mat.emissive) return;
    const baseR = mat.emissive.r;
    const baseG = mat.emissive.g;
    const baseB = mat.emissive.b;
    const baseI = (typeof mat.emissiveIntensity === 'number') ? mat.emissiveIntensity : 1.0;
    const start = performance.now();
    function envelope(t) {
      // Two Gaussian-ish bumps. Heights tuned so peak2 > peak1.
      const bump = (mu, height, sigma) => height *
        Math.exp(-((t - mu) * (t - mu)) / (2 * sigma * sigma));
      return bump(100, 0.6, 30) + bump(200, 1.0, 35);
    }
    function step(now) {
      const t = now - start;
      if (t > 350 || !Number.isFinite(t)) {
        mat.emissive.setRGB(baseR, baseG, baseB);
        mat.emissiveIntensity = baseI;
        return;
      }
      const k = envelope(t);
      // Push the cube emissive toward white by k.
      mat.emissive.setRGB(baseR + k, baseG + k, baseB + k);
      mat.emissiveIntensity = baseI + k;
      requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  // ── PR 6: data fetch ──────────────────────────────────────────────────
  // Asynchronous because the cache-cold path on the server can take up to
  // 5 s (fleet-wide tar.fleet_snapshot dispatch). Surface failures via
  // #viz-error rather than letting the scene sit empty.
  function setError(msg) {
    const e = root.querySelector('#viz-error');
    if (!e) return;
    e.textContent = msg;
    e.classList.add('shown');
  }
  function clearError() {
    const e = root.querySelector('#viz-error');
    if (e) e.classList.remove('shown');
  }

  function fetchAndRender() {
    const url = root.getAttribute('data-yuzu-viz-url');
    if (!url) {
      setError('viz: data-yuzu-viz-url not set on #viz-root');
      return Promise.resolve(null);
    }
    return fetch(url, {credentials: 'same-origin', headers: {'Accept': 'application/json'}})
      .then(function (r) {
        // gov R5 UP-17: an operator who was admin on page-load can be
        // demoted mid-session. The fetch returns 403 (RBAC denied) and
        // the renderer must surface that explicitly rather than show a
        // blank scene. 401 means the session itself died; reload routes
        // through the server's auth middleware.
        if (r.status === 401) {
          // gov R6 UP-15: scrub any cubes we'd previously rendered so the
          // operator doesn't see "live data" cubes alongside an "access
          // denied" overlay -- mixed signals would imply they still see
          // the fleet despite the denial.
          clearFleet();
          setError('Session expired. Please reload the page.');
          return null;
        }
        if (r.status === 403) {
          clearFleet();
          setError('Access denied. Your role no longer permits viewing the fleet topology.');
          return null;
        }
        if (r.status === 503) {
          clearFleet();
          setError('Fleet visualization is currently disabled by an administrator.');
          return null;
        }
        if (r.status === 413) {
          // gov R6 UP-6: opaque "HTTP 413" leaves the operator without an
          // actionable next step. Name the cap so they know what to ask
          // an admin to raise (or to scope the fleet down via management
          // groups).
          clearFleet();
          setError('Fleet exceeds the configured machines_max cap. Ask an administrator to ' +
                   'raise --viz-machines-max or scope the request via a management group.');
          return null;
        }
        if (!r.ok) {
          clearFleet();
          setError('Failed to fetch fleet topology (HTTP ' + r.status + '). Try reloading.');
          return null;
        }
        return r.json();
      })
      .then(function (data) {
        if (!data) return null;
        // gov R6 UP-10: a malformed payload (TypeError on machines.slice or
        // similar) would otherwise fall through to the network catch and
        // be misclassified as a network error. Validate the shape first so
        // the operator gets a payload-error message instead.
        if (typeof data !== 'object' || data === null) {
          setError('Malformed topology payload (not an object).');
          return null;
        }
        if (data.schema !== 'fleet_topology.v1') {
          // gov R6 UP-8: future schema bump -> hint the operator to reload
          // their browser cache, since the renderer is module-cached.
          setError('Unexpected topology schema: ' + (data.schema || '<missing>') +
                   '. Reload the page (Ctrl+Shift+R) to pick up the new dashboard.');
          return null;
        }
        // gov R6 UP-9 / UP-10: distinguish "machines field missing/null"
        // (server bug) and "machines is wrong type" (schema regression)
        // from "0 machines" (legitimate empty fleet). Each gets a distinct
        // operator-visible message.
        if (data.machines === undefined || data.machines === null) {
          clearError();
          clearFleet();
          setError('Server returned no machines field. This is a server-side bug; check the server log.');
          return null;
        }
        if (!Array.isArray(data.machines)) {
          clearError();
          clearFleet();
          setError('Malformed topology payload (machines is not an array).');
          return null;
        }
        clearError();
        addMachines(data.machines);
        return data;
      })
      .catch(function (err) {
        // gov R5 UP-17: network failures land here too; the user just
        // gets the same friendly overlay rather than a console-only
        // exception. SyntaxError from r.json() also lands here (truncated
        // body) -- distinguish in the message so the operator can tell
        // "connection broken" from "server returned bad JSON".
        const m = (err && err.message) ? err.message : 'network error';
        const kind = (err && err.name === 'SyntaxError')
                       ? 'Malformed JSON from server (truncated response or proxy issue)'
                       : 'Cannot reach server';
        clearFleet();
        setError(kind + ': ' + m);
        return null;
      });
  }

  // ── Render loop ────────────────────────────────────────────────────────
  // Continuous rAF: keeps the OrbitControls damping animation smooth and
  // gives WASD frames somewhere to apply. PR 11 may throttle to render-
  // on-input once the scene complexity (PR 7+ process nodes, PR 8/9 edges)
  // makes the cost more meaningful.
  function tick() {
    // gov R4 UP-3: when the GL context is lost, skip render() to avoid
    // spamming "context-lost" warnings. The handler above already
    // surfaced #viz-error; the operator must reload to recover.
    //
    // gov R5 UP-7: defensive Number.isFinite check on camera.position.
    // OrbitControls + WASD math should never push the camera into NaN
    // territory, but a single bad input can cascade through every frame
    // (renderer.render with NaN matrices crashes WebGL on some drivers).
    // Reset to a sane default and fall through to render so the operator
    // sees something rather than a hung scene.
    if (!_contextLost) {
      // gov R6 architect NICE-2: a poisoned `_offset` add can land non-
      // finite values on BOTH camera.position and controls.target. Reset
      // only camera.position would be insufficient because the next
      // `controls.update()` call recomputes camera.position from the bad
      // target, re-poisoning it within one frame. Reset both, then
      // controls.update() so the target write takes effect for this frame.
      const cp = camera.position;
      const ct = controls.target;
      if (!Number.isFinite(cp.x) || !Number.isFinite(cp.y) || !Number.isFinite(cp.z) ||
          !Number.isFinite(ct.x) || !Number.isFinite(ct.y) || !Number.isFinite(ct.z)) {
        camera.position.set(45, 60, 45);
        controls.target.set(0, TIER_Y.app, 0);
        camera.lookAt(0, TIER_Y.app, 0);
      }
      applyWasdPan();
      controls.update();
      renderer.render(scene, camera);
    }
    requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  // Kick off the initial topology fetch once the scene is alive. Don't
  // block the rAF loop — by the time the data lands, the scaffold is
  // already rendering, and addMachines() just splices into fleetGroup.
  fetchAndRender();

  // Expose for dev-console inspection AND test code (idempotency guard,
  // mount-time assertions, manual data refresh). Not a public API.
  // gov R6 architect SHOULD-3: dev-console handles live under __internal
  // so the namespace itself signals "do not depend on this" to userscripts
  // and third-party integrations. Tests use the same path.
  const dev = window.YuzuViz.__internal;
  dev.scene = scene;
  dev.camera = camera;
  dev.renderer = renderer;
  dev.controls = controls;
  dev.heldKeys = heldKeys;
  dev.root = root;
  dev.fleetGroup = fleetGroup;
  dev.cubeMeshes = cubeMeshes;
  dev.processMeshes = processMeshes;
  dev.socketMeshes = socketMeshes;
  dev.talkingSocketMeshes = talkingSocketMeshes;
  dev.edgeMeshes = edgeMeshes;
  dev.addMachines = addMachines;
  dev.fetchAndRender = fetchAndRender;
}

// Mount on initial DOMContentLoaded (full page nav) and on htmx:afterSettle
// (in case the page is reached via an HTMX swap inside a parent shell).
// mount() itself is idempotent so multiple firings are safe.
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', mount, { once: true });
} else {
  mount();
}
document.body.addEventListener('htmx:afterSettle', mount);
