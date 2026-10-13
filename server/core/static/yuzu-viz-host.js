// Per-host fleet viz renderer (PR 9-pre / Slice 2).
//
// Loaded as an ES module by /viz/host/<agent_id>; reads agent_id from the
// data-agent-id attribute on #viz-host-root, fetches the per-host topology
// JSON, and renders a bipartite IPC graph (processes + sockets as nodes;
// owns + connection edges) via Cytoscape.js with the built-in `cose`
// force-directed layout.
//
// Layout note: `cose` ships in cytoscape core — no layout extension to
// register, no dependency tree. The faster `fcose` reimplementation was
// dropped: it's a UMD bundle with an external `cose-base` dependency that
// doesn't resolve cleanly when cytoscape itself is loaded as an ESM
// importmap entry. For a single host's IPC graph (hundreds of nodes) the
// built-in cose is more than fast enough.

import cytoscape from "cytoscape";

const SCHEMA = "host_topology.v1";

function getAgentId() {
  const root = document.getElementById("viz-host-root");
  return root ? root.getAttribute("data-agent-id") : "";
}

// Tagged sentinel so the caller can branch on auth/disable status without
// string-matching exception messages.
class TopologyError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function loadTopology(agentId) {
  const url = `/api/v1/viz/host/${encodeURIComponent(agentId)}/topology`;
  const r = await fetch(url, { credentials: "same-origin" });
  if (r.status === 401) throw new TopologyError("not signed in", 401);
  if (r.status === 403) throw new TopologyError("permission denied", 403);
  if (r.status === 503) throw new TopologyError("viz endpoint disabled", 503);
  if (!r.ok) throw new TopologyError(`fetch failed: ${r.status}`, r.status);
  const j = await r.json();
  if (j.schema !== SCHEMA) throw new TopologyError(`unexpected schema: ${j.schema}`, 0);
  return j;
}

// Bipartite element builder: processes and sockets are both nodes, typed by
// `kind`. Process node id = "p<pid>". Listener socket id = "l<proto>:<port>:<pid>".
// Connection-half socket id = "c<proto>:<addr>:<port>:<pid>".
function buildElements(machine) {
  const elements = [];
  const sockets = new Map();

  for (const p of machine.processes || []) {
    elements.push({
      data: {
        id: `p${p.pid}`,
        kind: "process",
        label: `${p.name}:${p.pid}`,
        pid: p.pid,
        ppid: p.ppid,
        user: p.user,
        category: p.category,
      },
    });
  }

  function addSocket(id, dataExtra) {
    if (sockets.has(id)) return;
    sockets.set(id, true);
    elements.push({ data: { id, kind: "socket", ...dataExtra } });
  }

  for (const l of machine.listeners || []) {
    const sid = `l${l.proto}:${l.port}:${l.pid || 0}`;
    addSocket(sid, {
      label: `${l.proto} :${l.port}`,
      subkind: "listen",
      proto: l.proto,
      port: l.port,
    });
    if (l.pid) {
      elements.push({
        data: { source: `p${l.pid}`, target: sid, kind: "owns" },
      });
    }
  }

  for (const c of machine.connections || []) {
    if (c.scope !== "local" || !c.dst_pid) continue;
    const srcSid = `c${c.proto}:${c.src_addr}:${c.src_port}:${c.src_pid}`;
    const dstSid = `c${c.proto}:${c.dst_addr}:${c.dst_port}:${c.dst_pid}`;
    addSocket(srcSid, {
      label: `${c.src_addr}:${c.src_port}`,
      subkind: "established",
      proto: c.proto,
    });
    addSocket(dstSid, {
      label: `${c.dst_addr}:${c.dst_port}`,
      subkind: "established",
      proto: c.proto,
    });
    elements.push({ data: { source: `p${c.src_pid}`, target: srcSid, kind: "owns" } });
    elements.push({ data: { source: `p${c.dst_pid}`, target: dstSid, kind: "owns" } });
    elements.push({ data: { source: srcSid, target: dstSid, kind: "connection" } });
  }

  return elements;
}

let _cy = null;

// Cytoscape cannot read CSS variables, so resolve the slate tokens
// (yuzu.css) at render time and hand it the values.
function graphStyle() {
  const css = getComputedStyle(document.documentElement);
  const tok = (name) => css.getPropertyValue(name).trim();
  // Cytoscape's font-family grammar rejects single quotes; the token uses them.
  const mono = tok("--mds-font-family-mono").replace(/'/g, '"');
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        "font-family": mono,
        "border-width": 0,
      },
    },
    {
      selector: 'node[kind = "process"]',
      style: {
        "background-color": tok("--c1"),
        width: 32,
        height: 32,
        color: tok("--ink2"),
        "font-size": 11,
        "text-valign": "top",
        "text-margin-y": -6,
        "text-background-color": tok("--surface"),
        "text-background-opacity": 1,
        "text-background-padding": 3,
        "text-background-shape": "roundrectangle",
      },
    },
    {
      selector: 'node[kind = "socket"]',
      style: {
        "background-color": tok("--c3"),
        shape: "round-rectangle",
        width: "label",
        height: 18,
        padding: 6,
        color: tok("--bg"),
        "font-size": 9.5,
        "font-weight": 500,
        "text-valign": "center",
      },
    },
    {
      selector: "node:selected",
      style: {
        "border-width": 2,
        "border-style": "dashed",
        "border-color": tok("--primary-h"),
      },
    },
    {
      selector: 'edge[kind = "owns"]',
      style: { "line-color": tok("--faint"), "line-style": "dashed", width: 1 },
    },
    {
      selector: 'edge[kind = "connection"]',
      style: { "line-color": tok("--c2"), width: 2 },
    },
  ];
}

function renderGraph(machine) {
  const container = document.getElementById("ipc-graph");
  if (!container) return null;
  if (_cy) _cy.destroy();
  _cy = cytoscape({
    container,
    elements: buildElements(machine),
    layout: { name: "cose", animate: false },
    style: graphStyle(),
  });

  // Slice 4: tap a process node → broadcast the pid so the TAR tree
  // pane below can scroll-into-view + highlight the matching <details>.
  // One-way: IPC graph → TAR tree. Reverse direction is post-v1.
  _cy.on("tap", 'node[kind = "process"]', (evt) => {
    const pid = evt.target.data("pid");
    if (pid == null) return;
    document.body.dispatchEvent(
      new CustomEvent("yuzu:select-process", { detail: { pid } }),
    );
  });

  return _cy;
}

function updateStaleBanner(topo) {
  let banner = document.getElementById("stale-banner");
  if (!banner) {
    banner = document.createElement("div");
    banner.id = "stale-banner";
    banner.className = "vh-stale";
    banner.style.display = "none";
    const root = document.getElementById("viz-host-root");
    if (root && root.firstChild) root.insertBefore(banner, root.firstChild);
  }
  if (topo.stale) {
    banner.textContent = "stale snapshot — agent has not reported recently";
    banner.style.display = "block";
  } else {
    banner.style.display = "none";
  }
}

function showError(err) {
  const container = document.getElementById("ipc-graph");
  if (!container) return;
  const msg =
    err && err.status === 401
      ? "Sign in to view this host."
      : err && err.status === 403
        ? "You don't have permission to view this host."
        : err && err.status === 503
          ? "The viz endpoint is disabled by the operator."
          : `Could not load topology: ${err && err.message ? err.message : err}`;
  const note = document.createElement("div");
  note.className = "vh-error";
  note.textContent = msg;
  container.replaceChildren(note);
}

async function refresh() {
  const agentId = getAgentId();
  if (!agentId) return;
  try {
    const topo = await loadTopology(agentId);
    updateStaleBanner(topo);
    renderGraph(topo.machine);
  } catch (err) {
    console.error("yuzu-viz-host:", err);
    showError(err);
  }
}

function wireRefreshButton() {
  const btn = document.getElementById("refresh-btn");
  if (btn) btn.addEventListener("click", refresh);
}

async function mount() {
  wireRefreshButton();
  await refresh();
}

document.addEventListener("DOMContentLoaded", mount);
