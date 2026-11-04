# Threat Graph Roadmap

**Status:** Internal planning draft, 2026-05-11. Extends the existing 11-PR
visualization ladder (`docs/plans/feat-viz-engine-plan-2026-05-09.md`) with
the *Threat Graph* product vision discussed end-of-day 2026-05-10.

**Distribution:** Internal planning only — `docs/plans/` is the staging area
for product direction not yet ready for external publication. The
"Anti-Mythos" framing below names a specific LLM-driven offensive system
("Mythos") as the antagonist; before this doc moves into customer-facing
roadmap materials, the framing should be generalised to "LLM-driven
offensive enumeration tooling" without naming a specific competitor's
product, per standard vendor-roadmap hygiene.

## Anti-Mythos framing

Top-quality LLM-driven offensive systems (e.g. Anthropic's Mythos) can rapidly
enumerate and exploit a host's IPC + network surfaces by probing in well-defined
ways. The defender's response is the *same enumeration, visualised*. Yuzu's
Threat Graph is the defender's mirror of that capability: same primitives, same
inputs, used to harden instead of penetrate.

Concretely the visualisation needs to answer four operator questions in one
glance:

1. **What talks to what** — inside each host (IPC graph) and across the fleet
   (network graph).
2. **What is each thing's posture** — vulnerable / hardened / unknown,
   synthesised across vuln scan + AV + disk encryption + signed-binary + firewall
   exposure.
3. **Where should I insert controls** — WAF, IPS, API gateway, VxLAN
   separation, firewall, network-parser hardening — derived from the graph
   shape + posture.
4. **What can I do about it right now** — countermeasure actions delivered by
   the existing plugin surface, called directly from the canvas.

## Three composable layers

### Layer 1 — Per-host IPC graph (intra-cube)

Today's PR 8 catches TCP loopback only. The Threat Graph requires *all* same-host
IPC channels. The agent must collect, and the renderer must distinguish:

| Channel | Linux | macOS | Windows |
|---|---|---|---|
| TCP/UDP loopback (already shipped) | `/proc/net/tcp{,6}` | `lsof -i` / `netstat` | `GetExtendedTcpTable` |
| Unix domain sockets (path-bound) | `/proc/net/unix` | `lsof -U` | n/a (no Unix sockets pre-Win10 1803; AF_UNIX since) |
| Abstract-namespace Unix sockets | `@`-prefix in `/proc/net/unix` | n/a | n/a |
| Named pipes / FIFOs | `find / -type p` (FIFO) | same | `\\.\pipe\*` |
| Shared memory | SysV `ipcs -m` + POSIX `/dev/shm` | POSIX `/dev/shm` | shared sections |
| Message queues | SysV `ipcs -q` + POSIX `/dev/mqueue` | POSIX | mailslots |
| D-Bus (system + session) | dbus-monitor / `/var/run/dbus/` | n/a | n/a |
| eBPF maps (root) | `bpftool map list` | n/a | n/a |
| Windows ALPC ports | n/a | n/a | NtAlpcQueryInformation |

Wire model extensions:

- `EdgeKind` enum on `ConnectionEdge`: `TcpLoopback` (today), `UnixSocket`,
  `NamedPipe`, `SharedMemory`, `DBus`, `ALPC`, `EbpfMap`. Renders differently
  per kind (line style + colour) so an operator can read channel-class at
  a glance.
- `socket_path` field for filesystem-backed channels (Unix socket path, named
  pipe name) — replaces / complements `src_addr`+`src_port` for non-TCP
  channels.
- `world_accessible` boolean per edge — Unix socket with `0666`, named pipe
  with `Everyone`-ACE, abstract socket (no FS ACL at all), `/dev/shm` file
  world-rw. Highest-leverage rendering cue: red glow on edges whose endpoints
  any process can join.

### Layer 2 — Fleet network graph (inter-cube)

PR 9 today covers TCP cross-host. Threat Graph additions:

- **TLS-termination annotation** on edges — for TCP edges whose source process
  serves TLS, surface cert subject / issuer / expiry. (Operator question:
  "which edge is a network parser?")
- **Cross-host Unix sockets via shared mounts** — `/var/run/docker.sock`
  bind-mounted into a container is *technically* an IPC channel that crosses
  a containment boundary; should render as a special edge kind
  (`MountedSocket`) to flag the boundary crossing.
- **Inter-container traffic classification** — three Docker containers on the
  same host with a shared bridge network already produce inter-container TCP.
  Today this classifies `External` (the IPs aren't loopback and the other
  containers don't have `local_ips` in the fleet). Need a new `Containerised`
  scope when source + dest IPs both live in private RFC1918 ranges that the
  server recognises as Docker / Kubernetes / Podman ranges.

### Layer 3 — Per-process posture overlay

Each `ProcessNode` gains a `posture` envelope:

```json
{
  "vuln":       { "worst_severity": "high", "cve_count": 7 },
  "av":         { "scanned": true, "clean": true, "engine": "defender" },
  "signed":     { "verified": true, "issuer": "Microsoft Code Signing PCA" },
  "exposed":    { "listening_external_ports": [443, 22] },
  "binary":     { "hash_sha256": "ab…", "virustotal_score": null }
}
```

The renderer derives a composite glyph from `posture` — a single character
overlay on each process dot:

| Glyph | Means | Triggered by |
|---|---|---|
| (none) | hardened | all checks present, no findings |
| `?` | unknown | any check missing |
| `!` | warning | medium vuln OR unsigned binary OR unexpected listener |
| `⚠` | high risk | high/critical vuln OR AV detection OR known-bad VT hit |

Glyph is rendered as a `Sprite` child of the process Sphere — uses the
existing Sprite infrastructure from PR 6 (hostname labels) so no new
disposal/raycast invariants.

## Visualisation model — mode toggle on `/viz/fleet`

A single page with two render modes, persisted in `localStorage.yuzuVizMode`:

| Mode | Layout | Edges | Posture overlay |
|---|---|---|---|
| **Fleet** (default, today) | Hash-determined grid | TCP only | None |
| **Threat** | Same grid, posture glyphs visible | All IPC kinds (TCP + Unix + pipes + shm), `world_accessible` red glow, mounted-socket boundary cubes | Yes |

Mode toggle is a single-key shortcut (`T`) plus a UI control. Camera state is
shared across modes — toggle does not reset the view.

**Why not separate routes:** the data fetch, camera, scene graph, and disposal
contracts are identical. A mode toggle is one more boolean in the renderer
state machine; a separate route is a parallel codebase. The graph *layout*
might eventually diverge (force-directed clustering in Threat mode), but
that's a render-time decision, not a route-level one.

## Recommendation engine (operator-suggested controls)

The "where to put a WAF / firewall / VxLAN boundary" annotations are
**Yuzu-suggested via an agentic AI** — not operator-drawn freehand — and the
sprint cadence is per-customer. Architecturally that means:

- New server-side store `recommendations.db` with schema:
  ```sql
  CREATE TABLE recommendations (
    id TEXT PRIMARY KEY,                       -- uuid
    customer_id TEXT NOT NULL,                 -- multi-tenant key
    generated_at INTEGER NOT NULL,             -- epoch seconds
    generated_by TEXT NOT NULL,                -- "agent:mythos-defender-v1"
                                               -- or "operator:<principal>"
    kind TEXT NOT NULL,                        -- "insert_waf" / "vxlan_separate"
                                               -- / "firewall_rule" / "harden_parser"
                                               -- / "kill_world_socket"
    target_node_ids TEXT,                      -- JSON array of agent_ids
    target_edge_keys TEXT,                     -- JSON array of edge identifiers
    rationale TEXT,                            -- human-readable text
    status TEXT NOT NULL DEFAULT 'open',       -- open / accepted / dismissed / applied
    operator_note TEXT,
    yaml_source TEXT                           -- verbatim source, for audit
  );
  ```
- Recommendations produced by an **external agentic AI worker** posting via
  REST + MCP using a service-scoped API token. Same auth path as any
  operator; no special channel.
- Threat-mode overlay reads recommendations and renders them as ghost
  overlays — semi-transparent rectangles around target nodes, ghosted labels
  on edges, `rationale` text on click.
- Operators *accept / dismiss / apply* via the existing approval workflow
  (`workflows` store). "Apply" calls the relevant plugin action (firewall
  rule add, etc.).

This decouples the *visualisation* from the *recommender*. Yuzu doesn't need
to know how recommendations were generated — only how to render and
action them.

## Action surface — call existing plugins

Clicking a process or edge opens a side panel with action buttons. Each
button calls an existing plugin action via the REST `/api/v1/dispatch`
surface; no `viz.actions` API is introduced.

| User action | Plugin called | Plugin source |
|---|---|---|
| Check binary hash against VirusTotal | `processes.hash` + new server-side VT lookup | existing + new |
| Re-scan for vulnerabilities | `vuln_scan.scan` | existing |
| View firewall rules | `firewall.list` | existing |
| Add firewall rule (block this edge) | `firewall.add_rule` | existing on Windows; needs cross-platform |
| Map sockets back to processes | `sockwho.list` | existing |
| Run an ad-hoc bash script | `script_exec.bash` | existing |
| Check AV / disk encryption status | `antivirus.status` / `bitlocker.status` | existing |
| Kill process | `processes.kill` | existing |
| Quarantine binary | `quarantine.add` | existing |

## Plugin gap matrix

Existing plugins are listed in `agents/plugins/`. Items below are the gaps
between *what plugins exist* and *what the Threat Graph requires*. Each row
either needs a new plugin or a new action on an existing plugin.

### High priority (Layer 1 IPC enumeration — required for Threat mode demo)

| Need | Plugin | Status |
|---|---|---|
| Unix domain socket enumeration | **new** `unix_sockets` | not present; needs Linux + macOS support (path + abstract on Linux only) |
| Named pipe enumeration (Windows) | **new** `named_pipes` | not present; Windows-only initially, Linux FIFO inventory as a follow-up |
| Shared memory enumeration | **new** `shared_memory` | not present; SysV (`ipcs -m`) + POSIX (`/dev/shm` listing + `/dev/mqueue`) on Linux+macOS; shared sections on Windows |
| Process binary SHA-256 hashing | extend existing `processes` | no `sha256` references found in `processes/src/`; needs cross-platform hash collection wired into the existing process enumeration |

### High priority (Layer 3 posture)

| Need | Plugin | Status |
|---|---|---|
| AV status — macOS XProtect + third-party (SentinelOne, Crowdstrike) | extend existing `antivirus` | plugin has macOS + Linux + Windows skeletons today; verify what each branch actually reports |
| AV status — Linux ClamAV / SentinelOne / Crowdstrike | extend existing `antivirus` | same |
| Disk encryption — macOS FileVault | extend existing `bitlocker` (rename `disk_encryption`?) | plugin has macOS + Linux + Windows skeletons; verify FileVault path |
| Disk encryption — Linux LUKS / eCryptfs | extend existing `bitlocker` | same |
| Firewall — macOS `pfctl` enumeration | extend existing `firewall` | platform branches exist; verify pfctl coverage |
| Firewall — Linux `nftables` / `iptables` enumeration | extend existing `firewall` | same |
| Signed-binary verification — Authenticode | **new** `signed_binaries` | not present; Windows WinVerifyTrust |
| Signed-binary verification — codesign | **new** `signed_binaries` | macOS `csops` / `SecCodeCheckValidity` |
| Signed-binary verification — IMA/EVM | **new** `signed_binaries` | Linux kernel IMA hashes via `getxattr security.ima` |
| VirusTotal hash lookup | **server-side** integration | not present; called from server using `processes.hash` output, cached, rate-limited |

### Medium priority (Layer 2 network enrichment)

| Need | Plugin | Status |
|---|---|---|
| TLS-termination annotation per listening socket | extend existing `certificates` + new join in `echo` | `certificates` plugin exists; needs `which-pid-serves-which-cert` join |
| Container runtime awareness — detect docker / k8s / podman | extend existing `os_info` or new `container_runtime` | not present; `os_info` returns OS-level facts only |
| RFC1918 + RFC4193 + Docker default range classification | **server-side** in `fleet_topology_store` | new logic; no plugin |

### Low priority (defence in depth, attacker-class IPC)

| Need | Plugin | Status |
|---|---|---|
| D-Bus enumeration (Linux server installs that ship dbus) | **new** `dbus` | not present; `busctl list` |
| eBPF map + program enumeration (Linux, root-only) | **new** `ebpf_inventory` | not present; `bpftool map list` |
| Windows ALPC port enumeration | **new** `alpc_ports` | not present; NtAlpcQueryInformation |
| SysV semaphore / message queue enumeration | extend `shared_memory` | n/a until shared_memory ships |

## PR ladder extension (proposed PRs 12–22)

Stacks on top of the existing 11-PR ladder. Each demo should be operator-eyeballable in viz-UAT before merge (per `feedback_visual_features_need_visual_proof`).

| # | Title | Demo |
|---|---|---|
| 12 | Unix-socket IPC edges | New `unix_sockets` plugin; agent emits Unix sockets into `echo.fleet_snapshot`; renderer draws a green-tinted line for Unix-socket edges in Threat mode |
| 13 | Threat-mode toggle | `localStorage.yuzuVizMode`, `T`-key shortcut, mode-state in URL hash, ghost-overlay rendering scaffold (empty) |
| 14 | Process posture overlay | Composite glyph per process; vuln + signed + AV synthesis; recommended Sprite-glyph rendering |
| 15 | Process binary hashing | Extend `processes` plugin to emit SHA-256; server-side VirusTotal cache + lookup; posture envelope carries hash + VT score |
| 16 | Named-pipe IPC edges | New `named_pipes` plugin (Windows-first); render distinct edge kind |
| 17 | Shared-memory IPC edges | New `shared_memory` plugin (SysV + POSIX); render distinct edge kind |
| 18 | Signed-binary verification | New `signed_binaries` plugin (cross-platform); feeds posture envelope |
| 19 | Recommendation store | `recommendations.db` + REST + MCP tools; threat-mode renders empty-ghosts; accept / dismiss / apply workflows |
| 20 | Action surface | Side-panel on node click; calls existing plugin endpoints; "apply recommendation" wires to plugin actions |
| 21 | Cross-platform parity sweep | `antivirus`, `bitlocker` (rename `disk_encryption`?), `firewall` audit for macOS + Linux coverage; close gaps |
| 22 | Container-runtime awareness | Detect Docker/k8s/podman; classify inter-container traffic as `Containerised` scope; mounted-socket boundary edges |

Existing PRs 8–11 land first as planned; threat-mode-specific work begins
after PR 11 polish ships.

## Open questions

1. **Mode-toggle persistence** — `localStorage` or URL hash? URL hash is more
   shareable ("send me a link to the threat view"), `localStorage` is more
   per-operator. **Recommendation: URL hash primary, `localStorage`
   fallback.**
2. **Cross-tenant recommendation isolation** — the `customer_id` column in
   `recommendations.db` implies multi-tenant. Yuzu hasn't formalised multi-tenancy
   in stores yet (`audit.db`, `policies.db` etc. are single-tenant). **Defer
   until Workstream B Identity matures.**
3. **Disk-encryption plugin rename** — `bitlocker` is Windows-specific in name,
   pan-platform in implementation. Renaming breaks API token scope strings and
   audit history. **Recommendation: keep the name, add `disk_encryption` as an
   alias action name, audit-log emits the new name.**
4. **VirusTotal API key handling** — server-side cache means the API key lives
   on the server, not the agent. Goes into Settings → External Integrations.
   **Free tier rate limit is 4 req/min, so the lookup is async-batched.**
5. **eBPF / Windows ALPC enumeration require root / SYSTEM** — Yuzu's privilege
   model already supports this via the `_yuzu` virtual-service account
   (`docs/agent-privilege-model.md`). New privileged plugins must follow the
   procedure there.

## Cross-references

- Existing 11-PR ladder: `docs/plans/feat-viz-engine-plan-2026-05-09.md`
- Fleet-viz invariants (PR 7 + PR 8): `docs/fleet-viz-invariants.md`
- Privilege model for new privileged plugins: `docs/agent-privilege-model.md`
- Enterprise readiness workstreams: `docs/enterprise-readiness-soc2-first-customer.md`
- Capability map (what we claim to do): `docs/capability-map.md`
