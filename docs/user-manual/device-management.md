# Device Management

This guide covers the full device lifecycle in Yuzu: enrolling agents, monitoring connectivity, managing device identity, and performing over-the-air agent updates.

**Prerequisites:** A running Yuzu server. All `curl` examples assume an active admin session cookie in `$COOKIE` -- replace with your session token. The server listens on `http://localhost:8080` by default.

---

## Agent Enrollment

Yuzu uses a three-tier enrollment model. Every agent must register with the server before it can receive instructions. The tier determines how much manual intervention is required.

### Tier 1: Manual Approval

The default enrollment mode. When an agent connects without a token, it enters a **pending queue**. An administrator must explicitly approve or deny the agent before it can participate in the fleet.

**Agent side:**

```bash
yuzu-agent --server server.example.com:50051
```

The agent will attempt registration, receive a "pending" status, and retry periodically until approved.

**Server side (dashboard):** Navigate to **Settings > Pending Agents** to see the queue. Each entry shows the agent's hostname, OS, architecture, and the time it first connected. Click **Approve** or **Deny**.

**Server side (API):**

There is no dedicated JSON API endpoint to list pending agents. Use the HTMX fragment to retrieve the rendered HTML list:

```bash
# List pending agents (returns HTML fragment)
curl -s http://localhost:8080/fragments/settings/pending -b "$COOKIE"
```

```bash
# Approve a pending agent
curl -s -X POST http://localhost:8080/api/settings/pending-agents/agent-001/approve \
  -b "$COOKIE"
```

```bash
# Deny a pending agent
curl -s -X POST http://localhost:8080/api/settings/pending-agents/agent-001/deny \
  -b "$COOKIE"
```

```bash
# Remove a pending agent from the queue entirely
curl -s -X DELETE http://localhost:8080/api/settings/pending-agents/agent-001 \
  -b "$COOKIE"
```

### Tier 2: Pre-Shared Enrollment Tokens

For automated deployments, administrators generate **enrollment tokens** -- time-limited and use-limited secrets that agents present at registration for immediate enrollment without manual approval.

**Generate a token (HTMX -- returns HTML fragment):**

This endpoint is designed for the HTMX dashboard and accepts form-encoded parameters. It returns an HTML fragment containing the token list with the new token's raw value revealed once.

```bash
curl -s -X POST http://localhost:8080/api/settings/enrollment-tokens \
  -b "$COOKIE" \
  -d "label=datacenter-rollout-q1&max_uses=100&ttl_hours=72"
```

The response is an HTML fragment (the updated tokens table). The raw token value is displayed once in the fragment and cannot be retrieved again.

**Generate tokens in batch (JSON API for scripting):**

This endpoint accepts JSON and returns a JSON response, making it suitable for automation and scripting.

```bash
curl -s -X POST http://localhost:8080/api/settings/enrollment-tokens/batch \
  -b "$COOKIE" \
  -H "Content-Type: application/json" \
  -d '{
    "label": "site-deploy",
    "count": 10,
    "max_uses": 50,
    "ttl_hours": 24
  }'
```

Response:

```json
{
  "count": 10,
  "tokens": ["yuzu_enroll_xxx...", "yuzu_enroll_yyy...", "..."]
}
```

**Agent side:**

```bash
yuzu-agent --server server.example.com:50051 \
           --enrollment-token "yuzu_enroll_xxxxxxxxxxxxxxxxxxxxxxxx"
```

The agent includes the token in its `RegisterRequest`. If the token is valid and has remaining uses, enrollment succeeds immediately.

**List active tokens (returns HTML fragment):**

There is no dedicated JSON API endpoint to list enrollment tokens. Use the HTMX fragment:

```bash
curl -s http://localhost:8080/fragments/settings/tokens -b "$COOKIE"
```

**Revoke a token:**

```bash
curl -s -X DELETE http://localhost:8080/api/settings/enrollment-tokens/tok_a1b2c3d4 \
  -b "$COOKIE"
```

Tokens are persisted in `enrollment-tokens.cfg` alongside the server configuration file. They survive server restarts.

### Tier 3: Platform Trust (Planned)

Reserved for future implementation. Proto fields exist for `machine_certificate`, `attestation_signature`, and `attestation_provider` to support Windows certificate store attestation and cloud identity verification. Agents on domain-joined machines or cloud VMs will be able to prove their identity cryptographically without any shared secret.

---

## Auto-Approval Policies

Administrators can configure rules that automatically approve agents matching specific criteria, reducing manual toil for large deployments.

**View current auto-approval policies (dashboard):** Navigate to **Settings > Auto-Approve**.

**Add an auto-approval rule:**

The auto-approve endpoints use form-encoded parameters (designed for the HTMX dashboard) and return HTML fragments.

```bash
curl -s -X POST http://localhost:8080/api/settings/auto-approve \
  -b "$COOKIE" \
  -d "type=hostname_glob&value=web-*.example.com&label=Production+web+servers"
```

This rule automatically approves any agent whose hostname matches the glob pattern `web-*.example.com`.

Supported rule types: `hostname_glob`, `trusted_ca`, `ip_subnet`, `cloud_provider`.

**Set the auto-approve match mode:**

```bash
curl -s -X POST http://localhost:8080/api/settings/auto-approve/mode \
  -b "$COOKIE" \
  -d "mode=any"
```

Supported modes:

| Mode | Behavior |
|---|---|
| `any` | First matching enabled rule auto-approves the agent (default) |
| `all` | All enabled rules must match for auto-approval |

Note: Auto-approval only applies when rules exist and are enabled. When no rules are configured, all agents enter the pending queue regardless of mode. To disable auto-approval entirely, remove or disable all rules.

**Toggle a rule on/off:**

```bash
curl -s -X POST http://localhost:8080/api/settings/auto-approve/0/toggle \
  -b "$COOKIE"
```

**Delete a rule:**

```bash
curl -s -X DELETE http://localhost:8080/api/settings/auto-approve/0 \
  -b "$COOKIE"
```

**View the auto-approve settings fragment (HTMX):**

```bash
curl -s http://localhost:8080/fragments/settings/auto-approve -b "$COOKIE"
```

---

## Device Identity

Every enrolled agent reports identity attributes during registration and heartbeat:

| Field | Description | Example |
|---|---|---|
| `agent_id` | Unique identifier (UUID) | `a3f1c9e2-7b4d-4e8a-9f12-3c5d6e7f8a9b` |
| `hostname` | Machine hostname | `web-prod-01` |
| `os` | Operating system | `windows`, `linux`, `darwin` |
| `arch` | CPU architecture | `x86_64`, `aarch64` |
| `os_version` | OS version string | `Windows 11 Pro 10.0.26200` |
| `agent_version` | Running agent binary version | `0.9.3` |

These fields are used by the [Scope Engine](scope-engine.md) for device targeting and by [Management Groups](management-groups.md) for access scoping.

---

## Viewing Connected Agents

### Dashboard

**`/devices` now 302-redirects to `/hardware`** (the Hardware CI list — round-3, see `docs/user-manual/inventory.md`) — the old standalone Devices page no longer renders directly; a bookmarked `/devices` link still works, since browsers follow the redirect transparently. Hardware's own list requires **`Inventory:Read`** rather than the old page's `Infrastructure:Read`; every seeded built-in role holding one also holds the other, so no default-role regression, but a custom role granted `Infrastructure:Read` alone loses list access via the old URL. Each row shows hostname, OS, architecture, online status, and per-device DEX score, plus (new) agent version, claimed IP, and tags. Filter by OS or search by name; click any row to open that device's Hardware CI record. **DEX scoring is per-render, never fleet-wide:** opening a record scores that one device, and the list scores only the rows actually rendered after filtering — no page load may trigger a whole-fleet scoring pass.

> The list is sourced from the live connection registry, so it shows connected devices only (there is no offline/status filter). Enrolled-but-offline devices and real last-seen times arrive with the persistent device-inventory slice.

#### Device page (`/device?id=`, redirects to `/hardware/ci?id=`)

The per-device page is the shared entity view reached from any dashboard, organised into lens tabs — the same lens-tab machinery renders both the legacy device page's tabs and the Hardware CI record's Overview/DEX/Guardian tabs:

Every per-device route is scoped to the device's management group (a global grant **or** a role assigned on the device's group / an ancestor): opening a device outside your scope returns *forbidden*, never its data.

| Tab | Contents | Gate |
|---|---|---|
| **Device info** | Identity (agent ID, OS, arch, version), tags, group membership. | `Infrastructure:Read`, scoped to the device |
| **DEX** | Per-device DEX score + a summary of recent signal observations, with a link to the full DEX drill-down (which carries an *Application performance over time* panel — retained daily per-app-version CPU/memory from the central store, no live query, no `Execute`). | `GuaranteedState:Read`, scoped to the device. Signal-history view audited as `dex.device.view`; the app-perf panel audited as `dex.device.app_perf.view` (separate verb) |
| **Guardian** | Per-guard compliance state for the device (guard, state, last evaluated). | `GuaranteedState:Read`, scoped to the device (audited as `guardian.device.view`) |

A device with zero reported guards renders "No guards evaluated" even if the fleet-wide rule catalogue read is itself degraded — the per-device read no longer depends on the catalogue's own health for a zero-row device (a small, disclosed rendering delta from the ADR-0031 WS-A4 seam rewire).

#### Get live info

The **Get live info** button (shown when the device is online) dispatches read-only instructions to the agent **now** — not from cached heartbeat data — and renders a **TAR-styled live snapshot**: a KPI strip (uptime, process/service/connection/user counts) over a grid of **collapsible, uniformly-sized cards**. Cards are collapsed by default; an **Expand all / Collapse all** control toggles them together, and each card has a **pop-out (⤢)** for a larger view. Each card is one live query against the OS, dispatched through the same proven chokepoint as before.

Each card has its own audit verb so a usage-class read (what a person is running) stays separately countable from a machine-health read — the works-council posture (see [Audit log](audit-log.md)):

| Card | Source | Audit verb | OS |
|---|---|---|---|
| **Uptime** (KPI) | `os_info/uptime` | `device.live.uptime` | all |
| **Processes** — a parent→child **tree** (TAR `/tar` viewer style), each node showing the **SHA-256** of its on-disk image and its **live network connections** (joined by PID, public endpoints highlighted); suspicious `parent→child` spawns are flagged. Searchable by name / PID / hash / endpoint. | `processes/list_tree` + `network_diag/connections` | `device.live.process_tree` | tree all; hash all; connection join Windows |
| **Services** — run state | `services/list` | `device.live.services` | all |
| **Adapters & IP** | `network_config/ip_addresses` | `device.live.netconfig` | all |
| **ARP / neighbours** | `network_config/arp` | `device.live.arp` | all (constrained on Linux/macOS) |
| **DNS cache** | `network_config/dns_cache` | `device.live.dns_cache` | Windows, Linux |
| **Listening ports** | `network_diag/listening` | `device.live.listening` | all |
| **Active connections** | `network_diag/connections` | `device.live.connections` | all |
| **Logged-in users** | `users/logged_on` | `device.live.users` | all |
| **Capture sources** — read-only view of which TAR warehouse sources are capturing locally (toggle state + `$`-table + live row count); configure on the TAR page | `tar/status` | `device.live.capture_sources` | all |
| **Disk space** — free/used for the root volume with a colour-coded usage bar (>=90% used or <5 GiB free = red) | `disk_space/free` | `device.live.disk` | all |

Every card requires **`Execution:Execute`** in addition to `GuaranteedState:Read`, each scoped to the device's management group; without Execute the card shows an explanatory note rather than failing silently, and a device outside your scope cannot be live-queried at all. The process tree, connections, logged-in-user, and **DNS-cache** reads are **usage-class behavioral telemetry** (a person's running software, active connections, sessions, and resolved names) and are individually audit-logged; the remaining kinds (uptime, services, adapters/IP, listening ports, ARP, capture sources, disk space) are machine-health reads.

The **ARP** card now works on all three platforms, with per-OS limits: Windows reports IPv4 ARP and IPv6 neighbours including incomplete entries; Linux reports IPv4 ARP only (IPv6 neighbours live in a separate kernel table, and incomplete or non-Ethernet entries are skipped); macOS reports address and MAC only, with the interface name and static/dynamic type shown as `-` because the routing-socket dump does not carry them. The **DNS-cache** card works on Windows and Linux (`resolvectl`, falling back to `systemd-resolve --statistics`) but **not on macOS**, which exposes no resolver-cache contents; that card renders an honest "not available on this OS" note there. On a host with many distinct large executables the process card can take up to ~30 seconds (it hashes each on-disk image; the SDK `sha256_file` helper is `YUZU_EXPORT`, capped at 512 MiB per file, and deduplicates repeated images); a "Waiting for the device to respond…" message followed by a timeout with a *Reload to retry* prompt is normal, not a failure.

**Result-poll scoping invariant (#1634).** The live-snapshot result poll is scoped **at the store seam**: the route's `ResponsesFn` threads the device's `agent_id` into `ResponseQuery{.agent_id}`, so the response store only ever returns that device's rows. The route-level post-filter is retained purely as defense-in-depth — a future refactor that dropped it must still be unable to leak cross-agent rows. Any new poll surface must scope at the query, never rely on post-filtering alone.

The **Processes (tree)** and **ARP** cards depend on the `processes/list_tree` and `network_config/arp` agent actions, which ship with agents built from this release onward. An older agent that predates them returns an `unknown action` response, which currently renders as an **empty card** — upgrade the agent to populate those cards. (Tracked follow-up: have the agent emit an explicit "unsupported on this agent version" note instead of an empty card.)

The machine-readable equivalents (for agentic workers and automation) are `GET /api/v1/dex/devices/{id}` (the per-device DEX read model), `GET /api/v1/dex/devices/{id}/app-perf` (the REST twin of the *Application performance over time* panel — the retained per-`(app, version, day)` history, same `dex.device.app_perf.view` audit, fail-closed), and `POST /api/v1/dex/devices/{id}/live?kind=uptime|processes` (the live dispatch — POST because it has a side effect; the dashboard's additional cards — process tree, services, users, network, capture sources — are dashboard-only pending the REST/JSON A1 backfill **#1649**). They enforce the same scoped permissions and emit the same audit verbs as these panels. **They differ in failure mode, though:** the REST endpoints are **audit-fail-closed** — if the audit row cannot persist they return `503` + `Sec-Audit-Failed: true` and serve no data (or, for `/live`, dispatch nothing), whereas these dashboard panels set `Sec-Audit-Failed: true` on the response but continue to render (a transient audit hiccup must not blank the dashboard). Alert on `Sec-Audit-Failed: true` from **either** surface as a SOC 2 CC7.2 evidence-gap signal. See [REST API — DEX](rest-api.md).

##### Physical

The Hardware CI record's own **Live** lens (`/hardware` → device → **Live** tab) hx-gets the same `/fragments/device/live/*` fragments as the device page above — same dispatch-and-poll machinery, same cards — and adds ten physical-hardware cards, each wiring an already-shipped agent plugin action into the shared card renderer:

| Card | Source | Audit verb | OS |
|---|---|---|---|
| **Disks** — per-disk model, capacity, media type, and interface | `hardware/disks` | `device.live.hw_disks` | all |
| **Memory** — installed memory modules: slot, capacity, type, speed | `hardware/memory` | `device.live.hw_memory` | all |
| **Processors** — installed CPU(s): model, cores, threads, clock speed | `hardware/processors` | `device.live.hw_processors` | all |
| **Drivers** — installed device drivers: name, version, date, provider, class | `hardware/drivers` | `device.live.hw_drivers` | Windows, Linux |
| **Battery** — presence, charge state, percent, time-to-empty, cycle count, health | `power_health/battery` | `device.live.battery` | all |
| **Thermal** — thermal zone status and temperature | `power_health/thermal` | `device.live.thermal` | all |
| **Disk health (SMART)** — per-disk SMART health, percent used, spare percent | `disk_actions/smart` | `device.live.smart` | Windows, macOS |
| **Volumes** — mounted volumes: mount points, backing device, filesystem, size | `disk_actions/volumes` | `device.live.volumes` | Windows, macOS |
| **Network adapters** — adapter name, MAC, link speed, status | `network_config/adapters` | `device.live.adapters` | all |
| **Wi-Fi** — current association: SSID, signal, security, BSSID/channel | `wifi/connected` | `device.live.wifi` | all |

All ten are machine-health reads (hardware attributes, not per-user behavioral data) and require **`Execution:Execute`** plus `GuaranteedState:Read`, scoped to the device's management group — same gating as every other live card. **Drivers** is Windows- and Linux-only: the agent enumerates no equivalent driver registry on macOS. **Disk health (SMART)** and **Volumes** are Windows- and macOS-only: the `disk_actions` plugin's Linux leg does not back either action. The remaining six (Disks, Memory, Processors, Battery, Thermal, Network adapters, Wi-Fi) report on all three platforms.

**Deferred: disk-encryption status.** BitLocker/FileVault/LUKS state (`bitlocker/state`) was investigated for this round and dropped, not shipped. Its three platform legs return incompatible wire shapes — Windows a 5-field volume/conversion/percent/method/protection record, Linux a 3-field volume/crypto-type/active-or-inactive record with entirely different field semantics at the same positions, and macOS a bare 1-field enabled/disabled flag — so one generic column table would mislabel the Linux and macOS data. It needs a bespoke per-OS renderer rather than the shared card table; filed as a follow-up.

### REST API

**List all agents (legacy endpoint):**

This endpoint does not require authentication. It returns only currently connected agents (those with an active gRPC session).

```bash
curl -s http://localhost:8080/api/agents
```

Response:

```json
[
  {
    "agent_id": "a3f1c9e2-7b4d-4e8a-9f12-3c5d6e7f8a9b",
    "hostname": "web-prod-01",
    "os": "windows",
    "arch": "x86_64",
    "agent_version": "0.9.3"
  }
]
```

Note: This legacy endpoint does not include `status` or `last_heartbeat` fields. It only lists agents with active gRPC streams (implicitly online).

---

## Agent Heartbeat and Session Keepalive

After registration, agents maintain a persistent gRPC bidirectional stream with the server. The heartbeat serves three purposes:

1. **Liveness** -- the server marks agents as offline if no heartbeat is received within the configured timeout.
2. **Metadata refresh** -- agents report updated OS version, IP address, and plugin inventory on each heartbeat.
3. **Command delivery** -- the server uses the open stream to push `CommandRequest` messages to the agent without polling.

Heartbeat interval is configured agent-side (default: 30 seconds). The server's offline threshold is typically 3x the heartbeat interval.

---

## Agent CLI Flags

The full set of agent command-line flags:

| Flag | Description | Default |
|---|---|---|
| `--server` | Server address (`host:port`) | `localhost:50051` |
| `--enrollment-token` | Pre-shared token for Tier 2 enrollment | (none) |
| `--ca-cert` | Path to CA certificate PEM file (verifies the server) | (auto-discover) |
| `--client-cert` | Path to client certificate PEM file (mTLS) | (auto-discover) |
| `--client-key` | Path to client private key PEM file (mTLS) | (auto-discover) |
| `--cert-store` | Windows certificate store name (e.g. `MY`) | (none) |
| `--cert-subject` | Subject CN match for cert store lookup | (none) |
| `--cert-thumbprint` | SHA-1 thumbprint for cert store lookup (hex) | (none) |
| `--cert-dir` | Directory for the auto-provisioned per-agent mTLS credential (env `YUZU_CERT_DIR`) | `<data-dir>/certs` |
| `--no-auto-provision-cert` | Disable PKI auto-provisioning (do not request a per-agent client certificate at enrollment) | (enabled) |
| `--plugin-dir` | Directory containing plugin shared libraries | `./plugins` |
| `--log-level` | Logging verbosity (`trace`, `debug`, `info`, `warn`, `error`; lowercase and case sensitive, and an unrecognised value, including `WARN`, is treated as `off`; `--verbose` forces `trace` whatever this says). The `agent_actions` plugin's `set_log_level` action (needs `Infrastructure:Write` and, through the REST command dispatch, `Execution:Execute`) changes it at runtime but does not persist it, so it reverts when the agent restarts (env `YUZU_LOG_LEVEL`) | `info` |
| `--log-file` | Path for an on-disk log file, written in addition to the console. A Windows service agent has no console, so it defaults to `yuzu-agent.log` under its data directory (env `YUZU_LOG_FILE`) | (none) |
| `--log-max-size` | Size in bytes at which the agent's log file rotates. Applies whenever the agent writes a log file (`--log-file`, or the Windows-service default above), otherwise ignored (env `YUZU_LOG_MAX_SIZE`) | `52428800` (50 MB) |
| `--log-max-files` | Number of rotated log files kept. Applies whenever the agent writes a log file, otherwise ignored (env `YUZU_LOG_MAX_FILES`) | `5` |

### Per-agent mTLS auto-provisioning (PKI)

When the server runs with its built-in CA and the agent has no operator-supplied
client certificate (`--client-cert`/`--cert-store`) but does have the server CA
(`--ca-cert`), the agent automatically obtains its own client certificate at
enrollment: it generates an EC P-256 keypair + CSR, the server signs a per-agent
leaf (`CN=<agent-id>`) and returns it, and the agent persists the leaf + key
(mode `0600`) + issuing chain under `--cert-dir`, then reconnects with mutual TLS.
The leaf auto-renews once two-thirds of its lifetime has elapsed (checked at agent
start). Pass `--no-auto-provision-cert` to opt out (e.g. when you supply your own
client certificate). See `docs/auth-architecture.md` "Per-agent mTLS".

This applies equally to agents enrolling **through the Erlang gateway** — the
gateway relays the `RegisterResponse` verbatim **and signs the forwarded CSR**
(`ProxyRegister`, PKI PR5d), so the per-agent leaf reaches the agent on both the
direct and gateway paths.

**Files written under `--cert-dir`** (default `<data-dir>/certs`):

| File | Contents | Mode |
|---|---|---|
| `agent-client.key` | The agent's EC P-256 private key — never leaves the host, never sent to the server | `0600` |
| `agent-client.pem` | The per-agent client leaf the server issued (`CN=<agent-id>`) | `0644` |
| `agent-ca.pem` | The issuing CA chain the agent pins the server against | `0644` |

**Key loss → automatic re-provisioning.** If `agent-client.key` is deleted or
corrupted, the agent transparently re-provisions on its next enrollment: it
generates a fresh keypair + CSR and the server issues a **new** leaf with a
**new serial**. The previous serial remains in the server's issued-cert inventory
(`GET /api/v1/ca/issued`) as an orphaned row that no live agent holds — this is
harmless, but if you reconcile the inventory you should expect one orphan per
key-loss event and may revoke it for tidiness. No manual re-enrollment is needed.

> **Revocation is not bypassable by key deletion.** Auto-re-provisioning applies
> only when the agent's prior cert was *not* revoked. If you **revoke** an
> agent's certificate (`POST /api/v1/ca/revoke`) and that agent then deletes its
> key and reconnects, the server **refuses** to issue a fresh leaf (audit
> `ca.cert.reissue_blocked`, metric `yuzu_server_ca_reissue_blocked_total`) — the
> agent cannot silently resurrect a revoked identity. To bring a revoked agent
> back, an operator must deliberately re-approve it (clearing the revocation),
> not merely let it re-enroll.

> **Gateway-proxied agents:** per-agent mTLS revocation is enforced on
> **direct-connect** agents only. An agent that reaches the server *through a
> gateway* presents its leaf to the gateway, not the server, so revoking that
> agent's certificate (`POST /api/v1/ca/revoke`) does **not** by itself cut it
> off the data plane — the server never sees the agent's leaf on the
> gateway→server hop. To decommission a gateway-proxied agent promptly, also
> disconnect it at the gateway/management layer. Through-gateway cryptographic
> revocation is planned with the QUIC transport migration. See
> `docs/auth-architecture.md` "Gateway-proxied agents: revocation scope".

### Windows Certificate Store Integration

On Windows, agents can read their mTLS client certificate and private key directly from the Windows certificate store instead of PEM files on disk. This uses CryptoAPI/CNG (`CertOpenStore`, `CertFindCertificateInStore`, `NCryptExportKey`) and searches the Local Machine store first, falling back to Current User.

**By subject name:**

```bash
yuzu-agent --server server.example.com:50051 \
           --cert-store MY \
           --cert-subject "yuzu-agent"
```

**By thumbprint:**

```bash
yuzu-agent --server server.example.com:50051 \
           --cert-store MY \
           --cert-thumbprint "AB12CD34EF56..."
```

The agent exports the full certificate chain (leaf + intermediates) as PEM in memory. Either `--cert-subject` or `--cert-thumbprint` is required when `--cert-store` is specified.

---

## Over-the-Air Agent Updates

Administrators can upload new agent binaries to the server and promote them to production. Connected agents will download and apply the update automatically.

### Upload a New Binary

**Dashboard:** Navigate to **Settings > Agent Updates** and use the upload form.

**API:**

The upload endpoint accepts multipart form data. The version is derived automatically from the uploaded filename (with common extensions like `.tar.gz`, `.zip`, `.exe`, `.msi`, `.bin` stripped).

```bash
curl -s -X POST http://localhost:8080/api/settings/updates/upload \
  -b "$COOKIE" \
  -F "file=@yuzu-agent-0.9.4-linux-x64.tar.gz" \
  -F "platform=linux" \
  -F "arch=x86_64" \
  -F "rollout_pct=100" \
  -F "mandatory=true"
```

| Field | Required | Description |
|---|---|---|
| `file` | Yes | The agent binary to upload |
| `platform` | Yes | Target platform (`linux`, `windows`, `darwin`) |
| `arch` | Yes | Target architecture (`x86_64`, `aarch64`) |
| `rollout_pct` | No | Rollout percentage, 0--100 (default: `100`) |
| `mandatory` | No | Whether agents must apply this update (`true`/`false`, default: `false`) |

### View Available Updates

```bash
curl -s http://localhost:8080/fragments/settings/updates -b "$COOKIE"
```

### Set Rollout Percentage

The rollout endpoint controls what percentage of eligible agents receive a given update. Set to `100` for full deployment, or use a lower value for staged rollouts.

```bash
curl -s -X POST http://localhost:8080/api/settings/updates/linux/x86_64/0.9.4/rollout \
  -b "$COOKIE" \
  -d "rollout_pct=100"
```

To do a staged rollout, set a lower percentage first and increase it over time:

```bash
# Start with 10% of agents
curl -s -X POST http://localhost:8080/api/settings/updates/linux/x86_64/0.9.4/rollout \
  -b "$COOKIE" \
  -d "rollout_pct=10"
```

### Remove an Uploaded Binary

```bash
curl -s -X DELETE http://localhost:8080/api/settings/updates/linux/x86_64/0.9.4 \
  -b "$COOKIE"
```

---

## Settings Page Route Reference

Most enrollment and device management operations are performed through the HTMX dashboard. The endpoints below are designed for the dashboard (accepting form-encoded parameters and returning HTML fragments), with the exception of the batch token endpoint which accepts and returns JSON.

### HTMX Fragments (Server-Rendered HTML)

| Route | Description |
|---|---|
| `GET /fragments/settings/pending` | Pending agents queue |
| `GET /fragments/settings/tokens` | Enrollment tokens list |
| `GET /fragments/settings/auto-approve` | Auto-approval policies |
| `GET /fragments/settings/updates` | OTA agent updates |

### Action Endpoints

Unless noted, these endpoints accept form-encoded parameters and return HTML fragments (designed for HTMX consumption).

| Method | Route | Description | Format |
|---|---|---|---|
| `GET` | `/api/agents` | List all connected agents (no auth required) | JSON |
| `POST` | `/api/settings/pending-agents/{agent_id}/approve` | Approve a pending agent | HTMX |
| `POST` | `/api/settings/pending-agents/{agent_id}/deny` | Deny a pending agent | HTMX |
| `DELETE` | `/api/settings/pending-agents/{agent_id}` | Remove from pending queue | HTMX |
| `POST` | `/api/settings/enrollment-tokens` | Generate an enrollment token (form-encoded) | HTMX |
| `POST` | `/api/settings/enrollment-tokens/batch` | Generate tokens in batch (JSON in, JSON out) | JSON |
| `DELETE` | `/api/settings/enrollment-tokens/{token_id}` | Revoke a token | HTMX |
| `POST` | `/api/settings/auto-approve` | Add a rule (form: `type`, `value`, `label`) | HTMX |
| `POST` | `/api/settings/auto-approve/mode` | Set match mode (form: `mode=any\|all`) | HTMX |
| `POST` | `/api/settings/auto-approve/{index}/toggle` | Enable/disable a rule | HTMX |
| `DELETE` | `/api/settings/auto-approve/{index}` | Delete a rule | HTMX |
| `POST` | `/api/settings/updates/upload` | Upload an agent binary (multipart) | HTMX |
| `POST` | `/api/settings/updates/{platform}/{arch}/{version}/rollout` | Set rollout percentage (form: `rollout_pct`) | HTMX |
| `DELETE` | `/api/settings/updates/{platform}/{arch}/{version}` | Remove an uploaded binary | HTMX |

---

## Custom Device Properties

Administrators can define typed key-value properties on devices beyond the built-in identity fields and structured tags. Properties support four types: `string`, `int`, `bool`, and `datetime`.

### Property Schemas

Before setting properties, define a schema to enforce type and validation rules.

**Create a schema:**

```bash
curl -s -X POST http://localhost:8080/api/v1/custom-properties/schemas \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key": "asset_owner",
    "type": "string",
    "description": "Department or individual responsible for this device",
    "validation_regex": "^[a-zA-Z0-9_ -]{1,128}$"
  }'
```

Supported types: `string`, `int`, `bool`, `datetime`. Key names must be 1-64 characters matching `[a-zA-Z0-9_.-:]`. Values are limited to 1024 bytes.

### Setting Properties

```bash
curl -s -X PUT http://localhost:8080/api/v1/devices/agent-001/properties/asset_owner \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "IT Operations"}'
```

### Using Properties in Scope Expressions

Custom properties are available in scope expressions using the `props.<key>` syntax:

```
props.asset_owner == "IT Operations" AND ostype == "windows"
```

---

## Device Discovery

Discover unmanaged devices on your network using the `discovery` agent plugin and server-side discovery store.

### Running a Subnet Scan

Execute the `scan_subnet` action from the `discovery` plugin against an agent on the target subnet:

```bash
curl -s -X POST http://localhost:8080/api/v1/executions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "definition_id": "discovery.scan_subnet",
    "parameters": {"subnet": "192.168.1.0/24"},
    "scope": "agent_id == \"agent-on-target-subnet\""
  }'
```

The plugin performs an ARP scan and ping sweep, returning discovered hosts with IP address, MAC address, resolved hostname, and whether the host is already managed by Yuzu.

### Viewing Discovered Devices

```bash
curl -s http://localhost:8080/api/v1/discovery \
  -H "Authorization: Bearer $TOKEN"
```

### Marking a Device as Managed

When a discovered device is enrolled, link it to the enrolled agent:

```bash
curl -s -X POST http://localhost:8080/api/v1/discovery/{device_id}/mark-managed \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "a3f1c9e2-7b4d-..."}'
```

---

## Deployment Jobs

Deploy the Yuzu agent to discovered or known endpoints without manual installation. Deployment jobs target hosts by IP address and support multiple deployment methods.

### Creating a Deployment Job

```bash
curl -s -X POST http://localhost:8080/api/v1/deployment-jobs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Deploy to office subnet",
    "targets": ["192.168.1.10", "192.168.1.11", "192.168.1.12"],
    "method": "ssh",
    "os": "linux"
  }'
```

Supported deployment methods: `ssh`, `group_policy`, `manual`.

### Job Lifecycle

Jobs progress through the following states:

| State | Description |
|---|---|
| `pending` | Job created, not yet started |
| `running` | Deployment in progress |
| `completed` | All targets successfully deployed |
| `failed` | One or more targets failed |
| `cancelled` | Job was cancelled by an administrator |

### Monitoring Job Status

```bash
curl -s http://localhost:8080/api/v1/deployment-jobs/{job_id} \
  -H "Authorization: Bearer $TOKEN"
```

### Cancelling a Job

```bash
curl -s -X POST http://localhost:8080/api/v1/deployment-jobs/{job_id}/cancel \
  -H "Authorization: Bearer $TOKEN"
```
