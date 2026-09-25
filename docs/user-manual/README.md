# Yuzu User Manual

Yuzu is an enterprise endpoint management platform -- a single control plane for querying, commanding, patching, and enforcing compliance on Windows, Linux, and macOS fleets in real time. This manual covers day-to-day operations for administrators and operators.

All `curl` examples assume a running Yuzu server at `https://localhost:8080` (HTTPS is enabled by default) and an active admin session cookie in `$COOKIE`. Replace with your session token or API token as appropriate. For development without TLS, start the server with `--no-https`.

---

## Table of Contents

| Section | Description |
|---|---|
| [Device Management](device-management.md) | Agent enrollment (3-tier), heartbeat, identity, OTA updates, custom properties, device discovery, and deployment jobs |
| [Authentication](authentication.md) | Login, session management, mTLS, and Windows certificate store integration |
| [SCIM v2 Provisioning](scim-provisioning.md) | Auto-provision and auto-deprovision operators from an enterprise IdP (Okta/Entra/OneLogin) via SCIM 2.0 (SOC 2 CC6.2/CC6.8); Users-only, Groups→role mapping deferred |
| [RBAC](rbac.md) | Role-based access control -- principals, roles, securable types, per-operation permissions |
| [Engine Principals](engine-principals.md) | Durable identities for autonomous use-case-engine modules -- create/mint/rotate/confirm/transfer/revoke lifecycle, overlap-pair credential rotation, owner-delete interlock, and the independent no-admin auditor |
| [Asset Tagging](../asset-tagging-guide.md) | Structured tags (role, environment, location, service), categories, and tag compliance |
| [Management Groups](management-groups.md) | Hierarchical device grouping for access scoping and policy inheritance |
| [Instruction Engine](instructions.md) | Instruction definitions, sets, parameter/result schemas, scheduling, and approval workflows |
| [Scope Engine](scope-engine.md) | Expression-tree device targeting with AND/OR/NOT, tags, OS filters, and wildcards |
| [Audit Log](audit-log.md) | Structured audit events -- who did what, when, on which devices |
| [Response Store](response-store.md) | Persistent, filterable, aggregatable instruction response data |
| [Installed-Software Inventory](inventory.md) | Daily machine-scope installed-software sync to central Postgres (hash-skip, fleet-wide queries); first source of the agent daily-sync framework |
| [Software Licence Detection (SLE)](software-licensing.md) | Daily detection of installed software licences — type, channel, status, expiry — across Windows/Linux/macOS; the `/api/v1/sle/*` read surface + audited erasure; per-user `user_ref` privacy controls |
| [Agent Plugins](agent-plugins.md) | Plugin architecture, available plugins, and plugin development |
| [Autoruns](autoruns.md) | Persistence-source enumeration ("what starts automatically") across Windows (Run keys, Scheduled Tasks, WMI subscriptions), Linux (cron/systemd timers, XDG autostart), and macOS (launchd, Login Items) — the versioned 34-source catalog, row/status semantics, and real-hardware verification |
| [Cookbook](cookbook.md) | Practical examples for every plugin -- YAML, Python, CEL, Dashboard UI, and instruction chaining |
| [Policy Engine](policy-engine.md) | Desired-state rules, triggers, compliance checks, and auto-remediation |
| [Pre-flight readiness (`/auto`)](preflight.md) | Operator go/no-go checks across a device cohort before a fleet change — app/OS/disk/reboot thresholds, grouped by device, owner-scoped persisted runs with re-dispatch-on-reconnect |
| [Guaranteed State (Guardian)](guaranteed-state.md) | Real-time policy enforcement with agent-side guards, events, and remediation (control plane + agent skeleton shipped in v0.12; Windows enforcement lands in Guardian PR 3) |
| [DEX (Digital Employee Experience)](dex.md) | Read-only fleet-reliability dashboard over the Guardian event store — crash-free rates, 103-signal catalogue, per-app/per-device drill-downs (Windows, macOS, and Linux collectors; Linux covers Performance + storage on headless servers) |
| [Network Quality](network.md) | Continuous fleet TCP network quality — RTT, retransmit, and throughput (evidence-first; device/app co-occurrence is a later slice). Linux reports all three; Windows reports throughput + retransmit (RTT deferred). A DEX sub-view |
| [Metrics](metrics.md) | Prometheus `/metrics` endpoint, label conventions, and Grafana integration |
| [Server Administration](server-admin.md) | Configuration, TLS, user management, first-run setup, and backup |
| [TLS policy](tls.md) | Pinned TLS 1.2 cipher allow-list and version floor across the gRPC and HTTPS listeners -- what's pinned, what isn't yet, and what CI proves |
| [REST API Reference](rest-api.md) | Complete REST API v1 endpoint reference with request/response examples |
| [Gateway](gateway.md) | Erlang/OTP gateway node for multi-site deployments and scale-out |
| [TAR (Timeline Activity Record)](tar.md) | Continuous system state change tracking -- processes, network, services, users |
| [Upgrading](upgrading.md) | Version upgrades, rollback, and migration |
| [Release Verification](release-verification.md) | SHA256SUMS, cosign signatures, SLSA provenance, and CycloneDX / SPDX SBOMs |
| [MCP (AI Integration)](mcp.md) | Model Context Protocol server -- AI-driven fleet querying, tools, tokens, and approval workflows |
| [Security Hardening](security-hardening.md) | mTLS setup, firewall rules, secret management, quarantine, IOC checking, certificate inventory, and production hardening |

### Feature Guides (Inline)

The following features are documented within the files listed above:

| Feature | Location | Description |
|---|---|---|
| Custom Device Properties | [Device Management](device-management.md#custom-device-properties) | Typed key-value properties on devices with schema validation and scope integration |
| Device Discovery | [Device Management](device-management.md#device-discovery) | Subnet scanning to find unmanaged devices |
| Deployment Jobs | [Device Management](device-management.md#deployment-jobs) | Push agent installation to discovered endpoints |
| Device Quarantine | [Security Hardening](security-hardening.md#device-quarantine) | Network isolation for compromised devices |
| IOC Checking | [Security Hardening](security-hardening.md#ioc-checking) | Indicator of Compromise scanning for threat hunting |
| Certificate Inventory | [Security Hardening](security-hardening.md#certificate-inventory) | System certificate enumeration, inspection, and deletion |
| WiFi & WoL | [Agent Plugins](agent-plugins.md) · `agents/plugins/wifi/README.md`, `agents/plugins/wol/README.md` | WiFi network scanning and Wake-on-LAN magic packets |
| Patch Management | [REST API](rest-api.md) | Patch deployment, status tracking, and fleet compliance (via `PatchManager`) |
| Webhooks | [REST API](rest-api.md) | Event-driven HTTP notifications to external systems |
| Product Packs | [REST API](rest-api.md) | Signed YAML bundles containing definitions, policies, and templates |

### Operations Guides

| Section | Description |
|---|---|
| [Troubleshooting](../operations/troubleshooting.md) | Common issues, log diagnosis, and resolution steps |
| [High-Availability PostgreSQL](ha-postgres.md) | Opt-in Patroni + etcd + HAProxy failover profile — durability tiers, RTO/RPO, and production hardening requirements |
| [Disaster Recovery](../operations/disaster-recovery.md) | Backup strategy, restore procedures, and failover architecture |
| [Certificate Renewal](../operations/certificate-renewal.md) | TLS certificate lifecycle, rotation, and automated renewal |
| [Capacity Planning](../operations/capacity-planning.md) | Server sizing, storage growth, network bandwidth, and scaling patterns |
| [TAR Power Source](tar-power.md) | TAR power capture source: AC-line and sleep/wake history — on by default |
| [TAR Removable Source](tar-removable.md) | TAR removable-media capture source: attach/detach and executed-from-removable evidence — on by default |

---

## Supported Platforms

| Platform | Architecture | Server | Agent | Gateway |
|----------|-------------|--------|-------|---------|
| Linux | x64 (amd64) | Yes | Yes | Yes |
| Linux | ARM64 (aarch64) | Cross-compiled | Cross-compiled | Yes |
| Windows | x64 | Yes | Yes | -- |
| macOS | ARM64 (Apple Silicon) | Yes | Yes | -- |
| macOS | x64 (Intel) | Not supported | Not supported | -- |

> **Note:** macOS Intel (x64) builds are not currently produced or tested. Only Apple Silicon (ARM64) Macs running macOS 14+ are supported. If you require macOS Intel support, please open an issue.

## Quick Start

1. **Start the server** -- run `yuzu-server` with a configuration file or accept interactive first-run setup.
2. **Enroll an agent** -- run `yuzu-agent --server <host>:<port>` on a target endpoint. The agent will appear in the pending queue (Tier 1) or auto-enroll with a token (Tier 2).
3. **Approve the agent** -- open the Settings page in the dashboard or use the REST API to approve pending agents.
4. **Run your first instruction** -- see the [Getting Started tutorial](../getting-started.md) for a step-by-step walkthrough.

## Related Documentation

- [Getting Started Tutorial](../getting-started.md) -- hands-on walkthrough of the Instruction Engine
- [Architecture Overview](../architecture.md) -- system design and component interactions
- [YAML DSL Specification](../yaml-dsl-spec.md) -- formal spec for instruction definitions
- [Roadmap](../roadmap.md) -- planned features and issue tracking
- [Capability Map](../capability-map.md) -- 184 capabilities across 24 domains
