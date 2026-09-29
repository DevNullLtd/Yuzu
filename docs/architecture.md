# Yuzu Architecture

This document describes how Yuzu's components interact, the data flows between them, and the design rationale behind each subsystem.

## Component Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              Yuzu Server                                │
│                                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐   │
│  │  gRPC       │  │  HTTP/REST   │  │  Auth        │  │  Metrics    │   │
│  │  Services   │  │  API + HTMX  │  │  Manager     │  │  /metrics   │   │
│  │             │  │  Dashboard   │  │  (RBAC)      │  │             │   │
│  └──────┬──────┘  └──────┬───────┘  └───────┬──────┘  └─────────────┘   │
│         │         ┌──────────────┐          │                           │
│         │         │  MCP Server  │  (JSON-RPC 2.0, AI tool use)         │
│         │         │  /mcp/v1/    │          │                           │
│         │         └──────────────┘          │                           │
│         │                │                  │                           │
│  ┌──────▼────────────────▼──────────────────▼─────────────────────────┐ │
│  │                     Server Core                                    │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐   │ │
│  │  │ Agent        │  │ Instruction│  │ Response   │  │ Audit     │   │ │
│  │  │ Registry     │  │ Engine     │  │ Store      │  │ Log       │   │ │
│  │  └──────────────┘  └────────────┘  └────────────┘  └───────────┘   │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐   │ │
│  │  │ Scope        │  │ Policy     │  │ Scheduler  │  │ Event     │   │ │
│  │  │ Engine       │  │ Engine     │  │            │  │ Bus       │   │ │
│  │  └──────────────┘  └────────────┘  └────────────┘  └───────────┘   │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌────────────┐                  │ │
│  │  │ Management   │  │ NVD Sync   │  │ Content    │                  │ │
│  │  │ Groups       │  │            │  │ Repository │                  │ │
│  │  └──────────────┘  └────────────┘  └────────────┘                  │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
         │                                              │
    gRPC/mTLS                                     HTTP/REST
    (agents)                                    (browsers, API)
         │                                              │
    ┌────▼────┐                                    ┌────▼────┐
    │  Agent  │                                    │  Users  │
    │  Fleet  │                                    │  & API  │
    └─────────┘                                    │ Clients │
                                                   └─────────┘
```

## Data Flows

### 1. Agent Registration and Enrollment

```
Agent                           Server
  │                               │
  │──── Register(AgentInfo) ────► │  Contains: agent_id, hostname, OS, arch,
  │     + enrollment_token        │  plugins list, enrollment_token
  │                               │
  │                               ├── Validate enrollment token (Tier 2)
  │                               ├── OR check auto-approve rules
  │                               ├── OR add to pending queue (Tier 1)
  │                               │
  │◄── RegisterResponse ───────── │  Contains: session_id, enrollment_status
  │     (enrolled/pending/denied) │  (enrolled → proceed, pending → retry later)
  │                               │
  │──── Subscribe() ───────────── │  Bidirectional stream opens
  │     (bidi stream)             │  Server stores stream pointer in registry
```

**Why bidirectional streaming?** Polling-based command delivery (the legacy `Heartbeat` + `ExecuteCommand` pattern) introduces latency proportional to the heartbeat interval. The `Subscribe` RPC keeps a persistent stream open so the server can push commands immediately. This is critical for security response (quarantine a device NOW) and interactive querying. The difference from latency in commands manifests most in iterative situations such as LLM instrumented surfaces such as the MCP that Yuzu exposes; LLMs are naive and ‘walk up’ discovery of the correct course of action, iterated over failure. We want to make those failures as fast as possible - and successes as fast as possible as well - in order to allow agentic workloads to be performant.

**Why three enrollment tiers?** Different organizations have different security postures. Startup labs want zero-friction onboarding (Tier 2 tokens). Enterprises need approval workflows (Tier 1 manual). High-security environments need hardware attestation (Tier 3 platform trust).

### 2. Command Dispatch and Response Collection

```
Dashboard/API           Server                     Agent
     │                    │                          │
     │── SendCommand ───► │                          │
     │   (plugin, action, │                          │
     │    params, scope)  │                          │
     │                    ├── Scope engine evaluates │
     │                    │   which agents match     │
     │                    │                          │
     │                    │── CommandRequest ───────►│
     │                    │   (via Subscribe stream) │
     │                    │                          ├── Find plugin by name
     │                    │                          ├── Spawn execution thread
     │                    │                          ├── Call plugin execute()
     │                    │                          │
     │                    │◄── CommandResponse ──────│  Streamed: status, output chunks
     │                    │    (streaming)           │
     │                    ├── Store in Response Store│
     │                    ├── Aggregate if defined   │
     │                    │                          │
     │◄── SSE event ──────│                          │
     │   (real-time UI)   │                          │
```

**Why stream responses?** Plugins may produce output incrementally (e.g., scanning a filesystem). Streaming delivers results to the dashboard as they arrive rather than waiting for completion. This is also why the Response Store must handle appending partial results.

**Why a scope engine?** "Run this on all Windows 10 agents in the London office" is a common operation. Without a scope engine, the operator must manually list agent IDs. The scope engine evaluates an expression tree against the agent registry (OS type, tags, management group membership, FQDN pattern) and returns matching agents.

### 3. Instruction Definitions and Lifecycle

```
Admin                    Server
  │                         │
  │── Create Definition ───►│  Named, versioned template:
  │   (name, version,       │  - plugin + action + param schema
  │    param schema,        │  - response schema (typed columns)
  │    response schema,     │  - aggregation rules
  │    aggregation,         │  - TTL ranges
  │    instruction set)     │  - instruction type (question/action)
  │                         │
  │── Run Instruction ─────►│  Instantiate definition with:
  │   (definition name,     │  - parameter values
  │    scope expression,    │  - scope expression (who to target)
  │    parameter values)    │  - approved (or enters approval queue)
  │                         │
  │                         ├── Check approval workflow
  │                         ├── Evaluate scope → target agents
  │                         ├── Dispatch to agents
  │                         ├── Collect responses
  │                         ├── Aggregate server-side
  │                         │
  │◄── Results ─────────────│  Raw + aggregated, filterable, paginated
```

**Why instruction definitions?** Ad-hoc commands are powerful but dangerous at scale. Definitions provide:
- **Parameter validation** — prevent typos and invalid inputs
- **Response schemas** — typed columns enable aggregation, filtering, and downstream analytics
- **Versioning** — track which version of an instruction was run
- **Permission scoping** — assign to instruction sets with role-based access
- **Scheduling** — can't schedule an ad-hoc command; need a named definition

**Why server-side aggregation?** When 10,000 agents respond to "what antivirus is installed?", the operator doesn't want 10,000 rows. They want "8,200 have Defender, 1,500 have CrowdStrike, 300 have nothing." Aggregation (group-by + count/sum/min/max) runs server-side as responses arrive.

### 4. Policy Engine (Guaranteed State)

```
Admin                    Server                    Agent
  │                        │                         │
  │── Create Fragment ────►│  Check/Fix code block   │
  │── Create Rule ────────►│  Fragment + triggers    │
  │── Assign to Group ────►│  Policy → mgmt group    │
  │── Deploy ─────────────►│  Compile, hash, push    │
  │                        │                         │
  │                        │── Policy Document ─────►│  Agent receives rules + triggers
  │                        │                         │
  │                        │                         ├── Register triggers (interval,
  │                        │                         │   file change, service, etc.)
  │                        │                         │
  │                        │       [trigger fires]   │
  │                        │                         ├── Evaluate check instruction
  │                        │                         ├── If failed → run fix instruction
  │                        │                         ├── Report status to server
  │                        │                         │
  │                        │◄── Status Report ───────│  Rule statuses:
  │                        │                         │  CheckPassed, CheckFailed,
  │                        │                         │  FixPassed, FixErrored, etc.
  │                        │
  │◄── Compliance Dashboard│  Fleet compliance posture
```

**Why local evaluation?** If the server evaluates compliance, it must query every agent on every check interval — that's O(agents × rules × frequency) network round trips. Local evaluation means the agent watches for changes (via triggers) and only reports when something changes. This scales to hundreds of thousands of agents.

**Why triggers instead of polling?** Polling ("check every 5 minutes") wastes resources when nothing changes and misses changes between polls. Triggers (file watcher, service status change, event log) react to actual changes in near real time. Interval triggers are available as a fallback for things that can't be event-driven.

**Why separate check and fix?** Not all rules should auto-remediate. A check-only rule reports compliance status without modifying the system. A fix rule can attempt remediation but reports whether the fix succeeded. This separation supports audit-only mode (check only) and enforcement mode (check + fix).

### 5. Authentication, RBAC, and Access Control

```
User/API Client          Server
     │                     │
     │── Login ───────────►│  Session cookie (browser)
     │   or Bearer token   │  or API token (automation)
     │                     │
     │── Any Request ─────►│
     │                     ├── Authenticate (session or token)
     │                     ├── Identify principal
     │                     ├── Look up roles for principal
     │                     ├── For each role: check permissions
     │                     │   against (securable type, operation)
     │                     ├── Filter results by management group
     │                     │   visibility
     │                     │
     │◄── Response ────────│  Only data the principal can see
```

**Why management-group-scoped RBAC?** In large organizations, the London admin shouldn't see New York's devices, and vice versa. Management groups partition the fleet. Role assignments are scoped to groups (Principal + Role + ManagementGroup triple), so "Alice is Admin for London" and "Bob is Viewer for All" are both expressible.

### 6. Metrics and Observability

```
Agent                           Server                        External
  │                               │                             │
  │  yuzu_agent_commands_total    │  yuzu_server_agents_total   │
  │  yuzu_agent_plugins_loaded    │  yuzu_server_grpc_latency   │
  │  yuzu_agent_uptime_seconds    │  yuzu_server_responses_total│
  │                               │                             │
  │───── /metrics ───────────────►│                             │
  │  (Prometheus scrapes agent)   │───── /metrics ─────────────►│ Prometheus
  │                               │  (Prometheus scrapes server)│    │
  │                               │                             │    ▼
  │                               │                             │ Grafana
  │                               │                             │
  │                               │── Audit events ────────────►│ Splunk HEC
  │                               │── Webhooks ────────────────►│ ClickHouse
  │                               │── Response data ───────────►│ (via REST API)
```

**Why Prometheus-native?** Prometheus is the de facto standard for infrastructure metrics. By exposing `/metrics` in Prometheus exposition format, Yuzu integrates with existing monitoring stacks (Grafana, Alertmanager, Thanos) without custom adapters.

**Why design for ClickHouse/Splunk?** Endpoint management platforms generate massive volumes of structured data (inventory, command responses, compliance events). ClickHouse excels at columnar analytics over this data. Splunk excels at correlation and search. By using typed schemas, consistent timestamps, and structured JSON events, Yuzu data is immediately useful in these systems without ETL transformation.

### 7. Fleet Visualization (3D)

```
Operator                     Server                                  Agent
   │                           │                                       │
   │── GET /viz/fleet ────────►│  Auth gate; emit static HTML shell    │
   │   (browser)               │  (Cache-Control: no-cache, no-store)  │
   │                           │                                       │
   │◄── HTML shell ────────────│  importmap → /static/three.module.min.js
   │                           │             /static/three-orbit-controls.js
   │                           │             /static/yuzu-viz.js (renderer)
   │                           │                                       │
   │── GET /api/v1/viz/fleet/topology
   │   (or /fragments/...)     │                                       │
   │                           ├── Kill switch (--viz-disable)?  503   │
   │                           ├── Store null?                   503   │
   │                           ├── RBAC (Response.Read)?         403   │
   │                           ├── Parse params (machines_max,         │
   │                           │   include_vuln, fresh)                │
   │                           ├── FleetTopologyStore::get(...)        │
   │                           │     ├── cache hit (5 s TTL) → return  │
   │                           │     └── miss → single-flight refill:  │
   │                           │           dispatch tar.fleet_snapshot │
   │                           │           via fetcher seam            │
   │                           │                                       │
   │                           │── tar.fleet_snapshot ────────────────►│
   │                           │   (CommandRequest, fan-out per agent) │
   │                           │                                       ├── Collect
   │                           │                                       │   processes,
   │                           │                                       │   connections,
   │                           │                                       │   local_ips
   │                           │◄── CommandResponse (per agent) ───────│
   │                           │                                       │
   │                           ├── ResponseStore correlation by command_id
   │                           ├── 5 s aggregation timeout (partial OK)
   │                           ├── Categorise processes (Database / Browser /
   │                           │   Web / Runtime / System / Other) via
   │                           │   process_category.hpp heuristics
   │                           ├── Resolve cross-machine connections by
   │                           │   matching remote_addr against the
   │                           │   union of every agent's local_ips
   │                           ├── machines_max cap (default 5000,
   │                           │   ceiling 100000) — over cap → 413
   │                           ├── Audit emit (viz.fleet_topology +
   │                           │   viz.fleet_topology.invalidate when
   │                           │   ?fresh=1)
   │                           │
   │◄── JSON envelope ─────────│  fleet_topology.v1 — agents[], processes[],
   │   (or <script>-wrapped    │  connections[], categorisation, vuln overlay
   │    fragment)              │  if ?include_vuln=1
   │
   │── render() ───────────────┐
   │   (renderer module)       │  WebGLRenderer + OrbitControls camera +
   │                           │  WASD pan; machine cubes (one per agent,
   │                           │  deterministic FNV-1a grid, per-OS
   │                           │  palette) + Sprite hostname labels +
   │                           │  Raycaster hover tooltip; PR-7+ adds
   │                           │  process nodes, connection edges, vuln
   │                           │  overlays.
```

**Why a separate page route + REST surface?** Dashboard parity (agentic-first invariant A1) means every dashboard action must have a REST equivalent. The page (`/viz/fleet`) is the HTML shell + static asset bundle that browsers load; the REST endpoints (`/api/v1/viz/fleet/topology` and the `/fragments/...` companion) are what the renderer (and any LLM client / automation) actually call for data. Both go through the same `FleetTopologyStore`, the same kill-switch, RBAC, and audit gates.

**Why store-side categorisation?** The TAR (Telemetry, Acquisition, Response) plugin on each agent ships a flat process list with `cmdline` and `path`. Categorising client-side would mean every browser holds its own copy of the heuristics; doing it on the server lets the JSON envelope carry a single canonical category per process and lets the rules evolve without a renderer roll-out.

**Why a single-flight cache?** A topology fetch fans out to every agent in scope, so concurrent operator requests would otherwise dispatch N parallel `tar.fleet_snapshot` storms. The store coalesces concurrent misses onto one refill goroutine; in-flight waiters block on a condition variable up to a bounded timeout; subsequent gets within the 5 s TTL hit the cache.

**Why ES modules + importmap rather than UMD?** Three.js dropped UMD in r150+ — modern releases only publish `three.module.min.js`. The page declares an importmap mapping the bare specifier `"three"` to the vendored bundle, so OrbitControls' own `import { ... } from 'three'` resolves through the same map without a build-time bundler. Browser support floor: Chrome 89 / Firefox 108 / Safari 16.4 (importmap), all comfortably below the dashboard's existing baseline.

**Why a kill switch?** WebGL has a much larger attack surface than HTML, the renderer module is large (~6 KB hand-written + ~717 KB vendored), and the data path fans out to every agent. Operators who never use the feature should be able to disable it cleanly. `--viz-disable` (or `YUZU_VIZ_DISABLE=1`) makes both the page and the REST surface return 503 with an audit row, ahead of any RBAC check (tier-before-permission per `docs/auth-architecture.md` §3).

**Static-asset packaging.** The renderer was Pattern-A (hand-written `yuzu_viz_js_bundle.cpp`) through PR 5; at PR 6 the bundle exceeded MSVC's 16,380-byte raw-string-literal limit (C2026), and the renderer source migrated to `server/core/static/yuzu-viz.js` with `embed_js.py` codegen (Pattern B), matching the Three.js and OrbitControls pattern. The page HTML remains a Pattern-A hand-written TU (`viz_page_ui.cpp`). Vendored Three.js core and OrbitControls are Pattern-B over `vendor/three.module.min.js` and `vendor/three-orbit-controls.js`. See `docs/cpp-conventions.md` "Static-asset translation units" for when to use each pattern; `static/` houses our authoritative assets, `vendor/` houses upstream drops.

**Extension seam.** PR 6 filled the renderer's `mount() → buildScene()` callouts with machine cubes + Sprite hostname labels + Raycaster hover tooltip. PR 7+ fills the same seam with process nodes (interior of the cube), edges (intra-machine + cross-machine), and a vulnerability overlay when `?include_vuln=1`. The store, REST surface, audit, and kill switch are stable; renderer ships incrementally without further surface changes.

## Route Registration

Most HTTP surfaces the server exposes — REST, dashboard fragments, MCP — are registered by a
**route owner**: a class with a `register_routes(...)` method that the server calls once at
startup. As of #2542 PR-12, `server.cpp` **registers zero routes inline** on
`web_server_->{Get,Post,Put,Delete}` — every surface this prose has ever tracked here has moved to
its own `HttpRouteSink` module, and the campaign's inline-extraction goal (issue #438: an
in-process-untestable handler is an authorization/CSRF/scope-check blind spot) is complete. (Twenty
surfaces this prose previously credited to this inline count have moved to their own
`HttpRouteSink` modules: `POST /api/command` is `command_routes.cpp` (#2557); the
page-shell/static-asset surface — `/static/*`, `/`, `/chargen`, `/procfetch`, `/api/help*`,
`/help`, `/tar`, `/result-sets`, `/viz/fleet`, `/viz/host/:id`, `/instructions`; 25 routes — is
`page_routes.{hpp,cpp}` (#2542 PR-2); a #2542 follow-up split 10 further scattered routes into
`dashboard_api_routes.{hpp,cpp}` (`/api/me`, `/api/agents`, `/api/audit`, `POST
/api/export/json-to-csv`, `POST /api/scope/validate`, `/api/analytics/{status,recent}`; 7 routes)
and `nvd_routes.{hpp,cpp}` (`/api/nvd/{status,sync,match}`; 3 routes); the 5-route Custom
Properties API (7.6) — `/api/agents/:id/properties[/:key]`, `/api/property-schemas` — is
`custom_properties_routes.{hpp,cpp}` (#2542 PR-4); the Result Sets fragment API —
`/fragments/result-sets/{sidebar,create}` plus the three `:id`-scoped
`/fragments/result-sets/:id/{detail,pin,unpin,delete}`; 6 routes — is
`result_set_routes.{hpp,cpp}` (#2542 PR-5); the 13-route Instruction Definitions + Instruction Sets
API — `GET/POST /api/instructions`, `GET/PUT/DELETE /api/instructions/:id`,
`GET /api/instructions/:id/export`, `POST /api/instructions/import`,
`GET/POST /api/instruction-sets`, `DELETE /api/instruction-sets/:id`,
`GET /fragments/instructions/editor`, `POST /api/instructions/yaml`,
`POST /api/instructions/validate-yaml` — is `instruction_routes.{hpp,cpp}` (#2542 PR-7); the
7-route legacy pre-v1 Executions API — `GET /api/executions`, `GET /api/executions/:id`,
`GET /api/executions/:id/{summary,agents,children}`, `POST /api/executions/:id/{rerun,cancel}` —
is `execution_routes.{hpp,cpp}` (#2542 PR-7); the 4-route Schedules API —
`GET/POST /api/schedules`, `DELETE /api/schedules/:id`, `POST /api/schedules/:id/enable` — is
`schedule_routes.{hpp,cpp}` (#2542 PR-8); the 4-route Approval API — `GET /api/approvals`,
`GET /api/approvals/pending/count`, `POST /api/approvals/:id/{approve,reject}` — is
`approval_routes.{hpp,cpp}` (#2542 PR-9); the 6-route Health/Infra cluster — `GET /metrics`,
`GET /health`, `GET /api/health`, `GET /livez`, `GET /readyz`, `GET /fragments/health/summary` — is
`health_routes.{hpp,cpp}` (#2542 PR-10); the 3-route legacy pre-v1 Responses API — `GET
/api/responses/:id/aggregate`, `GET /api/responses/:id/export`, `GET /api/responses/(.+)` — is
`response_routes.{hpp,cpp}` (#2542 PR-11); the 4-route Tags API — `GET /api/tags`, `POST
/api/tags/set`, `POST /api/tags/delete`, `POST /api/tags/query` — is `tag_routes.{hpp,cpp}` (#2542
PR-11); the 3-route generic plugin-data Inventory API (Issue 7.17) — `GET
/api/inventory/tables`, `GET /api/inventory/:agent_id/:plugin`, `POST /api/inventory/query` — is
`data_inventory_routes.{hpp,cpp}` (#2542 PR-11, namespace `yuzu::server::data_inventory` to avoid
colliding with `inventory_routes.hpp`'s unrelated `/inventory` dashboard, which lives directly in
`yuzu::server`); and #2542 PR-12 (the Infra/Misc bundle — six small, heterogeneous modules with no
single owning store, matching the `dashboard_api_routes`/`nvd_routes` bundling precedent) split a
further 14 routes into six modules: the 2-route Runtime Configuration API (7.3) —
`GET /api/config`, `PUT /api/config/:key` — is `config_routes.{hpp,cpp}`; the 5-route Chargen +
Procfetch diagnostic API — `POST /api/chargen/{start,stop}`, `POST /api/procfetch/fetch`,
`GET /api/chargen/status`, `GET /api/procfetch/status` — is `diagnostics_routes.{hpp,cpp}`; the
legacy `GET /events` SSE stream is `legacy_events_routes.{hpp,cpp}`; the 2-route Instructions HTMX
fragment pair — `GET /fragments/instructions`, `POST /fragments/instructions/yaml-preview` — is
`instruction_fragment_routes.{hpp,cpp}` (deliberately not part of PR-7's `instruction_routes.cpp`
— see that module's header comment); the Approvals HTMX fragment — `GET /fragments/approvals` — is
`approvals_fragment_routes.{hpp,cpp}` (deliberately not part of PR-9's `approval_routes.cpp`); and
the 3-route MCP-disabled stub triple — `POST/GET/DELETE /mcp/v1/`, registered only when
`cfg_.mcp_disable` is true — is `mcp_disabled_routes.{hpp,cpp}`. Of the nineteen #2542 owner files
(everything above except `command_routes.cpp`, which is #2557), eighteen register against the same
stack-local `inline_sink`, constructed in `start_web_server()`. `mcp_disabled_routes.cpp` is the
one exception: it registers against its own local sink inside the `if (cfg_.mcp_disable)` block —
`inline_sink` is in fact still in scope there, but this module deliberately follows the
own-local-sink pattern `command_routes.cpp` already established, rather than reaching back out to
the shared one. Either would work identically at runtime — `HttplibRouteSink` is a stateless
forwarding wrapper — so this is a stylistic precedent, not a scope constraint.)

Counting the surface therefore needs a receiver-agnostic pattern, not a search for one variable
name:

```bash
grep -rnE '\b[A-Za-z_][A-Za-z0-9_]*(\.|->)(Get|Post|Put|Delete|Patch|Options)\(' server/core/src/*.cpp
```

Route owners name their receiver `svr` or `sink`; `server.cpp` names its `web_server_`. Grepping
only for `svr\.` returned nothing from `server.cpp` and read as "no inline routes" — a false
negative published in this document and in #2542 before it was caught; the receiver-agnostic
pattern above exists so a future inline registration can't hide the same way. `/api/command`'s
untestability is tracked by #2557; the owner-side migration by #2542.

**The registration seam.** A route owner's real `register_routes` takes `HttpRouteSink&`
(`server/core/src/http_route_sink.hpp`), and its `httplib::Server&` overload is a thin wrapper
that constructs a stack `HttplibRouteSink` and delegates to it. Production and tests therefore run
the *same* handler-construction code:

```cpp
void MyRoutes::register_routes(httplib::Server& svr, /* deps... */) {
    HttplibRouteSink sink(svr);
    register_routes(sink, /* deps... */);   // the real body lives here
}
```

**Why it is not optional.** A handler reachable only through the `httplib::Server&` overload
cannot be exercised in-process, because binding a real port plus an acceptor thread in a test
crashes under TSan with no TSan report (issue #438). Such a handler's authorization tier, CSRF
gate, and scope checks are then untestable, which is how the TAR retention-paused purge/reenable
fragments shipped a destructive operation with no route-handler coverage until #1786.

**Invariant.** New route owners register through `HttpRouteSink&`; new routes on an existing owner
register through the sink that owner already uses. Do not add a handler that only the
`httplib::Server&` overload — or an inline `web_server_->` call in `server.cpp` — can reach.
A registration outside the sink is a regression, not debt to extend: after #2542 PR-1
(`VerifyRoutes` and `NotificationRoutes` joined the sink pattern), the page-shell/static-asset
extraction (`page_routes.{hpp,cpp}`, PR-2, 25 routes registered against `inline_sink`), a #2542
follow-up (`dashboard_api_routes.{hpp,cpp}` + `nvd_routes.{hpp,cpp}`, 10 more scattered routes
registered against the same `inline_sink`), the Custom Properties API extraction
(`custom_properties_routes.{hpp,cpp}`, 5 routes, #2542 PR-4), the Result Sets fragment
extraction (`result_set_routes.{hpp,cpp}`, PR-5, 6 routes, also against `inline_sink`), and the
3-route MCP JSON-RPC endpoint (`mcp_server.{hpp,cpp}`, #2542 PR-6 — `McpServer::register_routes`
gained the `HttpRouteSink&` overload; its `httplib::Server&` overload is now the thin wrapper,
matching every other owning-class route module (`DeviceRoutes`, `ComplianceRoutes`, `DexRoutes`,
...) rather than the free-function `Deps`-struct + `inline_sink` pattern the other modules above
use — `server.cpp` still calls `mcp_server_->register_routes(*web_server_, ...)` unchanged, exactly
as it does for every other owning-class module), the Instruction Definitions + Instruction Sets /
legacy pre-v1 Executions extraction (`instruction_routes.{hpp,cpp}` +
`execution_routes.{hpp,cpp}`, PR-7, 13 + 7 = 20 routes, also against `inline_sink`), the Schedules
API extraction (`schedule_routes.{hpp,cpp}`, PR-8, 4 routes, also against `inline_sink`), the
Approval API extraction (`approval_routes.{hpp,cpp}`, PR-9, 4 routes, also against `inline_sink`),
the Health/Infra cluster extraction (`health_routes.{hpp,cpp}`, PR-10, 6 routes — `/metrics`,
`/health`, `/api/health`, `/livez`, `/readyz`, `/fragments/health/summary` — also against
`inline_sink`), the Data APIs extraction — the legacy pre-v1 Responses API
(`response_routes.{hpp,cpp}`, 3 routes), the Tags API (`tag_routes.{hpp,cpp}`, 4 routes), and the
generic plugin-data Inventory API (`data_inventory_routes.{hpp,cpp}`, 3 routes) — three separate
single-store modules landing together as one bundle PR (#2542 PR-11, 3 + 4 + 3 = 10 routes, also
against `inline_sink`), and the Infra/Misc bundle (PR-12, 14 routes across six modules —
`config_routes.{hpp,cpp}`, `diagnostics_routes.{hpp,cpp}`, `legacy_events_routes.{hpp,cpp}`,
`instruction_fragment_routes.{hpp,cpp}`, and `approvals_fragment_routes.{hpp,cpp}` against
`inline_sink`; `mcp_disabled_routes.{hpp,cpp}` against its own local sink inside
`if (cfg_.mcp_disable)`, the same pattern `command_routes.cpp` uses) — `server.cpp` registers ZERO
routes inline now; there is nothing left outside the sink for a further campaign PR to touch. An
earlier version of this sentence predicted otherwise twice ("no further PR touches them") and was
falsified both times; this is not a third prediction, it is the anchored count reading zero. Count
these with the anchored pattern
`grep -cE '^\s*web_server_->(Get|Post|Put|Delete|Patch|Options)\('
server/core/src/server.cpp`, not a bare `grep -c` of the receiver-agnostic pattern above — the
unanchored form over-counts by picking up at least one comment-line false match, which is how a
105/106 figure was previously published here; the anchored count was 104 immediately before the
page-shell extraction (independently re-verified during that extraction), 79 after it, 64 once both
the `dashboard_api_routes`/`nvd_routes` follow-up (-10) and the Custom Properties API extraction
(-5) had landed together, 58 once the Result Sets fragment extraction (-6) also landed, stayed 58
after the MCP extraction (#2542 PR-6) — that PR removed the last 3 raw `svr.{Get,Post,Delete}`
registrations in `mcp_server.cpp` (verify with
`grep -cE '\bsvr\.(Get|Post|Put|Delete|Patch|Options)\(' server/core/src/mcp_server.cpp`, now 0),
which were never counted by the `web_server_->` pattern above in the first place since they were
never inline in `server.cpp` — dropped to 38 once the Instruction Definitions + Instruction Sets /
legacy pre-v1 Executions extraction (-20, PR-7) landed, 34 once the Schedules API extraction (-4,
PR-8) also landed, 30 once the Approval API extraction (-4, PR-9) also landed, 24 once the
Health/Infra cluster extraction (-6, PR-10) also landed, 14 once the Data APIs bundle extraction
(-10: Responses -3, Tags -4, Inventory -3, PR-11) also landed, and is 0 now that the Infra/Misc
bundle (-14, PR-12) has also landed. Zero registrations remain outside the sink — the #2542
campaign's inline-route-extraction goal is complete.

## Storage Architecture

| Component | Backend | Purpose |
|---|---|---|
| Agent identity | SQLite (`agent.db`) | Persistent agent_id, enrollment state |
| Agent KV storage | SQLite (`agent.db`) | Cross-instruction persistent state |
| Server substrate | **PostgreSQL** (shared `PgPool`) | Server storage substrate (ADR-0006/0007); server **fails closed** without it |
| Server offline-endpoint state | **PostgreSQL** (`endpoint_state`) | Last-known per-agent identity + last-seen; renders offline hosts stale-flagged on `/viz/fleet` (first born-on-Postgres store) |
| Server responses | **PostgreSQL** (shared `PgPool`) | Command response persistence with TTL |
| Server audit | **PostgreSQL** (shared `PgPool`) | User action audit trail |
| Server identity/auth | **PostgreSQL** (`auth` + `scim_store` schemas) + config files (`.cfg`) | Users, tokens, enrollment, settings |
| NVD/CVE data | SQLite (`nvd_cves.db`) | Vulnerability database *(the one server store still on SQLite — a recorded deferral, not an exemption; see `docs/postgres-migration-ladder.md`)* |
| Policy state | **PostgreSQL** (shared `PgPool`) | Rule evaluation history, compliance |
| Threat-graph recommendations *(proposed, §28.9)* | **PostgreSQL** (born-on-PG, ADR-0006) | Agentic-AI-produced hardening suggestions awaiting operator accept/dismiss/apply |
| VirusTotal hash cache *(proposed, §28.8)* | **PostgreSQL** (born-on-PG, ADR-0006) | Rate-limited hash→verdict cache; 7-day TTL; keyed on SHA-256 |

**Substrate: PostgreSQL on the server, SQLite on the agent (ADR-0006, 2026-06-09).** As of the
flip (#1320 PR 3) the server **constructs a shared PostgreSQL pool at startup and fails closed
without it** — the substrate is live, not aspirational. Every server store except the NVD/CVE
cache is on the shared pool. `NvdDatabase` is a **recorded deferral, not an exemption**: it was
kept on SQLite to ship matching precision sooner, and its born-on-PG reshape stays queued as
vuln-scan milestone M1a (`docs/postgres-migration-ladder.md`) — ADR-0006's end state, no server
store on SQLite, still applies to it. The SQLite-everywhere principle has been **retired for the
server**. PostgreSQL is the standard server-side storage substrate, driven by cross-store
joins (the vuln-graph scoring join `edges ⨝ findings ⨝ value ⨝ guardian_state`), >1M-agent
scale (1.2M at HSBC), durable offline-endpoint state, and pgvector identity matching. **SQLite
is retained on the agent** — embedded-on-endpoint, zero-config, ~600KB, the federated edge
warehouse (ADR-0003) and `agent.db` KV/identity — because endpoint locality is exactly what
makes SQLite right there.

New server stores default to Postgres. The existing server stores other than `NvdDatabase` were
migrated incrementally, each behind its own per-store ADR + migration plan
(`SqliteTxn`/`SqliteStmt` → a pg transaction owner; `MigrationRunner` → a pg schema-migration
mechanism). This is a **breaking deployment change** — the server gains an external database
dependency (compose, Dockerfile, systemd, UAT/demo rigs, install docs, a CI Postgres service).
Secrets are **not** a plain Postgres column (envelope encryption / KMS / `pgcrypto`, separate
review). Substrate decision of record: `docs/adr/0006-server-postgresql-substrate.md`
(generalising ADR-0004).

## Plugin Architecture

```
Agent Process
  │
  ├── Plugin Loader
  │   ├── dlopen("hardware.so") → yuzu_plugin_descriptor()
  │   ├── dlopen("network.so")  → yuzu_plugin_descriptor()
  │   └── dlopen("custom.so")   → yuzu_plugin_descriptor()
  │
  ├── Plugin Registry (name → descriptor)
  │
  └── Command Dispatch
      └── execute(plugin_name, action, params)
          └── descriptor.execute(ctx, action, params, param_count)
              └── ctx->write_output("result data")
```

**Why a C ABI?** The plugin boundary must survive compiler version changes, standard library changes, and even language changes. A C ABI is the only binary-stable interface on all platforms. The C++ wrapper (`plugin.hpp`) provides ergonomic CRTP-based development while generating the C trampolines automatically via `YUZU_PLUGIN_EXPORT`.

**Why in-process plugins?** Out-of-process plugins (like VS Code extensions) add IPC overhead and deployment complexity. Endpoint management plugins are typically small, focused, and trusted (shipped by the vendor). In-process loading via `dlopen`/`LoadLibrary` gives sub-microsecond dispatch and zero serialization overhead.

## Security Model

| Layer | Mechanism | Purpose |
|---|---|---|
| Agent ↔ Server transport | mTLS (gRPC) | Mutual authentication, encrypted channel |
| Agent enrollment | 3-tier (manual, token, platform) | Flexible trust model |
| Dashboard auth | PBKDF2 sessions + OIDC | Human authentication |
| API auth | Bearer tokens | Automation authentication |
| Authorization | RBAC (principals, roles, permissions) | Fine-grained access control |
| Scope isolation | Management groups | Limit visibility per role assignment |
| Audit | Append-only audit log | Accountability and compliance |
| Secrets | Secure erase after use | Private keys zeroed in memory |

## Wire Protocol

All agent ↔ server communication uses Protocol Buffers v3 over gRPC with optional TLS. The proto files in `proto/` are the single source of truth:

- `yuzu/agent/v1/agent.proto` — AgentService (Register, Heartbeat, ExecuteCommand, Subscribe, ReportInventory)
- `yuzu/server/v1/management.proto` — ManagementService (ListAgents, GetAgent, SendCommand, WatchEvents, QueryInventory)
- `yuzu/gateway/v1/gateway.proto` — GatewayUpstream (ProxyRegister, BatchHeartbeat, ProxyInventory, NotifyStreamStatus)
- `yuzu/common/v1/common.proto` — Shared types (Platform, PluginInfo, ErrorDetail, Timestamp)

**Why Protobuf over JSON?** Protobuf is ~5x smaller on the wire and ~10x faster to parse than JSON. At 10,000 agents sending heartbeats every 30 seconds, this matters. Protobuf also provides schema evolution (add fields without breaking existing clients) and strongly typed codegen.
