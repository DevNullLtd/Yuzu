# Yuzu Guardian — Architecture Design

> **Status:** Proposal
> **Audience:** Engineering, Sales Engineering, Security Review.
> Customer-shareable as part of the technical due-diligence packet under
> an NDA. The §23 honest-tamper-resistance stance and the Windows-API
> surface inventory are deliberate content, not accidental disclosures.
> **Scope:** Agent (Windows + Linux + macOS) + Server (dashboard, REST API)
> **Platform priority:** Windows first, Linux second, macOS backlog
> **Depends on:** Phase 5 Policy Engine, Phase 4 KV Storage, Phase 4 Triggers
> **Related capabilities:** 13.2 Composable Instruction Chains, Policy Engine (Guaranteed State)
> **Target files:** See Section 12 (Implementation Plan) for complete file inventory

---

## 1. Problem statement

The existing Policy Engine evaluates desired-state rules on a poll-based schedule (default 300s). For configuration compliance where the requirement is "this setting must never be in a non-compliant state", a 5-minute window is unacceptable. The requirement is:

- **Millisecond-level enforcement** for event-driven rules (firewall, registry, services)
- **Timely condition detection** for time-based rules (process not running, software outdated, AV scan overdue)
- **Fully offline-capable** — policies cached locally, enforcement continues without network
- **Pre-login activation** — enforcement must be active before any user can log in
- **Auditable** — every detection and remediation journaled locally, synced to server when online
- **Operator-friendly** — dedicated dashboard page for policy management, distribution, and alert review

### What this system enforces

This is not limited to firewall ports and registry values. The system enforces any detectable system state across Windows, Linux, and macOS, including:

- A specific port must remain blocked (all platforms)
- A service must remain disabled or remain running (Windows SCM, Linux systemd, macOS launchd)
- Remote Desktop must stay off (Windows) / SSH root login must stay disabled (Linux)
- A critical process (e.g., EDR agent) must always be running (all platforms)
- A piece of software must have been updated within the last N days (all platforms)
- An antivirus scan must have run within the last N days (all platforms)
- A specific registry value must equal a specific setting (Windows)
- A config file key must equal a specific value (Linux, macOS)
- A kernel parameter must equal a specific value (Linux sysctl)
- SELinux must remain in enforcing mode (Linux)
- A plist preference must equal a specific value (macOS)

---

## 2. Two categories of guard

Not all detections are the same. A firewall rule change happens instantaneously and can be caught by a kernel notification. But "software hasn't been updated in 30 days" is a time-based condition that requires periodic evaluation. The architecture supports both via two guard categories.

The guard types below are Windows-specific. See Section 15 for Linux equivalents and Section 19 for macOS equivalents. The two-category model (event guards vs condition guards) is identical across all platforms.

```
 Guards
 ├── Event Guards (real-time, kernel-backed user-mode APIs)
 │   ├── Registry Guard       RegNotifyChangeKeyValue          ~0ms latency   [implemented]
 │   ├── File Guard           ReadDirectoryChangesW            ~0ms latency   [implemented]
 │   ├── ETW Guard            OpenTrace / ProcessTrace          ~1-5ms latency
 │   ├── WFP Guard            FwpmFilterSubscribeChanges0       ~0ms latency
 │   └── SCM Guard            NotifyServiceStatusChange         ~0ms latency
 │
 └── Condition Guards (periodic evaluation on a schedule)
     ├── Process Guard         ToolHelp32 snapshot + ETW hybrid  configurable interval
     ├── Software Guard        Registry Uninstall keys + WMI     configurable interval
     ├── Compliance Guard      Event Log query + WMI query       configurable interval
     └── WMI Guard             Arbitrary WMI query evaluation    configurable interval
```

**Event guards** block on kernel wait handles and fire within microseconds of a change. They are appropriate for configuration settings that can change at any moment and must be immediately reverted.

**File Guard (implemented — Change B).** Watches a target file in real time via `ReadDirectoryChangesW` on its parent directory (no polling — unlike the Trigger Engine's mtime poll), resilient like the Registry Guard (survives the parent directory and its whole ancestor chain being deleted and recreated; reconciles from scratch on every wake). Two assertions: **`file-exists`** drifts when the file's presence differs from the expected state (`expected: present` → fires on delete; `expected: absent` → tripwire, fires on create), and **`file-hash-equals`** drifts when the content (size pre-filter + bounded SHA-256) differs from a baseline (`expected_hash` supplied, or captured on arm) — with a settle window before hashing because a write is not atomic, so a no-op identical rewrite is *not* drift. Detection-only: file-content remediation needs the Content Distribution subsystem and is deferred. Windows-only for the MVP (Linux inotify / macOS FSEvents are Section 15 / 19 work).

**Condition guards** run on a configurable schedule (default intervals vary by type: 30s for process checks, 3600s for software freshness). They evaluate a condition against a threshold and raise a drift event if the condition is not met. They are appropriate for time-based compliance checks where "within X hours/days" is the requirement.

**Hybrid guards:** The Process Guard is a hybrid. It uses the `Microsoft-Windows-Kernel-Process` ETW provider (event IDs 1/2 for process start/stop) for near-real-time detection, backed by a periodic `CreateToolhelp32Snapshot` poll for safety. If a required process terminates, the ETW event fires within milliseconds; the periodic poll catches cases where the process was never started or the ETW session missed an event.

**User-space note:** The Yuzu agent runs as a Windows service under the SYSTEM account — user-mode with elevated privileges, not kernel-mode. All detection APIs listed are standard Win32 APIs callable from user space. The term "kernel-backed" means the notification mechanism is implemented inside the kernel (not polling), but the API surface is entirely user-mode. No kernel drivers are required. The SYSTEM account holds all necessary privileges (`SeSystemProfilePrivilege` for ETW, `FWPM_ACTRL_SUBSCRIBE` for WFP, etc.).

---

## 3. Architecture overview

### 3.1 Agent-side component hierarchy

```
 Yuzu Agent
 ├── Plugin Host (existing — 44 plugins, C ABI)
 ├── Trigger Engine (existing — interval, file, evtlog triggers)
 ├── Comms / gRPC (existing — bidirectional stream)
 ├── KV Storage (existing — SQLite, reused for policy cache)
 │
 └── Yuzu Guardian (NEW)
     │
     ├── Policy Cache
     │   ├── SQLite table in existing KV store
     │   ├── Versioned rules with HMAC signatures
     │   └── Full offline operation — no network dependency
     │
     ├── Guard Manager
     │   ├── Instantiates guards based on active policy rules
     │   ├── Routes guard events to the State Evaluator
     │   ├── Manages guard lifecycle (start/stop/restart)
     │   │
     │   ├── Event Guards (real-time)
     │   │   ├── Registry Guard
     │   │   ├── ETW Guard
     │   │   ├── WFP Guard
     │   │   └── SCM Guard
     │   │
     │   ├── Condition Guards (periodic)
     │   │   ├── Process Guard (hybrid: ETW + periodic poll)
     │   │   ├── Software Guard
     │   │   ├── Compliance Guard
     │   │   └── WMI Guard
     │   │
     │   └── Reconciliation Guard (periodic full-state check, safety net)
     │
     ├── State Evaluator
     │   ├── Compares detected state against policy assertion
     │   ├── Returns: compliant | drift | exempt
     │   └── Assertion type registry (extensible)
     │
     ├── Remediation Engine
     │   ├── Executes corrective action (in-process, no server round-trip)
     │   ├── Delegates failure handling to Resilience Strategy
     │   └── Re-entrancy protection (suppresses self-triggered events)
     │
     ├── Resilience Strategy (per-rule configurable)
     │   ├── Persist — immediate, sub-ms, never gives up (default)
     │   ├── Backoff — exponential delay, never gives up
     │   ├── Bounded — give up after N cycles, then keep detecting + alert
     │   ├── Escalation — forward design (post-MVP): A → B → C → terminal
     │   └── Race Detector — sliding window drift rate tracking
     │
     └── Audit Journal
         ├── Local SQLite journal (sequential IDs, HMAC integrity)
         ├── Async writes (fire-and-forget from guard threads)
         └── Batch sync to server when online
```

### 3.2 Data flow

```
Server ──push──→ Policy Cache (local SQLite)
                      │
              Guard Manager reads active rules,
              starts appropriate guards
                      │
              ┌───────┴────────┐
              │                │
        Event Guard       Condition Guard
        (kernel wait)     (scheduled timer)
              │                │
              └───────┬────────┘
                      │
              Guard fires ──→ State Evaluator
                                    │
                              Compare actual vs desired
                                    │
                              ┌─ Compliant ──→ no-op
                              └─ Drift ──→ Remediation Engine
                                               │
                                         Execute corrective action
                                         Write audit event (async)
                                         Re-arm guard
```

### 3.3 Server-side additions

```
 Yuzu Server (existing)
 │
 ├── Guaranteed State Store (NEW — SQLite table)
 │   ├── Rule CRUD (yaml_source + denormalised columns)
 │   └── Fleet compliance state aggregation
 │
 ├── REST API v1 additions (NEW endpoints)
 │   ├── /api/v1/guaranteed-state/rules          CRUD
 │   ├── /api/v1/guaranteed-state/push           Distribute to agents
 │   ├── /api/v1/guaranteed-state/status         Fleet compliance
 │   ├── /api/v1/guaranteed-state/events         Drift/remediation events
 │   └── /api/v1/guaranteed-state/alerts         Active alerts
 │
 ├── Dashboard additions (NEW page)
 │   ├── /guaranteed-state                       Main page
 │   ├── /guaranteed-state/rules/:id             Rule detail
 │   ├── /guaranteed-state/alerts                Alert timeline
 │   └── HTMX fragments for all interactive elements
 │
 └── MCP tool additions
     ├── get_guaranteed_state_status              Fleet compliance
     ├── list_guaranteed_state_rules              Rule listing
     └── get_guaranteed_state_alerts              Active alerts
```

---

## 4. Boot-time enforcement (pre-login activation)

The Guardian engine must be enforcing policies **before any user can log in**. The agent achieves this by splitting its initialisation into two phases:

```
Windows Boot Sequence                    Yuzu Agent
─────────────────────                    ──────────
Kernel + HAL init
Session Manager (smss.exe)
Service Control Manager starts
    │
    ├── Yuzu Agent service starts ──────→ Phase 1: start_local()
    │   (SERVICE_AUTO_START)                  │
    │                                        ├── Open SQLite KV store
    │                                        ├── Load policy cache
    │                                        ├── Start all guards
    │                                        ├── Run initial reconciliation
    │                                        └── ENFORCING ✓
    │
    ├── Network stack initialises
    │
Winlogon shows login screen ───────────→ Phase 2: sync_with_server()
    │                                        │
    │                                        ├── Connect gRPC
    │                                        ├── Fetch policy updates
    │                                        └── Flush audit journal
    │
User logs in ──────────────────────────→ Already enforcing for ~30s+
```

**Phase 1 — Local enforcement (no network required):**
Called immediately on service start. Opens SQLite, loads cached rules, starts all guards. Requires only filesystem and the OS subsystems being watched (registry, ETW, WFP, SCM) — all available as soon as the kernel finishes. Takes <1 second.

**Phase 2 — Network sync (background, non-blocking):**
Called after gRPC connects. Fetches latest policy updates, flushes queued audit events. If the network isn't ready, Phase 2 blocks but enforcement continues.

**Service configuration for earliest start:**
- `Start` = 2 (SERVICE_AUTO_START), `DelayedAutoStart` = 0
- Early service group via `Group` registry value
- Minimal `DependOn` (nothing required for Phase 1)
- `FailureActions`: restart immediately on first/second failure, 0ms delay

**Reconciliation on boot:** The reconciliation guard runs an immediate full-state check on startup to catch drift from while the agent was off (shutdown, OS updates, Safe Mode).

---

## 5. Guard types — detailed

### 5.1 Event Guards

#### 5.1.1 Registry Guard

Uses `RegNotifyChangeKeyValue` with `REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME`.

```cpp
void RegistryGuard::watch_loop() {
    HKEY hkey;
    RegOpenKeyExW(root_, path_.c_str(), 0, KEY_NOTIFY | KEY_READ, &hkey);
    HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    while (!stop_requested_) {
        RegNotifyChangeKeyValue(hkey, watch_subtree_,
            REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_NAME,
            event, TRUE);

        HANDLE handles[] = { event, stop_event_ };
        DWORD result = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

        if (result == WAIT_OBJECT_0) {
            auto state = read_current_state(hkey);
            evaluator_->evaluate(rule_id_, std::move(state));
        }
    }
    RegCloseKey(hkey);
}
```

**Latency:** ~0µs (kernel signals event handle), +10–50µs (thread wake scheduling).

**Re-arm gap:** `RegNotifyChangeKeyValue` is one-shot. Between the moment the notification fires and the next `RegNotifyChangeKeyValue` call to re-arm, changes are silently lost. This window is typically <100µs but is real. The reconciliation guard is the backstop — it catches anything missed during re-arm gaps. For rules where every single change must be captured (forensic audit), use an ETW guard as the primary instead, since ETW delivers events via a continuous session without re-arming.

**Applicable rules:** Firewall rules, service startup type, security policies, network settings, RDP enable/disable, Windows Update policies, any registry-backed configuration.

#### 5.1.2 ETW Guard

Subscribes to real-time ETW trace sessions via `EVENT_TRACE_REAL_TIME_MODE` with `OpenTrace` / `ProcessTrace` in a dedicated thread.

**Key ETW providers:**

| Provider | Events | Use case |
|----------|--------|----------|
| Microsoft-Windows-Windows Firewall With Advanced Security | 2004/2005/2006 | Firewall rule changes |
| Microsoft-Windows-Security-Auditing | 4946–4948, 4719 | Security policy changes |
| Microsoft-Windows-Kernel-Process | 1 (start), 2 (stop) | Process lifecycle (Process Guard hybrid) |
| Microsoft-Windows-Kernel-General | 1 | System time changes |
| Microsoft-Windows-GroupPolicy | Various | Group Policy changes |

**Latency:** ~1–5ms.

**Audit policy dependency:** The `Microsoft-Windows-Security-Auditing` provider only generates events if the relevant Windows audit policy is enabled (e.g., "Audit Filtering Platform Policy Change" for events 4946–4948). If auditing isn't configured, the ETW guard won't receive events even though the subscription is active. Rules using this provider should include a precondition checking the audit policy, or the guard should log a warning at startup if the required audit subcategory is disabled.

#### 5.1.3 WFP Guard

Uses `FwpmFilterSubscribeChanges0` (user-mode WFP management API). The WFP filter engine runs in the kernel, but the subscription API is user-mode callable. SYSTEM has `FWPM_ACTRL_SUBSCRIBE` by default.

**Important:** WFP operates at the filter level, not the firewall rule level. Windows Firewall rules are a higher-level abstraction that translates into WFP filters. WFP change notifications tell you a filter changed, but the notification content doesn't contain the original firewall rule name, port, or protocol in an easily parseable format. For firewall rule enforcement, the Registry Guard watching the `FirewallRules` key is the more practical primary detection mechanism. The WFP Guard is best used as a secondary/defence-in-depth layer that catches network filter changes made outside the Windows Firewall abstraction (e.g., programmatic WFP filter additions that bypass `netsh` entirely).

**Latency:** ~0ms.

#### 5.1.4 SCM Guard

Uses `NotifyServiceStatusChange` for real-time service state transitions.

**Latency:** ~0ms.

### 5.2 Condition Guards

#### 5.2.1 Process Guard (hybrid)

Ensures a required process is running (or a forbidden process is not running).

**Detection mechanism:**
- **Primary (real-time):** ETW `Microsoft-Windows-Kernel-Process` provider. Event ID 2 (process stop) fires within ~1ms. Event ID 1 (process start) catches forbidden processes.
- **Backup (periodic):** `CreateToolhelp32Snapshot` + `Process32First`/`Process32Next`. Default interval: 30s.

**Remediation options:** `restart-process`, `stop-process`, `restart-service`, `alert-only`

**Implementation note:** Process names matched case-insensitively. Captures PID, parent PID, executable path. Optional digital signature verification via `WinVerifyTrust` to prevent binary substitution.

#### 5.2.2 Software Guard

Ensures installed software is up to date (installed or updated within N days).

**Detection mechanism (periodic, default interval 3600s):**
- Registry `Uninstall` keys: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` (+ WOW64)
- Parse `InstallDate` (YYYYMMDD) and `DisplayVersion`
- Compare against `max_age_days` or `min_version`

**Remediation options:** `alert-only` (most common), `command` (trigger update check), `quarantine`

#### 5.2.3 Compliance Guard

Ensures a specific event has occurred within a time window.

**Detection mechanism (periodic, default interval 3600s):**
- Event Log: `EvtQuery` for specific event IDs within time window
- WMI: Query status objects (e.g., `MSFT_MpComputerStatus.LastFullScanEndTime`)

**Common compliance checks:**

| Check | Source | Property/Events |
|-------|--------|----------------|
| Defender last scan | WMI `MSFT_MpComputerStatus` | `LastFullScanEndTime` |
| Windows Update check | WMI `Win32_QuickFixEngineering` | `InstalledOn` |
| Backup last run | Event Log | Backup software event IDs |
| Password age | WMI `Win32_UserAccount` | `PasswordAge` |

**Remediation options:** `alert-only`, `command` (trigger scan/check), `quarantine`

#### 5.2.4 WMI Guard

Generic condition guard — evaluates arbitrary WQL queries on a schedule. The escape hatch for anything not covered by specialised guards.

**Detection mechanism (periodic):** `IWbemServices::ExecQuery` + property extraction + comparison against expected value.

---

## 6. Policy definition (YAML DSL)

Extends the existing `yuzu.io/v1alpha1` DSL with `kind: GuaranteedStateRule`.

### 6.1 Complete schema

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: <unique-rule-name>
  description: "<human-readable>"
  tags: [<tag>, ...]

spec:
  target:
    os: windows
    scope: "<scope expression>"

  # ── Precondition (optional, evaluated locally on agent) ────
  # Unlike scope (server-side targeting), preconditions run on the agent and
  # determine whether the rule applies to THIS machine's current state.
  # If the precondition fails, no guards start — zero resource usage.
  precondition:                       # Optional
    type: os-version | software-installed | file-exists | package-installed |
          registry-exists | wmi-query   # last two are Windows-only
    params: { ... }
    # type: software-installed          (all platforms)
    #   params: { software_name: "CrowdStrike Falcon Sensor" }
    # type: os-version                  (all platforms)
    #   params: { min_version: "10.0.19041" }
    # type: file-exists                 (all platforms)
    #   params: { path: "/etc/crowdstrike/falconctl" }
    # type: package-installed           (Linux)
    #   params: { package_name: "falcon-sensor" }
    # type: registry-exists             (Windows only)
    #   params: { path: "HKLM\\SOFTWARE\\SomeVendor\\Product" }
    # type: wmi-query                   (Windows only)
    #   params: { query: "SELECT * FROM ...", expected_count: 1 }
    recheck_interval: 300s          # Re-evaluate precondition periodically (default 300s)
                                     # If machine state changes (e.g., software installed later),
                                     # the precondition is re-checked and guards start if it passes

  # ── Detection ──────────────────────────────────────────────
  guards:
    - type: registry | etw | wfp | scm | process | software | compliance | wmi | reconciliation
      # Type-specific config (see Section 5)
      priority: primary | backup
      debounce: 0ms                 # Optional: coalesce rapid-fire events within this window
                                     # Default: 0 for event guards (fastest enforcement),
                                     # 0 for condition guards. Set 10-50ms for noisy subtrees (e.g., GPO keys)

  # ── Assertion ──────────────────────────────────────────────
  assertion:
    type: <assertion-type>           # See Section 6.3
    params: { ... }

  # ── Remediation ────────────────────────────────────────────
  remediation:
    action: enforce | alert-only | quarantine
    method: auto | registry-write | firewall-api | wfp-api | service-control |
            command | restart-process | stop-process
    # method: auto — derives the fix from the assertion's desired state.
    #   action: enforce + method: auto → applies the fix automatically
    #   action: alert-only + method: auto → reports what fix WOULD be applied
    #   action: alert-only + no method → pure detection, no fix computed
    #   Only valid for auto-derivable assertion types (see Section 6.5)
    params: { ... }                  # Not required when method: auto

    resilience:
      mode: persist | backoff | bounded     # Persist today; Backoff/Bounded = C3; escalation post-MVP
      # Mode-specific config (see Section 8.5)

  audit:
    severity: critical | high | medium | low
    notify: true
    event_type: "<custom event type>"

  version: 1
  enabled: true
  enforcement_mode: enforce | audit | disabled
  # NOTE (MVP / contract G7, #1209): the shipped MVP implements only
  # `enforce | audit` here and expresses "disabled" via the separate `enabled:
  # false` boolean above, not a third mode value. The store + REST validate
  # mode in {enforce, audit}. The 3-state master-override described below is the
  # forward design.
  # enforcement_mode is a master override:
  #   enforce  — rule operates as configured (action field takes effect)
  #   audit    — forces all actions to alert-only regardless of the action field
  #   disabled — rule is inactive, no guards started
```

### 6.2 Guard type configuration reference

```yaml
# Event guards (real-time)
- type: registry
  path: "HKLM\\SYSTEM\\..."
  watch: subtree | values

- type: etw
  provider: "<provider name or GUID>"
  event_ids: [2004, 2005, 2006]

- type: wfp          # No additional config

- type: scm
  service_name: "<service name>"

# Condition guards (periodic)
- type: process
  process_name: "<executable name>"
  interval: 30s
  verify_signature: true

- type: software
  software_name: "<display name regex>"
  interval: 3600s

- type: compliance
  source: event_log | wmi
  log_name: "..."              # For event_log
  event_ids: [1001]            # For event_log
  wmi_class: "..."             # For WMI
  wmi_property: "..."          # For WMI
  wmi_namespace: "..."         # For WMI
  interval: 3600s

- type: wmi
  query: "SELECT ... FROM ..."
  property: "..."
  namespace: "root/cimv2"
  interval: 300s

- type: reconciliation
  interval: 60s

# ── Linux guards (see Section 15 for details) ──
- type: inotify
  path: "/etc/ssh/sshd_config"      # File or directory to watch

- type: netlink
  family: netfilter | route | proc   # Which netlink family
  # netfilter: nftables rule changes
  # route: interface/address/routing changes
  # proc: process start/stop events

- type: dbus
  unit_name: "sshd.service"          # systemd unit to watch

- type: audit
  watch_path: "/etc/ssh/sshd_config" # File to audit-watch (optional)
  syscalls: [__NR_sethostname]       # Syscalls to monitor (optional)
  permissions: "wa"                   # w=write, a=attribute change

- type: sysctl
  key: "net.ipv4.ip_forward"         # Sysctl parameter name
  interval: 30s                       # Backup poll interval

# ── macOS guards (see Section 19 for details) ──
- type: endpoint_security
  events: [write, rename, exec, exit, setmode]  # ES event types to subscribe
  watch_paths: ["/etc/pf.conf"]                  # Path filter (critical for performance)

- type: fsevents                       # Degraded mode fallback (no ES entitlement)
  path: "/Library/Preferences/"
  latency: 0.0                         # Seconds; 0 = immediate delivery

- type: pf_firewall                    # Three-layer pf detection
  poll_interval: 5s                    # Layer 3 ioctl poll interval
```

### 6.3 Assertion type reference

| Assertion type | Category | Description | Platform |
|---|---|---|---|
| `firewall-port-blocked` | Event | Port must not accept connections | All |
| `firewall-rule-disabled` | Event | Named firewall rule must be disabled | All |
| `firewall-rule-exists` | Event | Firewall rule must exist with properties | All |
| `service-stopped` | Event | Service must be Stopped | All |
| `service-disabled` | Event | Service startup must be Disabled | All |
| `service-running` | Event | Service must be Running | All |
| `process-running` | Condition | Named process must be running | All |
| `process-not-running` | Condition | Named process must not be running | All |
| `software-updated-within` | Condition | Software updated within N days | All |
| `software-version-minimum` | Condition | Software version >= minimum | All |
| `av-scan-within` | Condition | AV scan ran within N days | All |
| `file-permissions` | Event | File must have specific mode/owner | All |
| `registry-value-equals` | Event | Registry value must equal specific value | Windows |
| `registry-value-absent` | Event | Registry key/value must not exist | Windows |
| `registry-value-range` | Event | DWORD value within min/max | Windows |
| `rdp-disabled` | Event | Remote Desktop must be disabled | Windows |
| `smb-v1-disabled` | Event | SMBv1 must be disabled | Windows |
| `windows-update-within` | Condition | Windows Update check within N days | Windows |
| `event-occurred-within` | Condition | Specific event within N hours | Windows |
| `wmi-value-equals` | Condition | WMI result equals expected | Windows |
| `wmi-value-threshold` | Condition | WMI result above/below threshold | Windows |
| `sysctl-value-equals` | Event/Condition | Kernel parameter must equal value | Linux |
| `config-value-equals` | Event | Config file key must equal value | Linux, macOS |
| `config-line-present` | Event | Config file must contain a line | Linux, macOS |
| `config-line-absent` | Event | Config file must NOT contain a line | Linux, macOS |
| `selinux-enforcing` | Event | SELinux must be in enforcing mode | Linux |
| `kernel-module-blocked` | Condition | Kernel module must not be loadable | Linux |
| `plist-value-equals` | Event | Property list value must match | macOS |
| `alf-enabled` | Event | Application Firewall must be on | macOS |

### 6.4 Auto-remediation reference (`method: auto`)

When `method: auto` is specified, the system derives the corrective action from the assertion's desired state. This avoids the operator having to define both the check and the fix for simple cases.

| Assertion type | Auto? | Derived fix |
|---|---|---|
| `registry-value-equals` | Yes | Write the expected value |
| `registry-value-absent` | Yes | Delete the key/value |
| `registry-value-range` | Yes | Clamp to nearest bound (if below min, set to min; if above max, set to max) |
| `service-disabled` | Yes | Set Start=4 (SERVICE_DISABLED) |
| `service-stopped` | Yes | Stop the service |
| `service-running` | Yes | Start the service |
| `firewall-port-blocked` | Yes | Block port via firewall API |
| `rdp-disabled` | Yes | Set fDenyTSConnections=1 |
| `smb-v1-disabled` | Yes | Disable SMBv1 via registry |
| `process-running` | Partial | Needs `process_path` or `service_name` in params |
| `process-not-running` | Yes | Terminate the process |
| `software-updated-within` | No | Cannot auto-update software |
| `software-version-minimum` | No | Cannot auto-update software |
| `av-scan-within` | No | Cannot derive scan command portably |
| `windows-update-within` | No | Cannot derive update trigger portably |
| `event-occurred-within` | No | Cannot force an event to occur |
| `wmi-value-equals` | No | Most WMI classes are read-only |
| `wmi-value-threshold` | No | Most WMI classes are read-only |
| `sysctl-value-equals` | Yes | `write()` to `/proc/sys/` path |
| `config-value-equals` | Yes | Atomic rewrite with correct value |
| `config-line-present` | Yes | Append line if missing |
| `config-line-absent` | Yes | Remove matching lines, atomic rewrite |
| `selinux-enforcing` | Yes | `security_setenforce(1)` via libselinux |
| `file-permissions` | Yes | `chmod()` + `chown()` |
| `kernel-module-blocked` | Yes | Write to `/etc/modprobe.d/` |
| `plist-value-equals` | Yes | `CFPreferencesSetAppValue` |
| `alf-enabled` | Yes | `CFPreferencesSetAppValue` on `com.apple.alf` |

Server rejects `method: auto` at rule creation time for non-auto-derivable assertion types with a clear validation error.

### 6.5 Debouncing

Guards support an optional `debounce` window that coalesces rapid-fire OS notifications into a single evaluation. This is configured per-guard in the YAML:

```yaml
guards:
  - type: registry
    path: "HKLM\\..."
    debounce: 50ms     # Wait 50ms after last change before evaluating
```

**How it works:** When the guard receives an OS notification, it starts (or resets) a debounce timer. The evaluation only fires after the timer expires without any new notifications. This means a burst of 15 registry changes within 50ms produces one evaluation, not 15.

**Three levels of debouncing:**
- **Input debounce** (per-guard): Coalesces OS notifications before evaluation. Configured via `debounce:` in the guard block. Default: 0 for all guard types (fastest possible enforcement). Set 10–50ms for noisy registry subtrees like Group Policy keys where a single logical change writes many values in rapid succession.
- **Remediation debounce** (per-rule): After a successful remediation, suppresses re-evaluation for a short window to absorb the self-triggered notification. Handled by the re-entrancy flag (see Section 8.4). Default: 5ms.
- **Audit debounce** (per-rule): Coalesces near-identical audit events to avoid flooding the journal. If the same rule on the same agent produces >N identical events within a window, they're collapsed into a single event with a count. Default: 1s window, collapse after 3 identical events.

**When NOT to debounce:** For rules where every single change must be individually tracked (e.g., forensic audit of who changed a security policy), set `debounce: 0`. The guard will fire on every notification.

### 6.6 Example rules

#### Block SMB port 445 (event-driven, escalation)

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: block-smb-port-445
  description: "Ensure SMB port 445 is blocked for inbound traffic"
  tags: [security, network, cis-benchmark-5.2.1]
spec:
  target:
    os: windows
    scope: "tag:production-workstations AND NOT tag:file-servers"
  guards:
    - type: registry
      path: "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules"
      watch: subtree
      debounce: 20ms                    # Firewall rule subtree is noisy during GPO refresh
      priority: primary
    - type: etw
      provider: "Microsoft-Windows-Windows Firewall With Advanced Security"
      event_ids: [2004, 2005, 2006]
      priority: primary
    - type: reconciliation
      interval: 60s
      priority: backup
  assertion:
    type: firewall-port-blocked
    params:
      port: 445
      protocol: TCP
      direction: inbound
  remediation:
    action: enforce
    method: firewall-api
    params: { port: 445, protocol: TCP, direction: inbound, action: block }
    resilience:
      mode: escalation     # forward design (post-MVP) — see §8.5
      steps:
        - method: firewall-api
          params: { port: 445, protocol: TCP, direction: inbound, action: block }
          max_failures: 3
          retry_delay: 50ms
        - method: registry-write
          params: { path: "HKLM\\...\\FirewallRules", delete_matching: "*|445|TCP|In|*" }
          max_failures: 3
          retry_delay: 100ms
        - method: wfp-api
          params: { action: block, port: 445, protocol: TCP, weight: 65535 }
          max_failures: 2
          retry_delay: 200ms
      on_exhausted: quarantine
  audit:
    severity: high
    notify: true
  version: 1
  enabled: true
  enforcement_mode: enforce
```

#### EDR agent must always be running (hybrid, backoff)

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: edr-agent-running
  description: "CrowdStrike Falcon sensor must always be running"
  tags: [security, edr, critical]
spec:
  target:
    os: windows
    scope: "all"
  precondition:
    type: software-installed
    params: { software_name: "CrowdStrike Windows Sensor" }
    recheck_interval: 300s
  guards:
    - type: process
      process_name: "CSFalconService.exe"
      interval: 30s
      verify_signature: true
      priority: primary
  assertion:
    type: process-running
    params: { process_name: "CSFalconService.exe", min_instances: 1 }
  remediation:
    action: enforce
    method: restart-service
    params: { service_name: "CSFalconService" }
    resilience:
      mode: backoff
      backoff_initial_ms: 5000
      backoff_max_ms: 60000
      max_delay: 300s
      jitter: true
  audit:
    severity: critical
    notify: true
  version: 1
  enabled: true
  enforcement_mode: enforce
```

#### Chrome updated within 30 days (condition, alert-only)

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: chrome-updated-30d
  description: "Google Chrome must have been updated within 30 days"
  tags: [compliance, software-freshness]
spec:
  target:
    os: windows
    scope: "tag:workstations"
  guards:
    - type: software
      software_name: "Google Chrome"
      interval: 3600s
  assertion:
    type: software-updated-within
    params: { software_name: "Google Chrome", max_age_days: 30 }
  remediation:
    action: alert-only
  audit:
    severity: medium
    notify: true
  version: 1
  enabled: true
  enforcement_mode: enforce
```

#### AV scan within 7 days (condition, trigger scan)

Note: This rule uses the `command` escape hatch because no system-call API exists for triggering a Windows Defender scan. This is an intentional exception to the system-calls-only principle.

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: av-scan-7d
  description: "Windows Defender full scan must have run within 7 days"
  tags: [compliance, antivirus, cis-benchmark-8.1]
spec:
  target:
    os: windows
    scope: "all"
  guards:
    - type: compliance
      source: wmi
      wmi_class: "MSFT_MpComputerStatus"
      wmi_property: "LastFullScanEndTime"
      wmi_namespace: "root/Microsoft/Windows/Defender"
      interval: 3600s
  assertion:
    type: av-scan-within
    params: { max_age_days: 7, scan_type: full }
  remediation:
    action: enforce
    method: command
    params:
      command: "pwsh.exe -NonInteractive -Command Start-MpScan -ScanType FullScan"
    resilience:
      mode: bounded
      max_attempts: 3
      resume_after_s: 86400    # auto-retry daily; omit to require a human
  audit:
    severity: high
    notify: true
  version: 1
  enabled: true
  enforcement_mode: enforce
```

#### SSH root login disabled (Linux, config-value-equals)

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: ssh-no-root-login
  description: "SSH must not permit root login"
  tags: [security, ssh, cis-benchmark]
spec:
  target:
    os: linux
    scope: "tag:servers"
  guards:
    - type: inotify
      path: /etc/ssh/sshd_config
      priority: primary
    - type: reconciliation
      interval: 60s
      priority: backup
  assertion:
    type: config-value-equals
    params:
      path: /etc/ssh/sshd_config
      key: PermitRootLogin
      expected: "no"
      format: sshd
  remediation:
    action: enforce
    method: auto
  audit:
    severity: high
    notify: true
  version: 1
  enabled: true
  enforcement_mode: enforce
```

#### IP forwarding disabled (Linux, sysctl)

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: no-ip-forwarding
  description: "IP forwarding must be disabled on workstations"
  tags: [security, network, cis-benchmark]
spec:
  target:
    os: linux
    scope: "tag:workstations"
  assertion:
    type: sysctl-value-equals
    params:
      key: net.ipv4.ip_forward
      expected: "0"
  remediation:
    action: enforce
    method: auto
  audit:
    severity: high
    notify: true
  version: 1
  enabled: true
  enforcement_mode: enforce
```

#### macOS Application Firewall enabled (macOS, plist)

```yaml
apiVersion: yuzu.io/v1alpha1
kind: GuaranteedStateRule
metadata:
  name: macos-alf-enabled
  description: "macOS Application Firewall must be enabled"
  tags: [security, firewall, macos]
spec:
  target:
    os: macos
    scope: "all"
  assertion:
    type: alf-enabled
    params: {}
  remediation:
    action: enforce
    method: auto
  audit:
    severity: high
    notify: true
  version: 1
  enabled: true
  enforcement_mode: enforce
```

---

## 7. Protobuf / wire protocol

### 7.1 New messages

```protobuf
// proto/yuzu/guardian/v1/guaranteed_state.proto

syntax = "proto3";
package yuzu.guardian.v1;
import "google/protobuf/timestamp.proto";

message GuaranteedStateRule {
  string rule_id = 1;
  string name = 2;
  string yaml_source = 3;
  uint64 version = 4;
  bool enabled = 5;
  string enforcement_mode = 6;
  bytes signature = 7;
}

message GuaranteedStatePush {
  repeated GuaranteedStateRule rules = 1;
  bool full_sync = 2;
  uint64 policy_generation = 3;
}

message GuaranteedStateEvent {
  string rule_id = 1;
  string rule_name = 2;
  string event_type = 3;
  string severity = 4;
  string guard_type = 5;
  string guard_category = 6;
  string detected_value = 7;
  string expected_value = 8;
  string remediation_action = 9;
  bool remediation_success = 10;
  uint64 detection_latency_us = 11;
  uint64 remediation_latency_us = 12;
  google.protobuf.Timestamp timestamp = 13;
  string resilience_strategy = 14;
  uint32 escalation_step = 15;
  double drift_rate = 16;
  string competing_process = 17;
  string platform = 18;           // "windows" | "linux" | "macos"
}

message GuaranteedStateStatus {
  string agent_id = 1;
  uint64 policy_generation = 2;
  uint32 total_rules = 3;
  uint32 compliant_rules = 4;
  uint32 drifted_rules = 5;
  uint32 errored_rules = 6;
  repeated GuaranteedStateRuleStatus rules = 7;
  string platform = 8;            // "windows" | "linux" | "macos"
}

message GuaranteedStateRuleStatus {
  string rule_id = 1;
  string status = 2;
  string guard_category = 3;
  uint32 drift_count = 4;
  uint32 remediation_count = 5;
  google.protobuf.Timestamp last_evaluation = 6;
  google.protobuf.Timestamp last_drift = 7;

  // Kernel-wiring health signal (added PR 1, populated starting PR 3 when the
  // Registry Guard self-test probe lands). Lets the dashboard distinguish
  // "compliant because nothing's happening" from "silently deaf because the
  // subscription never plugged into the kernel." On agents predating PR 3 the
  // fields are default-constructed — consumers MUST treat default as
  // "status unknown," NOT as "guard unhealthy."
  bool guard_healthy = 8;
  google.protobuf.Timestamp last_notification = 9;
  uint64 notifications_total = 10;
}
```

### 7.2 Wire integration

Uses existing `CommandRequest` with reserved plugin name `__guard__`:

```
Server → Agent:  CommandRequest  { plugin: "__guard__", action: "push_rules", params: "<GuaranteedStatePush>" }
Agent → Server:  CommandResponse { plugin: "__guard__", action: "event", output: "<GuaranteedStateEvent>" }
Server → Agent:  CommandRequest  { plugin: "__guard__", action: "get_status" }
Agent → Server:  CommandResponse { plugin: "__guard__", action: "status", output: "<GuaranteedStateStatus>" }
```

---

## 8. Agent implementation

### 8.1 New source files

```
agents/core/src/guardian_engine.hpp            GuardianEngine (lifecycle, two-phase init)
agents/core/src/guardian_engine.cpp
agents/core/src/guard_manager.hpp           Guard instance management
agents/core/src/guard_manager.cpp
agents/core/src/guard_base.hpp              Abstract guard interface
agents/core/src/guard_registry.hpp/.cpp     Registry guard (Windows)
agents/core/src/guard_etw.hpp/.cpp          ETW guard (Windows)
agents/core/src/guard_wfp.hpp/.cpp          WFP guard (Windows)
agents/core/src/guard_scm.hpp/.cpp          SCM guard (Windows)
agents/core/src/guard_process.hpp/.cpp      Process guard — hybrid (Windows)
agents/core/src/guard_software.hpp/.cpp     Software freshness guard (Windows)
agents/core/src/guard_compliance.hpp/.cpp   Compliance timer guard (Windows)
agents/core/src/guard_wmi.hpp/.cpp          Generic WMI guard (Windows)
agents/core/src/guard_reconciliation.hpp/.cpp  Reconciliation guard
agents/core/src/state_evaluator.hpp/.cpp    Assertion evaluation
agents/core/src/remediation_engine.hpp/.cpp Corrective actions
agents/core/src/guard_audit.hpp/.cpp        Local audit journal
agents/core/src/assertion_types.hpp/.cpp    Assertion type registry
agents/core/src/resilience_strategy.hpp/.cpp  Persist/Backoff/Bounded (Escalation forward)
agents/core/src/race_detector.hpp/.cpp      Drift rate tracking
```

### 8.2 Key class interfaces

```cpp
namespace yuzu::agent {

class GuardBase {
public:
    virtual ~GuardBase() = default;
    virtual std::expected<void, std::string> start() = 0;
    virtual void stop() = 0;
    virtual std::string_view type() const noexcept = 0;
    virtual std::string_view rule_id() const noexcept = 0;
    virtual std::string_view category() const noexcept = 0;  // "event" | "condition"

    // Synchronous state read — used by reconciliation guard to check current
    // compliance without waiting for an OS notification. Every guard type must
    // implement this so reconciliation can evaluate all rules at startup and
    // on periodic sweeps without duplicating detection logic.
    virtual StateSnapshot read_current_state() = 0;

protected:
    void notify_change(StateSnapshot snapshot);
    StateEvaluator* evaluator_;
    std::atomic<bool> stop_requested_{false};
};

class GuardianEngine {
public:
    explicit GuardianEngine(KvStorage& kv,
                         std::function<void(GuaranteedStateEvent)> event_sink);
    std::expected<void, std::string> start_local();   // Phase 1
    void sync_with_server(CommsLayer& comms);          // Phase 2
    void stop();
    void apply_rules(const GuaranteedStatePush& push);
    GuaranteedStateStatus get_status() const;
    void set_enforcement_mode(std::string_view rule_id, std::string_view mode);
private:
    GuardManager manager_;
    StateEvaluator evaluator_;
    RemediationEngine remediator_;
    GuardAudit audit_;
    KvStorage& kv_;
    bool local_started_{false};
};

class ResilienceStrategy {
public:
    enum class Action { Retry, RetryAfter, Escalate, Open, Terminal };
    virtual Action on_remediation_result(bool success, steady_clock::time_point now) = 0;
    virtual Action on_race_detected(double drifts_per_second) = 0;
    virtual void reset() = 0;
    virtual std::chrono::milliseconds delay() const = 0;
};

} // namespace yuzu::agent
```

### 8.3 Threading model

**Event guards:** One thread each, blocked on user-mode wait handle. Near-zero CPU. Evaluator + remediator run synchronously on guard thread (no handoff latency). Threads must be created with explicit 64KB stack size (`_beginthreadex` with `stack_size` parameter or equivalent) — Windows default is 1MB per thread, which at 200 threads would consume 200MB instead of the intended ~12MB.

**Condition guards:** Share a timer thread pool (4 threads). Each guard registers a callback at its interval. Pool threads must call `CoInitializeEx(nullptr, COINIT_MULTITHREADED)` on startup — WMI Guard and Compliance Guard use COM via `IWbemServices::ExecQuery`, which fails with `0x800401F0` if COM is uninitialised.

**ETW session pooling:** Windows limits concurrent real-time ETW trace sessions (typically 64 system-wide, shared with Sysmon, Defender, EDR tools). The GuardManager must pool ETW subscriptions — multiple rules watching the same ETW provider share a single trace session, with the manager multiplexing incoming events to the appropriate rule's evaluator. Never create one ETW session per rule.

**SCM guard fan-out:** `NotifyServiceStatusChange` watches one service handle per call. A rule asserting "5 services must be running" requires 5 separate SCM watch handles. The GuardManager should consolidate: one SCM guard instance per unique service name, routing state change events to all rules that reference that service.

**Thread budget:** 100 rules × 2 event guards = 200 threads. With 64KB stacks: ~12MB. Condition guards share 4 pooled threads. 1 dedicated audit journal writer thread.

**Audit journal writer:** Guard threads do not write to SQLite directly — they enqueue events into a lock-free MPSC (multi-producer, single-consumer) queue. A dedicated writer thread drains the queue and batches inserts into the audit SQLite table. This avoids SQLite's single-writer lock becoming a bottleneck on the enforcement path.

### 8.4 Re-entrancy protection

Remediation sets per-rule `remediating_` atomic flag → guard suppresses evaluation during active remediation → flag clears after remediation + 5ms delay.

### 8.5 Resilience modes (enforcement retry policy)

> **Canonical vocabulary (decided 2026-06-01).** These three modes supersede the
> earlier `fixed | backoff | escalation` naming. `Backoff` keeps its meaning; the
> old `Fixed` is renamed **`Bounded`** and refined; **`Persist`** is new and is the
> default. `Escalation` is retained below as forward design but is **deferred for
> the MVP** — it terminates in quarantine (§11.7), a subsystem the MVP lacks.

> **Implementation status.** All three modes + the parameters below are wired
> **agent-side** (the guard reads them from `remediation.params`; absent → `Persist`
> + 1 s debounce, so existing rules are unchanged). **C3b landed** server-side:
> create/update validate + canonicalise the resilience params (mode-relevant bounds,
> lenient-in / canonical-out, A4 error envelope) and `GET /api/v1/guaranteed-state/schemas`
> publishes the type catalog incl. the resilience subschema — both driven by one
> param-spec table (`server/core/src/guardian_resilience_schema.{hpp,cpp}`), with a
> cross-check test binding its keys to the agent's `resilience_keys`. A structured
> `PUT` now re-authors the Guard (validates the new policy) instead of silently
> dropping the blocks. Still outstanding: the **dashboard form (C3c)** — until then,
> the modes are authored via the structured `remediation` block over REST, not the UI.
> `Escalation` remains post-MVP.

A resilience mode governs **what a guard does, in enforce mode, when the watched
state keeps drifting** — i.e. during an active fight with a competing writer. Modes
are **enforce-only**: an audit-mode guard always just detects and alerts, never
retries. They are **per-rule**, and **only `Persist` carries the sub-millisecond
enforcement guarantee** — the others trade latency or coverage for it by design.

- **`Persist`** *(default)* — re-enforce immediately on every drift; sub-ms; never
  give up. The agent's baseline "write the expected value back on every
  notification" behaviour. Best for high-value toggles that must be restored
  instantly, accepting CPU spent fighting a fast adversary.
- **`Backoff`** — exponential delay between re-enforcements (initial × 2^n, capped
  at max); never gives up. Trades enforcement latency for calm, bounding CPU/event
  churn against a noisy or transient adversary. Choosing it is an explicit opt-out
  of the sub-ms guarantee.
- **`Bounded`** — give up after **X consecutive re-fix cycles** in one ongoing
  fight. Each fix *succeeds* and the adversary immediately re-flips, so the counter
  tracks *cycles*, not *failures*. A quiet window of sustained compliance
  (`quiet_reset_s`) resets the counter, so a value that drifts once a month never
  creeps toward the cap over the guard's lifetime. On give-up the guard **stops
  writing, keeps detecting, and raises an alert** — it stays alive and observing
  (drift remains visible on the events stream) and stays given-up until an admin
  re-pushes / re-enables the rule. Optional `resume_after_s` re-arms remediation
  automatically (default off — give-up is a hand-off to a human).
- **`Escalation`** *(forward design, post-MVP)* — chain of methods (A → B → C →
  terminal action such as quarantine), each step with its own failure threshold,
  for critical rules wanting defence in depth.

**Configuration.** Mode and its parameters (`max_attempts`, `quiet_reset_s`,
`backoff_initial_ms`, `backoff_max_ms`, `resume_after_s`) plus the debounce windows
(§6.5) are authored per-rule and travel as string entries in the rule's
`remediation.params` map (input debounce in `spark.params`) — **no proto change**.
The agent reads them in `start_guard_for_rule_locked` (C3a). Server-side schema
validation + the `GET /schemas` discovery surface (`guardian-mvp-contract.md`
decisions 1 & 3) are C3b; the dashboard create/edit form is C3c. Rules that omit
them fall back to `Persist` + the default 1 s event-debounce, so the addition is
backward-compatible with no migration.

**Race detection** *(forward).* A sliding window over drift rate can adjust mode
behaviour under a flood (> N drifts / window): `Bounded` gives up immediately,
`Backoff` jumps straight to max delay. Optional for the MVP — `Bounded`'s
quiet-window reset already supplies basic rate-awareness.

---

## 9. Server implementation

### 9.1 New SQLite tables

```sql
CREATE TABLE guaranteed_state_rules (
    rule_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE,
    yaml_source TEXT NOT NULL, version INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1, enforcement_mode TEXT DEFAULT 'enforce',
    severity TEXT DEFAULT 'medium', os_target TEXT NOT NULL,
    scope_expr TEXT, signature BLOB,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);

CREATE TABLE guaranteed_state_events (
    event_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL,
    agent_id TEXT NOT NULL, event_type TEXT NOT NULL,
    severity TEXT NOT NULL, guard_type TEXT, guard_category TEXT,
    detected_value TEXT, expected_value TEXT,
    remediation_action TEXT, remediation_success INTEGER,
    detection_latency_us INTEGER, remediation_latency_us INTEGER,
    timestamp TEXT NOT NULL
);
-- Composite (column, timestamp DESC) indexes cover the three documented
-- filter paths combined with the `ORDER BY timestamp DESC` used by every
-- event query, so SQLite satisfies each common "events for rule X / agent Y /
-- severity Z, newest first" without filesort.
CREATE INDEX idx_gse_rule_time     ON guaranteed_state_events(rule_id, timestamp DESC);
CREATE INDEX idx_gse_agent_time    ON guaranteed_state_events(agent_id, timestamp DESC);
CREATE INDEX idx_gse_severity_time ON guaranteed_state_events(severity, timestamp DESC);
CREATE INDEX idx_gse_time          ON guaranteed_state_events(timestamp DESC);
```

### 9.2 REST API endpoints

```
POST   /api/v1/guaranteed-state/rules              Create rule
GET    /api/v1/guaranteed-state/rules              List rules
GET    /api/v1/guaranteed-state/rules/:id          Get rule
PUT    /api/v1/guaranteed-state/rules/:id          Update rule
DELETE /api/v1/guaranteed-state/rules/:id          Delete rule
POST   /api/v1/guaranteed-state/push               Push to agents
GET    /api/v1/guaranteed-state/status             Fleet compliance
GET    /api/v1/guaranteed-state/status/:agent_id   Agent compliance
GET    /api/v1/guaranteed-state/events             Query events
GET    /api/v1/guaranteed-state/alerts             Active alerts
```

**RBAC:** securable type `guaranteed_state` — admin/security_admin: all; operator: read+push; user: read.

### 9.3 Audit-chain reconstruction

`guaranteed_state_rules` carries two principal columns populated by the REST handler from the session:

- `created_by` — principal who first authored the rule.
- `updated_by` — principal who last modified it (incremented by `version`).

`guaranteed_state_events` has **no** principal column — events originate from agents, not operators — but every rule mutation in `/api/v1/guaranteed-state/rules` emits an `audit_events` row via the normal `audit_store` path. In a compromise scenario, reconstructing "which principal pushed the rule version that caused this remediation" is a three-hop join:

```sql
-- Given a remediation event, find the rule version in effect and the
-- principal who authored that version.
SELECT ev.event_id,
       ev.agent_id,
       ev.event_type,
       ev.timestamp         AS event_ts,
       r.rule_id,
       r.version,
       r.updated_by,
       a.principal          AS rest_actor,
       a.action             AS rest_action,
       a.timestamp          AS rest_ts
FROM   guaranteed_state_events ev
JOIN   guaranteed_state_rules  r  ON r.rule_id    = ev.rule_id
JOIN   audit_events            a  ON a.target_id  = r.rule_id
                                 AND a.target_type = 'guaranteed_state_rule'
                                 AND a.timestamp   <= ev.timestamp
WHERE  ev.event_id = :event_id
ORDER  BY a.timestamp DESC
LIMIT  1;
```

**Gotchas:**

1. `audit_store.retention_days` (default 365d) is longer than `guaranteed_state_events.retention_days` (default 30d), so the event→audit direction always works within the events' window. Operators raising the audit retention below 90d should raise it back for Guardian forensics.
2. `guaranteed_state_rules.version` is the authoritative identifier of which rule revision was active at event time — **not** `updated_at`. Version increments on every PUT (REST handler responsibility); `audit_events.detail` stores the pre/post YAML diff so the exact change can be reproduced.
3. The join uses `target_type = 'guaranteed_state_rule'` — the REST handler in PR 2 must emit audit rows with that exact literal for the join to find them. Adding a new mutation path (bulk import, CLI upload) is the moment the audit-type literal is most likely to drift; the integration test in PR 2 must pin it.
4. A deleted rule leaves events but no `guaranteed_state_rules` row — the join above returns zero rows. For deleted-rule forensics, start from `audit_events.action = 'guaranteed_state_rule.delete'` and trace backwards.

---

## 10. Dashboard design

The dashboard uses the existing HTMX paradigm (server-rendered HTML fragments).

### 10.1 Main page: `/guaranteed-state`

```
┌──────────────────────────────────────────────────────────────────┐
│  Guaranteed State                                    [+ New Rule]│
├──────────────────────────────────────────────────────────────────┤
│  Platform: [All ▼]  [W] 148 agents  [L] 30 agents  [M] 20 agents │
├──────────────────────────────────────────────────────────────────┤
│  ┌──────┐  ┌─────────┐  ┌───────┐  ┌──────┐  ┌──────────────┐    │
│  │  42  │  │   39    │  │   2   │  │   1  │  │ ████████░ 93%│    │
│  │ Rules│  │Compliant│  │Drifted│  │Errors│  │  Fleet comp. │    │
│  └──────┘  └─────────┘  └───────┘  └──────┘  └──────────────┘    │
├────────────────────────────┬─────────────────────────────────────┤
│  Rules                     │  Recent events                      │
│  ┌───────────────────────┐ │  ┌────────────────────────────────┐ │
│  │ ● block-smb-445   [W] │ │  │ 10:42  DRIFT REMEDIATED        │ │
│  │   Compliant · 148/148 │ │  │ block-smb-445 on DESKTOP-A3F   │ │
│  │   [event] HIGH        │ │  │ Port 445 opened → blocked 2ms  │ │
│  ├───────────────────────┤ │  ├────────────────────────────────┤ │
│  │ ● edr-agent-running[W]│ │  │ 10:41  DRIFT DETECTED          │ │
│  │   Compliant · 148/148 │ │  │ av-scan-7d on LAPTOP-B92       │ │
│  │   [hybrid] CRITICAL   │ │  │ Last scan 9d ago → triggered   │ │
│  ├───────────────────────┤ │  ├────────────────────────────────┤ │
│  │ ◐ ssh-no-root-login[L]│ │  │ 10:38  COMPLIANT               │ │
│  │   2 drifted · 28/30   │ │  │ edr-agent-running on SRV-DC01  │ │
│  │   [event] HIGH        │ │  │ CSFalconService.exe running ✓  │ │
│  ├───────────────────────┤ │  ├────────────────────────────────┤ │
│  │ ● macos-alf-on    [M] │ │  │ 10:35  RESILIENCE ESCALATED    │ │
│  │   Compliant · 20/20   │ │  │ block-smb-445 on DESKTOP-K7M   │ │
│  │   [event] HIGH        │ │  │ firewall-api → registry-write  │ │
│  └───────────────────────┘ │  └────────────────────────────────┘ │
│                            │                                     │
│  Legend:                   │  [Show all events →]                │
│  ● Compliant  ◐ Drifted    │                                     │
│  ◉ Alert      ○ Disabled   │                                     │
├────────────────────────────┴─────────────────────────────────────┤
│  Push policies     Scope: [________________________]  [Push Now] │
├──────────────────────────────────────────────────────────────────┤
│  Pending approvals (1)                                           │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ block-rdp-new-policy    Submitted by admin@corp 2m ago     │  │
│  │ action: enforce · scope: tag:workstations                  │  │
│  │ [View YAML]              [Approve]  [Reject]               │  │
│  └────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### 10.2 Rule detail page: `/guaranteed-state/rules/:id`

```
┌──────────────────────────────────────────────────────────────────┐
│  ← Back    block-smb-port-445                    [Edit] [Delete] │
├──────────────────────────────────────────────────────────────────┤
│  Description: Ensure SMB port 445 is blocked for inbound traffic │
│  Severity: HIGH    Mode: Enforce    OS: Windows                  │
│  Scope: tag:production-workstations AND NOT tag:file-servers     │
│  Tags: security, network, cis-benchmark-5.2.1                    │
│  Guards: Registry (primary), ETW (primary), Reconciliation       │
│  Assertion: firewall-port-blocked (TCP/445/inbound)              │
│  Resilience: Escalation (firewall-api → registry → wfp-api)      │
├──────────────────────────────────────────────────────────────────┤
│  Agent compliance                           148 compliant / 148  │
│  ┌────────────┬───────────┬────────────┬────────┬──────────────┐ │
│  │ Agent      │ Status    │ Last check │ Drifts │ Remediations │ │
│  ├────────────┼───────────┼────────────┼────────┼──────────────┤ │
│  │ DESKTOP-A3F│ Compliant │ 10:42:31   │ 3      │ 3            │ │
│  │ DESKTOP-K7M│ Compliant │ 10:35:14   │ 1      │ 1            │ │
│  │ LAPTOP-B92 │ Compliant │ 10:40:05   │ 0      │ 0            │ │
│  └────────────┴───────────┴────────────┴────────┴──────────────┘ │
├──────────────────────────────────────────────────────────────────┤
│  YAML source                                            [Copy]   │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ apiVersion: yuzu.io/v1alpha1                               │  │
│  │ kind: GuaranteedStateRule                                  │  │
│  │ ...                                                        │  │
│  └────────────────────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────┤
│  Event history (last 24h)                                        │
│  ┌──────────┬─────────────┬──────────────────┬─────────────────┐ │
│  │ Time     │ Agent       │ Event            │ Latency         │ │
│  ├──────────┼─────────────┼──────────────────┼─────────────────┤ │
│  │ 10:42:31 │ DESKTOP-A3F │ drift.remediated │ 2ms             │ │
│  │ 10:35:14 │ DESKTOP-K7M │ resilience.escal.│ 340ms           │ │
│  └──────────┴─────────────┴──────────────────┴─────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### 10.3 HTMX fragment endpoints

```
GET  /gs/fragment/summary                 Summary stats bar
GET  /gs/fragment/rules                   Rule list with badges
GET  /gs/fragment/rules?status=drifted    Filtered rule list
GET  /gs/fragment/events                  Event timeline (latest 20)
GET  /gs/fragment/events?rule_id=X        Events by rule
GET  /gs/fragment/events?severity=high    Events by severity
GET  /gs/fragment/rule-detail/:id         Rule detail panel
GET  /gs/fragment/rule-agents/:id         Agent compliance table
GET  /gs/fragment/rule-yaml/:id           YAML source
POST /gs/fragment/push                    Push (returns status)
POST /gs/fragment/rules                   Create rule
PUT  /gs/fragment/rules/:id              Update rule
DELETE /gs/fragment/rules/:id            Delete rule
GET  /gs/fragment/approvals              Pending approvals list
POST /gs/fragment/approvals/:id/approve  Approve (returns updated list)
POST /gs/fragment/approvals/:id/reject   Reject (returns updated list)
```

### 10.4 Key HTMX patterns

```html
<!-- Rule list item — click loads detail -->
<div hx-get="/gs/fragment/rule-detail/block-smb-445"
     hx-target="#detail-panel" hx-swap="innerHTML">

<!-- Event timeline — auto-refresh every 5s -->
<div hx-get="/gs/fragment/events" hx-trigger="every 5s"
     hx-target="#event-list" hx-swap="innerHTML">

<!-- Push button -->
<button hx-post="/gs/fragment/push" hx-include="#push-form"
        hx-target="#push-result" hx-swap="innerHTML">
```

---

## 11. Security considerations

### 11.1 Two-person integrity (dual authorization)

Rules with `action: enforce` or `action: quarantine` can modify endpoint state. A single compromised or malicious admin account deploying a harmful enforcement rule could affect the entire fleet. To prevent this, enforcement rules require approval from a second administrator before deployment.

**Approval flow:**
1. Admin A creates or modifies a rule and submits for deployment
2. Server checks: does this change result in a rule that can modify endpoint state?
   - New rule with `action: enforce` or `quarantine` → requires approval
   - Existing rule modified to escalate enforcement (e.g., `alert-only` → `enforce`, or changing `method` to something more aggressive, or widening `scope`) → requires approval
   - Modifying remediation `params` (e.g., changing the `command` string) → requires approval
3. If approval required: rule enters `pending_approval` state, visible to all admins on the dashboard
4. Admin B reviews the full YAML source (with diff against previous version for modifications) and approves or rejects
5. Admin B must be a **different principal** than Admin A (server enforces `approver != submitter`)
6. On approval: rule is pushed to agents. On rejection: rule is marked rejected with reason, audit logged
7. Both the submission and the approval/rejection are audit events

**Rules that bypass approval:**
- New rules with `action: alert-only` — passive detection only, cannot modify endpoints. Deployed immediately.
- Modifications that reduce enforcement scope (e.g., disabling a rule via `enabled: false` (MVP) or `enforce` → `disabled` (forward design), `enforce` → `audit`, narrowing scope expression). These make the system less aggressive, not more.

**Configurable controls:**
- Global setting: `require_approval_for_enforcement: true` (default true, can be disabled for dev/test environments)
- Emergency override: A `break_glass` flag that allows single-admin deployment when `require_approval_for_enforcement` is true. Generates a `critical` severity audit event: `"gs.break_glass_deployment"` with the principal, rule ID, and justification text. The justification is mandatory — the server rejects break-glass without a reason. This is for genuine emergencies only (e.g., active security incident requiring immediate fleet-wide lockdown).

**Dashboard integration:** Pending approvals appear in the Guaranteed State dashboard with the full YAML source, the submitting admin's identity, and approve/reject buttons. The existing ApprovalManager (used by MCP tier-based approvals) is extended to handle guaranteed state rules.

**REST API:**
```
GET    /api/v1/guaranteed-state/approvals              List pending approvals
POST   /api/v1/guaranteed-state/approvals/:id/approve  Approve (requires different principal)
POST   /api/v1/guaranteed-state/approvals/:id/reject   Reject (with reason)
```

### 11.2 Policy signing

Rules are HMAC-SHA256 signed by the server before distribution. The agent validates signatures before activation.

**Key distribution:** The HMAC signing key is derived during agent enrollment using HKDF (RFC 5869) with the following inputs: the server's signing secret (generated at first run, stored in `yuzu-server.cfg`), the agent's unique `agent_id`, and a fixed context string `"guaranteed-state-rule-signing"`. This produces a per-agent key that is never transmitted over the wire — both the server and agent can derive it independently from the shared enrollment context. The agent stores the derived key in the OS credential store, not in the SQLite database:
- **Windows:** Windows Credential Store via `CredWrite` with `CRED_TYPE_GENERIC`
- **Linux:** Kernel keyring via `add_key()`/`keyctl()`, or file at `/var/lib/yuzu/.guardian-key` with mode 0600 owned by root
- **macOS:** Keychain via `SecItemAdd` with `kSecClassGenericPassword`

### 11.3 Remediation sandboxing

Fixed set of methods. `command` validates executed command matches the template from rule definition exactly — no arbitrary injection. `method: auto` derives fixes from a hardcoded mapping per assertion type — no user-supplied commands.

### 11.4 Anti-tampering

The agent process runs with elevated privileges (Windows: SYSTEM, Linux: root with capabilities, macOS: root via LaunchDaemon). SQLite is protected by OS-level access controls (Windows: ACLs, Linux/macOS: file mode 0600 owned by root). Guard watchdog restarts crashed threads. `guard.error` events on failures.

### 11.5 Process signature verification

Optional verification of monitored process binaries to prevent substitution attacks:
- **Windows:** `WinVerifyTrust` (Authenticode certificate chain)
- **Linux:** SHA-256 hash comparison against allowlist in rule params (or `fsverity` on kernel 5.4+)
- **macOS:** `SecStaticCodeCheckValidity` (Apple code signing chain)

### 11.6 Audit integrity

Sequential event IDs, timestamps, and HMAC integrity hashes. Server validates sequence continuity on sync — gaps indicate tampering or data loss. All approval/rejection decisions are audit events.

### 11.7 Quarantine action

When a rule specifies `action: quarantine` or a resilience chain reaches `on_exhausted: quarantine`, the agent isolates the endpoint from the network while preserving management connectivity.

**Behaviour:** The agent installs a firewall-level block-all rule with a single exception: the Yuzu gateway connection (by IP and port, already known from enrollment configuration). All other traffic is blocked, including DNS (UDP/TCP 53).

**Why DNS is blocked:** DNS is one of the most common data exfiltration and C2 channels. An attacker on a quarantined machine with DNS access can tunnel arbitrary data out via DNS TXT/CNAME queries to attacker-controlled domains. Blocking DNS completely closes this vector.

**Platform implementation:**
- **Windows:** WFP filter at weight 65535 (highest priority). `FwpmFilterAdd0` with `FWP_ACTION_BLOCK` for all traffic, paired with `FWP_ACTION_PERMIT` for the Yuzu gateway IP/port. WFP filters survive process restarts and persist until explicitly removed.
- **Linux:** nftables chain with priority -200 (before other chains). `libnftnl` inserts a drop-all rule with `accept` for the Yuzu gateway. If iptables-legacy, uses `libiptc` to insert equivalent rules at the top of INPUT/OUTPUT chains.
- **macOS:** pf anchor with block-all rules. `DIOCADDRULE` ioctl with `PF_DROP` for all traffic, `PF_PASS` for the Yuzu gateway. The anchor ensures quarantine rules don't interfere with other pf rules.

**Yuzu gateway connection:** The agent already holds the gateway IP from enrollment configuration (cached locally). If the agent was originally configured with a hostname, the resolved IP is cached in the local config at first successful connection. No DNS resolution is needed during quarantine.

**Quarantine exceptions YAML — static (defined at rule creation time):**

Rules can pre-define exceptions that always apply when quarantine activates. These are for predictable, standing exceptions that every quarantined machine should have:

```yaml
remediation:
  action: quarantine
  quarantine_exceptions:
    - ip: 10.0.0.5                      # On-prem EDR collector — always allowed
      port: 8443
      protocol: TCP
      reason: "EDR telemetry upload to on-prem collector"
```

**Runtime quarantine management via instructions:**

Adding exceptions, removing exceptions, and lifting quarantine are performed via Yuzu instructions — but the instruction updates Guardian's desired state rather than bypassing it. Guardian remains the sole enforcer at all times. This means:

- Guardian monitors quarantine firewall rules the same way it monitors everything else
- If a bad actor with local admin/root adds an unauthorised permit rule, Guardian detects the drift and removes it
- Only the Yuzu instruction delivery chain (gRPC, HMAC-signed, instruction tier approval) can modify what Guardian enforces
- There is no unmonitored firewall layer

The agent registers three instruction handlers under the `__guard__` plugin:

```
quarantine.add_exception    Update Guardian's desired state to include an additional permitted IP
quarantine.remove_exception Update Guardian's desired state to remove a previously added exception
quarantine.lift             Clear quarantine state and reset resilience strategy, restoring normal enforcement
```

**Server-side DNS resolution for exceptions:**

Both static (YAML) and runtime (instruction) exceptions support hostnames. The endpoint never resolves them — the server resolves hostnames to IPs before delivery (at policy push time for static exceptions, at instruction delivery time for runtime exceptions) and sends only IPs to the agent:

```
Operator writes:                              Agent receives (no DNS needed):
  host: av-updates.vendor.com                   ip: 203.0.113.45, port: 443, protocol: TCP
  port: 443, protocol: TCP                      ip: 203.0.113.46, port: 443, protocol: TCP
```

The server periodically re-resolves exception hostnames (default: every 300s) and pushes updated IP lists to quarantined agents via follow-up instructions. For CDN-backed services where IPs rotate frequently, the re-resolution interval can be reduced per-exception.

**How the update works (no monitoring gap):**

When an instruction arrives, the GuardianEngine performs an atomic update to the active rule's desired state. The guard thread is never stopped — it continues monitoring throughout:

1. Instruction arrives on the gRPC thread
2. GuardianEngine writes the updated desired state to the SQLite policy cache
3. GuardianEngine atomically swaps the in-memory desired state pointer for the active rule (old → new, with the exception IP added)
4. GuardianEngine applies the new exception firewall rule immediately (the new desired state includes the IP but the current firewall state doesn't — Guardian treats this as drift and remediates by adding the permit rule)
5. The guard thread was never stopped. It reads the desired state pointer on every evaluation — before the swap it enforces the old state, after the swap it enforces the new state. No intermediate state, no monitoring gap.

The worst-case race is: the guard fires between steps 2 and 3 (SQLite updated, pointer not yet swapped). One evaluation runs against the old desired state, which simply means the exception takes effect one cycle later — milliseconds at most. The quarantine block-all is enforced throughout.

**Workflow via dashboard or MCP:**

```
1. Guardian activates quarantine on DESKTOP-A3F
   → Agent blocks all traffic except Yuzu gateway
   → Dashboard shows quarantined status

2. Operator sends instruction: quarantine.add_exception
   Target: DESKTOP-A3F
   Params: { host: "av-updates.vendor.com", port: 443, protocol: "TCP",
             reason: "AV definition update for incident IR-2024-0891" }
   → Server resolves hostname to IPs [203.0.113.45, 203.0.113.46]
   → Instruction delivered to agent with resolved IPs
   → GuardianEngine atomically updates desired state to include those IPs
   → Guardian applies the permit rules as remediation of the "missing exception" drift
   → Server schedules periodic re-resolution (default 300s)
     and pushes updated IPs via follow-up instructions

3. Operator triggers AV scan via separate Yuzu instruction
   → Scan runs, results upload via the exception

4. Bad actor on the machine tries to add their own permit rule for a C2 server
   → Guardian detects the unauthorised rule as drift from desired state
   → Guardian removes it immediately

5. Operator sends instruction: quarantine.lift
   Target: DESKTOP-A3F
   Params: { reason: "Incident IR-2024-0891 resolved, root cause remediated" }
   → GuardianEngine clears quarantine state from policy cache
   → GuardianEngine resets the resilience strategy for the triggering rule to step 1
   → Guardian removes all quarantine firewall rules
   → Normal enforcement resumes with a fresh escalation chain
```

**Resilience reset on quarantine lift:** When `quarantine.lift` is received, the resilience strategy for the rule that triggered the quarantine is reset to its initial state (step 1, zero failure count). Without this, the exhausted failure counter would cause the next drift detection to immediately re-quarantine, bypassing the full escalation chain. The reset gives the operator's remediation a chance to hold — if the root cause was genuinely fixed, the rule stays compliant. If drift recurs, it escalates through the full chain again rather than jumping straight back to quarantine.

**Instruction approval:** These instructions use the existing Yuzu instruction approval tiers (separate from Guardian's two-person policy approval, and faster). `quarantine.add_exception` and `quarantine.lift` should be configured as requiring approval. `quarantine.remove_exception` can be lower-tier since it reduces access.

**Why instructions that update Guardian, not direct policy edits:** Policy modifications go through the two-person approval flow, which adds delay during an active incident. Instructions are faster (separate approval tier system), but by routing them through GuardianEngine's desired state, the instruction never bypasses enforcement. The instruction is the delivery mechanism; Guardian is always the enforcer.

**Quarantine is a terminal state** — once activated, it persists until an administrator explicitly lifts it. The agent does not auto-unquarantine even if the underlying rule becomes compliant, because quarantine typically indicates a sustained compromise attempt that warrants human investigation.

**Audit:** Quarantine activation and deactivation are `critical` severity audit events. Exception additions and IP re-resolution updates are `high` severity events.

### 11.8 Rule conflict detection

The server checks for assertion conflicts when a new rule is created or modified. If two rules watch the same resource with contradictory assertions (e.g., rule A says port 445 must be blocked, rule B says port 445 must be open), both rules would fight each other — each remediation triggers the other rule's drift detection, creating a remediation loop.

**Detection:** At rule creation/modification time, the server compares the new rule's assertion against all existing active rules. Conflicts are identified by matching the assertion type and key parameters (port+protocol for firewall rules, registry path+value name for registry rules, config file path+key for config assertions, service name for service rules).

**Behaviour:** The server rejects the conflicting rule with a clear error message identifying the existing rule it conflicts with. If the operator intends to replace the existing assertion, they must modify or delete the existing rule first. The two-person integrity approval process provides an additional check — the reviewing administrator can spot logical conflicts that automated detection might miss.

### 11.9 Config file remediation and service reload

When the agent modifies a config file (e.g., writing `PermitRootLogin no` to `/etc/ssh/sshd_config`), the file on disk is correct but the running service still uses its old configuration. The system reports "compliant" based on file content, but the running behaviour hasn't changed until the service reloads.

**Optional `post_remediation` hook:** Rules that modify config files can specify a service reload action:

```yaml
remediation:
  action: enforce
  method: auto
  post_remediation:
    reload_service: sshd          # Send SIGHUP to the service after successful remediation
    # On Linux: kill(pid, SIGHUP) or D-Bus ReloadUnit
    # On macOS: kill(pid, SIGHUP)
    # On Windows: not applicable (registry changes take effect immediately)
```

If `post_remediation` is not specified, the agent enforces file content only. This is the safe default — some config changes require a full service restart rather than a reload, and the agent should not restart production services without explicit operator intent.

**Validation:** For config file formats where validation is possible, the agent can optionally validate the modified config before writing. This is specified per-format:
- `sshd` format: Run `sshd -t -f /path/to/temp_config` before atomic rename (uses `command` internally)
- Other formats: Syntactic validation only (valid INI, valid JSON, valid YAML)

---

## 12. Implementation plan

| Phase | Scope | Files |
|-------|-------|-------|
| **A. Core framework** | GuardianEngine, PolicyCache, GuardManager, StateEvaluator, RemediationEngine, AuditJournal | `guardian_engine.*`, `guard_manager.*`, `state_evaluator.*`, `remediation_engine.*`, `guard_audit.*` |
| **B. Event guards** | RegistryGuard + re-entrancy protection | `guard_registry.*` |
| **C. Core assertions** | `firewall-port-blocked`, `registry-value-equals`, `service-disabled`, `service-running` | `assertion_types.*` |
| **D. Resilience** | Persist, Backoff, Bounded modes (Escalation forward); race detector | `resilience_strategy.*`, `race_detector.*` |
| **E. Core remediation** | `registry-write`, `firewall-api`, `service-control` | `remediation_engine.cpp` |
| **F. Condition guards** | ProcessGuard, SoftwareGuard, ComplianceGuard, WMIGuard | `guard_process.*`, `guard_software.*`, `guard_compliance.*`, `guard_wmi.*` |
| **G. Condition assertions** | `process-running`, `software-updated-within`, `av-scan-within`, `wmi-value-equals` | `assertion_types.cpp` |
| **H. Wire integration** | `__guard__` handler, push/pull, event reporting, offline sync | Agent dispatch, `guaranteed_state.proto` |
| **I. ETW+WFP+SCM guards** | Additional event guard types | `guard_etw.*`, `guard_wfp.*`, `guard_scm.*` |
| **J. Server store+API** | GuaranteedStateStore, REST endpoints, RBAC | `guaranteed_state_store.*`, `rest_api_v1.cpp` |
| **K. Dashboard** | HTMX pages, fragments, rule editor | `dashboard_guaranteed_state.*` |
| **L. MCP tools** | Read-only fleet compliance tools | `mcp_server.cpp` |
| **M. Hardening** | Signing, anti-tamper, audit integrity, signature verification | Cross-cutting |
| **M2. Quarantine** | Quarantine firewall layer (WFP/nftables/pf), instruction handlers (`quarantine.add_exception`/`remove_exception`/`lift`), server-side DNS resolution, atomic desired-state updates, resilience reset | `quarantine_manager.*`, instruction handlers in `guardian_engine.*` |

### 12.1 Modified existing files

```
agents/core/src/agent.cpp              Add GuardianEngine two-phase init
agents/core/meson.build                Add new sources
proto/yuzu/guardian/v1/                Add guaranteed_state.proto
proto/meson.build                      Add to codegen
server/core/src/rest_api_v1.cpp/.hpp   Add endpoints
server/core/src/server.cpp             Add store init + dashboard routes
server/core/src/mcp_server.cpp         Add MCP tools
server/core/meson.build                Add new sources
docs/user-manual/guaranteed-state.md   New manual section
docs/yaml-dsl-spec.md                  Add GuaranteedStateRule kind
content/definitions/                   Example YAML files
```

---

## 13. Cross-platform design

### 13.1 Design principle

Yuzu Guardian must feel identical to use across Windows, Linux, and macOS. An operator writes a `GuaranteedStateRule` YAML once, sets `target.os` (or omits it for all platforms), and the system selects the correct guards and remediation methods for each platform automatically.

The abstraction layers:

```
Operator experience (identical across platforms)
    │
    ├── YAML DSL — same schema, same assertion types, same remediation actions
    ├── Dashboard — same compliance view, same events, same approval workflow
    ├── REST API — same endpoints, same response format
    └── MCP tools — same queries, same output
    │
Platform abstraction boundary
    │
    ├── Guard selection — GuardManager picks platform-appropriate guards
    ├── Assertion evaluation — same logic, platform-specific state readers
    └── Remediation execution — same action names, platform-specific system calls
```

### 13.2 Platform-specific reality

While the universal assertion types handle common cases, many real-world rules are inherently platform-specific. An operator who wants "SSH must use key-based auth only" writes:

- **Linux:** `config-value-equals` targeting `/etc/ssh/sshd_config` with `key: PasswordAuthentication, expected: "no"`
- **Windows:** `registry-value-equals` targeting the OpenSSH registry key, or a Group Policy setting

These are different rules with different assertion types, different paths, and different value formats. The *intent* is the same but the *implementation* is inherently tied to how each OS stores configuration. The YAML DSL handles this naturally — platform-specific assertion types exist alongside universal ones, the `target.os` field makes the platform explicit, and the server rejects mismatches at creation time.

Operators managing mixed fleets will inevitably maintain some Windows-only and some Linux-only rules. The dashboard, compliance reporting, and approval workflow are identical regardless — the platform-specific element is limited to the YAML rule content.

### 13.3 Cross-platform gap analysis

Functional gaps exist between Windows, Linux, and macOS. These are inherent to OS paradigm differences and cannot be fully closed by the abstraction layer. The Windows-vs-Linux gaps are documented here; see Section 21.1 for the full three-platform comparison table including macOS.

**Gap 1 — Change detail granularity:**
Windows ETW tells you exactly WHAT changed (which firewall rule, which process modified it). Linux inotify tells you only THAT a file changed — the agent must re-read the file and diff against previous state to determine what changed. This adds microseconds to hundreds of microseconds to the Linux enforcement path depending on file size. The Linux Audit Guard provides syscall-level detail (which process wrote to which file) but not semantic content (which config key was changed). This gap is inherent to the filesystem-vs-registry paradigm.

**Gap 2 — No unified system query interface:**
Windows WMI provides a SQL-like query interface across thousands of system properties. Linux has no equivalent — system state is scattered across `/proc`, `/sys`, D-Bus, package databases, and log files, each with a different access method. The WMI Guard has no single Linux equivalent. Partial mitigation: a generic file-read guard for `/proc` and `/sys` values, plus the D-Bus Guard for systemd properties.

**Gap 3 — Process signature verification model:**
Windows has OS-level code signing (Authenticode) with certificate chain validation via `WinVerifyTrust`. Linux has no equivalent standard. The Linux design uses SHA-256 hash pinning against an allowlist — stronger (trusts exact binary) but higher maintenance (hashes change on every update). Operators should understand this difference when writing `process-running` rules with `verify_signature`.

**Gap 4 — Firewall backend complexity:**
Windows has one firewall API (`INetFwPolicy2` COM). Linux has two competing backends (nftables with real-time netlink notifications, legacy iptables with NO change notifications). The agent must auto-detect and use the correct backend. On iptables-legacy systems, firewall changes can only be detected by periodic polling — there is no real-time event-driven path. This is a latency regression compared to Windows for iptables-legacy environments.

**Areas where Linux is stronger:**
- Config file assertion with format-aware parsing (`sshd`, `ini`, `key-value`, `yaml`, `json`) — more flexible than registry for certain use cases
- SELinux/AppArmor enforcement — no Windows equivalent
- Granular capabilities (`CAP_NET_ADMIN`, `CAP_AUDIT_CONTROL`) — finer-grained than Windows "run as SYSTEM"
- Kernel parameter enforcement via sysctl — direct, discoverable kernel tuning

### 13.4 Cross-platform assertion types

Assertions fall into three categories:

**Universal assertions** — work on all platforms with platform-specific backends:

| Assertion | Windows backend | Linux backend | macOS backend |
|-----------|----------------|---------------|---------------|
| `service-running` | SCM `QueryServiceStatus` | systemd D-Bus `ActiveState` property | launchd `SMJobCopyDictionary` |
| `service-stopped` | SCM `QueryServiceStatus` | systemd D-Bus `ActiveState` property | launchd |
| `service-disabled` | Registry `Start` DWORD | systemd D-Bus `UnitFileState` property | launchd plist absence |
| `process-running` | ETW + ToolHelp32 | netlink proc connector + `/proc` | Endpoint Security + `proc_listpids` |
| `process-not-running` | ETW + ToolHelp32 | netlink + `/proc` | Endpoint Security + `proc_listpids` |
| `firewall-port-blocked` | Registry + WFP | nftables netlink | pf `/dev/pf` ioctl |
| `software-updated-within` | Registry Uninstall keys | dpkg/rpm database | pkgutil / Homebrew |
| `software-version-minimum` | Registry Uninstall keys | dpkg/rpm database | pkgutil / Homebrew |
| `av-scan-within` | WMI Defender | ClamAV/vendor logs | XProtect/vendor logs |
| `file-permissions` | NTFS ACLs via `GetSecurityInfo` | `stat()` | `stat()` |

**Platform-specific assertions** — only available on one OS:

| Assertion | Platform | Description |
|-----------|----------|-------------|
| `registry-value-equals` | Windows | Registry value must equal specific value |
| `registry-value-absent` | Windows | Registry key/value must not exist |
| `registry-value-range` | Windows | DWORD within min/max |
| `rdp-disabled` | Windows | Shorthand for fDenyTSConnections=1 |
| `smb-v1-disabled` | Windows | Shorthand for SMBv1 feature disabled |
| `sysctl-value-equals` | Linux | `/proc/sys/*` parameter must equal value |
| `config-value-equals` | Linux / macOS | Key=value in a config file must match |
| `config-line-present` | Linux / macOS | A config file must contain a specific line |
| `config-line-absent` | Linux / macOS | A config file must NOT contain a line |
| `selinux-enforcing` | Linux | SELinux must be in enforcing mode |
| `plist-value-equals` | macOS | Property list value must match |

**Server validates platform compatibility:** If a rule has `target.os: linux` but uses `registry-value-equals`, the server rejects it at creation time with a clear error. If `target.os` is omitted, the server infers the platform from the assertion type: platform-specific assertions (e.g., `registry-value-equals`) implicitly set the OS target. Universal assertions with no `target.os` deploy to all platforms. If inference is ambiguous, the server requires `target.os` to be explicit.

### 13.5 Auto-guard selection

The `guards:` block in the YAML is **optional**. If omitted, the GuardManager automatically selects the optimal guards for the target platform based on the assertion type:

```yaml
# Operator writes this — no guards: block needed:
spec:
  target:
    os: linux
  assertion:
    type: service-running
    params: { service_name: sshd }
  remediation:
    action: enforce
    method: auto

# GuardManager automatically selects:
#   - D-Bus Guard watching org.freedesktop.systemd1 for sshd.service state changes (primary)
#   - Reconciliation Guard with 60s interval (backup)
```

Auto-selection mapping:

| Assertion type | Windows auto-guards | Linux auto-guards | macOS auto-guards |
|---|---|---|---|
| `service-running/stopped/disabled` | SCM + Registry | D-Bus systemd | Endpoint Security exec/exit + poll |
| `firewall-port-blocked` | Registry + ETW firewall | Netfilter netlink | ES pfctl intercept + file watch + ioctl poll |
| `process-running/not-running` | ETW Kernel-Process + poll | Netlink proc connector + `/proc` poll | Endpoint Security exec/exit + `proc_listpids` poll |
| `registry-value-*` | Registry | N/A | N/A |
| `sysctl-value-equals` | N/A | Audit + poll | N/A |
| `config-value-equals` | N/A | inotify on config file | Endpoint Security / FSEvents on config file |
| `plist-value-equals` | N/A | N/A | Endpoint Security / FSEvents on plist file |
| `software-updated-within` | Poll (Software Guard) | Poll (Package Guard) | Poll (Package Guard) |
| `av-scan-within` | Poll (Compliance Guard) | Poll (Compliance Guard) | Poll (Compliance Guard) |
| `selinux-enforcing` | N/A | Audit + inotify | N/A |

If the operator specifies `guards:` explicitly, auto-selection is skipped and their guards are used. This allows advanced users to tune detection for their specific environment.

---

## 14. Platform remediation APIs (system calls only)

Yuzu Guardian remediation **never shells out to command-line tools**. All automatic remediation actions use direct system calls via platform-native libraries. This is faster (no process creation), more secure (no command injection), more reliable (no dependency on CLI tools), and less observable (no child process spawning).

The `command` remediation method exists as an escape hatch for operators who need custom actions, but `method: auto` and all built-in methods use system calls exclusively.

### 14.1 Windows remediation APIs

| Method | DLL | System calls | NOT this |
|--------|-----|-------------|----------|
| `registry-write` | `advapi32.dll` | `RegSetValueExW`, `RegDeleteValueW`, `RegDeleteKeyExW` | NOT `reg.exe add` |
| `registry-delete` | `advapi32.dll` | `RegDeleteValueW`, `RegDeleteKeyExW` | NOT `reg.exe delete` |
| `firewall-api` | `FirewallAPI.dll` | `INetFwPolicy2::get_Rules()` → `Add()` / `Remove()` (COM) | NOT `netsh advfirewall` |
| `wfp-api` | `fwpuclnt.dll` | `FwpmFilterAdd0`, `FwpmFilterDeleteById0` | NOT `netsh wfp` |
| `service-control` | `advapi32.dll` | `OpenServiceW`, `StartServiceW`, `ControlService`, `ChangeServiceConfigW` | NOT `sc.exe` or `net start` |
| `restart-process` | `kernel32.dll` | `CreateProcessW` (with process path from rule params) | NOT `cmd /c start` |
| `stop-process` | `kernel32.dll` | `OpenProcess` + `TerminateProcess` | NOT `taskkill.exe` |
| `sysctl` (Windows) | N/A | Not applicable on Windows | |

**COM initialization:** Methods using COM (`firewall-api`) require the calling thread to have called `CoInitializeEx`. The remediation engine initialises COM on first use per thread.

**Elevated operations:** All calls execute in the SYSTEM context (the agent's service account), which has sufficient privileges for all listed operations.

### 14.2 Linux remediation APIs

| Method | Library | System calls | NOT this |
|--------|---------|-------------|----------|
| `service-control` | `libsystemd` (`sd_bus_*`) | D-Bus call: `org.freedesktop.systemd1.Manager.StartUnit` / `StopUnit` / `DisableUnitFiles` / `EnableUnitFiles` | NOT `systemctl start` |
| `firewall-rule` | `libmnl` + `libnftnl` | netlink `NFNL_SUBSYS_NFTABLES` messages to add/delete nftables rules | NOT `nft add rule` or `iptables -A` |
| `sysctl-write` | libc | `open("/proc/sys/net/ipv4/ip_forward")` + `write("0")` | NOT `sysctl -w` |
| `config-write` | libc | `open()` + `write()` + `fsync()` + `rename()` (atomic write-to-temp-then-rename) | NOT `sed -i` |
| `file-permissions` | libc | `chmod()`, `chown()`, `fchmodat()` | NOT `chmod` CLI |
| `restart-process` | libc | `fork()` + `execve()` (with process path from rule params) | NOT `bash -c` |
| `stop-process` | libc | `kill(pid, SIGTERM)`, escalate to `SIGKILL` after timeout | NOT `kill` CLI or `killall` |
| `selinux-set` | `libselinux` | `security_setenforce(1)` | NOT `setenforce 1` |
| `service-reload` | `libsystemd` | D-Bus `ReloadUnit` or `kill(pid, SIGHUP)` for non-systemd services | NOT `systemctl reload` |

**Atomic config file writes:** The `config-write` method writes to a temporary file in the same directory, calls `fsync()`, then `rename()` over the original. This ensures the config file is never in a partially-written state, even if the agent crashes mid-write. The temporary file inherits the original's permissions and ownership via `fchmod()` + `fchown()` before the rename.

**Firewall abstraction:** Linux has two active firewall backends — nftables (modern, kernel 3.13+) and iptables-legacy. The `firewall-rule` method auto-detects which is in use at Guardian engine startup by attempting a netlink query to the `NFNL_SUBSYS_NFTABLES` kernel subsystem. If the kernel responds, nftables is active and the agent uses `libnftnl`. If the kernel returns `EPROTONOSUPPORT` or `ENOENT`, nftables is not available and the agent falls back to `libiptc` for iptables-legacy. This detection is cached for the lifetime of the agent process. File-presence checks (e.g., `/usr/sbin/nft`) are not used because a system can have nft installed but be running iptables-legacy.

---

## 15. Linux guard types — detailed

### 15.1 Event Guards (real-time)

#### 15.1.1 inotify Guard

The Linux equivalent of the Windows Registry Guard. Watches files and directories for modifications using the kernel's `inotify` subsystem.

```cpp
void InotifyGuard::watch_loop() {
    int inotify_fd = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
    int watch_fd = inotify_add_watch(inotify_fd, path_.c_str(),
        IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO);

    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = inotify_fd };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, inotify_fd, &ev);

    // stop_fd_ is a member eventfd, created in start(), signalled by stop()
    struct epoll_event stop_ev = { .events = EPOLLIN, .data.fd = stop_fd_ };
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, stop_fd_, &stop_ev);

    while (!stop_requested_) {
        struct epoll_event events[2];
        int n = epoll_wait(epoll_fd, events, 2, -1);

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == inotify_fd) {
                // Drain inotify events
                char buf[4096];
                read(inotify_fd, buf, sizeof(buf));
                // Read current file state and evaluate
                auto state = read_current_state();
                evaluator_->evaluate(rule_id_, std::move(state));
            }
        }
    }
    close(inotify_fd);
    close(epoll_fd);
}
```

**Applicable rules:** Config file changes (`/etc/ssh/sshd_config`, `/etc/sysctl.conf`, `/etc/fstab`, `/etc/pam.d/*`), SELinux policy files, firewall config files, cron files, sudoers.

**Latency:** ~0ms (kernel delivers inotify events synchronously).

**inotify limits:** The system-wide inotify watch limit (`/proc/sys/fs/inotify/max_user_watches`, default 8192) may need to be increased for deployments with many watched paths. The Guardian engine should check this limit at startup and log a warning if it's close to exhaustion.

**Atomic rename detection:** Many config management tools (Ansible, Puppet, Salt) write config files atomically via write-to-temp + `rename()`. The `IN_MOVED_TO` flag catches the rename. However, `inotify` watches are on inodes, not paths — after a rename replaces the watched file, the watch may point to the old inode. The guard must re-add the watch on the new inode after detecting a `IN_MOVED_TO` or `IN_DELETE_SELF` event. This is the same pattern used by `tail -F`.

#### 15.1.2 Netlink Guard

Monitors kernel networking state changes in real-time via netlink sockets. Covers routing table changes, network interface state, and netfilter rule modifications.

**Netlink families used:**

| Family | Purpose | Events |
|--------|---------|--------|
| `NETLINK_ROUTE` | Interface up/down, IP address changes, routing table | `RTM_NEWADDR`, `RTM_DELADDR`, `RTM_NEWLINK`, `RTM_DELLINK` |
| `NETLINK_NETFILTER` (via `NFNL_SUBSYS_NFTABLES`) | nftables rule changes | `NFT_MSG_NEWRULE`, `NFT_MSG_DELRULE`, `NFT_MSG_NEWCHAIN` |
| `NETLINK_CONNECTOR` (proc connector) | Process start/stop | `PROC_EVENT_FORK`, `PROC_EVENT_EXEC`, `PROC_EVENT_EXIT` |

**Implementation:** A single netlink socket per family, using `epoll` for multiplexing. The GuardManager pools netlink subscriptions — multiple rules watching the same family share a socket, with the manager dispatching events to the appropriate rule's evaluator.

**Latency:** ~0ms (kernel delivers netlink messages synchronously).

**Capabilities required:** The agent process requires `CAP_NET_ADMIN` for `NETLINK_NETFILTER` and `CAP_NET_ADMIN` for `NETLINK_ROUTE` multicast groups. The proc connector requires root or `CAP_NET_ADMIN`. These are set via systemd's `AmbientCapabilities` directive in the service unit file.

#### 15.1.3 D-Bus Guard (systemd)

Monitors systemd unit state changes in real-time via the D-Bus system bus. The Linux equivalent of the Windows SCM Guard.

**Implementation:** Subscribes to `org.freedesktop.systemd1.Manager` signals:
- `UnitNew` / `UnitRemoved` — unit added/removed
- `JobNew` / `JobRemoved` — job (start/stop/restart) completed
- Property changes on specific unit objects via `PropertiesChanged` signal

Uses `libsystemd`'s `sd_bus_add_match()` to filter for specific unit names (e.g., `sshd.service`), so the guard only wakes for relevant events.

```cpp
void DbusGuard::watch_loop() {
    sd_bus* bus = nullptr;
    sd_bus_open_system(&bus);

    // Subscribe to state changes for the specific service
    sd_bus_match_signal(bus, nullptr,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
        "JobRemoved",
        on_job_removed, this);

    while (!stop_requested_) {
        sd_bus_wait(bus, UINT64_MAX);
        sd_bus_process(bus, nullptr);
    }
    sd_bus_unref(bus);
}
```

**Latency:** ~1–5ms (D-Bus message delivery).

**Non-systemd fallback:** For systems without systemd (Alpine, older distros, containers), the D-Bus guard is unavailable. The guard manager falls back to polling `/proc/<pid>/status` for process-based service monitoring.

#### 15.1.4 Audit Guard

Uses the Linux Audit subsystem (`auditd`) for syscall-level monitoring. The Linux equivalent of Windows ETW for security-sensitive operations.

**Implementation:** Uses `libaudit` to add audit rules programmatically via `audit_add_rule_data()`, then reads events from the audit netlink socket.

**Example audit rules:**
- Watch a file for writes: `audit_add_watch(&rule, "/etc/ssh/sshd_config", AUDIT_PERM_WRITE)`
- Watch a syscall: `audit_rule_syscall_data(rule, __NR_sethostname)` — detects hostname changes

**Latency:** ~1ms.

**Interaction with auditd:** If `auditd` is running, the guardian's audit rules coexist with existing rules. The guardian uses a unique audit key prefix (`yuzu_guardian_`) so its rules can be identified and cleaned up on shutdown. If `auditd` is not running, the guardian can still read audit events directly from the kernel via the netlink socket.

**Capabilities required:** `CAP_AUDIT_CONTROL` to add/remove audit rules, `CAP_AUDIT_READ` to read events.

### 15.2 Condition Guards (periodic)

#### 15.2.1 Process Guard (hybrid) — Linux

Same design as Windows: real-time primary via netlink proc connector + periodic `/proc` scan backup.

**Primary (real-time):** The netlink proc connector (`NETLINK_CONNECTOR` with `CN_IDX_PROC`) delivers `PROC_EVENT_EXIT` events within ~0ms of a process terminating. `PROC_EVENT_EXEC` catches forbidden processes launching.

**Backup (periodic):** `opendir("/proc")` + scan for numeric directories + read `/proc/<pid>/comm` or `/proc/<pid>/cmdline`. Default interval: 30s.

**Signature verification:** On Linux, executable signature verification uses `fsverity` (kernel 5.4+) or checks against a hash allowlist maintained in the policy. There is no direct equivalent of Windows `WinVerifyTrust`. The guard computes the SHA-256 hash of the executable at the path reported by `/proc/<pid>/exe` and compares against the `expected_hash` in the rule params.

#### 15.2.2 Package Guard (Software Guard equivalent)

Checks installed package versions and install dates.

**Detection mechanism (periodic, default interval 3600s):**
- **Debian/Ubuntu:** Parse `/var/lib/dpkg/status` or call `dpkg-query --show` via `libdpkg` (not the CLI — read the dpkg database directly via file parsing)
- **RHEL/Fedora:** Query RPM database via `librpm` (`rpmtsCreate` → `rpmdbInitIterator` → `rpmdbNextIterator`)
- **Both:** Parse install/update timestamps from package database entries

**Remediation options:** `alert-only` (default), `command` (trigger package manager update — note: this is one case where the `command` escape hatch is justified, since package management varies significantly by distro).

#### 15.2.3 Compliance Guard — Linux

Same concept as Windows — checks that a specific event occurred within a time window.

**Detection mechanism (periodic, default interval 3600s):**
- **journald:** `sd_journal_open()` + `sd_journal_add_match()` for specific syslog identifiers or systemd units, filtered by timestamp
- **Traditional syslog:** File scan of `/var/log/syslog` or `/var/log/messages` with timestamp parsing
- **ClamAV scan time:** Parse `/var/log/clamav/clamav.log` for last scan timestamp, or query `clamd` via its Unix socket

#### 15.2.4 Sysctl Guard

Ensures kernel parameters in `/proc/sys/` have correct values.

**Detection mechanism:** The primary detection uses the Linux Audit subsystem, not inotify. `/proc/sys/` files are virtual files backed by kernel variables — they almost never trigger inotify events when modified via the `sysctl()` syscall or by writing to the file. Audit watches are the only reliable real-time mechanism.

- **Primary (real-time):** Audit watch on the specific `/proc/sys/` path (e.g., `-w /proc/sys/net/ipv4/ip_forward -p wa -k yuzu_guardian_sysctl`). Fires when any process modifies the value. ~1ms latency.
- **Backup (periodic):** `open()` + `read()` on the `/proc/sys/` file and compare against expected value. Default interval: 30s. Catches cases where the audit rule was not installed or the audit subsystem is unavailable.

**Example parameters:**
- `net.ipv4.ip_forward` — must be 0 (no IP forwarding)
- `kernel.randomize_va_space` — must be 2 (full ASLR)
- `net.ipv4.conf.all.accept_redirects` — must be 0
- `fs.suid_dumpable` — must be 0

---

## 16. Linux-specific assertion types

These supplement the universal assertions (which work on all platforms) with Linux-specific checks:

| Assertion | Guard(s) used | `method: auto` fix |
|-----------|--------------|-------------------|
| `sysctl-value-equals` | Audit + poll on `/proc/sys/` | Yes — `write()` to `/proc/sys/` path |
| `config-value-equals` | inotify on config file | Yes — atomic rewrite of the config file with the correct value |
| `config-line-present` | inotify on config file | Yes — append the line if missing |
| `config-line-absent` | inotify on config file | Yes — remove matching lines, atomic rewrite |
| `selinux-enforcing` | inotify on `/sys/fs/selinux/enforce` | Yes — `security_setenforce(1)` via `libselinux` |
| `file-permissions` | Audit watch on file | Yes — `chmod()` + `chown()` |
| `cron-job-exists` | inotify on `/etc/cron.d/` or `/var/spool/cron/` | Partial — can write cron file, needs `cron_entry` param |
| `kernel-module-loaded` | Poll `/proc/modules` | No — loading kernel modules is too dangerous for auto-remediation |
| `kernel-module-blocked` | Poll `/proc/modules` | Yes — `write("install modulename /bin/true")` to `/etc/modprobe.d/` |

### 16.1 Config file assertion details

The `config-value-equals` assertion handles common Linux config file formats:

```yaml
assertion:
  type: config-value-equals
  params:
    path: /etc/ssh/sshd_config
    key: PermitRootLogin
    expected: "no"
    format: sshd               # sshd | ini | key-value | yaml | json
    separator: " "             # Key-value separator (default: space for sshd format)
```

Supported formats:
- `sshd` — `Key Value` (space-separated, as in `sshd_config`, `ntp.conf`)
- `ini` — `[Section]\nKey = Value` (as in `systemd` unit overrides, `php.ini`)
- `key-value` — `KEY=VALUE` (as in `/etc/environment`, `/etc/default/*`)
- `yaml` — dot-notation path into YAML structure
- `json` — dot-notation path into JSON structure

The `method: auto` remediation for `config-value-equals` reads the file, parses it in the specified format, replaces the value for the matching key, and writes it back atomically. It preserves comments, whitespace, and file structure — only the target value changes.

**Parser edge case rules:**
- **Duplicate keys:** Only the first occurrence of the key (outside any conditional block) is matched and modified. Subsequent duplicates are left unchanged.
- **Conditional blocks:** `sshd` format supports `Match` blocks (conditional sections). The parser only modifies keys at the top level (before any `Match` directive). Keys inside `Match` blocks are ignored — operators who need to enforce values inside conditional blocks must use `config-line-present` / `config-line-absent` with the full line text.
- **Comments:** Lines beginning with `#` (sshd, key-value), `;` (ini), or `//` (json) are preserved. If the target key exists only in commented form (`#PermitRootLogin yes`), the parser uncomments it and sets the correct value.
- **Character encoding:** Files are read as UTF-8. Byte-order marks (BOM) are preserved if present. Mixed line endings are normalised to the file's dominant line ending style on write.

---

## 17. Linux service unit and capabilities

The Yuzu agent on Linux runs as a systemd service. The service unit must grant the capabilities needed by the Guardian engine.

### 17.1 systemd unit additions

```ini
[Service]
# Guardian capabilities (in addition to existing agent capabilities)
AmbientCapabilities=CAP_NET_ADMIN CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_ADMIN CAP_AUDIT_CONTROL CAP_AUDIT_READ CAP_DAC_READ_SEARCH

# Retain capabilities after setuid (if not running as root)
SecureBits=keep-caps

# File system access for Guardian
ReadWritePaths=/var/lib/yuzu
ReadOnlyPaths=/proc/sys /sys/fs/selinux
```

**Capability mapping:**

| Capability | Used by | Purpose |
|-----------|---------|---------|
| `CAP_NET_ADMIN` | Netlink Guard, Netfilter Guard | Monitor/modify network state and firewall rules |
| `CAP_AUDIT_CONTROL` | Audit Guard | Add/remove audit rules |
| `CAP_AUDIT_READ` | Audit Guard | Read audit events from netlink |
| `CAP_DAC_READ_SEARCH` | Config file guards | Read any file regardless of permissions |
| (root or `CAP_SYS_ADMIN`) | Sysctl write | Write to `/proc/sys/` (some parameters require root) |

### 17.2 Boot-time enforcement on Linux

The two-phase init works identically on Linux:

```
systemd starts ──────────────────────→ Phase 1: start_local()
    │                                       │
    ├── yuzu-agent.service starts           ├── Open SQLite
    │   (After=local-fs.target)             ├── Load policy cache
    │                                       ├── Start all guards
    │                                       └── ENFORCING ✓
    │
    ├── network-online.target ──────→ Phase 2: sync_with_server()
    │                                       │
    │                                       ├── Connect gRPC
    │                                       └── Sync policies
    │
    ├── display-manager.service
User logs in ──────────────────────→ Already enforcing
```

The service unit uses `After=local-fs.target` (not `After=network-online.target`) so Phase 1 starts before the network is available. The gRPC connection in Phase 2 uses the existing agent reconnection logic with exponential backoff.

---

## 18. Linux implementation files

```
agents/core/src/guard_inotify.hpp/.cpp       inotify guard (Linux)
agents/core/src/guard_netlink.hpp/.cpp       Netlink guard — routing + netfilter + proc (Linux)
agents/core/src/guard_dbus.hpp/.cpp          D-Bus systemd guard (Linux)
agents/core/src/guard_audit.hpp/.cpp         Linux Audit subsystem guard
agents/core/src/guard_sysctl.hpp/.cpp        Sysctl guard (Linux)
agents/core/src/guard_package.hpp/.cpp       Package freshness guard — dpkg/rpm (Linux)
agents/core/src/config_parser.hpp/.cpp       Config file parser (sshd, ini, key-value, yaml, json)
agents/core/src/remediation_linux.hpp/.cpp   Linux remediation methods (system calls only)
```

### 18.1 Platform compilation

All platform-specific guard files are conditionally compiled via `meson.build`:

```meson
if host_machine.system() == 'windows'
  guardian_sources += files(
    'guard_registry.cpp', 'guard_etw.cpp', 'guard_wfp.cpp',
    'guard_scm.cpp', 'guard_wmi.cpp', 'remediation_windows.cpp',
  )
  guardian_deps += [dependency('advapi32'), dependency('ole32')]
elif host_machine.system() == 'linux'
  guardian_sources += files(
    'guard_inotify.cpp', 'guard_netlink.cpp', 'guard_dbus.cpp',
    'guard_audit.cpp', 'guard_sysctl.cpp', 'guard_package.cpp',
    'config_parser.cpp', 'remediation_linux.cpp',
  )
  guardian_deps += [dependency('libsystemd'), dependency('libaudit'),
                    dependency('libmnl'), dependency('libnftnl')]
endif
```

### 18.2 Updated implementation plan (Linux phases)

| Phase | Scope | Files |
|-------|-------|-------|
| **N. Linux inotify + netlink guards** | Config file watching, network state monitoring, proc connector | `guard_inotify.*`, `guard_netlink.*` |
| **O. Linux D-Bus + Audit guards** | systemd service monitoring, syscall-level audit | `guard_dbus.*`, `guard_audit.*` |
| **P. Linux condition guards** | Package Guard (dpkg/rpm), Sysctl Guard, config file assertions | `guard_sysctl.*`, `guard_package.*`, `config_parser.*` |
| **Q. Linux remediation** | All remediation methods via system calls (libsystemd, libmnl, libnftnl, libc) | `remediation_linux.*` |
| **R. Cross-platform testing** | Verify identical YAML rules work on both Windows and Linux, same dashboard output | Test harness, CI matrix |

---

## 19. macOS guard types — detailed

### 19.1 Endpoint Security requirement

The macOS implementation depends heavily on Apple's Endpoint Security framework (macOS 10.15+). This provides real-time kernel-level notifications for file operations, process events, and network activity — it is the macOS equivalent of both Windows ETW and the Linux audit/netlink subsystems.

**Entitlement requirement:** Endpoint Security requires the `com.apple.developer.endpoint-security.client` entitlement, granted by Apple through their developer program. This is a significant deployment prerequisite. The agent supports two modes:

- **Full mode (with entitlement):** All guards available, real-time process monitoring, file operation interception
- **Degraded mode (without entitlement):** FSEvents + kqueue + polling only. No process exec interception, no real-time file write detection. Significantly reduced capability. The dashboard should show a warning badge on macOS agents running in degraded mode.

Production deployments should obtain the entitlement. Development/testing can use SIP-disabled machines.

**ES client slot limit:** macOS limits concurrent Endpoint Security clients to approximately 3–5 system-wide (varies by macOS version). Enterprise Macs often already have an EDR product (CrowdStrike, SentinelOne, Jamf Protect) consuming a slot. If all slots are taken, `es_new_client` fails and the agent falls back to degraded mode even with the entitlement. The dashboard should surface this as a distinct warning state: "ES unavailable — client slots exhausted."

### 19.2 Event Guards (real-time)

#### 19.2.1 Endpoint Security Guard

The primary detection mechanism on macOS. Subscribes to Endpoint Security events via `es_new_client` + `es_subscribe`.

```cpp
void EndpointSecurityGuard::start() {
    es_new_client(&client_, ^(es_client_t* c, const es_message_t* msg) {
        switch (msg->event_type) {
            case ES_EVENT_TYPE_NOTIFY_WRITE:
                handle_file_write(msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_RENAME:
                handle_file_rename(msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_EXEC:
                handle_process_exec(msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_EXIT:
                handle_process_exit(msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETMODE:
                handle_chmod(msg);
                break;
            case ES_EVENT_TYPE_NOTIFY_SETOWNER:
                handle_chown(msg);
                break;
        }
    });

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_NOTIFY_SETOWNER,
    };
    es_subscribe(client_, events, sizeof(events)/sizeof(events[0]));
}
```

**Latency:** ~0ms (kernel delivers events synchronously to the client callback).

**Path filtering (critical for performance):** Subscribing to `ES_EVENT_TYPE_NOTIFY_WRITE` delivers events for every file write on the system — thousands per second on a busy Mac. The Endpoint Security guard must implement aggressive path filtering: on receiving an event, it checks the target path against the set of paths actively watched by Guardian rules (stored in a hash set for O(1) lookup). Events for unwatched paths are discarded immediately in the callback without invoking the evaluator. Without this filtering, the agent would consume significant CPU processing irrelevant events.

**Objective-C++ compilation:** The Endpoint Security API uses Objective-C block syntax for callbacks (`^(es_client_t* c, const es_message_t* msg)`). The Yuzu codebase is C++23. Endpoint Security guard source files must use the `.mm` extension (Objective-C++) to compile blocks alongside C++ code. The meson build handles this via `objcpp_args` or by treating `.mm` files as Objective-C++ sources.

**What it replaces from other platforms:**
- Windows ETW → Endpoint Security (process events, security audit)
- Windows Registry Guard → Endpoint Security file write events on plist/config files
- Linux inotify → Endpoint Security file write/rename events
- Linux proc connector → Endpoint Security exec/exit events
- Linux Audit Guard → Endpoint Security (broader coverage, same kernel-level granularity)

**Advantage over inotify:** Unlike Linux inotify which only tells you THAT a file changed, Endpoint Security tells you WHICH process modified it, the full path, and the operation type. This partially closes the change-detail gap that exists between Linux and Windows.

#### 19.2.2 FSEvents Guard (degraded mode fallback)

Used when Endpoint Security entitlement is not available. Watches directories for file changes via `FSEventStreamCreate`.

```cpp
void FSEventsGuard::start() {
    CFStringRef path = CFStringCreateWithCString(nullptr, path_.c_str(), kCFStringEncodingUTF8);
    CFArrayRef paths = CFArrayCreate(nullptr, (const void**)&path, 1, nullptr);

    FSEventStreamContext ctx = { .info = this };
    stream_ = FSEventStreamCreate(nullptr, callback, &ctx, paths,
        kFSEventStreamEventIdSinceNow,
        0.0,  // latency: 0 = deliver immediately
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer);

    FSEventStreamScheduleWithRunLoop(stream_, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    FSEventStreamStart(stream_);
}
```

**Latency:** ~10-100ms (FSEvents batches even with latency=0 and `kFSEventStreamCreateFlagNoDefer`). Significantly slower than Endpoint Security.

**Applicable to:** Config file monitoring (`/etc/pf.conf`, plist files, `/etc/ssh/sshd_config`), launch daemon plists.

#### 19.2.3 launchd Guard

Monitors macOS service state. macOS uses launchd (not systemd, not SCM) for service management.

**Detection mechanism:**
- **Primary (real-time):** Endpoint Security `ES_EVENT_TYPE_NOTIFY_EXEC` filtered for the service's executable path — detects when the service process starts or stops
- **Secondary:** Watch `/Library/LaunchDaemons/` and `/Library/LaunchAgents/` for plist file changes (service added/removed/modified)
- **Backup (periodic):** `SMJobCopyDictionary` or XPC query to launchd for service state. Default interval: 30s.

**Latency:** ~0ms for process start/stop (Endpoint Security), ~10ms for plist changes (FSEvents), 30s for state poll.

**launchd API limitations:** macOS does not expose a stable public API for all launchd operations. Some operations are only available via XPC to `com.apple.launchd` (private but stable) or via command-line tools. The remediation section documents where `command` escape hatches are needed.

### 19.3 Condition Guards (periodic)

#### 19.3.1 Process Guard — macOS (hybrid)

Same design as Windows and Linux: real-time primary + periodic poll backup.

**Primary (real-time):** Endpoint Security `ES_EVENT_TYPE_NOTIFY_EXEC` (process start) and `ES_EVENT_TYPE_NOTIFY_EXIT` (process stop). ~0ms latency.

**Backup (periodic):** `proc_listpids(PROC_ALL_PIDS, ...)` + `proc_pidpath()` to enumerate processes. Default interval: 30s.

**Degraded mode (no Endpoint Security):** Poll-only using `proc_listpids`. No real-time detection.

**Signature verification:** macOS has `SecStaticCodeCheckValidity` for code signature verification (equivalent of Windows `WinVerifyTrust`). This verifies Apple's code signing chain — stronger than Linux's hash-only approach. Uses the Security.framework.

#### 19.3.2 Package Guard — macOS

**Detection mechanism (periodic, default 3600s):**
- **Homebrew:** Parse `/usr/local/Cellar/` (Intel) or `/opt/homebrew/Cellar/` (Apple Silicon) directory timestamps and `brew info --json` output
- **pkgutil:** `pkgutil --pkgs` + `pkgutil --pkg-info <id>` for install timestamps
- **App Store apps:** Parse `/Applications/*.app/Contents/Info.plist` for `CFBundleShortVersionString` and file modification timestamps

#### 19.3.3 Compliance Guard — macOS

**Detection mechanism (periodic, default 3600s):**
- **Unified logging:** `os_log` queries via `OSLogStore` API (macOS 12+). Equivalent of Linux journald queries.
- **XProtect status:** Read `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist` for definition update timestamps
- **Legacy:** Parse `/var/log/system.log` for older macOS versions

### 19.4 macOS firewall detection — the workaround

macOS `pf` has no change notification API. The design uses a three-layer detection strategy that achieves near-real-time for the common case:

```
Layer 1: Endpoint Security (real-time, ~0ms)
    Watch for pfctl process execution
    ├── ES_EVENT_TYPE_NOTIFY_EXEC where executable = /sbin/pfctl
    ├── Inspect arguments: -f (load rules), -a (anchor), -t (table), -d (disable), -e (enable)
    └── On match → trigger immediate rule evaluation via /dev/pf ioctl

Layer 2: File monitoring (real-time, ~0-10ms)
    Watch pf config files and ALF preferences
    ├── /etc/pf.conf — main pf ruleset
    ├── /etc/pf.anchors/* — anchor rulesets
    ├── /Library/Preferences/com.apple.alf.plist — Application Firewall config
    └── On change → trigger evaluation (file change doesn't mean rules loaded,
                     but indicates intent — evaluate current kernel state via ioctl)

Layer 3: Fast ioctl poll (periodic, 5s default)
    Read current pf state via /dev/pf ioctls
    ├── DIOCGETRULES — read active ruleset
    ├── DIOCGETSTATUS — check if pf is enabled/disabled
    └── Compare against expected state from policy assertion
```

**Why this works for most real-world scenarios:**

| How firewall is changed | Detection layer | Latency |
|------------------------|-----------------|---------|
| `pfctl -f /etc/pf.conf` (most common) | Layer 1: Endpoint Security exec event | ~0ms |
| `pfctl -a anchor -f rules` | Layer 1: Endpoint Security exec event | ~0ms |
| System Settings → Firewall toggle | Layer 2: ALF plist change | ~0-10ms |
| Edit `/etc/pf.conf` manually | Layer 2: File write event | ~0-10ms |
| Third-party app calls `pfctl` | Layer 1: Endpoint Security exec event | ~0ms |
| Direct `/dev/pf` ioctl (rare, advanced) | Layer 3: Poll | ≤5s |
| `pfctl -d` (disable pf entirely) | Layer 1: Endpoint Security exec event | ~0ms |

For the majority of real-world cases (changes via `pfctl` or System Settings), detection is real-time. The 5s poll catches the rare direct-ioctl edge case. The poll interval is configurable per-rule — for critical firewall rules, an operator can set it to 1s at the cost of slightly higher CPU usage from the ioctl calls.

**Remediation via system calls:**

```cpp
// Reading current pf rules — /dev/pf ioctl (must iterate)
int dev_pf = open("/dev/pf", O_RDWR);
struct pfioc_rule pr;
memset(&pr, 0, sizeof(pr));
pr.rule.action = PF_PASS;

// Step 1: get ticket and rule count
ioctl(dev_pf, DIOCGETRULES, &pr);
uint32_t ticket = pr.ticket;
uint32_t nr_rules = pr.nr;

// Step 2: iterate rules using DIOCGETRULE (singular) with ticket + index
for (uint32_t i = 0; i < nr_rules; i++) {
    memset(&pr, 0, sizeof(pr));
    pr.ticket = ticket;
    pr.nr = i;
    ioctl(dev_pf, DIOCGETRULE, &pr);
    // pr.rule now contains the i-th rule — check against expected state
}

// Adding a block rule — /dev/pf ioctl
struct pfioc_rule new_rule;
memset(&new_rule, 0, sizeof(new_rule));
new_rule.rule.action = PF_DROP;
new_rule.rule.direction = PF_IN;
new_rule.rule.proto = IPPROTO_TCP;
new_rule.rule.dst.port[0] = htons(445);
new_rule.rule.dst.port[1] = htons(445);
new_rule.rule.dst.port_op = PF_OP_EQ;
ioctl(dev_pf, DIOCADDRULE, &new_rule);

close(dev_pf);
```

This is a direct system call — no `pfctl` CLI involved. The agent opens `/dev/pf`, constructs the rule structure, and issues the ioctl. Requires root or membership in the `network` group.

---

## 20. macOS remediation APIs (system calls only)

| Method | Framework | System calls | NOT this |
|--------|-----------|-------------|----------|
| `firewall-rule` | `/dev/pf` ioctl | `DIOCADDRULE`, `DIOCDELETERULE`, `DIOCGETRULES` | NOT `pfctl` |
| `plist-write` | CoreFoundation | `CFPreferencesSetAppValue` + `CFPreferencesSynchronize` | NOT `defaults write` |
| `file-permissions` | libc | `chmod()`, `chown()` | NOT `chmod` CLI |
| `stop-process` | libc | `kill(pid, SIGTERM)` → `kill(pid, SIGKILL)` | NOT `kill` CLI |
| `restart-process` | libc | `posix_spawn()` with process path | NOT `open -a` or shell |
| `config-write` | libc | `open()` + `write()` + `fsync()` + `rename()` (atomic) | NOT `sed -i` |
| `code-sign-verify` | Security.framework | `SecStaticCodeCheckValidity` | NOT `codesign --verify` |

**launchd service control — exception:**
macOS does not expose a stable public API for starting/stopping/enabling/disabling launchd services programmatically. The `SMJobSubmit` API is deprecated. The modern `SMAppService` (macOS 13+) only works for the calling app's own services. For managing arbitrary system services, the agent must use one of:
- XPC to `com.apple.launchd` (private API — stable but undocumented, may break across major macOS versions)
- `command` method with `launchctl load/unload` (CLI escape hatch)

This is the ONE area where macOS genuinely requires the `command` escape hatch for service management. The document should be honest about this — Apple deliberately restricts programmatic service management for security reasons.

---

## 21. macOS-specific assertion types

| Assertion | Guard(s) used | `method: auto` fix |
|-----------|--------------|-------------------|
| `plist-value-equals` | Endpoint Security / FSEvents on plist file | Yes — `CFPreferencesSetAppValue` |
| `gatekeeper-enabled` | Poll `spctl --status` or read plist | Partial — `spctl` CLI needed |
| `filevault-enabled` | Poll `fdesetup status` or read CoreStorage | No — enabling FDE requires user interaction |
| `sip-enabled` | Poll `csrutil status` or read NVRAM | No — changing SIP requires Recovery boot |
| `xprotect-updated-within` | Poll XProtect plist timestamp | No — Apple controls XProtect updates |
| `alf-enabled` | Endpoint Security / FSEvents on ALF plist | Yes — `CFPreferencesSetAppValue` on `com.apple.alf` |
| `config-value-equals` | Same as Linux (shared implementation) | Yes — atomic file rewrite |

### 21.1 macOS gap analysis vs Windows and Linux

| Capability | Windows | Linux | macOS | Notes |
|-----------|---------|-------|-------|-------|
| Real-time config change | Registry ~0ms | inotify ~0ms | Endpoint Security ~0ms | macOS parity when ES entitlement present |
| Real-time firewall change | Registry + ETW ~0ms | Netlink ~0ms (nftables) | pfctl exec intercept ~0ms | macOS ~0ms for most cases, 5s poll for direct ioctl |
| Real-time process events | ETW ~0ms | Proc connector ~0ms | Endpoint Security ~0ms | Parity across all three |
| Real-time service state | SCM ~0ms | D-Bus ~1ms | Partial (ES exec/exit ~0ms) | macOS detects service process start/stop in real-time via ES, but not formal launchd state transitions |
| Service control via API | advapi32 SCM | libsystemd D-Bus | No stable public API | macOS gap — needs `command` escape hatch or private XPC |
| Code signing verification | WinVerifyTrust (Authenticode) | Hash pinning (different model) | SecStaticCodeCheckValidity (Apple signing) | Linux hash pinning is more restrictive (exact binary match) but higher maintenance. Windows/macOS use cert chain trust. Different security tradeoffs, not strictly weaker. |
| Unified system query | WMI | None (fragmented) | None (fragmented) | Windows strongest. Linux and macOS similar. |
| Config format | Registry (binary, API) | Text files (parseable) | Plist (binary+XML, API) | macOS plist is between registry and text files |
| Security framework | N/A | SELinux / AppArmor | SIP / Gatekeeper / TCC | Different models, all platform-specific |

---

## 22. macOS implementation files

```
agents/core/src/guard_endpoint_security.hpp/.mm    Endpoint Security guard (macOS, Objective-C++)
agents/core/src/guard_fsevents.hpp/.cpp            FSEvents guard — degraded mode (macOS)
agents/core/src/guard_launchd.hpp/.cpp             launchd service guard (macOS)
agents/core/src/guard_pf.hpp/.cpp                  pf firewall guard — three-layer (macOS)
agents/core/src/guard_package_macos.hpp/.cpp       Package guard — pkgutil/Homebrew (macOS)
agents/core/src/remediation_macos.hpp/.cpp         macOS remediation (CoreFoundation, /dev/pf, libc)
```

### 22.1 Meson conditional compilation

```meson
elif host_machine.system() == 'darwin'
  guardian_sources += files(
    'guard_endpoint_security.mm', 'guard_fsevents.cpp',
    'guard_launchd.cpp', 'guard_pf.cpp',
    'guard_package_macos.cpp', 'config_parser.cpp',
    'remediation_macos.cpp',
  )
  guardian_deps += [
    dependency('appleframeworks', modules: ['CoreFoundation', 'Security']),
  ]
  # EndpointSecurity is NOT an .framework bundle (it ships as
  # usr/lib/libEndpointSecurity.tbd + usr/include/EndpointSecurity/ on both
  # the Command Line Tools and full Xcode SDKs) -- `dependency('appleframeworks',
  # modules: ['EndpointSecurity'])` never succeeds against it (this was a real
  # probe defect elsewhere in the tree, fixed macOS Spark/Reflex/DEX programme
  # A0.5, 2026-09). Consume the shared top-level probe instead, like
  # agents/core/meson.build's own darwin branch does:
  guardian_deps += endpoint_security_deps
  guardian_args += endpoint_security_args
endif
```

### 22.2 Boot-time enforcement on macOS

```
launchd starts ──────────────────────→ Phase 1: start_local()
    │                                       │
    ├── com.yuzu.agent.plist                ├── Open SQLite
    │   (RunAtLoad=true)                    ├── Load policy cache
    │                                       ├── Start all guards
    │                                       └── ENFORCING ✓
    │
    ├── Network available ──────────→ Phase 2: sync_with_server()
    │
Login window appears
User logs in ──────────────────────→ Already enforcing
```

The launchd plist uses `RunAtLoad=true` and is placed in `/Library/LaunchDaemons/` (system-wide, runs as root). No `WaitForNetwork` key — Phase 1 starts immediately.

### 22.3 Updated implementation plan (macOS phases)

| Phase | Scope | Files |
|-------|-------|-------|
| **S. macOS Endpoint Security guard** | ES client setup, file/process/exec event handling | `guard_endpoint_security.*` |
| **T. macOS pf firewall guard** | Three-layer detection (ES exec intercept + file watch + ioctl poll) | `guard_pf.*` |
| **U. macOS launchd + package guards** | Service state monitoring, pkgutil/Homebrew queries | `guard_launchd.*`, `guard_package_macos.*` |
| **V. macOS remediation** | /dev/pf ioctl, CoreFoundation plist, code signature verification | `remediation_macos.*` |
| **W. Degraded mode (no ES entitlement)** | FSEvents fallback, poll-only process monitoring, warning system | `guard_fsevents.*`, degraded mode logic |
| **X. Three-platform integration testing** | Verify same YAML rules on Windows + Linux + macOS, same dashboard | CI matrix, test harness |

---

## 23. Future consideration: kernel-mode sensor

Yuzu Guardian runs entirely in user space. This is a deliberate design choice — the userspace approach meets all six problem statement requirements with sub-10ms enforcement latency, and a bug in userspace crashes the agent process (recoverable via service restart), not the entire machine.

The main weakness is tamper resistance: a local admin can kill the agent process or modify its policy cache. Partial mitigations exist in userspace (Windows Protected Process Light, Linux `prctl(PR_SET_DUMPABLE, 0)` with restricted capabilities, tamper-resistant service configuration), but a determined attacker with admin/root access can ultimately disable a userspace agent.

If a future release requires preventive enforcement (blocking changes before they happen rather than reverting after), the industry-standard approach is a hybrid architecture: a small, stable kernel component acts as a sensor and optional gate, while the userspace agent retains all policy logic, remediation, communication, and reporting. The kernel component observes events, optionally blocks operations (e.g., returning `STATUS_ACCESS_DENIED` from a Windows minifilter callback), and passes event data to userspace. It is deliberately minimal (a few thousand lines), changes infrequently, and on Windows is the only piece requiring WHQL certification. This is the architecture used by CrowdStrike, SentinelOne, and Microsoft Defender for Endpoint.

This would be a Phase 15+ addition, not a rearchitecture of the current Phases A–X design.

---

## 24. Standing Guardian invariants (governance reference)

Pulled out of CLAUDE.md so the design doc carries them. Every PR in the
Guardian ladder must check these.

- **No thread `GuardianEngine::stop()` joins may take `GuardianEngine::mtx_`.**
  `stop()` holds `mtx_` across its whole body AND joins BOTH the
  `ConvergenceScheduler` lanes and the outbox drain worker inside it, so an
  `mtx_` acquisition on any of those threads is a lock-vs-join deadlock — a hung
  agent shutdown, fleet-wide. In scope: the journal's prune/page maintenance and
  the convergence sweeps, both of which run directly on a joined thread.
  Collaborators are handed to the workers as pre-resolved handles at
  construction, never re-read off the engine under its lock. `mtx_` is a
  `WorkerHostileMutex` that ABORTS on violation in debug/sanitizer builds, keyed
  on the thread-local marker in `guardian_joined_thread_role.hpp` — but the abort
  is a backstop, not a licence to reason loosely, and it compiles out of a plain
  release build. (C0, #2298 gate 1 + Gate 4.)
  **NOT in scope since #3961**: the drain worker's INJECTED `send` (an arbitrary
  `std::function` supplied from `agent.cpp`) no longer runs on the joined thread
  — `GuardianOutboxDrainWorker::wrapped_send()` bounces every send through a
  per-lane `GuardianOutboxSendExecutor`, which runs it on its own DETACHED
  worker instead. That detached worker is covered by a separate invariant, the
  ORPHAN-EXIT CONTRACT (`guardian_outbox_send_executor.hpp`'s header comment):
  a worker wedged in a blocking syscall cannot be joined or force-cancelled, so
  `active_send_workers()` — summed into `GuardianEngine::active_io_workers()`
  (`guardian_engine.cpp`) alongside the state-reader and arm/disarm executors —
  is what keeps `main.cpp`/`service_win.cpp` from tearing down the state `send`
  captures while a detached send is still running, `hard_exit()`ing instead
  after a bounded grace. A source left out of that sum would silently reinstate
  the use-after-free the joined-thread rule used to prevent by a different
  mechanism.
  **Fourth additive source since #4783:** `GuardianLegacySinkExecutor::
  active_worker_count()` (`guardian_legacy_sink_executor.hpp`) is summed into
  `GuardianEngine::active_io_workers()` itself - the same `GuardianEngine`-level
  chokepoint the paragraph above describes, not a separate `AgentImpl`-level sum
  like the Spark extension below. This executor is the detached, bounded, FIFO
  sender every legacy `IGuard` producer (`FileGuard`/`RegistryGuard`/
  `ServiceGuard`/`SystemdServiceGuard`) now enqueues onto via
  `GuardianEngine::emit_guard_event()`, instead of writing to the Subscribe
  stream synchronously on its own detection thread; it is constructed
  unconditionally at `GuardianEngine` construction and stays live regardless of
  `prefer_spark_`. Its worker wears `GuardianDetachedWorkerRole` and retires -
  decrementing the count - only at its `AliveTicket`'s destruction, the same
  physical-alive-count binding described above for `GuardianIoExecutor`. The
  hazard is the same shape as the outbox executor's: a stalled-but-not-dead gRPC
  `Write()` (gateway up, not draining) wedges the worker in a blocking syscall
  that can be neither joined nor force-cancelled. If its count were left out of
  the sum, `main.cpp`/`service_win.cpp` could tear down the `AgentImpl` state its
  send callback captures (`stream_write_mu_`/`guardian_sink_stream_`) while that
  send is still running - reinstating the exact use-after-free the joined-thread
  rule and the outbox executor's own accounting both exist to prevent. See
  `guardian_legacy_sink_executor.hpp`'s own ORPHAN-EXIT CONTRACT note and
  `GuardianEngine::active_io_workers()`'s doc comment (`guardian_engine.cpp`).
  **Second role since rung 9c PR-1:** every `GuardianIoExecutor` worker body - `run()` and
  `submit()` alike, their `on_abandoned`/`on_complete` callbacks included - wears
  `GuardianDetachedWorkerRole` (`guardian_detached_worker_role.hpp`), and the same
  `WorkerHostileMutex` tripwire aborts on an `mtx_` acquisition from it; a different hazard
  (lock-vs-lifetime: a detached worker may outlive the engine and can never be joined), same
  remedy. **F3 binds to the PHYSICAL alive count (#4147):** `GuardianIoExecutor::
  active_worker_count()` is decremented at worker-payload destruction, the latest
  self-observable point before OS-thread exit, never at the earlier quota release `submit()`
  performs when the backend call returns - a worker still inside its completion callback
  keeps the count nonzero. Wiring a source to the quota count instead would reinstate the
  teardown race with no test calling it out.
  **Extended for Spark (PR-A, #2012/#3840; dormant until a mechanism uses it —
  Gate 6 compliance finding, PR-A round 5, folded in here; reworded at pass 5
  per an architect finding — the clause below previously read as modifying
  the primitive rather than the counter):** a second, independent additive
  source feeds the SAME chokepoint one level up.
  `AgentImpl::guardian_active_io_workers()` (`agent.cpp`) sums
  `GuardianEngine::active_io_workers()` (above) with a separate
  `spark_detached_workers_` counter — constructed via a default member
  initializer before any `SparkEngine`/mechanism exists, and never read
  through `spark_engine_`/`spark_boot_done_` — fed by `agents/core/src/
  spark_detached_call.hpp`'s `SparkDetachedLane`/`DetachedCall<T>` primitive,
  so it stays correct across a boot-time exception that resets
  `spark_engine_`. `main.cpp`/`service_win.cpp` poll the SUM at this
  `AgentImpl` level, not `GuardianEngine::active_io_workers()` alone; a
  future third additive source must add a term to that same sum inside
  `AgentImpl::guardian_active_io_workers()`, never a parallel counter read
  elsewhere.
- **Journal maintenance is paced by TIME, never by wake count.** The drain
  worker wakes on every outbox enqueue, and a paging pass is a full
  `list_entries` + parse + `validate_record` sweep of the journal.
  `JournalPagingBucket` does NOT bound that — it charges a token only when a
  batch pages net-new work, so with a full send window it never throttles at
  all. It is a wire limiter, not a scan limiter. Any future maintenance work
  added to this worker must carry its own `steady_clock` cadence, or it becomes
  O(event rate x journal size) on every managed endpoint. (C0, #2298 gate 1.)
- **RBAC `Push` seed is Guardian-only.** `rbac_store.cpp` has TWO operation
  arrays: `ops[]` (the full catalogue, 6 entries including `Push`) and
  `crud_ops[]` (the 5 ops cross-seeded to every securable type in the
  Administrator + ITServiceOwner role loops). `Push` is deliberately absent
  from `crud_ops[]` and is granted explicitly per role on `GuaranteedState`
  alone. **Do not add `Push` to `crud_ops[]` or cross-seed it** — every role
  gaining `*:Push` silently grants a privilege that any future handler
  consulting `perm_fn(..., "Push")` on a non-Guardian securable would accept.
  This is the H-4 invariant from Guardian PR 2 hardening round 2; see issue
  #485 for the upgrade-path migration that removes stale cross-type grants
  on deployments that ran pre-H-4 code.
- **Reserved plugin name `__guard__` is intercepted before the plugin match
  loop.** Load-time rejection lives in `plugin_loader.cpp` (PR #453);
  dispatch-time intercept lives in `agent.cpp` in front of the plugin scan
  (PR 2). Both halves must stay — the load-time check is the primary
  defence, the dispatch-time intercept is defence-in-depth. See #477 for the
  known `dlopen`-before-name-check gap that the load-time check inherits.
- **`dangerous_enforce_in_spec` is the single enforce-safety chokepoint —
  EXTEND it, never fork it.** It lives in `guardian_rule_spec.cpp` and gates
  dangerous enforce-promotion at every path that can set `enforcement_mode`:
  create (`derive_rule_spec`), the REST metadata update (`rest_api_v1`), and
  the push backstop (`guardian_push_builder`, which *downgrades* a dangerous
  enforce to audit rather than rejecting). Any new guard type with a
  dangerous enforce action must EXTEND `dangerous_enforce_in_spec` — never
  add a parallel gate. When Linux service-enforce lands it must EXTEND
  `dangerous_enforce_service_stop` with a Linux critical-unit denylist —
  never fork the gate.
- **The enforced set is read via `BaselineStore::deployed_member_rule_ids()`**
  — the push fan-out and the heartbeat reconcile both gate on it; it sources
  from each deployed Baseline's `deployed_snapshot`, not the live member set
  (the Push-not-Write invariant in `docs/user-manual/guaranteed-state.md`).
- **Guardian wire payloads in `CommandRequest.parameters` are not
  gateway-safe.** Any field that carries raw proto bytes (serialised
  `GuaranteedStatePush`, binary signatures, etc.) must NOT be placed in a
  `map<string, string>` that the gateway will re-encode via
  `gpb:e_type_string`. The Erlang gateway runs
  `unicode:characters_to_binary/1` which rejects invalid UTF-8 varints — the
  crash surface lands the moment Guardian PR 3 wires fan-out. See #478 for
  the schema/wire fix.

- **Published schema enums and the agent's per-type support arrays are bound by
  the H2/G9 cross-check tests** — add or remove a guard type in **both or
  neither**. A one-sided change leaves the published schema advertising a type
  the agent cannot enforce (or silently drops one it can), and nothing else in
  the build catches the divergence.

- **`full_sync`'s KV teardown clears `rule:` keys ONLY, never `baseline:`
  records (#4021).** A `file-hash-equals` rule authored with no `expected_hash`
  captures a baseline on arm; that capture is persisted per `rule_id` under
  `__guardian__`/`baseline:` (fingerprint = assertion type + authored path,
  schema-versioned separately from the fingerprint content so a future schema
  bump cannot silently mass-invalidate every existing record as "a genuine
  retarget"), and re-seeded at both arm sites (legacy
  `start_guard_for_rule_locked`, Spark's `reconcile_rule_locked`). A future
  blanket `kv_->clear(kKvNamespace)` — or a new key type added under this
  namespace without updating the scoped delete — silently reinstates the
  #4021 laundering (a genuinely drifted rule's baseline reset to whatever the
  target currently holds, with no remediation and no visible action). Absence
  from one push is not deletion — the server omits disabled/out-of-scope rules
  from every push, so a rule_id's baseline record is never swept merely for
  being absent from a full_sync. `guardian_persist_baseline` additionally
  refuses to overwrite a well-formed, same-fingerprint record (a write reaching
  that state can only mean a failed seed lookup — adversarial-review K1/C2-1).
  Spark's own first-ever baseline capture is NOT yet wired to this store
  (tracked as #4045) — under `prefer_spark_=true` (not the shipping default), a
  rule never armed via legacy still relaunders on full_sync/restart exactly as
  before this fix.
- **A guard whose own detection has permanently degraded must never publish
  itself compliant (PR #4748, CT-4).** `FileGuard`'s parent-directory
  (rename-detection) watch permanently disables after repeated teardown
  failures (`kParentIoAbandonLimit`, `guard_file.cpp`); `report_compliant()`
  gates on that state and substitutes a `guard.unhealthy` health report
  (`GuardDrift::Health`, `guard.hpp`) for any would-be compliant publication,
  re-sent on a `parent_unhealthy_refresh_ms` cadence (default 5 minutes) as a
  lost-edge backstop, for as long as the rule stays disabled — ordinary drift
  reporting for the guard's own detection is unaffected. `GuardianEngine::
  emit_guard_event`'s health arm runs BEFORE `apply_drift_to_event` and
  ignores every compliance field on the report unconditionally, so a future
  producer that sets both `health` and a compliance field cannot leak a false
  compliant/drift verdict through it. A future `Health` enumerator or a new
  degraded-detection state on ANY guard type (Registry, Service) must route
  through this same gate-and-substitute shape — never append a second,
  parallel "also emit compliant" event alongside a health report, which
  reopens the exact false-green window this PR closed.

## 25. Lifecycle-audit journal (ADR-0021 Stage 2, item 7)

Guardian's spark-backed rule engine keeps a durable audit trail of `guard.armed` /
`guard.disarmed` lifecycle events on the agent, independent of the compliance-drift
event stream. Full implementation-contract history (review lineage, the six
Sol/Fable hardening rounds, the rev-4.1 refinements, and the reasoning behind every
design choice below) lives in `docs/spark-item7-lifecycle-journal-design.md` — this
section states the guarantee and the loss-channel contract as shipped, since some
names and buckets changed during implementation and that doc is a point-in-time
design record, not maintained against the code afterward.

**The guarantee.** Process-crash-durable, duplicate-tolerant, bounded-retry delivery
of armed/disarmed/errored lifecycle events (`"errored"` gained the same durable
treatment as the other two in #2818/PR-2d, which fixed a replay-validation allowlist
that had quarantined it as tampered on any restart until then). Once persisted, an event survives a process
crash or restart and is re-sent on every reconnect/restart — regardless of any
possible prior acceptance (acceptance is unknowable; there is no ack) — until it
ages out of retention. A local gRPC `Write()` returning true is never delivery
confirmation. **Retention eviction and quarantine are the only deletion paths, and
every removal is counted.** Storage: `kv_store.db`, namespace `__guardian_journal__`
(`guardian_journal_format.hpp`), distinct from `__guardian__` so it survives
`full_sync`'s namespace clear. Owned by `GuardianEngine`, not the runtime — the
runtime is the object built to survive the agent via a detached `SparkEngine`
handler, so a borrowed `KvStore` there would be a dormant use-after-free.

**Retention (all three bounds enforced together, oldest evicted first by
`(timestamp, key)`):** 7 days, 1000 batches, 32 MiB
(`kJournalRetentionDays`/`kMaxJournalBatches`/`kMaxJournalBytes`,
`guardian_journal_format.hpp`). Quarantine (corrupt/unparseable batches) is
separately bounded at 100 batches. Replay is rate-limited by a process-lifetime
token bucket (0.1 batch/agent/s refill, burst 5, `kJournalPageRefillPerSec`/
`kJournalPageBurst`) that delays paging, never skips it — retention is the only
deletion path regardless of bucket state.

**The "alert" severities below are the designed posture, not the live one — no
alert on any of these channels pages an operator today.** The `yuzu-guardian-journal`
Prometheus rule group (`docs/prometheus/yuzu-alerts.yml`) is entirely commented out,
for two independent reasons, only the first of which clears at the `prefer_spark`
cutover: (1) the journal is inert pre-cutover, so every counter is provably 0 and an
enabled rule could only fire on a forged heartbeat; (2) no churn-robust
new-increment alert form exists yet for these unlabelled fleet-summed *cumulative*
counters over a *churning* agent population (`increase()`/`rate()`/`delta()`/bare
`> 0` each fail differently — full analysis in the YAML file's own preamble) — this
reason does **not** clear at cutover — tracked at #2336 (filed 2026-07-21), currently
unowned (no assignee, no milestone). Until both clear, every channel below is
graph-and-post-incident-review only. The only signals that currently roll up live —
not page; their alert rules sit in the same commented-out group as everything else
here — are two pipeline-health counters, `yuzu_fleet_guardian_journal_reporting` and
`..._tag_rejected` — server-owned counts published every sweep including at 0, unlike
the 30 agent-self-reported counters below, and the reason they can be sound where the
loss-channel counters cannot.

**Loss / removal channels — every one counted, all `yuzu.guardian_journal_*`
heartbeat tags unless noted (sparse-emit: a zero counter ships no tag; writer
`guardian_journal_heartbeat.hpp`, server-side rollup + HELP text
`guardian_journal_fleet_tags.hpp`):**

| channel | when | tag | severity |
|---|---|---|---|
| stage-drop | `pending_journal_` reserve exhausted under sustained write failure | `stage_dropped` | integrity gap, alert |
| stage-failure | a disarm record could not be built after the rule was already torn down | `stage_failures` | integrity gap, alert |
| field rejection | NUL / oversized / non-UTF-8 field kept a record out of the journal | `field_rejected` | integrity gap, alert |
| skewed-clock reject | normalized event timestamp floors to `seconds <= 0` (would replay as server-receipt-now and false-conflict) | `clock_rejected` | integrity gap, alert |
| write failure | a `set()` failed; per-push circuit-broken, retried by the maintenance tick | `write_failures` | integrity gap, alert |
| write-capacity reject | a new batch refused because the journal is at its byte/count cap | `write_capacity_rejected` | integrity gap, alert (UP-1) |
| gauge underflow | the write-ceiling size gauge read negative; persist fails CLOSED rather than trust a corrupt bound | `gauge_underflow` | integrity gap, alert (UP-2 / #2303) |
| key collision | boot-nonce + sequence collision upserted over a batch (~2⁻⁶⁴) | `key_collisions` | integrity gap, alert |
| quarantine | corrupt/unparseable batch removed from replay | `quarantined` | integrity gap, alert |
| quarantine-rename failure | could not even quarantine a corrupt batch | `quarantine_failures` | integrity gap, alert |
| quarantine-capacity eviction | quarantine itself over its 100-batch cap, oldest shed | `quarantine_capacity_evicted` | integrity gap, alert (UP-7) |
| page-read failure | a fallible journal scan failed; distinguished from "journal empty" and retried | `page_read_failures` | integrity gap, alert |
| eviction, no send evidence | aged out with no sent-label present (best-effort — a live entry may send before its batch key exists) | `evicted_no_send_evidence` | integrity gap, alert |
| eviction, sent-unacked | aged out with a sent-label present but never server-confirmed | `evicted_sent_unacked` | monitor |
| eviction, unclassified | aged out with disposition unknown — the third bucket that makes `batches_pruned == evicted_sent_unacked + evicted_no_send_evidence + evicted_unclassified` exact every pass, including shutdown/throw | `evicted_unclassified` | integrity gap, alert |
| clock-jump decline | a retention pass declined to age-evict because the wall clock jumped implausibly far forward — a deliberate non-delete, not a loss | `clock_jump_skips` | informational (retained evidence, not lost) |
| maintenance exception | a persist/prune/page throw was firewalled and swallowed | `maint_exceptions` | integrity gap, alert |
| lifecycle backpressure drop | a lifecycle entry was rejected at outbox enqueue for capacity (a staging loss, distinct from `stage_dropped`) | `guardian_journal_backpressure_drops` | integrity gap, alert |
| drain/send exception | a per-entry drain send threw; the head is retained and that log's drain stops | `guardian_drain_exceptions` / `guardian_send_exceptions` | integrity gap, alert |
| send stall / orphan-exception (#3953) | a `GuardianOutboxSendExecutor` send (either lane) exceeded its stall threshold before completing/reclaiming, or a reclaimed orphan's result was a thrown exception discarded for lack of anywhere correct to attribute it | `guardian_send_stalls` / `guardian_send_orphan_exceptions` | monitor (stall); diagnostic, not a loss (orphan-exception) |

Two related counters are reported alongside but are **not** journal loss channels:
`guardian_sweep_exceptions` (a firewalled convergence-sweep throw — drift
*detection* failing, not the audit trail) is kept separate on purpose, per
`guardian_journal_heartbeat.hpp`: a tag named `journal_maint_exceptions` counting
both would leave an operator unable to tell "audit trail at risk" from "detection
degraded", and the two need different remediation.

Two MAX-rolled-up age gauges (never summed fleet-wide — a single stalled endpoint
is the signal): `yuzu.guardian_journal_page_stale_seconds` and
`..._prune_stale_seconds`, emitted whenever journal stats are present (including
zero — a dead worker must not read identically to a healthy idle one). A third,
`..._headroom_blocked_seconds`, is sparse (0 = no replay-congestion episode, #2364).

**Not claimed:** end-to-end at-least-once (there is no server ack of an individual
lifecycle event, by design — Option A per the source doc); deterministic sub-second
ordering. `guard.errored` has exactly ONE lifecycle-journal producer today (#2818:
`GuardianSparkRuntime::on_subscription_lost`/`revalidate_subscriptions`, a spark
subscription-death detach) — dormant while `prefer_spark_=false`; other `errored`-status
paths (arm/boot failures) still journal nothing. All fleet counters are unlabelled or
low-cardinality — never keyed by raw `agent_id`.

**Standing invariant** (also recorded in §24): journal maintenance is paced by
time, not by wake count — the drain worker wakes on every outbox enqueue, and a
paging pass is a full journal scan, so any future maintenance work added to that
worker must carry its own `steady_clock` cadence or it becomes O(event rate ×
journal size) on every managed endpoint.

Data-inventory entry: `docs/enterprise-readiness-soc2-first-customer.md`,
agent-side `kv_store.db` namespaces.
