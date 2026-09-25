# Yuzu Cookbook

Practical examples for every plugin — YAML definitions, Python automation, CEL compliance expressions, and Dashboard UI walkthroughs. Each example shows real scope expressions so you can target all machines, a filtered subset, or machines identified by a previous instruction.

---

## How to Use This Guide

### Python Setup

All Python examples use the `requests` library with Bearer token authentication:

```python
import requests, time, json

YUZU = "https://yuzu.example.com"         # Your Yuzu server URL
TOKEN = "yuzu_abc123..."               # API token from Settings > API Tokens
HEADERS = {"X-Yuzu-Token": TOKEN, "Content-Type": "application/json"}

def execute(definition_id, scope="", params=None):
    """Execute an instruction and return the execution ID."""
    r = requests.post(f"{YUZU}/api/executions", headers=HEADERS, json={
        "definition_id": definition_id,
        "scope_expression": scope,
        "parameter_values": params or {}
    })
    r.raise_for_status()
    return r.json()["id"]

def wait_for(exec_id, timeout=120):
    """Poll until execution completes. Returns the execution summary."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{YUZU}/api/executions/{exec_id}/summary", headers=HEADERS)
        data = r.json()
        if data["status"] in ("completed", "failed", "cancelled"):
            return data
        time.sleep(2)
    raise TimeoutError(f"Execution {exec_id} did not complete in {timeout}s")

def get_responses(definition_id, exec_id=None, limit=1000):
    """Fetch result rows for a definition (optionally filtered by execution)."""
    params = {"limit": limit}
    if exec_id:
        params["execution_id"] = exec_id
    r = requests.get(f"{YUZU}/api/responses/{definition_id}", headers=HEADERS, params=params)
    r.raise_for_status()
    return r.json()
```

### Scope Expression Cheat Sheet

| Pattern | Meaning |
|---|---|
| *(empty string)* | All connected agents |
| `ostype == "windows"` | Windows machines only |
| `ostype == "linux"` | Linux machines only |
| `ostype == "darwin"` | macOS machines only |
| `tag:env == "production"` | Agents tagged with env=production |
| `hostname LIKE "web-*"` | Hostnames matching a wildcard |
| `hostname MATCHES "^db-\\d+$"` | Hostnames matching a regex |
| `arch IN ("x86_64", "aarch64")` | Multiple architectures |
| `ostype == "windows" AND tag:dept == "finance"` | Combined filters |
| `agent_id IN ("a1", "a2", "a3")` | Specific agents by ID |
| `NOT tag:quarantined == "true"` | Exclude tagged agents |

### CEL Expression Cheat Sheet

CEL expressions are used in PolicyFragment compliance checks to evaluate instruction results:

| Pattern | Meaning |
|---|---|
| `result.status == 'running'` | Exact string match |
| `result.count > 0` | Numeric comparison |
| `result.enabled == true` | Boolean check |
| `result.name.contains('yuzu')` | Substring search (case-insensitive) |
| `result.version.startsWith('2.')` | Prefix check |
| `result.host.matches('^web-\\d+$')` | Regex match |
| `result.status in ['running', 'starting']` | List membership |
| `result.score >= 80 ? 'pass' : 'fail'` | Ternary |
| `result.uptime_seconds > 86400 && result.status == 'running'` | Combined |
| `timestamp(result.last_check) + duration('1h') > timestamp(result.now)` | Time math |

---

## Part 1: Plugin Walkthroughs

### 1.1 OS Information (`os_info`)

Query operating system name, version, build, architecture, and uptime. The simplest plugin — no parameters, read-only, all platforms.

#### Actions

| Action | Definition ID | Description |
|---|---|---|
| `os_name` | `device.os_info.os_name` | OS product name (e.g., "Windows 11 Pro", "Ubuntu 24.04") |
| `os_version` | `device.os_info.os_version` | Kernel/version string |
| `os_build` | `device.os_info.os_build` | Build identifier (e.g., "22631.4890") |
| `os_arch` | `device.os_info.os_arch` | CPU architecture (x86_64, aarch64) |
| `uptime` | `device.os_info.uptime` | System uptime in seconds + display string |

#### YAML Definition

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: device.os_info.os_version
  displayName: OS Kernel / Version String
  version: 1.0.0
spec:
  type: question
  platforms: [windows, linux, darwin]
  execution:
    plugin: os_info
    action: os_version
  parameters:
    type: object
    properties: {}
  result:
    columns:
      - name: os_version
        type: string
      - name: os_product_version
        type: string
  approval:
    mode: auto
```

#### Python: Get OS Version from All Machines

```python
exec_id = execute("device.os_info.os_version")
wait_for(exec_id)
responses = get_responses("device.os_info.os_version", exec_id)
for row in responses:
    print(f"{row['agent_id']}: {row['output']['os_version']}")
```

#### Python: Get OS Version from Windows Machines Only

```python
exec_id = execute("device.os_info.os_version", scope='ostype == "windows"')
wait_for(exec_id)
```

#### Python: Get OS Name for Production Servers

```python
exec_id = execute("device.os_info.os_name",
                  scope='tag:env == "production" AND hostname LIKE "srv-*"')
wait_for(exec_id)
```

#### CEL Compliance Expression

Use in a PolicyFragment to flag machines running old OS builds:

```yaml
apiVersion: yuzu.io/v1alpha1
kind: PolicyFragment
metadata:
  id: policy.os_build_minimum
spec:
  check:
    ref: device.os_info.os_build
  compliance:
    expression: result.os_build >= '22631'
```

CEL for uptime monitoring (flag machines not rebooted in 30 days):

```cel
result.uptime_seconds < 2592000
```

#### Dashboard UI

1. Navigate to **Instructions > Definitions**
2. Find `device.os_info.os_version` in the list (or search for "os version")
3. Click **Execute** on the definition row
4. In the scope field, enter `ostype == "windows"` (or leave empty for all machines)
5. Click **Run** — no parameters needed
6. Switch to the **Executions** tab to monitor progress
7. Click the execution row to see per-agent results

---

### 1.2 Services (`services`)

Query and manage system services. Demonstrates both read-only queries and state-changing actions with parameters and approval gates.

#### Actions

| Action | Definition ID | Type | Description |
|---|---|---|---|
| `list` | `crossplatform.service.list` | question | List all installed services |
| `running` | `crossplatform.service.running` | question | List running services only |
| `set_start_mode` | `crossplatform.service.set_start_mode` | action | Change startup type (auto/manual/disabled) |

#### YAML Definition (Action with Parameters)

```yaml
apiVersion: yuzu.io/v1alpha1
kind: InstructionDefinition
metadata:
  id: crossplatform.service.set_start_mode
  displayName: Set Service Start Mode
  version: 1.0.0
spec:
  type: action
  platforms: [windows, linux, darwin]
  execution:
    plugin: services
    action: set_start_mode
  parameters:
    type: object
    required: [name, mode]
    properties:
      name:
        type: string
        displayName: Service Name
        validation:
          minLength: 1
          maxLength: 256
          pattern: "^[a-zA-Z0-9._@-]+$"
      mode:
        type: string
        displayName: Startup Mode
        validation:
          enum: [automatic, manual, disabled]
  result:
    columns:
      - name: status
        type: string
      - name: service
        type: string
      - name: mode
        type: string
  approval:
    mode: role-gated
```

#### Python: List Running Services on Tagged Machines

```python
exec_id = execute("crossplatform.service.running",
                  scope='tag:role == "webserver"')
summary = wait_for(exec_id)
print(f"Responded: {summary['agents_responded']}/{summary['agents_targeted']}")

responses = get_responses("crossplatform.service.running", exec_id)
for row in responses:
    print(f"{row['agent_id']}: {row['output']['name']} = {row['output']['status']}")
```

#### Python: Disable a Service on Production Machines

```python
exec_id = execute("crossplatform.service.set_start_mode",
                  scope='tag:env == "production" AND ostype == "windows"',
                  params={"name": "Spooler", "mode": "disabled"})
# This will require approval (role-gated) — check the Approvals tab
summary = wait_for(exec_id, timeout=300)
print(f"Success: {summary['agents_success']}, Failed: {summary['agents_failure']}")
```

#### CEL Compliance Expressions

Policy to ensure the Print Spooler is disabled:

```cel
result.status == 'stopped' && result.startup_type == 'disabled'
```

Policy to flag services with automatic start that are not running:

```cel
result.startup_type == 'automatic' && result.status != 'running'
```

#### Dashboard UI

**Querying services:**
1. **Instructions > Definitions** > find `crossplatform.service.running`
2. Click **Execute**, set scope to `tag:env == "production"`
3. Click **Run** — results appear in the Executions tab

**Changing a service (requires approval):**
1. Find `crossplatform.service.set_start_mode`
2. Click **Execute**
3. Fill in parameters: **Service Name** = `Spooler`, **Startup Mode** = `disabled`
4. Set scope: `ostype == "windows" AND tag:env == "staging"`
5. Click **Submit for Approval** (role-gated actions require admin approval)
6. An admin approves in **Instructions > Approvals**
7. Execution proceeds automatically after approval

---

### 1.3 Processes (`processes`)

List and query running processes. Demonstrates multi-row results and aggregation.

#### Actions

| Action | Definition ID | Description |
|---|---|---|
| `list` | `crossplatform.process.list` | List all running processes (PID + name) |
| `query` | `crossplatform.process.query` | Search processes by name substring |

#### Python: Check if a Process is Running Across the Fleet

```python
exec_id = execute("crossplatform.process.query",
                  scope='hostname LIKE "web-*"',
                  params={"name": "nginx"})
summary = wait_for(exec_id)

responses = get_responses("crossplatform.process.query", exec_id)
for row in responses:
    found = row["output"].get("found", "false")
    print(f"{row['agent_id']}: nginx {'RUNNING' if found == 'true' else 'NOT FOUND'}")
```

#### Python: Aggregate Process Count Across Fleet

```python
r = requests.get(f"{YUZU}/api/responses/crossplatform.process.list/aggregate",
                 headers=HEADERS,
                 params={"group_by": "name", "operation": "count", "limit": 20})
for entry in r.json():
    print(f"{entry['name']}: running on {entry['count']} machines")
```

#### CEL Compliance Expression

Policy: ensure a critical agent process is always running:

```cel
result.found == true
```

#### Dashboard UI

1. **Instructions > Definitions** > `crossplatform.process.query`
2. Click **Execute**
3. Enter parameter: **Process Name Filter** = `sshd`
4. Scope: `ostype == "linux"`
5. Click **Run**
6. In results, the `found` column shows `true`/`false` per agent

---

### 1.4 Filesystem (`filesystem`)

Secure file operations with path canonicalization. Demonstrates parameter-heavy definitions and the `base_dir` security constraint.

#### Key Actions (15 total)

| Action | Definition ID | Type | Description |
|---|---|---|---|
| `exists` | `device.filesystem.exists` | question | Check if a path exists |
| `list_dir` | `device.filesystem.list_dir` | question | List directory contents |
| `file_hash` | `device.filesystem.file_hash` | question | SHA-256 hash of a file |
| `read` | `device.filesystem.read` | question | Read file contents (size-limited) |
| `search` | `device.filesystem.search` | question | Search file for pattern matches |
| `replace` | `device.filesystem.replace` | action | Find and replace in a file |
| `write_content` | `device.filesystem.write_content` | action | Write content to a file |
| `create_temp` | `device.filesystem.create_temp` | question | Create a secure temp file |

#### Python: Check if a Config File Exists on Specific Machines

```python
exec_id = execute("device.filesystem.exists",
                  scope='agent_id IN ("agent-007", "agent-042")',
                  params={"path": "/etc/nginx/nginx.conf"})
summary = wait_for(exec_id)

responses = get_responses("device.filesystem.exists", exec_id)
for row in responses:
    exists = row["output"].get("exists", "false")
    print(f"{row['agent_id']}: {'EXISTS' if exists == 'true' else 'MISSING'}")
```

#### Python: Hash a Binary Across All Windows Machines

```python
exec_id = execute("device.filesystem.file_hash",
                  scope='ostype == "windows"',
                  params={
                      "path": "C:\\Windows\\System32\\cmd.exe",
                      "algorithm": "sha256"
                  })
wait_for(exec_id)
responses = get_responses("device.filesystem.file_hash", exec_id)

# Find machines with unexpected hashes
known_hash = "abc123..."  # expected hash
for row in responses:
    if row["output"].get("hash") != known_hash:
        print(f"ALERT: {row['agent_id']} has unexpected cmd.exe hash!")
```

#### CEL Compliance Expressions

Policy: critical config file must exist:

```cel
result.exists == true && result.type == 'file'
```

Policy: file hash must match known-good value:

```cel
result.hash == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
```

#### Dashboard UI

1. **Instructions > Definitions** > `device.filesystem.exists`
2. Click **Execute**
3. Parameters: **Path** = `/etc/ssh/sshd_config`, **Base Directory** = `/etc` (optional restriction)
4. Scope: `ostype == "linux" AND tag:role == "server"`
5. Click **Run**

---

### 1.5 Network Configuration (`network_config`)

Network interface and connectivity information. Demonstrates platform-specific filtering.

#### Python: Get Network Interfaces on Linux Servers

```python
exec_id = execute("device.network_config.ip_addresses",
                  scope='ostype == "linux" AND tag:env == "production"')
wait_for(exec_id)
responses = get_responses("device.network_config.ip_addresses", exec_id)
for row in responses:
    print(f"{row['agent_id']}: {row['output'].get('name')} = {row['output'].get('ip_address')}")
```

#### Python: DNS Resolution Test

```python
exec_id = execute("device.network_actions.ping",
                  scope='ostype == "windows"',
                  params={"hostname": "internal-api.corp.example.com"})
wait_for(exec_id)
```

#### CEL Compliance Expression

Policy: DNS must resolve the internal API hostname:

```cel
result.resolved == true && result.ip_address != ''
```

---

### 1.6 Installed Applications (`installed_apps`)

Software inventory across all platforms. Demonstrates management group scoping and version compliance.

#### Python: Get All Installed Software in a Management Group

```python
# Scope by management group
exec_id = execute("crossplatform.software.inventory",
                  scope='management_group == "Finance Department"')
wait_for(exec_id)
responses = get_responses("crossplatform.software.inventory", exec_id)

# Find machines with outdated Java
# `output` holds many newline-joined rows, each app|name|version|publisher|install_date|
# install_location|bundle_id (seven escape-aware tokens on plugin >= 1.2.0; an older
# agent emits five and does not escape `|`, so only 5- or 7-token lines are accepted).
import re
def split_row(line):
    return [t.replace("\\|", "|") for t in re.split(r"(?<!\\)\|", line)]
for row in responses:
    for line in row["output"].splitlines():
        if not line:
            continue
        tokens = split_row(line)
        if tokens[0] != "app" or len(tokens) not in (5, 7):
            continue
        name, version = tokens[1], tokens[2]
        if "java" in name.lower() and version < "21.0":
            print(f"OUTDATED JAVA: {row['agent_id']} has {name} {version}")
```

#### CEL Compliance Expression

CEL sees this definition's result as one raw `output` string (no `name`/`version` fields), so a version comparison is not expressible there; use the Python route above, or a substring test on `output` with the caveat that it also matches the publisher, install path and bundle identifier.

---

### 1.7 Registry (`registry`) -- Windows Only

Windows registry operations. Since the plugin is Windows-only, scope expressions implicitly target Windows.

#### Python: Read a Registry Value from All Windows Machines

```python
exec_id = execute("windows.registry.get_value",
                  scope='ostype == "windows"',
                  params={
                      "hive": "HKLM",
                      "key": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      "value": "CurrentBuildNumber"
                  })
wait_for(exec_id)
responses = get_responses("windows.registry.get_value", exec_id)
for row in responses:
    build = row["output"].get("data", "unknown")
    print(f"{row['agent_id']}: Windows Build {build}")
```

#### CEL Compliance Expression

Policy: Windows build must be 22621 or higher (Windows 11 22H2+):

```cel
int(result.data) >= 22621
```

#### Dashboard UI

1. **Instructions > Definitions** > `windows.registry.get_value`
2. Click **Execute**
3. Parameters: **Hive** = `HKLM`, **Key** = `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, **Value** = `CurrentBuildNumber`
4. Scope: leave empty (Windows-only plugin only runs on Windows agents)
5. Click **Run**

---

### 1.8 Script Execution (`script_exec`)

Execute PowerShell, Bash, or generic scripts on endpoints. This is the highest-risk plugin and always requires approval.

#### Python: Run a PowerShell Command on a Single Machine

```python
exec_id = execute("crossplatform.script.powershell",
                  scope='agent_id == "agent-007"',
                  params={
                      "command": "Get-Process | Where-Object {$_.CPU -gt 100} | Select-Object Name, CPU"
                  })
# Role-gated: check Approvals tab
summary = wait_for(exec_id, timeout=300)
```

#### Python: Run a Bash Script on Linux Fleet

```python
exec_id = execute("crossplatform.script.bash",
                  scope='ostype == "linux" AND tag:env == "staging"',
                  params={
                      "command": "df -h / | tail -1 | awk '{print $5}'"
                  })
summary = wait_for(exec_id, timeout=300)
responses = get_responses("crossplatform.script.bash", exec_id)
for row in responses:
    print(f"{row['agent_id']}: disk usage = {row['output'].get('stdout', 'N/A')}")
```

#### Dashboard UI

1. **Instructions > Definitions** > `crossplatform.script.bash`
2. Click **Execute**
3. Parameters: **Command** = `uptime`
4. Scope: `hostname == "buildserver-01"` (always scope tightly for scripts)
5. Click **Submit for Approval** (scripts always require approval)
6. Admin approves in **Approvals** tab

---

### 1.9 Vulnerability Scan (`vuln_scan`)

Scan endpoints for known CVEs. Demonstrates security workflows with severity-based CEL.

#### Python: Scan All Machines for Vulnerabilities

```python
exec_id = execute("security.vuln_scan.scan")  # empty scope = all machines
summary = wait_for(exec_id, timeout=600)  # scans take longer
print(f"Scanned {summary['agents_success']} machines")

responses = get_responses("security.vuln_scan.scan", exec_id)
critical = [r for r in responses if r["output"].get("severity") in ("critical", "high")]
print(f"Found {len(critical)} critical/high vulnerabilities across fleet")
```

#### CEL Compliance Expression

Policy: no critical vulnerabilities allowed:

```cel
result.severity != 'critical' && result.severity != 'high'
```

Policy: CVSS score must be below threshold:

```cel
result.cvss_score < 7.0
```

---

### 1.10 Hardware (`hardware`)

Hardware inventory with no parameters. Demonstrates simple asset tracking.

#### Python: Collect Hardware Inventory from All Machines

```python
for action in ["manufacturer", "model", "processors", "memory", "disks"]:
    exec_id = execute(f"device.hardware.{action}")
    wait_for(exec_id)

# Query manufacturer results
responses = get_responses("device.hardware.manufacturer")
for row in responses:
    print(f"{row['agent_id']}: {row['output'].get('manufacturer', 'Unknown')}")
```

#### CEL Compliance Expression

Policy: minimum 8 GB RAM required:

```cel
result.total_memory_mb >= 8192
```

---

## Part 2: Chaining Instructions

### Scenario: "Find OS version for all Windows machines that connected to https://example.com in the last 90 days"

#### Query Plan

Apply the cheapest filters first to minimize work at each stage:

| Step | What | Why first | Cost |
|---|---|---|---|
| 1 | Scope to `ostype == "windows"` | Attribute check, instant | Free (scope engine) |
| 2 | Query TAR for network events matching `example.com` | SQLite SELECT on agent-side TAR DB | Medium (per-agent DB query) |
| 3 | Run `os_info.os_version` on matching agents only | Only runs on the filtered set | Low (small target set) |

The key insight: **use the TAR (Timeline Activity Record), not netstat.** `netstat` only shows *current* connections. The TAR continuously records network connection events (opened/closed) with timestamps, so it has 90 days of history. Each TAR network event stores both the IP and the DNS hostname (resolved at collection time):

```json
{"proto":"tcp", "local_addr":"10.0.1.5", "local_port":52341,
 "remote_addr":"93.184.216.34", "remote_host":"example.com",
 "remote_port":443, "state":"ESTABLISHED",
 "pid":1234, "process_name":"chrome.exe"}
```

The `remote_host` field is resolved via reverse DNS at the moment the connection is first recorded by the TAR collector. This means hostname searches are just a string match against stored data — no DNS resolution at query time.

#### Complete Python Script

```python
import requests, time, json

YUZU = "https://yuzu.example.com"
TOKEN = "yuzu_abc123..."
HEADERS = {"X-Yuzu-Token": TOKEN, "Content-Type": "application/json"}

TARGET_HOSTNAME = "example.com"
DAYS_BACK = 90

def execute(definition_id, scope="", params=None):
    r = requests.post(f"{YUZU}/api/executions", headers=HEADERS, json={
        "definition_id": definition_id,
        "scope_expression": scope,
        "parameter_values": params or {}
    })
    r.raise_for_status()
    return r.json()["id"]

def wait_for(exec_id, timeout=300):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{YUZU}/api/executions/{exec_id}/summary", headers=HEADERS)
        data = r.json()
        if data["status"] in ("completed", "failed", "cancelled"):
            return data
        time.sleep(3)
    raise TimeoutError(f"Execution {exec_id} timed out")

def get_responses(definition_id, exec_id=None, limit=10000):
    params = {"limit": limit}
    if exec_id:
        params["execution_id"] = exec_id
    r = requests.get(f"{YUZU}/api/responses/{definition_id}",
                     headers=HEADERS, params=params)
    r.raise_for_status()
    return r.json()

# ── Step 1: Query TAR on Windows machines for network events ─────────────
# Scope to Windows first (cheapest filter — just an attribute check).
# Then query the TAR for network events in the last 90 days.
since_epoch = int(time.time()) - (DAYS_BACK * 86400)

print(f"Step 1: Querying TAR network events on all Windows machines (last {DAYS_BACK} days)...")
exec1 = execute("crossplatform.tar.query",
                scope='ostype == "windows"',
                params={
                    "from": str(since_epoch),
                    "type": "network",
                    "limit": "10000"
                })
summary1 = wait_for(exec1, timeout=600)
print(f"  Received responses from {summary1['agents_responded']} agents")

# ── Step 2: Filter TAR results for connections to our target hostname ────
# TAR stores remote_host (DNS name resolved at collection time), so this
# is a simple string match — no DNS resolution needed at query time.
print(f"Step 2: Filtering for connections to {TARGET_HOSTNAME}...")
responses = get_responses("crossplatform.tar.query", exec1)

matching_agents = set()
for row in responses:
    detail_str = row.get("output", {}).get("detail_json", "")
    if not detail_str:
        continue
    try:
        detail = json.loads(detail_str)
        remote_host = detail.get("remote_host", "")
        if TARGET_HOSTNAME in remote_host:
            matching_agents.add(row["agent_id"])
    except json.JSONDecodeError:
        continue

print(f"  Found {len(matching_agents)} Windows machines that connected to {TARGET_HOSTNAME}")

if not matching_agents:
    print("  No matching machines found. Done.")
    exit(0)

# ── Step 3: Get OS version from only those machines ──────────────────────
# This is the lightest operation — runs only on the filtered set.
agent_list = ", ".join(f'"{aid}"' for aid in matching_agents)
scope_expr = f"agent_id IN ({agent_list})"

print(f"Step 3: Getting OS version from {len(matching_agents)} machines...")
exec3 = execute("device.os_info.os_version", scope=scope_expr)
summary3 = wait_for(exec3)

# ── Results ──────────────────────────────────────────────────────────────
print(f"\nWindows machines that connected to {TARGET_HOSTNAME} in the last {DAYS_BACK} days:")
print("-" * 70)
os_responses = get_responses("device.os_info.os_version", exec3)
for row in os_responses:
    version = row.get("output", {}).get("os_version", "unknown")
    product = row.get("output", {}).get("os_product_version", "")
    agent = row["agent_id"]
    print(f"  {agent}: {version} ({product})")
print(f"\nTotal: {len(os_responses)} machines")
```

#### Why This Order Matters

```
All agents (e.g., 10,000)
    │
    ▼ scope: ostype == "windows"    ← FREE (attribute check)
Windows agents (e.g., 6,000)
    │
    ▼ TAR query: network events     ← MEDIUM (SQLite SELECT per agent)
Connected to example.com (e.g., 47)
    │
    ▼ os_info.os_version            ← CHEAP (47 agents, not 6,000)
Final results (47 rows)
```

If you reversed the order and ran `os_info` on all 10,000 agents first, you'd gather 10,000 OS version responses only to discard 9,953 of them. By filtering first with the TAR, you avoid dispatching unnecessary work to thousands of agents.

#### Dashboard UI Walkthrough

**Manual three-step approach:**

1. **Step 1: Query TAR on Windows fleet**
   - **Instructions > Definitions** > `crossplatform.tar.query`
   - Scope: `ostype == "windows"`
   - Parameters: **Start Time** = epoch for 90 days ago (e.g., `1719500000`), **Event Type Filter** = `network`, **Result Limit** = `10000`
   - Click **Run**

2. **Step 2: Review TAR results**
   - **Instructions > Executions** > click the TAR query execution
   - In the results, look at the `detail_json` column for `remote_addr` values matching the target IP (e.g., `93.184.216.34` for example.com)
   - Note the agent IDs of matching machines

3. **Step 3: Run os_version on matching machines**
   - **Instructions > Definitions** > `device.os_info.os_version`
   - Scope: `agent_id IN ("agent-007", "agent-042", ...)` (paste the IDs from step 2)
   - Click **Run**
   - Results show OS versions for only the machines that connected to the target

---

## Part 3: Quick Reference

Every plugin and action at a glance. Use Part 1 walkthroughs for detailed examples.

**Legend:** Q = question (read-only), A = action (state-changing) | W = Windows, L = Linux, M = macOS

### System & Identity

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `device.os_info.os_name` | os_name | Q | WLM | *(none)* | os_name:string |
| `device.os_info.os_version` | os_version | Q | WLM | *(none)* | os_version:string, os_product_version:string |
| `device.os_info.os_build` | os_build | Q | WLM | *(none)* | os_build:string |
| `device.os_info.os_arch` | os_arch | Q | WLM | *(none)* | os_arch:string |
| `device.os_info.uptime` | uptime | Q | WLM | *(none)* | uptime_seconds:int64, uptime_display:string |
| `device.hardware.manufacturer` | manufacturer | Q | WLM | *(none)* | manufacturer:string |
| `device.hardware.model` | model | Q | WLM | *(none)* | model:string |
| `device.hardware.bios` | bios | Q | WLM | *(none)* | vendor:string, version:string, date:string |
| `device.hardware.processors` | processors | Q | WLM | *(none)* | model:string, cores:int32, clock_mhz:int32 |
| `device.hardware.memory` | memory | Q | WLM | *(none)* | total_mb:int64, slots:int32, speed_mhz:int32 |
| `device.hardware.disks` | disks | Q | WLM | *(none)* | model:string, size_gb:int64, interface:string |
| `device.identity.device_name` | device_name | Q | WLM | *(none)* | hostname:string |
| `device.identity.domain` | domain | Q | WLM | *(none)* | domain:string, domain_type:string |
| `device.identity.ou` | ou | Q | WLM | *(none)* | ou:string |
| `crossplatform.storage.free` | free | Q | WLM | path:string (optional, default = volume root) | path:string, total_bytes:int64, free_bytes:int64, percent_used:int32 |
| `device.diagnostics.cpu_usage` | cpu_usage | Q | WLM | *(none)* | cpu_percent:int32 |
| `device.diagnostics.memory_usage` | memory_usage | Q | WLM | *(none)* | total_mb:int64, used_mb:int64, percent:int32 |

### Process & Service

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `crossplatform.process.list` | list | Q | WLM | *(none)* | pid:int64, name:string |
| `crossplatform.process.query` | query | Q | WLM | name:string (req) | found:bool, pid:int64, name:string |
| `crossplatform.service.list` | list | Q | WLM | *(none)* | name:string, display_name:string, status:string, startup_type:string |
| `crossplatform.service.running` | running | Q | WLM | *(none)* | name:string, display_name:string, status:string, startup_type:string |
| `crossplatform.service.set_start_mode` | set_start_mode | A | WLM | name:string (req), mode:enum (req) | status:string, service:string, mode:string |

### User & Session

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `device.users.list` | list | Q | WLM | *(none)* | username:string, full_name:string, enabled:bool |
| `device.users.logged_in` | logged_in | Q | WLM | *(none)* | username:string, session_type:string, login_time:string |
| `device.users.groups` | groups | Q | WLM | *(none)* | group_name:string, members:string |
| `device.users.admin_check` | admin_check | Q | WLM | *(none)* | username:string, is_admin:bool |

### Network

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `device.network_config.adapters` | adapters | Q | WLM | *(none)* | name:string, mac:string, speed_mbps:int64, status:string |
| `device.network_config.ip_addresses` | ip_addresses | Q | WLM | *(none)* | adapter:string, address:string, prefix_length:int32, gateway:string |
| `device.network_config.dns_servers` | dns_servers | Q | WLM | *(none)* | adapter:string, server:string, type:string |
| `device.network_config.proxy` | proxy | Q | WLM | *(none)* | proxy_type:string, proxy_address:string, bypass:string |
| `device.network_config.dns_cache` | dns_cache | Q | WLM | *(none)* | name:string, record_type:string, ttl:int32 |
| `device.network.netstat_list` | netstat | Q | WLM | *(none)* | proto:string, local_addr:string, local_port:int32, remote_addr:string, remote_port:int32, state:string, pid:int32 |
| `device.network_diag.listening` | listening | Q | WLM | *(none)* | proto:string, local_addr:string, local_port:int32, pid:int32 |
| `device.network_diag.connections` | connections | Q | WLM | *(none)* | proto:string, local_addr:string, remote_addr:string, remote_port:int32, pid:int32 |
| `device.network.netstat_attribution` | attribution | Q | WLM | *(none)* | proto:string, local_addr:string, local_port:int32, remote_addr:string, remote_port:int32, state:string, pid:int32, process_name:string, process_path:string |
| `device.network_actions.flush_dns` | flush_dns | A | WLM | *(none)* | status:string, output:string |
| `device.network_actions.ping` | ping | A | WLM | host:string (req) | output:string |
| `device.wifi.list_networks` | wifi scan | Q | WLM | *(none)* | ssid:string, signal:string, security:string |
| `device.wifi.connected` | wifi status | Q | WLM | *(none)* | ssid:string, signal:string, security:string, bssid:string |
| `device.wol.wake` | wake | A | WLM | mac:string (req), port:string | status:string, bytes_sent:string |
| `device.discovery.scan_subnet` | discovery | Q | WLM | subnet:string (req) | ip_address:string, hostname:string, mac_address:string, managed:string |

### Software & Patch

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `crossplatform.software.inventory` | list | Q | WLM | *(none)* | name:string, version:string, publisher:string, install_date:string, install_location:string, bundle_id:string |
| `crossplatform.software.query` | query | Q | WLM | name:string (req) | found:bool, name:string, version:string, publisher:string |
| `device.software_actions.list_upgradable` | upgradable | Q | WLM | *(none)* | package_name:string, current_version:string, available_version:string |
| `device.software_actions.installed_count` | count | Q | WLM | *(none)* | count:int32 |
| `windows.software.msi.list` | msi list | Q | W | *(none)* | product_code:guid, name:string, version:string |
| `windows.software.msi.product_codes` | msi codes | Q | W | *(none)* | product_code:guid, name:string |
| `device.windows_updates.installed` | installed updates | Q | WLM | *(none)* | identifier:string, description:string, install_date:string |
| `device.windows_updates.missing` | missing updates | Q | WLM | *(none)* | title:string, severity:string |
| `device.windows_updates.pending_reboot` | pending reboot | Q | WLM | *(none)* | source:string, pending:bool, detail:string |

### Security

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `security.antivirus.products` | products | Q | WLM | *(none)* | name:string, state:string |
| `security.antivirus.defender_status` | defender | Q | W | *(none)* | realtime_protection:string, definition_version:string, last_update:string |
| `security.antivirus.xprotect_status` | status | Q | M | *(none)* | definition_version:string, last_update:string, remediator_version:string, mrt_version:string |
| `security.firewall.state` | state | Q | WLM | *(none)* | profile_or_backend:string, state:string |
| `security.firewall.rules` | rules | Q | WLM | *(none)* | rule_name:string, enabled:string, direction:string, action:string |
| `security.certificates.list` | list | Q | WLM | store:string, expiring_within_days:int32 | subject:string, issuer:string, thumbprint:string, not_after:string |
| `security.certificates.details` | details | Q | WLM | thumbprint:string (req) | subject:string, issuer:string, thumbprint:string, serial:string |
| `security.certificates.delete` | delete | A | WLM | thumbprint:string (req), store:string | status:string |
| `device.event_logs.errors` | errors | Q | WLM | log:string, hours:int32 | timestamp:string, event_id:string, source:string, message:string |
| `device.event_logs.query` | query | Q | WLM | log:string (req), filter:string (req), count:int32 | timestamp:string, level:string, event_id:string, message:string |
| `security.ioc.check` | ioc check | Q | WLM | ip_addresses:string, domains:string, file_hashes:string | type:string, value:string, matched:bool, detail:string |
| `security.vuln_scan.scan` | vuln scan | Q | WLM | *(none)* | severity:string, category:string, title:string, detail:string |
| `security.vuln_scan.summary` | vuln summary | Q | WLM | *(none)* | severity:string, count:int32 |
| `security.encryption.state` | bitlocker | Q | WLM | *(none)* | volume:string, protection_status:string, encryption_method:string |
| `security.quarantine.status` | status | Q | WLM | *(none)* | state:string, whitelist:string |
| `security.quarantine.isolate` | isolate | A | WLM | server_ip:string, whitelist_ips:string | status:string, rules_applied:int32 |
| `security.quarantine.release` | release | A | WLM | *(none)* | status:string |
| `security.sccm.client_version` | sccm version | Q | W | *(none)* | installed:bool, version:string, service_status:string |

### File System

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `device.filesystem.exists` | exists | Q | WLM | path:string (req), base_dir:string | exists:bool, type:string, size:int64 |
| `device.filesystem.list_dir` | list_dir | Q | WLM | path:string (req), base_dir:string | entry_name:string, entry_type:string, size:int64 |
| `device.filesystem.file_hash` | file_hash | Q | WLM | path:string (req), algorithm:string | hash:string, algorithm:string, size:int64 |
| `device.filesystem.read` | read | Q | WLM | path:string (req), base_dir:string, max_bytes:int32 | content:clob, size:int64 |
| `device.filesystem.search` | search | Q | WLM | path:string (req), pattern:string (req), base_dir:string | total_matches:int32, line:int32, text:string |
| `device.filesystem.replace` | replace | A | WLM | path:string (req), search:string (req), replace:string (req) | replacements_made:int32 |
| `device.filesystem.write_content` | write_content | A | WLM | path:string (req), content:string (req) | status:string, bytes_written:int64 |
| `device.filesystem.create_temp` | create_temp | Q | WLM | prefix:string | path:string |
| `device.filesystem.delete` | delete | A | WLM | path:string (req) | status:string |
| `device.filesystem.copy` | copy | A | WLM | source:string (req), dest:string (req) | status:string, bytes:int64 |
| `device.filesystem.move` | move | A | WLM | source:string (req), dest:string (req) | status:string |
| `device.filesystem.mkdir` | mkdir | A | WLM | path:string (req) | status:string |
| `device.filesystem.permissions` | permissions | Q | WLM | path:string (req) | owner:string, group:string, mode:string |
| `device.filesystem.set_permissions` | set_permissions | A | WLM | path:string (req), mode:string (req) | status:string |
| `device.filesystem.disk_usage` | disk_usage | Q | WLM | path:string (req) | total_bytes:int64, used_bytes:int64, free_bytes:int64 |

### Execution

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `crossplatform.script.exec` | exec | A | WLM | command:string (req), timeout:int32 | exit_code:int32, stdout:clob, stderr:clob |
| `crossplatform.script.powershell` | powershell | A | W | command:string (req), timeout:int32 | exit_code:int32, stdout:clob, stderr:clob |
| `crossplatform.script.bash` | bash | A | LM | command:string (req), timeout:int32 | exit_code:int32, stdout:clob, stderr:clob |

### HTTP & Content Distribution

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `device.http.get` | get | Q | WLM | url:string (req), headers:string | status_code:int32, body:clob, content_type:string |
| `device.http.download` | download | A | WLM | url:string (req), dest:string (req), hash:string | status:string, bytes:int64, hash_ok:bool |
| `device.content.deploy` | deploy | A | WLM | package_id:string (req), dest:string (req) | status:string, files:int32 |

### Windows Depth

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `windows.registry.get_value` | get_value | Q | W | hive:enum (req), key:string (req), name:string (req) | value:string, type:string |
| `windows.registry.get_user_value` | get_user_value | Q | W | username:string, sid:string, key:string (req), name:string | username:string, value:string, type:string |
| `windows.registry.list_profiles` | list_profiles | Q | W | (none) | sid:string, profile_name:string, profile_path:string, hive_state:string |
| `windows.registry.set_value` | set_value | A | W | hive:enum (req), key:string (req), name:string (req), value:string (req), type:enum | status:string |
| `windows.registry.delete_value` | delete_value | A | W | hive:enum (req), key:string (req), name:string (req) | status:string |
| `windows.registry.delete_key` | delete_key | A | W | hive:enum (req), key:string (req) | status:string |
| `windows.registry.enumerate_keys` | enum_keys | Q | W | hive:enum (req), key:string (req) | subkey:string |
| `windows.registry.enumerate_values` | enum_values | Q | W | hive:enum (req), key:string (req) | name:string, type:string |
| `windows.registry.key_exists` | key_exists | Q | W | hive:enum (req), key:string (req) | exists:bool |
| `windows.wmi.query` | wmi query | Q | W | wql:string (req), namespace:string | property:string, value:string |
| `windows.wmi.get_instance` | wmi get | Q | W | class:string (req), namespace:string | property:string, value:string |

### Agent Infrastructure

| Definition ID | Action | Type | Platforms | Parameters | Result Columns |
|---|---|---|---|---|---|
| `device.status.version` | version | Q | WLM | *(none)* | version:string, build_number:string, git_commit:string |
| `device.status.info` | info | Q | WLM | *(none)* | os:string, arch:string, hostname:string |
| `device.status.health` | health | Q | WLM | *(none)* | uptime_seconds:int64, memory_rss_kb:int64 |
| `device.status.plugins` | plugins | Q | WLM | *(none)* | plugins_count:int32, plugin_name:string, plugin_version:string |
| `device.status.connection` | connection | Q | WLM | *(none)* | server_address:string, tls_enabled:bool, log_level:string |
| `device.status.config` | config | Q | WLM | *(none)* | agent_id:string, agent_version:string, server_address:string |
| `device.agent_actions.set_log_level` | set_log_level | A | WLM | level:enum (req) | status:string, level:string |
| `device.agent_actions.info` | agent info | Q | WLM | *(none)* | agent_id:string, agent_version:string, server_address:string, heartbeat_interval:string, plugins_count:int32 |
| `device.agent_logging.get_log` | get log | Q | WLM | lines:int32 | log_file:string, line_count:int32, line:string |
| `device.tags.set` | set tag | A | WLM | key:string (req), value:string | key:string, value:string |
| `device.tags.get` | get tag | Q | WLM | key:string (req) | key:string, value:string |
| `device.tags.get_all` | list tags | Q | WLM | *(none)* | key:string, value:string, count:int32 |
| `device.tags.delete` | delete tag | A | WLM | key:string (req) | key:string, found:bool |
| `agent.storage.set` | set kv | A | WLM | key:string (req), value:string (req) | status:string, key:string |
| `agent.storage.get` | get kv | Q | WLM | key:string (req) | key:string, value:string |
| `agent.storage.list` | list kv | Q | WLM | prefix:string | count:int32, key:string |

### Python Quick-Reference Snippets

```python
# ── One-liner examples for common operations ─────────────────────────────

# Get OS name from all machines
execute("device.os_info.os_name")

# List services on production Windows
execute("crossplatform.service.list", scope='ostype == "windows" AND tag:env == "production"')

# Check if nginx is running on web servers
execute("crossplatform.process.query", scope='hostname LIKE "web-*"', params={"name": "nginx"})

# Hash a file across all Linux machines
execute("device.filesystem.file_hash", scope='ostype == "linux"',
        params={"path": "/usr/bin/ssh", "algorithm": "sha256"})

# Read a registry value on Windows
execute("windows.registry.get_value", scope='ostype == "windows"',
        params={"hive": "HKLM", "key": "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                "value": "ProductName"})

# Run a PowerShell command on one machine
execute("crossplatform.script.powershell", scope='agent_id == "agent-007"',
        params={"command": "Get-ComputerInfo | Select-Object OsName, OsVersion"})

# Scan for vulnerabilities fleet-wide
execute("security.vuln_scan.scan")

# Get hardware inventory
execute("device.hardware.manufacturer")
execute("device.hardware.memory")
execute("device.hardware.disks")

# Check antivirus status on all endpoints
execute("security.antivirus.products")

# Get network connections (for chaining)
execute("device.network.netstat_list", scope='ostype == "windows"')

# Deploy content package
execute("device.content.deploy", params={"package_id": "pkg-001", "dest": "/opt/myapp"})
```
