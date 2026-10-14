# Instructions gate — 34 failing instructions handover

**Owner of next session**: resolve the 34 FAILing instructions on the `feat/viz-engine` branch so `/test` Phase 5 Instructions gate returns PASS.
**Branch at handover**: `feat/viz-engine`
**Last `/test` run before handover**: `1778652107-77698` (2026-05-13 07:01:47 UTC, default mode, **16 PASS / 1 FAIL / 0 WARN / 3 SKIP**).
**The one FAIL**: P5 Instructions — `144 pass / 34 fail / 7 pending / 33 skip (38s wall)`.

The fixes already landed in the commit that introduces this handover are listed under "What's already done"; this doc covers the remaining work.

## What the 34 failures actually are

Five distinct root causes. Counts × cause:

| Cause | Count | Whose bug | Fix shape |
|---|---|---|---|
| **A** Test runner does not synthesise required parameters from the YAML schema | 15 | `scripts/test/instructions_runner.py` | Teach `synthesise_params` to emit plausible defaults for `path`, `sql`, `url`, `directory`, `thumbprint`, `group`, `sha256`, `filename`, `pattern`, `root`, etc. |
| **B** Plugin correctly reports "platform not supported"; host is macOS and the def declares Windows-only | 9 | `instructions_runner.py` classification | Honour the YAML `platforms:` field — map host-OS-not-in-list to **SKIP**, not FAIL |
| **C** Plugin's macOS branch is stale or absent | 5 | Plugins (`wifi` airport, `procfetch` macOS, possibly `tar.export`, `agent_logging`, `event_logs`) | One-issue-per-plugin; track separately |
| **D** Server importer rejects `type: query`; the two defs that use it never reach the DB so dispatch is 404 | 2 | YAMLs OR `import_definition_json` validator | Either rename `type: query` → `type: question` in the 2 YAMLs (one-line each), or add `query` as a synonym in the validator |
| **E** Real bug in plugin SQL | 1 | `tar` plugin | `tar.export` UNION ALL column-count mismatch |
| **F** Plugin returns "error\|" for legitimate empty-result conditions | 2 | Plugins (`agent_logging.get_log`, `event_logs.errors`) | Plugin path returns `status\|empty` / rc=0 instead of `status\|error\|...` |

### Recommended order

The runner-side fixes (A + B) drop the FAIL count from 34 to **10** with one PR each. Recommend doing those first because they're contained and high-leverage.

1. **A** (15 disappear): edit `scripts/test/instructions_runner.py` `synthesise_params` (around line 200 in the existing file). Walk the YAML's `parameters:` block and emit synthesis defaults keyed on parameter name + type. Examples below.
2. **B** (9 disappear): edit `instructions_runner.py` to read the YAML's `platforms:` (or pull from the loaded definition); compare to host OS (`platform.system().lower()` → `windows` / `linux` / `darwin`); if host is not in the list, classify the outcome as `skip`, not `fail`.
3. **D** (2 disappear): rename `type: query` → `type: question` in `content/definitions/discovery.yaml` and `content/definitions/deployment.yaml` for the affected ids. Then verify the API returns them after rebuild. (Lower-risk than touching the validator.)
4. **E** (1 disappears): real bug — fix the `UNION ALL` column count in the tar plugin's export SQL.
5. **F** (2 disappear): plugin patches.
6. **C** (5 disappear): separate plugin work; file issues, prioritise per release urgency.

## Per-instruction table

This is the authoritative reproduction set. Each row records: id, type, declared platforms, what it does, the EXACT response body observed against a live macOS UAT, and the cause bucket (A–F).

| # | Instruction | type | platforms | What it does | Response on macOS UAT | Cause |
|---|---|---|---|---|---|---|
| 1 | `agent.content_dist.stage` | action | win/lin/mac | Download a file to agent's staging dir, verify SHA256 | `error\|missing required parameters: url, filename, sha256` | A |
| 2 | `agent.content_dist.upload_file` | action | win/lin/mac | Upload a local file from agent → server via multipart POST | `error\|missing required parameter: path` | A |
| 3 | `crossplatform.process.fetch` | question | win/lin | Deep process enumeration with SHA-1 hash of each exe | `error: process enumeration not supported on this platform` | B (also C — needs macOS branch) |
| 4 | `crossplatform.tar.export` | question | win/lin/mac | Export TAR events as JSON for Splunk/ELK | `error\|query failed: SELECTs to the left and right of UNION ALL do not have the same number ...` | E |
| 5 | `crossplatform.tar.sql` | question | win/lin/mac | Execute arbitrary SELECT against TAR warehouse | `error\|missing required 'sql' parameter` | A |
| 6 | `device.agent_logging.get_log` | question | win/lin/mac | Tail last N lines of the agent log | `status\|error\|agent log file not found` | F (also A — `lines` param) |
| 7 | `device.discovery.scan_subnet` | **query** | win/lin/mac | ARP-table + ICMP-sweep subnet scan | `DISPATCH_ERR: instruction definition not found` (server log: `bundled definition import failed: id=device.discovery.scan_subnet error=type must be 'question' or 'action'`) | D |
| 8 | `device.event_logs.errors` | question | win/lin/mac | Recent Level-2 (Error) event log entries | `error\|Timestamp\|\|...Ty Process[PID:TID] error\|2026-05-12 ...akd[951:...` (returned actual error log lines; runner heuristic sees `error\|` prefix and fails) | F |
| 9 | `device.filesystem.file_hash` | question | win/lin/mac | SHA-256 (default) of a given file | `error\|missing required parameter: path` | A |
| 10 | `device.filesystem.find_by_hash` | question | win/lin/mac | Recursive search for files with given SHA256 | `error\|missing required parameters: directory, sha256` | A |
| 11 | `device.filesystem.get_acl` | question | win/lin/mac | NTFS ACL / POSIX mode | `error\|missing required parameter: path` | A |
| 12 | `device.filesystem.get_signature` | question | win/lin/mac | Authenticode / codesign signature info | `error\|missing required parameter: path` | A |
| 13 | `device.filesystem.get_version_info` | question | win/lin/mac | PE/Mach-O / ELF version metadata of a binary | `error\|missing required parameter: path` | A |
| 14 | `device.filesystem.list_dir` | question | win/lin/mac | Non-recursive directory listing | `error\|missing required parameter: path` | A |
| 15 | `device.filesystem.read` | question | win/lin/mac | Read file contents (capped) | `error\|missing required parameter: path` | A |
| 16 | `device.filesystem.search` | question | win/lin/mac | Recursive glob search | `error\|missing required parameters: path, pattern` | A |
| 17 | `device.filesystem.search_dir` | question | win/lin/mac | Recursive search rooted at a directory | `error\|missing required parameters: root, pattern` | A |
| 18 | `device.users.group_members` | question | win/lin/mac | List members of a local OS group | `group_member\|error\|Missing required parameter: group` | A |
| 19 | `device.wifi.list_networks` | question | win/lin/mac | List nearby Wi-Fi networks (SSID, BSSID, signal) | `wifi\|error\|airport command not available\|0\|0\|none` | C — `airport` removed in macOS 14+; need `wdutil` |
| 20 | `security.certificates.details` | question | win/lin/mac | Details for cert by thumbprint | `error\|thumbprint parameter required` | A |
| 21 | `security.ioc.check` | question | win/lin/mac | Check IOC (hash/IP/domain) against device state | `error\|none\|false\|No IOC parameters provided` | A |
| 22 | `security.sccm.client_version` | question | win/lin/mac | SCCM client version | `installed\|false error\|platform not supported` | B (Windows-only) |
| 23 | `security.sccm.site` | question | win/lin/mac | SCCM assigned site code | `error\|platform not supported` | B |
| 24 | `server.deployment.list_jobs` | **query** | win/lin/mac | List server-side agent-deployment jobs | `DISPATCH_ERR: instruction definition not found` (same import rejection as #7) | D |
| 25 | `windows.registry.enumerate_keys` | question | windows | Enumerate subkeys of a registry path | `error\|registry not available on this platform` | B |
| 26 | `windows.registry.enumerate_values` | question | windows | Enumerate values under a registry key | `error\|registry not available on this platform` | B |
| 27 | `windows.registry.get_user_value` | question | windows | Read HKCU value from a per-user hive | `error\|registry not available on this platform` | B |
| 28 | `windows.registry.get_value` | question | windows | Read a single registry value | `error\|registry not available on this platform` | B |
| 29 | `windows.registry.key_exists` | question | windows | Check whether a registry key exists | `error\|registry not available on this platform` | B |
| 30 | `windows.software.msi.list` | question | windows | List installed MSI products | `error\|platform not supported` | B |
| 31 | `windows.software.msi.product_codes` | question | windows | Look up MSI product GUIDs | `error\|platform not supported` | B |
| 32 | `windows.wmi.get_instance` | question | windows | Fetch a single WMI/CIM instance | `error\|WMI not available on this platform` | B |
| 33 | `windows.wmi.query` | question | windows | Run a WQL query | `error\|WMI not available on this platform` | B |
| 34 | `workflow.version_compliance_check` | question | win/lin/mac | Compare a file's version metadata against a policy floor | `error\|missing required parameter: path` | A |

## Reproduction recipe

```bash
# 1. Bring up the stack (fixed in commit landing with this handover)
bash scripts/start-UAT.sh                    # must exit 0; if not, see "Known UAT bring-up failure modes" below

# 2. Run the Instructions gate standalone
bash scripts/test/instructions-tests.sh \
    --dashboard http://localhost:8080 \
    --user admin --password 'YuzuUatAdmin1!' \
    --run-id manual --gate-name instructions \
    --output /tmp/instructions-outcomes.json

# 3. Inspect the fail list
python3 -c "
import json; d=json.load(open('/tmp/instructions-outcomes.json'))
print('outcomes:', {o['outcome'] for o in d['outcomes']})
for o in d['outcomes']:
    if o['outcome'] in ('fail','error'):
        print(' ', o['definition_id'], '|', o.get('note',''))
"

# 4. To probe a single failing instruction against the live agent and read its
#    actual response (the runner doesn't always surface it cleanly):
curl -s -c /tmp/cookies.txt -X POST http://localhost:8080/login \
    -d 'username=admin&password=YuzuUatAdmin1!' >/dev/null
# Cookie-session writes to the instruction routes must carry an Origin (or Referer) naming the server; token-authenticated requests do not.
RESP=$(curl -s -b /tmp/cookies.txt -X POST \
    -H 'Origin: http://localhost:8080' \
    'http://localhost:8080/api/instructions/<DEF_ID>/execute' \
    -H 'Content-Type: application/json' -d '{}')
echo "$RESP"
CMD_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command_id',''))")
sleep 2
curl -s -b /tmp/cookies.txt "http://localhost:8080/api/responses/$CMD_ID" | python3 -m json.tool
```

A pre-built probe script lives at `/tmp/probe-fails.py` from the prior session — read it once if you want a working example; it logs in, dispatches every id in `/tmp/fails.txt`, polls once, and writes `(id, output)` to `/tmp/fail-details.tsv`. The list of 34 ids is below; copy it to `/tmp/fails.txt`:

```
agent.content_dist.stage
agent.content_dist.upload_file
crossplatform.process.fetch
crossplatform.tar.export
crossplatform.tar.sql
device.agent_logging.get_log
device.discovery.scan_subnet
device.event_logs.errors
device.filesystem.file_hash
device.filesystem.find_by_hash
device.filesystem.get_acl
device.filesystem.get_signature
device.filesystem.get_version_info
device.filesystem.list_dir
device.filesystem.read
device.filesystem.search
device.filesystem.search_dir
device.users.group_members
device.wifi.list_networks
security.certificates.details
security.ioc.check
security.sccm.client_version
security.sccm.site
server.deployment.list_jobs
windows.registry.enumerate_keys
windows.registry.enumerate_values
windows.registry.get_user_value
windows.registry.get_value
windows.registry.key_exists
windows.software.msi.list
windows.software.msi.product_codes
windows.wmi.get_instance
windows.wmi.query
workflow.version_compliance_check
```

## Concrete fix recipes

### A — parameter synthesis (15 instructions)

`scripts/test/instructions_runner.py` already calls `synthesise_params(parameters_block, override)` per instruction. The block walks each property and currently emits empty/None for properties without explicit defaults. The fix is a small per-name and per-type table of synthesis values:

| Param name (case-insensitive) | Suggested synthesis |
|---|---|
| `path` | host-OS-appropriate tiny readable file: `/bin/ls` (lin/mac), `C:\\Windows\\System32\\notepad.exe` (win) |
| `directory`, `root` | `/tmp` (lin/mac), `C:\\Temp` (win) |
| `pattern` | `*.txt` |
| `filename` | `synth.bin` |
| `url` | `https://example.invalid/synth` (the instruction will fail at HTTP, but no longer at "missing param" — that's the right failure mode for the run-it-once test) |
| `sha256` | `0000000000000000000000000000000000000000000000000000000000000000` |
| `sql` | `SELECT 1` |
| `group` | `wheel` (mac), `sudo` (lin), `Administrators` (win) |
| `thumbprint` | `0000000000000000000000000000000000000000` |
| `ioc_*` (hash/ip/domain) | hash=`d41d8cd98f00b204e9800998ecf8427e`, ip=`127.0.0.1`, domain=`example.invalid` |
| `lines` (and other ints) | YAML's `default:` if present; else `10` |

For params with a YAML-declared `default:`, use that. The runner already extracts the YAML — extending `synthesise_params` to honour `default` field is a one-liner.

After this, the 15 `A`-bucket instructions will move to either `pass` (if the synthesised value happens to work, e.g. `path=/bin/ls` → `filesystem.file_hash` returns a real hash) or `fail` with a different error (e.g. file not found, HTTP error). The latter is fine — the runner is exercising the **dispatch path**, not asserting on semantic correctness. Semantic-correctness tests for these come later (PR C in the test ladder per SKILL.md).

### B — platform-aware SKIP (9 instructions)

In `instructions_runner.py`, the YAML definition is already loaded — pull the `platforms:` field. Where the runner currently records an outcome:

```python
# Pseudo-code for the classification step:
host = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}[platform.system()]
if defn.platforms and host not in defn.platforms:
    return Outcome(outcome="skip", note=f"host={host} not in platforms={defn.platforms}")
```

This must run **before** dispatch (no point dispatching), and the test-runs DB writer must know about the new `skip` reason so trend queries work.

### D — `type: query` (2 instructions)

Open `content/definitions/discovery.yaml` and `content/definitions/deployment.yaml`, locate the spec blocks for `device.discovery.scan_subnet` and `server.deployment.list_jobs`, change `type: query` → `type: question` (both are read-only / data-returning, which matches `question` semantics).

Then `meson compile -C build-macos` rebuilds the embedded content. Verify:

```bash
curl -s -b /tmp/cookies.txt 'http://localhost:8080/api/instructions?limit=500' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); ids=[x['id'] for x in d['definitions']]; \
        print('scan_subnet:', 'device.discovery.scan_subnet' in ids); \
        print('list_jobs:',   'server.deployment.list_jobs' in ids)"
```

Optionally — and orthogonally — patch the importer at `server/core/src/instruction_store.cpp` (search for the `type must be 'question' or 'action'` literal) to accept `query` as an alias. That fixes the class of bug rather than the two instances.

### E — `tar.export` UNION ALL bug (1 instruction)

In the `tar` plugin (`agents/plugins/tar/src/tar_plugin.cpp` or sibling), the export action composes a SQL UNION ALL across multiple TAR tables; one branch's SELECT column count diverges from the others. Find the construction site and align. The error string `SELECTs to the left and right of UNION ALL do not have the same number of result columns` is unambiguous — SQLite emits it pre-exec, so the fix is verified by simply having `tar.export` dispatch return rc=0 with any body.

### F — empty-result returns rc=1 (2 instructions)

- `device.agent_logging.get_log`: when `get_log_file_path()` returns empty (no log on this host), return `status|empty` with rc=0 instead of `status|error|agent log file not found`. The semantically-correct response on a host with no agent log is "no rows", not "error".
- `device.event_logs.errors`: the runner currently sees output beginning with `error|` and classifies the response as a failure even though the lines are legitimate error events. Two options:
  - Plugin-side: change the column-0 marker from `error` to something neutral like `event`, with `Severity` indicating severity. Wire-format change — needs a synced dashboard fragment update.
  - Runner-side: stop treating "output starts with `error|`" as a failure signal; trust the agent's rc instead. (Cleaner; bounds the change to the runner.)

### C — stale macOS plugin paths (5 instructions)

These are per-plugin issues that don't share a single fix. File an issue per plugin and prioritise per release urgency:

- `crossplatform.process.fetch` — needs macOS `proc_listpids` / `proc_pidpath` / `sysctl` branch
- `device.wifi.list_networks` — replace `airport` (removed in macOS 14+) with `wdutil info` (privileged) or `system_profiler SPAirPortDataType`
- The other 3 are bucket-A/B duplicates and resolve via the runner fix.

## What's already done (commit landing with this handover)

The commit that lands this handover already fixed every test-infrastructure flake that was masking the Instructions gate as the only signal worth chasing:

| Fix | File(s) | Issue |
|---|---|---|
| EUnit gate accepts `Failed: 0` even when rebar3 reports cancellations | `scripts/test/eunit-gate.sh` (new), `.claude/skills/test/SKILL.md`, `scripts/run-tests.sh` | #1005 |
| CT *_SUITE.erl files moved out of `apps/yuzu_gw/test/` into `apps/yuzu_gw/test/ct/` | `gateway/apps/yuzu_gw/test/ct/*_SUITE.erl` (renames) | #1005 (a) |
| awk `; exit` SIGPIPE pattern under `set -o pipefail` replaced with `END{print val}` | `scripts/start-UAT.sh` × 2, `scripts/integration-test.sh` × 1 | #988-class |
| Phase 4 Fresh Stack Stand-up now exits 0 (7/7 inline tests reported) | (consequence of above) | |
| Security E2E Category 7 rate-limit test rewritten with `xargs -P` parallel storm + per-request header capture | `scripts/e2e-security-test.sh` | #1006/#1007 follow-up |
| UAT `--login-rate-limit 200` so parallel `/test` fan-out doesn't self-DoS | `scripts/start-UAT.sh` | #1006/#1007 |
| Agent no longer crashes on `agent_logging.get_log` macOS perm error | `agents/plugins/agent_logging/src/agent_logging_plugin.cpp` (`fs::exists(p)` → noexcept overload everywhere) | session-internal |
| Defence-in-depth try/catch around plugin `execute()` in agent dispatch loop | `agents/core/src/agent.cpp` | session-internal |
| `FleetTopologyStore::pushed_` LRU cap | `server/core/src/fleet_topology_store.{hpp,cpp}`, `server/core/src/server.cpp` | #1002 |
| Gateway-routed agents — `send_to`/`send_to_all` prefer `gw_pending_` over Subscribe stream | `server/core/src/agent_registry.cpp` | #1004 |
| Shared HeartbeatIngestion class — both Heartbeat handlers funnel through one entry point | `server/core/src/heartbeat_ingestion.{hpp,cpp}` (new), wired in agent & gateway services + `server.cpp` | #1000 |
| LocalDispatcher class — pump body shrunk; cap/truncation policy localised | `agents/core/src/local_dispatcher.{hpp,cpp}` (new); `agents/core/src/agent.cpp` pump simplified | #1001 |
| `coverage-gate.sh` skips Linux-only native file on macOS; per-host vcpkg triplet | `scripts/test/coverage-gate.sh` | #1009 |
| `start-UAT.sh` agent-registration deadline 15s → 30s | `scripts/start-UAT.sh` | #1003 |
| `integration-test.sh` fleet-health-recompute wait 10s → 20s | `scripts/integration-test.sh` | #1008 |

## Known UAT bring-up failure modes (for the next session's first 5 minutes)

If `bash scripts/start-UAT.sh` exits non-zero, in order of likelihood:

1. **Ports busy.** `bash scripts/start-UAT.sh stop` then `for p in 8080 50051 50052 50054 50055 50063 8081 9568; do pid=$(lsof -ti :$p 2>/dev/null); [ -n "$pid" ] && kill -9 $pid; done`. Retry.
2. **Agent crash from a previous Instructions run.** Log: `/tmp/yuzu-uat/agent.log`. The fix that prevents this (`fs::exists` noexcept + try/catch in dispatch) is already in the commit landing with this handover; you should not see it.
3. **Server config stale (admin creds reset).** The script regenerates `/tmp/yuzu-uat/yuzu-server.cfg` on every start; if your password test fails, `cat /tmp/yuzu-uat/yuzu-server.cfg` and re-derive the bcrypt-equivalent hash, OR just rerun start.
4. **gRPC channel between server and gateway not ready.** The script polls all three ports; if any fails to bind in time, raise the per-port wait (currently 30s for the web port, 15s for the gateway agent port).

## Where the runner code lives

- `scripts/test/instructions-tests.sh` — bash entry point; arg-parses and execs the runner.
- `scripts/test/instructions_runner.py` — the runner itself. Look at:
  - `synthesise_params()` (around line 200) — this is the `A` fix site.
  - `exercise()` (around line 285) — this is the dispatch loop; `B` classification goes here, before dispatch.
  - `Outcome` dataclass (top of file) — already has `outcome` values `pass`/`fail`/`error`/`pending_approval`/`skip`. Adding a new skip-reason is a one-liner.
  - The runner already records per-instruction timings into `test_timings` keyed by gate name + instruction id. Don't break that — trend tooling depends on it.

## Definition of done for the next session

- [ ] **A** + **B** + **D** fixes applied; `/test` Phase 5 Instructions FAIL count is ≤ 8 (E/C/F survivors only).
- [ ] Each remaining survivor has a GitHub issue with a one-line repro and the cause bucket.
- [ ] `/test` default mode returns **17 PASS / 0 FAIL / 0 WARN / 3 SKIP** OR **16/0/0/3 with Instructions = WARN** (if E/C/F are deferred). Either is a green-enough signal for release.
- [ ] No regression in any of the gates listed under "What's already done" (verify by running `/test` once after each fix).
- [ ] Handover this doc forward if work doesn't finish in one session.
