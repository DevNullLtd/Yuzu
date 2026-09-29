# app_usage

<!-- BEGIN GENERATED: plugin-doc-gen header -->
| | |
|---|---|
| **What it does** | Read-only machine-scope app usage inventory derived from TAR's usage fold (no pid, command line, or user names in output) |
| **Version** | 1.0.0 |
| **Kind** | Collector · read-only · gathered (crossplatform.app_usage.summary, crossplatform.app_usage.last_used, crossplatform.app_usage.foreground) |
| **Platforms** | Windows ✅ · macOS 🟡 constrained · Linux ✅ |
| **Actions** | `foreground` (definition `crossplatform.app_usage.foreground`) · `last_used` (definition `crossplatform.app_usage.last_used`) · `summary` (definition `crossplatform.app_usage.summary`) |
| **Security** | securable `Forensics` · operation Read · risk Medium · dispatch ReadOnly · approval gate AdminOrApproval |
| **Roles** | execute: endpoint-admin, security-admin · author: content-author |
<!-- END GENERATED -->

## How it works

`summary` aggregates `usage_daily` over a trailing window (`days`, default 30, clamped 1-365; `top`, default 25, clamped 1-500; sorted `by` `run_time` or `run_count`), merges in a `usage_daily_user` `COUNT(DISTINCT user)` per executable, and is preceded by one `meta` row carrying the fold's own health counters (coverage window, open runs, unmatched stops, clock anomalies, capture gaps, feeder state). `last_used` reports per-`exe_key` first/last-seen within TAR's retained window plus a trailing-30-day `run_count`/`total_seconds`, optionally narrowed to one executable via `exe` (normalised with the identical rule TAR writes `exe_key` under). `foreground` always reports `CONSTRAINED`/`foreground_not_captured` with rc 0 — a permanent, by-design degraded outcome rather than a hard failure, since no per-session focus-time source exists on any platform yet. Every action first classifies `tar_config.usage_enabled`'s tri-state (Enabled/Disabled/Errored, mirroring TAR's own #560 `canonical_source_enabled` fix) and checks the `usage_daily` table exists, reporting a typed constrained reason rather than an empty result when the source is off, mis-set, or the schema predates this fold.

Deliberately not: never opens `tar.db` for write (`SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX`, `PRAGMA query_only=1`); never selects a pid, command line, or user name — `usage_daily_user` contributes a distinct-user count only and `usage_live` contributes an open-run count only; never accepts an operator-supplied db path (would be an arbitrary-file read).

```mermaid
flowchart LR
  OP[Operator / workflow] --> SRV[Server<br/>authz: Forensics.Read, AdminOrApproval]
  SRV -- gRPC mTLS --> HOST[Agent plugin host] --> EX[app_usage.execute]
  EX -- SQLITE_OPEN_READONLY --> DB[(tar.db<br/>usage_daily · usage_daily_user · usage_live)]
  TAR[tar plugin process fold<br/>ETW · procfs · ES-or-poll] --> DB
  EX --> ROWS[rows + typed result status] --> RS[(ResponseStore)] --> API[REST /api/responses]
  EX -.->|last_used, in-process| SYNC[sync_source_app_usage.cpp<br/>ADR-0016 daily-sync]
```

## OS capability

<!-- BEGIN GENERATED: plugin-doc-gen capability -->
| Action | Windows | macOS | Linux |
|---|---|---|---|
| `foreground` | 🟡 constrained · rung 1 · not captured | 🟡 constrained · rung 1 · not captured | 🟡 constrained · rung 1 · not captured |
| `last_used` | ✅ supported · rung 1 · tar.db usage_daily (derived from TAR process/etw) | 🟡 constrained · rung 1 · tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll) | ✅ supported · rung 1 · tar.db usage_daily (derived from TAR process/procfs) |
| `summary` | ✅ supported · rung 1 · tar.db usage_daily (derived from TAR process/etw) | 🟡 constrained · rung 1 · tar.db usage_daily (derived from TAR process/endpoint_security or sysctl poll) | ✅ supported · rung 1 · tar.db usage_daily (derived from TAR process/procfs) |

**Declared limits per leg** (descriptor fallback text, verbatim):

- **`foreground` / Windows** — foreground/focus time and per-session attribution are not captured; promoted by the user-context-bridge roadmap without a schema change
- **`foreground` / macOS** — foreground/focus time and per-session attribution are not captured; promoted by the user-context-bridge roadmap without a schema change
- **`foreground` / Linux** — foreground/focus time and per-session attribution are not captured; promoted by the user-context-bridge roadmap without a schema change
- **`last_used` / macOS** — inherits the process source's names-only constraint; ES entitlement absent -> poll granularity
- **`summary` / macOS** — inherits the process source's names-only constraint; ES entitlement absent -> poll granularity
<!-- END GENERATED -->

## Privileges and prerequisites

| OS | Runs as | Extra grant needed | Measured | If the read is refused |
|---|---|---|---|---|
| Windows | agent service account (LocalSystem today, `#1442`) | None — opening `tar.db` read-only needs only whatever access LocalSystem already has (the file is created and owned by the agent via the `tar` plugin) | captured 2026-09-15 as interactive user (elevated) (`docs/samples/windows.txt`) — the capture ran under the operator's own elevated session, not the agent's LocalSystem posture | result status `UNAVAILABLE`/`PARTIAL`, row `constrained\|tar_db_unavailable\|<path>\|<sqlite error>` |
| macOS | agent daemon, root — the shipped LaunchDaemon has no `UserName` key (`docs/agent-privilege-model.md` "macOS is the current exception", required today for TAR's Endpoint Security client) | None beyond that — the read-only open needs no additional entitlement of its own | captured 2026-09-15 at euid 501 (`docs/samples/macos.txt`) — a lower-privilege posture than the agent's actual root LaunchDaemon; no live `tar.db` at the default path on the capture host | result status `UNAVAILABLE`/`PARTIAL`, row `constrained\|tar_db_unavailable\|<path>\|<sqlite error>`; a schema-missing or disabled host instead reports `CONSTRAINED`/`PARTIAL`, row `constrained\|usage_schema_missing` / `constrained\|usage_source_disabled` |
| Linux | agent daemon, dedicated unprivileged `yuzu` account by design (`docs/agent-privilege-model.md` TL;DR) | None — same read-only open | captured 2026-09-15 (`docs/samples/linux.txt`) | same shape as Windows/macOS |

No external binaries, no subprocesses, no network access — every branch is a `sqlite3_*` call against an already-open handle; no `popen`/`CreateProcess`/socket call appears anywhere in `app_usage_plugin.cpp` or `app_usage_parsers.hpp`.

## Data contract

### Inputs

<!-- BEGIN GENERATED: plugin-doc-gen inputs -->
| Definition | Parameter | Type | Required | Default | Constraints | Description |
|---|---|---|---|---|---|---|
| `crossplatform.app_usage.last_used` | `exe` | string | no | - | - | Optional executable name (or path — only the basename is used) to narrow the result to. Omit to return every executable TAR has recorded within its retained usage window. |
| `crossplatform.app_usage.summary` | `days` | int32 | no | 30 | - | Number of trailing days to summarise. Clamped to 1-365. |
| `crossplatform.app_usage.summary` | `top` | int32 | no | 25 | - | Maximum number of executables to return. Clamped to 1-500. |
| `crossplatform.app_usage.summary` | `by` | string | no | run_time | - | Ranking metric: "run_time" (total_seconds, default) or "run_count". Any other value is rejected with error\|bad_param\|by. |
<!-- END GENERATED -->

### Outputs

Pipe-delimited rows via `write_output()`. `summary` emits exactly one `meta` row (fold health counters) followed by zero or more `usage` rows, most-active-first. `last_used` emits zero or more `last_used` rows, one per executable, ordered by `exe_key`. Every action's failure path instead emits a single row in the shared `<class>|<reason>[|<detail>]` shape (`constrained|...`, `unavailable|...`, `error|...`) — described row-by-row in Result status below — never mixed with a `meta`/`usage`/`last_used` row in the same call.

<!-- BEGIN GENERATED: plugin-doc-gen outputs -->
**`crossplatform.app_usage.foreground` — `status|reason|detail`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `status` | string | - | Windows, Linux, macOS | `constrained` | Always "constrained" — this action never returns a success row. Values: constrained. |
| `reason` | string | - | Windows, Linux, macOS | `foreground_not_captured` | Always "foreground_not_captured". Values: foreground_not_captured. |
| `detail` | string | - | Windows, Linux, macOS | `user-context-bridge roadmap (session-scope attribution)` | Free-text pointer to the roadmap item that will fill this action in. Values: human-readable text. |

**`crossplatform.app_usage.last_used` — `exe_key|last_seen|first_seen|run_count_30d|total_seconds_30d`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `exe_key` | string | - | Windows, Linux, macOS | `chrome.exe` | Lowercased basename of the executable (P5-escaped, same rule as summary's exe_key column). Never a full path, pid, or command line. |
| `last_seen` | int64 | - | Windows, Linux, macOS | `1717286400` | Unix timestamp of the most recent run within TAR's retained usage window. Values: unix seconds. |
| `first_seen` | int64 | - | Windows, Linux, macOS | `1717200000` | Unix timestamp of the earliest run within TAR's retained usage window. Values: unix seconds. |
| `run_count_30d` | int64 | - | Windows, Linux, macOS | `8` | Number of runs recorded in the trailing 30 days. Values: non-negative integer. |
| `total_seconds_30d` | int64 | - | Windows, Linux, macOS | `28800` | Total wall-clock seconds observed running in the trailing 30 days. Values: non-negative integer. |

**`crossplatform.app_usage.summary` — `exe_key|run_count|total_seconds|first_seen|last_seen|distinct_users|superseded_runs|expired_runs`**

| Field | Type | Values | Available | Example | Description |
|---|---|---|---|---|---|
| `exe_key` | string | - | Windows, Linux, macOS | `chrome.exe` | Lowercased basename of the executable (P5-escaped: a literal "\|" becomes "\\|", CR/LF fold to a space, "\" folds to "/"). Never a full path, pid, or command line. |
| `run_count` | int64 | - | Windows, Linux, macOS | `12` | Number of runs recorded for this executable within the window. Values: non-negative integer. |
| `total_seconds` | int64 | - | Windows, Linux, macOS | `43200` | Total wall-clock seconds this executable was observed running within the window. Values: non-negative integer. |
| `first_seen` | int64 | - | Windows, Linux, macOS | `1717200000` | Unix timestamp of the earliest run within TAR's retained usage window (not every run ever recorded — rows older than TAR's retention are already gone). Values: unix seconds. |
| `last_seen` | int64 | - | Windows, Linux, macOS | `1717286400` | Unix timestamp of the most recent run within TAR's retained usage window. Values: unix seconds. |
| `distinct_users` | int64 | - | Windows, Linux, macOS | `2` | COUNT(DISTINCT user) over the window — a count only; no user name ever leaves the agent's SQLite database. Values: non-negative integer. |
| `superseded_runs` | int64 | - | Windows, Linux, macOS | `0` | Runs whose stop event was superseded by a newer start for the same pid before a clean stop was observed. Values: non-negative integer. |
| `expired_runs` | int64 | - | Windows, Linux, macOS | `1` | Runs closed by the fold's own timeout rather than an observed stop event. Values: non-negative integer. |
<!-- END GENERATED -->

### Result status

| Status | Completeness | Provenance | When |
|---|---|---|---|
| `OK` | full | — | `summary`/`last_used`: the query succeeded (rows may legitimately be empty on a quiet host). |
| `CONSTRAINED` | partial | `usage_source_disabled` | `tar_config.usage_enabled` reads `"false"` — the host has turned the fold off. |
| `CONSTRAINED` | partial | `usage_source_errored` | `tar_config.usage_enabled` holds a value that is neither `"true"` nor `"false"` (TAR itself is in an inconsistent tri-state, mirrors #560's `canonical_source_enabled`), or the `tar_config` read itself failed to prepare/step — a read failure maps here, fail-closed, and is never treated as an absent key (which falls through to `Enabled`, TAR's own default). |
| `CONSTRAINED` | partial | `usage_schema_missing` | The `usage_daily` table does not exist — the host's TAR schema predates this fold. |
| `CONSTRAINED` | partial | `usage_feeder_disabled` | `last_used` only: `tar_config.usage_feeder_enabled` reads `"false"` **or is absent** — TAR's own fold has stopped advancing (its `usage`/`process` collector is off), so `usage_daily` would otherwise silently serve a frozen, aging window as if it were live. Unlike `usage_enabled`, an absent feeder key is deliberately NOT treated as enabled — a missing key here is itself anomalous (a hand-restored or hand-edited `tar.db`), so it fails closed the same as an explicit `"false"`. `summary` surfaces the same signal via its `meta` row's `feeder_enabled` field instead of refusing to run. |
| `CONSTRAINED` | partial | `usage_feeder_errored` | `last_used` only: `tar_config.usage_feeder_enabled` holds a value that is neither `"true"` nor `"false"`, or the read itself failed to prepare/step — same fail-closed tri-state as `usage_source_errored`, applied to the feeder key. |
| `UNAVAILABLE` | partial | `tar_db_unavailable` | `tar.db` failed to open read-only (missing file, permission denied, lock contention) — every capture in this package hits this branch, since none of the capture hosts had a live `tar.db` with usage collection enabled at the default path. |
| `UNAVAILABLE` | partial | `tar_db_corrupt` | `tar.db` opened successfully but failed `PRAGMA quick_check(1)` — a distinct token from `tar_db_unavailable` (governance Gate 6 sre finding) so an operator can tell "benign, often transient" apart from "possible disk corruption, worth investigating" without parsing the free-text error detail. |
| `UNAVAILABLE` | partial | `bad_param` | `summary`'s `by` parameter is neither `run_time` nor `run_count`. |
| `UNAVAILABLE` | partial | `query_failed` | A prepared statement failed against an otherwise open, enabled, schema-correct db — `read_meta`'s accumulated `open_runs_query_failed`/`days_present_query_failed` reasons (`yuzu::shared::ConstraintAccumulator`), or a raw sqlite error surfaced from `run_summary`/`run_last_used`. |
| `CONSTRAINED` | partial | `last_used_truncated` | `last_used`, unfiltered form only: the result hit `kMaxLastUsedRows` (5000) distinct executables and was cut off there — a trailing row, not a replacement for the real `last_used` rows already emitted. Bounds the C++-side result-set size (row count returned to the caller, and the SQL `LIMIT` itself) against an unprivileged local user minting unboundedly many exe_keys — it does **not** bound the underlying query's own scan/sort cost against the same growth (`EXPLAIN QUERY PLAN` still shows a full scan+group before `LIMIT` trims the output; round-3 review CDX-R2-04/K6), which is a separate, still-open concern. |
| `CONSTRAINED` | partial | `foreground_not_captured` | `foreground`: always, rc 0 — a permanent degraded outcome, never a hard failure; this source has no per-session focus-time capture on any platform (see Caveats). |

### Where the data goes

- **Instruction result.** Every action's rows travel over the agent's mTLS gRPC channel as the command response and land in the ResponseStore, queryable at `/api/responses/{id}`.
- **Also consumed by daily-sync.** `last_used` is additionally invoked in-process (`LocalDispatcher`, no extra network hop) once per sync cycle by `sync_source_app_usage.cpp` (ADR-0016) — the companion server-side PR persists the projection in `AppUsageStore`. A `constrained` capture is parsed and skipped (`collect()` returns `std::nullopt`) rather than sent as an empty replace, so a disabled/errored/schema-missing host never overwrites a previously-good server view with "zero usage". `summary` and `foreground` are not sync sources — instruction-result only.
- **Not consumed by** TAR itself, DEX, or metrics — `app_usage` only reads `tar.db`; it emits no Prometheus series of its own.
- **Sensitivity.** Executable names and run times are a working-hours/presence proxy even with no user column at all — a host whose interactive tools (shell, editor, browser) cluster their `usage_daily` rows in a narrow daily window says something about when its operator is active, regardless of who that operator is. `distinct_users` is a `COUNT(DISTINCT user)` only; no user name, pid, or command line ever leaves the agent's SQLite database — enforced by a grep-based test over the plugin's own sources (`test_app_usage_parsers.cpp`) for the raw process-event table name and `cmdline`.
- **Siblings:** the `tar` plugin's own `usage`-source `query`/`export` actions read the identical tables through TAR's general-purpose action surface; `app_usage` is a narrower, purpose-built read with its own Forensics-gated approval posture and daily-sync integration.

## Sample output

<!-- BEGIN GENERATED: plugin-doc-gen samples -->
**Windows** — captured: windows Windows 10.0.26200 x86_64 · bare-metal · 2026-09-15 · interactive user (elevated) · leg-hash pending

```
== action=summary
constrained|tar_db_unavailable|C:\ProgramData\yuzu\agent\tar.db|unable to open database file
[result_status] UNAVAILABLE / PARTIAL / unable to open database file
[rc] 1

== action=last_used
constrained|tar_db_unavailable|C:\ProgramData\yuzu\agent\tar.db|unable to open database file
[result_status] UNAVAILABLE / PARTIAL / unable to open database file
[rc] 1

== action=foreground
constrained|foreground_not_captured|user-context-bridge roadmap (session-scope attribution)
[result_status] CONSTRAINED / PARTIAL / foreground/focus attribution not captured by this source
```

**macOS** — captured: macos macOS 26.6.2 arm64 · bare-metal · 2026-09-15 · euid 501 · leg-hash 21254047acbd

```
== action=summary
constrained|tar_db_unavailable|/var/lib/yuzu/agent/tar.db|unable to open database file
[result_status] UNAVAILABLE / PARTIAL / unable to open database file
[rc] 1

== action=last_used
constrained|tar_db_unavailable|/var/lib/yuzu/agent/tar.db|unable to open database file
[result_status] UNAVAILABLE / PARTIAL / unable to open database file
[rc] 1

== action=foreground
constrained|foreground_not_captured|user-context-bridge roadmap (session-scope attribution)
[result_status] CONSTRAINED / PARTIAL / foreground/focus attribution not captured by this source
```

**Linux** — captured: linux Debian GNU/Linux 13 (trixie) aarch64 · container · 2026-09-15 · euid 0 · leg-hash pending

```
== action=summary
constrained|tar_db_unavailable|/var/lib/yuzu/agent/tar.db|unable to open database file
[result_status] UNAVAILABLE / PARTIAL / unable to open database file
[rc] 1

== action=last_used
constrained|tar_db_unavailable|/var/lib/yuzu/agent/tar.db|unable to open database file
[result_status] UNAVAILABLE / PARTIAL / unable to open database file
[rc] 1

== action=foreground
constrained|foreground_not_captured|user-context-bridge roadmap (session-scope attribution)
[result_status] CONSTRAINED / PARTIAL / foreground/focus attribution not captured by this source
```
<!-- END GENERATED -->

## Caveats and known gaps

1. **Default-ON, diverging from most plugins.** `usage` ships `tar_config.usage_enabled = true` by default (`tar_schema_registry.cpp`'s `usage` source entry), per Alex's 2026-09-04 operator ruling (`docs/tar-implementer.md` "Amended (Wave 6, operator ruling 2026-09-04)") that extended the `power`/`removable` default-on precedent to further TAR sources as the roadmap brings each one in for change — this plugin is a read-only view over that already-default-on fold, not a separate opt-in decision of its own.
2. **`foreground` is always constrained, pending a user-context bridge.** Per-session focus-time and per-session attribution are not captured by any of the three platform legs today; the action exists in the descriptor and definition set so the roadmap can fill it in without a schema change once session-scope attribution lands, but every call to it reports `CONSTRAINED`/`foreground_not_captured` (rc 0) unconditionally.
3. **macOS granularity inherits the underlying TAR process source's ES-or-poll behaviour.** `usage_daily` is derived from TAR's `process` fold, not captured independently — when the Endpoint Security entitlement is present TAR observes real start/stop events; when it is absent TAR falls back to polling, which can miss short-lived processes and coarsens `first_seen`/`last_seen`/`run_count` accordingly. This plugin has no way to distinguish which regime produced a given row.
4. **Coverage is forward-only from source activation.** `usage_daily`/`usage_daily_user` only contain rows from the point the `usage` fold started running on a given host — a freshly enrolled agent, or one where `usage_enabled` was flipped on after a period off, has no history for the gap, and `summary`/`last_used` report exactly what is present, never a synthesized "since install" baseline.
5. **`first_seen`/`last_seen` are bounded by TAR's retention window, never all-time.** TAR prunes `usage_daily` on its own retention cadence (31-day default) — both timestamp fields are MIN/MAX over whatever rows are currently retained, not over every run this executable has ever had. Once a day's rows age out, this plugin has no way to see past them; do not read either field as a lifetime first/last-seen.

## Source and tests

<!-- BEGIN GENERATED: plugin-doc-gen source -->
- Plugin: `agents/plugins/app_usage/src/app_usage_parsers.hpp` · `agents/plugins/app_usage/src/app_usage_plugin.cpp`
- Definitions: `content/definitions/app_usage.yaml`
- Capability rows: `server/core/src/capability_decls/plugin_action_catalogue_app_usage.hpp`
- Tests: `tests/unit/server/test_app_usage_ingestion.cpp` · `tests/unit/server/test_app_usage_routes.cpp` · `tests/unit/server/test_app_usage_store.cpp` · `tests/unit/test_app_usage_local_dispatcher.cpp` · `tests/unit/test_app_usage_parsers.cpp`
- Privilege row: `docs/agent-privilege-model.md` (no row yet)
<!-- END GENERATED -->
