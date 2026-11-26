---
status: accepted
date: 2026-11-26
owner: "@Doomgoose (Alex Young)"
deciders: >-
  @Doomgoose (author and product owner for this decision). Ratified by PR approval from the
  engineering colleagues under the dev-branch protection rule (at least one non-author
  approval).
effective: >-
  Binding on merge for new agent plugin code that makes a blocking OS call with no timeout of its
  own. The plugin-local bounded sites that exist at merge are frozen, not converted.
scope: >-
  agent: where a blocking OS call is time-limited, what owns its resources, how an unanswered or
  cut-short read is reported, and what a plugin may include
builds-on: >-
  ADR-3002 (acquisition ladder; the in-process native calls these reads make)
related: ["3002-acquisition-ladder", "0016-agent-daily-sync-framework"]
context-refs: ["agents/core/include/yuzu/agent/bounded_single_flight.hpp", "agents/core/include/yuzu/agent/bounded_status.hpp", "agents/core/src/win_bounded_run.hpp", "agents/shared/bounded_wait.hpp", "tests/test_bounded_os_call_lexical.py", "docs/cpp-conventions.md"]
---

# ADR-3008: bounded OS calls live in agent-core

## Context

A plugin's `execute()` runs on a worker of the agent's bounded dispatch pool, with no deadline. An
OS call that never returns keeps that worker; enough of them and the agent rejects every command
(#3925). `yuzu::shared::bounded_call` (`agents/shared/bounded_wait.hpp`) bounds the wait, not the
call: it abandons a detached thread. If that thread's code is in a plugin, the agent can unload the
plugin under it.

## Decision

### D1. One exported agent-core function per blocking call

- A blocking OS call with no timeout of its own is bounded in agent-core, which is never unloaded:
  one exported function per call.
- It is never bounded in plugin text: a detached thread in an unloadable plugin is a
  use-after-unload.

Considered and rejected:

- **Pin the plugin module** (as the Echo offline-hive mount does). The module then stays loaded
  until process exit, and the abandoned thread still runs plugin code against plugin state, so
  every call site has to argue its own shutdown safety.
- **A timeout around `execute()` in dispatch.** A thread blocked in an OS call cannot be cancelled,
  so the agent could only abandon a thread that is running plugin code and holds the command
  context: the same unload hazard, for every plugin at once.

### D2. One shared driver

`bounded_single_flight.hpp` is the driver. Each function has its own process-wide slot. The deadline
covers the wait for the slot and the call together.

| Status | Meaning |
|---|---|
| `Completed` | The call returned within the deadline. It may still report an OS error. |
| `TimedOut` | No answer: the deadline passed, the call threw, or the budget was already spent. |
| `Busy` | A healthy call holds the slot; this caller started none. |
| `Abandoned` | An earlier call passed its deadline and its worker is still blocked; none started. |
| `Rejected` | The worker never ran: the outstanding-call ceiling refused, or setup failed. |

- At most one thread per function is ever abandoned.
- Recovery is automatic: the worker releases the slot when the OS call returns.
- The agent-core reads in D6 wait behind a healthy call, inside their own deadline. Several callers
  can want the same read (operator dispatch, Echo, daily sync), and an immediate `Busy` would turn
  a healthy overlap into a degraded answer on an unchanged host.
- `read_proc_snapshot_bounded` (macOS, its own slot, `kProcSnapshotDeadline` 5000 ms) keeps the
  immediate `Busy`: its documented `call_in_progress` answer does not change.

### D3. The worker owns every resource

- The worker allocates and frees every OS buffer, COM pointer, COM apartment and handle on its own
  thread. Its arguments are its own copies.
- The caller receives copied plain data, so after a deadline there is nothing for it to release.
- This covers COM (the VSS walk). It applies unchanged to a future `DeviceIoControl`, `ioctl` or
  IOKit call, each of which gets its own core function.

### D4. Reporting

- One cause vocabulary, `bounded_cause()`: `deadline_exceeded` (`TimedOut` and `Rejected`),
  `call_in_progress` (`Busy`), `abandoned_call_pending` (`Abandoned`).
- A read that did not complete is `CONSTRAINED` + `PARTIAL` and is never an empty success.
  `forward_bounded_failure()` writes `<prefix>:<cause>`; `shares` and `filesystem_posture` carry the
  same cause token through their own status writers.
- Echo skips the tick on a user or mapped-drive read that did not complete, and keeps its baseline.
- Completeness is separate from the deadline. An agent-core read that stopped at an entry cap or a
  page bound is `Completed` with `truncated` or `no_progress` set, and it is partial: reporting
  actions write the rows and mark them `CONSTRAINED` + `PARTIAL`, and Echo skips the tick and keeps
  its baseline.
- `local_admins` and `group_members` write no member rows when a NetAPI call failed.
- `shares.list` pages inside the plugin (`read_share_page` answers one page and carries neither
  flag). Its paging rule predates this decision and is unchanged: the row cap keeps the rows; a
  listing that stops advancing, or has an unanswered page, writes no share rows and still reports
  `CONSTRAINED` + `PARTIAL`.
- How a plugin reports an OS error that a call answered with is not decided here.

### D5. The plugin boundary

- Of the headers this decision adds, a plugin includes `bounded_status.hpp` and the `win_*.hpp`
  headers only. It does not include `bounded_single_flight.hpp`.
- One transitive exception: `process_introspect` includes `proc_snapshot_read.hpp` for its status
  type, and that header includes the driver. Instantiating the driver there does not compile
  (`YUZU_AGENT_CORE_CONSUMER`).
- Production functions take no default argument and no `std::function`. The `_for_test` seams are
  for test binaries.
- `read_hklm_values` is a generic read-only `HKEY_LOCAL_MACHINE` reader, not an allow-list. Its key
  and value names are compile-time constants in the caller, never operator input.
- `bounded_wait.hpp` is superseded for plugin use. Agent-core and test binaries remain valid
  callers. Existing plugin-local sites are frozen by `tests/test_bounded_os_call_lexical.py` until
  each moves. The gate also refuses the listed direct Windows calls, a direct include of the driver
  and a `_for_test` seam in plugin sources.

### D6. Deadline sizing

- Each call has a named constant.
- The constant must be at least 4x the worst healthy time measured on a real host; one that is not
  is raised. The pull request that sets or changes a constant reports the measurement.

| Function (`yuzu::agent::win`) | Header | Constant | Deadline | Slot | One deadline covers |
|---|---|---|---|---|---|
| `read_local_users` | `win_account_enum.hpp` | `kLocalUsersDeadline` | 10000 ms | `g_users_slot` | all pages, up to 16,384 accounts |
| `read_local_group_members` | `win_account_enum.hpp` | `kGroupMembersDeadline` | 5000 ms | `g_members_slot` | all pages, up to 16,384 members |
| `read_adapters` | `win_adapter_list.hpp` | `kAdapterListDeadline` | 5000 ms | `g_adapter_slot` | the adapter list |
| `read_join_info` | `win_join_info.hpp` | `kJoinInfoDeadline` | 5000 ms | `g_join_slot` | one call |
| `read_hklm_values` | `win_registry_read.hpp` | `kRegistryReadDeadline` | 5000 ms | `g_registry_slot` | one request |
| `read_smb_sessions` | `win_session_enum.hpp` | `kSmbSessionsDeadline` | 5000 ms | `g_smb_slot` | all pages at one level |
| `read_share_page` | `win_share_enum.hpp` | `kShareEnumDeadline` | 5000 ms | `g_share_slot` | one page |
| `read_vss_snapshots` | `win_vss_snapshots.hpp` | `kVssDeadline` | 15000 ms | `g_vss_slot` | the whole walk, up to 1,024 entries |
| `read_wts_sessions` | `win_wts_sessions.hpp` | `kWtsSessionsDeadline` | 5000 ms | `g_wts_slot` | the list and its queries, up to 4,096 sessions |

### D7. Not covered; stays in #3925

- File reads on dead network mounts.
- The reconnect thread-pool join.
- The busy-worker and queue-depth metric.
- The `disk_actions` `DeviceIoControl` volume reads.
- Blocking plugin calls not in the D6 table, for example the firewall plugin's own
  `GetAdaptersAddresses` and Echo's outbound mapped-drive (`WNet*`) enumeration.
- The frozen plugin-local `bounded_call` sites (the gate's table; a wrapper definition counts):

| File under `agents/plugins/` | Sites |
|---|---|
| `disk_space/src/disk_space_plugin.cpp` | 1 |
| `discovery/src/discovery_plugin.cpp` | 1 |
| `echo/src/echo_mapdrive_collector.cpp` | 1 |
| `echo/src/echo_registry_source.cpp` | 2 |
| `file_search/src/file_search_shell.cpp` | 1 |
| `file_search/src/file_search_win.cpp` | 1 |
| `installed_apps/src/installed_apps_pkgdb_read.hpp` | 1 |
| `ioc/src/ioc_plugin.cpp` | 1 |
| `power_health/src/power_health_plugin.cpp` | 10 |
| `printing/src/printing_plugin.cpp` | 3 |
| `processes/src/processes_plugin.cpp` | 2 |
| `procfetch/src/procfetch_plugin.cpp` | 1 |
| `windows_updates/src/windows_updates_plugin.cpp` | 1 |

- The agent-core drivers that predate the shared one: `msi_database_read.cpp`, `bundle_id_read.hpp`
  and `dism_bounded_call.cpp`.

Other bounded sites in agent-core also call `bounded_wait.hpp` directly and not the shared driver.
They are valid callers:

- `keychain_read.hpp` (macOS keychain reads).
- `passwd_lookup.cpp` (account database lookups).
- `enrollment_token_file.hpp` (the enrollment token file read).
- `server_address_resolver.cpp` (server name resolution).
- `sync_source_installed_software.cpp` (the time limit on a plugin capture). Its worker runs plugin
  code, so teardown waits for it and hard-exits instead of unloading under it.

## The #3925 acceptance criteria

| Criterion | Answer |
|---|---|
| A recorded decision on bounding OS calls, covering COM, `DeviceIoControl`, `ioctl` and IOKit, and in-flight resources | D1 and D3. The `disk_actions` volume reads are not converted (D7, #3925). |
| A shared primitive is safe against unload, and the `bounded_wait.hpp` limits are met or superseded | D1, D2 and D5. The worker runs agent-core code; at most one is abandoned per function; a refusal at the 64-call ceiling is `Rejected`, reported as `deadline_exceeded`; plugin use is superseded. |
| The `filesystem_posture` VSS read adopts the outcome and its hazard banner is removed or narrowed | It calls `read_vss_snapshots`; the banner is gone and the plugin README states the 15 s bound. |
| A test or documented manual procedure shows a wedged provider no longer exhausts the dispatch pool | Test: `tests/unit/test_win_vss_snapshots.cpp`, a never-returning reader times out, the next call is `Abandoned` without starting a reader, then the slot recovers. Manual procedure below. |

Manual procedure, on a disposable Windows machine:

1. Suspend `VSSVC.exe` and dispatch six concurrent `filesystem_posture.snapshots`. Each answers
   within 15 s plus 2 s with a constrained result.
2. With the process still suspended, a later snapshot call answers at once with
   `abandoned_call_pending`, and `os_info.os_name` answers in under 1 s.
3. Resume the process. The next snapshot call completes.

The other items raised in the #3925 comments (POSIX file reads, the reconnect join, the metric) are
the D7 list and stay there.

## Consequences

- A hung service costs one blocked agent-core thread per function instead of a dispatch worker per
  command. The blocked thread stays until the OS call returns or the process exits.
- A new blocking call means a new core function, its own slot and constant, and a portable result
  type the plugin's decisions can be unit-tested on.
- Capped reads report a partial list where an uncapped read would have streamed everything.
