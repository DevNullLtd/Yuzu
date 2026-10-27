# Timeline Activity Record — Implementer's Guide

Companion to `docs/user-manual/tar.md` (operator-facing). This doc is for
engineers maintaining the TAR plugin or building features on top of TAR.
It captures the design intent, the on-disk format, and the operational
behavior you cannot derive from the code alone.

For the historical product vision and rollout plan, see
[`docs/tar-warehouse-plan.md`](tar-warehouse-plan.md). For the OS support
matrix, see [`docs/user-manual/tar.md`](user-manual/tar.md#os-compatibility-matrix).

---

## 1. What TAR is for

TAR is a **forensics + inventory** capability, not a SIEM and not an EDR.
The design point is "what was happening on this machine at time T, with
no pre-configuration", which has two distinct uses:

1. **Forensic timeline reconstruction.** When an incident is reported,
   an operator can run a query like "show me every process named
   `chrome.exe` that started on this host between 2026-03-01 and
   2026-03-08" and get an answer regardless of whether logging was
   enabled at the time. The collector defaults are tuned so 90+ days of
   activity fits in single-digit MB on a typical workstation.

2. **Cheap inventory snapshots.** The same data — the most recent
   process list, the open TCP connection map, the running services —
   doubles as an always-fresh inventory source for dashboards and
   compliance evidence. Because the live tier is row-count-bounded, a
   `SELECT * FROM $Process_Live` always returns "now-ish".

What TAR is **not**:

- Not a kernel-mode probe. All collection is poll-based via documented
  user-mode APIs (`CreateToolhelp32Snapshot`, `/proc/*`, `sysctl`,
  `GetExtendedTcpTable`, `proc_listallpids` + `proc_pidfdinfo`,
  `systemctl`, `launchctl`, `WTSEnumerateSessionsW`, `getutxent`).
  Anything that lives shorter than the fast collector interval
  (default 60s) is invisible.
- Not a transport for events. TAR persists everything locally; the
  server queries on demand via the `query` and `sql` actions. There is
  no push-to-server stream and no aggregation across hosts at write
  time.
- Not encryption-at-rest, not compression. See
  §3 for the current on-disk format and the planned posture.

---

## 2. Architecture

```
                ┌────────── tar plugin ──────────┐
collect_fast    │ enumerate_processes()           │       writes
  (60s) ──────► │ enumerate_connections()         │ ───►  process_live
                │   diff vs tar_state             │       tcp_live
collect_slow    │ enumerate_services()            │       service_live
  (300s) ─────► │ enumerate_users()               │       user_live
                │   diff vs tar_state             │
                │ insert_*_events()               │
rollup          │   tar_aggregator runs SQL       │
  (15min) ────► │   INSERT INTO ..._hourly        │ ───►  *_hourly / *_daily / *_monthly
                │   from each lower tier          │
                │ run_retention():                │
                │   retention_sql() row-count     │ ───►  trims to a row ceiling
                │   guarded capped DELETE (time)  │ ───►  paced, clock-guarded
                └─────────────────────────────────┘
```

Flow:

1. The trigger engine fires `collect_fast` / `collect_slow` / `rollup` on
   their respective intervals (configurable via the `configure` action).
2. Each collector enumerates its source, reads the previous snapshot
   from `tar_state` (a key-value table inside `tar.db`), diffs them with
   `compute_*_events()` to produce typed event rows, and inserts via
   `TarDatabase::insert_*_events()`.
3. Periodically (`rollup` action, 15 min default) `tar_aggregator` runs
   the rollup SQL from the schema registry to build hourly summaries
   from live, daily from hourly, monthly from daily. Each tier has
   independent retention.

The schema registry (`tar_schema_registry.cpp`) is the single source of
truth for table shape, retention behavior, rollup SQL, and per-OS
support metadata. Adding a new capture source means: append to
`build_sources()`, populate `os_support`, write the collector, write
the diff, wire the typed insert, write tests. No DDL, no rollup
plumbing edits.

---

## 3. Local persistence

**Path.** `<agent_data_dir>/tar.db`. On Windows defaults to
`C:\ProgramData\yuzu\agent\tar.db`; on Linux/macOS to
`/var/lib/yuzu/agent/tar.db`.

**Format.** Plain SQLite 3, WAL journal mode (`tar_db.cpp` sets
`PRAGMA journal_mode=WAL` at open time). Pages are SQLite-default
(4 KB) and the file uses SQLite's standard schema — readable by any
external tool that can speak SQLite. **The on-disk database is NOT
encrypted and NOT compressed.** This is by design today (zero
runtime dependency, zero key-management surface) but is the target of
two planned changes:

- **Encryption-at-rest** via SQLCipher (deferred — would require
  vcpkg port + key derivation from the agent's TPM-bound identity
  certificate, similar to how the agent's gRPC client cert is bound).
- **Page-level compression** via SQLite's `zlib`-backed VFS shim
  (deferred — typical TAR rows compress 4-6× because of repeated
  process names and remote addresses, but the wins are dwarfed by
  retention-default tuning).

If you ship a feature that places sensitive data in TAR (private keys,
session tokens, customer PII), be aware that the cmdline redaction
patterns are the **only** content-protection layer today. Add new
patterns to `kDefaultRedactionPatterns` in `tar_collectors.hpp` rather
than scrubbing per-callsite.

**Schema versioning.** `tar_db.cpp` runs an idempotent migration at open
time. Current schema version is **8** (legacy `tar_events` was retired at v3 in
PR M14, but `kCreateSchema` kept recreating it on every open — v5 stops that and
drops it from already-migrated databases, #2093). Bumps go in the same
function, never in `applies_*` collectors.

---

## 4. Persistence across upgrade / uninstall / reinstall

| Operation | tar.db behavior |
|-----------|-----------------|
| **In-place agent upgrade** | tar.db is preserved (lives in the agent data dir, not the install dir). Schema migration runs at first open of the new binary. Live-tier rows captured by the old binary remain queryable; rollups continue. On Windows, the first open also re-secures `tar.db` and its sidecars, and refuses the open when the files are owned by an account other than SYSTEM, Administrators or the agent's (for example after the agent's service account changed; the new account also needs access to the files): see `docs/user-manual/tar.md` "Data storage". |
| **Uninstall** (`yuzu-agent --remove-service`, MSI uninstall) | tar.db is **left in place** by design. The data dir is operator-managed; uninstall removes the binary and service registration only. To wipe TAR data, delete `<data_dir>/tar.db` explicitly. |
| **Reinstall over an existing data dir** | The new binary opens the existing tar.db, runs migration if the schema version differs, and resumes collection. State in `tar_state` may be stale (see §5). On Windows, files left by a different agent account are refused rather than adopted (`docs/user-manual/tar.md` "Data storage"). |
| **`data_dir` change** (config update) | The new directory has no tar.db — the next collect_fast creates it from scratch. The old tar.db at the previous path is orphaned but not deleted. Operator concern, not TAR's. |
| **Roll back to an older agent** | The older binary opens the same `tar.db` (the registry source adds no schema version) but does not know the `registry` source, so the `registry_live` table, the `registry` row of `tar_cursor` and every `registry:%` baseline in `tar_state` stay on disk, with the per-key baselines holding every watched value unmasked (and the cursor row, for about one tick, the rendered old and new values of changes still waiting for their writer), and the older binary has no way to erase them. An older agent that does know the `registry` source (the key-watch-only build) reads a cursor that holds changes (`held` or `loss`, written as cursor version 2) as lost: one `gap:cursorlost` row and a re-baseline, and those changes are never rows. Run `tar.purge_source` on the paused `registry` source BEFORE the rollback. |
| **Corruption detected at open** (#559) | `TarDatabase::open` runs `PRAGMA integrity_check`; on failure the corrupt file and its `-wal`/`-shm`/`-journal` sidecars are renamed to `tar.db.corrupt-<epoch>` in the same directory (collision-safe if a second corruption lands in the same epoch-second) and a fresh database is initialised (a sidecar that can't be moved is removed so the new DB can't replay it). All `tar_state` (collector snapshots, `<source>_enabled` flags) resets to defaults; collection resumes against the empty DB. The agent logs `tar.db.corruption_detected`; the sidecar is **not** auto-deleted (operator recovers it). If the corrupt file can't be moved aside (read-only/locked/perms), open **fails closed** — TAR refuses to load rather than trust the corrupt DB. **Fleet visibility:** the plugin publishes `heartbeat.db_corruption_total` / `heartbeat.db_quarantine_last`, bridged to the `yuzu.plugin.tar.*` heartbeat tags; the server exposes `yuzu_fleet_tar_db_corruption_agents` and writes a `tar.db.corruption_quarantined` audit row — see docs/user-manual/tar.md "Fleet visibility". |

The "leave data on uninstall" rule is identical to other Yuzu agent
state stores. If a customer asks for "delete tar data on uninstall",
that is a deployment-tooling change (MSI custom action), not a TAR
plugin change.

> **Collect gate and retention share `canonical_source_enabled`.** Both
> `source_enabled()` (`tar_aggregator.cpp`) and `run_retention()` decide a
> source's state through it: `run_retention()` calls `source_enabled()` itself,
> and `source_enabled()` maps the stored value through
> `canonical_source_enabled(stored_value)`, which maps anything other than the
> literal `"true"` to non-enabled (`"false"` → disabled, anything else →
> `"errored"`). This is load-bearing: a value the plugin never writes fails
> **closed** — collection stops *and* retention preserves the rows — instead of
> a bare `!= "false"` that would treat a tampered/corrupt value as enabled and
> let retention delete the paused window (#560). `source_enabled()` also fails
> closed on a failed config read (closed database, SQL error): the registry
> default applies only to a confirmed-absent row. When adding a new capture
> source, gate collection on `source_enabled(*db_, "<name>")` and do **not** add
> a parallel `== "true"`/`== "false"` check or a raw `get_config("<src>_enabled",
> ...)` read — every collect, retention and purge gate for every registered
> source goes through the one helper, so the registry's `default_enabled` is
> the only place a default lives. Collect and retention gates use
> `source_enabled()` (an unreadable flag skips); discard, drain and purge
> decisions use `source_enabled_state()`, which distinguishes a confirmed
> `true`/`false` from an unreadable flag so a destructive path never acts on a
> failed read.
>
> **`paused_at` is cleared on any non-`true` → `true` re-enable.**
> `apply_source_enabled_transition` (`tar_aggregator.cpp`) canonicalises the
> previous stored value before **both** legs, so the disable leg fires on
> `prev_canon != "false"` and the re-enable leg clears `<source>_paused_at` on
> `prev_canon != "true"`. The two are exact mirrors over the tri-state: an
> `errored → true` recovery clears `paused_at` to `"0"` identically to a
> `false → true` re-enable, so a recovered source never reports `enabled=true`
> with a stale paused timestamp (#560). Idempotent `true → true` is a no-op and
> does not touch `paused_at`.

---

## 5. Startup detection / restart caveat

When the agent restarts, the saved `network` / `process` state in
`tar_state` is **stale** — it captures the world as the previous
process saw it, which may be hours or days ago. The next collect_fast
cycle compares the stale `previous` to a fresh `current` and emits
events for every difference.

For the **TCP collector specifically** this means: every connection
that was open both before the shutdown and after the restart appears
as a `connected` event in the timeline, because the state read from
`tar_state` does not include it (or includes a different connection
table). This is a known double-capture caveat.

The tradeoff was deliberate: the alternative — suppressing post-restart
"new" connections by some heuristic — risks dropping legitimate
re-establishment events (an attacker re-opening a C2 channel after a
reboot looks identical to a legitimate connection re-establishment).
Forensic completeness wins; analysts learn to read the post-restart
spike as a snapshot reset rather than 200 net-new connections.

The behavior is pinned by
`tests/unit/test_tar_warehouse.cpp::"TAR diff: TCP post-restart with
empty previous yields all-connected"`.

For **process and service collectors** the same principle applies but
the operational impact is smaller — long-running processes and
services appear as `started` events, which matches what an analyst
asking "what was running after the reboot?" expects to see anyway.

For **user sessions** there is no double-capture: the tty/session_id
is identical pre- and post-restart for the same logged-in user, so
the diff shows no change.

---

## 6. Device impact expectations

Steady-state CPU cost on a typical 8-core workstation, measured against
`v0.10.0` on a 5950X dev box:

| Phase | CPU | Wall time |
|-------|-----|-----------|
| `enumerate_processes()` (200 procs) | ~3 ms | ~5 ms |
| `enumerate_connections()` (300 sockets) | ~8 ms | ~10 ms |
| `enumerate_services()` (140 services) | ~50 ms | ~80 ms (dominated by `systemctl` fork on Linux) |
| `enumerate_users()` (5 sessions) | <1 ms | <1 ms |
| `compute_*_events()` (full diff) | <2 ms total | <3 ms |
| `insert_*_events()` (~50 rows, batched) | ~1 ms | ~2 ms |
| Rollup pass (15 min) | ~5–15 ms | ~20 ms |

Worst observed full collect_fast: ~25 ms. Worst observed collect_slow:
~150 ms (Linux `systemctl list-units` on a host with 400 units; macOS
`proc_listallpids` + per-fd `proc_pidfdinfo` on a host with 5000
sockets — consider raising `fast_interval` if the per-cycle cost
exceeds your latency budget).

Disk usage at default retention:

- live tiers: 4 × 5000 rows ≈ 20K rows total. ~3–5 MB depending on
  cmdline length.
- hourly: 24h × ~50 distinct process names ≈ ~1200 rows/day. ~30 MB
  over a year.
- daily: 31d × ~50 names ≈ ~1500 rows/month. ~5 MB/year.
- monthly: 12 × ~50 ≈ 600 rows. trivial.

A workstation kept at default retention sits comfortably under 50 MB
of TAR data over a year of normal use. A noisy CI host with hundreds
of helper processes per minute can exceed 500 MB; the
`process_stabilization_exclusions` knob (issue #59) is the intended
mitigation.

The redaction pass is regex-free (substring match, case-insensitive)
and runs once per process per collect cycle. At typical pattern
counts (5 default + 0–10 operator-added) it is dominated by the
`tolower` cost on cmdline; expect <1 µs per process.

---

## 7. Supportability without the upstream page

This file plus `docs/user-manual/tar.md` plus
`docs/tar-warehouse-plan.md` are the canonical TAR references. The
schema registry is queryable at runtime via the `compatibility` action
(per-source/OS matrix) and the `status` action (effective config). If
you find yourself reaching for an external doc or a "what does this
field mean" answer that isn't in this doc tree, file an issue — that's
the gap to close.

Routine debugging entry points:

| Symptom | Where to look |
|---------|---------------|
| "TAR isn't recording anything for source X" | `tar.status` output → `<source>_enabled` row. Then `compatibility` action to confirm OS support. Then check the agent log for "TAR plugin initialized". |
| "Query returns 0 rows but I know the event happened" | Check the collect interval (`fast_interval` / `slow_interval`) vs the event lifetime — anything shorter than the interval is sub-resolution. |
| "TCP collector shows a flood of `connected` events" | Almost always a restart artifact. Confirm against the agent's start time. |
| "tar.db is huge" | `status` returns `db_size_bytes`. If it's growing without bound the rollup trigger may not be firing — check trigger registration in `init()`. |
| "Schema migration failed at startup" | `agent.log` will show `TarDatabase: migrated to schema version N` on success or the SQLite error on failure. Migrations are idempotent — fixing the underlying issue and restarting will retry. |

For new-source bring-up, the smallest viable change is: add a
`CaptureSourceDef` to `build_sources()`, write the platform collectors
+ enumeration function, write the diff, write tests. No DDL, no
rollup, no plumbing changes — the registry is the contract.

## 8. Adding a capture source

A **capture source** is a snapshot-and-diff observer (births/deaths of host
state) — like `process`, `tcp`, `service`, `user`. ARP and DNS (ADR-0015) are the
worked example. Follow the **core capture-source pattern** below — do **not** copy
the self-contained *tier* files (`tar_perf.*`, `tar_proc_perf.*`, `tar_netqual.*`),
which are derived-metric samplers with their own headers and pure helpers, a
different shape.

The core pattern (mirror network/service/user — none of which have a per-source
header):

1. **`agents/plugins/tar/src/tar_collectors.hpp`** — add the collected-snapshot
   struct (e.g. `ArpEntry`), the `enumerate_<source>()` declaration, and the typed
   `compute_<source>_events()` diff declaration. **Watch for Win32 macro
   collisions** — `interface` is `#define interface struct` under the full
   `<windows.h>` (the server pulls it via httplib), so a member named `interface`
   breaks the moment a TU without `WIN32_LEAN_AND_MEAN` includes the header; name
   it `iface`.
2. **`agents/plugins/tar/src/tar_<source>_collector.cpp`** (new) — `#include
   "tar_collectors.hpp"`; implement `enumerate_<source>()` per platform with
   `#ifdef _WIN32` / `#elif __APPLE__` / `#elif __linux__`, returning `{}` on
   platforms whose collector is `kPlanned`. Enforce a per-cycle cap with a
   `spdlog::warn` on truncation (there is no agent `/metrics` and no event bus, so
   a log line is the truncation signal — not a metric or audit event).
3. **`tar_db.{hpp,cpp}`** — add the warehouse-row struct (e.g. `ArpEvent`, next to
   `NetworkEvent`) and `insert_<source>_events()` (mirror `insert_network_events`:
   `BEGIN`/prepared insert/`COMMIT`, `StmtPtr` RAII).
4. **`tar_diff.cpp`** — implement `compute_<source>_events()`: an `unordered_map`
   keyed on the source's identity (delimiter `\x1f`, which never appears in the
   data) → `appeared`/`removed`. Keep value-only fields (TTL, entry_type) **out**
   of the key so they don't churn the warehouse.
5. **`tar_schema_registry.cpp`** `build_sources()` — add ONE `CaptureSourceDef`.
   This is the single source of truth: it auto-drives the warehouse DDL, the
   `$Name_Tier` → `name_tier` translation, the read-only-SQL authorizer allowlist
   (`is_queryable_table`, the #760/#631 chokepoint — **no hardcoded list to
   touch**), and the `status` / `compatibility` / `configure` / `snapshot` actions.
   Untrusted operator SQL (`tar.sql`) runs only through
   `TarDatabase::execute_user_query` (read-only connection + that authorizer);
   the trusted `execute_query` is for registry-generated SQL only — never route
   operator input to it.
   Declare a row for **every** OS (`kSupported`/`kSupportedConstrained`/`kPlanned`/
   `kUnsupported`) — the schema-invariant test requires it. Add a `rollup_sql`
   branch per non-live tier. **Every capture source ships `default_enabled =
   true`** (Alex ruling 2026-10-21: all sources, every OS, no exceptions). The
   registry-wide test in `test_tar_schema_registry.cpp` fails any source that
   declares `false`, so a new source must ship enabled. The retrospective-reach
   control is the source's `<name>_lookback_seconds` key where one exists
   (`0` = forward-only), not the enable flag. A default-on source MUST state
   its default in its user-manual page, its changelog fragment, and the SOC 2
   data inventory — never only in a code comment. An agent that stored
   `<name>_enabled = "false"` before a source's default flipped is brought to
   the new default by a one-time, version-gated `tar.db` migration (see the v8
   block in `TarDatabase::open`), not by changing the registry alone.
6. **`tar_plugin.cpp`** — add a leg in `collect_fast_impl` (or `collect_slow_impl`)
   gated on `source_enabled(*db_, "<source>")`: enumerate → diff →
   `typed.empty() ? db_->set_state(key, json) : db_->insert_<src>_events(typed,
   StateWrite{key, json})` (events and baseline commit in one transaction, #1654).
   On failure emit `error|<src> insert failed` (had events) or
   `error|<src> state_save_failed` (baseline-only) and call
   `note_health(<registry name>, "insert_failed"|"state_save_failed")`; on success
   `note_health(<registry name>, "events_recorded")`. A leg that never calls
   `note_health` reads `never_ran` in status. For a non-core source (netqual, module, arp, dns, …) a failure is
   non-fatal (no `error|` line — don't fail the core legs' tick). Add `do_query`/`do_export` `type` branches if the source
   should appear in those actions.
7. **`agents/plugins/tar/meson.build`** — add the new `.cpp` to the
   `shared_library` sources; add any new Windows import lib (`dnsapi` for DNS).
8. **Content** (`content/definitions/`) — add `<source>_enabled` to
   `crossplatform.tar.configure` (the MCP/REST + GUI toggle path) and any canned
   `tar.sql` drill-downs.
9. **Server GUI** (optional) — the Capture-sources frame
   (`render_tar_capture_sources`) lists the eleven core sources (the original ten plus
   `registry`, which also adds the sixth `System` category chip) in a static array
   (`kSources` in `tar_process_tree.cpp`, plus the Push allowlist in
   `tar_tree_routes.cpp` and `kSrc` in `device_routes.cpp`); a new source is toggled through `tar.configure`
   until it is added to both; presentation metadata (category, always-on, `$`-name, badges)
   lives in that render function. Device-level panels (no pid) go in the
   process-tree pane (`render_tar_*_panel` + a `tar_tree_routes` fragment).
10. **Tests** — extend `test_tar_schema_registry.cpp` (every source has all three
    OS rows; every source in the `default_enabled=true` registry-wide invariant),
    `test_tar_diff.cpp` (appeared/removed + cap), `test_tar_warehouse.cpp` (DDL +
    `$`-name translation + authorizer), and add a `test_tar_<source>.cpp`.

**`usage` is not an example of this pattern.** It is a DERIVED source (a fold over
`process_live`, `tar_usage.cpp`/`tar_usage.hpp`) — no `enumerate_<source>()`, no
`compute_<source>_events()` diff, no collector `.cpp` of its own. Its lifecycle
(`usage_set_enabled`/`usage_ensure_baselined`, tar_usage.cpp) runs on a
`Disabled`/`PendingBaseline`/`Active` state machine, not the diff/poll cadence
above. It still gets a `CaptureSourceDef` row in `build_sources()` (step 5) so
the schema/`$Name_Tier` translation/queryable-table allowlist machinery applies
uniformly, but a new capture source should follow the numbered steps above, not
`tar_usage.*`.

### 8.1 Streaming sources and the `ProcStreamCollector` contract

Most sources are snapshot-and-diff pollers (above). A **streaming source**
instead consumes a live kernel event feed (ETW, Endpoint Security, an nstat
kctl socket). The standing rule is: a streaming source implements the
`ProcStreamCollector` lifecycle contract — `start()` returns false → caller
degrades to the poll; `drain()` moves buffered events out each fast tick;
`dropped()`/`kernel_dropped()` for backpressure visibility; `stalled()` +
idle-fallback; `method_name()` for the status field — reusing the shared
`EventRing<T>` bounded ring, **never a hand-rolled parallel ring/retry path**.

The interface is **not required to be `ProcStreamCollector` itself** when the
drained event type is not `ProcEvent`. The established precedent is
`ImageStreamCollector` (module loads, `docs/tar-module-loads.md` §M1): a
**sibling interface with the identical lifecycle contract**, because its
drained type is `ModuleEvent`. The contract, not the base class, is the
invariant.

**`BoundedPendingQueue<Event>` (`tar_cursor.hpp`, Wave 6) is a third bounded
buffer in this plugin and a deliberate exception to "reuse `EventRing<T>`.**
It exists because a cursor source's drain must be NON-DESTRUCTIVE: entries stay
queued until the event+cursor transaction commits, and are then released by
SEQUENCE, so a failed insert retries the same batch and an overflow eviction
between snapshot and ack cannot destroy an entry that was never committed.
`EventRing<T>`'s `drain()` removes on read, which cannot express that. Use
`EventRing<T>` for a stream whose loss is acceptable and counted; use
`BoundedPendingQueue` when the events are forensic and the sink is
transactional. Do not add a fourth.

**The `registry` source (`tar_registry_source.{hpp,cpp}`, pure core in
`tar_registry_parsers.hpp`) is the third `CursorSource` and the precedent for a
cursor source whose durable state is a snapshot baseline plus a position
cursor.** What it adds to the pattern:

- **Two stores, one transaction.** What changed comes from a
  `RegNotifyChangeKeyValue` subtree watch and a per-root baseline diff; each
  root's baseline lives in a `tar_state` row (`registry:<root>`) and is written
  by `insert_registry_events_and_cursor` in the SAME transaction as the rows and
  the cursor, so a baseline can never advance without the rows that explain it.
  A baseline read goes through the tri-state `try_get_state`; `get_state`'s
  empty-on-failure would read a transient SQLite error as "no baseline" and
  silently re-baseline. The baselines hold rendered (unmasked) values and are
  readable through `tar.sql` like `registry_live` itself;
  `purge_source("registry")` erases the table, the cursor row and every
  `registry:%` baseline in one transaction.
- **Four read statuses.** Complete, Absent, Unreadable, Capped. Removals are
  derived only from Complete and Absent reads; an Unreadable read changes
  nothing and a Capped one only adds and updates, so a partial read can never
  fabricate a deletion. Unreadable means the root, or any key beneath it other
  than an access-denied child, could not be read (an open, a query or an
  enumeration failure there makes the whole root Unreadable). Only an
  access-denied child is isolated: it is listed in the read's `skipped` set, the
  rest of the root is read as usual, and the diff keeps what the baseline holds
  beneath the denied key. That holds for up to `kSkippedCap` (32) children per
  read; the 33rd makes the read Capped, which derives no deletion in that root.
  A root going Unreadable, or the denied set gaining a member, writes one
  `gap:unreadable:<root>` row; the set is kept in the cursor so a steady state,
  a shrink or a clear writes nothing. A Capped read's list is partial, so it can
  add to the stored set but never shrinks it, and the stored set is clamped to
  `kSkippedCap` names so a root that stays Capped cannot grow the cursor row.
  Keys are opened with `REG_OPTION_OPEN_LINK`, so a watched key that is itself a
  symbolic link is recorded as the link (its `SymbolicLinkValue`) and its target
  is never followed: following it would let a user point this agent's SYSTEM
  token at a key they cannot read, and the price is that writes under a link a
  user planted over their own `Run` key are invisible. The reader's enumeration
  is index-driven, so `read_key` compares each key's value count, subkey count
  and last-write time before and after walking it; a difference means the key
  was written to mid-walk, and the read is Capped (no removals, root re-read at
  the next tick), never Complete, because a deletion at an index already passed
  would otherwise hide a surviving entry and report it removed.
- **Reconcile.** Every `kReconcileEveryTicks` (12) slow ticks every root is
  re-read whether or not the watch fired (hourly at the default 300 s
  `slow_interval`). It finds what the watch missed (a notify lost to a watcher
  that is not running, an unarmed root) and a child that became denied after the
  last read: the watch mask is `NAME | LAST_SET`, so a permission change raises
  nothing.
- **A root's first read is silent.** A root not yet baselined (first run, a user
  hive loaded at logon, a user who logged off and back on, a re-enable) has its
  first read taken as the baseline, with no rows. Writes made to it between the
  hive loading and that read, up to one slow interval, are folded into the
  baseline and are not recorded; no per-root gap row is written, since a logon
  would add one per root per user.
- **Rows land in the tick that observes the change, or the next one, and the writer is
  correlated, not verified.** A candidate is held only while `now - window_hi <
  kEtwSettle100ns` (5 s), and a notify window closes 1 s after the last notify, so a
  burst that ended more than about 6 s before the tick is written in that same tick;
  a burst nearer the tick, and every reconcile-found change (its window ends at the
  end of the read, after `now`), is held to the next one. A change whose marker
  cannot depend on a later event (`attr:off`, `attr:lost-restart`: both are decided
  before any event is consulted and only ever become more true within a run) is not
  held at all and is written in the tick that sees it, so a restart's whole
  reconcile (every change in it is `attr:lost-restart`) never sits in the cursor
  row; `attr:degraded` is held like any other, since a later tick can still record
  a loss over its window. The mechanism, the `attr:*` precedence, loss epochs and
  exactly what an attribution does and does not establish are written once, in the
  banner of `tar_registry_parsers.hpp` (the row key: `registry_diff_record_key`),
  with its residuals: a change that had no value-write event, an event delivered
  more than the settle interval after its window closed with no counted loss (a
  starved consumer, suspend/resume), an ambiguity any local process can force, and
  an `actor_image` read when the event was delivered. Every user-manual sentence
  must keep saying "a lead to verify, not proof".
- **`RegistryEtwBuffer` is not `BoundedPendingQueue`.** It releases by sequence
  identity like `ack_through`, but selectively: after a commit it retires the
  events older than the minimum root `window_base` (`retention_watermark`) that
  no held candidate's window covers (`release_event`). The events a held
  candidate still needs are interleaved with ones it does not, which a prefix
  release cannot express. `EventRing` (`tar_proc_stream.hpp`) was not reused for the
  same reason: it evicts by position, and this buffer must release selectively by
  sequence identity. It is not persisted: a restart, or a disable and
  re-enable, loses it, and the candidates it would have attributed are written
  `attr:lost-restart`. A root that is never completely read keeps its
  `window_base` at 0 and is left out of the watermark while it has no unread
  notify: every wide-window candidate of such a root has `window_lo` 0, before
  `events_since`, so it finalises `attr:lost-restart` whatever the buffer holds,
  and an idle one that stays Capped does not pin the buffer for the fleet. An
  unread notify changes that. A root the read budget deferred, or one marked
  again while it was being read, has no candidate yet, so the held-window test
  protects nothing of it: its next read builds a narrow window from the first
  unread notify, and until that read the floor stays at
  `max(window_base, first - slack)` (the pending stamps are passed to
  `retention_watermark`; the same floor ages the loss epochs). The pin ends when
  the root is read, which the fair rotation bounds. A root that was complete once
  and then stays Capped keeps its last `window_base` and so holds the watermark
  there: the buffer fills to the cap and the eviction shows as recurring
  `gap:loss` rows and `attr:degraded` (no volume guard is added).
- **The cursor row is a third content store.** Besides the rows and the
  baselines, `held` carries each waiting candidate's rendered old and new values
  until the next tick at most (readable through `tar.sql` as `tar_cursor`; erased by
  `purge_source("registry")`). A candidate held when the source is disabled stays in
  the row until re-enable (then written `attr:lost-restart` with its original
  `observed_at`; the disable does not drop it, since it is a change observed before
  the pause and the re-enable re-baselines silently) or `purge_source` on the paused
  source. Cursor decode treats `window_base`, `held` and `loss` as optional so a
  cursor written by the key-watch-only source decodes as present; a malformed one
  would re-baseline every root. The cursor is written as version 2 whenever it
  holds `held` or `loss` and as version 1 otherwise; decode accepts both and
  takes any other version as lost (`gap:cursorlost`, re-baseline). That is what
  makes a rollback loud: the key-watch-only build reads only version 1, so it
  takes a cursor holding changes as lost, where a build that ignored the unknown
  field would re-encode the cursor without them and drop changes whose baseline
  had already advanced, with no row. Decode also clamps a held candidate's window
  to a non-negative, ordered one, so a corrupt row cannot overflow the stitch's
  `now - window_hi`.
- **The Windows ETW code has no unit seam and no fault-injection test of the
  callback.** `WinEtw` (the session and consumer handles each behind a RAII
  owner, one `ProcessTrace` worker, a `noexcept` callback that contains every
  exception and counts a decode failure) is covered by compile plus the
  `[registry][windows]` live cases, which need an elevated agent and SKIP with a
  named reason otherwise. Teardown order is explicit in `WinEtw::stop()`:
  CloseTrace (it unblocks `ProcessTrace`), join, then stop the session. A
  session that cannot open is degrade-not-fail (`registry_capture_method` =
  `notify`, rows `attr:off`; the start-failure warning carries the Win32 error);
  one that dies after it opened is not restarted. The session takes the default
  ETW security descriptor (the sibling sessions set none either), so members of
  Performance Log Users can attach to the stream (value names, pids and sizes,
  system-wide) or stop it; a stop is detected (`ProcessTrace` returns) and shows
  as `attr:off`. The image name is looked up once per pid when its first event is
  delivered, refused when the process was created after the event (the pid was
  reused), and cached for five minutes, so it can be stale under pid reuse.
- **Windows warehouse columns are NOT NULL.** "Not applicable" is `''`/`0`, and an
  empty `data_type` distinguishes an absent value from an empty one.

**`NstatClient` (`tar_netqual_nstat.*`) is the second such case and a
deliberate, documented exception to a literal `ProcStreamCollector` subclass:**

- Its drained lifecycle type is `NstatFlowEvent` (a TCP 4-tuple open/close),
  not `ProcEvent`, so — exactly like `ImageStreamCollector` — it cannot be a
  `ProcStreamCollector` subclass without templating that base on its event
  type.
- It carries **one extra verb the streaming contract has no room for**:
  `snapshot_quality()`, a repeatable live-table read (no drain) that feeds the
  `netqual` quality leg. One kctl socket backs **two** consumer surfaces (the
  tcp lifecycle stream *and* the netqual snapshot), which the single-stream
  `ProcStreamCollector` shape does not model.
- It nonetheless **honours the contract verbatim**: `EventRing<NstatFlowEvent>`
  reused (not forked), the same `start()/drain()/dropped()/kernel_dropped()/
  stalled()/method_name()` surface, the same degrade-to-poll fallback. It adds
  no parallel backpressure or retry idiom.

If a future streaming source's drained type *is* `ProcEvent`, subclass
`ProcStreamCollector` — do not add a third parallel interface. A new sibling
interface is justified only by a genuinely different drained type, as here.
