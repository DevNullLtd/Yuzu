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
time. Current schema version is **5** (legacy `tar_events` was retired at v3 in
PR M14, but `kCreateSchema` kept recreating it on every open — v5 stops that and
drops it from already-migrated databases, #2093). Bumps go in the same
function, never in `applies_*` collectors.

---

## 4. Persistence across upgrade / uninstall / reinstall

| Operation | tar.db behavior |
|-----------|-----------------|
| **In-place agent upgrade** | tar.db is preserved (lives in the agent data dir, not the install dir). Schema migration runs at first open of the new binary. Live-tier rows captured by the old binary remain queryable; rollups continue. |
| **Uninstall** (`yuzu-agent --remove-service`, MSI uninstall) | tar.db is **left in place** by design. The data dir is operator-managed; uninstall removes the binary and service registration only. To wipe TAR data, delete `<data_dir>/tar.db` explicitly. |
| **Reinstall over an existing data dir** | The new binary opens the existing tar.db, runs migration if the schema version differs, and resumes collection. State in `tar_state` may be stale (see §5). |
| **`data_dir` change** (config update) | The new directory has no tar.db — the next collect_fast creates it from scratch. The old tar.db at the previous path is orphaned but not deleted. Operator concern, not TAR's. |
| **Corruption detected at open** (#559) | `TarDatabase::open` runs `PRAGMA integrity_check`; on failure the corrupt file and its `-wal`/`-shm` sidecars are renamed to `tar.db.corrupt-<epoch>` in the same directory (collision-safe if a second corruption lands in the same epoch-second) and a fresh database is initialised (a sidecar that can't be moved is removed so the new DB can't replay it). All `tar_state` (collector snapshots, `<source>_enabled` flags) resets to defaults; collection resumes against the empty DB. The agent logs `tar.db.corruption_detected`; the sidecar is **not** auto-deleted (operator recovers it). If the corrupt file can't be moved aside (read-only/locked/perms), open **fails closed** — TAR refuses to load rather than trust the corrupt DB. **Observability gap (tracked follow-up):** corruption is currently **log-only** — no Prometheus metric, no server audit event, no heartbeat tag surfaces it fleet-side; an operator learns of it only from the agent log. |

The "leave data on uninstall" rule is identical to other Yuzu agent
state stores. If a customer asks for "delete tar data on uninstall",
that is a deployment-tooling change (MSI custom action), not a TAR
plugin change.

> **Collect gate and retention share `canonical_source_enabled`.** Both
> `source_enabled()` (`tar_plugin.cpp`) and `run_retention()`
> (`tar_aggregator.cpp`) decide a source's state via
> `canonical_source_enabled(stored_value)`, which maps anything other than the
> literal `"true"` to non-enabled (`"false"` → disabled, anything else →
> `"errored"`). This is load-bearing: a value the plugin never writes fails
> **closed** — collection stops *and* retention preserves the rows — instead of
> a bare `!= "false"` that would treat a tampered/corrupt value as enabled and
> let retention delete the paused window (#560). When adding a new always-on
> capture source, gate collection on `source_enabled(*db_, "<name>")` and do
> **not** add a parallel `== "false"` retention check — `run_retention` walks
> `capture_sources()` and gates *every* registered source (including the opt-in
> ones) through the same canonical helper, so retention is uniform.
>
> **Caveat for the opt-in collect gates.** The *retention* gate is canonical for
> all sources, but the *collect* legs of the opt-in privacy sources (`procperf`,
> `netqual`) deliberately read a raw `db_->get_config("<src>_enabled","false") ==
> "true"` rather than `source_enabled()` — they default OFF and must not inherit
> a source's `default_enabled`. That raw `== "true"` is *coincidentally*
> fail-closed-equivalent to the canonical gate (only the literal `"true"`
> enables), so an `errored` value still stops collection — but it is a separate
> code path, not the shared helper. Unifying the opt-in collect gates onto
> `canonical_source_enabled` is tracked as a follow-up; until then, the perf and
> always-on collect legs are canonical and the two opt-in legs are raw-but-
> equivalent.
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
   branch per non-live tier. **Privacy-sensitive / usage-class sources are opt-in**
   (`default_enabled = false`, like `module`/`procperf`/`netqual`/`dns`) under the
   works-council posture. A source MAY also ship `default_enabled = false` as a
   cautious roll-out default even when it carries no PII (e.g. `software` —
   machine-scope asset inventory), letting an operator opt in per host.

   **Amended (Wave 6, operator ruling 2026-09-04).** `power` and `removable`
   ship `default_enabled = true` — the first *works-council-class* sources to do
   so (the five machine-scope sources `process`/`tcp`/`service`/`user`/`perf`
   have always been on; of the eight added since 1.5 under the opt-in
   posture, every one defaults off) — and, as the
   roadmap brings each existing source in for change, that source moves to
   default-on too. The works-council reasoning above is NOT withdrawn: it now
   attaches to the `<name>_lookback_seconds` control (`0` = forward-only)
   rather than to the enable flag, and it applies **at upgrade** rather than at
   an operator's opt-in, which is a stronger obligation, not a weaker one. A
   default-on source MUST therefore state the divergence plainly in its
   user-manual page, its changelog fragment, and the SOC 2 data inventory —
   never only in a code comment. Do not read the paragraph above as licence to
   ship a new source opt-in without asking; the ruling is the current posture.
6. **`tar_plugin.cpp`** — add a leg in `collect_fast_impl` (or `collect_slow_impl`)
   gated on `source_enabled(*db_, "<source>")`: enumerate → diff →
   `typed.empty() ? db_->set_state(key, json) : db_->insert_<src>_events(typed,
   StateWrite{key, json})` (events and baseline commit in one transaction, #1654).
   On failure emit `error|<src> insert failed` (had events) or
   `error|<src> state_save_failed` (baseline-only) and call
   `note_health(<registry name>, "insert_failed"|"state_save_failed")`; on success
   `note_health(<registry name>, "events_recorded")`. A leg that never calls
   `note_health` reads `never_ran` in status. For an opt-in source a failure is
   non-fatal (no `error|` line — don't fail the always-on legs' tick). Add `do_query`/`do_export` `type` branches if the source
   should appear in those actions.
7. **`agents/plugins/tar/meson.build`** — add the new `.cpp` to the
   `shared_library` sources; add any new Windows import lib (`dnsapi` for DNS).
8. **Content** (`content/definitions/`) — add `<source>_enabled` to
   `crossplatform.tar.configure` (the MCP/REST + GUI toggle path) and any canned
   `tar.sql` drill-downs.
9. **Server GUI** (optional) — the Capture-sources frame
   (`render_tar_capture_sources`) auto-lists any source the agent reports in
   `tar status`; presentation metadata (category, always-on, `$`-name, badges)
   lives in that render function. Device-level panels (no pid) go in the
   process-tree pane (`render_tar_*_panel` + a `tar_tree_routes` fragment).
10. **Tests** — extend `test_tar_schema_registry.cpp` (every source has all three
    OS rows; opt-in sources in the `default_enabled=false` cross-check),
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
