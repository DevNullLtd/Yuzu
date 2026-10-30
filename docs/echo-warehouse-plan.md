# Echo Data Warehouse: Mini-Snowflake on Every Endpoint

## Context

Yuzu's Echo plugin currently stores all events in a single flat `tar_events` table with JSON blobs in `detail_json`. Queries are limited to "filter by type + time range." The target architecture treats this data as **typed relational tables with granularity tiers** (Live/Hourly/Daily/Monthly) queryable via SQL SELECT. Each agent endpoint becomes a self-contained analytics node -- a mini-data-warehouse with typed tables per capture source, automatic roll-up aggregation, and a SQL query engine scoped to its own data. The server fans out SQL queries to targeted agents and aggregates results. The Dashboard is the operator's query interface.

---

## Phase 0: Schema Registry and Database Migration

**Goal:** Define the canonical table schemas and migrate the SQLite database from the single `tar_events` table to typed per-source tables.

### New files
- `agents/plugins/echo/src/echo_schema_registry.hpp` -- Data structures defining every capture source, its supported granularities, column definitions, DDL, and rollup SQL
- `agents/plugins/echo/src/echo_schema_registry.cpp` -- DDL string builders, `$`-name-to-table-name translation map, column metadata

### Key data structures
```cpp
struct ColumnDef { const char* name; const char* sql_type; };

struct GranularityDef {
    const char* suffix;              // "live", "hourly", "daily", "monthly"
    enum RetentionType { kRowCount, kTimeBased };
    RetentionType retention_type;
    int64_t retention_value;         // row count or seconds
    std::span<const ColumnDef> columns;
    const char* rollup_sql;          // NULL for live tier
};

struct CaptureSourceDef {
    const char* name;                // "process", "tcp", "service", "user"
    const char* dollar_name;         // "Process", "TCP", "Service", "User"
    std::span<const GranularityDef> granularities;
};
```

### Database migration
- Add `schema_version` key in `echo_config` (version 1 = legacy implied, version 2 = typed tables exist alongside tar_events)
- In `EchoDatabase::open()`, after existing schema creation, check version and create typed tables via DDL from the registry
- Old `tar_events` table is NOT dropped yet (backward compat)

### Modified files
- `agents/plugins/echo/src/echo_db.hpp` -- Add `execute_ddl()`, `create_typed_tables()`, `schema_version()`/`set_schema_version()`, `execute_query()` (returns generic rows)
- `agents/plugins/echo/src/echo_db.cpp` -- Migration logic in `open()`, typed table DDL
- `agents/plugins/echo/meson.build` -- Add `echo_schema_registry.cpp`

---

## Phase 1: Typed Live Tables

**Goal:** Collectors write to typed `*_live` tables with real columns instead of JSON blobs. Dual-write to legacy `tar_events` for backward compat.

### Typed table schemas (initial 4 sources)

**`process_live`:** id, ts, snapshot_id, action, pid, ppid, name, cmdline, user
**`tcp_live`:** id, ts, snapshot_id, action, proto, local_addr, local_port, remote_addr, remote_host, remote_port, state, pid, process_name
**`service_live`:** id, ts, snapshot_id, action, name, display_name, status, prev_status, startup_type, prev_startup_type
**`user_live`:** id, ts, snapshot_id, action, user, domain, logon_type, session_id

### Modified files
- `agents/plugins/echo/src/echo_collectors.hpp` -- Add typed event structs: `ProcessEvent`, `NetworkEvent`, `ServiceEvent`, `UserEvent`
- `agents/plugins/echo/src/echo_diff.cpp` -- Produce typed events alongside legacy `EchoEvent`
- `agents/plugins/echo/src/echo_db.hpp` -- Add typed insert methods: `insert_process_events()`, `insert_network_events()`, etc.
- `agents/plugins/echo/src/echo_db.cpp` -- Implement typed inserts with prepared statements
- `agents/plugins/echo/src/echo_plugin.cpp` -- Dual-write in collectors

---

## Phase 2: Aggregation Engine

**Goal:** Automatic roll-up from Live -> Hourly -> Daily -> Monthly via timer-driven SQL.

### Aggregation tables
- `process_hourly/daily/monthly`: hour_ts, name, user, start_count, stop_count
- `tcp_hourly/daily/monthly`: hour_ts, remote_addr, remote_port, proto, process_name, connect_count, disconnect_count
- `service_hourly`: hour_ts, name, status_changes, last_status
- `user_daily`: day_ts, user, domain, login_count, logout_count (Daily-only)

### Rollup mechanism
- New trigger `echo.rollup` fires every 900 seconds (15 min)
- Tracks `rollup_{source}_{tier}_at` in `echo_config`
- `INSERT INTO ... SELECT ... FROM *_live WHERE ts >= last AND ts < boundary GROUP BY ...`
- Idempotent: safe to re-fire, only processes new data
- Retention runs after aggregation

### Retention defaults
| Tier | Type | Default |
|------|------|---------|
| Live | Row count | 5,000 rows per table |
| Hourly | Time-based | 24 hours |
| Daily | Time-based | 31 days |
| Monthly | Time-based | 12 months |

### New files
- `agents/plugins/echo/src/echo_aggregator.hpp`
- `agents/plugins/echo/src/echo_aggregator.cpp`

### Modified files
- `agents/plugins/echo/src/echo_plugin.cpp` -- Register `echo.rollup` trigger, add `rollup` action
- `agents/plugins/echo/meson.build` -- Add `echo_aggregator.cpp`

---

## Phase 3: SQL Query Engine (Agent-Side)

**Goal:** New `echo.sql` action that executes arbitrary SELECT queries against `$`-prefixed tables.

### `$`-name translation
`$Process_Live` -> `process_live`, `$TCP_Hourly` -> `tcp_hourly`, etc. Whitelist-based via the schema registry.

### Safety (3-layer defense)
1. **SELECT-only** -- Reject INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/ATTACH/PRAGMA
2. **`$`-name whitelist** -- Only registered tables translate; unknowns error
3. **Single-statement** -- `sqlite3_prepare_v2()` + reject trailing SQL
4. **Timeout** -- `sqlite3_progress_handler()` at 5 seconds

### Output protocol: schema-in-band
```
__schema__|pid|name|cmdline|user|ts
1234|nginx|nginx -g daemon off;|www-data|1711050123
__total__|1
```

### New files
- `agents/plugins/echo/src/echo_sql_executor.hpp`
- `agents/plugins/echo/src/echo_sql_executor.cpp`

### Modified files
- `agents/plugins/echo/src/echo_plugin.cpp` -- Add `"sql"` action, implement `do_sql()` handler
- `agents/plugins/echo/meson.build` -- Add `echo_sql_executor.cpp`
- `content/definitions/echo.yaml` -- Add `crossplatform.echo.sql` InstructionDefinition

---

## Phase 4: Server-Side Dynamic Schema Support

**Goal:** Handle Echo SQL results with query-dependent column headers.

### `__schema__` line detection
In `publish_output_rows()`, detect `__schema__|` prefix -> parse columns, cache per command_id, publish OOB `<thead>` swap.

### DispatchFn extension
Add `parameters` map to the existing signature so the SQL can be forwarded to the agent.

### Modified files
- `server/core/src/dashboard_routes.hpp` -- DispatchFn signature change
- `server/core/src/dashboard_routes.cpp` -- New `POST /api/dashboard/echo-execute` route, dynamic schema in `render_results()`
- `server/core/src/agent_service_impl.cpp` -- `__schema__`/`__total__` detection, per-command schema cache
- `server/core/src/result_parsing.hpp` -- Add `"echo"` to kSchemas with dynamic marker
- `server/core/src/server.cpp` -- Update DispatchFn lambda to forward parameters

---

## Phase 5: Dashboard Echo Query UI

**Goal:** Add an Echo Query Composer to the Dashboard.

### Three interaction tiers
1. **Pre-built queries** -- InstructionDefinitions. Type "ECHO:" in instruction bar, autocomplete shows options
2. **Free-form SQL** -- `echo query`/`echo sql` activates SQL Editor textarea + Schema Browser sidebar
3. **Guided Query Builder** -- Source/granularity dropdowns, column checkboxes, WHERE builder, time range picker

### HTMX flow
1. `echo query` prefix -> OOB swap results area to Echo Composer, scope panel to Schema Browser
2. "Run Query" -> `POST /api/dashboard/echo-execute` with sql + scope
3. `__schema__` from first agent -> dynamic `<thead>` OOB swap
4. Data rows stream via SSE
5. Progress: `N / M agents` OOB updates

### New routes
| Route | Method | Purpose |
|-------|--------|---------|
| `/api/dashboard/echo-execute` | POST | Dispatch Echo SQL query |
| `/fragments/echo/schema` | GET | Schema browser HTMX fragment |
| `/fragments/echo/composer` | GET | Echo Composer panel |

### Modified files
- `server/core/src/dashboard_ui.cpp` -- Echo Composer HTML/CSS/JS
- `server/core/src/dashboard_routes.cpp` -- New Echo routes

---

## Phase 6: Pre-built Query Pack

### New file: `content/definitions/echo_warehouse.yaml`

| Name | SQL |
|------|-----|
| Echo: Recent Processes | `SELECT name, pid, cmdline, user, ts FROM $Process_Live WHERE ts > strftime('%s','now','-24 hours') ORDER BY ts DESC LIMIT 500` |
| Echo: TCP Connections by Process | `SELECT process_name, remote_addr, remote_port, proto, COUNT(*) as conn_count FROM $TCP_Live GROUP BY process_name, remote_addr, remote_port, proto ORDER BY conn_count DESC` |
| Echo: Listening Ports | `SELECT local_port, proto, pid, process_name FROM $TCP_Live WHERE state = 'LISTEN' ORDER BY local_port` |
| Echo: Hourly Process Summary | `SELECT hour_ts, name, start_count FROM $Process_Hourly ORDER BY hour_ts DESC LIMIT 168` |
| Echo: Service State Changes | `SELECT ts, name, action, status, prev_status FROM $Service_Live WHERE action = 'state_changed' ORDER BY ts DESC` |
| Echo: Network Connections to IP | `SELECT ts, process_name, pid, remote_port, proto FROM $TCP_Live WHERE remote_addr = '${target_ip}' ORDER BY ts DESC` |
| Echo: Daily Connection Summary | `SELECT day_ts, remote_addr, process_name, connect_count FROM $TCP_Daily ORDER BY day_ts DESC, connect_count DESC` |
| Echo: User Sessions | `SELECT ts, user, domain, logon_type, action FROM $User_Live ORDER BY ts DESC LIMIT 200` |
| Echo: Process Tree | `SELECT pid, ppid, name, user, ts FROM $Process_Live WHERE action = 'started' AND ts > strftime('%s','now','-1 hours') ORDER BY ts` |
| Echo: Software Changes | `SELECT ts, action, name, version, prev_version, scope, user FROM $Software_Live ORDER BY ts DESC LIMIT 200` |

---

## Phase 7: Retire Legacy `tar_events` Table

- Migration to schema version 3: `DROP TABLE IF EXISTS tar_events`
- Remove legacy insert calls from collectors
- `echo.query` and `echo.export` rewritten to query typed live tables (same output format)

---

## Phase 8: Additional Capture Sources

### Wave 1: Cross-platform
1. **Software installations** ✅ (Windows) -- diffs the machine-wide registry Uninstall keys (HKLM 64/32-bit; machine scope only — no per-user `HKU\<SID>`/`NTUSER.DAT`, so no profile-name PII) on the `echo.software` tick. Tables: `software_live`, `software_daily`, `software_monthly`. Linux (dpkg/rpm) + macOS (pkgutil) collectors are a fast-follow (schema is queryable-empty there). Off by default (opt-in via `software_enabled`). See `docs/user-manual/echo.md`.
2. **Device performance** ✅ -- CPU %, memory, disk I/O. Tables: `perf_live`, `perf_hourly` (shipped as the `perf`/`procperf` sources).

### Wave 2: Windows + partial macOS
3. **Boot performance** -- Event Log / uptime. Live-only
4. **DNS resolutions** -- Windows ETW. All 4 tiers

### Wave 3: Windows-specific
5. **ARP cache** -- Polling via GetIpNetTable
6. **Performance events** -- Crashes, patches, service failures
7. **Process stabilization** -- Launch timing for monitored processes
8. **Sensitive processes** -- Elevated system monitoring activity

---

## Verification Plan

### Unit tests
- `tests/unit/test_echo_schema_registry.cpp` -- DDL generation, `$`-name translation
- `tests/unit/test_echo_aggregator.cpp` -- Rollup boundaries, idempotency, retention
- `tests/unit/test_echo_sql_executor.cpp` -- SELECT-only validation, injection rejection, timeout

### Integration
1. Build: `meson compile -C build-linux`
2. Unit tests: `meson test -C build-linux --print-errorlogs`
3. UAT: `bash scripts/start-UAT.sh`
4. Verify tables: `echo.sql` with `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_live'`
5. After 60s collection: `echo.sql` with `SELECT * FROM $Process_Live LIMIT 10`
6. After 15min rollup: `echo.sql` with `SELECT * FROM $Process_Hourly`
7. Fleet fan-out: scope `__all__`, verify multi-agent results
8. Dashboard: Echo query mode, dynamic columns, streaming
9. Gateway unaffected: `rebar3 eunit && rebar3 dialyzer`

### Security validation
- `INSERT INTO process_live ...` -> rejected
- `SELECT * FROM $Nonexistent_Live` -> rejected
- `SELECT 1; DROP TABLE process_live` -> rejected
- `ATTACH DATABASE` -> rejected
