# ADR-0075: Criteria runs: three-valued verdicts over several inputs, stored as a result set

- **Status:** Proposed
- **Date:** 2026-11-18
- **Owner:** Nathan Dornbrook / platform (block `0xxx`; see `docs/adr/README.md`)
- **Deciders:** Nathan Dornbrook. The owner's decisions D1 to D40, made between 2026-11-07 and
  2026-11-18 while reviewing Dave Rae's criteria-run plan (version 4.1, 2026-11-06). This ADR cites
  them by number in brackets, for example (D25). It writes them down; it does not reopen them.
- **Builds on:**
  - `0072-scope-lifecycle-and-freshness.md` **as amended by D15**: an evaluation is metadata on a
    result set (completeness, `evaluated_at`, a members hash), not a row in a separate evaluations
    table, and its row grammar is the extended `result_set_matcher`. ADR-0072 is Proposed and not
    yet in the repository. It is revised in place for D15 and lands alongside this ADR (D40).
  - `docs/scope-walking-design.md` (result sets, `parent_id` lineage, re-eval) and
    `0036-result-set-store-postgres-migration.md` (the store on Postgres).
  - `0016-agent-daily-sync-framework.md` (installed-software inventory, blob v3, facet state).
  - `0017-management-group-confinement-list-reads.md` (admit, then filter) and
    `0033-access-control-spine.md` (one dispatch intersection; targeting is never authorization).
  - `0006-server-postgresql-substrate.md` and `0012-server-postgres-store-contract.md`. This ADR needs
    a narrow exception to ADR-0006, written as its own change (D27).
- **Depends on drafts not in the repository:** ADR-1012 (explicit response completeness), ADR-1013
  (the instruction operation digest) and ADR-1014 (armed conduits), all by Dave Rae and Proposed. The
  response-store ADR (D30) is not yet written.
- **Code references:** every `path:line` in this ADR is at `DevNullLtd/Yuzu@f4cc683af1`.

## Binding status

This ADR binds prospectively on acceptance. Nothing it describes is built. It covers all three
slices (D12); slice 1 is specified in full and slices 2 and 3 only as far as the decisions go.

Six points are deliberately left open. Each is marked **Open (Qnn pending)** where it arises, and
none may be decided by an implementing PR. They are listed together under *Open points*.

## Context

### The question a criteria run answers

An operator wants to know which devices meet some criteria, for example "OpenSSL is installed below
3.0.7", or "no copy of package X is installed". Today the result-set producers answer one input at
a time, two-valued: a device is a member or it is not. That hides the device the server could not
assess. A device with no inventory, an unread part of the inventory or a hidden device all look the
same as a device that does not match.

A criteria run asks one question over several inputs and gives every device in its cohort one of
three verdicts: `matched`, `not_matched` or `not_assessed`, with a cause for the last. The first
version reports and acts on nothing (D1).

### What exists today

| Fact | Where |
|---|---|
| Result sets are rows in `result_set_store.result_sets` with `source_kind`, an immutable `source_payload`, `status`, `ttl_at`, `pinned`, `parent_id` and `device_count`. | `server/core/src/result_set_store.cpp:156-172` |
| Members are `(result_set_id, device_id)` with an `ON DELETE CASCADE` foreign key, and no other column. | `result_set_store.cpp:173-176` |
| `source_kind` is a plain string. Four values: `inventory_query`, `echo_query`, `instruction_result`, `manual_curate`. | `result_set_store.hpp:129-136` |
| Status is `pending`, `materialized` or `failed`. | `result_set_store.hpp:124` |
| Caps: 1 h default lifetime, 10,000 sets per owner, 100,000 members per set, 50 pins per owner. | `result_set_store.hpp:293-296` |
| A new set gets `ttl_at = created_at + 1 h`. | `result_set_store.cpp:337` |
| The member cap is checked on create only; `materialize()` does not check it (filed as #7433). | `result_set_store.cpp:329`, `:1045-1106` |
| Members are written with one `unnest` insert inside a 4 s write bound. | `result_set_store.cpp:142`, `:400-401` |
| `gc_sweep` deletes unpinned sets past `ttl_at`, oldest first, 5,000 a pass, whatever their status; it runs about every 5 minutes. | `result_set_store.cpp:1259`, `:1443-1445`; `server.cpp:19769`, `:20048` |
| The matcher grammar is a `kind` matcher or one `{column, op, value}` test with `op` in `eq`, `in`, `contains`, `exists`, meaning "SUCCESS and at least one row satisfies it". A non-SUCCESS answer never qualifies. There is no three-valued mode. | `server/core/src/result_set_matcher.hpp:23-50`; `result_set_matcher.cpp:63-80` |
| One admission validator, `validate_matcher_object`, and a two-valued `response_matches`. | `result_set_matcher.hpp:63`, `:89`; `result_set_matcher.cpp:315`, `:376` |
| `from-inventory-query` is gated by scoped `Inventory:Read` and evaluates conditions over the generic `InventoryStore`. | `server/core/src/rest_api_v1.cpp:16149`, `:16203`, `:16426` |
| The generic `InventoryStore` excludes every typed source, `installed_software` included, in SQL. | `server/core/src/inventory_store.cpp:134-143`; `typed_inventory_sources.hpp:34-53` |
| The inventory conditions have their own grammar (`==`, `!=`, ordering, `contains`, `exists`, `version_gte`, `version_lte`; `combine` all or any) and version comparator. | `server/core/src/inventory_eval.hpp:14-18`, `:101-105`; `inventory_eval.cpp:539` |
| `from-instruction-result` and re-eval are gated by `Execution:Execute`. | `rest_api_v1.cpp:16660`, `:16677`, `:16871`, `:16888` |
| Re-eval is refused unless the set is `echo_query` or `instruction_result`. | `rest_api_v1.cpp:16945-16950`; `mcp_server.cpp:18362-18369` |
| `installed_software` coverage per part is stored in `software_facet_state` (status, token, `last_confirmed_at`, and so on), one row per device and facet. | `server/core/src/software_inventory_store.cpp:414-425` |
| The facet statuses are `full`, `delta`, `constrained`, `timeout`, `oversize`, `not_collected`, `disabled`. | `server/core/src/inventory_blob_v3.hpp:81-89` |
| A status-only section updates the facet's status but leaves its rows, `last_confirmed_at` and `section_hash` alone. | `software_inventory_store.cpp:1940-1960` |
| The agent writes blob v3: a complete facet as rows, any other as a status-only section. | `agents/core/src/sync_source_installed_software.cpp:1099-1111`; `agents/core/meson.build:86` |
| A hash-only report refreshes `last_seen` with server receipt time. | `software_inventory_store.cpp:1470-1475` |
| The store already reads facet state and `last_seen` per device for other routes. | `software_inventory_store.hpp:828-838` (`query_hosts`); `software_inventory_store.cpp:2109` (`source_last_seen_bulk`) |
| The sync interval resolves per management group, 1 h to 7 days, default 1 day. | `server/core/src/collection_settings_resolve.hpp:62-64`, `:78`, `:150-153` |
| The 48 h stale constant is used for the stale pill and gauge. | `server/core/src/software_catalogue_model.hpp:59` |
| `AgentExecStatus.status` is a free string and `error_detail` a plain, Forensics-sanitised string. | `server/core/src/execution_tracker.hpp:143-164` |
| §9.3's aggregate statuses are driven by `minSuccessPercent`, which no server code reads. | `docs/Instruction-Engine.md:775-797` |
| The topology floor has four inclusion classes and 12 Read pairs. | `server/core/src/authz_topology_floor.hpp:36-76`, `:100-154`; `tests/unit/server/test_authz_topology_floor.cpp:235` |
| 39 securables are seeded, mirrored for MCP and pinned by a test. | `server/core/src/rbac_store.cpp:526`, `:569`; `mcp_server.cpp:6227`; `tests/unit/server/test_rbac_store.cpp:332` |
| `ClickHouseSink` is write-only, plain `INSERT ... FORMAT JSONEachRow`, with no deduplication token. | `server/core/src/analytics_sinks.cpp:38`, `:61`; `deploy/clickhouse/init.sql:27-30` |
| ADR-0006 says ClickHouse is the analytics sink, not the substrate. | `docs/adr/0006-server-postgresql-substrate.md:72-75` |

## Vocabulary

- **Run:** one criteria question asked once over a cohort, stored as one result set of kind
  `criteria_run`.
- **Input:** one source of evidence the criteria read. Slice 1 has one kind, a stored
  `installed_software` read. From slice 3, a live input is one read-only instruction per device.
- **Cohort:** the run's target intersected with the devices the creator may see under every input's
  gate (R9).
- **Verdict:** per cohort device, `matched`, `not_matched` or `not_assessed`.
- **Cause:** why a device is `not_assessed`, from a closed list (R4).
- **Coverage:** whether a part of the installed-software inventory was read completely: Full,
  Partial or Unknown (R5).
- **Window:** the time from creation to the run's deadline.
- **Final:** every cohort device has a verdict, or the deadline has passed.
- **Warm copy and cold copy:** the run's verdicts in Postgres, and their exported copy in
  ClickHouse (R11).

## Decision

### R1. Observation only (D1)

A criteria run records verdicts. It dispatches nothing that changes a device and arms nothing. Any
later act phase is its own design, and must meet R4's rule for gates and R14.

### R2. A run is a stored result set (D4, D10, D11, D15, D38)

1. A run is a row in `result_set_store.result_sets` with a new `source_kind`, `criteria_run`.
   There is no separate run store, no composite instruction-definition kind and no new evaluator.
2. The run's inputs, criteria, target and window are written to `source_payload` at creation and
   never change, like every other result set (`docs/scope-walking-design.md:77`).
3. The producers are extended to take several inputs. The `inventory_query` producer supplies the
   stored inputs; the `instruction_result` producer supplies the live inputs from slice 3. A run's
   lineage uses `parent_id` as any other result set does.
4. ADR-0072's evaluation record (completeness, `evaluated_at`, members hash) is metadata on this
   result set, as ADR-0072 as amended by D15 states.
5. Authoring a run is the run request itself. Nothing is stored that could be executed by id later.

> **Code note.** Today's `inventory_query` producer reads the generic `InventoryStore`
> (`rest_api_v1.cpp:16426`), which excludes `installed_software` in SQL
> (`inventory_store.cpp:134-143`). Its conditions also use `inventory_eval`'s own grammar and version
> comparator (`inventory_eval.hpp:14-18`; `inventory_eval.cpp:539`), not `result_set_matcher`.
> Extending it to read `installed_software` therefore means a read against `SoftwareInventoryStore`.
> This ADR records the difference and does not choose the read path.

### R3. Inputs

1. **Slice 1 reads `installed_software` only** (D33), with its parts (`pkg_inventory`,
   `msi_packages`, `windows_optional_features`, `runtimes`, `middleware`). `device_ci`,
   `app_usage`, `app_perf`, `software_licensing` and `certificate_inventory` are each added later in
   their own change, with their own gate, audit and floor decision.
2. **Live inputs arrive in slice 3** (D12). Each is one command per input per device, with a stable
   command id (D3). ADR-0011's removal of the agent-side bundle is not reopened.
3. **A live input gives a definite value only when its answer carries ADR-1012's completeness record
   as Full with plugin status OK**, and only actions that declare completeness may be live inputs
   (D2). No second ADR-1012 exception is made.

### R4. The verdict (D7, D8, D14, D31)

1. **One grammar.** `result_set_matcher` gains quantifiers over an input's rows (`ANY`, `NONE`,
   `ALL`, `COUNT WHERE`), boolean combinators over named inputs, and a version comparator. The
   comparator is a total order, `vers:generic/` first; `nvd_version_compare` is not reused. The new
   constructs are allowed in both modes and pass the same `validate_matcher_object`.
2. **Evaluation is always three-valued** (Kleene K3). A row test with a missing field, a value that
   does not parse for the test, or an answer over the row bound is unknown, with cause
   `missing_value`, `malformed_value` or `row_bound`.
3. **The two-valued mode, the default, folds unknown to false once, at the top**, as SQL's `WHERE`
   does, and never at a leaf. Folding at a leaf would let `NONE(...)` over missing data come out
   true. `response_matches` keeps its `bool` signature by folding at the top, so every existing
   matcher gives exactly today's result (today's grammar has no negation, so both fold points agree
   on it).
4. **`"logic":"k3"`** returns the three-valued result with its cause. A criteria run always
   evaluates with it.
5. **`ALL` over an empty, Full answer is true** (D8). `NONE` over an empty, Full answer is true.
6. **Verdict mapping:** true is `matched`, false is `not_matched`, unknown is `not_assessed`.

The causes of `not_assessed` known today, by slice:

| Cause | Meaning | From |
|---|---|---|
| `missing_value`, `malformed_value`, `row_bound` | the row test could not be decided | slice 1 |
| `coverage_unproven` | `NONE` or `ALL` over a part that is not Full (R5) | slice 1 |
| `stale`, `no_inventory` | no fresh inventory by the deadline (R6) | slice 1 |
| `withheld:<securable>` | the creator may not see this device under that input's gate (R9) | slice 1 |
| `unanswered` | a live input was sent and no answer arrived (R13) | slice 3 |
| `withheld:authority_withdrawn` | the creator's token was revoked or expired (R9) | slice 3 |
| plugin and completeness causes | a live answer that is not Full or not OK | slice 3 |

The plugin and completeness causes follow ADR-1012 when it lands; this ADR does not name them.

> **Open (Q46 pending):** whether an act phase, when one is designed, must require `"logic":"k3"`.
> The two-valued fold is right for selecting devices and wrong for gating them: a gate that asks
> "block unless proven compliant" must not pass a device it could not assess. ConfigMgr's
> treatment of "not applicable" as compliant and Intune's default-compliant setting are the outside
> examples. Recorded here as a tension against D31, not decided.

### R5. Coverage comes from the facet state (D34)

1. Coverage for each part of the installed-software inventory is read from `software_facet_state`,
   which blob v3's `S` records already fill. No new `plugin_data` key is added: a new key would
   land in the generic store on the gateway path, readable under `Infrastructure:Read`
   (`typed_inventory_sources.hpp:5-14`), and would be missing on hash-only cycles.
2. The mapping, applied when the run reads the facet state, is fixed:

   | Facet status | Coverage |
   |---|---|
   | `full`, `delta` | Full |
   | `constrained`, `timeout`, `oversize` | Partial |
   | `not_collected`, `disabled`, no row | Unknown |

   A device whose agent still sends v2 has no facet rows and reads Unknown for every part.
3. ADR-1012 adopts this mapping rather than adding a field of its own.
4. A matching row proves presence, so `ANY` can be true under any coverage. `NONE` and `ALL` need
   Full; otherwise the device is `not_assessed:coverage_unproven`.
5. Freshness (R6) never stands in for coverage.

The agent side is already met: a constrained part is sent as a status-only section and never as
rows (`sync_source_installed_software.cpp:1099-1111`), so Full with zero rows comes only from a
complete read.

> **Open (Q43 pending):** whether a row found under a Partial part proves *current* presence. A
> status-only section leaves the rows of the last confirmed cycle in place, unconfirmed
> (`software_inventory_store.cpp:1940-1960`). R5.4 lets such a row make `ANY` true, but the row may
> come from an earlier cycle. The alternative is to accept it only when that part's
> `last_confirmed_at` is inside the R6 freshness window. Not decided.

### R6. When stored inventory is read (D18, D35)

1. Each device's stored inventory is read **once** per run, so its verdict cannot change after it
   settles.
2. A device is **fresh at start** when `last_seen >= start - (resolved interval_s + 2 h)`. That is
   26 h on the default daily interval, 3 h for an hourly group and 7 days plus 2 h for a weekly
   one. The 2 h allowance is a server constant.
3. The interval is resolved once, at start, through the existing collection-settings resolution. A
   settings change during the window does not move the threshold, and the run says so.
4. A fresh device is read at start. Any other device is read on its first `ReportInventory` or
   `ProxyInventory` receipt inside the window (`agent_service_impl.cpp:1017`;
   `gateway_service_impl.cpp:1801`). A hash-only receipt counts, because it refreshes `last_seen`.
5. The ingest hook checks an in-memory set of the devices waiting in open runs. It never queries the
   database for each report.
6. A device with no receipt by the deadline settles as `not_assessed:stale`, or
   `not_assessed:no_inventory` when it has never reported.
7. `kStaleWindowSecs` (48 h) stays the alerting threshold and is not reused here.

### R7. Settling: read once, written once (D5, D18, D25)

1. A verdict is written onto the member row once. `result_set_members` gains nullable `verdict` and
   `cause` columns, written by an update guarded on `verdict IS NULL`, never through the member
   insert (that insert uses `ON CONFLICT DO NOTHING`, `result_set_store.cpp:400-401`, and would keep
   a stale value silently).
2. A transient plugin status is final: for example `UNAVAILABLE` settles as `not_assessed` with no
   retry (D5).

> **Open (Q44 pending):** D5 settles a device on an early transient status even when most of the
> window is left. Intune keeps the last state through a transient error for seven days, and 1E
> accepts any answer inside its gather window. The operator's remedy today is a re-run (R12). Whether
> to state this as an accepted cost, or to change it, is not decided. `docs/Instruction-Engine.md:765-770`
> also describes a retry for transient plugin errors that no criteria-run path would use.

### R8. Run status

The run's verdict counts (`matched`, `not_matched`, and `not_assessed` by cause) sit beside its
status and say what the answers mean. ADR-0072's `complete` and `incomplete` are not reused for
them. When an act phase arrives, "decided" means a `not_assessed` count of zero (D16).

> **Open (Q41 pending):** where the run's status comes from and where the `not_assessed` causes
> live. D16 says the status is the Instruction Engine §9.3 aggregate over each (device, input)
> `AgentExecStatus`, and the causes go into the existing structured `error_detail`. At
> `f4cc683af1`:
> - `error_detail` is a plain string carrying agent error text, sanitised for Forensics at ingest
>   (`execution_tracker.hpp:69-76`, `:150-153`), not a structured field;
> - the §9.3 aggregate and `minSuccessPercent` are not implemented (`docs/Instruction-Engine.md:775-797`);
> - slice 1 sends no command, so there is no `AgentExecStatus` row for any slice-1 input.
>
> So the status vocabulary must be built, or D16 restated. This section is not to be filled in
> until the owner rules.

### R9. Authority (D6, D19, D20 parts 2-4, D21, D22, D39)

1. **A new securable, `CriteriaRun`**, seeded to Administrator only. `CriteriaRun:Execute` starts a
   run; `CriteriaRun:Read` reads one. Neither is implied by `Inventory:Read` or `Execution:Execute`.
   This makes 40 securables (`rbac_store.cpp:569`; `test_rbac_store.cpp:332`), with the MCP mirror
   (`mcp_server.cpp:6227`), the MCP tier and annotation rows, and the OpenAPI and SOC 2 inventory
   rows updated in the same change.
2. **The topology floor.** `CriteriaRun:Read` is added to `kTopologyFloor`, which then has 13 pairs.
   No new class is added. Class 2 (`authz_topology_floor.hpp:36-52`) is reworded to: the read
   preserves an Administrator-only posture across the RBAC-off toggle, whether that posture came
   from a gate migration or the Read pair was seeded Administrator-only by design. The test sentences
   that follow it (`:61-63`, `:70-76`) are updated in the same change. `CriteriaRun:Execute` needs no
   entry, because the legacy branch already keeps every non-Read operation Administrator-only. The
   test is on the Read pair, not the securable.
3. **The securable admits; the data gates filter.** The cohort is the target intersected with the
   devices the creator may see under every input's own gate: scoped `Inventory:Read` in slice 1,
   through the admit-then-filter `authorize_list_read` (`rbac_store.hpp:736`;
   `authz_gates.cpp:447-448`); `Execution:Execute` with the visible-device derivation of
   `dispatch_confined_arms` (`dispatch_confined_arms.hpp:704`) from slice 3. A management group, a
   scope expression or `__all__` is targeting, never authorization.
4. A device hidden for some inputs settles those inputs as `withheld:<securable>`. Devices excluded
   entirely are counted on the run, never silently left out.
5. Visibility is re-checked at each delivery step from slice 3.
6. **Only the creator reads a run in slice 1** (D6), and only while holding `CriteriaRun:Read`.
7. **Sessionless authority** after the request returns is the creator's durable
   `CriteriaRun:Execute` grant with RBAC on, or the legacy Administrator role with RBAC off. A
   JIT-elevated or group-held grant does not count.
8. **Tokens, from slice 3** (D22). Expiry is checked exactly from the stored `expires_at`.
   Revocation is checked by token id at each delivery step. `ApiTokenStore` adopts the durable
   write generation that RBAC and sessions use, so a revoke reaches every replica in about one
   second, in its own change (today it keeps a 60 s process-local cache,
   `api_token_store.hpp:1219`). An unreadable token store holds sends rather than ending the run.
   A confirmed revocation or expiry ends the run, and pending devices become
   `withheld:authority_withdrawn`.

`PowerManagement:Read` and `Decommission:Read` would also fit the widened class 2. Flooring them
is a separate consistency change, not part of this ADR.

### R10. Fleet-scale sets (D24)

Operator-supplied lists stay capped at 100,000 members. A server-derived kind such as
`criteria_run` may reach fleet size, but only after four changes to the shared store, all slice-1
prerequisites:

1. member sets are cached by result-set id within a byte budget (a materialised set never changes);
2. members are loaded in keyset pages wherever a whole set in memory is not needed;
3. members are inserted with `COPY` or in chunks, not one `unnest` statement;
4. `materialize()` enforces a per-kind cap (closing #7433).

### R11. Retention: warm in Postgres, cold in ClickHouse (D25 to D29, D37)

1. **The run's set lives from creation.** Its `ttl_at` is set at creation to the deadline plus the
   warm setting, and reset at final to final plus the warm setting. It is never pinned. This
   changes only what `gc_sweep` reads; there is no second delete path. Without it, a run with a
   window longer than an hour would be reaped mid-run (`result_set_store.cpp:337`, `:1443-1445`).
2. **Warm for 20 minutes by default** after final, in Postgres.
3. **Then cold in ClickHouse for 90 days**, as the store of record. This needs the narrow ADR-0006
   exception (D27): ClickHouse may hold append-only, retention-bound records; every read goes
   through core under R9's gates; only core holds the credentials; Grafana gets no datasource on
   these tables; Postgres stays the only substrate for transactional state.
4. **Export starts at final.** The set gains an `exported_at` stamp, written only when ClickHouse
   answers HTTP 200. `gc_sweep` reaps a `criteria_run` set only when its TTL has passed **and**
   `exported_at` is set. An unexported set stays warm and readable, is retried every tick, and
   raises a metric and an alert.
5. **Deduplication, two layers.** The table is `ReplacingMergeTree ORDER BY (result_set_id,
   device_id)`, partitioned by the day of final, with a 90-day TTL. Export batches are cut
   deterministically (by `device_id`, fixed size) and each is sent with
   `insert_deduplication_token = <result_set_id>:<batch_no>`, an optional parameter added to
   `ClickHouseSink`. Core reads with `FINAL`, or grouped by the key, so counts are exact before
   merges run. A test pins the batch cut.
6. Because a verdict is written once (R7), every duplicate is identical and no version column is
   needed.

> **Open (Q45 pending):** whether 90 days is long enough. AWS Config's retention for configuration
> history starts at 30 days and defaults to 7 years. If criteria-run verdicts become SOC 2
> evidence, the period needs an explicit justification. Recorded as a tension against D26, not
> decided.

### R12. Re-runs and refusals (D13, D32, D38)

1. **An operator may re-run a run.** A re-run inherits scope walking's re-eval: a new sibling
   result set, replayed from the specs stored at creation, with a new window, under the re-running
   operator's current authority.
2. **No automatic or scheduled re-walk.** Tracking consumers, schedules and `allow_rewalk` are
   refused until an ADR-1014 conduit design covers them.
3. **`definition_changed`** (from slice 3). Each live input records its definition's ADR-1013
   digest in `source_payload` at creation. A re-run recomputes each digest and, if any differs, is
   refused with `definition_changed`, naming the input and both digests. Nothing is dispatched; the
   operator starts a new run.
4. **`definition_disabled`** (from slice 3). A run or re-run whose live input names a definition with
   `enabled: false` is refused at creation with `definition_disabled`, the word the schedule runner
   already uses (`schedule_runner.cpp:98`), naming the input and the definition. Deliveries already
   under way continue, because they are built from the stored specs.

> **Open (Q42 pending):** whether slice 1 offers re-runs. Re-eval is refused today for every
> `source_kind` but `echo_query` and `instruction_result` (`rest_api_v1.cpp:16945-16950`;
> `mcp_server.cpp:18362-18369`), so a slice-1 re-run of a stored-inventory run means extending
> re-eval to the sync-source kinds, which the route's own description calls not supported
> (`rest_api_v1.cpp:2987`). Not decided.

### R13. Live delivery, from slice 3 (D17, D23, D25, D30)

1. **Deliver-on-connect is one general option of read-only dispatch**, not a criteria-run feature.
   Its window is the definition's existing `gather_ttl_seconds` (`instruction_store.cpp:352`), read
   for the first time, with its bound raised to 48 h. Its per-device state extends the command
   outbox (`command_outbox_store.cpp:96-103`) rather than adding a delivery table. Mutating
   instructions are refused. Guardian, Spark and Echo read-only actions get it too; `__guard__`
   needs an explicit refusal because it bypasses the agent's dedup claim.
2. **One cause, `unanswered`**, for a command sent with no answer. While the window is open, a
   device that reconnects with an unanswered row is re-sent the **same** command id once per
   reconnect, for read-only inputs only, inside the dedup horizon and while the command's execution
   record exists. The agent's dedup ring replays a finished answer. No new agent frame and no proto
   change.
3. **Outbox rows are not deleted at final.** They follow the general outbox retention sweep (#4166),
   which becomes a slice-3 prerequisite.
4. **The response store moves to ClickHouse under its own ADR** before slice 3, carrying
   `ResponseTierFilter` (#4990) and per-device scoping (#1634) into every query.

### R14. Approvals over a run's matched set (D37)

ADR-1013's D5 (the approver can read what was hashed, for as long as the digest is evidence)
applies only when an approval or a conduit binds a run's matched set, which is the act phase. Then
the approval store, or the arm record, copies the device list when the ticket is created. The run's
own retention does not change, and a ticket asked for after the run is gone from both stores is
refused, never approved on the hash alone.

## Slices (D12)

### Slice 1: stored inventory only

**What it builds:**
- the `criteria_run` kind and the run request (REST and MCP twins, per ADR-1005), gated by
  `CriteriaRun:Execute`, reading `installed_software` through the extended `inventory_query`
  producer;
- the K3 mode of `result_set_matcher` (R4);
- the coverage read and mapping (R5), the freshness test and read-on-receipt hook (R6);
- write-once verdicts on the members (R7) and the counts beside the status (R8);
- the export to ClickHouse and the reap guard (R11).

**The run, step by step:**
1. **Admission.** `CriteriaRun:Execute`; the criteria pass `validate_matcher_object`; the inputs are
   bounded; a service-scoped token is refused, as on the existing producers.
2. **Creation.** A `pending` `criteria_run` set with its `source_payload` and `ttl_at` set from the
   deadline (R11.1).
3. **Cohort.** The target intersected with the creator's visible devices under scoped
   `Inventory:Read` (R9.3). Excluded devices are counted.
4. **Reads.** Fresh devices are read at start; the rest on their first receipt in the window (R6).
5. **Verdicts.** Each device is evaluated three-valued once its read is in (R4, R5) and its verdict
   written once (R7).
6. **Final.** Every device settled, or the deadline passed; unread devices settle as `stale` or
   `no_inventory`. `ttl_at` is reset and the export starts (R11).

**Prerequisites, each its own change:**
- the agent's v3 writer (D34): already shipped (`sync_source_installed_software.cpp:1099-1111`);
- the `CriteriaRun` securable and the widened class 2 with its floor entry (R9.1, R9.2);
- K3 in `result_set_matcher` (R4);
- the four store changes (R10);
- `ttl_at` from creation (R11.1);
- the ADR-0006 exception and the ClickHouse cold store (R11.3 to R11.5).

**Not in slice 1:** live inputs, deliver-on-connect, token checks per delivery, `definition_changed`,
`definition_disabled`, any act phase, and reads by anyone but the creator.

### Slice 2: ADR-1012

The explicit-completeness contract for command responses lands and adopts R5's mapping. No
criteria-run surface changes.

### Slice 3: live inputs and deliver-on-connect

Live inputs (R3.2, R3.3), deliver-on-connect and `unanswered` (R13), per-step visibility and token
checks (R9.5, R9.8), and the two refusals (R12.3, R12.4). Prerequisites: deliver-on-connect, the
token store's durable generation, #4166, the response-store ADR and ADR-1013's digest.

## Consequences

- **Positive.** One stored shape for every scope-walking result; a device with no evidence is never
  reported as not matching; missing data cannot become a match through negation; existing matchers
  and producers keep their results; the securable shows up as its own line in an access review and
  can be granted separately later.
- **Costs accepted.**
  - Slice 1 waits on four store changes, the securable, K3 and the cold store.
  - Until every agent sends v3, `NONE` and `ALL` read `not_assessed:coverage_unproven` on old agents.
  - A run's cohort depends on who started it, so two operators can get different answers to the
    same criteria. The excluded count makes this visible.
  - A run abandoned before its deadline holds its set until the deadline plus 20 minutes, counted
    against the 10,000-per-owner limit.
  - A long ClickHouse outage grows Postgres by about 300 MB per fleet-wide run until it recovers.
  - Where the cold tier is on, ClickHouse is a required, stateful service in SOC 2 scope.
  - In the two-valued mode, "not a member" can mean "does not match" or "unknown"; only K3 tells
    them apart, and the documentation must say so.
- **Neutral.** Config criteria that need live inputs (`config A OR config B`) wait for slice 3.

## Considered options

| Option | Why not |
|---|---|
| A separate run store beside result sets | Two stores for one kind of record; reversed by D10 and D11. |
| A new evaluator under `common/include/` | A fourth expression language; K3 is a mode of the existing matcher (D7). |
| Folding unknown to false at each leaf | `NONE` over missing data would come out true (D31). |
| A new `plugin_data` key for coverage | Leaks on the gateway path, absent on hash-only cycles, duplicates v3 (D34). |
| Reading inventory on the first heartbeat | Usually reads the old value just before the fresh one lands (D18). |
| Reusing `Inventory:Read` or `Execution:Execute` for runs | Cannot be granted separately later (D19). |
| A new topology-floor class | Would be a fifth; class 2 already states the purpose (D39). |
| Verdicts in Postgres for 90 days | Rejected by the owner on volume (D26). |
| Deleting outbox rows at final | Breaks the spent-ticket ledger and idempotency (D25). |
| Re-running the stored old definition text | Runs a definition an administrator may have withdrawn (D32). |

## How comparable products handle it

Surveyed from public documentation on 2026-11-18. None argues for reversing a decision.

| Product | What it does | What this ADR takes |
|---|---|---|
| 1E Tachyon | Counts "success, no content" apart from "awaiting response"; a gather window accepts late connectors; the target count is approximate. | The window (R13.1); a cohort fixed at creation and never approximate (R9.4). |
| Tanium | Merges current and cached answers into one view; some Comply releases counted errors as findings. | Read once, pinned to one receipt (R6); a cause beside the status, never folded into it (R8). |
| Microsoft ConfigMgr | Reports "not applicable" as compliant, folded at the leaf. | Fold once, at the top (R4.3). |
| Microsoft Intune | "Not evaluated" hides its causes; a default-compliant setting exists. | Named causes (R4); "decided" means no `not_assessed` (R8). |
| osquery and Fleet | Discards old results when a policy changes; passes a host whose data is unreadable. | `definition_changed` (R12.3); Full coverage for `NONE` and `ALL` (R5.4). |
| AWS Config | The evaluated code returns yes, no or not applicable; "could not tell" belongs to the service. | Server-authored causes (R4). |
| OPA Gatekeeper | Keeps exact violation counts apart from a capped sample; overwrites status each run. | Exact counts beside members (R8, R10); sibling sets with lineage (R12.1). |
| SQL | Three-valued `NULL`; `WHERE` folds unknown to false, `CHECK` lets it pass. | The fold rule (R4.3) and Q46. |
| XCCDF | Separate results for error, not checked and not applicable. | Causes on one `not_assessed` value, not a larger verdict enum. |

## Routed concerns this touches

The implementing PRs, not this ADR, match the routed-concern tables row by row. The rows this design
reaches, as of `f4cc683af1`:
- authentication and RBAC (the new securable), the authorization-topology floor, per-device dispatch
  visibility and service-scoped confinement (`.claude/routed-concerns-access-control.md`);
- the Postgres substrate (the store changes and the ADR-0006 exception) and clock-guarded retention
  (`gc_sweep`'s new predicate) (`.claude/routed-concerns.md`);
- the agent daily-sync framework (the facet-state read and the ingest hook);
- the executions-history ladder and the Forensics tier on stored responses, from slice 3;
- agentic-first A1 to A5 (every new REST route and MCP tool).

## Not decided here

- The names and shapes of the run request, its REST route and its MCP tool.
- How `from_result_set:<run>` treats members that are not `matched`. Members carry every cohort
  device with its verdict (R7), while today's scope atom reads every member as in scope
  (`server/core/src/agent_registry.cpp:2301-2330`, through `member_set_owned`).
- Whether `kMaxPerOwner` counts `criteria_run` sets separately.
- The byte budget and eviction rule of the member cache (R10.1).
- The by-id execute routes ignoring `enabled` for every definition: a separate change.

## Open points

| Mark | Section | Question |
|---|---|---|
| Q41 | R8 | Run status and where `not_assessed` causes live (D16 against the code). |
| Q42 | R12 | Re-runs in slice 1 (D13 against re-eval refusing `inventory_query`). |
| Q43 | R5 | Whether a row under a Partial part proves current presence (D34, D35). |
| Q44 | R7 | An early transient status settling the device (D5). |
| Q45 | R11 | 90 days against evidence norms (D26). |
| Q46 | R4 | Whether the act phase must require `"logic":"k3"` (D31). |
