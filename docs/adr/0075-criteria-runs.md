# ADR-0075: Criteria runs: three-valued verdicts over several inputs, stored as a result set

- **Status:** Proposed (draft 3)
- **Date:** 2026-11-18 (draft 1); 2026-11-20 (drafts 2 and 3)
- **Owner:** Nathan Dornbrook / platform (block `0xxx`; see `docs/adr/README.md`)
- **Deciders:** Nathan Dornbrook. The owner's decisions D1 to D53, made between 2026-11-07 and
  2026-11-20 while reviewing a contributed criteria-run plan (version 4.1, 2026-11-06). This ADR
  cites them by number in brackets, for example (D25). It writes them down; it does not reopen them.
  Where a later decision replaced part of an earlier one, the later one is cited.
- **Builds on:**
  - `0072-scope-lifecycle-and-freshness.md` **as amended by D15**: an evaluation is metadata on a
    result set (completeness, `evaluated_at`, a members hash), not a row in a separate evaluations
    table, and its row grammar is the extended `result_set_matcher`. ADR-0072 is Proposed and not
    yet in the repository. It is revised in place for D15 and lands alongside this ADR (D40).
  - `docs/scope-walking-design.md` (result sets, `parent_id` lineage, re-eval, the incomplete-set
    rule) and `0036-result-set-store-postgres-migration.md` (the store on Postgres).
  - `0016-agent-daily-sync-framework.md` (installed-software inventory, blob v3, facet state).
  - `0017-management-group-confinement-list-reads.md` (admit, then filter) and
    `0033-access-control-spine.md` (one dispatch intersection; targeting is never authorization).
  - `0006-server-postgresql-substrate.md` and `0012-server-postgres-store-contract.md`. This ADR needs
    a narrow exception to ADR-0006, written as its own change (D27).
- **Depends on drafts not in the repository:** ADR-1012 (explicit response completeness), ADR-1013
  (the instruction operation digest) and ADR-1014 (armed conduits), all Proposed in the `1xxx`
  block. The response-store ADR (D30) is not yet written.
- **Code references:** every `path:line` in this ADR is at `DevNullLtd/Yuzu@f4cc683af1`. Drafts 2
  and 3 were written on a branch whose only change from that commit is this file, so the code is
  the same.

## Binding status

This ADR binds prospectively on acceptance. Nothing it describes is built. It covers all three
slices (D12); slice 1 is specified in full and slices 2 and 3 only as far as the decisions go.

Slice 1 is a **breaking change** to three shipping surfaces (R3.3). It ships with a `changelog.d/`
fragment and an upgrade note in `docs/user-manual/upgrading.md`, not with a deprecation window
(D48). Both are owed by the implementing PR; this ADR adds neither.

One point is deliberately left open. It is marked **Open (Q54 pending)** where it arises, and no
implementing PR may decide it. Four further points are this ADR's own design rather than an owner
decision; each is marked **Proposed, awaiting owner confirmation** where it arises, and none binds
until the owner confirms it. Both kinds are listed together under *Open points*.

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
| The matcher grammar is a `kind` matcher or one `{column, op, value}` test with `op` in `eq`, `in`, `contains`, `exists`, meaning "SUCCESS and at least one row satisfies it". A non-SUCCESS answer never qualifies. There is no ordering operator and no three-valued mode. | `server/core/src/result_set_matcher.hpp:23-50`; `result_set_matcher.cpp:63-80` |
| One admission validator, `validate_matcher_object`, and a two-valued `response_matches`. | `result_set_matcher.hpp:63`, `:89`; `result_set_matcher.cpp:315`, `:376` |
| `evaluate_inventory` has three callers: `POST /api/v1/inventory/evaluate` (read-only, fleet-read `Inventory:Read`), `POST /api/v1/result-sets/from-inventory-query` (scoped `Inventory:Read`) and MCP `create_result_set_from_inventory_query`. | `server/core/src/rest_api_v1.cpp:14988`, `:15013`, `:15112`; `:16149`, `:16203`, `:16474`; `mcp_server.cpp:17650`, `:17915` |
| All three read the generic `InventoryStore`, which excludes every typed source, `installed_software` included, in SQL. | `rest_api_v1.cpp:16426`; `server/core/src/inventory_store.cpp:134-143`; `typed_inventory_sources.hpp:34-53` |
| The inventory conditions have their own grammar: a list of `{plugin, field, op, value}` with `op` in `==`, `!=`, `>=`, `<=`, `>`, `<`, `contains`, `exists`, `version_gte`, `version_lte`, `combine` all or any, at most 500 conditions. Its numeric rules infer the domain from the operand's JSON type and tolerate a stored string that only starts with a number. | `server/core/src/inventory_eval.hpp:14-60`, `:101-105`, `:117`; `inventory_eval.cpp:529-570` |
| Its version operators use a private segment comparator in `inventory_eval.cpp`, not the `compare_versions` of `nvd_db`, which the agent-update path uses. | `inventory_eval.cpp:62-82`, `:539-540`; `nvd_db.cpp:29`; `agent_service_impl.cpp:2663` |
| The MCP tool's input schema requires `conditions`. | `mcp_server.cpp:1623-1640` |
| The other single-input producer routes: direct create, `from-echo-query`, `from-instruction-result`. | `rest_api_v1.cpp:15816`, `:16548`, `:16660` |
| `from-instruction-result` and re-eval are gated by `Execution:Execute`. Re-eval checks the gate before it loads the set, so the gate cannot depend on the set's kind. The check was added as a missing-authorization (CWE-862) fix. The MCP tool does the same. | `rest_api_v1.cpp:16660`, `:16677`, `:16871`, `:16877-16890`; `mcp_server.cpp:5784`, `:18290-18311` |
| An MCP tool's security row carries one `(securable, operation)` pair, and the tier and approval rules are keyed on that pair: the operator tier admits `Execution:Execute`, and the supervised tier needs approval for it. | `mcp_server.cpp:5558-5566`; `mcp_policy.hpp:25`, `:129`, `:148`, `:160` |
| Before a supervised-tier approval ticket is minted or redeemed for `reevaluate_result_set`, the server checks `Execution:Execute`, reads the stored set and binds the ticket to the `(plugin, action)` it would run. A set of any kind other than `echo_query` or `instruction_result` binds `unresolved`, which no real pair can equal. | `mcp_server.cpp:10191-10208`, `:10238-10291` |
| Re-eval is refused unless the set is `echo_query` or `instruction_result`, and its route description says sync sources are not supported. | `rest_api_v1.cpp:16945-16950`, `:2987`; `mcp_server.cpp:18362-18369` |
| The `from_result_set:` scope atom admits every member of an owned set. | `server/core/src/agent_registry.cpp:2295-2335` |
| An incomplete set resolves under a positive reference; under `NOT`, `LEN` or `STARTSWITH` it aborts with `result_set_unusable`. | `docs/scope-walking-design.md:164` |
| `installed_software` coverage per part is stored in `software_facet_state` (status, token, `last_confirmed_at`, and so on), one row per device and facet. | `server/core/src/software_inventory_store.cpp:414-425` |
| The facet statuses are `full`, `delta`, `constrained`, `timeout`, `oversize`, `not_collected`, `disabled`. | `server/core/src/inventory_blob_v3.hpp:81-89` |
| A status-only section updates the facet's status but leaves its rows, `last_confirmed_at` and `section_hash` alone. | `software_inventory_store.cpp:1940-1960` |
| The store's own row read, `query_software`, already returns each row with its facet's status and `last_confirmed_at`, filtered by an optional agent-id list in SQL. | `software_inventory_store.hpp:207-252`, `:821`; `software_inventory_store.cpp:2284`, `:2309`, `:2411` |
| The agent writes blob v3: a complete facet as rows, any other as a status-only section. | `agents/core/src/sync_source_installed_software.cpp:1099-1111`; `agents/core/meson.build:86` |
| A hash-only report refreshes `last_seen` with server receipt time. | `software_inventory_store.cpp:1470-1475` |
| The store already reads facet state and `last_seen` per device for other routes. | `software_inventory_store.hpp:828-838` (`query_hosts`); `software_inventory_store.cpp:2109` (`source_last_seen_bulk`) |
| The sync interval resolves per management group, 1 h to 7 days, default 1 day. | `server/core/src/collection_settings_resolve.hpp:62-64`, `:78`, `:150-153` |
| The 48 h stale constant is used for the stale pill and gauge. | `server/core/src/software_catalogue_model.hpp:59` |
| `AgentExecStatus.status` is a free string and `error_detail` a plain, Forensics-sanitised string. | `server/core/src/execution_tracker.hpp:143-164` |
| §9.3's aggregate statuses are driven by `minSuccessPercent`, which no server code reads. | `docs/Instruction-Engine.md:775-797` |
| The topology floor has four inclusion classes and 12 Read pairs. | `server/core/src/authz_topology_floor.hpp:36-76`, `:100-154`; `tests/unit/server/test_authz_topology_floor.cpp:235` |
| 39 securables are seeded today, mirrored for MCP and pinned by a test; `CriteriaRun` would be the 40th. | `server/core/src/rbac_store.cpp:526`, `:569`; `mcp_server.cpp:6227`; `tests/unit/server/test_rbac_store.cpp:332` |
| The audit trail is kept 365 days, as a floor. | `docs/enterprise-readiness-soc2-first-customer.md:836` |
| `ClickHouseSink` is write-only, plain `INSERT ... FORMAT JSONEachRow`, with no deduplication token. | `server/core/src/analytics_sinks.cpp:38`, `:61`; `deploy/clickhouse/init.sql:27-30` |
| ADR-0006 says ClickHouse is the analytics sink, not the substrate. | `docs/adr/0006-server-postgresql-substrate.md:72-75` |
| No `vers:` comparator exists in the server. The VERS specification lists `generic` but says its comparison algorithm "will be specified later", likely "similar to libversion". | `server/core/src/` (none); `package-url/vers-spec@be215c54ee`, `docs/types/vers-types.md:60-63` |
| At the pinned vcpkg baseline, the registry has a `libversion` port: version 3.0.4, port-version 1, MIT, source fixed by SHA512. It declares `supports: "!(windows & static)"`, because a static build produces a `version.lib` that clashes with the Windows SDK. The Windows triplet links dynamically except for the grpc stack, so on Windows it would build as a DLL. | `vcpkg.json:8`; `microsoft/vcpkg@9eec002df1`, `ports/libversion/vcpkg.json`, `ports/libversion/portfile.cmake`; `triplets/x64-windows.cmake:3`, `:83-85` |

## Vocabulary

- **Run:** one criteria question asked once over a cohort, stored as one result set of kind
  `criteria_run`.
- **Input:** one source of evidence the criteria read, named in the run request. Slice 1 has one
  kind, a stored `installed_software` read. From slice 3, a live input is one read-only instruction
  per device.
- **Input spec:** an input written in the shape its single-input producer accepts (R3.4).
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

### R1. Observation only (D1, D46)

A criteria run records verdicts. It dispatches nothing that changes a device and arms nothing. Any
later act phase is its own design, and must meet R4.4 and R14.

A later dispatch scoped by `from_result_set:<run>` is a separate act under its own authorization.
It does not make the run itself act on anything (D46).

### R2. A run is a stored result set (D4, D10, D11, D15, D38, D49)

1. A run is a row in `result_set_store.result_sets` with a new `source_kind`, `criteria_run`.
   There is no separate run store, no composite instruction-definition kind and no new evaluator.
2. The run's inputs, criteria, target and window are written to `source_payload` at creation and
   never change, like every other result set (`docs/scope-walking-design.md:77`).
3. **Runs have their own entry point** (R3.4). The producers' evaluation code is extended to serve N
   inputs and is shared by the run and by each single-input producer route (D4, D49). The
   `inventory_query` evaluation supplies the stored inputs; the `instruction_result` evaluation
   supplies the live inputs from slice 3. A run's lineage uses `parent_id` as any other result set
   does.
4. ADR-0072's evaluation record (completeness, `evaluated_at`, members hash) is metadata on this
   result set, as ADR-0072 as amended by D15 states.
5. Authoring a run is the run request itself. Nothing is stored that could be executed by id later.

### R3. Inputs and entry points (D2, D3, D12, D33, D47, D48, D49)

1. **Slice 1 reads `installed_software` only** (D33), with its parts (`pkg_inventory`,
   `msi_packages`, `windows_optional_features`, `runtimes`, `middleware`). `device_ci`,
   `app_usage`, `app_perf`, `software_licensing` and `certificate_inventory` are each added later in
   their own change, with their own gate, audit and floor decision.
2. **`inventory_query` moves wholly onto `result_set_matcher`** (D47). The matcher becomes the one
   grammar for inventory criteria. `inventory_eval`'s condition grammar ends, with
   `parse_inventory_condition`, `combine` and its private version comparator
   (`inventory_eval.hpp:14-105`; `inventory_eval.cpp:62-82`). This is part of slice 1, not a
   follow-up.
   - The evaluation reads `installed_software` through `SoftwareInventoryStore`'s own read API,
     which already returns each row with its facet's status and `last_confirmed_at`
     (`query_software`, `software_inventory_store.hpp:821`; `software_inventory_store.cpp:2309`,
     `:2411`). R5 needs both. A per-device read added for this lives in that store, beside
     `query_software`.
   - Generic sources are still read from `InventoryStore`. The typed-source exclusion on generic
     reads (`inventory_store.cpp:134-143`; `typed_inventory_sources.hpp:34-53`) is **not** touched.
   - The three callers share this one evaluation: `POST /api/v1/inventory/evaluate`,
     `POST /api/v1/result-sets/from-inventory-query` and MCP
     `create_result_set_from_inventory_query`.
   - **Proposed, awaiting owner confirmation:** sharing the one evaluation means
     `POST /api/v1/inventory/evaluate` also gains `installed_software` reads, under its existing
     fleet-read `Inventory:Read` gate (`rest_api_v1.cpp:15013`). The decisions list it among the
     moved surfaces but do not say so explicitly; this ADR draws the consequence and the owner has
     not yet confirmed it.
3. **The old condition-list shape is refused, not translated** (D48). The three surfaces accept
   matcher JSON only.
   - A request carrying `conditions` (or `combine`) gets an A4 `400`, MCP `-32602`, whose message
     names the new field (`matcher`, a working name). There is no translation layer and no legacy
     operator.
   - The MCP input schema (`mcp_server.cpp:1623-1640`), the OpenAPI entries and the user manual
     change in the same PR.
   - Nothing is migrated on the server: re-eval refuses `inventory_query`, so no stored condition
     list is ever replayed. Saved requests live only in callers' scripts.
   - It is a breaking change, with a `changelog.d/` fragment and an upgrade note (see *Binding
     status*).
4. **A run is created through its own entry point** (D49): `POST /api/v1/criteria-runs` and MCP
   `create_criteria_run` (working names).
   - It is gated on `CriteriaRun:Execute`, then narrowed by each input's data gate (R9.3, D21).
   - It writes a result set with `source_kind=criteria_run` (D10).
   - It has one gate, one audit verb and one A5 tool description.
   - Each input is an input spec, in the shape its producer already accepts: an inventory input is a
     source name and matcher JSON.
5. **The producer routes stay single-input**, on their own gates (`rest_api_v1.cpp:15816`,
   `:16149`, `:16548`, `:16660`; MCP twins at `mcp_server.cpp:1623-1677`). None gains a `kind` flag
   or a second gate chosen by a body field.
6. **Live inputs arrive in slice 3** (D12). Each is one command per input per device, with a stable
   command id (D3). ADR-0011's removal of the agent-side bundle is not reopened.
7. **A live input gives a definite value only when its answer carries ADR-1012's completeness record
   as Full with plugin status OK**, and only actions that declare completeness may be live inputs
   (D2). No second ADR-1012 exception is made.

How an inventory input reads as rows:
- For `installed_software`, each stored row is one row, and its columns are the row's fields (name,
  version, publisher, ecosystem, source, purl and the rest the store returns).
- For a generic source, the device's record for that plugin is one row, and a column is a dotted
  path into it, as the old `field` was.
- A record the old evaluator excluded as too deep or unparseable is `malformed_value` (R4.2), never
  a silent non-member in K3.

### R4. The verdict (D7, D8, D14, D31, D41, D46)

1. **One grammar.** `result_set_matcher` gains quantifiers over an input's rows (`ANY`, `NONE`,
   `ALL`, `COUNT WHERE`), boolean combinators (`and`, `or`, `not`) over row tests and over named
   inputs, ordering operators and a version comparator (R4.7 to R4.12). The new constructs are
   allowed in both modes and pass the same `validate_matcher_object`.
2. **Evaluation is always three-valued** (Kleene K3). A row test with a missing field, a value that
   does not parse for the test, or an answer over the row bound is unknown, with cause
   `missing_value`, `malformed_value` or `row_bound`.
3. **The two-valued mode, the default, folds unknown to false once, at the top**, as SQL's `WHERE`
   does, and never at a leaf. Folding at a leaf would let `NONE(...)` over missing data come out
   true. `response_matches` keeps its `bool` signature by folding at the top, so every existing
   matcher gives exactly today's result (today's grammar has no negation, so both fold points agree
   on it).
4. **A run always evaluates in K3 and never folds** (D46). `"logic":"k3"` returns the three-valued
   result with its cause; a run sets it and a caller cannot unset it. The two-valued fold is right
   for selecting devices and is never applied to a run. **A future act phase never acts on a
   `not_assessed` device**, and this ADR binds it to that.
5. **`ALL` over an empty, Full answer is true** (D8). `NONE` over an empty, Full answer is true.
6. **Verdict mapping:** true is `matched`, false is `not_matched`, unknown is `not_assessed`.

The cause is a **typed column** on the verdict row, from a closed list (D41). It is never packed into
`error_detail`. From slice 3, `error_detail` passes through unchanged as display text, still
Forensics-sanitised (#4990). The closed list, by slice:

| Cause | Meaning | From |
|---|---|---|
| `missing_value`, `malformed_value`, `row_bound` | the row test could not be decided | slice 1 |
| `coverage_unproven` | `NONE` or `ALL` over a part that is not Full (R5) | slice 1 |
| `unconfirmed` | `ANY` rests on a row whose facet was last confirmed outside the freshness window (R5.4) | slice 1 |
| `stale`, `no_inventory` | no fresh inventory by the deadline (R6) | slice 1 |
| `withheld:<securable>` | the creator may not see this device under that input's gate (R9) | slice 1 |
| `unanswered` | a live input was sent and no answer arrived (R13) | slice 3 |
| `transient:<status>` | a live input answered with a transient plugin status (R7.2) | slice 3 |
| `withheld:authority_withdrawn` | the creator's token was revoked or expired (R9) | slice 3 |
| plugin and completeness causes | a live answer that is not Full or not OK | slice 3 |

The plugin and completeness causes follow ADR-1012 when it lands; this ADR does not name them. A new
cause is a change to this list, never free text.

#### Ordering and typed comparison (D14, D48, D50 to D52)

The design below is new. `inventory_eval.hpp:14-60` was read as input to it, not as a contract to
keep (D48). Where it differs, the old result is not preserved.

7. **Four ordering operators, `lt`, `le`, `gt`, `ge`**, spelled like `eq`. There is no `ne`: a
   negated test is written with `not`, so `ANY(not eq)` ("some row differs") and `NONE(eq)` ("no row
   equals") stay distinct and visible in the criteria.
8. **Every ordering test names its domain**, `"as":"number"` or `"as":"version"`. Admission refuses
   an ordering test without one. The domain is never inferred from the operand's JSON type, as the
   old grammar did. `eq` and `in` may carry `as` to compare in that domain. Without `as` they stay
   today's text compares, so existing matchers keep their results (D31).
9. **The number domain is strict, and compares exact decimal values** (D50). Nothing is rounded
   through a double.
   - The operand is a JSON integer (within int64 or uint64), or a string in plain decimal form
     (optional `-`, digits with an optional fraction, an optional exponent). A JSON float operand is
     refused at admission, because its text is gone once parsed; this reason is unchanged from
     `inventory_eval.hpp:74-77`.
   - A stored JSON integer is exact. A stored JSON float is compared by the exact value it holds.
     A stored string counts as a number only when the **whole** string is in plain decimal form, so
     stored `"10.0"` equals operand `10`.
   - Any other stored value is `not_assessed` with cause `malformed_value`, never false and never
     compared as text: a boolean, an array, an object, an empty string, or a string that only starts
     with a number. `"5 GB"`, `"1.2.3"` and `"N/A"` all settle this way, and the run page counts them
     under that cause. A missing or null value is `missing_value`.
   - The old grammar's leading-number reading, which read `"5 GB"` as 5 and `"1.2.3"` as 1.2 under a
     string operand "so devices that matched before keep matching" (`inventory_eval.hpp:43-57`;
     `inventory_eval.cpp:556-566`, and the older leading-number read at `:568-597`), ends with that
     grammar. No flag brings it back. A value that carries a unit is fixed at the collector, which
     should report a typed numeric field.
   - `-0` equals `0`.
   - **Proposed, awaiting owner confirmation:** a lexeme longer than 64 bytes, or an exponent outside
     -1000 to 1000, is refused as an operand and is `malformed_value` when stored. These bounds keep
     the comparison cheap and would be server constants. They are this ADR's proposal, not an owner
     decision.
   - Accepted cost: a single-input producer used without K3 folds unknown to false at the top
     (R4.3), so a device storing `"5 GB"` drops out of that set without a trace, as a device storing
     `"N/A"` does today. Runs are always K3 (R4.4) and show it.
10. **The version domain orders by libversion's comparison algorithm** (D14, D48, D51), from
    `repology/libversion`. The VERS specification says `vers:generic` will likely be similar to it,
    but has not written the algorithm down (`package-url/vers-spec@be215c54ee`,
    `docs/types/vers-types.md:60-63`), so this ADR names libversion itself rather than an unwritten
    scheme. `nvd_db`'s
    `compare_versions` and `nvd_version_compare` are not used for criteria, and `inventory_eval`'s
    private comparator is deleted. The comparator is a total order. Equality under `"as":"version"`
    is the comparator's equality, not text equality.
    - **The pin is a content hash, never a release tag.** A tag can be moved upstream; a hash cannot.
      A release name such as 3.0.4 is a label for people only. The implementing PR chooses one of two
      routes, and either way names its pin as a hash:
      - *A vcpkg dependency.* The pin is the manifest's `builtin-baseline` commit (`vcpkg.json:8`),
        which fixes the port version, and the port fixes the source tarball by SHA512. At today's
        baseline that is `libversion` 3.0.4, port-version 1 (see *What exists today*). Its port
        refuses a static Windows build, and Yuzu's Windows triplet is dynamic outside the grpc stack
        (`triplets/x64-windows.cmake:3`, `:83-85`), so on Windows it builds as a DLL. The port's own
        comment warns of a `version.lib` name clash with the Windows SDK. Both are `build-ci` items in
        the implementing PR.
      - *A reimplementation.* The algorithm and libversion's test corpus are pinned to one libversion
        commit SHA, and the corpus runs as a conformance test.
    - **Changing the pin is a breaking change**, because it can change which devices match the same
      stored data. It ships with a `changelog.d/` fragment, an upgrade note and the diff of the
      corpus results.
    - **Ecosystem orders are not modelled in slice 1:** dpkg epochs and `~`, and RPM release fields.
      The user documentation says so.
11. **There is no text ordering** (D52). `lt`, `le`, `gt` and `ge` are admitted only under
    `"as":"number"` or `"as":"version"`. Text supports `eq`, `in`, `contains` and `exists` only.
    - An ordering test with no `as`, or naming any other domain, is refused at admission. It never
      falls back to comparing text.
    - The old lexical fallback (`inventory_eval.hpp:54-56`; `inventory_eval.cpp:599-606`) ends with
      the old grammar.
    - `"as":"text"`, byte-wise over UTF-8, can be added later without breaking anything. Comparing
      dates, if wanted, is a future `"as":"date"` domain that really parses dates, not a byte order
      that happens to sort ISO dates correctly.
    - Accepted cost: "installed before a date" cannot be expressed until a date domain exists.
12. **The cases are pinned by tests.** Each numeric and version case in today's `inventory_eval`
    tests is re-expressed in matcher JSON, and every case whose result changes is listed in the
    upgrade note. For example, a stored `"5 GB"` against `>` with the string operand `"4"` is a
    match today; under `gt` it is `malformed_value`.

### R5. Coverage comes from the facet state (D34, D35, D43)

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
4. **A found row proves presence (`ANY` true) only if its facet's `last_confirmed_at` is inside the
   R6 window measured at run start** (resolved `interval_s` + 2 h; 26 h on the default) (D43).
   Under a Full facet this always holds, because the cycle just confirmed it. Under a Partial facet
   a status-only section leaves the last confirmed rows in place, unconfirmed
   (`software_inventory_store.cpp:1940-1960`); a row older than the window leaves the device
   `not_assessed:unconfirmed`.
5. `NONE` and `ALL` need Full; otherwise the device is `not_assessed:coverage_unproven`.
6. Freshness (R6) never stands in for coverage.

The agent side is already met: a constrained part is sent as a status-only section and never as
rows (`sync_source_installed_software.cpp:1099-1111`), so Full with zero rows comes only from a
complete read. `last_confirmed_at` is already joined onto row reads
(`software_inventory_store.cpp:2309`, `:2411`).

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

### R7. Settling: read once, written once (D5, D18, D25, D44)

1. A verdict is written onto the member row once. `result_set_members` gains nullable `verdict` and
   `cause` columns, written by an update guarded on `verdict IS NULL`, never through the member
   insert (that insert uses `ON CONFLICT DO NOTHING`, `result_set_store.cpp:400-401`, and would keep
   a stale value silently).
2. **A transient plugin status is final** (D5, D44; from slice 3). An answer such as `UNAVAILABLE`
   or `windows:dism:busy` settles the device at once as `not_assessed:transient:<status>`, with no
   retry inside the window, even when most of the window is left.
3. This is an **accepted cost**. A retry is not cheap: the same-id re-send of R13.2 covers only
   unanswered commands, and the agent's dedup store replays the original terminal answer for a
   duplicate id and never re-executes (`docs/command-dedup.md`, invariant 4). A retry would need a
   new command id and a second dispatch record per (device, input).
4. The run page shows how many devices settled this way. The remedy is a whole-run re-run (R12.1);
   there is no filtered re-run, because sibling runs over different devices would not be
   comparable.

`docs/Instruction-Engine.md:765-770` describes a retry for transient plugin errors; no criteria-run
path uses it.

### R8. Run status (D16, D41)

1. **Run status is the run's own lifecycle**: `gathering` from creation, then `final` (D41).
   **Proposed, awaiting owner confirmation:** the result set's store status reads `pending` while
   gathering and `materialized` at final, so the existing readiness rules apply unchanged: a
   gathering run used as a scope aborts as pending (`docs/scope-walking-design.md:164`). A run whose
   store write fails is `failed`. D41 names only the lifecycle; this mapping onto the store statuses
   is this ADR's design.
2. **The verdict counts sit beside the status**: `matched`, `not_matched`, and `not_assessed` by
   cause, plus the count of devices excluded from the cohort (R9.4). They say what the answers mean;
   the status says only whether the run is still gathering.
3. The status does not depend on the Instruction Engine's §9.3 aggregate or `minSuccessPercent`
   (`docs/Instruction-Engine.md:775-797`), which stay unbuilt. Slice 1 sends no command, so there is
   no `AgentExecStatus` to aggregate.
4. ADR-0072's `complete` and `incomplete` are not overloaded for the verdict counts. When an act
   phase arrives, "decided" means a `not_assessed` count of zero (D16).

### R9. Authority (D6, D19, D20 parts 2-4, D21, D22, D39)

1. **A new securable, `CriteriaRun`**, seeded to Administrator only. `CriteriaRun:Execute` starts a
   run; `CriteriaRun:Read` reads one. Neither is implied by `Inventory:Read` or `Execution:Execute`.
   It is the 40th securable (39 are seeded today: `rbac_store.cpp:569`;
   `test_rbac_store.cpp:332`). The MCP mirror (`mcp_server.cpp:6227`), the MCP tier and annotation
   rows, and the OpenAPI and SOC 2 inventory rows are updated in the same change.
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
9. A service-scoped token is refused on the run entry point, as on the existing producers.

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

### R11. Retention: warm in Postgres, cold in ClickHouse, summary in the audit trail (D25 to D29, D37, D45)

1. **The run's set lives from creation.** Its `ttl_at` is set at creation to the deadline plus the
   warm setting, and reset at final to final plus the warm setting. It is never pinned. This
   changes only what `gc_sweep` reads; there is no second delete path. Without it, a run with a
   window longer than an hour would be reaped mid-run (`result_set_store.cpp:337`, `:1443-1445`).
2. **Warm for 20 minutes by default** after final, in Postgres.
3. **Then cold in ClickHouse for 90 days**, as the store of record. This needs the narrow ADR-0006
   exception (D27) to the clause that keeps ClickHouse as the analytics sink only
   (`0006-server-postgresql-substrate.md:72-75`): ClickHouse may hold append-only, retention-bound
   records; every read goes through core under R9's gates; only core holds the credentials; Grafana
   gets no datasource on these tables; Postgres stays the only substrate for transactional state.
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
7. **One audit event at final** (D45). When a run reaches `final`, one audit event records the
   creator, the input definitions and their digests, the target, the start and final times, and the
   counts (matched, not_matched, not_assessed by cause, excluded). It carries counts only, never
   device ids. It lives in the audit trail, kept 365 days as a floor
   (`docs/enterprise-readiness-soc2-first-customer.md:836`), and fails like every other audit write.
8. **Per-device verdicts are working data, not SOC 2 evidence.** The documentation says so plainly.
   If an act phase needs per-device evidence, that is the act phase's decision. Accepted cost: after
   90 days the record can say "device D was in a cohort of N, of which M matched", but not D's own
   verdict.

### R12. Re-runs and refusals (D13, D32, D38, D42, D53)

1. **An operator may re-run a run, from slice 1** (D42). The existing re-eval action
   (`POST /api/v1/result-sets/{id}/re-eval`, MCP `reevaluate_result_set`) accepts
   `source_kind=criteria_run`. A re-run replays the input specs stored at creation against the
   inventory stored now, with a new window, under the re-running operator's current authority, and
   produces a new sibling result set with lineage. There is no second "run again" path.
2. Only `criteria_run` is added to re-eval's accepted kinds (`rest_api_v1.cpp:16945-16950`;
   `mcp_server.cpp:18362-18369`). Re-eval of `inventory_query` and `manual_curate` stays a separate
   follow-up. The route description (`rest_api_v1.cpp:2987`) is updated in the same change.
3. **No automatic or scheduled re-walk.** Tracking consumers, schedules and `allow_rewalk` are
   refused until an ADR-1014 conduit design covers them.
4. **`definition_changed`** (from slice 3). Each live input records its definition's ADR-1013
   digest in `source_payload` at creation. A re-run recomputes each digest and, if any differs, is
   refused with `definition_changed`, naming the input and both digests. Nothing is dispatched; the
   operator starts a new run.
5. **`definition_disabled`** (from slice 3). A run or re-run whose live input names a definition with
   `enabled: false` is refused at creation with `definition_disabled`, the word the schedule runner
   already uses (`schedule_runner.cpp:98`), naming the input and the definition. Deliveries already
   under way continue, because they are built from the stored specs.
6. **The re-run gate: a floor, then the owned set, then its stored kind** (D53). On
   `POST /api/v1/result-sets/{id}/re-eval` and MCP `reevaluate_result_set` the order is:
   1. **Floor, before the load.** The caller must hold `Execution:Execute` or
      `CriteriaRun:Execute`. A session with neither grant is refused before any stored row is read,
      which keeps the missing-authorization fix recorded at `rest_api_v1.cpp:16877-16887`. Today the
      floor is the single `Execution:Execute` check at `rest_api_v1.cpp:16888` and
      `mcp_server.cpp:18291`.
   2. **`load_owned`** (`rest_api_v1.cpp:16891`; `mcp_server.cpp:18309`). It is owner-scoped, so
      another owner's set reads as not found and the reorder reveals nothing about it.
   3. **The gate by stored `source_kind`.** The kind is written by the server at creation, not read
      from the request body, so this is not the gate-by-body-field pattern D49 rejected.
      - A `criteria_run` set needs `CriteriaRun:Execute`, narrowed by each input's own gate, as at
        creation (R9.3, D21). An input that dispatches, from slice 3, still needs
        `Execution:Execute`.
      - Every other kind keeps `Execution:Execute`, unchanged.
   4. **MCP.** The tier row for `reevaluate_result_set` (`mcp_server.cpp:5784`) admits either
      securable, and the per-kind RBAC check runs after the load. Tier still runs before RBAC.
   5. **The supervised-tier approval pre-check** follows the same order. It checks
      `Execution:Execute` and reads the stored set before a ticket is minted or redeemed
      (`mcp_server.cpp:10191-10208`, `:10238-10291`), so its check becomes the same floor. What its
      ticket binds to for a `criteria_run` set is Q54.
   6. There is still one re-run path (R12.1). There is no criteria-run-specific re-run route.

> **Open (Q54 pending):** what a supervised-tier approval ticket binds to when an MCP caller re-runs
> a `criteria_run` set. Today the pre-check binds a ticket to the `(plugin, action)` the re-run
> would dispatch, read from the stored set. Any kind other than `echo_query` or
> `instruction_result` binds `unresolved`, which no real pair can equal, so the call is refused
> (`mcp_server.cpp:10249-10258`, `:10286-10290`). A slice-1 run dispatches nothing, so there is no
> pair to bind. Whether a supervised re-run needs approval at all also turns on how the tier and
> approval rules, which are keyed on one `(securable, operation)` pair per tool
> (`mcp_server.cpp:5558-5566`; `mcp_policy.hpp:129`, `:160`), treat `CriteriaRun:Execute`.
> - (a) Bind the ticket to the stored kind and a digest of the stored input specs and target, so
>   an approval is for exactly the re-run it names, and give a re-run the same approval rule as
>   creating a run.
> - (b) Need no approval for a re-run that dispatches nothing (slice 1); from slice 3, bind to the
>   live inputs' `(plugin, action)` pairs.
> - (c) Leave it as it is: a supervised-tier token cannot re-run a `criteria_run` set over MCP.
>
> Recommendation (a): the re-run is the same act as the creation it repeats, so it should need the
> same approval, and a digest gives the ticket something exact to bind to. (b) makes the approval
> rule change between slices, and (c) leaves a gap between REST and MCP that nothing records.

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

### R14. Consuming a run's result (D37, D46)

1. **`from_result_set:<run>` resolves to the run's `matched` members only** (D46). Members carry
   every cohort device with its verdict (R7), and today the atom admits every member
   (`agent_registry.cpp:2295-2335`). Without this, a follow-up dispatch would also reach
   `not_matched` and `not_assessed` devices.
2. **A run with any `not_assessed` device is an incomplete set** under the existing scope-walking
   rule (`docs/scope-walking-design.md:164`). A positive reference resolves. `NOT`, `LEN` or
   `STARTSWITH` over it aborts with `result_set_unusable`, permanently, because retrying does not
   change it; the remedy is a re-run.
3. **Proposed, awaiting owner confirmation:** both rules ship in slice 1, because the atom can
   resolve a run's set as soon as it exists (`agent_registry.cpp:2295-2335`). D46 places the change
   in "the slice that wires runs into scope walking"; this ADR reads that as slice 1. The
   alternative is to refuse `from_result_set:<run>` in slice 1 instead. Tests cover the inversion
   hazard (a `NOT` over a run with unassessed devices).
4. **Approvals over a run's matched set.** ADR-1013's D5 (the approver can read what was hashed, for
   as long as the digest is evidence) applies only when an approval or a conduit binds a run's
   matched set, which is the act phase. Then the approval store, or the arm record, copies the
   device list when the ticket is created. The run's own retention does not change, and a ticket
   asked for after the run is gone from both stores is refused, never approved on the hash alone.

## Slices (D12)

### Slice 1: stored inventory only

**What it builds:**
- the matcher's K3 evaluation, quantifiers, combinators, ordering operators, the strict number
  domain and the libversion version order (R4), under the one validator;
- `inventory_query` moved onto the matcher, reading `installed_software` through
  `SoftwareInventoryStore` (R3.2), shared by its three surfaces; the old `conditions[]` shape
  refused on all three (R3.3), and `inventory_eval`'s grammar deleted;
- the `criteria_run` kind and its entry point, `POST /api/v1/criteria-runs` and MCP
  `create_criteria_run` (R3.4), with A5 annotations, one audit verb at creation and the summary
  event at final (R11.7);
- the coverage read and mapping with the confirmation test (R5), the freshness test and
  read-on-receipt hook (R6);
- write-once verdicts with typed causes on the members (R7, R4), and the lifecycle status with the
  counts beside it (R8);
- re-eval of `criteria_run` sets, behind the floor, the owned-set load and the stored-kind gate
  (R12.1, R12.2, R12.6);
- the matched-only scope atom and the incomplete-set marking (R14.1 to R14.3);
- the export to ClickHouse and the reap guard (R11).

**The run, step by step:**
1. **Admission.** `CriteriaRun:Execute`; each input spec is bounded and its matcher passes
   `validate_matcher_object`; a service-scoped token is refused, as on the existing producers.
2. **Creation.** A `criteria_run` set, status `gathering` (store `pending`), with its
   `source_payload` and `ttl_at` set from the deadline (R11.1).
3. **Cohort.** The target intersected with the creator's visible devices under scoped
   `Inventory:Read` (R9.3). Excluded devices are counted.
4. **Reads.** Fresh devices are read at start; the rest on their first receipt in the window (R6).
5. **Verdicts.** Each device is evaluated in K3 once its read is in (R4, R5) and its verdict and
   cause written once (R7).
6. **Final.** Every device settled, or the deadline passed; unread devices settle as `stale` or
   `no_inventory`. The status becomes `final` (store `materialized`), `ttl_at` is reset, the summary
   audit event is written and the export starts (R11).

**Prerequisites, each its own change:**
- the agent's v3 writer (D34): already shipped (`sync_source_installed_software.cpp:1099-1111`);
- the `CriteriaRun` securable and the widened class 2 with its floor entry (R9.1, R9.2);
- the matcher's K3, quantifiers, combinators and typed comparison (R4.1 to R4.12);
- the libversion pin, by content hash (R4.10): either the vcpkg port at the pinned baseline, with
  its Windows DLL build and the `version.lib` name clash settled by `build-ci`, or a reimplementation
  pinned to one libversion commit with its corpus as a conformance test;
- the owner's confirmation of the four points marked *Proposed, awaiting owner confirmation*
  (R3.2, R4.9, R8.1, R14.3);
- Q54 answered, before the MCP re-run of a `criteria_run` set ships (R12.6);
- the move of `inventory_query` onto the matcher and the refusal of the old shape (R3.2, R3.3),
  with its `changelog.d/` fragment and upgrade note;
- the four store changes (R10);
- `ttl_at` from creation (R11.1);
- the ADR-0006 exception and the ClickHouse cold store (R11.3 to R11.5).

**Not in slice 1:** live inputs, deliver-on-connect, token checks per delivery, `definition_changed`,
`definition_disabled`, `transient:<status>`, any act phase, and reads by anyone but the creator.

### Slice 2: ADR-1012

The explicit-completeness contract for command responses lands and adopts R5's mapping. No
criteria-run surface changes.

### Slice 3: live inputs and deliver-on-connect

Live inputs (R3.6, R3.7), deliver-on-connect and `unanswered` (R13), transient answers settling as
final (R7.2), per-step visibility and token checks (R9.5, R9.8), and the two refusals (R12.4,
R12.5). Prerequisites: deliver-on-connect, the token store's durable generation, #4166, the
response-store ADR and ADR-1013's digest.

## Consequences

- **Positive.** One stored shape for every scope-walking result; one grammar for inventory criteria
  and result-set membership; a device with no evidence is never reported as not matching; missing
  data cannot become a match through negation; a run used as a scope reaches only matched devices;
  existing matchers keep their results; the securable shows up as its own line in an access review
  and can be granted separately later.
- **Costs accepted.**
  - Slice 1 is larger: it re-homes a shipping REST and MCP surface, and every caller of the three
    inventory-query surfaces must rewrite its requests on the day it ships. There are no production
    users, so no translation layer is kept (D48).
  - Stored values the old grammar matched by a leading number or a lexical compare no longer match
    in the two-valued mode, and read `malformed_value` in K3 (R4.9, R4.11). A value with a unit
    has to be fixed at its collector.
  - Changing the libversion pin is a breaking change of its own, with a fragment, an upgrade note
    and the corpus diff (R4.10). Ecosystem version orders such as dpkg epochs are not modelled.
  - "Installed before a date" cannot be expressed until an `"as":"date"` domain exists (R4.11).
  - Slice 1 waits on four store changes, the securable, the matcher work and the cold store.
  - Until every agent sends v3, `NONE` and `ALL` read `not_assessed:coverage_unproven` on old agents.
  - Under a facet that stays Partial, `ANY` reads `not_assessed:unconfirmed` once its rows are older
    than the window.
  - From slice 3, an early transient answer settles a device for the whole window (R7.3).
  - A run's cohort depends on who started it, so two operators can get different answers to the
    same criteria. The excluded count makes this visible.
  - A run abandoned before its deadline holds its set until the deadline plus 20 minutes, counted
    against the 10,000-per-owner limit.
  - A long ClickHouse outage grows Postgres by about 300 MB per fleet-wide run until it recovers.
  - Where the cold tier is on, ClickHouse is a required, stateful service in SOC 2 scope.
  - After 90 days only the run's summary remains, not any device's verdict (R11.8).
  - In the two-valued mode, "not a member" can mean "does not match" or "unknown"; only K3 tells
    them apart, and the documentation must say so.
- **Neutral.** Config criteria that need live inputs (`config A OR config B`) wait for slice 3.

## Considered options

| Option | Why not |
|---|---|
| A separate run store beside result sets | Two stores for one kind of record; reversed by D10 and D11. |
| A new evaluator under `common/include/` | Another expression language; K3 is a mode of the existing matcher (D7). |
| Two grammars side by side until a follow-up | Two sets of comparison rules for one question (D47). |
| K3 added to `inventory_eval` | A second K3 implementation (D47). |
| Lifting the typed-source exclusion for the producer | Breaks the typed-source rule and loses `last_confirmed_at` (D47). |
| Translating the old `conditions[]` at admission | A compatibility layer with no one to serve (D48). |
| Keeping `compare_versions` as a legacy operator | Two version orders inside one matcher (D48). |
| A `kind` flag on the existing producer routes | The gate is chosen by a field the caller controls (D49). |
| Folding unknown to false at each leaf | `NONE` over missing data would come out true (D31). |
| A run used as a scope admits every member | Reaches devices that do not match and devices nobody could check (D46). |
| Refusing `from_result_set:<run>` until an act phase | Blocks scope walking for no safety beyond R14.1 (D46). |
| A new `plugin_data` key for coverage | Leaks on the gateway path, absent on hash-only cycles, duplicates v3 (D34). |
| Trusting a row under a Partial facet at any age | An uninstalled package stays `matched` while the facet stays Partial (D43). |
| Reading inventory on the first heartbeat | Usually reads the old value just before the fresh one lands (D18). |
| Retrying a transient answer inside the window | Retry state, a second dispatch record and a rule for disagreeing answers (D44). |
| Causes packed into `error_detail` | Unchecked parsing, exposed to the Forensics sanitiser (D41). |
| Run status as the §9.3 aggregate | Unbuilt, and slice 1 has no command to aggregate (D41). |
| Reusing `Inventory:Read` or `Execution:Execute` for runs | Cannot be granted separately later (D19). |
| A new topology-floor class | Would be a fifth; class 2 already states the purpose (D39). |
| Verdicts in Postgres for 90 days | Rejected by the owner on volume (D26). |
| Configurable or 365-day verdict retention | A SOC 2 claim depending on each customer's setting, or about four times the storage (D45). |
| Deleting outbox rows at final | Breaks the spent-ticket ledger and idempotency (D25). |
| Re-running the stored old definition text | Runs a definition an administrator may have withdrawn (D32). |

## How comparable products handle it

Surveyed from public documentation on 2026-11-18. None argues for reversing a decision.

| Product | What it does | What this ADR takes |
|---|---|---|
| 1E Tachyon | Counts "success, no content" apart from "awaiting response"; a gather window accepts late connectors; once a device answers it is done. | The window (R13.1); an early answer is final (R7.2); a cohort fixed at creation and never approximate (R9.4). |
| Tanium | Merges current and cached answers into one view; some Comply releases counted errors as findings. | Read once, pinned to one receipt (R6); a typed cause beside the verdict, never folded into it (R4). |
| Microsoft ConfigMgr | Reports "not applicable" as compliant, folded at the leaf. | Fold once, at the top (R4.3), and never for a run (R4.4). |
| Microsoft Intune | "Not evaluated" hides its causes; a default-compliant setting exists. | Named causes (R4); "decided" means no `not_assessed` (R8.4). |
| osquery and Fleet | Discards old results when a policy changes; passes a host whose data is unreadable; one query language over typed tables. | `definition_changed` (R12.4); Full coverage for `NONE` and `ALL` (R5.5); one grammar (R3.2). |
| AWS Config | A closed compliance type beside a free-text annotation; remediation acts on non-compliant only; re-evaluate re-runs a stored rule. | The typed cause (R4); matched-only consumption (R14.1); re-runs (R12.1). |
| OPA Gatekeeper | Keeps exact violation counts apart from a capped sample; overwrites status each run. | Exact counts beside members (R8, R10); sibling sets with lineage (R12.1). |
| SQL | Three-valued `NULL`; `WHERE` folds unknown to false, `CHECK` lets it pass; `NOT IN` over a `NULL` misleads. | The fold rule (R4.3); `NOT` over an incomplete run refused (R14.2). |
| XCCDF | Separate results for error, not checked and not applicable. | Causes on one `not_assessed` value, not a larger verdict enum. |

## Routed concerns this touches

The implementing PRs, not this ADR, match the routed-concern tables row by row. The rows this design
reaches, as of `f4cc683af1`:
- authentication and RBAC (the new securable), the authorization-topology floor, per-device dispatch
  visibility and service-scoped confinement (`.claude/routed-concerns-access-control.md`);
- the Postgres substrate (the store changes and the ADR-0006 exception) and clock-guarded retention
  (`gc_sweep`'s new predicate) (`.claude/routed-concerns.md`);
- the agent daily-sync framework (the facet-state read, the typed-store read and the ingest hook);
- scope walking (the matched-only atom and the incomplete-set marking);
- the executions-history ladder and the Forensics tier on stored responses, from slice 3;
- agentic-first A1 to A5 (the new REST route and MCP tool, and the changed input schema of
  `create_result_set_from_inventory_query`);
- the MCP server's tier-before-RBAC ordering and approval rules (the `reevaluate_result_set` row and
  its approval pre-check, R12.6);
- the build and vcpkg toolchain, if the libversion pin is taken as a vcpkg dependency (R4.10).

## Not decided here

- The exact JSON spelling of the run request, of an input spec and of the new matcher constructs.
  The routes and tool names in R3.4 are working names.
- The A4 error code for the refused `conditions[]` shape (R3.3); its message must name the new field.
- Whether `kMaxPerOwner` counts `criteria_run` sets separately.
- The byte budget and eviction rule of the member cache (R10.1).
- The by-id execute routes ignoring `enabled` for every definition: a separate change.
- Which route carries the libversion pin, a vcpkg dependency or a reimplementation (R4.10). The
  implementing PR chooses; either way the pin is named as a hash.
- How the `reevaluate_result_set` security row admits either securable (R12.6), given that a row
  carries one `(securable, operation)` pair today (`mcp_server.cpp:5558-5566`).

## Open points

| Mark | Section | Question |
|---|---|---|
| Q54 | R12.6 | What a supervised-tier MCP approval ticket binds to when a `criteria_run` set is re-run, and whether such a re-run needs approval. |

Proposed by this ADR and awaiting owner confirmation (each is marked where it arises):

| Section | Proposal |
|---|---|
| R3.2 | `POST /api/v1/inventory/evaluate` shares the one evaluation, so it also gains `installed_software` reads under its fleet-read `Inventory:Read` gate. |
| R4.9 | The number domain's bounds: a lexeme of at most 64 bytes and an exponent between -1000 and 1000, as server constants. |
| R8.1 | `gathering` and `final` map onto the store statuses `pending` and `materialized`, with `failed` when the store write fails. |
| R14.3 | The matched-only scope filter and the incomplete-set marking ship in slice 1, rather than refusing `from_result_set:<run>` there. |

Settled since draft 1: run status and causes (R8, R4; D41), re-runs in slice 1 (R12.1; D42), a row
under a Partial facet (R5.4; D43), an early transient status (R7.2 to R7.4; D44), retention against
evidence norms (R11.7, R11.8; D45), the act phase and K3, and a run used as a scope (R4.4, R14; D46),
and the inventory grammar and entry points (R3; D47 to D49).

Settled since draft 2: the strict number domain (R4.9; D50), the libversion version order pinned by
content hash (R4.10; D51), no text ordering (R4.11; D52), and the re-run gate by stored kind
(R12.6; D53).
