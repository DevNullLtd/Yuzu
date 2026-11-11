# Resource Ledger: ADR-1005 batch C, instruction definition and instruction set twins (#2146)

New or modified owned resources in `server/core/src/` (`instruction_store.cpp`,
`instruction_authoring_routes.cpp`, `mcp_instruction_authoring.cpp`, `mcp_server.cpp`,
`instruction_referrers.{hpp,cpp}`, `instruction_routes.cpp`, `workflow_routes.cpp`,
`product_pack_store.cpp`, `policy_store.cpp`, `workflow_engine.cpp`, `server.cpp`) and their unit
tests, across commits `9d425b09f2` to `09dcec48a2` (fix rounds 6 to 11 added the legacy-route and
pack-uninstall referrer guards, the version-bound delete, the pack advisory and the pre-mint
reads). No file descriptor, `FILE*`, socket, `HANDLE`, subprocess, mapped library, temp path,
OpenSSL object, BCrypt handle, C string, thread or callback-owned raw pointer is added to
production code. The owned things are one persisted column, three transaction shapes, a set of
short read-only pooled leases (each taken and released inside one store method), one shared
throttle, and some value containers. The test-side resources are listed last.

## Resources

### Persisted column `deleted_seed_content.last_version`
- **Site:** migration v4 in `InstructionStore::migrations()` (`instruction_store.cpp`,
  `ALTER TABLE deleted_seed_content ADD COLUMN IF NOT EXISTS last_version BIGINT NOT NULL DEFAULT
  0`), written by the tombstone upsert in `delete_definition` (`GREATEST(deleted_seed_content
  .last_version, EXCLUDED.last_version)`) inside the delete's own transaction, and read by the
  floor subquery in `insert_definition_row`'s `insert_sql`.
- **Owner type:** the existing `instruction_store` schema; the column lives and dies with its
  tombstone row. No new table, index or schema. The tombstone rows themselves are permanent and
  stamped for every deleted definition id (owner-deferred growth item `up-15` in the governance
  ledger); this change adds a column, not a retention pass.
- **Release point:** the row's own deletion. Nothing separate to release.
- **Transfer:** never. The value is read back by value inside the INSERT statement.
- **Failure cleanup:** the upsert runs inside `delete_definition`'s `with_txn_for`, so a failure
  rolls the delete and the tombstone back together. The migration runs in its own transaction
  under the migration runner and is idempotent (`IF NOT EXISTS`). Rows stamped before v4 carry
  `last_version = 0`, which floors a re-created id at `now` only (documented in `upgrading.md`).

### Plain-create transaction in `insert_definition_row`
- **Site:** the `!is_seed` branch of `InstructionStore::insert_definition_row`
  (`instruction_store.cpp`): `pool_.with_txn_for(kWriteTimeout, ...)` running
  `kSeedCoordLockSql` (`pg_advisory_xact_lock(2037545589, hashtext('instruction_store:seed_
  coordination'))`) and then the INSERT, so the tombstone floor reads a committed tombstone.
- **Owner type:** the pooled connection lease and transaction owned by `with_txn_for`; the
  advisory lock is a TRANSACTION-scope lock (`pg_advisory_xact_lock`), so it has no separate
  owner. The lambda captures three locals by reference (`failure`, `landed`, `entered`), all
  declared before the call and read after it returns.
- **Release point:** `with_txn_for` issues COMMIT when the callback returns true and ROLLBACK when
  it returns false or throws (documented at `pg_pool.hpp` "returns true, ROLLBACK when it returns
  false or throws"); the advisory lock is released with the transaction either way. The lease is
  returned to the pool when `with_txn_for` returns.
- **Transfer:** never. Nothing escapes the callback except by value (`landed`, `failure`).
- **Failure cleanup:** a pool-acquire timeout or failed BEGIN means the callback never ran
  (`entered` stays false); a failed lock or INSERT sets `failure` and returns false (ROLLBACK); a
  COMMIT failure leaves `failure` empty. The three causes are reported with three distinct texts
  under `kInstructionStoreDbErrorPrefix`. The lock is taken first in the transaction and no other
  lock or lease is held across it. It serialises creates behind a concurrent delete, import or
  seed (the same lock those paths already take), bounded by the pool's lock timeout.

### `make_definition_referrers_fn`, `DefinitionReferrersFn` and its `RefusalLogThrottle`
- **Site:** `make_definition_referrers_fn` in `instruction_referrers.cpp`, called once from
  `server.cpp` (`DefinitionReferrersFn definition_referrers_fn = make_definition_referrers_fn(
  schedule_engine_.get(), workflow_engine_.get(), policy_store_.get())`, hoisted in round 7 to
  before `register_instruction_routes`) and copied into FOUR consumers: `instruction::Deps` (legacy
  DELETE), `authoring_deps.referrers_fn` (v1 REST DELETE), `wf_deps.referrers_fn` (pack uninstall)
  and `mcp_server_->set_definition_referrers_fn(...)` (MCP delete).
- **Owner type:** `DefinitionReferrersFn` is a small class wrapping a type-erased
  `std::function<Result(const std::string&, const Exclusions&)>` (`fn_`); it owns no raw resource.
  Its converting constructors take a callable of either arity and leave `fn_` EMPTY for a null
  function pointer or an empty `std::function` (so `explicit operator bool` reports "unwired").
  The factory creates a `std::shared_ptr<RefusalLogThrottle>` (`std::make_shared<
  RefusalLogThrottle>(std::chrono::seconds(60), 8)`), captured by value through the
  `source_failed` lambda into `fn_`. Every copy shares the one throttle; `RefusalLogThrottle` is
  internally mutex-guarded (`mu_`) and bounded to 8 keys. Three NON-OWNING raw pointers
  (`ScheduleEngine*`, `WorkflowEngine*`, `PolicyStore*`) are captured by value in the same lambda.
  `DefinitionReferrerExclusions` is two `std::unordered_set<std::string>` passed by const
  reference per call and not retained.
- **Release point:** the throttle is freed when the last copy of the closure is destroyed (the four
  consumers' copies and the per-call copy `ports.referrers_fn = definition_referrers_fn_` in
  `mcp_server.cpp`). The raw pointers are never deleted by the function.
- **Transfer:** the closure is copied (shared throttle), never moved out of its owner. The pointers
  are borrowed from `ServerImpl`'s `unique_ptr` members.
- **Failure cleanup / lifetime:** the function is invoked only from request handlers.
  `stop()` joins `web_thread_` (`ServerImpl`'s stop path in `server.cpp`, `web_thread_.join()`)
  before it resets `schedule_engine_` and `policy_store_` explicitly; `workflow_engine_` has no
  explicit reset in `stop()` and is destroyed with `ServerImpl`, after the web thread has been
  joined by `stop()`. A null pointer is handled: an unwired source returns
  `std::unexpected("a referrer source is not wired")` (the delete is refused, fail closed). The
  three source reads run one after another, each acquiring and releasing its own lease; none is
  held across the next call. The device-token source is NOT added (`DeviceTokenStore` is passed
  `nullptr`, no setter caller), so no resource is owned for it.

### `PolicyStore::fragments_referencing_instruction` and `WorkflowEngine::workflows_referencing_instruction`
- **Site:** `policy_store.cpp` and `workflow_engine.cpp`. Read-only methods; no new resource type.
  Round 9 added an `exclude_ids` parameter (`const std::unordered_set<std::string>&`) used by the
  pack uninstall.
- **Owner type:** one pooled connection lease each (`pool_.try_acquire_for(kAcquireTimeout)` /
  `kReadTimeout`), one `pg::PgResult` for the SELECT, and a local `std::vector<std::string>` of
  ids returned by value inside `std::expected`. The exclusion set is a parameter, not owned: it is
  copied into a local `std::vector<std::string_view>` and bound as ONE text[] literal
  (`pg::to_text_array`, a `std::string`) in `... AND NOT (id = ANY($3::text[]))`. It points into the
  caller's set, which outlives the call. It owns no resource beyond that vector and string.
- **Release point:** scope exit (lease, result and the vector are RAII). Both reads are bounded by
  `LIMIT $2` (`kPerSourceLimit`, which is `kMaxReferrersListed + 1`), applied AFTER the exclusion so
  an excluded row never takes a slot.
- **Transfer:** the vector moves out by value; the caller moves each id into a `DefinitionReferrer`.
- **Failure cleanup:** store not open, no connection in time and a failed query each return
  `std::unexpected(...)` (a degraded read); RAII only, no partial state.

### Pack-uninstall pre-check reads (`workflow_routes.cpp`, `DELETE /api/product-packs/{id}`)
- **Site:** the `DELETE` handler's block that runs before `product_pack_store->uninstall`.
- **Owner type:** local value containers only: `own_workflows` and `own_fragments`
  (`std::unordered_set<std::string>`) filled from `ProductPackStore::get`, a
  `DefinitionReferrerExclusions`, a `std::unordered_map<std::string, std::vector<HeldByPolicy>>`
  (`policy_held`, folded policy id and name for the 409 text), and `std::vector<DefinitionReferrer>
  blocking`. The reads are `ProductPackStore::get` (one lease inside the store), then one
  `PolicyStore::query_policies` per own fragment (`fragment_filter`, `limit` 4, one lease each), then
  one `referrers_fn` call per contained definition (three leases inside it). They run SEQUENTIALLY,
  each taking and releasing its own lease; no lease is held across the next read and NONE is held
  across `uninstall()`, which takes its own.
- **Release point:** scope exit; every refusal returns before `uninstall()` is reached, so a refused
  pack is untouched.
- **Transfer:** the exclusion set is moved into `exclusions` and read by reference per call; blockers
  are moved into `blocking`.
- **Failure cleanup:** an unwired closure or policy store, or a failing read, is a 503 with the audit
  row (`referrer_check_unwired` / `referrer_check_unavailable`); never treated as "no referrers". The
  check is advisory-not-transactional (a referrer created after the reads is not seen), by design.

### `ProductPackStore::packs_containing_item` and `DefinitionPackAdvisoryFn`
- **Site:** `product_pack_store.cpp` (`packs_containing_item`), `instruction_referrers.{hpp,cpp}`
  (`DefinitionPackAdvisoryFn`, `make_definition_pack_advisory_fn`, `pack_advisory_note`), read at the
  legacy DELETE, v1 DELETE and MCP `delete_definition` call sites.
- **Owner type:** `packs_containing_item` takes ONE pooled lease (`pool_.try_acquire_for(
  kReadTimeout)`, bounded acquire, no nested lease) and runs ONE bounded SELECT on
  `product_pack_store.product_pack_items` (`ORDER BY pack_id LIMIT $3`, limit 20 from
  `kPackAdvisoryQueryLimit`); the result is a local `std::vector<std::string>` returned by value in
  `std::expected`. `DefinitionPackAdvisoryFn` is a plain `std::function` over a raw non-owning
  `ProductPackStore*` captured by value (borrowed from `ServerImpl`, same lifetime pattern as the
  referrer closure); `pack_advisory_note` builds one `std::string`.
- **Release point:** scope exit (lease, `PgResult`, vector, string are RAII).
- **Transfer:** the note string is returned by value and appended to the delete's audit detail.
- **Failure cleanup:** the lookup is read BEFORE the delete (beside the pre-image read) so a failure
  cannot lose the outcome row; `pack_advisory_note` wraps the call in `try/catch(...)` and returns
  an empty note on an error, an unwired function or no pack, so it NEVER blocks or changes a
  delete's outcome. A failing read is logged once a minute and not counted in a metric.

### MCP pre-mint store reads (`stale_version_refusal`, `delete_referrer_refusal`)
- **Site:** `mcp_instruction_authoring.cpp`, called from the pre-ticket block in `mcp_server.cpp`.
- **Owner type:** each is one `InstructionStore::get_definition` (a single read through the store's
  own bounded lease) producing a local `std::optional<InstructionDefinition>`, plus a `const
  InstructionStore*` borrowed from `ServerImpl` for the call. `stale_version_refusal` (update, delete
  and an id-bearing YAML save) compares the stored `updated_at` to the token; `delete_referrer_refusal`
  gained an optional `existence_store` so an absent row falls through instead of being checked for
  referrers. No resource is owned beyond that value.
- **Release point:** scope exit; the lease is released inside `get_definition` before the next read.
- **Failure cleanup:** a store that is not open or whose read fails returns `store_unavailable()`
  (fail closed); no ticket is minted or consumed. The read is a best-effort early check: the handler
  still enforces the version atomically.

### `delete_definition` transaction with a version condition
- **Site:** `InstructionStore::delete_definition(id, optional expected_updated_at)`
  (`instruction_store.cpp`), one `pool_.with_txn_for(kWriteTimeout, ...)`.
- **Owner type:** the pooled connection lease and transaction owned by `with_txn_for`. The
  transaction-scope advisory lock `kSeedCoordLockSql` is the FIRST statement (the same lock
  `insert_definition_row`, import and seed take); the DELETE appends `AND updated_at=$2::bigint` only when
  an expected version is passed and, on zero rows, a follow-up existence SELECT in the same
  transaction tells not_found from a stale version (a zero-row delete commits an empty no-op
  transaction); the tombstone upsert follows a landed delete. The lambda captures `failure`, `deleted` and `stale` by
  reference, declared before the call.
- **Release point:** COMMIT when the callback returns true, ROLLBACK when it returns false or throws;
  the advisory lock goes with the transaction. Nothing escapes the callback but values.
- **Failure cleanup:** a failed lock, DELETE or probe sets `failure` and rolls the delete and the
  tombstone back together.

### `ticket_subject` containers
- **Site:** `ticket_subject` and `summarise_ticket_argument` in `mcp_instruction_authoring.cpp`.
- **Owner type:** function-local `std::unordered_set<std::string>` (`reserved`, `taken`), a
  `std::vector<std::pair<std::string, std::string>>` of key and JSON text (`parts`), one `dumped`
  `std::string` (only for a non-string `document`), the hex digest `std::optional<std::string>`, and
  the returned `std::string`. The 4 MiB document tree is read through a `const json*` into the
  caller's arguments and is not copied; a YAML string is read through `get_ref`.
- **Release point:** scope exit.
- **Transfer:** only the output string is returned (by value).
- **Failure cleanup:** RAII only; a `std::bad_alloc` unwinds every container. A SHA-256 provider
  failure returns `std::nullopt` before anything is persisted. Cost is linear in the number of
  arguments (hash lookups, not scans), pinned by a scaling-ratio test.

### `stamp_import_creator` (legacy import)
- **Site:** `instruction_routes.cpp`, called by `POST /api/instructions/import` before
  `store->import_definition_json`.
- **Owner type:** a local `nlohmann::json` parse of the request body and one `std::string` produced
  by `dump(-1, ' ', false, error_handler_t::replace)`.
- **Release point:** scope exit; the dumped string is a temporary passed to the store by value.
- **Transfer:** never; a body that is not depth-safe JSON, not parseable or not an object is
  returned unchanged.
- **Failure cleanup:** parsing uses `allow_exceptions=false` and `json_exceeds_depth` runs first;
  only a `std::bad_alloc` can throw, bounded by the existing 16 MiB request cap.

### Ownership changes with no resource
- `Ports::audit` (`mcp_instruction_authoring.hpp`) is a `std::function` that is now left UNSET when
  the server has no audit sink wired, instead of a stub; it is a handler-scoped borrow of `audit_fn`
  and `req` as before. Unset means every write refuses (`kAuditRefused`), never "audit off". No new
  owner.
- `approval_request_limits.hpp` holds `constexpr` constants only (a header with no database
  dependency, so `approvals_page_render.hpp` need not pull in `approval_manager.hpp`); the Approvals
  page clip works on a `std::string` by value.
- The REST `Auditor` and the MCP audit helpers are stack-scoped values; `detail::try_persist_audit`
  turns a throwing sink into a failed row. Route-dependency callbacks are `std::function` members of
  `RouteDeps` stored by value; the server-side lambdas capture `this`, with the same lifetime
  pattern as the legacy cluster (the HTTP server is joined before the stores are reset).
- `instruction_authoring_routes.cpp` keeps function-local `static std::once_flag`s, one per
  warn-once site (`warn_unwired(std::once_flag&, ...)`), replacing the single shared flag.

### Test-side resources (not production)
- **Ed25519 keys:** `test_instruction_authoring_routes.cpp` and `test_mcp_instruction_authoring.cpp`
  create `EVP_PKEY`, `EVP_PKEY_CTX` and `EVP_MD_CTX` objects, each held in a `std::unique_ptr` with
  its deleter (`EVP_PKEY_free`, `EVP_PKEY_CTX_free`, `EVP_MD_CTX_free`). The one raw `EVP_PKEY*`
  (`raw`, out-parameter of `EVP_PKEY_keygen`) is adopted into the owning pointer immediately.
- **Temporary databases:** the PG-backed tests use `YUZU_REQUIRE_PG_DB_TPL` with a
  `PgTestTemplate` (`authoring_tpl`, sharing the `instructionstore` key); the databases are dropped
  with `DROP DATABASE ... WITH (FORCE)` by the helper in `tests/unit/test_helpers.hpp`.
- **F3 concurrent test leases and threads:** the create-versus-uncommitted-delete test holds one pool
  lease (`delete_txn`) with a hand-opened transaction (`BEGIN`, the advisory lock, `DELETE`, the
  tombstone upsert) and runs the real `create_definition` on a `yuzu::test::Workers` thread
  (`tests/unit/server/test_principal_lock_gate.hpp`). `Workers` runs a `before_join` hook that ROLLBACKs
  the open transaction and then JOINS in its destructor, so a failing assertion cannot leave a joinable
  `std::thread` or wait out a full lock timeout. `workers` is declared after `delete_txn`, so it is
  destroyed first. The worker records its result in a captured local; no Catch macro runs off the
  main thread. The two-writer race test uses the same `Workers` seam with an empty hook.
- **Perf test:** the `ticket_subject` scaling test reads `std::chrono::steady_clock` only; no thread
  or file.
- **Source-tree read:** none added by this change.
