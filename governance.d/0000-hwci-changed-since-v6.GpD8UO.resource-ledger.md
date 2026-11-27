# Resource Ledger: migration v6, the keyset index swap and the generic read-index check

Range reviewed: `a9f55f6f46..b8fb783b9a` plus the fix round that follows it (the lock-first, schema-qualified v6 text, the
reworded WARN and the tests). Companion to the `0000-hwci-changed-since-v6.*.jsonl` fragment. The earlier governance
rounds of the delta work (`559baadde1..72b12a3e68`) left no structured ledger; the residual rows of
`docs/security-reviews/hardware-ci-changed-since-2026-11.md` are their durable trace, and the C++ added there
(`device_ci_watermark`, the `changed_since` clause of `device_ci_keyset_statement`, `kDbClockSecsExpr`, the v5 migration
text) uses only `std::string`, `pg::PgResult` and the pool lease, as below.

## Production code (`server/core/src/device_inventory_store.cpp`)

| Resource | Owner type | Acquired | Released | Failure cleanup |
|---|---|---|---|---|
| Pooled PostgreSQL connection used by the runtime index check (two sequential catalog queries) | the constructor's single pool `lease` (RAII, non-owning `PGconn*` passed down) | already held by `DeviceInventoryStore::DeviceInventoryStore` | constructor exit | no early return between acquire and release; the check never takes a second lease and cannot change `open_` |
| `PGresult` of each catalog query | `pg::PgResult` (RAII) | after each `exec_params` | end of `warn_if_index_unusable` | `valid`, `ready`, `partial` and `def` are copied into `std::string` immediately, so no `PQgetvalue` pointer outlives the result; libpq answers "" for NULL, never a null pointer |
| `key` (`std::string_view` over `def`) | borrowed view, declared in the same block as the owning `std::string def` | after `def.find(" USING btree ")` | end of the else-block | every use (`same_key`, the problem classification) is inside that block; the `substr` calls are bounds-safe (the second runs only after the first comparison proves `key.size() >= chk.key.size()`) |
| `IndexCheck` (name, key view, `const std::string& create_sql`, consequence) | stack temporary, call-scoped | braced init at the call of `warn_if_index_unusable` | end of the full expression | `create_sql` binds to namespace-scope `const std::string` objects (not temporaries); documented as call-scoped, never stored |
| `kKeysetIndexKey`, `kChangedAtIndexKey` (`constexpr std::string_view`), `kKeysetIndexName`, `kChangedAtIndexName` (`constexpr const char*`) | constant-initialised, static storage | program start | program end | none needed |
| `kMigrationV6Sql`, `kKeysetIndexCreateSql`, `kChangedAtIndexCreateSql` (`const std::string`, dynamic initialisation from the constants above and `index_ddl`) | namespace-scope statics in one TU, defined after their inputs | static init | program end | same-TU definition order; the only readers are `migrations()` (a function-local static that copies the SQL on first call) and the open path, and no static-initialisation-time caller exists in another TU |
| `drop_first` (`std::string`) and the formatted WARN | locals | per WARN | end of the function | spdlog format string is a literal; the consequence and DDL are arguments, never spliced into the format string |
| v6 migration body | text only; the runner applies it as ONE `PQexec` inside its own BEGIN, advisory lock and `SET LOCAL search_path` | by the runner | commit or rollback by the runner | a failed statement rolls the whole transaction back (no stamp, no hash row, v4's index untouched); a database object, not a C++ resource |

No new fd, HANDLE, SOCKET, `FILE*`, SQLite object, OpenSSL object, BCrypt handle, allocated C string, mapped library,
temp path, subprocess, thread, detached work, raw cast or manual cleanup.

## Test code (`tests/unit/server/test_device_inventory_store.cpp`)

| Resource | Owner type | Failure cleanup |
|---|---|---|
| Pools and leases in the new v6, warn-matrix and plan-shape cases | `PgPool` and lease RAII; every lease scope closes before `open_and_check` / `open_and_capture` open a store | no pool starvation; a `SKIP` thrown inside a lease scope releases the lease and result |
| `LogCapture` | existing RAII helper, `stop()` is idempotent and called before `text()` | none needed |
| Foreign table `public.yuzu_test_v6_foreign` in the public-schema section | created and dropped inside the section; the database itself is a throwaway template clone | a failing `CHECK` does not skip the `DROP TABLE` (it is a `CHECK`, not a `REQUIRE`); the database is dropped at the end of the run either way |
| Holder thread, latch and second pool in the v3-to-v6 upgrade case | unchanged from the earlier ledger (`std::jthread` joined on every path, latch counted down on every path) | the only change is the fixture (`DROP COLUMN changed_at`) |
| Throwaway databases | `YUZU_REQUIRE_PG_DB_TPL` / `YUZU_REQUIRE_PG_MIGRATION_DB` | index drops and creates leak nothing into other tests |
