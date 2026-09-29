# Unit-test conventions — shared helpers

Routed doc for the **unit-test conventions** concern in `.claude/routed-concerns.md`.
Loaded by `quality-engineer` on any change under `tests/unit/`.

Companion: `docs/testing/integration-tests.md` covers the shell/E2E stack-bring-up layer.
The authoritative statement of each helper's contract is its own doc comment at the source;
this doc is the index and carries the rules that live nowhere else.

## Temp files, DBs and scratch dirs

Use `yuzu::test::unique_temp_path(prefix)` / `yuzu::test::TempDbFile` / `yuzu::test::TempDir` from `tests/unit/test_helpers.hpp` for any test temp file, SQLite DB, or scratch dir. **Never** salt uniqueness with `std::hash<std::thread::id>` or `std::chrono::steady_clock` — silent collisions under Defender-induced I/O serialisation (flake #473; #482). Pass a **`yuzu_test_` (underscore) prefix** so names land inside the Wee Tam Defender path-exclusion wildcard `yuzu_*` (`scripts/windows-runner-defender-exclusions.ps1`) — the helpers' default `yuzu-test-` (hyphen) prefix does NOT match it; all three helpers take an explicit prefix for this.

## Standing invariant — shared-identity CI runners

**Standing invariant:** both self-hosted CI pools run 4 runner agents as ONE shared OS identity on ONE box — Windows "Wee Tam" (LOCAL SYSTEM, `deploy/windows/README.md`), Linux "Big Tam" (`runner` user sharing `$HOME`, `docs/ci-architecture.md`). A fixed registry key/port/named-object/path is a cross-JOB shared resource — two concurrent CI jobs on one box collide (#1871's `RegistryGuard` family; same bug on Linux gateway eunit `health_port`). Salt every such identifier per-test/per-process like `unique_temp_path()` — see `test_guard_registry.cpp`'s `TempRegKey`/`TempEnforceKey`.

## Route-handler tests — `TestRouteSink`

For route-handler tests, `TestRouteSink` (`tests/unit/server/test_route_sink.hpp`, used by 41 files) mirrors `httplib::Server`'s parsing of the path, the query string, and an `application/x-www-form-urlencoded` body into `req.params` (query first, so query wins) — and **nothing else**: no path percent-decoding, no multipart/chunked, no duplicate headers, and none of the pre/post-routing pipeline. So a gate that moves into pre-routing leaves every sink test green. Two traps: `Post(path, body)` defaults to `application/json` and does NOT populate `req.params` (omitting the content-type silently tests a handler's fallback instead of its production branch — the #1786 false-green, re-armable), and fixtures must declare the sink **after** the route owner it registers (its handlers capture the owner's `this`). Contract pinned by `tests/unit/server/test_route_sink_harness.cpp`.

## `ExecutionTracker` in `AgentServiceImpl` — `TrackerScope`

For server tests that need a live `ExecutionTracker` in `AgentServiceImpl`, use the `TrackerScope` RAII helper in `tests/unit/server/test_agent_service_impl.cpp` — takes a `pg::PgPool&` (ADR-0065; PG-backed, not `:memory:` SQLite), `set_execution_tracker`, nulls the borrowed pointer before the tracker destructs (the production shutdown contract, `agent_service_impl.hpp:113`). Promote to `test_helpers.hpp` once a second file needs it.

## Exception-safe test cleanup — `ScopeExit`

`yuzu::test::ScopeExit` (`tests/unit/test_helpers.hpp`) is a generic RAII cleanup
that runs on ANY scope exit, including exception unwind from a failing
`REQUIRE`/`CHECK` — declare it after whatever it releases/reads so it destructs
FIRST (reverse declaration order); its callback must not throw, since it can run
mid-unwind, where a second throw would terminate. Used by `test_thread_pool.cpp`
(releasing parked pool workers before `~ThreadPool` joins them) and
`test_guardian_outbox_send_executor.cpp` (#4223 — releasing a detached worker
parked on a test-owned gate pointer before the pointer's stack storage can be
destroyed). Promoted from `test_thread_pool.cpp` once a second file needed it.

## Agent-side journal storage tests — `FakeJournalStore`

For any Guardian journal concurrency checkpoint that needs a storage backend without real
SQLite I/O, use `yuzu::test::FakeJournalStore` (`tests/unit/fake_journal_store.hpp`) — an
in-memory `IJournalStore` implementation, self-serialised under one mutex, mirroring
`KvStore`'s locking/ownership contract exactly (see the header's own doc comment for the
full contract and its one documented divergence: case-sensitive prefix matching vs SQLite's
ASCII-case-insensitive `LIKE`). Contract pinned by `tests/unit/test_fake_journal_store.cpp`.
Unlike `PageRig`/`JournalRig` (same test file / `test_guardian_outbox_drain_worker.cpp`),
which construct `GuardianLifecycleJournal` against a real on-disk `KvStore` and remain the
right choice for tests that need genuine SQLite semantics (quarantine `Conflict` ordering,
extended result codes, `list_entries` byte-exactness), `FakeJournalStore` is for tests where
the concurrency property under test — not the storage engine — is the point (#4153).

## Live PostgreSQL — which macro to use

For server tests needing live **PostgreSQL**, use `PostgresTestDb` + `YUZU_REQUIRE_PG_DB(var)` from `test_helpers.hpp` (behind `YUZU_TEST_ENABLE_PG`, server suite only). Creates an ephemeral `yuzu_test_<epoch>_<salt>_<n>` DB on `YUZU_TEST_POSTGRES_DSN`, drops it `WITH (FORCE)`; the name-embedded epoch drives a suite-start sweep of databases leaked by killed runs. Skip-vs-fail: env **unset** → skip (local dev); **set but broken** → FAIL (`scripts/ci/ensure-postgres.sh` guarantees a reachable instance on every CI server-test leg). **Store-behaviour tests use the pre-migrated template variant** `YUZU_REQUIRE_PG_DB_TPL(var, tpl)` + a file-local `PgTestTemplate` (clones an already-migrated DB — per-test migration DDL drove the 2026-07-12 Windows server-suite timeout; recipe: `docs/postgres-store-playbook.md` step 7); plain `YUZU_REQUIRE_PG_DB` is only for fresh-DB / pg-substrate behaviour tests. **Migration-in-substance tests** (a real fresh migrate, `!is_open` on failure, backfill/upgrade, drift-detection) use `YUZU_REQUIRE_PG_MIGRATION_DB(var)` instead (#2354, #3443) — same contract, SKIPs on Windows by default (fail-closed; `YUZU_TEST_PG_MIGRATION_DDL=1` overrides), so a new store's migration test belongs on this macro, never plain `YUZU_REQUIRE_PG_DB`. Local: run `postgres:18` on `:5433` with `-c max_connections=400` (what `scripts/ci/ensure-postgres.sh` uses — at the default 100, a full parallel `--suite server` run fails with "too many clients"), then `export YUZU_TEST_POSTGRES_DSN=postgresql://yuzu:yuzu@localhost:5433/yuzu`.

## Prometheus alert rules — parse vs behaviour

**Prometheus alert rules are PARSE-checked by `promtool` for all rules, BEHAVIOUR-checked only for the alerts that have cases** in `tests/prometheus/yuzu-alerts.test.yml` (today: the `YuzuAuditRetention*` liveness pair). Nothing enforces that a rule change ships a case, so a green check on an edit to any other rule proves parseability only — and `prometheus-rules` is **not a required status check**, so a red one merges until branch protection says otherwise. The run does refuse to report success vacuously: no rules, no cases, no assertions, a stale `rule_files:` glob, or a behaviour suite that stays green against a deliberately broken copy of the rules file all fail it — `check rules` and `test rules` are handed DIFFERENT paths and otherwise disagree silently while printing a rule count (#2553). The opt-in `YUZU_TEST_ENABLE_PROMTOOL_DOCKER` (**presence-checked, so `=0` also enables it** — matching `YUZU_TEST_ENABLE_PG`) exists because `scripts/ci/flake-retry.py` runs `meson test` with **no `--suite` filter** on three REQUIRED legs, so any docker-dependent `docs`-suite test would put a container registry on all three — that shape was shipped once and reverted (#2553). **A new test here that pulls an image must be opt-in gated the same way.** Everything else — the skip-vs-fail contract, the check name, alert-authoring conventions — is in `tests/prometheus/run_promtool_tests.py`'s docstring and `docs/observability-conventions.md`.
