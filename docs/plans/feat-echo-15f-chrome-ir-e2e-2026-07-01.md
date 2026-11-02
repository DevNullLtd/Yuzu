# 15.F — Chrome-IR end-to-end test + Phase-15 roadmap correction

**Branch:** `feat/tar-15f-chrome-ir-e2e` (worktree, off `dev` @ `a86d7f31`) · **Date:** 2026-07-01

## Why this shape

Work began as "build roadmap 15.B (Result-Set Store + REST API)". Investigation of the
code showed **15.B and 15.C/15.D/15.E were already shipped on 2026-05-31** (`68427bba`,
`e7b47ca3`, `e6361a3a`), with much of **15.G** also done — but `docs/roadmap.md` still
marked them "Open". So the work was re-scoped (with the operator) to the one genuinely-open
Phase-15 item, **15.F**, plus correcting the stale status docs.

## What shipped in this branch

1. **`tests/unit/server/test_chrome_ir_chain.cpp`** (+ `tests/meson.build` entry) — an
   in-process Catch2 e2e for the scope-walking chain, driving the real `/api/v1/result-sets`
   handlers via `TestRouteSink` with a real `ResultSetStore` + a recording fake dispatch
   (same harness pattern as `test_rest_result_sets_async.cpp`). It drives
   ground(direct create) → `from-echo-query` narrow → `from-instruction-result` narrow →
   `materialize` (maintenance-thread stand-in) → pin, and asserts:
   - lineage is complete (`GET /{id}/lineage` reconstructs root→leaf);
   - the audit trail is complete (3× `result_set.create` + `result_set.pin`/`unpin`);
   - pinning prevents mid-incident GC (`gc_sweep()` removes nothing, pinned delete → 409);
   - clean teardown (unpin → delete leaf→root → 404).
   - **Result: 55 assertions pass.**
2. **`docs/roadmap.md`** — Phase-15 statuses corrected: 15.A–15.E marked Shipped (with
   commit refs + as-shipped notes, incl. the SQLite store / routes-in-`rest_api_v1.cpp`
   reality), 15.G marked "Largely shipped" with the exact remainders, 15.F marked
   In-progress with the as-built in-process approach (no `tests/integration/` or
   `scripts/uat/synthetic-fleet.sh` — those design-doc paths were aspirational). Dated
   status-correction note added under the phase header.
3. **`docs/capability-map.md`** — §30 items 30.1/30.2/30.3 → shipped, 30.4 → largely
   shipped; §30 rollup `4|3|1|0` and TOTAL `228|172|6|50` propagated.

## Verification

- `./scripts/setup.sh --tests && meson compile -C build-macos yuzu_server_tests` → exit 0.
- `build-macos/tests/yuzu_server_tests "[chrome_ir]"` → **All tests passed (55 assertions)**.
- Purely additive (one new test + docs); no production code touched.

## Deliberate scoping / honest limits

- The two async producers land `pending` and are completed by calling
  `ResultSetStore::materialize()` directly (no live agent in-process). The positive
  "GC removes an expired unpinned set" case is covered at the store level in
  `test_result_set_store.cpp` (`[result_set][gc]`) — a ttl can't be back-dated via REST.
- The ground set uses the direct create endpoint as a deterministic stand-in for the
  inventory-query producer (which needs an `InventoryStore` + eval engine and has its own
  coverage). Test value is the chain contract, not the individual producers.

## Follow-ups surfaced (not done here)

- **Migrate `ResultSetStore` SQLite → Postgres** (ADR-0006 / `docs/postgres-migration-ladder.md`).
- **15.G remainders:** `yuzu_result_sets_total`, `yuzu_result_set_resolve_seconds` histogram,
  final audit-polish pass; then narrow/close 15.G.
- **PR-E2:** Policy `fromResultSet:` (result-set TTL vs. continuous policy eval).
- Before PR: run `/governance` + `/test`, target `dev`.
