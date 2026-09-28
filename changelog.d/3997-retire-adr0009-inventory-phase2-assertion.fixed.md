- **`/test` Phase 2 upgrade-test gate no longer false-fails on every commit.** Phase 2 kept
  asserting a legacy `inventory.db` row survived a SQLite→PostgreSQL backfill after `1cf797ac4`
  (#3623) removed `InventoryStore::migrate_from_sqlite()` and the backfill path it depended on
  (ADR-0009's fresh-start-by-default amendment). The gate had been red on every `origin/dev`
  commit since, unrelated to any diff under test; the dead fixture-seed and its three assertions
  are removed (#3997).
