- **Test-history compatibility:** schema v4 preserves every gate observation,
  including an aborted attempt followed by a pass. This migration cannot be
  downgraded in place: older checkout recorders reject v4, including `/test`
  preflight. Keep a consistent pre-upgrade SQLite backup or select a separate
  `YUZU_TEST_DB` for older branches; retain the v4 history when restoring a backup.
  Manual coverage capture now generates a fresh run ID by default. See
  `docs/ci-architecture.md` for the backup and rollback procedure. (#7733)
