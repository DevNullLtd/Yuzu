- **The server now checks the PostgreSQL collation version at start and repeats the check.**
  It compares the database's recorded collation version with the version the operating system of the PostgreSQL server reports.
  This can differ after an operating-system or libc upgrade without a reindex.
  The check repeats every hour once a readable check has concluded, and every minute while a mismatch stands, no check has concluded yet or the latest one could not run.
  On a mismatch the server logs one error naming the database and both versions, and exports `yuzu_pg_collation_version_mismatch` (`1` on a mismatch, `0` on a match, absent until a check learns something, and removed again when the check does not apply).
  A check that could not run leaves the gauge as it was.
  The counter `yuzu_pg_collation_check_total{result}` counts every check by `ok`, `mismatch`, `not_applicable` or `unreadable`.
  The alert `YuzuPgCollationVersionMismatch` fires on the gauge when the shipped alert rules file is loaded, and clears without a restart once the database is fixed.
  The alert `YuzuPgCollationCheckBlind` fires when the check has failed at least five times in ten minutes (held for 5 minutes; at the one-minute cadence that takes six failures), because the gauge is then stale.
  The check only reports: it does not stop the server and it refuses, pauses or changes nothing.
  To repair, reindex first and then run `ALTER DATABASE ... REFRESH COLLATION VERSION`; the next check clears the gauge within about a minute, with no restart.
  Drift that begins while the server runs is seen at the next check, up to an hour later, and each replica checks on its own schedule.
  See the PostgreSQL collation version note in `server-admin.md`.
  At shutdown the check is told to stop at the start of the drain, so the wait for a check in flight overlaps the rest of shutdown.
