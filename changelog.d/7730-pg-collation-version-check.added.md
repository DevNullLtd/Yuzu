- **The server now checks the PostgreSQL collation version at start and repeats the check.**
  On the first start after the upgrade, a database that has already drifted logs one error naming the database and both versions and sets `yuzu_pg_collation_version_mismatch` to `1`; the check itself does not stop the server or change the database (what a detected mismatch pauses is described in the device-CI write pause entry).
  The check compares the database's recorded collation version with the version the operating system of the PostgreSQL server reports, which can differ after an operating-system or libc upgrade without a reindex.
  The first check runs in the server's constructor and can delay the listener bind by about 20 seconds in practice (about 40 seconds on a network that drops packets) when the database answers slowly.
  The check repeats every hour once a readable check has concluded, and every minute while a mismatch stands, no check has concluded yet or the latest one could not run.
  The gauge is `1` on a mismatch, `0` on a match, absent until a check learns something, and removed again when the check does not apply (a libc `C` or `POSIX` collation, PostgreSQL before 15, or no recorded version).
  A check that could not run leaves the gauge as it was.
  The counter `yuzu_pg_collation_check_total{result}` counts every check by `ok`, `mismatch`, `not_applicable` or `unreadable`, and the gauge `yuzu_pg_collation_check_last_completed_timestamp_seconds` gives the time of the latest completed check.
  Three alerts ship in `docs/prometheus/yuzu-alerts.yml` and fire only when that file is loaded.
  `YuzuPgCollationVersionMismatch` fires on the gauge, as one alert per job, and clears without a restart once the database is fixed.
  `YuzuPgCollationCheckBlind` fires when the check has failed at least five times in ten minutes (held for 5 minutes), because the gauge is then stale; measured with promtool v3.13.1 at one failure per minute (Prometheus 3 range semantics), exactly five failures go pending and never fire and six fire, and real scrape intervals and check durations shift this, so read it as about five to six failures.
  `YuzuPgCollationCheckStale` fires when no check has completed for two hours, which covers a check stuck mid-query.
  To repair, reindex first and then run `ALTER DATABASE ... REFRESH COLLATION VERSION`, as a change under your own process with a backup first; the next check clears the gauge within about a minute, with no restart.
  A database that records a version while the host reports none stays unreadable, and the refresh statement fails on it (measured on PostgreSQL 18.4 only).
  Drift that begins while the server runs is seen at the next check, up to an hour later, and each replica checks on its own schedule.
  See the PostgreSQL collation version note in `server-admin.md`.
