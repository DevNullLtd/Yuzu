- **Linux CI runs its non-pg and pg test phases at the same time.** The Linux
  job's separate test steps are now one step, `Test (non-pg + pg halves,
  concurrent)`, which runs both halves together and fails if either fails;
  test selection and widths are unchanged. Linux test logs in the `meson-logs`
  artifact are renamed per invocation (`testlog-nonpg-cheap`,
  `testlog-nonpg-server`, `testlog-pg`), plus one full log per half
  (`ci-half-nonpg.log` / `ci-half-pg.log`). Setting the
  repository variable `YUZU_CI_SEQUENTIAL_HALVES` to exactly `1` runs the
  halves one after the other again. Also adds a measurement-only `YUZU_TEST_PG_CLONE_STRATEGY`
  test variable (`wal_log` / `file_copy`, PostgreSQL 15+) for the `[pg]`
  template clone; unset changes nothing.
