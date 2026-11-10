- **Linux CI runs its non-pg and pg test phases concurrently.** The Linux job's
  three sequential test steps (`Test (non-pg suites)`, then `Test (pg shards,
  full)` or `Test (pg smoke)`) are now one step, `Test (non-pg + pg halves,
  concurrent)`, whose two halves run at the same time and which fails if either
  fails; selections, widths and the `with-test-slot.sh` gate are unchanged. Each
  `meson test` invocation uses its own `--logbase`, which `flake-retry.py`,
  `test-durations-summary.py` and the telemetry finalizer follow, so the
  cheap-suite invocations' suite timings and recovered flakes now reach the
  runner's test history too. Expected saving is about 7 minutes on the
  gcc-15/debug leg, pending measurement. Also adds a measurement-only
  `YUZU_TEST_PG_CLONE_STRATEGY` knob (`wal_log` / `file_copy`) for the `[pg]`
  template clone; unset changes nothing.
