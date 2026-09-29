- **macOS CI: the exit-42 teardown race no longer strands PRs.** The Catch2 test
  entry point's `hard_exit()` after `Session::run()` (#3507 AC1) was gated to
  Windows, so macOS still raced C++ static destruction against detached
  Guardian/Spark workers — the suite exited 42 with no failing test case, which
  `flake-retry.py` classifies as unrecoverable and hard-blocks. Observed on three
  of four attempts on one PR and again on an unrelated PR the same afternoon,
  while Linux stayed green. The guard now covers macOS, and its sanitizer
  exclusion detects Clang's `__has_feature(address_sanitizer)` alongside GCC/MSVC's
  `__SANITIZE_ADDRESS__` so an instrumented build still exits normally and keeps
  its leak report.
