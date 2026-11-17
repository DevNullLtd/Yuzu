- **Brotli 1.2.1 and SQLite 3.54.1 for every vcpkg build.** `vcpkg.json` now pins both ports
  with `overrides`, above the unchanged vcpkg baseline: Brotli 1.2.1 fixes CVE-2026-111497, a
  decoder buffer overflow reachable through cpp-httplib's response decompression in the
  agent's `http_client` and `content_dist` plugins, and SQLite 3.54.1 carries the CVE fixes
  released in 3.54.0. No other port changes. libpq stays at 18.4 because vcpkg has no later
  libpq version yet (the fixed release is 18.6); the PostgreSQL fixes since 18.4 are almost all
  server-side and do not affect the client library Yuzu links. Rebuild needed: the vcpkg tree on every build host and CI runner
  re-resolves on the manifest change.
