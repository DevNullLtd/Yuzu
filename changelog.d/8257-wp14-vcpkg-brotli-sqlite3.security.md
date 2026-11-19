- **Brotli 1.2.1 and SQLite 3.54.1 for every vcpkg build.** `vcpkg.json` now pins both ports
  with `overrides`, above the unchanged vcpkg baseline. Brotli 1.2.1 fixes CVE-2026-111497, a
  decoder buffer overflow reached through cpp-httplib's response decompression. On the server,
  that covers every outbound HTTP client: the OIDC provider (discovery, JWKS, token endpoint), the
  NVD feed, webhook and offload targets, directory sync, analytics sinks and health-check targets.
  On the agent, it covers the `http_client`, `content_dist` and `printing` plugins. Inbound server
  requests with a compressed body were already refused, and the agent's `virtualization` plugin
  does not decompress. SQLite 3.54.1 carries the fixes released in 3.54.0 for CVE-2026-119371 to
  CVE-2026-119379, CVE-2026-119586 and CVE-2026-119591. No other port changes. libpq stays at
  18.4 because vcpkg has no libpq 18.6 port. The project owner's assessment is that the PostgreSQL
  CVEs fixed in 18.6 are server-side issues, not defects in the libpq client library. The pins,
  the decisions and how to confirm the linked versions are in `docs/build-guide.md` ("Security
  dependency pins"). Source builds re-resolve and rebuild Brotli and SQLite on the next
  `vcpkg install`; no flags or configuration change.
