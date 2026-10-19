- **`/crypto` is now a per-operator widget dashboard (ADR-0070 D13).** Each operator adds,
  removes and reorders widgets; the layout is saved server-side per user in Postgres
  (`crypto_dashboard_layout_store`, ADR-0071) and is also readable and writable through
  `GET`/`PUT /api/v1/crypto/dashboard/layout` and the MCP tools `get_crypto_dashboard_layout` /
  `set_crypto_dashboard_layout`; `GET /api/v1/crypto/widgets` (`list_crypto_widgets`) lists the
  catalogue. Widgets cover the existing crypto-library figures (now also a devices-by-family
  bar chart) and new **Yuzu-issued certificate** counts from Yuzu's own internal CA only (never
  fleet certificates): active, expiring within 3/7/14/21/30/60 days, expired and revoked in the
  last 7/30/60/90 days, issued in the last 7 days, and issued/revoked per ISO week over 26 weeks
  (`GET /api/v1/crypto/ca/stats`, `get_crypto_ca_stats`). Every card states its criterion,
  every count carries `as_of` and the closed window set `crypto_widget_windows_v1`, and nothing
  is graded. Every number, bar and chart point drills down: the certificates behind a count
  (`GET /api/v1/crypto/ca/certificates`, `list_crypto_ca_certificates`, paged) or a family's
  devices. The Yuzu-issued widgets need `Security:Read`; a widget you cannot read shows as "not
  available to this account". New audit verbs `crypto.ca.stats.view`,
  `crypto.ca.certificates.view` and `crypto.dashboard.layout.update`.
