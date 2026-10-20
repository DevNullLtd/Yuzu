- **`/crypto` is now a per-operator widget dashboard (ADR-0070 D13).** Every operator starts on a
  default grid and can add, remove and reorder widgets; the layout is saved server-side per user in
  the `crypto_dashboard_layout_store` schema (ADR-0071), with a version every save must name: a save from a stale tab is refused (`409`) rather than overwriting a newer one, and a save
  without `expected_version` is a first save only (over a stored layout it is the same `409`,
  naming the stored version). Widgets cover the existing
  crypto-library figures (now also a devices-by-family bar chart) and new counts of certificates
  issued by **Yuzu's own internal CA** (agent and gateway certificates; never the certificates on
  your devices): active, expiring within 3/7/14/21/30/60 days and expired in the last 7/30/60/90
  days (status active only), revoked in the last 7/30/60/90 days in three reason buckets
  (`superseded`, `unpublished`, other), issued in the last 7 days (excluding `unpublished`), and
  issued and revoked per ISO week over 52 weeks, the current partial week flagged. Every count
  carries its criterion, `rule_id`, the window-set version `crypto_widget_windows_v1` and `as_of`
  (the database clock); nothing is graded. The Yuzu-issued counts need `Inventory:Read` and are
  withheld from a confined caller ("not available to this account"); the certificates behind a
  count need `Security:Read` and are served by `GET /api/v1/ca/issued` and MCP `list_issued_certs`
  with new optional filters (`kind`, `days`, `week`, `bucket`, `as_of`, `cursor`). The filtered
  list pages by an opaque **keyset cursor** (`next_cursor`, `null` on the last page; `offset` is
  refused with a filter), so a certificate revoked between pages never makes the walk skip
  another, and a pinned `as_of` is checked against the database clock; unfiltered calls are
  unchanged. New routes `GET /api/v1/crypto/widgets`, `GET`/`PUT /api/v1/crypto/dashboard/layout`
  and `GET /api/v1/crypto/ca/stats`; MCP `list_crypto_widgets`, `get_crypto_dashboard_layout`,
  `set_crypto_dashboard_layout` and `get_crypto_ca_stats`; audit verbs `crypto.ca.stats.view`
  (one row per dashboard draw, not per card), `crypto.ca.certificates.view`,
  `crypto.dashboard.layout.update` and `crypto.dashboard.layout.access_denied`;
  `yuzu_inventory_read_degrade_total` sources `ca_issued` and `crypto_layout`, and the alert
  `YuzuCryptoCaReadDegraded`. See `docs/user-manual/upgrading.md`.
