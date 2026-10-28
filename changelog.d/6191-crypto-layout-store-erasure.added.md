- **Per-operator `/crypto` dashboard layout store (ADR-0071).** A new Postgres schema,
  `crypto_dashboard_layout_store`, keeps each operator's dashboard layout, keyed by username. If
  the schema cannot be created or opened the server still starts without saved layouts, logging
  the failure at error, and `/readyz` stays `200` with the store listed under `degraded`.
  Deprovisioning an operator (SCIM `active:false`/`DELETE` or a dashboard user delete) erases their
  layout rows, and those of linked `oidc:`/`saml:` identities, after the deprovision commits,
  best-effort: a failure never changes the deprovision's answer, is counted on
  `yuzu_server_crypto_layout_erase_failures_total{reason}` and is alerted by
  `YuzuCryptoLayoutEraseFailed`, with a documented periodic check as the remedy. A database restore
  can bring erased rows back; run the same check after any restore. See
  `docs/user-manual/upgrading.md` and `docs/user-manual/crypto.md`.
