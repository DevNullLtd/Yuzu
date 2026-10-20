- **The CA store gains four indexes at upgrade (`ca_store` migration v5).** They back the
  `/crypto` Yuzu-issued certificate counts and their keyset-paged certificate list (ADR-0070 D13).
  The build runs inside the migration at the first start of the new version and blocks
  `ca_issued` writes (issuance, revocation, new enrolments) while it runs, waiting at most 30 s
  for its lock; if the wait expires the migration rolls back and the server refuses to start until
  it can retry. Plan the upgrade for a quiet period on a large CA store. See
  `docs/user-manual/upgrading.md`.
