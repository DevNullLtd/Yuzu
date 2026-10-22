- **The CA store gains three indexes at upgrade (`ca_store` migration v5).** They back the
  `/crypto` Yuzu-issued certificate counts and their keyset-paged certificate list (ADR-0070 D13),
  so the counts read only active, recently revoked and recently issued certificates rather than
  every certificate the CA ever issued. The build runs inside the migration at the first start of
  the new version and blocks `ca_issued` writes (issuance, revocation, new enrolments) while it
  runs: about 1.3 s per 250,000 rows and 9 s per million in local measurement. It waits at most
  30 s for its lock; if the wait expires the migration rolls back and the server refuses to start
  until it can retry. A second replica started during the build waits up to 10 s for it, then
  refuses to start, and starts on a retry. The HTTP listener, health probes included, opens only
  after the migration, so allow at least two minutes for the first start on a CA store above about
  a million rows, or a probe restart rolls the build back and begins it again. See
  `docs/user-manual/upgrading.md`.
