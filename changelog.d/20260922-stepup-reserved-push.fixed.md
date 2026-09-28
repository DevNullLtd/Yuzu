- **Two security-surface counts corrected in the operator docs.** `authentication.md` said eleven
  endpoints require a fresh MFA step-up proof; the gate is wired on twenty-four, and the omitted
  thirteen are the entire engine-principal lifecycle (create/delete, credential mint/rotate/confirm,
  role grant/revoke, transfer-owner), account unlock, the token rotate/confirm pair, and the two
  JIT admin-elevation endpoints (which share the same gate with the window floored to 300s) — so
  the doc understated which mutations are protected. The same counts in `server-admin.md`,
  `auth-architecture.md`, `mcp.md`, `metrics.md`, `rest-api.md` and `observability-conventions.md`
  are corrected with them. `security-hardening.md`'s quarantine
  threat-model section described three server-internal pushes as exempt from the containment
  dispatch gate; `SystemReservedPush` has four enumerators — the on-demand inventory sync
  (`__sync__.now`) was missing from both the count and the channel-by-channel table, in a section
  whose stated purpose is letting a reviewer account for every channel that reaches a contained
  device.
