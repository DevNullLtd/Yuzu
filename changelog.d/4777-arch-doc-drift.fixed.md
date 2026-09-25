- **Architecture, storage and convention docs reconciled with the code.** `docs/architecture.md`'s
  storage table described server responses, audit, identity/auth and policy state as SQLite
  "pending" a Postgres migration that was completed by 2026-08; every server store except the NVD
  cache is now documented on the shared pool, and `NvdDatabase` as a recorded deferral (born-on-PG
  reshape queued as vuln-scan M1a), not an exemption. **`docs/user-manual/server-admin.md`'s backup
  guidance named a retired `auth.db` — a backup built from it held no authentication state; a
  complete backup is now documented as `pg_dump` plus `--ca-dir` as a pair, with the live `.cfg`
  state files and the `agent-updates/` and `upload-blobs/` blob directories, whose files the
  dump's package and upload records point at** (the upgrade checklist, the `--data-dir` flag and
  "Data Storage and Encryption" sections, the systemd unit comment and README follow suit).
  **`docs/ops-runbooks/auth-db-recovery.md` said a server restart revokes every operator
  session; sessions are durable in PostgreSQL and survive a restart**, so the runbook now
  documents the REST revoke calls and an emergency fleet-wide SQL revocation that also advances
  the session write-generation. Also
  corrected: the MCP `ExecuteGate` approval-row count (~42 → ~50) and Destructive-row count
  (17 → 19) across `docs/mcp-server.md` and the user manual; `docs/authz-model.md`'s securable
  ordinals and count (38 securables × 8 operations); the Meson version text (Linux CI 1.12.0 per
  `requirements-ci.txt`; Windows runner 1.11.1); `docs/capability-map.md`'s reproduction output and
  TOTAL row; the Pattern A/B static-asset split in `docs/cpp-conventions.md`; and
  `docs/test-coverage.md`, where the legacy SSE `EventBus` stays listed as untested (the old
  evidence was for `ExecutionEventBus`) and stale untested rows are removed.
