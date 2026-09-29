# Disaster Recovery

## What to Back Up

| File | Location | Critical |
|------|----------|----------|
| `yuzu-server.cfg` | `/etc/yuzu/` | Yes — contains user credentials |
| `enrollment-tokens.cfg` | `/etc/yuzu/` | Yes — active enrollment tokens |
| `pending-agents.cfg` | `/etc/yuzu/` | Yes — pending approval queue |
| `*.db` (all SQLite databases) | `/var/lib/yuzu/` | Yes — all operational data |
| TLS certificates | `/etc/yuzu/certs/` | Yes — mTLS identity |

> Shipped InstructionDefinitions live inside the `yuzu-server` binary
> (embedded at build time by `server/core/scripts/embed_content.py`)
> and are reseeded on every boot into the PostgreSQL `instruction_store`
> schema (ADR-0058) — not `instructions.db`, which this store no longer
> reads or writes. Operator edits to definitions persist in Postgres;
> back them up via the `pg_dump`/`pg_restore` procedure covered
> elsewhere in this document for the server's Postgres substrate.

## Backup Strategy

### Automated Daily Backup

```bash
# Add to crontab
0 2 * * * /usr/local/bin/yuzu-backup.sh --data-dir /var/lib/yuzu --config-dir /etc/yuzu --output /backup/yuzu
```

### Pre-Upgrade Backup

Always back up before upgrading:
```bash
yuzu-backup.sh --output /backup/yuzu-pre-upgrade-$(date +%Y%m%d)
```

### Using the Backup Script

```bash
# Default paths
./scripts/yuzu-backup.sh

# Custom paths
./scripts/yuzu-backup.sh --data-dir /var/lib/yuzu --config-dir /etc/yuzu --output /backup/yuzu
```

The script:
1. Flushes SQLite WAL files (`PRAGMA wal_checkpoint(TRUNCATE)`)
2. Copies all `.db` and `.cfg` files
3. Generates a SHA256 manifest for integrity verification

## Restore Procedure

```bash
# 1. Stop the server
systemctl stop yuzu-server

# 2. Restore from backup
./scripts/yuzu-restore.sh /backup/yuzu-backup-20260321-020000

# 3. Verify manifest
# (restore script does this automatically)

# 4. Start the server
systemctl start yuzu-server

# 5. Verify
curl http://localhost:8080/livez
```

> **Restoring a backup taken before the OIDC-secret redaction fix?** Rotate the OIDC client
> secret. Earlier versions recorded it in the clear in the server log, `GET /api/config` and the
> `config.update` audit detail. The current server no longer discloses it - including for audit
> rows written before the fix, which are redacted when read - but **a restored backup still
> contains the plaintext bytes on disk**, and anything that read it while it was exposed still
> holds a working credential. See
> [Security hardening -> OIDC](../user-manual/security-hardening.md#oidc-hardening).

## Recovery Time

| Scenario | Data at Risk | Recovery Time |
|----------|-------------|---------------|
| Config file loss | Credentials, tokens | Minutes (restore from backup) |
| Database corruption | Responses, audit, policies | Minutes (restore + migration) |
| Full server loss | Everything | 15-30 minutes (new server + restore) |
| Agent data loss | Agent state, TAR history | Agent re-enrolls, TAR rebuilds |

## Failover Architecture

For high availability:

1. **Active-passive**: Two servers with shared storage (NFS/CIFS). Standby takes over on failure.
2. **Gateway multi-site**: Deploy gateways in each site. If one server goes down, re-point gateways.
3. **Database replication**: Use Litestream or sqlite3 backup API for continuous replication to object storage.

## Data Loss Mitigation

- **WAL mode**: SQLite WAL provides crash recovery — incomplete transactions are rolled back on restart
- **Retention policies**: Response and audit data have configurable retention (90/365 days default)
- **Agent resilience**: Agents buffer commands locally and retry on reconnection
