# Auth Store Recovery Runbook

Operator runbook for recovering a Yuzu server when authentication is broken or
an operator is locked out. Auth data lives in the server's **PostgreSQL
substrate, schema `auth`** (ADR-0006/0007) — there is no `auth.db` file, and
there is nothing to move aside.

**Read this first if you are mid-incident:** the two facts that change how you
recover, relative to the SQLite era, are

1. **The server fails closed without Postgres.** No SQLite fallback, no
   degraded mode. If Postgres is unreachable, `yuzu-server` refuses to start —
   so "auth is broken" is usually "Postgres is broken", and the fix is a
   Postgres fix, not a Yuzu fix.
2. **TOTP secrets are encrypted with a key that is NOT in the database.** A
   Postgres backup on its own cannot restore working MFA. See
   [Backup — the KEK pairing rule](#backup--the-kek-pairing-rule). This is the
   single most common way to turn a recoverable incident into an unrecoverable
   one.

This runbook assumes a single-node Yuzu deployment. For HA, coordinate with the
active leader; see `docs/architecture.md`.

> **Looking for the SQLite procedure?** It is gone, deliberately. Every
> file-based step (`sqlite3 .backup`, moving `auth.db`/`-wal`/`-shm` aside,
> `UPDATE`/`DELETE` against `auth.db`, the Windows Defender exclusion for those
> files) is inapplicable and will not work. Git history has it if you are
> recovering a pre-migration release.

## Detection signal

`yuzu-server` exits non-zero at startup. `journalctl -u yuzu-server` (Linux) or
the Windows event log shows one of these, and they mean different things:

| Log line | Meaning | Go to |
|---|---|---|
| `[PG] Refusing to start: no PostgreSQL DSN` | `--postgres-dsn` / `YUZU_POSTGRES_DSN` is unset | [Config](#no-dsn-configured) |
| `[PG] Refusing to start: cannot reach PostgreSQL substrate: …` | Postgres down, wrong DSN, network/auth failure | [Substrate down](#postgres-substrate-unreachable) |
| `[PG] Refusing to start: auth store (AuthDB) migration/open failed` | Database reachable, `auth` schema could not be created/opened | [Migration failure](#auth-schema-migration-failure) |
| `SecretCodec::init() failed for the auth store bootstrap — …` or `[PG] Refusing to start: SecretCodec::init() failed — …` | The secrets seam could not initialise — usually a missing or unreadable KEK | [KEK problems](#kek-missing-or-unreadable) |
| `SecretCodec::init() failed` … `kek_orphaned: stored secret blobs reference KEK version(s) […] absent from kek_meta` | A stored secret blob (for example one account's TOTP secret) names a key-encryption-key version that is not registered in `secrets.kek_meta` | [Stored secret names an unregistered KEK version](#stored-secret-names-an-unregistered-kek-version) |
| `[auth] Refusing to start: the 'engine:' namespace …` | An `engine:`-prefixed principal collides with the reserved namespace | `docs/ops-runbooks/engine-principal-store-recovery.md` |

If the shipped systemd unit is in use it retries `StartLimitBurst=3` times
within `StartLimitIntervalSec=60`, then enters `failed`:

```
$ systemctl status yuzu-server
● yuzu-server.service - Yuzu Endpoint Management Server
     Active: failed (Result: start-limit-hit) since ...
```

That `failed` state is deliberate — it stops a crash-loop from drowning the
journal. Clear it with `systemctl reset-failed yuzu-server` once fixed.

## Recovery procedures

The `psql "$YUZU_POSTGRES_DSN"` blocks in this runbook assume the DSN is set in your shell. On a Linux package
install it lives only in the env file (`/etc/yuzu/yuzu-server.env`, mode `0600`, readable only by root and the
`yuzu` account), so an interactive shell does not have it. Read the value into a shell variable instead of sourcing
the file, because a DSN containing `&` or spaces breaks as shell:
`YUZU_POSTGRES_DSN=$(sudo sed -n 's/^YUZU_POSTGRES_DSN=//p' /etc/yuzu/yuzu-server.env)`, then run the blocks as
written. The installer writes the line unquoted; if you edited it to add quotes, strip them from the value first.

### No DSN configured

The server has no auth store at all. Set the DSN and restart:

```bash
# Either the flag, in /etc/yuzu/yuzu-server.cfg …
--postgres-dsn postgresql://yuzu:...@db.internal:5432/yuzu
# … or the environment variable (preferred for secrets — keeps the password
# out of `ps` output and the config file).
sudo systemctl edit yuzu-server   # Environment=YUZU_POSTGRES_DSN=postgresql://…
sudo systemctl restart yuzu-server
```

### Postgres substrate unreachable

Yuzu is the symptom, not the cause. Confirm from the Yuzu host, as the service
account, using the same DSN the server uses:

```bash
sudo -u _yuzu psql "$YUZU_POSTGRES_DSN" -c 'SELECT 1'
```

Work the usual causes in order: Postgres service down; `pg_hba.conf` rejecting
the host/user; TLS requirement mismatch; network path (firewall, security
group, DNS); credential rotation that did not reach Yuzu; connection limit
exhausted (`FATAL: sorry, too many clients already`).

Yuzu restarts cleanly once Postgres is reachable — no Yuzu-side repair is
needed, and **no auth data is lost by the outage itself**. Sessions are
durable rows in Postgres (see [Sessions](#sessions-are-durable)), so an
operator whose session did not reach its absolute lifetime or idle timeout
during the outage does not need to sign in again after the restart.

### `auth` schema migration failure

The database is reachable but the `auth` schema could not be created or
opened. Usual causes, in likelihood order:

1. **Insufficient privilege.** The DSN's role needs `CREATE` on the database
   to run migrations. Verify:
   ```bash
   psql "$YUZU_POSTGRES_DSN" -c "\du"        # role attributes
   psql "$YUZU_POSTGRES_DSN" -c "SELECT has_database_privilege(current_user, current_database(), 'CREATE');"
   ```
2. **Schema drift** — a partially-created `auth` schema from an interrupted
   migration, or hand-made objects colliding with migration DDL. Inspect
   before touching anything:
   ```bash
   psql "$YUZU_POSTGRES_DSN" -c "\dt auth.*"
   psql "$YUZU_POSTGRES_DSN" -c "SELECT * FROM public.schema_meta WHERE store = 'auth';"
   ```
   The migration runner refuses to proceed on drift rather than guessing —
   that refusal is the fail-closed behaviour working, not a bug. Resolve by
   restoring from backup (preferred) or, on a deployment with no auth data
   worth keeping, dropping the schema so it rebuilds from the seed config:
   ```bash
   # DESTRUCTIVE — every local account, MFA enrolment and enrollment token in
   # this schema is discarded. Take a dump first even if you think it is empty.
   pg_dump "$YUZU_POSTGRES_DSN" --schema=auth > /var/backups/yuzu/auth-before-drop-$(date +%s).sql
   psql "$YUZU_POSTGRES_DSN" -c 'DROP SCHEMA auth CASCADE;'
   psql "$YUZU_POSTGRES_DSN" -c "DELETE FROM public.schema_meta WHERE store = 'auth';"
   sudo systemctl restart yuzu-server
   ```
   On restart the server re-seeds the admin account from `yuzu-server.cfg`.

### KEK missing or unreadable

`SecretCodec::init()` failed. The key-encryption key (KEK) that protects
envelope-encrypted columns lives on the **filesystem, not in Postgres**:

| | Path |
|---|---|
| Linux / macOS | `/etc/yuzu/certs/secrets-kek-v<N>.key` |
| Windows | `C:\ProgramData\Yuzu\certs\secrets-kek-v<N>.key` |

The directory is the one given by `--ca-dir`, falling back to the platform
default above. Files are `0600`, the directory `0700`, owned by the service
account (a restrictive DACL on Windows).

Check, as the service account:

```bash
sudo -u _yuzu ls -l /etc/yuzu/certs/secrets-kek-v*.key
```

- **Present but unreadable** → ownership/permissions drifted (a restore that
  did not preserve them, or a `chown -R` that overreached). Fix ownership to
  the service account; leave the modes at `0600`/`0700`.
- **Absent on a fresh install** → normal. The server generates
  `secrets-kek-v1` on first boot and logs
  `key_provider: generated KEK 'secrets-kek-v1' (0600, fsynced)`.
- **Absent on an existing install** → the KEK has been lost. Do **not** let the
  server generate a new one and consider it fixed: a new KEK cannot decrypt
  existing blobs. Go to [KEK permanently lost](#kek-permanently-lost).

**Docker Compose.** In the container the directory is `/etc/yuzu/certs` (the
images pass no `--ca-dir`), and it must sit on a named volume: `server-certs`
in the shipped composes from 0.14.1, `certs` in the two reference composes.
Check it with `docker compose exec server ls -l /etc/yuzu/certs`; while the
server is restart-looping, use
`docker compose run --rm --no-deps -T --user 0 --entrypoint ls server -ln /etc/yuzu/certs`
(as root, so a wrong owner shows as such instead of `Permission denied`).
In the affected 0.14.0 stacks there was no volume there, so recreating the
container (an image upgrade, `down` then `up`, `--force-recreate`) deleted the
key files, and `kek_unresolvable` follows on the next start (#5370).
Affected: a 0.14.0 Docker Compose stack whose server has no named volume on `/etc/yuzu/certs` while Postgres has one — `deploy/docker/docker-compose.yml` (the 0.14.0 README quickstart), `docker-compose.uat.yml`, `docker-compose.full-uat.yml`, `docker-compose.viz-uat.yml`, `docker-compose.demo.yml` used with `--keep`, any compose copied from them, and Compose Wizard output from before 0.14.1 in Plaintext mode, with 'Persist generated certs' unticked, or with named volumes off and an external Postgres. Not affected: `docker-compose.reference.yml` (which the README quickstart saves as `docker-compose.yml` since #5419) and `docker-compose.reference-gateway.yml` (their `certs` volume).
A `kek_unresolvable` there does not always mean the files are gone: a compose
that lost its volume line, files owned by the wrong uid, or keys left behind on
a dangling anonymous volume give the same error.
The diagnostic order, the copy-out procedure, and the options if the files are
already gone are in `docs/user-manual/upgrading.md`, "Docker Compose: copy
`/etc/yuzu/certs` out of the server container before you recreate it". Run the
diagnostics before anything destructive.

## Backup — the KEK pairing rule

**A Postgres dump alone is not a complete auth backup.** TOTP secrets in
`auth.users.mfa_totp_secret` are envelope-encrypted (ADR-0010); the wrapped
data key travels with the row, but the KEK that unwraps it is a file. Restore
the dump next to a *different* KEK and every MFA decrypt fails closed — users
are not silently downgraded to password-only, they are locked out of MFA with
`SecretUnavailable` errors and a `yuzu_server_secret_decrypt_failures_total{failure_class="kek_unresolvable"}`
counter climbing.

So: **capture the database dump and the keys directory as a pair, from the same
point in time, and restore them as a pair.**

Capture order: take the `pg_dump` first, then the keys directory; do not rotate the KEK between the two (key files only accumulate, so the archive stays a superset of what the dump references). Stopping the server for the pair guarantees it.

**Linux.** Both halves go to `/var/backups/yuzu`, which the block makes a root-owned `0700` directory, and both are written under `umask 077`, so the dump and the key archive are `0600` and owned by root. They stay root-owned: copy them off with `sudo`, keep them together, and encrypt the pair at rest. Use a directory that holds nothing else, since files already in it keep their own permissions. The block prints `OK:` only if both halves were written.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 -o root -g root /var/backups/yuzu
( set -o pipefail
  sudo -u _yuzu pg_dump "$YUZU_POSTGRES_DSN" --format=custom \
    | sudo sh -c "umask 077; cat > /var/backups/yuzu/yuzu-$STAMP.dump" &&
  sudo sh -c "umask 077; tar -czf /var/backups/yuzu/yuzu-keys-$STAMP.tar.gz -C /etc/yuzu certs" ) &&
  echo "OK: pair written to /var/backups/yuzu"
```

**Docker Compose.** Run from the compose directory. The keys directory is the server container's `/etc/yuzu/certs` volume. Both halves go to an owner-only directory outside any git checkout, because the key archive holds the CA private key and the KEK. The server is stopped for the pair, and `docker cp` reads the volume from the stopped container, so this works on the chiselled image too. The last line starts the server again whether or not the backup succeeded.

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BK="$HOME/yuzu-keys-backup"; mkdir -p "$BK" && chmod 700 "$BK"
docker compose stop server
( umask 077; set -o pipefail
  docker compose exec -T postgres pg_dump -U yuzu --format=custom yuzu < /dev/null \
       > "$BK/yuzu-$STAMP.dump" &&
  docker cp "$(docker compose ps -aq server)":/etc/yuzu/certs - | gzip \
       > "$BK/yuzu-keys-$STAMP.tar.gz" ) && echo "pair written to $BK"
docker compose start server
```

**Windows** (elevated PowerShell). The Windows installer stores the connection string in a file only Administrators and SYSTEM can read; a hand-configured server may use the `YUZU_POSTGRES_DSN` environment variable instead. The block first locks the backup directory to Administrators and SYSTEM (owner Administrators, inheritance removed, full control for those two only), the same grant the installer gives its own directories, so both halves inherit it. Each run writes to a new, timestamped directory (files already in a directory keep any permissions set on them directly, so the block refuses to reuse one). `pg_dump --file` writes the dump itself, because in Windows PowerShell 5.1 (and PowerShell before 7.4) `>` re-encodes a native command's output as text, which corrupts a custom-format dump.

```powershell
& {
  $Stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
  $Bk = "C:\Backups\Yuzu-$Stamp"
  if (Test-Path -LiteralPath $Bk) { throw "$Bk already exists: use a new, empty folder" }
  New-Item -ItemType Directory -Path $Bk | Out-Null
  icacls $Bk /setowner '*S-1-5-32-544' /L /Q | Out-Null
  if ($LASTEXITCODE) { throw 'icacls failed: the backup folder is not locked down, stop here' }
  icacls $Bk /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /L /Q | Out-Null
  if ($LASTEXITCODE) { throw 'icacls failed: the backup folder is not locked down, stop here' }
  $DsnFile = "C:\ProgramData\Yuzu Server\postgres.dsn"
  $Dsn = if (Test-Path $DsnFile) { (Get-Content -LiteralPath $DsnFile -Raw).Trim() } else { $Env:YUZU_POSTGRES_DSN }
  pg_dump --format=custom --file "$Bk\yuzu-$Stamp.dump" $Dsn
  if ($LASTEXITCODE) { throw 'pg_dump failed: no pair was written, stop here' }
  Compress-Archive -Path C:\ProgramData\Yuzu\certs -DestinationPath "$Bk\yuzu-keys-$Stamp.zip" -ErrorAction Stop
  Write-Output "OK: pair written to $Bk"
}
```

The block is one `& { ... }` script block, so a failure stops everything after it however it is pasted. Go on only after `OK: pair written to ...`.

Rules that follow from the pairing:

- **Encrypt the key archive at rest**, separately from the dump if your threat
  model allows — an attacker with both has every stored secret.
- **Never restore a dump onto a host whose keys directory came from a
  different backup generation.** If you cannot prove they are paired, treat the
  MFA enrolments as lost and plan a re-enrolment.
- **Retain old KEK versions.** After a KEK rotation, older versions are still
  needed to read any backup taken before the rotation completed. Do not prune
  key files on a schedule that is shorter than your backup retention.
- **Drill it.** A restore you have never rehearsed is a hypothesis. Restore
  into a scratch database + scratch keys directory, start a throwaway server,
  and verify a real TOTP login succeeds.

Postgres backup mechanics (PITR/WAL archiving, base backups, retention) are
your Postgres platform's concern and out of scope here; what is in scope is
that the keys directory rides along with whatever you choose.

**A restore rolls credentials and sessions back to the dump.** Passwords live
only in the auth store (#5274), so restoring a dump puts every local account's
password back to what it was when the dump was taken — including a password
changed since because it was exposed — and brings back the session rows and
lockout state of that moment, so sessions revoked since the dump (a password
change, **Sign out everywhere**, an admin force-logout) become valid again
until they expire. A failover to a standby that was behind loses the same recent changes. After any restore of the auth schema, or such a failover:

1. **Restart every server replica.** A running replica polls the session
   write-generation about once a second and drops its whole session cache when
   the stored value differs from the one it holds, a lower value included. After
   a point-in-time restore, or a failover to a standby that was behind, the
   counter can be lower than a replica's cached value; in the common case the
   replica notices at its next poll and rebuilds each session from its row, so a
   revocation takes effect within about that interval. The restart stays as
   defence in depth for the case the poll cannot see: a counter that is exactly
   equal to the replica's cached value at its next poll (restored to that value,
   or regressed and climbed back to it between two polls) looks unchanged, and
   that replica keeps serving the sessions it cached. A restart empties the cache. Until every
   replica has restarted, revoking a session (a password change, **Sign out
   everywhere**, an admin force-logout, or the SQL below) is not guaranteed to
   take effect on all replicas in that case; the worst case is bounded by the
   8-hour absolute session lifetime.
2. Revoke every operator session (`DELETE /api/v1/sessions?username=<name>` per
   account, or the SQL in [Sessions are durable](#sessions-are-durable)). Do it
   straight after the restarts: a session row restored from the dump is valid
   again from the moment a replica rebuilds it until this step runs.
3. Re-apply every password change or reset made since the dump — at minimum
   any made because a password was exposed — in the product.
4. Review the audit log for `user.password_change` / `user.password_reset`
   rows after the dump's timestamp to find them, but do not assume the rows
   are there. The audit store lives in the same database (schema
   `audit_store`), so a point-in-time restore, a failover to a standby that
   was behind, and a restore of a whole-database dump (the backups in this
   runbook are whole-database dumps) roll it back with the rest, and every
   audit row written after the dump is gone. Only a restore limited to the
   `auth` schema leaves it intact. After a whole-database restore an absent row
   proves nothing: use your change tickets, or a SIEM copy of the audit stream
   forwarded before the restore (see [Audit Log](../user-manual/audit-log.md)),
   as the record of what changed.
5. A restore of the auth schema also rolls back each account's MFA enrolment,
   its stored TOTP secret and its recovery codes to the dump. A factor cleared
   since the dump (a lost or compromised device) comes back, an approver
   enrolled since the dump is no longer enrolled (their approval is refused
   until they enrol again), and a recovery code consumed since the dump is
   unconsumed again and can be used. Do not rely on the audit log to find
   these changes: after a whole-database restore, point-in-time restore or
   failover the rows are gone (step 4), and a clear done with the direct SQL
   fallback (see [Fallback: direct SQL](#fallback-direct-sql)) writes no audit
   row at all. Compare the current state of `auth.users` for each account with
   your change tickets or the forwarded SIEM copy: `mfa_enrolled_at` (null
   means no enrolled factor), `mfa_disabled_at`, `role`, `is_active` and
   `password_hash` (the table holds no password-change time, so a password
   changed since the dump has reverted unless step 3 re-applied it). Where the
   audit store survived, or in the SIEM copy, also look for `mfa.disabled` (an
   administrator cleared their own factor; each clear writes an `attempted` row first and an outcome row after it,
   failed attempts write the outcome `result=error`, and `result=partial` means the factor was cleared but its
   sessions were not ended), `mfa.reset.breakglass` (an operator cleared one with
   the `--mfa-reset` CLI, with the same two rows), `mfa.enroll.verified` and `mfa.recovery_code.used`
   rows after the dump's timestamp. Then clear again or enrol again as
   intended (see "Enrolling a non-admin approver" below). The same restore can
   bring back other account state changed since the dump, such as a role
   change or a deactivation; check the accounts you changed against the same
   records.

**Restoring onto an empty database instead re-seeds `yuzu-server.cfg`.** If the
`auth` schema is empty when the server starts (a recreated Postgres, a dump
that did not include it), the server provisions the first administrator from
the password hash in `yuzu-server.cfg` — usually the original first-boot
password, not the current one. Keep that file protected, and change the
administrator password in the product right after such a rebuild.

## Post-restore verification

After any restore, before declaring the incident closed:

```bash
# 1. The server started and is serving. (/health and /readyz are on the web
#    port — --web-port, default 8080; https:// if TLS is enabled.)
systemctl status yuzu-server
curl -fsS http://127.0.0.1:8080/health

# 2. The auth schema is at the expected migration version.
psql "$YUZU_POSTGRES_DSN" -c "SELECT store, version FROM public.schema_meta WHERE store IN ('auth','scim_store');"

# 3. The KEK resolved — this must be ZERO, or absent entirely. A non-zero
#    kek_unresolvable count is the signature of a dump restored against the
#    wrong keys directory. /metrics is on the same web port and is always
#    unauthenticated over loopback.
curl -fsS http://127.0.0.1:8080/metrics | grep secret_decrypt_failures_total

# 4. A real MFA login works end-to-end (not just "the page loads").
```

Step 3 is the one people skip. It is the only cheap check that distinguishes
"restored correctly" from "restored, and every MFA user will be locked out the
moment they try to log in".

## Sessions are durable

Operator sessions are rows in the Postgres `session_store.sessions` table
(`SessionStore`, HA WS-1/1a, ADR-2002 §4). `AuthManager`'s in-memory
`sessions_` map is only a per-replica validate cache in front of those rows:
on a cache miss the server re-reads the row and rebuilds the session from it.
So:

- **A server restart is NOT a revocation.** The restart empties the cache, and
  the next request rebuilds each session from its row. The same holds for a
  crash or a failover to another replica.
- A row is removed only by an explicit revoke (sign-out, or the REST calls
  below, which delete by token or by username), by clearing the account's MFA
  factor (`yuzu-server --mfa-reset`, or Disable in Settings; see
  [Emergency MFA disable](#emergency-mfa-disable-break-glass)), or by the reaper once the
  session passes its absolute lifetime (8 hours). An idle-timed-out session
  is refused on every replica, but its row stays until the reaper removes it.

To revoke sessions, use the REST surface:

```bash
# Revoke every session for one operator (admin).
curl -fsS -X DELETE "https://yuzu.internal/api/v1/sessions?username=alice" \
     -H "Authorization: Bearer $TOKEN"

# Revoke your own (self-service).
curl -fsS -X DELETE https://yuzu.internal/api/v1/sessions/me \
     -H "Authorization: Bearer $TOKEN"
```

**Check that the revoke persisted.** Both calls delete the durable rows first,
then clear this replica's cache. If the response body reports
`db_persisted: false` (the audit row shows `result=partial` with
`db_error=true`), only this replica's cache was cleared. The rows survive, and
any replica that misses its cache, including this one after a restart, will
rebuild those sessions from them. Retry the revoke once the database is
healthy.

API tokens are a separate credential class. The admin `?username=` call does
**not** revoke them, and neither does a restart. `/sessions/me` ("Sign out
everywhere") revokes the caller's API tokens as well as their sessions (check
`api_tokens_db_persisted` in its response). Otherwise revoke tokens explicitly
via the token endpoints.

**Emergency fleet-wide revocation.** There is no single admin route that
revokes every operator's sessions. The audited path is the admin
`?username=` call above, once per operator. If that is not practical, delete
the rows directly in Postgres. This is a direct database operation: it
bypasses the server, **writes no audit row** (record it manually), and signs
out every operator including you. Take a backup first (see
[Backup — the KEK pairing rule](#backup--the-kek-pairing-rule)).

```bash
psql -v ON_ERROR_STOP=1 "$YUZU_POSTGRES_DSN" <<'SQL'
BEGIN;
DELETE FROM session_store.sessions;
-- Bump the write-generation exactly as SessionStore does, so every
-- replica that tracks this counter drops its cached sessions on its next
-- generation poll (~1s). After a restore or a failover to a lagging standby
-- a replica still notices a changed counter, but restart every replica as
-- well (see "A restore rolls credentials and sessions back" above).
INSERT INTO session_store.session_meta (key, value) VALUES ('write_generation', '1')
ON CONFLICT (key) DO UPDATE SET value = (session_store.session_meta.value::bigint + 1)::text;
COMMIT;
SQL
```

The generation bump is required. A running replica serves a cached session
without re-reading its row, and clears its cache only when it sees the
write-generation change. A bare `DELETE` therefore leaves every cached
session valid on the replica that holds it, until some later session change
moves the generation, the session expires, or that replica restarts.
After a point-in-time restore or a failover to a standby that was behind, a
replica also clears its cache when the counter is lower than the value it
cached, so the bump reaches it within about the poll interval. The exception is
a counter that is exactly equal to the replica's cached value at its next poll:
that looks unchanged and is not detected, so restart every server replica to be
sure the revocation reaches all of them.

`ON_ERROR_STOP` makes `psql` exit non-zero if any statement fails, in which
case the whole transaction has rolled back and nothing changed. Afterwards,
confirm `SELECT count(*) FROM session_store.sessions;` returns 0 and that
`write_generation` in `session_store.session_meta` went up. This revokes
sessions only: API tokens stay valid and must be revoked through the token
endpoints.

## Account lockout recovery

An operator is locked out by failed-login lockout
(`--auth-lockout-threshold`, default 5 within `--auth-lockout-window-secs`,
default 900). The window auto-expires, so the first question is whether you
need to act at all — waiting it out is the zero-risk path.

**Preferred — admin API** (audited, no database access needed):

```bash
curl -fsS -X POST "https://yuzu.internal/api/v1/users/alice/unlock" \
     -H "Authorization: Bearer $TOKEN"
```

Requires `UserManagement:Write` (plus MFA step-up when the caller is enrolled).
Self-target is allowed.

**Fallback — direct SQL**, when every admin is locked out and no valid token
exists. This writes no audit row; record it in your change-management system, as described under
[Fallback: direct SQL](#fallback-direct-sql):

```bash
# Inspect first.
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username, failed_login_count, locked_until FROM auth.users WHERE username = 'alice';"

# Clear one account.
psql "$YUZU_POSTGRES_DSN" -c \
  "UPDATE auth.users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL WHERE username = 'alice';"
```

Mass-unlock is a threshold-misconfiguration remedy only (e.g. someone deployed
`--auth-lockout-threshold=1`). Fix the flag in the same maintenance window, or
you will be back:

```bash
psql "$YUZU_POSTGRES_DSN" -c \
  "UPDATE auth.users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL;"
```

**Bulk unlock after an auth-store blip.** Before #5342 a login whose account
row could not be read was answered as a wrong password and counted a lockout
strike, so a Postgres blip during busy sign-in traffic could lock many
legitimate accounts at once. A server on this release answers those logins
`503` with no strike, but a wave of `auth.lockout.applied` audit rows clustered
around a store outage can still happen (a server not yet upgraded, or
automation retrying a stale password through the outage). Unlock only the
accounts whose last failure falls inside the outage window, after confirming
from the audit log that the window is right:

```bash
# Inspect: accounts locked by a failure inside the window (UTC).
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username, failed_login_count, last_failed_login_at, locked_until FROM auth.users
   WHERE locked_until > now()
     AND last_failed_login_at BETWEEN '2026-10-04 09:00:00+00' AND '2026-10-04 09:20:00+00';"

# Clear exactly those.
psql "$YUZU_POSTGRES_DSN" -c \
  "UPDATE auth.users SET failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL
   WHERE locked_until > now()
     AND last_failed_login_at BETWEEN '2026-10-04 09:00:00+00' AND '2026-10-04 09:20:00+00';"
```

Like the single-account fallback, this writes no audit row; record it. The
locks expire on their own after `--auth-lockout-window-secs`, so waiting is
still the zero-risk choice.

## Password reset

A local account's password lives **only** in the PostgreSQL auth store
(`auth.users.password_hash`/`salt_hex`). `yuzu-server.cfg` seeds the first
administrator into an *empty* `auth` schema and is never consulted for an
account that already exists there (#5274) — so **editing or regenerating
`yuzu-server.cfg` no longer resets anyone's password**, and neither does
re-running an installer with a new admin password. (Before #5274 a cfg hash
silently shadowed the stored one on the replica that loaded it, which made a
cfg edit look like a reset; that path is gone.)

**Preferred — in the product** (audited, no database access):

- An administrator resets it: Settings → User Management → **Reset
  password**, or
  ```bash
  curl -fsS -X POST "https://yuzu.internal/api/v1/users/alice/password" \
       -H "Cookie: yuzu_session=$COOKIE" -H "Origin: https://yuzu.internal" \
       -H "Content-Type: application/json" \
       -d '{"new_password":"<12-1024 bytes>"}'
  ```
  This needs an interactive dashboard session of a **durable
  Administrator** — with RBAC off, an account whose own role is `admin`;
  with RBAC on, a user `Administrator` grant. A JIT elevation, an IdP-group
  admin role or a custom role holding `UserManagement:Write` is refused
  (`403 durable_admin_required`), as are API and MCP tokens; MFA step-up
  applies when the caller is enrolled. The configured break-glass account
  cannot be reset this way (`403 break_glass_target`). The new password, the
  sign-out of the user's sessions, the discarding of an unfinished MFA
  enrolment, the lockout clear and the audit row are one database
  transaction — all of it lands, or none of it. Their API tokens and any
  ENROLLED second factor are **not** touched (the response reports how many
  tokens remain active); for a compromised account also run
  `yuzu-server --mfa-reset <user>` and revoke the tokens.
- A user who still knows their password changes it themselves: Settings →
  User Management → **Change password**, or `POST /api/v1/users/me/password`.
  They are signed out everywhere and sign in again with the new password.

Audit: `user.password_reset` / `user.password_change`, written in the same
transaction as the change (an audit failure makes no change: `503`). A reset
also clears the account's lockout, recording `auth.lockout.cleared`
(`detail=password_reset`) only when there was a lockout to clear. There
is no MCP tool for either (#5357 tracks a temporary-password reset tool).

**Re-running the Windows server installer is not a reset.** On an upgrade it
refuses `/ADMIN_PASS=` (and the removed `/OPERATOR_PASS=`) with exit code 11
(the config file it would write only seeds an empty database).

**Fallback — direct SQL**, when no administrator can sign in at all (the only
admin forgot their password). This writes no audit row and revokes no
sessions; record it in your change-management system, as described under
[Fallback: direct SQL](#fallback-direct-sql). Like the in-product
reset, it discards an unfinished (never-enrolled) TOTP enrolment so nobody can
complete it under the old password; an enrolled second factor is kept. Generate
the hash the way the server does (PBKDF2-HMAC-SHA256, 100 000 iterations, 32-byte key,
16-byte random salt, both hex-encoded):

```bash
read -rs NEWPW   # 12-1024 bytes; not echoed, not in shell history
# Passed via the environment, not argv (argv is visible to every local user in ps).
NEWPW="$NEWPW" python3 - <<'PY'
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', os.environ['NEWPW'].encode(), salt, 100000, dklen=32)
print(f"UPDATE auth.users SET password_hash = '{dk.hex()}', salt_hex = '{salt.hex()}', "
      "failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL, "
      "mfa_totp_secret = CASE WHEN mfa_enrolled_at IS NULL THEN NULL ELSE mfa_totp_secret END, "
      "mfa_last_counter = CASE WHEN mfa_enrolled_at IS NULL THEN 0 ELSE mfa_last_counter END, "
      "updated_at = now() WHERE username = 'admin' AND identity_source = 'local' "
      "AND provisioning_source = 'local' AND is_active;")
PY
# Review the printed statement, then run it:
psql "$YUZU_POSTGRES_DSN" -c "<the printed UPDATE>"
```

The same on Windows (elevated PowerShell; needs Python 3 and `psql` on
`PATH`). The connection string is read from the installer's locked file, as in
the backup example above:

```powershell
$Secure = Read-Host -AsSecureString 'New password (12-1024 bytes)'
$Env:NEWPW = [System.Net.NetworkCredential]::new('', $Secure).Password
@'
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac('sha256', os.environ['NEWPW'].encode(), salt, 100000, dklen=32)
print(f"UPDATE auth.users SET password_hash = '{dk.hex()}', salt_hex = '{salt.hex()}', "
      "failed_login_count = 0, last_failed_login_at = NULL, locked_until = NULL, "
      "mfa_totp_secret = CASE WHEN mfa_enrolled_at IS NULL THEN NULL ELSE mfa_totp_secret END, "
      "mfa_last_counter = CASE WHEN mfa_enrolled_at IS NULL THEN 0 ELSE mfa_last_counter END, "
      "updated_at = now() WHERE username = 'admin' AND identity_source = 'local' "
      "AND provisioning_source = 'local' AND is_active;")
'@ | python -
Remove-Item Env:NEWPW
# Review the printed statement, then run it:
$DsnFile = "C:\ProgramData\Yuzu Server\postgres.dsn"
$Dsn = if (Test-Path $DsnFile) { (Get-Content -LiteralPath $DsnFile -Raw).Trim() } else { $Env:YUZU_POSTGRES_DSN }
psql $Dsn -c "<the printed UPDATE>"
```

With the Docker Compose reference stack, generate the statement on the host
as above (the server image has no Python), then run it inside the `postgres`
service, which needs no published port or password:

```bash
docker compose exec -T postgres psql -U postgres -d yuzu -c "<the printed UPDATE>"
```

Run it from the directory holding your compose file (or add `-f <file>`);
adjust `-d` if your server's DSN names a different database.

Expect `UPDATE 1`. No restart is needed: login reads the auth store directly.
Then sign in, revoke the account's old sessions
(`DELETE /api/v1/sessions?username=admin`, or **Sign out everywhere**), and
consider enrolling a second administrator so the in-product reset is
available next time.

## Emergency MFA disable (break-glass)

**When to use.** An operator has lost both their authenticator device *and*
every recovery code — or has been locked out by MFA enforcement (the IdP not
asserting `amr`, a sole admin who could not enroll). The Settings → MFA panel
is behind login, so the dashboard path is unreachable.

### The `--mfa-reset` CLI (audited)

`yuzu-server --mfa-reset <username>` clears the user's MFA enrolment and exits
**without starting the server**. It also ends the account's sessions, and it
writes audit rows (`mfa.reset.breakglass`, principal = the OS account that ran
it): an `attempted` intent row before it clears anything, and an outcome row after.

**It needs the Postgres DSN and the keys directory.** This changed with the
Postgres migration and is the most common reason the command fails today:

```bash
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --postgres-dsn "$YUZU_POSTGRES_DSN" \
  --ca-dir /etc/yuzu/certs \
  --mfa-reset alice
# {"status":"ok","user":"alice","action":"mfa.reset.breakglass"}
```

- `--postgres-dsn` is **required** — without it the one-shot exits non-zero
  with "requires the Postgres auth store". The mandatory audit row is written
  through the SAME `--postgres-dsn` (ADR-0040: audit is Postgres-backed,
  schema `audit_store`) — there is no `<data-dir>/audit.db` write path
  anymore. Point `--postgres-dsn` at the real production database or the row
  lands somewhere nobody is looking (SOC 2 CC6.6), same risk as before, wrong
  flag.
- `--data-dir` is not needed. There is no legacy `audit.db` backfill gate any
  more (retired by the ADR-0009 hard cutover, 2026-09-04), so the one-shot also
  works on a database that has never seen a server boot. If a data directory
  is set (`--data-dir` or `YUZU_DATA_DIR`), it is still created and checked
  writable, and a failure there aborts the command.
- `--ca-dir` is required whenever the KEK is not in the platform default
  location, because the command builds the full auth stack (pool → key
  provider → codec → AuthDB) exactly as the server does.
- No TLS/HTTPS flags are needed; the command never serves.

**Authorisation — read the threat model.** `--mfa-reset` strips a second factor
with **no MFA, admin-password, or token check of its own**. The only enforced
control is OS-level access: anyone who can run a `yuzu-server` binary with the
DSN and the keys directory can downgrade **any** account, including the sole
admin. It does not verify it is running as the service account — that is an
operational expectation, not a code-enforced gate. Treat *DSN + keys-directory
access* as equivalent to MFA-reset authority over every account:

- Run on the server host as the service account (`_yuzu` / `yuzu` /
  `NT SERVICE\YuzuAgent`; see `docs/agent-privilege-model.md`).
- Keep the keys directory `0700` and its contents `0600`, service-account
  owned. Keep the DSN out of world-readable config and out of `ps` (prefer
  `YUZU_POSTGRES_DSN` in a `0600` environment file).
- Gate the invocation behind a narrow `sudoers` entry — ideally a dedicated
  break-glass group with a separate approver. The audit principal is the real
  OS identity (`getpwuid`/`GetUserNameA`, **not** the forgeable `$USER`), so a
  tight sudoers entry gives trustworthy attribution.

**Audit is mandatory and fail-closed.** The CLI first checks that the audit store opens (if it does not, it prints
`error: audit store unavailable; refusing to clear MFA without an audit record` and exits `1` without touching the account;
the server log adds a pointer to your documented break-glass SQL path), then writes the
`attempted` intent row (`MFA clear requested via --mfa-reset CLI (os_identity=<account>)`) BEFORE it clears any MFA. If
the audit store does not accept that row, the command prints `error: audit store did not accept the intent row; nothing
was changed` and exits `1` without touching the account; a second stderr line points at "Fallback: direct SQL" below, for the
case where an operator is locked out and the audit store cannot be restored. The whole point is to replace the unaudited SQL path. A
`{"status":"ok",…}` line with exit code 0 means both the intent row and the outcome row persisted.

**It ends the account's sessions.** After clearing the factor the one-shot
deletes the account's durable sessions (`SessionStore::invalidate_user`), which
bumps the session generation so every replica drops its cached copy on its next
refresh; the account is signed out everywhere. The number of sessions deleted is
recorded as `sessions_ended=<n>` at the end of the outcome row's `detail`
(`... (os_identity=<account>, sessions_ended=<n>)`, `result=success`); `<n>` counts every durable
session row deleted for the account, rows that had already expired but were not yet
reaped included, so it is not a count of sessions that were still usable. The
command's stdout line is unchanged. If ending the sessions fails, the factor is already cleared: the
command exits non-zero with `error: MFA cleared but the account's sessions were
not ended`; the server log carries `--mfa-reset: MFA cleared for '<name>' but ending its
sessions failed (<cause>). End them now with DELETE /api/v1/sessions?username=<name> and
record the reset.` The outcome row is still written, with `result=partial` and `sessions_ended=failed`. Treat
that as an incomplete reset and end the sessions as described under "Ending the
sessions by hand" below. If the clear itself fails, the command ends no session and exits `1` with
`error: failed to clear MFA; the state is unknown, check the account's status and re-run`, and the outcome row is
`result=error` (`MFA clear failed; state unknown, re-run after checking status (os_identity=<account>)`). The commit
acknowledgement may have been lost, so the clear MAY have landed. Re-run `--mfa-reset`: a re-run clears again
idempotently, ends the account's sessions and needs no admin session (do it only if the account has not re-enrolled
since, because a re-run also clears a newly enrolled factor). Alternatively, when an administrator session exists, check the
account's `mfa_enrolled_at` (null means no enrolled factor): if it is null the clear landed, and because the CLI ends no
session after a failed clear (the Settings route does), end the account's sessions by hand with
`DELETE /api/v1/sessions?username=<name>` (see "Ending the sessions by hand" below). Disabling MFA from Settings ends **every** session of the
account, the caller's included, and sends the browser to the landing page. If the
durable delete fails there, the audit row is `mfa.disabled` with `result=partial` and
`sessions_ended=failed`, the page says "MFA was disabled, but the account's sessions
could not be ended. Ask an administrator to end them.", and there is **no retry
control**: after the clear the page shows the not-enrolled view, and the Disable form
exists only in the enrolled view. If the clear itself fails on an account that had a
verified factor, the sessions are still ended (the clear may have committed with its
acknowledgement lost) and the audit row is `mfa.disabled` with `result=error` and
`disable failed (sessions_ended=<n>|failed)`; the user is signed out when the delete
succeeded, and when the delete failed too the page says "Could not confirm MFA was
disabled, and the account's sessions could not be ended. Its state is unknown: ask an
administrator to check it and end the sessions." (check the account's enrolment state
and end its sessions as below). Cancelling an enrolment that was never
verified ends no session (`result=ok`, `no verified factor to clear`). Settings
writes the same two rows. The `attempted` intent row (`MFA clear requested via Settings`) is written first and fails
closed: if the audit store does not accept it, the response is `503` with `Sec-Audit-Failed: true` and `Retry-After: 5`, the
message "Audit store unavailable; MFA was not changed." is shown as a toast on both Settings pages (an error toast has a close button; on Security and
sign-in the message also appears in the Two-factor sign-in panel) and nothing is cleared. Retry once the audit store has recovered, or tell the operator that the audit store needs attention. This guarantee on the Settings route relies on the audit store having opened and on the audit writer being wired into the route; server boot requires both (it refuses to start when the audit store cannot open, and binds the writer at boot). The CLI checks the intent write's result directly. The outcome row is written after the changes and cannot undo them: if it cannot be
written the request still completes and the server logs an error. A failed audit write also increments
`yuzu_server_audit_emit_failed_total`, which the `YuzuAuditPersistFailures` alert (critical) fires on, so a failed
outcome write after a clear pages. The factor clear and the session delete are two separate database commits, so a
process kill between them leaves the factor cleared, the sessions live and an `attempted` row with no outcome
row. Neither path
ends API tokens: an administrator revokes a token with
`DELETE /api/v1/tokens/{token_id}` (the global administrator role may revoke any
token; the owner lists token ids with `GET /api/v1/tokens`).

**Re-running `--mfa-reset`.** Running it again after a `sessions_ended=failed`
is safe for sessions (the delete is idempotent), but it also clears any factor
the user has enrolled in the meantime. Re-run it only before the user enrols
again; once they have, end the sessions with
`DELETE /api/v1/sessions?username=<name>` instead.

**Ending the sessions by hand.** `DELETE /api/v1/sessions?username=<name>` needs
`UserManagement:Write`. Calling it on your own username is permitted (the audit row
is `session.revoke_all.self`). It asks for an MFA step-up only when the caller is a
session whose account has an enrolled factor; an API-token caller and a session whose
account has no enrolled factor skip the step-up. So a sole administrator who has just
cleared their own factor can run it with their own session or an API token, and a
sole-administrator lockout where no administrator session or token is left is covered
by re-running `--mfa-reset` (before the user enrols again) or, if no `yuzu-server`
binary is available, by the single transaction under
[Fallback: direct SQL](#fallback-direct-sql). Treat `db_persisted: false` in the
response as a failed delete and call it again.

**Check that no session remains.** After ending the sessions, confirm that no live
row is left for the account:

```bash
psql -q "$YUZU_POSTGRES_DSN" -c \
  "SELECT count(*) FROM session_store.sessions WHERE username = 'alice';"
```

The count must be 0. A session the user opens after the reset (a fresh sign-in) shows
as a new row, so run the check straight after the delete. The delete bumps the session
write-generation, and each replica polls that counter about once a second
(`kSessionGenRefreshMs`, 1000 ms) and drops its cached sessions when it changes (a lower value after a restore or failover included), so
the account is signed out on every replica within about a second. If a replica's poll
is failing, it trusts its cache for at most 30 seconds from its last successful poll
(`kSessionGenStaleServeBoundMs`) and then falls back to the store, which no longer
holds the row. After a restore or a failover to a lagging standby a lower counter is also
detected at the next poll; only a counter exactly equal to a replica's cached value goes
undetected, see [Sessions are durable](#sessions-are-durable).

**Finding a partial result.** A failed session delete from Settings increments
`yuzu_auth_session_store_degrade_total{op="invalidate_user"}`, but a single event
does not reliably page: `YuzuSessionStoreDegraded` fires on
`increase(yuzu_auth_session_store_degrade_total[10m]) > 0` held for 10 minutes, so it
needs the database to keep failing. The `--mfa-reset` command emits no metric at all.
Look for the audit rows instead. This query lists the last seven days of rows whose
sessions were not ended:

```bash
psql -q "$YUZU_POSTGRES_DSN" -c \
  "SELECT to_timestamp(timestamp) AT TIME ZONE 'UTC' AS at_utc, principal, action, result, target_id, detail
     FROM audit_store.audit_events
    WHERE action IN ('mfa.disabled', 'mfa.reset.breakglass')
      AND (result = 'partial' OR detail LIKE '%sessions_ended=failed%')
      AND timestamp >= extract(epoch FROM now() - interval '7 days')
    ORDER BY timestamp DESC;"
```

Each row names the account in `target_id`. End its sessions, run the check above, and
record the manual deletion in your change-management system. The query is read-only.

**Finding a clear whose outcome is unknown.** Every clear writes an `attempted` intent row first, so a clear that was
requested but never reported its outcome (the process died after the clear, or the outcome write failed) leaves an
`attempted` row with no outcome row after it. This query lists, per action and account, the `attempted` rows that
outnumber the outcome rows over the last seven days, leaving out the last minute, where a request may simply be in
flight. A `blocked:` row (the Settings self-target guard) is written with no `attempted` row, so it is not counted as an
outcome:

```bash
psql -q "$YUZU_POSTGRES_DSN" -c \
  "SELECT action, target_id,
          count(*) FILTER (WHERE result = 'attempted') AS attempted,
          count(*) FILTER (WHERE result <> 'attempted' AND detail NOT LIKE 'blocked:%') AS outcome,
          to_timestamp(max(timestamp)) AT TIME ZONE 'UTC' AS last_at_utc
     FROM audit_store.audit_events
    WHERE action IN ('mfa.disabled', 'mfa.reset.breakglass')
      AND timestamp >= extract(epoch FROM now() - interval '7 days')
      AND timestamp <  extract(epoch FROM now() - interval '1 minute')
    GROUP BY action, target_id
   HAVING count(*) FILTER (WHERE result = 'attempted')
        > count(*) FILTER (WHERE result <> 'attempted' AND detail NOT LIKE 'blocked:%')
    ORDER BY max(timestamp) DESC;"
```

A listed account is suspect, not proven: read its rows in `id` order (`timestamp` is whole seconds), check
`auth.users.mfa_enrolled_at` (null means the factor is cleared), and if it is cleared end the account's sessions as
above. The comparison is by count, so an old row from before the window can offset a lost one, and an outcome row written inside the window by a build that
predates the intent row can offset a lone `attempted` row for the same account (a mixed-version window); it also lists a pair whose
`attempted` row falls inside the window and whose outcome row falls just after it. A requested clear can also leave
the factor intact: if the process dies between the intent write and the clear, the account is unchanged, so read the
`attempted` row as "requested, outcome unknown", not as proof that the factor was cleared. That query does **not** list
a pair whose outcome row is `error`, because an `error` row counts as an outcome there; the next query does.

**Finding a clear that ended `error` or `partial`.** A `result=error` outcome row means the clear reported a failure
and its state is unknown (the commit acknowledgement may have been lost, so the clear may have landed); a
`result=partial` row means the factor was cleared but its sessions were not ended. This query lists the last seven days
of both, for either action, leaving out the `blocked:` self-target refusals (which are `error` rows for a request that
changed nothing) and never matching the `attempted` intent rows:

```bash
psql -q "$YUZU_POSTGRES_DSN" -c \
  "SELECT to_timestamp(timestamp) AT TIME ZONE 'UTC' AS at_utc, principal, action, result, target_id, detail
     FROM audit_store.audit_events
    WHERE action IN ('mfa.disabled', 'mfa.reset.breakglass')
      AND result IN ('partial', 'error')
      AND detail NOT LIKE 'blocked:%'
      AND timestamp >= extract(epoch FROM now() - interval '7 days')
    ORDER BY timestamp DESC;"
```

For each listed account check `auth.users.mfa_enrolled_at`. If it is NULL the clear landed: end the account's sessions
by re-running `--mfa-reset` (a re-run clears again idempotently, ends the account's sessions and needs no admin session) or,
when an administrator session exists, by hand with `DELETE /api/v1/sessions?username=<name>` (the CLI ends no session after a
failed clear, while the Settings route does), then run the "Check that no session remains" query. If it is not NULL the factor
is intact, unless the account re-enrolled since a clear that did land; in that case end its sessions anyway with the
`DELETE` call. Re-run the clear only if it is still wanted. A SIEM rule can use the same predicate.

**Detective control.** Because the CLI exits without serving, it emits no
Prometheus metric — the audit row is the only signal. Alert on
`mfa.reset.breakglass` in `audit_events`; an unexpected one is an
authentication-downgrade event and should page on-call. Also alert on `mfa.disabled`
and `mfa.reset.breakglass` rows with `result=partial` or a `detail` containing `sessions_ended=failed`: each is an
account whose second factor is cleared and whose sessions may still be live. A database fault that fails
the session delete can fail the outcome audit write too, and a process kill between the two commits
leaves an `attempted` row with no outcome row (the query above finds them); if `YuzuAuditPersistFailures` fired or
`yuzu_auth_session_store_degrade_total{op="invalidate_user"}` rose in the same minutes, treat a
missing outcome row as unknown and end the sessions of any account that disabled MFA then.

Every clear now writes two rows, the `attempted` intent row and then the outcome row, so a SIEM rule that counts these
actions once per clear counts twice, and a rule written as `result <> 'success'` (or `result != 'ok'`) matches every
intent row and every `blocked:` row. Exclude `result = 'attempted'` and `detail LIKE 'blocked:%'` from rules that look for
failures, and key failure rules on `result IN ('partial','error')` as in the query above. Order the two rows by the audit
`id` (`timestamp` is whole seconds).

It is safe to run while the server is up: the one-shot opens its own pool and
does not talk to the running process.

### Fallback: direct SQL

Use it in three cases: no `yuzu-server` binary is available on the host;
`--mfa-reset` fails with `kek_orphaned` because the stored secret's header names a
key version that is not registered and that header is corrupt (see
[Stored secret names an unregistered KEK version](#stored-secret-names-an-unregistered-kek-version),
where a restore of the paired backup comes first when the version once existed); or
`--mfa-reset` refuses because the audit store does not open or does not accept the intent row
(`error: audit store unavailable; refusing to clear MFA without an audit record`, or
`error: audit store did not accept the intent row; nothing was changed`) while an
operator is locked out and the audit store cannot be restored in the time available.
**Last resort. It writes no audit row.** In the third case restore the audit store first
and re-run `--mfa-reset`, which is the audited path; use this SQL only when that cannot be done,
because it removes exactly the audit guarantee the CLI's refusal exists to keep.

Because the database leaves no record of this path, the change-management record that
follows it is the only evidence. It must state: who ran it (the OS account and the named
person), when (date, time and time zone), why (the lockout and why neither `--mfa-reset` nor
an audit-store restore was possible), the ticket reference, the account that was changed,
the full SQL transcript (the `psql` session output, including the `COMMIT`), and who approved
running it. The approver must be a different person from the one who ran the SQL. Approval comes before execution; where it
could only be given afterwards, record it as a retroactive exception. Record the post-change verification too: the
account's `mfa_enrolled_at` is NULL and the "Check that no session remains" query returns 0. The transcript is
self-reported, so corroborate it with Postgres statement logging (or pgaudit) where it is enabled. Where the audit store
later recovers, add a note to that ticket saying that no `mfa.reset.breakglass` or `mfa.disabled` row exists for this change.

```bash
psql -v ON_ERROR_STOP=1 "$YUZU_POSTGRES_DSN" <<'SQL'
BEGIN;
UPDATE auth.users
   SET mfa_totp_secret  = NULL,
       mfa_enrolled_at  = NULL,
       mfa_disabled_at  = now(),
       mfa_last_counter = 0
 WHERE username = 'alice';
DELETE FROM auth.mfa_recovery_codes WHERE username = 'alice';
DELETE FROM session_store.sessions WHERE username = 'alice';
INSERT INTO session_store.session_meta (key, value) VALUES ('write_generation', '1')
ON CONFLICT (key) DO UPDATE SET value = (session_store.session_meta.value::bigint + 1)::text;
COMMIT;
SQL
```

These run in ONE transaction on purpose. Unlike the server's own two commits (the
factor clear, then the session delete), an interruption cannot leave the factor
cleared with the sessions live, or the secret cleared with the old recovery codes
still valid. `ON_ERROR_STOP` makes `psql` stop and exit non-zero if a statement
fails, so a failed statement cannot turn the `COMMIT` into a silent rollback with
exit status 0. A session made under the old factor may hold an MFA proof from it,
which is why the session delete is part of the same transaction.

The generation bump is required for the same reason as in
[Sessions are durable](#sessions-are-durable). API tokens are not touched. Run the
"Check that no session remains" query above afterwards.

Clearing the secret needs no KEK (you are writing NULL, not reading
ciphertext), so this works even when the KEK is unavailable.

### Stored secret names an unregistered KEK version

A stored secret blob carries its key-encryption-key (KEK) version in its header: a
one-byte format marker, then the version as a four-byte big-endian number. If that
version is not registered in the `secrets.kek_meta` table, the secret cannot be
read, and the usual recovery is closed:

- The step-up gated routes answer `503` for that account, as for any unreadable
  secret. While the secret stays unreadable the account's password sign-in also
  answers `503` (measured for a truncated blob; expected for any unreadable
  secret), so the user cannot sign in at all until it is recovered.
- `yuzu-server --mfa-reset <username>` fails with exit status 1 and
  `SecretCodec::init() failed for the auth store bootstrap` naming `kek_orphaned`,
  because the secrets seam refuses to initialise while any stored blob names an
  unregistered key version. It never gets as far as clearing the account.
- A server restart refuses to start for the same reason. A server that is already
  running keeps serving until it is restarted, so fix this before any restart.

**The boot check covers every secret column, not only TOTP.** It scans each
registered secret column for blob headers that name a version absent from
`kek_meta`: `auth.users.mfa_totp_secret`, `webhook_store.webhooks.secret`,
`plugin_config_store.secrets.sealed_value`,
`offload_target_store.offload_targets.auth_credential` and
`runtime_config_store.runtime_config_secrets.sealed_value`
(`scan_orphaned_versions` in `pg/secret_codec.cpp`, run for every registered
column). The refusal line names the version number or numbers (`v<N>`), not the
table or the account. Each store has its own codec and its own scan, and the
refusal line names the store (for example `webhook_store SecretCodec::init()
failed`; the auth store's own line carries no store name). The SQL in this
runbook clears MFA enrolment only: clearing an account's TOTP secret therefore
fixes an orphan only if that orphan lives in `auth.users`, and an orphan in any
other store is recovered by restoring the paired `kek_meta` and keys backup, not
by SQL here (the server otherwise keeps refusing with the same line).

**Identify the affected accounts first (read-only).** The query below reads the
same four header bytes the boot check reads and lists the accounts whose TOTP blob
names a version that is not in `kek_meta`. It changes nothing.

```sql
SELECT username, blob_kek_version
  FROM (SELECT username,
               ('x' || encode(substring(mfa_totp_secret from 2 for 4), 'hex'))
                 ::bit(32)::bigint AS blob_kek_version
          FROM auth.users
         WHERE mfa_totp_secret IS NOT NULL
           AND length(mfa_totp_secret) >= 5) AS blobs
 WHERE blob_kek_version NOT IN (SELECT kek_version FROM secrets.kek_meta)
 ORDER BY username;

-- For comparison: the registered versions (retired ones count as registered).
SELECT kek_version, created_at, retired_at FROM secrets.kek_meta ORDER BY kek_version;
```

The `length(...) >= 5` filter mirrors the boot check, which skips a blob too short to
have a four-byte version. A zero-row result for `auth.users` while the server still
refuses to start means the orphan is in one of the other columns. To check one,
repeat the first query with that table and column, for example
`webhook_store.webhooks` and `secret`.

**Choose the remedy by the version number the log names.** Versions are small
integers: the first is `1` and each KEK rotation adds one.

- **The version legitimately existed** (a small number that a real rotation could
  have produced, for example one missing from the middle of the `kek_meta` list or
  one above its highest entry): a registration row was deleted, or the database was restored against a
  mismatched `kek_meta`. This is the first-choice case, and the server's own
  message prescribes the fix: restore `kek_meta` **and** the keys directory from the
  paired backup (see [Backup, the KEK pairing rule](#backup--the-kek-pairing-rule)
  and [KEK permanently lost](#kek-permanently-lost)). It recovers every affected
  account and every other store at once without discarding enrolments, and it is the
  remedy for an orphan outside `auth.users`, where this runbook offers no clearing
  statement. Do not clear secrets that a correct restore would have kept.
- **The blob header is corrupt** (a version number that cannot be real, such as
  `2880154539`, which is what a damaged or garbage blob header decodes to): the
  secret is not recoverable by any backup of the keys. The
  [direct SQL fallback](#fallback-direct-sql) is the remedy, because writing NULL
  needs no key. Run it only for the accounts the identification query listed with
  such a version, not for accounts whose blob is intact. Keep the existing warnings:
  it writes no audit row, so record it by hand. The account can re-enrol afterwards.

If the identification query lists more than one account, or the missing version is
one in use by many blobs, the cause is probably a `kek_meta` and keys-directory pair
that no longer match, which points to the restore rather than to clearing accounts
one by one.

## Break-glass arm (IdP outage under `--auth-mode=sso-only`)

Under `--auth-mode=sso-only` only an SSO provider (OIDC or SAML) mints a session. If the IdP is down, the
`--break-glass-user` account is the way back in — but it is exempt **only while
armed**, and arming is an out-of-band host CLI operation so it works when the
IdP does not.

```bash
sudo -u _yuzu yuzu-server \
  --config /etc/yuzu/yuzu-server.cfg \
  --postgres-dsn "$YUZU_POSTGRES_DSN" \
  --ca-dir /etc/yuzu/certs \
  --break-glass-user alice \
  --break-glass-arm
# → arms the named --break-glass-user for --break-glass-window-secs
#   (default 24h, auto-expiring), prints {"status":"ok",…,"armed_until":"…"}
#   and EXITS without serving.
```

`--break-glass-arm` **requires** `--break-glass-user` (or the
`YUZU_BREAK_GLASS_USER` env var) to name the account. It is a CLI/env option
only — it does not come from `yuzu-server.cfg`, so the one-shot must repeat
whatever the running service passes in its unit file. Omit it and the command
exits non-zero with `error: --break-glass-arm requires --break-glass-user`,
arming nothing.

Arming is fail-closed on audit: the audit store is checked reachable and
migrated *before* the mutate, and if the row fails to persist afterwards the
arm is rolled back (the account ends up NOT armed). If the rollback also fails,
the command exits non-zero and says so on stderr: the account may still be
armed, with no audit row. That makes the `--postgres-dsn` note above
load-bearing here too — point it at the real production database, or you
will arm the glass and record it somewhere nobody is looking.

Same flag requirements and the same threat model as `--mfa-reset` above. The
arm is audited at `kCritical` as `auth.breakglass.armed`, attributed to the OS
identity; the subsequent login is audited as `auth.breakglass.login` and
increments `yuzu_auth_break_glass_login_total`. The window auto-expires — you
do not need to disarm.

The break-glass account **must** have MFA enrolled: boot fails closed if it
does not, and an un-enrolled break-glass account is hard-denied at login
(enrolment is never offered on that path, since that would defeat the second
factor).

**Do not disable MFA on the armed break-glass account** (Settings → Two-factor sign-in → Disable, or `--mfa-reset`)
**while the IdP is unavailable.** The Settings disable signs the actor out, and under `--auth-mode=sso-only` the account
can then no longer sign in until its factor is enrolled again, which needs a restart with `--auth-mode=standard` (below),
a step you want to avoid during an IdP outage. A restart under `sso-only` also refuses to boot
until the account is enrolled.

To enrol the break-glass account, restart the server with `--auth-mode=standard`
and sign in as that account. This re-enables local-password login for every local
account, so keep the window short: on bare metal consider `--web-address
127.0.0.1`; in a container, restrict the published port instead (the image binds
0.0.0.0). The break-glass lockout exemption does not apply in standard mode, so
failed password attempts can lock the account for `--auth-lockout-window-secs`.
Only with the listener restricted as above, consider `--auth-lockout-threshold=0`
for the window (it disables throttling for every local account); otherwise an SSO
admin, if the IdP is up, can clear a lock with `POST /api/v1/users/{name}/unlock`.
Under
`--mfa-enforcement=required` the sign-in itself enrols MFA; otherwise enrol at
Settings → Security and sign-in → Two-factor sign-in, which needs the admin role. For a
non-admin break-glass account, also pass `--mfa-enforcement=required` for that
restart, and note that it applies to every user for the window: un-enrolled local
users are enrolled at login, and SSO users whose IdP sends no `amr` cannot pass
step-up. Then restore `--auth-mode=sso-only` and your usual `--mfa-enforcement`.
If the arm has lapsed by then and you still need break-glass access (the IdP is
still down), re-run `--break-glass-arm`; do not re-arm for a planned rotation.
The mode switch itself writes no audit row, so record the window in a change
ticket; the evidence is the startup WARN that `--break-glass-user` is ignored under
standard mode, the missing sso-only boot banner, the
`auth.login` and `mfa.enroll.verified` rows inside the window, and the banner
returning on the final restart.

To rotate the break-glass TOTP, clear it first with `--mfa-reset <user>` (an
enrolled account gets a challenge at sign-in, not enrolment, and cannot re-enrol
from Settings), then follow the enrolment sequence above. Do not restart under
sso-only between the reset and the re-enrolment: boot refuses until the account
is enrolled again.

## Locked out by MFA enforcement misconfiguration

`--mfa-enforcement=required` (or `admin-only`) with no enrolled accounts locks
everyone out. Enforcement is read from configuration at startup, not from the
database, so the fix is a restart with the flag relaxed — no data surgery:

```bash
# 1. Relax enforcement and restart. The auth schema is untouched.
sudo systemctl edit yuzu-server     # --mfa-enforcement=optional
sudo systemctl restart yuzu-server

# 2. Log in with password alone, enroll via Settings → Security and
#    sign-in → Two-factor sign-in, and SAVE the recovery codes.

# 3. Restore enforcement and restart.
```

To enrol a non-admin approver deliberately (rather than recover from a lockout), see the next section.

## Enrolling a non-admin approver

Approving or rejecting an approval request requires the approver's own account to have an enrolled MFA factor
(#6079); a local account without one is refused `403` with
`approver_assurance_required:mfa_not_enrolled`. An administrator can enrol its own account under Settings
→ Security and sign-in → Two-factor sign-in, but a **non-admin cannot enrol itself** in the default modes:
the Settings enrolment routes are administrator-only, and sign-in enrols an account only when
`--mfa-enforcement` protects it (`optional` protects nobody; `admin-only` protects administrators). The
seeded `Operator` role holds `Approval:Approve`, so on a fresh `optional` deployment with RBAC enforcement on
the non-admin approvers are exactly the accounts that cannot enrol. The seeded administrator is also un-enrolled under
`optional`, so a deployment that has not enrolled anyone has no approver at all. An administrator cannot
enrol another user's account on its behalf: Settings enrolment always enrols the signed-in account.

**This section applies only with RBAC enforcement on.** With RBAC enforcement off (the shipped default) the legacy
permission gate requires the `admin` role for `Approval:Approve`, so a non-admin is refused `403`
"admin role required" before the MFA check is reached, and enrolling a non-admin by path A or path B changes
nothing about that refusal. Turn RBAC enforcement on (and confirm the approver holds `Approval:Approve`) first.

There are two ways to enrol a non-admin, and neither is self-service:

| | Enrolment sign-in window (path A) | Promote, enrol, demote (path B) |
|---|---|---|
| Mechanism | Restart with `--mfa-enforcement=required`; each approver is enrolled at sign-in | An administrator raises the account's role to `admin`; the user enrols in Settings; the administrator sets the role back to `user` |
| Restarts | Two (open and close the window) | None, except under `--auth-mode=sso-only`, where local password sign-in is off: restart into `--auth-mode=standard` first and back afterwards (two restarts, as in path A) |
| Blast radius | Deployment-wide: every un-enrolled local user is forced to enrol, and SSO users without an MFA `amr` are gated | One account, for the minutes between promote and demote |
| Suits | Many approvers, planned maintenance | One or a few approvers, or an urgent decision |

**Both paths are trust-on-first-use.** Whoever completes the enrolment first becomes the account's enrolled
factor, and the approver check accepts that factor without knowing who holds the device. Anyone who
knows the account's password when the window opens, and signs in first, enrols their own authenticator;
the real user is then locked out of enrolment (the account is already enrolled, and only
`--mfa-reset <user>` clears it). Treat the enrolment as an identity-proofing step, not a formality:
establish who holds the password before the window, and verify who enrolled afterwards.

### What the step-0 query shows

The query in path A step 0 lists the **active local accounts with no enrolled factor** at the moment you run
it, with their legacy `role` column. It does **not** show who holds `Approval:Approve` (RBAC grants live
elsewhere; list them as described in [Upgrading](../user-manual/upgrading.md)), it does not cover OIDC or SAML
accounts (they are not local), and run afterwards it shows only that some enrolment happened for an account,
**never who performed it**. Do not read an empty result as proof that every enrolment was by the intended person.
That proof is the verification in step 4.

### Seeing that approvals are being refused, and why

Every approver refusal by the approver gate (not the central step-up check) leaves a `denied` row, or an `error` row for
an unreadable MFA store or for the clock-skew refusal, whose `detail` starts with `approver_assurance:` followed by the reason. This query, read-only, shows
how to see that approvals are currently being refused, and why, over the last hour:

```sql
SELECT detail, result, count(*) FROM audit_store.audit_events
 WHERE action IN ('approval.approve','approval.reject')
   AND detail LIKE 'approver_assurance:%' AND result IN ('denied','error')
   AND timestamp >= extract(epoch FROM now() - interval '1 hour')
 GROUP BY detail, result ORDER BY 3 DESC;
```

Run it with `psql "$YUZU_POSTGRES_DSN"`. A large count of `approver_assurance:mfa_not_enrolled` after an upgrade means
the approvers still have to enrol (this section); a row `approver_assurance:mfa_proof_clock_skew` with `result=error` is the
next entry. The central step-up check's own refusals (a stale proof, SAML, an
engine principal) are `mfa.step_up.required` rows, not `approval.*` rows, so they do not appear here.

### OIDC approvers refused with a clock-skew 503

**Symptom.** An OIDC approver is refused with `503` and the message `the approver's identity-provider MFA proof is
dated after the database clock`, and signing in again does not help. The body carries `retry_after_ms: null` (the key
is present with a null value, so there is no retry hint) and the A4 remediation says an administrator must correct clock
synchronisation. Local-account approvers do not get this answer. The dashboard shows the message and the remediation together to the
approver for a `503`, in the approve dialog and on the Approvals tab. What the approver sees depends on the
configuration (derived from the code path; not reproduced against a deliberately skewed rig), so do not rely on the `503` alone:

- **Default `--mfa-enforcement=optional`, `admin-only` with a non-administrator approver, or the step-up window at `0`.** The approver gets the `503` until the
  database clock reaches the stored proof instant, which is after at most as long as the skew is large. After that the
  cached proof stays dropped and the approver gets `403` `mfa_proof_missing` (its remediation names both causes, the
  identity provider sending no MFA `amr` and the Yuzu server and its database disagreeing about the time, and always ends
  by asking the administrator to check clock synchronisation) until the session cache re-derives (a session create, MFA mark, elevation or delete by any user clears it; an activity touch does not; so does a server restart). Signing in again re-creates the same state while the skew persists.
- **`--mfa-enforcement=required`, or `admin-only` for an administrator approver, with the window above `0`.** The central
  step-up check answers first (unchanged by this release). The OIDC approver sees a repeating `401` step-up challenge,
  there is no `approval.*` skew row and no skew log line, and `yuzu_auth_mfa_step_up_gate_total{outcome="refused"}`
  rises. Check clock synchronisation first, then the provider's `amr`.

**What to look for.** The audit trail has `approval.approve` / `approval.reject` rows with `result=error` and `detail`
`approver_assurance:mfa_proof_clock_skew` (the "Seeing that approvals are being refused" query above lists them). The
server log has error lines (one from the MFA check, one from the approval route) that contain `dated after the database clock`; grep for it:

```bash
journalctl -u yuzu-server | grep 'dated after the database clock'
# a container deployment:
docker logs <container> 2>&1 | grep 'dated after the database clock'
```

`yuzu_auth_secret_unavailable_total{route="approval"}` does **not** move for this refusal, because that counter stays a
store-fault signal. Do not conclude that the approval path is healthy from a flat counter.

**Cause.** The proof timestamp stored with an OIDC session is the ID token's `iat`, clamped at sign-in to the clock of the
Yuzu replica that took the sign-in (so an identity provider running ahead cannot by itself future-date the stored proof;
the provider is only the origin of the timestamp). The approver gate compares the stored proof with the database clock.
The refusal therefore means the replica's clock was ahead of the database clock: a database clock that is behind the
replica (a failover to a standby with a drifted clock, an NTP step, a resumed virtual machine, hosts synchronised to
different time sources) makes the stored proof read as dated in the future, so the gate refuses it.

**Fix.** Synchronise the clocks of the Yuzu server hosts and of the database host to the same time source (NTP or the
platform's time service), then have the approver sign in again. The remediation text also names the identity provider, which
is only the origin of the timestamp: because of the clamp it cannot cause this refusal alone. There is no retry hint because
retrying cannot help until the clocks agree. If the approver still gets `403`
`mfa_proof_missing` once the clocks agree, configure the provider to require MFA for approvers and to report it in `amr`
only when MFA was performed; Yuzu trusts the `amr` claim, so one asserted unconditionally defeats the control.

### Path A: an enrolment sign-in window

This uses the same enforced-login mechanism as the lockout recovery above. It costs two restarts, and
`--mfa-enforcement=required` applies to the whole deployment for as long as it is set.

```bash
# 0. Find who needs enrolling: local, active accounts with no enrolled factor.
#    Compare the list with who holds Approval:Approve (role is the legacy role column).
psql "$YUZU_POSTGRES_DSN" -c \
  "SELECT username, role FROM auth.users
    WHERE is_active AND identity_source = 'local' AND mfa_enrolled_at IS NULL
    ORDER BY username;"
```

**1. Prove who holds each password.** Every account on the step-0 list, not only the approvers, can be
enrolled by whoever signs in first. For each approver (and for any other account on the list whose password
you cannot vouch for), immediately before the window opens, reset the
password (Settings → User Management → **Reset password**, or `POST /api/v1/users/{username}/password`; see
[Changing and resetting a local password](../user-manual/authentication.md#changing-and-resetting-a-local-password))
and give the temporary password to that person out of band: in person, or on a channel you have already
verified belongs to them. The administrator must not sign in as the approver. The reset needs a durable
Administrator signed in locally, which an `--auth-mode=sso-only` deployment does not have (only the armed
break-glass account signs in locally): there, restart in `--auth-mode=standard` with your usual enforcement
first, reset the passwords, and only then restart with `required` in step 2, which adds a restart. Between that
first restart and the reset, the old passwords work again, so keep the interval short. The reset also signs the account
out everywhere and discards an unfinished enrolment. Ask the approver to be ready to sign in as soon as the window
opens, and to change the password afterwards (a non-admin cannot open Settings: use **Access → Users and roles → Your
account → Change password**, or `POST /api/v1/users/me/password`; once enrolled, that step needs a fresh code).

**2. Open the window.**

```bash
# systemd: add the setting in a drop-in, then restart.
sudo systemctl edit yuzu-server
sudo systemctl restart yuzu-server
```

In the editor that `systemctl edit` opens, add these two lines (they are file content, not shell input):

```ini
[Service]
Environment=YUZU_MFA_ENFORCEMENT=required
```

For the reference compose deployment, set the variable on the `server` service (for example in a
`docker-compose.override.yml`) and recreate the container:

```yaml
services:
  server:
    environment:
      YUZU_MFA_ENFORCEMENT: required
```

```bash
docker compose up -d server
```

If the unit's `ExecStart`, the container command or the config file already sets `--mfa-enforcement`, that
setting may take precedence over the environment variable; change it there instead. Do not assume either way:
confirm the window is open from the startup log, `MFA enforcement active: mode=required`. With more than one server replica, **every serving replica must carry the
setting**: enforcement is read per process, so a replica you did not restart does not force enrolment. The
enrolment-pending state is also per process (see `--mfa-login-pending-secs`), so keep each approver's
enrolment on one replica (session affinity, or run the window on a single replica). Under `--auth-mode=sso-only`
the window needs local password sign-in, so it also needs `--auth-mode=standard` for its duration (see the
break-glass section above for what that re-enables).

**3. Each approver signs in**, with the temporary password. Sign-in shows the enrolment step; they scan the
code, confirm it, and SAVE the recovery codes. Keep the window attended and as short as you can: close it as soon
as every approver you expect has enrolled. While it is open, watch the `mfa.enroll.required` and
`mfa.enroll.verified` audit rows come in, and have each approver confirm out of band (a call or message) that
they just enrolled.

**4. Close the window and verify it is closed.** Restore your usual enforcement (remove the
`Environment=` line, or the compose setting, or set `optional` / `admin-only`) and restart or recreate the
container. Then check all of the following:

- The startup log no longer says `MFA enforcement active: mode=required` (under `optional` there is no such
  line; under `admin-only` it names that mode). Under `--auth-mode=sso-only` the `Hardened auth mode ACTIVE
  (--auth-mode=sso-only)` startup WARN is back, which also shows local password sign-in is disabled again.
- Re-run the step-0 query: none of the approvers you enrolled still appears.
- Match every enrolment to a person. This is the evidence, and it must be compared against the change ticket
  rather than counted:

  ```bash
  psql -q "$YUZU_POSTGRES_DSN" -c \
    "SET TIME ZONE 'UTC';
     SELECT to_timestamp(timestamp) AS at, principal, source_ip, user_agent, detail
       FROM audit_store.audit_events
      WHERE action = 'mfa.enroll.verified'
        AND timestamp >= extract(epoch FROM timestamptz '<window start in UTC, e.g. 2026-10-20 09:00+00>')
      ORDER BY timestamp;"
  ```

  Each row is the account that enrolled, with the time, source address and browser it came from. `source_ip` is
  the address of the connection the server saw: behind a load balancer or reverse proxy it is the proxy's address
  for every row (the server does not read forwarded-address headers here), so the real client address is in the
  proxy's own access log, which you match to the row by time. Confirm that the
  time and source fit the person who was meant to enrol that account, and record the result in the change ticket.
  An account that enrolled when its owner did not, or from an address that is not theirs, was pre-empted.
- A test approval succeeds on a signed-in session (see "After upgrading, verify approvals on a test request" in
  [Upgrading](../user-manual/upgrading.md)).

**To abort.** If you stop before step 3, or decide not to continue, restore the enforcement setting and
restart or recreate the container as in step 4. The window itself changes no data, but step 1 does and an abort
does not undo it: the approvers' passwords were reset (you know the temporary ones), their sessions were ended and
any unfinished enrolment was discarded. Have each approver change the temporary password at their next sign-in, or
reset it again and hand over a new one only when you try again; an account that already enrolled stays enrolled
(clear it with `--mfa-reset <user>` if it should not be). Do not leave the deployment on `required` by accident, because
that keeps forcing enrolment on every un-enrolled local user, gates SSO users whose provider sends no MFA `amr`
at every step-up endpoint with no alert, and, if you also switched to `--auth-mode=standard` for the window,
keeps local password sign-in on.

**If an account was pre-empted.** Clear the enrolment on the server host with `--mfa-reset <user>` (see
[The `--mfa-reset` CLI (audited)](#the---mfa-reset-cli-audited); reset the password first, and treat any API
tokens the account holds as possibly exposed), then enrol again with a fresh window or path B.
Then review what the account did while it was enrolled by the wrong person. An approved ticket cannot be
withdrawn (see [Upgrading](../user-manual/upgrading.md)), so list the decisions it made and have an authorised
approver check each ticket's status and, where the decision was not the intended person's, deal with it as a
security incident:

```bash
psql -q "$YUZU_POSTGRES_DSN" -c \
  "SET TIME ZONE 'UTC';
   SELECT to_timestamp(timestamp) AS at, action, result, target_type, target_id, source_ip, detail
     FROM audit_store.audit_events
    WHERE principal = '<pre-empted account>'
      AND (   (action IN ('approval.approve', 'approval.reject')
               AND result IN ('attempted', 'success'))
           OR (action IN ('mcp.approve_request', 'mcp.reject_request')
               AND result = 'success'))
      AND timestamp >= extract(epoch FROM timestamptz '<lower bound in UTC, a few minutes before the wrong enrolment, e.g. 2026-10-20 09:55+00>')
    ORDER BY timestamp;"
```

**The lower bound is UTC.** The first statement pins the session to UTC, because `psql` otherwise reads a bare
`timestamptz` literal in the session's own time zone (the server default, the role's setting, `PGTZ` or a DSN
option), which moves the bound by whole hours and returns no rows without any error. Write the bound with an
explicit `+00`, and convert a time you read in local time to UTC first. The `timestamp` column is the writing replica's clock, so put the lower bound a few minutes
before the wrong enrolment to cover NTP skew between replicas; that margin covers clock skew only, not a time-zone
offset.

**An empty list is not evidence that the account did nothing.** The same output appears when the bound is wrong,
when the audit store was restored or purged, and when an audit write was lost (the `success` row of a REST decision
is best effort). Run this control over the SAME lower bound:

```bash
psql -q "$YUZU_POSTGRES_DSN" -c \
  "SET TIME ZONE 'UTC';
   SELECT count(*), to_timestamp(min(timestamp)) AS earliest, to_timestamp(max(timestamp)) AS latest
     FROM audit_store.audit_events
    WHERE timestamp >= extract(epoch FROM timestamptz '<lower bound in UTC, a few minutes before the wrong enrolment, e.g. 2026-10-20 09:55+00>');"
```

For a deployment that has been running since the wrong enrolment, `count` must be above zero (it counts every audit
row of every action and principal) and `earliest` must be at or after the bound. A `count` of zero means the bound
or the audit store is wrong, not that the account did nothing. A non-zero count shows the bound selects audit rows,
not that every decision left one; check the approvals the account could have decided against the tickets too.

A replica that has #6061 writes an `attempted` row and then an outcome row for each REST decision, and the
`success` rows are the decisions that took effect; an `attempted` row with no outcome row means the decision may or
may not have been applied (it was refused, the outcome row was lost, or the server stopped), so check each ticket's
status. A replica that predates #6061 writes only the `success` row. The `mcp.approve_request` and
`mcp.reject_request` rows are a decision made over MCP by a replica that
still allows it (an upgraded replica refuses MCP decisions, so these come from a replica not yet upgraded or from
a rollback). They leave a single `success` row, with `target_type` `mcp_tool`, `target_id` the tool name and the
approval ticket id in `detail`. See "Mixed-version admission" in [Upgrading](../user-manual/upgrading.md).

Consequences to plan for, because `--mfa-enforcement=required` applies to the whole deployment for as long
as it is set:

- **Every un-enrolled local user is forced to enrol at their next sign-in**, not only the approvers, and
  cannot reach the dashboard until they do. Run the window when those users are expected, and keep it short.
- **SSO users whose identity provider sends no MFA `amr` are gated** at every step-up endpoint (a `401` that
  loops through re-sign-in), not only at approval. Verify `amr` first, as in
  [Locked out by MFA enforcement misconfiguration](#locked-out-by-mfa-enforcement-misconfiguration).
- **Both restarts interrupt the server** (connected agents reconnect afterwards), and enforcement is read from
  configuration at startup, so there is no way to open or close the window without one. Existing sessions are
  durable and are not ended by a restart. A decision that cannot wait for two restarts is a case for path B.
- **Record the window in a change ticket**: when it opened and closed, the step-0 list, and the result of
  matching each `mfa.enroll.verified` row to a person.

### Path B: promote, enrol, demote

This needs no restart and no deployment-wide setting, except under `--auth-mode=sso-only`, where local password sign-in is off: restart into `--auth-mode=standard` before step 1 (the password reset needs it, as in path A) and back after step 5. It is the better choice for a few approvers or an urgent
decision. The administrator needs its own `admin` role (a JIT elevation does not qualify), and each role change
is step-up gated (a fresh proof when that administrator is enrolled).

1. Deliver a known password to the approver out of band, as in path A step 1.
2. An administrator raises the account to `admin` with `POST /api/settings/users/{username}/role` and the body
   `{"role":"admin"}`, from a signed-in administrator dashboard session. This ends the account's existing
   sessions.
3. The approver signs in and enrols, and SAVES the recovery codes. Under `--mfa-enforcement=optional` they enrol
   under Settings → Security and sign-in → Two-factor sign-in; under `admin-only` the sign-in itself walks the
   now-administrator account through enrolment. The administrator waits for the `mfa.enroll.verified` row, checks its time and source, and records in the
   change ticket the out-of-band handover and whether that row matched the person who was meant to enrol (see the
   `mfa.enroll.verified` query in path A's verification list). If it did not match, the account is a full
   administrator held by the wrong person at this moment: do step 4 immediately to end that exposure, then
   follow "If an account was pre-empted" above (reset the password, then clear the enrolment with `--mfa-reset`) and
   review what the account did while it held the `admin` role, from the `user.role_change` row of step 2 onward.
4. An administrator sets the role back with the body `{"role":"user"}`. This ends the account's sessions again, so the
   approver signs in once more (now with a code), and that sign-in carries the proof the approval check needs.
   Under `--auth-mode=sso-only` that sign-in is a local one, so keep `--auth-mode=standard` until it is done.
5. Verify the demote took effect. If the role change failed, the account stays a full administrator, and the
   sessions it already holds stay valid for up to their 8-hour lifetime:

   ```bash
   psql "$YUZU_POSTGRES_DSN" -c \
     "SELECT username, role FROM auth.users WHERE username = '<approver>';"
   psql "$YUZU_POSTGRES_DSN" -c \
     "SELECT to_timestamp(timestamp) AS at, principal, result, detail
        FROM audit_store.audit_events
       WHERE action = 'user.role_change' AND target_id = '<approver>'
       ORDER BY timestamp DESC LIMIT 5;"
   ```

   `role` must read `user` and the latest `user.role_change` row must be `result=success` with
   `new_role=user` in its `detail`. A `partial` row (`session_wipe_failed=true`) means the role changed but a
   session at the old role may survive. If the role is not `user`, repeat step 4; in every failing case end the
   account's sessions (`DELETE /api/v1/sessions?username=<approver>`). Under `--auth-mode=sso-only`, then restore
   that mode with a restart and record both restarts in the change ticket.

Consequences: for the minutes between steps 2 and 4 the account is a full administrator, with every
administrator-only page and route, and under the `role-gated` approval mode an administrator's own submissions
execute directly instead of waiting for approval. Keep the approver attended and the interval short. Both
role changes are audited (`user.role_change`). As a rough planning figure, allow about ten minutes of attended
administrator time per approver (an estimate, not a measurement), against the two restarts and the
deployment-wide effects of path A.

Afterwards, confirm each approver in the query from step 0 no longer appears and that a test approval
succeeds on a signed-in session (see "After upgrading, verify approvals on a test request" in
[Upgrading](../user-manual/upgrading.md)). Also check that at least one enrolled, authorised approver exists
who is not the submitter of each request you expect to be decided: a request cannot be decided by its own
submitter, and an administrator who is the only enrolled approver cannot approve their own request.
Break-glass accounts are enrolled by validation and get no exemption. OIDC approvers are not enrolled in
Yuzu at all; they need their identity provider to assert an MFA-method `amr`. SAML approvers cannot approve
(#4935). A proof made before an account's current enrolment does not count, so an approver who was
re-enrolled signs in or steps up again before approving. A non-admin approver who loses a device is in the same
position as before enrolment: `--mfa-reset <user>` removes the factor and the account must be enrolled again by
one of the two paths above.

## Step-up returns 503 while the authentication store is unavailable

The 37 routes that need a fresh MFA step-up (token, session, engine-principal,
RBAC and Guardian writes, password reset and the others listed in the
[REST API reference](../user-manual/rest-api.md#step-up-envelope-on-high-risk-endpoints))
check the caller's MFA state before the route runs. Other mutating routes and all
MCP tools are not step-up gated in this release, so this incident does not close
them. A gated route answers **`503`** and does not run in three cases:

- the server has **no wired authentication store** (reason
  `auth_store_unwired`). This is a defensive state (a boot-wiring fault, or a
  build that wires no store), not a field condition you should see after a
  normal boot. It answers `503` for any caller that reaches the check, a token
  caller included, and even when the step-up window is disabled;
- the store is wired but **cannot be read, or an enrolled account's stored second
  factor cannot be decrypted** (reason `mfa_status_unavailable`). This answers
  `503` to **local (password) sessions only**, since those are the only sessions
  whose enrollment is read from the store. API-token and MCP-token callers pass
  before any store read, OIDC sessions are judged on the identity provider's
  assertion, SAML sessions get their `403`, and engine principals get `403`;
- the check itself **threw an unexpected exception**, or could not fingerprint the session
  (reason `chokepoint_exception` for both). An exception can arise for any caller class; a
  fingerprint failure is reached only after the decision has passed, so an engine principal or a
  SAML session still gets its `403`. This is a fault in the server rather than in the store: the
  server log (sampled, one line in 100) holds the exception text for a thrown exception, or
  `could not fingerprint the session for <route label>` for a fingerprint failure, and the
  window lever below is not a fix for either.

```json
{"error": {"code": 503, "message": "authentication store is temporarily unavailable", ...},
 "meta": {"api_version": "v1", "mfa_step_up_required": true}}
```

There is no `challenge_url`: this is a server-side outage, not a request to
re-prove, so entering a TOTP code cannot clear it. The envelope's `meta` still
carries `mfa_step_up_required: true`, so a client must treat a `503` as "retry
shortly" and prompt for a code only on a `401`. Each refusal writes an
`mfa.step_up.required` audit row, best effort (every refusal has `result=error`;
the `reason=` token in `detail` tells them apart: a missing store is
`reason=auth_store_unwired`, an unreadable enrollment
`reason=mfa_status_unavailable`, an unexpected failure inside the check itself
`reason=chokepoint_exception` (also written when the session could not be fingerprinted); the `detail` also carries `cid=<id>`, equal to the
response's `X-Correlation-Id` header, and `stage=pre_authz`), and
`yuzu_auth_mfa_step_up_gate_total{outcome="unavailable"}` counts the 503s. If the
audit store is down too, the rows are lost and the counter is the only record. A
read failure the store does not classify as unavailable is answered `401` instead,
with the same `mfa_status_unavailable` reason and a remediation that says the
authentication store is unavailable; it is counted as `refused`, not
`unavailable`, so the alert below does not see it. A `503` is never a pass: the
gated route stays closed until the cause is fixed. Approve and reject add their own
check after this one. An approver whose stored session proof cannot be read, or a local
approver whose MFA state cannot be read at that check (the window is `0` or less, or the
fault falls between the two reads), can still receive a `503` from that check (A4 envelope with `retry_after_ms`,
counted `route="approval"` on `yuzu_auth_secret_unavailable_total`, audit
`approval.approve` or `approval.reject` with `result=error` and `detail`
`approver_assurance:mfa_store_unavailable`). A different `503` from the same route is the clock-skew refusal of an
OIDC approver (`retry_after_ms` is null, audit `result=error` with `detail` `approver_assurance:mfa_proof_clock_skew`, not
counted on `route="approval"`); it is not a store fault, and its entry is
[OIDC approvers refused with a clock-skew 503](#oidc-approvers-refused-with-a-clock-skew-503).

**The alert is slow by design.** `YuzuStepUpGateUnavailable` fires when the
`unavailable` outcome counts at least **3** refusals in a 10-minute window for one
instance and surface, held for 5 minutes. Expect it **no earlier than about 5
minutes after the third `503`**, plus scrape and evaluation delay, and it clears
up to 10 minutes after the last `503`. One or two stray `503`s never fire it, so a
quiet alert does not prove the check is healthy: on a low-traffic instance, read
the counter and the audit rows directly. The threshold is per (job, instance,
surface), so a few `503`s on each of many replicas (or spread across both
surfaces) may never reach 3 on any one series and not fire at all; during a
suspected outage, sum the counter across replicas yourself.

### When Postgres is stalled rather than down

A database that accepts connections but answers slowly or not at all (a frozen
host, a saturated disk, a paused container) behaves differently from one that
refuses connections. The measurements below come from one test rig: the database
container was paused for 30 seconds (the longer run is noted where it matters),
so the transport kept acknowledging packets while the database process answered
nothing. No gated request was admitted during any stall. Each figure below is
marked as measured or as derived from the code, because the two are not equally
firm.

- **Gated requests that already hold a database connection wait until the stall
  ends** (measured). The statement timeout does not cut them short, so they can
  stay open for the whole stall. That holds while the transport still
  acknowledges packets, as with a paused or hung database process. Over a dead
  network path the 10 second `tcp_user_timeout` on the pool's connections bounds
  the wait instead (`pg_pool.hpp`, derived from the code, not measured).
- **New requests fail with `503`** in about 1.6 to 10.3 seconds (measured over
  three runs: most failed within about 1.6 seconds, a second group took about 10.3
  seconds). The slower group is the requests that had to open a fresh connection
  and waited out the pool's 10 second connect timeout (`connect_timeout_s`,
  `pg_pool.hpp`).
- **After about 30 seconds of a long stall, cookie sessions begin to answer `401`
  `unauthorized` before the step-up check runs**, instead of `503`. The 30 second
  figure is derived from the code, not measured: the session validation cache is
  trusted for 30 seconds after the last successful refresh
  (`kSessionGenStaleServeBoundMs`, `auth.cpp`), after which a session has to be
  re-read from the database. It was seen only in a longer run (70 second stall),
  where the first `401` arrived after the first request had itself been held for
  60 seconds, so that run does not pin the onset. A `401` is still a refusal (the
  route does not run), but the status class changes from `503` to `401`. A client
  or monitor that reads every `401` as "re-authenticate" will misread the outage;
  check the database first.
- **Engine principals get `401` too** (measured). An engine token is resolved by
  the same pre-routing authentication as a session, so while the database cannot
  answer it is not resolved and the request is refused `401` `unauthorized`: no
  step-up envelope, no per-principal quota check and no step-up audit row. The
  `403` `engine_principal_denied` answer needs the credential to resolve first; the
  denial itself never reads the MFA store.
- **The server recovers without a restart** (one measurement: about 3 seconds
  after the database answered again, a gated request reached the step-up check
  and got its normal `401` challenge instead of `503`, and `/readyz` returned
  `200`). The wait is the pool's connect circuit breaker, whose
  window is capped at 5 seconds with jitter (`connect_backoff_cap`, `pg_pool.hpp`),
  so a slower recovery within that cap is expected.
- **The step-up refusal audit rows for requests during the stall are lost**
  (measured), as the audit store is the same database.

**What the counters record.** `yuzu_auth_mfa_step_up_gate_total` and
`yuzu_server_audit_emit_failed_total` count what happened, with two limits.
First, the gate counter records only refusals the step-up check itself decides.
A refusal decided before the gate is not counted there: the `401`
`unauthorized` that cookie sessions get once the session cache lapses, and an
engine credential that does not resolve during the outage, never reach the check.
Second, `yuzu_server_audit_emit_failed_total` is exposed with the type `counter`
(its `# TYPE` line comes from the metric's description, `server.cpp`), but the
server refreshes its value by a sweep every 15 seconds (the fleet health
recomputation thread in `server.cpp`), so it lags a burst by up to that long.
See the alert note above for the gate counter's own alert.

**An audit-only outage looks different.** If the audit store fails while the
authentication store is healthy, no step-up refusal is `unavailable`: the audit
write is best effort and never changes the refusal, so the refusals keep their
normal answer (for example a `401` challenge, counted `refused`) and `YuzuStepUpGateUnavailable` does not fire. The alert that
covers it is `YuzuAuditPersistFailures` (`docs/prometheus/yuzu-alerts.yml`), which
fires on `increase(yuzu_server_audit_emit_failed_total[5m]) > 0` held for 2
minutes, so allow for the 15 second refresh plus that hold. In that outage the
refusal rows are lost and the counters are the only record. The same alert covers the audit rows of an MFA clear
done in Settings: an intent row the audit store refuses (the disable answers `503` and changes nothing) and an outcome
row that is lost after a clear both increment `yuzu_server_audit_emit_failed_total`. `yuzu-server --mfa-reset` runs as
its own process and exports no metric, so a refusal there is seen only in the command's output and exit status.

**Probes during a stall.** `/livez` and `/login` stay fast (milliseconds,
measured). `/readyz` does not flip at once. It answers from the latest result of
a background reachability probe, not from a live query: the probe runs every 2
seconds, each query has a 2 second deadline, and the replica reports not ready
after 2 consecutive failures (`pg_reachability_rules.hpp`), so it flips within
about 10 seconds. In the measurements `/readyz` kept answering `200` for the first
9 seconds of the stall and `503` after. If no probe succeeds for 15 seconds the
verdict reads stale, which is also not ready, whatever the failure count says.
`/health` can wait on the database: it resolves a session only when the request
carries a credential header (`Cookie`, `Authorization` or `X-Yuzu-Token`;
`resolve_session_fn` in `health_routes.cpp`), and a session lookup that the
in-memory cache cannot answer is a database read, which during a stall can wait
for the pool's 10 second connect timeout when it has to open a connection
(derived from the code; not measured on this path). That figure is not an upper
bound: a request that already holds a database connection waits until the stall
ends (see the first bullet of the list above; measured there for gated requests,
not on this path). A request with no credential header resolves no session.
`/livez` does no session or database work. Point **liveness** probes at `/livez`
and **readiness** probes at `/readyz`, not at `/health`: a liveness probe that
waits on the database during a stall can fail repeatedly and restart a server
that would have recovered by itself; the restart then makes the incident longer.

### Precondition: Postgres must be reachable

Everything below assumes the server is running, which means it reached Postgres at
boot (the server refuses to start otherwise; see
[Postgres substrate unreachable](#postgres-substrate-unreachable)). If the server
is down, this section does not apply: use the boot procedures above.

### Work through the cause, not the route

1. Is Postgres reachable from the server now? See
   [Postgres substrate unreachable](#postgres-substrate-unreachable). Logins
   fail at the same time, so this is usually the same incident.
2. Did the KEK resolve? A non-zero `secret_decrypt_failures_total` for the
   `auth` store means enrolled accounts cannot be read; see
   [KEK missing or unreadable](#kek-missing-or-unreadable).
3. Check `yuzu_auth_secret_unavailable_total{route="mfa_stepup"}` against the
   other `route` values: if only `mfa_stepup` moves, look at the one account
   named in the audit rows' `detail`.

### Single account: prefer `--mfa-reset`

If one account's second factor is the problem (a corrupt or undecryptable
secret), reset that account with
[`yuzu-server --mfa-reset <username>`](#the---mfa-reset-cli-audited). It is
audited (`mfa.reset.breakglass`), needs the Postgres DSN and the keys directory,
and does not touch any other account or the rest of the fleet's step-up
protection. The account can re-enrol afterwards. Prefer it over the window
lever below. If `--mfa-reset` fails with `kek_orphaned`, the stored secret names
a key version that is not registered: see
[Stored secret names an unregistered KEK version](#stored-secret-names-an-unregistered-kek-version),
which makes restoring the paired `kek_meta` and keys backup the first choice and
keeps the [direct SQL fallback](#fallback-direct-sql) for a corrupt blob header.

### Last resort: disable the proof requirement fleet-wide

`--mfa-step-up-window-secs 0` (or less) makes the check pass without reading the
enrollment, so a gated route runs again for a local session. It is a deliberate
security reduction for **every** gated route and every account (see
[Locked out by MFA enforcement misconfiguration](#locked-out-by-mfa-enforcement-misconfiguration)
for the other recovery lever), so use it only when you cannot restore the
authentication store or reset the affected account. Know its limits:

- **It does not help the `auth_store_unwired` reason.** The null-store check
  runs before the window is consulted, so a server with no wired store answers
  `503` at any window value. That is a defensive state (a boot-wiring fault or
  a build that wires no store); restart the server with the store configured. The window lever only helps the
  `mfa_status_unavailable` case, and then only for the routes the check guards.
- **It is per process.** Set it on every replica that is failing, by restarting
  each with the flag; a replica you did not restart keeps refusing. The same holds
  for the revert: restore the window (default `300`) and restart **each** replica
  once the store is back. A replica left at `0` is a silent hole in step-up
  protection for as long as it runs.
- **The JIT-elevation routes ignore it.** They substitute a 300 s window, so
  elevation still asks for a fresh proof and still fails if the store cannot be
  read.
- **SAML sessions pass too.** The window check precedes the SAML denial, so while
  the window is `0` or less a SAML session reaches the 37 central routes instead of
  getting its `403`, except approve and reject (`POST /api/approvals/{id}/approve` and
  `/reject`), which keep their own gate whatever this value is (next bullet).
- **Approval approve and reject keep a gate of their own.** The approver gate
  (#6079) ignores this flag: an approver still needs an enrolled factor and a
  proof no older than the approver window on the database clock, a SAML session is still refused
  `approver_assurance_required:saml_mfa_unsupported`, and an unreadable enrolment is
  still a `503`. The lever does not unblock approvals.
- **Step-up evidence thins out.** While the window is `0` or less, no stale proof
  is refused, so none is recorded as a `mfa.step_up.required` row (passes never
  write one); the SAML refusal and the store read are skipped as well. Engine
  denials and unwired-store refusals still apply and are still recorded. Write the start and end times of the
  window into your incident record; the audit log cannot reconstruct them.
- **The reminder is slow too.** `YuzuStepUpWindowDisabled` fires after the gauge
  has read `0` or less for 10 minutes, so a short-lived window passes without an
  alert.

The server logs a startup `WARN` while the flag is in force. Restore the window and
restart once the store is back.

## What you cannot recover from

- **Lost `yuzu-server.cfg` and an empty `auth` schema.** The config is the seed
  for the admin account on first boot. If both are gone, start `yuzu-server`
  interactively on a terminal with no `yuzu-server.cfg` at the configured path
  (`--config`): it runs first-run setup, prompts for a new administrator and
  writes a fresh config. (There is no `--first-run-setup` flag; setup runs
  whenever the config file is absent and needs a TTY.)

- <a id="kek-permanently-lost"></a>**KEK permanently lost.** First, the server
  **will not start** on a database that still registers the lost version.
  Every boot verifies each registered KEK and stops with `kek_unresolvable`.
  The one-shot modes `--mfa-reset` and `--break-glass-arm` run after that check
  and fail the same way, and there is no supported way to deregister a KEK
  version. Without the key file, this database cannot be brought back by any
  supported means; it is usable again only with the key file restored from a
  backup. **Do not delete rows from `secrets.kek_meta` to force a start.** The
  server then mints a new key under the same version number, every secret
  sealed under the lost key (webhook secrets, plugin and runtime config
  secrets, offload credentials) becomes permanently undecryptable with no error
  at boot, and a key file you later find cannot be used (#5421). Take a
  `pg_dump` before you discard the database: it holds the audit log and
  configuration, but never restore it into a new install, because it registers
  the lost KEK. Otherwise you start over with a fresh database, and the CA in
  the same directory is usually gone too, which means a full agent
  re-enrolment. The Docker Compose case is worked through in
  `docs/user-manual/upgrading.md` (#5370). What the KEK does and does not
  protect:
  - **Not sealed under the KEK:** password hashes and MFA recovery codes are
    verify-only PBKDF2 hashes. They are lost only if you start over with a
    fresh database.
  - **Sealed, and unrecoverable without the key file:** TOTP secrets, so every
    enrolled user must re-enroll, and the other secret columns listed in
    `docs/user-manual/server-admin.md` "Key management (secrets KEK)", such as
    webhook signing secrets.
  - Any future envelope-encrypted column follows the same rule: re-enrollable
    or re-issuable by design, which is why ADR-0010 requires it.

  Do **not** delete the old key file until you are certain no backup you intend
  to honour still contains blobs wrapped under it.

- **Backups whose encryption key is lost.** Standard; nothing Yuzu-specific.

## Cross-references

- `docs/auth-architecture.md` — auth model, hardened mode, break-glass design
- `docs/user-manual/server-admin.md` — KEK lifecycle, rotation, secrets at rest
- `docs/adr/0006-server-postgresql-substrate.md` — fail-closed substrate
- `docs/adr/0010-secrets-at-rest-envelope-encryption.md` — envelope encryption
- `docs/postgres-store-playbook.md` — store authoring contract
- `docs/agent-privilege-model.md` — service accounts and sudoers
- `docs/ops-runbooks/engine-principal-store-recovery.md` — `engine:` namespace
